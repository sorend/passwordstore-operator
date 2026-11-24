package controller

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
	"github.com/sorend/passwordstore-operator/internal/gitstore"
	"github.com/sorend/passwordstore-operator/internal/gpg"
)

// Default keys in the Secrets that the specs of a store refer to.
const (
	defaultSSHKey        = "ssh-privatekey"
	defaultPassphraseKey = "passphrase"
	defaultTokenKey      = "token"
	defaultAppKey        = "private-key.pem"
	defaultGPGKey        = "private.key"
)

// Store is implemented by PasswordStore and ClusterPasswordStore.
type Store interface {
	client.Object
	StoreSpec() *passwordstorev1alpha1.PasswordStoreSpec
	StoreStatus() *passwordstorev1alpha1.PasswordStoreStatus
}

// storeKey identifies a store in the cache of repositories.
func storeKey(store client.Object) string {
	if _, ok := store.(*passwordstorev1alpha1.ClusterPasswordStore); ok {
		return passwordstorev1alpha1.KindClusterPasswordStore + "/" + store.GetName()
	}
	return passwordstorev1alpha1.KindPasswordStore + "/" + store.GetNamespace() + "/" + store.GetName()
}

// resolvedStore is a store with the credentials that its spec refers to read from the cluster.
type resolvedStore struct {
	key       string
	config    gitstore.Config
	decrypter *gpg.Decrypter
	// sensitive holds the credentials that were read, to keep them out of messages.
	sensitive [][]byte
}

// storeResolver reads what a store refers to. It reads Secrets directly from the API server and
// not from a cache, so that the credentials of the whole cluster are not held in memory.
type storeResolver struct {
	reader client.Reader
}

// resolve reads the Secrets that the store refers to and prepares the configuration for fetching
// the repository and the key for decrypting the entries. Errors have a reason for the condition.
func (r storeResolver) resolve(ctx context.Context, store Store) (*resolvedStore, error) {
	spec := store.StoreSpec()
	_, cluster := store.(*passwordstorev1alpha1.ClusterPasswordStore)

	out := &resolvedStore{key: storeKey(store)}
	read := func(ref passwordstorev1alpha1.SecretKeySelector, defaultKey string) ([]byte, error) {
		value, err := r.secretValue(ctx, store.GetNamespace(), cluster, ref, defaultKey)
		if err == nil {
			out.sensitive = append(out.sensitive, value)
		}
		return value, err
	}

	cfg := gitstore.Config{URL: spec.GitRepo.URL, Branch: spec.GitRepo.Branch, Path: spec.GitRepo.Path}
	if auth := spec.GitRepo.Auth; auth != nil {
		var err error
		switch {
		case auth.SSH != nil:
			cfg.Auth.SSH = &gitstore.SSHAuth{
				KnownHosts:            auth.SSH.KnownHosts,
				InsecureIgnoreHostKey: auth.SSH.InsecureIgnoreHostKey,
			}
			if cfg.Auth.SSH.PrivateKey, err = read(auth.SSH.PrivateKeySecretRef, defaultSSHKey); err != nil {
				return nil, err
			}
			if auth.SSH.PassphraseSecretRef != nil {
				if cfg.Auth.SSH.Passphrase, err = readLine(read, *auth.SSH.PassphraseSecretRef, defaultPassphraseKey); err != nil {
					return nil, err
				}
			}
		case auth.Token != nil:
			token, err := readLine(read, auth.Token.TokenSecretRef, defaultTokenKey)
			if err != nil {
				return nil, err
			}
			cfg.Auth.Token = &gitstore.TokenAuth{Username: auth.Token.Username, Token: string(token)}
		case auth.App != nil:
			key, err := read(auth.App.PrivateKeySecretRef, defaultAppKey)
			if err != nil {
				return nil, err
			}
			cfg.Auth.App = &gitstore.AppAuth{
				AppID:          auth.App.AppID,
				InstallationID: auth.App.InstallationID,
				PrivateKey:     key,
				BaseURL:        auth.App.BaseURL,
			}
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, failWrap(passwordstorev1alpha1.ReasonInvalidSpec, err)
	}
	out.config = cfg

	keyData, err := read(spec.GPG.PrivateKeySecretRef, defaultGPGKey)
	if err != nil {
		return nil, err
	}
	var passphrase []byte
	if spec.GPG.PassphraseSecretRef != nil {
		if passphrase, err = readLine(read, *spec.GPG.PassphraseSecretRef, defaultPassphraseKey); err != nil {
			return nil, err
		}
	}
	if out.decrypter, err = gpg.NewDecrypter(keyData, spec.GPG.ID, passphrase); err != nil {
		return nil, failWrap(passwordstorev1alpha1.ReasonGPGKeyInvalid, err)
	}
	return out, nil
}

// readLine reads a value that is one line, such as a token or a passphrase, and removes the line
// break that is left behind when it is made from a file or with echo.
func readLine(
	read func(passwordstorev1alpha1.SecretKeySelector, string) ([]byte, error),
	ref passwordstorev1alpha1.SecretKeySelector, defaultKey string,
) ([]byte, error) {
	value, err := read(ref, defaultKey)
	if err != nil {
		return nil, err
	}
	return bytes.TrimRight(value, "\r\n"), nil
}

// secretValue reads one key of a Secret. A PasswordStore can only use Secrets of its own
// namespace, a ClusterPasswordStore has to say which namespace each Secret is in.
func (r storeResolver) secretValue(
	ctx context.Context, storeNamespace string, cluster bool, ref passwordstorev1alpha1.SecretKeySelector, defaultKey string,
) ([]byte, error) {
	namespace := ref.Namespace
	switch {
	case cluster && namespace == "":
		return nil, fail(passwordstorev1alpha1.ReasonInvalidSpec,
			"the reference to Secret %q needs a namespace, because a ClusterPasswordStore is not in one", ref.Name)
	case !cluster && namespace != "" && namespace != storeNamespace:
		return nil, fail(passwordstorev1alpha1.ReasonInvalidSpec,
			"the reference to Secret %q is to the namespace %q, but a PasswordStore can only use Secrets in its own namespace %q",
			ref.Name, namespace, storeNamespace)
	case !cluster:
		namespace = storeNamespace
	}

	key := ref.Key
	if key == "" {
		key = defaultKey
	}

	var secret corev1.Secret
	if err := r.reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, &secret); err != nil {
		switch {
		case apierrors.IsNotFound(err):
			return nil, fail(passwordstorev1alpha1.ReasonCredentialsUnavailable, "Secret %s/%s not found", namespace, ref.Name)
		case apierrors.IsForbidden(err):
			return nil, fail(passwordstorev1alpha1.ReasonCredentialsUnavailable,
				"the operator is not allowed to read Secret %s/%s", namespace, ref.Name)
		}
		return nil, fmt.Errorf("get Secret %s/%s: %w", namespace, ref.Name, err)
	}

	value, ok := secret.Data[key]
	switch {
	case !ok:
		return nil, fail(passwordstorev1alpha1.ReasonCredentialsUnavailable,
			"Secret %s/%s has no key %q (it has: %s)", namespace, ref.Name, key, keysOf(secret.Data))
	case len(bytes.TrimSpace(value)) == 0:
		return nil, fail(passwordstorev1alpha1.ReasonCredentialsUnavailable, "key %q of Secret %s/%s is empty", key, namespace, ref.Name)
	}
	return value, nil
}

func keysOf(data map[string][]byte) string {
	if len(data) == 0 {
		return "no keys"
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, fmt.Sprintf("%q", k))
	}
	// The order is not important, but it is stable for the same Secret.
	slices.Sort(keys)
	return strings.Join(keys, ", ")
}

// storeReconciler holds the reconcile logic of PasswordStore and ClusterPasswordStore, which
// differ in how they are looked up and nothing else.
type storeReconciler struct {
	client.Client
	// Reader reads Secrets directly from the API server.
	Reader   client.Reader
	Recorder events.EventRecorder
	Options
}

// reconcile checks that the store is usable: that its credentials can be read, that the repository
// can be fetched and that the GPG key can be unlocked. It reports the result in the status.
func (r *storeReconciler) reconcile(ctx context.Context, store Store) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	resolved, err := storeResolver{reader: r.Reader}.resolve(ctx, store)
	var snapshot *gitstore.Snapshot
	if err == nil {
		snapshot, err = r.Git.Sync(ctx, resolved.key, resolved.config, 0)
		if err != nil {
			err = syncFailure(err)
		}
	}

	reason, known := failureReason(err)
	if err != nil && !known {
		// Not a problem of the store, for example the API server could not be reached. The
		// condition says nothing about those, and the controller tries again with a back-off.
		return ctrl.Result{}, err
	}

	status := store.StoreStatus()
	var changed bool
	var sensitive [][]byte
	if resolved != nil {
		sensitive = resolved.sensitive
	}
	if patchErr := patchStatus(ctx, r.Client, store, func() {
		status.ObservedGeneration = store.GetGeneration()
		if err != nil {
			changed = setReady(&status.Conditions, store.GetGeneration(), metav1.ConditionFalse, reason, message(err, sensitive))
			return
		}
		changed = setReady(&status.Conditions, store.GetGeneration(), metav1.ConditionTrue, passwordstorev1alpha1.ReasonSynced,
			fmt.Sprintf("Fetched revision %s, decrypting with key %s", shortRevision(snapshot.Revision()), resolved.decrypter.Fingerprint()))
		now := metav1.Now()
		status.Revision = snapshot.Revision()
		status.LastSyncTime = &now
		status.GPGFingerprint = resolved.decrypter.Fingerprint()
	}); patchErr != nil {
		return ctrl.Result{}, fmt.Errorf("update status: %w", patchErr)
	}

	if err != nil {
		log.Info("Store is not ready", "reason", reason, "message", message(err, sensitive))
		if changed {
			emit(r.Recorder, store, "Warning", reason, message(err, sensitive))
		}
		return ctrl.Result{RequeueAfter: r.retryInterval()}, nil
	}

	log.V(1).Info("Synced store", "revision", snapshot.Revision())
	if changed {
		emit(r.Recorder, store, "Normal", passwordstorev1alpha1.ReasonSynced, "Store is ready")
	}
	return ctrl.Result{RequeueAfter: r.storeSyncInterval()}, nil
}

// forget drops the cached repository of a store that does not exist any more.
func (r *storeReconciler) forget(store client.Object) {
	r.Git.Forget(storeKey(store))
}
