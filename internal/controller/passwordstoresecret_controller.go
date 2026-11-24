package controller

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
	"github.com/sorend/passwordstore-operator/internal/entry"
	"github.com/sorend/passwordstore-operator/internal/gitstore"
	"github.com/sorend/passwordstore-operator/internal/gpg"
)

// storeRefIndex is the field index that finds the PasswordStoreSecrets that use a store.
const storeRefIndex = ".spec.storeRef"

// PasswordStoreSecretReconciler reconciles a PasswordStoreSecret object
type PasswordStoreSecretReconciler struct {
	client.Client
	// Reader reads Secrets directly from the API server, instead of from a cache.
	Reader   client.Reader
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder
	Options
}

// +kubebuilder:rbac:groups=passwordstore.k8s.sorend.github.com,resources=passwordstoresecrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=passwordstore.k8s.sorend.github.com,resources=passwordstoresecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=passwordstore.k8s.sorend.github.com,resources=passwordstoresecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups=passwordstore.k8s.sorend.github.com,resources=passwordstores;clusterpasswordstores,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile renders the Secret of a PasswordStoreSecret from the entries of its store.
func (r *PasswordStoreSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var pss passwordstorev1alpha1.PasswordStoreSecret
	if err := r.Get(ctx, req.NamespacedName, &pss); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// The Secret is deleted together with the PasswordStoreSecret, by its owner reference.
	if !pss.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	interval := refreshInterval(&pss)
	revision, sensitive, err := r.render(ctx, &pss)

	reason, known := failureReason(err)
	if err != nil && !known {
		// Not a problem of this resource, for example the API server could not be reached. The
		// controller tries again with a back-off.
		return ctrl.Result{}, err
	}

	var changed bool
	if patchErr := patchStatus(ctx, r.Client, &pss, func() {
		status := &pss.Status
		status.ObservedGeneration = pss.Generation
		status.SecretName = targetName(&pss)
		if err != nil {
			changed = setReady(&status.Conditions, pss.Generation, metav1.ConditionFalse, reason, message(err, sensitive))
			return
		}
		changed = setReady(&status.Conditions, pss.Generation, metav1.ConditionTrue, passwordstorev1alpha1.ReasonSynced,
			fmt.Sprintf("Secret %s rendered from revision %s", targetName(&pss), shortRevision(revision)))
		now := metav1.Now()
		status.Revision = revision
		status.LastRefreshTime = &now
	}); patchErr != nil {
		return ctrl.Result{}, fmt.Errorf("update status: %w", patchErr)
	}

	if err != nil {
		log.Info("Could not render Secret", "secret", targetName(&pss), "reason", reason, "message", message(err, sensitive))
		if changed {
			emit(r.Recorder, &pss, corev1.EventTypeWarning, reason, message(err, sensitive))
		}
		return ctrl.Result{RequeueAfter: min(r.retryInterval(), interval)}, nil
	}

	log.V(1).Info("Rendered Secret", "secret", targetName(&pss), "revision", revision)
	if changed {
		emit(r.Recorder, &pss, corev1.EventTypeNormal, passwordstorev1alpha1.ReasonSynced, "Secret "+targetName(&pss)+" is up to date")
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

// render reads the entries and writes the Secret. It returns the revision of the store that the
// Secret was rendered from, and the credentials that were used, to keep them out of messages.
func (r *PasswordStoreSecretReconciler) render(ctx context.Context, pss *passwordstorev1alpha1.PasswordStoreSecret) (
	revision string, sensitive [][]byte, err error,
) {
	refs, err := parseData(pss.Spec.Data)
	if err != nil {
		return "", nil, err
	}
	if secretType(pss) == corev1.SecretTypeServiceAccountToken {
		return "", nil, fail(passwordstorev1alpha1.ReasonInvalidSpec,
			"a Secret of type %s cannot be generated: Kubernetes would fill it with the token of a ServiceAccount", corev1.SecretTypeServiceAccountToken)
	}
	if problems := validation.IsDNS1123Subdomain(targetName(pss)); len(problems) > 0 {
		return "", nil, fail(passwordstorev1alpha1.ReasonInvalidSpec, "the name %q of the Secret is not valid: %s",
			targetName(pss), strings.Join(problems, ", "))
	}

	store, err := r.lookupStore(ctx, pss)
	if err != nil {
		return "", nil, err
	}
	resolved, err := storeResolver{reader: r.Reader}.resolve(ctx, store)
	if resolved != nil {
		sensitive = resolved.sensitive
	}
	if err != nil {
		return "", sensitive, err
	}

	snapshot, err := r.Git.Sync(ctx, resolved.key, resolved.config, r.FetchCooldown)
	if err != nil {
		return "", sensitive, syncFailure(err)
	}

	data, err := readEntries(snapshot, resolved.decrypter, refs)
	if err != nil {
		return "", sensitive, err
	}
	if err := r.applySecret(ctx, pss, data); err != nil {
		return "", sensitive, err
	}
	return snapshot.Revision(), sensitive, nil
}

// refreshInterval returns how often the PasswordStoreSecret is refreshed.
func refreshInterval(pss *passwordstorev1alpha1.PasswordStoreSecret) time.Duration {
	interval, _ := time.ParseDuration(passwordstorev1alpha1.DefaultRefreshInterval)
	if pss.Spec.RefreshInterval != nil {
		interval = pss.Spec.RefreshInterval.Duration
	}
	return max(interval, minRefreshInterval)
}

// targetName returns the name of the Secret that is generated.
func targetName(pss *passwordstorev1alpha1.PasswordStoreSecret) string {
	if pss.Spec.Template != nil && pss.Spec.Template.Metadata.Name != "" {
		return pss.Spec.Template.Metadata.Name
	}
	return pss.Name
}

// lookupStore finds the store of a PasswordStoreSecret and checks that it may use it.
func (r *PasswordStoreSecretReconciler) lookupStore(ctx context.Context, pss *passwordstorev1alpha1.PasswordStoreSecret) (Store, error) {
	ref := pss.Spec.StoreRef
	switch kind := ref.ResolvedKind(); kind {
	case passwordstorev1alpha1.KindPasswordStore:
		var store passwordstorev1alpha1.PasswordStore
		if err := r.Get(ctx, types.NamespacedName{Namespace: pss.Namespace, Name: ref.Name}, &store); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, fail(passwordstorev1alpha1.ReasonStoreNotFound, "PasswordStore %q not found in namespace %q", ref.Name, pss.Namespace)
			}
			return nil, fmt.Errorf("get PasswordStore: %w", err)
		}
		return &store, nil

	case passwordstorev1alpha1.KindClusterPasswordStore:
		var store passwordstorev1alpha1.ClusterPasswordStore
		if err := r.Get(ctx, types.NamespacedName{Name: ref.Name}, &store); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, fail(passwordstorev1alpha1.ReasonStoreNotFound, "ClusterPasswordStore %q not found", ref.Name)
			}
			return nil, fmt.Errorf("get ClusterPasswordStore: %w", err)
		}
		allowed, err := r.namespaceAllowed(ctx, &store, pss.Namespace)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, fail(passwordstorev1alpha1.ReasonNamespaceNotAllowed,
				"ClusterPasswordStore %q does not allow PasswordStoreSecrets in namespace %q", ref.Name, pss.Namespace)
		}
		return &store, nil

	default:
		return nil, fail(passwordstorev1alpha1.ReasonInvalidSpec, "unknown store kind %q", kind)
	}
}

// namespaceAllowed reports whether the namespace may use the ClusterPasswordStore.
func (r *PasswordStoreSecretReconciler) namespaceAllowed(
	ctx context.Context, store *passwordstorev1alpha1.ClusterPasswordStore, namespace string,
) (bool, error) {
	if store.Spec.NamespaceSelector == nil {
		return true, nil
	}
	selector, err := metav1.LabelSelectorAsSelector(store.Spec.NamespaceSelector)
	if err != nil {
		return false, fail(passwordstorev1alpha1.ReasonInvalidSpec, "namespaceSelector of ClusterPasswordStore %q is invalid: %v", store.Name, err)
	}

	var ns corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: namespace}, &ns); err != nil {
		if apierrors.IsForbidden(err) {
			// Without the labels of the namespace the selector cannot be evaluated, so nothing is allowed.
			return false, fail(passwordstorev1alpha1.ReasonPermissionDenied,
				"the operator is not allowed to read the namespace %q, which the namespaceSelector of ClusterPasswordStore %q needs", namespace, store.Name)
		}
		return false, fmt.Errorf("get Namespace: %w", err)
	}
	return selector.Matches(labels.Set(ns.Labels)), nil
}

// dataRef is a key of the Secret and the entry that it is made from.
type dataRef struct {
	key string
	ref entry.Ref
}

// parseData validates spec.data. All problems are reported at once.
func parseData(data map[string]string) ([]dataRef, error) {
	refs := make([]dataRef, 0, len(data))
	var problems []string
	for _, key := range slices.Sorted(maps.Keys(data)) {
		if errs := validation.IsConfigMapKey(key); len(errs) > 0 {
			problems = append(problems, fmt.Sprintf("data key %q is not valid: %s", key, strings.Join(errs, ", ")))
			continue
		}
		ref, err := entry.Parse(data[key])
		if err != nil {
			problems = append(problems, fmt.Sprintf("data[%q]: %v", key, err))
			continue
		}
		refs = append(refs, dataRef{key: key, ref: ref})
	}
	if len(problems) > 0 {
		return nil, fail(passwordstorev1alpha1.ReasonInvalidSpec, "%s", strings.Join(problems, "; "))
	}
	if len(refs) == 0 {
		return nil, fail(passwordstorev1alpha1.ReasonInvalidSpec, "data is empty")
	}
	return refs, nil
}

// readEntries decrypts the entries that make up the data of the Secret. Either all of them can be
// read, or none is used and every problem is reported, so that a Secret is never half updated.
func readEntries(snapshot *gitstore.Snapshot, decrypter *gpg.Decrypter, refs []dataRef) (map[string][]byte, error) {
	data := make(map[string][]byte, len(refs))
	decrypted := make(map[string][]byte) // by file, several keys can use the same entry
	var problems []string
	var reason string

	for _, d := range refs {
		value, err := readEntry(snapshot, decrypter, d.ref, decrypted)
		if err != nil {
			problems = append(problems, fmt.Sprintf("data[%q]: %v", d.key, err))
			if reason == "" {
				reason, _ = failureReason(err)
			}
			continue
		}
		data[d.key] = value
	}
	if len(problems) > 0 {
		return nil, fail(reason, "%s", strings.Join(problems, "; "))
	}
	return data, nil
}

func readEntry(snapshot *gitstore.Snapshot, decrypter *gpg.Decrypter, ref entry.Ref, decrypted map[string][]byte) ([]byte, error) {
	var file string
	var ciphertext []byte
	for _, candidate := range ref.Files() {
		data, err := snapshot.ReadFile(candidate)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fail(passwordstorev1alpha1.ReasonEntryNotFound, "entry %q cannot be read: %v", ref.Path, err)
		}
		file, ciphertext = candidate, data
		break
	}
	if file == "" {
		return nil, fail(passwordstorev1alpha1.ReasonEntryNotFound, "entry %q not found in the store (looked for %s)",
			ref.Path, strings.Join(ref.Files(), ", "))
	}

	plaintext, ok := decrypted[file]
	if !ok {
		var err error
		if plaintext, err = decrypter.Decrypt(ciphertext); err != nil {
			return nil, fail(passwordstorev1alpha1.ReasonDecryptFailed, "entry %q cannot be decrypted: %v", ref.Path, err)
		}
		decrypted[file] = plaintext
	}

	value, err := ref.Select(plaintext)
	if err != nil {
		return nil, fail(passwordstorev1alpha1.ReasonEntryNotFound, "entry %q: %v", ref.Path, err)
	}
	return value, nil
}

// storeChanged selects the events of a store that matter to the PasswordStoreSecrets that use it:
// when it is created, deleted, its spec changes, or a new revision is fetched.
var storeChanged = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldStore, oldOK := e.ObjectOld.(Store)
		newStore, newOK := e.ObjectNew.(Store)
		if !oldOK || !newOK {
			return false
		}
		return oldStore.GetGeneration() != newStore.GetGeneration() ||
			oldStore.StoreStatus().Revision != newStore.StoreStatus().Revision ||
			isReady(oldStore.StoreStatus()) != isReady(newStore.StoreStatus())
	},
}

func isReady(status *passwordstorev1alpha1.PasswordStoreStatus) bool {
	for _, c := range status.Conditions {
		if c.Type == passwordstorev1alpha1.ConditionReady {
			return c.Status == metav1.ConditionTrue
		}
	}
	return false
}

// namespaceLabelsChanged selects the events of a Namespace that can change which
// ClusterPasswordStores its PasswordStoreSecrets may use.
var namespaceLabelsChanged = predicate.Funcs{
	CreateFunc:  func(event.CreateEvent) bool { return false },
	DeleteFunc:  func(event.DeleteEvent) bool { return false },
	GenericFunc: func(event.GenericEvent) bool { return false },
	UpdateFunc: func(e event.UpdateEvent) bool {
		return !maps.Equal(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels())
	},
}

// indexStoreRef indexes PasswordStoreSecrets by the store they use, as "Kind/name".
func indexStoreRef(obj client.Object) []string {
	pss, ok := obj.(*passwordstorev1alpha1.PasswordStoreSecret)
	if !ok {
		return nil
	}
	return []string{pss.Spec.StoreRef.ResolvedKind() + "/" + pss.Spec.StoreRef.Name}
}

// secretsForStore finds the PasswordStoreSecrets that use the store.
func (r *PasswordStoreSecretReconciler) secretsForStore(ctx context.Context, obj client.Object) []reconcile.Request {
	var kind string
	var opts []client.ListOption
	switch obj.(type) {
	case *passwordstorev1alpha1.PasswordStore:
		kind = passwordstorev1alpha1.KindPasswordStore
		opts = append(opts, client.InNamespace(obj.GetNamespace()))
	case *passwordstorev1alpha1.ClusterPasswordStore:
		kind = passwordstorev1alpha1.KindClusterPasswordStore
	default:
		return nil
	}
	opts = append(opts, client.MatchingFields{storeRefIndex: kind + "/" + obj.GetName()})

	var list passwordstorev1alpha1.PasswordStoreSecretList
	if err := r.List(ctx, &list, opts...); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to list PasswordStoreSecrets of a store", "store", obj.GetName())
		return nil
	}
	return requestsFor(list.Items)
}

// secretsInNamespace finds the PasswordStoreSecrets in a namespace that use a ClusterPasswordStore.
func (r *PasswordStoreSecretReconciler) secretsInNamespace(ctx context.Context, obj client.Object) []reconcile.Request {
	var list passwordstorev1alpha1.PasswordStoreSecretList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetName())); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to list PasswordStoreSecrets in a namespace", "namespace", obj.GetName())
		return nil
	}
	var users []passwordstorev1alpha1.PasswordStoreSecret
	for _, pss := range list.Items {
		if pss.Spec.StoreRef.ResolvedKind() == passwordstorev1alpha1.KindClusterPasswordStore {
			users = append(users, pss)
		}
	}
	return requestsFor(users)
}

func requestsFor(items []passwordstorev1alpha1.PasswordStoreSecret) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(items))
	for _, item := range items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&item)})
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *PasswordStoreSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(),
		&passwordstorev1alpha1.PasswordStoreSecret{}, storeRefIndex, indexStoreRef); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		// The status is written by this controller and must not trigger it again. The Secret is
		// refreshed again after its refresh interval.
		For(&passwordstorev1alpha1.PasswordStoreSecret{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// Only the metadata of Secrets is watched, so the data of the Secrets of the whole
		// cluster is not held in memory. A Secret that is changed or deleted is made right again.
		Owns(&corev1.Secret{}, builder.OnlyMetadata).
		// A Secret is rendered again as soon as its store has a new revision.
		Watches(&passwordstorev1alpha1.PasswordStore{}, handler.EnqueueRequestsFromMapFunc(r.secretsForStore), builder.WithPredicates(storeChanged)).
		Watches(&passwordstorev1alpha1.ClusterPasswordStore{}, handler.EnqueueRequestsFromMapFunc(r.secretsForStore), builder.WithPredicates(storeChanged)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.secretsInNamespace), builder.WithPredicates(namespaceLabelsChanged)).
		WithOptions(r.controllerOptions()).
		Named("passwordstoresecret").
		Complete(r)
}
