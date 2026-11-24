package controller

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
	"github.com/sorend/passwordstore-operator/internal/testutil"
)

// env is what a spec needs: a namespace, a PGP key, a Git server, and the Secret with the key.
type env struct {
	ns  string
	key *testutil.PGPKey
	git *testutil.GitServer
}

// newEnv creates the namespace and the Secret "gpg-key" with the private key.
func newEnv(gitOpts ...testutil.GitServerOption) *env {
	GinkgoHelper()
	e := &env{
		ns:  "t-" + rand.String(6),
		key: testutil.NewPGPKey(GinkgoT(), "store@example.com"),
		git: testutil.NewGitServer(GinkgoT(), gitOpts...),
	}
	Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: e.ns}})).To(Succeed())
	e.secret("gpg-key", map[string]string{"private.key": string(e.key.Private)})
	return e
}

// secret creates a Secret in the namespace of the env.
func (e *env) secret(name string, data map[string]string) *corev1.Secret {
	GinkgoHelper()
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: e.ns, Name: name}, StringData: data}
	Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	return secret
}

// commit encrypts the entries (path without .gpg -> content) to the key of the env and commits
// them. A nil entry is removed.
func (e *env) commit(entries map[string]*string) string {
	GinkgoHelper()
	files := make(map[string][]byte, len(entries))
	for path, content := range entries {
		if content == nil {
			files[path+".gpg"] = nil
			continue
		}
		files[path+".gpg"] = testutil.Encrypt(GinkgoT(), *content, e.key)
	}
	return e.git.Commit(GinkgoT(), "entries", files)
}

// entries is a shorthand for commit with plain strings.
func (e *env) entries(entries map[string]string) string {
	GinkgoHelper()
	m := make(map[string]*string, len(entries))
	for path, content := range entries {
		m[path] = &content
	}
	return e.commit(m)
}

// storeSpec returns the spec of a store at the Git server of the env, without credentials.
func (e *env) storeSpec() passwordstorev1alpha1.PasswordStoreSpec {
	return passwordstorev1alpha1.PasswordStoreSpec{
		GitRepo: passwordstorev1alpha1.GitRepoSpec{URL: e.git.URL},
		GPG: passwordstorev1alpha1.GPGSpec{
			ID:                  e.key.Email,
			PrivateKeySecretRef: passwordstorev1alpha1.SecretKeySelector{Name: "gpg-key"},
		},
	}
}

// store creates a PasswordStore, after letting the test change its spec.
func (e *env) store(name string, mutate ...func(*passwordstorev1alpha1.PasswordStoreSpec)) *passwordstorev1alpha1.PasswordStore {
	GinkgoHelper()
	spec := e.storeSpec()
	for _, m := range mutate {
		m(&spec)
	}
	store := &passwordstorev1alpha1.PasswordStore{ObjectMeta: metav1.ObjectMeta{Namespace: e.ns, Name: name}, Spec: spec}
	return create(store)
}

// clusterStore creates a ClusterPasswordStore whose Secrets are in the namespace of the env.
func (e *env) clusterStore(name string, mutate ...func(*passwordstorev1alpha1.ClusterPasswordStoreSpec)) *passwordstorev1alpha1.ClusterPasswordStore {
	GinkgoHelper()
	spec := passwordstorev1alpha1.ClusterPasswordStoreSpec{PasswordStoreSpec: e.storeSpec()}
	spec.GPG.PrivateKeySecretRef.Namespace = e.ns
	for _, m := range mutate {
		m(&spec)
	}
	return create(&passwordstorev1alpha1.ClusterPasswordStore{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: spec})
}

// pss creates a PasswordStoreSecret that uses the store, after letting the test change its spec.
func (e *env) pss(name, store string, data map[string]string, mutate ...func(*passwordstorev1alpha1.PasswordStoreSecret)) *passwordstorev1alpha1.PasswordStoreSecret {
	GinkgoHelper()
	obj := &passwordstorev1alpha1.PasswordStoreSecret{
		ObjectMeta: metav1.ObjectMeta{Namespace: e.ns, Name: name},
		Spec: passwordstorev1alpha1.PasswordStoreSecretSpec{
			StoreRef: passwordstorev1alpha1.StoreReference{Name: store},
			Data:     data,
		},
	}
	for _, m := range mutate {
		m(obj)
	}
	return create(obj)
}

// create creates the object and deletes it when the spec is done, so that the controllers, which
// keep running, do not keep working on objects of specs that are over.
func create[T client.Object](obj T) T {
	GinkgoHelper()
	Expect(k8sClient.Create(ctx, obj)).To(Succeed())
	DeferCleanup(func() {
		err := k8sClient.Delete(ctx, obj)
		if err != nil && !apierrors.IsNotFound(err) {
			Fail(fmt.Sprintf("delete %T: %v", obj, err))
		}
	})
	return obj
}

// conditionOf returns the Ready condition of a resource of this API group, read from the API
// server, or nil when there is none yet.
func conditionOf(obj client.Object) *metav1.Condition {
	GinkgoHelper()
	Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
	switch o := obj.(type) {
	case *passwordstorev1alpha1.PasswordStore:
		return meta.FindStatusCondition(o.Status.Conditions, passwordstorev1alpha1.ConditionReady)
	case *passwordstorev1alpha1.ClusterPasswordStore:
		return meta.FindStatusCondition(o.Status.Conditions, passwordstorev1alpha1.ConditionReady)
	case *passwordstorev1alpha1.PasswordStoreSecret:
		return meta.FindStatusCondition(o.Status.Conditions, passwordstorev1alpha1.ConditionReady)
	}
	Fail(fmt.Sprintf("conditionOf: unexpected type %T", obj))
	return nil
}

// eventuallyReady waits until the Ready condition is True.
func eventuallyReady(obj client.Object) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		c := conditionOf(obj)
		g.Expect(c).NotTo(BeNil(), "no Ready condition yet")
		g.Expect(c.Status).To(Equal(metav1.ConditionTrue), "Ready is False with reason %s: %s", c.Reason, c.Message)
		g.Expect(c.ObservedGeneration).To(Equal(obj.GetGeneration()))
	}).Should(Succeed())
}

// eventuallyNotReady waits until the Ready condition is False for the reason and returns it.
func eventuallyNotReady(obj client.Object, reason string) *metav1.Condition {
	GinkgoHelper()
	var got *metav1.Condition
	Eventually(func(g Gomega) {
		c := conditionOf(obj)
		g.Expect(c).NotTo(BeNil(), "no Ready condition yet")
		g.Expect(c.Status).To(Equal(metav1.ConditionFalse), "Ready is %s", c.Status)
		g.Expect(c.Reason).To(Equal(reason), "message: %s", c.Message)
		got = c
	}).Should(Succeed())
	return got
}

// getSecret reads a Secret from the API server.
func getSecret(namespace, name string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret)
	return secret, err
}

// eventuallySecretData waits until the Secret has exactly this data.
func eventuallySecretData(namespace, name string, want map[string]string) *corev1.Secret {
	GinkgoHelper()
	var got *corev1.Secret
	Eventually(func(g Gomega) {
		secret, err := getSecret(namespace, name)
		g.Expect(err).NotTo(HaveOccurred())
		have := make(map[string]string, len(secret.Data))
		for k, v := range secret.Data {
			have[k] = string(v)
		}
		g.Expect(have).To(Equal(want))
		got = secret
	}).Should(Succeed())
	return got
}

// consistentlyNoSecret checks that the Secret does not appear.
func consistentlyNoSecret(namespace, name string, duration time.Duration) {
	GinkgoHelper()
	Consistently(func() bool {
		_, err := getSecret(namespace, name)
		return apierrors.IsNotFound(err)
	}, duration, eventuallyInterval).Should(BeTrue(), "Secret %s/%s must not exist", namespace, name)
}

// update changes an object that the controllers also write to, retrying when they got there
// first.
func update[T client.Object](obj T, mutate func(T)) {
	GinkgoHelper()
	Eventually(func() error {
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			return err
		}
		mutate(obj)
		return k8sClient.Update(ctx, obj)
	}).Should(Succeed())
}

// newNamespace creates a namespace and returns its name.
func newNamespace() string {
	GinkgoHelper()
	name := "t-" + rand.String(6)
	Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})).To(Succeed())
	return name
}
