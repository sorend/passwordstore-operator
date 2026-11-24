package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
)

var _ = Describe("ClusterPasswordStore", func() {
	var e *env

	BeforeEach(func() { e = newEnv() })

	It("becomes Ready, with the Secrets it refers to in the namespace it names", func() {
		commit := e.entries(map[string]string{"a": "x"})
		store := e.clusterStore("ready-" + e.ns)
		eventuallyReady(store)

		Expect(store.Status.Revision).To(Equal(commit))
		Expect(store.Status.GPGFingerprint).To(Equal(e.key.Fingerprint))
	})

	It("needs a namespace for every Secret it refers to, because it has none", func() {
		e.entries(map[string]string{"a": "x"})
		store := e.clusterStore("no-namespace-"+e.ns, func(s *passwordstorev1alpha1.ClusterPasswordStoreSpec) {
			s.GPG.PrivateKeySecretRef.Namespace = ""
		})
		c := eventuallyNotReady(store, passwordstorev1alpha1.ReasonInvalidSpec)
		Expect(c.Message).To(ContainSubstring("needs a namespace"))
	})

	It("reports a Secret that does not exist in the namespace it names", func() {
		e.entries(map[string]string{"a": "x"})
		store := e.clusterStore("missing-"+e.ns, func(s *passwordstorev1alpha1.ClusterPasswordStoreSpec) {
			s.GPG.PrivateKeySecretRef.Name = "not-there"
		})
		c := eventuallyNotReady(store, passwordstorev1alpha1.ReasonCredentialsUnavailable)
		Expect(c.Message).To(ContainSubstring(e.ns + "/not-there"))

		e.secret("not-there", map[string]string{"private.key": string(e.key.Private)})
		eventuallyReady(store)
	})

	It("can read the Secrets of a namespace other than the one it is used from", func() {
		e.entries(map[string]string{"a": "x"})
		eventuallyReady(e.clusterStore("any-ns-" + e.ns))
	})

	It("reports a GPG key that does not fit", func() {
		e.entries(map[string]string{"a": "x"})
		store := e.clusterStore("wrong-key-"+e.ns, func(s *passwordstorev1alpha1.ClusterPasswordStoreSpec) {
			s.GPG.ID = "nobody@example.com"
		})
		c := eventuallyNotReady(store, passwordstorev1alpha1.ReasonGPGKeyInvalid)
		Expect(c.Message).To(ContainSubstring(e.key.Fingerprint))
	})
})
