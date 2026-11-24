package controller

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
	"github.com/sorend/passwordstore-operator/internal/testutil"
)

// Not a key: a few lines in the shape of one. The header is split so that no line of this file looks
// like a private key to a secret scanner.
const testPEM = "-----BEGIN PRIVATE " + "KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE " + "KEY-----\n"

var _ = Describe("PasswordStoreSecret", func() {
	var e *env

	BeforeEach(func() { e = newEnv() })

	Describe("rendering", func() {
		It("renders a Secret from entries, and says where it came from", func() {
			commit := e.entries(map[string]string{
				"k8s/postgres.db.svc/admin-user": "s3cr3t\n",
				"k8s/tls/key":                    testPEM,
				"k8s/login":                      "pw1\nusername: bob\nurl: https://example.com\n",
			})
			e.store("store")

			pss := e.pss("postgres", "store", map[string]string{
				"password":    "k8s/postgres.db.svc/admin-user",
				"tls.key":     "k8s/tls/key",
				"first-line":  "k8s/login#1",
				"username":    "k8s/login#username",
				"second-line": "k8s/login#2",
				"entry":       "k8s/login",
				"with-gpg":    "k8s/postgres.db.svc/admin-user.gpg",
			})
			eventuallyReady(pss)

			secret := eventuallySecretData(e.ns, "postgres", map[string]string{
				// A password is one line, and pass writes a newline after it that is not part of it.
				"password": "s3cr3t",
				// A key with several lines keeps its final newline, which some programs insist on.
				"tls.key":     testPEM,
				"first-line":  "pw1",
				"username":    "bob",
				"second-line": "username: bob",
				"entry":       "pw1\nusername: bob\nurl: https://example.com\n",
				// The name of the file is accepted too.
				"with-gpg": "s3cr3t",
			})
			Expect(secret.Type).To(Equal(corev1.SecretTypeOpaque))
			Expect(secret.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "passwordstore-operator"))

			By("making the PasswordStoreSecret the controller of the Secret, so that it is deleted with it")
			Expect(secret.OwnerReferences).To(HaveLen(1))
			owner := secret.OwnerReferences[0]
			Expect(owner.APIVersion).To(Equal("passwordstore.k8s.sorend.github.com/v1alpha1"))
			Expect(owner.Kind).To(Equal("PasswordStoreSecret"))
			Expect(owner.Name).To(Equal("postgres"))
			Expect(owner.UID).To(Equal(pss.UID))
			Expect(owner.Controller).To(HaveValue(BeTrue()))
			Expect(owner.BlockOwnerDeletion).To(HaveValue(BeTrue()))

			By("reporting it in the status")
			Expect(pss.Status.SecretName).To(Equal("postgres"))
			Expect(pss.Status.Revision).To(Equal(commit))
			Expect(pss.Status.LastRefreshTime).NotTo(BeNil())
			Expect(pss.Status.ObservedGeneration).To(Equal(pss.Generation))
			Expect(conditionOf(pss).Message).To(ContainSubstring(commit[:7]))
		})

		It("has defaults for the store kind and the refresh interval", func() {
			e.entries(map[string]string{"a": "x"})
			e.store("store")
			pss := e.pss("defaults", "store", map[string]string{"a": "a"})

			Expect(pss.Spec.StoreRef.Kind).To(Equal("PasswordStore"))
			Expect(pss.Spec.RefreshInterval).NotTo(BeNil())
			Expect(pss.Spec.RefreshInterval.Duration).To(Equal(5 * time.Minute))
		})

		It("renders the Secret that the template describes", func() {
			e.entries(map[string]string{"db/user": "bob\n", "db/pass": "pw\n"})
			e.store("store")

			pss := e.pss("db", "store", map[string]string{"username": "db/user", "password": "db/pass"},
				func(p *passwordstorev1alpha1.PasswordStoreSecret) {
					p.Spec.Template = &passwordstorev1alpha1.SecretTemplate{
						Type: string(corev1.SecretTypeBasicAuth),
						Metadata: passwordstorev1alpha1.SecretTemplateMetadata{
							Name:        "db-credentials",
							Labels:      map[string]string{"app": "db"},
							Annotations: map[string]string{"note": "from pass"},
						},
					}
				})
			eventuallyReady(pss)

			secret := eventuallySecretData(e.ns, "db-credentials", map[string]string{"username": "bob", "password": "pw"})
			Expect(secret.Type).To(Equal(corev1.SecretTypeBasicAuth))
			Expect(secret.Labels).To(And(
				HaveKeyWithValue("app", "db"),
				HaveKeyWithValue("app.kubernetes.io/managed-by", "passwordstore-operator"),
			))
			Expect(secret.Annotations).To(HaveKeyWithValue("note", "from pass"))
			Expect(pss.Status.SecretName).To(Equal("db-credentials"))

			_, err := getSecret(e.ns, "db")
			Expect(errors.IsNotFound(err)).To(BeTrue(), "no Secret is made under the name of the PasswordStoreSecret")
		})

		It("keeps the labels of others and drops the ones that leave the template", func() {
			e.entries(map[string]string{"a": "x"})
			e.store("store")
			pss := e.pss("labels", "store", map[string]string{"a": "a"}, func(p *passwordstorev1alpha1.PasswordStoreSecret) {
				p.Spec.Template = &passwordstorev1alpha1.SecretTemplate{Metadata: passwordstorev1alpha1.SecretTemplateMetadata{
					Labels:      map[string]string{"keep": "1", "drop": "2"},
					Annotations: map[string]string{"keep-a": "1", "drop-a": "2"},
					// The labels of the operator cannot be taken over by a template.
				}}
			})
			eventuallyReady(pss)
			secret := eventuallySecretData(e.ns, "labels", map[string]string{"a": "x"})
			Expect(secret.Labels).To(And(HaveKey("keep"), HaveKey("drop")))

			By("another tool labels the Secret")
			update(secret, func(s *corev1.Secret) {
				s.Labels["added-by-someone"] = "yes"
				s.Annotations["added-by-someone"] = "yes"
			})

			By("removing labels and annotations from the template")
			update(pss, func(p *passwordstorev1alpha1.PasswordStoreSecret) {
				p.Spec.Template.Metadata.Labels = map[string]string{"keep": "1"}
				p.Spec.Template.Metadata.Annotations = map[string]string{"keep-a": "1"}
			})
			eventuallyReady(pss)

			Eventually(func(g Gomega) {
				s, err := getSecret(e.ns, "labels")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(s.Labels).To(And(
					HaveKeyWithValue("keep", "1"),
					HaveKeyWithValue("added-by-someone", "yes"),
					HaveKeyWithValue("app.kubernetes.io/managed-by", "passwordstore-operator"),
					Not(HaveKey("drop")),
				))
				g.Expect(s.Annotations).To(And(
					HaveKeyWithValue("keep-a", "1"),
					HaveKeyWithValue("added-by-someone", "yes"),
					Not(HaveKey("drop-a")),
				))
			}).Should(Succeed())
		})

		It("does not let a template take over the labels of the operator", func() {
			e.entries(map[string]string{"a": "x"})
			e.store("store")
			pss := e.pss("reserved", "store", map[string]string{"a": "a"}, func(p *passwordstorev1alpha1.PasswordStoreSecret) {
				p.Spec.Template = &passwordstorev1alpha1.SecretTemplate{Metadata: passwordstorev1alpha1.SecretTemplateMetadata{
					Labels: map[string]string{"app.kubernetes.io/managed-by": "helm"},
				}}
			})
			eventuallyReady(pss)
			secret, err := getSecret(e.ns, "reserved")
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "passwordstore-operator"))
		})

		It("drops keys that leave spec.data", func() {
			e.entries(map[string]string{"a": "1", "b": "2"})
			e.store("store")
			pss := e.pss("shrinks", "store", map[string]string{"first": "a", "second": "b"})
			eventuallyReady(pss)
			eventuallySecretData(e.ns, "shrinks", map[string]string{"first": "1", "second": "2"})

			update(pss, func(p *passwordstorev1alpha1.PasswordStoreSecret) { p.Spec.Data = map[string]string{"first": "a"} })
			eventuallySecretData(e.ns, "shrinks", map[string]string{"first": "1"})
		})

		It("uses an entry for several keys and finds entries through symbolic links", func() {
			e.entries(map[string]string{"real/entry": "shared\n"})
			e.git.CommitSymlink(GinkgoT(), "alias", "aliases/entry.gpg", "../real/entry.gpg")
			e.store("store")
			pss := e.pss("links", "store", map[string]string{"one": "real/entry", "two": "real/entry", "via-link": "aliases/entry"})
			eventuallyReady(pss)
			eventuallySecretData(e.ns, "links", map[string]string{"one": "shared", "two": "shared", "via-link": "shared"})
		})
	})

	Describe("staying up to date", func() {
		It("makes the Secret right again when it is deleted", func() {
			e.entries(map[string]string{"a": "x"})
			e.store("store")
			pss := e.pss("restored", "store", map[string]string{"a": "a"})
			eventuallyReady(pss)
			original := eventuallySecretData(e.ns, "restored", map[string]string{"a": "x"})

			Expect(k8sClient.Delete(ctx, original)).To(Succeed())

			Eventually(func(g Gomega) {
				s, err := getSecret(e.ns, "restored")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(s.UID).NotTo(Equal(original.UID), "a new Secret")
				g.Expect(string(s.Data["a"])).To(Equal("x"))
			}, 30*time.Second).Should(Succeed())
		})

		It("reverts changes made to the Secret, also keys that were added", func() {
			e.entries(map[string]string{"a": "x"})
			e.store("store")
			eventuallyReady(e.pss("reverted", "store", map[string]string{"a": "a"}))
			secret := eventuallySecretData(e.ns, "reverted", map[string]string{"a": "x"})

			update(secret, func(s *corev1.Secret) {
				s.Data["a"] = []byte("tampered")
				s.Data["extra"] = []byte("added")
			})

			eventuallySecretData(e.ns, "reverted", map[string]string{"a": "x"})
		})

		It("renders the Secret again soon after its store has a new commit", func() {
			e.entries(map[string]string{"a": "one"})
			store := e.store("store")
			pss := e.pss("follows", "store", map[string]string{"a": "a"})
			eventuallyReady(pss)
			eventuallySecretData(e.ns, "follows", map[string]string{"a": "one"})

			// The store is asked to look at its repository again, here by a change of its spec,
			// and the Secrets that use it follow, without waiting for their own refresh.
			second := e.entries(map[string]string{"a": "two"})
			update(store, func(s *passwordstorev1alpha1.PasswordStore) { s.Spec.GitRepo.Branch = "main" })

			Eventually(func(g Gomega) {
				secret, err := getSecret(e.ns, "follows")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(string(secret.Data["a"])).To(Equal("two"))
			}, 30*time.Second).Should(Succeed())
			Eventually(func() string {
				Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pss), pss)).To(Succeed())
				return pss.Status.Revision
			}).Should(Equal(second))
		})

		It("looks for new commits itself at its refresh interval, and leaves the Secret alone when there is none", func() {
			e.entries(map[string]string{"a": "one"})
			// The store does not look again during the test, only the Secret can notice.
			e.store("store")
			pss := e.pss("refreshes", "store", map[string]string{"a": "a"}, func(p *passwordstorev1alpha1.PasswordStoreSecret) {
				p.Spec.RefreshInterval = &metav1.Duration{Duration: 10 * time.Second}
			})
			eventuallyReady(pss)
			secret := eventuallySecretData(e.ns, "refreshes", map[string]string{"a": "one"})
			first := pss.Status.LastRefreshTime.Time

			By("refreshing when there is nothing new, which writes nothing to the Secret")
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pss), pss)).To(Succeed())
				g.Expect(pss.Status.LastRefreshTime.Time).To(BeTemporally(">", first), "a refresh has happened")
			}, 45*time.Second).Should(Succeed())
			unchanged, err := getSecret(e.ns, "refreshes")
			Expect(err).NotTo(HaveOccurred())
			Expect(unchanged.ResourceVersion).To(Equal(secret.ResourceVersion),
				"the Secret is only written when its content changes, or the API server is written to every refresh")

			By("noticing a new commit")
			before := pss.Status.LastRefreshTime.Time
			second := e.entries(map[string]string{"a": "two"})

			Eventually(func(g Gomega) {
				secret, err := getSecret(e.ns, "refreshes")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(string(secret.Data["a"])).To(Equal("two"))
			}, 45*time.Second).Should(Succeed())
			// The Secret is written first and the status after it, so the status is waited for too.
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pss), pss)).To(Succeed())
				g.Expect(pss.Status.Revision).To(Equal(second))
				g.Expect(pss.Status.LastRefreshTime.Time).To(BeTemporally(">", before))
			}).Should(Succeed())
		})
	})

	Describe("when it cannot render the Secret", func() {
		It("reports every entry that is missing, makes no Secret, and recovers when they are added", func() {
			e.entries(map[string]string{"present": "x"})
			e.store("store")
			pss := e.pss("missing", "store", map[string]string{
				"ok": "present", "first": "absent/one", "second": "absent/two",
			})

			c := eventuallyNotReady(pss, passwordstorev1alpha1.ReasonEntryNotFound)
			Expect(c.Message).To(And(
				ContainSubstring(`data["first"]`), ContainSubstring("absent/one"),
				ContainSubstring(`data["second"]`), ContainSubstring("absent/two"),
				Not(ContainSubstring(`data["ok"]`)),
			))
			consistentlyNoSecret(e.ns, "missing", 2*time.Second)

			e.entries(map[string]string{"absent/one": "1", "absent/two": "2"})
			eventuallyReady(pss)
			eventuallySecretData(e.ns, "missing", map[string]string{"ok": "x", "first": "1", "second": "2"})
		})

		It("leaves the Secret as it is when an entry disappears", func() {
			e.entries(map[string]string{"a": "x", "b": "y"})
			e.store("store")
			pss := e.pss("keeps", "store", map[string]string{"a": "a", "b": "b"})
			eventuallyReady(pss)
			eventuallySecretData(e.ns, "keeps", map[string]string{"a": "x", "b": "y"})
			good := pss.Status.Revision

			e.commit(map[string]*string{"b": nil})
			// A change of the spec makes the PasswordStoreSecret look at the store again.
			update(pss, func(p *passwordstorev1alpha1.PasswordStoreSecret) { p.Spec.Data["c"] = "a" })

			eventuallyNotReady(pss, passwordstorev1alpha1.ReasonEntryNotFound)
			Consistently(func(g Gomega) {
				secret, err := getSecret(e.ns, "keeps")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(secret.Data).To(HaveKeyWithValue("b", []byte("y")), "the last good content stays")
				g.Expect(secret.Data).NotTo(HaveKey("c"), "nothing of the new spec is applied")
			}, 2*time.Second, eventuallyInterval).Should(Succeed())
			Expect(pss.Status.Revision).To(Equal(good), "the revision that the Secret is made from is unchanged")
		})

		It("reports an entry that is not encrypted to the key of the store", func() {
			stranger := testutil.NewPGPKey(GinkgoT(), "stranger@example.com")
			e.git.Commit(GinkgoT(), "foreign", map[string][]byte{"foreign.gpg": testutil.Encrypt(GinkgoT(), "x", stranger)})
			e.store("store")
			pss := e.pss("foreign", "store", map[string]string{"a": "foreign"})

			c := eventuallyNotReady(pss, passwordstorev1alpha1.ReasonDecryptFailed)
			Expect(c.Message).To(And(ContainSubstring("foreign"), ContainSubstring("not encrypted to the configured key")))
			consistentlyNoSecret(e.ns, "foreign", time.Second)
		})

		It("reports an entry that is not an OpenPGP message", func() {
			e.git.Commit(GinkgoT(), "plain", map[string][]byte{"plain.gpg": []byte("this is not encrypted")})
			e.store("store")
			c := eventuallyNotReady(e.pss("plain", "store", map[string]string{"a": "plain"}), passwordstorev1alpha1.ReasonDecryptFailed)
			Expect(c.Message).To(ContainSubstring("plain"))
		})

		It("reports a line or field that the entry does not have", func() {
			e.entries(map[string]string{"login": "pw\nusername: bob\n"})
			e.store("store")
			pss := e.pss("selectors", "store", map[string]string{
				"ok": "login#username", "line": "login#9", "field": "login#email",
			})
			c := eventuallyNotReady(pss, passwordstorev1alpha1.ReasonEntryNotFound)
			Expect(c.Message).To(And(
				ContainSubstring(`data["line"]`), ContainSubstring("no line 9"),
				ContainSubstring(`data["field"]`), ContainSubstring(`no field "email"`),
			))
		})

		It("reports references that are not valid, all at once", func() {
			e.entries(map[string]string{"a": "x"})
			e.store("store")
			pss := e.pss("invalid", "store", map[string]string{"one": "../outside", "two": "a//b", "three": "a#"})
			c := eventuallyNotReady(pss, passwordstorev1alpha1.ReasonInvalidSpec)
			Expect(c.Message).To(And(ContainSubstring(`data["one"]`), ContainSubstring(`data["two"]`), ContainSubstring(`data["three"]`)))
			consistentlyNoSecret(e.ns, "invalid", time.Second)
		})

		It("does not read outside of the store through a symbolic link", func() {
			e.entries(map[string]string{"inside": "x"})
			e.git.CommitSymlink(GinkgoT(), "link", "escape.gpg", "../../../etc/passwd")
			e.store("store")
			pss := e.pss("escape", "store", map[string]string{"a": "escape"})
			c := eventuallyNotReady(pss, passwordstorev1alpha1.ReasonEntryNotFound)
			Expect(c.Message).To(ContainSubstring("leaves the store"))
		})

		It("waits for a store that does not exist yet", func() {
			e.entries(map[string]string{"a": "x"})
			pss := e.pss("early", "store", map[string]string{"a": "a"})
			c := eventuallyNotReady(pss, passwordstorev1alpha1.ReasonStoreNotFound)
			Expect(c.Message).To(ContainSubstring(`"store"`))

			e.store("store")
			eventuallyReady(pss)
			eventuallySecretData(e.ns, "early", map[string]string{"a": "x"})
		})

		It("reports a store that cannot be used, with the reason of the store", func() {
			e.entries(map[string]string{"a": "x"})
			e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) { s.GPG.ID = "nobody@example.com" })
			c := eventuallyNotReady(e.pss("broken", "store", map[string]string{"a": "a"}), passwordstorev1alpha1.ReasonGPGKeyInvalid)
			Expect(c.Message).To(ContainSubstring(e.key.Fingerprint))
		})

		It("does not use a store of another namespace", func() {
			other := newEnv()
			other.entries(map[string]string{"a": "x"})
			other.store("foreign-store")

			// The store exists, but not in the namespace of the PasswordStoreSecret.
			pss := e.pss("cross", "foreign-store", map[string]string{"a": "a"})
			eventuallyNotReady(pss, passwordstorev1alpha1.ReasonStoreNotFound)
		})
	})

	Describe("a Secret that already exists", func() {
		It("is not overwritten when it does not belong to the PasswordStoreSecret", func() {
			e.entries(map[string]string{"a": "from-the-store"})
			e.store("store")
			e.secret("taken", map[string]string{"important": "do-not-lose-me"})

			pss := e.pss("taken", "store", map[string]string{"a": "a"})
			c := eventuallyNotReady(pss, passwordstorev1alpha1.ReasonSecretConflict)
			Expect(c.Message).To(ContainSubstring(passwordstorev1alpha1.ManagedAnnotation))

			Consistently(func(g Gomega) {
				s, err := getSecret(e.ns, "taken")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(s.Data).To(Equal(map[string][]byte{"important": []byte("do-not-lose-me")}))
				g.Expect(s.OwnerReferences).To(BeEmpty())
			}, 2*time.Second, eventuallyInterval).Should(Succeed())
		})

		It("is taken over when it says so", func() {
			e.entries(map[string]string{"a": "from-the-store"})
			e.store("store")
			existing := e.secret("adopted", map[string]string{"old-key": "old-value"})
			update(existing, func(s *corev1.Secret) {
				s.Annotations = map[string]string{passwordstorev1alpha1.ManagedAnnotation: "true"}
			})

			pss := e.pss("adopted", "store", map[string]string{"a": "a"})
			eventuallyReady(pss)

			secret := eventuallySecretData(e.ns, "adopted", map[string]string{"a": "from-the-store"})
			Expect(secret.OwnerReferences).To(HaveLen(1))
			Expect(secret.OwnerReferences[0].UID).To(Equal(pss.UID))
		})

		It("is not taken over when another controller owns it", func() {
			e.entries(map[string]string{"a": "x"})
			e.store("store")
			owner := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: e.ns, Name: "owner"}}
			Expect(k8sClient.Create(ctx, owner)).To(Succeed())
			Expect(k8sClient.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: e.ns, Name: "owned",
					Annotations: map[string]string{passwordstorev1alpha1.ManagedAnnotation: "true"},
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: "v1", Kind: "ConfigMap", Name: "owner", UID: owner.UID, Controller: new(true),
					}},
				},
				StringData: map[string]string{"k": "v"},
			})).To(Succeed())

			c := eventuallyNotReady(e.pss("owned", "store", map[string]string{"a": "a"}), passwordstorev1alpha1.ReasonSecretConflict)
			Expect(c.Message).To(ContainSubstring("controlled by ConfigMap"))
		})

		It("keeps its type, which Kubernetes does not let change", func() {
			e.entries(map[string]string{"a": "x"})
			e.store("store")
			pss := e.pss("typed", "store", map[string]string{"a": "a"})
			eventuallyReady(pss)
			eventuallySecretData(e.ns, "typed", map[string]string{"a": "x"})

			update(pss, func(p *passwordstorev1alpha1.PasswordStoreSecret) {
				p.Spec.Template = &passwordstorev1alpha1.SecretTemplate{Type: "example.com/custom"}
			})
			c := eventuallyNotReady(pss, passwordstorev1alpha1.ReasonSecretApplyFailed)
			Expect(c.Message).To(And(ContainSubstring("Opaque"), ContainSubstring("example.com/custom"), ContainSubstring("delete the Secret")))

			By("deleting the Secret, as the message says, which makes it again with the new type")
			secret, err := getSecret(e.ns, "typed")
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Type).To(Equal(corev1.SecretTypeOpaque))
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			eventuallyReady(pss)
			Eventually(func(g Gomega) {
				s, err := getSecret(e.ns, "typed")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(s.Type).To(Equal(corev1.SecretType("example.com/custom")))
			}).Should(Succeed())
		})

		It("reports a Secret that Kubernetes refuses", func() {
			e.entries(map[string]string{"a": "x"})
			e.store("store")
			// A TLS Secret needs tls.crt and tls.key.
			pss := e.pss("invalid-tls", "store", map[string]string{"a": "a"}, func(p *passwordstorev1alpha1.PasswordStoreSecret) {
				p.Spec.Template = &passwordstorev1alpha1.SecretTemplate{Type: string(corev1.SecretTypeTLS)}
			})
			c := eventuallyNotReady(pss, passwordstorev1alpha1.ReasonSecretApplyFailed)
			Expect(c.Message).To(ContainSubstring("tls.crt"))
		})
	})

	Describe("with a ClusterPasswordStore", func() {
		It("renders a Secret in the namespace of the PasswordStoreSecret", func() {
			e.entries(map[string]string{"shared/token": "cluster-wide\n"})
			e.clusterStore("shared-" + e.ns)

			pss := e.pss("from-cluster", "shared-"+e.ns, map[string]string{"token": "shared/token"},
				func(p *passwordstorev1alpha1.PasswordStoreSecret) { p.Spec.StoreRef.Kind = "ClusterPasswordStore" })
			eventuallyReady(pss)
			eventuallySecretData(e.ns, "from-cluster", map[string]string{"token": "cluster-wide"})
		})

		It("is used from another namespace than the one that holds its credentials", func() {
			e.entries(map[string]string{"shared/token": "cluster-wide\n"})
			e.clusterStore("shared-" + e.ns)

			user := newEnv()
			pss := user.pss("elsewhere", "shared-"+e.ns, map[string]string{"token": "shared/token"},
				func(p *passwordstorev1alpha1.PasswordStoreSecret) { p.Spec.StoreRef.Kind = "ClusterPasswordStore" })
			eventuallyReady(pss)
			eventuallySecretData(user.ns, "elsewhere", map[string]string{"token": "cluster-wide"})
		})

		It("is not found when it does not exist", func() {
			pss := e.pss("nothing", "no-such-store", map[string]string{"a": "a"},
				func(p *passwordstorev1alpha1.PasswordStoreSecret) { p.Spec.StoreRef.Kind = "ClusterPasswordStore" })
			c := eventuallyNotReady(pss, passwordstorev1alpha1.ReasonStoreNotFound)
			Expect(c.Message).To(ContainSubstring("ClusterPasswordStore"))
		})

		It("only serves the namespaces that its selector allows", func() {
			e.entries(map[string]string{"shared/token": "cluster-wide\n"})
			name := "restricted-" + e.ns
			e.clusterStore(name, func(s *passwordstorev1alpha1.ClusterPasswordStoreSpec) {
				s.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "payments"}}
			})

			pss := e.pss("gated", name, map[string]string{"token": "shared/token"},
				func(p *passwordstorev1alpha1.PasswordStoreSecret) { p.Spec.StoreRef.Kind = "ClusterPasswordStore" })
			c := eventuallyNotReady(pss, passwordstorev1alpha1.ReasonNamespaceNotAllowed)
			Expect(c.Message).To(And(ContainSubstring(name), ContainSubstring(e.ns)))
			consistentlyNoSecret(e.ns, "gated", time.Second)

			By("labeling the namespace so that the selector matches, which the PasswordStoreSecret notices")
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: e.ns}}
			update(ns, func(n *corev1.Namespace) { n.Labels = map[string]string{"team": "payments"} })
			eventuallyReady(pss)
			eventuallySecretData(e.ns, "gated", map[string]string{"token": "cluster-wide"})

			By("removing the label again")
			update(ns, func(n *corev1.Namespace) { n.Labels = nil })
			eventuallyNotReady(pss, passwordstorev1alpha1.ReasonNamespaceNotAllowed)
		})

		It("allows every namespace when the selector is empty", func() {
			e.entries(map[string]string{"shared/token": "cluster-wide\n"})
			name := "everyone-" + e.ns
			e.clusterStore(name, func(s *passwordstorev1alpha1.ClusterPasswordStoreSpec) {
				s.NamespaceSelector = &metav1.LabelSelector{}
			})
			pss := e.pss("open", name, map[string]string{"token": "shared/token"},
				func(p *passwordstorev1alpha1.PasswordStoreSecret) { p.Spec.StoreRef.Kind = "ClusterPasswordStore" })
			eventuallyReady(pss)
		})

		It("selects namespaces with expressions too", func() {
			e.entries(map[string]string{"shared/token": "cluster-wide\n"})
			name := "expr-" + e.ns
			e.clusterStore(name, func(s *passwordstorev1alpha1.ClusterPasswordStoreSpec) {
				s.NamespaceSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "kubernetes.io/metadata.name", Operator: metav1.LabelSelectorOpIn, Values: []string{e.ns}},
				}}
			})
			eventuallyReady(e.pss("by-name", name, map[string]string{"token": "shared/token"},
				func(p *passwordstorev1alpha1.PasswordStoreSecret) { p.Spec.StoreRef.Kind = "ClusterPasswordStore" }))

			other := newEnv()
			eventuallyNotReady(other.pss("by-name", name, map[string]string{"token": "shared/token"},
				func(p *passwordstorev1alpha1.PasswordStoreSecret) { p.Spec.StoreRef.Kind = "ClusterPasswordStore" }),
				passwordstorev1alpha1.ReasonNamespaceNotAllowed)
		})
	})

	It("records events for what happens to it", func() {
		e.entries(map[string]string{"a": "x"})
		e.store("store")
		pss := e.pss("evented", "store", map[string]string{"a": "absent"})
		eventuallyNotReady(pss, passwordstorev1alpha1.ReasonEntryNotFound)

		Eventually(func(g Gomega) {
			var events corev1.EventList
			g.Expect(k8sClient.List(ctx, &events, client.InNamespace(e.ns))).To(Succeed())
			var reasons []string
			for _, ev := range events.Items {
				if ev.InvolvedObject.Name == "evented" {
					reasons = append(reasons, ev.Reason)
				}
			}
			g.Expect(reasons).To(ContainElement(passwordstorev1alpha1.ReasonEntryNotFound))
		}).Should(Succeed())
	})
})
