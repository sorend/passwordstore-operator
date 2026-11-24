package controller

import (
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
	"github.com/sorend/passwordstore-operator/internal/testutil"
)

var _ = Describe("PasswordStore", func() {
	It("becomes Ready and reports what it fetched", func() {
		e := newEnv()
		commit := e.entries(map[string]string{"k8s/db/admin": "hunter2\n"})

		store := e.store("store")
		eventuallyReady(store)

		Expect(store.Status.Revision).To(Equal(commit))
		Expect(store.Status.GPGFingerprint).To(Equal(e.key.Fingerprint))
		Expect(store.Status.LastSyncTime).NotTo(BeNil())
		Expect(store.Status.ObservedGeneration).To(Equal(store.Generation))
		Expect(conditionOf(store).Message).To(ContainSubstring(commit[:7]))
	})

	It("reads a store that lives in a subdirectory and a branch", func() {
		e := newEnv()
		e.entries(map[string]string{"unrelated": "y"}) // a branch needs a commit to start from
		e.git.Checkout(GinkgoT(), "release")
		commit := e.entries(map[string]string{"infra/pass/a": "x"})
		e.git.Checkout(GinkgoT(), "main")
		e.entries(map[string]string{"unrelated-too": "z"})

		store := e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) {
			s.GitRepo.Branch = "release"
			s.GitRepo.Path = "infra/pass"
		})
		eventuallyReady(store)
		Expect(store.Status.Revision).To(Equal(commit))
	})

	Context("with a token", func() {
		var e *env

		BeforeEach(func() {
			e = newEnv(testutil.WithBasicAuth("x-access-token", "ghp_s3cr3t_t0ken"))
			e.entries(map[string]string{"a": "x"})
		})

		withToken := func(secret string) func(*passwordstorev1alpha1.PasswordStoreSpec) {
			return func(s *passwordstorev1alpha1.PasswordStoreSpec) {
				s.GitRepo.Auth = &passwordstorev1alpha1.GitAuth{Token: &passwordstorev1alpha1.GitTokenAuth{
					TokenSecretRef: passwordstorev1alpha1.SecretKeySelector{Name: secret},
				}}
			}
		}

		It("authenticates, also when the token has a trailing newline", func() {
			// What "kubectl create secret --from-file" makes of a file that ends in a newline.
			e.secret("git-token", map[string]string{"token": "ghp_s3cr3t_t0ken\n"})
			eventuallyReady(e.store("store", withToken("git-token")))
		})

		It("reports a token that is refused, without repeating it, and recovers when it is fixed", func() {
			secret := e.secret("git-token", map[string]string{"token": "ghp_wrong_t0ken"})
			store := e.store("store", withToken("git-token"))

			c := eventuallyNotReady(store, passwordstorev1alpha1.ReasonGitSyncFailed)
			Expect(c.Message).NotTo(ContainSubstring("ghp_wrong_t0ken"))
			Expect(store.Status.Revision).To(BeEmpty())

			secret.Data = map[string][]byte{"token": []byte("ghp_s3cr3t_t0ken")}
			Expect(k8sClient.Update(ctx, secret)).To(Succeed())
			eventuallyReady(store)
		})

		It("reports an anonymous clone of a private repository", func() {
			c := eventuallyNotReady(e.store("store"), passwordstorev1alpha1.ReasonGitSyncFailed)
			Expect(c.Message).To(ContainSubstring("authentication required"))
		})

		It("uses the user name and the key it is given", func() {
			custom := newEnv(testutil.WithBasicAuth("oauth2", "tok-from-custom-key"))
			custom.entries(map[string]string{"a": "x"})
			custom.secret("git-token", map[string]string{"mytoken": "tok-from-custom-key"})
			store := custom.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) {
				s.GitRepo.Auth = &passwordstorev1alpha1.GitAuth{Token: &passwordstorev1alpha1.GitTokenAuth{
					Username:       "oauth2",
					TokenSecretRef: passwordstorev1alpha1.SecretKeySelector{Name: "git-token", Key: "mytoken"},
				}}
			})
			eventuallyReady(store)
		})
	})

	Context("with credentials that cannot be read", func() {
		It("waits for a Secret that does not exist yet", func() {
			e := newEnv()
			e.entries(map[string]string{"a": "x"})
			store := e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) {
				s.GPG.PrivateKeySecretRef.Name = "later"
			})

			c := eventuallyNotReady(store, passwordstorev1alpha1.ReasonCredentialsUnavailable)
			Expect(c.Message).To(And(ContainSubstring(e.ns+"/later"), ContainSubstring("not found")))

			e.secret("later", map[string]string{"private.key": string(e.key.Private)})
			eventuallyReady(store)
		})

		It("names the keys that a Secret has when the one that is needed is missing", func() {
			e := newEnv()
			e.entries(map[string]string{"a": "x"})
			e.secret("wrong-keys", map[string]string{"key.asc": "x", "other": "y"})
			store := e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) {
				s.GPG.PrivateKeySecretRef.Name = "wrong-keys"
			})

			c := eventuallyNotReady(store, passwordstorev1alpha1.ReasonCredentialsUnavailable)
			Expect(c.Message).To(And(ContainSubstring(`"private.key"`), ContainSubstring(`"key.asc"`), ContainSubstring(`"other"`)))
		})

		It("uses the key that is named in the reference", func() {
			e := newEnv()
			e.entries(map[string]string{"a": "x"})
			e.secret("named", map[string]string{"my-gpg-key": string(e.key.Private)})
			store := e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) {
				s.GPG.PrivateKeySecretRef = passwordstorev1alpha1.SecretKeySelector{Name: "named", Key: "my-gpg-key"}
			})
			eventuallyReady(store)
		})

		It("refuses a Secret in another namespace", func() {
			e := newEnv()
			e.entries(map[string]string{"a": "x"})
			store := e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) {
				s.GPG.PrivateKeySecretRef.Namespace = "kube-system"
			})

			c := eventuallyNotReady(store, passwordstorev1alpha1.ReasonInvalidSpec)
			Expect(c.Message).To(ContainSubstring("own namespace"))
		})

		It("accepts the namespace of the store in a reference", func() {
			e := newEnv()
			e.entries(map[string]string{"a": "x"})
			store := e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) {
				s.GPG.PrivateKeySecretRef.Namespace = e.ns
			})
			eventuallyReady(store)
		})
	})

	Context("with a GPG key", func() {
		It("reports an id that matches none of the keys, and lists the keys it has", func() {
			e := newEnv()
			e.entries(map[string]string{"a": "x"})
			store := e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) { s.GPG.ID = "someone-else@example.com" })

			c := eventuallyNotReady(store, passwordstorev1alpha1.ReasonGPGKeyInvalid)
			Expect(c.Message).To(ContainSubstring(e.key.Fingerprint))
		})

		It("selects the key by fingerprint", func() {
			e := newEnv()
			e.entries(map[string]string{"a": "x"})
			eventuallyReady(e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) { s.GPG.ID = e.key.Fingerprint }))
		})

		It("needs the passphrase of a protected key", func() {
			e := newEnv()
			e.entries(map[string]string{"a": "x"})
			locked := testutil.NewPGPKey(GinkgoT(), "locked@example.com", testutil.WithPassphrase("open sesame"))
			e.secret("locked-key", map[string]string{"private.key": string(locked.Private)})
			e.secret("locked-pass", map[string]string{"passphrase": "open sesame\n"})
			use := func(passphrase bool) func(*passwordstorev1alpha1.PasswordStoreSpec) {
				return func(s *passwordstorev1alpha1.PasswordStoreSpec) {
					s.GPG.ID = "locked@example.com"
					s.GPG.PrivateKeySecretRef.Name = "locked-key"
					if passphrase {
						s.GPG.PassphraseSecretRef = &passwordstorev1alpha1.SecretKeySelector{Name: "locked-pass"}
					}
				}
			}

			c := eventuallyNotReady(e.store("without", use(false)), passwordstorev1alpha1.ReasonGPGKeyInvalid)
			Expect(c.Message).To(ContainSubstring("passphrase"))

			withPassphrase := e.store("with", use(true))
			eventuallyReady(withPassphrase)
			Expect(withPassphrase.Status.GPGFingerprint).To(Equal(locked.Fingerprint))
		})

		It("rejects a public key", func() {
			e := newEnv()
			e.entries(map[string]string{"a": "x"})
			e.secret("public", map[string]string{"private.key": string(e.key.Public)})
			store := e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) { s.GPG.PrivateKeySecretRef.Name = "public" })
			c := eventuallyNotReady(store, passwordstorev1alpha1.ReasonGPGKeyInvalid)
			Expect(c.Message).To(ContainSubstring("no private key"))
		})
	})

	It("reports a repository that cannot be fetched and recovers when it can", func() {
		e := newEnv()
		// No commits yet, which Git reports as an empty repository.
		store := e.store("store")
		eventuallyNotReady(store, passwordstorev1alpha1.ReasonGitSyncFailed)

		commit := e.entries(map[string]string{"a": "x"})
		eventuallyReady(store)
		Expect(store.Status.Revision).To(Equal(commit))
	})

	It("reports a path that is not in the repository", func() {
		e := newEnv()
		e.entries(map[string]string{"a": "x"})
		store := e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) { s.GitRepo.Path = "no/such/dir" })
		c := eventuallyNotReady(store, passwordstorev1alpha1.ReasonGitSyncFailed)
		Expect(c.Message).To(ContainSubstring("no/such/dir"))
	})

	It("checks its repository again when its spec changes", func() {
		e := newEnv()
		first := e.entries(map[string]string{"a": "one"})
		store := e.store("store")
		eventuallyReady(store)
		Expect(store.Status.Revision).To(Equal(first))

		second := e.entries(map[string]string{"a": "two"})
		Eventually(func() error {
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(store), store)).To(Succeed())
			store.Spec.GitRepo.Branch = "main"
			return k8sClient.Update(ctx, store)
		}).Should(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(store), store)).To(Succeed())
			g.Expect(store.Status.Revision).To(Equal(second))
			g.Expect(store.Status.ObservedGeneration).To(Equal(store.Generation))
		}).Should(Succeed())
	})

	It("records events for what happens to it", func() {
		e := newEnv()
		e.entries(map[string]string{"a": "x"})
		store := e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) { s.GPG.ID = "nobody@example.com" })
		eventuallyNotReady(store, passwordstorev1alpha1.ReasonGPGKeyInvalid)

		Eventually(func(g Gomega) {
			var events corev1.EventList
			g.Expect(k8sClient.List(ctx, &events, client.InNamespace(e.ns))).To(Succeed())
			var reasons []string
			for _, ev := range events.Items {
				if ev.InvolvedObject.Name == "store" && ev.Type == corev1.EventTypeWarning {
					reasons = append(reasons, ev.Reason)
				}
			}
			g.Expect(reasons).To(ContainElement(passwordstorev1alpha1.ReasonGPGKeyInvalid))
		}).Should(Succeed())
	})

	Context("over SSH", func() {
		var (
			e   *env
			ssh *testutil.SSHServer
			key *testutil.SSHKey
		)

		BeforeEach(func() {
			e = newEnv()
			e.entries(map[string]string{"a": "x"})
			key = testutil.NewSSHKey(GinkgoT())
			ssh = testutil.NewSSHServer(GinkgoT(), e.git.Root, key.Public)
		})

		useSSH := func(knownHosts string, insecure bool) func(*passwordstorev1alpha1.PasswordStoreSpec) {
			return func(s *passwordstorev1alpha1.PasswordStoreSpec) {
				s.GitRepo.URL = ssh.URL("store")
				s.GitRepo.Auth = &passwordstorev1alpha1.GitAuth{SSH: &passwordstorev1alpha1.GitSSHAuth{
					PrivateKeySecretRef:   passwordstorev1alpha1.SecretKeySelector{Name: "ssh-key"},
					KnownHosts:            knownHosts,
					InsecureIgnoreHostKey: insecure,
				}}
			}
		}

		It("authenticates with a key and verifies the host key", func() {
			e.secret("ssh-key", map[string]string{"ssh-privatekey": string(key.Private)})
			eventuallyReady(e.store("store", useSSH(ssh.KnownHosts, false)))
			Expect(ssh.Sessions()).To(BeNumerically(">", 0))
		})

		It("refuses a server whose host key is not the one in knownHosts", func() {
			e.secret("ssh-key", map[string]string{"ssh-privatekey": string(key.Private)})
			other := testutil.NewSSHServer(GinkgoT(), e.git.Root, key.Public)
			// The key of another server for the address of this one.
			wrong := strings.Replace(other.KnownHosts, "["+other.Host+"]:"+strconv.Itoa(other.Port), "["+ssh.Host+"]:"+strconv.Itoa(ssh.Port), 1)

			c := eventuallyNotReady(e.store("store", useSSH(wrong, false)), passwordstorev1alpha1.ReasonGitSyncFailed)
			Expect(c.Message).To(ContainSubstring("knownHosts"))
		})

		It("accepts any host key when told to", func() {
			e.secret("ssh-key", map[string]string{"ssh-privatekey": string(key.Private)})
			eventuallyReady(e.store("store", useSSH("", true)))
		})

		It("unlocks a key with a passphrase", func() {
			protected := testutil.NewSSHKey(GinkgoT(), testutil.WithSSHPassphrase("open sesame"))
			ssh = testutil.NewSSHServer(GinkgoT(), e.git.Root, protected.Public)
			e.secret("ssh-key", map[string]string{"ssh-privatekey": string(protected.Private), "passphrase": "open sesame"})
			store := e.store("store", useSSH(ssh.KnownHosts, false), func(s *passwordstorev1alpha1.PasswordStoreSpec) {
				s.GitRepo.Auth.SSH.PassphraseSecretRef = &passwordstorev1alpha1.SecretKeySelector{Name: "ssh-key"}
			})
			eventuallyReady(store)
		})
	})

	Context("as a GitHub App", func() {
		It("exchanges the key of the app for a token", func() {
			pemKey, rsaKey := testutil.NewRSAKeyPEM(GinkgoT())
			github := testutil.NewFakeGitHubApp(GinkgoT(), 1234, 5678, &rsaKey.PublicKey)
			e := newEnv(testutil.WithAuth(func(user, password string) bool {
				return user == "x-access-token" && github.IsValidToken(password)
			}))
			e.entries(map[string]string{"a": "x"})
			e.secret("app-key", map[string]string{"private-key.pem": string(pemKey)})

			store := e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) {
				s.GitRepo.Auth = &passwordstorev1alpha1.GitAuth{App: &passwordstorev1alpha1.GitAppAuth{
					AppID:               1234,
					InstallationID:      5678,
					PrivateKeySecretRef: passwordstorev1alpha1.SecretKeySelector{Name: "app-key"},
					BaseURL:             github.URL,
				}}
			})
			eventuallyReady(store)
			Expect(github.Requests()).To(Equal(1))
		})

		It("reports what GitHub says when it refuses the app", func() {
			pemKey, rsaKey := testutil.NewRSAKeyPEM(GinkgoT())
			github := testutil.NewFakeGitHubApp(GinkgoT(), 1234, 5678, &rsaKey.PublicKey)
			github.Fail(404, "Integration not found")
			e := newEnv()
			e.entries(map[string]string{"a": "x"})
			e.secret("app-key", map[string]string{"private-key.pem": string(pemKey)})

			store := e.store("store", func(s *passwordstorev1alpha1.PasswordStoreSpec) {
				s.GitRepo.Auth = &passwordstorev1alpha1.GitAuth{App: &passwordstorev1alpha1.GitAppAuth{
					AppID: 1234, InstallationID: 5678, BaseURL: github.URL,
					PrivateKeySecretRef: passwordstorev1alpha1.SecretKeySelector{Name: "app-key"},
				}}
			})
			c := eventuallyNotReady(store, passwordstorev1alpha1.ReasonGitSyncFailed)
			Expect(c.Message).To(ContainSubstring("Integration not found"))
		})
	})

	It("keeps the previous revision in its status while it cannot fetch", func() {
		e := newEnv()
		commit := e.entries(map[string]string{"a": "x"})
		store := e.store("store")
		eventuallyReady(store)

		// A change of the spec that makes the store unusable.
		Eventually(func() error {
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(store), store)).To(Succeed())
			store.Spec.GPG.ID = "nobody@example.com"
			return k8sClient.Update(ctx, store)
		}).Should(Succeed())
		eventuallyNotReady(store, passwordstorev1alpha1.ReasonGPGKeyInvalid)

		Expect(store.Status.Revision).To(Equal(commit), "the last revision that was fetched is still of interest")
		Expect(store.Status.LastSyncTime).NotTo(BeNil())
		Expect(time.Since(store.Status.LastSyncTime.Time)).To(BeNumerically("<", time.Minute))
	})
})
