package controller

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
)

// These specs check what the API server does with the CRDs, so mistakes in a spec are refused
// when it is applied, and not found out later in a condition.

var _ = Describe("CRD validation", func() {
	var ns string

	BeforeEach(func() { ns = newNamespace() })

	gpg := passwordstorev1alpha1.GPGSpec{
		ID:                  "store@example.com",
		PrivateKeySecretRef: passwordstorev1alpha1.SecretKeySelector{Name: "gpg-key"},
	}
	keyRef := passwordstorev1alpha1.SecretKeySelector{Name: "creds"}
	knownHost := "git.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

	newStore := func(mutate func(*passwordstorev1alpha1.GitRepoSpec)) *passwordstorev1alpha1.PasswordStore {
		repo := passwordstorev1alpha1.GitRepoSpec{URL: "https://git.example.com/org/pass.git"}
		mutate(&repo)
		return &passwordstorev1alpha1.PasswordStore{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, GenerateName: "v-"},
			Spec:       passwordstorev1alpha1.PasswordStoreSpec{GitRepo: repo, GPG: gpg},
		}
	}

	DescribeTable("a PasswordStore with a spec that is accepted",
		func(mutate func(*passwordstorev1alpha1.GitRepoSpec)) {
			store := newStore(mutate)
			Expect(k8sClient.Create(ctx, store)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, store) })
		},
		Entry("anonymous https", func(r *passwordstorev1alpha1.GitRepoSpec) {}),
		Entry("http", func(r *passwordstorev1alpha1.GitRepoSpec) { r.URL = "http://gitea.gitea.svc:3000/org/pass.git" }),
		Entry("https with a port", func(r *passwordstorev1alpha1.GitRepoSpec) { r.URL = "https://git.example.com:8443/org/pass.git" }),
		Entry("a branch and a path", func(r *passwordstorev1alpha1.GitRepoSpec) { r.Branch = "main"; r.Path = "infra/pass" }),
		Entry("a token", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.Auth = &passwordstorev1alpha1.GitAuth{Token: &passwordstorev1alpha1.GitTokenAuth{TokenSecretRef: keyRef}}
		}),
		Entry("a GitHub App", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.Auth = &passwordstorev1alpha1.GitAuth{App: &passwordstorev1alpha1.GitAppAuth{
				AppID: 1, InstallationID: 2, PrivateKeySecretRef: keyRef, BaseURL: "https://ghe.example.com/api/v3",
			}}
		}),
		Entry("ssh:// with host keys", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.URL = "ssh://git@git.example.com:2222/org/pass.git"
			r.Auth = &passwordstorev1alpha1.GitAuth{SSH: &passwordstorev1alpha1.GitSSHAuth{PrivateKeySecretRef: keyRef, KnownHosts: knownHost}}
		}),
		Entry("scp-style with host keys", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.URL = "git@github.com:org/pass.git"
			r.Auth = &passwordstorev1alpha1.GitAuth{SSH: &passwordstorev1alpha1.GitSSHAuth{PrivateKeySecretRef: keyRef, KnownHosts: knownHost}}
		}),
		Entry("scp-style with an absolute path", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.URL = "git@git.example.com:/srv/git/pass.git"
			r.Auth = &passwordstorev1alpha1.GitAuth{SSH: &passwordstorev1alpha1.GitSSHAuth{PrivateKeySecretRef: keyRef, KnownHosts: knownHost}}
		}),
		Entry("secrets that are named with dots and dashes, and in a namespace", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.Auth = &passwordstorev1alpha1.GitAuth{Token: &passwordstorev1alpha1.GitTokenAuth{
				TokenSecretRef: passwordstorev1alpha1.SecretKeySelector{Name: "git-token.v2", Namespace: ns, Key: "my.token_1"},
			}}
		}),
		Entry("ssh without verifying the host key, when it is asked for", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.URL = "git@github.com:org/pass.git"
			r.Auth = &passwordstorev1alpha1.GitAuth{SSH: &passwordstorev1alpha1.GitSSHAuth{PrivateKeySecretRef: keyRef, InsecureIgnoreHostKey: true}}
		}),
	)

	DescribeTable("a PasswordStore with a spec that is refused",
		func(mutate func(*passwordstorev1alpha1.GitRepoSpec), want string) {
			err := k8sClient.Create(ctx, newStore(mutate))
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected a validation error, got: %v", err)
			Expect(err.Error()).To(ContainSubstring(want))
		},
		Entry("a file URL, which would read from the operator", func(r *passwordstorev1alpha1.GitRepoSpec) { r.URL = "file:///var/run/secrets" }, "should match"),
		Entry("a local path", func(r *passwordstorev1alpha1.GitRepoSpec) { r.URL = "/srv/git/pass.git" }, "should match"),
		Entry("the git protocol", func(r *passwordstorev1alpha1.GitRepoSpec) { r.URL = "git://git.example.com/pass.git" }, "should match"),
		Entry("credentials in the URL", func(r *passwordstorev1alpha1.GitRepoSpec) { r.URL = "https://user:secret@git.example.com/pass.git" }, "should match"),
		Entry("a token in the URL", func(r *passwordstorev1alpha1.GitRepoSpec) { r.URL = "https://ghp_token@git.example.com/pass.git" }, "should match"),
		Entry("no URL", func(r *passwordstorev1alpha1.GitRepoSpec) { r.URL = "" }, "url"),
		Entry("an ssh URL without ssh authentication", func(r *passwordstorev1alpha1.GitRepoSpec) { r.URL = "git@github.com:org/pass.git" },
			"ssh and scp-style URLs require auth.ssh"),
		Entry("ssh authentication for an https URL", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.Auth = &passwordstorev1alpha1.GitAuth{SSH: &passwordstorev1alpha1.GitSSHAuth{PrivateKeySecretRef: keyRef, KnownHosts: knownHost}}
		}, "auth.ssh requires an ssh:// or scp-style URL"),
		Entry("a token for an ssh URL", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.URL = "ssh://git@git.example.com/pass.git"
			r.Auth = &passwordstorev1alpha1.GitAuth{Token: &passwordstorev1alpha1.GitTokenAuth{TokenSecretRef: keyRef}}
		}, "require"),
		Entry("a GitHub App for an ssh URL", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.URL = "git@github.com:org/pass.git"
			r.Auth = &passwordstorev1alpha1.GitAuth{App: &passwordstorev1alpha1.GitAppAuth{AppID: 1, InstallationID: 2, PrivateKeySecretRef: keyRef}}
		}, "require"),
		Entry("two authentication methods", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.Auth = &passwordstorev1alpha1.GitAuth{
				Token: &passwordstorev1alpha1.GitTokenAuth{TokenSecretRef: keyRef},
				App:   &passwordstorev1alpha1.GitAppAuth{AppID: 1, InstallationID: 2, PrivateKeySecretRef: keyRef},
			}
		}, "at most one of ssh, token or app may be set"),
		Entry("ssh without host keys", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.URL = "git@github.com:org/pass.git"
			r.Auth = &passwordstorev1alpha1.GitAuth{SSH: &passwordstorev1alpha1.GitSSHAuth{PrivateKeySecretRef: keyRef}}
		}, "knownHosts is required unless insecureIgnoreHostKey is true"),
		Entry("ssh with host keys and without verifying them", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.URL = "git@github.com:org/pass.git"
			r.Auth = &passwordstorev1alpha1.GitAuth{SSH: &passwordstorev1alpha1.GitSSHAuth{
				PrivateKeySecretRef: keyRef, KnownHosts: knownHost, InsecureIgnoreHostKey: true,
			}}
		}, "mutually exclusive"),
		Entry("host keys that are only white space", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.URL = "git@github.com:org/pass.git"
			r.Auth = &passwordstorev1alpha1.GitAuth{SSH: &passwordstorev1alpha1.GitSSHAuth{PrivateKeySecretRef: keyRef, KnownHosts: "  \n \t "}}
		}, "knownHosts is required unless insecureIgnoreHostKey is true"),
		Entry("a URL that looks like a scheme but is none", func(r *passwordstorev1alpha1.GitRepoSpec) { r.URL = "foo://bar/pass.git" }, "should match"),
		Entry("a name of a Secret that is not a name", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.Auth = &passwordstorev1alpha1.GitAuth{Token: &passwordstorev1alpha1.GitTokenAuth{
				TokenSecretRef: passwordstorev1alpha1.SecretKeySelector{Name: "Not_A_Name"},
			}}
		}, "should match"),
		Entry("a namespace of a Secret that is not a name", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.Auth = &passwordstorev1alpha1.GitAuth{Token: &passwordstorev1alpha1.GitTokenAuth{
				TokenSecretRef: passwordstorev1alpha1.SecretKeySelector{Name: "creds", Namespace: "Not.A.Namespace"},
			}}
		}, "should match"),
		Entry("a key of a Secret that cannot be one", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.Auth = &passwordstorev1alpha1.GitAuth{Token: &passwordstorev1alpha1.GitTokenAuth{
				TokenSecretRef: passwordstorev1alpha1.SecretKeySelector{Name: "creds", Key: "has a space"},
			}}
		}, "should match"),
		Entry("a GitHub App without an ID", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.Auth = &passwordstorev1alpha1.GitAuth{App: &passwordstorev1alpha1.GitAppAuth{InstallationID: 2, PrivateKeySecretRef: keyRef}}
		}, "appID"),
		Entry("a GitHub API URL that is not http(s)", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.Auth = &passwordstorev1alpha1.GitAuth{App: &passwordstorev1alpha1.GitAppAuth{
				AppID: 1, InstallationID: 2, PrivateKeySecretRef: keyRef, BaseURL: "ftp://api.example.com",
			}}
		}, "should match"),
		Entry("a token without a Secret", func(r *passwordstorev1alpha1.GitRepoSpec) {
			r.Auth = &passwordstorev1alpha1.GitAuth{Token: &passwordstorev1alpha1.GitTokenAuth{}}
		}, "name"),
	)

	It("refuses a store without a GPG id", func() {
		store := newStore(func(*passwordstorev1alpha1.GitRepoSpec) {})
		store.Spec.GPG.ID = ""
		err := k8sClient.Create(ctx, store)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("gpg.id"))
	})

	Describe("PasswordStoreSecret", func() {
		newPSS := func(mutate func(*passwordstorev1alpha1.PasswordStoreSecretSpec)) *passwordstorev1alpha1.PasswordStoreSecret {
			spec := passwordstorev1alpha1.PasswordStoreSecretSpec{
				StoreRef: passwordstorev1alpha1.StoreReference{Name: "store"},
				Data:     map[string]string{"password": "k8s/db/admin"},
			}
			mutate(&spec)
			return &passwordstorev1alpha1.PasswordStoreSecret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, GenerateName: "v-"}, Spec: spec}
		}

		DescribeTable("accepts",
			func(mutate func(*passwordstorev1alpha1.PasswordStoreSecretSpec)) {
				obj := newPSS(mutate)
				Expect(k8sClient.Create(ctx, obj)).To(Succeed())
				DeferCleanup(func() { _ = k8sClient.Delete(ctx, obj) })
			},
			Entry("the shortest refresh interval", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) {
				s.RefreshInterval = &metav1.Duration{Duration: 10_000_000_000}
			}),
			Entry("a ClusterPasswordStore", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) { s.StoreRef.Kind = "ClusterPasswordStore" }),
			Entry("keys with dots, dashes and underscores", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) {
				s.Data = map[string]string{"tls.crt": "a", "tls.key": "b", ".dockerconfigjson": "c", "MY_KEY-1": "d"}
			}),
			Entry("keys that start with a single dot, or have two in the middle", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) {
				s.Data = map[string]string{".hidden": "a", "a..b": "b", "a...": "c"}
			}),
			Entry("the longest key", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) {
				s.Data = map[string]string{strings.Repeat("k", 253): "a"}
			}),
			Entry("a name for the Secret", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) {
				s.Template = &passwordstorev1alpha1.SecretTemplate{Metadata: passwordstorev1alpha1.SecretTemplateMetadata{Name: "my-secret.v1"}}
			}),
		)

		DescribeTable("refuses",
			func(mutate func(*passwordstorev1alpha1.PasswordStoreSecretSpec), want string) {
				err := k8sClient.Create(ctx, newPSS(mutate))
				Expect(err).To(HaveOccurred())
				Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected a validation error, got: %v", err)
				Expect(err.Error()).To(ContainSubstring(want))
			},
			Entry("a refresh interval that is too short", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) {
				s.RefreshInterval = &metav1.Duration{Duration: 9_000_000_000}
			}, "refreshInterval must be at least 10s"),
			Entry("a refresh interval of a millisecond", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) {
				s.RefreshInterval = &metav1.Duration{Duration: 1_000_000}
			}, "refreshInterval must be at least 10s"),
			Entry("no data", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) { s.Data = map[string]string{} }, "data"),
			Entry("a key with a space", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) { s.Data = map[string]string{"bad key": "a"} }, "alphanumeric characters"),
			Entry("a key with a slash", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) { s.Data = map[string]string{"a/b": "a"} }, "alphanumeric characters"),
			Entry("a key that is a dot", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) { s.Data = map[string]string{".": "a"} }, "must not be '.'"),
			Entry("a key that is two dots", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) { s.Data = map[string]string{"..": "a"} }, "must not be '.'"),
			Entry("a key that starts with two dots", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) { s.Data = map[string]string{"..data": "a"} }, "must not be '.'"),
			Entry("a key that is too long", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) {
				s.Data = map[string]string{strings.Repeat("k", 254): "a"}
			}, "1 to 253"),
			Entry("a store of an unknown kind", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) { s.StoreRef.Kind = "SecretStore" }, "Unsupported value"),
			Entry("a store name with capitals", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) { s.StoreRef.Name = "MyStore" }, "should match"),
			Entry("a store name that is a path", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) { s.StoreRef.Name = "ns/store" }, "should match"),
			Entry("a Secret of the type of service account tokens", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) {
				s.Template = &passwordstorev1alpha1.SecretTemplate{Type: "kubernetes.io/service-account-token"}
			}, "service-account-token cannot be generated"),
			Entry("no store name", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) { s.StoreRef.Name = "" }, "name"),
			Entry("a Secret name that is not valid", func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) {
				s.Template = &passwordstorev1alpha1.SecretTemplate{Metadata: passwordstorev1alpha1.SecretTemplateMetadata{Name: "Not_Valid"}}
			}, "should match"),
		)

		It("refuses more keys than a Secret should have", func() {
			many := map[string]string{}
			for i := range 101 {
				many["key"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "entry"
			}
			err := k8sClient.Create(ctx, newPSS(func(s *passwordstorev1alpha1.PasswordStoreSecretSpec) { s.Data = many }))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("data"))
		})
	})
})
