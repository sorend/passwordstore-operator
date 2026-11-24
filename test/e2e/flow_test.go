//go:build e2e

package e2e

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/sorend/passwordstore-operator/internal/testutil"
	"github.com/sorend/passwordstore-operator/test/utils"
)

// These scenarios run the operator the way it is deployed: from its image, with the
// ServiceAccount and the permissions of config/rbac. That is what the tests of the controllers
// cannot show, as they run with the permissions of an administrator.
//
// The password store is served by the machine that runs the tests. The nodes of the kind cluster
// reach it through the gateway of the docker network that kind creates.

const (
	flowNamespace = "passwordstore-e2e"
	// operatorServiceAccount is the identity of the operator, as it is deployed.
	operatorServiceAccount = "system:serviceaccount:" + namespace + ":" + serviceAccountName
)

func passwordStoreFlow() {
	var (
		key *testutil.PGPKey
		git *testutil.GitServer
		url string
	)

	BeforeAll(func() {
		By("making a password store with a throwaway key, served to the cluster")
		key = testutil.NewPGPKey(GinkgoT(), "e2e@example.com")
		git = testutil.NewGitServer(GinkgoT(), testutil.WithListenAddress("0.0.0.0:0"))
		commitEntries(git, key, map[string]string{
			"k8s/postgres.db.svc/admin-user": "s3cr3t\n",
			"k8s/postgres.db.svc/connection": "unused-first-line\nusername: admin\nhost: postgres.db.svc\n",
		})
		url = git.HostURL(kindHostAddress())

		By("creating a namespace with the key of the store")
		kubectl(nil, "create", "namespace", flowNamespace)
		kubectl(nil, "-n", flowNamespace, "create", "secret", "generic", "gpg-key",
			"--from-literal=private.key="+string(key.Private))
	})

	AfterAll(func() {
		kubectlIgnoreErrors("delete", "clusterpasswordstore", "e2e-cluster-store", "--ignore-not-found")
		kubectlIgnoreErrors("delete", "namespace", flowNamespace, "--ignore-not-found", "--wait=false")
	})

	It("renders a Secret from the entries of a PasswordStore", func() {
		kubectl(strings.NewReader(fmt.Sprintf(`
apiVersion: passwordstore.k8s.sorend.github.com/v1alpha1
kind: PasswordStore
metadata:
  name: e2e
  namespace: %[1]s
spec:
  gitRepo:
    url: %[2]s
  gpg:
    id: %[3]s
    privateKeySecretRef:
      name: gpg-key
---
apiVersion: passwordstore.k8s.sorend.github.com/v1alpha1
kind: PasswordStoreSecret
metadata:
  name: postgres
  namespace: %[1]s
spec:
  storeRef:
    name: e2e
  refreshInterval: 10s
  template:
    metadata:
      labels:
        app: postgres
    type: kubernetes.io/basic-auth
  data:
    password: k8s/postgres.db.svc/admin-user
    username: k8s/postgres.db.svc/connection#username
`, flowNamespace, url, key.Fingerprint)), "apply", "-f", "-")

		By("waiting for the store to be ready")
		Eventually(func(g Gomega) {
			g.Expect(readyStatus("passwordstore", "e2e")).To(Equal("True"), describe("passwordstore", "e2e"))
		}).Should(Succeed())

		By("checking the Secret")
		Eventually(func(g Gomega) {
			g.Expect(secretValue("postgres", "password")).To(Equal("s3cr3t"))
		}).Should(Succeed())
		Expect(secretValue("postgres", "username")).To(Equal("admin"))
		secretField := func(jsonpath string) string {
			return kubectl(nil, "-n", flowNamespace, "get", "secret", "postgres", "-o", "jsonpath="+jsonpath)
		}
		Expect(secretField("{.type}")).To(Equal("kubernetes.io/basic-auth"))
		Expect(secretField("{.metadata.labels}")).To(And(
			ContainSubstring(`"app":"postgres"`),
			ContainSubstring(`"app.kubernetes.io/managed-by":"passwordstore-operator"`),
		))

		By("checking that the Secret is owned by the PasswordStoreSecret")
		Expect(secretField("{.metadata.ownerReferences[0].kind}")).To(Equal("PasswordStoreSecret"))

		By("checking that the resources are readable with kubectl get")
		Expect(kubectl(nil, "-n", flowNamespace, "get", "passwordstores")).To(ContainSubstring("e2e"))
		Expect(kubectl(nil, "-n", flowNamespace, "get", "passwordstoresecrets", "-o", "wide")).
			To(ContainSubstring("postgres"))
	})

	It("follows changes in the repository", func() {
		commitEntries(git, key, map[string]string{"k8s/postgres.db.svc/admin-user": "rotated\n"})

		// The refresh interval of the PasswordStoreSecret is ten seconds.
		Eventually(func(g Gomega) {
			g.Expect(secretValue("postgres", "password")).To(Equal("rotated"))
		}, 2*time.Minute).Should(Succeed())
		Expect(readyStatus("passwordstoresecret", "postgres")).To(Equal("True"))
	})

	It("says in the status what is wrong", func() {
		kubectl(strings.NewReader(fmt.Sprintf(`
apiVersion: passwordstore.k8s.sorend.github.com/v1alpha1
kind: PasswordStoreSecret
metadata:
  name: broken
  namespace: %s
spec:
  storeRef:
    name: e2e
  data:
    password: k8s/no/such/entry
`, flowNamespace)), "apply", "-f", "-")

		Eventually(func(g Gomega) {
			g.Expect(readyStatus("passwordstoresecret", "broken")).To(Equal("False"))
			g.Expect(kubectl(nil, "-n", flowNamespace, "get", "passwordstoresecret", "broken",
				"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].reason}`)).To(Equal("EntryNotFound"))
		}).Should(Succeed())
		Expect(kubectl(nil, "-n", flowNamespace, "get", "passwordstoresecret", "broken",
			"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].message}`)).To(ContainSubstring("k8s/no/such/entry"))

		_, err := utils.Run(exec.Command("kubectl", "-n", flowNamespace, "get", "secret", "broken"))
		Expect(err).To(HaveOccurred(), "no Secret may be made when an entry is missing")
	})

	It("serves a ClusterPasswordStore only to the namespaces that it allows", func() {
		kubectl(strings.NewReader(fmt.Sprintf(`
apiVersion: passwordstore.k8s.sorend.github.com/v1alpha1
kind: ClusterPasswordStore
metadata:
  name: e2e-cluster-store
spec:
  gitRepo:
    url: %[2]s
  gpg:
    id: %[3]s
    privateKeySecretRef:
      name: gpg-key
      namespace: %[1]s
  namespaceSelector:
    matchLabels:
      passwordstore-e2e: allowed
---
apiVersion: passwordstore.k8s.sorend.github.com/v1alpha1
kind: PasswordStoreSecret
metadata:
  name: from-cluster
  namespace: %[1]s
spec:
  storeRef:
    kind: ClusterPasswordStore
    name: e2e-cluster-store
  data:
    password: k8s/postgres.db.svc/admin-user
`, flowNamespace, url, key.Fingerprint)), "apply", "-f", "-")

		Eventually(func(g Gomega) {
			g.Expect(readyStatus("passwordstoresecret", "from-cluster")).To(Equal("False"))
			g.Expect(kubectl(nil, "-n", flowNamespace, "get", "passwordstoresecret", "from-cluster",
				"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].reason}`)).To(Equal("NamespaceNotAllowed"))
		}).Should(Succeed())

		By("labeling the namespace so that the store allows it")
		kubectl(nil, "label", "namespace", flowNamespace, "passwordstore-e2e=allowed")
		Eventually(func(g Gomega) {
			g.Expect(secretValue("from-cluster", "password")).To(Equal("rotated"))
		}).Should(Succeed())
	})

	It("does not connect to its own loopback interface, where the endpoint of its health checks is", func() {
		// 8081 is the port of the health probes of the operator. A Git server there would be the operator
		// itself, and the same is true of the metadata service of a cloud at 169.254.169.254.
		kubectl(strings.NewReader(fmt.Sprintf(`
apiVersion: passwordstore.k8s.sorend.github.com/v1alpha1
kind: PasswordStore
metadata:
  name: loopback
  namespace: %[1]s
spec:
  gitRepo:
    url: http://127.0.0.1:8081/repo.git
  gpg:
    id: %[2]s
    privateKeySecretRef:
      name: gpg-key
---
apiVersion: passwordstore.k8s.sorend.github.com/v1alpha1
kind: PasswordStore
metadata:
  name: metadata-service
  namespace: %[1]s
spec:
  gitRepo:
    url: http://169.254.169.254/latest/meta-data/
  gpg:
    id: %[2]s
    privateKeySecretRef:
      name: gpg-key
`, flowNamespace, key.Fingerprint)), "apply", "-f", "-")

		for _, store := range []string{"loopback", "metadata-service"} {
			Eventually(func(g Gomega) {
				g.Expect(readyStatus("passwordstore", store)).To(Equal("False"), describe("passwordstore", store))
				message := kubectl(nil, "-n", flowNamespace, "get", "passwordstore", store,
					"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].message}`)
				g.Expect(message).To(ContainSubstring("address not allowed"))
			}).Should(Succeed(), store)
		}
	})

	It("has only the permissions that it needs", func() {
		// kubectl exits with an error for "no", the answer is in the output.
		can := func(verb, resource string, extra ...string) string {
			args := slices.Concat([]string{"auth", "can-i", verb, resource, "--all-namespaces",
				"--as=" + operatorServiceAccount}, extra)
			out, _ := utils.Run(exec.Command("kubectl", args...))
			return strings.TrimSpace(out)
		}
		Expect(can("create", "secrets")).To(Equal("yes"))
		Expect(can("update", "secrets")).To(Equal("yes"))
		Expect(can("get", "secrets")).To(Equal("yes"))
		Expect(can("delete", "secrets")).To(Equal("no"), "Secrets are removed by their owner reference, not by the operator")
		Expect(can("patch", "secrets")).To(Equal("no"), "Secrets are created and updated, never patched")
		Expect(can("update", "passwordstoresecrets", "--subresource=finalizers")).To(Equal("yes"),
			"the Secrets that it makes block the deletion of their owner, which some clusters want this for")
		Expect(can("delete", "namespaces")).To(Equal("no"))
		Expect(can("create", "passwordstores")).To(Equal("no"), "the operator only reads what users define")
		Expect(can("update", "passwordstores", "--subresource=status")).To(Equal("yes"))
		Expect(can("update", "passwordstoresecrets", "--subresource=status")).To(Equal("yes"))
		Expect(can("update", "passwordstores")).To(Equal("no"), "the spec is the business of users")
		Expect(can("create", "deployments")).To(Equal("no"))
	})

	It("deletes the Secret together with the PasswordStoreSecret", func() {
		kubectl(nil, "-n", flowNamespace, "delete", "passwordstoresecret", "postgres")
		Eventually(func() error {
			_, err := utils.Run(exec.Command("kubectl", "-n", flowNamespace, "get", "secret", "postgres"))
			return err
		}).Should(HaveOccurred(), "the garbage collector must remove the Secret")
	})
}

// commitEntries encrypts entries to the key and commits them to the repository.
func commitEntries(git *testutil.GitServer, key *testutil.PGPKey, entries map[string]string) {
	GinkgoHelper()
	files := make(map[string][]byte, len(entries))
	for path, content := range entries {
		files[path+".gpg"] = testutil.Encrypt(GinkgoT(), content, key)
	}
	git.Commit(GinkgoT(), "e2e", files)
}

// kindHostAddress returns the address at which the machine that runs the tests is reachable from
// the nodes of the kind cluster: the gateway of the docker network that kind creates.
func kindHostAddress() string {
	GinkgoHelper()
	out, err := utils.Run(exec.Command("docker", "network", "inspect", "kind",
		"-f", "{{range .IPAM.Config}}{{.Gateway}} {{end}}"))
	Expect(err).NotTo(HaveOccurred(), "the docker network of kind must exist")
	for gateway := range strings.FieldsSeq(out) {
		if strings.Contains(gateway, ".") && !strings.Contains(gateway, ":") {
			return gateway
		}
	}
	Fail("no IPv4 gateway in the docker network of kind: " + out)
	return ""
}

// kubectl runs kubectl, fails the test if it fails, and returns what it printed.
func kubectl(stdin *strings.Reader, args ...string) string {
	GinkgoHelper()
	cmd := exec.Command("kubectl", args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	out, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "kubectl %s", strings.Join(args, " "))
	return out
}

func kubectlIgnoreErrors(args ...string) {
	_, _ = utils.Run(exec.Command("kubectl", args...))
}

// readyStatus returns the status of the Ready condition of a resource of the flow namespace.
func readyStatus(kind, name string) string {
	out, err := utils.Run(exec.Command("kubectl", "-n", flowNamespace, "get", kind, name,
		"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}`))
	if err != nil {
		return "error: " + err.Error()
	}
	return out
}

// describe returns kubectl describe, to explain a failure.
func describe(kind, name string) string {
	out, _ := utils.Run(exec.Command("kubectl", "-n", flowNamespace, "describe", kind, name))
	return out
}

// secretValue returns the decoded value of a key of a Secret of the flow namespace.
func secretValue(name, key string) string {
	out, err := utils.Run(exec.Command("kubectl", "-n", flowNamespace, "get", "secret", name,
		"-o", fmt.Sprintf("jsonpath={.data.%s}", strings.ReplaceAll(key, ".", `\.`))))
	if err != nil || out == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		return "undecodable: " + out
	}
	return string(decoded)
}
