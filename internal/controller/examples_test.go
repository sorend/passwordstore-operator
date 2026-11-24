package controller

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
)

// The examples in the documentation are checked by the API server that the controllers run against, so
// that an example that the schema of the CRDs refuses is found here, and not by whoever copies it.

var fencedYAML = regexp.MustCompile("(?s)```yaml\n(.*?)```")

// asResource makes a resource of this API group of what the yaml of the documentation holds. It is
// one already, or a fragment of one that the documentation shows alone: the spec of a PasswordStoreSecret,
// or the gitRepo or gpg of a store, which is put in a store that has the rest. It returns nil for
// anything else.
func asResource(object map[string]any) *unstructured.Unstructured {
	group := passwordstorev1alpha1.GroupVersion.Group
	if apiVersion, _ := object["apiVersion"].(string); strings.HasPrefix(apiVersion, group+"/") {
		if kind, _ := object["kind"].(string); kind != "" {
			return &unstructured.Unstructured{Object: object}
		}
		return nil
	}

	resource := func(kind string, spec map[string]any) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": passwordstorev1alpha1.GroupVersion.String(),
			"kind":       kind,
			"metadata":   map[string]any{"name": "example"},
			"spec":       spec,
		}}
	}

	if spec, ok := object["spec"].(map[string]any); ok {
		if _, ok := spec["storeRef"]; ok {
			return resource(passwordstorev1alpha1.KindPasswordStore+"Secret", spec)
		}
	}
	_, hasRepo := object["gitRepo"]
	_, hasKey := object["gpg"]
	if hasRepo || hasKey {
		spec := map[string]any{
			"gitRepo": map[string]any{"url": "https://github.com/you/passwords.git"},
			"gpg":     map[string]any{"id": "cluster@example.com", "privateKeySecretRef": map[string]any{"name": "gpg-key"}},
		}
		if hasRepo {
			spec["gitRepo"] = object["gitRepo"]
		}
		if hasKey {
			spec["gpg"] = object["gpg"]
		}
		return resource(passwordstorev1alpha1.KindPasswordStore, spec)
	}
	return nil
}

// yamlResources returns the resources of this API group that are in the yaml of a file: the ones
// in the fenced blocks of a Markdown file, or in the documents of a YAML file.
func yamlResources(path string) []*unstructured.Unstructured {
	GinkgoHelper()
	data, err := os.ReadFile(path)
	Expect(err).NotTo(HaveOccurred())

	var blocks []string
	if strings.HasSuffix(path, ".md") {
		for _, m := range fencedYAML.FindAllStringSubmatch(string(data), -1) {
			blocks = append(blocks, m[1])
		}
	} else {
		blocks = []string{string(data)}
	}

	var out []*unstructured.Unstructured
	for _, block := range blocks {
		for doc := range strings.SplitSeq(block, "\n---") {
			var object map[string]any
			if err := yaml.Unmarshal([]byte(doc), &object); err != nil || object == nil {
				continue // not a yaml document, such as a sketch with "..." in it
			}
			if obj := asResource(object); obj != nil {
				out = append(out, obj)
			}
		}
	}
	return out
}

var _ = Describe("The examples in the documentation", func() {
	check := func(path string, atLeast int) {
		GinkgoHelper()
		resources := yamlResources(path)
		Expect(len(resources)).To(BeNumerically(">=", atLeast),
			"%s has fewer examples than it should: the test found %d, so it may not be reading it right", path, len(resources))

		ns := newNamespace()
		for _, obj := range resources {
			if obj.GetKind() != passwordstorev1alpha1.KindClusterPasswordStore {
				obj.SetNamespace(ns)
			}
			if obj.GetName() == "" {
				obj.SetName("example")
			}
			By("checking " + obj.GetKind() + " " + obj.GetName() + " of " + filepath.Base(path))
			// A dry run goes through the admission of the API server, with the schema, the rules in
			// it and the defaults, and keeps nothing.
			err := k8sClient.Create(ctx, obj, client.DryRunAll)
			Expect(err).NotTo(HaveOccurred(), "%s %s in %s is refused", obj.GetKind(), obj.GetName(), path)
		}
	}

	It("in the README are valid", func() {
		// The quick start, the ways to authenticate, the passphrase, the PasswordStoreSecrets. If the
		// number found is less than this, the test is not reading the README right.
		check(filepath.Join("..", "..", "README.md"), 10)
	})

	for _, sample := range []string{
		"passwordstore_v1alpha1_passwordstore.yaml",
		"passwordstore_v1alpha1_clusterpasswordstore.yaml",
		"passwordstore_v1alpha1_passwordstoresecret.yaml",
	} {
		It("in config/samples/"+sample+" are valid", func() {
			check(filepath.Join("..", "..", "config", "samples", sample), 1)
		})
	}
})
