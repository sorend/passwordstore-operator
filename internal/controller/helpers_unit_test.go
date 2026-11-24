package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
	"github.com/sorend/passwordstore-operator/internal/entry"
	"github.com/sorend/passwordstore-operator/internal/gitstore"
	"github.com/sorend/passwordstore-operator/internal/gpg"
	"github.com/sorend/passwordstore-operator/internal/testutil"
)

func TestRedact(t *testing.T) {
	sensitive := [][]byte{[]byte("ghp_s3cr3t_t0ken"), []byte("hunter2-pass"), []byte("abc"), nil, []byte("  \n")}

	tests := map[string]struct{ in, want string }{
		"a token in a message":     {"remote: invalid credentials ghp_s3cr3t_t0ken for user", "remote: invalid credentials *** for user"},
		"twice":                    {"ghp_s3cr3t_t0ken and ghp_s3cr3t_t0ken", "*** and ***"},
		"two credentials":          {"ghp_s3cr3t_t0ken hunter2-pass", "*** ***"},
		"nothing to hide":          {"repository not found", "repository not found"},
		"short values are kept":    {"abc is not removed, it is too short to tell apart", "abc is not removed, it is too short to tell apart"},
		"a value with whitespace":  {"the token is ghp_s3cr3t_t0ken", "the token is ***"},
		"empty credentials ignore": {"", ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := redact(tt.in, sensitive); got != tt.want {
				t.Errorf("redact(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	t.Run("credentials with a trailing newline are found without it", func(t *testing.T) {
		got := redact("failed with s3cr3t-value", [][]byte{[]byte("s3cr3t-value\n")})
		if got != "failed with ***" {
			t.Errorf("redact = %q", got)
		}
	})
}

func TestMessageTruncates(t *testing.T) {
	long := errors.New(strings.Repeat("é", maxMessageLength+500))
	got := message(long, nil)
	if n := len([]rune(got)); n != maxMessageLength+3 {
		t.Errorf("message has %d runes, want %d", n, maxMessageLength+3)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("message %q does not show that it was shortened", got[len(got)-10:])
	}
	if got := message(errors.New("short"), nil); got != "short" {
		t.Errorf("message = %q", got)
	}
	if got := message(errors.New("token ghp_abcdef failed"), [][]byte{[]byte("ghp_abcdef")}); got != "token *** failed" {
		t.Errorf("message = %q", got)
	}
}

func TestFailureReason(t *testing.T) {
	err := fail("SomeReason", "something %s", "failed")
	if reason, ok := failureReason(err); !ok || reason != "SomeReason" {
		t.Errorf("failureReason = %q, %v", reason, ok)
	}
	if reason, ok := failureReason(fmt.Errorf("wrapped: %w", err)); !ok || reason != "SomeReason" {
		t.Errorf("failureReason of a wrapped error = %q, %v", reason, ok)
	}
	if _, ok := failureReason(errors.New("plain")); ok {
		t.Error("a plain error has no reason")
	}
	if got := err.Error(); got != "something failed" {
		t.Errorf("Error() = %q", got)
	}
	inner := errors.New("inner")
	if !errors.Is(failWrap("R", inner), inner) {
		t.Error("failWrap must keep the error that it wraps")
	}
}

func TestSetReadyReportsOnlyVisibleChanges(t *testing.T) {
	var conditions []metav1.Condition

	if !setReady(&conditions, 1, metav1.ConditionFalse, "Broken", "it is broken") {
		t.Error("the first condition is a change")
	}
	if setReady(&conditions, 1, metav1.ConditionFalse, "Broken", "it is broken") {
		t.Error("the same condition again is not a change")
	}
	if !setReady(&conditions, 1, metav1.ConditionFalse, "Broken", "it is broken differently") {
		t.Error("another message is a change")
	}
	if !setReady(&conditions, 2, metav1.ConditionTrue, "Synced", "fine") {
		t.Error("becoming ready is a change")
	}
	if len(conditions) != 1 || conditions[0].ObservedGeneration != 2 {
		t.Errorf("conditions = %+v, want one condition at generation 2", conditions)
	}
}

func TestShortRevision(t *testing.T) {
	if got := shortRevision("0123456789abcdef"); got != "0123456" {
		t.Errorf("shortRevision = %q", got)
	}
	if got := shortRevision("abc"); got != "abc" {
		t.Errorf("shortRevision = %q", got)
	}
}

func TestMergeMetadata(t *testing.T) {
	tests := map[string]struct {
		current, desired map[string]string
		previous         []string
		want             map[string]string
	}{
		"nothing at all":                    {want: nil},
		"adds the desired":                  {desired: map[string]string{"a": "1"}, want: map[string]string{"a": "1"}},
		"keeps what others added":           {current: map[string]string{"theirs": "x"}, desired: map[string]string{"a": "1"}, want: map[string]string{"theirs": "x", "a": "1"}},
		"overwrites a changed value":        {current: map[string]string{"a": "old"}, desired: map[string]string{"a": "new"}, want: map[string]string{"a": "new"}},
		"removes what left the template":    {current: map[string]string{"a": "1", "b": "2", "theirs": "x"}, desired: map[string]string{"a": "1"}, previous: []string{"a", "b"}, want: map[string]string{"a": "1", "theirs": "x"}},
		"keeps a key that is still wanted":  {current: map[string]string{"a": "1"}, desired: map[string]string{"a": "2"}, previous: []string{"a"}, want: map[string]string{"a": "2"}},
		"removing the last gives nil":       {current: map[string]string{"a": "1"}, previous: []string{"a"}, want: nil},
		"does not remove what it never set": {current: map[string]string{"theirs": "x"}, previous: []string{"a"}, want: map[string]string{"theirs": "x"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			before := fmt.Sprint(tt.current)
			got := mergeMetadata(tt.current, tt.desired, tt.previous)
			if fmt.Sprint(got) != fmt.Sprint(tt.want) || (got == nil) != (tt.want == nil) {
				t.Errorf("mergeMetadata = %v, want %v", got, tt.want)
			}
			if fmt.Sprint(tt.current) != before {
				t.Errorf("the input map was modified: %v", tt.current)
			}
		})
	}
}

func TestManagedMetadataRoundTrip(t *testing.T) {
	if m := readManagedMetadata(nil); len(m.Labels)+len(m.Annotations) != 0 {
		t.Errorf("nothing recorded, got %+v", m)
	}
	if m := readManagedMetadata(map[string]string{managedMetadataAnnotation: "{not json"}); len(m.Labels)+len(m.Annotations) != 0 {
		t.Errorf("a broken record is treated as empty, got %+v", m)
	}
	m := readManagedMetadata(map[string]string{managedMetadataAnnotation: `{"labels":["a","b"],"annotations":["c"]}`})
	if strings.Join(m.Labels, ",") != "a,b" || strings.Join(m.Annotations, ",") != "c" {
		t.Errorf("read %+v", m)
	}
}

func TestTemplateMetadataKeepsReservedKeysOut(t *testing.T) {
	pss := &passwordstorev1alpha1.PasswordStoreSecret{Spec: passwordstorev1alpha1.PasswordStoreSecretSpec{
		Template: &passwordstorev1alpha1.SecretTemplate{Metadata: passwordstorev1alpha1.SecretTemplateMetadata{
			Labels:      map[string]string{"app": "x", managedByLabel: "helm"},
			Annotations: map[string]string{"note": "y", managedMetadataAnnotation: "forged"},
		}},
	}}
	labels, annotations := templateMetadata(pss)
	if _, ok := labels[managedByLabel]; ok || labels["app"] != "x" {
		t.Errorf("labels = %v", labels)
	}
	if _, ok := annotations[managedMetadataAnnotation]; ok || annotations["note"] != "y" {
		t.Errorf("annotations = %v", annotations)
	}

	// Without a template there is nothing, and nothing breaks.
	labels, annotations = templateMetadata(&passwordstorev1alpha1.PasswordStoreSecret{})
	if len(labels)+len(annotations) != 0 {
		t.Errorf("got %v, %v", labels, annotations)
	}
}

func TestRefreshInterval(t *testing.T) {
	pss := func(d *time.Duration) *passwordstorev1alpha1.PasswordStoreSecret {
		p := &passwordstorev1alpha1.PasswordStoreSecret{}
		if d != nil {
			p.Spec.RefreshInterval = &metav1.Duration{Duration: *d}
		}
		return p
	}
	d := func(v time.Duration) *time.Duration { return &v }

	tests := map[string]struct {
		in   *time.Duration
		want time.Duration
	}{
		"default is five minutes":         {nil, 5 * time.Minute},
		"as given":                        {d(30 * time.Minute), 30 * time.Minute},
		"the lowest that is honored":      {d(10 * time.Second), 10 * time.Second},
		"lower is raised":                 {d(time.Second), 10 * time.Second},
		"zero is raised, not a busy loop": {d(0), 10 * time.Second},
		"negative is raised":              {d(-time.Hour), 10 * time.Second},
	}
	for name, tt := range tests {
		if got := refreshInterval(pss(tt.in)); got != tt.want {
			t.Errorf("%s: refreshInterval = %s, want %s", name, got, tt.want)
		}
	}
}

func TestOptionsDefaults(t *testing.T) {
	var o Options
	if o.storeSyncInterval() != DefaultStoreSyncInterval || o.retryInterval() != DefaultRetryInterval {
		t.Errorf("defaults = %s, %s", o.storeSyncInterval(), o.retryInterval())
	}
	o = Options{StoreSyncInterval: time.Second, RetryInterval: 2 * time.Second}
	if o.storeSyncInterval() != time.Second || o.retryInterval() != 2*time.Second {
		t.Errorf("explicit = %s, %s", o.storeSyncInterval(), o.retryInterval())
	}
}

func TestTargetNameAndSecretType(t *testing.T) {
	pss := &passwordstorev1alpha1.PasswordStoreSecret{ObjectMeta: metav1.ObjectMeta{Name: "mine"}}
	if targetName(pss) != "mine" || secretType(pss) != corev1.SecretTypeOpaque {
		t.Errorf("defaults: %q, %q", targetName(pss), secretType(pss))
	}
	pss.Spec.Template = &passwordstorev1alpha1.SecretTemplate{}
	if targetName(pss) != "mine" || secretType(pss) != corev1.SecretTypeOpaque {
		t.Errorf("empty template: %q, %q", targetName(pss), secretType(pss))
	}
	pss.Spec.Template = &passwordstorev1alpha1.SecretTemplate{
		Type:     "kubernetes.io/tls",
		Metadata: passwordstorev1alpha1.SecretTemplateMetadata{Name: "other"},
	}
	if targetName(pss) != "other" || secretType(pss) != corev1.SecretTypeTLS {
		t.Errorf("template: %q, %q", targetName(pss), secretType(pss))
	}
}

func TestParseData(t *testing.T) {
	t.Run("sorted and parsed", func(t *testing.T) {
		refs, err := parseData(map[string]string{"b": "k8s/b#2", "a": "k8s/a", "c": "/k8s/c.gpg"})
		if err != nil {
			t.Fatal(err)
		}
		keys, paths := make([]string, 0, len(refs)), make([]string, 0, len(refs))
		for _, r := range refs {
			keys = append(keys, r.key)
			paths = append(paths, r.ref.String())
		}
		if strings.Join(keys, ",") != "a,b,c" || strings.Join(paths, ",") != "k8s/a,k8s/b#2,k8s/c.gpg" {
			t.Errorf("keys %v, paths %v", keys, paths)
		}
	})

	t.Run("all problems at once, with the reason", func(t *testing.T) {
		_, err := parseData(map[string]string{"good": "a/b", "bad ref": "x", "one": "../up", "two": "a//b"})
		reason, ok := failureReason(err)
		if !ok || reason != passwordstorev1alpha1.ReasonInvalidSpec {
			t.Fatalf("err = %v, want InvalidSpec", err)
		}
		for _, want := range []string{`"bad ref"`, `data["one"]`, `data["two"]`} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %s", err, want)
			}
		}
		if strings.Contains(err.Error(), `data["good"]`) {
			t.Errorf("error %q mentions a key that is fine", err)
		}
	})

	t.Run("empty", func(t *testing.T) {
		if _, err := parseData(nil); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestStoreKey(t *testing.T) {
	ns := &passwordstorev1alpha1.PasswordStore{ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "pass"}}
	cluster := &passwordstorev1alpha1.ClusterPasswordStore{ObjectMeta: metav1.ObjectMeta{Name: "pass"}}
	other := &passwordstorev1alpha1.PasswordStore{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "pass"}}

	keys := map[string]bool{storeKey(ns): true, storeKey(cluster): true, storeKey(other): true}
	if len(keys) != 3 {
		t.Errorf("stores that are not the same must not share a key: %v", keys)
	}
	if storeKey(ns) != "PasswordStore/team/pass" || storeKey(cluster) != "ClusterPasswordStore/pass" {
		t.Errorf("keys: %q, %q", storeKey(ns), storeKey(cluster))
	}
}

func TestIndexStoreRef(t *testing.T) {
	pss := func(kind, name string) *passwordstorev1alpha1.PasswordStoreSecret {
		return &passwordstorev1alpha1.PasswordStoreSecret{Spec: passwordstorev1alpha1.PasswordStoreSecretSpec{
			StoreRef: passwordstorev1alpha1.StoreReference{Kind: kind, Name: name},
		}}
	}
	tests := map[string]struct {
		obj  client.Object
		want string
	}{
		"kind that is not set is a PasswordStore": {pss("", "s"), "PasswordStore/s"},
		"PasswordStore":        {pss("PasswordStore", "s"), "PasswordStore/s"},
		"ClusterPasswordStore": {pss("ClusterPasswordStore", "s"), "ClusterPasswordStore/s"},
	}
	for name, tt := range tests {
		if got := indexStoreRef(tt.obj); len(got) != 1 || got[0] != tt.want {
			t.Errorf("%s: index = %v, want %s", name, got, tt.want)
		}
	}
	if got := indexStoreRef(&corev1.Secret{}); got != nil {
		t.Errorf("another type is not indexed, got %v", got)
	}
}

func TestStorePredicate(t *testing.T) {
	store := func(generation int64, revision string, ready bool) *passwordstorev1alpha1.PasswordStore {
		status := metav1.ConditionFalse
		if ready {
			status = metav1.ConditionTrue
		}
		return &passwordstorev1alpha1.PasswordStore{
			ObjectMeta: metav1.ObjectMeta{Generation: generation},
			Status: passwordstorev1alpha1.PasswordStoreStatus{
				Revision:   revision,
				Conditions: []metav1.Condition{{Type: passwordstorev1alpha1.ConditionReady, Status: status}},
			},
		}
	}
	update := func(oldStore, newStore client.Object) bool {
		return storeChanged.Update(event.UpdateEvent{ObjectOld: oldStore, ObjectNew: newStore})
	}

	base := store(1, "aaa", true)
	if update(base, store(1, "aaa", true)) {
		t.Error("nothing changed, nothing to do")
	}
	if !update(base, store(2, "aaa", true)) {
		t.Error("a new generation must be seen")
	}
	if !update(base, store(1, "bbb", true)) {
		t.Error("a new revision must be seen, it is what makes the Secrets follow")
	}
	if !update(base, store(1, "aaa", false)) {
		t.Error("a store that stops being ready must be seen")
	}
	if update(&corev1.Secret{}, base) || update(base, &corev1.Secret{}) {
		t.Error("objects that are not stores are not of interest")
	}
	if !storeChanged.Create(event.CreateEvent{Object: base}) || !storeChanged.Delete(event.DeleteEvent{Object: base}) {
		t.Error("a store that is created or deleted must be seen")
	}
}

func TestNamespacePredicate(t *testing.T) {
	ns := func(labels map[string]string) client.Object {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Labels: labels}}
	}
	update := func(a, b client.Object) bool {
		return namespaceLabelsChanged.Update(event.UpdateEvent{ObjectOld: a, ObjectNew: b})
	}
	if update(ns(map[string]string{"a": "1"}), ns(map[string]string{"a": "1"})) {
		t.Error("the same labels are not a change")
	}
	if !update(ns(map[string]string{"a": "1"}), ns(map[string]string{"a": "2"})) {
		t.Error("another value is a change")
	}
	if !update(ns(nil), ns(map[string]string{"a": "1"})) {
		t.Error("a new label is a change")
	}
	if namespaceLabelsChanged.Create(event.CreateEvent{Object: ns(nil)}) || namespaceLabelsChanged.Delete(event.DeleteEvent{Object: ns(nil)}) {
		t.Error("a namespace that is created or deleted has no PasswordStoreSecrets that need to know")
	}
}

func TestSecretValue(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	secret := func(ns, name string, data map[string][]byte) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Data: data}
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		secret("team", "creds", map[string][]byte{"token": []byte("tok"), "custom": []byte("c"), "blank": []byte(" \n")}),
		secret("other", "creds", map[string][]byte{"token": []byte("other-tok")}),
		secret("team", "empty", nil),
	).Build()

	forbidden := interceptor.Funcs{Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
		return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "creds", errors.New("no"))
	}}
	broken := interceptor.Funcs{Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
		return apierrors.NewInternalError(errors.New("etcd is on fire"))
	}}

	ref := func(ns, name, key string) passwordstorev1alpha1.SecretKeySelector {
		return passwordstorev1alpha1.SecretKeySelector{Namespace: ns, Name: name, Key: key}
	}

	tests := map[string]struct {
		reader     client.Reader
		storeNS    string
		cluster    bool
		ref        passwordstorev1alpha1.SecretKeySelector
		want       string
		wantReason string
		wantErr    string
		wantAPIErr bool
	}{
		"namespaced, own namespace implied": {reader: base, storeNS: "team", ref: ref("", "creds", ""), want: "tok"},
		"namespaced, own namespace named":   {reader: base, storeNS: "team", ref: ref("team", "creds", ""), want: "tok"},
		"namespaced, key named":             {reader: base, storeNS: "team", ref: ref("", "creds", "custom"), want: "c"},
		"namespaced, other namespace": {
			reader: base, storeNS: "team", ref: ref("other", "creds", ""),
			wantReason: passwordstorev1alpha1.ReasonInvalidSpec, wantErr: "own namespace",
		},
		"cluster, namespace named": {reader: base, cluster: true, ref: ref("other", "creds", ""), want: "other-tok"},
		"cluster, no namespace": {
			reader: base, cluster: true, ref: ref("", "creds", ""),
			wantReason: passwordstorev1alpha1.ReasonInvalidSpec, wantErr: "needs a namespace",
		},
		"secret does not exist": {
			reader: base, storeNS: "team", ref: ref("", "nope", ""),
			wantReason: passwordstorev1alpha1.ReasonCredentialsUnavailable, wantErr: "team/nope not found",
		},
		"key does not exist": {
			reader: base, storeNS: "team", ref: ref("", "creds", "missing"),
			wantReason: passwordstorev1alpha1.ReasonCredentialsUnavailable, wantErr: `has no key "missing" (it has: "blank", "custom", "token")`,
		},
		"secret without data": {
			reader: base, storeNS: "team", ref: ref("", "empty", ""),
			wantReason: passwordstorev1alpha1.ReasonCredentialsUnavailable, wantErr: "no keys",
		},
		"value that is blank": {
			reader: base, storeNS: "team", ref: ref("", "creds", "blank"),
			wantReason: passwordstorev1alpha1.ReasonCredentialsUnavailable, wantErr: "is empty",
		},
		"not allowed to read": {
			reader: interceptedReader(t, scheme, forbidden), storeNS: "team", ref: ref("", "creds", ""),
			wantReason: passwordstorev1alpha1.ReasonCredentialsUnavailable, wantErr: "not allowed to read",
		},
		"the API server fails": {
			reader: interceptedReader(t, scheme, broken), storeNS: "team", ref: ref("", "creds", ""),
			wantErr: "etcd is on fire", wantAPIErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := storeResolver{reader: tt.reader}.secretValue(context.Background(), tt.storeNS, tt.cluster, tt.ref, "token")
			if tt.wantErr == "" {
				if err != nil || string(got) != tt.want {
					t.Fatalf("secretValue = %q, %v; want %q", got, err, tt.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
			}
			reason, hasReason := failureReason(err)
			if tt.wantAPIErr {
				if hasReason {
					t.Errorf("an API error is not a problem of the store, got reason %q", reason)
				}
				return
			}
			if !hasReason || reason != tt.wantReason {
				t.Errorf("reason = %q (%v), want %q", reason, hasReason, tt.wantReason)
			}
		})
	}
}

func interceptedReader(t *testing.T, scheme *runtime.Scheme, funcs interceptor.Funcs) client.Reader {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(funcs).Build()
}

func TestReadEntries(t *testing.T) {
	key := testutil.NewPGPKey(t, "entries@example.com")
	other := testutil.NewPGPKey(t, "other@example.com")
	server := testutil.NewGitServer(t)
	server.Commit(t, "entries", map[string][]byte{
		"login.gpg":   testutil.Encrypt(t, "pw\nusername: bob\n", key),
		"key.gpg":     testutil.Encrypt(t, "line1\nline2\n", key),
		"foreign.gpg": testutil.Encrypt(t, "secret", other),
		"plain.gpg":   []byte("not encrypted"),
	})
	snapshot, err := gitstore.NewManager(gitstore.Options{AllowInternalAddresses: true}).Sync(context.Background(), "s", gitstore.Config{URL: server.URL}, 0)
	if err != nil {
		t.Fatal(err)
	}
	decrypter, err := gpg.NewDecrypter(key.Private, key.Email, nil)
	if err != nil {
		t.Fatal(err)
	}

	refs := func(m map[string]string) []dataRef {
		out := make([]dataRef, 0, len(m))
		for k, v := range m {
			ref, err := entry.Parse(v)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, dataRef{key: k, ref: ref})
		}
		// As parseData returns them.
		slices.SortFunc(out, func(a, b dataRef) int { return strings.Compare(a.key, b.key) })
		return out
	}

	t.Run("reads and selects", func(t *testing.T) {
		data, err := readEntries(snapshot, decrypter, refs(map[string]string{
			"password": "login#1", "user": "login#username", "all": "login", "again": "login#2", "key": "key",
		}))
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"password": "pw", "user": "bob", "all": "pw\nusername: bob\n", "again": "username: bob", "key": "line1\nline2\n"}
		for k, v := range want {
			if string(data[k]) != v {
				t.Errorf("data[%s] = %q, want %q", k, data[k], v)
			}
		}
		if len(data) != len(want) {
			t.Errorf("%d keys, want %d", len(data), len(want))
		}
	})

	t.Run("one problem makes none of it available, and says what is wrong with each", func(t *testing.T) {
		data, err := readEntries(snapshot, decrypter, refs(map[string]string{
			"fine": "login", "gone": "missing/entry", "locked": "foreign", "garbage": "plain", "field": "login#nope",
		}))
		if data != nil {
			t.Errorf("data = %v, want nothing", data)
		}
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, want := range []string{
			`data["gone"]`, "missing/entry", `data["locked"]`, "not encrypted to the configured key",
			`data["garbage"]`, `data["field"]`, `no field "nope"`,
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not contain %q", err, want)
			}
		}
		if strings.Contains(err.Error(), `data["fine"]`) {
			t.Errorf("error %q mentions the entry that is fine", err)
		}
	})

	t.Run("the reason is the one of the first problem by key", func(t *testing.T) {
		_, err := readEntries(snapshot, decrypter, refs(map[string]string{"a": "missing", "b": "foreign"}))
		if reason, _ := failureReason(err); reason != passwordstorev1alpha1.ReasonEntryNotFound {
			t.Errorf("reason = %q, want EntryNotFound", reason)
		}
	})
}

func TestRedactHidesEachLineOfAKey(t *testing.T) {
	key := []byte("-----BEGIN " + "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\nQyNTUxOQAAACDsecretsecretsecret\n-----END " + "OPENSSH PRIVATE KEY-----\n")
	sensitive := [][]byte{key}

	// An error that shows one line of a key, which is not the whole key.
	got := redact("could not parse: QyNTUxOQAAACDsecretsecretsecret at offset 3", sensitive)
	if strings.Contains(got, "secretsecret") {
		t.Errorf("a line of the key is in the message: %q", got)
	}
	// The whole key is still hidden, in one piece.
	if got := redact("the key is "+strings.TrimSpace(string(key)), sensitive); strings.Contains(got, "b3BlbnNz") || strings.Contains(got, "secretsecret") {
		t.Errorf("the key is in the message: %q", got)
	}
	// Lines that are short are not hidden: they would match anything.
	if got := redact("end of file", [][]byte{[]byte("long enough to be hidden\nend")}); got != "end of file" {
		t.Errorf("a short line was hidden: %q", got)
	}
}

func TestMessageIsFitToBeShown(t *testing.T) {
	// What a server answers with ends up in the message, and in a terminal.
	err := errors.New("authentication required: \x1b[2J\x1b[1;31mPlease log in\x1b[0m\nat https://example.com\u202e")
	got := message(err, nil)
	for _, bad := range []string{"\x1b", "\n", "\u202e"} {
		if strings.Contains(got, bad) {
			t.Errorf("message %q has %q in it", got, bad)
		}
	}
	if !strings.Contains(got, "Please log in") || !strings.Contains(got, "https://example.com") {
		t.Errorf("the words of the message are gone: %q", got)
	}
}

func TestSyncFailureReasons(t *testing.T) {
	tests := map[string]struct {
		err  error
		want string
	}{
		"the spec is not valid":                {fmt.Errorf("fetch: %w", gitstore.ErrInvalidConfig), passwordstorev1alpha1.ReasonInvalidSpec},
		"the host is not one of those allowed": {fmt.Errorf("fetch: %w", gitstore.ErrHostNotAllowed), passwordstorev1alpha1.ReasonInvalidSpec},
		"the address is not allowed":           {fmt.Errorf("fetch: %w", gitstore.ErrAddressNotAllowed), passwordstorev1alpha1.ReasonGitSyncFailed},
		"the repository is too large":          {fmt.Errorf("fetch: %w", gitstore.ErrLimitExceeded), passwordstorev1alpha1.ReasonGitSyncFailed},
		"the path is not in the repository":    {fmt.Errorf("%w: %q", gitstore.ErrPathNotFound, "x"), passwordstorev1alpha1.ReasonGitSyncFailed},
		"anything else":                        {errors.New("connection refused"), passwordstorev1alpha1.ReasonGitSyncFailed},
	}
	for name, tt := range tests {
		reason, ok := failureReason(syncFailure(tt.err))
		if !ok || reason != tt.want {
			t.Errorf("%s: reason = %q, %v; want %q", name, reason, ok, tt.want)
		}
	}
}

func TestControllerOptions(t *testing.T) {
	o := Options{}.controllerOptions()
	if o.MaxConcurrentReconciles != 1 || o.ReconciliationTimeout != DefaultReconciliationTimeout {
		t.Errorf("defaults: %d workers, timeout %s", o.MaxConcurrentReconciles, o.ReconciliationTimeout)
	}
	o = Options{MaxConcurrentReconciles: 7, ReconciliationTimeout: time.Minute}.controllerOptions()
	if o.MaxConcurrentReconciles != 7 || o.ReconciliationTimeout != time.Minute {
		t.Errorf("explicit: %d workers, timeout %s", o.MaxConcurrentReconciles, o.ReconciliationTimeout)
	}
}

func TestRenderRefusesServiceAccountTokens(t *testing.T) {
	// The type is refused by the schema of the CRD, and also here, for a cluster where the rule of
	// the schema did not run. Nothing is looked up: the refusal comes first.
	pss := &passwordstorev1alpha1.PasswordStoreSecret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "token"},
		Spec: passwordstorev1alpha1.PasswordStoreSecretSpec{
			StoreRef: passwordstorev1alpha1.StoreReference{Name: "store"},
			Template: &passwordstorev1alpha1.SecretTemplate{
				Type:     string(corev1.SecretTypeServiceAccountToken),
				Metadata: passwordstorev1alpha1.SecretTemplateMetadata{Annotations: map[string]string{corev1.ServiceAccountNameKey: "admin"}},
			},
			Data: map[string]string{"token": "a"},
		},
	}
	_, _, err := (&PasswordStoreSecretReconciler{}).render(context.Background(), pss)
	reason, ok := failureReason(err)
	if !ok || reason != passwordstorev1alpha1.ReasonInvalidSpec || !strings.Contains(err.Error(), "service-account-token") {
		t.Fatalf("err = %v (reason %q), want InvalidSpec that names the type", err, reason)
	}
}

func TestNamespaceAllowedWithoutPermissionToReadNamespaces(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	forbidden := interceptor.Funcs{Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
		return apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, "team", errors.New("no"))
	}}
	r := &PasswordStoreSecretReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(forbidden).Build()}
	store := &passwordstorev1alpha1.ClusterPasswordStore{
		ObjectMeta: metav1.ObjectMeta{Name: "shared"},
		Spec: passwordstorev1alpha1.ClusterPasswordStoreSpec{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "payments"}},
		},
	}

	allowed, err := r.namespaceAllowed(context.Background(), store, "team")
	reason, ok := failureReason(err)
	if allowed || !ok || reason != passwordstorev1alpha1.ReasonPermissionDenied {
		t.Fatalf("allowed = %v, err = %v (reason %q), want it refused with PermissionDenied", allowed, err, reason)
	}
	if !strings.Contains(err.Error(), `"team"`) || !strings.Contains(err.Error(), `"shared"`) {
		t.Errorf("the message does not say which namespace and store: %v", err)
	}

	// Without a selector the namespace is not read, so the permission is not needed.
	store.Spec.NamespaceSelector = nil
	if allowed, err := r.namespaceAllowed(context.Background(), store, "team"); !allowed || err != nil {
		t.Errorf("without a selector: allowed = %v, err = %v", allowed, err)
	}
}
