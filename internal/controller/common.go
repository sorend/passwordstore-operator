package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
	"github.com/sorend/passwordstore-operator/internal/gitstore"
	"github.com/sorend/passwordstore-operator/internal/printable"
)

// Defaults for Options.
const (
	DefaultStoreSyncInterval       = 5 * time.Minute
	DefaultRetryInterval           = time.Minute
	DefaultFetchCooldown           = 10 * time.Second
	DefaultMaxConcurrentReconciles = 4
	// DefaultReconciliationTimeout is how long one reconcile may take. It is a good deal longer than
	// a fetch from a Git server, so that a fetch that is allowed to run its course is not cut short.
	DefaultReconciliationTimeout = 3 * time.Minute

	// minRefreshInterval is the lowest refresh interval that is honored. The CRD already requires
	// it, this keeps an object that got past the schema from making the operator busy-loop.
	minRefreshInterval = 10 * time.Second

	// maxMessageLength bounds the message of a condition.
	maxMessageLength = 1024

	// minRedactedLength is the length that a credential must have for it to be redacted from
	// messages. Shorter values would also match unrelated text.
	minRedactedLength = 6
)

// Options configure the reconcilers. They are shared by all of them.
type Options struct {
	// Git fetches the stores. It is shared, so that a store is fetched once for the reconcilers
	// of the store and of the Secrets that use it.
	Git *gitstore.Manager

	// StoreSyncInterval is how often a store checks its repository on its own. Defaults to
	// DefaultStoreSyncInterval.
	StoreSyncInterval time.Duration

	// RetryInterval is how soon a reconcile that failed is tried again. Defaults to
	// DefaultRetryInterval.
	RetryInterval time.Duration

	// FetchCooldown is the time within which a Secret reuses the last check of its store instead
	// of contacting the remote again. Zero makes every refresh contact the remote.
	FetchCooldown time.Duration

	// MaxConcurrentReconciles is the number of objects that a controller reconciles at the same
	// time. Defaults to 1.
	MaxConcurrentReconciles int

	// ReconciliationTimeout is how long a reconcile may take. A reconcile that is stuck, for example
	// on a server that does not answer, then does not keep its worker for ever. Defaults to
	// DefaultReconciliationTimeout.
	ReconciliationTimeout time.Duration
}

func (o Options) reconciliationTimeout() time.Duration {
	if o.ReconciliationTimeout <= 0 {
		return DefaultReconciliationTimeout
	}
	return o.ReconciliationTimeout
}

// controllerOptions are the options that every controller of the operator is made with.
func (o Options) controllerOptions() controller.Options {
	return controller.Options{
		MaxConcurrentReconciles: max(o.MaxConcurrentReconciles, 1),
		ReconciliationTimeout:   o.reconciliationTimeout(),
	}
}

func (o Options) storeSyncInterval() time.Duration {
	if o.StoreSyncInterval <= 0 {
		return DefaultStoreSyncInterval
	}
	return o.StoreSyncInterval
}

func (o Options) retryInterval() time.Duration {
	if o.RetryInterval <= 0 {
		return DefaultRetryInterval
	}
	return o.RetryInterval
}

// failure is an error that carries the reason to put in the Ready condition.
type failure struct {
	reason string
	err    error
}

func (f *failure) Error() string { return f.err.Error() }
func (f *failure) Unwrap() error { return f.err }

// fail returns an error with a reason for the Ready condition.
func fail(reason, format string, args ...any) error {
	return &failure{reason: reason, err: fmt.Errorf(format, args...)}
}

// failWrap returns err with a reason for the Ready condition.
func failWrap(reason string, err error) error {
	return &failure{reason: reason, err: err}
}

// failureReason returns the reason of an error made by fail or failWrap.
func failureReason(err error) (string, bool) {
	if f, ok := errors.AsType[*failure](err); ok {
		return f.reason, true
	}
	return "", false
}

// message turns an error into the message of a condition. Credentials are removed from it, which
// should not be in an error anyway, and it is shortened. It is also made fit to be shown: what a
// server answers with ends up here, and people read it in a terminal.
func message(err error, sensitive [][]byte) string {
	return printable.String(redact(err.Error(), sensitive), maxMessageLength)
}

// syncFailure gives the error of fetching a repository its reason. A repository that the spec names
// and that the operator is set not to accept is a problem of the spec, the rest is a problem of the fetch.
func syncFailure(err error) error {
	if errors.Is(err, gitstore.ErrInvalidConfig) || errors.Is(err, gitstore.ErrHostNotAllowed) {
		return failWrap(passwordstorev1alpha1.ReasonInvalidSpec, err)
	}
	return failWrap(passwordstorev1alpha1.ReasonGitSyncFailed, err)
}

// redact replaces credentials in text. Errors from the Git libraries and from the servers are
// not expected to repeat a credential, but they end up in a resource that more people can read
// than the credentials themselves.
func redact(text string, sensitive [][]byte) string {
	for _, s := range sensitive {
		v := strings.TrimSpace(string(s))
		if len(v) >= minRedactedLength {
			text = strings.ReplaceAll(text, v, "***")
		}
		// A key of several lines is also hidden line by line, as an error may only show one of them.
		if strings.Contains(v, "\n") {
			for line := range strings.SplitSeq(v, "\n") {
				if line = strings.TrimSpace(line); len(line) >= minRedactedLength {
					text = strings.ReplaceAll(text, line, "***")
				}
			}
		}
	}
	return text
}

// setReady sets the Ready condition and reports whether it changed in a way that people can
// see: its status, reason or message.
func setReady(conditions *[]metav1.Condition, generation int64, status metav1.ConditionStatus, reason, msg string) bool {
	previous := meta.FindStatusCondition(*conditions, passwordstorev1alpha1.ConditionReady)
	changed := previous == nil || previous.Status != status || previous.Reason != reason || previous.Message != msg
	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               passwordstorev1alpha1.ConditionReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: generation,
	})
	return changed
}

// patchStatus writes the status of obj, as changed by mutate, if it changed.
func patchStatus(ctx context.Context, c client.Client, obj client.Object, mutate func()) error {
	base, ok := obj.DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("%T is not a client.Object", obj)
	}
	mutate()
	if equality.Semantic.DeepEqual(base, obj) {
		return nil
	}
	return c.Status().Patch(ctx, obj, client.MergeFrom(base))
}

// emit records an event, unless there is no recorder, which is the case in some tests.
func emit(recorder events.EventRecorder, obj client.Object, eventType, reason, note string) {
	if recorder == nil {
		return
	}
	recorder.Eventf(obj, nil, eventType, reason, "Reconcile", "%s", note)
}

// shortRevision shortens a commit SHA for messages.
func shortRevision(revision string) string {
	if len(revision) > 7 {
		return revision[:7]
	}
	return revision
}
