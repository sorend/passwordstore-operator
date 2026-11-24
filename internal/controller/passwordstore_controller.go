package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
)

// PasswordStoreReconciler reconciles a PasswordStore object
type PasswordStoreReconciler struct {
	client.Client
	// Reader reads Secrets directly from the API server, instead of from a cache.
	Reader   client.Reader
	Recorder events.EventRecorder
	Options
}

// +kubebuilder:rbac:groups=passwordstore.k8s.sorend.github.com,resources=passwordstores,verbs=get;list;watch
// +kubebuilder:rbac:groups=passwordstore.k8s.sorend.github.com,resources=passwordstores/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile checks that a PasswordStore is usable: its credentials can be read, its repository can
// be fetched and its GPG key can be unlocked. The result is in the status of the PasswordStore.
func (r *PasswordStoreReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	sr := &storeReconciler{Client: r.Client, Reader: r.Reader, Recorder: r.Recorder, Options: r.Options}

	var store passwordstorev1alpha1.PasswordStore
	if err := r.Get(ctx, req.NamespacedName, &store); err != nil {
		if apierrors.IsNotFound(err) {
			sr.forget(&passwordstorev1alpha1.PasswordStore{
				ObjectMeta: objectMeta(req.Namespace, req.Name),
			})
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if !store.DeletionTimestamp.IsZero() {
		sr.forget(&store)
		return ctrl.Result{}, nil
	}
	return sr.reconcile(ctx, &store)
}

// SetupWithManager sets up the controller with the Manager.
func (r *PasswordStoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// The status is written by this controller and must not trigger it again. A store checks
		// its repository again after its sync interval.
		For(&passwordstorev1alpha1.PasswordStore{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WithOptions(r.controllerOptions()).
		Named("passwordstore").
		Complete(r)
}
