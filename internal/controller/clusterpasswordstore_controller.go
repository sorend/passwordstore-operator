package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
)

// ClusterPasswordStoreReconciler reconciles a ClusterPasswordStore object
type ClusterPasswordStoreReconciler struct {
	client.Client
	// Reader reads Secrets directly from the API server, instead of from a cache.
	Reader   client.Reader
	Recorder events.EventRecorder
	Options
}

// +kubebuilder:rbac:groups=passwordstore.k8s.sorend.github.com,resources=clusterpasswordstores,verbs=get;list;watch
// +kubebuilder:rbac:groups=passwordstore.k8s.sorend.github.com,resources=clusterpasswordstores/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile checks that a ClusterPasswordStore is usable: its credentials can be read, its
// repository can be fetched and its GPG key can be unlocked. The result is in its status.
func (r *ClusterPasswordStoreReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	sr := &storeReconciler{Client: r.Client, Reader: r.Reader, Recorder: r.Recorder, Options: r.Options}

	var store passwordstorev1alpha1.ClusterPasswordStore
	if err := r.Get(ctx, req.NamespacedName, &store); err != nil {
		if apierrors.IsNotFound(err) {
			sr.forget(&passwordstorev1alpha1.ClusterPasswordStore{ObjectMeta: objectMeta("", req.Name)})
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
func (r *ClusterPasswordStoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&passwordstorev1alpha1.ClusterPasswordStore{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WithOptions(r.controllerOptions()).
		Named("clusterpasswordstore").
		Complete(r)
}

func objectMeta(namespace, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: namespace, Name: name}
}
