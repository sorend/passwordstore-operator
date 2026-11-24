package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ClusterPasswordStoreSpec defines the desired state of ClusterPasswordStore.
type ClusterPasswordStoreSpec struct {
	PasswordStoreSpec `json:",inline"`

	// namespaceSelector restricts which namespaces may use this store. A PasswordStoreSecret
	// can only reference the store when the labels of its namespace match the selector. When
	// omitted every namespace may use the store, so any user who can create a
	// PasswordStoreSecret can read every entry the store's key can decrypt.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// ClusterPasswordStoreStatus defines the observed state of ClusterPasswordStore.
type ClusterPasswordStoreStatus struct {
	PasswordStoreStatus `json:",inline"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cpws
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Revision",type=string,JSONPath=`.status.revision`
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.gitRepo.url`,priority=1
// +kubebuilder:printcolumn:name="Message",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].message`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ClusterPasswordStore is a pass(1) password store in a Git repository that PasswordStoreSecrets
// in any namespace can read from, optionally limited by namespaceSelector. Because it is not
// namespaced, every Secret reference in its spec must name a namespace.
type ClusterPasswordStore struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ClusterPasswordStore
	// +required
	Spec ClusterPasswordStoreSpec `json:"spec"`

	// status defines the observed state of ClusterPasswordStore
	// +optional
	Status ClusterPasswordStoreStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ClusterPasswordStoreList contains a list of ClusterPasswordStore
type ClusterPasswordStoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ClusterPasswordStore `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ClusterPasswordStore{}, &ClusterPasswordStoreList{})
		return nil
	})
}
