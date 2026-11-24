package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DefaultRefreshInterval is the refresh interval applied when spec.refreshInterval is omitted.
const DefaultRefreshInterval = "5m"

// PasswordStoreSecretSpec defines the desired state of PasswordStoreSecret.
type PasswordStoreSecretSpec struct {
	// storeRef selects the password store to read the entries from.
	// +required
	StoreRef StoreReference `json:"storeRef"`

	// refreshInterval is how often the store is checked for changes and the Secret is
	// rendered again. A Secret is also refreshed as soon as its store sees a new commit.
	// +optional
	// +kubebuilder:default="5m"
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('10s')",message="refreshInterval must be at least 10s"
	RefreshInterval *metav1.Duration `json:"refreshInterval,omitempty"`

	// template describes the Secret that is generated, much like the template of a SealedSecret.
	// +optional
	Template *SecretTemplate `json:"template,omitempty"`

	// data maps keys of the generated Secret to entries of the password store. Each value is
	// the path of an entry relative to the root of the store, without the .gpg suffix, for
	// example k8s/postgres.db.svc/admin-user.
	//
	// A path on its own yields the whole decrypted entry. If the entry is a single line its
	// trailing newline is removed, entries with several lines are used as they are. A path can
	// be followed by a selector: "path#2" yields line 2 of the entry (so "path#1" is the first
	// line, which pass(1) treats as the password) and "path#username" yields the value of the
	// first "username: value" line after the first line of the entry, ignoring case. The name of
	// a field has no colon in it.
	// +required
	// +kubebuilder:validation:MinProperties=1
	// +kubebuilder:validation:MaxProperties=100
	// +kubebuilder:validation:XValidation:rule="self.all(k, size(k) <= 253 && k.matches('^[-._a-zA-Z0-9]+$') && k != '.' && !k.startsWith('..'))",message="keys must be 1 to 253 alphanumeric characters, '-', '_' or '.', and must not be '.' or start with '..'"
	Data map[string]string `json:"data"`
}

// StoreReference selects a password store.
type StoreReference struct {
	// kind of the store. A PasswordStore is looked up in the namespace of the
	// PasswordStoreSecret, a ClusterPasswordStore is cluster-wide.
	// +optional
	// +kubebuilder:default=PasswordStore
	// +kubebuilder:validation:Enum=PasswordStore;ClusterPasswordStore
	Kind string `json:"kind,omitempty"`

	// name of the store.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name"`
}

// SecretTemplate describes the Secret generated for a PasswordStoreSecret.
type SecretTemplate struct {
	// metadata of the generated Secret.
	// +optional
	Metadata SecretTemplateMetadata `json:"metadata,omitzero"`

	// type of the generated Secret, for example kubernetes.io/tls. Defaults to Opaque.
	// Kubernetes does not allow the type of an existing Secret to change. A Secret of type
	// kubernetes.io/service-account-token cannot be generated: Kubernetes fills such a Secret with
	// the token of a ServiceAccount, which this resource would otherwise give to whoever can create it.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self != 'kubernetes.io/service-account-token'",message="Secrets of type kubernetes.io/service-account-token cannot be generated"
	Type string `json:"type,omitempty"`
}

// SecretTemplateMetadata is the part of the metadata of a generated Secret that can be set.
type SecretTemplateMetadata struct {
	// name of the generated Secret. Defaults to the name of the PasswordStoreSecret. The Secret
	// is always created in the namespace of the PasswordStoreSecret.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name,omitempty"`

	// labels added to the generated Secret.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// annotations added to the generated Secret.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// PasswordStoreSecretStatus defines the observed state of PasswordStoreSecret.
type PasswordStoreSecretStatus struct {
	// observedGeneration is the generation of the spec that was last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the resource. The Ready condition is True when
	// the Secret was rendered from the latest revision of the store.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// secretName is the name of the generated Secret.
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// revision is the commit SHA of the store that the Secret was last rendered from.
	// +optional
	Revision string `json:"revision,omitempty"`

	// lastRefreshTime is when the Secret was last rendered successfully.
	// +optional
	LastRefreshTime *metav1.Time `json:"lastRefreshTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=pwss
// +kubebuilder:printcolumn:name="Store",type=string,JSONPath=`.spec.storeRef.name`
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.status.secretName`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Revision",type=string,JSONPath=`.status.revision`,priority=1
// +kubebuilder:printcolumn:name="Message",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].message`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PasswordStoreSecret generates a Kubernetes Secret from entries of a password store.
type PasswordStoreSecret struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PasswordStoreSecret
	// +required
	Spec PasswordStoreSecretSpec `json:"spec"`

	// status defines the observed state of PasswordStoreSecret
	// +optional
	Status PasswordStoreSecretStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PasswordStoreSecretList contains a list of PasswordStoreSecret
type PasswordStoreSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PasswordStoreSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &PasswordStoreSecret{}, &PasswordStoreSecretList{})
		return nil
	})
}
