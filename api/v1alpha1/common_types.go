package v1alpha1

// Kinds of password store that a PasswordStoreSecret can reference.
const (
	// KindPasswordStore is the namespaced store kind.
	KindPasswordStore = "PasswordStore"
	// KindClusterPasswordStore is the cluster-scoped store kind.
	KindClusterPasswordStore = "ClusterPasswordStore"
)

// ConditionReady is the condition type reported on every resource of this API group.
const ConditionReady = "Ready"

// Condition reasons set on the Ready condition.
const (
	// ReasonSynced means the resource is reconciled and up to date.
	ReasonSynced = "Synced"
	// ReasonInvalidSpec means the spec is semantically invalid, or asks for something that the
	// operator is set not to accept, such as a Git host that is not in its list.
	ReasonInvalidSpec = "InvalidSpec"
	// ReasonCredentialsUnavailable means a referenced Secret or key could not be read.
	ReasonCredentialsUnavailable = "CredentialsUnavailable"
	// ReasonGitSyncFailed means the Git repository could not be fetched.
	ReasonGitSyncFailed = "GitSyncFailed"
	// ReasonGPGKeyInvalid means the GPG private key could not be loaded or unlocked.
	ReasonGPGKeyInvalid = "GPGKeyInvalid"
	// ReasonStoreNotFound means the referenced store does not exist.
	ReasonStoreNotFound = "StoreNotFound"
	// ReasonNamespaceNotAllowed means the ClusterPasswordStore does not allow this namespace.
	ReasonNamespaceNotAllowed = "NamespaceNotAllowed"
	// ReasonEntryNotFound means an entry referenced in spec.data is missing from the store or cannot
	// be read, or the line or field that is selected from it does not exist.
	ReasonEntryNotFound = "EntryNotFound"
	// ReasonDecryptFailed means an entry could not be decrypted: it is not encrypted to the key, is
	// not an OpenPGP message, or is too large.
	ReasonDecryptFailed = "DecryptFailed"
	// ReasonSecretConflict means the target Secret exists and is not managed by this resource.
	ReasonSecretConflict = "SecretConflict"
	// ReasonSecretApplyFailed means the target Secret could not be created or updated.
	ReasonSecretApplyFailed = "SecretApplyFailed"
	// ReasonPermissionDenied means the operator is not allowed to do something that it needs to,
	// such as reading the namespace of a PasswordStoreSecret to evaluate a namespaceSelector.
	ReasonPermissionDenied = "PermissionDenied"
)

// ManagedAnnotation can be set to "true" on an existing Secret to let a PasswordStoreSecret
// take it over instead of reporting a conflict.
const ManagedAnnotation = "passwordstore.k8s.sorend.github.com/managed"

// SecretKeySelector selects a key of a Secret.
type SecretKeySelector struct {
	// name of the Secret.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name"`

	// namespace of the Secret. Required on a ClusterPasswordStore. On a PasswordStore it may be
	// omitted and otherwise must equal the namespace of the store: cross-namespace references
	// are not allowed.
	// +optional
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace,omitempty"`

	// key within the Secret's data. When omitted a default that depends on the referencing
	// field is used; the default is documented on that field.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	Key string `json:"key,omitempty"`
}
