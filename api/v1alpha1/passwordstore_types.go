package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// PasswordStoreSpec defines the desired state of a password store. It is shared by
// PasswordStore and ClusterPasswordStore.
type PasswordStoreSpec struct {
	// gitRepo describes the Git repository that holds the password store.
	// +required
	GitRepo GitRepoSpec `json:"gitRepo"`

	// gpg describes the GPG key used to decrypt the entries of the store.
	// +required
	GPG GPGSpec `json:"gpg"`
}

// GitRepoSpec describes how to reach the Git repository of a password store.
// +kubebuilder:validation:XValidation:rule="!(self.url.startsWith('ssh://') || !self.url.contains('://')) || (has(self.auth) && has(self.auth.ssh))",message="ssh and scp-style URLs require auth.ssh"
// +kubebuilder:validation:XValidation:rule="!has(self.auth) || !has(self.auth.ssh) || self.url.startsWith('ssh://') || !self.url.contains('://')",message="auth.ssh requires an ssh:// or scp-style URL"
// +kubebuilder:validation:XValidation:rule="!has(self.auth) || !(has(self.auth.token) || has(self.auth.app)) || self.url.startsWith('https://') || self.url.startsWith('http://')",message="auth.token and auth.app require an http(s):// URL"
type GitRepoSpec struct {
	// url of the Git repository. Supported forms are https://host/org/repo.git,
	// http://host/org/repo.git, ssh://[user@]host[:port]/org/repo.git and the scp-like
	// [user@]host:org/repo.git or [user@]host:/absolute/repo.git. Credentials must not be embedded in
	// the URL, use auth instead. http:// sends credentials, if there are any, in the clear.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^(https?://[^@/\s]+(/\S*)?|ssh://([^@:/\s]+@)?[^@/\s]+(/\S*)?|([A-Za-z0-9._-]+@)?[A-Za-z0-9._-]+:(/[^/\s]|[^/\s])\S*)$`
	URL string `json:"url"`

	// branch to read the store from. Defaults to the default branch of the remote.
	// +optional
	// +kubebuilder:validation:MaxLength=255
	Branch string `json:"branch,omitempty"`

	// path of the password store inside the repository, that is the directory that holds
	// the .gpg-id file. Defaults to the root of the repository.
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Path string `json:"path,omitempty"`

	// auth configures how to authenticate to the repository. Omit it to clone anonymously,
	// which only works for public repositories over http(s).
	// +optional
	Auth *GitAuth `json:"auth,omitempty"`
}

// GitAuth selects one way to authenticate to a Git repository.
// +kubebuilder:validation:XValidation:rule="[has(self.ssh), has(self.token), has(self.app)].filter(x, x).size() <= 1",message="at most one of ssh, token or app may be set"
type GitAuth struct {
	// ssh authenticates with an SSH private key. Requires an ssh:// or scp-style URL.
	// +optional
	SSH *GitSSHAuth `json:"ssh,omitempty"`

	// token authenticates over http(s) with a personal access token, deploy token or similar.
	// +optional
	Token *GitTokenAuth `json:"token,omitempty"`

	// app authenticates over https as a GitHub App installation. The operator signs a JWT with
	// the App's private key and exchanges it for a short-lived, read-only installation token.
	// +optional
	App *GitAppAuth `json:"app,omitempty"`
}

// GitSSHAuth authenticates to Git over SSH with a private key.
// +kubebuilder:validation:XValidation:rule="(has(self.knownHosts) && self.knownHosts.trim().size() > 0) || (has(self.insecureIgnoreHostKey) && self.insecureIgnoreHostKey)",message="knownHosts is required unless insecureIgnoreHostKey is true"
// +kubebuilder:validation:XValidation:rule="!(has(self.knownHosts) && self.knownHosts.trim().size() > 0 && has(self.insecureIgnoreHostKey) && self.insecureIgnoreHostKey)",message="knownHosts and insecureIgnoreHostKey are mutually exclusive"
type GitSSHAuth struct {
	// privateKeySecretRef selects the Secret key that holds the private key in PEM or OpenSSH
	// format. The key defaults to "ssh-privatekey", which matches Secrets of type
	// kubernetes.io/ssh-auth. The user name is taken from the repository URL and defaults to "git".
	// +required
	PrivateKeySecretRef SecretKeySelector `json:"privateKeySecretRef"`

	// passphraseSecretRef selects the Secret key that holds the passphrase of the private key.
	// The key defaults to "passphrase". Omit it for unencrypted keys.
	// +optional
	PassphraseSecretRef *SecretKeySelector `json:"passphraseSecretRef,omitempty"`

	// knownHosts holds the host keys of the Git server in known_hosts format, for example the
	// output of "ssh-keyscan -t ed25519 github.com". Host keys are public, so they are part
	// of the spec instead of a Secret. Required unless insecureIgnoreHostKey is true.
	// +optional
	// +kubebuilder:validation:MaxLength=65536
	KnownHosts string `json:"knownHosts,omitempty"`

	// insecureIgnoreHostKey disables verification of the server's host key. This makes the
	// connection vulnerable to man-in-the-middle attacks, only use it for testing.
	// +optional
	InsecureIgnoreHostKey bool `json:"insecureIgnoreHostKey,omitempty"`
}

// GitTokenAuth authenticates to Git over http(s) with a token sent as HTTP basic auth password.
type GitTokenAuth struct {
	// username sent together with the token. Defaults to "x-access-token", which GitHub and
	// GitLab accept for personal access tokens. Some providers require a specific value,
	// for example "oauth2" for GitLab OAuth tokens or "x-token-auth" for Bitbucket.
	// +optional
	// +kubebuilder:validation:MaxLength=255
	Username string `json:"username,omitempty"`

	// tokenSecretRef selects the Secret key that holds the token. The key defaults to "token".
	// +required
	TokenSecretRef SecretKeySelector `json:"tokenSecretRef"`
}

// GitAppAuth authenticates to GitHub as a GitHub App installation.
type GitAppAuth struct {
	// appID is the numeric ID of the GitHub App.
	// +required
	// +kubebuilder:validation:Minimum=1
	AppID int64 `json:"appID"`

	// installationID is the numeric ID of the installation of the App that has access to the
	// repository.
	// +required
	// +kubebuilder:validation:Minimum=1
	InstallationID int64 `json:"installationID"`

	// privateKeySecretRef selects the Secret key that holds the App's private key in PEM
	// format. The key defaults to "private-key.pem".
	// +required
	PrivateKeySecretRef SecretKeySelector `json:"privateKeySecretRef"`

	// baseURL of the GitHub API. Defaults to https://api.github.com. For GitHub Enterprise
	// Server use https://HOSTNAME/api/v3.
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https?://[^@\s]+$`
	BaseURL string `json:"baseURL,omitempty"`
}

// GPGSpec describes the key used to decrypt the entries of a password store.
type GPGSpec struct {
	// id of the GPG key the store is encrypted to, as given to "pass init". It can be a
	// fingerprint, a long or short key ID, or part of a user ID such as an email address.
	// It selects the key to use when the Secret holds more than one.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	ID string `json:"id"`

	// privateKeySecretRef selects the Secret key that holds the private key, ASCII-armored or
	// binary, as written by "gpg --export-secret-keys". The key defaults to "private.key".
	// +required
	PrivateKeySecretRef SecretKeySelector `json:"privateKeySecretRef"`

	// passphraseSecretRef selects the Secret key that holds the passphrase of the private key.
	// The key defaults to "passphrase". Omit it for keys without a passphrase.
	// +optional
	PassphraseSecretRef *SecretKeySelector `json:"passphraseSecretRef,omitempty"`
}

// PasswordStoreStatus defines the observed state of a password store. It is shared by
// PasswordStore and ClusterPasswordStore.
type PasswordStoreStatus struct {
	// observedGeneration is the generation of the spec that was last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the store. The Ready condition is True when
	// the repository was fetched and the GPG key was unlocked.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// revision is the commit SHA of the repository that was last fetched successfully.
	// +optional
	Revision string `json:"revision,omitempty"`

	// lastSyncTime is when the repository was last fetched successfully.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// gpgFingerprint is the fingerprint of the private key that was selected by gpg.id.
	// +optional
	GPGFingerprint string `json:"gpgFingerprint,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=pws
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Revision",type=string,JSONPath=`.status.revision`
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.gitRepo.url`,priority=1
// +kubebuilder:printcolumn:name="Message",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].message`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PasswordStore is a pass(1) password store in a Git repository that PasswordStoreSecrets in the
// same namespace can read from. Secrets it references must live in its own namespace.
type PasswordStore struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PasswordStore
	// +required
	Spec PasswordStoreSpec `json:"spec"`

	// status defines the observed state of PasswordStore
	// +optional
	Status PasswordStoreStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PasswordStoreList contains a list of PasswordStore
type PasswordStoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PasswordStore `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &PasswordStore{}, &PasswordStoreList{})
		return nil
	})
}
