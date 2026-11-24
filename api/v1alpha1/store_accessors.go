package v1alpha1

// StoreSpec returns the part of the spec that PasswordStore and ClusterPasswordStore share.
func (s *PasswordStore) StoreSpec() *PasswordStoreSpec { return &s.Spec }

// StoreStatus returns the part of the status that PasswordStore and ClusterPasswordStore share.
func (s *PasswordStore) StoreStatus() *PasswordStoreStatus { return &s.Status }

// StoreSpec returns the part of the spec that PasswordStore and ClusterPasswordStore share.
func (s *ClusterPasswordStore) StoreSpec() *PasswordStoreSpec { return &s.Spec.PasswordStoreSpec }

// StoreStatus returns the part of the status that PasswordStore and ClusterPasswordStore share.
func (s *ClusterPasswordStore) StoreStatus() *PasswordStoreStatus {
	return &s.Status.PasswordStoreStatus
}

// ResolvedKind returns the kind of the referenced store, which is PasswordStore when the kind is
// not set.
func (r StoreReference) ResolvedKind() string {
	if r.Kind == "" {
		return KindPasswordStore
	}
	return r.Kind
}
