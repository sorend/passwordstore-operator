package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
)

const (
	// managedByLabel marks the Secrets that the operator generates.
	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "passwordstore-operator"

	// managedMetadataAnnotation records which labels and annotations come from the template of the
	// PasswordStoreSecret. When one is removed from the template it is removed from the Secret too,
	// while the labels and annotations that other tools put on the Secret are left alone.
	managedMetadataAnnotation = "passwordstore.k8s.sorend.github.com/managed-metadata"
)

// managedMetadata is the content of managedMetadataAnnotation.
type managedMetadata struct {
	Labels      []string `json:"labels,omitempty"`
	Annotations []string `json:"annotations,omitempty"`
}

func readManagedMetadata(annotations map[string]string) managedMetadata {
	var m managedMetadata
	if raw, ok := annotations[managedMetadataAnnotation]; ok {
		// An annotation that cannot be read is treated as empty, which only means that a label
		// that was removed from the template is not removed from the Secret this time.
		_ = json.Unmarshal([]byte(raw), &m)
	}
	return m
}

// templateMetadata returns the labels and annotations of the template. The labels and annotations
// that the operator owns cannot be set from the template.
func templateMetadata(pss *passwordstorev1alpha1.PasswordStoreSecret) (labels, annotations map[string]string) {
	labels, annotations = map[string]string{}, map[string]string{}
	if t := pss.Spec.Template; t != nil {
		maps.Copy(labels, t.Metadata.Labels)
		maps.Copy(annotations, t.Metadata.Annotations)
	}
	delete(labels, managedByLabel)
	delete(annotations, managedMetadataAnnotation)
	return labels, annotations
}

// mergeMetadata returns current with the entries of desired set, and the entries removed that were
// set from the template before and no longer are. It returns nil for an empty map.
func mergeMetadata(current, desired map[string]string, previouslyManaged []string) map[string]string {
	out := maps.Clone(current)
	if out == nil {
		out = map[string]string{}
	}
	for _, key := range previouslyManaged {
		if _, stillWanted := desired[key]; !stillWanted {
			delete(out, key)
		}
	}
	maps.Copy(out, desired)
	if len(out) == 0 {
		return nil
	}
	return out
}

// secretType returns the type of the Secret that the PasswordStoreSecret describes.
func secretType(pss *passwordstorev1alpha1.PasswordStoreSecret) corev1.SecretType {
	if pss.Spec.Template != nil && pss.Spec.Template.Type != "" {
		return corev1.SecretType(pss.Spec.Template.Type)
	}
	return corev1.SecretTypeOpaque
}

// applySecret creates the Secret, or makes an existing one that belongs to the
// PasswordStoreSecret match it. A Secret that does not belong to it is not touched.
func (r *PasswordStoreSecretReconciler) applySecret(
	ctx context.Context, pss *passwordstorev1alpha1.PasswordStoreSecret, data map[string][]byte,
) error {
	name := targetName(pss)
	templateLabels, templateAnnotations := templateMetadata(pss)

	// The record of what came from the template is part of the Secret, so the next update knows
	// what to remove.
	record := managedMetadata{
		Labels:      slices.Sorted(maps.Keys(templateLabels)),
		Annotations: slices.Sorted(maps.Keys(templateAnnotations)),
	}
	desiredLabels := maps.Clone(templateLabels)
	desiredLabels[managedByLabel] = managedByValue
	desiredAnnotations := maps.Clone(templateAnnotations)
	if len(record.Labels) > 0 || len(record.Annotations) > 0 {
		raw, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("encode managed metadata: %w", err)
		}
		desiredAnnotations[managedMetadataAnnotation] = string(raw)
	}

	var existing corev1.Secret
	err := r.Reader.Get(ctx, types.NamespacedName{Namespace: pss.Namespace, Name: name}, &existing)
	if apierrors.IsNotFound(err) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   pss.Namespace,
				Name:        name,
				Labels:      desiredLabels,
				Annotations: mergeMetadata(nil, desiredAnnotations, nil),
			},
			Type: secretType(pss),
			Data: data,
		}
		if err := controllerutil.SetControllerReference(pss, secret, r.Scheme); err != nil {
			return failWrap(passwordstorev1alpha1.ReasonSecretApplyFailed, err)
		}
		return writeFailure("create", name, r.Create(ctx, secret))
	}
	if err != nil {
		return fmt.Errorf("get Secret %s/%s: %w", pss.Namespace, name, err)
	}

	if !existing.DeletionTimestamp.IsZero() {
		return fail(passwordstorev1alpha1.ReasonSecretApplyFailed, "Secret %q is being deleted", name)
	}
	owned := metav1.IsControlledBy(&existing, pss)
	if !owned {
		if owner := metav1.GetControllerOf(&existing); owner != nil {
			return fail(passwordstorev1alpha1.ReasonSecretConflict, "Secret %q is controlled by %s %q", name, owner.Kind, owner.Name)
		}
		if existing.Annotations[passwordstorev1alpha1.ManagedAnnotation] != "true" {
			return fail(passwordstorev1alpha1.ReasonSecretConflict,
				"Secret %q already exists and is not managed by this PasswordStoreSecret; to let it take over the Secret, annotate the Secret with %s=true",
				name, passwordstorev1alpha1.ManagedAnnotation)
		}
	}
	if want := secretType(pss); existing.Type != want {
		return fail(passwordstorev1alpha1.ReasonSecretApplyFailed,
			"the type of Secret %q is %q, which Kubernetes does not allow to change to %q; delete the Secret to have it created again",
			name, existing.Type, want)
	}

	previous := readManagedMetadata(existing.Annotations)
	updated := existing.DeepCopy()
	updated.Labels = mergeMetadata(existing.Labels, desiredLabels, previous.Labels)
	updated.Annotations = mergeMetadata(existing.Annotations, desiredAnnotations, previous.Annotations)
	if len(record.Labels) == 0 && len(record.Annotations) == 0 {
		delete(updated.Annotations, managedMetadataAnnotation)
	}
	updated.Data = data
	if !owned {
		if err := controllerutil.SetControllerReference(pss, updated, r.Scheme); err != nil {
			if _, ok := errors.AsType[*controllerutil.AlreadyOwnedError](err); ok {
				return failWrap(passwordstorev1alpha1.ReasonSecretConflict, err)
			}
			return failWrap(passwordstorev1alpha1.ReasonSecretApplyFailed, err)
		}
	}

	if equality.Semantic.DeepEqual(&existing, updated) {
		return nil
	}
	return writeFailure("update", name, r.Update(ctx, updated))
}

// writeFailure turns the error of a write into a reason for the condition when the cause is the
// content of the Secret, which only a change of the spec can fix. Other errors are returned as
// they are, to be tried again.
func writeFailure(action, name string, err error) error {
	switch {
	case err == nil:
		return nil
	case apierrors.IsInvalid(err), apierrors.IsForbidden(err), apierrors.IsRequestEntityTooLargeError(err):
		return failWrap(passwordstorev1alpha1.ReasonSecretApplyFailed, fmt.Errorf("%s Secret %q: %w", action, name, err))
	}
	return fmt.Errorf("%s Secret %q: %w", action, name, err)
}
