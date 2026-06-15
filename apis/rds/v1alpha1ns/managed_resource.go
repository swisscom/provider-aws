package v1alpha1ns

import (
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// LocalSecretReference is a reference to a secret in the same namespace.
type LocalSecretReference struct {
	// Name of the secret.
	Name string `json:"name"`
}

// ProviderConfigReference specifies the provider config to use.
// Only cluster-scoped ProviderConfig is supported in this temporary implementation.
type ProviderConfigReference struct {
	// Name of the provider config.
	// +kubebuilder:default="default"
	Name string `json:"name"`
}

// NamespacedSpec defines the desired state common to all namespaced managed resources.
// Fields match crossplane-runtime/v2 ManagedResourceSpec JSON schema.
type NamespacedSpec struct {
	// WriteConnectionSecretToReference specifies the name of a Secret to write
	// connection details to. The secret is created in the same namespace as the CR.
	// +optional
	WriteConnectionSecretToReference *LocalSecretReference `json:"writeConnectionSecretToRef,omitempty"`

	// ProviderConfigReference specifies how the provider should be configured.
	// +kubebuilder:default={"name": "default"}
	ProviderConfigReference *ProviderConfigReference `json:"providerConfigRef,omitempty"`

	// ManagementPolicies specify the array of actions Crossplane is allowed to
	// take on the managed and external resources.
	// +optional
	// +kubebuilder:default={"*"}
	ManagementPolicies xpv1.ManagementPolicies `json:"managementPolicies,omitempty"`

	// DeletionPolicy specifies what will happen to the underlying external
	// when this managed resource is deleted - either "Delete" or "Orphan" the
	// external resource.
	// +optional
	// +kubebuilder:default=Delete
	DeletionPolicy xpv1.DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// NamespacedStatus defines the observed state common to all namespaced managed resources.
type NamespacedStatus struct {
	xpv1.ConditionedStatus `json:",inline"`
}
