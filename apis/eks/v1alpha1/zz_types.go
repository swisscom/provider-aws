/*
Copyright 2021 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by ack-generate. DO NOT EDIT.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Hack to avoid import errors during build...
var (
	_ = &metav1.Time{}
)

// +kubebuilder:skipversion
type AddonHealth struct {
	Issues []*AddonIssue `json:"issues,omitempty"`
}

// +kubebuilder:skipversion
type AddonInfo struct {
	AddonName *string `json:"addonName,omitempty"`
	// Information about an Amazon EKS add-on from the Amazon Web Services Marketplace.
	MarketplaceInformation *MarketplaceInformation `json:"marketplaceInformation,omitempty"`

	Owner *string `json:"owner,omitempty"`

	Publisher *string `json:"publisher,omitempty"`

	Type *string `json:"type_,omitempty"`
}

// +kubebuilder:skipversion
type AddonIssue struct {
	Code *string `json:"code,omitempty"`

	Message *string `json:"message,omitempty"`

	ResourceIDs []*string `json:"resourceIDs,omitempty"`
}

// +kubebuilder:skipversion
type AddonVersionInfo struct {
	AddonVersion *string `json:"addonVersion,omitempty"`

	Architecture []*string `json:"architecture,omitempty"`

	RequiresConfiguration *bool `json:"requiresConfiguration,omitempty"`
}

// +kubebuilder:skipversion
type Addon_SDK struct {
	AddonARN *string `json:"addonARN,omitempty"`

	AddonName *string `json:"addonName,omitempty"`

	AddonVersion *string `json:"addonVersion,omitempty"`

	ClusterName *string `json:"clusterName,omitempty"`

	ConfigurationValues *string `json:"configurationValues,omitempty"`

	CreatedAt *metav1.Time `json:"createdAt,omitempty"`
	// The health of the add-on.
	Health *AddonHealth `json:"health,omitempty"`
	// Information about an Amazon EKS add-on from the Amazon Web Services Marketplace.
	MarketplaceInformation *MarketplaceInformation `json:"marketplaceInformation,omitempty"`

	ModifiedAt *metav1.Time `json:"modifiedAt,omitempty"`

	Owner *string `json:"owner,omitempty"`

	Publisher *string `json:"publisher,omitempty"`

	ServiceAccountRoleARN *string `json:"serviceAccountRoleARN,omitempty"`

	Status *string `json:"status,omitempty"`
	// The metadata that you apply to a resource to help you categorize and organize
	// them. Each tag consists of a key and an optional value. You define them.
	//
	// The following basic restrictions apply to tags:
	//
	//    * Maximum number of tags per resource – 50
	//
	//    * For each resource, each tag key must be unique, and each tag key can
	//    have only one value.
	//
	//    * Maximum key length – 128 Unicode characters in UTF-8
	//
	//    * Maximum value length – 256 Unicode characters in UTF-8
	//
	//    * If your tagging schema is used across multiple services and resources,
	//    remember that other services may have restrictions on allowed characters.
	//    Generally allowed characters are: letters, numbers, and spaces representable
	//    in UTF-8, and the following characters: + - = . _ : / @.
	//
	//    * Tag keys and values are case-sensitive.
	//
	//    * Do not use aws:, AWS:, or any upper or lowercase combination of such
	//    as a prefix for either keys or values as it is reserved for Amazon Web
	//    Services use. You cannot edit or delete tag keys or values with this prefix.
	//    Tags with this prefix do not count against your tags per resource limit.
	Tags map[string]*string `json:"tags,omitempty"`
}

// +kubebuilder:skipversion
type AutoScalingGroup struct {
	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type Certificate struct {
	Data *string `json:"data,omitempty"`
}

// +kubebuilder:skipversion
type ClusterIssue struct {
	Message *string `json:"message,omitempty"`

	ResourceIDs []*string `json:"resourceIDs,omitempty"`
}

// +kubebuilder:skipversion
type Compatibility struct {
	ClusterVersion *string `json:"clusterVersion,omitempty"`

	DefaultVersion *bool `json:"defaultVersion,omitempty"`

	PlatformVersions []*string `json:"platformVersions,omitempty"`
}

// +kubebuilder:skipversion
type ConnectorConfigRequest struct {
	RoleARN *string `json:"roleARN,omitempty"`
}

// +kubebuilder:skipversion
type ConnectorConfigResponse struct {
	ActivationCode *string `json:"activationCode,omitempty"`

	ActivationExpiry *metav1.Time `json:"activationExpiry,omitempty"`

	ActivationID *string `json:"activationID,omitempty"`

	Provider *string `json:"provider,omitempty"`

	RoleARN *string `json:"roleARN,omitempty"`
}

// +kubebuilder:skipversion
type ControlPlanePlacementRequest struct {
	GroupName *string `json:"groupName,omitempty"`
}

// +kubebuilder:skipversion
type ControlPlanePlacementResponse struct {
	GroupName *string `json:"groupName,omitempty"`
}

// +kubebuilder:skipversion
type EKSAnywhereSubscription struct {
	ARN *string `json:"arn,omitempty"`

	AutoRenew *bool `json:"autoRenew,omitempty"`

	CreatedAt *metav1.Time `json:"createdAt,omitempty"`

	EffectiveDate *metav1.Time `json:"effectiveDate,omitempty"`

	ExpirationDate *metav1.Time `json:"expirationDate,omitempty"`

	ID *string `json:"id,omitempty"`

	LicenseARNs []*string `json:"licenseARNs,omitempty"`

	Status *string `json:"status,omitempty"`
	// The metadata that you apply to a resource to help you categorize and organize
	// them. Each tag consists of a key and an optional value. You define them.
	//
	// The following basic restrictions apply to tags:
	//
	//    * Maximum number of tags per resource – 50
	//
	//    * For each resource, each tag key must be unique, and each tag key can
	//    have only one value.
	//
	//    * Maximum key length – 128 Unicode characters in UTF-8
	//
	//    * Maximum value length – 256 Unicode characters in UTF-8
	//
	//    * If your tagging schema is used across multiple services and resources,
	//    remember that other services may have restrictions on allowed characters.
	//    Generally allowed characters are: letters, numbers, and spaces representable
	//    in UTF-8, and the following characters: + - = . _ : / @.
	//
	//    * Tag keys and values are case-sensitive.
	//
	//    * Do not use aws:, AWS:, or any upper or lowercase combination of such
	//    as a prefix for either keys or values as it is reserved for Amazon Web
	//    Services use. You cannot edit or delete tag keys or values with this prefix.
	//    Tags with this prefix do not count against your tags per resource limit.
	Tags map[string]*string `json:"tags,omitempty"`
}

// +kubebuilder:skipversion
type EncryptionConfig struct {
	Resources []*string `json:"resources,omitempty"`
}

// +kubebuilder:skipversion
type ErrorDetail struct {
	ErrorCode *string `json:"errorCode,omitempty"`

	ErrorMessage *string `json:"errorMessage,omitempty"`

	ResourceIDs []*string `json:"resourceIDs,omitempty"`
}

// +kubebuilder:skipversion
type FargateProfileSelector struct {
	Namespace *string `json:"namespace,omitempty"`
}

// +kubebuilder:skipversion
type Issue struct {
	Message *string `json:"message,omitempty"`

	ResourceIDs []*string `json:"resourceIDs,omitempty"`
}

// +kubebuilder:skipversion
type KubernetesNetworkConfigRequest struct {
	ServiceIPv4CIDR *string `json:"serviceIPv4CIDR,omitempty"`
}

// +kubebuilder:skipversion
type KubernetesNetworkConfigResponse struct {
	ServiceIPv4CIDR *string `json:"serviceIPv4CIDR,omitempty"`

	ServiceIPv6CIDR *string `json:"serviceIPv6CIDR,omitempty"`
}

// +kubebuilder:skipversion
type LaunchTemplateSpecification struct {
	ID *string `json:"id,omitempty"`

	Name *string `json:"name,omitempty"`

	Version *string `json:"version,omitempty"`
}

// +kubebuilder:skipversion
type MarketplaceInformation struct {
	ProductID *string `json:"productID,omitempty"`

	ProductURL *string `json:"productURL,omitempty"`
}

// +kubebuilder:skipversion
type NodegroupResources struct {
	RemoteAccessSecurityGroup *string `json:"remoteAccessSecurityGroup,omitempty"`
}

// +kubebuilder:skipversion
type OIDC struct {
	Issuer *string `json:"issuer,omitempty"`
}

// +kubebuilder:skipversion
type OIDCIdentityProviderConfig struct {
	ClientID *string `json:"clientID,omitempty"`

	ClusterName *string `json:"clusterName,omitempty"`

	GroupsClaim *string `json:"groupsClaim,omitempty"`

	GroupsPrefix *string `json:"groupsPrefix,omitempty"`

	IdentityProviderConfigARN *string `json:"identityProviderConfigARN,omitempty"`

	IdentityProviderConfigName *string `json:"identityProviderConfigName,omitempty"`

	IssuerURL *string `json:"issuerURL,omitempty"`
	// The metadata that you apply to a resource to help you categorize and organize
	// them. Each tag consists of a key and an optional value. You define them.
	//
	// The following basic restrictions apply to tags:
	//
	//    * Maximum number of tags per resource – 50
	//
	//    * For each resource, each tag key must be unique, and each tag key can
	//    have only one value.
	//
	//    * Maximum key length – 128 Unicode characters in UTF-8
	//
	//    * Maximum value length – 256 Unicode characters in UTF-8
	//
	//    * If your tagging schema is used across multiple services and resources,
	//    remember that other services may have restrictions on allowed characters.
	//    Generally allowed characters are: letters, numbers, and spaces representable
	//    in UTF-8, and the following characters: + - = . _ : / @.
	//
	//    * Tag keys and values are case-sensitive.
	//
	//    * Do not use aws:, AWS:, or any upper or lowercase combination of such
	//    as a prefix for either keys or values as it is reserved for Amazon Web
	//    Services use. You cannot edit or delete tag keys or values with this prefix.
	//    Tags with this prefix do not count against your tags per resource limit.
	Tags map[string]*string `json:"tags,omitempty"`

	UsernameClaim *string `json:"usernameClaim,omitempty"`

	UsernamePrefix *string `json:"usernamePrefix,omitempty"`
}

// +kubebuilder:skipversion
type OIDCIdentityProviderConfigRequest struct {
	ClientID *string `json:"clientID,omitempty"`

	GroupsClaim *string `json:"groupsClaim,omitempty"`

	GroupsPrefix *string `json:"groupsPrefix,omitempty"`

	IdentityProviderConfigName *string `json:"identityProviderConfigName,omitempty"`

	IssuerURL *string `json:"issuerURL,omitempty"`

	UsernameClaim *string `json:"usernameClaim,omitempty"`

	UsernamePrefix *string `json:"usernamePrefix,omitempty"`
}

// +kubebuilder:skipversion
type OutpostConfigRequest struct {
	ControlPlaneInstanceType *string `json:"controlPlaneInstanceType,omitempty"`

	OutpostARNs []*string `json:"outpostARNs,omitempty"`
}

// +kubebuilder:skipversion
type OutpostConfigResponse struct {
	ControlPlaneInstanceType *string `json:"controlPlaneInstanceType,omitempty"`

	OutpostARNs []*string `json:"outpostARNs,omitempty"`
}

// +kubebuilder:skipversion
type PodIdentityAssociation struct {
	AssociationARN *string `json:"associationARN,omitempty"`

	AssociationID *string `json:"associationID,omitempty"`

	ClusterName *string `json:"clusterName,omitempty"`

	CreatedAt *metav1.Time `json:"createdAt,omitempty"`

	ModifiedAt *metav1.Time `json:"modifiedAt,omitempty"`

	Namespace *string `json:"namespace,omitempty"`

	RoleARN *string `json:"roleARN,omitempty"`

	ServiceAccount *string `json:"serviceAccount,omitempty"`
	// The metadata that you apply to a resource to help you categorize and organize
	// them. Each tag consists of a key and an optional value. You define them.
	//
	// The following basic restrictions apply to tags:
	//
	//    * Maximum number of tags per resource – 50
	//
	//    * For each resource, each tag key must be unique, and each tag key can
	//    have only one value.
	//
	//    * Maximum key length – 128 Unicode characters in UTF-8
	//
	//    * Maximum value length – 256 Unicode characters in UTF-8
	//
	//    * If your tagging schema is used across multiple services and resources,
	//    remember that other services may have restrictions on allowed characters.
	//    Generally allowed characters are: letters, numbers, and spaces representable
	//    in UTF-8, and the following characters: + - = . _ : / @.
	//
	//    * Tag keys and values are case-sensitive.
	//
	//    * Do not use aws:, AWS:, or any upper or lowercase combination of such
	//    as a prefix for either keys or values as it is reserved for Amazon Web
	//    Services use. You cannot edit or delete tag keys or values with this prefix.
	//    Tags with this prefix do not count against your tags per resource limit.
	Tags map[string]*string `json:"tags,omitempty"`
}

// +kubebuilder:skipversion
type PodIdentityAssociationSummary struct {
	AssociationARN *string `json:"associationARN,omitempty"`

	AssociationID *string `json:"associationID,omitempty"`

	ClusterName *string `json:"clusterName,omitempty"`

	Namespace *string `json:"namespace,omitempty"`

	ServiceAccount *string `json:"serviceAccount,omitempty"`
}

// +kubebuilder:skipversion
type Provider struct {
	KeyARN *string `json:"keyARN,omitempty"`
}

// +kubebuilder:skipversion
type RemoteAccessConfig struct {
	EC2SshKey *string `json:"ec2SshKey,omitempty"`

	SourceSecurityGroups []*string `json:"sourceSecurityGroups,omitempty"`
}

// +kubebuilder:skipversion
type Update struct {
	CreatedAt *metav1.Time `json:"createdAt,omitempty"`

	Errors []*ErrorDetail `json:"errors,omitempty"`

	ID *string `json:"id,omitempty"`

	Params []*UpdateParam `json:"params,omitempty"`

	Status *string `json:"status,omitempty"`

	Type *string `json:"type_,omitempty"`
}

// +kubebuilder:skipversion
type UpdateParam struct {
	Type *string `json:"type_,omitempty"`

	Value *string `json:"value,omitempty"`
}

// +kubebuilder:skipversion
type VPCConfigRequest struct {
	PublicAccessCIDRs []*string `json:"publicAccessCIDRs,omitempty"`

	SecurityGroupIDs []*string `json:"securityGroupIDs,omitempty"`

	SubnetIDs []*string `json:"subnetIDs,omitempty"`
}

// +kubebuilder:skipversion
type VPCConfigResponse struct {
	ClusterSecurityGroupID *string `json:"clusterSecurityGroupID,omitempty"`

	EndpointPrivateAccess *bool `json:"endpointPrivateAccess,omitempty"`

	EndpointPublicAccess *bool `json:"endpointPublicAccess,omitempty"`

	PublicAccessCIDRs []*string `json:"publicAccessCIDRs,omitempty"`

	SecurityGroupIDs []*string `json:"securityGroupIDs,omitempty"`

	SubnetIDs []*string `json:"subnetIDs,omitempty"`

	VPCID *string `json:"vpcID,omitempty"`
}
