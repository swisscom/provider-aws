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
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ProvisionedProductParameters defines the desired state of ProvisionedProduct
type ProvisionedProductParameters struct {
	// Region is which region the ProvisionedProduct will be created.
	// +kubebuilder:validation:Required
	Region string `json:"region"`
	// The language code.
	//
	//    * en - English (default)
	//
	//    * jp - Japanese
	//
	//    * zh - Chinese
	AcceptLanguage *string `json:"acceptLanguage,omitempty"`
	// Passed to CloudFormation. The SNS topic ARNs to which to publish stack-related
	// events.
	NotificationARNs []*string `json:"notificationARNs,omitempty"`
	// The path identifier of the product. This value is optional if the product
	// has a default path, and required if the product has more than one path. To
	// list the paths for a product, use ListLaunchPaths. You must provide the name
	// or ID, but not both.
	PathID *string `json:"pathID,omitempty"`
	// The name of the path. You must provide the name or ID, but not both.
	PathName *string `json:"pathName,omitempty"`
	// The product identifier. You must provide the name or ID, but not both.
	ProductID *string `json:"productID,omitempty"`
	// The name of the product. You must provide the name or ID, but not both.
	ProductName *string `json:"productName,omitempty"`
	// The identifier of the provisioning artifact. You must provide the name or
	// ID, but not both.
	ProvisioningArtifactID *string `json:"provisioningArtifactID,omitempty"`
	// The name of the provisioning artifact. You must provide the name or ID, but
	// not both.
	ProvisioningArtifactName *string `json:"provisioningArtifactName,omitempty"`
	// Parameters specified by the administrator that are required for provisioning
	// the product.
	ProvisioningParameters []*ProvisioningParameter `json:"provisioningParameters,omitempty"`
	// An object that contains information about the provisioning preferences for
	// a stack set.
	ProvisioningPreferences *ProvisioningPreferences `json:"provisioningPreferences,omitempty"`
	// One or more tags.
	Tags                               []*Tag `json:"tags,omitempty"`
	CustomProvisionedProductParameters `json:",inline"`
}

// ProvisionedProductSpec defines the desired state of ProvisionedProduct
type ProvisionedProductSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       ProvisionedProductParameters `json:"forProvider"`
}

// ProvisionedProductObservation defines the observed state of ProvisionedProduct
type ProvisionedProductObservation struct {
	// The ARN of the provisioned product.
	ARN *string `json:"arn,omitempty"`
	// The UTC time stamp of the creation time.
	CreatedTime *metav1.Time `json:"createdTime,omitempty"`
	// The path identifier.
	LastPathID *string `json:"lastPathID,omitempty"`
	// The product identifier. For example, prod-abcdzk7xy33qa.
	LastProductID *string `json:"lastProductID,omitempty"`
	// The identifier of the provisioning artifact. For example, pa-4abcdjnxjj6ne.
	LastProvisioningArtifactID *string `json:"lastProvisioningArtifactID,omitempty"`

	LastProvisioningParameters []*ProvisioningParameter `json:"lastProvisioningParameters,omitempty"`
	// The record identifier of the last request performed on this provisioned product
	// of the following types:
	//
	//    * ProvisionedProduct
	//
	//    * UpdateProvisionedProduct
	//
	//    * ExecuteProvisionedProductPlan
	//
	//    * TerminateProvisionedProduct
	LastProvisioningRecordID *string `json:"lastProvisioningRecordID,omitempty"`
	// The ARN of the launch role associated with the provisioned product.
	LaunchRoleARN *string `json:"launchRoleARN,omitempty"`

	Outputs map[string]*RecordOutput `json:"outputs,omitempty"`
	// The identifier of the provisioned product.
	ProvisionedProductID *string `json:"provisionedProductID,omitempty"`
	// The user-friendly name of the provisioned product.
	ProvisionedProductName *string `json:"provisionedProductName,omitempty"`
	// The type of provisioned product. The supported values are CFN_STACK and CFN_STACKSET.
	ProvisionedProductType *string `json:"provisionedProductType,omitempty"`
	// The errors that occurred.
	RecordErrors []*RecordError `json:"recordErrors,omitempty"`
	// The identifier of the record.
	RecordID *string `json:"recordID,omitempty"`
	// One or more tags.
	RecordTags []*RecordTag `json:"recordTags,omitempty"`
	// The record type.
	//
	//    * PROVISION_PRODUCT
	//
	//    * UPDATE_PROVISIONED_PRODUCT
	//
	//    * TERMINATE_PROVISIONED_PRODUCT
	RecordType *string `json:"recordType,omitempty"`
	// The current status of the provisioned product.
	//
	//    * AVAILABLE - Stable state, ready to perform any operation. The most recent
	//    operation succeeded and completed.
	//
	//    * UNDER_CHANGE - Transitive state. Operations performed might not have
	//    valid results. Wait for an AVAILABLE status before performing operations.
	//
	//    * TAINTED - Stable state, ready to perform any operation. The stack has
	//    completed the requested operation but is not exactly what was requested.
	//    For example, a request to update to a new version failed and the stack
	//    rolled back to the current version.
	//
	//    * ERROR - An unexpected error occurred. The provisioned product exists
	//    but the stack is not running. For example, CloudFormation received a parameter
	//    value that was not valid and could not launch the stack.
	//
	//    * PLAN_IN_PROGRESS - Transitive state. The plan operations were performed
	//    to provision a new product, but resources have not yet been created. After
	//    reviewing the list of resources to be created, execute the plan. Wait
	//    for an AVAILABLE status before performing operations.
	Status *string `json:"status,omitempty"`
	// The current status message of the provisioned product.
	StatusMessage *string `json:"statusMessage,omitempty"`
	// The time when the record was last updated.
	UpdatedTime *metav1.Time `json:"updatedTime,omitempty"`
}

// ProvisionedProductStatus defines the observed state of ProvisionedProduct.
type ProvisionedProductStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          ProvisionedProductObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// ProvisionedProduct is the Schema for the ProvisionedProducts API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,aws}
type ProvisionedProduct struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ProvisionedProductSpec   `json:"spec"`
	Status            ProvisionedProductStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ProvisionedProductList contains a list of ProvisionedProducts
type ProvisionedProductList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProvisionedProduct `json:"items"`
}

// Repository type metadata.
var (
	ProvisionedProductKind             = "ProvisionedProduct"
	ProvisionedProductGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ProvisionedProductKind}.String()
	ProvisionedProductKindAPIVersion   = ProvisionedProductKind + "." + GroupVersion.String()
	ProvisionedProductGroupVersionKind = GroupVersion.WithKind(ProvisionedProductKind)
)

func init() {
	SchemeBuilder.Register(&ProvisionedProduct{}, &ProvisionedProductList{})
}
