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

// TransitGatewayVPCAttachmentParameters defines the desired state of TransitGatewayVPCAttachment
type TransitGatewayVPCAttachmentParameters struct {
	// Region is which region the TransitGatewayVPCAttachment will be created.
	// +kubebuilder:validation:Required
	Region string `json:"region"`
	// The VPC attachment options.
	Options *CreateTransitGatewayVPCAttachmentRequestOptions `json:"options,omitempty"`
	// The tags to apply to the VPC attachment.
	TagSpecifications                           []*TagSpecification `json:"tagSpecifications,omitempty"`
	CustomTransitGatewayVPCAttachmentParameters `json:",inline"`
}

// TransitGatewayVPCAttachmentSpec defines the desired state of TransitGatewayVPCAttachment
type TransitGatewayVPCAttachmentSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       TransitGatewayVPCAttachmentParameters `json:"forProvider"`
}

// TransitGatewayVPCAttachmentObservation defines the observed state of TransitGatewayVPCAttachment
type TransitGatewayVPCAttachmentObservation struct {
	// The creation time.
	CreationTime *metav1.Time `json:"creationTime,omitempty"`
	// The state of the VPC attachment. Note that the initiating state has been
	// deprecated.
	State *string `json:"state,omitempty"`
	// The IDs of the subnets.
	SubnetIDs []*string `json:"subnetIDs,omitempty"`
	// The tags for the VPC attachment.
	Tags []*Tag `json:"tags,omitempty"`
	// The ID of the attachment.
	TransitGatewayAttachmentID *string `json:"transitGatewayAttachmentID,omitempty"`
	// The ID of the transit gateway.
	TransitGatewayID *string `json:"transitGatewayID,omitempty"`
	// The ID of the VPC.
	VPCID *string `json:"vpcID,omitempty"`
	// The ID of the Amazon Web Services account that owns the VPC.
	VPCOwnerID *string `json:"vpcOwnerID,omitempty"`

	CustomTransitGatewayVPCAttachmentObservation `json:",inline"`
}

// TransitGatewayVPCAttachmentStatus defines the observed state of TransitGatewayVPCAttachment.
type TransitGatewayVPCAttachmentStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          TransitGatewayVPCAttachmentObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// TransitGatewayVPCAttachment is the Schema for the TransitGatewayVPCAttachments API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,aws}
type TransitGatewayVPCAttachment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TransitGatewayVPCAttachmentSpec   `json:"spec"`
	Status            TransitGatewayVPCAttachmentStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TransitGatewayVPCAttachmentList contains a list of TransitGatewayVPCAttachments
type TransitGatewayVPCAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TransitGatewayVPCAttachment `json:"items"`
}

// Repository type metadata.
var (
	TransitGatewayVPCAttachmentKind             = "TransitGatewayVPCAttachment"
	TransitGatewayVPCAttachmentGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: TransitGatewayVPCAttachmentKind}.String()
	TransitGatewayVPCAttachmentKindAPIVersion   = TransitGatewayVPCAttachmentKind + "." + GroupVersion.String()
	TransitGatewayVPCAttachmentGroupVersionKind = GroupVersion.WithKind(TransitGatewayVPCAttachmentKind)
)

func init() {
	SchemeBuilder.Register(&TransitGatewayVPCAttachment{}, &TransitGatewayVPCAttachmentList{})
}
