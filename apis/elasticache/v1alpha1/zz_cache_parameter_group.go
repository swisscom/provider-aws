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

// CacheParameterGroupParameters defines the desired state of CacheParameterGroup
type CacheParameterGroupParameters struct {
	// Region is which region the CacheParameterGroup will be created.
	// +kubebuilder:validation:Required
	Region string `json:"region"`
	// The name of the cache parameter group family that the cache parameter group
	// can be used with.
	//
	// Valid values are: memcached1.4 | memcached1.5 | memcached1.6 | redis2.6 |
	// redis2.8 | redis3.2 | redis4.0 | redis5.0 | redis6.x
	// +kubebuilder:validation:Required
	CacheParameterGroupFamily *string `json:"cacheParameterGroupFamily"`
	// A user-specified description for the cache parameter group.
	// +kubebuilder:validation:Required
	Description *string `json:"description"`
	// A list of tags to be added to this resource. A tag is a key-value pair. A
	// tag key must be accompanied by a tag value, although null is accepted.
	Tags                                []*Tag `json:"tags,omitempty"`
	CustomCacheParameterGroupParameters `json:",inline"`
}

// CacheParameterGroupSpec defines the desired state of CacheParameterGroup
type CacheParameterGroupSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       CacheParameterGroupParameters `json:"forProvider"`
}

// CacheParameterGroupObservation defines the observed state of CacheParameterGroup
type CacheParameterGroupObservation struct {
	// The ARN (Amazon Resource Name) of the cache parameter group.
	ARN *string `json:"arn,omitempty"`
	// The name of the cache parameter group.
	CacheParameterGroupName *string `json:"cacheParameterGroupName,omitempty"`
	// Indicates whether the parameter group is associated with a Global datastore
	IsGlobal *bool `json:"isGlobal,omitempty"`
}

// CacheParameterGroupStatus defines the observed state of CacheParameterGroup.
type CacheParameterGroupStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          CacheParameterGroupObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// CacheParameterGroup is the Schema for the CacheParameterGroups API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,aws}
type CacheParameterGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              CacheParameterGroupSpec   `json:"spec"`
	Status            CacheParameterGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CacheParameterGroupList contains a list of CacheParameterGroups
type CacheParameterGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CacheParameterGroup `json:"items"`
}

// Repository type metadata.
var (
	CacheParameterGroupKind             = "CacheParameterGroup"
	CacheParameterGroupGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: CacheParameterGroupKind}.String()
	CacheParameterGroupKindAPIVersion   = CacheParameterGroupKind + "." + GroupVersion.String()
	CacheParameterGroupGroupVersionKind = GroupVersion.WithKind(CacheParameterGroupKind)
)

func init() {
	SchemeBuilder.Register(&CacheParameterGroup{}, &CacheParameterGroupList{})
}
