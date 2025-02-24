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

// StageParameters defines the desired state of Stage
type StageParameters struct {
	// Region is which region the Stage will be created.
	// +kubebuilder:validation:Required
	Region string `json:"region"`

	AccessLogSettings *AccessLogSettings `json:"accessLogSettings,omitempty"`

	AutoDeploy *bool `json:"autoDeploy,omitempty"`

	ClientCertificateID *string `json:"clientCertificateID,omitempty"`

	DefaultRouteSettings *RouteSettings `json:"defaultRouteSettings,omitempty"`

	DeploymentID *string `json:"deploymentID,omitempty"`

	Description *string `json:"description,omitempty"`

	RouteSettings map[string]*RouteSettings `json:"routeSettings,omitempty"`

	StageVariables map[string]*string `json:"stageVariables,omitempty"`

	Tags                  map[string]*string `json:"tags,omitempty"`
	CustomStageParameters `json:",inline"`
}

// StageSpec defines the desired state of Stage
type StageSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       StageParameters `json:"forProvider"`
}

// StageObservation defines the observed state of Stage
type StageObservation struct {
	APIGatewayManaged *bool `json:"apiGatewayManaged,omitempty"`

	CreatedDate *metav1.Time `json:"createdDate,omitempty"`

	LastDeploymentStatusMessage *string `json:"lastDeploymentStatusMessage,omitempty"`

	LastUpdatedDate *metav1.Time `json:"lastUpdatedDate,omitempty"`

	StageName *string `json:"stageName,omitempty"`

	CustomStageObservation `json:",inline"`
}

// StageStatus defines the observed state of Stage.
type StageStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          StageObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// Stage is the Schema for the Stages API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,aws}
type Stage struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              StageSpec   `json:"spec"`
	Status            StageStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// StageList contains a list of Stages
type StageList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Stage `json:"items"`
}

// Repository type metadata.
var (
	StageKind             = "Stage"
	StageGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: StageKind}.String()
	StageKindAPIVersion   = StageKind + "." + GroupVersion.String()
	StageGroupVersionKind = GroupVersion.WithKind(StageKind)
)

func init() {
	SchemeBuilder.Register(&Stage{}, &StageList{})
}
