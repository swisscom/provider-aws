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

// RestAPIParameters defines the desired state of RestAPI
type RestAPIParameters struct {
	// Region is which region the RestAPI will be created.
	// +kubebuilder:validation:Required
	Region string `json:"region"`
	// The source of the API key for metering requests according to a usage plan.
	// Valid values are: >HEADER to read the API key from the X-API-Key header of
	// a request. AUTHORIZER to read the API key from the UsageIdentifierKey from
	// a custom authorizer.
	APIKeySource *string `json:"apiKeySource,omitempty"`
	// The list of binary media types supported by the RestApi. By default, the
	// RestApi supports only UTF-8-encoded text payloads.
	BinaryMediaTypes []*string `json:"binaryMediaTypes,omitempty"`
	// The ID of the RestApi that you want to clone from.
	CloneFrom *string `json:"cloneFrom,omitempty"`
	// The description of the RestApi.
	Description *string `json:"description,omitempty"`
	// Specifies whether clients can invoke your API by using the default execute-api
	// endpoint. By default, clients can invoke your API with the default https://{api_id}.execute-api.{region}.amazonaws.com
	// endpoint. To require that clients use a custom domain name to invoke your
	// API, disable the default endpoint
	DisableExecuteAPIEndpoint *bool `json:"disableExecuteAPIEndpoint,omitempty"`
	// The endpoint configuration of this RestApi showing the endpoint types of
	// the API.
	EndpointConfiguration *EndpointConfiguration `json:"endpointConfiguration,omitempty"`
	// A nullable integer that is used to enable compression (with non-negative
	// between 0 and 10485760 (10M) bytes, inclusive) or disable compression (with
	// a null value) on an API. When compression is enabled, compression or decompression
	// is not applied on the payload if the payload size is smaller than this value.
	// Setting it to zero allows compression for any payload size.
	MinimumCompressionSize *int64 `json:"minimumCompressionSize,omitempty"`
	// The name of the RestApi.
	// +kubebuilder:validation:Required
	Name *string `json:"name"`
	// A stringified JSON policy document that applies to this RestApi regardless
	// of the caller and Method configuration.
	Policy *string `json:"policy,omitempty"`
	// The key-value map of strings. The valid character set is [a-zA-Z+-=._:/].
	// The tag key can be up to 128 characters and must not start with aws:. The
	// tag value can be up to 256 characters.
	Tags map[string]*string `json:"tags,omitempty"`
	// A version identifier for the API.
	Version                 *string `json:"version,omitempty"`
	CustomRestAPIParameters `json:",inline"`
}

// RestAPISpec defines the desired state of RestAPI
type RestAPISpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       RestAPIParameters `json:"forProvider"`
}

// RestAPIObservation defines the observed state of RestAPI
type RestAPIObservation struct {
	// The timestamp when the API was created.
	CreatedDate *metav1.Time `json:"createdDate,omitempty"`
	// The API's identifier. This identifier is unique across all of your APIs in
	// API Gateway.
	ID *string `json:"id,omitempty"`
	// The warning messages reported when failonwarnings is turned on during API
	// import.
	Warnings []*string `json:"warnings,omitempty"`
}

// RestAPIStatus defines the observed state of RestAPI.
type RestAPIStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          RestAPIObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// RestAPI is the Schema for the RestAPIS API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,aws}
type RestAPI struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              RestAPISpec   `json:"spec"`
	Status            RestAPIStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RestAPIList contains a list of RestAPIS
type RestAPIList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RestAPI `json:"items"`
}

// Repository type metadata.
var (
	RestAPIKind             = "RestAPI"
	RestAPIGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: RestAPIKind}.String()
	RestAPIKindAPIVersion   = RestAPIKind + "." + GroupVersion.String()
	RestAPIGroupVersionKind = GroupVersion.WithKind(RestAPIKind)
)

func init() {
	SchemeBuilder.Register(&RestAPI{}, &RestAPIList{})
}
