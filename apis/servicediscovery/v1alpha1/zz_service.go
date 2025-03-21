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

// ServiceParameters defines the desired state of Service
type ServiceParameters struct {
	// Region is which region the Service will be created.
	// +kubebuilder:validation:Required
	Region string `json:"region"`
	// A unique string that identifies the request and that allows failed CreateService
	// requests to be retried without the risk of running the operation twice. CreatorRequestId
	// can be any unique string (for example, a date/timestamp).
	CreatorRequestID *string `json:"creatorRequestID,omitempty"`
	// A description for the service.
	Description *string `json:"description,omitempty"`
	// A complex type that contains information about the Amazon Route 53 records
	// that you want Cloud Map to create when you register an instance.
	DNSConfig *DNSConfig `json:"dnsConfig,omitempty"`
	// Public DNS and HTTP namespaces only. A complex type that contains settings
	// for an optional Route 53 health check. If you specify settings for a health
	// check, Cloud Map associates the health check with all the Route 53 DNS records
	// that you specify in DnsConfig.
	//
	// If you specify a health check configuration, you can specify either HealthCheckCustomConfig
	// or HealthCheckConfig but not both.
	//
	// For information about the charges for health checks, see Cloud Map Pricing
	// (http://aws.amazon.com/cloud-map/pricing/).
	HealthCheckConfig *HealthCheckConfig `json:"healthCheckConfig,omitempty"`
	// A complex type that contains information about an optional custom health
	// check.
	//
	// If you specify a health check configuration, you can specify either HealthCheckCustomConfig
	// or HealthCheckConfig but not both.
	//
	// You can't add, update, or delete a HealthCheckCustomConfig configuration
	// from an existing service.
	HealthCheckCustomConfig *HealthCheckCustomConfig `json:"healthCheckCustomConfig,omitempty"`
	// The name that you want to assign to the service.
	//
	// Do not include sensitive information in the name if the namespace is discoverable
	// by public DNS queries.
	//
	// If you want Cloud Map to create an SRV record when you register an instance
	// and you're using a system that requires a specific SRV format, such as HAProxy
	// (http://www.haproxy.org/), specify the following for Name:
	//
	//    * Start the name with an underscore (_), such as _exampleservice.
	//
	//    * End the name with ._protocol, such as ._tcp.
	//
	// When you register an instance, Cloud Map creates an SRV record and assigns
	// a name to the record by concatenating the service name and the namespace
	// name (for example,
	//
	// _exampleservice._tcp.example.com).
	//
	// For services that are accessible by DNS queries, you can't create multiple
	// services with names that differ only by case (such as EXAMPLE and example).
	// Otherwise, these services have the same DNS name and can't be distinguished.
	// However, if you use a namespace that's only accessible by API calls, then
	// you can create services that with names that differ only by case.
	// +kubebuilder:validation:Required
	Name *string `json:"name"`
	// The ID of the namespace that you want to use to create the service. The namespace
	// ID must be specified, but it can be specified either here or in the DnsConfig
	// object.
	NamespaceID *string `json:"namespaceID,omitempty"`
	// The tags to add to the service. Each tag consists of a key and an optional
	// value that you define. Tags keys can be up to 128 characters in length, and
	// tag values can be up to 256 characters in length.
	Tags []*Tag `json:"tags,omitempty"`
	// If present, specifies that the service instances are only discoverable using
	// the DiscoverInstances API operation. No DNS records is registered for the
	// service instances. The only valid value is HTTP.
	Type                    *string `json:"type_,omitempty"`
	CustomServiceParameters `json:",inline"`
}

// ServiceSpec defines the desired state of Service
type ServiceSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       ServiceParameters `json:"forProvider"`
}

// ServiceObservation defines the observed state of Service
type ServiceObservation struct {
	// The Amazon Resource Name (ARN) that Cloud Map assigns to the service when
	// you create it.
	ARN *string `json:"arn,omitempty"`
	// The date and time that the service was created, in Unix format and Coordinated
	// Universal Time (UTC). The value of CreateDate is accurate to milliseconds.
	// For example, the value 1516925490.087 represents Friday, January 26, 2018
	// 12:11:30.087 AM.
	CreateDate *metav1.Time `json:"createDate,omitempty"`
	// The ID that Cloud Map assigned to the service when you created it.
	ID *string `json:"id,omitempty"`
	// The number of instances that are currently associated with the service. Instances
	// that were previously associated with the service but that are deleted aren't
	// included in the count. The count might not reflect pending registrations
	// and deregistrations.
	InstanceCount *int64 `json:"instanceCount,omitempty"`

	CustomServiceObservation `json:",inline"`
}

// ServiceStatus defines the observed state of Service.
type ServiceStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          ServiceObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// Service is the Schema for the Services API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,aws}
type Service struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ServiceSpec   `json:"spec"`
	Status            ServiceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ServiceList contains a list of Services
type ServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Service `json:"items"`
}

// Repository type metadata.
var (
	ServiceKind             = "Service"
	ServiceGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ServiceKind}.String()
	ServiceKindAPIVersion   = ServiceKind + "." + GroupVersion.String()
	ServiceGroupVersionKind = GroupVersion.WithKind(ServiceKind)
)

func init() {
	SchemeBuilder.Register(&Service{}, &ServiceList{})
}
