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

// ListenerParameters defines the desired state of Listener
type ListenerParameters struct {
	// Region is which region the Listener will be created.
	// +kubebuilder:validation:Required
	Region string `json:"region"`
	// Client affinity lets you direct all requests from a user to the same endpoint,
	// if you have stateful applications, regardless of the port and protocol of
	// the client request. Client affinity gives you control over whether to always
	// route each client to the same specific endpoint.
	//
	// Global Accelerator uses a consistent-flow hashing algorithm to choose the
	// optimal endpoint for a connection. If client affinity is NONE, Global Accelerator
	// uses the "five-tuple" (5-tuple) properties—source IP address, source port,
	// destination IP address, destination port, and protocol—to select the hash
	// value, and then chooses the best endpoint. However, with this setting, if
	// someone uses different ports to connect to Global Accelerator, their connections
	// might not be always routed to the same endpoint because the hash value changes.
	//
	// If you want a given client to always be routed to the same endpoint, set
	// client affinity to SOURCE_IP instead. When you use the SOURCE_IP setting,
	// Global Accelerator uses the "two-tuple" (2-tuple) properties— source (client)
	// IP address and destination IP address—to select the hash value.
	//
	// The default value is NONE.
	ClientAffinity *string `json:"clientAffinity,omitempty"`
	// The list of port ranges to support for connections from clients to your accelerator.
	// +kubebuilder:validation:Required
	PortRanges []*PortRange `json:"portRanges"`
	// The protocol for connections from clients to your accelerator.
	// +kubebuilder:validation:Required
	Protocol                 *string `json:"protocol"`
	CustomListenerParameters `json:",inline"`
}

// ListenerSpec defines the desired state of Listener
type ListenerSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       ListenerParameters `json:"forProvider"`
}

// ListenerObservation defines the observed state of Listener
type ListenerObservation struct {
	// The Amazon Resource Name (ARN) of the listener.
	ListenerARN *string `json:"listenerARN,omitempty"`

	CustomListenerObservation `json:",inline"`
}

// ListenerStatus defines the observed state of Listener.
type ListenerStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          ListenerObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// Listener is the Schema for the Listeners API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,aws}
type Listener struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ListenerSpec   `json:"spec"`
	Status            ListenerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ListenerList contains a list of Listeners
type ListenerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Listener `json:"items"`
}

// Repository type metadata.
var (
	ListenerKind             = "Listener"
	ListenerGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ListenerKind}.String()
	ListenerKindAPIVersion   = ListenerKind + "." + GroupVersion.String()
	ListenerGroupVersionKind = GroupVersion.WithKind(ListenerKind)
)

func init() {
	SchemeBuilder.Register(&Listener{}, &ListenerList{})
}
