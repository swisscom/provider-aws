package v1alpha1ns

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	route53v1alpha1 "github.com/crossplane-contrib/provider-aws/apis/route53/v1alpha1"
)

type ResourceRecordSetSpec struct {
	NamespacedSpec `json:",inline"`
	ForProvider    route53v1alpha1.ResourceRecordSetParameters `json:"forProvider"`
}

type ResourceRecordSetStatus struct {
	NamespacedStatus `json:",inline"`
}

// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,aws}
type ResourceRecordSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ResourceRecordSetSpec   `json:"spec"`
	Status            ResourceRecordSetStatus `json:"status,omitempty"`
}

type ResourceRecordSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResourceRecordSet `json:"items"`
}

var (
	ResourceRecordSetKind             = "ResourceRecordSet"
	ResourceRecordSetGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ResourceRecordSetKind}.String()
	ResourceRecordSetKindAPIVersion   = ResourceRecordSetKind + "." + GroupVersion.String()
	ResourceRecordSetGroupVersionKind = GroupVersion.WithKind(ResourceRecordSetKind)
)

func init() {
	SchemeBuilder.Register(&ResourceRecordSet{}, &ResourceRecordSetList{})
}
