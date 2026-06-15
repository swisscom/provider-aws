package v1beta1ns

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	ec2v1beta1 "github.com/crossplane-contrib/provider-aws/apis/ec2/v1beta1"
)

type SecurityGroupSpec struct {
	NamespacedSpec `json:",inline"`
	ForProvider    ec2v1beta1.SecurityGroupParameters `json:"forProvider"`
}

type SecurityGroupStatus struct {
	NamespacedStatus `json:",inline"`
	AtProvider       ec2v1beta1.SecurityGroupObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,aws}
type SecurityGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SecurityGroupSpec   `json:"spec"`
	Status            SecurityGroupStatus `json:"status,omitempty"`
}

type SecurityGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityGroup `json:"items"`
}

var (
	SecurityGroupKind             = "SecurityGroup"
	SecurityGroupGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: SecurityGroupKind}.String()
	SecurityGroupKindAPIVersion   = SecurityGroupKind + "." + GroupVersion.String()
	SecurityGroupGroupVersionKind = GroupVersion.WithKind(SecurityGroupKind)
)

func init() {
	SchemeBuilder.Register(&SecurityGroup{}, &SecurityGroupList{})
}
