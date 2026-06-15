package v1alpha1ns

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"
)

type GlobalClusterSpec struct {
	NamespacedSpec `json:",inline"`
	ForProvider    svcapitypes.GlobalClusterParameters `json:"forProvider"`
}

type GlobalClusterStatus struct {
	NamespacedStatus `json:",inline"`
	AtProvider       svcapitypes.GlobalClusterObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,aws}
type GlobalCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              GlobalClusterSpec   `json:"spec"`
	Status            GlobalClusterStatus `json:"status,omitempty"`
}

type GlobalClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GlobalCluster `json:"items"`
}

var (
	GlobalClusterKind             = "GlobalCluster"
	GlobalClusterGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: GlobalClusterKind}.String()
	GlobalClusterKindAPIVersion   = GlobalClusterKind + "." + GroupVersion.String()
	GlobalClusterGroupVersionKind = GroupVersion.WithKind(GlobalClusterKind)
)

func init() {
	SchemeBuilder.Register(&GlobalCluster{}, &GlobalClusterList{})
}
