package v1alpha1ns

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"
)

type DBClusterSpec struct {
	NamespacedSpec `json:",inline"`
	ForProvider    svcapitypes.DBClusterParameters `json:"forProvider"`
}

type DBClusterStatus struct {
	NamespacedStatus `json:",inline"`
	AtProvider       svcapitypes.DBClusterObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,aws}
type DBCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DBClusterSpec   `json:"spec"`
	Status            DBClusterStatus `json:"status,omitempty"`
}

type DBClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DBCluster `json:"items"`
}

var (
	DBClusterKind             = "DBCluster"
	DBClusterGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: DBClusterKind}.String()
	DBClusterKindAPIVersion   = DBClusterKind + "." + GroupVersion.String()
	DBClusterGroupVersionKind = GroupVersion.WithKind(DBClusterKind)
)

func init() {
	SchemeBuilder.Register(&DBCluster{}, &DBClusterList{})
}
