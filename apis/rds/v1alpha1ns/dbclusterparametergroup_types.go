package v1alpha1ns

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"
)

type DBClusterParameterGroupSpec struct {
	NamespacedSpec `json:",inline"`
	ForProvider    svcapitypes.DBClusterParameterGroupParameters `json:"forProvider"`
}

type DBClusterParameterGroupStatus struct {
	NamespacedStatus `json:",inline"`
	AtProvider       svcapitypes.DBClusterParameterGroupObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,aws}
type DBClusterParameterGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DBClusterParameterGroupSpec   `json:"spec"`
	Status            DBClusterParameterGroupStatus `json:"status,omitempty"`
}

type DBClusterParameterGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DBClusterParameterGroup `json:"items"`
}

var (
	DBClusterParameterGroupKind             = "DBClusterParameterGroup"
	DBClusterParameterGroupGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: DBClusterParameterGroupKind}.String()
	DBClusterParameterGroupKindAPIVersion   = DBClusterParameterGroupKind + "." + GroupVersion.String()
	DBClusterParameterGroupGroupVersionKind = GroupVersion.WithKind(DBClusterParameterGroupKind)
)

func init() {
	SchemeBuilder.Register(&DBClusterParameterGroup{}, &DBClusterParameterGroupList{})
}
