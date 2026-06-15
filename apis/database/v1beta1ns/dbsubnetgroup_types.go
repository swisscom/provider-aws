package v1beta1ns

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	databasev1beta1 "github.com/crossplane-contrib/provider-aws/apis/database/v1beta1"
)

type DBSubnetGroupSpec struct {
	NamespacedSpec `json:",inline"`
	ForProvider    databasev1beta1.DBSubnetGroupParameters `json:"forProvider,omitempty"`
}

type DBSubnetGroupStatus struct {
	NamespacedStatus `json:",inline"`
	AtProvider       databasev1beta1.DBSubnetGroupObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,aws}
type DBSubnetGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DBSubnetGroupSpec   `json:"spec"`
	Status            DBSubnetGroupStatus `json:"status,omitempty"`
}

type DBSubnetGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DBSubnetGroup `json:"items"`
}

var (
	DBSubnetGroupKind             = "DBSubnetGroup"
	DBSubnetGroupGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: DBSubnetGroupKind}.String()
	DBSubnetGroupKindAPIVersion   = DBSubnetGroupKind + "." + GroupVersion.String()
	DBSubnetGroupGroupVersionKind = GroupVersion.WithKind(DBSubnetGroupKind)
)

func init() {
	SchemeBuilder.Register(&DBSubnetGroup{}, &DBSubnetGroupList{})
}
