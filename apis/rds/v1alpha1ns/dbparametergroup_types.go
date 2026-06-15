package v1alpha1ns

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"
)

type DBParameterGroupSpec struct {
	NamespacedSpec `json:",inline"`
	ForProvider    svcapitypes.DBParameterGroupParameters `json:"forProvider"`
}

type DBParameterGroupStatus struct {
	NamespacedStatus `json:",inline"`
	AtProvider       svcapitypes.DBParameterGroupObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,aws}
type DBParameterGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DBParameterGroupSpec   `json:"spec"`
	Status            DBParameterGroupStatus `json:"status,omitempty"`
}

type DBParameterGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DBParameterGroup `json:"items"`
}

var (
	DBParameterGroupKind             = "DBParameterGroup"
	DBParameterGroupGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: DBParameterGroupKind}.String()
	DBParameterGroupKindAPIVersion   = DBParameterGroupKind + "." + GroupVersion.String()
	DBParameterGroupGroupVersionKind = GroupVersion.WithKind(DBParameterGroupKind)
)

func init() {
	SchemeBuilder.Register(&DBParameterGroup{}, &DBParameterGroupList{})
}
