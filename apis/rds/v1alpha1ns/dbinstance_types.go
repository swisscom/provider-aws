package v1alpha1ns

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"
)

type DBInstanceSpec struct {
	NamespacedSpec `json:",inline"`
	ForProvider    svcapitypes.DBInstanceParameters `json:"forProvider"`
}

type DBInstanceStatus struct {
	NamespacedStatus `json:",inline"`
	AtProvider       svcapitypes.DBInstanceObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,aws}
type DBInstance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DBInstanceSpec   `json:"spec"`
	Status            DBInstanceStatus `json:"status,omitempty"`
}

type DBInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DBInstance `json:"items"`
}

var (
	DBInstanceKind             = "DBInstance"
	DBInstanceGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: DBInstanceKind}.String()
	DBInstanceKindAPIVersion   = DBInstanceKind + "." + GroupVersion.String()
	DBInstanceGroupVersionKind = GroupVersion.WithKind(DBInstanceKind)
)

func init() {
	SchemeBuilder.Register(&DBInstance{}, &DBInstanceList{})
}
