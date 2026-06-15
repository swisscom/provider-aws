package v1alpha1ns

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"
)

type DBInstanceRoleAssociationSpec struct {
	NamespacedSpec `json:",inline"`
	ForProvider    svcapitypes.DBInstanceRoleAssociationParameters `json:"forProvider"`
}

type DBInstanceRoleAssociationStatus struct {
	NamespacedStatus `json:",inline"`
	AtProvider       svcapitypes.DBInstanceRoleAssociationObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,aws}
type DBInstanceRoleAssociation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DBInstanceRoleAssociationSpec   `json:"spec"`
	Status            DBInstanceRoleAssociationStatus `json:"status,omitempty"`
}

type DBInstanceRoleAssociationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DBInstanceRoleAssociation `json:"items"`
}

var (
	DBInstanceRoleAssociationKind             = "DBInstanceRoleAssociation"
	DBInstanceRoleAssociationGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: DBInstanceRoleAssociationKind}.String()
	DBInstanceRoleAssociationKindAPIVersion   = DBInstanceRoleAssociationKind + "." + GroupVersion.String()
	DBInstanceRoleAssociationGroupVersionKind = GroupVersion.WithKind(DBInstanceRoleAssociationKind)
)

func init() {
	SchemeBuilder.Register(&DBInstanceRoleAssociation{}, &DBInstanceRoleAssociationList{})
}
