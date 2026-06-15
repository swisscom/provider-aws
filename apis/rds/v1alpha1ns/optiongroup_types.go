package v1alpha1ns

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"
)

type OptionGroupSpec struct {
	NamespacedSpec `json:",inline"`
	ForProvider    svcapitypes.OptionGroupParameters `json:"forProvider"`
}

type OptionGroupStatus struct {
	NamespacedStatus `json:",inline"`
	AtProvider       svcapitypes.OptionGroupObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,aws}
type OptionGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OptionGroupSpec   `json:"spec"`
	Status            OptionGroupStatus `json:"status,omitempty"`
}

type OptionGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OptionGroup `json:"items"`
}

var (
	OptionGroupKind             = "OptionGroup"
	OptionGroupGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: OptionGroupKind}.String()
	OptionGroupKindAPIVersion   = OptionGroupKind + "." + GroupVersion.String()
	OptionGroupGroupVersionKind = GroupVersion.WithKind(OptionGroupKind)
)

func init() {
	SchemeBuilder.Register(&OptionGroup{}, &OptionGroupList{})
}
