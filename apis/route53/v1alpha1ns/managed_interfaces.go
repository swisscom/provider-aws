package v1alpha1ns

import xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"

func (mg *ResourceRecordSet) GetCondition(ct xpv1.ConditionType) xpv1.Condition { return mg.Status.GetCondition(ct) }
func (mg *ResourceRecordSet) SetConditions(c ...xpv1.Condition) { mg.Status.SetConditions(c...) }
func (mg *ResourceRecordSet) GetDeletionPolicy() xpv1.DeletionPolicy { return mg.Spec.DeletionPolicy }
func (mg *ResourceRecordSet) SetDeletionPolicy(p xpv1.DeletionPolicy) { mg.Spec.DeletionPolicy = p }
func (mg *ResourceRecordSet) GetManagementPolicies() xpv1.ManagementPolicies { return mg.Spec.ManagementPolicies }
func (mg *ResourceRecordSet) SetManagementPolicies(p xpv1.ManagementPolicies) { mg.Spec.ManagementPolicies = p }
func (mg *ResourceRecordSet) GetProviderConfigReference() *xpv1.Reference {
	if mg.Spec.ProviderConfigReference == nil { return nil }
	return &xpv1.Reference{Name: mg.Spec.ProviderConfigReference.Name}
}
func (mg *ResourceRecordSet) SetProviderConfigReference(r *xpv1.Reference) {
	if r == nil { mg.Spec.ProviderConfigReference = nil; return }
	if mg.Spec.ProviderConfigReference == nil { mg.Spec.ProviderConfigReference = &ProviderConfigReference{} }
	mg.Spec.ProviderConfigReference.Name = r.Name
}
func (mg *ResourceRecordSet) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo { return nil }
func (mg *ResourceRecordSet) SetPublishConnectionDetailsTo(_ *xpv1.PublishConnectionDetailsTo) {}
func (mg *ResourceRecordSet) GetWriteConnectionSecretToReference() *xpv1.SecretReference {
	if mg.Spec.WriteConnectionSecretToReference == nil { return nil }
	return &xpv1.SecretReference{Name: mg.Spec.WriteConnectionSecretToReference.Name, Namespace: mg.Namespace}
}
func (mg *ResourceRecordSet) SetWriteConnectionSecretToReference(r *xpv1.SecretReference) {
	if r == nil { mg.Spec.WriteConnectionSecretToReference = nil; return }
	mg.Spec.WriteConnectionSecretToReference = &LocalSecretReference{Name: r.Name}
}
