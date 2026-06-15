package v1beta1ns

import xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"

func (mg *SecurityGroup) GetCondition(ct xpv1.ConditionType) xpv1.Condition { return mg.Status.GetCondition(ct) }
func (mg *SecurityGroup) SetConditions(c ...xpv1.Condition) { mg.Status.SetConditions(c...) }
func (mg *SecurityGroup) GetDeletionPolicy() xpv1.DeletionPolicy { return mg.Spec.DeletionPolicy }
func (mg *SecurityGroup) SetDeletionPolicy(p xpv1.DeletionPolicy) { mg.Spec.DeletionPolicy = p }
func (mg *SecurityGroup) GetManagementPolicies() xpv1.ManagementPolicies { return mg.Spec.ManagementPolicies }
func (mg *SecurityGroup) SetManagementPolicies(p xpv1.ManagementPolicies) { mg.Spec.ManagementPolicies = p }
func (mg *SecurityGroup) GetProviderConfigReference() *xpv1.Reference {
	if mg.Spec.ProviderConfigReference == nil { return nil }
	return &xpv1.Reference{Name: mg.Spec.ProviderConfigReference.Name}
}
func (mg *SecurityGroup) SetProviderConfigReference(r *xpv1.Reference) {
	if r == nil { mg.Spec.ProviderConfigReference = nil; return }
	if mg.Spec.ProviderConfigReference == nil { mg.Spec.ProviderConfigReference = &ProviderConfigReference{} }
	mg.Spec.ProviderConfigReference.Name = r.Name
}
func (mg *SecurityGroup) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo { return nil }
func (mg *SecurityGroup) SetPublishConnectionDetailsTo(_ *xpv1.PublishConnectionDetailsTo) {}
func (mg *SecurityGroup) GetWriteConnectionSecretToReference() *xpv1.SecretReference {
	if mg.Spec.WriteConnectionSecretToReference == nil { return nil }
	return &xpv1.SecretReference{Name: mg.Spec.WriteConnectionSecretToReference.Name, Namespace: mg.Namespace}
}
func (mg *SecurityGroup) SetWriteConnectionSecretToReference(r *xpv1.SecretReference) {
	if r == nil { mg.Spec.WriteConnectionSecretToReference = nil; return }
	mg.Spec.WriteConnectionSecretToReference = &LocalSecretReference{Name: r.Name}
}
