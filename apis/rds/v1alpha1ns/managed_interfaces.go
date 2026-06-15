package v1alpha1ns

import xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"


func (mg *DBInstance) GetCondition(ct xpv1.ConditionType) xpv1.Condition { return mg.Status.GetCondition(ct) }
func (mg *DBInstance) SetConditions(c ...xpv1.Condition) { mg.Status.SetConditions(c...) }
func (mg *DBInstance) GetDeletionPolicy() xpv1.DeletionPolicy { return mg.Spec.DeletionPolicy }
func (mg *DBInstance) SetDeletionPolicy(p xpv1.DeletionPolicy) { mg.Spec.DeletionPolicy = p }
func (mg *DBInstance) GetManagementPolicies() xpv1.ManagementPolicies { return mg.Spec.ManagementPolicies }
func (mg *DBInstance) SetManagementPolicies(p xpv1.ManagementPolicies) { mg.Spec.ManagementPolicies = p }
func (mg *DBInstance) GetProviderConfigReference() *xpv1.Reference {
	if mg.Spec.ProviderConfigReference == nil { return nil }
	return &xpv1.Reference{Name: mg.Spec.ProviderConfigReference.Name}
}
func (mg *DBInstance) SetProviderConfigReference(r *xpv1.Reference) {
	if r == nil { mg.Spec.ProviderConfigReference = nil; return }
	if mg.Spec.ProviderConfigReference == nil { mg.Spec.ProviderConfigReference = &ProviderConfigReference{} }
	mg.Spec.ProviderConfigReference.Name = r.Name
}
func (mg *DBInstance) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo { return nil }
func (mg *DBInstance) SetPublishConnectionDetailsTo(_ *xpv1.PublishConnectionDetailsTo) {}
func (mg *DBInstance) GetWriteConnectionSecretToReference() *xpv1.SecretReference {
	if mg.Spec.WriteConnectionSecretToReference == nil { return nil }
	return &xpv1.SecretReference{Name: mg.Spec.WriteConnectionSecretToReference.Name, Namespace: mg.Namespace}
}
func (mg *DBInstance) SetWriteConnectionSecretToReference(r *xpv1.SecretReference) {
	if r == nil { mg.Spec.WriteConnectionSecretToReference = nil; return }
	mg.Spec.WriteConnectionSecretToReference = &LocalSecretReference{Name: r.Name}
}

func (mg *DBCluster) GetCondition(ct xpv1.ConditionType) xpv1.Condition { return mg.Status.GetCondition(ct) }
func (mg *DBCluster) SetConditions(c ...xpv1.Condition) { mg.Status.SetConditions(c...) }
func (mg *DBCluster) GetDeletionPolicy() xpv1.DeletionPolicy { return mg.Spec.DeletionPolicy }
func (mg *DBCluster) SetDeletionPolicy(p xpv1.DeletionPolicy) { mg.Spec.DeletionPolicy = p }
func (mg *DBCluster) GetManagementPolicies() xpv1.ManagementPolicies { return mg.Spec.ManagementPolicies }
func (mg *DBCluster) SetManagementPolicies(p xpv1.ManagementPolicies) { mg.Spec.ManagementPolicies = p }
func (mg *DBCluster) GetProviderConfigReference() *xpv1.Reference {
	if mg.Spec.ProviderConfigReference == nil { return nil }
	return &xpv1.Reference{Name: mg.Spec.ProviderConfigReference.Name}
}
func (mg *DBCluster) SetProviderConfigReference(r *xpv1.Reference) {
	if r == nil { mg.Spec.ProviderConfigReference = nil; return }
	if mg.Spec.ProviderConfigReference == nil { mg.Spec.ProviderConfigReference = &ProviderConfigReference{} }
	mg.Spec.ProviderConfigReference.Name = r.Name
}
func (mg *DBCluster) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo { return nil }
func (mg *DBCluster) SetPublishConnectionDetailsTo(_ *xpv1.PublishConnectionDetailsTo) {}
func (mg *DBCluster) GetWriteConnectionSecretToReference() *xpv1.SecretReference {
	if mg.Spec.WriteConnectionSecretToReference == nil { return nil }
	return &xpv1.SecretReference{Name: mg.Spec.WriteConnectionSecretToReference.Name, Namespace: mg.Namespace}
}
func (mg *DBCluster) SetWriteConnectionSecretToReference(r *xpv1.SecretReference) {
	if r == nil { mg.Spec.WriteConnectionSecretToReference = nil; return }
	mg.Spec.WriteConnectionSecretToReference = &LocalSecretReference{Name: r.Name}
}

func (mg *DBParameterGroup) GetCondition(ct xpv1.ConditionType) xpv1.Condition { return mg.Status.GetCondition(ct) }
func (mg *DBParameterGroup) SetConditions(c ...xpv1.Condition) { mg.Status.SetConditions(c...) }
func (mg *DBParameterGroup) GetDeletionPolicy() xpv1.DeletionPolicy { return mg.Spec.DeletionPolicy }
func (mg *DBParameterGroup) SetDeletionPolicy(p xpv1.DeletionPolicy) { mg.Spec.DeletionPolicy = p }
func (mg *DBParameterGroup) GetManagementPolicies() xpv1.ManagementPolicies { return mg.Spec.ManagementPolicies }
func (mg *DBParameterGroup) SetManagementPolicies(p xpv1.ManagementPolicies) { mg.Spec.ManagementPolicies = p }
func (mg *DBParameterGroup) GetProviderConfigReference() *xpv1.Reference {
	if mg.Spec.ProviderConfigReference == nil { return nil }
	return &xpv1.Reference{Name: mg.Spec.ProviderConfigReference.Name}
}
func (mg *DBParameterGroup) SetProviderConfigReference(r *xpv1.Reference) {
	if r == nil { mg.Spec.ProviderConfigReference = nil; return }
	if mg.Spec.ProviderConfigReference == nil { mg.Spec.ProviderConfigReference = &ProviderConfigReference{} }
	mg.Spec.ProviderConfigReference.Name = r.Name
}
func (mg *DBParameterGroup) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo { return nil }
func (mg *DBParameterGroup) SetPublishConnectionDetailsTo(_ *xpv1.PublishConnectionDetailsTo) {}
func (mg *DBParameterGroup) GetWriteConnectionSecretToReference() *xpv1.SecretReference {
	if mg.Spec.WriteConnectionSecretToReference == nil { return nil }
	return &xpv1.SecretReference{Name: mg.Spec.WriteConnectionSecretToReference.Name, Namespace: mg.Namespace}
}
func (mg *DBParameterGroup) SetWriteConnectionSecretToReference(r *xpv1.SecretReference) {
	if r == nil { mg.Spec.WriteConnectionSecretToReference = nil; return }
	mg.Spec.WriteConnectionSecretToReference = &LocalSecretReference{Name: r.Name}
}

func (mg *DBClusterParameterGroup) GetCondition(ct xpv1.ConditionType) xpv1.Condition { return mg.Status.GetCondition(ct) }
func (mg *DBClusterParameterGroup) SetConditions(c ...xpv1.Condition) { mg.Status.SetConditions(c...) }
func (mg *DBClusterParameterGroup) GetDeletionPolicy() xpv1.DeletionPolicy { return mg.Spec.DeletionPolicy }
func (mg *DBClusterParameterGroup) SetDeletionPolicy(p xpv1.DeletionPolicy) { mg.Spec.DeletionPolicy = p }
func (mg *DBClusterParameterGroup) GetManagementPolicies() xpv1.ManagementPolicies { return mg.Spec.ManagementPolicies }
func (mg *DBClusterParameterGroup) SetManagementPolicies(p xpv1.ManagementPolicies) { mg.Spec.ManagementPolicies = p }
func (mg *DBClusterParameterGroup) GetProviderConfigReference() *xpv1.Reference {
	if mg.Spec.ProviderConfigReference == nil { return nil }
	return &xpv1.Reference{Name: mg.Spec.ProviderConfigReference.Name}
}
func (mg *DBClusterParameterGroup) SetProviderConfigReference(r *xpv1.Reference) {
	if r == nil { mg.Spec.ProviderConfigReference = nil; return }
	if mg.Spec.ProviderConfigReference == nil { mg.Spec.ProviderConfigReference = &ProviderConfigReference{} }
	mg.Spec.ProviderConfigReference.Name = r.Name
}
func (mg *DBClusterParameterGroup) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo { return nil }
func (mg *DBClusterParameterGroup) SetPublishConnectionDetailsTo(_ *xpv1.PublishConnectionDetailsTo) {}
func (mg *DBClusterParameterGroup) GetWriteConnectionSecretToReference() *xpv1.SecretReference {
	if mg.Spec.WriteConnectionSecretToReference == nil { return nil }
	return &xpv1.SecretReference{Name: mg.Spec.WriteConnectionSecretToReference.Name, Namespace: mg.Namespace}
}
func (mg *DBClusterParameterGroup) SetWriteConnectionSecretToReference(r *xpv1.SecretReference) {
	if r == nil { mg.Spec.WriteConnectionSecretToReference = nil; return }
	mg.Spec.WriteConnectionSecretToReference = &LocalSecretReference{Name: r.Name}
}

func (mg *DBInstanceRoleAssociation) GetCondition(ct xpv1.ConditionType) xpv1.Condition { return mg.Status.GetCondition(ct) }
func (mg *DBInstanceRoleAssociation) SetConditions(c ...xpv1.Condition) { mg.Status.SetConditions(c...) }
func (mg *DBInstanceRoleAssociation) GetDeletionPolicy() xpv1.DeletionPolicy { return mg.Spec.DeletionPolicy }
func (mg *DBInstanceRoleAssociation) SetDeletionPolicy(p xpv1.DeletionPolicy) { mg.Spec.DeletionPolicy = p }
func (mg *DBInstanceRoleAssociation) GetManagementPolicies() xpv1.ManagementPolicies { return mg.Spec.ManagementPolicies }
func (mg *DBInstanceRoleAssociation) SetManagementPolicies(p xpv1.ManagementPolicies) { mg.Spec.ManagementPolicies = p }
func (mg *DBInstanceRoleAssociation) GetProviderConfigReference() *xpv1.Reference {
	if mg.Spec.ProviderConfigReference == nil { return nil }
	return &xpv1.Reference{Name: mg.Spec.ProviderConfigReference.Name}
}
func (mg *DBInstanceRoleAssociation) SetProviderConfigReference(r *xpv1.Reference) {
	if r == nil { mg.Spec.ProviderConfigReference = nil; return }
	if mg.Spec.ProviderConfigReference == nil { mg.Spec.ProviderConfigReference = &ProviderConfigReference{} }
	mg.Spec.ProviderConfigReference.Name = r.Name
}
func (mg *DBInstanceRoleAssociation) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo { return nil }
func (mg *DBInstanceRoleAssociation) SetPublishConnectionDetailsTo(_ *xpv1.PublishConnectionDetailsTo) {}
func (mg *DBInstanceRoleAssociation) GetWriteConnectionSecretToReference() *xpv1.SecretReference {
	if mg.Spec.WriteConnectionSecretToReference == nil { return nil }
	return &xpv1.SecretReference{Name: mg.Spec.WriteConnectionSecretToReference.Name, Namespace: mg.Namespace}
}
func (mg *DBInstanceRoleAssociation) SetWriteConnectionSecretToReference(r *xpv1.SecretReference) {
	if r == nil { mg.Spec.WriteConnectionSecretToReference = nil; return }
	mg.Spec.WriteConnectionSecretToReference = &LocalSecretReference{Name: r.Name}
}

func (mg *GlobalCluster) GetCondition(ct xpv1.ConditionType) xpv1.Condition { return mg.Status.GetCondition(ct) }
func (mg *GlobalCluster) SetConditions(c ...xpv1.Condition) { mg.Status.SetConditions(c...) }
func (mg *GlobalCluster) GetDeletionPolicy() xpv1.DeletionPolicy { return mg.Spec.DeletionPolicy }
func (mg *GlobalCluster) SetDeletionPolicy(p xpv1.DeletionPolicy) { mg.Spec.DeletionPolicy = p }
func (mg *GlobalCluster) GetManagementPolicies() xpv1.ManagementPolicies { return mg.Spec.ManagementPolicies }
func (mg *GlobalCluster) SetManagementPolicies(p xpv1.ManagementPolicies) { mg.Spec.ManagementPolicies = p }
func (mg *GlobalCluster) GetProviderConfigReference() *xpv1.Reference {
	if mg.Spec.ProviderConfigReference == nil { return nil }
	return &xpv1.Reference{Name: mg.Spec.ProviderConfigReference.Name}
}
func (mg *GlobalCluster) SetProviderConfigReference(r *xpv1.Reference) {
	if r == nil { mg.Spec.ProviderConfigReference = nil; return }
	if mg.Spec.ProviderConfigReference == nil { mg.Spec.ProviderConfigReference = &ProviderConfigReference{} }
	mg.Spec.ProviderConfigReference.Name = r.Name
}
func (mg *GlobalCluster) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo { return nil }
func (mg *GlobalCluster) SetPublishConnectionDetailsTo(_ *xpv1.PublishConnectionDetailsTo) {}
func (mg *GlobalCluster) GetWriteConnectionSecretToReference() *xpv1.SecretReference {
	if mg.Spec.WriteConnectionSecretToReference == nil { return nil }
	return &xpv1.SecretReference{Name: mg.Spec.WriteConnectionSecretToReference.Name, Namespace: mg.Namespace}
}
func (mg *GlobalCluster) SetWriteConnectionSecretToReference(r *xpv1.SecretReference) {
	if r == nil { mg.Spec.WriteConnectionSecretToReference = nil; return }
	mg.Spec.WriteConnectionSecretToReference = &LocalSecretReference{Name: r.Name}
}

func (mg *OptionGroup) GetCondition(ct xpv1.ConditionType) xpv1.Condition { return mg.Status.GetCondition(ct) }
func (mg *OptionGroup) SetConditions(c ...xpv1.Condition) { mg.Status.SetConditions(c...) }
func (mg *OptionGroup) GetDeletionPolicy() xpv1.DeletionPolicy { return mg.Spec.DeletionPolicy }
func (mg *OptionGroup) SetDeletionPolicy(p xpv1.DeletionPolicy) { mg.Spec.DeletionPolicy = p }
func (mg *OptionGroup) GetManagementPolicies() xpv1.ManagementPolicies { return mg.Spec.ManagementPolicies }
func (mg *OptionGroup) SetManagementPolicies(p xpv1.ManagementPolicies) { mg.Spec.ManagementPolicies = p }
func (mg *OptionGroup) GetProviderConfigReference() *xpv1.Reference {
	if mg.Spec.ProviderConfigReference == nil { return nil }
	return &xpv1.Reference{Name: mg.Spec.ProviderConfigReference.Name}
}
func (mg *OptionGroup) SetProviderConfigReference(r *xpv1.Reference) {
	if r == nil { mg.Spec.ProviderConfigReference = nil; return }
	if mg.Spec.ProviderConfigReference == nil { mg.Spec.ProviderConfigReference = &ProviderConfigReference{} }
	mg.Spec.ProviderConfigReference.Name = r.Name
}
func (mg *OptionGroup) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo { return nil }
func (mg *OptionGroup) SetPublishConnectionDetailsTo(_ *xpv1.PublishConnectionDetailsTo) {}
func (mg *OptionGroup) GetWriteConnectionSecretToReference() *xpv1.SecretReference {
	if mg.Spec.WriteConnectionSecretToReference == nil { return nil }
	return &xpv1.SecretReference{Name: mg.Spec.WriteConnectionSecretToReference.Name, Namespace: mg.Namespace}
}
func (mg *OptionGroup) SetWriteConnectionSecretToReference(r *xpv1.SecretReference) {
	if r == nil { mg.Spec.WriteConnectionSecretToReference = nil; return }
	mg.Spec.WriteConnectionSecretToReference = &LocalSecretReference{Name: r.Name}
}

// GetMasterUserPasswordSecretRef implements RDSClusterOrInstance for DBInstance.
func (mg *DBInstance) GetMasterUserPasswordSecretRef() *xpv1.SecretKeySelector {
	return mg.Spec.ForProvider.MasterUserPasswordSecretRef
}

// GetMasterUserPasswordSecretRef implements RDSClusterOrInstance for DBCluster.
func (mg *DBCluster) GetMasterUserPasswordSecretRef() *xpv1.SecretKeySelector {
	return mg.Spec.ForProvider.MasterUserPasswordSecretRef
}
