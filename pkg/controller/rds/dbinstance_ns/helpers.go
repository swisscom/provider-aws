package dbinstance_ns

import (
	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"
	nsapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1ns"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
)

// toV1DBInstance creates a minimal v1alpha1.DBInstance with the same ForProvider
// and external-name, for use with helper functions that expect the cluster-scoped type.
//
// Intentionally minimal: only copies fields accessed by GenerateCreateDBInstanceReadReplicaInput.
// Does NOT copy TypeMeta, Labels, Namespace, or Status.Conditions.
// If future helper functions need more fields, extend this accordingly.
func toV1DBInstance(cr *nsapitypes.DBInstance) *svcapitypes.DBInstance {
	v1cr := &svcapitypes.DBInstance{}
	v1cr.Spec.ForProvider = cr.Spec.ForProvider
	v1cr.Status.AtProvider = cr.Status.AtProvider
	v1cr.SetAnnotations(cr.GetAnnotations())
	meta.SetExternalName(v1cr, meta.GetExternalName(cr))
	return v1cr
}
