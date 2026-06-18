package managed

import (
	"context"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/errors"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const errApplyNsPCU = "cannot apply namespaced ProviderConfigUsage"

// A ProviderConfigUsageTracker tracks usage of a ProviderConfig by
// namespaced managed resources. It creates a ProviderConfigUsage in the same
// namespace as the managed resource, avoiding the cross-scope ownerReference issue.
type ProviderConfigUsageTracker struct {
	c  resource.Applicator
	of resource.ProviderConfigUsage
}

// NewProviderConfigUsageTracker creates a tracker for namespaced MRs.
func NewProviderConfigUsageTracker(c client.Client, of resource.ProviderConfigUsage) *ProviderConfigUsageTracker {
	return &ProviderConfigUsageTracker{c: resource.NewAPIUpdatingApplicator(c), of: of}
}

// Track creates or updates a namespaced ProviderConfigUsage in the MR's namespace.
func (u *ProviderConfigUsageTracker) Track(ctx context.Context, mg resource.Managed) error {
	pcu := u.of.DeepCopyObject().(resource.ProviderConfigUsage) //nolint:forcetypeassert
	gvk := mg.GetObjectKind().GroupVersionKind()
	ref := mg.GetProviderConfigReference()
	if ref == nil {
		return errors.New("managed resource has no provider config reference")
	}

	pcu.SetName(string(mg.GetUID()))
	pcu.SetNamespace(mg.GetNamespace())
	pcu.SetLabels(map[string]string{xpv1.LabelKeyProviderName: ref.Name})
	pcu.SetOwnerReferences([]metav1.OwnerReference{meta.AsController(meta.TypedReferenceTo(mg, gvk))})
	pcu.SetProviderConfigReference(xpv1.Reference{Name: ref.Name})
	pcu.SetResourceReference(xpv1.TypedReference{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Name:       mg.GetName(),
	})

	return errors.Wrap(
		resource.Ignore(resource.IsNotAllowed, u.c.Apply(ctx, pcu,
			resource.MustBeControllableBy(mg.GetUID()),
			resource.AllowUpdateIf(func(current, _ runtime.Object) bool {
				return current.(resource.ProviderConfigUsage).GetProviderConfigReference() != pcu.GetProviderConfigReference() //nolint:forcetypeassert
			}),
		)),
		errApplyNsPCU,
	)
}
