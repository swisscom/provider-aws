package resourcepolicy

import (
	"context"

	"github.com/crossplane-contrib/provider-aws/apis/v1alpha1"
	"github.com/crossplane-contrib/provider-aws/pkg/clients/iam"
	"github.com/crossplane-contrib/provider-aws/pkg/features"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	svcsdk "github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"

	ctrl "sigs.k8s.io/controller-runtime"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/cloudwatchlogs/v1alpha1"
)

// SetupResourcePolicy adds a controller that reconciles ResourcePolicy.
func SetupResourcePolicy(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(svcapitypes.ResourcePolicyGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), v1alpha1.StoreConfigGroupVersionKind))
	}

	opts := []option{
		func(e *external) {
			// e.preObserve = preObserve
			// e.preCreate = preCreate
			// e.preUpdate = preUpdate
			// e.preDelete = preDelete
			e.postObserve = postObserve
			e.isUpToDate = isUpToDate
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&svcapitypes.ResourcePolicy{}).
		Complete(managed.NewReconciler(mgr,
			resource.ManagedKind(svcapitypes.ResourcePolicyGroupVersionKind),
			managed.WithExternalConnecter(&connector{kube: mgr.GetClient(), opts: opts}),
			managed.WithPollInterval(o.PollInterval),
			managed.WithLogger(o.Logger.WithValues("controller", name)),
			managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
			managed.WithConnectionPublishers(cps...)))
}

// func preObserve(_ context.Context, cr *svcapitypes.ResourcePolicy, obj *svcsdk.DescribeResourcePoliciesInput) error {
// 	obj.PolicyName = pointer.ToOrNilIfZeroValue(meta.GetExternalName(cr))
// 	return nil
// }

// func preCreate(_ context.Context, cr *svcapitypes.ResourcePolicy, obj *svcsdk.PutResourcePolicyInput) error {
// 	obj.PolicyName = pointer.ToOrNilIfZeroValue(meta.GetExternalName(cr))
// 	return nil
// }

// func preUpdate(_ context.Context, cr *svcapitypes.ResourcePolicy, obj *svcsdk.PutResourcePolicyInput) error {
// 	obj.PolicyName = pointer.ToOrNilIfZeroValue(meta.GetExternalName(cr))
// 	return nil
// }

// func preDelete(_ context.Context, cr *svcapitypes.ResourcePolicy, obj *svcsdk.DeleteResourcePolicyInput) (bool, error) {
// 	obj.PolicyName = pointer.ToOrNilIfZeroValue(meta.GetExternalName(cr))
// 	return true, nil
// }

func postObserve(_ context.Context, cr *svcapitypes.ResourcePolicy, _ *svcsdk.DescribeResourcePoliciesOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	cr.SetConditions(xpv1.Available())
	return obs, nil
}

func isUpToDate(_ context.Context, cr *svcapitypes.ResourcePolicy, obj *svcsdk.DescribeResourcePoliciesOutput) (bool, string, error) {
	if len(obj.ResourcePolicies) == 0 {
		return false, "", nil
	}

	for _, policy := range obj.ResourcePolicies {
		if policy.PolicyName != nil && *policy.PolicyName == meta.GetExternalName(cr) {
			// Use existing method from iam to compare policy documents
			return iam.IsPolicyDocumentUpToDate(*cr.Spec.ForProvider.PolicyDocument, policy.PolicyDocument)
		}
	}
	return false, "", nil
}
