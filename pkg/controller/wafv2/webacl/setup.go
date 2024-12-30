/*
   Copyright 2021 The Crossplane Authors.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package webacl

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdk "github.com/aws/aws-sdk-go-v2/service/wafv2"
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane-contrib/provider-aws/apis/v1alpha1"
	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/wafv2/manualv1alpha1"
	"github.com/crossplane-contrib/provider-aws/pkg/features"
	"github.com/crossplane-contrib/provider-aws/pkg/utils/pointer"
	custommanaged "github.com/crossplane-contrib/provider-aws/pkg/utils/reconciler/managed"
	tagutils "github.com/crossplane-contrib/provider-aws/pkg/utils/tags"
)

const (
	errListTags      = "cannot list tags"
	errTagResource   = "cannot tag resource"
	errUntagResource = "cannot untag resource"
)

// SetupLogGroup adds a controller that reconciles LogGroup.
func SetupLogGroup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(svcapitypes.WebACLKind)
	opts := []option{
		func(e *external) {
			e.postObserve = postObserve
			e.preCreate = preCreate
			e.isUpToDate = u.isUpToDate
			e.preObserve = preObserve
		},
	}

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), v1alpha1.StoreConfigGroupVersionKind))
	}

	reconcilerOpts := []managed.ReconcilerOption{
		managed.WithInitializers(),
		managed.WithCriticalAnnotationUpdater(custommanaged.NewRetryingCriticalAnnotationUpdater(mgr.GetClient())),
		managed.WithExternalConnecter(&connector{kube: mgr.GetClient(), opts: opts}),
		managed.WithPollInterval(o.PollInterval),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...),
	}

	if o.Features.Enabled(features.EnableAlphaManagementPolicies) {
		reconcilerOpts = append(reconcilerOpts, managed.WithManagementPolicies())
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(svcapitypes.WebACLGroupVersionKind),
		reconcilerOpts...)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&svcapitypes.WebACL{}).
		Complete(r)
}

func preCreate(_ context.Context, ds *svcapitypes.WebACL, input *svcsdk.GetWebACLInput) error {
	input.Name = aws.String(meta.GetExternalName(ds))
	return nil
}

func preObserve(ctx context.Context, cr *svcapitypes.WebACL, input *svcsdk.GetWebACLInput) error {
	input.Name = aws.String(meta.GetExternalName(cr))
	return nil
}

func postObserve(_ context.Context, cr *svcapitypes.WebACL, resp *svcsdk.GetWebACLForResourceOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	cr.SetConditions(xpv1.Available())

	if resp == nil {
		cr.Status.AtProvider = svcapitypes.WebACLObservation{}
	} else {
		cr.Status.AtProvider = svcapitypes.WebACLObservation{
			ARN: resp.WebACL.ARN,
			ID:  resp.WebACL.Id,
		}

	}
	return obs, nil
}

func (u *updater) isUpToDate(_ context.Context, cr *svcapitypes.WebACL, obj *svcsdk.GetWebACLOutput) (bool, string, error) {
	if pointer.Int64Value(cr.Spec.ForProvider.RetentionInDays) != pointer.Int64Value(obj.LogGroups[0].RetentionInDays) {
		return false, "", nil
	}

	if pointer.StringValue(cr.Spec.ForProvider.KMSKeyID) != pointer.StringValue(obj.LogGroups[0].KmsKeyId) {
		return false, "", nil //TODO: test
	}

	trimmedArn := trimArnSuffix(*obj.LogGroups[0].Arn)
	tags, err := u.client.ListTagsForResource(&svcsdk.ListTagsForResourceInput{
		ResourceArn: &trimmedArn,
	})
	if err != nil {
		return false, "", errors.Wrap(err, errListTags)
	}
	add, remove := tagutils.DiffTagsMapPtr(cr.Spec.ForProvider.Tags, tags.Tags)

	return len(add) == 0 && len(remove) == 0, "", nil
}
