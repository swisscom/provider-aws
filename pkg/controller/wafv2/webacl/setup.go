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
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	svcsdk "github.com/aws/aws-sdk-go/service/wafv2"
	svcsdkapi "github.com/aws/aws-sdk-go/service/wafv2/wafv2iface"
	connectaws "github.com/crossplane-contrib/provider-aws/pkg/utils/connect/aws"
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	cpresource "github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane-contrib/provider-aws/apis/v1alpha1"
	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/wafv2/manualv1alpha1"
	"github.com/crossplane-contrib/provider-aws/pkg/features"
	errorutils "github.com/crossplane-contrib/provider-aws/pkg/utils/errors"
	custommanaged "github.com/crossplane-contrib/provider-aws/pkg/utils/reconciler/managed"
)

const (
	errCouldNotFindWebACL = "could not find WebACL"
)

// SetupWebACL adds a controller that reconciles SetupWebAcl.
func SetupWebACL(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(svcapitypes.WebACLKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), v1alpha1.StoreConfigGroupVersionKind))
	}

	reconcilerOpts := []managed.ReconcilerOption{
		managed.WithCriticalAnnotationUpdater(custommanaged.NewRetryingCriticalAnnotationUpdater(mgr.GetClient())),
		managed.WithInitializers(managed.NewNameAsExternalName(mgr.GetClient())),
		managed.WithExternalConnecter(&customConnector{kube: mgr.GetClient()}),
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

// customConnector is external connector with overridden Observe method due to ACK v0.38.1 doesn't correctly generate it.
type customConnector struct {
	kube client.Client
}

type customExternal struct {
	external
	cache *cache
}

type cachedCustomMethods struct {
	cache *cache
}

type cache struct {
	listWebACLsOutput *svcsdk.ListWebACLsOutput
}

func createEmptyCache() *cache {
	return &cache{}
}

func newCustomExternal(kube client.Client, client svcsdkapi.WAFV2API) *customExternal {
	sharedCache := createEmptyCache()
	c := cachedCustomMethods{cache: sharedCache}
	e := &customExternal{
		external{
			kube:           kube,
			client:         client,
			preObserve:     preObserve,
			postObserve:    postObserve,
			isUpToDate:     alwaysUpToDate,
			preCreate:      preCreate,
			preDelete:      c.preDelete,
			preUpdate:      c.preUpdate,
			lateInitialize: nopLateInitialize,
			postCreate:     nopPostCreate,
			postDelete:     nopPostDelete,
			postUpdate:     nopPostUpdate,
		},
		cache: sharedCache,
	}
	return e
}

func (c *customConnector) Connect(ctx context.Context, mg cpresource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*svcapitypes.WebACL)
	if !ok {
		return nil, errors.New(errUnexpectedObject)
	}
	sess, err := connectaws.GetConfigV1(ctx, c.kube, mg, cr.Spec.ForProvider.Region)
	if err != nil {
		return nil, errors.Wrap(err, errCreateSession)
	}
	return newCustomExternal(c.kube, svcsdk.New(sess)), nil
}

func preCreate(_ context.Context, ds *svcapitypes.WebACL, input *svcsdk.CreateWebACLInput) error {
	input.Name = aws.String(meta.GetExternalName(ds))
	return nil
}

func (e *customExternal) Observe(ctx context.Context, mg cpresource.Managed) (managed.ExternalObservation, error) {

	cr, ok := mg.(*svcapitypes.WebACL)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errUnexpectedObject)
	}
	if meta.GetExternalName(cr) == "" {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	input := GenerateGetWebACLInput(cr)
	listWebACLInput := svcsdk.ListWebACLsInput{
		Scope: cr.Spec.ForProvider.Scope,
	}
	ls, err := e.client.ListWebACLs(&listWebACLInput)
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	e.cache.listWebACLsOutput = ls
	for n, webACLSummary := range ls.WebACLs {
		if aws.StringValue(webACLSummary.Name) == meta.GetExternalName(cr) {
			input.Id = webACLSummary.Id
			break
		}
		if n == len(ls.WebACLs)-1 {
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil
		}
	}
	if err := e.preObserve(ctx, cr, input); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "pre-observe failed")
	}
	resp, err := e.client.GetWebACLWithContext(ctx, input)
	if err != nil {
		return managed.ExternalObservation{ResourceExists: false}, errorutils.Wrap(cpresource.Ignore(IsNotFound, err), errDescribe)
	}
	currentSpec := cr.Spec.ForProvider.DeepCopy()
	if err := e.lateInitialize(&cr.Spec.ForProvider, resp); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "late-init failed")
	}
	GenerateWebACL(resp).Status.AtProvider.DeepCopyInto(&cr.Status.AtProvider)
	upToDate := true
	diff := ""
	if !meta.WasDeleted(cr) { // There is no need to run isUpToDate if the resource is deleted
		upToDate, diff, err = e.isUpToDate(ctx, cr, resp)
		if err != nil {
			return managed.ExternalObservation{}, errors.Wrap(err, "isUpToDate check failed")
		}
	}
	return e.postObserve(ctx, cr, resp, managed.ExternalObservation{
		ResourceExists:          true,
		ResourceUpToDate:        upToDate,
		Diff:                    diff,
		ResourceLateInitialized: !cmp.Equal(&cr.Spec.ForProvider, currentSpec),
	}, nil)
}

func preObserve(ctx context.Context, ds *svcapitypes.WebACL, input *svcsdk.GetWebACLInput) error {
	input.Name = aws.String(meta.GetExternalName(ds))
	return nil
}

//func isUpToDate(_ context.Context, ds *svcapitypes.WebACL, input *svcsdk.GetWebACLOutput) (bool, string, error) {
//}

func postObserve(_ context.Context, ds *svcapitypes.WebACL, resp *svcsdk.GetWebACLOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	ds.SetConditions(xpv1.Available())

	if resp == nil {
		ds.Status.AtProvider = svcapitypes.WebACLObservation{}
	} else {
		ds.Status.AtProvider = svcapitypes.WebACLObservation{
			ARN: resp.WebACL.ARN,
			ID:  resp.WebACL.Id,
		}

	}

	return obs, nil
}

func (e *cachedCustomMethods) preUpdate(_ context.Context, ds *svcapitypes.WebACL, input *svcsdk.UpdateWebACLInput) error {
	input.Name = aws.String(meta.GetExternalName(ds))
	lockToken, err := getLockToken(e.cache.listWebACLsOutput.WebACLs, ds)
	if err != nil {
		return err
	}
	input.LockToken = lockToken
	return nil
}

func (e *cachedCustomMethods) preDelete(_ context.Context, ds *svcapitypes.WebACL, input *svcsdk.DeleteWebACLInput) (bool, error) {
	input.Name = aws.String(meta.GetExternalName(ds))
	lockToken, err := getLockToken(e.cache.listWebACLsOutput.WebACLs, ds)
	if err != nil {
		return false, err
	}
	input.LockToken = lockToken
	return false, nil
}

func getLockToken(webACLs []*svcsdk.WebACLSummary, ds *svcapitypes.WebACL) (*string, error) {
	var lockToken *string
	for n, webACLSummary := range webACLs {
		if aws.StringValue(webACLSummary.Name) == meta.GetExternalName(ds) {
			lockToken = webACLSummary.LockToken
			break
		}
		if n == len(webACLs)-1 {
			return lockToken, errors.New(fmt.Sprintf("%s %s", errCouldNotFindWebACL, meta.GetExternalName(ds)))
		}
	}
	return lockToken, nil
}
