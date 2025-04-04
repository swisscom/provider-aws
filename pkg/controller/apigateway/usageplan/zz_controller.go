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

// Code generated by ack-generate. DO NOT EDIT.

package usageplan

import (
	"context"

	svcapi "github.com/aws/aws-sdk-go/service/apigateway"
	svcsdk "github.com/aws/aws-sdk-go/service/apigateway"
	svcsdkapi "github.com/aws/aws-sdk-go/service/apigateway/apigatewayiface"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	cpresource "github.com/crossplane/crossplane-runtime/pkg/resource"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/apigateway/v1alpha1"
	connectaws "github.com/crossplane-contrib/provider-aws/pkg/utils/connect/aws"
	errorutils "github.com/crossplane-contrib/provider-aws/pkg/utils/errors"
)

const (
	errUnexpectedObject = "managed resource is not an UsagePlan resource"

	errCreateSession = "cannot create a new session"
	errCreate        = "cannot create UsagePlan in AWS"
	errUpdate        = "cannot update UsagePlan in AWS"
	errDescribe      = "failed to describe UsagePlan"
	errDelete        = "failed to delete UsagePlan"
)

type connector struct {
	kube client.Client
	opts []option
}

func (c *connector) Connect(ctx context.Context, cr *svcapitypes.UsagePlan) (managed.TypedExternalClient[*svcapitypes.UsagePlan], error) {
	sess, err := connectaws.GetConfigV1(ctx, c.kube, cr, cr.Spec.ForProvider.Region)
	if err != nil {
		return nil, errors.Wrap(err, errCreateSession)
	}
	return newExternal(c.kube, svcapi.New(sess), c.opts), nil
}

func (e *external) Observe(ctx context.Context, cr *svcapitypes.UsagePlan) (managed.ExternalObservation, error) {
	if meta.GetExternalName(cr) == "" {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	input := GenerateGetUsagePlanInput(cr)
	if err := e.preObserve(ctx, cr, input); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "pre-observe failed")
	}
	resp, err := e.client.GetUsagePlanWithContext(ctx, input)
	if err != nil {
		return managed.ExternalObservation{ResourceExists: false}, errorutils.Wrap(cpresource.Ignore(IsNotFound, err), errDescribe)
	}
	currentSpec := cr.Spec.ForProvider.DeepCopy()
	if err := e.lateInitialize(&cr.Spec.ForProvider, resp); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "late-init failed")
	}
	GenerateUsagePlan(resp).Status.AtProvider.DeepCopyInto(&cr.Status.AtProvider)
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

func (e *external) Create(ctx context.Context, cr *svcapitypes.UsagePlan) (managed.ExternalCreation, error) {
	cr.Status.SetConditions(xpv1.Creating())
	input := GenerateCreateUsagePlanInput(cr)
	if err := e.preCreate(ctx, cr, input); err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "pre-create failed")
	}
	resp, err := e.client.CreateUsagePlanWithContext(ctx, input)
	if err != nil {
		return managed.ExternalCreation{}, errorutils.Wrap(err, errCreate)
	}

	if resp.ApiStages != nil {
		f0 := []*svcapitypes.APIStage{}
		for _, f0iter := range resp.ApiStages {
			f0elem := &svcapitypes.APIStage{}
			if f0iter.ApiId != nil {
				f0elem.APIID = f0iter.ApiId
			}
			if f0iter.Stage != nil {
				f0elem.Stage = f0iter.Stage
			}
			if f0iter.Throttle != nil {
				f0elemf2 := map[string]*svcapitypes.ThrottleSettings{}
				for f0elemf2key, f0elemf2valiter := range f0iter.Throttle {
					f0elemf2val := &svcapitypes.ThrottleSettings{}
					if f0elemf2valiter.BurstLimit != nil {
						f0elemf2val.BurstLimit = f0elemf2valiter.BurstLimit
					}
					if f0elemf2valiter.RateLimit != nil {
						f0elemf2val.RateLimit = f0elemf2valiter.RateLimit
					}
					f0elemf2[f0elemf2key] = f0elemf2val
				}
				f0elem.Throttle = f0elemf2
			}
			f0 = append(f0, f0elem)
		}
		cr.Status.AtProvider.APIStages = f0
	} else {
		cr.Status.AtProvider.APIStages = nil
	}
	if resp.Description != nil {
		cr.Spec.ForProvider.Description = resp.Description
	} else {
		cr.Spec.ForProvider.Description = nil
	}
	if resp.Id != nil {
		cr.Status.AtProvider.ID = resp.Id
	} else {
		cr.Status.AtProvider.ID = nil
	}
	if resp.Name != nil {
		cr.Spec.ForProvider.Name = resp.Name
	} else {
		cr.Spec.ForProvider.Name = nil
	}
	if resp.ProductCode != nil {
		cr.Status.AtProvider.ProductCode = resp.ProductCode
	} else {
		cr.Status.AtProvider.ProductCode = nil
	}
	if resp.Quota != nil {
		f5 := &svcapitypes.QuotaSettings{}
		if resp.Quota.Limit != nil {
			f5.Limit = resp.Quota.Limit
		}
		if resp.Quota.Offset != nil {
			f5.Offset = resp.Quota.Offset
		}
		if resp.Quota.Period != nil {
			f5.Period = resp.Quota.Period
		}
		cr.Spec.ForProvider.Quota = f5
	} else {
		cr.Spec.ForProvider.Quota = nil
	}
	if resp.Tags != nil {
		f6 := map[string]*string{}
		for f6key, f6valiter := range resp.Tags {
			var f6val string
			f6val = *f6valiter
			f6[f6key] = &f6val
		}
		cr.Spec.ForProvider.Tags = f6
	} else {
		cr.Spec.ForProvider.Tags = nil
	}
	if resp.Throttle != nil {
		f7 := &svcapitypes.ThrottleSettings{}
		if resp.Throttle.BurstLimit != nil {
			f7.BurstLimit = resp.Throttle.BurstLimit
		}
		if resp.Throttle.RateLimit != nil {
			f7.RateLimit = resp.Throttle.RateLimit
		}
		cr.Spec.ForProvider.Throttle = f7
	} else {
		cr.Spec.ForProvider.Throttle = nil
	}

	return e.postCreate(ctx, cr, resp, managed.ExternalCreation{}, err)
}

func (e *external) Update(ctx context.Context, cr *svcapitypes.UsagePlan) (managed.ExternalUpdate, error) {
	input := GenerateUpdateUsagePlanInput(cr)
	if err := e.preUpdate(ctx, cr, input); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "pre-update failed")
	}
	resp, err := e.client.UpdateUsagePlanWithContext(ctx, input)
	return e.postUpdate(ctx, cr, resp, managed.ExternalUpdate{}, errorutils.Wrap(err, errUpdate))
}

func (e *external) Delete(ctx context.Context, cr *svcapitypes.UsagePlan) (managed.ExternalDelete, error) {
	cr.Status.SetConditions(xpv1.Deleting())
	input := GenerateDeleteUsagePlanInput(cr)
	ignore, err := e.preDelete(ctx, cr, input)
	if err != nil {
		return managed.ExternalDelete{}, errors.Wrap(err, "pre-delete failed")
	}
	if ignore {
		return managed.ExternalDelete{}, nil
	}
	resp, err := e.client.DeleteUsagePlanWithContext(ctx, input)
	return e.postDelete(ctx, cr, resp, errorutils.Wrap(cpresource.Ignore(IsNotFound, err), errDelete))
}

func (e *external) Disconnect(ctx context.Context) error {
	// Unimplemented, required by newer versions of crossplane-runtime
	return nil
}

type option func(*external)

func newExternal(kube client.Client, client svcsdkapi.APIGatewayAPI, opts []option) *external {
	e := &external{
		kube:           kube,
		client:         client,
		preObserve:     nopPreObserve,
		postObserve:    nopPostObserve,
		lateInitialize: nopLateInitialize,
		isUpToDate:     alwaysUpToDate,
		preCreate:      nopPreCreate,
		postCreate:     nopPostCreate,
		preDelete:      nopPreDelete,
		postDelete:     nopPostDelete,
		preUpdate:      nopPreUpdate,
		postUpdate:     nopPostUpdate,
	}
	for _, f := range opts {
		f(e)
	}
	return e
}

type external struct {
	kube           client.Client
	client         svcsdkapi.APIGatewayAPI
	preObserve     func(context.Context, *svcapitypes.UsagePlan, *svcsdk.GetUsagePlanInput) error
	postObserve    func(context.Context, *svcapitypes.UsagePlan, *svcsdk.UsagePlan, managed.ExternalObservation, error) (managed.ExternalObservation, error)
	lateInitialize func(*svcapitypes.UsagePlanParameters, *svcsdk.UsagePlan) error
	isUpToDate     func(context.Context, *svcapitypes.UsagePlan, *svcsdk.UsagePlan) (bool, string, error)
	preCreate      func(context.Context, *svcapitypes.UsagePlan, *svcsdk.CreateUsagePlanInput) error
	postCreate     func(context.Context, *svcapitypes.UsagePlan, *svcsdk.UsagePlan, managed.ExternalCreation, error) (managed.ExternalCreation, error)
	preDelete      func(context.Context, *svcapitypes.UsagePlan, *svcsdk.DeleteUsagePlanInput) (bool, error)
	postDelete     func(context.Context, *svcapitypes.UsagePlan, *svcsdk.DeleteUsagePlanOutput, error) (managed.ExternalDelete, error)
	preUpdate      func(context.Context, *svcapitypes.UsagePlan, *svcsdk.UpdateUsagePlanInput) error
	postUpdate     func(context.Context, *svcapitypes.UsagePlan, *svcsdk.UsagePlan, managed.ExternalUpdate, error) (managed.ExternalUpdate, error)
}

func nopPreObserve(context.Context, *svcapitypes.UsagePlan, *svcsdk.GetUsagePlanInput) error {
	return nil
}

func nopPostObserve(_ context.Context, _ *svcapitypes.UsagePlan, _ *svcsdk.UsagePlan, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	return obs, err
}
func nopLateInitialize(*svcapitypes.UsagePlanParameters, *svcsdk.UsagePlan) error {
	return nil
}
func alwaysUpToDate(context.Context, *svcapitypes.UsagePlan, *svcsdk.UsagePlan) (bool, string, error) {
	return true, "", nil
}

func nopPreCreate(context.Context, *svcapitypes.UsagePlan, *svcsdk.CreateUsagePlanInput) error {
	return nil
}
func nopPostCreate(_ context.Context, _ *svcapitypes.UsagePlan, _ *svcsdk.UsagePlan, cre managed.ExternalCreation, err error) (managed.ExternalCreation, error) {
	return cre, err
}
func nopPreDelete(context.Context, *svcapitypes.UsagePlan, *svcsdk.DeleteUsagePlanInput) (bool, error) {
	return false, nil
}
func nopPostDelete(_ context.Context, _ *svcapitypes.UsagePlan, _ *svcsdk.DeleteUsagePlanOutput, err error) (managed.ExternalDelete, error) {
	return managed.ExternalDelete{}, err
}
func nopPreUpdate(context.Context, *svcapitypes.UsagePlan, *svcsdk.UpdateUsagePlanInput) error {
	return nil
}
func nopPostUpdate(_ context.Context, _ *svcapitypes.UsagePlan, _ *svcsdk.UsagePlan, upd managed.ExternalUpdate, err error) (managed.ExternalUpdate, error) {
	return upd, err
}
