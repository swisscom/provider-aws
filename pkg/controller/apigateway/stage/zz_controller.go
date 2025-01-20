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

package stage

import (
	"context"

	svcapi "github.com/aws/aws-sdk-go/service/apigateway"
	svcsdk "github.com/aws/aws-sdk-go/service/apigateway"
	svcsdkapi "github.com/aws/aws-sdk-go/service/apigateway/apigatewayiface"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	errUnexpectedObject = "managed resource is not an Stage resource"

	errCreateSession = "cannot create a new session"
	errCreate        = "cannot create Stage in AWS"
	errUpdate        = "cannot update Stage in AWS"
	errDescribe      = "failed to describe Stage"
	errDelete        = "failed to delete Stage"
)

type connector struct {
	kube client.Client
	opts []option
}

func (c *connector) Connect(ctx context.Context, mg cpresource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*svcapitypes.Stage)
	if !ok {
		return nil, errors.New(errUnexpectedObject)
	}
	sess, err := connectaws.GetConfigV1(ctx, c.kube, mg, cr.Spec.ForProvider.Region)
	if err != nil {
		return nil, errors.Wrap(err, errCreateSession)
	}
	return newExternal(c.kube, svcapi.New(sess), c.opts), nil
}

func (e *external) Observe(ctx context.Context, mg cpresource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*svcapitypes.Stage)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errUnexpectedObject)
	}
	if meta.GetExternalName(cr) == "" {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	input := GenerateGetStageInput(cr)
	if err := e.preObserve(ctx, cr, input); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "pre-observe failed")
	}
	resp, err := e.client.GetStageWithContext(ctx, input)
	if err != nil {
		return managed.ExternalObservation{ResourceExists: false}, errorutils.Wrap(cpresource.Ignore(IsNotFound, err), errDescribe)
	}
	currentSpec := cr.Spec.ForProvider.DeepCopy()
	if err := e.lateInitialize(&cr.Spec.ForProvider, resp); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "late-init failed")
	}
	GenerateStage(resp).Status.AtProvider.DeepCopyInto(&cr.Status.AtProvider)
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

func (e *external) Create(ctx context.Context, mg cpresource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*svcapitypes.Stage)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errUnexpectedObject)
	}
	cr.Status.SetConditions(xpv1.Creating())
	input := GenerateCreateStageInput(cr)
	if err := e.preCreate(ctx, cr, input); err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "pre-create failed")
	}
	resp, err := e.client.CreateStageWithContext(ctx, input)
	if err != nil {
		return managed.ExternalCreation{}, errorutils.Wrap(err, errCreate)
	}

	if resp.AccessLogSettings != nil {
		f0 := &svcapitypes.AccessLogSettings{}
		if resp.AccessLogSettings.DestinationArn != nil {
			f0.DestinationARN = resp.AccessLogSettings.DestinationArn
		}
		if resp.AccessLogSettings.Format != nil {
			f0.Format = resp.AccessLogSettings.Format
		}
		cr.Status.AtProvider.AccessLogSettings = f0
	} else {
		cr.Status.AtProvider.AccessLogSettings = nil
	}
	if resp.CacheClusterEnabled != nil {
		cr.Spec.ForProvider.CacheClusterEnabled = resp.CacheClusterEnabled
	} else {
		cr.Spec.ForProvider.CacheClusterEnabled = nil
	}
	if resp.CacheClusterSize != nil {
		cr.Spec.ForProvider.CacheClusterSize = resp.CacheClusterSize
	} else {
		cr.Spec.ForProvider.CacheClusterSize = nil
	}
	if resp.CacheClusterStatus != nil {
		cr.Status.AtProvider.CacheClusterStatus = resp.CacheClusterStatus
	} else {
		cr.Status.AtProvider.CacheClusterStatus = nil
	}
	if resp.CanarySettings != nil {
		f4 := &svcapitypes.CanarySettings{}
		if resp.CanarySettings.DeploymentId != nil {
			f4.DeploymentID = resp.CanarySettings.DeploymentId
		}
		if resp.CanarySettings.PercentTraffic != nil {
			f4.PercentTraffic = resp.CanarySettings.PercentTraffic
		}
		if resp.CanarySettings.StageVariableOverrides != nil {
			f4f2 := map[string]*string{}
			for f4f2key, f4f2valiter := range resp.CanarySettings.StageVariableOverrides {
				var f4f2val string
				f4f2val = *f4f2valiter
				f4f2[f4f2key] = &f4f2val
			}
			f4.StageVariableOverrides = f4f2
		}
		if resp.CanarySettings.UseStageCache != nil {
			f4.UseStageCache = resp.CanarySettings.UseStageCache
		}
		cr.Status.AtProvider.CanarySettings = f4
	} else {
		cr.Status.AtProvider.CanarySettings = nil
	}
	if resp.ClientCertificateId != nil {
		cr.Status.AtProvider.ClientCertificateID = resp.ClientCertificateId
	} else {
		cr.Status.AtProvider.ClientCertificateID = nil
	}
	if resp.CreatedDate != nil {
		cr.Status.AtProvider.CreatedDate = &metav1.Time{*resp.CreatedDate}
	} else {
		cr.Status.AtProvider.CreatedDate = nil
	}
	if resp.DeploymentId != nil {
		cr.Status.AtProvider.DeploymentID = resp.DeploymentId
	} else {
		cr.Status.AtProvider.DeploymentID = nil
	}
	if resp.Description != nil {
		cr.Spec.ForProvider.Description = resp.Description
	} else {
		cr.Spec.ForProvider.Description = nil
	}
	if resp.DocumentationVersion != nil {
		cr.Spec.ForProvider.DocumentationVersion = resp.DocumentationVersion
	} else {
		cr.Spec.ForProvider.DocumentationVersion = nil
	}
	if resp.LastUpdatedDate != nil {
		cr.Status.AtProvider.LastUpdatedDate = &metav1.Time{*resp.LastUpdatedDate}
	} else {
		cr.Status.AtProvider.LastUpdatedDate = nil
	}
	if resp.MethodSettings != nil {
		f11 := map[string]*svcapitypes.MethodSetting{}
		for f11key, f11valiter := range resp.MethodSettings {
			f11val := &svcapitypes.MethodSetting{}
			if f11valiter.CacheDataEncrypted != nil {
				f11val.CacheDataEncrypted = f11valiter.CacheDataEncrypted
			}
			if f11valiter.CacheTtlInSeconds != nil {
				f11val.CacheTTLInSeconds = f11valiter.CacheTtlInSeconds
			}
			if f11valiter.CachingEnabled != nil {
				f11val.CachingEnabled = f11valiter.CachingEnabled
			}
			if f11valiter.DataTraceEnabled != nil {
				f11val.DataTraceEnabled = f11valiter.DataTraceEnabled
			}
			if f11valiter.LoggingLevel != nil {
				f11val.LoggingLevel = f11valiter.LoggingLevel
			}
			if f11valiter.MetricsEnabled != nil {
				f11val.MetricsEnabled = f11valiter.MetricsEnabled
			}
			if f11valiter.RequireAuthorizationForCacheControl != nil {
				f11val.RequireAuthorizationForCacheControl = f11valiter.RequireAuthorizationForCacheControl
			}
			if f11valiter.ThrottlingBurstLimit != nil {
				f11val.ThrottlingBurstLimit = f11valiter.ThrottlingBurstLimit
			}
			if f11valiter.ThrottlingRateLimit != nil {
				f11val.ThrottlingRateLimit = f11valiter.ThrottlingRateLimit
			}
			if f11valiter.UnauthorizedCacheControlHeaderStrategy != nil {
				f11val.UnauthorizedCacheControlHeaderStrategy = f11valiter.UnauthorizedCacheControlHeaderStrategy
			}
			f11[f11key] = f11val
		}
		cr.Status.AtProvider.MethodSettings = f11
	} else {
		cr.Status.AtProvider.MethodSettings = nil
	}
	if resp.StageName != nil {
		cr.Spec.ForProvider.StageName = resp.StageName
	} else {
		cr.Spec.ForProvider.StageName = nil
	}
	if resp.Tags != nil {
		f13 := map[string]*string{}
		for f13key, f13valiter := range resp.Tags {
			var f13val string
			f13val = *f13valiter
			f13[f13key] = &f13val
		}
		cr.Spec.ForProvider.Tags = f13
	} else {
		cr.Spec.ForProvider.Tags = nil
	}
	if resp.TracingEnabled != nil {
		cr.Spec.ForProvider.TracingEnabled = resp.TracingEnabled
	} else {
		cr.Spec.ForProvider.TracingEnabled = nil
	}
	if resp.Variables != nil {
		f15 := map[string]*string{}
		for f15key, f15valiter := range resp.Variables {
			var f15val string
			f15val = *f15valiter
			f15[f15key] = &f15val
		}
		cr.Spec.ForProvider.Variables = f15
	} else {
		cr.Spec.ForProvider.Variables = nil
	}
	if resp.WebAclArn != nil {
		cr.Status.AtProvider.WebACLARN = resp.WebAclArn
	} else {
		cr.Status.AtProvider.WebACLARN = nil
	}

	return e.postCreate(ctx, cr, resp, managed.ExternalCreation{}, err)
}

func (e *external) Update(ctx context.Context, mg cpresource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*svcapitypes.Stage)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errUnexpectedObject)
	}
	input := GenerateUpdateStageInput(cr)
	if err := e.preUpdate(ctx, cr, input); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "pre-update failed")
	}
	resp, err := e.client.UpdateStageWithContext(ctx, input)
	return e.postUpdate(ctx, cr, resp, managed.ExternalUpdate{}, errorutils.Wrap(err, errUpdate))
}

func (e *external) Delete(ctx context.Context, mg cpresource.Managed) error {
	cr, ok := mg.(*svcapitypes.Stage)
	if !ok {
		return errors.New(errUnexpectedObject)
	}
	cr.Status.SetConditions(xpv1.Deleting())
	input := GenerateDeleteStageInput(cr)
	ignore, err := e.preDelete(ctx, cr, input)
	if err != nil {
		return errors.Wrap(err, "pre-delete failed")
	}
	if ignore {
		return nil
	}
	resp, err := e.client.DeleteStageWithContext(ctx, input)
	return e.postDelete(ctx, cr, resp, errorutils.Wrap(cpresource.Ignore(IsNotFound, err), errDelete))
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
	preObserve     func(context.Context, *svcapitypes.Stage, *svcsdk.GetStageInput) error
	postObserve    func(context.Context, *svcapitypes.Stage, *svcsdk.Stage, managed.ExternalObservation, error) (managed.ExternalObservation, error)
	lateInitialize func(*svcapitypes.StageParameters, *svcsdk.Stage) error
	isUpToDate     func(context.Context, *svcapitypes.Stage, *svcsdk.Stage) (bool, string, error)
	preCreate      func(context.Context, *svcapitypes.Stage, *svcsdk.CreateStageInput) error
	postCreate     func(context.Context, *svcapitypes.Stage, *svcsdk.Stage, managed.ExternalCreation, error) (managed.ExternalCreation, error)
	preDelete      func(context.Context, *svcapitypes.Stage, *svcsdk.DeleteStageInput) (bool, error)
	postDelete     func(context.Context, *svcapitypes.Stage, *svcsdk.DeleteStageOutput, error) error
	preUpdate      func(context.Context, *svcapitypes.Stage, *svcsdk.UpdateStageInput) error
	postUpdate     func(context.Context, *svcapitypes.Stage, *svcsdk.Stage, managed.ExternalUpdate, error) (managed.ExternalUpdate, error)
}

func nopPreObserve(context.Context, *svcapitypes.Stage, *svcsdk.GetStageInput) error {
	return nil
}

func nopPostObserve(_ context.Context, _ *svcapitypes.Stage, _ *svcsdk.Stage, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	return obs, err
}
func nopLateInitialize(*svcapitypes.StageParameters, *svcsdk.Stage) error {
	return nil
}
func alwaysUpToDate(context.Context, *svcapitypes.Stage, *svcsdk.Stage) (bool, string, error) {
	return true, "", nil
}

func nopPreCreate(context.Context, *svcapitypes.Stage, *svcsdk.CreateStageInput) error {
	return nil
}
func nopPostCreate(_ context.Context, _ *svcapitypes.Stage, _ *svcsdk.Stage, cre managed.ExternalCreation, err error) (managed.ExternalCreation, error) {
	return cre, err
}
func nopPreDelete(context.Context, *svcapitypes.Stage, *svcsdk.DeleteStageInput) (bool, error) {
	return false, nil
}
func nopPostDelete(_ context.Context, _ *svcapitypes.Stage, _ *svcsdk.DeleteStageOutput, err error) error {
	return err
}
func nopPreUpdate(context.Context, *svcapitypes.Stage, *svcsdk.UpdateStageInput) error {
	return nil
}
func nopPostUpdate(_ context.Context, _ *svcapitypes.Stage, _ *svcsdk.Stage, upd managed.ExternalUpdate, err error) (managed.ExternalUpdate, error) {
	return upd, err
}
