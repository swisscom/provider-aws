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

	svcapi "github.com/aws/aws-sdk-go/service/wafv2"
	svcsdk "github.com/aws/aws-sdk-go/service/wafv2"
	svcsdkapi "github.com/aws/aws-sdk-go/service/wafv2/wafv2iface"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	cpresource "github.com/crossplane/crossplane-runtime/pkg/resource"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/wafv2/manualv1alpha1"
	connectaws "github.com/crossplane-contrib/provider-aws/pkg/utils/connect/aws"
	errorutils "github.com/crossplane-contrib/provider-aws/pkg/utils/errors"
)

const (
	errUnexpectedObject = "managed resource is not an WebACL resource"

	errCreateSession = "cannot create a new session"
	errCreate        = "cannot create WebACL in AWS"
	errUpdate        = "cannot update WebACL in AWS"
	errDescribe      = "failed to describe WebACL"
	errDelete        = "failed to delete WebACL"
)

type connector struct {
	kube client.Client
	opts []option
}

func (c *connector) Connect(ctx context.Context, mg cpresource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*svcapitypes.WebACL)
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
	cr, ok := mg.(*svcapitypes.WebACL)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errUnexpectedObject)
	}
	if meta.GetExternalName(cr) == "" {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	input := GenerateListWebACLsInput(cr)
	if err := e.preObserve(ctx, cr, input); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "pre-observe failed")
	}
	resp, err := e.client.ListWebACLsWithContext(ctx, input)
	if err != nil {
		return managed.ExternalObservation{ResourceExists: false}, errorutils.Wrap(cpresource.Ignore(IsNotFound, err), errDescribe)
	}
	resp = e.filterList(cr, resp)
	if len(resp.WebACLs) == 0 {
		return managed.ExternalObservation{ResourceExists: false}, nil
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

func (e *external) Create(ctx context.Context, mg cpresource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*svcapitypes.WebACL)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errUnexpectedObject)
	}
	cr.Status.SetConditions(xpv1.Creating())
	input := GenerateCreateWebACLInput(cr)
	if err := e.preCreate(ctx, cr, input); err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "pre-create failed")
	}
	resp, err := e.client.CreateWebACLWithContext(ctx, input)
	if err != nil {
		return managed.ExternalCreation{}, errorutils.Wrap(err, errCreate)
	}

	if resp.Summary.ARN != nil {
		cr.Status.AtProvider.ARN = resp.Summary.ARN
	} else {
		cr.Status.AtProvider.ARN = nil
	}
	if resp.Summary.Description != nil {
		cr.Spec.ForProvider.Description = resp.Summary.Description
	} else {
		cr.Spec.ForProvider.Description = nil
	}
	if resp.Summary.Id != nil {
		cr.Status.AtProvider.ID = resp.Summary.Id
	} else {
		cr.Status.AtProvider.ID = nil
	}
	if resp.Summary.LockToken != nil {
		cr.Status.AtProvider.LockToken = resp.Summary.LockToken
	} else {
		cr.Status.AtProvider.LockToken = nil
	}
	if resp.Summary.Name != nil {
		cr.Status.AtProvider.Name = resp.Summary.Name
	} else {
		cr.Status.AtProvider.Name = nil
	}

	return e.postCreate(ctx, cr, resp, managed.ExternalCreation{}, err)
}

func (e *external) Update(ctx context.Context, mg cpresource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*svcapitypes.WebACL)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errUnexpectedObject)
	}
	input := GenerateUpdateWebACLInput(cr)
	if err := e.preUpdate(ctx, cr, input); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "pre-update failed")
	}
	resp, err := e.client.UpdateWebACLWithContext(ctx, input)
	return e.postUpdate(ctx, cr, resp, managed.ExternalUpdate{}, errorutils.Wrap(err, errUpdate))
}

func (e *external) Delete(ctx context.Context, mg cpresource.Managed) error {
	cr, ok := mg.(*svcapitypes.WebACL)
	if !ok {
		return errors.New(errUnexpectedObject)
	}
	cr.Status.SetConditions(xpv1.Deleting())
	input := GenerateDeleteWebACLInput(cr)
	ignore, err := e.preDelete(ctx, cr, input)
	if err != nil {
		return errors.Wrap(err, "pre-delete failed")
	}
	if ignore {
		return nil
	}
	resp, err := e.client.DeleteWebACLWithContext(ctx, input)
	return e.postDelete(ctx, cr, resp, errorutils.Wrap(cpresource.Ignore(IsNotFound, err), errDelete))
}

type option func(*external)

func newExternal(kube client.Client, client svcsdkapi.WAFV2API, opts []option) *external {
	e := &external{
		kube:           kube,
		client:         client,
		preObserve:     nopPreObserve,
		postObserve:    nopPostObserve,
		lateInitialize: nopLateInitialize,
		isUpToDate:     alwaysUpToDate,
		filterList:     nopFilterList,
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
	client         svcsdkapi.WAFV2API
	preObserve     func(context.Context, *svcapitypes.WebACL, *svcsdk.ListWebACLsInput) error
	postObserve    func(context.Context, *svcapitypes.WebACL, *svcsdk.ListWebACLsOutput, managed.ExternalObservation, error) (managed.ExternalObservation, error)
	filterList     func(*svcapitypes.WebACL, *svcsdk.ListWebACLsOutput) *svcsdk.ListWebACLsOutput
	lateInitialize func(*svcapitypes.WebACLParameters, *svcsdk.ListWebACLsOutput) error
	isUpToDate     func(context.Context, *svcapitypes.WebACL, *svcsdk.ListWebACLsOutput) (bool, string, error)
	preCreate      func(context.Context, *svcapitypes.WebACL, *svcsdk.CreateWebACLInput) error
	postCreate     func(context.Context, *svcapitypes.WebACL, *svcsdk.CreateWebACLOutput, managed.ExternalCreation, error) (managed.ExternalCreation, error)
	preDelete      func(context.Context, *svcapitypes.WebACL, *svcsdk.DeleteWebACLInput) (bool, error)
	postDelete     func(context.Context, *svcapitypes.WebACL, *svcsdk.DeleteWebACLOutput, error) error
	preUpdate      func(context.Context, *svcapitypes.WebACL, *svcsdk.UpdateWebACLInput) error
	postUpdate     func(context.Context, *svcapitypes.WebACL, *svcsdk.UpdateWebACLOutput, managed.ExternalUpdate, error) (managed.ExternalUpdate, error)
}

func nopPreObserve(context.Context, *svcapitypes.WebACL, *svcsdk.ListWebACLsInput) error {
	return nil
}
func nopPostObserve(_ context.Context, _ *svcapitypes.WebACL, _ *svcsdk.ListWebACLsOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	return obs, err
}
func nopFilterList(_ *svcapitypes.WebACL, list *svcsdk.ListWebACLsOutput) *svcsdk.ListWebACLsOutput {
	return list
}

func nopLateInitialize(*svcapitypes.WebACLParameters, *svcsdk.ListWebACLsOutput) error {
	return nil
}
func alwaysUpToDate(context.Context, *svcapitypes.WebACL, *svcsdk.ListWebACLsOutput) (bool, string, error) {
	return true, "", nil
}

func nopPreCreate(context.Context, *svcapitypes.WebACL, *svcsdk.CreateWebACLInput) error {
	return nil
}
func nopPostCreate(_ context.Context, _ *svcapitypes.WebACL, _ *svcsdk.CreateWebACLOutput, cre managed.ExternalCreation, err error) (managed.ExternalCreation, error) {
	return cre, err
}
func nopPreDelete(context.Context, *svcapitypes.WebACL, *svcsdk.DeleteWebACLInput) (bool, error) {
	return false, nil
}
func nopPostDelete(_ context.Context, _ *svcapitypes.WebACL, _ *svcsdk.DeleteWebACLOutput, err error) error {
	return err
}
func nopPreUpdate(context.Context, *svcapitypes.WebACL, *svcsdk.UpdateWebACLInput) error {
	return nil
}
func nopPostUpdate(_ context.Context, _ *svcapitypes.WebACL, _ *svcsdk.UpdateWebACLOutput, upd managed.ExternalUpdate, err error) (managed.ExternalUpdate, error) {
	return upd, err
}