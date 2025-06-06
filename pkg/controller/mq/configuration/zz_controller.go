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

package configuration

import (
	"context"

	svcapi "github.com/aws/aws-sdk-go/service/mq"
	svcsdk "github.com/aws/aws-sdk-go/service/mq"
	svcsdkapi "github.com/aws/aws-sdk-go/service/mq/mqiface"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	cpresource "github.com/crossplane/crossplane-runtime/pkg/resource"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/mq/v1alpha1"
	connectaws "github.com/crossplane-contrib/provider-aws/pkg/utils/connect/aws"
	errorutils "github.com/crossplane-contrib/provider-aws/pkg/utils/errors"
)

const (
	errUnexpectedObject = "managed resource is not an Configuration resource"

	errCreateSession = "cannot create a new session"
	errCreate        = "cannot create Configuration in AWS"
	errUpdate        = "cannot update Configuration in AWS"
	errDescribe      = "failed to describe Configuration"
	errDelete        = "failed to delete Configuration"
)

type connector struct {
	kube client.Client
	opts []option
}

func (c *connector) Connect(ctx context.Context, cr *svcapitypes.Configuration) (managed.TypedExternalClient[*svcapitypes.Configuration], error) {
	sess, err := connectaws.GetConfigV1(ctx, c.kube, cr, cr.Spec.ForProvider.Region)
	if err != nil {
		return nil, errors.Wrap(err, errCreateSession)
	}
	return newExternal(c.kube, svcapi.New(sess), c.opts), nil
}

func (e *external) Observe(ctx context.Context, cr *svcapitypes.Configuration) (managed.ExternalObservation, error) {
	if meta.GetExternalName(cr) == "" {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	input := GenerateDescribeConfigurationInput(cr)
	if err := e.preObserve(ctx, cr, input); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "pre-observe failed")
	}
	resp, err := e.client.DescribeConfigurationWithContext(ctx, input)
	if err != nil {
		return managed.ExternalObservation{ResourceExists: false}, errorutils.Wrap(cpresource.Ignore(IsNotFound, err), errDescribe)
	}
	currentSpec := cr.Spec.ForProvider.DeepCopy()
	if err := e.lateInitialize(&cr.Spec.ForProvider, resp); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "late-init failed")
	}
	GenerateConfiguration(resp).Status.AtProvider.DeepCopyInto(&cr.Status.AtProvider)
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

func (e *external) Create(ctx context.Context, cr *svcapitypes.Configuration) (managed.ExternalCreation, error) {
	cr.Status.SetConditions(xpv1.Creating())
	input := GenerateCreateConfigurationRequest(cr)
	if err := e.preCreate(ctx, cr, input); err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "pre-create failed")
	}
	resp, err := e.client.CreateConfigurationWithContext(ctx, input)
	if err != nil {
		return managed.ExternalCreation{}, errorutils.Wrap(err, errCreate)
	}

	if resp.Arn != nil {
		cr.Status.AtProvider.ARN = resp.Arn
	} else {
		cr.Status.AtProvider.ARN = nil
	}
	if resp.AuthenticationStrategy != nil {
		cr.Spec.ForProvider.AuthenticationStrategy = resp.AuthenticationStrategy
	} else {
		cr.Spec.ForProvider.AuthenticationStrategy = nil
	}
	if resp.Created != nil {
		cr.Status.AtProvider.Created = &metav1.Time{*resp.Created}
	} else {
		cr.Status.AtProvider.Created = nil
	}
	if resp.Id != nil {
		cr.Status.AtProvider.ID = resp.Id
	} else {
		cr.Status.AtProvider.ID = nil
	}
	if resp.LatestRevision != nil {
		f4 := &svcapitypes.ConfigurationRevision{}
		if resp.LatestRevision.Created != nil {
			f4.Created = &metav1.Time{*resp.LatestRevision.Created}
		}
		if resp.LatestRevision.Description != nil {
			f4.Description = resp.LatestRevision.Description
		}
		if resp.LatestRevision.Revision != nil {
			f4.Revision = resp.LatestRevision.Revision
		}
		cr.Status.AtProvider.LatestRevision = f4
	} else {
		cr.Status.AtProvider.LatestRevision = nil
	}
	if resp.Name != nil {
		cr.Spec.ForProvider.Name = resp.Name
	} else {
		cr.Spec.ForProvider.Name = nil
	}

	return e.postCreate(ctx, cr, resp, managed.ExternalCreation{}, err)
}

func (e *external) Update(ctx context.Context, cr *svcapitypes.Configuration) (managed.ExternalUpdate, error) {
	return e.update(ctx, cr)

}

func (e *external) Delete(ctx context.Context, cr *svcapitypes.Configuration) (managed.ExternalDelete, error) {
	cr.Status.SetConditions(xpv1.Deleting())
	return e.delete(ctx, cr)

}

func (e *external) Disconnect(ctx context.Context) error {
	// Unimplemented, required by newer versions of crossplane-runtime
	return nil
}

type option func(*external)

func newExternal(kube client.Client, client svcsdkapi.MQAPI, opts []option) *external {
	e := &external{
		kube:           kube,
		client:         client,
		preObserve:     nopPreObserve,
		postObserve:    nopPostObserve,
		lateInitialize: nopLateInitialize,
		isUpToDate:     alwaysUpToDate,
		preCreate:      nopPreCreate,
		postCreate:     nopPostCreate,
		delete:         nopDelete,
		update:         nopUpdate,
	}
	for _, f := range opts {
		f(e)
	}
	return e
}

type external struct {
	kube           client.Client
	client         svcsdkapi.MQAPI
	preObserve     func(context.Context, *svcapitypes.Configuration, *svcsdk.DescribeConfigurationInput) error
	postObserve    func(context.Context, *svcapitypes.Configuration, *svcsdk.DescribeConfigurationOutput, managed.ExternalObservation, error) (managed.ExternalObservation, error)
	lateInitialize func(*svcapitypes.ConfigurationParameters, *svcsdk.DescribeConfigurationOutput) error
	isUpToDate     func(context.Context, *svcapitypes.Configuration, *svcsdk.DescribeConfigurationOutput) (bool, string, error)
	preCreate      func(context.Context, *svcapitypes.Configuration, *svcsdk.CreateConfigurationRequest) error
	postCreate     func(context.Context, *svcapitypes.Configuration, *svcsdk.CreateConfigurationResponse, managed.ExternalCreation, error) (managed.ExternalCreation, error)
	delete         func(context.Context, *svcapitypes.Configuration) (managed.ExternalDelete, error)
	update         func(context.Context, *svcapitypes.Configuration) (managed.ExternalUpdate, error)
}

func nopPreObserve(context.Context, *svcapitypes.Configuration, *svcsdk.DescribeConfigurationInput) error {
	return nil
}

func nopPostObserve(_ context.Context, _ *svcapitypes.Configuration, _ *svcsdk.DescribeConfigurationOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	return obs, err
}
func nopLateInitialize(*svcapitypes.ConfigurationParameters, *svcsdk.DescribeConfigurationOutput) error {
	return nil
}
func alwaysUpToDate(context.Context, *svcapitypes.Configuration, *svcsdk.DescribeConfigurationOutput) (bool, string, error) {
	return true, "", nil
}

func nopPreCreate(context.Context, *svcapitypes.Configuration, *svcsdk.CreateConfigurationRequest) error {
	return nil
}
func nopPostCreate(_ context.Context, _ *svcapitypes.Configuration, _ *svcsdk.CreateConfigurationResponse, cre managed.ExternalCreation, err error) (managed.ExternalCreation, error) {
	return cre, err
}
func nopDelete(context.Context, *svcapitypes.Configuration) (managed.ExternalDelete, error) {
	return managed.ExternalDelete{}, nil
}
func nopUpdate(context.Context, *svcapitypes.Configuration) (managed.ExternalUpdate, error) {
	return managed.ExternalUpdate{}, nil
}
