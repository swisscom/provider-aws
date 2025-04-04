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

package transitgatewayvpcattachment

import (
	"context"

	svcapi "github.com/aws/aws-sdk-go/service/ec2"
	svcsdk "github.com/aws/aws-sdk-go/service/ec2"
	svcsdkapi "github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	cpresource "github.com/crossplane/crossplane-runtime/pkg/resource"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/ec2/v1alpha1"
	connectaws "github.com/crossplane-contrib/provider-aws/pkg/utils/connect/aws"
	errorutils "github.com/crossplane-contrib/provider-aws/pkg/utils/errors"
)

const (
	errUnexpectedObject = "managed resource is not an TransitGatewayVPCAttachment resource"

	errCreateSession = "cannot create a new session"
	errCreate        = "cannot create TransitGatewayVPCAttachment in AWS"
	errUpdate        = "cannot update TransitGatewayVPCAttachment in AWS"
	errDescribe      = "failed to describe TransitGatewayVPCAttachment"
	errDelete        = "failed to delete TransitGatewayVPCAttachment"
)

type connector struct {
	kube client.Client
	opts []option
}

func (c *connector) Connect(ctx context.Context, cr *svcapitypes.TransitGatewayVPCAttachment) (managed.TypedExternalClient[*svcapitypes.TransitGatewayVPCAttachment], error) {
	sess, err := connectaws.GetConfigV1(ctx, c.kube, cr, cr.Spec.ForProvider.Region)
	if err != nil {
		return nil, errors.Wrap(err, errCreateSession)
	}
	return newExternal(c.kube, svcapi.New(sess), c.opts), nil
}

func (e *external) Observe(ctx context.Context, cr *svcapitypes.TransitGatewayVPCAttachment) (managed.ExternalObservation, error) {
	if meta.GetExternalName(cr) == "" {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	input := GenerateDescribeTransitGatewayVpcAttachmentsInput(cr)
	if err := e.preObserve(ctx, cr, input); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "pre-observe failed")
	}
	resp, err := e.client.DescribeTransitGatewayVpcAttachmentsWithContext(ctx, input)
	if err != nil {
		return managed.ExternalObservation{ResourceExists: false}, errorutils.Wrap(cpresource.Ignore(IsNotFound, err), errDescribe)
	}
	resp = e.filterList(cr, resp)
	if len(resp.TransitGatewayVpcAttachments) == 0 {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	currentSpec := cr.Spec.ForProvider.DeepCopy()
	if err := e.lateInitialize(&cr.Spec.ForProvider, resp); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "late-init failed")
	}
	GenerateTransitGatewayVPCAttachment(resp).Status.AtProvider.DeepCopyInto(&cr.Status.AtProvider)
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

func (e *external) Create(ctx context.Context, cr *svcapitypes.TransitGatewayVPCAttachment) (managed.ExternalCreation, error) {
	cr.Status.SetConditions(xpv1.Creating())
	input := GenerateCreateTransitGatewayVpcAttachmentInput(cr)
	if err := e.preCreate(ctx, cr, input); err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "pre-create failed")
	}
	resp, err := e.client.CreateTransitGatewayVpcAttachmentWithContext(ctx, input)
	if err != nil {
		return managed.ExternalCreation{}, errorutils.Wrap(err, errCreate)
	}

	if resp.TransitGatewayVpcAttachment.CreationTime != nil {
		cr.Status.AtProvider.CreationTime = &metav1.Time{*resp.TransitGatewayVpcAttachment.CreationTime}
	} else {
		cr.Status.AtProvider.CreationTime = nil
	}
	if resp.TransitGatewayVpcAttachment.Options != nil {
		f1 := &svcapitypes.CreateTransitGatewayVPCAttachmentRequestOptions{}
		if resp.TransitGatewayVpcAttachment.Options.ApplianceModeSupport != nil {
			f1.ApplianceModeSupport = resp.TransitGatewayVpcAttachment.Options.ApplianceModeSupport
		}
		if resp.TransitGatewayVpcAttachment.Options.DnsSupport != nil {
			f1.DNSSupport = resp.TransitGatewayVpcAttachment.Options.DnsSupport
		}
		if resp.TransitGatewayVpcAttachment.Options.Ipv6Support != nil {
			f1.IPv6Support = resp.TransitGatewayVpcAttachment.Options.Ipv6Support
		}
		cr.Spec.ForProvider.Options = f1
	} else {
		cr.Spec.ForProvider.Options = nil
	}
	if resp.TransitGatewayVpcAttachment.State != nil {
		cr.Status.AtProvider.State = resp.TransitGatewayVpcAttachment.State
	} else {
		cr.Status.AtProvider.State = nil
	}
	if resp.TransitGatewayVpcAttachment.SubnetIds != nil {
		f3 := []*string{}
		for _, f3iter := range resp.TransitGatewayVpcAttachment.SubnetIds {
			var f3elem string
			f3elem = *f3iter
			f3 = append(f3, &f3elem)
		}
		cr.Status.AtProvider.SubnetIDs = f3
	} else {
		cr.Status.AtProvider.SubnetIDs = nil
	}
	if resp.TransitGatewayVpcAttachment.Tags != nil {
		f4 := []*svcapitypes.Tag{}
		for _, f4iter := range resp.TransitGatewayVpcAttachment.Tags {
			f4elem := &svcapitypes.Tag{}
			if f4iter.Key != nil {
				f4elem.Key = f4iter.Key
			}
			if f4iter.Value != nil {
				f4elem.Value = f4iter.Value
			}
			f4 = append(f4, f4elem)
		}
		cr.Status.AtProvider.Tags = f4
	} else {
		cr.Status.AtProvider.Tags = nil
	}
	if resp.TransitGatewayVpcAttachment.TransitGatewayAttachmentId != nil {
		cr.Status.AtProvider.TransitGatewayAttachmentID = resp.TransitGatewayVpcAttachment.TransitGatewayAttachmentId
	} else {
		cr.Status.AtProvider.TransitGatewayAttachmentID = nil
	}
	if resp.TransitGatewayVpcAttachment.TransitGatewayId != nil {
		cr.Status.AtProvider.TransitGatewayID = resp.TransitGatewayVpcAttachment.TransitGatewayId
	} else {
		cr.Status.AtProvider.TransitGatewayID = nil
	}
	if resp.TransitGatewayVpcAttachment.VpcId != nil {
		cr.Status.AtProvider.VPCID = resp.TransitGatewayVpcAttachment.VpcId
	} else {
		cr.Status.AtProvider.VPCID = nil
	}
	if resp.TransitGatewayVpcAttachment.VpcOwnerId != nil {
		cr.Status.AtProvider.VPCOwnerID = resp.TransitGatewayVpcAttachment.VpcOwnerId
	} else {
		cr.Status.AtProvider.VPCOwnerID = nil
	}

	return e.postCreate(ctx, cr, resp, managed.ExternalCreation{}, err)
}

func (e *external) Update(ctx context.Context, cr *svcapitypes.TransitGatewayVPCAttachment) (managed.ExternalUpdate, error) {
	input := GenerateModifyTransitGatewayVpcAttachmentInput(cr)
	if err := e.preUpdate(ctx, cr, input); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "pre-update failed")
	}
	resp, err := e.client.ModifyTransitGatewayVpcAttachmentWithContext(ctx, input)
	return e.postUpdate(ctx, cr, resp, managed.ExternalUpdate{}, errorutils.Wrap(err, errUpdate))
}

func (e *external) Delete(ctx context.Context, cr *svcapitypes.TransitGatewayVPCAttachment) (managed.ExternalDelete, error) {
	cr.Status.SetConditions(xpv1.Deleting())
	input := GenerateDeleteTransitGatewayVpcAttachmentInput(cr)
	ignore, err := e.preDelete(ctx, cr, input)
	if err != nil {
		return managed.ExternalDelete{}, errors.Wrap(err, "pre-delete failed")
	}
	if ignore {
		return managed.ExternalDelete{}, nil
	}
	resp, err := e.client.DeleteTransitGatewayVpcAttachmentWithContext(ctx, input)
	return e.postDelete(ctx, cr, resp, errorutils.Wrap(cpresource.Ignore(IsNotFound, err), errDelete))
}

func (e *external) Disconnect(ctx context.Context) error {
	// Unimplemented, required by newer versions of crossplane-runtime
	return nil
}

type option func(*external)

func newExternal(kube client.Client, client svcsdkapi.EC2API, opts []option) *external {
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
	client         svcsdkapi.EC2API
	preObserve     func(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.DescribeTransitGatewayVpcAttachmentsInput) error
	postObserve    func(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.DescribeTransitGatewayVpcAttachmentsOutput, managed.ExternalObservation, error) (managed.ExternalObservation, error)
	filterList     func(*svcapitypes.TransitGatewayVPCAttachment, *svcsdk.DescribeTransitGatewayVpcAttachmentsOutput) *svcsdk.DescribeTransitGatewayVpcAttachmentsOutput
	lateInitialize func(*svcapitypes.TransitGatewayVPCAttachmentParameters, *svcsdk.DescribeTransitGatewayVpcAttachmentsOutput) error
	isUpToDate     func(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.DescribeTransitGatewayVpcAttachmentsOutput) (bool, string, error)
	preCreate      func(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.CreateTransitGatewayVpcAttachmentInput) error
	postCreate     func(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.CreateTransitGatewayVpcAttachmentOutput, managed.ExternalCreation, error) (managed.ExternalCreation, error)
	preDelete      func(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.DeleteTransitGatewayVpcAttachmentInput) (bool, error)
	postDelete     func(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.DeleteTransitGatewayVpcAttachmentOutput, error) (managed.ExternalDelete, error)
	preUpdate      func(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.ModifyTransitGatewayVpcAttachmentInput) error
	postUpdate     func(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.ModifyTransitGatewayVpcAttachmentOutput, managed.ExternalUpdate, error) (managed.ExternalUpdate, error)
}

func nopPreObserve(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.DescribeTransitGatewayVpcAttachmentsInput) error {
	return nil
}
func nopPostObserve(_ context.Context, _ *svcapitypes.TransitGatewayVPCAttachment, _ *svcsdk.DescribeTransitGatewayVpcAttachmentsOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	return obs, err
}
func nopFilterList(_ *svcapitypes.TransitGatewayVPCAttachment, list *svcsdk.DescribeTransitGatewayVpcAttachmentsOutput) *svcsdk.DescribeTransitGatewayVpcAttachmentsOutput {
	return list
}

func nopLateInitialize(*svcapitypes.TransitGatewayVPCAttachmentParameters, *svcsdk.DescribeTransitGatewayVpcAttachmentsOutput) error {
	return nil
}
func alwaysUpToDate(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.DescribeTransitGatewayVpcAttachmentsOutput) (bool, string, error) {
	return true, "", nil
}

func nopPreCreate(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.CreateTransitGatewayVpcAttachmentInput) error {
	return nil
}
func nopPostCreate(_ context.Context, _ *svcapitypes.TransitGatewayVPCAttachment, _ *svcsdk.CreateTransitGatewayVpcAttachmentOutput, cre managed.ExternalCreation, err error) (managed.ExternalCreation, error) {
	return cre, err
}
func nopPreDelete(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.DeleteTransitGatewayVpcAttachmentInput) (bool, error) {
	return false, nil
}
func nopPostDelete(_ context.Context, _ *svcapitypes.TransitGatewayVPCAttachment, _ *svcsdk.DeleteTransitGatewayVpcAttachmentOutput, err error) (managed.ExternalDelete, error) {
	return managed.ExternalDelete{}, err
}
func nopPreUpdate(context.Context, *svcapitypes.TransitGatewayVPCAttachment, *svcsdk.ModifyTransitGatewayVpcAttachmentInput) error {
	return nil
}
func nopPostUpdate(_ context.Context, _ *svcapitypes.TransitGatewayVPCAttachment, _ *svcsdk.ModifyTransitGatewayVpcAttachmentOutput, upd managed.ExternalUpdate, err error) (managed.ExternalUpdate, error) {
	return upd, err
}
