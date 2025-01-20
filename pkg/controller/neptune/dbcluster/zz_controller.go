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

package dbcluster

import (
	"context"

	svcapi "github.com/aws/aws-sdk-go/service/neptune"
	svcsdk "github.com/aws/aws-sdk-go/service/neptune"
	svcsdkapi "github.com/aws/aws-sdk-go/service/neptune/neptuneiface"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	cpresource "github.com/crossplane/crossplane-runtime/pkg/resource"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/neptune/v1alpha1"
	connectaws "github.com/crossplane-contrib/provider-aws/pkg/utils/connect/aws"
	errorutils "github.com/crossplane-contrib/provider-aws/pkg/utils/errors"
)

const (
	errUnexpectedObject = "managed resource is not an DBCluster resource"

	errCreateSession = "cannot create a new session"
	errCreate        = "cannot create DBCluster in AWS"
	errUpdate        = "cannot update DBCluster in AWS"
	errDescribe      = "failed to describe DBCluster"
	errDelete        = "failed to delete DBCluster"
)

type connector struct {
	kube client.Client
	opts []option
}

func (c *connector) Connect(ctx context.Context, mg cpresource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*svcapitypes.DBCluster)
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
	cr, ok := mg.(*svcapitypes.DBCluster)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errUnexpectedObject)
	}
	if meta.GetExternalName(cr) == "" {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	input := GenerateDescribeDBClustersInput(cr)
	if err := e.preObserve(ctx, cr, input); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "pre-observe failed")
	}
	resp, err := e.client.DescribeDBClustersWithContext(ctx, input)
	if err != nil {
		return managed.ExternalObservation{ResourceExists: false}, errorutils.Wrap(cpresource.Ignore(IsNotFound, err), errDescribe)
	}
	resp = e.filterList(cr, resp)
	if len(resp.DBClusters) == 0 {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	currentSpec := cr.Spec.ForProvider.DeepCopy()
	if err := e.lateInitialize(&cr.Spec.ForProvider, resp); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "late-init failed")
	}
	GenerateDBCluster(resp).Status.AtProvider.DeepCopyInto(&cr.Status.AtProvider)
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
	cr, ok := mg.(*svcapitypes.DBCluster)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errUnexpectedObject)
	}
	cr.Status.SetConditions(xpv1.Creating())
	input := GenerateCreateDBClusterInput(cr)
	if err := e.preCreate(ctx, cr, input); err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "pre-create failed")
	}
	resp, err := e.client.CreateDBClusterWithContext(ctx, input)
	if err != nil {
		return managed.ExternalCreation{}, errorutils.Wrap(err, errCreate)
	}

	if resp.DBCluster.AllocatedStorage != nil {
		cr.Status.AtProvider.AllocatedStorage = resp.DBCluster.AllocatedStorage
	} else {
		cr.Status.AtProvider.AllocatedStorage = nil
	}
	if resp.DBCluster.AssociatedRoles != nil {
		f1 := []*svcapitypes.DBClusterRole{}
		for _, f1iter := range resp.DBCluster.AssociatedRoles {
			f1elem := &svcapitypes.DBClusterRole{}
			if f1iter.FeatureName != nil {
				f1elem.FeatureName = f1iter.FeatureName
			}
			if f1iter.RoleArn != nil {
				f1elem.RoleARN = f1iter.RoleArn
			}
			if f1iter.Status != nil {
				f1elem.Status = f1iter.Status
			}
			f1 = append(f1, f1elem)
		}
		cr.Status.AtProvider.AssociatedRoles = f1
	} else {
		cr.Status.AtProvider.AssociatedRoles = nil
	}
	if resp.DBCluster.AutomaticRestartTime != nil {
		cr.Status.AtProvider.AutomaticRestartTime = &metav1.Time{*resp.DBCluster.AutomaticRestartTime}
	} else {
		cr.Status.AtProvider.AutomaticRestartTime = nil
	}
	if resp.DBCluster.AvailabilityZones != nil {
		f3 := []*string{}
		for _, f3iter := range resp.DBCluster.AvailabilityZones {
			var f3elem string
			f3elem = *f3iter
			f3 = append(f3, &f3elem)
		}
		cr.Spec.ForProvider.AvailabilityZones = f3
	} else {
		cr.Spec.ForProvider.AvailabilityZones = nil
	}
	if resp.DBCluster.BackupRetentionPeriod != nil {
		cr.Spec.ForProvider.BackupRetentionPeriod = resp.DBCluster.BackupRetentionPeriod
	} else {
		cr.Spec.ForProvider.BackupRetentionPeriod = nil
	}
	if resp.DBCluster.CharacterSetName != nil {
		cr.Spec.ForProvider.CharacterSetName = resp.DBCluster.CharacterSetName
	} else {
		cr.Spec.ForProvider.CharacterSetName = nil
	}
	if resp.DBCluster.CloneGroupId != nil {
		cr.Status.AtProvider.CloneGroupID = resp.DBCluster.CloneGroupId
	} else {
		cr.Status.AtProvider.CloneGroupID = nil
	}
	if resp.DBCluster.ClusterCreateTime != nil {
		cr.Status.AtProvider.ClusterCreateTime = &metav1.Time{*resp.DBCluster.ClusterCreateTime}
	} else {
		cr.Status.AtProvider.ClusterCreateTime = nil
	}
	if resp.DBCluster.CopyTagsToSnapshot != nil {
		cr.Spec.ForProvider.CopyTagsToSnapshot = resp.DBCluster.CopyTagsToSnapshot
	} else {
		cr.Spec.ForProvider.CopyTagsToSnapshot = nil
	}
	if resp.DBCluster.CrossAccountClone != nil {
		cr.Status.AtProvider.CrossAccountClone = resp.DBCluster.CrossAccountClone
	} else {
		cr.Status.AtProvider.CrossAccountClone = nil
	}
	if resp.DBCluster.DBClusterArn != nil {
		cr.Status.AtProvider.DBClusterARN = resp.DBCluster.DBClusterArn
	} else {
		cr.Status.AtProvider.DBClusterARN = nil
	}
	if resp.DBCluster.DBClusterIdentifier != nil {
		cr.Status.AtProvider.DBClusterIdentifier = resp.DBCluster.DBClusterIdentifier
	} else {
		cr.Status.AtProvider.DBClusterIdentifier = nil
	}
	if resp.DBCluster.DBClusterMembers != nil {
		f12 := []*svcapitypes.DBClusterMember{}
		for _, f12iter := range resp.DBCluster.DBClusterMembers {
			f12elem := &svcapitypes.DBClusterMember{}
			if f12iter.DBClusterParameterGroupStatus != nil {
				f12elem.DBClusterParameterGroupStatus = f12iter.DBClusterParameterGroupStatus
			}
			if f12iter.DBInstanceIdentifier != nil {
				f12elem.DBInstanceIdentifier = f12iter.DBInstanceIdentifier
			}
			if f12iter.IsClusterWriter != nil {
				f12elem.IsClusterWriter = f12iter.IsClusterWriter
			}
			if f12iter.PromotionTier != nil {
				f12elem.PromotionTier = f12iter.PromotionTier
			}
			f12 = append(f12, f12elem)
		}
		cr.Status.AtProvider.DBClusterMembers = f12
	} else {
		cr.Status.AtProvider.DBClusterMembers = nil
	}
	if resp.DBCluster.DBClusterOptionGroupMemberships != nil {
		f13 := []*svcapitypes.DBClusterOptionGroupStatus{}
		for _, f13iter := range resp.DBCluster.DBClusterOptionGroupMemberships {
			f13elem := &svcapitypes.DBClusterOptionGroupStatus{}
			if f13iter.DBClusterOptionGroupName != nil {
				f13elem.DBClusterOptionGroupName = f13iter.DBClusterOptionGroupName
			}
			if f13iter.Status != nil {
				f13elem.Status = f13iter.Status
			}
			f13 = append(f13, f13elem)
		}
		cr.Status.AtProvider.DBClusterOptionGroupMemberships = f13
	} else {
		cr.Status.AtProvider.DBClusterOptionGroupMemberships = nil
	}
	if resp.DBCluster.DBClusterParameterGroup != nil {
		cr.Status.AtProvider.DBClusterParameterGroup = resp.DBCluster.DBClusterParameterGroup
	} else {
		cr.Status.AtProvider.DBClusterParameterGroup = nil
	}
	if resp.DBCluster.DBSubnetGroup != nil {
		cr.Status.AtProvider.DBSubnetGroup = resp.DBCluster.DBSubnetGroup
	} else {
		cr.Status.AtProvider.DBSubnetGroup = nil
	}
	if resp.DBCluster.DatabaseName != nil {
		cr.Spec.ForProvider.DatabaseName = resp.DBCluster.DatabaseName
	} else {
		cr.Spec.ForProvider.DatabaseName = nil
	}
	if resp.DBCluster.DbClusterResourceId != nil {
		cr.Status.AtProvider.DBClusterResourceID = resp.DBCluster.DbClusterResourceId
	} else {
		cr.Status.AtProvider.DBClusterResourceID = nil
	}
	if resp.DBCluster.DeletionProtection != nil {
		cr.Spec.ForProvider.DeletionProtection = resp.DBCluster.DeletionProtection
	} else {
		cr.Spec.ForProvider.DeletionProtection = nil
	}
	if resp.DBCluster.EarliestRestorableTime != nil {
		cr.Status.AtProvider.EarliestRestorableTime = &metav1.Time{*resp.DBCluster.EarliestRestorableTime}
	} else {
		cr.Status.AtProvider.EarliestRestorableTime = nil
	}
	if resp.DBCluster.EnabledCloudwatchLogsExports != nil {
		f20 := []*string{}
		for _, f20iter := range resp.DBCluster.EnabledCloudwatchLogsExports {
			var f20elem string
			f20elem = *f20iter
			f20 = append(f20, &f20elem)
		}
		cr.Status.AtProvider.EnabledCloudwatchLogsExports = f20
	} else {
		cr.Status.AtProvider.EnabledCloudwatchLogsExports = nil
	}
	if resp.DBCluster.Endpoint != nil {
		cr.Status.AtProvider.Endpoint = resp.DBCluster.Endpoint
	} else {
		cr.Status.AtProvider.Endpoint = nil
	}
	if resp.DBCluster.Engine != nil {
		cr.Spec.ForProvider.Engine = resp.DBCluster.Engine
	} else {
		cr.Spec.ForProvider.Engine = nil
	}
	if resp.DBCluster.EngineVersion != nil {
		cr.Spec.ForProvider.EngineVersion = resp.DBCluster.EngineVersion
	} else {
		cr.Spec.ForProvider.EngineVersion = nil
	}
	if resp.DBCluster.GlobalClusterIdentifier != nil {
		cr.Spec.ForProvider.GlobalClusterIdentifier = resp.DBCluster.GlobalClusterIdentifier
	} else {
		cr.Spec.ForProvider.GlobalClusterIdentifier = nil
	}
	if resp.DBCluster.HostedZoneId != nil {
		cr.Status.AtProvider.HostedZoneID = resp.DBCluster.HostedZoneId
	} else {
		cr.Status.AtProvider.HostedZoneID = nil
	}
	if resp.DBCluster.IAMDatabaseAuthenticationEnabled != nil {
		cr.Status.AtProvider.IAMDatabaseAuthenticationEnabled = resp.DBCluster.IAMDatabaseAuthenticationEnabled
	} else {
		cr.Status.AtProvider.IAMDatabaseAuthenticationEnabled = nil
	}
	if resp.DBCluster.IOOptimizedNextAllowedModificationTime != nil {
		cr.Status.AtProvider.IOOptimizedNextAllowedModificationTime = &metav1.Time{*resp.DBCluster.IOOptimizedNextAllowedModificationTime}
	} else {
		cr.Status.AtProvider.IOOptimizedNextAllowedModificationTime = nil
	}
	if resp.DBCluster.KmsKeyId != nil {
		cr.Spec.ForProvider.KMSKeyID = resp.DBCluster.KmsKeyId
	} else {
		cr.Spec.ForProvider.KMSKeyID = nil
	}
	if resp.DBCluster.LatestRestorableTime != nil {
		cr.Status.AtProvider.LatestRestorableTime = &metav1.Time{*resp.DBCluster.LatestRestorableTime}
	} else {
		cr.Status.AtProvider.LatestRestorableTime = nil
	}
	if resp.DBCluster.MasterUsername != nil {
		cr.Spec.ForProvider.MasterUsername = resp.DBCluster.MasterUsername
	} else {
		cr.Spec.ForProvider.MasterUsername = nil
	}
	if resp.DBCluster.MultiAZ != nil {
		cr.Status.AtProvider.MultiAZ = resp.DBCluster.MultiAZ
	} else {
		cr.Status.AtProvider.MultiAZ = nil
	}
	if resp.DBCluster.PendingModifiedValues != nil {
		f32 := &svcapitypes.ClusterPendingModifiedValues{}
		if resp.DBCluster.PendingModifiedValues.AllocatedStorage != nil {
			f32.AllocatedStorage = resp.DBCluster.PendingModifiedValues.AllocatedStorage
		}
		if resp.DBCluster.PendingModifiedValues.BackupRetentionPeriod != nil {
			f32.BackupRetentionPeriod = resp.DBCluster.PendingModifiedValues.BackupRetentionPeriod
		}
		if resp.DBCluster.PendingModifiedValues.DBClusterIdentifier != nil {
			f32.DBClusterIdentifier = resp.DBCluster.PendingModifiedValues.DBClusterIdentifier
		}
		if resp.DBCluster.PendingModifiedValues.EngineVersion != nil {
			f32.EngineVersion = resp.DBCluster.PendingModifiedValues.EngineVersion
		}
		if resp.DBCluster.PendingModifiedValues.IAMDatabaseAuthenticationEnabled != nil {
			f32.IAMDatabaseAuthenticationEnabled = resp.DBCluster.PendingModifiedValues.IAMDatabaseAuthenticationEnabled
		}
		if resp.DBCluster.PendingModifiedValues.Iops != nil {
			f32.IOPS = resp.DBCluster.PendingModifiedValues.Iops
		}
		if resp.DBCluster.PendingModifiedValues.PendingCloudwatchLogsExports != nil {
			f32f6 := &svcapitypes.PendingCloudwatchLogsExports{}
			if resp.DBCluster.PendingModifiedValues.PendingCloudwatchLogsExports.LogTypesToDisable != nil {
				f32f6f0 := []*string{}
				for _, f32f6f0iter := range resp.DBCluster.PendingModifiedValues.PendingCloudwatchLogsExports.LogTypesToDisable {
					var f32f6f0elem string
					f32f6f0elem = *f32f6f0iter
					f32f6f0 = append(f32f6f0, &f32f6f0elem)
				}
				f32f6.LogTypesToDisable = f32f6f0
			}
			if resp.DBCluster.PendingModifiedValues.PendingCloudwatchLogsExports.LogTypesToEnable != nil {
				f32f6f1 := []*string{}
				for _, f32f6f1iter := range resp.DBCluster.PendingModifiedValues.PendingCloudwatchLogsExports.LogTypesToEnable {
					var f32f6f1elem string
					f32f6f1elem = *f32f6f1iter
					f32f6f1 = append(f32f6f1, &f32f6f1elem)
				}
				f32f6.LogTypesToEnable = f32f6f1
			}
			f32.PendingCloudwatchLogsExports = f32f6
		}
		if resp.DBCluster.PendingModifiedValues.StorageType != nil {
			f32.StorageType = resp.DBCluster.PendingModifiedValues.StorageType
		}
		cr.Status.AtProvider.PendingModifiedValues = f32
	} else {
		cr.Status.AtProvider.PendingModifiedValues = nil
	}
	if resp.DBCluster.PercentProgress != nil {
		cr.Status.AtProvider.PercentProgress = resp.DBCluster.PercentProgress
	} else {
		cr.Status.AtProvider.PercentProgress = nil
	}
	if resp.DBCluster.Port != nil {
		cr.Spec.ForProvider.Port = resp.DBCluster.Port
	} else {
		cr.Spec.ForProvider.Port = nil
	}
	if resp.DBCluster.PreferredBackupWindow != nil {
		cr.Spec.ForProvider.PreferredBackupWindow = resp.DBCluster.PreferredBackupWindow
	} else {
		cr.Spec.ForProvider.PreferredBackupWindow = nil
	}
	if resp.DBCluster.PreferredMaintenanceWindow != nil {
		cr.Spec.ForProvider.PreferredMaintenanceWindow = resp.DBCluster.PreferredMaintenanceWindow
	} else {
		cr.Spec.ForProvider.PreferredMaintenanceWindow = nil
	}
	if resp.DBCluster.ReadReplicaIdentifiers != nil {
		f37 := []*string{}
		for _, f37iter := range resp.DBCluster.ReadReplicaIdentifiers {
			var f37elem string
			f37elem = *f37iter
			f37 = append(f37, &f37elem)
		}
		cr.Status.AtProvider.ReadReplicaIdentifiers = f37
	} else {
		cr.Status.AtProvider.ReadReplicaIdentifiers = nil
	}
	if resp.DBCluster.ReaderEndpoint != nil {
		cr.Status.AtProvider.ReaderEndpoint = resp.DBCluster.ReaderEndpoint
	} else {
		cr.Status.AtProvider.ReaderEndpoint = nil
	}
	if resp.DBCluster.ReplicationSourceIdentifier != nil {
		cr.Spec.ForProvider.ReplicationSourceIdentifier = resp.DBCluster.ReplicationSourceIdentifier
	} else {
		cr.Spec.ForProvider.ReplicationSourceIdentifier = nil
	}
	if resp.DBCluster.ServerlessV2ScalingConfiguration != nil {
		f40 := &svcapitypes.ServerlessV2ScalingConfiguration{}
		if resp.DBCluster.ServerlessV2ScalingConfiguration.MaxCapacity != nil {
			f40.MaxCapacity = resp.DBCluster.ServerlessV2ScalingConfiguration.MaxCapacity
		}
		if resp.DBCluster.ServerlessV2ScalingConfiguration.MinCapacity != nil {
			f40.MinCapacity = resp.DBCluster.ServerlessV2ScalingConfiguration.MinCapacity
		}
		cr.Spec.ForProvider.ServerlessV2ScalingConfiguration = f40
	} else {
		cr.Spec.ForProvider.ServerlessV2ScalingConfiguration = nil
	}
	if resp.DBCluster.Status != nil {
		cr.Status.AtProvider.Status = resp.DBCluster.Status
	} else {
		cr.Status.AtProvider.Status = nil
	}
	if resp.DBCluster.StorageEncrypted != nil {
		cr.Spec.ForProvider.StorageEncrypted = resp.DBCluster.StorageEncrypted
	} else {
		cr.Spec.ForProvider.StorageEncrypted = nil
	}
	if resp.DBCluster.StorageType != nil {
		cr.Spec.ForProvider.StorageType = resp.DBCluster.StorageType
	} else {
		cr.Spec.ForProvider.StorageType = nil
	}
	if resp.DBCluster.VpcSecurityGroups != nil {
		f44 := []*svcapitypes.VPCSecurityGroupMembership{}
		for _, f44iter := range resp.DBCluster.VpcSecurityGroups {
			f44elem := &svcapitypes.VPCSecurityGroupMembership{}
			if f44iter.Status != nil {
				f44elem.Status = f44iter.Status
			}
			if f44iter.VpcSecurityGroupId != nil {
				f44elem.VPCSecurityGroupID = f44iter.VpcSecurityGroupId
			}
			f44 = append(f44, f44elem)
		}
		cr.Status.AtProvider.VPCSecurityGroups = f44
	} else {
		cr.Status.AtProvider.VPCSecurityGroups = nil
	}

	return e.postCreate(ctx, cr, resp, managed.ExternalCreation{}, err)
}

func (e *external) Update(ctx context.Context, mg cpresource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*svcapitypes.DBCluster)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errUnexpectedObject)
	}
	input := GenerateModifyDBClusterInput(cr)
	if err := e.preUpdate(ctx, cr, input); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "pre-update failed")
	}
	resp, err := e.client.ModifyDBClusterWithContext(ctx, input)
	return e.postUpdate(ctx, cr, resp, managed.ExternalUpdate{}, errorutils.Wrap(err, errUpdate))
}

func (e *external) Delete(ctx context.Context, mg cpresource.Managed) error {
	cr, ok := mg.(*svcapitypes.DBCluster)
	if !ok {
		return errors.New(errUnexpectedObject)
	}
	cr.Status.SetConditions(xpv1.Deleting())
	input := GenerateDeleteDBClusterInput(cr)
	ignore, err := e.preDelete(ctx, cr, input)
	if err != nil {
		return errors.Wrap(err, "pre-delete failed")
	}
	if ignore {
		return nil
	}
	resp, err := e.client.DeleteDBClusterWithContext(ctx, input)
	return e.postDelete(ctx, cr, resp, errorutils.Wrap(cpresource.Ignore(IsNotFound, err), errDelete))
}

type option func(*external)

func newExternal(kube client.Client, client svcsdkapi.NeptuneAPI, opts []option) *external {
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
	client         svcsdkapi.NeptuneAPI
	preObserve     func(context.Context, *svcapitypes.DBCluster, *svcsdk.DescribeDBClustersInput) error
	postObserve    func(context.Context, *svcapitypes.DBCluster, *svcsdk.DescribeDBClustersOutput, managed.ExternalObservation, error) (managed.ExternalObservation, error)
	filterList     func(*svcapitypes.DBCluster, *svcsdk.DescribeDBClustersOutput) *svcsdk.DescribeDBClustersOutput
	lateInitialize func(*svcapitypes.DBClusterParameters, *svcsdk.DescribeDBClustersOutput) error
	isUpToDate     func(context.Context, *svcapitypes.DBCluster, *svcsdk.DescribeDBClustersOutput) (bool, string, error)
	preCreate      func(context.Context, *svcapitypes.DBCluster, *svcsdk.CreateDBClusterInput) error
	postCreate     func(context.Context, *svcapitypes.DBCluster, *svcsdk.CreateDBClusterOutput, managed.ExternalCreation, error) (managed.ExternalCreation, error)
	preDelete      func(context.Context, *svcapitypes.DBCluster, *svcsdk.DeleteDBClusterInput) (bool, error)
	postDelete     func(context.Context, *svcapitypes.DBCluster, *svcsdk.DeleteDBClusterOutput, error) error
	preUpdate      func(context.Context, *svcapitypes.DBCluster, *svcsdk.ModifyDBClusterInput) error
	postUpdate     func(context.Context, *svcapitypes.DBCluster, *svcsdk.ModifyDBClusterOutput, managed.ExternalUpdate, error) (managed.ExternalUpdate, error)
}

func nopPreObserve(context.Context, *svcapitypes.DBCluster, *svcsdk.DescribeDBClustersInput) error {
	return nil
}
func nopPostObserve(_ context.Context, _ *svcapitypes.DBCluster, _ *svcsdk.DescribeDBClustersOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	return obs, err
}
func nopFilterList(_ *svcapitypes.DBCluster, list *svcsdk.DescribeDBClustersOutput) *svcsdk.DescribeDBClustersOutput {
	return list
}

func nopLateInitialize(*svcapitypes.DBClusterParameters, *svcsdk.DescribeDBClustersOutput) error {
	return nil
}
func alwaysUpToDate(context.Context, *svcapitypes.DBCluster, *svcsdk.DescribeDBClustersOutput) (bool, string, error) {
	return true, "", nil
}

func nopPreCreate(context.Context, *svcapitypes.DBCluster, *svcsdk.CreateDBClusterInput) error {
	return nil
}
func nopPostCreate(_ context.Context, _ *svcapitypes.DBCluster, _ *svcsdk.CreateDBClusterOutput, cre managed.ExternalCreation, err error) (managed.ExternalCreation, error) {
	return cre, err
}
func nopPreDelete(context.Context, *svcapitypes.DBCluster, *svcsdk.DeleteDBClusterInput) (bool, error) {
	return false, nil
}
func nopPostDelete(_ context.Context, _ *svcapitypes.DBCluster, _ *svcsdk.DeleteDBClusterOutput, err error) error {
	return err
}
func nopPreUpdate(context.Context, *svcapitypes.DBCluster, *svcsdk.ModifyDBClusterInput) error {
	return nil
}
func nopPostUpdate(_ context.Context, _ *svcapitypes.DBCluster, _ *svcsdk.ModifyDBClusterOutput, upd managed.ExternalUpdate, err error) (managed.ExternalUpdate, error) {
	return upd, err
}
