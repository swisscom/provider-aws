package dbinstance

import (
	"context"
	"github.com/aws/aws-sdk-go/aws/request"
	svcsdk "github.com/aws/aws-sdk-go/service/rds"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"sigs.k8s.io/controller-runtime/pkg/client"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"
	"github.com/crossplane-contrib/provider-aws/pkg/clients/rds/fake"
)

func TestCreate(t *testing.T) {
	type args struct {
		cr           *svcapitypes.DBInstance
		kube         client.Client
		awsRDSClient fake.MockRDSClient
	}

	type want struct {
		statusAtProvider *svcapitypes.CustomDBInstanceObservation
		err              error
	}

	cases := map[string]struct {
		args
		want
	}{
		"CreateReadReplica": {
			args: args{
				cr: &svcapitypes.DBInstance{
					Spec: svcapitypes.DBInstanceSpec{
						ForProvider: svcapitypes.DBInstanceParameters{
							CustomDBInstanceParameters: svcapitypes.CustomDBInstanceParameters{
								ReplicateSourceDBInstanceID: aws.String("source-db-instance-id"),
							},
						},
					},
				},
				kube: test.NewMockClient(),
				awsRDSClient: fake.MockRDSClient{
					MockCreateDBInstanceReadReplicaWithContext: func(ctx context.Context, input *svcsdk.CreateDBInstanceReadReplicaInput, optFns ...request.Option) (*svcsdk.CreateDBInstanceReadReplicaOutput, error) {
						return &svcsdk.CreateDBInstanceReadReplicaOutput{}, nil
					},
					MockCreateDBInstanceWithContext: func(ctx context.Context, input *svcsdk.CreateDBInstanceInput, optFns ...request.Option) (*svcsdk.CreateDBInstanceOutput, error) {
						return &svcsdk.CreateDBInstanceOutput{}, nil
					},
				},
			},
			want: want{
				statusAtProvider: &svcapitypes.CustomDBInstanceObservation{
					DatabaseRole: aws.String(databaseRoleReadReplica),
				},
			},
		},
		"CreateStandaloneInstance": {
			args: args{
				cr: &svcapitypes.DBInstance{
					Spec: svcapitypes.DBInstanceSpec{
						ForProvider: svcapitypes.DBInstanceParameters{
							CustomDBInstanceParameters: svcapitypes.CustomDBInstanceParameters{
								AutogeneratePassword: true,
							},
						},
					},
					Status: svcapitypes.DBInstanceStatus{
						AtProvider: svcapitypes.DBInstanceObservation{},
					},
				},
				kube: test.NewMockClient(),
				awsRDSClient: fake.MockRDSClient{
					MockCreateDBInstanceWithContext: func(ctx context.Context, input *svcsdk.CreateDBInstanceInput, optFns ...request.Option) (*svcsdk.CreateDBInstanceOutput, error) {
						return &svcsdk.CreateDBInstanceOutput{DBInstance: &svcsdk.DBInstance{}}, nil
					},
					MockCreateDBInstanceReadReplicaWithContext: func(ctx context.Context, input *svcsdk.CreateDBInstanceReadReplicaInput, optFns ...request.Option) (*svcsdk.CreateDBInstanceReadReplicaOutput, error) {
						return &svcsdk.CreateDBInstanceReadReplicaOutput{}, nil
					},
				},
			},
			want: want{
				statusAtProvider: &svcapitypes.CustomDBInstanceObservation{
					DatabaseRole: aws.String(databaseRolePrimary),
				},
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cr := tc.args.cr

			// Create a new DBInstance
			ce := newCustomExternal(tc.kube, &tc.awsRDSClient)
			_, err := ce.Create(context.TODO(), cr)
			if diff := cmp.Diff(tc.want.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("r: -want, +got error: \n%s", diff)
			}
			if diff := cmp.Diff(tc.want.statusAtProvider.DatabaseRole, cr.Status.AtProvider.DatabaseRole); diff != "" {
				t.Errorf("r: -want, +got: \n%s", diff)
			}
		})
	}
}
