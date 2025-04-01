/*
Copyright 2025 The Crossplane Authors.

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

package bucket

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/google/go-cmp/cmp"

	"github.com/crossplane-contrib/provider-aws/apis/s3/v1beta1"
	"github.com/crossplane-contrib/provider-aws/pkg/clients/s3"
	errorutils "github.com/crossplane-contrib/provider-aws/pkg/utils/errors"
	"github.com/crossplane-contrib/provider-aws/pkg/utils/pointer"
)

const (
	//	msgCallerIdentityGetFailed          = "cannot get caller identity"
	msgObjectLockConfigurationGetFailed = "cannot get Object Lock configuration"
	msgObjectLockConfigurationPutFailed = "cannot put Object Lock configuration"
)

type objectLockConfigurationCache struct {
	getObjectLockConfigurationOutput *awss3.GetObjectLockConfigurationOutput
}

// ObjectLockConfigurationClient is the client for API methods and reconciling the ObjectLockConfiguration
type ObjectLockConfigurationClient struct {
	client s3.BucketClient
	cache  objectLockConfigurationCache
}

// NewObjectLockConfigurationClient creates the client for Object Lock Configuration
func NewObjectLockConfigurationClient(client s3.BucketClient) *ObjectLockConfigurationClient {
	return &ObjectLockConfigurationClient{client: client}
}

// Observe checks if the resource exists and if it matches the local configuration
func (in *ObjectLockConfigurationClient) Observe(ctx context.Context, cr *v1beta1.Bucket) (ResourceStatus, error) {
	//	ci, err := in.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	//if err != nil {
	//	cr.SetConditions(xpv1.Unavailable().WithMessage(msgCallerIdentityGetFailed))
	//	return Updated, errorutils.Wrap(err, msgCallerIdentityGetFailed)
	//}
	response, err := in.client.GetObjectLockConfiguration(ctx, &awss3.GetObjectLockConfigurationInput{
		Bucket: pointer.ToOrNilIfZeroValue(meta.GetExternalName(cr)),
		//		ExpectedBucketOwner: ci.Account,
	})
	in.cache.getObjectLockConfigurationOutput = response
	//	in.cache.expectedBucketOwner = ci.Account
	if err != nil {
		cr.SetConditions(xpv1.Available().WithMessage(msgObjectLockConfigurationGetFailed))
		return Updated, errorutils.Wrap(err, msgObjectLockConfigurationGetFailed)
	}
	if !cmp.Equal(GenerateAWSObjectLockConfiguration(&cr.Spec.ForProvider), response.ObjectLockConfiguration) {
		return NeedsUpdate, nil
	}
	return Updated, nil
}

// CreateOrUpdate uses unified aws sdk call to create or update or delete Object Lock Configuration
func (in *ObjectLockConfigurationClient) CreateOrUpdate(ctx context.Context, cr *v1beta1.Bucket) error {
	if cr.Spec.ForProvider.ObjectLockEnabledForBucket == nil {
		return nil
	}
	input := &awss3.PutObjectLockConfigurationInput{
		Bucket:                  aws.String(meta.GetExternalName(cr)),
		ObjectLockConfiguration: GenerateAWSObjectLockConfiguration(&cr.Spec.ForProvider),
	}
	_, err := in.client.PutObjectLockConfiguration(ctx, input)
	if err != nil {
		cr.SetConditions(xpv1.ReconcileError(err).WithMessage(msgObjectLockConfigurationPutFailed))
		return errorutils.Wrap(err, msgObjectLockConfigurationPutFailed)
	}
	return nil
}

// Delete does nothing because there is no deletion call for Object Lock configuration.
func (in *ObjectLockConfigurationClient) Delete(_ context.Context, _ *v1beta1.Bucket) error {
	return nil
}

func (in *ObjectLockConfigurationClient) LateInitialize(_ context.Context, cr *v1beta1.Bucket) error {
	if cr.Spec.ForProvider.ObjectLockEnabledForBucket == nil && in.cache.getObjectLockConfigurationOutput != nil {
		objectLockEnabledForBucketValue := false
		if in.cache.getObjectLockConfigurationOutput.ObjectLockConfiguration.ObjectLockEnabled == "Enabled" {
			objectLockEnabledForBucketValue = true
		}
		cr.Spec.ForProvider.ObjectLockEnabledForBucket = &objectLockEnabledForBucketValue
	}
	return nil
}

func GenerateAWSObjectLockConfiguration(in *v1beta1.BucketParameters) *types.ObjectLockConfiguration {
	if in == nil {
		return nil
	}
	objectLockEnabledValue := "Disabled"
	if in.ObjectLockEnabledForBucket != nil && *in.ObjectLockEnabledForBucket == true {
		objectLockEnabledValue = "Enabled"
	}
	return &types.ObjectLockConfiguration{ObjectLockEnabled: types.ObjectLockEnabled(objectLockEnabledValue)}
}
