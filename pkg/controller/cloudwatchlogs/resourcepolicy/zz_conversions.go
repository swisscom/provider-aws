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

package resourcepolicy

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/cloudwatchlogs"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/cloudwatchlogs/v1alpha1"
)

// NOTE(muvaf): We return pointers in case the function needs to start with an
// empty object, hence need to return a new pointer.

// GeneratePutResourcePolicyInput returns a create input.
func GeneratePutResourcePolicyInput(cr *svcapitypes.ResourcePolicy) *svcsdk.PutResourcePolicyInput {
	res := &svcsdk.PutResourcePolicyInput{}

	if cr.Spec.ForProvider.PolicyDocument != nil {
		res.SetPolicyDocument(*cr.Spec.ForProvider.PolicyDocument)
	}

	return res
}

// GenerateDeleteResourcePolicyInput returns a deletion input.
func GenerateDeleteResourcePolicyInput(cr *svcapitypes.ResourcePolicy) *svcsdk.DeleteResourcePolicyInput {
	res := &svcsdk.DeleteResourcePolicyInput{}

	return res
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "ResourceNotFoundException"
}
