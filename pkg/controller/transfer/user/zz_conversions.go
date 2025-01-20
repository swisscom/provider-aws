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

package user

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/transfer"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/transfer/v1alpha1"
)

// NOTE(muvaf): We return pointers in case the function needs to start with an
// empty object, hence need to return a new pointer.

// GenerateDescribeUserInput returns input for read
// operation.
func GenerateDescribeUserInput(cr *svcapitypes.User) *svcsdk.DescribeUserInput {
	res := &svcsdk.DescribeUserInput{}

	if cr.Status.AtProvider.ServerID != nil {
		res.SetServerId(*cr.Status.AtProvider.ServerID)
	}
	if cr.Status.AtProvider.UserName != nil {
		res.SetUserName(*cr.Status.AtProvider.UserName)
	}

	return res
}

// GenerateUser returns the current state in the form of *svcapitypes.User.
func GenerateUser(resp *svcsdk.DescribeUserOutput) *svcapitypes.User {
	cr := &svcapitypes.User{}

	if resp.ServerId != nil {
		cr.Status.AtProvider.ServerID = resp.ServerId
	} else {
		cr.Status.AtProvider.ServerID = nil
	}

	return cr
}

// GenerateCreateUserInput returns a create input.
func GenerateCreateUserInput(cr *svcapitypes.User) *svcsdk.CreateUserInput {
	res := &svcsdk.CreateUserInput{}

	if cr.Spec.ForProvider.HomeDirectory != nil {
		res.SetHomeDirectory(*cr.Spec.ForProvider.HomeDirectory)
	}
	if cr.Spec.ForProvider.HomeDirectoryMappings != nil {
		f1 := []*svcsdk.HomeDirectoryMapEntry{}
		for _, f1iter := range cr.Spec.ForProvider.HomeDirectoryMappings {
			f1elem := &svcsdk.HomeDirectoryMapEntry{}
			if f1iter.Entry != nil {
				f1elem.SetEntry(*f1iter.Entry)
			}
			if f1iter.Target != nil {
				f1elem.SetTarget(*f1iter.Target)
			}
			if f1iter.Type != nil {
				f1elem.SetType(*f1iter.Type)
			}
			f1 = append(f1, f1elem)
		}
		res.SetHomeDirectoryMappings(f1)
	}
	if cr.Spec.ForProvider.HomeDirectoryType != nil {
		res.SetHomeDirectoryType(*cr.Spec.ForProvider.HomeDirectoryType)
	}
	if cr.Spec.ForProvider.Policy != nil {
		res.SetPolicy(*cr.Spec.ForProvider.Policy)
	}
	if cr.Spec.ForProvider.PosixProfile != nil {
		f4 := &svcsdk.PosixProfile{}
		if cr.Spec.ForProvider.PosixProfile.GID != nil {
			f4.SetGid(*cr.Spec.ForProvider.PosixProfile.GID)
		}
		if cr.Spec.ForProvider.PosixProfile.SecondaryGIDs != nil {
			f4f1 := []*int64{}
			for _, f4f1iter := range cr.Spec.ForProvider.PosixProfile.SecondaryGIDs {
				var f4f1elem int64
				f4f1elem = *f4f1iter
				f4f1 = append(f4f1, &f4f1elem)
			}
			f4.SetSecondaryGids(f4f1)
		}
		if cr.Spec.ForProvider.PosixProfile.UID != nil {
			f4.SetUid(*cr.Spec.ForProvider.PosixProfile.UID)
		}
		res.SetPosixProfile(f4)
	}
	if cr.Spec.ForProvider.Tags != nil {
		f5 := []*svcsdk.Tag{}
		for _, f5iter := range cr.Spec.ForProvider.Tags {
			f5elem := &svcsdk.Tag{}
			if f5iter.Key != nil {
				f5elem.SetKey(*f5iter.Key)
			}
			if f5iter.Value != nil {
				f5elem.SetValue(*f5iter.Value)
			}
			f5 = append(f5, f5elem)
		}
		res.SetTags(f5)
	}

	return res
}

// GenerateUpdateUserInput returns an update input.
func GenerateUpdateUserInput(cr *svcapitypes.User) *svcsdk.UpdateUserInput {
	res := &svcsdk.UpdateUserInput{}

	if cr.Spec.ForProvider.HomeDirectory != nil {
		res.SetHomeDirectory(*cr.Spec.ForProvider.HomeDirectory)
	}
	if cr.Spec.ForProvider.HomeDirectoryMappings != nil {
		f1 := []*svcsdk.HomeDirectoryMapEntry{}
		for _, f1iter := range cr.Spec.ForProvider.HomeDirectoryMappings {
			f1elem := &svcsdk.HomeDirectoryMapEntry{}
			if f1iter.Entry != nil {
				f1elem.SetEntry(*f1iter.Entry)
			}
			if f1iter.Target != nil {
				f1elem.SetTarget(*f1iter.Target)
			}
			if f1iter.Type != nil {
				f1elem.SetType(*f1iter.Type)
			}
			f1 = append(f1, f1elem)
		}
		res.SetHomeDirectoryMappings(f1)
	}
	if cr.Spec.ForProvider.HomeDirectoryType != nil {
		res.SetHomeDirectoryType(*cr.Spec.ForProvider.HomeDirectoryType)
	}
	if cr.Spec.ForProvider.Policy != nil {
		res.SetPolicy(*cr.Spec.ForProvider.Policy)
	}
	if cr.Spec.ForProvider.PosixProfile != nil {
		f4 := &svcsdk.PosixProfile{}
		if cr.Spec.ForProvider.PosixProfile.GID != nil {
			f4.SetGid(*cr.Spec.ForProvider.PosixProfile.GID)
		}
		if cr.Spec.ForProvider.PosixProfile.SecondaryGIDs != nil {
			f4f1 := []*int64{}
			for _, f4f1iter := range cr.Spec.ForProvider.PosixProfile.SecondaryGIDs {
				var f4f1elem int64
				f4f1elem = *f4f1iter
				f4f1 = append(f4f1, &f4f1elem)
			}
			f4.SetSecondaryGids(f4f1)
		}
		if cr.Spec.ForProvider.PosixProfile.UID != nil {
			f4.SetUid(*cr.Spec.ForProvider.PosixProfile.UID)
		}
		res.SetPosixProfile(f4)
	}
	if cr.Status.AtProvider.ServerID != nil {
		res.SetServerId(*cr.Status.AtProvider.ServerID)
	}
	if cr.Status.AtProvider.UserName != nil {
		res.SetUserName(*cr.Status.AtProvider.UserName)
	}

	return res
}

// GenerateDeleteUserInput returns a deletion input.
func GenerateDeleteUserInput(cr *svcapitypes.User) *svcsdk.DeleteUserInput {
	res := &svcsdk.DeleteUserInput{}

	if cr.Status.AtProvider.ServerID != nil {
		res.SetServerId(*cr.Status.AtProvider.ServerID)
	}
	if cr.Status.AtProvider.UserName != nil {
		res.SetUserName(*cr.Status.AtProvider.UserName)
	}

	return res
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "ResourceNotFoundException"
}
