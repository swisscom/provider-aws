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

package server

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/transfer"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/transfer/v1alpha1"
)

// NOTE(muvaf): We return pointers in case the function needs to start with an
// empty object, hence need to return a new pointer.

// GenerateDescribeServerInput returns input for read
// operation.
func GenerateDescribeServerInput(cr *svcapitypes.Server) *svcsdk.DescribeServerInput {
	res := &svcsdk.DescribeServerInput{}

	if cr.Status.AtProvider.ServerID != nil {
		res.SetServerId(*cr.Status.AtProvider.ServerID)
	}

	return res
}

// GenerateServer returns the current state in the form of *svcapitypes.Server.
func GenerateServer(resp *svcsdk.DescribeServerOutput) *svcapitypes.Server {
	cr := &svcapitypes.Server{}

	if resp.Server.Domain != nil {
		cr.Spec.ForProvider.Domain = resp.Server.Domain
	} else {
		cr.Spec.ForProvider.Domain = nil
	}
	if resp.Server.EndpointType != nil {
		cr.Spec.ForProvider.EndpointType = resp.Server.EndpointType
	} else {
		cr.Spec.ForProvider.EndpointType = nil
	}
	if resp.Server.IdentityProviderDetails != nil {
		f6 := &svcapitypes.IdentityProviderDetails{}
		if resp.Server.IdentityProviderDetails.DirectoryId != nil {
			f6.DirectoryID = resp.Server.IdentityProviderDetails.DirectoryId
		}
		if resp.Server.IdentityProviderDetails.Function != nil {
			f6.Function = resp.Server.IdentityProviderDetails.Function
		}
		if resp.Server.IdentityProviderDetails.InvocationRole != nil {
			f6.InvocationRole = resp.Server.IdentityProviderDetails.InvocationRole
		}
		if resp.Server.IdentityProviderDetails.SftpAuthenticationMethods != nil {
			f6.SftpAuthenticationMethods = resp.Server.IdentityProviderDetails.SftpAuthenticationMethods
		}
		if resp.Server.IdentityProviderDetails.Url != nil {
			f6.URL = resp.Server.IdentityProviderDetails.Url
		}
		cr.Spec.ForProvider.IdentityProviderDetails = f6
	} else {
		cr.Spec.ForProvider.IdentityProviderDetails = nil
	}
	if resp.Server.IdentityProviderType != nil {
		cr.Spec.ForProvider.IdentityProviderType = resp.Server.IdentityProviderType
	} else {
		cr.Spec.ForProvider.IdentityProviderType = nil
	}
	if resp.Server.PostAuthenticationLoginBanner != nil {
		cr.Spec.ForProvider.PostAuthenticationLoginBanner = resp.Server.PostAuthenticationLoginBanner
	} else {
		cr.Spec.ForProvider.PostAuthenticationLoginBanner = nil
	}
	if resp.Server.PreAuthenticationLoginBanner != nil {
		cr.Spec.ForProvider.PreAuthenticationLoginBanner = resp.Server.PreAuthenticationLoginBanner
	} else {
		cr.Spec.ForProvider.PreAuthenticationLoginBanner = nil
	}
	if resp.Server.ProtocolDetails != nil {
		f11 := &svcapitypes.ProtocolDetails{}
		if resp.Server.ProtocolDetails.As2Transports != nil {
			f11f0 := []*string{}
			for _, f11f0iter := range resp.Server.ProtocolDetails.As2Transports {
				var f11f0elem string
				f11f0elem = *f11f0iter
				f11f0 = append(f11f0, &f11f0elem)
			}
			f11.As2Transports = f11f0
		}
		if resp.Server.ProtocolDetails.PassiveIp != nil {
			f11.PassiveIP = resp.Server.ProtocolDetails.PassiveIp
		}
		if resp.Server.ProtocolDetails.SetStatOption != nil {
			f11.SetStatOption = resp.Server.ProtocolDetails.SetStatOption
		}
		if resp.Server.ProtocolDetails.TlsSessionResumptionMode != nil {
			f11.TLSSessionResumptionMode = resp.Server.ProtocolDetails.TlsSessionResumptionMode
		}
		cr.Spec.ForProvider.ProtocolDetails = f11
	} else {
		cr.Spec.ForProvider.ProtocolDetails = nil
	}
	if resp.Server.Protocols != nil {
		f12 := []*string{}
		for _, f12iter := range resp.Server.Protocols {
			var f12elem string
			f12elem = *f12iter
			f12 = append(f12, &f12elem)
		}
		cr.Spec.ForProvider.Protocols = f12
	} else {
		cr.Spec.ForProvider.Protocols = nil
	}
	if resp.Server.S3StorageOptions != nil {
		f13 := &svcapitypes.S3StorageOptions{}
		if resp.Server.S3StorageOptions.DirectoryListingOptimization != nil {
			f13.DirectoryListingOptimization = resp.Server.S3StorageOptions.DirectoryListingOptimization
		}
		cr.Spec.ForProvider.S3StorageOptions = f13
	} else {
		cr.Spec.ForProvider.S3StorageOptions = nil
	}
	if resp.Server.SecurityPolicyName != nil {
		cr.Spec.ForProvider.SecurityPolicyName = resp.Server.SecurityPolicyName
	} else {
		cr.Spec.ForProvider.SecurityPolicyName = nil
	}
	if resp.Server.ServerId != nil {
		cr.Status.AtProvider.ServerID = resp.Server.ServerId
	} else {
		cr.Status.AtProvider.ServerID = nil
	}
	if resp.Server.StructuredLogDestinations != nil {
		f17 := []*string{}
		for _, f17iter := range resp.Server.StructuredLogDestinations {
			var f17elem string
			f17elem = *f17iter
			f17 = append(f17, &f17elem)
		}
		cr.Spec.ForProvider.StructuredLogDestinations = f17
	} else {
		cr.Spec.ForProvider.StructuredLogDestinations = nil
	}
	if resp.Server.Tags != nil {
		f18 := []*svcapitypes.Tag{}
		for _, f18iter := range resp.Server.Tags {
			f18elem := &svcapitypes.Tag{}
			if f18iter.Key != nil {
				f18elem.Key = f18iter.Key
			}
			if f18iter.Value != nil {
				f18elem.Value = f18iter.Value
			}
			f18 = append(f18, f18elem)
		}
		cr.Spec.ForProvider.Tags = f18
	} else {
		cr.Spec.ForProvider.Tags = nil
	}
	if resp.Server.WorkflowDetails != nil {
		f20 := &svcapitypes.WorkflowDetails{}
		if resp.Server.WorkflowDetails.OnPartialUpload != nil {
			f20f0 := []*svcapitypes.WorkflowDetail{}
			for _, f20f0iter := range resp.Server.WorkflowDetails.OnPartialUpload {
				f20f0elem := &svcapitypes.WorkflowDetail{}
				if f20f0iter.ExecutionRole != nil {
					f20f0elem.ExecutionRole = f20f0iter.ExecutionRole
				}
				if f20f0iter.WorkflowId != nil {
					f20f0elem.WorkflowID = f20f0iter.WorkflowId
				}
				f20f0 = append(f20f0, f20f0elem)
			}
			f20.OnPartialUpload = f20f0
		}
		if resp.Server.WorkflowDetails.OnUpload != nil {
			f20f1 := []*svcapitypes.WorkflowDetail{}
			for _, f20f1iter := range resp.Server.WorkflowDetails.OnUpload {
				f20f1elem := &svcapitypes.WorkflowDetail{}
				if f20f1iter.ExecutionRole != nil {
					f20f1elem.ExecutionRole = f20f1iter.ExecutionRole
				}
				if f20f1iter.WorkflowId != nil {
					f20f1elem.WorkflowID = f20f1iter.WorkflowId
				}
				f20f1 = append(f20f1, f20f1elem)
			}
			f20.OnUpload = f20f1
		}
		cr.Spec.ForProvider.WorkflowDetails = f20
	} else {
		cr.Spec.ForProvider.WorkflowDetails = nil
	}

	return cr
}

// GenerateCreateServerInput returns a create input.
func GenerateCreateServerInput(cr *svcapitypes.Server) *svcsdk.CreateServerInput {
	res := &svcsdk.CreateServerInput{}

	if cr.Spec.ForProvider.Domain != nil {
		res.SetDomain(*cr.Spec.ForProvider.Domain)
	}
	if cr.Spec.ForProvider.EndpointType != nil {
		res.SetEndpointType(*cr.Spec.ForProvider.EndpointType)
	}
	if cr.Spec.ForProvider.HostKey != nil {
		res.SetHostKey(*cr.Spec.ForProvider.HostKey)
	}
	if cr.Spec.ForProvider.IdentityProviderDetails != nil {
		f3 := &svcsdk.IdentityProviderDetails{}
		if cr.Spec.ForProvider.IdentityProviderDetails.DirectoryID != nil {
			f3.SetDirectoryId(*cr.Spec.ForProvider.IdentityProviderDetails.DirectoryID)
		}
		if cr.Spec.ForProvider.IdentityProviderDetails.Function != nil {
			f3.SetFunction(*cr.Spec.ForProvider.IdentityProviderDetails.Function)
		}
		if cr.Spec.ForProvider.IdentityProviderDetails.InvocationRole != nil {
			f3.SetInvocationRole(*cr.Spec.ForProvider.IdentityProviderDetails.InvocationRole)
		}
		if cr.Spec.ForProvider.IdentityProviderDetails.SftpAuthenticationMethods != nil {
			f3.SetSftpAuthenticationMethods(*cr.Spec.ForProvider.IdentityProviderDetails.SftpAuthenticationMethods)
		}
		if cr.Spec.ForProvider.IdentityProviderDetails.URL != nil {
			f3.SetUrl(*cr.Spec.ForProvider.IdentityProviderDetails.URL)
		}
		res.SetIdentityProviderDetails(f3)
	}
	if cr.Spec.ForProvider.IdentityProviderType != nil {
		res.SetIdentityProviderType(*cr.Spec.ForProvider.IdentityProviderType)
	}
	if cr.Spec.ForProvider.PostAuthenticationLoginBanner != nil {
		res.SetPostAuthenticationLoginBanner(*cr.Spec.ForProvider.PostAuthenticationLoginBanner)
	}
	if cr.Spec.ForProvider.PreAuthenticationLoginBanner != nil {
		res.SetPreAuthenticationLoginBanner(*cr.Spec.ForProvider.PreAuthenticationLoginBanner)
	}
	if cr.Spec.ForProvider.ProtocolDetails != nil {
		f7 := &svcsdk.ProtocolDetails{}
		if cr.Spec.ForProvider.ProtocolDetails.As2Transports != nil {
			f7f0 := []*string{}
			for _, f7f0iter := range cr.Spec.ForProvider.ProtocolDetails.As2Transports {
				var f7f0elem string
				f7f0elem = *f7f0iter
				f7f0 = append(f7f0, &f7f0elem)
			}
			f7.SetAs2Transports(f7f0)
		}
		if cr.Spec.ForProvider.ProtocolDetails.PassiveIP != nil {
			f7.SetPassiveIp(*cr.Spec.ForProvider.ProtocolDetails.PassiveIP)
		}
		if cr.Spec.ForProvider.ProtocolDetails.SetStatOption != nil {
			f7.SetSetStatOption(*cr.Spec.ForProvider.ProtocolDetails.SetStatOption)
		}
		if cr.Spec.ForProvider.ProtocolDetails.TLSSessionResumptionMode != nil {
			f7.SetTlsSessionResumptionMode(*cr.Spec.ForProvider.ProtocolDetails.TLSSessionResumptionMode)
		}
		res.SetProtocolDetails(f7)
	}
	if cr.Spec.ForProvider.Protocols != nil {
		f8 := []*string{}
		for _, f8iter := range cr.Spec.ForProvider.Protocols {
			var f8elem string
			f8elem = *f8iter
			f8 = append(f8, &f8elem)
		}
		res.SetProtocols(f8)
	}
	if cr.Spec.ForProvider.S3StorageOptions != nil {
		f9 := &svcsdk.S3StorageOptions{}
		if cr.Spec.ForProvider.S3StorageOptions.DirectoryListingOptimization != nil {
			f9.SetDirectoryListingOptimization(*cr.Spec.ForProvider.S3StorageOptions.DirectoryListingOptimization)
		}
		res.SetS3StorageOptions(f9)
	}
	if cr.Spec.ForProvider.SecurityPolicyName != nil {
		res.SetSecurityPolicyName(*cr.Spec.ForProvider.SecurityPolicyName)
	}
	if cr.Spec.ForProvider.StructuredLogDestinations != nil {
		f11 := []*string{}
		for _, f11iter := range cr.Spec.ForProvider.StructuredLogDestinations {
			var f11elem string
			f11elem = *f11iter
			f11 = append(f11, &f11elem)
		}
		res.SetStructuredLogDestinations(f11)
	}
	if cr.Spec.ForProvider.Tags != nil {
		f12 := []*svcsdk.Tag{}
		for _, f12iter := range cr.Spec.ForProvider.Tags {
			f12elem := &svcsdk.Tag{}
			if f12iter.Key != nil {
				f12elem.SetKey(*f12iter.Key)
			}
			if f12iter.Value != nil {
				f12elem.SetValue(*f12iter.Value)
			}
			f12 = append(f12, f12elem)
		}
		res.SetTags(f12)
	}
	if cr.Spec.ForProvider.WorkflowDetails != nil {
		f13 := &svcsdk.WorkflowDetails{}
		if cr.Spec.ForProvider.WorkflowDetails.OnPartialUpload != nil {
			f13f0 := []*svcsdk.WorkflowDetail{}
			for _, f13f0iter := range cr.Spec.ForProvider.WorkflowDetails.OnPartialUpload {
				f13f0elem := &svcsdk.WorkflowDetail{}
				if f13f0iter.ExecutionRole != nil {
					f13f0elem.SetExecutionRole(*f13f0iter.ExecutionRole)
				}
				if f13f0iter.WorkflowID != nil {
					f13f0elem.SetWorkflowId(*f13f0iter.WorkflowID)
				}
				f13f0 = append(f13f0, f13f0elem)
			}
			f13.SetOnPartialUpload(f13f0)
		}
		if cr.Spec.ForProvider.WorkflowDetails.OnUpload != nil {
			f13f1 := []*svcsdk.WorkflowDetail{}
			for _, f13f1iter := range cr.Spec.ForProvider.WorkflowDetails.OnUpload {
				f13f1elem := &svcsdk.WorkflowDetail{}
				if f13f1iter.ExecutionRole != nil {
					f13f1elem.SetExecutionRole(*f13f1iter.ExecutionRole)
				}
				if f13f1iter.WorkflowID != nil {
					f13f1elem.SetWorkflowId(*f13f1iter.WorkflowID)
				}
				f13f1 = append(f13f1, f13f1elem)
			}
			f13.SetOnUpload(f13f1)
		}
		res.SetWorkflowDetails(f13)
	}

	return res
}

// GenerateUpdateServerInput returns an update input.
func GenerateUpdateServerInput(cr *svcapitypes.Server) *svcsdk.UpdateServerInput {
	res := &svcsdk.UpdateServerInput{}

	if cr.Spec.ForProvider.EndpointType != nil {
		res.SetEndpointType(*cr.Spec.ForProvider.EndpointType)
	}
	if cr.Spec.ForProvider.HostKey != nil {
		res.SetHostKey(*cr.Spec.ForProvider.HostKey)
	}
	if cr.Spec.ForProvider.IdentityProviderDetails != nil {
		f4 := &svcsdk.IdentityProviderDetails{}
		if cr.Spec.ForProvider.IdentityProviderDetails.DirectoryID != nil {
			f4.SetDirectoryId(*cr.Spec.ForProvider.IdentityProviderDetails.DirectoryID)
		}
		if cr.Spec.ForProvider.IdentityProviderDetails.Function != nil {
			f4.SetFunction(*cr.Spec.ForProvider.IdentityProviderDetails.Function)
		}
		if cr.Spec.ForProvider.IdentityProviderDetails.InvocationRole != nil {
			f4.SetInvocationRole(*cr.Spec.ForProvider.IdentityProviderDetails.InvocationRole)
		}
		if cr.Spec.ForProvider.IdentityProviderDetails.SftpAuthenticationMethods != nil {
			f4.SetSftpAuthenticationMethods(*cr.Spec.ForProvider.IdentityProviderDetails.SftpAuthenticationMethods)
		}
		if cr.Spec.ForProvider.IdentityProviderDetails.URL != nil {
			f4.SetUrl(*cr.Spec.ForProvider.IdentityProviderDetails.URL)
		}
		res.SetIdentityProviderDetails(f4)
	}
	if cr.Spec.ForProvider.PostAuthenticationLoginBanner != nil {
		res.SetPostAuthenticationLoginBanner(*cr.Spec.ForProvider.PostAuthenticationLoginBanner)
	}
	if cr.Spec.ForProvider.PreAuthenticationLoginBanner != nil {
		res.SetPreAuthenticationLoginBanner(*cr.Spec.ForProvider.PreAuthenticationLoginBanner)
	}
	if cr.Spec.ForProvider.ProtocolDetails != nil {
		f8 := &svcsdk.ProtocolDetails{}
		if cr.Spec.ForProvider.ProtocolDetails.As2Transports != nil {
			f8f0 := []*string{}
			for _, f8f0iter := range cr.Spec.ForProvider.ProtocolDetails.As2Transports {
				var f8f0elem string
				f8f0elem = *f8f0iter
				f8f0 = append(f8f0, &f8f0elem)
			}
			f8.SetAs2Transports(f8f0)
		}
		if cr.Spec.ForProvider.ProtocolDetails.PassiveIP != nil {
			f8.SetPassiveIp(*cr.Spec.ForProvider.ProtocolDetails.PassiveIP)
		}
		if cr.Spec.ForProvider.ProtocolDetails.SetStatOption != nil {
			f8.SetSetStatOption(*cr.Spec.ForProvider.ProtocolDetails.SetStatOption)
		}
		if cr.Spec.ForProvider.ProtocolDetails.TLSSessionResumptionMode != nil {
			f8.SetTlsSessionResumptionMode(*cr.Spec.ForProvider.ProtocolDetails.TLSSessionResumptionMode)
		}
		res.SetProtocolDetails(f8)
	}
	if cr.Spec.ForProvider.Protocols != nil {
		f9 := []*string{}
		for _, f9iter := range cr.Spec.ForProvider.Protocols {
			var f9elem string
			f9elem = *f9iter
			f9 = append(f9, &f9elem)
		}
		res.SetProtocols(f9)
	}
	if cr.Spec.ForProvider.S3StorageOptions != nil {
		f10 := &svcsdk.S3StorageOptions{}
		if cr.Spec.ForProvider.S3StorageOptions.DirectoryListingOptimization != nil {
			f10.SetDirectoryListingOptimization(*cr.Spec.ForProvider.S3StorageOptions.DirectoryListingOptimization)
		}
		res.SetS3StorageOptions(f10)
	}
	if cr.Spec.ForProvider.SecurityPolicyName != nil {
		res.SetSecurityPolicyName(*cr.Spec.ForProvider.SecurityPolicyName)
	}
	if cr.Status.AtProvider.ServerID != nil {
		res.SetServerId(*cr.Status.AtProvider.ServerID)
	}
	if cr.Spec.ForProvider.StructuredLogDestinations != nil {
		f13 := []*string{}
		for _, f13iter := range cr.Spec.ForProvider.StructuredLogDestinations {
			var f13elem string
			f13elem = *f13iter
			f13 = append(f13, &f13elem)
		}
		res.SetStructuredLogDestinations(f13)
	}
	if cr.Spec.ForProvider.WorkflowDetails != nil {
		f14 := &svcsdk.WorkflowDetails{}
		if cr.Spec.ForProvider.WorkflowDetails.OnPartialUpload != nil {
			f14f0 := []*svcsdk.WorkflowDetail{}
			for _, f14f0iter := range cr.Spec.ForProvider.WorkflowDetails.OnPartialUpload {
				f14f0elem := &svcsdk.WorkflowDetail{}
				if f14f0iter.ExecutionRole != nil {
					f14f0elem.SetExecutionRole(*f14f0iter.ExecutionRole)
				}
				if f14f0iter.WorkflowID != nil {
					f14f0elem.SetWorkflowId(*f14f0iter.WorkflowID)
				}
				f14f0 = append(f14f0, f14f0elem)
			}
			f14.SetOnPartialUpload(f14f0)
		}
		if cr.Spec.ForProvider.WorkflowDetails.OnUpload != nil {
			f14f1 := []*svcsdk.WorkflowDetail{}
			for _, f14f1iter := range cr.Spec.ForProvider.WorkflowDetails.OnUpload {
				f14f1elem := &svcsdk.WorkflowDetail{}
				if f14f1iter.ExecutionRole != nil {
					f14f1elem.SetExecutionRole(*f14f1iter.ExecutionRole)
				}
				if f14f1iter.WorkflowID != nil {
					f14f1elem.SetWorkflowId(*f14f1iter.WorkflowID)
				}
				f14f1 = append(f14f1, f14f1elem)
			}
			f14.SetOnUpload(f14f1)
		}
		res.SetWorkflowDetails(f14)
	}

	return res
}

// GenerateDeleteServerInput returns a deletion input.
func GenerateDeleteServerInput(cr *svcapitypes.Server) *svcsdk.DeleteServerInput {
	res := &svcsdk.DeleteServerInput{}

	if cr.Status.AtProvider.ServerID != nil {
		res.SetServerId(*cr.Status.AtProvider.ServerID)
	}

	return res
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "ResourceNotFoundException"
}
