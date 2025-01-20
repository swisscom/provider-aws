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
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/apigateway"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/apigateway/v1alpha1"
)

// NOTE(muvaf): We return pointers in case the function needs to start with an
// empty object, hence need to return a new pointer.

// GenerateGetStageInput returns input for read
// operation.
func GenerateGetStageInput(cr *svcapitypes.Stage) *svcsdk.GetStageInput {
	res := &svcsdk.GetStageInput{}

	if cr.Spec.ForProvider.StageName != nil {
		res.SetStageName(*cr.Spec.ForProvider.StageName)
	}

	return res
}

// GenerateStage returns the current state in the form of *svcapitypes.Stage.
func GenerateStage(resp *svcsdk.Stage) *svcapitypes.Stage {
	cr := &svcapitypes.Stage{}

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

	return cr
}

// GenerateCreateStageInput returns a create input.
func GenerateCreateStageInput(cr *svcapitypes.Stage) *svcsdk.CreateStageInput {
	res := &svcsdk.CreateStageInput{}

	if cr.Spec.ForProvider.CacheClusterEnabled != nil {
		res.SetCacheClusterEnabled(*cr.Spec.ForProvider.CacheClusterEnabled)
	}
	if cr.Spec.ForProvider.CacheClusterSize != nil {
		res.SetCacheClusterSize(*cr.Spec.ForProvider.CacheClusterSize)
	}
	if cr.Spec.ForProvider.Description != nil {
		res.SetDescription(*cr.Spec.ForProvider.Description)
	}
	if cr.Spec.ForProvider.DocumentationVersion != nil {
		res.SetDocumentationVersion(*cr.Spec.ForProvider.DocumentationVersion)
	}
	if cr.Spec.ForProvider.StageName != nil {
		res.SetStageName(*cr.Spec.ForProvider.StageName)
	}
	if cr.Spec.ForProvider.Tags != nil {
		f5 := map[string]*string{}
		for f5key, f5valiter := range cr.Spec.ForProvider.Tags {
			var f5val string
			f5val = *f5valiter
			f5[f5key] = &f5val
		}
		res.SetTags(f5)
	}
	if cr.Spec.ForProvider.TracingEnabled != nil {
		res.SetTracingEnabled(*cr.Spec.ForProvider.TracingEnabled)
	}
	if cr.Spec.ForProvider.Variables != nil {
		f7 := map[string]*string{}
		for f7key, f7valiter := range cr.Spec.ForProvider.Variables {
			var f7val string
			f7val = *f7valiter
			f7[f7key] = &f7val
		}
		res.SetVariables(f7)
	}

	return res
}

// GenerateUpdateStageInput returns an update input.
func GenerateUpdateStageInput(cr *svcapitypes.Stage) *svcsdk.UpdateStageInput {
	res := &svcsdk.UpdateStageInput{}

	if cr.Spec.ForProvider.StageName != nil {
		res.SetStageName(*cr.Spec.ForProvider.StageName)
	}

	return res
}

// GenerateDeleteStageInput returns a deletion input.
func GenerateDeleteStageInput(cr *svcapitypes.Stage) *svcsdk.DeleteStageInput {
	res := &svcsdk.DeleteStageInput{}

	if cr.Spec.ForProvider.StageName != nil {
		res.SetStageName(*cr.Spec.ForProvider.StageName)
	}

	return res
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "NotFoundException"
}
