//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	"github.com/crossplane/crossplane-runtime/apis/common/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CloudWatchMonitoringConfiguration) DeepCopyInto(out *CloudWatchMonitoringConfiguration) {
	*out = *in
	if in.LogStreamNamePrefix != nil {
		in, out := &in.LogStreamNamePrefix, &out.LogStreamNamePrefix
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CloudWatchMonitoringConfiguration.
func (in *CloudWatchMonitoringConfiguration) DeepCopy() *CloudWatchMonitoringConfiguration {
	if in == nil {
		return nil
	}
	out := new(CloudWatchMonitoringConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Configuration) DeepCopyInto(out *Configuration) {
	*out = *in
	if in.Classification != nil {
		in, out := &in.Classification, &out.Classification
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Configuration.
func (in *Configuration) DeepCopy() *Configuration {
	if in == nil {
		return nil
	}
	out := new(Configuration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ContainerInfo) DeepCopyInto(out *ContainerInfo) {
	*out = *in
	if in.EKSInfo != nil {
		in, out := &in.EKSInfo, &out.EKSInfo
		*out = new(EKSInfo)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ContainerInfo.
func (in *ContainerInfo) DeepCopy() *ContainerInfo {
	if in == nil {
		return nil
	}
	out := new(ContainerInfo)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ContainerProvider) DeepCopyInto(out *ContainerProvider) {
	*out = *in
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.Info != nil {
		in, out := &in.Info, &out.Info
		*out = new(ContainerInfo)
		(*in).DeepCopyInto(*out)
	}
	if in.Type != nil {
		in, out := &in.Type, &out.Type
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ContainerProvider.
func (in *ContainerProvider) DeepCopy() *ContainerProvider {
	if in == nil {
		return nil
	}
	out := new(ContainerProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CustomJobRunParameters) DeepCopyInto(out *CustomJobRunParameters) {
	*out = *in
	if in.VirtualClusterID != nil {
		in, out := &in.VirtualClusterID, &out.VirtualClusterID
		*out = new(string)
		**out = **in
	}
	if in.VirtualClusterIDRef != nil {
		in, out := &in.VirtualClusterIDRef, &out.VirtualClusterIDRef
		*out = new(v1.Reference)
		(*in).DeepCopyInto(*out)
	}
	if in.VirtualClusterIDSelector != nil {
		in, out := &in.VirtualClusterIDSelector, &out.VirtualClusterIDSelector
		*out = new(v1.Selector)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CustomJobRunParameters.
func (in *CustomJobRunParameters) DeepCopy() *CustomJobRunParameters {
	if in == nil {
		return nil
	}
	out := new(CustomJobRunParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CustomVirtualClusterParameters) DeepCopyInto(out *CustomVirtualClusterParameters) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CustomVirtualClusterParameters.
func (in *CustomVirtualClusterParameters) DeepCopy() *CustomVirtualClusterParameters {
	if in == nil {
		return nil
	}
	out := new(CustomVirtualClusterParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EKSInfo) DeepCopyInto(out *EKSInfo) {
	*out = *in
	if in.Namespace != nil {
		in, out := &in.Namespace, &out.Namespace
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EKSInfo.
func (in *EKSInfo) DeepCopy() *EKSInfo {
	if in == nil {
		return nil
	}
	out := new(EKSInfo)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Endpoint) DeepCopyInto(out *Endpoint) {
	*out = *in
	if in.CreatedAt != nil {
		in, out := &in.CreatedAt, &out.CreatedAt
		*out = (*in).DeepCopy()
	}
	if in.ExecutionRoleARN != nil {
		in, out := &in.ExecutionRoleARN, &out.ExecutionRoleARN
		*out = new(string)
		**out = **in
	}
	if in.FailureReason != nil {
		in, out := &in.FailureReason, &out.FailureReason
		*out = new(string)
		**out = **in
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
	if in.ReleaseLabel != nil {
		in, out := &in.ReleaseLabel, &out.ReleaseLabel
		*out = new(string)
		**out = **in
	}
	if in.SecurityGroup != nil {
		in, out := &in.SecurityGroup, &out.SecurityGroup
		*out = new(string)
		**out = **in
	}
	if in.StateDetails != nil {
		in, out := &in.StateDetails, &out.StateDetails
		*out = new(string)
		**out = **in
	}
	if in.Tags != nil {
		in, out := &in.Tags, &out.Tags
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	if in.VirtualClusterID != nil {
		in, out := &in.VirtualClusterID, &out.VirtualClusterID
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Endpoint.
func (in *Endpoint) DeepCopy() *Endpoint {
	if in == nil {
		return nil
	}
	out := new(Endpoint)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JobDriver) DeepCopyInto(out *JobDriver) {
	*out = *in
	if in.SparkSQLJobDriver != nil {
		in, out := &in.SparkSQLJobDriver, &out.SparkSQLJobDriver
		*out = new(SparkSQLJobDriver)
		(*in).DeepCopyInto(*out)
	}
	if in.SparkSubmitJobDriver != nil {
		in, out := &in.SparkSubmitJobDriver, &out.SparkSubmitJobDriver
		*out = new(SparkSubmitJobDriver)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JobDriver.
func (in *JobDriver) DeepCopy() *JobDriver {
	if in == nil {
		return nil
	}
	out := new(JobDriver)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JobRun) DeepCopyInto(out *JobRun) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JobRun.
func (in *JobRun) DeepCopy() *JobRun {
	if in == nil {
		return nil
	}
	out := new(JobRun)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *JobRun) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JobRunList) DeepCopyInto(out *JobRunList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]JobRun, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JobRunList.
func (in *JobRunList) DeepCopy() *JobRunList {
	if in == nil {
		return nil
	}
	out := new(JobRunList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *JobRunList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JobRunObservation) DeepCopyInto(out *JobRunObservation) {
	*out = *in
	if in.ARN != nil {
		in, out := &in.ARN, &out.ARN
		*out = new(string)
		**out = **in
	}
	if in.FailureReason != nil {
		in, out := &in.FailureReason, &out.FailureReason
		*out = new(string)
		**out = **in
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
	if in.State != nil {
		in, out := &in.State, &out.State
		*out = new(string)
		**out = **in
	}
	if in.StateDetails != nil {
		in, out := &in.StateDetails, &out.StateDetails
		*out = new(string)
		**out = **in
	}
	if in.VirtualClusterID != nil {
		in, out := &in.VirtualClusterID, &out.VirtualClusterID
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JobRunObservation.
func (in *JobRunObservation) DeepCopy() *JobRunObservation {
	if in == nil {
		return nil
	}
	out := new(JobRunObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JobRunParameters) DeepCopyInto(out *JobRunParameters) {
	*out = *in
	if in.ConfigurationOverrides != nil {
		in, out := &in.ConfigurationOverrides, &out.ConfigurationOverrides
		*out = new(string)
		**out = **in
	}
	if in.ExecutionRoleARN != nil {
		in, out := &in.ExecutionRoleARN, &out.ExecutionRoleARN
		*out = new(string)
		**out = **in
	}
	if in.JobDriver != nil {
		in, out := &in.JobDriver, &out.JobDriver
		*out = new(JobDriver)
		(*in).DeepCopyInto(*out)
	}
	if in.JobTemplateID != nil {
		in, out := &in.JobTemplateID, &out.JobTemplateID
		*out = new(string)
		**out = **in
	}
	if in.JobTemplateParameters != nil {
		in, out := &in.JobTemplateParameters, &out.JobTemplateParameters
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	if in.ReleaseLabel != nil {
		in, out := &in.ReleaseLabel, &out.ReleaseLabel
		*out = new(string)
		**out = **in
	}
	if in.Tags != nil {
		in, out := &in.Tags, &out.Tags
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	in.CustomJobRunParameters.DeepCopyInto(&out.CustomJobRunParameters)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JobRunParameters.
func (in *JobRunParameters) DeepCopy() *JobRunParameters {
	if in == nil {
		return nil
	}
	out := new(JobRunParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JobRunSpec) DeepCopyInto(out *JobRunSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JobRunSpec.
func (in *JobRunSpec) DeepCopy() *JobRunSpec {
	if in == nil {
		return nil
	}
	out := new(JobRunSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JobRunStatus) DeepCopyInto(out *JobRunStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JobRunStatus.
func (in *JobRunStatus) DeepCopy() *JobRunStatus {
	if in == nil {
		return nil
	}
	out := new(JobRunStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JobRun_SDK) DeepCopyInto(out *JobRun_SDK) {
	*out = *in
	if in.ARN != nil {
		in, out := &in.ARN, &out.ARN
		*out = new(string)
		**out = **in
	}
	if in.ClientToken != nil {
		in, out := &in.ClientToken, &out.ClientToken
		*out = new(string)
		**out = **in
	}
	if in.CreatedAt != nil {
		in, out := &in.CreatedAt, &out.CreatedAt
		*out = (*in).DeepCopy()
	}
	if in.CreatedBy != nil {
		in, out := &in.CreatedBy, &out.CreatedBy
		*out = new(string)
		**out = **in
	}
	if in.ExecutionRoleARN != nil {
		in, out := &in.ExecutionRoleARN, &out.ExecutionRoleARN
		*out = new(string)
		**out = **in
	}
	if in.FailureReason != nil {
		in, out := &in.FailureReason, &out.FailureReason
		*out = new(string)
		**out = **in
	}
	if in.FinishedAt != nil {
		in, out := &in.FinishedAt, &out.FinishedAt
		*out = (*in).DeepCopy()
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.JobDriver != nil {
		in, out := &in.JobDriver, &out.JobDriver
		*out = new(JobDriver)
		(*in).DeepCopyInto(*out)
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
	if in.ReleaseLabel != nil {
		in, out := &in.ReleaseLabel, &out.ReleaseLabel
		*out = new(string)
		**out = **in
	}
	if in.State != nil {
		in, out := &in.State, &out.State
		*out = new(string)
		**out = **in
	}
	if in.StateDetails != nil {
		in, out := &in.StateDetails, &out.StateDetails
		*out = new(string)
		**out = **in
	}
	if in.Tags != nil {
		in, out := &in.Tags, &out.Tags
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	if in.VirtualClusterID != nil {
		in, out := &in.VirtualClusterID, &out.VirtualClusterID
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JobRun_SDK.
func (in *JobRun_SDK) DeepCopy() *JobRun_SDK {
	if in == nil {
		return nil
	}
	out := new(JobRun_SDK)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JobTemplate) DeepCopyInto(out *JobTemplate) {
	*out = *in
	if in.CreatedAt != nil {
		in, out := &in.CreatedAt, &out.CreatedAt
		*out = (*in).DeepCopy()
	}
	if in.CreatedBy != nil {
		in, out := &in.CreatedBy, &out.CreatedBy
		*out = new(string)
		**out = **in
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
	if in.Tags != nil {
		in, out := &in.Tags, &out.Tags
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JobTemplate.
func (in *JobTemplate) DeepCopy() *JobTemplate {
	if in == nil {
		return nil
	}
	out := new(JobTemplate)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JobTemplateData) DeepCopyInto(out *JobTemplateData) {
	*out = *in
	if in.JobDriver != nil {
		in, out := &in.JobDriver, &out.JobDriver
		*out = new(JobDriver)
		(*in).DeepCopyInto(*out)
	}
	if in.JobTags != nil {
		in, out := &in.JobTags, &out.JobTags
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JobTemplateData.
func (in *JobTemplateData) DeepCopy() *JobTemplateData {
	if in == nil {
		return nil
	}
	out := new(JobTemplateData)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ParametricCloudWatchMonitoringConfiguration) DeepCopyInto(out *ParametricCloudWatchMonitoringConfiguration) {
	*out = *in
	if in.LogStreamNamePrefix != nil {
		in, out := &in.LogStreamNamePrefix, &out.LogStreamNamePrefix
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ParametricCloudWatchMonitoringConfiguration.
func (in *ParametricCloudWatchMonitoringConfiguration) DeepCopy() *ParametricCloudWatchMonitoringConfiguration {
	if in == nil {
		return nil
	}
	out := new(ParametricCloudWatchMonitoringConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SparkSQLJobDriver) DeepCopyInto(out *SparkSQLJobDriver) {
	*out = *in
	if in.EntryPoint != nil {
		in, out := &in.EntryPoint, &out.EntryPoint
		*out = new(string)
		**out = **in
	}
	if in.SparkSQLParameters != nil {
		in, out := &in.SparkSQLParameters, &out.SparkSQLParameters
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SparkSQLJobDriver.
func (in *SparkSQLJobDriver) DeepCopy() *SparkSQLJobDriver {
	if in == nil {
		return nil
	}
	out := new(SparkSQLJobDriver)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SparkSubmitJobDriver) DeepCopyInto(out *SparkSubmitJobDriver) {
	*out = *in
	if in.EntryPoint != nil {
		in, out := &in.EntryPoint, &out.EntryPoint
		*out = new(string)
		**out = **in
	}
	if in.EntryPointArguments != nil {
		in, out := &in.EntryPointArguments, &out.EntryPointArguments
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
	if in.SparkSubmitParameters != nil {
		in, out := &in.SparkSubmitParameters, &out.SparkSubmitParameters
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SparkSubmitJobDriver.
func (in *SparkSubmitJobDriver) DeepCopy() *SparkSubmitJobDriver {
	if in == nil {
		return nil
	}
	out := new(SparkSubmitJobDriver)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TemplateParameterConfiguration) DeepCopyInto(out *TemplateParameterConfiguration) {
	*out = *in
	if in.DefaultValue != nil {
		in, out := &in.DefaultValue, &out.DefaultValue
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TemplateParameterConfiguration.
func (in *TemplateParameterConfiguration) DeepCopy() *TemplateParameterConfiguration {
	if in == nil {
		return nil
	}
	out := new(TemplateParameterConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VirtualCluster) DeepCopyInto(out *VirtualCluster) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VirtualCluster.
func (in *VirtualCluster) DeepCopy() *VirtualCluster {
	if in == nil {
		return nil
	}
	out := new(VirtualCluster)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *VirtualCluster) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VirtualClusterList) DeepCopyInto(out *VirtualClusterList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]VirtualCluster, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VirtualClusterList.
func (in *VirtualClusterList) DeepCopy() *VirtualClusterList {
	if in == nil {
		return nil
	}
	out := new(VirtualClusterList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *VirtualClusterList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VirtualClusterObservation) DeepCopyInto(out *VirtualClusterObservation) {
	*out = *in
	if in.ARN != nil {
		in, out := &in.ARN, &out.ARN
		*out = new(string)
		**out = **in
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VirtualClusterObservation.
func (in *VirtualClusterObservation) DeepCopy() *VirtualClusterObservation {
	if in == nil {
		return nil
	}
	out := new(VirtualClusterObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VirtualClusterParameters) DeepCopyInto(out *VirtualClusterParameters) {
	*out = *in
	if in.ContainerProvider != nil {
		in, out := &in.ContainerProvider, &out.ContainerProvider
		*out = new(ContainerProvider)
		(*in).DeepCopyInto(*out)
	}
	if in.Tags != nil {
		in, out := &in.Tags, &out.Tags
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	out.CustomVirtualClusterParameters = in.CustomVirtualClusterParameters
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VirtualClusterParameters.
func (in *VirtualClusterParameters) DeepCopy() *VirtualClusterParameters {
	if in == nil {
		return nil
	}
	out := new(VirtualClusterParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VirtualClusterSpec) DeepCopyInto(out *VirtualClusterSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VirtualClusterSpec.
func (in *VirtualClusterSpec) DeepCopy() *VirtualClusterSpec {
	if in == nil {
		return nil
	}
	out := new(VirtualClusterSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VirtualClusterStatus) DeepCopyInto(out *VirtualClusterStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VirtualClusterStatus.
func (in *VirtualClusterStatus) DeepCopy() *VirtualClusterStatus {
	if in == nil {
		return nil
	}
	out := new(VirtualClusterStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VirtualCluster_SDK) DeepCopyInto(out *VirtualCluster_SDK) {
	*out = *in
	if in.ARN != nil {
		in, out := &in.ARN, &out.ARN
		*out = new(string)
		**out = **in
	}
	if in.ContainerProvider != nil {
		in, out := &in.ContainerProvider, &out.ContainerProvider
		*out = new(ContainerProvider)
		(*in).DeepCopyInto(*out)
	}
	if in.CreatedAt != nil {
		in, out := &in.CreatedAt, &out.CreatedAt
		*out = (*in).DeepCopy()
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
	if in.State != nil {
		in, out := &in.State, &out.State
		*out = new(string)
		**out = **in
	}
	if in.Tags != nil {
		in, out := &in.Tags, &out.Tags
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VirtualCluster_SDK.
func (in *VirtualCluster_SDK) DeepCopy() *VirtualCluster_SDK {
	if in == nil {
		return nil
	}
	out := new(VirtualCluster_SDK)
	in.DeepCopyInto(out)
	return out
}
