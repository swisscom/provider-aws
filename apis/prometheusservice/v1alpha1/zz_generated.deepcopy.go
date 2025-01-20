//go:build !ignore_autogenerated

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
func (in *AlertManagerDefinition) DeepCopyInto(out *AlertManagerDefinition) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AlertManagerDefinition.
func (in *AlertManagerDefinition) DeepCopy() *AlertManagerDefinition {
	if in == nil {
		return nil
	}
	out := new(AlertManagerDefinition)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AlertManagerDefinition) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AlertManagerDefinitionDescription) DeepCopyInto(out *AlertManagerDefinitionDescription) {
	*out = *in
	if in.CreatedAt != nil {
		in, out := &in.CreatedAt, &out.CreatedAt
		*out = (*in).DeepCopy()
	}
	if in.Data != nil {
		in, out := &in.Data, &out.Data
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
	if in.ModifiedAt != nil {
		in, out := &in.ModifiedAt, &out.ModifiedAt
		*out = (*in).DeepCopy()
	}
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(AlertManagerDefinitionStatus_SDK)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AlertManagerDefinitionDescription.
func (in *AlertManagerDefinitionDescription) DeepCopy() *AlertManagerDefinitionDescription {
	if in == nil {
		return nil
	}
	out := new(AlertManagerDefinitionDescription)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AlertManagerDefinitionList) DeepCopyInto(out *AlertManagerDefinitionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AlertManagerDefinition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AlertManagerDefinitionList.
func (in *AlertManagerDefinitionList) DeepCopy() *AlertManagerDefinitionList {
	if in == nil {
		return nil
	}
	out := new(AlertManagerDefinitionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AlertManagerDefinitionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AlertManagerDefinitionObservation) DeepCopyInto(out *AlertManagerDefinitionObservation) {
	*out = *in
	if in.StatusCode != nil {
		in, out := &in.StatusCode, &out.StatusCode
		*out = new(string)
		**out = **in
	}
	if in.StatusReason != nil {
		in, out := &in.StatusReason, &out.StatusReason
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AlertManagerDefinitionObservation.
func (in *AlertManagerDefinitionObservation) DeepCopy() *AlertManagerDefinitionObservation {
	if in == nil {
		return nil
	}
	out := new(AlertManagerDefinitionObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AlertManagerDefinitionParameters) DeepCopyInto(out *AlertManagerDefinitionParameters) {
	*out = *in
	if in.Data != nil {
		in, out := &in.Data, &out.Data
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
	in.CustomAlertManagerDefinitionParameters.DeepCopyInto(&out.CustomAlertManagerDefinitionParameters)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AlertManagerDefinitionParameters.
func (in *AlertManagerDefinitionParameters) DeepCopy() *AlertManagerDefinitionParameters {
	if in == nil {
		return nil
	}
	out := new(AlertManagerDefinitionParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AlertManagerDefinitionSpec) DeepCopyInto(out *AlertManagerDefinitionSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AlertManagerDefinitionSpec.
func (in *AlertManagerDefinitionSpec) DeepCopy() *AlertManagerDefinitionSpec {
	if in == nil {
		return nil
	}
	out := new(AlertManagerDefinitionSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AlertManagerDefinitionStatus) DeepCopyInto(out *AlertManagerDefinitionStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AlertManagerDefinitionStatus.
func (in *AlertManagerDefinitionStatus) DeepCopy() *AlertManagerDefinitionStatus {
	if in == nil {
		return nil
	}
	out := new(AlertManagerDefinitionStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AlertManagerDefinitionStatus_SDK) DeepCopyInto(out *AlertManagerDefinitionStatus_SDK) {
	*out = *in
	if in.StatusCode != nil {
		in, out := &in.StatusCode, &out.StatusCode
		*out = new(string)
		**out = **in
	}
	if in.StatusReason != nil {
		in, out := &in.StatusReason, &out.StatusReason
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AlertManagerDefinitionStatus_SDK.
func (in *AlertManagerDefinitionStatus_SDK) DeepCopy() *AlertManagerDefinitionStatus_SDK {
	if in == nil {
		return nil
	}
	out := new(AlertManagerDefinitionStatus_SDK)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AmpConfiguration) DeepCopyInto(out *AmpConfiguration) {
	*out = *in
	if in.WorkspaceARN != nil {
		in, out := &in.WorkspaceARN, &out.WorkspaceARN
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AmpConfiguration.
func (in *AmpConfiguration) DeepCopy() *AmpConfiguration {
	if in == nil {
		return nil
	}
	out := new(AmpConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CustomAlertManagerDefinitionParameters) DeepCopyInto(out *CustomAlertManagerDefinitionParameters) {
	*out = *in
	if in.WorkspaceID != nil {
		in, out := &in.WorkspaceID, &out.WorkspaceID
		*out = new(string)
		**out = **in
	}
	if in.WorkspaceIDRef != nil {
		in, out := &in.WorkspaceIDRef, &out.WorkspaceIDRef
		*out = new(v1.Reference)
		(*in).DeepCopyInto(*out)
	}
	if in.WorkspaceIDSelector != nil {
		in, out := &in.WorkspaceIDSelector, &out.WorkspaceIDSelector
		*out = new(v1.Selector)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CustomAlertManagerDefinitionParameters.
func (in *CustomAlertManagerDefinitionParameters) DeepCopy() *CustomAlertManagerDefinitionParameters {
	if in == nil {
		return nil
	}
	out := new(CustomAlertManagerDefinitionParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CustomRuleGroupsNamespaceParameters) DeepCopyInto(out *CustomRuleGroupsNamespaceParameters) {
	*out = *in
	if in.WorkspaceID != nil {
		in, out := &in.WorkspaceID, &out.WorkspaceID
		*out = new(string)
		**out = **in
	}
	if in.WorkspaceIDRef != nil {
		in, out := &in.WorkspaceIDRef, &out.WorkspaceIDRef
		*out = new(v1.Reference)
		(*in).DeepCopyInto(*out)
	}
	if in.WorkspaceIDSelector != nil {
		in, out := &in.WorkspaceIDSelector, &out.WorkspaceIDSelector
		*out = new(v1.Selector)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CustomRuleGroupsNamespaceParameters.
func (in *CustomRuleGroupsNamespaceParameters) DeepCopy() *CustomRuleGroupsNamespaceParameters {
	if in == nil {
		return nil
	}
	out := new(CustomRuleGroupsNamespaceParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CustomWorkspaceParameters) DeepCopyInto(out *CustomWorkspaceParameters) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CustomWorkspaceParameters.
func (in *CustomWorkspaceParameters) DeepCopy() *CustomWorkspaceParameters {
	if in == nil {
		return nil
	}
	out := new(CustomWorkspaceParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LoggingConfigurationMetadata) DeepCopyInto(out *LoggingConfigurationMetadata) {
	*out = *in
	if in.CreatedAt != nil {
		in, out := &in.CreatedAt, &out.CreatedAt
		*out = (*in).DeepCopy()
	}
	if in.ModifiedAt != nil {
		in, out := &in.ModifiedAt, &out.ModifiedAt
		*out = (*in).DeepCopy()
	}
	if in.Workspace != nil {
		in, out := &in.Workspace, &out.Workspace
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LoggingConfigurationMetadata.
func (in *LoggingConfigurationMetadata) DeepCopy() *LoggingConfigurationMetadata {
	if in == nil {
		return nil
	}
	out := new(LoggingConfigurationMetadata)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LoggingConfigurationStatus) DeepCopyInto(out *LoggingConfigurationStatus) {
	*out = *in
	if in.StatusReason != nil {
		in, out := &in.StatusReason, &out.StatusReason
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LoggingConfigurationStatus.
func (in *LoggingConfigurationStatus) DeepCopy() *LoggingConfigurationStatus {
	if in == nil {
		return nil
	}
	out := new(LoggingConfigurationStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RuleGroupsNamespace) DeepCopyInto(out *RuleGroupsNamespace) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RuleGroupsNamespace.
func (in *RuleGroupsNamespace) DeepCopy() *RuleGroupsNamespace {
	if in == nil {
		return nil
	}
	out := new(RuleGroupsNamespace)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RuleGroupsNamespace) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RuleGroupsNamespaceDescription) DeepCopyInto(out *RuleGroupsNamespaceDescription) {
	*out = *in
	if in.ARN != nil {
		in, out := &in.ARN, &out.ARN
		*out = new(string)
		**out = **in
	}
	if in.CreatedAt != nil {
		in, out := &in.CreatedAt, &out.CreatedAt
		*out = (*in).DeepCopy()
	}
	if in.Data != nil {
		in, out := &in.Data, &out.Data
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
	if in.ModifiedAt != nil {
		in, out := &in.ModifiedAt, &out.ModifiedAt
		*out = (*in).DeepCopy()
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(RuleGroupsNamespaceStatus_SDK)
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
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RuleGroupsNamespaceDescription.
func (in *RuleGroupsNamespaceDescription) DeepCopy() *RuleGroupsNamespaceDescription {
	if in == nil {
		return nil
	}
	out := new(RuleGroupsNamespaceDescription)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RuleGroupsNamespaceList) DeepCopyInto(out *RuleGroupsNamespaceList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]RuleGroupsNamespace, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RuleGroupsNamespaceList.
func (in *RuleGroupsNamespaceList) DeepCopy() *RuleGroupsNamespaceList {
	if in == nil {
		return nil
	}
	out := new(RuleGroupsNamespaceList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RuleGroupsNamespaceList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RuleGroupsNamespaceObservation) DeepCopyInto(out *RuleGroupsNamespaceObservation) {
	*out = *in
	if in.ARN != nil {
		in, out := &in.ARN, &out.ARN
		*out = new(string)
		**out = **in
	}
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(RuleGroupsNamespaceStatus_SDK)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RuleGroupsNamespaceObservation.
func (in *RuleGroupsNamespaceObservation) DeepCopy() *RuleGroupsNamespaceObservation {
	if in == nil {
		return nil
	}
	out := new(RuleGroupsNamespaceObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RuleGroupsNamespaceParameters) DeepCopyInto(out *RuleGroupsNamespaceParameters) {
	*out = *in
	if in.Data != nil {
		in, out := &in.Data, &out.Data
		*out = make([]byte, len(*in))
		copy(*out, *in)
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
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	in.CustomRuleGroupsNamespaceParameters.DeepCopyInto(&out.CustomRuleGroupsNamespaceParameters)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RuleGroupsNamespaceParameters.
func (in *RuleGroupsNamespaceParameters) DeepCopy() *RuleGroupsNamespaceParameters {
	if in == nil {
		return nil
	}
	out := new(RuleGroupsNamespaceParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RuleGroupsNamespaceSpec) DeepCopyInto(out *RuleGroupsNamespaceSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RuleGroupsNamespaceSpec.
func (in *RuleGroupsNamespaceSpec) DeepCopy() *RuleGroupsNamespaceSpec {
	if in == nil {
		return nil
	}
	out := new(RuleGroupsNamespaceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RuleGroupsNamespaceStatus) DeepCopyInto(out *RuleGroupsNamespaceStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RuleGroupsNamespaceStatus.
func (in *RuleGroupsNamespaceStatus) DeepCopy() *RuleGroupsNamespaceStatus {
	if in == nil {
		return nil
	}
	out := new(RuleGroupsNamespaceStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RuleGroupsNamespaceStatus_SDK) DeepCopyInto(out *RuleGroupsNamespaceStatus_SDK) {
	*out = *in
	if in.StatusCode != nil {
		in, out := &in.StatusCode, &out.StatusCode
		*out = new(string)
		**out = **in
	}
	if in.StatusReason != nil {
		in, out := &in.StatusReason, &out.StatusReason
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RuleGroupsNamespaceStatus_SDK.
func (in *RuleGroupsNamespaceStatus_SDK) DeepCopy() *RuleGroupsNamespaceStatus_SDK {
	if in == nil {
		return nil
	}
	out := new(RuleGroupsNamespaceStatus_SDK)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RuleGroupsNamespaceSummary) DeepCopyInto(out *RuleGroupsNamespaceSummary) {
	*out = *in
	if in.ARN != nil {
		in, out := &in.ARN, &out.ARN
		*out = new(string)
		**out = **in
	}
	if in.CreatedAt != nil {
		in, out := &in.CreatedAt, &out.CreatedAt
		*out = (*in).DeepCopy()
	}
	if in.ModifiedAt != nil {
		in, out := &in.ModifiedAt, &out.ModifiedAt
		*out = (*in).DeepCopy()
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(RuleGroupsNamespaceStatus_SDK)
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
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RuleGroupsNamespaceSummary.
func (in *RuleGroupsNamespaceSummary) DeepCopy() *RuleGroupsNamespaceSummary {
	if in == nil {
		return nil
	}
	out := new(RuleGroupsNamespaceSummary)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ScraperDescription) DeepCopyInto(out *ScraperDescription) {
	*out = *in
	if in.CreatedAt != nil {
		in, out := &in.CreatedAt, &out.CreatedAt
		*out = (*in).DeepCopy()
	}
	if in.LastModifiedAt != nil {
		in, out := &in.LastModifiedAt, &out.LastModifiedAt
		*out = (*in).DeepCopy()
	}
	if in.Tags != nil {
		in, out := &in.Tags, &out.Tags
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ScraperDescription.
func (in *ScraperDescription) DeepCopy() *ScraperDescription {
	if in == nil {
		return nil
	}
	out := new(ScraperDescription)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ScraperSummary) DeepCopyInto(out *ScraperSummary) {
	*out = *in
	if in.CreatedAt != nil {
		in, out := &in.CreatedAt, &out.CreatedAt
		*out = (*in).DeepCopy()
	}
	if in.LastModifiedAt != nil {
		in, out := &in.LastModifiedAt, &out.LastModifiedAt
		*out = (*in).DeepCopy()
	}
	if in.Tags != nil {
		in, out := &in.Tags, &out.Tags
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ScraperSummary.
func (in *ScraperSummary) DeepCopy() *ScraperSummary {
	if in == nil {
		return nil
	}
	out := new(ScraperSummary)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ValidationExceptionField) DeepCopyInto(out *ValidationExceptionField) {
	*out = *in
	if in.Message != nil {
		in, out := &in.Message, &out.Message
		*out = new(string)
		**out = **in
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ValidationExceptionField.
func (in *ValidationExceptionField) DeepCopy() *ValidationExceptionField {
	if in == nil {
		return nil
	}
	out := new(ValidationExceptionField)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Workspace) DeepCopyInto(out *Workspace) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Workspace.
func (in *Workspace) DeepCopy() *Workspace {
	if in == nil {
		return nil
	}
	out := new(Workspace)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Workspace) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceDescription) DeepCopyInto(out *WorkspaceDescription) {
	*out = *in
	if in.Alias != nil {
		in, out := &in.Alias, &out.Alias
		*out = new(string)
		**out = **in
	}
	if in.ARN != nil {
		in, out := &in.ARN, &out.ARN
		*out = new(string)
		**out = **in
	}
	if in.CreatedAt != nil {
		in, out := &in.CreatedAt, &out.CreatedAt
		*out = (*in).DeepCopy()
	}
	if in.PrometheusEndpoint != nil {
		in, out := &in.PrometheusEndpoint, &out.PrometheusEndpoint
		*out = new(string)
		**out = **in
	}
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(WorkspaceStatus_SDK)
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
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	if in.WorkspaceID != nil {
		in, out := &in.WorkspaceID, &out.WorkspaceID
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceDescription.
func (in *WorkspaceDescription) DeepCopy() *WorkspaceDescription {
	if in == nil {
		return nil
	}
	out := new(WorkspaceDescription)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceList) DeepCopyInto(out *WorkspaceList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Workspace, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceList.
func (in *WorkspaceList) DeepCopy() *WorkspaceList {
	if in == nil {
		return nil
	}
	out := new(WorkspaceList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *WorkspaceList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceObservation) DeepCopyInto(out *WorkspaceObservation) {
	*out = *in
	if in.ARN != nil {
		in, out := &in.ARN, &out.ARN
		*out = new(string)
		**out = **in
	}
	if in.PrometheusEndpoint != nil {
		in, out := &in.PrometheusEndpoint, &out.PrometheusEndpoint
		*out = new(string)
		**out = **in
	}
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(WorkspaceStatus_SDK)
		(*in).DeepCopyInto(*out)
	}
	if in.WorkspaceID != nil {
		in, out := &in.WorkspaceID, &out.WorkspaceID
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceObservation.
func (in *WorkspaceObservation) DeepCopy() *WorkspaceObservation {
	if in == nil {
		return nil
	}
	out := new(WorkspaceObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceParameters) DeepCopyInto(out *WorkspaceParameters) {
	*out = *in
	if in.Alias != nil {
		in, out := &in.Alias, &out.Alias
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
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	out.CustomWorkspaceParameters = in.CustomWorkspaceParameters
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceParameters.
func (in *WorkspaceParameters) DeepCopy() *WorkspaceParameters {
	if in == nil {
		return nil
	}
	out := new(WorkspaceParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceSpec) DeepCopyInto(out *WorkspaceSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceSpec.
func (in *WorkspaceSpec) DeepCopy() *WorkspaceSpec {
	if in == nil {
		return nil
	}
	out := new(WorkspaceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceStatus) DeepCopyInto(out *WorkspaceStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceStatus.
func (in *WorkspaceStatus) DeepCopy() *WorkspaceStatus {
	if in == nil {
		return nil
	}
	out := new(WorkspaceStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceStatus_SDK) DeepCopyInto(out *WorkspaceStatus_SDK) {
	*out = *in
	if in.StatusCode != nil {
		in, out := &in.StatusCode, &out.StatusCode
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceStatus_SDK.
func (in *WorkspaceStatus_SDK) DeepCopy() *WorkspaceStatus_SDK {
	if in == nil {
		return nil
	}
	out := new(WorkspaceStatus_SDK)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceSummary) DeepCopyInto(out *WorkspaceSummary) {
	*out = *in
	if in.Alias != nil {
		in, out := &in.Alias, &out.Alias
		*out = new(string)
		**out = **in
	}
	if in.ARN != nil {
		in, out := &in.ARN, &out.ARN
		*out = new(string)
		**out = **in
	}
	if in.CreatedAt != nil {
		in, out := &in.CreatedAt, &out.CreatedAt
		*out = (*in).DeepCopy()
	}
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(WorkspaceStatus_SDK)
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
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	if in.WorkspaceID != nil {
		in, out := &in.WorkspaceID, &out.WorkspaceID
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceSummary.
func (in *WorkspaceSummary) DeepCopy() *WorkspaceSummary {
	if in == nil {
		return nil
	}
	out := new(WorkspaceSummary)
	in.DeepCopyInto(out)
	return out
}
