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

package endpointgroup

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/globalaccelerator"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/globalaccelerator/v1alpha1"
)

// NOTE(muvaf): We return pointers in case the function needs to start with an
// empty object, hence need to return a new pointer.

// GenerateDescribeEndpointGroupInput returns input for read
// operation.
func GenerateDescribeEndpointGroupInput(cr *svcapitypes.EndpointGroup) *svcsdk.DescribeEndpointGroupInput {
	res := &svcsdk.DescribeEndpointGroupInput{}

	if cr.Status.AtProvider.EndpointGroupARN != nil {
		res.SetEndpointGroupArn(*cr.Status.AtProvider.EndpointGroupARN)
	}

	return res
}

// GenerateEndpointGroup returns the current state in the form of *svcapitypes.EndpointGroup.
func GenerateEndpointGroup(resp *svcsdk.DescribeEndpointGroupOutput) *svcapitypes.EndpointGroup {
	cr := &svcapitypes.EndpointGroup{}

	if resp.EndpointGroup.EndpointDescriptions != nil {
		f0 := []*svcapitypes.EndpointDescription{}
		for _, f0iter := range resp.EndpointGroup.EndpointDescriptions {
			f0elem := &svcapitypes.EndpointDescription{}
			if f0iter.ClientIPPreservationEnabled != nil {
				f0elem.ClientIPPreservationEnabled = f0iter.ClientIPPreservationEnabled
			}
			if f0iter.EndpointId != nil {
				f0elem.EndpointID = f0iter.EndpointId
			}
			if f0iter.HealthReason != nil {
				f0elem.HealthReason = f0iter.HealthReason
			}
			if f0iter.HealthState != nil {
				f0elem.HealthState = f0iter.HealthState
			}
			if f0iter.Weight != nil {
				f0elem.Weight = f0iter.Weight
			}
			f0 = append(f0, f0elem)
		}
		cr.Status.AtProvider.EndpointDescriptions = f0
	} else {
		cr.Status.AtProvider.EndpointDescriptions = nil
	}
	if resp.EndpointGroup.EndpointGroupArn != nil {
		cr.Status.AtProvider.EndpointGroupARN = resp.EndpointGroup.EndpointGroupArn
	} else {
		cr.Status.AtProvider.EndpointGroupARN = nil
	}
	if resp.EndpointGroup.EndpointGroupRegion != nil {
		cr.Spec.ForProvider.EndpointGroupRegion = resp.EndpointGroup.EndpointGroupRegion
	} else {
		cr.Spec.ForProvider.EndpointGroupRegion = nil
	}
	if resp.EndpointGroup.HealthCheckIntervalSeconds != nil {
		cr.Spec.ForProvider.HealthCheckIntervalSeconds = resp.EndpointGroup.HealthCheckIntervalSeconds
	} else {
		cr.Spec.ForProvider.HealthCheckIntervalSeconds = nil
	}
	if resp.EndpointGroup.HealthCheckPath != nil {
		cr.Spec.ForProvider.HealthCheckPath = resp.EndpointGroup.HealthCheckPath
	} else {
		cr.Spec.ForProvider.HealthCheckPath = nil
	}
	if resp.EndpointGroup.HealthCheckPort != nil {
		cr.Spec.ForProvider.HealthCheckPort = resp.EndpointGroup.HealthCheckPort
	} else {
		cr.Spec.ForProvider.HealthCheckPort = nil
	}
	if resp.EndpointGroup.HealthCheckProtocol != nil {
		cr.Spec.ForProvider.HealthCheckProtocol = resp.EndpointGroup.HealthCheckProtocol
	} else {
		cr.Spec.ForProvider.HealthCheckProtocol = nil
	}
	if resp.EndpointGroup.PortOverrides != nil {
		f7 := []*svcapitypes.PortOverride{}
		for _, f7iter := range resp.EndpointGroup.PortOverrides {
			f7elem := &svcapitypes.PortOverride{}
			if f7iter.EndpointPort != nil {
				f7elem.EndpointPort = f7iter.EndpointPort
			}
			if f7iter.ListenerPort != nil {
				f7elem.ListenerPort = f7iter.ListenerPort
			}
			f7 = append(f7, f7elem)
		}
		cr.Spec.ForProvider.PortOverrides = f7
	} else {
		cr.Spec.ForProvider.PortOverrides = nil
	}
	if resp.EndpointGroup.ThresholdCount != nil {
		cr.Spec.ForProvider.ThresholdCount = resp.EndpointGroup.ThresholdCount
	} else {
		cr.Spec.ForProvider.ThresholdCount = nil
	}
	if resp.EndpointGroup.TrafficDialPercentage != nil {
		cr.Spec.ForProvider.TrafficDialPercentage = resp.EndpointGroup.TrafficDialPercentage
	} else {
		cr.Spec.ForProvider.TrafficDialPercentage = nil
	}

	return cr
}

// GenerateCreateEndpointGroupInput returns a create input.
func GenerateCreateEndpointGroupInput(cr *svcapitypes.EndpointGroup) *svcsdk.CreateEndpointGroupInput {
	res := &svcsdk.CreateEndpointGroupInput{}

	if cr.Spec.ForProvider.EndpointConfigurations != nil {
		f0 := []*svcsdk.EndpointConfiguration{}
		for _, f0iter := range cr.Spec.ForProvider.EndpointConfigurations {
			f0elem := &svcsdk.EndpointConfiguration{}
			if f0iter.AttachmentARN != nil {
				f0elem.SetAttachmentArn(*f0iter.AttachmentARN)
			}
			if f0iter.ClientIPPreservationEnabled != nil {
				f0elem.SetClientIPPreservationEnabled(*f0iter.ClientIPPreservationEnabled)
			}
			if f0iter.EndpointID != nil {
				f0elem.SetEndpointId(*f0iter.EndpointID)
			}
			if f0iter.Weight != nil {
				f0elem.SetWeight(*f0iter.Weight)
			}
			f0 = append(f0, f0elem)
		}
		res.SetEndpointConfigurations(f0)
	}
	if cr.Spec.ForProvider.EndpointGroupRegion != nil {
		res.SetEndpointGroupRegion(*cr.Spec.ForProvider.EndpointGroupRegion)
	}
	if cr.Spec.ForProvider.HealthCheckIntervalSeconds != nil {
		res.SetHealthCheckIntervalSeconds(*cr.Spec.ForProvider.HealthCheckIntervalSeconds)
	}
	if cr.Spec.ForProvider.HealthCheckPath != nil {
		res.SetHealthCheckPath(*cr.Spec.ForProvider.HealthCheckPath)
	}
	if cr.Spec.ForProvider.HealthCheckPort != nil {
		res.SetHealthCheckPort(*cr.Spec.ForProvider.HealthCheckPort)
	}
	if cr.Spec.ForProvider.HealthCheckProtocol != nil {
		res.SetHealthCheckProtocol(*cr.Spec.ForProvider.HealthCheckProtocol)
	}
	if cr.Spec.ForProvider.PortOverrides != nil {
		f6 := []*svcsdk.PortOverride{}
		for _, f6iter := range cr.Spec.ForProvider.PortOverrides {
			f6elem := &svcsdk.PortOverride{}
			if f6iter.EndpointPort != nil {
				f6elem.SetEndpointPort(*f6iter.EndpointPort)
			}
			if f6iter.ListenerPort != nil {
				f6elem.SetListenerPort(*f6iter.ListenerPort)
			}
			f6 = append(f6, f6elem)
		}
		res.SetPortOverrides(f6)
	}
	if cr.Spec.ForProvider.ThresholdCount != nil {
		res.SetThresholdCount(*cr.Spec.ForProvider.ThresholdCount)
	}
	if cr.Spec.ForProvider.TrafficDialPercentage != nil {
		res.SetTrafficDialPercentage(*cr.Spec.ForProvider.TrafficDialPercentage)
	}

	return res
}

// GenerateUpdateEndpointGroupInput returns an update input.
func GenerateUpdateEndpointGroupInput(cr *svcapitypes.EndpointGroup) *svcsdk.UpdateEndpointGroupInput {
	res := &svcsdk.UpdateEndpointGroupInput{}

	if cr.Spec.ForProvider.EndpointConfigurations != nil {
		f0 := []*svcsdk.EndpointConfiguration{}
		for _, f0iter := range cr.Spec.ForProvider.EndpointConfigurations {
			f0elem := &svcsdk.EndpointConfiguration{}
			if f0iter.AttachmentARN != nil {
				f0elem.SetAttachmentArn(*f0iter.AttachmentARN)
			}
			if f0iter.ClientIPPreservationEnabled != nil {
				f0elem.SetClientIPPreservationEnabled(*f0iter.ClientIPPreservationEnabled)
			}
			if f0iter.EndpointID != nil {
				f0elem.SetEndpointId(*f0iter.EndpointID)
			}
			if f0iter.Weight != nil {
				f0elem.SetWeight(*f0iter.Weight)
			}
			f0 = append(f0, f0elem)
		}
		res.SetEndpointConfigurations(f0)
	}
	if cr.Status.AtProvider.EndpointGroupARN != nil {
		res.SetEndpointGroupArn(*cr.Status.AtProvider.EndpointGroupARN)
	}
	if cr.Spec.ForProvider.HealthCheckIntervalSeconds != nil {
		res.SetHealthCheckIntervalSeconds(*cr.Spec.ForProvider.HealthCheckIntervalSeconds)
	}
	if cr.Spec.ForProvider.HealthCheckPath != nil {
		res.SetHealthCheckPath(*cr.Spec.ForProvider.HealthCheckPath)
	}
	if cr.Spec.ForProvider.HealthCheckPort != nil {
		res.SetHealthCheckPort(*cr.Spec.ForProvider.HealthCheckPort)
	}
	if cr.Spec.ForProvider.HealthCheckProtocol != nil {
		res.SetHealthCheckProtocol(*cr.Spec.ForProvider.HealthCheckProtocol)
	}
	if cr.Spec.ForProvider.PortOverrides != nil {
		f6 := []*svcsdk.PortOverride{}
		for _, f6iter := range cr.Spec.ForProvider.PortOverrides {
			f6elem := &svcsdk.PortOverride{}
			if f6iter.EndpointPort != nil {
				f6elem.SetEndpointPort(*f6iter.EndpointPort)
			}
			if f6iter.ListenerPort != nil {
				f6elem.SetListenerPort(*f6iter.ListenerPort)
			}
			f6 = append(f6, f6elem)
		}
		res.SetPortOverrides(f6)
	}
	if cr.Spec.ForProvider.ThresholdCount != nil {
		res.SetThresholdCount(*cr.Spec.ForProvider.ThresholdCount)
	}
	if cr.Spec.ForProvider.TrafficDialPercentage != nil {
		res.SetTrafficDialPercentage(*cr.Spec.ForProvider.TrafficDialPercentage)
	}

	return res
}

// GenerateDeleteEndpointGroupInput returns a deletion input.
func GenerateDeleteEndpointGroupInput(cr *svcapitypes.EndpointGroup) *svcsdk.DeleteEndpointGroupInput {
	res := &svcsdk.DeleteEndpointGroupInput{}

	if cr.Status.AtProvider.EndpointGroupARN != nil {
		res.SetEndpointGroupArn(*cr.Status.AtProvider.EndpointGroupARN)
	}

	return res
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "EndpointGroupNotFoundException"
}
