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

package v1alpha1

type EncryptionType string

const (
	EncryptionType_AES256 EncryptionType = "AES256"
	EncryptionType_KMS    EncryptionType = "KMS"
)

type FindingSeverity string

const (
	FindingSeverity_INFORMATIONAL FindingSeverity = "INFORMATIONAL"
	FindingSeverity_LOW           FindingSeverity = "LOW"
	FindingSeverity_MEDIUM        FindingSeverity = "MEDIUM"
	FindingSeverity_HIGH          FindingSeverity = "HIGH"
	FindingSeverity_CRITICAL      FindingSeverity = "CRITICAL"
	FindingSeverity_UNDEFINED     FindingSeverity = "UNDEFINED"
)

type ImageActionType string

const (
	ImageActionType_EXPIRE ImageActionType = "EXPIRE"
)

type ImageFailureCode string

const (
	ImageFailureCode_InvalidImageDigest            ImageFailureCode = "InvalidImageDigest"
	ImageFailureCode_InvalidImageTag               ImageFailureCode = "InvalidImageTag"
	ImageFailureCode_ImageTagDoesNotMatchDigest    ImageFailureCode = "ImageTagDoesNotMatchDigest"
	ImageFailureCode_ImageNotFound                 ImageFailureCode = "ImageNotFound"
	ImageFailureCode_MissingDigestAndTag           ImageFailureCode = "MissingDigestAndTag"
	ImageFailureCode_ImageReferencedByManifestList ImageFailureCode = "ImageReferencedByManifestList"
	ImageFailureCode_KmsError                      ImageFailureCode = "KmsError"
	ImageFailureCode_UpstreamAccessDenied          ImageFailureCode = "UpstreamAccessDenied"
	ImageFailureCode_UpstreamTooManyRequests       ImageFailureCode = "UpstreamTooManyRequests"
	ImageFailureCode_UpstreamUnavailable           ImageFailureCode = "UpstreamUnavailable"
)

type ImageTagMutability string

const (
	ImageTagMutability_MUTABLE   ImageTagMutability = "MUTABLE"
	ImageTagMutability_IMMUTABLE ImageTagMutability = "IMMUTABLE"
)

type LayerAvailability string

const (
	LayerAvailability_AVAILABLE   LayerAvailability = "AVAILABLE"
	LayerAvailability_UNAVAILABLE LayerAvailability = "UNAVAILABLE"
)

type LayerFailureCode string

const (
	LayerFailureCode_InvalidLayerDigest LayerFailureCode = "InvalidLayerDigest"
	LayerFailureCode_MissingLayerDigest LayerFailureCode = "MissingLayerDigest"
)

type LifecyclePolicyPreviewStatus string

const (
	LifecyclePolicyPreviewStatus_IN_PROGRESS LifecyclePolicyPreviewStatus = "IN_PROGRESS"
	LifecyclePolicyPreviewStatus_COMPLETE    LifecyclePolicyPreviewStatus = "COMPLETE"
	LifecyclePolicyPreviewStatus_EXPIRED     LifecyclePolicyPreviewStatus = "EXPIRED"
	LifecyclePolicyPreviewStatus_FAILED      LifecyclePolicyPreviewStatus = "FAILED"
)

type ReplicationStatus string

const (
	ReplicationStatus_IN_PROGRESS ReplicationStatus = "IN_PROGRESS"
	ReplicationStatus_COMPLETE    ReplicationStatus = "COMPLETE"
	ReplicationStatus_FAILED      ReplicationStatus = "FAILED"
)

type RepositoryFilterType string

const (
	RepositoryFilterType_PREFIX_MATCH RepositoryFilterType = "PREFIX_MATCH"
)

type ScanFrequency string

const (
	ScanFrequency_SCAN_ON_PUSH    ScanFrequency = "SCAN_ON_PUSH"
	ScanFrequency_CONTINUOUS_SCAN ScanFrequency = "CONTINUOUS_SCAN"
	ScanFrequency_MANUAL          ScanFrequency = "MANUAL"
)

type ScanStatus string

const (
	ScanStatus_IN_PROGRESS              ScanStatus = "IN_PROGRESS"
	ScanStatus_COMPLETE                 ScanStatus = "COMPLETE"
	ScanStatus_FAILED                   ScanStatus = "FAILED"
	ScanStatus_UNSUPPORTED_IMAGE        ScanStatus = "UNSUPPORTED_IMAGE"
	ScanStatus_ACTIVE                   ScanStatus = "ACTIVE"
	ScanStatus_PENDING                  ScanStatus = "PENDING"
	ScanStatus_SCAN_ELIGIBILITY_EXPIRED ScanStatus = "SCAN_ELIGIBILITY_EXPIRED"
	ScanStatus_FINDINGS_UNAVAILABLE     ScanStatus = "FINDINGS_UNAVAILABLE"
)

type ScanType string

const (
	ScanType_BASIC    ScanType = "BASIC"
	ScanType_ENHANCED ScanType = "ENHANCED"
)

type ScanningConfigurationFailureCode string

const (
	ScanningConfigurationFailureCode_REPOSITORY_NOT_FOUND ScanningConfigurationFailureCode = "REPOSITORY_NOT_FOUND"
)

type ScanningRepositoryFilterType string

const (
	ScanningRepositoryFilterType_WILDCARD ScanningRepositoryFilterType = "WILDCARD"
)

type TagStatus string

const (
	TagStatus_TAGGED   TagStatus = "TAGGED"
	TagStatus_UNTAGGED TagStatus = "UNTAGGED"
	TagStatus_ANY      TagStatus = "ANY"
)

type UpstreamRegistry string

const (
	UpstreamRegistry_ecr_public                UpstreamRegistry = "ecr-public"
	UpstreamRegistry_quay                      UpstreamRegistry = "quay"
	UpstreamRegistry_k8s                       UpstreamRegistry = "k8s"
	UpstreamRegistry_docker_hub                UpstreamRegistry = "docker-hub"
	UpstreamRegistry_github_container_registry UpstreamRegistry = "github-container-registry"
	UpstreamRegistry_azure_container_registry  UpstreamRegistry = "azure-container-registry"
)
