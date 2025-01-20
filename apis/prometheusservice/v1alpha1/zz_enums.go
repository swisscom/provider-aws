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

type AlertManagerDefinitionStatusCode string

const (
	AlertManagerDefinitionStatusCode_CREATING        AlertManagerDefinitionStatusCode = "CREATING"
	AlertManagerDefinitionStatusCode_ACTIVE          AlertManagerDefinitionStatusCode = "ACTIVE"
	AlertManagerDefinitionStatusCode_UPDATING        AlertManagerDefinitionStatusCode = "UPDATING"
	AlertManagerDefinitionStatusCode_DELETING        AlertManagerDefinitionStatusCode = "DELETING"
	AlertManagerDefinitionStatusCode_CREATION_FAILED AlertManagerDefinitionStatusCode = "CREATION_FAILED"
	AlertManagerDefinitionStatusCode_UPDATE_FAILED   AlertManagerDefinitionStatusCode = "UPDATE_FAILED"
)

type LoggingConfigurationStatusCode string

const (
	LoggingConfigurationStatusCode_CREATING        LoggingConfigurationStatusCode = "CREATING"
	LoggingConfigurationStatusCode_ACTIVE          LoggingConfigurationStatusCode = "ACTIVE"
	LoggingConfigurationStatusCode_UPDATING        LoggingConfigurationStatusCode = "UPDATING"
	LoggingConfigurationStatusCode_DELETING        LoggingConfigurationStatusCode = "DELETING"
	LoggingConfigurationStatusCode_CREATION_FAILED LoggingConfigurationStatusCode = "CREATION_FAILED"
	LoggingConfigurationStatusCode_UPDATE_FAILED   LoggingConfigurationStatusCode = "UPDATE_FAILED"
)

type RuleGroupsNamespaceStatusCode string

const (
	RuleGroupsNamespaceStatusCode_CREATING        RuleGroupsNamespaceStatusCode = "CREATING"
	RuleGroupsNamespaceStatusCode_ACTIVE          RuleGroupsNamespaceStatusCode = "ACTIVE"
	RuleGroupsNamespaceStatusCode_UPDATING        RuleGroupsNamespaceStatusCode = "UPDATING"
	RuleGroupsNamespaceStatusCode_DELETING        RuleGroupsNamespaceStatusCode = "DELETING"
	RuleGroupsNamespaceStatusCode_CREATION_FAILED RuleGroupsNamespaceStatusCode = "CREATION_FAILED"
	RuleGroupsNamespaceStatusCode_UPDATE_FAILED   RuleGroupsNamespaceStatusCode = "UPDATE_FAILED"
)

type ScraperStatusCode string

const (
	ScraperStatusCode_CREATING        ScraperStatusCode = "CREATING"
	ScraperStatusCode_ACTIVE          ScraperStatusCode = "ACTIVE"
	ScraperStatusCode_DELETING        ScraperStatusCode = "DELETING"
	ScraperStatusCode_CREATION_FAILED ScraperStatusCode = "CREATION_FAILED"
	ScraperStatusCode_DELETION_FAILED ScraperStatusCode = "DELETION_FAILED"
)

type ValidationExceptionReason string

const (
	ValidationExceptionReason_UNKNOWN_OPERATION       ValidationExceptionReason = "UNKNOWN_OPERATION"
	ValidationExceptionReason_CANNOT_PARSE            ValidationExceptionReason = "CANNOT_PARSE"
	ValidationExceptionReason_FIELD_VALIDATION_FAILED ValidationExceptionReason = "FIELD_VALIDATION_FAILED"
	ValidationExceptionReason_OTHER                   ValidationExceptionReason = "OTHER"
)

type WorkspaceStatusCode string

const (
	WorkspaceStatusCode_CREATING        WorkspaceStatusCode = "CREATING"
	WorkspaceStatusCode_ACTIVE          WorkspaceStatusCode = "ACTIVE"
	WorkspaceStatusCode_UPDATING        WorkspaceStatusCode = "UPDATING"
	WorkspaceStatusCode_DELETING        WorkspaceStatusCode = "DELETING"
	WorkspaceStatusCode_CREATION_FAILED WorkspaceStatusCode = "CREATION_FAILED"
)
