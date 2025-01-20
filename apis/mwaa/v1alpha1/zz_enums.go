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

type EndpointManagement string

const (
	EndpointManagement_CUSTOMER EndpointManagement = "CUSTOMER"
	EndpointManagement_SERVICE  EndpointManagement = "SERVICE"
)

type EnvironmentStatus_SDK string

const (
	EnvironmentStatus_SDK_CREATING          EnvironmentStatus_SDK = "CREATING"
	EnvironmentStatus_SDK_CREATE_FAILED     EnvironmentStatus_SDK = "CREATE_FAILED"
	EnvironmentStatus_SDK_AVAILABLE         EnvironmentStatus_SDK = "AVAILABLE"
	EnvironmentStatus_SDK_UPDATING          EnvironmentStatus_SDK = "UPDATING"
	EnvironmentStatus_SDK_DELETING          EnvironmentStatus_SDK = "DELETING"
	EnvironmentStatus_SDK_DELETED           EnvironmentStatus_SDK = "DELETED"
	EnvironmentStatus_SDK_UNAVAILABLE       EnvironmentStatus_SDK = "UNAVAILABLE"
	EnvironmentStatus_SDK_UPDATE_FAILED     EnvironmentStatus_SDK = "UPDATE_FAILED"
	EnvironmentStatus_SDK_ROLLING_BACK      EnvironmentStatus_SDK = "ROLLING_BACK"
	EnvironmentStatus_SDK_CREATING_SNAPSHOT EnvironmentStatus_SDK = "CREATING_SNAPSHOT"
	EnvironmentStatus_SDK_PENDING           EnvironmentStatus_SDK = "PENDING"
)

type LoggingLevel string

const (
	LoggingLevel_CRITICAL LoggingLevel = "CRITICAL"
	LoggingLevel_ERROR    LoggingLevel = "ERROR"
	LoggingLevel_WARNING  LoggingLevel = "WARNING"
	LoggingLevel_INFO     LoggingLevel = "INFO"
	LoggingLevel_DEBUG    LoggingLevel = "DEBUG"
)

type Unit string

const (
	Unit_Seconds          Unit = "Seconds"
	Unit_Microseconds     Unit = "Microseconds"
	Unit_Milliseconds     Unit = "Milliseconds"
	Unit_Bytes            Unit = "Bytes"
	Unit_Kilobytes        Unit = "Kilobytes"
	Unit_Megabytes        Unit = "Megabytes"
	Unit_Gigabytes        Unit = "Gigabytes"
	Unit_Terabytes        Unit = "Terabytes"
	Unit_Bits             Unit = "Bits"
	Unit_Kilobits         Unit = "Kilobits"
	Unit_Megabits         Unit = "Megabits"
	Unit_Gigabits         Unit = "Gigabits"
	Unit_Terabits         Unit = "Terabits"
	Unit_Percent          Unit = "Percent"
	Unit_Count            Unit = "Count"
	Unit_Bytes_Second     Unit = "Bytes/Second"
	Unit_Kilobytes_Second Unit = "Kilobytes/Second"
	Unit_Megabytes_Second Unit = "Megabytes/Second"
	Unit_Gigabytes_Second Unit = "Gigabytes/Second"
	Unit_Terabytes_Second Unit = "Terabytes/Second"
	Unit_Bits_Second      Unit = "Bits/Second"
	Unit_Kilobits_Second  Unit = "Kilobits/Second"
	Unit_Megabits_Second  Unit = "Megabits/Second"
	Unit_Gigabits_Second  Unit = "Gigabits/Second"
	Unit_Terabits_Second  Unit = "Terabits/Second"
	Unit_Count_Second     Unit = "Count/Second"
	Unit_None             Unit = "None"
)

type UpdateStatus string

const (
	UpdateStatus_SUCCESS UpdateStatus = "SUCCESS"
	UpdateStatus_PENDING UpdateStatus = "PENDING"
	UpdateStatus_FAILED  UpdateStatus = "FAILED"
)

type WebserverAccessMode string

const (
	WebserverAccessMode_PRIVATE_ONLY WebserverAccessMode = "PRIVATE_ONLY"
	WebserverAccessMode_PUBLIC_ONLY  WebserverAccessMode = "PUBLIC_ONLY"
)
