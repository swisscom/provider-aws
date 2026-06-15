/*
Copyright 2024 The Crossplane Authors.

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

// Package v1beta1ns contains namespaced (Crossplane v2) managed resource types
// for the EC2 API group.
// NOTE: DeepCopy is generated manually (not via controller-gen) because
// controller-gen v0.16.0 panics on cross-module v2 type embeddings.
// +groupName=ec2.aws.m.crossplane.io
// +versionName=v1beta1
package v1beta1ns
