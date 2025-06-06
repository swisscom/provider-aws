/*
Copyright 2023 The Crossplane Authors.

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

package convert

import (
	"github.com/aws/aws-sdk-go-v2/service/elasticache/types"
)

// goverter:converter
// goverter:ignoreUnexported
// goverter:enum no
// goverter:output:file ./zz_converter.go
type Converter interface {
	DeepCopyAWSCacheCluster(*types.CacheCluster) *types.CacheCluster
}
