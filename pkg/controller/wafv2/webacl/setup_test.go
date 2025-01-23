/*
Copyright 2025 The Crossplane Authors.

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

package webacl

import (
	"context"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/google/go-cmp/cmp"
	"testing"

	svcsdk "github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/wafv2/v1alpha1"
	"github.com/crossplane-contrib/provider-aws/pkg/clients/wafv2/fake"
)

func TestIsUpToDate(t *testing.T) {
	type want struct {
		result bool
		err    error
	}
	type args struct {
		desired  *svcapitypes.WebACL
		observed *svcsdk.GetWebACLOutput
		client   *fake.MockWAFV2Client
		cache    *cache
	}

	webAclName := "webacl"
	webAclId := "88c4049f-eba9-4666-b9a9-f6aec5b5b41b"

	visibilityConfigMetricName := "metricName"
	visibilityConfigSampledRequestsEnabled := false
	visibilityConfigCloudWatchMetricsEnabled := false

	scope := "REGIONAL"

	tag1Key := "used-by-elb"
	tag1Value := "true"
	tag1NewValue := "false"

	ruleName := "ruleName"
	rulePriority := int64(0)
	ruleAndStatement := ` {
	              "Statements": [
	                {
	                  "ByteMatchStatement":
	                    {
	                      "FieldToMatch": {
	                        "SingleHeader": {
	                          "Name": "User-Agent"
	                        }
	                      },
	                      "PositionalConstraint": "CONTAINS",
	                      "SearchString": "YmFkQm90",
	                      "TextTransformations": [
	                        {
	                          "Priority": 0,
	                          "Type": "NONE"
	                        }
	                      ]
	                    }
	                },
	                {
	                  "ByteMatchStatement":
	                    {
	                      "FieldToMatch": {
	                        "SingleHeader": {
	                          "Name": "User-AgentCustom"
	                        }
	                      },
	                      "PositionalConstraint": "CONTAINS",
	                      "SearchString": "YmFkQm90",
	                      "TextTransformations": [
	                        {
	                          "Priority": 1,
	                          "Type": "NONE"
	                        }
	                      ]
	                    }
	                }
	              ]
	            }`

	desiredRuleAndStatement0FieldToMatchSingleHeaderName := "User-Agent"
	desiredRuleAndStatement0PositionalConstraint := "CONTAINS"
	desiredRuleAndStatement0SearchString := []byte("YmFkQm90") // Base64 encoded "badBot"
	desiredRuleAndStatement0TextTransformations0Priority := int64(0)
	desiredRuleAndStatement0TextTransformations0Type := svcsdk.TextTransformationTypeNone

	desiredRuleAndStatement1FieldToMatchSingleHeaderName := "User-AgentCustom"
	desiredRuleAndStatement1PositionalConstraint := desiredRuleAndStatement0PositionalConstraint
	desiredRuleAndStatement1SearchString := desiredRuleAndStatement0SearchString
	desiredRuleAndStatement1TextTransformations0Priority := int64(1)
	desiredRuleAndStatement1TextTransformations0Type := desiredRuleAndStatement0TextTransformations0Type

	cases := map[string]struct {
		args args
		want want
	}{
		"Same": {
			args: args{
				client: &fake.MockWAFV2Client{
					MockListTagsForResource: func(input *svcsdk.ListTagsForResourceInput) (*svcsdk.ListTagsForResourceOutput, error) {
						return &svcsdk.ListTagsForResourceOutput{
							TagInfoForResource: &svcsdk.TagInfoForResource{TagList: []*svcsdk.Tag{
								{Key: &tag1Key, Value: &tag1Value},
							}},
						}, nil
					},
				},
				desired: &svcapitypes.WebACL{
					ObjectMeta: metav1.ObjectMeta{
						Name: webAclName,
						Annotations: map[string]string{
							meta.AnnotationKeyExternalName: webAclName,
						},
					},
					Spec: svcapitypes.WebACLSpec{
						ForProvider: svcapitypes.WebACLParameters{
							Region: "eu-central-1",
							VisibilityConfig: &svcapitypes.VisibilityConfig{
								MetricName:               &visibilityConfigMetricName,
								SampledRequestsEnabled:   &visibilityConfigSampledRequestsEnabled,
								CloudWatchMetricsEnabled: &visibilityConfigCloudWatchMetricsEnabled,
							},
							DefaultAction: &svcapitypes.DefaultAction{
								Allow: &svcapitypes.AllowAction{},
							},
							Scope: &scope,
							Rules: []*svcapitypes.Rule{
								{
									Name: &ruleName,
									VisibilityConfig: &svcapitypes.VisibilityConfig{
										MetricName:               &visibilityConfigMetricName,
										SampledRequestsEnabled:   &visibilityConfigSampledRequestsEnabled,
										CloudWatchMetricsEnabled: &visibilityConfigCloudWatchMetricsEnabled,
									},
									Priority: &rulePriority,
									Action: &svcapitypes.RuleAction{
										Allow: &svcapitypes.AllowAction{},
									},
									Statement: &svcapitypes.Statement{
										AndStatement: &ruleAndStatement,
									},
								},
							},
							Tags: []*svcapitypes.Tag{
								{Key: &tag1Key, Value: &tag1Value},
							},
						},
					},
				},
				observed: &svcsdk.GetWebACLOutput{
					WebACL: &svcsdk.WebACL{
						Name: &webAclName,
						Id:   &webAclId,
						VisibilityConfig: &svcsdk.VisibilityConfig{
							MetricName:               &visibilityConfigMetricName,
							SampledRequestsEnabled:   &visibilityConfigSampledRequestsEnabled,
							CloudWatchMetricsEnabled: &visibilityConfigCloudWatchMetricsEnabled,
						},
						DefaultAction: &svcsdk.DefaultAction{
							Allow: &svcsdk.AllowAction{},
						},
						Rules: []*svcsdk.Rule{
							{
								Name: &ruleName,
								VisibilityConfig: &svcsdk.VisibilityConfig{
									MetricName:               &visibilityConfigMetricName,
									SampledRequestsEnabled:   &visibilityConfigSampledRequestsEnabled,
									CloudWatchMetricsEnabled: &visibilityConfigCloudWatchMetricsEnabled,
								},
								Priority: &rulePriority,
								Action: &svcsdk.RuleAction{
									Allow: &svcsdk.AllowAction{},
								},
								Statement: &svcsdk.Statement{
									AndStatement: &svcsdk.AndStatement{
										Statements: []*svcsdk.Statement{
											{ByteMatchStatement: &svcsdk.ByteMatchStatement{
												FieldToMatch: &svcsdk.FieldToMatch{
													SingleHeader: &svcsdk.SingleHeader{
														Name: &desiredRuleAndStatement0FieldToMatchSingleHeaderName,
													},
												},
												PositionalConstraint: &desiredRuleAndStatement0PositionalConstraint,
												SearchString:         desiredRuleAndStatement0SearchString,
												TextTransformations: []*svcsdk.TextTransformation{
													{Priority: &desiredRuleAndStatement0TextTransformations0Priority, Type: &desiredRuleAndStatement0TextTransformations0Type},
												},
											},
											},
											{ByteMatchStatement: &svcsdk.ByteMatchStatement{
												FieldToMatch: &svcsdk.FieldToMatch{
													SingleHeader: &svcsdk.SingleHeader{
														Name: &desiredRuleAndStatement1FieldToMatchSingleHeaderName,
													},
												},
												PositionalConstraint: &desiredRuleAndStatement1PositionalConstraint,
												SearchString:         desiredRuleAndStatement1SearchString,
												TextTransformations: []*svcsdk.TextTransformation{
													{Priority: &desiredRuleAndStatement1TextTransformations0Priority, Type: &desiredRuleAndStatement1TextTransformations0Type},
												},
											},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: want{
				result: true,
				err:    nil,
			},
		},
		"TagsAreChanegd": {
			args: args{
				client: &fake.MockWAFV2Client{
					MockListTagsForResource: func(input *svcsdk.ListTagsForResourceInput) (*svcsdk.ListTagsForResourceOutput, error) {
						return &svcsdk.ListTagsForResourceOutput{
							TagInfoForResource: &svcsdk.TagInfoForResource{TagList: []*svcsdk.Tag{
								{Key: &tag1Key, Value: &tag1Value},
							}},
						}, nil
					},
				},
				desired: &svcapitypes.WebACL{
					ObjectMeta: metav1.ObjectMeta{
						Name: webAclName,
						Annotations: map[string]string{
							meta.AnnotationKeyExternalName: webAclName,
						},
					},
					Spec: svcapitypes.WebACLSpec{
						ForProvider: svcapitypes.WebACLParameters{
							Region: "eu-central-1",
							VisibilityConfig: &svcapitypes.VisibilityConfig{
								MetricName:               &visibilityConfigMetricName,
								SampledRequestsEnabled:   &visibilityConfigSampledRequestsEnabled,
								CloudWatchMetricsEnabled: &visibilityConfigCloudWatchMetricsEnabled,
							},
							DefaultAction: &svcapitypes.DefaultAction{
								Allow: &svcapitypes.AllowAction{},
							},
							Scope: &scope,
							Tags: []*svcapitypes.Tag{
								{Key: &tag1Key, Value: &tag1NewValue},
							},
						},
					},
				},
				observed: &svcsdk.GetWebACLOutput{
					WebACL: &svcsdk.WebACL{
						Name: &webAclName,
						Id:   &webAclId,
						VisibilityConfig: &svcsdk.VisibilityConfig{
							MetricName:               &visibilityConfigMetricName,
							SampledRequestsEnabled:   &visibilityConfigSampledRequestsEnabled,
							CloudWatchMetricsEnabled: &visibilityConfigCloudWatchMetricsEnabled,
						},
						DefaultAction: &svcsdk.DefaultAction{
							Allow: &svcsdk.AllowAction{},
						},
					},
				},
			},
			want: want{
				result: false,
				err:    nil,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := shared{cache: tc.args.cache, client: tc.args.client}
			result, funcDiff, err := s.isUpToDate(context.TODO(), tc.args.desired, tc.args.observed)
			if diff := cmp.Diff(err, tc.want.err, test.EquateErrors()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.result, result); diff != "" {
				t.Errorf("r: -want, +got:\n%s\nthe diff is %s", diff, funcDiff)
			}
		})
	}
}
