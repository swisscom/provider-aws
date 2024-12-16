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

package webacl

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/wafv2"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/wafv2/manualv1alpha1"
)

// NOTE(muvaf): We return pointers in case the function needs to start with an
// empty object, hence need to return a new pointer.

// GenerateListWebACLsInput returns input for read
// operation.
func GenerateListWebACLsInput(cr *svcapitypes.WebACL) *svcsdk.ListWebACLsInput {
	res := &svcsdk.ListWebACLsInput{}

	if cr.Spec.ForProvider.Scope != nil {
		res.SetScope(*cr.Spec.ForProvider.Scope)
	}

	return res
}

// GenerateWebACL returns the current state in the form of *svcapitypes.WebACL.
func GenerateWebACL(resp *svcsdk.ListWebACLsOutput) *svcapitypes.WebACL {
	cr := &svcapitypes.WebACL{}

	found := false
	for _, elem := range resp.WebACLs {
		if elem.ARN != nil {
			cr.Status.AtProvider.ARN = elem.ARN
		} else {
			cr.Status.AtProvider.ARN = nil
		}
		if elem.Description != nil {
			cr.Spec.ForProvider.Description = elem.Description
		} else {
			cr.Spec.ForProvider.Description = nil
		}
		if elem.Id != nil {
			cr.Status.AtProvider.ID = elem.Id
		} else {
			cr.Status.AtProvider.ID = nil
		}
		if elem.LockToken != nil {
			cr.Status.AtProvider.LockToken = elem.LockToken
		} else {
			cr.Status.AtProvider.LockToken = nil
		}
		if elem.Name != nil {
			cr.Status.AtProvider.Name = elem.Name
		} else {
			cr.Status.AtProvider.Name = nil
		}
		found = true
		break
	}
	if !found {
		return cr
	}

	return cr
}

// GenerateCreateWebACLInput returns a create input.
func GenerateCreateWebACLInput(cr *svcapitypes.WebACL) *svcsdk.CreateWebACLInput {
	res := &svcsdk.CreateWebACLInput{}

	if cr.Spec.ForProvider.AssociationConfig != nil {
		f0 := &svcsdk.AssociationConfig{}
		if cr.Spec.ForProvider.AssociationConfig.RequestBody != nil {
			f0f0 := map[string]*svcsdk.RequestBodyAssociatedResourceTypeConfig{}
			for f0f0key, f0f0valiter := range cr.Spec.ForProvider.AssociationConfig.RequestBody {
				f0f0val := &svcsdk.RequestBodyAssociatedResourceTypeConfig{}
				if f0f0valiter.DefaultSizeInspectionLimit != nil {
					f0f0val.SetDefaultSizeInspectionLimit(*f0f0valiter.DefaultSizeInspectionLimit)
				}
				f0f0[f0f0key] = f0f0val
			}
			f0.SetRequestBody(f0f0)
		}
		res.SetAssociationConfig(f0)
	}
	if cr.Spec.ForProvider.CaptchaConfig != nil {
		f1 := &svcsdk.CaptchaConfig{}
		if cr.Spec.ForProvider.CaptchaConfig.ImmunityTimeProperty != nil {
			f1f0 := &svcsdk.ImmunityTimeProperty{}
			if cr.Spec.ForProvider.CaptchaConfig.ImmunityTimeProperty.ImmunityTime != nil {
				f1f0.SetImmunityTime(*cr.Spec.ForProvider.CaptchaConfig.ImmunityTimeProperty.ImmunityTime)
			}
			f1.SetImmunityTimeProperty(f1f0)
		}
		res.SetCaptchaConfig(f1)
	}
	if cr.Spec.ForProvider.ChallengeConfig != nil {
		f2 := &svcsdk.ChallengeConfig{}
		if cr.Spec.ForProvider.ChallengeConfig.ImmunityTimeProperty != nil {
			f2f0 := &svcsdk.ImmunityTimeProperty{}
			if cr.Spec.ForProvider.ChallengeConfig.ImmunityTimeProperty.ImmunityTime != nil {
				f2f0.SetImmunityTime(*cr.Spec.ForProvider.ChallengeConfig.ImmunityTimeProperty.ImmunityTime)
			}
			f2.SetImmunityTimeProperty(f2f0)
		}
		res.SetChallengeConfig(f2)
	}
	if cr.Spec.ForProvider.CustomResponseBodies != nil {
		f3 := map[string]*svcsdk.CustomResponseBody{}
		for f3key, f3valiter := range cr.Spec.ForProvider.CustomResponseBodies {
			f3val := &svcsdk.CustomResponseBody{}
			if f3valiter.Content != nil {
				f3val.SetContent(*f3valiter.Content)
			}
			if f3valiter.ContentType != nil {
				f3val.SetContentType(*f3valiter.ContentType)
			}
			f3[f3key] = f3val
		}
		res.SetCustomResponseBodies(f3)
	}
	if cr.Spec.ForProvider.DefaultAction != nil {
		f4 := &svcsdk.DefaultAction{}
		if cr.Spec.ForProvider.DefaultAction.Allow != nil {
			f4f0 := &svcsdk.AllowAction{}
			if cr.Spec.ForProvider.DefaultAction.Allow.CustomRequestHandling != nil {
				f4f0f0 := &svcsdk.CustomRequestHandling{}
				if cr.Spec.ForProvider.DefaultAction.Allow.CustomRequestHandling.InsertHeaders != nil {
					f4f0f0f0 := []*svcsdk.CustomHTTPHeader{}
					for _, f4f0f0f0iter := range cr.Spec.ForProvider.DefaultAction.Allow.CustomRequestHandling.InsertHeaders {
						f4f0f0f0elem := &svcsdk.CustomHTTPHeader{}
						if f4f0f0f0iter.Name != nil {
							f4f0f0f0elem.SetName(*f4f0f0f0iter.Name)
						}
						if f4f0f0f0iter.Value != nil {
							f4f0f0f0elem.SetValue(*f4f0f0f0iter.Value)
						}
						f4f0f0f0 = append(f4f0f0f0, f4f0f0f0elem)
					}
					f4f0f0.SetInsertHeaders(f4f0f0f0)
				}
				f4f0.SetCustomRequestHandling(f4f0f0)
			}
			f4.SetAllow(f4f0)
		}
		if cr.Spec.ForProvider.DefaultAction.Block != nil {
			f4f1 := &svcsdk.BlockAction{}
			if cr.Spec.ForProvider.DefaultAction.Block.CustomResponse != nil {
				f4f1f0 := &svcsdk.CustomResponse{}
				if cr.Spec.ForProvider.DefaultAction.Block.CustomResponse.CustomResponseBodyKey != nil {
					f4f1f0.SetCustomResponseBodyKey(*cr.Spec.ForProvider.DefaultAction.Block.CustomResponse.CustomResponseBodyKey)
				}
				if cr.Spec.ForProvider.DefaultAction.Block.CustomResponse.ResponseCode != nil {
					f4f1f0.SetResponseCode(*cr.Spec.ForProvider.DefaultAction.Block.CustomResponse.ResponseCode)
				}
				if cr.Spec.ForProvider.DefaultAction.Block.CustomResponse.ResponseHeaders != nil {
					f4f1f0f2 := []*svcsdk.CustomHTTPHeader{}
					for _, f4f1f0f2iter := range cr.Spec.ForProvider.DefaultAction.Block.CustomResponse.ResponseHeaders {
						f4f1f0f2elem := &svcsdk.CustomHTTPHeader{}
						if f4f1f0f2iter.Name != nil {
							f4f1f0f2elem.SetName(*f4f1f0f2iter.Name)
						}
						if f4f1f0f2iter.Value != nil {
							f4f1f0f2elem.SetValue(*f4f1f0f2iter.Value)
						}
						f4f1f0f2 = append(f4f1f0f2, f4f1f0f2elem)
					}
					f4f1f0.SetResponseHeaders(f4f1f0f2)
				}
				f4f1.SetCustomResponse(f4f1f0)
			}
			f4.SetBlock(f4f1)
		}
		res.SetDefaultAction(f4)
	}
	if cr.Spec.ForProvider.Description != nil {
		res.SetDescription(*cr.Spec.ForProvider.Description)
	}
	if cr.Spec.ForProvider.Rules != nil {
		f6 := []*svcsdk.Rule{}
		for _, f6iter := range cr.Spec.ForProvider.Rules {
			f6elem := &svcsdk.Rule{}
			if f6iter.Action != nil {
				f6elemf0 := &svcsdk.RuleAction{}
				if f6iter.Action.Allow != nil {
					f6elemf0f0 := &svcsdk.AllowAction{}
					if f6iter.Action.Allow.CustomRequestHandling != nil {
						f6elemf0f0f0 := &svcsdk.CustomRequestHandling{}
						if f6iter.Action.Allow.CustomRequestHandling.InsertHeaders != nil {
							f6elemf0f0f0f0 := []*svcsdk.CustomHTTPHeader{}
							for _, f6elemf0f0f0f0iter := range f6iter.Action.Allow.CustomRequestHandling.InsertHeaders {
								f6elemf0f0f0f0elem := &svcsdk.CustomHTTPHeader{}
								if f6elemf0f0f0f0iter.Name != nil {
									f6elemf0f0f0f0elem.SetName(*f6elemf0f0f0f0iter.Name)
								}
								if f6elemf0f0f0f0iter.Value != nil {
									f6elemf0f0f0f0elem.SetValue(*f6elemf0f0f0f0iter.Value)
								}
								f6elemf0f0f0f0 = append(f6elemf0f0f0f0, f6elemf0f0f0f0elem)
							}
							f6elemf0f0f0.SetInsertHeaders(f6elemf0f0f0f0)
						}
						f6elemf0f0.SetCustomRequestHandling(f6elemf0f0f0)
					}
					f6elemf0.SetAllow(f6elemf0f0)
				}
				if f6iter.Action.Block != nil {
					f6elemf0f1 := &svcsdk.BlockAction{}
					if f6iter.Action.Block.CustomResponse != nil {
						f6elemf0f1f0 := &svcsdk.CustomResponse{}
						if f6iter.Action.Block.CustomResponse.CustomResponseBodyKey != nil {
							f6elemf0f1f0.SetCustomResponseBodyKey(*f6iter.Action.Block.CustomResponse.CustomResponseBodyKey)
						}
						if f6iter.Action.Block.CustomResponse.ResponseCode != nil {
							f6elemf0f1f0.SetResponseCode(*f6iter.Action.Block.CustomResponse.ResponseCode)
						}
						if f6iter.Action.Block.CustomResponse.ResponseHeaders != nil {
							f6elemf0f1f0f2 := []*svcsdk.CustomHTTPHeader{}
							for _, f6elemf0f1f0f2iter := range f6iter.Action.Block.CustomResponse.ResponseHeaders {
								f6elemf0f1f0f2elem := &svcsdk.CustomHTTPHeader{}
								if f6elemf0f1f0f2iter.Name != nil {
									f6elemf0f1f0f2elem.SetName(*f6elemf0f1f0f2iter.Name)
								}
								if f6elemf0f1f0f2iter.Value != nil {
									f6elemf0f1f0f2elem.SetValue(*f6elemf0f1f0f2iter.Value)
								}
								f6elemf0f1f0f2 = append(f6elemf0f1f0f2, f6elemf0f1f0f2elem)
							}
							f6elemf0f1f0.SetResponseHeaders(f6elemf0f1f0f2)
						}
						f6elemf0f1.SetCustomResponse(f6elemf0f1f0)
					}
					f6elemf0.SetBlock(f6elemf0f1)
				}
				if f6iter.Action.Captcha != nil {
					f6elemf0f2 := &svcsdk.CaptchaAction{}
					if f6iter.Action.Captcha.CustomRequestHandling != nil {
						f6elemf0f2f0 := &svcsdk.CustomRequestHandling{}
						if f6iter.Action.Captcha.CustomRequestHandling.InsertHeaders != nil {
							f6elemf0f2f0f0 := []*svcsdk.CustomHTTPHeader{}
							for _, f6elemf0f2f0f0iter := range f6iter.Action.Captcha.CustomRequestHandling.InsertHeaders {
								f6elemf0f2f0f0elem := &svcsdk.CustomHTTPHeader{}
								if f6elemf0f2f0f0iter.Name != nil {
									f6elemf0f2f0f0elem.SetName(*f6elemf0f2f0f0iter.Name)
								}
								if f6elemf0f2f0f0iter.Value != nil {
									f6elemf0f2f0f0elem.SetValue(*f6elemf0f2f0f0iter.Value)
								}
								f6elemf0f2f0f0 = append(f6elemf0f2f0f0, f6elemf0f2f0f0elem)
							}
							f6elemf0f2f0.SetInsertHeaders(f6elemf0f2f0f0)
						}
						f6elemf0f2.SetCustomRequestHandling(f6elemf0f2f0)
					}
					f6elemf0.SetCaptcha(f6elemf0f2)
				}
				if f6iter.Action.Challenge != nil {
					f6elemf0f3 := &svcsdk.ChallengeAction{}
					if f6iter.Action.Challenge.CustomRequestHandling != nil {
						f6elemf0f3f0 := &svcsdk.CustomRequestHandling{}
						if f6iter.Action.Challenge.CustomRequestHandling.InsertHeaders != nil {
							f6elemf0f3f0f0 := []*svcsdk.CustomHTTPHeader{}
							for _, f6elemf0f3f0f0iter := range f6iter.Action.Challenge.CustomRequestHandling.InsertHeaders {
								f6elemf0f3f0f0elem := &svcsdk.CustomHTTPHeader{}
								if f6elemf0f3f0f0iter.Name != nil {
									f6elemf0f3f0f0elem.SetName(*f6elemf0f3f0f0iter.Name)
								}
								if f6elemf0f3f0f0iter.Value != nil {
									f6elemf0f3f0f0elem.SetValue(*f6elemf0f3f0f0iter.Value)
								}
								f6elemf0f3f0f0 = append(f6elemf0f3f0f0, f6elemf0f3f0f0elem)
							}
							f6elemf0f3f0.SetInsertHeaders(f6elemf0f3f0f0)
						}
						f6elemf0f3.SetCustomRequestHandling(f6elemf0f3f0)
					}
					f6elemf0.SetChallenge(f6elemf0f3)
				}
				if f6iter.Action.Count != nil {
					f6elemf0f4 := &svcsdk.CountAction{}
					if f6iter.Action.Count.CustomRequestHandling != nil {
						f6elemf0f4f0 := &svcsdk.CustomRequestHandling{}
						if f6iter.Action.Count.CustomRequestHandling.InsertHeaders != nil {
							f6elemf0f4f0f0 := []*svcsdk.CustomHTTPHeader{}
							for _, f6elemf0f4f0f0iter := range f6iter.Action.Count.CustomRequestHandling.InsertHeaders {
								f6elemf0f4f0f0elem := &svcsdk.CustomHTTPHeader{}
								if f6elemf0f4f0f0iter.Name != nil {
									f6elemf0f4f0f0elem.SetName(*f6elemf0f4f0f0iter.Name)
								}
								if f6elemf0f4f0f0iter.Value != nil {
									f6elemf0f4f0f0elem.SetValue(*f6elemf0f4f0f0iter.Value)
								}
								f6elemf0f4f0f0 = append(f6elemf0f4f0f0, f6elemf0f4f0f0elem)
							}
							f6elemf0f4f0.SetInsertHeaders(f6elemf0f4f0f0)
						}
						f6elemf0f4.SetCustomRequestHandling(f6elemf0f4f0)
					}
					f6elemf0.SetCount(f6elemf0f4)
				}
				f6elem.SetAction(f6elemf0)
			}
			if f6iter.CaptchaConfig != nil {
				f6elemf1 := &svcsdk.CaptchaConfig{}
				if f6iter.CaptchaConfig.ImmunityTimeProperty != nil {
					f6elemf1f0 := &svcsdk.ImmunityTimeProperty{}
					if f6iter.CaptchaConfig.ImmunityTimeProperty.ImmunityTime != nil {
						f6elemf1f0.SetImmunityTime(*f6iter.CaptchaConfig.ImmunityTimeProperty.ImmunityTime)
					}
					f6elemf1.SetImmunityTimeProperty(f6elemf1f0)
				}
				f6elem.SetCaptchaConfig(f6elemf1)
			}
			if f6iter.ChallengeConfig != nil {
				f6elemf2 := &svcsdk.ChallengeConfig{}
				if f6iter.ChallengeConfig.ImmunityTimeProperty != nil {
					f6elemf2f0 := &svcsdk.ImmunityTimeProperty{}
					if f6iter.ChallengeConfig.ImmunityTimeProperty.ImmunityTime != nil {
						f6elemf2f0.SetImmunityTime(*f6iter.ChallengeConfig.ImmunityTimeProperty.ImmunityTime)
					}
					f6elemf2.SetImmunityTimeProperty(f6elemf2f0)
				}
				f6elem.SetChallengeConfig(f6elemf2)
			}
			if f6iter.Name != nil {
				f6elem.SetName(*f6iter.Name)
			}
			if f6iter.OverrideAction != nil {
				f6elemf4 := &svcsdk.OverrideAction{}
				if f6iter.OverrideAction.Count != nil {
					f6elemf4f0 := &svcsdk.CountAction{}
					if f6iter.OverrideAction.Count.CustomRequestHandling != nil {
						f6elemf4f0f0 := &svcsdk.CustomRequestHandling{}
						if f6iter.OverrideAction.Count.CustomRequestHandling.InsertHeaders != nil {
							f6elemf4f0f0f0 := []*svcsdk.CustomHTTPHeader{}
							for _, f6elemf4f0f0f0iter := range f6iter.OverrideAction.Count.CustomRequestHandling.InsertHeaders {
								f6elemf4f0f0f0elem := &svcsdk.CustomHTTPHeader{}
								if f6elemf4f0f0f0iter.Name != nil {
									f6elemf4f0f0f0elem.SetName(*f6elemf4f0f0f0iter.Name)
								}
								if f6elemf4f0f0f0iter.Value != nil {
									f6elemf4f0f0f0elem.SetValue(*f6elemf4f0f0f0iter.Value)
								}
								f6elemf4f0f0f0 = append(f6elemf4f0f0f0, f6elemf4f0f0f0elem)
							}
							f6elemf4f0f0.SetInsertHeaders(f6elemf4f0f0f0)
						}
						f6elemf4f0.SetCustomRequestHandling(f6elemf4f0f0)
					}
					f6elemf4.SetCount(f6elemf4f0)
				}
				if f6iter.OverrideAction.None != nil {
					f6elemf4f1 := &svcsdk.NoneAction{}
					f6elemf4.SetNone(f6elemf4f1)
				}
				f6elem.SetOverrideAction(f6elemf4)
			}
			if f6iter.Priority != nil {
				f6elem.SetPriority(*f6iter.Priority)
			}
			if f6iter.RuleLabels != nil {
				f6elemf6 := []*svcsdk.Label{}
				for _, f6elemf6iter := range f6iter.RuleLabels {
					f6elemf6elem := &svcsdk.Label{}
					if f6elemf6iter.Name != nil {
						f6elemf6elem.SetName(*f6elemf6iter.Name)
					}
					f6elemf6 = append(f6elemf6, f6elemf6elem)
				}
				f6elem.SetRuleLabels(f6elemf6)
			}
			if f6iter.Statement != nil {
				f6elemf7 := &svcsdk.Statement{}
				if f6iter.Statement.ByteMatchStatement != nil {
					f6elemf7f1 := &svcsdk.ByteMatchStatement{}
					if f6iter.Statement.ByteMatchStatement.FieldToMatch != nil {
						f6elemf7f1f0 := &svcsdk.FieldToMatch{}
						if f6iter.Statement.ByteMatchStatement.FieldToMatch.AllQueryArguments != nil {
							f6elemf7f1f0f0 := &svcsdk.AllQueryArguments{}
							f6elemf7f1f0.SetAllQueryArguments(f6elemf7f1f0f0)
						}
						if f6iter.Statement.ByteMatchStatement.FieldToMatch.Body != nil {
							f6elemf7f1f0f1 := &svcsdk.Body{}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.Body.OversizeHandling != nil {
								f6elemf7f1f0f1.SetOversizeHandling(*f6iter.Statement.ByteMatchStatement.FieldToMatch.Body.OversizeHandling)
							}
							f6elemf7f1f0.SetBody(f6elemf7f1f0f1)
						}
						if f6iter.Statement.ByteMatchStatement.FieldToMatch.Cookies != nil {
							f6elemf7f1f0f2 := &svcsdk.Cookies{}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern != nil {
								f6elemf7f1f0f2f0 := &svcsdk.CookieMatchPattern{}
								if f6iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern.All != nil {
									f6elemf7f1f0f2f0f0 := &svcsdk.All{}
									f6elemf7f1f0f2f0.SetAll(f6elemf7f1f0f2f0f0)
								}
								if f6iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies != nil {
									f6elemf7f1f0f2f0f1 := []*string{}
									for _, f6elemf7f1f0f2f0f1iter := range f6iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies {
										var f6elemf7f1f0f2f0f1elem string
										f6elemf7f1f0f2f0f1elem = *f6elemf7f1f0f2f0f1iter
										f6elemf7f1f0f2f0f1 = append(f6elemf7f1f0f2f0f1, &f6elemf7f1f0f2f0f1elem)
									}
									f6elemf7f1f0f2f0.SetExcludedCookies(f6elemf7f1f0f2f0f1)
								}
								if f6iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies != nil {
									f6elemf7f1f0f2f0f2 := []*string{}
									for _, f6elemf7f1f0f2f0f2iter := range f6iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies {
										var f6elemf7f1f0f2f0f2elem string
										f6elemf7f1f0f2f0f2elem = *f6elemf7f1f0f2f0f2iter
										f6elemf7f1f0f2f0f2 = append(f6elemf7f1f0f2f0f2, &f6elemf7f1f0f2f0f2elem)
									}
									f6elemf7f1f0f2f0.SetIncludedCookies(f6elemf7f1f0f2f0f2)
								}
								f6elemf7f1f0f2.SetMatchPattern(f6elemf7f1f0f2f0)
							}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchScope != nil {
								f6elemf7f1f0f2.SetMatchScope(*f6iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchScope)
							}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.OversizeHandling != nil {
								f6elemf7f1f0f2.SetOversizeHandling(*f6iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.OversizeHandling)
							}
							f6elemf7f1f0.SetCookies(f6elemf7f1f0f2)
						}
						if f6iter.Statement.ByteMatchStatement.FieldToMatch.HeaderOrder != nil {
							f6elemf7f1f0f3 := &svcsdk.HeaderOrder{}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling != nil {
								f6elemf7f1f0f3.SetOversizeHandling(*f6iter.Statement.ByteMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling)
							}
							f6elemf7f1f0.SetHeaderOrder(f6elemf7f1f0f3)
						}
						if f6iter.Statement.ByteMatchStatement.FieldToMatch.Headers != nil {
							f6elemf7f1f0f4 := &svcsdk.Headers{}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern != nil {
								f6elemf7f1f0f4f0 := &svcsdk.HeaderMatchPattern{}
								if f6iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern.All != nil {
									f6elemf7f1f0f4f0f0 := &svcsdk.All{}
									f6elemf7f1f0f4f0.SetAll(f6elemf7f1f0f4f0f0)
								}
								if f6iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders != nil {
									f6elemf7f1f0f4f0f1 := []*string{}
									for _, f6elemf7f1f0f4f0f1iter := range f6iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders {
										var f6elemf7f1f0f4f0f1elem string
										f6elemf7f1f0f4f0f1elem = *f6elemf7f1f0f4f0f1iter
										f6elemf7f1f0f4f0f1 = append(f6elemf7f1f0f4f0f1, &f6elemf7f1f0f4f0f1elem)
									}
									f6elemf7f1f0f4f0.SetExcludedHeaders(f6elemf7f1f0f4f0f1)
								}
								if f6iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders != nil {
									f6elemf7f1f0f4f0f2 := []*string{}
									for _, f6elemf7f1f0f4f0f2iter := range f6iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders {
										var f6elemf7f1f0f4f0f2elem string
										f6elemf7f1f0f4f0f2elem = *f6elemf7f1f0f4f0f2iter
										f6elemf7f1f0f4f0f2 = append(f6elemf7f1f0f4f0f2, &f6elemf7f1f0f4f0f2elem)
									}
									f6elemf7f1f0f4f0.SetIncludedHeaders(f6elemf7f1f0f4f0f2)
								}
								f6elemf7f1f0f4.SetMatchPattern(f6elemf7f1f0f4f0)
							}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchScope != nil {
								f6elemf7f1f0f4.SetMatchScope(*f6iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchScope)
							}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.Headers.OversizeHandling != nil {
								f6elemf7f1f0f4.SetOversizeHandling(*f6iter.Statement.ByteMatchStatement.FieldToMatch.Headers.OversizeHandling)
							}
							f6elemf7f1f0.SetHeaders(f6elemf7f1f0f4)
						}
						if f6iter.Statement.ByteMatchStatement.FieldToMatch.JA3Fingerprint != nil {
							f6elemf7f1f0f5 := &svcsdk.JA3Fingerprint{}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior != nil {
								f6elemf7f1f0f5.SetFallbackBehavior(*f6iter.Statement.ByteMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior)
							}
							f6elemf7f1f0.SetJA3Fingerprint(f6elemf7f1f0f5)
						}
						if f6iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody != nil {
							f6elemf7f1f0f6 := &svcsdk.JsonBody{}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior != nil {
								f6elemf7f1f0f6.SetInvalidFallbackBehavior(*f6iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior)
							}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.MatchPattern != nil {
								f6elemf7f1f0f6f1 := &svcsdk.JsonMatchPattern{}
								if f6iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.MatchPattern.All != nil {
									f6elemf7f1f0f6f1f0 := &svcsdk.All{}
									f6elemf7f1f0f6f1.SetAll(f6elemf7f1f0f6f1f0)
								}
								if f6iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths != nil {
									f6elemf7f1f0f6f1f1 := []*string{}
									for _, f6elemf7f1f0f6f1f1iter := range f6iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths {
										var f6elemf7f1f0f6f1f1elem string
										f6elemf7f1f0f6f1f1elem = *f6elemf7f1f0f6f1f1iter
										f6elemf7f1f0f6f1f1 = append(f6elemf7f1f0f6f1f1, &f6elemf7f1f0f6f1f1elem)
									}
									f6elemf7f1f0f6f1.SetIncludedPaths(f6elemf7f1f0f6f1f1)
								}
								f6elemf7f1f0f6.SetMatchPattern(f6elemf7f1f0f6f1)
							}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.MatchScope != nil {
								f6elemf7f1f0f6.SetMatchScope(*f6iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.MatchScope)
							}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.OversizeHandling != nil {
								f6elemf7f1f0f6.SetOversizeHandling(*f6iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.OversizeHandling)
							}
							f6elemf7f1f0.SetJsonBody(f6elemf7f1f0f6)
						}
						if f6iter.Statement.ByteMatchStatement.FieldToMatch.Method != nil {
							f6elemf7f1f0f7 := &svcsdk.Method{}
							f6elemf7f1f0.SetMethod(f6elemf7f1f0f7)
						}
						if f6iter.Statement.ByteMatchStatement.FieldToMatch.QueryString != nil {
							f6elemf7f1f0f8 := &svcsdk.QueryString{}
							f6elemf7f1f0.SetQueryString(f6elemf7f1f0f8)
						}
						if f6iter.Statement.ByteMatchStatement.FieldToMatch.SingleHeader != nil {
							f6elemf7f1f0f9 := &svcsdk.SingleHeader{}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.SingleHeader.Name != nil {
								f6elemf7f1f0f9.SetName(*f6iter.Statement.ByteMatchStatement.FieldToMatch.SingleHeader.Name)
							}
							f6elemf7f1f0.SetSingleHeader(f6elemf7f1f0f9)
						}
						if f6iter.Statement.ByteMatchStatement.FieldToMatch.SingleQueryArgument != nil {
							f6elemf7f1f0f10 := &svcsdk.SingleQueryArgument{}
							if f6iter.Statement.ByteMatchStatement.FieldToMatch.SingleQueryArgument.Name != nil {
								f6elemf7f1f0f10.SetName(*f6iter.Statement.ByteMatchStatement.FieldToMatch.SingleQueryArgument.Name)
							}
							f6elemf7f1f0.SetSingleQueryArgument(f6elemf7f1f0f10)
						}
						if f6iter.Statement.ByteMatchStatement.FieldToMatch.URIPath != nil {
							f6elemf7f1f0f11 := &svcsdk.UriPath{}
							f6elemf7f1f0.SetUriPath(f6elemf7f1f0f11)
						}
						f6elemf7f1.SetFieldToMatch(f6elemf7f1f0)
					}
					if f6iter.Statement.ByteMatchStatement.PositionalConstraint != nil {
						f6elemf7f1.SetPositionalConstraint(*f6iter.Statement.ByteMatchStatement.PositionalConstraint)
					}
					if f6iter.Statement.ByteMatchStatement.SearchString != nil {
						f6elemf7f1.SetSearchString(f6iter.Statement.ByteMatchStatement.SearchString)
					}
					if f6iter.Statement.ByteMatchStatement.TextTransformations != nil {
						f6elemf7f1f3 := []*svcsdk.TextTransformation{}
						for _, f6elemf7f1f3iter := range f6iter.Statement.ByteMatchStatement.TextTransformations {
							f6elemf7f1f3elem := &svcsdk.TextTransformation{}
							if f6elemf7f1f3iter.Priority != nil {
								f6elemf7f1f3elem.SetPriority(*f6elemf7f1f3iter.Priority)
							}
							if f6elemf7f1f3iter.Type != nil {
								f6elemf7f1f3elem.SetType(*f6elemf7f1f3iter.Type)
							}
							f6elemf7f1f3 = append(f6elemf7f1f3, f6elemf7f1f3elem)
						}
						f6elemf7f1.SetTextTransformations(f6elemf7f1f3)
					}
					f6elemf7.SetByteMatchStatement(f6elemf7f1)
				}
				if f6iter.Statement.GeoMatchStatement != nil {
					f6elemf7f2 := &svcsdk.GeoMatchStatement{}
					if f6iter.Statement.GeoMatchStatement.CountryCodes != nil {
						f6elemf7f2f0 := []*string{}
						for _, f6elemf7f2f0iter := range f6iter.Statement.GeoMatchStatement.CountryCodes {
							var f6elemf7f2f0elem string
							f6elemf7f2f0elem = *f6elemf7f2f0iter
							f6elemf7f2f0 = append(f6elemf7f2f0, &f6elemf7f2f0elem)
						}
						f6elemf7f2.SetCountryCodes(f6elemf7f2f0)
					}
					if f6iter.Statement.GeoMatchStatement.ForwardedIPConfig != nil {
						f6elemf7f2f1 := &svcsdk.ForwardedIPConfig{}
						if f6iter.Statement.GeoMatchStatement.ForwardedIPConfig.FallbackBehavior != nil {
							f6elemf7f2f1.SetFallbackBehavior(*f6iter.Statement.GeoMatchStatement.ForwardedIPConfig.FallbackBehavior)
						}
						if f6iter.Statement.GeoMatchStatement.ForwardedIPConfig.HeaderName != nil {
							f6elemf7f2f1.SetHeaderName(*f6iter.Statement.GeoMatchStatement.ForwardedIPConfig.HeaderName)
						}
						f6elemf7f2.SetForwardedIPConfig(f6elemf7f2f1)
					}
					f6elemf7.SetGeoMatchStatement(f6elemf7f2)
				}
				if f6iter.Statement.IPSetReferenceStatement != nil {
					f6elemf7f3 := &svcsdk.IPSetReferenceStatement{}
					if f6iter.Statement.IPSetReferenceStatement.ARN != nil {
						f6elemf7f3.SetARN(*f6iter.Statement.IPSetReferenceStatement.ARN)
					}
					if f6iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig != nil {
						f6elemf7f3f1 := &svcsdk.IPSetForwardedIPConfig{}
						if f6iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.FallbackBehavior != nil {
							f6elemf7f3f1.SetFallbackBehavior(*f6iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.FallbackBehavior)
						}
						if f6iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.HeaderName != nil {
							f6elemf7f3f1.SetHeaderName(*f6iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.HeaderName)
						}
						if f6iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.Position != nil {
							f6elemf7f3f1.SetPosition(*f6iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.Position)
						}
						f6elemf7f3.SetIPSetForwardedIPConfig(f6elemf7f3f1)
					}
					f6elemf7.SetIPSetReferenceStatement(f6elemf7f3)
				}
				if f6iter.Statement.LabelMatchStatement != nil {
					f6elemf7f4 := &svcsdk.LabelMatchStatement{}
					if f6iter.Statement.LabelMatchStatement.Key != nil {
						f6elemf7f4.SetKey(*f6iter.Statement.LabelMatchStatement.Key)
					}
					if f6iter.Statement.LabelMatchStatement.Scope != nil {
						f6elemf7f4.SetScope(*f6iter.Statement.LabelMatchStatement.Scope)
					}
					f6elemf7.SetLabelMatchStatement(f6elemf7f4)
				}
				if f6iter.Statement.ManagedRuleGroupStatement != nil {
					f6elemf7f5 := &svcsdk.ManagedRuleGroupStatement{}
					if f6iter.Statement.ManagedRuleGroupStatement.ExcludedRules != nil {
						f6elemf7f5f0 := []*svcsdk.ExcludedRule{}
						for _, f6elemf7f5f0iter := range f6iter.Statement.ManagedRuleGroupStatement.ExcludedRules {
							f6elemf7f5f0elem := &svcsdk.ExcludedRule{}
							if f6elemf7f5f0iter.Name != nil {
								f6elemf7f5f0elem.SetName(*f6elemf7f5f0iter.Name)
							}
							f6elemf7f5f0 = append(f6elemf7f5f0, f6elemf7f5f0elem)
						}
						f6elemf7f5.SetExcludedRules(f6elemf7f5f0)
					}
					if f6iter.Statement.ManagedRuleGroupStatement.ManagedRuleGroupConfigs != nil {
						f6elemf7f5f1 := []*svcsdk.ManagedRuleGroupConfig{}
						for _, f6elemf7f5f1iter := range f6iter.Statement.ManagedRuleGroupStatement.ManagedRuleGroupConfigs {
							f6elemf7f5f1elem := &svcsdk.ManagedRuleGroupConfig{}
							if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet != nil {
								f6elemf7f5f1elemf0 := &svcsdk.AWSManagedRulesACFPRuleSet{}
								if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.CreationPath != nil {
									f6elemf7f5f1elemf0.SetCreationPath(*f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.CreationPath)
								}
								if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.EnableRegexInPath != nil {
									f6elemf7f5f1elemf0.SetEnableRegexInPath(*f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.EnableRegexInPath)
								}
								if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RegistrationPagePath != nil {
									f6elemf7f5f1elemf0.SetRegistrationPagePath(*f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RegistrationPagePath)
								}
								if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection != nil {
									f6elemf7f5f1elemf0f3 := &svcsdk.RequestInspectionACFP{}
									if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.AddressFields != nil {
										f6elemf7f5f1elemf0f3f0 := []*svcsdk.AddressField{}
										for _, f6elemf7f5f1elemf0f3f0iter := range f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.AddressFields {
											f6elemf7f5f1elemf0f3f0elem := &svcsdk.AddressField{}
											if f6elemf7f5f1elemf0f3f0iter.Identifier != nil {
												f6elemf7f5f1elemf0f3f0elem.SetIdentifier(*f6elemf7f5f1elemf0f3f0iter.Identifier)
											}
											f6elemf7f5f1elemf0f3f0 = append(f6elemf7f5f1elemf0f3f0, f6elemf7f5f1elemf0f3f0elem)
										}
										f6elemf7f5f1elemf0f3.SetAddressFields(f6elemf7f5f1elemf0f3f0)
									}
									if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.EmailField != nil {
										f6elemf7f5f1elemf0f3f1 := &svcsdk.EmailField{}
										if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.EmailField.Identifier != nil {
											f6elemf7f5f1elemf0f3f1.SetIdentifier(*f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.EmailField.Identifier)
										}
										f6elemf7f5f1elemf0f3.SetEmailField(f6elemf7f5f1elemf0f3f1)
									}
									if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PasswordField != nil {
										f6elemf7f5f1elemf0f3f2 := &svcsdk.PasswordField{}
										if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PasswordField.Identifier != nil {
											f6elemf7f5f1elemf0f3f2.SetIdentifier(*f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PasswordField.Identifier)
										}
										f6elemf7f5f1elemf0f3.SetPasswordField(f6elemf7f5f1elemf0f3f2)
									}
									if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PayloadType != nil {
										f6elemf7f5f1elemf0f3.SetPayloadType(*f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PayloadType)
									}
									if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PhoneNumberFields != nil {
										f6elemf7f5f1elemf0f3f4 := []*svcsdk.PhoneNumberField{}
										for _, f6elemf7f5f1elemf0f3f4iter := range f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PhoneNumberFields {
											f6elemf7f5f1elemf0f3f4elem := &svcsdk.PhoneNumberField{}
											if f6elemf7f5f1elemf0f3f4iter.Identifier != nil {
												f6elemf7f5f1elemf0f3f4elem.SetIdentifier(*f6elemf7f5f1elemf0f3f4iter.Identifier)
											}
											f6elemf7f5f1elemf0f3f4 = append(f6elemf7f5f1elemf0f3f4, f6elemf7f5f1elemf0f3f4elem)
										}
										f6elemf7f5f1elemf0f3.SetPhoneNumberFields(f6elemf7f5f1elemf0f3f4)
									}
									if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.UsernameField != nil {
										f6elemf7f5f1elemf0f3f5 := &svcsdk.UsernameField{}
										if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.UsernameField.Identifier != nil {
											f6elemf7f5f1elemf0f3f5.SetIdentifier(*f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.UsernameField.Identifier)
										}
										f6elemf7f5f1elemf0f3.SetUsernameField(f6elemf7f5f1elemf0f3f5)
									}
									f6elemf7f5f1elemf0.SetRequestInspection(f6elemf7f5f1elemf0f3)
								}
								if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection != nil {
									f6elemf7f5f1elemf0f4 := &svcsdk.ResponseInspection{}
									if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains != nil {
										f6elemf7f5f1elemf0f4f0 := &svcsdk.ResponseInspectionBodyContains{}
										if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains.FailureStrings != nil {
											f6elemf7f5f1elemf0f4f0f0 := []*string{}
											for _, f6elemf7f5f1elemf0f4f0f0iter := range f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains.FailureStrings {
												var f6elemf7f5f1elemf0f4f0f0elem string
												f6elemf7f5f1elemf0f4f0f0elem = *f6elemf7f5f1elemf0f4f0f0iter
												f6elemf7f5f1elemf0f4f0f0 = append(f6elemf7f5f1elemf0f4f0f0, &f6elemf7f5f1elemf0f4f0f0elem)
											}
											f6elemf7f5f1elemf0f4f0.SetFailureStrings(f6elemf7f5f1elemf0f4f0f0)
										}
										if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains.SuccessStrings != nil {
											f6elemf7f5f1elemf0f4f0f1 := []*string{}
											for _, f6elemf7f5f1elemf0f4f0f1iter := range f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains.SuccessStrings {
												var f6elemf7f5f1elemf0f4f0f1elem string
												f6elemf7f5f1elemf0f4f0f1elem = *f6elemf7f5f1elemf0f4f0f1iter
												f6elemf7f5f1elemf0f4f0f1 = append(f6elemf7f5f1elemf0f4f0f1, &f6elemf7f5f1elemf0f4f0f1elem)
											}
											f6elemf7f5f1elemf0f4f0.SetSuccessStrings(f6elemf7f5f1elemf0f4f0f1)
										}
										f6elemf7f5f1elemf0f4.SetBodyContains(f6elemf7f5f1elemf0f4f0)
									}
									if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header != nil {
										f6elemf7f5f1elemf0f4f1 := &svcsdk.ResponseInspectionHeader{}
										if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.FailureValues != nil {
											f6elemf7f5f1elemf0f4f1f0 := []*string{}
											for _, f6elemf7f5f1elemf0f4f1f0iter := range f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.FailureValues {
												var f6elemf7f5f1elemf0f4f1f0elem string
												f6elemf7f5f1elemf0f4f1f0elem = *f6elemf7f5f1elemf0f4f1f0iter
												f6elemf7f5f1elemf0f4f1f0 = append(f6elemf7f5f1elemf0f4f1f0, &f6elemf7f5f1elemf0f4f1f0elem)
											}
											f6elemf7f5f1elemf0f4f1.SetFailureValues(f6elemf7f5f1elemf0f4f1f0)
										}
										if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.Name != nil {
											f6elemf7f5f1elemf0f4f1.SetName(*f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.Name)
										}
										if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.SuccessValues != nil {
											f6elemf7f5f1elemf0f4f1f2 := []*string{}
											for _, f6elemf7f5f1elemf0f4f1f2iter := range f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.SuccessValues {
												var f6elemf7f5f1elemf0f4f1f2elem string
												f6elemf7f5f1elemf0f4f1f2elem = *f6elemf7f5f1elemf0f4f1f2iter
												f6elemf7f5f1elemf0f4f1f2 = append(f6elemf7f5f1elemf0f4f1f2, &f6elemf7f5f1elemf0f4f1f2elem)
											}
											f6elemf7f5f1elemf0f4f1.SetSuccessValues(f6elemf7f5f1elemf0f4f1f2)
										}
										f6elemf7f5f1elemf0f4.SetHeader(f6elemf7f5f1elemf0f4f1)
									}
									if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON != nil {
										f6elemf7f5f1elemf0f4f2 := &svcsdk.ResponseInspectionJson{}
										if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON.FailureValues != nil {
											f6elemf7f5f1elemf0f4f2f0 := []*string{}
											for _, f6elemf7f5f1elemf0f4f2f0iter := range f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON.FailureValues {
												var f6elemf7f5f1elemf0f4f2f0elem string
												f6elemf7f5f1elemf0f4f2f0elem = *f6elemf7f5f1elemf0f4f2f0iter
												f6elemf7f5f1elemf0f4f2f0 = append(f6elemf7f5f1elemf0f4f2f0, &f6elemf7f5f1elemf0f4f2f0elem)
											}
											f6elemf7f5f1elemf0f4f2.SetFailureValues(f6elemf7f5f1elemf0f4f2f0)
										}
										if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON.Identifier != nil {
											f6elemf7f5f1elemf0f4f2.SetIdentifier(*f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON.Identifier)
										}
										if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON.SuccessValues != nil {
											f6elemf7f5f1elemf0f4f2f2 := []*string{}
											for _, f6elemf7f5f1elemf0f4f2f2iter := range f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON.SuccessValues {
												var f6elemf7f5f1elemf0f4f2f2elem string
												f6elemf7f5f1elemf0f4f2f2elem = *f6elemf7f5f1elemf0f4f2f2iter
												f6elemf7f5f1elemf0f4f2f2 = append(f6elemf7f5f1elemf0f4f2f2, &f6elemf7f5f1elemf0f4f2f2elem)
											}
											f6elemf7f5f1elemf0f4f2.SetSuccessValues(f6elemf7f5f1elemf0f4f2f2)
										}
										f6elemf7f5f1elemf0f4.SetJson(f6elemf7f5f1elemf0f4f2)
									}
									if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.StatusCode != nil {
										f6elemf7f5f1elemf0f4f3 := &svcsdk.ResponseInspectionStatusCode{}
										if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.StatusCode.FailureCodes != nil {
											f6elemf7f5f1elemf0f4f3f0 := []*int64{}
											for _, f6elemf7f5f1elemf0f4f3f0iter := range f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.StatusCode.FailureCodes {
												var f6elemf7f5f1elemf0f4f3f0elem int64
												f6elemf7f5f1elemf0f4f3f0elem = *f6elemf7f5f1elemf0f4f3f0iter
												f6elemf7f5f1elemf0f4f3f0 = append(f6elemf7f5f1elemf0f4f3f0, &f6elemf7f5f1elemf0f4f3f0elem)
											}
											f6elemf7f5f1elemf0f4f3.SetFailureCodes(f6elemf7f5f1elemf0f4f3f0)
										}
										if f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.StatusCode.SuccessCodes != nil {
											f6elemf7f5f1elemf0f4f3f1 := []*int64{}
											for _, f6elemf7f5f1elemf0f4f3f1iter := range f6elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.StatusCode.SuccessCodes {
												var f6elemf7f5f1elemf0f4f3f1elem int64
												f6elemf7f5f1elemf0f4f3f1elem = *f6elemf7f5f1elemf0f4f3f1iter
												f6elemf7f5f1elemf0f4f3f1 = append(f6elemf7f5f1elemf0f4f3f1, &f6elemf7f5f1elemf0f4f3f1elem)
											}
											f6elemf7f5f1elemf0f4f3.SetSuccessCodes(f6elemf7f5f1elemf0f4f3f1)
										}
										f6elemf7f5f1elemf0f4.SetStatusCode(f6elemf7f5f1elemf0f4f3)
									}
									f6elemf7f5f1elemf0.SetResponseInspection(f6elemf7f5f1elemf0f4)
								}
								f6elemf7f5f1elem.SetAWSManagedRulesACFPRuleSet(f6elemf7f5f1elemf0)
							}
							if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet != nil {
								f6elemf7f5f1elemf1 := &svcsdk.AWSManagedRulesATPRuleSet{}
								if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.EnableRegexInPath != nil {
									f6elemf7f5f1elemf1.SetEnableRegexInPath(*f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.EnableRegexInPath)
								}
								if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.LoginPath != nil {
									f6elemf7f5f1elemf1.SetLoginPath(*f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.LoginPath)
								}
								if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection != nil {
									f6elemf7f5f1elemf1f2 := &svcsdk.RequestInspection{}
									if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.PasswordField != nil {
										f6elemf7f5f1elemf1f2f0 := &svcsdk.PasswordField{}
										if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.PasswordField.Identifier != nil {
											f6elemf7f5f1elemf1f2f0.SetIdentifier(*f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.PasswordField.Identifier)
										}
										f6elemf7f5f1elemf1f2.SetPasswordField(f6elemf7f5f1elemf1f2f0)
									}
									if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.PayloadType != nil {
										f6elemf7f5f1elemf1f2.SetPayloadType(*f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.PayloadType)
									}
									if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.UsernameField != nil {
										f6elemf7f5f1elemf1f2f2 := &svcsdk.UsernameField{}
										if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.UsernameField.Identifier != nil {
											f6elemf7f5f1elemf1f2f2.SetIdentifier(*f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.UsernameField.Identifier)
										}
										f6elemf7f5f1elemf1f2.SetUsernameField(f6elemf7f5f1elemf1f2f2)
									}
									f6elemf7f5f1elemf1.SetRequestInspection(f6elemf7f5f1elemf1f2)
								}
								if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection != nil {
									f6elemf7f5f1elemf1f3 := &svcsdk.ResponseInspection{}
									if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.BodyContains != nil {
										f6elemf7f5f1elemf1f3f0 := &svcsdk.ResponseInspectionBodyContains{}
										if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.BodyContains.FailureStrings != nil {
											f6elemf7f5f1elemf1f3f0f0 := []*string{}
											for _, f6elemf7f5f1elemf1f3f0f0iter := range f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.BodyContains.FailureStrings {
												var f6elemf7f5f1elemf1f3f0f0elem string
												f6elemf7f5f1elemf1f3f0f0elem = *f6elemf7f5f1elemf1f3f0f0iter
												f6elemf7f5f1elemf1f3f0f0 = append(f6elemf7f5f1elemf1f3f0f0, &f6elemf7f5f1elemf1f3f0f0elem)
											}
											f6elemf7f5f1elemf1f3f0.SetFailureStrings(f6elemf7f5f1elemf1f3f0f0)
										}
										if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.BodyContains.SuccessStrings != nil {
											f6elemf7f5f1elemf1f3f0f1 := []*string{}
											for _, f6elemf7f5f1elemf1f3f0f1iter := range f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.BodyContains.SuccessStrings {
												var f6elemf7f5f1elemf1f3f0f1elem string
												f6elemf7f5f1elemf1f3f0f1elem = *f6elemf7f5f1elemf1f3f0f1iter
												f6elemf7f5f1elemf1f3f0f1 = append(f6elemf7f5f1elemf1f3f0f1, &f6elemf7f5f1elemf1f3f0f1elem)
											}
											f6elemf7f5f1elemf1f3f0.SetSuccessStrings(f6elemf7f5f1elemf1f3f0f1)
										}
										f6elemf7f5f1elemf1f3.SetBodyContains(f6elemf7f5f1elemf1f3f0)
									}
									if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header != nil {
										f6elemf7f5f1elemf1f3f1 := &svcsdk.ResponseInspectionHeader{}
										if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header.FailureValues != nil {
											f6elemf7f5f1elemf1f3f1f0 := []*string{}
											for _, f6elemf7f5f1elemf1f3f1f0iter := range f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header.FailureValues {
												var f6elemf7f5f1elemf1f3f1f0elem string
												f6elemf7f5f1elemf1f3f1f0elem = *f6elemf7f5f1elemf1f3f1f0iter
												f6elemf7f5f1elemf1f3f1f0 = append(f6elemf7f5f1elemf1f3f1f0, &f6elemf7f5f1elemf1f3f1f0elem)
											}
											f6elemf7f5f1elemf1f3f1.SetFailureValues(f6elemf7f5f1elemf1f3f1f0)
										}
										if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header.Name != nil {
											f6elemf7f5f1elemf1f3f1.SetName(*f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header.Name)
										}
										if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header.SuccessValues != nil {
											f6elemf7f5f1elemf1f3f1f2 := []*string{}
											for _, f6elemf7f5f1elemf1f3f1f2iter := range f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header.SuccessValues {
												var f6elemf7f5f1elemf1f3f1f2elem string
												f6elemf7f5f1elemf1f3f1f2elem = *f6elemf7f5f1elemf1f3f1f2iter
												f6elemf7f5f1elemf1f3f1f2 = append(f6elemf7f5f1elemf1f3f1f2, &f6elemf7f5f1elemf1f3f1f2elem)
											}
											f6elemf7f5f1elemf1f3f1.SetSuccessValues(f6elemf7f5f1elemf1f3f1f2)
										}
										f6elemf7f5f1elemf1f3.SetHeader(f6elemf7f5f1elemf1f3f1)
									}
									if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON != nil {
										f6elemf7f5f1elemf1f3f2 := &svcsdk.ResponseInspectionJson{}
										if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON.FailureValues != nil {
											f6elemf7f5f1elemf1f3f2f0 := []*string{}
											for _, f6elemf7f5f1elemf1f3f2f0iter := range f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON.FailureValues {
												var f6elemf7f5f1elemf1f3f2f0elem string
												f6elemf7f5f1elemf1f3f2f0elem = *f6elemf7f5f1elemf1f3f2f0iter
												f6elemf7f5f1elemf1f3f2f0 = append(f6elemf7f5f1elemf1f3f2f0, &f6elemf7f5f1elemf1f3f2f0elem)
											}
											f6elemf7f5f1elemf1f3f2.SetFailureValues(f6elemf7f5f1elemf1f3f2f0)
										}
										if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON.Identifier != nil {
											f6elemf7f5f1elemf1f3f2.SetIdentifier(*f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON.Identifier)
										}
										if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON.SuccessValues != nil {
											f6elemf7f5f1elemf1f3f2f2 := []*string{}
											for _, f6elemf7f5f1elemf1f3f2f2iter := range f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON.SuccessValues {
												var f6elemf7f5f1elemf1f3f2f2elem string
												f6elemf7f5f1elemf1f3f2f2elem = *f6elemf7f5f1elemf1f3f2f2iter
												f6elemf7f5f1elemf1f3f2f2 = append(f6elemf7f5f1elemf1f3f2f2, &f6elemf7f5f1elemf1f3f2f2elem)
											}
											f6elemf7f5f1elemf1f3f2.SetSuccessValues(f6elemf7f5f1elemf1f3f2f2)
										}
										f6elemf7f5f1elemf1f3.SetJson(f6elemf7f5f1elemf1f3f2)
									}
									if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.StatusCode != nil {
										f6elemf7f5f1elemf1f3f3 := &svcsdk.ResponseInspectionStatusCode{}
										if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.StatusCode.FailureCodes != nil {
											f6elemf7f5f1elemf1f3f3f0 := []*int64{}
											for _, f6elemf7f5f1elemf1f3f3f0iter := range f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.StatusCode.FailureCodes {
												var f6elemf7f5f1elemf1f3f3f0elem int64
												f6elemf7f5f1elemf1f3f3f0elem = *f6elemf7f5f1elemf1f3f3f0iter
												f6elemf7f5f1elemf1f3f3f0 = append(f6elemf7f5f1elemf1f3f3f0, &f6elemf7f5f1elemf1f3f3f0elem)
											}
											f6elemf7f5f1elemf1f3f3.SetFailureCodes(f6elemf7f5f1elemf1f3f3f0)
										}
										if f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.StatusCode.SuccessCodes != nil {
											f6elemf7f5f1elemf1f3f3f1 := []*int64{}
											for _, f6elemf7f5f1elemf1f3f3f1iter := range f6elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.StatusCode.SuccessCodes {
												var f6elemf7f5f1elemf1f3f3f1elem int64
												f6elemf7f5f1elemf1f3f3f1elem = *f6elemf7f5f1elemf1f3f3f1iter
												f6elemf7f5f1elemf1f3f3f1 = append(f6elemf7f5f1elemf1f3f3f1, &f6elemf7f5f1elemf1f3f3f1elem)
											}
											f6elemf7f5f1elemf1f3f3.SetSuccessCodes(f6elemf7f5f1elemf1f3f3f1)
										}
										f6elemf7f5f1elemf1f3.SetStatusCode(f6elemf7f5f1elemf1f3f3)
									}
									f6elemf7f5f1elemf1.SetResponseInspection(f6elemf7f5f1elemf1f3)
								}
								f6elemf7f5f1elem.SetAWSManagedRulesATPRuleSet(f6elemf7f5f1elemf1)
							}
							if f6elemf7f5f1iter.AWSManagedRulesBotControlRuleSet != nil {
								f6elemf7f5f1elemf2 := &svcsdk.AWSManagedRulesBotControlRuleSet{}
								if f6elemf7f5f1iter.AWSManagedRulesBotControlRuleSet.EnableMachineLearning != nil {
									f6elemf7f5f1elemf2.SetEnableMachineLearning(*f6elemf7f5f1iter.AWSManagedRulesBotControlRuleSet.EnableMachineLearning)
								}
								if f6elemf7f5f1iter.AWSManagedRulesBotControlRuleSet.InspectionLevel != nil {
									f6elemf7f5f1elemf2.SetInspectionLevel(*f6elemf7f5f1iter.AWSManagedRulesBotControlRuleSet.InspectionLevel)
								}
								f6elemf7f5f1elem.SetAWSManagedRulesBotControlRuleSet(f6elemf7f5f1elemf2)
							}
							if f6elemf7f5f1iter.LoginPath != nil {
								f6elemf7f5f1elem.SetLoginPath(*f6elemf7f5f1iter.LoginPath)
							}
							if f6elemf7f5f1iter.PasswordField != nil {
								f6elemf7f5f1elemf4 := &svcsdk.PasswordField{}
								if f6elemf7f5f1iter.PasswordField.Identifier != nil {
									f6elemf7f5f1elemf4.SetIdentifier(*f6elemf7f5f1iter.PasswordField.Identifier)
								}
								f6elemf7f5f1elem.SetPasswordField(f6elemf7f5f1elemf4)
							}
							if f6elemf7f5f1iter.PayloadType != nil {
								f6elemf7f5f1elem.SetPayloadType(*f6elemf7f5f1iter.PayloadType)
							}
							if f6elemf7f5f1iter.UsernameField != nil {
								f6elemf7f5f1elemf6 := &svcsdk.UsernameField{}
								if f6elemf7f5f1iter.UsernameField.Identifier != nil {
									f6elemf7f5f1elemf6.SetIdentifier(*f6elemf7f5f1iter.UsernameField.Identifier)
								}
								f6elemf7f5f1elem.SetUsernameField(f6elemf7f5f1elemf6)
							}
							f6elemf7f5f1 = append(f6elemf7f5f1, f6elemf7f5f1elem)
						}
						f6elemf7f5.SetManagedRuleGroupConfigs(f6elemf7f5f1)
					}
					if f6iter.Statement.ManagedRuleGroupStatement.Name != nil {
						f6elemf7f5.SetName(*f6iter.Statement.ManagedRuleGroupStatement.Name)
					}
					if f6iter.Statement.ManagedRuleGroupStatement.RuleActionOverrides != nil {
						f6elemf7f5f3 := []*svcsdk.RuleActionOverride{}
						for _, f6elemf7f5f3iter := range f6iter.Statement.ManagedRuleGroupStatement.RuleActionOverrides {
							f6elemf7f5f3elem := &svcsdk.RuleActionOverride{}
							if f6elemf7f5f3iter.ActionToUse != nil {
								f6elemf7f5f3elemf0 := &svcsdk.RuleAction{}
								if f6elemf7f5f3iter.ActionToUse.Allow != nil {
									f6elemf7f5f3elemf0f0 := &svcsdk.AllowAction{}
									if f6elemf7f5f3iter.ActionToUse.Allow.CustomRequestHandling != nil {
										f6elemf7f5f3elemf0f0f0 := &svcsdk.CustomRequestHandling{}
										if f6elemf7f5f3iter.ActionToUse.Allow.CustomRequestHandling.InsertHeaders != nil {
											f6elemf7f5f3elemf0f0f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f6elemf7f5f3elemf0f0f0f0iter := range f6elemf7f5f3iter.ActionToUse.Allow.CustomRequestHandling.InsertHeaders {
												f6elemf7f5f3elemf0f0f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f6elemf7f5f3elemf0f0f0f0iter.Name != nil {
													f6elemf7f5f3elemf0f0f0f0elem.SetName(*f6elemf7f5f3elemf0f0f0f0iter.Name)
												}
												if f6elemf7f5f3elemf0f0f0f0iter.Value != nil {
													f6elemf7f5f3elemf0f0f0f0elem.SetValue(*f6elemf7f5f3elemf0f0f0f0iter.Value)
												}
												f6elemf7f5f3elemf0f0f0f0 = append(f6elemf7f5f3elemf0f0f0f0, f6elemf7f5f3elemf0f0f0f0elem)
											}
											f6elemf7f5f3elemf0f0f0.SetInsertHeaders(f6elemf7f5f3elemf0f0f0f0)
										}
										f6elemf7f5f3elemf0f0.SetCustomRequestHandling(f6elemf7f5f3elemf0f0f0)
									}
									f6elemf7f5f3elemf0.SetAllow(f6elemf7f5f3elemf0f0)
								}
								if f6elemf7f5f3iter.ActionToUse.Block != nil {
									f6elemf7f5f3elemf0f1 := &svcsdk.BlockAction{}
									if f6elemf7f5f3iter.ActionToUse.Block.CustomResponse != nil {
										f6elemf7f5f3elemf0f1f0 := &svcsdk.CustomResponse{}
										if f6elemf7f5f3iter.ActionToUse.Block.CustomResponse.CustomResponseBodyKey != nil {
											f6elemf7f5f3elemf0f1f0.SetCustomResponseBodyKey(*f6elemf7f5f3iter.ActionToUse.Block.CustomResponse.CustomResponseBodyKey)
										}
										if f6elemf7f5f3iter.ActionToUse.Block.CustomResponse.ResponseCode != nil {
											f6elemf7f5f3elemf0f1f0.SetResponseCode(*f6elemf7f5f3iter.ActionToUse.Block.CustomResponse.ResponseCode)
										}
										if f6elemf7f5f3iter.ActionToUse.Block.CustomResponse.ResponseHeaders != nil {
											f6elemf7f5f3elemf0f1f0f2 := []*svcsdk.CustomHTTPHeader{}
											for _, f6elemf7f5f3elemf0f1f0f2iter := range f6elemf7f5f3iter.ActionToUse.Block.CustomResponse.ResponseHeaders {
												f6elemf7f5f3elemf0f1f0f2elem := &svcsdk.CustomHTTPHeader{}
												if f6elemf7f5f3elemf0f1f0f2iter.Name != nil {
													f6elemf7f5f3elemf0f1f0f2elem.SetName(*f6elemf7f5f3elemf0f1f0f2iter.Name)
												}
												if f6elemf7f5f3elemf0f1f0f2iter.Value != nil {
													f6elemf7f5f3elemf0f1f0f2elem.SetValue(*f6elemf7f5f3elemf0f1f0f2iter.Value)
												}
												f6elemf7f5f3elemf0f1f0f2 = append(f6elemf7f5f3elemf0f1f0f2, f6elemf7f5f3elemf0f1f0f2elem)
											}
											f6elemf7f5f3elemf0f1f0.SetResponseHeaders(f6elemf7f5f3elemf0f1f0f2)
										}
										f6elemf7f5f3elemf0f1.SetCustomResponse(f6elemf7f5f3elemf0f1f0)
									}
									f6elemf7f5f3elemf0.SetBlock(f6elemf7f5f3elemf0f1)
								}
								if f6elemf7f5f3iter.ActionToUse.Captcha != nil {
									f6elemf7f5f3elemf0f2 := &svcsdk.CaptchaAction{}
									if f6elemf7f5f3iter.ActionToUse.Captcha.CustomRequestHandling != nil {
										f6elemf7f5f3elemf0f2f0 := &svcsdk.CustomRequestHandling{}
										if f6elemf7f5f3iter.ActionToUse.Captcha.CustomRequestHandling.InsertHeaders != nil {
											f6elemf7f5f3elemf0f2f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f6elemf7f5f3elemf0f2f0f0iter := range f6elemf7f5f3iter.ActionToUse.Captcha.CustomRequestHandling.InsertHeaders {
												f6elemf7f5f3elemf0f2f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f6elemf7f5f3elemf0f2f0f0iter.Name != nil {
													f6elemf7f5f3elemf0f2f0f0elem.SetName(*f6elemf7f5f3elemf0f2f0f0iter.Name)
												}
												if f6elemf7f5f3elemf0f2f0f0iter.Value != nil {
													f6elemf7f5f3elemf0f2f0f0elem.SetValue(*f6elemf7f5f3elemf0f2f0f0iter.Value)
												}
												f6elemf7f5f3elemf0f2f0f0 = append(f6elemf7f5f3elemf0f2f0f0, f6elemf7f5f3elemf0f2f0f0elem)
											}
											f6elemf7f5f3elemf0f2f0.SetInsertHeaders(f6elemf7f5f3elemf0f2f0f0)
										}
										f6elemf7f5f3elemf0f2.SetCustomRequestHandling(f6elemf7f5f3elemf0f2f0)
									}
									f6elemf7f5f3elemf0.SetCaptcha(f6elemf7f5f3elemf0f2)
								}
								if f6elemf7f5f3iter.ActionToUse.Challenge != nil {
									f6elemf7f5f3elemf0f3 := &svcsdk.ChallengeAction{}
									if f6elemf7f5f3iter.ActionToUse.Challenge.CustomRequestHandling != nil {
										f6elemf7f5f3elemf0f3f0 := &svcsdk.CustomRequestHandling{}
										if f6elemf7f5f3iter.ActionToUse.Challenge.CustomRequestHandling.InsertHeaders != nil {
											f6elemf7f5f3elemf0f3f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f6elemf7f5f3elemf0f3f0f0iter := range f6elemf7f5f3iter.ActionToUse.Challenge.CustomRequestHandling.InsertHeaders {
												f6elemf7f5f3elemf0f3f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f6elemf7f5f3elemf0f3f0f0iter.Name != nil {
													f6elemf7f5f3elemf0f3f0f0elem.SetName(*f6elemf7f5f3elemf0f3f0f0iter.Name)
												}
												if f6elemf7f5f3elemf0f3f0f0iter.Value != nil {
													f6elemf7f5f3elemf0f3f0f0elem.SetValue(*f6elemf7f5f3elemf0f3f0f0iter.Value)
												}
												f6elemf7f5f3elemf0f3f0f0 = append(f6elemf7f5f3elemf0f3f0f0, f6elemf7f5f3elemf0f3f0f0elem)
											}
											f6elemf7f5f3elemf0f3f0.SetInsertHeaders(f6elemf7f5f3elemf0f3f0f0)
										}
										f6elemf7f5f3elemf0f3.SetCustomRequestHandling(f6elemf7f5f3elemf0f3f0)
									}
									f6elemf7f5f3elemf0.SetChallenge(f6elemf7f5f3elemf0f3)
								}
								if f6elemf7f5f3iter.ActionToUse.Count != nil {
									f6elemf7f5f3elemf0f4 := &svcsdk.CountAction{}
									if f6elemf7f5f3iter.ActionToUse.Count.CustomRequestHandling != nil {
										f6elemf7f5f3elemf0f4f0 := &svcsdk.CustomRequestHandling{}
										if f6elemf7f5f3iter.ActionToUse.Count.CustomRequestHandling.InsertHeaders != nil {
											f6elemf7f5f3elemf0f4f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f6elemf7f5f3elemf0f4f0f0iter := range f6elemf7f5f3iter.ActionToUse.Count.CustomRequestHandling.InsertHeaders {
												f6elemf7f5f3elemf0f4f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f6elemf7f5f3elemf0f4f0f0iter.Name != nil {
													f6elemf7f5f3elemf0f4f0f0elem.SetName(*f6elemf7f5f3elemf0f4f0f0iter.Name)
												}
												if f6elemf7f5f3elemf0f4f0f0iter.Value != nil {
													f6elemf7f5f3elemf0f4f0f0elem.SetValue(*f6elemf7f5f3elemf0f4f0f0iter.Value)
												}
												f6elemf7f5f3elemf0f4f0f0 = append(f6elemf7f5f3elemf0f4f0f0, f6elemf7f5f3elemf0f4f0f0elem)
											}
											f6elemf7f5f3elemf0f4f0.SetInsertHeaders(f6elemf7f5f3elemf0f4f0f0)
										}
										f6elemf7f5f3elemf0f4.SetCustomRequestHandling(f6elemf7f5f3elemf0f4f0)
									}
									f6elemf7f5f3elemf0.SetCount(f6elemf7f5f3elemf0f4)
								}
								f6elemf7f5f3elem.SetActionToUse(f6elemf7f5f3elemf0)
							}
							if f6elemf7f5f3iter.Name != nil {
								f6elemf7f5f3elem.SetName(*f6elemf7f5f3iter.Name)
							}
							f6elemf7f5f3 = append(f6elemf7f5f3, f6elemf7f5f3elem)
						}
						f6elemf7f5.SetRuleActionOverrides(f6elemf7f5f3)
					}
					if f6iter.Statement.ManagedRuleGroupStatement.VendorName != nil {
						f6elemf7f5.SetVendorName(*f6iter.Statement.ManagedRuleGroupStatement.VendorName)
					}
					if f6iter.Statement.ManagedRuleGroupStatement.Version != nil {
						f6elemf7f5.SetVersion(*f6iter.Statement.ManagedRuleGroupStatement.Version)
					}
					f6elemf7.SetManagedRuleGroupStatement(f6elemf7f5)
				}
				if f6iter.Statement.RateBasedStatement != nil {
					f6elemf7f8 := &svcsdk.RateBasedStatement{}
					if f6iter.Statement.RateBasedStatement.AggregateKeyType != nil {
						f6elemf7f8.SetAggregateKeyType(*f6iter.Statement.RateBasedStatement.AggregateKeyType)
					}
					if f6iter.Statement.RateBasedStatement.CustomKeys != nil {
						f6elemf7f8f1 := []*svcsdk.RateBasedStatementCustomKey{}
						for _, f6elemf7f8f1iter := range f6iter.Statement.RateBasedStatement.CustomKeys {
							f6elemf7f8f1elem := &svcsdk.RateBasedStatementCustomKey{}
							if f6elemf7f8f1iter.Cookie != nil {
								f6elemf7f8f1elemf0 := &svcsdk.RateLimitCookie{}
								if f6elemf7f8f1iter.Cookie.Name != nil {
									f6elemf7f8f1elemf0.SetName(*f6elemf7f8f1iter.Cookie.Name)
								}
								if f6elemf7f8f1iter.Cookie.TextTransformations != nil {
									f6elemf7f8f1elemf0f1 := []*svcsdk.TextTransformation{}
									for _, f6elemf7f8f1elemf0f1iter := range f6elemf7f8f1iter.Cookie.TextTransformations {
										f6elemf7f8f1elemf0f1elem := &svcsdk.TextTransformation{}
										if f6elemf7f8f1elemf0f1iter.Priority != nil {
											f6elemf7f8f1elemf0f1elem.SetPriority(*f6elemf7f8f1elemf0f1iter.Priority)
										}
										if f6elemf7f8f1elemf0f1iter.Type != nil {
											f6elemf7f8f1elemf0f1elem.SetType(*f6elemf7f8f1elemf0f1iter.Type)
										}
										f6elemf7f8f1elemf0f1 = append(f6elemf7f8f1elemf0f1, f6elemf7f8f1elemf0f1elem)
									}
									f6elemf7f8f1elemf0.SetTextTransformations(f6elemf7f8f1elemf0f1)
								}
								f6elemf7f8f1elem.SetCookie(f6elemf7f8f1elemf0)
							}
							if f6elemf7f8f1iter.ForwardedIP != nil {
								f6elemf7f8f1elemf1 := &svcsdk.RateLimitForwardedIP{}
								f6elemf7f8f1elem.SetForwardedIP(f6elemf7f8f1elemf1)
							}
							if f6elemf7f8f1iter.HTTPMethod != nil {
								f6elemf7f8f1elemf2 := &svcsdk.RateLimitHTTPMethod{}
								f6elemf7f8f1elem.SetHTTPMethod(f6elemf7f8f1elemf2)
							}
							if f6elemf7f8f1iter.Header != nil {
								f6elemf7f8f1elemf3 := &svcsdk.RateLimitHeader{}
								if f6elemf7f8f1iter.Header.Name != nil {
									f6elemf7f8f1elemf3.SetName(*f6elemf7f8f1iter.Header.Name)
								}
								if f6elemf7f8f1iter.Header.TextTransformations != nil {
									f6elemf7f8f1elemf3f1 := []*svcsdk.TextTransformation{}
									for _, f6elemf7f8f1elemf3f1iter := range f6elemf7f8f1iter.Header.TextTransformations {
										f6elemf7f8f1elemf3f1elem := &svcsdk.TextTransformation{}
										if f6elemf7f8f1elemf3f1iter.Priority != nil {
											f6elemf7f8f1elemf3f1elem.SetPriority(*f6elemf7f8f1elemf3f1iter.Priority)
										}
										if f6elemf7f8f1elemf3f1iter.Type != nil {
											f6elemf7f8f1elemf3f1elem.SetType(*f6elemf7f8f1elemf3f1iter.Type)
										}
										f6elemf7f8f1elemf3f1 = append(f6elemf7f8f1elemf3f1, f6elemf7f8f1elemf3f1elem)
									}
									f6elemf7f8f1elemf3.SetTextTransformations(f6elemf7f8f1elemf3f1)
								}
								f6elemf7f8f1elem.SetHeader(f6elemf7f8f1elemf3)
							}
							if f6elemf7f8f1iter.IP != nil {
								f6elemf7f8f1elemf4 := &svcsdk.RateLimitIP{}
								f6elemf7f8f1elem.SetIP(f6elemf7f8f1elemf4)
							}
							if f6elemf7f8f1iter.LabelNamespace != nil {
								f6elemf7f8f1elemf5 := &svcsdk.RateLimitLabelNamespace{}
								if f6elemf7f8f1iter.LabelNamespace.Namespace != nil {
									f6elemf7f8f1elemf5.SetNamespace(*f6elemf7f8f1iter.LabelNamespace.Namespace)
								}
								f6elemf7f8f1elem.SetLabelNamespace(f6elemf7f8f1elemf5)
							}
							if f6elemf7f8f1iter.QueryArgument != nil {
								f6elemf7f8f1elemf6 := &svcsdk.RateLimitQueryArgument{}
								if f6elemf7f8f1iter.QueryArgument.Name != nil {
									f6elemf7f8f1elemf6.SetName(*f6elemf7f8f1iter.QueryArgument.Name)
								}
								if f6elemf7f8f1iter.QueryArgument.TextTransformations != nil {
									f6elemf7f8f1elemf6f1 := []*svcsdk.TextTransformation{}
									for _, f6elemf7f8f1elemf6f1iter := range f6elemf7f8f1iter.QueryArgument.TextTransformations {
										f6elemf7f8f1elemf6f1elem := &svcsdk.TextTransformation{}
										if f6elemf7f8f1elemf6f1iter.Priority != nil {
											f6elemf7f8f1elemf6f1elem.SetPriority(*f6elemf7f8f1elemf6f1iter.Priority)
										}
										if f6elemf7f8f1elemf6f1iter.Type != nil {
											f6elemf7f8f1elemf6f1elem.SetType(*f6elemf7f8f1elemf6f1iter.Type)
										}
										f6elemf7f8f1elemf6f1 = append(f6elemf7f8f1elemf6f1, f6elemf7f8f1elemf6f1elem)
									}
									f6elemf7f8f1elemf6.SetTextTransformations(f6elemf7f8f1elemf6f1)
								}
								f6elemf7f8f1elem.SetQueryArgument(f6elemf7f8f1elemf6)
							}
							if f6elemf7f8f1iter.QueryString != nil {
								f6elemf7f8f1elemf7 := &svcsdk.RateLimitQueryString{}
								if f6elemf7f8f1iter.QueryString.TextTransformations != nil {
									f6elemf7f8f1elemf7f0 := []*svcsdk.TextTransformation{}
									for _, f6elemf7f8f1elemf7f0iter := range f6elemf7f8f1iter.QueryString.TextTransformations {
										f6elemf7f8f1elemf7f0elem := &svcsdk.TextTransformation{}
										if f6elemf7f8f1elemf7f0iter.Priority != nil {
											f6elemf7f8f1elemf7f0elem.SetPriority(*f6elemf7f8f1elemf7f0iter.Priority)
										}
										if f6elemf7f8f1elemf7f0iter.Type != nil {
											f6elemf7f8f1elemf7f0elem.SetType(*f6elemf7f8f1elemf7f0iter.Type)
										}
										f6elemf7f8f1elemf7f0 = append(f6elemf7f8f1elemf7f0, f6elemf7f8f1elemf7f0elem)
									}
									f6elemf7f8f1elemf7.SetTextTransformations(f6elemf7f8f1elemf7f0)
								}
								f6elemf7f8f1elem.SetQueryString(f6elemf7f8f1elemf7)
							}
							if f6elemf7f8f1iter.URIPath != nil {
								f6elemf7f8f1elemf8 := &svcsdk.RateLimitUriPath{}
								if f6elemf7f8f1iter.URIPath.TextTransformations != nil {
									f6elemf7f8f1elemf8f0 := []*svcsdk.TextTransformation{}
									for _, f6elemf7f8f1elemf8f0iter := range f6elemf7f8f1iter.URIPath.TextTransformations {
										f6elemf7f8f1elemf8f0elem := &svcsdk.TextTransformation{}
										if f6elemf7f8f1elemf8f0iter.Priority != nil {
											f6elemf7f8f1elemf8f0elem.SetPriority(*f6elemf7f8f1elemf8f0iter.Priority)
										}
										if f6elemf7f8f1elemf8f0iter.Type != nil {
											f6elemf7f8f1elemf8f0elem.SetType(*f6elemf7f8f1elemf8f0iter.Type)
										}
										f6elemf7f8f1elemf8f0 = append(f6elemf7f8f1elemf8f0, f6elemf7f8f1elemf8f0elem)
									}
									f6elemf7f8f1elemf8.SetTextTransformations(f6elemf7f8f1elemf8f0)
								}
								f6elemf7f8f1elem.SetUriPath(f6elemf7f8f1elemf8)
							}
							f6elemf7f8f1 = append(f6elemf7f8f1, f6elemf7f8f1elem)
						}
						f6elemf7f8.SetCustomKeys(f6elemf7f8f1)
					}
					if f6iter.Statement.RateBasedStatement.ForwardedIPConfig != nil {
						f6elemf7f8f2 := &svcsdk.ForwardedIPConfig{}
						if f6iter.Statement.RateBasedStatement.ForwardedIPConfig.FallbackBehavior != nil {
							f6elemf7f8f2.SetFallbackBehavior(*f6iter.Statement.RateBasedStatement.ForwardedIPConfig.FallbackBehavior)
						}
						if f6iter.Statement.RateBasedStatement.ForwardedIPConfig.HeaderName != nil {
							f6elemf7f8f2.SetHeaderName(*f6iter.Statement.RateBasedStatement.ForwardedIPConfig.HeaderName)
						}
						f6elemf7f8.SetForwardedIPConfig(f6elemf7f8f2)
					}
					if f6iter.Statement.RateBasedStatement.Limit != nil {
						f6elemf7f8.SetLimit(*f6iter.Statement.RateBasedStatement.Limit)
					}
					f6elemf7.SetRateBasedStatement(f6elemf7f8)
				}
				if f6iter.Statement.RegexMatchStatement != nil {
					f6elemf7f9 := &svcsdk.RegexMatchStatement{}
					if f6iter.Statement.RegexMatchStatement.FieldToMatch != nil {
						f6elemf7f9f0 := &svcsdk.FieldToMatch{}
						if f6iter.Statement.RegexMatchStatement.FieldToMatch.AllQueryArguments != nil {
							f6elemf7f9f0f0 := &svcsdk.AllQueryArguments{}
							f6elemf7f9f0.SetAllQueryArguments(f6elemf7f9f0f0)
						}
						if f6iter.Statement.RegexMatchStatement.FieldToMatch.Body != nil {
							f6elemf7f9f0f1 := &svcsdk.Body{}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.Body.OversizeHandling != nil {
								f6elemf7f9f0f1.SetOversizeHandling(*f6iter.Statement.RegexMatchStatement.FieldToMatch.Body.OversizeHandling)
							}
							f6elemf7f9f0.SetBody(f6elemf7f9f0f1)
						}
						if f6iter.Statement.RegexMatchStatement.FieldToMatch.Cookies != nil {
							f6elemf7f9f0f2 := &svcsdk.Cookies{}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchPattern != nil {
								f6elemf7f9f0f2f0 := &svcsdk.CookieMatchPattern{}
								if f6iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchPattern.All != nil {
									f6elemf7f9f0f2f0f0 := &svcsdk.All{}
									f6elemf7f9f0f2f0.SetAll(f6elemf7f9f0f2f0f0)
								}
								if f6iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies != nil {
									f6elemf7f9f0f2f0f1 := []*string{}
									for _, f6elemf7f9f0f2f0f1iter := range f6iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies {
										var f6elemf7f9f0f2f0f1elem string
										f6elemf7f9f0f2f0f1elem = *f6elemf7f9f0f2f0f1iter
										f6elemf7f9f0f2f0f1 = append(f6elemf7f9f0f2f0f1, &f6elemf7f9f0f2f0f1elem)
									}
									f6elemf7f9f0f2f0.SetExcludedCookies(f6elemf7f9f0f2f0f1)
								}
								if f6iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies != nil {
									f6elemf7f9f0f2f0f2 := []*string{}
									for _, f6elemf7f9f0f2f0f2iter := range f6iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies {
										var f6elemf7f9f0f2f0f2elem string
										f6elemf7f9f0f2f0f2elem = *f6elemf7f9f0f2f0f2iter
										f6elemf7f9f0f2f0f2 = append(f6elemf7f9f0f2f0f2, &f6elemf7f9f0f2f0f2elem)
									}
									f6elemf7f9f0f2f0.SetIncludedCookies(f6elemf7f9f0f2f0f2)
								}
								f6elemf7f9f0f2.SetMatchPattern(f6elemf7f9f0f2f0)
							}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchScope != nil {
								f6elemf7f9f0f2.SetMatchScope(*f6iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchScope)
							}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.OversizeHandling != nil {
								f6elemf7f9f0f2.SetOversizeHandling(*f6iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.OversizeHandling)
							}
							f6elemf7f9f0.SetCookies(f6elemf7f9f0f2)
						}
						if f6iter.Statement.RegexMatchStatement.FieldToMatch.HeaderOrder != nil {
							f6elemf7f9f0f3 := &svcsdk.HeaderOrder{}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling != nil {
								f6elemf7f9f0f3.SetOversizeHandling(*f6iter.Statement.RegexMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling)
							}
							f6elemf7f9f0.SetHeaderOrder(f6elemf7f9f0f3)
						}
						if f6iter.Statement.RegexMatchStatement.FieldToMatch.Headers != nil {
							f6elemf7f9f0f4 := &svcsdk.Headers{}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchPattern != nil {
								f6elemf7f9f0f4f0 := &svcsdk.HeaderMatchPattern{}
								if f6iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchPattern.All != nil {
									f6elemf7f9f0f4f0f0 := &svcsdk.All{}
									f6elemf7f9f0f4f0.SetAll(f6elemf7f9f0f4f0f0)
								}
								if f6iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders != nil {
									f6elemf7f9f0f4f0f1 := []*string{}
									for _, f6elemf7f9f0f4f0f1iter := range f6iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders {
										var f6elemf7f9f0f4f0f1elem string
										f6elemf7f9f0f4f0f1elem = *f6elemf7f9f0f4f0f1iter
										f6elemf7f9f0f4f0f1 = append(f6elemf7f9f0f4f0f1, &f6elemf7f9f0f4f0f1elem)
									}
									f6elemf7f9f0f4f0.SetExcludedHeaders(f6elemf7f9f0f4f0f1)
								}
								if f6iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders != nil {
									f6elemf7f9f0f4f0f2 := []*string{}
									for _, f6elemf7f9f0f4f0f2iter := range f6iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders {
										var f6elemf7f9f0f4f0f2elem string
										f6elemf7f9f0f4f0f2elem = *f6elemf7f9f0f4f0f2iter
										f6elemf7f9f0f4f0f2 = append(f6elemf7f9f0f4f0f2, &f6elemf7f9f0f4f0f2elem)
									}
									f6elemf7f9f0f4f0.SetIncludedHeaders(f6elemf7f9f0f4f0f2)
								}
								f6elemf7f9f0f4.SetMatchPattern(f6elemf7f9f0f4f0)
							}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchScope != nil {
								f6elemf7f9f0f4.SetMatchScope(*f6iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchScope)
							}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.Headers.OversizeHandling != nil {
								f6elemf7f9f0f4.SetOversizeHandling(*f6iter.Statement.RegexMatchStatement.FieldToMatch.Headers.OversizeHandling)
							}
							f6elemf7f9f0.SetHeaders(f6elemf7f9f0f4)
						}
						if f6iter.Statement.RegexMatchStatement.FieldToMatch.JA3Fingerprint != nil {
							f6elemf7f9f0f5 := &svcsdk.JA3Fingerprint{}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior != nil {
								f6elemf7f9f0f5.SetFallbackBehavior(*f6iter.Statement.RegexMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior)
							}
							f6elemf7f9f0.SetJA3Fingerprint(f6elemf7f9f0f5)
						}
						if f6iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody != nil {
							f6elemf7f9f0f6 := &svcsdk.JsonBody{}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior != nil {
								f6elemf7f9f0f6.SetInvalidFallbackBehavior(*f6iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior)
							}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.MatchPattern != nil {
								f6elemf7f9f0f6f1 := &svcsdk.JsonMatchPattern{}
								if f6iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.MatchPattern.All != nil {
									f6elemf7f9f0f6f1f0 := &svcsdk.All{}
									f6elemf7f9f0f6f1.SetAll(f6elemf7f9f0f6f1f0)
								}
								if f6iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths != nil {
									f6elemf7f9f0f6f1f1 := []*string{}
									for _, f6elemf7f9f0f6f1f1iter := range f6iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths {
										var f6elemf7f9f0f6f1f1elem string
										f6elemf7f9f0f6f1f1elem = *f6elemf7f9f0f6f1f1iter
										f6elemf7f9f0f6f1f1 = append(f6elemf7f9f0f6f1f1, &f6elemf7f9f0f6f1f1elem)
									}
									f6elemf7f9f0f6f1.SetIncludedPaths(f6elemf7f9f0f6f1f1)
								}
								f6elemf7f9f0f6.SetMatchPattern(f6elemf7f9f0f6f1)
							}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.MatchScope != nil {
								f6elemf7f9f0f6.SetMatchScope(*f6iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.MatchScope)
							}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.OversizeHandling != nil {
								f6elemf7f9f0f6.SetOversizeHandling(*f6iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.OversizeHandling)
							}
							f6elemf7f9f0.SetJsonBody(f6elemf7f9f0f6)
						}
						if f6iter.Statement.RegexMatchStatement.FieldToMatch.Method != nil {
							f6elemf7f9f0f7 := &svcsdk.Method{}
							f6elemf7f9f0.SetMethod(f6elemf7f9f0f7)
						}
						if f6iter.Statement.RegexMatchStatement.FieldToMatch.QueryString != nil {
							f6elemf7f9f0f8 := &svcsdk.QueryString{}
							f6elemf7f9f0.SetQueryString(f6elemf7f9f0f8)
						}
						if f6iter.Statement.RegexMatchStatement.FieldToMatch.SingleHeader != nil {
							f6elemf7f9f0f9 := &svcsdk.SingleHeader{}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.SingleHeader.Name != nil {
								f6elemf7f9f0f9.SetName(*f6iter.Statement.RegexMatchStatement.FieldToMatch.SingleHeader.Name)
							}
							f6elemf7f9f0.SetSingleHeader(f6elemf7f9f0f9)
						}
						if f6iter.Statement.RegexMatchStatement.FieldToMatch.SingleQueryArgument != nil {
							f6elemf7f9f0f10 := &svcsdk.SingleQueryArgument{}
							if f6iter.Statement.RegexMatchStatement.FieldToMatch.SingleQueryArgument.Name != nil {
								f6elemf7f9f0f10.SetName(*f6iter.Statement.RegexMatchStatement.FieldToMatch.SingleQueryArgument.Name)
							}
							f6elemf7f9f0.SetSingleQueryArgument(f6elemf7f9f0f10)
						}
						if f6iter.Statement.RegexMatchStatement.FieldToMatch.URIPath != nil {
							f6elemf7f9f0f11 := &svcsdk.UriPath{}
							f6elemf7f9f0.SetUriPath(f6elemf7f9f0f11)
						}
						f6elemf7f9.SetFieldToMatch(f6elemf7f9f0)
					}
					if f6iter.Statement.RegexMatchStatement.RegexString != nil {
						f6elemf7f9.SetRegexString(*f6iter.Statement.RegexMatchStatement.RegexString)
					}
					if f6iter.Statement.RegexMatchStatement.TextTransformations != nil {
						f6elemf7f9f2 := []*svcsdk.TextTransformation{}
						for _, f6elemf7f9f2iter := range f6iter.Statement.RegexMatchStatement.TextTransformations {
							f6elemf7f9f2elem := &svcsdk.TextTransformation{}
							if f6elemf7f9f2iter.Priority != nil {
								f6elemf7f9f2elem.SetPriority(*f6elemf7f9f2iter.Priority)
							}
							if f6elemf7f9f2iter.Type != nil {
								f6elemf7f9f2elem.SetType(*f6elemf7f9f2iter.Type)
							}
							f6elemf7f9f2 = append(f6elemf7f9f2, f6elemf7f9f2elem)
						}
						f6elemf7f9.SetTextTransformations(f6elemf7f9f2)
					}
					f6elemf7.SetRegexMatchStatement(f6elemf7f9)
				}
				if f6iter.Statement.RegexPatternSetReferenceStatement != nil {
					f6elemf7f10 := &svcsdk.RegexPatternSetReferenceStatement{}
					if f6iter.Statement.RegexPatternSetReferenceStatement.ARN != nil {
						f6elemf7f10.SetARN(*f6iter.Statement.RegexPatternSetReferenceStatement.ARN)
					}
					if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch != nil {
						f6elemf7f10f1 := &svcsdk.FieldToMatch{}
						if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.AllQueryArguments != nil {
							f6elemf7f10f1f0 := &svcsdk.AllQueryArguments{}
							f6elemf7f10f1.SetAllQueryArguments(f6elemf7f10f1f0)
						}
						if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Body != nil {
							f6elemf7f10f1f1 := &svcsdk.Body{}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Body.OversizeHandling != nil {
								f6elemf7f10f1f1.SetOversizeHandling(*f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Body.OversizeHandling)
							}
							f6elemf7f10f1.SetBody(f6elemf7f10f1f1)
						}
						if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies != nil {
							f6elemf7f10f1f2 := &svcsdk.Cookies{}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchPattern != nil {
								f6elemf7f10f1f2f0 := &svcsdk.CookieMatchPattern{}
								if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchPattern.All != nil {
									f6elemf7f10f1f2f0f0 := &svcsdk.All{}
									f6elemf7f10f1f2f0.SetAll(f6elemf7f10f1f2f0f0)
								}
								if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies != nil {
									f6elemf7f10f1f2f0f1 := []*string{}
									for _, f6elemf7f10f1f2f0f1iter := range f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies {
										var f6elemf7f10f1f2f0f1elem string
										f6elemf7f10f1f2f0f1elem = *f6elemf7f10f1f2f0f1iter
										f6elemf7f10f1f2f0f1 = append(f6elemf7f10f1f2f0f1, &f6elemf7f10f1f2f0f1elem)
									}
									f6elemf7f10f1f2f0.SetExcludedCookies(f6elemf7f10f1f2f0f1)
								}
								if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies != nil {
									f6elemf7f10f1f2f0f2 := []*string{}
									for _, f6elemf7f10f1f2f0f2iter := range f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies {
										var f6elemf7f10f1f2f0f2elem string
										f6elemf7f10f1f2f0f2elem = *f6elemf7f10f1f2f0f2iter
										f6elemf7f10f1f2f0f2 = append(f6elemf7f10f1f2f0f2, &f6elemf7f10f1f2f0f2elem)
									}
									f6elemf7f10f1f2f0.SetIncludedCookies(f6elemf7f10f1f2f0f2)
								}
								f6elemf7f10f1f2.SetMatchPattern(f6elemf7f10f1f2f0)
							}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchScope != nil {
								f6elemf7f10f1f2.SetMatchScope(*f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchScope)
							}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.OversizeHandling != nil {
								f6elemf7f10f1f2.SetOversizeHandling(*f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.OversizeHandling)
							}
							f6elemf7f10f1.SetCookies(f6elemf7f10f1f2)
						}
						if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.HeaderOrder != nil {
							f6elemf7f10f1f3 := &svcsdk.HeaderOrder{}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.HeaderOrder.OversizeHandling != nil {
								f6elemf7f10f1f3.SetOversizeHandling(*f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.HeaderOrder.OversizeHandling)
							}
							f6elemf7f10f1.SetHeaderOrder(f6elemf7f10f1f3)
						}
						if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers != nil {
							f6elemf7f10f1f4 := &svcsdk.Headers{}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchPattern != nil {
								f6elemf7f10f1f4f0 := &svcsdk.HeaderMatchPattern{}
								if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchPattern.All != nil {
									f6elemf7f10f1f4f0f0 := &svcsdk.All{}
									f6elemf7f10f1f4f0.SetAll(f6elemf7f10f1f4f0f0)
								}
								if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders != nil {
									f6elemf7f10f1f4f0f1 := []*string{}
									for _, f6elemf7f10f1f4f0f1iter := range f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders {
										var f6elemf7f10f1f4f0f1elem string
										f6elemf7f10f1f4f0f1elem = *f6elemf7f10f1f4f0f1iter
										f6elemf7f10f1f4f0f1 = append(f6elemf7f10f1f4f0f1, &f6elemf7f10f1f4f0f1elem)
									}
									f6elemf7f10f1f4f0.SetExcludedHeaders(f6elemf7f10f1f4f0f1)
								}
								if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders != nil {
									f6elemf7f10f1f4f0f2 := []*string{}
									for _, f6elemf7f10f1f4f0f2iter := range f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders {
										var f6elemf7f10f1f4f0f2elem string
										f6elemf7f10f1f4f0f2elem = *f6elemf7f10f1f4f0f2iter
										f6elemf7f10f1f4f0f2 = append(f6elemf7f10f1f4f0f2, &f6elemf7f10f1f4f0f2elem)
									}
									f6elemf7f10f1f4f0.SetIncludedHeaders(f6elemf7f10f1f4f0f2)
								}
								f6elemf7f10f1f4.SetMatchPattern(f6elemf7f10f1f4f0)
							}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchScope != nil {
								f6elemf7f10f1f4.SetMatchScope(*f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchScope)
							}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.OversizeHandling != nil {
								f6elemf7f10f1f4.SetOversizeHandling(*f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.OversizeHandling)
							}
							f6elemf7f10f1.SetHeaders(f6elemf7f10f1f4)
						}
						if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JA3Fingerprint != nil {
							f6elemf7f10f1f5 := &svcsdk.JA3Fingerprint{}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior != nil {
								f6elemf7f10f1f5.SetFallbackBehavior(*f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior)
							}
							f6elemf7f10f1.SetJA3Fingerprint(f6elemf7f10f1f5)
						}
						if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody != nil {
							f6elemf7f10f1f6 := &svcsdk.JsonBody{}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior != nil {
								f6elemf7f10f1f6.SetInvalidFallbackBehavior(*f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior)
							}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.MatchPattern != nil {
								f6elemf7f10f1f6f1 := &svcsdk.JsonMatchPattern{}
								if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.MatchPattern.All != nil {
									f6elemf7f10f1f6f1f0 := &svcsdk.All{}
									f6elemf7f10f1f6f1.SetAll(f6elemf7f10f1f6f1f0)
								}
								if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths != nil {
									f6elemf7f10f1f6f1f1 := []*string{}
									for _, f6elemf7f10f1f6f1f1iter := range f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths {
										var f6elemf7f10f1f6f1f1elem string
										f6elemf7f10f1f6f1f1elem = *f6elemf7f10f1f6f1f1iter
										f6elemf7f10f1f6f1f1 = append(f6elemf7f10f1f6f1f1, &f6elemf7f10f1f6f1f1elem)
									}
									f6elemf7f10f1f6f1.SetIncludedPaths(f6elemf7f10f1f6f1f1)
								}
								f6elemf7f10f1f6.SetMatchPattern(f6elemf7f10f1f6f1)
							}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.MatchScope != nil {
								f6elemf7f10f1f6.SetMatchScope(*f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.MatchScope)
							}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.OversizeHandling != nil {
								f6elemf7f10f1f6.SetOversizeHandling(*f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.OversizeHandling)
							}
							f6elemf7f10f1.SetJsonBody(f6elemf7f10f1f6)
						}
						if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Method != nil {
							f6elemf7f10f1f7 := &svcsdk.Method{}
							f6elemf7f10f1.SetMethod(f6elemf7f10f1f7)
						}
						if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.QueryString != nil {
							f6elemf7f10f1f8 := &svcsdk.QueryString{}
							f6elemf7f10f1.SetQueryString(f6elemf7f10f1f8)
						}
						if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.SingleHeader != nil {
							f6elemf7f10f1f9 := &svcsdk.SingleHeader{}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.SingleHeader.Name != nil {
								f6elemf7f10f1f9.SetName(*f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.SingleHeader.Name)
							}
							f6elemf7f10f1.SetSingleHeader(f6elemf7f10f1f9)
						}
						if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.SingleQueryArgument != nil {
							f6elemf7f10f1f10 := &svcsdk.SingleQueryArgument{}
							if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.SingleQueryArgument.Name != nil {
								f6elemf7f10f1f10.SetName(*f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.SingleQueryArgument.Name)
							}
							f6elemf7f10f1.SetSingleQueryArgument(f6elemf7f10f1f10)
						}
						if f6iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.URIPath != nil {
							f6elemf7f10f1f11 := &svcsdk.UriPath{}
							f6elemf7f10f1.SetUriPath(f6elemf7f10f1f11)
						}
						f6elemf7f10.SetFieldToMatch(f6elemf7f10f1)
					}
					if f6iter.Statement.RegexPatternSetReferenceStatement.TextTransformations != nil {
						f6elemf7f10f2 := []*svcsdk.TextTransformation{}
						for _, f6elemf7f10f2iter := range f6iter.Statement.RegexPatternSetReferenceStatement.TextTransformations {
							f6elemf7f10f2elem := &svcsdk.TextTransformation{}
							if f6elemf7f10f2iter.Priority != nil {
								f6elemf7f10f2elem.SetPriority(*f6elemf7f10f2iter.Priority)
							}
							if f6elemf7f10f2iter.Type != nil {
								f6elemf7f10f2elem.SetType(*f6elemf7f10f2iter.Type)
							}
							f6elemf7f10f2 = append(f6elemf7f10f2, f6elemf7f10f2elem)
						}
						f6elemf7f10.SetTextTransformations(f6elemf7f10f2)
					}
					f6elemf7.SetRegexPatternSetReferenceStatement(f6elemf7f10)
				}
				if f6iter.Statement.RuleGroupReferenceStatement != nil {
					f6elemf7f11 := &svcsdk.RuleGroupReferenceStatement{}
					if f6iter.Statement.RuleGroupReferenceStatement.ARN != nil {
						f6elemf7f11.SetARN(*f6iter.Statement.RuleGroupReferenceStatement.ARN)
					}
					if f6iter.Statement.RuleGroupReferenceStatement.ExcludedRules != nil {
						f6elemf7f11f1 := []*svcsdk.ExcludedRule{}
						for _, f6elemf7f11f1iter := range f6iter.Statement.RuleGroupReferenceStatement.ExcludedRules {
							f6elemf7f11f1elem := &svcsdk.ExcludedRule{}
							if f6elemf7f11f1iter.Name != nil {
								f6elemf7f11f1elem.SetName(*f6elemf7f11f1iter.Name)
							}
							f6elemf7f11f1 = append(f6elemf7f11f1, f6elemf7f11f1elem)
						}
						f6elemf7f11.SetExcludedRules(f6elemf7f11f1)
					}
					if f6iter.Statement.RuleGroupReferenceStatement.RuleActionOverrides != nil {
						f6elemf7f11f2 := []*svcsdk.RuleActionOverride{}
						for _, f6elemf7f11f2iter := range f6iter.Statement.RuleGroupReferenceStatement.RuleActionOverrides {
							f6elemf7f11f2elem := &svcsdk.RuleActionOverride{}
							if f6elemf7f11f2iter.ActionToUse != nil {
								f6elemf7f11f2elemf0 := &svcsdk.RuleAction{}
								if f6elemf7f11f2iter.ActionToUse.Allow != nil {
									f6elemf7f11f2elemf0f0 := &svcsdk.AllowAction{}
									if f6elemf7f11f2iter.ActionToUse.Allow.CustomRequestHandling != nil {
										f6elemf7f11f2elemf0f0f0 := &svcsdk.CustomRequestHandling{}
										if f6elemf7f11f2iter.ActionToUse.Allow.CustomRequestHandling.InsertHeaders != nil {
											f6elemf7f11f2elemf0f0f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f6elemf7f11f2elemf0f0f0f0iter := range f6elemf7f11f2iter.ActionToUse.Allow.CustomRequestHandling.InsertHeaders {
												f6elemf7f11f2elemf0f0f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f6elemf7f11f2elemf0f0f0f0iter.Name != nil {
													f6elemf7f11f2elemf0f0f0f0elem.SetName(*f6elemf7f11f2elemf0f0f0f0iter.Name)
												}
												if f6elemf7f11f2elemf0f0f0f0iter.Value != nil {
													f6elemf7f11f2elemf0f0f0f0elem.SetValue(*f6elemf7f11f2elemf0f0f0f0iter.Value)
												}
												f6elemf7f11f2elemf0f0f0f0 = append(f6elemf7f11f2elemf0f0f0f0, f6elemf7f11f2elemf0f0f0f0elem)
											}
											f6elemf7f11f2elemf0f0f0.SetInsertHeaders(f6elemf7f11f2elemf0f0f0f0)
										}
										f6elemf7f11f2elemf0f0.SetCustomRequestHandling(f6elemf7f11f2elemf0f0f0)
									}
									f6elemf7f11f2elemf0.SetAllow(f6elemf7f11f2elemf0f0)
								}
								if f6elemf7f11f2iter.ActionToUse.Block != nil {
									f6elemf7f11f2elemf0f1 := &svcsdk.BlockAction{}
									if f6elemf7f11f2iter.ActionToUse.Block.CustomResponse != nil {
										f6elemf7f11f2elemf0f1f0 := &svcsdk.CustomResponse{}
										if f6elemf7f11f2iter.ActionToUse.Block.CustomResponse.CustomResponseBodyKey != nil {
											f6elemf7f11f2elemf0f1f0.SetCustomResponseBodyKey(*f6elemf7f11f2iter.ActionToUse.Block.CustomResponse.CustomResponseBodyKey)
										}
										if f6elemf7f11f2iter.ActionToUse.Block.CustomResponse.ResponseCode != nil {
											f6elemf7f11f2elemf0f1f0.SetResponseCode(*f6elemf7f11f2iter.ActionToUse.Block.CustomResponse.ResponseCode)
										}
										if f6elemf7f11f2iter.ActionToUse.Block.CustomResponse.ResponseHeaders != nil {
											f6elemf7f11f2elemf0f1f0f2 := []*svcsdk.CustomHTTPHeader{}
											for _, f6elemf7f11f2elemf0f1f0f2iter := range f6elemf7f11f2iter.ActionToUse.Block.CustomResponse.ResponseHeaders {
												f6elemf7f11f2elemf0f1f0f2elem := &svcsdk.CustomHTTPHeader{}
												if f6elemf7f11f2elemf0f1f0f2iter.Name != nil {
													f6elemf7f11f2elemf0f1f0f2elem.SetName(*f6elemf7f11f2elemf0f1f0f2iter.Name)
												}
												if f6elemf7f11f2elemf0f1f0f2iter.Value != nil {
													f6elemf7f11f2elemf0f1f0f2elem.SetValue(*f6elemf7f11f2elemf0f1f0f2iter.Value)
												}
												f6elemf7f11f2elemf0f1f0f2 = append(f6elemf7f11f2elemf0f1f0f2, f6elemf7f11f2elemf0f1f0f2elem)
											}
											f6elemf7f11f2elemf0f1f0.SetResponseHeaders(f6elemf7f11f2elemf0f1f0f2)
										}
										f6elemf7f11f2elemf0f1.SetCustomResponse(f6elemf7f11f2elemf0f1f0)
									}
									f6elemf7f11f2elemf0.SetBlock(f6elemf7f11f2elemf0f1)
								}
								if f6elemf7f11f2iter.ActionToUse.Captcha != nil {
									f6elemf7f11f2elemf0f2 := &svcsdk.CaptchaAction{}
									if f6elemf7f11f2iter.ActionToUse.Captcha.CustomRequestHandling != nil {
										f6elemf7f11f2elemf0f2f0 := &svcsdk.CustomRequestHandling{}
										if f6elemf7f11f2iter.ActionToUse.Captcha.CustomRequestHandling.InsertHeaders != nil {
											f6elemf7f11f2elemf0f2f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f6elemf7f11f2elemf0f2f0f0iter := range f6elemf7f11f2iter.ActionToUse.Captcha.CustomRequestHandling.InsertHeaders {
												f6elemf7f11f2elemf0f2f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f6elemf7f11f2elemf0f2f0f0iter.Name != nil {
													f6elemf7f11f2elemf0f2f0f0elem.SetName(*f6elemf7f11f2elemf0f2f0f0iter.Name)
												}
												if f6elemf7f11f2elemf0f2f0f0iter.Value != nil {
													f6elemf7f11f2elemf0f2f0f0elem.SetValue(*f6elemf7f11f2elemf0f2f0f0iter.Value)
												}
												f6elemf7f11f2elemf0f2f0f0 = append(f6elemf7f11f2elemf0f2f0f0, f6elemf7f11f2elemf0f2f0f0elem)
											}
											f6elemf7f11f2elemf0f2f0.SetInsertHeaders(f6elemf7f11f2elemf0f2f0f0)
										}
										f6elemf7f11f2elemf0f2.SetCustomRequestHandling(f6elemf7f11f2elemf0f2f0)
									}
									f6elemf7f11f2elemf0.SetCaptcha(f6elemf7f11f2elemf0f2)
								}
								if f6elemf7f11f2iter.ActionToUse.Challenge != nil {
									f6elemf7f11f2elemf0f3 := &svcsdk.ChallengeAction{}
									if f6elemf7f11f2iter.ActionToUse.Challenge.CustomRequestHandling != nil {
										f6elemf7f11f2elemf0f3f0 := &svcsdk.CustomRequestHandling{}
										if f6elemf7f11f2iter.ActionToUse.Challenge.CustomRequestHandling.InsertHeaders != nil {
											f6elemf7f11f2elemf0f3f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f6elemf7f11f2elemf0f3f0f0iter := range f6elemf7f11f2iter.ActionToUse.Challenge.CustomRequestHandling.InsertHeaders {
												f6elemf7f11f2elemf0f3f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f6elemf7f11f2elemf0f3f0f0iter.Name != nil {
													f6elemf7f11f2elemf0f3f0f0elem.SetName(*f6elemf7f11f2elemf0f3f0f0iter.Name)
												}
												if f6elemf7f11f2elemf0f3f0f0iter.Value != nil {
													f6elemf7f11f2elemf0f3f0f0elem.SetValue(*f6elemf7f11f2elemf0f3f0f0iter.Value)
												}
												f6elemf7f11f2elemf0f3f0f0 = append(f6elemf7f11f2elemf0f3f0f0, f6elemf7f11f2elemf0f3f0f0elem)
											}
											f6elemf7f11f2elemf0f3f0.SetInsertHeaders(f6elemf7f11f2elemf0f3f0f0)
										}
										f6elemf7f11f2elemf0f3.SetCustomRequestHandling(f6elemf7f11f2elemf0f3f0)
									}
									f6elemf7f11f2elemf0.SetChallenge(f6elemf7f11f2elemf0f3)
								}
								if f6elemf7f11f2iter.ActionToUse.Count != nil {
									f6elemf7f11f2elemf0f4 := &svcsdk.CountAction{}
									if f6elemf7f11f2iter.ActionToUse.Count.CustomRequestHandling != nil {
										f6elemf7f11f2elemf0f4f0 := &svcsdk.CustomRequestHandling{}
										if f6elemf7f11f2iter.ActionToUse.Count.CustomRequestHandling.InsertHeaders != nil {
											f6elemf7f11f2elemf0f4f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f6elemf7f11f2elemf0f4f0f0iter := range f6elemf7f11f2iter.ActionToUse.Count.CustomRequestHandling.InsertHeaders {
												f6elemf7f11f2elemf0f4f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f6elemf7f11f2elemf0f4f0f0iter.Name != nil {
													f6elemf7f11f2elemf0f4f0f0elem.SetName(*f6elemf7f11f2elemf0f4f0f0iter.Name)
												}
												if f6elemf7f11f2elemf0f4f0f0iter.Value != nil {
													f6elemf7f11f2elemf0f4f0f0elem.SetValue(*f6elemf7f11f2elemf0f4f0f0iter.Value)
												}
												f6elemf7f11f2elemf0f4f0f0 = append(f6elemf7f11f2elemf0f4f0f0, f6elemf7f11f2elemf0f4f0f0elem)
											}
											f6elemf7f11f2elemf0f4f0.SetInsertHeaders(f6elemf7f11f2elemf0f4f0f0)
										}
										f6elemf7f11f2elemf0f4.SetCustomRequestHandling(f6elemf7f11f2elemf0f4f0)
									}
									f6elemf7f11f2elemf0.SetCount(f6elemf7f11f2elemf0f4)
								}
								f6elemf7f11f2elem.SetActionToUse(f6elemf7f11f2elemf0)
							}
							if f6elemf7f11f2iter.Name != nil {
								f6elemf7f11f2elem.SetName(*f6elemf7f11f2iter.Name)
							}
							f6elemf7f11f2 = append(f6elemf7f11f2, f6elemf7f11f2elem)
						}
						f6elemf7f11.SetRuleActionOverrides(f6elemf7f11f2)
					}
					f6elemf7.SetRuleGroupReferenceStatement(f6elemf7f11)
				}
				if f6iter.Statement.SizeConstraintStatement != nil {
					f6elemf7f12 := &svcsdk.SizeConstraintStatement{}
					if f6iter.Statement.SizeConstraintStatement.ComparisonOperator != nil {
						f6elemf7f12.SetComparisonOperator(*f6iter.Statement.SizeConstraintStatement.ComparisonOperator)
					}
					if f6iter.Statement.SizeConstraintStatement.FieldToMatch != nil {
						f6elemf7f12f1 := &svcsdk.FieldToMatch{}
						if f6iter.Statement.SizeConstraintStatement.FieldToMatch.AllQueryArguments != nil {
							f6elemf7f12f1f0 := &svcsdk.AllQueryArguments{}
							f6elemf7f12f1.SetAllQueryArguments(f6elemf7f12f1f0)
						}
						if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Body != nil {
							f6elemf7f12f1f1 := &svcsdk.Body{}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Body.OversizeHandling != nil {
								f6elemf7f12f1f1.SetOversizeHandling(*f6iter.Statement.SizeConstraintStatement.FieldToMatch.Body.OversizeHandling)
							}
							f6elemf7f12f1.SetBody(f6elemf7f12f1f1)
						}
						if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies != nil {
							f6elemf7f12f1f2 := &svcsdk.Cookies{}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchPattern != nil {
								f6elemf7f12f1f2f0 := &svcsdk.CookieMatchPattern{}
								if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchPattern.All != nil {
									f6elemf7f12f1f2f0f0 := &svcsdk.All{}
									f6elemf7f12f1f2f0.SetAll(f6elemf7f12f1f2f0f0)
								}
								if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies != nil {
									f6elemf7f12f1f2f0f1 := []*string{}
									for _, f6elemf7f12f1f2f0f1iter := range f6iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies {
										var f6elemf7f12f1f2f0f1elem string
										f6elemf7f12f1f2f0f1elem = *f6elemf7f12f1f2f0f1iter
										f6elemf7f12f1f2f0f1 = append(f6elemf7f12f1f2f0f1, &f6elemf7f12f1f2f0f1elem)
									}
									f6elemf7f12f1f2f0.SetExcludedCookies(f6elemf7f12f1f2f0f1)
								}
								if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies != nil {
									f6elemf7f12f1f2f0f2 := []*string{}
									for _, f6elemf7f12f1f2f0f2iter := range f6iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies {
										var f6elemf7f12f1f2f0f2elem string
										f6elemf7f12f1f2f0f2elem = *f6elemf7f12f1f2f0f2iter
										f6elemf7f12f1f2f0f2 = append(f6elemf7f12f1f2f0f2, &f6elemf7f12f1f2f0f2elem)
									}
									f6elemf7f12f1f2f0.SetIncludedCookies(f6elemf7f12f1f2f0f2)
								}
								f6elemf7f12f1f2.SetMatchPattern(f6elemf7f12f1f2f0)
							}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchScope != nil {
								f6elemf7f12f1f2.SetMatchScope(*f6iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchScope)
							}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.OversizeHandling != nil {
								f6elemf7f12f1f2.SetOversizeHandling(*f6iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.OversizeHandling)
							}
							f6elemf7f12f1.SetCookies(f6elemf7f12f1f2)
						}
						if f6iter.Statement.SizeConstraintStatement.FieldToMatch.HeaderOrder != nil {
							f6elemf7f12f1f3 := &svcsdk.HeaderOrder{}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.HeaderOrder.OversizeHandling != nil {
								f6elemf7f12f1f3.SetOversizeHandling(*f6iter.Statement.SizeConstraintStatement.FieldToMatch.HeaderOrder.OversizeHandling)
							}
							f6elemf7f12f1.SetHeaderOrder(f6elemf7f12f1f3)
						}
						if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Headers != nil {
							f6elemf7f12f1f4 := &svcsdk.Headers{}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchPattern != nil {
								f6elemf7f12f1f4f0 := &svcsdk.HeaderMatchPattern{}
								if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchPattern.All != nil {
									f6elemf7f12f1f4f0f0 := &svcsdk.All{}
									f6elemf7f12f1f4f0.SetAll(f6elemf7f12f1f4f0f0)
								}
								if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders != nil {
									f6elemf7f12f1f4f0f1 := []*string{}
									for _, f6elemf7f12f1f4f0f1iter := range f6iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders {
										var f6elemf7f12f1f4f0f1elem string
										f6elemf7f12f1f4f0f1elem = *f6elemf7f12f1f4f0f1iter
										f6elemf7f12f1f4f0f1 = append(f6elemf7f12f1f4f0f1, &f6elemf7f12f1f4f0f1elem)
									}
									f6elemf7f12f1f4f0.SetExcludedHeaders(f6elemf7f12f1f4f0f1)
								}
								if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders != nil {
									f6elemf7f12f1f4f0f2 := []*string{}
									for _, f6elemf7f12f1f4f0f2iter := range f6iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders {
										var f6elemf7f12f1f4f0f2elem string
										f6elemf7f12f1f4f0f2elem = *f6elemf7f12f1f4f0f2iter
										f6elemf7f12f1f4f0f2 = append(f6elemf7f12f1f4f0f2, &f6elemf7f12f1f4f0f2elem)
									}
									f6elemf7f12f1f4f0.SetIncludedHeaders(f6elemf7f12f1f4f0f2)
								}
								f6elemf7f12f1f4.SetMatchPattern(f6elemf7f12f1f4f0)
							}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchScope != nil {
								f6elemf7f12f1f4.SetMatchScope(*f6iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchScope)
							}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.OversizeHandling != nil {
								f6elemf7f12f1f4.SetOversizeHandling(*f6iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.OversizeHandling)
							}
							f6elemf7f12f1.SetHeaders(f6elemf7f12f1f4)
						}
						if f6iter.Statement.SizeConstraintStatement.FieldToMatch.JA3Fingerprint != nil {
							f6elemf7f12f1f5 := &svcsdk.JA3Fingerprint{}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior != nil {
								f6elemf7f12f1f5.SetFallbackBehavior(*f6iter.Statement.SizeConstraintStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior)
							}
							f6elemf7f12f1.SetJA3Fingerprint(f6elemf7f12f1f5)
						}
						if f6iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody != nil {
							f6elemf7f12f1f6 := &svcsdk.JsonBody{}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior != nil {
								f6elemf7f12f1f6.SetInvalidFallbackBehavior(*f6iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior)
							}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.MatchPattern != nil {
								f6elemf7f12f1f6f1 := &svcsdk.JsonMatchPattern{}
								if f6iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.MatchPattern.All != nil {
									f6elemf7f12f1f6f1f0 := &svcsdk.All{}
									f6elemf7f12f1f6f1.SetAll(f6elemf7f12f1f6f1f0)
								}
								if f6iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths != nil {
									f6elemf7f12f1f6f1f1 := []*string{}
									for _, f6elemf7f12f1f6f1f1iter := range f6iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths {
										var f6elemf7f12f1f6f1f1elem string
										f6elemf7f12f1f6f1f1elem = *f6elemf7f12f1f6f1f1iter
										f6elemf7f12f1f6f1f1 = append(f6elemf7f12f1f6f1f1, &f6elemf7f12f1f6f1f1elem)
									}
									f6elemf7f12f1f6f1.SetIncludedPaths(f6elemf7f12f1f6f1f1)
								}
								f6elemf7f12f1f6.SetMatchPattern(f6elemf7f12f1f6f1)
							}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.MatchScope != nil {
								f6elemf7f12f1f6.SetMatchScope(*f6iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.MatchScope)
							}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.OversizeHandling != nil {
								f6elemf7f12f1f6.SetOversizeHandling(*f6iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.OversizeHandling)
							}
							f6elemf7f12f1.SetJsonBody(f6elemf7f12f1f6)
						}
						if f6iter.Statement.SizeConstraintStatement.FieldToMatch.Method != nil {
							f6elemf7f12f1f7 := &svcsdk.Method{}
							f6elemf7f12f1.SetMethod(f6elemf7f12f1f7)
						}
						if f6iter.Statement.SizeConstraintStatement.FieldToMatch.QueryString != nil {
							f6elemf7f12f1f8 := &svcsdk.QueryString{}
							f6elemf7f12f1.SetQueryString(f6elemf7f12f1f8)
						}
						if f6iter.Statement.SizeConstraintStatement.FieldToMatch.SingleHeader != nil {
							f6elemf7f12f1f9 := &svcsdk.SingleHeader{}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.SingleHeader.Name != nil {
								f6elemf7f12f1f9.SetName(*f6iter.Statement.SizeConstraintStatement.FieldToMatch.SingleHeader.Name)
							}
							f6elemf7f12f1.SetSingleHeader(f6elemf7f12f1f9)
						}
						if f6iter.Statement.SizeConstraintStatement.FieldToMatch.SingleQueryArgument != nil {
							f6elemf7f12f1f10 := &svcsdk.SingleQueryArgument{}
							if f6iter.Statement.SizeConstraintStatement.FieldToMatch.SingleQueryArgument.Name != nil {
								f6elemf7f12f1f10.SetName(*f6iter.Statement.SizeConstraintStatement.FieldToMatch.SingleQueryArgument.Name)
							}
							f6elemf7f12f1.SetSingleQueryArgument(f6elemf7f12f1f10)
						}
						if f6iter.Statement.SizeConstraintStatement.FieldToMatch.URIPath != nil {
							f6elemf7f12f1f11 := &svcsdk.UriPath{}
							f6elemf7f12f1.SetUriPath(f6elemf7f12f1f11)
						}
						f6elemf7f12.SetFieldToMatch(f6elemf7f12f1)
					}
					if f6iter.Statement.SizeConstraintStatement.Size != nil {
						f6elemf7f12.SetSize(*f6iter.Statement.SizeConstraintStatement.Size)
					}
					if f6iter.Statement.SizeConstraintStatement.TextTransformations != nil {
						f6elemf7f12f3 := []*svcsdk.TextTransformation{}
						for _, f6elemf7f12f3iter := range f6iter.Statement.SizeConstraintStatement.TextTransformations {
							f6elemf7f12f3elem := &svcsdk.TextTransformation{}
							if f6elemf7f12f3iter.Priority != nil {
								f6elemf7f12f3elem.SetPriority(*f6elemf7f12f3iter.Priority)
							}
							if f6elemf7f12f3iter.Type != nil {
								f6elemf7f12f3elem.SetType(*f6elemf7f12f3iter.Type)
							}
							f6elemf7f12f3 = append(f6elemf7f12f3, f6elemf7f12f3elem)
						}
						f6elemf7f12.SetTextTransformations(f6elemf7f12f3)
					}
					f6elemf7.SetSizeConstraintStatement(f6elemf7f12)
				}
				if f6iter.Statement.SQLIMatchStatement != nil {
					f6elemf7f13 := &svcsdk.SqliMatchStatement{}
					if f6iter.Statement.SQLIMatchStatement.FieldToMatch != nil {
						f6elemf7f13f0 := &svcsdk.FieldToMatch{}
						if f6iter.Statement.SQLIMatchStatement.FieldToMatch.AllQueryArguments != nil {
							f6elemf7f13f0f0 := &svcsdk.AllQueryArguments{}
							f6elemf7f13f0.SetAllQueryArguments(f6elemf7f13f0f0)
						}
						if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Body != nil {
							f6elemf7f13f0f1 := &svcsdk.Body{}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Body.OversizeHandling != nil {
								f6elemf7f13f0f1.SetOversizeHandling(*f6iter.Statement.SQLIMatchStatement.FieldToMatch.Body.OversizeHandling)
							}
							f6elemf7f13f0.SetBody(f6elemf7f13f0f1)
						}
						if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies != nil {
							f6elemf7f13f0f2 := &svcsdk.Cookies{}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchPattern != nil {
								f6elemf7f13f0f2f0 := &svcsdk.CookieMatchPattern{}
								if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchPattern.All != nil {
									f6elemf7f13f0f2f0f0 := &svcsdk.All{}
									f6elemf7f13f0f2f0.SetAll(f6elemf7f13f0f2f0f0)
								}
								if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies != nil {
									f6elemf7f13f0f2f0f1 := []*string{}
									for _, f6elemf7f13f0f2f0f1iter := range f6iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies {
										var f6elemf7f13f0f2f0f1elem string
										f6elemf7f13f0f2f0f1elem = *f6elemf7f13f0f2f0f1iter
										f6elemf7f13f0f2f0f1 = append(f6elemf7f13f0f2f0f1, &f6elemf7f13f0f2f0f1elem)
									}
									f6elemf7f13f0f2f0.SetExcludedCookies(f6elemf7f13f0f2f0f1)
								}
								if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies != nil {
									f6elemf7f13f0f2f0f2 := []*string{}
									for _, f6elemf7f13f0f2f0f2iter := range f6iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies {
										var f6elemf7f13f0f2f0f2elem string
										f6elemf7f13f0f2f0f2elem = *f6elemf7f13f0f2f0f2iter
										f6elemf7f13f0f2f0f2 = append(f6elemf7f13f0f2f0f2, &f6elemf7f13f0f2f0f2elem)
									}
									f6elemf7f13f0f2f0.SetIncludedCookies(f6elemf7f13f0f2f0f2)
								}
								f6elemf7f13f0f2.SetMatchPattern(f6elemf7f13f0f2f0)
							}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchScope != nil {
								f6elemf7f13f0f2.SetMatchScope(*f6iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchScope)
							}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.OversizeHandling != nil {
								f6elemf7f13f0f2.SetOversizeHandling(*f6iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.OversizeHandling)
							}
							f6elemf7f13f0.SetCookies(f6elemf7f13f0f2)
						}
						if f6iter.Statement.SQLIMatchStatement.FieldToMatch.HeaderOrder != nil {
							f6elemf7f13f0f3 := &svcsdk.HeaderOrder{}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling != nil {
								f6elemf7f13f0f3.SetOversizeHandling(*f6iter.Statement.SQLIMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling)
							}
							f6elemf7f13f0.SetHeaderOrder(f6elemf7f13f0f3)
						}
						if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Headers != nil {
							f6elemf7f13f0f4 := &svcsdk.Headers{}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchPattern != nil {
								f6elemf7f13f0f4f0 := &svcsdk.HeaderMatchPattern{}
								if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchPattern.All != nil {
									f6elemf7f13f0f4f0f0 := &svcsdk.All{}
									f6elemf7f13f0f4f0.SetAll(f6elemf7f13f0f4f0f0)
								}
								if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders != nil {
									f6elemf7f13f0f4f0f1 := []*string{}
									for _, f6elemf7f13f0f4f0f1iter := range f6iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders {
										var f6elemf7f13f0f4f0f1elem string
										f6elemf7f13f0f4f0f1elem = *f6elemf7f13f0f4f0f1iter
										f6elemf7f13f0f4f0f1 = append(f6elemf7f13f0f4f0f1, &f6elemf7f13f0f4f0f1elem)
									}
									f6elemf7f13f0f4f0.SetExcludedHeaders(f6elemf7f13f0f4f0f1)
								}
								if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders != nil {
									f6elemf7f13f0f4f0f2 := []*string{}
									for _, f6elemf7f13f0f4f0f2iter := range f6iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders {
										var f6elemf7f13f0f4f0f2elem string
										f6elemf7f13f0f4f0f2elem = *f6elemf7f13f0f4f0f2iter
										f6elemf7f13f0f4f0f2 = append(f6elemf7f13f0f4f0f2, &f6elemf7f13f0f4f0f2elem)
									}
									f6elemf7f13f0f4f0.SetIncludedHeaders(f6elemf7f13f0f4f0f2)
								}
								f6elemf7f13f0f4.SetMatchPattern(f6elemf7f13f0f4f0)
							}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchScope != nil {
								f6elemf7f13f0f4.SetMatchScope(*f6iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchScope)
							}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.OversizeHandling != nil {
								f6elemf7f13f0f4.SetOversizeHandling(*f6iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.OversizeHandling)
							}
							f6elemf7f13f0.SetHeaders(f6elemf7f13f0f4)
						}
						if f6iter.Statement.SQLIMatchStatement.FieldToMatch.JA3Fingerprint != nil {
							f6elemf7f13f0f5 := &svcsdk.JA3Fingerprint{}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior != nil {
								f6elemf7f13f0f5.SetFallbackBehavior(*f6iter.Statement.SQLIMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior)
							}
							f6elemf7f13f0.SetJA3Fingerprint(f6elemf7f13f0f5)
						}
						if f6iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody != nil {
							f6elemf7f13f0f6 := &svcsdk.JsonBody{}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior != nil {
								f6elemf7f13f0f6.SetInvalidFallbackBehavior(*f6iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior)
							}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.MatchPattern != nil {
								f6elemf7f13f0f6f1 := &svcsdk.JsonMatchPattern{}
								if f6iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.MatchPattern.All != nil {
									f6elemf7f13f0f6f1f0 := &svcsdk.All{}
									f6elemf7f13f0f6f1.SetAll(f6elemf7f13f0f6f1f0)
								}
								if f6iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths != nil {
									f6elemf7f13f0f6f1f1 := []*string{}
									for _, f6elemf7f13f0f6f1f1iter := range f6iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths {
										var f6elemf7f13f0f6f1f1elem string
										f6elemf7f13f0f6f1f1elem = *f6elemf7f13f0f6f1f1iter
										f6elemf7f13f0f6f1f1 = append(f6elemf7f13f0f6f1f1, &f6elemf7f13f0f6f1f1elem)
									}
									f6elemf7f13f0f6f1.SetIncludedPaths(f6elemf7f13f0f6f1f1)
								}
								f6elemf7f13f0f6.SetMatchPattern(f6elemf7f13f0f6f1)
							}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.MatchScope != nil {
								f6elemf7f13f0f6.SetMatchScope(*f6iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.MatchScope)
							}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.OversizeHandling != nil {
								f6elemf7f13f0f6.SetOversizeHandling(*f6iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.OversizeHandling)
							}
							f6elemf7f13f0.SetJsonBody(f6elemf7f13f0f6)
						}
						if f6iter.Statement.SQLIMatchStatement.FieldToMatch.Method != nil {
							f6elemf7f13f0f7 := &svcsdk.Method{}
							f6elemf7f13f0.SetMethod(f6elemf7f13f0f7)
						}
						if f6iter.Statement.SQLIMatchStatement.FieldToMatch.QueryString != nil {
							f6elemf7f13f0f8 := &svcsdk.QueryString{}
							f6elemf7f13f0.SetQueryString(f6elemf7f13f0f8)
						}
						if f6iter.Statement.SQLIMatchStatement.FieldToMatch.SingleHeader != nil {
							f6elemf7f13f0f9 := &svcsdk.SingleHeader{}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.SingleHeader.Name != nil {
								f6elemf7f13f0f9.SetName(*f6iter.Statement.SQLIMatchStatement.FieldToMatch.SingleHeader.Name)
							}
							f6elemf7f13f0.SetSingleHeader(f6elemf7f13f0f9)
						}
						if f6iter.Statement.SQLIMatchStatement.FieldToMatch.SingleQueryArgument != nil {
							f6elemf7f13f0f10 := &svcsdk.SingleQueryArgument{}
							if f6iter.Statement.SQLIMatchStatement.FieldToMatch.SingleQueryArgument.Name != nil {
								f6elemf7f13f0f10.SetName(*f6iter.Statement.SQLIMatchStatement.FieldToMatch.SingleQueryArgument.Name)
							}
							f6elemf7f13f0.SetSingleQueryArgument(f6elemf7f13f0f10)
						}
						if f6iter.Statement.SQLIMatchStatement.FieldToMatch.URIPath != nil {
							f6elemf7f13f0f11 := &svcsdk.UriPath{}
							f6elemf7f13f0.SetUriPath(f6elemf7f13f0f11)
						}
						f6elemf7f13.SetFieldToMatch(f6elemf7f13f0)
					}
					if f6iter.Statement.SQLIMatchStatement.SensitivityLevel != nil {
						f6elemf7f13.SetSensitivityLevel(*f6iter.Statement.SQLIMatchStatement.SensitivityLevel)
					}
					if f6iter.Statement.SQLIMatchStatement.TextTransformations != nil {
						f6elemf7f13f2 := []*svcsdk.TextTransformation{}
						for _, f6elemf7f13f2iter := range f6iter.Statement.SQLIMatchStatement.TextTransformations {
							f6elemf7f13f2elem := &svcsdk.TextTransformation{}
							if f6elemf7f13f2iter.Priority != nil {
								f6elemf7f13f2elem.SetPriority(*f6elemf7f13f2iter.Priority)
							}
							if f6elemf7f13f2iter.Type != nil {
								f6elemf7f13f2elem.SetType(*f6elemf7f13f2iter.Type)
							}
							f6elemf7f13f2 = append(f6elemf7f13f2, f6elemf7f13f2elem)
						}
						f6elemf7f13.SetTextTransformations(f6elemf7f13f2)
					}
					f6elemf7.SetSqliMatchStatement(f6elemf7f13)
				}
				if f6iter.Statement.XSSMatchStatement != nil {
					f6elemf7f14 := &svcsdk.XssMatchStatement{}
					if f6iter.Statement.XSSMatchStatement.FieldToMatch != nil {
						f6elemf7f14f0 := &svcsdk.FieldToMatch{}
						if f6iter.Statement.XSSMatchStatement.FieldToMatch.AllQueryArguments != nil {
							f6elemf7f14f0f0 := &svcsdk.AllQueryArguments{}
							f6elemf7f14f0.SetAllQueryArguments(f6elemf7f14f0f0)
						}
						if f6iter.Statement.XSSMatchStatement.FieldToMatch.Body != nil {
							f6elemf7f14f0f1 := &svcsdk.Body{}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.Body.OversizeHandling != nil {
								f6elemf7f14f0f1.SetOversizeHandling(*f6iter.Statement.XSSMatchStatement.FieldToMatch.Body.OversizeHandling)
							}
							f6elemf7f14f0.SetBody(f6elemf7f14f0f1)
						}
						if f6iter.Statement.XSSMatchStatement.FieldToMatch.Cookies != nil {
							f6elemf7f14f0f2 := &svcsdk.Cookies{}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchPattern != nil {
								f6elemf7f14f0f2f0 := &svcsdk.CookieMatchPattern{}
								if f6iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchPattern.All != nil {
									f6elemf7f14f0f2f0f0 := &svcsdk.All{}
									f6elemf7f14f0f2f0.SetAll(f6elemf7f14f0f2f0f0)
								}
								if f6iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies != nil {
									f6elemf7f14f0f2f0f1 := []*string{}
									for _, f6elemf7f14f0f2f0f1iter := range f6iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies {
										var f6elemf7f14f0f2f0f1elem string
										f6elemf7f14f0f2f0f1elem = *f6elemf7f14f0f2f0f1iter
										f6elemf7f14f0f2f0f1 = append(f6elemf7f14f0f2f0f1, &f6elemf7f14f0f2f0f1elem)
									}
									f6elemf7f14f0f2f0.SetExcludedCookies(f6elemf7f14f0f2f0f1)
								}
								if f6iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies != nil {
									f6elemf7f14f0f2f0f2 := []*string{}
									for _, f6elemf7f14f0f2f0f2iter := range f6iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies {
										var f6elemf7f14f0f2f0f2elem string
										f6elemf7f14f0f2f0f2elem = *f6elemf7f14f0f2f0f2iter
										f6elemf7f14f0f2f0f2 = append(f6elemf7f14f0f2f0f2, &f6elemf7f14f0f2f0f2elem)
									}
									f6elemf7f14f0f2f0.SetIncludedCookies(f6elemf7f14f0f2f0f2)
								}
								f6elemf7f14f0f2.SetMatchPattern(f6elemf7f14f0f2f0)
							}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchScope != nil {
								f6elemf7f14f0f2.SetMatchScope(*f6iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchScope)
							}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.OversizeHandling != nil {
								f6elemf7f14f0f2.SetOversizeHandling(*f6iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.OversizeHandling)
							}
							f6elemf7f14f0.SetCookies(f6elemf7f14f0f2)
						}
						if f6iter.Statement.XSSMatchStatement.FieldToMatch.HeaderOrder != nil {
							f6elemf7f14f0f3 := &svcsdk.HeaderOrder{}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling != nil {
								f6elemf7f14f0f3.SetOversizeHandling(*f6iter.Statement.XSSMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling)
							}
							f6elemf7f14f0.SetHeaderOrder(f6elemf7f14f0f3)
						}
						if f6iter.Statement.XSSMatchStatement.FieldToMatch.Headers != nil {
							f6elemf7f14f0f4 := &svcsdk.Headers{}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchPattern != nil {
								f6elemf7f14f0f4f0 := &svcsdk.HeaderMatchPattern{}
								if f6iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchPattern.All != nil {
									f6elemf7f14f0f4f0f0 := &svcsdk.All{}
									f6elemf7f14f0f4f0.SetAll(f6elemf7f14f0f4f0f0)
								}
								if f6iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders != nil {
									f6elemf7f14f0f4f0f1 := []*string{}
									for _, f6elemf7f14f0f4f0f1iter := range f6iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders {
										var f6elemf7f14f0f4f0f1elem string
										f6elemf7f14f0f4f0f1elem = *f6elemf7f14f0f4f0f1iter
										f6elemf7f14f0f4f0f1 = append(f6elemf7f14f0f4f0f1, &f6elemf7f14f0f4f0f1elem)
									}
									f6elemf7f14f0f4f0.SetExcludedHeaders(f6elemf7f14f0f4f0f1)
								}
								if f6iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders != nil {
									f6elemf7f14f0f4f0f2 := []*string{}
									for _, f6elemf7f14f0f4f0f2iter := range f6iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders {
										var f6elemf7f14f0f4f0f2elem string
										f6elemf7f14f0f4f0f2elem = *f6elemf7f14f0f4f0f2iter
										f6elemf7f14f0f4f0f2 = append(f6elemf7f14f0f4f0f2, &f6elemf7f14f0f4f0f2elem)
									}
									f6elemf7f14f0f4f0.SetIncludedHeaders(f6elemf7f14f0f4f0f2)
								}
								f6elemf7f14f0f4.SetMatchPattern(f6elemf7f14f0f4f0)
							}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchScope != nil {
								f6elemf7f14f0f4.SetMatchScope(*f6iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchScope)
							}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.Headers.OversizeHandling != nil {
								f6elemf7f14f0f4.SetOversizeHandling(*f6iter.Statement.XSSMatchStatement.FieldToMatch.Headers.OversizeHandling)
							}
							f6elemf7f14f0.SetHeaders(f6elemf7f14f0f4)
						}
						if f6iter.Statement.XSSMatchStatement.FieldToMatch.JA3Fingerprint != nil {
							f6elemf7f14f0f5 := &svcsdk.JA3Fingerprint{}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior != nil {
								f6elemf7f14f0f5.SetFallbackBehavior(*f6iter.Statement.XSSMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior)
							}
							f6elemf7f14f0.SetJA3Fingerprint(f6elemf7f14f0f5)
						}
						if f6iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody != nil {
							f6elemf7f14f0f6 := &svcsdk.JsonBody{}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior != nil {
								f6elemf7f14f0f6.SetInvalidFallbackBehavior(*f6iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior)
							}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.MatchPattern != nil {
								f6elemf7f14f0f6f1 := &svcsdk.JsonMatchPattern{}
								if f6iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.MatchPattern.All != nil {
									f6elemf7f14f0f6f1f0 := &svcsdk.All{}
									f6elemf7f14f0f6f1.SetAll(f6elemf7f14f0f6f1f0)
								}
								if f6iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths != nil {
									f6elemf7f14f0f6f1f1 := []*string{}
									for _, f6elemf7f14f0f6f1f1iter := range f6iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths {
										var f6elemf7f14f0f6f1f1elem string
										f6elemf7f14f0f6f1f1elem = *f6elemf7f14f0f6f1f1iter
										f6elemf7f14f0f6f1f1 = append(f6elemf7f14f0f6f1f1, &f6elemf7f14f0f6f1f1elem)
									}
									f6elemf7f14f0f6f1.SetIncludedPaths(f6elemf7f14f0f6f1f1)
								}
								f6elemf7f14f0f6.SetMatchPattern(f6elemf7f14f0f6f1)
							}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.MatchScope != nil {
								f6elemf7f14f0f6.SetMatchScope(*f6iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.MatchScope)
							}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.OversizeHandling != nil {
								f6elemf7f14f0f6.SetOversizeHandling(*f6iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.OversizeHandling)
							}
							f6elemf7f14f0.SetJsonBody(f6elemf7f14f0f6)
						}
						if f6iter.Statement.XSSMatchStatement.FieldToMatch.Method != nil {
							f6elemf7f14f0f7 := &svcsdk.Method{}
							f6elemf7f14f0.SetMethod(f6elemf7f14f0f7)
						}
						if f6iter.Statement.XSSMatchStatement.FieldToMatch.QueryString != nil {
							f6elemf7f14f0f8 := &svcsdk.QueryString{}
							f6elemf7f14f0.SetQueryString(f6elemf7f14f0f8)
						}
						if f6iter.Statement.XSSMatchStatement.FieldToMatch.SingleHeader != nil {
							f6elemf7f14f0f9 := &svcsdk.SingleHeader{}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.SingleHeader.Name != nil {
								f6elemf7f14f0f9.SetName(*f6iter.Statement.XSSMatchStatement.FieldToMatch.SingleHeader.Name)
							}
							f6elemf7f14f0.SetSingleHeader(f6elemf7f14f0f9)
						}
						if f6iter.Statement.XSSMatchStatement.FieldToMatch.SingleQueryArgument != nil {
							f6elemf7f14f0f10 := &svcsdk.SingleQueryArgument{}
							if f6iter.Statement.XSSMatchStatement.FieldToMatch.SingleQueryArgument.Name != nil {
								f6elemf7f14f0f10.SetName(*f6iter.Statement.XSSMatchStatement.FieldToMatch.SingleQueryArgument.Name)
							}
							f6elemf7f14f0.SetSingleQueryArgument(f6elemf7f14f0f10)
						}
						if f6iter.Statement.XSSMatchStatement.FieldToMatch.URIPath != nil {
							f6elemf7f14f0f11 := &svcsdk.UriPath{}
							f6elemf7f14f0.SetUriPath(f6elemf7f14f0f11)
						}
						f6elemf7f14.SetFieldToMatch(f6elemf7f14f0)
					}
					if f6iter.Statement.XSSMatchStatement.TextTransformations != nil {
						f6elemf7f14f1 := []*svcsdk.TextTransformation{}
						for _, f6elemf7f14f1iter := range f6iter.Statement.XSSMatchStatement.TextTransformations {
							f6elemf7f14f1elem := &svcsdk.TextTransformation{}
							if f6elemf7f14f1iter.Priority != nil {
								f6elemf7f14f1elem.SetPriority(*f6elemf7f14f1iter.Priority)
							}
							if f6elemf7f14f1iter.Type != nil {
								f6elemf7f14f1elem.SetType(*f6elemf7f14f1iter.Type)
							}
							f6elemf7f14f1 = append(f6elemf7f14f1, f6elemf7f14f1elem)
						}
						f6elemf7f14.SetTextTransformations(f6elemf7f14f1)
					}
					f6elemf7.SetXssMatchStatement(f6elemf7f14)
				}
				f6elem.SetStatement(f6elemf7)
			}
			if f6iter.VisibilityConfig != nil {
				f6elemf8 := &svcsdk.VisibilityConfig{}
				if f6iter.VisibilityConfig.CloudWatchMetricsEnabled != nil {
					f6elemf8.SetCloudWatchMetricsEnabled(*f6iter.VisibilityConfig.CloudWatchMetricsEnabled)
				}
				if f6iter.VisibilityConfig.MetricName != nil {
					f6elemf8.SetMetricName(*f6iter.VisibilityConfig.MetricName)
				}
				if f6iter.VisibilityConfig.SampledRequestsEnabled != nil {
					f6elemf8.SetSampledRequestsEnabled(*f6iter.VisibilityConfig.SampledRequestsEnabled)
				}
				f6elem.SetVisibilityConfig(f6elemf8)
			}
			f6 = append(f6, f6elem)
		}
		res.SetRules(f6)
	}
	if cr.Spec.ForProvider.Scope != nil {
		res.SetScope(*cr.Spec.ForProvider.Scope)
	}
	if cr.Spec.ForProvider.Tags != nil {
		f8 := []*svcsdk.Tag{}
		for _, f8iter := range cr.Spec.ForProvider.Tags {
			f8elem := &svcsdk.Tag{}
			if f8iter.Key != nil {
				f8elem.SetKey(*f8iter.Key)
			}
			if f8iter.Value != nil {
				f8elem.SetValue(*f8iter.Value)
			}
			f8 = append(f8, f8elem)
		}
		res.SetTags(f8)
	}
	if cr.Spec.ForProvider.TokenDomains != nil {
		f9 := []*string{}
		for _, f9iter := range cr.Spec.ForProvider.TokenDomains {
			var f9elem string
			f9elem = *f9iter
			f9 = append(f9, &f9elem)
		}
		res.SetTokenDomains(f9)
	}
	if cr.Spec.ForProvider.VisibilityConfig != nil {
		f10 := &svcsdk.VisibilityConfig{}
		if cr.Spec.ForProvider.VisibilityConfig.CloudWatchMetricsEnabled != nil {
			f10.SetCloudWatchMetricsEnabled(*cr.Spec.ForProvider.VisibilityConfig.CloudWatchMetricsEnabled)
		}
		if cr.Spec.ForProvider.VisibilityConfig.MetricName != nil {
			f10.SetMetricName(*cr.Spec.ForProvider.VisibilityConfig.MetricName)
		}
		if cr.Spec.ForProvider.VisibilityConfig.SampledRequestsEnabled != nil {
			f10.SetSampledRequestsEnabled(*cr.Spec.ForProvider.VisibilityConfig.SampledRequestsEnabled)
		}
		res.SetVisibilityConfig(f10)
	}

	return res
}

// GenerateUpdateWebACLInput returns an update input.
func GenerateUpdateWebACLInput(cr *svcapitypes.WebACL) *svcsdk.UpdateWebACLInput {
	res := &svcsdk.UpdateWebACLInput{}

	if cr.Spec.ForProvider.AssociationConfig != nil {
		f0 := &svcsdk.AssociationConfig{}
		if cr.Spec.ForProvider.AssociationConfig.RequestBody != nil {
			f0f0 := map[string]*svcsdk.RequestBodyAssociatedResourceTypeConfig{}
			for f0f0key, f0f0valiter := range cr.Spec.ForProvider.AssociationConfig.RequestBody {
				f0f0val := &svcsdk.RequestBodyAssociatedResourceTypeConfig{}
				if f0f0valiter.DefaultSizeInspectionLimit != nil {
					f0f0val.SetDefaultSizeInspectionLimit(*f0f0valiter.DefaultSizeInspectionLimit)
				}
				f0f0[f0f0key] = f0f0val
			}
			f0.SetRequestBody(f0f0)
		}
		res.SetAssociationConfig(f0)
	}
	if cr.Spec.ForProvider.CaptchaConfig != nil {
		f1 := &svcsdk.CaptchaConfig{}
		if cr.Spec.ForProvider.CaptchaConfig.ImmunityTimeProperty != nil {
			f1f0 := &svcsdk.ImmunityTimeProperty{}
			if cr.Spec.ForProvider.CaptchaConfig.ImmunityTimeProperty.ImmunityTime != nil {
				f1f0.SetImmunityTime(*cr.Spec.ForProvider.CaptchaConfig.ImmunityTimeProperty.ImmunityTime)
			}
			f1.SetImmunityTimeProperty(f1f0)
		}
		res.SetCaptchaConfig(f1)
	}
	if cr.Spec.ForProvider.ChallengeConfig != nil {
		f2 := &svcsdk.ChallengeConfig{}
		if cr.Spec.ForProvider.ChallengeConfig.ImmunityTimeProperty != nil {
			f2f0 := &svcsdk.ImmunityTimeProperty{}
			if cr.Spec.ForProvider.ChallengeConfig.ImmunityTimeProperty.ImmunityTime != nil {
				f2f0.SetImmunityTime(*cr.Spec.ForProvider.ChallengeConfig.ImmunityTimeProperty.ImmunityTime)
			}
			f2.SetImmunityTimeProperty(f2f0)
		}
		res.SetChallengeConfig(f2)
	}
	if cr.Spec.ForProvider.CustomResponseBodies != nil {
		f3 := map[string]*svcsdk.CustomResponseBody{}
		for f3key, f3valiter := range cr.Spec.ForProvider.CustomResponseBodies {
			f3val := &svcsdk.CustomResponseBody{}
			if f3valiter.Content != nil {
				f3val.SetContent(*f3valiter.Content)
			}
			if f3valiter.ContentType != nil {
				f3val.SetContentType(*f3valiter.ContentType)
			}
			f3[f3key] = f3val
		}
		res.SetCustomResponseBodies(f3)
	}
	if cr.Spec.ForProvider.DefaultAction != nil {
		f4 := &svcsdk.DefaultAction{}
		if cr.Spec.ForProvider.DefaultAction.Allow != nil {
			f4f0 := &svcsdk.AllowAction{}
			if cr.Spec.ForProvider.DefaultAction.Allow.CustomRequestHandling != nil {
				f4f0f0 := &svcsdk.CustomRequestHandling{}
				if cr.Spec.ForProvider.DefaultAction.Allow.CustomRequestHandling.InsertHeaders != nil {
					f4f0f0f0 := []*svcsdk.CustomHTTPHeader{}
					for _, f4f0f0f0iter := range cr.Spec.ForProvider.DefaultAction.Allow.CustomRequestHandling.InsertHeaders {
						f4f0f0f0elem := &svcsdk.CustomHTTPHeader{}
						if f4f0f0f0iter.Name != nil {
							f4f0f0f0elem.SetName(*f4f0f0f0iter.Name)
						}
						if f4f0f0f0iter.Value != nil {
							f4f0f0f0elem.SetValue(*f4f0f0f0iter.Value)
						}
						f4f0f0f0 = append(f4f0f0f0, f4f0f0f0elem)
					}
					f4f0f0.SetInsertHeaders(f4f0f0f0)
				}
				f4f0.SetCustomRequestHandling(f4f0f0)
			}
			f4.SetAllow(f4f0)
		}
		if cr.Spec.ForProvider.DefaultAction.Block != nil {
			f4f1 := &svcsdk.BlockAction{}
			if cr.Spec.ForProvider.DefaultAction.Block.CustomResponse != nil {
				f4f1f0 := &svcsdk.CustomResponse{}
				if cr.Spec.ForProvider.DefaultAction.Block.CustomResponse.CustomResponseBodyKey != nil {
					f4f1f0.SetCustomResponseBodyKey(*cr.Spec.ForProvider.DefaultAction.Block.CustomResponse.CustomResponseBodyKey)
				}
				if cr.Spec.ForProvider.DefaultAction.Block.CustomResponse.ResponseCode != nil {
					f4f1f0.SetResponseCode(*cr.Spec.ForProvider.DefaultAction.Block.CustomResponse.ResponseCode)
				}
				if cr.Spec.ForProvider.DefaultAction.Block.CustomResponse.ResponseHeaders != nil {
					f4f1f0f2 := []*svcsdk.CustomHTTPHeader{}
					for _, f4f1f0f2iter := range cr.Spec.ForProvider.DefaultAction.Block.CustomResponse.ResponseHeaders {
						f4f1f0f2elem := &svcsdk.CustomHTTPHeader{}
						if f4f1f0f2iter.Name != nil {
							f4f1f0f2elem.SetName(*f4f1f0f2iter.Name)
						}
						if f4f1f0f2iter.Value != nil {
							f4f1f0f2elem.SetValue(*f4f1f0f2iter.Value)
						}
						f4f1f0f2 = append(f4f1f0f2, f4f1f0f2elem)
					}
					f4f1f0.SetResponseHeaders(f4f1f0f2)
				}
				f4f1.SetCustomResponse(f4f1f0)
			}
			f4.SetBlock(f4f1)
		}
		res.SetDefaultAction(f4)
	}
	if cr.Spec.ForProvider.Description != nil {
		res.SetDescription(*cr.Spec.ForProvider.Description)
	}
	if cr.Status.AtProvider.ID != nil {
		res.SetId(*cr.Status.AtProvider.ID)
	}
	if cr.Status.AtProvider.LockToken != nil {
		res.SetLockToken(*cr.Status.AtProvider.LockToken)
	}
	if cr.Spec.ForProvider.Rules != nil {
		f8 := []*svcsdk.Rule{}
		for _, f8iter := range cr.Spec.ForProvider.Rules {
			f8elem := &svcsdk.Rule{}
			if f8iter.Action != nil {
				f8elemf0 := &svcsdk.RuleAction{}
				if f8iter.Action.Allow != nil {
					f8elemf0f0 := &svcsdk.AllowAction{}
					if f8iter.Action.Allow.CustomRequestHandling != nil {
						f8elemf0f0f0 := &svcsdk.CustomRequestHandling{}
						if f8iter.Action.Allow.CustomRequestHandling.InsertHeaders != nil {
							f8elemf0f0f0f0 := []*svcsdk.CustomHTTPHeader{}
							for _, f8elemf0f0f0f0iter := range f8iter.Action.Allow.CustomRequestHandling.InsertHeaders {
								f8elemf0f0f0f0elem := &svcsdk.CustomHTTPHeader{}
								if f8elemf0f0f0f0iter.Name != nil {
									f8elemf0f0f0f0elem.SetName(*f8elemf0f0f0f0iter.Name)
								}
								if f8elemf0f0f0f0iter.Value != nil {
									f8elemf0f0f0f0elem.SetValue(*f8elemf0f0f0f0iter.Value)
								}
								f8elemf0f0f0f0 = append(f8elemf0f0f0f0, f8elemf0f0f0f0elem)
							}
							f8elemf0f0f0.SetInsertHeaders(f8elemf0f0f0f0)
						}
						f8elemf0f0.SetCustomRequestHandling(f8elemf0f0f0)
					}
					f8elemf0.SetAllow(f8elemf0f0)
				}
				if f8iter.Action.Block != nil {
					f8elemf0f1 := &svcsdk.BlockAction{}
					if f8iter.Action.Block.CustomResponse != nil {
						f8elemf0f1f0 := &svcsdk.CustomResponse{}
						if f8iter.Action.Block.CustomResponse.CustomResponseBodyKey != nil {
							f8elemf0f1f0.SetCustomResponseBodyKey(*f8iter.Action.Block.CustomResponse.CustomResponseBodyKey)
						}
						if f8iter.Action.Block.CustomResponse.ResponseCode != nil {
							f8elemf0f1f0.SetResponseCode(*f8iter.Action.Block.CustomResponse.ResponseCode)
						}
						if f8iter.Action.Block.CustomResponse.ResponseHeaders != nil {
							f8elemf0f1f0f2 := []*svcsdk.CustomHTTPHeader{}
							for _, f8elemf0f1f0f2iter := range f8iter.Action.Block.CustomResponse.ResponseHeaders {
								f8elemf0f1f0f2elem := &svcsdk.CustomHTTPHeader{}
								if f8elemf0f1f0f2iter.Name != nil {
									f8elemf0f1f0f2elem.SetName(*f8elemf0f1f0f2iter.Name)
								}
								if f8elemf0f1f0f2iter.Value != nil {
									f8elemf0f1f0f2elem.SetValue(*f8elemf0f1f0f2iter.Value)
								}
								f8elemf0f1f0f2 = append(f8elemf0f1f0f2, f8elemf0f1f0f2elem)
							}
							f8elemf0f1f0.SetResponseHeaders(f8elemf0f1f0f2)
						}
						f8elemf0f1.SetCustomResponse(f8elemf0f1f0)
					}
					f8elemf0.SetBlock(f8elemf0f1)
				}
				if f8iter.Action.Captcha != nil {
					f8elemf0f2 := &svcsdk.CaptchaAction{}
					if f8iter.Action.Captcha.CustomRequestHandling != nil {
						f8elemf0f2f0 := &svcsdk.CustomRequestHandling{}
						if f8iter.Action.Captcha.CustomRequestHandling.InsertHeaders != nil {
							f8elemf0f2f0f0 := []*svcsdk.CustomHTTPHeader{}
							for _, f8elemf0f2f0f0iter := range f8iter.Action.Captcha.CustomRequestHandling.InsertHeaders {
								f8elemf0f2f0f0elem := &svcsdk.CustomHTTPHeader{}
								if f8elemf0f2f0f0iter.Name != nil {
									f8elemf0f2f0f0elem.SetName(*f8elemf0f2f0f0iter.Name)
								}
								if f8elemf0f2f0f0iter.Value != nil {
									f8elemf0f2f0f0elem.SetValue(*f8elemf0f2f0f0iter.Value)
								}
								f8elemf0f2f0f0 = append(f8elemf0f2f0f0, f8elemf0f2f0f0elem)
							}
							f8elemf0f2f0.SetInsertHeaders(f8elemf0f2f0f0)
						}
						f8elemf0f2.SetCustomRequestHandling(f8elemf0f2f0)
					}
					f8elemf0.SetCaptcha(f8elemf0f2)
				}
				if f8iter.Action.Challenge != nil {
					f8elemf0f3 := &svcsdk.ChallengeAction{}
					if f8iter.Action.Challenge.CustomRequestHandling != nil {
						f8elemf0f3f0 := &svcsdk.CustomRequestHandling{}
						if f8iter.Action.Challenge.CustomRequestHandling.InsertHeaders != nil {
							f8elemf0f3f0f0 := []*svcsdk.CustomHTTPHeader{}
							for _, f8elemf0f3f0f0iter := range f8iter.Action.Challenge.CustomRequestHandling.InsertHeaders {
								f8elemf0f3f0f0elem := &svcsdk.CustomHTTPHeader{}
								if f8elemf0f3f0f0iter.Name != nil {
									f8elemf0f3f0f0elem.SetName(*f8elemf0f3f0f0iter.Name)
								}
								if f8elemf0f3f0f0iter.Value != nil {
									f8elemf0f3f0f0elem.SetValue(*f8elemf0f3f0f0iter.Value)
								}
								f8elemf0f3f0f0 = append(f8elemf0f3f0f0, f8elemf0f3f0f0elem)
							}
							f8elemf0f3f0.SetInsertHeaders(f8elemf0f3f0f0)
						}
						f8elemf0f3.SetCustomRequestHandling(f8elemf0f3f0)
					}
					f8elemf0.SetChallenge(f8elemf0f3)
				}
				if f8iter.Action.Count != nil {
					f8elemf0f4 := &svcsdk.CountAction{}
					if f8iter.Action.Count.CustomRequestHandling != nil {
						f8elemf0f4f0 := &svcsdk.CustomRequestHandling{}
						if f8iter.Action.Count.CustomRequestHandling.InsertHeaders != nil {
							f8elemf0f4f0f0 := []*svcsdk.CustomHTTPHeader{}
							for _, f8elemf0f4f0f0iter := range f8iter.Action.Count.CustomRequestHandling.InsertHeaders {
								f8elemf0f4f0f0elem := &svcsdk.CustomHTTPHeader{}
								if f8elemf0f4f0f0iter.Name != nil {
									f8elemf0f4f0f0elem.SetName(*f8elemf0f4f0f0iter.Name)
								}
								if f8elemf0f4f0f0iter.Value != nil {
									f8elemf0f4f0f0elem.SetValue(*f8elemf0f4f0f0iter.Value)
								}
								f8elemf0f4f0f0 = append(f8elemf0f4f0f0, f8elemf0f4f0f0elem)
							}
							f8elemf0f4f0.SetInsertHeaders(f8elemf0f4f0f0)
						}
						f8elemf0f4.SetCustomRequestHandling(f8elemf0f4f0)
					}
					f8elemf0.SetCount(f8elemf0f4)
				}
				f8elem.SetAction(f8elemf0)
			}
			if f8iter.CaptchaConfig != nil {
				f8elemf1 := &svcsdk.CaptchaConfig{}
				if f8iter.CaptchaConfig.ImmunityTimeProperty != nil {
					f8elemf1f0 := &svcsdk.ImmunityTimeProperty{}
					if f8iter.CaptchaConfig.ImmunityTimeProperty.ImmunityTime != nil {
						f8elemf1f0.SetImmunityTime(*f8iter.CaptchaConfig.ImmunityTimeProperty.ImmunityTime)
					}
					f8elemf1.SetImmunityTimeProperty(f8elemf1f0)
				}
				f8elem.SetCaptchaConfig(f8elemf1)
			}
			if f8iter.ChallengeConfig != nil {
				f8elemf2 := &svcsdk.ChallengeConfig{}
				if f8iter.ChallengeConfig.ImmunityTimeProperty != nil {
					f8elemf2f0 := &svcsdk.ImmunityTimeProperty{}
					if f8iter.ChallengeConfig.ImmunityTimeProperty.ImmunityTime != nil {
						f8elemf2f0.SetImmunityTime(*f8iter.ChallengeConfig.ImmunityTimeProperty.ImmunityTime)
					}
					f8elemf2.SetImmunityTimeProperty(f8elemf2f0)
				}
				f8elem.SetChallengeConfig(f8elemf2)
			}
			if f8iter.Name != nil {
				f8elem.SetName(*f8iter.Name)
			}
			if f8iter.OverrideAction != nil {
				f8elemf4 := &svcsdk.OverrideAction{}
				if f8iter.OverrideAction.Count != nil {
					f8elemf4f0 := &svcsdk.CountAction{}
					if f8iter.OverrideAction.Count.CustomRequestHandling != nil {
						f8elemf4f0f0 := &svcsdk.CustomRequestHandling{}
						if f8iter.OverrideAction.Count.CustomRequestHandling.InsertHeaders != nil {
							f8elemf4f0f0f0 := []*svcsdk.CustomHTTPHeader{}
							for _, f8elemf4f0f0f0iter := range f8iter.OverrideAction.Count.CustomRequestHandling.InsertHeaders {
								f8elemf4f0f0f0elem := &svcsdk.CustomHTTPHeader{}
								if f8elemf4f0f0f0iter.Name != nil {
									f8elemf4f0f0f0elem.SetName(*f8elemf4f0f0f0iter.Name)
								}
								if f8elemf4f0f0f0iter.Value != nil {
									f8elemf4f0f0f0elem.SetValue(*f8elemf4f0f0f0iter.Value)
								}
								f8elemf4f0f0f0 = append(f8elemf4f0f0f0, f8elemf4f0f0f0elem)
							}
							f8elemf4f0f0.SetInsertHeaders(f8elemf4f0f0f0)
						}
						f8elemf4f0.SetCustomRequestHandling(f8elemf4f0f0)
					}
					f8elemf4.SetCount(f8elemf4f0)
				}
				if f8iter.OverrideAction.None != nil {
					f8elemf4f1 := &svcsdk.NoneAction{}
					f8elemf4.SetNone(f8elemf4f1)
				}
				f8elem.SetOverrideAction(f8elemf4)
			}
			if f8iter.Priority != nil {
				f8elem.SetPriority(*f8iter.Priority)
			}
			if f8iter.RuleLabels != nil {
				f8elemf6 := []*svcsdk.Label{}
				for _, f8elemf6iter := range f8iter.RuleLabels {
					f8elemf6elem := &svcsdk.Label{}
					if f8elemf6iter.Name != nil {
						f8elemf6elem.SetName(*f8elemf6iter.Name)
					}
					f8elemf6 = append(f8elemf6, f8elemf6elem)
				}
				f8elem.SetRuleLabels(f8elemf6)
			}
			if f8iter.Statement != nil {
				f8elemf7 := &svcsdk.Statement{}
				if f8iter.Statement.ByteMatchStatement != nil {
					f8elemf7f1 := &svcsdk.ByteMatchStatement{}
					if f8iter.Statement.ByteMatchStatement.FieldToMatch != nil {
						f8elemf7f1f0 := &svcsdk.FieldToMatch{}
						if f8iter.Statement.ByteMatchStatement.FieldToMatch.AllQueryArguments != nil {
							f8elemf7f1f0f0 := &svcsdk.AllQueryArguments{}
							f8elemf7f1f0.SetAllQueryArguments(f8elemf7f1f0f0)
						}
						if f8iter.Statement.ByteMatchStatement.FieldToMatch.Body != nil {
							f8elemf7f1f0f1 := &svcsdk.Body{}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.Body.OversizeHandling != nil {
								f8elemf7f1f0f1.SetOversizeHandling(*f8iter.Statement.ByteMatchStatement.FieldToMatch.Body.OversizeHandling)
							}
							f8elemf7f1f0.SetBody(f8elemf7f1f0f1)
						}
						if f8iter.Statement.ByteMatchStatement.FieldToMatch.Cookies != nil {
							f8elemf7f1f0f2 := &svcsdk.Cookies{}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern != nil {
								f8elemf7f1f0f2f0 := &svcsdk.CookieMatchPattern{}
								if f8iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern.All != nil {
									f8elemf7f1f0f2f0f0 := &svcsdk.All{}
									f8elemf7f1f0f2f0.SetAll(f8elemf7f1f0f2f0f0)
								}
								if f8iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies != nil {
									f8elemf7f1f0f2f0f1 := []*string{}
									for _, f8elemf7f1f0f2f0f1iter := range f8iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies {
										var f8elemf7f1f0f2f0f1elem string
										f8elemf7f1f0f2f0f1elem = *f8elemf7f1f0f2f0f1iter
										f8elemf7f1f0f2f0f1 = append(f8elemf7f1f0f2f0f1, &f8elemf7f1f0f2f0f1elem)
									}
									f8elemf7f1f0f2f0.SetExcludedCookies(f8elemf7f1f0f2f0f1)
								}
								if f8iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies != nil {
									f8elemf7f1f0f2f0f2 := []*string{}
									for _, f8elemf7f1f0f2f0f2iter := range f8iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies {
										var f8elemf7f1f0f2f0f2elem string
										f8elemf7f1f0f2f0f2elem = *f8elemf7f1f0f2f0f2iter
										f8elemf7f1f0f2f0f2 = append(f8elemf7f1f0f2f0f2, &f8elemf7f1f0f2f0f2elem)
									}
									f8elemf7f1f0f2f0.SetIncludedCookies(f8elemf7f1f0f2f0f2)
								}
								f8elemf7f1f0f2.SetMatchPattern(f8elemf7f1f0f2f0)
							}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchScope != nil {
								f8elemf7f1f0f2.SetMatchScope(*f8iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchScope)
							}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.OversizeHandling != nil {
								f8elemf7f1f0f2.SetOversizeHandling(*f8iter.Statement.ByteMatchStatement.FieldToMatch.Cookies.OversizeHandling)
							}
							f8elemf7f1f0.SetCookies(f8elemf7f1f0f2)
						}
						if f8iter.Statement.ByteMatchStatement.FieldToMatch.HeaderOrder != nil {
							f8elemf7f1f0f3 := &svcsdk.HeaderOrder{}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling != nil {
								f8elemf7f1f0f3.SetOversizeHandling(*f8iter.Statement.ByteMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling)
							}
							f8elemf7f1f0.SetHeaderOrder(f8elemf7f1f0f3)
						}
						if f8iter.Statement.ByteMatchStatement.FieldToMatch.Headers != nil {
							f8elemf7f1f0f4 := &svcsdk.Headers{}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern != nil {
								f8elemf7f1f0f4f0 := &svcsdk.HeaderMatchPattern{}
								if f8iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern.All != nil {
									f8elemf7f1f0f4f0f0 := &svcsdk.All{}
									f8elemf7f1f0f4f0.SetAll(f8elemf7f1f0f4f0f0)
								}
								if f8iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders != nil {
									f8elemf7f1f0f4f0f1 := []*string{}
									for _, f8elemf7f1f0f4f0f1iter := range f8iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders {
										var f8elemf7f1f0f4f0f1elem string
										f8elemf7f1f0f4f0f1elem = *f8elemf7f1f0f4f0f1iter
										f8elemf7f1f0f4f0f1 = append(f8elemf7f1f0f4f0f1, &f8elemf7f1f0f4f0f1elem)
									}
									f8elemf7f1f0f4f0.SetExcludedHeaders(f8elemf7f1f0f4f0f1)
								}
								if f8iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders != nil {
									f8elemf7f1f0f4f0f2 := []*string{}
									for _, f8elemf7f1f0f4f0f2iter := range f8iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders {
										var f8elemf7f1f0f4f0f2elem string
										f8elemf7f1f0f4f0f2elem = *f8elemf7f1f0f4f0f2iter
										f8elemf7f1f0f4f0f2 = append(f8elemf7f1f0f4f0f2, &f8elemf7f1f0f4f0f2elem)
									}
									f8elemf7f1f0f4f0.SetIncludedHeaders(f8elemf7f1f0f4f0f2)
								}
								f8elemf7f1f0f4.SetMatchPattern(f8elemf7f1f0f4f0)
							}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchScope != nil {
								f8elemf7f1f0f4.SetMatchScope(*f8iter.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchScope)
							}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.Headers.OversizeHandling != nil {
								f8elemf7f1f0f4.SetOversizeHandling(*f8iter.Statement.ByteMatchStatement.FieldToMatch.Headers.OversizeHandling)
							}
							f8elemf7f1f0.SetHeaders(f8elemf7f1f0f4)
						}
						if f8iter.Statement.ByteMatchStatement.FieldToMatch.JA3Fingerprint != nil {
							f8elemf7f1f0f5 := &svcsdk.JA3Fingerprint{}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior != nil {
								f8elemf7f1f0f5.SetFallbackBehavior(*f8iter.Statement.ByteMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior)
							}
							f8elemf7f1f0.SetJA3Fingerprint(f8elemf7f1f0f5)
						}
						if f8iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody != nil {
							f8elemf7f1f0f6 := &svcsdk.JsonBody{}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior != nil {
								f8elemf7f1f0f6.SetInvalidFallbackBehavior(*f8iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior)
							}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.MatchPattern != nil {
								f8elemf7f1f0f6f1 := &svcsdk.JsonMatchPattern{}
								if f8iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.MatchPattern.All != nil {
									f8elemf7f1f0f6f1f0 := &svcsdk.All{}
									f8elemf7f1f0f6f1.SetAll(f8elemf7f1f0f6f1f0)
								}
								if f8iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths != nil {
									f8elemf7f1f0f6f1f1 := []*string{}
									for _, f8elemf7f1f0f6f1f1iter := range f8iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths {
										var f8elemf7f1f0f6f1f1elem string
										f8elemf7f1f0f6f1f1elem = *f8elemf7f1f0f6f1f1iter
										f8elemf7f1f0f6f1f1 = append(f8elemf7f1f0f6f1f1, &f8elemf7f1f0f6f1f1elem)
									}
									f8elemf7f1f0f6f1.SetIncludedPaths(f8elemf7f1f0f6f1f1)
								}
								f8elemf7f1f0f6.SetMatchPattern(f8elemf7f1f0f6f1)
							}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.MatchScope != nil {
								f8elemf7f1f0f6.SetMatchScope(*f8iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.MatchScope)
							}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.OversizeHandling != nil {
								f8elemf7f1f0f6.SetOversizeHandling(*f8iter.Statement.ByteMatchStatement.FieldToMatch.JSONBody.OversizeHandling)
							}
							f8elemf7f1f0.SetJsonBody(f8elemf7f1f0f6)
						}
						if f8iter.Statement.ByteMatchStatement.FieldToMatch.Method != nil {
							f8elemf7f1f0f7 := &svcsdk.Method{}
							f8elemf7f1f0.SetMethod(f8elemf7f1f0f7)
						}
						if f8iter.Statement.ByteMatchStatement.FieldToMatch.QueryString != nil {
							f8elemf7f1f0f8 := &svcsdk.QueryString{}
							f8elemf7f1f0.SetQueryString(f8elemf7f1f0f8)
						}
						if f8iter.Statement.ByteMatchStatement.FieldToMatch.SingleHeader != nil {
							f8elemf7f1f0f9 := &svcsdk.SingleHeader{}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.SingleHeader.Name != nil {
								f8elemf7f1f0f9.SetName(*f8iter.Statement.ByteMatchStatement.FieldToMatch.SingleHeader.Name)
							}
							f8elemf7f1f0.SetSingleHeader(f8elemf7f1f0f9)
						}
						if f8iter.Statement.ByteMatchStatement.FieldToMatch.SingleQueryArgument != nil {
							f8elemf7f1f0f10 := &svcsdk.SingleQueryArgument{}
							if f8iter.Statement.ByteMatchStatement.FieldToMatch.SingleQueryArgument.Name != nil {
								f8elemf7f1f0f10.SetName(*f8iter.Statement.ByteMatchStatement.FieldToMatch.SingleQueryArgument.Name)
							}
							f8elemf7f1f0.SetSingleQueryArgument(f8elemf7f1f0f10)
						}
						if f8iter.Statement.ByteMatchStatement.FieldToMatch.URIPath != nil {
							f8elemf7f1f0f11 := &svcsdk.UriPath{}
							f8elemf7f1f0.SetUriPath(f8elemf7f1f0f11)
						}
						f8elemf7f1.SetFieldToMatch(f8elemf7f1f0)
					}
					if f8iter.Statement.ByteMatchStatement.PositionalConstraint != nil {
						f8elemf7f1.SetPositionalConstraint(*f8iter.Statement.ByteMatchStatement.PositionalConstraint)
					}
					if f8iter.Statement.ByteMatchStatement.SearchString != nil {
						f8elemf7f1.SetSearchString(f8iter.Statement.ByteMatchStatement.SearchString)
					}
					if f8iter.Statement.ByteMatchStatement.TextTransformations != nil {
						f8elemf7f1f3 := []*svcsdk.TextTransformation{}
						for _, f8elemf7f1f3iter := range f8iter.Statement.ByteMatchStatement.TextTransformations {
							f8elemf7f1f3elem := &svcsdk.TextTransformation{}
							if f8elemf7f1f3iter.Priority != nil {
								f8elemf7f1f3elem.SetPriority(*f8elemf7f1f3iter.Priority)
							}
							if f8elemf7f1f3iter.Type != nil {
								f8elemf7f1f3elem.SetType(*f8elemf7f1f3iter.Type)
							}
							f8elemf7f1f3 = append(f8elemf7f1f3, f8elemf7f1f3elem)
						}
						f8elemf7f1.SetTextTransformations(f8elemf7f1f3)
					}
					f8elemf7.SetByteMatchStatement(f8elemf7f1)
				}
				if f8iter.Statement.GeoMatchStatement != nil {
					f8elemf7f2 := &svcsdk.GeoMatchStatement{}
					if f8iter.Statement.GeoMatchStatement.CountryCodes != nil {
						f8elemf7f2f0 := []*string{}
						for _, f8elemf7f2f0iter := range f8iter.Statement.GeoMatchStatement.CountryCodes {
							var f8elemf7f2f0elem string
							f8elemf7f2f0elem = *f8elemf7f2f0iter
							f8elemf7f2f0 = append(f8elemf7f2f0, &f8elemf7f2f0elem)
						}
						f8elemf7f2.SetCountryCodes(f8elemf7f2f0)
					}
					if f8iter.Statement.GeoMatchStatement.ForwardedIPConfig != nil {
						f8elemf7f2f1 := &svcsdk.ForwardedIPConfig{}
						if f8iter.Statement.GeoMatchStatement.ForwardedIPConfig.FallbackBehavior != nil {
							f8elemf7f2f1.SetFallbackBehavior(*f8iter.Statement.GeoMatchStatement.ForwardedIPConfig.FallbackBehavior)
						}
						if f8iter.Statement.GeoMatchStatement.ForwardedIPConfig.HeaderName != nil {
							f8elemf7f2f1.SetHeaderName(*f8iter.Statement.GeoMatchStatement.ForwardedIPConfig.HeaderName)
						}
						f8elemf7f2.SetForwardedIPConfig(f8elemf7f2f1)
					}
					f8elemf7.SetGeoMatchStatement(f8elemf7f2)
				}
				if f8iter.Statement.IPSetReferenceStatement != nil {
					f8elemf7f3 := &svcsdk.IPSetReferenceStatement{}
					if f8iter.Statement.IPSetReferenceStatement.ARN != nil {
						f8elemf7f3.SetARN(*f8iter.Statement.IPSetReferenceStatement.ARN)
					}
					if f8iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig != nil {
						f8elemf7f3f1 := &svcsdk.IPSetForwardedIPConfig{}
						if f8iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.FallbackBehavior != nil {
							f8elemf7f3f1.SetFallbackBehavior(*f8iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.FallbackBehavior)
						}
						if f8iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.HeaderName != nil {
							f8elemf7f3f1.SetHeaderName(*f8iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.HeaderName)
						}
						if f8iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.Position != nil {
							f8elemf7f3f1.SetPosition(*f8iter.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.Position)
						}
						f8elemf7f3.SetIPSetForwardedIPConfig(f8elemf7f3f1)
					}
					f8elemf7.SetIPSetReferenceStatement(f8elemf7f3)
				}
				if f8iter.Statement.LabelMatchStatement != nil {
					f8elemf7f4 := &svcsdk.LabelMatchStatement{}
					if f8iter.Statement.LabelMatchStatement.Key != nil {
						f8elemf7f4.SetKey(*f8iter.Statement.LabelMatchStatement.Key)
					}
					if f8iter.Statement.LabelMatchStatement.Scope != nil {
						f8elemf7f4.SetScope(*f8iter.Statement.LabelMatchStatement.Scope)
					}
					f8elemf7.SetLabelMatchStatement(f8elemf7f4)
				}
				if f8iter.Statement.ManagedRuleGroupStatement != nil {
					f8elemf7f5 := &svcsdk.ManagedRuleGroupStatement{}
					if f8iter.Statement.ManagedRuleGroupStatement.ExcludedRules != nil {
						f8elemf7f5f0 := []*svcsdk.ExcludedRule{}
						for _, f8elemf7f5f0iter := range f8iter.Statement.ManagedRuleGroupStatement.ExcludedRules {
							f8elemf7f5f0elem := &svcsdk.ExcludedRule{}
							if f8elemf7f5f0iter.Name != nil {
								f8elemf7f5f0elem.SetName(*f8elemf7f5f0iter.Name)
							}
							f8elemf7f5f0 = append(f8elemf7f5f0, f8elemf7f5f0elem)
						}
						f8elemf7f5.SetExcludedRules(f8elemf7f5f0)
					}
					if f8iter.Statement.ManagedRuleGroupStatement.ManagedRuleGroupConfigs != nil {
						f8elemf7f5f1 := []*svcsdk.ManagedRuleGroupConfig{}
						for _, f8elemf7f5f1iter := range f8iter.Statement.ManagedRuleGroupStatement.ManagedRuleGroupConfigs {
							f8elemf7f5f1elem := &svcsdk.ManagedRuleGroupConfig{}
							if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet != nil {
								f8elemf7f5f1elemf0 := &svcsdk.AWSManagedRulesACFPRuleSet{}
								if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.CreationPath != nil {
									f8elemf7f5f1elemf0.SetCreationPath(*f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.CreationPath)
								}
								if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.EnableRegexInPath != nil {
									f8elemf7f5f1elemf0.SetEnableRegexInPath(*f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.EnableRegexInPath)
								}
								if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RegistrationPagePath != nil {
									f8elemf7f5f1elemf0.SetRegistrationPagePath(*f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RegistrationPagePath)
								}
								if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection != nil {
									f8elemf7f5f1elemf0f3 := &svcsdk.RequestInspectionACFP{}
									if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.AddressFields != nil {
										f8elemf7f5f1elemf0f3f0 := []*svcsdk.AddressField{}
										for _, f8elemf7f5f1elemf0f3f0iter := range f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.AddressFields {
											f8elemf7f5f1elemf0f3f0elem := &svcsdk.AddressField{}
											if f8elemf7f5f1elemf0f3f0iter.Identifier != nil {
												f8elemf7f5f1elemf0f3f0elem.SetIdentifier(*f8elemf7f5f1elemf0f3f0iter.Identifier)
											}
											f8elemf7f5f1elemf0f3f0 = append(f8elemf7f5f1elemf0f3f0, f8elemf7f5f1elemf0f3f0elem)
										}
										f8elemf7f5f1elemf0f3.SetAddressFields(f8elemf7f5f1elemf0f3f0)
									}
									if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.EmailField != nil {
										f8elemf7f5f1elemf0f3f1 := &svcsdk.EmailField{}
										if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.EmailField.Identifier != nil {
											f8elemf7f5f1elemf0f3f1.SetIdentifier(*f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.EmailField.Identifier)
										}
										f8elemf7f5f1elemf0f3.SetEmailField(f8elemf7f5f1elemf0f3f1)
									}
									if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PasswordField != nil {
										f8elemf7f5f1elemf0f3f2 := &svcsdk.PasswordField{}
										if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PasswordField.Identifier != nil {
											f8elemf7f5f1elemf0f3f2.SetIdentifier(*f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PasswordField.Identifier)
										}
										f8elemf7f5f1elemf0f3.SetPasswordField(f8elemf7f5f1elemf0f3f2)
									}
									if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PayloadType != nil {
										f8elemf7f5f1elemf0f3.SetPayloadType(*f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PayloadType)
									}
									if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PhoneNumberFields != nil {
										f8elemf7f5f1elemf0f3f4 := []*svcsdk.PhoneNumberField{}
										for _, f8elemf7f5f1elemf0f3f4iter := range f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.PhoneNumberFields {
											f8elemf7f5f1elemf0f3f4elem := &svcsdk.PhoneNumberField{}
											if f8elemf7f5f1elemf0f3f4iter.Identifier != nil {
												f8elemf7f5f1elemf0f3f4elem.SetIdentifier(*f8elemf7f5f1elemf0f3f4iter.Identifier)
											}
											f8elemf7f5f1elemf0f3f4 = append(f8elemf7f5f1elemf0f3f4, f8elemf7f5f1elemf0f3f4elem)
										}
										f8elemf7f5f1elemf0f3.SetPhoneNumberFields(f8elemf7f5f1elemf0f3f4)
									}
									if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.UsernameField != nil {
										f8elemf7f5f1elemf0f3f5 := &svcsdk.UsernameField{}
										if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.UsernameField.Identifier != nil {
											f8elemf7f5f1elemf0f3f5.SetIdentifier(*f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.RequestInspection.UsernameField.Identifier)
										}
										f8elemf7f5f1elemf0f3.SetUsernameField(f8elemf7f5f1elemf0f3f5)
									}
									f8elemf7f5f1elemf0.SetRequestInspection(f8elemf7f5f1elemf0f3)
								}
								if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection != nil {
									f8elemf7f5f1elemf0f4 := &svcsdk.ResponseInspection{}
									if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains != nil {
										f8elemf7f5f1elemf0f4f0 := &svcsdk.ResponseInspectionBodyContains{}
										if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains.FailureStrings != nil {
											f8elemf7f5f1elemf0f4f0f0 := []*string{}
											for _, f8elemf7f5f1elemf0f4f0f0iter := range f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains.FailureStrings {
												var f8elemf7f5f1elemf0f4f0f0elem string
												f8elemf7f5f1elemf0f4f0f0elem = *f8elemf7f5f1elemf0f4f0f0iter
												f8elemf7f5f1elemf0f4f0f0 = append(f8elemf7f5f1elemf0f4f0f0, &f8elemf7f5f1elemf0f4f0f0elem)
											}
											f8elemf7f5f1elemf0f4f0.SetFailureStrings(f8elemf7f5f1elemf0f4f0f0)
										}
										if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains.SuccessStrings != nil {
											f8elemf7f5f1elemf0f4f0f1 := []*string{}
											for _, f8elemf7f5f1elemf0f4f0f1iter := range f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains.SuccessStrings {
												var f8elemf7f5f1elemf0f4f0f1elem string
												f8elemf7f5f1elemf0f4f0f1elem = *f8elemf7f5f1elemf0f4f0f1iter
												f8elemf7f5f1elemf0f4f0f1 = append(f8elemf7f5f1elemf0f4f0f1, &f8elemf7f5f1elemf0f4f0f1elem)
											}
											f8elemf7f5f1elemf0f4f0.SetSuccessStrings(f8elemf7f5f1elemf0f4f0f1)
										}
										f8elemf7f5f1elemf0f4.SetBodyContains(f8elemf7f5f1elemf0f4f0)
									}
									if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header != nil {
										f8elemf7f5f1elemf0f4f1 := &svcsdk.ResponseInspectionHeader{}
										if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.FailureValues != nil {
											f8elemf7f5f1elemf0f4f1f0 := []*string{}
											for _, f8elemf7f5f1elemf0f4f1f0iter := range f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.FailureValues {
												var f8elemf7f5f1elemf0f4f1f0elem string
												f8elemf7f5f1elemf0f4f1f0elem = *f8elemf7f5f1elemf0f4f1f0iter
												f8elemf7f5f1elemf0f4f1f0 = append(f8elemf7f5f1elemf0f4f1f0, &f8elemf7f5f1elemf0f4f1f0elem)
											}
											f8elemf7f5f1elemf0f4f1.SetFailureValues(f8elemf7f5f1elemf0f4f1f0)
										}
										if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.Name != nil {
											f8elemf7f5f1elemf0f4f1.SetName(*f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.Name)
										}
										if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.SuccessValues != nil {
											f8elemf7f5f1elemf0f4f1f2 := []*string{}
											for _, f8elemf7f5f1elemf0f4f1f2iter := range f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.SuccessValues {
												var f8elemf7f5f1elemf0f4f1f2elem string
												f8elemf7f5f1elemf0f4f1f2elem = *f8elemf7f5f1elemf0f4f1f2iter
												f8elemf7f5f1elemf0f4f1f2 = append(f8elemf7f5f1elemf0f4f1f2, &f8elemf7f5f1elemf0f4f1f2elem)
											}
											f8elemf7f5f1elemf0f4f1.SetSuccessValues(f8elemf7f5f1elemf0f4f1f2)
										}
										f8elemf7f5f1elemf0f4.SetHeader(f8elemf7f5f1elemf0f4f1)
									}
									if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON != nil {
										f8elemf7f5f1elemf0f4f2 := &svcsdk.ResponseInspectionJson{}
										if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON.FailureValues != nil {
											f8elemf7f5f1elemf0f4f2f0 := []*string{}
											for _, f8elemf7f5f1elemf0f4f2f0iter := range f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON.FailureValues {
												var f8elemf7f5f1elemf0f4f2f0elem string
												f8elemf7f5f1elemf0f4f2f0elem = *f8elemf7f5f1elemf0f4f2f0iter
												f8elemf7f5f1elemf0f4f2f0 = append(f8elemf7f5f1elemf0f4f2f0, &f8elemf7f5f1elemf0f4f2f0elem)
											}
											f8elemf7f5f1elemf0f4f2.SetFailureValues(f8elemf7f5f1elemf0f4f2f0)
										}
										if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON.Identifier != nil {
											f8elemf7f5f1elemf0f4f2.SetIdentifier(*f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON.Identifier)
										}
										if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON.SuccessValues != nil {
											f8elemf7f5f1elemf0f4f2f2 := []*string{}
											for _, f8elemf7f5f1elemf0f4f2f2iter := range f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.JSON.SuccessValues {
												var f8elemf7f5f1elemf0f4f2f2elem string
												f8elemf7f5f1elemf0f4f2f2elem = *f8elemf7f5f1elemf0f4f2f2iter
												f8elemf7f5f1elemf0f4f2f2 = append(f8elemf7f5f1elemf0f4f2f2, &f8elemf7f5f1elemf0f4f2f2elem)
											}
											f8elemf7f5f1elemf0f4f2.SetSuccessValues(f8elemf7f5f1elemf0f4f2f2)
										}
										f8elemf7f5f1elemf0f4.SetJson(f8elemf7f5f1elemf0f4f2)
									}
									if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.StatusCode != nil {
										f8elemf7f5f1elemf0f4f3 := &svcsdk.ResponseInspectionStatusCode{}
										if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.StatusCode.FailureCodes != nil {
											f8elemf7f5f1elemf0f4f3f0 := []*int64{}
											for _, f8elemf7f5f1elemf0f4f3f0iter := range f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.StatusCode.FailureCodes {
												var f8elemf7f5f1elemf0f4f3f0elem int64
												f8elemf7f5f1elemf0f4f3f0elem = *f8elemf7f5f1elemf0f4f3f0iter
												f8elemf7f5f1elemf0f4f3f0 = append(f8elemf7f5f1elemf0f4f3f0, &f8elemf7f5f1elemf0f4f3f0elem)
											}
											f8elemf7f5f1elemf0f4f3.SetFailureCodes(f8elemf7f5f1elemf0f4f3f0)
										}
										if f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.StatusCode.SuccessCodes != nil {
											f8elemf7f5f1elemf0f4f3f1 := []*int64{}
											for _, f8elemf7f5f1elemf0f4f3f1iter := range f8elemf7f5f1iter.AWSManagedRulesACFPRuleSet.ResponseInspection.StatusCode.SuccessCodes {
												var f8elemf7f5f1elemf0f4f3f1elem int64
												f8elemf7f5f1elemf0f4f3f1elem = *f8elemf7f5f1elemf0f4f3f1iter
												f8elemf7f5f1elemf0f4f3f1 = append(f8elemf7f5f1elemf0f4f3f1, &f8elemf7f5f1elemf0f4f3f1elem)
											}
											f8elemf7f5f1elemf0f4f3.SetSuccessCodes(f8elemf7f5f1elemf0f4f3f1)
										}
										f8elemf7f5f1elemf0f4.SetStatusCode(f8elemf7f5f1elemf0f4f3)
									}
									f8elemf7f5f1elemf0.SetResponseInspection(f8elemf7f5f1elemf0f4)
								}
								f8elemf7f5f1elem.SetAWSManagedRulesACFPRuleSet(f8elemf7f5f1elemf0)
							}
							if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet != nil {
								f8elemf7f5f1elemf1 := &svcsdk.AWSManagedRulesATPRuleSet{}
								if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.EnableRegexInPath != nil {
									f8elemf7f5f1elemf1.SetEnableRegexInPath(*f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.EnableRegexInPath)
								}
								if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.LoginPath != nil {
									f8elemf7f5f1elemf1.SetLoginPath(*f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.LoginPath)
								}
								if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection != nil {
									f8elemf7f5f1elemf1f2 := &svcsdk.RequestInspection{}
									if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.PasswordField != nil {
										f8elemf7f5f1elemf1f2f0 := &svcsdk.PasswordField{}
										if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.PasswordField.Identifier != nil {
											f8elemf7f5f1elemf1f2f0.SetIdentifier(*f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.PasswordField.Identifier)
										}
										f8elemf7f5f1elemf1f2.SetPasswordField(f8elemf7f5f1elemf1f2f0)
									}
									if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.PayloadType != nil {
										f8elemf7f5f1elemf1f2.SetPayloadType(*f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.PayloadType)
									}
									if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.UsernameField != nil {
										f8elemf7f5f1elemf1f2f2 := &svcsdk.UsernameField{}
										if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.UsernameField.Identifier != nil {
											f8elemf7f5f1elemf1f2f2.SetIdentifier(*f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.RequestInspection.UsernameField.Identifier)
										}
										f8elemf7f5f1elemf1f2.SetUsernameField(f8elemf7f5f1elemf1f2f2)
									}
									f8elemf7f5f1elemf1.SetRequestInspection(f8elemf7f5f1elemf1f2)
								}
								if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection != nil {
									f8elemf7f5f1elemf1f3 := &svcsdk.ResponseInspection{}
									if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.BodyContains != nil {
										f8elemf7f5f1elemf1f3f0 := &svcsdk.ResponseInspectionBodyContains{}
										if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.BodyContains.FailureStrings != nil {
											f8elemf7f5f1elemf1f3f0f0 := []*string{}
											for _, f8elemf7f5f1elemf1f3f0f0iter := range f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.BodyContains.FailureStrings {
												var f8elemf7f5f1elemf1f3f0f0elem string
												f8elemf7f5f1elemf1f3f0f0elem = *f8elemf7f5f1elemf1f3f0f0iter
												f8elemf7f5f1elemf1f3f0f0 = append(f8elemf7f5f1elemf1f3f0f0, &f8elemf7f5f1elemf1f3f0f0elem)
											}
											f8elemf7f5f1elemf1f3f0.SetFailureStrings(f8elemf7f5f1elemf1f3f0f0)
										}
										if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.BodyContains.SuccessStrings != nil {
											f8elemf7f5f1elemf1f3f0f1 := []*string{}
											for _, f8elemf7f5f1elemf1f3f0f1iter := range f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.BodyContains.SuccessStrings {
												var f8elemf7f5f1elemf1f3f0f1elem string
												f8elemf7f5f1elemf1f3f0f1elem = *f8elemf7f5f1elemf1f3f0f1iter
												f8elemf7f5f1elemf1f3f0f1 = append(f8elemf7f5f1elemf1f3f0f1, &f8elemf7f5f1elemf1f3f0f1elem)
											}
											f8elemf7f5f1elemf1f3f0.SetSuccessStrings(f8elemf7f5f1elemf1f3f0f1)
										}
										f8elemf7f5f1elemf1f3.SetBodyContains(f8elemf7f5f1elemf1f3f0)
									}
									if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header != nil {
										f8elemf7f5f1elemf1f3f1 := &svcsdk.ResponseInspectionHeader{}
										if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header.FailureValues != nil {
											f8elemf7f5f1elemf1f3f1f0 := []*string{}
											for _, f8elemf7f5f1elemf1f3f1f0iter := range f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header.FailureValues {
												var f8elemf7f5f1elemf1f3f1f0elem string
												f8elemf7f5f1elemf1f3f1f0elem = *f8elemf7f5f1elemf1f3f1f0iter
												f8elemf7f5f1elemf1f3f1f0 = append(f8elemf7f5f1elemf1f3f1f0, &f8elemf7f5f1elemf1f3f1f0elem)
											}
											f8elemf7f5f1elemf1f3f1.SetFailureValues(f8elemf7f5f1elemf1f3f1f0)
										}
										if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header.Name != nil {
											f8elemf7f5f1elemf1f3f1.SetName(*f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header.Name)
										}
										if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header.SuccessValues != nil {
											f8elemf7f5f1elemf1f3f1f2 := []*string{}
											for _, f8elemf7f5f1elemf1f3f1f2iter := range f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.Header.SuccessValues {
												var f8elemf7f5f1elemf1f3f1f2elem string
												f8elemf7f5f1elemf1f3f1f2elem = *f8elemf7f5f1elemf1f3f1f2iter
												f8elemf7f5f1elemf1f3f1f2 = append(f8elemf7f5f1elemf1f3f1f2, &f8elemf7f5f1elemf1f3f1f2elem)
											}
											f8elemf7f5f1elemf1f3f1.SetSuccessValues(f8elemf7f5f1elemf1f3f1f2)
										}
										f8elemf7f5f1elemf1f3.SetHeader(f8elemf7f5f1elemf1f3f1)
									}
									if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON != nil {
										f8elemf7f5f1elemf1f3f2 := &svcsdk.ResponseInspectionJson{}
										if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON.FailureValues != nil {
											f8elemf7f5f1elemf1f3f2f0 := []*string{}
											for _, f8elemf7f5f1elemf1f3f2f0iter := range f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON.FailureValues {
												var f8elemf7f5f1elemf1f3f2f0elem string
												f8elemf7f5f1elemf1f3f2f0elem = *f8elemf7f5f1elemf1f3f2f0iter
												f8elemf7f5f1elemf1f3f2f0 = append(f8elemf7f5f1elemf1f3f2f0, &f8elemf7f5f1elemf1f3f2f0elem)
											}
											f8elemf7f5f1elemf1f3f2.SetFailureValues(f8elemf7f5f1elemf1f3f2f0)
										}
										if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON.Identifier != nil {
											f8elemf7f5f1elemf1f3f2.SetIdentifier(*f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON.Identifier)
										}
										if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON.SuccessValues != nil {
											f8elemf7f5f1elemf1f3f2f2 := []*string{}
											for _, f8elemf7f5f1elemf1f3f2f2iter := range f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.JSON.SuccessValues {
												var f8elemf7f5f1elemf1f3f2f2elem string
												f8elemf7f5f1elemf1f3f2f2elem = *f8elemf7f5f1elemf1f3f2f2iter
												f8elemf7f5f1elemf1f3f2f2 = append(f8elemf7f5f1elemf1f3f2f2, &f8elemf7f5f1elemf1f3f2f2elem)
											}
											f8elemf7f5f1elemf1f3f2.SetSuccessValues(f8elemf7f5f1elemf1f3f2f2)
										}
										f8elemf7f5f1elemf1f3.SetJson(f8elemf7f5f1elemf1f3f2)
									}
									if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.StatusCode != nil {
										f8elemf7f5f1elemf1f3f3 := &svcsdk.ResponseInspectionStatusCode{}
										if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.StatusCode.FailureCodes != nil {
											f8elemf7f5f1elemf1f3f3f0 := []*int64{}
											for _, f8elemf7f5f1elemf1f3f3f0iter := range f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.StatusCode.FailureCodes {
												var f8elemf7f5f1elemf1f3f3f0elem int64
												f8elemf7f5f1elemf1f3f3f0elem = *f8elemf7f5f1elemf1f3f3f0iter
												f8elemf7f5f1elemf1f3f3f0 = append(f8elemf7f5f1elemf1f3f3f0, &f8elemf7f5f1elemf1f3f3f0elem)
											}
											f8elemf7f5f1elemf1f3f3.SetFailureCodes(f8elemf7f5f1elemf1f3f3f0)
										}
										if f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.StatusCode.SuccessCodes != nil {
											f8elemf7f5f1elemf1f3f3f1 := []*int64{}
											for _, f8elemf7f5f1elemf1f3f3f1iter := range f8elemf7f5f1iter.AWSManagedRulesATPRuleSet.ResponseInspection.StatusCode.SuccessCodes {
												var f8elemf7f5f1elemf1f3f3f1elem int64
												f8elemf7f5f1elemf1f3f3f1elem = *f8elemf7f5f1elemf1f3f3f1iter
												f8elemf7f5f1elemf1f3f3f1 = append(f8elemf7f5f1elemf1f3f3f1, &f8elemf7f5f1elemf1f3f3f1elem)
											}
											f8elemf7f5f1elemf1f3f3.SetSuccessCodes(f8elemf7f5f1elemf1f3f3f1)
										}
										f8elemf7f5f1elemf1f3.SetStatusCode(f8elemf7f5f1elemf1f3f3)
									}
									f8elemf7f5f1elemf1.SetResponseInspection(f8elemf7f5f1elemf1f3)
								}
								f8elemf7f5f1elem.SetAWSManagedRulesATPRuleSet(f8elemf7f5f1elemf1)
							}
							if f8elemf7f5f1iter.AWSManagedRulesBotControlRuleSet != nil {
								f8elemf7f5f1elemf2 := &svcsdk.AWSManagedRulesBotControlRuleSet{}
								if f8elemf7f5f1iter.AWSManagedRulesBotControlRuleSet.EnableMachineLearning != nil {
									f8elemf7f5f1elemf2.SetEnableMachineLearning(*f8elemf7f5f1iter.AWSManagedRulesBotControlRuleSet.EnableMachineLearning)
								}
								if f8elemf7f5f1iter.AWSManagedRulesBotControlRuleSet.InspectionLevel != nil {
									f8elemf7f5f1elemf2.SetInspectionLevel(*f8elemf7f5f1iter.AWSManagedRulesBotControlRuleSet.InspectionLevel)
								}
								f8elemf7f5f1elem.SetAWSManagedRulesBotControlRuleSet(f8elemf7f5f1elemf2)
							}
							if f8elemf7f5f1iter.LoginPath != nil {
								f8elemf7f5f1elem.SetLoginPath(*f8elemf7f5f1iter.LoginPath)
							}
							if f8elemf7f5f1iter.PasswordField != nil {
								f8elemf7f5f1elemf4 := &svcsdk.PasswordField{}
								if f8elemf7f5f1iter.PasswordField.Identifier != nil {
									f8elemf7f5f1elemf4.SetIdentifier(*f8elemf7f5f1iter.PasswordField.Identifier)
								}
								f8elemf7f5f1elem.SetPasswordField(f8elemf7f5f1elemf4)
							}
							if f8elemf7f5f1iter.PayloadType != nil {
								f8elemf7f5f1elem.SetPayloadType(*f8elemf7f5f1iter.PayloadType)
							}
							if f8elemf7f5f1iter.UsernameField != nil {
								f8elemf7f5f1elemf6 := &svcsdk.UsernameField{}
								if f8elemf7f5f1iter.UsernameField.Identifier != nil {
									f8elemf7f5f1elemf6.SetIdentifier(*f8elemf7f5f1iter.UsernameField.Identifier)
								}
								f8elemf7f5f1elem.SetUsernameField(f8elemf7f5f1elemf6)
							}
							f8elemf7f5f1 = append(f8elemf7f5f1, f8elemf7f5f1elem)
						}
						f8elemf7f5.SetManagedRuleGroupConfigs(f8elemf7f5f1)
					}
					if f8iter.Statement.ManagedRuleGroupStatement.Name != nil {
						f8elemf7f5.SetName(*f8iter.Statement.ManagedRuleGroupStatement.Name)
					}
					if f8iter.Statement.ManagedRuleGroupStatement.RuleActionOverrides != nil {
						f8elemf7f5f3 := []*svcsdk.RuleActionOverride{}
						for _, f8elemf7f5f3iter := range f8iter.Statement.ManagedRuleGroupStatement.RuleActionOverrides {
							f8elemf7f5f3elem := &svcsdk.RuleActionOverride{}
							if f8elemf7f5f3iter.ActionToUse != nil {
								f8elemf7f5f3elemf0 := &svcsdk.RuleAction{}
								if f8elemf7f5f3iter.ActionToUse.Allow != nil {
									f8elemf7f5f3elemf0f0 := &svcsdk.AllowAction{}
									if f8elemf7f5f3iter.ActionToUse.Allow.CustomRequestHandling != nil {
										f8elemf7f5f3elemf0f0f0 := &svcsdk.CustomRequestHandling{}
										if f8elemf7f5f3iter.ActionToUse.Allow.CustomRequestHandling.InsertHeaders != nil {
											f8elemf7f5f3elemf0f0f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f8elemf7f5f3elemf0f0f0f0iter := range f8elemf7f5f3iter.ActionToUse.Allow.CustomRequestHandling.InsertHeaders {
												f8elemf7f5f3elemf0f0f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f8elemf7f5f3elemf0f0f0f0iter.Name != nil {
													f8elemf7f5f3elemf0f0f0f0elem.SetName(*f8elemf7f5f3elemf0f0f0f0iter.Name)
												}
												if f8elemf7f5f3elemf0f0f0f0iter.Value != nil {
													f8elemf7f5f3elemf0f0f0f0elem.SetValue(*f8elemf7f5f3elemf0f0f0f0iter.Value)
												}
												f8elemf7f5f3elemf0f0f0f0 = append(f8elemf7f5f3elemf0f0f0f0, f8elemf7f5f3elemf0f0f0f0elem)
											}
											f8elemf7f5f3elemf0f0f0.SetInsertHeaders(f8elemf7f5f3elemf0f0f0f0)
										}
										f8elemf7f5f3elemf0f0.SetCustomRequestHandling(f8elemf7f5f3elemf0f0f0)
									}
									f8elemf7f5f3elemf0.SetAllow(f8elemf7f5f3elemf0f0)
								}
								if f8elemf7f5f3iter.ActionToUse.Block != nil {
									f8elemf7f5f3elemf0f1 := &svcsdk.BlockAction{}
									if f8elemf7f5f3iter.ActionToUse.Block.CustomResponse != nil {
										f8elemf7f5f3elemf0f1f0 := &svcsdk.CustomResponse{}
										if f8elemf7f5f3iter.ActionToUse.Block.CustomResponse.CustomResponseBodyKey != nil {
											f8elemf7f5f3elemf0f1f0.SetCustomResponseBodyKey(*f8elemf7f5f3iter.ActionToUse.Block.CustomResponse.CustomResponseBodyKey)
										}
										if f8elemf7f5f3iter.ActionToUse.Block.CustomResponse.ResponseCode != nil {
											f8elemf7f5f3elemf0f1f0.SetResponseCode(*f8elemf7f5f3iter.ActionToUse.Block.CustomResponse.ResponseCode)
										}
										if f8elemf7f5f3iter.ActionToUse.Block.CustomResponse.ResponseHeaders != nil {
											f8elemf7f5f3elemf0f1f0f2 := []*svcsdk.CustomHTTPHeader{}
											for _, f8elemf7f5f3elemf0f1f0f2iter := range f8elemf7f5f3iter.ActionToUse.Block.CustomResponse.ResponseHeaders {
												f8elemf7f5f3elemf0f1f0f2elem := &svcsdk.CustomHTTPHeader{}
												if f8elemf7f5f3elemf0f1f0f2iter.Name != nil {
													f8elemf7f5f3elemf0f1f0f2elem.SetName(*f8elemf7f5f3elemf0f1f0f2iter.Name)
												}
												if f8elemf7f5f3elemf0f1f0f2iter.Value != nil {
													f8elemf7f5f3elemf0f1f0f2elem.SetValue(*f8elemf7f5f3elemf0f1f0f2iter.Value)
												}
												f8elemf7f5f3elemf0f1f0f2 = append(f8elemf7f5f3elemf0f1f0f2, f8elemf7f5f3elemf0f1f0f2elem)
											}
											f8elemf7f5f3elemf0f1f0.SetResponseHeaders(f8elemf7f5f3elemf0f1f0f2)
										}
										f8elemf7f5f3elemf0f1.SetCustomResponse(f8elemf7f5f3elemf0f1f0)
									}
									f8elemf7f5f3elemf0.SetBlock(f8elemf7f5f3elemf0f1)
								}
								if f8elemf7f5f3iter.ActionToUse.Captcha != nil {
									f8elemf7f5f3elemf0f2 := &svcsdk.CaptchaAction{}
									if f8elemf7f5f3iter.ActionToUse.Captcha.CustomRequestHandling != nil {
										f8elemf7f5f3elemf0f2f0 := &svcsdk.CustomRequestHandling{}
										if f8elemf7f5f3iter.ActionToUse.Captcha.CustomRequestHandling.InsertHeaders != nil {
											f8elemf7f5f3elemf0f2f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f8elemf7f5f3elemf0f2f0f0iter := range f8elemf7f5f3iter.ActionToUse.Captcha.CustomRequestHandling.InsertHeaders {
												f8elemf7f5f3elemf0f2f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f8elemf7f5f3elemf0f2f0f0iter.Name != nil {
													f8elemf7f5f3elemf0f2f0f0elem.SetName(*f8elemf7f5f3elemf0f2f0f0iter.Name)
												}
												if f8elemf7f5f3elemf0f2f0f0iter.Value != nil {
													f8elemf7f5f3elemf0f2f0f0elem.SetValue(*f8elemf7f5f3elemf0f2f0f0iter.Value)
												}
												f8elemf7f5f3elemf0f2f0f0 = append(f8elemf7f5f3elemf0f2f0f0, f8elemf7f5f3elemf0f2f0f0elem)
											}
											f8elemf7f5f3elemf0f2f0.SetInsertHeaders(f8elemf7f5f3elemf0f2f0f0)
										}
										f8elemf7f5f3elemf0f2.SetCustomRequestHandling(f8elemf7f5f3elemf0f2f0)
									}
									f8elemf7f5f3elemf0.SetCaptcha(f8elemf7f5f3elemf0f2)
								}
								if f8elemf7f5f3iter.ActionToUse.Challenge != nil {
									f8elemf7f5f3elemf0f3 := &svcsdk.ChallengeAction{}
									if f8elemf7f5f3iter.ActionToUse.Challenge.CustomRequestHandling != nil {
										f8elemf7f5f3elemf0f3f0 := &svcsdk.CustomRequestHandling{}
										if f8elemf7f5f3iter.ActionToUse.Challenge.CustomRequestHandling.InsertHeaders != nil {
											f8elemf7f5f3elemf0f3f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f8elemf7f5f3elemf0f3f0f0iter := range f8elemf7f5f3iter.ActionToUse.Challenge.CustomRequestHandling.InsertHeaders {
												f8elemf7f5f3elemf0f3f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f8elemf7f5f3elemf0f3f0f0iter.Name != nil {
													f8elemf7f5f3elemf0f3f0f0elem.SetName(*f8elemf7f5f3elemf0f3f0f0iter.Name)
												}
												if f8elemf7f5f3elemf0f3f0f0iter.Value != nil {
													f8elemf7f5f3elemf0f3f0f0elem.SetValue(*f8elemf7f5f3elemf0f3f0f0iter.Value)
												}
												f8elemf7f5f3elemf0f3f0f0 = append(f8elemf7f5f3elemf0f3f0f0, f8elemf7f5f3elemf0f3f0f0elem)
											}
											f8elemf7f5f3elemf0f3f0.SetInsertHeaders(f8elemf7f5f3elemf0f3f0f0)
										}
										f8elemf7f5f3elemf0f3.SetCustomRequestHandling(f8elemf7f5f3elemf0f3f0)
									}
									f8elemf7f5f3elemf0.SetChallenge(f8elemf7f5f3elemf0f3)
								}
								if f8elemf7f5f3iter.ActionToUse.Count != nil {
									f8elemf7f5f3elemf0f4 := &svcsdk.CountAction{}
									if f8elemf7f5f3iter.ActionToUse.Count.CustomRequestHandling != nil {
										f8elemf7f5f3elemf0f4f0 := &svcsdk.CustomRequestHandling{}
										if f8elemf7f5f3iter.ActionToUse.Count.CustomRequestHandling.InsertHeaders != nil {
											f8elemf7f5f3elemf0f4f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f8elemf7f5f3elemf0f4f0f0iter := range f8elemf7f5f3iter.ActionToUse.Count.CustomRequestHandling.InsertHeaders {
												f8elemf7f5f3elemf0f4f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f8elemf7f5f3elemf0f4f0f0iter.Name != nil {
													f8elemf7f5f3elemf0f4f0f0elem.SetName(*f8elemf7f5f3elemf0f4f0f0iter.Name)
												}
												if f8elemf7f5f3elemf0f4f0f0iter.Value != nil {
													f8elemf7f5f3elemf0f4f0f0elem.SetValue(*f8elemf7f5f3elemf0f4f0f0iter.Value)
												}
												f8elemf7f5f3elemf0f4f0f0 = append(f8elemf7f5f3elemf0f4f0f0, f8elemf7f5f3elemf0f4f0f0elem)
											}
											f8elemf7f5f3elemf0f4f0.SetInsertHeaders(f8elemf7f5f3elemf0f4f0f0)
										}
										f8elemf7f5f3elemf0f4.SetCustomRequestHandling(f8elemf7f5f3elemf0f4f0)
									}
									f8elemf7f5f3elemf0.SetCount(f8elemf7f5f3elemf0f4)
								}
								f8elemf7f5f3elem.SetActionToUse(f8elemf7f5f3elemf0)
							}
							if f8elemf7f5f3iter.Name != nil {
								f8elemf7f5f3elem.SetName(*f8elemf7f5f3iter.Name)
							}
							f8elemf7f5f3 = append(f8elemf7f5f3, f8elemf7f5f3elem)
						}
						f8elemf7f5.SetRuleActionOverrides(f8elemf7f5f3)
					}
					if f8iter.Statement.ManagedRuleGroupStatement.VendorName != nil {
						f8elemf7f5.SetVendorName(*f8iter.Statement.ManagedRuleGroupStatement.VendorName)
					}
					if f8iter.Statement.ManagedRuleGroupStatement.Version != nil {
						f8elemf7f5.SetVersion(*f8iter.Statement.ManagedRuleGroupStatement.Version)
					}
					f8elemf7.SetManagedRuleGroupStatement(f8elemf7f5)
				}
				if f8iter.Statement.RateBasedStatement != nil {
					f8elemf7f8 := &svcsdk.RateBasedStatement{}
					if f8iter.Statement.RateBasedStatement.AggregateKeyType != nil {
						f8elemf7f8.SetAggregateKeyType(*f8iter.Statement.RateBasedStatement.AggregateKeyType)
					}
					if f8iter.Statement.RateBasedStatement.CustomKeys != nil {
						f8elemf7f8f1 := []*svcsdk.RateBasedStatementCustomKey{}
						for _, f8elemf7f8f1iter := range f8iter.Statement.RateBasedStatement.CustomKeys {
							f8elemf7f8f1elem := &svcsdk.RateBasedStatementCustomKey{}
							if f8elemf7f8f1iter.Cookie != nil {
								f8elemf7f8f1elemf0 := &svcsdk.RateLimitCookie{}
								if f8elemf7f8f1iter.Cookie.Name != nil {
									f8elemf7f8f1elemf0.SetName(*f8elemf7f8f1iter.Cookie.Name)
								}
								if f8elemf7f8f1iter.Cookie.TextTransformations != nil {
									f8elemf7f8f1elemf0f1 := []*svcsdk.TextTransformation{}
									for _, f8elemf7f8f1elemf0f1iter := range f8elemf7f8f1iter.Cookie.TextTransformations {
										f8elemf7f8f1elemf0f1elem := &svcsdk.TextTransformation{}
										if f8elemf7f8f1elemf0f1iter.Priority != nil {
											f8elemf7f8f1elemf0f1elem.SetPriority(*f8elemf7f8f1elemf0f1iter.Priority)
										}
										if f8elemf7f8f1elemf0f1iter.Type != nil {
											f8elemf7f8f1elemf0f1elem.SetType(*f8elemf7f8f1elemf0f1iter.Type)
										}
										f8elemf7f8f1elemf0f1 = append(f8elemf7f8f1elemf0f1, f8elemf7f8f1elemf0f1elem)
									}
									f8elemf7f8f1elemf0.SetTextTransformations(f8elemf7f8f1elemf0f1)
								}
								f8elemf7f8f1elem.SetCookie(f8elemf7f8f1elemf0)
							}
							if f8elemf7f8f1iter.ForwardedIP != nil {
								f8elemf7f8f1elemf1 := &svcsdk.RateLimitForwardedIP{}
								f8elemf7f8f1elem.SetForwardedIP(f8elemf7f8f1elemf1)
							}
							if f8elemf7f8f1iter.HTTPMethod != nil {
								f8elemf7f8f1elemf2 := &svcsdk.RateLimitHTTPMethod{}
								f8elemf7f8f1elem.SetHTTPMethod(f8elemf7f8f1elemf2)
							}
							if f8elemf7f8f1iter.Header != nil {
								f8elemf7f8f1elemf3 := &svcsdk.RateLimitHeader{}
								if f8elemf7f8f1iter.Header.Name != nil {
									f8elemf7f8f1elemf3.SetName(*f8elemf7f8f1iter.Header.Name)
								}
								if f8elemf7f8f1iter.Header.TextTransformations != nil {
									f8elemf7f8f1elemf3f1 := []*svcsdk.TextTransformation{}
									for _, f8elemf7f8f1elemf3f1iter := range f8elemf7f8f1iter.Header.TextTransformations {
										f8elemf7f8f1elemf3f1elem := &svcsdk.TextTransformation{}
										if f8elemf7f8f1elemf3f1iter.Priority != nil {
											f8elemf7f8f1elemf3f1elem.SetPriority(*f8elemf7f8f1elemf3f1iter.Priority)
										}
										if f8elemf7f8f1elemf3f1iter.Type != nil {
											f8elemf7f8f1elemf3f1elem.SetType(*f8elemf7f8f1elemf3f1iter.Type)
										}
										f8elemf7f8f1elemf3f1 = append(f8elemf7f8f1elemf3f1, f8elemf7f8f1elemf3f1elem)
									}
									f8elemf7f8f1elemf3.SetTextTransformations(f8elemf7f8f1elemf3f1)
								}
								f8elemf7f8f1elem.SetHeader(f8elemf7f8f1elemf3)
							}
							if f8elemf7f8f1iter.IP != nil {
								f8elemf7f8f1elemf4 := &svcsdk.RateLimitIP{}
								f8elemf7f8f1elem.SetIP(f8elemf7f8f1elemf4)
							}
							if f8elemf7f8f1iter.LabelNamespace != nil {
								f8elemf7f8f1elemf5 := &svcsdk.RateLimitLabelNamespace{}
								if f8elemf7f8f1iter.LabelNamespace.Namespace != nil {
									f8elemf7f8f1elemf5.SetNamespace(*f8elemf7f8f1iter.LabelNamespace.Namespace)
								}
								f8elemf7f8f1elem.SetLabelNamespace(f8elemf7f8f1elemf5)
							}
							if f8elemf7f8f1iter.QueryArgument != nil {
								f8elemf7f8f1elemf6 := &svcsdk.RateLimitQueryArgument{}
								if f8elemf7f8f1iter.QueryArgument.Name != nil {
									f8elemf7f8f1elemf6.SetName(*f8elemf7f8f1iter.QueryArgument.Name)
								}
								if f8elemf7f8f1iter.QueryArgument.TextTransformations != nil {
									f8elemf7f8f1elemf6f1 := []*svcsdk.TextTransformation{}
									for _, f8elemf7f8f1elemf6f1iter := range f8elemf7f8f1iter.QueryArgument.TextTransformations {
										f8elemf7f8f1elemf6f1elem := &svcsdk.TextTransformation{}
										if f8elemf7f8f1elemf6f1iter.Priority != nil {
											f8elemf7f8f1elemf6f1elem.SetPriority(*f8elemf7f8f1elemf6f1iter.Priority)
										}
										if f8elemf7f8f1elemf6f1iter.Type != nil {
											f8elemf7f8f1elemf6f1elem.SetType(*f8elemf7f8f1elemf6f1iter.Type)
										}
										f8elemf7f8f1elemf6f1 = append(f8elemf7f8f1elemf6f1, f8elemf7f8f1elemf6f1elem)
									}
									f8elemf7f8f1elemf6.SetTextTransformations(f8elemf7f8f1elemf6f1)
								}
								f8elemf7f8f1elem.SetQueryArgument(f8elemf7f8f1elemf6)
							}
							if f8elemf7f8f1iter.QueryString != nil {
								f8elemf7f8f1elemf7 := &svcsdk.RateLimitQueryString{}
								if f8elemf7f8f1iter.QueryString.TextTransformations != nil {
									f8elemf7f8f1elemf7f0 := []*svcsdk.TextTransformation{}
									for _, f8elemf7f8f1elemf7f0iter := range f8elemf7f8f1iter.QueryString.TextTransformations {
										f8elemf7f8f1elemf7f0elem := &svcsdk.TextTransformation{}
										if f8elemf7f8f1elemf7f0iter.Priority != nil {
											f8elemf7f8f1elemf7f0elem.SetPriority(*f8elemf7f8f1elemf7f0iter.Priority)
										}
										if f8elemf7f8f1elemf7f0iter.Type != nil {
											f8elemf7f8f1elemf7f0elem.SetType(*f8elemf7f8f1elemf7f0iter.Type)
										}
										f8elemf7f8f1elemf7f0 = append(f8elemf7f8f1elemf7f0, f8elemf7f8f1elemf7f0elem)
									}
									f8elemf7f8f1elemf7.SetTextTransformations(f8elemf7f8f1elemf7f0)
								}
								f8elemf7f8f1elem.SetQueryString(f8elemf7f8f1elemf7)
							}
							if f8elemf7f8f1iter.URIPath != nil {
								f8elemf7f8f1elemf8 := &svcsdk.RateLimitUriPath{}
								if f8elemf7f8f1iter.URIPath.TextTransformations != nil {
									f8elemf7f8f1elemf8f0 := []*svcsdk.TextTransformation{}
									for _, f8elemf7f8f1elemf8f0iter := range f8elemf7f8f1iter.URIPath.TextTransformations {
										f8elemf7f8f1elemf8f0elem := &svcsdk.TextTransformation{}
										if f8elemf7f8f1elemf8f0iter.Priority != nil {
											f8elemf7f8f1elemf8f0elem.SetPriority(*f8elemf7f8f1elemf8f0iter.Priority)
										}
										if f8elemf7f8f1elemf8f0iter.Type != nil {
											f8elemf7f8f1elemf8f0elem.SetType(*f8elemf7f8f1elemf8f0iter.Type)
										}
										f8elemf7f8f1elemf8f0 = append(f8elemf7f8f1elemf8f0, f8elemf7f8f1elemf8f0elem)
									}
									f8elemf7f8f1elemf8.SetTextTransformations(f8elemf7f8f1elemf8f0)
								}
								f8elemf7f8f1elem.SetUriPath(f8elemf7f8f1elemf8)
							}
							f8elemf7f8f1 = append(f8elemf7f8f1, f8elemf7f8f1elem)
						}
						f8elemf7f8.SetCustomKeys(f8elemf7f8f1)
					}
					if f8iter.Statement.RateBasedStatement.ForwardedIPConfig != nil {
						f8elemf7f8f2 := &svcsdk.ForwardedIPConfig{}
						if f8iter.Statement.RateBasedStatement.ForwardedIPConfig.FallbackBehavior != nil {
							f8elemf7f8f2.SetFallbackBehavior(*f8iter.Statement.RateBasedStatement.ForwardedIPConfig.FallbackBehavior)
						}
						if f8iter.Statement.RateBasedStatement.ForwardedIPConfig.HeaderName != nil {
							f8elemf7f8f2.SetHeaderName(*f8iter.Statement.RateBasedStatement.ForwardedIPConfig.HeaderName)
						}
						f8elemf7f8.SetForwardedIPConfig(f8elemf7f8f2)
					}
					if f8iter.Statement.RateBasedStatement.Limit != nil {
						f8elemf7f8.SetLimit(*f8iter.Statement.RateBasedStatement.Limit)
					}
					f8elemf7.SetRateBasedStatement(f8elemf7f8)
				}
				if f8iter.Statement.RegexMatchStatement != nil {
					f8elemf7f9 := &svcsdk.RegexMatchStatement{}
					if f8iter.Statement.RegexMatchStatement.FieldToMatch != nil {
						f8elemf7f9f0 := &svcsdk.FieldToMatch{}
						if f8iter.Statement.RegexMatchStatement.FieldToMatch.AllQueryArguments != nil {
							f8elemf7f9f0f0 := &svcsdk.AllQueryArguments{}
							f8elemf7f9f0.SetAllQueryArguments(f8elemf7f9f0f0)
						}
						if f8iter.Statement.RegexMatchStatement.FieldToMatch.Body != nil {
							f8elemf7f9f0f1 := &svcsdk.Body{}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.Body.OversizeHandling != nil {
								f8elemf7f9f0f1.SetOversizeHandling(*f8iter.Statement.RegexMatchStatement.FieldToMatch.Body.OversizeHandling)
							}
							f8elemf7f9f0.SetBody(f8elemf7f9f0f1)
						}
						if f8iter.Statement.RegexMatchStatement.FieldToMatch.Cookies != nil {
							f8elemf7f9f0f2 := &svcsdk.Cookies{}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchPattern != nil {
								f8elemf7f9f0f2f0 := &svcsdk.CookieMatchPattern{}
								if f8iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchPattern.All != nil {
									f8elemf7f9f0f2f0f0 := &svcsdk.All{}
									f8elemf7f9f0f2f0.SetAll(f8elemf7f9f0f2f0f0)
								}
								if f8iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies != nil {
									f8elemf7f9f0f2f0f1 := []*string{}
									for _, f8elemf7f9f0f2f0f1iter := range f8iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies {
										var f8elemf7f9f0f2f0f1elem string
										f8elemf7f9f0f2f0f1elem = *f8elemf7f9f0f2f0f1iter
										f8elemf7f9f0f2f0f1 = append(f8elemf7f9f0f2f0f1, &f8elemf7f9f0f2f0f1elem)
									}
									f8elemf7f9f0f2f0.SetExcludedCookies(f8elemf7f9f0f2f0f1)
								}
								if f8iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies != nil {
									f8elemf7f9f0f2f0f2 := []*string{}
									for _, f8elemf7f9f0f2f0f2iter := range f8iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies {
										var f8elemf7f9f0f2f0f2elem string
										f8elemf7f9f0f2f0f2elem = *f8elemf7f9f0f2f0f2iter
										f8elemf7f9f0f2f0f2 = append(f8elemf7f9f0f2f0f2, &f8elemf7f9f0f2f0f2elem)
									}
									f8elemf7f9f0f2f0.SetIncludedCookies(f8elemf7f9f0f2f0f2)
								}
								f8elemf7f9f0f2.SetMatchPattern(f8elemf7f9f0f2f0)
							}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchScope != nil {
								f8elemf7f9f0f2.SetMatchScope(*f8iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.MatchScope)
							}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.OversizeHandling != nil {
								f8elemf7f9f0f2.SetOversizeHandling(*f8iter.Statement.RegexMatchStatement.FieldToMatch.Cookies.OversizeHandling)
							}
							f8elemf7f9f0.SetCookies(f8elemf7f9f0f2)
						}
						if f8iter.Statement.RegexMatchStatement.FieldToMatch.HeaderOrder != nil {
							f8elemf7f9f0f3 := &svcsdk.HeaderOrder{}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling != nil {
								f8elemf7f9f0f3.SetOversizeHandling(*f8iter.Statement.RegexMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling)
							}
							f8elemf7f9f0.SetHeaderOrder(f8elemf7f9f0f3)
						}
						if f8iter.Statement.RegexMatchStatement.FieldToMatch.Headers != nil {
							f8elemf7f9f0f4 := &svcsdk.Headers{}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchPattern != nil {
								f8elemf7f9f0f4f0 := &svcsdk.HeaderMatchPattern{}
								if f8iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchPattern.All != nil {
									f8elemf7f9f0f4f0f0 := &svcsdk.All{}
									f8elemf7f9f0f4f0.SetAll(f8elemf7f9f0f4f0f0)
								}
								if f8iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders != nil {
									f8elemf7f9f0f4f0f1 := []*string{}
									for _, f8elemf7f9f0f4f0f1iter := range f8iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders {
										var f8elemf7f9f0f4f0f1elem string
										f8elemf7f9f0f4f0f1elem = *f8elemf7f9f0f4f0f1iter
										f8elemf7f9f0f4f0f1 = append(f8elemf7f9f0f4f0f1, &f8elemf7f9f0f4f0f1elem)
									}
									f8elemf7f9f0f4f0.SetExcludedHeaders(f8elemf7f9f0f4f0f1)
								}
								if f8iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders != nil {
									f8elemf7f9f0f4f0f2 := []*string{}
									for _, f8elemf7f9f0f4f0f2iter := range f8iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders {
										var f8elemf7f9f0f4f0f2elem string
										f8elemf7f9f0f4f0f2elem = *f8elemf7f9f0f4f0f2iter
										f8elemf7f9f0f4f0f2 = append(f8elemf7f9f0f4f0f2, &f8elemf7f9f0f4f0f2elem)
									}
									f8elemf7f9f0f4f0.SetIncludedHeaders(f8elemf7f9f0f4f0f2)
								}
								f8elemf7f9f0f4.SetMatchPattern(f8elemf7f9f0f4f0)
							}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchScope != nil {
								f8elemf7f9f0f4.SetMatchScope(*f8iter.Statement.RegexMatchStatement.FieldToMatch.Headers.MatchScope)
							}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.Headers.OversizeHandling != nil {
								f8elemf7f9f0f4.SetOversizeHandling(*f8iter.Statement.RegexMatchStatement.FieldToMatch.Headers.OversizeHandling)
							}
							f8elemf7f9f0.SetHeaders(f8elemf7f9f0f4)
						}
						if f8iter.Statement.RegexMatchStatement.FieldToMatch.JA3Fingerprint != nil {
							f8elemf7f9f0f5 := &svcsdk.JA3Fingerprint{}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior != nil {
								f8elemf7f9f0f5.SetFallbackBehavior(*f8iter.Statement.RegexMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior)
							}
							f8elemf7f9f0.SetJA3Fingerprint(f8elemf7f9f0f5)
						}
						if f8iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody != nil {
							f8elemf7f9f0f6 := &svcsdk.JsonBody{}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior != nil {
								f8elemf7f9f0f6.SetInvalidFallbackBehavior(*f8iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior)
							}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.MatchPattern != nil {
								f8elemf7f9f0f6f1 := &svcsdk.JsonMatchPattern{}
								if f8iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.MatchPattern.All != nil {
									f8elemf7f9f0f6f1f0 := &svcsdk.All{}
									f8elemf7f9f0f6f1.SetAll(f8elemf7f9f0f6f1f0)
								}
								if f8iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths != nil {
									f8elemf7f9f0f6f1f1 := []*string{}
									for _, f8elemf7f9f0f6f1f1iter := range f8iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths {
										var f8elemf7f9f0f6f1f1elem string
										f8elemf7f9f0f6f1f1elem = *f8elemf7f9f0f6f1f1iter
										f8elemf7f9f0f6f1f1 = append(f8elemf7f9f0f6f1f1, &f8elemf7f9f0f6f1f1elem)
									}
									f8elemf7f9f0f6f1.SetIncludedPaths(f8elemf7f9f0f6f1f1)
								}
								f8elemf7f9f0f6.SetMatchPattern(f8elemf7f9f0f6f1)
							}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.MatchScope != nil {
								f8elemf7f9f0f6.SetMatchScope(*f8iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.MatchScope)
							}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.OversizeHandling != nil {
								f8elemf7f9f0f6.SetOversizeHandling(*f8iter.Statement.RegexMatchStatement.FieldToMatch.JSONBody.OversizeHandling)
							}
							f8elemf7f9f0.SetJsonBody(f8elemf7f9f0f6)
						}
						if f8iter.Statement.RegexMatchStatement.FieldToMatch.Method != nil {
							f8elemf7f9f0f7 := &svcsdk.Method{}
							f8elemf7f9f0.SetMethod(f8elemf7f9f0f7)
						}
						if f8iter.Statement.RegexMatchStatement.FieldToMatch.QueryString != nil {
							f8elemf7f9f0f8 := &svcsdk.QueryString{}
							f8elemf7f9f0.SetQueryString(f8elemf7f9f0f8)
						}
						if f8iter.Statement.RegexMatchStatement.FieldToMatch.SingleHeader != nil {
							f8elemf7f9f0f9 := &svcsdk.SingleHeader{}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.SingleHeader.Name != nil {
								f8elemf7f9f0f9.SetName(*f8iter.Statement.RegexMatchStatement.FieldToMatch.SingleHeader.Name)
							}
							f8elemf7f9f0.SetSingleHeader(f8elemf7f9f0f9)
						}
						if f8iter.Statement.RegexMatchStatement.FieldToMatch.SingleQueryArgument != nil {
							f8elemf7f9f0f10 := &svcsdk.SingleQueryArgument{}
							if f8iter.Statement.RegexMatchStatement.FieldToMatch.SingleQueryArgument.Name != nil {
								f8elemf7f9f0f10.SetName(*f8iter.Statement.RegexMatchStatement.FieldToMatch.SingleQueryArgument.Name)
							}
							f8elemf7f9f0.SetSingleQueryArgument(f8elemf7f9f0f10)
						}
						if f8iter.Statement.RegexMatchStatement.FieldToMatch.URIPath != nil {
							f8elemf7f9f0f11 := &svcsdk.UriPath{}
							f8elemf7f9f0.SetUriPath(f8elemf7f9f0f11)
						}
						f8elemf7f9.SetFieldToMatch(f8elemf7f9f0)
					}
					if f8iter.Statement.RegexMatchStatement.RegexString != nil {
						f8elemf7f9.SetRegexString(*f8iter.Statement.RegexMatchStatement.RegexString)
					}
					if f8iter.Statement.RegexMatchStatement.TextTransformations != nil {
						f8elemf7f9f2 := []*svcsdk.TextTransformation{}
						for _, f8elemf7f9f2iter := range f8iter.Statement.RegexMatchStatement.TextTransformations {
							f8elemf7f9f2elem := &svcsdk.TextTransformation{}
							if f8elemf7f9f2iter.Priority != nil {
								f8elemf7f9f2elem.SetPriority(*f8elemf7f9f2iter.Priority)
							}
							if f8elemf7f9f2iter.Type != nil {
								f8elemf7f9f2elem.SetType(*f8elemf7f9f2iter.Type)
							}
							f8elemf7f9f2 = append(f8elemf7f9f2, f8elemf7f9f2elem)
						}
						f8elemf7f9.SetTextTransformations(f8elemf7f9f2)
					}
					f8elemf7.SetRegexMatchStatement(f8elemf7f9)
				}
				if f8iter.Statement.RegexPatternSetReferenceStatement != nil {
					f8elemf7f10 := &svcsdk.RegexPatternSetReferenceStatement{}
					if f8iter.Statement.RegexPatternSetReferenceStatement.ARN != nil {
						f8elemf7f10.SetARN(*f8iter.Statement.RegexPatternSetReferenceStatement.ARN)
					}
					if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch != nil {
						f8elemf7f10f1 := &svcsdk.FieldToMatch{}
						if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.AllQueryArguments != nil {
							f8elemf7f10f1f0 := &svcsdk.AllQueryArguments{}
							f8elemf7f10f1.SetAllQueryArguments(f8elemf7f10f1f0)
						}
						if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Body != nil {
							f8elemf7f10f1f1 := &svcsdk.Body{}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Body.OversizeHandling != nil {
								f8elemf7f10f1f1.SetOversizeHandling(*f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Body.OversizeHandling)
							}
							f8elemf7f10f1.SetBody(f8elemf7f10f1f1)
						}
						if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies != nil {
							f8elemf7f10f1f2 := &svcsdk.Cookies{}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchPattern != nil {
								f8elemf7f10f1f2f0 := &svcsdk.CookieMatchPattern{}
								if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchPattern.All != nil {
									f8elemf7f10f1f2f0f0 := &svcsdk.All{}
									f8elemf7f10f1f2f0.SetAll(f8elemf7f10f1f2f0f0)
								}
								if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies != nil {
									f8elemf7f10f1f2f0f1 := []*string{}
									for _, f8elemf7f10f1f2f0f1iter := range f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies {
										var f8elemf7f10f1f2f0f1elem string
										f8elemf7f10f1f2f0f1elem = *f8elemf7f10f1f2f0f1iter
										f8elemf7f10f1f2f0f1 = append(f8elemf7f10f1f2f0f1, &f8elemf7f10f1f2f0f1elem)
									}
									f8elemf7f10f1f2f0.SetExcludedCookies(f8elemf7f10f1f2f0f1)
								}
								if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies != nil {
									f8elemf7f10f1f2f0f2 := []*string{}
									for _, f8elemf7f10f1f2f0f2iter := range f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies {
										var f8elemf7f10f1f2f0f2elem string
										f8elemf7f10f1f2f0f2elem = *f8elemf7f10f1f2f0f2iter
										f8elemf7f10f1f2f0f2 = append(f8elemf7f10f1f2f0f2, &f8elemf7f10f1f2f0f2elem)
									}
									f8elemf7f10f1f2f0.SetIncludedCookies(f8elemf7f10f1f2f0f2)
								}
								f8elemf7f10f1f2.SetMatchPattern(f8elemf7f10f1f2f0)
							}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchScope != nil {
								f8elemf7f10f1f2.SetMatchScope(*f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.MatchScope)
							}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.OversizeHandling != nil {
								f8elemf7f10f1f2.SetOversizeHandling(*f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Cookies.OversizeHandling)
							}
							f8elemf7f10f1.SetCookies(f8elemf7f10f1f2)
						}
						if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.HeaderOrder != nil {
							f8elemf7f10f1f3 := &svcsdk.HeaderOrder{}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.HeaderOrder.OversizeHandling != nil {
								f8elemf7f10f1f3.SetOversizeHandling(*f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.HeaderOrder.OversizeHandling)
							}
							f8elemf7f10f1.SetHeaderOrder(f8elemf7f10f1f3)
						}
						if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers != nil {
							f8elemf7f10f1f4 := &svcsdk.Headers{}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchPattern != nil {
								f8elemf7f10f1f4f0 := &svcsdk.HeaderMatchPattern{}
								if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchPattern.All != nil {
									f8elemf7f10f1f4f0f0 := &svcsdk.All{}
									f8elemf7f10f1f4f0.SetAll(f8elemf7f10f1f4f0f0)
								}
								if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders != nil {
									f8elemf7f10f1f4f0f1 := []*string{}
									for _, f8elemf7f10f1f4f0f1iter := range f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders {
										var f8elemf7f10f1f4f0f1elem string
										f8elemf7f10f1f4f0f1elem = *f8elemf7f10f1f4f0f1iter
										f8elemf7f10f1f4f0f1 = append(f8elemf7f10f1f4f0f1, &f8elemf7f10f1f4f0f1elem)
									}
									f8elemf7f10f1f4f0.SetExcludedHeaders(f8elemf7f10f1f4f0f1)
								}
								if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders != nil {
									f8elemf7f10f1f4f0f2 := []*string{}
									for _, f8elemf7f10f1f4f0f2iter := range f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders {
										var f8elemf7f10f1f4f0f2elem string
										f8elemf7f10f1f4f0f2elem = *f8elemf7f10f1f4f0f2iter
										f8elemf7f10f1f4f0f2 = append(f8elemf7f10f1f4f0f2, &f8elemf7f10f1f4f0f2elem)
									}
									f8elemf7f10f1f4f0.SetIncludedHeaders(f8elemf7f10f1f4f0f2)
								}
								f8elemf7f10f1f4.SetMatchPattern(f8elemf7f10f1f4f0)
							}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchScope != nil {
								f8elemf7f10f1f4.SetMatchScope(*f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.MatchScope)
							}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.OversizeHandling != nil {
								f8elemf7f10f1f4.SetOversizeHandling(*f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Headers.OversizeHandling)
							}
							f8elemf7f10f1.SetHeaders(f8elemf7f10f1f4)
						}
						if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JA3Fingerprint != nil {
							f8elemf7f10f1f5 := &svcsdk.JA3Fingerprint{}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior != nil {
								f8elemf7f10f1f5.SetFallbackBehavior(*f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior)
							}
							f8elemf7f10f1.SetJA3Fingerprint(f8elemf7f10f1f5)
						}
						if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody != nil {
							f8elemf7f10f1f6 := &svcsdk.JsonBody{}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior != nil {
								f8elemf7f10f1f6.SetInvalidFallbackBehavior(*f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior)
							}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.MatchPattern != nil {
								f8elemf7f10f1f6f1 := &svcsdk.JsonMatchPattern{}
								if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.MatchPattern.All != nil {
									f8elemf7f10f1f6f1f0 := &svcsdk.All{}
									f8elemf7f10f1f6f1.SetAll(f8elemf7f10f1f6f1f0)
								}
								if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths != nil {
									f8elemf7f10f1f6f1f1 := []*string{}
									for _, f8elemf7f10f1f6f1f1iter := range f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths {
										var f8elemf7f10f1f6f1f1elem string
										f8elemf7f10f1f6f1f1elem = *f8elemf7f10f1f6f1f1iter
										f8elemf7f10f1f6f1f1 = append(f8elemf7f10f1f6f1f1, &f8elemf7f10f1f6f1f1elem)
									}
									f8elemf7f10f1f6f1.SetIncludedPaths(f8elemf7f10f1f6f1f1)
								}
								f8elemf7f10f1f6.SetMatchPattern(f8elemf7f10f1f6f1)
							}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.MatchScope != nil {
								f8elemf7f10f1f6.SetMatchScope(*f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.MatchScope)
							}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.OversizeHandling != nil {
								f8elemf7f10f1f6.SetOversizeHandling(*f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.JSONBody.OversizeHandling)
							}
							f8elemf7f10f1.SetJsonBody(f8elemf7f10f1f6)
						}
						if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.Method != nil {
							f8elemf7f10f1f7 := &svcsdk.Method{}
							f8elemf7f10f1.SetMethod(f8elemf7f10f1f7)
						}
						if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.QueryString != nil {
							f8elemf7f10f1f8 := &svcsdk.QueryString{}
							f8elemf7f10f1.SetQueryString(f8elemf7f10f1f8)
						}
						if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.SingleHeader != nil {
							f8elemf7f10f1f9 := &svcsdk.SingleHeader{}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.SingleHeader.Name != nil {
								f8elemf7f10f1f9.SetName(*f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.SingleHeader.Name)
							}
							f8elemf7f10f1.SetSingleHeader(f8elemf7f10f1f9)
						}
						if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.SingleQueryArgument != nil {
							f8elemf7f10f1f10 := &svcsdk.SingleQueryArgument{}
							if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.SingleQueryArgument.Name != nil {
								f8elemf7f10f1f10.SetName(*f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.SingleQueryArgument.Name)
							}
							f8elemf7f10f1.SetSingleQueryArgument(f8elemf7f10f1f10)
						}
						if f8iter.Statement.RegexPatternSetReferenceStatement.FieldToMatch.URIPath != nil {
							f8elemf7f10f1f11 := &svcsdk.UriPath{}
							f8elemf7f10f1.SetUriPath(f8elemf7f10f1f11)
						}
						f8elemf7f10.SetFieldToMatch(f8elemf7f10f1)
					}
					if f8iter.Statement.RegexPatternSetReferenceStatement.TextTransformations != nil {
						f8elemf7f10f2 := []*svcsdk.TextTransformation{}
						for _, f8elemf7f10f2iter := range f8iter.Statement.RegexPatternSetReferenceStatement.TextTransformations {
							f8elemf7f10f2elem := &svcsdk.TextTransformation{}
							if f8elemf7f10f2iter.Priority != nil {
								f8elemf7f10f2elem.SetPriority(*f8elemf7f10f2iter.Priority)
							}
							if f8elemf7f10f2iter.Type != nil {
								f8elemf7f10f2elem.SetType(*f8elemf7f10f2iter.Type)
							}
							f8elemf7f10f2 = append(f8elemf7f10f2, f8elemf7f10f2elem)
						}
						f8elemf7f10.SetTextTransformations(f8elemf7f10f2)
					}
					f8elemf7.SetRegexPatternSetReferenceStatement(f8elemf7f10)
				}
				if f8iter.Statement.RuleGroupReferenceStatement != nil {
					f8elemf7f11 := &svcsdk.RuleGroupReferenceStatement{}
					if f8iter.Statement.RuleGroupReferenceStatement.ARN != nil {
						f8elemf7f11.SetARN(*f8iter.Statement.RuleGroupReferenceStatement.ARN)
					}
					if f8iter.Statement.RuleGroupReferenceStatement.ExcludedRules != nil {
						f8elemf7f11f1 := []*svcsdk.ExcludedRule{}
						for _, f8elemf7f11f1iter := range f8iter.Statement.RuleGroupReferenceStatement.ExcludedRules {
							f8elemf7f11f1elem := &svcsdk.ExcludedRule{}
							if f8elemf7f11f1iter.Name != nil {
								f8elemf7f11f1elem.SetName(*f8elemf7f11f1iter.Name)
							}
							f8elemf7f11f1 = append(f8elemf7f11f1, f8elemf7f11f1elem)
						}
						f8elemf7f11.SetExcludedRules(f8elemf7f11f1)
					}
					if f8iter.Statement.RuleGroupReferenceStatement.RuleActionOverrides != nil {
						f8elemf7f11f2 := []*svcsdk.RuleActionOverride{}
						for _, f8elemf7f11f2iter := range f8iter.Statement.RuleGroupReferenceStatement.RuleActionOverrides {
							f8elemf7f11f2elem := &svcsdk.RuleActionOverride{}
							if f8elemf7f11f2iter.ActionToUse != nil {
								f8elemf7f11f2elemf0 := &svcsdk.RuleAction{}
								if f8elemf7f11f2iter.ActionToUse.Allow != nil {
									f8elemf7f11f2elemf0f0 := &svcsdk.AllowAction{}
									if f8elemf7f11f2iter.ActionToUse.Allow.CustomRequestHandling != nil {
										f8elemf7f11f2elemf0f0f0 := &svcsdk.CustomRequestHandling{}
										if f8elemf7f11f2iter.ActionToUse.Allow.CustomRequestHandling.InsertHeaders != nil {
											f8elemf7f11f2elemf0f0f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f8elemf7f11f2elemf0f0f0f0iter := range f8elemf7f11f2iter.ActionToUse.Allow.CustomRequestHandling.InsertHeaders {
												f8elemf7f11f2elemf0f0f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f8elemf7f11f2elemf0f0f0f0iter.Name != nil {
													f8elemf7f11f2elemf0f0f0f0elem.SetName(*f8elemf7f11f2elemf0f0f0f0iter.Name)
												}
												if f8elemf7f11f2elemf0f0f0f0iter.Value != nil {
													f8elemf7f11f2elemf0f0f0f0elem.SetValue(*f8elemf7f11f2elemf0f0f0f0iter.Value)
												}
												f8elemf7f11f2elemf0f0f0f0 = append(f8elemf7f11f2elemf0f0f0f0, f8elemf7f11f2elemf0f0f0f0elem)
											}
											f8elemf7f11f2elemf0f0f0.SetInsertHeaders(f8elemf7f11f2elemf0f0f0f0)
										}
										f8elemf7f11f2elemf0f0.SetCustomRequestHandling(f8elemf7f11f2elemf0f0f0)
									}
									f8elemf7f11f2elemf0.SetAllow(f8elemf7f11f2elemf0f0)
								}
								if f8elemf7f11f2iter.ActionToUse.Block != nil {
									f8elemf7f11f2elemf0f1 := &svcsdk.BlockAction{}
									if f8elemf7f11f2iter.ActionToUse.Block.CustomResponse != nil {
										f8elemf7f11f2elemf0f1f0 := &svcsdk.CustomResponse{}
										if f8elemf7f11f2iter.ActionToUse.Block.CustomResponse.CustomResponseBodyKey != nil {
											f8elemf7f11f2elemf0f1f0.SetCustomResponseBodyKey(*f8elemf7f11f2iter.ActionToUse.Block.CustomResponse.CustomResponseBodyKey)
										}
										if f8elemf7f11f2iter.ActionToUse.Block.CustomResponse.ResponseCode != nil {
											f8elemf7f11f2elemf0f1f0.SetResponseCode(*f8elemf7f11f2iter.ActionToUse.Block.CustomResponse.ResponseCode)
										}
										if f8elemf7f11f2iter.ActionToUse.Block.CustomResponse.ResponseHeaders != nil {
											f8elemf7f11f2elemf0f1f0f2 := []*svcsdk.CustomHTTPHeader{}
											for _, f8elemf7f11f2elemf0f1f0f2iter := range f8elemf7f11f2iter.ActionToUse.Block.CustomResponse.ResponseHeaders {
												f8elemf7f11f2elemf0f1f0f2elem := &svcsdk.CustomHTTPHeader{}
												if f8elemf7f11f2elemf0f1f0f2iter.Name != nil {
													f8elemf7f11f2elemf0f1f0f2elem.SetName(*f8elemf7f11f2elemf0f1f0f2iter.Name)
												}
												if f8elemf7f11f2elemf0f1f0f2iter.Value != nil {
													f8elemf7f11f2elemf0f1f0f2elem.SetValue(*f8elemf7f11f2elemf0f1f0f2iter.Value)
												}
												f8elemf7f11f2elemf0f1f0f2 = append(f8elemf7f11f2elemf0f1f0f2, f8elemf7f11f2elemf0f1f0f2elem)
											}
											f8elemf7f11f2elemf0f1f0.SetResponseHeaders(f8elemf7f11f2elemf0f1f0f2)
										}
										f8elemf7f11f2elemf0f1.SetCustomResponse(f8elemf7f11f2elemf0f1f0)
									}
									f8elemf7f11f2elemf0.SetBlock(f8elemf7f11f2elemf0f1)
								}
								if f8elemf7f11f2iter.ActionToUse.Captcha != nil {
									f8elemf7f11f2elemf0f2 := &svcsdk.CaptchaAction{}
									if f8elemf7f11f2iter.ActionToUse.Captcha.CustomRequestHandling != nil {
										f8elemf7f11f2elemf0f2f0 := &svcsdk.CustomRequestHandling{}
										if f8elemf7f11f2iter.ActionToUse.Captcha.CustomRequestHandling.InsertHeaders != nil {
											f8elemf7f11f2elemf0f2f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f8elemf7f11f2elemf0f2f0f0iter := range f8elemf7f11f2iter.ActionToUse.Captcha.CustomRequestHandling.InsertHeaders {
												f8elemf7f11f2elemf0f2f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f8elemf7f11f2elemf0f2f0f0iter.Name != nil {
													f8elemf7f11f2elemf0f2f0f0elem.SetName(*f8elemf7f11f2elemf0f2f0f0iter.Name)
												}
												if f8elemf7f11f2elemf0f2f0f0iter.Value != nil {
													f8elemf7f11f2elemf0f2f0f0elem.SetValue(*f8elemf7f11f2elemf0f2f0f0iter.Value)
												}
												f8elemf7f11f2elemf0f2f0f0 = append(f8elemf7f11f2elemf0f2f0f0, f8elemf7f11f2elemf0f2f0f0elem)
											}
											f8elemf7f11f2elemf0f2f0.SetInsertHeaders(f8elemf7f11f2elemf0f2f0f0)
										}
										f8elemf7f11f2elemf0f2.SetCustomRequestHandling(f8elemf7f11f2elemf0f2f0)
									}
									f8elemf7f11f2elemf0.SetCaptcha(f8elemf7f11f2elemf0f2)
								}
								if f8elemf7f11f2iter.ActionToUse.Challenge != nil {
									f8elemf7f11f2elemf0f3 := &svcsdk.ChallengeAction{}
									if f8elemf7f11f2iter.ActionToUse.Challenge.CustomRequestHandling != nil {
										f8elemf7f11f2elemf0f3f0 := &svcsdk.CustomRequestHandling{}
										if f8elemf7f11f2iter.ActionToUse.Challenge.CustomRequestHandling.InsertHeaders != nil {
											f8elemf7f11f2elemf0f3f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f8elemf7f11f2elemf0f3f0f0iter := range f8elemf7f11f2iter.ActionToUse.Challenge.CustomRequestHandling.InsertHeaders {
												f8elemf7f11f2elemf0f3f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f8elemf7f11f2elemf0f3f0f0iter.Name != nil {
													f8elemf7f11f2elemf0f3f0f0elem.SetName(*f8elemf7f11f2elemf0f3f0f0iter.Name)
												}
												if f8elemf7f11f2elemf0f3f0f0iter.Value != nil {
													f8elemf7f11f2elemf0f3f0f0elem.SetValue(*f8elemf7f11f2elemf0f3f0f0iter.Value)
												}
												f8elemf7f11f2elemf0f3f0f0 = append(f8elemf7f11f2elemf0f3f0f0, f8elemf7f11f2elemf0f3f0f0elem)
											}
											f8elemf7f11f2elemf0f3f0.SetInsertHeaders(f8elemf7f11f2elemf0f3f0f0)
										}
										f8elemf7f11f2elemf0f3.SetCustomRequestHandling(f8elemf7f11f2elemf0f3f0)
									}
									f8elemf7f11f2elemf0.SetChallenge(f8elemf7f11f2elemf0f3)
								}
								if f8elemf7f11f2iter.ActionToUse.Count != nil {
									f8elemf7f11f2elemf0f4 := &svcsdk.CountAction{}
									if f8elemf7f11f2iter.ActionToUse.Count.CustomRequestHandling != nil {
										f8elemf7f11f2elemf0f4f0 := &svcsdk.CustomRequestHandling{}
										if f8elemf7f11f2iter.ActionToUse.Count.CustomRequestHandling.InsertHeaders != nil {
											f8elemf7f11f2elemf0f4f0f0 := []*svcsdk.CustomHTTPHeader{}
											for _, f8elemf7f11f2elemf0f4f0f0iter := range f8elemf7f11f2iter.ActionToUse.Count.CustomRequestHandling.InsertHeaders {
												f8elemf7f11f2elemf0f4f0f0elem := &svcsdk.CustomHTTPHeader{}
												if f8elemf7f11f2elemf0f4f0f0iter.Name != nil {
													f8elemf7f11f2elemf0f4f0f0elem.SetName(*f8elemf7f11f2elemf0f4f0f0iter.Name)
												}
												if f8elemf7f11f2elemf0f4f0f0iter.Value != nil {
													f8elemf7f11f2elemf0f4f0f0elem.SetValue(*f8elemf7f11f2elemf0f4f0f0iter.Value)
												}
												f8elemf7f11f2elemf0f4f0f0 = append(f8elemf7f11f2elemf0f4f0f0, f8elemf7f11f2elemf0f4f0f0elem)
											}
											f8elemf7f11f2elemf0f4f0.SetInsertHeaders(f8elemf7f11f2elemf0f4f0f0)
										}
										f8elemf7f11f2elemf0f4.SetCustomRequestHandling(f8elemf7f11f2elemf0f4f0)
									}
									f8elemf7f11f2elemf0.SetCount(f8elemf7f11f2elemf0f4)
								}
								f8elemf7f11f2elem.SetActionToUse(f8elemf7f11f2elemf0)
							}
							if f8elemf7f11f2iter.Name != nil {
								f8elemf7f11f2elem.SetName(*f8elemf7f11f2iter.Name)
							}
							f8elemf7f11f2 = append(f8elemf7f11f2, f8elemf7f11f2elem)
						}
						f8elemf7f11.SetRuleActionOverrides(f8elemf7f11f2)
					}
					f8elemf7.SetRuleGroupReferenceStatement(f8elemf7f11)
				}
				if f8iter.Statement.SizeConstraintStatement != nil {
					f8elemf7f12 := &svcsdk.SizeConstraintStatement{}
					if f8iter.Statement.SizeConstraintStatement.ComparisonOperator != nil {
						f8elemf7f12.SetComparisonOperator(*f8iter.Statement.SizeConstraintStatement.ComparisonOperator)
					}
					if f8iter.Statement.SizeConstraintStatement.FieldToMatch != nil {
						f8elemf7f12f1 := &svcsdk.FieldToMatch{}
						if f8iter.Statement.SizeConstraintStatement.FieldToMatch.AllQueryArguments != nil {
							f8elemf7f12f1f0 := &svcsdk.AllQueryArguments{}
							f8elemf7f12f1.SetAllQueryArguments(f8elemf7f12f1f0)
						}
						if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Body != nil {
							f8elemf7f12f1f1 := &svcsdk.Body{}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Body.OversizeHandling != nil {
								f8elemf7f12f1f1.SetOversizeHandling(*f8iter.Statement.SizeConstraintStatement.FieldToMatch.Body.OversizeHandling)
							}
							f8elemf7f12f1.SetBody(f8elemf7f12f1f1)
						}
						if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies != nil {
							f8elemf7f12f1f2 := &svcsdk.Cookies{}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchPattern != nil {
								f8elemf7f12f1f2f0 := &svcsdk.CookieMatchPattern{}
								if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchPattern.All != nil {
									f8elemf7f12f1f2f0f0 := &svcsdk.All{}
									f8elemf7f12f1f2f0.SetAll(f8elemf7f12f1f2f0f0)
								}
								if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies != nil {
									f8elemf7f12f1f2f0f1 := []*string{}
									for _, f8elemf7f12f1f2f0f1iter := range f8iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies {
										var f8elemf7f12f1f2f0f1elem string
										f8elemf7f12f1f2f0f1elem = *f8elemf7f12f1f2f0f1iter
										f8elemf7f12f1f2f0f1 = append(f8elemf7f12f1f2f0f1, &f8elemf7f12f1f2f0f1elem)
									}
									f8elemf7f12f1f2f0.SetExcludedCookies(f8elemf7f12f1f2f0f1)
								}
								if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies != nil {
									f8elemf7f12f1f2f0f2 := []*string{}
									for _, f8elemf7f12f1f2f0f2iter := range f8iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies {
										var f8elemf7f12f1f2f0f2elem string
										f8elemf7f12f1f2f0f2elem = *f8elemf7f12f1f2f0f2iter
										f8elemf7f12f1f2f0f2 = append(f8elemf7f12f1f2f0f2, &f8elemf7f12f1f2f0f2elem)
									}
									f8elemf7f12f1f2f0.SetIncludedCookies(f8elemf7f12f1f2f0f2)
								}
								f8elemf7f12f1f2.SetMatchPattern(f8elemf7f12f1f2f0)
							}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchScope != nil {
								f8elemf7f12f1f2.SetMatchScope(*f8iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.MatchScope)
							}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.OversizeHandling != nil {
								f8elemf7f12f1f2.SetOversizeHandling(*f8iter.Statement.SizeConstraintStatement.FieldToMatch.Cookies.OversizeHandling)
							}
							f8elemf7f12f1.SetCookies(f8elemf7f12f1f2)
						}
						if f8iter.Statement.SizeConstraintStatement.FieldToMatch.HeaderOrder != nil {
							f8elemf7f12f1f3 := &svcsdk.HeaderOrder{}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.HeaderOrder.OversizeHandling != nil {
								f8elemf7f12f1f3.SetOversizeHandling(*f8iter.Statement.SizeConstraintStatement.FieldToMatch.HeaderOrder.OversizeHandling)
							}
							f8elemf7f12f1.SetHeaderOrder(f8elemf7f12f1f3)
						}
						if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Headers != nil {
							f8elemf7f12f1f4 := &svcsdk.Headers{}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchPattern != nil {
								f8elemf7f12f1f4f0 := &svcsdk.HeaderMatchPattern{}
								if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchPattern.All != nil {
									f8elemf7f12f1f4f0f0 := &svcsdk.All{}
									f8elemf7f12f1f4f0.SetAll(f8elemf7f12f1f4f0f0)
								}
								if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders != nil {
									f8elemf7f12f1f4f0f1 := []*string{}
									for _, f8elemf7f12f1f4f0f1iter := range f8iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders {
										var f8elemf7f12f1f4f0f1elem string
										f8elemf7f12f1f4f0f1elem = *f8elemf7f12f1f4f0f1iter
										f8elemf7f12f1f4f0f1 = append(f8elemf7f12f1f4f0f1, &f8elemf7f12f1f4f0f1elem)
									}
									f8elemf7f12f1f4f0.SetExcludedHeaders(f8elemf7f12f1f4f0f1)
								}
								if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders != nil {
									f8elemf7f12f1f4f0f2 := []*string{}
									for _, f8elemf7f12f1f4f0f2iter := range f8iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders {
										var f8elemf7f12f1f4f0f2elem string
										f8elemf7f12f1f4f0f2elem = *f8elemf7f12f1f4f0f2iter
										f8elemf7f12f1f4f0f2 = append(f8elemf7f12f1f4f0f2, &f8elemf7f12f1f4f0f2elem)
									}
									f8elemf7f12f1f4f0.SetIncludedHeaders(f8elemf7f12f1f4f0f2)
								}
								f8elemf7f12f1f4.SetMatchPattern(f8elemf7f12f1f4f0)
							}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchScope != nil {
								f8elemf7f12f1f4.SetMatchScope(*f8iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.MatchScope)
							}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.OversizeHandling != nil {
								f8elemf7f12f1f4.SetOversizeHandling(*f8iter.Statement.SizeConstraintStatement.FieldToMatch.Headers.OversizeHandling)
							}
							f8elemf7f12f1.SetHeaders(f8elemf7f12f1f4)
						}
						if f8iter.Statement.SizeConstraintStatement.FieldToMatch.JA3Fingerprint != nil {
							f8elemf7f12f1f5 := &svcsdk.JA3Fingerprint{}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior != nil {
								f8elemf7f12f1f5.SetFallbackBehavior(*f8iter.Statement.SizeConstraintStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior)
							}
							f8elemf7f12f1.SetJA3Fingerprint(f8elemf7f12f1f5)
						}
						if f8iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody != nil {
							f8elemf7f12f1f6 := &svcsdk.JsonBody{}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior != nil {
								f8elemf7f12f1f6.SetInvalidFallbackBehavior(*f8iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior)
							}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.MatchPattern != nil {
								f8elemf7f12f1f6f1 := &svcsdk.JsonMatchPattern{}
								if f8iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.MatchPattern.All != nil {
									f8elemf7f12f1f6f1f0 := &svcsdk.All{}
									f8elemf7f12f1f6f1.SetAll(f8elemf7f12f1f6f1f0)
								}
								if f8iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths != nil {
									f8elemf7f12f1f6f1f1 := []*string{}
									for _, f8elemf7f12f1f6f1f1iter := range f8iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths {
										var f8elemf7f12f1f6f1f1elem string
										f8elemf7f12f1f6f1f1elem = *f8elemf7f12f1f6f1f1iter
										f8elemf7f12f1f6f1f1 = append(f8elemf7f12f1f6f1f1, &f8elemf7f12f1f6f1f1elem)
									}
									f8elemf7f12f1f6f1.SetIncludedPaths(f8elemf7f12f1f6f1f1)
								}
								f8elemf7f12f1f6.SetMatchPattern(f8elemf7f12f1f6f1)
							}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.MatchScope != nil {
								f8elemf7f12f1f6.SetMatchScope(*f8iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.MatchScope)
							}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.OversizeHandling != nil {
								f8elemf7f12f1f6.SetOversizeHandling(*f8iter.Statement.SizeConstraintStatement.FieldToMatch.JSONBody.OversizeHandling)
							}
							f8elemf7f12f1.SetJsonBody(f8elemf7f12f1f6)
						}
						if f8iter.Statement.SizeConstraintStatement.FieldToMatch.Method != nil {
							f8elemf7f12f1f7 := &svcsdk.Method{}
							f8elemf7f12f1.SetMethod(f8elemf7f12f1f7)
						}
						if f8iter.Statement.SizeConstraintStatement.FieldToMatch.QueryString != nil {
							f8elemf7f12f1f8 := &svcsdk.QueryString{}
							f8elemf7f12f1.SetQueryString(f8elemf7f12f1f8)
						}
						if f8iter.Statement.SizeConstraintStatement.FieldToMatch.SingleHeader != nil {
							f8elemf7f12f1f9 := &svcsdk.SingleHeader{}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.SingleHeader.Name != nil {
								f8elemf7f12f1f9.SetName(*f8iter.Statement.SizeConstraintStatement.FieldToMatch.SingleHeader.Name)
							}
							f8elemf7f12f1.SetSingleHeader(f8elemf7f12f1f9)
						}
						if f8iter.Statement.SizeConstraintStatement.FieldToMatch.SingleQueryArgument != nil {
							f8elemf7f12f1f10 := &svcsdk.SingleQueryArgument{}
							if f8iter.Statement.SizeConstraintStatement.FieldToMatch.SingleQueryArgument.Name != nil {
								f8elemf7f12f1f10.SetName(*f8iter.Statement.SizeConstraintStatement.FieldToMatch.SingleQueryArgument.Name)
							}
							f8elemf7f12f1.SetSingleQueryArgument(f8elemf7f12f1f10)
						}
						if f8iter.Statement.SizeConstraintStatement.FieldToMatch.URIPath != nil {
							f8elemf7f12f1f11 := &svcsdk.UriPath{}
							f8elemf7f12f1.SetUriPath(f8elemf7f12f1f11)
						}
						f8elemf7f12.SetFieldToMatch(f8elemf7f12f1)
					}
					if f8iter.Statement.SizeConstraintStatement.Size != nil {
						f8elemf7f12.SetSize(*f8iter.Statement.SizeConstraintStatement.Size)
					}
					if f8iter.Statement.SizeConstraintStatement.TextTransformations != nil {
						f8elemf7f12f3 := []*svcsdk.TextTransformation{}
						for _, f8elemf7f12f3iter := range f8iter.Statement.SizeConstraintStatement.TextTransformations {
							f8elemf7f12f3elem := &svcsdk.TextTransformation{}
							if f8elemf7f12f3iter.Priority != nil {
								f8elemf7f12f3elem.SetPriority(*f8elemf7f12f3iter.Priority)
							}
							if f8elemf7f12f3iter.Type != nil {
								f8elemf7f12f3elem.SetType(*f8elemf7f12f3iter.Type)
							}
							f8elemf7f12f3 = append(f8elemf7f12f3, f8elemf7f12f3elem)
						}
						f8elemf7f12.SetTextTransformations(f8elemf7f12f3)
					}
					f8elemf7.SetSizeConstraintStatement(f8elemf7f12)
				}
				if f8iter.Statement.SQLIMatchStatement != nil {
					f8elemf7f13 := &svcsdk.SqliMatchStatement{}
					if f8iter.Statement.SQLIMatchStatement.FieldToMatch != nil {
						f8elemf7f13f0 := &svcsdk.FieldToMatch{}
						if f8iter.Statement.SQLIMatchStatement.FieldToMatch.AllQueryArguments != nil {
							f8elemf7f13f0f0 := &svcsdk.AllQueryArguments{}
							f8elemf7f13f0.SetAllQueryArguments(f8elemf7f13f0f0)
						}
						if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Body != nil {
							f8elemf7f13f0f1 := &svcsdk.Body{}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Body.OversizeHandling != nil {
								f8elemf7f13f0f1.SetOversizeHandling(*f8iter.Statement.SQLIMatchStatement.FieldToMatch.Body.OversizeHandling)
							}
							f8elemf7f13f0.SetBody(f8elemf7f13f0f1)
						}
						if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies != nil {
							f8elemf7f13f0f2 := &svcsdk.Cookies{}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchPattern != nil {
								f8elemf7f13f0f2f0 := &svcsdk.CookieMatchPattern{}
								if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchPattern.All != nil {
									f8elemf7f13f0f2f0f0 := &svcsdk.All{}
									f8elemf7f13f0f2f0.SetAll(f8elemf7f13f0f2f0f0)
								}
								if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies != nil {
									f8elemf7f13f0f2f0f1 := []*string{}
									for _, f8elemf7f13f0f2f0f1iter := range f8iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies {
										var f8elemf7f13f0f2f0f1elem string
										f8elemf7f13f0f2f0f1elem = *f8elemf7f13f0f2f0f1iter
										f8elemf7f13f0f2f0f1 = append(f8elemf7f13f0f2f0f1, &f8elemf7f13f0f2f0f1elem)
									}
									f8elemf7f13f0f2f0.SetExcludedCookies(f8elemf7f13f0f2f0f1)
								}
								if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies != nil {
									f8elemf7f13f0f2f0f2 := []*string{}
									for _, f8elemf7f13f0f2f0f2iter := range f8iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies {
										var f8elemf7f13f0f2f0f2elem string
										f8elemf7f13f0f2f0f2elem = *f8elemf7f13f0f2f0f2iter
										f8elemf7f13f0f2f0f2 = append(f8elemf7f13f0f2f0f2, &f8elemf7f13f0f2f0f2elem)
									}
									f8elemf7f13f0f2f0.SetIncludedCookies(f8elemf7f13f0f2f0f2)
								}
								f8elemf7f13f0f2.SetMatchPattern(f8elemf7f13f0f2f0)
							}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchScope != nil {
								f8elemf7f13f0f2.SetMatchScope(*f8iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.MatchScope)
							}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.OversizeHandling != nil {
								f8elemf7f13f0f2.SetOversizeHandling(*f8iter.Statement.SQLIMatchStatement.FieldToMatch.Cookies.OversizeHandling)
							}
							f8elemf7f13f0.SetCookies(f8elemf7f13f0f2)
						}
						if f8iter.Statement.SQLIMatchStatement.FieldToMatch.HeaderOrder != nil {
							f8elemf7f13f0f3 := &svcsdk.HeaderOrder{}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling != nil {
								f8elemf7f13f0f3.SetOversizeHandling(*f8iter.Statement.SQLIMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling)
							}
							f8elemf7f13f0.SetHeaderOrder(f8elemf7f13f0f3)
						}
						if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Headers != nil {
							f8elemf7f13f0f4 := &svcsdk.Headers{}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchPattern != nil {
								f8elemf7f13f0f4f0 := &svcsdk.HeaderMatchPattern{}
								if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchPattern.All != nil {
									f8elemf7f13f0f4f0f0 := &svcsdk.All{}
									f8elemf7f13f0f4f0.SetAll(f8elemf7f13f0f4f0f0)
								}
								if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders != nil {
									f8elemf7f13f0f4f0f1 := []*string{}
									for _, f8elemf7f13f0f4f0f1iter := range f8iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders {
										var f8elemf7f13f0f4f0f1elem string
										f8elemf7f13f0f4f0f1elem = *f8elemf7f13f0f4f0f1iter
										f8elemf7f13f0f4f0f1 = append(f8elemf7f13f0f4f0f1, &f8elemf7f13f0f4f0f1elem)
									}
									f8elemf7f13f0f4f0.SetExcludedHeaders(f8elemf7f13f0f4f0f1)
								}
								if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders != nil {
									f8elemf7f13f0f4f0f2 := []*string{}
									for _, f8elemf7f13f0f4f0f2iter := range f8iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders {
										var f8elemf7f13f0f4f0f2elem string
										f8elemf7f13f0f4f0f2elem = *f8elemf7f13f0f4f0f2iter
										f8elemf7f13f0f4f0f2 = append(f8elemf7f13f0f4f0f2, &f8elemf7f13f0f4f0f2elem)
									}
									f8elemf7f13f0f4f0.SetIncludedHeaders(f8elemf7f13f0f4f0f2)
								}
								f8elemf7f13f0f4.SetMatchPattern(f8elemf7f13f0f4f0)
							}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchScope != nil {
								f8elemf7f13f0f4.SetMatchScope(*f8iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.MatchScope)
							}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.OversizeHandling != nil {
								f8elemf7f13f0f4.SetOversizeHandling(*f8iter.Statement.SQLIMatchStatement.FieldToMatch.Headers.OversizeHandling)
							}
							f8elemf7f13f0.SetHeaders(f8elemf7f13f0f4)
						}
						if f8iter.Statement.SQLIMatchStatement.FieldToMatch.JA3Fingerprint != nil {
							f8elemf7f13f0f5 := &svcsdk.JA3Fingerprint{}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior != nil {
								f8elemf7f13f0f5.SetFallbackBehavior(*f8iter.Statement.SQLIMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior)
							}
							f8elemf7f13f0.SetJA3Fingerprint(f8elemf7f13f0f5)
						}
						if f8iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody != nil {
							f8elemf7f13f0f6 := &svcsdk.JsonBody{}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior != nil {
								f8elemf7f13f0f6.SetInvalidFallbackBehavior(*f8iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior)
							}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.MatchPattern != nil {
								f8elemf7f13f0f6f1 := &svcsdk.JsonMatchPattern{}
								if f8iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.MatchPattern.All != nil {
									f8elemf7f13f0f6f1f0 := &svcsdk.All{}
									f8elemf7f13f0f6f1.SetAll(f8elemf7f13f0f6f1f0)
								}
								if f8iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths != nil {
									f8elemf7f13f0f6f1f1 := []*string{}
									for _, f8elemf7f13f0f6f1f1iter := range f8iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths {
										var f8elemf7f13f0f6f1f1elem string
										f8elemf7f13f0f6f1f1elem = *f8elemf7f13f0f6f1f1iter
										f8elemf7f13f0f6f1f1 = append(f8elemf7f13f0f6f1f1, &f8elemf7f13f0f6f1f1elem)
									}
									f8elemf7f13f0f6f1.SetIncludedPaths(f8elemf7f13f0f6f1f1)
								}
								f8elemf7f13f0f6.SetMatchPattern(f8elemf7f13f0f6f1)
							}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.MatchScope != nil {
								f8elemf7f13f0f6.SetMatchScope(*f8iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.MatchScope)
							}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.OversizeHandling != nil {
								f8elemf7f13f0f6.SetOversizeHandling(*f8iter.Statement.SQLIMatchStatement.FieldToMatch.JSONBody.OversizeHandling)
							}
							f8elemf7f13f0.SetJsonBody(f8elemf7f13f0f6)
						}
						if f8iter.Statement.SQLIMatchStatement.FieldToMatch.Method != nil {
							f8elemf7f13f0f7 := &svcsdk.Method{}
							f8elemf7f13f0.SetMethod(f8elemf7f13f0f7)
						}
						if f8iter.Statement.SQLIMatchStatement.FieldToMatch.QueryString != nil {
							f8elemf7f13f0f8 := &svcsdk.QueryString{}
							f8elemf7f13f0.SetQueryString(f8elemf7f13f0f8)
						}
						if f8iter.Statement.SQLIMatchStatement.FieldToMatch.SingleHeader != nil {
							f8elemf7f13f0f9 := &svcsdk.SingleHeader{}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.SingleHeader.Name != nil {
								f8elemf7f13f0f9.SetName(*f8iter.Statement.SQLIMatchStatement.FieldToMatch.SingleHeader.Name)
							}
							f8elemf7f13f0.SetSingleHeader(f8elemf7f13f0f9)
						}
						if f8iter.Statement.SQLIMatchStatement.FieldToMatch.SingleQueryArgument != nil {
							f8elemf7f13f0f10 := &svcsdk.SingleQueryArgument{}
							if f8iter.Statement.SQLIMatchStatement.FieldToMatch.SingleQueryArgument.Name != nil {
								f8elemf7f13f0f10.SetName(*f8iter.Statement.SQLIMatchStatement.FieldToMatch.SingleQueryArgument.Name)
							}
							f8elemf7f13f0.SetSingleQueryArgument(f8elemf7f13f0f10)
						}
						if f8iter.Statement.SQLIMatchStatement.FieldToMatch.URIPath != nil {
							f8elemf7f13f0f11 := &svcsdk.UriPath{}
							f8elemf7f13f0.SetUriPath(f8elemf7f13f0f11)
						}
						f8elemf7f13.SetFieldToMatch(f8elemf7f13f0)
					}
					if f8iter.Statement.SQLIMatchStatement.SensitivityLevel != nil {
						f8elemf7f13.SetSensitivityLevel(*f8iter.Statement.SQLIMatchStatement.SensitivityLevel)
					}
					if f8iter.Statement.SQLIMatchStatement.TextTransformations != nil {
						f8elemf7f13f2 := []*svcsdk.TextTransformation{}
						for _, f8elemf7f13f2iter := range f8iter.Statement.SQLIMatchStatement.TextTransformations {
							f8elemf7f13f2elem := &svcsdk.TextTransformation{}
							if f8elemf7f13f2iter.Priority != nil {
								f8elemf7f13f2elem.SetPriority(*f8elemf7f13f2iter.Priority)
							}
							if f8elemf7f13f2iter.Type != nil {
								f8elemf7f13f2elem.SetType(*f8elemf7f13f2iter.Type)
							}
							f8elemf7f13f2 = append(f8elemf7f13f2, f8elemf7f13f2elem)
						}
						f8elemf7f13.SetTextTransformations(f8elemf7f13f2)
					}
					f8elemf7.SetSqliMatchStatement(f8elemf7f13)
				}
				if f8iter.Statement.XSSMatchStatement != nil {
					f8elemf7f14 := &svcsdk.XssMatchStatement{}
					if f8iter.Statement.XSSMatchStatement.FieldToMatch != nil {
						f8elemf7f14f0 := &svcsdk.FieldToMatch{}
						if f8iter.Statement.XSSMatchStatement.FieldToMatch.AllQueryArguments != nil {
							f8elemf7f14f0f0 := &svcsdk.AllQueryArguments{}
							f8elemf7f14f0.SetAllQueryArguments(f8elemf7f14f0f0)
						}
						if f8iter.Statement.XSSMatchStatement.FieldToMatch.Body != nil {
							f8elemf7f14f0f1 := &svcsdk.Body{}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.Body.OversizeHandling != nil {
								f8elemf7f14f0f1.SetOversizeHandling(*f8iter.Statement.XSSMatchStatement.FieldToMatch.Body.OversizeHandling)
							}
							f8elemf7f14f0.SetBody(f8elemf7f14f0f1)
						}
						if f8iter.Statement.XSSMatchStatement.FieldToMatch.Cookies != nil {
							f8elemf7f14f0f2 := &svcsdk.Cookies{}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchPattern != nil {
								f8elemf7f14f0f2f0 := &svcsdk.CookieMatchPattern{}
								if f8iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchPattern.All != nil {
									f8elemf7f14f0f2f0f0 := &svcsdk.All{}
									f8elemf7f14f0f2f0.SetAll(f8elemf7f14f0f2f0f0)
								}
								if f8iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies != nil {
									f8elemf7f14f0f2f0f1 := []*string{}
									for _, f8elemf7f14f0f2f0f1iter := range f8iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies {
										var f8elemf7f14f0f2f0f1elem string
										f8elemf7f14f0f2f0f1elem = *f8elemf7f14f0f2f0f1iter
										f8elemf7f14f0f2f0f1 = append(f8elemf7f14f0f2f0f1, &f8elemf7f14f0f2f0f1elem)
									}
									f8elemf7f14f0f2f0.SetExcludedCookies(f8elemf7f14f0f2f0f1)
								}
								if f8iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies != nil {
									f8elemf7f14f0f2f0f2 := []*string{}
									for _, f8elemf7f14f0f2f0f2iter := range f8iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies {
										var f8elemf7f14f0f2f0f2elem string
										f8elemf7f14f0f2f0f2elem = *f8elemf7f14f0f2f0f2iter
										f8elemf7f14f0f2f0f2 = append(f8elemf7f14f0f2f0f2, &f8elemf7f14f0f2f0f2elem)
									}
									f8elemf7f14f0f2f0.SetIncludedCookies(f8elemf7f14f0f2f0f2)
								}
								f8elemf7f14f0f2.SetMatchPattern(f8elemf7f14f0f2f0)
							}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchScope != nil {
								f8elemf7f14f0f2.SetMatchScope(*f8iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.MatchScope)
							}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.OversizeHandling != nil {
								f8elemf7f14f0f2.SetOversizeHandling(*f8iter.Statement.XSSMatchStatement.FieldToMatch.Cookies.OversizeHandling)
							}
							f8elemf7f14f0.SetCookies(f8elemf7f14f0f2)
						}
						if f8iter.Statement.XSSMatchStatement.FieldToMatch.HeaderOrder != nil {
							f8elemf7f14f0f3 := &svcsdk.HeaderOrder{}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling != nil {
								f8elemf7f14f0f3.SetOversizeHandling(*f8iter.Statement.XSSMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling)
							}
							f8elemf7f14f0.SetHeaderOrder(f8elemf7f14f0f3)
						}
						if f8iter.Statement.XSSMatchStatement.FieldToMatch.Headers != nil {
							f8elemf7f14f0f4 := &svcsdk.Headers{}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchPattern != nil {
								f8elemf7f14f0f4f0 := &svcsdk.HeaderMatchPattern{}
								if f8iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchPattern.All != nil {
									f8elemf7f14f0f4f0f0 := &svcsdk.All{}
									f8elemf7f14f0f4f0.SetAll(f8elemf7f14f0f4f0f0)
								}
								if f8iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders != nil {
									f8elemf7f14f0f4f0f1 := []*string{}
									for _, f8elemf7f14f0f4f0f1iter := range f8iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders {
										var f8elemf7f14f0f4f0f1elem string
										f8elemf7f14f0f4f0f1elem = *f8elemf7f14f0f4f0f1iter
										f8elemf7f14f0f4f0f1 = append(f8elemf7f14f0f4f0f1, &f8elemf7f14f0f4f0f1elem)
									}
									f8elemf7f14f0f4f0.SetExcludedHeaders(f8elemf7f14f0f4f0f1)
								}
								if f8iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders != nil {
									f8elemf7f14f0f4f0f2 := []*string{}
									for _, f8elemf7f14f0f4f0f2iter := range f8iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders {
										var f8elemf7f14f0f4f0f2elem string
										f8elemf7f14f0f4f0f2elem = *f8elemf7f14f0f4f0f2iter
										f8elemf7f14f0f4f0f2 = append(f8elemf7f14f0f4f0f2, &f8elemf7f14f0f4f0f2elem)
									}
									f8elemf7f14f0f4f0.SetIncludedHeaders(f8elemf7f14f0f4f0f2)
								}
								f8elemf7f14f0f4.SetMatchPattern(f8elemf7f14f0f4f0)
							}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchScope != nil {
								f8elemf7f14f0f4.SetMatchScope(*f8iter.Statement.XSSMatchStatement.FieldToMatch.Headers.MatchScope)
							}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.Headers.OversizeHandling != nil {
								f8elemf7f14f0f4.SetOversizeHandling(*f8iter.Statement.XSSMatchStatement.FieldToMatch.Headers.OversizeHandling)
							}
							f8elemf7f14f0.SetHeaders(f8elemf7f14f0f4)
						}
						if f8iter.Statement.XSSMatchStatement.FieldToMatch.JA3Fingerprint != nil {
							f8elemf7f14f0f5 := &svcsdk.JA3Fingerprint{}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior != nil {
								f8elemf7f14f0f5.SetFallbackBehavior(*f8iter.Statement.XSSMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior)
							}
							f8elemf7f14f0.SetJA3Fingerprint(f8elemf7f14f0f5)
						}
						if f8iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody != nil {
							f8elemf7f14f0f6 := &svcsdk.JsonBody{}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior != nil {
								f8elemf7f14f0f6.SetInvalidFallbackBehavior(*f8iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.InvalidFallbackBehavior)
							}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.MatchPattern != nil {
								f8elemf7f14f0f6f1 := &svcsdk.JsonMatchPattern{}
								if f8iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.MatchPattern.All != nil {
									f8elemf7f14f0f6f1f0 := &svcsdk.All{}
									f8elemf7f14f0f6f1.SetAll(f8elemf7f14f0f6f1f0)
								}
								if f8iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths != nil {
									f8elemf7f14f0f6f1f1 := []*string{}
									for _, f8elemf7f14f0f6f1f1iter := range f8iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.MatchPattern.IncludedPaths {
										var f8elemf7f14f0f6f1f1elem string
										f8elemf7f14f0f6f1f1elem = *f8elemf7f14f0f6f1f1iter
										f8elemf7f14f0f6f1f1 = append(f8elemf7f14f0f6f1f1, &f8elemf7f14f0f6f1f1elem)
									}
									f8elemf7f14f0f6f1.SetIncludedPaths(f8elemf7f14f0f6f1f1)
								}
								f8elemf7f14f0f6.SetMatchPattern(f8elemf7f14f0f6f1)
							}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.MatchScope != nil {
								f8elemf7f14f0f6.SetMatchScope(*f8iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.MatchScope)
							}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.OversizeHandling != nil {
								f8elemf7f14f0f6.SetOversizeHandling(*f8iter.Statement.XSSMatchStatement.FieldToMatch.JSONBody.OversizeHandling)
							}
							f8elemf7f14f0.SetJsonBody(f8elemf7f14f0f6)
						}
						if f8iter.Statement.XSSMatchStatement.FieldToMatch.Method != nil {
							f8elemf7f14f0f7 := &svcsdk.Method{}
							f8elemf7f14f0.SetMethod(f8elemf7f14f0f7)
						}
						if f8iter.Statement.XSSMatchStatement.FieldToMatch.QueryString != nil {
							f8elemf7f14f0f8 := &svcsdk.QueryString{}
							f8elemf7f14f0.SetQueryString(f8elemf7f14f0f8)
						}
						if f8iter.Statement.XSSMatchStatement.FieldToMatch.SingleHeader != nil {
							f8elemf7f14f0f9 := &svcsdk.SingleHeader{}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.SingleHeader.Name != nil {
								f8elemf7f14f0f9.SetName(*f8iter.Statement.XSSMatchStatement.FieldToMatch.SingleHeader.Name)
							}
							f8elemf7f14f0.SetSingleHeader(f8elemf7f14f0f9)
						}
						if f8iter.Statement.XSSMatchStatement.FieldToMatch.SingleQueryArgument != nil {
							f8elemf7f14f0f10 := &svcsdk.SingleQueryArgument{}
							if f8iter.Statement.XSSMatchStatement.FieldToMatch.SingleQueryArgument.Name != nil {
								f8elemf7f14f0f10.SetName(*f8iter.Statement.XSSMatchStatement.FieldToMatch.SingleQueryArgument.Name)
							}
							f8elemf7f14f0.SetSingleQueryArgument(f8elemf7f14f0f10)
						}
						if f8iter.Statement.XSSMatchStatement.FieldToMatch.URIPath != nil {
							f8elemf7f14f0f11 := &svcsdk.UriPath{}
							f8elemf7f14f0.SetUriPath(f8elemf7f14f0f11)
						}
						f8elemf7f14.SetFieldToMatch(f8elemf7f14f0)
					}
					if f8iter.Statement.XSSMatchStatement.TextTransformations != nil {
						f8elemf7f14f1 := []*svcsdk.TextTransformation{}
						for _, f8elemf7f14f1iter := range f8iter.Statement.XSSMatchStatement.TextTransformations {
							f8elemf7f14f1elem := &svcsdk.TextTransformation{}
							if f8elemf7f14f1iter.Priority != nil {
								f8elemf7f14f1elem.SetPriority(*f8elemf7f14f1iter.Priority)
							}
							if f8elemf7f14f1iter.Type != nil {
								f8elemf7f14f1elem.SetType(*f8elemf7f14f1iter.Type)
							}
							f8elemf7f14f1 = append(f8elemf7f14f1, f8elemf7f14f1elem)
						}
						f8elemf7f14.SetTextTransformations(f8elemf7f14f1)
					}
					f8elemf7.SetXssMatchStatement(f8elemf7f14)
				}
				f8elem.SetStatement(f8elemf7)
			}
			if f8iter.VisibilityConfig != nil {
				f8elemf8 := &svcsdk.VisibilityConfig{}
				if f8iter.VisibilityConfig.CloudWatchMetricsEnabled != nil {
					f8elemf8.SetCloudWatchMetricsEnabled(*f8iter.VisibilityConfig.CloudWatchMetricsEnabled)
				}
				if f8iter.VisibilityConfig.MetricName != nil {
					f8elemf8.SetMetricName(*f8iter.VisibilityConfig.MetricName)
				}
				if f8iter.VisibilityConfig.SampledRequestsEnabled != nil {
					f8elemf8.SetSampledRequestsEnabled(*f8iter.VisibilityConfig.SampledRequestsEnabled)
				}
				f8elem.SetVisibilityConfig(f8elemf8)
			}
			f8 = append(f8, f8elem)
		}
		res.SetRules(f8)
	}
	if cr.Spec.ForProvider.Scope != nil {
		res.SetScope(*cr.Spec.ForProvider.Scope)
	}
	if cr.Spec.ForProvider.TokenDomains != nil {
		f10 := []*string{}
		for _, f10iter := range cr.Spec.ForProvider.TokenDomains {
			var f10elem string
			f10elem = *f10iter
			f10 = append(f10, &f10elem)
		}
		res.SetTokenDomains(f10)
	}
	if cr.Spec.ForProvider.VisibilityConfig != nil {
		f11 := &svcsdk.VisibilityConfig{}
		if cr.Spec.ForProvider.VisibilityConfig.CloudWatchMetricsEnabled != nil {
			f11.SetCloudWatchMetricsEnabled(*cr.Spec.ForProvider.VisibilityConfig.CloudWatchMetricsEnabled)
		}
		if cr.Spec.ForProvider.VisibilityConfig.MetricName != nil {
			f11.SetMetricName(*cr.Spec.ForProvider.VisibilityConfig.MetricName)
		}
		if cr.Spec.ForProvider.VisibilityConfig.SampledRequestsEnabled != nil {
			f11.SetSampledRequestsEnabled(*cr.Spec.ForProvider.VisibilityConfig.SampledRequestsEnabled)
		}
		res.SetVisibilityConfig(f11)
	}

	return res
}

// GenerateDeleteWebACLInput returns a deletion input.
func GenerateDeleteWebACLInput(cr *svcapitypes.WebACL) *svcsdk.DeleteWebACLInput {
	res := &svcsdk.DeleteWebACLInput{}

	if cr.Status.AtProvider.ID != nil {
		res.SetId(*cr.Status.AtProvider.ID)
	}
	if cr.Status.AtProvider.LockToken != nil {
		res.SetLockToken(*cr.Status.AtProvider.LockToken)
	}
	if cr.Spec.ForProvider.Scope != nil {
		res.SetScope(*cr.Spec.ForProvider.Scope)
	}

	return res
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "ResourceNotFoundException"
}