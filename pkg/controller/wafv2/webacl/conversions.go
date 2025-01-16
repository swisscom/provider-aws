//package webacl
//
//import (
//	svcsdk "github.com/aws/aws-sdk-go/service/wafv2"
//
//	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/wafv2/manualv1alpha1"
//)
//
//func setExternalRules(respRules []*svcsdk.Rule, target *svcapitypes.WebACLParameters) error {
//	var extRules []*svcapitypes.Rule
//	for _, v := range respRules {
//		extRule := &svcapitypes.Rule{}
//		extRuleStatement := &svcapitypes.Statement{}
//		if v.Name != nil {
//			extRule.Name = v.Name
//		}
//		if v.Action != nil {
//			var extAllowInsertHeaders []*svcapitypes.CustomHTTPHeader
//			var extBlockResponseHeaders []*svcapitypes.CustomHTTPHeader
//			var extCaptchaInsertHeaders []*svcapitypes.CustomHTTPHeader
//			var extChallengeInsertHeaders []*svcapitypes.CustomHTTPHeader
//			var extCountInspectionLimit []*svcapitypes.CustomHTTPHeader
//			for _, v := range v.Action.Allow.CustomRequestHandling.InsertHeaders {
//				extAllowInsertHeaders = append(extAllowInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
//			}
//			for _, v := range v.Action.Block.CustomResponse.ResponseHeaders {
//				extBlockResponseHeaders = append(extBlockResponseHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
//			}
//			for _, v := range v.Action.Captcha.CustomRequestHandling.InsertHeaders {
//				extCaptchaInsertHeaders = append(extCaptchaInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
//			}
//			for _, v := range v.Action.Challenge.CustomRequestHandling.InsertHeaders {
//				extChallengeInsertHeaders = append(extChallengeInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
//			}
//			extRule.Action = &svcapitypes.RuleAction{
//				Allow: &svcapitypes.AllowAction{
//					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
//						InsertHeaders: extAllowInsertHeaders,
//					},
//				},
//				Block: &svcapitypes.BlockAction{
//					CustomResponse: &svcapitypes.CustomResponse{
//						CustomResponseBodyKey: v.Action.Block.CustomResponse.CustomResponseBodyKey,
//						ResponseCode:          v.Action.Block.CustomResponse.ResponseCode,
//						ResponseHeaders:       extBlockResponseHeaders,
//					},
//				},
//				Captcha: &svcapitypes.CaptchaAction{
//					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
//						InsertHeaders: extCaptchaInsertHeaders,
//					},
//				},
//				Challenge: &svcapitypes.ChallengeAction{
//					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
//						InsertHeaders: extChallengeInsertHeaders,
//					},
//				},
//				Count: &svcapitypes.CountAction{
//					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
//						InsertHeaders: extCountInspectionLimit,
//					},
//				},
//			}
//
//		}
//		if v.OverrideAction != nil {
//			extOverrideAction := &svcapitypes.OverrideAction{}
//			var extCountInsertHeaders []*svcapitypes.CustomHTTPHeader
//			for _, v := range v.OverrideAction.Count.CustomRequestHandling.InsertHeaders {
//				extCountInsertHeaders = append(extCountInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
//			}
//			if v.OverrideAction.Count != nil {
//				extOverrideAction.Count = &svcapitypes.CountAction{
//					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
//						InsertHeaders: extCountInsertHeaders,
//					},
//				}
//			}
//			if v.OverrideAction.None != nil {
//				extOverrideAction.None = map[string]*string{}
//			}
//			extRule.OverrideAction = extOverrideAction
//		}
//		if v.CaptchaConfig != nil {
//			extRule.CaptchaConfig = &svcapitypes.CaptchaConfig{ImmunityTimeProperty: &svcapitypes.ImmunityTimeProperty{
//				ImmunityTime: v.CaptchaConfig.ImmunityTimeProperty.ImmunityTime,
//			}}
//		}
//		if v.ChallengeConfig != nil {
//			extRule.ChallengeConfig = &svcapitypes.ChallengeConfig{ImmunityTimeProperty: &svcapitypes.ImmunityTimeProperty{
//				ImmunityTime: v.ChallengeConfig.ImmunityTimeProperty.ImmunityTime,
//			}}
//		}
//		if v.Priority != nil {
//			extRule.Priority = v.Priority
//		}
//		if v.RuleLabels != nil {
//			var extRuleLabels []*svcapitypes.Label
//			for _, v := range v.RuleLabels {
//				extRuleLabels = append(extRuleLabels, &svcapitypes.Label{Name: v.Name})
//			}
//			extRule.RuleLabels = extRuleLabels
//		}
//		if v.VisibilityConfig != nil {
//			extRule.VisibilityConfig = &svcapitypes.VisibilityConfig{CloudWatchMetricsEnabled: v.VisibilityConfig.CloudWatchMetricsEnabled, MetricName: v.VisibilityConfig.MetricName, SampledRequestsEnabled: v.VisibilityConfig.SampledRequestsEnabled}
//		}
//		if v.Statement != nil {
//			if v.Statement.ByteMatchStatement != nil {
//				setRuleByteMatchStatement(v.Statement.ByteMatchStatement, extRuleStatement)
//			}
//			if v.Statement.ManagedRuleGroupStatement != nil {
//				err := setRuleManagedRuleGroupStatement(v.Statement.ManagedRuleGroupStatement, extRuleStatement)
//				if err != nil {
//					return err
//				}
//			}
//			if v.Statement.RateBasedStatement != nil {
//				err := setRuleRateBasedStatement(v.Statement.RateBasedStatement, extRuleStatement)
//				if err != nil {
//					return err
//				}
//			}
//			if v.Statement.OrStatement != nil {
//				jsonString, err := statementToString[svcsdk.OrStatement](*v.Statement.OrStatement)
//				if err != nil {
//					return err
//				}
//				extRule.Statement.OrStatement = jsonString
//			}
//			if v.Statement.AndStatement != nil {
//				jsonString, err := statementToString[svcsdk.AndStatement](*v.Statement.AndStatement)
//				if err != nil {
//					return err
//				}
//				extRule.Statement.AndStatement = jsonString
//			}
//			if v.Statement.NotStatement != nil {
//				jsonString, err := statementToString[svcsdk.NotStatement](*v.Statement.NotStatement)
//				if err != nil {
//					return err
//				}
//				extRule.Statement.NotStatement = jsonString
//			}
//			if v.Statement.GeoMatchStatement != nil {
//				extRuleStatement.GeoMatchStatement = &svcapitypes.GeoMatchStatement{
//					CountryCodes: v.Statement.GeoMatchStatement.CountryCodes,
//					ForwardedIPConfig: &svcapitypes.ForwardedIPConfig{
//						HeaderName:       v.Statement.GeoMatchStatement.ForwardedIPConfig.HeaderName,
//						FallbackBehavior: v.Statement.GeoMatchStatement.ForwardedIPConfig.FallbackBehavior,
//					},
//				}
//			}
//			if v.Statement.IPSetReferenceStatement != nil {
//				extRuleStatement.IPSetReferenceStatement = &svcapitypes.IPSetReferenceStatement{
//					ARN: v.Statement.IPSetReferenceStatement.ARN,
//					IPSetForwardedIPConfig: &svcapitypes.IPSetForwardedIPConfig{
//						HeaderName:       v.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.HeaderName,
//						FallbackBehavior: v.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.FallbackBehavior,
//					},
//				}
//			}
//			if v.Statement.LabelMatchStatement != nil {
//				extRuleStatement.LabelMatchStatement = &svcapitypes.LabelMatchStatement{
//					Key:   v.Statement.LabelMatchStatement.Key,
//					Scope: v.Statement.LabelMatchStatement.Scope,
//				}
//			}
//			if v.Statement.RegexMatchStatement != nil {
//				setRuleRegexMatchStatement(v.Statement.RegexMatchStatement, extRuleStatement)
//			}
//			if v.Statement.RegexPatternSetReferenceStatement != nil {
//				setRuleRegexPatternSetReferenceStatement(v.Statement.RegexPatternSetReferenceStatement, extRuleStatement)
//			}
//			if v.Statement.RuleGroupReferenceStatement != nil {
//				setRuleRuleGroupReferenceStatement(v.Statement.RuleGroupReferenceStatement, extRuleStatement)
//			}
//			if v.Statement.SizeConstraintStatement != nil {
//				setRuleSizeConstraintStatement(v.Statement.SizeConstraintStatement, extRuleStatement)
//			}
//			if v.Statement.SqliMatchStatement != nil {
//				setRuleSQLIMatchStatement(extRuleStatement, v)
//			}
//			if v.Statement.XssMatchStatement != nil {
//				extRuleStatement.XSSMatchStatement = &svcapitypes.XSSMatchStatement{
//					FieldToMatch:        setFieldToMatch(v.Statement.XssMatchStatement.FieldToMatch),
//					TextTransformations: setTextTransformations(v.Statement.XssMatchStatement.TextTransformations),
//				}
//			}
//			extRule.Statement = extRuleStatement
//		}
//		extRules = append(extRules, extRule)
//		target.Rules = extRules
//	}
//	return nil
//}
//
//func setExcludeRules(respExcludeRules []*svcsdk.ExcludedRule) []*svcapitypes.ExcludedRule {
//	var extRules []*svcapitypes.ExcludedRule
//	for _, v := range respExcludeRules {
//		extRules = append(extRules, &svcapitypes.ExcludedRule{Name: v.Name})
//	}
//	return extRules
//}
//
//func setFieldToMatch(respFieldToMatch *svcsdk.FieldToMatch) *svcapitypes.FieldToMatch {
//	extCookiesMatchPattern := &svcapitypes.CookieMatchPattern{
//		ExcludedCookies: respFieldToMatch.Cookies.MatchPattern.ExcludedCookies,
//		IncludedCookies: respFieldToMatch.Cookies.MatchPattern.IncludedCookies,
//	}
//	if respFieldToMatch.Cookies.MatchPattern.All != nil {
//		extCookiesMatchPattern.All = map[string]*string{}
//	}
//	extHeadersMatchPattern := &svcapitypes.HeaderMatchPattern{
//		ExcludedHeaders: respFieldToMatch.Headers.MatchPattern.ExcludedHeaders,
//		IncludedHeaders: respFieldToMatch.Headers.MatchPattern.IncludedHeaders,
//	}
//	extFieldToMatchJsonBodyMatchPattern := &svcapitypes.JSONMatchPattern{
//		IncludedPaths: respFieldToMatch.JsonBody.MatchPattern.IncludedPaths,
//	}
//	if respFieldToMatch.JsonBody.MatchPattern.All != nil {
//		extFieldToMatchJsonBodyMatchPattern.All = map[string]*string{}
//	}
//	extFieldToMatch := &svcapitypes.FieldToMatch{
//		Body: &svcapitypes.Body{OversizeHandling: respFieldToMatch.Body.OversizeHandling},
//		Cookies: &svcapitypes.Cookies{
//			MatchPattern:     extCookiesMatchPattern,
//			MatchScope:       respFieldToMatch.Cookies.MatchScope,
//			OversizeHandling: respFieldToMatch.Cookies.OversizeHandling,
//		},
//		HeaderOrder: &svcapitypes.HeaderOrder{OversizeHandling: respFieldToMatch.HeaderOrder.OversizeHandling},
//		Headers: &svcapitypes.Headers{
//			MatchPattern:     extHeadersMatchPattern,
//			MatchScope:       respFieldToMatch.Cookies.MatchScope,
//			OversizeHandling: respFieldToMatch.Cookies.OversizeHandling,
//		},
//		JA3Fingerprint: &svcapitypes.JA3Fingerprint{FallbackBehavior: respFieldToMatch.JA3Fingerprint.FallbackBehavior},
//		JSONBody: &svcapitypes.JSONBody{
//			InvalidFallbackBehavior: respFieldToMatch.JsonBody.InvalidFallbackBehavior,
//			MatchPattern:            extFieldToMatchJsonBodyMatchPattern,
//			MatchScope:              respFieldToMatch.JsonBody.MatchScope,
//			OversizeHandling:        respFieldToMatch.JsonBody.OversizeHandling,
//		},
//		SingleHeader: &svcapitypes.SingleHeader{
//			Name: respFieldToMatch.SingleHeader.Name,
//		},
//		SingleQueryArgument: &svcapitypes.SingleQueryArgument{
//			Name: respFieldToMatch.SingleQueryArgument.Name,
//		},
//	}
//	if respFieldToMatch.AllQueryArguments != nil {
//		extFieldToMatch.AllQueryArguments = map[string]*string{}
//	}
//	if respFieldToMatch.Method != nil {
//		extFieldToMatch.Method = map[string]*string{}
//	}
//	if respFieldToMatch.QueryString != nil {
//		extFieldToMatch.QueryString = map[string]*string{}
//	}
//	if respFieldToMatch.UriPath != nil {
//		extFieldToMatch.URIPath = map[string]*string{}
//	}
//	return extFieldToMatch
//}
//
//func setTextTransformations(respTextTransformations []*svcsdk.TextTransformation) []*svcapitypes.TextTransformation {
//	var extTextTransformations []*svcapitypes.TextTransformation
//	for _, v := range respTextTransformations {
//		extTextTransformations = append(extTextTransformations, &svcapitypes.TextTransformation{Priority: v.Priority, Type: v.Type})
//	}
//	return extTextTransformations
//}
//
//func setRuleActionOverrides(respRuleActionOverrides []*svcsdk.RuleActionOverride) []*svcapitypes.RuleActionOverride {
//	var extRuleActionOverrides []*svcapitypes.RuleActionOverride
//	for _, v := range respRuleActionOverrides {
//		var extAllowInsertHeaders []*svcapitypes.CustomHTTPHeader
//		for _, v := range v.ActionToUse.Allow.CustomRequestHandling.InsertHeaders {
//			extAllowInsertHeaders = append(extAllowInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
//		}
//		var extBlockResponseHeaders []*svcapitypes.CustomHTTPHeader
//		for _, v := range v.ActionToUse.Block.CustomResponse.ResponseHeaders {
//			extBlockResponseHeaders = append(extBlockResponseHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
//		}
//		var extCaptchaInsertHeaders []*svcapitypes.CustomHTTPHeader
//		for _, v := range v.ActionToUse.Captcha.CustomRequestHandling.InsertHeaders {
//			extCaptchaInsertHeaders = append(extCaptchaInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
//		}
//		var extChallengeInsertHeaders []*svcapitypes.CustomHTTPHeader
//		for _, v := range v.ActionToUse.Challenge.CustomRequestHandling.InsertHeaders {
//			extChallengeInsertHeaders = append(extChallengeInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
//		}
//		var extCountInsertHeaders []*svcapitypes.CustomHTTPHeader
//		for _, v := range v.ActionToUse.Count.CustomRequestHandling.InsertHeaders {
//			extCountInsertHeaders = append(extCountInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
//		}
//		extRuleActionOverrides = append(extRuleActionOverrides, &svcapitypes.RuleActionOverride{
//			ActionToUse: &svcapitypes.RuleAction{
//				Allow: &svcapitypes.AllowAction{
//					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
//						InsertHeaders: extAllowInsertHeaders,
//					},
//				},
//				Block: &svcapitypes.BlockAction{
//					CustomResponse: &svcapitypes.CustomResponse{
//						CustomResponseBodyKey: v.ActionToUse.Block.CustomResponse.CustomResponseBodyKey,
//						ResponseCode:          v.ActionToUse.Block.CustomResponse.ResponseCode,
//						ResponseHeaders:       extBlockResponseHeaders,
//					},
//				},
//				Captcha: &svcapitypes.CaptchaAction{
//					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
//						InsertHeaders: extCaptchaInsertHeaders,
//					},
//				},
//				Challenge: &svcapitypes.ChallengeAction{
//					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
//						InsertHeaders: extChallengeInsertHeaders,
//					},
//				},
//				Count: &svcapitypes.CountAction{
//					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
//						InsertHeaders: extCountInsertHeaders,
//					},
//				},
//			},
//			Name: v.Name,
//		})
//	}
//	return extRuleActionOverrides
//}
//
//func setRuleSQLIMatchStatement(respRuleStatement *svcsdk.SqliMatchStatement, extRuleStatement *svcapitypes.Statement) {
//	extRuleStatement.SQLIMatchStatement = &svcapitypes.SQLIMatchStatement{
//		FieldToMatch:        setFieldToMatch(respRuleStatement.FieldToMatch),
//		SensitivityLevel:    respRuleStatement.SensitivityLevel,
//		TextTransformations: setTextTransformations(respRuleStatement.TextTransformations),
//	}
//}
//
//func setRuleSizeConstraintStatement(respRuleStatement *svcsdk.SizeConstraintStatement, extRuleStatement *svcapitypes.Statement) {
//	extRuleStatement.SizeConstraintStatement = &svcapitypes.SizeConstraintStatement{
//		ComparisonOperator:  respRuleStatement.ComparisonOperator,
//		FieldToMatch:        setFieldToMatch(respRuleStatement.FieldToMatch),
//		Size:                respRuleStatement.Size,
//		TextTransformations: setTextTransformations(respRuleStatement.TextTransformations),
//	}
//}
//
//func setRuleRuleGroupReferenceStatement(respRuleStatement *svcsdk.RuleGroupReferenceStatement, extRuleStatement *svcapitypes.Statement) {
//	extRuleGroupReferenceStatement := &svcapitypes.RuleGroupReferenceStatement{
//		ARN:                 respRuleStatement.ARN,
//		ExcludedRules:       setExcludeRules(respRuleStatement.ExcludedRules),
//		RuleActionOverrides: setRuleActionOverrides(respRuleStatement.RuleActionOverrides),
//	}
//	extRuleStatement.RuleGroupReferenceStatement = extRuleGroupReferenceStatement
//}
//
//func setRuleRegexPatternSetReferenceStatement(respRuleStatement *svcsdk.RegexPatternSetReferenceStatement, extRuleStatement *svcapitypes.Statement) {
//	extRegexPatternSetReferenceStatement := &svcapitypes.RegexPatternSetReferenceStatement{
//		ARN:                 respRuleStatement.ARN,
//		FieldToMatch:        setFieldToMatch(respRuleStatement.FieldToMatch),
//		TextTransformations: setTextTransformations(respRuleStatement.TextTransformations),
//	}
//	extRuleStatement.RegexPatternSetReferenceStatement = extRegexPatternSetReferenceStatement
//}
//
//func setRuleRegexMatchStatement(respRuleStatement *svcsdk.RegexMatchStatement, extRuleStatement *svcapitypes.Statement) {
//	extRegexMatchStatement := &svcapitypes.RegexMatchStatement{
//		FieldToMatch:        setFieldToMatch(respRuleStatement.FieldToMatch),
//		RegexString:         respRuleStatement.RegexString,
//		TextTransformations: setTextTransformations(respRuleStatement.TextTransformations),
//	}
//	extRuleStatement.RegexMatchStatement = extRegexMatchStatement
//}
//
//func setRuleByteMatchStatement(respRuleStatement *svcsdk.ByteMatchStatement, extRuleStatement *svcapitypes.Statement) {
//	extRuleStatement.ByteMatchStatement = &svcapitypes.ByteMatchStatement{
//		PositionalConstraint: respRuleStatement.PositionalConstraint,
//		SearchString:         respRuleStatement.SearchString,
//		TextTransformations:  setTextTransformations(respRuleStatement.TextTransformations),
//		FieldToMatch:         setFieldToMatch(respRuleStatement.FieldToMatch),
//	}
//}
//
//func setRuleRateBasedStatement(respRuleStatement *svcsdk.RateBasedStatement, extRuleStatement *svcapitypes.Statement) error {
//	extForwardedIPConfig := &svcapitypes.ForwardedIPConfig{
//		HeaderName:       respRuleStatement.ForwardedIPConfig.HeaderName,
//		FallbackBehavior: respRuleStatement.ForwardedIPConfig.FallbackBehavior,
//	}
//	var extCustomKeys []*svcapitypes.RateBasedStatementCustomKey
//	for _, v := range respRuleStatement.CustomKeys {
//		extCustomKey := &svcapitypes.RateBasedStatementCustomKey{
//			Cookie:         &svcapitypes.RateLimitCookie{Name: v.Cookie.Name, TextTransformations: setTextTransformations(v.Cookie.TextTransformations)},
//			Header:         &svcapitypes.RateLimitHeader{Name: v.Header.Name, TextTransformations: setTextTransformations(v.Header.TextTransformations)},
//			LabelNamespace: &svcapitypes.RateLimitLabelNamespace{Namespace: v.LabelNamespace.Namespace},
//			QueryArgument:  &svcapitypes.RateLimitQueryArgument{Name: v.QueryArgument.Name, TextTransformations: setTextTransformations(v.QueryArgument.TextTransformations)},
//			QueryString:    &svcapitypes.RateLimitQueryString{TextTransformations: setTextTransformations(v.QueryString.TextTransformations)},
//			URIPath:        &svcapitypes.RateLimitURIPath{TextTransformations: setTextTransformations(v.UriPath.TextTransformations)},
//		}
//		if v.ForwardedIP != nil {
//			extCustomKey.ForwardedIP = map[string]*string{}
//		}
//		if v.HTTPMethod != nil {
//			extCustomKey.HTTPMethod = map[string]*string{}
//		}
//		if v.IP != nil {
//			extCustomKey.IP = map[string]*string{}
//		}
//		extCustomKeys = append(extCustomKeys, extCustomKey)
//	}
//	extRateBasedStatement := &svcapitypes.RateBasedStatement{
//		AggregateKeyType:  respRuleStatement.AggregateKeyType,
//		CustomKeys:        extCustomKeys,
//		ForwardedIPConfig: extForwardedIPConfig,
//		Limit:             respRuleStatement.Limit,
//	}
//	if respRuleStatement.ScopeDownStatement != nil {
//		jsonString, err := statementToString[svcsdk.Statement](*respRuleStatement.ScopeDownStatement)
//		if err != nil {
//			return err
//		}
//		extRateBasedStatement.ScopeDownStatement = jsonString
//	}
//	extRuleStatement.RateBasedStatement = extRateBasedStatement
//	return nil
//}
//
//func setRuleManagedRuleGroupStatement(respRuleStatement *svcsdk.ManagedRuleGroupStatement, extRuleStatement *svcapitypes.Statement) error {
//	var extExcludedRules []*svcapitypes.ExcludedRule
//	var extManagedRuleGroupConfigs []*svcapitypes.ManagedRuleGroupConfig
//	for _, v := range respRuleStatement.ExcludedRules {
//		extExcludedRules = append(extExcludedRules, &svcapitypes.ExcludedRule{Name: v.Name})
//	}
//	for _, v := range respRuleStatement.ManagedRuleGroupConfigs {
//		var extAddressFields []*svcapitypes.AddressField
//		var extPhoneNumberFields []*svcapitypes.PhoneNumberField
//		for _, v := range v.AWSManagedRulesACFPRuleSet.RequestInspection.AddressFields {
//			extAddressFields = append(extAddressFields, &svcapitypes.AddressField{Identifier: v.Identifier})
//		}
//		for _, v := range v.AWSManagedRulesACFPRuleSet.RequestInspection.PhoneNumberFields {
//			extPhoneNumberFields = append(extPhoneNumberFields, &svcapitypes.PhoneNumberField{Identifier: v.Identifier})
//		}
//		extRequestInspection := &svcapitypes.RequestInspectionACFP{
//			AddressFields: extAddressFields,
//			EmailField: &svcapitypes.EmailField{
//				Identifier: v.AWSManagedRulesACFPRuleSet.RequestInspection.EmailField.Identifier,
//			},
//			PasswordField: &svcapitypes.PasswordField{
//				Identifier: v.AWSManagedRulesACFPRuleSet.RequestInspection.PasswordField.Identifier,
//			},
//			PayloadType:       v.AWSManagedRulesACFPRuleSet.RequestInspection.PayloadType,
//			PhoneNumberFields: extPhoneNumberFields,
//			UsernameField: &svcapitypes.UsernameField{
//				Identifier: v.AWSManagedRulesACFPRuleSet.RequestInspection.UsernameField.Identifier,
//			},
//		}
//		extResponseInspectionBodyContains := &svcapitypes.ResponseInspectionBodyContains{
//			FailureStrings: make([]*string, 0),
//			SuccessStrings: make([]*string, 0),
//		}
//		for _, v := range v.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains.FailureStrings {
//			extResponseInspectionBodyContains.FailureStrings = append(extResponseInspectionBodyContains.FailureStrings, v)
//		}
//		for _, v := range v.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains.SuccessStrings {
//			extResponseInspectionBodyContains.SuccessStrings = append(extResponseInspectionBodyContains.SuccessStrings, v)
//		}
//
//		extResponseInspection := &svcapitypes.ResponseInspection{
//			BodyContains: extResponseInspectionBodyContains,
//			Header: &svcapitypes.ResponseInspectionHeader{
//				Name:          v.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.Name,
//				FailureValues: v.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.FailureValues,
//				SuccessValues: v.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.SuccessValues,
//			},
//			JSON: &svcapitypes.ResponseInspectionJSON{
//				FailureValues: v.AWSManagedRulesACFPRuleSet.ResponseInspection.Json.FailureValues,
//				Identifier:    v.AWSManagedRulesACFPRuleSet.ResponseInspection.Json.Identifier,
//				SuccessValues: v.AWSManagedRulesACFPRuleSet.ResponseInspection.Json.SuccessValues,
//			},
//		}
//
//		extManagedRuleGroupConfigs = append(extManagedRuleGroupConfigs,
//			&svcapitypes.ManagedRuleGroupConfig{
//				AWSManagedRulesACFPRuleSet: &svcapitypes.AWSManagedRulesACFPRuleSet{
//					CreationPath:         v.AWSManagedRulesACFPRuleSet.CreationPath,
//					EnableRegexInPath:    v.AWSManagedRulesACFPRuleSet.EnableRegexInPath,
//					RegistrationPagePath: v.AWSManagedRulesACFPRuleSet.RegistrationPagePath,
//					RequestInspection:    extRequestInspection,
//					ResponseInspection:   extResponseInspection,
//				},
//			},
//		)
//
//	}
//	extRuleStatement.ManagedRuleGroupStatement = &svcapitypes.ManagedRuleGroupStatement{
//		ExcludedRules:           extExcludedRules,
//		ManagedRuleGroupConfigs: extManagedRuleGroupConfigs,
//		Name:                    respRuleStatement.Name,
//		RuleActionOverrides:     setRuleActionOverrides(respRuleStatement.RuleActionOverrides),
//		VendorName:              respRuleStatement.VendorName,
//		Version:                 respRuleStatement.Version,
//	}
//	if respRuleStatement.ScopeDownStatement != nil {
//		jsonString, err := statementToString[svcsdk.Statement](*respRuleStatement.ScopeDownStatement)
//		if err != nil {
//			return err
//		}
//		extRuleStatement.ManagedRuleGroupStatement.ScopeDownStatement = jsonString
//	}
//	return nil
//}