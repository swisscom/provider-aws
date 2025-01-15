package webacl

import (
	svcsdk "github.com/aws/aws-sdk-go/service/wafv2"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/wafv2/manualv1alpha1"
)

func setExternalRules(respRules []*svcsdk.Rule, target *svcapitypes.WebACLParameters) error {
	var extRules []*svcapitypes.Rule
	for _, v := range respRules {
		extRule := &svcapitypes.Rule{}
		extRuleStatement := &svcapitypes.Statement{}
		if v.Name != nil {
			extRule.Name = v.Name
		}
		if v.Action != nil {
			var extAllowInsertHeaders []*svcapitypes.CustomHTTPHeader
			var extBlockResponseHeaders []*svcapitypes.CustomHTTPHeader
			var extCaptchaInsertHeaders []*svcapitypes.CustomHTTPHeader
			var extChallengeInsertHeaders []*svcapitypes.CustomHTTPHeader
			var extCountInspectionLimit []*svcapitypes.CustomHTTPHeader
			for _, v := range v.Action.Allow.CustomRequestHandling.InsertHeaders {
				extAllowInsertHeaders = append(extAllowInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
			}
			for _, v := range v.Action.Block.CustomResponse.ResponseHeaders {
				extBlockResponseHeaders = append(extBlockResponseHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
			}
			for _, v := range v.Action.Captcha.CustomRequestHandling.InsertHeaders {
				extCaptchaInsertHeaders = append(extCaptchaInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
			}
			for _, v := range v.Action.Challenge.CustomRequestHandling.InsertHeaders {
				extChallengeInsertHeaders = append(extChallengeInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
			}
			extRule.Action = &svcapitypes.RuleAction{
				Allow: &svcapitypes.AllowAction{
					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
						InsertHeaders: extAllowInsertHeaders,
					},
				},
				Block: &svcapitypes.BlockAction{
					CustomResponse: &svcapitypes.CustomResponse{
						CustomResponseBodyKey: v.Action.Block.CustomResponse.CustomResponseBodyKey,
						ResponseCode:          v.Action.Block.CustomResponse.ResponseCode,
						ResponseHeaders:       extBlockResponseHeaders,
					},
				},
				Captcha: &svcapitypes.CaptchaAction{
					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
						InsertHeaders: extCaptchaInsertHeaders,
					},
				},
				Challenge: &svcapitypes.ChallengeAction{
					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
						InsertHeaders: extChallengeInsertHeaders,
					},
				},
				Count: &svcapitypes.CountAction{
					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
						InsertHeaders: extCountInspectionLimit,
					},
				},
			}

		}
		if v.OverrideAction != nil {
			extOverrideAction := &svcapitypes.OverrideAction{}
			var extCountInsertHeaders []*svcapitypes.CustomHTTPHeader
			for _, v := range v.OverrideAction.Count.CustomRequestHandling.InsertHeaders {
				extCountInsertHeaders = append(extCountInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
			}
			if v.OverrideAction.Count != nil {
				extOverrideAction.Count = &svcapitypes.CountAction{
					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
						InsertHeaders: extCountInsertHeaders,
					},
				}
			}
			if v.OverrideAction.None != nil {
				extOverrideAction.None = map[string]*string{}
			}
			extRule.OverrideAction = extOverrideAction
		}
		if v.CaptchaConfig != nil {
			extRule.CaptchaConfig = &svcapitypes.CaptchaConfig{ImmunityTimeProperty: &svcapitypes.ImmunityTimeProperty{
				ImmunityTime: v.CaptchaConfig.ImmunityTimeProperty.ImmunityTime,
			}}
		}
		if v.ChallengeConfig != nil {
			extRule.ChallengeConfig = &svcapitypes.ChallengeConfig{ImmunityTimeProperty: &svcapitypes.ImmunityTimeProperty{
				ImmunityTime: v.ChallengeConfig.ImmunityTimeProperty.ImmunityTime,
			}}
		}
		if v.Priority != nil {
			extRule.Priority = v.Priority
		}
		if v.RuleLabels != nil {
			var extRuleLabels []*svcapitypes.Label
			for _, v := range v.RuleLabels {
				extRuleLabels = append(extRuleLabels, &svcapitypes.Label{Name: v.Name})
			}
			extRule.RuleLabels = extRuleLabels
		}
		if v.VisibilityConfig != nil {
			extRule.VisibilityConfig = &svcapitypes.VisibilityConfig{CloudWatchMetricsEnabled: v.VisibilityConfig.CloudWatchMetricsEnabled, MetricName: v.VisibilityConfig.MetricName, SampledRequestsEnabled: v.VisibilityConfig.SampledRequestsEnabled}
		}
		if v.Statement != nil {
			if v.Statement.ByteMatchStatement != nil {
				setRuleByteMatchStatement(v.Statement.ByteMatchStatement, extRuleStatement)
			}
			if v.Statement.OrStatement != nil {
				jsonString, err := statementToString[svcsdk.OrStatement](*v.Statement.OrStatement)
				if err != nil {
					return err
				}
				extRule.Statement.OrStatement = jsonString
			}
			if v.Statement.AndStatement != nil {
				jsonString, err := statementToString[svcsdk.AndStatement](*v.Statement.AndStatement)
				if err != nil {
					return err
				}
				extRule.Statement.AndStatement = jsonString
			}
			if v.Statement.NotStatement != nil {
				jsonString, err := statementToString[svcsdk.NotStatement](*v.Statement.NotStatement)
				if err != nil {
					return err
				}
				extRule.Statement.NotStatement = jsonString
			}
			if v.Statement.ManagedRuleGroupStatement != nil {
				err := setRuleManagedRuleGroupStatement(v.Statement.ManagedRuleGroupStatement, extRuleStatement)
				if err != nil {
					return err
				}
			}
			if v.Statement.RateBasedStatement != nil {
				err := setRuleRateBasedStatement(v.Statement.RateBasedStatement, extRuleStatement)
				if err != nil {
					return err
				}
			}
			if v.Statement.ByteMatchStatement != nil {
				var extTextTransformations []*svcapitypes.TextTransformation
				for _, v := range v.Statement.ByteMatchStatement.TextTransformations {
					extTextTransformations = append(extTextTransformations, &svcapitypes.TextTransformation{Priority: v.Priority, Type: v.Type})
				}
				extCookiesMatchPattern := &svcapitypes.CookieMatchPattern{
					ExcludedCookies: v.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern.ExcludedCookies,
					IncludedCookies: v.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern.IncludedCookies,
				}
				if v.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchPattern.All != nil {
					extCookiesMatchPattern.All = map[string]*string{}
				}
				extHeadersMatchPattern := &svcapitypes.HeaderMatchPattern{
					ExcludedHeaders: v.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern.ExcludedHeaders,
					IncludedHeaders: v.Statement.ByteMatchStatement.FieldToMatch.Headers.MatchPattern.IncludedHeaders,
				}
				extFieldToMatchJsonBodyMatchPattern := &svcapitypes.JSONMatchPattern{
					IncludedPaths: v.Statement.ByteMatchStatement.FieldToMatch.JsonBody.MatchPattern.IncludedPaths,
				}
				if v.Statement.ByteMatchStatement.FieldToMatch.JsonBody.MatchPattern.All != nil {
					extFieldToMatchJsonBodyMatchPattern.All = map[string]*string{}
				}
				extFieldToMatch := &svcapitypes.FieldToMatch{
					Body: &svcapitypes.Body{OversizeHandling: v.Statement.ByteMatchStatement.FieldToMatch.Body.OversizeHandling},
					Cookies: &svcapitypes.Cookies{
						MatchPattern:     extCookiesMatchPattern,
						MatchScope:       v.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchScope,
						OversizeHandling: v.Statement.ByteMatchStatement.FieldToMatch.Cookies.OversizeHandling,
					},
					HeaderOrder: &svcapitypes.HeaderOrder{OversizeHandling: v.Statement.ByteMatchStatement.FieldToMatch.HeaderOrder.OversizeHandling},
					Headers: &svcapitypes.Headers{
						MatchPattern:     extHeadersMatchPattern,
						MatchScope:       v.Statement.ByteMatchStatement.FieldToMatch.Cookies.MatchScope,
						OversizeHandling: v.Statement.ByteMatchStatement.FieldToMatch.Cookies.OversizeHandling,
					},
					JA3Fingerprint: &svcapitypes.JA3Fingerprint{FallbackBehavior: v.Statement.ByteMatchStatement.FieldToMatch.JA3Fingerprint.FallbackBehavior},
					JSONBody: &svcapitypes.JSONBody{
						InvalidFallbackBehavior: v.Statement.ByteMatchStatement.FieldToMatch.JsonBody.InvalidFallbackBehavior,
						MatchPattern:            extFieldToMatchJsonBodyMatchPattern,
						MatchScope:              v.Statement.ByteMatchStatement.FieldToMatch.JsonBody.MatchScope,
						OversizeHandling:        v.Statement.ByteMatchStatement.FieldToMatch.JsonBody.OversizeHandling,
					},
					SingleHeader: &svcapitypes.SingleHeader{
						Name: v.Statement.ByteMatchStatement.FieldToMatch.SingleHeader.Name,
					},
					SingleQueryArgument: &svcapitypes.SingleQueryArgument{
						Name: v.Statement.ByteMatchStatement.FieldToMatch.SingleQueryArgument.Name,
					},
				}
				if v.Statement.ByteMatchStatement.FieldToMatch.AllQueryArguments != nil {
					extFieldToMatch.AllQueryArguments = map[string]*string{}
				}
				if v.Statement.ByteMatchStatement.FieldToMatch.Method != nil {
					extFieldToMatch.Method = map[string]*string{}
				}
				if v.Statement.ByteMatchStatement.FieldToMatch.QueryString != nil {
					extFieldToMatch.QueryString = map[string]*string{}
				}
				if v.Statement.ByteMatchStatement.FieldToMatch.UriPath != nil {
					extFieldToMatch.URIPath = map[string]*string{}
				}
				extRuleStatement.ByteMatchStatement = &svcapitypes.ByteMatchStatement{
					PositionalConstraint: v.Statement.ByteMatchStatement.PositionalConstraint,
					SearchString:         v.Statement.ByteMatchStatement.SearchString,
					TextTransformations:  extTextTransformations,
					FieldToMatch:         extFieldToMatch,
				}
			}
			if v.Statement.GeoMatchStatement != nil {
				extRuleStatement.GeoMatchStatement = &svcapitypes.GeoMatchStatement{
					CountryCodes: v.Statement.GeoMatchStatement.CountryCodes,
					ForwardedIPConfig: &svcapitypes.ForwardedIPConfig{
						HeaderName:       v.Statement.GeoMatchStatement.ForwardedIPConfig.HeaderName,
						FallbackBehavior: v.Statement.GeoMatchStatement.ForwardedIPConfig.FallbackBehavior,
					},
				}
			}
			if v.Statement.IPSetReferenceStatement != nil {
				extRuleStatement.IPSetReferenceStatement = &svcapitypes.IPSetReferenceStatement{
					ARN: v.Statement.IPSetReferenceStatement.ARN,
					IPSetForwardedIPConfig: &svcapitypes.IPSetForwardedIPConfig{
						HeaderName:       v.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.HeaderName,
						FallbackBehavior: v.Statement.IPSetReferenceStatement.IPSetForwardedIPConfig.FallbackBehavior,
					},
				}
			}
			if v.Statement.LabelMatchStatement != nil {
				extRuleStatement.LabelMatchStatement = &svcapitypes.LabelMatchStatement{
					Key:   v.Statement.LabelMatchStatement.Key,
					Scope: v.Statement.LabelMatchStatement.Scope,
				}
			}
			if v.Statement.RateBasedStatement != nil {
				var extCustomKeys []*svcapitypes.RateBasedStatementCustomKey
				for _, v := range v.Statement.RateBasedStatement.CustomKeys {
					var extCookieTextTransformations []*svcapitypes.TextTransformation
					for _, v := range v.Cookie.TextTransformations {
						extCookieTextTransformations = append(extCookieTextTransformations, &svcapitypes.TextTransformation{Priority: v.Priority, Type: v.Type})
					}
					var extHeaderTextTransformations []*svcapitypes.TextTransformation
					for _, v := range v.Header.TextTransformations {
						extHeaderTextTransformations = append(extHeaderTextTransformations, &svcapitypes.TextTransformation{Priority: v.Priority, Type: v.Type})
					}
					var extQueryArgumentTextTransformations []*svcapitypes.TextTransformation
					for _, v := range v.QueryArgument.TextTransformations {
						extQueryArgumentTextTransformations = append(extQueryArgumentTextTransformations, &svcapitypes.TextTransformation{Priority: v.Priority, Type: v.Type})
					}
					var extQueryStringTextTransformations []*svcapitypes.TextTransformation
					for _, v := range v.QueryString.TextTransformations {
						extQueryStringTextTransformations = append(extQueryStringTextTransformations, &svcapitypes.TextTransformation{Priority: v.Priority, Type: v.Type})
					}
					var extURIPathTextTransformations []*svcapitypes.TextTransformation
					for _, v := range v.UriPath.TextTransformations {
						extURIPathTextTransformations = append(extURIPathTextTransformations, &svcapitypes.TextTransformation{Priority: v.Priority, Type: v.Type})
					}
					extCustomKey := &svcapitypes.RateBasedStatementCustomKey{
						Cookie: &svcapitypes.RateLimitCookie{
							Name:                v.Cookie.Name,
							TextTransformations: extCookieTextTransformations,
						},
						Header: &svcapitypes.RateLimitHeader{
							Name:                v.Header.Name,
							TextTransformations: extHeaderTextTransformations,
						},
						LabelNamespace: &svcapitypes.RateLimitLabelNamespace{
							Namespace: v.LabelNamespace.Namespace,
						},
						QueryArgument: &svcapitypes.RateLimitQueryArgument{
							Name:                v.QueryArgument.Name,
							TextTransformations: extQueryArgumentTextTransformations,
						},
						QueryString: &svcapitypes.RateLimitQueryString{
							TextTransformations: extQueryStringTextTransformations,
						},
						URIPath: &svcapitypes.RateLimitURIPath{
							TextTransformations: extURIPathTextTransformations,
						},
					}
					if v.ForwardedIP != nil {
						extCustomKey.ForwardedIP = map[string]*string{}
					}
					if v.HTTPMethod != nil {
						extCustomKey.HTTPMethod = map[string]*string{}
					}
					if v.IP != nil {
						extCustomKey.IP = map[string]*string{}
					}
					extCustomKeys = append(extCustomKeys, extCustomKey)

				}
				extRuleStatement.RateBasedStatement = &svcapitypes.RateBasedStatement{
					AggregateKeyType: v.Statement.RateBasedStatement.AggregateKeyType,
					Limit:            v.Statement.RateBasedStatement.Limit,
					CustomKeys:       extCustomKeys,
					ForwardedIPConfig: &svcapitypes.ForwardedIPConfig{
						HeaderName:       v.Statement.RateBasedStatement.ForwardedIPConfig.HeaderName,
						FallbackBehavior: v.Statement.RateBasedStatement.ForwardedIPConfig.FallbackBehavior,
					},
				}
				if v.Statement.RateBasedStatement.ScopeDownStatement != nil {
					jsonString, err := statementToString[svcsdk.Statement](*v.Statement.RateBasedStatement.ScopeDownStatement)
					if err != nil {
						return err
					}
					extRuleStatement.RateBasedStatement.ScopeDownStatement = jsonString
				}

			}

			extRule.Statement = extRuleStatement
		}
		extRules = append(extRules, extRule)
		target.Rules = extRules
	}
	return nil
}

func setRuleRateBasedStatement(respRuleStatement *svcsdk.RateBasedStatement, extRuleStatement *svcapitypes.Statement) error {
	extForwardedIPConfig := &svcapitypes.ForwardedIPConfig{
		HeaderName:       respRuleStatement.ForwardedIPConfig.HeaderName,
		FallbackBehavior: respRuleStatement.ForwardedIPConfig.FallbackBehavior,
	}
	var extCustomKeys []*svcapitypes.RateBasedStatementCustomKey
	for _, v := range respRuleStatement.CustomKeys {
		var extCookieTextTransofrmations []*svcapitypes.TextTransformation
		for _, v := range v.Cookie.TextTransformations {
			extCookieTextTransofrmations = append(extCookieTextTransofrmations, &svcapitypes.TextTransformation{Priority: v.Priority, Type: v.Type})
		}
		var extHeaderTextTransformations []*svcapitypes.TextTransformation
		for _, v := range v.Header.TextTransformations {
			extHeaderTextTransformations = append(extHeaderTextTransformations, &svcapitypes.TextTransformation{Priority: v.Priority, Type: v.Type})
		}
		var extQueryArgumentTextTransformations []*svcapitypes.TextTransformation
		for _, v := range v.QueryArgument.TextTransformations {
			extQueryArgumentTextTransformations = append(extQueryArgumentTextTransformations, &svcapitypes.TextTransformation{Priority: v.Priority, Type: v.Type})
		}
		var extQueryStringTextTransformations []*svcapitypes.TextTransformation
		for _, v := range v.QueryString.TextTransformations {
			extQueryStringTextTransformations = append(extQueryStringTextTransformations, &svcapitypes.TextTransformation{Priority: v.Priority, Type: v.Type})
		}
		var extURIPathTextTransformations []*svcapitypes.TextTransformation
		for _, v := range v.UriPath.TextTransformations {
			extURIPathTextTransformations = append(extURIPathTextTransformations, &svcapitypes.TextTransformation{Priority: v.Priority, Type: v.Type})
		}
		extCustomKey := &svcapitypes.RateBasedStatementCustomKey{
			Cookie:         &svcapitypes.RateLimitCookie{Name: v.Cookie.Name, TextTransformations: extCookieTextTransofrmations},
			Header:         &svcapitypes.RateLimitHeader{Name: v.Header.Name, TextTransformations: extHeaderTextTransformations},
			LabelNamespace: &svcapitypes.RateLimitLabelNamespace{Namespace: v.LabelNamespace.Namespace},
			QueryArgument:  &svcapitypes.RateLimitQueryArgument{Name: v.QueryArgument.Name, TextTransformations: extQueryArgumentTextTransformations},
			QueryString:    &svcapitypes.RateLimitQueryString{TextTransformations: extQueryStringTextTransformations},
			URIPath:        &svcapitypes.RateLimitURIPath{TextTransformations: extURIPathTextTransformations},
		}
		if v.ForwardedIP != nil {
			extCustomKey.ForwardedIP = map[string]*string{}
		}
		if v.HTTPMethod != nil {
			extCustomKey.HTTPMethod = map[string]*string{}
		}
		if v.IP != nil {
			extCustomKey.IP = map[string]*string{}
		}
		extCustomKeys = append(extCustomKeys, extCustomKey)
	}
	extRateBasedStatement := &svcapitypes.RateBasedStatement{
		AggregateKeyType:  respRuleStatement.AggregateKeyType,
		CustomKeys:        extCustomKeys,
		ForwardedIPConfig: extForwardedIPConfig,
		Limit:             respRuleStatement.Limit,
	}
	if respRuleStatement.ScopeDownStatement != nil {
		jsonString, err := statementToString[svcsdk.Statement](*respRuleStatement.ScopeDownStatement)
		if err != nil {
			return err
		}
		extRateBasedStatement.ScopeDownStatement = jsonString
	}
	extRuleStatement.Statement.RateBasedStatement = extRateBasedStatement
	return nil
}

func setRuleManagedRuleGroupStatement(respRuleStatement *svcsdk.ManagedRuleGroupStatement, extRuleStatement *svcapitypes.Statement) error {
	var extExcludedRules []*svcapitypes.ExcludedRule
	var extManagedRuleGroupConfigs []*svcapitypes.ManagedRuleGroupConfig
	for _, v := range respRuleStatement.ExcludedRules {
		extExcludedRules = append(extExcludedRules, &svcapitypes.ExcludedRule{Name: v.Name})
	}
	for _, v := range respRuleStatement.ManagedRuleGroupConfigs {
		var extAddressFields []*svcapitypes.AddressField
		var extPhoneNumberFields []*svcapitypes.PhoneNumberField
		for _, v := range v.AWSManagedRulesACFPRuleSet.RequestInspection.AddressFields {
			extAddressFields = append(extAddressFields, &svcapitypes.AddressField{Identifier: v.Identifier})
		}
		for _, v := range v.AWSManagedRulesACFPRuleSet.RequestInspection.PhoneNumberFields {
			extPhoneNumberFields = append(extPhoneNumberFields, &svcapitypes.PhoneNumberField{Identifier: v.Identifier})
		}
		extRequestInspection := &svcapitypes.RequestInspectionACFP{
			AddressFields: extAddressFields,
			EmailField: &svcapitypes.EmailField{
				Identifier: v.AWSManagedRulesACFPRuleSet.RequestInspection.EmailField.Identifier,
			},
			PasswordField: &svcapitypes.PasswordField{
				Identifier: v.AWSManagedRulesACFPRuleSet.RequestInspection.PasswordField.Identifier,
			},
			PayloadType:       v.AWSManagedRulesACFPRuleSet.RequestInspection.PayloadType,
			PhoneNumberFields: extPhoneNumberFields,
			UsernameField: &svcapitypes.UsernameField{
				Identifier: v.AWSManagedRulesACFPRuleSet.RequestInspection.UsernameField.Identifier,
			},
		}
		extResponseInspectionBodyContains := &svcapitypes.ResponseInspectionBodyContains{
			FailureStrings: make([]*string, 0),
			SuccessStrings: make([]*string, 0),
		}
		for _, v := range v.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains.FailureStrings {
			extResponseInspectionBodyContains.FailureStrings = append(extResponseInspectionBodyContains.FailureStrings, v)
		}
		for _, v := range v.AWSManagedRulesACFPRuleSet.ResponseInspection.BodyContains.SuccessStrings {
			extResponseInspectionBodyContains.SuccessStrings = append(extResponseInspectionBodyContains.SuccessStrings, v)
		}

		extResponseInspection := &svcapitypes.ResponseInspection{
			BodyContains: extResponseInspectionBodyContains,
			Header: &svcapitypes.ResponseInspectionHeader{
				Name:          v.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.Name,
				FailureValues: v.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.FailureValues,
				SuccessValues: v.AWSManagedRulesACFPRuleSet.ResponseInspection.Header.SuccessValues,
			},
			JSON: &svcapitypes.ResponseInspectionJSON{
				FailureValues: v.AWSManagedRulesACFPRuleSet.ResponseInspection.Json.FailureValues,
				Identifier:    v.AWSManagedRulesACFPRuleSet.ResponseInspection.Json.Identifier,
				SuccessValues: v.AWSManagedRulesACFPRuleSet.ResponseInspection.Json.SuccessValues,
			},
		}

		extManagedRuleGroupConfigs = append(extManagedRuleGroupConfigs,
			&svcapitypes.ManagedRuleGroupConfig{
				AWSManagedRulesACFPRuleSet: &svcapitypes.AWSManagedRulesACFPRuleSet{
					CreationPath:         v.AWSManagedRulesACFPRuleSet.CreationPath,
					EnableRegexInPath:    v.AWSManagedRulesACFPRuleSet.EnableRegexInPath,
					RegistrationPagePath: v.AWSManagedRulesACFPRuleSet.RegistrationPagePath,
					RequestInspection:    extRequestInspection,
					ResponseInspection:   extResponseInspection,
				},
			},
		)

	}
	var extRuleActionOverrides []*svcapitypes.RuleActionOverride
	for _, v := range respRuleStatement.RuleActionOverrides {
		var extAllowInsertHeaders []*svcapitypes.CustomHTTPHeader
		for _, v := range v.ActionToUse.Allow.CustomRequestHandling.InsertHeaders {
			extAllowInsertHeaders = append(extAllowInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
		}
		var extBlockResponseHeaders []*svcapitypes.CustomHTTPHeader
		for _, v := range v.ActionToUse.Block.CustomResponse.ResponseHeaders {
			extBlockResponseHeaders = append(extBlockResponseHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
		}
		var extCaptchaInsertHeaders []*svcapitypes.CustomHTTPHeader
		for _, v := range v.ActionToUse.Captcha.CustomRequestHandling.InsertHeaders {
			extCaptchaInsertHeaders = append(extCaptchaInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
		}
		var extChallengeInsertHeaders []*svcapitypes.CustomHTTPHeader
		for _, v := range v.ActionToUse.Challenge.CustomRequestHandling.InsertHeaders {
			extChallengeInsertHeaders = append(extChallengeInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
		}
		var extCountInsertHeaders []*svcapitypes.CustomHTTPHeader
		for _, v := range v.ActionToUse.Count.CustomRequestHandling.InsertHeaders {
			extCountInsertHeaders = append(extCountInsertHeaders, &svcapitypes.CustomHTTPHeader{Name: v.Name, Value: v.Value})
		}
		extRuleActionOverrides = append(extRuleActionOverrides, &svcapitypes.RuleActionOverride{
			ActionToUse: &svcapitypes.RuleAction{
				Allow: &svcapitypes.AllowAction{
					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
						InsertHeaders: extAllowInsertHeaders,
					},
				},
				Block: &svcapitypes.BlockAction{
					CustomResponse: &svcapitypes.CustomResponse{
						CustomResponseBodyKey: v.ActionToUse.Block.CustomResponse.CustomResponseBodyKey,
						ResponseCode:          v.ActionToUse.Block.CustomResponse.ResponseCode,
						ResponseHeaders:       extBlockResponseHeaders,
					},
				},
				Captcha: &svcapitypes.CaptchaAction{
					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
						InsertHeaders: extCaptchaInsertHeaders,
					},
				},
				Challenge: &svcapitypes.ChallengeAction{
					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
						InsertHeaders: extChallengeInsertHeaders,
					},
				},
				Count: &svcapitypes.CountAction{
					CustomRequestHandling: &svcapitypes.CustomRequestHandling{
						InsertHeaders: extCountInsertHeaders,
					},
				},
			},
			Name: v.Name,
		})
	}
	extRuleStatement.ManagedRuleGroupStatement = &svcapitypes.ManagedRuleGroupStatement{
		ExcludedRules:           extExcludedRules,
		ManagedRuleGroupConfigs: extManagedRuleGroupConfigs,
		Name:                    respRuleStatement.Name,
		RuleActionOverrides:     extRuleActionOverrides,
		VendorName:              respRuleStatement.VendorName,
		Version:                 respRuleStatement.Version,
	}
	if respRuleStatement.ScopeDownStatement != nil {
		jsonString, err := statementToString[svcsdk.Statement](*respRuleStatement.ScopeDownStatement)
		if err != nil {
			return err
		}
		extRuleStatement.ManagedRuleGroupStatement.ScopeDownStatement = jsonString
	}
	return nil
}

func setRuleByteMatchStatement(respRuleStatement *svcsdk.ByteMatchStatement, extRuleStatement *svcapitypes.Statement) {
	var extTextTransformations []*svcapitypes.TextTransformation
	for _, v := range respRuleStatement.TextTransformations {
		extTextTransformations = append(extTextTransformations, &svcapitypes.TextTransformation{Priority: v.Priority, Type: v.Type})
	}
	extRuleStatement.ByteMatchStatement = &svcapitypes.ByteMatchStatement{
		PositionalConstraint: respRuleStatement.PositionalConstraint,
		SearchString:         respRuleStatement.SearchString,
		TextTransformations:  extTextTransformations,
	}
	if respRuleStatement.FieldToMatch.AllQueryArguments != nil {
		extRuleStatement.ByteMatchStatement.FieldToMatch.AllQueryArguments = map[string]*string{}
	}
}
