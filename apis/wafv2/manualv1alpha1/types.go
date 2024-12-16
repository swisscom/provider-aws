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

package manualv1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Hack to avoid import errors during build...
var (
	_ = &metav1.Time{}
)

// +kubebuilder:skipversion
type APIKeySummary struct {
	TokenDomains []*string `json:"tokenDomains,omitempty"`
}

// +kubebuilder:skipversion
type AWSManagedRulesACFPRuleSet struct {
	CreationPath *string `json:"creationPath,omitempty"`

	EnableRegexInPath *bool `json:"enableRegexInPath,omitempty"`

	RegistrationPagePath *string `json:"registrationPagePath,omitempty"`
	// The criteria for inspecting account creation requests, used by the ACFP rule
	// group to validate and track account creation attempts.
	//
	// This is part of the AWSManagedRulesACFPRuleSet configuration in ManagedRuleGroupConfig.
	//
	// In these settings, you specify how your application accepts account creation
	// attempts by providing the request payload type and the names of the fields
	// within the request body where the username, password, email, and primary
	// address and phone number fields are provided.
	RequestInspection *RequestInspectionACFP `json:"requestInspection,omitempty"`
	// The criteria for inspecting responses to login requests and account creation
	// requests, used by the ATP and ACFP rule groups to track login and account
	// creation success and failure rates.
	//
	// Response inspection is available only in web ACLs that protect Amazon CloudFront
	// distributions.
	//
	// The rule groups evaluates the responses that your protected resources send
	// back to client login and account creation attempts, keeping count of successful
	// and failed attempts from each IP address and client session. Using this information,
	// the rule group labels and mitigates requests from client sessions and IP
	// addresses with too much suspicious activity in a short amount of time.
	//
	// This is part of the AWSManagedRulesATPRuleSet and AWSManagedRulesACFPRuleSet
	// configurations in ManagedRuleGroupConfig.
	//
	// Enable response inspection by configuring exactly one component of the response
	// to inspect, for example, Header or StatusCode. You can't configure more than
	// one component for inspection. If you don't configure any of the response
	// inspection options, response inspection is disabled.
	ResponseInspection *ResponseInspection `json:"responseInspection,omitempty"`
}

// +kubebuilder:skipversion
type AWSManagedRulesATPRuleSet struct {
	EnableRegexInPath *bool `json:"enableRegexInPath,omitempty"`

	LoginPath *string `json:"loginPath,omitempty"`
	// The criteria for inspecting login requests, used by the ATP rule group to
	// validate credentials usage.
	//
	// This is part of the AWSManagedRulesATPRuleSet configuration in ManagedRuleGroupConfig.
	//
	// In these settings, you specify how your application accepts login attempts
	// by providing the request payload type and the names of the fields within
	// the request body where the username and password are provided.
	RequestInspection *RequestInspection `json:"requestInspection,omitempty"`
	// The criteria for inspecting responses to login requests and account creation
	// requests, used by the ATP and ACFP rule groups to track login and account
	// creation success and failure rates.
	//
	// Response inspection is available only in web ACLs that protect Amazon CloudFront
	// distributions.
	//
	// The rule groups evaluates the responses that your protected resources send
	// back to client login and account creation attempts, keeping count of successful
	// and failed attempts from each IP address and client session. Using this information,
	// the rule group labels and mitigates requests from client sessions and IP
	// addresses with too much suspicious activity in a short amount of time.
	//
	// This is part of the AWSManagedRulesATPRuleSet and AWSManagedRulesACFPRuleSet
	// configurations in ManagedRuleGroupConfig.
	//
	// Enable response inspection by configuring exactly one component of the response
	// to inspect, for example, Header or StatusCode. You can't configure more than
	// one component for inspection. If you don't configure any of the response
	// inspection options, response inspection is disabled.
	ResponseInspection *ResponseInspection `json:"responseInspection,omitempty"`
}

// +kubebuilder:skipversion
type AWSManagedRulesBotControlRuleSet struct {
	EnableMachineLearning *bool `json:"enableMachineLearning,omitempty"`

	InspectionLevel *string `json:"inspectionLevel,omitempty"`
}

// +kubebuilder:skipversion
type AddressField struct {
	Identifier *string `json:"identifier,omitempty"`
}

// +kubebuilder:skipversion
type AllowAction struct {
	// Custom request handling behavior that inserts custom headers into a web request.
	// You can add custom request handling for WAF to use when the rule action doesn't
	// block the request. For example, CaptchaAction for requests with valid t okens,
	// and AllowAction.
	//
	// For information about customizing web requests and responses, see Customizing
	// web requests and responses in WAF (https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html)
	// in the WAF Developer Guide.
	CustomRequestHandling *CustomRequestHandling `json:"customRequestHandling,omitempty"`
}

// +kubebuilder:skipversion
type AssociationConfig struct {
	RequestBody map[string]*RequestBodyAssociatedResourceTypeConfig `json:"requestBody,omitempty"`
}

// +kubebuilder:skipversion
type BlockAction struct {
	// A custom response to send to the client. You can define a custom response
	// for rule actions and default web ACL actions that are set to BlockAction.
	//
	// For information about customizing web requests and responses, see Customizing
	// web requests and responses in WAF (https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html)
	// in the WAF Developer Guide.
	CustomResponse *CustomResponse `json:"customResponse,omitempty"`
}

// +kubebuilder:skipversion
type Body struct {
	OversizeHandling *string `json:"oversizeHandling,omitempty"`
}

// +kubebuilder:skipversion
type ByteMatchStatement struct {
	// The part of the web request that you want WAF to inspect. Include the single
	// FieldToMatch type that you want to inspect, with additional specifications
	// as needed, according to the type. You specify a single request component
	// in FieldToMatch for each rule statement that requires it. To inspect more
	// than one component of the web request, create a separate rule statement for
	// each component.
	//
	// Example JSON for a QueryString field to match:
	//
	// "FieldToMatch": { "QueryString": {} }
	//
	// Example JSON for a Method field to match specification:
	//
	// "FieldToMatch": { "Method": { "Name": "DELETE" } }
	FieldToMatch *FieldToMatch `json:"fieldToMatch,omitempty"`

	PositionalConstraint *string `json:"positionalConstraint,omitempty"`

	SearchString []byte `json:"searchString,omitempty"`

	TextTransformations []*TextTransformation `json:"textTransformations,omitempty"`
}

// +kubebuilder:skipversion
type CaptchaAction struct {
	// Custom request handling behavior that inserts custom headers into a web request.
	// You can add custom request handling for WAF to use when the rule action doesn't
	// block the request. For example, CaptchaAction for requests with valid t okens,
	// and AllowAction.
	//
	// For information about customizing web requests and responses, see Customizing
	// web requests and responses in WAF (https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html)
	// in the WAF Developer Guide.
	CustomRequestHandling *CustomRequestHandling `json:"customRequestHandling,omitempty"`
}

// +kubebuilder:skipversion
type CaptchaConfig struct {
	// Used for CAPTCHA and challenge token settings. Determines how long a CAPTCHA
	// or challenge timestamp remains valid after WAF updates it for a successful
	// CAPTCHA or challenge response.
	ImmunityTimeProperty *ImmunityTimeProperty `json:"immunityTimeProperty,omitempty"`
}

// +kubebuilder:skipversion
type ChallengeAction struct {
	// Custom request handling behavior that inserts custom headers into a web request.
	// You can add custom request handling for WAF to use when the rule action doesn't
	// block the request. For example, CaptchaAction for requests with valid t okens,
	// and AllowAction.
	//
	// For information about customizing web requests and responses, see Customizing
	// web requests and responses in WAF (https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html)
	// in the WAF Developer Guide.
	CustomRequestHandling *CustomRequestHandling `json:"customRequestHandling,omitempty"`
}

// +kubebuilder:skipversion
type ChallengeConfig struct {
	// Used for CAPTCHA and challenge token settings. Determines how long a CAPTCHA
	// or challenge timestamp remains valid after WAF updates it for a successful
	// CAPTCHA or challenge response.
	ImmunityTimeProperty *ImmunityTimeProperty `json:"immunityTimeProperty,omitempty"`
}

// +kubebuilder:skipversion
type CookieMatchPattern struct {
	// Inspect all of the elements that WAF has parsed and extracted from the web
	// request component that you've identified in your FieldToMatch specifications.
	//
	// This is used in the FieldToMatch specification for some web request component
	// types.
	//
	// JSON specification: "All": {}
	All map[string]*string `json:"all,omitempty"`

	ExcludedCookies []*string `json:"excludedCookies,omitempty"`

	IncludedCookies []*string `json:"includedCookies,omitempty"`
}

// +kubebuilder:skipversion
type Cookies struct {
	// The filter to use to identify the subset of cookies to inspect in a web request.
	//
	// You must specify exactly one setting: either All, IncludedCookies, or ExcludedCookies.
	//
	// Example JSON: "MatchPattern": { "IncludedCookies": [ "session-id-time", "session-id"
	// ] }
	MatchPattern *CookieMatchPattern `json:"matchPattern,omitempty"`

	MatchScope *string `json:"matchScope,omitempty"`

	OversizeHandling *string `json:"oversizeHandling,omitempty"`
}

// +kubebuilder:skipversion
type CountAction struct {
	// Custom request handling behavior that inserts custom headers into a web request.
	// You can add custom request handling for WAF to use when the rule action doesn't
	// block the request. For example, CaptchaAction for requests with valid t okens,
	// and AllowAction.
	//
	// For information about customizing web requests and responses, see Customizing
	// web requests and responses in WAF (https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html)
	// in the WAF Developer Guide.
	CustomRequestHandling *CustomRequestHandling `json:"customRequestHandling,omitempty"`
}

// +kubebuilder:skipversion
type CustomHTTPHeader struct {
	Name *string `json:"name,omitempty"`

	Value *string `json:"value,omitempty"`
}

// +kubebuilder:skipversion
type CustomRequestHandling struct {
	InsertHeaders []*CustomHTTPHeader `json:"insertHeaders,omitempty"`
}

// +kubebuilder:skipversion
type CustomResponse struct {
	CustomResponseBodyKey *string `json:"customResponseBodyKey,omitempty"`

	ResponseCode *int64 `json:"responseCode,omitempty"`

	ResponseHeaders []*CustomHTTPHeader `json:"responseHeaders,omitempty"`
}

// +kubebuilder:skipversion
type CustomResponseBody struct {
	Content *string `json:"content,omitempty"`

	ContentType *string `json:"contentType,omitempty"`
}

// +kubebuilder:skipversion
type DefaultAction struct {
	// Specifies that WAF should allow the request and optionally defines additional
	// custom handling for the request.
	//
	// This is used in the context of other settings, for example to specify values
	// for RuleAction and web ACL DefaultAction.
	Allow *AllowAction `json:"allow,omitempty"`
	// Specifies that WAF should block the request and optionally defines additional
	// custom handling for the response to the web request.
	//
	// This is used in the context of other settings, for example to specify values
	// for RuleAction and web ACL DefaultAction.
	Block *BlockAction `json:"block,omitempty"`
}

// +kubebuilder:skipversion
type EmailField struct {
	Identifier *string `json:"identifier,omitempty"`
}

// +kubebuilder:skipversion
type ExcludedRule struct {
	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type FieldToMatch struct {
	// Inspect all query arguments of the web request.
	//
	// This is used in the FieldToMatch specification for some web request component
	// types.
	//
	// JSON specification: "AllQueryArguments": {}
	AllQueryArguments map[string]*string `json:"allQueryArguments,omitempty"`
	// Inspect the body of the web request. The body immediately follows the request
	// headers.
	//
	// This is used to indicate the web request component to inspect, in the FieldToMatch
	// specification.
	Body *Body `json:"body,omitempty"`
	// Inspect the cookies in the web request. You can specify the parts of the
	// cookies to inspect and you can narrow the set of cookies to inspect by including
	// or excluding specific keys.
	//
	// This is used to indicate the web request component to inspect, in the FieldToMatch
	// specification.
	//
	// Example JSON: "Cookies": { "MatchPattern": { "All": {} }, "MatchScope": "KEY",
	// "OversizeHandling": "MATCH" }
	Cookies *Cookies `json:"cookies,omitempty"`
	// Inspect a string containing the list of the request's header names, ordered
	// as they appear in the web request that WAF receives for inspection. WAF generates
	// the string and then uses that as the field to match component in its inspection.
	// WAF separates the header names in the string using colons and no added spaces,
	// for example host:user-agent:accept:authorization:referer.
	HeaderOrder *HeaderOrder `json:"headerOrder,omitempty"`
	// Inspect all headers in the web request. You can specify the parts of the
	// headers to inspect and you can narrow the set of headers to inspect by including
	// or excluding specific keys.
	//
	// This is used to indicate the web request component to inspect, in the FieldToMatch
	// specification.
	//
	// If you want to inspect just the value of a single header, use the SingleHeader
	// FieldToMatch setting instead.
	//
	// Example JSON: "Headers": { "MatchPattern": { "All": {} }, "MatchScope": "KEY",
	// "OversizeHandling": "MATCH" }
	Headers *Headers `json:"headers,omitempty"`
	// Match against the request's JA3 fingerprint. The JA3 fingerprint is a 32-character
	// hash derived from the TLS Client Hello of an incoming request. This fingerprint
	// serves as a unique identifier for the client's TLS configuration. WAF calculates
	// and logs this fingerprint for each request that has enough TLS Client Hello
	// information for the calculation. Almost all web requests include this information.
	//
	// You can use this choice only with a string match ByteMatchStatement with
	// the PositionalConstraint set to EXACTLY.
	//
	// You can obtain the JA3 fingerprint for client requests from the web ACL logs.
	// If WAF is able to calculate the fingerprint, it includes it in the logs.
	// For information about the logging fields, see Log fields (https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html)
	// in the WAF Developer Guide.
	//
	// Provide the JA3 fingerprint string from the logs in your string match statement
	// specification, to match with any future requests that have the same TLS configuration.
	JA3Fingerprint *JA3Fingerprint `json:"ja3Fingerprint,omitempty"`
	// Inspect the body of the web request as JSON. The body immediately follows
	// the request headers.
	//
	// This is used to indicate the web request component to inspect, in the FieldToMatch
	// specification.
	//
	// Use the specifications in this object to indicate which parts of the JSON
	// body to inspect using the rule's inspection criteria. WAF inspects only the
	// parts of the JSON that result from the matches that you indicate.
	//
	// Example JSON: "JsonBody": { "MatchPattern": { "All": {} }, "MatchScope":
	// "ALL" }
	JSONBody *JSONBody `json:"jsonBody,omitempty"`
	// Inspect the HTTP method of the web request. The method indicates the type
	// of operation that the request is asking the origin to perform.
	//
	// This is used in the FieldToMatch specification for some web request component
	// types.
	//
	// JSON specification: "Method": {}
	Method map[string]*string `json:"method,omitempty"`
	// Inspect the query string of the web request. This is the part of a URL that
	// appears after a ? character, if any.
	//
	// This is used in the FieldToMatch specification for some web request component
	// types.
	//
	// JSON specification: "QueryString": {}
	QueryString map[string]*string `json:"queryString,omitempty"`
	// Inspect one of the headers in the web request, identified by name, for example,
	// User-Agent or Referer. The name isn't case sensitive.
	//
	// You can filter and inspect all headers with the FieldToMatch setting Headers.
	//
	// This is used to indicate the web request component to inspect, in the FieldToMatch
	// specification.
	//
	// Example JSON: "SingleHeader": { "Name": "haystack" }
	SingleHeader *SingleHeader `json:"singleHeader,omitempty"`
	// Inspect one query argument in the web request, identified by name, for example
	// UserName or SalesRegion. The name isn't case sensitive.
	//
	// This is used to indicate the web request component to inspect, in the FieldToMatch
	// specification.
	//
	// Example JSON: "SingleQueryArgument": { "Name": "myArgument" }
	SingleQueryArgument *SingleQueryArgument `json:"singleQueryArgument,omitempty"`
	// Inspect the path component of the URI of the web request. This is the part
	// of the web request that identifies a resource. For example, /images/daily-ad.jpg.
	//
	// This is used in the FieldToMatch specification for some web request component
	// types.
	//
	// JSON specification: "UriPath": {}
	URIPath map[string]*string `json:"uriPath,omitempty"`
}

// +kubebuilder:skipversion
type FirewallManagerRuleGroup struct {
	Name *string `json:"name,omitempty"`
	// The action to use in the place of the action that results from the rule group
	// evaluation. Set the override action to none to leave the result of the rule
	// group alone. Set it to count to override the result to count only.
	//
	// You can only use this for rule statements that reference a rule group, like
	// RuleGroupReferenceStatement and ManagedRuleGroupStatement.
	//
	// This option is usually set to none. It does not affect how the rules in the
	// rule group are evaluated. If you want the rules in the rule group to only
	// count matches, do not use this and instead use the rule action override option,
	// with Count action, in your rule group reference statement settings.
	OverrideAction *OverrideAction `json:"overrideAction,omitempty"`

	Priority *int64 `json:"priority,omitempty"`
	// Defines and enables Amazon CloudWatch metrics and web request sample collection.
	VisibilityConfig *VisibilityConfig `json:"visibilityConfig,omitempty"`
}

// +kubebuilder:skipversion
type FirewallManagerStatement struct {
	// A rule statement used to run the rules that are defined in a managed rule
	// group. To use this, provide the vendor name and the name of the rule group
	// in this statement. You can retrieve the required names by calling ListAvailableManagedRuleGroups.
	//
	// You cannot nest a ManagedRuleGroupStatement, for example for use inside a
	// NotStatement or OrStatement. You cannot use a managed rule group inside another
	// rule group. You can only reference a managed rule group as a top-level statement
	// within a rule that you define in a web ACL.
	//
	// You are charged additional fees when you use the WAF Bot Control managed
	// rule group AWSManagedRulesBotControlRuleSet, the WAF Fraud Control account
	// takeover prevention (ATP) managed rule group AWSManagedRulesATPRuleSet, or
	// the WAF Fraud Control account creation fraud prevention (ACFP) managed rule
	// group AWSManagedRulesACFPRuleSet. For more information, see WAF Pricing (http://aws.amazon.com/waf/pricing/).
	ManagedRuleGroupStatement *ManagedRuleGroupStatement `json:"managedRuleGroupStatement,omitempty"`
	// A rule statement used to run the rules that are defined in a RuleGroup. To
	// use this, create a rule group with your rules, then provide the ARN of the
	// rule group in this statement.
	//
	// You cannot nest a RuleGroupReferenceStatement, for example for use inside
	// a NotStatement or OrStatement. You cannot use a rule group reference statement
	// inside another rule group. You can only reference a rule group as a top-level
	// statement within a rule that you define in a web ACL.
	RuleGroupReferenceStatement *RuleGroupReferenceStatement `json:"ruleGroupReferenceStatement,omitempty"`
}

// +kubebuilder:skipversion
type ForwardedIPConfig struct {
	FallbackBehavior *string `json:"fallbackBehavior,omitempty"`

	HeaderName *string `json:"headerName,omitempty"`
}

// +kubebuilder:skipversion
type GeoMatchStatement struct {
	CountryCodes []*string `json:"countryCodes,omitempty"`
	// The configuration for inspecting IP addresses in an HTTP header that you
	// specify, instead of using the IP address that's reported by the web request
	// origin. Commonly, this is the X-Forwarded-For (XFF) header, but you can specify
	// any header name.
	//
	// If the specified header isn't present in the request, WAF doesn't apply the
	// rule to the web request at all.
	//
	// This configuration is used for GeoMatchStatement and RateBasedStatement.
	// For IPSetReferenceStatement, use IPSetForwardedIPConfig instead.
	//
	// WAF only evaluates the first IP address found in the specified HTTP header.
	ForwardedIPConfig *ForwardedIPConfig `json:"forwardedIPConfig,omitempty"`
}

// +kubebuilder:skipversion
type HeaderMatchPattern struct {
	// Inspect all of the elements that WAF has parsed and extracted from the web
	// request component that you've identified in your FieldToMatch specifications.
	//
	// This is used in the FieldToMatch specification for some web request component
	// types.
	//
	// JSON specification: "All": {}
	All map[string]*string `json:"all,omitempty"`

	ExcludedHeaders []*string `json:"excludedHeaders,omitempty"`

	IncludedHeaders []*string `json:"includedHeaders,omitempty"`
}

// +kubebuilder:skipversion
type HeaderOrder struct {
	OversizeHandling *string `json:"oversizeHandling,omitempty"`
}

// +kubebuilder:skipversion
type Headers struct {
	// The filter to use to identify the subset of headers to inspect in a web request.
	//
	// You must specify exactly one setting: either All, IncludedHeaders, or ExcludedHeaders.
	//
	// Example JSON: "MatchPattern": { "ExcludedHeaders": [ "KeyToExclude1", "KeyToExclude2"
	// ] }
	MatchPattern *HeaderMatchPattern `json:"matchPattern,omitempty"`

	MatchScope *string `json:"matchScope,omitempty"`

	OversizeHandling *string `json:"oversizeHandling,omitempty"`
}

// +kubebuilder:skipversion
type IPSet struct {
	ARN *string `json:"arn,omitempty"`

	Description *string `json:"description,omitempty"`

	ID *string `json:"id,omitempty"`

	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type IPSetForwardedIPConfig struct {
	FallbackBehavior *string `json:"fallbackBehavior,omitempty"`

	HeaderName *string `json:"headerName,omitempty"`

	Position *string `json:"position,omitempty"`
}

// +kubebuilder:skipversion
type IPSetReferenceStatement struct {
	ARN *string `json:"arn,omitempty"`
	// The configuration for inspecting IP addresses in an HTTP header that you
	// specify, instead of using the IP address that's reported by the web request
	// origin. Commonly, this is the X-Forwarded-For (XFF) header, but you can specify
	// any header name.
	//
	// If the specified header isn't present in the request, WAF doesn't apply the
	// rule to the web request at all.
	//
	// This configuration is used only for IPSetReferenceStatement. For GeoMatchStatement
	// and RateBasedStatement, use ForwardedIPConfig instead.
	IPSetForwardedIPConfig *IPSetForwardedIPConfig `json:"ipSetForwardedIPConfig,omitempty"`
}

// +kubebuilder:skipversion
type IPSetSummary struct {
	ARN *string `json:"arn,omitempty"`

	Description *string `json:"description,omitempty"`

	ID *string `json:"id,omitempty"`

	LockToken *string `json:"lockToken,omitempty"`

	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type ImmunityTimeProperty struct {
	ImmunityTime *int64 `json:"immunityTime,omitempty"`
}

// +kubebuilder:skipversion
type JA3Fingerprint struct {
	FallbackBehavior *string `json:"fallbackBehavior,omitempty"`
}

// +kubebuilder:skipversion
type JSONBody struct {
	InvalidFallbackBehavior *string `json:"invalidFallbackBehavior,omitempty"`
	// The patterns to look for in the JSON body. WAF inspects the results of these
	// pattern matches against the rule inspection criteria. This is used with the
	// FieldToMatch option JsonBody.
	MatchPattern *JSONMatchPattern `json:"matchPattern,omitempty"`

	MatchScope *string `json:"matchScope,omitempty"`

	OversizeHandling *string `json:"oversizeHandling,omitempty"`
}

// +kubebuilder:skipversion
type JSONMatchPattern struct {
	// Inspect all of the elements that WAF has parsed and extracted from the web
	// request component that you've identified in your FieldToMatch specifications.
	//
	// This is used in the FieldToMatch specification for some web request component
	// types.
	//
	// JSON specification: "All": {}
	All map[string]*string `json:"all,omitempty"`

	IncludedPaths []*string `json:"includedPaths,omitempty"`
}

// +kubebuilder:skipversion
type Label struct {
	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type LabelMatchStatement struct {
	Key *string `json:"key,omitempty"`

	Scope *string `json:"scope,omitempty"`
}

// +kubebuilder:skipversion
type LabelNameCondition struct {
	LabelName *string `json:"labelName,omitempty"`
}

// +kubebuilder:skipversion
type LabelSummary struct {
	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type LoggingConfiguration struct {
	ManagedByFirewallManager *bool `json:"managedByFirewallManager,omitempty"`

	ResourceARN *string `json:"resourceARN,omitempty"`
}

// +kubebuilder:skipversion
type ManagedProductDescriptor struct {
	IsAdvancedManagedRuleSet *bool `json:"isAdvancedManagedRuleSet,omitempty"`

	IsVersioningSupported *bool `json:"isVersioningSupported,omitempty"`

	ManagedRuleSetName *string `json:"managedRuleSetName,omitempty"`

	SNSTopicARN *string `json:"snsTopicARN,omitempty"`

	VendorName *string `json:"vendorName,omitempty"`
}

// +kubebuilder:skipversion
type ManagedRuleGroupConfig struct {
	// Details for your use of the account creation fraud prevention managed rule
	// group, AWSManagedRulesACFPRuleSet. This configuration is used in ManagedRuleGroupConfig.
	AWSManagedRulesACFPRuleSet *AWSManagedRulesACFPRuleSet `json:"awsManagedRulesACFPRuleSet,omitempty"`
	// Details for your use of the account takeover prevention managed rule group,
	// AWSManagedRulesATPRuleSet. This configuration is used in ManagedRuleGroupConfig.
	AWSManagedRulesATPRuleSet *AWSManagedRulesATPRuleSet `json:"awsManagedRulesATPRuleSet,omitempty"`
	// Details for your use of the Bot Control managed rule group, AWSManagedRulesBotControlRuleSet.
	// This configuration is used in ManagedRuleGroupConfig.
	AWSManagedRulesBotControlRuleSet *AWSManagedRulesBotControlRuleSet `json:"awsManagedRulesBotControlRuleSet,omitempty"`

	LoginPath *string `json:"loginPath,omitempty"`
	// The name of the field in the request payload that contains your customer's
	// password.
	//
	// This data type is used in the RequestInspection and RequestInspectionACFP
	// data types.
	PasswordField *PasswordField `json:"passwordField,omitempty"`

	PayloadType *string `json:"payloadType,omitempty"`
	// The name of the field in the request payload that contains your customer's
	// username.
	//
	// This data type is used in the RequestInspection and RequestInspectionACFP
	// data types.
	UsernameField *UsernameField `json:"usernameField,omitempty"`
}

// +kubebuilder:skipversion
type ManagedRuleGroupStatement struct {
	ExcludedRules []*ExcludedRule `json:"excludedRules,omitempty"`

	ManagedRuleGroupConfigs []*ManagedRuleGroupConfig `json:"managedRuleGroupConfigs,omitempty"`

	Name *string `json:"name,omitempty"`

	RuleActionOverrides []*RuleActionOverride `json:"ruleActionOverrides,omitempty"`

	ScopeDownStatement *string `json:"scopeDownStatement,omitempty"`

	VendorName *string `json:"vendorName,omitempty"`

	Version *string `json:"version,omitempty"`
}

// +kubebuilder:skipversion
type ManagedRuleGroupSummary struct {
	Description *string `json:"description,omitempty"`

	Name *string `json:"name,omitempty"`

	VendorName *string `json:"vendorName,omitempty"`

	VersioningSupported *bool `json:"versioningSupported,omitempty"`
}

// +kubebuilder:skipversion
type ManagedRuleGroupVersion struct {
	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type ManagedRuleSet struct {
	ARN *string `json:"arn,omitempty"`

	Description *string `json:"description,omitempty"`

	ID *string `json:"id,omitempty"`

	LabelNamespace *string `json:"labelNamespace,omitempty"`

	Name *string `json:"name,omitempty"`

	RecommendedVersion *string `json:"recommendedVersion,omitempty"`
}

// +kubebuilder:skipversion
type ManagedRuleSetSummary struct {
	ARN *string `json:"arn,omitempty"`

	Description *string `json:"description,omitempty"`

	ID *string `json:"id,omitempty"`

	LabelNamespace *string `json:"labelNamespace,omitempty"`

	LockToken *string `json:"lockToken,omitempty"`

	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type ManagedRuleSetVersion struct {
	AssociatedRuleGroupARN *string `json:"associatedRuleGroupARN,omitempty"`
}

// +kubebuilder:skipversion
type MobileSDKRelease struct {
	ReleaseVersion *string `json:"releaseVersion,omitempty"`

	Tags []*Tag `json:"tags,omitempty"`
}

// +kubebuilder:skipversion
type NotStatement struct {
	// The processing guidance for a Rule, used by WAF to determine whether a web
	// request matches the rule.
	//
	// For example specifications, see the examples section of CreateWebACL.
	Statement *Statement `json:"statement,omitempty"`
}

// +kubebuilder:skipversion
type OverrideAction struct {
	// Specifies that WAF should count the request. Optionally defines additional
	// custom handling for the request.
	//
	// This is used in the context of other settings, for example to specify values
	// for RuleAction and web ACL DefaultAction.
	Count *CountAction `json:"count,omitempty"`
	// Specifies that WAF should do nothing. This is used for the OverrideAction
	// setting on a Rule when the rule uses a rule group reference statement.
	//
	// This is used in the context of other settings, for example to specify values
	// for RuleAction and web ACL DefaultAction.
	//
	// JSON specification: "None": {}
	None map[string]*string `json:"none,omitempty"`
}

// +kubebuilder:skipversion
type PasswordField struct {
	Identifier *string `json:"identifier,omitempty"`
}

// +kubebuilder:skipversion
type PhoneNumberField struct {
	Identifier *string `json:"identifier,omitempty"`
}

// +kubebuilder:skipversion
type RateBasedStatement struct {
	AggregateKeyType *string `json:"aggregateKeyType,omitempty"`

	CustomKeys []*RateBasedStatementCustomKey `json:"customKeys,omitempty"`
	// The configuration for inspecting IP addresses in an HTTP header that you
	// specify, instead of using the IP address that's reported by the web request
	// origin. Commonly, this is the X-Forwarded-For (XFF) header, but you can specify
	// any header name.
	//
	// If the specified header isn't present in the request, WAF doesn't apply the
	// rule to the web request at all.
	//
	// This configuration is used for GeoMatchStatement and RateBasedStatement.
	// For IPSetReferenceStatement, use IPSetForwardedIPConfig instead.
	//
	// WAF only evaluates the first IP address found in the specified HTTP header.
	ForwardedIPConfig *ForwardedIPConfig `json:"forwardedIPConfig,omitempty"`

	Limit *int64 `json:"limit,omitempty"`

	ScopeDownStatement *string `json:"scopeDownStatement,omitempty"`
}

// +kubebuilder:skipversion
type RateBasedStatementCustomKey struct {
	// Specifies a cookie as an aggregate key for a rate-based rule. Each distinct
	// value in the cookie contributes to the aggregation instance. If you use a
	// single cookie as your custom key, then each value fully defines an aggregation
	// instance.
	Cookie *RateLimitCookie `json:"cookie,omitempty"`
	// Specifies the first IP address in an HTTP header as an aggregate key for
	// a rate-based rule. Each distinct forwarded IP address contributes to the
	// aggregation instance.
	//
	// This setting is used only in the RateBasedStatementCustomKey specification
	// of a rate-based rule statement. When you specify an IP or forwarded IP in
	// the custom key settings, you must also specify at least one other key to
	// use. You can aggregate on only the forwarded IP address by specifying FORWARDED_IP
	// in your rate-based statement's AggregateKeyType.
	//
	// This data type supports using the forwarded IP address in the web request
	// aggregation for a rate-based rule, in RateBasedStatementCustomKey. The JSON
	// specification for using the forwarded IP address doesn't explicitly use this
	// data type.
	//
	// JSON specification: "ForwardedIP": {}
	//
	// When you use this specification, you must also configure the forwarded IP
	// address in the rate-based statement's ForwardedIPConfig.
	ForwardedIP map[string]*string `json:"forwardedIP,omitempty"`
	// Specifies the request's HTTP method as an aggregate key for a rate-based
	// rule. Each distinct HTTP method contributes to the aggregation instance.
	// If you use just the HTTP method as your custom key, then each method fully
	// defines an aggregation instance.
	//
	// JSON specification: "RateLimitHTTPMethod": {}
	HTTPMethod map[string]*string `json:"httpMethod,omitempty"`
	// Specifies a header as an aggregate key for a rate-based rule. Each distinct
	// value in the header contributes to the aggregation instance. If you use a
	// single header as your custom key, then each value fully defines an aggregation
	// instance.
	Header *RateLimitHeader `json:"header,omitempty"`
	// Specifies the IP address in the web request as an aggregate key for a rate-based
	// rule. Each distinct IP address contributes to the aggregation instance.
	//
	// This setting is used only in the RateBasedStatementCustomKey specification
	// of a rate-based rule statement. To use this in the custom key settings, you
	// must specify at least one other key to use, along with the IP address. To
	// aggregate on only the IP address, in your rate-based statement's AggregateKeyType,
	// specify IP.
	//
	// JSON specification: "RateLimitIP": {}
	IP map[string]*string `json:"iP,omitempty"`
	// Specifies a label namespace to use as an aggregate key for a rate-based rule.
	// Each distinct fully qualified label name that has the specified label namespace
	// contributes to the aggregation instance. If you use just one label namespace
	// as your custom key, then each label name fully defines an aggregation instance.
	//
	// This uses only labels that have been added to the request by rules that are
	// evaluated before this rate-based rule in the web ACL.
	//
	// For information about label namespaces and names, see Label syntax and naming
	// requirements (https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-label-requirements.html)
	// in the WAF Developer Guide.
	LabelNamespace *RateLimitLabelNamespace `json:"labelNamespace,omitempty"`
	// Specifies a query argument in the request as an aggregate key for a rate-based
	// rule. Each distinct value for the named query argument contributes to the
	// aggregation instance. If you use a single query argument as your custom key,
	// then each value fully defines an aggregation instance.
	QueryArgument *RateLimitQueryArgument `json:"queryArgument,omitempty"`
	// Specifies the request's query string as an aggregate key for a rate-based
	// rule. Each distinct string contributes to the aggregation instance. If you
	// use just the query string as your custom key, then each string fully defines
	// an aggregation instance.
	QueryString *RateLimitQueryString `json:"queryString,omitempty"`
	// Specifies the request's URI path as an aggregate key for a rate-based rule.
	// Each distinct URI path contributes to the aggregation instance. If you use
	// just the URI path as your custom key, then each URI path fully defines an
	// aggregation instance.
	URIPath *RateLimitURIPath `json:"uriPath,omitempty"`
}

// +kubebuilder:skipversion
type RateLimitCookie struct {
	Name *string `json:"name,omitempty"`

	TextTransformations []*TextTransformation `json:"textTransformations,omitempty"`
}

// +kubebuilder:skipversion
type RateLimitHeader struct {
	Name *string `json:"name,omitempty"`

	TextTransformations []*TextTransformation `json:"textTransformations,omitempty"`
}

// +kubebuilder:skipversion
type RateLimitLabelNamespace struct {
	Namespace *string `json:"namespace,omitempty"`
}

// +kubebuilder:skipversion
type RateLimitQueryArgument struct {
	Name *string `json:"name,omitempty"`

	TextTransformations []*TextTransformation `json:"textTransformations,omitempty"`
}

// +kubebuilder:skipversion
type RateLimitQueryString struct {
	TextTransformations []*TextTransformation `json:"textTransformations,omitempty"`
}

// +kubebuilder:skipversion
type RateLimitURIPath struct {
	TextTransformations []*TextTransformation `json:"textTransformations,omitempty"`
}

// +kubebuilder:skipversion
type Regex struct {
	RegexString *string `json:"regexString,omitempty"`
}

// +kubebuilder:skipversion
type RegexMatchStatement struct {
	// The part of the web request that you want WAF to inspect. Include the single
	// FieldToMatch type that you want to inspect, with additional specifications
	// as needed, according to the type. You specify a single request component
	// in FieldToMatch for each rule statement that requires it. To inspect more
	// than one component of the web request, create a separate rule statement for
	// each component.
	//
	// Example JSON for a QueryString field to match:
	//
	// "FieldToMatch": { "QueryString": {} }
	//
	// Example JSON for a Method field to match specification:
	//
	// "FieldToMatch": { "Method": { "Name": "DELETE" } }
	FieldToMatch *FieldToMatch `json:"fieldToMatch,omitempty"`

	RegexString *string `json:"regexString,omitempty"`

	TextTransformations []*TextTransformation `json:"textTransformations,omitempty"`
}

// +kubebuilder:skipversion
type RegexPatternSet struct {
	ARN *string `json:"arn,omitempty"`

	Description *string `json:"description,omitempty"`

	ID *string `json:"id,omitempty"`

	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type RegexPatternSetReferenceStatement struct {
	ARN *string `json:"arn,omitempty"`
	// The part of the web request that you want WAF to inspect. Include the single
	// FieldToMatch type that you want to inspect, with additional specifications
	// as needed, according to the type. You specify a single request component
	// in FieldToMatch for each rule statement that requires it. To inspect more
	// than one component of the web request, create a separate rule statement for
	// each component.
	//
	// Example JSON for a QueryString field to match:
	//
	// "FieldToMatch": { "QueryString": {} }
	//
	// Example JSON for a Method field to match specification:
	//
	// "FieldToMatch": { "Method": { "Name": "DELETE" } }
	FieldToMatch *FieldToMatch `json:"fieldToMatch,omitempty"`

	TextTransformations []*TextTransformation `json:"textTransformations,omitempty"`
}

// +kubebuilder:skipversion
type RegexPatternSetSummary struct {
	ARN *string `json:"arn,omitempty"`

	Description *string `json:"description,omitempty"`

	ID *string `json:"id,omitempty"`

	LockToken *string `json:"lockToken,omitempty"`

	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type ReleaseSummary struct {
	ReleaseVersion *string `json:"releaseVersion,omitempty"`
}

// +kubebuilder:skipversion
type RequestBodyAssociatedResourceTypeConfig struct {
	DefaultSizeInspectionLimit *string `json:"defaultSizeInspectionLimit,omitempty"`
}

// +kubebuilder:skipversion
type RequestInspection struct {
	// The name of the field in the request payload that contains your customer's
	// password.
	//
	// This data type is used in the RequestInspection and RequestInspectionACFP
	// data types.
	PasswordField *PasswordField `json:"passwordField,omitempty"`

	PayloadType *string `json:"payloadType,omitempty"`
	// The name of the field in the request payload that contains your customer's
	// username.
	//
	// This data type is used in the RequestInspection and RequestInspectionACFP
	// data types.
	UsernameField *UsernameField `json:"usernameField,omitempty"`
}

// +kubebuilder:skipversion
type RequestInspectionACFP struct {
	AddressFields []*AddressField `json:"addressFields,omitempty"`
	// The name of the field in the request payload that contains your customer's
	// email.
	//
	// This data type is used in the RequestInspectionACFP data type.
	EmailField *EmailField `json:"emailField,omitempty"`
	// The name of the field in the request payload that contains your customer's
	// password.
	//
	// This data type is used in the RequestInspection and RequestInspectionACFP
	// data types.
	PasswordField *PasswordField `json:"passwordField,omitempty"`

	PayloadType *string `json:"payloadType,omitempty"`

	PhoneNumberFields []*PhoneNumberField `json:"phoneNumberFields,omitempty"`
	// The name of the field in the request payload that contains your customer's
	// username.
	//
	// This data type is used in the RequestInspection and RequestInspectionACFP
	// data types.
	UsernameField *UsernameField `json:"usernameField,omitempty"`
}

// +kubebuilder:skipversion
type ResponseInspection struct {
	// Configures inspection of the response body. WAF can inspect the first 65,536
	// bytes (64 KB) of the response body. This is part of the ResponseInspection
	// configuration for AWSManagedRulesATPRuleSet and AWSManagedRulesACFPRuleSet.
	//
	// Response inspection is available only in web ACLs that protect Amazon CloudFront
	// distributions.
	BodyContains *ResponseInspectionBodyContains `json:"bodyContains,omitempty"`
	// Configures inspection of the response header. This is part of the ResponseInspection
	// configuration for AWSManagedRulesATPRuleSet and AWSManagedRulesACFPRuleSet.
	//
	// Response inspection is available only in web ACLs that protect Amazon CloudFront
	// distributions.
	Header *ResponseInspectionHeader `json:"header,omitempty"`
	// Configures inspection of the response JSON. WAF can inspect the first 65,536
	// bytes (64 KB) of the response JSON. This is part of the ResponseInspection
	// configuration for AWSManagedRulesATPRuleSet and AWSManagedRulesACFPRuleSet.
	//
	// Response inspection is available only in web ACLs that protect Amazon CloudFront
	// distributions.
	JSON *ResponseInspectionJSON `json:"json,omitempty"`
	// Configures inspection of the response status code. This is part of the ResponseInspection
	// configuration for AWSManagedRulesATPRuleSet and AWSManagedRulesACFPRuleSet.
	//
	// Response inspection is available only in web ACLs that protect Amazon CloudFront
	// distributions.
	StatusCode *ResponseInspectionStatusCode `json:"statusCode,omitempty"`
}

// +kubebuilder:skipversion
type ResponseInspectionBodyContains struct {
	FailureStrings []*string `json:"failureStrings,omitempty"`

	SuccessStrings []*string `json:"successStrings,omitempty"`
}

// +kubebuilder:skipversion
type ResponseInspectionHeader struct {
	FailureValues []*string `json:"failureValues,omitempty"`

	Name *string `json:"name,omitempty"`

	SuccessValues []*string `json:"successValues,omitempty"`
}

// +kubebuilder:skipversion
type ResponseInspectionJSON struct {
	FailureValues []*string `json:"failureValues,omitempty"`

	Identifier *string `json:"identifier,omitempty"`

	SuccessValues []*string `json:"successValues,omitempty"`
}

// +kubebuilder:skipversion
type ResponseInspectionStatusCode struct {
	FailureCodes []*int64 `json:"failureCodes,omitempty"`

	SuccessCodes []*int64 `json:"successCodes,omitempty"`
}

// +kubebuilder:skipversion
type Rule struct {
	// The action that WAF should take on a web request when it matches a rule's
	// statement. Settings at the web ACL level can override the rule action setting.
	Action *RuleAction `json:"action,omitempty"`
	// Specifies how WAF should handle CAPTCHA evaluations. This is available at
	// the web ACL level and in each rule.
	CaptchaConfig *CaptchaConfig `json:"captchaConfig,omitempty"`
	// Specifies how WAF should handle Challenge evaluations. This is available
	// at the web ACL level and in each rule.
	ChallengeConfig *ChallengeConfig `json:"challengeConfig,omitempty"`

	Name *string `json:"name,omitempty"`
	// The action to use in the place of the action that results from the rule group
	// evaluation. Set the override action to none to leave the result of the rule
	// group alone. Set it to count to override the result to count only.
	//
	// You can only use this for rule statements that reference a rule group, like
	// RuleGroupReferenceStatement and ManagedRuleGroupStatement.
	//
	// This option is usually set to none. It does not affect how the rules in the
	// rule group are evaluated. If you want the rules in the rule group to only
	// count matches, do not use this and instead use the rule action override option,
	// with Count action, in your rule group reference statement settings.
	OverrideAction *OverrideAction `json:"overrideAction,omitempty"`

	Priority *int64 `json:"priority,omitempty"`

	RuleLabels []*Label `json:"ruleLabels,omitempty"`
	// The processing guidance for a Rule, used by WAF to determine whether a web
	// request matches the rule.
	//
	// For example specifications, see the examples section of CreateWebACL.
	Statement *Statement `json:"statement,omitempty"`
	// Defines and enables Amazon CloudWatch metrics and web request sample collection.
	VisibilityConfig *VisibilityConfig `json:"visibilityConfig,omitempty"`
}

// +kubebuilder:skipversion
type RuleAction struct {
	// Specifies that WAF should allow the request and optionally defines additional
	// custom handling for the request.
	//
	// This is used in the context of other settings, for example to specify values
	// for RuleAction and web ACL DefaultAction.
	Allow *AllowAction `json:"allow,omitempty"`
	// Specifies that WAF should block the request and optionally defines additional
	// custom handling for the response to the web request.
	//
	// This is used in the context of other settings, for example to specify values
	// for RuleAction and web ACL DefaultAction.
	Block *BlockAction `json:"block,omitempty"`
	// Specifies that WAF should run a CAPTCHA check against the request:
	//
	//    * If the request includes a valid, unexpired CAPTCHA token, WAF applies
	//    any custom request handling and labels that you've configured and then
	//    allows the web request inspection to proceed to the next rule, similar
	//    to a CountAction.
	//
	//    * If the request doesn't include a valid, unexpired token, WAF discontinues
	//    the web ACL evaluation of the request and blocks it from going to its
	//    intended destination. WAF generates a response that it sends back to the
	//    client, which includes the following: The header x-amzn-waf-action with
	//    a value of captcha. The HTTP status code 405 Method Not Allowed. If the
	//    request contains an Accept header with a value of text/html, the response
	//    includes a CAPTCHA JavaScript page interstitial.
	//
	// You can configure the expiration time in the CaptchaConfig ImmunityTimeProperty
	// setting at the rule and web ACL level. The rule setting overrides the web
	// ACL setting.
	//
	// This action option is available for rules. It isn't available for web ACL
	// default actions.
	Captcha *CaptchaAction `json:"captcha,omitempty"`
	// Specifies that WAF should run a Challenge check against the request to verify
	// that the request is coming from a legitimate client session:
	//
	//    * If the request includes a valid, unexpired challenge token, WAF applies
	//    any custom request handling and labels that you've configured and then
	//    allows the web request inspection to proceed to the next rule, similar
	//    to a CountAction.
	//
	//    * If the request doesn't include a valid, unexpired challenge token, WAF
	//    discontinues the web ACL evaluation of the request and blocks it from
	//    going to its intended destination. WAF then generates a challenge response
	//    that it sends back to the client, which includes the following: The header
	//    x-amzn-waf-action with a value of challenge. The HTTP status code 202
	//    Request Accepted. If the request contains an Accept header with a value
	//    of text/html, the response includes a JavaScript page interstitial with
	//    a challenge script. Challenges run silent browser interrogations in the
	//    background, and don't generally affect the end user experience. A challenge
	//    enforces token acquisition using an interstitial JavaScript challenge
	//    that inspects the client session for legitimate behavior. The challenge
	//    blocks bots or at least increases the cost of operating sophisticated
	//    bots. After the client session successfully responds to the challenge,
	//    it receives a new token from WAF, which the challenge script uses to resubmit
	//    the original request.
	//
	// You can configure the expiration time in the ChallengeConfig ImmunityTimeProperty
	// setting at the rule and web ACL level. The rule setting overrides the web
	// ACL setting.
	//
	// This action option is available for rules. It isn't available for web ACL
	// default actions.
	Challenge *ChallengeAction `json:"challenge,omitempty"`
	// Specifies that WAF should count the request. Optionally defines additional
	// custom handling for the request.
	//
	// This is used in the context of other settings, for example to specify values
	// for RuleAction and web ACL DefaultAction.
	Count *CountAction `json:"count,omitempty"`
}

// +kubebuilder:skipversion
type RuleActionOverride struct {
	// The action that WAF should take on a web request when it matches a rule's
	// statement. Settings at the web ACL level can override the rule action setting.
	ActionToUse *RuleAction `json:"actionToUse,omitempty"`

	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type RuleGroup struct {
	ARN *string `json:"arn,omitempty"`

	CustomResponseBodies map[string]*CustomResponseBody `json:"customResponseBodies,omitempty"`

	Description *string `json:"description,omitempty"`

	ID *string `json:"id,omitempty"`

	LabelNamespace *string `json:"labelNamespace,omitempty"`

	Name *string `json:"name,omitempty"`

	Rules []*Rule `json:"rules,omitempty"`
	// Defines and enables Amazon CloudWatch metrics and web request sample collection.
	VisibilityConfig *VisibilityConfig `json:"visibilityConfig,omitempty"`
}

// +kubebuilder:skipversion
type RuleGroupReferenceStatement struct {
	ARN *string `json:"arn,omitempty"`

	ExcludedRules []*ExcludedRule `json:"excludedRules,omitempty"`

	RuleActionOverrides []*RuleActionOverride `json:"ruleActionOverrides,omitempty"`
}

// +kubebuilder:skipversion
type RuleGroupSummary struct {
	ARN *string `json:"arn,omitempty"`

	Description *string `json:"description,omitempty"`

	ID *string `json:"id,omitempty"`

	LockToken *string `json:"lockToken,omitempty"`

	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type RuleSummary struct {
	// The action that WAF should take on a web request when it matches a rule's
	// statement. Settings at the web ACL level can override the rule action setting.
	Action *RuleAction `json:"action,omitempty"`

	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type SQLIMatchStatement struct {
	// The part of the web request that you want WAF to inspect. Include the single
	// FieldToMatch type that you want to inspect, with additional specifications
	// as needed, according to the type. You specify a single request component
	// in FieldToMatch for each rule statement that requires it. To inspect more
	// than one component of the web request, create a separate rule statement for
	// each component.
	//
	// Example JSON for a QueryString field to match:
	//
	// "FieldToMatch": { "QueryString": {} }
	//
	// Example JSON for a Method field to match specification:
	//
	// "FieldToMatch": { "Method": { "Name": "DELETE" } }
	FieldToMatch *FieldToMatch `json:"fieldToMatch,omitempty"`

	SensitivityLevel *string `json:"sensitivityLevel,omitempty"`

	TextTransformations []*TextTransformation `json:"textTransformations,omitempty"`
}

// +kubebuilder:skipversion
type SampledHTTPRequest struct {
	Labels []*Label `json:"labels,omitempty"`

	ResponseCodeSent *int64 `json:"responseCodeSent,omitempty"`

	RuleNameWithinRuleGroup *string `json:"ruleNameWithinRuleGroup,omitempty"`
}

// +kubebuilder:skipversion
type SingleHeader struct {
	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type SingleQueryArgument struct {
	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type SizeConstraintStatement struct {
	ComparisonOperator *string `json:"comparisonOperator,omitempty"`
	// The part of the web request that you want WAF to inspect. Include the single
	// FieldToMatch type that you want to inspect, with additional specifications
	// as needed, according to the type. You specify a single request component
	// in FieldToMatch for each rule statement that requires it. To inspect more
	// than one component of the web request, create a separate rule statement for
	// each component.
	//
	// Example JSON for a QueryString field to match:
	//
	// "FieldToMatch": { "QueryString": {} }
	//
	// Example JSON for a Method field to match specification:
	//
	// "FieldToMatch": { "Method": { "Name": "DELETE" } }
	FieldToMatch *FieldToMatch `json:"fieldToMatch,omitempty"`

	Size *int64 `json:"size,omitempty"`

	TextTransformations []*TextTransformation `json:"textTransformations,omitempty"`
}

// +kubebuilder:skipversion
type Statement struct {
	AndStatement *string `json:"andStatement,omitempty"`
	// A rule statement that defines a string match search for WAF to apply to web
	// requests. The byte match statement provides the bytes to search for, the
	// location in requests that you want WAF to search, and other settings. The
	// bytes to search for are typically a string that corresponds with ASCII characters.
	// In the WAF console and the developer guide, this is called a string match
	// statement.
	ByteMatchStatement *ByteMatchStatement `json:"byteMatchStatement,omitempty"`
	// A rule statement that labels web requests by country and region and that
	// matches against web requests based on country code. A geo match rule labels
	// every request that it inspects regardless of whether it finds a match.
	//
	//    * To manage requests only by country, you can use this statement by itself
	//    and specify the countries that you want to match against in the CountryCodes
	//    array.
	//
	//    * Otherwise, configure your geo match rule with Count action so that it
	//    only labels requests. Then, add one or more label match rules to run after
	//    the geo match rule and configure them to match against the geographic
	//    labels and handle the requests as needed.
	//
	// WAF labels requests using the alpha-2 country and region codes from the International
	// Organization for Standardization (ISO) 3166 standard. WAF determines the
	// codes using either the IP address in the web request origin or, if you specify
	// it, the address in the geo match ForwardedIPConfig.
	//
	// If you use the web request origin, the label formats are awswaf:clientip:geo:region:<ISO
	// country code>-<ISO region code> and awswaf:clientip:geo:country:<ISO country
	// code>.
	//
	// If you use a forwarded IP address, the label formats are awswaf:forwardedip:geo:region:<ISO
	// country code>-<ISO region code> and awswaf:forwardedip:geo:country:<ISO country
	// code>.
	//
	// For additional details, see Geographic match rule statement (https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-geo-match.html)
	// in the WAF Developer Guide (https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html).
	GeoMatchStatement *GeoMatchStatement `json:"geoMatchStatement,omitempty"`
	// A rule statement used to detect web requests coming from particular IP addresses
	// or address ranges. To use this, create an IPSet that specifies the addresses
	// you want to detect, then use the ARN of that set in this statement. To create
	// an IP set, see CreateIPSet.
	//
	// Each IP set rule statement references an IP set. You create and maintain
	// the set independent of your rules. This allows you to use the single set
	// in multiple rules. When you update the referenced set, WAF automatically
	// updates all rules that reference it.
	IPSetReferenceStatement *IPSetReferenceStatement `json:"ipSetReferenceStatement,omitempty"`
	// A rule statement to match against labels that have been added to the web
	// request by rules that have already run in the web ACL.
	//
	// The label match statement provides the label or namespace string to search
	// for. The label string can represent a part or all of the fully qualified
	// label name that had been added to the web request. Fully qualified labels
	// have a prefix, optional namespaces, and label name. The prefix identifies
	// the rule group or web ACL context of the rule that added the label. If you
	// do not provide the fully qualified name in your label match string, WAF performs
	// the search for labels that were added in the same context as the label match
	// statement.
	LabelMatchStatement *LabelMatchStatement `json:"labelMatchStatement,omitempty"`
	// A rule statement used to run the rules that are defined in a managed rule
	// group. To use this, provide the vendor name and the name of the rule group
	// in this statement. You can retrieve the required names by calling ListAvailableManagedRuleGroups.
	//
	// You cannot nest a ManagedRuleGroupStatement, for example for use inside a
	// NotStatement or OrStatement. You cannot use a managed rule group inside another
	// rule group. You can only reference a managed rule group as a top-level statement
	// within a rule that you define in a web ACL.
	//
	// You are charged additional fees when you use the WAF Bot Control managed
	// rule group AWSManagedRulesBotControlRuleSet, the WAF Fraud Control account
	// takeover prevention (ATP) managed rule group AWSManagedRulesATPRuleSet, or
	// the WAF Fraud Control account creation fraud prevention (ACFP) managed rule
	// group AWSManagedRulesACFPRuleSet. For more information, see WAF Pricing (http://aws.amazon.com/waf/pricing/).
	ManagedRuleGroupStatement *ManagedRuleGroupStatement `json:"managedRuleGroupStatement,omitempty"`

	NotStatement *string `json:"notStatement,omitempty"`

	OrStatement *string `json:"orStatement,omitempty"`
	// A rate-based rule counts incoming requests and rate limits requests when
	// they are coming at too fast a rate. The rule categorizes requests according
	// to your aggregation criteria, collects them into aggregation instances, and
	// counts and rate limits the requests for each instance.
	//
	// You can specify individual aggregation keys, like IP address or HTTP method.
	// You can also specify aggregation key combinations, like IP address and HTTP
	// method, or HTTP method, query argument, and cookie.
	//
	// Each unique set of values for the aggregation keys that you specify is a
	// separate aggregation instance, with the value from each key contributing
	// to the aggregation instance definition.
	//
	// For example, assume the rule evaluates web requests with the following IP
	// address and HTTP method values:
	//
	//    * IP address 10.1.1.1, HTTP method POST
	//
	//    * IP address 10.1.1.1, HTTP method GET
	//
	//    * IP address 127.0.0.0, HTTP method POST
	//
	//    * IP address 10.1.1.1, HTTP method GET
	//
	// The rule would create different aggregation instances according to your aggregation
	// criteria, for example:
	//
	//    * If the aggregation criteria is just the IP address, then each individual
	//    address is an aggregation instance, and WAF counts requests separately
	//    for each. The aggregation instances and request counts for our example
	//    would be the following: IP address 10.1.1.1: count 3 IP address 127.0.0.0:
	//    count 1
	//
	//    * If the aggregation criteria is HTTP method, then each individual HTTP
	//    method is an aggregation instance. The aggregation instances and request
	//    counts for our example would be the following: HTTP method POST: count
	//    2 HTTP method GET: count 2
	//
	//    * If the aggregation criteria is IP address and HTTP method, then each
	//    IP address and each HTTP method would contribute to the combined aggregation
	//    instance. The aggregation instances and request counts for our example
	//    would be the following: IP address 10.1.1.1, HTTP method POST: count 1
	//    IP address 10.1.1.1, HTTP method GET: count 2 IP address 127.0.0.0, HTTP
	//    method POST: count 1
	//
	// For any n-tuple of aggregation keys, each unique combination of values for
	// the keys defines a separate aggregation instance, which WAF counts and rate-limits
	// individually.
	//
	// You can optionally nest another statement inside the rate-based statement,
	// to narrow the scope of the rule so that it only counts and rate limits requests
	// that match the nested statement. You can use this nested scope-down statement
	// in conjunction with your aggregation key specifications or you can just count
	// and rate limit all requests that match the scope-down statement, without
	// additional aggregation. When you choose to just manage all requests that
	// match a scope-down statement, the aggregation instance is singular for the
	// rule.
	//
	// You cannot nest a RateBasedStatement inside another statement, for example
	// inside a NotStatement or OrStatement. You can define a RateBasedStatement
	// inside a web ACL and inside a rule group.
	//
	// For additional information about the options, see Rate limiting web requests
	// using rate-based rules (https://docs.aws.amazon.com/waf/latest/developerguide/waf-rate-based-rules.html)
	// in the WAF Developer Guide.
	//
	// If you only aggregate on the individual IP address or forwarded IP address,
	// you can retrieve the list of IP addresses that WAF is currently rate limiting
	// for a rule through the API call GetRateBasedStatementManagedKeys. This option
	// is not available for other aggregation configurations.
	//
	// WAF tracks and manages web requests separately for each instance of a rate-based
	// rule that you use. For example, if you provide the same rate-based rule settings
	// in two web ACLs, each of the two rule statements represents a separate instance
	// of the rate-based rule and gets its own tracking and management by WAF. If
	// you define a rate-based rule inside a rule group, and then use that rule
	// group in multiple places, each use creates a separate instance of the rate-based
	// rule that gets its own tracking and management by WAF.
	RateBasedStatement *RateBasedStatement `json:"rateBasedStatement,omitempty"`
	// A rule statement used to search web request components for a match against
	// a single regular expression.
	RegexMatchStatement *RegexMatchStatement `json:"regexMatchStatement,omitempty"`
	// A rule statement used to search web request components for matches with regular
	// expressions. To use this, create a RegexPatternSet that specifies the expressions
	// that you want to detect, then use the ARN of that set in this statement.
	// A web request matches the pattern set rule statement if the request component
	// matches any of the patterns in the set. To create a regex pattern set, see
	// CreateRegexPatternSet.
	//
	// Each regex pattern set rule statement references a regex pattern set. You
	// create and maintain the set independent of your rules. This allows you to
	// use the single set in multiple rules. When you update the referenced set,
	// WAF automatically updates all rules that reference it.
	RegexPatternSetReferenceStatement *RegexPatternSetReferenceStatement `json:"regexPatternSetReferenceStatement,omitempty"`
	// A rule statement used to run the rules that are defined in a RuleGroup. To
	// use this, create a rule group with your rules, then provide the ARN of the
	// rule group in this statement.
	//
	// You cannot nest a RuleGroupReferenceStatement, for example for use inside
	// a NotStatement or OrStatement. You cannot use a rule group reference statement
	// inside another rule group. You can only reference a rule group as a top-level
	// statement within a rule that you define in a web ACL.
	RuleGroupReferenceStatement *RuleGroupReferenceStatement `json:"ruleGroupReferenceStatement,omitempty"`
	// A rule statement that compares a number of bytes against the size of a request
	// component, using a comparison operator, such as greater than (>) or less
	// than (<). For example, you can use a size constraint statement to look for
	// query strings that are longer than 100 bytes.
	//
	// If you configure WAF to inspect the request body, WAF inspects only the number
	// of bytes of the body up to the limit for the web ACL. By default, for regional
	// web ACLs, this limit is 8 KB (8,192 bytes) and for CloudFront web ACLs, this
	// limit is 16 KB (16,384 bytes). For CloudFront web ACLs, you can increase
	// the limit in the web ACL AssociationConfig, for additional fees. If you know
	// that the request body for your web requests should never exceed the inspection
	// limit, you could use a size constraint statement to block requests that have
	// a larger request body size.
	//
	// If you choose URI for the value of Part of the request to filter on, the
	// slash (/) in the URI counts as one character. For example, the URI /logo.jpg
	// is nine characters long.
	SizeConstraintStatement *SizeConstraintStatement `json:"sizeConstraintStatement,omitempty"`
	// A rule statement that inspects for malicious SQL code. Attackers insert malicious
	// SQL code into web requests to do things like modify your database or extract
	// data from it.
	SQLIMatchStatement *SQLIMatchStatement `json:"sqliMatchStatement,omitempty"`
	// A rule statement that inspects for cross-site scripting (XSS) attacks. In
	// XSS attacks, the attacker uses vulnerabilities in a benign website as a vehicle
	// to inject malicious client-site scripts into other legitimate web browsers.
	XSSMatchStatement *XSSMatchStatement `json:"xssMatchStatement,omitempty"`
}

// +kubebuilder:skipversion
type Tag struct {
	Key *string `json:"key,omitempty"`

	Value *string `json:"value,omitempty"`
}

// +kubebuilder:skipversion
type TagInfoForResource struct {
	ResourceARN *string `json:"resourceARN,omitempty"`

	TagList []*Tag `json:"tagList,omitempty"`
}

// +kubebuilder:skipversion
type TextTransformation struct {
	Priority *int64 `json:"priority,omitempty"`

	Type *string `json:"type_,omitempty"`
}

// +kubebuilder:skipversion
type UsernameField struct {
	Identifier *string `json:"identifier,omitempty"`
}

// +kubebuilder:skipversion
type VersionToPublish struct {
	AssociatedRuleGroupARN *string `json:"associatedRuleGroupARN,omitempty"`
}

// +kubebuilder:skipversion
type VisibilityConfig struct {
	CloudWatchMetricsEnabled *bool `json:"cloudWatchMetricsEnabled,omitempty"`

	MetricName *string `json:"metricName,omitempty"`

	SampledRequestsEnabled *bool `json:"sampledRequestsEnabled,omitempty"`
}

// +kubebuilder:skipversion
type WebACLSummary struct {
	ARN *string `json:"arn,omitempty"`

	Description *string `json:"description,omitempty"`

	ID *string `json:"id,omitempty"`

	LockToken *string `json:"lockToken,omitempty"`

	Name *string `json:"name,omitempty"`
}

// +kubebuilder:skipversion
type WebACL_SDK struct {
	ARN *string `json:"arn,omitempty"`
	// Specifies custom configurations for the associations between the web ACL
	// and protected resources.
	//
	// Use this to customize the maximum size of the request body that your protected
	// CloudFront distributions forward to WAF for inspection. The default is 16
	// KB (16,384 bytes).
	//
	// You are charged additional fees when your protected resources forward body
	// sizes that are larger than the default. For more information, see WAF Pricing
	// (http://aws.amazon.com/waf/pricing/).
	AssociationConfig *AssociationConfig `json:"associationConfig,omitempty"`
	// Specifies how WAF should handle CAPTCHA evaluations. This is available at
	// the web ACL level and in each rule.
	CaptchaConfig *CaptchaConfig `json:"captchaConfig,omitempty"`
	// Specifies how WAF should handle Challenge evaluations. This is available
	// at the web ACL level and in each rule.
	ChallengeConfig *ChallengeConfig `json:"challengeConfig,omitempty"`

	CustomResponseBodies map[string]*CustomResponseBody `json:"customResponseBodies,omitempty"`
	// In a WebACL, this is the action that you want WAF to perform when a web request
	// doesn't match any of the rules in the WebACL. The default action must be
	// a terminating action.
	DefaultAction *DefaultAction `json:"defaultAction,omitempty"`

	Description *string `json:"description,omitempty"`

	ID *string `json:"id,omitempty"`

	LabelNamespace *string `json:"labelNamespace,omitempty"`

	ManagedByFirewallManager *bool `json:"managedByFirewallManager,omitempty"`

	Name *string `json:"name,omitempty"`

	Rules []*Rule `json:"rules,omitempty"`

	TokenDomains []*string `json:"tokenDomains,omitempty"`
	// Defines and enables Amazon CloudWatch metrics and web request sample collection.
	VisibilityConfig *VisibilityConfig `json:"visibilityConfig,omitempty"`
}

// +kubebuilder:skipversion
type XSSMatchStatement struct {
	// The part of the web request that you want WAF to inspect. Include the single
	// FieldToMatch type that you want to inspect, with additional specifications
	// as needed, according to the type. You specify a single request component
	// in FieldToMatch for each rule statement that requires it. To inspect more
	// than one component of the web request, create a separate rule statement for
	// each component.
	//
	// Example JSON for a QueryString field to match:
	//
	// "FieldToMatch": { "QueryString": {} }
	//
	// Example JSON for a Method field to match specification:
	//
	// "FieldToMatch": { "Method": { "Name": "DELETE" } }
	FieldToMatch *FieldToMatch `json:"fieldToMatch,omitempty"`

	TextTransformations []*TextTransformation `json:"textTransformations,omitempty"`
}