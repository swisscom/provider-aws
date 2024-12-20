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

package manualv1alpha1

type ActionValue string

const (
	ActionValue_ALLOW             ActionValue = "ALLOW"
	ActionValue_BLOCK             ActionValue = "BLOCK"
	ActionValue_COUNT             ActionValue = "COUNT"
	ActionValue_CAPTCHA           ActionValue = "CAPTCHA"
	ActionValue_CHALLENGE         ActionValue = "CHALLENGE"
	ActionValue_EXCLUDED_AS_COUNT ActionValue = "EXCLUDED_AS_COUNT"
)

type AssociatedResourceType string

const (
	AssociatedResourceType_CLOUDFRONT AssociatedResourceType = "CLOUDFRONT"
)

type BodyParsingFallbackBehavior string

const (
	BodyParsingFallbackBehavior_MATCH              BodyParsingFallbackBehavior = "MATCH"
	BodyParsingFallbackBehavior_NO_MATCH           BodyParsingFallbackBehavior = "NO_MATCH"
	BodyParsingFallbackBehavior_EVALUATE_AS_STRING BodyParsingFallbackBehavior = "EVALUATE_AS_STRING"
)

type ComparisonOperator string

const (
	ComparisonOperator_EQ ComparisonOperator = "EQ"
	ComparisonOperator_NE ComparisonOperator = "NE"
	ComparisonOperator_LE ComparisonOperator = "LE"
	ComparisonOperator_LT ComparisonOperator = "LT"
	ComparisonOperator_GE ComparisonOperator = "GE"
	ComparisonOperator_GT ComparisonOperator = "GT"
)

type CountryCode string

const (
	CountryCode_AF CountryCode = "AF"
	CountryCode_AX CountryCode = "AX"
	CountryCode_AL CountryCode = "AL"
	CountryCode_DZ CountryCode = "DZ"
	CountryCode_AS CountryCode = "AS"
	CountryCode_AD CountryCode = "AD"
	CountryCode_AO CountryCode = "AO"
	CountryCode_AI CountryCode = "AI"
	CountryCode_AQ CountryCode = "AQ"
	CountryCode_AG CountryCode = "AG"
	CountryCode_AR CountryCode = "AR"
	CountryCode_AM CountryCode = "AM"
	CountryCode_AW CountryCode = "AW"
	CountryCode_AU CountryCode = "AU"
	CountryCode_AT CountryCode = "AT"
	CountryCode_AZ CountryCode = "AZ"
	CountryCode_BS CountryCode = "BS"
	CountryCode_BH CountryCode = "BH"
	CountryCode_BD CountryCode = "BD"
	CountryCode_BB CountryCode = "BB"
	CountryCode_BY CountryCode = "BY"
	CountryCode_BE CountryCode = "BE"
	CountryCode_BZ CountryCode = "BZ"
	CountryCode_BJ CountryCode = "BJ"
	CountryCode_BM CountryCode = "BM"
	CountryCode_BT CountryCode = "BT"
	CountryCode_BO CountryCode = "BO"
	CountryCode_BQ CountryCode = "BQ"
	CountryCode_BA CountryCode = "BA"
	CountryCode_BW CountryCode = "BW"
	CountryCode_BV CountryCode = "BV"
	CountryCode_BR CountryCode = "BR"
	CountryCode_IO CountryCode = "IO"
	CountryCode_BN CountryCode = "BN"
	CountryCode_BG CountryCode = "BG"
	CountryCode_BF CountryCode = "BF"
	CountryCode_BI CountryCode = "BI"
	CountryCode_KH CountryCode = "KH"
	CountryCode_CM CountryCode = "CM"
	CountryCode_CA CountryCode = "CA"
	CountryCode_CV CountryCode = "CV"
	CountryCode_KY CountryCode = "KY"
	CountryCode_CF CountryCode = "CF"
	CountryCode_TD CountryCode = "TD"
	CountryCode_CL CountryCode = "CL"
	CountryCode_CN CountryCode = "CN"
	CountryCode_CX CountryCode = "CX"
	CountryCode_CC CountryCode = "CC"
	CountryCode_CO CountryCode = "CO"
	CountryCode_KM CountryCode = "KM"
	CountryCode_CG CountryCode = "CG"
	CountryCode_CD CountryCode = "CD"
	CountryCode_CK CountryCode = "CK"
	CountryCode_CR CountryCode = "CR"
	CountryCode_CI CountryCode = "CI"
	CountryCode_HR CountryCode = "HR"
	CountryCode_CU CountryCode = "CU"
	CountryCode_CW CountryCode = "CW"
	CountryCode_CY CountryCode = "CY"
	CountryCode_CZ CountryCode = "CZ"
	CountryCode_DK CountryCode = "DK"
	CountryCode_DJ CountryCode = "DJ"
	CountryCode_DM CountryCode = "DM"
	CountryCode_DO CountryCode = "DO"
	CountryCode_EC CountryCode = "EC"
	CountryCode_EG CountryCode = "EG"
	CountryCode_SV CountryCode = "SV"
	CountryCode_GQ CountryCode = "GQ"
	CountryCode_ER CountryCode = "ER"
	CountryCode_EE CountryCode = "EE"
	CountryCode_ET CountryCode = "ET"
	CountryCode_FK CountryCode = "FK"
	CountryCode_FO CountryCode = "FO"
	CountryCode_FJ CountryCode = "FJ"
	CountryCode_FI CountryCode = "FI"
	CountryCode_FR CountryCode = "FR"
	CountryCode_GF CountryCode = "GF"
	CountryCode_PF CountryCode = "PF"
	CountryCode_TF CountryCode = "TF"
	CountryCode_GA CountryCode = "GA"
	CountryCode_GM CountryCode = "GM"
	CountryCode_GE CountryCode = "GE"
	CountryCode_DE CountryCode = "DE"
	CountryCode_GH CountryCode = "GH"
	CountryCode_GI CountryCode = "GI"
	CountryCode_GR CountryCode = "GR"
	CountryCode_GL CountryCode = "GL"
	CountryCode_GD CountryCode = "GD"
	CountryCode_GP CountryCode = "GP"
	CountryCode_GU CountryCode = "GU"
	CountryCode_GT CountryCode = "GT"
	CountryCode_GG CountryCode = "GG"
	CountryCode_GN CountryCode = "GN"
	CountryCode_GW CountryCode = "GW"
	CountryCode_GY CountryCode = "GY"
	CountryCode_HT CountryCode = "HT"
	CountryCode_HM CountryCode = "HM"
	CountryCode_VA CountryCode = "VA"
	CountryCode_HN CountryCode = "HN"
	CountryCode_HK CountryCode = "HK"
	CountryCode_HU CountryCode = "HU"
	CountryCode_IS CountryCode = "IS"
	CountryCode_IN CountryCode = "IN"
	CountryCode_ID CountryCode = "ID"
	CountryCode_IR CountryCode = "IR"
	CountryCode_IQ CountryCode = "IQ"
	CountryCode_IE CountryCode = "IE"
	CountryCode_IM CountryCode = "IM"
	CountryCode_IL CountryCode = "IL"
	CountryCode_IT CountryCode = "IT"
	CountryCode_JM CountryCode = "JM"
	CountryCode_JP CountryCode = "JP"
	CountryCode_JE CountryCode = "JE"
	CountryCode_JO CountryCode = "JO"
	CountryCode_KZ CountryCode = "KZ"
	CountryCode_KE CountryCode = "KE"
	CountryCode_KI CountryCode = "KI"
	CountryCode_KP CountryCode = "KP"
	CountryCode_KR CountryCode = "KR"
	CountryCode_KW CountryCode = "KW"
	CountryCode_KG CountryCode = "KG"
	CountryCode_LA CountryCode = "LA"
	CountryCode_LV CountryCode = "LV"
	CountryCode_LB CountryCode = "LB"
	CountryCode_LS CountryCode = "LS"
	CountryCode_LR CountryCode = "LR"
	CountryCode_LY CountryCode = "LY"
	CountryCode_LI CountryCode = "LI"
	CountryCode_LT CountryCode = "LT"
	CountryCode_LU CountryCode = "LU"
	CountryCode_MO CountryCode = "MO"
	CountryCode_MK CountryCode = "MK"
	CountryCode_MG CountryCode = "MG"
	CountryCode_MW CountryCode = "MW"
	CountryCode_MY CountryCode = "MY"
	CountryCode_MV CountryCode = "MV"
	CountryCode_ML CountryCode = "ML"
	CountryCode_MT CountryCode = "MT"
	CountryCode_MH CountryCode = "MH"
	CountryCode_MQ CountryCode = "MQ"
	CountryCode_MR CountryCode = "MR"
	CountryCode_MU CountryCode = "MU"
	CountryCode_YT CountryCode = "YT"
	CountryCode_MX CountryCode = "MX"
	CountryCode_FM CountryCode = "FM"
	CountryCode_MD CountryCode = "MD"
	CountryCode_MC CountryCode = "MC"
	CountryCode_MN CountryCode = "MN"
	CountryCode_ME CountryCode = "ME"
	CountryCode_MS CountryCode = "MS"
	CountryCode_MA CountryCode = "MA"
	CountryCode_MZ CountryCode = "MZ"
	CountryCode_MM CountryCode = "MM"
	CountryCode_NA CountryCode = "NA"
	CountryCode_NR CountryCode = "NR"
	CountryCode_NP CountryCode = "NP"
	CountryCode_NL CountryCode = "NL"
	CountryCode_NC CountryCode = "NC"
	CountryCode_NZ CountryCode = "NZ"
	CountryCode_NI CountryCode = "NI"
	CountryCode_NE CountryCode = "NE"
	CountryCode_NG CountryCode = "NG"
	CountryCode_NU CountryCode = "NU"
	CountryCode_NF CountryCode = "NF"
	CountryCode_MP CountryCode = "MP"
	CountryCode_NO CountryCode = "NO"
	CountryCode_OM CountryCode = "OM"
	CountryCode_PK CountryCode = "PK"
	CountryCode_PW CountryCode = "PW"
	CountryCode_PS CountryCode = "PS"
	CountryCode_PA CountryCode = "PA"
	CountryCode_PG CountryCode = "PG"
	CountryCode_PY CountryCode = "PY"
	CountryCode_PE CountryCode = "PE"
	CountryCode_PH CountryCode = "PH"
	CountryCode_PN CountryCode = "PN"
	CountryCode_PL CountryCode = "PL"
	CountryCode_PT CountryCode = "PT"
	CountryCode_PR CountryCode = "PR"
	CountryCode_QA CountryCode = "QA"
	CountryCode_RE CountryCode = "RE"
	CountryCode_RO CountryCode = "RO"
	CountryCode_RU CountryCode = "RU"
	CountryCode_RW CountryCode = "RW"
	CountryCode_BL CountryCode = "BL"
	CountryCode_SH CountryCode = "SH"
	CountryCode_KN CountryCode = "KN"
	CountryCode_LC CountryCode = "LC"
	CountryCode_MF CountryCode = "MF"
	CountryCode_PM CountryCode = "PM"
	CountryCode_VC CountryCode = "VC"
	CountryCode_WS CountryCode = "WS"
	CountryCode_SM CountryCode = "SM"
	CountryCode_ST CountryCode = "ST"
	CountryCode_SA CountryCode = "SA"
	CountryCode_SN CountryCode = "SN"
	CountryCode_RS CountryCode = "RS"
	CountryCode_SC CountryCode = "SC"
	CountryCode_SL CountryCode = "SL"
	CountryCode_SG CountryCode = "SG"
	CountryCode_SX CountryCode = "SX"
	CountryCode_SK CountryCode = "SK"
	CountryCode_SI CountryCode = "SI"
	CountryCode_SB CountryCode = "SB"
	CountryCode_SO CountryCode = "SO"
	CountryCode_ZA CountryCode = "ZA"
	CountryCode_GS CountryCode = "GS"
	CountryCode_SS CountryCode = "SS"
	CountryCode_ES CountryCode = "ES"
	CountryCode_LK CountryCode = "LK"
	CountryCode_SD CountryCode = "SD"
	CountryCode_SR CountryCode = "SR"
	CountryCode_SJ CountryCode = "SJ"
	CountryCode_SZ CountryCode = "SZ"
	CountryCode_SE CountryCode = "SE"
	CountryCode_CH CountryCode = "CH"
	CountryCode_SY CountryCode = "SY"
	CountryCode_TW CountryCode = "TW"
	CountryCode_TJ CountryCode = "TJ"
	CountryCode_TZ CountryCode = "TZ"
	CountryCode_TH CountryCode = "TH"
	CountryCode_TL CountryCode = "TL"
	CountryCode_TG CountryCode = "TG"
	CountryCode_TK CountryCode = "TK"
	CountryCode_TO CountryCode = "TO"
	CountryCode_TT CountryCode = "TT"
	CountryCode_TN CountryCode = "TN"
	CountryCode_TR CountryCode = "TR"
	CountryCode_TM CountryCode = "TM"
	CountryCode_TC CountryCode = "TC"
	CountryCode_TV CountryCode = "TV"
	CountryCode_UG CountryCode = "UG"
	CountryCode_UA CountryCode = "UA"
	CountryCode_AE CountryCode = "AE"
	CountryCode_GB CountryCode = "GB"
	CountryCode_US CountryCode = "US"
	CountryCode_UM CountryCode = "UM"
	CountryCode_UY CountryCode = "UY"
	CountryCode_UZ CountryCode = "UZ"
	CountryCode_VU CountryCode = "VU"
	CountryCode_VE CountryCode = "VE"
	CountryCode_VN CountryCode = "VN"
	CountryCode_VG CountryCode = "VG"
	CountryCode_VI CountryCode = "VI"
	CountryCode_WF CountryCode = "WF"
	CountryCode_EH CountryCode = "EH"
	CountryCode_YE CountryCode = "YE"
	CountryCode_ZM CountryCode = "ZM"
	CountryCode_ZW CountryCode = "ZW"
	CountryCode_XK CountryCode = "XK"
)

type FailureReason string

const (
	FailureReason_TOKEN_MISSING         FailureReason = "TOKEN_MISSING"
	FailureReason_TOKEN_EXPIRED         FailureReason = "TOKEN_EXPIRED"
	FailureReason_TOKEN_INVALID         FailureReason = "TOKEN_INVALID"
	FailureReason_TOKEN_DOMAIN_MISMATCH FailureReason = "TOKEN_DOMAIN_MISMATCH"
)

type FallbackBehavior string

const (
	FallbackBehavior_MATCH    FallbackBehavior = "MATCH"
	FallbackBehavior_NO_MATCH FallbackBehavior = "NO_MATCH"
)

type FilterBehavior string

const (
	FilterBehavior_KEEP FilterBehavior = "KEEP"
	FilterBehavior_DROP FilterBehavior = "DROP"
)

type FilterRequirement string

const (
	FilterRequirement_MEETS_ALL FilterRequirement = "MEETS_ALL"
	FilterRequirement_MEETS_ANY FilterRequirement = "MEETS_ANY"
)

type ForwardedIPPosition string

const (
	ForwardedIPPosition_FIRST ForwardedIPPosition = "FIRST"
	ForwardedIPPosition_LAST  ForwardedIPPosition = "LAST"
	ForwardedIPPosition_ANY   ForwardedIPPosition = "ANY"
)

type IPAddressVersion string

const (
	IPAddressVersion_IPV4 IPAddressVersion = "IPV4"
	IPAddressVersion_IPV6 IPAddressVersion = "IPV6"
)

type InspectionLevel string

const (
	InspectionLevel_COMMON   InspectionLevel = "COMMON"
	InspectionLevel_TARGETED InspectionLevel = "TARGETED"
)

type JSONMatchScope string

const (
	JSONMatchScope_ALL   JSONMatchScope = "ALL"
	JSONMatchScope_KEY   JSONMatchScope = "KEY"
	JSONMatchScope_VALUE JSONMatchScope = "VALUE"
)

type LabelMatchScope string

const (
	LabelMatchScope_LABEL     LabelMatchScope = "LABEL"
	LabelMatchScope_NAMESPACE LabelMatchScope = "NAMESPACE"
)

type MapMatchScope string

const (
	MapMatchScope_ALL   MapMatchScope = "ALL"
	MapMatchScope_KEY   MapMatchScope = "KEY"
	MapMatchScope_VALUE MapMatchScope = "VALUE"
)

type OversizeHandling string

const (
	OversizeHandling_CONTINUE OversizeHandling = "CONTINUE"
	OversizeHandling_MATCH    OversizeHandling = "MATCH"
	OversizeHandling_NO_MATCH OversizeHandling = "NO_MATCH"
)

type ParameterExceptionField string

const (
	ParameterExceptionField_WEB_ACL                           ParameterExceptionField = "WEB_ACL"
	ParameterExceptionField_RULE_GROUP                        ParameterExceptionField = "RULE_GROUP"
	ParameterExceptionField_REGEX_PATTERN_SET                 ParameterExceptionField = "REGEX_PATTERN_SET"
	ParameterExceptionField_IP_SET                            ParameterExceptionField = "IP_SET"
	ParameterExceptionField_MANAGED_RULE_SET                  ParameterExceptionField = "MANAGED_RULE_SET"
	ParameterExceptionField_RULE                              ParameterExceptionField = "RULE"
	ParameterExceptionField_EXCLUDED_RULE                     ParameterExceptionField = "EXCLUDED_RULE"
	ParameterExceptionField_STATEMENT                         ParameterExceptionField = "STATEMENT"
	ParameterExceptionField_BYTE_MATCH_STATEMENT              ParameterExceptionField = "BYTE_MATCH_STATEMENT"
	ParameterExceptionField_SQLI_MATCH_STATEMENT              ParameterExceptionField = "SQLI_MATCH_STATEMENT"
	ParameterExceptionField_XSS_MATCH_STATEMENT               ParameterExceptionField = "XSS_MATCH_STATEMENT"
	ParameterExceptionField_SIZE_CONSTRAINT_STATEMENT         ParameterExceptionField = "SIZE_CONSTRAINT_STATEMENT"
	ParameterExceptionField_GEO_MATCH_STATEMENT               ParameterExceptionField = "GEO_MATCH_STATEMENT"
	ParameterExceptionField_RATE_BASED_STATEMENT              ParameterExceptionField = "RATE_BASED_STATEMENT"
	ParameterExceptionField_RULE_GROUP_REFERENCE_STATEMENT    ParameterExceptionField = "RULE_GROUP_REFERENCE_STATEMENT"
	ParameterExceptionField_REGEX_PATTERN_REFERENCE_STATEMENT ParameterExceptionField = "REGEX_PATTERN_REFERENCE_STATEMENT"
	ParameterExceptionField_IP_SET_REFERENCE_STATEMENT        ParameterExceptionField = "IP_SET_REFERENCE_STATEMENT"
	ParameterExceptionField_MANAGED_RULE_SET_STATEMENT        ParameterExceptionField = "MANAGED_RULE_SET_STATEMENT"
	ParameterExceptionField_LABEL_MATCH_STATEMENT             ParameterExceptionField = "LABEL_MATCH_STATEMENT"
	ParameterExceptionField_AND_STATEMENT                     ParameterExceptionField = "AND_STATEMENT"
	ParameterExceptionField_OR_STATEMENT                      ParameterExceptionField = "OR_STATEMENT"
	ParameterExceptionField_NOT_STATEMENT                     ParameterExceptionField = "NOT_STATEMENT"
	ParameterExceptionField_IP_ADDRESS                        ParameterExceptionField = "IP_ADDRESS"
	ParameterExceptionField_IP_ADDRESS_VERSION                ParameterExceptionField = "IP_ADDRESS_VERSION"
	ParameterExceptionField_FIELD_TO_MATCH                    ParameterExceptionField = "FIELD_TO_MATCH"
	ParameterExceptionField_TEXT_TRANSFORMATION               ParameterExceptionField = "TEXT_TRANSFORMATION"
	ParameterExceptionField_SINGLE_QUERY_ARGUMENT             ParameterExceptionField = "SINGLE_QUERY_ARGUMENT"
	ParameterExceptionField_SINGLE_HEADER                     ParameterExceptionField = "SINGLE_HEADER"
	ParameterExceptionField_DEFAULT_ACTION                    ParameterExceptionField = "DEFAULT_ACTION"
	ParameterExceptionField_RULE_ACTION                       ParameterExceptionField = "RULE_ACTION"
	ParameterExceptionField_ENTITY_LIMIT                      ParameterExceptionField = "ENTITY_LIMIT"
	ParameterExceptionField_OVERRIDE_ACTION                   ParameterExceptionField = "OVERRIDE_ACTION"
	ParameterExceptionField_SCOPE_VALUE                       ParameterExceptionField = "SCOPE_VALUE"
	ParameterExceptionField_RESOURCE_ARN                      ParameterExceptionField = "RESOURCE_ARN"
	ParameterExceptionField_RESOURCE_TYPE                     ParameterExceptionField = "RESOURCE_TYPE"
	ParameterExceptionField_TAGS                              ParameterExceptionField = "TAGS"
	ParameterExceptionField_TAG_KEYS                          ParameterExceptionField = "TAG_KEYS"
	ParameterExceptionField_METRIC_NAME                       ParameterExceptionField = "METRIC_NAME"
	ParameterExceptionField_FIREWALL_MANAGER_STATEMENT        ParameterExceptionField = "FIREWALL_MANAGER_STATEMENT"
	ParameterExceptionField_FALLBACK_BEHAVIOR                 ParameterExceptionField = "FALLBACK_BEHAVIOR"
	ParameterExceptionField_POSITION                          ParameterExceptionField = "POSITION"
	ParameterExceptionField_FORWARDED_IP_CONFIG               ParameterExceptionField = "FORWARDED_IP_CONFIG"
	ParameterExceptionField_IP_SET_FORWARDED_IP_CONFIG        ParameterExceptionField = "IP_SET_FORWARDED_IP_CONFIG"
	ParameterExceptionField_HEADER_NAME                       ParameterExceptionField = "HEADER_NAME"
	ParameterExceptionField_CUSTOM_REQUEST_HANDLING           ParameterExceptionField = "CUSTOM_REQUEST_HANDLING"
	ParameterExceptionField_RESPONSE_CONTENT_TYPE             ParameterExceptionField = "RESPONSE_CONTENT_TYPE"
	ParameterExceptionField_CUSTOM_RESPONSE                   ParameterExceptionField = "CUSTOM_RESPONSE"
	ParameterExceptionField_CUSTOM_RESPONSE_BODY              ParameterExceptionField = "CUSTOM_RESPONSE_BODY"
	ParameterExceptionField_JSON_MATCH_PATTERN                ParameterExceptionField = "JSON_MATCH_PATTERN"
	ParameterExceptionField_JSON_MATCH_SCOPE                  ParameterExceptionField = "JSON_MATCH_SCOPE"
	ParameterExceptionField_BODY_PARSING_FALLBACK_BEHAVIOR    ParameterExceptionField = "BODY_PARSING_FALLBACK_BEHAVIOR"
	ParameterExceptionField_LOGGING_FILTER                    ParameterExceptionField = "LOGGING_FILTER"
	ParameterExceptionField_FILTER_CONDITION                  ParameterExceptionField = "FILTER_CONDITION"
	ParameterExceptionField_EXPIRE_TIMESTAMP                  ParameterExceptionField = "EXPIRE_TIMESTAMP"
	ParameterExceptionField_CHANGE_PROPAGATION_STATUS         ParameterExceptionField = "CHANGE_PROPAGATION_STATUS"
	ParameterExceptionField_ASSOCIABLE_RESOURCE               ParameterExceptionField = "ASSOCIABLE_RESOURCE"
	ParameterExceptionField_LOG_DESTINATION                   ParameterExceptionField = "LOG_DESTINATION"
	ParameterExceptionField_MANAGED_RULE_GROUP_CONFIG         ParameterExceptionField = "MANAGED_RULE_GROUP_CONFIG"
	ParameterExceptionField_PAYLOAD_TYPE                      ParameterExceptionField = "PAYLOAD_TYPE"
	ParameterExceptionField_HEADER_MATCH_PATTERN              ParameterExceptionField = "HEADER_MATCH_PATTERN"
	ParameterExceptionField_COOKIE_MATCH_PATTERN              ParameterExceptionField = "COOKIE_MATCH_PATTERN"
	ParameterExceptionField_MAP_MATCH_SCOPE                   ParameterExceptionField = "MAP_MATCH_SCOPE"
	ParameterExceptionField_OVERSIZE_HANDLING                 ParameterExceptionField = "OVERSIZE_HANDLING"
	ParameterExceptionField_CHALLENGE_CONFIG                  ParameterExceptionField = "CHALLENGE_CONFIG"
	ParameterExceptionField_TOKEN_DOMAIN                      ParameterExceptionField = "TOKEN_DOMAIN"
	ParameterExceptionField_ATP_RULE_SET_RESPONSE_INSPECTION  ParameterExceptionField = "ATP_RULE_SET_RESPONSE_INSPECTION"
	ParameterExceptionField_ASSOCIATED_RESOURCE_TYPE          ParameterExceptionField = "ASSOCIATED_RESOURCE_TYPE"
	ParameterExceptionField_SCOPE_DOWN                        ParameterExceptionField = "SCOPE_DOWN"
	ParameterExceptionField_CUSTOM_KEYS                       ParameterExceptionField = "CUSTOM_KEYS"
	ParameterExceptionField_ACP_RULE_SET_RESPONSE_INSPECTION  ParameterExceptionField = "ACP_RULE_SET_RESPONSE_INSPECTION"
)

type PayloadType string

const (
	PayloadType_JSON         PayloadType = "JSON"
	PayloadType_FORM_ENCODED PayloadType = "FORM_ENCODED"
)

type Platform string

const (
	Platform_IOS     Platform = "IOS"
	Platform_ANDROID Platform = "ANDROID"
)

type PositionalConstraint string

const (
	PositionalConstraint_EXACTLY       PositionalConstraint = "EXACTLY"
	PositionalConstraint_STARTS_WITH   PositionalConstraint = "STARTS_WITH"
	PositionalConstraint_ENDS_WITH     PositionalConstraint = "ENDS_WITH"
	PositionalConstraint_CONTAINS      PositionalConstraint = "CONTAINS"
	PositionalConstraint_CONTAINS_WORD PositionalConstraint = "CONTAINS_WORD"
)

type RateBasedStatementAggregateKeyType string

const (
	RateBasedStatementAggregateKeyType_IP           RateBasedStatementAggregateKeyType = "IP"
	RateBasedStatementAggregateKeyType_FORWARDED_IP RateBasedStatementAggregateKeyType = "FORWARDED_IP"
	RateBasedStatementAggregateKeyType_CUSTOM_KEYS  RateBasedStatementAggregateKeyType = "CUSTOM_KEYS"
	RateBasedStatementAggregateKeyType_CONSTANT     RateBasedStatementAggregateKeyType = "CONSTANT"
)

type ResourceType string

const (
	ResourceType_APPLICATION_LOAD_BALANCER ResourceType = "APPLICATION_LOAD_BALANCER"
	ResourceType_API_GATEWAY               ResourceType = "API_GATEWAY"
	ResourceType_APPSYNC                   ResourceType = "APPSYNC"
	ResourceType_COGNITO_USER_POOL         ResourceType = "COGNITO_USER_POOL"
	ResourceType_APP_RUNNER_SERVICE        ResourceType = "APP_RUNNER_SERVICE"
	ResourceType_VERIFIED_ACCESS_INSTANCE  ResourceType = "VERIFIED_ACCESS_INSTANCE"
)

type ResponseContentType string

const (
	ResponseContentType_TEXT_PLAIN       ResponseContentType = "TEXT_PLAIN"
	ResponseContentType_TEXT_HTML        ResponseContentType = "TEXT_HTML"
	ResponseContentType_APPLICATION_JSON ResponseContentType = "APPLICATION_JSON"
)

type Scope string

const (
	Scope_CLOUDFRONT Scope = "CLOUDFRONT"
	Scope_REGIONAL   Scope = "REGIONAL"
)

type SensitivityLevel string

const (
	SensitivityLevel_LOW  SensitivityLevel = "LOW"
	SensitivityLevel_HIGH SensitivityLevel = "HIGH"
)

type SizeInspectionLimit string

const (
	SizeInspectionLimit_KB_16 SizeInspectionLimit = "KB_16"
	SizeInspectionLimit_KB_32 SizeInspectionLimit = "KB_32"
	SizeInspectionLimit_KB_48 SizeInspectionLimit = "KB_48"
	SizeInspectionLimit_KB_64 SizeInspectionLimit = "KB_64"
)

type TextTransformationType string

const (
	TextTransformationType_NONE                 TextTransformationType = "NONE"
	TextTransformationType_COMPRESS_WHITE_SPACE TextTransformationType = "COMPRESS_WHITE_SPACE"
	TextTransformationType_HTML_ENTITY_DECODE   TextTransformationType = "HTML_ENTITY_DECODE"
	TextTransformationType_LOWERCASE            TextTransformationType = "LOWERCASE"
	TextTransformationType_CMD_LINE             TextTransformationType = "CMD_LINE"
	TextTransformationType_URL_DECODE           TextTransformationType = "URL_DECODE"
	TextTransformationType_BASE64_DECODE        TextTransformationType = "BASE64_DECODE"
	TextTransformationType_HEX_DECODE           TextTransformationType = "HEX_DECODE"
	TextTransformationType_MD5                  TextTransformationType = "MD5"
	TextTransformationType_REPLACE_COMMENTS     TextTransformationType = "REPLACE_COMMENTS"
	TextTransformationType_ESCAPE_SEQ_DECODE    TextTransformationType = "ESCAPE_SEQ_DECODE"
	TextTransformationType_SQL_HEX_DECODE       TextTransformationType = "SQL_HEX_DECODE"
	TextTransformationType_CSS_DECODE           TextTransformationType = "CSS_DECODE"
	TextTransformationType_JS_DECODE            TextTransformationType = "JS_DECODE"
	TextTransformationType_NORMALIZE_PATH       TextTransformationType = "NORMALIZE_PATH"
	TextTransformationType_NORMALIZE_PATH_WIN   TextTransformationType = "NORMALIZE_PATH_WIN"
	TextTransformationType_REMOVE_NULLS         TextTransformationType = "REMOVE_NULLS"
	TextTransformationType_REPLACE_NULLS        TextTransformationType = "REPLACE_NULLS"
	TextTransformationType_BASE64_DECODE_EXT    TextTransformationType = "BASE64_DECODE_EXT"
	TextTransformationType_URL_DECODE_UNI       TextTransformationType = "URL_DECODE_UNI"
	TextTransformationType_UTF8_TO_UNICODE      TextTransformationType = "UTF8_TO_UNICODE"
)
