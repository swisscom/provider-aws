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
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// WebACLParameters defines the desired state of WebACL
type WebACLParameters struct {
	// Region is which region the WebACL will be created.
	// +kubebuilder:validation:Required
	Region string `json:"region"`
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
	// Specifies how WAF should handle CAPTCHA evaluations for rules that don't
	// have their own CaptchaConfig settings. If you don't specify this, WAF uses
	// its default settings for CaptchaConfig.
	CaptchaConfig *CaptchaConfig `json:"captchaConfig,omitempty"`
	// Specifies how WAF should handle challenge evaluations for rules that don't
	// have their own ChallengeConfig settings. If you don't specify this, WAF uses
	// its default settings for ChallengeConfig.
	ChallengeConfig *ChallengeConfig `json:"challengeConfig,omitempty"`
	// A map of custom response keys and content bodies. When you create a rule
	// with a block action, you can send a custom response to the web request. You
	// define these for the web ACL, and then use them in the rules and default
	// actions that you define in the web ACL.
	//
	// For information about customizing web requests and responses, see Customizing
	// web requests and responses in WAF (https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html)
	// in the WAF Developer Guide.
	//
	// For information about the limits on count and size for custom request and
	// response settings, see WAF quotas (https://docs.aws.amazon.com/waf/latest/developerguide/limits.html)
	// in the WAF Developer Guide.
	CustomResponseBodies map[string]*CustomResponseBody `json:"customResponseBodies,omitempty"`
	// The action to perform if none of the Rules contained in the WebACL match.
	// +kubebuilder:validation:Required
	DefaultAction *DefaultAction `json:"defaultAction"`
	// A description of the web ACL that helps with identification.
	Description *string `json:"description,omitempty"`
	// The Rule statements used to identify the web requests that you want to manage.
	// Each rule includes one top-level statement that WAF uses to identify matching
	// web requests, and parameters that govern how WAF handles them.
	Rules []*Rule `json:"rules,omitempty"`
	// Specifies whether this is for an Amazon CloudFront distribution or for a
	// regional application. A regional application can be an Application Load Balancer
	// (ALB), an Amazon API Gateway REST API, an AppSync GraphQL API, an Amazon
	// Cognito user pool, an App Runner service, or an Amazon Web Services Verified
	// Access instance.
	//
	// To work with CloudFront, you must also specify the Region US East (N. Virginia)
	// as follows:
	//
	//    * CLI - Specify the Region when you use the CloudFront scope: --scope=CLOUDFRONT
	//    --region=us-east-1.
	//
	//    * API and SDKs - For all calls, use the Region endpoint us-east-1.
	// +kubebuilder:validation:Required
	Scope *string `json:"scope"`
	// An array of key:value pairs to associate with the resource.
	Tags []*Tag `json:"tags,omitempty"`
	// Specifies the domains that WAF should accept in a web request token. This
	// enables the use of tokens across multiple protected websites. When WAF provides
	// a token, it uses the domain of the Amazon Web Services resource that the
	// web ACL is protecting. If you don't specify a list of token domains, WAF
	// accepts tokens only for the domain of the protected resource. With a token
	// domain list, WAF accepts the resource's host domain plus all domains in the
	// token domain list, including their prefixed subdomains.
	//
	// Example JSON: "TokenDomains": { "mywebsite.com", "myotherwebsite.com" }
	//
	// Public suffixes aren't allowed. For example, you can't use usa.gov or co.uk
	// as token domains.
	TokenDomains []*string `json:"tokenDomains,omitempty"`
	// Defines and enables Amazon CloudWatch metrics and web request sample collection.
	// +kubebuilder:validation:Required
	VisibilityConfig       *VisibilityConfig `json:"visibilityConfig"`
	CustomWebACLParameters `json:",inline"`
}

// WebACLSpec defines the desired state of WebACL
type WebACLSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       WebACLParameters `json:"forProvider"`
}

// WebACLObservation defines the observed state of WebACL
type WebACLObservation struct {
	// The Amazon Resource Name (ARN) of the entity.
	ARN *string `json:"arn,omitempty"`
	// The unique identifier for the web ACL. This ID is returned in the responses
	// to create and list commands. You provide it to operations like update and
	// delete.
	ID *string `json:"id,omitempty"`
	// A token used for optimistic locking. WAF returns a token to your get and
	// list requests, to mark the state of the entity at the time of the request.
	// To make changes to the entity associated with the token, you provide the
	// token to operations like update and delete. WAF uses the token to ensure
	// that no changes have been made to the entity since you last retrieved it.
	// If a change has been made, the update fails with a WAFOptimisticLockException.
	// If this happens, perform another get, and use the new token returned by that
	// operation.
	LockToken *string `json:"lockToken,omitempty"`
	// The name of the web ACL. You cannot change the name of a web ACL after you
	// create it.
	Name *string `json:"name,omitempty"`
}

// WebACLStatus defines the observed state of WebACL.
type WebACLStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          WebACLObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// WebACL is the Schema for the WebACLS API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,aws}
type WebACL struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              WebACLSpec   `json:"spec"`
	Status            WebACLStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WebACLList contains a list of WebACLS
type WebACLList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WebACL `json:"items"`
}

// Repository type metadata.
var (
	WebACLKind             = "WebACL"
	WebACLGroupKind        = schema.GroupKind{Group: CRDGroup, Kind: WebACLKind}.String()
	WebACLKindAPIVersion   = WebACLKind + "." + GroupVersion.String()
	WebACLGroupVersionKind = GroupVersion.WithKind(WebACLKind)
)

func init() {
	SchemeBuilder.Register(&WebACL{}, &WebACLList{})
}