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
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"unsafe"

	"github.com/aws/aws-sdk-go/aws"
	svcsdk "github.com/aws/aws-sdk-go/service/wafv2"
	svcsdkapi "github.com/aws/aws-sdk-go/service/wafv2/wafv2iface"
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	cpresource "github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pkg/errors"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane-contrib/provider-aws/apis/v1alpha1"
	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/wafv2/v1alpha1"
	"github.com/crossplane-contrib/provider-aws/pkg/features"
	connectaws "github.com/crossplane-contrib/provider-aws/pkg/utils/connect/aws"
	errorutils "github.com/crossplane-contrib/provider-aws/pkg/utils/errors"
	"github.com/crossplane-contrib/provider-aws/pkg/utils/jsonpatch"
	custommanaged "github.com/crossplane-contrib/provider-aws/pkg/utils/reconciler/managed"
	tagutils "github.com/crossplane-contrib/provider-aws/pkg/utils/tags"
)

const (
	errCouldNotFindWebACL = "could not find WebACL"
)

// SetupWebACL adds a controller that reconciles SetupWebAcl.
func SetupWebACL(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(svcapitypes.WebACLKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), v1alpha1.StoreConfigGroupVersionKind))
	}

	reconcilerOpts := []managed.ReconcilerOption{
		managed.WithInitializers(),
		managed.WithCriticalAnnotationUpdater(custommanaged.NewRetryingCriticalAnnotationUpdater(mgr.GetClient())),
		managed.WithExternalConnecter(&customConnector{kube: mgr.GetClient()}),
		managed.WithPollInterval(o.PollInterval),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...),
	}

	if o.Features.Enabled(features.EnableAlphaManagementPolicies) {
		reconcilerOpts = append(reconcilerOpts, managed.WithManagementPolicies())
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(svcapitypes.WebACLGroupVersionKind),
		reconcilerOpts...)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&svcapitypes.WebACL{}).
		Complete(r)
}

type statementWithInfiniteRecursion interface {
	svcsdk.Statement | svcsdk.AndStatement | svcsdk.OrStatement | svcsdk.NotStatement
}

type caseInsensitiveTypes interface {
	svcsdk.SingleHeader | svcsdk.SingleQueryArgument
}

// customConnector is external connector with overridden Observe method due to ACK v0.38.1 doesn't correctly generate it.
type customConnector struct {
	kube client.Client
}

type customExternal struct {
	external
	cache *cache
}

type shared struct {
	cache  *cache
	client svcsdkapi.WAFV2API
}

type cache struct {
	listWebACLsOutput *svcsdk.ListWebACLsOutput
	tagListOutput     []*svcsdk.Tag
}

func newCustomExternal(kube client.Client, client svcsdkapi.WAFV2API) *customExternal {
	shared := &shared{client: client, cache: &cache{}}
	e := &customExternal{
		external{
			kube:           kube,
			client:         client,
			preObserve:     preObserve,
			postObserve:    postObserve,
			isUpToDate:     shared.isUpToDate,
			preCreate:      preCreate,
			preDelete:      nopPreDelete,
			preUpdate:      shared.preUpdate,
			lateInitialize: nopLateInitialize,
			postCreate:     postCreate,
			postDelete:     nopPostDelete,
			postUpdate:     nopPostUpdate,
		},
		shared.cache,
	}
	return e
}

func (c *customConnector) Connect(ctx context.Context, mg cpresource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*svcapitypes.WebACL)
	if !ok {
		return nil, errors.New(errUnexpectedObject)
	}
	sess, err := connectaws.GetConfigV1(ctx, c.kube, mg, cr.Spec.ForProvider.Region)
	if err != nil {
		return nil, errors.Wrap(err, errCreateSession)
	}
	return newCustomExternal(c.kube, svcsdk.New(sess)), nil
}

func preObserve(_ context.Context, cr *svcapitypes.WebACL, input *svcsdk.GetWebACLInput) error {
	input.Id = aws.String(meta.GetExternalName(cr))
	return nil
}

func (e *customExternal) Observe(ctx context.Context, mg cpresource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*svcapitypes.WebACL)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errUnexpectedObject)
	}
	if meta.GetExternalName(cr) == "" {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	input := GenerateGetWebACLInput(cr)
	if err := e.preObserve(ctx, cr, input); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "pre-observe failed")
	}
	resp, err := e.client.GetWebACLWithContext(ctx, input)
	if err != nil {
		return managed.ExternalObservation{ResourceExists: false}, errorutils.Wrap(cpresource.Ignore(IsNotFound, err), errDescribe)
	}
	currentSpec := cr.Spec.ForProvider.DeepCopy()
	if err := e.lateInitialize(&cr.Spec.ForProvider, resp); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "late-init failed")
	}
	GenerateWebACL(resp).Status.AtProvider.DeepCopyInto(&cr.Status.AtProvider)
	upToDate := true
	diff := ""
	if !meta.WasDeleted(cr) { // There is no need to run isUpToDate if the resource is deleted
		upToDate, diff, err = e.isUpToDate(ctx, cr, resp)
		if err != nil {
			return managed.ExternalObservation{}, errors.Wrap(err, "isUpToDate check failed")
		}
	}
	return e.postObserve(ctx, cr, resp, managed.ExternalObservation{
		ResourceExists:          true,
		ResourceUpToDate:        upToDate,
		Diff:                    diff,
		ResourceLateInitialized: !cmp.Equal(&cr.Spec.ForProvider, currentSpec),
	}, nil)
}

func (s *shared) isUpToDate(_ context.Context, cr *svcapitypes.WebACL, resp *svcsdk.GetWebACLOutput) (upToDate bool, diff string, err error) {
	listTagOutput, err := s.client.ListTagsForResource(&svcsdk.ListTagsForResourceInput{ResourceARN: cr.Status.AtProvider.ARN})
	if err != nil {
		return false, "", err
	}
	s.cache.tagListOutput = listTagOutput.TagInfoForResource.TagList
	patch, err := createPatch(&cr.Spec.ForProvider, resp, listTagOutput.TagInfoForResource.TagList)
	if err != nil {
		return false, "", err
	}

	opts := []cmp.Option{
		cmpopts.EquateEmpty(),
		// Name and Scope are immutables
		cmpopts.IgnoreFields(svcapitypes.WebACLParameters{}, "Name", "Region", "Scope"),
	}

	diff = cmp.Diff(&svcapitypes.WebACLParameters{}, patch, opts...)
	if diff != "" {
		return false, "Found observed difference in wafv2 webacl " + diff, nil
	}
	return true, "", nil
}

//func cmpOptFilerValues(x, y interface{}) bool {
//	rulesRef := reflect.TypeOf([]*svcapitypes.Rule{})
//
//	vx, vy := reflect.ValueOf(x), reflect.ValueOf(y)
//	if vx.IsValid() && vy.IsValid() {
//		fmt.Println(fmt.Sprintf("==========\nvx type is %s", vx.Type().String()))
//		fmt.Println(fmt.Sprintf("vy type is %s", vy.Type().String()))
//		fmt.Println(fmt.Sprintf("ref type is %s", rulesRef.String()))
//	}
//	if vx.IsValid() && vy.IsValid() && vx.Type() == rulesRef && vy.Type() == rulesRef {
//		return false
//	}
//	return false
//}

func postObserve(_ context.Context, cr *svcapitypes.WebACL, output *svcsdk.GetWebACLOutput, obs managed.ExternalObservation, _ error) (managed.ExternalObservation, error) {
	cr.SetConditions(xpv1.Available())
	cr.Status.AtProvider = svcapitypes.WebACLObservation{
		ARN:       output.WebACL.ARN,
		ID:        output.WebACL.Id,
		LockToken: output.LockToken,
	}

	return obs, nil
}

func preCreate(_ context.Context, cr *svcapitypes.WebACL, input *svcsdk.CreateWebACLInput) error {
	err := setInputRuleStatementsFromJSON(cr, input.Rules)
	if err != nil {
		return err
	}
	return nil
}

func postCreate(_ context.Context, cr *svcapitypes.WebACL, output *svcsdk.CreateWebACLOutput, ec managed.ExternalCreation, err error) (managed.ExternalCreation, error) {
	meta.SetExternalName(cr, ptr.Deref(output.Summary.Id, ""))
	cr.Status.AtProvider = svcapitypes.WebACLObservation{
		ARN:       output.Summary.ARN,
		ID:        output.Summary.Id,
		LockToken: output.Summary.LockToken,
	}
	return ec, err
}

func (s *shared) preUpdate(_ context.Context, cr *svcapitypes.WebACL, input *svcsdk.UpdateWebACLInput) error {
	err := setInputRuleStatementsFromJSON(cr, input.Rules)
	if err != nil {
		return err
	}

	desiredTags := map[string]*string{}
	observedTags := map[string]*string{}

	for _, tag := range cr.Spec.ForProvider.Tags {
		desiredTags[*tag.Key] = tag.Value
	}
	for _, tag := range s.cache.tagListOutput {
		// ignore system tags
		if strings.HasPrefix(*tag.Key, "aws:") {
			continue
		}
		observedTags[*tag.Key] = tag.Value
	}
	tagsToAdd, tagsToRemove := tagutils.DiffTagsMapPtr(desiredTags, observedTags)

	if len(tagsToAdd) > 0 {
		var inputTags []*svcsdk.Tag
		for k, v := range tagsToAdd {
			inputTags = append(inputTags, &svcsdk.Tag{Key: aws.String(k), Value: v})
		}
		_, err = s.client.TagResource(&svcsdk.TagResourceInput{ResourceARN: cr.Status.AtProvider.ARN, Tags: inputTags})
		if err != nil {
			return err
		}
	}

	if len(tagsToRemove) > 0 {
		_, err = s.client.UntagResource(&svcsdk.UntagResourceInput{ResourceARN: cr.Status.AtProvider.ARN, TagKeys: tagsToRemove})
		if err != nil {
			return err
		}
	}

	return nil
}

//func (s *shared) preDelete(_ context.Context, cr *svcapitypes.WebACL, input *svcsdk.DeleteWebACLInput) (bool, error) {
//	lockToken, err := getLockToken(s.cache.listWebACLsOutput.WebACLs, cr)
//	if err != nil {
//		return false, err
//	}
//	input.LockToken = lockToken
//	return false, nil
//}

// getLockToken returns the lock token which is required for WebACL update and delete operations
//func getLockToken(webACLs []*svcsdk.WebACLSummary, cr *svcapitypes.WebACL) (*string, error) {
//	var lockToken *string
//	for n, webACLSummary := range webACLs {
//		if aws.StringValue(webACLSummary.Id) == meta.GetExternalName(cr) {
//			lockToken = webACLSummary.LockToken
//			break
//		}
//		if n == len(webACLs)-1 {
//			return lockToken, errors.New(fmt.Sprintf("%s %s", errCouldNotFindWebACL, meta.GetExternalName(cr)))
//		}
//	}
//	return lockToken, nil
//}

// statementFromJSONString convert back to sdk types the rule statements which were ignored in generator-config.yaml and handled by the controller as string(json)
func statementFromJSONString[S statementWithInfiniteRecursion](jsonPointer *string) (*S, error) {
	jsonString := ptr.Deref(jsonPointer, "")
	var statement S
	err := json.Unmarshal([]byte(jsonString), &statement)
	if err != nil {
		return nil, err
	}
	return &statement, nil
}

// statementToJSONString converts the statement which the controller handles as string to JSON string
func statementToJSONString[S statementWithInfiniteRecursion](statement S) (*string, error) {
	configBytes, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}
	configStr := string(configBytes)
	return &configStr, nil
}

// setInputRuleStatementsFromJSON sets the input for rule statements which were ignored in generator-config.yaml and handled as string(json)
func setInputRuleStatementsFromJSON(cr *svcapitypes.WebACL, rules []*svcsdk.Rule) (err error) {
	for i, rule := range cr.Spec.ForProvider.Rules {
		if rule.Statement.OrStatement != nil {
			rules[i].Statement.OrStatement, err = statementFromJSONString[svcsdk.OrStatement](rule.Statement.OrStatement)
			if err != nil {
				return err
			}
		}
		if rule.Statement.AndStatement != nil {
			rules[i].Statement.AndStatement, err = statementFromJSONString[svcsdk.AndStatement](rule.Statement.AndStatement)
			if err != nil {
				return err
			}
		}
		if rule.Statement.NotStatement != nil {
			rules[i].Statement.NotStatement, err = statementFromJSONString[svcsdk.NotStatement](rule.Statement.NotStatement)
			if err != nil {
				return err
			}
		}
		if rule.Statement.ManagedRuleGroupStatement != nil && rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement != nil {
			rules[i].Statement.ManagedRuleGroupStatement.ScopeDownStatement, err = statementFromJSONString[svcsdk.Statement](rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement)
			if err != nil {
				return err
			}
		}
		if rule.Statement.ByteMatchStatement != nil && rule.Statement.RateBasedStatement.ScopeDownStatement != nil {
			rules[i].Statement.RateBasedStatement.ScopeDownStatement, err = statementFromJSONString[svcsdk.Statement](rule.Statement.RateBasedStatement.ScopeDownStatement)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func changeToLowerCase(params any) {
	v := reflect.Indirect(reflect.ValueOf(params))
	fmt.Println(fmt.Sprintf("v type is %s", v.Type().String()))

	for i := 0; i < v.NumField(); i++ {
		fmt.Println(fmt.Sprintf("i %d from v.NumField - %d", i, v.NumField()))
		field := reflect.TypeOf(v.Interface()).Field(i)
		fmt.Println(fmt.Sprintf("fieldName is %s", field.Name))
		if v.FieldByName(field.Name).IsValid() {
			if field.Type == reflect.TypeOf([]*svcapitypes.Rule{}) || field.Type == reflect.TypeOf([]*svcsdk.Rule{}) {
				fmt.Println("rules are found...")
				for ri := 0; ri < v.FieldByName(field.Name).Len(); ri++ {
					fmt.Println(fmt.Sprintf("range over rules, i %d from len is %d", ri, v.FieldByName(field.Name).Len()))
					if v.FieldByName(field.Name).Index(ri).IsValid() && (v.FieldByName(field.Name).Index(ri).Type() == reflect.TypeOf(&svcapitypes.Statement{}) || v.FieldByName(field.Name).Index(ri).Type() == reflect.TypeOf(svcsdk.Statement{})) {
						statement := v.FieldByName(field.Name).Index(ri).Addr().Interface()
						fmt.Println(fmt.Sprintf("statement is found in a rule - %s, run nested loop", v.FieldByName(field.Name).Index(ri).FieldByName("Name").Elem().String()))
						changeToLowerCase(statement)
					}
				}
			}
			if field.Type == reflect.TypeOf(svcsdk.AndStatement{}) || field.Type == reflect.TypeOf(svcsdk.OrStatement{}) {
				for si := 0; si < v.FieldByName(field.Name).FieldByName("Statements").Len(); si++ {
					nestedStatement := v.FieldByName(field.Name).FieldByName("Statements").Index(si).Addr().Interface()
					fmt.Println(fmt.Sprintf("nestedStatement is found in a statement - %s, run nested loop", field.Type.String()))
					changeToLowerCase(nestedStatement)
				}
			}

			if field.Type == reflect.TypeOf(&svcapitypes.NotStatement{}) {
				nestedStatement := v.FieldByName(field.Name).FieldByName("Statement").Addr().Interface()
				fmt.Println(fmt.Sprintf("nestedStatement is found in a statement - %s, run nested loop", field.Type.String()))
				changeToLowerCase(nestedStatement)
			}

			if field.Type == reflect.TypeOf(&svcapitypes.ByteMatchStatement{}) ||
				field.Type == reflect.TypeOf(&svcsdk.ByteMatchStatement{}) ||
				field.Type == reflect.TypeOf(&svcapitypes.RegexMatchStatement{}) ||
				field.Type == reflect.TypeOf(&svcsdk.RegexMatchStatement{}) ||
				field.Type == reflect.TypeOf(&svcapitypes.RegexPatternSetReferenceStatement{}) ||
				field.Type == reflect.TypeOf(&svcsdk.RegexPatternSetReferenceStatement{}) ||
				field.Type == reflect.TypeOf(&svcapitypes.SizeConstraintStatement{}) ||
				field.Type == reflect.TypeOf(&svcsdk.SizeConstraintStatement{}) ||
				field.Type == reflect.TypeOf(&svcapitypes.SQLIMatchStatement{}) ||
				field.Type == reflect.TypeOf(&svcsdk.SqliMatchStatement{}) ||
				field.Type == reflect.TypeOf(&svcapitypes.XSSMatchStatement{}) ||
				field.Type == reflect.TypeOf(&svcsdk.XssMatchStatement{}) {

				fmt.Println(fmt.Sprintf("statement confug is found - %s", field.Type.String()))
				for i := 0; i < v.FieldByName(field.Name).NumField(); i++ {
					statementField := reflect.TypeOf(v.FieldByName(field.Name).Interface()).Field(i)
					if statementField.Type == reflect.TypeOf(&svcsdk.FieldToMatch{}) || statementField.Type == reflect.TypeOf(&svcapitypes.FieldToMatch{}) {
						fmt.Println("field to match is found, run nested loop...")
						fieldToMatch := v.FieldByName(field.Name).Field(i).Addr().Interface()
						changeToLowerCase(fieldToMatch)
					}
				}
			}

			if field.Type == reflect.TypeOf(&svcapitypes.SingleHeader{}) ||
				field.Type == reflect.TypeOf(&svcsdk.SingleHeader{}) ||
				field.Type == reflect.TypeOf(&svcapitypes.SingleQueryArgument{}) ||
				field.Type == reflect.TypeOf(&svcsdk.SingleQueryArgument{}) {

				fmt.Println(fmt.Sprintf("FieldToMatch.Name is found in %s", v.FieldByName(field.Name)))
				caseInSensitiveName := v.FieldByName(field.Name).FieldByName("Name")
				if caseInSensitiveName.IsValid() && caseInSensitiveName.CanSet() {
					lowerCasedName := strings.ToLower(caseInSensitiveName.Elem().String())
					caseInSensitiveName.SetPointer(unsafe.Pointer(&lowerCasedName))
					fmt.Println("transformed to lower case")
				}
			}
		}
	}
}

func createPatch(currentParams *svcapitypes.WebACLParameters, resp *svcsdk.GetWebACLOutput, respTagList []*svcsdk.Tag) (*svcapitypes.WebACLParameters, error) {
	targetConfig := currentParams.DeepCopy()
	changeToLowerCase(targetConfig)
	externalConfig := GenerateWebACL(resp).Spec.ForProvider
	patch := &svcapitypes.WebACLParameters{}
	err := addJsonifiedRuleStatements(resp.WebACL.Rules, externalConfig)
	if err != nil {
		return patch, err
	}

	for i, rule := range targetConfig.Rules {
		// Unmarshalling the JSON string to the struct and marshaling it back to JSON string to further comparison with marshaled JSON string from the response
		if rule.Statement.AndStatement != nil {
			sdkStatement, err := statementFromJSONString[svcsdk.AndStatement](targetConfig.Rules[i].Statement.AndStatement)
			changeToLowerCase(sdkStatement)
			if err != nil {
				return patch, err
			}
			targetConfig.Rules[i].Statement.AndStatement, err = statementToJSONString[svcsdk.AndStatement](*sdkStatement)

			if err != nil {
				return patch, err
			}
		}
		if rule.Statement.OrStatement != nil {
			sdkStatement, err := statementFromJSONString[svcsdk.OrStatement](targetConfig.Rules[i].Statement.OrStatement)
			if err != nil {
				return patch, err
			}
			targetConfig.Rules[i].Statement.OrStatement, err = statementToJSONString[svcsdk.OrStatement](*sdkStatement)
			if err != nil {
				return patch, err
			}
		}
		if rule.Statement.NotStatement != nil {
			sdkStatement, err := statementFromJSONString[svcsdk.NotStatement](targetConfig.Rules[i].Statement.NotStatement)
			if err != nil {
				return patch, err
			}
			targetConfig.Rules[i].Statement.NotStatement, err = statementToJSONString[svcsdk.NotStatement](*sdkStatement)
			if err != nil {
				return patch, err
			}
		}
		if rule.Statement.ManagedRuleGroupStatement != nil && rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement != nil {
			return patch, errors.New("WTF I'M HERE")
			sdkStatement, err := statementFromJSONString[svcsdk.Statement](targetConfig.Rules[i].Statement.ManagedRuleGroupStatement.ScopeDownStatement)
			if err != nil {
				return patch, err
			}
			targetConfig.Rules[i].Statement.ManagedRuleGroupStatement.ScopeDownStatement, err = statementToJSONString[svcsdk.Statement](*sdkStatement)
			if err != nil {
				return patch, err
			}
		}
		if rule.Statement.RateBasedStatement != nil && rule.Statement.RateBasedStatement.ScopeDownStatement != nil {
			sdkStatement, err := statementFromJSONString[svcsdk.Statement](targetConfig.Rules[i].Statement.RateBasedStatement.ScopeDownStatement)
			if err != nil {
				return patch, err
			}
			targetConfig.Rules[i].Statement.RateBasedStatement.ScopeDownStatement, err = statementToJSONString[svcsdk.Statement](*sdkStatement)
			if err != nil {
				return patch, err
			}
		}
	}
	for _, v := range respTagList {
		externalConfig.Tags = append(externalConfig.Tags, &svcapitypes.Tag{Key: v.Key, Value: v.Value})
	}

	//if len(externalConfig.Rules) > 0 && externalConfig.Rules[0].Statement != nil && externalConfig.Rules[0].Statement.AndStatement != nil {
	//	return patch, errors.New(fmt.Sprintf("external: %+v target: %+v", *externalConfig.Rules[0].Statement.AndStatement, *targetConfig.Rules[0].Statement.AndStatement))
	//	return patch, errors.New(fmt.Sprintf("external: %s target: %s", gjson.Get(*externalConfig.Rules[0].Statement.AndStatement, "Statements.0.ByteMatchStatement.SearchString"), gjson.Get(*targetConfig.Rules[0].Statement.AndStatement, "Statements.0.ByteMatchStatement.SearchString")))
	//}

	jsonPatch, err := jsonpatch.CreateJSONPatch(externalConfig, targetConfig)
	if err != nil {
		return patch, err
	}
	if err := json.Unmarshal(jsonPatch, patch); err != nil {
		return patch, err
	}
	return patch, nil
}

// addJsonifiedRuleStatements adds the Jsonified rule statements to the externalConfig(other fields prepared by GenerateWebACL)
func addJsonifiedRuleStatements(resp []*svcsdk.Rule, externalConfig svcapitypes.WebACLParameters) error {
	for i, rule := range resp {
		if rule.Statement.AndStatement != nil {
			//if rule.statementWithInfiniteRecursion.AndStatement.Statements != nil {
			//for _, statement := range rule.statementWithInfiniteRecursion.AndStatement.Statements {
			//	err := decodeRespBase64SearchStringIfExists(statement)
			//	if err != nil {
			//		return err
			//	}
			//}
			//}
			jsonStringStatement, err := statementToJSONString[svcsdk.AndStatement](*rule.Statement.AndStatement)
			if err != nil {
				return err
			}
			externalConfig.Rules[i].Statement.AndStatement = jsonStringStatement
		}
		if rule.Statement.OrStatement != nil {
			//			if rule.statementWithInfiniteRecursion.OrStatement.Statements != nil {
			//				for _, statement := range rule.statementWithInfiniteRecursion.OrStatement.Statements {
			//					err := decodeRespBase64SearchStringIfExists(statement)
			//					if err != nil {
			//						return err
			//					}
			//				}
			//			}
			jsonStringStatement, err := statementToJSONString[svcsdk.OrStatement](*rule.Statement.OrStatement)
			if err != nil {
				return err
			}
			externalConfig.Rules[i].Statement.OrStatement = jsonStringStatement
		}
		if rule.Statement.NotStatement != nil {
			//if rule.statementWithInfiniteRecursion.NotStatement.statementWithInfiniteRecursion != nil {
			//				err := decodeRespBase64SearchStringIfExists(rule.statementWithInfiniteRecursion.NotStatement.statementWithInfiniteRecursion)
			//				if err != nil {
			//					return err
			//				}
			//}
			jsonStringStatement, err := statementToJSONString[svcsdk.NotStatement](*rule.Statement.NotStatement)
			if err != nil {
				return err
			}
			externalConfig.Rules[i].Statement.NotStatement = jsonStringStatement
		}
		if rule.Statement.ManagedRuleGroupStatement != nil && rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement != nil {
			//			err := decodeRespBase64SearchStringIfExists(rule.statementWithInfiniteRecursion.ManagedRuleGroupStatement.ScopeDownStatement)
			//			if err != nil {
			//				return err
			//			}
			jsonStringStatement, err := statementToJSONString[svcsdk.Statement](*rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement)
			if err != nil {
				return err
			}
			externalConfig.Rules[i].Statement.ManagedRuleGroupStatement.ScopeDownStatement = jsonStringStatement
		}
		if rule.Statement.RateBasedStatement != nil && rule.Statement.RateBasedStatement.ScopeDownStatement != nil {
			//			err := decodeRespBase64SearchStringIfExists(rule.statementWithInfiniteRecursion.RateBasedStatement.ScopeDownStatement)
			//			if err != nil {
			//				return err
			//			}
			jsonStringStatement, err := statementToJSONString[svcsdk.Statement](*rule.Statement.RateBasedStatement.ScopeDownStatement)
			if err != nil {
				return err
			}
			externalConfig.Rules[i].Statement.RateBasedStatement.ScopeDownStatement = jsonStringStatement
		}
	}
	return nil
}

//// decodeRespBase64SearchStringIfExists decodes the search string if it exists in the statement. It is needed before marshaling the statement to JSON otherwise it will be encoded to base64 second time.
//func decodeRespBase64SearchStringIfExists(statement *svcsdk.statementWithInfiniteRecursion) error {
//	if statement.ByteMatchStatement != nil && statement.ByteMatchStatement.SearchString != nil {
//		decodedString, err := base64.StdEncoding.DecodeString(string(statement.ByteMatchStatement.SearchString))
//		statement.ByteMatchStatement.SearchString = decodedString
//		if err != nil {
//			return err
//		}
//	}
//	return nil
//}
