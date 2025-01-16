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

package webacl

import (
	"context"
	"encoding/json"
	"fmt"

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
	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/wafv2/manualv1alpha1"
	"github.com/crossplane-contrib/provider-aws/pkg/features"
	connectaws "github.com/crossplane-contrib/provider-aws/pkg/utils/connect/aws"
	errorutils "github.com/crossplane-contrib/provider-aws/pkg/utils/errors"
	"github.com/crossplane-contrib/provider-aws/pkg/utils/jsonpatch"
	custommanaged "github.com/crossplane-contrib/provider-aws/pkg/utils/reconciler/managed"
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
		managed.WithCriticalAnnotationUpdater(custommanaged.NewRetryingCriticalAnnotationUpdater(mgr.GetClient())),
		managed.WithInitializers(managed.NewNameAsExternalName(mgr.GetClient())),
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

type Statement interface {
	svcsdk.Statement | svcsdk.AndStatement | svcsdk.OrStatement | svcsdk.NotStatement
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
}

func newCustomExternal(kube client.Client, client svcsdkapi.WAFV2API) *customExternal {
	shared := &shared{client: client}
	e := &customExternal{
		external{
			kube:           kube,
			client:         client,
			preObserve:     preObserve,
			postObserve:    postObserve,
			isUpToDate:     shared.isUpToDate,
			preCreate:      preCreate,
			preDelete:      shared.preDelete,
			preUpdate:      shared.preUpdate,
			lateInitialize: nopLateInitialize,
			postCreate:     nopPostCreate,
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
	listWebACLInput := svcsdk.ListWebACLsInput{
		Scope: cr.Spec.ForProvider.Scope,
	}
	ls, err := e.client.ListWebACLs(&listWebACLInput)
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	e.cache.listWebACLsOutput = ls
	for n, webACLSummary := range ls.WebACLs {
		if aws.StringValue(webACLSummary.Name) == meta.GetExternalName(cr) {
			input.Id = webACLSummary.Id
			break
		}
		if n == len(ls.WebACLs)-1 {
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil
		}
	}
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
	listTagsOutput, err := s.client.ListTagsForResource(&svcsdk.ListTagsForResourceInput{ResourceARN: cr.Status.AtProvider.ARN})
	if err != nil {
		return false, "", err
	}
	patch, err := createPatch(&cr.Spec.ForProvider, resp, listTagsOutput.TagInfoForResource.TagList)
	if err != nil {
		return false, "", err
	}
	diff = cmp.Diff(&svcapitypes.WebACLParameters{}, patch, cmpopts.EquateEmpty(),
		cmpopts.IgnoreFields(svcapitypes.WebACLParameters{}, "Region"),
	)

	if diff != "" {
		return false, "Found observed difference in wafv2 weback " + diff, nil
	}

	return true, "", nil
}

func postObserve(_ context.Context, cr *svcapitypes.WebACL, resp *svcsdk.GetWebACLOutput, obs managed.ExternalObservation, _ error) (managed.ExternalObservation, error) {

	cr.SetConditions(xpv1.Available())

	if resp == nil {
		cr.Status.AtProvider = svcapitypes.WebACLObservation{}
	} else {
		cr.Status.AtProvider = svcapitypes.WebACLObservation{
			ARN: resp.WebACL.ARN,
			ID:  resp.WebACL.Id,
		}

	}

	return obs, nil
}

func preCreate(_ context.Context, cr *svcapitypes.WebACL, input *svcsdk.CreateWebACLInput) error {
	input.Name = aws.String(meta.GetExternalName(cr))
	err := setInputRuleStatementsFromJSON(cr, input.Rules)
	if err != nil {
		return err
	}
	return nil
}

func preObserve(_ context.Context, cr *svcapitypes.WebACL, input *svcsdk.GetWebACLInput) error {
	input.Name = aws.String(meta.GetExternalName(cr))

	return nil
}

func (s *shared) preUpdate(_ context.Context, cr *svcapitypes.WebACL, input *svcsdk.UpdateWebACLInput) error {
	input.Name = aws.String(meta.GetExternalName(cr))
	lockToken, err := getLockToken(s.cache.listWebACLsOutput.WebACLs, cr)
	if err != nil {
		return err
	}
	input.LockToken = lockToken
	err = setInputRuleStatementsFromJSON(cr, input.Rules)
	if err != nil {
		return err
	}
	return nil
}

func (s *shared) preDelete(_ context.Context, cr *svcapitypes.WebACL, input *svcsdk.DeleteWebACLInput) (bool, error) {
	input.Name = aws.String(meta.GetExternalName(cr))
	lockToken, err := getLockToken(s.cache.listWebACLsOutput.WebACLs, cr)
	if err != nil {
		return false, err
	}
	input.LockToken = lockToken
	return false, nil
}

func getLockToken(webACLs []*svcsdk.WebACLSummary, cr *svcapitypes.WebACL) (*string, error) {
	var lockToken *string
	for n, webACLSummary := range webACLs {
		if aws.StringValue(webACLSummary.Name) == meta.GetExternalName(cr) {
			lockToken = webACLSummary.LockToken
			break
		}
		if n == len(webACLs)-1 {
			return lockToken, errors.New(fmt.Sprintf("%s %s", errCouldNotFindWebACL, meta.GetExternalName(cr)))
		}
	}
	return lockToken, nil
}

func statementFromJSONString[S Statement](jsonPointer *string) (*S, error) {
	jsonString := ptr.Deref(jsonPointer, "")

	var statement S
	err := json.Unmarshal([]byte(jsonString), &statement)
	if err != nil {
		return nil, err
	}

	return &statement, nil
}

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

func createPatch(currentParams *svcapitypes.WebACLParameters, resp *svcsdk.GetWebACLOutput, respTagList []*svcsdk.Tag) (*svcapitypes.WebACLParameters, error) {
	targetConfig := currentParams.DeepCopy()
	externalConfig := GenerateWebACL(resp).Spec.ForProvider
	patch := &svcapitypes.WebACLParameters{}
	for _, v := range respTagList {
		externalConfig.Tags = append(externalConfig.Tags, &svcapitypes.Tag{Key: v.Key, Value: v.Value})
	}
	jsonPatch, err := jsonpatch.CreateJSONPatch(externalConfig, targetConfig)
	if err != nil {
		return patch, err
	}
	if err := json.Unmarshal(jsonPatch, patch); err != nil {
		return patch, err
	}

	return patch, nil
}

//func statementToString[S Statement](statement S) (*string, error) {
//	configBytes, err := json.Marshal(statement)
//	if err != nil {
//		return nil, err
//	}
//	configStr := string(configBytes)
//	return &configStr, nil
//}
