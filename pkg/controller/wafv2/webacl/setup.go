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
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane-contrib/provider-aws/apis/v1alpha1"
	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/wafv2/manualv1alpha1"
	"github.com/crossplane-contrib/provider-aws/pkg/features"
	custommanaged "github.com/crossplane-contrib/provider-aws/pkg/utils/reconciler/managed"
)

const (
	errCouldNotFindWebACL = "could not find WebACL"
)

// SetupWebACL adds a controller that reconciles SetupWebAcl.
func SetupWebACL(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(svcapitypes.WebACLKind)

	opts := []option{customSetupExternal()}
	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), v1alpha1.StoreConfigGroupVersionKind))
	}

	reconcilerOpts := []managed.ReconcilerOption{
		managed.WithCriticalAnnotationUpdater(custommanaged.NewRetryingCriticalAnnotationUpdater(mgr.GetClient())),
		managed.WithInitializers(managed.NewNameAsExternalName(mgr.GetClient())),
		managed.WithExternalConnecter(&connector{kube: mgr.GetClient(), opts: opts}),
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

type CreateOrUpdateInput interface {
	*svcsdk.CreateWebACLInput | *svcsdk.UpdateWebACLInput
}
type custom struct {
	external
	cache *cache
}

type cache struct {
	listWebACLsOutput *svcsdk.ListWebACLsOutput
}

func customSetupExternal() func(*external) {
	return func(e *external) {
		c := &custom{}
		e.preCreate = preCreate
		e.preObserve = c.preObserve
		e.postObserve = postObserve
		e.preUpdate = c.preUpdate
		e.preDelete = c.preDelete
	}
}

func preCreate(_ context.Context, cr *svcapitypes.WebACL, input *svcsdk.CreateWebACLInput) error {
	input.Name = aws.String(meta.GetExternalName(cr))
	err := setInputStatements(cr, input.Rules)
	if err != nil {
		return err
	}
	return nil
}

func (c *custom) preObserve(_ context.Context, cr *svcapitypes.WebACL, input *svcsdk.GetWebACLInput) error {
	input.Name = aws.String(meta.GetExternalName(cr))

	listWebACLInput := svcsdk.ListWebACLsInput{
		Scope: cr.Spec.ForProvider.Scope,
	}
	ls, err := c.client.ListWebACLs(&listWebACLInput)
	if err != nil {
		return err
	}
	c.cache.listWebACLsOutput = ls
	for n, webACLSummary := range ls.WebACLs {
		if aws.StringValue(webACLSummary.Name) == meta.GetExternalName(cr) {
			input.Id = webACLSummary.Id
			break
		}
		if n == len(ls.WebACLs)-1 {
			return errors.New(fmt.Sprintf("%s %s", errCouldNotFindWebACL, meta.GetExternalName(cr)))
		}
	}
	return nil
}

//func isUpToDate(_ context.Context, cr *svcapitypes.WebACL, input *svcsdk.GetWebACLOutput) (bool, string, error) {
//}

func postObserve(_ context.Context, cr *svcapitypes.WebACL, resp *svcsdk.GetWebACLOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	if err.Error() == fmt.Sprintf("%s %s", errCouldNotFindWebACL, meta.GetExternalName(cr)) {
		obs.ResourceExists = false
	}
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

func (c *custom) preUpdate(_ context.Context, cr *svcapitypes.WebACL, input *svcsdk.UpdateWebACLInput) error {
	input.Name = aws.String(meta.GetExternalName(cr))
	lockToken, err := getLockToken(c.cache.listWebACLsOutput.WebACLs, cr)
	if err != nil {
		return err
	}
	input.LockToken = lockToken
	err = setInputStatements(cr, input.Rules)
	if err != nil {
		return err
	}
	return nil
}

func (c *custom) preDelete(_ context.Context, cr *svcapitypes.WebACL, input *svcsdk.DeleteWebACLInput) (bool, error) {
	input.Name = aws.String(meta.GetExternalName(cr))
	lockToken, err := getLockToken(c.cache.listWebACLsOutput.WebACLs, cr)
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

func statementFromString[S Statement](jsonConf *string) (*S, error) {
	if jsonConf == nil {
		jsonConf = aws.String("")
	}

	var statement S
	err := json.Unmarshal([]byte(*jsonConf), &statement)
	if err != nil {
		return nil, err
	}

	return &statement, nil
}

func setInputStatements(cr *svcapitypes.WebACL, rules []*svcsdk.Rule) (err error) {
	for i, rule := range cr.Spec.ForProvider.Rules {
		if rule.Statement.OrStatement != nil {
			rules[i].Statement.OrStatement, err = statementFromString[svcsdk.OrStatement](rule.Statement.OrStatement)
			if err != nil {
				return err
			}
		}
		if rule.Statement.AndStatement != nil {
			rules[i].Statement.AndStatement, err = statementFromString[svcsdk.AndStatement](rule.Statement.AndStatement)
			if err != nil {
				return err
			}
		}
		if rule.Statement.NotStatement != nil {
			rules[i].Statement.NotStatement, err = statementFromString[svcsdk.NotStatement](rule.Statement.NotStatement)
			if err != nil {
				return err
			}
		}
		if rule.Statement.ManagedRuleGroupStatement != nil && rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement != nil {
			rules[i].Statement.ManagedRuleGroupStatement.ScopeDownStatement, err = statementFromString[svcsdk.Statement](rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement)
			if err != nil {
				return err
			}
		}
		if rule.Statement.ByteMatchStatement != nil && rule.Statement.RateBasedStatement.ScopeDownStatement != nil {
			rules[i].Statement.RateBasedStatement.ScopeDownStatement, err = statementFromString[svcsdk.Statement](rule.Statement.RateBasedStatement.ScopeDownStatement)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
