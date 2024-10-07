package trigger

import (
	"context"
	"encoding/json"

	svcsdk "github.com/aws/aws-sdk-go/service/glue"
	svcsdkapi "github.com/aws/aws-sdk-go/service/glue/glueiface"
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

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/glue/v1alpha1"
	"github.com/crossplane-contrib/provider-aws/apis/v1alpha1"
	"github.com/crossplane-contrib/provider-aws/pkg/features"
	connectaws "github.com/crossplane-contrib/provider-aws/pkg/utils/connect/aws"
	errorutils "github.com/crossplane-contrib/provider-aws/pkg/utils/errors"
	"github.com/crossplane-contrib/provider-aws/pkg/utils/jsonpatch"
	"github.com/crossplane-contrib/provider-aws/pkg/utils/pointer"
)

type customConnector struct {
	kube client.Client
}

type customExternal struct {
	external
}

func (c *customConnector) Connect(ctx context.Context, mg cpresource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*svcapitypes.Trigger)
	if !ok {
		return nil, errors.New(errUnexpectedObject)
	}
	sess, err := connectaws.GetConfigV1(ctx, c.kube, mg, cr.Spec.ForProvider.Region)
	if err != nil {
		return nil, errors.Wrap(err, errCreateSession)
	}
	return newCustomExternal(c.kube, svcsdk.New(sess)), nil
}

func newCustomExternal(kube client.Client, client svcsdkapi.GlueAPI) *customExternal {
	return &customExternal{
		external{
			kube:           kube,
			client:         client,
			preObserve:     preObserve,
			postObserve:    postObserve,
			lateInitialize: nopLateInitialize,
			isUpToDate:     isUpToDate,
			preCreate:      preCreate,
			postCreate:     nopPostCreate,
			preDelete:      preDelete,
			postDelete:     nopPostDelete,
			preUpdate:      preUpdate,
			postUpdate:     nopPostUpdate},
	}
}

func (e *customExternal) Observe(ctx context.Context, mg cpresource.Managed) (managed.ExternalObservation, error) {
	return e.Observe(ctx, mg)
}

func (e *customExternal) Create(ctx context.Context, mg cpresource.Managed) (managed.ExternalCreation, error) {
	return e.Create(ctx, mg)
}

func (e *customExternal) Delete(ctx context.Context, mg cpresource.Managed) error {
	return e.Delete(ctx, mg)
}

func (e *customExternal) Update(ctx context.Context, mg cpresource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*svcapitypes.Trigger)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errUnexpectedObject)
	}
	input := &svcsdk.UpdateTriggerInput{}

	predicate := svcsdk.Predicate{}
	if cr.Spec.ForProvider.Predicate != nil {
		if cr.Spec.ForProvider.Predicate.Conditions != nil {
			for _, condition := range cr.Spec.ForProvider.Predicate.Conditions {
				predicate.Conditions = append(
					predicate.Conditions,
					&svcsdk.Condition{
						CrawlState:      condition.CrawlState,
						CrawlerName:     condition.CrawlerName,
						JobName:         condition.JobName,
						LogicalOperator: condition.LogicalOperator,
						State:           condition.State,
					},
				)
			}
		}
		if cr.Spec.ForProvider.Predicate.Logical != nil {
			predicate.Logical = cr.Spec.ForProvider.Predicate.Logical
		}
	}
	input.TriggerUpdate.Predicate = &predicate

	if cr.Spec.ForProvider.EventBatchingCondition != nil {
		if cr.Spec.ForProvider.EventBatchingCondition.BatchSize != nil {
			input.TriggerUpdate.EventBatchingCondition.BatchSize = cr.Spec.ForProvider.EventBatchingCondition.BatchSize
		}
		if cr.Spec.ForProvider.EventBatchingCondition.BatchWindow != nil {
			input.TriggerUpdate.EventBatchingCondition.BatchWindow = cr.Spec.ForProvider.EventBatchingCondition.BatchWindow
		}
	}

	var actions []*svcsdk.Action
	if cr.Spec.ForProvider.Actions != nil {
		for _, action := range cr.Spec.ForProvider.Actions {
			notificationProperty := &svcsdk.NotificationProperty{}
			if action.NotificationProperty != nil && action.NotificationProperty.NotifyDelayAfter != nil {
				notificationProperty.NotifyDelayAfter = action.NotificationProperty.NotifyDelayAfter
			}
			actions = append(actions, &svcsdk.Action{
				Arguments:             action.Arguments,
				CrawlerName:           action.CrawlerName,
				JobName:               action.JobName,
				NotificationProperty:  notificationProperty,
				SecurityConfiguration: action.SecurityConfiguration,
			})
		}
	}
	input.TriggerUpdate.Actions = actions

	if cr.Spec.ForProvider.Schedule != nil {
		input.TriggerUpdate.Schedule = cr.Spec.ForProvider.Schedule
	}

	if cr.Spec.ForProvider.Description != nil {
		input.TriggerUpdate.Description = cr.Spec.ForProvider.Description
	}

	if err := preUpdate(ctx, cr, input); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "pre-update failed")
	}
	resp, err := e.client.UpdateTriggerWithContext(ctx, input)
	return nopPostUpdate(ctx, cr, resp, managed.ExternalUpdate{}, errorutils.Wrap(err, errUpdate))
}

// SetupTrigger adds a controller that reconciles Trigger.
func SetupTrigger(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(svcapitypes.TriggerGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), v1alpha1.StoreConfigGroupVersionKind))
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&svcapitypes.Trigger{}).
		Complete(managed.NewReconciler(mgr,
			resource.ManagedKind(svcapitypes.TriggerGroupVersionKind),
			managed.WithExternalConnecter(&customConnector{kube: mgr.GetClient()}),
			managed.WithPollInterval(o.PollInterval),
			managed.WithLogger(o.Logger.WithValues("controller", name)),
			managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
			managed.WithConnectionPublishers(cps...)))
}

func preCreate(_ context.Context, cr *svcapitypes.Trigger, input *svcsdk.CreateTriggerInput) error {
	input.Name = pointer.ToOrNilIfZeroValue(meta.GetExternalName(cr))
	return nil
}

func preDelete(_ context.Context, cr *svcapitypes.Trigger, input *svcsdk.DeleteTriggerInput) (bool, error) {
	state := ptr.Deref(cr.Status.AtProvider.State, "")
	if state == svcsdk.TriggerStateActivating || state == svcsdk.TriggerStateDeactivating ||
		state == svcsdk.TriggerStateCreating || state == svcsdk.TriggerStateDeleting {
		return false, nil
	}
	input.Name = pointer.ToOrNilIfZeroValue(meta.GetExternalName(cr))
	return false, nil
}

func preObserve(_ context.Context, cr *svcapitypes.Trigger, input *svcsdk.GetTriggerInput) error {
	input.Name = pointer.ToOrNilIfZeroValue(meta.GetExternalName(cr))
	return nil
}

func isUpToDate(_ context.Context, cr *svcapitypes.Trigger, resp *svcsdk.GetTriggerOutput) (upToDate bool, diff string, err error) {
	state := ptr.Deref(cr.Status.AtProvider.State, "")
	if state == svcsdk.TriggerStateActivating || state == svcsdk.TriggerStateDeactivating ||
		state == svcsdk.TriggerStateCreating || state == svcsdk.TriggerStateDeleting {
		return true, "", nil
	}
	patch, err := createPatch(&cr.Spec.ForProvider, resp)
	if err != nil {
		return false, "", err
	}
	diff = cmp.Diff(&cr.Spec.ForProvider, patch, cmpopts.EquateEmpty(),
		cmpopts.IgnoreFields(svcapitypes.TriggerParameters{}, "Region"),
		cmpopts.IgnoreFields(svcapitypes.TriggerParameters{}, "Tags"),
		cmpopts.IgnoreFields(svcapitypes.TriggerParameters{}, "StartOnCreation"),
	)
	if diff != "" {
		return false, "Found observed difference in glue trigger\n" + diff, nil
	}
	return true, "", nil
}

func postObserve(_ context.Context, cr *svcapitypes.Trigger, resp *svcsdk.GetTriggerOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	cr.Status.AtProvider.ID = resp.Trigger.Id
	cr.Status.AtProvider.State = resp.Trigger.State
	cr.SetConditions(xpv1.Available())
	return obs, nil
}

func preUpdate(_ context.Context, cr *svcapitypes.Trigger, input *svcsdk.UpdateTriggerInput) error {
	input.Name = pointer.ToOrNilIfZeroValue(meta.GetExternalName(cr))
	return nil
}

func createPatch(currentParams *svcapitypes.TriggerParameters, resp *svcsdk.GetTriggerOutput) (*svcapitypes.TriggerParameters, error) {
	targetConfig := currentParams.DeepCopy()
	externalConfig := &svcapitypes.TriggerParameters{}
	externalConfig.Schedule = resp.Trigger.Schedule
	var actions []*svcapitypes.Action
	for _, action := range resp.Trigger.Actions {
		notificationProperty := &svcapitypes.NotificationProperty{}
		if action.NotificationProperty != nil && action.NotificationProperty.NotifyDelayAfter != nil {
			notificationProperty.NotifyDelayAfter = action.NotificationProperty.NotifyDelayAfter
		}
		actions = append(actions, &svcapitypes.Action{
			Arguments:             action.Arguments,
			CrawlerName:           action.CrawlerName,
			JobName:               action.JobName,
			NotificationProperty:  notificationProperty,
			SecurityConfiguration: action.SecurityConfiguration,
		})
	}
	externalConfig.Actions = actions
	externalConfig.Description = resp.Trigger.Description
	eventBatchingCondition := &svcapitypes.EventBatchingCondition{}
	if resp.Trigger.EventBatchingCondition != nil {
		if resp.Trigger.EventBatchingCondition.BatchSize != nil {
			eventBatchingCondition.BatchSize = resp.Trigger.EventBatchingCondition.BatchSize
		}
		if resp.Trigger.EventBatchingCondition.BatchWindow != nil {
			eventBatchingCondition.BatchWindow = resp.Trigger.EventBatchingCondition.BatchWindow
		}
	}
	externalConfig.EventBatchingCondition = eventBatchingCondition
	predicate := &svcapitypes.Predicate{}
	if resp.Trigger.Predicate != nil {
		if resp.Trigger.Predicate.Conditions != nil {
			for _, condition := range resp.Trigger.Predicate.Conditions {
				predicate.Conditions = append(predicate.Conditions, &svcapitypes.Condition{
					JobName: condition.JobName,
					State:   condition.State,
				})
			}
		}
		if resp.Trigger.Predicate.Logical != nil {
			predicate.Logical = resp.Trigger.Predicate.Logical
		}
	}
	externalConfig.Predicate = predicate
	externalConfig.TriggerType = resp.Trigger.Type
	externalConfig.WorkflowName = resp.Trigger.WorkflowName

	jsonPatch, err := jsonpatch.CreateJSONPatch(externalConfig, targetConfig)
	if err != nil {
		return nil, err
	}
	patch := &svcapitypes.TriggerParameters{}
	if err := json.Unmarshal(jsonPatch, patch); err != nil {
		return nil, err
	}
	return patch, nil
}
