package trigger

import (
	"context"
	"encoding/json"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	svcsdk "github.com/aws/aws-sdk-go/service/glue"
	"github.com/crossplane-contrib/provider-aws/pkg/utils/jsonpatch"
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/glue/v1alpha1"
	"github.com/crossplane-contrib/provider-aws/apis/v1alpha1"
	"github.com/crossplane-contrib/provider-aws/pkg/features"
	"github.com/crossplane-contrib/provider-aws/pkg/utils/pointer"
)

// SetupTrigger adds a controller that reconciles Trigger.
func SetupTrigger(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(svcapitypes.TriggerGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), v1alpha1.StoreConfigGroupVersionKind))
	}

	opts := []option{
		func(e *external) {
			e.preCreate = preCreate
			e.preDelete = preDelete
			e.preObserve = preObserve
			e.isUpToDate = isUpToDate
			e.postObserve = postObserve
			e.preUpdate = preUpdate
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&svcapitypes.Trigger{}).
		Complete(managed.NewReconciler(mgr,
			resource.ManagedKind(svcapitypes.TriggerGroupVersionKind),
			managed.WithExternalConnecter(&connector{kube: mgr.GetClient(), opts: opts}),
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

func isUpToDate(_ context.Context, cr *svcapitypes.Trigger, resp *svcsdk.GetTriggerOutput) (bool, string, error) {
	state := ptr.Deref(cr.Status.AtProvider.State, "")
	if state == svcsdk.TriggerStateActivating || state == svcsdk.TriggerStateDeactivating ||
		state == svcsdk.TriggerStateCreating || state == svcsdk.TriggerStateDeleting {
		return true, "", nil
	}
	patch, err := createPatch(&cr.Spec.ForProvider, resp)
	if err != nil {
		return false, "", err
	}
	diff := cmp.Diff(&svcapitypes.TriggerParameters{}, patch, cmpopts.EquateEmpty(),
		cmpopts.IgnoreTypes(svcapitypes.TriggerParameters{}, "Region"),
		cmpopts.IgnoreTypes(svcapitypes.TriggerParameters{}, "Tags"),
		cmpopts.IgnoreTypes(svcapitypes.TriggerParameters{}, "StartOnCreation"),
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
