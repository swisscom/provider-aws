/*
Copyright 2023 The Crossplane Authors.

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

package provisionedproduct

import (
	"context"
	"fmt"
	"strings"

	"github.com/crossplane-contrib/provider-aws/pkg/utils/metrics"

	cfsdkv2 "github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfsdkv2types "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	requestv1 "github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	svcsdk "github.com/aws/aws-sdk-go/service/servicecatalog"
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	cpresource "github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/servicecatalog/v1alpha1"
	"github.com/crossplane-contrib/provider-aws/apis/v1alpha1"
	awsclient "github.com/crossplane-contrib/provider-aws/pkg/clients"
	clientset "github.com/crossplane-contrib/provider-aws/pkg/clients/servicecatalog"
	"github.com/crossplane-contrib/provider-aws/pkg/features"
)

const (
	acceptLanguageEnglish = "en"

	msgProvisionedProductStatusSdkTainted        = "provisioned product has status TAINTED"
	msgProvisionedProductStatusSdkUnderChange    = "provisioned product is updating, availability depends on product"
	msgProvisionedProductStatusSdkPlanInProgress = "provisioned product is awaiting plan approval"
	msgProvisionedProductStatusSdkError          = "provisioned product has status ERROR"

	errCouldNotGetProvisionedProductOutputs = "could not get provisioned product outputs"
	errCouldNotGetCFParameters              = "could not get cloudformation stack parameters"
	errCouldNotDescribeRecord               = "could not describe record"
	errCouldNotLookupProduct                = "could not lookup product"
	errCreatExternalNameIsNotValid          = "external name is not equal provisioned product name"
	errAwsAPICodeInvalidParametersException = "Last Successful Provisioning Record doesn't exist."
)

type custom struct {
	*external
	kube    client.Client
	client  clientset.Client
	session *session.Session
	cache   cache
}

type cache struct {
	getProvisionedProductOutputs []*svcsdk.RecordOutput
}

func (c *custom) Connect(ctx context.Context, mg cpresource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*svcapitypes.ProvisionedProduct)
	if !ok {
		return nil, errors.New(errUnexpectedObject)
	}
	sess, err := awsclient.GetConfigV1(ctx, c.kube, mg, cr.Spec.ForProvider.Region)
	c.session = sess
	if err != nil {
		return nil, errors.Wrap(err, errCreateSession)
	}

	awsCfg, err := awsclient.GetConfig(ctx, c.kube, mg, cr.Spec.ForProvider.Region)
	if err != nil {
		return nil, errors.Wrap(err, errCreateSession)
	}
	cfClient := cfsdkv2.NewFromConfig(*awsCfg)
	svcClient := svcsdk.New(sess)
	c.client = &clientset.CustomServiceCatalogClient{CfClient: cfClient, Client: svcClient}
	// We do not re-implement all the ExternalClient interface, so we want
	// to reuse the generated one as much as we can (mostly for the Observe,
	// Create, Update, Delete methods which call all of our custom hooks)
	c.external = &external{
		kube:   c.kube,
		client: svcClient,

		// All of our overrides must go here
		isUpToDate:     c.isUpToDate,
		lateInitialize: c.lateInitialize,
		preObserve:     c.preObserve,
		postObserve:    c.postObserve,
		preUpdate:      c.preUpdate,
		preCreate:      c.preCreate,
		preDelete:      c.preDelete,

		// If we do not implement a method, we must specify the no-op function
		postCreate: nopPostCreate,
		postDelete: nopPostDelete,
		postUpdate: nopPostUpdate,
	}
	metrics.MetricAWSAPIRecCalls.WithLabelValues(cr.GetObjectKind().GroupVersionKind().Kind, cr.GetObjectKind().GroupVersionKind().Group, cr.Name, "create").Set(0)
	metrics.MetricAWSAPIRecCalls.WithLabelValues(cr.GetObjectKind().GroupVersionKind().Kind, cr.GetObjectKind().GroupVersionKind().Group, cr.Name, "observe").Set(0)
	metrics.MetricAWSAPIRecCalls.WithLabelValues(cr.GetObjectKind().GroupVersionKind().Kind, cr.GetObjectKind().GroupVersionKind().Group, cr.Name, "update").Set(0)
	metrics.MetricAWSAPIRecCalls.WithLabelValues(cr.GetObjectKind().GroupVersionKind().Kind, cr.GetObjectKind().GroupVersionKind().Group, cr.Name, "delete").Set(0)

	return c.external, nil
}

// SetupProvisionedProduct adds a controller that reconciles a ProvisionedProduct
func SetupProvisionedProduct(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(svcapitypes.ProvisionedProductKind)
	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), v1alpha1.StoreConfigGroupVersionKind))
	}

	reconcilerOpts := []managed.ReconcilerOption{
		managed.WithExternalConnecter(&custom{kube: mgr.GetClient()}),
		managed.WithPollInterval(o.PollInterval),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...),
	}

	if o.Features.Enabled(features.EnableAlphaManagementPolicies) {
		reconcilerOpts = append(reconcilerOpts, managed.WithManagementPolicies())
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&svcapitypes.ProvisionedProduct{}).
		Complete(managed.NewReconciler(mgr,
			resource.ManagedKind(svcapitypes.ProvisionedProductGroupVersionKind),
			reconcilerOpts...))
}

func (c *custom) lateInitialize(spec *svcapitypes.ProvisionedProductParameters, _ *svcsdk.DescribeProvisionedProductOutput) error {
	acceptLanguageEnglish := acceptLanguageEnglish
	spec.AcceptLanguage = awsclient.LateInitializeStringPtr(spec.AcceptLanguage, &acceptLanguageEnglish)
	return nil
}

func (c *custom) preCreate(_ context.Context, ds *svcapitypes.ProvisionedProduct, input *svcsdk.ProvisionProductInput) error {
	metrics.MetricAWSAPIRecCalls.WithLabelValues(ds.GetObjectKind().GroupVersionKind().Kind, ds.GetObjectKind().GroupVersionKind().Group, ds.Name, "create").Inc()
	input.ProvisionToken = aws.String(genIdempotencyToken())
	if ds.GetName() != meta.GetExternalName(ds) {
		return errors.New(errCreatExternalNameIsNotValid)
	}
	input.ProvisionedProductName = aws.String(meta.GetExternalName(ds))
	return nil
}

func (c *custom) preUpdate(_ context.Context, ds *svcapitypes.ProvisionedProduct, input *svcsdk.UpdateProvisionedProductInput) error {
	metrics.MetricAWSAPIRecCalls.WithLabelValues(ds.GetObjectKind().GroupVersionKind().Kind, ds.GetObjectKind().GroupVersionKind().Group, ds.Name, "update").Inc()
	input.UpdateToken = aws.String(genIdempotencyToken())
	if ds.GetName() == meta.GetExternalName(ds) {
		input.ProvisionedProductName = aws.String(meta.GetExternalName(ds))
	} else {
		input.ProvisionedProductId = aws.String(meta.GetExternalName(ds))
	}
	return nil
}

func (c *custom) preObserve(_ context.Context, ds *svcapitypes.ProvisionedProduct, input *svcsdk.DescribeProvisionedProductInput) error {
	if ds.GetName() == meta.GetExternalName(ds) {
		input.Name = aws.String(meta.GetExternalName(ds))
	} else {
		input.Id = aws.String(meta.GetExternalName(ds))
	}
	metrics.MetricAWSAPIRecCalls.WithLabelValues(ds.GetObjectKind().GroupVersionKind().Kind, ds.GetObjectKind().GroupVersionKind().Group, ds.Name, "observe").Inc()
	return nil
}

func (c *custom) isUpToDate(ctx context.Context, ds *svcapitypes.ProvisionedProduct, resp *svcsdk.DescribeProvisionedProductOutput) (bool, string, error) { // nolint:gocyclo
	// If the product is undergoing change, we want to assume that it is not up-to-date. This will force this resource
	// to be queued for an update (which will be skipped due to UNDER_CHANGE), and once that update fails, we will
	// recheck the status again. This will allow us to quickly transition from UNDER_CHANGE to AVAILABLE without having
	// to wait for the entire polling interval to pass before re-checking the status.
	if pointer.StringDeref(resp.ProvisionedProductDetail.Status, "") == string(svcapitypes.ProvisionedProductStatus_SDK_UNDER_CHANGE) {
		return true, "", nil
	}

	getPPOutputInput := &svcsdk.GetProvisionedProductOutputsInput{ProvisionedProductId: resp.ProvisionedProductDetail.Id}
	getPPOutput, err := c.client.GetProvisionedProductOutputs(getPPOutputInput)
	c.session.Handlers.Send.PushFront(func(r *requestv1.Request) {
		metrics.MetricAWSAPIRecCalls.WithLabelValues(ds.GetObjectKind().GroupVersionKind().Kind, ds.GetObjectKind().GroupVersionKind().Group, ds.Name, "observe").Inc()
	})
	if err != nil {
		// We want to specifically handle this exception, since it will occur when something
		// is wrong with the provisioned product (error on creation, tainted, etc)
		// We will be able to handle those specific cases in postObserve
		var aerr awserr.Error
		if ok := errors.As(err, &aerr); ok && aerr.Code() == svcsdk.ErrCodeInvalidParametersException && aerr.Message() == errAwsAPICodeInvalidParametersException {
			return false, "", nil
		}
		return false, "", errors.Wrap(err, errCouldNotGetProvisionedProductOutputs)
	}
	c.cache.getProvisionedProductOutputs = getPPOutput.Outputs
	cfStackParameters, err := c.client.GetCloudformationStackParameters(getPPOutput.Outputs)
	metrics.MetricAWSAPIRecCalls.WithLabelValues(ds.GetObjectKind().GroupVersionKind().Kind, ds.GetObjectKind().GroupVersionKind().Group, ds.Name, "observe").Inc()
	if err != nil {
		return false, "", errors.Wrap(err, errCouldNotGetCFParameters)
	}

	productOrArtifactIsChanged, err := c.productOrArtifactIsChanged(ds, resp.ProvisionedProductDetail)
	if err != nil {
		return false, "", errors.Wrap(err, "could not discover if product or artifact ids have changed")
	}
	provisioningParamsAreChanged, err := c.provisioningParamsAreChanged(ctx, cfStackParameters, ds)
	if err != nil {
		return false, "", errors.Wrap(err, "could not compare provisioning parameters with previous ones")
	}

	if productOrArtifactIsChanged || provisioningParamsAreChanged {
		return false, "", nil
	}
	return true, "", nil
}

func (c *custom) postObserve(_ context.Context, ds *svcapitypes.ProvisionedProduct, resp *svcsdk.DescribeProvisionedProductOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	describeRecordInput := svcsdk.DescribeRecordInput{Id: resp.ProvisionedProductDetail.LastRecordId}
	describeRecordOutput, err := c.client.DescribeRecord(&describeRecordInput)
	metrics.MetricAWSAPIRecCalls.WithLabelValues(ds.GetObjectKind().GroupVersionKind().Kind, ds.GetObjectKind().GroupVersionKind().Group, ds.Name, "observe").Inc()
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, errCouldNotDescribeRecord)
	}

	setConditions(describeRecordOutput, resp, ds)

	var outputs = make(map[string]*svcapitypes.RecordOutput)
	for _, v := range c.cache.getProvisionedProductOutputs {
		outputs[*v.OutputKey] = &svcapitypes.RecordOutput{
			Description: v.Description,
			OutputValue: v.OutputValue}
	}

	ds.Status.AtProvider.Outputs = outputs
	ds.Status.AtProvider.ARN = resp.ProvisionedProductDetail.Arn
	ds.Status.AtProvider.CreatedTime = &metav1.Time{Time: *resp.ProvisionedProductDetail.CreatedTime}
	ds.Status.AtProvider.LastProvisioningRecordID = resp.ProvisionedProductDetail.LastProvisioningRecordId
	ds.Status.AtProvider.LaunchRoleARN = resp.ProvisionedProductDetail.LaunchRoleArn
	ds.Status.AtProvider.Status = resp.ProvisionedProductDetail.Status
	ds.Status.AtProvider.StatusMessage = resp.ProvisionedProductDetail.StatusMessage
	ds.Status.AtProvider.ProvisionedProductType = resp.ProvisionedProductDetail.Type
	ds.Status.AtProvider.RecordType = describeRecordOutput.RecordDetail.RecordType
	ds.Status.AtProvider.LastPathID = describeRecordOutput.RecordDetail.PathId
	ds.Status.AtProvider.LastProductID = describeRecordOutput.RecordDetail.ProductId
	ds.Status.AtProvider.LastProvisioningArtifactID = describeRecordOutput.RecordDetail.ProvisioningArtifactId
	ds.Status.AtProvider.LastProvisioningParameters = ds.Spec.ForProvider.ProvisioningParameters

	return obs, nil
}

func (c *custom) preDelete(_ context.Context, ds *svcapitypes.ProvisionedProduct, input *svcsdk.TerminateProvisionedProductInput) (bool, error) {
	if pointer.StringDeref(ds.Status.AtProvider.Status, "") == string(svcapitypes.ProvisionedProductStatus_SDK_UNDER_CHANGE) {
		return true, nil
	}
	input.TerminateToken = aws.String(genIdempotencyToken())
	if ds.GetName() == meta.GetExternalName(ds) {
		input.ProvisionedProductName = aws.String(meta.GetExternalName(ds))
	} else {
		input.ProvisionedProductId = aws.String(meta.GetExternalName(ds))
	}
	metrics.MetricAWSAPIRecCalls.WithLabelValues(ds.GetObjectKind().GroupVersionKind().Kind, ds.GetObjectKind().GroupVersionKind().Group, ds.Name, "delete").Inc()
	return false, nil
}

func setConditions(describeRecordOutput *svcsdk.DescribeRecordOutput, resp *svcsdk.DescribeProvisionedProductOutput, cr *svcapitypes.ProvisionedProduct) {
	ppStatus := aws.StringValue(resp.ProvisionedProductDetail.Status)
	switch {
	case ppStatus == string(svcapitypes.ProvisionedProductStatus_SDK_AVAILABLE):
		cr.SetConditions(xpv1.Available())
	case ppStatus == string(svcapitypes.ProvisionedProductStatus_SDK_UNDER_CHANGE):
		recordType := pointer.StringDeref(describeRecordOutput.RecordDetail.RecordType, "UPDATE_PROVISIONED_PRODUCT")
		switch {
		case recordType == "PROVISION_PRODUCT":
			cr.SetConditions(xpv1.Creating())
		case recordType == "UPDATE_PROVISIONED_PRODUCT":
			cr.SetConditions(xpv1.Available().WithMessage(msgProvisionedProductStatusSdkUnderChange))
		case recordType == "TERMINATE_PROVISIONED_PRODUCT":
			cr.SetConditions(xpv1.Deleting())
		}
	case ppStatus == string(svcapitypes.ProvisionedProductStatus_SDK_PLAN_IN_PROGRESS):
		cr.SetConditions(xpv1.Unavailable().WithMessage(msgProvisionedProductStatusSdkPlanInProgress))
	case ppStatus == string(svcapitypes.ProvisionedProductStatus_SDK_ERROR):
		cr.SetConditions(xpv1.Unavailable().WithMessage(msgProvisionedProductStatusSdkError))
	case ppStatus == string(svcapitypes.ProvisionedProductStatus_SDK_TAINTED):
		cr.SetConditions(xpv1.Unavailable().WithMessage(msgProvisionedProductStatusSdkTainted))
	}
}

func (c *custom) provisioningParamsAreChanged(ctx context.Context, cfStackParams []cfsdkv2types.Parameter, ds *svcapitypes.ProvisionedProduct) (bool, error) {
	nn := types.NamespacedName{
		Name: ds.GetName(),
	}
	xr := svcapitypes.ProvisionedProduct{}
	err := c.kube.Get(ctx, nn, &xr)
	if err != nil {
		return false, err
	}
	// Product should be updated if amount of provisioning params from desired stats lesser than the amount from previous reconciliation loop
	if len(xr.Status.AtProvider.LastProvisioningParameters) > len(ds.Spec.ForProvider.ProvisioningParameters) {
		return true, nil
	}

	cfStackKeyValue := make(map[string]string)
	for _, v := range cfStackParams {
		if v.ParameterKey != nil {
			cfStackKeyValue[*v.ParameterKey] = pointer.StringDeref(v.ParameterValue, "")
		}
	}

	for _, v := range ds.Spec.ForProvider.ProvisioningParameters {
		// In this statement/comparison, the provider ignores spaces from the left and right of the parameter value from
		// the desired state. Because on cloudformation side spaces are also trimmed
		if cfv, ok := cfStackKeyValue[*v.Key]; ok && strings.TrimSpace(pointer.StringDeref(v.Value, "")) == cfv {
			continue
		} else if !ok {
			return false, errors.Errorf("provisioning parameter %s is not present in cloud formation stack", *v.Key)
		} else {
			return true, nil
		}
	}

	return false, nil
}

func (c *custom) productOrArtifactIsChanged(ds *svcapitypes.ProvisionedProduct, resp *svcsdk.ProvisionedProductDetail) (bool, error) {
	// ProvisioningArtifactID and ProvisioningArtifactName are mutual exclusive params, the same about ProductID and ProductName
	// But if describe a provisioned product aws api will return only IDs, so it's impossible to compare names with ids
	// Conditional statement below works only if desired state includes ProvisioningArtifactID and ProductID
	if ds.Spec.ForProvider.ProvisioningArtifactID != nil && ds.Spec.ForProvider.ProductID != nil &&
		(*ds.Spec.ForProvider.ProvisioningArtifactID != *resp.ProvisioningArtifactId ||
			*ds.Spec.ForProvider.ProductID != *resp.ProductId) {
		return true, nil
		// In case if desired state includes not only IDs provider runs func `getArtifactID`, which produces
		// additional request to aws api and retrieves an artifact id(even if it is already defined in the desired state)
		// based on ProductId/ProductName for further comparison with artifact id in the current state
	} else if ds.Spec.ForProvider.ProvisioningArtifactName != nil || ds.Spec.ForProvider.ProductName != nil {
		desiredArtifactID, err := c.getArtifactID(ds)
		if err != nil {
			return false, err
		}
		if desiredArtifactID != *resp.ProvisioningArtifactId {
			return true, nil
		}
	}
	return false, nil
}

func (c *custom) getArtifactID(ds *svcapitypes.ProvisionedProduct) (string, error) {
	if ds.Spec.ForProvider.ProvisioningArtifactName != nil && ds.Spec.ForProvider.ProvisioningArtifactID != nil {
		return "", errors.Wrap(errors.New("artifact id and name are mutually exclusive"), errCouldNotLookupProduct)
	}

	input := svcsdk.DescribeProductInput{
		Id:   ds.Spec.ForProvider.ProductID,
		Name: ds.Spec.ForProvider.ProductName,
	}
	// DescribeProvisioningArtifact method fits much better, but it has a bug
	output, err := c.client.DescribeProduct(&input)
	metrics.MetricAWSAPIRecCalls.WithLabelValues(ds.GetObjectKind().GroupVersionKind().Kind, ds.GetObjectKind().GroupVersionKind().Group, ds.Name, "observe").Inc()
	if err != nil {
		return "", errors.Wrap(err, errCouldNotLookupProduct)
	}

	for _, artifact := range output.ProvisioningArtifacts {
		if pointer.StringDeref(ds.Spec.ForProvider.ProvisioningArtifactName, "") == *artifact.Name ||
			pointer.StringDeref(ds.Spec.ForProvider.ProvisioningArtifactID, "") == *artifact.Id {
			return *artifact.Id, nil
		}
	}
	return "", errors.Wrap(errors.New("artifact not found"), errCouldNotLookupProduct)
}

func genIdempotencyToken() string {
	return fmt.Sprintf("provider-aws-%s", uuid.New())
}
