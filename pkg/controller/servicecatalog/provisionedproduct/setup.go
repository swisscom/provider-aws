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
	"reflect"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	cfsdkv2 "github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfsdkv2types "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/servicecatalog"
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
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

// SetupProvisionedProduct adds a controller that reconciles a ProvisionedProduct
func SetupProvisionedProduct(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(svcapitypes.ProvisionedProductKind)
	awsCfg, err := awsconfig.LoadDefaultConfig(context.TODO())
	if err != nil {
		return err
	}
	cfClient := cfsdkv2.NewFromConfig(awsCfg)
	kube := mgr.GetClient()
	opts := []option{prepareSetupExternal(cfClient, kube)}
	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), v1alpha1.StoreConfigGroupVersionKind))
	}

	reconcilerOpts := []managed.ReconcilerOption{
		managed.WithExternalConnecter(&connector{kube: kube, opts: opts}),
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

func prepareSetupExternal(cfClient *cfsdkv2.Client, kube client.Client) func(*external) {
	return func(e *external) {
		c := &custom{client: &clientset.CustomServiceCatalogClient{CfClient: cfClient, Client: e.client}, kube: kube}
		e.preCreate = preCreate
		e.preUpdate = c.preUpdate
		e.isUpToDate = c.isUpToDate
		e.lateInitialize = c.lateInitialize
		e.preObserve = c.preObserve
		e.postObserve = c.postObserve
		e.preDelete = preDelete
	}
}

type custom struct {
	kube   client.Client
	client clientset.Client
	cache  cache
}

type cache struct {
	getProvisionedProductOutputs []*svcsdk.RecordOutput
}

func (c *custom) lateInitialize(spec *svcapitypes.ProvisionedProductParameters, _ *svcsdk.DescribeProvisionedProductOutput) error {
	acceptLanguageEnglish := acceptLanguageEnglish
	spec.AcceptLanguage = awsclient.LateInitializeStringPtr(spec.AcceptLanguage, &acceptLanguageEnglish)
	return nil
}

func preCreate(_ context.Context, cr *svcapitypes.ProvisionedProduct, input *svcsdk.ProvisionProductInput) error {
	input.ProvisionToken = aws.String(genIdempotencyToken())
	if cr.GetName() != meta.GetExternalName(cr) {
		return errors.New(errCreatExternalNameIsNotValid)
	}
	input.ProvisionedProductName = aws.String(meta.GetExternalName(cr))
	return nil
}

func (c *custom) preUpdate(_ context.Context, cr *svcapitypes.ProvisionedProduct, input *svcsdk.UpdateProvisionedProductInput) error {
	input.UpdateToken = aws.String(genIdempotencyToken())
	if cr.GetName() == meta.GetExternalName(cr) {
		input.ProvisionedProductName = aws.String(meta.GetExternalName(cr))
	} else {
		input.ProvisionedProductId = aws.String(meta.GetExternalName(cr))
	}
	return nil
}

func (c *custom) isUpToDate(ctx context.Context, ds *svcapitypes.ProvisionedProduct, resp *svcsdk.DescribeProvisionedProductOutput) (bool, string, error) { // nolint:gocyclo
	// If the product is undergoing change, we want to assume that it is not up-to-date. This will force this resource
	// to be queued for an update (which will be skipped due to UNDER_CHANGE), and once that update fails, we will
	// recheck the status again. This will allow us to quickly transition from UNDER_CHANGE to AVAILABLE without having
	// to wait for the entire polling interval to pass before re-checking the status.
	if pointer.StringDeref(ds.Status.AtProvider.Status, "") == string(svcapitypes.ProvisionedProductStatus_SDK_UNDER_CHANGE) ||
		reflect.ValueOf(ds.Status.AtProvider).IsZero() {
		return true, "", nil
	}

	getPPOutputInput := &svcsdk.GetProvisionedProductOutputsInput{ProvisionedProductId: resp.ProvisionedProductDetail.Id}
	getPPOutput, err := c.client.GetProvisionedProductOutputs(getPPOutputInput)
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
	if err != nil {
		return false, "", errors.Wrap(err, errCouldNotGetCFParameters)
	}

	productOrArtifactIsChanged, err := c.productOrArtifactIsChanged(&ds.Spec.ForProvider, resp.ProvisionedProductDetail)
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

func (c *custom) preObserve(_ context.Context, cr *svcapitypes.ProvisionedProduct, input *svcsdk.DescribeProvisionedProductInput) error {
	if cr.GetName() == meta.GetExternalName(cr) {
		input.Name = aws.String(meta.GetExternalName(cr))
	} else {
		input.Id = aws.String(meta.GetExternalName(cr))
	}
	return nil

}

func (c *custom) postObserve(_ context.Context, cr *svcapitypes.ProvisionedProduct, resp *svcsdk.DescribeProvisionedProductOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	describeRecordInput := svcsdk.DescribeRecordInput{Id: resp.ProvisionedProductDetail.LastRecordId}
	describeRecordOutput, err := c.client.DescribeRecord(&describeRecordInput)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, errCouldNotDescribeRecord)
	}

	setConditions(describeRecordOutput, resp, cr)

	var outputs = make(map[string]*svcapitypes.RecordOutput)
	for _, v := range c.cache.getProvisionedProductOutputs {
		outputs[*v.OutputKey] = &svcapitypes.RecordOutput{
			Description: v.Description,
			OutputValue: v.OutputValue}
	}

	cr.Status.AtProvider.Outputs = outputs
	cr.Status.AtProvider.ARN = resp.ProvisionedProductDetail.Arn
	cr.Status.AtProvider.CreatedTime = &metav1.Time{Time: *resp.ProvisionedProductDetail.CreatedTime}
	cr.Status.AtProvider.LastProvisioningRecordID = resp.ProvisionedProductDetail.LastProvisioningRecordId
	cr.Status.AtProvider.LaunchRoleARN = resp.ProvisionedProductDetail.LaunchRoleArn
	cr.Status.AtProvider.Status = resp.ProvisionedProductDetail.Status
	cr.Status.AtProvider.StatusMessage = resp.ProvisionedProductDetail.StatusMessage
	cr.Status.AtProvider.ProvisionedProductType = resp.ProvisionedProductDetail.Type
	cr.Status.AtProvider.RecordType = describeRecordOutput.RecordDetail.RecordType
	cr.Status.AtProvider.LastPathID = describeRecordOutput.RecordDetail.PathId
	cr.Status.AtProvider.LastProductID = describeRecordOutput.RecordDetail.ProductId
	cr.Status.AtProvider.LastProvisioningArtifactID = describeRecordOutput.RecordDetail.ProvisioningArtifactId
	cr.Status.AtProvider.LastProvisioningParameters = cr.Spec.ForProvider.ProvisioningParameters

	return obs, nil
}

func preDelete(_ context.Context, cr *svcapitypes.ProvisionedProduct, input *svcsdk.TerminateProvisionedProductInput) (bool, error) {
	if pointer.StringDeref(cr.Status.AtProvider.Status, "") == string(svcapitypes.ProvisionedProductStatus_SDK_UNDER_CHANGE) {
		return true, nil
	}
	input.TerminateToken = aws.String(genIdempotencyToken())
	if cr.GetName() == meta.GetExternalName(cr) {
		input.ProvisionedProductName = aws.String(meta.GetExternalName(cr))
	} else {
		input.ProvisionedProductId = aws.String(meta.GetExternalName(cr))
	}
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
		cfStackKeyValue[*v.ParameterKey] = pointer.StringDeref(v.ParameterValue, "")
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

func (c *custom) productOrArtifactIsChanged(ds *svcapitypes.ProvisionedProductParameters, resp *svcsdk.ProvisionedProductDetail) (bool, error) {
	// ProvisioningArtifactID and ProvisioningArtifactName are mutual exclusive params, the same about ProductID and ProductName
	// But if describe a provisioned product aws api will return only IDs, so it's impossible to compare names with ids
	// Conditional statement below works only if desired state includes ProvisioningArtifactID and ProductID
	if ds.ProvisioningArtifactID != nil && ds.ProductID != nil &&
		(*ds.ProvisioningArtifactID != *resp.ProvisioningArtifactId ||
			*ds.ProductID != *resp.ProductId) {
		return true, nil
		// In case if desired state includes not only IDs provider runs func `getArtifactID`, which produces
		// additional request to aws api and retrieves an artifact id(even if it is already defined in the desired state)
		// based on ProductId/ProductName for further comparison with artifact id in the current state
	} else if ds.ProvisioningArtifactName != nil || ds.ProductName != nil {
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

func (c *custom) getArtifactID(ds *svcapitypes.ProvisionedProductParameters) (string, error) {
	if ds.ProvisioningArtifactName != nil && ds.ProvisioningArtifactID != nil {
		return "", errors.Wrap(errors.New("artifact id and name are mutually exclusive"), errCouldNotLookupProduct)
	}

	input := svcsdk.DescribeProductInput{
		Id:   ds.ProductID,
		Name: ds.ProductName,
	}
	// DescribeProvisioningArtifact method fits much better, but it has a bug
	output, err := c.client.DescribeProduct(&input)
	if err != nil {
		return "", errors.Wrap(err, errCouldNotLookupProduct)
	}

	for _, artifact := range output.ProvisioningArtifacts {
		if pointer.StringDeref(ds.ProvisioningArtifactName, "") == *artifact.Name ||
			pointer.StringDeref(ds.ProvisioningArtifactID, "") == *artifact.Id {
			return pointer.StringDeref(artifact.Id, ""), nil
		}
	}
	return "", errors.Wrap(errors.New("artifact not found"), errCouldNotLookupProduct)
}

func genIdempotencyToken() string {
	return fmt.Sprintf("provider-aws-%s", uuid.New())
}
