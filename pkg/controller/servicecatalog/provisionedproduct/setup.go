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

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	cfsdkv2 "github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfsdkv2types "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
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
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/servicecatalog/v1alpha1"
	"github.com/crossplane-contrib/provider-aws/apis/v1alpha1"
	aws "github.com/crossplane-contrib/provider-aws/pkg/clients"
	awsclient "github.com/crossplane-contrib/provider-aws/pkg/clients"
	clientset "github.com/crossplane-contrib/provider-aws/pkg/clients/servicecatalog"
	"github.com/crossplane-contrib/provider-aws/pkg/features"
)

const (
	acceptLanguageEnglish = "en"

	msgProvisionedProductStatusSdkTainted     = "provisioned product has status TAINTED"
	msgProvisionedProductStatusSdkUnderChange = "provisioned product is updating, availability depends on product"

	errUpdatePending                        = "provisioned product is already under change, not updating"
	errProvisionedProductStatusSdkError     = "provisioned product has status ERROR"
	errCouldNotGetProvisionedProductOutputs = "could not get provisioned product outputs"
	errCouldNotGetCFParameters              = "could not get cloudformation stack parameters"
	errCouldNotDescribeRecord               = "could not describe record"
)

// SetupProvisionedProduct adds a controller that reconciles a ProvisionedProduct
func SetupProvisionedProduct(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(svcapitypes.ProvisionedProductKind)
	awsCfg, err := awsconfig.LoadDefaultConfig(context.TODO())
	if err != nil {
		return err
	}
	cfClient := cfsdkv2.NewFromConfig(awsCfg)
	opts := []option{prepareSetupExternal(cfClient)}
	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), v1alpha1.StoreConfigGroupVersionKind))
	}

	reconcilerOpts := []managed.ReconcilerOption{
		managed.WithExternalConnecter(&connector{kube: mgr.GetClient(), opts: opts}),
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

func prepareSetupExternal(cfClient *cfsdkv2.Client) func(*external) {
	return func(e *external) {
		c := &custom{client: &clientset.CustomServiceCatalogClient{CfClient: cfClient, Client: e.client}}
		e.isUpToDate = c.isUpToDate
		e.lateInitialize = c.lateInitialize
		e.postObserve = c.postObserve
		e.preUpdate = c.preUpdate
		e.preCreate = preCreate
		e.preDelete = preDelete
	}
}

type custom struct {
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

func (c *custom) isUpToDate(_ context.Context, ds *svcapitypes.ProvisionedProduct, resp *svcsdk.DescribeProvisionedProductOutput) (bool, string, error) {
	if pointer.StringDeref(ds.Status.AtProvider.Status, "") == string(svcapitypes.ProvisionedProductStatus_SDK_UNDER_CHANGE) {
		return true, "", nil
	}
	getPPOutputInput := &svcsdk.GetProvisionedProductOutputsInput{ProvisionedProductId: resp.ProvisionedProductDetail.Id}
	getPPOutput, err := c.client.GetProvisionedProductOutputs(getPPOutputInput)
	if err != nil {
		// We want to specifically handle this exception, since it will occur when something
		// is wrong with the provisioned product (error on creation, tainted, etc)
		// We will be able to handle those specific cases in postObserve
		var aerr awserr.Error
		if ok := errors.As(err, &aerr); ok {
			if aerr.Code() == svcsdk.ErrCodeInvalidParametersException && aerr.Message() == "Last Successful Provisioning Record doesn't exist." {
				return false, "", nil
			}
		}
		return false, "", errors.Wrap(err, errCouldNotGetProvisionedProductOutputs)
	}
	c.cache.getProvisionedProductOutputs = getPPOutput.Outputs
	cfStackParameters, err := c.client.GetCloudformationStackParameters(getPPOutput.Outputs)
	if err != nil {
		return false, "", errors.Wrap(err, errCouldNotGetCFParameters)
	}

	productOrArtifactAreNotChanged, err := c.productOrArtifactAreNotChanged(&ds.Spec.ForProvider, resp.ProvisionedProductDetail)
	if err != nil {
		return false, "", err
	}

	if !provisioningParamsAreNotChanged(cfStackParameters, ds.Spec.ForProvider.ProvisioningParameters) || !productOrArtifactAreNotChanged {
		return false, "", nil
	}
	return true, "", nil
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

	ppStatus := aws.StringValue(resp.ProvisionedProductDetail.Status)
	switch {
	case ppStatus == string(svcapitypes.ProvisionedProductStatus_SDK_AVAILABLE):
		cr.Status.SetConditions(xpv1.Available())
	case ppStatus == string(svcapitypes.ProvisionedProductStatus_SDK_UNDER_CHANGE) && *describeRecordOutput.RecordDetail.RecordType == "UPDATE_PROVISIONED_PRODUCT":
		cr.SetConditions(xpv1.Available().WithMessage(msgProvisionedProductStatusSdkUnderChange))
	case ppStatus == string(svcapitypes.ProvisionedProductStatus_SDK_ERROR):
		cr.Status.SetConditions(xpv1.Unavailable().WithMessage(errProvisionedProductStatusSdkError))
	case ppStatus == string(svcapitypes.ProvisionedProductStatus_SDK_TAINTED):
		cr.Status.SetConditions(xpv1.Unavailable().WithMessage(msgProvisionedProductStatusSdkTainted))
	}

	var outputs = make(map[string]*svcapitypes.RecordOutput)
	for _, v := range c.cache.getProvisionedProductOutputs {
		outputs[*v.OutputKey] = &svcapitypes.RecordOutput{
			Description: v.Description,
			OutputValue: v.OutputValue}
	}

	if meta.GetExternalName(cr) == "" {
		meta.SetExternalName(cr, *cr.Spec.ForProvider.Name)
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

	return obs, nil
}

func preCreate(_ context.Context, cr *svcapitypes.ProvisionedProduct, obj *svcsdk.ProvisionProductInput) error {
	obj.ProvisionToken = aws.String(genIdempotencyToken())
	meta.SetExternalName(cr, *cr.Spec.ForProvider.Name)
	return nil
}

func preDelete(_ context.Context, cr *svcapitypes.ProvisionedProduct, obj *svcsdk.TerminateProvisionedProductInput) (bool, error) {
	if pointer.StringDeref(cr.Status.AtProvider.Status, "") == string(svcapitypes.ProvisionedProductStatus_SDK_UNDER_CHANGE) {
		return true, nil
	}
	obj.TerminateToken = aws.String(genIdempotencyToken())
	obj.ProvisionedProductName = aws.String(meta.GetExternalName(cr))
	return false, nil
}

func (c *custom) preUpdate(_ context.Context, cr *svcapitypes.ProvisionedProduct, input *svcsdk.UpdateProvisionedProductInput) error {
	if pointer.StringDeref(cr.Status.AtProvider.Status, "") == string(svcapitypes.ProvisionedProductStatus_SDK_UNDER_CHANGE) {
		return errors.New(errUpdatePending)
	}
	input.UpdateToken = aws.String(genIdempotencyToken())
	input.ProvisionedProductName = aws.String(meta.GetExternalName(cr))
	return nil
}

func provisioningParamsAreNotChanged(cfStackParams []cfsdkv2types.Parameter, currentParams []*svcapitypes.ProvisioningParameter) bool {
	if len(cfStackParams) != len(currentParams) {
		return false
	}

	cfStackKeyValue := make(map[string]string)
	for _, v := range cfStackParams {
		cfStackKeyValue[*v.ParameterKey] = *v.ParameterValue
	}

	for _, v := range currentParams {
		if cfv, ok := cfStackKeyValue[*v.Key]; ok && cfv == *v.Value {
			continue
		} else {
			return false
		}
	}
	return true
}

func (c *custom) productOrArtifactAreNotChanged(ds *svcapitypes.ProvisionedProductParameters, resp *svcsdk.ProvisionedProductDetail) (bool, error) {
	// ProvisioningArtifactID and ProvisioningArtifactName are mutual exclusive params, the same about ProductID and ProductName
	// But if describe a provisioned product aws api will return only IDs, so it's impossible to compare names with ids
	// Conditional statement below works only if desired state includes ProvisioningArtifactID and ProductID
	if ds.ProvisioningArtifactID != nil && ds.ProductID != nil &&
		(*ds.ProvisioningArtifactID != *resp.ProvisioningArtifactId ||
			*ds.ProductID != *resp.ProductId) {
		return false, nil
		// In case if desired state includes not only IDs provider runs func `getArtifactID`, which produces
		// additional request to aws api and retrieves an artifact id based on ProductId/ProductName and ProvisioningArtifactId/ProvisioningArtifactName
		// for further comparison with artifact id in the current state
	} else if ds.ProvisioningArtifactName != nil || ds.ProductName != nil {
		desiredArtifactID, err := c.getArtifactID(ds)
		if err != nil {
			return false, err
		}
		if desiredArtifactID != *resp.ProvisioningArtifactId {
			return false, nil
		}
	}
	return true, nil
}

func (c *custom) getArtifactID(crParams *svcapitypes.ProvisionedProductParameters) (string, error) {
	input := svcsdk.DescribeProvisioningArtifactInput{
		ProductId:                crParams.ProductID,
		ProvisioningArtifactId:   crParams.ProvisioningArtifactID,
		ProductName:              crParams.ProductName,
		ProvisioningArtifactName: crParams.ProvisioningArtifactName,
	}
	output, err := c.client.DescribeProvisioningArtifact(&input)
	if err != nil {
		return "", err
	}
	return *output.ProvisioningArtifactDetail.Id, nil
}

func genIdempotencyToken() string {
	return fmt.Sprintf("provider-aws-%s", uuid.New())
}
