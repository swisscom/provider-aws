package provisionedproduct

import (
	"fmt"

	cfsdkv2types "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	svcsdk "github.com/aws/aws-sdk-go/service/servicecatalog"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"k8s.io/utils/pointer"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/servicecatalog/v1alpha1"
)

const (
	errCouldNotLookupProduct = "could not lookup product"
)

func provisioningParamsAreChanged(cfStackParams []cfsdkv2types.Parameter, currentParams []*svcapitypes.ProvisioningParameter) bool {
	if len(cfStackParams) != len(currentParams) {
		return true
	}

	cfStackKeyValue := make(map[string]string)
	for _, v := range cfStackParams {
		cfStackKeyValue[*v.ParameterKey] = pointer.StringDeref(v.ParameterValue, "")
	}

	for _, v := range currentParams {
		if cfv, ok := cfStackKeyValue[*v.Key]; ok && pointer.StringEqual(&cfv, v.Value) {
			continue
		} else {
			return true
		}
	}

	return false
}

func (c *custom) productOrArtifactAreChanged(ds *svcapitypes.ProvisionedProductParameters, resp *svcsdk.ProvisionedProductDetail) (bool, error) {
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
	input := svcsdk.DescribeProductInput{
		Id:   ds.ProductID,
		Name: ds.ProductName,
	}
	// DescribeProvisioningArtifact methods fits much better, but it has a bug
	output, err := c.client.DescribeProduct(&input)
	if err != nil {
		return "", errors.Wrap(err, errCouldNotLookupProduct)
	}
	if ds.ProvisioningArtifactName != nil && ds.ProvisioningArtifactID != nil {
		return "", errors.Wrap(errors.New("artifact id and name are mutually exclusive"), errCouldNotLookupProduct)
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
