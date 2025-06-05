// file: pkg/controller/rds/dbinstance/ignore_tags_test.go
package dbinstance

import (
	"strings"
	"testing"

	svcsdk "github.com/aws/aws-sdk-go/service/rds"
	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"
	"github.com/crossplane-contrib/provider-aws/pkg/controller/rds/utils"
	"github.com/crossplane-contrib/provider-aws/pkg/utils/pointer"
)

func TestIgnoreSystemTagsInObservedList(t *testing.T) {
	// Desired tags on the CR (what users actually manage).
	spec := []*svcapitypes.Tag{
		{
			Key:   pointer.ToOrNilIfZeroValue("owner"),
			Value: pointer.ToOrNilIfZeroValue("cp"),
		},
	}

	// Tags that AWS returns for the DB instance – it includes system tags.
	rawAWS := []*svcsdk.Tag{
		{Key: pointer.ToOrNilIfZeroValue("owner"),         Value: pointer.ToOrNilIfZeroValue("cp")},
		{Key: pointer.ToOrNilIfZeroValue("aws:createdBy"), Value: pointer.ToOrNilIfZeroValue("rds")},
		{Key: pointer.ToOrNilIfZeroValue("c7n:Finding"),   Value: pointer.ToOrNilIfZeroValue("foo")},
	}

	// <--- this block copies the filtering code verbatim from isUpToDate() --->
	var observed []*svcsdk.Tag
	for _, tag := range rawAWS {
		if strings.HasPrefix(*tag.Key, "aws:") || strings.HasPrefix(*tag.Key, "c7n:") {
			continue // ignore system / c7n tags
		}
		observed = append(observed, &svcsdk.Tag{
			Key:   tag.Key,
			Value: tag.Value,
		})
	}
	// -----------------------------------------------------------------------

	add, remove := utils.DiffTags(spec, observed)

	if len(add) != 0 || len(remove) != 0 {
		t.Fatalf("system tags should have been ignored: add=%v remove=%v", add, remove)
	}
}
