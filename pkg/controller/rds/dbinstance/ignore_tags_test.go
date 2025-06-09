// file: pkg/controller/rds/dbinstance/ignore_tags_test.go
package dbinstance

import (
	"testing"

	svcsdk "github.com/aws/aws-sdk-go/service/rds"
	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"
	"github.com/crossplane-contrib/provider-aws/pkg/controller/rds/utils"
	"github.com/crossplane-contrib/provider-aws/pkg/utils/pointer"
)

// TestIgnorePrefixesAreRespected verifies that aws:, c7n:, and any user-supplied
// prefixes are ignored when we diff tags.
func TestIgnorePrefixesAreRespected(t *testing.T) {
	// Tags declared in the CR.
	spec := []*svcapitypes.Tag{
		{Key: pointer.ToOrNilIfZeroValue("owner"), Value: pointer.ToOrNilIfZeroValue("cp")},
	}

	// Tags returned by AWS for the DB instance.
	raw := []*svcsdk.Tag{
		{Key: pointer.ToOrNilIfZeroValue("owner"),        Value: pointer.ToOrNilIfZeroValue("cp")},
		{Key: pointer.ToOrNilIfZeroValue("aws:createdBy"), Value: pointer.ToOrNilIfZeroValue("rds")},
		{Key: pointer.ToOrNilIfZeroValue("c7n:Finding"),   Value: pointer.ToOrNilIfZeroValue("foo")},
		{Key: pointer.ToOrNilIfZeroValue("foo:bar"),       Value: pointer.ToOrNilIfZeroValue("baz")}, // extra user-ignored prefix
	}

	// Pretend the user added an extra ignore prefix via YAML.
	customPrefixes := []string{"foo:"}

	// Build the final ignore slice the same way the controller does.
	ignore := append([]string{"aws:", "c7n:"}, customPrefixes...)

	// Strip ignored tags, keeping only the ones we care about.
	var observed []*svcsdk.Tag
	for _, tag := range raw {
		if utils.ShouldIgnore(pointer.StringValue(tag.Key), ignore) {
			continue
		}
		observed = append(observed, &svcsdk.Tag{
			Key:   tag.Key,
			Value: tag.Value,
		})
	}

	add, remove := utils.DiffTags(spec, observed)

	if len(add) != 0 || len(remove) != 0 {
		t.Fatalf("ignored tags leaked into diff; add=%v remove=%v", add, remove)
	}
}
