package wafv2

import (
	svcsdk "github.com/aws/aws-sdk-go/service/wafv2"
	svcsdkapi "github.com/aws/aws-sdk-go/service/wafv2/wafv2iface"
)

// Client represents a custom client to retrieve information from AWS related to service catalog or cloud formation as resource behind the provisioned product
type Client interface {
	ListWebACLs(*svcsdk.ListWebACLsInput) (*svcsdk.ListWebACLsOutput, error)
	ListTagsForResource(*svcsdk.ListTagsForResourceInput) (*svcsdk.ListTagsForResourceOutput, error)
	TagResource(*svcsdk.TagResourceInput) (*svcsdk.TagResourceOutput, error)
}

// CustomWAFV2Client is a type that implements(just wraps) those methods of WAFV2API interface which we want to mock, otherwise all methods had to be mocked for testing purposes
type CustomWAFV2Client struct {
	OriginalClient svcsdkapi.WAFV2API
}

// ListWebACLs is wrapped ListWebACLs from github.com/aws/aws-sdk-go/service/wafv2
func (c *CustomWAFV2Client) ListWebACLs(input *svcsdk.ListWebACLsInput) (*svcsdk.ListWebACLsOutput, error) {
	return c.OriginalClient.ListWebACLs(input)
}

// ListTagsForResource is wrapped ListTagsForResource from github.com/aws/aws-sdk-go/service/wafv2
func (c *CustomWAFV2Client) ListTagsForResource(input *svcsdk.ListTagsForResourceInput) (*svcsdk.ListTagsForResourceOutput, error) {
	return c.OriginalClient.ListTagsForResource(input)
}

// TagResource is wrapped TagResource from github.com/aws/aws-sdk-go/service/wafv2
func (c *CustomWAFV2Client) TagResource(input *svcsdk.TagResourceInput) (*svcsdk.TagResourceOutput, error) {
	return c.OriginalClient.TagResource(input)
}
