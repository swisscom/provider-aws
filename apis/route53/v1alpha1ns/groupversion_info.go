package v1alpha1ns

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

const (
	CRDGroup   = "route53.aws.m.crossplane.io"
	CRDVersion = "v1alpha1"
)

var (
	GroupVersion  = schema.GroupVersion{Group: CRDGroup, Version: CRDVersion}
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	AddToScheme   = SchemeBuilder.AddToScheme
)
