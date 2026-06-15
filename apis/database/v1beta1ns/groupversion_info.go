package v1beta1ns

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

const (
	CRDGroup   = "database.aws.m.crossplane.io"
	CRDVersion = "v1beta1"
)

var (
	GroupVersion  = schema.GroupVersion{Group: CRDGroup, Version: CRDVersion}
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	AddToScheme   = SchemeBuilder.AddToScheme
)
