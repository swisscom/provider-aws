package v1alpha1ns

import "k8s.io/apimachinery/pkg/runtime"

func (in *ProviderConfigUsage) DeepCopyInto(out *ProviderConfigUsage) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.ProviderConfigUsage = in.ProviderConfigUsage
}

func (in *ProviderConfigUsage) DeepCopy() *ProviderConfigUsage {
	if in == nil { return nil }
	out := new(ProviderConfigUsage)
	in.DeepCopyInto(out)
	return out
}

func (in *ProviderConfigUsage) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil { return c }
	return nil
}

func (in *ProviderConfigUsageList) DeepCopyInto(out *ProviderConfigUsageList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ProviderConfigUsage, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *ProviderConfigUsageList) DeepCopy() *ProviderConfigUsageList {
	if in == nil { return nil }
	out := new(ProviderConfigUsageList)
	in.DeepCopyInto(out)
	return out
}

func (in *ProviderConfigUsageList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil { return c }
	return nil
}
