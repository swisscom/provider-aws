package v1alpha1ns

import resource "github.com/crossplane/crossplane-runtime/pkg/resource"

func (l *ResourceRecordSetList) GetItems() []resource.Managed {
	items := make([]resource.Managed, len(l.Items))
	for i := range l.Items {
		items[i] = &l.Items[i]
	}
	return items
}
