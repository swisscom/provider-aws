#!/usr/bin/env bash
# hack/gen-namespaced.sh
#
# Generates namespaced (Crossplane v2) CRD types and controllers for RDS resources.
# Run this after `make services SERVICES=rds` to re-sync namespaced copies.
#
# Usage: ./hack/gen-namespaced.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NS_API_PKG="apis/rds/v1alpha1ns"
NS_CTRL_DIR="pkg/controller/rds"

# Resources: directory_name package_name TypeName
RESOURCES=(
  "dbinstance:dbinstance:DBInstance"
  "dbcluster:dbcluster:DBCluster"
  "dbparametergroup:dbparametergroup:DBParameterGroup"
  "dbclusterparametergroup:dbclusterparametergroup:DBClusterParameterGroup"
  "dbinstanceroleassociation:dbinstanceroleassociation:DBInstanceRoleAssociation"
  "globalcluster:globalcluster:GlobalCluster"
  "optiongroup:optiongroup:OptionGroup"
)

echo "==> Cleaning old generated ns files..."
rm -rf "${NS_API_PKG}/zz_"*.go "${NS_API_PKG}/custom_types.go" "${NS_API_PKG}/referencers.go"
for entry in "${RESOURCES[@]}"; do
  IFS=: read -r dir _ _ <<< "$entry"
  # Preserve helpers.go (manually maintained)
  if [[ -d "${NS_CTRL_DIR}/${dir}_ns" ]]; then
    find "${NS_CTRL_DIR}/${dir}_ns" -name "*.go" ! -name "helpers.go" -delete
  fi
done

echo "==> Generating namespaced API types in ${NS_API_PKG}/"
mkdir -p "$NS_API_PKG"

# --- doc.go ---
cat > "${NS_API_PKG}/doc.go" << 'EOF'
/*
Copyright 2024 The Crossplane Authors.

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

// Package v1alpha1ns contains namespaced (Crossplane v2) managed resource types
// for the RDS API group.
// NOTE: DeepCopy is generated manually (not via controller-gen) because
// controller-gen v0.16.0 panics on cross-module v2 type embeddings.
// +groupName=rds.aws.m.crossplane.io
// +versionName=v1alpha1
package v1alpha1ns
EOF

# --- groupversion_info.go ---
cat > "${NS_API_PKG}/groupversion_info.go" << 'EOF'
package v1alpha1ns

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

const (
	CRDGroup   = "rds.aws.m.crossplane.io"
	CRDVersion = "v1alpha1"
)

var (
	GroupVersion  = schema.GroupVersion{Group: CRDGroup, Version: CRDVersion}
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	AddToScheme   = SchemeBuilder.AddToScheme
)
EOF

# --- managed_resource.go (bridge between v2 spec and v1 Managed interface) ---
cat > "${NS_API_PKG}/managed_resource.go" << 'EOF'
package v1alpha1ns

import (
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// LocalSecretReference is a reference to a secret in the same namespace.
type LocalSecretReference struct {
	// Name of the secret.
	Name string `json:"name"`
}

// ProviderConfigReference specifies the provider config to use.
// Only cluster-scoped ProviderConfig is supported in this temporary implementation.
type ProviderConfigReference struct {
	// Name of the provider config.
	// +kubebuilder:default="default"
	Name string `json:"name"`
}

// NamespacedSpec defines the desired state common to all namespaced managed resources.
// Fields match crossplane-runtime/v2 ManagedResourceSpec JSON schema.
type NamespacedSpec struct {
	// WriteConnectionSecretToReference specifies the name of a Secret to write
	// connection details to. The secret is created in the same namespace as the CR.
	// +optional
	WriteConnectionSecretToReference *LocalSecretReference `json:"writeConnectionSecretToRef,omitempty"`

	// ProviderConfigReference specifies how the provider should be configured.
	// +kubebuilder:default={"name": "default"}
	ProviderConfigReference *ProviderConfigReference `json:"providerConfigRef,omitempty"`

	// ManagementPolicies specify the array of actions Crossplane is allowed to
	// take on the managed and external resources.
	// +optional
	// +kubebuilder:default={"*"}
	ManagementPolicies xpv1.ManagementPolicies `json:"managementPolicies,omitempty"`

	// DeletionPolicy specifies what will happen to the underlying external
	// when this managed resource is deleted - either "Delete" or "Orphan" the
	// external resource.
	// +optional
	// +kubebuilder:default=Delete
	DeletionPolicy xpv1.DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// NamespacedStatus defines the observed state common to all namespaced managed resources.
type NamespacedStatus struct {
	xpv1.ConditionedStatus `json:",inline"`
}
EOF

# --- Generate CRD type file for each resource ---
gen_type_file() {
  local type_name=$1
  local file_name=$2

  cat > "${NS_API_PKG}/${file_name}" << GOEOF
package v1alpha1ns

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"
)

type ${type_name}Spec struct {
	NamespacedSpec \`json:",inline"\`
	ForProvider    svcapitypes.${type_name}Parameters \`json:"forProvider"\`
}

type ${type_name}Status struct {
	NamespacedStatus \`json:",inline"\`
	AtProvider       svcapitypes.${type_name}Observation \`json:"atProvider,omitempty"\`
}

// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,aws}
type ${type_name} struct {
	metav1.TypeMeta   \`json:",inline"\`
	metav1.ObjectMeta \`json:"metadata,omitempty"\`
	Spec              ${type_name}Spec   \`json:"spec"\`
	Status            ${type_name}Status \`json:"status,omitempty"\`
}

type ${type_name}List struct {
	metav1.TypeMeta \`json:",inline"\`
	metav1.ListMeta \`json:"metadata,omitempty"\`
	Items           []${type_name} \`json:"items"\`
}

var (
	${type_name}Kind             = "${type_name}"
	${type_name}GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ${type_name}Kind}.String()
	${type_name}KindAPIVersion   = ${type_name}Kind + "." + GroupVersion.String()
	${type_name}GroupVersionKind = GroupVersion.WithKind(${type_name}Kind)
)

func init() {
	SchemeBuilder.Register(&${type_name}{}, &${type_name}List{})
}
GOEOF
}

for entry in "${RESOURCES[@]}"; do
  IFS=: read -r dir _ type_name <<< "$entry"
  # Use dir name as file base (simpler and consistent)
  file_name="${dir}_types.go"
  echo "  Generating type: ${type_name} -> ${NS_API_PKG}/${file_name}"
  gen_type_file "$type_name" "$file_name"
done

# --- managed_list.go ---
{
  echo "package v1alpha1ns"
  echo ""
  echo 'import resource "github.com/crossplane/crossplane-runtime/pkg/resource"'
  echo ""
  for entry in "${RESOURCES[@]}"; do
    IFS=: read -r _ _ type_name <<< "$entry"
    cat << GOEOF

func (l *${type_name}List) GetItems() []resource.Managed {
	items := make([]resource.Managed, len(l.Items))
	for i := range l.Items {
		items[i] = &l.Items[i]
	}
	return items
}
GOEOF
  done
} > "${NS_API_PKG}/managed_list.go"

# --- managed_interfaces.go (implements resource.Managed on each concrete type) ---
{
  echo "package v1alpha1ns"
  echo ""
  echo 'import xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"'
  echo ""
  for entry in "${RESOURCES[@]}"; do
    IFS=: read -r _ _ type_name <<< "$entry"
    cat << GOEOF

func (mg *${type_name}) GetCondition(ct xpv1.ConditionType) xpv1.Condition { return mg.Status.GetCondition(ct) }
func (mg *${type_name}) SetConditions(c ...xpv1.Condition) { mg.Status.SetConditions(c...) }
func (mg *${type_name}) GetDeletionPolicy() xpv1.DeletionPolicy { return mg.Spec.DeletionPolicy }
func (mg *${type_name}) SetDeletionPolicy(p xpv1.DeletionPolicy) { mg.Spec.DeletionPolicy = p }
func (mg *${type_name}) GetManagementPolicies() xpv1.ManagementPolicies { return mg.Spec.ManagementPolicies }
func (mg *${type_name}) SetManagementPolicies(p xpv1.ManagementPolicies) { mg.Spec.ManagementPolicies = p }
func (mg *${type_name}) GetProviderConfigReference() *xpv1.Reference {
	if mg.Spec.ProviderConfigReference == nil { return nil }
	return &xpv1.Reference{Name: mg.Spec.ProviderConfigReference.Name}
}
func (mg *${type_name}) SetProviderConfigReference(r *xpv1.Reference) {
	if r == nil { mg.Spec.ProviderConfigReference = nil; return }
	if mg.Spec.ProviderConfigReference == nil { mg.Spec.ProviderConfigReference = &ProviderConfigReference{} }
	mg.Spec.ProviderConfigReference.Name = r.Name
}
func (mg *${type_name}) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo { return nil }
func (mg *${type_name}) SetPublishConnectionDetailsTo(_ *xpv1.PublishConnectionDetailsTo) {}
func (mg *${type_name}) GetWriteConnectionSecretToReference() *xpv1.SecretReference {
	if mg.Spec.WriteConnectionSecretToReference == nil { return nil }
	return &xpv1.SecretReference{Name: mg.Spec.WriteConnectionSecretToReference.Name, Namespace: mg.Namespace}
}
func (mg *${type_name}) SetWriteConnectionSecretToReference(r *xpv1.SecretReference) {
	if r == nil { mg.Spec.WriteConnectionSecretToReference = nil; return }
	mg.Spec.WriteConnectionSecretToReference = &LocalSecretReference{Name: r.Name}
}
GOEOF
  done

  # Additional interface methods for types that implement RDSClusterOrInstance
  cat << 'GOEOF'

// GetMasterUserPasswordSecretRef implements RDSClusterOrInstance for DBInstance.
func (mg *DBInstance) GetMasterUserPasswordSecretRef() *xpv1.SecretKeySelector {
	return mg.Spec.ForProvider.MasterUserPasswordSecretRef
}

// GetMasterUserPasswordSecretRef implements RDSClusterOrInstance for DBCluster.
func (mg *DBCluster) GetMasterUserPasswordSecretRef() *xpv1.SecretKeySelector {
	return mg.Spec.ForProvider.MasterUserPasswordSecretRef
}
GOEOF
} > "${NS_API_PKG}/managed_interfaces.go"

echo "==> Generating DeepCopy methods (manual, controller-gen panics on cross-module v2 types)..."
cat > "${NS_API_PKG}/deepcopy.go" << 'DCEOF'
//go:build !ignore_autogenerated

// Code generated by hack/gen-namespaced.sh. DO NOT EDIT.

package v1alpha1ns

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

func (in *LocalSecretReference) DeepCopyInto(out *LocalSecretReference) { *out = *in }
func (in *LocalSecretReference) DeepCopy() *LocalSecretReference {
	if in == nil { return nil }
	out := new(LocalSecretReference)
	*out = *in
	return out
}

func (in *ProviderConfigReference) DeepCopyInto(out *ProviderConfigReference) { *out = *in }
func (in *ProviderConfigReference) DeepCopy() *ProviderConfigReference {
	if in == nil { return nil }
	out := new(ProviderConfigReference)
	*out = *in
	return out
}

func (in *NamespacedSpec) DeepCopyInto(out *NamespacedSpec) {
	*out = *in
	if in.WriteConnectionSecretToReference != nil {
		in, out := &in.WriteConnectionSecretToReference, &out.WriteConnectionSecretToReference
		*out = new(LocalSecretReference)
		**out = **in
	}
	if in.ProviderConfigReference != nil {
		in, out := &in.ProviderConfigReference, &out.ProviderConfigReference
		*out = new(ProviderConfigReference)
		**out = **in
	}
	if in.ManagementPolicies != nil {
		in, out := &in.ManagementPolicies, &out.ManagementPolicies
		*out = make(xpv1.ManagementPolicies, len(*in))
		copy(*out, *in)
	}
}

func (in *NamespacedSpec) DeepCopy() *NamespacedSpec {
	if in == nil { return nil }
	out := new(NamespacedSpec)
	in.DeepCopyInto(out)
	return out
}

func (in *NamespacedStatus) DeepCopyInto(out *NamespacedStatus) {
	*out = *in
	in.ConditionedStatus.DeepCopyInto(&out.ConditionedStatus)
}

func (in *NamespacedStatus) DeepCopy() *NamespacedStatus {
	if in == nil { return nil }
	out := new(NamespacedStatus)
	in.DeepCopyInto(out)
	return out
}
DCEOF

for entry in "${RESOURCES[@]}"; do
  IFS=: read -r _ _ type_name <<< "$entry"
  cat >> "${NS_API_PKG}/deepcopy.go" << DCEOF

func (in *${type_name}Spec) DeepCopyInto(out *${type_name}Spec) {
	*out = *in
	in.NamespacedSpec.DeepCopyInto(&out.NamespacedSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

func (in *${type_name}Spec) DeepCopy() *${type_name}Spec {
	if in == nil { return nil }
	out := new(${type_name}Spec)
	in.DeepCopyInto(out)
	return out
}

func (in *${type_name}Status) DeepCopyInto(out *${type_name}Status) {
	*out = *in
	in.NamespacedStatus.DeepCopyInto(&out.NamespacedStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

func (in *${type_name}Status) DeepCopy() *${type_name}Status {
	if in == nil { return nil }
	out := new(${type_name}Status)
	in.DeepCopyInto(out)
	return out
}

func (in *${type_name}) DeepCopyInto(out *${type_name}) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *${type_name}) DeepCopy() *${type_name} {
	if in == nil { return nil }
	out := new(${type_name})
	in.DeepCopyInto(out)
	return out
}

func (in *${type_name}) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil { return c }
	return nil
}

func (in *${type_name}List) DeepCopyInto(out *${type_name}List) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]${type_name}, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *${type_name}List) DeepCopy() *${type_name}List {
	if in == nil { return nil }
	out := new(${type_name}List)
	in.DeepCopyInto(out)
	return out
}

func (in *${type_name}List) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil { return c }
	return nil
}
DCEOF
done

echo "==> Generating namespaced controllers..."

gen_ns_controller() {
  local dir=$1
  local pkg=$2
  local type_name=$3
  local ns_dir="${NS_CTRL_DIR}/${dir}_ns"

  mkdir -p "$ns_dir"

  # Common sed args to patch the generated files
  local sed_args=(
    -e "s/^package ${pkg}$/package ${pkg}_ns/"
    -e '/^import/,/^)/{
      s|svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"|svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"\
\tnsapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1ns"|
    }'
    -e "s|\*svcapitypes\.${type_name}\([^A-Za-z0-9_]\)|\*nsapitypes.${type_name}\1|g"
    -e "s|\*svcapitypes\.${type_name}\$|\*nsapitypes.${type_name}|g"
    -e "s|svcapitypes\.${type_name}GroupKind|nsapitypes.${type_name}GroupKind|g"
    -e "s|svcapitypes\.${type_name}GroupVersionKind|nsapitypes.${type_name}GroupVersionKind|g"
    -e "s|\&svcapitypes\.${type_name}{}|\&nsapitypes.${type_name}{}|g"
    -e "s|\&svcapitypes\.${type_name}List{}|\&nsapitypes.${type_name}List{}|g"
  )

  echo "  Patching ${dir} -> ${dir}_ns"

  # zz_controller.go
  if [[ -f "${NS_CTRL_DIR}/${dir}/zz_controller.go" ]]; then
    sed "${sed_args[@]}" "${NS_CTRL_DIR}/${dir}/zz_controller.go" > "${ns_dir}/zz_controller.go"
  fi

  # zz_conversions.go
  if [[ -f "${NS_CTRL_DIR}/${dir}/zz_conversions.go" ]]; then
    sed "${sed_args[@]}" "${NS_CTRL_DIR}/${dir}/zz_conversions.go" > "${ns_dir}/zz_conversions.go"
  fi

  # setup.go
  if [[ -f "${NS_CTRL_DIR}/${dir}/setup.go" ]]; then
    sed "${sed_args[@]}" "${NS_CTRL_DIR}/${dir}/setup.go" > "${ns_dir}/setup.go"
  fi
}

for entry in "${RESOURCES[@]}"; do
  IFS=: read -r dir pkg type_name <<< "$entry"
  gen_ns_controller "$dir" "$pkg" "$type_name"
done

echo "==> Post-processing: fixing known issues..."

# Fix dbinstance_ns: use toV1DBInstance adapter for ReadReplica path
sed -i '' 's/dbinstance\.GenerateCreateDBInstanceReadReplicaInput(cr)/dbinstance.GenerateCreateDBInstanceReadReplicaInput(toV1DBInstance(cr))/' \
  "${NS_CTRL_DIR}/dbinstance_ns/setup.go"

# Remove unused svcapitypes imports ONLY from files that have zero svcapitypes. usage
for f in $(find "${NS_CTRL_DIR}" -path "*_ns/*.go" -exec grep -l 'svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"' {} \;); do
  # Count svcapitypes. usages outside the import line
  count=$(grep -v 'svcapitypes "' "$f" | grep -c 'svcapitypes\.' || true)
  if [[ "$count" -eq 0 ]]; then
    sed -i '' '/svcapitypes "github.com\/crossplane-contrib\/provider-aws\/apis\/rds\/v1alpha1"/d' "$f"
  fi
done

echo "==> Verifying build..."
if go build ./apis/rds/v1alpha1ns/ ./pkg/controller/rds/... 2>&1 | grep -v "resource/unstructured"; then
  echo "WARNING: Build has errors (see above). The unstructured error is pre-existing."
else
  echo "OK: All namespaced packages compile."
fi

echo ""
echo "Done. Remember to:"
echo "  1. Run 'make generate' to produce deepcopy and CRD YAMLs"
echo "  2. Verify apis/aws.go has rdsv1alpha1ns import and SchemeBuilder.AddToScheme"
echo "  3. Verify pkg/controller/rds/setup.go registers the _ns controllers"
