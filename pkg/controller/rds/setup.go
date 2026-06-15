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

package rds

import (
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane-contrib/provider-aws/pkg/controller/rds/dbcluster"
	dbclusterns "github.com/crossplane-contrib/provider-aws/pkg/controller/rds/dbcluster_ns"
	"github.com/crossplane-contrib/provider-aws/pkg/controller/rds/dbclusterparametergroup"
	dbclusterparametergroupns "github.com/crossplane-contrib/provider-aws/pkg/controller/rds/dbclusterparametergroup_ns"
	"github.com/crossplane-contrib/provider-aws/pkg/controller/rds/dbinstance"
	dbinstancens "github.com/crossplane-contrib/provider-aws/pkg/controller/rds/dbinstance_ns"
	"github.com/crossplane-contrib/provider-aws/pkg/controller/rds/dbinstanceroleassociation"
	dbinstanceroleassociationns "github.com/crossplane-contrib/provider-aws/pkg/controller/rds/dbinstanceroleassociation_ns"
	"github.com/crossplane-contrib/provider-aws/pkg/controller/rds/dbparametergroup"
	dbparametergroupns "github.com/crossplane-contrib/provider-aws/pkg/controller/rds/dbparametergroup_ns"
	"github.com/crossplane-contrib/provider-aws/pkg/controller/rds/globalcluster"
	globalclusterns "github.com/crossplane-contrib/provider-aws/pkg/controller/rds/globalcluster_ns"
	"github.com/crossplane-contrib/provider-aws/pkg/controller/rds/optiongroup"
	optiongroupns "github.com/crossplane-contrib/provider-aws/pkg/controller/rds/optiongroup_ns"
	"github.com/crossplane-contrib/provider-aws/pkg/utils/setup"
)

// Setup prometheusservice controllers.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	return setup.SetupControllers(
		mgr, o,
		dbcluster.SetupDBCluster,
		dbclusterparametergroup.SetupDBClusterParameterGroup,
		dbinstance.SetupDBInstance,
		dbinstanceroleassociation.SetupDBInstanceRoleAssociation,
		dbparametergroup.SetupDBParameterGroup,
		globalcluster.SetupGlobalCluster,
		optiongroup.SetupOptionGroup,
		// Namespaced (Crossplane v2) controllers
		dbclusterns.SetupDBCluster,
		dbclusterparametergroupns.SetupDBClusterParameterGroup,
		dbinstancens.SetupDBInstance,
		dbinstanceroleassociationns.SetupDBInstanceRoleAssociation,
		dbparametergroupns.SetupDBParameterGroup,
		globalclusterns.SetupGlobalCluster,
		optiongroupns.SetupOptionGroup,
	)
}
