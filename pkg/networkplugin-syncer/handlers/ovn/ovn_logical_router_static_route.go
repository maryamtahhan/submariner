/*
SPDX-License-Identifier: Apache-2.0

Copyright Contributors to the Submariner project.

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

package ovn

import (
	"context"
	"time"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/stringset"
	"k8s.io/klog/v2"
)

// getExistingSubmarinerRouterRoutesToPort gets the ovn logical_router_statics_routes
// with an output port related to the provided port.
func (ovn *SyncHandler) getExistingSubmarinerRouterRoutesToPort(lrp string) (stringset.Interface, map[string]string, error) {
	// This is the standard ovsdb timeout used by ovn-kubernetes
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	subRouterStaticRoutes := []nbdb.LogicalRouterStaticRoute{}
	subnets := stringset.New()
	// map of subnets to UUID for the LRSRs to make deletion easier
	subnetUUID := map[string]string{}

	// get the logical router static routes with the specified outport
	err := ovn.nbdb.WhereCache(func(item *nbdb.LogicalRouterStaticRoute) bool {
		return item.OutputPort != nil && *item.OutputPort == lrp
	}).List(ctx, &subRouterStaticRoutes)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "can't find submariner logicalRouterPolicies")
	}

	if len(subRouterStaticRoutes) == 0 {
		klog.Info("no existing submariner static routes found")
		return subnets, subnetUUID, libovsdbclient.ErrNotFound
	}

	// extract subnet from lrsr "ip_prefix" field
	for _, route := range subRouterStaticRoutes {
		subnet := route.IPPrefix
		subnetUUID[subnet] = route.UUID
		subnets.Add(subnet)
	}

	return subnets, subnetUUID, nil
}

func (ovn *SyncHandler) addSubmRoutesToSubnets(staticRoutes []nbdb.LogicalRouterStaticRoute, nextHop string) error {
	opModels := []libovsdbops.OperationModel{}

	submarinerLogicalRouter := nbdb.LogicalRouter{
		Name: submarinerLogicalRouter,
	}

	// nothing too add
	if len(staticRoutes) == 0 {
		return nil
	}

	for i, _ := range staticRoutes {
		indexCopy := i
		opModels = append(opModels, libovsdbops.OperationModel{
			Model: &staticRoutes[i],
			DoAfter: func() {
				submarinerLogicalRouter.StaticRoutes = append(submarinerLogicalRouter.StaticRoutes, staticRoutes[indexCopy].UUID)
			},
		})
	}

	// mutate submarinerClusterRouter to add new LRSRs
	opModels = append(opModels, libovsdbops.OperationModel{
		Model:          &submarinerLogicalRouter,
		ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == submarinerLogicalRouter.Name },
		OnModelMutations: []interface{}{
			&submarinerLogicalRouter.StaticRoutes,
		},
		ErrNotFound: true,
	})

	m := libovsdbops.NewModelClient(ovn.nbdb)
	if _, err := m.CreateOrUpdate(opModels...); err != nil {
		return errors.Wrapf(err, "failed to create submariner logical Router static routes and add them to the submariner router")
	}

	return nil
}

func (ovn *SyncHandler) removeRoutesToSubnets(toRemove []string) error {
	opModels := []libovsdbops.OperationModel{}

	// nothing to remove
	if len(toRemove) == 0 {
		return nil
	}

	for _, uuid := range toRemove {
		removeLrsr := nbdb.LogicalRouterStaticRoute{
			UUID: uuid,
		}

		opModels = append(opModels, libovsdbops.OperationModel{
			Model: &removeLrsr,
		})
	}

	m := libovsdbops.NewModelClient(ovn.nbdb)
	if err := m.Delete(opModels...); err != nil {
		return errors.Wrapf(err, "failed to delete submariner logical outer static routes")

	}

	return nil
}

func buildLRSRsFromSubnets(subnetsToAdd []string, outPort, nextHop string) []nbdb.LogicalRouterStaticRoute {
	toAdd := []nbdb.LogicalRouterStaticRoute{}

	for _, subnet := range subnetsToAdd {
		toAdd = append(toAdd, nbdb.LogicalRouterStaticRoute{
			OutputPort: &outPort,
			Nexthop:    nextHop,
			IPPrefix:   subnet,
		})
	}

	return toAdd
}
