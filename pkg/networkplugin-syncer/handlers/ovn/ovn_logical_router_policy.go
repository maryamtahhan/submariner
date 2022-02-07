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
	"fmt"
	"strings"
	"time"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/stringset"
	"k8s.io/klog/v2"
)

func (ovn *SyncHandler) removePoliciesForRemoteSubnets(toRemove []string) error {
	opModels := []libovsdbops.OperationModel{}

	// nothing to remove
	if len(toRemove) == 0 {
		return nil
	}

	for _, uuid := range toRemove {
		removeLrp := nbdb.LogicalRouterPolicy{
			UUID: uuid,
		}

		opModels = append(opModels, libovsdbops.OperationModel{
			Model: &removeLrp,
		})
	}

	m := libovsdbops.NewModelClient(ovn.nbdb)
	if err := m.Delete(opModels...); err != nil {
		return errors.Wrapf(err, "failed to delete submariner logical Router policies")

	}

	return nil
}

func (ovn *SyncHandler) addPoliciesForRemoteSubnets(toAdd []nbdb.LogicalRouterPolicy) error {
	opModels := []libovsdbops.OperationModel{}

	ovnClusterRouter := nbdb.LogicalRouter{
		Name: ovnClusterRouter,
	}

	// nothing to add
	if len(toAdd) == 0 {
		return nil
	}

	for i, _ := range toAdd {
		// none of these LRPs should exist yet, since we already looked them up
		indexCopy := i
		opModels = append(opModels, libovsdbops.OperationModel{
			Model: &toAdd[i],
			DoAfter: func() {
				ovnClusterRouter.Policies = append(ovnClusterRouter.Policies, toAdd[indexCopy].UUID)
			},
		})
	}

	// mutate ovnClusterRouter to add new LRPs
	opModels = append(opModels, libovsdbops.OperationModel{
		Model:          &ovnClusterRouter,
		ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == ovnClusterRouter.Name },
		OnModelMutations: []interface{}{
			&ovnClusterRouter.Policies,
		},
		ErrNotFound: true,
	})

	m := libovsdbops.NewModelClient(ovn.nbdb)
	if _, err := m.CreateOrUpdate(opModels...); err != nil {
		return errors.Wrapf(err, "failed to create submariner logical Router policies and add them to the ovn cluster router")
	}

	return nil
}

func (ovn *SyncHandler) getSubmarinerLRPSubnets(rerouteIP string) (stringset.Interface, map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	subRouterPolicies := []nbdb.LogicalRouterPolicy{}
	// map of subnets to UUID for the LRPs to make deletion easier
	subnets := stringset.New()
	subnetUUID := map[string]string{}

	err := ovn.nbdb.WhereCache(func(item *nbdb.LogicalRouterPolicy) bool {
		return item.Priority == ovnRoutePoliciesPrio
	}).List(ctx, &subRouterPolicies)
	if err != nil {
		return nil, nil, fmt.Errorf("can't find submariner logicalRouterPolicies: %v", err)
	}

	if len(subRouterPolicies) == 0 {
		klog.Info("no existing submariner static routes found")
		return subnets, subnetUUID, libovsdbclient.ErrNotFound
	}

	// extract subnet from lrp "match" field
	// this field looks like: "ip4.dst == 10.2.0.0/16"
	for _, policy := range subRouterPolicies {
		subnet := strings.Split(policy.Match, " ")[2]

		subnetUUID[subnet] = policy.UUID
		subnets.Add(subnet)
	}

	return subnets, subnetUUID, nil
}

// getNorthSubnetsToAddAndRemove receives the existing state for the north (other clusters) routes in the OVN
// database as an StringSet, and based on the known remote endpoints it will return the elements that need
// to be added and removed.
func buildLRPsFromSubnets(subnetsToAdd []string) []nbdb.LogicalRouterPolicy {
	tmpDownstreamIP := submarinerDownstreamIP
	toAdd := []nbdb.LogicalRouterPolicy{}

	for _, subnet := range subnetsToAdd {
		toAdd = append(toAdd, nbdb.LogicalRouterPolicy{
			Priority: ovnRoutePoliciesPrio,
			Action:   "reroute",
			Match:    "ip4.dst == " + subnet,
			Nexthop:  &tmpDownstreamIP,
			ExternalIDs: map[string]string{
				"submariner": "true",
			},
		})
	}

	return toAdd
}
