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
	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/sbdb"
	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	"k8s.io/klog"
)

// Ensure the core submariner ovn topology is setup and current in a single transaction
// to ovn nbdb. Creates the foolowing resources
//
// (localnetPort) - subGatewaySwitch
//
//		&&&
//
// subRouter 							 subJoinSwitch					 		ovnClusterRouter
//     |(subRouter2JoinLRP)-(subJoin2RouterLSP)|(subClusterSwPort)-(subJoin2RouterLSP)|
func (ovn *SyncHandler) ensureSubmarinerInfra() error {

	klog.Info("Ensuring submariner ovn topology and connecting to ovn-cluster-router")

	subLogicalRouter := nbdb.LogicalRouter{
		Name: submarinerLogicalRouter,
	}

	ovnClusterRouter := nbdb.LogicalRouter{
		Name: ovnClusterRouter,
	}

	subJoinSwitch := nbdb.LogicalSwitch{
		Name: submarinerDownstreamSwitch,
	}

	subGatewaySwitch := nbdb.LogicalSwitch{
		Name: submarinerUpstreamSwitch,
	}

	subGatewayToLocalNetLsp := nbdb.LogicalSwitchPort{
		Name:      submarinerUpstreamLocalnetPort,
		Type:      "localnet",
		Addresses: []string{"unknown"},
		Options: map[string]string{
			"network_name": SubmarinerUpstreamLocalnet,
		},
	}

	subJoinToSubRouterLsp := nbdb.LogicalSwitchPort{
		Name: submarinerDownstreamSwPort,
		Type: "router",
		Options: map[string]string{
			"router-port": submarinerDownstreamRPort,
		},
		Addresses: []string{"router"},
	}

	subJointoOvnRouterLsp := nbdb.LogicalSwitchPort{
		Name: ovnClusterSubmarinerSwPort,
		Type: "router",
		Options: map[string]string{
			"router-port": ovnClusterSubmarinerRPort,
		},
		Addresses: []string{"router"},
	}

	// setup LRP to connect the submariner logical router to the submariner logical switch
	subRouterToJoinLrp := nbdb.LogicalRouterPort{
		Name:     submarinerDownstreamRPort,
		MAC:      submarinerDownstreamMAC,
		Networks: []string{submarinerDownstreamNET},
	}

	ovnRouterToJoinLrp := nbdb.LogicalRouterPort{
		Name:     ovnClusterSubmarinerRPort,
		MAC:      ovnClusterSubmarinerMAC,
		Networks: []string{ovnClusterSubmarinerNET},
	}

	opModels := []libovsdbops.OperationModel{
		// create or update the submariner gateway localnet switch port
		{
			Model: &subGatewayToLocalNetLsp,
			OnModelUpdates: []interface{}{
				&subGatewayToLocalNetLsp.Type,
				&subGatewayToLocalNetLsp.Options,
				&subGatewayToLocalNetLsp.Addresses,
			},
			DoAfter: func() {
				subGatewaySwitch.Ports = append(subGatewaySwitch.Ports, subGatewayToLocalNetLsp.UUID)
			},
		},
		// mutate/create the submariner gateway switch switch to ensure the submariner
		// downstream port is added to it's port list
		{
			Model:          &subGatewaySwitch,
			ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == subGatewaySwitch.Name },
			OnModelMutations: []interface{}{
				&subGatewaySwitch.Ports,
			},
		},
		// create or update the submariner downstream switch port
		{
			Model: &subJoinToSubRouterLsp,
			OnModelUpdates: []interface{}{
				&subJoinToSubRouterLsp.Type,
				&subJoinToSubRouterLsp.Options,
				&subJoinToSubRouterLsp.Addresses,
			},
			DoAfter: func() {
				subJoinSwitch.Ports = append(subJoinSwitch.Ports, subJoinToSubRouterLsp.UUID)
			},
		},
		// create or update the join switch to ovn router lsp
		{
			Model: &subJointoOvnRouterLsp,
			OnModelUpdates: []interface{}{
				&subJointoOvnRouterLsp.Type,
				&subJointoOvnRouterLsp.Options,
				&subJointoOvnRouterLsp.Addresses,
			},
			DoAfter: func() {
				subJoinSwitch.Ports = append(subJoinSwitch.Ports, subJointoOvnRouterLsp.UUID)
			},
		},
		// mutate the submariner join switch switch to ensure the submariner
		// downstream port is added to it's port list
		{
			Model:          &subJoinSwitch,
			ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == subJoinSwitch.Name },
			OnModelMutations: []interface{}{
				&subJoinSwitch.Ports,
			},
		},
		// create or update the submariner logical router port
		{
			Model: &subRouterToJoinLrp,
			OnModelUpdates: []interface{}{
				&subRouterToJoinLrp.MAC,
				&subRouterToJoinLrp.Networks,
			},
			DoAfter: func() {
				subLogicalRouter.Ports = append(subLogicalRouter.Ports, subRouterToJoinLrp.UUID)
			},
		},
		// create or update the ovn cluster router to submariner join switch LSP
		{
			Model: &ovnRouterToJoinLrp,
			OnModelUpdates: []interface{}{
				&ovnRouterToJoinLrp.MAC,
				&ovnRouterToJoinLrp.Networks,
			},
			DoAfter: func() {
				ovnClusterRouter.Ports = append(ovnClusterRouter.Ports, ovnRouterToJoinLrp.UUID)
			},
		},
		// create or update the submariner logical router
		{
			Model:          &subLogicalRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == subLogicalRouter.Name },
			OnModelMutations: []interface{}{
				&subLogicalRouter.Ports,
			},
		},
		// update the ovn cluster router
		{
			Model:          &ovnClusterRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == ovnClusterRouter.Name },
			OnModelMutations: []interface{}{
				&ovnClusterRouter.Ports,
			},
			ErrNotFound: true,
		},
	}

	m := libovsdbops.NewModelClient(ovn.nbdb)
	if _, err := m.CreateOrUpdate(opModels...); err != nil {
		return errors.Wrapf(err, "failed to create submariner logical Router and connect it to the submariner join switch %s",
			submarinerLogicalRouter)

	}

	// At this point, we are missing the ovn_cluster_router policies and the
	// local-to-remote & remote-to-local routes in submariner_router, that
	// depends on endpoint details that we will receive via events.
	return nil
}

// setupOvnClusterRouterLRPs configures the ovn cluster router's logical router policies
func (ovn *SyncHandler) setupOvnClusterRouterLRPs() error {
	existingPolicySubnets, subnetUUIDs, err := ovn.getSubmarinerLRPSubnets(submarinerDownstreamIP)
	if err != nil && err != libovsdbclient.ErrNotFound {
		return errors.Wrapf(err, "error reading existing submariner logical router policies", ovnClusterRouter)
	}

	klog.V(log.DEBUG).Infof("Existing submariner logical router policies in %q router for subnets %v", ovnClusterRouter, existingPolicySubnets)

	subnetsToAdd, subnetsToRemove := ovn.getNorthSubnetsToAddAndRemove(existingPolicySubnets)

	lrpToAdd := buildLRPsFromSubnets(subnetsToAdd)

	klog.V(log.DEBUG).Infof("adding these raw ovn logical router policies  %v", lrpToAdd)

	ovn.logRoutingChanges("north logical router policies", ovnClusterRouter, subnetsToAdd, subnetsToRemove)

	err = ovn.addPoliciesForRemoteSubnets(lrpToAdd)
	if err != nil {
		return err
	}

	// Get UUIDs of LRPs to remove
	removeLSPUUIDs := []string{}

	for _, subnet := range subnetsToRemove {
		if uuid, ok := subnetUUIDs[subnet]; ok {
			removeLSPUUIDs = append(removeLSPUUIDs, uuid)
		}
	}

	err = ovn.removePoliciesForRemoteSubnets(removeLSPUUIDs)
	if err != nil {
		return err
	}

	return nil
}

// associateSubmarinerRouterToChassis locks the submariner_router to a specific node
func (ovn *SyncHandler) associateSubmarinerRouterToChassis(chassis *sbdb.Chassis) error {
	subLogicalRouter := nbdb.LogicalRouter{
		Name: submarinerLogicalRouter,
		Options: map[string]string{
			"chassis": chassis.Name,
		},
	}

	opModels := []libovsdbops.OperationModel{
		// update the submariner cluster router's options
		{
			Model:          &subLogicalRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == submarinerLogicalRouter },
			OnModelMutations: []interface{}{
				&subLogicalRouter.Options,
			},
		},
	}

	m := libovsdbops.NewModelClient(ovn.nbdb)
	if _, err := m.CreateOrUpdate(opModels...); err != nil {
		return errors.Wrap(err, "Update the chassis for the submariner router")

	}

	return nil
}

// createOrUpdateSubmarinerExternalPort ensures that the submariner external Port
// can communicate with the node where the gaetway switch is located.
func (ovn *SyncHandler) createOrUpdateSubmarinerExternalPort() error {
	klog.Info("Ensuring connection between submariner router and submariner gateway switch")

	subLogicalRouter := nbdb.LogicalRouter{
		Name: submarinerLogicalRouter,
	}

	subGatewaySwitch := nbdb.LogicalSwitch{
		Name: submarinerUpstreamSwitch,
	}

	subGatewayToSubRouterLsp := nbdb.LogicalSwitchPort{
		Name: submarinerUpstreamSwPort,
		Type: "router",
		Options: map[string]string{
			"router-port": submarinerUpstreamRPort,
		},
		Addresses: []string{"router"},
	}

	subRouterTosubGatewayLrp := nbdb.LogicalRouterPort{
		Name:     submarinerUpstreamRPort,
		MAC:      submarinerUpstreamMAC,
		Networks: []string{submarinerUpstreamNET},
	}

	opModels := []libovsdbops.OperationModel{
		// create or update the submariner gateway to submariner router lsp
		{
			Model: &subGatewayToSubRouterLsp,
			OnModelUpdates: []interface{}{
				&subGatewayToSubRouterLsp.Type,
				&subGatewayToSubRouterLsp.Options,
				&subGatewayToSubRouterLsp.Addresses,
			},
			DoAfter: func() {
				subGatewaySwitch.Ports = []string{subGatewayToSubRouterLsp.UUID}
			},
		},
		// Add submariner gateway to submariner router lsp to submariner gateway switch
		{
			Model:          &subGatewaySwitch,
			ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == subGatewaySwitch.Name },
			OnModelMutations: []interface{}{
				&subGatewaySwitch.Ports,
			},
			ErrNotFound: true,
		},
		// create or update the submariner router to submariner gateway switch lrp
		{
			Model: &subRouterTosubGatewayLrp,
			OnModelUpdates: []interface{}{
				&subRouterTosubGatewayLrp.MAC,
				&subRouterTosubGatewayLrp.Networks,
			},
			DoAfter: func() {
				subLogicalRouter.Ports = []string{subRouterTosubGatewayLrp.UUID}
			},
		},
		// mutate the submariner logical router adding the submariner router to submariner gateway switch lrp
		{
			Model:          &subLogicalRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == subLogicalRouter.Name },
			OnModelMutations: []interface{}{
				&subLogicalRouter.Ports,
			},
			ErrNotFound: true,
		},
	}

	m := libovsdbops.NewModelClient(ovn.nbdb)
	if _, err := m.CreateOrUpdate(opModels...); err != nil {
		return errors.Wrap(err, "failed to connect the submariner router to the submariner gateway switch")

	}

	return nil
}

// updateSubmarinerRouterRemoteRoutes reconciles ovn static routes on the submariner router
func (ovn *SyncHandler) updateSubmarinerRouterRemoteRoutes() error {
	existingSubnets, subnetUUIDs, err := ovn.getExistingSubmarinerRouterRoutesToPort(submarinerUpstreamRPort)
	if err != nil && err != libovsdbclient.ErrNotFound {
		return err
	}

	klog.V(log.DEBUG).Infof("Existing north static routes in %q router for subnets %v", submarinerLogicalRouter, existingSubnets.Elements())

	subnetsToAdd, subnetsToRemove := ovn.getNorthSubnetsToAddAndRemove(existingSubnets)

	lrsrToAdd := buildLRSRsFromSubnets(subnetsToAdd, submarinerUpstreamRPort, HostUpstreamIP)

	ovn.logRoutingChanges("north staic routes", submarinerLogicalRouter, subnetsToAdd, subnetsToRemove)

	klog.V(log.DEBUG).Infof("adding these raw ovn logical router static routes %v", lrsrToAdd)

	err = ovn.addSubmRoutesToSubnets(lrsrToAdd, HostUpstreamIP)
	if err != nil {
		return err
	}

	// Get UUIDs of LRSRs to remove
	removeLRSRUUIDs := []string{}

	for _, subnet := range subnetsToRemove {
		if uuid, ok := subnetUUIDs[subnet]; ok {
			removeLRSRUUIDs = append(removeLRSRUUIDs, uuid)
		}
	}

	err = ovn.removeRoutesToSubnets(removeLRSRUUIDs)
	if err != nil {
		return err
	}

	return nil
}

func (ovn *SyncHandler) updateSubmarinerRouterLocalRoutes() error {
	existingSubnets, subnetUUIDs, err := ovn.getExistingSubmarinerRouterRoutesToPort(submarinerDownstreamRPort)
	if err != nil && err != libovsdbclient.ErrNotFound {
		return err
	}

	klog.V(log.DEBUG).Infof("Existing south static routes in %q router for subnets %v", submarinerLogicalRouter, existingSubnets)

	subnetsToAdd, subnetsToRemove := ovn.getSouthSubnetsToAddAndRemove(existingSubnets)

	lrsrToAdd := buildLRSRsFromSubnets(subnetsToAdd, submarinerDownstreamRPort, ovnClusterSubmarinerIP)

	ovn.logRoutingChanges("south static routes", submarinerLogicalRouter, subnetsToAdd, subnetsToRemove)

	err = ovn.addSubmRoutesToSubnets(lrsrToAdd, ovnClusterSubmarinerIP)
	if err != nil {
		return err
	}

	// Get UUIDs of LRSRs to remove
	removeLRSRUUIDs := []string{}

	for _, subnet := range subnetsToRemove {
		if uuid, ok := subnetUUIDs[subnet]; ok {
			removeLRSRUUIDs = append(removeLRSRUUIDs, uuid)
		}
	}

	err = ovn.removeRoutesToSubnets(removeLRSRUUIDs)
	if err != nil {
		return err
	}

	return nil
}

func (ovn *SyncHandler) logRoutingChanges(kind, router string, toAdd, toRemove []string) {
	if len(toAdd) == 0 && len(toRemove) == 0 {
		klog.Infof("%s for %q are up to date", kind, router)
	} else {
		if len(toAdd) > 0 {
			klog.Infof("New %s to add to %q : %v", kind, router, toAdd)
		}
		if len(toRemove) > 0 {
			klog.Infof("Old %s to remove from %q : %v", kind, router, toRemove)
		}
	}
}
