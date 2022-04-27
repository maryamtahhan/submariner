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

package vxlan

import (
	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/cable/cableutils"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	"github.com/submariner-io/submariner/pkg/netlink"
	"github.com/submariner-io/submariner/pkg/types"
	"k8s.io/klog"
)

const (
	CableDriverName = "vxlan"
	defaultPort     = 4500
)

type Operation int

const (
	Add Operation = iota
	Delete
	Flush
)

type vxlanDriver struct {
	localEndpoint types.SubmarinerEndpoint
	localCluster  types.SubmarinerCluster
	connections   []v1.Connection
	vxlan         *cableutils.VxlanCable
}

func init() {
	cable.AddDriver(CableDriverName, NewDriver)
}

func NewDriver(localEndpoint *types.SubmarinerEndpoint, localCluster *types.SubmarinerCluster) (cable.Driver, error) {
	// We'll panic if localEndpoint or localCluster are nil, this is intentional
	var err error

	v := vxlanDriver{
		localEndpoint: *localEndpoint,
		localCluster:  *localCluster,
	}

	port, err := localEndpoint.Spec.GetBackendPort(v1.UDPPortConfig, defaultPort)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the UDP port configuration")
	}

	if v.vxlan, err = cableutils.CreateVxlanInterface(v.localEndpoint.Spec.PrivateIP, localEndpoint.Spec.Hostname, int(port)); err != nil {
		return nil, errors.Wrap(err, "failed to setup vxlanDriver link")
	}

	return &v, nil
}

func (v *vxlanDriver) ConnectToEndpoint(endpointInfo *natdiscovery.NATEndpointInfo) (string, error) {
	// We'll panic if endpointInfo is nil, this is intentional
	remoteEndpoint := endpointInfo.Endpoint

	if err := cableutils.SetupVxlanRoutes(v.vxlan, endpointInfo,
		v.localEndpoint.Spec.ClusterID, v.localCluster.Spec.ClusterCIDR[0]); err != nil {
		return "", errors.Wrap(err, "error setting  up vxlan routes")
	}

	v.connections = append(v.connections, v1.Connection{
		Endpoint: remoteEndpoint.Spec, Status: v1.Connected,
		UsingIP: endpointInfo.UseIP, UsingNAT: endpointInfo.UseNAT,
	})

	klog.V(log.DEBUG).Infof("Done adding endpoint for cluster %s", remoteEndpoint.Spec.ClusterID)

	return endpointInfo.UseIP, nil
}

func (v *vxlanDriver) DisconnectFromEndpoint(remoteEndpoint *types.SubmarinerEndpoint) error {
	// We'll panic if remoteEndpoint is nil, this is intentional
	klog.V(log.DEBUG).Infof("Removing endpoint %#v", remoteEndpoint)

	if err := cableutils.CleanupVxlanRoutes(v.vxlan, remoteEndpoint, v.localEndpoint.Spec.ClusterID, v.connections); err != nil {
		return errors.Wrap(err, "error cleaning up vxlan routes")
	}

	v.connections = removeConnectionForEndpoint(v.connections, remoteEndpoint)
	cable.RecordDisconnected(CableDriverName, &v.localEndpoint.Spec, &remoteEndpoint.Spec)

	klog.V(log.DEBUG).Infof("Done removing endpoint for cluster %s", remoteEndpoint.Spec.ClusterID)

	return nil
}

func removeConnectionForEndpoint(connections []v1.Connection, endpoint *types.SubmarinerEndpoint) []v1.Connection {
	for j := range connections {
		if connections[j].Endpoint.CableName == endpoint.Spec.CableName {
			copy(connections[j:], connections[j+1:])
			return connections[:len(connections)-1]
		}
	}

	return connections
}

func (v *vxlanDriver) GetConnections() ([]v1.Connection, error) {
	return v.connections, nil
}

func (v *vxlanDriver) GetActiveConnections() ([]v1.Connection, error) {
	return v.connections, nil
}

func (v *vxlanDriver) Init() error {
	return nil
}

func (v *vxlanDriver) GetName() string {
	return CableDriverName
}

func (v *vxlanDriver) Cleanup() error {
	klog.Infof("Uninstalling the vxlan cable driver")

	err := netlink.DeleteIfaceAndAssociatedRoutes(cableutils.VxlanIfaceName, cableutils.TableID)

	if err != nil {
		klog.Errorf("unable to delete interface %s and associated routes from table %d", v.vxlan.Iface, cableutils.TableID)
	}

	err = v.vxlan.NetLink.RuleDelIfPresent(netlink.NewTableRule(cableutils.TableID))
	if err != nil {
		return errors.Wrapf(err, "unable to delete IP rule pointing to %d table", cableutils.TableID)
	}

	return nil
}
