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

package cableutils

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	netlinkAPI "github.com/submariner-io/submariner/pkg/netlink"
	"github.com/submariner-io/submariner/pkg/routeagent_driver/cni"
	"github.com/submariner-io/submariner/pkg/types"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog"
)

const (
	VxlanIfaceName         = "vxlan-tunnel"
	VxlanOverhead          = 50
	VxlanVTepNetworkPrefix = 241
	TableID                = 100
)

type VxlanCable struct {
	Mutex   sync.Mutex
	Iface   *Iface
	NetLink netlinkAPI.Interface
}

type Iface struct {
	Link   *netlink.Vxlan
	VtepIP net.IP
}

type VxlanAttributes struct {
	name     string
	vxlanID  int
	group    net.IP
	srcAddr  net.IP
	vtepPort int
	mtu      int
}

func getTunnelEndPointIPAddress(ipAddr string, prefix int) (net.IP, error) {
	ipSlice := strings.Split(ipAddr, ".")
	if len(ipSlice) < 4 {
		return nil, fmt.Errorf("invalid ipAddr [%s]", ipAddr)
	}

	ipSlice[0] = strconv.Itoa(prefix)
	tunnelIP := net.ParseIP(strings.Join(ipSlice, "."))

	return tunnelIP, nil
}

func ConfigureIPAddress(ipAddress net.IP, mask net.IPMask, link netlink.Link, ifname string) error {
	ipConfig := &netlink.Addr{IPNet: &net.IPNet{
		IP:   ipAddress,
		Mask: mask,
	}}

	err := netlink.AddrAdd(link, ipConfig)
	if errors.Is(err, syscall.EEXIST) {
		return nil
	} else if err != nil {
		return errors.Wrapf(err, "unable to configure address (%s) on interface (%s)", ipAddress, ifname)
	}

	return nil
}

func CreateVxlanInterface(ipAddr, hostname string, port int) (*VxlanCable, error) {
	v := VxlanCable{
		NetLink: netlinkAPI.New(),
	}

	vtepIP, err := getTunnelEndPointIPAddress(ipAddr, VxlanVTepNetworkPrefix)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to derive the vxlan vtepIP for %s", ipAddr)
	}

	defaultHostIface, err := netlinkAPI.GetDefaultGatewayInterface()
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to find the default interface on host: %s",
			hostname)
	}
	// Derive the MTU based on the default outgoing interface.
	vxlanMtu := defaultHostIface.MTU - VxlanOverhead
	attrs := &VxlanAttributes{
		name:     VxlanIfaceName,
		vxlanID:  1000,
		group:    nil,
		srcAddr:  nil,
		vtepPort: port,
		mtu:      vxlanMtu,
	}

	v.Iface, err = newVxlanIface(attrs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create vxlan interface on Gateway Node")
	}

	v.Iface.VtepIP = vtepIP

	err = v.NetLink.RuleAddIfNotPresent(netlinkAPI.NewTableRule(TableID))
	if err != nil && !os.IsExist(err) {
		return nil, errors.Wrap(err, "failed to add ip rule")
	}

	err = v.NetLink.EnableLooseModeReversePathFilter(VxlanIfaceName)
	if err != nil {
		return nil, errors.Wrap(err, "unable to update vxlan rp_filter proc entry")
	}

	klog.V(log.DEBUG).Infof("Successfully configured rp_filter to loose mode(2) on %s", VxlanIfaceName)

	err = ConfigureIPAddress(vtepIP, net.CIDRMask(8, 32), v.Iface.Link, v.Iface.Link.Name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to configure vxlan interface ipaddress on the Gateway Node")
	}

	return &v, nil
}

func newVxlanIface(attrs *VxlanAttributes) (*Iface, error) {
	iface := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:  attrs.name,
			MTU:   attrs.mtu,
			Flags: net.FlagUp,
		},
		VxlanId: attrs.vxlanID,
		SrcAddr: attrs.srcAddr,
		Group:   attrs.group,
		Port:    attrs.vtepPort,
	}

	vxlanIface := &Iface{
		Link: iface,
	}

	if err := createVxlanIface(vxlanIface); err != nil {
		return nil, err
	}

	return vxlanIface, nil
}

func createVxlanIface(iface *Iface) error {
	err := netlink.LinkAdd(iface.Link)
	if errors.Is(err, syscall.EEXIST) {
		klog.Errorf("Got error: %v, %v", err, iface.Link)
		// Get the properties of existing vxlan interface.
		existing, err := netlink.LinkByName(iface.Link.Name)
		if err != nil {
			return errors.Wrap(err, "failed to retrieve link info")
		}

		if isVxlanConfigTheSame(iface.Link, existing) {
			klog.V(log.DEBUG).Infof("VxLAN interface already exists with same configuration.")

			iface.Link = existing.(*netlink.Vxlan)

			return nil
		}

		// Config does not match, delete the existing interface and re-create it.
		if err = netlink.LinkDel(existing); err != nil {
			return errors.Wrap(err, "failed to delete the existing vxlan interface")
		}

		if err = netlink.LinkAdd(iface.Link); err != nil {
			return errors.Wrap(err, "failed to re-create the the vxlan interface")
		}
	} else if err != nil {
		return errors.Wrap(err, "failed to create the the vxlan interface")
	}

	return nil
}

func isVxlanConfigTheSame(newLink, currentLink netlink.Link) bool {
	required := newLink.(*netlink.Vxlan)
	existing := currentLink.(*netlink.Vxlan)

	if required.VxlanId != existing.VxlanId {
		klog.Warningf("VxlanId of existing interface (%d) does not match with required VxlanId (%d)", existing.VxlanId, required.VxlanId)
		return false
	}

	if len(required.Group) > 0 && len(existing.Group) > 0 && !required.Group.Equal(existing.Group) {
		klog.Warningf("Vxlan Group (%v) of existing interface does not match with required Group (%v)", existing.Group, required.Group)
		return false
	}

	if len(required.SrcAddr) > 0 && len(existing.SrcAddr) > 0 && !required.SrcAddr.Equal(existing.SrcAddr) {
		klog.Warningf("Vxlan SrcAddr (%v) of existing interface does not match with required SrcAddr (%v)", existing.SrcAddr, required.SrcAddr)
		return false
	}

	if required.Port > 0 && existing.Port > 0 && required.Port != existing.Port {
		klog.Warningf("Vxlan Port (%d) of existing interface does not match with required Port (%d)", existing.Port, required.Port)
		return false
	}

	return true
}

func addRoute(ipAddressList []net.IPNet, gwIP, ip net.IP, linkIdx int) error {
	for i := range ipAddressList {
		route := &netlink.Route{
			LinkIndex: linkIdx,
			Src:       ip,
			Dst:       &ipAddressList[i],
			Gw:        gwIP,
			Type:      netlink.NDA_DST,
			Flags:     netlink.NTF_SELF,
			Priority:  100,
			Table:     TableID,
		}
		err := netlink.RouteAdd(route)

		if errors.Is(err, syscall.EEXIST) {
			err = netlink.RouteReplace(route)
		}

		if err != nil {
			return errors.Wrapf(err, "unable to add the route entry %v", route)
		}

		klog.V(log.DEBUG).Infof("Successfully added the route entry %v and gw ip %v", route, gwIP)
	}

	return nil
}

func delRoute(ipAddressList []net.IPNet, linkIdx, tableID int) error {
	for i := range ipAddressList {
		route := &netlink.Route{
			LinkIndex: linkIdx,
			Dst:       &ipAddressList[i],
			Gw:        nil,
			Type:      netlink.NDA_DST,
			Flags:     netlink.NTF_SELF,
			Priority:  100,
			Table:     tableID,
		}

		err := netlink.RouteDel(route)
		if err != nil {
			return errors.Wrapf(err, "unable to add the route entry %v", route)
		}

		klog.V(log.DEBUG).Infof("Successfully deleted the route entry %v", route)
	}

	return nil
}

func addFDB(ipAddress net.IP, hwAddr string, linkIdx int) error {
	macAddr, err := net.ParseMAC(hwAddr)
	if err != nil {
		return errors.Wrapf(err, "invalid MAC Address (%s) supplied", hwAddr)
	}

	if ipAddress == nil {
		return fmt.Errorf("invalid ipAddress (%v) supplied", ipAddress)
	}

	neigh := &netlink.Neigh{
		LinkIndex:    linkIdx,
		Family:       unix.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		Type:         netlink.NDA_DST,
		IP:           ipAddress,
		State:        netlink.NUD_PERMANENT | netlink.NUD_NOARP,
		HardwareAddr: macAddr,
	}

	err = netlink.NeighAppend(neigh)
	if err != nil {
		return errors.Wrapf(err, "unable to add the bridge fdb entry %v", neigh)
	}

	klog.V(log.DEBUG).Infof("Successfully added the bridge fdb entry %v", neigh)

	return nil
}

func delFDB(ipAddress net.IP, hwAddr string, linkIdx int) error {
	macAddr, err := net.ParseMAC(hwAddr)
	if err != nil {
		return errors.Wrapf(err, "invalid MAC Address (%s) supplied", hwAddr)
	}

	neigh := &netlink.Neigh{
		LinkIndex:    linkIdx,
		Family:       unix.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		Type:         netlink.NDA_DST,
		IP:           ipAddress,
		State:        netlink.NUD_PERMANENT | netlink.NUD_NOARP,
		HardwareAddr: macAddr,
	}

	err = netlink.NeighDel(neigh)
	if err != nil {
		return errors.Wrapf(err, "unable to delete the bridge fdb entry %v", neigh)
	}

	klog.V(log.DEBUG).Infof("Successfully deleted the bridge fdb entry %v", neigh)

	return nil
}

// Parse CIDR string and skip errors.
func parseSubnets(subnets []string) []net.IPNet {
	nets := make([]net.IPNet, 0, len(subnets))

	for _, sn := range subnets {
		_, cidr, err := net.ParseCIDR(sn)
		if err != nil {
			// this should not happen. Log and continue
			klog.Errorf("failed to parse subnet %s: %v", sn, err)
			continue
		}

		nets = append(nets, *cidr)
	}

	return nets
}

func SetupVxlanRoutes(v *VxlanCable, endpointInfo *natdiscovery.NATEndpointInfo,
	clusterID, clusterCIDR string) error {
	// We'll panic if endpointInfo is nil, this is intentional
	remoteEndpoint := endpointInfo.Endpoint
	if clusterID == remoteEndpoint.Spec.ClusterID {
		klog.V(log.DEBUG).Infof("Will not connect to self")
		return nil
	}

	remoteIP := net.ParseIP(endpointInfo.UseIP)
	if remoteIP == nil {
		return fmt.Errorf("failed to parse remote IP %s", endpointInfo.UseIP)
	}

	allowedIPs := parseSubnets(remoteEndpoint.Spec.Subnets)

	klog.V(log.DEBUG).Infof("Connecting cluster %s endpoint %s",
		remoteEndpoint.Spec.ClusterID, remoteIP)
	v.Mutex.Lock()
	defer v.Mutex.Unlock()

	privateIP := endpointInfo.Endpoint.Spec.PrivateIP

	remoteVtepIP, err := getTunnelEndPointIPAddress(privateIP, VxlanVTepNetworkPrefix)
	if err != nil {
		return fmt.Errorf("failed to derive the vxlan vtepIP for %s: %w", privateIP, err)
	}

	err = addFDB(remoteIP, "00:00:00:00:00:00", v.Iface.Link.Index)

	if err != nil {
		return fmt.Errorf("failed to add remoteIP %q to the forwarding database", remoteIP)
	}

	var cniIPAddress net.IP

	if cniIface, err := cni.Discover(clusterCIDR); err != nil {
		klog.Errorf("Failed to get the CNI interface IP for cluster CIDR %q, host-networking use-cases may not work",
			clusterCIDR)

		cniIPAddress = nil
	} else {
		cniIPAddress = net.ParseIP(cniIface.IPAddress)
	}

	err = addRoute(allowedIPs, remoteVtepIP, cniIPAddress, v.Iface.Link.Index)

	if err != nil {
		return fmt.Errorf("failed to add route for the CIDR %q with remoteVtepIP %q and vxlanInterfaceIP %q: %w",
			allowedIPs, remoteVtepIP, v.Iface.VtepIP, err)
	}

	return nil
}

func CleanupVxlanRoutes(v *VxlanCable, remoteEndpoint *types.SubmarinerEndpoint, clusterID string, connections []v1.Connection) error {
	// We'll panic if remoteEndpoint is nil, this is intentional
	klog.V(log.DEBUG).Infof("Cleaning up vxlan routes for %#v", remoteEndpoint)

	if clusterID == remoteEndpoint.Spec.ClusterID {
		klog.V(log.DEBUG).Infof("Will not disconnect self")
		return nil
	}

	v.Mutex.Lock()
	defer v.Mutex.Unlock()

	var ip string

	for j := range connections {
		if connections[j].Endpoint.CableName == remoteEndpoint.Spec.CableName {
			ip = connections[j].UsingIP
		}
	}

	if ip == "" {
		klog.Errorf("Cannot disconnect remote endpoint %q - no prior connection entry found", remoteEndpoint.Spec.CableName)
		return nil
	}

	remoteIP := net.ParseIP(ip)

	if remoteIP == nil {
		return fmt.Errorf("failed to parse remote IP %s", ip)
	}

	allowedIPs := parseSubnets(remoteEndpoint.Spec.Subnets)

	err := delFDB(remoteIP, "00:00:00:00:00:00", v.Iface.Link.Index)
	if err != nil {
		return fmt.Errorf("failed to delete remoteIP %q from the forwarding database: %w", remoteIP, err)
	}

	err = delRoute(allowedIPs, v.Iface.Link.Index, TableID)

	if err != nil {
		return fmt.Errorf("failed to remove route for the CIDR %q: %w", allowedIPs, err)
	}

	klog.V(log.DEBUG).Infof("Done removing endpoint for cluster %s", remoteEndpoint.Spec.ClusterID)

	return nil
}
