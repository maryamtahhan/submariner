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

package cabledriver

import (
	"syscall"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	"github.com/submariner-io/submariner/pkg/cable/iptun"
	"github.com/submariner-io/submariner/pkg/event"
	"github.com/vishvananda/netlink"
	"k8s.io/klog"
)

type ipTunCleanup struct {
	event.HandlerBase
}

func NewIPTunCleanup() event.Handler {
	return &ipTunCleanup{}
}

func (h *ipTunCleanup) GetNetworkPlugins() []string {
	return []string{event.AnyNetworkPlugin}
}

func (h *ipTunCleanup) GetName() string {
	return "IPTun cleanup handler"
}

func (h *ipTunCleanup) TransitionToNonGateway() error {
	klog.Infof("Cleaning up the routes")

	link, err := netlink.LinkByName(iptun.IPTunIface)
	if err != nil {
		if !errors.Is(err, netlink.LinkNotFoundError{}) {
			klog.Warningf("Failed to retrieve the ipip-tunnel interface during transition to non-gateway: %v", err)
		}

		return nil
	}

	currentRouteList, err := netlink.RouteList(link, syscall.AF_INET)

	if err != nil {
		klog.Warningf("Unable to cleanup routes, error retrieving routes on the link %s: %v", iptun.IPTunIface, err)
	} else {
		for i := range currentRouteList {
			klog.V(log.DEBUG).Infof("Processing route %v", currentRouteList[i])
			if currentRouteList[i].Table == iptun.TableID {
				if err = netlink.RouteDel(&currentRouteList[i]); err != nil {
					klog.Errorf("Error removing route %s: %v", currentRouteList[i], err)
				}
			}
		}
	}

	err = netlink.LinkDel(link)
	if err != nil {
		return errors.Wrapf(err, "failed to delete the ipip-tunnel interface")
	}

	return nil
}
