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
	"github.com/pkg/errors"
	"github.com/submariner-io/submariner/pkg/cable/cableutils"
	"github.com/submariner-io/submariner/pkg/event"
	"github.com/submariner-io/submariner/pkg/netlink"
	"k8s.io/klog"
)

type vxlanXFRMCleanup struct {
	event.HandlerBase
}

func NewVXLANXFRMCleanup() event.Handler {
	return &vxlanXFRMCleanup{}
}

func (h *vxlanXFRMCleanup) GetNetworkPlugins() []string {
	return []string{event.AnyNetworkPlugin}
}

func (h *vxlanXFRMCleanup) GetName() string {
	return "VXLAN cleanup handler"
}

func (h *vxlanXFRMCleanup) TransitionToNonGateway() error {
	var err error

	klog.Infof("Cleaning up")

	if err = netlink.DeleteXfrmRules(); err != nil {
		return errors.Wrap(err, "failed to DeleteXfrmRules")
	}

	if err = netlink.DeleteIfaceAndAssociatedRoutes(cableutils.VxlanIfaceName, cableutils.TableID); err != nil {
		return errors.Wrap(err, "failed to DeleteIfaceAndAssociatedRoutes")
	}

	return nil
}
