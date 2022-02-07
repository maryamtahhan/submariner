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

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/pkg/errors"
)

// ensureServiceLoadbalancers make sure we add the clusterLBGroup load_balancer_group
// to the submariner router so that all VIPs are accessible for the clusterset.
func (ovn *SyncHandler) ensureServiceLoadBalancers() error {
	clusterLBGroup := &nbdb.LoadBalancerGroup{
		Name: "clusterLBGroup",
	}

	// Get the clusterLBGroup
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	err := ovn.nbdb.Get(ctx, clusterLBGroup)
	if err != nil {
		return err
	}

	// Add the OVN ClusterLBGroup to the submariner router
	submarinerLogicalRouter := nbdb.LogicalRouter{
		Name: submarinerLogicalRouter,
	}

	submarinerLogicalRouter.LoadBalancerGroup = []string{clusterLBGroup.UUID}

	opModels := []libovsdbops.OperationModel{
		{
			Model:          &submarinerLogicalRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == submarinerLogicalRouter.Name },
			OnModelMutations: []interface{}{
				&submarinerLogicalRouter.LoadBalancerGroup,
			},
			ErrNotFound: true,
		},
	}

	m := libovsdbops.NewModelClient(ovn.nbdb)
	if _, err := m.CreateOrUpdate(opModels...); err != nil {
		return errors.Wrapf(err, "failed to add ovn clusterLBGroup to the submariner router")
	}

	return nil
}
