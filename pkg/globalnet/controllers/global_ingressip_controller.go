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

package controllers

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/federate"
	"github.com/submariner-io/admiral/pkg/syncer"
	"github.com/submariner-io/admiral/pkg/util"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/globalnet/controllers/iptables"
	"github.com/submariner-io/submariner/pkg/ipam"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

func NewGlobalIngressIPController(config *syncer.ResourceSyncerConfig, pool *ipam.IPPool) (Interface, error) {
	// We'll panic if config is nil, this is intentional
	var err error

	klog.Info("Creating GlobalIngressIP controller")

	iptIface, err := iptables.New()
	if err != nil {
		return nil, errors.Wrap(err, "error creating the IPTablesInterface handler")
	}

	controller := &globalIngressIPController{
		baseIPAllocationController: newBaseIPAllocationController(pool, iptIface),
	}

	_, gvr, err := util.ToUnstructuredResource(&submarinerv1.GlobalIngressIP{}, config.RestMapper)
	if err != nil {
		return nil, errors.Wrap(err, "error converting resource")
	}

	federator := federate.NewUpdateFederator(config.SourceClient, config.RestMapper, corev1.NamespaceAll)

	client := config.SourceClient.Resource(*gvr)

	list, err := client.Namespace(corev1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "error listing the resources")
	}

	for i := range list.Items {
		obj := &list.Items[i]
		gip := &submarinerv1.GlobalIngressIP{}
		_ = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, gip)

		var target string
		var tType iptables.TargetType

		if gip.Spec.Target == submarinerv1.ClusterIPService {
			target = gip.GetAnnotations()[kubeProxyIPTableChainAnnotation]
		} else if gip.Spec.Target == submarinerv1.HeadlessServicePod {
			target = gip.GetAnnotations()[headlessSvcPodIP]
			tType = iptables.PodTarget
		} else if gip.Spec.Target == submarinerv1.HeadlessServiceEndpoints {
			target = gip.GetAnnotations()[headlessSvcEndpointsIP]
			tType = iptables.EndpointsTarget
		}

		if target == "" {
			continue
		}

		// nolint:wrapcheck  // No need to wrap these errors.
		err = controller.reserveAllocatedIPs(federator, obj, func(reservedIPs []string) error {
			if gip.Spec.Target == submarinerv1.ClusterIPService {
				return controller.iptIface.AddIngressRulesForService(reservedIPs[0], target)
			} else if gip.Spec.Target == submarinerv1.HeadlessServicePod || gip.Spec.Target == submarinerv1.HeadlessServiceEndpoints {
				err := controller.iptIface.AddIngressRulesForHeadlessSvc(reservedIPs[0], target, tType)
				if err != nil {
					return err
				}

				key, _ := cache.MetaNamespaceKeyFunc(obj)
				return controller.iptIface.AddEgressRulesForHeadlessSVC(key, target, reservedIPs[0], globalNetIPTableMark, tType)
			}
			return nil
		})

		if err != nil {
			return nil, err
		}
	}

	controller.resourceSyncer, err = syncer.NewResourceSyncer(&syncer.ResourceSyncerConfig{
		Name:                "GlobalIngressIP syncer",
		ResourceType:        &submarinerv1.GlobalIngressIP{},
		SourceClient:        config.SourceClient,
		SourceNamespace:     corev1.NamespaceAll,
		RestMapper:          config.RestMapper,
		Federator:           federator,
		Scheme:              config.Scheme,
		Transform:           controller.process,
		ResourcesEquivalent: syncer.AreSpecsEquivalent,
	})

	if err != nil {
		return nil, errors.Wrap(err, "error creating the syncer")
	}

	return controller, nil
}

func (c *globalIngressIPController) process(from runtime.Object, numRequeues int, op syncer.Operation) (runtime.Object, bool) {
	ingressIP := from.(*submarinerv1.GlobalIngressIP)

	klog.Infof("Processing %sd %#v", op, ingressIP)

	switch op {
	case syncer.Create:
		prevStatus := ingressIP.Status
		requeue := c.onCreate(ingressIP)

		return checkStatusChanged(&prevStatus, &ingressIP.Status, ingressIP), requeue
	case syncer.Delete:
		return nil, c.onDelete(ingressIP, numRequeues)
	case syncer.Update:
	}

	return nil, false
}

func (c *globalIngressIPController) onCreate(ingressIP *submarinerv1.GlobalIngressIP) bool {
	// If Ingress GlobalIP is already allocated, simply return.
	if ingressIP.Status.AllocatedIP != "" {
		return false
	}

	key, _ := cache.MetaNamespaceKeyFunc(ingressIP)

	klog.Infof("Allocating global IP for %q", key)

	ips, err := c.pool.Allocate(1)
	if err != nil {
		klog.Errorf("Error allocating IP for %q: %v", key, err)

		ingressIP.Status.Conditions = util.TryAppendCondition(ingressIP.Status.Conditions, &metav1.Condition{
			Type:    string(submarinerv1.GlobalEgressIPAllocated),
			Status:  metav1.ConditionFalse,
			Reason:  "IPPoolAllocationFailed",
			Message: fmt.Sprintf("Error allocating a global IP from the pool: %v", err),
		})

		return true
	}

	var target string
	var tType iptables.TargetType

	if ingressIP.Spec.Target == submarinerv1.HeadlessServicePod {
		target = ingressIP.GetAnnotations()[headlessSvcPodIP]
		if target == "" {
			_ = c.pool.Release(ips...)

			klog.Warningf("%q annotation is missing on %q", headlessSvcPodIP, key)

			return true
		}

		tType = iptables.PodTarget
	} else if ingressIP.Spec.Target == submarinerv1.HeadlessServiceEndpoints {
		target = ingressIP.GetAnnotations()[headlessSvcEndpointsIP]
		if target == "" {
			_ = c.pool.Release(ips...)

			klog.Warningf("%q annotation is missing on %q", headlessSvcEndpointsIP, key)

			return true
		}

		tType = iptables.EndpointsTarget
	}

	if ingressIP.Spec.Target == submarinerv1.ClusterIPService {
		chainName := ingressIP.GetAnnotations()[kubeProxyIPTableChainAnnotation]
		if chainName == "" {
			_ = c.pool.Release(ips...)

			klog.Warningf("%q annotation is missing on %q", kubeProxyIPTableChainAnnotation, key)

			return true
		}

		err = c.iptIface.AddIngressRulesForService(ips[0], chainName)
		if err != nil {
			klog.Errorf("Error while programming Service %q ingress rules: %v", key, err)

			_ = c.pool.Release(ips...)

			ingressIP.Status.Conditions = util.TryAppendCondition(ingressIP.Status.Conditions, &metav1.Condition{
				Type:    string(submarinerv1.GlobalEgressIPAllocated),
				Status:  metav1.ConditionFalse,
				Reason:  "ProgramIPTableRulesFailed",
				Message: fmt.Sprintf("Error programming ingress rules: %v", err),
			})

			return true
		}
	} else if ingressIP.Spec.Target == submarinerv1.HeadlessServicePod || ingressIP.Spec.Target == submarinerv1.HeadlessServiceEndpoints {
		err = c.iptIface.AddIngressRulesForHeadlessSvc(ips[0], target, tType)
		if err != nil {
			klog.Errorf("Error while programming Service %q ingress rules for Pod: %v", key, err)
			err = errors.WithMessage(err, "Error programming ingress rules")
		} else {
			err = c.iptIface.AddEgressRulesForHeadlessSVC(key, target, ips[0], globalNetIPTableMark, tType)
			if err != nil {
				_ = c.iptIface.RemoveIngressRulesForHeadlessSvc(ips[0], target, tType)
				err = errors.WithMessage(err, "Error programming egress rules")
			}
		}

		if err != nil {
			_ = c.pool.Release(ips...)
			ingressIP.Status.Conditions = util.TryAppendCondition(ingressIP.Status.Conditions, &metav1.Condition{
				Type:    string(submarinerv1.GlobalEgressIPAllocated),
				Status:  metav1.ConditionFalse,
				Reason:  "ProgramIPTableRulesFailed",
				Message: err.Error(),
			})

			return true
		}
	}

	ingressIP.Status.AllocatedIP = ips[0]

	ingressIP.Status.Conditions = util.TryAppendCondition(ingressIP.Status.Conditions, &metav1.Condition{
		Type:    string(submarinerv1.GlobalEgressIPAllocated),
		Status:  metav1.ConditionTrue,
		Reason:  "Success",
		Message: "Allocated global IP",
	})

	return false
}

// nolint:wrapcheck  // No need to wrap these errors.
func (c *globalIngressIPController) onDelete(ingressIP *submarinerv1.GlobalIngressIP, numRequeues int) bool {
	if ingressIP.Status.AllocatedIP == "" {
		return false
	}

	key, _ := cache.MetaNamespaceKeyFunc(ingressIP)

	return c.flushRulesAndReleaseIPs(key, numRequeues, func(allocatedIPs []string) error {
		var target string
		var tType iptables.TargetType
		if ingressIP.Spec.Target == submarinerv1.HeadlessServicePod {
			target = ingressIP.GetAnnotations()[headlessSvcPodIP]
			tType = iptables.PodTarget
		} else if ingressIP.Spec.Target == submarinerv1.HeadlessServiceEndpoints {
			target = ingressIP.GetAnnotations()[headlessSvcEndpointsIP]
			tType = iptables.EndpointsTarget
		}

		if ingressIP.Spec.Target == submarinerv1.ClusterIPService {
			chainName := ingressIP.GetAnnotations()[kubeProxyIPTableChainAnnotation]
			if chainName != "" {
				return c.iptIface.RemoveIngressRulesForService(ingressIP.Status.AllocatedIP, chainName)
			}
		} else if ingressIP.Spec.Target == submarinerv1.HeadlessServicePod || ingressIP.Spec.Target == submarinerv1.HeadlessServiceEndpoints {
			if target != "" {
				if err := c.iptIface.RemoveIngressRulesForHeadlessSvc(ingressIP.Status.AllocatedIP, target, tType); err != nil {
					return err
				}

				return c.iptIface.RemoveEgressRulesForHeadlessSVC(key, target, ingressIP.Status.AllocatedIP, globalNetIPTableMark, tType)
			}
		}

		return nil
	}, ingressIP.Status.AllocatedIP)
}
