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

package vxlanlibreswan

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"

	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	subv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/cable/cableutils"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	"github.com/submariner-io/submariner/pkg/netlink"
	"github.com/submariner-io/submariner/pkg/types"
	"k8s.io/klog"
)

const (
	cableDriverName = "vxlan-libreswan"
	vxlanPort       = 4789
)

type vxlanLibreswan struct {
	localEndpoint types.SubmarinerEndpoint
	// This tracks the requested connections
	connections []subv1.Connection

	secretKey string
	logFile   string

	ipSecNATTPort   string
	defaultNATTPort int32

	debug                 bool
	forceUDPEncapsulation bool

	vxlan        *cableutils.VxlanCable
	localCluster types.SubmarinerCluster
}

type specification struct {
	Debug       bool
	ForceEncaps bool
	PSK         string
	PSKSecret   string
	LogFile     string
	NATTPort    string `default:"4500"`
}

const (
	ipsecSpecEnvVarPrefix = "ce_ipsec"
)

func init() {
	cable.AddDriver(cableDriverName, NewDriver)
}

// NewDriver starts an IKE daemon using Libreswan and configures it to manage Submariner's endpoints.
// It also creates a vxlan interface.
func NewDriver(localEndpoint *types.SubmarinerEndpoint, localCluster *types.SubmarinerCluster) (cable.Driver, error) {
	// We'll panic if localEndpoint or localCluster are nil, this is intentional
	ipSecSpec := specification{}

	err := envconfig.Process(ipsecSpecEnvVarPrefix, &ipSecSpec)
	if err != nil {
		return nil, errors.Wrapf(err, "error processing environment config for %s", ipsecSpecEnvVarPrefix)
	}

	defaultNATTPort, err := strconv.ParseUint(ipSecSpec.NATTPort, 10, 16)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing CR_IPSEC_NATTPORT environment variable")
	}

	nattPort, err := localEndpoint.Spec.GetBackendPort(subv1.UDPPortConfig, int32(defaultNATTPort))
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %q from local endpoint", subv1.UDPPortConfig)
	}

	encodedPsk := ipSecSpec.PSK

	if ipSecSpec.PSKSecret != "" {
		pskBytes, err := os.ReadFile(fmt.Sprintf("/var/run/secrets/submariner.io/%s/psk", ipSecSpec.PSKSecret))
		if err != nil {
			return nil, errors.Wrapf(err, "error reading secret %s", ipSecSpec.PSKSecret)
		}
		var psk strings.Builder
		encoder := base64.NewEncoder(base64.StdEncoding, &psk)

		if _, err := encoder.Write(pskBytes); err != nil {
			return nil, errors.Wrap(err, "error encoding secret")
		}

		encoder.Close()

		encodedPsk = psk.String()
	}

	v := vxlanLibreswan{
		secretKey:             encodedPsk,
		debug:                 ipSecSpec.Debug,
		logFile:               ipSecSpec.LogFile,
		ipSecNATTPort:         strconv.Itoa(int(nattPort)),
		defaultNATTPort:       int32(defaultNATTPort),
		localEndpoint:         *localEndpoint,
		connections:           []subv1.Connection{},
		forceUDPEncapsulation: ipSecSpec.ForceEncaps,
		localCluster:          *localCluster,
	}

	if v.vxlan, err = cableutils.CreateVxlanInterface(localEndpoint.Spec.PrivateIP, localEndpoint.Spec.Hostname, vxlanPort); err != nil {
		return nil, errors.Wrap(err, "failed to setup Vxlan link")
	}

	return &v, nil
}

// GetName returns driver's name.
func (i *vxlanLibreswan) GetName() string {
	return cableDriverName
}

// Init initializes the driver with any state it needs.
func (i *vxlanLibreswan) Init() error {
	// Ensure Pluto is started
	if err := cableutils.ConfigureRunPluto(i.secretKey, i.logFile, i.debug); err != nil {
		return errors.Wrap(err, "error starting Pluto")
	}

	return nil
}

func (i *vxlanLibreswan) refreshConnectionStatus() error {
	activeConnectionsRx, activeConnectionsTx, err := cableutils.RetrieveActiveConnectionStats()
	if err != nil {
		return errors.Wrap(err, "error retrieving connection stats")
	}

	cable.RecordNoConnections()

	for j := range i.connections {
		isConnected := false
		rx, tx := 0, 0

		for x := 0; x < 2; x++ {
			connectionName := fmt.Sprintf("%s-%d-%d", i.connections[j].Endpoint.CableName, 0, x)

			subRx, okRx := activeConnectionsRx[connectionName]
			subTx, okTx := activeConnectionsTx[connectionName]

			if okRx || okTx {
				i.connections[j].Status = subv1.Connected
				isConnected = true
				rx += subRx
				tx += subTx
			} else {
				klog.V(log.DEBUG).Infof("Connection %q not found in active connections obtained from whack: %v, %v",
					connectionName, activeConnectionsRx, activeConnectionsTx)
			}
		}

		cable.RecordConnection(cableDriverName, &i.localEndpoint.Spec, &i.connections[j].Endpoint, string(i.connections[j].Status), false)
		cable.RecordRxBytes(cableDriverName, &i.localEndpoint.Spec, &i.connections[j].Endpoint, rx)
		cable.RecordTxBytes(cableDriverName, &i.localEndpoint.Spec, &i.connections[j].Endpoint, tx)

		if !isConnected {
			// Pluto should be connecting for us
			i.connections[j].Status = subv1.Connecting
			cable.RecordConnection(cableDriverName, &i.localEndpoint.Spec, &i.connections[j].Endpoint, string(i.connections[j].Status), false)
			klog.V(log.DEBUG).Infof("Connection %q not found in active connections obtained from whack: %v, %v",
				i.connections[j].Endpoint.CableName, activeConnectionsRx, activeConnectionsTx)
		}
	}

	return nil
}

// GetActiveConnections returns an array of all the active connections.
func (i *vxlanLibreswan) GetActiveConnections() ([]subv1.Connection, error) {
	return i.connections, nil
}

// GetConnections() returns an array of the existing connections, including status and endpoint info.
func (i *vxlanLibreswan) GetConnections() ([]subv1.Connection, error) {
	if err := i.refreshConnectionStatus(); err != nil {
		return []subv1.Connection{}, err
	}

	return i.connections, nil
}

// ConnectToEndpoint establishes a connection to the given endpoint and returns a string
// representation of the IP address of the target endpoint.
func (i *vxlanLibreswan) ConnectToEndpoint(endpointInfo *natdiscovery.NATEndpointInfo) (string, error) {
	// We'll panic if endpointInfo is nil, this is intentional
	remoteEndpoint := &endpointInfo.Endpoint

	if i.localEndpoint.Spec.ClusterID == remoteEndpoint.Spec.ClusterID {
		klog.V(log.DEBUG).Infof("Will not connect to self")
		return "", nil
	}

	rightNATTPort, err := remoteEndpoint.Spec.GetBackendPort(subv1.UDPPortConfig, i.defaultNATTPort)
	if err != nil {
		klog.Warningf("Error parsing %q from remote endpoint %q - using port %d instead: %v", subv1.UDPPortConfig,
			remoteEndpoint.Spec.CableName, i.defaultNATTPort, err)
	}

	// Ensure we’re listening
	if err := cableutils.Whack("--listen"); err != nil {
		return "", errors.Wrap(err, "error listening")
	}

	if err := cableutils.SetupVxlanRoutes(i.vxlan, endpointInfo,
		i.localEndpoint.Spec.ClusterID, i.localCluster.Spec.ClusterCIDR[0]); err != nil {
		return "", errors.Wrap(err, "error setting  up vxlan routes")
	}

	klog.Infof("Creating connection(s) for %v", remoteEndpoint)

	err = i.connectToEndpoint(remoteEndpoint.Spec.CableName, endpointInfo, rightNATTPort)
	if err != nil {
		return "", err
	}

	i.connections = append(i.connections,
		subv1.Connection{Endpoint: remoteEndpoint.Spec, Status: subv1.Connected, UsingIP: endpointInfo.UseIP, UsingNAT: endpointInfo.UseNAT})
	cable.RecordConnection(cableDriverName, &i.localEndpoint.Spec, &remoteEndpoint.Spec, string(subv1.Connected), true)

	return endpointInfo.UseIP, nil
}

func searchArgs(data []string, s string) int {
	for idx, v := range data {
		if s == v {
			return idx
		}
	}

	return -1
}

func (i *vxlanLibreswan) connectToEndpoint(connectionName string, endpointInfo *natdiscovery.NATEndpointInfo,
	rightNATTPort int32,
) error {
	// Identifiers are used for authentication, they’re always the private IPs
	localEndpointIdentifier := i.localEndpoint.Spec.PrivateIP
	remoteEndpointIdentifier := endpointInfo.Endpoint.Spec.PrivateIP

	// Two xfrm transport rules setup for vxlan ==> two connectionNames
	connectionNames := []string{}
	for j := 0; j < 2; j++ {
		connectionNames = append(connectionNames, fmt.Sprintf("%s-%d-%d", connectionName, 0, j))
	}

	args := []string{}
	args = append(args, "--psk", "--encrypt")

	if endpointInfo.UseNAT || i.forceUDPEncapsulation {
		args = append(args, "--forceencaps")
	}

	args = append(args, "--name", connectionNames[0],

		// Left-hand side
		"--id", localEndpointIdentifier,
		"--host", i.localEndpoint.Spec.PrivateIP,
		"--ikeport", i.ipSecNATTPort,
		"--clientprotoport", "udp/vxlan",
		"--to",

		// Right-hand side
		"--id", remoteEndpointIdentifier,
		"--host", endpointInfo.UseIP,
		"--clientprotoport", "udp",
		"--ikeport", strconv.Itoa(int(rightNATTPort)))

	klog.Infof("Executing whack with args: %v", args)

	if err := cableutils.Whack(args...); err != nil {
		return errors.Wrapf(err, "failed to execute whack with args %v", args)
	}

	// ipsec whack the reverse clientprotoport xfrm rule
	connNameIdx := searchArgs(args, connectionNames[0])
	args[connNameIdx] = connectionNames[1]
	vxlanIdx := searchArgs(args, "udp/vxlan")
	udpIdx := searchArgs(args, "udp")
	swap := reflect.Swapper(args)
	swap(vxlanIdx, udpIdx)

	klog.Infof("Executing whack with args: %v", args)

	if err := cableutils.Whack(args...); err != nil {
		return errors.Wrapf(err, "failed to execute whack with args %v", args)
	}

	for j := 0; j < 2; j++ {
		if err := cableutils.Whack("--route", "--name", connectionNames[j]); err != nil {
			return errors.Wrapf(err, "failed to execute whack with args %v", args)
		}

		if err := cableutils.Whack("--route", "--name", connectionNames[j]); err != nil {
			return errors.Wrapf(err, "failed to execute whack with args %v", args)
		}
	}

	return nil
}

// DisconnectFromEndpoint disconnects from the connection to the given endpoint.
func (i *vxlanLibreswan) DisconnectFromEndpoint(endpoint *types.SubmarinerEndpoint) error {
	// We'll panic if endpoint is nil, this is intentional
	connectionName := endpoint.Spec.CableName

	klog.Infof("Deleting connection to %v", endpoint)

	args := []string{}

	args = append(args, "--delete",
		"--name", connectionName)

	klog.Infof("Whacking with %v", args)

	cmd := exec.Command("/usr/libexec/ipsec/whack", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			klog.Errorf("error deleting a connection with args %v; got exit code %d: %v", args, exitError.ExitCode(), err)
		} else {
			return errors.Wrapf(err, "error deleting a connection with args %v", args)
		}
	}

	if err := cableutils.CleanupVxlanRoutes(i.vxlan, endpoint, i.localEndpoint.Spec.ClusterID, i.connections); err != nil {
		return errors.Wrap(err, "error cleaning up vxlan routes")
	}

	i.connections = removeConnectionForEndpoint(i.connections, endpoint)
	cable.RecordDisconnected(cableDriverName, &i.localEndpoint.Spec, &endpoint.Spec)

	return nil
}

func removeConnectionForEndpoint(connections []subv1.Connection, endpoint *types.SubmarinerEndpoint) []subv1.Connection {
	for j := range connections {
		if connections[j].Endpoint.CableName == endpoint.Spec.CableName {
			copy(connections[j:], connections[j+1:])
			return connections[:len(connections)-1]
		}
	}

	return connections
}

func (i *vxlanLibreswan) Cleanup() error {
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
