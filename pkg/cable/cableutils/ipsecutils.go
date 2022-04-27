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
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	subv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"k8s.io/klog"
)

// Line format: 006 #3: "submariner-cable-cluster3-172-17-0-8-0-0", type=ESP, add_time=1590508783, inBytes=0, outBytes=0, id='172.17.0.8'
//          or: 006 #2: "submariner-cable-cluster3-172-17-0-8-0-0"[1] 3.139.75.179, type=ESP, add_time=1617195756, inBytes=0, outBytes=0,
//                        id='@10.0.63.203-0-0'"
var trafficStatusRE = regexp.MustCompile(`.* "([^"]+)"[^,]*, .*inBytes=(\d+), outBytes=(\d+).*`)

func RetrieveActiveConnectionStats() (map[string]int, map[string]int, error) {
	// Retrieve active tunnels from the daemon
	cmd := exec.Command("/usr/libexec/ipsec/whack", "--trafficstatus")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, errors.WithMessage(err, "error retrieving whack's stdout")
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, errors.WithMessage(err, "error starting whack")
	}

	scanner := bufio.NewScanner(stdout)
	activeConnectionsRx := make(map[string]int)
	activeConnectionsTx := make(map[string]int)

	for scanner.Scan() {
		line := scanner.Text()

		matches := trafficStatusRE.FindStringSubmatch(line)
		if matches != nil {
			_, ok := activeConnectionsRx[matches[1]]
			if !ok {
				activeConnectionsRx[matches[1]] = 0
			}

			_, ok = activeConnectionsTx[matches[1]]
			if !ok {
				activeConnectionsTx[matches[1]] = 0
			}

			inBytes, err := strconv.Atoi(matches[2])
			if err != nil {
				klog.Warningf("Invalid inBytes in whack output line: %q", line)
			} else {
				activeConnectionsRx[matches[1]] += inBytes
			}

			outBytes, err := strconv.Atoi(matches[3])
			if err != nil {
				klog.Warningf("Invalid outBytes in whack output line: %q", line)
			} else {
				activeConnectionsTx[matches[1]] += outBytes
			}
		} else {
			klog.V(log.DEBUG).Infof("Ignoring whack output line: %q", line)
		}
	}

	return activeConnectionsRx, activeConnectionsTx, errors.Wrap(cmd.Wait(), "error waiting for whack to complete")
}

func Whack(args ...string) error {
	var err error

	for i := 0; i < 3; i++ {
		cmd := exec.Command("/usr/libexec/ipsec/whack", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		klog.V(log.TRACE).Infof("Whacking with %v", args)

		if err = cmd.Run(); err == nil {
			break
		}

		klog.Warningf("error %v whacking with args: %v", err, args)
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		return errors.Wrapf(err, "error whacking with args %v", args)
	}

	return nil
}

func ExtractSubnets(endpoint *subv1.EndpointSpec) []string {
	subnets := make([]string, 0, len(endpoint.Subnets))

	for _, subnet := range endpoint.Subnets {
		if !strings.HasPrefix(subnet, endpoint.PrivateIP+"/") {
			subnets = append(subnets, subnet)
		}
	}

	return subnets
}

func runPluto(debug bool, logFile string) error {
	klog.Info("Starting Pluto")

	args := []string{}

	if debug {
		args = append(args, "--stderrlog")
	}

	cmd := exec.Command("/usr/local/bin/pluto", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	var outputFile *os.File

	if logFile != "" {
		out, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o666)
		if err != nil {
			return errors.Wrapf(err, "failed to open log file %s", logFile)
		}

		cmd.Stdout = out
		cmd.Stderr = out
		outputFile = out
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}

	if err := cmd.Start(); err != nil {
		// Note - Close handles nil receiver.
		outputFile.Close()
		return errors.Wrapf(err, "error starting the Pluto process with args %v", args)
	}

	go func() {
		defer outputFile.Close()
		klog.Fatalf("Pluto exited: %v", cmd.Wait())
	}()

	// Wait up to 5s for the control socket.
	for i := 0; i < 5; i++ {
		_, err := os.Stat("/run/pluto/pluto.ctl")
		if err == nil {
			break
		}

		if !os.IsNotExist(err) {
			klog.Infof("Failed to stat the control socket: %v", err)
			break
		}

		time.Sleep(1 * time.Second)
	}

	if debug {
		if err := Whack("--debug", "base"); err != nil {
			return err
		}
	}

	return nil
}

func ConfigureRunPluto(secretKey, logFile string, debug bool) error {
	// Write the secrets file:
	// %any %any : PSK "secret"
	// TODO Check whether the file already exists
	file, err := os.Create("/etc/ipsec.d/submariner.secrets")
	if err != nil {
		return errors.Wrap(err, "error creating the secrets file")
	}
	defer file.Close()

	fmt.Fprintf(file, "%%any %%any : PSK \"%s\"\n", secretKey)

	// Ensure Pluto is started
	if err := runPluto(debug, logFile); err != nil {
		return errors.Wrap(err, "error starting Pluto")
	}

	return nil
}
