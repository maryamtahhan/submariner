module github.com/submariner-io/submariner

go 1.13

require (
	github.com/cenkalti/backoff/v4 v4.1.2
	github.com/coreos/go-iptables v0.6.0
	github.com/ebay/go-ovn v0.1.1-0.20210414223409-7376ba97f8cd
	github.com/emirpasic/gods v1.12.0
	github.com/go-ping/ping v0.0.0-20210506233800-ff8be3320020
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.18.1
	github.com/ovn-org/libovsdb v0.6.1-0.20220127023511-a619f0fd93be
	github.com/ovn-org/ovn-kubernetes/go-controller v0.0.0-20220201142617-e3ef6c090fd4
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.12.1
	github.com/submariner-io/admiral v0.12.0-m3
	github.com/submariner-io/shipyard v0.12.0-m3
	github.com/uw-labs/lichen v0.1.4
	github.com/vishvananda/netlink v1.1.1-0.20210518155637-4cb3795f2ccb
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20211215182854-7a385b3431de
	google.golang.org/protobuf v1.27.1
	k8s.io/api v0.22.1
	k8s.io/apimachinery v0.22.1
	k8s.io/client-go v1.5.2
	k8s.io/klog v1.0.0
	k8s.io/klog/v2 v2.20.0
	k8s.io/utils v0.0.0-20210707171843-4b05e18ac7d9
	sigs.k8s.io/controller-runtime v0.7.0
	sigs.k8s.io/mcs-api v0.1.0
)

// Pinned to kubernetes-1.19.10
replace (
	k8s.io/api => k8s.io/api v0.19.10
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.10
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.10
	k8s.io/client-go => k8s.io/client-go v0.19.10
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.19.10
)
