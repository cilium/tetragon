// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procevents

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProcsContainerIdOffset(t *testing.T) {
	test1 := "123456789abcdef"
	offsetValue := 7
	test2 := "docker-123456789abcdef"

	test3 := "cri-containerd-123456789abcdef"
	offsetValue3 := 15

	s, i := ProcsContainerIdOffset(test1)
	assert.Equal(t, s, test1, "Expect input == output")
	assert.Equal(t, i, 0, "Expect zero offset")

	s, i = ProcsContainerIdOffset(test2)
	assert.Equal(t, test1, s, "Expect output is test1")
	assert.Equal(t, offsetValue, i, "Expect docker- offset")

	s, i = ProcsContainerIdOffset(test3)
	assert.Equal(t, test1, s, "Expect output is test3")
	assert.Equal(t, offsetValue3, i, "Expect docker- offset")

	s, i = ProcsContainerIdOffset("")
	assert.Equal(t, s, "", "Expect output '' empty string")
	assert.Equal(t, i, 0, "Expect ContainerId offset should be zero")
}

func TestProcsContainerId(t *testing.T) {
	myPid := uint32(os.Getpid())

	s, e := procsDockerId(myPid)
	// This is not in a docker-cgroup so we have no info
	assert.Equal(t, "", s, "No cgroup info here")
	assert.NoError(t, e)

	// To further test we need a k8s environment unforunately. TBD
}

func TestProcsFindContainerId(t *testing.T) {
	p := "6:pids:/kubepods/besteffort/pod26ab26cd-6409-443f-a13c-fd6c231207c8/ae7a1981e064c217035e0b23979c8defd51c850d1af26fbcf148187e5b0da61c"
	d, i := procsFindDockerId(p)
	assert.Equal(t, i, 0, "ContainerId offset wrong")
	assert.Equal(t, d, "ae7a1981e064c217035e0b23979c8de", "ContainerId wrong")

	p = "4:pids:/kubepods/burstable/pod1399d9c7-c86f-4371-8568-07b3d32258a4/91f2457fb4c2b1356eefc7bace36532f5eb3d354804bb2cff787ea321320b5a5"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 0, "ContainerId offset wrong")
	assert.Equal(t, d, "91f2457fb4c2b1356eefc7bace36532", "ContainerId wrong")

	p = "4:pids:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podeb052b63_ea96_4728_ab4a_64ab3babccd7.slice/cri-containerd-5694f82f44168cc048e014ae14d1b0c8ef673bec49f329dc169911ea638f63c2.scope"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 15, "ContainerId offset wrong")
	assert.Equal(t, d, "5694f82f44168cc048e014ae14d1b0c", "ContainerId wrong")

	p = "4:pids:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podeb052b63_ea96_4728_ab4a_64ab3babccd7.slice/docker-5694f82f44168cc048e014ae14d1b0c8ef673bec49f329dc169911ea638f63c2.scope"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 7, "ContainerId offset wrong")
	assert.Equal(t, d, "5694f82f44168cc048e014ae14d1b0c", "ContainerId wrong")

	// A docker container directly using systemd driver as a cgroup driver
	p = "0::/system.slice/docker-ee40841f79d52f66f4958c8a484bd2dfb453228874dcca1a3f2ec6e8420ec87c.scope"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 7, "ContainerId offset wrong")
	assert.Equal(t, d, "ee40841f79d52f66f4958c8a484bd2d", "ContainerId wrong")

	// A docker container using cgroupfs driver
	p = "0::/docker/5aaf9eb7648eeb1459d86eaa0ace8bcfa93089642e5c3113a14250dae3238aaf"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 0, "ContainerId offset wrong")
	assert.Equal(t, d, "5aaf9eb7648eeb1459d86eaa0ace8bc", "ContainerId wrong")

	// Podman directly using systemd driver as a cgroup manager under a user slice
	p = "0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-6fb480da903b96185cd497db694641d13534e2b80cf4cb738b6691677146adea.scope/container"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 7, "ContainerId offset wrong")
	assert.Equal(t, d, "6fb480da903b96185cd497db694641d", "ContainerId wrong")

	// Podman container directly using systemd driver as a cgroup manager under root
	p = "0::/machine.slice/libpod-89e89703fbd1e88b72d279d951ce389d3742874205196d73f96e0dcbc0da0659.scope/container"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 7, "ContainerId offset wrong")
	assert.Equal(t, d, "89e89703fbd1e88b72d279d951ce389", "ContainerId wrong")

	// Podman container directly using --cgroup-manager cgroupfs under root
	p = "0::/libpod_parent/libpod-01f3c60cfaadbb51e4d5947dd2ef0480d53551cbcee8f3ada8c3723b2bf03bf4"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 7, "ContainerId offset wrong")
	assert.Equal(t, d, "01f3c60cfaadbb51e4d5947dd2ef048", "ContainerId wrong")

	// Podman directly using --cgroup-manager cgroupfs under root, this is the container monitor
	p = "0::/libpod_parent/conmon"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 0, "ContainerId offset wrong should be zero")
	assert.Equal(t, d, "", "ContainerId wrong should return empty")

	// Minikube with docker container and --extra-config=kubelet.cgroup-driver=systemd
	p = "0::/system.slice/docker-1b3319ed9c1d4cca681f9c102da9b015555785b6240c4e4619f11b535cabdc07.scope/init.scope"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 0, "ContainerId offset wrong should be zero")
	assert.Equal(t, d, "", "ContainerId wrong should return empty")

	p = "0::/system.slice/docker-1b3319ed9c1d4cca681f9c102da9b015555785b6240c4e4619f11b535cabdc07.scope/system.slice/containerd.service"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 0, "ContainerId offset wrong should be zero")
	assert.Equal(t, d, "", "ContainerId wrong should return empty")

	p = "0::/system.slice/docker-1b3319ed9c1d4cca681f9c102da9b015555785b6240c4e4619f11b535cabdc07.scope/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podeb653d22_2525_47ca_9fc4_3762497ae1d2.slice/docker-84e9ffffe97fea4c5a0f01d401611cbafbf7e559fc6190ed74abfc2b25e889d4.scope"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 7, "ContainerId offset wrong")
	assert.Equal(t, d, "84e9ffffe97fea4c5a0f01d401611cb", "ContainerId wrong")

	p = "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podeb653d22_2525_47ca_9fc4_3762497ae1d2.slice/docker-84e9ffffe97fea4c5a0f01d401611cbafbf7e559fc6190ed74abfc2b25e889d4.scope"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 7, "ContainerId offset wrong")
	assert.Equal(t, d, "84e9ffffe97fea4c5a0f01d401611cb", "ContainerId wrong")

	// Minikube with containerd runtime and cgroupfs
	p = "0::/system.slice/docker-94acc75af8cf9c56e10676b0760ed424bec95dadc91f68f6564014686930200e.scope/kubepods/besteffort/pod13cb8437-00ed-40e4-99d8-e17193a58086/a5a6a3af5d51ad95b915ca948710b90a94abc279e84963b9d22a39f342ce67d9"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 0, "ContainerId offset wrong")
	assert.Equal(t, d, "a5a6a3af5d51ad95b915ca948710b90", "ContainerId wrong")

	p = "0::/kubepods/besteffort/pod13cb8437-00ed-40e4-99d8-e17193a58086/a5a6a3af5d51ad95b915ca948710b90a94abc279e84963b9d22a39f342ce67d9"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 0, "ContainerId offset wrong")
	assert.Equal(t, d, "a5a6a3af5d51ad95b915ca948710b90", "ContainerId wrong")

	// Kind: containerd service under a system slice which is under a docker container that is using systemd as cgroup manager
	p = "0::/system.slice/docker-c1146e7ccca9ab4436abd69923c07d097b37b762ed21cc3f24584c2f84e77c57.scope/system.slice/containerd.service"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 0, "ContainerId offset wrong should be zero")
	assert.Equal(t, d, "", "ContainerId wrong should be empty")

	// Kind: kubelet under a system slice which is under a docker container that is using systemd as cgroup manager
	p = "0::/system.slice/docker-c1146e7ccca9ab4436abd69923c07d097b37b762ed21cc3f24584c2f84e77c57.scope/system.slice/kubelet.service"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 0, "ContainerId offset wrong should be zero")
	assert.Equal(t, d, "", "ContainerId wrong should be empty")

	// Kind with a cgroup driver cgroupfs under /kubelet/ path
	p = "0::/system.slice/docker-c1146e7ccca9ab4436abd69923c07d097b37b762ed21cc3f24584c2f84e77c57.scope/kubelet/kubepods/burstable/pod09a70ae9ccc491e651e5c773579b3490/b0e6aa50e847c3d3b1880e307ec7996040275c8063832cffc9274defce2cb655"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 0, "ContainerId offset wrong")
	assert.Equal(t, d, "b0e6aa50e847c3d3b1880e307ec7996", "ContainerId wrong")

	// Kind with a cgroup driver cgroupfs under /kubelet/ path
	p = "0::/system.slice/docker-c1146e7ccca9ab4436abd69923c07d097b37b762ed21cc3f24584c2f84e77c57.scope/kubelet/kubepods/pod55db13a1-c151-4cdd-a48b-e002a2b1fb58/21e677e6fe95215ea48bcb5609c10e67ba8e76a7a3ea749af704e72260eb93fe"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 0, "ContainerId offset wrong")
	assert.Equal(t, d, "21e677e6fe95215ea48bcb5609c10e6", "ContainerId wrong")

	// Cgroupv1 Hierarchy with CgroupPath set
	p = "4:pids:/podruntime.slice/containerd.service/kubepods-burstable-pod29349498_197c_4919_b13f_9a928e7d001b.slice:cri-containerd:0ca2b3cd20e5f55a2bbe8d4aa3f811cf7963b40f0542ad147054b0fcb60fc400"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 80, "ContainerId offset wrong")
	assert.Equal(t, d, "0ca2b3cd20e5f55a2bbe8d4aa3f811c", "ContainerId wrong")

	p = "11:pids:/actions_job/ec5fd62ba68d0b75a3cbdb7f7f78b526440b7969e22b2b362fb6f429ded42fdc"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 20, "ContainerId offset wrong")
	assert.Equal(t, d, "ec5fd62ba68d0b75a3cbdb7f7f78b52", "ContainerId wrong")

	p = ""
	d, i = procsFindDockerId(p)
	assert.Equal(t, d, "", "Expect output '' empty string")
	assert.Equal(t, i, 0, "Expect ContainerId offset should be zero")
}
