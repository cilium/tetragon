// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package caps

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/constants"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/namespace"
)

var (
	// Set default last capability based on upstream unix go library
	cap_last_cap = int32(constants.CAP_LAST_CAP)
	lastCapOnce  sync.Once
)

// GetLastCap() Returns unix.CAP_LAST_CAP unless the kernel
// defines another last cap which is the case for old kernels.
func GetLastCap() int32 {
	lastCapOnce.Do(func() {
		d, err := os.ReadFile(filepath.Join(option.Config.ProcFS, "/sys/kernel/cap_last_cap"))
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Could not read kernel cap_last_cap, using default '%d' as cap_last_cap", cap_last_cap)
		}
		val, err := strconv.ParseInt(strings.TrimRight(string(d), "\n"), 10, 32)
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Could not parse cap_last_cap, using default '%d' as cap_last_cap", cap_last_cap)
			return
		}
		// just silence some CodeQL
		if val >= 0 && val < constants.CAP_LAST_CAP {
			cap_last_cap = int32(val)
		}
	})
	return cap_last_cap
}

func isCapValid(capInt int32) bool {
	if capInt >= 0 && capInt <= constants.CAP_LAST_CAP {
		return true
	}

	return false
}

// AreSubset() Checks if "a" is a subset of "set"
// Rerturns true if all "a" capabilities are also in "set", otherwise
// false.
func AreSubset(a uint64, set uint64) bool {
	return (!((a & ^uint64(set)) != 0))
}

// capToMask() returns the mask of the corresponding u32
func capToMask(capability int32) uint32 {
	return uint32(1 << ((capability) & 31))
}

// GetCapsFullSet() Returns up to date (go unix library) full set.
func GetCapsFullSet() uint64 {
	// Get last u32 bits
	caps := uint64(capToMask(GetLastCap()+1)-1) << 32
	// Get first u32 bits
	caps |= uint64(^uint32(0))

	return caps
}

func GetCapability(capInt int32) (string, error) {
	if !isCapValid(capInt) {
		return "", fmt.Errorf("invalid capability value %d", capInt)
	}

	str, ok := capabilitiesString[uint64(capInt)]
	if !ok {
		return "", fmt.Errorf("could not map capability value %d", capInt)
	}

	return str, nil
}

func GetCapabilities(capInt uint64) string {
	var caps []string
	for i := uint64(0); i < 64; i++ {
		if (1<<i)&capInt != 0 {
			caps = append(caps, capabilitiesString[i])
		}
	}
	return strings.Join(caps, " ")
}

func GetCapabilitiesHex(capInt uint64) string {
	return fmt.Sprintf("%016x", capInt)
}

/* uapi/linux/capability.h */
var capabilitiesString = map[uint64]string{
	/* In a system with the [_POSIX_CHOWN_RESTRICTED] option defined, this
	   overrides the restriction of changing file ownership and group
	   ownership. */
	0: "CAP_CHOWN",
	/* Override all DAC access, including ACL execute access if
	   [_POSIX_ACL] is defined. Excluding DAC access covered by
	   CAP_LINUX_IMMUTABLE. */

	1: "DAC_OVERRIDE",

	/* Overrides all DAC restrictions regarding read and search on files
	   and directories, including ACL restrictions if [_POSIX_ACL] is
	   defined. Excluding DAC access covered by "$1"_LINUX_IMMUTABLE. */
	2: "CAP_DAC_READ_SEARCH",

	/* Overrides all restrictions about allowed operations on files, where
	   file owner ID must be equal to the user ID, except where CAP_FSETID
	   is applicable. It doesn't override MAC and DAC restrictions. */

	3: "CAP_FOWNER",

	/* Overrides the following restrictions that the effective user ID
	   shall match the file owner ID when setting the S_ISUID and S_ISGID
	   bits on that file; that the effective group ID (or one of the
	   supplementary group IDs) shall match the file owner ID when setting
	   the S_ISGID bit on that file; that the S_ISUID and S_ISGID bits are
	   cleared on successful return from chown(2) (not implemented). */

	4: "CAP_FSETID",

	/* Overrides the restriction that the real or effective user ID of a
	   process sending a signal must match the real or effective user ID
	   of the process receiving the signal. */

	5: "CAP_KILL",

	/* Allows setgid(2) manipulation */
	/* Allows setgroups(2) */
	/* Allows forged gids on socket credentials passing. */

	6: "CAP_SETGID",

	/* Allows set*uid(2) manipulation (including fsuid). */
	/* Allows forged pids on socket credentials passing. */

	7: "CAP_SETUID",

	/**
	 ** Linux-specific capabilities
	 **/

	/* Without VFS support for capabilities:
	 *   Transfer any capability in your permitted set to any pid,
	 *   remove any capability in your permitted set from any pid
	 * With VFS support for capabilities (neither of above, but)
	 *   Add any capability from current's capability bounding set
	 *       to the current process' inheritable set
	 *   Allow taking bits out of capability bounding set
	 *   Allow modification of the securebits for a process
	 */

	8: "CAP_SETPCAP",

	/* Allow modification of S_IMMUTABLE and S_APPEND file attributes */

	9: "CAP_LINUX_IMMUTABLE",

	/* Allows binding to TCP/UDP sockets below 1024 */
	/* Allows binding to ATM VCIs below 32 */

	10: "CAP_NET_BIND_SERVICE",

	/* Allow broadcasting, listen to multicast */

	11: "CAP_NET_BROADCAST",

	/* Allow interface configuration */
	/* Allow administration of IP firewall, masquerading and accounting */
	/* Allow setting debug option on sockets */
	/* Allow modification of routing tables */
	/* Allow setting arbitrary process / process group ownership on
	   sockets */
	/* Allow binding to any address for transparent proxying (also via NET_RAW) */
	/* Allow setting TOS (type of service) */
	/* Allow setting promiscuous mode */
	/* Allow clearing driver statistics */
	/* Allow multicasting */
	/* Allow read/write of device-specific registers */
	/* Allow activation of ATM control sockets */

	12: "CAP_NET_ADMIN",

	/* Allow use of RAW sockets */
	/* Allow use of PACKET sockets */
	/* Allow binding to any address for transparent proxying (also via NET_ADMIN) */

	13: "CAP_NET_RAW",

	/* Allow locking of shared memory segments */
	/* Allow mlock and mlockall (which doesn't really have anything to do
	   with IPC) */

	14: "CAP_IPC_LOCK",

	/* Override IPC ownership checks */

	15: "CAP_IPC_OWNER",

	/* Insert and remove kernel modules - modify kernel without limit */
	16: "CAP_SYS_MODULE",

	/* Allow ioperm/iopl access */
	/* Allow sending USB messages to any device via /dev/bus/usb */

	17: "CAP_SYS_RAWIO",

	/* Allow use of chroot() */

	18: "CAP_SYS_CHROOT",

	/* Allow ptrace() of any process */

	19: "CAP_SYS_PTRACE",
	/* Allow configuration of process accounting */

	20: "CAP_SYS_PACCT",

	/* Allow configuration of the secure attention key */
	/* Allow administration of the random device */
	/* Allow examination and configuration of disk quotas */
	/* Allow setting the domainname */
	/* Allow setting the hostname */
	/* Allow calling bdflush() */
	/* Allow mount() and umount(), setting up new smb connection */
	/* Allow some autofs root ioctls */
	/* Allow nfsservctl */
	/* Allow VM86_REQUEST_IRQ */
	/* Allow to read/write pci config on alpha */
	/* Allow irix_prctl on mips (setstacksize) */
	/* Allow flushing all cache on m68k (sys_cacheflush) */
	/* Allow removing semaphores */
	/* Used instead of CAP_CHOWN to "chown" IPC message queues, semaphores
	   and shared memory */
	/* Allow locking/unlocking of shared memory segment */
	/* Allow turning swap on/off */
	/* Allow forged pids on socket credentials passing */
	/* Allow setting readahead and flushing buffers on block devices */
	/* Allow setting geometry in floppy driver */
	/* Allow turning DMA on/off in xd driver */
	/* Allow administration of md devices (mostly the above, but some
	   extra ioctls) */
	/* Allow tuning the ide driver */
	/* Allow access to the nvram device */
	/* Allow administration of apm_bios, serial and bttv (TV) device */
	/* Allow manufacturer commands in isdn CAPI support driver */
	/* Allow reading non-standardized portions of pci configuration space */
	/* Allow DDI debug ioctl on sbpcd driver */
	/* Allow setting up serial ports */
	/* Allow sending raw qic-117 commands */
	/* Allow enabling/disabling tagged queuing on SCSI controllers and sending
	   arbitrary SCSI commands */
	/* Allow setting encryption key on loopback filesystem */
	/* Allow setting zone reclaim policy */
	/* Allow everything under CAP_BPF and CAP_PERFMON for backward compatibility */

	21: "CAP_SYS_ADMIN",

	/* Allow use of reboot() */

	22: "CAP_SYS_BOOT",

	/* Allow raising priority and setting priority on other (different
	   UID) processes */
	/* Allow use of FIFO and round-robin (realtime) scheduling on own
	   processes and setting the scheduling algorithm used by another
	   process. */
	/* Allow setting cpu affinity on other processes */

	23: "CAP_SYS_NICE",

	/* Override resource limits. Set resource limits. */
	/* Override quota limits. */
	/* Override reserved space on ext2 filesystem */
	/* Modify data journaling mode on ext3 filesystem (uses journaling
	   resources) */
	/* NOTE: ext2 honors fsuid when checking for resource overrides, so
	   you can override using fsuid too */
	/* Override size restrictions on IPC message queues */
	/* Allow more than 64hz interrupts from the real-time clock */
	/* Override max number of consoles on console allocation */
	/* Override max number of keymaps */
	/* Control memory reclaim behavior */

	24: "CAP_SYS_RESOURCE",

	/* Allow manipulation of system clock */
	/* Allow irix_stime on mips */
	/* Allow setting the real-time clock */

	25: "CAP_SYS_TIME",

	/* Allow configuration of tty devices */
	/* Allow vhangup() of tty */

	26: "CAP_SYS_TTY_CONFIG",

	/* Allow the privileged aspects of mknod() */

	27: "CAP_MKNOD",

	/* Allow taking of leases on files */

	28: "CAP_LEASE",

	/* Allow writing the audit log via unicast netlink socket */

	29: "CAP_AUDIT_WRITE",

	/* Allow configuration of audit via unicast netlink socket */

	30: "CAP_AUDIT_CONTROL",

	/* Set or remove capabilities on files */

	31: "CAP_SETFCAP",

	/* Override MAC access.
	   The base kernel enforces no MAC policy.
	   An LSM may enforce a MAC policy, and if it does and it chooses
	   to implement capability based overrides of that policy, this is
	   the capability it should use to do so. */

	32: "CAP_MAC_OVERRIDE",

	/* Allow MAC configuration or state changes.
	   The base kernel requires no MAC configuration.
	   An LSM may enforce a MAC policy, and if it does and it chooses
	   to implement capability based checks on modifications to that
	   policy or the data required to maintain it, this is the
	   capability it should use to do so. */

	33: "CAP_MAC_ADMIN",

	/* Allow configuring the kernel's syslog (printk behaviour) */

	34: "CAP_SYSLOG",

	/* Allow triggering something that will wake the system */

	35: "CAP_WAKE_ALARM",

	/* Allow preventing system suspends */

	36: "CAP_BLOCK_SUSPEND",

	/* Allow reading the audit log via multicast netlink socket */

	37: "CAP_AUDIT_READ",

	/*
	 * Allow system performance and observability privileged operations
	 * using perf_events, i915_perf and other kernel subsystems
	 */

	38: "CAP_PERFMON",

	/*
	 * CAP_BPF allows the following BPF operations:
	 * - Creating all types of BPF maps
	 * - Advanced verifier features
	 *   - Indirect variable access
	 *   - Bounded loops
	 *   - BPF to BPF function calls
	 *   - Scalar precision tracking
	 *   - Larger complexity limits
	 *   - Dead code elimination
	 *   - And potentially other features
	 * - Loading BPF Type Format (BTF) data
	 * - Retrieve xlated and JITed code of BPF programs
	 * - Use bpf_spin_lock() helper
	 *
	 * CAP_PERFMON relaxes the verifier checks further:
	 * - BPF progs can use of pointer-to-integer conversions
	 * - speculation attack hardening measures are bypassed
	 * - bpf_probe_read to read arbitrary kernel memory is allowed
	 * - bpf_trace_printk to print kernel memory is allowed
	 *
	 * CAP_SYS_ADMIN is required to use bpf_probe_write_user.
	 *
	 * CAP_SYS_ADMIN is required to iterate system wide loaded
	 * programs, maps, links, BTFs and convert their IDs to file descriptors.
	 *
	 * CAP_PERFMON and CAP_BPF are required to load tracing programs.
	 * CAP_NET_ADMIN and CAP_BPF are required to load networking programs.
	 */
	39: "CAP_BPF",

	/* Allow checkpoint/restore related operations */
	/* Allow PID selection during clone3() */
	/* Allow writing to ns_last_pid */

	40: "CAP_CHECKPOINT_RESTORE",
}

func GetPIDCaps(filename string) (uint32, uint64, uint64, uint64) {
	pid := uint32(0)
	permitted := uint64(0)
	effective := uint64(0)
	inheritable := uint64(0)

	getValue64Hex := func(line string) (uint64, error) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("Fields to few arguments")
		}
		pidField := fields[len(fields)-1]
		pid, err := strconv.ParseUint(pidField, 16, 64)
		return pid, err
	}

	getValue32Int := func(line string) (uint32, error) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("Fields to few arguments")
		}
		pidField := fields[len(fields)-1]
		pid, err := strconv.ParseUint(pidField, 10, 32)
		return uint32(pid), err
	}

	file, err := os.ReadFile(filename)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("ReadFile failed: %s", filename)
		return 0, 0, 0, 0
	}
	statuslines := strings.Split(string(file), "\n")
	for _, line := range statuslines {
		err = nil
		if strings.Contains(line, "NStgid:") {
			pid, err = getValue32Int(line)
		}
		if strings.Contains(line, "CapPrm:") {
			permitted, err = getValue64Hex(line)
		}
		if strings.Contains(line, "CapEff:") {
			effective, err = getValue64Hex(line)
		}
		if strings.Contains(line, "CapInh:") {
			inheritable, err = getValue64Hex(line)
		}
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("ReadFile (%s) error: %s", line, filename)
		}
	}
	return pid, permitted, effective, inheritable
}

func GetCapabilitiesTypes(capInt uint64) []tetragon.CapabilitiesType {
	var caps []tetragon.CapabilitiesType
	for i := uint64(0); i < 64; i++ {
		if (1<<i)&capInt != 0 {
			e := tetragon.CapabilitiesType(i)
			caps = append(caps, e)
		}
	}
	return caps
}

func GetMsgCapabilities(caps processapi.MsgCapabilities) *tetragon.Capabilities {
	return &tetragon.Capabilities{
		Permitted:   GetCapabilitiesTypes(caps.Permitted),
		Effective:   GetCapabilitiesTypes(caps.Effective),
		Inheritable: GetCapabilitiesTypes(caps.Inheritable),
	}
}

func GetCurrentCapabilities() *tetragon.Capabilities {
	pidStr := strconv.Itoa(int(namespace.GetMyPidG()))
	procCaps := filepath.Join(option.Config.ProcFS, pidStr, "status")
	_, permitted, effective, inheritable := GetPIDCaps(procCaps)

	return &tetragon.Capabilities{
		Permitted:   GetCapabilitiesTypes(permitted),
		Effective:   GetCapabilitiesTypes(effective),
		Inheritable: GetCapabilitiesTypes(inheritable),
	}
}

func GetSecureBitsTypes(secBit uint32) []tetragon.SecureBitsType {
	if secBit == 0 {
		return nil
	}

	var bits []tetragon.SecureBitsType

	if secBit&uint32(tetragon.SecureBitsType_SecBitNoRoot) != 0 {
		bits = append(bits, tetragon.SecureBitsType_SecBitNoRoot)
	}

	if secBit&uint32(tetragon.SecureBitsType_SecBitNoRootLocked) != 0 {
		bits = append(bits, tetragon.SecureBitsType_SecBitNoRootLocked)
	}

	if secBit&uint32(tetragon.SecureBitsType_SecBitNoSetUidFixup) != 0 {
		bits = append(bits, tetragon.SecureBitsType_SecBitNoSetUidFixup)
	}

	if secBit&uint32(tetragon.SecureBitsType_SecBitNoSetUidFixupLocked) != 0 {
		bits = append(bits, tetragon.SecureBitsType_SecBitNoSetUidFixupLocked)
	}

	if secBit&uint32(tetragon.SecureBitsType_SecBitKeepCaps) != 0 {
		bits = append(bits, tetragon.SecureBitsType_SecBitKeepCaps)
	}

	if secBit&uint32(tetragon.SecureBitsType_SecBitKeepCapsLocked) != 0 {
		bits = append(bits, tetragon.SecureBitsType_SecBitKeepCapsLocked)
	}

	if secBit&uint32(tetragon.SecureBitsType_SecBitNoCapAmbientRaise) != 0 {
		bits = append(bits, tetragon.SecureBitsType_SecBitNoCapAmbientRaise)
	}

	if secBit&uint32(tetragon.SecureBitsType_SecBitNoCapAmbientRaiseLocked) != 0 {
		bits = append(bits, tetragon.SecureBitsType_SecBitNoCapAmbientRaiseLocked)
	}

	return bits
}

func GetPrivilegesChangedReasons(reasons uint32) []tetragon.ProcessPrivilegesChanged {
	if reasons == 0 {
		return nil
	}

	var bits []tetragon.ProcessPrivilegesChanged

	if reasons&uint32(processapi.ExecveFileCaps) != 0 {
		bits = append(bits, tetragon.ProcessPrivilegesChanged_PRIVILEGES_RAISED_EXEC_FILE_CAP)
	}

	if reasons&uint32(processapi.ExecveSetuidRoot) != 0 {
		bits = append(bits, tetragon.ProcessPrivilegesChanged_PRIVILEGES_RAISED_EXEC_FILE_SETUID)
	}

	if reasons&uint32(processapi.ExecveSetgidRoot) != 0 {
		bits = append(bits, tetragon.ProcessPrivilegesChanged_PRIVILEGES_RAISED_EXEC_FILE_SETGID)
	}

	if len(bits) > 0 {
		return bits
	}

	return nil
}
