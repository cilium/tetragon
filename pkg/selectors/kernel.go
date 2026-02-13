// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package selectors

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/config"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/mbset"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/network"
)

const (
	ActionTypeInvalid                     = -1
	ActionTypePost                        = 0
	ActionTypeFollowFd                    = 1
	ActionTypeSigKill                     = 2
	ActionTypeUnfollowFd                  = 3
	ActionTypeOverride                    = 4
	ActionTypeCopyFd                      = 5
	ActionTypeGetUrl                      = 6
	ActionTypeDnsLookup                   = 7
	ActionTypeNoPost                      = 8
	ActionTypeSignal                      = 9
	ActionTypeTrackSock                   = 10
	ActionTypeUntrackSock                 = 11
	ActionTypeNotifyEnforcer              = 12
	ActionTypeCleanupEnforcerNotification = 13
	ActionTypeSet                         = 14
)

var actionTypeTable = map[string]uint32{
	"post":                        ActionTypePost,
	"followfd":                    ActionTypeFollowFd,
	"unfollowfd":                  ActionTypeUnfollowFd,
	"sigkill":                     ActionTypeSigKill,
	"override":                    ActionTypeOverride,
	"copyfd":                      ActionTypeCopyFd,
	"geturl":                      ActionTypeGetUrl,
	"dnslookup":                   ActionTypeDnsLookup,
	"nopost":                      ActionTypeNoPost,
	"signal":                      ActionTypeSignal,
	"tracksock":                   ActionTypeTrackSock,
	"untracksock":                 ActionTypeUntrackSock,
	"notifyenforcer":              ActionTypeNotifyEnforcer,
	"cleanupenforcernotification": ActionTypeCleanupEnforcerNotification,
	"set":                         ActionTypeSet,
}

var actionTypeStringTable = map[uint32]string{
	ActionTypePost:                        "post",
	ActionTypeFollowFd:                    "followfd",
	ActionTypeUnfollowFd:                  "unfollowfd",
	ActionTypeSigKill:                     "sigkill",
	ActionTypeOverride:                    "override",
	ActionTypeCopyFd:                      "copyfd",
	ActionTypeGetUrl:                      "geturl",
	ActionTypeDnsLookup:                   "dnslookup",
	ActionTypeNoPost:                      "nopost",
	ActionTypeSignal:                      "signal",
	ActionTypeTrackSock:                   "tracksock",
	ActionTypeUntrackSock:                 "untracksock",
	ActionTypeCleanupEnforcerNotification: "cleanupenforcernotification",
	ActionTypeSet:                         "set",
}

const (
	ActionRateLimitScopeThread = iota
	ActionRateLimitScopeProcess
	ActionRateLimitScopeGlobal
)

var actionRateLimitScope = map[string]uint32{
	"thread":  ActionRateLimitScopeThread,
	"process": ActionRateLimitScopeProcess,
	"global":  ActionRateLimitScopeGlobal,
}

// Action argument table entry (for URL and FQDN arguments)
type ActionArgEntry struct {
	arg     string
	tableId idtable.EntryID
}

func (g *ActionArgEntry) SetID(id idtable.EntryID) {
	g.tableId = id
}

func (g *ActionArgEntry) GetArg() string {
	return g.arg
}

func MatchActionSigKill(spec any) bool {
	var sels []v1alpha1.KProbeSelector
	switch s := spec.(type) {
	case *v1alpha1.KProbeSpec:
		sels = s.Selectors
	case *v1alpha1.TracepointSpec:
		sels = s.Selectors
	default:
		return false
	}

	for _, s := range sels {
		for _, act := range s.MatchActions {
			if strings.ToLower(act.Action) == actionTypeStringTable[ActionTypeSigKill] {
				return true
			}
		}
	}
	return false
}

const (
	namespaceTypeUts             = 0
	namespaceTypeIpc             = 1
	namespaceTypeMnt             = 2
	namespaceTypePid             = 3
	namespaceTypePidForChildren  = 4
	namespaceTypeNet             = 5
	namespaceTypeTime            = 6
	namespaceTypeTimeForChildren = 7
	namespaceTypeCgroup          = 8
	namespaceTypeUser            = 9
)

var namespaceTypeTable = map[string]uint32{
	"uts":             namespaceTypeUts,
	"ipc":             namespaceTypeIpc,
	"mnt":             namespaceTypeMnt,
	"pid":             namespaceTypePid,
	"pidforchildren":  namespaceTypePidForChildren,
	"net":             namespaceTypeNet,
	"time":            namespaceTypeTime,
	"timeforchildren": namespaceTypeTimeForChildren,
	"cgroup":          namespaceTypeCgroup,
	"user":            namespaceTypeUser,
}

const (
	capsPermitted   = 0
	capsEffective   = 1
	capsInheritable = 2
)

var capabilitiesTypeTable = map[string]uint32{
	"effective":   capsEffective,
	"inheritable": capsInheritable,
	"permitted":   capsPermitted,
}

const (
	SelectorOpGT  = 1
	SelectorOpLT  = 2
	SelectorOpEQ  = 3
	SelectorOpNEQ = 4
	// Pid and Namespace ops
	SelectorOpIn    = 5
	SelectorOpNotIn = 6
	// String ops
	SelectorOpPrefix  = 8
	SelectorOpPostfix = 9
	// Map ops
	SelectorInMap    = 10
	SelectorNotInMap = 11

	SelectorOpMASK = 12

	// socket ops
	SelectorOpSaddr        = 13
	SelectorOpDaddr        = 14
	SelectorOpSport        = 15
	SelectorOpDport        = 16
	SelectorOpProtocol     = 17
	SelectorOpNotSport     = 18
	SelectorOpNotDport     = 19
	SelectorOpSportPriv    = 20
	SelectorOpNotSportPriv = 21
	SelectorOpDportPriv    = 22
	SelectorOpNotDportPriv = 23
	SelectorOpNotSaddr     = 24
	SelectorOpNotDaddr     = 25
	// file ops
	SelectorOpNotPrefix  = 26
	SelectorOpNotPostfix = 27
	// more socket ops
	SelectorOpFamily = 28
	SelectorOpState  = 29
	// capabilities
	SelectorOpCapabilitiesGained = 30
	// range
	SelectorOpInRange    = 31
	SelectorOpNotInRange = 32
	// match string
	SelectorOpSubString        = 33
	SelectorOpSubStringIgnCase = 34
	// file type
	SelectorOpFileType    = 35
	SelectorOpNotFileType = 36
)

var selectorOpStringTable = map[uint32]string{
	SelectorOpGT:                 "gt",
	SelectorOpLT:                 "lt",
	SelectorOpEQ:                 "Equal",
	SelectorOpNEQ:                "NotEqual",
	SelectorOpIn:                 "In",
	SelectorOpNotIn:              "NotIn",
	SelectorOpPrefix:             "Prefix",
	SelectorOpPostfix:            "Postfix",
	SelectorInMap:                "InMap",
	SelectorNotInMap:             "NotInMap",
	SelectorOpMASK:               "Mask",
	SelectorOpSaddr:              "SAddr",
	SelectorOpDaddr:              "DAddr",
	SelectorOpSport:              "SPort",
	SelectorOpDport:              "DPort",
	SelectorOpProtocol:           "Protocol",
	SelectorOpNotSport:           "NotSPort",
	SelectorOpNotDport:           "NotDPort",
	SelectorOpSportPriv:          "SPortPriv",
	SelectorOpNotSportPriv:       "NotSPortPriv",
	SelectorOpDportPriv:          "DPortPriv",
	SelectorOpNotDportPriv:       "NotDPortPriv",
	SelectorOpNotSaddr:           "NotSAddr",
	SelectorOpNotDaddr:           "NotDAddr",
	SelectorOpNotPrefix:          "NotPrefix",
	SelectorOpNotPostfix:         "NotPostfix",
	SelectorOpFamily:             "Family",
	SelectorOpState:              "State",
	SelectorOpCapabilitiesGained: "CapabilitiesGained",
	SelectorOpInRange:            "InRange",
	SelectorOpNotInRange:         "NotInRange",
	SelectorOpSubString:          "SubString",
	SelectorOpSubStringIgnCase:   "SubStringIgnCase",
	SelectorOpFileType:           "FileType",
	SelectorOpNotFileType:        "NotFileType",
}

func SelectorOp(op string) (uint32, error) {
	switch op {
	case "gt", "GT", "GreaterThan":
		return SelectorOpGT, nil
	case "lt", "LT", "LessThan":
		return SelectorOpLT, nil
	case "eq", "Equal":
		return SelectorOpEQ, nil
	case "neq", "NotEqual":
		return SelectorOpNEQ, nil
	case "In":
		return SelectorOpIn, nil
	case "NotIn":
		return SelectorOpNotIn, nil
	case "prefix", "Prefix":
		return SelectorOpPrefix, nil
	case "notprefix", "NotPrefix":
		return SelectorOpNotPrefix, nil
	case "postfix", "Postfix":
		return SelectorOpPostfix, nil
	case "notpostfix", "NotPostfix":
		return SelectorOpNotPostfix, nil
	case "InMap":
		return SelectorInMap, nil
	case "NotInMap":
		return SelectorNotInMap, nil
	case "mask", "Mask":
		return SelectorOpMASK, nil
	case "saddr", "Saddr", "SAddr":
		return SelectorOpSaddr, nil
	case "daddr", "Daddr", "DAddr":
		return SelectorOpDaddr, nil
	case "notsaddr", "NotSaddr", "NotSAddr":
		return SelectorOpNotSaddr, nil
	case "notdaddr", "NotDaddr", "NotDAddr":
		return SelectorOpNotDaddr, nil
	case "sport", "Sport", "SPort":
		return SelectorOpSport, nil
	case "dport", "Dport", "DPort":
		return SelectorOpDport, nil
	case "protocol", "Protocol":
		return SelectorOpProtocol, nil
	case "notsport", "NotSport", "NotSPort":
		return SelectorOpNotSport, nil
	case "notdport", "NotDport", "NotDPort":
		return SelectorOpNotDport, nil
	case "sportpriv", "SportPriv", "SPortPriv":
		return SelectorOpSportPriv, nil
	case "dportpriv", "DportPriv", "DPortPriv":
		return SelectorOpDportPriv, nil
	case "notsportpriv", "NotSportPriv", "NotSPortPriv":
		return SelectorOpNotSportPriv, nil
	case "notdportpriv", "NotDportPriv", "NotDPortPriv":
		return SelectorOpNotDportPriv, nil
	case "family", "Family":
		return SelectorOpFamily, nil
	case "state", "State":
		return SelectorOpState, nil
	case "CapabilitiesGained":
		return SelectorOpCapabilitiesGained, nil
	case "InRange":
		return SelectorOpInRange, nil
	case "NotInRange":
		return SelectorOpNotInRange, nil
	case "SubString":
		return SelectorOpSubString, nil
	case "SubStringIgnCase":
		return SelectorOpSubStringIgnCase, nil
	case "FileType":
		return SelectorOpFileType, nil
	case "NotFileType":
		return SelectorOpNotFileType, nil
	}

	return 0, fmt.Errorf("unknown op '%s'", op)
}

const (
	pidNamespacePid = 0x1
	pidFollowForks  = 0x2
)

func pidSelectorFlags(pid *v1alpha1.PIDSelector) uint32 {
	flags := uint32(0)

	if pid.IsNamespacePID {
		flags |= pidNamespacePid
	}
	if pid.FollowForks {
		flags |= pidFollowForks
	}
	return flags
}

func pidSelectorValue(pid *v1alpha1.PIDSelector) ([]byte, uint32) {
	b := make([]byte, len(pid.Values)*4)

	for i, v := range pid.Values {
		off := i * 4
		binary.LittleEndian.PutUint32(b[off:], v)
	}
	return b, uint32(len(b))
}

func ParseMatchPid(k *KernelSelectorState, pid *v1alpha1.PIDSelector) error {
	op, err := SelectorOp(pid.Operator)
	if err != nil {
		return fmt.Errorf("matchpid error: %w", err)
	}
	WriteSelectorUint32(&k.data, op)

	flags := pidSelectorFlags(pid)
	WriteSelectorUint32(&k.data, flags)

	value, size := pidSelectorValue(pid)
	WriteSelectorUint32(&k.data, size/4)
	WriteSelectorByteArray(&k.data, value, size)
	return nil
}

func ParseMatchPids(k *KernelSelectorState, matchPids []v1alpha1.PIDSelector) error {
	loff := AdvanceSelectorLength(&k.data)
	for _, p := range matchPids {
		if err := ParseMatchPid(k, &p); err != nil {
			return err
		}
	}
	WriteSelectorLength(&k.data, loff)
	return nil
}

func ActionTypeFromString(action string) int32 {
	act, ok := actionTypeTable[strings.ToLower(action)]
	if !ok {
		return ActionTypeInvalid
	}
	return int32(act)
}

func writeRangeInMap(v string, ty uint32, op uint32, m *ValueMap) error {
	// We store the start and end of the range as uint64s for unsigned values, and as int64s
	// for signed values. This is to allow both a signed range from -5 to 5, and also an
	// unsigned range where at least limit exceeds max(int64). If we only stored the range
	// limits as uint64s, then the range from -5 to 5 would be interpretted as being from
	// 5 to uint64(-5), which is the literal opposite of what was intended. If we only stored
	// the range as int64s, then we couldn't correctly accommodate values that exceed max(int64),
	// for similar reasons.
	var uRangeVal [2]uint64
	var sRangeVal [2]int64
	rangeStr := strings.Split(v, ":")
	if len(rangeStr) > 2 {
		return fmt.Errorf("MatchArgs value %s invalid: range should be 'min:max'", v)
	} else if len(rangeStr) == 1 {
		// If only one value in the string, e.g. "5", then add it a second time to simulate
		// a range that starts and ends with itself, e.g. as if "5:5" had been specified.
		rangeStr = append(rangeStr, rangeStr[0])

		// Special actions for particular network ops
		switch op {
		case SelectorOpProtocol:
			protocol, err := network.InetProtocolNumber(v)
			if err == nil {
				protocolStr := strconv.FormatUint(uint64(protocol), 10)
				rangeStr = []string{protocolStr, protocolStr}
			}
		case SelectorOpFamily:
			family, err := network.InetFamilyNumber(v)
			if err == nil {
				familyStr := strconv.FormatUint(uint64(family), 10)
				rangeStr = []string{familyStr, familyStr}
			}
		case SelectorOpState:
			state, err := network.TcpStateNumber(v)
			if err == nil {
				stateStr := strconv.FormatUint(uint64(state), 10)
				rangeStr = []string{stateStr, stateStr}
			}
		}
	}
	for idx := range 2 {
		switch ty {
		case gt.GenericIntType, gt.GenericS64Type, gt.GenericS32Type, gt.GenericS16Type, gt.GenericS8Type, gt.GenericSyscall64, gt.GenericSizeType:
			i, err := strconv.ParseInt(rangeStr[idx], 10, 64)
			if err != nil {
				return fmt.Errorf("MatchArgs value %s invalid: %w", v, err)
			}
			sRangeVal[idx] = i

		case gt.GenericU64Type, gt.GenericU32Type, gt.GenericU16Type, gt.GenericU8Type:
			i, err := strconv.ParseUint(rangeStr[idx], 10, 64)
			if err != nil {
				return fmt.Errorf("MatchArgs value %s invalid: %w", v, err)
			}
			uRangeVal[idx] = i
		default:
			return fmt.Errorf("unknown type: %d", ty)
		}
	}
	switch ty {
	case gt.GenericIntType, gt.GenericS64Type, gt.GenericS32Type, gt.GenericS16Type, gt.GenericS8Type, gt.GenericSyscall64, gt.GenericSizeType:
		if sRangeVal[0] > sRangeVal[1] {
			sRangeVal[0], sRangeVal[1] = sRangeVal[1], sRangeVal[0]
		}
		for val := sRangeVal[0]; val <= sRangeVal[1]; val++ {
			var valByte [8]byte
			binary.LittleEndian.PutUint64(valByte[:], uint64(val))
			m.Data[valByte] = struct{}{}
		}

	case gt.GenericU64Type, gt.GenericU32Type, gt.GenericU16Type, gt.GenericU8Type:
		if uRangeVal[0] > uRangeVal[1] {
			uRangeVal[0], uRangeVal[1] = uRangeVal[1], uRangeVal[0]
		}
		for val := uRangeVal[0]; val <= uRangeVal[1]; val++ {
			var valByte [8]byte
			binary.LittleEndian.PutUint64(valByte[:], val)
			m.Data[valByte] = struct{}{}
		}
	}
	return nil
}

func writeMatchRangesInMap(k *KernelSelectorState, values []string, ty uint32, op uint32) error {
	mid, m := k.newValueMap()
	for _, v := range values {
		err := writeRangeInMap(v, ty, op, &m)
		if err != nil {
			return err
		}
	}
	// write the map id into the selector
	WriteSelectorUint32(&k.data, mid)
	return nil
}

func writeListValuesInMap(k *KernelSelectorState, v string, ty uint32, m *ValueMap) error {
	if k.listReader == nil {
		return errors.New("failed list values loading is not supported")
	}
	values, err := k.listReader.Read(v, ty)
	if err != nil {
		return err
	}
	for idx := range values {
		var val [8]byte

		switch ty {
		case gt.GenericIntType, gt.GenericS64Type, gt.GenericS32Type, gt.GenericS16Type, gt.GenericS8Type, gt.GenericSyscall64, gt.GenericSizeType:
			binary.LittleEndian.PutUint64(val[:], uint64(values[idx]))
		case gt.GenericU64Type, gt.GenericU32Type, gt.GenericU16Type, gt.GenericU8Type:
			binary.LittleEndian.PutUint64(val[:], uint64(values[idx]))
		default:
			return fmt.Errorf("unknown type: %d", ty)
		}
		m.Data[val] = struct{}{}
	}
	return nil
}

func writeMatchValuesRange(k *KernelSelectorState, values []string, ty uint32) error {
	// NB: maxMatchValues should match MAX_MATCH_VALUES in bpf/process/types/basic.h
	maxMatchValues := 4

	if len(values) > maxMatchValues {
		return fmt.Errorf("selector does not support more than %d values", maxMatchValues)
	}

	for _, v := range values {
		rangeStr := strings.Split(v, ":")
		if len(rangeStr) != 2 {
			return fmt.Errorf("MatchArgs value %s invalid: range should be 'min:max'", v)
		}

		rangeMin, err := strconv.ParseInt(rangeStr[0], 0, 64)
		if err != nil {
			return fmt.Errorf("MatchArgs value %s invalid: %w", v, err)
		}

		rangeMax, err := strconv.ParseInt(rangeStr[1], 0, 64)
		if err != nil {
			return fmt.Errorf("MatchArgs value %s invalid: %w", v, err)
		}

		switch ty {
		case gt.GenericIntType, gt.GenericS32Type, gt.GenericSizeType, gt.GenericU32Type, gt.GenericU16Type, gt.GenericU8Type, gt.GenericS16Type, gt.GenericS8Type:
			if rangeMax > math.MaxUint32 || rangeMin > math.MaxUint32 {
				return fmt.Errorf("range out of range (%d:%d) allowed max %d", rangeMin, rangeMax, math.MaxUint32)
			}
			WriteSelectorUint32(&k.data, uint32(rangeMin))
			WriteSelectorUint32(&k.data, uint32(rangeMax))

		case gt.GenericS64Type, gt.GenericSyscall64, gt.GenericU64Type:
			WriteSelectorUint64(&k.data, uint64(rangeMin))
			WriteSelectorUint64(&k.data, uint64(rangeMax))

		default:
			return fmt.Errorf("MatchArgs type %s unsupported for range operators", gt.GenericTypeString(int(ty)))
		}
	}
	return nil
}

func writeMatchValuesInMap(k *KernelSelectorState, values []string, ty uint32, op uint32) error {
	mid, m := k.newValueMap()
	for _, v := range values {
		var val [8]byte

		if strings.HasPrefix(v, "list:") {
			err := writeListValuesInMap(k, v[len("list:"):], ty, &m)
			if err != nil {
				return err
			}
			continue
		}
		// if not list, most likely port range
		if strings.Contains(v, ":") {
			err := writeRangeInMap(v, ty, op, &m)
			if err != nil {
				return err
			}
			continue
		}
		switch ty {
		case gt.GenericIntType, gt.GenericS64Type, gt.GenericS32Type, gt.GenericS16Type, gt.GenericS8Type, gt.GenericSyscall64, gt.GenericSizeType:
			i, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("MatchArgs value %s invalid: %w", v, err)
			}
			binary.LittleEndian.PutUint64(val[:], uint64(i))
		case gt.GenericU64Type, gt.GenericU32Type, gt.GenericU16Type, gt.GenericU8Type:
			i, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return fmt.Errorf("MatchArgs value %s invalid: %w", v, err)
			}
			binary.LittleEndian.PutUint64(val[:], uint64(i))
		default:
			return fmt.Errorf("unknown type: %d", ty)
		}
		m.Data[val] = struct{}{}
	}
	// write the map id into the selector
	WriteSelectorUint32(&k.data, mid)
	return nil
}

func writeMatchAddrsInMap(k *KernelSelectorState, values []string) error {
	m4 := k.createAddr4Map()
	m6 := k.createAddr6Map()
	for _, v := range values {
		addr, maskLen, err := parseAddr(v)
		if err != nil {
			return fmt.Errorf("MatchArgs value %s invalid: parse IP: %w", v, err)
		}

		if len(addr) == net.IPv4len {
			val := KernelLPMTrie4{prefixLen: maskLen, addr: binary.LittleEndian.Uint32(addr)}
			m4[val] = struct{}{}
		} else if len(addr) == net.IPv6len {
			val := KernelLPMTrie6{prefixLen: maskLen}
			copy(val.addr[:], addr)
			m6[val] = struct{}{}
		} else {
			return fmt.Errorf("MatchArgs value '%s' invalid: should be either 4 or 16 bytes long", v)
		}
	}
	// write the map ids into the selector
	if len(m4) != 0 {
		m4id := k.insertAddr4Map(m4)
		WriteSelectorUint32(&k.data, m4id)
	} else {
		WriteSelectorUint32(&k.data, 0xffffffff)
	}
	if len(m6) != 0 {
		m6id := k.insertAddr6Map(m6)
		WriteSelectorUint32(&k.data, m6id)
	} else {
		WriteSelectorUint32(&k.data, 0xffffffff)
	}
	return nil
}

func parseAddr(v string) ([]byte, uint32, error) {
	if strings.Contains(v, "/") {
		prefix, err := netip.ParsePrefix(v)
		if err != nil {
			return nil, 0, fmt.Errorf("CIDR is invalid: %w", err)
		}
		return prefix.Addr().AsSlice(), uint32(prefix.Bits()), nil
	}

	ipAddr, err := netip.ParseAddr(v)
	if err != nil {
		return nil, 0, fmt.Errorf("IP address is invalid: %w", err)
	}

	return ipAddr.AsSlice(), uint32(ipAddr.BitLen()), nil
}

func capsStrToUint64(values []string) (uint64, error) {
	caps := uint64(0)
	for _, v := range values {
		valstr := strings.ToUpper(strings.TrimSpace(v))
		c, ok := tetragon.CapabilitiesType_value[valstr]
		if !ok {
			return 0, fmt.Errorf("value %s unknown", valstr)
		}
		caps |= (1 << c)
	}
	return caps, nil
}

func writeMatchValues(k *KernelSelectorState, values []string, ty, op uint32) error {
	// NB: maxMatchValues should match MAX_MATCH_VALUES in bpf/process/types/basic.h
	maxMatchValues := 4
	if len(values) > maxMatchValues {
		return fmt.Errorf("selector does not support more than %d values: consider using InMap or NotInMap operators", maxMatchValues)
	}

	for _, v := range values {
		switch ty {

		case gt.GenericIntType, gt.GenericS32Type, gt.GenericSizeType, gt.GenericS16Type, gt.GenericS8Type:
			if (ty == gt.GenericS16Type || ty == gt.GenericS8Type) && !config.EnableLargeProgs() {
				return fmt.Errorf("MatchArgs type %s is only supported in kernels supporting large programs (normally versions >= 5.3)", gt.GenericTypeString(int(ty)))
			}
			i, err := strconv.ParseInt(v, 0, 32)
			if err != nil {
				return fmt.Errorf("MatchArgs value %s invalid: %w", v, err)
			}
			WriteSelectorInt32(&k.data, int32(i))
		case gt.GenericU32Type, gt.GenericU16Type, gt.GenericU8Type:
			if (ty == gt.GenericU16Type || ty == gt.GenericU8Type) && !config.EnableLargeProgs() {
				return fmt.Errorf("MatchArgs type %s is only supported in kernels supporting large programs (normally versions >= 5.3)", gt.GenericTypeString(int(ty)))
			}
			i, err := strconv.ParseUint(v, 0, 32)
			if err != nil {
				return fmt.Errorf("MatchArgs value %s invalid: %w", v, err)
			}
			WriteSelectorUint32(&k.data, uint32(i))
		case gt.GenericS64Type, gt.GenericSyscall64:
			i, err := strconv.ParseInt(v, 0, 64)
			if err != nil {
				return fmt.Errorf("MatchArgs value %s invalid: %w", v, err)
			}
			WriteSelectorInt64(&k.data, int64(i))
		case gt.GenericU64Type:
			i, err := strconv.ParseUint(v, 0, 64)
			if err != nil {
				return fmt.Errorf("MatchArgs value %s invalid: %w", v, err)
			}
			WriteSelectorUint64(&k.data, uint64(i))
		case gt.GenericSockType, gt.GenericSkbType, gt.GenericSockaddrType, gt.GenericSocketType, gt.GenericNetDev:
			return fmt.Errorf("MatchArgs type sock, socket, skb, sockaddr and net_device do not support operator %s", selectorOpStringTable[op])
		case gt.GenericKernelCap, gt.GenericCapInheritable, gt.GenericCapPermitted, gt.GenericCapEffective:
			mask, err := parseCapabilitiesMask(v)
			if err != nil {
				return fmt.Errorf("MatchArgs capabilities mask value %s invalid: %w", v, err)
			}
			WriteSelectorUint64(&k.data, uint64(mask))
		default:
			return fmt.Errorf("MatchArgs type %s unsupported", gt.GenericTypeString(int(ty)))
		}
	}
	return nil
}

func writeMatchStrings(k *KernelSelectorState, values []string, ty uint32) error {
	maps := k.createStringMaps()

	for _, v := range values {
		trimNulSuffix := ty == gt.GenericStringType
		value, size, err := ArgStringSelectorValue(v, trimNulSuffix)
		if err != nil {
			return fmt.Errorf("MatchArgs value %s invalid: %w", v, err)
		}
		numSubMaps := StringMapsNumSubMaps
		if !kernels.MinKernelVersion("5.11") {
			numSubMaps = StringMapsNumSubMapsSmall
		}

		for sizeIdx := range numSubMaps {
			stringMapSize := StringMapsSizes[sizeIdx]
			if sizeIdx == 7 && !kernels.MinKernelVersion("5.11") {
				stringMapSize = StringMapSize7a
			}

			if size == stringMapSize {
				maps[sizeIdx][value] = struct{}{}
				break
			}
		}
	}
	// write the map ids into the selector
	mapDetails := k.insertStringMaps(maps)
	for _, md := range mapDetails {
		WriteSelectorUint32(&k.data, md)
	}
	return nil
}

func writePrefix(k *KernelSelectorState, values []string, selector string) (uint32, error) {
	mid, m := k.newStringPrefixMap()
	for _, v := range values {
		value, size := ArgSelectorValue(v)
		if size > StringPrefixMaxLength {
			return 0, fmt.Errorf("%s value %s invalid: string is longer than %d characters", selector, v, StringPrefixMaxLength)
		}
		val := KernelLPMTrieStringPrefix{prefixLen: size * 8} // prefix is in bits, but size is in bytes
		copy(val.data[:], value)
		m[val] = struct{}{}
	}
	return mid, nil
	// write the map id into the selector

}

func writePrefixBinaries(k *KernelSelectorState, values []string) (uint32, error) {
	return writePrefix(k, values, "MatchBinaries")
}

func writePrefixStrings(k *KernelSelectorState, values []string) error {
	mid, err := writePrefix(k, values, "MatchArgs")
	if err != nil {
		return err
	}
	WriteSelectorUint32(&k.data, mid)
	return nil
}

func writePostfix(k *KernelSelectorState, values []string, ty uint32, selector string) (uint32, error) {
	mid, m := k.newStringPostfixMap()
	for _, v := range values {
		var value []byte
		var size uint32
		if ty == gt.GenericCharBuffer {
			value, size = ArgPostfixSelectorValue(v, false)
		} else {
			value, size = ArgPostfixSelectorValue(v, true)
		}
		// Due to the constraints of the reverse copy in BPF, we will not be able to match a postfix
		// longer than 127 characters, so throw an error if the user specified one.
		if size >= StringPostfixMaxLength {
			return 0, fmt.Errorf("%s value %s invalid: string is longer than %d characters", selector, v, StringPostfixMaxLength-1)
		}
		val := KernelLPMTrieStringPostfix{prefixLen: size * 8} // postfix is in bits, but size is in bytes
		// Copy postfix in reverse order, so that it can be used in LPM map
		for i := range value {
			val.data[len(value)-i-1] = value[i]
		}
		m[val] = struct{}{}
	}
	return mid, nil
}

func writePostfixBinaries(k *KernelSelectorState, values []string) (uint32, error) {
	return writePostfix(k, values, gt.GenericCharBuffer, "MatchBinaries")
}

func writePostfixStrings(k *KernelSelectorState, values []string, ty uint32) error {
	mid, err := writePostfix(k, values, ty, "MatchArgs")
	if err != nil {
		return err
	}
	WriteSelectorUint32(&k.data, mid)
	return nil
}

var fileTypeTable = map[string]uint32{
	"sock":    syscall.S_IFSOCK,
	"socket":  syscall.S_IFSOCK,
	"lnk":     syscall.S_IFLNK,
	"link":    syscall.S_IFLNK,
	"reg":     syscall.S_IFREG,
	"regular": syscall.S_IFREG,
	"blk":     syscall.S_IFBLK,
	"block":   syscall.S_IFBLK,
	"dir":     syscall.S_IFDIR,
	"chr":     syscall.S_IFCHR,
	"char":    syscall.S_IFCHR,
	"fifo":    syscall.S_IFIFO,
	"pipe":    syscall.S_IFIFO,
}

func writeMatchFileType(k *KernelSelectorState, values []string, op uint32) error {
	sValues := make([]string, 0, len(values))
	for _, v := range values {
		val, ok := fileTypeTable[v]
		if !ok {
			return fmt.Errorf("unknown file type: %s", v)
		}
		sValues = append(sValues, strconv.FormatUint(uint64(val), 10))
	}
	return writeMatchValues(k, sValues, gt.GenericU32Type, op)
}

func checkOp(op uint32) error {
	switch op {
	case SelectorOpGT, SelectorOpLT, SelectorOpCapabilitiesGained:
		if !config.EnableLargeProgs() {
			opName := selectorOpStringTable[op]
			return fmt.Errorf(
				"operator %d (%s) is only supported in kernels supporting large programs (normally versions >= 5.3)",
				op, opName,
			)
		}
	}
	return nil
}

func argIndexTypeFromArgs(
	arg *v1alpha1.ArgSelector,
	argsIndex int,
	sig []v1alpha1.KProbeArg,
) (uint32, uint32, error) {
	index := arg.Args[argsIndex]
	if index >= uint32(len(sig)) {
		return 0, 0, fmt.Errorf("wrong ArgSelector.Arg value %d, max(%d)", index, uint32(len(sig)))
	}
	ty := sig[index].Type
	return index, uint32(gt.GenericTypeFromString(ty)), nil
}

func isCapabilityType(ty uint32) bool {
	switch ty {
	case gt.GenericKernelCap, gt.GenericCapInheritable, gt.GenericCapPermitted, gt.GenericCapEffective:
		return true
	}
	return false
}

func argIndexType(arg *v1alpha1.ArgSelector, sig []v1alpha1.KProbeArg) (uint32, uint32, error) {
	if len(arg.Args) > 0 {
		return argIndexTypeFromArgs(arg, 0, sig)
	}
	for idx, s := range sig {
		if arg.Index == s.Index {
			// TBD: We shouldn't get this far with invalid KProbe args
			// KProbe args have already been validated
			return uint32(idx), uint32(gt.GenericTypeFromString(s.Type)), nil
		}
	}
	return 0, 0, errors.New("argFilter for unknown index")
}

func dataIndexType(arg *v1alpha1.ArgSelector, data []v1alpha1.KProbeArg) (uint32, uint32, error) {
	if len(arg.Args) > 0 {
		return argIndexTypeFromArgs(arg, 0, data)
	}
	if arg.Index >= uint32(len(data)) {
		return 0, 0, fmt.Errorf("matchData index out of bonds (0,%d)", len(data))
	}
	ty := data[arg.Index].Type
	return arg.Index, uint32(gt.GenericTypeFromString(ty)), nil
}

func ParseMatchArg(k *KernelSelectorState, arg *v1alpha1.ArgSelector, sig []v1alpha1.KProbeArg) error {
	index, ty, err := argIndexType(arg, sig)
	if err != nil {
		return err
	}
	WriteSelectorUint32(&k.data, index)
	return parseMatchArg(k, arg, sig, ty)
}

func ParseMatchData(k *KernelSelectorState, arg *v1alpha1.ArgSelector, data []v1alpha1.KProbeArg, base uint32) error {
	index, ty, err := dataIndexType(arg, data)
	if err != nil {
		return err
	}
	WriteSelectorUint32(&k.data, index+base)
	return parseMatchArg(k, arg, data, ty)
}

const (
	substringMaxLen = 100
)

func writeMatchSubString(k *KernelSelectorState, values []string) error {
	for _, v := range values {
		id := len(k.subStrs)
		if id >= SubstringMapEntries {
			return fmt.Errorf("substring error: Only %d substrings allowed", SubstringMapEntries)
		}
		if len(v) >= substringMaxLen {
			return fmt.Errorf("substring error: Substring is bigger than 100 chars (%d) %s", len(v), v)
		}
		k.subStrs = append(k.subStrs, v)
		WriteSelectorUint32(&k.data, uint32(id))
	}
	return nil
}

func parseMatchArg(k *KernelSelectorState, arg *v1alpha1.ArgSelector, sig []v1alpha1.KProbeArg, ty uint32) error {
	op, err := SelectorOp(arg.Operator)
	if err != nil {
		return fmt.Errorf("matcharg error: %w", err)
	}
	err = checkOp(op)
	if err != nil {
		return fmt.Errorf("matcharg error: %w", err)
	}
	WriteSelectorUint32(&k.data, op)
	moff := AdvanceSelectorLength(&k.data)
	WriteSelectorUint32(&k.data, ty)

	switch op {
	case SelectorOpInRange, SelectorOpNotInRange:
		err := writeMatchValuesRange(k, arg.Values, ty)
		if err != nil {
			return fmt.Errorf("writeMatchValuesIntervals error: %w", err)
		}
	case SelectorInMap, SelectorNotInMap:
		err := writeMatchValuesInMap(k, arg.Values, ty, op)
		if err != nil {
			return fmt.Errorf("writeMatchRangesInMap error: %w", err)
		}
	case SelectorOpSubStringIgnCase, SelectorOpSubString:
		switch ty {
		case gt.GenericStringType, gt.GenericCharBuffer:
			if err := writeMatchSubString(k, arg.Values); err != nil {
				return fmt.Errorf("writeMatchSubString error: %w", err)
			}
		}
	case SelectorOpEQ, SelectorOpNEQ:
		switch ty {
		case gt.GenericFdType, gt.GenericFileType, gt.GenericPathType, gt.GenericStringType, gt.GenericCharBuffer, gt.GenericLinuxBinprmType, gt.GenericDataLoc, gt.GenericNetDev:
			err := writeMatchStrings(k, arg.Values, ty)
			if err != nil {
				return fmt.Errorf("writeMatchStrings error: %w", err)
			}
		default:
			err = writeMatchValues(k, arg.Values, ty, op)
			if err != nil {
				return fmt.Errorf("writeMatchValues error: %w", err)
			}
		}
	case SelectorOpPrefix, SelectorOpNotPrefix:
		err := writePrefixStrings(k, arg.Values)
		if err != nil {
			return fmt.Errorf("writePrefixStrings error: %w", err)
		}
	case SelectorOpPostfix, SelectorOpNotPostfix:
		err := writePostfixStrings(k, arg.Values, ty)
		if err != nil {
			return fmt.Errorf("writePostfixStrings error: %w", err)
		}
	case SelectorOpSport, SelectorOpDport, SelectorOpNotSport, SelectorOpNotDport, SelectorOpProtocol, SelectorOpFamily, SelectorOpState:
		if ty != gt.GenericSockType && ty != gt.GenericSkbType && ty != gt.GenericSockaddrType && ty != gt.GenericSocketType {
			return errors.New("sock/socket/skb/sockaddr operators specified for non-sock/socket/skb/sockaddr type")
		}
		if ty == gt.GenericSockaddrType && (op == SelectorOpDport || op == SelectorOpNotDport || op == SelectorOpProtocol || op == SelectorOpState) {
			return errors.New("sockaddr only supports [not]saddr, [not]sport[priv], and family")
		}
		err := writeMatchRangesInMap(k, arg.Values, gt.GenericU64Type, op) // force type for ports and protocols as ty is sock/socket/skb/sockaddr
		if err != nil {
			return fmt.Errorf("writeMatchRangesInMap error: %w", err)
		}
	case SelectorOpSaddr, SelectorOpDaddr, SelectorOpNotSaddr, SelectorOpNotDaddr:
		if ty != gt.GenericSockType && ty != gt.GenericSkbType && ty != gt.GenericSockaddrType && ty != gt.GenericSocketType {
			return errors.New("sock/socket/skb/sockaddr operators specified for non-sock/socket/skb/sockaddr type")
		}
		if ty == gt.GenericSockaddrType && (op == SelectorOpDaddr || op == SelectorOpNotDaddr) {
			return errors.New("sockaddr only supports [not]saddr, [not]sport[priv], and family")
		}
		err := writeMatchAddrsInMap(k, arg.Values)
		if err != nil {
			return fmt.Errorf("writeMatchAddrsInMap error: %w", err)
		}
	case SelectorOpSportPriv, SelectorOpDportPriv, SelectorOpNotSportPriv, SelectorOpNotDportPriv:
		// These selectors do not take any values, but we do check that they are only used for sock/skb.
		if ty != gt.GenericSockType && ty != gt.GenericSkbType && ty != gt.GenericSockaddrType && ty != gt.GenericSocketType {
			return errors.New("sock/socket/skb/sockaddr operators specified for non-sock/socket/skb/sockaddr type")
		}
		if ty == gt.GenericSockaddrType && (op == SelectorOpDportPriv || op == SelectorOpNotDportPriv) {
			return errors.New("sockaddr only supports [not]saddr, [not]sport[priv], and family")
		}
	case SelectorOpFileType, SelectorOpNotFileType:
		if ty != gt.GenericFileType && ty != gt.GenericPathType {
			return errors.New("FileType operators specified for non-file/path type")
		}
		err := writeMatchFileType(k, arg.Values, op)
		if err != nil {
			return fmt.Errorf("writeMatchFileType error: %w", err)
		}
	case SelectorOpCapabilitiesGained:
		if len(arg.Args) != 2 {
			return errors.New("CapabilitiesGained operator requires two args: the new and the old capability")
		}
		index2, ty2, err := argIndexTypeFromArgs(arg, 1, sig)
		if err != nil {
			return fmt.Errorf("failed to get second argument for CapabilitiesGained operator: %w", err)
		}
		if !isCapabilityType(ty) || !isCapabilityType(ty2) {
			return errors.New("CapabilitiesGained operator requaries capability type arguments")
		}
		// write the index of the second argument in the data
		WriteSelectorUint32(&k.data, index2)

	default:
		err = writeMatchValues(k, arg.Values, ty, op)
		if err != nil {
			return fmt.Errorf("writeMatchValues error: %w", err)
		}
	}

	WriteSelectorLength(&k.data, moff)
	return nil
}

func ParseMatchArgs(k *KernelSelectorState, matchArgs []v1alpha1.ArgSelector, matchData []v1alpha1.ArgSelector,
	args []v1alpha1.KProbeArg, data []v1alpha1.KProbeArg) error {
	maxArgs := 1
	if config.EnableLargeProgs() {
		maxArgs = 5 // we support up 5 argument filters under matchArgs with kernels >= 5.3, otherwise 1 argument
	}
	if len(matchArgs)+len(matchData) > maxArgs {
		return fmt.Errorf("parseMatchArgs: supports up to %d filters (%d provided)", maxArgs, len(matchArgs)+len(matchData))
	}
	actionOffset := GetCurrentOffset(&k.data)
	loff := AdvanceSelectorLength(&k.data)
	argOff := make([]uint32, 5)
	for i := range 5 {
		argOff[i] = AdvanceSelectorLength(&k.data)
		WriteSelectorOffsetUint32(&k.data, argOff[i], 0)
	}

	var i int

	for _, a := range matchArgs {
		WriteSelectorOffsetUint32(&k.data, argOff[i], GetCurrentOffset(&k.data)-actionOffset)
		if err := ParseMatchArg(k, &a, args); err != nil {
			return err
		}
		i = i + 1
	}

	// index in matchData selectors are based on the number of arguments that
	// are stored before data fields, hence we 'base' matchData index/args
	// values with len(args)
	base := uint32(len(args))

	for _, d := range matchData {
		WriteSelectorOffsetUint32(&k.data, argOff[i], GetCurrentOffset(&k.data)-actionOffset)
		if err := ParseMatchData(k, &d, data, base); err != nil {
			return err
		}
		i = i + 1
	}
	WriteSelectorLength(&k.data, loff)
	return nil
}

// User specifies rateLimit in seconds, minutes or hours, but we store it in milliseconds.
func parseRateLimit(str string, scopeStr string) (uint32, uint32, error) {
	multiplier := uint32(0)
	switch str[len(str)-1] {
	case 's', 'S':
		multiplier = 1
	case 'm', 'M':
		multiplier = 60
	case 'h', 'H':
		multiplier = 60 * 60
	}
	var rateLimit uint64
	var err error
	if multiplier != 0 {
		if len(str) == 1 {
			return 0, 0, fmt.Errorf("parseRateLimit: rateLimit value %s is invalid", str)
		}
		rateLimit, err = strconv.ParseUint(str[:len(str)-1], 10, 32)
	} else {
		rateLimit, err = strconv.ParseUint(str, 10, 32)
		multiplier = 1
	}
	if err != nil {
		return 0, 0, fmt.Errorf("parseRateLimit: rateLimit value %s is invalid", str)
	}
	scope := uint32(ActionRateLimitScopeThread)
	if scopeStr != "" {
		var ok bool
		scope, ok = actionRateLimitScope[scopeStr]
		if !ok {
			return 0, 0, fmt.Errorf("parseRateLimit: rateLimitScope value %s is invalid", scopeStr)
		}
	}

	rateLimit = min(rateLimit*uint64(multiplier)*1000, 0xffffffff)
	return uint32(rateLimit), scope, nil
}

func ParseMatchAction(k *KernelSelectorState, action *v1alpha1.ActionSelector, actionArgTable *idtable.Table) error {
	act, ok := actionTypeTable[strings.ToLower(action.Action)]
	if !ok {
		return fmt.Errorf("parseMatchAction: ActionType %s unknown", action.Action)
	}
	WriteSelectorUint32(&k.data, act)

	rateLimit := uint32(0)
	rateLimitScope := uint32(0)
	if action.RateLimit != "" {
		if act != ActionTypePost {
			return fmt.Errorf("rate limiting can only applied to post action (was applied to '%s')", action.Action)
		}
		var err error
		rateLimit, rateLimitScope, err = parseRateLimit(action.RateLimit, action.RateLimitScope)
		if err != nil {
			return err
		}
	}

	switch act {
	case ActionTypeFollowFd, ActionTypeCopyFd:
		WriteSelectorUint32(&k.data, action.ArgFd)
		WriteSelectorUint32(&k.data, action.ArgName)
	case ActionTypeUnfollowFd:
		WriteSelectorUint32(&k.data, action.ArgFd)
		WriteSelectorUint32(&k.data, action.ArgName)
	case ActionTypeOverride:
		if k.isUprobe {
			id, err := parseOverrideRegs(k, action.ArgRegs, uint64(action.ArgError))
			if err != nil {
				return err
			}
			WriteSelectorUint32(&k.data, id)
		} else {
			WriteSelectorInt32(&k.data, action.ArgError)
		}
	case ActionTypeGetUrl, ActionTypeDnsLookup:
		actionArg := ActionArgEntry{
			tableId: idtable.UninitializedEntryID,
		}
		switch act {
		case ActionTypeGetUrl:
			actionArg.arg = action.ArgUrl
		case ActionTypeDnsLookup:
			actionArg.arg = action.ArgFqdn
		}
		actionArgTable.AddEntry(&actionArg)
		WriteSelectorUint32(&k.data, uint32(actionArg.tableId.ID))
	case ActionTypeSignal:
		WriteSelectorUint32(&k.data, action.ArgSig)
	case ActionTypeTrackSock, ActionTypeUntrackSock:
		WriteSelectorUint32(&k.data, action.ArgSock)
	case ActionTypePost:
		WriteSelectorUint32(&k.data, rateLimit)
		WriteSelectorUint32(&k.data, rateLimitScope)
		kernelStackTrace := uint32(0)
		if action.KernelStackTrace {
			kernelStackTrace = 1
		}
		WriteSelectorUint32(&k.data, kernelStackTrace)
		userStackTrace := uint32(0)
		if action.UserStackTrace {
			userStackTrace = 1
		}
		WriteSelectorUint32(&k.data, userStackTrace)
		imaHash := uint32(0)
		if action.ImaHash {
			imaHash = 1
		}
		WriteSelectorUint32(&k.data, imaHash)
	case ActionTypeNoPost:
		// no arguments
	case ActionTypeSigKill:
		// no arguments
		// NB: we should deprecate this action and just use ActionTypeSignal with SIGKILL
	case ActionTypeNotifyEnforcer:
		WriteSelectorInt32(&k.data, action.ArgError)
		WriteSelectorUint32(&k.data, action.ArgSig)
		actionArgIndex := ^uint32(1)
		if action.EnforcerNotifyActionArgIndex != nil {
			actionArgIndex = *(action.EnforcerNotifyActionArgIndex)
		}
		WriteSelectorUint32(&k.data, actionArgIndex)
	case ActionTypeCleanupEnforcerNotification:
		// no arguments
	case ActionTypeSet:
		WriteSelectorUint32(&k.data, action.ArgIndex)
		WriteSelectorUint32(&k.data, action.ArgValue)
	default:
		return fmt.Errorf("ParseMatchAction: act %d (%s) is missing a handler", act, actionTypeStringTable[act])
	}
	return nil
}

func ParseMatchActions(k *KernelSelectorState, actions []v1alpha1.ActionSelector, actionArgTable *idtable.Table) error {
	if len(actions) > 3 {
		return fmt.Errorf("only %d actions are support for selector (current number of values is %d)", 3, len(actions))
	}
	loff := AdvanceSelectorLength(&k.data)
	for _, a := range actions {
		if err := ParseMatchAction(k, &a, actionArgTable); err != nil {
			return err
		}
	}

	// No action (size value 4) defaults to post action.
	WriteSelectorLength(&k.data, loff)
	return nil
}

func namespaceSelectorValue(ns *v1alpha1.NamespaceSelector, nstype string) ([]byte, uint32, error) {
	b := make([]byte, len(ns.Values)*4)

	if len(ns.Values) > 4 { // 4 should match the number of iterations in selector_match() in pfilter.h
		return b, 0, fmt.Errorf("matchNamespace supports up to 4 values per filter (current number of values is %d)", len(ns.Values))
	}
	for i, v := range ns.Values {
		val, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			// the only case that we can accept and is not a uint32 is "<host_ns>"
			// in this case we should replace that with the approproate value
			if v == "host_ns" {
				n, err := namespace.GetHostNsInode(nstype)
				if err != nil {
					return b, 0, fmt.Errorf("matchNamespace reading host '%s' namespace failed: %w", nstype, err)
				}
				val = uint64(n)
			} else {
				return b, 0, fmt.Errorf("values for matchNamespace can only be numeric or \"host_ns\". (%w)", err)
			}
		}

		off := i * 4
		binary.LittleEndian.PutUint32(b[off:], uint32(val))
	}
	return b, uint32(len(b)), nil
}

func ParseMatchNamespace(k *KernelSelectorState, action *v1alpha1.NamespaceSelector) error {
	nsstr := strings.ToLower(action.Namespace)
	// write namespace type
	ns, ok := namespaceTypeTable[nsstr]
	if !ok {
		return fmt.Errorf("parseMatchNamespace: actionType %s unknown", action.Namespace)
	}
	WriteSelectorUint32(&k.data, ns)

	// write operator
	op, err := SelectorOp(action.Operator)
	if err != nil {
		return fmt.Errorf("matchNamespace error: %w", err)
	}
	if (op != SelectorOpIn) && (op != SelectorOpNotIn) {
		return errors.New("matchNamespace supports only In and NotIn operators")
	}
	WriteSelectorUint32(&k.data, op)

	// write values
	value, size, err := namespaceSelectorValue(action, nsstr)
	if err != nil {
		return err
	}
	WriteSelectorUint32(&k.data, size/4)
	WriteSelectorByteArray(&k.data, value, size)
	return nil
}

func ParseMatchNamespaces(k *KernelSelectorState, actions []v1alpha1.NamespaceSelector) error {
	maxNActions := 4 // 4 should match the value of the NUM_NS_FILTERS_SMALL in pfilter.h
	if config.EnableLargeProgs() {
		maxNActions = 10 // 10 should match the value of ns_max_types in hubble_msg.h
	}
	if len(actions) > maxNActions {
		return fmt.Errorf("matchNamespace supports up to %d filters (current number of filters is %d)", maxNActions, len(actions))
	}
	loff := AdvanceSelectorLength(&k.data)
	// maybe write the number of namespace matches
	for _, a := range actions {
		if err := ParseMatchNamespace(k, &a); err != nil {
			return err
		}
	}
	WriteSelectorLength(&k.data, loff)
	return nil
}

func ParseMatchNamespaceChange(k *KernelSelectorState, action *v1alpha1.NamespaceChangesSelector) error {
	// write operator
	op, err := SelectorOp(action.Operator)
	if err != nil {
		return fmt.Errorf("matchNamespaceChanges error: %w", err)
	}
	if (op != SelectorOpIn) && (op != SelectorOpNotIn) {
		return errors.New("matchNamespaceChanges supports only In and NotIn operators")
	}
	WriteSelectorUint32(&k.data, op)

	// process and write values
	nsval := uint32(0)
	for _, v := range action.Values {
		nsstr := strings.ToLower(v)
		ns, ok := namespaceTypeTable[nsstr]
		if !ok {
			return fmt.Errorf("parseMatchNamespaceChange: actionType %s unknown", v)
		}
		nsval |= (1 << ns)
	}
	WriteSelectorUint32(&k.data, nsval)
	return nil
}

func ParseMatchNamespaceChanges(k *KernelSelectorState, actions []v1alpha1.NamespaceChangesSelector) error {
	if len(actions) > 1 {
		return fmt.Errorf("matchNamespaceChanges supports only a single filter (current number of filters is %d)", len(actions))
	}
	if (len(actions) == 1) && !config.EnableLargeProgs() {
		return errors.New("matchNamespaceChanges is only supported in kernels >= 5.3")
	}
	loff := AdvanceSelectorLength(&k.data)
	// maybe write the number of namespace matches
	for _, a := range actions {
		if err := ParseMatchNamespaceChange(k, &a); err != nil {
			return err
		}
	}
	WriteSelectorLength(&k.data, loff)
	return nil
}

func ParseMatchCaps(k *KernelSelectorState, action *v1alpha1.CapabilitiesSelector) error {
	// type
	tystr := strings.ToLower(action.Type)
	ty, ok := capabilitiesTypeTable[tystr]
	if !ok {
		return fmt.Errorf("parseMatchCapability: actionType %s unknown", action.Type)
	}
	WriteSelectorUint32(&k.data, ty)

	// operator
	op, err := SelectorOp(action.Operator)
	if err != nil {
		return fmt.Errorf("matchCapabilities error: %w", err)
	}
	if (op != SelectorOpIn) && (op != SelectorOpNotIn) {
		return errors.New("matchCapabilities supports only In and NotIn operators")
	}
	WriteSelectorUint32(&k.data, op)

	// isnamespacecapability
	isns := uint32(0) // false by default
	if action.IsNamespaceCapability {
		// If IsNamespaceCapability == true will try to match the capabilities
		//     only when current_user_namespace != host_user_namespace.
		// If IsNamespaceCapability == false will try to match the capabilities
		//     ignoring the user_namespace value.
		// To implement this we pass the "/proc/1/ns/user" value as the host
		// user namespace to compare with that inside the kernel.
		isns, err = namespace.GetPidNsInode(1, "user")
		if err != nil {
			return fmt.Errorf("matchCapabilities reading pid 1 user namespace failed: %w", err)
		}
	}
	WriteSelectorUint32(&k.data, isns)

	// values
	caps, err := capsStrToUint64(action.Values)
	if err != nil {
		return err
	}
	WriteSelectorUint64(&k.data, caps)

	return nil
}

func ParseMatchCapabilities(k *KernelSelectorState, actions []v1alpha1.CapabilitiesSelector) error {
	loff := AdvanceSelectorLength(&k.data)
	for _, a := range actions {
		if err := ParseMatchCaps(k, &a); err != nil {
			return err
		}
	}
	WriteSelectorLength(&k.data, loff)
	return nil
}

func ParseMatchCapabilityChanges(k *KernelSelectorState, actions []v1alpha1.CapabilitiesSelector) error {
	loff := AdvanceSelectorLength(&k.data)
	for _, a := range actions {
		if err := ParseMatchCaps(k, &a); err != nil {
			return err
		}
	}
	WriteSelectorLength(&k.data, loff)
	return nil
}

type genericMatchBinariesSelector int

const (
	matchBinaries genericMatchBinariesSelector = iota
	matchParentBinaries
)

func (s genericMatchBinariesSelector) String() string {
	switch s {
	case matchBinaries:
		return "matchBinaries"
	case matchParentBinaries:
		return "matchParentBinaries"
	}
	return ""
}

func (s genericMatchBinariesSelector) keyFromSelectorID(selectorID int) int {
	var offset int
	if s == matchParentBinaries {
		// matchParentBinaries selector options and paths are stored with MaxSelectors
		// offset in matchBinaries maps.
		offset = MaxSelectors
	}
	return selectorID + offset
}

func ParseMatchBinary(k *KernelSelectorState, b *v1alpha1.BinarySelector, selIdx int, selectorType genericMatchBinariesSelector) error {
	if selectorType != matchBinaries && selectorType != matchParentBinaries {
		return errors.New("selector must be either matchBinaries or matchParentBinaries")
	}

	op, err := SelectorOp(b.Operator)
	if err != nil {
		return fmt.Errorf("%s error: %w", selectorType, err)
	}

	// ignore matchBinaries selectors with no values
	if len(b.Values) == 0 {
		return nil
	}

	// prepare the selector options
	sel := MatchBinariesSelectorOptions{}
	sel.Op = op
	sel.MBSetID = mbset.InvalidID
	if b.FollowChildren {
		if op != SelectorOpIn && op != SelectorOpNotIn {
			return fmt.Errorf("%s: followChildren not yet implemented for operation '%s'", selectorType, b.Operator)
		}

		sel.MBSetID, err = mbset.AllocID()
		if err != nil {
			return fmt.Errorf("%s followChildren: failed to allocate ID: %w", selectorType, err)
		}
	}

	switch op {
	case SelectorOpIn, SelectorOpNotIn:
		for _, s := range b.Values {
			if len(s) > processapi.BINARY_PATH_MAX_LEN-1 {
				return fmt.Errorf("%s error: Binary names > %d chars not supported", selectorType, processapi.BINARY_PATH_MAX_LEN-1)
			}
			k.WriteMatchBinariesPath(selectorType.keyFromSelectorID(selIdx), s)
		}
	case SelectorOpPrefix, SelectorOpNotPrefix:
		if !config.EnableLargeProgs() {
			return fmt.Errorf("%s error: \"Prefix\" and \"NotPrefix\" operators need large BPF progs (kernel>5.3)", selectorType)
		}
		sel.MapID, err = writePrefixBinaries(k, b.Values)
		if err != nil {
			return fmt.Errorf("failed to write the prefix operator for the %s selector: %w", selectorType, err)
		}
	case SelectorOpPostfix, SelectorOpNotPostfix:
		if !config.EnableLargeProgs() {
			return fmt.Errorf("%s error: \"Postfix\" and \"NotPostfix\" operators need large BPF progs (kernel>5.3)", selectorType)
		}
		sel.MapID, err = writePostfixBinaries(k, b.Values)
		if err != nil {
			return fmt.Errorf("failed to write the prefix operator for the %s selector: %w", selectorType, err)
		}
	default:
		return fmt.Errorf("%s error: Only \"In\", \"NotIn\", \"Prefix\", \"NotPrefix\", \"Postfix\" and \"NotPostfix\" operators are supported", selectorType)
	}

	k.AddMatchBinaries(selectorType.keyFromSelectorID(selIdx), sel)

	return nil
}

func ParseMatchBinaries(k *KernelSelectorState, binaries []v1alpha1.BinarySelector, selIdx int, selector genericMatchBinariesSelector) error {
	if len(binaries) > 1 {
		return errors.New("only support a single matchBinaries per selector")
	}

	if len(binaries) > 0 && selector == matchParentBinaries && !option.Config.ParentsMapEnabled {
		return errors.New("matchParentBinaries selector can be used only with parents map enabled")
	}

	for _, s := range binaries {
		if err := ParseMatchBinary(k, &s, selIdx, selector); err != nil {
			return err
		}
	}
	return nil
}

type KernelSelectorArgs struct {
	Selectors      []v1alpha1.KProbeSelector
	Args           []v1alpha1.KProbeArg
	Data           []v1alpha1.KProbeArg
	ActionArgTable *idtable.Table
	ListReader     ValueReader
	Maps           *KernelSelectorMaps
	IsUprobe       bool
}

// The byte array storing the selector configuration has the following format
// array := [N][S1_off][S2_off]...[SN_off][S1][S2][...][SN]
//
//	N: is the number of selectors (u32)
//	Sx_off: is the relative offset of  selector x (diff of Sx to Sx_off)
//	Sx: holds the data for the selector
//
// Each selector x starts with its length in bytes, and then stores a number of sections for the
// different matchers. Each section will typically starts with its length in bytes.
//
// Sx := [length]
//
//	[matchPIDs]
//	[matchNamespaces]
//	[matchCapabilities]
//	[matchNamespaceChanges]
//	[matchCapabilityChanges]
//	[matchArgs]
//	[matchActions]
//
// matchPIDs := [length][PID1][PID2]...[PIDn]
// matchNamespaces := [length][NSx][NSy]...[NSn]
// matchCapabilities := [length][CAx][CAy]...[CAn]
// matchNamespaceChanges := [length][NCx][NCy]...[NCn]
// matchCapabilityChanges := [length][CAx][CAy]...[CAn]
// matchArgs := [length][ARGx][ARGy]...[ARGn]
// PIDn := [op][flags][nValues][v1]...[vn]
// Argn := [index][op][valueGen]
// NSn := [namespace][op][valueInt]
// NCn := [op][valueInt]
// CAn := [type][op][namespacecap][valueInt]
// valueGen := [type][len][v]
// valueInt := [len][v]
//
// For some examples, see kernel_test.go
func InitKernelSelectors(selectors []v1alpha1.KProbeSelector, args []v1alpha1.KProbeArg, data []v1alpha1.KProbeArg, actionArgTable *idtable.Table) ([4096]byte, error) {
	state, err := InitKernelSelectorState(&KernelSelectorArgs{
		Selectors:      selectors,
		Args:           args,
		Data:           data,
		ActionArgTable: actionArgTable,
	})
	if err != nil {
		return [4096]byte{}, err
	}
	return state.data.e, nil
}

func InitKernelReturnSelectors(selectors []v1alpha1.KProbeSelector, returnArg *v1alpha1.KProbeArg, actionArgTable *idtable.Table) ([4096]byte, error) {
	state, err := InitKernelReturnSelectorState(selectors, returnArg, actionArgTable, nil, nil)
	if err != nil {
		return [4096]byte{}, err
	}
	return state.data.e, nil
}

func createKernelSelectorState(
	selectors []v1alpha1.KProbeSelector,
	listReader ValueReader,
	maps *KernelSelectorMaps,
	isUprobe bool,
	parseSelector func(k *KernelSelectorState, selectors *v1alpha1.KProbeSelector, selIdx int) error,
) (*KernelSelectorState, error) {
	if len(selectors) > MaxSelectors {
		return nil, fmt.Errorf("no more than %d selectors supported (%d provided)", MaxSelectors, len(selectors))
	}
	state := NewKernelSelectorState(listReader, maps, isUprobe)

	WriteSelectorUint32(&state.data, uint32(len(selectors)))
	soff := make([]uint32, len(selectors))
	for i := range selectors {
		soff[i] = AdvanceSelectorLength(&state.data)
	}
	for i, s := range selectors {
		WriteSelectorLength(&state.data, soff[i])
		loff := AdvanceSelectorLength(&state.data)
		if err := parseSelector(state, &s, i); err != nil {
			return nil, err
		}
		WriteSelectorLength(&state.data, loff)
	}
	return state, nil
}

func InitKernelSelectorState(args *KernelSelectorArgs) (*KernelSelectorState, error) {

	parse := func(k *KernelSelectorState, selector *v1alpha1.KProbeSelector, selIdx int) error {
		if err := ParseMatchPids(k, selector.MatchPIDs); err != nil {
			return fmt.Errorf("parseMatchPids error: %w", err)
		}
		if err := ParseMatchNamespaces(k, selector.MatchNamespaces); err != nil {
			return fmt.Errorf("parseMatchNamespaces error: %w", err)
		}
		if err := ParseMatchCapabilities(k, selector.MatchCapabilities); err != nil {
			return fmt.Errorf("parseMatchCapabilities error: %w", err)
		}
		if err := ParseMatchNamespaceChanges(k, selector.MatchNamespaceChanges); err != nil {
			return fmt.Errorf("parseMatchNamespaceChanges error: %w", err)
		}
		if err := ParseMatchCapabilityChanges(k, selector.MatchCapabilityChanges); err != nil {
			return fmt.Errorf("parseMatchCapabilityChanges error: %w", err)
		}
		if err := ParseMatchBinaries(k, selector.MatchBinaries, selIdx, matchBinaries); err != nil {
			return fmt.Errorf("parseMatchBinaries error: %w", err)
		}
		if err := ParseMatchBinaries(k, selector.MatchParentBinaries, selIdx, matchParentBinaries); err != nil {
			return fmt.Errorf("parseMatchParentBinaries error: %w", err)
		}
		if err := ParseMatchArgs(k, selector.MatchArgs, selector.MatchData, args.Args, args.Data); err != nil {
			return fmt.Errorf("parseMatchArgs  error: %w", err)
		}
		if err := ParseMatchActions(k, selector.MatchActions, args.ActionArgTable); err != nil {
			return fmt.Errorf("parseMatchActions error: %w", err)
		}
		return nil
	}

	return createKernelSelectorState(args.Selectors, args.ListReader, args.Maps, args.IsUprobe, parse)
}

func InitKernelReturnSelectorState(selectors []v1alpha1.KProbeSelector, returnArg *v1alpha1.KProbeArg,
	actionArgTable *idtable.Table, listReader ValueReader, maps *KernelSelectorMaps) (*KernelSelectorState, error) {

	parse := func(k *KernelSelectorState, selector *v1alpha1.KProbeSelector, _ int) error {
		if err := ParseMatchArgs(k, selector.MatchReturnArgs, []v1alpha1.ArgSelector{}, []v1alpha1.KProbeArg{*returnArg}, []v1alpha1.KProbeArg{}); err != nil {
			return fmt.Errorf("parseMatchArgs  error: %w", err)
		}
		if err := ParseMatchActions(k, selector.MatchReturnActions, actionArgTable); err != nil {
			return fmt.Errorf("parseMatchActions error: %w", err)
		}
		return nil
	}

	return createKernelSelectorState(selectors, listReader, maps, false, parse)
}

func CleanupKernelSelectorState(state *KernelSelectorState) error {
	var errs error

	for selectorID, paths := range state.MatchBinariesPaths() {
		sel := state.MatchBinaries()[selectorID]
		if err := mbset.RemoveID(sel.MBSetID, paths); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

func HasOverride(selectors []v1alpha1.KProbeSelector) bool {
	for _, s := range selectors {
		for _, action := range s.MatchActions {
			act := actionTypeTable[strings.ToLower(action.Action)]
			if act == ActionTypeOverride {
				return true
			}
		}
	}
	return false
}

func HasOperator(selectors []v1alpha1.KProbeSelector, op uint32) bool {
	for _, s := range selectors {
		for _, a := range slices.Concat(s.MatchArgs, s.MatchData, s.MatchReturnArgs) {
			argOp, err := SelectorOp(a.Operator)
			if err != nil {
				return false
			}
			if argOp == op {
				return true
			}
		}
	}
	return false
}

func HasSetArgIndex(spec *v1alpha1.UsdtSpec) (bool, uint32) {
	for _, s := range spec.Selectors {
		for _, action := range s.MatchActions {
			act := actionTypeTable[strings.ToLower(action.Action)]
			if act == ActionTypeSet {
				return true, action.ArgIndex
			}
		}
	}
	return false, 0
}

func HasSet(spec *v1alpha1.UsdtSpec) bool {
	ok, _ := HasSetArgIndex(spec)
	return ok
}

func HasSigkillAction(kspec *v1alpha1.KProbeSpec) bool {
	for i := range kspec.Selectors {
		s := &kspec.Selectors[i]
		for j := range s.MatchActions {
			act := strings.ToLower(s.MatchActions[j].Action)
			if act == "sigkill" {
				return true
			}
		}
	}
	return false
}

func HasEnforcementAction(selectors []v1alpha1.KProbeSelector) bool {
	for _, s := range selectors {
		for _, action := range s.MatchActions {
			act := actionTypeTable[strings.ToLower(action.Action)]
			if act == ActionTypeSigKill || act == ActionTypeSignal || act == ActionTypeNotifyEnforcer || act == ActionTypeOverride || act == ActionTypeSet {
				return true
			}
		}
	}
	return false
}

func HasFilter(selectors []v1alpha1.KProbeSelector, index uint32) bool {
	for _, s := range selectors {
		for _, a := range s.MatchArgs {
			if a.Index == index {
				return true
			}
		}
	}
	return false
}

// HasNotifyEnforcerAction returns true if any selector in the KProbeSpec has a NotifyEnforcer action
func HasNotifyEnforcerAction(kspec *v1alpha1.KProbeSpec) bool {
	for _, s := range kspec.Selectors {
		for _, action := range s.MatchActions {
			if action.Action == "NotifyEnforcer" {
				return true
			}
		}
	}
	return false
}

func HasFDInstall(sel []v1alpha1.KProbeSelector) bool {
	for _, selector := range sel {
		for _, matchAction := range selector.MatchActions {
			if a := ActionTypeFromString(matchAction.Action); a == ActionTypeFollowFd ||
				a == ActionTypeUnfollowFd ||
				a == ActionTypeCopyFd {
				return true
			}
		}
	}
	return false
}

func HasRateLimit(selectors []v1alpha1.KProbeSelector) bool {
	for _, selector := range selectors {
		for _, matchAction := range selector.MatchActions {
			if len(matchAction.RateLimit) > 0 {
				return true
			}
		}
	}
	return false
}

func HasStackTrace(selectors []v1alpha1.KProbeSelector) bool {
	for _, selector := range selectors {
		for _, matchAction := range selector.MatchActions {
			if matchAction.KernelStackTrace || matchAction.UserStackTrace {
				return true
			}
		}
	}
	return false
}

func HasSockTrack(spec *v1alpha1.KProbeSpec) bool {
	// Check ReturnArgAction
	if spec.ReturnArgAction != "" {
		if a := ActionTypeFromString(spec.ReturnArgAction); a == ActionTypeTrackSock ||
			a == ActionTypeUntrackSock {
			return true
		}
	}

	// Check selectors MatchActions and MatchReturnActions
	for _, selector := range spec.Selectors {
		for _, matchAction := range selector.MatchActions {
			if a := ActionTypeFromString(matchAction.Action); a == ActionTypeTrackSock ||
				a == ActionTypeUntrackSock {
				return true
			}
		}
		for _, matchReturnAction := range selector.MatchReturnActions {
			if a := ActionTypeFromString(matchReturnAction.Action); a == ActionTypeTrackSock ||
				a == ActionTypeUntrackSock {
				return true
			}
		}
	}
	return false
}

func HasSelector(spec *v1alpha1.KProbeSpec) bool {
	return len(spec.Selectors) != 0
}

// parseCapabilitiesMask create a capabilities mask
func parseCapabilitiesMask(s string) (uint64, error) {
	mask, err := strconv.ParseUint(s, 0, 64)
	if err == nil {
		return mask, nil
	}
	caps := strings.Split(s, ",")
	mask, err = capsStrToUint64(caps)
	if err != nil {
		return uint64(0), fmt.Errorf("parseCapabilitiesMask: %w", err)
	}
	return mask, nil
}
