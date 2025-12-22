// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cilium/tetragon/pkg/api/dataapi"
	processapi "github.com/cilium/tetragon/pkg/api/processapi"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/reader/network"
	"github.com/cilium/tetragon/pkg/strutils"
)

type argPrinter struct {
	ty       int
	userType int
	index    int
	maxData  bool
	label    string
	data     bool
}

const (
	argReturnCopyBit  = 1 << 4
	argMaxDataBit     = 1 << 5
	argCurrentTaskBit = 1 << 6
	argPtRegsBit      = 1 << 7
)

func argReturnCopy(meta int) bool {
	return meta&argReturnCopyBit != 0
}

// meta value format:
// bits
//
//	0-3 : SizeArgIndex
//	  4 : ReturnCopy
//	  5 : MaxData
//	  6 : CurrentTask
func getMetaValue(arg *v1alpha1.KProbeArg) (int, error) {
	var meta int

	if arg.SizeArgIndex > 0 {
		if arg.SizeArgIndex > 15 {
			return 0, fmt.Errorf("invalid SizeArgIndex value (>15): %v", arg.SizeArgIndex)
		}
		meta = int(arg.SizeArgIndex)
	}
	if arg.Size > 0 {
		if arg.Size > 0xFFFF {
			return 0, fmt.Errorf("invalid Size value (>65535): %v", arg.Size)
		}
		// Pack Size into bits 8-23
		meta = meta | (int(arg.Size) << 8)
	}
	if arg.ReturnCopy {
		meta = meta | argReturnCopyBit
	}
	if arg.MaxData {
		meta = meta | argMaxDataBit
	}
	if hasCurrentTaskSource(arg) {
		meta = meta | argCurrentTaskBit
	}
	if hasPtRegsSource(arg) {
		meta = meta | argPtRegsBit
	}
	return meta, nil
}

// getTracepointMetaArg is a temporary helper to find meta values while tracepoint
// converts into new CRD and config formats.
func getTracepointMetaValue(arg *v1alpha1.KProbeArg) int {
	if arg.SizeArgIndex > 0 {
		return int(arg.SizeArgIndex)
	}
	if arg.ReturnCopy {
		return -1
	}
	return 0
}

func getArg(r *bytes.Reader, a argPrinter) api.MsgGenericKprobeArg {
	var err error

	switch a.ty {
	case gt.GenericIntType, gt.GenericS32Type:
		var output int32
		var arg api.MsgGenericKprobeArgInt

		if a.userType != gt.GenericInvalidType {
			arg.UserSpaceType = int32(a.userType)
		}

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("Int type error", "arg.usertype", gt.GenericUserTypeToString(a.userType), logfields.Error, err)
		}

		arg.Index = uint64(a.index)
		arg.Value = output
		arg.Label = a.label
		return arg
	case gt.GenericFileType, gt.GenericFdType, gt.GenericKiocb:
		var arg api.MsgGenericKprobeArgFile
		var flags uint32
		var b int32
		var mode uint16

		/* Eat file descriptor its not used in userland */
		if a.ty == gt.GenericFdType {
			binary.Read(r, binary.LittleEndian, &b)
		}

		arg.Index = uint64(a.index)
		arg.Value, err = parseString(r)
		if err != nil {
			if errors.Is(err, errParseStringSize) {
				// If no size then path walk was not possible and file was
				// either a mount point or not a "file" at all which can
				// happen if running without any filters and kernel opens an
				// anonymous inode. For this lets just report its on "/" all
				// though pid filtering will mostly catch this.
				arg.Value = "/"
			} else {
				logger.GetLogger().Warn("error parsing arg type file", logfields.Error, err)
			}
		}

		// read the first byte that keeps the flags
		err := binary.Read(r, binary.LittleEndian, &flags)
		if err != nil {
			flags = 0
		}

		if a.ty == gt.GenericFileType || a.ty == gt.GenericKiocb {
			err := binary.Read(r, binary.LittleEndian, &mode)
			if err != nil {
				mode = 0
			}
			arg.Permission = mode
		}

		arg.Flags = flags
		arg.Label = a.label
		return arg
	case gt.GenericInt32ArrType:
		var count uint32
		var arg api.MsgGenericKprobeArgInt32List
		err := binary.Read(r, binary.LittleEndian, &count)
		if err != nil {
			logger.GetLogger().Warn("Int32Arr type error (reading count)", logfields.Error, err)
		} else {
			if count == 0xFFFFFFFC {
				// count == -4 (0xFFFFFFFC) indicates CHAR_BUF_SAVED_FOR_RETPROBE.
				// This means the argument is an output parameter (return copy), so the data
				// is not yet available at kprobe entry. It will be sent in a subsequent
				// event from the retprobe.
			} else if count > 2048 {
				logger.GetLogger().Warn("Int32Arr size too large", "size", count)
			} else {
				values := make([]int32, count)
				if err := binary.Read(r, binary.LittleEndian, &values); err != nil {
					logger.GetLogger().Warn("Int32Arr type error (reading values)", "count", count, logfields.Error, err)
				} else {
					arg.Value = values
				}
			}
		}

		arg.Index = uint64(a.index)
		arg.Label = a.label
		return arg
	case gt.GenericPathType, gt.GenericDentryType:
		var arg api.MsgGenericKprobeArgPath
		var flags uint32
		var mode uint16

		arg.Index = uint64(a.index)
		arg.Value, err = parseString(r)
		if err != nil {
			if errors.Is(err, errParseStringSize) {
				arg.Value = "/"
			} else {
				logger.GetLogger().Warn("error parsing arg type path", logfields.Error, err)
			}
		}

		// read the first byte that keeps the flags
		err := binary.Read(r, binary.LittleEndian, &flags)
		if err != nil {
			flags = 0
		}

		err = binary.Read(r, binary.LittleEndian, &mode)
		if err != nil {
			mode = 0
		}

		arg.Flags = flags
		arg.Permission = mode
		arg.Label = a.label
		return arg
	case gt.GenericFilenameType, gt.GenericStringType, gt.GenericNetDev:
		var arg api.MsgGenericKprobeArgString

		arg.Index = uint64(a.index)
		arg.Value, err = parseString(r)
		if err != nil {
			logger.GetLogger().Warn("error parsing arg type string", logfields.Error, err)
		}

		arg.Label = a.label
		return arg
	case gt.GenericCredType:
		var cred processapi.MsgGenericCred
		var arg api.MsgGenericKprobeArgCred

		err := binary.Read(r, binary.LittleEndian, &cred)
		if err != nil {
			logger.GetLogger().Warn("cred type err", logfields.Error, err)
		}

		arg.Index = uint64(a.index)
		arg.Uid = cred.Uid
		arg.Gid = cred.Gid
		arg.Suid = cred.Suid
		arg.Sgid = cred.Sgid
		arg.Euid = cred.Euid
		arg.Egid = cred.Egid
		arg.FSuid = cred.FSuid
		arg.FSgid = cred.FSgid
		arg.SecureBits = cred.SecureBits
		arg.Cap.Permitted = cred.Cap.Permitted
		arg.Cap.Effective = cred.Cap.Effective
		arg.Cap.Inheritable = cred.Cap.Inheritable
		arg.UserNs.Level = cred.UserNs.Level
		arg.UserNs.Uid = cred.UserNs.Uid
		arg.UserNs.Gid = cred.UserNs.Gid
		arg.UserNs.NsInum = cred.UserNs.NsInum
		arg.Label = a.label
		return arg
	case gt.GenericCharBuffer, gt.GenericCharIovec, gt.GenericIovIter:
		arg, err := ReadArgBytes(r, a.index, a.maxData)
		if err == nil {
			arg.Label = a.label
			return *arg
		}
		logger.GetLogger().Warn("failed to read bytes argument", logfields.Error, err)
	case gt.GenericSkbType:
		var skb api.MsgGenericKprobeSkb
		var arg api.MsgGenericKprobeArgSkb

		err := binary.Read(r, binary.LittleEndian, &skb)
		if err != nil {
			logger.GetLogger().Warn("skb type err", logfields.Error, err)
		}

		arg.Index = uint64(a.index)
		arg.Hash = skb.Hash
		arg.Len = skb.Len
		arg.Priority = skb.Priority
		arg.Mark = skb.Mark
		arg.Family = skb.Tuple.Family
		arg.Saddr = network.GetIP(skb.Tuple.Saddr, skb.Tuple.Family).String()
		arg.Daddr = network.GetIP(skb.Tuple.Daddr, skb.Tuple.Family).String()
		arg.Sport = uint32(skb.Tuple.Sport)
		arg.Dport = uint32(skb.Tuple.Dport)
		arg.Proto = uint32(skb.Tuple.Protocol)
		arg.SecPathLen = skb.SecPathLen
		arg.SecPathOLen = skb.SecPathOLen
		arg.Label = a.label
		return arg
	case gt.GenericSockType, gt.GenericSocketType:
		var sock api.MsgGenericKprobeSock
		var arg api.MsgGenericKprobeArgSock

		err := binary.Read(r, binary.LittleEndian, &sock)
		if err != nil {
			logger.GetLogger().Warn("sock type err", logfields.Error, err)
		}

		arg.Index = uint64(a.index)
		arg.Family = sock.Tuple.Family
		arg.State = sock.State
		arg.Type = sock.Type
		arg.Protocol = sock.Tuple.Protocol
		arg.Mark = sock.Mark
		arg.Priority = sock.Priority
		arg.Saddr = network.GetIP(sock.Tuple.Saddr, sock.Tuple.Family).String()
		arg.Daddr = network.GetIP(sock.Tuple.Daddr, sock.Tuple.Family).String()
		arg.Sport = uint32(sock.Tuple.Sport)
		arg.Dport = uint32(sock.Tuple.Dport)
		arg.Sockaddr = sock.Sockaddr
		arg.Label = a.label
		return arg
	case gt.GenericSockaddrType:
		var address api.MsgGenericKprobeSockaddr
		var arg api.MsgGenericKprobeArgSockaddr

		err := binary.Read(r, binary.LittleEndian, &address)
		if err != nil {
			logger.GetLogger().Warn("sockaddr type err", logfields.Error, err)
		}

		arg.Index = uint64(a.index)
		arg.SinFamily = address.SinFamily
		arg.SinAddr = network.GetIP(address.SinAddr, address.SinFamily).String()
		arg.SinPort = uint32(address.SinPort)
		return arg
	case gt.GenericS64Type:
		var output int64
		var arg api.MsgGenericKprobeArgLong

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("Size type err", logfields.Error, err)
		}

		arg.Index = uint64(a.index)
		arg.Value = output
		arg.Label = a.label
		return arg
	case gt.GenericSizeType, gt.GenericU64Type:
		var output uint64
		var arg api.MsgGenericKprobeArgSize

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("Size type err", logfields.Error, err)
		}

		arg.Index = uint64(a.index)
		arg.Value = output
		arg.Label = a.label
		return arg
	case gt.GenericNopType:
		// do nothing
	case gt.GenericBpfAttr:
		var output api.MsgGenericKprobeBpfAttr
		var arg api.MsgGenericKprobeArgBpfAttr

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("bpf_attr type error", logfields.Error, err)
		}
		arg.ProgType = output.ProgType
		arg.InsnCnt = output.InsnCnt
		length := bytes.IndexByte(output.ProgName[:], 0) // trim tailing null bytes
		arg.ProgName = string(output.ProgName[:length])
		arg.Label = a.label
		return arg
	case gt.GenericBpfProgType:
		var output api.MsgGenericKprobeBpfProg
		var arg api.MsgGenericKprobeArgBpfProg

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("bpf_attr type error", logfields.Error, err)
		}
		arg.ProgType = output.ProgType
		arg.InsnCnt = output.InsnCnt
		length := bytes.IndexByte(output.ProgName[:], 0) // trim tailing null bytes
		arg.ProgName = string(output.ProgName[:length])
		arg.Label = a.label
		return arg
	case gt.GenericPerfEvent:
		var output api.MsgGenericKprobePerfEvent
		var arg api.MsgGenericKprobeArgPerfEvent

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("perf_event type error", logfields.Error, err)
		}
		length := bytes.IndexByte(output.KprobeFunc[:], 0) // trim tailing null bytes
		arg.KprobeFunc = string(output.KprobeFunc[:length])
		arg.Type = output.Type
		arg.Config = output.Config
		arg.ProbeOffset = output.ProbeOffset
		arg.Label = a.label
		return arg
	case gt.GenericBpfMap:
		var output api.MsgGenericKprobeBpfMap
		var arg api.MsgGenericKprobeArgBpfMap

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("bpf_map type error", logfields.Error, err)
		}

		arg.MapType = output.MapType
		arg.KeySize = output.KeySize
		arg.ValueSize = output.ValueSize
		arg.MaxEntries = output.MaxEntries
		length := bytes.IndexByte(output.MapName[:], 0) // trim tailing null bytes
		arg.MapName = string(output.MapName[:length])
		arg.Label = a.label
		return arg
	case gt.GenericU32Type:
		var output uint32
		var arg api.MsgGenericKprobeArgUInt

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("UInt type error", logfields.Error, err)
		}

		arg.Index = uint64(a.index)
		arg.Value = output
		arg.Label = a.label
		return arg
	case gt.GenericUserNamespace:
		var output api.MsgGenericUserNamespace
		var arg api.MsgGenericKprobeArgUserNamespace

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("user_namespace type error", logfields.Error, err)
		}
		arg.Level = output.Level
		arg.Uid = output.Uid
		arg.Gid = output.Gid
		arg.NsInum = output.NsInum
		arg.Label = a.label
		return arg
	case gt.GenericCapability:
		var output api.MsgGenericKprobeCapability
		var arg api.MsgGenericKprobeArgCapability

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("capability type error", logfields.Error, err)
		}
		arg.Value = output.Value
		arg.Label = a.label
		return arg
	case gt.GenericLoadModule:
		var output api.MsgGenericLoadModule
		var arg api.MsgGenericKprobeArgLoadModule

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("load_module type error", logfields.Error, err)
		} else if output.Name[0] != 0x00 {
			i := bytes.IndexByte(output.Name[:api.MODULE_NAME_LEN], 0)
			if i == -1 {
				i = api.MODULE_NAME_LEN
			}
			arg.Name = string(output.Name[:i])
			arg.SigOk = output.SigOk
			arg.Taints = output.Taints
		}
		arg.Label = a.label
		return arg
	case gt.GenericKernelModule:
		var output api.MsgGenericLoadModule
		var arg api.MsgGenericKprobeArgKernelModule

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("kernel module type error", logfields.Error, err)
		} else if output.Name[0] != 0x00 {
			i := bytes.IndexByte(output.Name[:api.MODULE_NAME_LEN], 0)
			if i == -1 {
				i = api.MODULE_NAME_LEN
			}
			arg.Name = string(output.Name[:i])
			arg.Taints = output.Taints
		}
		arg.Label = a.label
		return arg
	case gt.GenericU16Type:
		var output uint32
		var arg api.MsgGenericKprobeArgUInt

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("UInt type error", logfields.Error, err)
		}

		arg.Index = uint64(a.index)
		arg.Value = uint32(uint16(output))
		arg.Label = a.label
		return arg
	case gt.GenericU8Type:
		var output uint32
		var arg api.MsgGenericKprobeArgUInt

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("UInt type error", logfields.Error, err)
		}

		arg.Index = uint64(a.index)
		arg.Value = uint32(uint8(output))
		arg.Label = a.label
		return arg
	case gt.GenericS16Type:
		var output uint32
		var arg api.MsgGenericKprobeArgInt

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("Int type error", logfields.Error, err)
		}

		arg.Index = uint64(a.index)
		arg.Value = int32(int16(output))
		arg.Label = a.label
		return arg
	case gt.GenericS8Type:
		var output uint32
		var arg api.MsgGenericKprobeArgInt

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("Int type error", logfields.Error, err)
		}

		arg.Index = uint64(a.index)
		arg.Value = int32(int8(output))
		arg.Label = a.label
		return arg
	case gt.GenericKernelCap:
		var output uint64
		var arg api.MsgGenericKprobeArgKernelCapType

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("kernel_cap_t type error", logfields.Error, err)
		} else {
			arg.Caps = output
		}

		arg.Index = uint64(a.index)
		arg.Label = a.label
		return arg
	case gt.GenericCapInheritable:
		var output uint64
		var arg api.MsgGenericKprobeArgCapInheritable

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("kernel_cap_t cap_inheritable type error", logfields.Error, err)
		} else {
			arg.Caps = output
		}

		arg.Index = uint64(a.index)
		arg.Label = a.label
		return arg
	case gt.GenericCapPermitted:
		var output uint64
		var arg api.MsgGenericKprobeArgCapPermitted

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("kernel_cap_t cap_permitted type error", logfields.Error, err)
		} else {
			arg.Caps = output
		}

		arg.Index = uint64(a.index)
		arg.Label = a.label
		return arg
	case gt.GenericCapEffective:
		var output uint64
		var arg api.MsgGenericKprobeArgCapEffective

		err := binary.Read(r, binary.LittleEndian, &output)
		if err != nil {
			logger.GetLogger().Warn("kernel_cap_t cap_effective type error", logfields.Error, err)
		} else {
			arg.Caps = output
		}

		arg.Index = uint64(a.index)
		arg.Label = a.label
		return arg
	case gt.GenericLinuxBinprmType:
		var arg api.MsgGenericKprobeArgLinuxBinprm
		var flags uint32
		var mode uint16

		arg.Index = uint64(a.index)
		arg.Value, err = parseString(r)
		if err != nil {
			if errors.Is(err, errParseStringSize) {
				arg.Value = "/"
			} else {
				logger.GetLogger().Warn("error parsing arg type linux_binprm", logfields.Error, err)
			}
		}

		err := binary.Read(r, binary.LittleEndian, &flags)
		if err != nil {
			flags = 0
		}

		err = binary.Read(r, binary.LittleEndian, &mode)
		if err != nil {
			mode = 0
		}
		arg.Flags = flags
		arg.Permission = mode
		arg.Label = a.label
		return arg
	default:
		logger.GetLogger().Warn("Unknown event type", "event-type", a.ty, logfields.Error, err)
	}

	return nil
}

// parseString parses strings encoded from BPF copy_strings in the form:
// *---------*---------*
// | 4 bytes | N bytes |
// |  size   | string  |
// *---------*---------*
func parseString(r io.Reader) (string, error) {
	var size int32
	err := binary.Read(r, binary.LittleEndian, &size)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errParseStringSize, err)
	}

	if size < 0 {
		return "", errors.New("string size is negative")
	}

	// limit the size of the string to avoid huge memory allocation and OOM kill in case of issue
	if size > int32(maxStringSize) {
		return "", fmt.Errorf("string size too large: %d, max size is %d", size, maxStringSize)
	}
	stringBuffer := make([]byte, size)
	err = binary.Read(r, binary.LittleEndian, &stringBuffer)
	if err != nil {
		return "", fmt.Errorf("error parsing string from binary with size %d: %w", size, err)
	}

	// remove the trailing '\0' from the C string
	if len(stringBuffer) > 0 && stringBuffer[len(stringBuffer)-1] == '\x00' {
		stringBuffer = stringBuffer[:len(stringBuffer)-1]
	}

	return strutils.UTF8FromBPFBytes(stringBuffer), nil
}

func ReadArgBytes(r *bytes.Reader, index int, hasMaxData bool) (*api.MsgGenericKprobeArgBytes, error) {
	var bytes, bytesRd, hasDataEvents int32
	var arg api.MsgGenericKprobeArgBytes

	if hasMaxData {
		/* First int32 indicates if data events are used (1) or not (0). */
		if err := binary.Read(r, binary.LittleEndian, &hasDataEvents); err != nil {
			return nil, fmt.Errorf("failed to read original size for buffer argument: %w", err)
		}
		if hasDataEvents != 0 {
			var desc dataapi.DataEventDesc

			if err := binary.Read(r, binary.LittleEndian, &desc); err != nil {
				return nil, err
			}
			data, err := observer.DataGet(desc)
			if err != nil {
				return nil, err
			}
			arg.Index = uint64(index)
			arg.OrigSize = uint64(len(data) + int(desc.Leftover))
			arg.Value = data
			return &arg, nil
		}
	}

	if err := binary.Read(r, binary.LittleEndian, &bytes); err != nil {
		return nil, fmt.Errorf("failed to read original size for buffer argument: %w", err)
	}

	arg.Index = uint64(index)
	if bytes == CharBufSavedForRetprobe {
		return &arg, nil
	}
	// bpf-side returned an error
	if bytes < 0 {
		// NB: once we extended arguments to also pass errors, we can change
		// this.
		arg.Value = []byte(kprobeCharBufErrorToString(bytes))
		return &arg, nil
	}
	arg.OrigSize = uint64(bytes)
	if err := binary.Read(r, binary.LittleEndian, &bytesRd); err != nil {
		return nil, fmt.Errorf("failed to read size for buffer argument: %w", err)
	}

	if bytesRd > 0 {
		arg.Value = make([]byte, bytesRd)
		if err := binary.Read(r, binary.LittleEndian, &arg.Value); err != nil {
			return nil, fmt.Errorf("failed to read buffer (size: %d): %w", bytesRd, err)
		}
	}

	// NB: there are cases (e.g., read()) where it is valid to have an
	// empty (zero-length) buffer.
	return &arg, nil
}
