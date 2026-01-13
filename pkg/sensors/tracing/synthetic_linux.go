// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/constants"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

type genericArg struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

func parseKprobeArg(raw json.RawMessage) (tracingapi.MsgGenericKprobeArg, error) {
	var ga genericArg
	if err := json.Unmarshal(raw, &ga); err != nil {
		return nil, err
	}

	switch ga.Type {
	case "int":
		var v tracingapi.MsgGenericKprobeArgInt
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "uint":
		var v tracingapi.MsgGenericKprobeArgUInt
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "size":
		var v tracingapi.MsgGenericKprobeArgSize
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "long":
		var v tracingapi.MsgGenericKprobeArgLong
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "string":
		var v tracingapi.MsgGenericKprobeArgString
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "bytes":
		var v tracingapi.MsgGenericKprobeArgBytes
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "sock":
		var v tracingapi.MsgGenericKprobeArgSock
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "skb":
		var v tracingapi.MsgGenericKprobeArgSkb
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "sockaddr":
		var v tracingapi.MsgGenericKprobeArgSockaddr
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "file":
		var v tracingapi.MsgGenericKprobeArgFile
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "path":
		var v tracingapi.MsgGenericKprobeArgPath
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "cred":
		var v tracingapi.MsgGenericKprobeArgCred
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "bpf_attr":
		var v tracingapi.MsgGenericKprobeArgBpfAttr
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "perf_event":
		var v tracingapi.MsgGenericKprobeArgPerfEvent
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "bpf_map":
		var v tracingapi.MsgGenericKprobeArgBpfMap
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "user_ns":
		var v tracingapi.MsgGenericKprobeArgUserNamespace
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "capability":
		var v tracingapi.MsgGenericKprobeArgCapability
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "load_module":
		var v tracingapi.MsgGenericKprobeArgLoadModule
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "kernel_module":
		var v tracingapi.MsgGenericKprobeArgKernelModule
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "binprm":
		var v tracingapi.MsgGenericKprobeArgLinuxBinprm
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	default:
		return nil, fmt.Errorf("unknown kprobe arg type: %s", ga.Type)
	}
}

func parseTracepointArg(raw json.RawMessage) (any, error) {
	var ga genericArg
	if err := json.Unmarshal(raw, &ga); err != nil {
		// Fallback: try to unmarshal as primitive
		var i interface{}
		if err := json.Unmarshal(raw, &i); err == nil {
			// Careful with numbers, they come as float64
			return i, nil
		}
		return nil, err
	}

	switch ga.Type {
	case "uint64":
		var v uint64
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "int64":
		var v int64
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "uint32":
		var v uint32
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "int32":
		var v int32
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "uint16":
		var v uint16
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "int16":
		var v int16
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "uint8":
		var v uint8
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "int8":
		var v int8
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "string":
		var v string
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "bytes":
		var v []byte
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "sock":
		var v tracingapi.MsgGenericKprobeArgSock
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "skb":
		var v tracingapi.MsgGenericKprobeArgSkb
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "sockaddr":
		var v tracingapi.MsgGenericKprobeArgSockaddr
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "syscall_id":
		var v tracingapi.MsgGenericSyscallID
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "binprm":
		var v tracingapi.MsgGenericKprobeArgLinuxBinprm
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "file":
		var v tracingapi.MsgGenericKprobeArgFile
		if err := json.Unmarshal(ga.Value, &v); err != nil {
			return nil, err
		}
		return v, nil
	default:
		return nil, fmt.Errorf("unknown tracepoint arg type: %s", ga.Type)
	}
}

func RegisterSyntheticEvents() {
	observer.RegisterSyntheticUnmarshaler("Kprobe", func(data json.RawMessage) (notify.Message, error) {
		var temp struct {
			Msg              *tracingapi.MsgGenericKprobe           `json:"Msg"`
			ReturnAction     uint64                                 `json:"ReturnAction"`
			FuncName         string                                 `json:"FuncName"`
			Args             []json.RawMessage                      `json:"Args"`
			Data             []json.RawMessage                      `json:"Data"`
			PolicyName       string                                 `json:"PolicyName"`
			Message          string                                 `json:"Message"`
			KernelStackTrace [constants.PERF_MAX_STACK_DEPTH]uint64 `json:"KernelStackTrace"`
			UserStackTrace   [constants.PERF_MAX_STACK_DEPTH]uint64 `json:"UserStackTrace"`
			Tags             []string                               `json:"Tags"`
		}
		if err := json.Unmarshal(data, &temp); err != nil {
			return nil, err
		}

		event := &tracing.MsgGenericKprobeUnix{
			Msg:              temp.Msg,
			ReturnAction:     temp.ReturnAction,
			FuncName:         temp.FuncName,
			PolicyName:       temp.PolicyName,
			Message:          temp.Message,
			KernelStackTrace: temp.KernelStackTrace,
			UserStackTrace:   temp.UserStackTrace,
			Tags:             temp.Tags,
		}

		for _, rawArg := range temp.Args {
			arg, err := parseKprobeArg(rawArg)
			if err != nil {
				return nil, err
			}
			event.Args = append(event.Args, arg)
		}
		for _, rawArg := range temp.Data {
			arg, err := parseKprobeArg(rawArg)
			if err != nil {
				return nil, err
			}
			event.Data = append(event.Data, arg)
		}

		return event, nil
	})

	observer.RegisterSyntheticUnmarshaler("Tracepoint", func(data json.RawMessage) (notify.Message, error) {
		var temp struct {
			Msg        *tracingapi.MsgGenericTracepoint `json:"Msg"`
			Subsys     string                           `json:"Subsys"`
			Event      string                           `json:"Event"`
			Args       []json.RawMessage                `json:"Args"`
			PolicyName string                           `json:"PolicyName"`
			Message    string                           `json:"Message"`
			Tags       []string                         `json:"Tags"`
		}
		if err := json.Unmarshal(data, &temp); err != nil {
			return nil, err
		}

		event := &tracing.MsgGenericTracepointUnix{
			Msg:        temp.Msg,
			Subsys:     temp.Subsys,
			Event:      temp.Event,
			PolicyName: temp.PolicyName,
			Message:    temp.Message,
			Tags:       temp.Tags,
		}

		for _, rawArg := range temp.Args {
			arg, err := parseTracepointArg(rawArg)
			if err != nil {
				return nil, err
			}
			event.Args = append(event.Args, arg)
		}

		return event, nil
	})

	observer.RegisterSyntheticUnmarshaler("Uprobe", func(data json.RawMessage) (notify.Message, error) {
		var temp struct {
			Msg          *tracingapi.MsgGenericKprobe `json:"Msg"`
			Path         string                       `json:"Path"`
			Symbol       string                       `json:"Symbol"`
			Offset       uint64                       `json:"Offset"`
			RefCtrOffset uint64                       `json:"RefCtrOffset"`
			PolicyName   string                       `json:"PolicyName"`
			Message      string                       `json:"Message"`
			Args         []json.RawMessage            `json:"Args"`
			Data         []json.RawMessage            `json:"Data"`
			Tags         []string                     `json:"Tags"`
		}
		if err := json.Unmarshal(data, &temp); err != nil {
			return nil, err
		}

		event := &tracing.MsgGenericUprobeUnix{
			Msg:          temp.Msg,
			Path:         temp.Path,
			Symbol:       temp.Symbol,
			Offset:       temp.Offset,
			RefCtrOffset: temp.RefCtrOffset,
			PolicyName:   temp.PolicyName,
			Message:      temp.Message,
			Tags:         temp.Tags,
		}

		for _, rawArg := range temp.Args {
			arg, err := parseKprobeArg(rawArg)
			if err != nil {
				return nil, err
			}
			event.Args = append(event.Args, arg)
		}
		for _, rawArg := range temp.Data {
			arg, err := parseKprobeArg(rawArg)
			if err != nil {
				return nil, err
			}
			event.Data = append(event.Data, arg)
		}

		return event, nil
	})
}
