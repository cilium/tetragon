// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tetragoninfo

import (
	"errors"
	"fmt"

	"github.com/spf13/viper"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/version"
)

// Info is a simplified version of tetragon.GetInfoResponse.
type Info struct {
	Name    string
	Version string
	Probes  map[string]bool
	Conf    map[string]any
	Build   version.BuildInfo
}

// Decode decodes a gRPC response into an Info structure
func Decode(res *tetragon.GetInfoResponse) *Info {
	probes := make(map[string]bool, len(res.Probes))
	for _, probe := range res.Probes {
		probes[probe.Name] = probe.Enabled.GetValue()
	}
	return &Info{
		Name:    res.Name,
		Version: res.Version,
		Probes:  probes,
		Conf:    decodeConf(res.Conf),
		Build: version.BuildInfo{
			GoVersion: res.GetBuild().GoVersion,
			Commit:    res.GetBuild().Commit,
			Time:      res.GetBuild().Time,
			Modified:  res.GetBuild().Modified,
		},
	}
}

// decodeConf decodes the configuration part of info
func decodeConf(conf []*tetragon.GetInfoResponse_ConfVal) map[string]any {
	ret := make(map[string]any, len(conf))
	for _, cnf := range conf {
		var val any
		key := cnf.GetKey()
		value, err := cnf.GetValue().UnmarshalNew()
		if err != nil {
			ret[key] = fmt.Errorf("failed to unmarshall value: %w", err)
			continue
		}
		switch v := value.(type) {
		case *wrapperspb.StringValue:
			val = v.GetValue()
		case *wrapperspb.Int64Value:
			val = v.GetValue()
		case *wrapperspb.BoolValue:
			val = v.GetValue()
		case *structpb.ListValue:
			val = v.AsSlice()
		default:
			val = fmt.Errorf("unknown value type: %T", val)
		}
		ret[key] = val
	}
	return ret
}

// Gather gathers all the necessary inormation and encodes it in the appropriate gRPC message
func Gather() *tetragon.GetInfoResponse {
	// NB: ignore errors, and let's provide users with partial information when this happens
	conf, _ := buildConf()
	build := version.ReadBuildInfo()
	res := &tetragon.GetInfoResponse{
		Name:    version.Name,
		Version: version.Version,
		Probes:  bpfProbes(),
		Conf:    conf,
		Build: &tetragon.GetInfoResponse_BuildInfo{
			GoVersion: build.GoVersion,
			Commit:    build.Commit,
			Time:      build.Time,
			Modified:  build.Modified,
		},
	}
	return res
}

func buildConf() ([]*tetragon.GetInfoResponse_ConfVal, error) {
	return encodeConf(viper.AllSettings())
}

func encodeConf(conf map[string]any) ([]*tetragon.GetInfoResponse_ConfVal, error) {
	var ret []*tetragon.GetInfoResponse_ConfVal
	var retErr error

	for key, val := range conf {
		var value *anypb.Any
		var err error
		switch x := val.(type) {
		case string:
			value, err = anypb.New(wrapperspb.String(x))
		case bool:
			value, err = anypb.New(wrapperspb.Bool(x))
		case int:
			value, err = anypb.New(wrapperspb.Int64(int64(x)))
		case []string:
			values := make([]*structpb.Value, 0, len(x))
			for _, s := range x {
				values = append(values, structpb.NewStringValue(s))
			}
			value, err = anypb.New(&structpb.ListValue{
				Values: values,
			})
		default:
			err = fmt.Errorf("unknown type: %T", val)
		}

		if err != nil {
			err := fmt.Errorf("failed to wrap type key %s (with value type %T): %w", key, val, err)
			errors.Join(retErr, err)
		}
		ret = append(ret, &tetragon.GetInfoResponse_ConfVal{
			Key:   key,
			Value: value,
		})
	}
	return ret, retErr
}
