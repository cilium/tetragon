// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package getevents

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/encoder"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetEncoder returns an encoder for an event stream based on configuration options.
var GetEncoder = func(w io.Writer, colorMode encoder.ColorMode, timestamps bool, compact bool) encoder.EventEncoder {
	if compact {
		return encoder.NewCompactEncoder(w, colorMode, timestamps)
	}
	return json.NewEncoder(w)
}

func getRequest(namespaces []string, host bool, processes []string, pods []string) *tetragon.GetEventsRequest {
	if host {
		// Host events can be matched by an empty namespace string.
		namespaces = append(namespaces, "")
	}
	return &tetragon.GetEventsRequest{
		AllowList: []*tetragon.Filter{{
			BinaryRegex: processes,
			Namespace:   namespaces,
			PodRegex:    pods,
		}},
	}
}

func getEvents(ctx context.Context, client tetragon.FineGuidanceSensorsClient) {
	host := viper.GetBool("host")
	namespaces := viper.GetStringSlice("namespace")
	processes := viper.GetStringSlice("process")
	pods := viper.GetStringSlice("pod")
	timestamps := viper.GetBool("timestamps")
	compact := viper.GetString(common.KeyOutput) == "compact"
	colorMode := encoder.ColorMode(viper.GetString(common.KeyColor))

	request := getRequest(namespaces, host, processes, pods)
	stream, err := client.GetEvents(ctx, request)
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("Failed to call GetEvents")
	}
	eventEncoder := GetEncoder(os.Stdout, colorMode, timestamps, compact)
	for {
		res, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
				logger.GetLogger().WithError(err).Fatal("Failed to receive events")
			}
			return
		}
		if err = eventEncoder.Encode(res); err != nil {
			logger.GetLogger().WithError(err).WithField("event", res).Debug("Failed to encode event")
		}
	}
}

func New() *cobra.Command {
	cmd := cobra.Command{
		Use:   "getevents",
		Short: "Print events",
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(getEvents)
		},
	}

	flags := cmd.Flags()
	flags.StringP("output", "o", "json", "Output format. json or compact")
	flags.String("color", "auto", "Colorize compact output. auto, always, or never")
	flags.StringSliceP("namespace", "n", nil, "Get events by Kubernetes namespaces")
	flags.StringSlice("process", nil, "Get events by process name regex")
	flags.StringSlice("pod", nil, "Get events by pod name regex")
	flags.Bool("host", false, "Get host events")
	flags.Bool("timestamps", false, "Include timestamps in compact output")
	viper.BindPFlags(flags)
	return &cmd
}
