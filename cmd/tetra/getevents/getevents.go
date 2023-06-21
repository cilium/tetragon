// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package getevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// DocLong documents the commands with some examples
const DocLong = `This command prints and filter events by connecting to the server or via
redirection of events to the stdin. Examples:

  # Connect, print and filter by process events
  %[1]s getevents --process netserver

  # Redirect events and filter by namespace from stdin
  cat events.json | %[1]s getevents -o compact --namespace default

  # Exclude parent field
  %[1]s getevents -F parent

  # Include only process and parent.pod fields
  %[1]s getevents -f process,parent.pod`

var (
	output        string
	color         string
	includeFields []string
	excludeFields []string
	namespaces    []string
	processes     []string
	pods          []string
	host          bool
	timestamps    bool
	ttyEncode     string
)

// GetEncoder returns an encoder for an event stream based on configuration options.
var GetEncoder = func(w io.Writer, colorMode encoder.ColorMode, timestamps bool, compact bool, tty string) encoder.EventEncoder {
	if tty != "" {
		return encoder.NewTtyEncoder(w, tty)
	}
	if compact {
		return encoder.NewCompactEncoder(w, colorMode, timestamps)
	}
	return json.NewEncoder(w)
}

// GetFilter returns a filter for an event stream based on configuration options.
var GetFilter = func() *tetragon.Filter {
	if host {
		// Host events can be matched by an empty namespace string.
		namespaces = append(namespaces, "")
	}
	// Only set these filters if they are not empty. We currently rely on Protobuf to
	// marshal empty lists as nil for filters to function properly. It doesn't work with
	// stdin mode since it doesn't go over the wire, causing all events to get filtered
	// out because empty allowlist does not match anything.
	filter := tetragon.Filter{}
	if len(processes) > 0 {
		filter.BinaryRegex = processes
	}
	if len(namespaces) > 0 {
		filter.Namespace = namespaces
	}
	if len(pods) > 0 {
		filter.PodRegex = pods
	}

	return &filter
}

func getRequest(includeFields, excludeFields []string, filter *tetragon.Filter) *tetragon.GetEventsRequest {
	var fieldFilters []*tetragon.FieldFilter
	if len(includeFields) > 0 {
		fieldFilters = append(fieldFilters, &tetragon.FieldFilter{
			EventSet: []tetragon.EventType{},
			Fields: &fieldmaskpb.FieldMask{
				Paths: includeFields,
			},
			Action: tetragon.FieldFilterAction_INCLUDE,
		})
	}
	if len(excludeFields) > 0 {
		fieldFilters = append(fieldFilters, &tetragon.FieldFilter{
			EventSet: []tetragon.EventType{},
			Fields: &fieldmaskpb.FieldMask{
				Paths: excludeFields,
			},
			Action: tetragon.FieldFilterAction_EXCLUDE,
		})
	}

	return &tetragon.GetEventsRequest{
		FieldFilters: fieldFilters,
		AllowList:    []*tetragon.Filter{filter},
	}
}

func getEvents(ctx context.Context, client tetragon.FineGuidanceSensorsClient) {
	request := getRequest(includeFields, excludeFields, GetFilter())
	stream, err := client.GetEvents(ctx, request)
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("Failed to call GetEvents")
	}
	eventEncoder := GetEncoder(os.Stdout, encoder.ColorMode(color), timestamps, output == "compact", ttyEncode)
	for {
		res, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled && !errors.Is(err, io.EOF) {
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
		Long:  fmt.Sprintf(DocLong, "tetra"),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if output != "json" && output != "compact" {
				return fmt.Errorf("invalid value for %q flag: %s", common.KeyOutput, output)
			}
			if color != "auto" && color != "always" && color != "never" {
				return fmt.Errorf("invalid value for %q flag: %s", "color", color)
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			fi, _ := os.Stdin.Stat()
			if fi.Mode()&os.ModeNamedPipe != 0 {
				// read events from stdin
				getEvents(context.Background(), newIOReaderClient(os.Stdin, viper.GetBool("debug")))
				return
			}
			// connect to server
			common.CliRun(getEvents)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&output, common.KeyOutput, "o", "json", "Output format. json or compact")
	flags.StringVar(&color, "color", "auto", "Colorize compact output. auto, always, or never")
	flags.StringSliceVarP(&includeFields, "include-fields", "f", nil, "Include only fields in events")
	flags.StringSliceVarP(&excludeFields, "exclude-fields", "F", nil, "Exclude fields from events")
	flags.StringSliceVarP(&namespaces, "namespace", "n", nil, "Get events by Kubernetes namespaces")
	flags.StringSliceVar(&processes, "process", nil, "Get events by process name regex")
	flags.StringSliceVar(&pods, "pod", nil, "Get events by pod name regex")
	flags.BoolVar(&host, "host", false, "Get host events")
	flags.BoolVar(&timestamps, "timestamps", false, "Include timestamps in compact output")
	flags.StringVarP(&ttyEncode, "tty-encode", "t", "", "Encode terminal data by file path (all other events will be ignored)")
	return &cmd
}
