// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package getevents

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/encoder"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

type Opts struct {
	Output        string
	Color         string
	IncludeFields []string
	EventTypes    []string
	ExcludeFields []string
	Namespaces    []string
	Namespace     []string // deprecated: use Namespaces
	Processes     []string
	Process       []string // deprecated: use Processes
	Pods          []string
	Pod           []string // deprecated: use Pods
	Host          bool
	Timestamps    bool
	TTYEncode     string
	StackTraces   bool
	ImaHash       bool
	PolicyNames   []string
	CelExpression []string
	Reconnect     bool
	ReconnectWait time.Duration
}

var Options Opts

// GetEncoder returns an encoder for an event stream based on configuration options.
var GetEncoder = func(w io.Writer, colorMode encoder.ColorMode, timestamps bool, compact bool, tty string, stackTraces bool, imaHash bool) encoder.EventEncoder {
	if tty != "" {
		return encoder.NewTtyEncoder(w, tty)
	}
	if compact {
		return encoder.NewCompactEncoder(w, colorMode, timestamps, stackTraces, imaHash)
	}
	return encoder.NewProtojsonEncoder(w)
}

// GetFilter returns a filter for an event stream based on configuration options.
var GetFilter = func() *tetragon.Filter {
	if Options.Host {
		// Host events can be matched by an empty namespace string.
		Options.Namespaces = append(Options.Namespaces, "")
	}
	// Only set these filters if they are not empty. We currently rely on Protobuf to
	// marshal empty lists as nil for filters to function properly. It doesn't work with
	// stdin mode since it doesn't go over the wire, causing all events to get filtered
	// out because empty allowlist does not match anything.
	filter := tetragon.Filter{}
	if len(Options.Processes) > 0 {
		filter.BinaryRegex = Options.Processes
	}
	if len(Options.Namespaces) > 0 {
		filter.Namespace = Options.Namespaces
	}
	if len(Options.Pods) > 0 {
		filter.PodRegex = Options.Pods
	}
	// Is used to filter on the event types i.e. PROCESS_EXEC, PROCESS_EXIT etc.
	if len(Options.EventTypes) > 0 {
		var eventType tetragon.EventType

		for _, v := range Options.EventTypes {
			eventType = tetragon.EventType(tetragon.EventType_value[v])
			filter.EventSet = append(filter.EventSet, eventType)
		}
	}
	if len(Options.PolicyNames) > 0 {
		filter.PolicyNames = Options.PolicyNames
	}
	if len(Options.CelExpression) > 0 {
		filter.CelExpression = Options.CelExpression
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

func getEvents(ctx context.Context, client tetragon.FineGuidanceSensorsClient) error {
	request := getRequest(Options.IncludeFields, Options.ExcludeFields, GetFilter())
	stream, err := client.GetEvents(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to call GetEvents: %w", err)
	}
	eventEncoder := GetEncoder(os.Stdout, encoder.ColorMode(Options.Color), Options.Timestamps, Options.Output == "compact", Options.TTYEncode, Options.StackTraces, Options.ImaHash)
	for {
		res, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled && !errors.Is(err, io.EOF) {
				return fmt.Errorf("failed to receive events: %w", err)
			}
			return nil
		}
		if err = eventEncoder.Encode(res); err != nil {
			return fmt.Errorf("failed to encode event %#v: %w", res, err)
		}
	}
}

func New() *cobra.Command {
	cmd := cobra.Command{
		Use:   "getevents",
		Short: "Print events",
		Long: `This command prints and filter events by connecting to the server or via
redirection of events to the stdin. Examples:

  # Connect, print and filter by process events
  tetra getevents --process netserver

  # Redirect events and filter by namespace from stdin
  cat events.json | tetra getevents -o compact --namespace default

  # Exclude parent field
  tetra getevents -F parent

  # Include only process and parent.pod fields
  tetra getevents -f process,parent.pod`,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if Options.Output != "json" && Options.Output != "compact" {
				return fmt.Errorf("invalid value for %q flag: %s", common.KeyOutput, Options.Output)
			}
			if Options.Color != "auto" && Options.Color != "always" && Options.Color != "never" {
				return fmt.Errorf("invalid value for %q flag: %s", "color", Options.Color)
			}

			for _, v := range Options.EventTypes {
				if _, found := tetragon.EventType_value[v]; !found {
					var supportedEventTypes string
					for _, v := range tetragon.EventType_name {
						supportedEventTypes += v + ", "
					}
					supportedEventTypes = strings.TrimSuffix(supportedEventTypes, ", ")
					return fmt.Errorf("invalid value for %q flag: %s. Supported are %s", "event-types", v, supportedEventTypes)
				}
			}

			// merge deprecated to new flags, appending since order does not matter
			Options.Namespaces = append(Options.Namespace, Options.Namespaces...)
			Options.Pods = append(Options.Pod, Options.Pods...)
			Options.Processes = append(Options.Process, Options.Processes...)

			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			fi, _ := os.Stdin.Stat()
			if fi.Mode()&os.ModeNamedPipe != 0 {
				// read events from stdin
				return getEvents(context.Background(), newIOReaderClient(os.Stdin, common.Debug))
			}

			reconnect := Options.Reconnect
			tryGetEvents := func() error {
				// connect to server
				c, err := common.NewClientWithDefaultContextAndAddress()
				if err != nil {
					return fmt.Errorf("failed create gRPC client: %w", err)
				}
				defer c.Close()
				ret := getEvents(c.SignalCtx, c.Client)
				if ctxErr := c.SignalCtx.Err(); ctxErr != nil && errors.Is(ctxErr, context.Canceled) {
					// we got a signal, so we should not try to reconnect
					reconnect = false
				}
				return ret
			}

			for {
				err := tryGetEvents()
				if !reconnect {
					return err
				}
				fmt.Fprintf(os.Stderr, "getevents: err:%v retrying in %v\n", err, Options.ReconnectWait)
				time.Sleep(Options.ReconnectWait)
			}

		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&Options.Output, common.KeyOutput, "o", "json", "Output format. json or compact")
	flags.StringVar(&Options.Color, "color", "auto", "Colorize compact output. auto, always, or never")
	flags.StringSliceVarP(&Options.IncludeFields, "include-fields", "f", nil, "Include only fields in events")
	flags.StringSliceVarP(&Options.EventTypes, "event-types", "e", nil, "Include only events of given types")
	flags.StringSliceVarP(&Options.ExcludeFields, "exclude-fields", "F", nil, "Exclude fields from events")

	flags.StringSliceVarP(&Options.Namespace, "namespace", "n", nil, "Get events by Kubernetes namespace")
	flags.StringSliceVar(&Options.Namespaces, "namespaces", nil, "Get events by Kubernetes namespaces")
	flags.MarkHidden("namespaces")

	flags.StringSliceVar(&Options.Process, "process", nil, "Get events by process name regex")
	flags.StringSliceVar(&Options.Processes, "processes", nil, "Get events by processes name regex")
	flags.MarkHidden("processes")

	flags.StringSliceVar(&Options.Pod, "pod", nil, "Get events by pod name regex")
	flags.StringSliceVar(&Options.Pods, "pods", nil, "Get events by pods name regex")
	flags.MarkHidden("pods")

	flags.BoolVar(&Options.Host, "host", false, "Get host events")
	flags.BoolVar(&Options.Timestamps, "timestamps", false, "Include timestamps in compact output")
	flags.StringVarP(&Options.TTYEncode, "tty-encode", "t", "", "Encode terminal data by file path (all other events will be ignored)")
	flags.BoolVar(&Options.StackTraces, "stack-traces", true, "Include stack traces in compact output")
	flags.BoolVar(&Options.ImaHash, "ima-hash", true, "Include ima hashes in compact output")
	flags.StringSliceVar(&Options.PolicyNames, "policy-names", nil, "Get events by tracing policy names")
	flags.StringSliceVar(&Options.CelExpression, "cel-expression", nil, "Get events satisfying the CEL expression")
	flags.BoolVar(&Options.Reconnect, "reconnect", false, "Keep trying to connect even if an error occurred")
	flags.DurationVar(&Options.ReconnectWait, "reconnect-wait", 2*time.Second, "wait time before attempting to reconnect")
	return &cmd
}
