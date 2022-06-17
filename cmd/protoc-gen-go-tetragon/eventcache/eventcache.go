// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventcache

import (
	"fmt"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"google.golang.org/protobuf/compiler/protogen"
)

// getEventsResponse generates a new GetEventsResponse_<EVENT_TYPE>
func doGetEventsResponse(g *protogen.GeneratedFile, eventType string) string {
	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")
	subtype := common.TetragonApiIdent(g, fmt.Sprintf("GetEventsResponse_%s", eventType))

	return tetragonGER + `{
        Event: &` + subtype + `{` + eventType + `: e},
        NodeName: nodeName,
        Time: timestamp,
    }`
}

func generateDoHandleEvents(g *protogen.GeneratedFile, f *protogen.File) error {
	tetragonProcessInternal := common.PkgProcessIdent(g, "ProcessInternal")
	tetragonGER := common.TetragonApiIdent(g, "GetEventsResponse")
	timestamp := common.GoIdent(g, "google.golang.org/protobuf/types/known/timestamppb", "Timestamp")

	incErrorCount := common.TetragonIdent(g, "pkg/metrics/errormetrics", "ErrorTotalInc")
	mInfoFailed := common.TetragonIdent(g, "pkg/metrics/errormetrics", "EventCacheProcessInfoFailed")
	incProcessInfoErrors := common.TetragonIdent(g, "pkg/metrics/eventcachemetrics", "ProcessInfoErrorInc")

	g.P(`func DoHandleEvent(event eventObj, internal *` + tetragonProcessInternal + `, labels []string, nodeName string, timestamp *` + timestamp + `) (*` + tetragonGER + `, error) {
        switch e := event.(type) {`)
	for _, msg := range f.Messages {
		if !common.IsProcessEvent(msg) {
			continue
		}
		g.P(`
        case *` + g.QualifiedGoIdent(msg.GoIdent) + `:
            if internal != nil {
                e.Process = internal.GetProcessCopy()
            } else {
                ` + incProcessInfoErrors + `("` + msg.GoIdent.GoName + `")
                ` + incErrorCount + `(` + mInfoFailed + `)
            }
            return &` + doGetEventsResponse(g, msg.GoIdent.GoName) + `, nil`)
	}
	g.P(`}
            return nil, ` + common.FmtErrorf(g, "DoHandleEvent: Unhandled event type %T", "event") + `
        }`)

	return nil
}

// Generate generates boilerplate code for the event cache
func Generate(gen *protogen.Plugin, f *protogen.File) error {
	g := common.NewCodegenFile(gen, f, "eventcache")

	tetragonProcess := common.ProcessIdent(g)

	g.P(`
        type eventObj interface {
            GetProcess() *` + tetragonProcess + `
        }
    `)

	if err := generateDoHandleEvents(g, f); err != nil {
		return err
	}

	return nil
}
