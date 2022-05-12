//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package eventcache

import (
	"fmt"

	"github.com/isovalent/tetragon-oss/cmd/protoc-gen-go-tetragon/common"
	"google.golang.org/protobuf/compiler/protogen"
)

// getEventsResponse generates a new GetEventsResponse_<EVENT_TYPE>
func doGetEventsResponse(g *protogen.GeneratedFile, eventType string) string {
	fgsGER := common.FgsApiIdent(g, "GetEventsResponse")
	subtype := common.FgsApiIdent(g, fmt.Sprintf("GetEventsResponse_%s", eventType))

	return fgsGER + `{
        Event: &` + subtype + `{` + eventType + `: e},
        NodeName: nodeName,
        Time: timestamp,
    }`
}

func generateDoHandleEvents(g *protogen.GeneratedFile, f *protogen.File) error {
	fgsProcessInternal := common.GoIdent(g, "github.com/isovalent/tetragon-oss/pkg/process", "ProcessInternal")
	fgsGER := common.FgsApiIdent(g, "GetEventsResponse")
	timestamp := common.GoIdent(g, "google.golang.org/protobuf/types/known/timestamppb", "Timestamp")

	mErrorCount := common.GoIdent(g, "github.com/isovalent/tetragon-oss/pkg/metrics", "ErrorCount")
	mInfoFailed := common.GoIdent(g, "github.com/isovalent/tetragon-oss/pkg/metrics", "EventCacheProcessInfoFailed")
	mProcessInfoErrors := common.GoIdent(g, "github.com/isovalent/tetragon-oss/pkg/metrics", "ProcessInfoErrors")

	g.P(`func DoHandleEvent(event eventObj, internal *` + fgsProcessInternal + `, labels []string, nodeName string, timestamp *` + timestamp + `) (*` + fgsGER + `, error) {
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
                ` + mProcessInfoErrors + `.WithLabelValues("` + msg.GoIdent.GoName + `").Inc()
                ` + mErrorCount + `.WithLabelValues(string(` + mInfoFailed + `)).Inc()
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
	g := common.NewGeneratedFile(gen, f, "eventcache")

	fgsProcess := common.FgsApiIdent(g, "Process")

	g.P(`
        type eventObj interface {
            GetProcess() *` + fgsProcess + `
        }
    `)

	if err := generateDoHandleEvents(g, f); err != nil {
		return err
	}

	return nil
}
