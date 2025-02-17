// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"fmt"
	"strings"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"
)

var yamlTemplate = `apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: example_yaml
  namespace: default
spec:
  kprobes:
  - call: __x64_sys_connect
    selectors:
    - matchActions:
      - action: Override
        argError: -111
    syscall: true
  - call: __x64_sys_listen
    selectors:
    - matchActions:
      - action: Override
        argError: -111
    syscall: true
{{- if .IncludeOpts }}
  options:
{{- range $k, $v := .Opts }}
  - name: {{ $k }}
    value: {{ $v }}
{{- end }}
{{- end}}
`

type tmplData struct {
	IncludeOpts bool
	Opts        map[string]string
}

func TestPolicyYAMLSetMode(t *testing.T) {
	type tc struct {
		desc  string
		iData tmplData
		mode  string
		oData tmplData
	}

	tcs := []tc{
		{
			"no options",
			tmplData{false, nil},
			"",
			tmplData{false, nil},
		}, {
			"other options unchanged",
			tmplData{true, map[string]string{"foo": "lala"}},
			"",
			tmplData{true, map[string]string{"foo": "lala"}},
		}, {
			"no options, set to enforce",
			tmplData{false, nil},
			"enforce",
			tmplData{true, map[string]string{"policy-mode": "enforce"}},
		}, {
			"other options, set to monitor",
			tmplData{true, map[string]string{"foo": "lala"}},
			"monitor",
			tmplData{true, map[string]string{"foo": "lala", "policy-mode": "monitor"}},
		}, {
			"policy mode set to enforce, set to monitor",
			tmplData{true, map[string]string{"policy-mode": "enforce"}},
			"monitor",
			tmplData{true, map[string]string{"policy-mode": "monitor"}},
		}, {
			"policy mode set to enforce and other options, set to monitor",
			tmplData{true, map[string]string{"a": "b", "policy-mode": "enforce"}},
			"monitor",
			tmplData{true, map[string]string{"a": "b", "policy-mode": "monitor"}},
		},
	}

	tmpl := template.Must(template.New("yaml").Parse(yamlTemplate))
	for i := range tcs {
		c := &tcs[i]
		var inBld strings.Builder
		err := tmpl.Execute(&inBld, c.iData)
		require.NoError(t, err)
		in := inBld.String()

		var outBld strings.Builder
		err = tmpl.Execute(&outBld, c.oData)
		require.NoError(t, err)
		out := outBld.String()
		ret, err := PolicyYAMLSetMode([]byte(in), c.mode)
		require.NoError(t, err, fmt.Sprintf("unexpected error test %q", c.desc))
		require.Equal(t, out, string(ret), fmt.Sprintf("test %q failed", c.desc))
	}

}
