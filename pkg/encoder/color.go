// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package encoder

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/api/v1/fgs"
	"github.com/fatih/color"
)

type colorer struct {
	colors  []*color.Color
	red     *color.Color
	green   *color.Color
	blue    *color.Color
	cyan    *color.Color
	magenta *color.Color
	yellow  *color.Color
}

func newColorer(when ColorMode) *colorer {
	red := color.New(color.FgRed)
	green := color.New(color.FgGreen)
	blue := color.New(color.FgBlue)
	cyan := color.New(color.FgCyan)
	magenta := color.New(color.FgMagenta)
	yellow := color.New(color.FgYellow)

	c := &colorer{
		red:     red,
		green:   green,
		blue:    blue,
		cyan:    cyan,
		magenta: magenta,
		yellow:  yellow,
	}

	c.colors = []*color.Color{
		red, green, blue,
		cyan, magenta, yellow,
	}
	switch when {
	case Always:
		c.enable()
	case Never:
		c.disable()
	case Auto:
		c.auto()
	}
	return c
}

func (c *colorer) auto() {
	for _, v := range c.colors {
		if color.NoColor { // NoColor is global and set dynamically
			v.DisableColor()
		} else {
			v.EnableColor()
		}
	}
}

func (c *colorer) enable() {
	for _, v := range c.colors {
		v.EnableColor()
	}
}

func (c *colorer) disable() {
	for _, v := range c.colors {
		v.DisableColor()
	}
}

func printCap(c int) bool {
	switch c {
	case int(fgs.CapabilitiesType_CAP_SYS_ADMIN):
		return true
	}
	return false
}

func processCaps(c *fgs.Capabilities) string {
	var caps []string

	if c == nil {
		return ""
	}

	for e := range c.Effective {
		if printCap(e) {
			caps = append(caps, fgs.CapabilitiesType_name[int32(e)])
		}
	}

	capsString := strings.Join(caps, ",")
	if len(caps) > 0 {
		capsString = "🛑 " + capsString
	}
	return capsString
}

func (c colorer) processInfo(host string, process *fgs.Process) (string, string) {
	source := c.green.Sprint(host)
	if process.Pod != nil {
		source = c.green.Sprint(process.Pod.Namespace, "/", process.Pod.Name)
	}
	proc := c.magenta.Sprint(process.Binary)
	caps := c.magenta.Sprint(processCaps(process.Cap))
	return fmt.Sprintf("%s %s", source, proc), caps
}
