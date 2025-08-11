// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package encoder

import (
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type Colorer struct {
	Colors  []*color.Color
	Red     *color.Color
	Green   *color.Color
	Blue    *color.Color
	Cyan    *color.Color
	Magenta *color.Color
	Yellow  *color.Color
}

func NewColorer(when ColorMode) *Colorer {
	red := color.New(color.FgRed)
	green := color.New(color.FgGreen)
	blue := color.New(color.FgBlue)
	cyan := color.New(color.FgCyan)
	magenta := color.New(color.FgMagenta)
	yellow := color.New(color.FgYellow)

	c := &Colorer{
		Red:     red,
		Green:   green,
		Blue:    blue,
		Cyan:    cyan,
		Magenta: magenta,
		Yellow:  yellow,
	}

	c.Colors = []*color.Color{
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

func (c *Colorer) auto() {
	for _, v := range c.Colors {
		if color.NoColor { // NoColor is global and set dynamically
			v.DisableColor()
		} else {
			v.EnableColor()
		}
	}
}

func (c *Colorer) enable() {
	for _, v := range c.Colors {
		v.EnableColor()
	}
}

func (c *Colorer) disable() {
	for _, v := range c.Colors {
		v.DisableColor()
	}
}

func printCap(c int) bool {
	switch c {
	case int(tetragon.CapabilitiesType_CAP_SYS_ADMIN):
		return true
	}
	return false
}

func processCaps(c *tetragon.Capabilities) string {
	var caps []string

	if c == nil {
		return ""
	}

	for e := range c.Effective {
		if printCap(e) {
			caps = append(caps, tetragon.CapabilitiesType_name[int32(e)])
		}
	}

	capsString := strings.Join(caps, ",")
	if len(caps) > 0 {
		capsString = "🛑 " + capsString
	}
	return capsString
}

func (c *Colorer) ProcessInfo(host string, process *tetragon.Process) (string, string) {
	source := c.Green.Sprint(host)
	if process.Pod != nil {
		source = c.Green.Sprint(process.Pod.Namespace, "/", process.Pod.Name)
	}
	proc := c.Magenta.Sprint(process.Binary)
	caps := c.Magenta.Sprint(processCaps(process.Cap))
	return fmt.Sprintf("%s %s", source, proc), caps
}
