// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/pelletier/go-toml"
	tomlparser "github.com/pelletier/go-toml/v2/unstable"
)

type patchCrioConf struct {
	EnableAnnotations enableAnnotations `cmd:"" help:"enable annotations"`
}

type enableAnnotations struct {
	ConfFile    string   `name:"config-file" default:"/etc/crio/crio.conf" help:"crio configuration file location (input) (${default}))"`
	Outfile     string   `name:"output-file" default:"" help:"output file location"`
	Annotations []string `name:"annotations"`
}

func doEnableAnnotations(log *slog.Logger, c *enableAnnotations) ([]addLine, error) {
	data, err := os.ReadFile(c.ConfFile)
	if err != nil {
		return nil, err
	}

	p := tomlparser.Parser{
		KeepComments: true,
	}
	p.Reset(data)

	lines := []addLine{}
	insideRuntime := false
	var annotationsLoc tomlparser.Shape
	for p.NextExpression() {
		e := p.Expression()
		switch insideRuntime {
		case false:
			if e.Kind == tomlparser.Table {
				c := e.Child()
				if c == nil || c.Kind != tomlparser.Key || string(c.Data) != "crio" {
					continue
				}
				c = c.Next()
				if c == nil || c.Kind != tomlparser.Key || string(c.Data) != "runtime" {
					continue
				}
				c = c.Next()
				if c == nil || c.Kind != tomlparser.Key || string(c.Data) != "runtimes" {
					continue
				}
				c = c.Next()
				if c == nil || c.Kind != tomlparser.Key {
					continue
				}
				insideRuntime = true
			}
		case true:
			foundAnnotations := false
			done := false
			annotations := []string{}
			if e.Kind == tomlparser.KeyValue {
				var array *tomlparser.Node
				for c := e.Child(); c != nil; c = c.Next() {
					annotationsLoc = p.Shape(c.Raw)
					if c.Kind == tomlparser.Key && string(c.Data) == "allowed_annotations" {
						foundAnnotations = true
					} else if c.Kind == tomlparser.Array {
						array = c
					}

					if foundAnnotations && array != nil {
						for cc := array.Child(); cc != nil; cc = cc.Next() {
							if cc.Kind == tomlparser.String {
								annotations = append(annotations, string(cc.Data))
							}
						}
						break
					}
				}

			} else {
				done = true
			}

			if foundAnnotations || done {
				annotations = append(annotations, c.Annotations...)
				qannotations := make([]string, 0, len(annotations))
				for _, a := range annotations {
					qannotations = append(qannotations, fmt.Sprintf("%q", a))
				}
				insideRuntime = false
				lines = append(lines, addLine{
					pos:         toml.Position{Col: annotationsLoc.Start.Column, Line: annotationsLoc.Start.Line},
					line:        fmt.Sprintf("allowed_annotations = [%s]", strings.Join(qannotations, ", ")),
					replaceLine: foundAnnotations,
				})
			}
		}
	}

	return lines, nil

}

func (c *enableAnnotations) Run(log *slog.Logger) error {

	changes, err := doEnableAnnotations(log, c)
	if len(changes) == 0 {
		log.Info("nothing to do")
		return nil
	}

	outFname := c.Outfile
	if outFname == "" {
		f, err := os.CreateTemp("", "crio.*.conf")
		if err != nil {
			return err
		}
		outFname = f.Name()
		f.Close()
	}

	err = applyChanges(c.ConfFile, outFname, changes)
	if err != nil {
		return err
	}
	log.Info("written output", "filename", outFname)
	return nil

}
