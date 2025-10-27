// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracepoint

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	tracepointsPath = "/sys/kernel/tracing/events"
)

// Tracepoint represents the information of a Linux tracepoint
type Tracepoint struct {
	Subsys string
	Event  string
	Format *Format
}

// Format contains the details for the tracepoint: name, id, and fields
type Format struct {
	Name   string
	ID     int
	Fields []FieldFormat
}

// FieldFormat describes the format for each of the tracepoint fields
type FieldFormat struct {
	FieldStr string
	Field    *Field
	Offset   uint
	Size     uint
	IsSigned bool
}

func (tff *FieldFormat) ParseField() error {
	ty, err := parseField(tff.FieldStr)
	if err != nil {
		return err
	}
	tff.Field = ty
	return nil
}

// LoadFormat loads the format of a tracepoint from /sys/kernel/tracing
func (gt *Tracepoint) LoadFormat() error {
	gtf, err := tracepointLoadFormat(gt.Subsys, gt.Event)
	if err == nil {
		gt.Format = gtf
	}
	return err
}

// tracepointLoadFormat is the low-level function for loading the format of the given tracepoint
//
// For reference:
// # cat /sys/kernel/tracing/events/syscalls/sys_enter_lseek/format
// name: sys_enter_lseek
// ID: 682
// format:
//
//	field:unsigned short common_type;       offset:0;       size:2; signed:0;
//	field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//	field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//	field:int common_pid;   offset:4;       size:4; signed:1;
//
//	field:int __syscall_nr; offset:8;       size:4; signed:1;
//	field:unsigned int fd;  offset:16;      size:8; signed:0;
//	field:off_t offset;     offset:24;      size:8; signed:0;
//	field:unsigned int whence;      offset:32;      size:8; signed:0;
func tracepointLoadFormat(subsys string, event string) (*Format, error) {
	fname := fmt.Sprintf("%s/%s/%s/format", tracepointsPath, subsys, event)
	f, err := os.Open(fname)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tracepoint format: %w", err)
	}
	defer f.Close()

	var ret Format
	var ok bool
	scanner := bufio.NewScanner(f)

	errEmptyLine := errors.New("empty line")
	errPrintFormatLine := errors.New("print format line")

	getMatches := func(regexp *regexp.Regexp, errMsg string) ([]string, error) {
		ok = scanner.Scan()
		if ok {
			text := scanner.Text()
			if text == "" {
				return nil, errEmptyLine
			}
			if strings.HasPrefix(text, "print fmt:") {
				return nil, errPrintFormatLine
			}
			result := regexp.FindStringSubmatch(text)
			if len(result) > regexp.NumSubexp() {
				return result, nil
			}
			return nil, fmt.Errorf("%s: failed to match regular expression (->%s<- vs ->%s<-)", errMsg, regexp.String(), text)
		}

		err := scanner.Err()
		if err == nil {
			err = io.EOF
		}
		return nil, err
	}

	nameRe := regexp.MustCompile(`name: (\w+)`)
	res, err := getMatches(nameRe, "parsing name field")
	if err != nil {
		return nil, err
	}
	ret.Name = res[1]

	idRe := regexp.MustCompile(`ID: (\d+)`)
	res, err = getMatches(idRe, "parsing id field")
	if err != nil {
		return nil, err
	}
	id, err := strconv.Atoi(res[1])
	if err != nil {
		return nil, fmt.Errorf("parsing id field: failed: %w", err)
	}
	ret.ID = id

	formatRe := regexp.MustCompile(`format:`)
	if _, err := getMatches(formatRe, "parsing format string"); err != nil {
		return nil, err
	}

	fieldRe := regexp.MustCompile(`\tfield:([^;]+);\toffset:(\d+);\tsize:(\d+);\tsigned:(0|1);`)

FieldsLoop:
	for {
		res, err := getMatches(fieldRe, "parsing fields")
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				break FieldsLoop
			case errors.Is(err, errEmptyLine):
				continue FieldsLoop
			case errors.Is(err, errPrintFormatLine):
				break FieldsLoop
			default:
				return nil, err
			}
		}

		offset64, err := strconv.ParseUint(res[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parsing ofset field failed: %w", err)
		}

		size64, err := strconv.ParseUint(res[3], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parsing size field failed: %w", err)
		}

		isSigned, err := strconv.ParseBool(res[4])
		if err != nil {
			return nil, fmt.Errorf("parsing signed field failed: %w", err)
		}

		ret.Fields = append(ret.Fields, FieldFormat{
			FieldStr: res[1],
			Offset:   uint(offset64),
			Size:     uint(size64),
			IsSigned: isSigned,
		})
	}

	return &ret, nil
}

// GetAllTracepoints iterates the tracepointsPath directory and returns all events found there.
// The Format field for this events is going to be empty. Callers can call LoadFormat() to fill it.
func GetAllTracepoints() ([]Tracepoint, error) {
	ret := []Tracepoint{}
	err := filepath.Walk(tracepointsPath, func(path string, info fs.FileInfo, _ error) error {
		if info.IsDir() {
			name := strings.TrimPrefix(path, tracepointsPath+"/")
			arr := strings.Split(name, "/")
			if len(arr) == 2 {
				ret = append(ret, Tracepoint{
					Subsys: arr[0],
					Event:  arr[1],
				})
				return filepath.SkipDir
			}

		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}
