// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Tetragon bugtool code

package bugtool

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	gopssignal "github.com/google/gops/signal"
	"go.uber.org/multierr"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"

	"github.com/vishvananda/netlink"
)

// InitInfo contains information about how Tetragon was initialized.
type InitInfo struct {
	ExportFname string `json:"export_fname"`
	LibDir      string `json:"lib_dir"`
	BTFFname    string `json:"btf_fname"`
	ServerAddr  string `json:"server_address"`
	MetricsAddr string `json:"metrics_address"`
	GopsAddr    string `json:"gops_address"`
	MapDir      string `json:"map_dir"`
	BpfToolPath string `json:"bpftool_path"`
	GopsPath    string `json:"gops_path"`
	PID         int    `json:"pid"`
}

// LoadInitInfo returns the InitInfo by reading the info file from its default location
func LoadInitInfo() (*InitInfo, error) {
	return doLoadInitInfo(defaults.InitInfoFile)
}

// SaveInitInfo saves InitInfo to the info file
func SaveInitInfo(info *InitInfo) error {
	return doSaveInitInfo(defaults.InitInfoFile, info)
}

func doLoadInitInfo(fname string) (*InitInfo, error) {
	f, err := os.Open(fname)
	if err != nil {
		logger.GetLogger().Warn("failed to open file", "infoFile", fname)
		return nil, err
	}
	defer f.Close()

	var info InitInfo
	if err := json.NewDecoder(f).Decode(&info); err != nil {
		logger.GetLogger().Warn("failed to read information from file", "infoFile", fname)
		return nil, err
	}

	return &info, nil
}

func doSaveInitInfo(fname string, info *InitInfo) error {
	// Complete InitInfo here
	bpftool, err := exec.LookPath("bpftool")
	if err != nil {
		logger.GetLogger().Warn("failed to locate bpftool binary, on bugtool debugging ensure you have bpftool installed")
	} else {
		info.BpfToolPath = bpftool
		logger.GetLogger().Info("Successfully detected bpftool path", "bpftool", info.BpfToolPath)
	}

	gops, err := exec.LookPath("gops")
	if err != nil {
		logger.GetLogger().Warn("failed to locate gops binary, on bugtool debugging ensure you have gops installed")
	} else {
		info.GopsPath = gops
		logger.GetLogger().Info("Successfully detected gops path", "gops", info.GopsPath)
	}

	// Create DefaultRunDir if it does not already exist
	if err := os.MkdirAll(defaults.DefaultRunDir, 0755); err != nil {
		logger.GetLogger().Warn("failed to directory exists", "infoFile", fname)
		return err
	}
	f, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE, 0744)
	if err != nil {
		logger.GetLogger().Warn("failed to create file", "infoFile", fname)
		return err
	}
	defer f.Close()

	if err := f.Truncate(0); err != nil {
		logger.GetLogger().Warn("failed to truncate file", "infoFile", fname)
		return err
	}

	if err := json.NewEncoder(f).Encode(info); err != nil {
		logger.GetLogger().Warn("failed to write information to file", "infoFile", fname)
		return err
	}

	return nil
}

type bugtoolInfo struct {
	info      *InitInfo
	prefixDir string
	multiLog  MultiLog
	tarWriter *tar.Writer
}

func doTarAddBuff(tarWriter *tar.Writer, fname string, buff *bytes.Buffer) error {
	logHdr := tar.Header{
		Typeflag: tar.TypeReg,
		Name:     fname,
		Size:     int64(buff.Len()),
		Mode:     0644,
	}

	if err := tarWriter.WriteHeader(&logHdr); err != nil {
		logger.GetLogger().Error("failed to write log buffer tar header")
	}

	_, err := io.Copy(tarWriter, buff)
	if err != nil {
		logger.GetLogger().Error("failed to copy log buffer")
	}
	return err
}

func (s *bugtoolInfo) tarAddBuff(fname string, buff *bytes.Buffer) error {
	name := filepath.Join(s.prefixDir, fname)
	return doTarAddBuff(s.tarWriter, name, buff)
}

func (s *bugtoolInfo) TarAddJson(fname string, obj interface{}) error {
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return s.tarAddBuff(fname, bytes.NewBuffer(b))
}

func (s *bugtoolInfo) tarAddFile(fnameSrc string, fnameDst string) error {
	fileSrc, err := os.Open(fnameSrc)
	if err != nil {
		s.multiLog.WithField("path", fnameSrc).Warn("failed to open file")
		return err
	}
	defer fileSrc.Close()

	fileSrcInfo, err := fileSrc.Stat()
	if err != nil {
		s.multiLog.WithField("path", fnameSrc).Warn("failed to stat file")
		return err
	}

	hdr, err := tar.FileInfoHeader(fileSrcInfo, "" /* unused link target */)
	if err != nil {
		s.multiLog.Warn("error creating tar header")
		return err
	}
	hdr.Name = filepath.Join(s.prefixDir, fnameDst)

	if err := s.tarWriter.WriteHeader(hdr); err != nil {
		s.multiLog.Warn("failed to write tar header")
		return err
	}

	_, err = io.Copy(s.tarWriter, fileSrc)
	if err != nil {
		s.multiLog.WithError(err).WithField("fnameSrc", fnameSrc).Warn("error copying data from source file")
		return err
	}

	return nil
}

type Commander interface {
	ExecCmd(dstFname string, cmdName string, cmdArgs ...string) error
}

type GRPCer interface {
	TarAddJson(fname string, obj interface{}) error
}

type CommandAction func(Commander) error
type GRPCAction func(GRPCer) error

// Bugtool gathers information and writes it as a tar archive in the given filename.
// Additional command or grpc calls can be enqueued through last 2 params.
func Bugtool(outFname string, bpftool string, gops string, commandActions []CommandAction, grpcActions []GRPCAction) error {
	info, err := LoadInitInfo()
	if err != nil {
		return err
	}

	if bpftool != "" {
		info.BpfToolPath = bpftool
	}

	if gops != "" {
		info.GopsPath = gops
	}

	return doBugtool(info, outFname, commandActions, grpcActions)
}

func doBugtool(info *InitInfo, outFname string, commandActions []CommandAction, grpcActions []GRPCAction) error {
	// we log into two logs, one is the standard one and another one is a
	// buffer that we are going to include as a file into the bugtool archive.
	logBuff := new(bytes.Buffer)
	bugtoolLogger := slog.New(slog.NewTextHandler(logBuff, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	multiLog := MultiLog{
		Logs: []logger.FieldLogger{
			logger.GetLogger(),
			bugtoolLogger,
		},
	}
	prefixDir := "tetragon-bugtool-" + time.Now().Format("20060102150405")

	outFile, err := os.Create(outFname)
	if err != nil {
		multiLog.WithError(err).WithField("tarFile", outFname).Warn("failed to create bugtool tarfile")
		return err
	}
	defer outFile.Close()

	si := bugtoolInfo{
		info:      info,
		prefixDir: prefixDir,
		multiLog:  multiLog,
	}

	gzWriter := gzip.NewWriter(outFile)
	defer gzWriter.Close()

	si.tarWriter = tar.NewWriter(gzWriter)
	defer func() {
		defer si.tarWriter.Close()
		si.tarAddBuff("tetragon-bugtool.log", logBuff)
	}()

	si.addInitInfo()
	si.addLibFiles()
	si.addBTFFile()
	si.addTetragonLog()
	si.addMetrics()
	si.ExecCmd("dmesg.out", "dmesg")
	si.addTcInfo()
	si.addBpftoolInfo()
	si.addGopsInfo()
	si.dumpPolicyFilterMap()
	si.addGrpcInfo()
	si.addPmapOut()
	si.addMemCgroupStats()
	si.addBPFMapsStats()
	si.addTracefsTraceFile()

	// Additional command actions
	for _, action := range commandActions {
		action(&si)
	}

	// Additional grpc actions
	for _, action := range grpcActions {
		action(&si)
	}

	return nil
}

func (s *bugtoolInfo) addInitInfo() error {
	s.multiLog.Info("saving init info")
	buff := new(bytes.Buffer)
	if err := json.NewEncoder(buff).Encode(s.info); err != nil {
		s.multiLog.Warn("failed to serialze init info")
		return err
	}
	return s.tarAddBuff("tetragon-info.json", buff)
}

// addLibFiles adds all files under the hubble lib directory to the archive.
//
// Currently, this includes the bpf files and potentially the btf file if it is stored there.  If
// there are files that we do not want to add, we can filter them out, but for now we can just grab
// everything.
func (s *bugtoolInfo) addLibFiles() error {
	s.multiLog.WithField("libDir", s.info.LibDir).Info("retrieving lib directory")
	return filepath.Walk(
		s.info.LibDir,
		// NB: if the walk function returns an error, the walk terminates.
		// We want to gather as much information as possible, so we
		// never return an error.
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				s.multiLog.WithField("path", path).Warn("error walking path.")
				return nil
			}

			if info.IsDir() && info.Name() == "metadata" {
				s.multiLog.WithField("path", path).Info("skipping metadata directory")
				return filepath.SkipDir
			}

			// We ignore non-regular files.
			// Note that this also includes symbolic links. We could be smarter about
			// symlinks if they point within the directory we are archiving, but since
			// we do not use them, there is currently no reason for the complexity.
			mode := info.Mode()
			if !mode.IsRegular() && !mode.IsDir() {
				s.multiLog.WithField("path", path).Warn("not a regular file, ignoring")
				return nil
			}

			if !strings.HasSuffix(info.Name(), ".o") {
				s.multiLog.WithField("path", path).Warn("not an object file, ignoring")
				return nil
			}

			hdr, err := tar.FileInfoHeader(info, "" /* unused link target */)
			if err != nil {
				s.multiLog.WithField("path", path).Warn("error creating tar header")
				return nil
			}
			// fix filename
			hdr.Name = filepath.Join(s.prefixDir, "lib", strings.TrimPrefix(path, s.info.LibDir))

			if err := s.tarWriter.WriteHeader(hdr); err != nil {
				s.multiLog.WithField("path", path).Warn("failed to write tar header")
				return nil
			}

			if info.IsDir() {
				return nil
			}

			// open and copy file to the tar archive
			file, err := os.Open(path)
			if err != nil {
				s.multiLog.WithField("path", path).Warn("error opening file")
				return nil
			}
			defer file.Close()
			_, err = io.Copy(s.tarWriter, file)
			if err != nil {
				s.multiLog.WithField("path", path).Warn("error copying data from file")
				return nil
			}
			return nil
		})
}

// addBTFFile adds the btf file to the archive.
func (s *bugtoolInfo) addBTFFile() error {
	btfFname, err := filepath.EvalSymlinks(s.info.BTFFname)
	if err != nil && s.info.BTFFname != "" {
		s.multiLog.WithField("btfFname", s.info.BTFFname).Warnf("error resolving btf file: %s", err)
		return err
	}

	if s.info.BTFFname == "" {
		s.multiLog.Warnf("no btf filename in tetragon config, attempting to fall back to /sys/kernel/btf/vmlinux")
		btfFname = "/sys/kernel/btf/vmlinux"
	}

	if rel, err := filepath.Rel(s.info.LibDir, btfFname); err == nil && !strings.HasPrefix(rel, "..") {
		s.multiLog.WithField("btfFname", btfFname).Infof("btf file already in lib dir: %s", rel)
		return nil
	}

	err = s.tarAddFile(btfFname, "btf")
	if err == nil {
		s.multiLog.WithField("btfFname", btfFname).Info("btf file added")
	}
	return err
}

// addTetragonLog adds the tetragon log file to the archive
func (s *bugtoolInfo) addTetragonLog() error {
	if s.info.ExportFname == "" {
		s.multiLog.Info("no export file specified")
		return nil
	}

	err := s.tarAddFile(s.info.ExportFname, "tetragon.log")
	if err == nil {
		s.multiLog.WithField("exportFname", s.info.ExportFname).Info("tetragon log file added")
	}
	return err
}

// addMetrics adds the output of metrics in the tar file
func (s *bugtoolInfo) addMetrics() error {
	// nothing to do if metrics server is not running
	if s.info.MetricsAddr == "" {
		return nil
	}

	// determine the port that the metrics server listens to
	slice := strings.Split(s.info.MetricsAddr, ":")
	if len(slice) < 2 {
		s.multiLog.WithField("metricsAddr", s.info.MetricsAddr).Warn("could not determine metrics port")
		return errors.New("failed to determine metrics port")
	}
	port := slice[len(slice)-1]

	// contact metrics server
	metricsAddr := fmt.Sprintf("http://localhost:%s/metrics", port)
	s.multiLog.WithField("metricsAddr", metricsAddr).Info("contacting metrics server")
	resp, err := http.Get(metricsAddr)
	if err != nil {
		s.multiLog.WithField("metricsAddr", metricsAddr).WithField("err", err).Warn("failed to contact metrics server")
		return err
	}
	defer resp.Body.Close()

	buff := new(bytes.Buffer)
	if _, err = buff.ReadFrom(resp.Body); err != nil {
		s.multiLog.Warn("error in reading metrics server response: %s", err)
	}
	return s.tarAddBuff("metrics", buff)
}

// ExecCmd executes a command and saves its output (both stdout and stderr) to a file in the tar archive
func (s *bugtoolInfo) ExecCmd(dstFname string, cmdName string, cmdArgs ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, cmdName, cmdArgs...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		s.multiLog.Warnf("StdinPipe() failed: %s", err)
		return err
	}
	stdin.Close()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.multiLog.Warnf("StdoutPipe() failed: %v", err)
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		s.multiLog.Warnf("StderrPipe() failed: %v", err)
		return err
	}

	err = cmd.Start()
	if err != nil {
		s.multiLog.WithField("cmd", cmd).WithError(err).Warnf("failed to execute command")
		return err
	}
	// NB: copying everything to a buffer makes things easier because we can
	// compute the size of the file we want to write to the tar archive.
	// If, however, we use this with programs (not currently the case) that
	// have outputs too large for memory, this would be problematic because
	// it will lead to swapping or OOM.
	outbuff := new(bytes.Buffer)
	if _, err = outbuff.ReadFrom(stdout); err != nil {
		s.multiLog.WithField("cmd", cmd).WithError(err).Warnf("error reading stdout")
	}

	errbuff := new(bytes.Buffer)
	if _, err = errbuff.ReadFrom(stderr); err != nil {
		s.multiLog.WithField("cmd", cmd).WithError(err).Warnf("error reading stderr")
	}

	errStr := "0"
	err = cmd.Wait()
	if err != nil {
		errStr = err.Error()
	}
	s.multiLog.WithField("cmd", cmd).WithField("ret", errStr).WithField("dstFname", dstFname).Info("executed command")

	ret := s.tarAddBuff(dstFname, outbuff)
	if errbuff.Len() > 0 {
		errstderr := s.tarAddBuff(dstFname+".err", errbuff)
		ret = multierr.Append(ret, errstderr)
	}
	return ret
}

// addTcInfo adds information about tc filters on the devices
func (s *bugtoolInfo) addTcInfo() error {
	links, err := netlink.LinkList()
	if err != nil {
		s.multiLog.WithError(err).Warn("listing devices failed")
		return err
	}

	// NB: We could save the interfaces that tetragon installed programs and
	// query only those by saving the interfaces to the info file. Instead,
	// we perform the command for all links in the system. This is simpler
	// and also provides additional information that may be useful.
	for _, link := range links {
		linkName := link.Attrs().Name
		s.ExecCmd(fmt.Sprintf("tc-info.%s.ingress", linkName), "tc", "filter", "show", "dev", linkName, "ingress")
		s.ExecCmd(fmt.Sprintf("tc-info.%s.egress", linkName), "tc", "filter", "show", "dev", linkName, "egress")
	}

	return err
}

// addBpftoolInfo adds information about loaded eBPF maps and programs
func (s *bugtoolInfo) addBpftoolInfo() {
	if s.info.BpfToolPath == "" {
		s.multiLog.Warn("Failed to locate bpftool, please install it and specify its path")
		return
	}

	_, err := os.Stat(s.info.BpfToolPath)
	if err != nil {
		s.multiLog.WithError(err).Warn("Failed to locate bpftool. Please install it or specify its path, see 'bugtool --help'")
		return
	}
	s.ExecCmd("bpftool-maps.json", s.info.BpfToolPath, "map", "show", "-j")
	s.ExecCmd("bpftool-progs.json", s.info.BpfToolPath, "prog", "show", "-j")
	s.ExecCmd("bpftool-cgroups.json", s.info.BpfToolPath, "cgroup", "tree", "-j")
}

func (s *bugtoolInfo) getPProf(file string, gopsSignal byte) error {
	if s.info.GopsAddr == "" {
		s.multiLog.Info("Skipping gops dump info as daemon is running without gops, use --gops-address to enable gops")
		return nil
	}

	s.multiLog.WithField("gops-address", s.info.GopsAddr).Info("Contacting gops server for pprof dump")

	conn, err := net.Dial("tcp", s.info.GopsAddr)
	if err != nil {
		s.multiLog.WithField("gops-address", s.info.GopsAddr).WithError(err).Warn("Failed to contact gops server")
		return err
	}

	buf := []byte{gopsSignal}
	if _, err := conn.Write(buf); err != nil {
		s.multiLog.WithField("gops-address", s.info.GopsAddr).WithField("file", file).WithError(err).Warn("Failed to send gops pprof command")
		return err
	}

	buff := new(bytes.Buffer)
	if _, err = buff.ReadFrom(conn); err != nil {
		s.multiLog.WithField("gops-address", s.info.GopsAddr).WithField("file", file).WithError(err).Warn("Failed reading gops pprof response")
	}
	return s.tarAddBuff(file, buff)
}

func (s *bugtoolInfo) addGopsInfo() {
	if s.info.GopsAddr == "" {
		s.multiLog.Info("Skipping gops dump info as daemon is running without gops, use --gops-address to enable gops")
		return
	}

	if s.info.GopsPath == "" {
		s.multiLog.WithField("gops-address", s.info.GopsAddr).Warn("Failed to locate gops. Please install it or specify its path, see 'bugtool --help'")
		return
	}

	_, err := os.Stat(s.info.GopsPath)
	if err != nil {
		s.multiLog.WithField("gops-address", s.info.GopsAddr).WithError(err).Warn("Failed to locate gops, please install it")
		return
	}

	s.multiLog.WithField("gops-address", s.info.GopsAddr).WithField("gops-path", s.info.GopsPath).Info("Dumping gops information")

	s.ExecCmd("gops.stack", s.info.GopsPath, "stack", s.info.GopsAddr)
	s.ExecCmd("gops.stats", s.info.GopsPath, "stats", s.info.GopsAddr)
	s.ExecCmd("gops.memstats", s.info.GopsPath, "memstats", s.info.GopsAddr)
	profiles := map[string]byte{
		"cpu":  gopssignal.CPUProfile,
		"heap": gopssignal.HeapProfile,
	}
	for name, signal := range profiles {
		err = s.getPProf("gops.pprof-"+name, signal)
		if err != nil {
			s.multiLog.
				WithField("gops-address", s.info.GopsAddr).
				WithField("gops-path", s.info.GopsPath).
				WithField("profile", name).
				WithError(err).
				Warn("Failed to dump gops pprof")
		} else {
			s.multiLog.
				WithField("gops-address", s.info.GopsAddr).
				WithField("gops-path", s.info.GopsPath).
				WithField("profile", name).
				Info("Successfully dumped gops pprof")
		}
	}
}

func (s *bugtoolInfo) dumpPolicyFilterMap() error {
	fname := path.Join(s.info.MapDir, policyfilter.MapName)
	m, err := policyfilter.OpenMap(fname)
	if err != nil {
		s.multiLog.WithError(err).Warnf("failed to open policyfilter map")
		return err
	}

	obj, err := m.Dump()
	if err != nil {
		s.multiLog.WithError(err).Warnf("failed to dump policyfilter map")
		return err
	}
	return s.TarAddJson(policyfilter.MapName+".json", obj)
}

func (s *bugtoolInfo) addGrpcInfo() {
	c, err := common.NewClient(context.Background(), s.info.ServerAddr, 5*time.Second)
	if err != nil {
		s.multiLog.Warnf("failed to create gRPC client to %s: %v", s.info.ServerAddr, err)
		return
	}
	defer c.Close()

	res, err := c.Client.ListTracingPolicies(c.Ctx, &tetragon.ListTracingPoliciesRequest{})
	if err != nil || res == nil {
		s.multiLog.Warnf("failed to list tracing policies: %v", err)
		return
	}

	fname := "tracing-policies.json"
	err = s.TarAddJson(fname, res)
	if err != nil {
		s.multiLog.Warnf("failed to dump tracing policies: %v", err)
		return
	}

	s.multiLog.Infof("dumped tracing policies in %s", fname)
}

func (s bugtoolInfo) addPmapOut() error {
	pmap, err := exec.LookPath("pmap")
	if err != nil {
		s.multiLog.WithError(err).Warn("Failed to locate pmap. Please install it.")
		return fmt.Errorf("failed to locate pmap: %w", err)
	}

	s.ExecCmd("pmap.out", pmap, "-x", strconv.Itoa(s.info.PID))
	return nil
}

func findCgroupMountPath(r io.Reader, unified bool, controller string) (string, error) {
	cgroupName := "cgroup"
	if unified {
		cgroupName = "cgroup2"
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 3 && (fields[2] == cgroupName) {
			if unified || !unified && strings.HasSuffix(fields[1], controller) {
				return fields[1], nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading /proc/mounts: %w", err)
	}

	return "", errors.New("cgroup filesystem not found")
}

func FindCgroupMountPath(unified bool, controller string) (string, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return "", fmt.Errorf("failed to open /proc/mounts: %w", err)
	}
	defer file.Close()
	return findCgroupMountPath(file, unified, controller)
}

func findMemoryCgroupPath(r io.Reader) (bool, string, error) {
	var unified bool
	var memoryCgroupPath string

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		// '/proc/$PID/cgroup' lists a process's cgroup membership. If legacy cgroup is
		// in use in the system, this file may contain multiple lines, one for each
		// hierarchy. The entry for cgroup v2 is always in the format '0::$PATH'.
		if strings.HasPrefix(line, "0::/") {
			unified = true
			memoryCgroupPath = strings.TrimPrefix(line, "0::")

			// we don't break here because we want to consider cases in which
			// cgroup v2 line is before other cgroup v1 lines and we want to
			// consider hybrid as v1, not sure it can happen in real life
			continue
		}

		// Parsing for cgroup v1, consider hybrid as v1
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 {
			if parts[1] == "memory" {
				unified = false
				memoryCgroupPath = parts[2]
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return false, "", fmt.Errorf("failed reading /proc/self/cgroup: %w", err)
	}

	return unified, memoryCgroupPath, nil
}

func FindMemoryCgroupPath() (unified bool, memoryCgroupPath string, err error) {
	file, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return false, "", fmt.Errorf("failed to open /proc/self/cgroup: %w", err)
	}
	defer file.Close()
	return findMemoryCgroupPath(file)
}

func (s bugtoolInfo) addMemCgroupStats() error {
	unifiedCgroup, memoryCgroupPath, err := FindMemoryCgroupPath()
	if err != nil {
		s.multiLog.WithError(err).Warn("failed finding the memory cgroup path")
		return fmt.Errorf("failed to find memory cgroup path: %w", err)
	}

	cgroupMountPath, err := FindCgroupMountPath(unifiedCgroup, "memory")
	if err != nil {
		s.multiLog.WithError(err).Warn("failed to find cgroup mount path")
		return fmt.Errorf("failed to find cgroup mount path: %w", err)
	}

	cgroupPath := filepath.Join(cgroupMountPath, memoryCgroupPath)

	// can't use s.tarAddFile here unfortunately because it is using io.Copy
	// based on the size retrieved from the stat of the file, and cgroup fs
	// files have size equal to 0
	readAndWrite := func(cgroupBasePath string, file string) error {
		buf, err := os.ReadFile(filepath.Join(cgroupBasePath, file))
		if err != nil {
			s.multiLog.WithError(err).WithField("file", file).Warn("failed to read cgroup file")
			return fmt.Errorf("failed to read file %s: %w", file, err)
		}
		err = s.tarAddBuff(file, bytes.NewBuffer(buf))
		if err == nil {
			s.multiLog.WithField("file", file).Info("cgroup file added")
			return fmt.Errorf("failed to add buffer: %w", err)
		}
		return nil
	}

	if unifiedCgroup {
		readAndWrite(cgroupPath, "memory.current")
		readAndWrite(cgroupPath, "memory.stat")
	} else {
		err := readAndWrite(cgroupPath, "memory.usage_in_bytes")
		if err != nil {
			// Before cgroup namespace, /proc/pid/cgroup mapping was broken, so
			// Docker back in the days mounted the cgroup hierarchy flat in the
			// containerfs.  For compatibility, it still does that for cgroup v1.
			// See more https://lewisgaul.co.uk/blog/coding/2022/05/13/cgroups-intro/#cgroups-and-containers
			cgroupPath = cgroupMountPath
			s.multiLog.WithField("cgroupPath", cgroupPath).Info("retrying to read cgroup file from a different legacy path")
			readAndWrite(cgroupPath, "memory.usage_in_bytes")
		}
		readAndWrite(cgroupPath, "memory.kmem.usage_in_bytes")
		readAndWrite(cgroupPath, "memory.stat")
	}

	return nil
}

func (s bugtoolInfo) addBPFMapsStats() error {
	out, err := RunMapsChecks(TetragonBPFFS)
	if err != nil {
		s.multiLog.WithError(err).Warn("failed to run BPF maps checks")
		return fmt.Errorf("failed to run BPF maps checks: %w", err)
	}

	const file = "debugmaps.json"
	err = s.TarAddJson(file, out)
	if err != nil {
		s.multiLog.WithError(err).Warn("failed to add the BPF maps checks to the tar archive")
		return err
	}
	s.multiLog.WithField("file", file).Info("BPF maps checks added")
	return nil
}

func (s *bugtoolInfo) addTracefsTraceFile() {
	err := s.ExecCmd("trace", "cat", "/sys/kernel/tracing/trace")
	if err != nil {
		s.multiLog.Warnf("failed to get trace file: %v", err)
	}
}
