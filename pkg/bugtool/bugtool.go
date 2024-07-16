// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Tetragon bugtool code

package bugtool

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	gopssignal "github.com/google/gops/signal"
	"go.uber.org/multierr"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// InitInfo contains information about how Tetragon was initialized.
type InitInfo struct {
	ExportFname string `json:"export_fname"`
	LibDir      string `json:"lib_dir"`
	BtfFname    string `json:"btf_fname"`
	ServerAddr  string `json:"server_address"`
	MetricsAddr string `json:"metrics_address"`
	GopsAddr    string `json:"gops_address"`
	MapDir      string `json:"map_dir"`
	BpfToolPath string `json:"bpftool_path"`
	GopsPath    string `json:"gops_path"`
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
		logger.GetLogger().WithField("infoFile", fname).Warn("failed to open file")
		return nil, err
	}
	defer f.Close()

	var info InitInfo
	if err := json.NewDecoder(f).Decode(&info); err != nil {
		logger.GetLogger().WithField("infoFile", fname).Warn("failed to read information from file")
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
		logger.GetLogger().WithField("bpftool", info.BpfToolPath).Info("Successfully detected bpftool path")
	}

	gops, err := exec.LookPath("gops")
	if err != nil {
		logger.GetLogger().Warn("failed to locate gops binary, on bugtool debugging ensure you have gops installed")
	} else {
		info.GopsPath = gops
		logger.GetLogger().WithField("gops", info.GopsPath).Info("Successfully detected gops path")
	}

	// Create DefaultRunDir if it does not already exist
	if err := os.MkdirAll(defaults.DefaultRunDir, 0755); err != nil {
		logger.GetLogger().WithField("infoFile", fname).Warn("failed to directory exists")
		return err
	}
	f, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE, 0744)
	if err != nil {
		logger.GetLogger().WithField("infoFile", fname).Warn("failed to create file")
		return err
	}
	defer f.Close()

	if err := f.Truncate(0); err != nil {
		logger.GetLogger().WithField("infoFile", fname).Warn("failed to truncate file")
		return err
	}

	if err := json.NewEncoder(f).Encode(info); err != nil {
		logger.GetLogger().WithField("infoFile", fname).Warn("failed to write information to file")
		return err
	}

	return nil
}

type bugtoolInfo struct {
	info      *InitInfo
	prefixDir string
	multiLog  MultiLog
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

func (s *bugtoolInfo) tarAddBuff(tarWriter *tar.Writer, fname string, buff *bytes.Buffer) error {
	name := filepath.Join(s.prefixDir, fname)
	return doTarAddBuff(tarWriter, name, buff)
}

func (s *bugtoolInfo) tarAddJson(tarWriter *tar.Writer, fname string, obj interface{}) error {
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return s.tarAddBuff(tarWriter, fname, bytes.NewBuffer(b))
}

func (s *bugtoolInfo) tarAddFile(tarWriter *tar.Writer, fnameSrc string, fnameDst string) error {
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

	if err := tarWriter.WriteHeader(hdr); err != nil {
		s.multiLog.Warn("failed to write tar header")
		return err
	}

	_, err = io.Copy(tarWriter, fileSrc)
	if err != nil {
		s.multiLog.WithField("fnameSrc", fnameSrc).Warn("error copying data from source file")
		return err
	}

	return nil
}

// Bugtool gathers information and writes it as a tar archive in the given filename
func Bugtool(outFname string, bpftool string, gops string) error {
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

	return doBugtool(info, outFname)
}

func doBugtool(info *InitInfo, outFname string) error {
	// we log into two logs, one is the standard one and another one is a
	// buffer that we are going to include as a file into the bugtool archive.
	bugtoolLogger := logrus.New()
	logBuff := new(bytes.Buffer)
	bugtoolLogger.Out = logBuff
	logrus.SetLevel(logrus.InfoLevel)
	multiLog := MultiLog{
		Logs: []logrus.FieldLogger{
			logger.GetLogger(),
			bugtoolLogger,
		},
	}
	prefixDir := fmt.Sprintf("tetragon-bugtool-%s", time.Now().Format("20060102150405"))

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

	tarWriter := tar.NewWriter(gzWriter)
	defer func() {
		defer tarWriter.Close()
		si.tarAddBuff(tarWriter, "tetragon-bugtool.log", logBuff)
	}()

	si.addInitInfo(tarWriter)
	si.addLibFiles(tarWriter)
	si.addBtfFile(tarWriter)
	si.addTetragonLog(tarWriter)
	si.addMetrics(tarWriter)
	si.execCmd(tarWriter, "dmesg.out", "dmesg")
	si.addTcInfo(tarWriter)
	si.addBpftoolInfo(tarWriter)
	si.addGopsInfo(tarWriter)
	si.dumpPolicyFilterMap(tarWriter)
	si.addGrpcInfo(tarWriter)
	return nil
}

func (s *bugtoolInfo) addInitInfo(tarWriter *tar.Writer) error {
	s.multiLog.Info("saving init info")
	buff := new(bytes.Buffer)
	if err := json.NewEncoder(buff).Encode(s.info); err != nil {
		s.multiLog.Warn("failed to serialze init info")
		return err
	}
	return s.tarAddBuff(tarWriter, "tetragon-info.json", buff)
}

// addLibFiles adds all files under the hubble lib directory to the archive.
//
// Currently, this includes the bpf files and potentially the btf file if it is stored there.  If
// there are files that we do not want to add, we can filter them out, but for now we can just grab
// everything.
func (s *bugtoolInfo) addLibFiles(tarWriter *tar.Writer) error {
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
			if !(mode.IsRegular() || mode.IsDir()) {
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

			if err := tarWriter.WriteHeader(hdr); err != nil {
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
			_, err = io.Copy(tarWriter, file)
			if err != nil {
				s.multiLog.WithField("path", path).Warn("error copying data from file")
				return nil
			}
			return nil
		})
}

// addBtfFile adds the btf file to the archive.
func (s *bugtoolInfo) addBtfFile(tarWriter *tar.Writer) error {
	btfFname, err := filepath.EvalSymlinks(s.info.BtfFname)
	if err != nil && s.info.BtfFname != "" {
		s.multiLog.WithField("btfFname", s.info.BtfFname).Warnf("error resolving btf file: %s", err)
		return err
	}

	if s.info.BtfFname == "" {
		s.multiLog.Warnf("no btf filename in tetragon config, attempting to fall back to /sys/kernel/btf/vmlinux")
		btfFname = "/sys/kernel/btf/vmlinux"
	}

	if rel, err := filepath.Rel(s.info.LibDir, btfFname); err == nil && !strings.HasPrefix(rel, "..") {
		s.multiLog.WithField("btfFname", btfFname).Infof("btf file already in lib dir: %s", rel)
		return nil
	}

	err = s.tarAddFile(tarWriter, btfFname, "btf")
	if err == nil {
		s.multiLog.WithField("btfFname", btfFname).Info("btf file added")
	}
	return err
}

// addTetragonLog adds the tetragon log file to the archive
func (s *bugtoolInfo) addTetragonLog(tarWriter *tar.Writer) error {
	if s.info.ExportFname == "" {
		s.multiLog.Info("no export file specified")
		return nil
	}

	err := s.tarAddFile(tarWriter, s.info.ExportFname, "tetragon.log")
	if err == nil {
		s.multiLog.WithField("exportFname", s.info.ExportFname).Info("tetragon log file added")
	}
	return err
}

// addMetrics adds the output of metrics in the tar file
func (s *bugtoolInfo) addMetrics(tarWriter *tar.Writer) error {
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
	return s.tarAddBuff(tarWriter, "metrics", buff)
}

// execCmd executes a command and saves its output (both stdout and stderr) to a file in the tar archive
func (s *bugtoolInfo) execCmd(tarWriter *tar.Writer, dstFname string, cmdName string, cmdArgs ...string) error {
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

	ret := s.tarAddBuff(tarWriter, dstFname, outbuff)
	if errbuff.Len() > 0 {
		errstderr := s.tarAddBuff(tarWriter, dstFname+".err", errbuff)
		ret = multierr.Append(ret, errstderr)
	}
	return ret
}

// addTcInfo adds information about tc filters on the devices
func (s *bugtoolInfo) addTcInfo(tarWriter *tar.Writer) error {
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
		s.execCmd(tarWriter, fmt.Sprintf("tc-info.%s.ingress", linkName), "tc", "filter", "show", "dev", linkName, "ingress")
		s.execCmd(tarWriter, fmt.Sprintf("tc-info.%s.egress", linkName), "tc", "filter", "show", "dev", linkName, "egress")
	}

	return err
}

// addBpftoolInfo adds information about loaded eBPF maps and programs
func (s *bugtoolInfo) addBpftoolInfo(tarWriter *tar.Writer) {
	if s.info.BpfToolPath == "" {
		s.multiLog.Warn("Failed to locate bpftool, please install it and specify its path")
		return
	}

	_, err := os.Stat(s.info.BpfToolPath)
	if err != nil {
		s.multiLog.WithError(err).Warn("Failed to locate bpftool. Please install it or specify its path, see 'bugtool --help'")
		return
	}
	s.execCmd(tarWriter, "bpftool-maps.json", s.info.BpfToolPath, "map", "show", "-j")
	s.execCmd(tarWriter, "bpftool-progs.json", s.info.BpfToolPath, "prog", "show", "-j")
	s.execCmd(tarWriter, "bpftool-cgroups.json", s.info.BpfToolPath, "cgroup", "tree", "-j")
}

func (s *bugtoolInfo) getPProf(tarWriter *tar.Writer, file string) error {
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

	buf := []byte{gopssignal.HeapProfile}
	if _, err := conn.Write(buf); err != nil {
		s.multiLog.WithField("gops-address", s.info.GopsAddr).WithError(err).Warn("Failed to send gops pprof-heap command")
		return err
	}

	buff := new(bytes.Buffer)
	if _, err = buff.ReadFrom(conn); err != nil {
		s.multiLog.WithField("gops-address", s.info.GopsAddr).WithError(err).Warn("Failed reading gops pprof-heap response")
	}
	return s.tarAddBuff(tarWriter, file, buff)
}

func (s *bugtoolInfo) addGopsInfo(tarWriter *tar.Writer) {
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

	s.execCmd(tarWriter, "gops.stack", s.info.GopsPath, "stack", s.info.GopsAddr)
	s.execCmd(tarWriter, "gops.stats", s.info.GopsPath, "stats", s.info.GopsAddr)
	s.execCmd(tarWriter, "gops.memstats", s.info.GopsPath, "memstats", s.info.GopsAddr)
	err = s.getPProf(tarWriter, "gops.pprof-heap")
	if err != nil {
		s.multiLog.WithField("gops-address", s.info.GopsAddr).WithField("gops-path", s.info.GopsPath).WithError(err).Warn("Failed to dump gops pprof-heap")
	} else {
		s.multiLog.WithField("gops-address", s.info.GopsAddr).WithField("gops-path", s.info.GopsPath).Info("Successfully dumped gops pprof-heap")
	}
}

func (s *bugtoolInfo) dumpPolicyFilterMap(tarWriter *tar.Writer) error {
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
	return s.tarAddJson(tarWriter, policyfilter.MapName+".json", obj)
}

func (s *bugtoolInfo) addGrpcInfo(tarWriter *tar.Writer) {
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
	err = s.tarAddJson(tarWriter, fname, res)
	if err != nil {
		s.multiLog.Warnf("failed to dump tracing policies: %v", err)
		return
	}

	s.multiLog.Infof("dumped tracing policies in %s", fname)
}
