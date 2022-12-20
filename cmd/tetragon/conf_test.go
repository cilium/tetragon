package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

type confInput struct {
	path    string
	dropIn  bool
	write   bool // If set we write options to file/directories even if empty
	options map[string]interface{}
}

type testCase struct {
	description     string
	confs           []confInput
	expectedOptions map[string]interface{} // The expected Options after parsing all the above
}

var (
	globalTestIndex = 0

	testCases = []testCase{
		{
			description: "Default configuration",
			// expected options: default options nothing changes
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "",
				keyHubbleLib:       "/var/lib/tetragon/",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "",
					dropIn: false,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "All Empty due to All empty values in /etc/tetragon/tetragon.yaml",
			// expected options: all zeroed / cleared values
			// As we write empty /etc/tetragon/tetragon.yaml file
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "",
				keyHubbleLib:       "",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true, // write empty values
					options: map[string]interface{}{
						keyConfigDir:       "",
						keyExportFilename:  "",
						keyHubbleLib:       "",
						keyBTF:             "",
						keyVerbosity:       0,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(0),
					},
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Partial update due to partial values in /etc/tetragon/tetragon.yaml",
			// expected options: partial update
			// As we write /etc/tetragon/tetragon.yaml file
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "",
				keyHubbleLib:       "/var/lib/tetragon/",
				keyBTF:             "/sys/kernel/btf/vmlinux",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true, // write values
					// Partial update only btf
					options: map[string]interface{}{
						keyBTF: "/sys/kernel/btf/vmlinux",
					},
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Re-test default values",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "",
				keyHubbleLib:       "/var/lib/tetragon/",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "",
					dropIn: false,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test Drop-in /usr/lib/tetragon/tetragon.conf.d/",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "/var/log/tetragon.log_0",
				keyHubbleLib:       "/usr/lib/tetragon/bpf/_0",
				keyBTF:             "/sys/kernel/btf/vmlinux-usr-lib_0",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/tetragon.log_0",
						keyHubbleLib:      "/usr/lib/tetragon/bpf/_0",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "",
					dropIn: false,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test Drop-in /usr/local/lib/tetragon/tetragon.conf.d/",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "/var/log/tetragon.log_1",
				keyHubbleLib:       "/usr/local/lib/tetragon/bpf/_1",
				keyBTF:             "/sys/kernel/btf/vmlinux-usr-local-lib_1",
				keyVerbosity:       2,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/tetragon.log_0",
						keyHubbleLib:      "/usr/lib/tetragon/bpf/_0",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						keyVerbosity:      1,
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/tetragon.log_1",
						keyHubbleLib:      "/usr/local/lib/tetragon/bpf/_1",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						keyVerbosity:      2,
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "",
					dropIn: false,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test n1 Drop-in /etc/tetragon/tetragon.conf.d/",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "/var/log/tetragon.log_2",
				keyHubbleLib:       "/var/lib/tetragon/_2",
				keyBTF:             "/sys/kernel/btf/vmlinux-etc_2",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(20000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/tetragon.log_0",
						keyHubbleLib:      "/usr/lib/tetragon/bpf/_0",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						keyVerbosity:      1,
						keyEventQueueSize: uint(15000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/tetragon.log_1",
						keyHubbleLib:      "/usr/local/lib/tetragon/bpf/_1",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						keyVerbosity:      2,
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/tetragon.log_2",
						keyHubbleLib:      "/var/lib/tetragon/_2",
						keyBTF:            "/sys/kernel/btf/vmlinux-etc_2",
						keyVerbosity:      0,
						keyEventQueueSize: uint(20000),
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "",
					dropIn: false,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			// Set all options to zero in drop-in
			description: "Test n2 Drop-in /etc/tetragon/tetragon.conf.d/",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "",
				keyHubbleLib:       "",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/tetragon.log_0",
						keyHubbleLib:      "/usr/lib/tetragon/bpf/_0",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						keyVerbosity:      1,
						keyEventQueueSize: uint(15000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "",
						keyHubbleLib:      "/usr/local/lib/tetragon/bpf/_1",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						keyVerbosity:      2,
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "",
						keyExportFilename:  "",
						keyHubbleLib:       "",
						keyBTF:             "",
						keyVerbosity:       0,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(0),
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "",
					dropIn: false,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test n1 /etc/tetragon/tetragon.yaml",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "/var/run/tetragon/tetragon.log_3",
				keyHubbleLib:       "/var/lib/tetragon/bpf/_3",
				keyBTF:             "/sys/kernel/btf/vmlinux-etc-tetragon.yaml_3",
				keyVerbosity:       99,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: true,
				keyEventQueueSize:  uint(30000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/tetragon.log_0",
						keyHubbleLib:      "/usr/lib/tetragon/bpf/_0",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						keyVerbosity:      1,
						keyEventQueueSize: uint(15000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/tetragon.log_1",
						keyHubbleLib:      "/usr/local/lib/tetragon/bpf/_1",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						keyVerbosity:      2,
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/tetragon.log_2",
						keyHubbleLib:      "/var/lib/tetragon/_2",
						keyBTF:            "/sys/kernel/btf/vmlinux-etc_2",
						keyVerbosity:      99,
						keyEnableK8sAPI:   true,
						keyEventQueueSize: uint(20000),
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename:  "/var/run/tetragon/tetragon.log_3",
						keyHubbleLib:       "/var/lib/tetragon/bpf/_3",
						keyBTF:             "/sys/kernel/btf/vmlinux-etc-tetragon.yaml_3",
						keyEnableCiliumAPI: true,
						keyEnableK8sAPI:    false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			// Set all options to zero in drop-in
			description: "Test n2 /etc/tetragon/tetragon.yaml",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "",
				keyHubbleLib:       "",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/tetragon.log_0",
						keyHubbleLib:      "/usr/lib/tetragon/bpf/_0",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						keyVerbosity:      1,
						keyEventQueueSize: uint(15000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/tetragon.log_1",
						keyHubbleLib:      "/usr/local/lib/tetragon/bpf/_1",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						keyVerbosity:      2,
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/tetragon.log_2",
						keyHubbleLib:      "/var/lib/tetragon/_2",
						keyBTF:            "/sys/kernel/btf/vmlinux-etc_2",
						keyVerbosity:      99,
						keyEnableK8sAPI:   true,
						keyEventQueueSize: uint(20000),
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "",
						keyExportFilename:  "",
						keyHubbleLib:       "",
						keyBTF:             "",
						keyVerbosity:       0,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(0),
					},
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
	}
)

func writeDropInConf(t *testing.T, dir string, options map[string]interface{}) error {
	for k, v := range options {
		data := []byte(fmt.Sprint(v))
		file := filepath.Join(dir, k)
		err := os.WriteFile(file, data, 0644)
		if err != nil {
			return fmt.Errorf("failed to write %s: %v", file, err)
		}
	}

	return nil
}

func setupConfig(t *testing.T, root string, test testCase) error {
	for _, c := range test.confs {
		if c.path == "" {
			continue
		}

		if c.dropIn == true {
			err := os.MkdirAll(filepath.Join(root, c.path), 0755)
			if err != nil {
				return err
			}

			if c.write {
				err = writeDropInConf(t, filepath.Join(root, c.path), c.options)
				if err != nil {
					return err
				}
			}

		} else {
			file := filepath.Join(root, c.path)
			err := os.MkdirAll(filepath.Dir(file), 0755)
			if err != nil {
				return err
			}

			if c.write {
				data, err := yaml.Marshal(&c.options)
				if err != nil {
					return err
				}

				err = os.WriteFile(file, data, 0644)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func cleanupConfig(t *testing.T, root string, test testCase) {
	for _, c := range test.confs {
		if c.path != "" {
			os.RemoveAll(filepath.Join(root, c.path))
		}
	}
}

func runTestCases(t *testing.T) {
	testDir := t.TempDir()

	c := testCases[globalTestIndex]

	err := setupConfig(t, testDir, c)
	require.NoErrorf(t, err, "failed at test case %s", c.description)

	defaultConf := filepath.Join(testDir, defaults.DefaultTgConfDir)
	defaultConfDropIns := make([]string, 0)
	for _, c := range defaults.DefaultTgConfDropIns {
		defaultConfDropIns = append(defaultConfDropIns, filepath.Join(testDir, c))
	}
	log.Infof("Test %s index %d dumping settings before: %+v", c.description, globalTestIndex, viper.AllSettings())
	readConfigSettings(defaultConf, defaultConfDropIns)
	log.Infof("Test %s index %d expected settings: %+v", c.description, globalTestIndex, c.expectedOptions)
	log.Infof("Test %s index %d dumping settings after: %+v", c.description, globalTestIndex, viper.AllSettings())

	for opt, v := range c.expectedOptions {
		switch expected := v.(type) {
		case int:
			actual := viper.GetInt(opt)
			require.EqualValuesf(t, expected, actual, "failed to match int option '%s' at test %s", opt, c.description)
		case uint:
			actual := viper.GetUint(opt)
			require.EqualValuesf(t, expected, actual, "failed to match uint option '%s' at test %s", opt, c.description)
		case string:
			actual := viper.GetString(opt)
			require.EqualValuesf(t, expected, actual, "failed to match string option '%s' at test %s", opt, c.description)
		case bool:
			actual := viper.GetBool(opt)
			require.EqualValuesf(t, expected, actual, "failed to match bool option '%s' at test %s", opt, c.description)
		}
	}

	cleanupConfig(t, testDir, c)
}

func TestReadConfigSettings(t *testing.T) {
	for i, c := range testCases {
		globalTestIndex = i
		rootCmd := &cobra.Command{
			Use:   "testing-only",
			Short: "Perform read configuration tests",
			Run: func(cmd *cobra.Command, args []string) {
				runTestCases(t)
			},
		}

		flags := rootCmd.PersistentFlags()
		flags.String(keyConfigDir, "", "Configuration directory that contains a file for each option")
		flags.String(keyHubbleLib, defaults.DefaultTetragonLib, "Location of Tetragon libs (btf and bpf files)")
		flags.String(keyBTF, "", "Location of btf")
		flags.String(keyExportFilename, "", "Filename for JSON export. Disabled by default")
		flags.Int(keyVerbosity, 0, "set verbosity level for eBPF verifier dumps. Pass 0 for silent, 1 for truncated logs, 2 for a full dump")
		flags.Bool(keyEnableK8sAPI, false, "Access Kubernetes API to associate Tetragon events with Kubernetes pods")
		flags.Bool(keyEnableCiliumAPI, false, "Access Cilium API to associate Tetragon events with Cilium endpoints and DNS cache")
		flags.Uint(keyEventQueueSize, 10000, "Set the size of the internal event queue.")
		viper.BindPFlags(flags)
		t.Run(c.description, func(t *testing.T) {
			rootCmd.Execute()
		})
		viper.Reset()
	}
}
