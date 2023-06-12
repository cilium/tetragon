package metricschecker

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMetricFamilies(t *testing.T) {
	families, err := getMetricFamilies(TETRAGON_SAMPLE_METRICS)
	require.NoError(t, err, "parsing must succeed")
	_, family := families["go_gc_duration_seconds"]
	assert.NotNil(t, family)
}

const TETRAGON_SAMPLE_METRICS = `
# HELP event_cache_count The total number of Tetragon event cache accesses. For internal use only.
# TYPE event_cache_count counter
event_cache_count 0
# HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 2.5192e-05
go_gc_duration_seconds{quantile="0.25"} 2.9896e-05
go_gc_duration_seconds{quantile="0.5"} 3.365e-05
go_gc_duration_seconds{quantile="0.75"} 3.5257e-05
go_gc_duration_seconds{quantile="1"} 6.1794e-05
go_gc_duration_seconds_sum 0.00038515
go_gc_duration_seconds_count 11
# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 18
# HELP go_info Information about the Go environment.
# TYPE go_info gauge
go_info{version="go1.20.5"} 1
# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.
# TYPE go_memstats_alloc_bytes gauge
go_memstats_alloc_bytes 3.7075208e+07
# HELP go_memstats_alloc_bytes_total Total number of bytes allocated, even if freed.
# TYPE go_memstats_alloc_bytes_total counter
go_memstats_alloc_bytes_total 3.38012136e+08
# HELP go_memstats_buck_hash_sys_bytes Number of bytes used by the profiling bucket hash table.
# TYPE go_memstats_buck_hash_sys_bytes gauge
go_memstats_buck_hash_sys_bytes 1.628081e+06
# HELP go_memstats_frees_total Total number of frees.
# TYPE go_memstats_frees_total counter
go_memstats_frees_total 2.016494e+06
# HELP go_memstats_gc_sys_bytes Number of bytes used for garbage collection system metadata.
# TYPE go_memstats_gc_sys_bytes gauge
go_memstats_gc_sys_bytes 1.1876032e+07
# HELP go_memstats_heap_alloc_bytes Number of heap bytes allocated and still in use.
# TYPE go_memstats_heap_alloc_bytes gauge
go_memstats_heap_alloc_bytes 3.7075208e+07
# HELP go_memstats_heap_idle_bytes Number of heap bytes waiting to be used.
# TYPE go_memstats_heap_idle_bytes gauge
go_memstats_heap_idle_bytes 9.7353728e+07
# HELP go_memstats_heap_inuse_bytes Number of heap bytes that are in use.
# TYPE go_memstats_heap_inuse_bytes gauge
go_memstats_heap_inuse_bytes 4.0009728e+07
# HELP go_memstats_heap_objects Number of allocated objects.
# TYPE go_memstats_heap_objects gauge
go_memstats_heap_objects 397836
# HELP go_memstats_heap_released_bytes Number of heap bytes released to OS.
# TYPE go_memstats_heap_released_bytes gauge
go_memstats_heap_released_bytes 7.4727424e+07
# HELP go_memstats_heap_sys_bytes Number of heap bytes obtained from system.
# TYPE go_memstats_heap_sys_bytes gauge
go_memstats_heap_sys_bytes 1.37363456e+08
# HELP go_memstats_last_gc_time_seconds Number of seconds since 1970 of last garbage collection.
# TYPE go_memstats_last_gc_time_seconds gauge
go_memstats_last_gc_time_seconds 1.6865802863761244e+09
# HELP go_memstats_lookups_total Total number of pointer lookups.
# TYPE go_memstats_lookups_total counter
go_memstats_lookups_total 0
# HELP go_memstats_mallocs_total Total number of mallocs.
# TYPE go_memstats_mallocs_total counter
go_memstats_mallocs_total 2.41433e+06
# HELP go_memstats_mcache_inuse_bytes Number of bytes in use by mcache structures.
# TYPE go_memstats_mcache_inuse_bytes gauge
go_memstats_mcache_inuse_bytes 19200
# HELP go_memstats_mcache_sys_bytes Number of bytes used for mcache structures obtained from system.
# TYPE go_memstats_mcache_sys_bytes gauge
go_memstats_mcache_sys_bytes 31200
# HELP go_memstats_mspan_inuse_bytes Number of bytes in use by mspan structures.
# TYPE go_memstats_mspan_inuse_bytes gauge
go_memstats_mspan_inuse_bytes 566400
# HELP go_memstats_mspan_sys_bytes Number of bytes used for mspan structures obtained from system.
# TYPE go_memstats_mspan_sys_bytes gauge
go_memstats_mspan_sys_bytes 1.45248e+06
# HELP go_memstats_next_gc_bytes Number of heap bytes when next garbage collection will take place.
# TYPE go_memstats_next_gc_bytes gauge
go_memstats_next_gc_bytes 7.5105736e+07
# HELP go_memstats_other_sys_bytes Number of bytes used for other system allocations.
# TYPE go_memstats_other_sys_bytes gauge
go_memstats_other_sys_bytes 2.733962e+06
# HELP go_memstats_stack_inuse_bytes Number of bytes in use by the stack allocator.
# TYPE go_memstats_stack_inuse_bytes gauge
go_memstats_stack_inuse_bytes 1.048576e+06
# HELP go_memstats_stack_sys_bytes Number of bytes obtained from system for stack allocator.
# TYPE go_memstats_stack_sys_bytes gauge
go_memstats_stack_sys_bytes 1.048576e+06
# HELP go_memstats_sys_bytes Number of bytes obtained from system.
# TYPE go_memstats_sys_bytes gauge
go_memstats_sys_bytes 1.56133787e+08
# HELP go_threads Number of OS threads created.
# TYPE go_threads gauge
go_threads 23
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 0.92
# HELP process_max_fds Maximum number of open file descriptors.
# TYPE process_max_fds gauge
process_max_fds 524288
# HELP process_open_fds Number of open file descriptors.
# TYPE process_open_fds gauge
process_open_fds 45
# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 1.22687488e+08
# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1.68658028578e+09
# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 2.524352512e+09
# HELP process_virtual_memory_max_bytes Maximum amount of virtual memory available in bytes.
# TYPE process_virtual_memory_max_bytes gauge
process_virtual_memory_max_bytes 1.8446744073709552e+19
# HELP promhttp_metric_handler_requests_in_flight Current number of scrapes being served.
# TYPE promhttp_metric_handler_requests_in_flight gauge
promhttp_metric_handler_requests_in_flight 1
# HELP promhttp_metric_handler_requests_total Total number of scrapes by HTTP status code.
# TYPE promhttp_metric_handler_requests_total counter
promhttp_metric_handler_requests_total{code="200"} 1
promhttp_metric_handler_requests_total{code="500"} 0
promhttp_metric_handler_requests_total{code="503"} 0
# HELP tetragon_errors_total The total number of Tetragon errors. For internal use only.
# TYPE tetragon_errors_total counter
tetragon_errors_total{type="process_cache_miss_on_get"} 1
# HELP tetragon_events_total The total number of Tetragon events
# TYPE tetragon_events_total counter
tetragon_events_total{binary="/bin/sh",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/opt/brave-bin/brave",namespace="",pod="",type="PROCESS_EXEC"} 28
tetragon_events_total{binary="/opt/brave-bin/brave",namespace="",pod="",type="PROCESS_EXIT"} 9
tetragon_events_total{binary="/opt/brave-bin/chrome_crashpad_handler",namespace="",pod="",type="PROCESS_EXEC"} 2
tetragon_events_total{binary="/opt/discord/Discord",namespace="",pod="",type="PROCESS_EXEC"} 8
tetragon_events_total{binary="/opt/discord/chrome_crashpad_handler",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/tmp/go-build2757782206/b001/exe/tetragon",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/alacritty",namespace="",pod="",type="PROCESS_EXEC"} 2
tetragon_events_total{binary="/usr/bin/browserpass",namespace="",pod="",type="PROCESS_EXEC"} 2
tetragon_events_total{binary="/usr/bin/browserpass",namespace="",pod="",type="PROCESS_EXIT"} 7
tetragon_events_total{binary="/usr/bin/cat",namespace="",pod="",type="PROCESS_EXEC"} 62
tetragon_events_total{binary="/usr/bin/cat",namespace="",pod="",type="PROCESS_EXIT"} 62
tetragon_events_total{binary="/usr/bin/containerd",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/curl",namespace="",pod="",type="PROCESS_EXEC"} 3
tetragon_events_total{binary="/usr/bin/curl",namespace="",pod="",type="PROCESS_EXIT"} 2
tetragon_events_total{binary="/usr/bin/dbus-daemon",namespace="",pod="",type="PROCESS_EXEC"} 2
tetragon_events_total{binary="/usr/bin/dhcpcd",namespace="",pod="",type="PROCESS_EXEC"} 5
tetragon_events_total{binary="/usr/bin/dnsmasq",namespace="",pod="",type="PROCESS_EXEC"} 2
tetragon_events_total{binary="/usr/bin/dockerd",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/git",namespace="",pod="",type="PROCESS_EXEC"} 4
tetragon_events_total{binary="/usr/bin/git",namespace="",pod="",type="PROCESS_EXIT"} 4
tetragon_events_total{binary="/usr/bin/gnome-keyring-daemon",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/go",namespace="",pod="",type="PROCESS_EXEC"} 2
tetragon_events_total{binary="/usr/bin/go",namespace="",pod="",type="PROCESS_EXIT"} 9
tetragon_events_total{binary="/usr/bin/gssproxy",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/lightdm",namespace="",pod="",type="PROCESS_EXEC"} 2
tetragon_events_total{binary="/usr/bin/mkdir",namespace="",pod="",type="PROCESS_EXEC"} 31
tetragon_events_total{binary="/usr/bin/mkdir",namespace="",pod="",type="PROCESS_EXIT"} 31
tetragon_events_total{binary="/usr/bin/nfsdcld",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/node",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/nvim",namespace="",pod="",type="PROCESS_EXEC"} 2
tetragon_events_total{binary="/usr/bin/picom",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/polybar",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/pulseaudio",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/python3.11",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/redshift",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/resolvconf",namespace="",pod="",type="PROCESS_EXEC"} 31
tetragon_events_total{binary="/usr/bin/resolvconf",namespace="",pod="",type="PROCESS_EXIT"} 62
tetragon_events_total{binary="/usr/bin/rm",namespace="",pod="",type="PROCESS_EXEC"} 62
tetragon_events_total{binary="/usr/bin/rm",namespace="",pod="",type="PROCESS_EXIT"} 62
tetragon_events_total{binary="/usr/bin/rpc.idmapd",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/rpc.mountd",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/rpc.statd",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/rpcbind",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/ruby",namespace="",pod="",type="PROCESS_EXEC"} 2
tetragon_events_total{binary="/usr/bin/ruby",namespace="",pod="",type="PROCESS_EXIT"} 2
tetragon_events_total{binary="/usr/bin/starship",namespace="",pod="",type="PROCESS_EXEC"} 4
tetragon_events_total{binary="/usr/bin/starship",namespace="",pod="",type="PROCESS_EXIT"} 6
tetragon_events_total{binary="/usr/bin/sudo",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/tmux",namespace="",pod="",type="PROCESS_EXEC"} 3
tetragon_events_total{binary="/usr/bin/udevadm",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/vagrant",namespace="",pod="",type="PROCESS_EXEC"} 2
tetragon_events_total{binary="/usr/bin/vagrant",namespace="",pod="",type="PROCESS_EXIT"} 3
tetragon_events_total{binary="/usr/bin/volnoti",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/wpa_supplicant",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/xbindkeys",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/bin/xclip",namespace="",pod="",type="PROCESS_EXEC"} 3
tetragon_events_total{binary="/usr/bin/xclip",namespace="",pod="",type="PROCESS_EXIT"} 2
tetragon_events_total{binary="/usr/bin/zsh",namespace="",pod="",type="PROCESS_EXEC"} 8
tetragon_events_total{binary="/usr/bin/zsh",namespace="",pod="",type="PROCESS_EXIT"} 8
tetragon_events_total{binary="/usr/lib/Xorg",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/lib/at-spi-bus-launcher",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/lib/bluetooth/bluetoothd",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/lib/dhcpcd/dhcpcd-run-hooks",namespace="",pod="",type="PROCESS_EXEC"} 31
tetragon_events_total{binary="/usr/lib/dhcpcd/dhcpcd-run-hooks",namespace="",pod="",type="PROCESS_EXIT"} 93
tetragon_events_total{binary="/usr/lib/git-core/git",namespace="",pod="",type="PROCESS_EXEC"} 2
tetragon_events_total{binary="/usr/lib/git-core/git",namespace="",pod="",type="PROCESS_EXIT"} 2
tetragon_events_total{binary="/usr/lib/go/bin/go",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/lib/polkit-1/polkitd",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/lib/pulse/gsettings-helper",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/lib/rtkit-daemon",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/lib/slack/chrome_crashpad_handler",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/lib/slack/slack",namespace="",pod="",type="PROCESS_EXEC"} 7
tetragon_events_total{binary="/usr/lib/systemd/systemd",namespace="",pod="",type="PROCESS_EXEC"} 3
tetragon_events_total{binary="/usr/lib/systemd/systemd-journald",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/lib/systemd/systemd-logind",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="/usr/lib/systemd/systemd-machined",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="<kernel>",namespace="",pod="",type="PROCESS_EXEC"} 1
# HELP tetragon_generic_kprobe_merge_ok_total The total number of successful attempts to merge a kprobe and kretprobe event.
# TYPE tetragon_generic_kprobe_merge_ok_total counter
tetragon_generic_kprobe_merge_ok_total 0
# HELP tetragon_generic_kprobe_merge_pushed The total number of pushed events for later merge.
# TYPE tetragon_generic_kprobe_merge_pushed counter
tetragon_generic_kprobe_merge_pushed 0
# HELP tetragon_map_drops The total number of entries dropped per LRU map.
# TYPE tetragon_map_drops counter
tetragon_map_drops{map="processLru"} 378
# HELP tetragon_map_in_use_gauge The total number of in-use entries per map.
# TYPE tetragon_map_in_use_gauge gauge
tetragon_map_in_use_gauge{map="eventcache",total="0"} 0
tetragon_map_in_use_gauge{map="execve_map",total="32768"} 117
tetragon_map_in_use_gauge{map="processLru",total="65536"} 504
# HELP tetragon_msg_op_total The total number of times we encounter a given message opcode. For internal use only.
# TYPE tetragon_msg_op_total counter
tetragon_msg_op_total{msg_op="23"} 350
tetragon_msg_op_total{msg_op="5"} 241
tetragon_msg_op_total{msg_op="7"} 364
# HELP tetragon_ringbuf_perf_event_received The total number of Tetragon ringbuf perf events received.
# TYPE tetragon_ringbuf_perf_event_received gauge
tetragon_ringbuf_perf_event_received 955
`
