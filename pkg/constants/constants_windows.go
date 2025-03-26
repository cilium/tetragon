package constants

import (
	"golang.org/x/sys/windows"
)

const (
	AF_INET              = windows.AF_INET
	AF_INET6             = windows.AF_INET6
	PERF_MAX_STACK_DEPTH = 0x7f
	CBitFieldMaskBit34   = 0x400000000
	CAP_LAST_CAP         = 0x28
	CAP_CHOWN            = 0
	AF_UNIX              = windows.AF_UNIX
	AF_NETBIOS           = windows.AF_NETBIOS
	AF_IRDA              = windows.AF_IRDA
	AF_BTH               = windows.AF_BTH
	CGROUP2_SUPER_MAGIC  = 0x63677270
	BPF_STATS_RUN_TIME   = 0
	S_IFMT               = 0xf000
)
