.PHONY: all clean
.SUFFIXES:

include ./Makefile.defs

ALIGNCHECKER = bpf_alignchecker.o

# generic sensors
PROCESS = bpf_loader.o \
	  bpf_cgroup.o \
	  bpf_enforcer.o bpf_multi_enforcer.o bpf_fmodret_enforcer.o \
	  bpf_map_test_p1.o bpf_map_test_p2.o bpf_map_test_p3.o \
	  bpf_prog_iter.o

# v4.19
# base sensor
PROCESS += bpf_execve_event.o bpf_fork.o bpf_exit.o bpf_execve_bprm_commit_creds.o
# generic probes
PROCESS += bpf_generic_kprobe.o bpf_generic_retkprobe.o bpf_generic_tracepoint.o \
	   bpf_generic_uprobe.o
# lsm
PROCESS += bpf_generic_lsm_core.o bpf_generic_lsm_output.o

# v5.3
# base sensor
PROCESS += bpf_execve_event_v53.o
# generic probes
PROCESS += bpf_generic_kprobe_v53.o bpf_generic_retkprobe_v53.o \
	   bpf_multi_kprobe_v53.o bpf_multi_retkprobe_v53.o \
	   bpf_generic_tracepoint_v53.o bpf_generic_uprobe_v53.o

# v5.11
# base sensor
PROCESS += bpf_execve_event_v511.o
# generic probes
PROCESS += bpf_generic_kprobe_v511.o bpf_generic_retkprobe_v511.o \
	   bpf_multi_kprobe_v511.o bpf_multi_retkprobe_v511.o \
	   bpf_generic_tracepoint_v511.o bpf_generic_uprobe_v511.o
# lsm
PROCESS += bpf_generic_lsm_core_v511.o bpf_generic_lsm_output_v511.o \
	   bpf_generic_lsm_ima_file_v511.o bpf_generic_lsm_ima_bprm_v511.o

# v6.1
# base sensor
PROCESS += bpf_execve_event_v61.o
# generic probes
PROCESS += bpf_generic_kprobe_v61.o bpf_generic_retkprobe_v61.o \
	   bpf_multi_kprobe_v61.o bpf_multi_retkprobe_v61.o \
	   bpf_generic_tracepoint_v61.o bpf_generic_uprobe_v61.o \
	   bpf_multi_uprobe_v61.o
# lsm
PROCESS += bpf_generic_lsm_core_v61.o bpf_generic_lsm_output_v61.o \
	   bpf_generic_lsm_ima_file_v61.o bpf_generic_lsm_ima_bprm_v61.o

CGROUP = bpf_cgroup_mkdir.o bpf_cgroup_rmdir.o bpf_cgroup_release.o
BPFTEST = bpf_lseek.o

OBJSDIR         := objs/
DEPSDIR         := deps/
ALIGNCHECKERDIR := alignchecker/
PROCESSDIR      := process/
CGROUPDIR       := cgroup/
BPFTESTDIR      := test/

TLSOBJ        := $(addprefix $(OBJSDIR),$(TLS))
NOPOBJ        := $(addprefix $(OBJSDIR),$(NOP))
PROCESSOBJ    := $(addprefix $(OBJSDIR),$(PROCESS))
CGROUPOBJ     := $(addprefix $(OBJSDIR),$(CGROUP))
TESTOBJ       := $(addprefix $(OBJSDIR),$(BPFTEST))
ALIGNCHECKEROBJ := $(addprefix $(OBJSDIR),$(ALIGNCHECKER))
OBJS          := $(PROCESSOBJ) $(CGROUPOBJ) $(TESTOBJ) $(NOPOBJ) $(ALIGNCHECKEROBJ)
DEPS          := $(patsubst $(OBJSDIR)%.o,$(DEPSDIR)%.d,$(OBJS))

all: $(OBJS) $(DEPS)

# NB: https://www.gnu.org/software/make/manual/html_node/Prerequisite-Types.html
$(OBJS): | $(OBJSDIR)
$(DEPS): | $(DEPSDIR)

$(OBJSDIR):
	mkdir $(OBJSDIR)

$(DEPSDIR):
	mkdir $(DEPSDIR)

CFLAGS_v53  = -D__LARGE_BPF_PROG
CFLAGS_v511 = -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS
CFLAGS_v61  = -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -D__V61_BPF_PROG

CFLAGS_bpf_enforcer.o           = -D__BPF_OVERRIDE_RETURN
CFLAGS_bpf_multi_enforcer.o     = -D__BPF_OVERRIDE_RETURN -D__MULTI_KPROBE
CFLAGS_bpf_generic_lsm_core.o   = -D__LARGE_BPF_PROG
CFLAGS_bpf_generic_lsm_output.o = -D__LARGE_BPF_PROG

MTARGET = $(patsubst $(DEPSDIR)%.d,$(OBJSDIR)%.o,$@)

rule_d_CFLAGS = $(CFLAGS_$(notdir $(MTARGET)))
rule_o_CFLAGS = $(CFLAGS_$(notdir $@))

rule_d = $(CLANG) $(CLANG_FLAGS) $(rule_d_CFLAGS) $1 -MM -MP -MT $(MTARGET) $< > $@
rule_o = $(CLANG) $(CLANG_FLAGS) $(rule_o_CFLAGS) $1 -c $< -o $@

VARIANT_CFLAGS = $$(CFLAGS_$1)

define DEFINE_VARIANT
VAR := $1
deps/bpf_multi_kprobe_$$(VAR).d: process/bpf_generic_kprobe.c
	$$(call rule_d,$(VARIANT_CFLAGS))
deps/bpf_multi_retkprobe_$$(VAR).d: process/bpf_generic_retkprobe.c
	$$(call rule_d,$(VARIANT_CFLAGS))
deps/bpf_multi_uprobe_$$(VAR).d: process/bpf_generic_uprobe.c
	$$(call rule_d,$(VARIANT_CFLAGS))

$(OBJSDIR)%_$$(VAR).o:
	$$(call rule_o,$(VARIANT_CFLAGS))

$(DEPSDIR)%_$$(VAR).d: process/%.c
	$$(call rule_d,$(VARIANT_CFLAGS))

CFLAGS_bpf_multi_kprobe_$$(VAR).o    = -D__MULTI_KPROBE
CFLAGS_bpf_multi_retkprobe_$$(VAR).o = -D__MULTI_KPROBE
ifeq (v61,$$(VAR))
CFLAGS_bpf_multi_uprobe_$$(VAR).o    = -D__MULTI_KPROBE
endif

endef

$(eval $(call DEFINE_VARIANT,v53))
$(eval $(call DEFINE_VARIANT,v511))
$(eval $(call DEFINE_VARIANT,v61))

objs/%.o:
	$(rule_o)

$(DEPSDIR)%.d: $(ALIGNCHECKERDIR)%.c
	$(rule_d)
$(DEPSDIR)bpf_multi_enforcer.d: process/bpf_enforcer.c
	$(rule_d)
$(DEPSDIR)bpf_fmodret_enforcer.d: process/bpf_enforcer.c
	$(rule_d)
$(DEPSDIR)%.d: $(PROCESSDIR)%.c
	$(rule_d)
$(DEPSDIR)%.d: $(BPFTESTDIR)%.c
	$(rule_d)
$(DEPSDIR)%.d: $(CGROUPDIR)%.c
	$(rule_d)

# include dependencies, see https://lists.gnu.org/archive/html/make-w32/2004-03/msg00062.html
ifeq (,$(filter $(MAKECMDGOALS),clean run-test))
-include $(DEPS)
endif

# the 'test' target is already taken
run-test:
	$(MAKE) -C tests test

SUBDIRS=tests

clean:
	@$(ECHO_CLEAN)
	$(QUIET) $(foreach TARGET,$(SUBDIRS), \
		$(MAKE) -C $(TARGET) clean)
	$(QUIET)rm -f $(OBJSDIR)*.{o,ll,i,s}
	$(QUIET)rm -f $(DEPSDIR)*.d
