# Copyright Authors of Tetragon
# SPDX-License-Identifier: Apache-2.0

# We build BPF objects in 2 stages:
# - first we build dependency '.d' files for all object and include them
#   directly in the Makefile to get all the dependency rules for the object
# - then we build the all the objects
#
# We allow to build objects for specific kernel version (variant) with the
# kernel version suffix. Each variant can define extra CFLAGS by defining
# following variable:
#
#   CFLAGS_<version>   (example: CFLAGS_v53 := ...)
#
# Each object (standard or variant) can define extra CFLAGS by defining
# following variable:
#
#   CFLAGS_<object.o>  (example: CFLAGS_bpf_enforcer.o = -D__BPF_OVERRIDE_RETURN)
#
# It's possible to make .ll file for any object, like:
#
#  $ make -C bpf objs/bpf_generic_kprobe_v61.ll

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

# v3.10 RHEL7
# base sensor
PROCESS += bpf_execve_event_v310.o bpf_exit_v310.o bpf_fork_v310.o

# v4.19
# base sensor
PROCESS += bpf_execve_event.o bpf_fork.o bpf_exit.o bpf_execve_bprm_commit_creds.o
# generic probes
PROCESS += bpf_generic_kprobe.o bpf_generic_retkprobe.o bpf_generic_tracepoint.o \
	   bpf_generic_uprobe.o bpf_generic_rawtp.o bpf_generic_usdt.o

# lsm
PROCESS += bpf_generic_lsm_core.o bpf_generic_lsm_output.o

# v5.3
# base sensor
PROCESS += bpf_execve_event_v53.o
# generic probes
PROCESS += bpf_generic_kprobe_v53.o bpf_generic_retkprobe_v53.o \
	   bpf_multi_kprobe_v53.o bpf_multi_retkprobe_v53.o \
	   bpf_generic_tracepoint_v53.o bpf_generic_uprobe_v53.o \
	   bpf_generic_rawtp_v53.o \
	   bpf_generic_usdt_v53.o

# v5.11
# base sensor
PROCESS += bpf_execve_event_v511.o
# generic probes
PROCESS += bpf_generic_kprobe_v511.o bpf_generic_retkprobe_v511.o \
	   bpf_multi_kprobe_v511.o bpf_multi_retkprobe_v511.o \
	   bpf_generic_tracepoint_v511.o bpf_generic_uprobe_v511.o \
	   bpf_generic_rawtp_v511.o \
	   bpf_generic_usdt_v511.o

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
	   bpf_multi_uprobe_v61.o \
	   bpf_generic_rawtp_v61.o \
	   bpf_generic_usdt_v61.o \
	   bpf_multi_usdt_v61.o

# v6.12
# base sensor
PROCESS += bpf_execve_event_v612.o
# generic probes
PROCESS += bpf_generic_kprobe_v612.o bpf_generic_retkprobe_v612.o \
	   bpf_multi_kprobe_v612.o bpf_multi_retkprobe_v612.o \
	   bpf_generic_tracepoint_v612.o bpf_generic_uprobe_v612.o \
	   bpf_multi_uprobe_v612.o \
	   bpf_generic_rawtp_v612.o \
	   bpf_generic_usdt_v612.o \
	   bpf_multi_usdt_v612.o

# lsm
PROCESS += bpf_generic_lsm_core_v61.o bpf_generic_lsm_output_v61.o \
	   bpf_generic_lsm_ima_file_v61.o bpf_generic_lsm_ima_bprm_v61.o \
	   bpf_generic_lsm_core_v612.o bpf_generic_lsm_output_v612.o \
	   bpf_generic_lsm_ima_file_v612.o bpf_generic_lsm_ima_bprm_v612.o


# execve_map update
PROCESS += bpf_execve_map_update_v612.o bpf_execve_map_update_v61.o bpf_execve_map_update_v511.o \
	   bpf_execve_map_update_v53.o bpf_execve_map_update.o


CGROUP = bpf_cgroup_mkdir.o bpf_cgroup_rmdir.o bpf_cgroup_release.o bpf_cgtracker.o
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

# Define extra CFLAGS for each variant
CFLAGS_v310 = -D__RHEL7_BPF_PROG
CFLAGS_v53  = -D__LARGE_BPF_PROG
CFLAGS_v511 = -D__LARGE_BPF_PROG -D__V511_BPF_PROG
CFLAGS_v61  = -D__LARGE_BPF_PROG -D__V511_BPF_PROG -D__V61_BPF_PROG
CFLAGS_v612 = -D__LARGE_BPF_PROG -D__V511_BPF_PROG -D__V61_BPF_PROG -D__V612_BPF_PROG

# Define extra CFLAGS for objects
CFLAGS_bpf_enforcer.o           = -D__BPF_OVERRIDE_RETURN
CFLAGS_bpf_multi_enforcer.o     = -D__BPF_OVERRIDE_RETURN -D__MULTI_KPROBE
CFLAGS_bpf_generic_lsm_core.o   = -D__LARGE_BPF_PROG
CFLAGS_bpf_generic_lsm_output.o = -D__LARGE_BPF_PROG

# Rules
MTARGET_o  = $(patsubst $(DEPSDIR)%.d,$(OBJSDIR)%.o,$@)
MTARGET_ll = $(patsubst $(DEPSDIR)%.d,$(OBJSDIR)%.ll,$@)
MTARGET_i = $(patsubst $(DEPSDIR)%.d,$(OBJSDIR)%.i,$@)

rule_d_CFLAGS  = $(CFLAGS_$(notdir $(MTARGET_o)))
rule_o_CFLAGS  = $(CFLAGS_$(notdir $@))
rule_ll_CFLAGS = $(CFLAGS_$(notdir $(patsubst %.ll,%.o,$@)))

rule_d  = $(CLANG) $(CLANG_FLAGS) $(rule_d_CFLAGS) $1 -MM -MP -MT $(MTARGET_o)  $< >  $@ && \
          $(CLANG) $(CLANG_FLAGS) $(rule_d_CFLAGS) $1 -MM -MP -MT $(MTARGET_ll) $< >> $@ && \
          $(CLANG) $(CLANG_FLAGS) $(rule_d_CFLAGS) $1 -MM -MP -MT $(MTARGET_i) $< >> $@
rule_o  = $(CLANG) $(CLANG_FLAGS) $(rule_o_CFLAGS) $1 -c $< -o $@
rule_ll = $(CLANG) $(CLANG_FLAGS) $(rule_ll_CFLAGS) -emit-llvm $1 -c $< -o $@
rule_i  = $(CLANG) $(CLANG_FLAGS) $(rule_o_CFLAGS) $1 -E $< -o $@

VARIANT_CFLAGS = $$(CFLAGS_$1)

# Variant rules
define DEFINE_VARIANT
VAR := $1

# We need to define extra rules for multi probes because the object name
# is different then the source file.
$(DEPSDIR)bpf_multi_kprobe_$$(VAR).d: $(PROCESSDIR)bpf_generic_kprobe.c
$(DEPSDIR)bpf_multi_retkprobe_$$(VAR).d: $(PROCESSDIR)bpf_generic_retkprobe.c
$(DEPSDIR)bpf_multi_uprobe_$$(VAR).d: $(PROCESSDIR)bpf_generic_uprobe.c
$(DEPSDIR)bpf_multi_usdt_$$(VAR).d: $(PROCESSDIR)bpf_generic_usdt.c

# Object build rule for VARIANT objects
$(OBJSDIR)%_$$(VAR).o:
	$$(call rule_o,$(VARIANT_CFLAGS))

$(OBJSDIR)%_$$(VAR).i:
	$$(call rule_i,$(VARIANT_CFLAGS))

$(OBJSDIR)%_$$(VAR).ll:
	$$(call rule_ll,$(VARIANT_CFLAGS))

# Generic dependency files for VARIANT objects
$(DEPSDIR)%_$$(VAR).d: $(PROCESSDIR)%.c
	$$(call rule_d,$(VARIANT_CFLAGS))

# Define extra CFLAGS for variant objects
CFLAGS_bpf_multi_kprobe_$$(VAR).o    = -D__MULTI_KPROBE
CFLAGS_bpf_multi_retkprobe_$$(VAR).o = -D__MULTI_KPROBE
ifeq (v61,$$(VAR))
CFLAGS_bpf_multi_uprobe_$$(VAR).o    = -D__MULTI_KPROBE
CFLAGS_bpf_multi_usdt_$$(VAR).o      = -D__MULTI_KPROBE
endif
ifeq (v612,$$(VAR))
CFLAGS_bpf_multi_uprobe_$$(VAR).o    = -D__MULTI_KPROBE
CFLAGS_bpf_multi_usdt_$$(VAR).o      = -D__MULTI_KPROBE
endif
endef # DEFINE_VARIANT

$(eval $(call DEFINE_VARIANT,v310))
$(eval $(call DEFINE_VARIANT,v53))
$(eval $(call DEFINE_VARIANT,v511))
$(eval $(call DEFINE_VARIANT,v61))
$(eval $(call DEFINE_VARIANT,v612))

# Object build rule for non VARIANT objects
objs/%.o:
	$(rule_o)

objs/%.i:
	$(rule_i)

objs/%.ll:
	$(rule_ll)

# Generic dependency files
$(DEPSDIR)bpf_multi_enforcer.d: $(PROCESSDIR)bpf_enforcer.c
$(DEPSDIR)bpf_fmodret_enforcer.d: $(PROCESSDIR)bpf_enforcer.c

$(DEPSDIR)%.d: $(ALIGNCHECKERDIR)%.c
	$(rule_d)
$(DEPSDIR)%.d: $(PROCESSDIR)%.c
	$(rule_d)
$(DEPSDIR)%.d: $(BPFTESTDIR)%.c
	$(rule_d)
$(DEPSDIR)%.d: $(CGROUPDIR)%.c
	$(rule_d)
$(DEPSDIR)%.d:
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
