.PHONY: all clean
.SUFFIXES:

include ./Makefile.defs

ALIGNCHECKERDIR = alignchecker/
PROCESSDIR := process/
CGROUPDIR := cgroup/
BPFTESTDIR := test/

ALIGNCHECKER = bpf_alignchecker.o
PROCESS = bpf_execve_event.o bpf_execve_event_v53.o bpf_fork.o bpf_exit.o bpf_generic_kprobe.o \
	  bpf_execve_bprm_commit_creds.o \
	  bpf_generic_kprobe_v53.o bpf_generic_retkprobe.o bpf_generic_retkprobe_v53.o \
	  bpf_multi_kprobe_v53.o bpf_multi_retkprobe_v53.o \
	  bpf_generic_tracepoint.o bpf_generic_tracepoint_v53.o \
	  bpf_generic_uprobe.o bpf_generic_uprobe_v53.o \
	  bpf_generic_lsm_core.o bpf_generic_lsm_output.o \
	  bpf_generic_lsm_core_v511.o bpf_generic_lsm_output_v511.o \
	  bpf_generic_lsm_ima_file_v511.o bpf_generic_lsm_ima_bprm_v511.o \
	  bpf_execve_event_v61.o \
	  bpf_generic_kprobe_v61.o bpf_generic_retkprobe_v61.o \
	  bpf_generic_tracepoint_v61.o \
	  bpf_multi_kprobe_v61.o bpf_multi_retkprobe_v61.o \
	  bpf_generic_uprobe_v61.o \
	  bpf_multi_uprobe_v61.o \
	  bpf_execve_event_v511.o \
	  bpf_generic_kprobe_v511.o bpf_generic_retkprobe_v511.o \
	  bpf_generic_tracepoint_v511.o \
	  bpf_multi_kprobe_v511.o bpf_multi_retkprobe_v511.o \
	  bpf_generic_uprobe_v511.o \
	  bpf_generic_lsm_core_v61.o bpf_generic_lsm_output_v61.o \
	  bpf_generic_lsm_ima_file_v61.o bpf_generic_lsm_ima_bprm_v61.o \
	  bpf_loader.o \
	  bpf_cgroup.o \
	  bpf_enforcer.o bpf_multi_enforcer.o bpf_fmodret_enforcer.o \
	  bpf_map_test_p1.o bpf_map_test_p2.o bpf_map_test_p3.o \
	  bpf_prog_iter.o

CGROUP = bpf_cgroup_mkdir.o bpf_cgroup_rmdir.o bpf_cgroup_release.o
BPFTEST = bpf_lseek.o

OBJSDIR       := objs/
DEPSDIR       := deps/

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

MTARGET = $(patsubst $(DEPSDIR)%.d,$(OBJSDIR)%.o,$@)

define DEFINE_VARIANT
VAR := $1
deps/bpf_execve_event_$$(VAR).d: process/bpf_execve_event.c
deps/bpf_generic_kprobe_$$(VAR).d: process/bpf_generic_kprobe.c
deps/bpf_generic_retkprobe_$$(VAR).d: process/bpf_generic_retkprobe.c
deps/bpf_multi_kprobe_$$(VAR).d: process/bpf_generic_kprobe.c
deps/bpf_multi_retkprobe_$$(VAR).d: process/bpf_generic_retkprobe.c
deps/bpf_generic_tracepoint_$$(VAR).d: process/bpf_generic_tracepoint.c
deps/bpf_generic_uprobe_$$(VAR).d: process/bpf_generic_uprobe.c
deps/bpf_multi_uprobe_$$(VAR).d: process/bpf_generic_uprobe.c
deps/bpf_generic_lsm_core_$$(VAR).d: process/bpf_generic_lsm_core.c
deps/bpf_generic_lsm_output_$$(VAR).d: process/bpf_generic_lsm_output.c
deps/bpf_generic_lsm_ima_bprm_$$(VAR).d: process/bpf_generic_lsm_ima_bprm.c
deps/bpf_generic_lsm_ima_file_$$(VAR).d: process/bpf_generic_lsm_ima_file.c
endef

# Generic build targets for each sub-dir

$(eval $(call DEFINE_VARIANT,v53))
$(eval $(call DEFINE_VARIANT,v511))
$(eval $(call DEFINE_VARIANT,v61))

objs/%.o:
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(ALIGNCHECKERDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(MTARGET) $< > $@


# Enforcer programs: bpf_enforcer, bpf_multi_enforcer, bpf_fmodret_enforcer

## bpf_enforcer: __BPF_OVERRIDE_RETURN, but no __MULTI_KPROBE
objs/bpf_enforcer.o:
	$(CLANG) $(CLANG_FLAGS) -D__BPF_OVERRIDE_RETURN -c $< -o $@

$(DEPSDIR)bpf_enforcer.d: process/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -D__BPF_OVERRIDE_RETURN -MM -MP -MT $(MTARGET) $< > $@

## bpf_multi_enforcer: __BPF_OVERRIDE_RETURN and __MULTI_KPROBE
objs/bpf_multi_enforcer.o:
	$(CLANG) $(CLANG_FLAGS) -D__BPF_OVERRIDE_RETURN -D__MULTI_KPROBE -c $< -o $@

$(DEPSDIR)bpf_multi_enforcer.d: process/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -D__BPF_OVERRIDE_RETURN -D__MULTI_KPROBE -MM -MP -MT $(MTARGET) $< > $@

## bpf_fmodret_enforcer no bpf_override_return: we need fmod_ret
objs/bpf_fmodret_enforcer.o:
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)bpf_fmodret_enforcer.d: process/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(MTARGET) $< > $@

# PROCESSDIR
objs/bpf_multi_kprobe_v53.o objs/bpf_multi_retkprobe_v53.o:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__MULTI_KPROBE -c $< -o $@

objs/%_v53.o:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -c $< -o $@

$(DEPSDIR)%.d: $(PROCESSDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(MTARGET) $< > $@


$(DEPSDIR)%_v53.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -MM -MP -MT $(MTARGET) $< > $@

objs/bpf_multi_kprobe_v61.o objs/bpf_multi_retkprobe_v61.o:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -D__V61_BPF_PROG -D__MULTI_KPROBE -c $< -o $@

objs/bpf_multi_uprobe_v61.o:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__V61_BPF_PROG -D__MULTI_KPROBE -c $< -o $@

objs/%_v61.o:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -D__V61_BPF_PROG -c $< -o $@

$(DEPSDIR)%_v61.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -D__V61_BPF_PROG -MM -MP -MT $(MTARGET) $< > $@

objs/bpf_multi_kprobe_v511.o objs/bpf_multi_retkprobe_v511.o:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -D__MULTI_KPROBE -c $< -o $@

objs/%_v511.o:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -c $< -o $@

$(DEPSDIR)%_v511.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -MM -MP -MT $(MTARGET) $< > $@

objs/bpf_generic_lsm_core.o:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -c $< -o $@

$(DEPSDIR)/bpf_generic_lsm_core.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -MM -MP -MT $(MTARGET)   $< > $@

objs/bpf_generic_lsm_output.o:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -c $< -o $@

$(DEPSDIR)/bpf_generic_lsm_output.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -MM -MP -MT $(MTARGET)   $< > $@


# BPFTESTDIR
$(DEPSDIR)%.d: $(BPFTESTDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(MTARGET) $< > $@

# CGROUPDIR
$(DEPSDIR)%.d: $(CGROUPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(MTARGET) $< > $@

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
