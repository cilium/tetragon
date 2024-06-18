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
	  bpf_generic_lsm.o bpf_generic_lsm_v511.o \
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
	  bpf_generic_lsm_v61.o \
	  bpf_loader.o \
	  bpf_cgroup.o \
	  bpf_enforcer.o bpf_multi_enforcer.o bpf_fmodret_enforcer.o \
	  bpf_map_test_p1.o bpf_map_test_p2.o

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
LLOBJS        := $(patsubst $(OBJSDIR)%.o,$(OBJSDIR)%.ll,$(OBJS))
DEPS          := $(patsubst $(OBJSDIR)%.ll,$(DEPSDIR)%.d,$(LLOBJS))

all: $(OBJS) $(DEPS)

# NB: https://www.gnu.org/software/make/manual/html_node/Prerequisite-Types.html
$(OBJS): | $(OBJSDIR)
$(DEPS): | $(DEPSDIR)
$(LLOBJS): | $(OBJSDIR)

$(OBJSDIR):
	mkdir $(OBJSDIR)

$(DEPSDIR):
	mkdir $(DEPSDIR)

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
deps/bpf_generic_lsm_$$(VAR).d: process/bpf_generic_lsm.c
endef

# Generic build targets for each sub-dir

$(eval $(call DEFINE_VARIANT,v53))
$(eval $(call DEFINE_VARIANT,v511))
$(eval $(call DEFINE_VARIANT,v61))

# ALIGNCHECKER
objs/%.ll: $(ALIGNCHECKERDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(ALIGNCHECKERDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@


# Enforcer programs: bpf_enforcer, bpf_multi_enforcer, bpf_fmodret_enforcer

## bpf_enforcer: __BPF_OVERRIDE_RETURN, but no __MULTI_KPROBE
objs/bpf_enforcer.ll: process/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -D__BPF_OVERRIDE_RETURN -c $< -o $@

$(DEPSDIR)bpf_enforcer.d: process/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -D__BPF_OVERRIDE_RETURN -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@) $< > $@

## bpf_multi_enforcer: __BPF_OVERRIDE_RETURN and __MULTI_KPROBE
objs/bpf_multi_enforcer.ll: process/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -D__BPF_OVERRIDE_RETURN -D__MULTI_KPROBE -c $< -o $@

$(DEPSDIR)/bpf_multi_enforcer.d: process/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -D__BPF_OVERRIDE_RETURN -D__MULTI_KPROBE -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@) $< > $@

## bpf_fmodret_enforcer no bpf_override_return: we need fmod_ret
objs/bpf_fmodret_enforcer.ll: process/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)/bpf_fmodret_enforcer.d: process/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@) $< > $@

# PROCESSDIR
objs/%.ll: $(PROCESSDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

objs/bpf_multi_kprobe_v53.ll objs/bpf_multi_retkprobe_v53.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__MULTI_KPROBE -c $< -o $@

objs/%_v53.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -c $< -o $@

$(DEPSDIR)%.d: $(PROCESSDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@


$(DEPSDIR)%_v53.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

objs/bpf_multi_kprobe_v61.ll objs/bpf_multi_retkprobe_v61.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -D__V61_BPF_PROG -D__MULTI_KPROBE -c $< -o $@

objs/bpf_multi_uprobe_v61.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__V61_BPF_PROG -D__MULTI_KPROBE -c $< -o $@

objs/%_v61.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -D__V61_BPF_PROG -c $< -o $@

$(DEPSDIR)%_v61.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -D__V61_BPF_PROG -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

objs/bpf_multi_kprobe_v511.ll objs/bpf_multi_retkprobe_v511.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -D__MULTI_KPROBE -c $< -o $@

objs/%_v511.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -c $< -o $@

$(DEPSDIR)%_v511.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

objs/bpf_generic_lsm.ll: process/bpf_generic_lsm.c
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -c $< -o $@

$(DEPSDIR)/bpf_generic_lsm.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -MM -MP -MT $(patsubst $(DEPSDIR)bpf_generic_lsm.d, $(OBJSDIR)bpf_generic_lsm.ll, $@)   $< > $@

# BPFTESTDIR
objs/%.ll: $(BPFTESTDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(BPFTESTDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# CGROUPDIR
objs/%.ll: $(CGROUPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(CGROUPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# Remaining objects are built without mcpu=v2
objs/%.o: objs/%.ll
	$(LLC) $(LLC_FLAGS) -filetype=obj $< -o $@

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
