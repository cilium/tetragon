include ../Makefile.defs

TESTS = prepend_name_test.o pid_match_test.o

OBJSDIR  := objs/
OBJS := $(addprefix $(OBJSDIR),$(TESTS))
SUDO ?= sudo

.PHONY: all
all: $(OBJS)

.PHONY: test
test: $(OBJS)
	go test -exec "$(SUDO)" ./ $(BPFGOTESTFLAGS)

$(OBJS): | $(OBJSDIR)

$(OBJSDIR):
	mkdir $(OBJSDIR)

objs/%.o: %.c
	$(CLANG) $(CLANG_FLAGS) -I ../ -c $< -o $@

.PHONY: clean
clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(OBJSDIR)*.{o,ll,i,s}
