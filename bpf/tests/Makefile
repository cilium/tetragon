include ../Makefile.defs

TESTS = prepend_name_test.o

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

objs/%.ll: %.c
	$(CLANG) $(CLANG_FLAGS) -I ../ -c $< -o $@

objs/%.o: objs/%.ll
	$(LLC) $(LLC_FLAGS) -filetype=obj $< -o $@

.PHONY: clean
clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(OBJSDIR)*.{o,ll,i,s}
