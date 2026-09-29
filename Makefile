# agent — build, test, install.
#
# The install layout is the whole reason this file exists, and it is not
# negotiable at runtime: the Lua tree ships as loose files beside the binary
# rather than embedded in it, so that a user can read the sandbox policy they are
# being asked to approve. An embedded copy is un-editable and un-inspectable, and
# a tool that asks before it touches your files ought to show you the file.
#
#     <prefix>/bin/agent            the executable
#     <prefix>/share/agent/lua/     the tree — policy, tools, starter config
#
# `src/lua/tree.rs` finds the tree by walking up from its own executable, so the
# binary is relocatable: move the prefix anywhere and it still resolves.

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/agent
CARGO ?= cargo
# `--locked` so an install cannot silently pick up a different dependency set
# than the one the suite was run against.
CARGO_FLAGS ?= --locked
# `share/agent/lua` is what the loader looks for; `PACKAGE` must agree with
# `PACKAGE` in src/lua/tree.rs.
PACKAGE := agent

.PHONY: all build test gate lint fmt fmt-check clippy install uninstall clean

all: build

build:
	$(CARGO) build --release

test:
	$(CARGO) test

# The gate the project holds itself to. `verify-sandbox.sh` runs the suite,
# fails on any clippy warning in a sandbox file, and scans those files for
# leftover instrumentation.
gate:
	./scripts/verify-sandbox.sh

lint: clippy

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check

# Installs the binary and the tree. `PREFIX=/home/you/.local make install` needs
# no root and is the recommended first try, because the agent's own config lives
# in ~/.config/agent and nothing here writes there.
install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 target/release/agent $(DESTDIR)$(BINDIR)/agent
	install -d $(DESTDIR)$(SHAREDIR)
	# The tree is copied, not linked: a symlink to the checkout would make an
	# installed agent follow whatever happens to be in the working tree.
	rm -rf $(DESTDIR)$(SHAREDIR)/lua
	cp -R lua $(DESTDIR)$(SHAREDIR)/lua
	@echo
	@echo "installed:"
	@echo "  $$(ls -d $(DESTDIR)$(BINDIR)/agent)"
	@echo "  $$(ls -d $(DESTDIR)$(SHAREDIR)/lua)/init.lua"
	@echo
	@echo "run $(DESTDIR)$(BINDIR)/agent once; it writes ~/.config/agent/init.lua"
	@echo "from the shipped one, which you then edit."

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/agent
	rm -rf $(DESTDIR)$(SHAREDIR)/lua
	@echo "left $(DESTDIR)$(SHAREDIR) (remove it by hand if it is now empty)"

clean:
	$(CARGO) clean
