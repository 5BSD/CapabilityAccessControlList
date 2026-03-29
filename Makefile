# CACL - Capability Access Control List FreeBSD Kernel Module
#
# Standard targets:
#   all       - Build the kernel module (default)
#   clean     - Remove built files
#   install   - Install module to /boot/modules
#   load      - Load the module
#   unload    - Unload the module
#   reload    - Unload and reload the module
#   test      - Build tests, load module, run tests, unload module
#   man       - Install man pages
#
# Variables:
#   DESTDIR   - Installation prefix (default: empty)
#   DEBUG     - Enable debug build (default: no)
#

KMOD=	cacl
SRCS=	cacl.c

# Request vnode_if.h generation - bsd.kmod.mk handles this
SRCS+=	vnode_if.h

# Man pages
MAN=	cacl.4

# Debug build support
.if defined(DEBUG)
DEBUG_FLAGS+=	-DDEBUG -g
.endif

# Include FreeBSD kernel module build infrastructure
.include <bsd.kmod.mk>

# Custom targets
# Note: bsd.kmod.mk provides 'load' and 'unload' targets

.PHONY: reload test test-only man-install

reload:
	-kldunload $(KMOD)
	kldload ./$(KMOD).ko

# Build tests only (no run)
test-build:
	@echo "=== Building tests ==="
	$(MAKE) -C tests clean
	$(MAKE) -C tests

# Run tests only (assumes module loaded)
test-only:
	@if [ ! -c /dev/cacl ]; then \
		echo "ERROR: /dev/cacl not found. Load module first: make load"; \
		exit 1; \
	fi
	@cd tests && ./run_tests.sh

# Full test cycle: build module, build tests, load, run, unload
test: all test-build
	@echo ""
	@echo "=== Loading module ==="
	@if kldstat -q -m $(KMOD) 2>/dev/null; then \
		echo "Unloading existing $(KMOD) module..."; \
		kldunload $(KMOD) || true; \
	fi
	kldload ./$(KMOD).ko
	@if [ ! -c /dev/cacl ]; then \
		echo "ERROR: /dev/cacl not created after kldload"; \
		exit 1; \
	fi
	@echo "Module loaded successfully."
	@echo ""
	@echo "=== Running tests ==="
	@cd tests && ./run_tests.sh; \
	test_result=$$?; \
	echo ""; \
	echo "=== Unloading module ==="; \
	kldunload $(KMOD); \
	exit $$test_result

man-install:
	install -m 444 cacl.4 $(DESTDIR)/usr/share/man/man4/

# Help target
.PHONY: help
help:
	@echo "CACL Kernel Module Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build the kernel module (default)"
	@echo "  clean      - Remove built files"
	@echo "  install    - Install module to /boot/modules"
	@echo "  load       - Load the module (from bsd.kmod.mk)"
	@echo "  unload     - Unload the module (from bsd.kmod.mk)"
	@echo "  reload     - Unload and reload the module"
	@echo "  test       - Full cycle: build, load, run tests, unload"
	@echo "  test-build - Build tests only"
	@echo "  test-only  - Run tests (module must be loaded)"
	@echo "  man-install - Install man pages"
	@echo "  help       - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  DEBUG=1    - Enable debug build"
	@echo ""
	@echo "Quick start:"
	@echo "  make           # Build module"
	@echo "  make test      # Build, load, test, unload (as root)"
