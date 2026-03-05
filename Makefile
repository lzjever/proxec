# Makefile for proxec
# Following GNU Make conventions where applicable

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

CARGO ?= cargo
INSTALL ?= install

.PHONY: all build release test check lint fmt clean install uninstall

all: build

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test

check: lint
	$(CARGO) check

lint:
	$(CARGO) clippy -- -D warnings

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt -- --check

clean:
	$(CARGO) clean

install: release
	$(INSTALL) -Dm755 target/release/proxec $(DESTDIR)$(BINDIR)/proxec

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/proxec

dist: release
	mkdir -p dist
	tar -czvf dist/proxec-$(shell git describe --tags 2>/dev/null || echo "dev")-$(shell uname -m).tar.gz \
		-C target/release proxec

.PHONY: help
help:
	@echo "Targets:"
	@echo "  all       - build (default)"
	@echo "  release   - optimized build"
	@echo "  test      - run tests"
	@echo "  lint      - run clippy"
	@echo "  fmt       - format code"
	@echo "  clean     - remove artifacts"
	@echo "  install   - install to $(BINDIR)"
	@echo "  uninstall - remove from $(BINDIR)"
	@echo "  dist      - create release tarball"
