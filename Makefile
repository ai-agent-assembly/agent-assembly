SHELL := /bin/bash

.DEFAULT_GOAL := help

.PHONY: help dev-setup install-tools clone-sdks install-hooks build-workspace \
        test dev-verify smoke-python smoke-node smoke-go gateway-health \
        demo-record

## dev-setup: Bootstrap the full local development environment (install tools, clone SDKs, install hooks, build)
dev-setup: install-tools clone-sdks install-hooks build-workspace
	@echo ""
	@echo "dev-setup complete. Run 'make dev-verify' to validate."

## clone-sdks: Clone (or pull) SDK polyrepos listed in scripts/sdk-repos.txt into sibling dirs
clone-sdks:
	@while IFS= read -r url || [ -n "$$url" ]; do \
		[ -z "$$url" ] && continue; \
		repo=$$(basename "$$url" .git); \
		dest="$$(dirname $$(pwd))/$$repo"; \
		if [ -d "$$dest/.git" ]; then \
			echo "  Updating $$repo ..."; \
			git -C "$$dest" pull --ff-only; \
		else \
			echo "  Cloning $$repo ..."; \
			git clone "$$url" "$$dest"; \
		fi; \
	done < scripts/sdk-repos.txt

## test: Run the full test suite across all workspace crates
test:
	@cargo nextest run --workspace --exclude aa-ebpf

## smoke-python: Run Python SDK smoke tests against the sibling python-sdk directory
smoke-python:
	@printf "[1/4] python smoke ... "; \
	sdk="$$(dirname $$(pwd))/python-sdk"; \
	t0=$$(date +%s); \
	if (cd "$$sdk" && pytest tests/smoke/ -q) >/tmp/aa-smoke-python.log 2>&1; then \
		t1=$$(date +%s); echo "OK ($$(( t1 - t0 ))s)"; \
	else \
		t1=$$(date +%s); echo "FAIL ($$(( t1 - t0 ))s)"; \
		cat /tmp/aa-smoke-python.log >&2; exit 1; \
	fi

## smoke-node: Run Node SDK smoke tests against the sibling node-sdk directory
smoke-node:
	@printf "[2/4] node smoke   ... "; \
	sdk="$$(dirname $$(pwd))/node-sdk"; \
	t0=$$(date +%s); \
	if (cd "$$sdk" && npm test --workspace smoke) >/tmp/aa-smoke-node.log 2>&1; then \
		t1=$$(date +%s); echo "OK ($$(( t1 - t0 ))s)"; \
	else \
		t1=$$(date +%s); echo "FAIL ($$(( t1 - t0 ))s)"; \
		cat /tmp/aa-smoke-node.log >&2; exit 1; \
	fi

## smoke-go: Run Go SDK smoke tests against the sibling go-sdk directory
smoke-go:
	@printf "[3/4] go smoke     ... "; \
	sdk="$$(dirname $$(pwd))/go-sdk"; \
	t0=$$(date +%s); \
	if (cd "$$sdk" && go test ./internal/smoke/...) >/tmp/aa-smoke-go.log 2>&1; then \
		t1=$$(date +%s); echo "OK ($$(( t1 - t0 ))s)"; \
	else \
		t1=$$(date +%s); echo "FAIL ($$(( t1 - t0 ))s)"; \
		cat /tmp/aa-smoke-go.log >&2; exit 1; \
	fi

## build-workspace: Build the Cargo workspace (excludes eBPF crates requiring nightly)
build-workspace:
	@cargo build --workspace --exclude aa-ebpf

## install-hooks: Install git pre-commit hooks via pre-commit
install-hooks:
	@pre-commit install

## install-tools: Check required toolchains via scripts/install.sh
install-tools:
	@bash scripts/install.sh

## help: Show this help message
help:
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^## [a-zA-Z_-]+:' $(MAKEFILE_LIST) \
		| sed 's/^## /  /' \
		| column -t -s ':'
