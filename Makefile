SHELL := /bin/bash

.DEFAULT_GOAL := help

.PHONY: help dev-setup install-tools clone-sdks install-hooks build-workspace \
        dev-verify smoke-python smoke-node smoke-go gateway-health \
        demo-record

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
