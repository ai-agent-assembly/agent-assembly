SHELL := /bin/bash

.DEFAULT_GOAL := help

.PHONY: help dev-setup install-tools clone-sdks install-hooks build-workspace \
        dev-verify smoke-python smoke-node smoke-go gateway-health \
        demo-record

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
