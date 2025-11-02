# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
# Copyright (c) 2025 Taira. All rights reserved.

# Build BoringTun static library for Apple platforms
#
# This Makefile builds the BoringTun Rust library as a static library
# for multiple architectures (arm64, x86_64) and platforms (macOS, iOS).
#
# Usage:
#   make build              # Build for current platform and architectures
#   make clean              # Clean build artifacts
#
# Environment variables (typically passed by Xcode or set for standalone builds):
#   ARCHS                   # Target architectures (default: x86_64 arm64)
#   PLATFORM_NAME           # Platform (default: macosx)
#   SDKROOT                 # SDK root path
#   CONFIGURATION_BUILD_DIR # Output directory for built library
#   CONFIGURATION_TEMP_DIR  # Temporary build directory

# Build configuration
ARCHS ?= x86_64 arm64
PLATFORM_NAME ?= macosx
SDKROOT ?= $(shell xcrun --sdk $(PLATFORM_NAME) --show-sdk-path)
CONFIGURATION_BUILD_DIR ?= $(CURDIR)/out
CONFIGURATION_TEMP_DIR ?= $(CURDIR)/.tmp

export PATH := $(PATH):/usr/local/bin:/opt/homebrew/bin
CARGO ?= cargo
LIPO ?= lipo
DESTDIR ?= $(CONFIGURATION_BUILD_DIR)
BUILDDIR ?= $(CONFIGURATION_TEMP_DIR)/boringtun-build

# Rust target triples for each architecture and platform
RUST_TARGET_arm64_macosx := aarch64-apple-darwin
RUST_TARGET_x86_64_macosx := x86_64-apple-darwin
RUST_TARGET_arm64_iphoneos := aarch64-apple-ios
RUST_TARGET_x86_64_iphoneos := x86_64-apple-ios
RUST_TARGET_arm64_iphonesimulator := aarch64-apple-ios-sim
RUST_TARGET_x86_64_iphonesimulator := x86_64-apple-ios

# BoringTun crate directory
BORINGTUN_DIR := $(CURDIR)/../../Packages/boringtun

.PHONY: build clean install

build: $(DESTDIR)/libboringtun.a

# Build BoringTun for a specific architecture
define build-boringtun
$(BUILDDIR)/libboringtun-$(1).a: $(BORINGTUN_DIR)/Cargo.toml
	@mkdir -p "$(BUILDDIR)"
	cd "$(BORINGTUN_DIR)" && \
		$(CARGO) build \
			--release \
			--target $(RUST_TARGET_$(1)_$(PLATFORM_NAME)) \
			--package boringtun \
			--features ffi-bindings \
			--lib
	@mkdir -p "$(BUILDDIR)"
	cp "$(BORINGTUN_DIR)/target/$(RUST_TARGET_$(1)_$(PLATFORM_NAME))/release/libboringtun.rlib" \
		"$(BUILDDIR)/libboringtun-$(1).a"
endef

# Generate build rules for each architecture
$(foreach ARCH,$(ARCHS),$(eval $(call build-boringtun,$(ARCH))))

# Create universal binary using lipo
$(DESTDIR)/libboringtun.a: $(foreach ARCH,$(ARCHS),$(BUILDDIR)/libboringtun-$(ARCH).a)
	@mkdir -p "$(DESTDIR)"
	$(LIPO) -create -output "$@" $^
	@echo "Built universal library: $@"

clean:
	rm -rf "$(BUILDDIR)" "$(DESTDIR)/libboringtun.a"
	cd "$(BORINGTUN_DIR)" && $(CARGO) clean

install: build
