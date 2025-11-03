# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
# Copyright (c) 2025 Taira. All rights reserved.

# Build BoringTun static library and XCFramework for Apple platforms
#
# This Makefile builds the BoringTun Rust library as a static library
# for multiple architectures (arm64, x86_64) and platforms (macOS, iOS).
#
# Usage:
#   make build              # Build for current platform and architectures (legacy)
#   make build-xcframework  # Build XCFramework for all platforms (recommended)
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

.PHONY: build clean install build-xcframework prepare-headers

build: $(DESTDIR)/libboringtun.a

# XCFramework output path (two levels up to package root)
XCFRAMEWORK_PATH := $(CURDIR)/../../BoringTun.xcframework
HEADERS_DIR := $(DESTDIR)/headers

# Build BoringTun for a specific architecture
define build-boringtun
$(BUILDDIR)/libboringtun-$(1).a: $(BORINGTUN_DIR)/Cargo.toml
	@mkdir -p "$(BUILDDIR)"
	cd "$(BORINGTUN_DIR)" && \
		RUSTFLAGS="-C embed-bitcode=yes" $(CARGO) rustc \
			--release \
			--target $(RUST_TARGET_$(1)_$(PLATFORM_NAME)) \
			--package boringtun \
			--features ffi-bindings \
			--crate-type=staticlib
	@mkdir -p "$(BUILDDIR)"
	cp "$(BORINGTUN_DIR)/target/$(RUST_TARGET_$(1)_$(PLATFORM_NAME))/release/libboringtun.a" \
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
	rm -rf "$(BUILDDIR)" "$(DESTDIR)" "$(XCFRAMEWORK_PATH)"
	cd "$(BORINGTUN_DIR)" && $(CARGO) clean

install: build

# XCFramework build targets

# Prepare headers directory for XCFramework
prepare-headers:
	@echo "Preparing headers for XCFramework..."
	@mkdir -p "$(HEADERS_DIR)"
	@cp "$(BORINGTUN_DIR)/boringtun/src/wireguard_ffi.h" "$(HEADERS_DIR)/"
	@cp "$(CURDIR)/boringtun.h" "$(HEADERS_DIR)/"
	@cp "$(CURDIR)/module.modulemap" "$(HEADERS_DIR)/"
	@echo "Headers prepared in $(HEADERS_DIR)"

# Build static library for macOS (ARM64 only - Apple Silicon)
$(DESTDIR)/libboringtun-macosx.a:
	@echo "Building BoringTun for macOS (arm64)..."
	@mkdir -p "$(DESTDIR)"
	cd "$(BORINGTUN_DIR)" && RUSTFLAGS="-C embed-bitcode=yes" $(CARGO) rustc --release --target aarch64-apple-darwin --package boringtun --features ffi-bindings --crate-type=staticlib
	@cp "$(BORINGTUN_DIR)/target/aarch64-apple-darwin/release/libboringtun.a" "$@"
	@echo "Built macOS library: $@"

# Build static library for iOS device (ARM64 only)
$(DESTDIR)/libboringtun-iphoneos.a:
	@echo "Building BoringTun for iOS device (arm64)..."
	@mkdir -p "$(DESTDIR)"
	cd "$(BORINGTUN_DIR)" && RUSTFLAGS="-C embed-bitcode=yes" $(CARGO) rustc --release --target aarch64-apple-ios --package boringtun --features ffi-bindings --crate-type=staticlib
	@cp "$(BORINGTUN_DIR)/target/aarch64-apple-ios/release/libboringtun.a" "$@"
	@echo "Built iOS device library: $@"

# Build static library for iOS simulator (ARM64 only - Apple Silicon Macs)
$(DESTDIR)/libboringtun-iphonesimulator.a:
	@echo "Building BoringTun for iOS simulator (arm64)..."
	@mkdir -p "$(DESTDIR)"
	cd "$(BORINGTUN_DIR)" && \
		IPHONEOS_DEPLOYMENT_TARGET=15.0 \
		RUSTFLAGS="-C embed-bitcode=yes" \
		CFLAGS_aarch64_apple_ios_sim="-target arm64-apple-ios15.0-simulator" \
		$(CARGO) rustc --release --target aarch64-apple-ios-sim --package boringtun --features ffi-bindings --crate-type=staticlib
	@cp "$(BORINGTUN_DIR)/target/aarch64-apple-ios-sim/release/libboringtun.a" "$@"
	@echo "Built iOS simulator library: $@"

# Create XCFramework from all platform libraries (ARM64-only, no lipo)
# NOTE: iOS simulator omitted due to ring 0.16.20 build issues - can add later
build-xcframework: $(DESTDIR)/libboringtun-macosx.a $(DESTDIR)/libboringtun-iphoneos.a prepare-headers
	@echo "Creating XCFramework..."
	@rm -rf "$(XCFRAMEWORK_PATH)"
	xcodebuild -create-xcframework \
		-library "$(DESTDIR)/libboringtun-macosx.a" \
		-headers "$(HEADERS_DIR)" \
		-library "$(DESTDIR)/libboringtun-iphoneos.a" \
		-headers "$(HEADERS_DIR)" \
		-output "$(XCFRAMEWORK_PATH)"
	@echo "  XCFramework created at: $(XCFRAMEWORK_PATH)"
	@echo ""
	@echo "Platforms included:"
	@echo "  - macOS (ARM64)"
	@echo "  - iOS device (ARM64)"
	@echo "  - iOS simulator (SKIPPED - ring crate build issue, will add later)"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Run 'swift build' to verify package builds"
	@echo "  2. Run 'swift test' to verify tests pass"
