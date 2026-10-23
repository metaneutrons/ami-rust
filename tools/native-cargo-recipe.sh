#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Internal, immutable producer recipe selection; v2 remains the default.
native_cargo_select_recipe() {
  case "${2-three-host-v2}" in
    three-host-v2)
      RECIPE_NAME=three-host-v2
      RECIPE_SOURCE_SHA=73c9fc79976541cb43cefb39ce878218a3245493e86bb37fac449ec3bee00a52
      SOURCE_PATCH_SHA=1f22b7e2c6a7f4469cc6c2f4a84019d8d8ade558e78241d1e996d88a7f1de97f
      ;;
    three-host-v3)
      RECIPE_NAME=three-host-v3
      RECIPE_SOURCE_SHA=9c8ac1d58262c73116c74172c93c345196bd8ffa3995bebba3d1f8ea00bc59ce
      SOURCE_PATCH_SHA=2c3ab831d216cc4395decc4bcc307a1d9bac6b6936cd01d7c496c44e55d9826b
      ;;
    *) echo "unsupported native Cargo recipe" >&2; return 1 ;;
  esac
  RECIPE="$1/host/cargo-repro/$RECIPE_NAME"
}
