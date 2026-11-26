#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
# Explicit ELF alignment also covers devices configured with 16 KiB pages.
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-z,max-page-size=16384"
binding_env=()
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    # cargo-ndk's Windows CLANG_PATH can lack .exe; libclang then loses its
    # builtin include directory. Its underscore target args also replace the
    # generic args. Bindgen prefers the hyphen target keys we supply here.
    llvm_dir=$(cygpath -u "${LIBCLANG_PATH:-C:/Program Files/LLVM/bin}")
    test -f "$llvm_dir/libclang.dll" && test -f "$llvm_dir/clang.exe" || {
      echo 'Android JavaScript build requires LLVM; set LIBCLANG_PATH to its bin directory.' >&2
      exit 1
    }
    export LIBCLANG_PATH=$(cygpath -m "$llvm_dir")
    resource=$("$llvm_dir/clang.exe" -print-resource-dir | tr -d '\r')
    resource=$(cygpath -m "$resource")
    sysroot=$(cygpath -m "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/windows-x86_64/sysroot")
    for triple in aarch64-linux-android x86_64-linux-android; do
      binding_env+=("BINDGEN_EXTRA_CLANG_ARGS_$triple=--sysroot=\"$sysroot\" -I\"$sysroot/usr/include/$triple\" -resource-dir=\"$resource\"")
    done
    ;;
esac
env "${binding_env[@]}" cargo ndk -t arm64-v8a -t x86_64 --platform 26 -o android/app/src/main/jniLibs build --release -p prism-android --locked
