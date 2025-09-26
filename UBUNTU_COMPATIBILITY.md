# Ubuntu Compatibility Review for `fresh_node_notak.sh`

This document summarizes the findings from reviewing `fresh_node_notak.sh` for use on Ubuntu systems.

## Overview
The script is designed to bootstrap a Raspberry Pi-based mesh radio by installing networking and media services. It targets Debian-based distributions and makes heavy use of `apt`, `systemd`, and Python tooling.

Ubuntu shares Debian roots, so most package operations and service setup steps should apply. However, several issues will prevent the script from running to completion on a stock Ubuntu installation without modification.

## Critical Failures
The following problems stop the script because `set -u` treats undefined variables/functions as fatal:

1. **Undefined `RNSD_PATH` variable** – The Reticulum version check references `$RNSD_PATH`, but the variable is never set. On Ubuntu the script will exit immediately when it reaches the check block.【F:fresh_node_notak.sh†L312-L317】 Suggested fix: resolve the binary location before the version check and fail cleanly if it is missing, e.g.

   ```bash
   RNSD_PATH="${RNSD_PATH:-$(command -v rnsd || true)}"
   if [ -z "$RNSD_PATH" ]; then
     error "rnsd binary not found in PATH"
     exit 1
   fi
   ```

2. **Missing `need_cmd` helper** – The script calls `need_cmd rnstatus` without defining `need_cmd`. With `set -u`, this raises an "unbound variable" error and aborts execution.【F:fresh_node_notak.sh†L319-L321】 Suggested fix: either delete the helper usage or implement it inline. A minimal helper that works with `set -u` is:

   ```bash
   need_cmd() {
     command -v "$1" >/dev/null 2>&1 || {
       error "Required command '$1' not found"
       exit 1
     }
   }
   ```

   After adding the helper near the other utility functions, the existing `need_cmd rnstatus` line will work as intended.

3. **Undefined `$HOME_DIR` variable** – The Reticulum summary echoes `$HOME_DIR`, which is never assigned (the script uses `TARGET_HOME` earlier). This also terminates the run under `set -u`.【F:fresh_node_notak.sh†L326-L328】 Suggested fix: reuse `TARGET_HOME` instead of the nonexistent variable:

   ```bash
   echo "Configs: ${TARGET_HOME}/.config/reticulum"
   ```

Any Ubuntu run will therefore fail before the MediaMTX installation step.

## Other Ubuntu-Specific Concerns

- **Architecture-specific MediaMTX download** – The script fetches the `mediamtx_linux_amd64.tar.gz` artifact.【F:fresh_node_notak.sh†L341-L350】 This works on x86_64 Ubuntu but will fail on armhf/arm64 Ubuntu builds typically used on Raspberry Pi hardware. Add architecture detection before downloading, e.g.

  ```bash
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64) MTX_PKG=mediamtx_linux_amd64.tar.gz ;;
    aarch64) MTX_PKG=mediamtx_linux_arm64v8.tar.gz ;;
    armv7l|armv6l) MTX_PKG=mediamtx_linux_armv7.tar.gz ;;
    *) error "Unsupported architecture: $ARCH"; exit 1 ;;
  esac
  curl -L -o mediamtx.tar.gz "https://github.com/bluenviron/mediamtx/releases/latest/download/${MTX_PKG}"
  ```

- **`sudo` invocation while already root** – Ubuntu images usually ship with `sudo`, so `sudo systemctl ...` works, but the extra `sudo` call is unnecessary and can break on minimal images without `sudo`.【F:fresh_node_notak.sh†L323-L324】 Simplify the call to `systemctl --no-pager --full status rnsd || true`.

## Debian/Ubuntu Shared Package Availability
The core package set (`python3`, `aircrack-ng`, `batctl`, etc.) is available from Ubuntu's repositories, so the initial apt phases should succeed.【F:fresh_node_notak.sh†L87-L208】 The conditional block that installs Raspberry Pi kernel headers is skipped on Ubuntu because it detects the `ID=ubuntu` field in `/etc/os-release`, so it should not attempt to install Raspberry Pi–specific packages on Ubuntu.【F:fresh_node_notak.sh†L143-L165】

## Recommendations
To make the script Ubuntu-compatible:

1. Define `RNSD_PATH` (e.g., `RNSD_PATH=$(command -v rnsd)` with a fallback check) before use.【F:fresh_node_notak.sh†L312-L317】
2. Either implement a `need_cmd` helper or replace the call with a direct availability check for `rnstatus`.【F:fresh_node_notak.sh†L319-L321】
3. Use the existing `TARGET_HOME` variable (or define `HOME_DIR`) when referencing the Reticulum configuration directory.【F:fresh_node_notak.sh†L326-L328】
4. Detect the CPU architecture and download the matching MediaMTX tarball instead of hard-coding the amd64 build, ensuring Ubuntu-on-ARM installations succeed.【F:fresh_node_notak.sh†L341-L350】
5. Drop or guard the redundant `sudo` use when the script is already running as root to improve portability.【F:fresh_node_notak.sh†L323-L324】

Addressing these items will allow the script to complete successfully on Ubuntu while preserving compatibility with Raspberry Pi OS.
