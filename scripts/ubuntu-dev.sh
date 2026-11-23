#!/usr/bin/env bash
# ubuntu-dev.sh — Install required dependencies on Ubuntu to build src/proxy
#                 and run eBPF-proxy-nat/build.sh.

set -euo pipefail

# Ensure script is run with sudo if not already root
SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
    else
        echo "error: root privileges or sudo required to install packages." >&2
        exit 1
    fi
fi

PACKAGES=(
    build-essential
    clang
    llvm
    libelf-dev
    libbpf-dev
    libssl-dev
    pkg-config
    iproute2
)

# Kernel headers for the running kernel if available, otherwise generic
KERNEL_PKG="linux-headers-$(uname -r)"
if apt-cache show "$KERNEL_PKG" &>/dev/null; then
    PACKAGES+=("$KERNEL_PKG")
else
    PACKAGES+=(linux-headers-generic)
fi

echo "==> Updating apt package index..."
$SUDO apt-get update

echo "==> Installing packages: ${PACKAGES[*]}..."
$SUDO apt-get install -y "${PACKAGES[@]}"

echo "==> Development environment packages successfully installed."
