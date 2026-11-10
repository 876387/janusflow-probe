#!/bin/sh
# JanusFlow (雅努斯流 · janusflow.cn / JanusFlow.net / atooli.com)
# One-Click Installer for OpenWrt Routers (21.02 / 22.03 / 23.05 / 24.10)

set -e

ENDPOINT="https://www.atooli.com"
API_KEY=""
SECRET=""
IFACE="br-lan"
DEVICE_ID="openwrt-gw-01"
LOCAL_CIDR="10.0.0.0/8"
INTERVAL="60"

while [ $# -gt 0 ]; do
    case "$1" in
        --endpoint) ENDPOINT="$2"; shift 2 ;;
        --api-key) API_KEY="$2"; shift 2 ;;
        --secret) SECRET="$2"; shift 2 ;;
        --iface) IFACE="$2"; shift 2 ;;
        --device-id) DEVICE_ID="$2"; shift 2 ;;
        --local-cidr) LOCAL_CIDR="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

echo "[JanusFlow] Installing OpenWrt Edge Probe dependencies..."
if command -v opkg >/dev/null 2>&1; then
    opkg update
    opkg install python3-light python3-openssl python3-urllib python3-logging tcpdump-mini
fi

mkdir -p /etc/janusflow /var/run/janusflow
chmod 0700 /etc/janusflow

cat > /etc/janusflow/probe.env <<EOF
JANUSFLOW_ENDPOINT="${ENDPOINT}"
JANUSFLOW_API_KEY="${API_KEY}"
JANUSFLOW_SIGN_SECRET="${SECRET}"
JANUSFLOW_IFACE="${IFACE}"
JANUSFLOW_DEVICE_ID="${DEVICE_ID}"
JANUSFLOW_LOCAL_CIDR="${LOCAL_CIDR}"
JANUSFLOW_INTERVAL="${INTERVAL}"
JANUSFLOW_MODE="both"
EOF
chmod 0600 /etc/janusflow/probe.env

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_SRC="${SCRIPT_DIR}/../../src/janusflow_probe"
if [ ! -d "${LIB_SRC}" ]; then
    echo "[JanusFlow] ERROR: janusflow_probe library not found at ${LIB_SRC}; run this installer from a full repo checkout." >&2
    exit 1
fi
mkdir -p /usr/lib/janusflow/janusflow_probe
cp -f "${LIB_SRC}"/*.py /usr/lib/janusflow/janusflow_probe/
cp -f "${SCRIPT_DIR}/openwrt_probe_agent.py" /usr/bin/janusflow-openwrt-probe
chmod 0755 /usr/bin/janusflow-openwrt-probe

if [ -d /etc/init.d ]; then
    cp -f "${SCRIPT_DIR}/janusflow-probe.init" /etc/init.d/janusflow-probe
    chmod 0755 /etc/init.d/janusflow-probe
    /etc/init.d/janusflow-probe enable
    /etc/init.d/janusflow-probe restart
    echo "[JanusFlow] OpenWrt procd service 'janusflow-probe' enabled and started."
fi
