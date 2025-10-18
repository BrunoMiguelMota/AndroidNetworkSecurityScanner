#!/bin/sh
# Fix common OpenWrt firewall4 (nftables) audit findings.
# - Normalizes WAN policies to 'drop' / 'reject' (lowercase for audit).
# - Removes any WAN=>* forwardings.
# - Disables and stops miniupnpd (UPnP/NAT-PMP).
# - Disables WAN IPSec allow rules (ESP/ISAKMP).
# - Leaves essential WAN rules (DHCP renew, IGMP/MLD, ICMPv6) intact.
#
# Usage:
#   chmod +x fix-openwrt-security.sh
#   ./fix-openwrt-security.sh
#
# Safe to re-run. Creates dated backups of /etc/config/firewall and /etc/config/upnpd.

set -eu

ts="$(date +%Y%m%d-%H%M%S)"
backup() {
  src="$1"
  [ -f "$src" ] || return 0
  cp "$src" "${src}.bak.${ts}"
  echo "[*] Backed up $(basename "$src") to ${src}.bak.${ts}"
}

find_zone_index() {
  # $1 = zone name (e.g., wan)
  name="$1"
  i=0
  while uci -q get firewall.@zone[$i] >/dev/null 2>&1; do
    zname="$(uci -q get firewall.@zone[$i].name || true)"
    if [ "$zname" = "$name" ]; then
      echo "$i"
      return 0
    fi
    i=$((i+1))
  done
  return 1
}

echo "=== OpenWrt Security Fixer ==="

# Ensure firewall4 exists
if ! opkg list-installed 2>/dev/null | grep -q '^firewall4 '; then
  echo "[!] firewall4 not detected. This script targets firewall4 (OpenWrt 22.03+)."
  exit 1
fi

backup /etc/config/firewall
[ -f /etc/config/upnpd ] && backup /etc/config/upnpd || true

# 1) Normalize WAN zone policies and keep masquerade as-is
WAN_IDX="$(find_zone_index wan || true)"
if [ -n "${WAN_IDX}" ]; then
  # Set to lowercase to satisfy the audit script’s string check
  uci set "firewall.@zone[${WAN_IDX}].input=drop"
  uci set "firewall.@zone[${WAN_IDX}].forward=reject"
  # Leave output/masq untouched
  echo "[*] Set WAN zone: input=drop, forward=reject"
else
  echo "[!] WAN zone not found; skipping WAN policy normalization."
fi

# 2) Remove any forwardings that originate from WAN
i=0
removed_fwds=0
while uci -q get firewall.@forwarding[$i] >/dev/null 2>&1; do
  src="$(uci -q get firewall.@forwarding[$i].src || true)"
  if [ "$src" = "wan" ]; then
    dest="$(uci -q get firewall.@forwarding[$i].dest || echo '?')"
    uci delete firewall.@forwarding[$i]
    echo "[*] Removed forwarding: wan => ${dest}"
    removed_fwds=$((removed_fwds+1))
    i=$((i-1)) # indices shift after deletion
  fi
  i=$((i+1))
done
[ "$removed_fwds" -eq 0 ] && echo "[*] No WAN=>* forwardings found."

# 3) Disable WAN IPSec allow rules unless explicitly needed
#    (These are often present but not required for most users.)
i=0
disabled_ipsec=0
while uci -q get firewall.@rule[$i] >/dev/null 2>&1; do
  name="$(uci -q get firewall.@rule[$i].name || echo)"
  src="$(uci -q get firewall.@rule[$i].src || echo)"
  if [ "$src" = "wan" ]; then
    case "$name" in
      *Allow-IPSec-ESP*|*Allow-ISAKMP*)
        uci set firewall.@rule[$i].enabled='0'
        echo "[*] Disabled WAN rule: $name"
        disabled_ipsec=$((disabled_ipsec+1))
        ;;
    esac
  fi
  i=$((i+1))
done
[ "$disabled_ipsec" -eq 0 ] && echo "[*] No WAN IPSec allow rules found to disable."

# 4) Disable and stop miniupnpd (UPnP/NAT-PMP)
if [ -x /etc/init.d/miniupnpd ]; then
  uci -q set upnpd.config.enabled='0' || true
  uci -q set upnpd.config.enable_upnp='0' || true
  uci -q set upnpd.config.enable_natpmp='0' || true
  uci -q commit upnpd || true
  /etc/init.d/miniupnpd stop || true
  /etc/init.d/miniupnpd disable || true
  echo "[*] miniupnpd disabled and stopped."
else
  echo "[*] miniupnpd not installed; nothing to disable."
fi

# Commit firewall changes and restart to flush any dynamic rules (e.g., prior UPnP)
uci commit firewall
/etc/init.d/firewall restart

echo
echo "=== Summary ==="
echo "- WAN zone set to input=drop, forward=reject (lowercase for audit)."
echo "- Removed ${removed_fwds} WAN=>* forwardings."
echo "- Disabled ${disabled_ipsec} WAN IPSec rules (ESP/ISAKMP) if present."
echo "- UPnP (miniupnpd) disabled/stopped (if installed)."
echo
echo "Note: The audit may still WARN about:"
echo "  - Allow-DHCP-Renew, Allow-DHCPv6 (required for ISP DHCP/DHCPv6)."
echo "  - Allow-IGMP/MLD and Allow-ICMPv6 (required for IPv6 and multicast)."
echo "These are normal and recommended to keep."
echo
echo "Re-run your audit script now."
