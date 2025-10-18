#!/bin/sh
# OpenWrt Security Audit (firewall4/nftables focused)
# - Safe to run: read-only checks, no changes made
# - BusyBox/ash compatible; avoids non-default deps
# - Tested on OpenWrt 22.03+ (firewall4); works on GL.iNet builds too
#
# Usage:
#   chmod +x openwrt-security-audit.sh
#   ./openwrt-security-audit.sh
#
# Exit code: 0 if no FAIL items, 1 otherwise

set -eu

# ------------- UI helpers -------------
RED="$(printf '\033[31m')" || true
YEL="$(printf '\033[33m')" || true
GRN="$(printf '\033[32m')" || true
CYA="$(printf '\033[36m')" || true
RST="$(printf '\033[0m')" || true

PASS_C="${GRN}[PASS]${RST}"
WARN_C="${YEL}[WARN]${RST}"
FAIL_C="${RED}[FAIL]${RST}"
INFO_C="${CYA}[INFO]${RST}"

FAILS=0

pass() { printf "%s %s\n" "$PASS_C" "$*"; }
warn() { printf "%s %s\n" "$WARN_C" "$*"; }
fail() { printf "%s %s\n" "$FAIL_C" "$*"; FAILS=1; }
info() { printf "%s %s\n" "$INFO_C" "$*"; }

has() { command -v "$1" >/dev/null 2>&1; }

# ------------- UCI helpers -------------
# Return index of firewall zone by name, or empty if not found
zone_index_by_name() {
  name="$1"
  idx=""
  i=0
  while uci -q get firewall.@zone[$i] >/dev/null 2>&1; do
    zname="$(uci -q get firewall.@zone[$i].name || true)"
    [ "$zname" = "$name" ] && { idx="$i"; break; }
    i=$((i+1))
  done
  [ -n "$idx" ] && printf "%s" "$idx" || true
}

zone_opt() {
  name="$1"; opt="$2"
  idx="$(zone_index_by_name "$name" || true)"
  [ -n "$idx" ] && uci -q get "firewall.@zone[$idx].$opt" || true
}

# Return count of forwardings from a source zone
count_forwardings_from() {
  src="$1"
  c=0
  i=0
  while uci -q get firewall.@forwarding[$i] >/dev/null 2>&1; do
    s="$(uci -q get firewall.@forwarding[$i].src || true)"
    [ "$s" = "$src" ] && c=$((c+1))
    i=$((i+1))
  done
  printf "%s" "$c"
}

# Return list of dest zones for a given src zone (space-separated)
forward_dests_from() {
  src="$1"
  i=0
  out=""
  while uci -q get firewall.@forwarding[$i] >/dev/null 2>&1; do
    s="$(uci -q get firewall.@forwarding[$i].src || true)"
    if [ "$s" = "$src" ]; then
      d="$(uci -q get firewall.@forwarding[$i].dest || true)"
      [ -n "$d" ] && out="$out $d"
    fi
    i=$((i+1))
  done
  printf "%s\n" "$out"
}

# ------------- Core checks -------------

check_firewall_backend() {
  if opkg list-installed 2>/dev/null | grep -q '^firewall4 '; then
    pass "firewall4 (nftables) detected."
  elif opkg list-installed 2>/dev/null | grep -q '^firewall '; then
    warn "Legacy firewall (fw3/iptables) detected. Consider upgrading to firewall4."
  else
    fail "No firewall package found (firewall4 or firewall)."
  fi
}

check_legacy_iptables_mix() {
  legacy_found=0
  if has iptables-legacy && iptables-legacy-save 2>/dev/null | grep -qv '^#'; then
    legacy_found=1
  fi
  if has ip6tables-legacy && ip6tables-legacy-save 2>/dev/null | grep -qv '^#'; then
    legacy_found=1
  fi
  if [ "$legacy_found" -eq 1 ]; then
    fail "Legacy iptables rules are loaded. Mixing with firewall4 is unsafe. Flush/remove iptables-legacy and restart firewall."
  else
    pass "No active legacy iptables rules detected."
  fi
}

check_wan_zone() {
  # WAN zone posture
  input="$(zone_opt wan input || echo drop)"
  forward="$(zone_opt wan forward || echo reject)"
  masq="$(zone_opt wan masq || echo 0)"
  fcount="$(count_forwardings_from wan)"
  fwdests="$(forward_dests_from wan | awk '{$1=$1;print}')"

  # Input
  case "$input" in
    drop) pass "WAN input: drop";;
    reject) warn "WAN input: reject (acceptable, but 'drop' is stealthier).";;
    *) fail "WAN input: '$input' (should be drop or reject).";;
  esac

  # Forward
  if [ "$forward" = "reject" ]; then
    pass "WAN forward policy: reject"
  else
    fail "WAN forward policy is '$forward' (should be reject)."
  fi

  # Masquerade
  if [ "$masq" = "1" ]; then
    pass "WAN masquerading enabled."
  else
    warn "WAN masquerading disabled. OK if you don't NAT on WAN (e.g., bridge or routed)."
  fi

  # Inter-zone forwardings
  if [ "$fcount" -gt 0 ]; then
    fail "Forwardings from WAN to other zones: $fwdests (remove unless you are intentionally routing from WAN inward)."
  else
    pass "No forwardings from WAN to internal/VPN zones."
  fi
}

check_upnp() {
  if [ -x /etc/init.d/miniupnpd ]; then
    if /etc/init.d/miniupnpd enabled >/dev/null 2>&1 || /etc/init.d/miniupnpd status 2>/dev/null | grep -q running; then
      # Check ACL posture quickly
      if uci -q show upnpd | grep -q "enabled='1'"; then
        fail "UPnP (miniupnpd) is enabled/running. Disable it to prevent WAN port mappings unless you explicitly need it."
      else
        warn "miniupnpd service present; verify it is disabled and stopped."
      fi
    else
      pass "UPnP (miniupnpd) is disabled/stopped."
    fi
  else
    pass "UPnP daemon not installed."
  fi
}

check_wan_port_forwards() {
  i=0
  count=0
  while uci -q get firewall.@redirect[$i] >/dev/null 2>&1; do
    src="$(uci -q get firewall.@redirect[$i].src || true)"
    enabled="$(uci -q get firewall.@redirect[$i].enabled || echo 1)"
    name="$(uci -q get firewall.@redirect[$i].name || echo "redirect_$i")"
    if [ "$src" = "wan" ] && [ "$enabled" = "1" ]; then
      dport="$(uci -q get firewall.@redirect[$i].dest_port || echo '?')"
      toip="$(uci -q get firewall.@redirect[$i].dest_ip || echo '?')"
      proto="$(uci -q get firewall.@redirect[$i].proto || echo 'tcp')"
      warn "WAN port forward: $name proto=${proto} dport=${dport} → ${toip}"
      count=$((count+1))
    fi
    i=$((i+1))
  done
  [ "$count" -eq 0 ] && pass "No active WAN port forwards."
}

check_wan_allow_rules() {
  # General accept rules from WAN (e.g., SSH/HTTP/HTTPS) are risky
  i=0
  found=0
  while uci -q get firewall.@rule[$i] >/dev/null 2>&1; do
    src="$(uci -q get firewall.@rule[$i].src || true)"
    target="$(uci -q get firewall.@rule[$i].target || true)"
    enabled="$(uci -q get firewall.@rule[$i].enabled || echo 1)"
    dest_port="$(uci -q get firewall.@rule[$i].dest_port || true)"
    name="$(uci -q get firewall.@rule[$i].name || echo "rule_$i")"
    if [ "$src" = "wan" ] && [ "$target" = "ACCEPT" ] && [ "$enabled" = "1" ]; then
      warn "WAN allow rule: $name (dest_port=${dest_port:-any})"
      found=1
    fi
    i=$((i+1))
  done
  [ "$found" -eq 0 ] && pass "No permissive 'ACCEPT' rules from WAN."
}

check_dropbear() {
  if [ ! -f /etc/config/dropbear ]; then
    warn "Dropbear (SSH) config not found; ensure SSH exposure is intended."
    return
  fi
  inst=0
  bad_pw=0
  exposed_any=0
  while uci -q get dropbear.@dropbear[$inst] >/dev/null 2>&1; do
    pw="$(uci -q get dropbear.@dropbear[$inst].PasswordAuth || echo 1)"
    rpw="$(uci -q get dropbear.@dropbear[$inst].RootPasswordAuth || echo 1)"
    port="$(uci -q get dropbear.@dropbear[$inst].Port || echo 22)"
    iface="$(uci -q get dropbear.@dropbear[$inst].Interface || true)"
    [ "$pw" = "1" ] && bad_pw=1
    [ "$rpw" = "1" ] && bad_pw=1
    # If not bound to LAN interface specifically, rely on firewall. Warn if WAN allow rule exists for SSH.
    inst=$((inst+1))
  done

  if [ "$bad_pw" -eq 1 ]; then
    warn "SSH password authentication enabled. Consider key-based auth (set PasswordAuth/RootPasswordAuth to '0')."
  else
    pass "SSH password authentication disabled (good)."
  fi

  # Detect explicit WAN open for 22
  i=0
  ssh_open_wan=0
  while uci -q get firewall.@rule[$i] >/dev/null 2>&1; do
    src="$(uci -q get firewall.@rule[$i].src || true)"
    target="$(uci -q get firewall.@rule[$i].target || true)"
    dport="$(uci -q get firewall.@rule[$i].dest_port || true)"
    enabled="$(uci -q get firewall.@rule[$i].enabled || echo 1)"
    if [ "$src" = "wan" ] && [ "$target" = "ACCEPT" ] && [ "$enabled" = "1" ]; then
      case "$dport" in
        *22*|22) ssh_open_wan=1 ;;
      esac
    fi
    i=$((i+1))
  done
  if [ "$ssh_open_wan" -eq 1 ]; then
    fail "SSH allowed from WAN. Remove the WAN allow rule or bind Dropbear to LAN only."
  else
    pass "SSH not explicitly allowed from WAN."
  fi
}

check_luci_http() {
  if [ ! -f /etc/config/uhttpd ]; then
    info "uhttpd (LuCI) not installed or config missing."
    return
  fi

  # Look for WAN allow rules to 80/443
  i=0
  http_open_wan=0
  https_open_wan=0
  while uci -q get firewall.@rule[$i] >/dev/null 2>&1; do
    src="$(uci -q get firewall.@rule[$i].src || true)"
    target="$(uci -q get firewall.@rule[$i].target || true)"
    dport="$(uci -q get firewall.@rule[$i].dest_port || true)"
    enabled="$(uci -q get firewall.@rule[$i].enabled || echo 1)"
    if [ "$src" = "wan" ] && [ "$target" = "ACCEPT" ] && [ "$enabled" = "1" ]; then
      case "$dport" in
        *80*|80) http_open_wan=1 ;;
      esac
      case "$dport" in
        *443*|443) https_open_wan=1 ;;
      esac
    fi
    i=$((i+1))
  done

  if [ "$http_open_wan" -eq 1 ]; then
    fail "LuCI HTTP (80) allowed from WAN. Disable or restrict to LAN."
  else
    pass "No WAN allow rule for HTTP (80)."
  fi
  if [ "$https_open_wan" -eq 1 ]; then
    warn "LuCI HTTPS (443) allowed from WAN. If remote admin is not required, remove this rule."
  else
    pass "No WAN allow rule for HTTPS (443)."
  fi
}

check_listeners() {
  # Best-effort: show listeners; many builds lack ss/netstat options
  if has ss; then
    info "Listening TCP sockets (first 15):"
    ss -lnt 2>/dev/null | sed -n '1,15p' || true
  elif has netstat; then
    info "Listening TCP sockets (first 15):"
    netstat -lnt 2>/dev/null | sed -n '1,15p' || true
  else
    info "No ss/netstat available to list listeners."
  fi
}

check_wifi_security() {
  i=0
  open_count=0
  weak_count=0
  while uci -q get wireless.@wifi-iface[$i] >/dev/null 2>&1; do
    enc="$(uci -q get wireless.@wifi-iface[$i].encryption || echo none)"
    ssid="$(uci -q get wireless.@wifi-iface[$i].ssid || echo iface_$i)"
    disabled="$(uci -q get wireless.@wifi-iface[$i].disabled || echo 0)"
    [ "$disabled" = "1" ] && { i=$((i+1)); continue; }
    case "$enc" in
      none|open|wep|*wep*)
        fail "Wi‑Fi '$ssid' uses insecure encryption '$enc'. Use WPA2-PSK (psk2) or WPA3 (sae/sae-mixed)."
        open_count=$((open_count+1))
        ;;
      psk|psk-mixed)
        warn "Wi‑Fi '$ssid' uses WPA/WPA2 mixed (psk/psk-mixed). Prefer psk2 or sae-mixed."
        weak_count=$((weak_count+1))
        ;;
      psk2|sae|sae-mixed|wpa3*)
        : # good
        ;;
      *)
        warn "Wi‑Fi '$ssid' encryption '$enc' is unrecognized; verify it's secure."
        ;;
    esac
    i=$((i+1))
  done
  [ "$open_count" -eq 0 ] && pass "No open/WEPl Wi‑Fi networks."
  [ "$weak_count" -eq 0 ] && pass "No legacy WPA-only Wi‑Fi (good)."
}

check_pbr_vpn() {
  # Optional: detect Policy Based Routing and VPN kill-switch stance
  if opkg list-installed 2>/dev/null | grep -q '^pbr '; then
    se="$(uci -q get pbr.config.strict_enforcement || echo 0)"
    if [ "$se" = "1" ]; then
      pass "PBR strict enforcement enabled (reduces VPN leak risk)."
    else
      warn "PBR installed but strict enforcement is off. VPN-marked flows may fall back to WAN if VPN is down."
    fi
  else
    info "PBR not detected. If you depend on split tunneling, consider installing pbr."
  fi
}

check_routes_leak_hint() {
  # Show main and any numeric tables often used by WAN/WG; user can confirm
  info "Routing tables (default routes):"
  has ip && ip -4 route show table main | grep -E '^default' || true

  # List tables referenced by ip rules
  if has ip; then
    ip -4 rule show | awk '/lookup/ {print $NF}' | sort -u | while read -r t; do
      case "$t" in
        main|local|default) continue ;;
      esac
      printf " - table %s: " "$t"
      ip -4 route show table "$t" | grep -E '^default' || echo "(no default)"
    done
  fi
}

check_ipv6_posture() {
  # Ensure WAN zone also covers IPv6 (firewall4 is inet, but check policy)
  input="$(zone_opt wan input || echo drop)"
  forward="$(zone_opt wan forward || echo reject)"
  if [ "$input" = "drop" ] || [ "$input" = "reject" ]; then
    pass "IPv6 unsolicited inbound is blocked by WAN input policy."
  else
    fail "WAN input policy may allow unsolicited IPv6 inbound."
  fi
}

# ------------- Run all checks -------------

echo "=== OpenWrt Security Audit ==="
echo "Hostname: $(cat /proc/sys/kernel/hostname 2>/dev/null || echo unknown)"
echo "Model: $(cat /tmp/sysinfo/model 2>/dev/null || echo unknown)"
echo "Release: $(cat /etc/openwrt_release 2>/dev/null | tr '\n' ' ' || echo unknown)"
echo

check_firewall_backend
check_legacy_iptables_mix
check_wan_zone
check_upnp
check_wan_port_forwards
check_wan_allow_rules
check_dropbear
check_luci_http
check_listeners
check_wifi_security
check_pbr_vpn
check_routes_leak_hint
check_ipv6_posture

echo
if [ "$FAILS" -eq 0 ]; then
  echo "${GRN}Overall: no FAIL items detected.${RST}"
  exit 0
else
  echo "${RED}Overall: FAIL items detected. Review and remediate above.${RST}"
  exit 1
fi
