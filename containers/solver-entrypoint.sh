#!/bin/sh
# Web-blind solver entrypoint.
#
# Installs an egress allowlist, then execs the requested command. Blocks
# everything except: loopback, the embedded Docker DNS, the host gateway
# (challenge targets publish ports on the host and are reached via
# host.docker.internal -> gateway), and the devin backend endpoints from
# SOLVER_ALLOWED_HOSTS. Everything else — the general internet — is
# dropped, so a session cannot look up published benchmark solutions.
set -eu

# IPv4 first, so a failed ip6tables on hosts without v6 is non-fatal.
ip6tables -P OUTPUT DROP 2>/dev/null || true

GW="$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')"

iptables -A OUTPUT -o lo -j ACCEPT
# embedded Docker DNS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
# host gateway + host.docker.internal aliases: challenge targets publish
# ports on the host and are reached via these (the exact IP differs by
# runtime: docker-desktop, colima, plain dockerd)
if [ -n "${GW:-}" ]; then
    iptables -A OUTPUT -d "$GW" -j ACCEPT
fi
for host in host.docker.internal gateway.docker.internal; do
    for ip in $(getent hosts "$host" 2>/dev/null | awk '{print $1}' | sort -u); do
        case "$ip" in
            *:*) ;;
            *) iptables -A OUTPUT -d "$ip" -j ACCEPT ;;
        esac
    done
done
# devin backend endpoints (resolved now; CDN rotation within a run is rare
# and a failed session simply retries)
for host in ${SOLVER_ALLOWED_HOSTS:-}; do
    for ip in $(getent hosts "$host" 2>/dev/null | awk '{print $1}' | sort -u); do
        case "$ip" in
            *:*) ;;    # v6 handled by the blanket drop above
            *) iptables -A OUTPUT -d "$ip" -j ACCEPT ;;
        esac
    done
done
iptables -A OUTPUT -j DROP

exec "$@"
