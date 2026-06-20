#!/bin/bash
# Guest-side host/internet connectivity test for the ViperBoard host_tap NIC.
#
# Pass this to the gem5 config's --app argument. The e1000 NIC (enp0s5) is
# bridged to the host TAP device (gem5-tap, host side 192.168.100.1). Requires
# the host-side tap + NAT to already be set up, and a guest kernel with the
# e1000 module (e.g. vmlinux-rocm70). Run under KVM so real TCP/DNS timeouts
# behave.
set -x

IFACE=enp0s5
HOST_IP=192.168.100.1
GUEST_IP=192.168.100.2

# Bring up the interface and put it on the tap subnet.
ip link set "$IFACE" up
ip addr add "$GUEST_IP"/24 dev "$IFACE"
ip route add default via "$HOST_IP"
ip -o addr show "$IFACE"
ip route

# L3 reachability to the host end of the tap.
echo "=== NET_TEST ping host ($HOST_IP) ==="
ping -c 3 -W 3 "$HOST_IP"

# Internet by IP (no DNS): proves NIC -> tap -> host NAT -> internet works.
echo "=== NET_TEST ping internet (1.1.1.1) ==="
ping -c 3 -W 3 1.1.1.1

# DNS: external resolvers (8.8.8.8) are egress-filtered on this network, so use
# the host's internal resolvers (match `resolvectl status` on the host). The
# image uses systemd-resolved, so set it via resolvectl and write resolv.conf.
echo "=== NET_TEST DNS setup ==="
resolvectl dns "$IFACE" 10.176.3.2 10.234.250.9 2>/dev/null || true
resolvectl domain "$IFACE" '~.' 2>/dev/null || true
rm -f /etc/resolv.conf
printf 'nameserver 10.176.3.2\nnameserver 10.234.250.9\n' > /etc/resolv.conf

echo "=== NET_TEST ping by name (example.com) ==="
ping -c 3 -W 3 example.com

echo "=== NET_TEST HTTP (example.com) ==="
curl -sS -m 20 -o /dev/null \
    -w 'NET_TEST HTTP %{http_code} in %{time_total}s\n' \
    http://example.com/ || echo "NET_TEST curl failed"

echo "=== NET_TEST COMPLETE ==="
m5 exit
