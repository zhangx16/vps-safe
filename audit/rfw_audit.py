"""Audit-only RFW-inspired protocol observations; never attaches XDP or drops packets.

FET exemptions/thresholds adapted from narwhal-cloud/rfw (MIT option).
See third_party/RFW-LICENSE-MIT.txt and docs/rfw-rules.md for provenance.
"""
import collections
import ipaddress
import re
import socket
import struct
import time

SMTP_PORTS = {25, 465, 587, 2525}
PROTOCOL_TITLES = {
    'http': '观察到明文 HTTP 入站', 'socks5': '观察到 SOCKS5 握手入站',
    'wireguard': '观察到 WireGuard 特征入站', 'quic': '观察到 QUIC 特征入站',
    'fet': '疑似全加密流量特征（统计推断）',
}


def audit_hit(rule, title, scope, evidence, severity='info'):
    return dict(rule=rule, title=title, severity=severity, scope=scope, kind='network',
                evidence=evidence, status='observation' if severity == 'info' else 'needs_review')


def smtp_findings(network):
    result = []
    for row in network:
        connections = row.get('smtp_outbound', [])
        if connections:
            result.append(audit_hit('smtp-egress', '观察到 SMTP 端口外连，需核实邮件用途', row['scope'],
                                   dict(connections=connections, direction='outbound',
                                        inference_only=True, detection='destination-port'), 'medium'))
    return result


def country_findings(clients, geo, policy):
    result, unknown = [], 0
    mode = policy.get('mode', 'off')
    if mode == 'off':
        return result, dict(mode='off', unknown_ips=0)
    countries = set(policy['countries'])
    for scope, peers in clients.items():
        if scope == 'HOST' or (policy.get('containers') and scope not in policy['containers']):
            continue
        violations = collections.Counter()
        for ip in peers:
            country = geo.get(ip).get('country')
            if not country:
                unknown += 1
                continue
            restricted = country in countries if mode == 'deny' else country not in countries
            if restricted:
                violations[country] += 1
        if violations:
            result.append(audit_hit('country-policy', '入站来源不符合配置的国家策略', scope,
                                   dict(mode=mode, countries=dict(violations), policy_countries=sorted(countries),
                                        audit_only=True, inference_only=True), 'medium'))
    return result, dict(mode=mode, unknown_ips=unknown)


def decode_frame(frame):
    """Ethernet with up to 2 VLANs; unfragmented IPv4/basic IPv6 TCP/UDP only."""
    if len(frame) < 14:
        return None
    ether = int.from_bytes(frame[12:14], 'big')
    offset = 14
    for _ in range(2):
        if ether not in (0x8100, 0x88a8):
            break
        if len(frame) < offset + 4:
            return None
        ether = int.from_bytes(frame[offset+2:offset+4], 'big')
        offset += 4
    if ether == 0x0800:
        data = frame[offset:]
        if len(data) < 20 or data[0] >> 4 != 4:
            return None
        ihl = (data[0] & 15) * 4
        total = int.from_bytes(data[2:4], 'big')
        if ihl < 20 or total < ihl or len(data) < total or int.from_bytes(data[6:8], 'big') & 0x3fff:
            return None
        proto, src, dst = data[9], socket.inet_ntop(socket.AF_INET, data[12:16]), socket.inet_ntop(socket.AF_INET, data[16:20])
        transport = data[ihl:total]
    elif ether == 0x86dd:
        data = frame[offset:]
        if len(data) < 40 or data[0] >> 4 != 6:
            return None
        total = 40 + int.from_bytes(data[4:6], 'big')
        if len(data) < total:
            return None
        proto, src, dst = data[6], socket.inet_ntop(socket.AF_INET6, data[8:24]), socket.inet_ntop(socket.AF_INET6, data[24:40])
        transport = data[40:total]
    else:
        return None
    if proto == 6:
        if len(transport) < 20:
            return None
        header = (transport[12] >> 4) * 4
        if header < 20 or len(transport) < header:
            return None
        payload, flags = transport[header:], transport[13]
    elif proto == 17:
        if len(transport) < 8:
            return None
        size = int.from_bytes(transport[4:6], 'big')
        if size < 8 or len(transport) < size:
            return None
        payload, flags = transport[8:size], 0
    else:
        return None
    sport, dport = struct.unpack('!HH', transport[:4])
    return dict(src=src, dst=dst, sport=sport, dport=dport,
                transport='tcp' if proto == 6 else 'udp', flags=flags, payload=payload)


def is_http(payload):
    return bool(re.match(rb'^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) ', payload))


def fet_candidate(payload):
    """RFW-derived strict heuristic, not Shannon entropy or proxy identification."""
    if len(payload) < 16:
        return False
    tls = len(payload) >= 5 and payload[0] in (20, 21, 22, 23) and payload[1] == 3 and payload[2] <= 4
    if tls or is_http(payload) or all(32 <= b <= 126 for b in payload[:6]):
        return False
    sample = payload[:32]
    # bin().count supports Python 3.9, unlike int.bit_count().
    average = sum(bin(b).count('1') for b in sample) * 100 // len(sample)
    return 340 < average < 460


def quic_long(payload):
    if len(payload) < 7 or payload[0] & 0xC0 != 0xC0:
        return False
    version = payload[1:5]
    dcid = payload[5]
    if dcid > 20 or len(payload) < 7 + dcid:
        return False
    scid = payload[6 + dcid]
    if scid > 20 or len(payload) < 7 + dcid + scid:
        return False
    remaining = len(payload) - (7 + dcid + scid)
    if version == b'\0\0\0\0':
        return remaining >= 4 and remaining % 4 == 0
    return version in (b'\0\0\0\1', bytes.fromhex('6b3343cf')) and remaining >= 1


def detect_protocol(packet, first_tcp_payload=False, quic_known=False, fet_mode='off'):
    p = packet['payload']
    if not p:
        return None
    if packet['transport'] == 'tcp':
        if is_http(p):
            return 'http'
        if len(p) >= 3 and p[0] == 5 and 1 <= p[1] <= 32 and len(p) >= 2 + p[1] and all(v <= 9 or v == 128 for v in p[2:2+p[1]]):
            return 'socks5'
        if first_tcp_payload and fet_mode == 'strict' and fet_candidate(p):
            return 'fet'
    else:
        if len(p) >= 4 and p[1:4] == b'\0\0\0':
            if (p[0] in (1, 2, 3) and len(p) == {1:148, 2:92, 3:64}[p[0]]) or (p[0] == 4 and len(p) >= 32 and len(p) % 16 == 0):
                return 'wireguard'
        if quic_long(p):
            return 'quic'
        # Short headers alone are ambiguous: require an observed long header in this flow.
        if quic_known and len(p) >= 2 and p[0] & 0xC0 == 0x40:
            return 'quic'
        # Conservative legacy Google QUIC public header with an 8-byte connection ID.
        if len(p) >= 13 and p[0] & 0x09 == 0x09 and re.fullmatch(rb'Q0[0-9]{2}', p[9:13]):
            return 'quic'
    return None


def packet_scope(packet, forwards, names, excluded):
    mapping = forwards.get((packet['transport'], packet['dport']))
    if mapping:
        return (names.get(mapping[0], mapping[0]), mapping[1]) if mapping[1] not in excluded else (None, None)
    if packet['dport'] not in excluded:
        return 'HOST', packet['dport']
    return None, None


def capture(interface, seconds, max_packets, fet_mode, forwards, containers, excluded, errors):
    """Bounded, passive AF_PACKET sampling; no promiscuous mode, PCAP or payload logs."""
    names = {c['name']:c['id'] for c in containers}
    totals = collections.Counter()
    sources = collections.defaultdict(set)
    syn_flows, quic_flows = set(), set()
    seen = count = 0
    start = time.monotonic()
    try:
        if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', interface):
            raise ValueError('invalid interface name')
        socket.if_nametoindex(interface)
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
            sock.bind((interface, 0))
            sock.settimeout(0.25)
            while count < max_packets and time.monotonic() - start < seconds:
                try:
                    frame, address = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                count += 1
                if address[2] == socket.PACKET_OUTGOING:
                    continue
                packet = decode_frame(frame)
                if not packet:
                    continue
                try:
                    if not ipaddress.ip_address(packet['src']).is_global:
                        continue
                except ValueError:
                    continue
                scope, guest = packet_scope(packet, forwards, names, excluded)
                if scope is None:
                    continue
                seen += 1
                flow = (packet['src'],packet['sport'],packet['dst'],packet['dport'])
                if packet['transport'] == 'tcp' and packet['flags'] & 2 and not packet['flags'] & 16:
                    if len(syn_flows) < 4096:
                        syn_flows.add(flow)
                first = packet['transport'] == 'tcp' and flow in syn_flows and bool(packet['payload'])
                protocol = detect_protocol(packet, first, flow in quic_flows, fet_mode)
                if first:
                    syn_flows.discard(flow)
                if protocol == 'quic' and quic_long(packet['payload']) and len(quic_flows) < 4096:
                    quic_flows.add(flow)
                if protocol:
                    key = (scope, protocol, packet['dport'], guest)
                    totals[key] += 1
                    if len(sources[key]) < 256:
                        sources[key].add(packet['src'])
    except (OSError, ValueError) as e:
        errors.append(dict(command='passive_capture', error=type(e).__name__))
    hits = [audit_hit('protocol-' + proto, PROTOCOL_TITLES[proto], scope,
                     dict(interface=interface, host_port=port, guest_port=guest,
                          observed_packets=num, unique_sources=len(sources[(scope,proto,port,guest)]),
                          protocol=proto, attribution='narwhal-port-map' if scope != 'HOST' else 'host-unattributed',
                          inference_only=proto == 'fet', payload_saved=False),
                     'medium' if proto == 'fet' else 'info')
            for (scope,proto,port,guest),num in totals.items()]
    return hits, dict(enabled=True, interface=interface, sampled_packets=count, parsed_inbound=seen,
                      duration_seconds=round(time.monotonic()-start,2), limit_reached=count>=max_packets,
                      fet_mode=fet_mode, ipv6='basic-header-only',
                      limitations='Sampling only; no TCP reassembly/IPv6 extensions/fragments; no XDP-blocked packets. Protocol presence does not imply abuse.')


def parse_rfw_stats(text, forwards, containers, previous=None):
    """Parse ungrouped `rfw stats` output. Historical counters are not live clients."""
    previous = previous or {}
    names = {c['name']:c['id'] for c in containers}
    records, next_state = [], {}
    for line in text.splitlines():
        m = re.fullmatch(r'\s*(\S+)\s+(TCP|UDP)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*', line)
        if not m:
            continue
        src, proto, port, allowed, blocked, total = m.groups()
        try:
            ipaddress.ip_address(src)
        except ValueError:
            continue
        port, allowed, blocked, total = map(int, (port, allowed, blocked, total))
        if not 1 <= port <= 65535 or total != allowed + blocked:
            continue
        key = src + '/' + proto + '/' + str(port)
        old = previous.get(key)
        delta = blocked - old if isinstance(old, int) and blocked >= old else None
        next_state[key] = blocked
        mapping = forwards.get((proto.lower(),port))
        scope = names.get(mapping[0],mapping[0]) if mapping else 'HOST'
        records.append(dict(scope=scope, source_ip=src, protocol=proto, host_port=port,
                            allowed=allowed, blocked=blocked, blocked_delta=delta,
                            cumulative=True, last_seen_available=False))
    return records, next_state
