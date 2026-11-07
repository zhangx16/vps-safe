#!/usr/bin/env python3
"""NAT/container abuse evidence collector. Python 3.9+, Linux, standard library."""
import argparse
import collections
import datetime as dt
import fcntl
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request

import rfw_audit

VERSION = '0.2.0'
BASE = Path(__file__).resolve().parent
DEFAULTS = dict(exclude_client_ports=[22, 8792], min_client_ips=5,
                min_geo_regions=3, min_consecutive_samples=3,
                min_geo_duration_seconds=120, geo_level='country',
                max_geo_lookups=100, max_startup_files=3000, max_file_bytes=262144,
                allowlist=[], country_policy={'mode': 'off', 'countries': [], 'containers': []})
START_DIRS = ['etc/systemd/system', 'etc/init.d', 'etc/local.d', 'etc/cron.d',
              'etc/crontabs', 'var/spool/cron', 'etc/periodic']
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def load_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default


def private_dir(path):
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    if p.is_symlink() or p.stat().st_uid != os.getuid():
        raise ValueError('State/report directory must be owned by current user and not a symlink')
    p.chmod(0o700)
    return p


def atomic_text(path, text):
    p = Path(path)
    tmp = p.with_name(p.name + '.tmp-' + str(os.getpid()))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    finally:
        if tmp.exists():
            tmp.unlink()


def read_text(path):
    try:
        return Path(path).read_text(errors='replace')
    except (OSError, ValueError):
        return ''


class Runner:
    def __init__(self):
        self.errors = []

    def run(self, argv, timeout=25, optional=False):
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                               env={**os.environ, 'LC_ALL': 'C'})
            if p.returncode and not optional:
                self.errors.append({'command': argv[0], 'error': 'exit ' + str(p.returncode)})
            return p.stdout if not p.returncode else ''
        except (OSError, subprocess.TimeoutExpired) as e:
            if not optional:
                self.errors.append({'command': argv[0], 'error': type(e).__name__})
            return ''

    def json(self, argv, optional=False):
        try:
            return json.loads(self.run(argv, optional=optional) or '[]')
        except ValueError:
            self.errors.append({'command': argv[0], 'error': 'invalid JSON'})
            return []


def read_process(pid):
    p = Path('/proc') / str(pid)
    raw = (p / 'stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    args = (p / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
    return dict(pid=int(pid), ppid=int(fields[1]), comm=(p / 'comm').read_text().strip(),
                exe=os.readlink(p / 'exe'), cgroup=(p / 'cgroup').read_text().strip(),
                pid_ns=os.readlink(p / 'ns/pid'), start_ticks=int(fields[19]),
                ticks=int(fields[11]) + int(fields[12]),
                rss_mib=round(int(fields[21]) * os.sysconf('SC_PAGE_SIZE') / 1048576, 2),
                _args=args)


def processes():
    result = {}
    for p in Path('/proc').iterdir():
        if p.name.isdigit():
            try:
                result[int(p.name)] = read_process(int(p.name))
            except (OSError, ValueError, IndexError):
                pass
    return result


def discover(runner):
    result = []
    for runtime in ('podman', 'docker'):
        if not shutil.which(runtime):
            continue
        ids = runner.run([runtime, 'ps', '-aq']).split()
        if not ids:
            continue
        rows = runner.json([runtime, 'inspect', *ids])
        for x in rows if isinstance(rows, list) else []:
            state = x.get('State', {})
            result.append(dict(runtime=runtime, id=x['Id'], name=x['Name'].lstrip('/'),
                               pid=state.get('Pid', 0), state=state.get('Status', 'unknown'),
                               upper_dir=x.get('GraphDriver', {}).get('Data', {}).get('UpperDir'),
                               mounts=[m.get('Destination', '') for m in x.get('Mounts', [])]))
    if shutil.which('incus'):
        for x in runner.json(['incus', 'list', '--format', 'json']):
            state = runner.json(['incus', 'query', '/1.0/instances/' + x['name'] + '/state'])
            if isinstance(state, dict) and 'metadata' in state:
                state = state['metadata']
            result.append(dict(runtime='incus', id=x['name'], name=x['name'],
                               pid=state.get('pid', 0) if isinstance(state, dict) else 0,
                               state=x.get('status', 'unknown'), upper_dir=None, mounts=[]))
    return result


def map_processes(procs, containers):
    for p in procs.values():
        p['scope'] = 'HOST'
        for c in containers:
            init = procs.get(c['pid'])
            # A host PID namespace container cannot safely be inferred from namespace alone.
            same_ns = init and init['pid_ns'] == p['pid_ns'] and init['pid_ns'] != os.readlink('/proc/1/ns/pid')
            cg = p['cgroup']
            cid = c['id']
            cgroup_match = (cid in cg) if c['runtime'] != 'incus' else any(
                t in cg for t in ('/lxc.payload.' + cid + '/', '/lxc/' + cid + '/',
                                  '/lxc.payload.' + cid + '\n')) or cg.endswith('/lxc.payload.' + cid)
            if cgroup_match or same_ns:
                p['scope'] = c['id']
                break


def allowed(scope, rule_id, cfg):
    now = dt.datetime.now(dt.timezone.utc)
    for e in cfg['allowlist']:
        if e.get('container') != scope or rule_id not in e.get('rules', []):
            continue
        if e.get('expires'):
            try:
                if dt.datetime.fromisoformat(e['expires'].replace('Z', '+00:00')) <= now:
                    continue
            except (ValueError, TypeError):
                continue
        return True
    return False


def rule_matches(text, rules):
    return [r for r in rules if r['_regex'].search(text)]


def finding(rule, scope, kind, evidence):
    return dict(rule=rule['id'], title=rule['title'], severity=rule['severity'],
                scope=scope, kind=kind, evidence=evidence, status='needs_review')


def process_findings(procs, rules):
    hits = []
    for p in procs.values():
        if p['pid'] == os.getpid():
            continue
        for r in rule_matches(p['comm'] + ' ' + p['exe'] + ' ' + p['_args'], rules):
            # Never persist arguments: proxy credentials frequently appear in argv.
            evidence = {k: p[k] for k in ('pid', 'comm', 'exe', 'start_ticks', 'rss_mib', 'cpu_pct')}
            evidence['boot_id'] = read_text(BOOT_ID).strip()
            if r['id'] == 'open-proxy':
                evidence['authentication'] = proxy_auth(p)
            hits.append(finding(r, p['scope'], 'process', evidence))
    return hits


def proxy_auth(p):
    """Configuration evidence only; no passwords, usernames or proxy requests."""
    if p['comm'] == 'microsocks':
        user = bool(re.search(r'(?:^|\s)-u(?:\s|\S)', p['_args']))
        password = bool(re.search(r'(?:^|\s)-P(?:\s|\S)', p['_args']))
        bypass = bool(re.search(r'(?:^|\s)-(?:1|w)(?:\s|\S|$)', p['_args']))
        return 'credentials_configured_with_possible_bypass' if user and password and bypass else (
            'credentials_configured' if user and password else 'no_credentials_in_arguments')
    if p['comm'] == 'danted':
        root = Path('/proc') / str(p['pid']) / 'root'
        for rel in ('etc/danted.conf', 'etc/sockd.conf', 'usr/local/etc/sockd.conf'):
            try:
                f = rooted_file(root, rel)
                if not f.is_file() or f.stat().st_size > 262144:
                    continue
                text = '\n'.join(line.split('#', 1)[0] for line in f.read_text().splitlines())
                methods = re.findall(r'^\s*(?:socksmethod|method)\s*:\s*([^\n}]+)', text, re.M)
                if any('none' in value.split() for value in methods):
                    return 'anonymous_method_configured'
                if methods and all('username' in value.split() or 'pam.username' in value.split() for value in methods):
                    return 'username_authentication_configured'
            except (OSError, ValueError):
                pass
    return 'unknown_review_required'


def rooted_file(root, path):
    """Resolve symlinks as the container would, never via host absolute symlinks."""
    todo = list(Path(path).parts)
    parts = []
    links = 0
    while todo:
        part = todo.pop(0)
        if part in ('', '/', '.'):
            continue
        if part == '..':
            if not parts:
                raise ValueError('path escapes container root')
            parts.pop()
            continue
        q = root.joinpath(*parts, part)
        if q.is_symlink():
            links += 1
            if links > 30:
                raise ValueError('symlink loop')
            target = os.readlink(q)
            if target.startswith('/'):
                parts = []
            todo = list(Path(target).parts) + todo
        else:
            parts.append(part)
    return root.joinpath(*parts)


def startup_command(line, path):
    s = line.strip()
    if not s or s.startswith(('#', ';')):
        return ''
    if path.endswith(('.service', '.socket', '.timer')):
        return s.split('=', 1)[1] if re.match(r'^Exec(Start|StartPre|StartPost|Stop|Reload)\s*=', s) else ''
    if '/cron' in path or '/periodic/' in path:
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', s):
            return ''
        return s
    # OpenRC dependencies/descriptions are not executed programs.
    if re.match(r'^(use|need|after|before|provide|description|name)\b', s):
        return ''
    return s if re.match(r'^(command(?:_args)?=|exec\s|start-stop-daemon\s|(?:/\S+|\w[\w.-]*)\s)', s) else ''


def startup_findings(containers, rules, cfg, runner):
    hits, coverage = [], []
    scopes = [dict(id='HOST', root=Path('/'), type='host')]
    for c in containers:
        if c['pid']:
            scopes.append(dict(id=c['id'], root=Path('/proc') / str(c['pid']) / 'root', type='running'))
        elif c.get('upper_dir'):
            scopes.append(dict(id=c['id'], root=Path(c['upper_dir']), type='stopped_upper_only'))
    for scope in scopes:
        root, seen, count, errors = scope['root'], set(), 0, 0
        files = []
        try:
            for rel in START_DIRS:
                base = root / rel
                if base.is_dir():
                    for parent, dirs, names in os.walk(base, followlinks=False):
                        dirs[:] = [n for n in dirs if not (Path(parent) / n).is_symlink()]
                        for name in names:
                            files.append((Path(parent) / name).relative_to(root))
                            if len(files) >= cfg['max_startup_files']:
                                break
                        if len(files) >= cfg['max_startup_files']:
                            break
                if len(files) >= cfg['max_startup_files']:
                    break
            files += [Path('etc/rc.local'), Path('etc/crontab')]
            for rel in files:
                try:
                    f = rooted_file(root, str(rel))
                    if not f.is_file() or f.stat().st_size > cfg['max_file_bytes']:
                        continue
                    key = (f.stat().st_dev, f.stat().st_ino)
                    if key in seen:
                        continue
                    seen.add(key)
                    count += 1
                    for no, line in enumerate(f.read_text(errors='replace').splitlines(), 1):
                        command = startup_command(line, '/' + str(rel))
                        for r in rule_matches(command, rules) if command else []:
                            hits.append(finding(r, scope['id'], 'startup',
                                                dict(path='/' + str(rel), line=no,
                                                     coverage=scope['type'])))
                except (OSError, ValueError):
                    errors += 1
        except OSError:
            errors += 1
        coverage.append(dict(scope=scope['id'], files=count, errors=errors, type=scope['type'],
                             truncated=len(files) >= cfg['max_startup_files']))
    return hits, coverage


def endpoint(value):
    addr, _, port = value.rpartition(':')
    return addr.strip('[]'), int(port) if port.isdigit() else 0


def public_ip(value):
    try:
        ip = ipaddress.ip_address(value.split('%')[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return str(ip) if ip.is_global else None
    except ValueError:
        return None


def socket_rows(text):
    rows = []
    for line in text.splitlines():
        a = line.split()
        if len(a) >= 5:
            la, lp = endpoint(a[3])
            ra, rp = endpoint(a[4])
            rows.append(dict(state=a[0], local_ip=la, local_port=lp, remote_ip=ra, remote_port=rp))
    return rows


def narwhal_ports(db_path, errors):
    if not Path(db_path).exists():
        return {}
    try:
        con = sqlite3.connect('file:' + str(Path(db_path).resolve()) + '?mode=ro', uri=True, timeout=2)
        rows = con.execute('select protocol,host_port,vm_id,guest_port from port_forwards').fetchall()
        con.close()
        return {(str(proto).lower(), int(port)): (vm, int(guest)) for proto, port, vm, guest in rows}
    except sqlite3.Error as e:
        errors.append({'command': 'narwhal_database', 'error': type(e).__name__})
        return {}


def collect_network(containers, runner, cfg, db_path):
    clients = collections.defaultdict(set)
    stats = []
    forwards = narwhal_ports(db_path, runner.errors)
    host = socket_rows(runner.run(['ss', '-Htan']))
    excluded = set(cfg['exclude_client_ports'])
    names = {c['name']: c['id'] for c in containers}
    # Narwhal userspace TCP forwarding preserves the real client only on the host socket.
    for row in host:
        mapping = forwards.get(('tcp', row['local_port']))
        if row['state'] == 'ESTAB' and mapping and mapping[1] not in excluded:
            peer = public_ip(row['remote_ip'])
            if peer:
                clients[names.get(mapping[0], mapping[0])].add(peer)
    scopes = [dict(id='HOST', pid=0)] + [c for c in containers if c['pid']]
    host_netns = os.readlink('/proc/1/ns/net')
    for c in scopes:
        prefix = [] if c['id'] == 'HOST' else ['nsenter', '-t', str(c['pid']), '-n']
        if c['id'] != 'HOST':
            try:
                if os.readlink('/proc/' + str(c['pid']) + '/ns/net') == host_netns:
                    stats.append(dict(scope=c['id'], shared_host_netns=True, incoming_clients=[]))
                    continue
            except OSError:
                continue
        listeners = socket_rows(runner.run(prefix + ['ss', '-Hlnt']))
        ports = {r['local_port'] for r in listeners} - excluded
        rows = host if c['id'] == 'HOST' else socket_rows(runner.run(prefix + ['ss', '-Htan']))
        states = collections.Counter(r['state'] for r in rows)
        smtp = [dict(remote_ip=r['remote_ip'], remote_port=r['remote_port'], state=r['state'])
                for r in rows if r['state'] in ('ESTAB', 'SYN-SENT')
                and r['remote_port'] in rfw_audit.SMTP_PORTS and r['local_port'] not in ports
                and public_ip(r['remote_ip'])]
        peers = set()
        for row in rows:
            peer = public_ip(row['remote_ip'])
            if peer and row['state'] == 'ESTAB':
                peers.add(peer)
                if row['local_port'] in ports:
                    clients[c['id']].add(peer)
        stats.append(dict(scope=c['id'], tcp_states=dict(states), public_tcp_peers=len(peers),
                          listening_tcp_ports=sorted(ports), smtp_outbound=smtp[:100]))
    # UDP DNAT attribution, when conntrack is installed. Only original client tuples are used.
    udp_available = bool(shutil.which('conntrack'))
    if udp_available:
        local_ips = set()
        for interface in runner.json(['ip', '-j', 'address']):
            local_ips.update(a.get('local') for a in interface.get('addr_info', []))
        text = runner.run(['conntrack', '-L', '-p', 'udp'], timeout=15)
        for line in text.splitlines():
            pairs = re.findall(r'\b(src|dst|sport|dport)=([^\s]+)', line)
            original = {}
            for k, v in pairs:
                if k in original:
                    break
                original[k] = v
            try:
                mapping = forwards.get(('udp', int(original.get('dport', '0'))))
                # Exclude UNREPLIED probes: mere unsolicited packets are not established usage.
                if (mapping and original.get('dst') in local_ips and
                        mapping[1] not in excluded and '[UNREPLIED]' not in line):
                    peer = public_ip(original.get('src', ''))
                    if peer:
                        clients[names.get(mapping[0], mapping[0])].add(peer)
            except ValueError:
                continue
    for s in stats:
        s['incoming_clients'] = sorted(clients.get(s['scope'], set()))
    return stats, clients, dict(udp_conntrack=udp_available, narwhal_forward_rules=len(forwards),
                              limitations='TCP current established sockets; UDP conntrack optional. QUIC/proxy tunnels may hide clients. UDP records may outlive active sessions.')


class Geo:
    def __init__(self, provider, db_path, state_dir, cfg, errors):
        self.provider, self.cfg, self.errors = provider, cfg, errors
        self.cache_path = state_dir / 'geo-cache.json'
        self.cache = load_json(self.cache_path, {})
        self.lookups = 0
        self.reader = None
        if db_path:
            try:
                import maxminddb
                self.reader = maxminddb.open_database(db_path)
            except (ImportError, OSError, ValueError) as e:
                raise ValueError('Offline GeoIP requires maxminddb and a valid database: ' + str(e))

    def get(self, ip):
        if self.reader:
            raw = self.reader.get(ip) or {}
            sub = raw.get('subdivisions', [])
            return dict(country=raw.get('country', {}).get('iso_code'),
                        region=sub[0].get('iso_code') if sub else None)
        if self.provider == 'none':
            return {}
        cached = self.cache.get(ip, {})
        if time.time() - cached.get('time', 0) < 86400:
            return cached.get('data', {})
        if self.lookups >= self.cfg['max_geo_lookups']:
            return {}
        self.lookups += 1
        try:
            req = urllib.request.Request('https://ipwho.is/' + ip,
                                         headers={'User-Agent': 'nat-safe/' + VERSION})
            with urllib.request.urlopen(req, timeout=5) as response:
                raw = json.loads(response.read(65536))
            if not raw.get('success'):
                return {}
            data = dict(country=raw.get('country_code'), region=raw.get('region_code'))
            self.cache[ip] = dict(time=time.time(), data=data)
            return data
        except (OSError, ValueError) as e:
            self.errors.append({'command': 'geo_lookup', 'error': type(e).__name__})
            return {}

    def save(self):
        self.cache = {ip: v for ip, v in self.cache.items() if time.time() - v.get('time', 0) < 86400}
        atomic_text(self.cache_path, json.dumps(self.cache, ensure_ascii=False))
        if self.reader:
            self.reader.close()


def geo_findings(clients, geo, cfg, previous, now):
    hits, history = [], {}
    for scope, peers in clients.items():
        if scope == 'HOST':
            continue
        regions = set()
        known = 0
        for ip in sorted(peers):
            d = geo.get(ip)
            if d.get('country'):
                known += 1
                regions.add(d['country'] + (':' + (d.get('region') or '?') if cfg['geo_level'] == 'region' else ''))
        # Region unknown is never positive geographic evidence.
        if cfg['geo_level'] == 'region':
            regions = {r for r in regions if not r.endswith(':?')}
        exceeds = len(peers) >= cfg['min_client_ips'] and len(regions) >= cfg['min_geo_regions']
        old = previous.get(scope, {})
        contiguous = 0 <= now - old.get('last', 0) <= 900
        if exceeds:
            count = old.get('count', 0) + 1 if contiguous else 1
            first = old.get('first', now) if contiguous else now
            history[scope] = dict(count=count, first=first, last=now)
            sustained = count >= cfg['min_consecutive_samples'] and now - first >= cfg['min_geo_duration_seconds']
            rule = dict(id='multi-region-sharing', title='疑似跨地区多人共享/机场行为', severity='high' if sustained else 'medium')
            hit = finding(rule, scope, 'network', dict(client_ips=len(peers), geo_known_ips=known,
                          regions=sorted(regions), samples=count, duration_seconds=round(now-first),
                          sustained=sustained, inference_only=True))
            hits.append(hit)
        elif len(peers) >= cfg['min_client_ips'] and known < cfg['min_client_ips']:
            hits.append(finding(dict(id='many-clients', title='多个公网来源，地区证据不足', severity='medium'),
                                scope, 'network', dict(client_ips=len(peers), geo_known_ips=known)))
    return hits, history


def apply_policy(hits, cfg):
    for h in hits:
        if allowed(h['scope'], h['rule'], cfg):
            h['status'] = 'allowlisted'


def verify_identity(evidence):
    if read_text(BOOT_ID).strip() != evidence.get('boot_id'):
        return False
    try:
        p = read_process(evidence['pid'])
        return p['start_ticks'] == evidence['start_ticks'] and p['exe'] == evidence['exe']
    except (OSError, ValueError, IndexError, KeyError):
        return False


def enforce(hits, containers, args, runner):
    actions = []
    selected = set(args.select or [])
    requested = set(args.rule or [])
    cs = {c['id']: c for c in containers}
    by_name = {c['name']: c['id'] for c in containers}
    selected = {by_name.get(s, s) for s in selected}
    eligible = [h for h in hits if h['scope'] in selected and h['rule'] in requested and h['status'] != 'allowlisted']
    for h in eligible:
        action = dict(scope=h['scope'], rule=h['rule'], action=args.action, utc=utc())
        if h['kind'] == 'network':
            # Geography is inference; never authorize automatic punishment from this signal alone.
            action.update(result='refused', reason='network/geo findings require manual business review; not an enforcement trigger')
            actions.append(action)
            continue
        if h['kind'] != 'process' or not verify_identity(h['evidence']):
            action.update(result='refused', reason='requires a live process with matching PID/start time/executable')
            actions.append(action)
            continue
        if args.action == 'terminate':
            if h['scope'] == 'HOST':
                action.update(result='refused', reason='host processes are protected')
            elif not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
                action.update(result='refused', reason='race-free termination requires Python/kernel pidfd support')
            else:
                fd = None
                try:
                    fd = os.pidfd_open(h['evidence']['pid'])
                    # Recheck after obtaining the stable process reference.
                    if not verify_identity(h['evidence']):
                        raise ProcessLookupError('process identity changed')
                    signal.pidfd_send_signal(fd, signal.SIGTERM)
                    action.update(result='signal_sent', pid=h['evidence']['pid'], signal='SIGTERM',
                                  note='Startup item is not disabled; supervisor may restart process.')
                except OSError as e:
                    action.update(result='failed', reason=type(e).__name__)
                finally:
                    if fd is not None:
                        os.close(fd)
        else:
            c = cs.get(h['scope'])
            if not c:
                action.update(result='refused', reason='only a discovered container can be stopped')
            elif any(a.get('scope') == c['id'] and a.get('result') == 'stopped' for a in actions):
                continue
            else:
                if c['runtime'] in ('podman', 'docker'):
                    cmd = [c['runtime'], 'stop', '--time', '10', c['id']]
                    inspect = runner.json([c['runtime'], 'inspect', c['id']])
                    current = inspect[0] if isinstance(inspect, list) and inspect else {}
                    if current.get('State', {}).get('Pid') != c['pid'] or current.get('Id') != c['id']:
                        action.update(result='refused', reason='container identity changed')
                        actions.append(action)
                        continue
                else:
                    cmd = ['incus', 'stop', c['name'], '--timeout', '10']
                    current = runner.json(['incus', 'query', '/1.0/instances/' + c['name'] + '/state'])
                    if isinstance(current, dict) and 'metadata' in current:
                        current = current['metadata']
                    if not isinstance(current, dict) or current.get('pid') != c['pid']:
                        action.update(result='refused', reason='Incus process identity changed')
                        actions.append(action)
                        continue
                errors_before = len(runner.errors)
                runner.run(cmd, timeout=20)
                action.update(result='stopped' if len(runner.errors) == errors_before else 'failed')
                action['recovery_command'] = ([c['runtime'], 'start', c['id']] if c['runtime'] != 'incus'
                                              else ['incus', 'start', c['name']])
        actions.append(action)
    return actions


def format_report(report):
    names = {c['id']: c['name'] for c in report['containers']}
    lines = ['# NAT Safe 检测报告', '', '时间：' + report['utc'],
             '主机：' + report['hostname'], '模式：' + report['mode'], '',
             '名称/正则命中是待核实证据，不自动证明滥用。多地区来源属于推断。', '',
             '|级别|容器|规则|证据|状态|', '|---|---|---|---|---|']
    for h in report['findings']:
        ev = h['evidence']
        desc = ('PID ' + str(ev['pid']) + ' ' + ev['exe']) if 'pid' in ev else (
            ev['path'] + ':' + str(ev['line']) if 'path' in ev else json.dumps(ev, ensure_ascii=False))
        if ev.get('authentication'):
            desc += ' / auth=' + ev['authentication']
        cells = [h['severity'], names.get(h['scope'], h['scope']), h['title'], desc, h['status']]
        lines.append('|' + '|'.join(str(c).replace('|', '\\|').replace('\n', ' ') for c in cells) + '|')
    if not report['findings']:
        lines.append('|—|—|本次未命中|不代表历史或改名程序绝对无违规|—|')
    lines += ['', '## 检查覆盖与限制', '',
              '- 运行中进程及常见启动目录；停止容器仅检查可访问的可写层启动文件。',
              '- 进程参数参与匹配，但不会写入报告，避免暴露账号、密码、令牌。',
              '- 多地区检测仅使用入站来源；出站网站/CDN IP 不作为用户来源。',
              '- 默认不联网查 IP；无地区资料时会标记证据不足。',
              '- UDP 依赖 conntrack；单次快照无法证明历史行为，隧道可能隐藏用户。',
              '- 未扫描全部磁盘文件、用户 shell 历史、所有应用配置或远端业务。',
              '- HTTP/SOCKS5/WireGuard/QUIC 是协议观察，不自动等同违规；FET 只是统计推断。',
              '- RFW 累积访问计数不当作活跃用户，受攻击的容器不因被阻断访问而受罚。',
              '', '## RFW 扩展覆盖', '', '```json',
              json.dumps(report.get('rfw_coverage', {}), ensure_ascii=False, indent=2), '```',
              '', '## RFW 历史端口访问计数', '', '```json',
              json.dumps(report.get('rfw_port_access', []), ensure_ascii=False, indent=2), '```',
              '', '## 处置记录', '', '```json', json.dumps(report['actions'], ensure_ascii=False, indent=2), '```',
              '', '## 采集异常', '', '```json', json.dumps(report['errors'], ensure_ascii=False, indent=2), '```']
    return '\n'.join(lines) + '\n'


def write_reports(report, out, stem):
    atomic_text(out / (stem + '.json'), json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    md = format_report(report)
    atomic_text(out / (stem + '.md'), md)
    page = '<!doctype html><meta charset="utf-8"><title>NAT Safe</title><style>body{max-width:1200px;margin:32px auto;padding:0 20px;font:15px/1.7 system-ui}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><pre>' + html.escape(md) + '</pre>'
    atomic_text(out / (stem + '.html'), page)


def validate_config(cfg):
    for key in ('min_client_ips', 'min_geo_regions', 'min_consecutive_samples', 'min_geo_duration_seconds',
                'max_geo_lookups', 'max_startup_files', 'max_file_bytes'):
        if type(cfg[key]) is not int or cfg[key] < 1:
            raise ValueError(key + ' must be a positive integer')
    if cfg['geo_level'] not in ('country', 'region'):
        raise ValueError('geo_level must be country or region')
    if not isinstance(cfg['allowlist'], list) or not all(isinstance(x, dict) for x in cfg['allowlist']):
        raise ValueError('allowlist must be a list of objects')
    if not isinstance(cfg['exclude_client_ports'], list) or not all(type(x) is int and 1 <= x <= 65535 for x in cfg['exclude_client_ports']):
        raise ValueError('exclude_client_ports must be a port list')
    policy = cfg['country_policy']
    if not isinstance(policy, dict) or policy.get('mode', 'off') not in ('off', 'allow', 'deny'):
        raise ValueError('country_policy.mode must be off, allow or deny')
    countries = policy.get('countries', [])
    if not isinstance(countries, list) or not all(isinstance(x, str) and re.fullmatch('[A-Z]{2}', x) for x in countries):
        raise ValueError('country_policy.countries must contain uppercase two-letter country codes')
    if policy.get('mode', 'off') != 'off' and not countries:
        raise ValueError('Enabled country policy requires at least one country')
    if not isinstance(policy.get('containers', []), list) or not all(isinstance(x, str) for x in policy.get('containers', [])):
        raise ValueError('country_policy.containers must be a list of exact container IDs')


def scan(args, cfg, rules, runner, state_dir):
    cs = discover(runner)
    first = processes()
    started = time.monotonic()
    time.sleep(args.sample_seconds)
    procs = processes()
    elapsed = time.monotonic() - started
    hz = os.sysconf('SC_CLK_TCK')
    map_processes(procs, cs)
    for pid, p in procs.items():
        old = first.get(pid, p)
        ticks = max(0, p['ticks'] - old['ticks']) if p['start_ticks'] == old['start_ticks'] else 0
        p['cpu_pct'] = round(ticks / hz / elapsed * 100, 1)
    hits = process_findings(procs, rules)
    sh, coverage = startup_findings(cs, rules, cfg, runner)
    hits += sh
    net, clients, nc = collect_network(cs, runner, cfg, args.narwhal_db)
    hits += rfw_audit.smtp_findings(net)
    previous = load_json(state_dir / 'geo-history.json', {})
    geo = Geo(args.geo_provider, args.geo_db, state_dir, cfg, runner.errors)
    gh, history = geo_findings(clients, geo, cfg, previous, time.time())
    ch, country_coverage = rfw_audit.country_findings(clients, geo, cfg['country_policy'])
    hits += ch
    geo.save()
    atomic_text(state_dir / 'geo-history.json', json.dumps(history))
    hits += gh
    capture_coverage = dict(enabled=False, reason='Use --capture-interface to explicitly enable passive sampling')
    forwards = narwhal_ports(args.narwhal_db, runner.errors)
    if args.capture_interface:
        ph, capture_coverage = rfw_audit.capture(args.capture_interface, args.capture_seconds,
            args.max_packets, args.fet_mode, forwards, cs, set(cfg['exclude_client_ports']), runner.errors)
        hits += ph
    port_access = []
    if args.rfw_stats:
        p = Path(args.rfw_stats)
        if p.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('RFW stats import exceeds 8 MiB')
        counters = load_json(state_dir / 'rfw-counters.json', {})
        port_access, counters = rfw_audit.parse_rfw_stats(p.read_text(), forwards, cs, counters)
        atomic_text(state_dir / 'rfw-counters.json', json.dumps(counters))
        if not port_access:
            runner.errors.append(dict(command='rfw_stats_import', error='no valid ungrouped records found'))
    apply_policy(hits, cfg)
    report = dict(version=VERSION, utc=utc(), hostname=socket.gethostname(), mode='enforce' if args.enforce else 'audit',
                  containers=[{k: c[k] for k in ('id', 'name', 'runtime', 'state', 'pid')} for c in cs],
                  process_count=len(procs), findings=hits, startup_coverage=coverage, network=net,
                  network_coverage=nc, geo_provider='offline' if args.geo_db else args.geo_provider,
                  rfw_coverage=dict(capture=capture_coverage, country_policy=country_coverage,
                                    smtp='TCP destination-port heuristic; not spam proof',
                                    port_access_import=bool(args.rfw_stats)), rfw_port_access=port_access,
                  top_cpu=[{k: p[k] for k in ('pid', 'comm', 'scope', 'cpu_pct', 'rss_mib')}
                           for p in sorted(procs.values(), key=lambda p: p['cpu_pct'], reverse=True)[:15]],
                  actions=[], errors=runner.errors)
    return report, cs


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version', action='version', version=VERSION)
    p.add_argument('--config', help='JSON configuration')
    p.add_argument('--rules', default=str(BASE / 'rules.json'))
    p.add_argument('--output', default='/var/log/nat-safe')
    p.add_argument('--state-dir', default='/var/lib/nat-safe')
    p.add_argument('--narwhal-db', default='/opt/narwhal-agent/agent.db')
    p.add_argument('--sample-seconds', type=float, default=2)
    p.add_argument('--geo-provider', choices=['none', 'ipwhois'], default='none',
                   help='ipwhois sends public client IPs to ipwho.is over HTTPS; optional')
    p.add_argument('--geo-db', help='Offline MaxMind database; requires optional maxminddb Python package')
    p.add_argument('--capture-interface', help='Explicit bounded passive protocol sampling on this interface')
    p.add_argument('--capture-seconds', type=float, default=5)
    p.add_argument('--max-packets', type=int, default=5000)
    p.add_argument('--fet-mode', choices=['off', 'loose', 'strict'], default='off')
    p.add_argument('--rfw-stats', help='Import a saved, ungrouped rfw stats text file; historical counters only')
    p.add_argument('--enforce', action='store_true')
    p.add_argument('--select', action='append', help='Exact container ID/name; repeatable')
    p.add_argument('--rule', action='append', help='Reviewed policy rule ID; repeatable')
    p.add_argument('--action', choices=['terminate', 'stop-container'], default='terminate')
    p.add_argument('--watch', type=int, default=0, metavar='SECONDS', help='Repeat at interval; 0 = once')
    p.add_argument('--retention-days', type=int, default=30)
    return p


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    if os.geteuid() != 0:
        raise ValueError('Run as root to inspect container processes and namespaces')
    if not 0.1 <= args.sample_seconds <= 60 or args.watch < 0 or (args.watch and args.watch < 10) or args.retention_days < 1:
        raise ValueError('Invalid sample/interval/retention value')
    if not 0.1 <= args.capture_seconds <= 30 or not 1 <= args.max_packets <= 100000:
        raise ValueError('Capture requires 0.1..30 seconds and 1..100000 packets')
    if args.fet_mode != 'off' and not args.capture_interface:
        raise ValueError('--fet-mode requires explicit --capture-interface')
    if args.enforce and (not args.select or not args.rule):
        raise ValueError('--enforce requires explicit --select and --rule; HOST is always protected')
    cfg = {**DEFAULTS, **load_json(args.config, {})} if args.config else dict(DEFAULTS)
    validate_config(cfg)
    rules = load_json(args.rules)
    if not isinstance(rules, list) or not rules:
        raise ValueError('Rules must be a nonempty JSON array')
    ids = set()
    for r in rules:
        if r['id'] in ids:
            raise ValueError('Duplicate rule ID')
        ids.add(r['id'])
        r['_regex'] = re.compile(r['pattern'], re.I)
    if set(args.rule or []) - ids:
        raise ValueError('Only explicit configured process rule IDs can be selected for enforcement')
    out, state = private_dir(args.output), private_dir(args.state_dir)
    lockfd = os.open(str(state / 'scan.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lockfd)
        raise ValueError('Another scan is running with this state directory')
    try:
        while True:
            started = time.monotonic()
            runner = Runner()
            report, cs = scan(args, cfg, rules, runner, state)
            stem = 'report-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
            # Write evidence durably before any process signal or container operation.
            write_reports(report, out, stem)
            if args.enforce:
                report['actions'] = enforce(report['findings'], cs, args, runner)
                write_reports(report, out, stem)
            print(json.dumps(dict(report=str(out / (stem + '.html')), findings=len(report['findings']),
                                  errors=len(report['errors']), actions=report['actions']), ensure_ascii=False), flush=True)
            cutoff = time.time() - args.retention_days * 86400
            for old in out.glob('report-*'):
                if old.suffix in ('.json', '.md', '.html') and not old.is_symlink() and old.stat().st_mtime < cutoff:
                    old.unlink()
            if not args.watch:
                return 0
            time.sleep(max(0, args.watch - (time.monotonic() - started)))
    finally:
        os.close(lockfd)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError, re.error) as exc:
        print('nat-safe: ' + str(exc), file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
