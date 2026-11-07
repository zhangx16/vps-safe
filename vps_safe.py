#!/usr/bin/env python3
"""VPS firewall and anti-abuse CLI. Owns only nft table inet vps_safe."""
import argparse
import copy
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

VERSION='0.1.0'
BASE=Path(__file__).resolve().parent
TABLE='vps_safe'
MARKER='managed-by-vps-safe'
DEFAULT=dict(wan_interfaces=[],management_tcp_ports=[22],allow_tcp_ports=[],allow_udp_ports=[],
             host_default_drop=False,blocked_source_cidrs=[],blocked_tcp_ports=[],blocked_udp_ports=[],
             block_smtp=True,smtp_ports=[25,465,587,2525],smtp_exempt_cidrs=[],quarantine_ips=[],
             source_policy=dict(mode='off',cidrs=[],families=[4,6]),drop_invalid=True,
             syn_rate_per_second=0,syn_burst=50)


def now():return dt.datetime.now(dt.timezone.utc).isoformat()

def run(argv,text=None,check=True):
    p=subprocess.run(argv,input=text,capture_output=True,text=True,timeout=30)
    if check and p.returncode:raise ValueError(f'{argv[0]} failed: {p.stderr.strip()[:600]}')
    return p


def read_json(path,default=None):
    try:return json.loads(Path(path).read_text())
    except FileNotFoundError:return default


def atomic(path,text):
    path=Path(path);tmp=path.with_name(path.name+'.tmp-'+uuid.uuid4().hex)
    fd=os.open(str(tmp),os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as f:f.write(text);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if tmp.exists():tmp.unlink()


def save(path,obj):atomic(path,json.dumps(obj,ensure_ascii=False,indent=2)+'\n')

def networks(values,hosts=False):
    if not isinstance(values,list) or len(values)>65536:raise ValueError('CIDRs must be a list of at most 65536 entries')
    result=[]
    for v in values:
        if not isinstance(v,str):raise ValueError('CIDR must be a string')
        n=ipaddress.ip_network(v,strict=False)
        if hosts:
            if n.prefixlen!=n.max_prefixlen or n.network_address.is_loopback or n.network_address.is_multicast or n.network_address.is_unspecified or n.network_address.is_link_local:
                raise ValueError('Quarantine requires individual non-loopback IPv4/IPv6 addresses')
        result.append(str(n))
    if hosts:return sorted(set(result))
    merged=[]
    for family in (4,6):
        merged.extend(str(n) for n in ipaddress.collapse_addresses(ipaddress.ip_network(x) for x in result if ipaddress.ip_network(x).version==family))
    return sorted(merged)


def validate(raw):
    if not isinstance(raw,dict):raise ValueError('Config must be a JSON object')
    unknown=set(raw)-set(DEFAULT)
    if unknown:raise ValueError('Unknown config fields: '+', '.join(sorted(unknown)))
    c=copy.deepcopy(DEFAULT);c.update(raw)
    if not isinstance(c['wan_interfaces'],list) or not c['wan_interfaces']:raise ValueError('Set actual WAN interface(s), e.g. ens18; use doctor to inspect')
    for i in c['wan_interfaces']:
        if not isinstance(i,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',i) or i=='lo':raise ValueError('Invalid WAN interface')
    for field in ('management_tcp_ports','allow_tcp_ports','allow_udp_ports','blocked_tcp_ports','blocked_udp_ports','smtp_ports'):
        v=c[field]
        if not isinstance(v,list) or len(v)>1024 or not all(type(p) is int and 1<=p<=65535 for p in v):raise ValueError('Invalid port list: '+field)
        c[field]=sorted(set(v))
    if not c['management_tcp_ports']:raise ValueError('Management TCP ports cannot be empty')
    if set(c['management_tcp_ports'])&set(c['blocked_tcp_ports']):raise ValueError('Blocked ports overlap management ports')
    for f in ('host_default_drop','block_smtp','drop_invalid'):
        if type(c[f]) is not bool:raise ValueError(f+' must be boolean')
    for f,lo,hi in [('syn_rate_per_second',0,1000000),('syn_burst',1,1000000)]:
        if type(c[f]) is not int or not lo<=c[f]<=hi:raise ValueError('Invalid '+f)
    for f in ('blocked_source_cidrs','smtp_exempt_cidrs'):c[f]=networks(c[f])
    c['quarantine_ips']=networks(c['quarantine_ips'],hosts=True)
    s=c['source_policy']
    if not isinstance(s,dict) or set(s)-{'mode','cidrs','families'}:raise ValueError('Invalid source_policy')
    s={'mode':'off','cidrs':[],'families':[4,6],**s}
    if s['mode'] not in ('off','allow','deny'):raise ValueError('Invalid source policy mode')
    if not isinstance(s['families'],list) or not s['families'] or not all(type(x) is int and x in (4,6) for x in s['families']):raise ValueError('Invalid source policy families')
    s['cidrs']=networks(s['cidrs'])
    if s['mode']!='off' and not s['cidrs']:raise ValueError('Enabled source policy requires CIDRs')
    if s['mode']=='allow':
        for family in s['families']:
            if not any(ipaddress.ip_network(n).version==family for n in s['cidrs']):raise ValueError(f'Allow policy has no IPv{family} ranges; specify intended families explicitly')
    c['source_policy']=s
    return c


def detected_ssh_ports():
    ports=set()
    env=os.environ.get('SSH_CONNECTION','').split()
    if len(env)==4 and env[3].isdigit() and 1<=int(env[3])<=65535:ports.add(int(env[3]))
    if shutil.which('ss'):
        p=run(['ss','-Hlnpt'],check=False)
        for line in p.stdout.splitlines():
            a=line.split()
            if 'sshd' in line and len(a)>=4:
                port=a[3].rpartition(':')[2]
                if port.isdigit():ports.add(int(port))
    return ports


def prepare(config,detect=True):
    c=validate(read_json(config))
    if detect:c['management_tcp_ports']=sorted(set(c['management_tcp_ports'])|detected_ssh_ports())
    return validate(c)


def group(values,family):return [n for n in values if ipaddress.ip_network(n).version==family]


def render(c):
    c=validate(c)
    lines=['# Generated by VPS Safe; only this named table is managed.',f'table inet {TABLE} {{',f'  comment "{MARKER}"']
    def nftset(name,typ,values,interval=False):
        flags=' flags interval;' if interval else ''
        elements=' elements = { '+', '.join('"'+v+'"' if typ=='ifname' else str(v) for v in values)+' };' if values else ''
        lines.append(f'  set {name} {{ type {typ};{flags}{elements} }}')
    nftset('wan','ifname',c['wan_interfaces'])
    for field,name in [('management_tcp_ports','management'),('allow_tcp_ports','allowed_tcp'),('allow_udp_ports','allowed_udp'),('blocked_tcp_ports','blocked_tcp'),('blocked_udp_ports','blocked_udp'),('smtp_ports','smtp')]:nftset(name,'inet_service',c[field])
    for family,typ in [(4,'ipv4_addr'),(6,'ipv6_addr')]:
        for field,name in [('blocked_source_cidrs','blocked_src'),('smtp_exempt_cidrs','smtp_exempt'),('quarantine_ips','quarantine')]:nftset(name+str(family),typ,group(c[field],family),True)
        nftset('source_policy'+str(family),typ,group(c['source_policy']['cidrs'],family),True)
    lines+=['  chain ingress {','    type filter hook prerouting priority -150; policy accept;',
            '    iifname != @wan return']
    if c['drop_invalid']:lines.append('    ct state invalid counter drop')
    lines += ['    meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept',
              '    udp sport 67 udp dport 68 accept', '    udp sport 547 udp dport 546 accept']
    lines.append('    tcp dport @management counter accept')
    for family,p in [(4,'ip'),(6,'ip6')]:lines.append(f'    ct direction original {p} saddr @blocked_src{family} counter drop')
    policy=c['source_policy']
    if policy['mode']!='off':
        for family in sorted(set(policy['families'])):
            p='ip' if family==4 else 'ip6';neg=' !=' if policy['mode']=='allow' else ''
            lines.append(f'    ct direction original {p} saddr{neg} @source_policy{family} counter drop')
    lines+=['    ct direction original tcp dport @blocked_tcp counter drop',
            '    ct direction original udp dport @blocked_udp counter drop']
    if c['syn_rate_per_second']:
        for family,p in [(4,'ip'),(6,'ip6')]:
            lines.append(f"    ct state new tcp flags & (syn | ack) == syn meter syn{family} size 65535 {{ {p} saddr timeout 30s limit rate over {c['syn_rate_per_second']}/second burst {c['syn_burst']} packets }} counter drop")
    lines+=['  }','  chain input {','    type filter hook input priority -5; policy accept;']
    for family,p in [(4,'ip'),(6,'ip6')]:lines.append(f'    {p} saddr @quarantine{family} counter drop')
    lines+=['    iifname "lo" accept','    ct state established,related accept',
            '    meta l4proto { icmp, ipv6-icmp } accept',
            '    udp sport 67 udp dport 68 accept', '    udp sport 547 udp dport 546 accept',
            '    tcp dport @management accept','    iifname @wan tcp dport @allowed_tcp accept',
            '    iifname @wan udp dport @allowed_udp accept']
    if c['host_default_drop']:lines.append('    iifname @wan counter drop')
    lines+=['  }','  chain forward {','    type filter hook forward priority -5; policy accept;']
    for family,p in [(4,'ip'),(6,'ip6')]:
        lines += [f'    {p} saddr @quarantine{family} counter drop',f'    {p} daddr @quarantine{family} counter drop']
    if c['block_smtp']:
        for family,p in [(4,'ip'),(6,'ip6')]:lines.append(f'    oifname @wan tcp dport @smtp {p} saddr @smtp_exempt{family} accept')
        lines.append('    oifname @wan tcp dport @smtp counter drop')
    lines+=['  }','  chain output {','    type filter hook output priority -5; policy accept;']
    for family,p in [(4,'ip'),(6,'ip6')]:lines.append(f'    {p} daddr @quarantine{family} counter drop')
    if c['block_smtp']:
        for family,p in [(4,'ip'),(6,'ip6')]:lines.append(f'    oifname @wan tcp dport @smtp {p} saddr @smtp_exempt{family} accept')
        lines.append('    oifname @wan tcp dport @smtp counter drop')
    lines+=['  }','}']
    return '\n'.join(lines)+'\n'


def private_state(path):
    p=Path(path);p.mkdir(parents=True,mode=0o700,exist_ok=True)
    if p.is_symlink() or p.stat().st_uid!=os.geteuid():raise ValueError('State directory must be owned by current user and not a symlink')
    p.chmod(0o700);return p.resolve()


class Firewall:
    def __init__(self,state):self.state=private_state(state)
    def current(self):
        current=read_json(self.state/'current.json',{})
        if current.get('id'):
            # The transaction file is authoritative if a crash interrupted the pointer update.
            current['status']=self.transaction(current['id'])['status']
        return current
    def transaction(self,txid):
        if not re.fullmatch(r'[0-9a-f]{32}',txid):raise ValueError('Invalid transaction ID')
        data=read_json(self.state/('transaction-'+txid+'.json'))
        if not data:raise ValueError('Transaction not found')
        return data
    def write_tx(self,tx):save(self.state/('transaction-'+tx['id']+'.json'),tx)
    def snapshot(self):
        p=run(['nft','-j','list','tables'])
        tables=json.loads(p.stdout).get('nftables',[])
        exists=any(x.get('table',{}).get('family')=='inet' and x['table'].get('name')==TABLE for x in tables)
        if not exists:return ''
        text=run(['nft','list','table','inet',TABLE]).stdout
        # nft 1.0.6 omits table comments from JSON, but preserves them in text output.
        if not re.match(r'table inet '+TABLE+r'\s*\{\s*comment "'+MARKER+r'"',text):
            raise ValueError('Refusing to replace an unmanaged table named '+TABLE)
        return text
    def replace(self,body,check=True):
        old=self.snapshot();text=(f'delete table inet {TABLE}\n' if old else '')+body
        if text:
            if check:run(['nft','--check','-f','-'],text)
            run(['nft','-f','-'],text)
    def cancel(self,tx):
        if tx.get('timer'):run(['systemctl','stop',tx['timer']+'.timer'],check=False)
    def rollback(self,txid,if_pending=False):
        tx=self.transaction(txid)
        if if_pending and tx['status']!='pending':return dict(status='no-op',reason='transaction is no longer pending')
        if tx['status'] in ('rolled-back','disabled'):return dict(status='no-op',reason=tx['status'])
        if self.current().get('id')!=txid:raise ValueError('Refusing to roll back an older transaction over newer rules')
        self.replace(tx['previous'])
        tx['status']='rolled-back';tx['finished']=now();self.write_tx(tx);self.cancel(tx)
        save(self.state/'current.json',dict(id=txid,status='rolled-back'))
        # Restore the previous confirmed boot configuration, not the rolled-back candidate.
        if tx.get('previous_confirmed') is None:
            (self.state/'confirmed.json').unlink(missing_ok=True)
        else:save(self.state/'confirmed.json',tx['previous_confirmed'])
        return dict(status='rolled-back',transaction=txid)
    def apply(self,config,seconds=120,auto=True,metadata=None):
        current=self.current()
        if current.get('status')=='pending':raise ValueError('An apply is pending; confirm or roll it back first')
        body=render(config);old=self.snapshot()
        candidate=(f'delete table inet {TABLE}\n' if old else '')+body
        run(['nft','--check','-f','-'],candidate)
        txid=uuid.uuid4().hex
        tx=dict(id=txid,status='pending',created=now(),deadline=time.time()+seconds,previous=old,
                previous_confirmed=read_json(self.state/'confirmed.json'),config=config,rules=body,
                sha256=hashlib.sha256(body.encode()).hexdigest(),metadata=metadata or {})
        self.write_tx(tx);save(self.state/'current.json',dict(id=txid,status='pending'))
        if auto:
            if not shutil.which('systemd-run') or not shutil.which('systemctl') or not Path('/run/systemd/system').exists():
                tx['status']='aborted';self.write_tx(tx);save(self.state/'current.json',dict(id=txid,status='aborted'))
                raise ValueError('Automatic rollback requires systemd; use --no-auto-rollback only with console access')
            if os.stat('/proc/self/ns/net').st_ino!=os.stat('/proc/1/ns/net').st_ino:
                tx['status']='aborted';self.write_tx(tx);save(self.state/'current.json',dict(id=txid,status='aborted'))
                raise ValueError('Automatic rollback must run in systemd host network namespace')
            tx['timer']='vps-safe-rollback-'+txid;self.write_tx(tx)
            helper=self.state/('rollback-'+txid+'.py')
            # Keep watchdog code stable even if the repository/install is moved or updated.
            atomic(helper,Path(__file__).read_text())
            argv=['systemd-run','--quiet','--unit='+tx['timer'],'--on-active='+str(seconds)+'s','--timer-property=AccuracySec=1s',
                  '--property=Type=oneshot',sys.executable,str(helper),'rollback','--transaction',txid,
                  '--state-dir',str(self.state),'--if-pending']
            try:run(argv)
            except (OSError,ValueError,subprocess.TimeoutExpired):
                tx['status']='aborted';self.write_tx(tx);save(self.state/'current.json',dict(id=txid,status='aborted'));raise
        try:run(['nft','-f','-'],candidate)
        except (OSError,ValueError,subprocess.TimeoutExpired):
            # nft applies a batch atomically; keep the watchdog if outcome is uncertain.
            if not auto:self.rollback(txid)
            raise
        if not auto:tx['deadline']=None
        self.write_tx(tx)
        return dict(status='pending',transaction=txid,automatic_rollback=auto,rollback_after=seconds if auto else None,
                    protected_ssh_ports=config['management_tcp_ports'],
                    confirm_command=[sys.executable,str(BASE/'vps_safe.py'),'confirm','--transaction',txid,'--state-dir',str(self.state)],
                    report=str(self.state/('transaction-'+txid+'.json')))
    def confirm(self,txid):
        tx=self.transaction(txid)
        if self.current().get('id')!=txid or tx['status']!='pending':raise ValueError('Transaction is not the current pending apply')
        if tx.get('deadline') and time.time()>=tx['deadline']:raise ValueError('Confirmation deadline passed; wait for rollback or run rollback')
        # A reboot configuration always contains the expanded, SSH-protected config.
        save(self.state/'confirmed.json',dict(config=tx['config'],rules=tx['rules'],transaction=txid))
        tx['status']='confirmed';tx['finished']=now();self.write_tx(tx)
        save(self.state/'current.json',dict(id=txid,status='confirmed'));self.cancel(tx)
        return dict(status='confirmed',transaction=txid,boot_persistence='Enable vps-safe-firewall.service explicitly after confirming access')


def host_addresses():
    result=set()
    for iface in json.loads(run(['ip','-j','address']).stdout):
        result.update(a.get('local') for a in iface.get('addr_info',[]))
    return result


def apply_preflight(c):
    names={i['ifname'] for i in json.loads(run(['ip','-j','link']).stdout)}
    missing=set(c['wan_interfaces'])-names
    if missing:raise ValueError('WAN interface not present: '+', '.join(sorted(missing)))
    own=host_addresses()
    if any(str(ipaddress.ip_network(n).network_address) in own for n in c['quarantine_ips']):raise ValueError('Refusing to quarantine a host/bridge local address')


def quarantine_addresses(runtime,name):
    if name.startswith('-') or not re.fullmatch(r'[A-Za-z0-9_.-]+',name):raise ValueError('Invalid container identifier')
    addresses=[]
    if runtime in ('podman','docker'):
        rows=json.loads(run([runtime,'inspect',name]).stdout)
        if not rows:raise ValueError('Container not found')
        x=rows[0]
        if x.get('HostConfig',{}).get('NetworkMode')=='host':raise ValueError('Host-network containers cannot be isolated by IP')
        for net in x.get('NetworkSettings',{}).get('Networks',{}).values():
            addresses.extend([net.get('IPAddress'),net.get('GlobalIPv6Address')])
        addresses.extend([x.get('NetworkSettings',{}).get('IPAddress'),x.get('NetworkSettings',{}).get('GlobalIPv6Address')])
        target=dict(runtime=runtime,id=x['Id'],name=x.get('Name'))
    else:
        x=json.loads(run(['incus','query','/1.0/instances/'+name+'/state']).stdout)
        if 'metadata' in x:x=x['metadata']
        for net in x.get('network',{}).values():
            addresses.extend(a.get('address') for a in net.get('addresses',[]) if a.get('scope')=='global')
        target=dict(runtime=runtime,id=name)
    clean=[]
    for addr in addresses:
        if not addr:continue
        ip=ipaddress.ip_address(addr)
        if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast):clean.append(str(ip))
    if not clean:raise ValueError('No usable container IPs; no firewall changes made')
    return networks(clean,hosts=True),target


def doctor():
    result=dict(version=VERSION,root=os.geteuid()==0,dependencies={x:shutil.which(x) for x in ['python3','nft','ip','ss','systemd-run','systemctl']},
                ssh_ports=sorted(detected_ssh_ports()),systemd=Path('/run/systemd/system').exists(),
                remarks=['Layer 3/4 firewall; protocol DPI and geographic sharing are audit evidence, not automatic ban triggers.'])
    if shutil.which('ip'):
        result['interfaces']=json.loads(run(['ip','-j','link']).stdout)
        result['default_routes']=json.loads(run(['ip','-j','route','show','default']).stdout)
    return result


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version',action='version',version=VERSION)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('doctor')
    for cmd in ['render','check','apply','quarantine']:
        s=sub.add_parser(cmd);s.add_argument('--config',default='/etc/vps-safe/config.json')
        s.add_argument('--no-ssh-detect',action='store_true',help='Render/check only; apply still detects SSH')
        if cmd=='render':s.add_argument('--output')
        if cmd in ('apply','quarantine'):
            s.add_argument('--state-dir',default='/var/lib/vps-safe')
            s.add_argument('--rollback-after',type=int,default=120)
            s.add_argument('--no-auto-rollback',action='store_true',help='Console use only; explicitly disable rollback timer')
        if cmd=='quarantine':
            s.add_argument('--runtime',choices=['podman','docker','incus'],required=True)
            s.add_argument('--container',required=True)
    for cmd in ['confirm','rollback','status','disable','restore']:
        s=sub.add_parser(cmd);s.add_argument('--state-dir',default='/var/lib/vps-safe')
        if cmd in ('confirm','rollback'):s.add_argument('--transaction',required=cmd=='confirm')
        if cmd=='rollback':s.add_argument('--if-pending',action='store_true')
    audit=sub.add_parser('audit',add_help=False);audit.add_argument('args',nargs=argparse.REMAINDER)
    return p


def main(argv=None):
    os.umask(0o077)
    # Pass all audit options through unchanged, including --help.
    argv=sys.argv[1:] if argv is None else argv
    if argv and argv[0]=='audit':
        audit_args=argv[1:]
        for option,value in [('--output','/var/log/vps-safe/audit'),('--state-dir','/var/lib/vps-safe-audit')]:
            if not any(x==option or x.startswith(option+'=') for x in audit_args):audit_args += [option,value]
        if Path('/etc/vps-safe/audit.json').is_file() and not any(x=='--config' or x.startswith('--config=') for x in audit_args):
            audit_args += ['--config','/etc/vps-safe/audit.json']
        os.execv(sys.executable,[sys.executable,str(BASE/'audit/nat_safe.py'),*audit_args])
    args=parser().parse_args(argv)
    if args.command=='doctor':print(json.dumps(doctor(),ensure_ascii=False,indent=2));return 0
    if args.command in ('render','check','apply','quarantine'):
        c=prepare(args.config,detect=not args.no_ssh_detect or args.command in ('apply','quarantine'))
        if args.command=='render':
            body=render(c)
            if args.output:atomic(args.output,body)
            else:print(body,end='')
            return 0
    if os.geteuid()!=0:raise ValueError('Firewall operations require root')
    if not shutil.which('nft'):raise ValueError('Install nftables first: apt-get install nftables')
    if args.command=='check':
        fw=Firewall('/var/lib/vps-safe')
        old=fw.snapshot();run(['nft','--check','-f','-'],(f'delete table inet {TABLE}\n' if old else '')+render(c))
        print(json.dumps(dict(status='syntax-ok',protected_ssh_ports=c['management_tcp_ports'])));return 0
    if args.command in ('apply','quarantine'):
        if not 30<=args.rollback_after<=3600:raise ValueError('Rollback delay must be 30..3600 seconds')
        meta={}
        if args.command=='quarantine':
            addresses,target=quarantine_addresses(args.runtime,args.container)
            c['quarantine_ips']=sorted(set(c['quarantine_ips'])|set(addresses));meta={'quarantine_target':target,'addresses':addresses}
        apply_preflight(c)
    fw=Firewall(args.state_dir)
    fd=os.open(str(fw.state/'lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        if args.command in ('apply','quarantine'):result=fw.apply(c,args.rollback_after,not args.no_auto_rollback,meta)
        elif args.command=='confirm':result=fw.confirm(args.transaction)
        elif args.command=='rollback':
            txid=args.transaction or fw.current().get('id')
            result=fw.rollback(txid,args.if_pending) if txid else dict(status='no-op',reason='No transaction')
        elif args.command=='status':
            result=dict(current=fw.current(),confirmed=bool(read_json(fw.state/'confirmed.json')),table=fw.snapshot())
        elif args.command=='disable':
            current=fw.current()
            fw.replace('')
            if current:
                tx=fw.transaction(current['id']);fw.cancel(tx);tx['status']='disabled';fw.write_tx(tx)
                save(fw.state/'current.json',dict(id=tx['id'],status='disabled'))
            if shutil.which('systemctl'):run(['systemctl','disable','--now','vps-safe-firewall.service'],check=False)
            result=dict(status='disabled',other_firewalls_unchanged=True)
        elif args.command=='restore':
            if fw.current().get('status')=='pending':raise ValueError('Pending apply must be resolved before restore')
            confirmed=read_json(fw.state/'confirmed.json')
            if not confirmed:raise ValueError('No confirmed rules to restore')
            apply_preflight(confirmed['config']);fw.replace(confirmed['rules']);result=dict(status='restored')
        print(json.dumps(result,ensure_ascii=False,indent=2));return 0
    finally:os.close(fd)


if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,OSError,KeyError,TypeError,subprocess.TimeoutExpired) as e:
        print('vps-safe: '+str(e),file=sys.stderr);sys.exit(2)
