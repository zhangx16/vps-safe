#!/usr/bin/env python3
"""Run ONLY as: sudo unshare --net python3 tests/kernel_cases.py."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).parents[1]))
import vps_safe as v


def cmd(*args):return subprocess.check_output(args,stderr=subprocess.STDOUT,text=True)

def net(pid,*args):return cmd('nsenter','-t',str(pid),'-n',*args)

def ns():
    p=subprocess.Popen(['unshare','--net','sleep','120'])
    for _ in range(100):
        if os.stat(f'/proc/{p.pid}/ns/net').st_ino!=os.stat('/proc/self/ns/net').st_ino:return p
        time.sleep(.01)
    raise RuntimeError('namespace creation timed out')

def link(name,peer,pid,host_ip,peer_ip):
    cmd('ip','link','add',name,'type','veth','peer','name',peer)
    cmd('ip','link','set',peer,'netns',str(pid))
    cmd('ip','addr','add',host_ip,'dev',name);cmd('ip','link','set',name,'up')
    net(pid,'ip','link','set','lo','up');net(pid,'ip','addr','add',peer_ip,'dev',peer);net(pid,'ip','link','set',peer,'up')

def connect(pid,addr,port,expected):
    family='socket.AF_INET6' if ':' in addr else 'socket.AF_INET'
    code='import socket;s=socket.socket('+family+');s.settimeout(.2);r=s.connect_ex(('+repr(addr)+','+str(port)+'));s.close();print(r)'
    r=int(net(pid,'python3','-c',code)) if pid else int(cmd('python3','-c',code))
    assert (r==0)==expected,(addr,port,r,expected)

def main():
    assert os.geteuid()==0
    assert os.stat('/proc/self/ns/net').st_ino!=os.stat('/proc/1/ns/net').st_ino,'Refusing to run outside an isolated network namespace'
    peer=container=server=None;listeners=[];checks=[]
    try:
        cmd('ip','link','set','lo','up')
        peer=ns();container=ns()
        link('wan','uplink',peer.pid,'198.18.0.1/24','198.18.0.2/24')
        link('lan','cnic',container.pid,'10.88.0.1/24','10.88.0.2/24')
        cmd('ip','-6','addr','add','2001:db8:10::1/64','dev','wan','nodad')
        net(peer.pid,'ip','-6','addr','add','2001:db8:10::2/64','dev','uplink','nodad')
        cmd('ip','-6','addr','add','fd88::1/64','dev','lan','nodad')
        net(container.pid,'ip','-6','addr','add','fd88::2/64','dev','cnic','nodad')
        net(container.pid,'ip','-6','route','add','default','via','fd88::1')
        net(peer.pid,'ip','-6','route','add','fd88::/64','via','2001:db8:10::1')
        net(container.pid,'ip','route','add','default','via','10.88.0.1')
        cmd('sysctl','-w','net.ipv4.ip_forward=1')
        cmd('sysctl','-w','net.ipv6.conf.all.forwarding=1')
        cmd('nft','add','table','ip','fixture_nat')
        cmd('nft','add','chain','ip','fixture_nat','postrouting','{ type nat hook postrouting priority 100; policy accept; }')
        cmd('nft','add','rule','ip','fixture_nat','postrouting','oifname','wan','masquerade')
        cmd('nft','add','table','inet','foreign_fixture')
        for port in [2222,8080,8081]:
            s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',port));s.listen(32);listeners.append(s)
            s=socket.socket(socket.AF_INET6);s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('::',port));s.listen(32);listeners.append(s)
        server_code='import socket,time;ss=[]\nfor af,addr in [(socket.AF_INET,"0.0.0.0"),(socket.AF_INET6,"::")]:\n for p in [25,443]:\n  s=socket.socket(af);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n  if af==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)\n  s.bind((addr,p));s.listen(32);ss.append(s)\nprint("ready",flush=True);time.sleep(60)'
        server=subprocess.Popen(['nsenter','-t',str(peer.pid),'-n','python3','-u','-c',server_code],stdout=subprocess.PIPE,text=True)
        assert server.stdout.readline().strip()=='ready'
        c=v.validate({'wan_interfaces':['wan'],'management_tcp_ports':[2222],'allow_tcp_ports':[8080],'host_default_drop':True})
        with tempfile.TemporaryDirectory(prefix='vps-safe-kernel-') as td:
            fw=v.Firewall(td)
            a=fw.apply(c,auto=False)
            connect(peer.pid,'198.18.0.1',2222,True);connect(peer.pid,'198.18.0.1',8080,True);connect(peer.pid,'198.18.0.1',8081,False)
            checks.append('management allowed; configured service allowed; unexpected WAN port blocked')
            connect(None,'198.18.0.2',25,False);connect(None,'198.18.0.2',443,True)
            checks.append('host SMTP egress blocked; HTTPS unaffected')
            connect(container.pid,'198.18.0.2',25,False);connect(container.pid,'198.18.0.2',443,True)
            checks.append('container SMTP forwarding blocked; pre-existing masquerade NAT preserved')
            connect(peer.pid,'2001:db8:10::1',2222,True);connect(peer.pid,'2001:db8:10::1',8080,True);connect(peer.pid,'2001:db8:10::1',8081,False)
            connect(None,'2001:db8:10::2',25,False);connect(None,'2001:db8:10::2',443,True)
            connect(container.pid,'2001:db8:10::2',25,False);connect(container.pid,'2001:db8:10::2',443,True)
            checks.append('real IPv6 management, inbound filtering, host/container SMTP and HTTPS verified')
            fw.confirm(a['transaction'])
            denied={**c,'blocked_source_cidrs':['198.18.0.2/32','2001:db8:10::2/128']}
            b=fw.apply(denied,auto=False)
            connect(peer.pid,'198.18.0.1',2222,True);connect(peer.pid,'198.18.0.1',8080,False)
            connect(None,'198.18.0.2',443,True)
            connect(peer.pid,'2001:db8:10::1',2222,True);connect(peer.pid,'2001:db8:10::1',8080,False);connect(None,'2001:db8:10::2',443,True)
            checks.append('source deny preserves management and outgoing reply traffic')
            fw.rollback(b['transaction']);connect(peer.pid,'198.18.0.1',8080,True)
            assert 'foreign_fixture' in cmd('nft','list','tables')
            assert 'fixture_nat' in cmd('nft','list','tables')
            checks.append('rollback restores previous rules without touching foreign tables')
            c2={**c,'smtp_exempt_cidrs':['198.18.0.1/32']}
            b=fw.apply(c2,auto=False);connect(None,'198.18.0.2',25,True);fw.confirm(b['transaction'])
            checks.append('explicit SMTP source exception works')
            q={**c,'quarantine_ips':['10.88.0.2/32','fd88::2/128']}
            b=fw.apply(q,auto=False);connect(container.pid,'198.18.0.2',443,False)
            connect(container.pid,'2001:db8:10::2',443,False)
            checks.append('container quarantine blocks forwarded traffic')
            # Simulate the watchdog command with a separate process in this namespace.
            cmd(sys.executable,str(Path(v.__file__).resolve()),'rollback','--transaction',b['transaction'],'--state-dir',td,'--if-pending')
            connect(container.pid,'198.18.0.2',443,True)
            connect(container.pid,'2001:db8:10::2',443,True)
            checks.append('independent rollback process restores connectivity')
            all_rules={**c,'syn_rate_per_second':1000,'quarantine_ips':['fd00::2/128']}
            b=fw.apply(all_rules,auto=False);fw.confirm(b['transaction'])
            # Ensure a snapshot containing dynamic meter definitions can be restored.
            d=fw.apply(c,auto=False);fw.rollback(d['transaction'])
            checks.append('IPv4/IPv6 sets and SYN meter syntax/snapshots load on kernel')
        print(json.dumps({'kernel_tests':'PASS','checks':checks},indent=2))
    finally:
        for s in listeners:s.close()
        for p in [server,container,peer]:
            if p:
                p.terminate()
                try:p.wait(timeout=3)
                except subprocess.TimeoutExpired:p.kill();p.wait()

if __name__=='__main__':main()
