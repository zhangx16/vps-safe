import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
spec = importlib.util.spec_from_file_location('nat_safe', Path(__file__).parents[1] / 'nat_safe.py')
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)


class FakeGeo:
    def __init__(self, data): self.data = data
    def get(self, ip): return self.data.get(ip, {})


class NatSafeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = dict(n.DEFAULTS)
        self.rules = json.loads((n.BASE / 'rules.json').read_text())
        for r in self.rules: r['_regex'] = n.re.compile(r['pattern'], n.re.I)

    def test_rules_all_categories(self):
        samples = {'packet-tools':'hping3', 'scanner':'masscan', 'ddos':'python3 /tmp/ddos.py',
                   'proxy-panel':'/usr/local/x-ui/x-ui', 'miner':'xmrig', 'airport-node':'V2bX',
                   'weak-crypto':'aes-256-cfb', 'anti-dd':'reinstall.sh', 'mtproto':'mtg',
                   'benchmark':'geekbench', 'bot-crawler':'chromedriver', 'credential-attack':'hydra',
                   'traditional-vpn':'openvpn', 'open-proxy':'microsocks'}
        for rid, sample in samples.items():
            with self.subTest(rule=rid): self.assertIn(rid, [r['id'] for r in n.rule_matches(sample, self.rules)])
        self.assertNotIn('weak-crypto', [r['id'] for r in n.rule_matches('chacha20-poly1305', self.rules)])

    def test_startup_false_positives(self):
        self.assertEqual(n.startup_command('Description=Block OpenVPN FreeProxy', 'x.service'), '')
        self.assertEqual(n.startup_command('use afc-client amd openvpn', '/etc/init.d/netmount'), '')
        self.assertEqual(n.startup_command('# ExecStart=/usr/bin/xmrig', 'x.service'), '')
        self.assertIn('xmrig', n.startup_command('ExecStart=/usr/bin/xmrig --secret hidden', 'x.service'))

    def test_symlinks_resolve_inside_container(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/'etc').mkdir(); (root/'usr/lib').mkdir(parents=True)
            (root/'usr/lib/tool').write_text('safe'); (root/'etc/link').symlink_to('/usr/lib/tool')
            self.assertEqual(n.rooted_file(root, 'etc/link'), root/'usr/lib/tool')
            (root/'etc/bad').symlink_to('../../../etc/shadow')
            with self.assertRaises(ValueError): n.rooted_file(root, 'etc/bad')

    def test_process_report_omits_password(self):
        p = dict(pid=999999, ppid=1, comm='microsocks', exe='/usr/bin/microsocks',
                 _args='microsocks -u privateuser -P SUPERSECRET', scope='container',
                 start_ticks=1, rss_mib=1, cpu_pct=0)
        found = n.process_findings({999999:p}, self.rules)
        self.assertTrue(found)
        self.assertNotIn('SUPERSECRET', json.dumps(found)); self.assertNotIn('privateuser', json.dumps(found))
        self.assertEqual(found[0]['evidence']['authentication'], 'credentials_configured')

    def test_ipv6_and_private_sources(self):
        self.assertEqual(n.endpoint('[2001:4860:4860::8888]:443'), ('2001:4860:4860::8888',443))
        self.assertIsNone(n.public_ip('10.0.0.1'))
        self.assertEqual(n.public_ip('::ffff:8.8.8.8'), '8.8.8.8')

    def test_inbound_only_attribution(self):
        class R(n.Runner):
            def run(self, argv, **kw):
                if argv == ['ss','-Hlnt']: return 'LISTEN 0 100 0.0.0.0:30000 0.0.0.0:*\n'
                if argv == ['ss','-Htan']:
                    return ('ESTAB 0 0 10.0.0.1:30000 8.8.8.8:50000\n'
                            'ESTAB 0 0 10.0.0.1:40000 1.1.1.1:443\n'
                            'ESTAB 0 0 10.0.0.1:30001 9.9.9.9:50001\n')
                return ''
        with patch.object(n, 'narwhal_ports', return_value={('tcp',30000):('abc',443),('tcp',30001):('abc',22)}), patch.object(n.shutil,'which',return_value=None):
            _, clients, _ = n.collect_network([], R(), self.cfg, '/nonexistent')
        self.assertEqual(clients['abc'], {'8.8.8.8'})
        self.assertNotIn('1.1.1.1', clients['abc']); self.assertNotIn('9.9.9.9', clients['abc'])

    def test_geography_requires_concurrent_ips_and_persistence(self):
        peers = {'a','b','c','d','e'}
        geo = FakeGeo({x:{'country':c} for x,c in zip(sorted(peers),['US','JP','DE','US','JP'])})
        h,s = n.geo_findings({'c':peers},geo,self.cfg,{},1000)
        self.assertFalse(h[0]['evidence']['sustained'])
        h,s = n.geo_findings({'c':peers},geo,self.cfg,s,1060)
        self.assertFalse(h[0]['evidence']['sustained'])
        h,s = n.geo_findings({'c':peers},geo,self.cfg,s,1120)
        self.assertTrue(h[0]['evidence']['sustained'])
        self.assertEqual(h[0]['severity'],'high')
        h,s = n.geo_findings({'c':{'a'}},geo,self.cfg,s,1180)
        self.assertFalse(h); self.assertEqual(s,{})

    def test_unknown_geo_never_proves_multiple_regions(self):
        h,_ = n.geo_findings({'c':set('abcde')},FakeGeo({}),self.cfg,{},1000)
        self.assertEqual(h[0]['rule'],'many-clients')
        cfg={**self.cfg,'geo_level':'region'}
        h,_=n.geo_findings({'c':set('abcde')},FakeGeo({x:{'country':x} for x in 'abcde'}),cfg,{},1000)
        self.assertFalse(any(x['rule']=='multi-region-sharing' for x in h))

    def test_expired_allowlist_is_not_active(self):
        self.cfg['allowlist']=[{'container':'c','rules':['miner'],'expires':'2000-01-01T00:00:00Z'}]
        self.assertFalse(n.allowed('c','miner',self.cfg))
        self.cfg['allowlist']=[{'container':'c','rules':['miner'],'expires':'2999-01-01T00:00:00Z'}]
        self.assertTrue(n.allowed('c','miner',self.cfg)); self.assertFalse(n.allowed('other','miner',self.cfg))

    def test_host_enforcement_protected(self):
        args=n.parser().parse_args(['--enforce','--select','HOST','--rule','miner'])
        h=n.finding({'id':'miner','title':'miner','severity':'high'},'HOST','process',{})
        with patch.object(n,'verify_identity',return_value=True):
            a=n.enforce([h],[],args,n.Runner())
        self.assertEqual(a[0]['result'],'refused')

    def test_stale_pid_refused(self):
        args=n.parser().parse_args(['--enforce','--select','c','--rule','miner'])
        h=n.finding({'id':'miner','title':'miner','severity':'high'},'c','process',{})
        with patch.object(n,'verify_identity',return_value=False):
            a=n.enforce([h],[],args,n.Runner())
        self.assertEqual(a[0]['result'],'refused')

    def test_geo_never_automatically_punished(self):
        args=n.parser().parse_args(['--enforce','--select','c','--rule','multi-region-sharing'])
        h=n.finding({'id':'multi-region-sharing','title':'geo','severity':'high'},'c','network',{'sustained':True})
        a=n.enforce([h],[],args,n.Runner())
        self.assertEqual(a[0]['result'],'refused')

    def test_atomic_report_private_and_html_escaped(self):
        r=dict(utc=n.utc(),hostname='<script>alert(1)</script>',mode='audit',containers=[],findings=[],actions=[],errors=[])
        with tempfile.TemporaryDirectory() as td:
            n.write_reports(r,Path(td),'report-test')
            p=Path(td)/'report-test.html'
            self.assertNotIn('<script>',p.read_text());self.assertIn('&lt;script&gt;',p.read_text())
            self.assertEqual(p.stat().st_mode & 0o777,0o600)

    def test_invalid_config(self):
        with self.assertRaises(ValueError):n.validate_config({**self.cfg,'min_client_ips':0})

    def test_reviewed_container_stop_is_targeted(self):
        class R(n.Runner):
            def __init__(self): super().__init__(); self.calls=[]
            def json(self, argv, **kw): return [{'Id':'full-id','State':{'Pid':123}}]
            def run(self, argv, **kw): self.calls.append(argv); return ''
        r=R(); args=n.parser().parse_args(['--enforce','--select','friendly','--rule','miner','--action','stop-container'])
        h=n.finding({'id':'miner','title':'miner','severity':'high'},'full-id','process',{})
        cs=[{'id':'full-id','name':'friendly','runtime':'podman','pid':123}]
        with patch.object(n,'verify_identity',return_value=True): actions=n.enforce([h],cs,args,r)
        self.assertEqual(r.calls,[['podman','stop','--time','10','full-id']])
        self.assertEqual(actions[0]['result'],'stopped')
        self.assertEqual(actions[0]['recovery_command'],['podman','start','full-id'])

    def test_allowlisted_process_is_not_stopped(self):
        args=n.parser().parse_args(['--enforce','--select','c','--rule','miner'])
        h=n.finding({'id':'miner','title':'miner','severity':'high'},'c','process',{})
        h['status']='allowlisted'
        self.assertEqual(n.enforce([h],[],args,n.Runner()),[])

    def test_udp_outbound_and_unreplied_not_counted(self):
        class R(n.Runner):
            def json(self, argv, **kw): return [{'addr_info':[{'local':'8.8.8.8'}]}]
            def run(self, argv, **kw):
                if argv[0]=='conntrack':
                    return ('udp 17 30 src=1.1.1.1 dst=8.8.8.8 sport=4000 dport=30000 src=10.0.0.1 dst=1.1.1.1 sport=443 dport=4000\n'
                            'udp 17 30 src=9.9.9.9 dst=4.2.2.2 sport=4000 dport=30000 src=10.0.0.1 dst=9.9.9.9 sport=443 dport=4000\n'
                            'udp 17 30 src=208.67.222.222 dst=8.8.8.8 sport=4000 dport=30000 [UNREPLIED] src=10.0.0.1 dst=208.67.222.222 sport=443 dport=4000\n')
                return ''
        with patch.object(n,'narwhal_ports',return_value={('udp',30000):('c',443)}),patch.object(n.shutil,'which',return_value='/usr/sbin/conntrack'):
            _,clients,_=n.collect_network([],R(),self.cfg,'/nonexistent')
        self.assertEqual(clients['c'],{'1.1.1.1'})

    def test_smtp_direction_and_imap_exclusion(self):
        class R(n.Runner):
            def run(self, argv, **kw):
                if argv == ['ss','-Hlnt']: return 'LISTEN 0 10 0.0.0.0:25 0.0.0.0:*\n'
                if argv == ['ss','-Htan']:
                    return ('ESTAB 0 0 10.0.0.1:40000 8.8.8.8:587\n'
                            'ESTAB 0 0 10.0.0.1:25 1.1.1.1:59000\n'
                            'ESTAB 0 0 10.0.0.1:40001 9.9.9.9:993\n'
                            'SYN-SENT 0 0 10.0.0.1:40002 8.8.8.8:25\n')
                return ''
        with patch.object(n,'narwhal_ports',return_value={}),patch.object(n.shutil,'which',return_value=None):
            network,_,_=n.collect_network([],R(),self.cfg,'/nonexistent')
        self.assertEqual({x['remote_port'] for x in network[0]['smtp_outbound']},{25,587})
        self.assertEqual(len(network[0]['smtp_outbound']),2)


if __name__=='__main__': unittest.main()
