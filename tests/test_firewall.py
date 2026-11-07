import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).parents[1]))
import vps_safe as v


def config():return v.validate({'wan_interfaces':['wan']})


class FirewallTests(unittest.TestCase):
    def test_interface_injection_and_unknown_fields_rejected(self):
        for raw in [{'wan_interfaces':['eth0; flush ruleset']},{'wan_interfaces':['lo']},{'wan_interfaces':['wan'],'typo':True}]:
            with self.assertRaises(ValueError):v.validate(raw)
    def test_management_cannot_be_blocked(self):
        with self.assertRaises(ValueError):v.validate({'wan_interfaces':['wan'],'blocked_tcp_ports':[22]})
        with self.assertRaises(ValueError):v.validate({'wan_interfaces':['wan'],'management_tcp_ports':[]})
    def test_quarantine_is_host_only(self):
        for ips in [['0.0.0.0/0'],['10.0.0.0/24'],['127.0.0.1'],['::1'],['fe80::1']]:
            with self.subTest(ips=ips),self.assertRaises(ValueError):v.validate({'wan_interfaces':['wan'],'quarantine_ips':ips})
        self.assertEqual(v.validate({'wan_interfaces':['wan'],'quarantine_ips':['10.88.0.2']})['quarantine_ips'],['10.88.0.2/32'])
    def test_allow_policy_requires_both_intended_families(self):
        with self.assertRaises(ValueError):v.validate({'wan_interfaces':['wan'],'source_policy':{'mode':'allow','cidrs':['192.0.2.0/24']}})
        c=v.validate({'wan_interfaces':['wan'],'source_policy':{'mode':'allow','cidrs':['192.0.2.0/24'],'families':[4]}})
        self.assertIn('ip saddr != @source_policy4',v.render(c))
    def test_table_is_scoped_and_no_global_flush(self):
        body=v.render(config());self.assertIn('table inet vps_safe',body)
        self.assertNotIn('flush ruleset',body);self.assertNotIn('policy drop',body)
        self.assertIn('ct direction original',body);self.assertIn('tcp dport @management counter accept',body)
        self.assertIn('nd-neighbor-solicit',body);self.assertIn('udp sport 67 udp dport 68 accept',body)
    def test_smtp_in_host_and_forward_egress(self):
        body=v.render(config());self.assertEqual(body.count('oifname @wan tcp dport @smtp counter drop'),2)
        self.assertNotIn('tcp sport @smtp counter drop',body)
    def test_no_auto_enforcement_from_geo_or_names(self):
        c=config();body=v.render(c)
        self.assertNotIn('xmrig',body);self.assertNotIn('QUIC',body)
        self.assertEqual(c['source_policy']['mode'],'off')
    def test_ssh_environment_protects_custom_port(self):
        with patch.dict(os.environ,{'SSH_CONNECTION':'203.0.113.2 50000 198.51.100.1 2222'}),patch.object(v.shutil,'which',return_value=None):
            self.assertIn(2222,v.detected_ssh_ports())
    def test_state_absolute_and_private(self):
        with tempfile.TemporaryDirectory() as td:
            p=v.private_state(td+'/state');self.assertTrue(p.is_absolute());self.assertEqual(p.stat().st_mode&0o777,0o700)
            v.save(p/'a.json',{'ok':True});self.assertEqual((p/'a.json').stat().st_mode&0o777,0o600)
    def test_stale_transaction_never_rolls_back_newer_apply(self):
        with tempfile.TemporaryDirectory() as td:
            fw=v.Firewall(td);a='a'*32;b='b'*32
            fw.write_tx({'id':a,'status':'pending'});fw.write_tx({'id':b,'status':'confirmed'})
            v.save(fw.state/'current.json',{'id':b,'status':'confirmed'})
            with self.assertRaises(ValueError):fw.rollback(a)
    def test_confirmed_timer_is_noop(self):
        with tempfile.TemporaryDirectory() as td:
            fw=v.Firewall(td);tx='a'*32;fw.write_tx({'id':tx,'status':'confirmed'})
            self.assertEqual(fw.rollback(tx,True)['status'],'no-op')
    def test_current_recovers_interrupted_pointer_update(self):
        with tempfile.TemporaryDirectory() as td:
            fw=v.Firewall(td);tx='a'*32;fw.write_tx({'id':tx,'status':'confirmed'})
            v.save(fw.state/'current.json',{'id':tx,'status':'pending'})
            self.assertEqual(fw.current()['status'],'confirmed')
    def test_no_timer_means_no_apply_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            fw=v.Firewall(td);calls=[]
            def command(argv,text=None,check=True):calls.append(argv);return type('R',(),{'stdout':'','returncode':0})()
            with patch.object(fw,'snapshot',return_value=''),patch.object(v,'run',side_effect=command),patch.object(v.shutil,'which',return_value=None):
                with self.assertRaises(ValueError):fw.apply(config())
            self.assertFalse(any(cmd[:2]==['nft','-f'] for cmd in calls))
            self.assertEqual(fw.current()['status'],'aborted')
    def test_confirm_deadline_is_checked(self):
        with tempfile.TemporaryDirectory() as td:
            fw=v.Firewall(td);tx='b'*32;fw.write_tx({'id':tx,'status':'pending','deadline':1})
            v.save(fw.state/'current.json',{'id':tx,'status':'pending'})
            with self.assertRaises(ValueError):fw.confirm(tx)
    def test_overlapping_cidrs_are_collapsed(self):
        self.assertEqual(v.networks(['10.0.0.0/8','10.1.0.0/16']),['10.0.0.0/8'])
        self.assertEqual(v.networks(['10.0.0.2','10.0.0.3'],hosts=True),['10.0.0.2/32','10.0.0.3/32'])
    def test_watchdog_is_armed_before_atomic_apply(self):
        with tempfile.TemporaryDirectory() as td:
            fw=v.Firewall(td);calls=[];original_exists=v.Path.exists
            original_stat=os.stat
            def exists(path):
                return True if str(path)=='/run/systemd/system' else original_exists(path)
            def command(argv,text=None,check=True):
                calls.append(argv);return type('R',(),{'stdout':'','returncode':0})()
            with patch.object(fw,'snapshot',return_value=''),patch.object(v,'run',side_effect=command),patch.object(v.shutil,'which',return_value='/mock/tool'),patch.object(v.Path,'exists',exists),patch.object(v.os,'stat',wraps=os.stat) as stat_mock:
                # The host namespace is equal in normal unit-test environments.
                ns=type('S',(),{'st_ino':123})()
                stat_mock.side_effect=lambda p,*a,**kw:ns if str(p) in ('/proc/self/ns/net','/proc/1/ns/net') else original_stat(p,*a,**kw)
                result=fw.apply(config())
            names=[x[0] for x in calls]
            self.assertEqual(names,['nft','systemd-run','nft'])
            timer=calls[1];helper=timer[timer.index(sys.executable)+1]
            self.assertTrue(Path(helper).is_file());self.assertIn(td,helper)
            self.assertTrue(result['automatic_rollback'])
    def test_host_network_container_is_not_quarantined(self):
        obj=[{'Id':'id','HostConfig':{'NetworkMode':'host'}}]
        with patch.object(v,'run',return_value=type('R',(),{'stdout':json.dumps(obj)})()):
            with self.assertRaises(ValueError):v.quarantine_addresses('podman','container')
    def test_container_ips_are_resolved_without_shell(self):
        obj=[{'Id':'full-id','Name':'sample','HostConfig':{},'NetworkSettings':{'Networks':{'n':{'IPAddress':'10.88.0.2','GlobalIPv6Address':'fd88::2'}}}}]
        with patch.object(v,'run',return_value=type('R',(),{'stdout':json.dumps(obj)})()) as called:
            ips,target=v.quarantine_addresses('podman','sample')
        self.assertEqual(ips,['10.88.0.2/32','fd88::2/128']);self.assertEqual(target['id'],'full-id')
        called.assert_called_once_with(['podman','inspect','sample'])
    def test_preflight_protects_host_addresses(self):
        c=config();c['quarantine_ips']=['10.0.0.1/32']
        with patch.object(v,'run',return_value=type('R',(),{'stdout':'[{"ifname":"wan"}]'})()),patch.object(v,'host_addresses',return_value={'10.0.0.1'}):
            with self.assertRaises(ValueError):v.apply_preflight(c)

if __name__=='__main__':unittest.main()
