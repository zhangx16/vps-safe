import ipaddress
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).parents[1]))
import rfw_audit as r


def ipv4_frame(payload, proto=6, fragment=0):
    tcp=struct.pack('!HHIIHHHH',40000,12345,0,0,0x5018,0,0,0)
    udp=struct.pack('!HHHH',40000,12345,8+len(payload),0)
    transport=(tcp if proto==6 else udp)+payload
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(transport),1,fragment,64,proto,0,
                   ipaddress.ip_address('8.8.8.8').packed,ipaddress.ip_address('1.1.1.1').packed)
    return b'\0'*12+b'\x08\x00'+ip+transport


def packet(payload, transport='tcp'):
    return {'payload':payload,'transport':transport}


class RfwTests(unittest.TestCase):
    def test_nonstandard_http_and_socks(self):
        p=r.decode_frame(ipv4_frame(b'GET / HTTP/1.1\r\n'))
        self.assertEqual(p['dport'],12345)
        self.assertEqual(r.detect_protocol(p),'http')
        self.assertEqual(r.detect_protocol(packet(b'\x05\x02\x00\x02')),'socks5')
        self.assertIsNone(r.detect_protocol(packet(b'\x05\x00')))
        self.assertFalse(r.is_http(b'POSTER binary'))

    def test_tls_not_plaintext_or_fet(self):
        p=b'\x16\x03\x03\x00\x20'+b'\x0f'*32
        self.assertIsNone(r.detect_protocol(packet(p),True,fet_mode='strict'))

    def test_wireguard_lengths_and_reserved_bytes(self):
        for kind,size in [(1,148),(2,92),(3,64),(4,32)]:
            self.assertEqual(r.detect_protocol(packet(bytes([kind])+b'\0'*(size-1),'udp')),'wireguard')
        self.assertIsNone(r.detect_protocol(packet(b'\x01\0\0\0'+b'x'*20,'udp')))
        self.assertIsNone(r.detect_protocol(packet(b'\x01\x01\0\0'+b'x'*144,'udp')))

    def test_quic_versions_and_short_flow_context(self):
        for version in [bytes.fromhex('00000001'),bytes.fromhex('6b3343cf')]:
            p=b'\xc0'+version+b'\x00\x00\x01'
            self.assertEqual(r.detect_protocol(packet(p,'udp')),'quic')
        self.assertIsNone(r.detect_protocol(packet(b'\x40random','udp')))
        self.assertEqual(r.detect_protocol(packet(b'\x40random','udp'),quic_known=True),'quic')
        self.assertFalse(r.quic_long(b'\xc0\0\0\0\1\xff\0'))
        self.assertIsNone(r.detect_protocol(packet(b'\xc0\x12\x34\x56\x78\0\0x','udp')))

    def test_quic_negotiation_and_gquic(self):
        self.assertTrue(r.quic_long(b'\xc0\0\0\0\0\0\0'+b'\0\0\0\1'))
        self.assertFalse(r.quic_long(b'\xc0\0\0\0\0\0\0x'))
        self.assertEqual(r.detect_protocol(packet(b'\x09'+b'abcdefgh'+b'Q043','udp')),'quic')

    def test_fet_heuristic_requires_first_payload_and_strict(self):
        p=b'\x0f'*32
        self.assertTrue(r.fet_candidate(p))
        self.assertIsNone(r.detect_protocol(packet(p),False,fet_mode='strict'))
        self.assertIsNone(r.detect_protocol(packet(p),True,fet_mode='loose'))
        self.assertEqual(r.detect_protocol(packet(p),True,fet_mode='strict'),'fet')
        self.assertFalse(r.fet_candidate(b'\0'*32))
        self.assertFalse(r.fet_candidate(b'\xff'*32))
        self.assertFalse(r.fet_candidate(b'abcdef'+b'\x0f'*26))
        self.assertFalse(r.fet_candidate(b'GET / '+b'\x0f'*26))
        self.assertFalse(r.fet_candidate(b'\x0f'*15))

    def test_fragment_truncation_and_invalid_headers_skipped(self):
        self.assertIsNone(r.decode_frame(ipv4_frame(b'abc',fragment=0x2000)))
        self.assertIsNone(r.decode_frame(ipv4_frame(b'abc')[:-1]))
        self.assertIsNone(r.decode_frame(b'garbage'))
        f=bytearray(ipv4_frame(b'abc'));f[14]=0x41
        self.assertIsNone(r.decode_frame(bytes(f)))

    def test_vlan_and_basic_ipv6(self):
        f=ipv4_frame(b'GET / ')
        vlan=f[:12]+b'\x81\x00\x00\x01\x08\x00'+f[14:]
        self.assertEqual(r.decode_frame(vlan)['payload'],b'GET / ')
        payload=b'\x05\x01\0';tcp=struct.pack('!HHIIHHHH',3000,6000,0,0,0x5018,0,0,0)+payload
        ip=struct.pack('!IHBB16s16s',6<<28,len(tcp),6,64,ipaddress.ip_address('2001:4860::1').packed,ipaddress.ip_address('2606:4700::1').packed)
        p=r.decode_frame(b'\0'*12+b'\x86\xdd'+ip+tcp)
        self.assertEqual(p['src'],'2001:4860::1');self.assertEqual(r.detect_protocol(p),'socks5')

    def test_smtp_is_network_evidence_not_spam_verdict(self):
        hits=r.smtp_findings([{'scope':'c','smtp_outbound':[{'remote_ip':'8.8.8.8','remote_port':587,'state':'ESTAB'}]}])
        self.assertEqual(hits[0]['kind'],'network');self.assertTrue(hits[0]['evidence']['inference_only'])
        self.assertFalse(r.smtp_findings([{'scope':'c','smtp_outbound':[]}]))

    def test_country_allow_deny_unknown(self):
        class Geo:
            def get(self,ip):return {'country':{'a':'US','b':'JP'}.get(ip)}
        clients={'c':{'a','b','unknown'},'HOST':{'b'}}
        hits,coverage=r.country_findings(clients,Geo(),{'mode':'deny','countries':['JP']})
        self.assertEqual(hits[0]['evidence']['countries'],{'JP':1});self.assertEqual(coverage['unknown_ips'],1)
        hits,_=r.country_findings(clients,Geo(),{'mode':'allow','countries':['JP']})
        self.assertEqual(hits[0]['evidence']['countries'],{'US':1})
        hits,_=r.country_findings(clients,Geo(),{'mode':'allow','countries':['JP'],'containers':['other']})
        self.assertFalse(hits)

    def test_stats_counter_delta_and_reset(self):
        s='Source IP Proto Port Allowed Blocked Total\n8.8.8.8 TCP 30000 5 7 12\n1.1.1.1 UDP 1234 1 0 1\n'
        rows,state=r.parse_rfw_stats(s,{('tcp',30000):('vm-name',80)},[{'name':'vm-name','id':'full-id'}])
        self.assertEqual(rows[0]['scope'],'full-id');self.assertTrue(rows[0]['cumulative'])
        self.assertIsNone(rows[0]['blocked_delta'])
        rows,_=r.parse_rfw_stats(s.replace('5 7 12','5 9 14'),{},[],state)
        self.assertEqual(rows[0]['blocked_delta'],2)
        rows,_=r.parse_rfw_stats(s.replace('5 7 12','5 1 6'),{},[],state)
        self.assertIsNone(rows[0]['blocked_delta'])
        rows,_=r.parse_rfw_stats('garbage TCP 30000 5 7 12\n8.8.8.8 TCP 70000 1 0 1\n',{},[])
        self.assertFalse(rows)

    def test_no_ssh_or_management_capture_attribution(self):
        p={'transport':'tcp','dport':30000}
        self.assertEqual(r.packet_scope(p,{('tcp',30000):('vm',22)},{'vm':'id'},{22,8792}),(None,None))
        self.assertEqual(r.packet_scope(p,{('tcp',30000):('vm',80)},{'vm':'id'},{22,8792}),('id',80))


if __name__=='__main__':unittest.main()
