
#
# Copyright (C) Roman Arutyunyan
#

import unittest
import socket
import nginx
import sys
import re


files = [

(
'nginx.conf',
'''
daemon off;

events {
}

stream {
    python_include foo.py;
    python_include dns.py;

    python_set $response response(s);

    resolver 127.0.0.1:8081 ipv6=off;

    server {
        listen 127.0.0.1:8080;
        python_preread preread(s);
        return $response;
    }

    server {
        listen 127.0.0.1:8081 udp;
        python_content dns(s);
    }
}
'''
),

(
'foo.py',
r'''
import ngx


def preread(s):
    if len(s.buf) == 0:
        return ngx.AGAIN

    colon = s.buf.find(':')
    if colon == -1 or colon == len(s.buf) - 1:
        return ngx.ERROR

    fun = s.buf[0:colon]
    name = s.buf[colon + 1:]
    resp = ''

    if fun == 'gethostbyname':
        try:
            resp = socket.gethostbyname(name)
        except socket.herror:
            resp = 'nxdomain'

    elif fun == 'gethostbyname_ex':
        try:
            resp = socket.gethostbyname_ex(name)
        except socket.herror:
            resp = 'nxdomain'

    elif fun == 'getaddrinfo':
        try:
            resp = socket.getaddrinfo(name, 80, socket.AF_INET,
                                      socket.SOCK_STREAM)
        except socket.gaierror:
            resp = 'nxdomain'

    s.ctx['resp'] = resp
    return ngx.OK

def response(s):
    return s.ctx['resp']
'''
),

(
'dns.py',
r'''
import struct
import socket
import ngx


# name_as_int -> [ (addr, ttl) ]
dns_db = {
    0x666f6f31: [ (0x7f000001, 0) ],                      # foo1
    0x666f6f32: [ (0x7f000001, 0), (0x7f000002, 0) ],     # foo2
    0x62617231: [ (0x7f000001, 100) ],                    # bar1
    0x62617232: [ (0x7f000001, 100), (0x7f000002, 100) ]  # bar2
}


def dns(s):
    # accept only 4-character names
    # treat them as 4-byte integers

    (id, flags, qd, an, ns, ar, four, name, zero, type, cl) = struct.unpack(
        '!HHHHHHBIBHH', s.buf)

    s.log('dns request id:0x{0:x}, name:0x{1:x}'.format(id, name))

    if name not in dns_db:
        ret = struct.pack('!HHHHHHBIBHH',
                          id,                  # ID
                          0x8583,              # flags: QR, AA, RD, RA, NXDOMAIN
                          1, 0,                # QDCOUNT=1, ANCOUNT=0
                          0, 0,                # NSCOUNT=0, ARCOUNT=0
                          4, name, 0, 1, 1)    # question

    else:
        addrs = dns_db[name]

        ret = struct.pack('!HHHHHHBIBHH',
                          id,                  # ID
                          0x8580,              # flags: QR, AA, RD, RA
                          1, len(addrs),       # QDCOUNT=1, ANCOUNT=XX
                          0, 0,                # NSCOUNT=0, ARCOUNT=0
                          4, name, 0, 1, 1)    # question

        for addr in addrs:
            ret += struct.pack('!BIBHHIHI',
                               4,              # name length=4
                               name,           # name as integer
                               0,              # name length=0 (end)
                               1, 1, addr[1],  # TYPE=1, CLASS=1, TTL=XX
                               4, addr[0]      # RDLEN=1, RDATA=XX
                               )

    s.sock.send(ret)
'''
),

]


class StreamResolveTestCase(nginx.StreamTestCase):

    @classmethod
    def setUpClass(cls):
        cls.ngx = nginx.Run(files, ['stream', 'nosync'])

    @classmethod
    def tearDownClass(cls):
        cls.ngx.close()

    def test_gethostbyname(self):
        s = self.stream('gethostbyname:foo1')
        self.assertEqual(s.recv(128), '127.0.0.1')

    def test_gethostbyname_multi(self):
        s = self.stream('gethostbyname:foo2')
        self.assertIn(s.recv(128), ['127.0.0.1', '127.0.0.2'])

    def test_gethostbyname_cached(self):
        s = self.stream('gethostbyname:bar2')
        s = self.stream('gethostbyname:bar2')
        self.assertIn(s.recv(128), ['127.0.0.1', '127.0.0.2'])

    def test_gethostbyname_nxdomain(self):
        s = socket.create_connection(('127.0.0.1', 8080))
        s.send('gethostbyname:quxx')
        self.assertEqual(s.recv(128), 'nxdomain')

    def test_gethostbyname_ex(self):
        s = self.stream('gethostbyname_ex:foo1')
        c = ( 'foo1', [], ['127.0.0.1'] )
        self.assertEqual(s.recv(128), str(c))

    def test_gethostbyname_ex_multi(self):
        s = self.stream('gethostbyname_ex:foo2')
        c1 = ( 'foo2', [], ['127.0.0.1', '127.0.0.2'] )
        c2 = ( 'foo2', [], ['127.0.0.2', '127.0.0.1'] )
        self.assertIn(s.recv(128), [ str(c1), str(c2) ])

    def test_getaddrinfo(self):
        s = self.stream('getaddrinfo:foo2')
        c = [ (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 80)),
              (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.2', 80)) ]
        self.assertIn(s.recv(128), [ str(c), str(reversed(c)) ])

    def test_getaddrinfo_nxdomain(self):
        s = self.stream('getaddrinfo:quxx')
        self.assertEqual(s.recv(128), 'nxdomain')


if __name__ == '__main__':
    unittest.main(argv=sys.argv)
