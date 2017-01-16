
#
# Copyright (C) Roman Arutyunyan
#

import unittest
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

http {
    python_include foo.py;

    root .;

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location /props {
            python_content props(r);
        }

        location /raw_http {
            python_content raw_http(r);
        }

        location /connrefuse {
            python_content connrefuse(r);
        }

        location /sockname {
            python_content sockname(r);
        }

        location /fileno {
            python_content fileno(r);
        }

        location /sockopt {
            python_content sockopt(r);
        }

        location /timeout {
            add_header timeout $request_time;
            python_content timeout(r);
        }

        location /makefile {
            python_content makefile(r);
        }

        location /hlib {
            python_content hlib(r);
        }

        location /ulib {
            python_content ulib(r);
        }
    }

    server {
        listen 127.0.0.1:8081;
        server_name localhost;

        location / {
            return 200 FOO;
        }

        location /addr {
            return 200 "('$remote_addr', $remote_port)";
        }
    }
}
'''
),

(
'foo.py',
r'''
import re
import ngx
import struct
import socket
import httplib
import urllib


def props(r):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    r.ho['sock-family1'] = s.family
    r.ho['sock-family2'] = socket.AF_INET
    r.ho['sock-type1'] = s.type
    r.ho['sock-type2'] = socket.SOCK_STREAM

    return 204

def raw_http(r):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 8081))
    s.send('GET / HTTP/1.0\r\n')
    s.sendall('Host: localhost\r\n\r\n')

    ret = ''
    while True:
        d = s.recv(512)
        if len(d) == 0:
            break
        ret += d

    s.close()

    r.status = 200
    r.sendHeader()
    r.send(ret, ngx.SEND_LAST)

def connrefuse(r):
    s = socket.socket(socket.AF_INET)

    err = 0
    try:
        s.connect(('127.0.0.1', 8082))
    except socket.error as e:
        err = 1
    if err == 0:
        return 440

    err = s.connect_ex(('127.0.0.1', 8083))
    if err == 0:
        return 441

    s.close()

    return 204

def sockname(r):
    s = socket.socket(socket.AF_INET)

    s.connect(('127.0.0.1', 8081))
    s.sendall('GET /addr HTTP/1.0\r\nHost: localhost\r\n\r\n');

    f = s.makefile()
    for line in f:
        if line == '\r\n':
            r.ho['remote-addr']  = f.read()
            break

    r.status = 200
    r.sendHeader()
    r.send(str(s.getsockname()) + '-' + str(s.getpeername()), ngx.SEND_LAST)

def fileno(r):
    s = socket.socket(socket.AF_INET)
    s.connect(('127.0.0.1', 8081))
    r.ho['fd'] = s.fileno()
    return 204

def sockopt(r):
    s = socket.socket(socket.AF_INET)
    s.connect(('127.0.0.1', 8081))

    ls = struct.pack('ii', 1, 1234)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, ls)
    ls = s.getsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                      struct.calcsize('ii'))
    res = struct.unpack('ii', ls)

    # FreeBSD may return 128 as l_onoff value, put 1 instead
    if res[0] != 0:
        res = (1, res[1])
    r.ho['so-linger'] = res

    r.ho['so-type1'] = s.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
    r.ho['so-type2'] = socket.SOCK_STREAM

    return 204

def timeout(r):
    socket.setdefaulttimeout(0.1)
    s = socket.create_connection(('127.0.0.1', 8081))

    try:
        s.recv(1)
    except socket.timeout:
        r.ho['timeout1'] = 1

    s.settimeout(0.2)
    try:
        s.recv(1)
    except socket.timeout:
        r.ho['timeout2'] = 1

    return 204

def makefile(r):
    s = socket.create_connection(('127.0.0.1', 8081))
    f = s.makefile()
    f.write('GET / HTTP/1.0\r\n')
    f.writelines(['Host: localhost\r\n',
                  'Fd: {0}\r\n'.format(f.fileno()),
                  '\r\n'])
    lines = f.readlines()
    f.close()

    r.status = 200
    r.sendHeader()
    if len(lines):
        r.send(lines[len(lines) - 1])
    r.send(None, ngx.SEND_LAST)

def hlib(r):
    hc = httplib.HTTPConnection('127.0.0.1', 8081)
    hc.request('GET', '/')
    rs = hc.getresponse()

    r.status = rs.status
    r.sendHeader()
    r.send(rs.read(), ngx.SEND_LAST)

def ulib(r):
    u = urllib.urlopen('http://127.0.0.1:8081/')

    r.status = u.getcode()
    r.sendHeader()
    r.send(u.read(), ngx.SEND_LAST)
'''
),

]


class HTTPSocketTestCase(nginx.HTTPTestCase):

    @classmethod
    def setUpClass(cls):
        cls.ngx = nginx.Run(files, ['nosync'])

    @classmethod
    def tearDownClass(cls):
        cls.ngx.close()

    def test_props(self):
        r = self.http('/props')
        self.assertEqual(r.status, 204)
        self.assertEqual(r.getheader('sock-family1'),
                         r.getheader('sock-family2'))
        self.assertEqual(r.getheader('sock-type1'),
                         r.getheader('sock-type1'))

    def test_raw_http(self):
        r = self.http('/raw_http')
        self.assertEqual(r.status, 200)
        ret = r.read();
        self.assertIsNotNone(re.search('200 OK', ret))
        self.assertIsNotNone(re.search('FOO$', ret))

    def test_connrefuse(self):
        r = self.http('/connrefuse')
        self.assertEqual(r.status, 204)

    def test_bind(self):
        r = self.http('/sockname')
        self.assertEqual(r.read(), r.getheader('remote-addr')
                                   + "-('127.0.0.1', 8081)")

    def test_fileno(self):
        r = self.http('/fileno')
        self.assertEqual(r.status, 204)
        self.assertTrue(r.getheader('fd').isdigit())

    def test_sockopt(self):
        r = self.http('/sockopt')
        self.assertEqual(r.status, 204)
        self.assertEqual(r.getheader('so-linger'), '(1, 1234)')
        self.assertEqual(r.getheader('so-type1'), r.getheader('so-type2'))

    def test_timeout(self):
        r = self.http('/timeout')
        self.assertEqual(r.status, 204)
        self.assertEqual(r.getheader('timeout1'), '1')
        self.assertEqual(r.getheader('timeout2'), '1')
        self.assertAlmostEqual(float(r.getheader('timeout')), 0.3, delta=0.02)

    def test_makefile(self):
        r = self.http('/makefile')
        self.assertEqual(r.status, 200)
        self.assertEqual(r.read(), 'FOO')

    def test_hlib(self):
        r = self.http('/hlib')
        self.assertEqual(r.status, 200)
        self.assertEqual(r.read(), 'FOO')

    def test_ulib(self):
        r = self.http('/ulib')
        self.assertEqual(r.status, 200)
        self.assertEqual(r.read(), 'FOO')


if __name__ == '__main__':
    unittest.main(argv=sys.argv)
