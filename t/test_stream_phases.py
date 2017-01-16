
#
# Copyright (C) Roman Arutyunyan
#

import unittest
import socket
import nginx
import time
import sys


files = [

(
'nginx.conf',
'''
daemon off;

events {
}

stream {
    python "import ngx";

    python_include foo.py;
    python_set $foo s.ctx['foo'];

    server {
        listen 127.0.0.1:8080;
        listen 127.0.0.1:8080 udp;
        python_access access(s);
        return $foo;
    }

    server {
        listen 127.0.0.1:8081;
        python_preread preread(s);
        return $foo;
    }

    server {
        listen 127.0.0.1:8082;
        python_log log(s);
        return FOO;
    }

    server {
        listen 127.0.0.1:8083;
        python_content echo(s);
    }
}
'''
),

(
'foo.py',
r'''
def access(s):
    if s.var['protocol'] == 'TCP':
        s.ctx['foo'] = 'FOO'
    elif s.buf == 'bar':
        return ngx.ABORT
    else:
        s.ctx['foo'] = s.buf

def preread(s):
    if len(s.buf) < 3:
        return ngx.AGAIN

    s.ctx['foo'] = s.buf[0:3]
    return ngx.OK

def log(s):
    file = open('test-log', 'w')
    file.write('FOOBAR');
    file.close()

def echo(s):
    while True:
        b = s.sock.recv(128)
        if len(b) == 0:
            return
        s.sock.send(b)
'''
),

]


class StreamPhasesTestCase(nginx.StreamTestCase):

    @classmethod
    def setUpClass(cls):
        cls.ngx = nginx.Run(files, ['stream'])

    @classmethod
    def tearDownClass(cls):
        cls.ngx.close()

    def test_access1(self):
        r = self.stream()
        self.assertEqual(r.recv(10), 'FOO')

    def test_access2(self):
        r = self.stream('bar', udp=1)
        r.settimeout(0.1)
        timeout = 0
        try:
            r.recv(10)
        except socket.timeout:
            timeout = 1
        self.assertEqual(timeout, 1)

    def test_access3(self):
        r = self.stream('qux', udp=1)
        self.assertEqual(r.recv(10), 'qux')

    def test_preread(self):
        r = self.stream('1', port=8081)
        time.sleep(0.1)
        r.send('23456')
        self.assertEqual(r.recv(10), '123')

    def test_log(self):
        r = self.stream(port=8082)
        self.assertEqual(r.recv(10), 'FOO')
        time.sleep(0.1) # give a little time to create file
        file = open(self.__class__.ngx.test_dir + '/test-log')
        self.assertEqual(file.read(), 'FOOBAR')

    def test_content(self):
        r = self.stream(port=8083)
        r.sendall('FOO')
        self.assertEqual(r.recv(10), 'FOO')
        r.sendall('BAR')
        self.assertEqual(r.recv(10), 'BAR')
        r.sendall('QYXQYX')
        self.assertEqual(r.recv(10), 'QYXQYX')


if __name__ == '__main__':
	unittest.main(argv=sys.argv)
