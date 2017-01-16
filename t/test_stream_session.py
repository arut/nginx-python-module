
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

stream {
    python_include foo.py;

    python_set $var "s.var['remote_addr'] + 'foo'";
    python_set $ctx s.ctx['bar'];
    python_set $names "s.ctx['sockname'] + s.ctx['peername']";

    server {
        listen 127.0.0.1:8080;
        return $var;
    }

    server {
        listen 127.0.0.1:8081;
        python_access access(s);
        return $ctx;
    }

    server {
        listen 127.0.0.1:8082;
        python_access access2(s);
        return FOO;
    }

    server {
        listen 127.0.0.1:8083;
        python_access access3(s);
        return $names;
    }
}
'''
),

(
'foo.py',
r'''

import ngx

def access(s):
    s.ctx['foo'] = 'FOO'
    s.ctx['bar'] = s.ctx['foo']

def access2(s):
    s.log('TESTING NGINX PYTHON LOGGING', ngx.LOG_INFO)
    return ngx.OK

def access3(s):
    s.ctx['sockname'] = s.sock.getsockname()
    s.ctx['peername'] = s.sock.getpeername()
'''
),

]


class StreamSessionTestCase(nginx.StreamTestCase):

    @classmethod
    def setUpClass(cls):
        cls.ngx = nginx.Run(files, ['stream'])

    @classmethod
    def tearDownClass(cls):
        cls.ngx.close()

    def test_var(self):
        r = self.stream()
        self.assertEqual(r.recv(20), '127.0.0.1foo')

    def test_ctx(self):
        r = self.stream(port=8081)
        self.assertEqual(r.recv(10), 'FOO')

    def test_log(self):
        r = self.stream(port=8082)
        self.assertEqual(r.recv(10), 'FOO')

        log = open(self.__class__.ngx.log_file)
        m = None
        for line in log:
            m = re.search('\[info\].*TESTING NGINX PYTHON LOGGING', line)
            if m:
                break
        self.assertNotEqual(m, None)

    def test_sock(self):
        r = self.stream(port=8083)
        self.assertEqual(r.recv(128), "('127.0.0.1', 8083, '127.0.0.1', "
                                      + str(r.getsockname()[1]) + ")")


if __name__ == '__main__':
    unittest.main(argv=sys.argv)
