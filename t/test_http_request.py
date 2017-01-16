
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

    python_set $hi "r.hi['foo'] + r.hi['bar']";
    python_set $arg "r.arg['foo'] + r.arg['bar']";
    python_set $var "r.var['remote_addr'] + r.var['arg_foo']";
    python_set $ctx r.ctx['foo'];

    root .;

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location /hi {
            return 200 $hi;
        }

        location /ho {
            python_content content(r);
        }

        location /var {
            return 200 $var;
        }

        location /arg {
            return 200 $arg;
        }

        location /ctx {
            python_access access(r);
            add_header Foo $ctx;
        }

        location /status {
            python_content content2(r);
        }

        location /log {
            python_log "r.log('TESTING NGINX PYTHON LOGGING', ngx.LOG_INFO)";
            return 200;
        }

        location /send {
            python_content content3(r);
        }
    }
}
'''
),

(
'foo.py',
r'''
import ngx

def access(r):
    r.ctx['foo'] = 'FOO'

def content(r):
    r.ho['foo'] = 'FOO';
    r.ho['bar'] = r.ho['foo']
    r.status = 200
    r.sendHeader()
    r.send('')
    r.send(None, ngx.SEND_LAST)

def content2(r):
    r.status = 222
    r.ho['status'] = r.status
    r.sendHeader()
    r.send(None, ngx.SEND_LAST)

def content3(r):
    r.status = 200
    r.ho['Content-Length'] = 9
    r.sendHeader()
    r.send('FOO')
    r.send('BAR', ngx.SEND_FLUSH)
    r.send('QUX', ngx.SEND_LAST)
'''
),

('ctx', 'FOOBAR')

]


class HTTPRequestTestCase(nginx.HTTPTestCase):

    @classmethod
    def setUpClass(cls):
        cls.ngx = nginx.Run(files)

    @classmethod
    def tearDownClass(cls):
        cls.ngx.close()

    def test_hi(self):
        r = self.http('/hi', headers={ 'foo': 'FOO', 'bar': 'BAR' })
        self.assertEqual(r.read(), 'FOOBAR')

    def test_ho(self):
        r = self.http('/ho')
        self.assertEqual(r.getheader('foo') + r.getheader('bar'), 'FOOFOO')

    def test_var(self):
        r = self.http('/var?foo=FOO')
        self.assertEqual(r.read(), '127.0.0.1FOO')

    def test_arg(self):
        r = self.http('/arg?foo=FOO&bar=BAR')
        self.assertEqual(r.read(), 'FOOBAR')

    def test_ctx(self):
        r = self.http('/ctx')
        self.assertEqual(r.getheader('Foo'), 'FOO')

    def test_status(self):
        r = self.http('/status')
        self.assertEqual(r.status, 222)
        self.assertEqual(r.getheader('status'), '222')

    def test_log(self):
        r = self.http('/log')
        self.assertEqual(r.status, 200)

        log = open(self.__class__.ngx.log_file)
        m = None
        for line in log:
            m = re.search('\[info\].*TESTING NGINX PYTHON LOGGING', line)
            if m:
                break
        self.assertNotEqual(m, None)

    def test_send(self):
        r = self.http('/send')
        self.assertEqual(r.read(), 'FOOBARQUX')


if __name__ == '__main__':
    unittest.main(argv=sys.argv)
