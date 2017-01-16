
#
# Copyright (C) Roman Arutyunyan
#

import unittest
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

http {
    python "import ngx";

    python_include foo.py;

    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        root .;

        location /access {
            python_access access(r);
        }

        location /log {
            python_log log(r);
            return 200;
        }

        location /content {
            python_content content(r);
        }

        location /request_body {
            python_content request_body(r);
        }
    }
}
'''
),

(
'foo.py',
r'''
def access(r):
    if r.arg['foo'] == 'x':
        return 456
    elif r.arg['foo'] == 'y':
        return ngx.DECLINED

def log(r):
    file = open('test-log', 'w')
    file.write('FOOBAR');
    file.close()

def content(r):
    r.status = 200
    r.ho['Content-Length'] = 9
    r.sendHeader()
    r.send('FOOBAR');
    r.send('XYZ', ngx.SEND_LAST)

def request_body(r):
    s = r.var['request_body']
    r.status = 200
    r.ho['Content-Length'] = len(s)
    r.sendHeader()
    r.send(s, ngx.SEND_LAST)
'''
),

('access', 'FOOBAR')

]


class HTTPPhasesTestCase(nginx.HTTPTestCase):

    @classmethod
    def setUpClass(cls):
        cls.ngx = nginx.Run(files)

    @classmethod
    def tearDownClass(cls):
        cls.ngx.close()

    def test_access1(self):
        r = self.http('/access?foo=x')
        self.assertEqual(r.status, 456)

    def test_access2(self):
        r = self.http('/access?foo=y')
        self.assertEqual(r.read(), 'FOOBAR')

    def test_access3(self):
        r = self.http('/access')
        self.assertEqual(r.read(), 'FOOBAR')

    def test_log(self):
        r = self.http('/log')
        time.sleep(0.1) # give a little time to create file
        file = open(self.__class__.ngx.test_dir + '/test-log')
        self.assertEqual(file.read(), 'FOOBAR')

    def test_content(self):
        r = self.http('/content')
        self.assertEqual(r.read(), 'FOOBARXYZ')

    def test_request_body(self):
        r = self.http('/request_body', body='FOOBAR')
        self.assertEqual(r.read(), 'FOOBAR')


if __name__ == '__main__':
	unittest.main(argv=sys.argv)
