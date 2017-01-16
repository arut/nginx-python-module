
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

    python_set $var var(r);

    root .;

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location /access {
            add_header a-time $request_time;
            python_access access(r);
        }

        location /proxy_access {
            proxy_read_timeout 100ms;
            add_header pa-time $request_time always;
            proxy_pass http://127.0.0.1:8080/access;
        }

        location /content {
            add_header c-time $request_time;
            python_content content(r);
        }

        location /proxy_content {
            proxy_read_timeout 100ms;
            add_header pc-time $request_time always;
            proxy_pass http://127.0.0.1:8080/content;
        }

        location /var {
            return 200 $var;
        }

        location /log {
            python_log var(r);
            return 200;
        }
    }
}
'''
),

(
'foo.py',
r'''
import ngx
import time

def access(r):
    time.sleep(0.2)

def content(r):
    time.sleep(0.2)
    r.status = 200
    r.sendHeader()
    r.send(None, ngx.SEND_LAST)

def var(r):
    time.sleep(0.1)
'''
),

('access', 'FOOBAR')

]


class HTTPSleepTestCase(nginx.HTTPTestCase):

    @classmethod
    def setUpClass(cls):
        cls.ngx = nginx.Run(files, ['nosync'])

    @classmethod
    def tearDownClass(cls):
        cls.ngx.close()

    def test_access(self):
        r = self.http('/access')
        self.assertEqual(r.status, 200)
        self.assertAlmostEqual(float(r.getheader('a-time')), 0.2, delta=0.02)

    def test_access_nonblocking(self):
        r = self.http('/proxy_access')
        self.assertEqual(r.status, 504)
        self.assertAlmostEqual(float(r.getheader('pa-time')), 0.1, delta=0.02)

    def test_content(self):
        r = self.http('/content')
        self.assertEqual(r.status, 200)
        self.assertAlmostEqual(float(r.getheader('c-time')), 0.2, delta=0.02)

    def test_content_nonblocking(self):
        r = self.http('/proxy_content')
        self.assertEqual(r.status, 504)
        self.assertAlmostEqual(float(r.getheader('pc-time')), 0.1, delta=0.02)

    def test_var(self):
        r = self.http('/var')
        self.assertEqual(r.status, 200)

    def test_log(self):
        r = self.http('/log')
        self.assertEqual(r.status, 200)


if __name__ == '__main__':
    unittest.main(argv=sys.argv)
