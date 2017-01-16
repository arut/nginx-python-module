
#
# Copyright (C) Roman Arutyunyan
#

import unittest
import nginx
import sys


files = [

(
'nginx.conf',
'''
daemon off;

events {
}

http {
    python_include foo.py;

    python "import hashlib";

    python
"
def sum(x, y):
    return x + y
";

    python_set $const 123456;
    python_set $md5 hashlib.md5(r.arg["foo"]).hexdigest();
    python_set $sum "sum(int(r.hi['x-foo']), int(r.hi['x-bar']))";
    python_set $included "xyz(r, 3)";
    python_set $recursive "sum(int(r.var['const']), int(r.hi['x-bar']))";
    python_set $empty empty(r);

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location /const {
            return 200 $const;
        }

        location /empty {
            return 200 $empty;
        }

        location /md5 {
            return 200 $md5;
        }

        location /sum {
            return 200 $sum;
        }

        location /recursive {
            return 200 $recursive;
        }

        location /included {
            return 200 $included;
        }
    }
}
'''
),

(
'foo.py',
r'''
import math

def xyz(r, x):
    y = int(r.arg['foobaz'])
    return math.trunc(math.pow(y, x))

def empty():
    pass
'''
)

]


class HTTPBasicTestCase(nginx.HTTPTestCase):

    @classmethod
    def setUpClass(cls):
        cls.ngx = nginx.Run(files)

    @classmethod
    def tearDownClass(cls):
        cls.ngx.close()

    def test_const(self):
        r = self.http('/const')
        self.assertEqual(r.read(), '123456')

    def test_empty(self):
        r = self.http('/empty')
        self.assertEqual(r.status, 200)

    def test_md5(self):
        r = self.http('/md5?foo=123')
        self.assertEqual(r.read(), '202cb962ac59075b964b07152d234b70')

    def test_sum(self):
        r = self.http('/sum', headers={ 'x-foo': '12', 'x-bar': '23' });
        self.assertEqual(r.read(), '35')

    def test_recursive(self):
        r = self.http('/recursive', headers={ 'x-bar': '10' });
        self.assertEqual(r.read(), '123466')

    def test_included(self):
        r = self.http('/included?foobaz=5')
        self.assertEqual(r.read(), '125')


if __name__ == '__main__':
    unittest.main(argv=sys.argv)
