
#
# Copyright (C) Roman Arutyunyan
#

import subprocess
import unittest
import tempfile
import httplib
import shutil
import signal
import socket
import time
import sets
import os
import re


class Run:

    def __init__(self, files, require = []):
        self.nginx_bin = os.getenv('TEST_NGINX_BINARY', '../nginx/objs/nginx')

        cf = subprocess.check_output([self.nginx_bin, '-V'],
                                     stderr=subprocess.STDOUT)

        rset = sets.Set(require)

        if 'stream' in rset and not re.search('--with-stream([^-].*)?$', cf):
            raise unittest.SkipTest('nginx is built without stream')

        if 'nosync' in rset and re.search('-DNGX_PYTHON_SYNC=0*[1-9]', cf):
            raise unittest.SkipTest('nginx-python-module is built sync')

        self.test_dir = tempfile.mkdtemp('nginx-test')

        try:
            os.mkdir('{0}/logs'.format(self.test_dir))

            self.pid_file = '{0}/nginx.pid'.format(self.test_dir)
            self.log_file = '{0}/error.log'.format(self.test_dir)

            for (name, data) in files:
                self.writeFile(name, data)

            self.pid = os.fork()

            if self.pid == 0:
                gl = '''pid {0};
                        error_log {1} debug;
                        working_directory {2};
                     '''.format(self.pid_file,
                                self.log_file,
                                self.test_dir)

                if 'TEST_NGINX_CATLOG' in os.environ:
                    gl += 'error_log stderr debug;'

                args = [ self.nginx_bin, '-p', '{0}/'.format(self.test_dir),
                                         '-c', 'nginx.conf',
                                         '-g', gl ]

                os.execv(self.nginx_bin, args)

            while not os.path.exists(self.pid_file):
                if os.waitpid(self.pid, os.WNOHANG)[0] == self.pid:
                    raise Exception('failed to start nginx')
                time.sleep(0.1)

        except:
            self.close()
            raise

    def writeFile(self, name, data):
        path = '{0}/{1}'.format(self.test_dir, name)

        file = open(path, 'w')
        file.write(data);
        file.close()

    def close(self):
        if self.pid:
            os.kill(self.pid, signal.SIGTERM)
            os.waitpid(self.pid, 0)

        if 'TEST_NGINX_LEAVE' not in os.environ:
            shutil.rmtree(self.test_dir)


class BaseTestCase(unittest.TestCase):

    # 'zzz' is needed to make this test last
    def test_zzz_alert(self):
        log = open(self.__class__.ngx.log_file)
        s = ''
        for line in log:
            m = line.find(' [alert] ')
            if m != -1:
                s = line
                break
        self.assertEqual(s, '')


class HTTPTestCase(BaseTestCase):

    def http(self, uri='/', method='GET', body=None, headers={}, port=8080):
        c = httplib.HTTPConnection('127.0.0.1', port)
        c.request(method, uri, body, headers)
        return c.getresponse()


class StreamTestCase(BaseTestCase):

    def stream(self, msg='', port=8080, udp=0):
        s = socket.socket(socket.AF_INET,
                          socket.SOCK_STREAM if udp == 0 else socket.SOCK_DGRAM)
        s.connect(('127.0.0.1', port))
        s.send(msg)
        return s
