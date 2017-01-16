
#
# Copyright (C) Roman Arutyunyan
#

import unittest
import sys
import os


dir_path = os.path.dirname(os.path.realpath(__file__))

sys.argv.insert(1, 'discover')
sys.argv.insert(2, dir_path)

unittest.main(argv=sys.argv)
