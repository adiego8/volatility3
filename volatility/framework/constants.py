"""Volatility 3 Constants

Stores all the constant values that are generally fixed throughout volatility
This includes default scanning block sizes, etc."""
import os.path

import sys

PLUGINS_PATH = [os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plugins"))]
BANG = "!"
PACKAGE_VERSION = "3.0.0_alpha1"

LOGLEVEL_V = 9
LOGLEVEL_VV = 8
LOGLEVEL_VVV = 7

if sys.platform == 'windows':
    CACHE_PATH = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "volatility3")
else:
    CACHE_PATH = os.path.join(os.path.expanduser("~"), ".cache", "volatility3")
os.makedirs(CACHE_PATH, exist_ok = True)
