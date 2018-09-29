#!/usr/bin/python

#
# LICENSE: MIT
#
# Copyright (C) 2017 Marco Matarazzo
#
# Based on check_redis.py from Samuel Stauffer
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

import socket
import sys
from optparse import OptionParser

EXIT_OK = 0
EXIT_WARN = 1
EXIT_CRITICAL = 2
EXIT_INVALID_AUTH = 3

def get_info(host, port, timeout, auth):
    socket.setdefaulttimeout(timeout or None)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    if auth is not None:
        s.send("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n" % (len(auth), auth))
        result = s.recv(100)
        if 'OK' not in result:
            print "ERROR: Invalid authentication"
            sys.exit(EXIT_INVALID_AUTH)

    s.send("*1\r\n$4\r\ninfo\r\n")
    buf = ""
    while '\r\n\r\n' not in buf:
        buf += s.recv(8192)
    s.close()
    return dict(x.split(':', 1) for x in buf.split('\r\n') if ':' in x)


def build_parser():
    parser = OptionParser()
    parser.add_option("-s", "--server", dest="server", help="Redis server to connect to.", default="127.0.0.1")
    parser.add_option("-p", "--port", dest="port", help="Redis port to connect to.", type="int", default=6379)
    parser.add_option("-a", "--auth", dest="auth", help="Authentication string", default=None)
    parser.add_option("-k", "--key", dest="key_value", help="Stat to monitor (memory_mb, hit_ratio, or custom)", default="memory_mb")
    parser.add_option("-w", "--warn", dest="warn_value", help="Warning threshold.", type="int")
    parser.add_option("-c", "--critical", dest="crit_value", help="Critical threshold.", type="int")
    parser.add_option("-t", "--timeout", dest="timeout", help="Milliseconds to wait before timing out", type="int", default=2000)
    return parser


def main():
    parser = build_parser()
    options, _args = parser.parse_args()
    if not options.warn_value:
        parser.error("Warning level required")
    if not options.crit_value:
        parser.error("Critical level required")

    try:
        info = get_info(options.server, int(options.port), options.timeout / 1000.0, options.auth)
    except socket.error:
        print ("CRITICAL: Error connecting to redis %s:%s: %s" % (options.server, options.port, exc))
        sys.exit(EXIT_CRITICAL)
    except exc:
        print ("CRITICAL: Error getting INFO from redis %s:%s: %s" % (options.server, options.port, exc))
        sys.exit(EXIT_CRITICAL)

    reverse_check = False
    if options.key_value == 'memory_mb':
        info_value = int(info.get("used_memory_rss") or info["used_memory"]) / (1024*1024)
    elif options.key_value == 'hit_ratio':
        reverse_check = True
        hit = int(info.get("keyspace_hits"))
        miss = int(info.get("keyspace_misses"))
        info_value = int(100*hit)/(hit+miss)
    else:
        info_value = int(info.get(options.key_value))

    exit_string = "OK"
    if reverse_check:
        if info_value < options.crit_value:
            exit_string = "CRITICAL"
        elif info_value < options.warn_value:
            exit_string = "WARNING"
    else:
        if info_value > options.crit_value:
            exit_string = "CRITICAL"
        elif info_value > options.warn_value:
            exit_string = "WARNING"

    status = "%s: Redis %s is %d" % (exit_string, options.key_value, info_value)
    perfdata = "%s=%d;%d;%d;%d;%d" % (options.key_value, info_value, options.warn_value, options.crit_value, 0, info_value)

    print status, "||", perfdata

    if exit_string == "OK":
        sys.exit(EXIT_OK)
    if exit_string == "WARNING":
        sys.exit(EXIT_WARNING)
    else:
        sys.exit(EXIT_CRITICAL)

if __name__ == "__main__":
    main()