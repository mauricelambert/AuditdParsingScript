#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This script parses auditd logs to found suspicious execution by statistics
#    Copyright (C) 2025  AuditdParsingScript

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

from base64 import b16decode
from collections import Counter
from time import gmtime, strftime

executables = Counter()

for line in open("audit.log.4", "rb"):
    if b" exe=" in line:
        audit_start, data = line.split(b"):")
        time = strftime("%Y-%m-%d %H:%M:%S", gmtime(float(audit_start.split(b"(")[1].split(b":")[0].decode())))
        data = data.split(b' exe=')[1].split()[0]
        if data.startswith(b'"') or data.startswith(b"'"):
            exe = data[1:-1].decode()
        else:
            exe = b16decode(data.upper()).decode()
        print(time, exe)
        executables[exe] += 1

print(executables.most_common())

# [('/usr/bin/sudo', 17597), ('/usr/sbin/sshd', 11135), ('/usr/sbin/crond', 1746), ('/usr/sbin/xtables-multi', 98), ('/usr/lib/systemd/systemd', 8), ('/usr/bin/su', 6), ('/usr/bin/rpm', 2)]
# [('/usr/bin/sudo', 17483), ('/usr/sbin/sshd', 11185), ('/usr/sbin/crond', 1710), ('/usr/sbin/xtables-multi', 127), ('/usr/bin/python2.7', 28), ('/usr/bin/crontab', 12), ('/usr/sbin/ebtables-restore', 12), ('/usr/lib/systemd/systemd', 4), ('/usr/sbin/groupadd', 2), ('/usr/bin/dockerd', 2), ('/', 1)]
