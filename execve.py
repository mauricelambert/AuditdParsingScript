#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This script parses auditd logs to list all processes and arguments
#    Copyright (C) 2024  AuditdParsingScript

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

from time import gmtime, strftime

executables = set()

for line in open("audit.log", "rb"):
    if line.startswith(b"type=EXECVE "):
        audit_start, data = line.split(b"):")
        time = strftime("%Y-%m-%d %H:%M:%S", gmtime(float(audit_start.split(b"(")[1].split(b":")[0].decode())))
        data = data.split()
        if data[0].startswith(b'argc='):
            exe = data[1][4:-1].decode()
            print(time, exe, *[x[4:-1].decode() for x in data[2:]])
            executables.add(exe)