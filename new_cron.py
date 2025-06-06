#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This script parses cron logs (not auditd) to list all new process from a specific date
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

from sys import argv, executable, exit, stderr
from datetime import datetime

if len(argv) != 2:
    print('USAGES:', executable, argv[0], '[datetime:2025-06-04 20:33:44]')
    exit(1)

current_year = datetime.now().year
start = datetime.strptime(argv[1], "%Y-%m-%d %H:%M:%S")
logs = set()

with open('cron.logs', 'r') as file:
    for line in file:
        date = ' '.join(line.split()[:3])
        full_date_str = f"{current_year} {date}"
        date = datetime.strptime(full_date_str, "%Y %b %d %H:%M:%S")
        if date < start:
            logs.add(line.split(maxsplit=5)[5])
        elif date >= start and line.split(maxsplit=5)[5] not in logs:
            print(line.strip())