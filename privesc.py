#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This script analyzes auditd logs to identify privileges escalation
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

from re import search
from typing import Tuple
from dataclasses import dataclass
from time import gmtime, strftime

@dataclass
class Process:
    id: int
    euid: int
    time: str
    comm: str
    exe: str

process_user = {}

def parse_line(line: bytes) -> Tuple[str, str, str]:
    audit_start, data = line.split(b"):")
    time = strftime("%Y-%m-%d %H:%M:%S", gmtime(float(audit_start.split(b"(")[1].split(b":")[0].decode())))
    
    comm = b""
    exe = b""
    for element in data.split():
        if element.startswith(b"comm="):
            comm = element[6:-1]
        elif element.startswith(b"exe="):
            exe = element[4:-1]
    
    return time, comm.decode(), exe.decode()

for line in open("audit.log", "rb"):
    match = search(rb"\spid=(?P<pid>\d+)\s.*\seuid=(?P<euid>\d+)\s", line)
    if match:
        if process_user.get(match["pid"]) is None:
            process_user[match["pid"]] = Process(int(match["pid"].decode()), int(match["euid"].decode()), *parse_line(line))
        elif process_user[match["pid"]].euid and process_user[match["pid"]].euid != int(match["euid"].decode()):
            process = process_user[match["pid"]]
            time, comm, exe = parse_line(line)
            pid = int(match["pid"].decode())
            euid = int(match["euid"].decode())
            print("Privesc:")
            print("\t- ", "Creation time: ", process.time, ", Process ID: ", process.id, ", Precedent EUID: ", process.euid, ", Comm: ", process.comm, ", Executable: ", process.exe, sep="")
            print("\t- ", "Privesc  time: ",         time, ", Process ID: ",        pid, ", Current   EUID: ",         euid, ", Comm: ",         comm, ", Executable: ",         exe, sep="")
            process_user[match["pid"]].euid = euid