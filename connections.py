#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This script parses SOCKADDR auditd logs (saddr field as IP, port and protocol)
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

from enum import Enum
from base64 import b16decode
from ipaddress import ip_address
from time import gmtime, strftime

class SocketTypes(Enum):
    SOCK_STREAM = 1
    SOCK_DGRAM  = 2
    SOCK_RAW    = 3
    SOCK_RDM    = 4
    SOCK_SEQPACKET  = 5
    SOCK_DCCP   = 6
    SOCK_PACKET = 10

socket_types = {
    x.value: x.name for x in SocketTypes
}

for line in open("audit.log", "rb"):
    if line.startswith(b"type=SOCKADDR "):
        audit_start, data = line.split(b"):")
        time = strftime("%Y-%m-%d %H:%M:%S", gmtime(float(audit_start.split(b"(")[1].split(b":")[0].decode())))
        data = b16decode(data.strip()[6:])
        if len(data) != 16:
            print("Invalid length:", line)
        protocol = socket_types.get(data[0], "Unknown")
        port = int.from_bytes(data[2:4])
        ip = str(ip_address(int.from_bytes(data[4:8])))
        print(time, protocol, ip, port, line)