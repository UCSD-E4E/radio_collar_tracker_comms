#!/usr/bin/env python3
###############################################################################
#     Radio Collar Tracker Ground Control Software
#     Copyright (C) 2020  Nathan Hui
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################
#
# DATE      WHO Description
# -----------------------------------------------------------------------------
# 03/26/22  HG  Changed GCS to server and drone to client
# 07/29/20  NH  Added isOpen to mavComms
# 07/23/20  NH  Initial docstrings
# 05/23/20  NH  Moved heartbeat watchdog timeout to parameter
# 05/21/20  NH  Refactored options information into own class
# 05/20/20  NH  Fixed SYS_autostart type in SETOPT command, added exception
#                 logging to both receivers
# 05/18/20  NH  Implemented binary data protocol, moved droneComms to rctComms,
#                 added callback functionality
# 04/26/20  NH  Added catch for JSON Decoder errors
# 04/25/20  NH  Moved Commands and PacketTypes to rctTransport
# 04/20/20  NH  Updated docstrings and imports
# 04/19/20  NH  Switched to RCT Transport for comms
# 04/16/20  NH  Moved Commands and Events to module scope, added helper for
#               sending commands, cleaned up eventing mechanisms
# 04/14/20  NH  Initial commit, fixed start parameters, added support for
#               multiline packet
#
###############################################################################
from __future__ import annotations

import binascii
import datetime as dt
import enum
import json
import logging
import struct
import threading
import time
import traceback
from typing import Any, Callable, Dict, List, Optional, Type

from deprecated import deprecated

import RCTComms.transport
from RCTComms.options import (BASE_OPTIONS, ENG_OPTIONS, EXP_OPTIONS, Options,
                              base_options_keywords,
                              engineering_options_keywords,
                              expert_options_keywords, option_param_table)


class PACKET_CLASS(enum.Enum):
    '''
    Valid Packet Classes
    '''
    STATUS = 0x01
    CONFIGURATION = 0x02
    UPGRADE = 0x03
    DATA = 0x04
    COMMAND = 0x05


class STATUS_ID(enum.Enum):
    '''
    Status Packet IDs
    '''
    HEARTBEAT = 0x01
    EXCEPTION = 0x02


class CONFIG_ID(enum.Enum):
    '''
    Configuration Packet IDs
    '''
    FREQUENCIES = 0x01
    OPTIONS = 0x01


class UPGRADE_ID(enum.Enum):
    '''
    Upgrade Packet IDs
    '''
    STATUS = 0x01


class DATA_ID(enum.Enum):
    '''
    Data Packet IDs
    '''
    PING = 0x01
    VEHICLE = 0x02


class COMMAND_ID(enum.Enum):
    '''
    Command Packet IDs
    '''
    ACK = 0x01
    GETF = 0x02
    SETF = 0x03
    GETOPT = 0x04
    SETOPT = 0x05
    START = 0x07
    STOP = 0x09
    UPGRADE = 0x0B


class rctBinaryPacket:
    def __init__(self, payload: bytes, packetClass: int, packetID: int) -> None:
        self._payload = payload
        self._pclass = packetClass
        self._pid = packetID

    def to_bytes(self) -> bytes:
        payloadLen = len(self._payload)
        header = struct.pack('<BBBBH', 0xE4, 0xEb,
                             self._pclass, self._pid, payloadLen)
        msg = header + self._payload
        cksum = binascii.crc_hqx(msg, 0xFFFF).to_bytes(2, 'big')
        return msg + cksum

    def getClassIDCode(self) -> int:
        return self._pclass << 8 | self._pid

    def __str__(self) -> str:
        string = self.to_bytes().hex().upper()
        length = 4
        return '0x%s' % ' '.join(string[i:i + length] for i in range(0, len(string), length))

    def __repr__(self) -> str:
        string = self.to_bytes().hex().upper()
        length = 4
        return '0x%s' % ' '.join(string[i:i + length] for i in range(0, len(string), length))

    def __eq__(self, packet) -> bool:
        if not isinstance(packet, rctBinaryPacket):
            return False
        return self.to_bytes() == packet.to_bytes()

    @classmethod
    def from_bytes(cls, packet: bytes) -> rctBinaryPacket:
        if binascii.crc_hqx(packet, 0xFFFF) != 0:
            raise RuntimeError("Checksum verification failed")
        if len(packet) < 8:
            raise RuntimeError("Packet too short!")
        s1, s2, pcls, pid, _ = struct.unpack("<BBBBH", packet[0:6])
        if s1 != 0xE4 or s2 != 0xEB:
            raise RuntimeError("Not a packet!")
        payload = packet[6:-2]
        return rctBinaryPacket(payload, pcls, pid)

    @classmethod
    def matches(cls, packetClass: int, packetID: int) -> bool:
        return True


class rctPingPacket(rctBinaryPacket):
    def __init__(self, lat: float, lon: float, alt: float, txp: float, txf: int, timestamp: dt.datetime = None):
        self.lat = lat
        self.lon = lon
        self.alt = alt
        self.txp = txp
        self.txf = txf
        if timestamp is None:
            timestamp = dt.datetime.now()
        self.timestamp = timestamp

        self._pclass = 0x04
        self._pid = 0x01
        self._payload = struct.pack("<BQllHfL", 0x01, int(timestamp.timestamp(
        ) * 1e3), int(lat * 1e7), int(lon * 1e7), int(alt * 10), txp, txf)

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x04 and packetID == 0x01

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:-2]
        _, _, pcls, pid, _ = struct.unpack("<BBBBH", header)
        if not cls.matches(pcls, pid):
            raise RuntimeError("Incorrect packet type")
        _, timeMS, lat7, lon7, alt1, txp, txf = struct.unpack(
            '<BQllHfL', payload)
        timestamp = dt.datetime.fromtimestamp(timeMS / 1e3)
        lat = lat7 / 1e7
        lon = lon7 / 1e7
        alt = alt1 / 10
        return rctPingPacket(lat, lon, alt, txp, txf, timestamp)


class rctHeartBeatPacket(rctBinaryPacket):

    class SDR_STATES(enum.Enum):
        find_devices = 0
        wait_recycle = 1
        usrp_probe = 2
        rdy = 3
        fail = 4

    class EXT_SENSOR_STATES(enum.Enum):
        get_tty = 0
        get_msg = 1
        wait_recycle = 2
        rdy = 3
        fail = 4

    class STORAGE_STATES(enum.Enum):
        get_output_dir = 0
        check_output_dir = 1
        check_space = 2
        wait_recycle = 3
        rdy = 4
        fail = 5

    class SYS_STATES(enum.Enum):
        init = 0
        wait_init = 1
        wait_start = 2
        start = 3
        wait_end = 4
        finish = 5
        fail = 6

    class SW_STATES(enum.Enum):
        stop = 0
        start = 1

    def __init__(self, systemState: int,
                 sdrState: int,
                 sensorState: int,
                 storageState: int,
                 switchState: int,
                 timestamp: dt.datetime=None):
        self.systemState = systemState
        self.sdrState = sdrState
        self.sensorState = sensorState
        self.storageState = storageState
        self.switchState = switchState
        if timestamp is None:
            timestamp = dt.datetime.now()
        self.timestamp = timestamp
        self._pclass = 0x01
        self._pid = 0x01
        self._payload = struct.pack('<BBBBBBQ', 0x01, systemState,
                                    sdrState, sensorState,
                                    storageState, switchState,
                                    int(timestamp.timestamp() * 1e3))

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        if packetClass == 0x01 and packetID == 0x01:
            return True
        else:
            return False

    @classmethod
    def from_bytes(cls, packet: bytes):
        if binascii.crc_hqx(packet, 0xFFFF) != 0:
            raise RuntimeError("Checksum verification failed")
        if len(packet) < 8:
            raise RuntimeError("Packet too short!")
        s1, s2, pcls, pid, _ = struct.unpack("<BBBBH", packet[0:6])
        if s1 != 0xE4 or s2 != 0xEB:
            raise RuntimeError("Not a packet!")
        if not cls.matches(pcls, pid):
            raise RuntimeError("Incorrect packet type")
        _, systemState, sdrState, sensorState, storageState, switchState, timeMS = struct.unpack(
            '<BBBBBBQ', packet[6:-2])
        timestamp = dt.datetime.fromtimestamp(timeMS / 1e3)
        return rctHeartBeatPacket(systemState, sdrState, sensorState, storageState, switchState, timestamp)


class rctExceptionPacket(rctBinaryPacket):
    def __init__(self, e: str, tb: str):
        self._pclass = 0x01
        self._pid = 0x02
        self._payload = struct.pack('<BHH', 0x01, len(e), len(
            tb)) + e.encode('ascii') + tb.encode('ascii')
        self.exception = e
        self.traceback = tb

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x01 and packetID == 0x02

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:-2]
        _, _, pcls, pid, _ = struct.unpack("<BBBBH", header)
        if not cls.matches(pcls, pid):
            raise RuntimeError("Incorrect packet type")
        _, eLen, tbLen = struct.unpack('<BHH', payload[0x0000:0x0005])
        eStr = payload[0x0005:0x0005 + eLen].decode()
        tbStr = payload[0x0005 + eLen: 0x0005 + eLen + tbLen].decode()
        return rctExceptionPacket(eStr, tbStr)


class rctFrequenciesPacket(rctBinaryPacket):
    def __init__(self, frequencies: list):
        self._pclass = 0x02
        self._pid = 0x01
        self.frequencies = frequencies
        self._payload = struct.pack('<BB%dL' % len(
            frequencies), 0x01, len(frequencies), *tuple(frequencies))

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x02 and packetID == 0x01

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:-2]
        _, _, pcls, pid, _ = struct.unpack("<BBBBH", header)
        if not cls.matches(pcls, pid):
            raise RuntimeError("Incorrect packet type")
        _, nFreqs = struct.unpack('<BB', payload[0x0000:0x0002])
        freqs = struct.unpack(
            '<%dL' % nFreqs, payload[0x0002:0x0002 + 4 * nFreqs])
        return rctFrequenciesPacket(list(freqs))


class rctOptionsPacket(rctBinaryPacket):

    def __init__(self, scope: int, kwargs: Dict[Options: Any]):
        self.__log = logging.getLogger('rctOptionsPacket')
        if scope == BASE_OPTIONS:
            accepted_kw = base_options_keywords
        elif scope == EXP_OPTIONS:
            accepted_kw = base_options_keywords + \
                expert_options_keywords
        elif scope == ENG_OPTIONS:
            accepted_kw = base_options_keywords + \
                expert_options_keywords + engineering_options_keywords
        else:
            raise RuntimeError('Unrecognized scope')

        pclass = 0x02
        pid = 0x02
        payload = struct.pack('<BB', 0x01, scope)
        self.options: Dict[Options, Any] = {}
        self.scope = scope
        for keyword in accepted_kw:
            option_param = option_param_table[keyword]

            if not isinstance(kwargs[keyword], option_param.type_list):
                msg = (f'kw {keyword} expected type {option_param.type_list}, found '
                    f'{type(kwargs[keyword])}')
                raise TypeError(msg)

            self.options[keyword] = kwargs[keyword]
            try:
                if option_param.format_str != 's':
                    payload += struct.pack(option_param.format_str,
                                                kwargs[keyword])
                else:
                    payload += struct.pack('<H', len(kwargs[keyword]))
                    payload += kwargs[keyword].encode('ascii')
            except struct.error as exc:
                self.__log.exception('Failed to pack for kw %s, format %s, value %s', keyword,
                                     option_param.format_str, kwargs[keyword])
                raise exc
        super().__init__(payload=payload, packetClass=pclass, packetID=pid)

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x02 and packetID == 0x02

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:-2]
        _, _, pcls, pid, _ = struct.unpack("<BBBBH", header)
        if not cls.matches(pcls, pid):
            raise RuntimeError("Incorrect packet type")
        _, scope = struct.unpack('<BB', payload[0x0000:0x0002])
        idx = 0x0002
        options = {}
        if scope >= BASE_OPTIONS:
            for keyword in base_options_keywords:
                option_params = option_param_table[keyword]
                options[keyword], idx = option_params.unpack_from(
                    buffer=payload,
                    offset=idx
                )
        if scope >= EXP_OPTIONS:
            for keyword in expert_options_keywords:
                option_params = option_param_table[keyword]
                options[keyword], idx = option_params.unpack_from(
                    buffer=payload,
                    offset=idx
                )
        if scope >= ENG_OPTIONS:
            for keyword in engineering_options_keywords:
                option_params = option_param_table[keyword]
                options[keyword], idx = option_params.unpack_from(
                    buffer=payload,
                    offset=idx
                )
        return rctOptionsPacket(scope, options)


class rctUpgradeStatusPacket(rctBinaryPacket):
    UPGRADE_READY = 0x00
    UPGRADE_PROGRESS = 0x01
    UPGRADE_COMPLETE = 0xFE
    UPGRADE_FAILED = 0xFF

    def __init__(self, state: int, msg: str):
        self._pclass = 0x03
        self._pid = 0x01
        self._payload = struct.pack(
            '<BBH', 0x01, state, len(msg)) + msg.encode('ascii')
        self.state = state
        self.msg = msg

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x03 and packetID == 0x01

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:-2]
        _, _, pcls, pid, _ = struct.unpack("<BBBBH", header)
        if not cls.matches(pcls, pid):
            raise RuntimeError("Incorrect packet type")
        _, state, strlen = struct.unpack('<BBH', payload[0x0000: 0x0004])
        msg = payload[0x0004:0x0004 + strlen].decode()
        return rctUpgradeStatusPacket(state, msg)

class rctUpgradePacket(rctBinaryPacket):

    def __init__(self, numPacket, numTotal, fileBytes):
        self._pclass = 0x03
        self._pid = 0x02
        self.numPacket = numPacket
        self.numTotal = numTotal
        self.fileBytes = fileBytes
        self._payload = struct.pack('<BHHH', 0x01, numPacket, numTotal, len(fileBytes)) + fileBytes

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x03 and packetID == 0x02

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:-2]
        _, _, pcls, pid, _ = struct.unpack("<BBBBH", header)
        if not cls.matches(pcls, pid):
            raise RuntimeError("Incorrect packet type")
        #TODO: fix decoding
        _, numPacket, numTotal, bytesLen = struct.unpack('<BHHH', payload[0x0000: 0x0007])
        fileBytes = payload[0x0007:0x0007 + bytesLen]
        return rctUpgradePacket(numPacket, numTotal, fileBytes)


class rctConePacket(rctBinaryPacket):
    def __init__(self, lat: float, lon: float, alt: float, power: float, angle: float, timestamp: dt.datetime = None):
        self.lat = lat
        self.lon = lon
        self.alt = alt
        self.power = power
        self.angle = angle
        if timestamp is None:
            timestamp = dt.datetime.now()
        self.timestamp = timestamp

        self._pclass = 0x04
        self._pid = 0x04
        self._payload = struct.pack("<BQllHff", 0x01, int(timestamp.timestamp(
        ) * 1e3), int(lat * 1e7), int(lon * 1e7), int(alt * 10), power, angle)


    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x04 and packetID == 0x04

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:-2]
        _, _, pcls, pid, _ = struct.unpack("<BBBBH", header)
        if not cls.matches(pcls, pid):
            raise RuntimeError("Incorrect packet type")
        _, timeMS, lat7, lon7, alt1, power, angle = struct.unpack(
            '<BQllHff', payload)
        timestamp = dt.datetime.fromtimestamp(timeMS / 1e3)
        lat = lat7 / 1e7
        lon = lon7 / 1e7
        alt = alt1 / 10
        return rctConePacket(lat, lon, alt, power, angle, timestamp)

class rctVehiclePacket(rctBinaryPacket):
    def __init__(self, lat: float, lon: float, alt: float, hdg: int, timestamp: dt.datetime = None):
        self.lat = lat
        self.lon = lon
        self.alt = alt
        self.hdg = hdg
        if timestamp is None:
            timestamp = dt.datetime.now()
        self.timestamp = timestamp

        self._pclass = 0x04
        self._pid = 0x02
        self._payload = struct.pack("<BQllHH", 0x01, int(timestamp.timestamp(
        ) * 1e3), int(lat * 1e7), int(lon * 1e7), int(alt * 10), hdg)

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x04 and packetID == 0x02

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:-2]
        _, _, pcls, pid, _ = struct.unpack("<BBBBH", header)
        if not cls.matches(pcls, pid):
            raise RuntimeError("Incorrect packet type")
        _, timeMS, lat7, lon7, alt1, hdg = struct.unpack(
            '<BQllHH', payload)
        timestamp = dt.datetime.fromtimestamp(timeMS / 1e3)
        lat = lat7 / 1e7
        lon = lon7 / 1e7
        alt = alt1 / 10
        return rctVehiclePacket(lat, lon, alt, hdg, timestamp)


class rctACKCommand(rctBinaryPacket):
    def __init__(self, commandID: int, ack: bool, timestamp: dt.datetime = None):
        self.commandID = commandID
        self.ack = ack
        if timestamp is None:
            timestamp = dt.datetime.now()
        self.timestamp = timestamp
        self._pclass = 0x05
        self._pid = 0x01
        self._payload = struct.pack(
            '<BB?Q', 0x01, commandID, ack, int(timestamp.timestamp() * 1e3))

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x05 and packetID == 0x01

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:-2]
        _, _, pcls, pid, _ = struct.unpack("<BBBBH", header)
        if not cls.matches(pcls, pid):
            raise RuntimeError("Incorrect packet type")
        _, commandID, ack, timeMS = struct.unpack('<BB?Q', payload)
        timestamp = dt.datetime.fromtimestamp(timeMS / 1e3)
        return rctACKCommand(commandID, ack, timestamp)


class rctGETFCommand(rctBinaryPacket):
    def __init__(self):
        self._pclass = 0x05
        self._pid = 0x02
        self._payload = b'\x01'

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x05 and packetID == 0x02

    @classmethod
    def from_bytes(cls, packet: bytes):
        return rctGETFCommand()


class rctSETFCommand(rctBinaryPacket):
    def __init__(self, frequencies: list):
        self._pclass = 0x05
        self._pid = 0x03
        self.frequencies = frequencies
        self._payload = struct.pack('<BB%dL' % len(
            frequencies), 0x01, len(frequencies), *tuple(frequencies))

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x05 and packetID == 0x03

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:-2]
        _, _, pcls, pid, _ = struct.unpack("<BBBBH", header)
        if not cls.matches(pcls, pid):
            raise RuntimeError("Incorrect packet type")
        _, nFreqs = struct.unpack('<BB', payload[0x0000:0x0002])
        freqs = struct.unpack(
            '<%dL' % nFreqs, payload[0x0002:0x0002 + 4 * nFreqs])
        return rctSETFCommand(list(freqs))


class rctGETOPTCommand(rctBinaryPacket):

    def __init__(self, scope: int):
        self._pclass = 0x05
        self._pid = 0x04
        self._payload = struct.pack('<BB', 0x01, scope)
        self.scope = scope

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x05 and packetID == 0x04

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:-2]
        _, _, pcls, pid, _ = struct.unpack("<BBBBH", header)
        if not cls.matches(pcls, pid):
            raise RuntimeError("Incorrect packet type")
        _, scope = struct.unpack('<BB', payload[0x0000:0x0002])
        return rctGETOPTCommand(scope)


class rctSETOPTCommand(rctBinaryPacket):

    def __init__(self, scope: int, kwargs: Dict[Options, Any]):
        accepted_kw: List[str] = []
        if scope >= BASE_OPTIONS:
            accepted_kw = base_options_keywords
        if scope >= EXP_OPTIONS:
            accepted_kw = base_options_keywords + \
                expert_options_keywords
        if scope >= ENG_OPTIONS:
            accepted_kw = base_options_keywords + \
                expert_options_keywords + engineering_options_keywords
        if accepted_kw == []:
            raise RuntimeError("Invalid scope")

        pclass = 0x05
        pid = 0x05
        payload = struct.pack('<BB', 0x01, scope)
        self.options: Dict[Options, Any] = {}
        self.scope = scope
        for keyword in accepted_kw:
            option_param = option_param_table[keyword]
            payload += option_param.pack(kwargs[keyword])
            self.options[keyword] = kwargs[keyword]
        super().__init__(payload=payload, packetClass=pclass, packetID=pid)

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x05 and packetID == 0x05

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:-2]
        _, _, pcls, pid, _ = struct.unpack("<BBBBH", header)
        if not cls.matches(pcls, pid):
            raise RuntimeError("Incorrect packet type")
        _, scope = struct.unpack('<BB', payload[0x0000:0x0002])
        idx = 0x0002
        options = {}
        if scope >= BASE_OPTIONS:
            for keyword in base_options_keywords:
                option_param = option_param_table[keyword]
                options[keyword], idx = option_param.unpack_from(payload, idx)
        if scope >= EXP_OPTIONS:
            for keyword in expert_options_keywords:
                option_param = option_param_table[keyword]
                options[keyword], idx = option_param.unpack_from(payload, idx)
        if scope >= ENG_OPTIONS:
            for keyword in engineering_options_keywords:
                option_param = option_param_table[keyword]
                options[keyword], idx = option_param.unpack_from(payload, idx)
        return rctSETOPTCommand(scope, options)


class rctSTARTCommand(rctBinaryPacket):
    def __init__(self):
        self._pclass = 0x05
        self._pid = 0x07
        self._payload = b'\x01'

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x05 and packetID == 0x07

    @classmethod
    def from_bytes(cls, packet: bytes):
        return rctSTARTCommand()


class rctSTOPCommand(rctBinaryPacket):
    def __init__(self):
        self._pclass = 0x05
        self._pid = 0x09
        self._payload = b'\x01'

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x05 and packetID == 0x09

    @classmethod
    def from_bytes(cls, packet: bytes):
        return rctSTOPCommand()


class rctUPGRADECommand(rctBinaryPacket):
    def __init__(self):
        self._pclass = 0x05
        self._pid = 0x0B
        self._payload = b'\x01'

    @classmethod
    def matches(cls, packetClass: int, packetID: int):
        return packetClass == 0x05 and packetID == 0x0B

    @classmethod
    def from_bytes(cls, packet: bytes):
        return rctUPGRADECommand()

class RctEngrCommand(rctBinaryPacket):
    """Engineering command packet

    """
    def __init__(self, command_word: str, args: Dict[str, Any]) -> None:
        self.command_word = command_word
        self.args = args
        payload_bytes = json.dumps({command_word:args}).encode(encoding='ascii')
        super().__init__(payload=payload_bytes, packetClass=0x06, packetID=0x00)

    @classmethod
    def matches(cls, packetClass: int, packetID: int) -> bool:
        return packetClass == 0x06 and packetID == 0x00

    @classmethod
    def from_bytes(cls, packet: bytes) -> rctBinaryPacket:
        header = packet[0:6]
        payload_bytes = packet[6:-2]
        _, _, pcls, pid, _ = struct.unpack('<BBBBH', header)
        if not cls.matches(pcls, pid):
            raise RuntimeError('Incorrect packet type')
        payload: Dict[str, Dict[str, Any]] = json.loads(payload_bytes.decode(encoding='ascii'))
        assert len(payload.keys()) == 1
        cmd_word = list(payload.keys())[0]
        return RctEngrCommand(command_word=cmd_word, args=payload[cmd_word])

class EVENTS(enum.Enum):
    STATUS_HEARTBEAT = 0x0101
    STATUS_EXCEPTION = 0x0102
    CONFIG_FREQUENCIES = 0x0201
    CONFIG_OPTIONS = 0x0202
    UPGRADE_STATUS = 0x0301
    UPGRADE_DATA = 0x0302
    DATA_PING = 0x0401
    DATA_VEHICLE = 0x0402
    DATA_CONE = 0x0404
    COMMAND_ACK = 0x0501
    COMMAND_GETF = 0x0502
    COMMAND_SETF = 0x0503
    COMMAND_GETOPT = 0x0504
    COMMAND_SETOPT = 0x0505
    COMMAND_START = 0x0507
    COMMAND_STOP = 0x0509
    COMMAND_UPGRADE = 0x050B
    ENGR_CMD = 0x0600
    GENERAL_NO_HEARTBEAT = 0x10000
    GENERAL_EXCEPTION = 0x20000
    GENERAL_UNKNOWN = 0x30000

class ChecksumError(RuntimeError):
    """Checksum verification error
    """
    def __init__(self, packet: bytes, *args: object) -> None:
        self.packet = packet
        super().__init__(*args)

class rctBinaryPacketFactory:
    class State(enum.Enum):
        FIND_SYNC = 0
        HEADER = 1
        PAYLOAD = 2
        CKSUM = 3
        VALIDATE = 4

    packetMap: Dict[int, Type[rctBinaryPacket]] = {
        EVENTS.STATUS_HEARTBEAT.value: rctHeartBeatPacket,
        EVENTS.STATUS_EXCEPTION.value: rctExceptionPacket,
        EVENTS.CONFIG_FREQUENCIES.value: rctFrequenciesPacket,
        EVENTS.CONFIG_OPTIONS.value: rctOptionsPacket,
        EVENTS.UPGRADE_STATUS.value: rctUpgradeStatusPacket,
        EVENTS.UPGRADE_DATA.value: rctUpgradePacket,
        EVENTS.DATA_PING.value: rctPingPacket,
        EVENTS.DATA_CONE.value: rctConePacket,
        EVENTS.DATA_VEHICLE.value: rctVehiclePacket,
        EVENTS.COMMAND_ACK.value: rctACKCommand,
        EVENTS.COMMAND_GETF.value: rctGETFCommand,
        EVENTS.COMMAND_SETF.value: rctSETFCommand,
        EVENTS.COMMAND_GETOPT.value: rctGETOPTCommand,
        EVENTS.COMMAND_SETOPT.value: rctSETOPTCommand,
        EVENTS.COMMAND_START.value: rctSTARTCommand,
        EVENTS.COMMAND_STOP.value: rctSTOPCommand,
        EVENTS.COMMAND_UPGRADE.value: rctUPGRADECommand,
        EVENTS.ENGR_CMD.value: RctEngrCommand,
    }

    def __init__(self):
        self.__state = self.State.FIND_SYNC
        self.__payloadLen = 0
        self.__log = logging.getLogger('Binary Packet Parser')

    def parseByte(self, data: int) -> Optional[rctBinaryPacket]:
        if self.__state == self.State.FIND_SYNC:
            if data == 0xE4:
                self.__state = self.State.HEADER
                self.__buffer = bytearray()
                self.__buffer.append(data)
            return None
        elif self.__state == self.State.HEADER:
            self.__buffer.append(data)
            if len(self.__buffer) == 0x0006:
                self.__state = self.State.PAYLOAD
                self.__payloadLen, = struct.unpack(
                    '<H', self.__buffer[0x0004:0x0006])
            return None
        elif self.__state == self.State.PAYLOAD:
            self.__buffer.append(data)
            if len(self.__buffer) == self.__payloadLen + 0x0006:
                self.__state = self.State.CKSUM
            return None
        elif self.__state == self.State.CKSUM:
            self.__buffer.append(data)
            self.__state = self.State.VALIDATE
            return None
        elif self.__state == self.State.VALIDATE:
            self.__buffer.append(data)
            if binascii.crc_hqx(self.__buffer, 0xFFFF) != 0:
                self.__log.error('Invalid checksum for buffer %s',
                                 self.__buffer.hex(' ', -2))
                self.__state = self.State.FIND_SYNC
                raise ChecksumError(self.__buffer)
            packetID, = struct.unpack('>H', self.__buffer[0x0002:0x0004])
            self.__state = self.State.FIND_SYNC
            if packetID not in self.packetMap:
                return rctBinaryPacket.from_bytes(self.__buffer)
            else:
                return self.packetMap[packetID].from_bytes(self.__buffer)
        else:
            raise RuntimeError("Unknown state")

    def parseBytes(self, data: bytes) -> List[rctBinaryPacket]:
        packets: List[rctBinaryPacket] = []
        for byte in data:
            try:
                retval = self.parseByte(byte)
            except ChecksumError:
                # At this point, we are going to simply drop the packet.
                continue
            if retval is not None:
                packets.append(retval)
        return packets




class gcsComms:
    '''
    Radio Collar Tracker UDP Interface
    '''
    __BUFFER_LEN = 1024
    __lock = threading.Lock()

    def __init__(self, port: RCTComms.transport.RCTAbstractTransport, disconnected: Optional[Callable[[], None]] = None, GC_HeartbeatWatchdogTime=30):
        '''
        Initializes the UDP interface on the specified port.  Also specifies a
        filename to use as a logfile, which defaults to no log.

        :param port: Port object
        :type port: rctTransport.RCTAbstractTransport
        :param originString: Origin string
        :type originString: str
        :param disconnected: callback to inform owner of a disconnected event
        :type disconnected: Callable[[], None]
        '''
        self.__log = logging.getLogger('rctGCS.gcsComms')
        self.sock = port
        self.__disconnected = disconnected

        self.__receiverThread: Optional[threading.Thread] = None
        self.__hb_thread = threading.Thread(target=self.heartbeat_monitor,
                                            name='Heartbeat Monitor',
                                            daemon=True)
        self.__log.info('RTC gcsComms created')
        self.HS_run = False
        self.__mavIP: Optional[str] = None
        self.__lastHeartbeat: Optional[dt.datetime] = None
        self.__packetMap: Dict[int, List[Callable]] = {
            evt.value: [] for evt in EVENTS
        }
        self.__packetMap[EVENTS.STATUS_HEARTBEAT.value] = [self.__processHeartbeat]

        self.GC_HeartbeatWatchdogTime: int = GC_HeartbeatWatchdogTime

        self.__parser = rctBinaryPacketFactory()

    def set_disconnect(self, cb_: Callable[[], None]):
        """Sets the disconnect behavior

        Args:
            cb_ (Callable[[], None]): Sets the disconnect behavior
        """
        self.__disconnected = cb_

    def __waitForHeartbeat(self, guiTick: Callable=None, timeout: int=None):
        '''
        Waits to receive a heartbeat packet.  Returns a tuple containing the
        MAV's IP address and port number as a single tuple, and the contents of
        the received heartbeat packet.
        :param guiTick:
        :type guiTick:
        :param timeout: Seconds to wait before timing out
        :type timeout: Integer
        '''
        if timeout is None:
            timeout = self.GC_HeartbeatWatchdogTime
        self.__log.debug('Waiting %d s for heartbeats', timeout)
        for _ in range(timeout):
            try:
                data, addr = self.sock.receive(1024, 1)
                if data is None:
                    self.__log.warning('Received None from transport, assuming disconnected')
                    self.__disconnected()
                    break
                packets = self.__parser.parseBytes(data)
                for packet in packets:
                    self.__log.info("Received %s", type(packet).__name__)
                    if isinstance(packet, rctHeartBeatPacket):
                        self.__lastHeartbeat = dt.datetime.now()
                        return addr, packets
            except TimeoutError:
                pass
            if guiTick is not None:
                guiTick()
        self.__log.error("Failed to receive any heartbeats")
        return (None, None)

    def __receiverLoop(self):
        '''
        Receiver thread
        '''
        self.__log.info('RCT gcsComms rxThread started')
        assert self.__lastHeartbeat is not None

        while self.HS_run:
            try:
                data, addr = self.sock.receive(self.__BUFFER_LEN, 1)
                if data:
                    self.__log.info("Received: %s", data.hex(' ', -2))
            except TimeoutError:
                continue
            if not data:
                self.__disconnected()
                break

            try:
                packets = self.__parser.parseBytes(data)
            except Exception as exc:
                self.__log.exception('Failed to parse packets: %s', exc)
                raise exc

            for packet in packets:
                self.__log.info('Received %s', type(packet).__name__)
                packet_code = packet.getClassIDCode()
                try:
                    for callback in self.__packetMap[packet_code]:
                        callback(packet=packet, addr=addr)
                except KeyError:
                    for callback in self.__packetMap[EVENTS.GENERAL_UNKNOWN.value]:
                        callback(packet=packet, addr=addr)
                except Exception as exc:
                    self.__log.exception('Failed to handle packet')
                    for callback in self.__packetMap[EVENTS.GENERAL_EXCEPTION.value]:
                        callback(packet=packet, addr=addr)
                    raise exc


    def heartbeat_monitor(self):
        """Heartbeat Monitor thread
        """
        assert self.__lastHeartbeat is not None
        while self.HS_run:
            time.sleep(1)
            time_since_heartbeat = dt.datetime.now() - self.__lastHeartbeat
            if time_since_heartbeat.total_seconds() > self.GC_HeartbeatWatchdogTime:
                self.__log.warning("No heartbeats, last heartbeat at %s",
                                   self.__lastHeartbeat)
                for callback in self.__packetMap[EVENTS.GENERAL_NO_HEARTBEAT.value]:
                    callback(packet=None, addr=None)

    def start(self, gui: Callable=None):
        '''
        Starts the receiver.
        '''
        self.__log.info("RCT gcsComms starting...")
        self.sock.open()
        self.__mavIP, packets = self.__waitForHeartbeat(guiTick=gui)
        if self.__mavIP is None or packets is None:
            raise RuntimeError("Failed to receive heartbeats")
        for packet in packets:
            packetCode = packet.getClassIDCode()
            try:
                for callback in self.__packetMap[packetCode]:
                    callback(packet=packet, addr=self.__mavIP)
            except KeyError:
                for callback in self.__packetMap[EVENTS.GENERAL_UNKNOWN.value]:
                    callback(packet=packet, addr=self.__mavIP)
            except Exception:
                for callback in self.__packetMap[EVENTS.GENERAL_EXCEPTION.value]:
                    callback(packet=packet, addr=self.__mavIP)
        self.HS_run = True
        self.__receiverThread = threading.Thread(target=self.__receiverLoop, name='gcsComms rx')
        self.__receiverThread.start()
        self.__hb_thread.start()
        self.__log.info('RCT gcsComms started')

    def stop(self):
        '''
        Stops the receiver.
        '''
        self.__log.info("HS_run set to False")
        self.HS_run = False
        if self.__receiverThread is not None:
            self.__receiverThread.join(timeout=1)
        self.__hb_thread.join()
        self.__log.info('RCT gcsComms stopped')
        self.sock.close()

    def __processHeartbeat(self, packet: rctBinaryPacket, addr: str):
        '''
        Internal callback to handle recognizing loss of heartbeat
        '''
        self.__lastHeartbeat = dt.datetime.now()

    def registerCallback(self, event: EVENTS, callback: Callable) -> None:
        '''
        Registers a callback for the particular packet keyword
        :param event: Event to trigger on
        :type event: EVENTS
        :param callback: Callback function
        :type callback: function pointer.  The function shall accept two
                keyword parameters: packet (rctBinaryPacket) and addr (str).  The packet
                dictionary shall the the packet payload, and the addr shall be
                the address of the MAV
        '''
        callback = self.__synchronized_callback(callback)
        self.__packetMap[event.value].append(callback)

    def __synchronized_callback(self, callback):
        def lockAndCall(packet: rctBinaryPacket, addr: str):
            with gcsComms.__lock:
                callback(packet, addr)
        return lockAndCall

    def unregisterCallback(self, event: EVENTS, callback):
        self.__packetMap[event.value].remove(callback)

    def sendMessage(self, payload: bytes, packetClass: int, packetID: int):
        '''
        Sends the specified dictionary as a packet
        :param packet: Packet to send
        :type packet: dictionary
        '''
        assert isinstance(payload, bytes)
        payloadLen = len(payload)
        header = struct.pack('<BBBBH', 0xE4, 0xEb,
                             packetClass, packetID, payloadLen)
        msg = header + payload
        cksum = binascii.crc_hqx(msg, 0xFFFF).to_bytes(2, 'big')
        self.__log.info("Send: %s" % ((msg + cksum).hex()))
        self.sock.send(msg, self.__mavIP)

    def sendPacket(self, packet: rctBinaryPacket):
        '''
        Sends the specified packet object
        :param packet:
        :type packet:
        '''

        self.__log.info("Send: %s as %s", type(packet).__name__, packet)
        self.sock.send(packet.to_bytes(), self.__mavIP)


class mavComms:

    def __init__(self, port: RCTComms.transport.RCTAbstractTransport):
        self.__log = logging.getLogger('rctComms.mavComms')
        self.__port = port

        self.__rxThread = None
        self.__log.info('RCT mavComms created')
        self.HS_run = False
        self.gcsAddr: Optional[str] = None
        self.__packetMap: Dict[int, List[Callable]] = {
            evt.value: [] for evt in EVENTS
        }

        self.__parser = rctBinaryPacketFactory()

        self.port_open_event = threading.Event()

    def isOpen(self):
        return self.__port.isOpen()

    def start(self):
        self.__log.info('RCT mavComms starting...')
        self.HS_run = True
        self.__rxThread = threading.Thread(target=self.__receiver, name='mavComms_receiver', daemon=True)
        self.__rxThread.start()

    def stop(self):
        self.__log.info('HS_run set to False')
        self.HS_run = False
        if self.__rxThread is not None:
            self.__rxThread.join(timeout=1)
        self.__port.close()
        self.port_open_event.set()
        self.port_open_event.clear()
        self.__log.info('RCT mavComms stopped')

    def sendToGCS(self, packet: rctBinaryPacket):
        self.send_packet(packet, self.gcsAddr)

    def sendToAll(self, packet: rctBinaryPacket):
        self.send_packet(packet, None)

    @deprecated
    def sendPacket(self, packet: rctBinaryPacket, dest: Optional[str], timeout=5):
        return self.send_packet(packet=packet, dest=dest, timeout=timeout)

    def send_packet(self, packet: rctBinaryPacket, dest: Optional[str], timeout=5):
        """Sends the specified packet to the specified destination

        Args:
            packet (rctBinaryPacket): Packet to send
            dest (Optional[str]): Destination address
            timeout (int, optional): Timeout. Defaults to 5.

        Raises:
            exc: Failed to send
        """
        self.port_open_event.wait(timeout=5)
        self.__log.info('Send: %s as %s', type(packet).__name__, packet)
        now = dt.datetime.now()
        while True:
            try:
                self.__port.send(packet.to_bytes(), dest)
                return
            except Exception as exc:   # pylint: disable=broad-except
                # try until timeout
                self.__log.exception('Failed to send packet')
                self.__port.reconnect_on_fail(timeout=1)
                if (dt.datetime.now() - now).total_seconds() >= timeout:
                    raise exc

    def sendPing(self, ping: rctPingPacket):
        self.send_packet(ping, None)

    def sendCone(self, cone: rctConePacket):
        self.send_packet(cone, None)

    def sendVehicle(self, vehicle: rctVehiclePacket):
        self.send_packet(vehicle, None)

    def send_exception(self, exception: str, tb_: str):
        """Sends an exception message

        Args:
            exception (str): Exception message
            tb_ (str): Traceback info
        """
        packet = rctExceptionPacket(exception, tb_)
        try:
            self.sendToAll(packet)
        except Exception: # pylint: disable=broad-except
            # This is only called in an exception handler - it cannot be allowed
            # to raise another exception!
            self.__log.exception('Failed to send exception!')

    def __receiver(self):
        if not self.__port.isOpen():
            self.__port.open()
        self.port_open_event.set()
        while self.HS_run is True:
            try:
                data, addr = self.__port.receive(1024, 1)
                self.__log.info('Received: %s', data.hex(' ', -2))
            except TimeoutError:
                continue
            except Exception as exc:
                self.send_exception(str(exc), traceback.format_exc())
                self.__log.exception('Failed to receive packet: %s', exc)
                self.__port.reconnect_on_fail()
                continue

            try:
                packets = self.__parser.parseBytes(data)
            except Exception as exc:
                self.__log.exception('Failed to parse packets: %s', exc)
                self.send_exception(str(exc), tb_=traceback.format_exc())
                continue

            try:
                for packet in packets:
                    self.__log.info('Received %s', type(packet).__name__)
                    packet_code = packet.getClassIDCode()
                    self.__log.debug('Looking for 0x%04x', packet_code)
                    try:
                        self.execute_cb(packet_code, {
                            'packet': packet,
                            'addr': addr
                        })
                    except KeyError:
                        self.execute_cb(EVENTS.GENERAL_UNKNOWN.value, {
                            'packet': packet,
                            'addr': addr
                        })
            except Exception as exc:
                self.send_exception(str(exc), tb_=traceback.format_exc())
                self.__log.exception('Failed to handle packets: %s', exc)

    def execute_cb(self, event_value: int, kwargs):
        cb_fns = self.__packetMap[event_value]
        if len(cb_fns) == 0:
            self.__log.info('Empty callback list for %s', EVENTS(event_value))
        for cb_ in cb_fns:
            self.__log.debug('Executing %s', cb_.__name__)
            try:
                cb_(**kwargs)
            except Exception as exc:
                self.__log.exception('Exception during callback')
                raise exc

    @deprecated
    def registerCallback(self, event: EVENTS, callback: Callable):
        self.register_callback(event=event, callback=callback)

    def register_callback(self, event: EVENTS, callback: Callable):
        """Registers the specified callback

        Args:
            event (EVENTS): Event to register with
            callback (Callable): Callback function
        """
        self.__log.info('Registering %s to %s', callback.__name__, event.name)
        self.__packetMap[event.value].append(callback)
