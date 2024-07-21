'''Packet Definitions
'''
from __future__ import annotations

import binascii
import datetime as dt
import enum
import json
import struct
from typing import Any, Dict, List, Sequence

from rctcomms.options import (BASE_OPTIONS, ENG_OPTIONS, EXP_OPTIONS, Options,
                              base_options_keywords,
                              engineering_options_keywords,
                              expert_options_keywords, option_param_table)


class BinaryPacket:
    """Base Binary Packet Class
    """
    def __init__(self, payload: bytes, packet_class: int, packet_id: int) -> None:
        self._payload = payload
        self._pclass = packet_class
        self._pid = packet_id

    def to_bytes(self) -> bytes:
        """Renders this packet to its binary representation

        Returns:
            bytes: Binary representation of this packet
        """
        payload_len = len(self._payload)
        header = struct.pack('<BBBBH', 0xE4, 0xEb,
                             self._pclass, self._pid, payload_len)
        msg = header + self._payload
        cksum = binascii.crc_hqx(msg, 0xFFFF).to_bytes(2, 'big')
        return msg + cksum

    def get_class_id_code(self) -> int:
        """Retrieves the class ID value

        Returns:
            int: ID value
        """
        return self._pclass << 8 | self._pid

    def __str__(self) -> str:
        string = self.to_bytes().hex().upper()
        length = 4
        return f'0x{' '.join(string[i:i + length] for i in range(0, len(string), length))}'

    def __repr__(self) -> str:
        string = self.to_bytes().hex().upper()
        length = 4
        return f'0x{' '.join(string[i:i + length] for i in range(0, len(string), length))}'

    def __eq__(self, packet) -> bool:
        if not isinstance(packet, BinaryPacket):
            return False
        return self.to_bytes() == packet.to_bytes()

    @classmethod
    def from_bytes(cls, packet: bytes) -> BinaryPacket:
        """Creates a binary packet from its binary representation

        Args:
            packet (bytes): Bytes to convert

        Raises:
            RuntimeError: Checksum verification failed
            RuntimeError: Packet length mismatch
            RuntimeError: Not a recognized packet

        Returns:
            RctBinaryPacket: Binary packet
        """
        if binascii.crc_hqx(packet, 0xFFFF) != 0:
            raise RuntimeError('Checksum verification failed')
        if len(packet) < 8:
            raise RuntimeError('Packet too short!')
        s1, s2, pcls, pid, _ = struct.unpack('<BBBBH', packet[0:6])
        if s1 != 0xE4 or s2 != 0xEB:
            raise RuntimeError('Not a packet!')
        payload = packet[6:-2]
        return BinaryPacket(payload, pcls, pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int) -> bool:
        """Checks if the specified class/id values match

        Args:
            packet_class (int): Packet Class value
            packet_id (int): Packet ID value

        Returns:
            bool: True if matches, else False
        """
        assert packet_class is not None
        assert packet_id is not None

        return True

    @classmethod
    def _parse_header(cls, packet: bytes, packet_class: int, packet_id: int) -> bytes:
        if binascii.crc_hqx(packet, 0xFFFF) != 0:
            raise RuntimeError('Checksum verification failed')
        if len(packet) < 8:
            raise RuntimeError('Packet too short!')
        header = packet[0:6]
        payload = packet[6:-2]
        start1, start2, pcls, pid, _ = struct.unpack('<BBBBH', header)
        if start1 != 0xE4 or start2 != 0xEB:
            raise RuntimeError('Not a packet!')
        if packet_class != pcls or packet_id != pid:
            raise RuntimeError('Incorrect Packet Type')
        return payload

class PingPacket(BinaryPacket):
    """RCT Ping Packet

    """
    def __init__(self,
                 lat: float,
                 lon: float,
                 alt: float,
                 txp: float,
                 txf: int,
                 timestamp: dt.datetime = None):
        # pylint: disable=too-many-arguments
        self.lat = lat
        self.lon = lon
        self.alt = alt
        self.txp = txp
        self.txf = txf
        if timestamp is None:
            timestamp = dt.datetime.now()
        self.timestamp = timestamp

        _pclass = 0x04
        _pid = 0x01
        _payload = struct.pack('<BQllHfL', 0x01, int(timestamp.timestamp(
        ) * 1e3), int(lat * 1e7), int(lon * 1e7), int(alt * 10), txp, txf)
        super().__init__(payload=_payload, packet_class=_pclass, packet_id=_pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x04 and packet_id == 0x01

    @classmethod
    def from_bytes(cls, packet: bytes):
        payload = cls._parse_header(packet, 0x04, 0x01)
        _, time_ms, lat7, lon7, alt1, txp, txf = struct.unpack(
            '<BQllHfL', payload)
        timestamp = dt.datetime.fromtimestamp(time_ms / 1e3)
        lat = lat7 / 1e7
        lon = lon7 / 1e7
        alt = alt1 / 10
        return PingPacket(lat, lon, alt, txp, txf, timestamp)


class HeartbeatPacket(BinaryPacket):
    """RCT Hearbeat Packet
    """
    class SdrStates(enum.Enum):
        """SDR States
        """
        FIND_DEVICES = 0
        WAIT_RECYCLE = 1
        USRP_PROBE = 2
        RDY = 3
        FAIL = 4

    class ExtSensorStates(enum.Enum):
        """External Sensor States
        """
        GET_TTY = 0
        GET_MSG = 1
        WAIT_RECYCLE = 2
        RDY = 3
        FAIL = 4

    class StorageStates(enum.Enum):
        """Storage States
        """
        GET_OUTPUT_DIR = 0
        CHECK_OUTPUT_DIR = 1
        CHECK_SPACE = 2
        WAIT_RECYCLE = 3
        RDY = 4
        FAIL = 5

    class SysStates(enum.Enum):
        """System States
        """
        INIT = 0
        WAIT_INIT = 1
        WAIT_START = 2
        START = 3
        WAIT_END = 4
        FINISH = 5
        FAIL = 6

    class SwStates(enum.Enum):
        """Switch States
        """
        STOP = 0
        START = 1

    def __init__(self, system_state: int,
                 sdr_state: int,
                 sensor_state: int,
                 storage_state: int,
                 switch_state: int,
                 timestamp: dt.datetime=None):
        # pylint: disable=too-many-arguments
        self.system_state = system_state
        self.sdr_state = sdr_state
        self.sensor_state = sensor_state
        self.storage_state = storage_state
        self.switch_state = switch_state
        if timestamp is None:
            timestamp = dt.datetime.now()
        self.timestamp = timestamp

        _pclass = 0x01
        _pid = 0x01
        _payload = struct.pack('<BBBBBBQ', 0x01, system_state,
                                    sdr_state, sensor_state,
                                    storage_state, switch_state,
                                    int(timestamp.timestamp() * 1e3))
        super().__init__(payload=_payload, packet_class=_pclass, packet_id=_pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x01 and packet_id == 0x01

    @classmethod
    def from_bytes(cls, packet: bytes):
        payload = cls._parse_header(packet, 0x01, 0x01)
        _, system, sdr, sensor, storage, switch, time_ms = struct.unpack(
            '<BBBBBBQ', payload)
        timestamp = dt.datetime.fromtimestamp(time_ms / 1e3)
        return HeartbeatPacket(system, sdr, sensor, storage, switch, timestamp)


class ExceptionPacket(BinaryPacket):
    """Exception Message
    """
    def __init__(self, e: str, tb: str):
        _pclass = 0x01
        _pid = 0x02
        _payload = struct.pack('<BHH', 0x01, len(e), len(
            tb)) + e.encode('ascii') + tb.encode('ascii')
        self.exception = e
        self.traceback = tb
        super().__init__(payload=_payload, packet_class=_pclass, packet_id=_pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x01 and packet_id == 0x02

    @classmethod
    def from_bytes(cls, packet: bytes):
        payload = cls._parse_header(packet, 0x01, 0x02)
        _, exc_len, tb_len = struct.unpack('<BHH', payload[0x0000:0x0005])
        exc_msg = payload[0x0005:0x0005 + exc_len].decode()
        tb_msg = payload[0x0005 + exc_len: 0x0005 + exc_len + tb_len].decode()
        return ExceptionPacket(exc_msg, tb_msg)


class FrequenciesPacket(BinaryPacket):
    """Frequencies Packet
    """
    def __init__(self, frequencies: Sequence[int]):
        self.frequencies = frequencies

        _pclass = 0x02
        _pid = 0x01
        _payload = struct.pack(f'<BB{len(frequencies)}L', 0x01, len(frequencies), *frequencies)
        super().__init__(_payload, _pclass, _pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x02 and packet_id == 0x01

    @classmethod
    def from_bytes(cls, packet: bytes):
        payload = cls._parse_header(packet, 0x02, 0x01)
        _, n_freqs = struct.unpack('<BB', payload[0x0000:0x0002])
        freqs = struct.unpack(f'<{n_freqs}L', payload[0x0002:0x0002 + 4 * n_freqs])
        return FrequenciesPacket(freqs)


class OptionsPacket(BinaryPacket):
    """Options Packet
    """
    def __init__(self, scope: int, kwargs: Dict[Options: Any]):
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
            except Exception as exc:
                raise RuntimeError(f'Failed to pack for kw {keyword}, format '
                                   f'{option_param.format_str}, value {kwargs[keyword]}') from exc

        super().__init__(payload=payload, packet_class=pclass, packet_id=pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x02 and packet_id == 0x02

    @classmethod
    def from_bytes(cls, packet: bytes):
        payload = cls._parse_header(packet, 0x02, 0x02)
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
        return OptionsPacket(scope, options)


class UpgradeStatusPacket(BinaryPacket):
    """Upgrade Status Packet
    """
    UPGRADE_READY = 0x00
    UPGRADE_PROGRESS = 0x01
    UPGRADE_COMPLETE = 0xFE
    UPGRADE_FAILED = 0xFF

    def __init__(self, state: int, msg: str):
        self.state = state
        self.msg = msg
        _pclass = 0x03
        _pid = 0x01
        _payload = struct.pack(
            '<BBH', 0x01, state, len(msg)) + msg.encode('ascii')
        super().__init__(_payload, _pclass, _pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x03 and packet_id == 0x01

    @classmethod
    def from_bytes(cls, packet: bytes):
        payload = cls._parse_header(packet, 0x03, 0x01)
        _, state, strlen = struct.unpack('<BBH', payload[0x0000: 0x0004])
        msg = payload[0x0004:0x0004 + strlen].decode()
        return UpgradeStatusPacket(state, msg)

class UpgradePacket(BinaryPacket):
    """Upgrade Packet
    """

    def __init__(self, numPacket, numTotal, fileBytes):
        self.num_packet = numPacket
        self.num_total = numTotal
        self.file_bytes = fileBytes

        _pclass = 0x03
        _pid = 0x02
        _payload = struct.pack('<BHHH', 0x01, numPacket, numTotal, len(fileBytes)) + fileBytes
        super().__init__(_payload, _pclass, _pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x03 and packet_id == 0x02

    @classmethod
    def from_bytes(cls, packet: bytes):
        payload = cls._parse_header(packet, 0x03, 0x02)
        #TODO: fix decoding
        _, num_packet, num_total, bytes_len = struct.unpack('<BHHH', payload[0x0000: 0x0007])
        file_bytes = payload[0x0007:0x0007 + bytes_len]
        return UpgradePacket(num_packet, num_total, file_bytes)


class ConePacket(BinaryPacket):
    """Cone Packet
    """

    def __init__(self,
                 lat: float,
                 lon: float,
                 alt: float,
                 power: float,
                 angle: float,
                 timestamp: dt.datetime = None):
        # pylint: disable=too-many-arguments
        self.lat = lat
        self.lon = lon
        self.alt = alt
        self.power = power
        self.angle = angle
        if timestamp is None:
            timestamp = dt.datetime.now()
        self.timestamp = timestamp

        _pclass = 0x04
        _pid = 0x04
        _payload = struct.pack('<BQllHff', 0x01, int(timestamp.timestamp(
        ) * 1e3), int(lat * 1e7), int(lon * 1e7), int(alt * 10), power, angle)
        super().__init__(_payload, _pclass, _pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x04 and packet_id == 0x04

    @classmethod
    def from_bytes(cls, packet: bytes):
        payload = cls._parse_header(packet, 0x04, 0x04)
        _, time_ms, lat7, lon7, alt1, power, angle = struct.unpack(
            '<BQllHff', payload)
        timestamp = dt.datetime.fromtimestamp(time_ms / 1e3)
        lat = lat7 / 1e7
        lon = lon7 / 1e7
        alt = alt1 / 10
        return ConePacket(lat, lon, alt, power, angle, timestamp)

class VehiclePacket(BinaryPacket):
    """Vehicle Data Packet
    """
    def __init__(self, lat: float, lon: float, alt: float, hdg: int, timestamp: dt.datetime = None):
        # pylint: disable=too-many-arguments
        self.lat = lat
        self.lon = lon
        self.alt = alt
        self.hdg = hdg
        if timestamp is None:
            timestamp = dt.datetime.now()
        self.timestamp = timestamp

        _pclass = 0x04
        _pid = 0x02
        _payload = struct.pack('<BQllHH', 0x01, int(timestamp.timestamp(
        ) * 1e3), int(lat * 1e7), int(lon * 1e7), int(alt * 10), hdg)
        super().__init__(_payload, _pclass, _pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x04 and packet_id == 0x02

    @classmethod
    def from_bytes(cls, packet: bytes):
        payload = cls._parse_header(packet, 0x04, 0x02)
        _, time_ms, lat7, lon7, alt1, hdg = struct.unpack(
            '<BQllHH', payload)
        timestamp = dt.datetime.fromtimestamp(time_ms / 1e3)
        lat = lat7 / 1e7
        lon = lon7 / 1e7
        alt = alt1 / 10
        return VehiclePacket(lat, lon, alt, hdg, timestamp)


class ACKCommand(BinaryPacket):
    """Ack Packet
    """
    def __init__(self, commandID: int, ack: bool, timestamp: dt.datetime = None):
        self.command_id = commandID
        self.ack = ack
        if timestamp is None:
            timestamp = dt.datetime.now()
        self.timestamp = timestamp

        _pclass = 0x05
        _pid = 0x01
        _payload = struct.pack(
            '<BB?Q', 0x01, commandID, ack, int(timestamp.timestamp() * 1e3))
        super().__init__(_payload, _pclass, _pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x05 and packet_id == 0x01

    @classmethod
    def from_bytes(cls, packet: bytes):
        payload = cls._parse_header(packet, 0x05, 0x01)
        _, command_id, ack, time_ms = struct.unpack('<BB?Q', payload)
        timestamp = dt.datetime.fromtimestamp(time_ms / 1e3)
        return ACKCommand(command_id, ack, timestamp)


class GetFCommand(BinaryPacket):
    """Get Frequencies Command Packet
    """

    def __init__(self):
        super().__init__(b'\x01', 0x05, 0x02)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x05 and packet_id == 0x02

    @classmethod
    def from_bytes(cls, packet: bytes):
        return GetFCommand()


class SetFCommand(BinaryPacket):
    """Set Frequencies Command
    """
    def __init__(self, frequencies: Sequence[int]):
        _pclass = 0x05
        _pid = 0x03
        self.frequencies = frequencies
        _payload = struct.pack(f'<BB{len(frequencies)}L', 0x01, len(frequencies), *frequencies)
        super().__init__(_payload, _pclass, _pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x05 and packet_id == 0x03

    @classmethod
    def from_bytes(cls, packet: bytes):
        payload = cls._parse_header(packet, 0x05, 0x03)
        _, n_freqs = struct.unpack('<BB', payload[0x0000:0x0002])
        freqs = struct.unpack(f'<{n_freqs}L', payload[0x0002:0x0002 + 4 * n_freqs])
        return SetFCommand(freqs)


class GetOptCommand(BinaryPacket):
    """Get Options Command
    """

    def __init__(self, scope: int):
        self.scope = scope
        _pclass = 0x05
        _pid = 0x04
        _payload = struct.pack('<BB', 0x01, scope)
        super().__init__(_payload, _pclass, _pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x05 and packet_id == 0x04

    @classmethod
    def from_bytes(cls, packet: bytes):
        payload = cls._parse_header(packet, 0x05, 0x04)
        _, scope = struct.unpack('<BB', payload[0x0000:0x0002])
        return GetOptCommand(scope)


class SetOptCommand(BinaryPacket):
    """Set Options Command
    """

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
            raise RuntimeError('Invalid scope')

        pclass = 0x05
        pid = 0x05
        payload = struct.pack('<BB', 0x01, scope)
        self.options: Dict[Options, Any] = {}
        self.scope = scope
        for keyword in accepted_kw:
            option_param = option_param_table[keyword]
            payload += option_param.pack(kwargs[keyword])
            self.options[keyword] = kwargs[keyword]
        super().__init__(payload=payload, packet_class=pclass, packet_id=pid)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x05 and packet_id == 0x05

    @classmethod
    def from_bytes(cls, packet: bytes):
        payload = cls._parse_header(packet, 0x05, 0x05)
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
        return SetOptCommand(scope, options)


class StartCommand(BinaryPacket):
    """Start Command
    """

    def __init__(self):
        super().__init__(b'\x01', 0x05, 0x07)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x05 and packet_id == 0x07

    @classmethod
    def from_bytes(cls, packet: bytes):
        cls._parse_header(packet, 0x05, 0x7)
        return StartCommand()


class StopCommand(BinaryPacket):
    """Stop Command
    """
    def __init__(self):
        super().__init__(b'\x01', 0x05, 0x09)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x05 and packet_id == 0x09

    @classmethod
    def from_bytes(cls, packet: bytes):
        cls._parse_header(packet, 0x05, 0x09)
        return StopCommand()


class UpgradeCommand(BinaryPacket):
    """Upgrade Command
    """
    def __init__(self):
        super().__init__(b'\x01', 0x05, 0x0B)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int):
        return packet_class == 0x05 and packet_id == 0x0B

    @classmethod
    def from_bytes(cls, packet: bytes):
        cls._parse_header(packet, 0x05, 0x0B)
        return UpgradeCommand()

class EngrCommand(BinaryPacket):
    """Engineering command packet

    """
    def __init__(self, command_word: str, args: Dict[str, Any]) -> None:
        self.command_word = command_word
        self.args = args
        payload_bytes = json.dumps({command_word:args}).encode(encoding='ascii')
        super().__init__(payload=payload_bytes, packet_class=0x06, packet_id=0x00)

    @classmethod
    def matches(cls, packet_class: int, packet_id: int) -> bool:
        return packet_class == 0x06 and packet_id == 0x00

    @classmethod
    def from_bytes(cls, packet: bytes) -> BinaryPacket:
        payload_bytes = cls._parse_header(packet, 0x06, 0x00)
        payload: Dict[str, Dict[str, Any]] = json.loads(payload_bytes.decode(encoding='ascii'))
        assert len(payload.keys()) == 1
        cmd_word = list(payload.keys())[0]
        return EngrCommand(command_word=cmd_word, args=payload[cmd_word])
