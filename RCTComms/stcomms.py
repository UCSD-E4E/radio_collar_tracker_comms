import enum
import struct

headerLen = 6

class COMMAND_ID(enum.Enum):
    '''
    Command Packet IDs
    '''
    SET_TIME = 0x00
    SET_ALARM = 0x01
    CLEAR_ALARM = 0x02
    GET_TIME = 0x03
    SET_STATE = 0x04
    GET_TIME_ACK = 0x05
    
class stBinaryPacket:
    '''
    Base class for sleep timer binary packets
    '''
    def __init__(self, payload: bytes, packetID: int) -> None:
        self._payload = payload
        self._pid = packetID

    def to_bytes(self) -> bytes:
        '''
        Converts the packet to binary bytes
        '''
        payloadLen = len(self._payload)
        header = struct.pack('<BBHH', 0xE4, 0xEb, payloadLen + headerLen,
                             self._pid)
        msg = header + self._payload
        return msg

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
        if not isinstance(packet, stBinaryPacket):
            return False
        return self.to_bytes() == packet.to_bytes()

    @classmethod
    def from_bytes(cls, packet: bytes):
        '''
        Converts binary bytes into a stBinaryPacket
        '''
        if len(packet) < 6:
            raise RuntimeError("Packet too short!")
        s1, s2, _, pid, = struct.unpack("<BBHH", packet[0:6])
        if s1 != 0xE4 or s2 != 0xEB:
            raise RuntimeError("Not a packet!")
        payload = packet[6:0] 
        return stBinaryPacket(payload, pid)

    @classmethod
    def matches(cls, packetClass: int, packetID: int) -> bool:
        return True
    
class SETALARMCommand(stBinaryPacket):
    '''
    Packet for setting sleep timer alarm
    '''
    def __init__(self, msec: int):
        '''
        :param msec: The amount of time (in miliseconds) that the alarm will be set (how long to turn off)
        '''
        self._pid = COMMAND_ID.SET_ALARM.value
        self._payload = struct.pack('<I', msec)
        self.time = msec

    @classmethod
    def matches(cls, packetID: int):
        return packetID == COMMAND_ID.SET_ALARM.value

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:] 
        _, _, _, pid = struct.unpack("<BBHH", header)
        if pid != COMMAND_ID.SET_ALARM.value:
            raise RuntimeError("Incorrect packet type")
        time = struct.unpack('<I', payload)
        return cls(time)
    
class GETTIMECommand(stBinaryPacket):
    '''
    Packet for sending a get alarm command
    '''
    def __init__(self):
        self._pid = COMMAND_ID.GET_TIME.value
        self._payload = struct.pack('<')

    @classmethod
    def matches(cls, packetID: int):
        return packetID == COMMAND_ID.GET_TIME.value

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:]
        _, _, _, pid= struct.unpack("<BBHB", header)
        if pid != COMMAND_ID.GET_TIME.value:
            raise RuntimeError("Incorrect packet type")
        return cls()
    
class CLEARALARMCommand(stBinaryPacket):
    '''
    Packet for sending a clear alarm command
    '''
    def __init__(self):
        self._pid = COMMAND_ID.CLEAR_ALARM.value
        self._payload = struct.pack('<')

    @classmethod
    def matches(cls, packetID: int):
        return packetID == COMMAND_ID.CLEAR_ALARM.value

    @classmethod
    def from_bytes(cls, packet: bytes):
        header = packet[0:6]
        payload = packet[6:]
        _, _, _, pid = struct.unpack("<BBHB", header)
        if pid != COMMAND_ID.CLEAR_ALARM.value:
            raise RuntimeError("Incorrect packet type")
        return cls()