'''RCT Comms
'''
from __future__ import annotations

import binascii
import datetime as dt
import enum
import logging
import struct
import threading
import time
import traceback
from typing import Callable, Dict, List, Optional, Type

import rctcomms.transport
from rctcomms.packets import (EngrCommand, ACKCommand, BinaryPacket,
                              ConePacket, ExceptionPacket,
                              FrequenciesPacket, GetFCommand,
                              GetOptCommand, HeartbeatPacket,
                              OptionsPacket, PingPacket, SetFCommand,
                              SetOptCommand, StartCommand,
                              StopCommand, UpgradeCommand,
                              UpgradePacket, UpgradeStatusPacket,
                              VehiclePacket)


class PacketClass(enum.Enum):
    '''
    Valid Packet Classes
    '''
    STATUS = 0x01
    CONFIGURATION = 0x02
    UPGRADE = 0x03
    DATA = 0x04
    COMMAND = 0x05


class StatusId(enum.Enum):
    '''
    Status Packet IDs
    '''
    HEARTBEAT = 0x01
    EXCEPTION = 0x02


class ConfigId(enum.Enum):
    '''
    Configuration Packet IDs
    '''
    FREQUENCIES = 0x01
    OPTIONS = 0x01


class UpgradeId(enum.Enum):
    '''
    Upgrade Packet IDs
    '''
    STATUS = 0x01


class DataId(enum.Enum):
    '''
    Data Packet IDs
    '''
    PING = 0x01
    VEHICLE = 0x02


class CommandId(enum.Enum):
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


class Events(enum.Enum):
    """Event Codes
    """
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


class RctBinaryPacketFactory:
    """Packet Factory Class
    """
    class State(enum.Enum):
        """Factory internal state
        """
        FIND_SYNC = 0
        HEADER = 1
        PAYLOAD = 2
        CKSUM = 3
        VALIDATE = 4

    packetMap: Dict[int, Type[BinaryPacket]] = {
        Events.STATUS_HEARTBEAT.value: HeartbeatPacket,
        Events.STATUS_EXCEPTION.value: ExceptionPacket,
        Events.CONFIG_FREQUENCIES.value: FrequenciesPacket,
        Events.CONFIG_OPTIONS.value: OptionsPacket,
        Events.UPGRADE_STATUS.value: UpgradeStatusPacket,
        Events.UPGRADE_DATA.value: UpgradePacket,
        Events.DATA_PING.value: PingPacket,
        Events.DATA_CONE.value: ConePacket,
        Events.DATA_VEHICLE.value: VehiclePacket,
        Events.COMMAND_ACK.value: ACKCommand,
        Events.COMMAND_GETF.value: GetFCommand,
        Events.COMMAND_SETF.value: SetFCommand,
        Events.COMMAND_GETOPT.value: GetOptCommand,
        Events.COMMAND_SETOPT.value: SetOptCommand,
        Events.COMMAND_START.value: StartCommand,
        Events.COMMAND_STOP.value: StopCommand,
        Events.COMMAND_UPGRADE.value: UpgradeCommand,
        Events.ENGR_CMD.value: EngrCommand,
    }

    def __init__(self):
        self.__state = self.State.FIND_SYNC
        self.__payload_len = 0
        self.__log = logging.getLogger('Binary Packet Parser')
        self.__buffer = bytearray()

    def parse_byte(self, data: int) -> Optional[BinaryPacket]:
        """Parses a single byte of data

        Args:
            data (int): Next Byte value

        Raises:
            ChecksumError: Bad Checksum
            RuntimeError: Bad state

        Returns:
            Optional[rctBinaryPacket]: Packet if valid packet received, otherwise None
        """
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
                self.__payload_len, = struct.unpack(
                    '<H', self.__buffer[0x0004:0x0006])
            return None
        elif self.__state == self.State.PAYLOAD:
            self.__buffer.append(data)
            if len(self.__buffer) == self.__payload_len + 0x0006:
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
            packet_id, = struct.unpack('>H', self.__buffer[0x0002:0x0004])
            self.__state = self.State.FIND_SYNC
            if packet_id not in self.packetMap:
                return BinaryPacket.from_bytes(self.__buffer)
            return self.packetMap[packet_id].from_bytes(self.__buffer)
        else:
            raise RuntimeError('Unknown state')

    def parse_bytes(self, data: bytes) -> List[BinaryPacket]:
        """Parses a sequence of bytes for valid packets

        Args:
            data (bytes): Incoming bytes to parse

        Returns:
            List[rctBinaryPacket]: List of completed packets, otherwise empty list
        """
        packets: List[BinaryPacket] = []
        for byte in data:
            try:
                retval = self.parse_byte(byte)
            except ChecksumError:
                # At this point, we are going to simply drop the packet.
                continue
            if retval is not None:
                packets.append(retval)
        return packets


class GcsComms:
    '''
    Radio Collar Tracker UDP Interface
    '''
    __BUFFER_LEN = 1024
    __lock = threading.Lock()

    def __init__(self,
                 port: rctcomms.transport.AbstractTransport,
                 disconnected: Optional[Callable[[], None]] = None,
                 heartbeat_watchdog_time=30):
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

        self.__receiver_thread: Optional[threading.Thread] = None
        self.__hb_thread = threading.Thread(target=self.heartbeat_monitor,
                                            name='Heartbeat Monitor',
                                            daemon=True)
        self.__log.info('RTC gcsComms created')
        self.hs_run = False
        self.__mav_ip: Optional[str] = None
        self.__last_heartbeat: Optional[dt.datetime] = None
        self.__packet_map: Dict[int, List[Callable]] = {
            evt.value: [] for evt in Events
        }
        self.__packet_map[Events.STATUS_HEARTBEAT.value] = [
            self.__process_heartbeat]

        self.heartbeat_watchdog_time: int = heartbeat_watchdog_time

        self.__parser = RctBinaryPacketFactory()

    def set_disconnect(self, cb_: Callable[[], None]):
        """Sets the disconnect behavior

        Args:
            cb_ (Callable[[], None]): Sets the disconnect behavior
        """
        self.__disconnected = cb_

    def __wait_for_heartbeat(self, gui_tick: Callable = None, timeout: int = None):
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
            timeout = self.heartbeat_watchdog_time
        self.__log.debug('Waiting %d s for heartbeats', timeout)
        for _ in range(timeout):
            try:
                data, addr = self.sock.receive(1024, 1)
                if data is None:
                    self.__log.warning(
                        'Received None from transport, assuming disconnected')
                    self.__disconnected()
                    break
                packets = self.__parser.parse_bytes(data)
                for packet in packets:
                    self.__log.info('Received %s', type(packet).__name__)
                    if isinstance(packet, HeartbeatPacket):
                        self.__last_heartbeat = dt.datetime.now()
                        return addr, packets
            except TimeoutError:
                pass
            if gui_tick is not None:
                gui_tick()
        self.__log.error('Failed to receive any heartbeats')
        return (None, None)

    def __receiver_loop(self):
        '''
        Receiver thread
        '''
        self.__log.info('RCT gcsComms rxThread started')
        assert self.__last_heartbeat is not None

        while self.hs_run:
            try:
                data, addr = self.sock.receive(self.__BUFFER_LEN, 1)
                if data:
                    self.__log.info('Received: %s', data.hex(' ', -2))
            except TimeoutError:
                continue
            if not data:
                self.__disconnected()
                break

            try:
                packets = self.__parser.parse_bytes(data)
            except Exception as exc:
                self.__log.exception('Failed to parse packets: %s', exc)
                raise exc

            for packet in packets:
                self.__log.info('Received %s', type(packet).__name__)
                packet_code = packet.get_class_id_code()
                try:
                    for callback in self.__packet_map[packet_code]:
                        callback(packet=packet, addr=addr)
                except KeyError:
                    for callback in self.__packet_map[Events.GENERAL_UNKNOWN.value]:
                        callback(packet=packet, addr=addr)
                except Exception as exc:
                    self.__log.exception('Failed to handle packet')
                    for callback in self.__packet_map[Events.GENERAL_EXCEPTION.value]:
                        callback(packet=packet, addr=addr)
                    raise exc

    def heartbeat_monitor(self):
        """Heartbeat Monitor thread
        """
        assert self.__last_heartbeat is not None
        while self.hs_run:
            time.sleep(1)
            time_since_heartbeat = dt.datetime.now() - self.__last_heartbeat
            if time_since_heartbeat.total_seconds() > self.heartbeat_watchdog_time:
                self.__log.warning('No heartbeats, last heartbeat at %s',
                                   self.__last_heartbeat)
                for callback in self.__packet_map[Events.GENERAL_NO_HEARTBEAT.value]:
                    callback(packet=None, addr=None)

    def start(self, gui: Callable = None):
        '''
        Starts the receiver.
        '''
        self.__log.info('RCT gcsComms starting...')
        self.sock.open()
        self.__mav_ip, packets = self.__wait_for_heartbeat(gui_tick=gui)
        if self.__mav_ip is None or packets is None:
            raise RuntimeError('Failed to receive heartbeats')
        for packet in packets:
            packet_code = packet.get_class_id_code()
            try:
                for callback in self.__packet_map[packet_code]:
                    callback(packet=packet, addr=self.__mav_ip)
            except KeyError:
                for callback in self.__packet_map[Events.GENERAL_UNKNOWN.value]:
                    callback(packet=packet, addr=self.__mav_ip)
            except Exception:
                for callback in self.__packet_map[Events.GENERAL_EXCEPTION.value]:
                    callback(packet=packet, addr=self.__mav_ip)
        self.hs_run = True
        self.__receiver_thread = threading.Thread(
            target=self.__receiver_loop, name='gcsComms rx')
        self.__receiver_thread.start()
        self.__hb_thread.start()
        self.__log.info('RCT gcsComms started')

    def stop(self):
        '''
        Stops the receiver.
        '''
        self.__log.info('HS_run set to False')
        self.hs_run = False
        if self.__receiver_thread is not None:
            self.__receiver_thread.join(timeout=1)
        self.__hb_thread.join()
        self.__log.info('RCT gcsComms stopped')
        self.sock.close()

    def __process_heartbeat(self, packet: BinaryPacket, addr: str):
        '''
        Internal callback to handle recognizing loss of heartbeat
        '''
        assert packet is not None
        assert addr is not None
        self.__last_heartbeat = dt.datetime.now()

    def register_callback(self, event: Events, callback: Callable) -> None:
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
        self.__packet_map[event.value].append(callback)

    def __synchronized_callback(self, callback):
        def lock_and_call(packet: BinaryPacket, addr: str):
            with GcsComms.__lock:
                callback(packet, addr)
        return lock_and_call

    def unregister_callback(self, event: Events, callback):
        """Unregisters the specified callback from the specific event

        Args:
            event (Events): Event to unregister from
            callback (function): Callback to unregister
        """
        self.__packet_map[event.value].remove(callback)

    def send_message(self, payload: bytes, packet_class: int, packet_id: int):
        '''
        Sends the specified dictionary as a packet
        :param packet: Packet to send
        :type packet: dictionary
        '''
        assert isinstance(payload, bytes)
        payload_len = len(payload)
        header = struct.pack('<BBBBH', 0xE4, 0xEb,
                             packet_class, packet_id, payload_len)
        msg = header + payload
        cksum = binascii.crc_hqx(msg, 0xFFFF).to_bytes(2, 'big')
        self.__log.info('Send: %s', ((msg + cksum).hex()))
        self.sock.send(msg, self.__mav_ip)

    def send_packet(self, packet: BinaryPacket):
        '''
        Sends the specified packet object
        :param packet:
        :type packet:
        '''

        self.__log.info('Send: %s as %s', type(packet).__name__, packet)
        self.sock.send(packet.to_bytes(), self.__mav_ip)


class MavComms:
    """MAV Comms Interface
    """

    def __init__(self, port: rctcomms.transport.AbstractTransport):
        self.__log = logging.getLogger('rctComms.mavComms')
        self.__port = port

        self.__rx_thread = None
        self.__log.info('RCT mavComms created')
        self.hs_run = False
        self.gcs_addr: Optional[str] = None
        self.__packet_map: Dict[int, List[Callable]] = {
            evt.value: [] for evt in Events
        }

        self.__parser = RctBinaryPacketFactory()

        self.port_open_event = threading.Event()

    def is_open(self) -> bool:
        """Checks if interface is open

        Returns:
            bool: True if open, otherwise False
        """
        return self.__port.is_open()

    def start(self):
        """Starts the MavComms listener
        """
        self.__log.info('RCT mavComms starting...')
        self.hs_run = True
        self.__rx_thread = threading.Thread(
            target=self.__receiver, name='mavComms_receiver', daemon=True)
        self.__rx_thread.start()

    def stop(self):
        """Stops the MavComms listener
        """
        self.__log.info('HS_run set to False')
        self.hs_run = False
        if self.__rx_thread is not None:
            self.__rx_thread.join(timeout=1)
        self.__port.close()
        self.port_open_event.set()
        self.port_open_event.clear()
        self.__log.info('RCT mavComms stopped')

    def send_to_gcs(self, packet: BinaryPacket):
        """Sends the given packet to the GCS

        Args:
            packet (rctBinaryPacket): Packet to send
        """
        self.send_packet(packet, self.gcs_addr)

    def send_to_all(self, packet: BinaryPacket):
        """Sends the given packet to all receivers

        Args:
            packet (rctBinaryPacket): Packet to send
        """
        self.send_packet(packet, None)

    def send_packet(self, packet: BinaryPacket, dest: Optional[str], timeout=5):
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

    def send_ping(self, ping: PingPacket):
        """Sends the specified Ping packet

        Args:
            ping (rctPingPacket): Ping packet
        """
        self.send_packet(ping, None)

    def send_cone(self, cone: ConePacket):
        """Sends the specified Cone packet

        Args:
            cone (rctConePacket): Cone packet
        """
        self.send_packet(cone, None)

    def send_vehicle(self, vehicle: VehiclePacket):
        """Sends the specified vehicle packet

        Args:
            vehicle (rctVehiclePacket): Vehicle Packet
        """
        self.send_packet(vehicle, None)

    def send_exception(self, exception: str, tb_: str):
        """Sends an exception message

        Args:
            exception (str): Exception message
            tb_ (str): Traceback info
        """
        packet = ExceptionPacket(exception, tb_)
        try:
            self.send_to_all(packet)
        except Exception:  # pylint: disable=broad-except
            # This is only called in an exception handler - it cannot be allowed
            # to raise another exception!
            self.__log.exception('Failed to send exception!')

    def __receiver(self):
        if not self.__port.is_open():
            self.__port.open()
        self.port_open_event.set()
        while self.hs_run is True:
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
                packets = self.__parser.parse_bytes(data)
            except Exception as exc:
                self.__log.exception('Failed to parse packets: %s', exc)
                self.send_exception(str(exc), tb_=traceback.format_exc())
                continue

            try:
                for packet in packets:
                    self.__log.info('Received %s', type(packet).__name__)
                    packet_code = packet.get_class_id_code()
                    self.__log.debug('Looking for 0x%04x', packet_code)
                    try:
                        self.execute_cb(packet_code, {
                            'packet': packet,
                            'addr': addr
                        })
                    except KeyError:
                        self.execute_cb(Events.GENERAL_UNKNOWN.value, {
                            'packet': packet,
                            'addr': addr
                        })
            except Exception as exc:
                self.send_exception(str(exc), tb_=traceback.format_exc())
                self.__log.exception('Failed to handle packets: %s', exc)

    def execute_cb(self, event_value: int, kwargs: Dict):
        """Executes the specified callback

        Args:
            event_value (int): Event value to execute
            kwargs (Dict): kwargs for callback
        """
        cb_fns = self.__packet_map[event_value]
        if len(cb_fns) == 0:
            self.__log.info('Empty callback list for %s', Events(event_value))
        for cb_ in cb_fns:
            self.__log.debug('Executing %s', cb_.__name__)
            try:
                cb_(**kwargs)
            except Exception as exc:
                self.__log.exception('Exception during callback')
                raise exc

    def register_callback(self, event: Events, callback: Callable):
        """Registers the specified callback

        Args:
            event (EVENTS): Event to register with
            callback (Callable): Callback function
        """
        self.__log.info('Registering %s to %s', callback.__name__, event.name)
        self.__packet_map[event.value].append(callback)
