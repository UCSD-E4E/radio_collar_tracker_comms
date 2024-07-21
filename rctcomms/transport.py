'''Radio Collar Tracker Communication Transport Abstractions
'''

import abc
import datetime as dt
import logging
import os
import select
import selectors
import socket
import threading
import time
import types
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import ParseResult, parse_qs, urlparse

import serial
from schema import Or, Schema


class FatalException(Exception):
    """Fatal Exception

    This is thrown when the transport has encountered a fatal error and cannot
    recover its previous state.
    """
class AbstractTransport(abc.ABC):
    '''
    Abstract transport class - all transport types should inherit from this
    '''
    @abc.abstractmethod
    def __init__(self) -> None:
        '''
        Constructor for the RCTAbstractTransport class.  This constructor shall
        provision resources for the port, but it shall not open the port.  That
        is, other processes must be able to access the port after this function
        returns.
        '''

    @abc.abstractmethod
    def open(self) -> None:
        '''
        Opens the port represented by the RCTAbstractTransport class.  After
        this function returns, the port shall be owned by this process and be
        capable of sending and receiving data.  Failure to open the port shall
        result in an Exception being thrown.
        '''

    @abc.abstractmethod
    def receive(self, buffer_len: int, timeout: int=None) -> Tuple[bytes, str]:
        '''
        Receives data from the port.  This function shall attempt to retrieve at
        most buffer_len bytes from the port within timeout seconds.

        If there are less than buffer_len bytes available when this function is
        called, the function shall return all available bytes immediately.  If
        there are more than buffer_len bytes available when this function is
        called, the function shall return exactly buffer_len bytes.  If there is no
        data available when this function is called, this function shall wait at
        most timeout seconds.  If any data arrives within timeout seconds, that
        data shall be immediately returned.  If no data arrives, the function
        shall raise an Exception.

        This function shall return a tuple containing two elements.  The first
        element shall be a bytes object containing the data received.  The
        second element shall be a string denoting the originating machine.

        Making a call to this function when the port is not open shall result in
        an Exception.

        :param buffer_len:    Maximum number of bytes to return
        :param timeout:    Maximum number of seconds to wait for data
        '''

    @abc.abstractmethod
    def send(self, data: bytes, dest) -> None:
        '''
        Sends data to the specified destination from the port.  This function
        shall transmit the provided data to the specified destination.

        This function shall block until all data is transmitted.

        :param data:    Data to transmit
        :param dest:    Destination to route data to
        '''

    @abc.abstractmethod
    def close(self) -> None:
        '''
        Closes the underlying port.  This function shall release the underlying
        port to be used by other processes.  Calling this function on a port
        that is already closed shall not result in an Exception.  Subsequent
        calls to open() shall not fail if the port is available for this process
        to own.
        '''

    @abc.abstractmethod
    def is_open(self) -> bool:
        '''
        Returns True if the port is open, False otherwise
        '''

    @property
    @abc.abstractmethod
    def port_name(self) -> str:
        """Returns the name of the port

        Returns:
            str: String representation of the port
        """

    @abc.abstractmethod
    def reconnect_on_fail(self, timeout: int = 30):
        """Attempts to reconnect this transport.

        If this transport is currently connected, this method must not make any
        changes.

        If this transport is not currently connected and can be connected, this
        method must leave the transport in a functional state similar to as if
        it has just come out of `open`.

        If this transport is not currently connected and cannot be connected,
        this method must raise a RCTComms.transport.FatalException.

        Note that this method must be thread-safe, as send and recieve may happen concurrently.

        Args:
            timeout (int, optional): Timeout. Defaults to 30.
        """


class UDPClient(AbstractTransport):
    """UDP Client
    """
    def __init__(self, port: int):
        self.__socket: Optional[socket.socket] = None
        self.__port = port
        self.__fail = False
        self.__log = logging.getLogger(f'UDP Client {port}')
        self.__rx_lock = Lock()
        self.__tx_lock = Lock()

    def open(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__socket.bind(('', self.__port))

    def close(self):
        try:
            self.__socket.close()
        finally:
            self.__socket = None

    def receive(self, buffer_len: int, timeout: int=None):
        try:
            with self.__rx_lock:
                if self.__socket is None:
                    raise RuntimeError()
                ready = select.select([self.__socket], [], [], timeout)
                if len(ready[0]) != 1:
                    raise TimeoutError
                data, addr = self.__socket.recvfrom(buffer_len)
                return data, addr[0]
        except Exception as exc:
            self.__log.exception('Fail on receive')
            self.__fail = True
            raise exc

    def send(self, data: bytes, dest):
        try:
            with self.__tx_lock:
                if self.__socket is None:
                    raise RuntimeError()
                self.__socket.sendto(data, (dest, self.__port))
        except Exception as exc:
            self.__log.exception('Fail on send')
            self.__fail = True
            raise exc

    def is_open(self):
        return self.__socket is not None

    @property
    def port_name(self) -> str:
        """Returns the name of the port

        Returns:
            str: String representation of the port
        """
        return self.__port

    def reconnect_on_fail(self, timeout: int = 30):
        with self.__rx_lock, self.__tx_lock:
            if not self.__fail:
                return
            start = dt.datetime.now()

            try:
                self.__socket.close()
            except Exception: # pylint: disable=broad-except
                # pass any exception - idea is to suppress and recover
                self.__log.exception('Failed to close on reconnect')

            self.__socket = None

            while (dt.datetime.now() - start).total_seconds() < timeout:
                try:
                    self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self.__socket.bind(('', self.__port))
                except Exception: # pylint: disable=broad-except
                    # need to keep trying until timeout
                    self.__log.exception('Failed to open on reconnect')
                    time.sleep(1)
            raise FatalException('Unable to reconnect')

class UDPServer(AbstractTransport):
    """UDP Broadcast Server
    """
    def __init__(self, port: int):
        self.__socket: Optional[socket.socket] = None
        self.__port = port

    def open(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.__socket.setblocking(False)
        self.__socket.bind(('', self.__port))

    def close(self):
        if self.__socket is None:
            raise RuntimeError()
        try:
            self.__socket.close()
        except Exception:
            pass
        self.__socket = None

    def receive(self, buffer_len: int, timeout: int = None):
        if self.__socket is None:
            raise RuntimeError()
        ready = select.select([self.__socket], [], [], timeout)
        if ready[0]:
            data, addr = self.__socket.recvfrom(buffer_len)
            return data, addr[0]
        else:
            raise TimeoutError

    def send(self, data: bytes, dest):
        if self.__socket is None:
            raise RuntimeError()
        if dest is None:
            dest = '255.255.255.255'
        self.__socket.sendto(data, (dest, self.__port))

    def is_open(self):
        return self.__socket is not None

    @property
    def port_name(self) -> str:
        """Returns the name of the port

        Returns:
            str: String representation of the port
        """
        return self.__port


class PipeClient(AbstractTransport):
    """Pipe Client Transport
    """
    def __init__(self):
        self.__in_file = None
        self.__out_file = None

    def open(self):
        client_to_sim = Path('/tmp/rctClient2Simulator')
        sim_to_client = Path('/tmp/rctSimulator2Client')
        if not client_to_sim.exists():
            os.mkfifo(client_to_sim.as_posix())
        if not sim_to_client.exists():
            os.mkfifo(sim_to_client.as_posix())

        self.__in_file = os.open(sim_to_client.as_posix(), os.O_NONBLOCK | os.O_RDONLY)
        self.__out_file = open(client_to_sim, 'wb')

    def close(self):
        self.__in_file = None
        self.__out_file = None

    def receive(self, buffer_len: int, timeout: int = None):
        pass

    def send(self, data: bytes, dest):
        pass

    def is_open(self):
        return self.__in_file is not None and self.__out_file is not None

    @property
    def port_name(self) -> str:
        """Returns the name of the port

        Returns:
            str: String representation of the port
        """
        return 'pipe'

class TCPClient(AbstractTransport):
    """TCP Client
    """
    def __init__(self, port: int, addr: str):
        self.__target = (addr, port)
        self.__socket: Optional[socket.socket] = None
        self.__fail = False
        self.__log = logging.getLogger(f'TCP Client {addr}:{port}')
        self.__rx_lock = Lock()
        self.__tx_lock = Lock()

    def open(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.__socket.connect(self.__target)

    def close(self):
        if self.__socket is None:
            raise RuntimeError()
        try:
            self.__socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        self.__socket.close()
        self.__socket = None
        self.__fail = False

    def receive(self, buffer_len: int, timeout: int=None):
        try:
            with self.__rx_lock:
                if self.__socket is None:
                    raise RuntimeError()
                ready = select.select([self.__socket], [], [], timeout)
                if len(ready[0]) != 1:
                    raise TimeoutError
                data = self.__socket.recv(buffer_len)
                return data, self.__target[0]
        except Exception as exc:
            self.__log.exception('Fail on receive')
            self.__fail = True
            raise exc

    def send(self, data: bytes, dest):
        # pylint: disable=unused-argument
        try:
            with self.__tx_lock:
                if self.__socket is None:
                    raise RuntimeError()
                self.__socket.send(data)
        except Exception as exc:
            self.__log.exception('Fail on send')
            self.__fail = True
            raise exc

    def is_open(self):
        return self.__socket is not None

    @property
    def port_name(self) -> str:
        """Returns the name of the port

        Returns:
            str: String representation of the port
        """
        return f'{self.__target[0]}:{self.__target[1]}'

    def reconnect_on_fail(self, timeout: int = 30):
        with self.__rx_lock, self.__tx_lock:
            if not self.__fail:
                return
            start = dt.datetime.now()

            try:
                self.__socket.shutdown(socket.SHUT_RDWR)
                self.__socket.close()
            except Exception: # pylint: disable=broad-except
                # pass any exception - idea is to suppress and recover
                self.__log.exception('Failed to close on reconnect')

            self.__socket = None

            while (dt.datetime.now() - start).total_seconds() < timeout:
                try:
                    self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.__socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    self.__socket.connect(self.__target)
                except Exception: # pylint: disable=broad-except
                    # need to keep trying until timeout
                    self.__log.exception('Failed to open on reconnect')
                    time.sleep(1)
            raise FatalException('Unable to reconnect')

class TCPServer:
    """TCP Server Transport
    """
    def __init__(self,
                 port: int,
                 connection_handler: Callable[[AbstractTransport, int], None], addr: str = ''):
        '''
        Creates an RCTTCPServer object to be bound to the specified port.
        '''
        self.__log = logging.getLogger('RCT TCP Server')
        self.__port = port
        self.__socket: Optional[socket.socket] = None
        self._generator_thread: Optional[threading.Thread] = None
        self.__running: Optional[threading.Event] = None
        self.__host_addr = addr
        self.__connection_handler = connection_handler
        self.__connection_index = 0
        self.sim_list = []

    def open(self):
        '''
        Opens the server. Socket is created and generatorThread begins listening
        for new connections.
        '''
        # Use printed addr in rctconfig
        self.__log.info('Server started at %s', socket.gethostbyname(socket.gethostname()))

        error_time = 1
        while self.__socket is None:
            try:
                self.__running = threading.Event()
                self.__running.clear()
                self.__socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                self.__socket.settimeout(2)
                self.__socket.bind((self.__host_addr, self.__port))
                self.__log.info('Port is listening')
                self.__socket.listen()
            except Exception as exc: # pylint: disable=broad-except
                self.__running.set()
                self.__running = None
                self.__socket = None
                self.__log.exception('Failed to open port: %s', exc)
                time.sleep(error_time)
                error_time = min(2 * error_time, 10)
        self._generator_thread = threading.Thread(target=self.generator_loop,
                                                daemon=True)
        self._generator_thread.start()

    def generator_loop(self):
        '''
        Thread to accept new connections to the server. A new
        RCTTCPConnection object is made each time a client connects.
        '''

        while not self.__running.is_set():
            try:
                client_conn, client_addr = self.__socket.accept()
                self.__log.info('New connection accepted from %s', client_addr)
                if client_conn is not None and client_addr is not None:
                    new_connection = RCTTCPConnection(client_addr,
                                                      client_conn,
                                                      self.__connection_index)
                    self.__connection_handler(new_connection, self.__connection_index)
                    self.__connection_index += 1
                    self.sim_list.append(new_connection)
            except socket.timeout:
                pass
            except ConnectionAbortedError:
                break

    def close(self):
        '''
        Closes this server. GeneratorThread is stopped and all connections are
        closed.
        '''
        if self.__socket is None or self._generator_thread is None:
            raise RuntimeError()
        try:
            self.__running.set()
            self._generator_thread.join(timeout=2)
            self.__socket.close()
        finally:
            self.__socket = None
            self._generator_thread = None

    def is_open(self) -> bool:
        """Checks if the server connection exists

        Returns:
            bool: True if open, otherwise False
        """
        return self.__socket is not None

class RCTTCPConnection(AbstractTransport):
    """TCP Connection
    """
    def __init__(self, addr: Tuple[str, int], conn: socket.socket, idx: int):
        self.__addr = addr
        self.__socket = conn
        self.__id = idx
        self.__sel = selectors.DefaultSelector()
        data = types.SimpleNamespace(addr=self.__addr, inb=b'', outb=b'')
        self.__sel.register(self.__socket, selectors.EVENT_READ, data=data)

    def open(self):
        return

    def close(self):
        if self.__socket is None:
            raise RuntimeError()
        try:
            self.__sel.unregister(self.__socket)
            self.__socket.close()
        except Exception:
            pass

    def receive(self, buffer_len: int, timeout: int=None):
        if self.__socket is None:
            raise RuntimeError()
        if self.__addr is None:
            raise RuntimeError()

        events = self.__sel.select(timeout=timeout)
        if len(events) < 1:
            raise TimeoutError()

        for key, mask in events:
            if mask and selectors.EVENT_READ:
                recv_data = key.fileobj.recv(buffer_len)
                if recv_data:
                    return recv_data, self.__addr[0]
                else:
                    self.close()

        return None, self.__addr[0]


    def send(self, data: bytes, dest):
        # pylint: disable=unused-argument
        if self.__socket is None:
            raise RuntimeError()
        self.__socket.send(data)

    def is_open(self):
        return self.__socket is not None

    @property
    def port_name(self) -> str:
        """Returns the name of the port

        Returns:
            str: String representation of the port
        """
        return f'{self.__addr[0]}:{self.__addr[1]}'

class RCTSerialTransport(AbstractTransport):
    '''
    Serial Transport
    No client/server distinction
    '''
    def __init__(self, port: str, *, baudrate: int = 115200) -> None:
        '''
        Constructor for an RCTSerialTransport
        :param port: port to be used in underlying socket connection
        '''
        self.__port = port
        self.__serial: Optional[serial.Serial] = None
        self.__baudrate = baudrate
        self.__log = logging.getLogger(port)
        self.__log.setLevel(logging.WARNING)
        self.__fail = False
        self.__rx_lock = Lock()
        self.__tx_lock = Lock()

    @property
    def port_name(self) -> str:
        """Returns the name of the port

        Returns:
            str: String representation of the port
        """
        return self.__port

    def open(self) -> None:
        '''
        Open the serial port.
        '''
        if self.__serial is None:
            self.__serial = serial.Serial(self.__port, baudrate=self.__baudrate)
            if hasattr(self.__serial, 'set_buffer_size'):
                self.__serial.set_buffer_size(rx_size=65536)
        if not self.__serial.isOpen():
            self.__serial.open()
        self.__log.info('Opened')

    def receive(self, buffer_len: int, timeout: int=None) -> Tuple[bytes, str]:
        '''
        Receive up to buffer_len bytes of data from the port within timeout sec.

        :param buffer_len: Maximum number of bytes to return
        :param timeout: Maximum number of seconds to wait for data

        :return data, sender: Tuple containing the bytes received (data) and the
                machine which sent that data (sender)
        '''
        try:
            with self.__rx_lock:
                self.__log.debug('Started rx')
                if not self.is_open():
                    raise RuntimeError

                self.__serial.timeout = timeout
                self.__log.debug('Set timeout to %d', self.__serial.timeout)
                to_read = buffer_len
                self.__log.debug('Reading %d bytes', to_read)
                data = self.__serial.read(to_read)
                self.__log.debug('Got %d bytes', len(data))

                if len(data) == 0:
                    raise TimeoutError

                return data, self.__port
        except TimeoutError as exc:
            raise exc
        except Exception as exc:
            self.__log.exception('Fail during receive')
            self.__fail = True
            raise exc

    def send(self, data: bytes, dest) -> None:
        '''
        Send given data to the specified destination from the port.

        :param data: Data to transmit
        :param dest: Destination to route data to
        '''
        try:
            with self.__tx_lock:
                if not self.is_open():
                    raise RuntimeError

                self.__serial.write(data)
        except Exception as exc:
            self.__log.exception('Fail during send')
            self.__fail = True
            raise exc

    def close(self) -> None:
        '''
        Close the underlying port.
        This function shall release the underlying port to be used by other
            processes.
        Subsequent calls to open() shall not fail if the port is available for
            this process to own.
        '''
        with self.__tx_lock, self.__tx_lock:
            if self.__serial is not None:
                self.__serial.close()
            self.__fail = False

    def is_open(self) -> bool:
        '''
        Return True if the port is open, False otherwise
        '''
        if self.__serial is None:
            return False
        return self.__serial.isOpen()

    def reconnect_on_fail(self, timeout: int = 30):
        """Reconnects this transport if failed

        Args:
            timeout (int, optional): Timeout. Defaults to 30.

        Raises:
            FatalException: Unable to reconnect
        """
        self.__log.warning('Starting reconnect')
        with self.__tx_lock, self.__rx_lock:
            if not self.__fail:
                return
            start = dt.datetime.now()

            try:
                self.__serial.close()
            except Exception:   # pylint: disable=broad-except
                # pass any exception - idea is to suppress and recover
                self.__log.exception('Failed to close on reconnect')

            self.__serial = None    # This should delete the serial object, though we won't know
            while (dt.datetime.now() - start).total_seconds() < timeout:
                try:
                    self.__serial = serial.Serial(self.__port, baudrate=self.__baudrate)
                    self.__log.info('Reconnected')
                    return
                except Exception: # pylint: disable=broad-except
                    # need to keep trying until timeout
                    self.__log.exception('Failed to open on reconnect')
                    time.sleep(1)
            self.__log.fatal('Unable to reconnect')
            raise FatalException('Unable to reconnect')


class RCTTransportFactory:
    """Enables creating transports from a string specification
    """
    # pylint: disable=too-few-public-methods
    # This is a factory class with a single creation routine
    @classmethod
    def create_transport(cls, spec: str) -> AbstractTransport:
        """Creates a new transport based on a string specification.

        | Type          | Resulting Object      | Syntax                            |
        |---------------|-----------------------|-----------------------------------|
        | Serial        | RCTSerialTransport    | serial:{device}?baud={baudrate}   |
        | TCP Client    | RCTTCPClient          | tcpc://{hostname}:{port}          |

        Args:
            spec (str): String specification of desired transport

        Raises:
            RuntimeError: Unrecognized transport

        Returns:
            RCTAbstractTransport: Created transport
        """
        logger = logging.getLogger('Transport Factory')
        logger.debug('Parsing %s', spec)
        result, factory = cls.parse_spec(spec)
        logger.info('Recognized scheme %s pointed towards %s', result.scheme, result.netloc)
        return factory(result)

    @classmethod
    def parse_spec(cls, spec: str) -> \
            Tuple[ParseResult, Callable[[ParseResult], AbstractTransport]]:
        """Parses the specified spec

        Raises:
            RuntimeError: Unrecognized schema

        Returns:
            Tuple[ParseResult, Callable[[ParseResult], RCTAbstractTransport]]: Parse result and
            factory function
        """
        transport_map: Dict[ParseResult, Callable[[ParseResult], AbstractTransport]] = {
            'udps': cls.__create_udpserver,
            'udpc': cls.__create_udpclient,
            'tcpc': cls.__create_tcpclient,
            'tcps': cls.__create_tcpserver,
            'serial': cls.__create_serial,
        }
        result = urlparse(spec)
        if result.scheme not in transport_map:
            raise RuntimeError(f'Unrecognized transport {result.scheme}')
        factory = transport_map[result.scheme]
        return result,factory

    @classmethod
    def __create_udpclient(cls, spec: ParseResult) -> UDPClient:
        raise NotImplementedError

    @classmethod
    def __create_udpserver(cls, spec: ParseResult) -> UDPServer:
        raise NotImplementedError

    @classmethod
    def __create_tcpclient(cls, spec: ParseResult) -> TCPClient:
        return TCPClient(port=spec.port, addr=spec.netloc)

    @classmethod
    def __create_tcpserver(cls, spec: ParseResult) -> RCTTCPConnection:
        raise NotImplementedError

    @classmethod
    def __create_serial(cls, spec: ParseResult) -> RCTSerialTransport:
        args = cls.extract_serial_args(spec)
        return RCTSerialTransport(**args)

    @classmethod
    def extract_serial_args(cls, spec: ParseResult) -> Dict[str, Any]:
        """Extracts the serial arguments from the specified spec string

        Args:
            spec (ParseResult): Transport specification

        Raises:
            RuntimeError: Empty device

        Returns:
            Dict[str, Any]: Serial Transport args
        """
        schema = Schema({
            'baud': [Or(int, str)]
        })
        params = schema.validate(parse_qs(spec.query))
        args = {
            'port': spec.path,
            'baudrate': int(params['baud'][0])
        }
        if args['port'] == '':
            raise RuntimeError(f'Unknown device {spec.path}')
        return args
