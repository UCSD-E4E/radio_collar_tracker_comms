'''Radio Collar Tracker Communication Transport Abstractions
'''

import abc
import logging
import os
import select
import selectors
import socket
import threading
import time
import types
from typing import Callable, Dict, Optional, Tuple
from urllib.parse import ParseResult, parse_qs, urlparse

import serial
from schema import Schema, Or


class RCTAbstractTransport(abc.ABC):
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
    def isOpen(self) -> bool:
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


class RCTUDPClient(RCTAbstractTransport):
    def __init__(self, port: int):
        self.__socket: Optional[socket.socket] = None
        self.__port = port

    def open(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__socket.bind(("", self.__port))

    def close(self):
        try:
            self.__socket.close()
        finally:
            self.__socket = None

    def receive(self, buffer_len: int, timeout: int=None):
        if self.__socket is None:
            raise RuntimeError()
        ready = select.select([self.__socket], [], [], timeout)
        if len(ready[0]) == 1:
            data, addr = self.__socket.recvfrom(buffer_len)
            return data, addr[0]
        else:
            raise TimeoutError

    def send(self, data: bytes, dest):
        if self.__socket is None:
            raise RuntimeError()
        self.__socket.sendto(data, (dest, self.__port))

    def isOpen(self):
        return self.__socket is not None

    @property
    def port_name(self) -> str:
        """Returns the name of the port

        Returns:
            str: String representation of the port
        """
        return self.__port

class RCTUDPServer(RCTAbstractTransport):
    def __init__(self, port: int):
        self.__socket: Optional[socket.socket] = None
        self.__port = port

    def open(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.__socket.setblocking(False)
        self.__socket.bind(("", self.__port))

    def close(self):
        if self.__socket is None:
            raise RuntimeError()
        try:
            self.__socket.close()
        except:
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

    def isOpen(self):
        return self.__socket is not None

    @property
    def port_name(self) -> str:
        """Returns the name of the port

        Returns:
            str: String representation of the port
        """
        return self.__port


class RCTPipeClient(RCTAbstractTransport):
    def __init__(self):
        self.__inFile = None
        self.__outFile = None

    def open(self):
        if not os.path.exists("/tmp/rctClient2Simulator"):
            os.mkfifo('/tmp/rctClient2Simulator')
        if not os.path.exists("/tmp/rctSimulator2Client"):
            os.mkfifo('/tmp/rctSimulator2Client')

        self.__inFile = os.open(
            '/tmp/rctSimulator2Client', os.O_NONBLOCK | os.O_RDONLY)
        self.__outFile = open('/tmp/rctClient2Simulator', 'wb')

    def close(self):
        self.__inFile = None
        self.__outFile = None

    def receive(self, buffer_len: int, timeout: int = None):
        pass

    def send(self, data: bytes, dest):
        pass

    def isOpen(self):
        return self.__inFile is not None and self.__outFile is not None

    @property
    def port_name(self) -> str:
        """Returns the name of the port

        Returns:
            str: String representation of the port
        """
        return 'pipe'

class RCTTCPClient(RCTAbstractTransport):
    def __init__(self, port: int, addr: str):
        self.__target = (addr, port)
        self.__socket: Optional[socket.socket] = None

    def open(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.__socket.connect(self.__target)

    def close(self):
        if self.__socket is None:
            raise RuntimeError()
        try:
            self.__socket.shutdown(socket.SHUT_RDWR)
        except:
            pass
        self.__socket.close()
        self.__socket = None

    def receive(self, buffer_len: int, timeout: int=None):
        if self.__socket is None:
            raise RuntimeError()
        ready = select.select([self.__socket], [], [], timeout)
        if len(ready[0]) == 1:
            data = self.__socket.recv(buffer_len)
            return data, self.__target[0]
        else:
            raise TimeoutError

    def send(self, data: bytes, dest):
        # pylint: disable=unused-argument
        if self.__socket is None:
            raise RuntimeError()
        self.__socket.send(data)

    def isOpen(self):
        return self.__socket is not None

    @property
    def port_name(self) -> str:
        """Returns the name of the port

        Returns:
            str: String representation of the port
        """
        return f'{self.__target[0]}:{self.__target[1]}'

class RCTTCPServer:
    def __init__(self, port: int, connectionHandler: Callable[[RCTAbstractTransport, int], None], addr: str = ''):
        '''
        Creates an RCTTCPServer object to be bound to the specified port.
        '''
        self.__log = logging.getLogger('RCT TCP Server')
        self.__port = port
        self.__socket: Optional[socket.socket] = None
        self.__generatorThread: Optional[threading.Thread] = None
        self.__running: Optional[threading.Event] = None
        self.__hostAdr = addr
        self.__connection_handler = connectionHandler
        self.__connection_index = 0
        self.simList = []

    def open(self):
        '''
        Opens the server. Socket is created and generatorThread begins listening
        for new connections.
        '''
        # Use printed addr in rctconfig
        self.__log.info('Server started at {}'.format(
                        socket.gethostbyname(socket.gethostname())))

        error_time = 1
        while self.__socket is None:
            try:
                self.__running = threading.Event()
                self.__running.clear()
                self.__socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                self.__socket.settimeout(2)
                self.__socket.bind((self.__hostAdr, self.__port))
                self.__log.info('Port is listening')
                self.__socket.listen()
            except Exception as exc: # pylint: disable=broad-except
                self.__running.set()
                self.__running = None
                self.__socket = None
                self.__log.exception('Failed to open port: %s', exc)
                time.sleep(error_time)
                error_time = min(2 * error_time, 10)
        self.__generatorThread = threading.Thread(target=self.generatorLoop,
                                                daemon=True)
        self.__generatorThread.start()

    def generatorLoop(self):
        '''
        Thread to accept new connections to the server. A new
        RCTTCPConnection object is made each time a client connects.
        '''

        while not self.__running.is_set():
            try:
                clientConn, clientAddr = self.__socket.accept()
                self.__log.info('New connection accepted from {}'.format(clientAddr))
                if clientConn is not None and clientAddr is not None:
                    newConnection = RCTTCPConnection(clientAddr, clientConn, self.__connection_index)
                    self.__connection_handler(newConnection, self.__connection_index)
                    self.__connection_index += 1
                    self.simList.append(newConnection)
            except socket.timeout:
                pass
            except ConnectionAbortedError:
                break

    def close(self):
        '''
        Closes this server. GeneratorThread is stopped and all connections are
        closed.
        '''
        if self.__socket is None or self.__generatorThread is None:
            raise RuntimeError()
        try:
            self.__running.set()
            self.__generatorThread.join(timeout=2)
            self.__socket.close()
        finally:
            self.__socket = None
            self.__generatorThread = None

    def isOpen(self):
        return self.__socket is not None

class RCTTCPConnection(RCTAbstractTransport):
    def __init__(self, addr: Tuple[str, int], conn: socket.socket, id: int):
        self.__addr = addr
        self.__socket = conn
        self.__id = id
        self.__sel = selectors.DefaultSelector()
        data = types.SimpleNamespace(addr=self.__addr, inb=b"", outb=b"")
        self.__sel.register(self.__socket, selectors.EVENT_READ, data=data)

    def open(self):
        return

    def close(self):
        if self.__socket is None:
            raise RuntimeError()
        try:
            self.__sel.unregister(self.__socket)
            self.__socket.close()
        except:
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

    def isOpen(self):
        return self.__socket is not None

    @property
    def port_name(self) -> str:
        """Returns the name of the port

        Returns:
            str: String representation of the port
        """
        return f'{self.__addr[0]}:{self.__addr[1]}'

class RCTSerialTransport(RCTAbstractTransport):
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

    def receive(self, buffer_len: int, timeout: int=None) -> Tuple[bytes, str]:
        '''
        Receive up to buffer_len bytes of data from the port within timeout sec.

        :param buffer_len: Maximum number of bytes to return
        :param timeout: Maximum number of seconds to wait for data

        :return data, sender: Tuple containing the bytes received (data) and the
                machine which sent that data (sender)
        '''
        if not self.__serial.isOpen():
            raise RuntimeError

        self.__serial.timeout = timeout
        available = self.__serial.inWaiting()
        if available < buffer_len:
            data = self.__serial.read(available)
        else:
            data = self.__serial.read(buffer_len)

        if len(data) == 0:
            raise TimeoutError

        return data, self.__port

    def send(self, data: bytes, dest) -> None:
        '''
        Send given data to the specified destination from the port.

        :param data: Data to transmit
        :param dest: Destination to route data to
        '''
        if not self.__serial.isOpen():
            raise RuntimeError

        self.__serial.write(data)

    def close(self) -> None:
        '''
        Close the underlying port.
        This function shall release the underlying port to be used by other
            processes.
        Subsequent calls to open() shall not fail if the port is available for
            this process to own.
        '''
        if self.__serial is not None:
            self.__serial.close()

    def isOpen(self) -> bool:
        '''
        Return True if the port is open, False otherwise
        '''
        if self.__serial is None:
            return False
        return self.__serial.isOpen()

class RCTTransportFactory:
    """Enables creating transports from a string specification
    """
    # pylint: disable=too-few-public-methods
    # This is a factory class with a single creation routine
    @classmethod
    def create_transport(cls, spec: str) -> RCTAbstractTransport:
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
        transport_map: Dict[ParseResult, Callable[[ParseResult], RCTAbstractTransport]] = {
            'udps': cls.__create_udpserver,
            'udpc': cls.__create_udpclient,
            'tcpc': cls.__create_tcpclient,
            'tcps': cls.__create_tcpserver,
            'serial': cls.__create_serial,
        }
        result = urlparse(spec)
        if result.scheme not in transport_map:
            raise RuntimeError(f'Unrecognized transport {result.scheme}')
        return transport_map[result.scheme](result)

    @classmethod
    def __create_udpclient(cls, spec: ParseResult) -> RCTUDPClient:
        raise NotImplementedError

    @classmethod
    def __create_udpserver(cls, spec: ParseResult) -> RCTUDPServer:
        raise NotImplementedError

    @classmethod
    def __create_tcpclient(cls, spec: ParseResult) -> RCTTCPClient:
        return RCTTCPClient(port=spec.port, addr=spec.netloc)

    @classmethod
    def __create_tcpserver(cls, spec: ParseResult) -> RCTTCPConnection:
        raise NotImplementedError

    @classmethod
    def __create_serial(cls, spec: ParseResult) -> RCTSerialTransport:
        schema = Schema({
            'baud': [Or(int, str)]
        })
        params = schema.validate(parse_qs(spec.query))
        return RCTSerialTransport(spec.path, baudrate=int(params['baud'][0]))
