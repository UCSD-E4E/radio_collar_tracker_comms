"""
Transport tests for serial transport class
"""
import pytest
import queue
import random
import threading

from dataclasses import dataclass
from typing import Tuple

from RCTComms.transport import (RCTAbstractTransport, RCTSerialTransport)

NUM_TRIALS = 128
TARGET_IP = '127.0.0.1'
TARGET_PORT = 'COM2'

@dataclass
class TransportPair:
    '''
    Dataclass to store two abstract transport objects, a client and a server
    which are paired together.
    '''
    client: RCTAbstractTransport
    server: RCTAbstractTransport

def transport_open(transport: RCTAbstractTransport):
    """
    Attempts to open the transport

    Args:
        transport (RCTAbstractTransport): Transport to open
    """
    while True:
        try:
            transport.open()
            return
        except ConnectionError:
            continue

@pytest.fixture(name='transport_pair')
def create_transport_pair(request, serial_pair):
    """
    Creates a transport pair

    Args:
        request (pytest.FixtureRequest): Fixture Request

    Raises:
        RuntimeError: Unknown transport type
        TimeoutError: Failed to connect

    Yields:
        TransportPair: Pair of active transports
    """

    if request.param == 'serial':
        # install com0com pair 'COM1' and 'COM2' to test
        transport_pair = TransportPair(RCTSerialTransport(serial_pair[0]), RCTSerialTransport(serial_pair[1]))
        server_open_thread = threading.Thread(target=transport_open, args=(transport_pair.server,))
        client_open_thread = threading.Thread(target=transport_open, args=(transport_pair.client,))
        server_open_thread.start()
        client_open_thread.start()
        client_open_thread.join(timeout=5)
        server_open_thread.join(timeout=5)
    else:
        raise RuntimeError

    if client_open_thread.is_alive() or server_open_thread.is_alive():
        raise TimeoutError()

    yield transport_pair
    transport_pair.server.close()
    transport_pair.client.close()

@pytest.mark.timeout(20)
@pytest.mark.parametrize('transport_pair', ['serial'], indirect=True)
def test_open(transport_pair: TransportPair):
    """
    Tests that transport objects open correctly

    Args:
        transport_pair (TransportPair): Transport Pair
    """

    client = transport_pair.client
    server = transport_pair.server

    assert client.isOpen()
    assert server.isOpen()

def rx_thread(server: RCTAbstractTransport, stop_event: threading.Event, data_queue: queue.Queue):
    """
    test_data receiver thread

    Args:
        server (RCTAbstractTransport): Transport server
        stop_event (threading.Event): Stop Event
        data_queue (queue.Queue): Return queue
    """
    while not stop_event.is_set():
        try:
            retval = server.receive(65536, 1)
        except TimeoutError:
            continue
        if retval is not None:
            data_queue.put(retval)

@pytest.mark.timeout(20)
@pytest.mark.parametrize('transport_pair', ['serial'], indirect=True)
def test_data(transport_pair: TransportPair):
    """
    Tests the data throughput

    Args:
        transport_pair (TransportPair): Transport Pair
    """
    random.seed(0)
    rx_queue: queue.Queue[Tuple[bytes, str]] = queue.Queue()
    stop_event = threading.Event()
    rcvr = threading.Thread(
        target=rx_thread,
        args=(transport_pair.server, stop_event, rx_queue),
        name='rx_thread'
    )
    rcvr.start()
    for _ in range(NUM_TRIALS):
        data_size = random.randint(0, 65535)
        sim_data = bytes([random.randint(0, 255) for _ in range(data_size)])
        transport_pair.client.send(sim_data, TARGET_IP)
        retval = rx_queue.get(True, timeout=10)
        assert retval is not None
        recv_data, origin = retval
        assert recv_data == sim_data
        assert origin == transport_pair.server.port_name
    stop_event.set()
    rcvr.join()
    assert not rcvr.is_alive()
