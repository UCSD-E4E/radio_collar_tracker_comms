import queue
import random
import socket
import threading

from dataclasses import dataclass
from typing import Tuple

import pytest
from RCTComms.transport import (RCTAbstractTransport, RCTTCPClient,
                                RCTTCPServer, RCTUDPClient, RCTUDPServer)

NUM_TRIALS = 128
TARGET_IP = '127.0.0.1'

@dataclass
class TransportPair:
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

def server_connection_handler(connection, id):
    return

def server_disconnect_handler():
    return

@pytest.fixture(name='transport_pair')
def create_transport_pair(request):
    """
    Creates a transport pair

    Args:
        request (pytest.FixtureRequest): Fixture Request

    Raises:
        RuntimeError: Unknown socket type
        TimeoutError: Failed to connect

    Yields:
        TransportPair: Pair of active transports
    """
    with socket.socket() as sock:
        sock.bind(('', 0))
        port = sock.getsockname()[1]
    if request.param == 'tcp':
        server = RCTTCPServer(port, server_connection_handler)
        client = RCTTCPClient(port, TARGET_IP)

        server_open_thread = threading.Thread(target=transport_open, args=(server,))
        client_open_thread = threading.Thread(target=transport_open, args=(client,))
        server_open_thread.start()
        client_open_thread.start()
        while len(server.simList) < 1:
            continue
        client_open_thread.join(timeout=5)
        server_open_thread.join(timeout=5)

        server_connection = server.simList[0]
        transport_pair = TransportPair(client, server_connection)

    elif request.param == 'udp':
        transport_pair = TransportPair(RCTUDPClient(port), RCTUDPServer(port))
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
    try:
        transport_pair.client.close()
        transport_pair.server.close()
    except:
        pass


@pytest.mark.timeout(20)
@pytest.mark.parametrize('transport_pair', ['tcp', 'udp'], indirect=True)
def test_open(transport_pair: TransportPair):

    client = transport_pair.client
    server = transport_pair.server

    assert(client.isOpen())
    assert(server.isOpen())

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
@pytest.mark.parametrize('transport_pair', ['tcp', 'udp'], indirect=True)
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
        assert origin == TARGET_IP
    stop_event.set()
    rcvr.join()
    assert not rcvr.is_alive()
