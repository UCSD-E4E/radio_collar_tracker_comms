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
    transport.open()
    
@pytest.fixture
def transportPair(request):

    with socket.socket() as s:
        s.bind(('', 0))
        port = s.getsockname()[1]
    if request.param == 'tcp':
        transport_pair = TransportPair(RCTTCPClient(port, TARGET_IP), RCTTCPServer(port))
    elif request.param == 'udp':
        transport_pair = TransportPair(RCTUDPClient(port), RCTUDPServer(port))
    else:
        raise RuntimeError

    server_open_thread = threading.Thread(target=transport_open, args=(transport_pair.server,))
    client_open_thread = threading.Thread(target=transport_open, args=(transport_pair.client,))
    server_open_thread.start()
    client_open_thread.start()
    client_open_thread.join(timeout=5)
    server_open_thread.join(timeout=5)
    if client_open_thread.is_alive() or server_open_thread.is_alive():
        raise TimeoutError()

    yield transport_pair
    try:
        transport_pair.client.close()
        transport_pair.server.close()
    except:
        pass


@pytest.mark.parametrize('transportPair', ['tcp', 'udp'], indirect=True)
def test_open(transportPair: TransportPair):

    client = transportPair.client
    server = transportPair.server

    assert(client.isOpen())
    assert(server.isOpen())

@pytest.mark.parametrize('transportPair', ['tcp'], indirect=True)
def test_data(transportPair: TransportPair):
    def rx_thread(server: RCTAbstractTransport, stopEvent: threading.Event, data_queue: queue.Queue):
        while not stopEvent.is_set():
            try:
                retval = server.receive(65536, 1)
            except TimeoutError:
                continue
            if retval is not None:
                data_queue.put(retval)
    random.seed(0)
    rx_queue: queue.Queue[Tuple[bytes, str]] = queue.Queue()
    stop_event = threading.Event()
    rx = threading.Thread(target=rx_thread, args=(transportPair.server, stop_event, rx_queue))
    rx.start()
    for _ in range(NUM_TRIALS):
        data_size = random.randint(0, 65535)
        test_data = bytes([random.randint(0, 255) for _ in range(data_size)])
        transportPair.client.send(test_data, TARGET_IP)
        retval = rx_queue.get(True, timeout=5)
        assert(retval is not None)
        recv_data, origin = retval
        assert(recv_data == test_data)
        assert(origin == TARGET_IP)
    stop_event.set()
    rx.join()
    assert(not rx.is_alive())
