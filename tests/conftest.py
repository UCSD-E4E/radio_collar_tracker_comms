'''Comms Test Support
'''
import logging
import time
from dataclasses import dataclass
from queue import Empty, Queue
from typing import Tuple

import pytest

from rctcomms.comms import GcsComms, MavComms, HeartbeatPacket
from rctcomms.transport import AbstractTransport, FatalException


class RCTQueueTransport(AbstractTransport):
    """Queue based transport for testing
    """
    def __init__(self,
                 rx_q: "Queue[bytes]",
                 tx_q: "Queue[bytes]",
                 name: str) -> None:
        self.rx_q = rx_q
        self.tx_q = tx_q
        self.__open = False
        self.__log = logging.getLogger(name)
        self.__name = name
        super().__init__()

    def open(self) -> None:
        assert not self.__open
        self.__open = True

    def receive(self, buffer_len: int, timeout: int = None) -> Tuple[bytes, str]:
        assert self.__open
        try:
            data = self.rx_q.get(timeout=timeout)
            self.__log.info('Received %s', data)
        except Empty as exc:
            raise TimeoutError from exc
        return data, ''

    def send(self, data: bytes, dest) -> None:
        assert self.__open
        self.__log.info('Put %s', data)
        self.tx_q.put(data)

    def close(self) -> None:
        assert self.__open
        self.__open = False

    def is_open(self) -> bool:
        return self.__open

    @property
    def port_name(self) -> str:
        return self.__name

    def reconnect_on_fail(self, timeout: int = 30):
        raise FatalException

@dataclass
class CommsPair:
    """Pair of MAV/GCS comms
    """
    gcs: GcsComms
    mav: MavComms


@pytest.fixture(name='comms')
def create_comms() -> CommsPair:
    """Creates a Comms Pair

    Raises:
        TimeoutError: Failed to setup pair

    Returns:
        CommsPair: Comms Pair

    Yields:
        Iterator[CommsPair]: _description_
    """
    to_queue = Queue()
    from_queue = Queue()
    server = RCTQueueTransport(rx_q=to_queue, tx_q=from_queue, name='server')
    client = RCTQueueTransport(rx_q=from_queue, tx_q=to_queue, name='client')
    mav = MavComms(client)
    mav.start()
    mav.send_packet(HeartbeatPacket(0, 0, 0, 0, 0), '')
    time.sleep(1)

    gcs = GcsComms(server)
    gcs.start()

    yield CommsPair(gcs, mav)
    mav.stop()
    gcs.stop()
