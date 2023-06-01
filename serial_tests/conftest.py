'''Test Fixtures
'''
import logging
import os
import pty
import tty
from contextlib import ExitStack
from io import FileIO
from selectors import EVENT_READ
from selectors import DefaultSelector as Selector
from threading import Thread
from typing import Dict, Tuple

import pytest


class VirtualSerialPortPair:
    """Virtual Serial Port Pair

    Logic adapted from https://github.com/ezramorris/PyVirtualSerialPorts/
    """
    def __init__(self, loopback: bool = False, debug: bool = False):
        self.__loopback = loopback
        self.__debug = debug
        self.__master_files: Dict[int, FileIO] = {}
        self.__slave_names = {}
        self.__thread = Thread(target=self.__echo, daemon=True)
        self.__logger = logging.getLogger(f'VirtualSerialPortPair {id(self)}')

    def __enter__(self):
        for _ in range(2):
            master_fd, slave_fd = pty.openpty()
            tty.setraw(master_fd)
            os.set_blocking(master_fd, False)
            slave_name = os.ttyname(slave_fd)
            self.__master_files[master_fd] = open(master_fd, 'r+b', buffering=0)
            self.__slave_names[master_fd] = slave_name
        self.__thread.start()
        return self

    def __echo(self):
        with Selector() as selector, ExitStack() as stack:
            for descriptor, handle in self.__master_files.items():
                stack.enter_context(handle)
                selector.register(descriptor, EVENT_READ)

            while True:
                for key, events in selector.select():
                    if not events & EVENT_READ:
                        continue

                    data = self.__master_files[key.fileobj].read()
                    if self.__debug:
                        self.__logger.info((self.__slave_names[key.fileobj], data))

                    for descriptor, handle in self.__master_files.items():
                        if self.__loopback or descriptor != key.fileobj:
                            handle.write(data)

    @property
    def ports(self) -> Tuple[str, str]:
        """Returns the port names
        """
        return tuple(self.__slave_names.values())

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.__slave_names = {}
        for handle in self.__master_files.values():
            handle.close()

@pytest.fixture(name='serial_pair', scope='session')
def create_serial_pair() -> Tuple[str, str]:
    """Creates a serial port pair for testing

    Returns:
        Tuple[str, str]: Serial Port Pair

    Yields:
        Iterator[Tuple[str, str]]: Serial port Pair
    """
    with VirtualSerialPortPair() as port_pair:
        ports = port_pair.ports
        yield ports
