import itertools
import queue
import socket
import threading
import time
from dataclasses import dataclass
from os import urandom
from random import randint, random, randrange, seed
from typing import Any, Dict, List, Tuple, Union

import pytest

from RCTComms.comms import (EVENTS, OPTIONS_SCOPE, gcsComms, mavComms,
                            rctACKCommand, rctExceptionPacket,
                            rctFrequenciesPacket, rctGETFCommand,
                            rctGETOPTCommand, rctHeartBeatPacket,
                            rctOptionsPacket, rctPingPacket, rctSETFCommand,
                            rctSETOPTCommand, rctSTARTCommand, rctSTOPCommand,
                            rctUPGRADECommand, rctUpgradePacket,
                            rctUpgradeStatusPacket, rctVehiclePacket)
from RCTComms.transport import RCTTCPClient, RCTTCPServer


@dataclass
class CommsPair:
    """Pair of MAV/GCS comms
    """
    gcs: gcsComms
    mav: mavComms

def start_gcs(gcs: gcsComms):
    """GCS Start Logic

    Args:
        gcs (gcsComms): GCS Object
    """
    gcs.start()

def start_mav(mav: mavComms):
    """MAV Start Logics

    Args:
        mav (mavComms): MAV Ovject
    """
    mav.start()
    mav.sendToGCS(rctHeartBeatPacket(0, 0, 0, 0, 0))

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
    addr = '127.0.0.1'
    with socket.socket() as sock:
        sock.bind(('', 0))
        port = sock.getsockname()[1]
    server = RCTTCPServer(port)
    client = RCTTCPClient(port, addr)
    gcs = gcsComms(server)
    mav = mavComms(client)

    gcs_start = threading.Thread(target=start_gcs, args=(gcs,), name='gcs_start')
    mav_start = threading.Thread(target=start_mav, args=(mav,), name='mav_start')
    gcs_start.start()
    time.sleep(0.5)
    mav_start.start()
    mav_start.join(timeout=1)
    gcs_start.join(timeout=1)
    if mav_start.is_alive() or gcs_start.is_alive():
        raise TimeoutError()

    yield CommsPair(gcs, mav)

    mav.stop()
    gcs.stop()


def test_heartbeat(comms: CommsPair):
    """Tests heartbeats

    Args:
        comms (CommsPair): Comms Pair
    """
    heartbeat_queue: "queue.Queue[rctHeartBeatPacket]" = queue.Queue()
    def cb_(packet: rctHeartBeatPacket, addr: str): # pylint: disable=unused-argument
        heartbeat_queue.put(packet)

    comms.gcs.registerCallback(EVENTS.STATUS_HEARTBEAT, cb_)
    params = [
        [e.value for e in rctHeartBeatPacket.SYS_STATES],
        [e.value for e in rctHeartBeatPacket.SDR_STATES],
        [e.value for e in rctHeartBeatPacket.EXT_SENSOR_STATES],
        [e.value for e in rctHeartBeatPacket.STORAGE_STATES],
        [e.value for e in rctHeartBeatPacket.SW_STATES],
    ]
    for param in itertools.product(*params):
        heartbeat = rctHeartBeatPacket(*param)
        comms.mav.sendToGCS(heartbeat)
        rx_ = heartbeat_queue.get(True, timeout=2)
        assert rx_ == heartbeat
        assert rx_.systemState == heartbeat.systemState
        assert rx_.sdrState == heartbeat.sdrState
        assert rx_.sensorState == heartbeat.sensorState
        assert rx_.storageState == heartbeat.storageState
        assert rx_.switchState == heartbeat.switchState
        assert abs((rx_.timestamp - heartbeat.timestamp).total_seconds()) < 1e-3

def test_exception(comms: CommsPair):
    """Tests exceptions

    Args:
        comms (CommsPair): Comms Pair
    """
    exc_queue: "queue.Queue[rctExceptionPacket]" = queue.Queue()
    def cb_(packet: rctExceptionPacket, addr: str): # pylint: disable=unused-argument
        exc_queue.put(packet)

    comms.gcs.registerCallback(EVENTS.STATUS_EXCEPTION, cb_)

    exc = rctExceptionPacket('test_exc', 'test_tb')
    comms.mav.sendToGCS(exc)
    rx_ = exc_queue.get(True, timeout=2)
    assert rx_ == exc
    assert rx_.exception == exc.exception
    assert rx_.traceback == exc.traceback

@pytest.mark.parametrize('n_freqs', [1, 2, 4, 8])
def test_frequencies(comms: CommsPair, n_freqs: int):
    """Tests sending frequencies

    Args:
        comms (CommsPair): Comms Pair
        n_freqs (int): Number of frequencies
    """
    pkt_queue: "queue.Queue[rctFrequenciesPacket]" = queue.Queue()
    def cb_(packet: rctFrequenciesPacket, addr: str): # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.mav.registerCallback(EVENTS.CONFIG_FREQUENCIES, cb_)

    freqs = rctFrequenciesPacket([randint(172000000, 174000000) for _ in range(n_freqs)])
    comms.gcs.sendPacket(freqs)

    rx_ = pkt_queue.get(True, timeout=2)
    assert rx_ == freqs
    assert rx_.frequencies == freqs.frequencies

@pytest.mark.parametrize('opt_scope',
    [
         # pylint: disable=protected-access
        (OPTIONS_SCOPE.BASE_OPTIONS, OPTIONS_SCOPE._baseOptionKeywords),
        (OPTIONS_SCOPE.EXP_OPTIONS,
            OPTIONS_SCOPE._baseOptionKeywords + OPTIONS_SCOPE._expOptionKeywords),
        (OPTIONS_SCOPE.ENG_OPTIONS,
            OPTIONS_SCOPE._baseOptionKeywords + OPTIONS_SCOPE._expOptionKeywords +\
            OPTIONS_SCOPE._engOptionKeywords)
    ])
def test_options(comms: CommsPair, opt_scope: Tuple[int, List[str]]):
    """Test sending options

    Args:
        comms (CommsPair): Comms Pair
        opt_scope (Tuple[int, List[str]]): Scope of options
    """
    seed(0)
    pkt_queue: "queue.Queue[rctOptionsPacket]" = queue.Queue()
    def cb_(packet: rctOptionsPacket, addr: str): # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.mav.registerCallback(EVENTS.CONFIG_OPTIONS, cb_)

    scope = opt_scope[0]
    options: Dict[str, Any] = {}

    populate_params(options, opt_scope[1])

    opt = rctOptionsPacket(scope, **options)
    comms.gcs.sendPacket(opt)

    rx_ = pkt_queue.get(True, timeout=1)

    assert rx_ == opt
    for key in opt_scope[1]:
        verify_option_key(opt, rx_, key)

def verify_option_key(opt: Union[rctOptionsPacket, rctSETOPTCommand], rx: Union[rctOptionsPacket, rctSETOPTCommand], key: str):
    assert(key in rx.options)
    assert(key in opt.options)
    if isinstance(rx.options[key], (int, str)):
        assert(rx.options[key] == opt.options[key])
    elif isinstance(rx.options[key], float):
        assert(abs(rx.options[key] - opt.options[key]) < 1e-3)
    else:
        raise NotImplementedError(type(rx.options[key]))

def populate_params(options: Dict[str, Any], params: List[str]):
    for kw in params:
        kw_param = OPTIONS_SCOPE.kw_types[kw]
        if "<L" == kw_param.fmt:
            options[kw] = randint(0, 2**32 - 1)
        elif "<B" == kw_param.fmt:
            options[kw] = randint(0, 2**8 - 1)
        elif "<f" == kw_param.fmt:
            options[kw] = random() * 100
        elif 's' == kw_param.fmt:
            options[kw] = f'{random() * 100}'
        elif '<?' == kw_param.fmt:
            options[kw] = random() > 0.5
        else:
            raise NotImplementedError(kw_param.fmt)

def test_upgradeStatusPacket(comms: CommsPair):
    seed(0)
    pkt_queue: queue.Queue[rctUpgradeStatusPacket] = queue.Queue()
    def cb(packet: rctUpgradeStatusPacket, addr: str):
        pkt_queue.put(packet)

    comms.gcs.registerCallback(EVENTS.UPGRADE_STATUS, cb)

    states = [rctUpgradeStatusPacket.UPGRADE_READY,
              rctUpgradeStatusPacket.UPGRADE_PROGRESS,
              rctUpgradeStatusPacket.UPGRADE_COMPLETE,
              rctUpgradeStatusPacket.UPGRADE_FAILED]
    msg =  ['rctUpgradeStatusPacket.UPGRADE_READY',
              'rctUpgradeStatusPacket.UPGRADE_PROGRESS',
              'rctUpgradeStatusPacket.UPGRADE_COMPLETE',
              'rctUpgradeStatusPacket.UPGRADE_FAILED']
    for i in range(len(states)):
        pkt = rctUpgradeStatusPacket(states[i], msg[i])
        comms.mav.sendToGCS(pkt)

        rx = pkt_queue.get(True, timeout=1)

        assert(rx == pkt)
        assert(rx.state == states[i])
        assert(rx.msg == msg[i])

def test_upgradePacket(comms: CommsPair):
    seed(0)
    
    pkt_queue: queue.Queue[rctUpgradePacket] = queue.Queue()
    def cb(packet: rctUpgradePacket, addr: str):
        pkt_queue.put(packet)

    comms.mav.registerCallback(EVENTS.UPGRADE_DATA, cb)

    img = urandom(16384)
    pkt_num = 1
    total_packets = 3
    pkt = rctUpgradePacket(pkt_num, total_packets, img)

    comms.gcs.sendPacket(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert(rx == pkt)
    assert(rx.numPacket == pkt_num)
    assert(rx.numTotal == total_packets)
    assert(rx.fileBytes == img)

def test_vehicle(comms: CommsPair):
    seed(0)

    pkt_queue: queue.Queue[rctVehiclePacket] = queue.Queue()
    def cb(packet: rctVehiclePacket, addr: str):
        pkt_queue.put(packet)

    comms.gcs.registerCallback(EVENTS.DATA_VEHICLE, cb)

    params: Dict[str, Any] = {
        'lat': (random() - 0.5) * 180,
        'lon': (random() - 0.5) * 360,
        'alt': random() * 400,
        'hdg': randint(0, 359),
    }

    pkt = rctVehiclePacket(**params)
    assert(abs(pkt.lat - params['lat']) < 1e-7)
    assert(abs(pkt.lon - params['lon']) < 1e-7)
    assert(abs(pkt.alt - params['alt']) < 1e-1)
    assert(abs(pkt.hdg - params['hdg']) < 0.5)

    comms.mav.sendToGCS(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert(rx == pkt)
    assert(abs(rx.lat - params['lat']) < 1e-7)
    assert(abs(rx.lon - params['lon']) < 1e-7)
    assert(abs(rx.alt - params['alt']) < 1e-1)
    assert(abs(rx.hdg - params['hdg']) < 0.5)

def test_pingPacket(comms: CommsPair):
    seed(0)

    pkt_queue: queue.Queue[rctPingPacket] = queue.Queue()
    def cb(packet: rctPingPacket, addr: str):
        pkt_queue.put(packet)

    comms.gcs.registerCallback(EVENTS.DATA_PING, cb)

    params: Dict[str, Any] = {
        'lat': (random() - 0.5) * 180,
        'lon': (random() - 0.5) * 360,
        'alt': random() * 400,
        'txp': random() * 50,
        'txf': randint(170000000, 180000000)
    }

    pkt = rctPingPacket(**params)
    assert(abs(pkt.lat - params['lat']) < 1e-7)
    assert(abs(pkt.lon - params['lon']) < 1e-7)
    assert(abs(pkt.alt - params['alt']) < 1e-1)
    assert(abs(pkt.txp - params['txp']) < 1e-6)
    assert(pkt.txf == params['txf'])

    comms.mav.sendToGCS(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt
    assert abs(rx.lat - params['lat']) < 1e-7
    assert abs(rx.lon - params['lon']) < 1e-7
    assert abs(rx.alt - params['alt']) < 1e-1
    assert abs(rx.txp - params['txp']) < 1e-6
    assert rx.txf == params['txf']

def test_cmdAck(comms: CommsPair):
    seed(0)

    pkt_queue: queue.Queue[rctACKCommand] = queue.Queue()
    def cb(packet: rctACKCommand, addr: str):
        pkt_queue.put(packet)

    comms.gcs.registerCallback(EVENTS.COMMAND_ACK, cb)

    params: Dict[str, Any] = {
        'commandID': randint(0, 255),
        'ack': random() > 0.5
    }

    pkt = rctACKCommand(**params)
    assert pkt.commandID == params['commandID']
    assert pkt.ack == params['ack']

    comms.mav.sendToGCS(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt
    assert rx.commandID == params['commandID']
    assert rx.ack == params['ack']

def test_getFCmd(comms: CommsPair):
    seed(0)

    pkt_queue: queue.Queue[rctGETFCommand] = queue.Queue()
    def cb(packet: rctGETFCommand, addr: str):
        pkt_queue.put(packet)

    comms.mav.registerCallback(EVENTS.COMMAND_GETF, cb)

    params: Dict[str, Any] = {
    }

    pkt = rctGETFCommand(**params)

    comms.gcs.sendPacket(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt

def test_setFCmd(comms: CommsPair):
    seed(0)

    pkt_queue: queue.Queue[rctSETFCommand] = queue.Queue()
    def cb(packet: rctSETFCommand, addr: str):
        pkt_queue.put(packet)

    comms.mav.registerCallback(EVENTS.COMMAND_SETF, cb)

    params: Dict[str, Any] = {
        'frequencies': [randint(170000000, 180000000) for _ in range(randint(0, 16))]
    }

    pkt = rctSETFCommand(**params)
    assert pkt.frequencies == params['frequencies']

    comms.gcs.sendPacket(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt
    assert rx.frequencies == params['frequencies']

def test_getOptCmd(comms: CommsPair):
    seed(0)

    pkt_queue: queue.Queue[rctGETOPTCommand] = queue.Queue()
    def cb(packet: rctGETOPTCommand, addr: str):
        pkt_queue.put(packet)

    comms.mav.registerCallback(EVENTS.COMMAND_GETOPT, cb)

    params: Dict[str, Any] = {
        'scope': randint(0, 255)
    }

    pkt = rctGETOPTCommand(**params)
    assert pkt.scope == params['scope']

    comms.gcs.sendPacket(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt
    assert rx.scope == params['scope']

@pytest.mark.parametrize('opt_scope',
    [
        (OPTIONS_SCOPE.BASE_OPTIONS, OPTIONS_SCOPE._baseOptionKeywords),
        (OPTIONS_SCOPE.EXP_OPTIONS, OPTIONS_SCOPE._baseOptionKeywords + OPTIONS_SCOPE._expOptionKeywords),
        (OPTIONS_SCOPE.ENG_OPTIONS, OPTIONS_SCOPE._baseOptionKeywords + OPTIONS_SCOPE._expOptionKeywords + OPTIONS_SCOPE._engOptionKeywords)
    ])
def test_setOptCmd(comms: CommsPair, opt_scope):
    seed(0)
    pkt_queue: queue.Queue[rctSETOPTCommand] = queue.Queue()
    def cb(packet: rctSETOPTCommand, addr: str):
        pkt_queue.put(packet)

    comms.mav.registerCallback(EVENTS.COMMAND_SETOPT, cb)

    scope = opt_scope[0]
    options: Dict[str, Any] = {}

    populate_params(options, opt_scope[1])

    opt = rctSETOPTCommand(scope, **options)
    comms.gcs.sendPacket(opt)

    rx = pkt_queue.get(True, timeout=1)

    assert rx == opt
    for key in opt_scope[1]:
        verify_option_key(opt, rx, key)

def test_startCmd(comms: CommsPair):
    seed(0)

    pkt_queue: queue.Queue[rctSTARTCommand] = queue.Queue()
    def cb(packet: rctSTARTCommand, addr: str):
        pkt_queue.put(packet)

    comms.mav.registerCallback(EVENTS.COMMAND_START, cb)

    params: Dict[str, Any] = {
    }

    pkt = rctSTARTCommand(**params)

    comms.gcs.sendPacket(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt

def test_stopCmd(comms: CommsPair):
    seed(0)

    pkt_queue: queue.Queue[rctSTOPCommand] = queue.Queue()
    def cb(packet: rctSTOPCommand, addr: str):
        pkt_queue.put(packet)

    comms.mav.registerCallback(EVENTS.COMMAND_STOP, cb)

    params: Dict[str, Any] = {
    }

    pkt = rctSTOPCommand(**params)

    comms.gcs.sendPacket(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt

def test_upgradeCmd(comms: CommsPair):
    seed(0)

    pkt_queue: queue.Queue[rctUPGRADECommand] = queue.Queue()
    def cb(packet: rctUPGRADECommand, addr: str):
        pkt_queue.put(packet)

    comms.mav.registerCallback(EVENTS.COMMAND_UPGRADE, cb)

    params: Dict[str, Any] = {
    }

    pkt = rctUPGRADECommand(**params)

    comms.gcs.sendPacket(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt
