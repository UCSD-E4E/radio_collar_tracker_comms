'''Packet Tests
'''
import itertools
import queue
import time
from os import urandom
from random import randint, random, seed
from typing import Any, Dict, List, Tuple, Union

import pytest
from conftest import CommsPair

from rctcomms.comms import Events
from rctcomms.options import (BASE_OPTIONS, ENG_OPTIONS, EXP_OPTIONS, Options,
                              base_options_keywords,
                              engineering_options_keywords,
                              expert_options_keywords, option_param_table,
                              validate_option)
from rctcomms.packets import (ACKCommand, EngrCommand, ExceptionPacket,
                              FrequenciesPacket, GetFCommand, GetOptCommand,
                              HeartbeatPacket, OptionsPacket, PingPacket,
                              SetFCommand, SetOptCommand, StartCommand,
                              StopCommand, UpgradeCommand, UpgradePacket,
                              UpgradeStatusPacket, VehiclePacket)


@pytest.mark.timeout(10)
def test_heartbeat(comms: CommsPair):
    """Tests heartbeats

    Args:
        comms (CommsPair): Comms Pair
    """
    heartbeat_queue: queue.Queue[HeartbeatPacket] = queue.Queue()

    def cb_(packet: HeartbeatPacket, addr: str):  # pylint: disable=unused-argument
        heartbeat_queue.put(packet)

    comms.gcs.register_callback(Events.STATUS_HEARTBEAT, cb_)
    params = [
        [e.value for e in HeartbeatPacket.SysStates],
        [e.value for e in HeartbeatPacket.SdrStates],
        [e.value for e in HeartbeatPacket.ExtSensorStates],
        [e.value for e in HeartbeatPacket.StorageStates],
        [e.value for e in HeartbeatPacket.SwStates],
    ]
    for param in itertools.product(*params):
        heartbeat = HeartbeatPacket(*param)
        comms.mav.send_to_gcs(heartbeat)
        rx_ = heartbeat_queue.get(True, timeout=2)
        assert rx_ == heartbeat
        assert rx_.system_state == heartbeat.system_state
        assert rx_.sdr_state == heartbeat.sdr_state
        assert rx_.sensor_state == heartbeat.sensor_state
        assert rx_.storage_state == heartbeat.storage_state
        assert rx_.switch_state == heartbeat.switch_state
        assert abs((rx_.timestamp - heartbeat.timestamp).total_seconds()) < 1e-3


@pytest.mark.timeout(10)
def test_exception(comms: CommsPair):
    """Tests exceptions

    Args:
        comms (CommsPair): Comms Pair
    """
    exc_queue: queue.Queue[ExceptionPacket] = queue.Queue()

    def cb_(packet: ExceptionPacket, addr: str):  # pylint: disable=unused-argument
        exc_queue.put(packet)

    comms.gcs.register_callback(Events.STATUS_EXCEPTION, cb_)

    exc = ExceptionPacket('test_exc', 'test_tb')
    comms.mav.send_to_gcs(exc)
    rx_ = exc_queue.get(True, timeout=2)
    assert rx_ == exc
    assert rx_.exception == exc.exception
    assert rx_.traceback == exc.traceback


@pytest.mark.timeout(10)
@pytest.mark.parametrize('n_freqs', [1, 2, 4, 8])
def test_frequencies(comms: CommsPair, n_freqs: int):
    """Tests sending frequencies

    Args:
        comms (CommsPair): Comms Pair
        n_freqs (int): Number of frequencies
    """
    pkt_queue: queue.Queue[FrequenciesPacket] = queue.Queue()

    def cb_(packet: FrequenciesPacket, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.mav.register_callback(Events.CONFIG_FREQUENCIES, cb_)

    freqs = FrequenciesPacket(
        tuple(randint(172000000, 174000000) for _ in range(n_freqs)))
    comms.gcs.send_packet(freqs)

    rx_ = pkt_queue.get(True, timeout=2)
    assert rx_ == freqs
    assert rx_.frequencies == freqs.frequencies


@pytest.mark.timeout(10)
@pytest.mark.parametrize('opt_scope',
                         [
                             # pylint: disable=protected-access
                             (BASE_OPTIONS, base_options_keywords),
                             (EXP_OPTIONS,
                              base_options_keywords + expert_options_keywords),
                             (ENG_OPTIONS,
                              base_options_keywords + expert_options_keywords +\
                              engineering_options_keywords)
                         ])
def test_options(comms: CommsPair, opt_scope: Tuple[int, List[str]]):
    """Test sending options

    Args:
        comms (CommsPair): Comms Pair
        opt_scope (Tuple[int, List[str]]): Scope of options
    """
    seed(0)
    pkt_queue: queue.Queue[OptionsPacket] = queue.Queue()

    def cb_(packet: OptionsPacket, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.mav.register_callback(Events.CONFIG_OPTIONS, cb_)

    scope = opt_scope[0]
    options: Dict[Options, Any] = {}

    populate_params(options, opt_scope[1])

    opt = OptionsPacket(scope, options)
    comms.gcs.send_packet(opt)
    time.sleep(1)

    rx_ = pkt_queue.get(timeout=1)

    assert rx_ == opt
    for key in opt_scope[1]:
        verify_option_key(opt, rx_, key)


def verify_option_key(opt: Union[OptionsPacket, SetOptCommand],
                      rx: Union[OptionsPacket, SetOptCommand],
                      key: str):
    """Verifies option keys
    """
    assert key in rx.options
    assert key in opt.options
    if isinstance(rx.options[key], (int, str)):
        assert rx.options[key] == opt.options[key]
    elif isinstance(rx.options[key], float):
        assert abs(rx.options[key] - opt.options[key]) < 1e-3
    else:
        raise NotImplementedError(type(rx.options[key]))


def populate_params(options: Dict[Options, Any], params: List[Options]):
    """Populates the parameters into the options dict

    Args:
        options (Dict[Options, Any]): Dict to populate
        params (List[Options]): Params to use

    Raises:
        NotImplementedError: Parameter not supported
    """
    for kw in params:
        kw_param = option_param_table[kw]
        while True:
            if '<L' == kw_param.format_str:
                options[kw] = randint(0, 2**32 - 1)
            elif '<B' == kw_param.format_str:
                options[kw] = randint(0, 2**8 - 1)
            elif '<f' == kw_param.format_str:
                options[kw] = random() * 100
            elif 's' == kw_param.format_str:
                options[kw] = f'{random() * 100}'
            elif '<?' == kw_param.format_str:
                options[kw] = random() > 0.5
            elif '' == kw_param.format_str:
                continue
            else:
                raise NotImplementedError(kw_param.format_str)

            try:
                validate_option(kw, options[kw])
                break
            except AssertionError:
                continue


@pytest.mark.timeout(10)
def test_upgrade_status_packet(comms: CommsPair):
    """Tests Upgrade Status Packet

    Args:
        comms (CommsPair): Comms Pair
    """
    seed(0)
    pkt_queue: queue.Queue[UpgradeStatusPacket] = queue.Queue()

    def cb(packet: UpgradeStatusPacket, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.gcs.register_callback(Events.UPGRADE_STATUS, cb)

    states = [UpgradeStatusPacket.UPGRADE_READY,
              UpgradeStatusPacket.UPGRADE_PROGRESS,
              UpgradeStatusPacket.UPGRADE_COMPLETE,
              UpgradeStatusPacket.UPGRADE_FAILED]
    msg = ['rctUpgradeStatusPacket.UPGRADE_READY',
           'rctUpgradeStatusPacket.UPGRADE_PROGRESS',
           'rctUpgradeStatusPacket.UPGRADE_COMPLETE',
           'rctUpgradeStatusPacket.UPGRADE_FAILED']
    for idx, state in enumerate(states):
        pkt = UpgradeStatusPacket(state, msg[idx])
        comms.mav.send_to_gcs(pkt)

        rx = pkt_queue.get(True, timeout=1)

        assert rx == pkt
        assert rx.state == state
        assert rx.msg == msg[idx]


@pytest.mark.timeout(10)
def test_upgrade_packet(comms: CommsPair):
    """Tests Upgrade Packet

    Args:
        comms (CommsPair): Comms Pair
    """
    seed(0)

    pkt_queue: queue.Queue[UpgradePacket] = queue.Queue()

    def cb(packet: UpgradePacket, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.mav.register_callback(Events.UPGRADE_DATA, cb)

    img = urandom(16384)
    pkt_num = 1
    total_packets = 3
    pkt = UpgradePacket(pkt_num, total_packets, img)

    comms.gcs.send_packet(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt
    assert rx.num_packet == pkt_num
    assert rx.num_total == total_packets
    assert rx.file_bytes == img


@pytest.mark.timeout(10)
def test_vehicle(comms: CommsPair):
    """Test Vehicle Packet

    Args:
        comms (CommsPair): Comms Pair
    """
    seed(0)

    pkt_queue: queue.Queue[VehiclePacket] = queue.Queue()

    def cb(packet: VehiclePacket, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.gcs.register_callback(Events.DATA_VEHICLE, cb)

    params: Dict[str, Any] = {
        'lat': (random() - 0.5) * 180,
        'lon': (random() - 0.5) * 360,
        'alt': random() * 400,
        'hdg': randint(0, 359),
    }

    pkt = VehiclePacket(**params)
    assert abs(pkt.lat - params['lat']) < 1e-7
    assert abs(pkt.lon - params['lon']) < 1e-7
    assert abs(pkt.alt - params['alt']) < 1e-1
    assert abs(pkt.hdg - params['hdg']) < 0.5

    comms.mav.send_to_gcs(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt
    assert abs(rx.lat - params['lat']) < 1e-7
    assert abs(rx.lon - params['lon']) < 1e-7
    assert abs(rx.alt - params['alt']) < 1e-1
    assert abs(rx.hdg - params['hdg']) < 0.5


@pytest.mark.timeout(10)
def test_ping_packet(comms: CommsPair):
    """Tests Ping Packet

    Args:
        comms (CommsPair): Comms Pair
    """
    seed(0)

    pkt_queue: queue.Queue[PingPacket] = queue.Queue()

    def cb(packet: PingPacket, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.gcs.register_callback(Events.DATA_PING, cb)

    params: Dict[str, Any] = {
        'lat': (random() - 0.5) * 180,
        'lon': (random() - 0.5) * 360,
        'alt': random() * 400,
        'txp': random() * 50,
        'txf': randint(170000000, 180000000)
    }

    pkt = PingPacket(**params)
    assert abs(pkt.lat - params['lat']) < 1e-7
    assert abs(pkt.lon - params['lon']) < 1e-7
    assert abs(pkt.alt - params['alt']) < 1e-1
    assert abs(pkt.txp - params['txp']) < 1e-6
    assert pkt.txf == params['txf']

    comms.mav.send_to_gcs(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt
    assert abs(rx.lat - params['lat']) < 1e-7
    assert abs(rx.lon - params['lon']) < 1e-7
    assert abs(rx.alt - params['alt']) < 1e-1
    assert abs(rx.txp - params['txp']) < 1e-6
    assert rx.txf == params['txf']


@pytest.mark.timeout(10)
def test_cmd_ack(comms: CommsPair):
    """Tests command acknowledge packet

    Args:
        comms (CommsPair): Comms Pair
    """
    seed(0)

    pkt_queue: queue.Queue[ACKCommand] = queue.Queue()

    def cb(packet: ACKCommand, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.gcs.register_callback(Events.COMMAND_ACK, cb)

    params: Dict[str, Any] = {
        'commandID': randint(0, 255),
        'ack': random() > 0.5
    }

    pkt = ACKCommand(**params)
    assert pkt.command_id == params['commandID']
    assert pkt.ack == params['ack']

    comms.mav.send_to_gcs(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt
    assert rx.command_id == params['commandID']
    assert rx.ack == params['ack']


@pytest.mark.timeout(10)
def test_get_f_cmd(comms: CommsPair):
    """Tests Get Frequency Command

    Args:
        comms (CommsPair): Comms Pair
    """
    seed(0)

    pkt_queue: queue.Queue[GetFCommand] = queue.Queue()

    def cb(packet: GetFCommand, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.mav.register_callback(Events.COMMAND_GETF, cb)

    params: Dict[str, Any] = {
    }

    pkt = GetFCommand(**params)

    comms.gcs.send_packet(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt


@pytest.mark.timeout(10)
def test_set_f_cmd(comms: CommsPair):
    """Tests Set Frequency Command

    Args:
        comms (CommsPair): Comms Pair
    """
    seed(0)

    pkt_queue: queue.Queue[SetFCommand] = queue.Queue()

    def cb(packet: SetFCommand, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.mav.register_callback(Events.COMMAND_SETF, cb)

    params: Dict[str, Any] = {
        'frequencies': tuple(randint(170000000, 180000000) for _ in range(randint(0, 16)))
    }

    pkt = SetFCommand(**params)
    assert pkt.frequencies == params['frequencies']

    comms.gcs.send_packet(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt
    assert rx.frequencies == params['frequencies']


@pytest.mark.timeout(10)
def test_get_opt_cmd(comms: CommsPair):
    """Tests Get Options Command

    Args:
        comms (CommsPair): Comms Pair
    """
    seed(0)

    pkt_queue: queue.Queue[GetOptCommand] = queue.Queue()

    def cb(packet: GetOptCommand, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.mav.register_callback(Events.COMMAND_GETOPT, cb)

    params: Dict[str, Any] = {
        'scope': randint(0, 255)
    }

    pkt = GetOptCommand(**params)
    assert pkt.scope == params['scope']

    comms.gcs.send_packet(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt
    assert rx.scope == params['scope']


@pytest.mark.timeout(10)
@pytest.mark.parametrize('opt_scope',
                         [
                             (BASE_OPTIONS, base_options_keywords),
                             (EXP_OPTIONS, base_options_keywords +
                              expert_options_keywords),
                             (ENG_OPTIONS, base_options_keywords + expert_options_keywords +
                              engineering_options_keywords)
                         ])
def test_set_options_command(comms: CommsPair, opt_scope: Tuple[int, List[Options]]):
    """Test Set Options Command

    Args:
        comms (CommsPair): Comms Pair
        opt_scope (Tuple[int, List[Options]]): Options Scope
    """
    seed(0)
    pkt_queue: queue.Queue[SetOptCommand] = queue.Queue()

    def cb(packet: SetOptCommand, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.mav.register_callback(Events.COMMAND_SETOPT, cb)

    scope = opt_scope[0]
    options: Dict[Options, Any] = {}

    populate_params(options, opt_scope[1])

    opt = SetOptCommand(scope, options)
    comms.gcs.send_packet(opt)

    rx = pkt_queue.get(True, timeout=1)

    assert rx == opt
    for key in opt_scope[1]:
        verify_option_key(opt, rx, key)


@pytest.mark.timeout(10)
def test_start_command(comms: CommsPair):
    """Tests the start command

    Args:
        comms (CommsPair): Comms Pair
    """
    seed(0)

    pkt_queue: queue.Queue[StartCommand] = queue.Queue()

    def cb(packet: StartCommand, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.mav.register_callback(Events.COMMAND_START, cb)

    params: Dict[str, Any] = {
    }

    pkt = StartCommand(**params)

    comms.gcs.send_packet(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt


@pytest.mark.timeout(10)
def test_stop_command(comms: CommsPair):
    """Tests the stop command

    Args:
        comms (CommsPair): Comms Pair
    """
    seed(0)

    pkt_queue: queue.Queue[StopCommand] = queue.Queue()

    def cb(packet: StopCommand, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.mav.register_callback(Events.COMMAND_STOP, cb)

    params: Dict[str, Any] = {
    }

    pkt = StopCommand(**params)

    comms.gcs.send_packet(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt


@pytest.mark.timeout(10)
def test_upgrade_command(comms: CommsPair):
    """Tests the Upgrade Command

    Args:
        comms (CommsPair): Comms Pair
    """
    seed(0)

    pkt_queue: queue.Queue[UpgradeCommand] = queue.Queue()

    def cb(packet: UpgradeCommand, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.mav.register_callback(Events.COMMAND_UPGRADE, cb)

    params: Dict[str, Any] = {
    }

    pkt = UpgradeCommand(**params)

    comms.gcs.send_packet(pkt)

    rx = pkt_queue.get(True, timeout=1)
    assert rx == pkt


def test_engr_cmd(comms: CommsPair):
    """Tests the engineering command

    Args:
        comms (CommsPair): Test Comms
    """
    seed(0)

    pkt_queue: queue.Queue[EngrCommand] = queue.Queue()

    def mock_cb(packet: EngrCommand, addr: str):  # pylint: disable=unused-argument
        pkt_queue.put(packet)

    comms.mav.register_callback(Events.ENGR_CMD, mock_cb)
    pkt = EngrCommand('test', {'arg1': 1234})

    comms.gcs.send_packet(pkt)

    rx_pkt = pkt_queue.get(True, timeout=1)

    assert rx_pkt == pkt
