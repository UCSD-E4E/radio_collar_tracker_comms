'''Tests the Transport Factory's parsing
'''
import pytest
from serial.tools import list_ports

from rctcomms.transport import RCTSerialTransport, RCTTransportFactory


def test_serial():
    """Tests loading serial
    """
    available_ports = list_ports.comports()
    if len(available_ports) == 0:
        return
    port_to_use = available_ports[0]
    spec = f'serial:{port_to_use.name}?baud=57600'
    transport = RCTTransportFactory.create_transport(spec)
    assert isinstance(transport, RCTSerialTransport)

@pytest.mark.parametrize('spec, device, baud', [
    ('serial:COM7?baud=57600', 'COM7', 57600),
    ('serial:/dev/ttyUSB0?baud=115200', '/dev/ttyUSB0', 115200),
    ('serial:///dev/ttyUSB0?baud=115200', '/dev/ttyUSB0', 115200),
])
def test_serial_good_spec_parse(spec: str, device: str, baud: int):
    """Tests serial spec parsing

    Args:
        spec (str): Spec string
        device (str): Expected device
        baud (int): Expected baudrate
    """
    result, _ = RCTTransportFactory.parse_spec(spec)
    args = RCTTransportFactory.extract_serial_args(result)
    assert args['port'] == device
    assert args['baudrate'] == baud
