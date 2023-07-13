'''Tests the Transport Factory's parsing
'''
from serial.tools import list_ports

from RCTComms.transport import RCTSerialTransport, RCTTransportFactory


def test_serial():
    """Tests loading serial
    """
    available_ports = list_ports.comports()
    if len(available_ports) == 0:
        return
    port_to_use = available_ports[0]
    spec = f'serial://{port_to_use.name}?baud=57600'
    transport = RCTTransportFactory.create_transport(spec)
    assert isinstance(transport, RCTSerialTransport)
