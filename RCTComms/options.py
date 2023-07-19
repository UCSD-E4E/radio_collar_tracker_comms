'''Common Options
'''
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional, Type, Tuple, Sequence

BASE_OPTIONS = 0x01
EXP_OPTIONS = 0x02
ENG_OPTIONS = 0x04

class Options(Enum):
    DSP_PING_WIDTH = 'DSP_ping_width'
    DSP_PING_SNR = 'DSP_ping_snr'
    DSP_PING_MAX = 'DSP_ping_max'
    DSP_PING_MIN = 'DSP_ping_min'
    GPS_BAUD = 'GPS_baud'
    GPS_DEVICE = 'GPS_device'
    GPS_MODE = 'GPS_mode'
    TGT_FREQUENCIES = 'TGT_frequencies'
    SDR_SAMPLING_FREQ = 'SDR_sampling_freq'
    SDR_CENTER_FREQ = 'SDR_center_freq'
    SDR_GAIN = 'SDR_gain'
    SYS_AUTOSTART = 'SYS_autostart'
    SYS_OUTPUT_DIR = 'SYS_output_dir'
    SYS_NETWORK = 'SYS_network'
    SYS_WIFI_MONITOR_INTERVAL = 'SYS_wifi_monitor_interval'
    SYS_HEARTBEAT_PERIOD = 'SYS_heartbeat_period'

@dataclass
class OptionParams:
    type_list: Sequence[Type]
    format_str: str
    length: int
    scope_mask: int
    validation_fn: Optional[Callable[[Any], bool]] = None
    transform_fn: Optional[Callable[[Any], Any]] = None

    def unpack_from(self, buffer: bytes, offset: int) -> Tuple[Any, int]:
        """Unpacks this option from the buffer at the specified offset

        Args:
            buffer (bytes): Buffer to unpack from
            idx (int): Offset to unpack from

        Returns:
            Tuple[Any, int]: Value, and index of next byte
        """
        if self.format_str == 's':
            strlen, = struct.unpack_from('<H', buffer, offset=offset)
            new_str = buffer[offset + 2:offset + 2 + strlen].decode('ascii')
            return new_str, offset + 2 + strlen
        value, = struct.unpack_from(self.format_str, buffer, offset=offset)
        if self.transform_fn:
            value = self.transform_fn(value)
        return value, offset + self.length

    def pack(self, value: Any) -> bytes:
        """Packs this option into a buffer

        Args:
            value (Any): Value to pack

        Returns:
            bytes: Binary blob
        """
        assert isinstance(value, self.type_list)
        if self.format_str == 's':
            assert isinstance(value, str)
            strlen = len(value)
            return struct.pack(f'<H{strlen}s', strlen, value.encode('ascii'))
        return struct.pack(self.format_str, value)
            

option_param_table = {
    Options.DSP_PING_WIDTH: OptionParams(
        type_list=(int, float),
        format_str='<f',
        length=4,
        scope_mask=EXP_OPTIONS,
        validation_fn=lambda x: x > 0,
        transform_fn=float
    ),
    Options.DSP_PING_SNR: OptionParams(
        type_list=(int, float),
        format_str='<f',
        length=4,
        scope_mask=EXP_OPTIONS,
        validation_fn=lambda x: x > 0,
        transform_fn=float
    ),
    Options.DSP_PING_MAX: OptionParams(
        type_list=(int, float),
        format_str='<f',
        length=4,
        scope_mask=EXP_OPTIONS,
        validation_fn=lambda x: x > 1,
        transform_fn=float
    ),
    Options.DSP_PING_MIN: OptionParams(
        type_list=(int, float),
        format_str='<f',
        length=4,
        scope_mask=EXP_OPTIONS,
        validation_fn=lambda x: 0 < x < 1,
        transform_fn=float
    ),
    Options.GPS_MODE: OptionParams(
        type_list=(bool),
        format_str='<?',
        length=1,
        scope_mask=ENG_OPTIONS
    ),
    Options.GPS_DEVICE: OptionParams(
        type_list=(str),
        format_str='s',
        length=2,
        scope_mask=ENG_OPTIONS
    ),
    Options.GPS_BAUD: OptionParams(
        type_list=(int),
        format_str='<L',
        length=4,
        scope_mask=ENG_OPTIONS,
        validation_fn=lambda x: x > 0
    ),
    Options.TGT_FREQUENCIES: OptionParams(
        type_list=(list),
        format_str='',
        length=4,
        scope_mask=0xFF
    ),
    Options.SYS_AUTOSTART: OptionParams(
        type_list=(bool),
        format_str='<?',
        length=1,
        scope_mask=ENG_OPTIONS,
    ),
    Options.SYS_OUTPUT_DIR: OptionParams(
        type_list=(str),
        format_str='s',
        length=2,
        scope_mask=EXP_OPTIONS,
    ),
    Options.SDR_SAMPLING_FREQ: OptionParams(
        type_list=(int),
        format_str='<L',
        length=4,
        scope_mask=BASE_OPTIONS,
        validation_fn=lambda x: x > 0
    ),
    Options.SDR_CENTER_FREQ: OptionParams(
        type_list=(int),
        format_str='<L',
        length=4,
        scope_mask=BASE_OPTIONS,
        validation_fn=lambda x: x > 0
    ),
    Options.SDR_GAIN: OptionParams(
        type_list=(int, float),
        format_str='<f',
        length=4,
        scope_mask=BASE_OPTIONS,
        transform_fn=float
    ),
    Options.SYS_NETWORK: OptionParams(
        type_list=(str),
        format_str='s',
        length=2,
        scope_mask=EXP_OPTIONS,
    ),
    Options.SYS_WIFI_MONITOR_INTERVAL: OptionParams(
        type_list=(int),
        format_str='<L',
        length=4,
        scope_mask=EXP_OPTIONS
    ),
    Options.SYS_HEARTBEAT_PERIOD: OptionParams(
        type_list=(int),
        format_str='<L',
        length=4,
        scope_mask=EXP_OPTIONS,
        validation_fn=lambda x: x > 0
    )
}

def validate_option(key: Options, value: Any) -> Any:
    """Validates the option value

    Args:
        key (Options): Option key
        value (Any): Value to be validated

    Raises:
        KeyError: Unknown key

    Returns:
        Any: Validated value
    """
    if key not in option_param_table:
        raise KeyError('Unknown key')

    param_entry = option_param_table[key]
    # validate first
    if param_entry.validation_fn:
        assert param_entry.validation_fn(value)

    # Transform
    if param_entry.transform_fn:
        value = param_entry.transform_fn(value)
    return value

base_options_keywords = [option
                         for option, param in option_param_table.items()
                         if param.scope_mask == BASE_OPTIONS]
expert_options_keywords = [option
                           for option, param in option_param_table.items()
                           if param.scope_mask == EXP_OPTIONS]
engineering_options_keywords = [option
                                for option, param in option_param_table.items()
                                if param.scope_mask == ENG_OPTIONS]