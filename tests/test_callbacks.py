'''Callback testing
'''
from enum import Enum, auto
from unittest.mock import Mock

from rctcomms.callbacks import supports_callbacks


class ActionEvent(Enum):
    """Action Event
    """
    EVENT1 = auto()
    EVENT2 = auto()
    EVENT3 = auto()

@supports_callbacks(ActionEvent)
class MockClass:
    """Test Class
    """
    def __init__(self, arg1) -> None:
        self.arg1 = arg1

    def do_cb_1(self) -> None:
        """Executes callback 1
        """
        self.execute_callback(ActionEvent.EVENT1)

    def do_cb_2(self) -> None:
        """Executes callback 1
        """
        self.execute_callback(ActionEvent.EVENT2)

    def do_cb_3(self) -> None:
        """Executes callback 1
        """
        self.execute_callback(ActionEvent.EVENT3)

def test_callbacks():
    """Test callback functionality
    """
    obj = MockClass(arg1='test')
    mock_cb1 = Mock()
    obj.register_callback(ActionEvent.EVENT1, mock_cb1)
    obj.do_cb_1()
    mock_cb1.assert_called_once()
    mock_cb2 = Mock()
    obj.register_callback(ActionEvent.EVENT2, mock_cb2)
    obj.do_cb_2()
    mock_cb1.assert_called_once()
    mock_cb3 = Mock()
    obj.register_callback(ActionEvent.EVENT3, mock_cb3)
    obj.do_cb_3()

    mock_cb1.assert_called_once()

    mock_cb2.assert_called_once()

    mock_cb3.assert_called_once()

    assert obj.arg1 == 'test'
