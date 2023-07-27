'''Callback Support
'''
from typing import Callable, Dict, Set, TypeVar

Event = TypeVar('Event')
def supports_callbacks(event_type: Event):
    """Adds callbacks to the class

    Args:
        event_type (Event): Event enumeration
    """
    def wrapper(obj):
        def register_callback(self, event: Event, cb_: Callable[[Event], None]) -> int:
            callbacks: Dict[Event, Set[int]] = self.callbacks
            callback_map: Dict[int, Callable[[Event], None]] = self.callback_map
            callbacks[event].add(id(cb_))
            callback_map[id(cb_)] = cb_
            return id(cb_)

        def unregister_callback(self, cb_id: int) -> None:
            callbacks: Dict[Event, Set[int]] = self.callbacks
            callback_map: Dict[int, Callable[[Event], None]] = self.callback_map
            for evt_cb in callbacks.values():
                assert isinstance(evt_cb, set)
                evt_cb.remove(cb_id)
            callback_map.pop(cb_id)

        def execute_callback(self, event: Event) -> None:
            callbacks: Dict[Event, Set[int]] = self.callbacks
            callback_map: Dict[int, Callable[[Event], None]] = self.callback_map
            for cb_id in callbacks[event]:
                callback_map[cb_id](event)

        callbacks = {evt: set() for evt in event_type}
        callback_map = {}
        setattr(obj, 'callbacks', callbacks)
        setattr(obj, 'callback_map', callback_map)
        setattr(obj, 'register_callback', register_callback)
        setattr(obj, 'unregister_callback', unregister_callback)
        setattr(obj, 'execute_callback', execute_callback)
        return obj
    return wrapper
