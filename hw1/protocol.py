import random
import socket
from enum import StrEnum
from functools import singledispatch

from hw1.tcp.data_segmentizer import TCPDataSegmentizer
from hw1.tcp.segment import SegmentFlag, Segment
from hw1.tcp.segment_formatter import TCPSegmentFormatter


class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data) -> int:
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg


class TCPState(StrEnum):
    INITIAL = 'INITIAL'
    WAITING_FOR_CONNECTION_ACK = 'WAITING_FOR_CONNECTION_ACK'
    CONNECTED = 'CONNECTED'
    WAITING_FOR_DATA_ACK = 'WAITING_FOR_DATA_ACK'
    WAITING_FOR_DISCONNECTION_ACK = 'WAITING_FOR_DISCONNECTION_ACK'


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._formatter = TCPSegmentFormatter()
        self._segmentizer = TCPDataSegmentizer()
        self._state: TCPState = TCPState.INITIAL

    def send(self, data: bytes) -> int:
        if self._state == TCPState.INITIAL:
            return self._on_initial(data=data)
        elif self._state == TCPState.CONNECTED:
            return self._on_connected(data=data)

        raise RuntimeError(f'Unreachable code with state {self._state}')

    def _on_initial(self, data: bytes) -> int:
        self._connect()
        return self.send(data=data)

    def _connect(self):
        syn_segment = Segment(
            sender_port=322,
            receiver_port=1337,
            data_start_byte=random.randint(1, 1337),
            byte_to_read=0,
            segment_flags=(SegmentFlag.SYN,),
            window_size=1 * 1460,
            segment_params=tuple(),
            data=None,
        )
        print(syn_segment)
        syn_segment_data = list(self._formatter.serialize([syn_segment]))[0]

        self.sendto(syn_segment_data)
        self._state = TCPState.WAITING_FOR_CONNECTION_ACK

    def _on_connected(self, data: bytes) -> int:
        pass

    def recv(self, n: int) -> bytes:
        # return self.recvfrom(n)

        if self._state == TCPState.INITIAL:
            return self._on_recv_initial(n=n)
        elif self._state == TCPState.CONNECTED:
            return self._on_recv_connected(n=n)

        raise RuntimeError(f'Unreachable code with state {self._state}')

    def _on_recv_initial(self, n: int) -> bytes:
        self._formatter.parse(self.recvfrom)

        syn_segment = Segment(
            sender_port=322,
            receiver_port=1337,
            data_start_byte=random.randint(1, 1337),
            byte_to_read=0,
            segment_flags=(SegmentFlag.SYN,),
            window_size=1 * 1460,
            segment_params=tuple(),
            data=None,
        )
        print(syn_segment)
        syn_segment_data = list(self._formatter.serialize([syn_segment]))[0]

        self.sendto(syn_segment_data)
        self._state = TCPState.WAITING_FOR_CONNECTION_ACK

