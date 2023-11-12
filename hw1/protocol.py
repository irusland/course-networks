import dataclasses
import functools
import logging
import random
import socket
import threading
import time
from enum import Enum

from tcp.buffer import Buffer
from tcp.data_segmentizer import TCPDataSegmentizer
from tcp.errors import (
    TCPConnectionACKTimeout, TCPUnexpectedSegmentError,
    TCPDataACKTimeout, TCPDataSendRetryExhausted,
)
from tcp.segment import SegmentFlag, Segment
from tcp.segment_formatter import TCPSegmentFormatter
from tcp.segment_pickle_formatter import TCPSegmentPickleFormatter
from tcp.settings import TCPSettings


logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(module)s %(funcName)s %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

LOG_CALL_ENABLED = False


def log_call(f):
    if LOG_CALL_ENABLED:
        @functools.wraps(f)
        def _f(*args, **kwargs):
            logger.info('%s%s', f.__name__, (args[1:], kwargs))
            return f(*args, **kwargs)
        return _f
    return f


class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)
        self.udp_socket.setblocking(False)

    def sendto(self, data) -> int:
        logger.debug('Sending segment size: %s', len(data))
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        logger.debug('Received segment size: %s', len(msg))
        return msg


class TCPState(str, Enum):
    INITIAL = 'INITIAL'
    WAITING_FOR_CONNECTION_SYN_ACK = 'WAITING_FOR_CONNECTION_SYN_ACK'
    WAITING_FOR_CONNECTION_ACK = 'WAITING_FOR_CONNECTION_ACK'
    CONNECTED = 'CONNECTED'
    WAITING_FOR_DATA_ACK = 'WAITING_FOR_DATA_ACK'
    WAITING_FOR_DISCONNECTION_ACK = 'WAITING_FOR_DISCONNECTION_ACK'


@dataclasses.dataclass(init=True, frozen=True)
class Data:
    data: bytes
    to_send: int
    data_start_byte: int


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, local_addr: tuple[str, int], remote_addr: tuple[str, int], name: str):
        super().__init__(local_addr=local_addr, remote_addr=remote_addr)
        self._sender_port = local_addr[1]
        self._receiver_port = remote_addr[1]
        self._formatter = TCPSegmentFormatter()
        # self._formatter = TCPSegmentPickleFormatter()
        self._segmentizer = TCPDataSegmentizer()
        self._settings = TCPSettings()
        self.__state: TCPState = TCPState.INITIAL

        self._is_recv_worker_running = True

        logger.info('starting worker')
        self._send_change_state_lock = threading.Lock()
        self._recv_worker_thread = threading.Thread(target=self._recv_worker, daemon=True)
        self._recv_worker_thread.name = f'{name}_recv_worker'
        self._recv_worker_thread.start()

        self._recv_buffer = Buffer()
        self._data_start_byte = 0
        self.__byte_to_read = 0

        self._reset_all_retries()

    def __del__(self):
        self._is_recv_worker_running = False
        self.udp_socket.close()
        self._recv_worker_thread.join()

    @property
    def _state(self) -> TCPState:
        return self.__state

    @_state.setter
    def _state(self, value: TCPState) -> None:
        logger.info(f'{self.__state} -> {value}: State changed.')
        self.__state = value

    @property
    def _byte_to_read(self) -> int:
        return self.__byte_to_read

    @_byte_to_read.setter
    def _byte_to_read(self, value: int) -> None:
        logger.info(f'{self.__byte_to_read} -> {value}: byte_to_read changed.')
        self.__byte_to_read = value

    @log_call
    def _reset_connect_retries(self):
        self._connect_retries = self._settings.connect_ack_retries

    @log_call
    def _reset_data_ack_retries(self):
        self._data_ack_retries = self._settings.data_ack_retries

    @log_call
    def _reset_send_retries(self):
        self._send_retries = self._settings.send_data_retries

    @log_call
    def _reset_all_retries(self):
        self._reset_connect_retries()
        self._reset_data_ack_retries()
        self._reset_send_retries()

    @log_call
    def send(self, data: bytes) -> int:
        logger.info("Send: %s", data)
        return self._send(
            data=Data(data=data, to_send=len(data), data_start_byte=self._data_start_byte)
        )

    @log_call
    def _send(self, data: Data) -> int:
        if self._state == TCPState.INITIAL:
            return self._on_initial(data=data)
        elif self._state == TCPState.CONNECTED:
            return self._on_connected(data=data)
        elif self._state == TCPState.WAITING_FOR_CONNECTION_SYN_ACK:
            return self._on_connection_syn_ack_wait(data=data)
        elif self._state == TCPState.WAITING_FOR_DATA_ACK:
            return self._on_data_ack_wait(data=data)

        raise RuntimeError(f'Unreachable code with state {self._state}')

    @log_call
    def _on_initial(self, data: Data) -> int:
        self._connect()
        return self._send(data=data)

    @log_call
    def _connect(self):
        syn_segment = Segment(
            sender_port=self._sender_port,
            receiver_port=self._receiver_port,
            data_start_byte=self._data_start_byte,
            byte_to_read=0,
            segment_flags=(SegmentFlag.SYN,),
            window_size=1 * Segment.size,
            urgent_pointer=0,
            segment_params={},
            data=None,
        )
        with self._send_change_state_lock:
            self._send_segment(segment=syn_segment)
            self._state = TCPState.WAITING_FOR_CONNECTION_SYN_ACK

    @log_call
    def _on_connection_syn_ack_wait(self, data: Data) -> int:
        if self._connect_retries > 0:
            self._connect_retries -= 1
            time.sleep(self._settings.connect_ack_wait.total_seconds())
        else:
            logger.info('Retry exhausted waiting for SYN, ACK')

            self._reset_connect_retries()
            self._state = TCPState.INITIAL
            raise TCPConnectionACKTimeout()
        return self._send(data=data)

    @log_call
    def _on_connected(self, data: Data) -> int:
        if data.data_start_byte + data.to_send <= self._data_start_byte:
            logger.info('Data was sent, all ACKs received')
            return data.to_send
        segment = Segment(
            sender_port=self._sender_port,
            receiver_port=self._receiver_port,
            data_start_byte=self._data_start_byte,
            byte_to_read=self._byte_to_read,
            segment_flags=tuple(),
            window_size=1 * Segment.size,
            urgent_pointer=0,
            segment_params={'data': data.to_send},
            data=data.data,
        )
        with self._send_change_state_lock:
            self._send_segment(segment=segment)
            self._state = TCPState.WAITING_FOR_DATA_ACK
        return self._send(data=data)

    def _send_segment(self, segment: Segment):
        logger.info('send %s', segment)
        segment_data = self._formatter.serialize_segment(segment)
        self.sendto(segment_data)

    @log_call
    def _on_data_ack_wait(self, data: Data) -> int:
        if self._data_ack_retries > 0:
            self._data_ack_retries -= 1
            time.sleep(self._settings.data_ack_wait.total_seconds())
        else:
            logger.info('Timeout waiting for data ACK, retry')
            self._send_retries -= 1
            if self._send_retries <= 0:
                raise TCPDataSendRetryExhausted()
            self._reset_data_ack_retries()
            segment = Segment(
                sender_port=self._sender_port,
                receiver_port=self._receiver_port,
                data_start_byte=self._data_start_byte,
                byte_to_read=self._byte_to_read,
                segment_flags=tuple(),
                window_size=1 * Segment.size,
                urgent_pointer=0,
                segment_params={'data': data.to_send},
                data=data.data,
            )
            with self._send_change_state_lock:
                self._send_segment(segment=segment)

        return self._send(data)

    # ------------------–------------------- RECV --------------------------------------
    @log_call
    def recv(self, n: int) -> bytes:
        while len(self._recv_buffer) == 0:
            logger.info('Current recv buffer: %s', self._recv_buffer.getvalue())
            time.sleep(self._settings.recv_data_wait.total_seconds())
        data = bytes(self._recv_buffer.get(n))
        logger.info("Recv: %s", data)
        return data

    @log_call
    def _recv_worker(self):
        while self._is_recv_worker_running:
            try:
                data = self.recvfrom(Segment.size)
            except BlockingIOError:
                continue

            with self._send_change_state_lock:
                pass
            self._recv(data=data)

    @log_call
    def _recv(self, data: bytes):
        segment = self._formatter.parse_segment(data)
        logger.info('recv %s', segment)
        if self._state == TCPState.INITIAL:
            return self._on_recv_initial(segment)
        elif self._state == TCPState.WAITING_FOR_CONNECTION_SYN_ACK:
            return self._on_recv_wait_for_connection_syn_ack(segment)
        elif self._state == TCPState.WAITING_FOR_CONNECTION_ACK:
            return self._on_recv_wait_for_connection_ack(segment)
        elif self._state == TCPState.CONNECTED:
            return self._on_recv_connected(segment)
        elif self._state == TCPState.WAITING_FOR_DATA_ACK:
            return self._on_recv_wait_for_data_ack(segment)

        raise RuntimeError(f'Unreachable code with state {self._state}')

    @log_call
    def _on_recv_initial(self, received_segment: Segment):
        if (SegmentFlag.SYN,) != received_segment.segment_flags:
            raise TCPUnexpectedSegmentError(f'{received_segment}')

        self._byte_to_read = received_segment.data_start_byte + 0 + 1
        syn_ack_segment = Segment(
            sender_port=self._sender_port,
            receiver_port=self._receiver_port,
            data_start_byte=self._data_start_byte,
            byte_to_read=self._byte_to_read,
            segment_flags=(SegmentFlag.SYN, SegmentFlag.ACK),
            window_size=1 * Segment.size,
            urgent_pointer=0,
            segment_params={},
            data=None,
        )
        with self._send_change_state_lock:
            self._send_segment(segment=syn_ack_segment)
            self._state = TCPState.WAITING_FOR_CONNECTION_ACK

    @log_call
    def _on_recv_wait_for_connection_ack(self, received_segment: Segment):
        if (SegmentFlag.ACK,) != received_segment.segment_flags:
            raise TCPUnexpectedSegmentError(f'{received_segment}')

        self._state = TCPState.CONNECTED

    @log_call
    def _on_recv_wait_for_connection_syn_ack(self, received_segment: Segment):
        if sorted((SegmentFlag.ACK, SegmentFlag.SYN)) != sorted(received_segment.segment_flags):
            raise TCPUnexpectedSegmentError(f'{received_segment}')

        self._byte_to_read = received_segment.byte_to_read + 1
        ack_segment = Segment(
            sender_port=self._sender_port,
            receiver_port=self._receiver_port,
            data_start_byte=self._data_start_byte,
            byte_to_read=self._byte_to_read,
            segment_flags=(SegmentFlag.ACK,),
            window_size=1 * Segment.size,
            urgent_pointer=0,
            segment_params={},
            data=None,
        )
        with self._send_change_state_lock:
            self._send_segment(segment=ack_segment)
            self._state = TCPState.CONNECTED

    @log_call
    def _on_recv_connected(self, received_segment: Segment):
        if received_segment.segment_flags == tuple():
            return self._on_recv_data(received_segment)
        elif received_segment.segment_flags == (SegmentFlag.FIN,):
            raise NotImplementedError()
        elif received_segment.segment_flags == (SegmentFlag.RST,):
            raise NotImplementedError()

        raise RuntimeError(f'Unreachable code with state {self._state}')

    @log_call
    def _on_recv_data(self, received_segment: Segment):
        data_len = received_segment.segment_params['data']
        logger.info(
            'self._byte_to_read %s, received_segment.data_start_byte %s',
            self._byte_to_read, received_segment.data_start_byte
        )
        if received_segment.data_start_byte == self._byte_to_read:
            # получили текущий сегмент данных
            logger.info('_on_recv_data current segment')
            self._byte_to_read = (
                received_segment.data_start_byte
                + data_len
                + 1
            )
            self._recv_buffer.put(received_segment.data)
        elif received_segment.data_start_byte > self._byte_to_read:
            # получили сегмент данных из будущего
            raise TCPUnexpectedSegmentError(received_segment)
        else:
            # получили старый сегмент данных из-за ретрая
            logger.info('_on_recv_data old segment, just ACK')

        ack_segment = Segment(
            sender_port=self._sender_port,
            receiver_port=self._receiver_port,
            data_start_byte=self._data_start_byte,
            byte_to_read=self._byte_to_read,
            segment_flags=(SegmentFlag.ACK,),
            window_size=1 * Segment.size,
            urgent_pointer=0,
            segment_params={},
            data=None,
        )
        with self._send_change_state_lock:
            self._send_segment(segment=ack_segment)

    def _on_recv_wait_for_data_ack(self, segment: Segment):
        if (SegmentFlag.ACK,) != segment.segment_flags:
            if segment.segment_flags == tuple():
                return self._on_recv_data(segment)
            raise TCPUnexpectedSegmentError(f'{segment}')

        if self._data_start_byte >= segment.byte_to_read:
            logger.info('Old ACK received, skip ACK')
            return
        self._data_start_byte = segment.byte_to_read
        self._state = TCPState.CONNECTED
        self._reset_all_retries()
        logger.debug('Data was ACKed')
