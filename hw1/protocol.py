import dataclasses
import functools
import logging
import random
import socket
import sys
import threading
import time
from enum import Enum

from tcp.buffer import Buffer
from tcp.data_segmentizer import TCPDataSegmentizer
from tcp.errors import (
    TCPConnectionACKTimeout, TCPUnexpectedSegmentError,
    TCPDataACKTimeout, TCPDataSendRetryExhausted, TCPTooMuchDataError,
)
from tcp.segment import SegmentFlag, Segment
from tcp.segment_formatter import TCPSegmentFormatter
from tcp.segment_pickle_formatter import TCPSegmentPickleFormatter
from tcp.settings import TCPSettings, MAX_LOG_DATA_SIZE

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(module)s %(funcName)s %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

LOG_CALL_ENABLED = False
sys.setrecursionlimit(20000)


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

        self._recv_pre_buffer = []
        self._recv_pre_buffer_total_size = 0
        self._recv_buffer = Buffer()
        self._data_start_byte = 0
        self.__byte_to_read = 0

        self._non_acked_size = 0

        self._reset_all_retries()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._is_recv_worker_running = False
        self._recv_worker_thread.join()
        self.udp_socket.close()
        return False

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
        logger.debug(f'{self.__byte_to_read} -> {value}: byte_to_read changed.')
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
        logger.info("Send: %s %s", len(data), data[:MAX_LOG_DATA_SIZE])
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
            window_size=1,
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
            logger.info('Timeout waiting for SYN, ACK, retry')
            self._send_retries -= 1
            if self._send_retries <= 0:
                raise TCPDataSendRetryExhausted()
            self._reset_connect_retries()
            self._connect()

        return self._send(data=data)

    @log_call
    def _on_connected(self, data: Data) -> int:
        logger.info('Data processed %s/%s', self._data_start_byte - data.data_start_byte, data.to_send)

        if data.data_start_byte + data.to_send <= self._data_start_byte:
            logger.info('Data was sent, all ACKs received')
            return data.to_send

        window_data_start_byte = self._data_start_byte
        was_sent_in_window = 0
        for s in range(self._settings.window_size // Segment.get_bytes_num('data')):
            data_start = window_data_start_byte - data.data_start_byte + was_sent_in_window
            data_to_send = data.data[data_start:data_start + Segment.get_bytes_num('data')]
            if data_start >= data.to_send:
                break
            if len(data_to_send) == 0:
                logger.error('data_to_send len 0 %s %s %s %s', was_sent_in_window, data.to_send, data_start, s)

            segment = Segment(
                sender_port=self._sender_port,
                receiver_port=self._receiver_port,
                data_start_byte=data_start + data.data_start_byte,
                byte_to_read=self._byte_to_read,
                segment_flags=tuple(),
                window_size=1,
                urgent_pointer=0,
                segment_params={'data': len(data_to_send), 'size': data.to_send},
                data=data_to_send,
            )
            was_sent_in_window += len(data_to_send)
            with self._send_change_state_lock:
                self._send_segment(segment=segment)
            logger.info('Was sent: %s / %s bytes, in window %s', was_sent_in_window, data.to_send, self._settings.window_size)

        self._state = TCPState.WAITING_FOR_DATA_ACK
        return self._send(data=data)

    def _send_segment(self, segment: Segment):
        segment_data = self._formatter.serialize_segment(segment)
        logger.info('send %s %s', len(segment_data), segment)
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
            return self._on_connected(data=data)

        return self._send(data)

    # ------------------–------------------- RECV --------------------------------------
    @log_call
    def recv(self, n: int) -> bytes:
        while len(self._recv_buffer) == 0:
            logger.debug('Current recv buffer: %s', self._recv_buffer.getvalue())
            time.sleep(self._settings.recv_data_wait.total_seconds())
        data = bytes(self._recv_buffer.get(n))
        logger.info("Recv: %s %s", len(data), data[:MAX_LOG_DATA_SIZE])
        return data

    @log_call
    def _recv_worker(self):
        try:
            while self._is_recv_worker_running:
                try:
                    data = self.recvfrom(Segment.size)
                except BlockingIOError:
                    continue

                with self._send_change_state_lock:
                    pass
                self._recv(data=data)
        except Exception as e:
            logger.exception('Exception in worker')
            raise e

    @log_call
    def _recv(self, data: bytes):
        segment = self._formatter.parse_segment(data)
        logger.info('recv %s %s', len(data), segment)
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

        self._byte_to_read = received_segment.data_start_byte
        syn_ack_segment = Segment(
            sender_port=self._sender_port,
            receiver_port=self._receiver_port,
            data_start_byte=self._data_start_byte,
            byte_to_read=self._byte_to_read,
            segment_flags=(SegmentFlag.SYN, SegmentFlag.ACK),
            window_size=1,
            urgent_pointer=0,
            segment_params={},
            data=None,
        )
        with self._send_change_state_lock:
            self._send_segment(segment=syn_ack_segment)
            self._state = TCPState.WAITING_FOR_CONNECTION_ACK

    @log_call
    def _on_recv_wait_for_connection_ack(self, received_segment: Segment):
        if (SegmentFlag.ACK,) == received_segment.segment_flags:
            self._state = TCPState.CONNECTED
        elif (SegmentFlag.SYN,) == received_segment.segment_flags:
            logger.info('Got SYN again, retry SYN ACK')
            self._on_recv_initial(received_segment=received_segment)
        elif tuple() == received_segment.segment_flags:
            logger.info('Got data already, believe that connect was ACKed')
            self._state = TCPState.CONNECTED
            self._on_recv_connected(received_segment=received_segment)
        else:
            raise TCPUnexpectedSegmentError(f'{received_segment}')

    @log_call
    def _on_recv_wait_for_connection_syn_ack(self, received_segment: Segment, change_state_to_connected: bool = True):
        if sorted((SegmentFlag.ACK, SegmentFlag.SYN)) != sorted(received_segment.segment_flags):
            raise TCPUnexpectedSegmentError(f'{received_segment}')

        ack_segment = Segment(
            sender_port=self._sender_port,
            receiver_port=self._receiver_port,
            data_start_byte=self._data_start_byte,
            byte_to_read=self._byte_to_read,
            segment_flags=(SegmentFlag.ACK,),
            window_size=1,
            urgent_pointer=0,
            segment_params={},
            data=None,
        )
        with self._send_change_state_lock:
            self._send_segment(segment=ack_segment)
            if change_state_to_connected:
                self._state = TCPState.CONNECTED

    @log_call
    def _on_recv_connected(self, received_segment: Segment):
        if received_segment.segment_flags == tuple():
            return self._on_recv_data(received_segment)
        elif received_segment.segment_flags == (SegmentFlag.ACK,):
            logger.debug('Duplicated ACK possible, process')
            return self._on_recv_wait_for_data_ack(received_segment)
        elif received_segment.segment_flags == (SegmentFlag.ACK, SegmentFlag.SYN):
            logger.debug('Duplicated SYN ACK possible, process')
            return self._on_recv_wait_for_connection_syn_ack(received_segment)
        elif received_segment.segment_flags == (SegmentFlag.FIN,):
            raise NotImplementedError()
        elif received_segment.segment_flags == (SegmentFlag.RST,):
            raise NotImplementedError()

        raise RuntimeError(f'Unreachable code with state {self._state} {received_segment.segment_flags}')

    @log_call
    def _on_recv_data(self, received_segment: Segment):
        data_len = received_segment.segment_params['data']
        total_data_len = received_segment.segment_params['size']
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
            )

            if self._recv_pre_buffer_total_size < total_data_len:
                self._recv_pre_buffer_total_size += data_len
                self._non_acked_size += data_len
                logger.info(
                    'Accumulated in buffer %s / %s bytes',
                    self._recv_pre_buffer_total_size,
                    total_data_len
                )
                self._recv_pre_buffer.append(received_segment.data)

            if self._recv_pre_buffer_total_size == total_data_len:
                logger.info('Flushing %s bytes from buffer', self._recv_pre_buffer_total_size)
                self._recv_buffer.put(b''.join(self._recv_pre_buffer))
                self._recv_pre_buffer = []
                self._recv_pre_buffer_total_size = 0
                self._non_acked_size = self._settings.window_size
            elif self._recv_pre_buffer_total_size > total_data_len:
                raise TCPTooMuchDataError(f'in buffer {self._recv_pre_buffer_total_size} expected {total_data_len}')

            if self._non_acked_size >= self._settings.window_size:
                logger.info('Batch ACK of %s bytes with ws %s', self._non_acked_size, self._settings.window_size)
                self._non_acked_size = 0
                ack_segment = Segment(
                    sender_port=self._sender_port,
                    receiver_port=self._receiver_port,
                    data_start_byte=self._data_start_byte,
                    byte_to_read=self._byte_to_read,
                    segment_flags=(SegmentFlag.ACK,),
                    window_size=1,
                    urgent_pointer=0,
                    segment_params={},
                    data=None,
                )
                with self._send_change_state_lock:
                    self._send_segment(segment=ack_segment)

        elif received_segment.data_start_byte > self._byte_to_read:
            # получили сегмент данных из будущего
            # raise TCPUnexpectedSegmentError(received_segment)
            logger.warning('Got future segment %s', received_segment)
        else:
            # получили старый сегмент данных из-за ретрая
            logger.info('_on_recv_data old segment, just ACK')

            ack_segment = Segment(
                sender_port=self._sender_port,
                receiver_port=self._receiver_port,
                data_start_byte=self._data_start_byte,
                byte_to_read=self._byte_to_read,
                segment_flags=(SegmentFlag.ACK,),
                window_size=1,
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
            elif segment.segment_flags == (SegmentFlag.ACK, SegmentFlag.SYN):
                return self._on_recv_wait_for_connection_syn_ack(segment, change_state_to_connected=False)
            raise TCPUnexpectedSegmentError(f'{segment}')

        if self._data_start_byte >= segment.byte_to_read:
            logger.info('Old ACK received, skip ACK')
            return
        self._data_start_byte = segment.byte_to_read
        self._state = TCPState.CONNECTED
        self._reset_all_retries()
        logger.debug('Data was ACKed')
