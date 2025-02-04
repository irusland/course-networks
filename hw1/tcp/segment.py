import dataclasses
import logging
from enum import IntEnum
from typing import Any, Optional, Tuple

from tcp.settings import MAX_LOG_DATA_SIZE


class SegmentFlag(IntEnum):
    ACK = 1
    SYN = 2
    FIN = 4
    RST = 8
    # More flags possible


logger = logging.getLogger(__name__)


@dataclasses.dataclass(init=True, frozen=True)
class Segment:
    """
    ———————————————————————  32 bits  ————————————————————————
          Sender Port            |        Receiver port
    ——————————————————————————————————————————————————————————
                      Data start byte number
    ——————————————————————————————————————————————————————————
                         ACK byte number
    ——————————————————————————————————————————————————————————
    Header len   |    FLAGS     |          Window Size
    ——————————————————————————————————————————————————————————
              Check sum.        |   unused urgent
    ——————————————————————————————————————————————————————————
                       Optional[Params].
    ——————————————————————————————————————————————————————————
                         Optional[Data].
    ——————————————————————————————————————————————————————————
    FLAG - ACK, SYN, FIN, RST
    Params - MSS (Max Segment Size), Window Size (До 1ГБ), SACK
    Max data transmission - 4GB
    """
    sender_port: int  # 2 bytes
    receiver_port: int  # 2 bytes
    data_start_byte: int  # 4 bytes
    byte_to_read: int  # 4 bytes

    @property
    def header_len(self) -> int:  # 1 byte
        return (
            2 + 2 + 4 + 4 + 1 + 1 + 2 + 2
            + 40  # may be counted dynamically
        )

    segment_flags: Tuple[SegmentFlag, ...]  # 1 byte
    window_size: int  # 2 bytes

    @property
    def check_sum(self) -> int:  # 2 bytes
        fields = (
            self.sender_port,
            self.receiver_port,
            self.data_start_byte,
            self.byte_to_read,
            self.header_len,
            tuple(sorted(self.segment_flags)),
            self.window_size,
            # self.check_sum,
            self.urgent_pointer,
            tuple(self.segment_params.items()),
            self.data,
        )
        check_sum = hash(fields)
        return check_sum % self.get_max_value('check_sum')

    urgent_pointer: int  # 2 bytes
    segment_params: dict[str, Any]  # 0-40 bytes
    data: Optional[bytes]  # 0-1460(1420 if segment_params) bytes

    _field_name_to_bytes_num = {
        'sender_port': 2,
        'receiver_port': 2,
        'data_start_byte': 4,
        'byte_to_read': 4,
        'header_len': 1,
        'segment_flags': 1,
        'window_size': 2,
        'check_sum': 2,
        'urgent_pointer': 2,
        'segment_params': 40,
        'data': 14200,
    }

    size = sum(_field_name_to_bytes_num.values())

    @staticmethod
    def get_bytes_num(field_name: str) -> int:
        return Segment._field_name_to_bytes_num[field_name]

    @staticmethod
    def get_max_value(field_name: str) -> int:
        byte_len = Segment.get_bytes_num(field_name=field_name)
        max_value = 2 ** (byte_len * 8)
        return max_value

    def __repr__(self) -> str:
        kws = []
        for field_name in self._field_name_to_bytes_num.keys():
            value = getattr(self, field_name)
            if field_name == 'data' and value is not None:
                data_len = len(value)
                if data_len > MAX_LOG_DATA_SIZE:
                    value = f'{value[:MAX_LOG_DATA_SIZE]}...{data_len-MAX_LOG_DATA_SIZE}...'
            kws.append(f"{field_name}={value!r}")

        return "{}({})".format(type(self).__name__, ", ".join(kws))

    def __hash__(self) -> int:
        return self.check_sum

    def __eq__(self, other) -> bool:
        if "Segment" in str(type(other)):  # todo: fix relative import issue
            for field in self._field_name_to_bytes_num.keys():
                if field == 'segment_flags':
                    continue
                if getattr(self, field) != getattr(other, field):
                    return False
            if sorted(self.segment_flags) != sorted(other.segment_flags):
                return False
            return True
        return False
