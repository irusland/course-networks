from typing import Iterable

from hw1.tcp.segment import Segment
from hw1.tcp.segment_formatter import TCPSegmentFormatter


class TCPDataSegmentizer:
    def __init__(self, tcp_segment_formatter: TCPSegmentFormatter):
        self._tcp_segment_formatter = tcp_segment_formatter

    def to_segments(self, data: bytes) -> Iterable[Segment]:
        ...

    def to_data(self, segments: Iterable[Segment]) -> Iterable[bytes]:
        ...
