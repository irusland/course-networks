from typing import Iterable

from hw1.tcp.segment import Segment, SegmentFlag
import random


class TCPDataSegmentizer:
    def to_segments(self, data: bytes) -> Iterable[Segment]:
        ...

    def to_data(self, segments: Iterable[Segment]) -> Iterable[bytes]:
        ...
