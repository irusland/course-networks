import json
import logging
import pickle
from typing import Iterable, Optional, Any

from tcp.segment import Segment, SegmentFlag

logger = logging.getLogger(__name__)


class TCPSegmentPickleFormatter:
    def serialize(self, segments: Iterable[Segment]) -> Iterable[bytes]:
        for segment in segments:
            yield self.serialize_segment(segment)

    def serialize_segment(self, segment: Segment) -> bytes:
        logger.debug('Serializing segment %s', segment)
        b= pickle.dumps(segment)
        bb=bytearray(Segment.size)
        bb[:len(b)] = b
        return bb

    def parse(self, segments: Iterable[bytes]) -> Iterable[Segment]:
        for segment in segments:
            yield self.parse_segment(raw_segment=segment)

    def parse_segment(self, raw_segment: bytes) -> Segment:
        return pickle.loads(raw_segment)
