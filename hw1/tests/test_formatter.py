import random

import pytest

from hw1.tcp.segment import Segment, SegmentFlag
from hw1.tcp.segment_formatter import TCPSegmentFormatter


@pytest.mark.parametrize(
    'segment', [
        Segment(
            sender_port=322,
            receiver_port=1337,
            data_start_byte=1337,
            byte_to_read=0,
            segment_flags=(SegmentFlag.SYN,),
            window_size=1 * Segment.size,
            urgent_pointer=0,
            segment_params={},
            data=None,
        ),
        Segment(
            sender_port=random.randint(1, 5000),
            receiver_port=random.randint(1, 5000),
            data_start_byte=random.randint(1, 5000),
            byte_to_read=random.randint(1, 5000),
            segment_flags=(SegmentFlag.SYN,),
            window_size=random.randint(1, 10) * Segment.size,
            urgent_pointer=0,
            segment_params={'data': 100},
            data=(123456789).to_bytes(100, byteorder='big'),
        ),
        Segment(
            sender_port=28467,
            receiver_port=28438,
            data_start_byte=593,
            byte_to_read=67,
            segment_flags=(SegmentFlag.SYN, SegmentFlag.ACK),
            window_size=Segment.size,
            urgent_pointer=0,
            segment_params={},
            data=None
        )

    ]
)
def test_formatter_parses(segment):
    formatter = TCPSegmentFormatter()

    data = formatter.serialize_segment(segment=segment)
    parsed_segment = formatter.parse_segment(raw_segment=data)

    assert segment == parsed_segment
    assert len(data) == segment.size == parsed_segment.size == Segment.size
