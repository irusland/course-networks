import json
import logging
from typing import Iterable, Optional, Any

from tcp.segment import Segment, SegmentFlag

logger = logging.getLogger(__name__)


class TCPSegmentFormatter:
    def serialize(self, segments: Iterable[Segment]) -> Iterable[bytes]:
        for segment in segments:
            yield self.serialize_segment(segment)

    def serialize_segment(self, segment: Segment) -> bytes:
        logger.debug('Serializing segment %s', segment)
        data: list[bytes] = []

        data.append(self._get_int_data(segment=segment, field_name='sender_port'))
        data.append(self._get_int_data(segment=segment, field_name='receiver_port'))
        data.append(self._get_int_data(segment=segment, field_name='data_start_byte'))
        data.append(self._get_int_data(segment=segment, field_name='byte_to_read'))
        data.append(self._get_int_data(segment=segment, field_name='header_len'))

        data.append(self._get_flags_data(segment=segment))

        data.append(self._get_int_data(segment=segment, field_name='window_size'))
        data.append(self._get_int_data(segment=segment, field_name='check_sum'))
        data.append(self._get_int_data(segment=segment, field_name='urgent_pointer'))

        data.append(self._get_segment_params(segment=segment))

        data.append(self._get_data(segment))

        return b''.join(data)

    def _get_data(self, segment: Segment) -> bytes:
        data_max_len = segment.get_bytes_num('data')
        raw_data = bytearray(data_max_len)
        if segment.data is None:
            return bytes(data_max_len)
        raw_data[0:segment.segment_params['data']] = segment.data
        return bytes(raw_data)

    def _get_flags_data(self, segment: Segment) -> bytes:
        flags_value = 0
        for flag in segment.segment_flags:
            flags_value |= flag

        return flags_value.to_bytes(
            segment.get_bytes_num('segment_flags'),
            byteorder='big'
        )

    def _get_int_data(self, segment: Segment, field_name: str) -> bytes:
        field_value = getattr(segment, field_name)
        assert segment.get_max_value(field_name) > field_value  # todo rm
        return field_value.to_bytes(
            segment.get_bytes_num(field_name),
            byteorder='big'
        )

    def _get_segment_params(self, segment: Segment) -> bytes:
        jparams = json.dumps(segment.segment_params).encode('ascii')
        params = bytearray(40)
        params[0:len(jparams)] = jparams
        return bytes(params)

    def parse(self, segments: Iterable[bytes]) -> Iterable[Segment]:
        for segment in segments:
            yield self.parse_segment(raw_segment=segment)

    def parse_segment(self, raw_segment: bytes) -> Segment:
        bytes_processed = 0
        was_processed, sender_port = self._get_int_from(
            raw=raw_segment, bytes_processed=bytes_processed, field_name='sender_port'
        )
        bytes_processed += was_processed
        was_processed, receiver_port = self._get_int_from(
            raw=raw_segment, bytes_processed=bytes_processed, field_name='receiver_port'
        )
        bytes_processed += was_processed
        was_processed, data_start_byte = self._get_int_from(
            raw=raw_segment, bytes_processed=bytes_processed, field_name='data_start_byte'
        )
        bytes_processed += was_processed
        was_processed, byte_to_read = self._get_int_from(
            raw=raw_segment, bytes_processed=bytes_processed, field_name='byte_to_read'
        )
        bytes_processed += was_processed
        was_processed, header_len = self._get_int_from(
            raw=raw_segment, bytes_processed=bytes_processed, field_name='header_len'
        )
        bytes_processed += was_processed
        was_processed, segment_flags = self._segment_flags_from(
            raw=raw_segment, bytes_processed=bytes_processed
        )
        bytes_processed += was_processed
        was_processed, window_size = self._get_int_from(
            raw=raw_segment, bytes_processed=bytes_processed, field_name='window_size'
        )
        bytes_processed += was_processed
        was_processed, check_sum = self._get_int_from(
            raw=raw_segment, bytes_processed=bytes_processed, field_name='check_sum'
        )
        bytes_processed += was_processed
        was_processed, urgent_pointer = self._get_int_from(
            raw=raw_segment, bytes_processed=bytes_processed, field_name='urgent_pointer'
        )
        bytes_processed += was_processed

        was_processed, segment_params = self._segment_params_from(raw=raw_segment, bytes_processed=bytes_processed)
        bytes_processed += was_processed

        bytes_processed, data = self._data_from(bytes_processed, raw_segment, segment_params)
        bytes_processed += was_processed

        segment = Segment(
            sender_port=sender_port,
            receiver_port=receiver_port,
            data_start_byte=data_start_byte,
            byte_to_read=byte_to_read,
            segment_flags=segment_flags,
            window_size=window_size,
            urgent_pointer=urgent_pointer,
            segment_params=segment_params,
            data=data,
        )

        self._validate_segment(
            segment=segment, header_len=header_len, check_sum=check_sum
        )
        logger.debug('Parsed segment %s', segment)
        return segment

    def _get_int_from(self, raw: bytes, bytes_processed: int, field_name: str) -> tuple[int, int]:
        num = Segment.get_bytes_num(field_name=field_name)
        data = raw[bytes_processed: bytes_processed + num]
        return num, self._int_from(data=data)

    def _int_from(self, data: bytes) -> int:
        return int.from_bytes(data, byteorder='big')

    def _segment_flags_from(self, raw: bytes, bytes_processed: int) -> tuple[int, tuple[SegmentFlag]]:
        num = Segment.get_bytes_num(field_name='segment_flags')
        data = raw[bytes_processed: bytes_processed + num]
        flags_value = self._int_from(data=data)
        real_flags: list[SegmentFlag] = []
        for possible_flag in list(SegmentFlag):
            if flags_value & possible_flag > 0:
                real_flags.append(possible_flag)

        return num, tuple(real_flags)

    def _segment_params_from(self, raw: bytes, bytes_processed: int) -> tuple[int, dict[str, Any]]:
        num = Segment.get_bytes_num('segment_params')
        data = raw[bytes_processed: bytes_processed + num]
        ascii_params = data.decode('ascii')
        final_bracket_idx = ascii_params.rindex('}')
        json_params = ascii_params[:final_bracket_idx + 1]
        return num, json.loads(json_params)

    def _data_from(self, bytes_processed: int, raw_segment: bytes, segment_params: dict[str, Any]) -> tuple[int, Optional[bytes]]:
        data_len = segment_params.get('data', 0)
        if data_len == 0:
            data = None
        else:
            data = raw_segment[bytes_processed:bytes_processed + data_len]
        was_processed = Segment.get_bytes_num('data')
        return was_processed, data

    def _validate_segment(self, segment: Segment, header_len: int, check_sum: int):
        if segment.header_len != header_len:
            raise ValueError('invalid header len')
        if segment.check_sum != check_sum:
            raise ValueError(f'invalid check_sum, expected "{check_sum}", actual: "{segment.check_sum}" of segment {segment}')
        if segment.data is not None:
            if len(segment.data) != segment.segment_params['data']:
                raise ValueError('invalid data len')
