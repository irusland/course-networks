import dataclasses
import datetime


@dataclasses.dataclass(init=True)
class TCPSettings:
    connect_ack_wait = datetime.timedelta(milliseconds=100)
    connect_ack_retries = 3

    recv_data_wait = datetime.timedelta(milliseconds=100)

    data_ack_wait = datetime.timedelta(milliseconds=100)
    data_ack_retries = 3
