import dataclasses
import datetime


@dataclasses.dataclass(init=True)
class TCPSettings:
    connect_ack_wait = datetime.timedelta(milliseconds=10)
    connect_ack_retries = 30

    recv_data_wait = datetime.timedelta(milliseconds=10)

    data_ack_wait = datetime.timedelta(milliseconds=10)
    data_ack_retries = 30
