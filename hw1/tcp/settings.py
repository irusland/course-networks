import dataclasses
import datetime


@dataclasses.dataclass(init=True)
class TCPSettings:
    connect_ack_wait = datetime.timedelta(milliseconds=1)
    connect_ack_retries = 30

    recv_data_wait = datetime.timedelta(milliseconds=1)

    data_ack_wait = datetime.timedelta(milliseconds=1)
    data_ack_retries = 30

    send_data_retries = 30
