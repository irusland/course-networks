class TCPError(Exception):
    ...


class TCPConnectionACKTimeout(TCPError):
    ...


class TCPUnexpectedSegmentError(TCPError):
    ...


class TCPDataACKTimeout(TCPError):
    ...


class TCPDataSendRetryExhausted(TCPError):
    ...


class TCPTooMuchDataError(TCPError):
    ...
