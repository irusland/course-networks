class TCPError(Exception):
    ...


class TCPConnectionACKTimeout(TCPError):
    ...


class TCPUnexpectedSegmentError(TCPError):
    ...


class TCPDataACKTimeout(TCPError):
    ...
