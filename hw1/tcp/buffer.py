class Buffer:
    def __init__(self):
        self._buf = bytearray()

    def put(self, data):
        self._buf.extend(data)

    def get(self, size):
        data = self._buf[:size]
        self._buf[:size] = b''
        return data

    def peek(self, size):
        return self._buf[:size]

    def getvalue(self):
        return self._buf

    def __len__(self):
        return len(self._buf)


if __name__ == '__main__':
    buffer = Buffer()
    print(buffer.getvalue())
    buffer.put(b'asd')
    print(buffer.getvalue())
    buffer.put(b'asd')
    print(buffer.getvalue())
    buffer.get(6)
    print(buffer.getvalue())
