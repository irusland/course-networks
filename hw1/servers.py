import logging
import os

from protocol import MyTCPProtocol

logger = logging.getLogger(__name__)


class Base:
    def __init__(self, socket: MyTCPProtocol, iterations: int, msg_size: int):
        self.socket = socket
        self.iterations = iterations
        self.msg_size = msg_size


class EchoServer(Base):

    def run(self):
        for i in range(self.iterations):
            logger.info('Server iteration = %s/%s', i, self.iterations)
            msg = self.socket.recv(self.msg_size)
            self.socket.send(msg)


class EchoClient(Base):

    def run(self):
        for i in range(self.iterations):
            logger.info('Client iteration = %s/%s', i, self.iterations)
            expected_msg = os.urandom(self.msg_size)
            n = self.socket.send(expected_msg)
            assert n == self.msg_size
            actual_msg = self.socket.recv(n)
            assert actual_msg == expected_msg
