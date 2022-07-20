from ssl_networking import socket, ssl


class SSLClient:
    """
    A SSL-wrapped server for sending messages for a Certificate entity
    """
    def __init__(self, entity_name, cert_file):
        self.entity_name = entity_name
        self._context = ssl.SSLContext()
        self._context.load_cert_chain(cert_file)
        self._sock = None
        self._ssock = None

    def __del__(self):
        self.close()

    def connect(self, server_host, server_port):
        """
        Connects to another SSL-wrapped server, for communication
        :param server_host: the other server's host
        :param server_port: the other server's port
        :return:
        """
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._ssock = self._context.wrap_socket(self._sock,)
        self._ssock.connect((server_host, server_port))

    def send(self, msg):
        """
        Sends a message
        :param msg: a message; a string
        :return:
        """
        print(f'\t{str(self.entity_name).capitalize()}: Sending now the message. Good luck for me!')
        self._ssock.send(msg.encode())


    def close(self):
        """
        Closes the socket
        :return:
        """
        self._ssock.close()
