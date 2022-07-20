from ssl_networking import socket, ssl

from ssl_networking.config import PORT, IP_PREFIX, CHUNK_SIZE


class SSLServer:
    """
    A SSL-wrapped server for receiving messages for a Certificate entity
    """
    def __init__(self, entity_name, cert_file):
        self.entity_name = entity_name
        self.host = IP_PREFIX + self.entity_name[-1]
        self.port = PORT
        self._context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self._context.load_cert_chain(cert_file)

    def connect(self):
        """
        Connects to a SSL-wrapped socket
        :return:
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind((self.host, self.port))
            sock.listen(5)
            while True:
                conn, _ = sock.accept()
                with self._context.wrap_socket(conn, server_side=True) as sconn:
                    self._recv(sconn)

    def _recv(self, sock):
        """
        Receives a message in the SSL-wrapped socket
        :param sock:
        :return:
        """
        print(f"\t{str(self.entity_name).capitalize()}: Hey! It seems I'm going to get a message!")
        msg = ""
        while True:
            data = sock.recv(CHUNK_SIZE)
            msg += data.decode()
            if not data and msg:
                break
        print(f"\t{str(self.entity_name).capitalize()}: I got this message: {msg}")

    def get_connection_details(self):
        """
        :return: the server's host and port
        """
        return self.host, self.port
