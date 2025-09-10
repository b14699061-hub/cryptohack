import socket

class Client:
    """
    A simple client class for a socket connection.
    """
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = None

    def connect(self):
        """
        Connects the client to the server.
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            self.sock.connect((self.host, self.port))
            
        except ConnectionRefusedError:
            
            self.close()
            return False
        except Exception as e:
            
            self.close()
            return False
        return True

    def send_message(self, message: str) -> str:
        if not self.sock:
            return "Error: Client is not connected to a server."

        try:
            self.sock.sendall(message.encode('utf-8'))
            
            data = self.sock.recv(1024)
            
            response = data.decode('utf-8')
            
            return response
            
        except Exception as e:
            
            return f"Error: {e}"

    def close(self):
        """
        Closes the socket connection.
        """
        if self.sock:
            self.sock.close()
            self.sock = None