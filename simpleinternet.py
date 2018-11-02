import socket
import threading

def get_my_ip_address(use_ipv6=True):
  payload = b"""GET / HTTP/1.1\nHost: ifconfig.co\nUser-Agent: curl/7.54.0\nAccept: */*\n"""
  s = socket.socket(socket.AF_INET6 if use_ipv6 else socket.AF_INET, socket.SOCK_STREAM)
  s.connect(('ifconfig.co', 80))
  s.sendall(m)
  ip_address = s.recv(1024).split(b'\r\n')[-1].strip()
  s.close()
  return ip_address

class SimpleServerThread(therading.Thread):
  def __init__(self, client_socket, address, handle_message, global_state, client_state):
    self.client_socket = client_socket
    self.address = address
    self.handle_message = handle_message
    self.global_state = global_state
    self.client_state = client_state
  def run(self):
    error = None
    while 1:
      message = receive_chunked_data(self.client_socket)
      status, response = self.handle_message(message, self.address, self.global_state, self.client_state)
      if status == SimpleNetStatus.leave:
        break
      elif status == SimpleNetStatus.stay:
        pass
      else:
        error = "Bad status from handler (%s)" % (status,)
        break
      send_data_as_chunks(response, self.client_socket)
    if error:
      raise Error(error)

def receive_chunked_data(send_socket):
  message = b''
  while 1:
    chunk = self.client_socket.recv(1024)
    chunk_length = int(chunk[:4])
    if chunk_length == 1021:
      message += chunk[4:]
      continue
    break
  message += chunk[4:chunk_length + 4]
  return message

def chunkify_for_sending(data):
  if data == b'':
    return [b'0000']
  chunks = []
  a = 0
  z = 1020
  while a < len(data):
    chunks.append(data[a:z])
    a = z
    z += 1020
  return list(map(lambda chunk: b'%04d' % len(chunk) + chunk))

def send_data_as_chunks(data, recv_socket):
  chunks = chunkify_for_sending(data)
  for chunk in chunks:
    recv_socket.sendall(chunk)

class SimpleNetStatus:
  leave = 0
  stay = 1

class SimpleServer:
  def __init__(self, initial_global_state, generate_client_state, handle_message, port=23, use_ipv6=True):
    self.global_state = initial_global_state
    self.generate_client_state = generate_client_state
    self.handle_message = handle_message
    self.port = port
    self.use_ipv6 = use_ipv6
    self.socket = socket.socket(socket.AF_INET6 if use_ipv6 else socket.AF_INET, socket.SOCK_STREAM)
  def start(self):
    self.socket.bind((socket.gethostname(), self.port))
    self.socket.listen(5)
    while 1:
      client_socket, address = self.socket.accept()
      client_thread = SimpleServerThread(client_socket,
                                         address,
                                         self.handle_message,
                                         self.global_state,
                                         self.generate_client_state(self.global_state, address))

class SimpleClient:
  def __init__(self, server_address, initial_state, handle_message, first_message=b'', port=23, use_ipv6=True):
    self.server_address = server_address
    self.state = initial_state
    self.handle_message = handle_message
    self.first_message = first_message
    self.port = port
    self.use_ipv6 = use_ipv6
    self.socket = socket.socket(socket.AF_INET6 if use_ipv6 else socket.AF_INET, socket.SOCK_STREAM)
  def start(self):
    self.socket.connect((self.server_address, self.port))
    message = self.first_message
    error = None
    while 1:
      send_data_as_chunks(message, self.socket)
      response = receive_chunked_data(self.socket)
      status, message = self.handle_message(response, self.server_address, self.state)
      if status == SimpleNetStatus.leave:
        break
      elif status == SimpleNetStatus.stay:
        pass
      else:
        raise Error("Bad status from handler (%s)" % (status,))
