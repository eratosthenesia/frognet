import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

def now():
  return time.clock_gettime(0)

def bytify(thing):
  return base64.b64encode(pickle.dumps(thing))

def unbytify(thingbytes):
  return pickle.loads(base64.b64decode(thingbytes))

def file_contents(file_path):
  with open(file_path, 'rb') as file:
    contents = file.read()
  return contents

class RSAMessage:
  def __init__(self, ciphertext, signature):
    self.ciphertext = ciphertext
    self.signature = signature

class RSANode:
  def __init__(self, password=None, public_exponent=65537, key_size=2048, bytify=None, unbytify=None,
                     public_key_raw=None, _private_key_raw=None, public_mode=False):
    if public_key_raw:
      if isinstance(public_key_raw, tuple):
        public_key_raw, from_file = public_key_raw
        if from_file:
          public_key_raw = file_contents(public_key_raw)
      self.raw_mode = True
      self.public_key_raw = public_key_raw
      if _private_key_raw:
        if isinstance(_private_key_raw, tuple):
          _private_key_raw, from_file = _private_key_raw
          if from_file:
            _private_key_raw = file_contents(_private_key_raw)
        self._private_key_raw = _private_key_raw
        self.public_mode = False
      else:
        self.public_mode = public_mode
      self.set_password(password)
    else:
      self.raw_mode = False
      self._private_key = rsa.generate_private_key(backend=default_backend(), public_exponent=public_exponent, key_size=key_size)
      self.public_key = self._private_key.public_key()
      self.public_mode = False
      self.set_password(password)
    self.talking_to = None
    self.messages = {}
    self.fake_messages = {}
    self.message_digest = []
    self.public_exponent = public_exponent
    self.key_size = key_size
    self.bytify = bytify
    self.unbytify = unbytify
  def pub(self):
    if hasattr(self, 'public_key'):
      return self.public_key.public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.PKCS1)
    return None
  def hash(self):
    return hash(self.pub())
  def __eq__(self, other):
    return isinstance(other, RSANode) and self.pub() == other.pub()
  def talk_to(self, other_node, reciprocate=False):
    self.talking_to = other_node
    if reciprocate:
      other_node.talking_to = self
  def set_password(self, password, do_unset_raw=True):
    self.password = self.bytify(password)
    if do_unset_raw and self.raw_mode:
      self.unset_raw()
  def unset_raw(self):
    if not self.public_mode:
      self._private_key = load_pem_private_key(data=self._private_key_raw, password=self.password, backend=default_backend())
    self.public_key = load_pem_public_key(data=self.public_key_raw, backend=default_backend())
    del self._private_key_raw
    del self.public_key_raw
    self.raw_mode = False
  def __getstate__(self):
    state = self.__dict__.copy()
    if '_private_key_raw' in state:
      return state
    if not self.public_mode:
      state['_private_key_raw'] = state['_private_key'].private_bytes(serialization.Encoding.PEM,
                                                                      serialization.PrivateFormat.PKCS8,
                                                                      serialization.BestAvailableEncryption(self.password))
    state['public_key_raw'] = self.pub()
    del state['_private_key']
    del state['public_key']
    return state
  def __setstate__(self, state):
    self.__dict__.update(state)
    self.raw_mode = True
  def resolve_other_node(self, other_node):
    if other_node is None:
      other_node = self.talking_to
    if other_node is None:
      raise Error("Must have a sender in mind")
    return other_node
  def check_permissions(self):
    if self.raw_mode:
      raise Error("RSANode must be given a password after being loaded.")
    if self.public_mode:
      raise Error("Cannot decrypt or sign without being out of private mode.")
  def chunkify(self, bytes):
    chunks = []
    a = 0
    b = self.key_size >> 4
    while a < len(bytes):
      chunks.append(bytes[a:b])
      a = b
      b += self.key_size >> 4
    return chunks
  def encrypt(self, data, other_node):
    other_node = self.resolve_other_node(other_node)
    self.check_permissions()
    data_bytes = self.bytify(data)
    chunks = self.chunkify(data_bytes)
    encrypted_chunks = [self.encrypt_chunk(chunk, other_node) for chunk in chunks]
    return self.bytify(encrypted_chunks)
  def encrypt_chunk(self, chunk, other_node):
    ciphertext = other_node.public_key.encrypt(chunk,
                                               padding.OAEP(
                                                 mgf=padding.MGF1(
                                                   algorithm=hashes.SHA1()),
                                                 algorithm=hashes.SHA1(),
                                                 label=None))
    signature = self._private_key.sign(chunk,
                                       padding.PSS(
                                         mgf=padding.MGF1(
                                           algorithm=hashes.SHA1()),
                                         salt_length=padding.PSS.MAX_LENGTH),
                                       hashes.SHA256())
    message = {'ciphertext': ciphertext, 'signature': signature}
    return self.bytify(message)
  def decrypt(self, message_bytes, other_node=None):
    other_node = self.resolve_other_node(other_node)
    self.check_permissions()
    encrypted_chunks = self.unbytify(message_bytes)
    decrypted_chunks = [self.decrypt_chunk(chunk, other_node) for chunk in encrypted_chunks]
    data_bytes = b''
    genuine_ratio = 0
    signatures = []
    for chunk_data in decrypted_chunks:
      data_bytes += chunk_data['message']
      genuine_ratio += 1 if chunk_data['genuine'] else 0
      signatures.append(chunk_data['signature'])
    genuine_ratio /= len(decrypted_chunks)
    return {'data': self.unbytify(data_bytes), 'genuine_ratio': genuine_ratio, 'signatures': signatures}
  def decrypt_chunk(self, message_bytes, other_node):
    message = self.unbytify(message_bytes) 
    ciphertext = message['ciphertext']
    signature = message['signature']
    data_bytes = self._private_key.decrypt(ciphertext,
                                          padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                            algorithm=hashes.SHA1(),
                                            label=None))
    try:
      other_node.public_key.verify(signature,
                                   data_bytes,
                                   padding.PSS(
                                     mgf=padding.MGF1(hashes.SHA1()),
                                     salt_length=padding.PSS.MAX_LENGTH),
                                   hashes.SHA256())
      genuine = True
    except cryptography.exceptions.InvalidSignature:
      genuine = False
    return {'message': data_bytes, 'genuine': genuine, 'signature': signature}
  def send(self, thing, other_node=None):
    other_node = self.resolve_other_node(other_node)
    other_node.recv(self.encrypt(thing, other_node), self)
  def recv(self, message_bytes=None, other_node=None):
    other_node = self.resolve_other_node(other_node)
    message_data = self.decrypt(message_bytes, other_node)
    pub = other_node.pub()
    if message_data['genuine_ratio'] == 1:
      messages = self.messages
    else:
      messages = self.fake_messages
    if pub not in messages:
      self.messages[pub] = {}
    messages[pub][now()] = message_data
    self.message_digest.append({'from': pub[100:100+32], 'data': message_data['data'], 'genuine_ratio': message_data['genuine_ratio'], 'at': now()})

x=RSANode('abc')
y=RSANode('def')
x.talk_to(y, True)
x.send('hi')
x.send('bye')
x.send(y)
print(y.message_digest)