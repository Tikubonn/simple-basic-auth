
import pytest
from http.server import HTTPServer, BaseHTTPRequestHandler
from multiprocessing import Process
from simple_basic_auth import BasicAuth

class _TestServer (HTTPServer):

  def __init__ (self, server_address:tuple[str, int], auth:"simple_basic_auth.BasicAuth"):
    super().__init__(server_address, _TestHandler)
    self.auth = auth

class _TestHandler (BaseHTTPRequestHandler):

  def do_GET (self):
    if self.server.auth.authorize(self):
      self.send_response(200)
      self.end_headers()
    else:
      self.server.auth.send_unauthorized(self)

TEST_USER:str = "User"
TEST_PASSWORD:str = "Password"
TEST_REALM:str = "Realm"
TEST_SERVER_ADDRESS:tuple[str, int] = ("127.0.0.1", 8080)

def _process_main ():
  auth = BasicAuth(TEST_USER, TEST_PASSWORD, TEST_REALM)
  server = _TestServer(TEST_SERVER_ADDRESS, auth)
  server.serve_forever()

@pytest.fixture
def test_server ():
  process = Process(target=_process_main, daemon=True)
  process.start()
  yield process
  process.kill()
