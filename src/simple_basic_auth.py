
import re
import base64
import secrets
import logging
import traceback
from typing import ClassVar
from dataclasses import dataclass

"""http.server 向けの簡素な Basic 認証の機能を提供します。

Examples
--------
>>> from http.server import BaseHTTPRequestHandler, HTTPServer
>>> from simple_basic_auth import BasicAuth
>>> 
>>> class _Handler (BaseHTTPRequestHandler):
>>>   def do_GET (self):
>>>     auth = BasicAuth("anonymous", "password", "SecretZone")
>>>     if auth.authorize(self):
>>>       self.send_response(200)
>>>       self.send_header("Content-Type", "text/plain; charset=ascii")
>>>       self.end_headers()
>>>       self.wfile.write(b"Authorization was succeed.")
>>>     else:
>>>       auth.send_unauthorized(self)
>>> 
>>> with HTTPServer(("127.0.0.1", 8080), _Handler) as server:
>>>  try:
>>>    server.serve_forever()
>>>  except KeyboardInterrupt:
>>>    pass
"""

_LOGGER:"logging.Logger" = logging.getLogger(__name__)

@dataclass(frozen=True)
class BasicAuth:

  """1ユーザに対する Basic 認証機能を提供します。

  Attributes
  ----------
  user : str
    認証するユーザ名です。
  password : str
    認証するユーザのパスワードです。
  realm : str
    認証する保護領域名です。
  """

  user:str
  password:str
  realm:str

  _REGEXP_AUTHORIZATION:ClassVar[re.Pattern] = re.compile(r"^Basic (.*?)$")

  def _parse_authorization (self, source:str) -> tuple[str, str]:
    match = self._REGEXP_AUTHORIZATION.match(source)
    if match:
      main, = match.groups()
      main_decoded = base64.b64decode(main.strip()).decode("utf-8")
      user, password = main_decoded.split(":", 1)
      return user, password
    else:
      raise ValueError("Given an invalid source: {!r}".format(source))

  def authorize (self, handler:"http.server.BaseHTTPRequestHandler") -> bool:

    """BaseHTTPRequestHandler の内容から認証を試みます。

    Parameters
    ----------
    handler : http.server.BaseHTTPRequestHandler
      認証情報を取得するために参照される BaseHTTPRequestHandler オブジェクトです。

    Returns
    -------
    bool
      認証の成功の有無を表す真偽値です。
    """

    authorization = handler.headers.get("Authorization", "")
    if authorization:
      try:
        user, password = self._parse_authorization(authorization)
        if (
          secrets.compare_digest(user, self.user) and 
          secrets.compare_digest(password, self.password)):

          _LOGGER.info("Basic authorization was succeed") #log.

          return True
        else:

          _LOGGER.info("Basic authorization was failed: {:s}".format("User, password are mismatched.")) #log.

          return False
      except:
        traceback.print_exc()

        _LOGGER.info("Basic authorization was failed: {:s}".format("Internal server error caused on processing.")) #log.
        
        return False
    else:

      _LOGGER.info("Basic authorization was failed: {:s}".format("Missing Authorization header.")) #log.

      return False

  def send_unauthorized (self, handler:"http.server.BaseHTTPRequestHandler"):

    """接続先の相手に認証情報を要求します。

    Parameters
    ----------
    handler : http.server.BaseHTTPRequestHandler
      認証情報を要求するために使われる BaseHTTPRequestHandler オブジェクトです。
    """

    handler.send_response(401)
    handler.send_header("WWW-Authenticate", "Basic realm=\"{:s}\", charset=\"UTF-8\"".format(self.realm))
    handler.send_header("Content-Type", "text/plain; charset=ascii".format(self.realm))
    handler.end_headers()
    handler.wfile.write(b"401 Unauthorized")
