
import base64
import logging
import secrets

"""http.server 向けの簡素な Basic 認証の機能を提供します。

Examples
--------
>>> from http.server import BaseHTTPRequestHandler, HTTPServer
>>> from simple_basic_auth import BasicAuth
>>>
>>> auth = BasicAuth("anonymous", "password", "SecretZone")
>>> 
>>> class _Handler (BaseHTTPRequestHandler):
>>>   def do_GET (self):
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

class BasicAuth:

  """1ユーザに対する Basic 認証機能を提供します。
  """

  @staticmethod
  def _gen_expect_authorization (user:str, password:str) -> str:

    """ユーザ名・パスワードから理想的な Authorization ヘッダの内容を生成します。

    Parameters
    ----------
    user : str
      認証するユーザ名です。
    password : str 
      認証するユーザのパスワードです。

    Returns
    -------
    str
      ユーザ名・パスワードから生成された理想的な Authorization ヘッダです。
    """

    return "Basic {:s}".format(
      base64.b64encode(
        "{:s}:{:s}".format(user, password).encode("utf-8")
      ).decode("ascii")
    )

  def __init__ (self, user:str, password:str, realm:str):

    """インスタンスの初期化を行います。

    Notes
    -----
    本クラスは user, password 引数の値をそのままの形ではなく、
    理想的な Authorization ヘッダの内容に変換して保存します。
    変換の際には _gen_expect_authorization 秘匿メソッドが使用されます。

    Parameters
    ----------
    user : str
      認証するユーザ名です。
    password : str
      認証するユーザのパスワードです。
    realm : str
      認証する保護領域名です。
    """

    self._expect_authorization = BasicAuth._gen_expect_authorization(user, password)
    self._realm = realm

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
      if secrets.compare_digest(self._expect_authorization, authorization):
        
        _LOGGER.info("Basic authorization was succeed") #log.

        return True
      else:

        _LOGGER.info("Basic authorization was failed: {:s}".format("User, password are mismatched.")) #log.

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
    handler.send_header("WWW-Authenticate", 'Basic realm="{:s}", charset="UTF-8"'.format(self._realm))
    handler.send_header("Content-Type", "text/plain; charset=ascii".format(self._realm))
    handler.end_headers()
    handler.wfile.write(b"401 Unauthorized")
