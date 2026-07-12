
import pytest
import conftest
import requests
import requests.auth

"""実際に HTTP 通信を行い動作確認を行います。

Notes
-----
引数 test_server の定義は同ディレクトリの conftest.py を参照してください。
"""

def test_authorize_without_authorization_header (test_server):

  """認証用ヘッダを添付しなかった場合の動作確認です。
  """

  HOST, PORT = conftest.TEST_SERVER_ADDRESS
  response = requests.get("http://{:s}:{:d}".format(HOST, PORT))
  assert response.status_code == 401
  assert response.headers.get("WWW-Authenticate", "") == 'Basic realm="{:s}", charset="UTF-8"'.format(conftest.TEST_REALM)

def test_authorize_with_invalid_authorization_header (test_server):

  """無効な認証用ヘッダを添付した場合の動作確認です。
  """

  HOST, PORT = conftest.TEST_SERVER_ADDRESS
  auth = requests.auth.HTTPBasicAuth("", "")
  response = requests.get("http://{:s}:{:d}".format(HOST, PORT), auth=auth)
  assert response.status_code == 401
  assert response.headers.get("WWW-Authenticate", "") == 'Basic realm="{:s}", charset="UTF-8"'.format(conftest.TEST_REALM)

def test_authorize (test_server):

  """有効な認証用ヘッダを添付した場合の動作確認です。
  """

  HOST, PORT = conftest.TEST_SERVER_ADDRESS
  auth = requests.auth.HTTPBasicAuth(conftest.TEST_USER, conftest.TEST_PASSWORD)
  response = requests.get("http://{:s}:{:d}".format(HOST, PORT), auth=auth)
  assert response.status_code == 200
