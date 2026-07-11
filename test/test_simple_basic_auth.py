
import base64
import pytest
from simple_basic_auth import BasicAuth

@pytest.mark.parametrize(
  [
    "source",
    "expect_result"
  ],
  [
    pytest.param(
      "Basic {:s}".format(base64.b64encode(b"abc:def").decode("ascii")),
      ("abc", "def")
    ),
  ]
)
def test_simple_basic_auth_parse_authorization (source:str, expect_result:tuple[str, str]):
  auth = BasicAuth("", "", "")
  assert expect_result == auth._parse_authorization(source)

@pytest.mark.parametrize(
  [
    "source",
    "expect_exception"
  ],
  [
    pytest.param(
      "",
      ValueError
    ),
  ]
)
def test_simple_basic_auth_parse_authorization_error (source:str, expect_exception:"typing.Type[Exception]"):
  auth = BasicAuth("", "", "")
  with pytest.raises(expect_exception):
    auth._parse_authorization(source)
