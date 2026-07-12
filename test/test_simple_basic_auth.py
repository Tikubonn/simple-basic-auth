
import base64
import pytest
from simple_basic_auth import BasicAuth

@pytest.mark.parametrize(
  [
    "user",
    "password",
    "expect_authorization"
  ],
  [
    pytest.param(
      "abc",
      "def",
      "Basic {:s}".format(
        base64.b64encode(
          "{:s}:{:s}".format("abc", "def").encode("utf-8")
        ).decode("ascii")
      )
    )
  ]
)
def test_basic_auth_gen_expect_authorization (user:str, password:str, expect_authorization:str):
  assert BasicAuth._gen_expect_authorization(user, password) == expect_authorization
