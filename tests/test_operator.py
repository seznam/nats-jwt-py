#    Copyright 2024 Seznam.cz, a.s.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import os
import unittest
from typing import Final

from nats_jwt.v2.snippets import Operator, Account, User

# get a file path
assets = os.path.join(os.path.dirname(__file__), "assets")
jwt = os.path.join(assets, "jwt")

# data created with nsc
OPERATOR_JWT_PATH: Final[str] = os.path.join(jwt, "operator.jwt")
ACCOUNT_JWT_PATH: Final[str] = os.path.join(jwt, "account.jwt")
USER_JWT_PATH: Final[str] = os.path.join(jwt, "user.jwt")


class TestSigningCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.operator_seed = b"SOABUEGQYIM4FW5N3DDTLRNRCCCFJMKEW4ZBQXCG6623H2PYPZEBACY44U"
        self.account_seed = b"SAAH4B5A7STCHHZWQJIOXMPH5DBYUGWC6CIWAKGCNSJYVCCUSPXQHQXDYU"
        self.user_seed = b"SUAPYFTOO4IHFUARZDDUO2Q3PQS7JSCFBWKODIBNEYLFVGRVU4UNPUL4ME"

        with open(OPERATOR_JWT_PATH) as f:
            self.operator_jwt = f.read()

        with open(ACCOUNT_JWT_PATH) as f:
            self.account_jwt = f.read()

        with open(USER_JWT_PATH) as f:
            self.user_jwt = f.read()

        self.operator = Operator(
            seed=self.operator_seed,
        )

        self.account = Account(
            jwt=self.account_jwt,
            seed=self.account_seed,
            signer_kp=self.operator.key_pair,
        )

        self.user = User(
            jwt=self.user_jwt,
            seed=self.user_seed,
            signer_kp=self.account.key_pair,
        )

    def test_operator_signs_account_correctly(self):
        oc = Operator()
        a = oc.create_account("test_account")
        assert oc.verify(a.jwt)

    def test_self_signing(self):
        self.operator.verify(self.account_jwt)
        self.operator.verify(self.account.jwt)

        self.account.verify(self.user_jwt)
        self.account.verify(self.user.jwt)


if __name__ == '__main__':
    unittest.main()
