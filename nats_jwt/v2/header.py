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

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Annotated, Final

from dataclasses_json import dataclass_json

# Version is a semantic version
__Version__: Final[tuple[int, int, int]] = (2, 4, 0)

Version: Final[str] = ".".join(map(str, __Version__))

# TokenTypeJwt is the JWT token type supported JWT tokens
# encoded and decoded by this library
# from RFC7519 5.1 "typ":
# it is RECOMMENDED that "JWT" always be spelled using uppercase characters for compatibility
TokenTypeJwt: Final[str] = "JWT"

# AlgorithmNkey is the algorithm supported by JWT tokens
# encoded and decoded by this library
AlgorithmNkeyOld: Final[str] = "ed25519"
AlgorithmNkey: Final[str] = AlgorithmNkeyOld + "-nkey"

JSONable = Annotated[str, "JSONable is a type that can be marshalled to JSON"]


@dataclass_json
@dataclass(frozen=True)
class Header:
    """ Header is a JWT Jose Header """
    typ: str
    alg: str

    def valid(self) -> bool:
        """ Validates the Header.
        It returns `True` if the Header is a JWT header, and the algorithm used is the NKEY algorithm,
        otherwise it raises an exception.

        Raises:
            ValueError: invalid header

        Note:
             it may go into initializer, but the author is trying to be close to the origin go version
        """
        if TokenTypeJwt != self.typ.upper():
            raise ValueError(f"not supported type \"{self.typ}\"")

        alg = self.alg.lower()
        if not alg.startswith(AlgorithmNkeyOld):
            raise ValueError(f"unexpected \"{self.alg}\" algorithm")
        if AlgorithmNkeyOld != alg and AlgorithmNkey != alg:
            raise ValueError(f"unexpected \"{self.alg}\" algorithm")

        return True


def parse_headers(s: JSONable) -> Header:
    """ Parses a JWT header

    Raises:
        ValueError: invalid header
    """
    header = Header(**json.loads(s))
    header.valid()  # throws ValueError

    return header
