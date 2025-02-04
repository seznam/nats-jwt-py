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

""" Snippets are created to make it easier to work with JWTs.

Snippets help with creating, verifying and signing JWTs for NATS.
"""

import typing as t
from abc import ABC, abstractmethod

from nkeys import from_seed, KeyPair, ErrInvalidSignature

from nats_jwt.nkeys_ext import create_account_pair, create_operator_pair, create_user_pair, keypair_from_pubkey
from nats_jwt.v2.account_claims import AccountClaims
from nats_jwt.v2.claims import AnyClaims, extract_payload_sig_from_jwt
from nats_jwt.v2.operator_claims import OperatorClaims
from nats_jwt.v2.user_claims import UserClaims


JWT = t.Annotated[str, "Json Web Token"]


class MissingAttribute(Exception):
    """ Exception raised when a required attribute is missing. """
    pass


def init_new_operator(name: str) -> tuple[KeyPair, str]:
    """ Create a new operator by its name.

    This process is inspired by the NATS GitHub example.

    The Operator can be signed by another keypair, and trust itself.

    Args:
        name: name of the operator

    Returns:
        tuple of an operator key pair (instance of nkeys.KeyPair) and (str) JWT
    """
    okp: KeyPair = create_operator_pair()
    oc: OperatorClaims = OperatorClaims(okp.public_key.decode(), name)
    oskp: KeyPair = create_operator_pair()
    oc.nats.signing_keys.append(oskp.public_key.decode())

    jwt: str = oc.encode(okp)

    return okp, jwt


def create_account(operator: KeyPair, name: str) -> tuple[KeyPair, str]:
    """ Create a new account by its name.

    Args:
        operator: operator key pair, that will sign the account
        name: name of the account

    Returns:
        tuple of an account key pair (instance of nkeys.KeyPair) and (str) JWT
    """
    akp: KeyPair = create_account_pair()
    ac: AccountClaims = AccountClaims(akp.public_key.decode(), name)

    askp: KeyPair = create_account_pair()
    ac.nats.signing_keys.add(askp.public_key.decode())

    jwt: str = ac.encode(operator)

    return akp, jwt


class Snippet(ABC, t.Generic[AnyClaims]):
    """ Abstract class to help with creating, verifying and signing JWTs for NATS.

    Attributes:
        key_pair: key-pair of the represented entity
        seed_getter: function that will get the nats_seed for a given public key.

        claims: claims of the account

    Children should implement:
        claims_t: type of claims that will be used
        new_pair: function that will create a new key pair

    """
    key_pair: KeyPair
    seed_getter: t.Callable[[str | None], bytes | str] = None

    @property
    @abstractmethod
    def claims_t(self) -> t.Type[AnyClaims]:
        """
        Returns:
            type of claims that will be used, e.g. AccountClaims
        """
        pass

    @staticmethod
    @abstractmethod
    def new_pair() -> KeyPair:
        """
        Returns:
            function that will create a new key pair for the represented entity
        """
        pass

    claims: AnyClaims | None

    def __init__(
            self,
            jwt: JWT | None = None,
            claims: AnyClaims | None = None,
            seed: bytes | None = None,
            seed_getter: t.Callable[[str], bytes] = None,
    ):
        """ Create a new instance of a snippet.

        Args:
            seed: nats seed, starting with `S`
                Not raw.
            jwt:
            seed_getter: function that will get the nats_seed for a given public key.

        Note:
            does not set claims
        """
        self.claims = claims

        if seed_getter is not None or seed is not None:
            self.seed_getter = lambda _: seed if seed else seed_getter

        if jwt is not None:
            self.claims = self.claims_t.decode_claims(jwt)

            signing_keys = self.claims.nats.signing_keys if isinstance(self, Verifier) else None

            if signing_keys:
                if self.seed_getter is not None:
                    nats_seed = self.seed_getter(signing_keys[0])
                    self.key_pair = from_seed(nats_seed)
                    # we have everything we need
                    return

                # we can get only public key
                self.key_pair = keypair_from_pubkey(signing_keys[0])

        if seed is not None:
            self.key_pair = from_seed(seed)
            return

        # nothing was passed in, create a new instance
        self.key_pair = self.new_pair()

    def set_claims(self, claims: AnyClaims) -> None:
        """ Setter of claims for the snippet. """
        self.claims = claims

    @property
    def jwt(self) -> JWT:
        """ Return a JWT of the snippet.

        Note:
            requires claims to be set

        Note:
            JWT is created in this method.
            It encodes on the fly by accessing this property.

        Returns:
            JWT of the entity
        """
        if self.claims is None:
            raise MissingAttribute("claims")
        return self.claims.encode(self.key_pair)


class Verifier:
    """ Mixin for a snippet that can verify JWTs.

    Attributes:
        claims: claims of the entity (can be None)
        key_pair: key-pair of the represented entity
    """
    claims: AnyClaims | None
    key_pair: KeyPair

    def verify(self, jwt: JWT) -> bool:
        """ Verify a JWT is signed by this entity.

        Args:
            jwt: JWT to verify

        Returns:
            True if the JWT is signed by this entity, False otherwise
        """
        try:
            if self.claims is None:
                # if we can't get claims, we extract from jwt claims and signature to verify
                return self.key_pair.verify(*extract_payload_sig_from_jwt(jwt))

            # if claims are set, we can verify with them
            return self.claims.verify_jwt(jwt)
        except ErrInvalidSignature as e:
            return False


class Operator(Snippet, Verifier):
    """ Snippet representing an operator in NATS.

    Attributes:
        claims_t: type of claims that will be used, e.g. OperatorClaims
        claims: claims of the operator
    """
    claims_t: t.Final[t.Type[AnyClaims]] = OperatorClaims
    claims: OperatorClaims | None

    @staticmethod
    def new_pair() -> KeyPair:
        """ Creates a new operator key pair.

        Returns:
            new operator key pair (instance of nkeys.KeyPair)
        """
        return create_operator_pair()

    def create_account(self, name: str) -> "Account":
        """ Creates an account for this operator.

        Args:
            name: name of the account

        Returns:
            new account snippet, that will be signed by this operator on JWT gen (jwt-gen is lazy)
        """
        akp: KeyPair = create_account_pair()
        ac = AccountClaims(akp.public_key.decode(), name)
        return Account(
            claims=ac,
            signer_kp=self.key_pair,
            seed=akp.seed,
        )


class Account(Snippet, Verifier):
    """ Snippet representing an account in NATS.

    Attributes:
        claims_t: type of claims that will be used, e.g. AccountClaims
        claims: claims of the account

        _skp: (protected) key-pair of the operator that will sign the JWT of this account
    """
    claims: AccountClaims
    claims_t = AccountClaims

    def __init__(
            self,
            jwt: JWT | None = None,
            claims: AnyClaims | None = None,
            seed: bytes | None = None,
            seed_getter: t.Callable[[str], bytes] = None,
            signer_kp: KeyPair | None = None,
    ):
        """ Create a new instance of an account snippet.

        Args:
            jwt: JWT of the account
            claims: claims of the account
            seed: nats seed, starting with `S`
                Not raw.
            seed_getter: function that will get the nats_seed for a given public key.
            signer_kp: key-pair of the operator that will sign the JWT of this account
        """
        super().__init__(jwt, claims, seed, seed_getter)
        self._skp: KeyPair | None = signer_kp

    @staticmethod
    def new_pair() -> KeyPair:
        """ Creates a new account key pair.

        Returns:
            new account key pair (instance of nkeys.KeyPair)
        """
        return create_account_pair()

    def create_user(self, name: str) -> "User":
        """ Creates a user for this account.

        Args:
            name: name of the user

        Returns:
            new user snippet, that will be signed by this account on JWT gen (jwt-gen is lazy)
        """
        ukp: KeyPair = create_user_pair()
        uc = UserClaims(ukp.public_key.decode(), name)
        return User(
            claims=uc,
            signer_kp=self.key_pair,
            seed=ukp.seed,
        )

    @property
    def jwt(self) -> JWT:
        """ Return a JWT of the user """
        if self.claims is None:
            raise MissingAttribute("claims")
        if self._skp is None:
            raise MissingAttribute("signer key pair (_skp).")
        return self.claims.encode(self._skp)


class User(Snippet):
    """ Snippet representing a user in NATS.

    Attributes:
        claims_t: type of claims that will be used, e.g. UserClaims
        claims: claims of the user

        _skp: (protected) key-pair of the account that will sign the JWT of this user
    """
    claims_t = UserClaims

    @staticmethod
    def new_pair() -> KeyPair:
        """ Creates a new user key pair.

        Returns:
            new user key pair (instance of nkeys.KeyPair)
        """
        return create_user_pair()

    def __init__(
            self,
            jwt: JWT | None = None,
            claims: AnyClaims | None = None,
            seed: bytes | None = None,
            seed_getter: t.Callable[[str], bytes | str] = None,
            signer_kp: KeyPair | None = None,
    ):
        """ Create a new instance of a user snippet.

        Args:
            jwt: JWT of the user
            claims: claims of the user
            seed: nats seed, starting with `S`
                Not raw.
            seed_getter: function that will get the nats_seed for a given public key.
            signer_kp: key-pair of the account that will sign the JWT of this user
        """
        super().__init__(jwt, claims, seed, seed_getter)
        self._skp: KeyPair = signer_kp

    @property
    def jwt(self) -> JWT:
        """ Return a JWT of the user """
        if self.claims is None:
            raise MissingAttribute("claims")
        if self._skp is None:
            raise MissingAttribute("signer key pair(_skp).")
        self.claims: UserClaims
        return self.claims.encode(self._skp)
