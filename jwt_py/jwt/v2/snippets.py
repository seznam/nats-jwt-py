import typing as t
from abc import ABC, abstractmethod

from nkeys import from_seed, KeyPair

from jwt.nkeys_ext import create_account_pair, create_operator_pair, create_user_pair, keypair_from_pubkey
from jwt.v2.account_claims import AccountClaims
from jwt.v2.claims import AnyClaims, extract_payload_sig_from_jwt
from jwt.v2.operator_claims import OperatorClaims
from jwt.v2.user_claims import UserClaims


def init_new_operator(name: str) -> tuple[KeyPair, str]:
    okp: KeyPair = create_operator_pair()
    oc: OperatorClaims = OperatorClaims(okp.public_key.decode(), name)
    oskp: KeyPair = create_operator_pair()
    oc.nats.signing_keys.append(oskp.public_key.decode())

    jwt: str = oc.encode(okp)

    return okp, jwt


def create_account(operator: KeyPair, name: str) -> tuple[KeyPair, str]:
    akp: KeyPair = create_account_pair()
    ac: AccountClaims = AccountClaims(akp.public_key.decode(), name)

    askp: KeyPair = create_account_pair()
    ac.nats.signing_keys.add(askp.public_key.decode())

    jwt: str = ac.encode(operator)

    return akp, jwt


JWT = t.Annotated[str, "Json Web Token"]


class Snippet(ABC, t.Generic[AnyClaims]):
    key_pair: KeyPair
    seed_getter: t.Callable[[str], bytes | str] = None

    @property
    @abstractmethod
    def claims_t(self) -> t.Type[AnyClaims]:
        pass

    @staticmethod
    @abstractmethod
    def new_pair() -> KeyPair:
        pass

    claims: AnyClaims | None

    def __init__(
            self,
            jwt: JWT | None = None,
            claims: AnyClaims | None = None,
            seed: bytes | None = None,
            seed_getter: t.Callable[[str], bytes] = None,
    ):
        """

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
        self.claims = claims

    @property
    def jwt(self) -> JWT:
        if self.claims is None:
            raise Exception("Claims not set")
        return self.claims.encode(self.key_pair)


class Verifier:
    claims: AnyClaims | None
    key_pair: KeyPair

    def verify(self, jwt: JWT) -> bool:
        if self.claims is None:
            return self.key_pair.verify(*extract_payload_sig_from_jwt(jwt))

        return self.claims.verify_jwt(jwt)


class Operator(Snippet, Verifier):
    claims_t: t.Final[t.Type[AnyClaims]] = OperatorClaims
    claims: OperatorClaims | None

    @staticmethod
    def new_pair() -> KeyPair:
        return create_operator_pair()

    def create_account(self, name: str) -> "Account":
        akp = create_account_pair()
        ac = AccountClaims(akp.public_key.decode(), name)
        return Account(
            claims=ac,
            signer_kp=self.key_pair,
            seed=akp.seed,
        )


class Account(Snippet, Verifier):
    claims: AccountClaims

    def __init__(
            self,
            jwt: JWT | None = None,
            claims: AnyClaims | None = None,
            seed: bytes | None = None,
            seed_getter: t.Callable[[str], bytes] = None,
            signer_kp: KeyPair | None = None,
    ):
        super().__init__(jwt, claims, seed, seed_getter)
        self._skp = signer_kp

    @staticmethod
    def new_pair() -> KeyPair:
        return create_account_pair()

    claims_t = AccountClaims

    def create_user(self, name: str) -> "User":
        ukp = create_user_pair()
        uc = UserClaims(ukp.public_key.decode(), name)
        return User(
            claims=uc,
            signer_kp=self.key_pair,
            seed=ukp.seed,
        )

    @property
    def jwt(self) -> JWT:
        if self.claims is None:
            raise Exception("Claims not set")
        if self._skp is None:
            raise Exception("Signer key pair not set. There is no one to sign my jwt :(")
        return self.claims.encode(self._skp)


class User(Snippet):
    claims_t = UserClaims

    @staticmethod
    def new_pair() -> KeyPair:
        return create_user_pair()

    def __init__(
            self,
            jwt: JWT | None = None,
            claims: AnyClaims | None = None,
            seed: bytes | None = None,
            seed_getter: t.Callable[[str], bytes | str] = None,
            signer_kp: KeyPair | None = None,
    ):
        super().__init__(jwt, claims, seed, seed_getter)
        self._skp = signer_kp

    @property
    def jwt(self) -> JWT:
        if self.claims is None:
            raise Exception("Claims not set")
        if self._skp is None:
            raise Exception("Signer key pair not set. There is no one to sign my jwt :(")
        self.claims: UserClaims
        return self.claims.encode(self._skp)
