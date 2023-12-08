import base64
import hashlib
from dataclasses import dataclass

import nkeys

from jwt.v2.claims import ActivationClaim, ClaimsData, ClaimType, GenericFields, PrefixByte
from jwt.nkeys_ext import Decode
from jwt.v2.types import ExportType, Subject
from jwt.v2.validation import ValidationResults


@dataclass
class Activation:
    """
    Activation defines the custom parts of an activation claim
    """

    import_subject: Subject = ""
    import_type: ExportType = None
    issuer_account: str = None
    generic_fields: GenericFields = None

    def is_service(self) -> bool:
        return self.import_type == ExportType.Service

    def is_stream(self) -> bool:
        return self.import_type == ExportType.Stream

    def validate(self, vr: ValidationResults) -> None:
        if not self.is_service() and not self.is_stream():
            vr.add(f"invalid import type: {self.import_type}", level="e")

        self.import_subject.validate(vr)


@dataclass
class ActivationClaims(GenericFields, ClaimsData):
    """ ActivationClaims holds the data specific to an activation JWT

    Attributes:
        nats: Activation (in go version is activation)
    """
    nats: Activation = None  # attr: activation

    # Signature of method 'ActivationClaims.encode()' does not match signature of the base method in class 'ClaimsData'
    def encode(self, pair: nkeys.KeyPair) -> str:  # noqa
        """

        Raises:
            ValueError: if subject is not a valid account
        """
        # try to decode, to see if it's a valid account
        Decode(nkeys.PREFIX_BYTE_ACCOUNT, self.sub.encode())  # throws ValueError

        self.type = ActivationClaim
        return super().encode(pair, self)  # throws ValueError

    def payload(self) -> Activation:
        return self.nats

    def validate(self, vr: ValidationResults) -> None:
        self.validate_with_time_checks(vr, True)

    def validate_with_time_checks(self, vr: ValidationResults, time_checks: bool):
        if time_checks:
            super().validate(vr)

        self.nats.validate(vr)

        if self.nats.issuer_account != "":
            try:
                Decode(nkeys.PREFIX_BYTE_ACCOUNT, self.nats.issuer_account.encode())
            except ValueError:
                vr.add("account_id is not an account public key", level="e")

    def claim_type(self) -> ClaimType:
        return self.type

    @staticmethod
    def expected_prefixes() -> list[PrefixByte]:  # noqa
        return [nkeys.PREFIX_BYTE_ACCOUNT, nkeys.PREFIX_BYTE_OPERATOR]

    def claims(self) -> ClaimsData:
        # python does not allow a return of an object as parent class
        return self

    def hash_id(self) -> str:
        """ HashID returns a hash of the claims that can be used to identify it.
        The hash is calculated by creating a string with
        issuerPubKey.subjectPubKey.<subject> and constructing the sha-256 hash and base32 encoding that.
        <subject> is the exported subject, minus any wildcards, so foo.* becomes foo.
        the one special case is that if the export start with "*" or is ">" the <subject> `_` """
        if not self.iss or not self.sub or not self.nats.import_subject:
            raise ValueError("not enough data in the activaion claims to create a hash")

        subject = clean_subject(self.nats.import_subject)

        sha = hashlib.sha256()
        sha.update(f"{self.iss}.{self.sub}.{subject}".encode())

        return base64.b32encode(
            sha.digest()
        ).decode()  # .rstrip(b"=").decode()  # TODO: check if rstrip is needed


def clean_subject(subject: Subject) -> Subject:
    split = subject.split("_")
    cleaned = ""

    for i, tok in enumerate(split):
        if tok == "*" or tok == ">":
            if i == 0:
                cleaned = "_"
                break

            cleaned = "_".join(split[:i])
            break

    if cleaned == "":
        cleaned = subject

    return cleaned


def new_activation_claims(subject: Subject) -> ActivationClaims:
    return ActivationClaims(name="", sub=subject)
