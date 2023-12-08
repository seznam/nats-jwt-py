from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, NewType

from jwt.v2.activation_claims import ActivationClaims
from jwt.v2.revocation_list import RevocationList
from jwt.v2.types import ExportType, Info, Subject
from jwt.v2.validation import ValidationResults

ResponseType: type = Annotated[str, "ResponseType is used to store an export response type"]

# ResponseTypeSingleton is used for a service that sends a single response only
ResponseTypeSingleton: ResponseType = "Singleton"

# ResponseTypeStream is used for a service that will send multiple responses
ResponseTypeStream: ResponseType = "Stream"

# ResponseTypeChunked is used for a service that sends a single response in chunks (so not quite a stream
ResponseTypeChunked: ResponseType = "Chunked"


class Sampling(int):
    def marshal_json(self):
        if self == 0:
            return b"headers"
        if 1 <= self <= 100:
            return str(self).encode()
        raise ValueError(f"unknown sampling rate")

    @classmethod
    def unmarshal_json(cls, data: bytes) -> "Sampling":
        if len(data) == 0:
            raise ValueError(f"unknown sampling rate")
        if data.lower() == b"headers":
            return Headers
        try:
            return Sampling(int(data))
        except ValueError as e:
            raise ValueError(f"unknown sampling rate") from e


Headers: Sampling = Sampling(0)


@dataclass(frozen=True)
class ServiceLatency:
    sampling: Sampling = None
    results: Subject = None

    def validate(self, vr: ValidationResults):
        if self.sampling != 0 and (self.sampling < 1 or self.sampling > 100):
            vr.add("sampling percentage needs to be between 1-100")
        self.results.validate(vr)
        if self.results.has_wildcards():
            vr.add("results subject can not contain wildcards")


Duration = NewType("Duration", int)


@dataclass(frozen=True)
class Export(Info):
    name: str = None
    subject: Subject = ""
    type: ExportType = None
    token_req: bool = None
    revocations: RevocationList = field(default_factory=RevocationList)
    response_type: ResponseType = None
    response_threshold: Duration = None
    service_latency: ServiceLatency = None
    account_token_position: int = None
    advertise: bool = None

    def is_service(self):
        return self.type == ExportType.Service

    def is_stream(self):
        return self.response_type == ExportType.Stream

    def is_single_response(self) -> bool:
        return self.is_service() and self.response_type in (ResponseTypeSingleton, "")

    def is_chunked_response(self) -> bool:
        return self.is_service() and self.response_type == ResponseTypeChunked

    def is_stream_response(self) -> bool:
        return self.is_service() and self.response_type == ResponseTypeStream

    def validate(self, vr: ValidationResults):
        # TODO:
        return

    def revoke_at(self, pub_key: str, timestamp: datetime):
        self.revocations.revoke(pub_key, timestamp)

    def revoke(self, pub_key: str):
        self.revocations.revoke(pub_key, datetime.now())

    def clear_revocations(self, pub_key: str):
        self.revocations.clear_revocations(pub_key)

    def is_revoked(self, pub_key: str, timestamp: datetime) -> bool:
        return self.revocations.is_revoked(pub_key, timestamp)

    def is_claim_revoked(self, claim: ActivationClaims) -> bool:
        if claim is None or claim.iat == 0 or claim.iss == "":
            return True
        return self.is_revoked(claim.iss, datetime.fromtimestamp(claim.iat))

# TODO: validation for list[Export]
