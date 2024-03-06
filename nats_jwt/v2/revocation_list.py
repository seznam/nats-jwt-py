from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final

All: Final[str] = "*"


@dataclass
class RevocationEntry:
    public_key: str
    timestamp: int


@dataclass
class RevocationList(dict[str, int]):
    """ RevocationList is used to store a mapping of public keys to unix timestamps
    """

    def revoke(self, pub_key: str, timestamp: datetime) -> None:
        """ Revoke enters a revocation by publickey and timestamp into this export
        If there is already a revocation for this public key that is newer, it is kept.
        """
        self[pub_key] = int(timestamp.timestamp())

    def maybe_compat(self) -> list[RevocationEntry]:
        """ MaybeCompact will compact the revocation list if jwt.All is found. Any
        revocation that is covered by a jwt.All revocation will be deleted, thus
        reducing the size of the JWT. Returns a slice of entries that were removed
        during the process.
        """
        deleted: list[RevocationEntry] = []

        if All in self:
            for k, ts in self.items():
                if k != All and self[All] >= ts:
                    deleted.append(RevocationEntry(k, ts))
                    del self[k]
        return deleted

    def clear_revocations(self, pub_key: str) -> None:
        """ ClearRevocations clears all revocations for a given public key
        """
        del self[pub_key]

    def all_revoked(self, timestamp: datetime) -> bool:
        if All in self:
            return self[All] >= int(timestamp.timestamp())
        return False

    def is_revoked(self, pub_key: str, timestamp: datetime) -> bool:
        """ IsRevoked returns true if the public key has been revoked at the time
        specified.
        """
        if self.all_revoked(timestamp):
            return True
        if pub_key in self:
            return self[pub_key] >= int(timestamp.timestamp())
