"""Time helpers. Everything is UTC, whole seconds (common.schema.json Timestamp).

`clock.frozen` lets tests move time across bucket and checkpoint boundaries.
"""
from datetime import datetime, timezone


class Clock:
    frozen: int | None = None

    def now(self) -> int:
        if self.frozen is not None:
            return self.frozen
        return int(datetime.now(timezone.utc).timestamp())


clock = Clock()


def floor_bucket(t: int, bucket: int) -> int:
    """Voter-side time: a voter event exactly on a boundary belongs to the bucket that starts there."""
    return t // bucket * bucket


def ceil_bucket(t: int, bucket: int) -> int:
    return -(-t // bucket) * bucket


def system_bucket_start(t: int, bucket: int) -> int:
    """Release unit of a system event: one created exactly on a boundary belongs to the bucket that ends there."""
    return ceil_bucket(t, bucket) - bucket


def iso(t: int) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> int:
    return int(datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def to_dt(t: int) -> datetime:
    return datetime.fromtimestamp(t, timezone.utc)


def from_dt(d: datetime) -> int:
    return int(d.timestamp())
