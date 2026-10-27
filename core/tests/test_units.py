"""Unit tests that need no database."""
import json
import re
from pathlib import Path

from app import elections, ids
from app.timeutil import ceil_bucket, floor_bucket, iso, parse_iso, system_bucket_start

VECTORS = Path(__file__).resolve().parents[2] / "tests" / "vectors" / "hash-vectors.json"


def test_id_formats():
    assert re.fullmatch(r"elc_[0-9A-HJKMNP-TV-Z]{26}", ids.ulid("elc"))
    assert re.fullmatch(r"evr_[0-9A-HJKMNP-TV-Z]{26}", ids.random_id("evr"))
    assert re.fullmatch(r"[A-Za-z0-9_-]{22}", ids.token128())


def test_ulid_sorts_by_time_random_ids_do_not_carry_it():
    a, b = ids.ulid("evt"), ids.ulid("evt")
    assert a[:14] <= b[:14]          # first 10 chars after the prefix are the millisecond time
    assert len({ids.random_id("vtr") for _ in range(100)}) == 100


def test_bucket_rules():
    # voter event on a boundary belongs to the bucket that starts there; a system event to the one that ends there
    assert floor_bucket(120, 60) == 120
    assert system_bucket_start(120, 60) == 60
    assert system_bucket_start(121, 60) == 120
    assert ceil_bucket(121, 60) == 180
    assert iso(parse_iso("2026-11-03T09:00:00Z")) == "2026-11-03T09:00:00Z"


def test_config_hash_matches_shared_vector():
    v = next(x for x in json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"] if x["name"] == "config_hash")
    inp = dict(v["input"])
    inp["window_start"], inp["window_end"] = parse_iso(inp["window_start"]), parse_iso(inp["window_end"])
    assert elections.config_hash(inp) == v["expected"]


def test_link_csv_has_the_contract_columns():
    text = elections.to_csv([{"external_ref": "s1", "name": "Kim", "link": "http://x/vote/elc_1#t=abc"}])
    assert text.splitlines()[0] == "external_ref,name,link"
    assert elections.to_csv([]) == ""
