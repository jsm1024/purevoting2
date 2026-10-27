"""Offline publication against explicitly simulated Core/Gateway services.

httpx.MockTransport dispatches requests in-process. No socket, RPC, blockchain
transaction, real service credential or deployed contract is used. The mock
does perform the frozen request-schema, canonical-hash and EIP-191 checks.
"""

from __future__ import annotations

import copy
import json
import re
import secrets
from collections.abc import Mapping
from typing import Any

import httpx
import yaml
from jsonschema.exceptions import ValidationError

from .findings import contract_validator, validate_submission
from .hashing import Hc, canonical, finding_record_digest
from .paths import reference_root
from .signing import EIP191Signer, verify_signature
from .storage import FindingStore


GATEWAY_URL = "https://gateway.simulation.invalid"
CORE_URL = "https://core.simulation.invalid"
DEMO_SERVICE_KEY = "local-simulation-rule-key"


class PublicationError(RuntimeError):
    """A permanent publication error; the durable item remains pending."""

    def __init__(self, stage: str, finding_id: str, status: int, code: str):
        self.stage = stage
        self.finding_id = finding_id
        self.status = status
        self.code = code
        super().__init__(f"{stage} rejected finding {finding_id}: HTTP {status} ({code})")


def _problem(status: int, code: str, title: str) -> httpx.Response:
    return httpx.Response(
        status,
        json={"type": "about:blank", "title": title, "status": status, "code": code},
        headers={"content-type": "application/problem+json"},
    )


class LocalServices:
    """In-memory remote-service fixture, separate from the worker outbox.

    Keep this object when restarting the worker to model remote services that
    remain up. It is not a durable or production Core/Gateway implementation.
    ``body_attempts`` holds request bytes for tests; it is never written to a log.
    ``requests`` contains only safe endpoint/status metadata.
    """

    def __init__(
        self,
        signer_address: str,
        service_key: str,
        committed_checkpoints: Mapping[str, int],
        *,
        transient_body_failures: int = 0,
        transient_gateway_failures: int = 0,
    ):
        for value in (transient_body_failures, transient_gateway_failures):
            if type(value) is not int or value < 0:
                raise ValueError("Transient failure counts must be nonnegative integers")
        if not service_key:
            raise ValueError("A mock service key is required")
        self.signer_address = signer_address
        self._service_key = service_key
        self.committed_checkpoints: dict[str, int] = {}
        for election_id, checkpoint in committed_checkpoints.items():
            self.accept_checkpoint(election_id, checkpoint)
        self.transient_body_failures = transient_body_failures
        self.transient_gateway_failures = transient_gateway_failures
        self.registered_records: dict[str, dict[str, Any]] = {}
        self.stored_bodies: dict[str, bytes] = {}
        self.body_attempts: dict[str, list[bytes]] = {}
        self.requests: list[dict[str, Any]] = []
        common = json.loads(
            (reference_root() / "contracts/common.schema.json").read_text(encoding="utf-8")
        )
        self._finding_id_pattern = re.compile(common["$defs"]["FindingId"]["pattern"])
        self._known_problem_codes = frozenset(common["$defs"]["ProblemCode"]["enum"])
        gateway = yaml.safe_load(
            (reference_root() / "contracts/ledger-gateway.openapi.yaml").read_text(encoding="utf-8")
        )
        operation = gateway["paths"]["/v1/finding-records"]["post"]
        schema = operation["requestBody"]["content"]["application/json"]["schema"]
        self._registration_validator = contract_validator(schema, filename="ledger-gateway.openapi.yaml")
        acknowledgment = operation["responses"]["201"]["content"]["application/json"]["schema"]
        self._registration_ack_validator = contract_validator(
            acknowledgment, filename="ledger-gateway.openapi.yaml"
        )

    def accept_checkpoint(self, election_id: str, checkpoint: int) -> None:
        """Seed a simulated accepted checkpoint; this performs no discovery."""
        if type(checkpoint) is not int or checkpoint < 0:
            raise ValueError("A committed checkpoint must be a nonnegative integer")
        self.committed_checkpoints[election_id] = max(
            checkpoint, self.committed_checkpoints.get(election_id, -1)
        )

    def _register(self, body: dict[str, Any]) -> httpx.Response:
        try:
            canonical(body)
            self._registration_validator.validate(body)
        except (ValidationError, ValueError, TypeError):
            return _problem(400, "VALIDATION_ERROR", "Invalid finding registration")
        if self.transient_gateway_failures:
            self.transient_gateway_failures -= 1
            return _problem(503, "LEDGER_UNAVAILABLE", "Simulated Gateway outage")
        if body["finding_checkpoint"] > self.committed_checkpoints.get(body["election_id"], -1):
            return _problem(422, "CHECKPOINT_NOT_FOUND", "Checkpoint is not accepted")
        digest = finding_record_digest(
            body["finding_id"], body["election_id"], body["rule_id"], body["result"],
            body["finding_checkpoint"], body["finding_hash"],
        )
        if (
            body["signature"]["signer"] != self.signer_address
            or not verify_signature(digest, body["signature"])
        ):
            return _problem(422, "SIGNATURE_INVALID", "Finding signature is invalid")
        finding_id = body["finding_id"]
        existing = self.registered_records.get(finding_id)
        if existing is not None:
            fields = (
                "election_id", "finding_id", "rule_id", "result",
                "finding_checkpoint", "finding_hash",
            )
            if any(existing["request"][key] != body[key] for key in fields):
                return _problem(409, "CONFLICT", "Finding registration already differs")
            return httpx.Response(200, json={"event_id": existing["event_id"]})
        # A deterministic schema-shaped event ID is sufficient for this mock
        # response. This is not a fabricated real FINDING_RECORDED chain event.
        event_id = "evt_" + finding_id.removeprefix("fnd_")
        self.registered_records[finding_id] = {
            "request": copy.deepcopy(body), "event_id": event_id,
        }
        return httpx.Response(201, json={"event_id": event_id})

    def _store_body(self, body: dict[str, Any], raw: bytes) -> httpx.Response:
        try:
            validate_submission(body)
        except (ValidationError, ValueError, TypeError):
            return _problem(400, "VALIDATION_ERROR", "Invalid finding body")
        finding_id = body["finding_id"]
        self.body_attempts.setdefault(finding_id, []).append(raw)
        existing = self.stored_bodies.get(finding_id)
        if existing is not None:
            if Hc(json.loads(existing)) != Hc(body):
                return _problem(409, "CONFLICT", "Stored finding body already differs")
            return httpx.Response(200, json={"finding_id": finding_id})
        if self.transient_body_failures:
            self.transient_body_failures -= 1
            return _problem(503, "LEDGER_UNAVAILABLE", "Simulated record-index visibility delay")
        registered = self.registered_records.get(finding_id)
        if registered is None:
            return _problem(503, "LEDGER_UNAVAILABLE", "Finding record is not visible")
        record = registered["request"]
        if (
            record["finding_hash"] != Hc(body)
            or record["election_id"] != body["election_id"]
            or record["rule_id"] != body["rule_id"]
            or record["result"] != body["result"]
            or record["finding_checkpoint"] != body["checkpoint"]
        ):
            return _problem(422, "FINDING_NOT_RECORDED", "Body does not match its registered finding")
        self.stored_bodies[finding_id] = raw
        return httpx.Response(201, json={"finding_id": finding_id})

    def handle(self, request: httpx.Request) -> httpx.Response:
        finding_id: str | None = None
        stage = "unknown"
        body: Any = None
        raw = request.content
        if request.url.host == "gateway.simulation.invalid" and request.url.path == "/v1/finding-records":
            stage = "register"
        elif request.url.host == "core.simulation.invalid" and request.url.path == "/internal/v1/findings":
            stage = "body"
        if not secrets.compare_digest(request.headers.get("X-Service-Key", ""), self._service_key):
            response = _problem(403, "FORBIDDEN", "A Rule Engine service key is required")
        elif request.method != "POST" or stage == "unknown":
            response = _problem(404, "NOT_FOUND", "No such simulated endpoint")
        else:
            try:
                body = json.loads(raw)
            except (ValueError, UnicodeError):
                response = _problem(400, "VALIDATION_ERROR", "Invalid JSON request")
            else:
                if isinstance(body, dict):
                    candidate_id = body.get("finding_id")
                    if isinstance(candidate_id, str) and self._finding_id_pattern.fullmatch(candidate_id):
                        finding_id = candidate_id
                response = self._register(body) if stage == "register" else self._store_body(body, raw)
        self.requests.append({
            "stage": stage, "path": request.url.path,
            "status": response.status_code, "finding_id": finding_id,
        })
        return response


class LocalPublicationSimulator:
    """Publish pending durable bodies once per call, using in-process services.

    If ``committed_checkpoints`` is omitted, initial queue checkpoints seed the
    mock's accepted-checkpoint state. That is a developer fixture assumption,
    not verification that a real Gateway accepted those checkpoints.

    On 503 the same durable bytes remain pending for the caller's bounded retry.
    Other errors raise PublicationError. There is no direct-chain fallback.
    """

    def __init__(
        self,
        store: FindingStore,
        signer: EIP191Signer,
        *,
        service_key: str = DEMO_SERVICE_KEY,
        transient_body_failures: int = 0,
        transient_gateway_failures: int = 0,
        committed_checkpoints: Mapping[str, int] | None = None,
        backend: LocalServices | None = None,
    ):
        self.store = store
        self.signer = signer
        if backend is not None and (
            transient_body_failures or transient_gateway_failures or committed_checkpoints is not None
        ):
            raise ValueError("Configure an existing backend directly before reusing it")
        if backend is None:
            if committed_checkpoints is None:
                accepted: dict[str, int] = {}
                for record in store.records():
                    election_id = record["election_id"]
                    accepted[election_id] = max(record["checkpoint"], accepted.get(election_id, -1))
                committed_checkpoints = accepted
            backend = LocalServices(
                signer.address, service_key, committed_checkpoints,
                transient_body_failures=transient_body_failures,
                transient_gateway_failures=transient_gateway_failures,
            )
        self.backend = backend
        self.client = httpx.Client(
            transport=httpx.MockTransport(backend.handle),
            headers={"X-Service-Key": service_key, "Content-Type": "application/json"},
            timeout=5.0,
        )

    def registration_for(self, body: dict[str, Any]) -> dict[str, Any]:
        """Produce the exact frozen signed-registration request for a body."""
        validate_submission(body)
        finding_hash = Hc(body)
        digest = finding_record_digest(
            body["finding_id"], body["election_id"], body["rule_id"], body["result"],
            body["checkpoint"], finding_hash,
        )
        return {
            "election_id": body["election_id"],
            "finding_id": body["finding_id"],
            "rule_id": body["rule_id"],
            "result": body["result"],
            "finding_checkpoint": body["checkpoint"],
            "finding_hash": finding_hash,
            "signature": self.signer.sign_digest(digest),
        }

    def _require_success(self, response: httpx.Response, stage: str, finding_id: str) -> None:
        if response.status_code in (200, 201):
            # Only the Gateway's new-registration 201 response has a required
            # JSON acknowledgment. Gateway 200 and Core 200/201 may be empty.
            if stage == "register" and response.status_code == 201:
                try:
                    self.backend._registration_ack_validator.validate(response.json())
                except (ValidationError, ValueError, TypeError):
                    raise PublicationError(stage, finding_id, response.status_code, "INVALID_RESPONSE") from None
            return
        try:
            problem = response.json()
            candidate_code = problem.get("code") if isinstance(problem, dict) else None
            code = candidate_code if (
                isinstance(candidate_code, str) and candidate_code in self.backend._known_problem_codes
            ) else "HTTP_ERROR"
        except ValueError:
            code = "HTTP_ERROR"
        raise PublicationError(stage, finding_id, response.status_code, code)

    def publish_all(self) -> dict[str, Any]:
        """One bounded attempt per pending item; never loop or sleep on 503."""
        report: dict[str, Any] = {"registered": 0, "stored": 0, "retryable": 0}
        first_request = len(self.backend.requests)
        for record in self.store.pending():
            finding_id = record["finding_id"]
            if record["state"] == "QUEUED":
                registration = self.registration_for(record["body"])
                response = self.client.post(
                    GATEWAY_URL + "/v1/finding-records", content=canonical(registration)
                )
                if response.status_code == 503:
                    report["retryable"] += 1
                    continue
                self._require_success(response, "register", finding_id)
                self.store.mark_registered(finding_id)
                report["registered"] += 1
            response = self.client.post(
                CORE_URL + "/internal/v1/findings", content=record["body_bytes"]
            )
            if response.status_code == 503:
                report["retryable"] += 1
                continue
            self._require_success(response, "body", finding_id)
            self.store.mark_stored(finding_id)
            report["stored"] += 1
        report.update({
            "pending": len(self.store.pending()),
            "requests": self.backend.requests[first_request:],
            "identical_retry_bodies": all(
                all(raw == attempts[0] for raw in attempts)
                for attempts in self.backend.body_attempts.values()
            ),
            "body_attempt_count": sum(len(attempts) for attempts in self.backend.body_attempts.values()),
            "retried_body_count": sum(len(attempts) > 1 for attempts in self.backend.body_attempts.values()),
            "transport": "in-process httpx.MockTransport",
            "direct_chain_fallback": False,
        })
        return report

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "LocalPublicationSimulator":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
