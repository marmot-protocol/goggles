"""Deterministic seed-data generator for local development.

Goggles inspects Marmot audit-log JSONL, so the identifiers it stores
(``account_ref``, ``engine_id``, ``group_ref``, ``msg_id``, digests, pubkeys)
are opaque hex blobs by nature -- that part cannot be made "human readable".
What this module makes realistic is the *shape* of the data: a handful of
groups with different participant counts and very different activity levels,
each participant a distinct recorder (engine) that logs its own view of the
shared conversation -- messages sent and received, delivery expectations and
gaps, group-state and epoch changes, and a fork/convergence decision.

A "participant" in goggles is a distinct engine that logged events for a
shared ``group_ref``; an N-participant group is therefore N separate uploaded
audit logs that reference one ``group_ref``. Each participant's account label,
pubkey, and device ride in the JSONL body via ``source_context`` (the same
place real recorders now put them), so the seeded app exercises the
body-derived identity path rather than upload headers.

Everything is derived deterministically from human labels via SHA-256, so
re-seeding (``just reset-db``) reproduces byte-identical logs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from django.template.defaultfilters import slugify

SCHEMA_V2 = "marmot-forensics-audit/v2"
OBFUSCATED = "obfuscated_sensitive_data"
FULL_DATA = "full_data"

# Relays the synthetic recorders publish through / receive from. Real public
# Nostr relays, used only as plausible-looking strings in seed data.
PRIMARY_RELAY = "wss://relay.primal.net"
SECONDARY_RELAY = "wss://relay.damus.io"


def _hex64(label: str) -> str:
    """Return a deterministic 64-hex-char id (msg_id / digest / group_ref)."""
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _hex32(label: str) -> str:
    """Return a deterministic 32-hex-char id (account_ref / engine_id)."""
    return _hex64(label)[:32]


@dataclass(frozen=True)
class Participant:
    name: str
    device_label: str
    platform: str

    @property
    def account_ref(self) -> str:
        return _hex32(f"account:{self.name}")

    @property
    def engine_id(self) -> str:
        return _hex32(f"engine:{self.name}")

    @property
    def account_pubkey_hex(self) -> str:
        return _hex64(f"pubkey:{self.name}")

    @property
    def session_id(self) -> str:
        return f"recorder-{self.engine_id[:8]}"


@dataclass(frozen=True)
class SeededLog:
    """One participant's audit log, ready to hand to ``ingest_audit_log_bytes``."""

    source_name: str
    account_label: str
    device_label: str
    platform: str
    account_pubkey_hex: str
    jsonl: str

    @property
    def dump_bytes(self) -> bytes:
        return self.jsonl.encode("utf-8")


class GroupScript:
    """Accumulates per-participant event timelines for a single group.

    A shared millisecond clock advances as the narrative unfolds so events
    interleave realistically across participants, while each participant keeps
    its own ``seq`` counter (one append-only log per recorder).
    """

    def __init__(self, name: str, participants: list[Participant], *, start_ms: int):
        self.name = name
        self.group_ref = _hex64(f"group:{name}")
        self.participants = participants
        self.clock = start_ms
        self._events: dict[str, list[dict]] = {p.name: [] for p in participants}
        self._seqs: dict[str, int] = {p.name: 0 for p in participants}
        self._msg_counter = 0
        self._commit_counter = 0

    # -- low-level emit ----------------------------------------------------

    def tick(self, ms: int = 1_000) -> None:
        self.clock += ms

    def emit(
        self,
        participant: Participant,
        kind: dict,
        *,
        mode: str = FULL_DATA,
        context: dict | None = None,
    ) -> None:
        seq = self._seqs[participant.name]
        self._seqs[participant.name] = seq + 1
        event = {
            "schema_version": SCHEMA_V2,
            "seq": seq,
            "wall_time_ms": self.clock,
            "recorder_session_id": participant.session_id,
            "audit_data_mode": mode,
            "account_ref": participant.account_ref,
            "engine_id": participant.engine_id,
            "group_ref": self.group_ref,
            "context": context if context is not None else {},
            "kind": kind,
        }
        self._events[participant.name].append(event)
        self.tick(120)

    # -- narrative beats ---------------------------------------------------

    def start(self, participant: Participant) -> None:
        """Bootstrap a participant's log: recorder up, then forensic capture on.

        The recorder comes up in obfuscated mode (where the schema forbids a
        pubkey in ``source``), escalates to full-data capture, then records the
        account pubkey via a full-data ``source_context`` event. Account
        identity therefore arrives in the JSONL body -- the path goggles now
        relies on -- rather than upload headers.
        """
        self.emit(
            participant,
            {"type": "recorder_started", "recorder": "darkmatter"},
            mode=OBFUSCATED,
            context={
                "source": {
                    "account_label": participant.name,
                    "device_name": participant.device_label,
                    "platform": participant.platform,
                }
            },
        )
        self.emit(
            participant,
            {
                "type": "audit_data_mode_changed",
                "previous_mode": OBFUSCATED,
                "new_mode": FULL_DATA,
                "reason": "forensic_capture_enabled",
                "recorder_restarted": True,
            },
        )
        self.emit(
            participant,
            {
                "type": "source_context",
                "source": {
                    "account_label": participant.name,
                    "account_pubkey_hex": participant.account_pubkey_hex,
                    "device_name": participant.device_label,
                    "platform": participant.platform,
                },
            },
        )

    def _next_msg_id(self, sender: Participant) -> str:
        self._msg_counter += 1
        return _hex64(f"msg:{self.name}:{sender.name}:{self._msg_counter}")

    def _next_commit_id(self, label: str) -> str:
        self._commit_counter += 1
        return _hex64(f"commit:{self.name}:{label}:{self._commit_counter}")

    def send_message(
        self,
        sender: Participant,
        recipients: list[Participant],
        text: str,
        *,
        epoch: int,
        observed_by: list[Participant] | None = None,
        publish: str = "acked",
    ) -> str:
        """Model one application message and its delivery across the group.

        ``recipients`` are everyone expected to receive it; ``observed_by``
        (defaults to all recipients) are those whose recorders actually logged
        it. Anyone expected but not observing shows up as a delivery gap.
        """
        observed_by = recipients if observed_by is None else observed_by
        msg_id = self._next_msg_id(sender)
        payload_digest = _hex64(f"payload:{msg_id}")
        author = {"member_ref": sender.account_ref, "account_pubkey_hex": sender.account_pubkey_hex}

        self.emit(
            sender,
            {
                "type": "message_content_decoded",
                "msg_id": msg_id,
                "artifact_kind": "application_message",
                "author": author,
                "decoded_payload": {"content_type": "text/plain", "text": text},
                "decoded_app_event": {
                    "format": "nostr",
                    "kind": 9,
                    "content": text,
                    "pubkey_hex": sender.account_pubkey_hex,
                },
            },
            mode=FULL_DATA,
        )
        self.emit(
            sender,
            {
                "type": "recipient_expectation",
                "msg_id": msg_id,
                "expectation": {
                    "artifact_kind": "application_message",
                    "recipient_scope": "all_other_current_group_members",
                    "membership_epoch": epoch,
                    "expected_member_refs": [r.account_ref for r in recipients],
                    "expected_count": len(recipients),
                },
            },
            mode=FULL_DATA,
        )
        self.emit(
            sender,
            {
                "type": "publish_attempt",
                "msg_id": msg_id,
                "target_kind": "application_message",
                "relay_urls": [PRIMARY_RELAY, SECONDARY_RELAY],
                "required_acks": 1,
            },
        )
        if publish == "failed":
            self.emit(
                sender,
                {
                    "type": "publish_failure",
                    "msg_id": msg_id,
                    "target_kind": "application_message",
                    "required_acks": 2,
                    "relay_url": PRIMARY_RELAY,
                    "stage": "relay_publish",
                    "reason": "relay_error",
                },
            )
        else:
            self.emit(
                sender,
                {
                    "type": "publish_outcome",
                    "msg_id": msg_id,
                    "target_kind": "application_message",
                    "accepted_relay_urls": [PRIMARY_RELAY],
                    "failed_relays": [{"relay_url": SECONDARY_RELAY, "reason": "timeout"}],
                    "required_acks": 1,
                    "met_required_acks": True,
                },
            )

        for recipient in observed_by:
            self.tick(300)
            self.emit(
                recipient,
                {
                    "type": "transport_received",
                    "msg_id": msg_id,
                    "transport": {
                        "transport": "nostr",
                        "delivery_plane": "relay",
                        "relay_url": PRIMARY_RELAY,
                        "nostr_event_id": _hex64(f"wire:{msg_id}:{recipient.name}"),
                        "nostr_kind": 445,
                    },
                    "payload_len": len(text) + 48,
                    "payload_digest": payload_digest,
                },
            )
            self.emit(
                recipient,
                {
                    "type": "message_content_decoded",
                    "msg_id": msg_id,
                    "artifact_kind": "application_message",
                    "author": author,
                    "decoded_payload": {"content_type": "text/plain", "text": text},
                },
                mode=FULL_DATA,
            )
        return msg_id

    def change_topic(self, actor: Participant, epoch: int, text: str) -> None:
        commit_id = self._next_commit_id(f"topic-{epoch}")
        self.emit(
            actor,
            {
                "type": "group_state_changed",
                "epoch": epoch,
                "change_kind": "topic_changed",
                "actor_member_ref": actor.account_ref,
                "origin_commit_id": commit_id,
                "fields": ["topic"],
                "value": {"digest": _hex64(f"topic:{self.name}:{text}"), "text": text},
            },
            mode=FULL_DATA,
        )

    def promote_admin(
        self,
        actor: Participant,
        subject: Participant,
        *,
        from_epoch: int,
        to_epoch: int,
    ) -> None:
        commit_id = self._next_commit_id(f"promote-{subject.name}")
        self.emit(
            actor,
            {
                "type": "human_action",
                "action": "promote_admin",
                "origin": "local_user",
                "phase": "succeeded",
                "fields": ["admins"],
                "component_ids": [32770],
                "target_count": 1,
                "message_ids": [commit_id],
                "from_epoch": from_epoch,
                "to_epoch": to_epoch,
            },
            mode=FULL_DATA,
            context={
                "operation_id": f"op-promote-{slugify(subject.name)}",
                "human_action": {
                    "action": "promote_admin",
                    "origin": "local_user",
                    "fields": ["admins"],
                    "component_ids": [32770],
                    "target_count": 1,
                },
            },
        )
        self.emit(
            actor,
            {
                "type": "group_state_changed",
                "epoch": to_epoch,
                "change_kind": "admin_added",
                "membership_change_source": "admin_action",
                "actor_member_ref": actor.account_ref,
                "subject_member_ref": subject.account_ref,
                "origin_commit_id": commit_id,
                "fields": ["admins"],
            },
            mode=FULL_DATA,
        )

    def commit_epoch(
        self,
        actor: Participant,
        epoch: int,
        *,
        previous_state: str = "pending",
        reason: str = "winning_commit_applied",
    ) -> None:
        self.emit(
            actor,
            {
                "type": "epoch_state_changed",
                "previous_state": previous_state,
                "new_state": "committed",
                "epoch": epoch,
                "reason": reason,
                "pending_ref": epoch,
                "pending_kind": "commit",
            },
            mode=FULL_DATA,
        )

    def resolve_fork(self, actor: Participant, run_id: str, *, tip_epoch: int) -> None:
        """Emit a convergence decision picking a winning branch over a fork."""
        winner = _hex64(f"branch:{self.name}:a:{run_id}")
        loser = _hex64(f"branch:{self.name}:b:{run_id}")
        self.emit(
            actor,
            {
                "type": "convergence_decision",
                "current_tip_epoch": tip_epoch - 1,
                "max_rewind_commits": 5,
                "selected_branch_id": winner,
                "selected_fork_epoch": tip_epoch - 2,
                "selected_tip_epoch": tip_epoch,
                "candidates": [
                    {
                        "branch_id": winner,
                        "fork_epoch": tip_epoch - 2,
                        "tip_epoch": tip_epoch,
                        "eligible": True,
                        "commit_ids": [_hex64(f"commit:{self.name}:{run_id}:a")],
                        "commit_count": 2,
                        "tip_priority": "app_witness",
                        "score": {
                            "valid_commit_depth": 2,
                            "effective_commit_depth": 2,
                            "witness_quorum_met": True,
                            "app_witness_score": 9,
                        },
                    },
                    {
                        "branch_id": loser,
                        "fork_epoch": tip_epoch - 2,
                        "tip_epoch": tip_epoch - 1,
                        "eligible": False,
                        "rejection_reasons": ["lower_weight"],
                        "commit_count": 1,
                        "tip_priority": "stale",
                        "score": {
                            "valid_commit_depth": 1,
                            "effective_commit_depth": 1,
                            "witness_quorum_met": False,
                            "app_witness_score": 2,
                        },
                    },
                ],
                "rule_trace": [
                    {
                        "rule_name": "highest_weight",
                        "scope": "candidate_pair",
                        "candidate_branch_id": winner,
                        "other_candidate_branch_id": loser,
                        "inputs": {"branch_a_weight": 9, "branch_b_weight": 2},
                        "result": {"winner": winner},
                        "decisive": True,
                        "selected_branch_id": winner,
                    }
                ],
            },
            mode=FULL_DATA,
            context={"convergence": {"run_id": run_id, "phase": "selected"}},
        )

    def confirm_epoch(self, actor: Participant, *, from_epoch: int, to_epoch: int) -> None:
        self.emit(
            actor,
            {
                "type": "epoch_confirmed",
                "from_epoch": from_epoch,
                "to_epoch": to_epoch,
                "pending_kind": "commit",
                "origin_commit_id": self._next_commit_id(f"confirm-{to_epoch}"),
            },
        )

    def converge_run_state(
        self,
        actor: Participant,
        run_id: str,
        phase: str,
        *,
        current_tip_epoch: int | None = None,
        reason: str = "",
        error_kind: str = "",
    ) -> None:
        kind: dict = {"type": "convergence_run_state", "phase": phase}
        if current_tip_epoch is not None:
            kind["current_tip_epoch"] = current_tip_epoch
        if reason:
            kind["reason"] = reason
        if error_kind:
            kind["error_kind"] = error_kind
        self.emit(
            actor,
            kind,
            context={"convergence": {"run_id": run_id, "phase": phase}},
        )

    def blocked_convergence_decision(
        self,
        actor: Participant,
        run_id: str,
        *,
        tip_epoch: int,
    ) -> None:
        """Emit a convergence decision where no branch is eligible.

        Two commits race at the same epoch after a partition; neither reaches
        witness quorum, so convergence cannot pick a winner (no
        ``selected_branch_id``) and the run is left blocked.
        """
        branch_a = _hex64(f"branch:{self.name}:a:{run_id}")
        branch_b = _hex64(f"branch:{self.name}:b:{run_id}")
        self.emit(
            actor,
            {
                "type": "convergence_decision",
                "current_tip_epoch": tip_epoch - 1,
                "max_rewind_commits": 5,
                "candidates": [
                    {
                        "branch_id": branch_a,
                        "fork_epoch": tip_epoch - 1,
                        "tip_epoch": tip_epoch,
                        "eligible": False,
                        "rejection_reasons": ["witness_quorum_not_met"],
                        "commit_ids": [_hex64(f"commit:{self.name}:{run_id}:a")],
                        "commit_count": 1,
                        "tip_priority": "contested",
                        "score": {
                            "valid_commit_depth": 1,
                            "effective_commit_depth": 1,
                            "witness_quorum_met": False,
                            "app_witness_score": 1,
                        },
                    },
                    {
                        "branch_id": branch_b,
                        "fork_epoch": tip_epoch - 1,
                        "tip_epoch": tip_epoch,
                        "eligible": False,
                        "rejection_reasons": ["competing_commit", "witness_quorum_not_met"],
                        "commit_ids": [_hex64(f"commit:{self.name}:{run_id}:b")],
                        "commit_count": 1,
                        "tip_priority": "contested",
                        "score": {
                            "valid_commit_depth": 1,
                            "effective_commit_depth": 1,
                            "witness_quorum_met": False,
                            "app_witness_score": 1,
                        },
                    },
                ],
                "losing_branch_ids": [branch_a, branch_b],
                "error_kinds": ["no_eligible_branch"],
                "rule_trace": [
                    {
                        "rule_name": "witness_quorum",
                        "scope": "candidate",
                        "candidate_branch_id": branch_a,
                        "inputs": {"required_witnesses": 2, "observed_witnesses": 1},
                        "result": {"eligible": False},
                        "decisive": True,
                        "rejected_branch_id": branch_a,
                    },
                    {
                        "rule_name": "witness_quorum",
                        "scope": "candidate",
                        "candidate_branch_id": branch_b,
                        "inputs": {"required_witnesses": 2, "observed_witnesses": 1},
                        "result": {"eligible": False},
                        "decisive": True,
                        "rejected_branch_id": branch_b,
                    },
                ],
            },
            context={"convergence": {"run_id": run_id, "phase": "evaluating"}},
        )

    def roll_back_epoch(
        self, actor: Participant, *, pending_epoch: int, restored_epoch: int
    ) -> None:
        self.emit(
            actor,
            {
                "type": "epoch_rolled_back",
                "pending_epoch": pending_epoch,
                "restored_epoch": restored_epoch,
                "pending_kind": "commit",
            },
        )

    def resolve_fork_to_incumbent(
        self,
        actor: Participant,
        *,
        source_epoch: int,
        invalidated_msg_id: str,
    ) -> None:
        self.emit(
            actor,
            {
                "type": "fork_resolution",
                "source_epoch": source_epoch,
                "candidate_digest": _hex64(f"candidate:{self.name}:{source_epoch}"),
                "incumbent_digest": _hex64(f"incumbent:{self.name}:{source_epoch}"),
                "winner": "incumbent",
                "invalidated_msg_id": invalidated_msg_id,
            },
        )

    def invalidate_message(self, actor: Participant, msg_id: str, *, epoch: int) -> None:
        self.emit(
            actor,
            {
                "type": "message_state_changed",
                "msg_id": msg_id,
                "artifact_kind": "application_message",
                "previous_state": "committed",
                "new_state": "epoch_invalidated",
                "epoch": epoch,
                "reason": "fork_resolved_against_branch",
            },
        )

    def peeler_stale_epoch(self, actor: Participant, msg_id: str) -> None:
        self.emit(
            actor,
            {
                "type": "peeler_outcome",
                "msg_id": msg_id,
                "artifact_kind": "application_message",
                "outcome": "stale_epoch",
                "fallback_snapshot_used": True,
                "fallback_attempt_count": 2,
                "detail": "rewound to last committed snapshot after stale epoch",
            },
        )

    # -- serialization -----------------------------------------------------

    def to_logs(self) -> list[SeededLog]:
        logs = []
        for participant in self.participants:
            events = self._events[participant.name]
            jsonl = "".join(json.dumps(event, separators=(",", ":")) + "\n" for event in events)
            logs.append(
                SeededLog(
                    source_name=f"{slugify(self.name)}-{slugify(participant.name)}.jsonl",
                    account_label=participant.name,
                    device_label=participant.device_label,
                    platform=participant.platform,
                    account_pubkey_hex=participant.account_pubkey_hex,
                    jsonl=jsonl,
                )
            )
        return logs


# Per-group base timestamps, spaced days apart so the groups sort distinctly on
# the dashboard. 1730000000000 == 2024-10-27T04:53:20Z.
_BASE_MS = 1_730_000_000_000
_DAY_MS = 86_400_000


def _trailhead_group() -> list[SeededLog]:
    """Small, light group: two hikers, a couple of messages, one topic change."""
    maya = Participant("Maya Okonkwo", "iPhone 15 Pro", "ios")
    theo = Participant("Theo Almeida", "Pixel 8", "android")
    script = GroupScript("Trailhead Crew", [maya, theo], start_ms=_BASE_MS)

    script.start(maya)
    script.start(theo)

    script.send_message(maya, [theo], "Trail this Saturday? Thinking Eagle Creek, 8am.", epoch=4)
    script.tick(45_000)
    script.send_message(theo, [maya], "I'm in. Bringing the dog and extra water.", epoch=4)
    script.tick(30_000)
    script.change_topic(maya, 5, "Trailhead Crew — Eagle Creek Sat 8am")
    script.commit_epoch(maya, 5)
    return script.to_logs()


def _acme_group() -> list[SeededLog]:
    """Medium work group: a delivery gap, a publish retry, and a fork resolution."""
    dana = Participant("Dana Whitfield", "MacBook Pro", "macos")
    erik = Participant("Erik Lindqvist", "ThinkPad (Fedora)", "linux")
    priya = Participant("Priya Nair", "Galaxy S24", "android")
    sam = Participant("Sam Cohen", "iPhone 13", "ios")
    script = GroupScript("Acme Standup", [dana, erik, priya, sam], start_ms=_BASE_MS + _DAY_MS)

    for member in (dana, erik, priya, sam):
        script.start(member)

    # Dana's standup note reaches Erik and Priya, but Sam's recorder never logs
    # it -> a missing-recipient delivery gap.
    script.send_message(
        dana,
        [erik, priya, sam],
        "Standup in 5. Drop blockers in the thread.",
        epoch=11,
        observed_by=[erik, priya],
    )
    script.tick(60_000)
    script.send_message(erik, [dana, priya, sam], "Blocked on the staging deploy creds.", epoch=11)
    script.tick(40_000)
    # Priya's first publish fails on a relay, the message still lands for others.
    script.send_message(
        priya,
        [dana, erik, sam],
        "I can rotate the creds after standup.",
        epoch=11,
        observed_by=[dana, erik, sam],
        publish="failed",
    )
    script.tick(90_000)
    # Two branches diverged at epoch 12; Dana's recorder records the convergence.
    script.resolve_fork(dana, "run-standup-1", tip_epoch=12)
    script.commit_epoch(dana, 12)
    script.tick(15_000)
    script.change_topic(dana, 12, "Acme Standup — daily 9:30 PT")
    return script.to_logs()


def _family_group() -> list[SeededLog]:
    """Large, busy group: six members, admin change, lots of chatter."""
    rosa = Participant("Rosa Family", "iPhone 15", "ios")
    hank = Participant("Hank Family", "Pixel 9", "android")
    pearl = Participant("Grandma Pearl", "iPad (10th gen)", "ios")
    liam = Participant("Liam Family", "iPhone SE", "ios")
    noah = Participant("Noah Family", "Galaxy A54", "android")
    olivia = Participant("Olivia Family", "MacBook Air", "macos")
    members = [rosa, hank, pearl, liam, noah, olivia]
    script = GroupScript("Family", members, start_ms=_BASE_MS + 3 * _DAY_MS)

    for member in members:
        script.start(member)

    def others(me: Participant) -> list[Participant]:
        return [m for m in members if m is not me]

    # Rosa promotes Hank to admin.
    script.promote_admin(rosa, hank, from_epoch=20, to_epoch=21)
    script.commit_epoch(rosa, 21)
    script.tick(120_000)

    # A burst of chatter. Grandma Pearl's tablet misses a couple (delivery gaps).
    script.send_message(rosa, others(rosa), "Sunday dinner at 5 — who's coming?", epoch=21)
    script.tick(50_000)
    script.send_message(
        hank,
        others(hank),
        "I'll fire up the grill 🔥",
        epoch=21,
        observed_by=[rosa, liam, noah, olivia],  # Pearl misses it
    )
    script.tick(70_000)
    script.send_message(liam, others(liam), "Can I bring a friend?", epoch=21)
    script.tick(40_000)
    script.send_message(
        olivia,
        others(olivia),
        "Sending the photos from last week 📷",
        epoch=21,
        observed_by=[rosa, hank, liam, noah],  # Pearl misses it
    )
    script.tick(80_000)
    script.send_message(noah, others(noah), "I'm running 15 late, save me a plate", epoch=21)
    script.tick(30_000)
    script.send_message(pearl, others(pearl), "Bringing the apple pie ❤️", epoch=21)
    script.tick(60_000)
    script.change_topic(rosa, 22, "Family ❤️ — Sunday dinner 5pm")
    script.commit_epoch(rosa, 22)
    return script.to_logs()


def _fork_failure_group() -> list[SeededLog]:
    """Forensic worst case: a network partition forks the group and convergence
    fails to pick a winner, forcing an epoch rollback.

    The trail mirrors a real Marmot incident: a clean baseline epoch, a partition
    where two engines commit competing state at the same epoch, a convergence run
    that evaluates both branches but blocks because neither reaches witness
    quorum, an epoch rollback, fork resolution back to the incumbent state, and
    the partitioned branch's message invalidated -- with a stale-epoch peeler
    fallback on the engine that was offline.
    """
    quinn = Participant("Quinn Alvarez", "Fedora Workstation", "linux")
    riley = Participant("Riley Tanaka", "MacBook Pro", "macos")
    avery = Participant("Avery Brooks", "Pixel 9 Pro", "android")
    members = [quinn, riley, avery]
    script = GroupScript("Mesh Relay QA", members, start_ms=_BASE_MS + 6 * _DAY_MS)

    for member in members:
        script.start(member)

    # Clean baseline: everyone agrees at epoch 30.
    script.confirm_epoch(quinn, from_epoch=29, to_epoch=30)
    script.commit_epoch(quinn, 30)
    script.send_message(quinn, [riley, avery], "Pre-partition sanity check — all green.", epoch=30)
    script.tick(120_000)

    # Partition: Riley is isolated and commits competing state at epoch 31. Its
    # message only reaches Avery; Quinn never sees it (the partitioned side).
    run_id = "conv-mesh-31"
    riley_msg = script.send_message(
        riley,
        [quinn, avery],
        "Posting from the partitioned side — did this land?",
        epoch=31,
        observed_by=[avery],
    )
    script.tick(40_000)

    # Quinn's recorder detects two commits at epoch 31 and opens a convergence run
    # that cannot resolve: neither branch reaches witness quorum.
    script.converge_run_state(quinn, run_id, "started", current_tip_epoch=30)
    script.converge_run_state(quinn, run_id, "evaluating", current_tip_epoch=30)
    script.blocked_convergence_decision(quinn, run_id, tip_epoch=31)
    script.converge_run_state(
        quinn,
        run_id,
        "blocked",
        current_tip_epoch=30,
        reason="no branch reached witness quorum",
        error_kind="witness_quorum_not_met",
    )
    script.tick(20_000)

    # The pending epoch is rolled back to the last agreed state, fork resolves to
    # the incumbent, and the partitioned message is invalidated.
    script.roll_back_epoch(quinn, pending_epoch=31, restored_epoch=30)
    script.resolve_fork_to_incumbent(quinn, source_epoch=30, invalidated_msg_id=riley_msg)
    script.invalidate_message(quinn, riley_msg, epoch=31)
    script.converge_run_state(
        quinn,
        run_id,
        "failed",
        current_tip_epoch=30,
        reason="rolled back to epoch 30; manual re-sync required",
        error_kind="unrecoverable_fork",
    )
    script.tick(30_000)

    # Riley rejoins after the partition heals and its peeler hits the stale epoch,
    # falling back to the last committed snapshot.
    script.invalidate_message(riley, riley_msg, epoch=31)
    script.peeler_stale_epoch(riley, riley_msg)
    return script.to_logs()


# (display name, participant count) for each seeded group.
# Kept in sync with the builders below; consumed by tests and tooling that need
# to address a seeded group without re-deriving it from ingested events.
SCENARIO_GROUPS: tuple[tuple[str, int], ...] = (
    ("Trailhead Crew", 2),
    ("Mesh Relay QA", 3),
    ("Acme Standup", 4),
    ("Family", 6),
)


def group_ref_for(name: str) -> str:
    """Return the deterministic ``group_ref`` a seeded group ingests under."""
    return _hex64(f"group:{name}")


def build_dev_scenario() -> list[SeededLog]:
    """Build the full local-development scenario: four groups of varying size."""
    return [
        *_trailhead_group(),
        *_fork_failure_group(),
        *_acme_group(),
        *_family_group(),
    ]
