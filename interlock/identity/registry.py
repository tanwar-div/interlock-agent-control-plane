"""Agent registry: identity, capability and revocation.

Every agent that can propose an action must first be registered. Registration
mints an Ed25519 keypair and issues an `AgentCard` — a public identity document
signed by the control plane, carrying the agent's SPIFFE id, its public key,
the tools it may call, and the maximum severity it may ever reach.

Two properties matter:

  * **Attribution.** A proposal carries a signature made with the agent's
    private key, so "which agent asked for this" is provable rather than
    self-declared.
  * **Capability.** Tools and severity ceiling are an allowlist on the card.
    An agent that talks its way into wanting a dangerous tool still cannot
    invoke one that is not on its card.
"""
from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path
from typing import Any

from interlock.common.config import get_settings
from interlock.common.models import (
    ActionProposal,
    AgentCard,
    Severity,
    canonical_json,
    utcnow,
)
from interlock.common.store import DocumentStore, get_store
from interlock.identity.keys import (
    control_plane_key,
    generate_keypair,
    sign,
    verify,
)

logger = logging.getLogger(__name__)

_AGENT_KEY_DIR = Path(".interlock-keys/agents")


class IdentityError(RuntimeError):
    """Raised when identity, capability or signature checks fail."""


class AgentRegistry:
    def __init__(self, store: DocumentStore | None = None) -> None:
        self._store = store or get_store()
        self._settings = get_settings()
        self._collection = self._settings.collection_agents

    # --- identifiers ------------------------------------------------------

    def spiffe_id(self, namespace: str, name: str) -> str:
        return f"spiffe://{self._settings.trust_domain}/ns/{namespace}/agent/{name}"

    # --- registration -----------------------------------------------------

    async def register(
        self,
        *,
        name: str,
        namespace: str,
        display_name: str,
        allowed_tools: list[str],
        max_severity: Severity,
    ) -> tuple[AgentCard, str]:
        """Register an agent, returning its card and private key PEM.

        Re-registering an existing agent keeps its identity and key so that
        restarts do not invalidate signatures already in the ledger.
        """
        spiffe = self.spiffe_id(namespace, name)
        agent_id = spiffe.replace("://", "_").replace("/", "_")

        existing = await self._store.get(self._collection, agent_id)
        key_path = _AGENT_KEY_DIR / f"{agent_id}.pem"

        if existing and key_path.exists():
            card = AgentCard.model_validate(existing)
            # Capabilities are refreshed from code so the card cannot drift
            # away from what the deployment actually intends to grant.
            card.allowed_tools = sorted(allowed_tools)
            card.max_severity = max_severity
            card.revoked = False
            card = self._sign_card(card)
            await self._store.put(self._collection, agent_id, card.model_dump(mode="json"))
            return card, key_path.read_text()

        private_pem, public_pem = generate_keypair()
        _AGENT_KEY_DIR.mkdir(parents=True, exist_ok=True)
        key_path.write_text(private_pem)
        key_path.chmod(0o600)

        card = AgentCard(
            agent_id=agent_id,
            display_name=display_name,
            spiffe_id=spiffe,
            namespace=namespace,
            public_key_pem=public_pem,
            allowed_tools=sorted(allowed_tools),
            max_severity=max_severity,
        )
        card = self._sign_card(card)
        await self._store.put(self._collection, agent_id, card.model_dump(mode="json"))
        logger.info("registered agent %s with %d tools", spiffe, len(allowed_tools))
        return card, private_pem

    def _sign_card(self, card: AgentCard) -> AgentCard:
        private_pem, _ = control_plane_key()
        card.registry_signature = sign(private_pem, canonical_json(card.signing_payload()))
        return card

    # --- lookup -----------------------------------------------------------

    async def get_by_spiffe(self, spiffe: str) -> AgentCard | None:
        rows = await self._store.query(
            self._collection, where=[("spiffe_id", "==", spiffe)], limit=1
        )
        return AgentCard.model_validate(rows[0]) if rows else None

    async def list_cards(self) -> list[AgentCard]:
        rows = await self._store.query(self._collection)
        return [AgentCard.model_validate(r) for r in rows]

    async def revoke(self, spiffe: str, reason: str = "") -> None:
        card = await self.get_by_spiffe(spiffe)
        if card is None:
            raise IdentityError(f"unknown agent {spiffe}")
        card.revoked = True
        await self._store.patch(
            self._collection, card.agent_id, {"revoked": True, "revocation_reason": reason}
        )
        logger.warning("revoked agent %s (%s)", spiffe, reason or "no reason given")

    # --- verification -----------------------------------------------------

    def verify_card(self, card: AgentCard) -> bool:
        """Check the registry's own signature over an agent card."""
        if not card.registry_signature:
            return False
        _, public_pem = control_plane_key()
        return verify(public_pem, canonical_json(card.signing_payload()), card.registry_signature)

    async def authenticate_proposal(self, proposal: ActionProposal) -> AgentCard:
        """Establish that a proposal really came from a live, entitled agent.

        Raises `IdentityError` on any failure; callers must treat that as a
        hard deny rather than a warning.
        """
        card = await self.get_by_spiffe(proposal.actor)
        if card is None:
            raise IdentityError(f"proposal from unregistered actor '{proposal.actor}'")
        if card.revoked:
            raise IdentityError(f"agent {card.spiffe_id} is revoked")
        if not self.verify_card(card):
            raise IdentityError(f"agent card for {card.spiffe_id} fails registry signature check")
        if not proposal.signature:
            raise IdentityError("proposal is unsigned")
        if not verify(card.public_key_pem, canonical_json(proposal.signing_payload()), proposal.signature):
            raise IdentityError("proposal signature does not match the registered agent key")

        # Reject stale signatures so a previously approved proposal cannot be
        # replayed later against a changed environment.
        age = (utcnow() - _aware(proposal.created_at)).total_seconds()
        if age > self._settings.proposal_max_age_seconds:
            raise IdentityError(
                f"proposal is {age:.0f}s old, exceeding the "
                f"{self._settings.proposal_max_age_seconds}s replay window"
            )
        if age < -60:
            raise IdentityError("proposal is timestamped in the future")

        return card

    @staticmethod
    def check_capability(card: AgentCard, action_type: str) -> None:
        """Enforce the tool allowlist recorded on the card."""
        if action_type not in card.allowed_tools:
            raise IdentityError(
                f"agent {card.spiffe_id} is not entitled to '{action_type}' "
                f"(entitled to: {', '.join(card.allowed_tools) or 'nothing'})"
            )


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def sign_proposal(proposal: ActionProposal, private_pem: str) -> ActionProposal:
    """Attach the proposing agent's signature to a proposal."""
    proposal.signature = sign(private_pem, canonical_json(proposal.signing_payload()))
    return proposal
