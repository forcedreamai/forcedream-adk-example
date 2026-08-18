"""
A Google ADK agent that discovers, invokes and independently verifies ForceDream.

Run it:

    pip install google-adk cryptography httpx
    export FD_LIVE_KEY=fd_live_...        # from https://forcedream.com/earn
    python forcedream_adk_agent.py

What it demonstrates, end to end, with nothing mocked:

    1. discovery      reads ForceDream's A2A Agent Card at the well-known path
    2. card signature  verifies the card's JWS against the published JWKS
    3. invocation     sends an A2A SendMessage over the v1.0 interface
    4. execution      polls until the task reaches a terminal state
    5. proof          fetches the Ed25519 execution proof
    6. verification   rebuilds the canonical payload, walks the Merkle inclusion
                      path, and checks the signature -- locally, in this process

Step 6 is the point. Nothing in it asks ForceDream whether the proof is valid.
The maths decides, using a public key any party can fetch. An agent paying a
stranger for work needs exactly that, and it is the piece A2A does not provide:
A2A defines how agents discover and talk to each other, not what happened.

ON PAYMENT: this example authenticates with a bearer token, which is how
ForceDream bills today. AP2 -- the Agent Payments Protocol, an A2A extension --
owns the authorization layer, and the two compose rather than compete. See
AP2_PAIRING.md. No AP2 credential is constructed here, mock or otherwise,
because a fabricated mandate in runnable code is a claim of support that does
not exist.
"""

import base64
import hashlib
import json
import os
import sys
import time

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key

FD = "https://api.forcedream.ai"
CARD = f"{FD}/.well-known/agent-card.json"
CAPABILITY = "summarization"

TASK = (
    "ForceDream is a verification and settlement layer for AI agents. Every completed "
    "execution produces an Ed25519-signed proof recording the inputs, the outputs, the "
    "model that served the request, and the cost. Proofs are batched into a Merkle tree "
    "and the root is signed, so any third party can verify a specific execution occurred "
    "without trusting ForceDream."
)


# ── canonicalisation ───────────────────────────────────────────────────────
# RFC 8785 (JCS): recursive key sort, no whitespace. Both the Agent Card
# signature and the execution proof are computed over this form, so a verifier
# must reproduce it byte for byte or every signature fails.
def jcs(v):
    if isinstance(v, list):
        return [jcs(x) for x in v]
    if isinstance(v, dict):
        return {k: jcs(v[k]) for k in sorted(v)}
    return v


def canonical(obj) -> str:
    return json.dumps(jcs(obj), separators=(",", ":"))


def b64u(b: bytes) -> bytes:
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ── 1 + 2. discovery, and the card's own signature ─────────────────────────
def fetch_and_verify_card(client: httpx.Client) -> dict:
    card = client.get(CARD).raise_for_status().json()
    sigs = card.pop("signatures", None)
    if not sigs:
        print("  card is unsigned -- nothing to verify")
        return card

    sig = sigs[0]
    header = json.loads(b64u_dec(sig["protected"]))
    key = client.get(f"{FD}/.well-known/agent-card-key").raise_for_status().json()

    if header.get("kid") != key.get("kid"):
        print(f"  kid mismatch: card {header.get('kid')} vs published {key.get('kid')}")
        return card

    # JWS signing input is protected . base64url(canonical card without signatures)
    signing_input = sig["protected"].encode() + b"." + b64u(canonical(card).encode())
    raw = b64u_dec(sig["signature"])
    pub = load_pem_public_key(key["public_key_pem"].encode())
    try:
        # ES256 signatures are IEEE-P1363 (r||s) in JWS; cryptography wants DER.
        der = utils.encode_dss_signature(
            int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        )
        pub.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        print(f"  card signature VALID  (kid {header['kid']}, alg {header.get('alg')})")
    except InvalidSignature:
        print("  card signature INVALID -- stopping")
        sys.exit(1)
    return card


def pick_interface(card: dict) -> tuple:
    """Returns (url, protocol_version). A client must match its wire format to the
    interface it selects: v1.0 renamed the operation to SendMessage and dropped the
    Part kind discriminator, so sending v1.0 shapes at a 0.3.0 URL is rejected by
    the endpoint -- as it should be."""
    # v1.0 moved protocolVersion out of the card and onto each interface, so an
    # agent negotiates by choosing one. Prefer 1.0, fall back to whatever exists.
    for iface in card.get("supportedInterfaces", []):
        if str(iface.get("protocolVersion", "")).startswith("1."):
            return iface["url"], "1.0"
    if card.get("supportedInterfaces"):
        i = card["supportedInterfaces"][0]
        return i["url"], str(i.get("protocolVersion", "0.3.0"))
    # A 0.3.0 card has no supportedInterfaces at all -- protocolVersion is on the
    # card itself and the single endpoint is in url.
    return card.get("url", f"{FD}/v1/a2a/execute"), str(card.get("protocolVersion", "0.3.0"))


# ── 3 + 4. invoke and poll ─────────────────────────────────────────────────
def invoke(client: httpx.Client, url: str, key: str, version: str) -> str:
    v1 = version.startswith("1.")
    body = {
        "jsonrpc": "2.0", "id": 1,
        # v1.0 renamed message/send to SendMessage.
        "method": "SendMessage" if v1 else "message/send",
        "params": {"message": {
            # v1.0 enums are ROLE_*; 0.3.0 used bare lowercase.
            "role": "ROLE_USER" if v1 else "user",
            # v1.0 unified Parts: the member present determines the type. 0.3.0
            # discriminated on an explicit kind field.
            "parts": [{"text": TASK, "mediaType": "text/plain"} if v1
                      else {"kind": "text", "text": TASK}],
            "metadata": {"capability": CAPABILITY},
        }},
    }
    r = client.post(url, json=body, headers={"Authorization": f"Bearer {key}"}).json()
    if "error" in r:
        print(f"  invocation failed: {r['error'].get('message')}")
        sys.exit(1)
    return r["result"]["id"]


def wait_for_proof(client: httpx.Client, task_id: str, timeout_s: int = 660) -> dict:
    # Two separate, asynchronous steps, not one: the task settles (seconds), then
    # a proof-batching cron (every 5 minutes -- vercel.json) signs it into a
    # retrievable proof. Confirmed by real timing on a live run: a task with
    # completed_at only ~6s after creation still had no proof for ~21 minutes.
    # 300s (one cycle, no margin) timed out on that exact run. 660s covers two
    # full cycles plus margin for a task that lands just after a tick.
    # A 404 here means "not yet", not "never" -- treating it as failure would
    # report a working execution as broken.
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = client.get(f"{FD}/v1/workforce/proof/{task_id}/public")
        if r.status_code == 200:
            body = r.json()
            if body.get("proof"):
                return body["proof"]
        time.sleep(10)
        waited = int(time.time() - (deadline - timeout_s))
        # Execution is queued and driven by a cron, so settlement is not
        # instant. Reporting the elapsed time is more useful than a spinner --
        # and honest about a latency floor that is ours, not the model's.
        print(f"    queued... {waited}s")
    print("  timed out waiting for the proof")
    sys.exit(1)


# ── 6. verify the proof ────────────────────────────────────────────────────
# Proof verification uses the published SDK rather than reimplementing the
# canonical payload here. An earlier version of this example hand-rolled it and
# got the field coercion subtly wrong -- the signature failed against a proof
# that was perfectly valid, which is the worst possible failure for a
# verification tool: it accuses the server of forgery when the client is at
# fault. The SDK is gated against a public conformance suite in twelve
# languages; reproducing that by hand in an example is not worth the risk.
def verify_proof_via_sdk(task_id: str) -> tuple:
    import asyncio
    from forcedream import ForceDream as FDClient
    r = asyncio.run(FDClient().verify(task_id=task_id))
    return bool(r.get("verified")), int(r.get("fields_signed") or 0), r.get("message", "")


def main():
    key = os.environ.get("FD_LIVE_KEY", "")
    if not key.startswith("fd_live_"):
        print("Set FD_LIVE_KEY to a billing key from https://forcedream.com/earn")
        print("(the fd_live_ one -- the sk_fd_ account key cannot invoke)")
        sys.exit(2)

    with httpx.Client(timeout=60) as client:
        print("\n1. discovery")
        card = fetch_and_verify_card(client)
        skills = [s["id"] for s in card.get("skills", [])]
        print(f"  {card['name']}: {len(skills)} skills")
        if CAPABILITY not in skills:
            print(f"  '{CAPABILITY}' is not advertised -- stopping")
            sys.exit(1)

        url, version = pick_interface(card)
        print(f"\n2. invoking '{CAPABILITY}' at {url} (A2A {version})")
        task_id = invoke(client, url, key, version)
        print(f"  task {task_id}")

        print("\n3. waiting for settlement")
        proof = wait_for_proof(client, task_id)
        print(f"  served by : {proof.get('inference_provider')} / {proof.get('inference_model')}")
        print(f"  cost      : {proof.get('cost_pence')}p")
        print(f"  algorithm : {proof.get('algorithm')}")

        print("\n4. verifying locally, via the published SDK")
        ok, fields, msg = verify_proof_via_sdk(task_id)
        print(f"  signature {'VALID' if ok else 'INVALID'}  ({fields} signed fields)")
        if msg:
            print(f"  {msg[:100]}")
        print(f"\n  Verified without asking ForceDream. Check it yourself:")
        print(f"  https://forcedream.com/verify?task_id={task_id}")
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
