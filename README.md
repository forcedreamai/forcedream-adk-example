# Verify a ForceDream execution from your own agent

A working client that discovers ForceDream over A2A, invokes a real capability,
and verifies the resulting Ed25519 execution proof — in your process, using
published keys, without asking ForceDream whether its own proof is valid.

Written to be read by an agent developer. It talks A2A over HTTP, so any
framework can be the caller: Google ADK, LangChain, CrewAI, or a plain script.

## Thirty seconds, no account

Discovery and card verification need no key. This fetches ForceDream's A2A Agent
Card and checks the card's own JWS signature against the published JWKS:

    pip install httpx cryptography
    python -c "
    import httpx, json, base64
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes
    FD='https://api.forcedream.ai'
    card=httpx.get(f'{FD}/.well-known/agent-card.json').json()
    key=httpx.get(f'{FD}/.well-known/agent-card-key').json()
    sig=card.pop('signatures')[0]
    jcs=lambda v: [jcs(x) for x in v] if isinstance(v,list) else ({k:jcs(v[k]) for k in sorted(v)} if isinstance(v,dict) else v)
    b64=lambda b: base64.urlsafe_b64encode(b).rstrip(b'=')
    inp=sig['protected'].encode()+b'.'+b64(json.dumps(jcs(card),separators=(',',':')).encode())
    raw=base64.urlsafe_b64decode(sig['signature']+'==')
    der=utils.encode_dss_signature(int.from_bytes(raw[:32],'big'),int.from_bytes(raw[32:],'big'))
    load_pem_public_key(key['public_key_pem'].encode()).verify(der,inp,ec.ECDSA(hashes.SHA256()))
    print('Agent Card signature VALID —', card['name'], f\"({len(card['skills'])} skills)\")
    "

If that prints VALID, you have independently confirmed that the Agent Card you
just fetched was signed by the key ForceDream publishes. Most published A2A
agent cards are not signed at all.

## The full run

Needs a billing key. Signup is free and includes trial credit:
https://forcedream.com/earn — take the `fd_live_` key, not the `sk_fd_` one.
Only `fd_live_` can invoke.

    git clone https://github.com/forcedreamai/forcedream-adk-example
    cd forcedream-adk-example
    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
    export FD_LIVE_KEY=fd_live_...
    .venv/bin/python forcedream_adk_agent.py

Four stages, all against production:

    1. discovery      reads the Agent Card, verifies its JWS
    2. negotiation    picks an interface and matches the wire format to its
                      protocol version — v1.0 renamed the operation to
                      SendMessage and dropped the Part `kind` discriminator, so
                      sending v1.0 shapes at a 0.3.0 URL is correctly rejected
    3. execution      submits a real, billed task and waits for settlement
    4. verification   checks the Ed25519 proof via the published SDK

**Expect roughly 90 seconds at stage 3.** Execution is queued and driven by a
cron rather than run in the request, so settlement is not instant. The client
prints elapsed time rather than a spinner, because a latency floor that is ours
should be visible rather than disguised.

A run costs 1–3p against your trial balance. Failed or schema-invalid
executions are not charged.

## Why verification goes through the SDK

Stage 4 calls `forcedream.verify()` rather than reconstructing the canonical
payload here. An earlier draft of this example hand-rolled it, got the field
coercion subtly wrong, and reported a perfectly valid proof as forged.

That is the worst failure mode a verification tool has: it accuses the server
when the client is at fault. The same defect hit all twelve ForceDream SDKs when
model binding shipped, which is why the
[conformance suite](https://github.com/forcedreamai/forcedream-sdk-conformance)
exists and why every SDK is gated against it in CI.

If you are building your own verifier, start from that suite. Run
`./run_matrix.sh` there to see twelve independent implementations agree on the
same nine cases.

## What the proof does and does not establish

**It establishes** that a specific execution occurred with specific inputs and
outputs, which provider and model ForceDream selected, what it cost, and that
none of that has been altered since. Anyone can check this against a published
key with no account.

**It does not establish that the output was good.** Cryptography does not answer
that question. A signed proof of a poor summary is still a signed proof.

**It does not establish that the provider agrees they served the request.** The
proof records the model ForceDream *selected*. No inference provider currently
signs an attestation binding a request to a model version, so that link rests on
ForceDream's word. It is the last unclosed gap in the chain and it needs the
provider, not us: https://forcedream.com/demo/attestation

**It does not establish that you authorized the payment.** That is a different
protocol's job — see [AP2_PAIRING.md](AP2_PAIRING.md) for how an execution proof
composes with an AP2 Payment Mandate, and for a plain statement of which of the
two ForceDream implements today.

## Verify anything, including proofs that are not yours

    pip install forcedream
    python -c "
    import asyncio
    from forcedream import ForceDream
    r = asyncio.run(ForceDream().verify(task_id='wtask_90d5a41b1c2a6bdd0f35'))
    print(r['verified'], r['fields_signed'], 'fields')
    "

No key, no account, someone else's execution. That is the point of the design:
verification must not require the trust of the party being verified.
