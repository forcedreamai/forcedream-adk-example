# Authorization and execution are different problems

AP2 — the Agent Payments Protocol — went to v0.2 in April 2026 and was donated to
the FIDO Alliance in May 2026 for community governance. It is an extension of A2A
and MCP, and it owns one specific slot in the agentic commerce stack:
authorization.

ForceDream owns a different one: execution proof.

Neither is sufficient alone, and the gap between them is where an agent paying a
stranger actually gets hurt.

## What each one establishes

**AP2 Payment Mandate.** A W3C Verifiable Credential binding a user's
authorization to a specific transaction — what the user agreed to, what the agent
selected, what was to be charged. Signed by the user's authority.

It establishes that a payment was authorized. It says nothing about whether any
work was performed.

**ForceDream execution proof.** An Ed25519 signature over a canonical payload
recording the task, a hash of the inputs, a hash of the outputs, the provider and
model that served the request, and the cost. Batched into a Merkle tree; the root
is signed. Verifiable by anyone against a published key.

It establishes that a specific execution occurred. It says nothing about whether
the payer agreed to it.

## The failure modes each one leaves open

With **only an AP2 mandate**, a buyer has cryptographic proof they authorized £5
for a summarization, and no way to establish that a summarization happened, what
model produced it, or what it cost to run. A merchant can charge against a valid
mandate for work never performed. The mandate verifies perfectly.

With **only a ForceDream proof**, a buyer has cryptographic proof that
`gpt-oss-20b` produced a specific output for 1p at a specific time, and no way to
establish that they ever agreed to pay for it. The proof verifies perfectly.

Both artefacts are individually sound. Neither closes the loop.

## What the pairing looks like

The two bind on the transaction identifier and the amount:

    AP2 Payment Mandate          ForceDream execution proof
    ------------------------     --------------------------------
    who authorized               task_id
    what they authorized         input_hash / output_hash
    maximum amount               cost_pence  (must be <= authorized)
    signed by the user           inference_provider / inference_model
                                 signed by ForceDream

A buyer verifies the mandate against the user's key and the proof against
ForceDream's published key. Two independent signatures, from two parties with no
incentive to collude, covering authorization and performance respectively.

Neither party can forge the other's half.

## What ForceDream implements today, precisely

Execution proofs: **yes**, live, and verifiable by any third party without an
account. Twelve SDKs implement the verification contract and are gated against a
public conformance suite.

AP2 mandates: **no**. Not partially, not behind a flag. Billing today
authenticates with a bearer token and settles against a prepaid balance, which is
a conventional API arrangement rather than an agent-native one.

This document is a design position, not a compatibility claim. The example agent
in this directory constructs no AP2 credential, mock or otherwise — a fabricated
mandate in runnable code would read as support that does not exist.

## The honest gap in our own half

A ForceDream proof records the model **we selected**. It cannot establish that the
provider agrees they served the request — no inference provider currently signs
an attestation binding a request to a model version. That is the last unclosed
link, and it needs the provider, not us.

See https://forcedream.com/demo/attestation for what that would take.
