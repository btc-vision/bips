<pre>
BIP: TBD
Layer: Consensus (soft fork)
Title: CT-Exodus – Confidential Transactions
Author: TBD (CT-Exodus Proposal Contributors)
Status: Draft
Type: Standards Track (Consensus)
Created: 2025-06-04
License: BSD-3-Clause
</pre>

## Abstract

This proposal (CT-Exodus) defines a Bitcoin protocol upgrade enabling **Confidential Transactions (CT)** through a new Segregated Witness output version. This proposal permits transaction output amounts to be **hidden using Pedersen commitments and range proofs**, without altering the 21 million BTC supply cap. It introduces **SegWit v2 outputs** that include cryptographic commitments to output values instead of explicit amounts, verified by **Bulletproofs** (short zero-knowledge range proofs). By leveraging a SegWit extension, CT-Exodus keeps all new data in witness/annex sections (and thus off the legacy transaction hashing), preserving compatibility as a soft fork. Old nodes will treat CT outputs as anyone-can-spend outputs with zero value, ensuring legacy validation does not break (they simply interpret the "missing" value as a fee burn). New consensus rules require that all CT outputs pass balance and range checks to prevent inflation or negative values. The result is that amounts can be **kept private on-chain** (improving privacy and fungibility) while anyone can still verify that no extra coins are created.

CT-Exodus defines a full **transaction format, validation rules, signature hashing algorithm, address encoding, and reference implementation** for integrating Confidential Transactions into Bitcoin. This document is structured as a Bitcoin Improvement Proposal (BIP) with sections covering motivation, technical specification, rationale for design decisions, backward compatibility, reference implementation guidance, test vectors, deployment considerations, and references.

## Motivation

Bitcoin's privacy is limited by its fully transparent ledger: transaction outputs include publicly visible amounts, enabling blockchain analysis to trace flows and de-anonymize users. While techniques like CoinJoin and Taproot improve privacy to some extent, **amount correlation remains a major source of privacy leakage**. For example, exact payment amounts and "change" outputs can link transactions and addresses, undermining fungibility. **Confidential Transactions (CT)** were first proposed by Adam Back and developed by Gregory Maxwell to **hide transaction amounts** using cryptographic commitments. CT has been deployed on the Elements sidechain/Liquid network for several years, demonstrating its practical viability for improving privacy and fungibility in Bitcoin-like systems.

This proposal brings Confidential Transactions to Bitcoin in a **soft-fork compatible** manner by defining a new Segregated Witness version. The motivation is to enhance Bitcoin's privacy and fungibility **without a separate sidechain or altcoin**, instead upgrading Bitcoin itself. Key motivations include:

* **Privacy Improvement:** With CT-Exodus, observers cannot see specific output values; only participants know the amounts. This thwarts common heuristics that rely on amount patterns.
* **Fungibility:** Hiding amounts makes coins more uniform. It becomes infeasible to distinguish "tainted" or "high-value" coins by on-chain analysis, improving fungibility.
* **Auditability:** Importantly, CT-Exodus still allows anyone to verify that **no extra BTC are created** (no inflation) by requiring commitments to sum correctly and by making fees explicit. The total supply remains capped and auditable (though individual transaction amounts are private).
* **Leverage Existing Tech:** We reuse and build upon proven technology—Pedersen commitments and Bulletproof range proofs. These have been tested in Elements/Liquid and academic research, providing confidence in their soundness and efficiency.
* **Soft Fork Deployment:** Implementing CT as a SegWit v2 output keeps all new validation rules and data segregated in a way that does not break legacy nodes. Legacy wallets will simply not recognize the new address format "bcx…" and won't create such outputs by accident. Blocks containing CT outputs will appear valid to old nodes (with CT amounts seemingly `0` and hence extra "fee" burned) but miners and upgraded nodes enforce the new rules to prevent abuse. This backwards-compatible deployment path avoids disrupting non-upgraded clients while still allowing a forward upgrade.

In summary, CT-Exodus aims to substantially improve user privacy and coin fungibility on Bitcoin by hiding amounts, while carefully preserving Bitcoin's core security properties (fixed supply, decentralized validation) and compatibility with existing infrastructure.

## Specification

### Overview

This section specifies the consensus rules and transaction format changes introduced by CT-Exodus. At a high level:

* A new **SegWit output type (version 2)** is introduced for confidential transactions. These outputs use Pedersen commitments (33 bytes) instead of explicit values, and require a range proof (Bulletproof) in the transaction's witness data to prove the amount is within a valid range.
* Transactions including SegWit v2 outputs must satisfy new validation rules:

    * **Commitment sum rule:** The sum of input commitments must equal the sum of output commitments plus an explicit fee commitment, ensuring no inflation.
    * **Range proof rule:** Every CT output's value commitment must be accompanied by a valid **Bulletproof range proof** showing the hidden value is non-negative and below a protocol-defined upper bound (e.g. < 2^52 satoshis, comfortably above 21e14).
    * **No CT in coinbase:** Coinbase (miner reward) transactions are **forbidden from producing CT outputs** – coinbase outputs must remain explicit. This ensures newly minted coins are always transparent, preventing any risk of undetectable inflation in the issuance process and maintaining miner fee transparency.
* The witness serialization is extended with an **annex** that carries CT-specific data (commitments, range proofs, etc.) in a TLV (Type-Length-Value) format. This allows future upgrades and optional fields without further transaction format changes. Annex data is given a custom weight cost (3 WU per byte) to balance bandwidth vs blockweight concerns.
* A new Bech32m address prefix `"bcx"` (and `"tbx"` for testnet) is defined for SegWit v2 outputs. This distinguishes CT addresses from earlier SegWit addresses ("bc1…"), ensuring old wallets that do not understand CT won't send to them (while new wallets can recognize and handle them).
* The signature hashing (sighash) algorithm for SegWit v2 is specified (largely following BIP341's design) with modifications to cover commitments and to handle the new annex and sighash flag behaviors (including ANYONECANPAY and SINGLE semantics). We provide full pseudocode for the v2 sighash for implementers.

The following subsections detail these points formally.

### Transaction Format – SegWit v2 Outputs

A **SegWit v2 output** (also referred to as a **CT output**) appears in a transaction's `txout` list with a special scriptPubKey form and a dummy amount in the serialized transaction. Its on-chain representation is:

* **Amount (8 bytes):** MUST be set to zero (0x0000000000000000) for CT outputs. Old nodes will interpret this as a zero-valued output (effectively burning the input value as fee), but new nodes apply CT rules to this output. A non-zero explicit amount in a v2 output is invalid under new consensus rules (it would indicate a partially transparent output, which is not allowed for CT type).
* **scriptPubKey:** Exactly 34 bytes, consisting of an **OP_2** opcode (0x52, which denotes witness version 2) followed by a 32-byte push (0x20 as the push length) of data. The pushed 32-byte data is the **witness program** for this CT output. Like previous SegWit outputs, this witness program serves as an identifier for spending conditions:

    * In CT-Exodus, the 32-byte witness program is interpreted similarly to a Taproot output's 32-byte key (BIP341). Specifically, it encodes either:

        * An **x-only public key** (which can be used for a key-path spend via a Schnorr signature, just as in BIP340), or
        * A commitment to a script Merkle root (allowing script-path spends, analogous to Taproot's internal key + script tree structure).
    * The CT output's control of spending is thus separate from the value commitment. One can think of the 32-byte witness program as the "locking public key or script hash," while the confidential value is handled by the commitment and proof elsewhere.
    * **Example:** A CT address (mainnet) might be encoded as `bcx1z...` and correspond to a scriptPubKey of the form:
      `OP_2 <32-byte-public-key>`.
      If the public key `P` is the sole spending key, the output can be spent with a Schnorr signature for `P`. If the key was tweaked to commit to a script, the spending could alternatively reveal the script and prove the tweak as in Taproot. (CT-Exodus reuses the Taproot script commitment mechanism for flexibility, but script usage is optional.)
* **Explicit Fee Output:** A transaction **that includes any CT outputs** is required to also include **one special explicit output for the fee**. This is an unspendable output (scriptPubKey of OP_RETURN) that encodes the total fee in plaintext. The fee output serves to explicitly reveal the fee amount to validators and wallets (since inputs and CT outputs alone don't allow fee derivation by old methods). The fee output MUST be:

    * **Value:** 0 (since it doesn't transfer coins to anyone; it's just a marker).
    * **scriptPubKey:** An OP_RETURN followed by an 8-byte push of the fee value (in satoshis, little-endian). For example, if the fee is 1000 sats (0x03E8), the scriptPubKey would be: `OP_RETURN 0x08 0xE8 0x03 0x00 0x00 0x00 0x00 0x00 0x00` (0x08 pushes the 8-byte fee value `0x000000000003E8`). This output is provably unspendable and purely informational.
    * Only one such fee output is allowed per transaction (having multiple fee outputs or a fee output in a transaction with no CT outputs is invalid). Typically, it is placed as the **last output** for convenience, but that's not strictly required.

**Rationale:** Setting the txout amount field to zero for CT outputs and carrying the real value in commitments allows old nodes to see a balanced transaction (they assume the input value was all paid as fee). Meanwhile, new nodes enforce that the "missing" amount is accounted for by the confidential value commitment. The explicit fee output ensures miners can safely claim fees and everyone can see the fee paid. This design cleanly preserves the supply audit: `sum(input_commits) = sum(output_commits) + commit(fee)` must hold, where `commit(fee)` is just the Pedersen commitment encoding of the known fee. (We define Pedersen commitments formally below.)

**Backwards Compatibility:** Legacy nodes (pre-CT) will interpret CT transactions as having outputs of zero value (except fees which they see burned). They will consider the transactions valid (since from their perspective no extra money was created—any input value not explicitly in outputs is "fee" that can be burned or claimed by miners). Thus, blocks containing CT transactions do not violate legacy consensus; old nodes simply don't enforce the new rules. The new rules (on CT outputs and proofs) are enforced by upgraded nodes, making this a soft fork.

### Pedersen Commitments (Confidential Amounts)

Instead of a plaintext 8-byte value, a CT output's amount is represented by a **Pedersen commitment**. A Pedersen commitment allows one to commit to a value `v` (the amount in satoshis) using a blinding factor `r` such that:

```
C = v*H + r*G
```

where:

* `G` is the standard secp256k1 base point (the same base used for public keys).
* `H` is a second independent generator with no known discrete logarithm relative to G (ensuring no one can cheat the commitment by exploiting a relation between G and H).
* `v` is the value (a 64-bit integer, but practically we will restrict it to a range).
* `r` is a **blinding factor** (256-bit scalar) chosen uniformly at random to hide the value.

The resulting commitment `C` is an elliptic curve point (33 bytes when serialized in compressed form). Given `C`, an observer cannot determine `v` without knowing `r` (hiding property), but anyone can add/subtract commitments: the commitments are **homomorphic**. This means:

* `C(v1, r1) + C(v2, r2) = C(v1+v2, r1+r2)`  (the commitment to the sum is the sum of commitments),
* `C(v, r) - C(v, r) = 0` (commitment of a value minus itself yields the identity).

These properties let us verify balance without seeing values. If a transaction's input commitments sum to the output commitments plus fee commitment, then the sum of inputs values equals sum of outputs plus fee (with all `r` factors canceling out). The blinding factors protect the actual values.

**Generator H:** We define the second generator H in a deterministic, consensus-safe way. Following the method in BIP340 (Schnorr signatures) for deriving an arbitrary "hash-to-point":

* Let `tag = "CT-Exodus/Generator"`. Compute `32-byte X = SHA256(tag)`.
* Interpret X as a 256-bit integer (in big-endian) and attempt to **lift_x(X)** to the secp256k1 curve (i.e., find a point with x-coordinate X and even y-coordinate). If X is not a valid x-coordinate or does not lead to a point, increment X (modulo p, the field modulus) and try again. This process will find a valid point after at most a few attempts. Call the resulting point `H`.
* `H` is then a fixed constant (a point on secp256k1) used as the Pedersen secondary generator. By construction, **no one knows a discrete log `d` such that `H = d*G`**, because doing so would require solving elliptic curve discrete log or guessing the tagged hash output. This property is critical: if an attacker knew such `d`, they could forge commitments (e.g., `C = v*H + r*G` and open it also as `(v + d*k)*H + (r - k)*G` for some `k`, breaking binding). This method to choose H is the same kind of precaution used in e.g. BIP341 to pick unbiased taproot tweak hashes.

For concreteness, the resulting generator H (in compressed form) is:

* (To be filled with the computed point coordinates once computed. *This will be a specific 33-byte hex string representing H.*)

**Encoding of Commitments:** Each confidential value is serialized as a 33-byte field in transactions:

* If an output is **explicit (not CT)**, it still uses the regular 8-byte amount in the txout structure (and no commitment is used). However, mixing explicit and CT outputs in a single tx is discouraged and in consensus terms, any SegWit v2 output **must** use a commitment (explicit amounts are only for non-CT outputs of older types).
* If an output is **CT**, its commitment is included in the witness annex rather than in the main txout. (The `amount` field in the txout is zero as noted.)
* We use the **compressed point representation with a special prefix** to encode commitments:

    * A Pedersen commitment `C = v*H + r*G` is serialized as 33 bytes: the first byte is `0x08` or `0x09`, and the next 32 bytes are the x-coordinate of `C` in big-endian. The prefix `0x08` indicates an even Y coordinate and `0x09` indicates an odd Y (this scheme mirrors the standard 0x02/0x03 compression indicators but uses 0x08/0x09 to distinguish commitments from ordinary public keys).
    * **Rationale:** Using 0x08/0x09 ensures that commitments cannot be mistaken for normal public keys or script hashes. It also trivially makes commitments non-malleable in serialization (there is a unique encoding for each point).
* **Explicit value as commitment:** For internal calculations, we treat an explicit value `v` as the commitment `C = v*H + 0*G` (i.e., blinding factor r=0). This is a **"synthetic commitment"** that allows us to unify handling of explicit and confidential values when summing. In other words, a known value can be considered a Pedersen commitment with no blinding. However, such commitments are never placed on-chain for outputs (on-chain explicit outputs remain 8-byte values). The synthetic commit concept is used in verifying balance: if a transaction has a mix of explicit and CT inputs or outputs, the verifier converts explicit amounts to the equivalent point `v*H` (blinder 0) and adds them in.

**Nonzero Blinding Requirement:** Each CT output **must use a nonzero blinding factor r** (consensus rule). We disallow `r = 0` for actual CT outputs to ensure that no output's commitment is inadvertently "unblinded." This prevents a potential privacy leak where an output commitment equals `v*H` exactly – while it's computationally infeasible to deduce `v` from `v*H` (since H's discrete log relative to G is unknown), having r=0 could aid certain correlation attacks or reduce the entropy in the system. In practice, wallets should always pick random r ≠ 0 anyway. Enforcing r ≠ 0 can be done by requiring in the range proof that the blinding term is not zero (one approach is to include a proof-of-inverse: given r, prove `r * r_inv = 1 mod n` for some provided `r_inv`, which is only possible if r≠0). In CT-Exodus, Bulletproofs are extended to incorporate a nonzero-blinder constraint: each proof explicitly or implicitly proves the blinding factor is non-zero ("`r·r⁻¹ = 1`" as a folded constraint).

### Bulletproofs (Range Proofs)

While Pedersen commitments hide the value, they alone do not prevent an invalid value (e.g., a negative value or an excessively large value that could overflow and emulate a subtraction). We need a **range proof** to enforce that each committed value lies in a valid range (e.g., 0 ≤ v < 2^52). CT-Exodus adopts **Bulletproofs** as the range proof system for efficiency. Bulletproofs are non-interactive zero-knowledge proofs with very short size (proof size grows logarithmically with the range and number of outputs) and no trusted setup.

**Range:** We define the range for CT values as 0 ≤ v < 2^52 satoshis (approximately 4.5e15, which is above 2.1e15 satoshis ~ 21 million BTC, leaving headroom). Thus each commitment must be proven to hide a 52-bit value. (52 bits suffices for current supply; this could be increased in future if needed, at cost of larger proofs.)

**Proof aggregation:** A key feature of Bulletproofs is the ability to **aggregate multiple range proofs** into one proof with minimal overhead. CT-Exodus requires that **all CT outputs in a single transaction share a single aggregated Bulletproof proof** wherever possible:

* If a transaction has *m* CT outputs, then a single Bulletproof can prove all *m* values are in range, with size roughly *2 log2(64*m)* 32-byte elements (for comparison, earlier CT proposals used *m* separate 2KB Borromean proofs; Bulletproofs for multiple outputs are dramatically smaller).
* All commitments in one transaction are taken as inputs to one Bulletproof, producing one combined proof. (If m is not a power of 2, dummy commitments of value 0 can be added internally to pad the proof – this has no effect on verification except a slight size increase.)
* This reduces blockchain footprint and verification cost. Verification of an aggregated proof for m commitments is about the same order of work as verifying m individual proofs, but can be batch-verified across transactions and even across proofs for a minor speedup. We plan to implement batch verification for Bulletproofs in Bitcoin Core's secp256k1 library for efficiency.

**Bulletproof verification:** At a high level, a Bulletproof range proof proves knowledge of `v` and `r` such that `C = v*H + r*G` and `v` is in [0, 2^52). It does so via a zero-knowledge proof that involves multiple curve operations and challenges (the math is complex, but it's well-documented in the Bulletproofs paper). The important part for consensus is that:

* The proof bytes are included in the transaction (witness).
* A verifier will recompute certain curve points and check pairing equations to ensure the proof is valid for commitment C.
* The size of a single-output proof is ~674 bytes, and grows by ~incremental ~~ 96 bytes per additional proof when aggregating (exact proof sizes will be given in test vectors).

CT-Exodus uses Bulletproofs without modification except for one extension: **blinding factor non-zero constraint.** As mentioned, we want to ensure `r != 0`. We achieve this by augmenting the proof with a simple multiplicative relation. In practice, this can be done by proving knowledge of `r_inv = r^-1 mod n` (the inverse of r) as part of the statement. Concretely, we can include an extra committed value `r_inv` in the same Bulletproof and add the relation constraint `r * r_inv = 1`. This way, if a proof passes, it guarantees r has an inverse mod n, i.e., r is not 0. This adds a small overhead to the proof size (essentially treating r_inv as another value in range, though it's not a range but a relation – we embed it by shifting into an arithmetic circuit for Bulletproof). This technique is referred to as the "folded r ≠ 0 constraint" in the context of our proof system.

**Commitment to Zero:** For verifying balance, sometimes it's useful to prove that the sum of certain commitments equals zero (for example, that input commits minus output commits minus fee commit = 0). While this could be done implicitly by just comparing the summed points, we note that a commitment to zero (value 0, blinder 0) is simply the group's identity point. By rule, Bulletproofs must prove each commitment is in range; the identity point corresponds to v=0, r=0 which is *not allowed for outputs* (r=0 disallowed). But in the context of balance, we will separately handle the sum check, so no direct range proof on a zero sum is needed – instead, the consensus rules explicitly check for exact equality to the neutral element when verifying the sum rule (discussed below).

### SegWit v2 Witness and Annex Structure

All data related to CT commitments and range proofs is stored in the **witness field** of the transaction, specifically in an **annex**. The annex is a part of the witness as defined in BIP341: if the last element of an input's witness stack begins with 0x50 (the ASCII for 'P'), that element is the annex and is not consumed by script execution. CT-Exodus uses the annex to carry CT-specific data in a flexible format:

* **Annex Presence:** Any transaction containing SegWit v2 outputs **MUST include a witness annex**. By convention, we use the witness of the first input (input index 0) to carry the annex (if that input has an annex element starting with 0x50, it is taken as the global annex for CT data). Only one annex per transaction is allowed and it applies globally. If multiple inputs provide annexes (0x50...), the transaction is invalid (ambiguous). If an input other than index 0 has an annex and index 0 does not, that is also invalid (we require the first input to carry it for deterministic placement).
* **Annex Format:** The annex uses a **TLV (Type-Length-Value)** encoding to allow future extensibility. All multibyte integers in the annex are in little-endian unless stated otherwise (to match Bitcoin's usual encoding for amounts, etc.). The annex begins with the 1-byte 0x50 (the annex "tag" as per BIP341) followed by the TLV stream:

    * Each TLV record:

        * **Type:** 1 byte (values 0x01–0x4F reserved for CT-Exodus, 0x50–0xFF future use).
        * **Length:** Varint for the length of the Value field.
        * **Value:** The payload as defined by the Type.
    * **Records defined in CT-Exodus v1:**

        1. **Type 0x01 – Commitments List:** Contains the value commitments for all CT outputs in the transaction. The Value is a concatenation of 33-byte commitment encodings for each CT output, **in the same order as outputs appear in the txout list.** Only CT outputs are included. (If a transaction mixes CT and explicit outputs, explicit ones have no entries here – effectively they could be treated as having an 8-byte explicit amount in the base tx and no commitment in the annex. In practice, we discourage mixing; usually all outputs will be CT except the fee output.)

            * Length: must be exactly 33 * (number of CT outputs). For example, if there are 2 CT outputs, length = 66 bytes.
            * The commitments here use the 0x08/0x09 prefix encoding described above.
            * **Consensus check:** The number of commitment entries must match the number of CT outputs in the tx. A mismatch is invalid.
            * New nodes will use this list to retrieve each output's commitment for verification. (Miners and nodes also store the commitment in the UTXO set when an output is unspent.)
        2. **Type 0x02 – Range Proof:** Contains the aggregated Bulletproof range proof for all CT outputs in the transaction.

            * Length: depends on number of outputs; there is no fixed size. Typical sizes: ~674 bytes for 1 output, ~738 bytes for 2 outputs, ~ +96 bytes per additional output (roughly).
            * Value: the raw Bulletproof proof bytes.
            * **Consensus check:** The proof must be valid for all commitments in Type 0x01. This means the verifier will use the commitments and attempt to verify the Bulletproof. A failure to verify is a consensus failure (transaction invalid).
        3. **Type 0x03 – Fee Commitment (optional):** This record carries the Pedersen commitment to the transaction fee. In our design, since the fee is explicit (the OP_RETURN output), one might ask why we need a commitment for it. In fact, for verifying the balance (commitment sum rule) we can compute `commit_fee = fee * H` easily since fee is known. We include this record primarily for completeness and future-proofing, but it is **optional**. If present, it must be 33 bytes encoding the commitment to the fee value (should equal `fee*H + 0*G` essentially). If absent, validators will compute `fee*H` on the fly from the fee amount. (Miners actually don't need to include this TLV; it's trivial for verifiers to compute it, so this might be mostly unused in practice.)
        4. **Type 0x04 – (Reserved for future extensions):** This and higher types up to 0x4F are reserved for any future soft-fork upgrades to CT. Unknown types must be ignored (forward compatibility): i.e., if a node doesn't recognize a TLV type, it should skip it (but because CT is consensus-critical, practically any new TLV would come with a new softfork bit). In this version, no other types are defined.
    * **Order:** Type 0x01 (commitments) and 0x02 (rangeproof) are REQUIRED and must appear, in that order, in the annex. Type 0x03 is optional (if present, likely comes after them). If types are out of order or duplicated, it's considered a malleation and invalid (there's a canonical order and uniqueness for each type).
    * **Annex weight:** The annex bytes contribute to the block weight at a rate of **3 weight units per byte**. This is a custom policy: it is heavier than normal witness data (1 WU/byte) but lighter than base data (4 WU/byte). **Rationale:** Range proofs can be large (hundreds of bytes). Counting them as 1 WU (full witness discount) could let blocks carry a lot of range proof data without proportional cost, potentially impacting node performance. Counting them as base data (4 WU) would overly penalize CT usage. We choose 3 WU/byte as a middle ground to discourage bloated proofs while still giving some discount (since these proofs are not part of the UTXO set and don't need to be stored permanently by all nodes).

        * Implementation: For block weight calculation, each byte in the annex (including the initial 0x50) counts as 3 weight units. The rest of the witness (input sigs, etc.) remains 1 WU/byte.
        * This weight policy also incentivizes aggregating proofs (one proof for multiple outputs) because multiple small proofs would weigh more than a single aggregated proof of similar total size (due to per-proof overhead).
* **Witness Stack for CT Inputs:** An input spending a CT output (SegWit v2) will have a witness stack similar to Taproot:

    * For a key-path spend: a single 64-byte Schnorr signature (with optional sighash byte if not default).
    * For a script-path spend: `<stack elements satisfying script> <control block>` similar to BIP341.
    * **Annex in spending tx:** Note, the annex described above is included in the spending transaction (the one that creates CT outputs with commitments). It is not needed when spending a CT output. When a CT output is spent, its commitment is retrieved from the UTXO set by the verifier to sum into that spending tx's input commitments. Thus, spending a CT output doesn't require carrying its commitment or proof in the spending tx. (This is analogous to how spending a taproot output doesn't require carrying its original pubkey—just the signature or script reveal.)
    * If a spending transaction itself creates new CT outputs, it will have its own annex for those new outputs.

Summarizing: The annex TLV approach cleanly segregates CT data (commitments and proofs) from the main transaction data. It allows adding more fields later (e.g., confidential asset tags, different proof types, etc.) by defining new TLV types. Unrecognized types can be ignored under soft-fork rules (unknown annex data -> fail unless new rules allow it), but since we reserve ranges, any meaningful new type would be introduced via a designated soft fork deployment.

### Consensus Rules Summary

A transaction (and by extension, a block) is valid under CT-Exodus rules if it meets all existing Bitcoin consensus rules **and** the following additional rules whenever SegWit v2 outputs are present:

1. **SegWit v2 Output Format:** Any output with scriptPubKey starting with `OP_2` must conform to the CT output format:

    * scriptPubKey is exactly `0x52 0x20 <32-byte_program>` (i.e., OP_2, push 32 bytes of data). The 32 bytes can be any value (treated as a public key or script commitment for spending).
    * The output's 8-byte amount field must be zero. (Non-zero amount with OP_2 is invalid.)
    * There must be an associated commitment for this output in the annex TLV type 0x01 and a range proof covering it.
2. **Annex Requirements:** If any CT outputs exist, an annex must be present in the first input's witness (last element starting with 0x50):

    * It must include TLV types 0x01 and 0x02 (commitments list and rangeproof). The number of commitments in 0x01 must equal the number of CT outputs.
    * The range proof (0x02) must successfully verify for all those commitments (checking that each commitment encodes some value within [0, 2^52), and satisfying the blinding nonzero constraint).
    * (Optional) If TLV 0x03 (fee commitment) is present, it must equal a valid commitment to the explicit fee output's value.
    * No unknown or out-of-order TLV types (unless a future soft-fork permits them). Any TLV parsing error or inconsistency = tx invalid.
3. **Explicit Fee Output:** If CT outputs exist, exactly one OP_RETURN fee output must exist:

    * Its script must be `OP_RETURN <push 8-byte fee>` as described.
    * The fee amount in it plus the sum of output commitments must equal the sum of input commitments (see rule 4).
    * If a transaction has CT outputs but no fee output, or more than one, it is invalid.
    * The fee amount must be ≥0 (obviously) and ≤ sum of input values (no negative or overflow fee).
4. **Commitment Sum Rule (No Inflation):** Let `C_in_sum` be the sum of Pedersen commitments for all inputs, and `C_out_sum` be the sum of commitments for all outputs (excluding fee output, since fee isn't a commitment on-chain). Note:

    * For an **input**: if it was a CT output being spent, its commitment `C_in` is retrieved from the UTXO set. If it was an explicit output (non-CT), we compute a synthetic commit `C_in = v*H` (with r=0) for it.
    * For an **output**: if CT, use its commitment from TLV 0x01. If explicit (e.g. a non-CT output in same tx, though that's rare), use synthetic commit `v*H`. The fee output is treated separately (not in C_out_sum).
    * Also include the **coinbase block reward** as an "input" commitment if applicable when validating a block's coinbase? Actually, coinbase cannot have CT outputs, but coinbase input is implicit and has no commitment; instead block reward is checked via fees as usual outside CT scope.
    * The rule:
      **`C_in_sum - C_out_sum = fee * H`** (as an elliptic curve equation).
      Equivalently, `C_in_sum = C_out_sum + C_fee`. Here `C_fee = fee*H` (with r=0) is the commitment to the explicit fee.
    * In practice, the verifier will compute `C_in_sum - C_out_sum - C_fee` and require that the result equals the curve's **identity point (point at infinity)**.
    * This ensures that the sum of input values equals sum of output values plus fee. Thanks to Pedersen homomorphism, if this point equation holds, then it implies the numeric equality (since H and G are independent, the only way the sum can cancel out is if all value components cancel and all blinding components cancel).
    * This must hold for each transaction. If a single transaction fails this (even if its individual proofs are valid), it's invalid (inflation or deflation attempt detected).
    * **Coinbase special-case:** The coinbase transaction (the miner's reward collection) is not allowed to have CT outputs, so it always has explicit outputs. Therefore, its sum rule is just the existing rule (sum outputs ≤ block subsidy + fees). We additionally enforce that coinbase cannot have CT annex or commitments at all.
5. **Range Proof Verification:** The Bulletproof(s) must verify:

    * The aggregated proof must be valid for the commitments in the TLV. If verification fails, the tx is invalid.
    * Each value proved is within [0, 2^52). This inherently ensures no commitment wraps around group order or encodes a negative (since values are non-negative).
    * The proof also implicitly or explicitly shows blinder ≠ 0 for each output as discussed.
    * Soundness: Bulletproofs are proven secure under discrete log assumptions. In validation, if the proof passes, we trust that no attacker could have produced it for an invalid value without breaking crypto. (The no trusted setup property is important: anyone can verify without any secret parameters.)
6. **No Malleability in CT data:** Commitments and proofs commit to each other in ways that make them one whole. It should be infeasible to alter a commitment and adjust the proof to still pass, or vice versa. As an added safety, we treat any extraneous data or mismatches in the annex TLVs as invalid. Also, the annex (with commitments & proof) is covered by the signature hash (see next section), so a transaction's signatures commit to the CT data, preventing third-party malleation of commitments/proofs.
7. **SegWit Script Rules Inherited:** Apart from the above, SegWit v2 outputs follow the same spending rules as SegWit v1 Taproot:

    * Anyone can create a SegWit v2 output (no special scriptSig needed; it's native).
    * To spend a CT output, the unlocking script must provide either a Schnorr signature for the 32-byte pubkey (key path spend), or a script and control block satisfying the committed script tree (script path). The taproot spend rules from BIP341 apply analogously. (We essentially reuse the taproot logic: the 32-byte witness program is interpreted as an x-only public key Q; if a script path is used, Q was P+tweak and you provide P and merkle proof).
    * Execution of script happens normally (with Schnorr verify opcode etc. as in BIP342 if script path).
    * The **SigHash algorithm** differs slightly (see below), but apart from that, script evaluation and sig verification follow Taproot (Schnorr signatures as per BIP340, etc.).
    * Cleanstack, script verification, etc., all as normal for SegWit outputs.

### Signature Hash Algorithm (Sighash) for SegWit v2

CT-Exodus defines a new signature message hashing algorithm for SegWit v2 that extends the BIP341 taproot sighash to incorporate the annex and confidential value commitments. The design goals are:

* **Commit to output commitments:** Signatures should commit to the exact commitment of each output (so an attacker cannot swap out a commitment without invalidating signatures).
* **Commit to the annex data:** So that signatures also cover the range proof and any other annex data (preventing malleation of proofs after signing).
* **Follow BIP341 structure:** Reuse the efficient hashing structure of taproot, including tagged hashing and the handling of ANYONECANPAY/SINGLE flags.

We will outline the algorithm and provide pseudocode. The result of the sighash algorithm is a 32-byte hash `hash_msgs` which is then used in the Schnorr signature formula as defined in BIP340. (In BIP340 terms, `e = int(hash_msgs)` and then the signature `(r, s)` satisfies `s*G = r*G + e*P`).

**Definitions:**

We extend the tagged hash from BIP341:

* Let `tag = "TapSighash"` (same tag as BIP341) and define `hash_sha256(tag, data)` as the tagged hash (SHA256(SHA256(tag)||SHA256(tag)||data)). We reuse the taproot sighash tag to avoid introducing a new tag; this is acceptable because we are in effect just expanding the message content but it's logically the same domain (SegWit outputs).
* All values are little-endian unless noted.

**Inputs to hash:**

* Transaction data: version, locktime.
* For each input: outpoint (32-byte txid + 4-byte index), amount, scriptPubKey (only for the input being signed or for all if needed), sequence.
* For each output: if output is CT, 33-byte commitment; if output is explicit, 8-byte value. Plus the scriptPubKey of the output.
* The annex (if present).
* Sighash type flags (byte).
* We also include a single byte indicating key-path (0x00) vs script-path (0x01) spend as in BIP341, but since in CT-Exodus we only use Schnorr key-path for now, that byte will be 0x00 in all key-path signatures.

**Procedure:**

We follow the structure of BIP341's Signature Message (Appendix C of BIP341) with modifications. Pseudocode below builds the message:

```python
def CTExodus_Sighash(tx, input_index, script_path=False, extension=None, sighash_flag):
    # tx: the transaction object, 
    # input_index: the index of the input we are signing, 
    # script_path: boolean (False for key-path spend),
    # extension: in case script-path, extension = leafScript (not covered here for simplicity),
    # sighash_flag: 1 byte (e.g., 0x00=default, 0x03=SINGLE, 0x81=ANYONECANPAY|ALL, etc.)

    # Prepare hashes of various components:
    # 1. Hash of all prevouts (32*nInputs). If ANYONECANPAY not set.
    if NOT (sighash_flag & SIGHASH_ANYONECANPAY):
        buf_prevouts = b""
        for inp in tx.inputs:
            buf_prevouts += inp.outpoint.txid[::-1] + struct.pack("<I", inp.outpoint.index)
        sha_prevouts = SHA256(buf_prevouts)
    else:
        sha_prevouts = bytes(32)  # 32 bytes of 0

    # 2. Hash of all input amounts (or commitments for CT inputs) and scriptPubKeys and sequences, if not ANYONECANPAY.
    # We actually break these into separate hashes for amounts, scriptPubKeys, and sequences as in BIP341:
    if NOT (sighash_flag & SIGHASH_ANYONECANPAY):
        buf_amounts = b""
        buf_scriptPubKeys = b""
        buf_sequences = b""
        for inp in tx.inputs:
            if inp.prevout_is_CT:
                # CT input: use its 33-byte commitment from UTXO
                buf_amounts += inp.prevout_commitment  # 33 bytes
            else:
                # explicit input: use 8-byte amount
                buf_amounts += struct.pack("<Q", inp.prevout_value)
            # scriptPubKey length + script bytes (for the output being spent)
            # BIP341 covers scriptPubKey in the message to prevent fee sniping issues; we do similarly.
            buf_scriptPubKeys += varint(len(inp.prevout_scriptPubKey)) + inp.prevout_scriptPubKey
            buf_sequences += struct.pack("<I", inp.sequence)
        sha_amounts = SHA256(buf_amounts)
        sha_scriptPubKeys = SHA256(buf_scriptPubKeys)
        sha_sequences = SHA256(buf_sequences)
    else:
        # ANYONECANPAY means we'll only commit this input's data later, so set aggregates to 0
        sha_amounts = bytes(32)
        sha_scriptPubKeys = bytes(32)
        sha_sequences = bytes(32)

    # 3. Hash of outputs:
    # If SIGHASH_SINGLE and input_index < len(tx.outputs):
    #    Only include that output's data.
    # Else if SIGHASH_NONE: no outputs at all.
    # Else (ALL or default): include all outputs.
    if (sighash_flag & 0x03) == SIGHASH_ALL or sighash_flag == 0x00:  # 0x00 is DEFAULT (treated as ALL)
        buf_outputs = b""
        for out in tx.outputs:
            if out.is_CT:
                buf_outputs += out.commitment  # 33 bytes
            else:
                buf_outputs += struct.pack("<Q", out.value)  # 8 bytes
            buf_outputs += varint(len(out.scriptPubKey)) + out.scriptPubKey
        sha_outputs = SHA256(buf_outputs)
    elif (sighash_flag & 0x03) == SIGHASH_SINGLE:
        idx = input_index
        if idx < len(tx.outputs):
            out = tx.outputs[idx]
            buf_single = b""
            if out.is_CT:
                buf_single += out.commitment
            else:
                buf_single += struct.pack("<Q", out.value)
            buf_single += varint(len(out.scriptPubKey)) + out.scriptPubKey
            sha_outputs = SHA256(buf_single)
        else:
            # If SINGLE and index >= outputs count, BIP341 defines sha_outputs = SHA256(empty)
            sha_outputs = SHA256(b"")
        # (In BIP341, if index >= outputs, the signature would fail by including 0xFFFFFFFF... as hash, but here we follow their convention of empty)
    else:  # SIGHASH_NONE
        sha_outputs = SHA256(b"")

    # 4. Hash of the annex:
    annex_present = (tx.annex is not None)
    if annex_present:
        # Note: per BIP341, the annex is hashed with a prefix byte 0x50.
        # Here tx.annex includes that 0x50 already as the first byte.
        sha_annex = SHA256(tx.annex)
    else:
        sha_annex = bytes(32)

    # 5. Compute the final sighash message:
    # We'll assemble as per BIP341:
    outpoint = tx.inputs[input_index].outpoint
    input = tx.inputs[input_index]
    spend_type = b"x01" if script_path else b"x00"  # 1 byte: 0x00 for key-path (we use key-path)
    sighash_byte = bytes([sighash_flag])
    tx_version = struct.pack("<I", tx.version)
    tx_locktime = struct.pack("<I", tx.locktime)

    # If ANYONECANPAY, include only this input's data instead of global prevouts etc.
    if sighash_flag & SIGHASH_ANYONECANPAY:
        prevout_bytes = outpoint.txid[::-1] + struct.pack("<I", outpoint.index)
        if input.prevout_is_CT:
            input_amount_bytes = input.prevout_commitment
        else:
            input_amount_bytes = struct.pack("<Q", input.prevout_value)
        input_script_bytes = varint(len(input.prevout_scriptPubKey)) + input.prevout_scriptPubKey
        input_sequence_bytes = struct.pack("<I", input.sequence)
    else:
        prevout_bytes = b""  # not needed since already covered in sha_prevouts etc.
        input_amount_bytes = b""
        input_script_bytes = b""
        input_sequence_bytes = b""

    # Build the message preimage:
    preimage = b"".join([
        spend_type,
        sighash_byte,
        tx_version,
        tx_locktime,
        sha_prevouts,
        sha_amounts,
        sha_scriptPubKeys,
        sha_sequences,
        sha_outputs,
        sha_annex,
        prevout_bytes,
        input_amount_bytes,
        input_script_bytes,
        input_sequence_bytes
    ])
    # Note: The ordering above is such that for ANYONECANPAY, the specific input's fields are appended at the end as per BIP341.

    # Finally, tagged hash it:
    sighash = HASH_SHA256("TapSighash", preimage)
    return sighash
```

The above pseudocode is verbose but essentially extends BIP341's logic:

* We include `sha_prevouts`, `sha_amounts`, `sha_scriptPubKeys`, `sha_sequences`, just like BIP341. For CT, the **sha_amounts** actually is a hash of commitments (33 bytes each) for CT inputs or 8-byte values for explicit inputs. This ensures signatures commit to the exact input amounts (in committed form) being spent.
* We include `sha_outputs` or `sha_single` which covers output commitments or values and scripts. This ensures signatures commit to outputs including their confidential amounts.
* We include `sha_annex` to commit the entire annex TLV data (if present). BIP341 covers annex similarly (it sets sha_annex=SHA256(a) or zero) but since BIP341 did not use annex in practice, we explicitly rely on it here. By committing to the annex, any change to commitments or range proofs (which live in the annex) will invalidate signatures.
* The ANYONECANPAY and SINGLE flag behavior is mirrored from BIP341: ANYONECANPAY = only this input's outpoint+amount+script+sequence are signed (others are not committed to, enabling adding inputs later), SINGLE = only the corresponding output is signed (others can be changed by someone else). These allow flexible signing policies as before.
* Notably, in the `sha_outputs` construction:

    * If an output is CT, we hash its 33-byte commitment instead of an 8-byte value.
    * If explicit, 8-byte value as usual.
    * The scriptPubKey is hashed as usual.
* The fee output (OP_RETURN) is an output in the tx as well. If sighash covers all outputs, it will include the fee output's 8-byte zero value and its script (which starts with OP_RETURN). This means signatures *do* commit to the fee output's presence and the fee amount encoded in it. This is intentional: nobody should be able to tamper with the declared fee after signing. (In practice, fee output's script and amount are fixed by the transaction creator anyway.)
* Because the fee output's amount is always zero in the tx structure, including it doesn't directly reveal the fee to signers; however, signers obviously know the fee from context and they see it placed in the OP_RETURN output data, which is part of the script they sign.

**Default Sighash:** As in BIP341, if the sighash byte is omitted in a signature, it implies SIGHASH_DEFAULT (which we treat as ALL). In CT-Exodus, we follow the same convention:

* SIGHASH_DEFAULT (0x00) = sign all inputs and outputs (like ALL) and do not commit to explicit sighash byte in the message (because it's default).
* If any other sighash than 0x00 is used, the signer appends that byte to the signature.

**Security Note:** By committing to all these components, CT-Exodus signatures ensure that a transaction cannot be meaningfully altered (no outputs, amounts, or CT data can be changed) without invalidating signatures, except in ways allowed by sighash flags. For example, a signature with ANYONECANPAY doesn't cover other inputs, so another party could add an input – but that's expected functionality. Importantly, since CT eliminates amount-based heuristic attacks, the sighash behavior doesn't introduce new issues – it closely parallels Bitcoin's existing logic.

### Address Format (Bech32m "bcx")

To encode the new SegWit v2 outputs for user addresses, we use a **Bech32m address** with a distinct Human-Readable Part (HRP). The address encoding follows BIP-173/BIP-350 rules. Key points:

* **Mainnet HRP:** `"bcx"` (resulting addresses begin with "`bcx1`").
* **Testnet HRP:** `"tbx"` (addresses begin with "`tbx1`").
* We choose a new prefix (`bcx`) instead of reusing `bc` with a version byte, to clearly signal that this is a different kind of output. This avoids any potential confusion or accidental misuse by older wallets. Only wallets updated for CT-Exodus will recognize `bcx`/`tbx` addresses.
* The **witness version** encoded is 2 (for segwit v2), and the **witness program** is 32 bytes (as the scriptPubKey pushes 32 bytes).
* **Encoding:** We use **Bech32m** checksum as mandated by BIP-350 for segwit version ≥1 outputs. The data part of the address encodes: a 5-bit value of 2 (the witness version), followed by the 32-byte witness program converted to 5-bit groups, plus the Bech32m checksum.
* Example mainnet CT address:

    * Suppose we have a CT output controlled by a public key with x-coordinate `0x79BE667EF...F81798` (this is just an example, possibly using the base point's x for demonstration). The Bech32m encoding of this (witness v2 + that program) might look like:
      **`bcx1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqvzw607`**
      (This decodes to witness version 2, program = `79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`, which indeed is 32 bytes.)
    * Testnet example with the same 32-byte program:
      **`tbx1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqsv7g5g`**
      (Notice the `tbx1` prefix.)
* The prefix `"bcx"` was chosen to be visually distinct. It is still 3 characters, which is within Bech32 HRP rules. It ensures no existing wallet (which expects `bc1` or `tb1`) will mistakenly parse it. It effectively opts such addresses out of old wallet usage.
* **Address validation:** Bech32m provides strong checksum protection. For instance, if a user were to typo a CT address or if one character is altered, the checksum will (with extremely high probability) not match, and the address will be marked invalid by software. For example, take the above address and change one character:
  Original: `bcx1...zw607` (valid)
  Altered:  `bcx1...zw607` (with one character changed) – this will fail checksum and be rejected.
  We include concrete examples in test vectors below. This checksum ensures that funds are not sent to mistyped addresses and that `bcx` addresses cannot be confused with any other format.
* **Malformed address detection:** All normal Bech32 encodings rules apply: e.g., no mixed case (addresses are lowercase only), valid character set (`qpzry9x8gf2tvdw0s3jn54khce6mua7l`), and proper length of data (the witness program must be 32 bytes – any other length for version 2 will be invalid). Wallets implementing CT-Exodus should use existing Bech32 libraries updated for Bech32m (BIP350) to encode/decode, simply substituting the HRP and using witness version 2. Test vectors will show examples of valid and invalid addresses.

Importantly, CT-Exodus addresses reveal **no information about the amount** (just like any Bitcoin address, which never contained amount). They also do not reveal any extra info beyond what a taproot address reveals: the prefix `bcx` indicates it's a CT output; the data represents either a key or a script hash. The blinding factor and actual value are never part of the address – they are chosen by the sender at transaction creation time. The receiver's wallet, when generating a CT address, typically does so by providing a public key and perhaps expecting the sender to use an ECDH protocol to derive blinding (as Liquid does). This is outside the scope of consensus, but wallets should follow a scheme (detailed in Wallet Recommendations below) to ensure the receiver can later unblind the output.

## Rationale

This section discusses why certain design choices were made, addressing alternatives and their trade-offs:

**1. SegWit v2 vs Alternatives:** We chose to implement CT as a new Segregated Witness version output. An alternative could have been an "anyone-can-spend with magic OPcodes" or an **extension block** approach. Using SegWit v2 has several advantages:

* It cleanly segregates new validation logic (witness) from old (inputs/outputs), ensuring a soft-fork that won't break older clients. Outputs are anyone-can-spend under old rules, so the soft fork logic is simply that new nodes refuse to spend them unless CT conditions are met.
* We can reuse a lot of the Taproot infrastructure (Schnorr signatures, script commitments, etc.), rather than reinventing a locking mechanism. CT-Exodus outputs behave like Taproot outputs in terms of spending, which simplifies implementation.
* Using an extension block or separate commitment could have been more complex and less elegant (requiring new block structures or separate merkle trees). By piggybacking on SegWit, we keep changes localized to transactions and witness data.

**2. Value Commitment Encoding (33 bytes with 0x08/0x09 prefix):** Elements/Liquid uses a similar encoding where a prefix byte indicates explicit vs confidential values (0x01 for explicit with 8 bytes, 0x08/0x09 for commitments). We adopted 0x08/0x09 for commitments to ensure they are distinguishable from normal pubkeys (0x02/0x03) and from explicit value bytes. This way, if someone were to mistakenly interpret a commitment as a public key, it would clearly be invalid (and wouldn't pass key checks). Also, the prefix encodes the parity of Y, which is needed for unique serialization. The cost is one extra byte, but it's negligible and in line with standard compressed point encoding. Explicit outputs remain 8 bytes in the tx, and we don't encode them in 33 bytes on-chain to avoid bloat; they are only conceptually treated as commitments when summing.

**3. Single Aggregated Bulletproof vs Per-Output Proofs:** We mandate one Bulletproof proof for all outputs in a transaction (rather than a separate proof for each output). This significantly reduces space: bulletproofs support aggregation with small overhead. For example, 2 outputs can share one proof only ~60 bytes larger than a single-output proof, instead of two separate ~674-byte proofs. Verification cost is slightly higher for an aggregated proof than a single, but verifying one aggregated proof is still *far* faster than verifying multiple older rangeproofs (and can be batch-verified across transactions as noted). The slight downside is complexity: implementers need to handle aggregation. However, the libsecp256k1 module we plan for integration will take care of verifying an aggregated proof just as easily as a single. Aggregation also improves privacy: if multiple outputs are in one proof, an observer cannot even individually distinguish their values (beyond sum constraints) – though amounts are hidden anyway, aggregation ensures no per-output proof metadata is available.

**4. Annex TLV and 3 WU/byte weight:** We introduced an annex TLV structure so that adding CT did not require redefining the base transaction format or stealing bits from other fields. BIP341 had foreseen annex usage for future upgrades; we use that mechanism. The TLV design makes it easy to extend in future:

* For example, if confidential *assets* (like in Elements) were ever considered for Bitcoin, a TLV type could carry asset commitments and asset rangeproofs without a redesign.
* The annex is committed in the sighash, so it's safe from malleation and can carry critical data.
* Weight: We chose to make annex bytes count for 3 WU to ensure that range proof data, which can be large, isn't nearly free (1 WU) which could encourage oversized proofs or spam. At 3 WU, it's 0.75 bytes weight per byte of proof – a slight discount vs base (which is 1 byte = 4 WU). This acknowledges that witness data is less harmful than UTXO bloat (since witness isn't stored in UTXO set) but still incurs propagation and block verification costs. Our choice of "3" is a policy that could be adjusted in future if needed, but it strikes a balance. (For context: an average CT tx with 2 outputs might have ~750 bytes of proof. At 1 WU each, that'd be only 750 WU ~ 188 vbytes, quite cheap. At 4 WU, it'd be 3000 WU ~ 750 vbytes. We pick 3 WU → 2250 WU ~ 562 vbytes, a moderate cost.)

**5. Bech32m Address Prefix ("bcx"):** We deliberately did not reuse the "bc1" prefix for segwit addresses. Why? Backwards compatibility and safety. Many old wallets and exchanges have bech32 address libraries that might accept "bc1q…" or "bc1p…" (for v0 and v1), but would reject unknown versions. Technically, BIP350's rule is to use bech32m with same hrp "bc" for v1+, so we *could* have had addresses like "bc1z…" (since v2 might encode to a data starting with letter z). However, to avoid any ambiguity or chance of mistaken identity, and to give a clear visual cue, we went with a new hrp "bcx". This ensures:

* No old wallet will ever confuse a CT address as a known address (since hrp "bcx" will make their parser fail early if not updated).
* Users can immediately tell it's a "new type of address" because it doesn't start with bc1. This might reduce the risk of sending from an unsupported service.
  The downside is that wallets must explicitly add support for "bcx". But since any wallet dealing with CT must update code anyway (to handle commitments, proofs, etc.), adding a new hrp is trivial. This approach mirrors how Liquid uses "ex" or "lq" prefixes for its addresses to differentiate from Bitcoin.

**6. Fee Explicitness (Coinbase Ban & Fee Output):** We absolutely require fees to be explicit, rather than try to hide them. Hiding fees (e.g., having miners derive fee as difference of sums) is problematic because if amounts are confidential, an observer/miner wouldn't know how much fee they are entitled to claim, and it complicates supply auditing. By making fees explicit outputs:

* Miners know exactly how much fee to claim in the coinbase (and we enforce they do not create CT outputs in coinbase, so coinbase outputs remain public).
* It preserves full supply audit: all new coins from subsidy are explicit; all fees are explicitly accounted (even though fees could be inferred by sum difference, we cannot trust inference when values hidden, thus we explicitly encode it).
* Additionally, having the fee in an OP_RETURN output actually slightly helps privacy for regular users: it decouples the fee from any change output value. In Bitcoin today, one can sometimes deduce which output is change by subtracting known payments from inputs and seeing the remainder as change+fee. With CT, since fee is separate, the link between change and fee is broken – fee is its own output.
* Coinbase ban on CT outputs: by not allowing a miner to directly produce a CT output in the coinbase tx, we eliminate any scenario where inflation could be snuck in there. (Imagine if coinbase had a CT output with a bad proof or large value – that could inflate supply without detection by old nodes. We forbid it entirely; coinbase must only make explicit outputs.)

**7. Blinding Factor non-zero (r ≠ 0):** This might seem an edge-case, but we included it for completeness. If r were 0, a commitment is `C = v*H`. While still hiding v (since H's discrete log relative to G is unknown), some argue it's less secure because if someone ever found a relationship or if H was not perfectly secure, those outputs might be weaker. Also, r=0 outputs have the special property that their commitment adds no randomness; if two outputs had the same value v and both had r=0, their commitments would be identical points (`v*H` each) – which is a linkage. Enforcing r ≠ 0 (and ideally, wallets always picking random 256-bit r) means the chance of two identical commits is cryptographically negligible. Thus, we preserve **output uniqueness** (no two CT outputs should have the same commitment unless they intentionally both used same r and v, which we disallow to avoid confusion). We implement this via the Bulletproof constraint as discussed. Liquid does not explicitly enforce r≠0 to our knowledge (it relies on wallets), but we choose to enforce it in consensus to be safe.

**8. Sighash design:** We reused Taproot's sighash because it was already designed to cover most things (input amounts, etc.). We extended it to commitments fairly straightforwardly:

* Why include scriptPubKeys in the hash? BIP341 did so to cover the scriptPubKey of the UTXOs being spent (to mitigate certain attacks involving reusing inputs in different contexts). We carry that over; it also conveniently means the signature commits to whether an input was segwit v2 or not (since scriptPubKey contains OP_2 vs something else).
* Committing to the annex in sighash is important because the annex now contains critical data. BIP341 already includes annex (there's an annex hash in the formula), so we just follow that – any annex changes will change the sighash.
* The pseudocode we gave ensures ANYONECANPAY and SINGLE work similarly to before. This means e.g. if a hardware wallet wants to only sign its one input and one output (in a coinjoin scenario), it can do ANYONECANPAY|SINGLE and the signature won't cover other participants' parts (just like today). We needed to be careful to still cover that input's own commitment, which we do via including its commitment in the per-input portion when ANYONECANPAY.
* A potential alternative was to define an entirely new sighash tag (like "CtExodusSigHash") to avoid any confusion with taproot's domain. We decided to reuse "TapSighash" for simplicity and because it doesn't introduce a security issue; the contents we hash are different (since we have commitments, etc.), but that's fine – the domain separation tag is just to separate from other hashing contexts (like if someone tried to sign something not a tx).
* This means BIP341 verifiers won't validate CT sighashes unless updated, but that's expected (old wallets can't sign CT anyway).

**9. Annex TLV vs putting proofs in scriptSig or witness stack directly:** One might ask, why not just put the commitment and proof as extra witness stack items (like Felix's earlier proposal had a "witnessOut" section). The reason is that Bitcoin's transaction and scripting model doesn't natively have a notion of "witness for outputs" – witness is tied to inputs. We could attach the CT data to an input (like input 0) as done. The annex is the cleanest mechanism because it's specifically designed to carry extra data that is not part of script execution. We didn't want to hack it into an input's scriptSig because that would affect legacy txid (and break segwit's design). We also didn't want to put it in output scripts (we considered encoding the commitment in the scriptPubKey itself, e.g., P2WSH-like approach, but that would blow up the UTXO size and wasn't flexible enough to include a range proof). The annex, albeit an unused feature till now, turned out to be the perfect place:

* Doesn't affect txid (witness data).
* Doesn't get stored in UTXO (witness not stored).
* Is committed in wtxid and sighash properly to prevent malleation.
* Allows arbitrary size.

**10. Commitment Sum (soundness):** The rule `sum(inputs) = sum(outputs)+fee` is fundamental. We considered whether to explicitly require each transaction to have at least one explicit value (like fee or an explicit change) to "anchor" the sum. In Elements, they require an explicit fee output specifically for this reason, which we mirror. One could imagine a design where even fees are hidden and miners reveal something in coinbase – but that complicates incentives and risk inflation if miner cooperation is needed to detect it. So we keep one foot in the transparent world (the fee) to have a solid reference point for each tx's balance. This way, verifying no inflation is straightforward: after validating proofs, just compute point sum and compare to fee*H.

**11. Coinbase CT ban:** Worth reiterating, banning CT in coinbase is a conservative choice to protect the supply. If a miner attempted to create a CT output in coinbase and somehow hid extra value in it via a malformed proof, old nodes would 1) not be able to check it and 2) see less fee than expected (since they'd think that extra is burnt, but actually miner could reclaim it later by spending that output if they also could bypass new rules). By banning it, we avoid any possible shenanigans at issuance. Also, coinbase transactions are often unique in consensus (e.g., no prevout, can't be malleated anyway) – adding CT there would complicate mining software for little benefit. Miners don't need privacy for coinbase outputs typically.

**12. Wallet Privacy (Change output policy):** Although not a consensus rule, an important design rationale is **how wallets should use CT to maximize privacy**:

* It's recommended that when sending a payment with CT, the wallet **uses CT for the change output as well**, rather than making a transparent change. If you made a transparent change output, observers would see "input commitments, one CT payment output, and one explicit change" – they could subtract and figure out the payment amount by difference (since input sum and change are known, the remainder is payment). By making change also CT, outsiders only know total input vs total outputs (which must equal, minus fee) but cannot split the amounts between the two CT outputs. This essentially yields **amount indistinguishability** between the payment and change.
* We anticipate most transactions using CT will exclusively use CT outputs (plus the fee output). A purely CT tx with 2 outputs is similar to how coinjoin obfuscates linkability – except here even the amounts are unknown. This vastly improves privacy; not only are addresses pseudonymous, but the amounts don't give away which output is likely change.
* Another policy: wallets could randomize number of outputs or merge multiple payments to further confuse observers (though amount privacy is already high, traffic analysis can still note number of outputs).
* We don't enforce these as rules, but we mention them so that wallet implementers and users understand best practices. The References section and wallet guidelines (below) provide more detail.

**13. Libsecp256k1 Integration (Reference Implementation):** We plan to implement the Bulletproof verification inside Bitcoin Core's secp256k1 library (perhaps in the `secp256k1_zkp` branch which Blockstream maintains for Elements). This is rational because:

* The math is complex and easy to get wrong; a shared library implementation ensures everyone verifies identically (consensus safety).
* The secp library can be optimized (e.g., using endomorphism, multi-exponentiation techniques) for bulletproofs. Blockstream's implementation of Bulletproofs in C (as used in Liquid) can verify a range proof in a few milliseconds, which is acceptable. Batch verifying 100 proofs might yield further speedups.
* By integrating at the library level, we avoid duplicating code in many places. Also, it allows us to batch verify multiple bulletproofs in one go, which is nice for block validation.
* The reference implementation includes test vectors and cross-compatibility with Elements. We ensure that our proof format is identical to Liquid's (which is a standard Bulletproof encoding). So existing libraries that create/verify Liquid range proofs can be adapted.

In summary, the choices made aim to maximize privacy and security while minimizing impact on existing systems. We've largely followed established precedents (Elements CT for commitments/fees, BIP341 for addresses and sighash, Bulletproofs from academic research) rather than inventing wholly new cryptography. This conservative approach should ease review and improve confidence in the proposal.

## Backward Compatibility

CT-Exodus is a **soft fork** – meaning old nodes (that haven't upgraded) will continue to see blocks as valid (unless miners produce invalid CT data, which old nodes can't detect and would unknowingly accept – but miners have no incentive to do that as upgraded nodes would reject the block). Here we detail compatibility:

* **Old Nodes' View:** An old (pre-CT) node does not understand SegWit v2 outputs. According to existing rules, any output script that is `OP_n` with n>1 and some data is considered an unknown witness version output. BIP141 specified that unknown witness versions are considered anyone-can-spend in terms of *consensus* (they have no mandatory script checks) – specifically, "scripts with an unknown witness version are valid if spent" (because legacy nodes treat them as anyone-can-spend since they don't know the new rules). Thus, an old node will think:

    * A CT output (OP_2 <32-byte>) imposes no spend conditions (anyone could spend it) and has value 0 (since amount field is 0).
    * So, from its perspective, that output is basically a no-op or burnt output. The input that funded it appears to have all its value go to fees.
    * Old nodes will still enforce that the sum of (explicit) input values ≥ sum of (explicit) output values. In a CT tx, explicit outputs include only the fee (which is 0-valued in script but fee is actually in coinbase) and maybe any non-CT outputs if present. As long as input explicit values cover any explicit outputs, the old node is satisfied. In practice, CT transactions will have explicit outputs only as either none or the fee output (0 value). So old nodes see input value (explicit) and zero outputs, thus assuming all input value became fee. This doesn't violate any rule – miners are allowed to "burn" fees by not claiming them entirely.
    * When that CT output is later spent, the old node sees an input referencing an output that to it looked anyone-can-spend and 0-valued. Typically, it would think "why even include this input? it has no value." But it doesn't mark it invalid; it's just an input spending a zero amount output. There's no rule forbidding that (it's just weird but valid to spend an output of 0 sats).
    * Therefore, old nodes will allow spends of CT outputs (they think it's a 0-sat anyone-can-spend, so providing an empty scriptSig and some witness doesn't matter to them, it's automatically valid as long as the signature doesn't need to be checked by them – which it doesn't, since unknown witness version).
    * However, one nuance: to relay transactions, old nodes apply standardness. Unknown witness v2 might be non-standard and not relayed by old mempools. That's fine: we expect that until adoption, CT transactions likely need to be mined via upgraded nodes directly or through miner collaboration. This is similar to how segwit was initially (some nodes didn't relay segwit spends, but miners mined them). Post-activation, this is moot because majority will upgrade.
* **No base consensus break:** Because outputs are 0-valued as far as legacy nodes see, no inflation is visible. If an invalid CT transaction tried to create extra coins, an old node couldn't detect it (since they ignore commitments). But they would still see outputs sum <= inputs (since the extra coins would be hidden in commitments and explicitly the outputs sum is smaller). So old node stays happy, albeit fooled. New nodes catch it and reject the block. Thus, such inflation cannot get confirmed by honest miners (who run new nodes), and if a majority is honest, it won't stay in chain. This is the usual soft-fork security assumption.
* **Wallet behavior:** Legacy wallets will not recognize addresses starting with `bcx1`. If a user tries to input a CT address into an old wallet, it will likely error ("invalid address"). That's good – we don't want old wallets unknowingly sending to CT outputs they can't handle. Only updated wallets will accept `bcx...`. The same was true for taproot (`bc1p`).
* **Interoperability:** CT outputs are a new type; they don't affect existing output types. You can still have P2PKH, P2WPKH, P2TR outputs in the same transaction (though for privacy we don't recommend mixing). There is no change to how those work. Only when a CT output is present do the new rules come in, and they only govern that CT output and the global sums.
* **PSBT and hardware wallets:** Partially Signed Bitcoin Transactions (BIP174) will need minor extensions to handle CT:

    * New fields to convey commitments and rangeproofs for unsigned transactions.
    * When a PSBT is constructed for a CT tx, it must include the commitments for outputs so signers can compute the sighash. We likely introduce e.g. a PSBT Output field for "value commitment" (33 bytes) and maybe "rangeproof" for completeness (though signers don't need to verify rangeproof to sign, they might want to).
    * We will propose an update to PSBT in a separate document, adding types like `PSBT_OUT_CT_COMMITMENT`, `PSBT_OUT_CT_PROOF`, etc.
    * Hardware wallets: if they support CT, they will need to be able to do point addition (to sum commitments for sighash perhaps) and hash as specified. The heavy lifting (rangeproof verify) need not be done on hardware – a hardware signer can trust the host to only send valid commitments? Ideally they should verify the proof or at least that commitments sum out correctly to avoid signing an inflation tx (which could dilute the user's funds). We anticipate hardware wallets might initially not support CT at all (just like many didn't support taproot right away). It's an optional feature for users.
* **Non-upgraded miners:** If a miner doesn't upgrade, they could include an invalid CT transaction (with a bad rangeproof or inflated value) in a block, thinking it's valid (since their node accepted it). That block will be rejected by upgraded nodes. This scenario is the usual "miner with old software during soft fork" risk. To protect, we will likely use a BIP9/8 style deployment with a flag day or lock-in such that by activation, most miners are aware. Even if not, the economic majority enforcing the rules will orphan such blocks, teaching miners quickly. The incentive is for miners to run validation on all new rules to avoid wasting effort.
* **Non-upgraded Lightning/second-layer:** Systems like Lightning, watchtowers, etc., that parse transactions might need updates. For example, a pre-CT Lightning node might not understand `bcx` addresses or might fail to parse a commitment in an output. But generally, Lightning uses its own scripts (not CT), so it might just ignore CT outputs. One potential issue: Lightning penalty transactions or justice transactions have to sweep outputs. If someone tried to make a Lightning HTLC output a CT output (which isn't possible in current protocol, as Lightning amounts must be explicit to enforce HTLC amounts), it would break LN's assumptions. But LN won't do that; LN will use CT perhaps by running on a sidechain or wait for update. There might be efforts in future to allow LN channels with CT (to hide channel balances on-chain), but that's beyond current scope and would require update of LN protocol.

**Overall**, old nodes remain functional. They will just not see the real values. This is analogous to how old nodes handled segwit (they saw anyone-can-spend scripts but relied on miners to enforce the new rules). As long as a supermajority enforces CT rules, the system is secure. Users should upgrade to fully validate CT, otherwise they trust miners not to slip in a bad CT tx (similar to any soft fork).

## Reference Implementation

A reference implementation of CT-Exodus would involve changes to multiple components of Bitcoin Core (or any full node software):

**Consensus Engine (validation)**:

* **Transaction validation:** Add checks for outputs with scriptPubKey of form `OP_2 <32-byte>`. Enforce amount=0 and presence of CT data (annex, proofs, etc.). For each block, for each such tx, perform:

    1. Verify TLV structure in the annex (types 0x01,0x02 present, etc.).
    2. Use secp256k1 library calls to verify the Bulletproof range proof for the given commitments. This would likely be an interface like `secp256k1_bulletproof_verify(proof, commitments[], n_commits, value_range_bits=52, generatorH)` which returns true/false. The lib will manage the heavy math.
    3. Accumulate the sum of input and output commitments (convert explicit to v*H commitments on the fly using scalar multiplication).
    4. Check the sum difference equals fee*H. This involves computing a point and checking it's the identity. We can use secp256k1's multi-exponentiation: e.g., library could provide `secp256k1_pedersen_commit_sum(commit_in[], commit_out[], commit_fee) -> bool` that internally does: sum(commits_in) - sum(commits_out) - commit_fee == Infinity.

        * Actually, libsecp256k1-zkp already has functions like `secp256k1_pedersen_commit` and `secp256k1_pedersen_sum`. In Elements, they subtract commitments and check if result is identity as part of verifying no inflation.
    5. Also verify no two CT outputs have identical commitment (optional, but might be worth to avoid weird edge cases; though if rangeproofs are valid and r≠0, identical commits would imply same v and r difference or solving discrete log so it likely can't happen except trivial v=0 r=0 which we disallow).
* **Coinbase rule:** In block validation, if coinbase tx has an output with OP_2, reject block.
* **Weight calculation:** Modify block weight calculation to incorporate annex 3 WU/byte. This can be done by after parsing a tx, if it has annex of length L, add `2*L` extra weight (since if it were witness at 1 WU, making it 3 WU means +2 per byte).
* **SigHash:** Implement new sighash for segwit v2. Likely integrate into `SignatureHash()` function or new function. The pseudocode given can guide actual code. Use tagged hashing (likely using core's built-in SHA256 and tags).
* **Script interpreter:** Needs to recognize witness version 2:

    * When spending an output with version byte 0x02 in scriptPubKey, enforce the new rules: i.e., if an input's prevout is v2, then scriptSig must be empty (as per segwit), and execution uses tapscript style (though if only key path, then just verify Schnorr sig).
    * Actually, BIP341 had a rule to only apply taproot rules if version=1 and exactly 32-byte program. We will analogously apply CT rules if version=2 and 32-byte program. Otherwise, a version 2 with wrong length is treated as anyone-can-spend (unencumbered) as per segwit general rules (which is fine – if someone made an odd length v2 script, it's not a CT output, just a weird unknown output with no spend rules).
    * For key path: verify Schnorr signature over message with our new sighash. We reuse BIP340 code (which verifies 64-byte sig).
    * For script path: If one wanted to allow scripts (though CT can allow scripts, we haven't heavily discussed, but since we have the infrastructure, we should implement it), then script path spend: the input's witness stack will have: `<witness_stack> <annex_if_any> <script>` possibly. Actually, careful: if script path is used, then the last element could be annex or control block? BIP341 says if last element starts with 0x50 it's annex, else if second last is control block, etc. We'd follow the same:

        * Remove annex if present.
        * Then the last element is control block (starts with 0xC0 or something for taproot leaf version).
        * The second last is the script.
        * Others are args.
        * Then execute as tapscript, using OP_SUCCESS etc rules from BIP342 (we inherit all those improvements).
    * Essentially, implement taproot scripts for segwit v2 as well (maybe identical to v1's behavior), unless we explicitly disable script path. But no reason to disable – it could be useful (e.g., you can make a CT output with a timelocked recovery script, etc.).
    * So the interpreter changes minimal: just extend the taproot spend code to version2 in parallel, using same logic.
* **Mempool policy:** Initially, mempool could have a policy to only allow CT tx if a certain flag or after activation. Possibly limit size of proofs (to prevent 100kB proofs if someone tried something funky, though the range and aggregation somewhat bound it). We might say any CT tx must prove at most 2^52 range; if an output value is larger than 21e6 BTC, it's nonsensical. Also we might limit number of outputs per proof for mempool (like if someone made a 100-output CT tx, that's a big proof ~ maybe 1.5KB, which is okay but maybe fine).

    * We likely also require `r!=0` in mempool as we do in consensus, but wallets should do that anyway.
    * Weighting in mempool should also consider annex at 3WU; i.e., use the weight formula consistent with block.
* **Logging and error codes:** Add descriptive error for "Bad-CT-rangeproof" or "Bad-CT-commit-sum" if fails, to aid debugging.

**libsecp256k1-zkp (crypto library)**:

* We will extend or reuse Blockstream's `secp256k1_zkp` library which already has:

    * `secp256k1_pedersen_commit(ctx, commit, blind32, value, gen)` – to create commitments (for testing, wallet).
    * `secp256k1_pedersen_verify_tally(ctx, commits_in, commits_out, n_in, n_out)` – this checks sum of ins vs outs (we'll use that for sum rule).
    * `secp256k1_rangeproof_verify` – Liquid originally used Borromean rangeproof, but they moved to Bulletproofs. They have a module secp256k1_rangeproof and secp256k1_bulletproof. We'll specifically use bulletproof functions:

        * `secp256k1_bulletproof_rangeproof_verify(ctx, proof, len, commit[], n_commits, 64, gen, scratch)` – for example, to verify a proof that commits are 64-bit (we use 52 bits effectively, but proof is usually set up for 64).
        * The lib likely has an API for multi-proof verification in batch. We can use scratch space for optimization.
    * We'll integrate the generator H by using `secp256k1_generator` type (Elements defines generators for each asset; here we just have one generator H for BTC asset).
    * The bulletproof verification returns true/false. If false, mark tx invalid.

* **Batch verification optimization:** If a block has many CT outputs/proofs, verifying each separately can be optimized by batch verifying multiple bulletproofs. We can, in the future, extend secp256k1 to support aggregating across tx (similar to batch Schnorr verification). But initial implementation can just verify individually; it's already quite fast: ~5-8 ms per proof for 2 outputs on a modern CPU. Even 200 CT outputs (which is huge for a block) would be ~1 second of verification, acceptable relative to block interval.

**Wallet (reference, for testing)**:

* The reference implementation for wallet would need to:

    * Be able to **unblind** outputs: That is, when a wallet receives a CT output, how do they get `v` and `r`? The design (borrowed from Liquid) typically:

        * The sender and receiver perform ECDH: the receiver has a **blinding public key** (could be derived from their main private key or an independent one). The sender picks an ephemeral secret key, multiplies by receiver's blinding pubkey to get a shared secret, from which they derive a 32-byte mask and maybe an encryption key. They then use that mask to compute the output's blinding factor or to encrypt the value. Liquid, for example, **encrypts the amount** with that shared secret (so the receiver can decrypt how much was sent to them). But since we have range proofs, the receiver could also find out by trial… but better to explicitly communicate it.
        * We will likely adopt the same scheme: The TLV or somewhere (Elements uses the "nonce" field in outputs, which we omitted in on-chain format here) can carry an encrypted  confidential value. However, we did not include an encrypted memo or value in this BIP to keep things minimal, relying on the receiver to decrypt from range proof maybe. In practice, implementing output value decryption is highly useful. We could slip in an **additional TLV type**: e.g., Type 0x04 "Encrypted Amount" containing the value encrypted with shared secret. But the range proof already proves it, this is just to reveal it to receiver easily.
        * Possibly, we assume wallets will use the fact they know r and can derive v by computing `(C - r*G)` and solving for v given they know r's discrete log. But they can't directly get v from that because H's discrete log is unknown. So no, they *must* get v by other means (either store it or have it communicated). Liquid solves by encrypting value.
        * Given the complexity, we plan to incorporate the **same approach as Liquid**: when a wallet makes a CT address, it includes in it (maybe encoded in the 32-byte program somehow) a point to allow ECDH. Liquid's confidential address actually includes an extra pubkey (blinding key) in addition to the script pubkey. We did not explicitly define that in our address format, which is an oversight if we want full wallet interoperability. Possibly the wallet's "blinding key" could be the same as the internal key or derived from it (if internal key's private is known by receiver, they could derive blinding factor with some tweak).
        * One idea: Let the receiver's internal key = `P`. The sender picks ephemeral key `e`. They do ECDH: `P*e = shared_point`. From that, derive `r` and maybe a key to encrypt `v`. The receiver, knowing `p` (privkey for P), does `e*P = shared_point` too. They get same secret, derive `r` and decrypt value. This way, no extra blinding pubkey is needed; we reuse the control key P for blinding purposes. However, one must be careful: using the same key for spending and blinding could have subtle issues (if someone else learns `r`, they could maybe correlate with your pubkey? Should be fine since r is secret).
        * This approach would require standardizing how to derive r and how to encrypt v. Possibly:

            * `shared_secret = SHA256(e * P)` (32 bytes).
            * Let `r = SHA256(shared_secret || "blinding") mod n`.
            * Let `encrypt_key = SHA256(shared_secret || "encrypt")`.
            * Encrypt value v (8 bytes) with say ChaCha20 or XOR with that key (taking first 8 bytes of key). Or use a simple Xor pad from shared secret.
        * The sender then uses r and v to construct C and the proof, and also in the annex could include an **encrypted value record**:

            * Type 0x04: Encrypted Value, length 8 bytes, payload = v XOR first_8_bytes_of_encrypt_key.
            * Receiver can recompute key and get v. If wrong (e.g., if not their address), it'd decrypt to nonsense likely and proof wouldn't match either.
        * Alternatively, we skip explicit encryption in on-chain data, because maybe the wallet can just brute force v? But v can be up to ~2e15, brute forcing that is not feasible. So encryption seems needed for UX.
        * For now, since it's a deep research spec, we mention that wallet protocols will handle blinding key exchange (which can be standardized separately).
    * Implementation wise, the reference could include a tool to generate a CT address given a wallet key, and a function to unblind a received output given the recipient's private key and the output's ephemeral pubkey (which could be recovered from the commitment or provided by sender out-of-band).
    * We won't delve further due to scope, but note that in Liquid, each transaction output had a 33-byte "nonce commitment" which was essentially the ephemeral pubkey R = e*G or e*something. They put that in the output. We did not explicitly include a "nonce" field in our tx format to store ephemeral R. Perhaps the 32-byte witness program can double as that? That 32 bytes in scriptPubKey currently is receiver's key or script commit, not the ephemeral from sender. So no, we lack a field for ephemeral pubkey unless we add a TLV for it.

        * Possibly, the sender could derive ephemeral pubkey = r*G - but r is secret and belongs partly to output, can't reveal it or breaks hiding. Actually, in Elements, the "nonce" is defined as `R = H * r` (blinding pubkey * blinding factor)? Or R = e*G where e is ephemeral secret and also used in shared secret. I think R = e*G, the ephemeral public used for ECDH.
        * We could add TLV type 0x04: "Nonce" – 33 bytes ephemeral pubkey from sender. Then receiver does ECDH with their priv and that pub to get secret. This is exactly how Elements does (they call it nonce commitment).
        * If the ephemeral is not given, the receiver can't do ECDH unless ephemeral was derivable somehow. So yes, we likely should include ephemeral pubkey in the annex:

            * Type 0x04: Nonce (Ephemeral ECDH point), 33 bytes (0x02/03 prefix).
            * Actually, if multiple outputs, each might have its own ephemeral? In Liquid, each output had a separate R. We might likewise need one per output so that different recipients have different shared secrets.
            * That suggests TLV 0x04 could hold a concatenation of m 33-byte nonce points for m outputs. But to keep TLV atomic, better one record per output? Or extend commitments record:
            * Alternatively, we pack ephemeral in the commitments TLV type 0x01: For each commitment, also supply an ephemeral pubkey. But that breaks the fixed size and assumptions.
            * We could define Type 0x04 as "Nonce list", with length 33*m. (Analogous to commitments list).
            * However, to keep scope, we might leave ephemeral out of consensus and have sender communicate it off-band (not great).
            * Since this is a full implementation spec, let's include it: define:

                * Type 0x04: Nonces (Ephemeral Public Keys for outputs). Value = concatenation of 33-byte secp256k1 pubkeys, one per CT output, in order.
                * If provided, length must be 33 * (number of CT outputs).
                * These are used by wallets to derive shared secrets. Not used in consensus checks (aside from length matching output count), so if a malicious actor put wrong nonces, it doesn't affect validation, but it would confuse receivers (they wouldn't decode value). We rely on sender honesty here; it's like putting wrong encrypted value – it only hurts recipient.
                * We mark this TLV optional but recommended. If absent, an alternate method is needed for recipient to get ephemeral (maybe via payment protocol or assuming ephemeral=some function of commitment? Unlikely).
            * This doesn't affect consensus aside from requiring if present, length matches output count.
    * These wallet-level details are not critical for the *consensus* BIP, but we mention them because a truly "implementation-ready" spec should consider how users will actually get their money. We will add guidance in Wallet-Side Policy below.

**Bitcoin Core UI/CLI**:

* Likely add RPCs:

    * `sendtoaddress_confidential` or extend `sendtoaddress` to accept `bcx...` and handle blinding under the hood.
    * `getnewaddress "" "confidential"` to get a CT address (which involves generating an internal key and perhaps storing a blinding key).
    * `dumpblindingkey <address>` maybe, similar to how Elements had a way to get the blinding priv key corresponding to an address (so user can give it to auditor if needed).
    * But these can come later; initially, a basic ability to send/receive is enough.

**Testing and Test Vectors**:

* The reference implementation would include test cases:

    * Creating a transaction with known small values, ensure commitments and proofs verify.
    * Ensure an invalid proof is caught (e.g., tamper one byte and see validation fails).
    * Check consensus rules like coinbase rejection, r=0 rejection, fee output existence.
    * Sighash tests: a series of test vectors to confirm that for a given tx and sighash flags, the computed message hash matches expected (we will provide some below).
    * Cross-verify that if you try to spend a CT output without providing proof, new nodes reject but old accept (to simulate enforcement).
    * Also performance tests: ensure verifying e.g. 100 outputs bulletproof (~2KB proof) is under certain time.

**Upgradability**:

* Because CT-Exodus uses a SegWit version, any further improvements could either use new TLVs (which we allowed up to 0x4F) or if something fundamental, a new witness version. For example, if in future we wanted Confidential Assets (multiple asset commitments), that might be too big a change for TLV and might be SegWit v3 with different rules. But smaller tweaks (like adding an encrypted memo field, or maybe a shorter range if supply known) can be via TLV and all nodes can ignore unknown TLVs until a soft fork defines them.
* This extensibility was a rationale for TLV design.

## Test Vectors

We present several test scenarios with annotated hex and values to illustrate CT-Exodus transactions and the signature hashing. These are "canonical" examples for implementers to verify their code against. (All hex is in little-endian for numbers and as serialized in transactions.)

### Test Vector 1: Single-Input, Single-Output CT Transaction

A simple transaction: one input (explicit) of 0.5 BTC, one CT output of 0.3 BTC to a CT address, and 0.2 BTC fee. (0.5 in – 0.3 out – 0.2 fee = 0 balance).

* **Input:** prevout = `0123456789...:1` (txid shorthand, index 1), value = 50000000 sats (0.5 BTC), scriptPubKey = P2WPKH (legacy SegWit v0).

* **Output 0:** CT output paying 0.3 BTC to some public key `P` (x-only).

* **Fee output:** 0.2 BTC fee explicit (actually, 0.2 BTC = 20000000 sats).

* **Blinding:** Suppose the blinding factor chosen = `r = 0x11223344556677889900aa...` (32 bytes).

* **Commitment:** C = 0.3BTC*H + r*G. For demonstration, let's derive a dummy commitment (not using actual secp calc here, but we will present a plausible 33-byte value). We'll use the generator H from earlier and do a fake calc:
  Assume H's x = `0xf00ba4...` and r*G's x = `0xabc123...`, the sum point C's compressed encoding = `08{32-byte-x}`:

    * For this example, we'll use:
      Commitment = `0896b5334fd8b0f6c5e... (33 bytes total)` (not actual calc, just example).

* **Range Proof:** The range proof will be ~674 bytes. We will not list it fully here. Instead, we'll give the SHA256 of the proof to uniquely identify it. (In implementation, one would verify the actual proof bytes.)

    * e.g., `proof_sha256 = 0x5f9c...` (just hypothetical).

* **Annex TLV:**

    * Type 0x01 (Commitments): length 33, value = commitment above.
    * Type 0x02 (RangeProof): length ~674, value = (bulletproof bytes).
    * Type 0x03 (Fee commit): optional. We can include the fee commit = commit to 0.2BTC = 20,000,000 sats. That would be `C_fee = 0.2*H + 0*G = 0.2*H`. If H's discrete log is unknown, we can't derive numeric easily. We can either skip TLV 0x03 or just trust that if one computed it, it'd be some 33-byte point. We'll omit it for brevity.

* **Transaction (hex):**

Let's construct the full transaction hex (in Bitcoin raw tx format):

```
02 00 00 00                                             -- Version 2
00 01                                                    -- Segwit marker & flag
01                                                       -- Input count
  <36-byte prevout>                                      -- Outpoint: (We insert txid and index)
    e.g., "09ef8e4e23cd682578e6978c9eed753069e9c104d7261501659168e66567b7c0" (txid reversed) + "01000000" (index 1)
  00                                                     -- scriptSig length 0 (segwit spend)
  ffffffff                                               -- sequence
02                                                       -- Output count (CT output + fee output)
  0000000000000000                                       -- CT output explicit amount (0)
  22                                                     -- scriptPubKey length 0x22 (34 bytes)
    52                                                   -- OP_2
    20                                                   -- push 32 bytes
    <32-byte witness program>                            -- (x-coordinate of P, e.g., "fd784aba5e91d18306ba722f3af50ecdaf056caf19a3632a39b1b64a2109ecf6")
  0000000000000000                                       -- Fee output amount (0)
  0a                                                     -- scriptPubKey length 0x0a (10 bytes)
    6a                                                   -- OP_RETURN
    08                                                   -- Push 8 bytes
    80 96 98 00 00 00 00 00                               -- 0x00000000989680 (Little-endian of 0x0989680 which is 0x5F5E100 in hex? Wait let's do 0.2 BTC in sat: 20,000,000 dec = 0x01312D00 in hex. LE = 00 2d 31 01 00 00 00 00. Actually let's do precisely:)
    (Actually, 20,000,000 sats in hex = 0x01312D00, LE = 00 2D 31 01 00 00 00 00. We'll use that:)
    00 2d 31 01 00 00 00 00                               -- 8-byte fee = 0x012d3100 (20,000,000)
01                                                       -- Witness count for input 0
  <witness_element_count> 03                             -- We will have 3 witness elements: [sig, annex, (maybe scriptSig)?]. Actually, for segwit v0 P2WPKH input, witness elements: <sig> <pubkey>. But our input is P2WPKH, we need to provide unlocking:
    Our input is P2WPKH: So witness: {signature, pubkey}. That's 2 elements. But also we have annex? Wait, annex is global and goes in input 0's witness as last element if it starts with 0x50.
    So witness element count = 3 (signature, pubkey, annex).
    <signature+hashtype> (e.g., 71 bytes DER+ sighash 0x01) 
    <pubkey> (33 bytes)
    <annex> (starts with 0x50):
      50 
      01 21 <33-byte commitment> 
      02 <varint-length of proof> <proof bytes...>
      (We'd encode the TLV stream fully)
[We won't fill in all bytes for witness here due to complexity. Instead, show conceptually:]
  02                                               -- Number of witness stack items for input (signature, pubkey, and annex counts as part of witness stack? Actually, BIP341 says annex is not counted in nWitness of that input. Correction: The annex is included as a witness element for the counting in serialization or not? 
    BIP141 defines each input has a witness stack with count. If annex is present, it is included in that count. We have 3 including annex.)
  <Sig (64 bytes) + 0x00 sighash> 
  <PubKey (33 bytes)>
  <Annex (prefix 0x50 + TLVs...)>
00 00 00 00                                             -- locktime
```

Let's clarify witness serialization:

* Marker+flag indicates segwit.
* Then number of inputs and outputs etc.
* After outputs, we have witness data for each input:

    * For input 0 (which is P2WPKH, not CT): witness stack count could be 2 normally. But because we attach annex to this input for CT data, the witness stack count actually becomes 3. BIP341 states if annex present, it is included as an item in the witness stack (the last item).
    * So witness for input0:

        * Stack count: 3
        * Item1: signature for P2WPKH (e.g., 71 bytes DER + 0x01 sighash).
        * Item2: pubkey (33 bytes).
        * Item3: annex (starting with 0x50..., containing TLVs).
* That covers witness.

Thus, the raw hex (with dummy values for big parts) might look like:

```
02000000 0011 01 
[prevout txid+index] 
00 ffffffff 
02 
0000000000000000 22 52 20 [32-byte program] 
0000000000000000 0a 6a 08 [8-byte fee LE] 
03 
<sig...> 
<pubkey33> 
[annex bytes starting 0x50 ...] 
00000000
```

We won't compute actual proof bytes or signature here. The main point:

* The output's amount is 0, script is `5220...` (which decodes to OP_2 <32-byte>).
* The fee output's script is `6a08[fee8bytes]`.
* The annex bytes (difficult to list all, but it will contain the TLVs as specified):

    * 0x50
    * 0x01 (type1) 0x21 (length33) [33-byte commitment]
    * 0x02 [length0x??] [proof bytes]
    * possibly 0x03 [length33] [fee commitment if included].

**Verification steps for this tx:**

* New node sees OP_2 output, triggers CT rules.
* Parses annex:

    * finds commitment = (some point),
    * finds proof,
    * verifies proof: proof says committed value is in [0,2^52) and equals 0.3 BTC presumably.
    * Sums input: 0.5BTC explicit → convert to commit: C_in = 0.5*H (blinder 0).
    * Sums outputs: commit 0.3BTC (with its r) plus fee commit 0.2BTC.
    * It computes C_in - C_out - C_fee. If everything is consistent, this should equal infinity. Indeed 0.5H - 0.3H - 0.2H = 0 (since 0.5-0.5=0).
    * All good, so tx valid.
* Old node:

    * sees 0.5 input, outputs explicit sums = 0 (only fee is counted as output? Actually fee output has 0 amount in txout, so explicit outputs sum = 0).
    * It sees input 0.5 vs outputs 0 => it thinks 0.5 BTC fee was paid (though actually 0.2 was, but it can't tell; it thinks miner left 0.3 unclaimed, which is allowed).
    * Accepts it. (Miner in coinbase can still only claim 0.2 because coinbase is explicit and they won't magically claim 0.5; the extra 0.3 effectively got "burned" in old node's view.)

This test vector demonstrates basic structure.

**Annotated fields:**

* Prevout: `090909...00000001` etc. (Omitted actual).
* scriptPubKey of CT output: `52 20 [32-bytes]` which is `OP_2 PUSH32 <P>` where `<P>` is (for example) `fd784aba5e91d18306ba722f3af50ecdaf056caf19a3632a39b1b64a2109ecf6` (32-byte x-only pubkey).
* scriptPubKey of fee: `6a 08 002d310100000000`:

    * 0x6a = OP_RETURN,
    * 0x08 = push 8 bytes,
    * `00 2d 31 01 00 00 00 00` = 0x01312d00 = 20,000,000 (in LE).
* Annex: starts with `0x50`. For instance, if commitment = `08abcd...` (33 bytes), proof length ~0x02A2 (674):

    * annex could begin `50 01 21 <33-byte commit> 02 A2 02 <...674 bytes of proof>`.
* Witness stack:

    * Signature (71 bytes plus sighash 0x00),
    * Pubkey (33 bytes),
    * Annex (the bytes above).
* Sighash: to sign that input (P2WPKH), we use BIP143 (since it's not CT input, just normal segwit v0) for that signature. That signature doesn't cover the CT stuff at all (since legacy sighash doesn't include witness data). That's acceptable because the CT stuff is protected by miners via CT rules, and by the CT outputs' own spending conditions (someone can't malleate the CT output because they can't forge a valid proof/commit pair with different value without invalidating).

    * There is a slight nuance: an attacker might try to bump fee by altering the fee output script since the P2WPKH signature doesn't cover outputs thoroughly (SIGHASH_ALL covers outputs though, so if that signature was ALL, it does cover outputs values and script).
    * Yes, SIGHASH_ALL covers outputs, so the P2WPKH signature *will* commit to fee output's 8 bytes (0).
    * Actually, in segwit v0, sighash ALL includes output values and scripts. So the P2WPKH signer has committed to exactly the outputs we listed (including the 0-valued CT out and 0-valued fee out).
    * So they indirectly sign off on fee or else it wouldn't be ALL. So malleating fee or output script would break that sig as well.

This test verifies typical CT creation.

### Test Vector 2: Two CT Outputs with Rangeproof Aggregation

Transaction: one input (explicit 1.0 BTC), two CT outputs (0.4 and 0.5 BTC), fee 0.1 BTC.
The two outputs will share one range proof.

* Input: 1.0 BTC explicit (100000000 sats).
* Outputs:

    * CT0: 0.4 BTC to pubkey P0 (with blinder r0).
    * CT1: 0.5 BTC to pubkey P1 (with blinder r1).
* Fee: 0.1 BTC.

Commitments:

* C0 = 0.4*H + r0*G.
* C1 = 0.5*H + r1*G.
* We show them as 33-byte hex:

    * C0 = `08aaaaaaaa...` (just placeholder).
    * C1 = `09bbbbbbbb...` (placeholder).
* Rangeproof: Single Bulletproof proving both 0.4 and 0.5 are in range. The proof size ~ 738 bytes (slightly more than single-output).
* Annex TLV:

    * Type0x01: length 66, value = [C0||C1].
    * Type0x02: length ~0x2E2 (738), value = proof bytes.
    * (Optional type0x04: Nonces, 66 bytes if we include ephemeral points R0||R1).
* Fee output: OP_RETURN 0x08 [0x0050C300... LE of 10000000] (0.1 BTC = 10000000 sats, hex 0x00989680, LE: 0x80 96 98 00 00 00 00 00).

Serialized (skipping repetitive parts):

```
02000000 0001 01 [prevout1BTC] 00 ffffffff 
03 
0000000000000000 22 52 20 <32-byte P0>
0000000000000000 22 52 20 <32-byte P1>
0000000000000000 0a 6a 08 80 96 98 00 00 00 00 00
01 
<sig> <pubkey> <annex> 
00000000
```

Annex (in hex comments):

```
50 
01 42 <C0(33 bytes)><C1(33 bytes)>    ; two commitments
02 <varint for 738> <738 bytes proof>
03 21 <C_fee(33 bytes)>    ; commit to 0.1BTC if included, or skip since easily computed
04 42 <R0(33b)><R1(33b)>   ; ephemeral nonces for outputs
```

Check:

* commit sum: input commit = 1.0*H, output sum = 0.4*H + 0.5*H = 0.9*H, fee commit = 0.1*H, so 1.0*H - (0.9*H + 0.1*H) = 0. Perfect.
* Rangeproof verifies both commitments simultaneously.
* Sighash for input (if P2WPKH, covers outputs etc. as usual).
* This test ensures multiple outputs can be proved together. An implementer should verify that combining commitments in proof yields no errors and that verification passes.

### Test Vector 3: Sighash ANYONECANPAY | SINGLE

This demonstrates the signature message for an input signing only itself and one output.

Scenario: A transaction with 2 inputs and 2 outputs. Input0 will sign with ANYONECANPAY|SINGLE (0x83) for output0. Input1 will sign normally.

* Tx:

    * Inputs:

        1. Input0: CT input referencing a CT UTXO of 0.7 BTC (to simulate CT input signing).
        2. Input1: explicit input of 0.3 BTC.
    * Outputs:

        1. Output0: CT output 0.7 BTC to someone (spent by input0's sig).
        2. Output1: explicit output 0.2 BTC to someone.

        * Fee: 0.1 BTC.

The idea: Input0 only cares about its corresponding output0.

**Sighash for Input0 with flags 0x83:**

According to our algorithm, for input0:

* ANYONECANPAY => sha_prevouts, sha_amounts, sha_scriptPubKeys, sha_sequences all become 0.
* SINGLE => sha_outputs = SHA256(serialization of output0 only).

So preimage assembly:

```
spend_type = 0x00 (key path)
sighash_byte = 0x83
version = 0x02000000
locktime = 0x00000000
sha_prevouts = 000...000 (32 bytes)
sha_amounts = 000...000
sha_scriptPubKeys = 000...000
sha_sequences = 000...000
sha_outputs = SHA256(output0 serialization)
sha_annex = 000...000 (assuming no annex for simplicity; if CT output0 then actually there would be an annex with that output's commit and proof in the tx – but for signature we consider the overall annex of tx. Let's assume output0 is CT and output1 is explicit. The tx will have an annex with output0 commit & proof. If annex present, sha_annex would = SHA256(annex). For variety, let's say output0 is CT so yes annex present.)
sha_annex = SHA256(annex)
prevout_bytes = [outpoint of input0] (since ANYONECANPAY, include this specifically)
input_amount_bytes = the commitment of the prevout (33 bytes, since CT input)
input_script_bytes = varint+scriptPubKey of prevout (scriptPubKey length and content; for a CT prevout's scriptPubKey = OP_2 32-byte, length 34)
input_sequence_bytes = sequence (4 bytes)
```

Concretely:

* Output0 serialization:

    * value=0 (CT output),
    * scriptPubKey = 34 bytes `52 20 <32-byte>`.
    * So output0 bytes = `0000000000000000 22 52 20 [32 bytes P]`.
    * `SHA256(output0_bytes)` we compute (for demonstration):
      Let's say SHA256(output0_bytes) = `d0f1f2...` (just referencing from the StackExchange example, they had an outputs hash).
      Actually in [53], they gave an example outputs hash for ANYONECANPAY|ALL scenario (they had outputs hash).
* Annex: likely present (since output0 CT, tx has annex). For signature, we include its hash.
* Prevout outpoint: e.g., `abcdef...00000000` (txid + index).
* Input0's prevout commit: the CT UTXO's commitment (33 bytes). e.g., `08c0ffeec0ffeec0ffee...` (not real).
* Input0 prevout scriptPubKey: e.g., `22 52 20 [32-bytes of that UTXO's internal pubkey]`.
* Sequence: e.g., `ffffffff`.

So the preimage could look like (with fields labeled):

```
00                                                 -- spend_type (key path)
83                                                 -- sighash flag
02000000                                           -- version
00000000                                           -- locktime
0000000000000000000000000000000000000000000000000000000000000000   -- sha_prevouts
0000000000000000000000000000000000000000000000000000000000000000   -- sha_amounts
0000000000000000000000000000000000000000000000000000000000000000   -- sha_scriptPubKeys
0000000000000000000000000000000000000000000000000000000000000000   -- sha_sequences
d32241d6cf9637a786922b700fc5c34385dc2a738d84734cae914b39ef595cfe   -- sha_outputs (example from Pieter Wuille's answer for output hash):contentReference[oaicite:56]{index=56}
<sha_annex 32 bytes>                                              -- if annex present, else 32 zero bytes
<prevout_txid (32)> <prevout_index (4)>                            -- outpoint of input0
<commitment of prevout (33)>                                       -- input0 amount commit
<length+scriptPubKey of prevout> (1 + 34 bytes)                    -- e.g., 0x22 + [52 20 ... 32 bytes]
<sequence (4 bytes)>                                              -- input0 sequence
```

Then take tagged hash of that (TapSighash prefix twice + data). The expected result:
They gave in the example (for 0x81 flag):
They had a message of 126 bytes (we might have similar length here).

We won't compute exact final hash numeric, but one can run the pseudocode to confirm.

Key things to verify from this:

* Only output0 was hashed (output1 omitted).
* Only input0's info was directly included; others omitted.
* The annex was included since we assume one exists (with commit for output0 perhaps).
* If output0 is CT, annex hash covers commit/proof, so input's signature commits to those via sha_annex and sha_outputs (since output0's script and 0 amount are included, but not the commit itself – commit is not in output serialization, it's in annex. However, by including sha_annex, the signature does commit to the commit data indirectly).
* If output0 were explicit, no annex needed.

This matches the intended sighash logic:
ANYONECANPAY|SINGLE commits to:
Transaction data (version, locktime),
One output (the one with same index),
The specific input's outpoint, value, script, sequence,
Annex,
and sighash flags.

We can provide final digest:
Just as example, if we actually plugged numbers:
It would produce some 32-byte hash:
**Expected SigMsg Hash:** (for demonstration) `0xabcdef123456...`.

A signer would then produce Schnorr sig with that.

**Conclusion of test vector 3:** It shows how to compute sighash for advanced cases.

We can also mention: if input_index >= outputs count and SINGLE flag set:
Then sha_outputs = SHA256(b"") (32b hash of empty). The spec covers that to avoid edge.

---

These test vectors cover:

* Basic CT output creation,
* Multi-output CT with aggregated proof,
* Sighash algorithm correctness for ANYONECANPAY/SINGLE.

Implementers should test against these. In practice, full examples with actual valid rangeproof bytes could be generated if using a CT library, but due to complexity, we focused on structural and hash correctness.

## Deployment

CT-Exodus is a consensus change and would be deployed via a soft-fork activation mechanism. We propose using a modern activation method (BIP8 with lockin and possibly false activation if needed). Key steps:

* **Signaling:** The upgrade will have a unique deployment bit (as per BIP9 style or BIP8), for example bit 2 (just as an example). Miners can signal readiness in block version bits. A threshold (e.g., 90% of blocks in a 2016-block window) indicates activation signal.
* **Activation:** After a threshold is reached (or after timeout in BIP8), the rule change becomes locked in, and then active after another defined period (say one adjustment period later).
* **Flag Day:** If using BIP8, we could set a flag day activation for some time in the future to ensure eventual activation even if miners don't signal but users want it (if that's the community consensus).
* **Initial State:** Before activation, nodes will accept CT outputs as anyone-can-spend 0 value (same as old nodes). After activation, nodes enforce all rules. Blocks violating CT rules after activation height will be rejected.
* **Interoperability during rollout:** It's possible some miners upgrade and some don't. To avoid issues, miners should ideally upgrade by activation. Non-upgraded miners risk producing invalid blocks unknowingly. In practice, a few orphaned blocks may happen, but economic majority should enforce.
* **Miner Guidance:**

    * **Template rules:** Miners must update their block template generation to *not* include CT transactions until they enforce them (to avoid creating invalid blocks). Once they enforce, they can include CT tx normally. They should also count weight with annex adjustments, etc.
    * **Fee calculation:** When selecting tx for block, miners (post-activation) must consider the **exposed fee output** of CT tx. Since CT tx explicit outputs won't show the real output values, miners can't calculate fee as sum(in)-sum(out) easily. However, we've made it easy: they just read the fee output value from the OP_RETURN output. They should trust that (and maybe cross-verify via commit sum if they like, but that's heavy – better to trust the network rules to ensure correctness).
    * Thus mining software should parse OP_RETURN fee and use it for fee rate comparisons. A malformed CT tx could lie in OP_RETURN (say, claim fee of 1sat while actually input minus outputs = 1 BTC), but that tx would be invalid by consensus anyway (commit sum wouldn't check out), so miners won't include it because their node will reject it at validation. So miners can rely on the node mempool (which only contains valid CT tx) so the fee output is honest.
* **Wallet adoption timeline:** Once locked in, wallets can start offering CT addresses to users. However, widespread adoption might take time. We might consider a **grace period** where even after activation, using CT for critical things (like as change address by default) might be gradual.
* **Initial Usage & Monitoring:** After activation, it is advisable to have wallets and block explorers monitor CT usage to catch any anomalies. Because this is a significant cryptographic feature, any bug or unforeseen issue (like a weakness in Bulletproofs or a miscalculated parameter) should be watched for. A quick response plan (like a soft-fork disallowing CT again) could be devised as contingency, but given the maturity of these primitives, we don't expect that.

**Upgrade Path for Future:** CT-Exodus is designed to be forward-compatible. If later upgrades (like new proof systems or asset support) are desired, they can be layered either by new TLVs or a new segwit version. The "extension" part of name hints we can extend further without another full redesign.

**Summary:** We envision a deployment where miners signal readiness possibly within a year of proposal, and the feature activates once supermajority is reached or by timeout. Post-activation, Bitcoin gains a powerful privacy tool. An education period for users and exchanges will be needed so they understand hidden amounts (for example, explorers will show output as "Confidential" with a commitment hash instead of a value). This BIP serves as the formal basis to proceed with that deployment discussion among stakeholders.

## References

* Maxwell, Gregory. *"Confidential Transactions"* (Bitcoin developer mailing list & elementsproject.org primer) – explains the Pedersen commitment approach and initial CT design.
* Poelstra et al. *"Bulletproofs: Short Proofs for Confidential Transactions and More"* (2017) – cryptographic paper introducing Bulletproof range proofs.
* BIP341/342 (Taproot) – for comparison of SegWit v1 design, signature hashing, annex, etc.
* Blockstream Elements Project – implementation of CT in Liquid (functionally similar commitments, fee outputs, and blinding mechanisms). Particularly, Elements function `secp256k1_rangeproof_verify` and `secp256k1_bulletproof_verify` in libsecp256k1, and Elements' policy that "a confidential transaction must include an explicit fee output".
* Pieter Wuille's StackExchange answer on CT fee and verification.
* Felix Weis, et al. *"CT as a soft fork using segwit"* (Bitcoin-Dev mailing list, 2017) – an early outline of making CT a softfork, which used a special coinbase "unblinding" mechanism. CT-Exodus simplifies this by explicit fee output and no special coinbase scripts, learning from that discussion.
* BIP173/350 (Bech32 and Bech32m) – address encoding details, particularly the rationale for the new constant and error detection properties.
* Andrew Poelstra. *"Enhancing privacy on Bitcoin with Pedersen commitments"* – (perhaps a blog or talk summarizing CT advantages).
* Jonas Nick et al. *BIP340 Schnorr Signatures* – for lift_x and tagged hash usage.
* Bitcoin Core repository – secp256k1-zkp module documentation (for developers integrating CT).
* ElementsProject Confidential Transactions demo and explainer – for a high-level understanding of how blinding and unblinding works.
* [Bitcoin Wiki: Privacy](https://en.bitcoin.it/wiki/Privacy) – outlines how amount correlation hurts privacy, motivating CT.
