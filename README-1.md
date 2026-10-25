# aat-vectors

An independent, claim-level checker and a set of test vectors for
[draft-niyikiza-oauth-attenuating-agent-tokens-01](https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-01)
(Attenuating Authorization Tokens for Agentic Delegation Chains).

Status: first version, 25 October 2026. 43 vectors. Not run against any other implementation yet.

## What this is

The draft defines six invariants (I1 to I6) and a constraint attenuation matrix (Sections 3.4, 4.5).
Section 8.2 says implementers MUST test I4 against the full matrix. I found no published vectors
for that. This repository offers:

- `aat_invariants.py`: a small checker (standard library only) for I1 to I5 and the constraint rules,
  written from my reading of the draft text. It looks at claims, not signatures.
- `vectors.json`: 43 vectors (parent, child, expected violations, and the draft section each
  expectation comes from). `generate_vectors.py` rebuilds them.
- `test_vectors.py`: runs the checker against the vectors. `python3 -I test_vectors.py`
- `OPEN_QUESTIONS.md`: places where the text I could read did not settle the answer. I did not guess
  silently. Each is a question for the author or for anyone who reads the full text differently.

## What this is not

- **Not the first implementation.** The draft names a reference implementation (Tenuo). I have not
  run these vectors against it and do not know whether it agrees with them.
- **Not independent evidence of correctness.** The expected values are my reading of the draft. If my
  reading is wrong, both the checker and the vectors are wrong together. The value of this
  repository shows only when someone else runs the vectors and either agrees or finds a disagreement.
- **Not a signature verifier.** I6, signature checks, replay and Section 7 steps beyond the claim
  checks are out of scope. Part of Section 7 and Appendix E were cut off in the text I could read.
- Only the version -01 text was used. Later versions may differ.

## How the vectors were checked

I broke the checker on purpose in 18 different ways (for example, allowing a wider range, dropping
the depth check, comparing `1` and `true` as equal). The vectors caught every one. That shows the
vectors test something. It does not show they are right.

## Related work

The draft and its reference implementation are the author's. Separate drafts cover other parts of the
same problem (for example, Delegate SD-JWT, which per one secondary analysis does not check that each
hop narrows authority). No novelty is claimed here for the concept of attenuation.

Developed with substantial LLM assistance. MIT licensed.
