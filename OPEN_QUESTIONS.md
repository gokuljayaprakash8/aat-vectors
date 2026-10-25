# Open questions

Points where the text of draft-niyikiza-oauth-attenuating-agent-tokens-01 that I could read did
not settle the answer. Each shows what this checker does today. If you read the full text
differently, please open an issue.

**Q1. Which child types may sit under a parent `wildcard`?**
Section 4.5 as I read it says a derived `wildcard` is valid only if the parent is also `wildcard`,
and that `exact` subsumes `wildcard`. It is unclear whether `range`, `one_of`, `contains` and the
rest may be derived from a `wildcard` parent. The draft also says cross-type pairs not explicitly
permitted must be rejected. This checker rejects them. Not in the vectors.

**Q2. How are `all` and `any` clauses matched?**
The text says `all` uses one-to-one matching and may add clauses "at any position". The checker
matches clauses by position. If matching is order-independent, some chains it rejects are valid.

**Q3. What is the exact format of `jwk_thumbprint_uri` (I1)?**
The checker uses the RFC 9278 form (`urn:ietf:params:oauth:jwk-thumbprint:sha-256:...`). The draft's
exact format was not confirmed.

**Q4. How is value equality defined for `exact`, `one_of` and the rest?**
The checker treats JSON values as equal only if they have the same type and the same canonical form,
so `1`, `1.0` and `true` are all different. The draft text I read does not say. Two implementations
could disagree here, and a disagreement could let an attacker slip in a wider value.

**Q5. Edge cases in `range`.**
Not specified in what I read: `min` greater than `max`, non-numeric bounds, NaN and infinity,
and a child range that is empty. The checker does not treat these specially.

**Q6. Empty parent tool map.**
The text says if the parent's argument map for a tool is empty, the child may add argument keys.
The vector `I4-adds-argument-under-empty-parent` encodes that reading. It may be intentional or
an oversight, since adding an argument constraint can only narrow a tool that had no constraints.

**Q7. Section 7 step order and I6.**
Part of Section 7 (from step 7f on) and Appendix E were not available to me. Nothing here covers them.
