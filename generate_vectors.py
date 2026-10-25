"""Generates vectors/vectors.json. Every vector is: a parent, a child, now, limits, expect (list of
violation codes; [] = valid), and `basis` (draft section the expectation comes from).
Expectations are MY reading of draft-niyikiza-oauth-attenuating-agent-tokens-01."""
import copy, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aat_invariants import jwk_thumbprint_uri

NOW = 1_800_000_000
LIMITS = {"MAX_DELEGATION_DEPTH": 8, "MAX_IAT_SKEW": 30, "MAX_TOKEN_LIFETIME": 3600}
PK = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}

def tok(depth, tools, iss, iat=NOW - 100, exp=NOW + 1000, maxd=4):
    t = {"jti": "t%d" % depth, "iss": iss, "iat": iat, "exp": exp, "cnf": {"jwk": PK},
         "del_depth": depth, "del_max_depth": maxd,
         "authorization_details": [{"type": "attenuating_agent_token", "tools": tools}]}
    if depth:
        t["par_hash"] = "x"
    return t

PARENT = tok(0, {"send_email": {"to": {"constraint_type": "one_of", "values": ["a@x.com", "b@x.com"]},
                              "n": {"constraint_type": "range", "min": 0, "max": 10}},
                 "read_file": {}}, "https://issuer.example")
CHILD_ISS = jwk_thumbprint_uri(PK)

def child(**over):
    c = tok(1, {"send_email": {"to": {"constraint_type": "one_of", "values": ["a@x.com"]},
                              "n": {"constraint_type": "range", "min": 1, "max": 5}}}, CHILD_ISS)
    for k, v in over.items():
        c[k] = v
    return c

V = []
def add(name, c, expect, basis, parent=None):
    V.append({"name": name, "parent": parent or PARENT, "child": c, "now": NOW, "limits": LIMITS,
              "expect": expect, "basis": basis})

add("valid-narrowing", child(), [], "4.2-4.5")
add("I1-wrong-issuer", child(iss="https://evil.example"), ["I1"], "4.2")
add("I2-depth-skips", child(del_depth=2), ["I2"], "4.3")
add("I2-depth-same-as-parent", child(del_depth=0), ["I2"], "4.3")
add("I2-child-max-depth-wider", child(del_max_depth=5), ["I2"], "4.3")
add("I2-control-valid-depth", child(del_depth=1, del_max_depth=4), [], "4.3 (control)")
add("I2-depth-over-global-limit", tok(9, PARENT["authorization_details"][0]["tools"], CHILD_ISS, maxd=9), ["I2"], "4.3 MAX_DELEGATION_DEPTH", parent=tok(8, PARENT["authorization_details"][0]["tools"], "https://issuer.example", maxd=9))
add("I3-exp-after-parent", child(exp=NOW + 2000), ["I3"], "4.4")
add("I3-already-expired", child(exp=NOW - 1), ["I3"], "4.4")
add("I3-iat-before-parent", child(iat=NOW - 200), ["I3"], "4.4")
add("I3-iat-in-future-beyond-skew", child(iat=NOW + 31), ["I3"], "4.4")
add("I3-control-valid-lifetime", child(), [], "4.4 (control)")
add("I3-lifetime-over-max", child(iat=NOW - 100, exp=NOW - 100 + 3601), ["I3"], "4.4 MAX_TOKEN_LIFETIME", parent=tok(0, PARENT["authorization_details"][0]["tools"], "https://issuer.example", exp=NOW + 9000))

c = child(); c["authorization_details"][0]["tools"]["delete_all"] = {}
add("I4-adds-tool", c, ["I4"], "4.5")
c = child(); c["authorization_details"][0]["tools"]["send_email"]["to"] = {"constraint_type": "one_of", "values": ["c@x.com"]}
add("I4-one_of-not-subset", c, ["I4"], "4.5 one_of")
c = child(); c["authorization_details"][0]["tools"]["send_email"]["n"] = {"constraint_type": "range", "min": 0, "max": 11}
add("I4-range-widened-max", c, ["I4"], "4.5 range")
c = child(); c["authorization_details"][0]["tools"]["send_email"]["n"] = {"constraint_type": "range", "min": -1, "max": 5}
add("I4-range-widened-min", c, ["I4"], "4.5 range")
c = child(); del c["authorization_details"][0]["tools"]["send_email"]["n"]
add("I4-drops-constrained-argument", c, ["I4"], "4.5 (same argument keys when parent map non-empty)")
c = child(); c["authorization_details"][0]["tools"]["send_email"]["extra"] = {"constraint_type": "wildcard"}
add("I4-adds-argument-under-nonempty-parent", c, ["I4"], "4.5 (same argument keys when parent map non-empty)")
c = child(); c["authorization_details"][0]["tools"]["read_file"] = {"path": {"constraint_type": "exact", "value": "/tmp/a"}}
add("I4-adds-argument-under-empty-parent", c, [], "4.5 (parent map empty: child may add keys)")
c = child(); c["authorization_details"][0]["tools"]["send_email"]["to"] = {"constraint_type": "exact", "value": "a@x.com"}
add("I4-exact-under-one_of-member", c, [], "4.5 exact subsumes one_of (member)")
c = child(); c["authorization_details"][0]["tools"]["send_email"]["to"] = {"constraint_type": "exact", "value": "z@x.com"}
add("I4-exact-under-one_of-nonmember", c, ["I4"], "4.5 exact subsumes one_of (member)")
c = child(); c["authorization_details"][0]["tools"]["send_email"]["n"] = {"constraint_type": "exact", "value": 3}
add("I4-exact-under-range-inside", c, [], "4.5 exact subsumes range")
c = child(); c["authorization_details"][0]["tools"]["send_email"]["n"] = {"constraint_type": "exact", "value": 99}
add("I4-exact-under-range-outside", c, ["I4"], "4.5 exact subsumes range")
c = child(); c["authorization_details"][0]["tools"]["send_email"]["n"] = {"constraint_type": "one_of", "values": [1, 2]}
add("I4-cross-type-range-to-one_of-rejected", c, ["I4"], "4.5 (cross-type pair not explicitly permitted must be rejected)")
c = child(); c["authorization_details"][0]["tools"]["send_email"]["n"] = {"constraint_type": "frobnicate"}
add("I4-unregistered-type-rejected", c, ["I4"], "3.5 / 4.5")

c = child(); c["authorization_details"][0]["tools"]["send_email"]["n"] = {"constraint_type": "exact", "value": True}
add("I4-exact-true-is-not-a-number-in-range", c, ["I4"], "JSON typing (open question Q4)")
mx_parent_exact = tok(0, {"t": {"a": {"constraint_type": "exact", "value": 1}}}, "https://issuer.example")
add("I4-exact-1-vs-true-differ", tok(1, {"t": {"a": {"constraint_type": "exact", "value": True}}}, CHILD_ISS), ["I4"], "JSON typing (open question Q4)", parent=mx_parent_exact)
# single-constraint attenuation matrix (parent constraint, child constraint, expected valid)
def mx(name, p, c_, ok, basis):
    par = tok(0, {"t": {"a": p}}, "https://issuer.example")
    ch = tok(1, {"t": {"a": c_}}, CHILD_ISS, exp=NOW + 1000)
    add("matrix-" + name, ch, [] if ok else ["I4"], basis, parent=par)
mx("not_one_of-superset-ok", {"constraint_type": "not_one_of", "excluded": [1]}, {"constraint_type": "not_one_of", "excluded": [1, 2]}, True, "4.5 not_one_of")
mx("not_one_of-subset-bad", {"constraint_type": "not_one_of", "excluded": [1, 2]}, {"constraint_type": "not_one_of", "excluded": [1]}, False, "4.5 not_one_of")
mx("contains-superset-ok", {"constraint_type": "contains", "required": ["x"]}, {"constraint_type": "contains", "required": ["x", "y"]}, True, "4.5 contains")
mx("contains-subset-bad", {"constraint_type": "contains", "required": ["x", "y"]}, {"constraint_type": "contains", "required": ["x"]}, False, "4.5 contains")
mx("subset-narrower-ok", {"constraint_type": "subset", "allowed": ["x", "y"]}, {"constraint_type": "subset", "allowed": ["x"]}, True, "4.5 subset")
mx("subset-wider-bad", {"constraint_type": "subset", "allowed": ["x"]}, {"constraint_type": "subset", "allowed": ["x", "y"]}, False, "4.5 subset")
mx("wildcard-under-wildcard-ok", {"constraint_type": "wildcard"}, {"constraint_type": "wildcard"}, True, "4.5 wildcard")
mx("wildcard-under-exact-bad", {"constraint_type": "exact", "value": 1}, {"constraint_type": "wildcard"}, False, "4.5 wildcard")
mx("exact-under-wildcard-ok", {"constraint_type": "wildcard"}, {"constraint_type": "exact", "value": 1}, True, "4.5 exact subsumes wildcard")
mx("range-exclusivity-tighten-ok", {"constraint_type": "range", "min": 0, "max": 10}, {"constraint_type": "range", "min": 0, "max": 10, "max_inclusive": False}, True, "4.5 range")
mx("range-exclusivity-loosen-bad", {"constraint_type": "range", "min": 0, "max": 10, "max_inclusive": False}, {"constraint_type": "range", "min": 0, "max": 10}, False, "4.5 range")
mx("all-add-clause-ok", {"constraint_type": "all", "constraints": [{"constraint_type": "wildcard"}]}, {"constraint_type": "all", "constraints": [{"constraint_type": "wildcard"}, {"constraint_type": "exact", "value": 1}]}, True, "4.5 all")
mx("all-drop-clause-bad", {"constraint_type": "all", "constraints": [{"constraint_type": "wildcard"}, {"constraint_type": "exact", "value": 1}]}, {"constraint_type": "all", "constraints": [{"constraint_type": "wildcard"}]}, False, "4.5 all")
mx("any-remove-clause-ok", {"constraint_type": "any", "constraints": [{"constraint_type": "exact", "value": 1}, {"constraint_type": "exact", "value": 2}]}, {"constraint_type": "any", "constraints": [{"constraint_type": "exact", "value": 1}]}, True, "4.5 any")
mx("any-add-clause-bad", {"constraint_type": "any", "constraints": [{"constraint_type": "exact", "value": 1}]}, {"constraint_type": "any", "constraints": [{"constraint_type": "exact", "value": 1}, {"constraint_type": "exact", "value": 2}]}, False, "4.5 any")

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json"), "w") as f:
    json.dump({"draft": "draft-niyikiza-oauth-attenuating-agent-tokens-01", "now": NOW, "vectors": V}, f, indent=1)
print(len(V), "vectors")
