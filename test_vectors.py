import json, os, sys, unittest
HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
from aat_invariants import check_pair

with open(os.path.join(HERE, "vectors.json")) as f:
    DATA = json.load(f)

class T(unittest.TestCase):
    def test_all_vectors(self):
        for v in DATA["vectors"]:
            with self.subTest(v["name"]):
                self.assertEqual(check_pair(v["parent"], v["child"], v["now"], v["limits"]), v["expect"], v["basis"])
    def test_every_invariant_has_a_negative_vector(self):
        covered = {c for v in DATA["vectors"] for c in v["expect"]}
        self.assertTrue({"I1", "I2", "I3", "I4"} <= covered)

if __name__ == "__main__":
    unittest.main()
