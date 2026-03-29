import unittest
from pathlib import Path

from generator import generate_toml
from run import _shape_generated_fragments
from variations.honestcue import HonestCueVariation
from variations.promptsteal import PromptStealVariation


ROOT = Path(__file__).resolve().parents[1]


def _identity_fragmenter(var, *, api_key=None):
    return [step for step, _ in var]


def _prefix_legitimizer(step, *, api_key=None):
    return f"LEGIT::{step}"


class FragmentShapeTests(unittest.TestCase):
    def _assert_stage_becomes_fragment(self, variation_cls, seed_file: str, seed: int):
        gen = variation_cls(str(ROOT / seed_file))
        var = gen.make_variation(seed)

        fragments = _shape_generated_fragments(
            var,
            fragment=False,
            legitimize=False,
            api_key=None,
            make_fragments_fn=_identity_fragmenter,
            legitimize_fragment_fn=_prefix_legitimizer,
        )

        self.assertEqual(len(fragments), len(var))
        self.assertTrue(all(len(fragment_vars) == 1 for fragment_vars in fragments))
        self.assertEqual([frag_vars[0] for frag_vars in fragments], [step for step, _ in var])

        toml_text = generate_toml(gen.data["metadata"], fragments, seed)
        self.assertEqual(toml_text.count("[[fragments]]"), len(var))
        self.assertEqual(toml_text.count("[[fragments.variations]]"), len(var))

    def test_promptsteal_stages_become_fragments(self):
        self._assert_stage_becomes_fragment(PromptStealVariation, "seeds/promptsteal.json", 42)

    def test_honestcue_stages_become_fragments(self):
        self._assert_stage_becomes_fragment(HonestCueVariation, "seeds/honestcue.json", 42)

    def test_fragment_and_legitimize_preserve_fragment_boundaries(self):
        var = [
            ("stage-1", "discovery"),
            ("stage-2", "collection"),
        ]

        def fake_fragmenter(_var, *, api_key=None):
            return ["frag-a", "frag-b", "frag-c"]

        fragments = _shape_generated_fragments(
            var,
            fragment=True,
            legitimize=True,
            api_key="dummy",
            make_fragments_fn=fake_fragmenter,
            legitimize_fragment_fn=_prefix_legitimizer,
        )

        self.assertEqual(
            fragments,
            [["LEGIT::frag-a"], ["LEGIT::frag-b"], ["LEGIT::frag-c"]],
        )


if __name__ == "__main__":
    unittest.main()
