import unittest
from pathlib import Path

from generator import GeneratedFragment, generate_toml
from run import _shape_generated_fragments
from variations.honestcue import HonestCueVariation
from variations.promptsteal import PromptStealVariation


ROOT = Path(__file__).resolve().parents[1]


def _prefix_legitimizer(step, *, api_key=None):
    return f"LEGIT::{step}"


class FragmentShapeTests(unittest.TestCase):
    def _assert_stage_becomes_fragment(self, variation_cls, seed_file: str, seed: int):
        gen = variation_cls(str(ROOT / seed_file))
        var = gen.make_variation(seed)
        stage_descriptions = [
            stage.get("description", f"Stage {idx}")
            for idx, stage in enumerate(gen.data["attack_stages"])
        ]

        fragments = _shape_generated_fragments(
            var,
            stage_descriptions,
            fragment=False,
            legitimize=False,
            api_key=None,
            make_fragment_groups_fn=lambda _var, *, api_key=None: [[step] for step, _ in _var],
            legitimize_fragment_fn=_prefix_legitimizer,
        )

        self.assertEqual(len(fragments), len(var))
        self.assertTrue(all(isinstance(fragment, GeneratedFragment) for fragment in fragments))
        self.assertTrue(all(len(fragment.variations) == 1 for fragment in fragments))
        self.assertEqual([fragment.variations[0] for fragment in fragments], [step for step, _ in var])
        self.assertEqual([fragment.description for fragment in fragments], stage_descriptions)

        toml_text = generate_toml(gen.data["metadata"], fragments, seed)
        self.assertEqual(toml_text.count("[[fragments]]"), len(var))
        self.assertEqual(toml_text.count("[[fragments.variations]]"), len(var))
        for description in stage_descriptions:
            self.assertIn(description, toml_text)

    def test_promptsteal_stages_become_fragments(self):
        self._assert_stage_becomes_fragment(PromptStealVariation, "seeds/promptsteal.json", 42)

    def test_honestcue_stages_become_fragments(self):
        self._assert_stage_becomes_fragment(HonestCueVariation, "seeds/honestcue.json", 42)

    def test_fragment_and_legitimize_preserve_fragment_boundaries(self):
        var = [
            ("stage-1", "discovery"),
            ("stage-2", "collection"),
        ]
        stage_descriptions = ["Discovery step", "Collection step"]

        def fake_fragment_groups(_var, *, api_key=None):
            return [["frag-a", "frag-b"], ["frag-c"]]

        fragments = _shape_generated_fragments(
            var,
            stage_descriptions,
            fragment=True,
            legitimize=True,
            api_key="dummy",
            make_fragment_groups_fn=fake_fragment_groups,
            legitimize_fragment_fn=_prefix_legitimizer,
        )

        self.assertEqual(
            fragments,
            [
                GeneratedFragment("Discovery step (fragment 1/2)", ["LEGIT::frag-a"]),
                GeneratedFragment("Discovery step (fragment 2/2)", ["LEGIT::frag-b"]),
                GeneratedFragment("Collection step", ["LEGIT::frag-c"]),
            ],
        )


if __name__ == "__main__":
    unittest.main()
