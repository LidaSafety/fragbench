import unittest
from pathlib import Path
from unittest.mock import patch

from generator import (
    GeneratedFragment,
    GeneratedStage,
    StyledVariation,
    generate_toml,
    make_fragment_groups,
)
from run import _shape_generated_stages
from variations.honestcue import HonestCueVariation
from variations.promptsteal import PromptStealVariation


ROOT = Path(__file__).resolve().parents[1]


def _prefix_legitimizer(step, *, api_key=None, backend=None, model=None, base_url=None):
    return f"LEGIT::{step}"


class FragmentShapeTests(unittest.TestCase):
    def _assert_stage_becomes_stage_with_one_fragment(self, variation_cls, seed_file: str, seed: int):
        gen = variation_cls(str(ROOT / seed_file))
        var = gen.make_variation(seed)
        stage_descriptions = [
            stage.get("description", f"Stage {idx}")
            for idx, stage in enumerate(gen.data["attack_stages"])
        ]

        stages = _shape_generated_stages(
            var,
            stage_descriptions,
            fragment=False,
            legitimize=False,
            api_key=None,
            make_fragment_groups_fn=lambda _var, *, api_key=None: [[step] for step, _ in _var],
            legitimize_fragment_fn=_prefix_legitimizer,
            llm_backend="anthropic",
            llm_model=None,
            llm_base_url="https://openrouter.ai/api/v1",
        )

        self.assertEqual(len(stages), len(var))
        self.assertTrue(all(isinstance(stage, GeneratedStage) for stage in stages))
        self.assertTrue(all(len(stage.fragments) == 1 for stage in stages))
        self.assertEqual([stage.description for stage in stages], stage_descriptions)
        self.assertEqual(
            [stage.fragments[0].variations[0].prompt for stage in stages],
            [step for step, _ in var],
        )

        toml_text = generate_toml(gen.data["metadata"], stages, seed)
        self.assertEqual(toml_text.count("[[stages]]"), len(var))
        self.assertEqual(toml_text.count("[[stages.fragments]]"), len(var))
        self.assertEqual(toml_text.count("[[stages.fragments.variations]]"), len(var))
        for description in stage_descriptions:
            self.assertIn(description, toml_text)

    def test_promptsteal_stages_become_stages(self):
        self._assert_stage_becomes_stage_with_one_fragment(PromptStealVariation, "seeds/promptsteal.json", 42)

    def test_honestcue_stages_become_stages(self):
        self._assert_stage_becomes_stage_with_one_fragment(HonestCueVariation, "seeds/honestcue.json", 42)

    def test_fragment_and_legitimize_preserve_stage_and_fragment_boundaries(self):
        var = [
            ("stage-1", "discovery"),
            ("stage-2", "collection"),
        ]
        stage_descriptions = ["Discovery step", "Collection step"]

        def fake_fragment_groups(_var, *, api_key=None, backend=None, model=None, base_url=None):
            return [["frag-a", "frag-b"], ["frag-c"]]

        stages = _shape_generated_stages(
            var,
            stage_descriptions,
            fragment=True,
            legitimize=True,
            api_key="dummy",
            make_fragment_groups_fn=fake_fragment_groups,
            legitimize_fragment_fn=_prefix_legitimizer,
            llm_backend="anthropic",
            llm_model=None,
            llm_base_url="https://openrouter.ai/api/v1",
        )

        self.assertEqual(
            stages,
            [
                GeneratedStage(
                    "Discovery step",
                    [
                        GeneratedFragment(
                            "frag-a",
                            [StyledVariation(style="generated", prompt="LEGIT::frag-a")],
                        ),
                        GeneratedFragment(
                            "frag-b",
                            [StyledVariation(style="generated", prompt="LEGIT::frag-b")],
                        ),
                    ],
                ),
                GeneratedStage(
                    "Collection step",
                    [
                        GeneratedFragment(
                            "frag-c",
                            [StyledVariation(style="generated", prompt="LEGIT::frag-c")],
                        ),
                    ],
                ),
            ],
        )

        toml_text = generate_toml(
            {
                "id": "TEST",
                "technique": "T0000",
                "technique_name": "Generated",
                "description": "Test attack",
                "tags": ["generated"],
            },
            stages,
            7,
        )
        self.assertEqual(toml_text.count("[[stages]]"), 2)
        self.assertEqual(toml_text.count("[[stages.fragments]]"), 3)
        self.assertEqual(toml_text.count("[[stages.fragments.variations]]"), 3)
        self.assertIn("index = 0", toml_text)
        self.assertIn("index = 1", toml_text)

    def test_fragment_groups_fall_back_when_model_returns_more_than_two_parts(self):
        with patch("generator._generator_complete", return_value='["a", "b", "c"]'):
            groups = make_fragment_groups(
                [("original operational step", "discovery")],
                api_key="dummy",
                backend="openrouter",
            )

        self.assertEqual(groups, [["original operational step"]])


if __name__ == "__main__":
    unittest.main()
