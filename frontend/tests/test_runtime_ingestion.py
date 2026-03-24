import unittest

from frontend.runtime_server import ArtifactBundle, normalize_bundle


class RuntimeIngestionTests(unittest.TestCase):
    def test_normalize_bundle_with_minimal_events(self):
        seeds = [
            {
                "metadata": {"id": "TEST-1", "technique": "T1048", "technique_name": "Exfiltration"},
                "attack_stages": [
                    {
                        "index": 0,
                        "description": "discover",
                        "mitre_tactic": "discovery",
                        "mitre_technique": "T1595",
                        "mitre_technique_name": "Active Scanning",
                        "baseline_prompt": "scan subnet",
                    }
                ],
            }
        ]
        attacks = [{"metadata": {"id": "TEST-1"}, "fragments": [{"index": 0, "variations": [{"style": "direct", "prompt": "scan"}]}]}]
        events = [
            {"event": "session_start", "attack_id": "TEST-1", "model": "x"},
            {"event": "user_query", "query": "scan with nmap"},
            {"event": "assistant_response", "tool_calls": ['tool_call("bash", {"cmd":"nmap"})']},
            {"event": "tool_result", "result_preview": "hosts up"},
            {"event": "query_complete"},
        ]

        bundle = ArtifactBundle(seeds=seeds, attacks=attacks, session_events=events, mcp_logs=[], source={"session_file": "test.jsonl"})
        data = normalize_bundle(bundle)
        self.assertEqual(data["run"]["attack_id"], "TEST-1")
        self.assertEqual(len(data["campaigns"]), 1)
        self.assertEqual(len(data["fragments"]), 1)
        self.assertEqual(len(data["traces"]), 1)
        self.assertGreaterEqual(data["traces"][0]["risk"], 0.12)
        self.assertIn("coverage", data["mitre"])

    def test_normalize_bundle_falls_back_without_attack_id(self):
        bundle = ArtifactBundle(
            seeds=[{"metadata": {"id": "A1"}, "attack_stages": []}],
            attacks=[],
            session_events=[{"event": "session_start"}],
            mcp_logs=[],
            source={},
        )
        data = normalize_bundle(bundle)
        self.assertEqual(data["run"]["attack_id"], "A1")
        self.assertEqual(data["campaigns"][0]["id"], "A1")


if __name__ == "__main__":
    unittest.main()
