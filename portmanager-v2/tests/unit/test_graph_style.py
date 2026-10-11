"""Regression checks for sampled 60-second graph formatting."""
import unittest

from pm2 import graph_style


class GraphStyleTests(unittest.TestCase):
    def test_missing_is_not_zero(self):
        result = graph_style.summarize([], 100)
        self.assertEqual(result["graph_up"], " " * 60)
        self.assertEqual(result["coverage_seconds"], 0)
        self.assertIsNone(result["up_mbps"])

    def test_partial_minute(self):
        result = graph_style.summarize([(100, 5, 10, 2)], 100)
        self.assertEqual(result["coverage_seconds"], 5)
        self.assertEqual(result["graph_up"].count("█"), 5)
        self.assertEqual(result["up_mbps"], 10)
        self.assertEqual(result["down_mbps"], 2)
        self.assertEqual(graph_style.avg_text(10, 5), "10.00*")

    def test_complete_minute_is_weighted(self):
        result = graph_style.summarize([(30, 30, 6, 4), (60, 30, 12, 2)], 60)
        self.assertEqual(result["coverage_seconds"], 60)
        self.assertAlmostEqual(result["up_mbps"], 9)
        self.assertAlmostEqual(result["down_mbps"], 3)
        self.assertNotIn(" ", result["graph_up"])
        self.assertEqual(graph_style.avg_text(9, 60), "9.00")

    def test_zero_traffic_and_future_rows(self):
        result = graph_style.summarize([(20, 10, 0, 0), (100, 5, 500, 500)], 20)
        self.assertEqual(result["coverage_seconds"], 10)
        self.assertEqual(result["up_mbps"], 0)
        self.assertEqual(result["graph_up"][-1], "▁")
        self.assertEqual(result["graph_up"][0], " ")
        self.assertEqual(len(graph_style.summarize([], 1, columns=12)["graph_up"]), 12)

    def test_units(self):
        self.assertEqual(graph_style.rate_text(.21419), "214.19 Kbit/s")
        self.assertEqual(graph_style.rate_text(97.39), "97.39 Mbit/s")


if __name__ == "__main__":
    unittest.main()
