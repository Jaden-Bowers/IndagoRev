"""Tests for evidence classification, process cleanup, and benchmark statistics."""
from dataclasses import replace
from pathlib import Path
import os
import sys
import time
import unittest
from unittest.mock import patch

from anti_dynamic_benchmark import benchmark, distribution, summarize
from anti_dynamic_harness import bounded_count, positive_float, warmup_count
from anti_dynamic_support import (
    Case, FIXTURES, command_for, execute, fnv1a, functional_cases, success_case, validate,
)


def result(stdout="", returncode=0, **changes):
    return {"returncode": returncode, "stdout": stdout, "stderr": "", "error": None,
            "timed_out": False, "elapsed_ns": 123, **changes}


class OracleTests(unittest.TestCase):
    def test_success_requires_exit_and_every_marker(self):
        case = Case("check", "example", contains=("first", "last"), excludes=("secret",))
        for row in (result("first"), result("first last", 10), result("first last secret"),
                    result("first last", -11), result("first last", stderr="error")):
            with self.subTest(row=row):
                self.assertEqual(validate(case, row)[0], "failed")
        self.assertEqual(validate(case, result("first last"))[0], "passed")

    def test_detection_must_not_emit_payload(self):
        case = success_case("tracer_status", "gdb")
        output = "phase=before pid=123 tracer=456\nreason=tracer-present-before-payload"
        self.assertEqual(validate(case, result(output, 10))[0], "passed")
        self.assertEqual(validate(case, result(output + "\npayload=oops", 10))[0], "failed")
        self.assertEqual(validate(case, result(output.replace("tracer=456", "tracer=0"), 10))[0], "failed")

    def test_no_silent_gdb_startup_success(self):
        case = success_case("encrypted_records", "gdb", True)
        self.assertEqual(validate(case, result("", stderr="ptrace denied"))[0], "failed")
        self.assertEqual(validate(case, result("", 77, stderr="ptrace denied"))[0], "failed")

    def test_unavailable_requires_evidence_and_no_payload(self):
        case = success_case("ptrace_guard", "native")
        text = "reason=tracing-denied-or-unavailable"
        self.assertEqual(validate(case, result(text, 77))[0], "unavailable")
        self.assertEqual(validate(case, result("", 77))[0], "failed")
        self.assertEqual(validate(case, result(text + "\npayload=x", 77))[0], "failed")
        self.assertEqual(validate(replace(case, allow_unavailable=False), result(text, 77))[0], "failed")

    def test_encrypted_mapping_restriction_is_unavailable(self):
        case = success_case("encrypted_code", "native")
        self.assertEqual(validate(case, result(returncode=77,
                         stderr="mprotect executable: Permission denied"))[0], "unavailable")

    def test_timeout_and_spawn_error_are_not_detections(self):
        case = Case("detected", "example", expected_exit=10)
        self.assertEqual(validate(case, result(returncode=10, timed_out=True))[0], "timeout")
        self.assertEqual(validate(case, result(returncode=10, error="missing executable"))[0], "error")

    def test_matrix_is_unique_and_covers_every_fixture_mode(self):
        cases = functional_cases(True)
        identities = [(case.fixture, case.mode, case.name) for case in cases]
        self.assertEqual(len(identities), len(set(identities)))
        self.assertEqual(len(cases), 61)
        for fixture in FIXTURES:
            for mode in ("native", "gdb"):
                for observe in (False, True):
                    self.assertIn((fixture, mode, "observe" if observe else "strict"), identities)

    def test_gdb_command_does_not_use_a_shell(self):
        case = success_case("signal_guard", "gdb", True)
        command = command_for(case, Path("/a directory"))
        self.assertIn("set startup-with-shell off", command)
        self.assertIn("--return-child-result", command)
        self.assertIn("-x", command)
        script = Path(command[command.index("-x") + 1])
        self.assertIn("$_siginfo.si_code == -6", script.read_text())
        self.assertNotIn("handle SIGTRAP nostop noprint pass", command)
        self.assertEqual(command[-2:], ["/a directory/indago_anti_signal_guard", "--observe"])
        with self.assertRaises(ValueError):
            command_for(replace(case, mode="unknown"), Path("/tmp"))

    def test_hash_known_vector(self):
        self.assertEqual(fnv1a(b"hello"), 0x4f9f2cab)


class ExecutionTests(unittest.TestCase):
    def test_exit_stdout_stderr_are_preserved(self):
        row = execute([sys.executable, "-c",
                       "import sys; print('out'); print('err', file=sys.stderr); sys.exit(7)"], 2)
        self.assertEqual(row["returncode"], 7)
        self.assertEqual(row["stdout"], "out\n")
        self.assertEqual(row["stderr"], "err\n")
        self.assertGreater(row["elapsed_ns"], 0)

    def test_missing_executable_is_recorded(self):
        row = execute(["/does-not-exist/anti-dynamic-test"], 2)
        self.assertIsNotNone(row["error"])
        self.assertIsNone(row["returncode"])

    def test_timeout_kills_descendant_and_preserves_output(self):
        script = ("import subprocess,sys,time; "
                  "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                  "print(p.pid,flush=True); time.sleep(30)")
        row = execute([sys.executable, "-c", script], 0.3)
        self.assertTrue(row["timed_out"])
        self.assertLess(row["elapsed_ns"], 5_000_000_000)
        child = int(row["stdout"].strip())
        stat = Path(f"/proc/{child}/stat")
        # A reparented zombie is dead but may remain briefly until init reaps it.
        for _ in range(50):
            if not stat.exists() or stat.read_text().split(") ", 1)[1].startswith("Z "):
                break
            time.sleep(0.01)
        else:
            self.fail("timed-out descendant is still running")

    def test_controlled_locale_and_loader_environment(self):
        script = "import os; print(os.getenv('LC_ALL')); print(os.getenv('LD_LIBRARY_PATH'))"
        with patch.dict(os.environ, {"LC_ALL": "invalid", "LD_LIBRARY_PATH": "/fake"}):
            row = execute([sys.executable, "-c", script], 2)
        self.assertEqual(row["stdout"], "C\nNone\n")


class StatisticsTests(unittest.TestCase):
    def test_nearest_rank_and_sample_standard_deviation(self):
        stats = distribution(list(range(1, 21)))
        self.assertEqual(stats["count"], 20)
        self.assertEqual(stats["median_ns"], 10.5)
        self.assertEqual(stats["p95_ns"], 19)
        self.assertAlmostEqual(stats["stdev_ns"], 5.9160797831)
        self.assertEqual(distribution([]), {"count": 0})
        self.assertEqual(distribution([8])["stdev_ns"], 0)

    def test_incomplete_groups_do_not_get_ratios(self):
        rows = []
        for mode, value in (("native", 10), ("gdb", 100)):
            for phase, status in (("warmup", "passed"), ("measure", "passed"), ("measure", "passed")):
                rows.append({"case": {"fixture": "ptrace_guard", "mode": mode},
                             "phase": phase, "status": status, "elapsed_ns": value})
        summary = summarize(rows, 2, ["native", "gdb"])
        self.assertEqual(summary["gdb_to_native_median_ratio"]["ptrace_guard"], 10)
        self.assertEqual(summary["groups"][0]["wall_time"]["count"], 2)
        self.assertFalse(summary["complete"])  # Other fixtures are missing.
        rows[0]["status"] = "failed"  # Even a warmup failure makes the group incomplete.
        self.assertNotIn("ptrace_guard", summarize(rows, 2, ["native", "gdb"])["gdb_to_native_median_ratio"])
        rows[0]["status"] = "passed"
        rows[1]["status"] = "unavailable"
        group = summarize(rows, 2, ["native", "gdb"])["groups"][0]
        self.assertEqual(group["wall_time"]["count"], 1)
        self.assertFalse(group["complete"])

    def test_shuffled_rounds_are_reproducible_and_keep_warmups(self):
        def fake(case, build, timeout):
            return {"case": {"fixture": case.fixture, "mode": case.mode},
                    "status": "passed", "elapsed_ns": 100}
        with patch("anti_dynamic_benchmark.run_case", side_effect=fake):
            with patch("builtins.print"):
                first = benchmark(Path("/tmp"), True, 1, 2, 1, 1729)
                second = benchmark(Path("/tmp"), True, 1, 2, 1, 1729)
        self.assertEqual(first["rows"], second["rows"])
        self.assertEqual(len(first["rows"]), 36)
        self.assertTrue(first["summary"]["complete"])
        self.assertTrue(all(group["wall_time"]["count"] == 2 for group in first["summary"]["groups"]))

    def test_numeric_bounds_reject_unbounded_or_invalid_runs(self):
        import argparse
        for converter, text in ((bounded_count, "0"), (bounded_count, "1001"),
                                (warmup_count, "-1"), (warmup_count, "101"),
                                (positive_float, "nan"), (positive_float, "inf"),
                                (positive_float, "0")):
            with self.subTest(text=text), self.assertRaises(argparse.ArgumentTypeError):
                converter(text)


if __name__ == "__main__":
    unittest.main()
