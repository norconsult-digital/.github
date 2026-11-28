import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "dotnet-cd-jobs.yml"
BASH = os.environ.get("TEST_BASH") or shutil.which("bash")


def step_script(name):
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"      - name: {name}")
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("      - name: ")),
        len(lines),
    )
    run = lines.index("        run: |", start, end) + 1
    script = []
    for line in lines[run:end]:
        if line and not line.startswith("          "):
            break
        script.append(line[10:] if line else "")
    return "\n".join(script)


@unittest.skipUnless(BASH, "Bash is required")
class MigrationSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "migrations-bundle.exe"
        self.bundle.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$2\" >> \"$INVOCATIONS\"\n"
            "if [[ \"$2\" == *fail-db* ]]; then exit 17; fi\n",
            encoding="utf-8",
        )
        self.bundle.chmod(0o755)
        self.az = self.root / "az"
        self.az.write_text('#!/usr/bin/env bash\nprintf "%s" "$AZ_CONNECTION"\n', encoding="utf-8")
        self.az.chmod(0o755)
        self.summary = self.root / "summary"
        self.invocations = self.root / "invocations"
        self.env = os.environ.copy()
        self.env.update(
            {
                "RUNNER_TEMP": self.root.as_posix(),
                "GITHUB_ENV": (self.root / "github-env").as_posix(),
                "GITHUB_STEP_SUMMARY": self.summary.as_posix(),
                "INVOCATIONS": self.invocations.as_posix(),
                "PATH": self.root.as_posix() + os.pathsep + os.environ.get("PATH", ""),
                "MIGRATION_SUMMARY": "true",
                "TIMEOUT": "0",
                "ENDPOINT": "test",
                "KEY": "test",
                "LABEL": "test",
            }
        )
        result = self.run_script("Prepare migration summary")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.env["MIGRATION_SUMMARY_HELPER"] = Path(self.env["GITHUB_ENV"]).read_text(
            encoding="utf-8"
        ).strip().split("=", 1)[1]

    def run_script(self, name):
        return subprocess.run(
            [BASH, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step_script(name)],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
        )

    def summary_text(self):
        return self.summary.read_text(encoding="utf-8") if self.summary.exists() else ""

    def test_all_five_paths_report_a_successful_command(self):
        paths = [
            "Set executable permission for migrations-bundle and run",
            "Run migrations with the connection from App Configuration",
            "Run migrations for multiple DB connections",
            "Run migrations for optionalDbConnection1 if provided",
            "Run migrations for optionalDbConnection2 if provided",
        ]
        connection = 'Server=example;Password="secret;with-semicolon";Initial Catalog=test-db;'
        self.env.update(
            {
                "CONNECTION": connection,
                "AZ_CONNECTION": connection,
                "DB_CONNECTIONS": json.dumps([connection]),
            }
        )
        for path in paths:
            with self.subTest(path=path):
                result = self.run_script(path)
                self.assertEqual(result.returncode, 0, result.stderr)
        summary = self.summary_text()
        self.assertEqual(summary.count("Migration command completed"), 5)
        self.assertEqual(summary.count("`test-db`"), 5)
        self.assertNotIn("secret", summary)
        self.assertNotIn("Server=", summary)
        self.assertIn("new migrations may not have been applied", summary)

    def test_failure_stops_after_failing_database_and_preserves_exit_code(self):
        connections = [
            "Server=example;Database=first-db",
            "Server=example;Database=fail-db",
            "Server=example;Database=not-run-db",
        ]
        self.env["DB_CONNECTIONS"] = json.dumps(connections)
        result = self.run_script("Run migrations for multiple DB connections")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual(self.invocations.read_text(encoding="utf-8").splitlines(), connections[:2])
        summary = self.summary_text()
        self.assertIn("`first-db`: Migration command completed", summary)
        self.assertIn("`fail-db`: Migration command failed (exit 17)", summary)
        self.assertNotIn("not-run-db", summary)

    def test_all_five_paths_report_and_preserve_a_failed_command(self):
        paths = [
            "Set executable permission for migrations-bundle and run",
            "Run migrations with the connection from App Configuration",
            "Run migrations for multiple DB connections",
            "Run migrations for optionalDbConnection1 if provided",
            "Run migrations for optionalDbConnection2 if provided",
        ]
        connection = "Server=example;Database=fail-db"
        self.env.update(
            {
                "CONNECTION": connection,
                "AZ_CONNECTION": connection,
                "DB_CONNECTIONS": json.dumps([connection]),
            }
        )
        for path in paths:
            with self.subTest(path=path):
                result = self.run_script(path)
                self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual(self.summary_text().count("`fail-db`: Migration command failed (exit 17)"), 5)

    def test_unsafe_or_ambiguous_names_are_not_exposed(self):
        connections = [
            "Server=example;Password=secret;Database=good-db",
            'Server=example;Password=secret;Database="bad;Password=secret"',
            "Server=example;Password=secret;Database=first;Initial Catalog=second",
            "Server=example;Password=secret",
            'Server=example;Password="unclosed;Database=secret',
        ]
        self.env["DB_CONNECTIONS"] = json.dumps(connections)
        result = self.run_script("Run migrations for multiple DB connections")
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = self.summary_text()
        self.assertIn("`good-db`", summary)
        self.assertEqual(summary.count("`unknown`"), 4)
        self.assertNotIn("secret", summary)

    def test_missing_parser_does_not_change_migration_result(self):
        fake_pwsh = self.root / "pwsh"
        fake_pwsh.write_text("#!/usr/bin/env bash\nexit 127\n", encoding="utf-8")
        fake_pwsh.chmod(0o755)
        self.env["CONNECTION"] = "Server=example;Database=fail-db;Password=secret"
        result = self.run_script("Set executable permission for migrations-bundle and run")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertIn("Could not safely determine the migration database name", result.stdout)
        self.assertIn("`unknown`: Migration command failed (exit 17)", self.summary_text())
        self.assertNotIn("secret", self.summary_text())

    def test_summary_write_failure_does_not_change_migration_result(self):
        self.env["GITHUB_STEP_SUMMARY"] = self.root.as_posix()
        self.env["CONNECTION"] = "Server=example;Database=fail-db"
        result = self.run_script("Set executable permission for migrations-bundle and run")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertIn("Could not write the migration summary", result.stdout)

    def test_disabled_summary_preserves_failure_and_writes_nothing(self):
        self.env["MIGRATION_SUMMARY"] = "false"
        self.env["DB_CONNECTIONS"] = json.dumps(
            ["Server=example;Database=fail-db", "Server=example;Database=not-run-db"]
        )
        result = self.run_script("Run migrations for multiple DB connections")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual(len(self.invocations.read_text(encoding="utf-8").splitlines()), 1)
        self.assertEqual(self.summary_text(), "")


if __name__ == "__main__":
    unittest.main()
