import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from wpguard.cli import run
from wpguard.database import classify_cron, classify_option, classify_post, classify_user, is_administrator
from wpguard.integrity import hashes_match
from wpguard.malware import content_findings, is_silence
from wpguard.models import Finding, Options, Site, WpConfig
from wpguard.remediate import plan
from wpguard.scan import scan_site
from wpguard.site import load_site
from wpguard.versioning import compare, is_affected
from wpguard.wpconfig import parse_wp_config, split_db_host


def glue(*parts: str) -> str:
    return "".join(parts)


SHELL_LINE = glue("ev", "al(", "base64_", "decode('abc'));")
ASSERT_LINE = glue("ass", "ert($_PO", "ST['cmd']);")


class VersionTests(unittest.TestCase):
    def test_php_order(self):
        self.assertEqual(compare("6.2", "6.2.1"), -1)
        self.assertEqual(compare("7.1", "7.1"), 0)
        self.assertEqual(compare("7.1.1", "7.1"), 1)
        self.assertEqual(compare("1.0", "1.0.0"), -1)
        self.assertEqual(compare("1.0rc1", "1.0"), -1)
        self.assertLess(compare("1.0", "1.0pl1"), 0)

    def test_affected_range(self):
        operator = {
            "min_version": None,
            "min_operator": None,
            "max_version": "7.1",
            "max_operator": "lt",
        }
        self.assertTrue(is_affected("6.9", operator))
        self.assertFalse(is_affected("7.1", operator))
        self.assertFalse(is_affected("7.1.0", operator))
        self.assertTrue(is_affected("1.2.3", {"unfixed": "1"}))

    def test_supply_chain_marker(self):
        from wpguard.vulns import findings_from_vulnerabilities
        found = findings_from_vulnerabilities(
            {"supplychain": [{"verdict": "malicious", "name": "Hijack"}]},
            [],
            "1.0",
            "plugin:demo",
            "Demo",
        )
        self.assertEqual(found[0].code, "supply-chain")
        self.assertEqual(found[0].severity, "critical")


class ConfigTests(unittest.TestCase):
    def test_defines_and_host(self):
        text = glue(
            "<?php\n",
            "define('DB_NAME', 'my\\'db');\n",
            "define('DB_PASSWORD', 's3cret-horse-battery-staple');\n",
            "define('DB_HOST', 'localhost:3307');\n",
            "define('DB_USER', 'wp');\n",
            "$table_prefix = 'wp_';\n",
        )
        config = parse_wp_config(text)
        self.assertEqual(config.db_name, "my'db")
        self.assertEqual(config.db_password, "s3cret-horse-battery-staple")
        self.assertEqual(config.db_user, "wp")
        self.assertEqual(split_db_host("localhost:3307"), ("localhost", 3307, None))
        self.assertEqual(split_db_host("localhost:/tmp/mysql.sock")[2], "/tmp/mysql.sock")
        self.assertNotIn("s3cret-horse-battery-staple", repr(config))


class MalwareTests(unittest.TestCase):
    def test_benign_plugin_is_quiet(self):
        text = """<?php
        /**
         * Plugin Name: Hello Dolly
         * Version: 1.7.2
         */
        function example_init() {
            $value = isset($_POST['name']) ? $_POST['name'] : '';
            update_option('example', $value);
        }
        """
        found = content_findings(
            "wp-content/plugins/hello/hello.php", "hello.php", ".php", text, Path("hello.php")
        )
        self.assertEqual(found, [])

    def test_obfuscated_call_is_critical_in_uploads(self):
        text = "<?php " + SHELL_LINE + " " + ASSERT_LINE
        found = content_findings("wp-content/uploads/a.php", "a.php", ".php", text, Path("a.php"))
        codes = {item.code for item in found}
        self.assertIn("php-eval-decode", codes)
        self.assertIn("php-assert-input", codes)
        matched = next(item for item in found if item.code == "php-eval-decode")
        self.assertEqual(matched.severity, "critical")

    def test_silence(self):
        self.assertTrue(is_silence("<?php\n// Silence is golden.\n"))


class DatabaseRuleTests(unittest.TestCase):
    def test_hidden_admin_and_options(self):
        caps = 'a:1:{s:13:"administrator";b:1;}'
        self.assertTrue(is_administrator(caps))
        found = classify_user(
            "55e7183bded6e0fa810c47b04e65ea6e",
            "55e7183bded6e0fa810c47b04e65ea6e@113c971f77f8.com",
            caps,
            "2024-08-01",
        )
        self.assertEqual(found[0].severity, "critical")
        self.assertEqual(classify_option("siteurl", 0, 0, 0, 0, 20), [])
        hex_option = classify_option("55e7183bded6e0fa810c47b04e65ea6e", 12, 0, 0, 0, 400)
        self.assertEqual(hex_option[0].code, "hex-option")
        post = classify_post(3, "post", "Home", 0, 4, 0, 0, 0, 0)
        self.assertEqual(post[0].severity, "critical")
        self.assertEqual(classify_cron(0, 0, 8, 200)[0].code, "cron-payload")


class IntegrityTests(unittest.TestCase):
    def test_hash_list(self):
        self.assertTrue(hashes_match("aaa", "bbb", ["aaa", "ccc"], []))
        self.assertFalse(hashes_match("aaa", "bbb", ["ddd"], ["eee"]))


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_site(root: Path) -> None:
    write(root / "wp-config.php", """<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wp');
define('DB_PASSWORD', 's3cret-horse-battery-staple');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
""")
    write(root / "wp-includes" / "version.php", "<?php $wp_version = '6.4.2';\n")
    write(root / "wp-content" / "plugins" / "hello-dolly" / "hello.php", """<?php
/**
 * Plugin Name: Hello Dolly
 * Version: 1.7.2
 */
function hello_dolly() { return 'hello'; }
""")
    write(root / "wp-content" / "themes" / "demo" / "style.css", "/*\nTheme Name: Demo\nVersion: 1.0\n*/\n")
    write(root / "wp-content" / "uploads" / "index.php", "<?php\n// Silence is golden.\n")
    write(root / "wp-content" / "uploads" / "shell.php", "<?php\n" + SHELL_LINE + "\n")
    write(root / "wp-content" / "uploads" / "photo.php.jpg", "not an image")
    write(root / "wp-config.php.bak", "<?php define('DB_PASSWORD', 's3cret-horse-battery-staple');\n")
    write(root / ".htaccess", "php_value auto_prepend_file /tmp/a.php\n")
    write(root / "index.php", "<?php require __DIR__ . '/wp-blog-header.php';\n")


class ScanTests(unittest.TestCase):
    def test_offline_scan_finds_planted_files_and_hides_password(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_site(root)
            site = load_site(root)
            self.assertEqual(site.core_version, "6.4.2")
            self.assertEqual(site.plugins[0].slug, "hello-dolly")
            self.assertEqual(site.themes[0].version, "1.0")
            report = scan_site(site, Options(
                offline=True,
                quiet=True,
                workers=1,
                sections={"surface", "malware"},
            ), None)
            codes = {item.code for item in report.findings}
            self.assertIn("php-eval-decode", codes)
            self.assertIn("php-in-uploads", codes)
            self.assertIn("double-extension", codes)
            self.assertIn("config-backup", codes)
            self.assertIn("config-auto-prepend", codes)
            upload_index = [
                item.code for item in report.findings
                if item.location.endswith("uploads/index.php")
            ]
            self.assertNotIn("php-in-uploads", upload_index)
            blob = json.dumps([item.to_dict() for item in report.findings], ensure_ascii=False)
            self.assertNotIn("s3cret-horse-battery-staple", blob)
            buffer = io.StringIO()
            report_file = root / "report.json"
            with redirect_stdout(buffer):
                code = run([
                    "malware-scan", str(root), "--offline", "--format", "json",
                    "--workers", "1", "--min-severity", "high",
                    "--output", str(report_file),
                ])
            self.assertEqual(code, 2)
            payload = json.loads(buffer.getvalue())
            self.assertGreaterEqual(payload["sites"][0]["summary"]["critical"], 1)
            self.assertNotIn("s3cret-horse-battery-staple", buffer.getvalue())
            self.assertNotIn("s3cret-horse-battery-staple", report_file.read_text(encoding="utf-8"))

    def test_remediate_plan_does_not_touch_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shell = root / "wp-content" / "uploads" / "shell.php"
            write(shell, "<?php\n" + SHELL_LINE + "\n")
            finding = Finding(
                severity="critical",
                category="malware",
                code="php-in-uploads",
                title="PHP in uploads",
                location="wp-content/uploads/shell.php",
                absolute_path=str(shell),
            )
            site = Site(root, WpConfig(None), "6.4.2", [], [], "en_US")
            actions = plan([finding], site, quarantine=True)
            self.assertEqual(len(actions), 1)
            self.assertEqual(actions[0].kind, "quarantine")
            self.assertTrue(shell.exists())
            self.assertFalse(actions[0].done)

    def test_core_mismatch_is_restore(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "wp-includes" / "load.php"
            write(target, "<?php echo 1;\n")
            digest = hashlib.md5(b"clean").hexdigest()
            finding = Finding(
                severity="critical",
                category="integrity",
                code="core-mismatch",
                title="core changed",
                location="wp-includes/load.php",
                absolute_path=str(target),
                details={
                    "kind": "core",
                    "version": "6.4.2",
                    "expected_md5": [digest],
                    "expected_sha256": [],
                },
            )
            site = Site(root, WpConfig(None), "6.4.2", [], [], "en_US")
            actions = plan([finding], site, quarantine=True)
            self.assertEqual([item.kind for item in actions], ["restore"])


class BackgroundTests(unittest.TestCase):
    def test_child_command_drops_background_and_sets_report(self):
        from wpguard.background import child_argv, default_report_path, write_placeholder
        output = default_report_path()
        self.assertEqual(output.name, "wp-guard-report.txt")
        command = child_argv(["scan", "/var/www", "--background", "--workers", "1"], output)
        self.assertNotIn("--background", command)
        self.assertIn("--output", command)
        self.assertIn("--quiet", command)
        self.assertEqual(command[1:3], ["-m", "wpguard"])
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.txt"
            write_placeholder(report, "/home/user/public_html")
            text = report.read_text(encoding="utf-8")
            self.assertIn("Проверка ещё идёт", text)
            self.assertIn("/home/user/public_html", text)

    def test_detached_process_survives_parent(self):
        import os
        import sys
        import time
        from wpguard.background import launch_detached, process_alive
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            marker = folder / "done.txt"
            env = os.environ.copy()
            env["MARKER"] = str(marker)
            pid = launch_detached(
                [sys.executable, "-c", "open(__import__('os').environ['MARKER'], 'w', encoding='utf-8').write('ok')"],
                folder / "job.log",
                env,
            )
            self.assertGreater(pid, 0)
            for _ in range(50):
                if marker.is_file():
                    break
                time.sleep(0.05)
            self.assertEqual(marker.read_text(encoding="utf-8"), "ok")
            for _ in range(50):
                if not process_alive(pid):
                    break
                time.sleep(0.05)
            self.assertFalse(process_alive(pid))


if __name__ == "__main__":
    unittest.main()
