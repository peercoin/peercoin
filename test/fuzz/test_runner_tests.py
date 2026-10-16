#!/usr/bin/env python3
# Copyright (c) 2026 The Peercoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise fuzz runner cleanup with real subprocesses, without a fuzz build."""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest


@unittest.skipUnless(os.name == 'posix', 'The executable fixture uses a POSIX shebang')
class FuzzRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(prefix='peercoin-fuzz-runner-')
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)
        (self.root / 'fuzz').mkdir()
        self.runner = self.root / 'fuzz' / 'test_runner.py'
        shutil.copyfile(Path(__file__).with_name('test_runner.py'), self.runner)
        (self.root / 'config.ini').write_text(
            f'[components]\nENABLE_FUZZ_BINARY=true\n'
            f'[environment]\nSRCDIR={self.root}\nBUILDDIR={self.root}\n',
            encoding='utf-8',
        )
        self.fuzz = self.root / 'fake_fuzz.py'
        self.fuzz.write_text(f'#!{sys.executable}\n' + '''
import json
import os
from pathlib import Path
import subprocess
import sys
import time

root = Path(os.environ['FIXTURE_ROOT'])
if 'PRINT_ALL_FUZZ_TARGETS_AND_ABORT' in os.environ:
    print(os.environ['FIXTURE_TARGETS'])
    sys.exit(0)
if '-help=1' in sys.argv:
    if os.environ.get('FIXTURE_LIBFUZZER'):
        print('libFuzzer', file=sys.stderr)
    sys.exit(0)
target = os.environ['FUZZ']
def record_pid(name, pid):
    pending = root / (name + '.pid.tmp')
    pending.write_text(str(pid))
    pending.replace(root / (name + '.pid'))
record_pid(target, os.getpid())
(root / (target + '.args')).write_text(json.dumps(sys.argv[1:]))
if target == 'a_hang':
    if os.environ.get('FIXTURE_CHILD'):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        record_pid('child', child.pid)
    print('partial output from hanging target', file=sys.stderr, flush=True)
    if os.environ.get('FIXTURE_EXIT_PARENT'):
        sys.exit(0)
    time.sleep(60)
elif target == 'b_fail':
    deadline = time.monotonic() + 5
    while not (root / 'a_hang.args').exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    print('fixture failure', file=sys.stderr)
    sys.exit(7)
elif target.startswith('queued'):
    time.sleep(60)
print('#1 DONE', file=sys.stderr)
''', encoding='utf-8')
        self.fuzz.chmod(0o755)
        self.corpus = self.root / 'corpus'
        self.env = os.environ | {'BITCOINFUZZ': str(self.fuzz), 'FIXTURE_ROOT': str(self.root)}
        self.addCleanup(self.kill_remaining_processes)

    def kill_remaining_processes(self):
        # Bound regressions in cleanup itself so a failing test leaves no workers.
        for pid_file in self.root.glob('*.pid'):
            pid = int(pid_file.read_text())
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def command(self, *options):
        return [sys.executable, str(self.runner), '-j2', *options, str(self.corpus)]

    def run_runner(self, targets, *options, **env):
        self.env.update(FIXTURE_TARGETS='\n'.join(targets), **env)
        result = subprocess.run(self.command(*options), env=self.env, capture_output=True, text=True, timeout=10)
        self.assert_processes_stopped()
        return result

    def assert_processes_stopped(self):
        for pid_file in self.root.glob('*.pid'):
            status = subprocess.run(
                ['ps', '-p', pid_file.read_text(), '-o', 'stat='],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            self.assertTrue(not status or status.startswith('Z'), f'{pid_file.stem} still running: {status}')

    def test_success_and_progress(self):
        result = self.run_runner(['first', 'second'])
        self.assertEqual(result.returncode, 0, result.stderr)
        for target in ['first', 'second']:
            self.assertIn(f'Starting fuzz target {target}', result.stderr)
            self.assertIn(f'Finished fuzz target {target} (exit code 0)', result.stderr)

    def test_libfuzzer_corpus_replay(self):
        (self.corpus / 'first').mkdir(parents=True)
        (self.corpus / 'first' / 'seed').write_bytes(b'input')
        result = self.run_runner(['first'], FIXTURE_LIBFUZZER='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Summary:', result.stdout)
        self.assertEqual(json.loads((self.root / 'first.args').read_text()), ['-runs=1', str(self.corpus / 'first')])

    def test_libfuzzer_empty_corpus(self):
        result = self.run_runner(['first'], '--empty_min_time=1', FIXTURE_LIBFUZZER='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.root / 'first.args').read_text()), ['-max_total_time=1'])

    def test_timeout_preserves_output(self):
        result = self.run_runner(['a_hang'], '--timeout=0.5', FIXTURE_CHILD='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Fuzz target a_hang timed out after 0.5 seconds', result.stderr)
        self.assertIn('partial output from hanging target', result.stderr)

    def test_timeout_kills_child_after_parent_exits(self):
        result = self.run_runner(['a_hang'], '--timeout=0.5', FIXTURE_CHILD='1', FIXTURE_EXIT_PARENT='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Fuzz target a_hang timed out', result.stderr)

    def test_failure_stops_active_and_queued_targets(self):
        targets = ['a_hang', 'b_fail'] + [f'queued{i:02}' for i in range(20)]
        result = self.run_runner(targets)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('fixture failure', result.stderr)
        self.assertIn('Failure generated from target with exit code 7', result.stderr)
        self.assertLess(len(list(self.root.glob('queued*.pid'))), 20)

    def test_failure_cleanup_in_generate_and_merge_modes(self):
        (self.root / 'merge').mkdir()
        for option in ['--generate', f'--m_dir={self.root / "merge"}']:
            with self.subTest(option=option):
                for marker in self.root.glob('*.args'):
                    marker.unlink()
                result = self.run_runner(['a_hang', 'b_fail'], option, FIXTURE_LIBFUZZER='1')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Starting fuzz target a_hang', result.stderr)

    def test_interrupt_stops_active_target(self):
        self.env['FIXTURE_TARGETS'] = 'a_hang'
        with subprocess.Popen(self.command(), env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as runner:
            try:
                deadline = time.monotonic() + 5
                while not (self.root / 'a_hang.args').exists():
                    if time.monotonic() > deadline:
                        self.fail('Hanging fixture did not start')
                    time.sleep(0.01)
                runner.send_signal(signal.SIGINT)
                _, stderr = runner.communicate(timeout=5)
                self.assertNotEqual(runner.returncode, 0, stderr)
                self.assert_processes_stopped()
            finally:
                if runner.poll() is None:
                    runner.kill()

    def test_invalid_timeout(self):
        for timeout in ['0', '-1', 'nan', 'inf']:
            with self.subTest(timeout=timeout):
                result = self.run_runner(['first'], f'--timeout={timeout}')
                self.assertEqual(result.returncode, 2)
                self.assertIn('--timeout must be a finite positive number', result.stderr)


if __name__ == '__main__':
    unittest.main()
