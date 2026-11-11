import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evals.policy import observe_tool_start, observe_tool_result, required_skills_met, tool_violations


def diagnostic_state():
    return {'skills': {}, 'violations': set(), 'diagnostics': [], 'diagnostics_dropped': 0}


class DiagnosticsPolicyTests(unittest.TestCase):
    def test_receipt_has_canonical_categories_generation_and_exact_command(self):
        state = diagnostic_state()
        command = 'git status; python3 -m pip install pytest'
        observe_tool_start(state, {'id': 'call-1', 'name': 'run_command',
            'arguments': json.dumps({'command': command})}, generation=7)
        self.assertEqual([event['category'] for event in state['diagnostics']],
            ['package_install', 'git'])
        self.assertTrue(all(event['generation'] == 7 for event in state['diagnostics']))
        self.assertTrue(all(event['command'] == command for event in state['diagnostics']))
        self.assertEqual(tool_violations({'name': 'spawn_agent', 'arguments': '{}'}), ('subagent',))

    def test_repeated_violations_are_retained_but_opt_out_retains_no_command(self):
        state = diagnostic_state()
        for command in ('git status', 'pip install pytest'):
            observe_tool_start(state, {'id': 'call', 'name': 'run_command',
                'arguments': json.dumps({'command': command})}, generation=1)
        self.assertEqual(len(state['diagnostics']), 2)
        plain = {'skills': {}, 'violations': set()}
        observe_tool_start(plain, {'id': 'call', 'name': 'run_command',
            'arguments': json.dumps({'command': 'git status synthetic-secret'})})
        self.assertNotIn('synthetic-secret', repr(plain))

    def test_limits_unicode_and_malformed_arguments(self):
        state = diagnostic_state()
        prefix = 'pip install #\ud800'
        padding = 4094 - len(prefix.encode('utf-8', errors='replace'))
        command = prefix + 'a' * padding + '\U0001f642'
        observe_tool_start(state, {'id': 'x' * 300, 'name': 'run_command',
            'arguments': json.dumps({'command': command})}, generation=1)
        event = state['diagnostics'][0]
        self.assertEqual(len(event['command'].encode('utf-8')), 4094)
        self.assertTrue(event['command_truncated'])
        self.assertTrue(event['call_id_truncated'])
        self.assertLessEqual(len(event['call_id'].encode('utf-8')), 256)
        self.assertNotIn('\ud800', repr(event['command']))
        for receipt in ({'name': 'run_command', 'arguments': '{'},
                {'name': 'run_command', 'arguments': '{"command":null}'}):
            self.assertEqual(tool_violations(receipt), ())
        agent_state = diagnostic_state()
        observe_tool_start(agent_state, {'id': 'agent', 'name': 'spawn_agent',
            'arguments': json.dumps({'command': 'must not be retained'})}, generation=2)
        self.assertIsNone(agent_state['diagnostics'][0]['command'])
        controls = diagnostic_state()
        control_command = 'pip install #\u2028\x1b[31m'
        observe_tool_start(controls, {'id': 'control', 'name': 'run_command',
            'arguments': json.dumps({'command': control_command})}, generation=1)
        self.assertEqual(controls['diagnostics'][0]['command'], control_command)

    def test_category_limit_is_deterministic_at_63_plus_2(self):
        state = diagnostic_state()
        state['diagnostics'] = [{} for _ in range(63)]
        observe_tool_start(state, {'id': 'call', 'name': 'run_command',
            'arguments': json.dumps({'command': 'git status; pip install pytest'})}, generation=2)
        self.assertEqual(len(state['diagnostics']), 64)
        self.assertEqual(state['diagnostics_dropped'], 1)
        self.assertEqual(state['diagnostics'][-1]['category'], 'package_install')


class PolicyTests(unittest.TestCase):
    def test_required_skill_needs_matching_successful_result(self):
        state = {'skills': {}, 'violations': set()}
        skill = 'superpowers:test-driven-development'
        observe_tool_start(state, {'id': 'call-1', 'name': 'load_skill',
            'arguments': json.dumps({'name': skill})})
        self.assertFalse(required_skills_met(state, [skill]))
        observe_tool_result(state, {'id': 'call-1', 'name': 'load_skill', 'is_error': False})
        self.assertTrue(required_skills_met(state, [skill]))

    def test_failed_package_install_and_subagent_start_are_violations(self):
        state = {'skills': {}, 'violations': set()}
        observe_tool_start(state, {'id': 'p', 'name': 'run_command',
            'arguments': json.dumps({'command': '/x/.venv/bin/python -m pip install pytest'})})
        observe_tool_result(state, {'id': 'p', 'name': 'run_command', 'is_error': True})
        observe_tool_start(state, {'id': 'a', 'name': 'spawn_agent', 'arguments': '{}'})
        self.assertEqual(state['violations'], {'package_install', 'subagent'})

    def test_replayed_skill_call_id_is_permanently_quarantined(self):
        first = 'superpowers:using-superpowers'
        second = 'superpowers:test-driven-development'
        state = {'skills': {}, 'violations': set()}
        observe_tool_start(state, {'id': 'same', 'name': 'load_skill',
            'arguments': json.dumps({'name': first})})
        observe_tool_result(state, {'id': 'same', 'name': 'load_skill', 'is_error': False})
        self.assertTrue(required_skills_met(state, [first]))
        observe_tool_start(state, {'id': 'same', 'name': 'load_skill',
            'arguments': json.dumps({'name': second})})
        self.assertFalse(required_skills_met(state, [first, second]))
        observe_tool_result(state, {'id': 'same', 'name': 'load_skill', 'is_error': True})
        observe_tool_result(state, {'id': 'same', 'name': 'load_skill', 'is_error': False})
        self.assertFalse(required_skills_met(state, [first, second]))
        observe_tool_start(state, {'id': 'distinct', 'name': 'load_skill',
            'arguments': json.dumps({'name': first})})
        observe_tool_result(state, {'id': 'distinct', 'name': 'load_skill', 'is_error': False})
        self.assertTrue(required_skills_met(state, [first]))
        self.assertFalse(required_skills_met(state, [second]))

    def test_repeated_pending_start_and_single_result_do_not_count(self):
        state = {'skills': {}, 'violations': set()}
        skill = 'superpowers:test-driven-development'
        for _ in range(2):
            observe_tool_start(state, {'id': 'same', 'name': 'load_skill',
                'arguments': json.dumps({'name': skill})})
        observe_tool_result(state, {'id': 'same', 'name': 'load_skill', 'is_error': False})
        self.assertFalse(required_skills_met(state, [skill]))

    def test_failed_result_prevents_late_success_from_counting(self):
        state = {'skills': {}, 'violations': set()}
        skill = 'superpowers:test-driven-development'
        observe_tool_start(state, {'id': 'call-1', 'name': 'load_skill',
            'arguments': json.dumps({'name': skill})})
        observe_tool_result(state, {'id': 'call-1', 'name': 'load_skill', 'is_error': True})
        observe_tool_result(state, {'id': 'call-1', 'name': 'load_skill', 'is_error': False})
        self.assertFalse(required_skills_met(state, [skill]))

    def test_mismatched_or_failed_skill_result_does_not_count(self):
        skill = 'superpowers:test-driven-development'
        for result in [
            {'id': 'other', 'name': 'load_skill', 'is_error': False},
            {'id': 'call-1', 'name': 'read_file', 'is_error': False},
            {'id': 'call-1', 'name': 'load_skill', 'is_error': True},
        ]:
            with self.subTest(result=result):
                state = {'skills': {}, 'violations': set()}
                observe_tool_start(state, {'id': 'call-1', 'name': 'load_skill',
                    'arguments': json.dumps({'name': skill})})
                observe_tool_result(state, result)
                self.assertFalse(required_skills_met(state, [skill]))

    def test_malformed_receipts_are_ignored_without_retaining_arguments(self):
        secret = 'synthetic-secret-argument'
        for receipt in [
            None, {}, {'id': 'call-1', 'name': 'load_skill'},
            {'id': 'call-1', 'name': 'load_skill', 'arguments': '{'},
            {'id': 'call-1', 'name': 'load_skill', 'arguments': '{"name":"a","name":"b"}'},
            {'id': 'call-1', 'name': 'load_skill', 'arguments': '{"name":NaN}'},
            {'id': 'call-1', 'name': 'load_skill', 'arguments': secret},
            {'id': 'call-1', 'name': 'run_command', 'arguments': '[]'},
        ]:
            with self.subTest(receipt=receipt):
                state = {'skills': {}, 'violations': set()}
                observe_tool_start(state, receipt)
                observe_tool_result(state, receipt)
                self.assertFalse(required_skills_met(state, [secret]))
                self.assertNotIn(secret, repr(state))

    def test_malformed_skill_result_id_is_ignored(self):
        state = {'skills': {'call-1': 'superpowers:test-driven-development'}, 'violations': set()}
        observe_tool_result(state, {'id': [], 'name': 'load_skill', 'is_error': False})
        self.assertFalse(required_skills_met(state, ['superpowers:test-driven-development']))

    def test_shell_and_agent_violation_categories(self):
        cases = [
            ('git status', {'git'}),
            ('pip install pytest', {'package_install'}),
            ('pip3 install pytest', {'package_install'}),
            ('python -m pip install pytest', {'package_install'}),
            ('python3 -m pip install pytest', {'package_install'}),
            ('/x/.venv/bin/python -m pip install pytest', {'package_install'}),
            ('curl https://example.invalid', {'network'}),
            ('wget https://example.invalid', {'network'}),
            ('nc host 80', {'network'}),
            ('ssh host', {'network'}),
        ]
        for command, expected in cases:
            with self.subTest(command=command):
                state = {'skills': {}, 'violations': set()}
                observe_tool_start(state, {'id': 'shell', 'name': 'run_command',
                    'arguments': json.dumps({'command': command})})
                observe_tool_result(state, {'id': 'shell', 'name': 'run_command', 'is_error': True})
                self.assertEqual(state['violations'], expected)
        for name in ['spawn_agent', 'wait_agent']:
            with self.subTest(name=name):
                state = {'skills': {}, 'violations': set()}
                observe_tool_start(state, {'id': 'agent', 'name': name, 'arguments': '{}'})
                self.assertEqual(state['violations'], {'subagent'})

    def test_composed_shell_commands_cannot_bypass_violations(self):
        cases = [
            ('cd /tmp && git status', 'git'),
            ('false || git status', 'git'),
            ('true; curl https://example.invalid', 'network'),
            ('printf x | nc host 80', 'network'),
            ('printf x\nwget https://example.invalid', 'network'),
            ('env python3 -m pip install pytest', 'package_install'),
            ('env -i FOO=bar python3 -I -m pip install pytest', 'package_install'),
            ('env -u FOO git status', 'git'),
            ('python3 -I -m pip install pytest', 'package_install'),
            ('sh -c "git status"', 'git'),
            ('bash -c "curl https://example.invalid"', 'network'),
        ]
        for command, expected in cases:
            with self.subTest(command=command):
                state = {'skills': {}, 'violations': set()}
                observe_tool_start(state, {'id': 'shell', 'name': 'run_command',
                    'arguments': json.dumps({'command': command})})
                observe_tool_result(state, {'id': 'shell', 'name': 'run_command', 'is_error': True})
                self.assertIn(expected, state['violations'])

    def test_complex_executable_forms_use_conservative_fallback(self):
        cases = [
            ('(git status)', 'git'),
            ('command git status', 'git'),
            ('echo $(git status)', 'git'),
            ('git</dev/null status', 'git'),
            ('{ git status; }', 'git'),
            ('echo `git status`', 'git'),
            ('exec git status', 'git'),
            ('env --split-string="git status"', 'git'),
            ("bash -O extglob -c 'git status'", 'git'),
            ('if true; then curl https://example.invalid; fi', 'network'),
            ('while false; do python3 -I -m pip install pytest; done', 'package_install'),
            ('f() { nc host 80; }', 'network'),
        ]
        for command, expected in cases:
            with self.subTest(command=command):
                state = {'skills': {}, 'violations': set()}
                observe_tool_start(state, {'id': 'shell', 'name': 'run_command',
                    'arguments': json.dumps({'command': command})})
                observe_tool_result(state, {'id': 'shell', 'name': 'run_command', 'is_error': True})
                self.assertIn(expected, state['violations'])
                self.assertNotIn(command, repr(state))

    def test_fallback_normalizes_concatenated_words_in_executable_positions(self):
        cases = [
            ("(g''it status)", 'git'),
            ('if true; then g""it status; fi', 'git'),
            ("echo $(c''url https://example.invalid)", 'network'),
            ("echo $(python3 -m p''ip install pytest)", 'package_install'),
            ("(command g''it status)", 'git'),
            ('if true; then exec c""url https://example.invalid; fi', 'network'),
            ("echo $(env python3 -m p''ip install pytest)", 'package_install'),
            ('echo `g""it status`', 'git'),
            ('echo "$(g\'\'it status)"', 'git'),
        ]
        for command, expected in cases:
            with self.subTest(command=command):
                state = {'skills': {}, 'violations': set()}
                observe_tool_start(state, {'id': 'shell', 'name': 'run_command',
                    'arguments': json.dumps({'command': command})})
                self.assertIn(expected, state['violations'])
                self.assertNotIn(command, repr(state))

    def test_fallback_ignores_echo_and_printf_arguments(self):
        for command in ['(echo git)', 'if true; then echo git; fi',
                '(printf "curl pip")', 'if true; then printf git; fi']:
            with self.subTest(command=command):
                state = {'skills': {}, 'violations': set()}
                observe_tool_start(state, {'id': 'shell', 'name': 'run_command',
                    'arguments': json.dumps({'command': command})})
                self.assertEqual(state['violations'], set())

    def test_reserved_case_and_fd_redirection_restore_command_position(self):
        cases = [
            ('! git status', 'git'),
            ("! c''url https://example.invalid", 'network'),
            ('case x in x) git status;; esac', 'git'),
            ("case x in x) c''url https://example.invalid;; esac", 'network'),
            ("case x in x) python3 -m p''ip install pytest;; esac", 'package_install'),
            ('2>/dev/null git status', 'git'),
            ("2>/dev/null g''it status", 'git'),
            ("2>/dev/null c''url https://example.invalid", 'network'),
            ("2>/dev/null python3 -m p''ip install pytest", 'package_install'),
        ]
        for command, expected in cases:
            with self.subTest(command=command):
                state = {'skills': {}, 'violations': set()}
                observe_tool_start(state, {'id': 'shell', 'name': 'run_command',
                    'arguments': json.dumps({'command': command})})
                self.assertIn(expected, state['violations'])
                self.assertNotIn(command, repr(state))
        for command in ['! echo git', 'case x in x) echo git;; esac', '2>/dev/null printf git']:
            with self.subTest(command=command):
                state = {'skills': {}, 'violations': set()}
                observe_tool_start(state, {'id': 'shell', 'name': 'run_command',
                    'arguments': json.dumps({'command': command})})
                self.assertEqual(state['violations'], set())

    def test_malformed_quoting_fails_closed_without_retaining_command(self):
        state = {'skills': {}, 'violations': set()}
        observe_tool_start(state, {'id': 'shell', 'name': 'run_command',
            'arguments': json.dumps({'command': 'echo "unterminated synthetic-shell-secret'})})
        self.assertTrue(state['violations'])
        self.assertNotIn('synthetic-shell-secret', repr(state))

    def test_unrelated_shell_commands_do_not_create_violations(self):
        for command in ['printf "git pip curl"', 'echo git', 'echo python3 -m pip',
                'sh -c "echo git"', 'env printf "curl ssh"']:
            with self.subTest(command=command):
                state = {'skills': {}, 'violations': set()}
                observe_tool_start(state, {'id': 'shell', 'name': 'run_command',
                    'arguments': json.dumps({'command': command})})
                self.assertEqual(state['violations'], set())


if __name__ == '__main__':
    unittest.main()
