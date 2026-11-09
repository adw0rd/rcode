import shlex

if __package__:
    from .runtime.runtime import strict
else:
    from runtime import strict


def _arguments(receipt):
    if not isinstance(receipt, dict) or not isinstance(receipt.get('arguments'), str):
        return None
    try:
        value = strict(receipt['arguments'].encode())
    except (ValueError, UnicodeError):
        return None
    return value if isinstance(value, dict) else None


def observe_tool_start(state, receipt):
    if not isinstance(receipt, dict):
        return
    name = receipt.get('name')
    call_id = receipt.get('id')
    arguments = _arguments(receipt)
    if name == 'load_skill':
        skill = arguments.get('name') if arguments else None
        if isinstance(call_id, str) and isinstance(skill, str) and skill:
            state['skills'][call_id] = skill
        return
    if name in ('spawn_agent', 'wait_agent'):
        state['violations'].add('subagent')
    if name != 'run_command' or not arguments:
        return
    command = arguments.get('command')
    if not isinstance(command, str):
        return
    try:
        tokens = shlex.split(command)
    except ValueError:
        return
    if not tokens:
        return
    executable = tokens[0].rsplit('/', 1)[-1]
    if executable == 'git':
        state['violations'].add('git')
    if executable in ('pip', 'pip3') or (
        (executable == 'python' or executable.startswith('python3'))
        and len(tokens) >= 3 and tokens[1:3] == ['-m', 'pip']
    ):
        state['violations'].add('package_install')
    if executable in ('curl', 'wget', 'nc', 'ssh'):
        state['violations'].add('network')


def observe_tool_result(state, receipt):
    if not isinstance(receipt, dict) or receipt.get('is_error') is not False:
        return
    call_id = receipt.get('id')
    if receipt.get('name') != 'load_skill' or not isinstance(call_id, str) or call_id not in state['skills']:
        return
    state.setdefault('skill_successes', set()).add(call_id)


def required_skills_met(state, required):
    skills = state.get('skills')
    successes = state.get('skill_successes', set())
    if not isinstance(skills, dict) or not isinstance(successes, (set, frozenset)):
        return False
    if not isinstance(required, list) or not all(isinstance(skill, str) for skill in required):
        return False
    return all(any(call_id in successes and skills.get(call_id) == skill for call_id in skills)
        for skill in required)
