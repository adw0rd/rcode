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


def _assignment(token):
    name, separator, _value = token.partition('=')
    return bool(separator and name and (name[0].isalpha() or name[0] == '_')
        and all(char.isalnum() or char == '_' for char in name))


def _python_pip(arguments):
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == '-m':
            return index + 1 < len(arguments) and arguments[index + 1] == 'pip'
        if token in ('-c', '--'):
            return False
        if token in ('-W', '-X', '--check-hash-based-pycs'):
            index += 2
        elif token.startswith('-'):
            index += 1
        else:
            return False
    return False


def _classify_simple(tokens, state, depth):
    while tokens and _assignment(tokens[0]):
        tokens = tokens[1:]
    if not tokens:
        return
    executable = tokens[0].rsplit('/', 1)[-1]
    if executable == 'env':
        index = 1
        while index < len(tokens):
            token = tokens[index]
            if token == '--':
                index += 1
                break
            if token in ('-S', '--split-string') and index + 1 < len(tokens):
                _classify_shell(tokens[index + 1], state, depth + 1)
                return
            if token in ('-u', '--unset', '-C', '--chdir'):
                index += 2
                continue
            if _assignment(token) or token.startswith('-'):
                index += 1
                continue
            break
        _classify_simple(tokens[index:], state, depth + 1)
        return
    if executable == 'git':
        state['violations'].add('git')
    if executable in ('pip', 'pip3') or (
        (executable == 'python' or executable.startswith('python3')) and _python_pip(tokens[1:])
    ):
        state['violations'].add('package_install')
    if executable in ('curl', 'wget', 'nc', 'ssh'):
        state['violations'].add('network')
    if executable not in ('sh', 'bash'):
        return
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == '-c' or (token.startswith('-') and not token.startswith('--') and 'c' in token[1:]):
            if index + 1 < len(tokens):
                _classify_shell(tokens[index + 1], state, depth + 1)
            return
        if token in ('-o', '--option'):
            index += 2
        elif token.startswith('-'):
            index += 1
        else:
            return


def _classify_shell(command, state, depth=0):
    if depth > 8:
        state['violations'].update(('git', 'package_install', 'network'))
        return
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=';&|\n')
        lexer.whitespace_split = True
        lexer.whitespace = ' \t\r'
        tokens = list(lexer)
    except ValueError:
        state['violations'].update(('git', 'package_install', 'network'))
        return
    simple = []
    for token in tokens:
        if token and all(char in ';&|\n' for char in token):
            _classify_simple(simple, state, depth)
            simple = []
        else:
            simple.append(token)
    _classify_simple(simple, state, depth)


def observe_tool_start(state, receipt):
    if not isinstance(receipt, dict):
        return
    name = receipt.get('name')
    call_id = receipt.get('id')
    arguments = _arguments(receipt)
    if name == 'load_skill':
        if not isinstance(call_id, str):
            return
        seen = state.setdefault('skill_calls', set())
        if call_id in seen:
            state.setdefault('quarantined_skills', set()).add(call_id)
            state['skills'].pop(call_id, None)
            state.setdefault('skill_successes', set()).discard(call_id)
            state.setdefault('pending_skills', set()).discard(call_id)
            return
        seen.add(call_id)
        skill = arguments.get('name') if arguments else None
        if isinstance(skill, str) and skill:
            state['skills'][call_id] = skill
            state.setdefault('pending_skills', set()).add(call_id)
        return
    if name in ('spawn_agent', 'wait_agent'):
        state['violations'].add('subagent')
    if name != 'run_command' or not arguments:
        return
    command = arguments.get('command')
    if isinstance(command, str):
        _classify_shell(command, state)


def observe_tool_result(state, receipt):
    if not isinstance(receipt, dict) or receipt.get('name') != 'load_skill':
        return
    call_id = receipt.get('id')
    pending = state.setdefault('pending_skills', set())
    if not isinstance(call_id, str) or call_id not in pending:
        return
    pending.remove(call_id)
    if receipt.get('is_error') is False and call_id not in state.get('quarantined_skills', set()):
        state.setdefault('skill_successes', set()).add(call_id)


def required_skills_met(state, required):
    skills = state.get('skills')
    successes = state.get('skill_successes', set())
    quarantined = state.get('quarantined_skills', set())
    if not isinstance(skills, dict) or not isinstance(successes, (set, frozenset)):
        return False
    if not isinstance(quarantined, (set, frozenset)):
        return False
    if not isinstance(required, list) or not all(isinstance(skill, str) for skill in required):
        return False
    return all(any(call_id in successes and call_id not in quarantined and skills.get(call_id) == skill
        for call_id in skills) for skill in required)
