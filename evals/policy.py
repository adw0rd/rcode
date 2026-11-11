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


def _substitutions(token):
    bodies = []
    offset = 0
    while True:
        begin = token.find('$(', offset)
        if begin < 0:
            return bodies
        depth = 1
        quote = None
        escaped = False
        for index in range(begin + 2, len(token)):
            char = token[index]
            if escaped:
                escaped = False
                continue
            if char == '\\':
                escaped = True
                continue
            if quote:
                if char == quote:
                    quote = None
                continue
            if char in ('\'', '"'):
                quote = char
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    bodies.append(token[begin + 2:index])
                    offset = index + 1
                    break
        else:
            return bodies


def _fallback_violations(tokens, state, depth):
    if depth > 8:
        state['violations'].update(('git', 'package_install', 'network'))
        return
    command_position = True
    backtick = False
    case_depth = 0
    case_pattern = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        nested = _substitutions(token)
        quoted_backticks = token.split('`')
        if nested or len(quoted_backticks) > 2:
            for body in nested:
                _classify_shell(body, state, depth + 1)
            for body in quoted_backticks[1::2]:
                if body:
                    _classify_shell(body, state, depth + 1)
            command_position = False
            index += 1
            continue
        closing_backtick = False
        if '`' in token:
            if backtick:
                closing_backtick = True
                backtick = False
            else:
                backtick = True
                command_position = True
            token = token.replace('`', '')
        if not token:
            index += 1
            continue
        if all(char in ';&|\n' for char in token):
            if token == '|' and case_pattern:
                command_position = False
            else:
                command_position = True
                if case_depth and token in (';;', ';;&', ';&'):
                    case_pattern = True
        elif token in ('(', '{'):
            command_position = True
        elif token == ')' and case_pattern:
            case_pattern = False
            command_position = True
        elif token in (')', '}', '()'):
            command_position = False
        elif command_position and token == 'case':
            case_depth += 1
            case_pattern = False
            command_position = False
        elif token == 'in' and case_depth:
            case_pattern = True
            command_position = False
        elif token == 'esac' and case_depth:
            case_depth -= 1
            case_pattern = False
            command_position = False
        elif (command_position and token.isdigit() and index + 1 < len(tokens)
                and tokens[index + 1] and all(char in '<>&' for char in tokens[index + 1])):
            pass
        elif '<' in token or '>' in token:
            if token in ('<', '>', '<<', '>>', '<<<', '<>', '>|', '>&', '<&'):
                index += 1
        elif token == '$':
            pass
        elif token in ('then', 'do', 'else', 'elif'):
            command_position = True
        elif token in ('fi', 'done'):
            command_position = False
        elif command_position and token in ('if', 'while', 'until', 'for', 'select',
                'function', 'time', 'coproc', '!'):
            command_position = True
        elif command_position and token in ('in', 'esac'):
            command_position = True
        elif command_position and not _assignment(token):
            _classify_simple([token, *tokens[index + 1:]], state, depth + 1)
            command_position = False
        if closing_backtick:
            command_position = False
        index += 1


def _complex_form(tokens):
    reserved = {'if', 'while', 'until', 'for', 'case', 'select', 'function', 'time',
        'then', 'else', 'elif', 'fi', 'do', 'done', 'in', 'esac', 'coproc', '!', '{', '}'}
    return any('`' in token or '$(' in token or '<' in token or '>' in token
        or token in reserved or (token and all(char in '(){}' for char in token))
        for token in tokens)


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
            if token.startswith('--split-string=') or (token.startswith('-S') and token != '-S'):
                _classify_shell(token.split('=', 1)[1] if '=' in token else token[2:], state, depth + 1)
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
    if executable in ('command', 'exec'):
        index = 1
        while index < len(tokens):
            token = tokens[index]
            if token == '--':
                index += 1
                break
            if executable == 'exec' and token == '-a':
                index += 2
                continue
            if token.startswith('-'):
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
        if token in ('-o', '-O', '+o', '+O', '--option'):
            index += 2
        elif token.startswith(('-', '+')):
            index += 1
        else:
            return


def _classify_shell(command, state, depth=0):
    if depth > 8:
        state['violations'].update(('git', 'package_install', 'network'))
        return
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars='();<>|&{}\n')
        lexer.whitespace_split = True
        lexer.whitespace = ' \t\r'
        tokens = list(lexer)
    except ValueError:
        state['violations'].update(('git', 'package_install', 'network'))
        return
    if _complex_form(tokens):
        _fallback_violations(tokens, state, depth)
        return
    simple = []
    for token in tokens:
        if token and all(char in ';&|\n' for char in token):
            _classify_simple(simple, state, depth)
            simple = []
        else:
            simple.append(token)
    _classify_simple(simple, state, depth)


CATEGORY_ORDER = ('package_install', 'git', 'network', 'subagent')
DIAGNOSTICS_LIMIT = 64


def tool_violations(receipt):
    if not isinstance(receipt, dict):
        return ()
    name = receipt.get('name')
    if name in ('spawn_agent', 'wait_agent'):
        return ('subagent',)
    if name != 'run_command':
        return ()
    arguments = _arguments(receipt)
    command = arguments.get('command') if arguments else None
    if not isinstance(command, str):
        return ()
    temporary = {'violations': set()}
    _classify_shell(command, temporary)
    return tuple(category for category in CATEGORY_ORDER if category in temporary['violations'])


def _bounded_text(value, limit):
    raw = value.encode('utf-8', errors='replace')
    truncated = len(raw) > limit
    return raw[:limit].decode('utf-8', errors='ignore'), truncated


def _record_diagnostics(state, receipt, categories, generation):
    events = state.get('diagnostics')
    if events is None:
        return
    arguments = _arguments(receipt)
    raw_command = (arguments.get('command')
        if receipt.get('name') == 'run_command' and arguments else None)
    command, command_truncated = (_bounded_text(raw_command, 4096)
        if isinstance(raw_command, str) else (None, False))
    identity = receipt.get('id')
    identity, identity_truncated = (_bounded_text(identity, 256)
        if isinstance(identity, str) else (None, False))
    for category in categories:
        if len(events) >= DIAGNOSTICS_LIMIT:
            state['diagnostics_dropped'] = state.get('diagnostics_dropped', 0) + 1
            continue
        events.append({'version': 1,
            'generation': generation if type(generation) is int and generation >= 1 else None,
            'category': category, 'tool': receipt['name'], 'call_id': identity,
            'call_id_truncated': identity_truncated, 'command': command,
            'command_truncated': command_truncated})


def observe_tool_start(state, receipt, generation=None):
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
    categories = tool_violations(receipt)
    state['violations'].update(categories)
    if categories:
        _record_diagnostics(state, receipt, categories, generation)


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
