# -*- coding: utf-8 -*-
#
# common_ai.py
#
# Description: AI chat engine for batchRun - supports OpenAI-compatible and Anthropic APIs.

import os
import re
import sys
import json
import threading

from PyQt5.QtCore import QThread, pyqtSignal

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/common')
import common

# openai and anthropic are lazy-imported inside their respective methods
# (_agent_loop_openai / _agent_loop_anthropic) to avoid startup penalty.

# Fallback dangerous commands (used only when config.ai_dangerous_commands is empty).
DEFAULT_DANGEROUS_COMMANDS = [
    'rm', 'rmdir', 'shred', 'truncate',
    'mkfs', 'fdisk', 'parted', 'wipefs', 'dd',
    'lvremove', 'vgremove', 'pvremove',
    'kill', 'killall', 'pkill',
    'shutdown', 'reboot', 'poweroff', 'halt', 'init',
    'systemctl', 'service',
    'useradd', 'userdel', 'usermod',
    'passwd', 'chpasswd',
    'groupadd', 'groupdel', 'groupmod',
    'chown', 'chmod', 'visudo',
    'iptables', 'ip6tables', 'nftables',
    'firewall-cmd', 'ufw',
    'ifdown', 'nmcli',
    'yum', 'dnf', 'apt', 'rpm', 'pip',
    'bkill', 'badmin', 'bstop', 'bresume', 'brestart', 'bswitch',
    'scontrol', 'scancel',
    'crontab', 'at',
    'mount', 'umount', 'fsck',
]

SYSTEM_PROMPT = """You are a cluster IT administrator and cluster security administrator AI assistant in batchRun.

Your role covers:
- Asset management: hardware inventory, OS versions, CPU models, memory configurations, host lifecycle
- Network configuration: network topology, connectivity, DNS/hosts, port management, VLAN/subnet planning
- System operations: host availability, load monitoring, CPU/memory/swap/tmp usage, uptime, service health, configuration consistency, patch management, scheduled maintenance
- Security hardening: access control, SSH hardening, firewall rules, vulnerability scanning, intrusion detection, compliance auditing, security baseline enforcement

batchRun is an HPC batch operations tool — it manages host inventory in groups, executes commands across hundreds of hosts in parallel via SSH, collects system metrics, and performs security audits. The "cluster" refers to ALL hosts defined in batchRun's host.list configuration, organized by groups.

Key paths for this installation:
- Host list: {host_list}
- Database directory: {db_path}

Tools: run_command (execute any Linux command on the management node — read data files, run batch_run for cross-host operations, grep/cat/python for analysis, etc.)

Response rules:
- Be concise and direct. Lead with the conclusion or diagnosis, then explain briefly.
- Reply in user's language.
- If a command fails or returns an error, immediately retry with an alternative command. Not all flags are supported across different Linux distributions — use simpler, universally compatible flags on retry.
- If a command output is truncated, analyze the available portion first. If insufficient, use pipe commands (grep, awk, sort, head) to filter precisely rather than re-running the same command.
- IMPORTANT: Only run commands when the user asks a specific question about their cluster, hosts, or resources. For greetings or general questions, respond conversationally — briefly introduce your capabilities without executing any commands.
- IMPORTANT: During diagnostic/information-gathering phases, you MUST execute commands directly via run_command tool — never list them as text for the user to choose.
- IMPORTANT: After executing commands, you MUST always provide a clear conclusion to the user — even if the result is negative (e.g. "not found", "no match", "all normal"). Never end your response with just command outputs and no summary. Summarize what you searched, what you found (or didn't find), and what it means.
- IMPORTANT: When analyzing the cluster, prefer reading pre-collected data files (host_stat.json, host_info.json, etc.) over running batch_run commands to remote hosts. Only use live batch_run commands when the data files are stale or don't contain the needed information.
- IMPORTANT: Minimize the number of tool calls. When you need to gather multiple pieces of information, combine them into a SINGLE command using shell features (semicolons, pipes, &&, subshells). For example, use `cat file1.json | python3 -c "import json,sys; d=json.load(sys.stdin); ..."` to read and analyze in one call, or `uptime; free -h; df -h` to gather multiple metrics at once. Aim for NO MORE than 5 tool calls per response. If you find yourself needing more, step back and design a more efficient approach (e.g. write a short inline script).
- IMPORTANT: When gathering information from remote hosts, write a local shell script that collects ALL needed data in one pass, then execute it via batch_run. batch_run natively supports executing local scripts on remote hosts — if a command is not found remotely, it will automatically scp the script and run it. Example workflow: write a script `/tmp/check_cluster.sh` containing all checks (uptime, df, free, ps, etc.), then run `batch_run -G RUN -P 128 -t 60 -c '/tmp/check_cluster.sh'`. This is far more efficient than calling batch_run multiple times with different commands.
- IMPORTANT: When using batch_run to execute commands on remote hosts, unless the user explicitly specifies a target group or host range, always default to `-G RUN`. If the RUN group does not exist (batch_run reports an error), fall back to `-G ALL`. Do NOT split execution across multiple groups in separate calls — use one group that covers all targets in a single batch_run invocation.
- IMPORTANT: When running batch_run for tasks that may take longer than a few seconds per host (e.g. package queries, large file searches, service restarts), always extend the timeout with `-t <seconds>` (e.g. `-t 60` or `-t 120`). The default timeout is short (10s serial, 20s parallel) and will cause premature failures on slow operations.
- IMPORTANT: When you have finished diagnosis and are presenting final actionable solutions that would CHANGE system state (kill processes, modify configs, restart services), you MUST end your response with a clearly formatted numbered list like this:

---
**可选操作：**
1. <action description>
2. <action description>
3. <action description>

请回复数字选择操作，或直接提问。

Do NOT execute any state-changing action from this list until the user explicitly chooses one by number. This applies only to final repair/modification suggestions, not to read-only diagnostic commands.
"""

# Tool definitions in OpenAI format.
TOOLS_OPENAI = [
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Execute a command on the management node and return its output. Use for Linux system commands (uptime, free, df, top, ps, ip, ss, etc.), cluster management commands, and information gathering.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The command to execute, e.g. 'uptime', 'free -h', 'df -h', 'cat /etc/os-release'"
                    }
                },
                "required": ["command"]
            }
        }
    }
]

# Tool definitions in Anthropic format.
TOOLS_ANTHROPIC = [
    {
        "name": t["function"]["name"],
        "description": t["function"]["description"],
        "input_schema": t["function"]["parameters"]
    }
    for t in TOOLS_OPENAI
]

MAX_OUTPUT_LENGTH = 4000


def detect_api_type(model_name):
    """Auto-detect API type from model name."""
    if 'claude' in model_name.lower():
        return 'anthropic'

    return 'openai'


def parse_xml_tool_calls(content):
    """Parse XML-formatted tool calls from model content (fallback for models that don't use function calling)."""
    if '<function_calls>' not in content:
        return []

    results = []
    invoke_pattern = re.compile(r'<invoke\s+name="([^"]+)">(.*?)</invoke>', re.DOTALL)
    param_pattern = re.compile(r'<parameter\s+name="([^"]+)">(.*?)</parameter>', re.DOTALL)

    for match in invoke_pattern.finditer(content):
        tool_name = match.group(1)
        invoke_body = match.group(2)
        args = {}

        for param_match in param_pattern.finditer(invoke_body):
            args[param_match.group(1)] = param_match.group(2).strip()

        results.append({'name': tool_name, 'arguments': json.dumps(args, ensure_ascii=False)})

    return results


# ============================================================
# Tool execution functions.
# ============================================================

def execute_command(command, dangerous_list, confirm_callback):
    """Execute a command with safety checks."""
    if not command.strip():
        return "Error: empty command."

    tokens = [token for token in re.split(r'[\s|;&<>()`{}\'"$\\]+', command) if token]

    for token in tokens:
        if (token in dangerous_list) or (os.path.basename(token) in dangerous_list):
            if not confirm_callback(command):
                return f"User rejected execution of command: {command}"

            break

    try:
        (return_code, stdout, stderr) = common.run_command(command)
        output = stdout.decode('utf-8', errors='replace') if stdout else ''

        if return_code != 0:
            err = stderr.decode('utf-8', errors='replace') if stderr else ''
            output = f"Command exited with code {return_code}.\nStdout:\n{output}\nStderr:\n{err}"

        if len(output) > MAX_OUTPUT_LENGTH:
            output = output[:MAX_OUTPUT_LENGTH] + f"\n... (truncated, total {len(output)} chars. Analyze available data first. If insufficient, use pipe commands to filter precisely rather than re-running the same command.)"

        return output if output.strip() else "(no output)"
    except Exception as e:
        return f"Error executing command: {e}"


# ============================================================
# Skill loading (conf/skills/*/SKILL.md).
# ============================================================

def load_skills(skills_dir):
    """
    Load skills from skills_dir. Each subdirectory with a SKILL.md is one skill.
    Returns a list of dicts: [{"name": ..., "tags": [...], "content": ...}, ...]
    """
    skills = []

    if not os.path.isdir(skills_dir):
        return skills

    for name in sorted(os.listdir(skills_dir)):
        skill_file = os.path.join(skills_dir, name, 'SKILL.md')

        if not os.path.isfile(skill_file):
            continue

        try:
            with open(skill_file, 'r', errors='replace') as f:
                text = f.read()
        except Exception:
            continue

        # Parse YAML frontmatter for tags.
        tags = []

        if text.startswith('---'):
            parts = text.split('---', 2)

            if len(parts) >= 3:
                for line in parts[1].splitlines():
                    line = line.strip().lstrip('- ').strip()

                    if line and not line.endswith(':') and ':' not in line:
                        tags.append(line.lower())

                text = parts[2].strip()

        skills.append({"name": name, "tags": tags, "content": text})

    return skills


def _tag_matches(tag, msg_lower):
    """Check if a skill tag matches the message. Word-boundary for ASCII tags, substring for CJK."""
    if tag.isascii():
        return bool(re.search(r'\b' + re.escape(tag) + r'\b', msg_lower))

    return tag in msg_lower


def match_skills(skills, user_message):
    """
    Check if user_message matches any skill tags.
    Returns (content_string, matched_skill_names).
    """
    if not skills:
        return ('', [])

    msg_lower = user_message.lower()
    matched_content = []
    matched_names = []

    for skill in skills:
        for tag in skill['tags']:
            if _tag_matches(tag, msg_lower):
                matched_content.append(skill['content'])
                matched_names.append(skill['name'])
                break

    return ('\n\n'.join(matched_content), matched_names)


# ============================================================
# Message format converters (OpenAI <-> Anthropic).
# ============================================================

def openai_messages_to_anthropic(messages):
    """
    Convert OpenAI-format messages to Anthropic format.
    Returns (system_prompt, anthropic_messages).
    """
    system = ""
    anthropic_msgs = []

    for msg in messages:
        role = msg.get('role', '')

        if role == 'system':
            system = msg.get('content', '')
        elif role == 'user':
            anthropic_msgs.append({"role": "user", "content": msg['content']})
        elif role == 'assistant':
            content_blocks = []

            if msg.get('content'):
                content_blocks.append({"type": "text", "text": msg['content']})

            for tc in msg.get('tool_calls', []):
                func = tc.get('function', {})

                try:
                    input_data = json.loads(func.get('arguments', '{}'))
                except json.JSONDecodeError:
                    input_data = {}

                content_blocks.append({
                    "type": "tool_use",
                    "id": tc.get('id', ''),
                    "name": func.get('name', ''),
                    "input": input_data
                })

            if content_blocks:
                anthropic_msgs.append({"role": "assistant", "content": content_blocks})
        elif role == 'tool':
            tool_result = {
                "type": "tool_result",
                "tool_use_id": msg.get('tool_call_id', ''),
                "content": msg.get('content', '')
            }

            if anthropic_msgs and anthropic_msgs[-1]['role'] == 'user' and isinstance(anthropic_msgs[-1]['content'], list):
                anthropic_msgs[-1]['content'].append(tool_result)
            else:
                anthropic_msgs.append({"role": "user", "content": [tool_result]})

    return system, anthropic_msgs


# ============================================================
# AiChatThread - supports both OpenAI and Anthropic APIs.
# ============================================================

class AiChatThread(QThread):
    """Worker thread for AI chat with streaming and tool calling."""
    token_received = pyqtSignal(str)
    tool_call_start = pyqtSignal(str, str)
    tool_call_result = pyqtSignal(str, str)
    finished_signal = pyqtSignal()
    error_signal = pyqtSignal(str)
    confirm_requested = pyqtSignal(str)
    status_signal = pyqtSignal(str)
    sources_signal = pyqtSignal(dict)

    def __init__(self, api_base_url, api_key, model_name, messages,
                 dangerous_commands=None, skills=None,
                 debug=False, confirm_mode='signal', max_tokens=None):
        super().__init__()
        self.api_base_url = api_base_url.rstrip('/')
        self.api_key = api_key
        self.model_name = model_name
        self.messages = messages
        self.dangerous_commands = dangerous_commands or DEFAULT_DANGEROUS_COMMANDS
        self.skills = skills or []
        self.debug = debug
        self.confirm_mode = confirm_mode
        self.max_tokens = max_tokens
        self._stop_flag = False
        self._confirm_event = threading.Event()
        self._confirm_result = False
        self._sources = {"skills": []}
        self._timing_stats = {"llm_total": 0.0, "llm_first_token_max": 0.0, "llm_generation_total": 0.0, "tool_total": 0.0, "llm_calls": 0, "output_tokens": 0}

        # Auto-detect API type.
        self.api_type = detect_api_type(model_name)

        # Copy the system message dict so skill injection doesn't accumulate.
        if self.messages and self.messages[0].get('role') == 'system':
            self.messages[0] = dict(self.messages[0])

        # Track system prompt composition for debug output.
        self._prompt_parts = {}
        _base_len = len(self.messages[0].get('content', '')) if self.messages else 0
        self._prompt_parts['base'] = _base_len

        # Inject matched skill content into system prompt.
        self._inject_skills()
        _after_skills = len(self.messages[0].get('content', '')) if self.messages else 0
        self._prompt_parts['skill'] = _after_skills - _base_len

        if self.debug:
            if self._sources.get("skills"):
                common.bprint(f'[AI Debug] Injected skills: {self._sources["skills"]}', date_format='%Y-%m-%d %H:%M:%S')

    # Skills that are always injected regardless of tag matching.
    ALWAYS_INJECT_SKILLS = ['batchrun_usage']

    def _inject_skills(self):
        """Inject skills into system prompt. Always-inject skills are included unconditionally; others are matched by tag."""
        if not self.skills:
            return

        user_msg = ''

        for msg in reversed(self.messages):
            if msg.get('role') == 'user':
                user_msg = msg.get('content', '')
                break

        injected_content = []
        injected_names = []

        # Always inject core skills.
        for skill in self.skills:
            if skill['name'] in self.ALWAYS_INJECT_SKILLS:
                injected_content.append(skill['content'])
                injected_names.append(skill['name'])

        # Tag-match remaining skills from user message.
        if user_msg:
            remaining_skills = [s for s in self.skills if s['name'] not in self.ALWAYS_INJECT_SKILLS]
            matched_content, matched_names = match_skills(remaining_skills, user_msg)

            if matched_content:
                injected_content.append(matched_content)
                injected_names.extend(matched_names)

        if injected_names:
            self._sources["skills"] = injected_names

        if injected_content and self.messages and self.messages[0].get('role') == 'system':
            self.messages[0]['content'] = self.messages[0]['content'] + '\n\n' + '\n\n'.join(injected_content)

    def stop(self):
        self._stop_flag = True

    def set_confirm_result(self, result):
        """Called from main thread to respond to confirmation request."""
        self._confirm_result = result
        self._confirm_event.set()

    def _request_confirmation(self, command):
        """Request user confirmation for dangerous command. Blocks until user responds."""
        if self.confirm_mode == 'auto_reject':
            return False

        self._confirm_result = False
        self._confirm_event.clear()
        self.confirm_requested.emit(command)

        while not self._confirm_event.wait(timeout=1.0):
            if self._stop_flag:
                return False

        return self._confirm_result

    def run(self):
        try:
            if self.api_type == 'anthropic':
                self._agent_loop_anthropic()
            else:
                self._agent_loop_openai()
        except Exception as e:
            self.error_signal.emit(str(e))
        finally:
            self.sources_signal.emit(self._sources)
            self.finished_signal.emit()

    @staticmethod
    def _tool_description(tool_name, args):
        """Generate a human-readable description of the tool call."""
        if tool_name == 'run_command':
            return 'Executing: ' + args.get('command', '')

        return 'Calling ' + tool_name

    def _execute_tool(self, tool_name, args):
        if tool_name == 'run_command':
            return execute_command(
                args.get('command', ''),
                self.dangerous_commands,
                self._request_confirmation
            )

        return f"Unknown tool: {tool_name}"

    def _convert_tool_messages_for_fallback(self):
        """Convert tool-call messages to plain user/assistant format for APIs with incomplete tool support."""
        fallback = []

        for msg in self.messages:
            role = msg.get('role', '')

            if role == 'tool':
                tool_id = msg.get('tool_call_id', '')
                content = msg.get('content', '')
                fallback.append({"role": "user", "content": f"[Tool result ({tool_id})]:\n{content}"})
            elif role == 'assistant' and msg.get('tool_calls'):
                parts = []
                text_content = msg.get('content') or ''

                if text_content:
                    parts.append(text_content)

                for tc in msg['tool_calls']:
                    fn = tc.get('function', {})
                    parts.append(f"[Calling tool: {fn.get('name', '')}({fn.get('arguments', '')})]")

                fallback.append({"role": "assistant", "content": '\n'.join(parts)})
            else:
                fallback.append(msg)

        return fallback

    # ==========================================================
    # OpenAI-compatible API loop.
    # ==========================================================

    _openai_client_cache = {}
    _anthropic_client_cache = {}

    def _get_openai_client(self):
        """Get or create a cached OpenAI client."""
        from openai import OpenAI

        base_url = self.api_base_url

        if base_url.endswith('/chat/completions'):
            base_url = base_url[:-len('/chat/completions')]

        if not any(f'/v{n}' in base_url for n in range(1, 10)):
            base_url = base_url + '/v1'

        cache_key = (base_url, self.api_key)

        if cache_key not in AiChatThread._openai_client_cache:
            AiChatThread._openai_client_cache[cache_key] = OpenAI(base_url=base_url, api_key=self.api_key, timeout=120.0)

        return AiChatThread._openai_client_cache[cache_key]

    def _get_anthropic_client(self):
        """Get or create a cached Anthropic client."""
        import anthropic

        cache_key = (self.api_base_url, self.api_key)

        if cache_key not in AiChatThread._anthropic_client_cache:
            AiChatThread._anthropic_client_cache[cache_key] = anthropic.Anthropic(base_url=self.api_base_url, api_key=self.api_key)

        return AiChatThread._anthropic_client_cache[cache_key]

    MAX_TOOL_CALLS = 10

    def _agent_loop_openai(self):
        import time as _time

        try:
            client = self._get_openai_client()
        except ImportError:
            self.error_signal.emit('openai package is not installed. Run: pip install openai')
            return

        max_loops = 10
        total_tool_calls = 0

        for loop_i in range(max_loops):
            if self._stop_flag:
                return

            if self.debug:
                _sys_len = len(self.messages[0].get('content', '')) if self.messages else 0
                _non_sys_chars = sum(len(str(m.get('content', ''))) for m in self.messages[1:])
                _total_chars = _sys_len + _non_sys_chars
                _msg_count = len(self.messages)
                _parts = self._prompt_parts
                _skill_info = f', skill={_parts["skill"]}' if _parts.get('skill', 0) > 0 else ''

                common.bprint(f'[AI Debug] ──── Loop {loop_i} ────', date_format='%Y-%m-%d %H:%M:%S')
                common.bprint(f'[AI Debug] INPUT: {_msg_count} msgs, system={_sys_len}(base={_parts.get("base", 0)}{_skill_info}), conversation={_non_sys_chars}, total={_total_chars} chars', date_format='%Y-%m-%d %H:%M:%S')

            self.status_signal.emit('Waiting for LLM response')
            _t_api = _time.time()

            is_last_loop = (loop_i == max_loops - 1) or (total_tool_calls >= self.MAX_TOOL_CALLS)

            if is_last_loop:
                self.messages.append({"role": "user", "content": "You have reached the maximum number of tool calls. Stop calling tools NOW and provide your conclusion based on all information collected so far. Summarize findings and give actionable recommendations."})
            elif total_tool_calls >= self.MAX_TOOL_CALLS - 2:
                self.messages.append({"role": "user", "content": "You are approaching the tool call limit. Wrap up your investigation — combine any remaining checks into one final command if needed, then provide your conclusion in the next response."})

            _api_kwargs = dict(
                model=self.model_name,
                messages=self.messages,
                temperature=0,
                stream=True,
                stream_options={"include_usage": True}
            )

            if not is_last_loop:
                _api_kwargs['tools'] = TOOLS_OPENAI

            if self.max_tokens:
                _api_kwargs['max_tokens'] = self.max_tokens

            try:
                response = client.chat.completions.create(**_api_kwargs)
            except Exception as e:
                if self.debug:
                    common.bprint(f'[AI Debug] API call failed: {e}, retrying without tools ...', date_format='%Y-%m-%d %H:%M:%S')

                try:
                    fallback_messages = self._convert_tool_messages_for_fallback()

                    _fallback_kwargs = dict(
                        model=self.model_name,
                        messages=fallback_messages,
                        temperature=0,
                        stream=True,
                        stream_options={"include_usage": True}
                    )

                    if self.max_tokens:
                        _fallback_kwargs['max_tokens'] = self.max_tokens

                    response = client.chat.completions.create(**_fallback_kwargs)
                except Exception as e2:
                    self.error_signal.emit(f"API call failed: {e2}")
                    return

            full_content = ""
            tool_calls_data = {}
            _first_chunk = True
            _first_token_time = 0.0
            _first_token_abs = 0.0
            _completion_tokens = 0
            _chunk_count = 0

            try:
                for chunk in response:
                    if _first_chunk:
                        _first_token_abs = _time.time()
                        _first_token_time = _first_token_abs - _t_api
                        self._timing_stats["llm_first_token_max"] = max(self._timing_stats["llm_first_token_max"], _first_token_time)
                        _first_chunk = False

                    if self._stop_flag:
                        return

                    if hasattr(chunk, 'usage') and chunk.usage and hasattr(chunk.usage, 'completion_tokens'):
                        _completion_tokens = chunk.usage.completion_tokens

                    choice = chunk.choices[0] if chunk.choices else None

                    if not choice:
                        continue

                    delta = choice.delta

                    if delta and delta.content:
                        full_content += delta.content
                        _chunk_count += 1

                        if is_last_loop:
                            self.token_received.emit(delta.content)

                    if delta and delta.tool_calls:
                        for tc in delta.tool_calls:
                            idx = tc.index

                            if idx not in tool_calls_data:
                                tool_calls_data[idx] = {'id': '', 'name': '', 'arguments': ''}

                            if tc.id:
                                tool_calls_data[idx]['id'] = tc.id

                            if tc.function and tc.function.name:
                                tool_calls_data[idx]['name'] = tc.function.name

                            if tc.function and tc.function.arguments:
                                tool_calls_data[idx]['arguments'] += tc.function.arguments
                                _chunk_count += 1
            except Exception as e:
                self.error_signal.emit(f"Stream error: {e}")
                return

            self._timing_stats["output_tokens"] += _completion_tokens if _completion_tokens > 0 else _chunk_count

            _t_end = _time.time()
            _llm_elapsed = _t_end - _t_api
            _generation_time = (_t_end - _first_token_abs) if _first_token_abs > 0 else 0
            self._timing_stats["llm_total"] += _llm_elapsed
            self._timing_stats["llm_calls"] += 1
            self._timing_stats["llm_generation_total"] += _generation_time

            if self.debug:
                _effective_tokens = _completion_tokens if _completion_tokens > 0 else _chunk_count
                _tpm = (_generation_time / _effective_tokens * 1000) if _effective_tokens > 0 else 0
                _tool_names = [tool_calls_data[i]['name'] for i in sorted(tool_calls_data.keys())] if tool_calls_data else []
                _output_summary = f'content={len(full_content)} chars' if full_content else 'no content'

                if _tool_names:
                    _output_summary += f', tools=[{", ".join(_tool_names)}]'

                common.bprint(f'[AI Debug] OUTPUT: {_output_summary}', date_format='%Y-%m-%d %H:%M:%S')
                common.bprint(f'[AI Debug] PERF: total={_llm_elapsed:.1f}s, first_token={_first_token_time:.2f}s, tokens={_effective_tokens}, TPM={_tpm:.0f}ms/token', date_format='%Y-%m-%d %H:%M:%S')

            if not tool_calls_data:
                xml_tool_calls = parse_xml_tool_calls(full_content) if full_content else []

                if not xml_tool_calls:
                    if full_content:
                        if not is_last_loop:
                            self.token_received.emit(full_content)

                        self.messages.append({"role": "assistant", "content": full_content})
                    else:
                        self.error_signal.emit('LLM returned empty response, please retry.')

                    return

                if self.debug:
                    common.bprint(f'[AI Debug] Parsed {len(xml_tool_calls)} tool call(s) from XML in content (fallback)', date_format='%Y-%m-%d %H:%M:%S')

                display_content = re.sub(r'<function_calls>.*?</function_calls>', '', full_content, flags=re.DOTALL).strip()

                if display_content:
                    self.messages.append({"role": "assistant", "content": display_content})

                for i, xtc in enumerate(xml_tool_calls):
                    if self._stop_flag:
                        return

                    tool_name = xtc['name']

                    try:
                        args = json.loads(xtc['arguments'])
                    except json.JSONDecodeError:
                        args = {}

                    self.tool_call_start.emit(tool_name, self._tool_description(tool_name, args))
                    _t_tool = _time.time()
                    result = self._execute_tool(tool_name, args)
                    self._timing_stats["tool_total"] += _time.time() - _t_tool
                    total_tool_calls += 1

                    self.tool_call_result.emit(tool_name, result)
                    self.messages.append({"role": "user", "content": f"[Tool result from {tool_name}]:\n{result}"})

                continue

            assistant_tool_calls = []

            for idx in sorted(tool_calls_data.keys()):
                tc = tool_calls_data[idx]
                assistant_tool_calls.append({
                    "id": tc['id'],
                    "type": "function",
                    "function": {"name": tc['name'], "arguments": tc['arguments']}
                })

            self.messages.append({
                "role": "assistant",
                "content": full_content or None,
                "tool_calls": assistant_tool_calls
            })

            for idx in sorted(tool_calls_data.keys()):
                if self._stop_flag:
                    return

                tc = tool_calls_data[idx]
                tool_name = tc['name']

                try:
                    args = json.loads(tc['arguments'])
                except json.JSONDecodeError:
                    args = {}

                self.tool_call_start.emit(tool_name, self._tool_description(tool_name, args))
                _t_tool = _time.time()
                result = self._execute_tool(tool_name, args)
                self._timing_stats["tool_total"] += _time.time() - _t_tool
                total_tool_calls += 1

                self.tool_call_result.emit(tool_name, result)

                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tc['id'],
                    "content": result
                })

    # ==========================================================
    # Anthropic API loop (Claude models via anthropic SDK).
    # ==========================================================

    def _agent_loop_anthropic(self):
        import time as _time

        try:
            client = self._get_anthropic_client()
        except ImportError:
            self.error_signal.emit('anthropic package is not installed. Run: pip install anthropic')
            return

        max_loops = 10
        total_tool_calls = 0

        for loop_i in range(max_loops):
            if self._stop_flag:
                return

            if self.debug:
                _sys_len = len(self.messages[0].get('content', '')) if self.messages else 0
                _non_sys_chars = sum(len(str(m.get('content', ''))) for m in self.messages[1:])
                _total_chars = _sys_len + _non_sys_chars
                _msg_count = len(self.messages)
                _parts = self._prompt_parts
                _skill_info = f', skill={_parts["skill"]}' if _parts.get('skill', 0) > 0 else ''

                common.bprint(f'[AI Debug] ──── Loop {loop_i} ────', date_format='%Y-%m-%d %H:%M:%S')
                common.bprint(f'[AI Debug] INPUT: {_msg_count} msgs, system={_sys_len}(base={_parts.get("base", 0)}{_skill_info}), conversation={_non_sys_chars}, total={_total_chars} chars', date_format='%Y-%m-%d %H:%M:%S')

            self.status_signal.emit('Waiting for LLM response')

            is_last_loop = (loop_i == max_loops - 1) or (total_tool_calls >= self.MAX_TOOL_CALLS)

            if is_last_loop:
                self.messages.append({"role": "user", "content": "You have reached the maximum number of tool calls. Stop calling tools NOW and provide your conclusion based on all information collected so far. Summarize findings and give actionable recommendations."})
            elif total_tool_calls >= self.MAX_TOOL_CALLS - 2:
                self.messages.append({"role": "user", "content": "You are approaching the tool call limit. Wrap up your investigation — combine any remaining checks into one final command if needed, then provide your conclusion in the next response."})

            system, anthropic_msgs = openai_messages_to_anthropic(self.messages)

            _t_api = _time.time()

            _api_kwargs = dict(
                model=self.model_name,
                system=system,
                messages=anthropic_msgs,
                max_tokens=(self.max_tokens or 4096),
                temperature=0,
                stream=True
            )

            if not is_last_loop:
                _api_kwargs['tools'] = TOOLS_ANTHROPIC

            try:
                stream = client.messages.create(**_api_kwargs)
            except Exception as e:
                self.error_signal.emit(f"API call failed: {e}")
                return

            full_content = ""
            tool_calls = {}
            _first_chunk = True
            _first_token_time = 0.0
            _first_token_abs = 0.0
            _completion_tokens = 0
            _chunk_count = 0

            try:
                for event in stream:
                    if self._stop_flag:
                        return

                    if _first_chunk:
                        _first_token_abs = _time.time()
                        _first_token_time = _first_token_abs - _t_api
                        self._timing_stats["llm_first_token_max"] = max(self._timing_stats["llm_first_token_max"], _first_token_time)
                        _first_chunk = False

                    if event.type == 'message_delta' and hasattr(event, 'usage'):
                        _completion_tokens = getattr(event.usage, 'output_tokens', 0)

                    if event.type == 'content_block_start':
                        if event.content_block.type == 'tool_use':
                            tool_calls[event.index] = {
                                'id': event.content_block.id,
                                'name': event.content_block.name,
                                'arguments': ''
                            }
                    elif event.type == 'content_block_delta':
                        if event.delta.type == 'text_delta':
                            full_content += event.delta.text
                            _chunk_count += 1

                            if is_last_loop:
                                self.token_received.emit(event.delta.text)
                        elif event.delta.type == 'input_json_delta':
                            if event.index in tool_calls:
                                tool_calls[event.index]['arguments'] += event.delta.partial_json
                                _chunk_count += 1
            except Exception as e:
                self.error_signal.emit(f"Stream error: {e}")
                return

            self._timing_stats["output_tokens"] += _completion_tokens if _completion_tokens > 0 else _chunk_count

            _t_end = _time.time()
            _llm_elapsed = _t_end - _t_api
            _generation_time = (_t_end - _first_token_abs) if _first_token_abs > 0 else 0
            self._timing_stats["llm_total"] += _llm_elapsed
            self._timing_stats["llm_calls"] += 1
            self._timing_stats["llm_generation_total"] += _generation_time

            if self.debug:
                _effective_tokens = _completion_tokens if _completion_tokens > 0 else _chunk_count
                _tpm = (_generation_time / _effective_tokens * 1000) if _effective_tokens > 0 else 0
                _tool_names = [tool_calls[i]['name'] for i in sorted(tool_calls.keys())] if tool_calls else []
                _output_summary = f'content={len(full_content)} chars' if full_content else 'no content'

                if _tool_names:
                    _output_summary += f', tools=[{", ".join(_tool_names)}]'

                common.bprint(f'[AI Debug] OUTPUT: {_output_summary}', date_format='%Y-%m-%d %H:%M:%S')
                common.bprint(f'[AI Debug] PERF: total={_llm_elapsed:.1f}s, first_token={_first_token_time:.2f}s, tokens={_effective_tokens}, TPM={_tpm:.0f}ms/token', date_format='%Y-%m-%d %H:%M:%S')

            if not tool_calls:
                xml_tool_calls = parse_xml_tool_calls(full_content) if full_content else []

                if not xml_tool_calls:
                    if full_content:
                        if not is_last_loop:
                            self.token_received.emit(full_content)

                        self.messages.append({"role": "assistant", "content": full_content})
                    else:
                        self.error_signal.emit('LLM returned empty response, please retry.')

                    return

                if self.debug:
                    common.bprint(f'[AI Debug] Parsed {len(xml_tool_calls)} tool call(s) from XML in content (fallback)', date_format='%Y-%m-%d %H:%M:%S')

                display_content = re.sub(r'<function_calls>.*?</function_calls>', '', full_content, flags=re.DOTALL).strip()

                if display_content:
                    self.messages.append({"role": "assistant", "content": display_content})

                for i, xtc in enumerate(xml_tool_calls):
                    if self._stop_flag:
                        return

                    tool_name = xtc['name']

                    try:
                        args = json.loads(xtc['arguments'])
                    except json.JSONDecodeError:
                        args = {}

                    self.tool_call_start.emit(tool_name, self._tool_description(tool_name, args))
                    _t_tool = _time.time()
                    result = self._execute_tool(tool_name, args)
                    self._timing_stats["tool_total"] += _time.time() - _t_tool
                    total_tool_calls += 1

                    self.tool_call_result.emit(tool_name, result)
                    self.messages.append({"role": "user", "content": f"[Tool result from {tool_name}]:\n{result}"})

                continue

            assistant_tool_calls = []

            for idx in sorted(tool_calls.keys()):
                tc = tool_calls[idx]
                assistant_tool_calls.append({
                    "id": tc['id'],
                    "type": "function",
                    "function": {"name": tc['name'], "arguments": tc['arguments']}
                })

            self.messages.append({
                "role": "assistant",
                "content": full_content or None,
                "tool_calls": assistant_tool_calls
            })

            for idx in sorted(tool_calls.keys()):
                if self._stop_flag:
                    return

                tc = tool_calls[idx]
                tool_name = tc['name']

                try:
                    args = json.loads(tc['arguments'])
                except json.JSONDecodeError:
                    args = {}

                self.tool_call_start.emit(tool_name, self._tool_description(tool_name, args))
                _t_tool = _time.time()
                result = self._execute_tool(tool_name, args)
                self._timing_stats["tool_total"] += _time.time() - _t_tool
                total_tool_calls += 1

                self.tool_call_result.emit(tool_name, result)

                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tc['id'],
                    "content": result
                })
