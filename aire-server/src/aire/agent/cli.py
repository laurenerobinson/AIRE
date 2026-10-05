"""Standard-library interactive CLI over an existing read-only analysis DB."""
import argparse
import os
from pathlib import Path

from aire.agent.binary_scope import resolve_binary
from aire.agent.runner import AgentLimits, AgentRunner
from aire.agent.session import AgentSession
from aire.ai.chat import _display
from aire.ai.ollama_client import OllamaClient
from aire.security.rule_engine import _ReadOnlyRuleStore


def render_event(event):
    tag = 'TOOL' if event.event_type in ('tool_started', 'tool_completed') else 'AGENT'
    details = event.message
    if event.tool_name:
        details = event.tool_name + ': ' + details
    if event.function_id:
        details += f' ({event.function_name} at {event.function_address})'
    if event.metadata.get('code'):
        details += ' [' + str(event.metadata['code']) + ']'
    return f'[{tag}] {_display(details)}'


def main(argv=None, *, input_fn=None, output=None, client=None):
    parser = argparse.ArgumentParser(prog='aire', description='A.I.R.E. read-only binary agent')
    subparsers = parser.add_subparsers(dest='command', required=True)
    chat = subparsers.add_parser('chat', help='Chat over an existing persisted binary analysis')
    chat.add_argument('binary')
    chat.add_argument('--database', type=Path, default=Path(os.environ.get('AIRE_DATABASE', 'analysis.sqlite')))
    chat.add_argument('--session', type=Path, help='Explicit conversation state file, separate from analysis')
    chat.add_argument('--question', help='Run one request and exit')
    chat.add_argument('--model')
    chat.add_argument('--host')
    chat.add_argument('--num-ctx', type=int)
    chat.add_argument('--max-iterations', type=int, default=6)
    chat.add_argument('--max-tool-calls', type=int, default=8)
    chat.add_argument('--timeout', type=float, default=180)
    chat.add_argument('--evidence-chars', type=int, default=8000)

    gui = subparsers.add_parser('gui', help='Launch the local A.I.R.E. analysis workspace')
    gui.add_argument('binary', nargs='?', help='Stored binary ID, matching file path, or unique stored name')
    gui.add_argument('--database', type=Path, default=Path(os.environ.get('AIRE_DATABASE', 'analysis.sqlite')))
    gui.add_argument('--session-dir', type=Path, help='GUI conversation directory (default: ~/.aire/gui-sessions)')
    gui.add_argument('--bind', default='127.0.0.1', help='Loopback bind address (default: 127.0.0.1)')
    gui.add_argument('--port', type=int, default=8765)
    gui.add_argument('--no-browser', action='store_true', help='Do not open the default browser automatically')
    gui.add_argument('--model')
    gui.add_argument('--ollama-host')
    gui.add_argument('--num-ctx', type=int)
    gui.add_argument('--max-iterations', type=int, default=6)
    gui.add_argument('--max-tool-calls', type=int, default=8)
    gui.add_argument('--timeout', type=float, default=180)
    gui.add_argument('--evidence-chars', type=int, default=8000)
    args = parser.parse_args(argv)
    read = input_fn or input
    write = output or (lambda value: print(value, flush=True))
    try:
        limits = AgentLimits(args.max_iterations, args.max_tool_calls, args.timeout,
                             evidence_chars=args.evidence_chars)
        if args.command == 'gui':
            from aire.api.server import GuiApplication, GuiModelConfig, serve
            application = GuiApplication(args.database, initial_binary=args.binary,
                session_dir=args.session_dir,
                model_config=GuiModelConfig(args.ollama_host, args.model, args.num_ctx),
                limits=limits)
            return serve(application, host=args.bind, port=args.port,
                         open_browser=not args.no_browser, output=write)
        model = client or OllamaClient(host=args.host, model=args.model, num_ctx=args.num_ctx)
        with _ReadOnlyRuleStore(args.database) as store:
            binary = resolve_binary(store, args.binary)
            if args.session and args.session.resolve() == args.database.resolve():
                raise ValueError('Session file must be separate from the analysis database')
            if args.session and Path(binary.path).resolve() == args.session.resolve():
                raise ValueError('Session file must be separate from the binary')
            session = (AgentSession.load(args.session, binary.binary_id)
                       if args.session and args.session.exists() else AgentSession(binary.binary_id))
            runner = AgentRunner(store, model, limits=limits)
            write('A.I.R.E. Agent\nBinary: ' + _display(binary.program_name or Path(binary.path).name))
            while True:
                try:
                    question = args.question if args.question is not None else read('> ')
                except EOFError:
                    return 0
                if not question.strip():
                    if args.question is not None:
                        raise ValueError('Question must not be empty')
                    continue
                if question.strip().lower() in ('exit', 'quit', '/quit'):
                    return 0
                result = runner.run(session, question, on_event=lambda event: write(render_event(event)))
                write('\nA.I.R.E.:\n' + result.answer)
                if args.session:
                    session.save(args.session)
                if args.question is not None:
                    return 0 if result.status == 'completed' else 1
    except KeyboardInterrupt:
        write('\n[AGENT] Cancelled')
        return 130
    except Exception as exc:
        write('[AGENT] Error: ' + _display(str(exc)))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
