# -*- coding: utf-8 -*-
"""Line-oriented, ASCII-safe progress events shared by Python 2/3 workers."""
import json
import sys

PREFIX = '[MCP_PROGRESS] '


def emit_progress(state, index, total, path, error=None):
    if isinstance(path, bytes):
        path = path.decode('utf-8', 'replace')
    event = dict(state=state, index=index, total=total, path=path)
    if error is not None:
        event['error'] = type(error).__name__
    sys.stdout.write(PREFIX + json.dumps(event, ensure_ascii=True) + '\n')
    sys.stdout.flush()


def parse_progress(line):
    if not line.startswith(PREFIX):
        return None
    try:
        event = json.loads(line[len(PREFIX):])
        index, total = event['index'], event['total']
        if (event['state'] not in ('start', 'done', 'error') or
                type(index) is not int or type(total) is not int or
                not 1 <= index <= total or not event['path']):
            return None
        if not isinstance(event['path'], type(u'')):
            return None
        return event
    except (ValueError, KeyError, TypeError):
        return None


def run_file_with_progress(callback, src, dst, opts, rel, index, total):
    emit_progress('start', index, total, rel)
    try:
        result = callback(src, dst, opts, rel)
    except Exception as exc:
        emit_progress('error', index, total, rel, exc)
        raise
    emit_progress('done', index, total, rel)
    return result
