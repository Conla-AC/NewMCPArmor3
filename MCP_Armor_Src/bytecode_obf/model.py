# -*- coding: utf-8 -*-
"""Low-level Python 2.7 CodeType reconstruction."""


import types

try:
    _text_type = unicode
except NameError:
    _text_type = str


def _code_string(value):
    if isinstance(value, _text_type) and not isinstance(value, bytes):
        return value.encode('utf-8')
    return value


def _code_names(values):
    return tuple(_code_string(value) for value in values)


def rebuild_code(co, consts=None, code_bytes=None, filename=None, name=None, firstlineno=None, names=None, varnames=None, nlocals=None, stacksize=None, lnotab=None):
    if consts is None:
        consts = co.co_consts
    if code_bytes is None:
        code_bytes = co.co_code
    if filename is None:
        filename = co.co_filename
    if name is None:
        name = co.co_name
    if firstlineno is None:
        firstlineno = co.co_firstlineno
    if names is None:
        names = co.co_names
    if varnames is None:
        varnames = co.co_varnames
    if nlocals is None:
        nlocals = co.co_nlocals
    if stacksize is None:
        stacksize = co.co_stacksize
    if lnotab is None:
        lnotab = co.co_lnotab
    # Python 3.11+ exposes a stable ``CodeType.replace`` API and carries
    # exception-table/line-table fields that did not exist in Python 2.7.
    # Preserve those fields instead of calling the legacy 14-argument
    # constructor.  The Python 2 target path below remains unchanged.
    if hasattr(co, 'replace'):
        updates = {
            'co_consts': tuple(consts),
            'co_code': bytes(code_bytes) if isinstance(code_bytes, (bytes, bytearray)) else code_bytes,
            'co_names': tuple(names),
            'co_varnames': tuple(varnames),
            'co_filename': filename,
            'co_name': name,
            'co_firstlineno': firstlineno,
        }
        if hasattr(co, 'co_linetable'):
            updates['co_linetable'] = co.co_linetable
        elif hasattr(co, 'co_lnotab'):
            updates['co_lnotab'] = lnotab
        return co.replace(**updates)
    return types.CodeType(co.co_argcount, nlocals, stacksize, co.co_flags,
                          code_bytes, tuple(consts), _code_names(names),
                          _code_names(varnames), _code_string(filename),
                          _code_string(name), firstlineno, lnotab,
                          _code_names(co.co_freevars),
                          _code_names(co.co_cellvars))
