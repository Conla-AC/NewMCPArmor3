# -*- coding: utf-8 -*-
"""Low-level Python 2.7 CodeType reconstruction."""
from __future__ import absolute_import, print_function

import types


def _code_string(value):
    if isinstance(value, unicode):
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
    return types.CodeType(co.co_argcount, nlocals, stacksize, co.co_flags,
                          code_bytes, tuple(consts), _code_names(names),
                          _code_names(varnames), _code_string(filename),
                          _code_string(name), firstlineno, lnotab,
                          _code_names(co.co_freevars),
                          _code_names(co.co_cellvars))
