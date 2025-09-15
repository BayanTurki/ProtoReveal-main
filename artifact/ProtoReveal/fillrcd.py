import angr
import pyvex

Record = dict()


def get_transfer_insts(block: angr.block):
    GET = 0
    PUT = 0

    for expr in block.vex.expressions:
        if isinstance(expr, pyvex.expr.Get):
            GET += 1
    for stmt in block.vex.statements:
        if isinstance(stmt, pyvex.stmt.Put):
            PUT += 1
    return GET, PUT


def getRcd():
    return Record
