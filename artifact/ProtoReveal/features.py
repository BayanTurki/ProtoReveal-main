import angr
import pyvex
import fillrcd
import networkx as nx


def get_n_pred_or_succ(graph: nx.DiGraph, source_node, n, succ=True):
    # get successors or predecessors for up to n generations

    res = []
    q = [(source_node, 0)]

    while q:
        node, gen = q.pop()

        if gen > n:
            break  # If we are at the nth generation

        res.append(node)

        if succ:
            to_add = graph.successors(node)
        else:
            to_add = graph.predecessors(node)

        for r in to_add:
            q.append((r, gen + 1))

    return set(res)


def get_op_count(op, function, block=None):
    count = 0
    if block:
        for expr in block.vex.expressions:
            if isinstance(expr, pyvex.expr.Binop):
                if op in expr.op:
                    count += 1
    elif function:
        for block in function.blocks:
            for expr in block.vex.expressions:
                if isinstance(expr, pyvex.expr.Binop):
                    if op in expr.op:
                        count += 1
    return count


def get_features(block: angr.block, cfg: angr.analyses.cfg, block_addr):
    features = dict()
    ops = ["Shl", "Shr", "Mul", "Sub", "Add", "Div", "And", "Or", "Xor", "Cmp"]
    jump_kind = block.vex.jumpkind
    for op in ops:
        count = get_op_count(op, None, block)
        features[op] = count
    node = cfg.get_any_node(block_addr)
    if node is not None:
        features[f"Succ_len"] = len(node.successors)
        features[f"pred_len"] = len(node.predecessors)
    else:
        features[f"Succ_len"] = 0
        features[f"pred_len"] = 0
    get, put = fillrcd.get_transfer_insts(block)
    features[f"GET"] = get
    features[f"PUT"] = put

    features["jk"] = jump_kind
    return features
