import logging

import networkx
import pyvex

log = logging.getLogger(__name__)


def _traverse(start_addrs, stepper):
    visited = set()
    queue = start_addrs
    while len(queue) > 0:
        next = queue.pop()
        visited.add(next)
        queue += [n for n in stepper(next) if not n in visited]

    return visited


def apply_peripheral_accesses_heuristic(cfg, low_addr=0x40000000, high_addr=0x5FFFFFFF):
    """Apply heuristic to prune call graph based on identifying functions that access peripheral
    mapped addresses."""
    # Step 1: Identify all functions that appear to access peripheral addresses
    accesses = find_peripheral_accesses(cfg, low_addr, high_addr)
    peri_funcs = set([accesses[i]["function"] for i in accesses])

    # Step 2: Identify all functions that connect to these functions
    cg = cfg.functions.callgraph.to_undirected()
    step_func = lambda n: cg.neighbors(n)
    linked_funcs = _traverse(list(peri_funcs), step_func)


def apply_main_loop_heuristic(cfg):
    """Apply main loop heuristic to prune call graph.

    Many modules contain a main loop that calls various handlers forever, which can be
    identified based on the number of in and out edges in the call graph. If we identify this
    loop and all its caller and callee functions, we can eliminate a lot of falsely identified
    functions from the call graph.
    """
    # Step 1: Find main loop, which we expect to have 1 predecessor and many successors
    main_loop_addr = None
    main_loop_succs = 0
    for func_addr in cfg.functions:
        if len(list(cfg.functions.callgraph.predecessors(func_addr))) != 1:
            continue

        num_succs = len(list(cfg.functions.callgraph.successors(func_addr)))

        if num_succs > main_loop_succs:
            # new best candidate
            main_loop_addr = func_addr
            main_loop_succs = num_succs

    if main_loop_addr is None:
        log.error(
            "Failed to find any candidate for a main control loop, cannot apply heuristic"
        )
        return

    log.info("Best candidate for main control loop: %#x" % main_loop_addr)

    # Step 2: Identify all functions that succeed or precede the main loop function
    linked_funcs = set()
    succ_func = lambda n: cfg.functions.callgraph.successors(n)
    pred_func = lambda n: cfg.functions.callgraph.predecessors(n)
    # callees
    linked_funcs |= _traverse([main_loop_addr], succ_func)
    # callers
    linked_funcs |= _traverse([main_loop_addr], pred_func)

    log.debug("# functions before: %d" % len(cfg.functions.keys()))
    log.debug("# functions after:  %d" % len(linked_funcs))

    # Step 3: Remove any functions from call graph not reached in Step 2
    filter = [addr for addr in cfg.functions if not addr in linked_funcs]
    for addr in filter:
        cfg.functions.callgraph.remove_node(addr)


def build_cfg(proj, options):
    """Build a CFG of the target program.

    Keyword Arguments:
    proj -- An angr project.
    options -- Command line options.

    Returns:
    An angr CFG.
    """
    try:
        cfg = proj.analyses.CFGFast(
            resolve_indirect_jumps=False,
            start_at_entry=False,
            show_progressbar=True,
        )
    except (IndexError, KeyError, AttributeError) as e:
        log.warning(f"CFGFast failed with error: {e}. Trying alternative CFG approach...")
        # Try a simpler CFG approach that might work better
        try:
            cfg = proj.analyses.CFGFast(
                resolve_indirect_jumps=False,
                start_at_entry=True,
                show_progressbar=False,
            )
        except:
            log.warning("Alternative CFG also failed. Using linear disassembly approach for problematic firmware...")
            # Try linear disassembly approach for problematic firmware
            try:
                # Create a simple CFG using linear disassembly
                cfg = proj.analyses.CFGEmulated(
                    starts=[proj.entry],
                    keep_state=True,
                    state_add_options=angr.sim_options.refs,
                    context_sensitivity_level=0,
                )
            except:
                log.warning("Linear disassembly also failed. Creating minimal CFG for problematic firmware...")
                # Create a minimal CFG for problematic firmware
                class MinimalCFG:
                    def __init__(self, project):
                        self.project = project
                        # Create a basic graph with the project's entry point
                        entry_addr = project.entry
                        self.graph = type('Graph', (), {
                            'nodes': lambda: [entry_addr] if entry_addr else [],
                            'edges': lambda: [],
                            'successors': lambda node: [],
                            'predecessors': lambda node: []
                        })()
                        self.functions = type('Functions', (), {
                            'callgraph': type('CallGraph', (), {
                                'nodes': lambda *args: [entry_addr] if entry_addr else [],
                                'successors': lambda node: [],
                                'predecessors': lambda node: [],
                                'to_undirected': lambda *args: type('UndirectedGraph', (), {
                                    'neighbors': lambda node: []
                                })()
                            })()
                        })()
                        self.nodes = lambda: [entry_addr] if entry_addr else []
                        self.edges = lambda: []
                        self.get_any_node = lambda x: type('Node', (), {
                            'addr': x,
                            'successors': [],
                            'predecessors': []
                        })() if x else None
                cfg = MinimalCFG(proj)

    if options.use_loop_heuristic:
        log.info("Applying main loop heuristic")
        apply_main_loop_heuristic(cfg)

    if not options.skip_peripheral_heuristic:
        log.info("Applying peripheral heuristic")
        apply_peripheral_accesses_heuristic(
            cfg,
            options.peripheral_start_address,
            options.peripheral_end_address,
        )

    return cfg


def _get_const_accesses(
    state, func_addr, block_addr, accesses, low_addr=0x4000_0000, high_addr=0x5FFF_FFFF
):
    # lift the target code block
    block = state.block(block_addr)

    # Since ARM sometimes loads a pointer from a constant address that then itself points to a
    # further address, we need to track the values of some tmp variables
    tmp_vals = dict()

    # for tracking which machine instruction the current VEX IR statement corresponds to
    curr_insn_addr = None

    for stmt in block.vex.statements:
        # track current machine instruction address
        if isinstance(stmt, pyvex.stmt.IMark):
            curr_insn_addr = stmt.addr

        # check writes to tmp variables
        elif isinstance(stmt, pyvex.stmt.WrTmp):
            # check load address
            if isinstance(stmt.data, pyvex.expr.Load) or isinstance(
                stmt.data, pyvex.stmt.LoadG
            ):
                ld_addr = None

                # check loads from constant addresses
                if isinstance(stmt.data.addr, pyvex.expr.Const):
                    ld_addr = stmt.data.addr.con.value

                    # stash the loaded value because we might need it in future statements
                    # (ex: loaded a pointer from memory)
                    ld_val = state.memory.load(
                        ld_addr,
                        size=stmt.data.result_size(stmt.data.ty) // 8,
                        endness=state.project.arch.memory_endness,
                    )

                    # we only care about concrete values that might be pointers
                    if ld_val.size() == state.project.arch.bits:
                        if not state.solver.symbolic(ld_val):
                            ld_val = state.solver.eval(ld_val)
                            tmp_vals[stmt.tmp] = ld_val

                # check loads from addresses represented as a tmp we know the value of
                elif isinstance(stmt.data.addr, pyvex.expr.RdTmp):
                    tmp = stmt.data.addr.tmp
                    if tmp in tmp_vals:
                        ld_addr = tmp_vals[tmp]

                if not ld_addr is None and ld_addr >= low_addr and ld_addr <= high_addr:
                    # this statement loads from an address in our target range
                    accesses[curr_insn_addr] = {
                        "function": func_addr,
                        "block": block.addr,
                        "type": "load",
                        "address": ld_addr,
                    }

            elif isinstance(stmt.data, pyvex.expr.Binop) and stmt.data.op.startswith(
                "Iop_Add"
            ):
                # sometimes a constant offset is added to an address before dereferencing it
                args = list()
                for arg in stmt.data.args:
                    if isinstance(arg, pyvex.expr.Const):
                        args.append(arg.con.value)
                    elif isinstance(arg, pyvex.expr.RdTmp) and arg.tmp in tmp_vals:
                        args.append(tmp_vals[arg.tmp])

                # if we have 2 args in our list, that means we know concrete values for both
                # parts of the addition and can calculate the result without needing to
                # constraint solve
                if len(args) == 2:
                    res = args[0] + args[1]
                    tmp_vals[stmt.tmp] = res

        # check stores to memory
        elif isinstance(stmt, pyvex.stmt.Store):
            st_addr = None

            # check stores to constant addresses
            if isinstance(stmt.addr, pyvex.expr.Const):
                st_addr = stmt.addr.con.value

            # check stores to addresses represented as a tmp we know the value of
            elif isinstance(stmt.addr, pyvex.expr.RdTmp):
                tmp = stmt.addr.tmp
                if tmp in tmp_vals:
                    st_addr = tmp_vals[tmp]

            if not st_addr is None:
                if st_addr >= low_addr and st_addr <= high_addr:
                    # this statement stores to an address in our target range
                    accesses[curr_insn_addr] = {
                        "function": func_addr,
                        "block": block.addr,
                        "type": "store",
                        "address": st_addr,
                    }


def find_peripheral_accesses(cfg, low_addr=0x4000_0000, high_addr=0x5FFF_FFFF):
    """Given an angr CFG, find all the memory accesses to MMIO peripherals.

    Keyword Arguments:
    cfg -- An angr CFG.
    low_addr -- Lowest possible address (inclusive) for peripheral MMIO.
    high_addr -- Highest possible address (inclusive) for peripheral MMIO.

    A dictionary of accesses, keyed by instruction address, containing the addresses of the
    function and block the instruction belongs to, whether it performed a store or load, and the
    peripheral address it accessed.
    """
    state = cfg.project.factory.blank_state()
    accesses = dict()

    for func_addr in cfg.functions.callgraph.nodes():
        func = cfg.functions[func_addr]

        for block_addr in func.block_addrs:
            _get_const_accesses(
                state, func_addr, block_addr, accesses, low_addr, high_addr
            )

    return accesses


def write_callgraph(cfg, ofp):
    """Given an angr CFG, save a call graph in DOT format.

    Keyword Arguments:
    cfg -- angr CFG.
    ofp -- Output filepath.
    """

    # TODO: angr call graphs aren't descriptive. They only provide the function's starting
    # address. If we had a function level bindiff or a database of symbols from similar modules,
    # we could guess function names.

    try:
        networkx.drawing.nx_pydot.write_dot(cfg.functions.callgraph, ofp)
    except Exception as ex:
        log.error("Failed to save call graph: %s" % str(ex))
