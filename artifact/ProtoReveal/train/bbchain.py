import features
import angr
import pandas as pd


def Register_Add(accesses, BB_addr):
    # key: memory address
    # val: dictionary (key: function address, val: rw)
    by_mem_addr = dict()

    for insn_addr in accesses:
        info = accesses[insn_addr]
        mem_addr = info["address"]
        func_addr = info["block"]
        access = info["type"]

        if not mem_addr in by_mem_addr:
            by_mem_addr[mem_addr] = dict()
        if not func_addr in by_mem_addr[mem_addr]:
            by_mem_addr[mem_addr][func_addr] = 0

        if access == "store":
            by_mem_addr[mem_addr][func_addr] |= 2
        elif access == "load":
            by_mem_addr[mem_addr][func_addr] |= 1

    mem_addrs = list(by_mem_addr.keys())
    mem_addrs.sort()
    for peri_addr in mem_addrs:
        func_addrs = list(by_mem_addr[peri_addr].keys())
        func_addrs.sort()

        for func_addr in func_addrs:
            if BB_addr == func_addr:
                return peri_addr


def ext_chain(peri_accesses, cfg):
    groups = []
    for k, v in peri_accesses.items():
        block = v["block"]
        block_node = cfg.get_any_node(block)
        if v["type"] == "load":  # proceding for read operations
            g = features.get_n_pred_or_succ(cfg.graph, block_node, 1, True)
            groups.append([block_node, g])
        else:  # proceding for write operations
            g = features.get_n_pred_or_succ(cfg.graph, block_node, 1, False)
            groups.append([block_node, g])
    print(groups)
    return groups


def chain_dataset(cfg: angr.analyses.cfg, groups, label, num, path, acc):
    chain = {}
    data = dict()

    ops = [
        "FM.no",
        "Name",
        "BB_Addr",
        "Reg_add",
        "Shl",
        "Shr",
        "Mul",
        "Sub",
        "Add",
        "Div",
        "And",
        "Or",
        "Xor",
        "Cmp",
        "Succ_len",
        "pred_len",
        "GET",
        "PUT",
        "jk",
        "peripheral",
    ]

    for op in ops:
        temp = []
        temp2 = []
        data[op] = temp
        chain[op] = temp2
        Record = {}

    for group in groups:
        for op in ops:
            temp = []
            chain[op] = temp
        head = group[0]
        ch = group[1]
        print(ch)
        for block in ch:
            if block.block != None:
                f = features.get_features(block.block, cfg, block_addr=block.block.addr)
                for op in ops:
                    if op == "jk":
                        if f[op] == "Ijk_Ret":
                            temp = chain[op]
                            temp.append(0)
                        if f[op] == "Ijk_Boring":
                            temp = chain[op]
                            temp.append(1)
                        if f[op] == "Ijk_Call":
                            temp = chain[op]
                            temp.append(2)
                    elif op == "peripheral":
                        temp = chain[op]
                        temp.append(label)
                    elif op == "Name":
                        temp = chain[op]
                        temp.append(path)
                    elif op == "FM.no":
                        temp = chain[op]
                        temp.append(num)
                    elif op == "BB_Addr":
                        temp = chain[op]
                        temp.append(hex((block.block.addr)))
                    elif op == "Reg_add":
                        temp = chain[op]
                        a = Register_Add(acc, block.block.addr)
                        if a != None:
                            temp.append(hex(a))
                        else:
                            temp.append(" ")
                    else:
                        m = f[op]
                        temp = chain[op]
                        temp.append(m)

        for op in ops:
            if op == "peripheral":
                temp = data[op]
                temp.append(label)
            elif op == "peripheral":
                temp = data[op]
                temp.append(label)
            elif op == "Name":
                temp = data[op]
                temp.append(path)
            elif op == "FM.no":
                temp = data[op]
                temp.append(num)
            elif op == "BB_Addr":
                temp = data[op]
                a = chain["BB_Addr"]

                temp.append(hex(head.block.addr))
            elif op == "Reg_add":
                temp = data[op]
                a = Register_Add(acc, head.block.addr)
                if a != None:
                    temp.append(hex(a))
                else:
                    temp.append(" ")

            else:
                temp = chain[op]
                add = sum(temp)
                temp = data[op]
                temp.append(add)

    df = pd.DataFrame(data=data)

    try:
        df2 = pd.read_csv(f"Level2_Depth1.csv")
        df2 = df2.drop(["Unnamed: 0"], axis=1)
        vertical_concat = pd.concat([df, df2], axis=0)

        vertical_concat.to_csv(f"Level2_Depth1.csv")
    except:
        df.to_csv(f"Level2_Depth1.csv")
