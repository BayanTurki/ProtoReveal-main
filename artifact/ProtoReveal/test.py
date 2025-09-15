#!/usr/bin/env python

import pandas as pd
import logging
import os
from optparse import OptionGroup, OptionParser
import angr
import cle
import graph
import train.bbchain as bbchain
from pathlib import Path
import argparse

log = logging.getLogger(__name__)

PROGRAM_USAGE = "Usage: %prog [options] module"


def parse_args(path):
    parser = OptionParser(usage=PROGRAM_USAGE)

    group_analysis = OptionGroup(parser, "Analysis Options")
    group_analysis.add_option(
        "-a",
        "--arch",
        action="store",
        type="str",
        default="ARMEL",
        help="Machine architecture to use.",
    )
    group_analysis.add_option(
        "-b",
        "--base-addr",
        action="store",
        type="int",
        default=None,
        help="Base virtual address to load module. If none is provided, best guess will be made.",
    )
    group_analysis.add_option(
        "--use-loop-heuristic",
        action="store_true",
        default=False,
        help="Enable call graph pruning via main loop identification heuristic.",
    )
    group_analysis.add_option(
        "--skip-peripheral-heuristic",
        action="store_true",
        default=False,
        help="Disable call graph pruning via peripheral accesses heuristic.",
    )
    group_analysis.add_option(
        "--peripheral-start-address",
        action="store",
        type="int",
        default=0x4000_0000,
        help="Starting address for peripheral mapped memory (default: 0x40000000).",
    )
    group_analysis.add_option(
        "--peripheral-end-address",
        action="store",
        type="int",
        default=0x5FFF_FFFF,
        help="Ending address for peripheral mapped memory, inclusive (default: 0x5fffffff).",
    )
    group_analysis.add_option(
        "--analysis-depth",
        action="store",
        type="int",
        default=1,
        help="how deep to go with the data dependency graph",
    )
    group_analysis.add_option(
        "--cluster",
        action="store_true",
        default=True,
        help="do clustering heuristic",
    )
    parser.add_option_group(group_analysis)

    group_output = OptionGroup(parser, "Output Options")
    group_output.add_option(
        "--save-callgraph",
        action="store",
        type="str",
        default=None,
        help="Save recovered call graph in DOT format to the provided filepath.",
    )
    group_output.add_option(
        "--print-accesses",
        action="store_true",
        help="Print accessed peripheral addresses and the access locations.",
        default=False,
    )
    parser.add_option_group(group_output)

    group_symbex = OptionGroup(parser, "Symbolic execution options")
    group_symbex.add_option(
        "-e",
        "--execute",
        action="store_true",
        default=False,
        help="Symbolically execute the module(to observe the values written to peripherals).",
    )
    group_symbex.add_option(
        "-r",
        "--exec-reads",
        action="store_true",
        default=True,
        help="Symbolically execute basic blocks that only read from peripheral addresses.",
    )
    group_symbex.add_option(
        "--exec-func",
        type="int",
        action="store",
        help="symbolically execute this function (we only support exec'ing one function for now).",
    )
    group_symbex.add_option(
        "-d",
        "--ddg",
        action="store_true",
        default=False,
        help="Use ddg to recover constraints",
    )
    parser.add_option_group(group_symbex)

    group_logging = OptionGroup(parser, "Logging Options")
    group_logging.add_option(
        "-l",
        "--logging",
        action="store",
        type="int",
        default=20,
        help="Log level [10-50] (default: 20 - Info).",
    )
    group_logging.add_option(
        "--logging-angr",
        action="store",
        type="int",
        default=40,
        help="Level for Angr (default: Error).",
    )
    parser.add_option_group(group_logging)

    group_debug = OptionGroup(parser, "Debugging Options")
    group_debug.add_option(
        "-i",
        "--interactive",
        action="store_true",
        default=False,
        help="Spawn interactive shell after performing initial analysis.",
    )
    parser.add_option_group(group_debug)

    options, args = parser.parse_args()

    os.path.isfile(os.path.realpath(path))
    return (options, args)


def pp_memory_accesses(accesses, path, label):
    by_mem_addr = dict()

    for insn_addr in accesses:
        info = accesses[insn_addr]
        mem_addr = info["address"]
        func_addr = info["function"]
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

    log.info("Peripheral Accesses:")

    for peri_addr in mem_addrs:
        log.info("  Memory Address: %#x" % peri_addr)
        log.info(f"range: {path, label}")

        func_addrs = list(by_mem_addr[peri_addr].keys())
        func_addrs.sort()

        for func_addr in func_addrs:
            acc_flag = by_mem_addr[peri_addr][func_addr]
            acc_str = ["", "R", "W", "RW"][acc_flag]
            log.info("    Function %#x: %s" % (func_addr, acc_str))


def set_log_levels(options):
    """Sets all the log levels based on user provided options."""
    logging.getLogger(__name__).setLevel(options.logging)
    logging.getLogger(angr.__name__).setLevel(options.logging_angr)
    logging.getLogger(graph.__name__).setLevel(options.logging)


def main(args, options, label, num):
    main_bin_fp = args
    set_log_levels(options)
    # determine what the base address of the module should be
    if options.base_addr is None:
        log.info("No base address provided, using default value")
        options.base_addr = 0x100000
    log.info("Using base address: %#x" % options.base_addr)

    log.info("Loading module: %s" % main_bin_fp)
    with open(main_bin_fp, "rb") as ibin:
        blob = cle.Blob(
            binary=main_bin_fp,
            binary_stream=ibin,
            is_main_bin=True,
            arch=options.arch,
            base_addr=options.base_addr,
        )

    log.info("Creating project")
    format=Path(main_bin_fp).suffix
    if (format=='.bin'):
        #for bin
        with open(main_bin_fp, "rb") as ibin:
            blob = cle.Blob(
                    binary=main_bin_fp,
                    binary_stream=ibin,
                    is_main_bin=True,
                    arch=options.arch,
                    base_addr=options.base_addr
                    )
        proj = angr.Project(thing=blob,use_sim_procedures=False)

    else:
        #for elf    
        proj = angr.Project(main_bin_fp,auto_load_libs=True)

    log.info("Recovering control flow graph")
    cfg = graph.build_cfg(proj, options)

    if not options.save_callgraph is None:
        log.info("Saving call graph to: %s" % options.save_callgraph)
        graph.write_callgraph(cfg, options.save_callgraph)

    log.info("Recovering peripheral accesses")
    peri_accesses = graph.find_peripheral_accesses(
        cfg,
        options.peripheral_start_address,
        options.peripheral_end_address,
    )
    if options.print_accesses:
        pp_memory_accesses(peri_accesses, path, label)

    # *********
    # Basic Blocks chain features
    # *********
    grp = bbchain.ext_chain(peri_accesses, cfg)
    samp2 = bbchain.chain_dataset(
        cfg, groups=grp, label=label, num=num, path=path, acc=peri_accesses
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tool Options")
    parser.add_argument("FM", type=str, help="Name of Firmware")
    parser.add_argument("op", type=str, help="write predict for predict test for test")
    args = parser.parse_args()

    # path to this script's directory
    script_dir = os.path.dirname(os.path.realpath(__file__))
    data_dir = os.path.join(script_dir, "../data")
    mcus = [
        "M031M032",
        "M051",
        "M261:M262:M263",
        "M451",
        "M480",
        "Mini51",
        "Nano100",
        "NUC100:120",
        "NUC123",
        "NUC126",
        "NUC230240",
        "M251:M252",
        "M471",
        "Mini58",
        "NUC200",
        "NUC472:NUC442",
        "SAM3x8e",
        "STM32F",
        "STM32C",
        "STM32G",
        "STM32L",
        "EFM32HappyGecko",
        "EFM32LeopardGecko",
        "EFM32ZeroGecko",
        "MSP432E401Y",
        "MSPM0L1228",
        "MSPM0L2228",
        "K32L3",
        "LPC824",
        "LPC54114",
        "MXRT600",
        "PIC32MK",
        "PIC32MX",
        "PIC32MZ"
    ]
    num = 0

    if args.op == "test":
        for dirname in mcus:
            paths = os.listdir(os.path.join(data_dir, dirname))
            for path in paths:
                options, rgs = parse_args(path)
                options.arch = "armcortexm"
                options.print_accesses = True
                if "PIC32" in dirname:    
                    options.arch="mips32"
                options.print_accesses=True
                if path in args.FM or args.FM in path:
                    print(f"Processing firmware: {path} in directory: {dirname}")
                    try:
                        if (dirname == "PIC32MX"):
                            num = num + 1

                            
                            options.peripheral_start_address = 0xBF800000
                            options.peripheral_end_address = 0xBF8001FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF800200
                            options.peripheral_end_address = 0xBF8003FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF800600
                            options.peripheral_end_address = 0xBF800FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF802000
                            options.peripheral_end_address = 0xBF8029FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "InputCapture",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF803000
                            options.peripheral_end_address = 0xBF8039FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "OutputCompare",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF805000
                            options.peripheral_end_address = 0xBF8053FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF805800
                            options.peripheral_end_address = 0xBF805BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF806000
                            options.peripheral_end_address = 0xBF8063FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF807000
                            options.peripheral_end_address = 0xBF8071FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ParallelMasterPort",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF808000
                            options.peripheral_end_address = 0xBF8081FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF809000
                            options.peripheral_end_address = 0xBF8091FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF809800
                            options.peripheral_end_address = 0xBF8099FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ComparatorVoltageREF",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF80A000
                            options.peripheral_end_address = 0xBF80A1FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "Comparator",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF80F000
                            options.peripheral_end_address = 0xBF80F1FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "Oscillator",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF80F200
                            options.peripheral_end_address = 0xBF80F3FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "Configuration",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF80F400
                            options.peripheral_end_address = 0xBF80F5FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "Flash-nvm",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF80F600
                            options.peripheral_end_address = 0xBF80F7FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "Reset",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF881000
                            options.peripheral_end_address = 0xBF881FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "Interrupts",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF882000
                            options.peripheral_end_address = 0xBF882FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "BusMatrix",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF883000
                            options.peripheral_end_address = 0xBF883FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF884000
                            options.peripheral_end_address = 0xBF884FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "PrefetchCache",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF886000
                            options.peripheral_end_address = 0xBF8861FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                        elif (dirname == "PIC32MZ"):
                            num = num + 1

                            
                            options.peripheral_start_address = 0xBF8E0000
                            options.peripheral_end_address = 0xBF8E0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "PrefetchCache",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF8E1000
                            options.peripheral_end_address = 0xBF8E1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ebi",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF8E2000
                            options.peripheral_end_address = 0xBF8E2FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sqi",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF8E3000
                            options.peripheral_end_address = 0xBF8E4FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usb",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF8E5000
                            options.peripheral_end_address = 0xBF8E5FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "Crypto",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF8E6000
                            options.peripheral_end_address = 0xBF8E6020
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rng",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF880000
                            options.peripheral_end_address = 0xBF881FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "can",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF882000
                            options.peripheral_end_address = 0xBF883FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "Ethernet",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF884000
                            options.peripheral_end_address = 0xBF884FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "USBCR",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF860000
                            options.peripheral_end_address = 0xBF8609B0
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "port",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF840000
                            options.peripheral_end_address = 0xBF841FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF842000
                            options.peripheral_end_address = 0xBF843FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "InputCapture",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF844000
                            options.peripheral_end_address = 0xBF84AFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "OutputCompare",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF84B000
                            options.peripheral_end_address = 0xBF84BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF84C000
                            options.peripheral_end_address = 0xBF84CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "Comparator",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF820000
                            options.peripheral_end_address = 0xBF820FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF821000
                            options.peripheral_end_address = 0xBF821FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF822000
                            options.peripheral_end_address = 0xBF82DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "UART",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF82E000
                            options.peripheral_end_address = 0xBF82E090
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ParallelMasterPort",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF810000
                            options.peripheral_end_address = 0xBF810FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "Interrupts",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF811000
                            options.peripheral_end_address = 0xBF811650
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF800000
                            options.peripheral_end_address = 0xBF8005FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "Configuration",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF800600
                            options.peripheral_end_address = 0xBF8007FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "FlashController",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF800800
                            options.peripheral_end_address = 0xBF8009FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF800A00
                            options.peripheral_end_address = 0xBF800BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dmt",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF800C00
                            options.peripheral_end_address = 0xBF800DFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "RTCC",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF800E00
                            options.peripheral_end_address = 0xBF8011FF

                        elif (dirname == "PIC32MK"):
                            num = num + 1

                            
                            options.peripheral_start_address = 0xBF800000
                            options.peripheral_end_address = 0xBF8007FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "CFG-PMD",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF800800
                            options.peripheral_end_address = 0xBF8009FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "PrefetchCache",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF800A00
                            options.peripheral_end_address = 0xBF800BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "FC-NVM",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF800C00
                            options.peripheral_end_address = 0xBF800DFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF800E00
                            options.peripheral_end_address = 0xBF80FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dmt",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF801000
                            options.peripheral_end_address = 0xBF8011FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "icd",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF801200
                            options.peripheral_end_address = 0xBF8013FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "Oscillator",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF801400
                            options.peripheral_end_address = 0xBF801799
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pps",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF801800
                            options.peripheral_end_address = 0xBF801800
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "plvd",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF810000
                            options.peripheral_end_address = 0xBF810FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "EVIC",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF811000
                            options.peripheral_end_address = 0xBF811650
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF820000
                            options.peripheral_end_address = 0xBF821FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF822000
                            options.peripheral_end_address = 0xBF823FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "InputCapture",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF824000
                            options.peripheral_end_address = 0xBF825FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "OutputCompare",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF826000
                            options.peripheral_end_address = 0xBF826FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF827000
                            options.peripheral_end_address = 0xBF827FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF828000
                            options.peripheral_end_address = 0xBF828FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF829000
                            options.peripheral_end_address = 0xBF829FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "DATAEE",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF82A000
                            options.peripheral_end_address = 0xBF82B1FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                           
                            options.peripheral_start_address = 0xBF82B200
                            options.peripheral_end_address = 0xBF82BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "qei",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF82C000
                            options.peripheral_end_address = 0xBF82C1FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "Comparator",
                                num,
                            )

                            
                            options.peripheral_start_address = 0xBF82D000
                            options.peripheral_end_address = 0xBF82DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "CTMU",
                                num,
                            )

                            # Parallel Master Port 0xBF82E000 - 0xBF82F000
                            options.peripheral_start_address = 0xBF82E000
                            options.peripheral_end_address = 0xBF82F000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ParallelMasterPort",
                                num,
                            )

                            # RTCC 0xBF8C0000 - 0xBF8C01FF
                            options.peripheral_start_address = 0xBF8C0000
                            options.peripheral_end_address = 0xBF8C01FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "RTCC",
                                num,
                            )

                            # Deep Sleep 0xBF8C0200 - 0xBF8C02FF
                            options.peripheral_start_address = 0xBF8C0200
                            options.peripheral_end_address = 0xBF8C02FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "DeepSleep",
                                num,
                            )

                            # SSXCTL 0xBF8F0000 - 0xBF8F0100
                            options.peripheral_start_address = 0xBF8F0000
                            options.peripheral_end_address = 0xBF8F0100
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "SSXCTL",
                                num,
                            )

#################################################################

                        elif (dirname == "M261:M262:M263"):
                            num = num + 1
                            # SPI 0x4006_1000 –  0x4006_4FFF
                            options.peripheral_start_address = 0x40061000
                            options.peripheral_end_address = 0x40064FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # i2c 0x40080000   0x40082FFF
                            options.peripheral_start_address = 0x40080000
                            options.peripheral_end_address = 0x40082FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # UART 0x40070000  0x40075FFF
                            options.peripheral_start_address = 0x40070000
                            options.peripheral_end_address = 0x40075FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking CLK_BA 0x4000_0200 – 0x4000_02FF
                            options.peripheral_start_address = 0x40000200
                            options.peripheral_end_address = 0x400002FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking NMI_BA 0x40000300 – 0x400003FF
                            options.peripheral_start_address = 0x40000300
                            options.peripheral_end_address = 0x400003FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "nmi",
                                num,
                            )

                            ##checking GPIO_BA 0x40004000 – 0x40004FFF
                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40004FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking USBH_BA 0x40009000 – 0x40009FFF
                            options.peripheral_start_address = 0x40009000
                            options.peripheral_end_address = 0x40009FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbh",
                                num,
                            )

                            ##checking DMA_BA 0x40008000 – 0x40008FFF
                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x40008FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            ##checking CRC_BA 0x40031000 – 0x40031FFF
                            options.peripheral_start_address = 0x40031000
                            options.peripheral_end_address = 0x40031FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            ##checking FMC_BA 0x4000C000 – 0x4000CFFF
                            options.peripheral_start_address = 0x4000C000
                            options.peripheral_end_address = 0x4000CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking EBI_BA 0x40010000 – 0x40010FFF
                            options.peripheral_start_address = 0x40010000
                            options.peripheral_end_address = 0x40010FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ebi",
                                num,
                            )

                            ##checking WDT_BA 0x40040000 – 0x40040FFF
                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40040FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking RTC_BA 0x40041000 – 0x40041FFF
                            options.peripheral_start_address = 0x40041000
                            options.peripheral_end_address = 0x40041FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            ##checking EADC_BA 0x40043000 – 0x40043FFF
                            options.peripheral_start_address = 0x40043000
                            options.peripheral_end_address = 0x40043FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "eadc",
                                num,
                            )

                            ##checking ACMP_BA  0x40045000 – 0x40045FFF
                            options.peripheral_start_address = 0x40045000
                            options.peripheral_end_address = 0x40045FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            ##checking DAC_BA 0x40047000 – 0x40047FFF
                            options.peripheral_start_address = 0x40047000
                            options.peripheral_end_address = 0x40047FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dac",
                                num,
                            )

                            ##checking I2S_BA  0x40048000 – 0x40048FFF
                            options.peripheral_start_address = 0x40048000
                            options.peripheral_end_address = 0x40048FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2s",
                                num,
                            )

                            ##checking OTG_BA 0x4004D000 – 0x4004DFFF
                            options.peripheral_start_address = 0x4004D000
                            options.peripheral_end_address = 0x4004DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "otg",
                                num,
                            )

                            ##checking TMR_BA 0x40051000 – 0x40051FFF
                            options.peripheral_start_address = 0x40050000
                            options.peripheral_end_address = 0x40051FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking EPWM_BA 0x40059000 – 0x40059FFF
                            options.peripheral_start_address = 0x40058000
                            options.peripheral_end_address = 0x40059FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "epwm",
                                num,
                            )

                            ##checking BPWM_BA  0x4005_B000 – 0x4005_BFFF
                            options.peripheral_start_address = 0x4005A000
                            options.peripheral_end_address = 0x4005BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "bpwm",
                                num,
                            )

                            ##checking QSPI_BA  0x40060000 – 0x40060FFF
                            options.peripheral_start_address = 0x40060000
                            options.peripheral_end_address = 0x40060FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "qspi",
                                num,
                            )

                            # checking SC0_BA  0x40090000 – 0x40092FFF
                            options.peripheral_start_address = 0x40090000
                            options.peripheral_end_address = 0x40092FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sc",
                                num,
                            )

                            ##checking QEI_BA 0x400B0000 – 0x400B1FFF
                            options.peripheral_start_address = 0x400B0000
                            options.peripheral_end_address = 0x400B1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "qei",
                                num,
                            )

                            ##checking ECAP_BA 0x400B4000 – 0x400B5FFF
                            options.peripheral_start_address = 0x400B4000
                            options.peripheral_end_address = 0x400B5FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ecap",
                                num,
                            )

                            ##checking TRNG_BA   0x400B9000 – 0x400B9FFF
                            options.peripheral_start_address = 0x400B9000
                            options.peripheral_end_address = 0x400B9FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "trng",
                                num,
                            )

                            ##checking USBD_BA   0x400C0000 – 0x400C0FFF
                            options.peripheral_start_address = 0x400C0000
                            options.peripheral_end_address = 0x400C0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbd",
                                num,
                            )

                            ##checking USCI_BA 0x400D1000 – 0x400D1FFF
                            options.peripheral_start_address = 0x400D0000
                            options.peripheral_end_address = 0x400D1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usci",
                                num,
                            )

                            ## SYS newly add
                            options.peripheral_start_address = 0x40000000
                            options.peripheral_end_address = 0x400001FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            ## SDH newly add
                            options.peripheral_start_address = 0x4000D000
                            options.peripheral_end_address = 0x4000_DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sdh",
                                num,
                            )

                            
                            options.peripheral_start_address = 0x40032000
                            options.peripheral_end_address = 0x40034FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crpt",
                                num,
                            )

                            
                            options.peripheral_start_address = 0x400A0000
                            options.peripheral_end_address = 0x400A0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "can",
                                num,
                            )

                            ###########################################################################################
                        elif dirname == "SAM3x8e":
                            num = num + 1

                            options.peripheral_start_address = 0x40000000
                            options.peripheral_end_address = 0x40003FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "hasmci",
                                num,
                            )

                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ssc",
                                num,
                            )

                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x4007FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            options.peripheral_start_address = 0x40080000
                            options.peripheral_end_address = 0x40083FFF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tc",
                                num,
                            )

                            options.peripheral_start_address = 0x40084000
                            options.peripheral_end_address = 0x40087FFF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tc",
                                num,
                            )

                            options.peripheral_start_address = 0x40088000
                            options.peripheral_end_address = 0x4008BFFF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tc",
                                num,
                            )

                            options.peripheral_start_address = 0x4008C000  # ok
                            options.peripheral_end_address = 0x40093FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "twi",
                                num,
                            )

                            options.peripheral_start_address = 0x40094000  # ok
                            options.peripheral_end_address = 0x40097FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            options.peripheral_start_address = 0x40098000
                            options.peripheral_end_address = 0x400A7FFF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usart",
                                num,
                            )

                            options.peripheral_start_address = 0x400AC000
                            options.peripheral_end_address = 0x400AFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )  # ok

                            options.peripheral_start_address = 0x400B0000
                            options.peripheral_end_address = 0x400B3FFF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "emac",
                                num,
                            )

                            options.peripheral_start_address = 0x400B4000
                            options.peripheral_end_address = 0x400BBFFF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "can",
                                num,
                            )

                            options.peripheral_start_address = 0x400BC000
                            options.peripheral_end_address = 0x400BFFFF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "trng",
                                num,
                            )

                            options.peripheral_start_address = 0x400C0000
                            options.peripheral_end_address = 0x400C3FFF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x400C4000
                            options.peripheral_end_address = 0x400C7FFF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dmac",
                                num,
                            )

                            options.peripheral_start_address = 0x400C8000
                            options.peripheral_end_address = 0x400CFFFF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dacc",
                                num,
                            )

                            # system controller

                            options.peripheral_start_address = 0x400E0000
                            options.peripheral_end_address = 0x400E01FF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "smc",
                                num,
                            )

                            options.peripheral_start_address = 0x400E0600
                            options.peripheral_end_address = 0x400E07FF  # ok 0x400e0600
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pmc",
                                num,
                            )

                            options.peripheral_start_address = 0x400E0800
                            options.peripheral_end_address = 0x400E093F  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            options.peripheral_start_address = 0x400E0940
                            options.peripheral_end_address = 0x400E09FF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "chipid",
                                num,
                            )

                            options.peripheral_start_address = 0x400E0A00
                            options.peripheral_end_address = 0x400E0DFF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "eefc",
                                num,
                            )

                            options.peripheral_start_address = 0x400E0E00
                            options.peripheral_end_address = 0x400E19FF  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pio",
                                num,
                            )

                            options.peripheral_start_address = 0x400E1A00
                            options.peripheral_end_address = 0x400E1A0F  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rstc",
                                num,
                            )

                            options.peripheral_start_address = 0x400E1A10
                            options.peripheral_end_address = 0x400E1A2F  # ok
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "supc",
                                num,
                            )

                            options.peripheral_start_address = 0x400E1A30  # ok
                            options.peripheral_end_address = 0x400E1A4F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtt",
                                num,
                            )

                            options.peripheral_start_address = 0x400E1A50
                            options.peripheral_end_address = 0x400E1A5F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            options.peripheral_start_address = 0x400E1A60  # ok
                            options.peripheral_end_address = 0x400E1A8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            options.peripheral_start_address = 0x400E1A90  # ok
                            options.peripheral_end_address = 0x400E1AAF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gbpr",
                                num,
                            )

                        elif dirname == "Mini51":  # Done
                            num = num + 1
                            options.peripheral_start_address = 0x40030000
                            options.peripheral_end_address = 0x40033FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # I2c 0x40020000 – 0x40023FFF
                            options.peripheral_start_address = 0x40020000
                            options.peripheral_end_address = 0x40023FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # uart 0x4005_0000 – 0x40053FFF
                            options.peripheral_start_address = 0x40050000
                            options.peripheral_end_address = 0x40053FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking GCR_BA 0x5000_0000 – 0x5000_01FF
                            options.peripheral_start_address = 0x50000000
                            options.peripheral_end_address = 0x500001FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gcr",
                                num,
                            )

                            ##checking CLK_BA 0x5000_0200 – 0x5000_02FF
                            options.peripheral_start_address = 0x50000200
                            options.peripheral_end_address = 0x500002FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking INT_BA 0x5000_0300 – 0x5000_03FF
                            options.peripheral_start_address = 0x50000300
                            options.peripheral_end_address = 0x500003FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "int",
                                num,
                            )

                            ##checking GPIO_BA 0x5000_4000 – 0x5000_7FFF
                            options.peripheral_start_address = 0x50004000
                            options.peripheral_end_address = 0x50007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking FMC_BA 0x5000_C000 – 0x5000_FFFF
                            options.peripheral_start_address = 0x5000C000
                            options.peripheral_end_address = 0x5000FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking WDT_BA 0x4000_4000 – 0x4000_7FFF
                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking TMR_BA  0x40010000 – 0x40013FFF
                            options.peripheral_start_address = 0x40010000
                            options.peripheral_end_address = 0x40013FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking PWM_BA  0x40040000 – 0x40043FFF
                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40043FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking ACMP_BA  0x400D0000 – 0x400D3FFF
                            options.peripheral_start_address = 0x400D0000
                            options.peripheral_end_address = 0x400D3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            ##checking ADC12_BA 0x400E0000 – 0x400E3FFF
                            options.peripheral_start_address = 0x400E0000
                            options.peripheral_end_address = 0x400E3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            # checking SCS_BA  sure 0xE000_ED00 – 0xE000_ED8F
                            options.peripheral_start_address = 0xE000E010
                            options.peripheral_end_address = 0xE000ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                        elif dirname == "NUC123":  # Done
                            num = num + 1
                            # SPI 0x4003_0000 – 0x4003_3FFF
                            options.peripheral_start_address = 0x40030000
                            options.peripheral_end_address = 0x40037FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )
                            options.peripheral_start_address = 0x40130000
                            options.peripheral_end_address = 0x40133FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # I2C 0x4012_0000 – 0x4012_3FFF
                            options.peripheral_start_address = 0x40020000
                            options.peripheral_end_address = 0x40023FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )
                            options.peripheral_start_address = 0x40120000
                            options.peripheral_end_address = 0x40123FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # UART 0x40150000 – 0x40153FFF
                            options.peripheral_start_address = 0x40050000
                            options.peripheral_end_address = 0x40053FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )
                            options.peripheral_start_address = 0x40150000
                            options.peripheral_end_address = 0x40153FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking GCR_BA 0x50000000 – 0x500001FF
                            options.peripheral_start_address = 0x50000000
                            options.peripheral_end_address = 0x500001FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gcr",
                                num,
                            )

                            ##checking CLK_BA 0x5000_0200 – 0x5000_02FF
                            options.peripheral_start_address = 0x50000200
                            options.peripheral_end_address = 0x500002FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking INT_BA 0x5000_0300 – 0x5000_03FF
                            options.peripheral_start_address = 0x50000300
                            options.peripheral_end_address = 0x500003FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "int",
                                num,
                            )

                            ##checking GPIO_BA 0x5000_4000 – 0x5000_7FFF
                            options.peripheral_start_address = 0x50004000
                            options.peripheral_end_address = 0x50007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking DMA_BA 0x5000_8000 – 0x5000_BFFF
                            options.peripheral_start_address = 0x50008000
                            options.peripheral_end_address = 0x5000BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            ##checking FMC_BA 0x5000_C000 – 0x5000_FFFF
                            options.peripheral_start_address = 0x5000C000
                            options.peripheral_end_address = 0x5000FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking WDT_BA 0x4000_4000 – 0x4000_7FFF
                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking TMR_BA 0x4011_0000 – 0x4011_3FFF
                            options.peripheral_start_address = 0x40010000
                            options.peripheral_end_address = 0x40013FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )
                            options.peripheral_start_address = 0x40110000
                            options.peripheral_end_address = 0x40113FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking PWM_BA  0x40040000 – 0x40043FFF
                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40043FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking USBD_BA   0x40060000 – 0x40063FFF
                            options.peripheral_start_address = 0x40060000
                            options.peripheral_end_address = 0x40063FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbd",
                                num,
                            )

                            ##checking ADC12_BA 0x400E0000 – 0x400EFFFF
                            options.peripheral_start_address = 0x400E0000
                            options.peripheral_end_address = 0x400EFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            ##checking PS2_BA 0x4010_0000 – 0x4010_3FFF
                            options.peripheral_start_address = 0x40100000
                            options.peripheral_end_address = 0x40103FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ps2",
                                num,
                            )

                            ##checking I2S_BA  0x401A0000 – 0x401A3FFF
                            options.peripheral_start_address = 0x401A0000
                            options.peripheral_end_address = 0x401A3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2s",
                                num,
                            )

                            # checking SCS_BA  sure 0xE000_ED00 – 0xE000_ED8F
                            options.peripheral_start_address = 0xE000E010
                            options.peripheral_end_address = 0xE000ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                        elif dirname == "NUC126":  # Done
                            num = num + 1
                            # SYS newley added
                            options.peripheral_start_address = 0x50000000
                            options.peripheral_end_address = 0x500001FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            # SPI
                            options.peripheral_start_address = 0x40030000
                            options.peripheral_end_address = 0x40037FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # 12c 0x4012_0000 – 0x4012_3FFF
                            options.peripheral_start_address = 0x40020000
                            options.peripheral_end_address = 0x40023FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )
                            options.peripheral_start_address = 0x40120000
                            options.peripheral_end_address = 0x40123FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # UART 0x40150000 – 0x4015_3FFF
                            options.peripheral_start_address = 0x40050000
                            options.peripheral_end_address = 0x40053FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )
                            options.peripheral_start_address = 0x40150000
                            options.peripheral_end_address = 0x40157FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking CLK_BA 0x5000_0200 – 0x5000_02FF
                            options.peripheral_start_address = 0x50000200
                            options.peripheral_end_address = 0x500002FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking INT_BA 0x5000_0300 – 0x5000_03FF
                            options.peripheral_start_address = 0x50000300
                            options.peripheral_end_address = 0x500003FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "int",
                                num,
                            )

                            ##checking GPIO_BA 0x5000_4000 – 0x5000_7FFF
                            options.peripheral_start_address = 0x50004000
                            options.peripheral_end_address = 0x50007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking DMA_BA 0x5000_8000 – 0x5000_BFFF
                            options.peripheral_start_address = 0x50008000
                            options.peripheral_end_address = 0x5000BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            ##checking FMC_BA 0x5000C000 – 0x5000_FFFF
                            options.peripheral_start_address = 0x5000C000
                            options.peripheral_end_address = 0x5000FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking EBI_BA 0x5001_0000 – 0x5001_03FF
                            options.peripheral_start_address = 0x50010000
                            options.peripheral_end_address = 0x500103FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ebi",
                                num,
                            )

                            ##checking HDIV_BA 0x5001_4000 – 0x5001_7FFF
                            options.peripheral_start_address = 0x50014000
                            options.peripheral_end_address = 0x50017FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "hdiv",
                                num,
                            )

                            ##checking CRC_BA 0x50018000 – 0x5001FFFF
                            options.peripheral_start_address = 0x50018000
                            options.peripheral_end_address = 0x5001FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            ##checking WDT_BA 0x40004000 – 0x40007FFF
                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking RTC_BA 0x40008000 – 0x4000BFFF
                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x4000BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            ##checking TMR_BA 0x4011_0000 – 0x4011_3FFF
                            options.peripheral_start_address = 0x40010000
                            options.peripheral_end_address = 0x40013FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )
                            options.peripheral_start_address = 0x40110000
                            options.peripheral_end_address = 0x40113FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking PWM_BA  0x4014_0000 – 0x4014_3FFF
                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40043FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )
                            options.peripheral_start_address = 0x40140000
                            options.peripheral_end_address = 0x40143FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking USBD_BA   0x4006_0000 – 0x4006_3FFF
                            options.peripheral_start_address = 0x40060000
                            options.peripheral_end_address = 0x40063FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbd",
                                num,
                            )

                            ##checking USCI_BA 0x40074000 – 0x40077FFF
                            options.peripheral_start_address = 0x40070000
                            options.peripheral_end_address = 0x40077FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usci",
                                num,
                            )
                            options.peripheral_start_address = 0x40170000
                            options.peripheral_end_address = 0x40173FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usci",
                                num,
                            )

                            ##checking ACMP_BA  0x400D0000 – 0x400D3FFF
                            options.peripheral_start_address = 0x400D0000
                            options.peripheral_end_address = 0x400D3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            ##checking ADC12_BA  0x400E_0000 – 0x400E_FFFF
                            options.peripheral_start_address = 0x400E0000
                            options.peripheral_end_address = 0x400EFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            # checking SC0_BA  0x4019_4000 – 0x4019_7FFF
                            options.peripheral_start_address = 0x40190000
                            options.peripheral_end_address = 0x40197FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sc",
                                num,
                            )

                            # checking SCS_BA  sure 0xE000_ED00 – 0xE000_ED8F
                            options.peripheral_start_address = 0xE000E010
                            options.peripheral_end_address = 0xE000ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                        elif dirname == "NUC100:120":  # Done
                            num = num + 1
                            # SPI 0x40130000  –  0x40137FFF
                            options.peripheral_start_address = 0x40030000
                            options.peripheral_end_address = 0x40037FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )
                            options.peripheral_start_address = 0x40130000
                            options.peripheral_end_address = 0x40137FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # I2C 0x40120000 – 0x40123FFF
                            options.peripheral_start_address = 0x40020000
                            options.peripheral_end_address = 0x40023FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )
                            options.peripheral_start_address = 0x40120000
                            options.peripheral_end_address = 0x40123FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # UART 0x4015_0000 –  0x40157FFF
                            options.peripheral_start_address = 0x40050000
                            options.peripheral_end_address = 0x40053FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )
                            options.peripheral_start_address = 0x40150000
                            options.peripheral_end_address = 0x40157FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking GCR_BA 0x50000000 – 0x500001FF
                            options.peripheral_start_address = 0x50000000
                            options.peripheral_end_address = 0x500001FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gcr",
                                num,
                            )

                            ##checking CLK_BA  0x50000200 – 0x500002FF
                            options.peripheral_start_address = 0x50000200
                            options.peripheral_end_address = 0x500002FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking INT_BA 0x50000300 – 0x500003FF
                            options.peripheral_start_address = 0x50000300
                            options.peripheral_end_address = 0x500003FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "int",
                                num,
                            )

                            ##checking GPIO_BA 0x50004000 – 0x50007FFF
                            options.peripheral_start_address = 0x50004000
                            options.peripheral_end_address = 0x50007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking DMA 0x50008000 – 0x5000BFFF
                            options.peripheral_start_address = 0x50008000
                            options.peripheral_end_address = 0x5000BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            ##checking FMC_BA 0x5000C000 – 0x5000FFFF
                            options.peripheral_start_address = 0x5000C000
                            options.peripheral_end_address = 0x5000FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking WDT_BA 0x40004000 – 0x40007FFF
                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking RTC_BA 0x40008000 – 0x4000BFFF
                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x4000BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            ##checking PWM_BA  0x40140000 – 0x40143FFF
                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40043FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )
                            options.peripheral_start_address = 0x40140000
                            options.peripheral_end_address = 0x40143FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking USBD_BA   0x40060000 – 0x40063FFF
                            options.peripheral_start_address = 0x40060000
                            options.peripheral_end_address = 0x40063FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbd",
                                num,
                            )

                            ##checking ACMP_BA  0x400D0000 – 0x400D3FFF
                            options.peripheral_start_address = 0x400D0000
                            options.peripheral_end_address = 0x400D3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            ##checking ADC12_BA  0x400E0000 – 0x400EFFFF
                            options.peripheral_start_address = 0x400E0000
                            options.peripheral_end_address = 0x400EFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            ##checking PS2_BA 0x40100000 – 0x40103FFF
                            options.peripheral_start_address = 0x40100000
                            options.peripheral_end_address = 0x40103FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ps2",
                                num,
                            )

                            ##checking TMR_BA 0x40110000 – 0x40113FFF
                            options.peripheral_start_address = 0x40010000
                            options.peripheral_end_address = 0x40013FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )
                            options.peripheral_start_address = 0x40110000
                            options.peripheral_end_address = 0x40113FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            # checking SC0_BA
                            options.peripheral_start_address = 0x40190000
                            options.peripheral_end_address = 0x4019BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sc",
                                num,
                            )

                            # checking SCS_BA  sure 0xE000_ED00 – 0xE000_ED8F
                            options.peripheral_start_address = 0xE000E010
                            options.peripheral_end_address = 0xE000ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                            # checking I2S newly added
                            options.peripheral_start_address = 0x401A0000
                            options.peripheral_end_address = 0x401A3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2s",
                                num,
                            )

                        elif dirname == "M051":  # Done
                            num = num + 1
                            # SPI 0x40034000 – 0x40037FFF
                            options.peripheral_start_address = 0x40030000
                            options.peripheral_end_address = 0x40037FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # I2C
                            options.peripheral_start_address = 0x40020000
                            options.peripheral_end_address = 0x40023FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )
                            options.peripheral_start_address = 0x40120000
                            options.peripheral_end_address = 0x40123FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # UART 0x4015_0000 – 0x4015_3FFF
                            options.peripheral_start_address = 0x40050000
                            options.peripheral_end_address = 0x40053FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )
                            options.peripheral_start_address = 0x40150000
                            options.peripheral_end_address = 0x40153FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking GCR_BA 0x5000_0000 – 0x5000_01FF
                            options.peripheral_start_address = 0x50000000
                            options.peripheral_end_address = 0x500001FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gcr",
                                num,
                            )

                            ##checking CLK_BA  0x5000_0200 – 0x5000_02FF
                            options.peripheral_start_address = 0x50000200
                            options.peripheral_end_address = 0x500002FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking INT_BA 0x5000_0300 – 0x5000_03FF
                            options.peripheral_start_address = 0x50000300
                            options.peripheral_end_address = 0x500003FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "int",
                                num,
                            )

                            ##checking GPIO_BA 0x50004000 – 0x50007FFF
                            options.peripheral_start_address = 0x50004000
                            options.peripheral_end_address = 0x50007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking FMC_BA 0x5000C000 – 0x5000FFFF
                            options.peripheral_start_address = 0x5000C000
                            options.peripheral_end_address = 0x5000FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking EBI_BA 0x50010000 – 0x500103FF
                            options.peripheral_start_address = 0x50010000
                            options.peripheral_end_address = 0x500103FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ebi",
                                num,
                            )

                            ##checking HDIV_BA 0x50014000 – 0x50017FFF
                            options.peripheral_start_address = 0x50014000
                            options.peripheral_end_address = 0x50017FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "hdiv",
                                num,
                            )

                            ##checking WDT_BA 0x40004000 – 0x400000FF
                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x400000FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking WWDT_BA newly added
                            options.peripheral_start_address = 0x40004100
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking TMR_BA  0x40110000 – 0x40113FFF
                            options.peripheral_start_address = 0x40010000
                            options.peripheral_end_address = 0x40013FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )
                            options.peripheral_start_address = 0x40110000
                            options.peripheral_end_address = 0x40113FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking PWM  0x40040000 – 0x40043FFF
                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40043FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking PWMB newly added
                            options.peripheral_start_address = 0x40140000
                            options.peripheral_end_address = 0x40143FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking ACMP_BA  0x401D0000 – 0x401D3FFF
                            options.peripheral_start_address = 0x400D0000
                            options.peripheral_end_address = 0x400D3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )
                            options.peripheral_start_address = 0x401D0000
                            options.peripheral_end_address = 0x401D3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            ##checking ADC12_BA 0x400E0000 – 0x400EFFFF
                            options.peripheral_start_address = 0x400E0000
                            options.peripheral_end_address = 0x400EFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            # checking SCS_BA  sure 0xE000_ED00 – 0xE000_ED8F
                            options.peripheral_start_address = 0xE000E010
                            options.peripheral_end_address = 0xE000ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                        elif dirname == "M480":  # Done
                            num = num + 1
                            # SPI
                            options.peripheral_start_address = 0x40061000
                            options.peripheral_end_address = 0x40064FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # I2C
                            options.peripheral_start_address = 0x40080000
                            options.peripheral_end_address = 0x40082FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # UART 0x40070000  0x40077FFF
                            options.peripheral_start_address = 0x40070000
                            options.peripheral_end_address = 0x40077FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking CLK_BA
                            options.peripheral_start_address = 0x40000200
                            options.peripheral_end_address = 0x400002FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking NMI_BA 0x40000300 – 0x400003FF
                            options.peripheral_start_address = 0x40000300
                            options.peripheral_end_address = 0x400003FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "nmi",
                                num,
                            )

                            ##checking GPIO_BA 0x40004000 – 0x40004FFF
                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40004FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking DMA 0x40008000 – 0x40008FFF
                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x40008FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            ##checking USBH_BA 0x40009000 – 0x40009FFF
                            options.peripheral_start_address = 0x40009000
                            options.peripheral_end_address = 0x40009FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbh",
                                num,
                            )

                            ##checking FMC_BA 0x4000C000 – 0x4000CFFF
                            options.peripheral_start_address = 0x4000C000
                            options.peripheral_end_address = 0x4000CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking EBI_BA 0x40010000 – 0x40010FFF
                            options.peripheral_start_address = 0x40010000
                            options.peripheral_end_address = 0x40010FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ebi",
                                num,
                            )

                            ##checking CRC_BA 0x40031000 – 0x40031FFF
                            options.peripheral_start_address = 0x40031000
                            options.peripheral_end_address = 0x40031FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            ##checking WDT_BA 0x40040000 – 0x40040FFF
                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40040FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking RTC_BA 0x40041000 – 0x40041FFF
                            options.peripheral_start_address = 0x40041000
                            options.peripheral_end_address = 0x40041FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            ##checking ADC_BA 0x40043000 – 0x40043FFF
                            options.peripheral_start_address = 0x40043000
                            options.peripheral_end_address = 0x40043FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )
                            options.peripheral_start_address = 0x4004B000
                            options.peripheral_end_address = 0x4004BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            ##checking ACMP_BA 0x4004_5000 – 0x4004_5FFF
                            options.peripheral_start_address = 0x40045000
                            options.peripheral_end_address = 0x40045FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            ##checking DAC_BA 0x40047000 – 0x40047FFF
                            options.peripheral_start_address = 0x40047000
                            options.peripheral_end_address = 0x40047FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dac",
                                num,
                            )

                            ##checking I2S_BA  0x40048000 – 0x40048FFF
                            options.peripheral_start_address = 0x40048000
                            options.peripheral_end_address = 0x40048FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2s",
                                num,
                            )

                            ##checking OTG_BA 0x4004D000 – 0x4004DFFF
                            options.peripheral_start_address = 0x4004D000
                            options.peripheral_end_address = 0x4004DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "otg",
                                num,
                            )

                            # HSOTG newly added
                            options.peripheral_start_address = 0x4004F000
                            options.peripheral_end_address = 0x4004FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "hsotg",
                                num,
                            )

                            ##checking TMR_BA  0x40051000 – 0x40051FFF
                            options.peripheral_start_address = 0x40050000
                            options.peripheral_end_address = 0x40051FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking PWM_BPWM_BABA  0x4005B000 – 0x4005BFFF
                            options.peripheral_start_address = 0x4005A000
                            options.peripheral_end_address = 0x4005BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "bpwm",
                                num,
                            )

                            ##checking QSPI_BA  0x40069000 – 0x40069FFF
                            options.peripheral_start_address = 0x40060000
                            options.peripheral_end_address = 0x40060FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "qspi",
                                num,
                            )
                            options.peripheral_start_address = 0x40069000
                            options.peripheral_end_address = 0x40069FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "qspi",
                                num,
                            )

                            # checking SC0_BA  0x40093000 – 0x40093FFF
                            options.peripheral_start_address = 0x40090000
                            options.peripheral_end_address = 0x40093FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sc",
                                num,
                            )

                            ##checking USBD_BA
                            options.peripheral_start_address = 0x400C0000
                            options.peripheral_end_address = 0x400C0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbd",
                                num,
                            )

                            ##checking USCI_BA 0x400D1000 – 0x400D1FFF
                            options.peripheral_start_address = 0x400D0000
                            options.peripheral_end_address = 0x400D1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usci",
                                num,
                            )

                            # checking SCS_BA  sure 0xE000_ED00 – 0xE000_ED8F
                            options.peripheral_start_address = 0xE000E010
                            options.peripheral_end_address = 0xE000ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                            ##checking EPWM_BA 0x40059000 – 0x40059FFF
                            options.peripheral_start_address = 0x40058000
                            options.peripheral_end_address = 0x40059FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "epwm",
                                num,
                            )

                            ##checking QEI_BA 0x400B1000 – 0x400B1FFF
                            options.peripheral_start_address = 0x400B0000
                            options.peripheral_end_address = 0x400B1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "qei",
                                num,
                            )

                            ##checking ECAP_BA 0x400B5000 – 0x400B5FFF
                            options.peripheral_start_address = 0x400B4000
                            options.peripheral_end_address = 0x400B5FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ecap",
                                num,
                            )

                            ##checking TRNG_BA   0x400B9000 – 0x400B9FFF
                            options.peripheral_start_address = 0x400B9000
                            options.peripheral_end_address = 0x400B9FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "trng",
                                num,
                            )

                            ## SYS newly added
                            options.peripheral_start_address = 0x40000000
                            options.peripheral_end_address = 0x4000_01FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            ## SPIM newly added
                            options.peripheral_start_address = 0x40007000
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spim",
                                num,
                            )

                            ## EMAC newly added
                            options.peripheral_start_address = 0x4000B000
                            options.peripheral_end_address = 0x4000BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "emac",
                                num,
                            )

                            ## SDH newly added
                            options.peripheral_start_address = 0x4000D000
                            options.peripheral_end_address = 0x4000EFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sdh",
                                num,
                            )

                            ## HSUSBD newly added
                            options.peripheral_start_address = 0x40019000
                            options.peripheral_end_address = 0x40019FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sdh",
                                num,
                            )

                            ## HSUSBD newly added
                            options.peripheral_start_address = 0x4001A000
                            options.peripheral_end_address = 0x4001_AFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sdh",
                                num,
                            )

                            ## CCAP newly added
                            options.peripheral_start_address = 0x40030000
                            options.peripheral_end_address = 0x40030FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ccap",
                                num,
                            )

                            ## SWDC newly added
                            options.peripheral_start_address = 0x4003E000
                            options.peripheral_end_address = 0x4003EFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "swdc",
                                num,
                            )

                            ## ETMC new
                            options.peripheral_start_address = 0x4003F000
                            options.peripheral_end_address = 0x4003FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "etmc",
                                num,
                            )

                            ## CRYP new
                            options.peripheral_start_address = 0x50080000
                            options.peripheral_end_address = 0x50080FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "cryp",
                                num,
                            )

                            ## OPA new 0x4004_6000 – 0x4004_6FFF
                            options.peripheral_start_address = 0x40046000
                            options.peripheral_end_address = 0x40046FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "opa",
                                num,
                            )

                            ## CAN new
                            options.peripheral_start_address = 0x400A0000
                            options.peripheral_end_address = 0x400A_2FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "can",
                                num,
                            )

                        elif dirname == "M031M032":  # DONE
                            num = num + 1
                            # UART
                            options.peripheral_start_address = 0x40070000
                            options.peripheral_end_address = 0x40077FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            # I2C
                            options.peripheral_start_address = 0x40080000
                            options.peripheral_end_address = 0x40081FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # SPI
                            options.peripheral_start_address = 0x40061000
                            options.peripheral_end_address = 0x40061FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            ##checking CLK_BA
                            options.peripheral_start_address = 0x40000200
                            options.peripheral_end_address = 0x400002FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking NMI_BA
                            options.peripheral_start_address = 0x40000300
                            options.peripheral_end_address = 0x400003FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "nmi",
                                num,
                            )

                            ##checking GPIO_BA 0x40004000 – 0x40004FFF
                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40004FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking DMA 0x40008000 – 0x40008FFF
                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x40008FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            ##checking FMC_BA 0x4000C000 – 0x4000CFFF
                            options.peripheral_start_address = 0x4000C000
                            options.peripheral_end_address = 0x4000CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking EBI_BA 0x40010000 – 0x40010FFF
                            options.peripheral_start_address = 0x40010000
                            options.peripheral_end_address = 0x40010FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ebi",
                                num,
                            )

                            ##checking HDIV_BA 0x40014000 – 0x40017FFF
                            options.peripheral_start_address = 0x40014000
                            options.peripheral_end_address = 0x40017FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "hdiv",
                                num,
                            )

                            ##checking CRC_BA 0x40031000 – 0x40031FFF
                            options.peripheral_start_address = 0x40031000
                            options.peripheral_end_address = 0x40031FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            ##checking WDT_BA 0x40040000 – 0x40040FFF
                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40040FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking RTC_BA 0x40041000 – 0x40041FFF
                            options.peripheral_start_address = 0x40041000
                            options.peripheral_end_address = 0x40041FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            ##checking ADC12_BA  0x40043000 – 0x40043FFF
                            options.peripheral_start_address = 0x40043000
                            options.peripheral_end_address = 0x40043FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            ##checking ACMP_BA  0x40045000 – 0x40045FFF
                            options.peripheral_start_address = 0x40045000
                            options.peripheral_end_address = 0x40045FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            ##checking TMR_BA  0x40051000 – 0x40051FFF
                            options.peripheral_start_address = 0x40050000
                            options.peripheral_end_address = 0x40051FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking PWM_BA  0x40059000 – 0x40059FFF
                            options.peripheral_start_address = 0x40058000
                            options.peripheral_end_address = 0x40059FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking PWM_BPWM_BABA  0x4005A000 – 0x4005AFFF
                            options.peripheral_start_address = 0x4005A000
                            options.peripheral_end_address = 0x4005BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "bpwm",
                                num,
                            )

                            ##checking QSPI_BA  0x40045000 – 0x40045FFF
                            options.peripheral_start_address = 0x40060000
                            options.peripheral_end_address = 0x40060FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "qspi",
                                num,
                            )

                            ##checking USBD_BA
                            options.peripheral_start_address = 0x400C0000
                            options.peripheral_end_address = 0x400C0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbd",
                                num,
                            )

                            ##checking USCI_BA
                            options.peripheral_start_address = 0x400D0000
                            options.peripheral_end_address = 0x400D1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usci",
                                num,
                            )

                            # checking SCS_BA  sure
                            options.peripheral_start_address = 0xE000E010
                            options.peripheral_end_address = 0xE000ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                            # checking SYS_BA new added
                            options.peripheral_start_address = 0x40000000
                            options.peripheral_end_address = 0x4000_01FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                        elif dirname == "Nano100":  # DONE
                            num = num + 1
                            # checking spi sure
                            options.peripheral_start_address = 0x40030000
                            options.peripheral_end_address = 0x40033FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )
                            options.peripheral_start_address = 0x40130000
                            options.peripheral_end_address = 0x40133FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )
                            options.peripheral_start_address = 0x400D0000
                            options.peripheral_end_address = 0x400D3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # checking for UART sure
                            options.peripheral_start_address = 0x40050000
                            options.peripheral_end_address = 0x40053FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )
                            options.peripheral_start_address = 0x40150000
                            options.peripheral_end_address = 0x40153FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking I2c sure
                            options.peripheral_start_address = 0x40020000
                            options.peripheral_end_address = 0x40023FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )
                            options.peripheral_start_address = 0x40120000
                            options.peripheral_end_address = 0x40123FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            ##checking GCR_BA
                            options.peripheral_start_address = 0x50000000
                            options.peripheral_end_address = 0x500001FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gcr",
                                num,
                            )

                            ##checking CLK_BA
                            options.peripheral_start_address = 0x50000200
                            options.peripheral_end_address = 0x500002FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking INT_BA
                            options.peripheral_start_address = 0x50000300
                            options.peripheral_end_address = 0x500003FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "int",
                                num,
                            )

                            ##checking GPIO_BA
                            options.peripheral_start_address = 0x50004000
                            options.peripheral_end_address = 0x50007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking DMA_BA
                            options.peripheral_start_address = 0x50008000
                            options.peripheral_end_address = 0x5000BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            ##checking FMC_BA
                            options.peripheral_start_address = 0x5000C000
                            options.peripheral_end_address = 0x5000FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking EBI_BA
                            options.peripheral_start_address = 0x50010000
                            options.peripheral_end_address = 0x500103FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ebi",
                                num,
                            )

                            ##checking WDT_BA
                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking RTC_BA
                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x4000BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            ##checking TMR_BA
                            options.peripheral_start_address = 0x40010000
                            options.peripheral_end_address = 0x40013FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )
                            options.peripheral_start_address = 0x40110000
                            options.peripheral_end_address = 0x40113FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking PWM_BA
                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40043FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )
                            options.peripheral_start_address = 0x40140000
                            options.peripheral_end_address = 0x40143FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking USBD_BA
                            options.peripheral_start_address = 0x40060000
                            options.peripheral_end_address = 0x40063FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbd",
                                num,
                            )

                            ##checking DAC_BA
                            options.peripheral_start_address = 0x400A0000
                            options.peripheral_end_address = 0x400A3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dac",
                                num,
                            )

                            ##checking LCD_BA
                            options.peripheral_start_address = 0x400B0000
                            options.peripheral_end_address = 0x400B3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lcd",
                                num,
                            )

                            ##checking ADC12_BA
                            options.peripheral_start_address = 0x400E0000
                            options.peripheral_end_address = 0x400E3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            # checking SC0_BA  sure
                            options.peripheral_start_address = 0x40190000
                            options.peripheral_end_address = 0x40193FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sc",
                                num,
                            )
                            options.peripheral_start_address = 0x401B0000
                            options.peripheral_end_address = 0x401B3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sc",
                                num,
                            )
                            options.peripheral_start_address = 0x401C0000
                            options.peripheral_end_address = 0x401C3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sc",
                                num,
                            )

                            ##checking I2S_BA
                            options.peripheral_start_address = 0x401A0000
                            options.peripheral_end_address = 0x401A3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2s",
                                num,
                            )

                            # checking SCS_BA  sure
                            options.peripheral_start_address = 0xE000E010
                            options.peripheral_end_address = 0xE000ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                        elif dirname == "NUC230240":  # DONE
                            num = num + 1
                            # spi
                            options.peripheral_start_address = 0x40030000
                            options.peripheral_end_address = 0x40037FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # spi
                            options.peripheral_start_address = 0x40130000
                            options.peripheral_end_address = 0x40137FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # i2c
                            options.peripheral_start_address = 0x40020000
                            options.peripheral_end_address = 0x40023FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )
                            options.peripheral_start_address = 0x40120000
                            options.peripheral_end_address = 0x40123FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # uart
                            options.peripheral_start_address = 0x40050000
                            options.peripheral_end_address = 0x40053FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )
                            options.peripheral_start_address = 0x40150000
                            options.peripheral_end_address = 0x40157FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking GCR_BA
                            options.peripheral_start_address = 0x50000000
                            options.peripheral_end_address = 0x500001FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gcr",
                                num,
                            )

                            ##checking CLK_BA
                            options.peripheral_start_address = 0x50000200
                            options.peripheral_end_address = 0x500002FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking INT_BA
                            options.peripheral_start_address = 0x50000300
                            options.peripheral_end_address = 0x500003FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "int_ba",
                                num,
                            )

                            ##checking GPIO_BA
                            options.peripheral_start_address = 0x50004000
                            options.peripheral_end_address = 0x50007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking DMA_BA
                            options.peripheral_start_address = 0x50008000
                            options.peripheral_end_address = 0x5000BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            ##checking FMC_BA
                            options.peripheral_start_address = 0x5000C000
                            options.peripheral_end_address = 0x5000FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking EBI_BA
                            options.peripheral_start_address = 0x50010000
                            options.peripheral_end_address = 0x500103FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ebi",
                                num,
                            )

                            ##checking WDT_BA
                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking RTC_BA
                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x4000BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            ##checking TMR_BA
                            options.peripheral_start_address = 0x40010000
                            options.peripheral_end_address = 0x40013FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )
                            options.peripheral_start_address = 0x40110000
                            options.peripheral_end_address = 0x40113FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking PWM_BA
                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40043FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )
                            options.peripheral_start_address = 0x40140000
                            options.peripheral_end_address = 0x40143FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking USBD_BA
                            options.peripheral_start_address = 0x40060000
                            options.peripheral_end_address = 0x40063FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbd",
                                num,
                            )

                            ##checking ACMP_BA
                            options.peripheral_start_address = 0x400D0000
                            options.peripheral_end_address = 0x400D3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            ##checking ADC12_BA
                            options.peripheral_start_address = 0x400E0000
                            options.peripheral_end_address = 0x400EFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            ##checking PS2_BA
                            options.peripheral_start_address = 0x40100000
                            options.peripheral_end_address = 0x40103FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ps2",
                                num,
                            )

                            # checking SC0_BA  sure
                            options.peripheral_start_address = 0x40190000
                            options.peripheral_end_address = 0x4019BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sc",
                                num,
                            )

                            ##checking I2S_BA
                            options.peripheral_start_address = 0x401A0000
                            options.peripheral_end_address = 0x401A3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2s",
                                num,
                            )

                            # checking SCS_BA  sure
                            options.peripheral_start_address = 0xE000E010
                            options.peripheral_end_address = 0xE000ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                            # checking CAN_BA newley added
                            options.peripheral_start_address = 0x40180000
                            options.peripheral_end_address = 0x4018_7FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "can",
                                num,
                            )

                        elif dirname == "M451":  # DONE
                            num = num + 1
                            # SPI
                            options.peripheral_start_address = 0x40060000
                            options.peripheral_end_address = 0x40062FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # I2C
                            options.peripheral_start_address = 0x40080000
                            options.peripheral_end_address = 0x40081FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # UART
                            options.peripheral_start_address = 0x40070000
                            options.peripheral_end_address = 0x40073FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking CLK_BA
                            options.peripheral_start_address = 0x40000200
                            options.peripheral_end_address = 0x400002FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking GPIO_BA
                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40004FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking DMA
                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x40008FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            ##checking USBH_BA
                            options.peripheral_start_address = 0x40009000
                            options.peripheral_end_address = 0x40009FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbh",
                                num,
                            )

                            ##checking FMC_BA
                            options.peripheral_start_address = 0x4000C000
                            options.peripheral_end_address = 0x4000CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking EBI_BA
                            options.peripheral_start_address = 0x40010000
                            options.peripheral_end_address = 0x40010FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ebi",
                                num,
                            )

                            ##checking CRC_BA
                            options.peripheral_start_address = 0x40031000
                            options.peripheral_end_address = 0x40031FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            ##checking WDT_BA
                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40040FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking RTC_BA
                            options.peripheral_start_address = 0x40041000
                            options.peripheral_end_address = 0x40041FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            ##checking EADC_BA
                            options.peripheral_start_address = 0x40043000
                            options.peripheral_end_address = 0x40043FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            ##checking ACMP_BA
                            options.peripheral_start_address = 0x40045000
                            options.peripheral_end_address = 0x40045FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            ##checking DAC_BA
                            options.peripheral_start_address = 0x40047000
                            options.peripheral_end_address = 0x40047FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dac",
                                num,
                            )

                            ##checking OTG_BA
                            options.peripheral_start_address = 0x4004D000
                            options.peripheral_end_address = 0x4004DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "otg",
                                num,
                            )

                            ##checking TMR_BA
                            options.peripheral_start_address = 0x40050000
                            options.peripheral_end_address = 0x40050FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking TMR_BA
                            options.peripheral_start_address = 0x40051000
                            options.peripheral_end_address = 0x40051FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking PWM_BA
                            options.peripheral_start_address = 0x40058000
                            options.peripheral_end_address = 0x40059FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking SC_BA
                            options.peripheral_start_address = 0x40090000
                            options.peripheral_end_address = 0x40090FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sc",
                                num,
                            )

                            ##checking USBD_BA
                            options.peripheral_start_address = 0x400C0000
                            options.peripheral_end_address = 0x400C0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbd",
                                num,
                            )

                            # checking SCS_BA  sure
                            options.peripheral_start_address = 0xE000E010
                            options.peripheral_end_address = 0xE000ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                            # SYS_BA new
                            options.peripheral_start_address = 0x40000000
                            options.peripheral_end_address = 0x400001FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            ## New one
                            options.peripheral_start_address = 0x40000300
                            options.peripheral_end_address = 0x400003FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "nmi",
                                num,
                            )

                            ## CAN newly add
                            options.peripheral_start_address = 0x400A0000
                            options.peripheral_end_address = 0x400A0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "can",
                                num,
                            )

                            # Started From here again

                        elif dirname == "M251:M252":
                            num = num + 1
                            # SPI
                            options.peripheral_start_address = 0x4006_1000
                            options.peripheral_end_address = 0x4006_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # I2C
                            options.peripheral_start_address = 0x4008_0000
                            options.peripheral_end_address = 0x4008_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # UART
                            options.peripheral_start_address = 0x4007_0000
                            options.peripheral_end_address = 0x4007_2FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking CLK_BA
                            options.peripheral_start_address = 0x4000_0200
                            options.peripheral_end_address = 0x4000_02FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking GPIO_BA
                            options.peripheral_start_address = 0x4000_4000
                            options.peripheral_end_address = 0x4000_4FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking DMA
                            options.peripheral_start_address = 0x4000_8000
                            options.peripheral_end_address = 0x4000_8FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            ##checking FMC_BA
                            options.peripheral_start_address = 0x4000_C000
                            options.peripheral_end_address = 0x4000_CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking EBI_BA
                            options.peripheral_start_address = 0x4001_0000
                            options.peripheral_end_address = 0x4001_0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ebi",
                                num,
                            )

                            ##checking CRC_BA
                            options.peripheral_start_address = 0x4003_1000
                            options.peripheral_end_address = 0x4003_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            ##checking WDT_BA
                            options.peripheral_start_address = 0x4004_0000
                            options.peripheral_end_address = 0x4004_0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking RTC_BA
                            options.peripheral_start_address = 0x4004_1000
                            options.peripheral_end_address = 0x4004_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            ##checking EADC_BA
                            options.peripheral_start_address = 0x4004_3000
                            options.peripheral_end_address = 0x4004_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            ##checking ACMP_BA
                            options.peripheral_start_address = 0x4004_5000
                            options.peripheral_end_address = 0x4004_5FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            ##checking DAC_BA
                            options.peripheral_start_address = 0x4004_7000
                            options.peripheral_end_address = 0x4004_7FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dac",
                                num,
                            )

                            ##checking TMR_BA # newly added
                            options.peripheral_start_address = 0x4005_0000
                            options.peripheral_end_address = 0x4005_0FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking TMR_BA
                            options.peripheral_start_address = 0x4005_1000
                            options.peripheral_end_address = 0x4005_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking PWM_BA
                            options.peripheral_start_address = 0x4005_8000
                            options.peripheral_end_address = 0x4005_9FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking SC_BA
                            options.peripheral_start_address = 0x4009_0000
                            options.peripheral_end_address = 0x4009_0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sc",
                                num,
                            )

                            # checking SCS_BA  sure
                            options.peripheral_start_address = 0xE000_E010
                            options.peripheral_end_address = 0xE000_ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                            options.peripheral_start_address = 0x4006_0000
                            options.peripheral_end_address = 0x4005_0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "qspi",
                                num,
                            )

                            options.peripheral_start_address = 0x4005_A000
                            options.peripheral_end_address = 0x4005_BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "bpwm",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x400D_0000  # had wrong address previously
                            )
                            options.peripheral_end_address = 0x400D_2FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usci",
                                num,
                            )

                            options.peripheral_start_address = 0x4000_0300
                            options.peripheral_end_address = 0x4000_03FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "nmi",
                                num,
                            )

                            # SYS newly added
                            options.peripheral_start_address = 0x4000_0000
                            options.peripheral_end_address = 0x4000_01FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            # OPA newly added
                            options.peripheral_start_address = 0x4004_6000
                            options.peripheral_end_address = 0x4004_6FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "opa",
                                num,
                            )

                            # USBD newly added
                            options.peripheral_start_address = 0x400C_0000
                            options.peripheral_end_address = 0x400C_0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbd",
                                num,
                            )

                            # PSIO_BD newly added 0x400C_3000 – 0x400C_3FFF
                            options.peripheral_start_address = 0x400C_3000
                            options.peripheral_end_address = 0x400C_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "psio",
                                num,
                            )

                        elif dirname == "M471":
                            num = num + 1

                            # SYS newly added
                            options.peripheral_start_address = 0x4000_0000
                            options.peripheral_end_address = 0x4000_01FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            # SPI
                            options.peripheral_start_address = 0x4006_1000
                            options.peripheral_end_address = 0x4006_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # I2C
                            options.peripheral_start_address = 0x4008_0000
                            options.peripheral_end_address = 0x4008_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # UART
                            options.peripheral_start_address = 0x4007_0000
                            options.peripheral_end_address = 0x4007_5FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking CLK_BA
                            options.peripheral_start_address = 0x4000_0200
                            options.peripheral_end_address = 0x4000_02FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking GPIO_BA
                            options.peripheral_start_address = 0x4000_4000
                            options.peripheral_end_address = 0x4000_4FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking DMA
                            options.peripheral_start_address = 0x4000_8000
                            options.peripheral_end_address = 0x4000_8FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            ##checking FMC_BA
                            options.peripheral_start_address = 0x4000_C000
                            options.peripheral_end_address = 0x4000_CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking EBI_BA
                            options.peripheral_start_address = 0x4001_0000
                            options.peripheral_end_address = 0x4001_0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ebi",
                                num,
                            )

                            ##checking CRC_BA
                            options.peripheral_start_address = 0x4003_1000
                            options.peripheral_end_address = 0x4003_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            ##checking WDT_BA
                            options.peripheral_start_address = 0x4004_0000
                            options.peripheral_end_address = 0x4004_0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking RTC_BA
                            options.peripheral_start_address = 0x4004_1000
                            options.peripheral_end_address = 0x4004_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            ##checking EADC_BA
                            options.peripheral_start_address = 0x4004_3000
                            options.peripheral_end_address = 0x4004_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            ##checking ACMP_BA
                            options.peripheral_start_address = 0x4004_5000
                            options.peripheral_end_address = 0x4004_5FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            ##checking DAC_BA
                            options.peripheral_start_address = 0x4004_7000
                            options.peripheral_end_address = 0x4004_7FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dac",
                                num,
                            )

                            ##checking TMR_BA
                            options.peripheral_start_address = 0x4005_1000
                            options.peripheral_end_address = 0x4005_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking PWM_BA
                            options.peripheral_start_address = 0x4005_8000
                            options.peripheral_end_address = 0x4005_9FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking SC_BA
                            options.peripheral_start_address = 0x4009_0000
                            options.peripheral_end_address = 0x4009_0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sc",
                                num,
                            )

                            # checking SCS_BA  sure
                            options.peripheral_start_address = 0xE000_E010
                            options.peripheral_end_address = 0xE000_ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                            options.peripheral_start_address = 0x4005_A000
                            options.peripheral_end_address = 0x4005_BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "bpwm",
                                num,
                            )

                            options.peripheral_start_address = 0x4000_0300
                            options.peripheral_end_address = 0x4000_03FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "nmi",
                                num,
                            )

                            options.peripheral_start_address = 0x400B_A000
                            options.peripheral_end_address = 0x400B_AFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "prng",
                                num,
                            )

                        elif dirname == "Mini58":
                            num = num + 1
                            # SPI
                            options.peripheral_start_address = 0x4003_0000
                            options.peripheral_end_address = 0x4003_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # I2C
                            options.peripheral_start_address = 0x4002_0000
                            options.peripheral_end_address = 0x4002_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # I2C Newly Added
                            options.peripheral_start_address = 0x4012_0000
                            options.peripheral_end_address = 0x4012_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # UART
                            options.peripheral_start_address = 0x4005_0000
                            options.peripheral_end_address = 0x4005_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            # UART # Newly Added
                            options.peripheral_start_address = 0x4015_0000
                            options.peripheral_end_address = 0x4015_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking CLK_BA
                            options.peripheral_start_address = 0x5000_0200
                            options.peripheral_end_address = 0x5000_02FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking GPIO_BA
                            options.peripheral_start_address = 0x5000_4000
                            options.peripheral_end_address = 0x5000_7FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking FMC_BA
                            options.peripheral_start_address = 0x5000_C000
                            options.peripheral_end_address = 0x5000_FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking WDT_BA
                            options.peripheral_start_address = 0x4000_4000
                            options.peripheral_end_address = 0x4000_00FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            options.peripheral_start_address = 0x4000_4100
                            options.peripheral_end_address = 0x4000_47FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking EADC_BA
                            options.peripheral_start_address = 0x400E_0000
                            options.peripheral_end_address = 0x400E_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            ##checking ACMP_BA
                            options.peripheral_start_address = 0x400D_0000
                            options.peripheral_end_address = 0x400D_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            options.peripheral_start_address = 0x4001_0000
                            options.peripheral_end_address = 0x4001_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking PWM_BA
                            options.peripheral_start_address = 0x4004_0000
                            options.peripheral_end_address = 0x4004_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            # checking SCS_BA  sure
                            options.peripheral_start_address = 0xE000_E010
                            options.peripheral_end_address = 0xE000_ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                            options.peripheral_start_address = 0x5000_0300
                            options.peripheral_end_address = 0x5000_03FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "int",
                                num,
                            )

                            # Newly added SYS
                            options.peripheral_start_address = 0x5000_0000
                            options.peripheral_end_address = 0x5000_01FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                        elif dirname == "NUC200":
                            num = num + 1
                            # GCR
                            options.peripheral_start_address = 0x5000_0000
                            options.peripheral_end_address = 0x5000_01FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gcr",
                                num,
                            )

                            # SPI
                            options.peripheral_start_address = 0x4003_0000
                            options.peripheral_end_address = 0x4003_7FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            options.peripheral_start_address = 0x4013_0000
                            options.peripheral_end_address = 0x4013_7FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # I2C
                            options.peripheral_start_address = 0x4002_0000
                            options.peripheral_end_address = 0x4002_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = 0x4012_0000
                            options.peripheral_end_address = 0x4012_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # I2S newley added
                            options.peripheral_start_address = 0x401A_0000
                            options.peripheral_end_address = 0x401A_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2s",
                                num,
                            )

                            # UART
                            options.peripheral_start_address = 0x4005_0000
                            options.peripheral_end_address = 0x4005_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            options.peripheral_start_address = 0x4015_0000
                            options.peripheral_end_address = 0x4015_7FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking CLK_BA
                            options.peripheral_start_address = 0x5000_0200
                            options.peripheral_end_address = 0x5000_02FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking GPIO_BA
                            options.peripheral_start_address = 0x5000_4000
                            options.peripheral_end_address = 0x5000_7FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking DMA
                            options.peripheral_start_address = 0x5000_8000
                            options.peripheral_end_address = 0x5000_BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            ##checking FMC_BA
                            options.peripheral_start_address = 0x5000_C000
                            options.peripheral_end_address = 0x5000_FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            ##checking WDT_BA
                            options.peripheral_start_address = 0x4000_4000
                            options.peripheral_end_address = 0x4000_7FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking RTC_BA
                            options.peripheral_start_address = 0x4000_8000
                            options.peripheral_end_address = 0x4000_BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            ##checking EADC_BA
                            options.peripheral_start_address = 0x400E_0000
                            options.peripheral_end_address = 0x400E_FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            ##checking ACMP_BA
                            options.peripheral_start_address = 0x400D_0000
                            options.peripheral_end_address = 0x400D_3FFF
                            # options.peripheral_end_address=  0x400E_FFFF #Wrong End Address here commented the old one
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            ##checking TMR_BA
                            options.peripheral_start_address = 0x4001_0000
                            options.peripheral_end_address = 0x4001_3FFF
                            # options.peripheral_end_address=  0x4005_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )  # wrong end address commented the old one

                            ##checking TMR_BA
                            options.peripheral_start_address = 0x4011_0000
                            options.peripheral_end_address = 0x4011_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )  # newly added

                            ##checking PWM_BA
                            options.peripheral_start_address = 0x4004_0000
                            options.peripheral_end_address = 0x4004_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking PWMB_BA
                            options.peripheral_start_address = 0x4014_0000
                            options.peripheral_end_address = 0x4014_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking SC_BA
                            options.peripheral_start_address = 0x4019_0000
                            options.peripheral_end_address = 0x4019_BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sc",
                                num,
                            )

                            # checking SCS_BA  sure
                            # options.peripheral_start_address=0xE000_E010
                            options.peripheral_start_address = 0xE000_ED00
                            options.peripheral_end_address = 0xE000_ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                            # checking SYST_BA  newley added
                            options.peripheral_start_address = 0xE000_E010
                            options.peripheral_end_address = 0xE000_E0FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            # options.peripheral_start_address=0x4000_0300
                            # options.peripheral_end_address=  0x4000_03FF
                            options.peripheral_start_address = 0x5000_0300
                            options.peripheral_end_address = 0x5000_03FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "int",
                                num,
                            )

                            # Newley added USBD_BA
                            options.peripheral_start_address = 0x4006_0000
                            options.peripheral_end_address = 0x4006_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbd",
                                num,
                            )

                            # Newley added PS2_BA
                            options.peripheral_start_address = 0x4010_0000
                            options.peripheral_end_address = 0x4010_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ps2",
                                num,
                            )

                            # Newley added NVIC_BA
                            options.peripheral_start_address = 0xE000_E100
                            options.peripheral_end_address = 0xE000_ECFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "nvi",
                                num,
                            )

                        elif dirname == "NUC472:NUC442":
                            num = num + 1
                            # SPI
                            options.peripheral_start_address = 0x4006_0000
                            options.peripheral_end_address = 0x4006_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            # SYS
                            options.peripheral_start_address = 0x4000_0000
                            options.peripheral_end_address = 0x4000_01FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )  # it was spi

                            # I2C
                            options.peripheral_start_address = 0x4008_0000
                            options.peripheral_end_address = 0x4008_4FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # UART
                            options.peripheral_start_address = 0x4007_0000
                            options.peripheral_end_address = 0x4007_5FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            ##checking CLK_BA
                            options.peripheral_start_address = 0x4000_0200
                            options.peripheral_end_address = 0x4000_02FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            ##checking GPIO_BA
                            options.peripheral_start_address = 0x4000_4000
                            options.peripheral_end_address = 0x4000_4FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            ##checking DMA
                            options.peripheral_start_address = 0x4000_8000
                            options.peripheral_end_address = 0x4000_8FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            ##checking FMC_BA
                            options.peripheral_start_address = 0x4000_C000
                            options.peripheral_end_address = 0x4000_CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fmc",
                                num,
                            )

                            # new added sdh
                            options.peripheral_start_address = 0x4000_D000
                            options.peripheral_end_address = 0x4000_DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sdh",
                                num,
                            )

                            ##checking WDT_BA
                            options.peripheral_start_address = 0x4004_0000
                            options.peripheral_end_address = 0x4004_0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            ##checking RTC_BA
                            options.peripheral_start_address = 0x4004_1000
                            options.peripheral_end_address = 0x4004_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            ##checking EADC_BA # this is ADC no EADC corrected version is below
                            options.peripheral_start_address = 0x4004_0000
                            options.peripheral_end_address = 0x4004_4FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x4004_3000
                            options.peripheral_end_address = 0x4004_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            ##checking ACMP_BA
                            options.peripheral_start_address = 0x4004_5000
                            options.peripheral_end_address = 0x4004_5FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            ##checking TMR_BA
                            options.peripheral_start_address = 0x4005_0000  # 0x4005_0000 – 0x4005_0FFF 0x4005_1000 – 0x4005_1FFF
                            options.peripheral_end_address = 0x4005_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            ##checking PWM_BA
                            options.peripheral_start_address = 0x4000_8000
                            options.peripheral_end_address = 0x4005_9FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            ##checking EPWM_BA new
                            options.peripheral_start_address = 0x4005_C000
                            options.peripheral_end_address = 0x4005_DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "epwm",
                                num,
                            )

                            ##checking SC_BA
                            options.peripheral_start_address = 0x4009_0000
                            options.peripheral_end_address = 0x4009_5FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sc",
                                num,
                            )

                            # checking SCS_BA  sure
                            options.peripheral_start_address = 0xE000_E010
                            options.peripheral_end_address = 0xE000_ED8F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scs",
                                num,
                            )

                            options.peripheral_start_address = 0x4000_0300
                            options.peripheral_end_address = 0x4000_03FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "int",
                                num,
                            )

                            # New Added
                            options.peripheral_start_address = 0x4000_B000
                            options.peripheral_end_address = 0x4000_BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "emac",
                                num,
                            )

                            options.peripheral_start_address = 0x4001_0000
                            options.peripheral_end_address = 0x4001_0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ebi",
                                num,
                            )

                            options.peripheral_start_address = 0x4001_9000
                            options.peripheral_end_address = 0x4001_9FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbd",
                                num,
                            )

                            options.peripheral_start_address = 0x4000_9000
                            options.peripheral_end_address = 0x4000_9FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usbh",
                                num,
                            )

                            # Above 2 have similar ranges 0x4001_9000 – 0x4001_9FFF 0x4000_9000 – 0x4000_9FFF

                            options.peripheral_start_address = 0x4004_4000
                            options.peripheral_end_address = 0x400_4FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "eadc",
                                num,
                            )

                            options.peripheral_start_address = 0x4004_8000
                            options.peripheral_end_address = 0x4004_9FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2s",
                                num,
                            )

                            options.peripheral_start_address = 0x4004_D000
                            options.peripheral_end_address = 0x4004_DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "otg",
                                num,
                            )

                            options.peripheral_start_address = 0x4000_0300
                            options.peripheral_end_address = 0x4000_03FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "int",
                                num,
                            )

                            # CAP new added
                            options.peripheral_start_address = 0x4003_0000
                            options.peripheral_end_address = 0x4003_0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "cap",
                                num,
                            )

                            # CRC new added
                            options.peripheral_start_address = 0x4003_1000
                            options.peripheral_end_address = 0x4003_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            # CRYP new added
                            options.peripheral_start_address = 0x5000_8000
                            options.peripheral_end_address = 0x5000_FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "cryp",
                                num,
                            )

                            # OPA new added
                            options.peripheral_start_address = 0x4004_6000
                            options.peripheral_end_address = 0x4004_6FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "opa",
                                num,
                            )

                            # CAN new added
                            options.peripheral_start_address = 0x400A_0000
                            options.peripheral_end_address = 0x400A_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "can",
                                num,
                            )

                            # QEI new added
                            options.peripheral_start_address = 0x400B_0000
                            options.peripheral_end_address = 0x400B_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "qei",
                                num,
                            )

                            # ECAP new added
                            options.peripheral_start_address = 0x400B_0000
                            options.peripheral_end_address = 0x400B_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ecap",
                                num,
                            )

                            # PS2 new added
                            options.peripheral_start_address = 0x400E_0000
                            options.peripheral_end_address = 0x400E_0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ps2",
                                num,
                            )

                        #################################################################
                        elif dirname == "STM32C":
                            # For GPIOA to GPIOF
                            num = num + 1
                            options.peripheral_start_address = (
                                0x5000_0000  # 0x5000 0000 - 0x5000 17FF
                            )
                            options.peripheral_end_address = 0x5FFF_17FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x4002_2000
                            options.peripheral_end_address = 0x4002_23FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "FlashInterfaceRegister",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4002_3000  # 0x4002 3000 - 0x4002 33FF
                            )
                            options.peripheral_end_address = 0x4002_33FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4002_1800  # 0x4002 1800 - 0x4002 1BFF
                            )
                            options.peripheral_end_address = 0x4002_1BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "exti",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4002_1000  # 0x4002 1000 - 0x4002 13FF
                            )
                            options.peripheral_end_address = 0x4002_13FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rcc",
                                num,
                            )

                            

                            options.peripheral_start_address = (
                                0x4002_0800  # 0x4002 0800 - 0x4002 0BFF
                            )
                            options.peripheral_end_address = 0x4002_0BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dmaux",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4002_0000  # 0x4002 0000 - 0x4002 03FF
                            )
                            options.peripheral_end_address = 0x4002_03FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4001_5800  # 0x4001 5800 - 0x4001 5BFF
                            )
                            options.peripheral_end_address = 0x4001_5BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dbg",
                                num,
                            )

                            # From TMR 16 to 17
                            options.peripheral_start_address = 0x4001_4400  # 0x4001 4400 - 0x4001 47FF/ 0x4001 4800 - 0x4001 4BFF
                            options.peripheral_end_address = 0x4001_4BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )


                            options.peripheral_start_address = (
                                0x4001_3000  # 0x4001 3000 - 0x4001 33FF
                            )
                            options.peripheral_end_address = 0x4001_33FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi/i2s",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4001_2C00  # 0x4001 2C00 - 0x4001 2FFF
                            )
                            options.peripheral_end_address = 0x4001_2FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4001_2400  # 0x4001 2400 - 0x4001 27FF
                            )
                            options.peripheral_end_address = 0x4001_27FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4001_0080  # 0x4001 0080 - 0x4001 03FF
                            )
                            options.peripheral_end_address = 0x4001_03FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            # Missed the second SYS So added it here
                            options.peripheral_start_address = (
                                0x4001_0000  # 0x4001 0000 - 0x4001 001C
                            )
                            options.peripheral_end_address = 0x4001_001C
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4000_7000  # 0x4000 7000 - 0x4000 73FF
                            )
                            options.peripheral_end_address = 0x4000_73FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwr",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4000_5400  # 0x4000 5400 - 0x4000 57FF
                            )
                            options.peripheral_end_address = 0x4000_57FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )


                            options.peripheral_start_address = (
                                0x4000_3000  # 0x4000 3000 - 0x4000 33FF
                            )
                            options.peripheral_end_address = 0x4000_33FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "iwdg",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4000_2C00  # 0x4000 2C00 - 0x4000 2FFF
                            )
                            options.peripheral_end_address = 0x4000_2FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wwdg",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4000_2800  # 0x4000 2800 - 0x4000 2BFF
                            )
                            options.peripheral_end_address = 0x4000_2BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            options.peripheral_start_address = 0x4000_2000  # ok
                            options.peripheral_end_address = 0x4000_23FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x4000_0400  # ok
                            options.peripheral_end_address = 0x4000_07FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                        #################################################################

                        elif dirname == "STM32F":
                            num = num + 1  # 0x5000 0000 - 0x5003 FFFF
                            options.peripheral_start_address = 0x5000_0000  #
                            options.peripheral_end_address = 0x5003_FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usb",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4002_3C00  # 0x4002 3C00 - 0x4002 3FFF
                            )
                            options.peripheral_end_address = 0x4002_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "FlashInterfaceRegister",
                                num,
                            )

                            #
                            options.peripheral_start_address = (
                                0x5000_0000  # 0x5000 0000 - 0x5003 FFFF
                            )
                            options.peripheral_end_address = 0x5003_FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "otg",
                                num,
                            )
                            # Combining the above two because similar ranges ?

                            options.peripheral_start_address = 0x4002_6000
                            options.peripheral_end_address = 0x4002_67FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )  # 00x4002 6000 - 0x4002 63FF/0x4002 6400 - 0x4002 67FF

                            options.peripheral_start_address = (
                                0x4002_3800  # 0x4002 3800 - 0x4002 3BFF
                            )
                            options.peripheral_end_address = 0x4002_3BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rcc",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4002_3000  # 0x4002 3000 - 0x4002 33FF
                            )
                            options.peripheral_end_address = 0x4002_33FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4002_1C00  # 0x4002 1C00 - 0x4002 1FFF
                            )
                            options.peripheral_end_address = 0x4002_1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x4002_0000  # 0x4002 0000 - 0x4002 03FF/0x4002 1000 - 0x4002 13FF
                            options.peripheral_end_address = 0x4002_13FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            # 0x4001 4000 - 0x4001 43FF/ 0x4001 4800 - 0x4001 4BFF
                            options.peripheral_start_address = 0x4001_4000
                            options.peripheral_end_address = 0x4001_4BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            # 0x4001 3C00 - 0x4001 3FFF
                            options.peripheral_start_address = (
                                0x4001_3C00  # 0x4001 3C00 - 0x4001 3FFF
                            )
                            options.peripheral_end_address = 0x4001_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "exti",
                                num,
                            )
                            # 0x4001 3800 - 0x4001 3BFF
                            options.peripheral_start_address = 0x4001_3800
                            options.peripheral_end_address = 0x4001_3BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )  # 0x4001 3800 - 0x4001 3BFF
   
                            options.peripheral_start_address = (
                                0x4001_3400  # 0x4001 3400 - 0x4001 37FF
                            )
                            options.peripheral_end_address = 0x4001_37FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi/i2s",
                                num,
                            )

 
                            options.peripheral_start_address = (
                                0x4001_3000  # 0x4001 3000 - 0x4001 33FF
                            )
                            options.peripheral_end_address = 0x4001_33FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )



                            options.peripheral_start_address = (
                                0x4001_2C00  # 0x4001 2C00 - 0x4001 2FFF
                            )
                            options.peripheral_end_address = 0x4001_2FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sdio",
                                num,
                            )
                            # 0x4001 2000 - 0x4001 23FF
                            options.peripheral_start_address = (
                                0x4001_2000  # 0x4001 2000 - 0x4001 23FF
                            )
                            options.peripheral_end_address = 0x4001_23FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x4001_1000
                            options.peripheral_end_address = 0x4001_17FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usart",
                                num,
                            )

                            # 0x4001 0000 - 0x4001 03FF/ 0x4001 0400 - 0x4001 07FF
                            options.peripheral_start_address = 0x4001_0000
                            options.peripheral_end_address = 0x4001_07FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )
                            # 0x4000 7000 - 0x4000 73FF
                            options.peripheral_start_address = (
                                0x4000_7000  # 0x4000 7000 - 0x4000 73FF
                            )
                            options.peripheral_end_address = 0x4000_73FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwr",
                                num,
                            )

                            # 0x4000_5400- 0x4000_5FFF
                            options.peripheral_start_address = 0x4000_5400  # 0x4000 5400 - 0x4000 57FF/0x4000 5C00 - 0x4000 5FFF
                            options.peripheral_end_address = 0x4000_5FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            # 0x4000_4400 - 0x4000_47FF
                            options.peripheral_start_address = (
                                0x4000_4400  # 0x4000 4400 - 0x4000 47FF
                            )
                            options.peripheral_end_address = 0x4000_47FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usart",
                                num,
                            )

                            # 0x4000_4000 - 0x4000_43FF
                            options.peripheral_start_address = (
                                0x4000_4000  # 0x4000 4000 - 0x4000 43FF
                            )
                            options.peripheral_end_address = 0x4000_43FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2s",
                                num,
                            )

                            # 0x4000_3C00 - 0x4000_3FFF
                            options.peripheral_start_address = 0x4000_3800  # 0x4000 3800 - 0x4000 3BFF/ 0x4000 3C00 - 0x4000 3FFF
                            options.peripheral_end_address = 0x4000_3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi/i2s",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4000_3400  # 0x4000 3400 - 0x4000 37FF
                            )
                            options.peripheral_end_address = 0x4000_37FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2s",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4000_3000  # 0x4000 3000 - 0x4000 33FF
                            )
                            options.peripheral_end_address = 0x4000_33FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "iwdg",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4000_2C00  # 0x4000 2C00 - 0x4000 2FFF
                            )
                            options.peripheral_end_address = 0x4000_2FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wwdg",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4000_2800  # 0x4000 2800 - 0x4000 2BFF
                            )
                            options.peripheral_end_address = 0x4000_2BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc/bkp",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4000_0000  # 0x4000 0FFF
                            )
                            options.peripheral_end_address = 0x4000_0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                        elif (
                            dirname == "STM32G"
                        ):  # ###############################################
                            num = num + 1
                            options.peripheral_start_address = 0x50000000  # ok
                            options.peripheral_end_address = 0x500017FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40026000  # 0x4002 6000 - 0x4002 63FF
                            )
                            options.peripheral_end_address = 0x400263FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "aes",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40025000  # 0x4002 5000 - 0x4002 53FF
                            )
                            options.peripheral_end_address = 0x400253FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rng",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40023000  # 0x4002 3000 - 0x4002 33FF
                            )
                            options.peripheral_end_address = 0x400233FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            options.peripheral_start_address = 0x40022000  # flash
                            options.peripheral_end_address = 0x400223FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "FlashInterfaceRegister",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40021800  # 0x4002 1800 - 0x4002 1BFF
                            )
                            options.peripheral_end_address = 0x40021BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "exti",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40021000  # 0x4002 1000 - 0x4002 13FF
                            )
                            options.peripheral_end_address = 0x400213FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rcc",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40020000  # 0x4002 0000 0x4002 07FF
                            )
                            options.peripheral_end_address = 0x400207FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40020800  # 0x4002 0800 - 0x4002 0BFF
                            )
                            options.peripheral_end_address = 0x40020BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dmaux",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40015800  # 0x4001 5800 - 0x4001 5BFF
                            )
                            options.peripheral_end_address = 0x40015BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dbg",
                                num,
                            )

                            options.peripheral_start_address = 0x40014000  # 0x4001 4800 - 0x4001 4BFF /0x4001 4400 - 0x4001 47FF/ 0x4001 4000 - 0x4001 43FF
                            options.peripheral_end_address = 0x40014BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x40013FFF  # 0x4001 3800 - 0x4001 3BFF/0x4001 3C00 - 0x4001 3FFF
                            options.peripheral_end_address = 0x40013C00
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usart",
                                num,
                            )

                            options.peripheral_start_address = 0x40013BFF  #
                            options.peripheral_end_address = 0x40013800
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usart",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40013000  # 0x4001 3000 - 0x4001 33FF
                            )
                            options.peripheral_end_address = 0x400133FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi/i2s",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40012C00  # 0x4001 2C00 - 0x4001 2FFF
                            )
                            options.peripheral_end_address = 0x40012FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40012400  # 0x4001 2400 - 0x4001 27FF
                            )
                            options.peripheral_end_address = 0x400127FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40010200  # 0x4001 0200 - 0x4001 03FF
                            )
                            options.peripheral_end_address = 0x400103FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "comp",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40010080  # 0x4001 0080 - 0x4001 01FF
                            )
                            options.peripheral_end_address = 0x400101FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40010030  # 0x4001 0030 - 0x4001 007F
                            )
                            options.peripheral_end_address = 0x4001007F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "vrefbuf",
                                num,
                            )

                            options.peripheral_start_address = 0x40010000  # syscfg
                            options.peripheral_end_address = 0x4001002F
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4000B400  # 0x4000 B400- 0x4000 BBFF
                            )
                            options.peripheral_end_address = 0x4000BBFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fdcan",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4000B000  # 0x4000 B000 - 0x4000 B3FF
                            )
                            options.peripheral_end_address = 0x4000B3FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tamp",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x4000A000  # 0x4000 A000 /0x4000 A7FF
                            )
                            options.peripheral_end_address = 0x4000A7FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ucpd",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40009800  # 0x4000 9800 - 0x4000 9FFF
                            )
                            options.peripheral_end_address = 0x40009FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usb",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40009400  # 0x4000 9400 - 0x4000 97FF
                            )
                            options.peripheral_end_address = 0x400097FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lptim",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40008800  # 0x4000 8800 - 0x4000 8BFF
                            )
                            options.peripheral_end_address = 0x40008BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40008000  # 0x4000 8000  . 0x4000 87FF
                            )
                            options.peripheral_end_address = 0x400087FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lpuart",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40007C00  # 0x4000 7C00 - 0x4000 7FFF
                            )
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lptim",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40007800  # 0x4000 7800 - 0x4000 7BFF
                            )
                            options.peripheral_end_address = 0x40007BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "cec",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40007400  # 0x4000 7400 - 0x4000 77FF
                            )
                            options.peripheral_end_address = 0x400077FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dac",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40007000  # 0x4000 7000 - 0x4000 73FF
                            )
                            options.peripheral_end_address = 0x400073FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwr",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40006C00  # 0x4000 6C00 - 0x4000 6FFF
                            )
                            options.peripheral_end_address = 0x40006FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crs",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40006400  # 0x4000 6400 - 0x4000 6BFF
                            )
                            options.peripheral_end_address = 0x40006BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "fdcan",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40005C00  # 0x4000 5C00 - 0x4000 5FFF
                            )
                            options.peripheral_end_address = 0x40005FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usb",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40005400  # 0x4000 5400 0x4000 5BFF
                            )
                            options.peripheral_end_address = 0x40005BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40004400  # 0x4000 4400 - 0x4000 53FF
                            )
                            options.peripheral_end_address = 0x400053FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usart",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40003C00  # 0x4000 3C00 - 0x4000 3FFF
                            )
                            options.peripheral_end_address = 0x40003FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40003BFF  # 0x4000 3800 - 0x4000 3BFF
                            )
                            options.peripheral_end_address = 0x40003800
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi/i2s",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40003000  # 0x4000 3000 - 0x4000 33FF
                            )
                            options.peripheral_end_address = 0x400033FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "iwdg",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40002C00  # 0x4000 2C00 - 0x4000 2FFF
                            )
                            options.peripheral_end_address = 0x40002FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wwdg",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40002800  # 0x4000 2800 - 0x4000 2BFF
                            )
                            options.peripheral_end_address = 0x40002BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40002000  # 0x4000 2000 - 0x4000 23FF
                            )
                            options.peripheral_end_address = 0x400023FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = (
                                0x40001000  # 0x4000 1000 0x4000 17FF
                            )
                            options.peripheral_end_address = 0x400017FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x40000000  #
                            options.peripheral_end_address = 0x40000BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                        #################################################################

                        elif dirname == "STM32L":
                            num = num + 1
                            options.peripheral_start_address = 0x50060800  #
                            options.peripheral_end_address = 0x50060BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rng",
                                num,
                            )

                            options.peripheral_start_address = 0x50040000  #
                            options.peripheral_end_address = 0x500403FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x50000000  #
                            options.peripheral_end_address = 0x5003FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "otg",
                                num,
                            )

                            options.peripheral_start_address = 0x48001FFF  #
                            options.peripheral_end_address = 0x48000000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x40024000  #
                            options.peripheral_end_address = 0x400243FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tsc",
                                num,
                            )

                            options.peripheral_start_address = 0x40023000  #
                            options.peripheral_end_address = 0x400233FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            options.peripheral_start_address = 0x40022000  #
                            options.peripheral_end_address = 0x400223FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "FlashInterfaceRegister",
                                num,
                            )

                            options.peripheral_start_address = 0x40021000  #
                            options.peripheral_end_address = 0x400213FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rcc",
                                num,
                            )

                            options.peripheral_start_address = 0x40020000  #
                            options.peripheral_end_address = 0x400207FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            options.peripheral_start_address = 0x40016000  #
                            options.peripheral_end_address = 0x400063FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dfsdm",
                                num,
                            )

                            options.peripheral_start_address = 0x40015400  #
                            options.peripheral_end_address = 0x40005BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sai",
                                num,
                            )

                            options.peripheral_start_address = 0x40014000  #
                            options.peripheral_end_address = 0x40014BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x40013800  #
                            options.peripheral_end_address = 0x40013BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usart",
                                num,
                            )

                            options.peripheral_start_address = 0x40013400  #
                            options.peripheral_end_address = 0x400137FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x40013000  #
                            options.peripheral_end_address = 0x400133FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            options.peripheral_start_address = 0x40012C00  #
                            options.peripheral_end_address = 0x40012FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x40012800  #
                            options.peripheral_end_address = 0x40012BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sdmmc",
                                num,
                            )

                            options.peripheral_start_address = 0x40010400  #
                            options.peripheral_end_address = 0x400107FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "exti",
                                num,
                            )

                            options.peripheral_start_address = 0x40010200  #
                            options.peripheral_end_address = 0x400103FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "comp",
                                num,
                            )

                            options.peripheral_start_address = 0x40010030  #
                            options.peripheral_end_address = 0x400101FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "vrefbuf",
                                num,
                            )

                            options.peripheral_start_address = 0x40009400  #
                            options.peripheral_end_address = 0x400097FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lptim",
                                num,
                            )

                            options.peripheral_start_address = 0x40008800  #
                            options.peripheral_end_address = 0x40008BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "swpmi",
                                num,
                            )

                            options.peripheral_start_address = 0x40008000  #
                            options.peripheral_end_address = 0x400083FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lpuart",
                                num,
                            )

                            options.peripheral_start_address = 0x40007C00  #
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lptim",
                                num,
                            )

                            options.peripheral_start_address = 0x40007800  #
                            options.peripheral_end_address = 0x40007BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "opamp",
                                num,
                            )

                            options.peripheral_start_address = 0x40007400  #
                            options.peripheral_end_address = 0x400077FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dac",
                                num,
                            )

                            options.peripheral_start_address = 0x40007000  #
                            options.peripheral_end_address = 0x400073FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwr",
                                num,
                            )

                            options.peripheral_start_address = 0x40006400  #
                            options.peripheral_end_address = 0x400067FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "can",
                                num,
                            )

                            options.peripheral_start_address = 0x40005400  #
                            options.peripheral_end_address = 0x40005FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = 0x40004C00  #
                            options.peripheral_end_address = 0x400053FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            options.peripheral_start_address = 0x40004400  #
                            options.peripheral_end_address = 0x40004BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usart",
                                num,
                            )

                            options.peripheral_start_address = 0x40003800  #
                            options.peripheral_end_address = 0x40003FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            options.peripheral_start_address = 0x40003000  #
                            options.peripheral_end_address = 0x400033FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "iwdg",
                                num,
                            )

                            options.peripheral_start_address = 0x40002C00  #
                            options.peripheral_end_address = 0x40002FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wwdg",
                                num,
                            )

                            options.peripheral_start_address = 0x40002800  #
                            options.peripheral_end_address = 0x40002BFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            options.peripheral_start_address = 0x40002400  #
                            options.peripheral_end_address = 0x400027FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lcd",
                                num,
                            )

                            options.peripheral_start_address = 0x40000000  #
                            options.peripheral_end_address = 0x400017FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                        #################################################################

                        elif dirname == "EFM32LeopardGecko":
                            num = num + 1
                            options.peripheral_start_address = 0x40000000  #
                            options.peripheral_end_address = 0x40000400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "vcmp",
                                num,
                            )

                            options.peripheral_start_address = 0x40001000  #
                            options.peripheral_end_address = 0x40001400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            options.peripheral_start_address = 0x40002000  #
                            options.peripheral_end_address = 0x40002400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x40004000  #
                            options.peripheral_end_address = 0x40004400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dac",
                                num,
                            )

                            options.peripheral_start_address = 0x40006000  #
                            options.peripheral_end_address = 0x40007000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x40008000  #
                            options.peripheral_end_address = 0x40008400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ebi",
                                num,
                            )

                            options.peripheral_start_address = 0x4000A000  #
                            options.peripheral_end_address = 0x4000A800
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = 0x4000C000  #
                            options.peripheral_end_address = 0x4000CC00
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usart",
                                num,
                            )

                            options.peripheral_start_address = 0x4000E000  #
                            options.peripheral_end_address = 0x4000E800
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            options.peripheral_start_address = 0x40010000  #
                            options.peripheral_end_address = 0x40011000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x40080000  #
                            options.peripheral_end_address = 0x40080400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            options.peripheral_start_address = 0x40081000  #
                            options.peripheral_end_address = 0x40081400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "burtc",
                                num,
                            )

                            options.peripheral_start_address = 0x40082000  #
                            options.peripheral_end_address = 0x40082400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "letim",
                                num,
                            )

                            options.peripheral_start_address = 0x40084000  #
                            options.peripheral_end_address = 0x40084800
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "leuart",
                                num,
                            )

                            options.peripheral_start_address = 0x40086000  #
                            options.peripheral_end_address = 0x40086C00
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pcnt",
                                num,
                            )

                            options.peripheral_start_address = 0x40088000  #
                            options.peripheral_end_address = 0x40088400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdog",
                                num,
                            )

                            options.peripheral_start_address = 0x4008A000  #
                            options.peripheral_end_address = 0x4008A400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lcd",
                                num,
                            )

                            options.peripheral_start_address = 0x4008C000  #
                            options.peripheral_end_address = 0x4008C400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lesense",
                                num,
                            )

                            options.peripheral_start_address = 0x400C0000  #
                            options.peripheral_end_address = 0x400C0400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "msc",
                                num,
                            )

                            options.peripheral_start_address = 0x400C2000  #
                            options.peripheral_end_address = 0x400C4000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            options.peripheral_start_address = 0x400C4000  #
                            options.peripheral_end_address = 0x400C4400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usb",
                                num,
                            )

                            options.peripheral_start_address = 0x400C6000  #
                            options.peripheral_end_address = 0x400C6400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "emu",
                                num,
                            )

                            options.peripheral_start_address = 0x400C8000  #
                            options.peripheral_end_address = 0x400C8400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "cmu",
                                num,
                            )

                            options.peripheral_start_address = 0x400CA000  #
                            options.peripheral_end_address = 0x400CA400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rmu",
                                num,
                            )

                            options.peripheral_start_address = 0x400CC000  #
                            options.peripheral_end_address = 0x400CC400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "prs",
                                num,
                            )

                            options.peripheral_start_address = 0x400E0000  #
                            options.peripheral_end_address = 0x400E0400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "aes",
                                num,
                            )

                        #################################################################

                        elif dirname == "EFM32HappyGecko":
                            num = num + 1
                            options.peripheral_start_address = 0x40000000  #
                            options.peripheral_end_address = 0x40000400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "vcmp",
                                num,
                            )

                            options.peripheral_start_address = 0x40001000  #
                            options.peripheral_end_address = 0x40001800
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            options.peripheral_start_address = 0x40002000  #
                            options.peripheral_end_address = 0x40002400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x40002000  #
                            options.peripheral_end_address = 0x40002400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x40004000  #
                            options.peripheral_end_address = 0x40004400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "idac",
                                num,
                            )

                            options.peripheral_start_address = 0x40006000  #
                            options.peripheral_end_address = 0x40007000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x4000A000  #
                            options.peripheral_end_address = 0x4000A400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = 0x4000C000  #
                            options.peripheral_end_address = 0x4000C800
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usart",
                                num,
                            )

                            options.peripheral_start_address = 0x40010000  #
                            options.peripheral_end_address = 0x40010C00
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x40080000  #
                            options.peripheral_end_address = 0x40080400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            options.peripheral_start_address = 0x40084000  #
                            options.peripheral_end_address = 0x40084400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "leuart",
                                num,
                            )

                            options.peripheral_start_address = 0x40086000  #
                            options.peripheral_end_address = 0x40086400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pcnt",
                                num,
                            )

                            options.peripheral_start_address = 0x40088000  #
                            options.peripheral_end_address = 0x40088400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdog",
                                num,
                            )

                            options.peripheral_start_address = 0x400C0000  #
                            options.peripheral_end_address = 0x400C0400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "msc",
                                num,
                            )

                            options.peripheral_start_address = 0x400C2000  #
                            options.peripheral_end_address = 0x400C4000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            options.peripheral_start_address = 0x400C4000  #
                            options.peripheral_end_address = 0x400C4400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usb",
                                num,
                            )

                            options.peripheral_start_address = 0x400C6000  #
                            options.peripheral_end_address = 0x400C6400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "emu",
                                num,
                            )

                            options.peripheral_start_address = 0x400C8000  #
                            options.peripheral_end_address = 0x400C8400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "cmu",
                                num,
                            )

                            options.peripheral_start_address = 0x400CA000  #
                            options.peripheral_end_address = 0x400CA400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rmu",
                                num,
                            )

                            options.peripheral_start_address = 0x400CC000  #
                            options.peripheral_end_address = 0x400CC400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "prs",
                                num,
                            )

                            options.peripheral_start_address = 0x400E0000  #
                            options.peripheral_end_address = 0x400E0400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "aes",
                                num,
                            )

                        #################################################################

                        elif dirname == "EFM32ZeroGecko":
                            num = num + 1
                            options.peripheral_start_address = 0x40000000  #
                            options.peripheral_end_address = 0x40000400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "vcmp",
                                num,
                            )

                            options.peripheral_start_address = 0x40001000  #
                            options.peripheral_end_address = 0x40001400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            options.peripheral_start_address = 0x40002000  #
                            options.peripheral_end_address = 0x40002400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x40004000  #
                            options.peripheral_end_address = 0x40004400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "idac",
                                num,
                            )

                            options.peripheral_start_address = 0x40006000  #
                            options.peripheral_end_address = 0x40007000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x4000A000  #
                            options.peripheral_end_address = 0x4000A400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = 0x4000C400  #
                            options.peripheral_end_address = 0x4000C800
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usart",
                                num,
                            )

                            options.peripheral_start_address = 0x40010000  #
                            options.peripheral_end_address = 0x40010800
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x40080000  #
                            options.peripheral_end_address = 0x40080400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            options.peripheral_start_address = 0x40084000  #
                            options.peripheral_end_address = 0x40084400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "leuart",
                                num,
                            )

                            options.peripheral_start_address = 0x40086000  #
                            options.peripheral_end_address = 0x40086400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pcnt",
                                num,
                            )

                            options.peripheral_start_address = 0x40088000  #
                            options.peripheral_end_address = 0x40088400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdog",
                                num,
                            )

                            options.peripheral_start_address = 0x400C0000  #
                            options.peripheral_end_address = 0x400C0400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "msc",
                                num,
                            )

                            options.peripheral_start_address = 0x400C2000  #
                            options.peripheral_end_address = 0x400C4000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            options.peripheral_start_address = 0x400C6000  #
                            options.peripheral_end_address = 0x400C6400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "emu",
                                num,
                            )

                            options.peripheral_start_address = 0x400C8000  #
                            options.peripheral_end_address = 0x400C8400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "cmu",
                                num,
                            )

                            options.peripheral_start_address = 0x400CA000  #
                            options.peripheral_end_address = 0x400CA400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rmu",
                                num,
                            )

                            options.peripheral_start_address = 0x400CC000  #
                            options.peripheral_end_address = 0x400CC400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "prs",
                                num,
                            )

                            options.peripheral_start_address = 0x400E0000  #
                            options.peripheral_end_address = 0x400E0400
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "AES",
                                num,
                            )

                        #################################################################

                        elif dirname == "MSPM0L1228":  ## start from here
                            num = num + 1
                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x4002FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "comp",
                                num,
                            )

                            options.peripheral_start_address = 0x40030000
                            options.peripheral_end_address = 0x4006FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "vref",
                                num,
                            )

                            options.peripheral_start_address = 0x40070000
                            options.peripheral_end_address = 0x4007FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lcd",
                                num,
                            )

                            options.peripheral_start_address = 0x40080000
                            options.peripheral_end_address = 0x40083FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wwdt",
                                num,
                            )

                            options.peripheral_start_address = 0x40084000
                            options.peripheral_end_address = 0x4008BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "timg",
                                num,
                            )

                            options.peripheral_start_address = 0x4008C000
                            options.peripheral_end_address = 0x4008FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "timg",
                                num,
                            )

                            options.peripheral_start_address = 0x40090000
                            options.peripheral_end_address = 0x40093FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "timg",
                                num,
                            )

                            options.peripheral_start_address = 0x40094000
                            options.peripheral_end_address = 0x400950FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lfss",
                                num,
                            )

                            options.peripheral_start_address = 0x40095100
                            options.peripheral_end_address = 0x400952FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            options.peripheral_start_address = 0x40095300
                            options.peripheral_end_address = 0x4009FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "iwdt",
                                num,
                            )

                            options.peripheral_start_address = 0x400A0000
                            options.peripheral_end_address = 0x400ABFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x400AC000
                            options.peripheral_end_address = 0x400AEFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "keystore",
                                num,
                            )

                            options.peripheral_start_address = 0x400AF000
                            options.peripheral_end_address = 0x400C6FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            options.peripheral_start_address = 0x400C7000
                            options.peripheral_end_address = 0x400C8FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "debugss",
                                num,
                            )

                            options.peripheral_start_address = 0x400C9000
                            options.peripheral_end_address = 0x400CCFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "event",
                                num,
                            )

                            options.peripheral_start_address = 0x400CD000
                            options.peripheral_end_address = 0x400EFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "nvm",
                                num,
                            )

                            options.peripheral_start_address = 0x400F0000
                            options.peripheral_end_address = 0x400FFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = 0x40100000
                            options.peripheral_end_address = 0x40107FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            options.peripheral_start_address = 0x40108000
                            options.peripheral_end_address = 0x403FFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            options.peripheral_start_address = 0x40400000
                            options.peripheral_end_address = 0x40423FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "mcpuss",
                                num,
                            )

                            options.peripheral_start_address = 0x40424000
                            options.peripheral_end_address = 0x40427FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wuc",
                                num,
                            )

                            options.peripheral_start_address = 0x40428000
                            options.peripheral_end_address = 0x40429FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "iomux",
                                num,
                            )

                            options.peripheral_start_address = 0x4042A000
                            options.peripheral_end_address = 0x4043FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            options.peripheral_start_address = 0x40440000
                            options.peripheral_end_address = 0x40443FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            options.peripheral_start_address = 0x40442000
                            options.peripheral_end_address = 0x40443FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "aesadv",
                                num,
                            )

                            options.peripheral_start_address = 0x40444000
                            options.peripheral_end_address = 0x40467FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "trng",
                                num,
                            )

                            options.peripheral_start_address = 0x40468000
                            options.peripheral_end_address = 0x40559FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            options.peripheral_start_address = 0x4055A000
                            options.peripheral_end_address = 0x4085FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x40860000
                            options.peripheral_end_address = 0x40886FFF
                            main(
                                os.path.join(data_dir, dirname, path), options, "", num
                            )

                            options.peripheral_start_address = 0x40870000
                            options.peripheral_end_address = 0x40872000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "timg",
                                num,
                            )

                        elif dirname == "MSPM0L2228":
                            num = num + 1
                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x4002FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "comp",
                                num,
                            )

                            options.peripheral_start_address = 0x40030000
                            options.peripheral_end_address = 0x4006FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "vref",
                                num,
                            )

                            options.peripheral_start_address = 0x40070000
                            options.peripheral_end_address = 0x4007FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lcd",
                                num,
                            )

                            options.peripheral_start_address = 0x40080000
                            options.peripheral_end_address = 0x40083FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wwdt",
                                num,
                            )

                            options.peripheral_start_address = 0x40084000
                            options.peripheral_end_address = 0x4008BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "timg",
                                num,
                            )

                            options.peripheral_start_address = 0x4008C000
                            options.peripheral_end_address = 0x4008FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "timg",
                                num,
                            )

                            options.peripheral_start_address = 0x40090000
                            options.peripheral_end_address = 0x40093FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "timg",
                                num,
                            )

                            options.peripheral_start_address = 0x40094000
                            options.peripheral_end_address = 0x400950FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lfss",
                                num,
                            )

                            options.peripheral_start_address = 0x40095100
                            options.peripheral_end_address = 0x400952FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            options.peripheral_start_address = 0x40095300
                            options.peripheral_end_address = 0x4009FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "iwdt",
                                num,
                            )

                            options.peripheral_start_address = 0x400A0000
                            options.peripheral_end_address = 0x400ABFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x400AC000
                            options.peripheral_end_address = 0x400AEFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "keystore",
                                num,
                            )

                            options.peripheral_start_address = 0x400AF000
                            options.peripheral_end_address = 0x400C6FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            options.peripheral_start_address = 0x400C7000
                            options.peripheral_end_address = 0x400C8FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "debugss",
                                num,
                            )

                            options.peripheral_start_address = 0x400C9000
                            options.peripheral_end_address = 0x400CCFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "event",
                                num,
                            )

                            options.peripheral_start_address = 0x400CD000
                            options.peripheral_end_address = 0x400EFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "nvm",
                                num,
                            )

                            options.peripheral_start_address = 0x400F0000
                            options.peripheral_end_address = 0x400FFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = 0x40100000
                            options.peripheral_end_address = 0x40107FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            options.peripheral_start_address = 0x40108000
                            options.peripheral_end_address = 0x403FFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            options.peripheral_start_address = 0x40400000
                            options.peripheral_end_address = 0x40423FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "mcpuss",
                                num,
                            )

                            options.peripheral_start_address = 0x40424000
                            options.peripheral_end_address = 0x40427FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wuc",
                                num,
                            )

                            options.peripheral_start_address = 0x40428000
                            options.peripheral_end_address = 0x40429FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "iomux",
                                num,
                            )

                            options.peripheral_start_address = 0x4042A000
                            options.peripheral_end_address = 0x4043FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            options.peripheral_start_address = 0x40440000
                            options.peripheral_end_address = 0x40443FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            options.peripheral_start_address = 0x40442000
                            options.peripheral_end_address = 0x40443FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "aesadv",
                                num,
                            )

                            options.peripheral_start_address = 0x40444000
                            options.peripheral_end_address = 0x40467FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "trng",
                                num,
                            )

                            options.peripheral_start_address = 0x40468000
                            options.peripheral_end_address = 0x40559FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            options.peripheral_start_address = 0x4055A000
                            options.peripheral_end_address = 0x4085FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x40860000
                            options.peripheral_end_address = 0x40886FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x40870000
                            options.peripheral_end_address = 0x40872000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "timg",
                                num,
                            )

                        elif dirname == "MSP432E401Y":
                            num = num + 1
                            options.peripheral_start_address = 0x40000000
                            options.peripheral_end_address = 0x40001FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x4000BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ssi",
                                num,
                            )

                            options.peripheral_start_address = 0x4000C000
                            options.peripheral_end_address = 0x40013FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            options.peripheral_start_address = 0x40020000
                            options.peripheral_end_address = 0x40023FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = 0x40024000
                            options.peripheral_end_address = 0x40027FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x40028000
                            options.peripheral_end_address = 0x40028FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pwm",
                                num,
                            )

                            options.peripheral_start_address = 0x4002C000
                            options.peripheral_end_address = 0x4002CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "qei",
                                num,
                            )

                            options.peripheral_start_address = 0x40030000
                            options.peripheral_end_address = 0x40035FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x40038000
                            options.peripheral_end_address = 0x40039FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x4003C000
                            options.peripheral_end_address = 0x4003CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "analogComparator",
                                num,
                            )

                            options.peripheral_start_address = 0x4003D000
                            options.peripheral_end_address = 0x4003DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40041FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "can",
                                num,
                            )

                            options.peripheral_start_address = 0x40050000
                            options.peripheral_end_address = 0x40050FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usb",
                                num,
                            )

                            options.peripheral_start_address = 0x40058000
                            options.peripheral_end_address = 0x40066FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x400AF000
                            options.peripheral_end_address = 0x400AFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "eeprom",
                                num,
                            )

                            options.peripheral_start_address = 0x400B8000
                            options.peripheral_end_address = 0x400B9FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = 0x400C0000
                            options.peripheral_end_address = 0x400C3FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = 0x400D0000
                            options.peripheral_end_address = 0x400D0FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "epio",
                                num,
                            )

                            options.peripheral_start_address = 0x400E0000
                            options.peripheral_end_address = 0x400E1FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x400EC000
                            options.peripheral_end_address = 0x400ECFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ethernetController",
                                num,
                            )

                            options.peripheral_start_address = 0x400F9000
                            options.peripheral_end_address = 0x400F9FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "systemException",
                                num,
                            )

                            options.peripheral_start_address = 0x400FC000
                            options.peripheral_end_address = 0x400FCFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "hibernation",
                                num,
                            )

                            options.peripheral_start_address = 0x400FD000
                            options.peripheral_end_address = 0x400FDFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "flashMemoryControl",
                                num,
                            )

                            options.peripheral_start_address = 0x400FE000
                            options.peripheral_end_address = 0x400FEFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            options.peripheral_start_address = 0x400FF000
                            options.peripheral_end_address = 0x400FFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "udma",
                                num,
                            )

                            options.peripheral_start_address = 0x42000000
                            options.peripheral_end_address = 0x43FFFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "bitBandedAlias",
                                num,
                            )

                            options.peripheral_start_address = 0x44030000
                            options.peripheral_end_address = 0x44030FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            options.peripheral_start_address = 0x44034000
                            options.peripheral_end_address = 0x44035FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sha",
                                num,
                            )

                            options.peripheral_start_address = 0x44036000
                            options.peripheral_end_address = 0x44037FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "aes",
                                num,
                            )

                            options.peripheral_start_address = 0x44038000
                            options.peripheral_end_address = 0x44039FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "des",
                                num,
                            )

                            options.peripheral_start_address = 0x44054000
                            options.peripheral_end_address = 0x44054FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ephy",
                                num,
                            )

                            options.peripheral_start_address = 0x60000000
                            options.peripheral_end_address = 0xDFFFFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "epio",
                                num,
                            )

                        elif dirname == "MXRT600":
                            num = num + 1
                            options.peripheral_start_address = 0x40000000
                            options.peripheral_end_address = 0x40000FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "RSTCTL",
                                num,
                            )

                            options.peripheral_start_address = 0x40001000
                            options.peripheral_end_address = 0x40001FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40005FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "IOCON",
                                num,
                            )

                            options.peripheral_start_address = 0x40006000
                            options.peripheral_end_address = 0x4000DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "uart",
                                num,
                            )

                            options.peripheral_start_address = 0x4000E000
                            options.peripheral_end_address = 0x4000EFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wwdt",
                                num,
                            )

                            options.peripheral_start_address = 0x4000F000
                            options.peripheral_end_address = 0x4001FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "utick",
                                num,
                            )

                            options.peripheral_start_address = 0x40020000
                            options.peripheral_end_address = 0x40020FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "RSTCTL",
                                num,
                            )

                            options.peripheral_start_address = 0x40021000
                            options.peripheral_end_address = 0x40021FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "clk",
                                num,
                            )

                            options.peripheral_start_address = 0x40022000
                            options.peripheral_end_address = 0x40024FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            options.peripheral_start_address = 0x40025000
                            options.peripheral_end_address = 0x40025FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x40026000
                            options.peripheral_end_address = 0x40027FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "inputMultiplexingControls",
                                num,
                            )

                            options.peripheral_start_address = 0x40028000
                            options.peripheral_end_address = 0x4002CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "CT32B",
                                num,
                            )

                            options.peripheral_start_address = 0x4002D000
                            options.peripheral_end_address = 0x4002DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "MRT",
                                num,
                            )

                            options.peripheral_start_address = 0x4002E000
                            options.peripheral_end_address = 0x4002EFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wwdt",
                                num,
                            )

                            options.peripheral_start_address = 0x4002F000
                            options.peripheral_end_address = 0x4002FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "frequencyMeasureUnit",
                                num,
                            )

                            options.peripheral_start_address = 0x40030000
                            options.peripheral_end_address = 0x40035FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            options.peripheral_start_address = 0x40036000
                            options.peripheral_end_address = 0x400FFFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i3c",
                                num,
                            )

                            options.peripheral_start_address = 0x40100000
                            options.peripheral_end_address = 0x40103FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x40104000
                            options.peripheral_end_address = 0x40105FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            options.peripheral_start_address = 0x40106000
                            options.peripheral_end_address = 0x4010EFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "flexcomInterface",
                                num,
                            )

                            options.peripheral_start_address = 0x4010F000
                            options.peripheral_end_address = 0x4010FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "debugMailbox",
                                num,
                            )

                            options.peripheral_start_address = 0x40110000
                            options.peripheral_end_address = 0x40110FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "messageUnitA",
                                num,
                            )

                            options.peripheral_start_address = 0x40111000
                            options.peripheral_end_address = 0x40111FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "messageUnitB",
                                num,
                            )

                            options.peripheral_start_address = 0x40112000
                            options.peripheral_end_address = 0x40112FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "semaphore",
                                num,
                            )

                            options.peripheral_start_address = 0x40113000
                            options.peripheral_end_address = 0x40113FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "osEventTimer",
                                num,
                            )

                            options.peripheral_start_address = 0x40114000
                            options.peripheral_end_address = 0x4011FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "osEventTimer",
                                num,
                            )

                            options.peripheral_start_address = 0x40120000
                            options.peripheral_end_address = 0x40120FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            options.peripheral_start_address = 0x40121000
                            options.peripheral_end_address = 0x40121FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dmic",
                                num,
                            )

                            options.peripheral_start_address = 0x40122000
                            options.peripheral_end_address = 0x40125FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "flexcomInterface",
                                num,
                            )

                            options.peripheral_start_address = 0x40126000
                            options.peripheral_end_address = 0x4012FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "flexcomInterface",
                                num,
                            )

                            options.peripheral_start_address = 0x40130000
                            options.peripheral_end_address = 0x40133FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "otp",
                                num,
                            )

                            options.peripheral_start_address = 0x40134000
                            options.peripheral_end_address = 0x40134FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "flexSpi",
                                num,
                            )

                            options.peripheral_start_address = 0x40135000
                            options.peripheral_end_address = 0x40135FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pmc",
                                num,
                            )

                            options.peripheral_start_address = 0x40136000
                            options.peripheral_end_address = 0x40137FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sdio",
                                num,
                            )

                            options.peripheral_start_address = 0x40138000
                            options.peripheral_end_address = 0x40138FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "randomeNumberGenerator",
                                num,
                            )

                            options.peripheral_start_address = 0x40139000
                            options.peripheral_end_address = 0x40139FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "acmp",
                                num,
                            )

                            options.peripheral_start_address = 0x4013A000
                            options.peripheral_end_address = 0x4013AFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x4013B000
                            options.peripheral_end_address = 0x4013FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "hsUsbPhy",
                                num,
                            )

                            options.peripheral_start_address = 0x40140000
                            options.peripheral_end_address = 0x40143FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "hsUsbRam",
                                num,
                            )

                            options.peripheral_start_address = 0x40144000
                            options.peripheral_end_address = 0x40144FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "hsUsbDevice",
                                num,
                            )

                            options.peripheral_start_address = 0x40145000
                            options.peripheral_end_address = 0x40145FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "hsUsbHost",
                                num,
                            )

                            options.peripheral_start_address = 0x40146000
                            options.peripheral_end_address = 0x40147FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scTimer",
                                num,
                            )

                            options.peripheral_start_address = 0x40148000
                            options.peripheral_end_address = 0x40144FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "securityControlRegister",
                                num,
                            )

                            options.peripheral_start_address = 0x40145000
                            options.peripheral_end_address = 0x40150FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "powerQuadCoprocessor",
                                num,
                            )

                            options.peripheral_start_address = 0x40151000
                            options.peripheral_end_address = 0x40151FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "casperProcessor",
                                num,
                            )

                            options.peripheral_start_address = 0x40152000
                            options.peripheral_end_address = 0x40153FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "casperRam",
                                num,
                            )

                            options.peripheral_start_address = 0x40154000
                            options.peripheral_end_address = 0x40157FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x40158000
                            options.peripheral_end_address = 0x4016E383
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                        elif dirname == "LPC54114":
                            num = num + 1
                            options.peripheral_start_address = 0x400A0000
                            options.peripheral_end_address = 0x400A1000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x4009C000
                            options.peripheral_end_address = 0x4009D000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "isp",
                                num,
                            )

                            options.peripheral_start_address = 0x40082000
                            options.peripheral_end_address = 0x40083000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            options.peripheral_start_address = 0x40084000
                            options.peripheral_end_address = 0x40084FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usb",
                                num,
                            )

                            options.peripheral_start_address = 0x40085000
                            options.peripheral_end_address = 0x40085FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scTimer",
                                num,
                            )

                            options.peripheral_start_address = 0x40086000
                            options.peripheral_end_address = 0x4008AFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "flexcomInterface",
                                num,
                            )

                            options.peripheral_start_address = 0x4008B000
                            options.peripheral_end_address = 0x4008BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "mailbox",
                                num,
                            )

                            options.peripheral_start_address = 0x4008C000
                            options.peripheral_end_address = 0x4008FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x40090000
                            options.peripheral_end_address = 0x40091000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dmic",
                                num,
                            )

                            options.peripheral_start_address = 0x40095000
                            options.peripheral_end_address = 0x40095FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            options.peripheral_start_address = 0x40096000
                            options.peripheral_end_address = 0x40099000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "flexcomInterface",
                                num,
                            )

                            options.peripheral_start_address = 0x40000000
                            options.peripheral_end_address = 0x40000FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            options.peripheral_start_address = 0x40001000
                            options.peripheral_end_address = 0x40001FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "IOCON",
                                num,
                            )

                            options.peripheral_start_address = 0x40002000
                            options.peripheral_end_address = 0x40003FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gint",
                                num,
                            )

                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40004FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pint",
                                num,
                            )

                            options.peripheral_start_address = 0x40005000
                            options.peripheral_end_address = 0x40006000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "inputMuxes",
                                num,
                            )

                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x4000A000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x4000C000
                            options.peripheral_end_address = 0x4000CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdt",
                                num,
                            )

                            options.peripheral_start_address = 0x4000D000
                            options.peripheral_end_address = 0x4000DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "MRT",
                                num,
                            )

                            options.peripheral_start_address = 0x4000E000
                            options.peripheral_end_address = 0x4000E000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "microtickTimer",
                                num,
                            )

                            options.peripheral_start_address = 0x40028000
                            options.peripheral_end_address = 0x40029000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x4002C000
                            options.peripheral_end_address = 0x4002D000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            options.peripheral_start_address = 0x40034000
                            options.peripheral_end_address = 0x40035000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "flashController",
                                num,
                            )

                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40041000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            options.peripheral_start_address = 0x40048000
                            options.peripheral_end_address = 0x4004A000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                        elif dirname == "LPC824":
                            num = num + 1
                            options.peripheral_start_address = 0x40000000
                            options.peripheral_end_address = 0x40003FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wwdt",
                                num,
                            )

                            options.peripheral_start_address = 0x40004000
                            options.peripheral_end_address = 0x40007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "MRT",
                                num,
                            )

                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x4000BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tmr",
                                num,
                            )

                            options.peripheral_start_address = 0x4000C000
                            options.peripheral_end_address = 0x40010000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "switchMatrix",
                                num,
                            )

                            options.peripheral_start_address = 0x4001C000
                            options.peripheral_end_address = 0x4001FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "adc",
                                num,
                            )

                            options.peripheral_start_address = 0x40020000
                            options.peripheral_end_address = 0x40023FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "PMU",
                                num,
                            )

                            options.peripheral_start_address = 0x40024000
                            options.peripheral_end_address = 0x40027FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "analogComparator",
                                num,
                            )

                            options.peripheral_start_address = 0x40028000
                            options.peripheral_end_address = 0x4002BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            options.peripheral_start_address = 0x4002C000
                            options.peripheral_end_address = 0x40030000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "inputMuxes",
                                num,
                            )

                            options.peripheral_start_address = 0x40040000
                            options.peripheral_end_address = 0x40043FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "flashController",
                                num,
                            )

                            options.peripheral_start_address = 0x40044000
                            options.peripheral_end_address = 0x40047FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "IOCON",
                                num,
                            )

                            options.peripheral_start_address = 0x40048000
                            options.peripheral_end_address = 0x4004C000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sys",
                                num,
                            )

                            options.peripheral_start_address = 0x40050000
                            options.peripheral_end_address = 0x40057FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = 0x40058000
                            options.peripheral_end_address = 0x40060000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spi",
                                num,
                            )

                            options.peripheral_start_address = 0x40064000
                            options.peripheral_end_address = 0x4006FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usart",
                                num,
                            )

                            options.peripheral_start_address = 0x40070000
                            options.peripheral_end_address = 0x40078000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2c",
                                num,
                            )

                            options.peripheral_start_address = 0x50000000
                            options.peripheral_end_address = 0x50003FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "crc",
                                num,
                            )

                            options.peripheral_start_address = 0x50004000
                            options.peripheral_end_address = 0x50007FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scTimer",
                                num,
                            )

                            options.peripheral_start_address = 0x50008000
                            options.peripheral_end_address = 0x5000C000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            options.peripheral_start_address = 0x4000E000
                            options.peripheral_end_address = 0x4000E000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                        elif dirname == "K32L3":
                            num = num + 1
                            options.peripheral_start_address = 0x40001000
                            options.peripheral_end_address = 0x40002000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "MSCM",
                                num,
                            )

                            options.peripheral_start_address = 0x40003000
                            options.peripheral_end_address = 0x40003FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "syspm",
                                num,
                            )

                            options.peripheral_start_address = 0x40008000
                            options.peripheral_end_address = 0x40008FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "DMA",
                                num,
                            )

                            options.peripheral_start_address = 0x40009000
                            options.peripheral_end_address = 0x4000A000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "DMA",
                                num,
                            )

                            options.peripheral_start_address = 0x4000C000
                            options.peripheral_end_address = 0x4000D000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "flexBus",
                                num,
                            )

                            options.peripheral_start_address = 0x4000D000
                            options.peripheral_end_address = 0x40018000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "xrdc",
                                num,
                            )

                            options.peripheral_start_address = 0x4001B000
                            options.peripheral_end_address = 0x4001C000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sema",
                                num,
                            )

                            options.peripheral_start_address = 0x40020000
                            options.peripheral_end_address = 0x40020FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "msmc",
                                num,
                            )

                            options.peripheral_start_address = 0x40021000
                            options.peripheral_end_address = 0x40021FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dmaux",
                                num,
                            )

                            options.peripheral_start_address = 0x40022000
                            options.peripheral_end_address = 0x40022FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ewm",
                                num,
                            )

                            options.peripheral_start_address = 0x40023000
                            options.peripheral_end_address = 0x40023FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "msmc",
                                num,
                            )

                            options.peripheral_start_address = 0x40024000
                            options.peripheral_end_address = 0x40024FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "llwu",
                                num,
                            )

                            options.peripheral_start_address = 0x40025000
                            options.peripheral_end_address = 0x40025FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "MU",
                                num,
                            )

                            options.peripheral_start_address = 0x40026000
                            options.peripheral_end_address = 0x40026FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sim",
                                num,
                            )

                            options.peripheral_start_address = 0x40027000
                            options.peripheral_end_address = 0x40027FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sim",
                                num,
                            )

                            options.peripheral_start_address = 0x40028000
                            options.peripheral_end_address = 0x40028FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "spm",
                                num,
                            )

                            options.peripheral_start_address = 0x40029000
                            options.peripheral_end_address = 0x40029FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rgmu",
                                num,
                            )

                            options.peripheral_start_address = 0x4002A000
                            options.peripheral_end_address = 0x4002AFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdog",
                                num,
                            )

                            options.peripheral_start_address = 0x4002B000
                            options.peripheral_end_address = 0x4002BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pcc",
                                num,
                            )

                            options.peripheral_start_address = 0x4002C000
                            options.peripheral_end_address = 0x4002CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "scg",
                                num,
                            )

                            options.peripheral_start_address = 0x4002D000
                            options.peripheral_end_address = 0x4002DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "systemRegisterFile",
                                num,
                            )

                            options.peripheral_start_address = 0x4002E000
                            options.peripheral_end_address = 0x4002EFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "vbatRegisterFile",
                                num,
                            )

                            options.peripheral_start_address = 0x4002F000
                            options.peripheral_end_address = 0x4002FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "CRC",
                                num,
                            )

                            options.peripheral_start_address = 0x40030000
                            options.peripheral_end_address = 0x40030FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lpit",
                                num,
                            )

                            options.peripheral_start_address = 0x40031000
                            options.peripheral_end_address = 0x40031FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "rtc",
                                num,
                            )

                            options.peripheral_start_address = 0x40032000
                            options.peripheral_end_address = 0x40033FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lptmr",
                                num,
                            )

                            options.peripheral_start_address = 0x40034000
                            options.peripheral_end_address = 0x40034FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tstmr",
                                num,
                            )

                            options.peripheral_start_address = 0x40035000
                            options.peripheral_end_address = 0x40037FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tpm",
                                num,
                            )

                            options.peripheral_start_address = 0x40038000
                            options.peripheral_end_address = 0x40038FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "EMVSIM",
                                num,
                            )

                            options.peripheral_start_address = 0x40039000
                            options.peripheral_end_address = 0x40039FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "flexl",
                                num,
                            )

                            options.peripheral_start_address = 0x4003A000
                            options.peripheral_end_address = 0x4003CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lpi2",
                                num,
                            )

                            options.peripheral_start_address = 0x4003D000
                            options.peripheral_end_address = 0x4003DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "i2s",
                                num,
                            )

                            options.peripheral_start_address = 0x4003E000
                            options.peripheral_end_address = 0x4003EFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sdhc",
                                num,
                            )

                            options.peripheral_start_address = 0x4003F000
                            options.peripheral_end_address = 0x40041FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lpspi",
                                num,
                            )

                            options.peripheral_start_address = 0x40042000
                            options.peripheral_end_address = 0x40044FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lpuart",
                                num,
                            )

                            options.peripheral_start_address = 0x40045000
                            options.peripheral_end_address = 0x40045FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usb",
                                num,
                            )

                            options.peripheral_start_address = 0x40046000
                            options.peripheral_end_address = 0x40049FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "port",
                                num,
                            )

                            options.peripheral_start_address = 0x4004A000
                            options.peripheral_end_address = 0x4004AFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lpadc",
                                num,
                            )

                            options.peripheral_start_address = 0x4004B000
                            options.peripheral_end_address = 0x4004BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lpcmp",
                                num,
                            )

                            options.peripheral_start_address = 0x4004C000
                            options.peripheral_end_address = 0x4004CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dac",
                                num,
                            )

                            options.peripheral_start_address = 0x4004D000
                            options.peripheral_end_address = 0x4007FFFE
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "vref",
                                num,
                            )

                            options.peripheral_start_address = 0x41000000
                            options.peripheral_end_address = 0x4107FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "cm",
                                num,
                            )

                            options.peripheral_start_address = 0x48000000
                            options.peripheral_end_address = 0x48000FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "flexRam",
                                num,
                            )

                            options.peripheral_start_address = 0x48010000
                            options.peripheral_end_address = 0x480107FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usb",
                                num,
                            )

                            options.peripheral_start_address = 0x48020000
                            options.peripheral_end_address = 0x48020FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "gpio",
                                num,
                            )

                            options.peripheral_start_address = 0x41008000
                            options.peripheral_end_address = 0x4100A000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dma",
                                num,
                            )

                            options.peripheral_start_address = 0x4100F000
                            options.peripheral_end_address = 0x40010000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "ioPort",
                                num,
                            )

                            options.peripheral_start_address = 0x4101B000
                            options.peripheral_end_address = 0x4101C000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "sema",
                                num,
                            )

                            options.peripheral_start_address = 0x41020000
                            options.peripheral_end_address = 0x41020FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "msmc",
                                num,
                            )

                            options.peripheral_start_address = 0x41021000
                            options.peripheral_end_address = 0x41021FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "dmamux",
                                num,
                            )

                            options.peripheral_start_address = 0x41022000
                            options.peripheral_end_address = 0x41022FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "intmux",
                                num,
                            )

                            options.peripheral_start_address = 0x41023000
                            options.peripheral_end_address = 0x41023FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "llwu",
                                num,
                            )

                            options.peripheral_start_address = 0x41024000
                            options.peripheral_end_address = 0x41024FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "MU",
                                num,
                            )

                            options.peripheral_start_address = 0x41025000
                            options.peripheral_end_address = 0x41025FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "trgmux",
                                num,
                            )

                            options.peripheral_start_address = 0x41026000
                            options.peripheral_end_address = 0x41026FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "wdog",
                                num,
                            )

                            options.peripheral_start_address = 0x41027000
                            options.peripheral_end_address = 0x41027FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "pcc",
                                num,
                            )

                            options.peripheral_start_address = 0x41028000
                            options.peripheral_end_address = 0x41028FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "cau",
                                num,
                            )

                            options.peripheral_start_address = 0x41029000
                            options.peripheral_end_address = 0x41029FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "trng",
                                num,
                            )

                            options.peripheral_start_address = 0x4102A000
                            options.peripheral_end_address = 0x4102AFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lpit",
                                num,
                            )

                            options.peripheral_start_address = 0x4102B000
                            options.peripheral_end_address = 0x4102BFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lptmr",
                                num,
                            )

                            options.peripheral_start_address = 0x4102C000
                            options.peripheral_end_address = 0x4102CFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tstmr",
                                num,
                            )

                            options.peripheral_start_address = 0x4102D000
                            options.peripheral_end_address = 0x4102DFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "tpm",
                                num,
                            )

                            options.peripheral_start_address = 0x4102E000
                            options.peripheral_end_address = 0x4102F000
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lpi2",
                                num,
                            )

                            options.peripheral_start_address = 0x41035000
                            options.peripheral_end_address = 0x41035FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lpspi",
                                num,
                            )

                            options.peripheral_start_address = 0x41036000
                            options.peripheral_end_address = 0x41036FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lpuart",
                                num,
                            )

                            options.peripheral_start_address = 0x41037000
                            options.peripheral_end_address = 0x41037FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "port",
                                num,
                            )

                            options.peripheral_start_address = 0x41038000
                            options.peripheral_end_address = 0x4107FFFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "lpcmp",
                                num,
                            )

                            options.peripheral_start_address = 0x48000000
                            options.peripheral_end_address = 0x48000FFF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "flexRam",
                                num,
                            )

                            options.peripheral_start_address = 0x48010000
                            options.peripheral_end_address = 0x480107FF
                            main(
                                os.path.join(data_dir, dirname, path),
                                options,
                                "usb",
                                num,
                            )

                    except Exception as e:
                        print(e)
        
        # Process the CSV file to generate Level3 data
        df = pd.read_csv("Level2_Depth1.csv")  

        # Define the columns to be aggregated by summation
        features_to_aggregate = [
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
        ]

        # Group by 'Name', 'BB_Addr', and 'Reg_add' and compute the sum for the specified features
        aggregated_df = df.groupby(["Name", "BB_Addr", "Reg_add"], as_index=False)[
            features_to_aggregate
        ].sum()

        # Drop the aggregated features from the original DataFrame
        df_dropped = df.drop(columns=features_to_aggregate)

        # Merge the aggregated features back into the original DataFrame without losing other columns
        merged_df = pd.merge(
            df_dropped.drop_duplicates(subset=["Name", "BB_Addr", "Reg_add"]),
            aggregated_df,
            on=["Name", "BB_Addr", "Reg_add"],
            how="right",
        )

        # Sort the DataFrame by 'Name', 'BB_Addr', 'Reg_add'
        sorted_df = merged_df.sort_values(by=["Name", "BB_Addr", "Reg_add"])

        # Ensure 'peripheral' is the last column if it exists in the DataFrame
        if "peripheral" in sorted_df.columns:
            cols = [col for col in sorted_df.columns if col != "peripheral"] + [
                "peripheral"
            ]
            sorted_df = sorted_df[cols]

        # Save the results to a new CSV file
        sorted_df.to_csv(
            "New_Level3_depth.csv", index=False
        )  # Adjust this path as necessary
        
        print("Level3 data generated successfully: New_Level3_depth.csv")
    else:
        options, rgs = parse_args(args.FM)
        options.arch = "armcortexm"
        options.print_accesses = True
        options.peripheral_start_address = int(args.ps, 16)
        options.peripheral_end_address = int(args.pe, 16)

        path = args.FM
        main(f"{args.FM}", options, " ", num)
