#!/usr/bin/env python

import pandas as pd
import logging
import os
from optparse import OptionGroup, OptionParser
import angr
import cle
import graph
import predict.bbchain as bbchain
import argparse
import predict.Predict_ as Predict_
from pathlib import Path

log = logging.getLogger(__name__)

PROGRAM_USAGE = "Usage: %prog [options] module"


def parse_args(path):
    parser = OptionParser(usage=PROGRAM_USAGE)

    group_analysis = OptionGroup(parser, "Analysis Options")

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


def set_log_levels(options):
    """Sets all the log levels based on user provided options."""
    logging.getLogger(__name__).setLevel(options.logging)
    logging.getLogger(angr.__name__).setLevel(options.logging_angr)
    logging.getLogger(graph.__name__).setLevel(options.logging)


def ext_features(path, options, num=0):
    """
    path : Main path of bin file

    options: options e.g start and end address

    num: serial number of firmware (optional)
    """

    main_bin_fp = path
    set_log_levels(options)
    # determine what the base address of the module should be
    if options.base_addr is None:
        log.info("No base address provided, using default value")
        options.base_addr = 0x100000
    log.info("Using base address: %#x" % options.base_addr)

    log.info("Loading module: %s" % main_bin_fp)
    log.info("Creating project")
    
    # Check file type like test.py does
    format = Path(main_bin_fp).suffix
    if (format == '.bin'):
        # for bin files
        with open(main_bin_fp, "rb") as ibin:
            blob = cle.Blob(
                binary=main_bin_fp,
                binary_stream=ibin,
                is_main_bin=True,
                arch=options.arch,
                base_addr=options.base_addr
            )
        proj = angr.Project(thing=blob, use_sim_procedures=False)
        # Set platform to avoid calling convention issues
        proj.arch.platform = 'baremetal'
    else:
        # for elf files
        proj = angr.Project(main_bin_fp, auto_load_libs=True)
        # Set platform to avoid calling convention issues
        proj.arch.platform = 'baremetal'
            
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

    grp = bbchain.ext_chain(peri_accesses, cfg)
    bbchain.chain_dataset(cfg, groups=grp, num=num, path=path, acc=peri_accesses)


def main():
    ## entery point of this program
    ## executing this boundary will give the outputs

    ##Parsing the arguments
    parser = argparse.ArgumentParser(description="Tool Options")
    # firmware
    parser.add_argument("FM", default="", type=str, help="Path of file for Predictions")
    parser.add_argument("arch", default="armcortexm", type=str, help="End Address")
    parser.add_argument("op", type=str, help="Architecture")
    parser.add_argument("S_A", default="0x40000000", type=str, help="Start Address")
    parser.add_argument("E_A", default="0x5FFFFFFF", type=str, help="End Address")

    args = parser.parse_args()

    path = args.FM
    options, rgs = parse_args(path)

  
    if args.op == "predict":
        options.peripheral_start_address = int(args.S_A, 16)
        options.peripheral_end_address = int(args.E_A, 16)
        options.arch=args.arch
        ext_features(f"{path}", options)

    df = pd.read_csv("Level2_Depth1.csv")  # Make sure to adjust this path as necessary
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
        "Level3_PrePredict.csv", index=False
    )  # Adjust this path as necessary
    Predict_.Predict()
    os.remove("Level2_Depth1.csv")


if __name__ == "__main__":
    main()

