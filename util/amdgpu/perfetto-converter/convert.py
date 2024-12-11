#!/usr/bin/env python3

import argparse
import ast
import gzip
import sys

from tg4perfetto import TraceGenerator

parser = argparse.ArgumentParser()

parser.add_argument(
    "-i",
    "--input",
    type=str,
    default="",
    help="Input file. Usually path to perfetto-log.gz in m5out directory.",
)
parser.add_argument(
    "-o",
    "--output",
    type=str,
    default="",
    help="Output file. This is the trace loaded to ui.perfetto.dev.",
)
parser.add_argument(
    "-t",
    "--tasks",
    type=str,
    default="",
    help="Comma-delimited list of Task IDs to show wavefront-level details",
)
parser.add_argument(
    "-s",
    "--start-at-aql-task",
    type=int,
    default=-1,
    help="Start trace at this AQL task.",
)
parser.add_argument(
    "-d",
    "--start-at-sdma-copy",
    type=int,
    default=-1,
    help="Start trace at this SDMA copy packet.",
)

args = parser.parse_args()

if args.input == "":
    print("No input file specified! Exiting.")
    sys.exit(1)
if args.output == "":
    print("No output file specified! Exiting.")
    sys.exit(1)

tgen = TraceGenerator(args.output)

# Parse input file to find starting ticks and number of tracks.
first_aql = 0
first_sdma = 0

sdma_mappings = {}
aql_mappings = {}
wf_mappings = {}

# Keept track of start/end ticks for specific tasks. This can be used to
# create a trace file containing only detailed information about a single
# task, for example.
task_windows = {}

tasks_of_interest = []
skip_tasks = []
if args.tasks != "":
    for task in args.tasks.split(","):
        tasks_of_interest.append(int(task))

print(f"{tasks_of_interest = }")

# Log format is <Group>;<ID>;<Start>;<End>;<Description>;<Info dict>.
with gzip.open(args.input, "r") as log:
    line_num = 0
    sdma_copies = 0

    for line in log:
        line_num += 1
        utf_line = line.decode("utf-8").rstrip()
        fields = utf_line.split(";")
        if len(fields) != 6:
            print(f"Input seems malformated. Suspect line number {line_num}:")
            print(f"{utf_line}")
            sys.exit(1)

        # Starting ticks
        group = fields[0]
        start_tick = int(fields[2])

        if group == "AQL":
            # track start/end tick for each task. The task ID is extracted
            # using the info dict and selecting the "Dispatch ID" value.
            end_tick = int(fields[3])
            slice_extra = ast.literal_eval(
                fields[5]
            )  # Converts string to dict
            task_id = int(slice_extra["Dispatch ID"])
            print(f"Extracted task id {task_id} -> {start_tick}, {end_tick}")
            task_windows[task_id] = (start_tick, end_tick)

            if task_id == args.start_at_aql_task:
                # Generally these are ordered, but just in case.
                if first_aql == 0 or start_tick < first_aql:
                    first_aql = start_tick

            # Keep track of tasks to skip
            if not task_id in tasks_of_interest:
                skip_tasks.append(task_id)

        if group == "SDMA":
            if sdma_copies == args.start_at_sdma_copy:
                first_sdma = start_tick

            print(f"Extract SDMA copy {sdma_copies} @ {start_tick}")

            sdma_copies += 1

        # Track counts. Note that the max value might not be the same as
        # the number of tracks. For example, there may be two AQL queues
        # numbered 5, 8 which would create 8 tracks. But Perfetto auto
        # hides unused tracks so using a lazy approach here.
        track_name = fields[1]

        if group == "AQL" and not track_name in aql_mappings:
            aql_mappings[track_name] = len(aql_mappings)
        if group == "SDMA" and not track_name in sdma_mappings:
            sdma_mappings[track_name] = len(sdma_mappings)
        if group == "WF" and not track_name in wf_mappings:
            wf_mappings[track_name] = len(wf_mappings)

# Create a "process ID" group for AQL and SDMA queues.
aqls = tgen.create_group("AQL Queues // id:")
sdmas = tgen.create_group("SDMA Engines // id:")

# Create a group for each CU. There is too much information under one group
# if all waves are grouped by GPU.
cu_groups = []
cu_dict = {}  # str ("CU#") -> int (cu_group index)

# Sort the keys so that CU0 shows before CU1, etc.
ip_tracks = []
ip_mappings = {}
for key in sorted(wf_mappings.keys()):
    cu = key.split("-")[0]
    ip = key.split("-")[1]
    if not cu in cu_dict:
        cu_dict[cu] = len(cu_groups)
        cu_groups.append(tgen.create_group(f"{cu} // id:"))

        idx = cu_dict[cu]
        ip_mappings[key] = len(ip_tracks)
        ip_tracks.append(
            cu_groups[idx].create_track(f"{ip}")
        )  # SIMD, UTC, etc.
    else:
        idx = cu_dict[cu]
        ip_mappings[key] = len(ip_tracks)
        ip_tracks.append(
            cu_groups[idx].create_track(f"{ip}")
        )  # SIMD, UTC, etc.


# Start the trace at task 0. Ideally this would start are first non-BLIT kernel
global_start_tick = 0
if first_aql != 0 and first_sdma != 0:
    global_start_tick = min(first_aql, first_sdma)
elif first_aql != 0:
    global_start_tick = first_aql
elif first_sdma != 0:
    global_start_tick = first_sdma

print(f"Starting trace at {global_start_tick}")
print(f"{skip_tasks = }")

sdma_tracks = []
for idx in range(len(sdma_mappings)):
    sdma_tracks.append(sdmas.create_track(f"SDMA {idx}"))

aql_tracks = []
for idx in range(len(aql_mappings)):
    aql_tracks.append(aqls.create_track(f"AQL Queue {idx}"))

with gzip.open(args.input, "r") as log:
    for line in log:
        utf_line = line.decode("utf-8").rstrip()
        fields = utf_line.split(";")

        group = fields[0]
        track_name = fields[1]
        start_tick = int(fields[2])
        end_tick = int(fields[3])
        slice_text = fields[4]
        slice_extra = ast.literal_eval(fields[5])  # Converts string to dict

        # Check if this is task of interest before processing WF group.
        if group == "WF":
            for task in skip_tasks:
                roi_start, roi_end = task_windows[task]
                if start_tick > roi_start and start_tick < roi_end:
                    continue

        # If we chose to start displaying after the first slice, skip any
        # slice before that time. If there is a slice that starts in the
        # past but ends after the starting display tick, make it partially
        # displayed.
        if end_tick <= global_start_tick:
            continue
        start_tick -= global_start_tick
        end_tick -= global_start_tick

        if start_tick < 0:
            start_tick = 0

        # Perfetto time is in nanoseconds while ticks are picoseconds.
        # Convert the times here. Note that if this makes start == end the
        # slice will be displayed as an "instant" in Perfetto's UI.
        start_tick = int(start_tick / 1000.0)
        end_tick = int(end_tick / 1000.0)

        if group == "AQL":
            track_id = aql_mappings[track_name]
            aql_tracks[track_id].open(start_tick, slice_text, slice_extra)
            aql_tracks[track_id].close(end_tick)
        elif group == "SDMA":
            track_id = sdma_mappings[track_name]
            sdma_tracks[track_id].open(start_tick, slice_text, slice_extra)
            sdma_tracks[track_id].close(end_tick)
        elif group == "WF":
            track_id = ip_mappings[track_name]
            ip_tracks[track_id].open(start_tick, slice_text, slice_extra)
            ip_tracks[track_id].close(end_tick)
            if track_name == "CU3-SIMD0 WF0":
                print(f"Start at {start_tick}")
                print(f"Close at {end_tick}")

tgen.flush()
