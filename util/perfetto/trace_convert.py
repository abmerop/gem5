#!/usr/bin/env python3

import argparse
import ast
import gzip
import os
import sys
import uuid

from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import (
    ProcessDescriptor,
    ThreadDescriptor,
    TrackDescriptor,
    TrackEvent,
)
from perfetto.trace_builder.proto_builder import TraceProtoBuilder


def make_process(builder: TraceProtoBuilder, pid: int, process_name: str):
    """Register a top-level process track in the Perfetto trace.

    All tracks created by make_track or make_counter_track should be parented
    (directly or transitively) to a process track. Returns the UUID assigned
    to the new process track, which callers should pass as parent_uuid to
    child tracks.
    """
    new_uuid = uuid.uuid4().int & ((1 << 63) - 1)
    packet = builder.add_packet()
    packet.timestamp = 0
    packet.track_descriptor.uuid = new_uuid
    packet.track_descriptor.process.pid = pid
    packet.track_descriptor.process.process_name = process_name

    return new_uuid


def make_track(builder: TraceProtoBuilder, parent_uuid: int, name: str):
    """Create a named child track nested under an existing track.

    Tracks created here can hold slice events (make_slice) and can themselves
    be parents of further child tracks, building the hierarchy shown in the
    Perfetto UI. Children are ordered lexicographically within their parent.
    Returns the UUID of the new track.
    """
    new_uuid = uuid.uuid4().int & ((1 << 63) - 1)
    packet = builder.add_packet()
    packet.track_descriptor.uuid = new_uuid
    packet.track_descriptor.parent_uuid = parent_uuid
    packet.track_descriptor.name = name
    packet.track_descriptor.child_ordering = TrackDescriptor.LEXICOGRAPHIC

    return new_uuid


def make_counter_track(
    builder: TraceProtoBuilder, parent_uuid: int, name: str, units: str = ""
):
    """Create a counter track nested under an existing track.

    Counter tracks display a continuous numeric value over time (e.g. bytes
    used, occupancy) rather than discrete slices. Events on this track should
    be added with make_counter. The optional units string is shown in the
    Perfetto UI alongside the counter values. Returns the UUID of the new
    counter track.
    """
    new_uuid = uuid.uuid4().int & ((1 << 63) - 1)
    packet = builder.add_packet()
    packet.track_descriptor.uuid = new_uuid
    packet.track_descriptor.parent_uuid = parent_uuid
    packet.track_descriptor.name = name
    packet.track_descriptor.counter.SetInParent()
    if units != "":
        packet.track_descriptor.counter.unit_name = " " + units

    return new_uuid


def make_slice(
    builder: TraceProtoBuilder,
    track_uuid: int,
    start: int,
    finish: int,
    text: str,
    annotations=None,
):
    """Emit a slice (time-range) event on an existing track.

    If start == finish the event is also emitted as an instant marker so it
    remains visible when zoomed out. The text label is shown on the slice in
    the Perfetto UI.

    Optional annotations are attached as debug key/value pairs visible in the
    Perfetto event detail panel. The annotations dict may contain bool, int,
    float, or str values; each is stored in the appropriate protobuf field.
    """
    if start == finish:
        packet = builder.add_packet()
        packet.timestamp = start
        packet.track_event.type = TrackEvent.TYPE_INSTANT
        packet.track_event.track_uuid = track_uuid
        packet.track_event.name = text
        packet.trusted_packet_sequence_id = 1001

    packet = builder.add_packet()
    packet.timestamp = start
    packet.track_event.type = TrackEvent.TYPE_SLICE_BEGIN
    packet.track_event.track_uuid = track_uuid
    packet.track_event.name = text
    packet.trusted_packet_sequence_id = 1001

    packet = builder.add_packet()
    packet.timestamp = finish
    packet.track_event.type = TrackEvent.TYPE_SLICE_END
    packet.track_event.track_uuid = track_uuid
    packet.track_event.name = text
    packet.trusted_packet_sequence_id = 1001

    if annotations is not None:
        for key, value in annotations.items():
            annotation = packet.track_event.debug_annotations.add()
            annotation.name = key

            # Set the appropriate value field based on type
            if isinstance(value, bool):
                annotation.bool_value = value
            elif isinstance(value, int):
                annotation.int_value = value
            elif isinstance(value, float):
                annotation.double_value = value
            elif isinstance(value, str):
                annotation.string_value = value


def make_counter(
    builder: TraceProtoBuilder, track_uuid: int, start: int, value: int
):
    """Emit a counter sample on an existing counter track.

    Records the numeric value at the given timestamp. The Perfetto UI
    interpolates linearly between successive counter samples to draw a
    continuous graph. The track must have been created with make_counter_track.
    """
    packet = builder.add_packet()
    packet.timestamp = start
    packet.track_event.type = TrackEvent.TYPE_COUNTER
    packet.track_event.track_uuid = track_uuid
    packet.track_event.counter_value = value
    packet.trusted_packet_sequence_id = 1001


if __name__ == "__main__":
    # Input files are gzip-compressed text files produced by gem5's Perfetto
    # debug flag. Each line encodes one event in semicolon-delimited fields:
    #
    #   <hierarchy>;<name>;<track_type>;<start>;<end>;<slice_text>;<annotations>
    #
    #   hierarchy   - dot-separated gem5 object path, e.g. "board.gpus.shader".
    #                 Leading "board." and "system." prefixes are stripped so
    #                 that the top-level gem5 containers do not appear as extra
    #                 nesting levels in the UI.
    #   name        - label used for the leaf track (replaces the last hierarchy
    #                 component in the Perfetto track tree).
    #   track_type  - "slices" for time-range events, "counter" for numeric
    #                 samples.
    #   start       - event start timestamp in gem5 ticks (also used as the
    #                 sample timestamp for counter events).
    #   end         - event end timestamp in gem5 ticks (the counter value for
    #                 counter events).
    #   slice_text  - label shown on the slice in the UI; for counter tracks
    #                 this field holds the units string for the counter.
    #   annotations - optional JSON object whose key/value pairs are attached
    #                 as debug annotations visible in the Perfetto detail panel.
    #
    # The converter produces one Perfetto process per input file (named after
    # the file). Within each process the hierarchy components become nested
    # tracks, built lazily as new paths are encountered so that the file can be
    # streamed without loading it entirely into memory.

    parser = argparse.ArgumentParser(
        description="Convert compressed gem5 traces to Perfetto format"
    )
    parser.add_argument(
        "input", nargs="+", help="Compressed gem5 trace files (.gz)"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="gem5_trace.pftrace",
        help="Output Perfetto trace file (default: gem5_trace.pftrace)",
    )
    args = parser.parse_args()

    # Verify all input files exist before processing any of them.
    for input_file in args.input:
        if not os.path.exists(input_file):
            print(
                f"Error: input file '{input_file}' does not exist",
                file=sys.stderr,
            )
            sys.exit(1)

    builder = TraceProtoBuilder()
    pid_counter = 0

    for input_file in args.input:
        # Each input file becomes a separate top-level process in the Perfetto
        # UI, named after the file's basename. This makes it easy to compare
        # multiple simulation runs side-by-side in the same trace view.
        process_name = os.path.basename(input_file)
        file_process_uuid = make_process(builder, pid_counter, process_name)
        pid_counter += 1

        # Maps a dot-joined hierarchy path to its track UUID for this file.
        # Tracks are created on first use and reused for all subsequent events
        # that share the same path, keeping the tree structure consistent.
        track_uuids = {}

        with gzip.open(input_file, "rt") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                parts = line.split(";")
                if len(parts) < 7:
                    continue

                (
                    hierarchy,
                    name,
                    track_type,
                    start,
                    end,
                    slice_text,
                    annotations_str,
                ) = (
                    parts[0],
                    parts[1],
                    parts[2],
                    parts[3],
                    parts[4],
                    parts[5],
                    parts[6],
                )

                start = int(start)
                end = int(end)

                # Annotations are an optional str->str dict in a string.
                annotations = None
                if annotations_str.strip():
                    annotations = ast.literal_eval(annotations_str)

                # Strip well-known top-level gem5 prefixes so the UI tree
                # starts at a meaningful component rather than the root object.
                if hierarchy.startswith("board."):
                    hierarchy = hierarchy[len("board.") :]
                if hierarchy.startswith("system."):
                    hierarchy = hierarchy[len("system.") :]
                components = hierarchy.split(".")

                # Walk each level of the hierarchy, creating a track the first
                # time a given path is seen. Intermediate levels use the
                # component name from the hierarchy string; the leaf level uses
                # <name> from the event record so it can be labelled
                # independently of the object path. Counter tracks are created
                # for the leaf of counter events; all other levels use regular
                # tracks regardless of event type.
                last = len(components) - 1
                for i in range(len(components)):
                    path = ".".join(components[: i + 1])
                    if path not in track_uuids:
                        parent_uuid = (
                            file_process_uuid
                            if i == 0
                            else track_uuids[".".join(components[:i])]
                        )
                        track_name = name if i == last else components[i]
                        track_name = (
                            components[i] if name == "" else track_name
                        )
                        if track_type == "counter" and i == last:
                            track_uuids[path] = make_counter_track(
                                builder, parent_uuid, track_name, slice_text
                            )
                        else:
                            track_uuids[path] = make_track(
                                builder, parent_uuid, track_name
                            )

                # Emit the event on the leaf track.
                track_uuid = track_uuids[hierarchy]

                if track_type == "counter":
                    make_counter(builder, track_uuid, start, end)
                else:
                    make_slice(
                        builder,
                        track_uuid,
                        start,
                        end,
                        slice_text,
                        annotations,
                    )

    with open(args.output, "wb") as f:
        f.write(builder.serialize())
