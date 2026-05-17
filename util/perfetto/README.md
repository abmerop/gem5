# Perfetto trace converter for gem5

This tool takes a dump of logged events from gem5 in a specific format and converts them to a Perfetto trace which can be viewed in [https://ui.perfetto.dev/](Perfetto's brower-based UI).
It is designed to be generic for any gem5 Named object (e.g., SimObjects).
A hierarchy of the gem5 topology is automatically converted into nested Perfetto tracks with the name in the gem5 hierarchy separated by dots as the track name.
This tool supports adding slices (a horizontal bar over time), instants (a point in time shown as an arrow), and counters (a line graph over time).
These can be added by adding logging calls to gem5's C++ code.
Logging is enabled in the simulation globally using the Perfetto debug flag so that config scripts do not need to be modified.
However, it is recommended to pause/unpause logging using some region of interest (e.g., for GPU model when a kernel ends/starts).
Examples are provided in the gem5 model.

## Installation

The official `perfetto` python module is required.

    ```bash
    python3 -m venv ~/.venv/perfetto
    pip install -r requirements.txt
    ```

## Usage

To start run some gem5 application with perfetto logging enabled.
Follow regular gem5 process to build gem5 and obtain any resources needed, then run.
For example:

    ```bash
    build/VEGA_X86/gem5.opt --debug-flags=Perfetto -d perfetto-test1 configs/example/gpufs/mi300.py --disk-image ~/gem5-resources/src/x86-ubuntu-gpu-ml/disk-image/x86-ubuntu-gpu-ml --kernel ~/gem5-resources/src/x86-ubuntu-gpu-ml/vmlinux-gpu-ml --app ~/gem5-resources/src/gpu/square/bin.default/square.default
    ```

Convert the trace using the python script in this directory.
Multiple gem5 outputs can be compared at once in a single trace file:

    ```bash
    ~/.venv/perfetto/bin/python3 ./util/perfetto/trace_convert.py perfetto-test1/perfetto-log.gz perfetto-test2/perfetto-log.gz -o compare-test1-test2.pftrace
    ```

Open the outputted file compare-test1-test2.pftrace in your browser of choice.
