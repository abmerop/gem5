# Copyright (c) 2024 Advanced Micro Devices, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived from this
# software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Script to run a full system GPU simulation.

Usage:
------
```
scons build/VEGA_X86/gem5.opt
./build/VEGA_X86/gem5.opt
    configs/example/gem5_library/x86-mi300x-gpu.py
    --image <disk image>
    --kernel <kernel>
    --app <gpu application>
```

Example:
--------
```
./build/VEGA_X86/gem5.opt
    configs/example/gem5_library/x86-mix300x-gpu.py
    --image ./gem5-resources/src/x86-ubuntu-gpu-ml/disk-image/x86-ubuntu-gpu-ml
    --kernel ./gem5-resources/src/x86-ubuntu-gpu-ml/vmlinux-gpu-ml
    --app ./gem5-resources/src/gpu/square/bin.default/square.default
```
"""

import argparse

import m5

from gem5.coherence_protocol import CoherenceProtocol
from gem5.components.devices.gpus.amdgpu import MI300X
from gem5.components.memory import HBM2Stack
from gem5.components.memory.single_channel import SingleChannelDDR4_2400
from gem5.components.processors.cpu_types import CPUTypes
from gem5.components.processors.simple_processor import SimpleProcessor
from gem5.components.processors.simple_switchable_processor import (
    SimpleSwitchableProcessor,
)
from gem5.isas import ISA
from gem5.prebuilt.viper.board import ViperBoard
from gem5.prebuilt.viper.cpu_cache_hierarchy import ViperCPUCacheHierarchy
from gem5.resources.resource import (
    DiskImageResource,
    FileResource,
)
from gem5.simulate.simulator import (
    ExitEvent,
    Simulator,
)
from gem5.utils.requires import requires

requires(
    coherence_protocol_required=CoherenceProtocol.GPU_VIPER,
)

# Kernel, disk, and applications are obtained locally.
parser = argparse.ArgumentParser()

parser.add_argument(
    "--image",
    type=str,
    required=True,
    help="Full path to the gem5-resources x86-ubuntu-gpu-ml disk-image.",
)

parser.add_argument(
    "--kernel",
    type=str,
    required=True,
    help="Full path to the gem5-resources vmlinux-gpu-ml kernel.",
)

parser.add_argument(
    "--app",
    type=str,
    required=True,
    help="Path to GPU application, python script, or bash script to run",
)

parser.add_argument(
    "--opts",
    type=str,
    default="",
    help="Additional arguments for the GPU application",
)

parser.add_argument(
    "--kvm-perf",
    default=False,
    action="store_true",
    help="Use KVM perf counters to give accurate GPU insts/cycles with KVM",
)

parser.add_argument(
    "--switch-cpu-every-kernel",
    default=False,
    action="store_true",
    help="Switch to atomic CPU at kernel start and KVM at kernel end",
)

args = parser.parse_args()

memory = SingleChannelDDR4_2400(size="8GiB")

# Note: Only KVM is extensively tested and supported.
processor = SimpleSwitchableProcessor(
    starting_core_type=CPUTypes.KVM,
    switch_core_type=CPUTypes.ATOMIC,
    isa=ISA.X86,
    num_cores=1,
)

for proc in processor.start:
    proc.core.usePerf = args.kvm_perf

# The GPU must be created first so we can assign CPU-side DMA ports to the
# CPU cache hierarchy.
gpu0 = MI300X(gpu_memory=HBM2Stack(size="16GiB"))

board = ViperBoard(
    clk_freq="3GHz",
    processor=processor,
    memory=memory,
    cache_hierarchy=ViperCPUCacheHierarchy(),
    gpus=[gpu0],
)


# Example of using a local disk image resource
disk = DiskImageResource(local_path=args.image, root_partition="1")
kernel = FileResource(local_path=args.kernel)

board.set_kernel_disk_workload(
    kernel=kernel,
    disk_image=disk,
    readfile_contents=board.make_gpu_app(gpu0, args.app, args.opts),
)


def handle_kernel_start():
    switched = False
    while True:
        print(f"Resetting stats because kernel started")
        m5.stats.reset()
        if not switched or args.switch_cpu_every_kernel:
            simulator.switch_processor()
            switched = True
        yield False


def handle_kernel_end():
    while True:
        print(f"Dump stats because kernel completed")
        m5.stats.dump()
        if args.switch_cpu_every_kernel:
            simulator.switch_processor()
        yield False


simulator = Simulator(
    board=board,
    on_exit_event={
        ExitEvent.KERNEL_START: handle_kernel_start(),
        ExitEvent.KERNEL_END: handle_kernel_end(),
        ExitEvent.BLIT_END: handle_kernel_end(),
    },
)


simulator.run()
