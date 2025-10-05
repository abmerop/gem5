/*
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "dev/amdgpu/xgmi_hive.hh"

#include "debug/XGMI.hh"
#include "dev/amdgpu/amdgpu_device.hh"

namespace gem5
{

XGMIHive::XGMIHive(const XGMIHiveParams &p) : SimObject(p), hiveId(p.hive_id)
{}

void
XGMIHive::init()
{
    // Running total size
    Addr current_offset = 0;

    for (auto &[gpuId, frameSize] : gpuFrameSize) {
        gpuFrameOffset.insert(
            {gpuId, AddrRange(current_offset, frameSize.size())});
        DPRINTF(XGMI,
                "GPU device %d in xGMI hive %d frame offset %#lx size %#lx\n",
                gpuId, hiveId, current_offset, frameSize.size());
        current_offset += frameSize.size();
    }
}

void
XGMIHive::addNode(AMDGPUDevice *device)
{
    DPRINTF(XGMI, "Adding GPU device %d to xGMI hive %d memory size %#lx\n",
            device->getGpuId(), hiveId, device->getVRAMSize());

    gpuFrameSize.insert(
        {device->getGpuId(), AddrRange(0, device->getVRAMSize())});
}

void
XGMIHive::updateAddressRange(int gpu_id, const AddrRange &pcieBar0Range)
{
    // Frame offset is the sum of all lower GPU ID devices' VRAM sizes.
    gpuAddressRange[gpu_id] = pcieBar0Range;

    DPRINTF(XGMI,
            "GPU device %d in xGMI hive %d PCIe BAR0 range %#lx - %#lx\n",
            gpu_id, hiveId, pcieBar0Range.start(), pcieBar0Range.end());
}

bool
XGMIHive::isXgmiAddress(Addr addr) const
{
    return false;
}

Addr
XGMIHive::getXgmiBaseAddr(int gpuId) const
{
    panic_if(gpuFrameOffset.count(gpuId) == 0,
             "XGMI Hive %d has no frame offset for GPU ID %d\n", hiveId,
             gpuId);
    return gpuFrameOffset.at(gpuId).start();
}

Addr
XGMIHive::getFrameSize(int gpuId) const
{
    panic_if(gpuFrameSize.count(gpuId) == 0,
             "XGMI Hive %d has no frame size for GPU ID %d\n", hiveId, gpuId);
    return gpuFrameSize.at(gpuId).size();
}

} // namespace gem5
