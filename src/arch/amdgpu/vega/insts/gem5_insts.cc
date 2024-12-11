/*
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
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

#include "arch/amdgpu/vega/insts/instructions.hh"
#include "debug/PseudoInst.hh"
#include "dev/amdgpu/amdgpu_device.hh"
#include "gpu-compute/gpu_command_processor.hh"
#include "mem/abstract_mem.hh"

namespace gem5
{

namespace VegaISA
{

// --- Inst_VOP1__S_GEM5_MARK_REGION class methods ---

Inst_VOP1__S_GEM5_MARK_REGION::Inst_VOP1__S_GEM5_MARK_REGION(InFmt_VOP1 *iFmt)
    : Inst_VOP1(iFmt, "s_vop1_gem5_mark_region")
{
    setFlag(ALU);
} // Inst_VOP1__S_GEM5_MARK_REGION

Inst_VOP1__S_GEM5_MARK_REGION::~Inst_VOP1__S_GEM5_MARK_REGION()
{
} // ~Inst_VOP1__S_GEM5_MARK_REGION

void
Inst_VOP1__S_GEM5_MARK_REGION::execute(GPUDynInstPtr gpuDynInst)
{
    Wavefront *wf = gpuDynInst->wavefront();
    ConstVecOperandU32 srcV5(gpuDynInst, 5 + 0x100);
    ConstVecOperandU32 srcV6(gpuDynInst, 6 + 0x100);
    ConstVecOperandU32 srcV7(gpuDynInst, 7 + 0x100);

    srcV5.readSrc();
    srcV6.readSrc();
    srcV7.readSrc();

    auto& cp = gpuDynInst->computeUnit()->shader->gpuCmdProc;
    assert(wf->execMask(0));

    uint64_t vaddr;
    uint32_t flags = srcV7[0];

    vaddr  = (static_cast<uint64_t>(srcV5[0])) << 32;
    vaddr |= (static_cast<uint64_t>(srcV6[0]));

    // Get the physical address of our region string
    auto tgen = cp.translate(vaddr, 64);
    auto addr_range = *(tgen->begin());
    Addr paddr = addr_range.paddr;
    DPRINTF(PseudoInst, "Mark region translated %#lx -> %#lx\n", vaddr, paddr);

    // The UserTranslationGen intentionally puts addresses in the aliased
    // MMHUB aperture. Subtract the base of that to get a framebuffer address
    // we can access functionally.
    // NB: Might be able to check if it is in the MMHUB, we know it's GPU addr,
    // otherwise it's a host address if it is not a fault. That could make this
    // instruction a bit flexible to use either CPU or GPU addresses.
    auto& vm = cp.getGPUDevice()->getVM();
    paddr -= vm.getMMHUBBase();

    DPRINTF(PseudoInst, "Mark region translated %#lx -> %#lx\n", vaddr, paddr);

    // Region name size fixed to 64 bytes
    RequestPtr request = std::make_shared<Request>(paddr, 64, 0,
                                                   cp.vramRequestorId());
    auto read_pkt = new Packet(request, MemCmd::ReadReq);
    read_pkt->allocate();
    cp.system()->getDeviceMemory(read_pkt)->access(read_pkt);

    char region_name[64];
    std::memcpy(region_name, read_pkt->getPtr<char>(), 64);

    DPRINTF(PseudoInst, "Read region name as %s\n", region_name);

    std::string track_test(region_name);
    wf->markRegion(track_test, flags);
} // execute

} // namespace VegaISA
} // namespace gem5
