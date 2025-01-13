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

#ifndef __INCLUDE_GEM5_AMDGPU_OPS_HH__
#define __INCLUDE_GEM5_AMDGPU_OPS_HH__

#include <cstdint>

namespace gem5
{

namespace AMDGPU
{

// This is required to be in any kernel which uses amdgpu pseudo insts. The
// asm macros must be in the same translation unit.
__device__ void setup_pseudo_insts() {
    // Using VOP1 encoding to implement region marker
    // 0 1 1 1 1 1 1 <8 bit vector dest> <8 bit opcode> <9 bit vector source>
    // Always read and write to v5 (write is ignored anyway)
    // This hardcodes opcode as 250 decimal. VOP1 has 108-255 available.
    // 0 1 1 1 1 1 1 <8 bit vector dest> <8 bit opcode> <9 bit vector source>
    // 0 1 1 1 1 1 1    0000 1010           1111 1010      1 0000 1010
    // 0111_1110_0000_1011_1111_0101_0000_1010
    //   7   e     1    5   f     5    0    a
    // 0x7e 15 f7 0a
    asm volatile("\n\
      .macro fake_mark_region\n\
        .byte 0x05, 0xf5, 0x0b, 0x7e\n\
      .endm");
}

// Mark a region of interest within an application. This is used only for
// adding tracks to Perfetto logs.
constexpr uint32_t region_start   = 0;
constexpr uint32_t region_end     = 1;
constexpr uint32_t region_instant = 2;

// Ideally the type of the first parameter would be such that a cast is not
// needed, but this works as is.
__device__ void gem5_mark_region(uint64_t addr, uint32_t start_end)
{
    uint32_t addrHi = (addr >> 32) & 0xFFFFFFFF;
    uint32_t addrLo = (addr >>  0) & 0xFFFFFFFF;
    asm volatile("\n\
        v_mov_b32 v5, %0\n\
        v_mov_b32 v6, %1\n\
        v_mov_b32 v7, %2\n\
        fake_mark_region"
        : // outputs
        : "v"(addrHi),
          "v"(addrLo),
          "v"(start_end)
        : "v5", "v6", "v7" // clobber list
    );
}

} // namespace AMDGPU
} // namespace gem5

#endif // __INCLUDE_GEM5_AMDGPU_OPS_HH__
