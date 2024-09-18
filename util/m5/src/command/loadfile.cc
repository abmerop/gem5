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

#include <cstring>
#include <iostream>

#include "args.hh"
#include "command.hh"
#include "dispatch_table.hh"

namespace
{

int
load_file(const DispatchTable &dt, std::ostream &os,
          const std::string &host_filename)
{
    char buf[256 * 1024];

    // Touch all buffer pages to ensure they are mapped in the
    // page table. This is required in the case of X86_FS, where
    // Linux does demand paging.
    std::memset(buf, 0, sizeof(buf));

    int len;
    int offset = 0;
    while ((len = (*dt.m5_load_file)(
             buf, sizeof(buf), offset, host_filename.c_str())) > 0) {
        os.write(buf, len);
        os.flush();
        if (!os) {
            std::cerr << "Failed to write file" << std::endl;
            exit(2);
        }
        offset += len;
    }

    return offset;
}

bool
do_load_file(const DispatchTable &dt, Args &args)
{
    if (args.size() != 1)
        return false;

    const std::string &host_filename = args.pop();

    load_file(dt, std::cout, host_filename);

    return true;
}

Command load_file_cmd = {
    "loadfile", 1, 1, do_load_file, "\n"
        "        read a file from the host and write it to stdout" };

} // anonymous namespace
