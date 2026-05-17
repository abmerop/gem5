/*
 * Copyright (c) 2026 Advanced Micro Devices, Inc.
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

#include "base/perfetto.hh"

#include <sstream>

#include "debug/Perfetto.hh"
#include "sim/sim_exit.hh"

namespace gem5
{

// Singleton instance of the PerfettoLogger
PerfettoLogger perfettoLogger;

void
PerfettoLogger::init()
{
    perfettoLog = simout.create("perfetto-log.gz");

    registerExitCallback([this]() { exitCallback(); });
}

void
PerfettoLogger::exitCallback()
{
    simout.close(perfettoLog);
}

void
PerfettoLogger::writePerfettoLog(const std::string &line,
                                 const PerfettoAnnotation &annotations)
{
    if (!debug::Perfetto || !enabled) {
        return;
    }

    // Automatically initialize the logger if it hasn't been already. This
    // allows users to use the logger without having to worry about what will
    // call initialization.
    if (!perfettoLog) {
        init();
    }

    std::ostream *os(perfettoLog->stream());
    os->write(line.c_str(), line.length());

    // This will be read in python using ast.literal_eval. This function will
    // convert it to a python dict to pass to the perfetto tool. It is more
    // forgiving that json parsers so things like the ending stray comma are
    // not a problem.
    std::stringstream fmt;
    fmt << "{";
    if (!annotations.empty()) {
        for (const auto &[key, value] : annotations) {
            fmt << "\"" << key << "\": \"" << value << "\", ";
        }
    }
    fmt << "}";

    os->write(fmt.str().c_str(), fmt.str().length());

    os->write("\n", 1);
}

} // namespace gem5
