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

#ifndef __BASE_PERFETTO_HH__
#define __BASE_PERFETTO_HH__

#include <unordered_map>

#include "base/named.hh"
#include "base/output.hh"
#include "base/types.hh"
#include "sim/cur_tick.hh"

namespace gem5
{

using PerfettoAnnotation = std::unordered_map<std::string, std::string>;

// Helpers with all inputs
static inline std::string
perfettoSlice(std::string heirarchy, std::string nice_name, Tick start,
              Tick end, std::string slice_text)
{
    // Format: hierarchy, track name, track type, start, end, slice text, debug
    // annotations (added later)
    return heirarchy + ";" + nice_name + ";slices;" + std::to_string(start) +
           ";" + std::to_string(end) + ";" + slice_text + ";";
}

static inline std::string
perfettoCounter(std::string heirarchy, std::string nice_name, Tick ts,
                uint64_t value, std::string slice_text)
{
    // Format: hierarchy, track name, track type, start, end, slice text, debug
    // annotations (added later)
    return heirarchy + ";" + nice_name + ";counter;" + std::to_string(ts) +
           ";" + std::to_string(value) + ";" + slice_text + ";";
}

static inline std::string
perfettoSlice(Named *named, Tick start, Tick end, std::string slice_text)
{
    return perfettoSlice(named->name(), "", start, end, slice_text);
}

static inline std::string
perfettoCounter(Named *named, Tick ts, uint64_t value, std::string slice_text)
{
    return perfettoCounter(named->name(), "", ts, value, slice_text);
}

static inline std::string
perfettoInstant(std::string heirarchy, std::string nice_name, Tick ts,
                std::string slice_text)
{
    // Format: hierarchy, track name, track type, start, end, slice text, debug
    // annotations (added later)
    return heirarchy + ";" + nice_name + ";slices;" + std::to_string(ts) +
           ";" + std::to_string(ts) + ";" + slice_text + ";";
}

// Main perfetto logger singleton.
class PerfettoLogger
{
  public:
    PerfettoLogger() = default;

    // Create perfetto-log.gz for the current simulation in the simout
    // directory and set logging as enabled. The caller should check that
    // logging is requested before calling this function.
    void init();

    // Pause/unpause can be controlled by some top-level SimObject to enable
    // or disable logging before/after region of interest.
    void
    pause()
    {
        enabled = false;
    }
    void
    unpause()
    {
        enabled = true;
    }

    // Write a line to the perfetto log if enabled. Annotations are optional.
    // If provided they are displayed in the perfetto UI in the "debug" area.
    // Ignored if logging is not enabled.
    void writePerfettoLog(const std::string &line,
                          const PerfettoAnnotation &annotations);

    // A global sample period if not overriden by individual counter. This is
    // used to control how often the counter logs changes in value. More
    // frequent logging will cause larger traces which may be unmanageable.
    // Value must be greater than 0. Default is 100us.
    Tick samplePeriod = 100000;

  private:
    bool enabled = false;
    OutputStream *perfettoLog = nullptr;

    void exitCallback();
};

extern PerfettoLogger perfettoLogger;

// Helper class for counter. Just define once and uses operator overloads to
// log values. If the counter is not initialized with a Named object, it will
// be a no-op and not log anything. Perfetto allows for integer and floating
// point counters, so create a base class template.
template <typename CType> class BasePerfettoCounter
{
  public:
    BasePerfettoCounter() : _named(nullptr) {}

    BasePerfettoCounter(Named *named, std::string units_displayed = "")
        : _named(named),
          units(units_displayed),
          lastLogTick(-perfettoLogger.samplePeriod),
          samplePeriod(perfettoLogger.samplePeriod)
    {}

    void
    setPeriod(Tick period)
    {
        samplePeriod = period;
    }

    void
    log(Tick ts, CType value)
    {
        // If not named (not enough information to log) or sample period is 0
        // (disabled), do nothing.
        if (!_named || !samplePeriod) {
            return;
        }

        sampleValue += value;

        // Honor the logging frequency of this counter.
        if (curTick() - lastLogTick < samplePeriod) {
            return;
        }

        // Log the first value (happens due to lastLogTick being -samplePeriod)
        CType log_value = value;
        if (lastLogTick >= 0) {
            log_value = sampleValue;
        }

        perfettoLogger.writePerfettoLog(
            perfettoCounter(_named->name(), "", ts, log_value, units), {});

        lastLogTick = curTick();
        sampleValue = CType{}; // reset sample value after logging
    }

    CType
    operator=(CType value)
    {
        sampleValue = CType{};
        log(curTick(), value);
        return value;
    }

    CType
    operator+=(CType value)
    {
        log(curTick(), value);
        return sampleValue;
    }

    // Postfix
    CType
    operator++(int)
    {
        log(curTick(), CType{1});
        return sampleValue;
    }

    // Prefix
    CType
    operator++()
    {
        log(curTick(), CType{1});
        return sampleValue;
    }

  private:
    Named *_named = nullptr;
    std::string units = "";
    int64_t lastLogTick = 0;
    CType sampleValue{};
    Tick samplePeriod = 0;
};

// Define a convenient type for the common uint64_t counter case.
using PerfettoCounter = BasePerfettoCounter<uint64_t>;

} // namespace gem5

#endif // __BASE_PERFETTO_HH__
