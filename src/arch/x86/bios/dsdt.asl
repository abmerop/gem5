/*
 * Copyright (c) 2026 Advanced Micro Devices, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Minimal Differentiated System Description Table (DSDT) for gem5's x86
 * platform.
 *
 * gem5 emits a hardware-reduced FADT that points at this DSDT. Its only
 * purpose is to give the guest's ACPICA a DSDT to load so that ACPI stays
 * *enabled*. Without any DSDT, ACPICA cannot build a namespace and disables
 * ACPI entirely, which in turn breaks kernel modules that hard-depend on ACPI
 * being available (most notably the WMI driver, which amdgpu depends on).
 *
 * The body is intentionally empty (just the predefined \_SB scope). No power
 * management, devices, or methods are described because gem5 models a
 * hardware-reduced platform.
 *
 * This is the human-readable source. The build embeds the compiled binary
 * (dsdt.aml) checked in alongside it; iasl is NOT required to build gem5.
 * To regenerate dsdt.aml after editing this file:
 *
 *     iasl dsdt.asl     # produces dsdt.aml
 *
 * (Requires the acpica-tools / iasl package. Only needed by developers
 * editing this ASL, never by a normal gem5 build.)
 */

DefinitionBlock ("dsdt.aml", "DSDT", 2, "GEM5  ", "GEM5DSDT", 0x00000001)
{
    Scope (\_SB)
    {
    }
}
