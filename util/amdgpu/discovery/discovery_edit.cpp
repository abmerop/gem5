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

// discovery_edit.cpp
// Patch the base address(es) of one IP instance in an AMDGPU discovery binary
// blob, then recompute all affected checksums so the driver accepts the
// modified blob.
//
// Usage:
//   discovery_edit <input_blob> <output_blob> <hw_id> [instance=<N>] <addr0>
//   [addr1 ...]
//
// <hw_id>      : decimal or 0x-prefixed hex hardware ID (e.g. 11 or 0xb for
// GC) instance=<N> : optional, selects instance number when multiple IPs share
// a hw_id
//                defaults to 0 if omitted
// <addrN>      : new base addresses, decimal or 0x-prefixed hex
//                must match the existing num_base_address count exactly
//
// Checksum rules (from amdgpu_discovery_init):
//   table_info[IP_DISCOVERY].checksum = bytesum(blob[ip_disc_offset ..
//   +ihdr->size]) binary_header.binary_checksum     =
//   bytesum(blob[offset_after_checksum_field .. +bhdr->binary_size])
//
// The ip_discovery_header.size covers the entire IP discovery table (all dies
// + IP entries), so patching any base address within that region invalidates
// both the table and binary checksums.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Struct definitions (matches discovery.h, #pragma pack(1), little-endian)
// ---------------------------------------------------------------------------

#pragma pack(1)

#define BINARY_SIGNATURE 0x28211407u
#define DISCOVERY_TABLE_SIGNATURE 0x53445049u
#define TOTAL_TABLES 6

enum table_idx
{
    IP_DISCOVERY = 0,
    GC,
    HARVEST_INFO,
    VCN_INFO,
    MALL_INFO,
    NPS_INFO,
};

struct table_info
{
    uint16_t offset;
    uint16_t checksum;
    uint16_t size;
    uint16_t padding;
};

struct binary_header
{
    uint32_t binary_signature;
    uint16_t version_major;
    uint16_t version_minor;
    uint16_t binary_checksum;
    uint16_t binary_size;
    table_info table_list[TOTAL_TABLES];
};

struct die_info
{
    uint16_t die_id;
    uint16_t die_offset;
};

struct ip_discovery_header
{
    uint32_t signature;
    uint16_t version;
    uint16_t size;
    uint32_t id;
    uint16_t num_dies;
    die_info dies[16];
    union
    {
        uint16_t padding[1];
        struct
        {
            uint8_t base_addr_64_bit : 1;
            uint8_t reserved : 7;
            uint8_t reserved2;
        };
    };
};

struct die_header
{
    uint16_t die_id;
    uint16_t num_ips;
};

struct ip
{
    uint16_t hw_id;
    uint8_t number_instance;
    uint8_t num_base_address;
    uint8_t major;
    uint8_t minor;
    uint8_t revision;
    uint8_t harvest : 4;
    uint8_t reserved : 4;
};

struct ip_v3
{
    uint16_t hw_id;
    uint8_t instance_number;
    uint8_t num_base_address;
    uint8_t major;
    uint8_t minor;
    uint8_t revision;
    uint8_t sub_revision : 4;
    uint8_t variant : 4;
};

struct ip_v4
{
    uint16_t hw_id;
    uint8_t instance_number;
    uint8_t num_base_address;
    uint8_t major;
    uint8_t minor;
    uint8_t revision;
    uint8_t sub_revision : 4;
    uint8_t variant : 4;
};

#pragma pack()

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static uint16_t
bytesum(const uint8_t *data, uint32_t size)
{
    uint16_t s = 0;
    for (uint32_t i = 0; i < size; i++) {
        s += data[i];
    }
    return s;
}

template <typename T>
static T *
blob_at(std::vector<uint8_t> &blob, size_t offset)
{
    if (offset + sizeof(T) > blob.size()) {
        return nullptr;
    }
    return reinterpret_cast<T *>(blob.data() + offset);
}

static bool
parse_uint64(const char *s, uint64_t &out)
{
    char *end;
    out = strtoull(s, &end, 0);
    return end != s && *end == '\0';
}

// ---------------------------------------------------------------------------
// Checksum update
// ---------------------------------------------------------------------------

// Recompute table_info[IP_DISCOVERY].checksum and
// binary_header.binary_checksum. All other table checksums are unaffected
// because we only touch IP discovery data.
static void
recompute_checksums(std::vector<uint8_t> &blob)
{
    auto *bhdr = blob_at<binary_header>(blob, 0);

    // --- ip_discovery table checksum ---
    // Covers: blob[ip_off .. ip_off + ihdr->size)
    uint16_t ip_off = bhdr->table_list[IP_DISCOVERY].offset;
    if (ip_off) {
        auto *ihdr = blob_at<ip_discovery_header>(blob, ip_off);
        if (ihdr && ip_off + ihdr->size <= blob.size()) {
            bhdr->table_list[IP_DISCOVERY].checksum =
                bytesum(blob.data() + ip_off, ihdr->size);
        }
    }

    // --- binary_header checksum ---
    // Covers: blob[start .. bhdr->binary_size)
    // where start = offsetof(binary_checksum) + sizeof(binary_checksum)
    //             = 8 + 2 = 10
    constexpr size_t chk_field_end = offsetof(binary_header, binary_checksum) +
                                     sizeof(bhdr->binary_checksum); // = 10
    uint16_t bin_size = bhdr->binary_size;
    if (bin_size > blob.size()) {
        bin_size = static_cast<uint16_t>(blob.size());
    }
    if (bin_size > chk_field_end) {
        bhdr->binary_checksum =
            bytesum(blob.data() + chk_field_end,
                    bin_size - static_cast<uint16_t>(chk_field_end));
    }
}

// ---------------------------------------------------------------------------
// IP search + patch
// ---------------------------------------------------------------------------

struct PatchTarget
{
    size_t addr_offset; // byte offset of base_address[0] in blob
    uint8_t num_addr;
    bool addr64; // true if addresses are 64-bit (ip_discovery v4 +
                 // base_addr_64_bit)
};

// Walk all dies/IPs, find the entry matching hw_id + instance, return its
// address array location.
static bool
find_ip(std::vector<uint8_t> &blob, uint16_t target_hw_id,
        uint8_t target_instance, PatchTarget &out)
{
    auto *bhdr = blob_at<binary_header>(blob, 0);
    if (!bhdr) {
        return false;
    }

    uint16_t ip_off = bhdr->table_list[IP_DISCOVERY].offset;
    if (!ip_off) {
        fprintf(stderr, "Error: no IP_DISCOVERY table in blob\n");
        return false;
    }

    auto *ihdr = blob_at<ip_discovery_header>(blob, ip_off);
    if (!ihdr) {
        fprintf(stderr, "Error: ip_discovery_header out of bounds\n");
        return false;
    }
    if (ihdr->signature != DISCOVERY_TABLE_SIGNATURE) {
        fprintf(stderr, "Error: bad ip_discovery_header signature 0x%08X\n",
                ihdr->signature);
        return false;
    }

    bool addr64 = (ihdr->version == 4 && ihdr->base_addr_64_bit);
    uint16_t num_dies = ihdr->num_dies > 16 ? 16 : ihdr->num_dies;

    for (uint16_t d = 0; d < num_dies; d++) {
        uint16_t die_off = ihdr->dies[d].die_offset;
        auto *dhdr = blob_at<die_header>(blob, die_off);
        if (!dhdr) {
            continue;
        }

        uint32_t cur = die_off + sizeof(die_header);

        for (uint16_t i = 0; i < dhdr->num_ips; i++) {
            if (cur >= blob.size()) {
                break;
            }

            uint16_t hw_id;
            uint8_t instance_number;
            uint8_t num_base_address;
            size_t fixed_size;

            if (ihdr->version <= 2) {
                auto *e = reinterpret_cast<ip *>(blob.data() + cur);
                hw_id = e->hw_id;
                instance_number = e->number_instance;
                num_base_address = e->num_base_address;
                fixed_size = sizeof(ip);
            } else if (ihdr->version == 3) {
                auto *e = reinterpret_cast<ip_v3 *>(blob.data() + cur);
                hw_id = e->hw_id;
                instance_number = e->instance_number;
                num_base_address = e->num_base_address;
                fixed_size = sizeof(ip_v3);
            } else {
                auto *e = reinterpret_cast<ip_v4 *>(blob.data() + cur);
                hw_id = e->hw_id;
                instance_number = e->instance_number;
                num_base_address = e->num_base_address;
                fixed_size = sizeof(ip_v4);
            }

            size_t addr_bytes =
                addr64 ? (size_t)num_base_address * sizeof(uint64_t)
                       : (size_t)num_base_address * sizeof(uint32_t);

            if (hw_id == target_hw_id && instance_number == target_instance) {
                out.addr_offset = cur + fixed_size;
                out.num_addr = num_base_address;
                out.addr64 = addr64;
                return true;
            }

            cur += fixed_size + addr_bytes;
        }
    }

    fprintf(stderr,
            "Error: hw_id=%u instance=%u not found in IP discovery table\n",
            target_hw_id, target_instance);
    return false;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

static void
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s <input> <output> <hw_id> [instance=<N>] <addr0> [addr1 "
            "...]\n"
            "\n"
            "  <hw_id>       decimal or 0x-hex hardware ID (e.g. 11 or 0xb "
            "for GC)\n"
            "  instance=<N>  optional instance selector (default 0)\n"
            "  <addrN>       new base addresses (decimal or 0x-hex)\n"
            "                must match the existing num_base_address count\n"
            "\n"
            "Examples:\n"
            "  %s in.bin out.bin 11 0x10200000\n"
            "  %s in.bin out.bin 0xb instance=1 0x10200000 0x10210000\n",
            prog, prog, prog);
}

int
main(int argc, char *argv[])
{
    if (argc < 5) {
        usage(argv[0]);
        return 1;
    }

    const char *input_path = argv[1];
    const char *output_path = argv[2];

    // Parse hw_id
    uint64_t hw_id_raw;
    if (!parse_uint64(argv[3], hw_id_raw) || hw_id_raw > 0xFFFF) {
        fprintf(stderr, "Error: invalid hw_id '%s'\n", argv[3]);
        return 1;
    }
    uint16_t hw_id = static_cast<uint16_t>(hw_id_raw);

    // Parse optional instance=N
    int next_arg = 4;
    uint8_t instance = 0;
    if (next_arg < argc && strncmp(argv[next_arg], "instance=", 9) == 0) {
        uint64_t inst_raw;
        if (!parse_uint64(argv[next_arg] + 9, inst_raw) || inst_raw > 0xFF) {
            fprintf(stderr, "Error: invalid instance '%s'\n", argv[next_arg]);
            return 1;
        }
        instance = static_cast<uint8_t>(inst_raw);
        next_arg++;
    }

    // Parse base addresses
    int num_addrs = argc - next_arg;
    if (num_addrs < 1) {
        fprintf(stderr, "Error: at least one base address required\n");
        usage(argv[0]);
        return 1;
    }
    std::vector<uint64_t> new_addrs(num_addrs);
    for (int i = 0; i < num_addrs; i++) {
        if (!parse_uint64(argv[next_arg + i], new_addrs[i])) {
            fprintf(stderr, "Error: invalid address '%s'\n",
                    argv[next_arg + i]);
            return 1;
        }
    }

    // Load blob
    std::ifstream fin(input_path, std::ios::binary | std::ios::ate);
    if (!fin) {
        fprintf(stderr, "Error: cannot open '%s'\n", input_path);
        return 1;
    }
    auto fsize = fin.tellg();
    fin.seekg(0);
    std::vector<uint8_t> blob(fsize);
    if (!fin.read(reinterpret_cast<char *>(blob.data()), fsize)) {
        fprintf(stderr, "Error: read failed\n");
        return 1;
    }

    // Validate signature
    auto *bhdr = blob_at<binary_header>(blob, 0);
    if (!bhdr) {
        fprintf(stderr, "Error: blob smaller than binary_header\n");
        return 1;
    }
    if (bhdr->binary_signature != BINARY_SIGNATURE) {
        fprintf(stderr,
                "Warning: unexpected signature 0x%08X (expected 0x%08X)\n",
                bhdr->binary_signature, BINARY_SIGNATURE);
    }

    // Find the IP
    PatchTarget target;
    if (!find_ip(blob, hw_id, instance, target)) {
        return 1;
    }

    // Validate address count
    if ((int)target.num_addr != num_addrs) {
        fprintf(stderr,
                "Error: hw_id=%u instance=%u has %u base address(es) but %d "
                "provided\n",
                hw_id, instance, target.num_addr, num_addrs);
        return 1;
    }

    // Validate 32-bit constraint for non-64-bit blobs
    if (!target.addr64) {
        for (int i = 0; i < num_addrs; i++) {
            if (new_addrs[i] > 0xFFFFFFFFu) {
                fprintf(stderr,
                        "Error: addr[%d]=0x%llX exceeds 32 bits and this blob "
                        "uses 32-bit addresses\n",
                        i, (unsigned long long)new_addrs[i]);
                return 1;
            }
        }
    }

    // Print what we're doing
    printf("Patching hw_id=%u (0x%X) instance=%u:\n", hw_id, hw_id, instance);
    for (int i = 0; i < num_addrs; i++) {
        if (target.addr64) {
            uint64_t old_val;
            memcpy(&old_val,
                   blob.data() + target.addr_offset + i * sizeof(uint64_t),
                   sizeof(uint64_t));
            printf("  base_address[%d]: 0x%016llX -> 0x%016llX\n", i,
                   (unsigned long long)old_val,
                   (unsigned long long)new_addrs[i]);
        } else {
            uint32_t old_val;
            memcpy(&old_val,
                   blob.data() + target.addr_offset + i * sizeof(uint32_t),
                   sizeof(uint32_t));
            printf("  base_address[%d]: 0x%08X -> 0x%08X\n", i, old_val,
                   (uint32_t)new_addrs[i]);
        }
    }

    // Apply the patch
    if (target.addr64) {
        for (int i = 0; i < num_addrs; i++) {
            uint64_t v = new_addrs[i];
            memcpy(blob.data() + target.addr_offset + i * sizeof(uint64_t), &v,
                   sizeof(v));
        }
    } else {
        for (int i = 0; i < num_addrs; i++) {
            uint32_t v = static_cast<uint32_t>(new_addrs[i]);
            memcpy(blob.data() + target.addr_offset + i * sizeof(uint32_t), &v,
                   sizeof(v));
        }
    }

    // Recompute checksums
    recompute_checksums(blob);
    printf("Checksums updated.\n");

    // Write output
    std::ofstream fout(output_path, std::ios::binary);
    if (!fout) {
        fprintf(stderr, "Error: cannot open '%s' for writing\n", output_path);
        return 1;
    }
    if (!fout.write(reinterpret_cast<const char *>(blob.data()),
                    blob.size())) {
        fprintf(stderr, "Error: write failed\n");
        return 1;
    }
    printf("Written to '%s'\n", output_path);
    return 0;
}
