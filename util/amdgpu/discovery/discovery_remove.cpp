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

// discovery_remove.cpp
// Remove one IP instance from an AMDGPU discovery binary blob and recompute
// all affected size/offset/checksum fields so the driver accepts the result.
//
// Usage:
//   discovery_remove <input_blob> <output_blob> <hw_id> [instance=<N>]
//
// <hw_id>      : decimal or 0x-prefixed hex hardware ID (e.g. 11 or 0xb for
// GC) instance=<N> : optional instance selector (default 0)
//
// After erasing the IP entry (its fixed header + base_address array), the
// following fields are updated:
//
//   die_header.num_ips                    decremented by 1
//   ip_discovery_header.size              decreased by removed_bytes
//   table_list[IP_DISCOVERY].size         decreased by removed_bytes
//   binary_header.binary_size             decreased by removed_bytes
//   ip_discovery_header.dies[d].die_offset  shifted for every die whose
//                                           die_header lies after the removed
//                                           entry
//   table_list[t].offset                  shifted for every non-zero table
//   whose
//                                           data lies after the removed entry
//   table_list[IP_DISCOVERY].checksum     recomputed over new IP discovery
//   block binary_header.binary_checksum         recomputed over new binary
//   body

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Struct definitions  (mirrors discovery.h, #pragma pack(1), little-endian)
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
// Find result
// ---------------------------------------------------------------------------

struct FindResult
{
    size_t entry_start;    // byte offset of the IP entry's fixed header
    size_t entry_size;     // fixed header + base_address array
    size_t ip_disc_offset; // byte offset of ip_discovery_header in blob
    size_t die_hdr_offset; // byte offset of the containing die_header in blob
};

static bool
find_ip(std::vector<uint8_t> &blob, uint16_t target_hw_id,
        uint8_t target_instance, FindResult &out)
{
    auto *bhdr = blob_at<binary_header>(blob, 0);
    if (!bhdr) {
        return false;
    }

    size_t ip_disc_offset = bhdr->table_list[IP_DISCOVERY].offset;
    if (!ip_disc_offset) {
        fprintf(stderr, "Error: no IP_DISCOVERY table in blob\n");
        return false;
    }

    auto *ihdr = blob_at<ip_discovery_header>(blob, ip_disc_offset);
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
        size_t die_off = ihdr->dies[d].die_offset;
        auto *dhdr = blob_at<die_header>(blob, die_off);
        if (!dhdr) {
            continue;
        }

        size_t cur = die_off + sizeof(die_header);

        for (uint16_t i = 0; i < dhdr->num_ips; i++) {
            if (cur >= blob.size()) {
                break;
            }

            uint16_t hw_id;
            uint8_t instance_number;
            uint8_t num_base_address;
            size_t fixed_size;

            if (ihdr->version <= 2) {
                auto *e = reinterpret_cast<const ip *>(blob.data() + cur);
                hw_id = e->hw_id;
                instance_number = e->number_instance;
                num_base_address = e->num_base_address;
                fixed_size = sizeof(ip);
            } else if (ihdr->version == 3) {
                auto *e = reinterpret_cast<const ip_v3 *>(blob.data() + cur);
                hw_id = e->hw_id;
                instance_number = e->instance_number;
                num_base_address = e->num_base_address;
                fixed_size = sizeof(ip_v3);
            } else {
                auto *e = reinterpret_cast<const ip_v4 *>(blob.data() + cur);
                hw_id = e->hw_id;
                instance_number = e->instance_number;
                num_base_address = e->num_base_address;
                fixed_size = sizeof(ip_v4);
            }

            size_t addr_bytes =
                addr64 ? (size_t)num_base_address * sizeof(uint64_t)
                       : (size_t)num_base_address * sizeof(uint32_t);

            if (hw_id == target_hw_id && instance_number == target_instance) {
                out.entry_start = cur;
                out.entry_size = fixed_size + addr_bytes;
                out.ip_disc_offset = ip_disc_offset;
                out.die_hdr_offset = die_off;
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
// Offset/size fixups and checksum recompute
// ---------------------------------------------------------------------------

// Shift every stored offset that points past `removed_start` down by
// `removed_size`. Must be called AFTER the blob has already been erased (so
// sizes are already smaller), but using offsets captured before the erase.
static void
fixup_offsets(std::vector<uint8_t> &blob, size_t removed_start,
              size_t removed_size, size_t ip_disc_offset)
{
    auto *bhdr = blob_at<binary_header>(blob, 0);
    auto *ihdr = blob_at<ip_discovery_header>(blob, ip_disc_offset);

    // die_info[d].die_offset in ip_discovery_header:
    // Any die whose die_header was located after the removed entry shifts
    // down.
    uint16_t num_dies = ihdr->num_dies > 16 ? 16 : ihdr->num_dies;
    for (uint16_t d = 0; d < num_dies; d++) {
        if (ihdr->dies[d].die_offset > removed_start) {
            ihdr->dies[d].die_offset -= static_cast<uint16_t>(removed_size);
        }
    }

    // table_list[t].offset for other tables whose data follows the removed
    // entry:
    for (int t = 0; t < TOTAL_TABLES; t++) {
        uint16_t off = bhdr->table_list[t].offset;
        if (off != 0 && off > removed_start) {
            bhdr->table_list[t].offset -= static_cast<uint16_t>(removed_size);
        }
    }
}

static void
recompute_checksums(std::vector<uint8_t> &blob, size_t ip_disc_offset)
{
    auto *bhdr = blob_at<binary_header>(blob, 0);
    auto *ihdr = blob_at<ip_discovery_header>(blob, ip_disc_offset);

    // table_list[IP_DISCOVERY].checksum covers blob[ip_disc_offset ..
    // +ihdr->size]
    if (ip_disc_offset + ihdr->size <= blob.size()) {
        bhdr->table_list[IP_DISCOVERY].checksum =
            bytesum(blob.data() + ip_disc_offset, ihdr->size);
    }

    // binary_header.binary_checksum covers blob[10 .. binary_size)
    constexpr size_t chk_field_end =
        10; // offsetof(binary_checksum) + sizeof(binary_checksum)
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
// Main
// ---------------------------------------------------------------------------

static void
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s <input> <output> <hw_id> [instance=<N>]\n"
            "\n"
            "  <hw_id>       decimal or 0x-hex hardware ID (e.g. 11 or 0xb "
            "for GC)\n"
            "  instance=<N>  optional instance selector (default 0)\n"
            "\n"
            "Examples:\n"
            "  %s in.bin out.bin 11\n"
            "  %s in.bin out.bin 0xb instance=2\n",
            prog, prog, prog);
}

int
main(int argc, char *argv[])
{
    if (argc < 4) {
        usage(argv[0]);
        return 1;
    }

    const char *input_path = argv[1];
    const char *output_path = argv[2];

    uint64_t hw_id_raw;
    if (!parse_uint64(argv[3], hw_id_raw) || hw_id_raw > 0xFFFF) {
        fprintf(stderr, "Error: invalid hw_id '%s'\n", argv[3]);
        return 1;
    }
    uint16_t hw_id = static_cast<uint16_t>(hw_id_raw);

    uint8_t instance = 0;
    if (argc >= 5) {
        if (strncmp(argv[4], "instance=", 9) != 0) {
            fprintf(stderr, "Error: unexpected argument '%s'\n", argv[4]);
            usage(argv[0]);
            return 1;
        }
        uint64_t inst_raw;
        if (!parse_uint64(argv[4] + 9, inst_raw) || inst_raw > 0xFF) {
            fprintf(stderr, "Error: invalid instance '%s'\n", argv[4]);
            return 1;
        }
        instance = static_cast<uint8_t>(inst_raw);
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

    // Find the IP entry
    FindResult found;
    if (!find_ip(blob, hw_id, instance, found)) {
        return 1;
    }

    printf("Removing hw_id=%u (0x%X) instance=%u: %zu bytes at blob offset "
           "0x%zX\n",
           hw_id, hw_id, instance, found.entry_size, found.entry_start);

    // 1. Erase the entry from the blob.
    blob.erase(blob.begin() + static_cast<ptrdiff_t>(found.entry_start),
               blob.begin() + static_cast<ptrdiff_t>(found.entry_start +
                                                     found.entry_size));

    // All pointers into the blob obtained before this point are now dangling.
    // Re-derive every pointer we need from here on.

    // 2. Decrement die_header.num_ips.
    //    The die_header is before entry_start, so its offset is unchanged
    //    after the erase.
    auto *dhdr = blob_at<die_header>(blob, found.die_hdr_offset);
    if (!dhdr) {
        fprintf(
            stderr,
            "Error: die_header out of bounds after erase (corrupt blob?)\n");
        return 1;
    }
    dhdr->num_ips--;

    // 3. Update size fields (all headers are before the removed region).
    auto *ihdr = blob_at<ip_discovery_header>(blob, found.ip_disc_offset);
    if (!ihdr) {
        fprintf(stderr,
                "Error: ip_discovery_header out of bounds after erase\n");
        return 1;
    }
    ihdr->size -= static_cast<uint16_t>(found.entry_size);
    bhdr = blob_at<binary_header>(blob, 0);
    bhdr->table_list[IP_DISCOVERY].size -=
        static_cast<uint16_t>(found.entry_size);
    bhdr->binary_size -= static_cast<uint16_t>(found.entry_size);

    // 4. Fix up stored offsets that pointed past the removed region.
    fixup_offsets(blob, found.entry_start, found.entry_size,
                  found.ip_disc_offset);

    // 5. Recompute checksums.
    recompute_checksums(blob, found.ip_disc_offset);

    printf("Updated: die.num_ips, ip_discovery_header.size, "
           "table_list[IP_DISCOVERY].size,\n"
           "         binary_size, die_offsets, table offsets, checksums.\n");

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
    printf("Written to '%s' (%zu bytes, was %zu)\n", output_path, blob.size(),
           blob.size() + found.entry_size);
    return 0;
}
