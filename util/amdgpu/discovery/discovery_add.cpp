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

// discovery_add.cpp
// Append a new IP entry to one die in an AMDGPU discovery binary blob and
// recompute all affected size/offset/checksum fields.
//
// Usage:
//   discovery_add <input> <output> <hw_id> [die=<N>] [instance=<N>]
//                 major=<N> minor=<N> revision=<N>
//                 [harvest=<N>]       (v1/v2 blobs only, default 0)
//                 [sub_revision=<N>]  (v3/v4 blobs only, default 0)
//                 [variant=<N>]       (v3/v4 blobs only, default 0)
//                 <addr0> [addr1 ...]
//
// <hw_id>           decimal or 0x-prefixed hex hardware ID
// die=<N>           0-based die index to append to (default 0)
// instance=<N>      instance number (default 0)
// major/minor/revision  HCID version fields (required)
// harvest           v1/v2: harvest nibble (4-bit, default 0)
// sub_revision      v3/v4: HCID sub-revision nibble (4-bit, default 0)
// variant           v3/v4: HW variant nibble (4-bit, default 0)
// <addrN>           base addresses (decimal or 0x-hex); count sets
// num_base_address
//
// The new entry is appended at the end of the target die's IP list.
// After insertion the following fields are updated:
//   die_header.num_ips                    incremented by 1
//   ip_discovery_header.size              increased by entry_size
//   table_list[IP_DISCOVERY].size         increased by entry_size
//   binary_header.binary_size             increased by entry_size
//   ip_discovery_header.dies[d].die_offset  shifted for every die whose
//                                           die_header lies after the insert
//                                           point
//   table_list[t].offset                  shifted for every non-zero table
//   whose
//                                           data lies after the insert point
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
// Struct definitions (mirrors discovery.h, #pragma pack(1), little-endian)
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

// Fixed-size header portions of each IP struct version (base_address[]
// excluded).
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

// ip_v4 fixed header is identical to ip_v3; only the base_address width
// differs.
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

// Parse "key=value" where value is an integer. Returns true and sets `out` on
// match.
static bool
parse_kv(const char *arg, const char *key, uint64_t &out)
{
    size_t klen = strlen(key);
    if (strncmp(arg, key, klen) != 0 || arg[klen] != '=') {
        return false;
    }
    return parse_uint64(arg + klen + 1, out);
}

// ---------------------------------------------------------------------------
// IP entry size calculation (for walking existing entries)
// ---------------------------------------------------------------------------

static size_t
ip_entry_size(uint16_t version, bool addr64, uint8_t num_base_address)
{
    size_t fixed =
        (version <= 2) ? sizeof(ip) : sizeof(ip_v3); // ip_v4 == ip_v3 size
    size_t addr_bytes = addr64 ? (size_t)num_base_address * sizeof(uint64_t)
                               : (size_t)num_base_address * sizeof(uint32_t);
    return fixed + addr_bytes;
}

// ---------------------------------------------------------------------------
// Walk to find the byte offset just past the last IP in a given die (= insert
// point).
// ---------------------------------------------------------------------------

// Returns the byte offset immediately after the last IP entry in die[die_idx],
// which is where we will insert the new entry.
static bool
find_insert_point(std::vector<uint8_t> &blob, uint16_t die_idx,
                  size_t &insert_point, size_t &ip_disc_offset,
                  size_t &die_hdr_offset)
{
    auto *bhdr = blob_at<binary_header>(blob, 0);
    if (!bhdr) {
        return false;
    }

    ip_disc_offset = bhdr->table_list[IP_DISCOVERY].offset;
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

    uint16_t num_dies = ihdr->num_dies > 16 ? 16 : ihdr->num_dies;
    if (die_idx >= num_dies) {
        fprintf(stderr,
                "Error: die index %u is out of range (blob has %u dies)\n",
                die_idx, num_dies);
        return false;
    }

    bool addr64 = (ihdr->version == 4 && ihdr->base_addr_64_bit);

    die_hdr_offset = ihdr->dies[die_idx].die_offset;
    auto *dhdr = blob_at<die_header>(blob, die_hdr_offset);
    if (!dhdr) {
        fprintf(stderr, "Error: die_header[%u] out of bounds\n", die_idx);
        return false;
    }

    // Walk all existing IP entries in this die to find where they end.
    size_t cur = die_hdr_offset + sizeof(die_header);
    for (uint16_t i = 0; i < dhdr->num_ips; i++) {
        if (cur + sizeof(ip) > blob.size()) {
            fprintf(stderr, "Error: IP entry %u in die %u out of bounds\n", i,
                    die_idx);
            return false;
        }
        // num_base_address is at byte offset 3 into the fixed header for all
        // versions.
        uint8_t num_base = blob[cur + 3];
        cur += ip_entry_size(ihdr->version, addr64, num_base);
    }

    insert_point = cur;
    return true;
}

// ---------------------------------------------------------------------------
// Build the new IP entry bytes based on blob version
// ---------------------------------------------------------------------------

static std::vector<uint8_t>
build_entry(uint16_t version, bool addr64, uint16_t hw_id, uint8_t instance,
            uint8_t major, uint8_t minor, uint8_t revision,
            uint8_t harvest,      // v1/v2
            uint8_t sub_revision, // v3/v4
            uint8_t variant,      // v3/v4
            const std::vector<uint64_t> &addrs)
{
    std::vector<uint8_t> entry;
    uint8_t num_base = static_cast<uint8_t>(addrs.size());

    if (version <= 2) {
        ip hdr{};
        hdr.hw_id = hw_id;
        hdr.number_instance = instance;
        hdr.num_base_address = num_base;
        hdr.major = major;
        hdr.minor = minor;
        hdr.revision = revision;
        hdr.harvest = harvest & 0xF;
        hdr.reserved = 0;
        entry.resize(sizeof(ip));
        memcpy(entry.data(), &hdr, sizeof(ip));
    } else {
        // ip_v3 and ip_v4 have identical fixed headers
        ip_v3 hdr{};
        hdr.hw_id = hw_id;
        hdr.instance_number = instance;
        hdr.num_base_address = num_base;
        hdr.major = major;
        hdr.minor = minor;
        hdr.revision = revision;
        hdr.sub_revision = sub_revision & 0xF;
        hdr.variant = variant & 0xF;
        entry.resize(sizeof(ip_v3));
        memcpy(entry.data(), &hdr, sizeof(ip_v3));
    }

    for (const uint64_t addr : addrs) {
        if (addr64) {
            uint8_t bytes[8];
            memcpy(bytes, &addr, 8);
            entry.insert(entry.end(), bytes, bytes + 8);
        } else {
            uint32_t a32 = static_cast<uint32_t>(addr);
            uint8_t bytes[4];
            memcpy(bytes, &a32, 4);
            entry.insert(entry.end(), bytes, bytes + 4);
        }
    }

    return entry;
}

// ---------------------------------------------------------------------------
// Offset fixups and checksum recompute
// ---------------------------------------------------------------------------

// Shift every stored offset that pointed at or past `insert_point` up by
// `added_size`. Called AFTER the blob has been grown by insertion.
static void
fixup_offsets(std::vector<uint8_t> &blob, size_t insert_point,
              size_t added_size, size_t ip_disc_offset)
{
    auto *bhdr = blob_at<binary_header>(blob, 0);
    auto *ihdr = blob_at<ip_discovery_header>(blob, ip_disc_offset);

    // die_info[d].die_offset: shift dies whose die_header was at/after
    // insert_point. (The die we inserted into has its die_header before
    // insert_point, so it is unaffected.)
    uint16_t num_dies = ihdr->num_dies > 16 ? 16 : ihdr->num_dies;
    for (uint16_t d = 0; d < num_dies; d++) {
        if (ihdr->dies[d].die_offset >= insert_point) {
            ihdr->dies[d].die_offset += static_cast<uint16_t>(added_size);
        }
    }

    // table_list[t].offset for non-IP tables whose data sits at/after
    // insert_point.
    for (int t = 0; t < TOTAL_TABLES; t++) {
        uint16_t off = bhdr->table_list[t].offset;
        if (off != 0 && off >= insert_point) {
            bhdr->table_list[t].offset += static_cast<uint16_t>(added_size);
        }
    }
}

static void
recompute_checksums(std::vector<uint8_t> &blob, size_t ip_disc_offset)
{
    auto *bhdr = blob_at<binary_header>(blob, 0);
    auto *ihdr = blob_at<ip_discovery_header>(blob, ip_disc_offset);

    // table_list[IP_DISCOVERY].checksum covers blob[ip_disc_offset ..
    // +ihdr->size)
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
    fprintf(
        stderr,
        "Usage:\n"
        "  %s <input> <output> <hw_id> [die=<N>] [instance=<N>]\n"
        "      major=<N> minor=<N> revision=<N>\n"
        "      [harvest=<N>]      (v1/v2 blobs, default 0)\n"
        "      [sub_revision=<N>] (v3/v4 blobs, default 0)\n"
        "      [variant=<N>]      (v3/v4 blobs, default 0)\n"
        "      <addr0> [addr1 ...]\n"
        "\n"
        "  <hw_id>     decimal or 0x-hex hardware ID (e.g. 11 or 0xb for GC)\n"
        "  die=<N>     0-based index of the die to append to (default 0)\n"
        "  instance=<N>  instance number (default 0)\n"
        "  major/minor/revision  HCID version (required)\n"
        "  harvest     v1/v2: harvest nibble (default 0)\n"
        "  sub_revision  v3/v4: HCID sub-revision nibble (default 0)\n"
        "  variant     v3/v4: HW variant nibble (default 0)\n"
        "  <addrN>     base addresses; count determines num_base_address\n"
        "\n"
        "  Key=value args may appear in any order before the addresses.\n"
        "  Any arg without '=' is treated as a base address.\n"
        "\n"
        "Examples:\n"
        "  %s in.bin out.bin 11 major=1 minor=0 revision=0 0x10200000\n"
        "  %s in.bin out.bin 0xb die=1 instance=2 major=1 minor=0 revision=0 "
        "\\\n"
        "      sub_revision=1 variant=0 0x10200000 0x10210000\n",
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

    // argv[3] = hw_id (positional)
    uint64_t hw_id_raw;
    if (!parse_uint64(argv[3], hw_id_raw) || hw_id_raw > 0xFFFF) {
        fprintf(stderr, "Error: invalid hw_id '%s'\n", argv[3]);
        return 1;
    }
    uint16_t hw_id = static_cast<uint16_t>(hw_id_raw);

    // argv[4..] = key=value pairs and addresses
    uint64_t die_idx = 0;
    uint64_t instance = 0;
    uint64_t major = UINT64_MAX; // sentinel: not provided
    uint64_t minor = UINT64_MAX;
    uint64_t revision = UINT64_MAX;
    uint64_t harvest = 0;
    uint64_t sub_revision = 0;
    uint64_t variant = 0;
    std::vector<uint64_t> addrs;

    for (int i = 4; i < argc; i++) {
        const char *arg = argv[i];
        uint64_t v;

        if (parse_kv(arg, "die", v)) {
            die_idx = v;
        } else if (parse_kv(arg, "instance", v)) {
            instance = v;
        } else if (parse_kv(arg, "major", v)) {
            major = v;
        } else if (parse_kv(arg, "minor", v)) {
            minor = v;
        } else if (parse_kv(arg, "revision", v)) {
            revision = v;
        } else if (parse_kv(arg, "harvest", v)) {
            harvest = v;
        } else if (parse_kv(arg, "sub_revision", v)) {
            sub_revision = v;
        } else if (parse_kv(arg, "variant", v)) {
            variant = v;
        } else if (strchr(arg, '=') != nullptr) {
            fprintf(stderr, "Error: unrecognised argument '%s'\n", arg);
            return 1;
        } else {
            // Positional: base address
            if (!parse_uint64(arg, v)) {
                fprintf(stderr, "Error: invalid address '%s'\n", arg);
                return 1;
            }
            addrs.push_back(v);
        }
    }

    // Validate required fields
    if (major == UINT64_MAX || minor == UINT64_MAX || revision == UINT64_MAX) {
        fprintf(stderr, "Error: major, minor, and revision are required\n");
        usage(argv[0]);
        return 1;
    }
    if (addrs.empty()) {
        fprintf(stderr, "Error: at least one base address is required\n");
        usage(argv[0]);
        return 1;
    }
    if (addrs.size() > 255) {
        fprintf(stderr, "Error: num_base_address exceeds 255\n");
        return 1;
    }
    if (die_idx > 15) {
        fprintf(stderr, "Error: die index %llu is out of range (max 15)\n",
                (unsigned long long)die_idx);
        return 1;
    }

    // Check 4-bit fields
    auto check4 = [](const char *name, uint64_t v) -> bool {
        if (v > 0xF) {
            fprintf(stderr, "Error: %s=%llu exceeds 4-bit range (0-15)\n",
                    name, (unsigned long long)v);
            return false;
        }
        return true;
    };
    if (!check4("harvest", harvest)) {
        return 1;
    }
    if (!check4("sub_revision", sub_revision)) {
        return 1;
    }
    if (!check4("variant", variant)) {
        return 1;
    }
    if (!check4("major", major)) {
        return 1;
    }
    if (!check4("minor", minor)) {
        return 1;
    }
    if (!check4("revision", revision)) {
        return 1;
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

    // Find insert point (end of target die's IP list)
    size_t insert_point, ip_disc_offset, die_hdr_offset;
    if (!find_insert_point(blob, static_cast<uint16_t>(die_idx), insert_point,
                           ip_disc_offset, die_hdr_offset)) {
        return 1;
    }

    // Determine blob version to know which header variant and address width to
    // use
    auto *ihdr = blob_at<ip_discovery_header>(blob, ip_disc_offset);
    bool addr64 = (ihdr->version == 4 && ihdr->base_addr_64_bit);

    // Validate 32-bit address constraint for non-64-bit blobs
    if (!addr64) {
        for (size_t i = 0; i < addrs.size(); i++) {
            if (addrs[i] > 0xFFFFFFFFu) {
                fprintf(stderr,
                        "Error: addr[%zu]=0x%llX exceeds 32 bits and this "
                        "blob uses 32-bit addresses\n",
                        i, (unsigned long long)addrs[i]);
                return 1;
            }
        }
    }

    // Build the new IP entry
    std::vector<uint8_t> entry = build_entry(
        ihdr->version, addr64, hw_id, static_cast<uint8_t>(instance),
        static_cast<uint8_t>(major), static_cast<uint8_t>(minor),
        static_cast<uint8_t>(revision), static_cast<uint8_t>(harvest),
        static_cast<uint8_t>(sub_revision), static_cast<uint8_t>(variant),
        addrs);

    size_t entry_size = entry.size();

    printf("Adding hw_id=%u (0x%X) instance=%u into die index %llu:\n", hw_id,
           hw_id, (unsigned)instance, (unsigned long long)die_idx);
    printf("  blob version=%u  addr_width=%s\n", ihdr->version,
           addr64 ? "64-bit" : "32-bit");
    printf("  major=%llu  minor=%llu  revision=%llu",
           (unsigned long long)major, (unsigned long long)minor,
           (unsigned long long)revision);
    if (ihdr->version <= 2) {
        printf("  harvest=%llu", (unsigned long long)harvest);
    } else {
        printf("  sub_revision=%llu  variant=%llu",
               (unsigned long long)sub_revision, (unsigned long long)variant);
    }
    printf("\n");
    for (size_t i = 0; i < addrs.size(); i++) {
        if (addr64) {
            printf("  base_address[%zu]=0x%016llX\n", i,
                   (unsigned long long)addrs[i]);
        } else {
            printf("  base_address[%zu]=0x%08X\n", i, (uint32_t)addrs[i]);
        }
    }
    printf("  inserting %zu bytes at blob offset 0x%zX\n", entry_size,
           insert_point);

    // 1. Insert the new entry bytes into the blob.
    blob.insert(blob.begin() + static_cast<ptrdiff_t>(insert_point),
                entry.begin(), entry.end());

    // All pointers into the blob obtained before this point are now dangling.
    // Re-derive every pointer we need from here on.

    // 2. Increment die_header.num_ips.
    //    The die_header is always before insert_point, so its offset is
    //    unchanged.
    auto *dhdr = blob_at<die_header>(blob, die_hdr_offset);
    if (!dhdr) {
        fprintf(stderr, "Error: die_header out of bounds after insert\n");
        return 1;
    }
    dhdr->num_ips++;

    // 3. Update size fields.
    ihdr = blob_at<ip_discovery_header>(blob, ip_disc_offset);
    if (!ihdr) {
        fprintf(stderr,
                "Error: ip_discovery_header out of bounds after insert\n");
        return 1;
    }
    ihdr->size += static_cast<uint16_t>(entry_size);
    bhdr = blob_at<binary_header>(blob, 0);
    bhdr->table_list[IP_DISCOVERY].size += static_cast<uint16_t>(entry_size);
    bhdr->binary_size += static_cast<uint16_t>(entry_size);

    // 4. Fix up stored offsets that pointed at or past the insertion point.
    fixup_offsets(blob, insert_point, entry_size, ip_disc_offset);

    // 5. Recompute checksums.
    recompute_checksums(blob, ip_disc_offset);

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
           blob.size() - entry_size);
    return 0;
}
