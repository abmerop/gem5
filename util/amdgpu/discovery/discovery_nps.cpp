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

// discovery_nps.cpp
// Add, remove, or edit the NPS_INFO table of an AMDGPU discovery binary blob
// and recompute every affected size/offset/checksum field so the driver
// accepts the modified blob.
//
// Usage:
//   discovery_nps <input> <output> <command> [args...]
//
// Commands:
//   show
//       Print the NPS_INFO table (or report that it is absent).
//
//   set-type <nps_type>
//       Set the nps_type field of an existing table.
//
//   add base=<addr> limit=<addr>
//       Append a new instance to an existing table (count++).
//
//   edit index=<N> [base=<addr>] [limit=<addr>]
//       Modify the base and/or limit address of instance N.
//
//   remove index=<N>
//       Remove instance N (later instances shift down, count--).
//
//   create [nps_type=<N>] [base=<addr> limit=<addr> [base=<addr> limit=<addr>
//   ...]]
//       Create a new NPS_INFO table (only valid if none exists). Optionally
//       seed it with one or more instances.
//
//   remove-table
//       Strip the entire NPS_INFO table from the blob.
//
// The NPS_INFO table is a fixed-size 212-byte structure (nps_info_v1_0) with
// room for NPS_INFO_TABLE_MAX_NUM_INSTANCES (12) instances; the `count` field
// selects how many are valid. Instance-level commands (add/remove/edit/
// set-type) therefore never change the table size -- they only rewrite the
// 212-byte region and recompute checksums. The create/remove-table commands
// do change the blob layout and additionally fix up table/die offsets and
// binary_size.
//
// Checksum rules (from amdgpu_discovery_init):
//   table_list[NPS_INFO].checksum  = bytesum(blob[nps_offset .. +size_bytes))
//   binary_header.binary_checksum  = bytesum(blob[10 .. +binary_size))
//
// To keep the blob fitting the fixed-size ROM region it is loaded into, the
// total output file length is preserved: when create/remove-table grow or
// shrink the meaningful data, the trailing zero padding is consumed or
// restored so the file size matches the input (the file only grows when the
// input has no padding left to consume).

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
#define NPS_INFO_TABLE_ID 0x0053504Eu
#define NPS_INFO_TABLE_MAX_NUM_INSTANCES 12
#define NPS_INFO_TABLE_SIZE 212 // sizeof(nps_info_v1_0)
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

struct nps_info_header
{
    uint32_t table_id;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t size_bytes;
};

struct nps_instance_info_v1_0
{
    uint64_t base_address;
    uint64_t limit_address;
};

struct nps_info_v1_0
{
    nps_info_header header;
    uint32_t nps_type;
    uint32_t count;
    nps_instance_info_v1_0 instance_info[NPS_INFO_TABLE_MAX_NUM_INSTANCES];
};

#pragma pack()

static_assert(sizeof(nps_info_v1_0) == NPS_INFO_TABLE_SIZE,
              "nps_info_v1_0 must be 212 bytes");

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
// Checksum recompute (NPS table + binary header)
// ---------------------------------------------------------------------------

static void
recompute_checksums(std::vector<uint8_t> &blob)
{
    auto *bhdr = blob_at<binary_header>(blob, 0);
    if (!bhdr) {
        return;
    }

    // table_list[NPS_INFO].checksum covers blob[nps_off .. +size_bytes)
    uint16_t nps_off = bhdr->table_list[NPS_INFO].offset;
    if (nps_off) {
        auto *nhdr = blob_at<nps_info_header>(blob, nps_off);
        if (nhdr && nps_off + nhdr->size_bytes <= blob.size()) {
            bhdr->table_list[NPS_INFO].checksum =
                bytesum(blob.data() + nps_off, nhdr->size_bytes);
        }
    }

    // binary_header.binary_checksum covers blob[10 .. binary_size)
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
// Blob I/O
// ---------------------------------------------------------------------------

static bool
load_blob(const char *path, std::vector<uint8_t> &blob)
{
    std::ifstream fin(path, std::ios::binary | std::ios::ate);
    if (!fin) {
        fprintf(stderr, "Error: cannot open '%s'\n", path);
        return false;
    }
    auto fsize = fin.tellg();
    fin.seekg(0);
    blob.resize(fsize);
    if (!fin.read(reinterpret_cast<char *>(blob.data()), fsize)) {
        fprintf(stderr, "Error: read failed\n");
        return false;
    }
    return true;
}

// Write the blob, restoring `orig_size` by zero-padding the tail when the
// blob shrank. If the blob grew larger than the original, the larger size is
// written and a warning is printed (the ROM region must be able to hold it).
static bool
write_blob(const char *path, std::vector<uint8_t> &blob, size_t orig_size)
{
    if (blob.size() < orig_size) {
        blob.resize(orig_size, 0); // restore fixed ROM size with zero padding
    } else if (blob.size() > orig_size) {
        // The blob grew. If the excess bytes are all zero they are displaced
        // trailing padding and can be trimmed to keep the fixed ROM size;
        // otherwise real data would be lost, so keep the larger blob and warn.
        size_t excess = blob.size() - orig_size;
        bool all_zero = true;
        for (size_t i = blob.size() - excess; i < blob.size(); i++) {
            if (blob[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            blob.resize(orig_size);
        } else {
            fprintf(stderr,
                    "Warning: output grew from %zu to %zu bytes (no trailing "
                    "padding to consume)\n",
                    orig_size, blob.size());
        }
    }

    std::ofstream fout(path, std::ios::binary);
    if (!fout) {
        fprintf(stderr, "Error: cannot open '%s' for writing\n", path);
        return false;
    }
    if (!fout.write(reinterpret_cast<const char *>(blob.data()),
                    blob.size())) {
        fprintf(stderr, "Error: write failed\n");
        return false;
    }
    printf("Written to '%s' (%zu bytes)\n", path, blob.size());
    return true;
}

// ---------------------------------------------------------------------------
// Table location / printing
// ---------------------------------------------------------------------------

// Returns the NPS table offset (0 if absent), validating the table_id when
// present.
static uint16_t
nps_offset(std::vector<uint8_t> &blob)
{
    auto *bhdr = blob_at<binary_header>(blob, 0);
    if (!bhdr) {
        return 0;
    }
    uint16_t off = bhdr->table_list[NPS_INFO].offset;
    if (!off) {
        return 0;
    }
    auto *nhdr = blob_at<nps_info_header>(blob, off);
    if (!nhdr) {
        fprintf(stderr, "Error: NPS table offset 0x%04X out of bounds\n", off);
        return 0;
    }
    if (nhdr->table_id != NPS_INFO_TABLE_ID) {
        fprintf(stderr,
                "Warning: unexpected NPS table_id 0x%08X (expected 0x%08X)\n",
                nhdr->table_id, NPS_INFO_TABLE_ID);
    }
    return off;
}

static void
print_nps(std::vector<uint8_t> &blob)
{
    uint16_t off = nps_offset(blob);
    if (!off) {
        printf("nps_info: [not present]\n");
        return;
    }
    auto *n = blob_at<nps_info_v1_0>(blob, off);
    if (!n) {
        printf("nps_info: [out of bounds]\n");
        return;
    }
    printf("nps_info (@ 0x%04X): version=%u.%u  size=%u bytes  nps_type=%u  "
           "count=%u\n",
           off, n->header.version_major, n->header.version_minor,
           n->header.size_bytes, n->nps_type, n->count);
    uint32_t cnt = n->count > NPS_INFO_TABLE_MAX_NUM_INSTANCES
                       ? NPS_INFO_TABLE_MAX_NUM_INSTANCES
                       : n->count;
    for (uint32_t i = 0; i < cnt; i++) {
        printf("  instance[%u]: base=0x%016llX  limit=0x%016llX\n", i,
               (unsigned long long)n->instance_info[i].base_address,
               (unsigned long long)n->instance_info[i].limit_address);
    }
}

// ---------------------------------------------------------------------------
// Offset fixups for layout-changing commands (create / remove-table)
// ---------------------------------------------------------------------------

// Shift every stored offset at/after `point` by `delta` (signed). Used after
// growing (delta>0) or shrinking (delta<0) the blob at `point`. The NPS table
// entry itself is handled separately by the caller.
static void
fixup_offsets(std::vector<uint8_t> &blob, size_t point, int delta)
{
    auto *bhdr = blob_at<binary_header>(blob, 0);
    if (!bhdr) {
        return;
    }

    uint16_t ip_off = bhdr->table_list[IP_DISCOVERY].offset;
    if (ip_off) {
        auto *ihdr = blob_at<ip_discovery_header>(blob, ip_off);
        if (ihdr) {
            uint16_t num_dies = ihdr->num_dies > 16 ? 16 : ihdr->num_dies;
            for (uint16_t d = 0; d < num_dies; d++) {
                if (ihdr->dies[d].die_offset >= point) {
                    ihdr->dies[d].die_offset += static_cast<uint16_t>(delta);
                }
            }
        }
    }

    for (int t = 0; t < TOTAL_TABLES; t++) {
        if (t == NPS_INFO) {
            continue; // handled by the caller
        }
        uint16_t off = bhdr->table_list[t].offset;
        if (off != 0 && off >= point) {
            bhdr->table_list[t].offset += static_cast<uint16_t>(delta);
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

static int
cmd_set_type(std::vector<uint8_t> &blob, uint32_t nps_type)
{
    uint16_t off = nps_offset(blob);
    if (!off) {
        fprintf(stderr, "Error: no NPS table present (use 'create' first)\n");
        return 1;
    }
    auto *n = blob_at<nps_info_v1_0>(blob, off);
    if (!n) {
        fprintf(stderr, "Error: NPS table out of bounds\n");
        return 1;
    }
    printf("nps_type: %u -> %u\n", n->nps_type, nps_type);
    n->nps_type = nps_type;
    recompute_checksums(blob);
    return 0;
}

static int
cmd_add(std::vector<uint8_t> &blob, uint64_t base, uint64_t limit)
{
    uint16_t off = nps_offset(blob);
    if (!off) {
        fprintf(stderr, "Error: no NPS table present (use 'create' first)\n");
        return 1;
    }
    auto *n = blob_at<nps_info_v1_0>(blob, off);
    if (!n) {
        fprintf(stderr, "Error: NPS table out of bounds\n");
        return 1;
    }
    if (n->count >= NPS_INFO_TABLE_MAX_NUM_INSTANCES) {
        fprintf(stderr, "Error: NPS table is full (count=%u, max=%u)\n",
                n->count, NPS_INFO_TABLE_MAX_NUM_INSTANCES);
        return 1;
    }
    uint32_t idx = n->count;
    n->instance_info[idx].base_address = base;
    n->instance_info[idx].limit_address = limit;
    n->count++;
    printf("Added instance[%u]: base=0x%016llX  limit=0x%016llX  (count=%u)\n",
           idx, (unsigned long long)base, (unsigned long long)limit, n->count);
    recompute_checksums(blob);
    return 0;
}

static int
cmd_edit(std::vector<uint8_t> &blob, uint32_t index, bool have_base,
         uint64_t base, bool have_limit, uint64_t limit)
{
    uint16_t off = nps_offset(blob);
    if (!off) {
        fprintf(stderr, "Error: no NPS table present\n");
        return 1;
    }
    auto *n = blob_at<nps_info_v1_0>(blob, off);
    if (!n) {
        fprintf(stderr, "Error: NPS table out of bounds\n");
        return 1;
    }
    if (index >= n->count) {
        fprintf(stderr, "Error: index %u out of range (count=%u)\n", index,
                n->count);
        return 1;
    }
    if (have_base) {
        printf("instance[%u].base:  0x%016llX -> 0x%016llX\n", index,
               (unsigned long long)n->instance_info[index].base_address,
               (unsigned long long)base);
        n->instance_info[index].base_address = base;
    }
    if (have_limit) {
        printf("instance[%u].limit: 0x%016llX -> 0x%016llX\n", index,
               (unsigned long long)n->instance_info[index].limit_address,
               (unsigned long long)limit);
        n->instance_info[index].limit_address = limit;
    }
    recompute_checksums(blob);
    return 0;
}

static int
cmd_remove(std::vector<uint8_t> &blob, uint32_t index)
{
    uint16_t off = nps_offset(blob);
    if (!off) {
        fprintf(stderr, "Error: no NPS table present\n");
        return 1;
    }
    auto *n = blob_at<nps_info_v1_0>(blob, off);
    if (!n) {
        fprintf(stderr, "Error: NPS table out of bounds\n");
        return 1;
    }
    if (index >= n->count) {
        fprintf(stderr, "Error: index %u out of range (count=%u)\n", index,
                n->count);
        return 1;
    }
    printf("Removing instance[%u]: base=0x%016llX  limit=0x%016llX\n", index,
           (unsigned long long)n->instance_info[index].base_address,
           (unsigned long long)n->instance_info[index].limit_address);
    // Shift later instances down by one.
    for (uint32_t i = index; i + 1 < n->count; i++) {
        n->instance_info[i] = n->instance_info[i + 1];
    }
    n->count--;
    // Zero the now-unused trailing slot so stale data does not linger.
    n->instance_info[n->count].base_address = 0;
    n->instance_info[n->count].limit_address = 0;
    printf("count=%u\n", n->count);
    recompute_checksums(blob);
    return 0;
}

static int
cmd_create(std::vector<uint8_t> &blob, uint32_t nps_type,
           const std::vector<nps_instance_info_v1_0> &instances)
{
    if (nps_offset(blob)) {
        fprintf(
            stderr,
            "Error: NPS table already exists (use add/edit/remove-table)\n");
        return 1;
    }
    if (instances.size() > NPS_INFO_TABLE_MAX_NUM_INSTANCES) {
        fprintf(stderr, "Error: too many instances (%zu, max %u)\n",
                instances.size(), NPS_INFO_TABLE_MAX_NUM_INSTANCES);
        return 1;
    }

    auto *bhdr = blob_at<binary_header>(blob, 0);
    if (!bhdr) {
        fprintf(stderr, "Error: blob smaller than binary_header\n");
        return 1;
    }

    // Place the new table at the current end of meaningful data so it does not
    // collide with any existing table (NPS is conventionally last).
    size_t insert_point = bhdr->binary_size;
    if (insert_point > blob.size()) {
        fprintf(stderr, "Error: binary_size 0x%zX exceeds blob size 0x%zX\n",
                insert_point, blob.size());
        return 1;
    }

    // Build the 212-byte table.
    nps_info_v1_0 tbl{};
    tbl.header.table_id = NPS_INFO_TABLE_ID;
    tbl.header.version_major = 1;
    tbl.header.version_minor = 0;
    tbl.header.size_bytes = NPS_INFO_TABLE_SIZE;
    tbl.nps_type = nps_type;
    tbl.count = static_cast<uint32_t>(instances.size());
    for (size_t i = 0; i < instances.size(); i++) {
        tbl.instance_info[i] = instances[i];
    }

    // Insert the table bytes at the insert point (grows the blob; trailing
    // padding, if any, is consumed back at write time to preserve file size).
    const uint8_t *raw = reinterpret_cast<const uint8_t *>(&tbl);
    blob.insert(blob.begin() + static_cast<ptrdiff_t>(insert_point), raw,
                raw + NPS_INFO_TABLE_SIZE);

    // Pointers are invalidated by insert; re-derive.
    bhdr = blob_at<binary_header>(blob, 0);

    // Shift any offsets at/after the insert point (none expected when NPS is
    // last, handled for generality).
    fixup_offsets(blob, insert_point, NPS_INFO_TABLE_SIZE);

    // Register the new table.
    bhdr->table_list[NPS_INFO].offset = static_cast<uint16_t>(insert_point);
    bhdr->table_list[NPS_INFO].size = NPS_INFO_TABLE_SIZE;
    bhdr->table_list[NPS_INFO].padding = 0;
    bhdr->binary_size += NPS_INFO_TABLE_SIZE;

    recompute_checksums(blob); // sets table + binary checksums

    printf("Created NPS table @ 0x%04zX: nps_type=%u  count=%zu  size=%d "
           "bytes\n",
           insert_point, nps_type, instances.size(), NPS_INFO_TABLE_SIZE);
    for (size_t i = 0; i < instances.size(); i++) {
        printf("  instance[%zu]: base=0x%016llX  limit=0x%016llX\n", i,
               (unsigned long long)instances[i].base_address,
               (unsigned long long)instances[i].limit_address);
    }
    return 0;
}

static int
cmd_remove_table(std::vector<uint8_t> &blob)
{
    auto *bhdr = blob_at<binary_header>(blob, 0);
    if (!bhdr) {
        fprintf(stderr, "Error: blob smaller than binary_header\n");
        return 1;
    }
    uint16_t off = nps_offset(blob);
    if (!off) {
        fprintf(stderr, "Error: no NPS table present\n");
        return 1;
    }
    auto *nhdr = blob_at<nps_info_header>(blob, off);
    uint16_t tbl_size = nhdr ? static_cast<uint16_t>(nhdr->size_bytes)
                             : bhdr->table_list[NPS_INFO].size;
    if (tbl_size == 0) {
        tbl_size = NPS_INFO_TABLE_SIZE;
    }
    if (off + tbl_size > blob.size()) {
        fprintf(stderr, "Error: NPS table extends past blob end\n");
        return 1;
    }

    printf("Removing NPS table @ 0x%04X (%u bytes)\n", off, tbl_size);

    // Erase the table bytes and shift everything after it down.
    blob.erase(blob.begin() + off, blob.begin() + off + tbl_size);

    bhdr = blob_at<binary_header>(blob, 0);

    // Clear the table entry first so fixup_offsets skips it.
    bhdr->table_list[NPS_INFO].offset = 0;
    bhdr->table_list[NPS_INFO].checksum = 0;
    bhdr->table_list[NPS_INFO].size = 0;
    bhdr->table_list[NPS_INFO].padding = 0;

    // Shift offsets that pointed past the removed region down (none expected
    // when NPS is last, handled for generality).
    fixup_offsets(blob, off, -static_cast<int>(tbl_size));

    bhdr->binary_size -= tbl_size;

    recompute_checksums(blob);
    return 0;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

static void
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s <input> <output> <command> [args...]\n"
            "\n"
            "Commands:\n"
            "  show\n"
            "      Print the NPS_INFO table (or report it is absent).\n"
            "  set-type <nps_type>\n"
            "      Set the nps_type field of an existing table.\n"
            "  add base=<addr> limit=<addr>\n"
            "      Append a new instance (count++).\n"
            "  edit index=<N> [base=<addr>] [limit=<addr>]\n"
            "      Modify base and/or limit of instance N.\n"
            "  remove index=<N>\n"
            "      Remove instance N (count--).\n"
            "  create [nps_type=<N>] [base=<addr> limit=<addr> ...]\n"
            "      Create a new NPS_INFO table (only if none exists).\n"
            "  remove-table\n"
            "      Strip the entire NPS_INFO table.\n"
            "\n"
            "Addresses and nps_type accept decimal or 0x-prefixed hex.\n"
            "For 'show', <output> may be omitted; otherwise the (possibly\n"
            "unchanged) blob is written to <output>.\n"
            "\n"
            "Examples:\n"
            "  %s in.bin -            show\n"
            "  %s in.bin out.bin      edit index=0 base=0x200000000 "
            "limit=0x4FFFFFFFF\n"
            "  %s in.bin out.bin      add base=0x500000000 limit=0x5FFFFFFFF\n"
            "  %s in.bin out.bin      create nps_type=1 base=0x0 "
            "limit=0x3FFFFFFFF\n"
            "  %s in.bin out.bin      remove-table\n",
            prog, prog, prog, prog, prog, prog);
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
    const char *command = argv[3];

    std::vector<uint8_t> blob;
    if (!load_blob(input_path, blob)) {
        return 1;
    }
    size_t orig_size = blob.size();

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

    // 'show' does not modify the blob and does not require an output file.
    if (strcmp(command, "show") == 0) {
        print_nps(blob);
        return 0;
    }

    int rc = 0;
    if (strcmp(command, "set-type") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Error: set-type requires <nps_type>\n");
            return 1;
        }
        uint64_t v;
        if (!parse_uint64(argv[4], v) || v > 0xFFFFFFFFu) {
            fprintf(stderr, "Error: invalid nps_type '%s'\n", argv[4]);
            return 1;
        }
        rc = cmd_set_type(blob, static_cast<uint32_t>(v));
    } else if (strcmp(command, "add") == 0) {
        uint64_t base = 0, limit = 0;
        bool hb = false, hl = false;
        for (int i = 4; i < argc; i++) {
            uint64_t v;
            if (parse_kv(argv[i], "base", v)) {
                base = v;
                hb = true;
            } else if (parse_kv(argv[i], "limit", v)) {
                limit = v;
                hl = true;
            } else {
                fprintf(stderr, "Error: unrecognised argument '%s'\n",
                        argv[i]);
                return 1;
            }
        }
        if (!hb || !hl) {
            fprintf(stderr, "Error: add requires base=<addr> limit=<addr>\n");
            return 1;
        }
        rc = cmd_add(blob, base, limit);
    } else if (strcmp(command, "edit") == 0) {
        uint64_t index = 0, base = 0, limit = 0;
        bool hi = false, hb = false, hl = false;
        for (int i = 4; i < argc; i++) {
            uint64_t v;
            if (parse_kv(argv[i], "index", v)) {
                index = v;
                hi = true;
            } else if (parse_kv(argv[i], "base", v)) {
                base = v;
                hb = true;
            } else if (parse_kv(argv[i], "limit", v)) {
                limit = v;
                hl = true;
            } else {
                fprintf(stderr, "Error: unrecognised argument '%s'\n",
                        argv[i]);
                return 1;
            }
        }
        if (!hi) {
            fprintf(stderr, "Error: edit requires index=<N>\n");
            return 1;
        }
        if (!hb && !hl) {
            fprintf(stderr,
                    "Error: edit requires at least one of base=/limit=\n");
            return 1;
        }
        rc = cmd_edit(blob, static_cast<uint32_t>(index), hb, base, hl, limit);
    } else if (strcmp(command, "remove") == 0) {
        uint64_t index = 0;
        bool hi = false;
        for (int i = 4; i < argc; i++) {
            uint64_t v;
            if (parse_kv(argv[i], "index", v)) {
                index = v;
                hi = true;
            } else {
                fprintf(stderr, "Error: unrecognised argument '%s'\n",
                        argv[i]);
                return 1;
            }
        }
        if (!hi) {
            fprintf(stderr, "Error: remove requires index=<N>\n");
            return 1;
        }
        rc = cmd_remove(blob, static_cast<uint32_t>(index));
    } else if (strcmp(command, "create") == 0) {
        uint64_t nps_type = 0;
        std::vector<nps_instance_info_v1_0> instances;
        bool pending_base = false;
        uint64_t pending_base_val = 0;
        for (int i = 4; i < argc; i++) {
            uint64_t v;
            if (parse_kv(argv[i], "nps_type", v)) {
                nps_type = v;
            } else if (parse_kv(argv[i], "base", v)) {
                if (pending_base) {
                    fprintf(stderr,
                            "Error: base= without a matching limit=\n");
                    return 1;
                }
                pending_base = true;
                pending_base_val = v;
            } else if (parse_kv(argv[i], "limit", v)) {
                if (!pending_base) {
                    fprintf(stderr,
                            "Error: limit= without a preceding base=\n");
                    return 1;
                }
                instances.push_back({pending_base_val, v});
                pending_base = false;
            } else {
                fprintf(stderr, "Error: unrecognised argument '%s'\n",
                        argv[i]);
                return 1;
            }
        }
        if (pending_base) {
            fprintf(stderr, "Error: trailing base= without a limit=\n");
            return 1;
        }
        if (nps_type > 0xFFFFFFFFu) {
            fprintf(stderr, "Error: nps_type out of range\n");
            return 1;
        }
        rc = cmd_create(blob, static_cast<uint32_t>(nps_type), instances);
    } else if (strcmp(command, "remove-table") == 0) {
        rc = cmd_remove_table(blob);
    } else {
        fprintf(stderr, "Error: unknown command '%s'\n", command);
        usage(argv[0]);
        return 1;
    }

    if (rc != 0) {
        return rc;
    }

    if (!write_blob(output_path, blob, orig_size)) {
        return 1;
    }
    return 0;
}
