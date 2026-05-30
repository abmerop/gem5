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
// discovery_reader.cpp
// Reads and pretty-prints an AMDGPU IP discovery binary blob.
// Usage: discovery_reader <binary_file>
//
// The blob layout (all little-endian, #pragma pack(1)):
//   [0]  binary_header           -- signature, version, checksum, size,
//   table_list[6] [table_list[IP_DISCOVERY].offset]  ip_discovery_header +
//   die_header[] + ip_v{1,3,4}[] [table_list[GC].offset]            gc_info_v*
//   [table_list[HARVEST_INFO].offset]  harvest_table
//   [table_list[VCN_INFO].offset]      vcn_info_v1_0
//   [table_list[MALL_INFO].offset]     mall_info_v{1,2}_0
//   [table_list[NPS_INFO].offset]      nps_info_v1_0

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

// ---------------------------------------------------------------------------
// Replicated from discovery.h (without kernel types / macros)
// ---------------------------------------------------------------------------

#define BINARY_SIGNATURE 0x28211407u
#define DISCOVERY_TABLE_SIGNATURE 0x53445049u
#define GC_TABLE_ID 0x4347u
#define HARVEST_TABLE_SIGNATURE 0x56524148u
#define VCN_INFO_TABLE_ID 0x004E4356u
#define MALL_INFO_TABLE_ID 0x4C4C414Du
#define NPS_INFO_TABLE_ID 0x0053504Eu

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

static const char *table_names[] = {
    "IP_DISCOVERY", "GC", "HARVEST_INFO", "VCN_INFO", "MALL_INFO", "NPS_INFO",
};

#pragma pack(1)

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
        uint16_t padding[1]; // version <= 3
        struct
        { // version == 4
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

// v1/v2 IP entry (variable-length: fixed header + num_base_address * uint32_t)
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
    // uint32_t base_address[num_base_address] follows
};

// v3 IP entry
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
    // uint32_t base_address[num_base_address] follows
};

// v4 IP entry (same fixed header as v3, but base addresses may be 64-bit)
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
    // uint32_t or uint64_t base_address[num_base_address] follows
};

struct gpu_info_header
{
    uint32_t table_id;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t size;
};

struct gc_info_v1_0
{
    gpu_info_header header;
    uint32_t gc_num_se;
    uint32_t gc_num_wgp0_per_sa;
    uint32_t gc_num_wgp1_per_sa;
    uint32_t gc_num_rb_per_se;
    uint32_t gc_num_gl2c;
    uint32_t gc_num_gprs;
    uint32_t gc_num_max_gs_thds;
    uint32_t gc_gs_table_depth;
    uint32_t gc_gsprim_buff_depth;
    uint32_t gc_parameter_cache_depth;
    uint32_t gc_double_offchip_lds_buffer;
    uint32_t gc_wave_size;
    uint32_t gc_max_waves_per_simd;
    uint32_t gc_max_scratch_slots_per_cu;
    uint32_t gc_lds_size;
    uint32_t gc_num_sc_per_se;
    uint32_t gc_num_sa_per_se;
    uint32_t gc_num_packer_per_sc;
    uint32_t gc_num_gl2a;
};

struct gc_info_v1_1
{
    gpu_info_header header;
    uint32_t gc_num_se;
    uint32_t gc_num_wgp0_per_sa;
    uint32_t gc_num_wgp1_per_sa;
    uint32_t gc_num_rb_per_se;
    uint32_t gc_num_gl2c;
    uint32_t gc_num_gprs;
    uint32_t gc_num_max_gs_thds;
    uint32_t gc_gs_table_depth;
    uint32_t gc_gsprim_buff_depth;
    uint32_t gc_parameter_cache_depth;
    uint32_t gc_double_offchip_lds_buffer;
    uint32_t gc_wave_size;
    uint32_t gc_max_waves_per_simd;
    uint32_t gc_max_scratch_slots_per_cu;
    uint32_t gc_lds_size;
    uint32_t gc_num_sc_per_se;
    uint32_t gc_num_sa_per_se;
    uint32_t gc_num_packer_per_sc;
    uint32_t gc_num_gl2a;
    uint32_t gc_num_tcp_per_sa;
    uint32_t gc_num_sdp_interface;
    uint32_t gc_num_tcps;
};

struct gc_info_v1_2
{
    gpu_info_header header;
    uint32_t gc_num_se;
    uint32_t gc_num_wgp0_per_sa;
    uint32_t gc_num_wgp1_per_sa;
    uint32_t gc_num_rb_per_se;
    uint32_t gc_num_gl2c;
    uint32_t gc_num_gprs;
    uint32_t gc_num_max_gs_thds;
    uint32_t gc_gs_table_depth;
    uint32_t gc_gsprim_buff_depth;
    uint32_t gc_parameter_cache_depth;
    uint32_t gc_double_offchip_lds_buffer;
    uint32_t gc_wave_size;
    uint32_t gc_max_waves_per_simd;
    uint32_t gc_max_scratch_slots_per_cu;
    uint32_t gc_lds_size;
    uint32_t gc_num_sc_per_se;
    uint32_t gc_num_sa_per_se;
    uint32_t gc_num_packer_per_sc;
    uint32_t gc_num_gl2a;
    uint32_t gc_num_tcp_per_sa;
    uint32_t gc_num_sdp_interface;
    uint32_t gc_num_tcps;
    uint32_t gc_num_tcp_per_wpg;
    uint32_t gc_tcp_l1_size;
    uint32_t gc_num_sqc_per_wgp;
    uint32_t gc_l1_instruction_cache_size_per_sqc;
    uint32_t gc_l1_data_cache_size_per_sqc;
    uint32_t gc_gl1c_per_sa;
    uint32_t gc_gl1c_size_per_instance;
    uint32_t gc_gl2c_per_gpu;
};

struct gc_info_v1_3
{
    gpu_info_header header;
    uint32_t gc_num_se;
    uint32_t gc_num_wgp0_per_sa;
    uint32_t gc_num_wgp1_per_sa;
    uint32_t gc_num_rb_per_se;
    uint32_t gc_num_gl2c;
    uint32_t gc_num_gprs;
    uint32_t gc_num_max_gs_thds;
    uint32_t gc_gs_table_depth;
    uint32_t gc_gsprim_buff_depth;
    uint32_t gc_parameter_cache_depth;
    uint32_t gc_double_offchip_lds_buffer;
    uint32_t gc_wave_size;
    uint32_t gc_max_waves_per_simd;
    uint32_t gc_max_scratch_slots_per_cu;
    uint32_t gc_lds_size;
    uint32_t gc_num_sc_per_se;
    uint32_t gc_num_sa_per_se;
    uint32_t gc_num_packer_per_sc;
    uint32_t gc_num_gl2a;
    uint32_t gc_num_tcp_per_sa;
    uint32_t gc_num_sdp_interface;
    uint32_t gc_num_tcps;
    uint32_t gc_num_tcp_per_wpg;
    uint32_t gc_tcp_l1_size;
    uint32_t gc_num_sqc_per_wgp;
    uint32_t gc_l1_instruction_cache_size_per_sqc;
    uint32_t gc_l1_data_cache_size_per_sqc;
    uint32_t gc_gl1c_per_sa;
    uint32_t gc_gl1c_size_per_instance;
    uint32_t gc_gl2c_per_gpu;
    uint32_t gc_tcp_size_per_cu;
    uint32_t gc_tcp_cache_line_size;
    uint32_t gc_instruction_cache_size_per_sqc;
    uint32_t gc_instruction_cache_line_size;
    uint32_t gc_scalar_data_cache_size_per_sqc;
    uint32_t gc_scalar_data_cache_line_size;
    uint32_t gc_tcc_size;
    uint32_t gc_tcc_cache_line_size;
};

struct gc_info_v2_0
{
    gpu_info_header header;
    uint32_t gc_num_se;
    uint32_t gc_num_cu_per_sh;
    uint32_t gc_num_sh_per_se;
    uint32_t gc_num_rb_per_se;
    uint32_t gc_num_tccs;
    uint32_t gc_num_gprs;
    uint32_t gc_num_max_gs_thds;
    uint32_t gc_gs_table_depth;
    uint32_t gc_gsprim_buff_depth;
    uint32_t gc_parameter_cache_depth;
    uint32_t gc_double_offchip_lds_buffer;
    uint32_t gc_wave_size;
    uint32_t gc_max_waves_per_simd;
    uint32_t gc_max_scratch_slots_per_cu;
    uint32_t gc_lds_size;
    uint32_t gc_num_sc_per_se;
    uint32_t gc_num_packer_per_sc;
};

struct gc_info_v2_1
{
    gpu_info_header header;
    uint32_t gc_num_se;
    uint32_t gc_num_cu_per_sh;
    uint32_t gc_num_sh_per_se;
    uint32_t gc_num_rb_per_se;
    uint32_t gc_num_tccs;
    uint32_t gc_num_gprs;
    uint32_t gc_num_max_gs_thds;
    uint32_t gc_gs_table_depth;
    uint32_t gc_gsprim_buff_depth;
    uint32_t gc_parameter_cache_depth;
    uint32_t gc_double_offchip_lds_buffer;
    uint32_t gc_wave_size;
    uint32_t gc_max_waves_per_simd;
    uint32_t gc_max_scratch_slots_per_cu;
    uint32_t gc_lds_size;
    uint32_t gc_num_sc_per_se;
    uint32_t gc_num_packer_per_sc;
    uint32_t gc_num_tcp_per_sh;
    uint32_t gc_tcp_size_per_cu;
    uint32_t gc_num_sdp_interface;
    uint32_t gc_num_cu_per_sqc;
    uint32_t gc_instruction_cache_size_per_sqc;
    uint32_t gc_scalar_data_cache_size_per_sqc;
    uint32_t gc_tcc_size;
};

struct harvest_info_header
{
    uint32_t signature;
    uint32_t version;
};

struct harvest_info
{
    uint16_t hw_id;
    uint8_t number_instance;
    uint8_t reserved;
};

struct harvest_table
{
    harvest_info_header header;
    harvest_info list[32];
};

struct mall_info_header
{
    uint32_t table_id;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t size_bytes;
};

struct mall_info_v1_0
{
    mall_info_header header;
    uint32_t mall_size_per_m;
    uint32_t m_s_present;
    uint32_t m_half_use;
    uint32_t m_mall_config;
    uint32_t reserved[5];
};

struct mall_info_v2_0
{
    mall_info_header header;
    uint32_t mall_size_per_umc;
    uint32_t reserved[8];
};

struct vcn_info_header
{
    uint32_t table_id;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t size_bytes;
};

struct vcn_instance_info_v1_0
{
    uint32_t instance_num;
    uint32_t fuse_data; // bitfield: av1_disabled[0], vp9_disabled[1],
                        // hevc_disabled[2], h264_disabled[3]
    uint32_t reserved[2];
};

struct vcn_info_v1_0
{
    vcn_info_header header;
    uint32_t num_of_instances;
    vcn_instance_info_v1_0 instance_info[4];
    uint32_t reserved[4];
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
    nps_instance_info_v1_0 instance_info[12];
};

#pragma pack()

// ---------------------------------------------------------------------------
// HW ID name table (from amdgpu_discovery.c + soc15_hw_ip.h)
// ---------------------------------------------------------------------------

static const std::unordered_map<uint16_t, const char *> hw_id_names = {
    {1, "MP1"},          {2, "MP2"},         {3, "THM"},
    {4, "SMUIO"},        {5, "FUSE"},        {6, "CLKA"},
    {10, "PWR"},         {11, "GC"},         {12, "UVD/VCN"},
    {13, "AUDIO_AZ"},    {14, "ACP"},        {15, "DCI"},
    {16, "DCO"},         {17, "XDMA"},       {18, "DCEAZ"},
    {19, "SDPMUX"},      {20, "NTB"},        {21, "VPE"},
    {24, "IOHC"},        {28, "L2IMU"},      {32, "VCE"},
    {34, "MMHUB"},       {35, "ATHUB"},      {36, "DBGU_NBIO"},
    {37, "DFX"},         {38, "DBGU0"},      {39, "DBGU1"},
    {40, "OSSSYS"},      {41, "HDP"},        {42, "SDMA0"},
    {43, "SDMA1"},       {44, "ISP"},        {45, "DBGU_IO"},
    {46, "DF"},          {47, "CLKB"},       {48, "FCH"},
    {49, "DFX_DAP"},     {50, "L1IMU_PCIE"}, {51, "L1IMU_NBIF"},
    {52, "L1IMU_IOAGR"}, {53, "L1IMU3"},     {54, "L1IMU4"},
    {55, "L1IMU5"},      {56, "L1IMU6"},     {57, "L1IMU7"},
    {58, "L1IMU8"},      {59, "L1IMU9"},     {60, "L1IMU10"},
    {61, "L1IMU11"},     {62, "L1IMU12"},    {63, "L1IMU13"},
    {64, "L1IMU14"},     {65, "L1IMU15"},    {66, "WAFLC"},
    {67, "FCH_USB_PD"},  {68, "SDMA2"},      {69, "SDMA3"},
    {70, "PCIE"},        {80, "PCS"},        {89, "DDCL"},
    {90, "SST"},         {91, "LSDMA"},      {100, "IOAGR"},
    {108, "NBIF"},       {124, "IOAPIC"},    {128, "SYSTEMHUB"},
    {144, "NTBCCP"},     {150, "UMC"},       {168, "SATA"},
    {170, "USB"},        {176, "CCXSEC"},    {200, "XGMI"},
    {216, "XGBE"},       {255, "MP0"},       {271, "DMU"},
    {272, "DIO"},        {274, "DAZ"},
};

static const char *
hw_id_name(uint16_t id)
{
    auto it = hw_id_names.find(id);
    return (it != hw_id_names.end()) ? it->second : "UNKNOWN";
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static bool
check_bounds(const std::vector<uint8_t> &blob, size_t offset, size_t len)
{
    return offset + len <= blob.size();
}

template <typename T>
static const T *
at(const std::vector<uint8_t> &blob, size_t offset)
{
    if (!check_bounds(blob, offset, sizeof(T))) {
        return nullptr;
    }
    return reinterpret_cast<const T *>(blob.data() + offset);
}

static void
print_hex32(const char *label, uint32_t v, int indent = 0)
{
    printf("%*s%-40s 0x%08X (%u)\n", indent, "", label, v, v);
}
static void
print_hex16(const char *label, uint16_t v, int indent = 0)
{
    printf("%*s%-40s 0x%04X (%u)\n", indent, "", label, v, v);
}
static void
print_u32(const char *label, uint32_t v, int indent = 0)
{
    printf("%*s%-40s %u\n", indent, "", label, v);
}
static void
print_u16(const char *label, uint16_t v, int indent = 0)
{
    printf("%*s%-40s %u\n", indent, "", label, v);
}
// ---------------------------------------------------------------------------
// Table printers
// ---------------------------------------------------------------------------

static void
print_binary_header(const binary_header *h)
{
    printf("=== binary_header ===\n");
    print_hex32("binary_signature", h->binary_signature);
    printf("  %-40s %u.%u\n", "version", h->version_major, h->version_minor);
    print_hex16("binary_checksum", h->binary_checksum);
    print_u16("binary_size", h->binary_size);
    printf("  table_list:\n");
    for (int i = 0; i < TOTAL_TABLES; i++) {
        const auto &t = h->table_list[i];
        printf("    [%d] %-12s  offset=0x%04X  checksum=0x%04X  size=0x%04X\n",
               i, table_names[i], t.offset, t.checksum, t.size);
    }
}

static void
print_ip_discovery(const std::vector<uint8_t> &blob, uint16_t table_offset)
{
    printf("\n=== ip_discovery_header (@ 0x%04X) ===\n", table_offset);

    const auto *ihdr = at<ip_discovery_header>(blob, table_offset);
    if (!ihdr) {
        printf("  [out of bounds]\n");
        return;
    }

    print_hex32("signature", ihdr->signature);
    print_u16("version", ihdr->version);
    print_u16("size", ihdr->size);
    print_hex32("id", ihdr->id);
    print_u16("num_dies", ihdr->num_dies);

    bool addr64 = false;
    if (ihdr->version == 4) {
        addr64 = (ihdr->base_addr_64_bit != 0);
        printf("  %-40s %u\n", "base_addr_64_bit",
               (unsigned)ihdr->base_addr_64_bit);
    }

    uint16_t num_dies = ihdr->num_dies;
    if (num_dies > 16) {
        num_dies = 16;
    }

    for (uint16_t d = 0; d < num_dies; d++) {
        uint16_t die_off = ihdr->dies[d].die_offset;
        printf("\n  --- Die %u (die_id=%u, die_offset=0x%04X) ---\n", d,
               ihdr->dies[d].die_id, die_off);

        const auto *dhdr = at<die_header>(blob, die_off);
        if (!dhdr) {
            printf("    [die_header out of bounds]\n");
            continue;
        }

        printf("    die_id=%u  num_ips=%u\n", dhdr->die_id, dhdr->num_ips);

        uint32_t ip_off = die_off + sizeof(die_header);

        for (uint16_t i = 0; i < dhdr->num_ips; i++) {
            if (ip_off + sizeof(ip_v4) > blob.size()) {
                printf("    [ip entry %u out of bounds]\n", i);
                break;
            }

            if (ihdr->version <= 2) {
                const auto *e =
                    reinterpret_cast<const ip *>(blob.data() + ip_off);
                printf("    ip[%u]: hw_id=%-5u (%-14s) inst=%u  %u.%u.%u"
                       "  harvest=%u  num_addr=%u",
                       i, e->hw_id, hw_id_name(e->hw_id), e->number_instance,
                       e->major, e->minor, e->revision, e->harvest,
                       e->num_base_address);
                const uint32_t *addrs =
                    reinterpret_cast<const uint32_t *>(e + 1);
                for (uint8_t a = 0; a < e->num_base_address; a++) {
                    printf("  base[%u]=0x%08X", a, addrs[a]);
                }
                printf("\n");
                ip_off += sizeof(ip) + e->num_base_address * sizeof(uint32_t);
            } else if (ihdr->version == 3) {
                const auto *e =
                    reinterpret_cast<const ip_v3 *>(blob.data() + ip_off);
                printf("    ip[%u]: hw_id=%-5u (%-14s) inst=%u  %u.%u.%u"
                       "  sub_rev=%u  variant=%u  num_addr=%u",
                       i, e->hw_id, hw_id_name(e->hw_id), e->instance_number,
                       e->major, e->minor, e->revision, e->sub_revision,
                       e->variant, e->num_base_address);
                const uint32_t *addrs =
                    reinterpret_cast<const uint32_t *>(e + 1);
                for (uint8_t a = 0; a < e->num_base_address; a++) {
                    printf("  base[%u]=0x%08X", a, addrs[a]);
                }
                printf("\n");
                ip_off +=
                    sizeof(ip_v3) + e->num_base_address * sizeof(uint32_t);
            } else { // v4
                const auto *e =
                    reinterpret_cast<const ip_v4 *>(blob.data() + ip_off);
                printf("    ip[%u]: hw_id=%-5u (%-14s) inst=%u  %u.%u.%u"
                       "  sub_rev=%u  variant=%u  num_addr=%u",
                       i, e->hw_id, hw_id_name(e->hw_id), e->instance_number,
                       e->major, e->minor, e->revision, e->sub_revision,
                       e->variant, e->num_base_address);
                if (addr64) {
                    const uint64_t *addrs =
                        reinterpret_cast<const uint64_t *>(e + 1);
                    for (uint8_t a = 0; a < e->num_base_address; a++) {
                        printf("  base[%u]=0x%016llX", a,
                               (unsigned long long)addrs[a]);
                    }
                    ip_off +=
                        sizeof(ip_v4) + e->num_base_address * sizeof(uint64_t);
                } else {
                    const uint32_t *addrs =
                        reinterpret_cast<const uint32_t *>(e + 1);
                    for (uint8_t a = 0; a < e->num_base_address; a++) {
                        printf("  base[%u]=0x%08X", a, addrs[a]);
                    }
                    ip_off +=
                        sizeof(ip_v4) + e->num_base_address * sizeof(uint32_t);
                }
                printf("\n");
            }
        }
    }
}

static void
print_gc_table(const std::vector<uint8_t> &blob, uint16_t table_offset)
{
    printf("\n=== GC table (@ 0x%04X) ===\n", table_offset);
    if (table_offset == 0) {
        printf("  [not present]\n");
        return;
    }

    const auto *hdr = at<gpu_info_header>(blob, table_offset);
    if (!hdr) {
        printf("  [out of bounds]\n");
        return;
    }

    printf("  table_id=0x%08X  version=%u.%u  size=%u bytes\n", hdr->table_id,
           hdr->version_major, hdr->version_minor, hdr->size);

#define FIELD(s, f) print_u32(#f, s->f, 4)

    if (hdr->version_major == 1) {
        if (hdr->version_minor == 0) {
            const auto *gc = at<gc_info_v1_0>(blob, table_offset);
            if (!gc) {
                printf("  [truncated]\n");
                return;
            }
            FIELD(gc, gc_num_se);
            FIELD(gc, gc_num_wgp0_per_sa);
            FIELD(gc, gc_num_wgp1_per_sa);
            FIELD(gc, gc_num_rb_per_se);
            FIELD(gc, gc_num_gl2c);
            FIELD(gc, gc_num_gprs);
            FIELD(gc, gc_num_max_gs_thds);
            FIELD(gc, gc_gs_table_depth);
            FIELD(gc, gc_gsprim_buff_depth);
            FIELD(gc, gc_parameter_cache_depth);
            FIELD(gc, gc_double_offchip_lds_buffer);
            FIELD(gc, gc_wave_size);
            FIELD(gc, gc_max_waves_per_simd);
            FIELD(gc, gc_max_scratch_slots_per_cu);
            FIELD(gc, gc_lds_size);
            FIELD(gc, gc_num_sc_per_se);
            FIELD(gc, gc_num_sa_per_se);
            FIELD(gc, gc_num_packer_per_sc);
            FIELD(gc, gc_num_gl2a);
        } else if (hdr->version_minor == 1) {
            const auto *gc = at<gc_info_v1_1>(blob, table_offset);
            if (!gc) {
                printf("  [truncated]\n");
                return;
            }
            FIELD(gc, gc_num_se);
            FIELD(gc, gc_num_wgp0_per_sa);
            FIELD(gc, gc_num_wgp1_per_sa);
            FIELD(gc, gc_num_rb_per_se);
            FIELD(gc, gc_num_gl2c);
            FIELD(gc, gc_num_gprs);
            FIELD(gc, gc_num_max_gs_thds);
            FIELD(gc, gc_gs_table_depth);
            FIELD(gc, gc_gsprim_buff_depth);
            FIELD(gc, gc_parameter_cache_depth);
            FIELD(gc, gc_double_offchip_lds_buffer);
            FIELD(gc, gc_wave_size);
            FIELD(gc, gc_max_waves_per_simd);
            FIELD(gc, gc_max_scratch_slots_per_cu);
            FIELD(gc, gc_lds_size);
            FIELD(gc, gc_num_sc_per_se);
            FIELD(gc, gc_num_sa_per_se);
            FIELD(gc, gc_num_packer_per_sc);
            FIELD(gc, gc_num_gl2a);
            FIELD(gc, gc_num_tcp_per_sa);
            FIELD(gc, gc_num_sdp_interface);
            FIELD(gc, gc_num_tcps);
        } else if (hdr->version_minor == 2) {
            const auto *gc = at<gc_info_v1_2>(blob, table_offset);
            if (!gc) {
                printf("  [truncated]\n");
                return;
            }
            FIELD(gc, gc_num_se);
            FIELD(gc, gc_num_wgp0_per_sa);
            FIELD(gc, gc_num_wgp1_per_sa);
            FIELD(gc, gc_num_rb_per_se);
            FIELD(gc, gc_num_gl2c);
            FIELD(gc, gc_num_gprs);
            FIELD(gc, gc_num_max_gs_thds);
            FIELD(gc, gc_gs_table_depth);
            FIELD(gc, gc_gsprim_buff_depth);
            FIELD(gc, gc_parameter_cache_depth);
            FIELD(gc, gc_double_offchip_lds_buffer);
            FIELD(gc, gc_wave_size);
            FIELD(gc, gc_max_waves_per_simd);
            FIELD(gc, gc_max_scratch_slots_per_cu);
            FIELD(gc, gc_lds_size);
            FIELD(gc, gc_num_sc_per_se);
            FIELD(gc, gc_num_sa_per_se);
            FIELD(gc, gc_num_packer_per_sc);
            FIELD(gc, gc_num_gl2a);
            FIELD(gc, gc_num_tcp_per_sa);
            FIELD(gc, gc_num_sdp_interface);
            FIELD(gc, gc_num_tcps);
            FIELD(gc, gc_num_tcp_per_wpg);
            FIELD(gc, gc_tcp_l1_size);
            FIELD(gc, gc_num_sqc_per_wgp);
            FIELD(gc, gc_l1_instruction_cache_size_per_sqc);
            FIELD(gc, gc_l1_data_cache_size_per_sqc);
            FIELD(gc, gc_gl1c_per_sa);
            FIELD(gc, gc_gl1c_size_per_instance);
            FIELD(gc, gc_gl2c_per_gpu);
        } else if (hdr->version_minor == 3) {
            const auto *gc = at<gc_info_v1_3>(blob, table_offset);
            if (!gc) {
                printf("  [truncated]\n");
                return;
            }
            FIELD(gc, gc_num_se);
            FIELD(gc, gc_num_wgp0_per_sa);
            FIELD(gc, gc_num_wgp1_per_sa);
            FIELD(gc, gc_num_rb_per_se);
            FIELD(gc, gc_num_gl2c);
            FIELD(gc, gc_num_gprs);
            FIELD(gc, gc_num_max_gs_thds);
            FIELD(gc, gc_gs_table_depth);
            FIELD(gc, gc_gsprim_buff_depth);
            FIELD(gc, gc_parameter_cache_depth);
            FIELD(gc, gc_double_offchip_lds_buffer);
            FIELD(gc, gc_wave_size);
            FIELD(gc, gc_max_waves_per_simd);
            FIELD(gc, gc_max_scratch_slots_per_cu);
            FIELD(gc, gc_lds_size);
            FIELD(gc, gc_num_sc_per_se);
            FIELD(gc, gc_num_sa_per_se);
            FIELD(gc, gc_num_packer_per_sc);
            FIELD(gc, gc_num_gl2a);
            FIELD(gc, gc_num_tcp_per_sa);
            FIELD(gc, gc_num_sdp_interface);
            FIELD(gc, gc_num_tcps);
            FIELD(gc, gc_num_tcp_per_wpg);
            FIELD(gc, gc_tcp_l1_size);
            FIELD(gc, gc_num_sqc_per_wgp);
            FIELD(gc, gc_l1_instruction_cache_size_per_sqc);
            FIELD(gc, gc_l1_data_cache_size_per_sqc);
            FIELD(gc, gc_gl1c_per_sa);
            FIELD(gc, gc_gl1c_size_per_instance);
            FIELD(gc, gc_gl2c_per_gpu);
            FIELD(gc, gc_tcp_size_per_cu);
            FIELD(gc, gc_tcp_cache_line_size);
            FIELD(gc, gc_instruction_cache_size_per_sqc);
            FIELD(gc, gc_instruction_cache_line_size);
            FIELD(gc, gc_scalar_data_cache_size_per_sqc);
            FIELD(gc, gc_scalar_data_cache_line_size);
            FIELD(gc, gc_tcc_size);
            FIELD(gc, gc_tcc_cache_line_size);
        } else {
            printf("  [unknown v1.%u -- showing header only]\n",
                   hdr->version_minor);
        }
    } else if (hdr->version_major == 2) {
        if (hdr->version_minor == 0) {
            const auto *gc = at<gc_info_v2_0>(blob, table_offset);
            if (!gc) {
                printf("  [truncated]\n");
                return;
            }
            FIELD(gc, gc_num_se);
            FIELD(gc, gc_num_cu_per_sh);
            FIELD(gc, gc_num_sh_per_se);
            FIELD(gc, gc_num_rb_per_se);
            FIELD(gc, gc_num_tccs);
            FIELD(gc, gc_num_gprs);
            FIELD(gc, gc_num_max_gs_thds);
            FIELD(gc, gc_gs_table_depth);
            FIELD(gc, gc_gsprim_buff_depth);
            FIELD(gc, gc_parameter_cache_depth);
            FIELD(gc, gc_double_offchip_lds_buffer);
            FIELD(gc, gc_wave_size);
            FIELD(gc, gc_max_waves_per_simd);
            FIELD(gc, gc_max_scratch_slots_per_cu);
            FIELD(gc, gc_lds_size);
            FIELD(gc, gc_num_sc_per_se);
            FIELD(gc, gc_num_packer_per_sc);
        } else if (hdr->version_minor == 1) {
            const auto *gc = at<gc_info_v2_1>(blob, table_offset);
            if (!gc) {
                printf("  [truncated]\n");
                return;
            }
            FIELD(gc, gc_num_se);
            FIELD(gc, gc_num_cu_per_sh);
            FIELD(gc, gc_num_sh_per_se);
            FIELD(gc, gc_num_rb_per_se);
            FIELD(gc, gc_num_tccs);
            FIELD(gc, gc_num_gprs);
            FIELD(gc, gc_num_max_gs_thds);
            FIELD(gc, gc_gs_table_depth);
            FIELD(gc, gc_gsprim_buff_depth);
            FIELD(gc, gc_parameter_cache_depth);
            FIELD(gc, gc_double_offchip_lds_buffer);
            FIELD(gc, gc_wave_size);
            FIELD(gc, gc_max_waves_per_simd);
            FIELD(gc, gc_max_scratch_slots_per_cu);
            FIELD(gc, gc_lds_size);
            FIELD(gc, gc_num_sc_per_se);
            FIELD(gc, gc_num_packer_per_sc);
            FIELD(gc, gc_num_tcp_per_sh);
            FIELD(gc, gc_tcp_size_per_cu);
            FIELD(gc, gc_num_sdp_interface);
            FIELD(gc, gc_num_cu_per_sqc);
            FIELD(gc, gc_instruction_cache_size_per_sqc);
            FIELD(gc, gc_scalar_data_cache_size_per_sqc);
            FIELD(gc, gc_tcc_size);
        } else {
            printf("  [unknown v2.%u -- showing header only]\n",
                   hdr->version_minor);
        }
    } else {
        printf("  [unknown version %u.%u -- showing header only]\n",
               hdr->version_major, hdr->version_minor);
    }
#undef FIELD
}

static void
print_harvest_table(const std::vector<uint8_t> &blob, uint16_t table_offset)
{
    printf("\n=== harvest_table (@ 0x%04X) ===\n", table_offset);
    if (table_offset == 0) {
        printf("  [not present]\n");
        return;
    }

    const auto *ht = at<harvest_table>(blob, table_offset);
    if (!ht) {
        printf("  [out of bounds]\n");
        return;
    }

    printf("  signature=0x%08X  version=%u\n", ht->header.signature,
           ht->header.version);

    bool any = false;
    for (int i = 0; i < 32; i++) {
        if (ht->list[i].hw_id == 0) {
            continue;
        }
        printf("  list[%2d]: hw_id=%-5u (%-14s) instance=%u\n", i,
               ht->list[i].hw_id, hw_id_name(ht->list[i].hw_id),
               ht->list[i].number_instance);
        any = true;
    }
    if (!any) {
        printf("  [no harvested IPs]\n");
    }
}

static void
print_vcn_table(const std::vector<uint8_t> &blob, uint16_t table_offset)
{
    printf("\n=== vcn_info (@ 0x%04X) ===\n", table_offset);
    if (table_offset == 0) {
        printf("  [not present]\n");
        return;
    }

    const auto *v = at<vcn_info_v1_0>(blob, table_offset);
    if (!v) {
        printf("  [out of bounds]\n");
        return;
    }

    printf("  table_id=0x%08X  version=%u.%u  size=%u bytes\n",
           v->header.table_id, v->header.version_major,
           v->header.version_minor, v->header.size_bytes);
    printf("  num_of_instances=%u\n", v->num_of_instances);

    uint32_t n = v->num_of_instances;
    if (n > 4) {
        n = 4;
    }
    for (uint32_t i = 0; i < n; i++) {
        const auto &inst = v->instance_info[i];
        uint32_t fd = inst.fuse_data;
        printf("  instance[%u]: vcn_num=%u  fuses: av1=%s vp9=%s hevc=%s "
               "h264=%s\n",
               i, inst.instance_num, (fd & 1) ? "disabled" : "enabled",
               (fd & 2) ? "disabled" : "enabled",
               (fd & 4) ? "disabled" : "enabled",
               (fd & 8) ? "disabled" : "enabled");
    }
}

static void
print_mall_table(const std::vector<uint8_t> &blob, uint16_t table_offset)
{
    printf("\n=== mall_info (@ 0x%04X) ===\n", table_offset);
    if (table_offset == 0) {
        printf("  [not present]\n");
        return;
    }

    const auto *hdr = at<mall_info_header>(blob, table_offset);
    if (!hdr) {
        printf("  [out of bounds]\n");
        return;
    }

    printf("  table_id=0x%08X  version=%u.%u  size=%u bytes\n", hdr->table_id,
           hdr->version_major, hdr->version_minor, hdr->size_bytes);

    if (hdr->version_major == 1 && hdr->version_minor == 0) {
        const auto *m = at<mall_info_v1_0>(blob, table_offset);
        if (!m) {
            printf("  [truncated]\n");
            return;
        }
        printf("  mall_size_per_m=0x%X  m_s_present=0x%X  m_half_use=0x%X  "
               "m_mall_config=0x%X\n",
               m->mall_size_per_m, m->m_s_present, m->m_half_use,
               m->m_mall_config);
    } else if (hdr->version_major == 2 && hdr->version_minor == 0) {
        const auto *m = at<mall_info_v2_0>(blob, table_offset);
        if (!m) {
            printf("  [truncated]\n");
            return;
        }
        printf("  mall_size_per_umc=0x%X\n", m->mall_size_per_umc);
    } else {
        printf("  [unknown version %u.%u]\n", hdr->version_major,
               hdr->version_minor);
    }
}

static void
print_nps_table(const std::vector<uint8_t> &blob, uint16_t table_offset)
{
    printf("\n=== nps_info (@ 0x%04X) ===\n", table_offset);
    if (table_offset == 0) {
        printf("  [not present]\n");
        return;
    }

    const auto *n = at<nps_info_v1_0>(blob, table_offset);
    if (!n) {
        printf("  [out of bounds]\n");
        return;
    }

    printf("  table_id=0x%08X  version=%u.%u  size=%u bytes\n",
           n->header.table_id, n->header.version_major,
           n->header.version_minor, n->header.size_bytes);
    printf("  nps_type=%u  count=%u\n", n->nps_type, n->count);

    uint32_t cnt = n->count;
    if (cnt > 12) {
        cnt = 12;
    }
    for (uint32_t i = 0; i < cnt; i++) {
        printf("  instance[%u]: base=0x%016llX  limit=0x%016llX\n", i,
               (unsigned long long)n->instance_info[i].base_address,
               (unsigned long long)n->instance_info[i].limit_address);
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int
main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <discovery_binary>\n", argv[0]);
        return 1;
    }

    std::ifstream f(argv[1], std::ios::binary | std::ios::ate);
    if (!f) {
        fprintf(stderr, "Cannot open '%s'\n", argv[1]);
        return 1;
    }
    auto fsize = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> blob(fsize);
    if (!f.read(reinterpret_cast<char *>(blob.data()), fsize)) {
        fprintf(stderr, "Read error\n");
        return 1;
    }

    printf("File: %s  (%zu bytes)\n\n", argv[1], blob.size());

    // 1. binary_header
    const auto *bhdr = at<binary_header>(blob, 0);
    if (!bhdr) {
        fprintf(stderr, "File too small to contain binary_header\n");
        return 1;
    }
    if (bhdr->binary_signature != BINARY_SIGNATURE) {
        fprintf(
            stderr,
            "Warning: unexpected binary_signature 0x%08X (expected 0x%08X)\n",
            bhdr->binary_signature, BINARY_SIGNATURE);
    }

    print_binary_header(bhdr);

    // 2. Each sub-table
    print_ip_discovery(blob, bhdr->table_list[IP_DISCOVERY].offset);
    print_gc_table(blob, bhdr->table_list[GC].offset);
    print_harvest_table(blob, bhdr->table_list[HARVEST_INFO].offset);
    print_vcn_table(blob, bhdr->table_list[VCN_INFO].offset);
    print_mall_table(blob, bhdr->table_list[MALL_INFO].offset);
    print_nps_table(blob, bhdr->table_list[NPS_INFO].offset);

    return 0;
}
