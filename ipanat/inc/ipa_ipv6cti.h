/*
 * Copyright (c) 2018, 2020 The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *  * Neither the name of The Linux Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Changes from Qualcomm Technologies, Inc. are provided under the following license:
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef IPA_IPV6CTI_H
#define IPA_IPV6CTI_H

#include "ipa_table.h"
#include "ipa_mem_descriptor.h"
#include "ipa_nat_utils.h"

#include <sys/ioctl.h>

#undef CT_MAKE_TBL_HDL
#define CT_MAKE_TBL_HDL(hdl, mt) \
	((mt) << 31 | (hdl))

#undef CT_BREAK_TBL_HDL
#define CT_BREAK_TBL_HDL(hdl_in, mt, hdl_out) \
	do { \
		mt      = (hdl_in >> 31) & 0x0000000001; \
		hdl_out = (hdl_in)       & 0x00000000FF; \
	} while ( 0 )

#undef CT_VALID_TBL_HDL
#define CT_VALID_TBL_HDL(h) \
	(((h) & 0x00000000FF) == IPA_IPV6CT_MAX_TBLS)

#undef min
#define min(a, b) ((a) < (b)) ? (a) : (b)

#undef max
#define max(a, b) ((a) > (b)) ? (a) : (b)

#define IPA_IPV6CT_MAX_TBLS   1

#define IPA_IPV6CT_RULE_FLAG_FIELD_OFFSET        34
#define IPA_IPV6CT_RULE_NEXT_FIELD_OFFSET        40
#define IPA_IPV6CT_RULE_PROTO_FIELD_OFFSET       38

#define IPA_IPV6CT_FLAG_ENABLE_BIT  1

#define IPA_IPV6CT_DIRECTION_ALLOW_BIT  1
#define IPA_IPV6CT_DIRECTION_DISALLOW_BIT 0

#define IPA_IPV6CT_INVALID_PROTO_FIELD_VALUE 0xFF00
#define IPA_IPV6CT_INVALID_PROTO_FIELD_CMP   0xFF

typedef enum
{
	IPA_IPV6CT_TABLE_FLAGS,
	IPA_IPV6CT_TABLE_NEXT_INDEX,
	IPA_IPV6CT_TABLE_PROTOCOL,
	IPA_IPV6CT_TABLE_DMA_CMD_MAX
} ipa_ipv6ct_table_dma_cmd_type;

/*------------------------  IPV6CT Table Entry  ---------------------------------------------------

  -------------------------------------------------------------------------------------------------
  |     7     |      6      |     5     |     4     |     3     |     2     |     1     |     0     |
  ---------------------------------------------------------------------------------------------------
  |                              Outbound Src IPv6 Address (8 LSB Bytes)                            |
  ---------------------------------------------------------------------------------------------------
  |                              Outbound Src IPv6 Address (8 MSB Bytes)                            |
  ---------------------------------------------------------------------------------------------------
  |                              Outbound Dest IPv6 Address (8 LSB Bytes)                           |
  ---------------------------------------------------------------------------------------------------
  |                              Outbound Dest IPv6 Address (8 MSB Bytes)                           |
  ---------------------------------------------------------------------------------------------------
  | Protocol  |           TimeStamp (3B)            |       Flags (2B)      |Rsvd   |S |uC activatio|
  |    (1B)   |                                     |Enable|Redirect|Resv   |[15:14]|13|Index [12:0]|
  ---------------------------------------------------------------------------------------------------
  |Reserved   |Settings     |     Src Port (2B)     |     Dest Port (2B)    |    Next Index (2B)    |
  |  (1B)     |  (1B)       |                       |                       |                       |
  ---------------------------------------------------------------------------------------------------
  |           SW Specific Parameters(4B)            |                   Reserved (4B)               |
  |     Prev Index (2B)     |    Reserved (2B)      |                                               |
  ---------------------------------------------------------------------------------------------------
  |                                             Reserved (8B)                                       |
  ---------------------------------------------------------------------------------------------------

  Settings(1B)
 -----------------------------------------------
 |IN Allowed|OUT Allowed|Reserved|uC processing|
 |[7:7]     |[6:6]      |[5:1]   |[0:0]        |
 -----------------------------------------------

  Dont change below structure definition.
  It should be same as above(little endian order)
  -------------------------------------------------------------------------------------------------*/
typedef struct ipa_ipv6ct_hw_entry
{
	uint64_t src_ipv6_lsb : 64;
	uint64_t src_ipv6_msb : 64;
	uint64_t dest_ipv6_lsb : 64;
	uint64_t dest_ipv6_msb : 64;

	uint64_t uc_activation_index : 13;
	uint64_t s : 1;
	uint64_t rsvd1 : 16;
	uint64_t redirect : 1;
	uint64_t enable : 1;
	uint64_t time_stamp : 24;
	uint64_t protocol : 8;

	uint64_t next_index : 16;
	uint64_t dest_port : 16;
	uint64_t src_port : 16;
	uint64_t ucp : 1;
	uint64_t rsvd2 : 5;
	uint64_t out_allowed : 1;
	uint64_t in_allowed : 1;
	uint64_t rsvd3 : 8;

	uint64_t rsvd4 : 48;
	uint64_t prev_index : 16;

	uint64_t rsvd5 : 64;
} ipa_ipv6ct_hw_entry;

/*
	----------------------
	|    1    |    0     |
	----------------------
	|     Flags(2B)      |
	|Enable|Redirect|Resv|
	----------------------
*/
typedef struct
{
	uint16_t rsvd1 : 14;
	uint16_t redirect : 1;
	uint16_t enable : 1;
} ipa_ipv6ct_flags;

struct ipa_ct_ip6_table_cache {
	ipa_mem_descriptor mem_desc;
	ipa_table table;
	ipa_table_dma_cmd_helper table_dma_cmd_helpers[IPA_IPV6CT_TABLE_DMA_CMD_MAX];
};

struct ipa_ct_cache {
	ipa_descriptor* ipa_desc;
	struct ipa_ct_ip6_table_cache ip6_tbl[IPA_IPV6CT_MAX_TBLS];
	uint8_t table_cnt;
	enum ipa3_nat_mem_in nmi;
};

typedef enum
{
	USE_NAT_TABLE   = 0,

	USE_MAX
} CtWhichTbl2Use;

#define CT_VALID_WHICHTBL2USE(w) \
	( (w) >= USE_NAT_TABLE && (w) < USE_MAX )

#endif

/*
 * The following used for retrieving table stats.
 */
typedef struct
{
	enum ipa3_nat_mem_in nmi;
	uint32_t tot_ents;
	uint32_t tot_base_ents;
	uint32_t tot_base_ents_filled;
	uint32_t tot_expn_ents;
	uint32_t tot_expn_ents_filled;
	uint32_t tot_chains;
	uint32_t min_chain_len;
	uint32_t max_chain_len;
	float    avg_chain_len;
} ipa_cti_tbl_stats;

typedef struct
{
	CtWhichTbl2Use        which;
	uint32_t            tot_for_avg;
	ipa_cti_tbl_stats* stats_ptr;
} ct_chain_stat_help;
int ipa_cti_add_ipv6_tbl(
	const char* mem_type_ptr,
	uint16_t    number_of_entries,
	uint32_t*   tbl_hdl);

int ipa_cti_del_ipv6_tbl(
	uint32_t tbl_hdl);

int ipa_cti_add_ipv6_rule(
	uint32_t                 tbl_hdl,
	const ipa_ipv6ct_rule* clnt_rule,
	uint32_t*                rule_hdl );

int ipa_cti_del_ipv6_rule(
	uint32_t tbl_hdl,
	uint32_t rule_hdl );

int ipa_cti_query_timestamp(
	uint32_t  tbl_hdl,
	uint32_t  rule_hdl,
	uint32_t* time_stamp);

static int ipa_ipv6ct_post_init_cmd(
	struct ipa_ct_cache*           ct_cache_ptr,
	struct ipa_ct_ip6_table_cache* ct_table,
	uint8_t tbl_index,
	bool focus_change);

/**
 * ipa_ct_vote_clock() - used for voting clock
 * @vote_type: [in] desired vote type
 */
int ipa_ct_vote_clock(enum ipa_app_clock_vote_type vote_type);

int ipa_cti_get_sram_size(uint32_t* size_ptr);

int ipa_calc_num_sram_ct_table_entries(
        uint32_t  sram_size,
        uint32_t  table1_ent_size,
        uint16_t* num_entries_ptr);

int ipa_ipv6ct_clear_table(uint32_t tbl_hdl);

int ipa_ipv6ct_walk_table(
        uint32_t          tbl_hdl,
        CtWhichTbl2Use      which,
        ipa_table_walk_cb walk_cb,
        void*             arb_data_ptr );

int ipa_ipv6ct_stats_table(
        uint32_t            tbl_hdl,
        ipa_cti_tbl_stats* ct_stats_ptr);

int ipa_ipv6ct_copy_table(
        uint32_t          src_tbl_hdl,
        uint32_t          dst_tbl_hdl,
        ipa_table_walk_cb copy_cb );

static inline char* prep_ct_rule_4print(
	ipa_ipv6ct_hw_entry* rule_ptr,
	char*                buf_ptr,
	uint32_t             buf_sz )
{
	if ( rule_ptr && buf_ptr && buf_sz )
	{
		snprintf(
			buf_ptr, buf_sz,
			"CT RULE: "
			"src_msb(0x%016X)"
			"src_msb(0x%016X)"
			"dest_msb(0x%016X) "
			"dest_lsb(0x%016X)"
			"ucp(0x%04X) "
			"s(0x%02X) "
			"uc_act_idx(0x%04X) "
			"src_port(0x%04X) "
			"dest_port(0x%04X) "
			"protocol(0x%02X)",
			rule_ptr->src_ipv6_msb,
			rule_ptr->src_ipv6_lsb,
			rule_ptr->dest_ipv6_msb,
			rule_ptr->dest_ipv6_lsb,
			rule_ptr->ucp,
			rule_ptr->s,
			rule_ptr->uc_activation_index,
			rule_ptr->src_port,
			rule_ptr->dest_port,
			rule_ptr->protocol);
	}

	return buf_ptr;
}
