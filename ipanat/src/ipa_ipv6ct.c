/*
 * Copyright (c) 2018-2020 The Linux Foundation. All rights reserved.
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
#include "ipa_ipv6ct.h"
#include "ipa_ipv6cti.h"

#include <sys/ioctl.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/msm_ipa.h>

#define IPA_IPV6CT_DEBUG_FILE_PATH "/sys/kernel/debug/ipa/ipv6ct"
#define IPA_UC_ACT_DEBUG_FILE_PATH "/sys/kernel/debug/ipa/uc_act_table"
#define IPA_IPV6CT_TABLE_NAME "IPA IPv6CT table"
#define IPA_MAX_DMA_ENTRIES_FOR_ADD 2
#define IPA_MAX_DMA_ENTRIES_FOR_DEL 2

static struct ipa_ct_cache ipv6_ct_cache[IPA_NAT_MEM_IN_MAX];

static struct ipa_ct_cache *active_ct_cache_ptr = NULL;

static int ipa_ipv6ct_create_table(
	struct ipa_ct_cache*           ct_cache_ptr,
	struct ipa_ct_ip6_table_cache* ct_table,
	uint16_t number_of_entries,
	uint8_t table_index);

static int ipa_ipv6ct_destroy_table(
	struct ipa_ct_cache*		   ct_cache_ptr,
	struct ipa_ct_ip6_table_cache* ct_table);

static void ipa_ipv6ct_create_table_dma_cmd_helpers(
	struct ipa_ct_ip6_table_cache* ct_table,
	uint8_t table_indx );

static int ipa_ipv6ct_post_dma_cmd(
	struct ipa_ct_cache*        ct_cache_ptr,
	struct ipa_ioc_nat_dma_cmd* cmd);

static uint16_t ipa_ipv6ct_hash(const ipa_ipv6ct_rule* rule, uint16_t size);

static uint16_t ipa_ipv6ct_xor_segments(uint64_t num);

static int table_entry_is_valid(void* entry);

static uint16_t table_entry_get_next_index(void* entry);

static uint16_t table_entry_get_prev_index(void* entry, uint16_t entry_index, void* meta, uint16_t base_table_size);

static void table_entry_set_prev_index(void* entry, uint16_t entry_index, uint16_t prev_index,
	void* meta, uint16_t base_table_size);

static int table_entry_head_insert(void* entry, void* user_data, uint16_t* dma_command_data);

static int table_entry_tail_insert(void* entry, void* user_data);

static uint16_t table_entry_get_delete_head_dma_command_data(void* head, void* next_entry);

extern pthread_mutex_t ipv6ct_mutex;

static ipa_table_entry_interface entry_interface =
{
	table_entry_is_valid,
	table_entry_get_next_index,
	table_entry_get_prev_index,
	table_entry_set_prev_index,
	table_entry_head_insert,
	table_entry_tail_insert,
	table_entry_get_delete_head_dma_command_data
};

int ipa_cti_get_sram_size(
	uint32_t* size_ptr)
{
	struct ipa_ct_cache* ct_cache_ptr =
		&ipv6_ct_cache[IPA_NAT_MEM_IN_SRAM];
	struct ipa_nat_in_sram_info ct_sram_info;
	int ret;

	IPADBG("In\n");

	if (pthread_mutex_lock(&ipv6ct_mutex)) {
		IPAERR("unable to lock the ct mutex\n");
		ret = -EINVAL;
		goto bail;
	}

	if ( ! ct_cache_ptr->ipa_desc ) {
		ct_cache_ptr->ipa_desc = ipa_descriptor_open();
		if ( ct_cache_ptr->ipa_desc == NULL ) {
			IPAERR("failed to open IPA driver file descriptor\n");
			ret = -EIO;
			goto unlock;
		}
	}

	memset(&ct_sram_info, 0, sizeof(ct_sram_info));

	ret = ioctl(ct_cache_ptr->ipa_desc->fd,
				IPA_IOC_GET_CT_IN_SRAM_INFO,
				&ct_sram_info);

	if (ret) {
		IPAERR("CT_IN_SRAM_INFO ioctl failure %d on IPA fd %d\n",
			   ret, ct_cache_ptr->ipa_desc->fd);
		goto unlock;
	}

	if ( (*size_ptr = ct_sram_info.sram_mem_available_for_nat) == 0 )
	{
		IPAERR("sram_mem_available_for_ct is zero\n");
		ret = -EINVAL;
		goto unlock;
	}

unlock:
	if (pthread_mutex_unlock(&ipv6ct_mutex)) {
		IPAERR("unable to unlock the nat mutex\n");
		ret = (ret) ? ret : -EPERM;
	}

bail:
	IPADBG("Out\n");

	return ret;
}

int ipa_ct_add_ipv6_tbl(uint16_t number_of_entries, const char *mem_type_ptr, uint32_t* table_handle)
{

	int ret;

	if (table_handle == NULL || mem_type_ptr == NULL || number_of_entries == 0) {
		IPAERR(
			"Invalid parameters tbl_hdl=%pK mem_type_ptr=%p number_of_entries=%d\n",
			table_handle,
			mem_type_ptr,
			number_of_entries);
		return -EINVAL;
	}

	*table_handle = 0;

	ret = ipa_cti_add_ipv6_tbl(
		mem_type_ptr, number_of_entries, table_handle);

	if (ret) {
		IPAERR("unable to add CT table\n");
		return ret;
	}

	IPADBG("Returning table handle 0x%x\n", *table_handle);

	return ret;
}

int ipa_ct_del_ipv6_tbl(uint32_t table_handle)
{

	int ret;

	if (table_handle == IPA_TABLE_INVALID_ENTRY)
	{
		IPAERR("invalid table handle %d passed\n", table_handle);
		return -EINVAL;
	}
	IPADBG("Passed Table Handle: 0x%x\n", table_handle);

	ret = ipa_cti_del_ipv6_tbl(table_handle);

	if (ret) {
		IPAERR("unable to del CT table\n");
		return ret;
	}

	return ret;
}

int ipa_ct_add_ipv6_rule(
	uint32_t tbl_hdl,
	const ipa_ipv6ct_rule *clnt_rule,
	uint32_t *rule_hdl)
{
	int result = -EINVAL;

	if ( tbl_hdl == IPA_TABLE_INVALID_ENTRY ||
		 rule_hdl == NULL ||
		 clnt_rule == NULL ) {
		IPAERR(
			"Invalid parameters tbl_hdl=%d clnt_rule=%pK rule_hdl=%pK\n",
			tbl_hdl, clnt_rule, rule_hdl);
		return result;
	}

	IPADBG("Passed Table handle: 0x%x\n", tbl_hdl);

	if (ipa_cti_add_ipv6_rule(tbl_hdl, clnt_rule, rule_hdl)) {
		return result;
	}

	IPADBG("Returning rule handle %u\n", *rule_hdl);

	return 0;
}

int ipa_ct_del_ipv6_rule(
	uint32_t tbl_hdl,
	uint32_t rule_hdl)
{
	int result = -EINVAL;

	if ( tbl_hdl == IPA_TABLE_INVALID_ENTRY || rule_hdl == IPA_TABLE_INVALID_ENTRY )
	{
		IPAERR("Invalid parameters tbl_hdl=0x%08X rule_hdl=0x%08X\n",
			   tbl_hdl, rule_hdl);
		return result;
	}

	IPADBG("Passed Table: 0x%08X and rule handle 0x%08X\n", tbl_hdl, rule_hdl);

	result = ipa_cti_del_ipv6_rule(tbl_hdl, rule_hdl);
	if (result) {
		IPAERR(
			"Unable to delete rule with handle 0x%08X "
			"from hw for CT table with handle 0x%08X\n",
			rule_hdl, tbl_hdl);
		return result;
	}

	return 0;
}

int ipa_ct_query_timestamp(
	uint32_t tbl_hdl,
	uint32_t rule_hdl,
	uint32_t* time_stamp)
{
	int result = -EINVAL;

	if ( tbl_hdl == IPA_TABLE_INVALID_ENTRY || rule_hdl == IPA_TABLE_INVALID_ENTRY || time_stamp == NULL)
	{
		IPAERR("Invalid parameters tbl_hdl=0x%08X rule_hdl=0x%08X\n",
			   tbl_hdl, rule_hdl);
		return result;
	}

	IPADBG("Passed Table: 0x%08X and rule handle 0x%08X\n", tbl_hdl, rule_hdl);

	result = ipa_cti_query_timestamp(tbl_hdl, rule_hdl, time_stamp);
	if (result) {
		IPAERR(
			"Unable to delete rule with handle 0x%08X "
			"from hw for CT table with handle 0x%08X\n",
			rule_hdl, tbl_hdl);
		return result;
	}

	return 0;
}

static int ipa_ipv6ct_post_init_cmd(
	struct ipa_ct_cache*           ct_cache_ptr,
	struct ipa_ct_ip6_table_cache* ct_table,
	uint8_t tbl_index,
	bool focus_change)
{
	struct ipa_ioc_ipv6ct_init cmd;
	int ret;

	IPADBG("In\n");

	IPADBG("ct_cache_ptr(%p) ct_table(%p) tbl_index(%u) focus_change(%u)\n",
		   ct_cache_ptr, ct_table, tbl_index, focus_change);

	memset(&cmd, 0, sizeof(cmd));

	cmd.tbl_index = tbl_index;
	cmd.focus_change = focus_change;

	cmd.base_table_offset = ct_table->mem_desc.addr_offset;
	cmd.expn_table_offset = cmd.base_table_offset + (ct_table->table.table_entries * sizeof(ipa_ipv6ct_hw_entry));
	cmd.mem_type = ct_cache_ptr->nmi;

	/* Driver/HW expected base table size to be power^2-1 due to H/W hash calculation */
	cmd.table_entries = ct_table->table.table_entries - 1;
	cmd.expn_table_entries = ct_table->table.expn_table_entries;

	ret = ioctl(ct_cache_ptr->ipa_desc->fd, IPA_IOC_INIT_IPV6CT_TABLE, &cmd);
	if (ret)
	{
		IPAERR("unable to post init cmd Error: %d IPA fd %d\n", ret, ct_cache_ptr->ipa_desc->fd);
		return ret;
	}

	IPADBG("Posted IPA_IOC_INIT_IPV6CT_TABLE to kernel successfully\n");
	return 0;
}

int ipa_ipv6ct_post_init_cmd_int(
	uint32_t tbl_hdl )
{
	enum ipa3_nat_mem_in            nmi = 0;
	struct ipa_ct_cache*           ct_cache_ptr;
	struct ipa_ct_ip6_table_cache* ct_table;
	int ret;

	IPADBG("In\n");

	CT_BREAK_TBL_HDL(tbl_hdl, nmi, tbl_hdl);

	if ( ! IPA_VALID_NAT_MEM_IN(nmi) ) {
		IPAERR("Bad cache type argument passed\n");
		ret = -EINVAL;
		goto bail;
	}

	IPADBG("nmi(%s)\n", ipa3_ct_mem_in_as_str(nmi));

	ct_cache_ptr = &ipv6_ct_cache[nmi];

	if (pthread_mutex_lock(&ipv6ct_mutex)) {
		IPAERR("unable to lock the ct mutex\n");
		ret = -EINVAL;
		goto bail;
	}

	if ( ! ct_cache_ptr->table_cnt ) {
		IPAERR("No initialized table in CT cache\n");
		ret = -EINVAL;
		goto unlock;
	}

	ct_table = &ct_cache_ptr->ip6_tbl[tbl_hdl - 1];

	ret = ipa_ipv6ct_post_init_cmd(
		ct_cache_ptr,
		ct_table,
		tbl_hdl - 1,
		true);

	if (ret) {
		IPAERR("unable to post ct_init command Error %d\n", ret);
		goto unlock;
	}

unlock:
	if (pthread_mutex_unlock(&ipv6ct_mutex)) {
		IPAERR("unable to unlock the ct mutex\n");
		ret = (ret) ? ret : -EPERM;
	}

bail:
	IPADBG("Out\n");

	return ret;
}

/**
 * ipa_ipv6ct_add_tbl() - Adds a new IPv6CT table
 * @number_of_entries: [in] number of IPv6CT entries
 * @table_handle: [out] handle of new IPv6CT table
 *
 * This function creates new IPv6CT table and posts IPv6CT init command to HW
 *
 * Returns:	0  On Success, negative on failure
 */
int ipa_ipv6ct_add_tbl(uint16_t number_of_entries, enum ipa3_nat_mem_in nmi, uint32_t* table_handle)
{
	int ret;
	struct ipa_ct_cache*           ct_cache_ptr;
	struct ipa_ct_ip6_table_cache* ct_table;
	enum ipa3_nat_mem_in           ch_nmi;

	IPADBG("\n");

	if (table_handle == NULL || number_of_entries == 0)
	{
		IPAERR("Invalid parameters table_handle=%pK number_of_entries=%d\n", table_handle, number_of_entries);
		return -EINVAL;
	}

	*table_handle = 0;

	if ( ! IPA_VALID_NAT_MEM_IN(nmi) ) {
		IPAERR("Bad cache type argument passed\n");
		ret = -EINVAL;
		goto bail;
	}

	ct_cache_ptr = &ipv6_ct_cache[nmi];

	if (pthread_mutex_lock(&ipv6ct_mutex)) {
		IPAERR("unable to lock the ct mutex\n");
		ret = -EINVAL;
		goto bail;
	}

	ct_cache_ptr->nmi = nmi;

	if (ct_cache_ptr->table_cnt >= IPA_IPV6CT_MAX_TBLS)
	{
		IPAERR("Can't add addition IPv6 connection tracking table. Maximum %d tables allowed\n", IPA_IPV6CT_MAX_TBLS);
		ret = -EINVAL;
		goto unlock;
	}

	if (!ct_cache_ptr->ipa_desc)
	{
		ct_cache_ptr->ipa_desc = ipa_descriptor_open();
		if (ct_cache_ptr->ipa_desc == NULL)
		{
			IPAERR("failed to open IPA driver file descriptor\n");
			ret = -EIO;
			goto unlock;
		}
	}

	if (ct_cache_ptr->ipa_desc->ver < IPA_HW_v4_0)
	{
		IPAERR("IPv6 connection tracking isn't supported for IPA version %d\n", ct_cache_ptr->ipa_desc->ver);
		ret = -EPERM;
		goto bail_ipa_desc;
	}

	ct_table = &ct_cache_ptr->ip6_tbl[ct_cache_ptr->table_cnt];
	ret = ipa_ipv6ct_create_table(ct_cache_ptr, ct_table, number_of_entries, ct_cache_ptr->table_cnt);
	if (ret)
	{
		IPAERR("unable to create ipv6ct table Error: %d\n", ret);
		goto bail_ipa_desc;
	}

	/* Initialize the ipa hw with ipv6ct table dimensions */
	ret = ipa_ipv6ct_post_init_cmd(ct_cache_ptr, ct_table, ct_cache_ptr->table_cnt, false);
	if (ret)
	{
		IPAERR("unable to post ipv6ct_init command Error %d\n", ret);
		goto bail_ipv6ct_table;
	}

	/* Return table handle */
	ct_cache_ptr->table_cnt++;

	*table_handle = CT_MAKE_TBL_HDL(ct_cache_ptr->table_cnt, nmi);

	IPADBG("Returning table handle 0x%x\n", *table_handle);
	goto unlock;

bail_ipv6ct_table:
	ipa_ipv6ct_destroy_table(ct_cache_ptr, ct_table);
bail_ipa_desc:
	if (!ct_cache_ptr->table_cnt) {
		ipa_descriptor_close(ct_cache_ptr->ipa_desc);
		ct_cache_ptr->ipa_desc = NULL;
	}
unlock:
	if (pthread_mutex_unlock(&ipv6ct_mutex)) {
		IPAERR("unable to unlock the ct mutex\n");
		ret = -EPERM;
		goto bail;
	}

bail:
	IPADBG("Out\n");

	return ret;
}

int ipa_ipv6ct_del_tbl(uint32_t table_handle)
{
	enum ipa3_nat_mem_in           nmi = 0;
	struct ipa_ct_cache*           ct_cache_ptr;
	struct ipa_ct_ip6_table_cache* ct_table;
	int ret;

	IPADBG("In\n");

	CT_BREAK_TBL_HDL(table_handle, nmi, table_handle);

	if (table_handle == IPA_TABLE_INVALID_ENTRY || table_handle > IPA_IPV6CT_MAX_TBLS)
	{
		IPAERR("invalid table handle %d passed\n", table_handle);
		return -EINVAL;
	}
	IPADBG("Passed Table Handle: 0x%x\n", table_handle);

	if ( ! IPA_VALID_NAT_MEM_IN(nmi) ) {
		IPAERR("Bad cache type argument passed\n");
		ret = -EINVAL;
		goto bail;
	}

	if (pthread_mutex_lock(&ipv6ct_mutex))
	{
		IPAERR("unable to lock the ipv6ct mutex\n");
		return -EINVAL;
	}

	ct_cache_ptr = &ipv6_ct_cache[nmi];

	ct_table = &ct_cache_ptr->ip6_tbl[table_handle - 1];

	if (ct_cache_ptr->ipa_desc->ver < IPA_HW_v4_0)
	{
		IPAERR("IPv6 connection tracking isn't supported for IPA version %d\n", ct_cache_ptr->ipa_desc->ver);
		ret = -EINVAL;
		goto unlock;
	}

	if (!ct_table->mem_desc.valid)
	{
		IPAERR("invalid table handle %d\n", table_handle);
		ret = -EINVAL;
		goto unlock;
	}

	ret = ipa_ipv6ct_destroy_table(ct_cache_ptr, ct_table);
	if (ret)
	{
		IPAERR("unable to delete IPV6CT table with handle %d\n", table_handle);
		goto unlock;
	}

	if (! --ct_cache_ptr->table_cnt) {
		ipa_descriptor_close(ct_cache_ptr->ipa_desc);
		ct_cache_ptr->ipa_desc = NULL;
	}

unlock:
	if (pthread_mutex_unlock(&ipv6ct_mutex))
	{
		IPAERR("unable to unlock the ipv6ct mutex\n");
		return (ret) ? ret : -EPERM;
	}

bail:
	IPADBG("Out\n");
	return ret;
}

int ipa_ipv6ct_add_rule(uint32_t table_handle, const ipa_ipv6ct_rule* user_rule, uint32_t* rule_handle)
{
	int ret;
	struct ipa_ct_cache*           ct_cache_ptr;
	struct ipa_ct_ip6_table_cache* ct_table;
	enum ipa3_nat_mem_in            nmi = 0;
	uint16_t new_entry_index;
	uint32_t new_entry_handle;
	const uint32_t cmd_sz = sizeof(struct ipa_ioc_nat_dma_cmd) +
		(IPA_MAX_DMA_ENTRIES_FOR_ADD * sizeof(struct ipa_ioc_nat_dma_one));
	char cmd_buf[cmd_sz];
	struct ipa_ioc_nat_dma_cmd* cmd;

	IPADBG("\n");

	IPADBG("Passed Table handle: 0x%x\n", table_handle);

	CT_BREAK_TBL_HDL(table_handle, nmi, table_handle);

	if ( ! IPA_VALID_NAT_MEM_IN(nmi) ) {
		IPAERR("Bad cache type argument passed\n");
		return -EINVAL;
	}

	IPADBG("tbl_hdl(0x%08X) nmi(%s)\n",
		   table_handle,
		   ipa3_ct_mem_in_as_str(nmi));

	if (table_handle == IPA_TABLE_INVALID_ENTRY || table_handle > IPA_IPV6CT_MAX_TBLS ||
		rule_handle == NULL || user_rule == NULL)
	{
		IPAERR("Invalid parameters table_handle=%d rule_handle=%pK user_rule=%pK\n",
			table_handle, rule_handle, user_rule);
		return -EINVAL;
	}
	IPADBG("Passed Table handle: 0x%x\n", table_handle);

	ct_cache_ptr = &ipv6_ct_cache[nmi];

	IPADBG("Passed Table handle: 0x%x\n", table_handle);

	ct_table = &ct_cache_ptr->ip6_tbl[table_handle - 1];

	IPADBG("Passed Table handle: 0x%x\n", table_handle);

	if (ct_cache_ptr->ipa_desc->ver < IPA_HW_v4_0)
	{
		IPAERR("IPv6 connection tracking isn't supported for IPA version %d\n", ct_cache_ptr->ipa_desc->ver);
		return -EINVAL;
	}

	if (user_rule->protocol == IPA_IPV6CT_INVALID_PROTO_FIELD_CMP)
	{
		IPAERR("invalid parameter protocol=%d\n", user_rule->protocol);
		return -EINVAL;
	}

	if (pthread_mutex_lock(&ipv6ct_mutex))
	{
		IPAERR("unable to lock the ipv6ct mutex\n");
		return -EINVAL;
	}

	if (!ct_table->mem_desc.valid)
	{
		IPAERR("invalid table handle %d\n", table_handle);
		ret = -EINVAL;
		goto unlock;
	}

	memset(cmd_buf, 0, sizeof(cmd_buf));
	cmd = (struct ipa_ioc_nat_dma_cmd*) cmd_buf;
	cmd->entries = 0;
	new_entry_index = ipa_ipv6ct_hash(user_rule, ct_table->table.table_entries - 1);
	cmd->mem_type = ct_table->table.nmi;

	ret = ipa_table_add_entry(&ct_table->table, (void*)user_rule, &new_entry_index, &new_entry_handle, cmd);
	if (ret)
	{
		IPAERR("failed to add a new IPV6CT entry\n");
		goto unlock;
	}

	ret = ipa_ipv6ct_post_dma_cmd(ct_cache_ptr, cmd);
	if (ret)
	{
		IPAERR("unable to post dma command\n");
		goto bail;
	}

	if (pthread_mutex_unlock(&ipv6ct_mutex))
	{
		IPAERR("unable to unlock the ipv6ct mutex\n");
		return -EPERM;
	}

	*rule_handle = new_entry_handle;

	IPADBG("return\n");
	return 0;

bail:
	ipa_table_erase_entry(&ct_table->table, new_entry_index);
unlock:
	if (pthread_mutex_unlock(&ipv6ct_mutex))
		IPAERR("unable to unlock the ipv6ct mutex\n");
	return ret;
}

int ipa_ipv6ct_del_rule(uint32_t table_handle, uint32_t rule_handle)
{
	struct ipa_ct_cache*           ct_cache_ptr;
	struct ipa_ct_ip6_table_cache* ct_table;
	enum ipa3_nat_mem_in            nmi = 0;
	ipa_table_iterator table_iterator;
	ipa_ipv6ct_hw_entry* entry;
	const uint32_t cmd_sz = sizeof(struct ipa_ioc_nat_dma_cmd) +
		(IPA_MAX_DMA_ENTRIES_FOR_DEL * sizeof(struct ipa_ioc_nat_dma_one));
	char cmd_buf[cmd_sz];
	struct ipa_ioc_nat_dma_cmd* cmd;
	uint16_t idx;
	int ret;

	IPADBG("\n");

	CT_BREAK_TBL_HDL(table_handle, nmi, table_handle);

	if ( ! IPA_VALID_NAT_MEM_IN(nmi) ) {
		IPAERR("Bad cache type argument passed\n");
		ret = -EINVAL;
		goto done;
	}

	if (table_handle == IPA_TABLE_INVALID_ENTRY || table_handle > IPA_IPV6CT_MAX_TBLS ||
		rule_handle == IPA_TABLE_INVALID_ENTRY)
	{
		IPAERR("Invalid parameters table_handle=%d rule_handle=%d\n", table_handle, rule_handle);
		return -EINVAL;
	}
	IPADBG("Passed Table: 0x%x and rule handle 0x%x\n", table_handle, rule_handle);

	IPADBG("nmi(%s)\n", ipa3_ct_mem_in_as_str(nmi));

	ct_cache_ptr = &ipv6_ct_cache[nmi];

	ct_table = &ct_cache_ptr->ip6_tbl[table_handle - 1];

	if (ct_cache_ptr->ipa_desc->ver < IPA_HW_v4_0)
	{
		IPAERR("IPv6 connection tracking isn't supported for IPA version %d\n", ct_cache_ptr->ipa_desc->ver);
		return -EINVAL;
	}

	if (pthread_mutex_lock(&ipv6ct_mutex))
	{
		IPAERR("unable to lock the ipv6ct mutex\n");
		return -EINVAL;
	}

	if (! ct_table->mem_desc.valid)
	{
		IPAERR("invalid table handle %d\n", table_handle);
		ret = -EINVAL;
		goto unlock;
	}

	ret = ipa_table_get_entry(&ct_table->table, rule_handle, (void**)&entry, &idx);
	if (ret)
	{
		IPAERR("unable to retrive the entry with handle=%d in IPV6CT table with handle=%d\n",
			rule_handle, table_handle);
		goto unlock;
	}

	ret = ipa_table_iterator_init(&table_iterator, &ct_table->table, entry, idx);
	if (ret)
	{
		IPAERR("unable to create iterator which points to the entry index=%d in IPV6CT table with handle=%d\n",
			idx, table_handle);
		goto unlock;
	}

	memset(cmd_buf, 0, sizeof(cmd_buf));
	cmd = (struct ipa_ioc_nat_dma_cmd*) cmd_buf;
	cmd->entries = 0;
	cmd->mem_type = ct_table->table.nmi;

	ipa_table_create_delete_command(&ct_table->table, cmd, &table_iterator);

	ret = ipa_ipv6ct_post_dma_cmd(ct_cache_ptr, cmd);
	if (ret)
	{
		IPAERR("unable to post dma command\n");
		goto unlock;
	}

	if (!ipa_table_itr_valid_check(&table_iterator))
	{
		/* The entry can be deleted */
		uint8_t is_prev_empty = (table_iterator.prev_entry != NULL &&
			((ipa_ipv6ct_hw_entry*)table_iterator.prev_entry)->protocol == IPA_IPV6CT_INVALID_PROTO_FIELD_CMP);
		ipa_table_delete_entry(&ct_table->table, &table_iterator, is_prev_empty);
	}

unlock:
	if (pthread_mutex_unlock(&ipv6ct_mutex))
	{
		IPAERR("unable to unlock the ipv6ct mutex\n");
		return (ret) ? ret : -EPERM;
	}

done:
	IPADBG("return\n");
	return ret;
}

int ipa_ipv6ct_query_timestamp(uint32_t table_handle, uint32_t rule_handle, uint32_t* time_stamp)
{
	int ret;
	enum ipa3_nat_mem_in           nmi = 0;
	struct ipa_ct_cache*           ct_cache_ptr;
	struct ipa_ct_ip6_table_cache* ct_table;
	ipa_ipv6ct_hw_entry *entry;

	IPADBG("In\n");

	CT_BREAK_TBL_HDL(table_handle, nmi, table_handle);

	if ( ! IPA_VALID_NAT_MEM_IN(nmi) ) {
		IPAERR("Bad cache type argument passed\n");
		ret = -EINVAL;
		goto bail;
	}

	IPADBG("nmi(%s)\n", ipa3_ct_mem_in_as_str(nmi));

	if (table_handle == IPA_TABLE_INVALID_ENTRY || table_handle > IPA_IPV6CT_MAX_TBLS ||
		rule_handle == IPA_TABLE_INVALID_ENTRY || time_stamp == NULL)
	{
		IPAERR("invalid parameters passed table_handle=%d rule_handle=%d time_stamp=%pK\n",
			table_handle, rule_handle, time_stamp);
		return -EINVAL;
	}
	IPADBG("Passed Table: %d and rule handle %d\n", table_handle, rule_handle);

	ct_cache_ptr = &ipv6_ct_cache[nmi];

	ct_table = &ct_cache_ptr->ip6_tbl[table_handle - 1];

	if (ct_cache_ptr->ipa_desc->ver < IPA_HW_v4_0)
	{
		IPAERR("IPv6 connection tracking isn't supported for IPA version %d\n", ct_cache_ptr->ipa_desc->ver);
		return -EINVAL;
	}

	if (pthread_mutex_lock(&ipv6ct_mutex))
	{
		IPAERR("unable to lock the ipv6ct mutex\n");
		return -EINVAL;
	}

	if (!ct_table->mem_desc.valid)
	{
		IPAERR("invalid table handle %d\n", table_handle);
		ret = -EINVAL;
		goto unlock;
	}

	ret = ipa_table_get_entry(&ct_table->table, rule_handle, (void**)&entry, NULL);
	if (ret)
	{
		IPAERR("unable to retrive the entry with handle=%d in IPV6CT table with handle=%d\n",
			rule_handle, table_handle);
		goto unlock;
	}

	*time_stamp = entry->time_stamp;

unlock:
	if (pthread_mutex_unlock(&ipv6ct_mutex))
	{
		IPAERR("unable to unlock the ipv6ct mutex\n");
		return (ret) ? ret : -EPERM;
	}

bail:
	IPADBG("Out\n");
	return ret;
}

/**
* ipv6ct_hash() - Find the index into ipv6ct table
* @rule: [in] an IPv6CT rule
* @size: [in] size of the IPv6CT table
*
* This hash method is used to find the hash index of an entry into IPv6CT table.
* In case of result zero, N-1 will be returned, where N is size of IPv6CT table.
*
* Returns: >0 index into IPv6CT table, negative on failure
*/
static uint16_t ipa_ipv6ct_hash(const ipa_ipv6ct_rule* rule, uint16_t size)
{
	uint16_t hash = 0;

	IPADBG("src_ipv6_lsb 0x%llx\n", rule->src_ipv6_lsb);
	IPADBG("src_ipv6_msb 0x%llx\n", rule->src_ipv6_msb);
	IPADBG("dest_ipv6_lsb 0x%llx\n", rule->dest_ipv6_lsb);
	IPADBG("dest_ipv6_msb 0x%llx\n", rule->dest_ipv6_msb);
	IPADBG("src_port: 0x%x dest_port: 0x%x\n", rule->src_port, rule->dest_port);
	IPADBG("protocol: 0x%x size: 0x%x\n", rule->protocol, size);

	hash ^= ipa_ipv6ct_xor_segments(rule->src_ipv6_lsb);
	hash ^= ipa_ipv6ct_xor_segments(rule->src_ipv6_msb);
	hash ^= ipa_ipv6ct_xor_segments(rule->dest_ipv6_lsb);
	hash ^= ipa_ipv6ct_xor_segments(rule->dest_ipv6_msb);

	hash ^= rule->src_port;
	hash ^= rule->dest_port;
	hash ^= rule->protocol;

	/*
	 * The size passed to hash function expected be power^2-1, while the actual size is power^2,
	 * actual_size = size + 1
	 */
	hash &= size;

	/* If the hash resulted to zero then set it to maximum value as zero is unused entry in ipv6ct table */
	if (hash == 0)
	{
		hash = size;
	}

	IPADBG("ipa_ipv6ct_hash returning value: %d\n", hash);
	return hash;
}

static uint16_t ipa_ipv6ct_xor_segments(uint64_t num)
{
	const uint64_t mask = 0xffff;
	const size_t bits_in_two_byte = 16;
	uint16_t ret = 0;

	IPADBG("\n");

	while (num)
	{
		ret ^= (uint16_t)(num & mask);
		num >>= bits_in_two_byte;
	}

	IPADBG("return\n");
	return ret;
}

static int table_entry_is_valid(void* entry)
{
	ipa_ipv6ct_hw_entry* ipv6ct_entry = (ipa_ipv6ct_hw_entry*)entry;

	IPADBG("\n");

	return ipv6ct_entry->enable;
}

static uint16_t table_entry_get_next_index(void* entry)
{
	uint16_t result;
	ipa_ipv6ct_hw_entry* ipv6ct_entry = (ipa_ipv6ct_hw_entry*)entry;

	IPADBG("\n");

	result = ipv6ct_entry->next_index;

	IPADBG("Next entry of %pK is %d\n", entry, result);
	return result;
}

static uint16_t table_entry_get_prev_index(void* entry, uint16_t entry_index, void* meta, uint16_t base_table_size)
{
	uint16_t result;
	ipa_ipv6ct_hw_entry* ipv6ct_entry = (ipa_ipv6ct_hw_entry*)entry;

	IPADBG("\n");

	result = ipv6ct_entry->prev_index;

	IPADBG("Previous entry of %d is %d\n", entry_index, result);
	return result;
}

static void table_entry_set_prev_index(void* entry, uint16_t entry_index, uint16_t prev_index,
	void* meta, uint16_t base_table_size)
{
	ipa_ipv6ct_hw_entry* ipv6ct_entry = (ipa_ipv6ct_hw_entry*)entry;

	IPADBG("Previous entry of %d is %d\n", entry_index, prev_index);

	ipv6ct_entry->prev_index = prev_index;

	IPADBG("return\n");
}

static int table_entry_copy_from_user(void* entry, void* user_data)
{
	ipa_ipv6ct_hw_entry* ipv6ct_entry = (ipa_ipv6ct_hw_entry*)entry;
	const ipa_ipv6ct_rule* user_rule = (const ipa_ipv6ct_rule*)user_data;

	IPADBG("\n");

	ipv6ct_entry->src_ipv6_lsb = user_rule->src_ipv6_lsb;
	ipv6ct_entry->src_ipv6_msb = user_rule->src_ipv6_msb;
	ipv6ct_entry->dest_ipv6_lsb = user_rule->dest_ipv6_lsb;
	ipv6ct_entry->dest_ipv6_msb = user_rule->dest_ipv6_msb;
	ipv6ct_entry->protocol = user_rule->protocol;
	ipv6ct_entry->src_port = user_rule->src_port;
	ipv6ct_entry->dest_port = user_rule->dest_port;
	ipv6ct_entry->ucp = user_rule->ucp;
	ipv6ct_entry->uc_activation_index = user_rule->uc_activation_index;
	ipv6ct_entry->s = user_rule->s;

	switch (user_rule->direction_settings)
	{
	case IPA_IPV6CT_DIRECTION_DENY_ALL:
		break;
	case IPA_IPV6CT_DIRECTION_ALLOW_OUT:
		ipv6ct_entry->out_allowed = IPA_IPV6CT_DIRECTION_ALLOW_BIT;
		break;
	case IPA_IPV6CT_DIRECTION_ALLOW_IN:
		ipv6ct_entry->in_allowed = IPA_IPV6CT_DIRECTION_ALLOW_BIT;
		break;
	case IPA_IPV6CT_DIRECTION_ALLOW_ALL:
		ipv6ct_entry->out_allowed = IPA_IPV6CT_DIRECTION_ALLOW_BIT;
		ipv6ct_entry->in_allowed = IPA_IPV6CT_DIRECTION_ALLOW_BIT;
		break;
	default:
		IPAERR("wrong value for IPv6CT direction setting parameter %d\n", user_rule->direction_settings);
		return -EINVAL;
	}

	IPADBG("return\n");
	return 0;
}

static int table_entry_head_insert(void* entry, void* user_data, uint16_t* dma_command_data)
{
	int ret;

	IPADBG("\n");

	ret = table_entry_copy_from_user(entry, user_data);
	if (ret)
	{
		IPAERR("unable to copy from user a new entry\n");
		return ret;
	}

	*dma_command_data = 0;
	((ipa_ipv6ct_flags*)dma_command_data)->enable = IPA_IPV6CT_FLAG_ENABLE_BIT;

	IPADBG("return\n");
	return 0;
}

static int table_entry_tail_insert(void* entry, void* user_data)
{
	int ret;

	IPADBG("\n");

	ret = table_entry_copy_from_user(entry, user_data);
	if (ret)
	{
		IPAERR("unable to copy from user a new entry\n");
		return ret;
	}

	((ipa_ipv6ct_hw_entry*)entry)->enable = IPA_IPV6CT_FLAG_ENABLE_BIT;

	IPADBG("return\n");
	return 0;
}

static uint16_t table_entry_get_delete_head_dma_command_data(void* head, void* next_entry)
{
	IPADBG("\n");
	return IPA_IPV6CT_INVALID_PROTO_FIELD_VALUE;
}

/**
 * ipa_ipv6ct_create_table() - Creates a new IPv6CT table
 * @ipv6ct_table: [in] IPv6CT table
 * @number_of_entries: [in] number of IPv6CT entries
 * @table_index: [in] the index of the IPv6CT table
 *
 * This function creates new IPv6CT table:
 * - Initializes table, memory descriptor and table_dma_cmd_helpers structures
 * - Allocates, maps and clears the memory for table
 *
 * Returns:	0  On Success, negative on failure
 */
static int ipa_ipv6ct_create_table(
	struct ipa_ct_cache*           ct_cache_ptr,
	struct ipa_ct_ip6_table_cache* ct_table,
	uint16_t number_of_entries,
	uint8_t table_index)
{
	int ret, size;

	IPADBG("In\n");

	ipa_table_init(
		&ct_table->table, IPA_IPV6CT_TABLE_NAME, ct_cache_ptr->nmi,
		sizeof(ipa_ipv6ct_hw_entry), NULL, 0, &entry_interface);

	ret = ipa_table_calculate_entries_num(
		&ct_table->table, number_of_entries, ct_cache_ptr->nmi);

	if (ret)
	{
		IPAERR("unable to calculate number of entries in ipv6ct table %d, while required by user %d\n",
			table_index, number_of_entries);
		return ret;
	}

	size = ipa_table_calculate_size(&ct_table->table);
	IPADBG("IPv6CT table size: %d\n", size);

	ipa_mem_descriptor_init(
		&ct_table->mem_desc,
		IPA_IPV6CT_DEV_NAME,
		size,
		table_index,
		IPA_IOC_ALLOC_IPV6CT_TABLE,
		IPA_IOC_DEL_IPV6CT_TABLE,
		true); /* false here means don't consider using sram */

	ret = ipa_mem_descriptor_allocate_ct_memory(
		&ct_table->mem_desc,
		ct_cache_ptr->ipa_desc->fd);

	if (ret)
	{
		IPAERR("unable to allocate ipv6ct memory descriptor Error: %d\n", ret);
		goto bail;
	}

	ipa_table_calculate_addresses(&ct_table->table, ct_table->mem_desc.base_addr);

	ipa_table_reset(&ct_table->table);

	ipa_ipv6ct_create_table_dma_cmd_helpers(ct_table, table_index);

	IPADBG("return\n");
	return 0;

bail:
	memset(ct_table, 0, sizeof(*ct_table));
	return ret;
}

static int ipa_ipv6ct_destroy_table(
	struct ipa_ct_cache*		   ct_cache_ptr,
	struct ipa_ct_ip6_table_cache* ct_table)

{
	int ret;

	IPADBG("\n");

	ret = ipa_mem_descriptor_delete(&ct_table->mem_desc, ct_cache_ptr->ipa_desc->fd);
	if (ret)
		IPAERR("unable to delete IPV6CT descriptor\n");

	memset(ct_table, 0, sizeof(*ct_table));

	IPADBG("return\n");
	return ret;
}

/**
 * ipa_ipv6ct_create_table_dma_cmd_helpers() -
 *   Creates dma_cmd_helpers for base table in the received IPv6CT table
 * @ipv6ct_table: [in] IPv6CT table
 * @table_indx: [in] The index of the IPv6CT table
 *
 * A DMA command helper helps to generate the DMA command for one
 * specific field change. Each table has 3 different types of field
 * change: update_head, update_entry and delete_head. This function
 * creates the helpers and updates the base table correspondingly.
 */
static void ipa_ipv6ct_create_table_dma_cmd_helpers(
	struct ipa_ct_ip6_table_cache* ct_table,
	uint8_t table_indx )
{
	IPADBG("\n");

	ipa_table_dma_cmd_helper_init(
		&ct_table->table_dma_cmd_helpers[IPA_IPV6CT_TABLE_FLAGS],
		table_indx,
		IPA_IPV6CT_BASE_TBL,
		IPA_IPV6CT_EXPN_TBL,
		ct_table->mem_desc.addr_offset + IPA_IPV6CT_RULE_FLAG_FIELD_OFFSET);

	ipa_table_dma_cmd_helper_init(
		&ct_table->table_dma_cmd_helpers[IPA_IPV6CT_TABLE_NEXT_INDEX],
		table_indx,
		IPA_IPV6CT_BASE_TBL,
		IPA_IPV6CT_EXPN_TBL,
		ct_table->mem_desc.addr_offset + IPA_IPV6CT_RULE_NEXT_FIELD_OFFSET);

	ipa_table_dma_cmd_helper_init(
		&ct_table->table_dma_cmd_helpers[IPA_IPV6CT_TABLE_PROTOCOL],
		table_indx,
		IPA_IPV6CT_BASE_TBL,
		IPA_IPV6CT_EXPN_TBL,
		ct_table->mem_desc.addr_offset + IPA_IPV6CT_RULE_PROTO_FIELD_OFFSET);

	ct_table->table.dma_help[HELP_UPDATE_HEAD] =
		&ct_table->table_dma_cmd_helpers[IPA_IPV6CT_TABLE_FLAGS];
	ct_table->table.dma_help[HELP_UPDATE_ENTRY] =
		&ct_table->table_dma_cmd_helpers[IPA_IPV6CT_TABLE_NEXT_INDEX];
	ct_table->table.dma_help[HELP_DELETE_HEAD] =
		&ct_table->table_dma_cmd_helpers[IPA_IPV6CT_TABLE_PROTOCOL];

	IPADBG("return\n");
}

static int ipa_ipv6ct_post_dma_cmd(
	struct ipa_ct_cache*        ct_cache_ptr,
	struct ipa_ioc_nat_dma_cmd* cmd)
{
	IPADBG("In\n");

	cmd->mem_type = ct_cache_ptr->nmi;

	if (ioctl(ct_cache_ptr->ipa_desc->fd, IPA_IOC_TABLE_DMA_CMD, cmd))
	{
		IPAERR("ioctl (IPA_IOC_TABLE_DMA_CMD) on fd %d has failed\n",
			  ct_cache_ptr->ipa_desc->fd);
		return -EIO;
	}
	IPADBG("posted IPA_IOC_TABLE_DMA_CMD to kernel successfully\n");
	return 0;
}

void ipa_ipv6ct_dump_table(uint32_t table_handle)
{
	struct ipa_ct_ip6_table_cache* ct_table = NULL;
	struct ipa_ct_cache*        ct_cache_ptr = NULL;
	enum ipa3_nat_mem_in nmi = 0;

	CT_BREAK_TBL_HDL(table_handle, nmi, table_handle);

	if (table_handle == IPA_TABLE_INVALID_ENTRY || table_handle > IPA_IPV6CT_MAX_TBLS)
	{
		IPAERR("invalid parameters passed %d\n", table_handle);
		return;
	}

	if (pthread_mutex_lock(&ipv6ct_mutex))
	{
		IPAERR("unable to lock the ipv6ct mutex\n");
		return;
	}

	ct_cache_ptr = &ipv6_ct_cache[nmi];

	if (ct_cache_ptr->ipa_desc->ver < IPA_HW_v4_0)
	{
		IPAERR("IPv6 connection tracking isn't supported for IPA version %d\n", ct_cache_ptr->ipa_desc->ver);
		goto unlock;
	}

	ct_table = &ct_cache_ptr->ip6_tbl[table_handle - 1];

	if (!ct_table->mem_desc.valid)
	{
		IPAERR("invalid table handle %d\n", table_handle);
		goto unlock;
	}

	/* Prevents interleaving with later kernel printouts. Flush doesn't help. */
	sleep(1);
	ipa_read_debug_info(IPA_IPV6CT_DEBUG_FILE_PATH);
	ipa_read_debug_info(IPA_UC_ACT_DEBUG_FILE_PATH);
	sleep(1);

unlock:
	if (pthread_mutex_unlock(&ipv6ct_mutex))
		IPAERR("unable to unlock the ipv6ct mutex\n");
}

/**
 * ipa_ipv6ct_add_uc_act_entry() - add uc activation entry
 * @u: [in] structure specifying the uC activation entry
 *
 * Returns:	0  On Success, negative on failure
 */
int ipa_ipv6ct_add_uc_act_entry(union ipa_ioc_uc_activation_entry *u)
{
	IPADBG("\n");

	int fd = open(IPA_DEV_NAME, O_RDONLY);

	if (fd < 0)
	{
		IPAERR("Unable to open ipa device\n");
		return -1;
	}

	if(ioctl(fd, IPA_IOC_ADD_UC_ACT_ENTRY, u))
	{
		IPAERR("ioctl (IPA_IOC_ADD_UC_ACT_ENTRY) on fd %d has failed\n",
			fd);
		return -EIO;
	}
	IPADBG("posted IPA_IOC_ADD_UC_ACT_ENTRY to kernel successfully, index %d\n",
		u->ipv6_nat.index);
	close(fd);
	return 0;
}

/**
 * ipa_ipv6ct_del_uc_act_entry() - del uc activation entry
 * @index: [in] index of the uc activation entry to be removed
 *
 * Returns:	0  On Success, negative on failure
 */
int ipa_ipv6ct_del_uc_act_entry(uint16_t idx)
{
	IPADBG("\n");

	int fd = open(IPA_DEV_NAME, O_RDONLY);

	if (fd < 0)
	{
		IPAERR("Unable to open ipa device\n");
		return -1;
	}

	if(ioctl(fd, IPA_IOC_DEL_UC_ACT_ENTRY, idx))
	{
		IPAERR("ioctl (IPA_IOC_DEL_UC_ACT_ENTRY) on fd %d has failed\n",
			fd);
		return -EIO;
	}
	IPADBG("posted IPA_IOC_DEL_UC_ACT_ENTRY to kernel successfully, index %d\n",
		idx);
	close(fd);
	return 0;
}

int ipa_cti_vote_clock(
    enum ipa_app_clock_vote_type vote_type )
{
	struct ipa_ct_cache* ct_cache_ptr =
		&ipv6_ct_cache[IPA_NAT_MEM_IN_SRAM];

	int ret = 0;

	IPADBG("In\n");

	if ( ! ct_cache_ptr->ipa_desc ) {
		ct_cache_ptr->ipa_desc = ipa_descriptor_open();
		if ( ct_cache_ptr->ipa_desc == NULL ) {
			IPAERR("failed to open IPA driver file descriptor\n");
			ret = -EIO;
			goto bail;
		}
	}

	ret = ioctl(ct_cache_ptr->ipa_desc->fd,
				IPA_IOC_APP_CLOCK_VOTE,
				vote_type);

	if (ret) {
		IPAERR("APP_CLOCK_VOTE ioctl failure %d on IPA fd %d\n",
			   ret, ct_cache_ptr->ipa_desc->fd);
		goto bail;
	}

bail:
	IPADBG("Out\n");

	return ret;
}

/**
 * ipa_ct_vote_clock() - used for voting clock
 * @vote_type: [in] desired vote type
 */
int ipa_ct_vote_clock(
	enum ipa_app_clock_vote_type vote_type )
{
	if ( ! (vote_type >= IPA_APP_CLK_DEVOTE &&
			vote_type <= IPA_APP_CLK_RESET_VOTE) )
	{
		IPAERR("Bad vote_type(%u) parameter\n", vote_type);
		return -EINVAL;
	}

	return ipa_cti_vote_clock(vote_type);
}

static int Get2PowerTightUpperBound(uint16_t num)
{
	uint16_t tmp = num, prev = 0, curr = 2;

	if (num == 0)
		return 2;

	while (tmp != 1)
	{
		prev = curr;
		curr <<= 1;
		tmp >>= 1;
	}

	return (num == prev) ? prev : curr;
}

/**
 * GetEvenTightUpperBound() - Returns the tight upper bound which is an even number
 * @num: [in] given number
 *
 * Returns the tight upper bound for a given number which is an even number
 *
 * Returns: the tight upper bound which is an even number
 */
static int GetEvenTightUpperBound(uint16_t num)
{
	if (num == 0)
		return 2;

	return (num % 2) ? num + (uint16_t)1 : num;
}

int ipa_calc_num_sram_ct_table_entries(
	uint32_t  sram_size,
	uint32_t  table1_ent_size,
	uint16_t* num_entries_ptr)
{
	ipa_table ipv6ct_table;
	int       size = 0;
	uint16_t  tot;

	IPADBG("In\n");

	IPADBG("sram_size(%x or %u)\n", sram_size, sram_size);

	*num_entries_ptr = 0;

	tot = 1;

	while ( 1 )
	{
		IPADBG("Trying %u entries\n", tot);

		ipa_table_init(&ipv6ct_table,
					   "tmp_sram_table1",
					   IPA_NAT_MEM_IN_DDR,
					   table1_ent_size,
					   NULL,
					   0,
					   NULL);


		ipv6ct_table.table_entries =
			Get2PowerTightUpperBound(tot * IPA_BASE_TABLE_PCNT_4SRAM);
		ipv6ct_table.expn_table_entries =
			GetEvenTightUpperBound(tot * IPA_EXPANSION_TABLE_PCNT_4SRAM);

		size  = ipa_table_calculate_size(&ipv6ct_table);

		IPADBG("%u entries consumes size(0x%x or %u)\n", tot, size, size);

		if ( size > sram_size )
			break;

		*num_entries_ptr = tot;

		++tot;
	}

	IPADBG("Optimal number of entries: %u\n", *num_entries_ptr);

	IPADBG("Out\n");

	return (*num_entries_ptr) ? 0 : -1;
}

int ipa_ipv6ct_clear_table(uint32_t tbl_hdl)
{
	enum ipa3_nat_mem_in nmi = 0;
	struct ipa_ct_cache*           ct_cache_ptr;
	struct ipa_ct_ip6_table_cache* ct_table;
	int ret = 0;

	IPADBG("In\n");

	CT_BREAK_TBL_HDL(tbl_hdl, nmi, tbl_hdl);

	if ( ! IPA_VALID_NAT_MEM_IN(nmi) ) {
		IPAERR("Bad cache type argument passed\n");
		ret = -EINVAL;
		goto bail;
	}

	IPADBG("nmi(%s)\n", ipa3_ct_mem_in_as_str(nmi));

	ct_cache_ptr = &ipv6_ct_cache[nmi];

	if (pthread_mutex_lock(&ipv6ct_mutex)) {
		IPAERR("unable to lock the ct mutex\n");
		ret = -EINVAL;
		goto bail;
	}

	if ( ! ct_cache_ptr->table_cnt ) {
		IPAERR("No initialized table in CT\n");
		ret = -EINVAL;
		goto unlock;
	}

	ct_table = &ct_cache_ptr->ip6_tbl[tbl_hdl- 1];

	ipa_table_reset(&ct_table->table);
	ct_table->table.cur_tbl_cnt =
		ct_table->table.cur_expn_tbl_cnt = 0;

unlock:
	if (pthread_mutex_unlock(&ipv6ct_mutex)) {
		IPAERR("unable to unlock the ct mutex\n");
		ret = (ret) ? ret : -EPERM;
	}

bail:
	IPADBG("Out\n");

	return ret;
}

int ipa_ipv6ct_walk_table(
	uint32_t          tbl_hdl,
	CtWhichTbl2Use      which,
	ipa_table_walk_cb walk_cb,
	void*             arb_data_ptr )
{
	enum ipa3_nat_mem_in            nmi = 0;
	uint32_t                        broken_tbl_hdl = 0;
	struct ipa_ct_cache*            ct_cache_ptr;
	struct ipa_ct_ip6_table_cache*  ct_table;
	ipa_table*                      ipa_tbl_ptr;

	int ret = 0;

	IPADBG("In\n");


	if ( ! CT_VALID_TBL_HDL(tbl_hdl) ||
		 ! CT_VALID_WHICHTBL2USE(which) ||
		 ! walk_cb )
	{
		IPAERR("Bad arg: tbl_hdl(0x%08X) and/or WhichTbl2Use(%u) and/or walk_cb(%p)\n",
			   tbl_hdl, which, walk_cb);
		ret = -EINVAL;
		goto bail;
	}

	if ( pthread_mutex_lock(&ipv6ct_mutex) )
	{
		IPAERR("unable to lock the ct mutex\n");
		ret = -EINVAL;
		goto bail;
	}

	/*
	 * Now walk the table and pass the valid records to the user's
	 * walk callback...
	 */

	CT_BREAK_TBL_HDL(tbl_hdl, nmi, broken_tbl_hdl);

	if ( ! IPA_VALID_NAT_MEM_IN(nmi) )
	{
		IPAERR("Bad nat type argument passed\n");
		ret = -EINVAL;
		goto unlock;
	}

	ct_cache_ptr = &ipv6_ct_cache[nmi];

	if ( ! ct_cache_ptr->table_cnt )
	{
		IPAERR("No ipv6ct_table initialized table in CT cache\n");
		ret = -EINVAL;
		goto unlock;
	}

	ct_table = &ct_cache_ptr->ip6_tbl[broken_tbl_hdl - 1];

	ipa_tbl_ptr = &ct_table->table;

	ret = ipa_table_walk(ipa_tbl_ptr, 0, WHEN_SLOT_FILLED, walk_cb, arb_data_ptr);

	if ( ret != 0 )
	{
		IPAERR("ipa_table_walk returned non-zero (%d)\n", ret);
		goto unlock;
	}

unlock:
	if ( pthread_mutex_unlock(&ipv6ct_mutex) )
	{
		IPAERR("unable to unlock the ct mutex\n");
		ret = (ret) ? ret : -EPERM;
	}

bail:
	IPADBG("Out\n");

	return ret;
}

static int ct_gen_chain_stats(
	ipa_table*      table_ptr,
	uint32_t        rule_hdl,
	void*           record_ptr,
	uint16_t        record_index,
	void*           meta_record_ptr,
	uint16_t        meta_record_index,
	void*           arb_data_ptr )
{
	ct_chain_stat_help* csh_ptr = (ct_chain_stat_help*) arb_data_ptr;

	enum ipa3_nat_mem_in nmi;
	uint8_t              is_expn_tbl = 0;
	uint16_t             rule_index = 0;

	uint32_t             chain_len = 0;

	BREAK_RULE_HDL(table_ptr, rule_hdl, is_expn_tbl, rule_index);

	if ( is_expn_tbl )
	{
		return 1;
	}

	if ( csh_ptr->which == USE_NAT_TABLE )
	{
		struct ipa_ipv6ct_hw_entry* list_elem_ptr =
			(struct ipa_ipv6ct_hw_entry*) record_ptr;

		if ( list_elem_ptr->next_index )
		{
			chain_len = 1;

			while ( list_elem_ptr->next_index )
			{
				chain_len++;

				list_elem_ptr = GOTO_REC(table_ptr, list_elem_ptr->next_index);
			}
		}
	}

	if ( chain_len )
	{
		csh_ptr->stats_ptr->tot_chains += 1;

		csh_ptr->tot_for_avg += chain_len;

		if ( csh_ptr->stats_ptr->min_chain_len == 0 )
		{
			csh_ptr->stats_ptr->min_chain_len = chain_len;
		}
		else
		{
			csh_ptr->stats_ptr->min_chain_len =
				min(csh_ptr->stats_ptr->min_chain_len, chain_len);
		}

		csh_ptr->stats_ptr->max_chain_len =
			max(csh_ptr->stats_ptr->max_chain_len, chain_len);
	}

	return 0;
}

int ipa_ipv6ct_stats_table(
	uint32_t            tbl_hdl,
	ipa_cti_tbl_stats* ct_stats_ptr)
{
	enum ipa3_nat_mem_in           nmi = 0;
	uint32_t                       broken_tbl_hdl = 0;
	struct ipa_ct_cache*           ct_cache_ptr;
	struct ipa_ct_ip6_table_cache* ct_table;

	ipa_table*                      ipa_tbl_ptr;

	ct_chain_stat_help                 csh;

	int ret = 0;

	IPADBG("In\n");

	if ( ! CT_VALID_TBL_HDL(tbl_hdl) ||
		 ! ct_stats_ptr)
	{
		IPAERR("Bad arg: "
			   "tbl_hdl(0x%08X) and/or "
			   "nat_stats_ptr(%p) and/or "
			   "idx_stats_ptr(%p)\n",
			   tbl_hdl,
			   ct_stats_ptr);
		ret = -EINVAL;
		goto bail;
	}

	if ( pthread_mutex_lock(&ipv6ct_mutex) )
	{
		IPAERR("unable to lock the ct mutex\n");
		ret = -EINVAL;
		goto bail;
	}

	memset(ct_stats_ptr, 0, sizeof(ipa_cti_tbl_stats));

	CT_BREAK_TBL_HDL(tbl_hdl, nmi, broken_tbl_hdl);

	if ( ! IPA_VALID_NAT_MEM_IN(nmi) )
	{
		IPAERR("Bad cache type argument passed\n");
		ret = -EINVAL;
		goto unlock;
	}

	ct_cache_ptr = &ipv6_ct_cache[nmi];

	if ( ! ct_cache_ptr->table_cnt )
	{
		IPAERR("No initialized table in CT cache\n");
		ret = -EINVAL;
		goto unlock;
	}

	ct_table = &ct_cache_ptr->ip6_tbl[broken_tbl_hdl - 1];

	/*
	 * Gather CT table stats...
	 */
	ipa_tbl_ptr = &ct_table->table;

	ct_stats_ptr->nmi                  = nmi;

	ct_stats_ptr->tot_base_ents        = ipa_tbl_ptr->table_entries;
	ct_stats_ptr->tot_expn_ents        = ipa_tbl_ptr->expn_table_entries;
	ct_stats_ptr->tot_ents             =
	ct_stats_ptr->tot_base_ents + ct_stats_ptr->tot_expn_ents;

	ct_stats_ptr->tot_base_ents_filled = ipa_tbl_ptr->cur_tbl_cnt;
	ct_stats_ptr->tot_expn_ents_filled = ipa_tbl_ptr->cur_expn_tbl_cnt;

	memset(&csh, 0, sizeof(ct_chain_stat_help));

	csh.which     = USE_NAT_TABLE;
	csh.stats_ptr = ct_stats_ptr;

	ret = ipa_table_walk(
		ipa_tbl_ptr, 0, WHEN_SLOT_FILLED, ct_gen_chain_stats, &csh);

	if ( ret < 0 )
	{
		IPAERR("Error gathering chain stats\n");
		ret = -EINVAL;
		goto unlock;
	}

	if ( csh.tot_for_avg && ct_stats_ptr->tot_chains )
	{
		ct_stats_ptr->avg_chain_len =
			(float) csh.tot_for_avg / (float) ct_stats_ptr->tot_chains;
	}

	ret = 0;

unlock:
	if ( pthread_mutex_unlock(&ipv6ct_mutex) )
	{
		IPAERR("unable to unlock the ct mutex\n");
		ret = (ret) ? ret : -EPERM;
	}

bail:
	IPADBG("Out\n");

	return ret;
}

int ipa_ipv6ct_copy_table(
	uint32_t          src_tbl_hdl,
	uint32_t          dst_tbl_hdl,
	ipa_table_walk_cb copy_cb )
{
	int ret = 0;

	IPADBG("In\n");

	if ( ! copy_cb )
	{
		IPAERR("copy_cb is null\n");
		ret = -EINVAL;
		goto bail;
	}

	if (pthread_mutex_lock(&ipv6ct_mutex))
	{
		IPAERR("unable to lock the ct mutex\n");
		ret = -EINVAL;
		goto bail;
	}

	/*
	 * Clear the destination table...
	 */
	ret = ipa_ipv6ct_clear_table(dst_tbl_hdl);

	if ( ret == 0 )
	{
		/*
		 * Now walk the source table and pass the valid records to the
		 * user's copy callback...
		 */
		ret = ipa_ipv6ct_walk_table(
			src_tbl_hdl, USE_NAT_TABLE, copy_cb, dst_tbl_hdl);

		if ( ret != 0 )
		{
			IPAERR("ipa_table_walk returned non-zero (%d)\n", ret);
			goto unlock;
		}
	}

unlock:
	if (pthread_mutex_unlock(&ipv6ct_mutex))
	{
		IPAERR("unable to unlock the ct mutex\n");
		ret = (ret) ? ret : -EPERM;
	}

bail:
	IPADBG("Out\n");

	return ret;
}
