/*
 * Copyright (c) 2014, 2018-2019 The Linux Foundation. All rights reserved.
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
 */

/*=========================================================================*/
/*!
	@file
	ipa_nat_test022.c

	@brief
	Note: Verify the following scenario:
	1. Add ipv4 table
	2. Add ipv4 rules till filled
	3. Print stats
	4. Delete ipv4 table
*/
/*=========================================================================*/

#include "ipa_nat_test.h"

int ipa_nat_test022(
	const char* nat_mem_type,
	u32 pub_ip_add,
	int total_entries,
	u32 tbl_hdl,
	int sep,
	void* arb_data_ptr)
{
	int* tbl_hdl_ptr = (int*) arb_data_ptr;

	ipa_nat_ipv4_rule ipv4_rule;

	u32               tot;

	u32               tot_ents;
	u32               last_tot_ents;

	u32               tot_base_ents,      tot_expn_ents;
	u32               last_tot_base_ents, last_tot_expn_ents;

	u32               tbe_filled,      tee_filled;
	u32               last_tbe_filled, last_tee_filled;

	enum ipa3_nat_mem_in nmi;
	enum ipa3_nat_mem_in last_nmi;

	const char* mem_type;

	bool switched = false;

	u32 rule_hdls[1024];

	int i, ret;

	IPADBG("In\n");

	if ( sep )
	{
		ret = ipa_nat_add_ipv4_tbl(pub_ip_add, nat_mem_type, total_entries, &tbl_hdl);
		CHECK_ERR_TBL_STOP(ret, tbl_hdl);
	}

	ret = ipa_nati_clear_ipv4_tbl(tbl_hdl);
	CHECK_ERR_TBL_STOP(ret, tbl_hdl);

	ret = ipa_nati_ipv4_tbl_stats(
		tbl_hdl,
		USE_NAT_TABLE,
		&nmi,
		&tot_base_ents, &tbe_filled,
		&tot_expn_ents, &tee_filled);

	CHECK_ERR_TBL_STOP(ret, tbl_hdl);

	mem_type = (nmi == IPA_NAT_MEM_IN_SRAM) ? "SRAM" : "DDR";

	tot_ents = tot_base_ents + tot_expn_ents;

	IPADBG("Attempting rule adds to %s table of size: (%u)\n",
		   mem_type,
		   tot_ents);

	last_nmi           = nmi;
	last_tot_base_ents = tot_base_ents;
	last_tot_expn_ents = tot_expn_ents;
	last_tbe_filled    = tbe_filled;
	last_tee_filled    = tee_filled;
	last_tot_ents      = tot_ents;

	memset(rule_hdls, 0, sizeof(rule_hdls));

	for ( i = tot = 0; i < array_sz(rule_hdls); i++ )
	{
		IPADBG("Trying %d ipa_nat_add_ipv4_rule()\n", i);

		memset(&ipv4_rule, 0, sizeof(ipv4_rule));

		ipv4_rule.protocol     = IPPROTO_TCP;
		ipv4_rule.public_port  = RAN_PORT;
		ipv4_rule.target_ip    = RAN_ADDR;
		ipv4_rule.target_port  = RAN_PORT;
		ipv4_rule.private_ip   = RAN_ADDR;
		ipv4_rule.private_port = RAN_PORT;

		ret = ipa_nat_add_ipv4_rule(tbl_hdl, &ipv4_rule, &rule_hdls[i]);
		CHECK_ERR_TBL_ACTION(ret, tbl_hdl, break);

		IPADBG("Success %d ipa_nat_add_ipv4_rule() -> rule_hdl(0x%08X)\n",
			   i, rule_hdls[i]);

		ret = ipa_nati_ipv4_tbl_stats(
			tbl_hdl,
			USE_NAT_TABLE,
			&nmi,
			&tot_base_ents, &tbe_filled,
			&tot_expn_ents, &tee_filled);

		CHECK_ERR_TBL_ACTION(ret, tbl_hdl, break);

		tot_ents = tot_base_ents + tot_expn_ents;

		/*
		 * Are we in hybrid mode and have we switch memory type?
		 * Check for it and print the appropriate stats.
		 */
		if ( nmi != last_nmi )
		{
			switched = true;

			mem_type = (last_nmi == IPA_NAT_MEM_IN_SRAM) ? "SRAM" : "DDR";

			IPADBG("Able to add %u records to %s table of size %u or %f percent\n",
				   tot, mem_type, last_tot_ents,
				   ((float) tot / (float) last_tot_ents) * 100.0);
			IPADBG("Able to add %u records to %s BASE table of size %u or %f percent\n",
				   last_tbe_filled, mem_type, last_tot_base_ents,
				   ((float) last_tbe_filled / (float) last_tot_base_ents) * 100.0);
			IPADBG("Able to add %u records to %s EXPN table of size %u or %f percent\n",
				   last_tee_filled, mem_type, last_tot_expn_ents,
				   ((float) last_tee_filled / (float) last_tot_expn_ents) * 100.0);
		}

		tot++;

		mem_type = (nmi == IPA_NAT_MEM_IN_SRAM) ? "SRAM" : "DDR";

		last_nmi           = nmi;
		last_tot_base_ents = tot_base_ents;
		last_tot_expn_ents = tot_expn_ents;
		last_tbe_filled    = tbe_filled;
		last_tee_filled    = tee_filled;
		last_tot_ents      = tot_ents;

		if ( switched )
		{
			switched = false;

			IPADBG("Continuing rule adds to %s table of size: (%u)\n",
				   mem_type,
				   tot_ents);
		}
	}

	ret = ipa_nati_ipv4_tbl_stats(
		tbl_hdl,
		USE_NAT_TABLE,
		&nmi,
		&tot_base_ents, &tbe_filled,
		&tot_expn_ents, &tee_filled);

	CHECK_ERR_TBL_STOP(ret, tbl_hdl);

	tot_ents = tot_base_ents + tot_expn_ents;

	mem_type = (nmi == IPA_NAT_MEM_IN_SRAM) ? "SRAM" : "DDR";

	IPADBG("Able to add %u records to %s table of size %u or %f percent\n",
		   tot, mem_type, tot_ents,
		   ((float) tot / (float) tot_ents) * 100.0);
	IPADBG("Able to add %u records to %s BASE table of size %u or %f percent\n",
		   tbe_filled, mem_type, tot_base_ents,
		   ((float) tbe_filled / (float) tot_base_ents) * 100.0);
	IPADBG("Able to add %u records to %s EXPN table of size %u or %f percent\n",
		   tee_filled, mem_type, tot_expn_ents,
		   ((float) tee_filled / (float) tot_expn_ents) * 100.0);

	IPADBG("Deleting all rules\n");

	for ( i = 0; i < tot; i++ )
	{
		IPADBG("Trying %d ipa_nat_del_ipv4_rule(0x%08X)\n",
			   i, rule_hdls[i]);
		ret = ipa_nat_del_ipv4_rule(tbl_hdl, rule_hdls[i]);
		CHECK_ERR_TBL_STOP(ret, tbl_hdl);
		IPADBG("Success ipa_nat_del_ipv4_rule(%d)\n", i);
	}

	if ( sep )
	{
		ret = ipa_nat_del_ipv4_tbl(tbl_hdl);
		*tbl_hdl_ptr = 0;
		CHECK_ERR(ret);
	}

	IPADBG("Out\n");

	return 0;
}
