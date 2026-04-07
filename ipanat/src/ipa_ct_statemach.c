/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include <errno.h>
#include <pthread.h>

#include "ipa_nat_map.h"

#include "ipa_ipv6ct.h"
#include "ipa_ipv6cti.h"

#include "ipa_ct_statemach.h"



#undef PRCNT_OF
#define PRCNT_OF(v) \
	((.25) * (v))

#undef  CT_CHOOSE_MEM_SUB
#define CT_CHOOSE_MEM_SUB() \
	(cti_obj.curr_state == CTI_STATE_HYBRID) ? \
	SRAM_SUB : \
	DDR_SUB

#undef  CT_CHOOSE_MAPS
#define CT_CHOOSE_MAPS(o2n, n2o) \
	do { \
		uint32_t sub = CT_CHOOSE_MEM_SUB(); \
		o2n = cti_obj.map_pairs[sub].orig2new_map; \
		n2o = cti_obj.map_pairs[sub].new2orig_map; \
	} while (0)

#undef  CT_CHOOSE_CNTR
#define CT_CHOOSE_CNTR() \
	&(cti_obj.tot_rules_in_table[CT_CHOOSE_MEM_SUB()])

#undef  CT_CHOOSE_SW_STATS
#define CT_CHOOSE_SW_STATS() \
	&(cti_obj.sw_stats[CT_CHOOSE_MEM_SUB()])

/*
 * BACKROUND INFORMATION
 *
 * As it relates to why this file exists...
 *
 * In the past, a CT table API was presented to upper layer
 * applications.  Said API mananged low level details of CT table
 * creation, manipulation, and destruction.  The API
 * managed/manipulated CT tables that lived exclusively in DDR. DDR
 * based tables are fine, but lead to uneeded bus accesses to/from DDR
 * by the IPA while doing its NAT duties. These accesses cause CT to
 * take longer than necessary.
 *
 * If the DDR bus accesses could be eliminated by storing the table in
 * the IPA's internal memory (ie. SRAM), the IPA's IP V6 CT could be
 * sped up. This leads us to the following description of this file's
 * intent.
 *
 * The purpose and intent of this file is to hijack the API described
 * above, but in a way that allows the tables to live in both SRAM and
 * DDR.  The details of whether SRAM or DDR is being used is hidden
 * from the application.  More specifically, the API will allow the
 * following to occur completely tranparent to the application using
 * the API.
 *
 *   (1) CT tables can live exclusively in DDR (traditional and
 *       historically like before)
 *
 *   (2) CT tables can live simultaneously in SRAM and DDR.  SRAM
 *       initially being used by the IPA, but both being kept in sync.
 *       When SRAM becomes too full, a switch to DDR will occur.
 *
 *   (3) The same as (2) above, but after the switch to DDR occurs,
 *       we'll have the ability to switch back to SRAM if/when DDR
 *       table entry deletions take us to a small enough entry
 *       count. An entry count that when met, allows us to switch back
 *       using SRAM again.
 *
 * As above, all of these details will just magically happen unknown
 * to the application using the API.  The implementation is done via a
 * state machine.
 */

/*
 * The following will be used to keep state machine state for and
 * between API calls...
 */
static ipa_cti_obj cti_obj = {
	.prev_state          = CTI_STATE_NULL,
	.curr_state          = CTI_STATE_NULL,
	.hold_state          = false,
	.state_to_hold       = CTI_STATE_NULL,
	.ddr_tbl_hdl         = 0,
	.sram_tbl_hdl        = 0,
	.tot_slots_in_sram   = 0,
	.back_to_sram_thresh = 0,
	/*
	 * Remember:
	 *   tot_rules_in_table[0] for ddr, and
	 *   tot_rules_in_table[1] for sram
	 */
	.tot_rules_in_table  = { 0, 0 },
	/*
	 * Remember:
	 *   map_pairs[0] for ddr, and
	 *   map_pairs[1] for sram
	 */
	.map_pairs = { {MAP_NUM_04, MAP_NUM_05}, {MAP_NUM_06, MAP_NUM_07} },
	/*
	 * Remember:
	 *   sw_stats[0] for ddr, and
	 *   sw_stats[1] for sram
	 */
	.sw_stats = { {0, 0}, {0, 0} },
};

/*
 * The following needed to protect cti_obj above, as well as a number
 * of data stuctures within the file ipa_ipv6ct.c
 */
pthread_mutex_t ipv6ct_mutex;
static bool     ct_mutex_initt = false;

static inline int ct_mutex_init(void)
{
	static pthread_mutexattr_t ct_mutex_attr;

	int ret = 0;

	IPADBG("In\n");

	ret = pthread_mutexattr_init(&ct_mutex_attr);

	if ( ret != 0 )
	{
		IPAERR("pthread_mutexattr_init() failed: ret(%d)\n", ret );
		goto bail;
	}

	ret = pthread_mutexattr_settype(
		&ct_mutex_attr, PTHREAD_MUTEX_RECURSIVE);

	if ( ret != 0 )
	{
		IPAERR("pthread_mutexattr_settype() failed: ret(%d)\n",
			   ret );
		goto bail;
	}

	ret = pthread_mutex_init(&ipv6ct_mutex, &ct_mutex_attr);

	if ( ret != 0 )
	{
		IPAERR("pthread_mutex_init() failed: ret(%d)\n",
			   ret );
		goto bail;
	}

	ct_mutex_initt = true;

bail:
	IPADBG("Out\n");

	return ret;
}

/*
 * Function for taking/locking the mutex...
 */
static int ct_take_mutex()
{
	int ret;

again:
	if ( ct_mutex_initt )
	{
		ret = pthread_mutex_lock(&ipv6ct_mutex);
	}
	else
	{
		ret = ct_mutex_init();

		if ( ret == 0 )
		{
			goto again;
		}
	}

	if ( ret != 0 )
	{
		IPAERR("Unable to lock the %s nat mutex\n",
			   (ct_mutex_initt) ? "initialized" : "uninitialized");
	}

	return ret;
}

/*
 * Function for giving/unlocking the mutex...
 */
static int ct_give_mutex()
{
	int ret = (ct_mutex_initt) ? pthread_mutex_unlock(&ipv6ct_mutex) : -1;

	if ( ret != 0 )
	{
		IPAERR("Unable to unlock the %s nat mutex\n",
			   (ct_mutex_initt) ? "initialized" : "uninitialized");
	}

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: ct_migrate_rule
 *
 * PARAMS:
 *
 *   table_ptr         (IN) The table being walked
 *
 *   tbl_rule_hdl      (IN) The ct rule's handle from the source table
 *
 *   record_ptr        (IN) The ct rule record from the source table
 *
 *   record_index      (IN) The record above's index in the table being walked
 *
 *   meta_record_ptr   (IN) If meta data in table, this will be it
 *
 *   meta_record_index (IN) The record above's index in the table being walked
 *
 *   arb_data_ptr      (IN) The destination table handle
 *
 * DESCRIPTION:
 *
 *   This routine is intended to copy records from a source table to a
 *   destination table.

 *   It is used in union with the ipa_ipv6ct_copy_table() API call
 *   below.
 *
 *   It is compatible with the ipa_ipv6ct_walk_table() API.
 *
 *   In the context of the ipa_ipv6ct_copy_table(), the arguments
 *   passed in are as enumerated above.
 *
 * AN IMPORTANT NOTE ON RULE HANDLES WHEN IN MYBRID MODE
 *
 *   The rule_hdl is used to find a rule in the ct table.  It is, in
 *   effect, an index into the table.  The applcation above us retains
 *   it for future manipulation of the rule in the table.
 *
 *   In hybrid mode, a rule can and will move between SRAM and DDR.
 *   Because of this, its handle will change.  The application has
 *   only the original handle and doesn't know of the new handle.  A
 *   mapping, used in hybrid mode, will maintain a relationship
 *   between the original handle and the rule's current real handle...
 *
 *   To help you get a mindset of how this is done:
 *
 *     The original handle will map (point) to the new and new handle
 *     will map (point) back to original.
 *
 * NOTE WELL: There are two sets of maps.  One for each memory type...
 *
 * RETURNS:
 *
 *   Returns 0 on success, non-zero on failure
 */
static int ct_migrate_rule(
	ipa_table*      table_ptr,
	uint32_t        tbl_rule_hdl,
	void*           record_ptr,
	uint16_t        record_index,
	void*           meta_record_ptr,
	uint16_t        meta_record_index,
	void*           arb_data_ptr )
{
	ipa_ipv6ct_hw_entry* ct_rule_ptr = (struct ipa_ipv6ct_hw_entry*) record_ptr;
	uint32_t             dst_tbl_hdl  = (uint32_t) arb_data_ptr;

	ipa_ipv6ct_rule    v6_rule;

	uint32_t             orig_rule_hdl;
	uint32_t             new_rule_hdl;

	uint32_t             src_orig2new_map, src_new2orig_map;
	uint32_t             dst_orig2new_map, dst_new2orig_map;
	uint32_t*            cnt_ptr;

	const char*          mig_dir_ptr;

	char                 buf[1024];
	int                  ret;

	IPADBG("In\n");

	IPADBG("tbl_mem_type(%s) tbl_rule_hdl(%u) -> %s\n",
		   ipa3_ct_mem_in_as_str(table_ptr->nmi),
		   tbl_rule_hdl,
		   prep_ct_rule_4print(ct_rule_ptr, buf, sizeof(buf)));

	IPADBG("dst_tbl_hdl(0x%08X)\n", dst_tbl_hdl);

	/*
	 * What is the type of the source table?
	 */
	if ( table_ptr->nmi == IPA_NAT_MEM_IN_SRAM )
	{
		mig_dir_ptr = "SRAM -> DDR";

		src_orig2new_map = cti_obj.map_pairs[SRAM_SUB].orig2new_map;
		src_new2orig_map = cti_obj.map_pairs[SRAM_SUB].new2orig_map;

		dst_orig2new_map = cti_obj.map_pairs[DDR_SUB].orig2new_map;
		dst_new2orig_map = cti_obj.map_pairs[DDR_SUB].new2orig_map;

		cnt_ptr          = &(cti_obj.tot_rules_in_table[DDR_SUB]);
	}
	else
	{
		mig_dir_ptr = "DDR -> SRAM";

		src_orig2new_map = cti_obj.map_pairs[DDR_SUB].orig2new_map;
		src_new2orig_map = cti_obj.map_pairs[DDR_SUB].new2orig_map;

		dst_orig2new_map = cti_obj.map_pairs[SRAM_SUB].orig2new_map;
		dst_new2orig_map = cti_obj.map_pairs[SRAM_SUB].new2orig_map;

		cnt_ptr          = &(cti_obj.tot_rules_in_table[SRAM_SUB]);
	}

	if ( ct_rule_ptr->protocol == IPA_IPV6CT_INVALID_PROTO_FIELD_CMP )
	{
		IPADBG("%s: Special \"first rule in list\" case. "
			   "Rule's enabled bit on, but protocol implies deleted\n",
			   mig_dir_ptr);
		ret = 0;
		goto bail;
	}

	ret = ipa_nat_map_find(src_new2orig_map, tbl_rule_hdl, &orig_rule_hdl);

	if ( ret != 0 )
	{
		IPAERR("%s: ipa_nat_map_find(src_new2orig_map) fail\n", mig_dir_ptr);
		goto bail;
	}

	memset(&v6_rule, 0, sizeof(v6_rule));

	v6_rule.src_ipv6_lsb   = ct_rule_ptr->src_ipv6_lsb;
	v6_rule.src_ipv6_msb = ct_rule_ptr->src_ipv6_msb;
	v6_rule.dest_ipv6_lsb     = ct_rule_ptr->dest_ipv6_lsb;
	v6_rule.dest_ipv6_msb  = ct_rule_ptr->dest_ipv6_msb;
	if(ct_rule_ptr->in_allowed && ct_rule_ptr->out_allowed)
		v6_rule.direction_settings    = IPA_IPV6CT_DIRECTION_ALLOW_ALL;
	else if(ct_rule_ptr->in_allowed && !ct_rule_ptr->out_allowed)
		v6_rule.direction_settings    = IPA_IPV6CT_DIRECTION_ALLOW_IN;
	else if(!ct_rule_ptr->in_allowed && ct_rule_ptr->out_allowed)
		v6_rule.direction_settings    = IPA_IPV6CT_DIRECTION_ALLOW_OUT;
	else
		v6_rule.direction_settings    = IPA_IPV6CT_DIRECTION_DENY_ALL;
	v6_rule.ucp  = ct_rule_ptr->ucp;
	v6_rule.s    = ct_rule_ptr->s;
	v6_rule.uc_activation_index     = ct_rule_ptr->uc_activation_index;
	v6_rule.src_port       = ct_rule_ptr->src_port;
	v6_rule.dest_port   = ct_rule_ptr->dest_port;
	v6_rule.protocol = ct_rule_ptr->protocol;

	ret = ipa_ipv6ct_add_rule(dst_tbl_hdl, &v6_rule, &new_rule_hdl);

	if ( ret != 0 )
	{
		IPAERR("%s: ipa_ipv6ct_add_rule() fail\n", mig_dir_ptr);
		goto bail;
	}

	(*cnt_ptr)++;

	/*
	 * The following is needed to maintain the original handle and
	 * have it point to the new handle.
	 *
	 * Remember, original handle points to new and the new handle
	 * points back to original.
	 */
	ret = ipa_nat_map_add(dst_orig2new_map, orig_rule_hdl, new_rule_hdl);

	if ( ret != 0 )
	{
		IPAERR("%s: ipa_nat_map_add(dst_orig2new_map) fail\n", mig_dir_ptr);
		goto bail;
	}

	ret = ipa_nat_map_add(dst_new2orig_map, new_rule_hdl, orig_rule_hdl);

	if ( ret != 0 )
	{
		IPAERR("%s: ipa_nat_map_add(dst_new2orig_map) fail\n", mig_dir_ptr);
		goto bail;
	}

	IPADBG("orig_rule_hdl(0x%08X) new_rule_hdl(0x%08X)\n",
		   orig_rule_hdl, new_rule_hdl);

bail:
	IPADBG("Out\n");

	return ret;
}

/*
 * ****************************************************************************
 *
 * HIJACKED API FUNCTIONS START HERE
 *
 * ****************************************************************************
 */
int ipa_cti_add_ipv6_tbl(
	const char* mem_type_ptr,
	uint16_t    number_of_entries,
	uint32_t*   tbl_hdl)
{
	arb_t* args[] = {
		(arb_t*)(arb_t)number_of_entries,
		(arb_t*) tbl_hdl,
		(arb_t*) mem_type_ptr,
	};

	int ret;

	IPADBG("In\n");

	ret = ipa_cti_statemach(&cti_obj,CTI_TRIG_ADD_TABLE, args);

	if ( ret == 0 )
	{
		IPADBG("tbl_hdl val(0x%08X)\n", *tbl_hdl);
	}

	IPADBG("Out\n");

	return ret;
}

int ipa_cti_del_ipv6_tbl(
	uint32_t tbl_hdl)
{
	arb_t* args[] = {
		(arb_t*)(arb_t)tbl_hdl,
	};

	int ret;

	IPADBG("In\n");

	ret = ipa_cti_statemach(&cti_obj, CTI_TRIG_DEL_TABLE, args);

	IPADBG("Out\n");

	return ret;
}

int ipa_cti_add_ipv6_rule(
	uint32_t                 tbl_hdl,
	const ipa_ipv6ct_rule* clnt_rule,
	uint32_t*                rule_hdl )
{
	arb_t* args[] = {
		(arb_t*)(arb_t)tbl_hdl,
		(arb_t*) clnt_rule,
		(arb_t*) rule_hdl,
	};

	int ret;

	IPADBG("In\n");

	ret = ipa_cti_statemach(&cti_obj, CTI_TRIG_ADD_RULE, args);

	if ( ret == 0 )
	{
		IPADBG("rule_hdl val(%u)\n", *rule_hdl);
	}

	IPADBG("Out\n");

	return ret;
}

int ipa_cti_del_ipv6_rule(
	uint32_t tbl_hdl,
	uint32_t rule_hdl )
{
	arb_t* args[] = {
		(arb_t*)(arb_t)tbl_hdl,
		(arb_t*)(arb_t)rule_hdl,
	};

	int ret;

	IPADBG("In\n");

	ret = ipa_cti_statemach(&cti_obj, CTI_TRIG_DEL_RULE, args);

	IPADBG("Out\n");

	return ret;
}

int ipa_cti_query_timestamp(
	uint32_t  tbl_hdl,
	uint32_t  rule_hdl,
	uint32_t* time_stamp)
{
	arb_t* args[] = {
		(arb_t*)(arb_t)tbl_hdl,
		(arb_t*)(arb_t)rule_hdl,
		(arb_t*) time_stamp,
	};

	int ret;

	IPADBG("In\n");

	ret = ipa_cti_statemach(&cti_obj, CTI_TRIG_GET_TSTAMP, args);

	if ( ret == 0 )
	{
		IPADBG("time_stamp val(0x%08X)\n", *time_stamp);
	}

	IPADBG("Out\n");

	return ret;
}


int ipa_cti_clear_ipv6_tbl(
	uint32_t tbl_hdl,
	const char* mem_type_ptr)
{
	arb_t* args[] = {
		(arb_t*)(arb_t)tbl_hdl,
		(arb_t*) mem_type_ptr,
	};

	int ret;

	IPADBG("In\n");

	ret = ipa_cti_statemach(&cti_obj, CTI_TRIG_CLR_TABLE, args);

	IPADBG("Out\n");

	return ret;
}

/*
 * ****************************************************************************
 *
 * STATE MACHINE CODE BEGINS HERE
 *
 * ****************************************************************************
 */
static int _smCtUndef(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr ); /* forward declaration */

/******************************************************************************/
/*
 * FUNCTION: _smCtDelTbl
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the destruction of the DDR based CT
 *   table.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtDelTbl(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t**  args = arb_data_ptr;

	uint32_t tbl_hdl = (uint32_t) args[0];

	int ret;

	IPADBG("In\n");

	IPADBG("tbl_hdl(0x%08X)\n", tbl_hdl);

	ret = ipa_ipv6ct_del_tbl(tbl_hdl);

	if ( ret == 0 && ! CT_IN_HYBRID_STATE() )
	{
		/*
		 * The following will create the preferred "initial state" for
		 * restart...
		 */
		CT_BACK2_UNSTARTED_STATE();
	}

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtFirstTbl
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the creation of the very first CT table(s)
 *   before any others have ever been created...
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtFirstTbl(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t**   args = arb_data_ptr;

	uint16_t    number_of_entries = (uint16_t)    args[0];
	uint32_t*   tbl_hdl_ptr       = (uint32_t*)   args[1];
	const char* mem_type_ptr      = (const char*) args[2];

	int ret;

	IPADBG("In\n");

	/*
	 * This is the first time in here.  Let the ipacm's XML config (or
	 * state_to_hold) drive initial state...
	 */
	SET_CTIOBJ_STATE(
		cti_obj_ptr,
		(cti_obj_ptr->hold_state && cti_obj_ptr->state_to_hold) ?
		cti_obj_ptr->state_to_hold                               :
		mem_type_str_to_ipa_cti_state(mem_type_ptr));

	ret = ipa_cti_statemach(cti_obj_ptr, CTI_TRIG_ADD_TABLE, args);

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtAddDdrTbl
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the creation of a CT table in DDR.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtAddDdrTbl(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t**   args = arb_data_ptr;

	uint16_t  number_of_entries = (uint16_t)  args[0];
	uint32_t* tbl_hdl_ptr       = (uint32_t*) args[1];

	int ret;

	IPADBG("In\n");

	IPADBG("number_of_entries(%u) tbl_hdl_ptr(%p)\n",
		   number_of_entries, tbl_hdl_ptr);

	ret = ipa_ipv6ct_add_tbl(
		number_of_entries,
		IPA_NAT_MEM_IN_DDR,
		&cti_obj_ptr->ddr_tbl_hdl);

	if ( ret == 0 )
	{
		*tbl_hdl_ptr = cti_obj_ptr->ddr_tbl_hdl;

		IPADBG("DDR table creation successful: tbl_hdl(0x%08X)\n",
			   *tbl_hdl_ptr);
	}

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtAddSramTbl
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the creation of a CT table in SRAM.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtAddSramTbl(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t**   args = arb_data_ptr;

	uint16_t  number_of_entries = (uint16_t)  args[0];
	uint32_t* tbl_hdl_ptr       = (uint32_t*) args[1];

	uint32_t  sram_size = 0;

	int ret;

	IPADBG("In\n");

	IPADBG("tbl_hdl_ptr(%p)\n",
		   tbl_hdl_ptr);

	ret = ipa_cti_get_sram_size(&sram_size);

	if ( ret == 0 )
	{
		ret = ipa_calc_num_sram_ct_table_entries(
			sram_size,
			sizeof(struct ipa_ipv6ct_hw_entry),
			&cti_obj_ptr->tot_slots_in_sram);

		if ( ret == 0 )
		{
			cti_obj_ptr->back_to_sram_thresh =
				PRCNT_OF(cti_obj_ptr->tot_slots_in_sram);

			IPADBG("sram_size(%u or 0x%x) tot_slots_in_sram(%u) back_to_sram_thresh(%u)\n",
				   sram_size,
				   sram_size,
				   cti_obj_ptr->tot_slots_in_sram,
				   cti_obj_ptr->back_to_sram_thresh);

			IPADBG("Voting clock on for sram table creation\n");

			if ( (ret = ipa_ct_vote_clock(IPA_APP_CLK_VOTE)) != 0 )
			{
				IPAERR("Voting clock on failed\n");
				goto done;
			}

			ret = ipa_ipv6ct_add_tbl(
				cti_obj_ptr->tot_slots_in_sram,
				IPA_NAT_MEM_IN_SRAM,
				&cti_obj_ptr->sram_tbl_hdl);

			if ( ipa_ct_vote_clock(IPA_APP_CLK_DEVOTE) != 0 )
			{
				IPAWARN("Voting clock off failed\n");
			}

			if ( ret == 0 )
			{
				*tbl_hdl_ptr = cti_obj_ptr->sram_tbl_hdl;

				IPADBG("SRAM table creation successful: tbl_hdl(0x%08X)\n",
					   *tbl_hdl_ptr);
			}
		}
	}

done:
	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtAddSramAndDdrTbl
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the creation of CT tables in both DDR
 *   and in SRAM.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtAddSramAndDdrTbl(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t**   args = arb_data_ptr;

	uint16_t  number_of_entries = (uint16_t)  args[0];
	uint32_t* tbl_hdl_ptr       = (uint32_t*) args[1];

	uint32_t tbl_hdl;

	int ret;

	IPADBG("In\n");

	cti_obj_ptr->tot_rules_in_table[SRAM_SUB] = 0;
	cti_obj_ptr->tot_rules_in_table[DDR_SUB]  = 0;

	ipa_nat_map_clear(cti_obj_ptr->map_pairs[SRAM_SUB].orig2new_map);
	ipa_nat_map_clear(cti_obj_ptr->map_pairs[SRAM_SUB].new2orig_map);
	ipa_nat_map_clear(cti_obj_ptr->map_pairs[DDR_SUB].orig2new_map);
	ipa_nat_map_clear(cti_obj_ptr->map_pairs[DDR_SUB].new2orig_map);

	ret = _smCtAddSramTbl(cti_obj_ptr, trigger, arb_data_ptr);

	if ( ret == 0 )
	{
		if ( cti_obj_ptr->tot_slots_in_sram >= number_of_entries )
		{
			/*
			 * The number of slots in SRAM can accommodate what was
			 * being requested for DDR, hence no need to use DDR and
			 * we will continue by using SRAM only...
			 */
			SET_CTIOBJ_STATE(cti_obj_ptr, CTI_STATE_SRAM_ONLY);
		}
		else
		{
			/*
			 * SRAM not big enough. Let's create secondary DDR based
			 * table...
			 */
			arb_t*   new_args[] = {
				(arb_t*)(arb_t)number_of_entries,
				(arb_t*) &tbl_hdl,  /* to protect app's table handle above */
			};

			ret = _smCtAddDdrTbl(cti_obj_ptr, trigger, new_args);

			if ( ret == 0 )
			{
				/*
				 * The following will tell the IPA to change focus to
				 * SRAM...
				 */
				ret = ipa_cti_statemach(cti_obj_ptr, CTI_TRIG_GOTO_SRAM, 0);
			}
		}
	}
	else
	{
		/*
		 * SRAM table creation in HYBRID mode failed.  Can we fall
		 * back to DDR only?  We need to try and see what happens...
		 */
		ret = _smCtAddDdrTbl(cti_obj_ptr, trigger, arb_data_ptr);

		if ( ret == 0 )
		{
			SET_CTIOBJ_STATE(cti_obj_ptr, CTI_STATE_DDR_ONLY);
		}
	}

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smDelSramAndDdrTbl
 *
 * PARAMS:
 *
 *   nati_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the destruction of the SRAM, then DDR
 *   based CT tables.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtDelSramAndDdrTbl(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	int ret;

	IPADBG("In\n");

	cti_obj_ptr->tot_rules_in_table[SRAM_SUB] = 0;
	cti_obj_ptr->tot_rules_in_table[DDR_SUB]  = 0;

	ipa_nat_map_clear(cti_obj_ptr->map_pairs[SRAM_SUB].orig2new_map);
	ipa_nat_map_clear(cti_obj_ptr->map_pairs[SRAM_SUB].new2orig_map);
	ipa_nat_map_clear(cti_obj_ptr->map_pairs[DDR_SUB].orig2new_map);
	ipa_nat_map_clear(cti_obj_ptr->map_pairs[DDR_SUB].new2orig_map);

	ret = _smCtDelTbl(cti_obj_ptr, trigger, arb_data_ptr);

	if ( ret == 0 )
	{
		arb_t* new_args[] = {
			(arb_t*)(arb_t)cti_obj_ptr->ddr_tbl_hdl,
		};

		ret = _smCtDelTbl(cti_obj_ptr, trigger, new_args);
	}

	if ( ret == 0 )
	{
		/*
		 * The following will create the preferred "initial state" for
		 * restart...
		 */
		CT_BACK2_UNSTARTED_STATE();
	}

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smAddRuleToTbl
 *
 * PARAMS:
 *
 *   nati_obj_ptr (IN) A pointer to an initialized nati object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the addtion of a NAT rule into the DDR
 *   based table.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtAddRuleToTbl(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t** args = arb_data_ptr;

	uint32_t           tbl_hdl   = (uint32_t)           args[0];
	ipa_ipv6ct_rule* clnt_rule = (ipa_ipv6ct_rule*) args[1];
	uint32_t*          rule_hdl  = (uint32_t*)          args[2];

	char buf[1024];

	int ret;

	IPADBG("In\n");

	IPADBG("tbl_hdl(0x%08X) clnt_rule_ptr(%p) rule_hdl_ptr(%p)\n",
		   tbl_hdl, clnt_rule, rule_hdl);

	ret = ipa_ipv6ct_add_rule(tbl_hdl, clnt_rule, rule_hdl);

	if ( ret == 0 )
	{
		uint32_t* cnt_ptr = CT_CHOOSE_CNTR();

		(*cnt_ptr)++;

		IPADBG("rule_hdl value(%u or 0x%08X)\n",
			   *rule_hdl, *rule_hdl);
	}

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smDelRuleFromTbl
 *
 * PARAMS:
 *
 *   nati_obj_ptr (IN) A pointer to an initialized nati object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the deletion of a NAT rule from the DDR
 *   based table.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtDelRuleFromTbl(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t**  args = arb_data_ptr;

	uint32_t tbl_hdl  = (uint32_t) args[0];
	uint32_t rule_hdl = (uint32_t) args[1];

	int ret;

	IPADBG("In\n");

	IPADBG("tbl_hdl(0x%08X) rule_hdl(%u)\n", tbl_hdl, rule_hdl);

	ret = ipa_ipv6ct_del_rule(tbl_hdl, rule_hdl);

	if ( ret == 0 )
	{
		uint32_t* cnt_ptr = CT_CHOOSE_CNTR();

		(*cnt_ptr)--;
	}

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtAddRuleHybrid
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the addition of a CT rule into either
 *   the SRAM or DDR based table.
 *
 *   *** !!! HOWEVER *** REMEMBER !!! ***
 *
 *   We're here because we're in a HYBRID state...with the potential
 *   moving between SRAM and DDR.  THIS HAS IMLICATIONS AS IT RELATES
 *   TO RULE MAPPING.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtAddRuleHybrid(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t** args = arb_data_ptr;

	uint32_t           tbl_hdl   = (uint32_t)           args[0];
	ipa_ipv6ct_rule* clnt_rule = (ipa_ipv6ct_rule*) args[1];
	uint32_t*          rule_hdl  = (uint32_t*)          args[2];

	arb_t*             new_args[] = {
		(arb_t*)(arb_t)(cti_obj_ptr->curr_state == CTI_STATE_HYBRID) ?
		         tbl_hdl :
		         cti_obj_ptr->ddr_tbl_hdl,
		(arb_t*) clnt_rule,
		(arb_t*) rule_hdl,
	};

	uint32_t orig2new_map, new2orig_map;

	int ret;

	IPADBG("In\n");

	ret = _smCtAddRuleToTbl(cti_obj_ptr, trigger, new_args);

	if ( ret == 0 )
	{
		/*
		 * The rule_hdl is used to find a rule in the ct table.  It
		 * is, in effect, an index into the table.  The applcation
		 * above us retains it for future manipulation of the rule in
		 * the table.
		 *
		 * In hybrid mode, a rule can and will move between SRAM and
		 * DDR.  Because of this, its handle will change.  The
		 * application has only the original handle and doesn't know
		 * of the new handle.  A mapping, used in hybrid mode, will
		 * maintain a relationship between the original handle and the
		 * rule's current real handle...
		 *
		 * To help you get a mindset of how this is done:
		 *
		 *   The original handle will map (point) to the new and new
		 *   handle will map (point) back to original.
		 *
		 * NOTE WELL: There are two sets of maps.  One for each memory
		 *            type...
		 */
		CT_CHOOSE_MAPS(orig2new_map, new2orig_map);

		ret = ipa_nat_map_add(orig2new_map, *rule_hdl, *rule_hdl);

		if ( ret == 0 )
		{
			ret = ipa_nat_map_add(new2orig_map, *rule_hdl, *rule_hdl);
		}
	}
	else
	{
		if ( cti_obj_ptr->curr_state == CTI_STATE_HYBRID
			 &&
			 ! cti_obj_ptr->hold_state )
		{
			/*
			 * In hybrid mode, we always start in SRAM...hence
			 * CTI_STATE_HYBRID implies SRAM.  The rule addition
			 * above did not work, meaning the SRAM table is full,
			 * hence let's jump to DDR...
			 *
			 * The following will focus us on DDR and cause the copy
			 * of data from SRAM to DDR.
			 */
			IPAINFO("Add of rule failed...attempting table switch\n");

			ret = ipa_cti_statemach(cti_obj_ptr, CTI_TRIG_TBL_SWITCH, 0);

			if ( ret == 0 )
			{
				SET_CTIOBJ_STATE(cti_obj_ptr, CTI_STATE_HYBRID_DDR);

				/*
				 * Now add the rule to DDR...
				 */
				ret = ipa_cti_statemach(cti_obj_ptr, trigger, arb_data_ptr);
			}
		}
	}

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtDelRuleHybrid
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the deletion of a CT rule from either
 *   the SRAM or DDR based table.
 *
 *   *** !!! HOWEVER *** REMEMBER !!! ***
 *
 *   We're here because we're in a HYBRID state...with the potential
 *   moving between SRAM and DDR.  THIS HAS IMLICATIONS AS IT RELATES
 *   TO RULE MAPPING.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtDelRuleHybrid(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t**  args = arb_data_ptr;

	uint32_t tbl_hdl       = (uint32_t) args[0];
	uint32_t orig_rule_hdl = (uint32_t) args[1];

	uint32_t new_rule_hdl;

	uint32_t orig2new_map,  new2orig_map;

	int      ret;

	IPADBG("In\n");

	CT_CHOOSE_MAPS(orig2new_map, new2orig_map);

	/*
	 * The rule_hdl is used to find a rule in the ct table.  It is,
	 * in effect, an index into the table.  The applcation above us
	 * retains it for future manipulation of the rule in the table.
	 *
	 * In hybrid mode, a rule can and will move between SRAM and DDR.
	 * Because of this, its handle will change.  The application has
	 * only the original handle and doesn't know of the new handle.  A
	 * mapping, used in hybrid mode, will maintain a relationship
	 * between the original handle and the rule's current real
	 * handle...
	 *
	 * To help you get a mindset of how this is done:
	 *
	 *   The original handle will map (point) to the new and new
	 *   handle will map (point) back to original.
	 *
	 * NOTE WELL: There are two sets of maps.  One for each memory
	 *            type...
	 */
	ret = ipa_nat_map_del(orig2new_map, orig_rule_hdl, &new_rule_hdl);

	if ( ret == 0 )
	{
		arb_t* new_args[]  = {
			(arb_t*)(arb_t)(cti_obj_ptr->curr_state == CTI_STATE_HYBRID) ?
			        tbl_hdl :
			        cti_obj_ptr->ddr_tbl_hdl,
			(arb_t*)(arb_t)new_rule_hdl,
		};

		IPADBG("orig_rule_hdl(0x%08X) -> new_rule_hdl(0x%08X)\n",
			   orig_rule_hdl, new_rule_hdl);

		ipa_nat_map_del(new2orig_map, new_rule_hdl, NULL);

		ret = _smCtDelRuleFromTbl(cti_obj_ptr, trigger, new_args);

		if ( ret == 0 && cti_obj_ptr->curr_state == CTI_STATE_HYBRID_DDR )
		{
			/*
			 * We need to check when/if we can go back to SRAM.
			 *
			 * How/why can we go back?
			 *
			 *   Given enough deletions, and when we get to a user
			 *   defined threshold (ie. a percentage of what SRAM can
			 *   hold), we can pop back to using SRAM.
			 */
			uint32_t* cnt_ptr = CT_CHOOSE_CNTR();

			if ( *cnt_ptr <= cti_obj_ptr->back_to_sram_thresh
				 &&
				 ! cti_obj_ptr->hold_state )
			{
				/*
				 * The following will focus us on SRAM and cause the copy
				 * of data from DDR to SRAM.
				 */
				IPAINFO("Switch back to SRAM threshold has been reached -> "
						"Total rules in DDR(%u) <= SRAM THRESH(%u)\n",
						*cnt_ptr,
						cti_obj_ptr->back_to_sram_thresh);

				ret = ipa_cti_statemach(cti_obj_ptr, CTI_TRIG_TBL_SWITCH, 0);

				if ( ret == 0 )
				{
					SET_CTIOBJ_STATE(cti_obj_ptr, CTI_STATE_HYBRID);
				}
				else
				{
					/*
					 * The following will force us stay in DDR for
					 * now, but the next delete will trigger the
					 * switch logic above to run again...perhaps it
					 * will work then.
					 */
					ret = 0;
				}
			}
		}
	}

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtGoToDdr
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the IPA to use the DDR based CT
 *   table...
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtGoToDdr(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	int ret;
	struct ipa_ct_cache*           ct_cache_ptr;
	struct ipa_ct_ip6_table_cache* ct_table;

	IPADBG("In\n");

	ret = ipa_ipv6ct_post_init_cmd_int(cti_obj_ptr->ddr_tbl_hdl);

	if ( ret == 0 )
	{
		SET_CTIOBJ_STATE(cti_obj_ptr, CTI_STATE_HYBRID_DDR);
	}

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtGoToSram
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the IPA to use the SRAM based CT
 *   table...
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtGoToSram(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	int ret;

	IPADBG("In\n");

	ret = ipa_ipv6ct_post_init_cmd_int(cti_obj_ptr->sram_tbl_hdl);

	if ( ret == 0 )
	{
		SET_CTIOBJ_STATE(cti_obj_ptr, CTI_STATE_HYBRID);
	}

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtGetTmStmp
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   Retrieve rule's timestamp from CT table.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtGetTmStmp(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t** args = arb_data_ptr;

	uint32_t  tbl_hdl    = (uint32_t)  args[0];
	uint32_t  rule_hdl   = (uint32_t)  args[1];
	uint32_t* time_stamp = (uint32_t*) args[2];

	int ret;

	IPADBG("In\n");

	IPADBG("tbl_hdl(0x%08X) rule_hdl(%u) time_stamp_ptr(%p)\n",
		   tbl_hdl, rule_hdl, time_stamp);

	ret = ipa_ipv6ct_query_timestamp(tbl_hdl, rule_hdl, time_stamp);

	if ( ret == 0 )
	{
		IPADBG("time_stamp(0x%08X)\n", *time_stamp);
	}

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtGetTmStmpHybrid
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   Retrieve rule's timestamp from the state approriate CT table.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtGetTmStmpHybrid(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t** args = arb_data_ptr;

	uint32_t  tbl_hdl       = (uint32_t)  args[0];
	uint32_t  orig_rule_hdl = (uint32_t)  args[1];
	uint32_t* time_stamp    = (uint32_t*) args[2];

	uint32_t  new_rule_hdl;

	uint32_t  orig2new_map, new2orig_map;

	int       ret;

	IPADBG("In\n");

	CT_CHOOSE_MAPS(orig2new_map, new2orig_map);

	ret = ipa_nat_map_find(orig2new_map, orig_rule_hdl, &new_rule_hdl);

	if ( ret == 0 )
	{
		arb_t* new_args[] = {
			(arb_t*)(arb_t)(cti_obj_ptr->curr_state ==CTI_STATE_HYBRID) ?
			         tbl_hdl :
			         cti_obj_ptr->ddr_tbl_hdl,
			(arb_t*)(arb_t)new_rule_hdl,
			(arb_t*) time_stamp,
		};

		ret = _smCtGetTmStmp(cti_obj_ptr, trigger, new_args);
	}

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtClrTbl
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the clearing of a table.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtClrTbl(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t**  args = arb_data_ptr;

	uint32_t tbl_hdl = (uint32_t) args[0];
	enum ipa3_nat_mem_in nmi = 0;

	uint32_t             unused_hdl = 0, sub;

	int ret;

	IPADBG("In\n");

	IPADBG("tbl_hdl(0x%08X)\n", tbl_hdl);


	CT_BREAK_TBL_HDL(tbl_hdl, nmi, unused_hdl);

	if ( ! IPA_VALID_NAT_MEM_IN(nmi) ) {
		IPAERR("Bad cache type\n");
		ret = -EINVAL;
		goto bail;
	}


	sub = (nmi == IPA_NAT_MEM_IN_SRAM) ? SRAM_SUB : DDR_SUB;

	cti_obj_ptr->tot_rules_in_table[sub] = 0;

	ipa_nat_map_clear(cti_obj.map_pairs[sub].orig2new_map);
	ipa_nat_map_clear(cti_obj.map_pairs[sub].new2orig_map);

	ret = ipa_ipv6ct_clear_table(tbl_hdl);

bail:
	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtClrTblHybrid
 *
 * PARAMS:
 *
 *   nati_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the clearing of the appropriate hybrid
 *   table.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtClrTblHybrid(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t**  args = arb_data_ptr;

	uint32_t tbl_hdl = (uint32_t) args[0];

	arb_t*   new_args[] = {
		(arb_t*)(arb_t)(cti_obj_ptr->curr_state == CTI_STATE_HYBRID) ?
		         tbl_hdl :
		         cti_obj_ptr->ddr_tbl_hdl,
	};

	int ret;

	IPADBG("In\n");

	ret = _smCtClrTbl(cti_obj_ptr, trigger, new_args);

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtWalkTbl
 *
 * PARAMS:
 *
 *   nati_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the walk of a table.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtWalkTbl(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t** args = arb_data_ptr;

	uint32_t          tbl_hdl = (uint32_t)          args[0];
	CtWhichTbl2Use      which   = (CtWhichTbl2Use)      args[1];
	ipa_table_walk_cb walk_cb = (ipa_table_walk_cb) args[2];
	arb_t*            wadp    = (arb_t*)            args[3];

	int ret;

	IPADBG("In\n");

	IPADBG("tbl_hdl(0x%08X)\n", tbl_hdl);

	ret = ipa_ipv6ct_walk_table(tbl_hdl, which, walk_cb, wadp);

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtWalkTblHybrid
 *
 * PARAMS:
 *
 *   nati_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the walk of the appropriate hybrid
 *   table.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtWalkTblHybrid(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t** args = arb_data_ptr;

	uint32_t          tbl_hdl = (uint32_t)          args[0];
	CtWhichTbl2Use      which   = (CtWhichTbl2Use)      args[1];
	ipa_table_walk_cb walk_cb = (ipa_table_walk_cb) args[2];
	arb_t*            wadp    = (arb_t*)            args[3];

	arb_t* new_args[] = {
		(arb_t*)(arb_t)(cti_obj_ptr->curr_state == CTI_STATE_HYBRID) ?
		         tbl_hdl :
		         cti_obj_ptr->ddr_tbl_hdl,
		(arb_t*) which,
		(arb_t*) walk_cb,
		(arb_t*) wadp,
	};

	int ret;

	IPADBG("In\n");

	ret = _smCtWalkTbl(cti_obj_ptr, trigger, new_args);

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtStatTbl
 *
 * PARAMS:
 *
 *   nati_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will get size/usage stats for a table.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtStatTbl(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t** args = arb_data_ptr;

	uint32_t            tbl_hdl       = (uint32_t)            args[0];
	ipa_cti_tbl_stats* ct_stats_ptr = (ipa_cti_tbl_stats*) args[1];

	int ret;

	IPADBG("In\n");

	IPADBG("tbl_hdl(0x%08X)\n", tbl_hdl);

	ret = ipa_ipv6ct_stats_table(tbl_hdl, ct_stats_ptr);

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtStatTblHybrid
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause the retrieval of table size/usage stats
 *   for the appropriate hybrid table.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtStatTblHybrid(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	arb_t** args = arb_data_ptr;

	uint32_t            tbl_hdl       = (uint32_t)            args[0];
	ipa_cti_tbl_stats* ct_stats_ptr = (ipa_cti_tbl_stats*) args[1];

	arb_t* new_args[] = {
		(arb_t*)(arb_t)(cti_obj_ptr->curr_state == CTI_STATE_HYBRID) ?
		         tbl_hdl :
		         cti_obj_ptr->ddr_tbl_hdl,
		(arb_t*) ct_stats_ptr,
	};

	int ret;

	IPADBG("In\n");

	ret = _smCtStatTbl(cti_obj_ptr, trigger, new_args);

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtSwitchFromDdrToSram
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause a copy of the DDR table to SRAM and then
 *   will make the IPA use the SRAM...
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtSwitchFromDdrToSram(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	cti_switch_stats* sw_stats_ptr = CT_CHOOSE_SW_STATS();

	uint32_t*          cnt_ptr      = CT_CHOOSE_CNTR();

	ipa_cti_tbl_stats ct_stats;

	const char*        mem_type;

	uint64_t           start, stop;

	int                stats_ret, ret;

	bool               collect_stats = (bool) arb_data_ptr;

	IPADBG("In\n");

	stats_ret = (collect_stats) ?
		ipa_ipv6ct_stats_table(
			cti_obj_ptr->ddr_tbl_hdl, &ct_stats) :
		-1;

	currTimeAs(TimeAsNanSecs, &start);

	/*
	 * First, switch focus to SRAM...
	 */
	ret = ipa_cti_statemach(cti_obj_ptr, CTI_TRIG_GOTO_SRAM, 0);

	if ( ret == 0 )
	{
		/*
		 * Clear destination counter...
		 */
		cti_obj_ptr->tot_rules_in_table[SRAM_SUB] = 0;

		/*
		 * Clear destination SRAM maps...
		 */
		ipa_nat_map_clear(cti_obj.map_pairs[SRAM_SUB].orig2new_map);
		ipa_nat_map_clear(cti_obj.map_pairs[SRAM_SUB].new2orig_map);

		/*
		 * Now copy DDR's content to SRAM...
		 */
		ret = ipa_ipv6ct_copy_table(
			cti_obj_ptr->ddr_tbl_hdl,
			cti_obj_ptr->sram_tbl_hdl,
			ct_migrate_rule);

		currTimeAs(TimeAsNanSecs, &stop);

		if ( ret == 0 )
		{
			sw_stats_ptr->pass += 1;

			IPADBG("Transistion from DDR to SRAM took %f microseconds\n",
				   (float) (stop - start) / 1000.0);
		}
		else
		{
			sw_stats_ptr->fail += 1;
		}

		IPADBG("Transistion pass/fail counts (DDR to SRAM) PASS: %u FAIL: %u\n",
			   sw_stats_ptr->pass,
			   sw_stats_ptr->fail);

		if ( stats_ret == 0 )
		{
			mem_type = ipa3_ct_mem_in_as_str(ct_stats.nmi);

			/*
			 * CT table stats...
			 */
			IPADBG("Able to add (%u) records to %s "
				   "CT table of size (%u) or (%f) percent\n",
				   *cnt_ptr,
				   mem_type,
				   ct_stats.tot_ents,
				   ((float) *cnt_ptr / (float) ct_stats.tot_ents) * 100.0);

			IPADBG("Able to add (%u) records to %s "
				   "NAT BASE table of size (%u) or (%f) percent\n",
				   ct_stats.tot_base_ents_filled,
				   mem_type,
				   ct_stats.tot_base_ents,
				   ((float) ct_stats.tot_base_ents_filled /
					(float) ct_stats.tot_base_ents) * 100.0);

			IPADBG("Able to add (%u) records to %s "
				   "NAT EXPN table of size (%u) or (%f) percent\n",
				   ct_stats.tot_expn_ents_filled,
				   mem_type,
				   ct_stats.tot_expn_ents,
				   ((float) ct_stats.tot_expn_ents_filled /
					(float) ct_stats.tot_expn_ents) * 100.0);

			IPADBG("%s NAT table chains: tot_chains(%u) min_len(%u) max_len(%u) avg_len(%f)\n",
				   mem_type,
				   ct_stats.tot_chains,
				   ct_stats.min_chain_len,
				   ct_stats.max_chain_len,
				   ct_stats.avg_chain_len);

		}
	}

	IPADBG("Out\n");

	return ret;
}

/******************************************************************************/
/*
 * FUNCTION: _smCtSwitchFromSramToDdr
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following will cause a copy of the SRAM table to DDR and then
 *   will make the IPA use the DDR...
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtSwitchFromSramToDdr(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	cti_switch_stats* sw_stats_ptr = CT_CHOOSE_SW_STATS();

	uint32_t*          cnt_ptr      = CT_CHOOSE_CNTR();

	ipa_cti_tbl_stats ct_stats;

	const char*        mem_type;

	uint64_t           start, stop;

	int                stats_ret, ret;

	bool               collect_stats = (bool) arb_data_ptr;

	IPADBG("In\n");

	stats_ret = (collect_stats) ?
		ipa_ipv6ct_stats_table(
			cti_obj_ptr->sram_tbl_hdl, &ct_stats) :
		-1;

	currTimeAs(TimeAsNanSecs, &start);

	/*
	 * First, switch focus to DDR...
	 */
	ret = ipa_cti_statemach(cti_obj_ptr, CTI_TRIG_GOTO_DDR, 0);

	if ( ret == 0 )
	{
		/*
		 * Clear destination counter...
		 */
		cti_obj_ptr->tot_rules_in_table[DDR_SUB] = 0;

		/*
		 * Clear destination DDR maps...
		 */
		ipa_nat_map_clear(cti_obj.map_pairs[DDR_SUB].orig2new_map);
		ipa_nat_map_clear(cti_obj.map_pairs[DDR_SUB].new2orig_map);

		/*
		 * Now copy SRAM's content to DDR...
		 */
		ret = ipa_ipv6ct_copy_table(
			cti_obj_ptr->sram_tbl_hdl,
			cti_obj_ptr->ddr_tbl_hdl,
			ct_migrate_rule);

		currTimeAs(TimeAsNanSecs, &stop);

		if ( ret == 0 )
		{
			sw_stats_ptr->pass += 1;

			IPADBG("Transistion from SRAM to DDR took %f microseconds\n",
				   (float) (stop - start) / 1000.0);
		}
		else
		{
			sw_stats_ptr->fail += 1;
		}

		IPADBG("Transistion pass/fail counts (SRAM to DDR) PASS: %u FAIL: %u\n",
			   sw_stats_ptr->pass,
			   sw_stats_ptr->fail);

		if ( stats_ret == 0 )
		{
			mem_type = ipa3_ct_mem_in_as_str(ct_stats.nmi);

			/*
			 * CT table stats...
			 */
			IPADBG("Able to add (%u) records to %s "
				   "CT table of size (%u) or (%f) percent\n",
				   *cnt_ptr,
				   mem_type,
				   ct_stats.tot_ents,
				   ((float) *cnt_ptr / (float) ct_stats.tot_ents) * 100.0);

			IPADBG("Able to add (%u) records to %s "
				   "CT BASE table of size (%u) or (%f) percent\n",
				   ct_stats.tot_base_ents_filled,
				   mem_type,
				   ct_stats.tot_base_ents,
				   ((float) ct_stats.tot_base_ents_filled /
					(float) ct_stats.tot_base_ents) * 100.0);

			IPADBG("Able to add (%u) records to %s "
				   "CT EXPN table of size (%u) or (%f) percent\n",
				   ct_stats.tot_expn_ents_filled,
				   mem_type,
				   ct_stats.tot_expn_ents,
				   ((float) ct_stats.tot_expn_ents_filled /
					(float) ct_stats.tot_expn_ents) * 100.0);

			IPADBG("%s CT table chains: tot_chains(%u) min_len(%u) max_len(%u) avg_len(%f)\n",
				   mem_type,
				   ct_stats.tot_chains,
				   ct_stats.min_chain_len,
				   ct_stats.max_chain_len,
				   ct_stats.avg_chain_len);

		}
	}

	IPADBG("Out\n");

	return ret;
}


/******************************************************************************/
/*
 * The following table relates a cti object's state and a transition
 * trigger to a callback...
 */
static cti_statemach_tuple
_ct_state_mach_tbl[CTI_STATE_LAST+1][CTI_TRIG_LAST+1] =
{
	{
		SM_ROW( CTI_STATE_NULL,       CTI_TRIG_NULL,       _smCtUndef ),
		SM_ROW( CTI_STATE_NULL,       CTI_TRIG_ADD_TABLE,  _smCtFirstTbl ),
		SM_ROW( CTI_STATE_NULL,       CTI_TRIG_DEL_TABLE,  _smCtUndef ),
		SM_ROW( CTI_STATE_NULL,       CTI_TRIG_CLR_TABLE,  _smCtUndef ),
		SM_ROW( CTI_STATE_NULL,       CTI_TRIG_WLK_TABLE,  _smCtUndef ),
		SM_ROW( CTI_STATE_NULL,       CTI_TRIG_TBL_STATS,  _smCtUndef ),
		SM_ROW( CTI_STATE_NULL,       CTI_TRIG_ADD_RULE,   _smCtUndef ),
		SM_ROW( CTI_STATE_NULL,       CTI_TRIG_DEL_RULE,   _smCtUndef ),
		SM_ROW( CTI_STATE_NULL,       CTI_TRIG_TBL_SWITCH, _smCtUndef ),
		SM_ROW( CTI_STATE_NULL,       CTI_TRIG_GOTO_DDR,   _smCtUndef ),
		SM_ROW( CTI_STATE_NULL,       CTI_TRIG_GOTO_SRAM,  _smCtUndef ),
		SM_ROW( CTI_STATE_NULL,       CTI_TRIG_GET_TSTAMP, _smCtUndef ),
		SM_ROW( CTI_STATE_NULL,       CTI_TRIG_LAST,       _smCtUndef ),
	},

	{
		SM_ROW( CTI_STATE_DDR_ONLY,   CTI_TRIG_NULL,       _smCtUndef ),
		SM_ROW( CTI_STATE_DDR_ONLY,   CTI_TRIG_ADD_TABLE,  _smCtAddDdrTbl ),
		SM_ROW( CTI_STATE_DDR_ONLY,   CTI_TRIG_DEL_TABLE,  _smCtDelTbl ),
		SM_ROW( CTI_STATE_DDR_ONLY,   CTI_TRIG_CLR_TABLE,  _smCtClrTbl ),
		SM_ROW( CTI_STATE_DDR_ONLY,   CTI_TRIG_WLK_TABLE,  _smCtWalkTbl ),
		SM_ROW( CTI_STATE_DDR_ONLY,   CTI_TRIG_TBL_STATS,  _smCtStatTbl ),
		SM_ROW( CTI_STATE_DDR_ONLY,   CTI_TRIG_ADD_RULE,   _smCtAddRuleToTbl ),
		SM_ROW( CTI_STATE_DDR_ONLY,   CTI_TRIG_DEL_RULE,   _smCtDelRuleFromTbl ),
		SM_ROW( CTI_STATE_DDR_ONLY,   CTI_TRIG_TBL_SWITCH, _smCtUndef ),
		SM_ROW( CTI_STATE_DDR_ONLY,   CTI_TRIG_GOTO_DDR,   _smCtUndef ),
		SM_ROW( CTI_STATE_DDR_ONLY,   CTI_TRIG_GOTO_SRAM,  _smCtUndef ),
		SM_ROW( CTI_STATE_DDR_ONLY,   CTI_TRIG_GET_TSTAMP, _smCtGetTmStmp ),
		SM_ROW( CTI_STATE_DDR_ONLY,   CTI_TRIG_LAST,       _smCtUndef ),
	},

	{
		SM_ROW( CTI_STATE_SRAM_ONLY,  CTI_TRIG_NULL,       _smCtUndef ),
		SM_ROW( CTI_STATE_SRAM_ONLY,  CTI_TRIG_ADD_TABLE,  _smCtAddSramTbl ),
		SM_ROW( CTI_STATE_SRAM_ONLY,  CTI_TRIG_DEL_TABLE,  _smCtDelTbl ),
		SM_ROW( CTI_STATE_SRAM_ONLY,  CTI_TRIG_CLR_TABLE,  _smCtClrTbl ),
		SM_ROW( CTI_STATE_SRAM_ONLY,  CTI_TRIG_WLK_TABLE,  _smCtWalkTbl ),
		SM_ROW( CTI_STATE_SRAM_ONLY,  CTI_TRIG_TBL_STATS,  _smCtStatTbl ),
		SM_ROW( CTI_STATE_SRAM_ONLY,  CTI_TRIG_ADD_RULE,   _smCtAddRuleToTbl ),
		SM_ROW( CTI_STATE_SRAM_ONLY,  CTI_TRIG_DEL_RULE,   _smCtDelRuleFromTbl ),
		SM_ROW( CTI_STATE_SRAM_ONLY,  CTI_TRIG_TBL_SWITCH, _smCtUndef ),
		SM_ROW( CTI_STATE_SRAM_ONLY,  CTI_TRIG_GOTO_DDR,   _smCtUndef ),
		SM_ROW( CTI_STATE_SRAM_ONLY,  CTI_TRIG_GOTO_SRAM,  _smCtUndef ),
		SM_ROW( CTI_STATE_SRAM_ONLY,  CTI_TRIG_GET_TSTAMP, _smCtGetTmStmp ),
		SM_ROW( CTI_STATE_SRAM_ONLY,  CTI_TRIG_LAST,       _smCtUndef ),
	},

	{
		SM_ROW( CTI_STATE_HYBRID,     CTI_TRIG_NULL,       _smCtUndef ),
		SM_ROW( CTI_STATE_HYBRID,     CTI_TRIG_ADD_TABLE,  _smCtAddSramAndDdrTbl ),
		SM_ROW( CTI_STATE_HYBRID,     CTI_TRIG_DEL_TABLE,  _smCtDelSramAndDdrTbl ),
		SM_ROW( CTI_STATE_HYBRID,     CTI_TRIG_CLR_TABLE,  _smCtClrTblHybrid ),
		SM_ROW( CTI_STATE_HYBRID,     CTI_TRIG_WLK_TABLE,  _smCtWalkTblHybrid ),
		SM_ROW( CTI_STATE_HYBRID,     CTI_TRIG_TBL_STATS,  _smCtStatTblHybrid ),
		SM_ROW( CTI_STATE_HYBRID,     CTI_TRIG_ADD_RULE,   _smCtAddRuleHybrid ),
		SM_ROW( CTI_STATE_HYBRID,     CTI_TRIG_DEL_RULE,   _smCtDelRuleHybrid ),
		SM_ROW( CTI_STATE_HYBRID,     CTI_TRIG_TBL_SWITCH, _smCtSwitchFromSramToDdr ),
		SM_ROW( CTI_STATE_HYBRID,     CTI_TRIG_GOTO_DDR,   _smCtGoToDdr ),
		SM_ROW( CTI_STATE_HYBRID,     CTI_TRIG_GOTO_SRAM,  _smCtGoToSram ),
		SM_ROW( CTI_STATE_HYBRID,     CTI_TRIG_GET_TSTAMP, _smCtGetTmStmpHybrid ),
		SM_ROW( CTI_STATE_HYBRID,     CTI_TRIG_LAST,       _smCtUndef ),
	},

	{
		SM_ROW( CTI_STATE_HYBRID_DDR, CTI_TRIG_NULL,       _smCtUndef ),
		SM_ROW( CTI_STATE_HYBRID_DDR, CTI_TRIG_ADD_TABLE,  _smCtUndef ),
		SM_ROW( CTI_STATE_HYBRID_DDR, CTI_TRIG_DEL_TABLE,  _smCtDelSramAndDdrTbl ),
		SM_ROW( CTI_STATE_HYBRID_DDR, CTI_TRIG_CLR_TABLE,  _smCtClrTblHybrid ),
		SM_ROW( CTI_STATE_HYBRID_DDR, CTI_TRIG_WLK_TABLE,  _smCtWalkTblHybrid ),
		SM_ROW( CTI_STATE_HYBRID_DDR, CTI_TRIG_TBL_STATS,  _smCtStatTblHybrid ),
		SM_ROW( CTI_STATE_HYBRID_DDR, CTI_TRIG_ADD_RULE,   _smCtAddRuleHybrid ),
		SM_ROW( CTI_STATE_HYBRID_DDR, CTI_TRIG_DEL_RULE,   _smCtDelRuleHybrid ),
		SM_ROW( CTI_STATE_HYBRID_DDR, CTI_TRIG_TBL_SWITCH, _smCtSwitchFromDdrToSram ),
		SM_ROW( CTI_STATE_HYBRID_DDR, CTI_TRIG_GOTO_DDR,   _smCtGoToDdr ),
		SM_ROW( CTI_STATE_HYBRID_DDR, CTI_TRIG_GOTO_SRAM,  _smCtGoToSram ),
		SM_ROW( CTI_STATE_HYBRID_DDR, CTI_TRIG_GET_TSTAMP, _smCtGetTmStmpHybrid ),
		SM_ROW( CTI_STATE_HYBRID_DDR, CTI_TRIG_LAST,       _smCtUndef ),
	},

	{
		SM_ROW( CTI_STATE_LAST,       CTI_TRIG_NULL,       _smCtUndef ),
		SM_ROW( CTI_STATE_LAST,       CTI_TRIG_ADD_TABLE,  _smCtUndef ),
		SM_ROW( CTI_STATE_LAST,       CTI_TRIG_DEL_TABLE,  _smCtUndef ),
		SM_ROW( CTI_STATE_LAST,       CTI_TRIG_CLR_TABLE,  _smCtUndef ),
		SM_ROW( CTI_STATE_LAST,       CTI_TRIG_WLK_TABLE,  _smCtUndef ),
		SM_ROW( CTI_STATE_LAST,       CTI_TRIG_TBL_STATS,  _smCtUndef ),
		SM_ROW( CTI_STATE_LAST,       CTI_TRIG_ADD_RULE,   _smCtUndef ),
		SM_ROW( CTI_STATE_LAST,       CTI_TRIG_DEL_RULE,   _smCtUndef ),
		SM_ROW( CTI_STATE_LAST,       CTI_TRIG_TBL_SWITCH, _smCtUndef ),
		SM_ROW( CTI_STATE_LAST,       CTI_TRIG_GOTO_DDR,   _smCtUndef ),
		SM_ROW( CTI_STATE_LAST,       CTI_TRIG_GOTO_SRAM,  _smCtUndef ),
		SM_ROW( CTI_STATE_LAST,       CTI_TRIG_GET_TSTAMP, _smCtUndef ),
		SM_ROW( CTI_STATE_LAST,       CTI_TRIG_LAST,       _smCtUndef ),
	},
};

/******************************************************************************/
/*
 * FUNCTION: _smCtUndef
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Whatever you like
 *
 * DESCRIPTION:
 *
 *   The following does nothing, except report an undefined action for
 *   a particular state/trigger combo...
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
static int _smCtUndef(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	IPAERR("CB(%s): undefined action for STATE(%s) with TRIGGER(%s)\n",
		   _ct_state_mach_tbl[cti_obj_ptr->curr_state][trigger].sm_cb_as_str,
		   _ct_state_mach_tbl[cti_obj_ptr->curr_state][trigger].state_as_str,
		   _ct_state_mach_tbl[cti_obj_ptr->curr_state][trigger].trigger_as_str);

	return -1;
}

/******************************************************************************/
/*
 * FUNCTION: ipa_cti_statemach
 *
 * PARAMS:
 *
 *   cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   trigger      (IN) The trigger to run through the state machine
 *
 *   arb_data_ptr (IN) Anything you like.  Will be passed, untouched,
 *                     to the state/trigger callback function.
 *
 * DESCRIPTION:
 *
 *   This function allows a cti object and a trigger to be run
 *   through the state machine.
 *
 * RETURNS:
 *
 *   zero on success, otherwise non-zero
 */
int ipa_cti_statemach(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr )
{
	const char* ss_ptr  = _ct_state_mach_tbl[cti_obj_ptr->curr_state][trigger].state_as_str;
	const char* ts_ptr  = _ct_state_mach_tbl[cti_obj_ptr->curr_state][trigger].trigger_as_str;
	const char* cbs_ptr = _ct_state_mach_tbl[cti_obj_ptr->curr_state][trigger].sm_cb_as_str;

	bool vote = false;

	int ret, ret_mtx;

	IPADBG("In\n");

	ret = ct_take_mutex();

	if ( ret != 0 )
	{
		goto bail;
	}

	IPADBG("STATE(%s) TRIGGER(%s) CB(%s)\n", ss_ptr, ts_ptr, cbs_ptr);

	vote = CT_VOTE_REQUIRED(trigger);

	if ( vote )
	{
		IPADBG("Voting clock on STATE(%s) TRIGGER(%s)\n",
			   ss_ptr, ts_ptr);

		if ( ipa_ct_vote_clock(IPA_APP_CLK_VOTE) != 0 )
		{
			IPAERR("Voting failed STATE(%s) TRIGGER(%s)\n", ss_ptr, ts_ptr);
			ret = -EINVAL;
			goto unlock;
		}
	}

	ret = _ct_state_mach_tbl[cti_obj_ptr->curr_state][trigger].sm_cb(
		cti_obj_ptr, trigger, arb_data_ptr);

	if ( vote )
	{
		IPADBG("Voting clock off STATE(%s) TRIGGER(%s)\n",
			   ss_ptr, ts_ptr);

		if ( ipa_ct_vote_clock(IPA_APP_CLK_DEVOTE) != 0 )
		{
			IPAERR("Voting failed STATE(%s) TRIGGER(%s)\n", ss_ptr, ts_ptr);
		}
	}

unlock:
	ret_mtx = ct_give_mutex();
	ret = (ret) ? ret : ret_mtx;

bail:
	IPADBG("Out\n");

	return ret;
}

bool ipa_ct_is_sram_supported(void)
{
	return CT_VALID_TBL_HDL(cti_obj.sram_tbl_hdl);
}
