/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#if !defined(_IPA_CT_STATEMACH_H_)
# define _IPA_CT_STATEMACH_H_

typedef uintptr_t arb_t;

/*
 * Function for taking/locking the mutex...
 */
static int ct_take_mutex(void);

/*
 * Function for giving/unlocking the mutex...
 */
static int ct_give_mutex(void);

#define MAKE_AS_STR_CASE(v) case v: return #v

/******************************************************************************/
/**
 * The following enum represents the states that a cti object can be
 * in.
 */
typedef enum {
	CTI_STATE_NULL       = 0,
	CTI_STATE_DDR_ONLY   = 1, /* CT in DDR only (traditional) */
	CTI_STATE_SRAM_ONLY  = 2, /* CT in SRAM only (new) */
	CTI_STATE_HYBRID     = 3, /* CT simultaneously in both SRAM/DDR */
	CTI_STATE_HYBRID_DDR = 4, /* CT transitioned from SRAM to DDR */

	CTI_STATE_LAST
} ipa_cti_state;

/* KEEP THE FOLLOWING IN SYNC WITH ABOVE. */
static inline const char* ipa_cti_state_as_str(
	ipa_cti_state s )
{
	switch ( s )
	{
		MAKE_AS_STR_CASE(CTI_STATE_NULL);
		MAKE_AS_STR_CASE(CTI_STATE_DDR_ONLY);
		MAKE_AS_STR_CASE(CTI_STATE_SRAM_ONLY);
		MAKE_AS_STR_CASE(CTI_STATE_HYBRID);
		MAKE_AS_STR_CASE(CTI_STATE_HYBRID_DDR);
		MAKE_AS_STR_CASE(CTI_STATE_LAST);

	default:
		break;
	}

	return "???";
}

# undef strcasesame
# define strcasesame(a, b) (!strcasecmp(a, b))

static inline ipa_cti_state mem_type_str_to_ipa_cti_state(
	const char* str )
{
	if ( str ) {
		if (strcasesame(str, "HYBRID" ))
			return CTI_STATE_HYBRID;
		if (strcasesame(str, "SRAM" ))
			return CTI_STATE_SRAM_ONLY;
	}
	return CTI_STATE_DDR_ONLY;
}

/******************************************************************************/
/**
 * The following enum represents the API triggers that may or may not
 * cause a cti object to transition through its various allowable
 * states defined in ipa_nati_state above.
 */
typedef enum {
	CTI_TRIG_NULL       =  0,
	CTI_TRIG_ADD_TABLE  =  1,
	CTI_TRIG_DEL_TABLE  =  2,
	CTI_TRIG_CLR_TABLE  =  3,
	CTI_TRIG_WLK_TABLE  =  4,
	CTI_TRIG_TBL_STATS  =  5,
	CTI_TRIG_ADD_RULE   =  6,
	CTI_TRIG_DEL_RULE   =  7,
	CTI_TRIG_TBL_SWITCH =  8,
	CTI_TRIG_GOTO_DDR   =  9,
	CTI_TRIG_GOTO_SRAM  = 10,
	CTI_TRIG_GET_TSTAMP = 11,

	CTI_TRIG_LAST
} ipa_cti_trigger;

/******************************************************************************/
/**
 * The following structure used to keep switch stats.
 */
typedef struct
{
	uint32_t pass;
	uint32_t fail;
} cti_switch_stats;

/******************************************************************************/
/**
 * The following structure used to direct map usage.
 *
 * Maps are needed to map rule handles..orig to new and new to orig.
 * See comments in ipa_ct_statemach.c on this topic...
 */
typedef struct
{
	uint32_t orig2new_map;
	uint32_t new2orig_map;
}cti_map_pair;

/******************************************************************************/
/**
 * The following is a cti object that will maintain state relative to
 * various API calls.
 */
typedef struct
{
	ipa_cti_state prev_state;
	ipa_cti_state curr_state;
	int           hold_state;
	ipa_cti_state state_to_hold;
	uint32_t       ddr_tbl_hdl;
	uint32_t       sram_tbl_hdl;
	uint32_t       tot_slots_in_sram;
	uint32_t       back_to_sram_thresh;
	/*
	 * tot_rules_in_table[0] for ddr, and
	 * tot_rules_in_table[1] for sram
	 */
	uint32_t       tot_rules_in_table[2];
	/*
	 * map_pairs[0] for ddr, and
	 * map_pairs[1] for sram
	 */
	cti_map_pair  map_pairs[2];
	/*
	 * sw_stats[0] for ddr, and
	 * sw_stats[1] for sram
	 */
	cti_switch_stats sw_stats[2];
} ipa_cti_obj;

/*
 * For use with the arrays above..in ipa_cti_obj...
 */
#undef DDR_SUB
#undef SRAM_SUB

#define DDR_SUB  0
#define SRAM_SUB 1

#undef CT_BACK2_UNSTARTED_STATE
#define CT_BACK2_UNSTARTED_STATE() \
	cti_obj.prev_state = cti_obj.curr_state = CTI_STATE_NULL;

#undef CT_IN_UNSTARTED_STATE
#define CT_IN_UNSTARTED_STATE() \
	( cti_obj.prev_state == CTI_STATE_NULL )

#undef CT_IN_HYBRID_STATE
#define CT_IN_HYBRID_STATE() \
	( cti_obj.curr_state == CTI_STATE_HYBRID || \
	  cti_obj.curr_state == CTI_STATE_HYBRID_DDR )

#undef CT_COMPATIBLE_NMI_4SWITCH
#define CT_COMPATIBLE_NMI_4SWITCH(n) \
	( (n) == IPA_NAT_MEM_IN_SRAM && cti_obj.curr_state == CTI_STATE_HYBRID_DDR ) || \
	( (n) == IPA_NAT_MEM_IN_DDR  && cti_obj.curr_state == CTI_STATE_HYBRID ) || \
	( (n) == IPA_NAT_MEM_IN_DDR  && cti_obj.curr_state == CTI_STATE_DDR_ONLY ) || \
	( (n) == IPA_NAT_MEM_IN_SRAM && cti_obj.curr_state == CTI_STATE_SRAM_ONLY )

#undef CT_GEN_HOLD_STATE
#define CT_GEN_HOLD_STATE() \
	( ! CT_IN_HYBRID_STATE() ) ? cti_obj.curr_state : \
	(cti_obj.curr_state == CTI_STATE_HYBRID) ? CTI_STATE_SRAM_ONLY : \
	CTI_STATE_DDR_ONLY

#undef  CT_SRAM_CURRENTLY_ACTIVE
#define CT_SRAM_CURRENTLY_ACTIVE() \
	( cti_obj.curr_state == CTI_STATE_SRAM_ONLY || \
	  cti_obj.curr_state == CTI_STATE_HYBRID )

#define CT_SRAM_TO_BE_ACCESSED(t) \
	( CT_SRAM_CURRENTLY_ACTIVE() || \
	  (t) == CTI_TRIG_GOTO_SRAM || \
	  (t) == CTI_TRIG_TBL_SWITCH )

/*
 * NOTE: The exclusion of timestamp retrieval and table creation
 *       below.
 *
 * Why?
 *
 *  In re timestamp:
 *
 *   Because timestamp retrieval institutes too many repetitive
 *   accesses, hence would lead to too many successive votes. Instead,
 *   it will be handled differently and in the app layer above.
 *
 *  In re table creation:
 *
 *    Because it can't be known, apriori, whether or not sram is
 *    really available for use. Instead, we'll move table creation
 *    voting to a place where we know sram is available.
 */
#undef  CT_VOTE_REQUIRED
#define CT_VOTE_REQUIRED(t) \
	( CT_SRAM_TO_BE_ACCESSED(t) && \
	  (t) != CTI_TRIG_GET_TSTAMP && \
	  (t) != CTI_TRIG_ADD_TABLE )

/******************************************************************************/
/**
 * A helper macro for changing a cti object's state...
 */
# undef SET_CTIOBJ_STATE
# define SET_CTIOBJ_STATE(x, s)  {        \
		(x)->prev_state = (x)->curr_state; \
		(x)->curr_state = s;               \
	}

/******************************************************************************/
/**
 * A function signature for a state/trigger callback function...
 */
typedef int (*cti_statemach_cb)(
	ipa_cti_obj*    cti_obj_ptr,
	ipa_cti_trigger trigger,
	arb_t*           arb_data_ptr );

/******************************************************************************/
/**
 * A structure for relating state to trigger callbacks.
 */
typedef struct
{
	ipa_cti_state    state;
	ipa_cti_trigger  trigger;
	cti_statemach_cb sm_cb;
	const char*       state_as_str;
	const char*       trigger_as_str;
	const char*       sm_cb_as_str;
} cti_statemach_tuple;

#undef SM_ROW
#define SM_ROW(s, t, f) \
	{ s, t, f, #s, #t, #f }

/******************************************************************************/
/**
 * FUNCTION: ipa_cti_statemach
 *
 * PARAMS:
 *
 *   @cti_obj_ptr (IN) A pointer to an initialized cti object
 *
 *   @trigger      (IN) The trigger to run through the state machine
 *
 *   @arb_data_ptr (IN) Anything you like.  Will be passed, untouched,
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
	arb_t*           arb_data_ptr );

#endif /* #if !defined(_IPA_CT_STATEMACH_H_) */
