/*
Copyright (c) 2013-2019, The Linux Foundation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
		* Redistributions of source code must retain the above copyright
			notice, this list of conditions and the following disclaimer.
		* Redistributions in binary form must reproduce the above
			copyright notice, this list of conditions and the following
			disclaimer in the documentation and/or other materials provided
			with the distribution.
		* Neither the name of The Linux Foundation nor the names of its
			contributors may be used to endorse or promote products derived
			from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*!
	@file
	IPACM_Filtering.cpp

	@brief
	This file implements the IPACM filtering functionality.

	@Author
	Skylar Chang

*/
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include "IPACM_Filtering.h"
#include <IPACM_Log.h>
#include "IPACM_Defs.h"


const char *IPACM_Filtering::DEVICE_NAME = "/dev/ipa";

IPACM_Filtering::IPACM_Filtering()
{
	fd = open(DEVICE_NAME, O_RDWR);
	if (fd < 0)
	{
		IPACMERR("Failed opening %s.\n", DEVICE_NAME);
	}
}

IPACM_Filtering::~IPACM_Filtering()
{
	close(fd);
}

bool IPACM_Filtering::DeviceNodeIsOpened()
{
	return fd;
}

bool IPACM_Filtering::combine_flt_attribute(ipa_flt_rule_add *replicate_rule,
		ipa_flt_rule_add *q6_rule)
{
	unsigned int index = 0, q_index = 0, r_index = 0;
	int fd = 0;
	struct ipa_ioc_generate_flt_eq flt_eq;
	fd = open(IPA_DEVICE_NAME, O_RDWR);

	if (0 == fd)
	{
		IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
		return false;
	}

	memset(&flt_eq, 0, sizeof(flt_eq));
	memcpy(&flt_eq.attrib, &replicate_rule->rule.attrib, sizeof(flt_eq.attrib));
	flt_eq.ip = IPA_IP_v6;

	if(0 != ioctl(fd, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
	{
		IPACMERR("Failed to get eq_attrib\n");
		goto fail;
	}

	memcpy(&replicate_rule->rule.eq_attrib,
			&flt_eq.eq_attrib,
			sizeof(replicate_rule->rule.eq_attrib));

	if (q6_rule->rule.eq_attrib.tos_eq_present == 1)
	{
		replicate_rule->rule.eq_attrib.tos_eq_present = 1;
		replicate_rule->rule.eq_attrib.tos_eq =
			q6_rule->rule.eq_attrib.tos_eq;
	}

	if (q6_rule->rule.eq_attrib.protocol_eq_present == 1)
	{
		replicate_rule->rule.eq_attrib.protocol_eq_present = 1;
		replicate_rule->rule.eq_attrib.protocol_eq =
			q6_rule->rule.eq_attrib.protocol_eq;
	}

	r_index = replicate_rule->rule.eq_attrib.num_ihl_offset_range_16;
	q_index = q6_rule->rule.eq_attrib.num_ihl_offset_range_16;
	if ((r_index + q_index) > IPA_IPFLTR_NUM_IHL_RANGE_16_EQNS)
	{
		IPACMDBG_H ("num_ihl_offset_range_16  Max %d passed value %d + %d\n",
				IPA_IPFLTR_NUM_IHL_RANGE_16_EQNS,
				q_index, r_index);
		goto fail;
	}
	for (index = 0; index < q_index; index++)
	{
		replicate_rule->rule.eq_attrib.ihl_offset_range_16[r_index].offset =
			q6_rule->rule.eq_attrib.ihl_offset_range_16[index].offset;
		replicate_rule->rule.eq_attrib.ihl_offset_range_16[r_index].range_low =
			q6_rule->rule.eq_attrib.ihl_offset_range_16[index].range_low;
		replicate_rule->rule.eq_attrib.ihl_offset_range_16[r_index].range_high =
			q6_rule->rule.eq_attrib.ihl_offset_range_16[index].range_high;
		replicate_rule->rule.eq_attrib.num_ihl_offset_range_16++;
	}

	r_index = replicate_rule->rule.eq_attrib.num_offset_meq_32;
	q_index = q6_rule->rule.eq_attrib.num_offset_meq_32;
	if ((r_index + q_index) > IPA_IPFLTR_NUM_MEQ_32_EQNS)
	{
		IPACMDBG_H ("num_offset_meq_32	Max %d passed value %d + %d\n",
				IPA_IPFLTR_NUM_MEQ_32_EQNS,
				q_index, r_index);
		goto fail;
	}
	for (index = 0; index < q_index; index++)
	{
		replicate_rule->rule.eq_attrib.offset_meq_32[r_index].offset =
			q6_rule->rule.eq_attrib.offset_meq_32[index].offset;
		replicate_rule->rule.eq_attrib.offset_meq_32[r_index].mask =
			q6_rule->rule.eq_attrib.offset_meq_32[index].mask;
		replicate_rule->rule.eq_attrib.offset_meq_32[r_index].value =
			q6_rule->rule.eq_attrib.offset_meq_32[index].value;
		replicate_rule->rule.eq_attrib.num_offset_meq_32++;
	}

	if (q6_rule->rule.eq_attrib.tc_eq_present == 1)
	{
		replicate_rule->rule.eq_attrib.tc_eq_present = 1;
		replicate_rule->rule.eq_attrib.tc_eq =
			q6_rule->rule.eq_attrib.tc_eq;
	}

	if (q6_rule->rule.eq_attrib.fl_eq_present == 1)
	{
		replicate_rule->rule.eq_attrib.fl_eq_present = 1;
		replicate_rule->rule.eq_attrib.fl_eq =
			q6_rule->rule.eq_attrib.fl_eq;
	}

	if (q6_rule->rule.eq_attrib.ihl_offset_eq_16_present == 1)
	{
		replicate_rule->rule.eq_attrib.ihl_offset_eq_16_present =
			q6_rule->rule.eq_attrib.ihl_offset_eq_16_present;
		replicate_rule->rule.eq_attrib.ihl_offset_eq_16.offset =
			q6_rule->rule.eq_attrib.ihl_offset_eq_16.offset;
		replicate_rule->rule.eq_attrib.ihl_offset_eq_16.offset =
			q6_rule->rule.eq_attrib.ihl_offset_eq_16.value;
	}

	if (q6_rule->rule.eq_attrib.ihl_offset_eq_32_present == 1)
	{
		replicate_rule->rule.eq_attrib.ihl_offset_eq_32_present =
			q6_rule->rule.eq_attrib.ihl_offset_eq_32_present;
		replicate_rule->rule.eq_attrib.ihl_offset_eq_32.offset =
			q6_rule->rule.eq_attrib.ihl_offset_eq_32.offset;
		replicate_rule->rule.eq_attrib.ihl_offset_eq_32.value =
			q6_rule->rule.eq_attrib.ihl_offset_eq_32.value;
	}


	r_index = replicate_rule->rule.eq_attrib.num_ihl_offset_meq_32;
	q_index = q6_rule->rule.eq_attrib.num_ihl_offset_meq_32;
	if ((r_index + q_index) > IPA_IPFLTR_NUM_IHL_MEQ_32_EQNS)
	{
		IPACMDBG_H ("num_ihl_offset_meq_32	Max %d passed value %d + %d\n",
				IPA_IPFLTR_NUM_IHL_MEQ_32_EQNS,
				q_index, r_index);
		goto fail;
	}
	for (index = 0; index < q_index; index++)
	{
		replicate_rule->rule.eq_attrib.ihl_offset_meq_32[r_index].offset =
			q6_rule->rule.eq_attrib.ihl_offset_meq_32[index].offset;
		replicate_rule->rule.eq_attrib.ihl_offset_meq_32[r_index].mask =
			q6_rule->rule.eq_attrib.ihl_offset_meq_32[index].mask;
		replicate_rule->rule.eq_attrib.ihl_offset_meq_32[r_index].value =
			q6_rule->rule.eq_attrib.ihl_offset_meq_32[index].value;

		replicate_rule->rule.eq_attrib.num_ihl_offset_meq_32++;
	}

	r_index = replicate_rule->rule.eq_attrib.num_offset_meq_128;
	q_index = q6_rule->rule.eq_attrib.num_offset_meq_128;
	if ((r_index + q_index) > IPA_IPFLTR_NUM_MEQ_128_EQNS)
	{
		IPACMDBG_H ("num_offset_meq_128  Max %d passed value %d + %d\n",
				IPA_IPFLTR_NUM_MEQ_128_EQNS,
				q_index, r_index);
		goto fail;
	}
	for (index = 0; index < q_index; index++)
	{

		replicate_rule->rule.eq_attrib.offset_meq_128[r_index].offset =
			q6_rule->rule.eq_attrib.offset_meq_128[index].offset;


		memcpy(&replicate_rule->rule.eq_attrib.offset_meq_128[r_index].mask,
				&q6_rule->rule.eq_attrib.offset_meq_128[index].mask,
				sizeof(uint8_t) * 16);

		memcpy(&replicate_rule->rule.eq_attrib.offset_meq_128[r_index].value,
				&q6_rule->rule.eq_attrib.offset_meq_128[index].value,
				sizeof(uint8_t) * 16);

		replicate_rule->rule.eq_attrib.num_offset_meq_128++;
	}

	if (q6_rule->rule.eq_attrib.metadata_meq32_present == 1)
	{
		replicate_rule->rule.eq_attrib.metadata_meq32_present =
			q6_rule->rule.eq_attrib.metadata_meq32_present;
		replicate_rule->rule.eq_attrib.metadata_meq32.offset =
			q6_rule->rule.eq_attrib.metadata_meq32.offset;
		replicate_rule->rule.eq_attrib.metadata_meq32.mask =
			q6_rule->rule.eq_attrib.metadata_meq32.mask;
		replicate_rule->rule.eq_attrib.metadata_meq32.value =
			q6_rule->rule.eq_attrib.metadata_meq32.value;
	}
	replicate_rule->rule.eq_attrib.rule_eq_bitmap |=
		q6_rule->rule.eq_attrib.rule_eq_bitmap;

	close(fd);
	return true;

fail:
	close(fd);
	return false;
}

#if defined(FEATURE_IPACM_PER_CLIENT_STATS)
bool IPACM_Filtering::AddFilteringRule_v2(struct ipa_ioc_add_flt_rule_v2 const *ruleTable)
{
	int retval = 0;
	int i;
	int num_rules = ruleTable->num_rules;
	int cnt;

	IPACMDBG_H("Printing filter add attributes\n");
	IPACMDBG_H("ip type: %d\n", ruleTable->ip);
	IPACMDBG_H("Number of rules: %d\n", ruleTable->num_rules);
	IPACMDBG_H("End point: %d and global value: %d\n", ruleTable->ep, ruleTable->global);
	IPACMDBG_H("commit value: %d\n", ruleTable->commit);
	for (int cnt=0; cnt<ruleTable->num_rules; cnt++)
	{
		IPACMDBG("Filter rule:%d attrib mask: 0x%x\n", cnt,
				((struct ipa_flt_rule_add_v2  *)ruleTable->rules)[cnt].rule.attrib.attrib_mask);
	}

	retval = ioctl(fd, IPA_IOC_ADD_FLT_RULE_V2, ruleTable);
	if (retval != 0)
	{
		for (cnt = 0; cnt < ruleTable->num_rules; cnt++)
		{
			if (((struct ipa_flt_rule_add_v2  *)ruleTable->rules)[cnt].status != 0)
			{
				IPACMDBG_H("Adding Filter rule:%d failed with status:%d\n",
								 cnt, ((struct ipa_flt_rule_add_v2 *)ruleTable->rules)[cnt].status);
			}
		}
		return false;
	}

	for (cnt = 0; cnt<ruleTable->num_rules; cnt++)
	{
		if (((struct ipa_flt_rule_add_v2  *)ruleTable->rules)[cnt].status != 0)
		{
			IPACMERR("Adding Filter rule:%d failed with status:%d\n",
							 cnt, ((struct ipa_flt_rule_add_v2 *)ruleTable->rules)[cnt].status);
		}
	}
	IPACMDBG("Added Filtering rule %p\n", ruleTable);
	return true;
}
#endif //IPA_HW_FNR_STATS

bool IPACM_Filtering::AddFilteringRule(struct ipa_ioc_add_flt_rule const *ruleTable)
{
	int retval = 0;

	IPACMDBG("Printing filter add attributes\n");
	IPACMDBG("ip type: %d\n", ruleTable->ip);
	IPACMDBG("Number of rules: %d\n", ruleTable->num_rules);
	IPACMDBG("End point: %d and global value: %d\n", ruleTable->ep, ruleTable->global);
	IPACMDBG("commit value: %d\n", ruleTable->commit);
	for (int cnt=0; cnt<ruleTable->num_rules; cnt++)
	{
		if (ruleTable->rules[cnt].rule.eq_attrib_type)
		{
			IPACMDBG_H("Filter rule : %d eq attrib mask : 0x%x\n",
				cnt, ruleTable->rules[cnt].rule.eq_attrib.rule_eq_bitmap);
		}
		else
		{
			IPACMDBG("Filter rule:%d attrib mask: 0x%x\n", cnt,
				ruleTable->rules[cnt].rule.attrib.attrib_mask);
		}
	}

	retval = ioctl(fd, IPA_IOC_ADD_FLT_RULE, ruleTable);
	if (retval != 0)
	{
		IPACMERR("Failed adding Filtering rule %p\n", ruleTable);
		PERROR("unable to add filter rule:");

		for (int cnt = 0; cnt < ruleTable->num_rules; cnt++)
		{
			if (ruleTable->rules[cnt].status != 0)
			{
				IPACMERR("Adding Filter rule:%d failed with status:%d\n",
								 cnt, ruleTable->rules[cnt].status);
			}
		}
		return false;
	}

	for (int cnt = 0; cnt<ruleTable->num_rules; cnt++)
	{
		if(ruleTable->rules[cnt].status != 0)
		{
			IPACMERR("Adding Filter rule:%d failed with status:%d\n",
							 cnt, ruleTable->rules[cnt].status);
		}
	}

	IPACMDBG("Added Filtering rule %p\n", ruleTable);
	return true;
}

bool IPACM_Filtering::AddFilteringRuleAfter(struct ipa_ioc_add_flt_rule_after const *ruleTable)
{
#ifdef FEATURE_IPA_V3
	int retval = 0;

	IPACMDBG("Printing filter add attributes\n");
	IPACMDBG("ip type: %d\n", ruleTable->ip);
	IPACMDBG("Number of rules: %d\n", ruleTable->num_rules);
	IPACMDBG("End point: %d\n", ruleTable->ep);
	IPACMDBG("commit value: %d\n", ruleTable->commit);

	retval = ioctl(fd, IPA_IOC_ADD_FLT_RULE_AFTER, ruleTable);

	for (int cnt = 0; cnt<ruleTable->num_rules; cnt++)
	{
		if(ruleTable->rules[cnt].status != 0)
		{
			IPACMERR("Adding Filter rule:%d failed with status:%d\n",
							 cnt, ruleTable->rules[cnt].status);
		}
	}

	if (retval != 0)
	{
		IPACMERR("Failed adding Filtering rule %p\n", ruleTable);
		return false;
	}
	IPACMDBG("Added Filtering rule %p\n", ruleTable);
#endif
	return true;
}

bool IPACM_Filtering::DeleteFilteringRule(struct ipa_ioc_del_flt_rule *ruleTable)
{
	int retval = 0;

	retval = ioctl(fd, IPA_IOC_DEL_FLT_RULE, ruleTable);
	if (retval != 0)
	{
		IPACMERR("Failed deleting Filtering rule %p\n", ruleTable);
		return false;
	}

	IPACMDBG("Deleted Filtering rule %p\n", ruleTable);
	return true;
}

bool IPACM_Filtering::Commit(enum ipa_ip_type ip)
{
	int retval = 0;

	retval = ioctl(fd, IPA_IOC_COMMIT_FLT, ip);
	if (retval != 0)
	{
		IPACMERR("failed committing Filtering rules.\n");
		return false;
	}

	IPACMDBG("Committed Filtering rules to IPA HW.\n");
	return true;
}

bool IPACM_Filtering::Reset(enum ipa_ip_type ip)
{
	int retval = 0;

	retval = ioctl(fd, IPA_IOC_RESET_FLT, ip);
	retval |= ioctl(fd, IPA_IOC_COMMIT_FLT, ip);
	if (retval)
	{
		IPACMERR("failed resetting Filtering block.\n");
		return false;
	}

	IPACMDBG("Reset command issued to IPA Filtering block.\n");
	return true;
}

bool IPACM_Filtering::DeleteFilteringHdls
(
	 uint32_t *flt_rule_hdls,
	 ipa_ip_type ip,
	 uint8_t num_rules
)
{
	struct ipa_ioc_del_flt_rule *flt_rule;
	bool res = true;
	int len = 0, cnt = 0;
        const uint8_t UNIT_RULES = 1;

	len = (sizeof(struct ipa_ioc_del_flt_rule)) + (UNIT_RULES * sizeof(struct ipa_flt_rule_del));
	flt_rule = (struct ipa_ioc_del_flt_rule *)malloc(len);
	if (flt_rule == NULL)
	{
		IPACMERR("unable to allocate memory for del filter rule\n");
		return false;
	}

	for (cnt = 0; cnt < num_rules; cnt++)
	{
	    memset(flt_rule, 0, len);
	    flt_rule->commit = 1;
	    flt_rule->num_hdls = UNIT_RULES;
	    flt_rule->ip = ip;

	    if (flt_rule_hdls[cnt] == 0)
	    {
		   IPACMERR("invalid filter handle passed, ignoring it: %d\n", cnt)
	    }
            else
	    {

		   flt_rule->hdl[0].status = -1;
		   flt_rule->hdl[0].hdl = flt_rule_hdls[cnt];
		   IPACMDBG("Deleting filter hdl:(0x%x) with ip type: %d\n", flt_rule_hdls[cnt], ip);

	           if (DeleteFilteringRule(flt_rule) == false)
	           {
		        PERROR("Filter rule deletion failed!\n");
		        res = false;
		        goto fail;
	           }
		   else
	           {

		        if (flt_rule->hdl[0].status != 0)
		        {
			     IPACMERR("Filter rule hdl 0x%x deletion failed with error:%d\n",
		        					 flt_rule->hdl[0].hdl, flt_rule->hdl[0].status);
			     res = false;
			     goto fail;
		        }
		   }
	    }
	}

fail:
	free(flt_rule);

	return res;
}

#ifdef FEATURE_IPACM_UL_FIREWALL
bool IPACM_Filtering::AddWanULFilteringRule(struct ipa_ioc_add_flt_rule const * rule_table_v6, uint8_t mux_id, bool is_enable)
{
	int ret = 0, cnt, num_rules = 0, pos = 0;

	ipa_configure_ul_firewall_rules_req_msg_v01 qmi_rule_msg;

	int fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
	if(fd_wwan_ioctl < 0)
	{
		IPACMERR("Failed to open %s.\n",WWAN_QMI_IOCTL_DEVICE_NAME);
		return false;
	}

	/* Used in v6 case only*/
	if(rule_table_v6 != NULL)
	{
		num_rules += rule_table_v6->num_rules;
		IPACMDBG_H("Get %d WAN UL IPv6 filtering rules.\n", rule_table_v6->num_rules);
	}
	else
	{
		IPACMERR("Invalid filter table addr\n");
		close(fd_wwan_ioctl);
		return false;
	}

	if(num_rules > QMI_IPA_MAX_UL_FIREWALL_RULES_V01)
	{
		IPACMERR("The number of ul filtering rules exceed limit.\n");
		close(fd_wwan_ioctl);
		return false;
	}
	else
	{
		memset(&qmi_rule_msg, 0, sizeof(qmi_rule_msg));
		qmi_rule_msg.firewall_rules_list_len = num_rules;
		IPACMDBG_H("Get %d WAN UL filtering rules in total.\n", num_rules);

		if(rule_table_v6 != NULL)
		{
			for(cnt = rule_table_v6->num_rules - 1; cnt >= 0; cnt--)
			{
				if (pos < QMI_IPA_MAX_UL_FIREWALL_RULES_V01)
				{
					qmi_rule_msg.firewall_rules_list[pos].ip_type = QMI_IPA_IP_TYPE_V6_V01;
					memcpy(&qmi_rule_msg.firewall_rules_list[pos].filter_rule,
						&rule_table_v6->rules[cnt].rule.eq_attrib,
						sizeof(struct ipa_filter_rule_type_v01));
					pos++;
				}
				else
				{
					IPACMERR(" QMI only support max %d rules, current (%d)\n ", QMI_IPA_MAX_UL_FIREWALL_RULES_V01, pos);
				}
			}

			qmi_rule_msg.mux_id = mux_id;
			if (is_enable == false)
			{
				qmi_rule_msg.disable_valid = 1;
				qmi_rule_msg.disable = 1;
			}
		}

		ret = ioctl(fd_wwan_ioctl, WAN_IOC_ADD_UL_FLT_RULE, &qmi_rule_msg);
		if (ret != 0)
		{
			IPACMERR("Failed adding Filtering rule %p with ret %d\n ", &qmi_rule_msg, ret);
			close(fd_wwan_ioctl);
			return false;
		}
	}
	close(fd_wwan_ioctl);
	return true;
}
#endif

#ifdef FEATURE_VLAN_MPDN
bool IPACM_Filtering::AddWanDLFilteringRule(struct ipa_ioc_add_flt_rule const *rule_table_v4, struct ipa_ioc_add_flt_rule const * rule_table_v6,
	uint8_t *mux_id_v4, uint8_t *mux_id_v6)
#else
bool IPACM_Filtering::AddWanDLFilteringRule(struct ipa_ioc_add_flt_rule const *rule_table_v4, struct ipa_ioc_add_flt_rule const * rule_table_v6, uint8_t mux_id)
#endif
{
	int ret = 0, cnt, num_rules = 0, pos = 0;
	ipa_install_fltr_rule_req_msg_v01 qmi_rule_msg;
#ifdef FEATURE_IPA_V3
	ipa_install_fltr_rule_req_ex_msg_v01 qmi_rule_ex_msg;
#endif

	int fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
	if(fd_wwan_ioctl < 0)
	{
		IPACMERR("Failed to open %s.\n",WWAN_QMI_IOCTL_DEVICE_NAME);
		return false;
	}

	if(rule_table_v4 != NULL)
	{
#ifdef FEATURE_VLAN_MPDN
		if(!mux_id_v4)
		{
			IPACMERR("got NULL v4 mux IDs array\n");
			return false;
		}
#endif
		num_rules += rule_table_v4->num_rules;
		IPACMDBG_H("Get %d WAN DL IPv4 filtering rules.\n", rule_table_v4->num_rules);
	}
	if(rule_table_v6 != NULL)
	{
#ifdef FEATURE_VLAN_MPDN
		if(!mux_id_v6)
		{
			IPACMERR("got NULL v6 mux IDs array\n");
			return false;
		}
#endif
		num_rules += rule_table_v6->num_rules;
		IPACMDBG_H("Get %d WAN DL IPv6 filtering rules.\n", rule_table_v6->num_rules);
	}

	/* if it is not IPA v3, use old QMI format */
#ifndef FEATURE_IPA_V3
	if(num_rules > QMI_IPA_MAX_FILTERS_V01)
	{
		IPACMERR("The number of filtering rules exceed limit.\n");
		close(fd_wwan_ioctl);
		return false;
	}
	else
	{
		memset(&qmi_rule_msg, 0, sizeof(qmi_rule_msg));

		if (num_rules > 0)
		{
			qmi_rule_msg.filter_spec_list_valid = true;
		}
		else
		{
			qmi_rule_msg.filter_spec_list_valid = false;
		}

		qmi_rule_msg.filter_spec_list_len = num_rules;
		qmi_rule_msg.source_pipe_index_valid = 0;

		IPACMDBG_H("Get %d WAN DL filtering rules in total.\n", num_rules);

		if(rule_table_v4 != NULL)
		{
			for(cnt = rule_table_v4->num_rules - 1; cnt >= 0; cnt--)
			{
				if (pos < QMI_IPA_MAX_FILTERS_V01)
				{
					qmi_rule_msg.filter_spec_list[pos].filter_spec_identifier = pos;
					qmi_rule_msg.filter_spec_list[pos].ip_type = QMI_IPA_IP_TYPE_V4_V01;
					qmi_rule_msg.filter_spec_list[pos].filter_action = GetQmiFilterAction(rule_table_v4->rules[cnt].rule.action);
					qmi_rule_msg.filter_spec_list[pos].is_routing_table_index_valid = 1;
					qmi_rule_msg.filter_spec_list[pos].route_table_index = rule_table_v4->rules[cnt].rule.rt_tbl_idx;
					qmi_rule_msg.filter_spec_list[pos].is_mux_id_valid = 1;
#ifdef FEATURE_VLAN_MPDN
					qmi_rule_msg.filter_spec_list[pos].mux_id = mux_id_v4[cnt];
#else
					qmi_rule_msg.filter_spec_list[pos].mux_id = mux_id;
#endif
					memcpy(&qmi_rule_msg.filter_spec_list[pos].filter_rule,
						&rule_table_v4->rules[cnt].rule.eq_attrib,
						sizeof(struct ipa_filter_rule_type_v01));
					pos++;
				}
				else
				{
					IPACMERR(" QMI only support max %d rules, current (%d)\n ",QMI_IPA_MAX_FILTERS_V01, pos);
				}
			}
		}

		if(rule_table_v6 != NULL)
		{
			for(cnt = rule_table_v6->num_rules - 1; cnt >= 0; cnt--)
			{
				if (pos < QMI_IPA_MAX_FILTERS_V01)
				{
					qmi_rule_msg.filter_spec_list[pos].filter_spec_identifier = pos;
					qmi_rule_msg.filter_spec_list[pos].ip_type = QMI_IPA_IP_TYPE_V6_V01;
					qmi_rule_msg.filter_spec_list[pos].filter_action = GetQmiFilterAction(rule_table_v6->rules[cnt].rule.action);
					qmi_rule_msg.filter_spec_list[pos].is_routing_table_index_valid = 1;
					qmi_rule_msg.filter_spec_list[pos].route_table_index = rule_table_v6->rules[cnt].rule.rt_tbl_idx;
					qmi_rule_msg.filter_spec_list[pos].is_mux_id_valid = 1;
#ifdef FEATURE_VLAN_MPDN
					qmi_rule_msg.filter_spec_list[pos].mux_id = mux_id_v6[cnt];
#else
					qmi_rule_msg.filter_spec_list[pos].mux_id = mux_id;
#endif
					memcpy(&qmi_rule_msg.filter_spec_list[pos].filter_rule,
						&rule_table_v6->rules[cnt].rule.eq_attrib,
						sizeof(struct ipa_filter_rule_type_v01));
					pos++;
				}
				else
				{
					IPACMERR(" QMI only support max %d rules, current (%d)\n ",QMI_IPA_MAX_FILTERS_V01, pos);
				}
			}
		}

		ret = ioctl(fd_wwan_ioctl, WAN_IOC_ADD_FLT_RULE, &qmi_rule_msg);
		if (ret != 0)
		{
			IPACMERR("Failed adding Filtering rule %p with ret %d\n ", &qmi_rule_msg, ret);
			close(fd_wwan_ioctl);
			return false;
		}
	}
	/* if it is IPA v3, use new QMI format */
#else
	if(num_rules > QMI_IPA_MAX_FILTERS_EX_V01)
	{
		IPACMERR("The number of filtering rules exceed limit.\n");
		close(fd_wwan_ioctl);
		return false;
	}
	else
	{
		memset(&qmi_rule_ex_msg, 0, sizeof(qmi_rule_ex_msg));

		if (num_rules > 0)
		{
			qmi_rule_ex_msg.filter_spec_ex_list_valid = true;
		}
		else
		{
			qmi_rule_ex_msg.filter_spec_ex_list_valid = false;
		}
		qmi_rule_ex_msg.filter_spec_ex_list_len = num_rules;
		qmi_rule_ex_msg.source_pipe_index_valid = 0;

		IPACMDBG_H("Get %d WAN DL filtering rules in total.\n", num_rules);

		if(rule_table_v4 != NULL)
		{
			for(cnt = rule_table_v4->num_rules - 1; cnt >= 0; cnt--)
			{
				if (pos < QMI_IPA_MAX_FILTERS_EX_V01)
				{
					qmi_rule_ex_msg.filter_spec_ex_list[pos].ip_type = QMI_IPA_IP_TYPE_V4_V01;
					qmi_rule_ex_msg.filter_spec_ex_list[pos].filter_action = GetQmiFilterAction(rule_table_v4->rules[cnt].rule.action);
					qmi_rule_ex_msg.filter_spec_ex_list[pos].is_routing_table_index_valid = 1;
					qmi_rule_ex_msg.filter_spec_ex_list[pos].route_table_index = rule_table_v4->rules[cnt].rule.rt_tbl_idx;
					qmi_rule_ex_msg.filter_spec_ex_list[pos].is_mux_id_valid = 1;
#ifdef FEATURE_VLAN_MPDN
					qmi_rule_ex_msg.filter_spec_ex_list[pos].mux_id = mux_id_v4[cnt];
#else
					qmi_rule_ex_msg.filter_spec_ex_list[pos].mux_id = mux_id;
#endif
					qmi_rule_ex_msg.filter_spec_ex_list[pos].rule_id = rule_table_v4->rules[cnt].rule.rule_id;
					qmi_rule_ex_msg.filter_spec_ex_list[pos].is_rule_hashable = rule_table_v4->rules[cnt].rule.hashable;
					memcpy(&qmi_rule_ex_msg.filter_spec_ex_list[pos].filter_rule,
						&rule_table_v4->rules[cnt].rule.eq_attrib,
						sizeof(struct ipa_filter_rule_type_v01));

					pos++;
				}
				else
				{
					IPACMERR(" QMI only support max %d rules, current (%d)\n ",QMI_IPA_MAX_FILTERS_EX_V01, pos);
				}
			}
		}

		if(rule_table_v6 != NULL)
		{
			for(cnt = rule_table_v6->num_rules - 1; cnt >= 0; cnt--)
			{
				if (pos < QMI_IPA_MAX_FILTERS_EX_V01)
				{
					qmi_rule_ex_msg.filter_spec_ex_list[pos].ip_type = QMI_IPA_IP_TYPE_V6_V01;
					qmi_rule_ex_msg.filter_spec_ex_list[pos].filter_action = GetQmiFilterAction(rule_table_v6->rules[cnt].rule.action);
					qmi_rule_ex_msg.filter_spec_ex_list[pos].is_routing_table_index_valid = 1;
					qmi_rule_ex_msg.filter_spec_ex_list[pos].route_table_index = rule_table_v6->rules[cnt].rule.rt_tbl_idx;
					qmi_rule_ex_msg.filter_spec_ex_list[pos].is_mux_id_valid = 1;
#ifdef FEATURE_VLAN_MPDN
					qmi_rule_ex_msg.filter_spec_ex_list[pos].mux_id = mux_id_v6[cnt];
#else
					qmi_rule_ex_msg.filter_spec_ex_list[pos].mux_id = mux_id;
#endif
					qmi_rule_ex_msg.filter_spec_ex_list[pos].rule_id = rule_table_v6->rules[cnt].rule.rule_id;
					qmi_rule_ex_msg.filter_spec_ex_list[pos].is_rule_hashable = rule_table_v6->rules[cnt].rule.hashable;
					memcpy(&qmi_rule_ex_msg.filter_spec_ex_list[pos].filter_rule,
						&rule_table_v6->rules[cnt].rule.eq_attrib,
						sizeof(struct ipa_filter_rule_type_v01));

					pos++;
				}
				else
				{
					IPACMERR(" QMI only support max %d rules, current (%d)\n ",QMI_IPA_MAX_FILTERS_EX_V01, pos);
				}
			}
		}

		ret = ioctl(fd_wwan_ioctl, WAN_IOC_ADD_FLT_RULE_EX, &qmi_rule_ex_msg);
		if (ret != 0)
		{
			IPACMERR("Failed adding Filtering rule %p with ret %d\n ", &qmi_rule_ex_msg, ret);
			close(fd_wwan_ioctl);
			return false;
		}
	}
#endif

	close(fd_wwan_ioctl);
	return true;
}

bool IPACM_Filtering::SendFilteringRuleIndex(struct ipa_fltr_installed_notif_req_msg_v01* table)
{
	int ret = 0;
	int fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
	if(fd_wwan_ioctl < 0)
	{
		IPACMERR("Failed to open %s.\n",WWAN_QMI_IOCTL_DEVICE_NAME);
		return false;
	}

	ret = ioctl(fd_wwan_ioctl, WAN_IOC_ADD_FLT_RULE_INDEX, table);
	if (ret != 0)
	{
		IPACMERR("Failed adding filtering rule index %p with ret %d\n", table, ret);
		close(fd_wwan_ioctl);
		return false;
	}

	IPACMDBG("Added Filtering rule index %p\n", table);
	close(fd_wwan_ioctl);
	return true;
}

ipa_filter_action_enum_v01 IPACM_Filtering::GetQmiFilterAction(ipa_flt_action action)
{
	switch(action)
	{
	case IPA_PASS_TO_ROUTING:
		return QMI_IPA_FILTER_ACTION_ROUTING_V01;

	case IPA_PASS_TO_SRC_NAT:
		return QMI_IPA_FILTER_ACTION_SRC_NAT_V01;

	case IPA_PASS_TO_DST_NAT:
		return QMI_IPA_FILTER_ACTION_DST_NAT_V01;

	case IPA_PASS_TO_EXCEPTION:
		return QMI_IPA_FILTER_ACTION_EXCEPTION_V01;

	default:
		return IPA_FILTER_ACTION_ENUM_MAX_ENUM_VAL_V01;
	}
}

bool IPACM_Filtering::ModifyFilteringRule(struct ipa_ioc_mdfy_flt_rule* ruleTable)
{
	int i, ret = 0;

	IPACMDBG("Printing filtering add attributes\n");
	IPACMDBG("IP type: %d Number of rules: %d commit value: %d\n", ruleTable->ip, ruleTable->num_rules, ruleTable->commit);

	if(!ruleTable->num_rules)
	{
		IPACMERR("0 rules to modify, iptype %s\n", ruleTable->ip == IPA_IP_v4 ? "v4" : "v6");
		return false;
	}

	for (i=0; i<ruleTable->num_rules; i++)
	{
		IPACMDBG("Filter rule:%d attrib mask: 0x%x\n", i, ruleTable->rules[i].rule.attrib.attrib_mask);
	}

	ret = ioctl(fd, IPA_IOC_MDFY_FLT_RULE, ruleTable);

	for (i = 0; i < ruleTable->num_rules; i++)
	{
		if (ruleTable->rules[i].status != 0)
		{
			IPACMERR("Modifying filter rule %d failed\n", i);
		}
	}

	if (ret != 0)
	{
		IPACMERR("Failed modifying filtering rule IOCTL for %pK\n", ruleTable);
		return false;
	}

	IPACMDBG("Modified filtering rule %p\n", ruleTable);
	return true;
}

