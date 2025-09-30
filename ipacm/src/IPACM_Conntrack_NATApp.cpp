/*
Copyright (c) 2013-2021, The Linux Foundation. All rights reserved.

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

Changes from Qualcomm Technologies, Inc. are provided under the following license:

Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause-Clear

*/
#include "IPACM_Conntrack_NATApp.h"
#include "IPACM_ConntrackClient.h"
#include "IPACM_Iface.h"
#include "IPACM_Wan.h"

extern "C"
{
#include <ipa_ipv6ct.h>
#include <ipa_nat_drv.h>
}

#include <algorithm>

#define INVALID_IP_ADDR 0x0

#define HDR_METADATA_MUX_ID_BMASK 0x00FF0000
#define HDR_METADATA_MUX_ID_SHFT 0x10

#define DUAL_BACKHAUL_PDN_COUNT 2

#undef strcasesame
#define strcasesame(a, b) (!strcasecmp(a, b))

#undef  SRAM_IN_USE
#define SRAM_IN_USE() \
	( strcasesame(mem_type, "HYBRID" ) || \
	  strcasesame(mem_type, "SRAM" ) )

#define CT_SRAM_IN_USE() \
	( strcasesame(ct_mem_type, "HYBRID" ) || \
	  strcasesame(ct_mem_type, "SRAM" ) )


/* NatApp class Implementation */
NatApp *NatApp::pInstance = NULL;

bool NatApp::kernel_ver_updated = false;
bool NatApp::is_kernel_ver_upgraded = false;

extern int bool_dual_backhaul;

NatApp::NatApp()
{
	max_entries = 0;
	mem_type = NULL;

	cache = NULL;

	nat_table_hdl = 0;
	pub_ip_addr = 0;

	curCnt = 0;

	pALGPorts = NULL;
	nALGPort = 0;

	ct = NULL;
	ct_hdl = NULL;

	memset(temp, 0, sizeof(temp));
}

int NatApp::Init(void)
{
	IPACM_Config *pConfig;
	int size = 0;

	pConfig = IPACM_Config::GetInstance();
	if(pConfig == NULL)
	{
		IPACMERR("Unable to get Config instance\n");
		return -1;
	}

	mem_type = pConfig->GetNatMemType();

	max_entries = pConfig->GetNatMaxEntries();

	size = (sizeof(nat_table_entry) * max_entries);
	cache = (nat_table_entry *)malloc(size);
	if(cache == NULL)
	{
		IPACMERR("Unable to allocate memory for cache\n");
		goto fail;
	}
	IPACMDBG("Allocated %d bytes for config manager nat cache\n", size);
	memset(cache, 0, size);

	nALGPort = pConfig->GetAlgPortCnt();
	if(nALGPort > 0)
	{
		pALGPorts = (ipacm_alg *)malloc(sizeof(ipacm_alg) * nALGPort);
		if(pALGPorts == NULL)
		{
			IPACMERR("Unable to allocate memory for alg prots\n");
			goto fail;
		}
		memset(pALGPorts, 0, sizeof(ipacm_alg) * nALGPort);

		if(pConfig->GetAlgPorts(nALGPort, pALGPorts) != 0)
		{
			IPACMERR("Unable to retrieve ALG prots\n");
			goto fail;
		}

		IPACMDBG("Printing %d alg ports information\n", nALGPort);
		for(int cnt=0; cnt<nALGPort; cnt++)
		{
			IPACMDBG("%d: Proto[%d], port[%d]\n", cnt, pALGPorts[cnt].protocol, pALGPorts[cnt].port);
		}
	}

	return 0;

fail:
	free(cache);
	free(pALGPorts);
	return -1;
}

NatApp* NatApp::GetInstance()
{
	if(pInstance == NULL)
	{
		pInstance = new NatApp();

		if(pInstance->Init())
		{
			delete pInstance;
			return NULL;
		}
	}

	return pInstance;
}

uint32_t NatApp::GenerateMetdata(uint8_t mux_id)
{
	return (mux_id << HDR_METADATA_MUX_ID_SHFT) & HDR_METADATA_MUX_ID_BMASK;
}

/* NAT APP related object function definitions */
#ifdef FEATURE_VLAN_MPDN
int NatApp::AddPdn(uint32_t pub_ip, uint8_t mux_id, bool is_sta, bool ip_pass)
{
	int ret = IPACM_SUCCESS;
	int cnt = 0;
	ipa_nat_ipv4_rule nat_rule;
	ipa_nat_pdn_entry entry;
	uint8_t pdn_index;
	uint8_t pdn_count = 0;
	IPACMDBG_H("%s() %d\n", __FUNCTION__, __LINE__);

	entry.dst_metadata = 0;
	entry.src_metadata = GenerateMetdata(mux_id);
	entry.public_ip = pub_ip;
	entry.is_sta = is_sta;

	ret = ipa_nat_get_pdn_count(&pdn_count);
	if(ret)
	{
		IPACMERR("unable to get pdn count Error:%d\n", ret);
		return ret;
	}
	IPACMDBG_H("AddPDN isSta:%d, pdn_count: %d, ip 0x%X\n", is_sta,pdn_count,pub_ip);


	if(!pdn_count)
	{
		/* create the NAT table, the PDN will be stored in index 0 */
		if(is_sta)
		{
			/* This function stores pub_ip at pdn[0].
			 * We don't want that for non STA PDNs*/
			ret = ipa_nat_add_ipv4_tbl(pub_ip, mem_type, max_entries, &nat_table_hdl);
		}
		else
		{
			ret = ipa_nat_add_ipv4_tbl(pub_ip, mem_type, max_entries, &nat_table_hdl);
		}
		if(ret)
		{
			IPACMERR("unable to create nat table Error:%d\n", ret);
			return ret;
		}
		IPACMDBG_H("succeesfully created NAT table for ip 0x%X\n", pub_ip);
		entry.src_metadata = GenerateMetdata(mux_id);
		pdn_index = 0;

		if(is_sta)
		{
			IPACMDBG_H("got pdn index %d\n", pdn_index);
			entry.src_metadata = 0;
			entry.is_sta = true;
			IPACMDBG_H("attempting second backhaul ADDPDN\n");
		}

		/* modify PDN 0 so it will hold the mux ID in the src metadata field */
		ret = ipa_nat_modify_pdn(nat_table_hdl, pdn_index, &entry);
		IPACMDBG_H("modify pdn index %d\n", pdn_index);
		if(ret)
		{
			IPACMERR("unable to modify PDN 0 entry Error:%d\n", ret);
			return ret;
		}
	}
	else
	{
#ifdef FEATURE_DUAL_BACKHAUL
		if(is_sta)
		{
			if(ipa_nat_get_pdn_index(pub_ip, &pdn_index) < 0)
			{
				entry.public_ip = pub_ip;
				entry.src_metadata = 0;
				entry.is_sta = true;
				IPACMDBG_H("attempting second backhaul modify ADDPDN\n");
				ret = ipa_nat_alloc_pdn(&entry, &pdn_index);
				if(ret){
					IPACMERR("unable to modify PDN 0 entry Error:%d\n", ret);
					return ret;
				}
			}
		}
		else
		{
#endif
			/* only allocate a PDN if it is a new one */
			if(ipa_nat_get_pdn_index(pub_ip, &pdn_index) < 0)
			{
				ret = ipa_nat_alloc_pdn(&entry, &pdn_index);
				if(ret)
				{
					IPACMERR("couldn't allocate a pdn index\n");
					return ret;
				}
				IPACMDBG_H("successfully allocated index %d for ip 0x%X\n",
						pdn_index, pub_ip);
			}
			else
			{
				IPACMDBG_H("pdn already existed with index %d\n", pdn_index);
			}
#ifdef FEATURE_DUAL_BACKHAUL
		}
#endif

	}

	/* now traverse cache and add the PDN entries */
	for(cnt = 0; cnt < max_entries; cnt++)
	{
		if((cache[cnt].private_ip != 0)
			/* flush only entries which are related to this PDN */
			&& (cache[cnt].public_ip == pub_ip) && (cache[cnt].enabled == false))
		{
			if(is_sta && (isAlgPort(cache[cnt].protocol, cache[cnt].private_port) ||
				isAlgPort(cache[cnt].protocol, cache[cnt].target_port))) {
				IPACMERR("STA backhaul: connection using ALG Port, ignore\n");
				memset(&cache[cnt], 0, sizeof(cache[cnt]));
				curCnt--;
				continue;
			}

			if (ip_pass && cache[cnt].dummy_nat) {
				IPACMERR("IP Pass enabled: connection using dummy Nat, ignore\n");
				memset(&cache[cnt], 0, sizeof(cache[cnt]));
				curCnt--;
				continue;
			}

			memset(&nat_rule, 0, sizeof(nat_rule));
			nat_rule.private_ip = cache[cnt].private_ip;
			nat_rule.target_ip = cache[cnt].target_ip;
			nat_rule.target_port = cache[cnt].target_port;
			nat_rule.private_port = cache[cnt].private_port;
			nat_rule.public_port = cache[cnt].public_port;
			nat_rule.protocol = cache[cnt].protocol;
			nat_rule.uc_activation_index = cache[cnt].uc_activation_index;
			nat_rule.ucp = cache[cnt].ucp;
			nat_rule.s = cache[cnt].s;
			nat_rule.pdn_index = pdn_index;
			cache[cnt].pdn_index = pdn_index;

			if(ipa_nat_add_ipv4_rule(nat_table_hdl, &nat_rule, &cache[cnt].rule_hdl) < 0)
			{
				IPACMERR("unable to add the rule delete from cache\n");
				memset(&cache[cnt], 0, sizeof(cache[cnt]));
				curCnt--;
				continue;
			}
			IPACMDBG("cache entry %d rule handle %d\n", cnt, cache[cnt].rule_hdl);
			cache[cnt].enabled = true;

			IPACMDBG("new pdn added below rule successfully\n");
			iptodot("Private IP", nat_rule.private_ip);
			iptodot("Target IP", nat_rule.target_ip);
			IPACMDBG("Private Port:%d \t Target Port: %d\n", nat_rule.private_port, nat_rule.target_port);
			IPACMDBG("Public Port:%d\n", nat_rule.public_port);
			IPACMDBG("protocol: %d\n", nat_rule.protocol);
			IPACMDBG("pdn index: %d\n", nat_rule.pdn_index);
		}

	}

	return ret;
}
#endif
int NatApp::AddTable(uint32_t pub_ip, uint8_t mux_id, bool is_sta)
{
	int ret;
	int cnt = 0;
	ipa_nat_ipv4_rule nat_rule;
	IPACMDBG_H("%s() %d\n", __FUNCTION__, __LINE__);

	/* Not reset the cache wait it timeout by destroy event */
#if 0
	if (pub_ip != pub_ip_addr_pre)
	{
		IPACMDBG("Reset the cache because NAT-ipv4 different\n");
		memset(cache, 0, sizeof(nat_table_entry) * max_entries);
		curCnt = 0;
	}
#endif
	ret = ipa_nat_add_ipv4_tbl(pub_ip, mem_type, max_entries, &nat_table_hdl);
	if(ret)
	{
		IPACMERR("unable to create nat table Error:%d\n", ret);
		return ret;
	}

	if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0) {
		/* modify PDN 0 so it will hold the mux ID in the src metadata field */
		ipa_nat_pdn_entry entry;

		entry.dst_metadata = 0;
		entry.src_metadata = GenerateMetdata(mux_id);
		entry.public_ip = pub_ip;
		ret = ipa_nat_modify_pdn(nat_table_hdl, 0, &entry);
		if(ret)
		{
			IPACMERR("unable to modify PDN 0 entry Error:%d INIT_HDR_METADATA register values will be used!\n", ret);
		}
	}

	/* Add back the cached NAT-entry */
	if (pub_ip == pub_ip_addr_pre)
	{
		IPACMDBG("Restore the cache to ipa NAT-table\n");
		for(cnt = 0; cnt < max_entries; cnt++)
		{
			if((cache[cnt].private_ip !=0))
			{
				if(is_sta && (isAlgPort(cache[cnt].protocol, cache[cnt].private_port) ||
					isAlgPort(cache[cnt].protocol, cache[cnt].target_port))) {
					IPACMERR("STA backhaul: connection using ALG Port, ignore\n");
					memset(&cache[cnt], 0, sizeof(cache[cnt]));
					curCnt--;
					continue;
				}

				memset(&nat_rule, 0 , sizeof(nat_rule));
				nat_rule.private_ip = cache[cnt].private_ip;
				nat_rule.target_ip = cache[cnt].target_ip;
				nat_rule.target_port = cache[cnt].target_port;
				nat_rule.private_port = cache[cnt].private_port;
				nat_rule.public_port = cache[cnt].public_port;
				nat_rule.protocol = cache[cnt].protocol;
				nat_rule.uc_activation_index = cache[cnt].uc_activation_index;
				nat_rule.ucp = cache[cnt].ucp;
				nat_rule.s = cache[cnt].s;


				if(ipa_nat_add_ipv4_rule(nat_table_hdl, &nat_rule, &cache[cnt].rule_hdl) < 0)
				{
					IPACMERR("unable to add the rule delete from cache\n");
					memset(&cache[cnt], 0, sizeof(cache[cnt]));
					curCnt--;
					continue;
				}
				IPACMDBG("cache entry %d rule handle %d\n", cnt, cache[cnt].rule_hdl);
				cache[cnt].enabled = true;

				IPACMDBG("On wan-iface reset added below rule successfully\n");
				iptodot("Private IP", nat_rule.private_ip);
				iptodot("Target IP", nat_rule.target_ip);
				IPACMDBG("Private Port:%d \t Target Port: %d\n", nat_rule.private_port, nat_rule.target_port);
				IPACMDBG("Public Port:%d\n", nat_rule.public_port);
				IPACMDBG("protocol: %d\n", nat_rule.protocol);
			}
		}
	}

	pub_ip_addr = pub_ip;
	return 0;
}

void NatApp::Reset()
{
	int cnt = 0;

	nat_table_hdl = 0;
	pub_ip_addr = 0;
	/* NAT tbl deleted, reset enabled bit */
	for(cnt = 0; cnt < max_entries; cnt++)
	{
		cache[cnt].enabled = false;
	}
}

#ifdef FEATURE_VLAN_MPDN
int NatApp::RemovePdn(uint32_t pub_ip)
{
	int ret;
	uint8_t pdn_index;
	uint8_t pdn_cnt;
	IPACMDBG_H("%s() %d\n", __FUNCTION__, __LINE__);

	CHK_TBL_HDL();

	ret = ipa_nat_get_pdn_index(pub_ip, &pdn_index);
#ifdef FEATURE_DUAL_BACKHAUL
	ret = ipa_nat_get_pdn_count(&pdn_cnt);
	if(pdn_cnt < DUAL_BACKHAUL_PDN_COUNT && pdn_index == 0 && bool_dual_backhaul == 1)
	{
		IPACMDBG_H("only eth is there don't remove any pdn\n");
		bool_dual_backhaul = 0;
		return IPACM_FAILURE;
	}
#endif

	IPACMDBG_H("RemovePDN  pdn_index:%d, IP: %x\n",pdn_index, pub_ip);
	if(ret)
	{
		IPACMERR("pdn doesn't exist on pdn table\n");
		return IPACM_FAILURE;
	}
	IPACMDBG_H("pdn ip found at pdn_index:%d\n", pdn_index);
	/* remove all PDN entries */
	for(int cnt = 0; cnt < max_entries; cnt++)
	{
		if((cache[cnt].pdn_index == pdn_index) &&
			(cache[cnt].enabled == true))
		{
			if(ipa_nat_del_ipv4_rule(nat_table_hdl, cache[cnt].rule_hdl) < 0)
			{
				IPACMERR("unable to delete rule with private ip 0x%X\n", cache[cnt].private_ip);
				continue;
			}
			memset(&cache[cnt], 0, sizeof(cache[cnt]));
		}
	}

	ret = ipa_nat_dealloc_pdn(pdn_index);
	if(ret)
	{
		IPACMERR(" couldn't deallocate PDN in index %d\n",pdn_index);
		return IPACM_FAILURE;
	}

	ret = ipa_nat_get_pdn_count(&pdn_cnt);
	if(ret)
	{
		IPACMERR(" couldn't acquire number of PDNs\n");
		return IPACM_FAILURE;
	}

	if(!pdn_cnt)
	{
		IPACMDBG_H("removing NAT table\n");
		ret = ipa_nat_del_ipv4_tbl(nat_table_hdl);
		if(ret)
		{
			IPACMERR("unable to delete nat table Error: %d\n", ret);;
			return ret;
		}

		Reset();
	}
	IPACMDBG_H("RemovePDN  pdn_index:%d, pdn_count: %d, ip 0x%X\n",pdn_index,pdn_cnt,pub_ip);


	return 0;
}
#endif

int NatApp::DeleteTable(uint32_t pub_ip)
{
	int ret;
	IPACMDBG_H("%s() %d\n", __FUNCTION__, __LINE__);

	CHK_TBL_HDL();

	if(pub_ip_addr != pub_ip)
	{
		IPACMDBG("Public ip address is not matching\n");
		IPACMERR("unable to delete the nat table\n");
		return -1;
	}

	ret = ipa_nat_del_ipv4_tbl(nat_table_hdl);
	if(ret)
	{
		IPACMERR("unable to delete nat table Error: %d\n", ret);;
		return ret;
	}

	pub_ip_addr_pre = pub_ip_addr;
	Reset();
	return 0;
}

int NatApp::MoveTable(bool to_ddr)
{
	int ret;

	if (to_ddr) {
		IPACMDBG_H("direction TO_DDR - move and lock table at DDR\n");
		ret = ipa_nat_switch_to(IPA_NAT_MEM_IN_DDR, true);
	} else {
		IPACMDBG_H("direction TO_SRAM - allow table transition to SRAM\n");
		ret = ipa_nat_switch_to(IPA_NAT_MEM_IN_DDR, false);
	}

	return ret;
}

/* Check for duplicate entries */
bool NatApp::ChkForDup(const nat_table_entry *rule)
{
	int cnt = 0;
	IPACMDBG("%s() %d\n", __FUNCTION__, __LINE__);

	for(; cnt < max_entries; cnt++)
	{
		if(cache[cnt].private_ip == rule->private_ip &&
			 cache[cnt].target_ip == rule->target_ip &&
			 cache[cnt].private_port ==  rule->private_port  &&
			 cache[cnt].target_port == rule->target_port &&
			 cache[cnt].protocol == rule->protocol  &&
			 cache[cnt].dst_only == rule->dst_only  &&
			 cache[cnt].src_only == rule->src_only)
		{
			log_nat(rule->protocol,rule->private_ip,rule->target_ip,rule->private_port,\
			rule->public_port,rule->target_port,rule->src_only,rule->dst_only,"Duplicate Rule\n");
			return true;
		}
	}

	return false;
}

/* Check for duplicate entries */
bool NatApp::ChkForDupGRE(const nat_table_entry *rule)
{
	int cnt = 0;
	IPACMDBG("%s() %d\n", __FUNCTION__, __LINE__);

	for(; cnt < max_entries; cnt++)
	{
		//one GRE connection per server is supported
		if(cache[cnt].protocol == IPPROTO_GRE &&
		   cache[cnt].target_ip == rule->target_ip)
		{
			log_nat(rule->protocol,rule->private_ip,rule->target_ip,rule->private_port,\
			rule->public_port,rule->target_port,rule->src_only,rule->dst_only,"Duplicate Rule\n");
			return true;
		}
	}

	return false;
}

/* Delete the entry from Nat table on connection close */
int NatApp::DeleteEntryGRE(const nat_table_entry *rule)
{
	int cnt = 0;
	IPACMDBG("%s() %d\n", __FUNCTION__, __LINE__);

	log_nat(rule->protocol,rule->private_ip,rule->target_ip,rule->private_port,\
	rule->public_port,rule->target_port,rule->src_only,rule->dst_only,"for deletion\n");


	for(; cnt < max_entries; cnt++)
	{
		if(cache[cnt].protocol == IPPROTO_GRE &&
		   cache[cnt].target_ip == rule->target_ip)
		{

			if(cache[cnt].enabled == true)
			{
				log_nat(cache[cnt].protocol,cache[cnt].private_ip,cache[cnt].target_ip,cache[cnt].private_port,\
					cache[cnt].public_port,cache[cnt].target_port,cache[cnt].src_only,cache[cnt].dst_only,"for deletion\n");
				if(ipa_nat_del_ipv4_rule(nat_table_hdl, cache[cnt].rule_hdl) < 0)
				{
					IPACMERR("%s() %d deletion failed\n", __FUNCTION__, __LINE__);
				}
				else
				{
					IPACMDBG_H("Deleted Nat entry(%d) Successfully\n", cnt);
				}
			}
			else
			{
				IPACMDBG_H("Deleted Nat entry(%d) only from cache\n", cnt);
			}

			memset(&cache[cnt], 0, sizeof(cache[cnt]));
			curCnt--;
			break;
		}
	}

	return 0;
}

/* Check for sw allow entries */
bool NatApp::ChkSWAllow(const nat_table_entry *rule)
{
	int i, j;
	IPACM_extd_swallow_entry_conf_t entry;
	IPACM_swallow_t *sw_filter_cfg = NULL;
	IPACMDBG("Entry\n");

	if(!IPACM_Iface::ipacmcfg->ipacm_msgflt_enable)
	{
		IPACMERR("msg filtering feature is not enabled\n");
		return false;
	}
	if(!IPACM_Iface::ipacmcfg->sw_filter_cfg)
	{
		IPACMERR("SW Config not updated/pdn index not updated!\n");
		return false;
	}
	if(sw_filter_cfg == NULL) {
		sw_filter_cfg = (IPACM_swallow_t *)calloc(1, sizeof(IPACM_swallow_t));
	}
	if(sw_filter_cfg == NULL) {
		IPACMERR("Could not allocate memory \n");
		return IPACM_FAILURE;
	}
	memcpy(sw_filter_cfg, IPACM_Iface::ipacmcfg->sw_filter_cfg, sizeof(IPACM_swallow_t));

	for(i = 0; i < sw_filter_cfg->pdn_count;i++)
	{
		/* PDN Not yet up */
		if(sw_filter_cfg->pdns[i].v4_up != TRUE || sw_filter_cfg->pdns[i].public_ipv4_addr != rule->public_ip)
			continue;

		for(j = 0; j < sw_filter_cfg->pdns[i].num_extd_swallow_entries;j++)
		{
			entry = sw_filter_cfg->pdns[i].extd_swallow_entries[j];

			/* Check if entry is v4 */
			if(entry.ip_vsn != IP_V4)
				continue;

			/* Check if rule protocol matches with entry protocol */
			if((entry.protocol) && (!(((entry.protocol &  IPPROTO_UDP) == rule->protocol) ||
				((entry.protocol &	IPPROTO_TCP) == rule->protocol))))
				continue;

			if(firewall_tuple_match_with_nat(entry, rule))
			{
				log_nat(rule->protocol,rule->private_ip,rule->target_ip,rule->private_port,\
				rule->public_port,rule->target_port,rule->src_only,rule->dst_only,"SW Allow V4 Rule - Do not add\n");
				if(sw_filter_cfg != NULL)
					free(sw_filter_cfg);
				return true;
			}
		}
	}
	IPACMDBG("Exit\n");
	/* No pdn found */
	if(sw_filter_cfg != NULL)
		free(sw_filter_cfg);
	return false;
}

/* Delete the entry from Nat table on connection close */
int NatApp::DeleteEntry(const nat_table_entry *rule)
{
	int cnt = 0;
	IPACMDBG("%s() %d\n", __FUNCTION__, __LINE__);

	log_nat(rule->protocol,rule->private_ip,rule->target_ip,rule->private_port,\
	rule->public_port,rule->target_port,rule->src_only,rule->dst_only,"for deletion\n");


	for(; cnt < max_entries; cnt++)
	{
		if(cache[cnt].private_ip == rule->private_ip &&
			 cache[cnt].target_ip == rule->target_ip &&
			 cache[cnt].private_port ==  rule->private_port  &&
			 cache[cnt].target_port == rule->target_port &&
			 cache[cnt].protocol == rule->protocol &&
			 cache[cnt].dst_only == rule->dst_only &&
			 cache[cnt].src_only == rule->src_only)
		{

			if(cache[cnt].enabled == true)
			{
				log_nat(cache[cnt].protocol,cache[cnt].private_ip,cache[cnt].target_ip,cache[cnt].private_port,\
					cache[cnt].public_port,cache[cnt].target_port,cache[cnt].src_only,cache[cnt].dst_only,"for deletion\n");
				if(ipa_nat_del_ipv4_rule(nat_table_hdl, cache[cnt].rule_hdl) < 0)
				{
					IPACMERR("%s() %d deletion failed\n", __FUNCTION__, __LINE__);
				}
				else
				{
					IPACMDBG_H("Deleted Nat entry(%d) Successfully\n", cnt);
				}
			}
			else
			{
				IPACMDBG_H("Deleted Nat entry(%d) only from cache\n", cnt);
			}
			if(cache[cnt].sw_allow && rule->sw_allow)
			{
				IPACMDBG_H("backup the sw allow Nat entry(%d) only from cache\n", cnt);
			}
			else
			{
				memset(&cache[cnt], 0, sizeof(cache[cnt]));
				curCnt--;
			}
			break;
		}
	}

	return 0;
}

void NatApp::restore_nat_for_sw_flt_entries(IPACM_extd_swallow_entry_conf_t extd_firewall_entries)
{
	int i;
	char iptype[4]={0}, cmd[100];
	ipa_nat_ipv4_rule nat_rule;
	for(i = 0; i < max_entries; i++)
	{
		if(cache[i].sw_allow == true)
		{
			if(firewall_tuple_match_with_nat(extd_firewall_entries, &cache[i]))
			{
				memset(&nat_rule, 0, sizeof(nat_rule));
	  			nat_rule.private_ip = cache[i].private_ip;
	  			nat_rule.target_ip = cache[i].target_ip;
	  			nat_rule.target_port = cache[i].target_port;
	  			nat_rule.private_port = cache[i].private_port;
	  			nat_rule.public_port = cache[i].public_port;
	  			nat_rule.protocol = cache[i].protocol;

		  		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_5) {
		  			nat_rule.uc_activation_index =cache[i].uc_activation_index;
		  			nat_rule.ucp = cache[i].ucp;
		  			nat_rule.s = cache[i].s;
		  			nat_rule.dst_only = cache[i].dst_only;
		  			nat_rule.src_only = cache[i].src_only;
				}
		  		nat_rule.pdn_index = cache[i].pdn_index;
				if(ipa_nat_add_ipv4_rule(nat_table_hdl, &nat_rule, &cache[i].rule_hdl) < 0)
				{
  					IPACMERR("unable to add the rule\n");
				}
  				cache[i].sw_allow = false;
  				IPACMDBG_H("cache entry %d rule handle %d\n", i, cache[i].rule_hdl);
  				cache[i].enabled = true;
			}
		}
	}
}

void NatApp::firewall_compare(IPACM_swallow_conf_t *backup_firewall_config, IPACM_swallow_conf_t *firewall_config)
{
	int i,j;
	if(backup_firewall_config->num_extd_swallow_entries == 0)
	{
		IPACMERR("backup firewall entry is zero, so no need to check further\n");
		goto end;
	}
	for(i = 0; i < backup_firewall_config->num_extd_swallow_entries; i++)
	{
		if(backup_firewall_config->extd_swallow_entries[i].ip_vsn != IP_V4)
		{
			continue;
		}
		for(j = 0; j < firewall_config->num_extd_swallow_entries; j++)
		{
			if((firewall_config->extd_swallow_entries[j].ip_vsn != backup_firewall_config->extd_swallow_entries[i].ip_vsn) ||
				(firewall_config->extd_swallow_entries[j].direction != backup_firewall_config->extd_swallow_entries[i].direction)||
				(firewall_config->extd_swallow_entries[j].attrib.u.v4.protocol != backup_firewall_config->extd_swallow_entries[i].attrib.u.v4.protocol))
			{
				continue;
			}

			if(firewall_config->extd_swallow_entries[j].attrib.src_port_lo == backup_firewall_config->extd_swallow_entries[i].attrib.src_port_lo &&
				firewall_config->extd_swallow_entries[j].attrib.src_port_hi == backup_firewall_config->extd_swallow_entries[i].attrib.src_port_hi &&
				firewall_config->extd_swallow_entries[j].attrib.dst_port_lo == backup_firewall_config->extd_swallow_entries[i].attrib.dst_port_lo &&
				firewall_config->extd_swallow_entries[j].attrib.dst_port_hi == backup_firewall_config->extd_swallow_entries[i].attrib.dst_port_hi &&
				firewall_config->extd_swallow_entries[j].attrib.src_port == backup_firewall_config->extd_swallow_entries[i].attrib.src_port &&
				firewall_config->extd_swallow_entries[j].attrib.dst_port == backup_firewall_config->extd_swallow_entries[i].attrib.dst_port &&
				firewall_config->extd_swallow_entries[j].attrib.u.v4.src_addr == backup_firewall_config->extd_swallow_entries[i].attrib.u.v4.src_addr &&
				firewall_config->extd_swallow_entries[j].attrib.u.v4.dst_addr == backup_firewall_config->extd_swallow_entries[i].attrib.u.v4.dst_addr)
			{
				IPACMDBG("firewall entry is matched\n");
				break;
			}
			else
			{
				IPACMDBG("firewall entry is not present\n");
				continue;
			}
		}
		if((j == firewall_config->num_extd_swallow_entries) || (firewall_config->num_extd_swallow_entries == 0))
		{
			IPACMERR("flushing the deleted nat entry\n");
			restore_nat_for_sw_flt_entries(backup_firewall_config->extd_swallow_entries[i]);
		}
	}
end:
	IPACMERR("reaching end of the firewall\n");
}

bool NatApp::firewall_tuple_match_with_nat(IPACM_extd_swallow_entry_conf_t extd_firewall_entries, const nat_table_entry *del_entry)
{

	bool src_range = false,dst_range =false;
	if(extd_firewall_entries.attrib.attrib_mask & IPA_FLT_SRC_PORT_RANGE)
	{
		src_range = true;
	}
	if(extd_firewall_entries.attrib.attrib_mask & IPA_FLT_DST_PORT_RANGE)
	{
		dst_range = true;
	}
	if(extd_firewall_entries.direction == IPACM_MSGR_UL_FIREWALL && !del_entry->dst_nat)
	{
		if((!((extd_firewall_entries.attrib.u.v4.src_addr!=0) ^ (extd_firewall_entries.attrib.u.v4.src_addr == del_entry->private_ip)) &&
			!((extd_firewall_entries.attrib.u.v4.dst_addr!=0)^ (extd_firewall_entries.attrib.u.v4.dst_addr == del_entry->target_ip)) &&
			!((src_range) ^ (extd_firewall_entries.attrib.src_port_lo <=  del_entry->private_port &&
			extd_firewall_entries.attrib.src_port_hi >=  del_entry->private_port)) &&
			!((dst_range) ^ ((extd_firewall_entries.attrib.dst_port_lo <=  del_entry->target_port) &&
			(extd_firewall_entries.attrib.dst_port_hi >=  del_entry->target_port))) &&
			!((extd_firewall_entries.attrib.src_port != 0) ^ (extd_firewall_entries.attrib.src_port ==  del_entry->private_port)) &&
			!((extd_firewall_entries.attrib.dst_port != 0) ^ (extd_firewall_entries.attrib.dst_port ==  del_entry->target_port))))
		{
			IPACMERR("Matched in UL\n");
			return true;
		}
		else if(((extd_firewall_entries.attrib.u.v4.src_addr == 0)) &&
		(extd_firewall_entries.attrib.u.v4.dst_addr == 0) &&
		(!src_range)  && (!dst_range) &&
		(extd_firewall_entries.attrib.src_port == 0) &&
		(extd_firewall_entries.attrib.dst_port == 0))
		{
			IPACMERR("Matched in UL wildcard entry\n");
			return true;
		}
	}
	else if(extd_firewall_entries.direction == IPACM_MSGR_DL_FIREWALL && del_entry->dst_nat)
	{
		if (!((extd_firewall_entries.attrib.u.v4.src_addr!=0) ^ (extd_firewall_entries.attrib.u.v4.src_addr == del_entry->target_ip)) &&
		!((extd_firewall_entries.attrib.u.v4.dst_addr!=0)^ (extd_firewall_entries.attrib.u.v4.dst_addr == del_entry->private_ip)) &&
		!((src_range) ^ (extd_firewall_entries.attrib.src_port_lo <=  del_entry->target_port &&
		extd_firewall_entries.attrib.src_port_hi >=  del_entry->target_port)) &&
		!((dst_range) ^ ((extd_firewall_entries.attrib.dst_port_lo <=  del_entry->private_port) &&
		(extd_firewall_entries.attrib.dst_port_hi >=  del_entry->private_port))) &&
		!((extd_firewall_entries.attrib.src_port != 0) ^ (extd_firewall_entries.attrib.src_port ==  del_entry->target_port)) &&
		!((extd_firewall_entries.attrib.dst_port != 0) ^ (extd_firewall_entries.attrib.dst_port ==  del_entry->private_port)))
		{
			IPACMERR("Matched in DL\n");
			return true;
		}
		else if(((extd_firewall_entries.attrib.u.v4.src_addr==0)) &&
		(extd_firewall_entries.attrib.u.v4.dst_addr!=0) &&
		(!src_range)  && (!dst_range) &&
		(extd_firewall_entries.attrib.src_port == 0) &&
		(extd_firewall_entries.attrib.dst_port == 0))
		{
			IPACMERR("Matched in DL wildcard entry\n");
			return true;
		}
	}
	return false;
}

void NatApp::HandleSWAllowEntries(void)
{
	int i, j, k,cnt;
	IPACM_swallow_conf_t entry;
	const nat_table_entry *del_entry;
	bool pdn_found=false;
	IPACMDBG("Entry\n");

	if(!IPACM_Iface::ipacmcfg->sw_filter_cfg)
	{
		IPACMERR("SW Config not updated/pdn index not updated!\n");
		return;
	}
	memset(&backup_sw_filter_cfg, 0, sizeof(IPACM_swallow_t));
	memcpy(&backup_sw_filter_cfg, &sw_filter_cfg, sizeof(IPACM_swallow_t));
	memset(&sw_filter_cfg, 0, sizeof(IPACM_swallow_t));
	memcpy(&sw_filter_cfg, IPACM_Iface::ipacmcfg->sw_filter_cfg, sizeof(IPACM_swallow_t));

	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		firewall_compare(&backup_sw_filter_cfg.pdns[i], &sw_filter_cfg.pdns[i]);
	}

	for(i = 0; i < backup_sw_filter_cfg.pdn_count; i++)
	{
		pdn_found = false;
		for(k = 0; k < sw_filter_cfg.pdn_count; k++)
		{
			if (strncmp(backup_sw_filter_cfg.pdns[i].net_dev, sw_filter_cfg.pdns[k].net_dev, IPA_IFACE_NAME_LEN) == 0)
			{
				pdn_found = true;
				break;
			}
		}

		if (!pdn_found)
		{
			IPACMDBG_H("PDN with netdev '%s' was removed from sw_filter_cfg. Restoring NAT entries.\n",
					backup_sw_filter_cfg.pdns[i].net_dev);
			for(j = 0; j < backup_sw_filter_cfg.pdns[i].num_extd_swallow_entries; j++) {
				restore_nat_for_sw_flt_entries(backup_sw_filter_cfg.pdns[i].extd_swallow_entries[j]);
			}
		}
	}

	for(i = 0; i < sw_filter_cfg.pdn_count; i++)
	{
		IPACMDBG("pdn_index_v4 %d\n", sw_filter_cfg.pdns[i].v4_up);
		/* PDN not up yet */
		if(sw_filter_cfg.pdns[i].v4_up != TRUE)
		{
			IPACMERR("sw_filter_cfg.pdns[i].v4_up \n");
			continue;
		}
		for(j = 0; j < sw_filter_cfg.pdns[i].num_extd_swallow_entries;j++)
		{
			entry = sw_filter_cfg.pdns[i];

			/* Check if entry is v4 */
			if(entry.extd_swallow_entries[j].ip_vsn != IP_V4)
			{
				IPACMERR("sw_filter_cfg.pdns[i].pdn is not v4 entry\n");
				continue;
			}
			else
			{
				IPACMERR("sw_filter_cfg.pdns[i].pdn is v4 entry\n");
			}

			for(cnt = 0; cnt < max_entries; cnt++)
			{
				/* Check if cache protocol matches with entry protocol */
				if(((entry.extd_swallow_entries[j].protocol) && (!(((entry.extd_swallow_entries[j].protocol &  IPPROTO_UDP) == cache[cnt].protocol) ||
				((entry.extd_swallow_entries[j].protocol &	IPPROTO_TCP) == cache[cnt].protocol)))) || (!cache[cnt].enabled) ||
				(sw_filter_cfg.pdns[i].public_ipv4_addr != cache[cnt].public_ip) || (cache[cnt].sw_allow))
				{
					continue;
				}

				if(firewall_tuple_match_with_nat(entry.extd_swallow_entries[j], &cache[cnt]))
				{
					log_nat(cache[cnt].protocol,cache[cnt].private_ip,cache[cnt].target_ip,cache[cnt].private_port,\
					cache[cnt].public_port,cache[cnt].target_port,cache[cnt].src_only,cache[cnt].dst_only,"SW Allow V4 Rule - Deleting Rule\n");
					cache[cnt].sw_allow = true;
					del_entry = &cache[cnt];
					DeleteEntry(del_entry);
				}
			}
		}
	}
	IPACMDBG("Exit\n");
}

/* Add new entry to the nat table on new connection */
int NatApp::AddEntry(const nat_table_entry *rule, bool isVlan)
{
	int cnt = 0;
	ipa_nat_ipv4_rule nat_rule;
#ifdef FEATURE_VLAN_MPDN
	bool cacheOnly = false;
	uint8_t pdn_index;
#endif

	IPACMDBG("%s() %d\n", __FUNCTION__, __LINE__);

	CHK_TBL_HDL();
	log_nat(rule->protocol,rule->private_ip,rule->target_ip,rule->private_port,\
	rule->public_port,rule->target_port,rule->src_only,rule->dst_only,"for addition\n");

	if(rule->private_ip == 0 ||
		 rule->target_ip == 0 ||
		 rule->private_port == 0  ||
		 rule->target_port == 0 ||
		 rule->protocol == 0)
	{
		IPACMERR("Invalid Connection, ignoring it\n");
		return 0;
	}
#ifdef FEATURE_VLAN_MPDN
#ifdef FEATURE_DUAL_BACKHAUL
	if(IPACM_Wan::second_backhaul_active && rule->public_ip == IPACM_Wan::second_backhaul_ipv4)
	{
		pdn_index = 0;
		IPACMDBG_H("second backhaul addentry\n");
	}
	else
	{
#endif
		if(ipa_nat_get_pdn_index(rule->public_ip, &pdn_index))
		{
			if(isVlan)
			{
				IPACMDBG_H("vlan iface doesn't have a valid pdn, \
					only moving to cache");
				iptodot("private ip", rule->private_ip);
				iptodot("target ip", rule->target_ip);
				iptodot("public ip", rule->public_ip);
				cacheOnly = true;
			}
			else
			{
				IPACMERR("couldn't acquire PDN index for public ip 0x%X\n",
					rule->public_ip);
				return IPACM_FAILURE;
			}
		}
#ifdef FEATURE_DUAL_BACKHAUL
	}
#endif
#endif

	if(!ChkForDup(rule))
	{
		for(; cnt < max_entries; cnt++)
		{
			if(cache[cnt].private_ip == 0 &&
				 cache[cnt].target_ip == 0 &&
				 cache[cnt].private_port == 0  &&
				 cache[cnt].target_port == 0 &&
				 cache[cnt].protocol == 0)
			{
				IPACMDBG_H("found free cache entry %d\n", cnt);
				break;
			}
		}

		if(max_entries == cnt)
		{
			IPACMERR("Error: Unable to add, reached maximum rules\n");
			return -1;
		}
		else
		{
			memset(&nat_rule, 0, sizeof(nat_rule));
			if(rule->protocol == IPPROTO_GRE)
			{
				nat_rule.private_ip = rule->private_ip;
				nat_rule.target_ip = rule->target_ip;
				nat_rule.protocol = rule->protocol;
			}
			else
			{
				nat_rule.private_ip = rule->private_ip;
				nat_rule.target_ip = rule->target_ip;
				nat_rule.target_port = rule->target_port;
				nat_rule.private_port = rule->private_port;
				nat_rule.public_port = rule->public_port;
				nat_rule.protocol = rule->protocol;
			}

		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_5) {
			nat_rule.uc_activation_index = rule->uc_activation_index;
			nat_rule.ucp = rule->ucp;
			nat_rule.s = rule->s;
			nat_rule.dst_only = rule->dst_only;
			nat_rule.src_only = rule->src_only;
		}
#ifdef FEATURE_VLAN_MPDN
			nat_rule.pdn_index = pdn_index;
#endif

			if(isPwrSaveIf(rule->private_ip) ||
				 isPwrSaveIf(rule->target_ip)
#ifdef FEATURE_VLAN_MPDN
				|| cacheOnly
#endif
				)
			{
#ifdef FEATURE_VLAN_MPDN
				if(cacheOnly)
				{
					IPACMDBG("only caching vlan rule\n");
				}
				else
#endif
				{
					IPACMDBG("Device is Power Save mode: Dont insert into nat table but cache\n");
				}
				cache[cnt].enabled = false;
				cache[cnt].rule_hdl = 0;
			}
			else if(ChkSWAllow(rule))
			{
				cache[cnt].sw_allow = true;
				cache[cnt].enabled = true;
			}
			else
			{
				if(ipa_nat_add_ipv4_rule(nat_table_hdl, &nat_rule, &cache[cnt].rule_hdl) < 0)
				{
					IPACMERR("unable to add the rule\n");
					return -1;
				}
				IPACMDBG_H("cache entry %d rule handle %d\n", cnt, cache[cnt].rule_hdl);
				cache[cnt].enabled = true;
			}

			cache[cnt].private_ip = rule->private_ip;
			cache[cnt].target_ip = rule->target_ip;
			cache[cnt].target_port = rule->target_port;
			cache[cnt].private_port = rule->private_port;
			cache[cnt].protocol = rule->protocol;
			cache[cnt].timestamp = 0;
			cache[cnt].public_port = rule->public_port;
			cache[cnt].dst_nat = rule->dst_nat;

		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_5) {
			cache[cnt].uc_activation_index = (uint16_t) rule->uc_activation_index;
			cache[cnt].ucp = rule->ucp;
			cache[cnt].s = rule->s;
			cache[cnt].dst_only = rule->dst_only;
			cache[cnt].src_only = rule->src_only;
		}
#ifdef FEATURE_VLAN_MPDN
			cache[cnt].pdn_index = pdn_index;
			cache[cnt].public_ip = rule->public_ip;
#endif
			cache[cnt].ip_pass_entry = rule->ip_pass_entry;
			curCnt++;
		}

	}
	else
	{
		IPACMERR("Duplicate rule. Ignore it\n");
		return -1;
	}

	if(cache[cnt].enabled == true)
	{
		IPACMDBG_H("Added rule(%d) successfully handle (%d)\n", cnt, cache[cnt].rule_hdl);
	}
  else
  {
    IPACMDBG_H("Cached rule(%d) successfully\n", cnt);
  }

	return 0;
}

void NatApp::UpdateCTUdpTs(nat_table_entry *rule, uint32_t new_ts)
{
	int ret;

	iptodot("Private IP:", rule->private_ip);
	iptodot("Target IP:",  rule->target_ip);
	IPACMDBG("Private Port: %d, Target Port: %d\n", rule->private_port, rule->target_port);

	if(!ct_hdl)
	{
		ct_hdl = nfct_open(CONNTRACK, 0);
		if(!ct_hdl)
		{
			PERROR("nfct_open");
			return;
		}
	}

	if(!ct)
	{
		ct = nfct_new();
		if(!ct)
		{
			PERROR("nfct_new");
			return;
		}
	}

	nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
	if(rule->protocol == IPPROTO_UDP)
	{
		nfct_set_attr_u8(ct, ATTR_L4PROTO, rule->protocol);
		nfct_set_attr_u32(ct, ATTR_TIMEOUT, udp_timeout);
	}
	else if(rule->protocol == IPPROTO_GRE)
	{
		nfct_set_attr_u8(ct, ATTR_L4PROTO, rule->protocol);
		nfct_set_attr_u32(ct, ATTR_TIMEOUT, gre_timeout);
	}
	else
	{
		nfct_set_attr_u8(ct, ATTR_L4PROTO, rule->protocol);
		nfct_set_attr_u32(ct, ATTR_TIMEOUT, tcp_timeout);
	}

	if(rule->dst_nat == false)
	{
		nfct_set_attr_u32(ct, ATTR_IPV4_SRC, htonl(rule->private_ip));
		nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(rule->private_port));

		nfct_set_attr_u32(ct, ATTR_IPV4_DST, htonl(rule->target_ip));
		nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(rule->target_port));

		IPACMDBG("dst nat is not set\n");
	}
	else
	{
		nfct_set_attr_u32(ct, ATTR_IPV4_SRC, htonl(rule->target_ip));
		nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(rule->target_port));
#ifdef FEATURE_VLAN_MPDN
		nfct_set_attr_u32(ct, ATTR_IPV4_DST, htonl(rule->public_ip));
#else
		nfct_set_attr_u32(ct, ATTR_IPV4_DST, htonl(pub_ip_addr));
#endif

		nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(rule->public_port));

		IPACMDBG("dst nat is set\n");
	}

	iptodot("Source IP:", nfct_get_attr_u32(ct, ATTR_IPV4_SRC));
	iptodot("Destination IP:",  nfct_get_attr_u32(ct, ATTR_IPV4_DST));
	IPACMDBG("Source Port: %d, Destination Port: %d\n",
					 nfct_get_attr_u16(ct, ATTR_PORT_SRC), nfct_get_attr_u16(ct, ATTR_PORT_DST));

	IPACMDBG("updating %d connection with time: %d\n",
					 rule->protocol, nfct_get_attr_u32(ct, ATTR_TIMEOUT));


	ret = nfct_query(ct_hdl, NFCT_Q_UPDATE, ct);
	if(ret == -1)
	{
		IPACMERR("unable to update time stamp");
		DeleteEntry(rule);
	}
	else
	{
		rule->timestamp = new_ts;
		IPACMDBG("Updated time stamp successfully\n");
	}

	return;
}

void NatApp::UpdateUDPTimeStamp()
{
	int cnt;
	uint32_t ts;
	bool read_to = false;
	bool keep_awake;

	keep_awake = ( max_entries && SRAM_IN_USE() && ipa_nat_is_sram_supported() );

	if ( keep_awake )
	{
		IPACMDBG("Voting clock on\n");

		if ( ipa_nat_vote_clock(IPA_APP_CLK_VOTE) != 0 )
		{
			IPACMERR("Voting clock on failed\n");
			return;
		}
	}

	for(cnt = 0; cnt < max_entries; cnt++)
	{
		ts = 0;
		if(cache[cnt].enabled == true &&
		   ((cache[cnt].private_ip != cache[cnt].public_ip) ||
		   		(cache[cnt].ip_pass_entry)))
		{
			IPACMDBG("\n");
			if(ipa_nat_query_timestamp(nat_table_hdl, cache[cnt].rule_hdl, &ts) < 0)
			{
				IPACMERR("unable to retrieve timeout for rule handle: %d\n", cache[cnt].rule_hdl);
				continue;
			}

			if(cache[cnt].timestamp == ts)
			{
				IPACMDBG("No Change in Time Stamp: cahce:%d, ipahw:%d\n",
								                  cache[cnt].timestamp, ts);
				continue;
			}

			if (read_to == false) {
				read_to = true;
				Read_TcpUdp_Timeout();
			}

			UpdateCTUdpTs(&cache[cnt], ts);
		} /* end of outer if */

	} /* end of for loop */

	if ( keep_awake )
	{
		IPACMDBG("Voting clock off\n");

		if ( ipa_nat_vote_clock(IPA_APP_CLK_DEVOTE) != 0 )
		{
			IPACMERR("Voting clock off failed\n");
		}
	}
}

bool NatApp::isAlgPort(uint8_t proto, uint16_t port)
{
	int cnt;
	for(cnt = 0; cnt < nALGPort; cnt++)
	{
		if(proto == pALGPorts[cnt].protocol &&
			 port == pALGPorts[cnt].port)
		{
			return true;
		}
	}

	return false;
}

bool NatApp::isPwrSaveIf(uint32_t ip_addr)
{
	int cnt;

	for(cnt = 0; cnt < IPA_MAX_NUM_WIFI_CLIENTS; cnt++)
	{
		if(0 != PwrSaveIfs[cnt] &&
			 ip_addr == PwrSaveIfs[cnt])
		{
			return true;
		}
	}

	return false;
}

int NatApp::UpdatePwrSaveIf(uint32_t client_lan_ip)
{
	int cnt;
	IPACMDBG_H("Received IP address: 0x%x\n", client_lan_ip);

	if(client_lan_ip == INVALID_IP_ADDR)
	{
		IPACMERR("Invalid ip address received\n");
		return -1;
	}

	/* check for duplicate events */
	for(cnt = 0; cnt < IPA_MAX_NUM_WIFI_CLIENTS; cnt++)
	{
		if(PwrSaveIfs[cnt] == client_lan_ip)
		{
			IPACMDBG("The client 0x%x is already in power save\n", client_lan_ip);
			return 0;
		}
	}

	for(cnt = 0; cnt < IPA_MAX_NUM_WIFI_CLIENTS; cnt++)
	{
		if(PwrSaveIfs[cnt] == 0)
		{
			PwrSaveIfs[cnt] = client_lan_ip;
			break;
		}
	}

	for(cnt = 0; cnt < max_entries; cnt++)
	{
		if(cache[cnt].private_ip == client_lan_ip &&
			 cache[cnt].enabled == true)
		{
			if(ipa_nat_del_ipv4_rule(nat_table_hdl, cache[cnt].rule_hdl) < 0)
			{
				IPACMERR("unable to delete the rule\n");
				continue;
			}

			cache[cnt].enabled = false;
			cache[cnt].rule_hdl = 0;
		}
	}

	return 0;
}

int NatApp::ResetPwrSaveIf(uint32_t client_lan_ip)
{
	int cnt;
	ipa_nat_ipv4_rule nat_rule;
	uint8_t pdn_index;

	IPACMDBG_H("Received ip address: 0x%x\n", client_lan_ip);

	if(client_lan_ip == INVALID_IP_ADDR)
	{
		IPACMERR("Invalid ip address received\n");
		return -1;
	}

	for(cnt = 0; cnt < IPA_MAX_NUM_WIFI_CLIENTS; cnt++)
	{
		if(PwrSaveIfs[cnt] == client_lan_ip)
		{
			PwrSaveIfs[cnt] = 0;
			break;
		}
	}

	for(cnt = 0; cnt < max_entries; cnt++)
	{
		IPACMDBG("cache (%d): enable %d, ip 0x%x\n", cnt, cache[cnt].enabled, cache[cnt].private_ip);

		if(cache[cnt].private_ip == client_lan_ip &&
			 cache[cnt].enabled == false)
		{
			memset(&nat_rule, 0 , sizeof(nat_rule));
			nat_rule.private_ip = cache[cnt].private_ip;
			nat_rule.target_ip = cache[cnt].target_ip;
			nat_rule.target_port = cache[cnt].target_port;
			nat_rule.private_port = cache[cnt].private_port;
			nat_rule.public_port = cache[cnt].public_port;
			nat_rule.protocol = cache[cnt].protocol;
			nat_rule.uc_activation_index = cache[cnt].uc_activation_index;
			nat_rule.ucp = cache[cnt].ucp;
			nat_rule.s = cache[cnt].s;
#ifdef FEATURE_VLAN_MPDN
			if(ipa_nat_get_pdn_index(cache[cnt].public_ip, &pdn_index))
			{
				IPACMERR("Unable to extract the pdn index for 0x%x Not deleting the cache entry\n",
								cache[cnt].public_ip);
				continue;
			}
			IPACMDBG("Extracted pdn index %d for public ip 0x%x\n", pdn_index, cache[cnt].public_ip);
			nat_rule.pdn_index = pdn_index;
#endif

			if(ipa_nat_add_ipv4_rule(nat_table_hdl, &nat_rule, &cache[cnt].rule_hdl) < 0)
			{
				IPACMERR("unable to add the rule delete from cache\n");
				memset(&cache[cnt], 0, sizeof(cache[cnt]));
				curCnt--;
				continue;
			}

			IPACMDBG_H("cache entry %d rule handle %d\n", cnt, cache[cnt].rule_hdl);
			cache[cnt].enabled = true;

			IPACMDBG("On power reset added below rule successfully\n");
			iptodot("Private IP", nat_rule.private_ip);
			iptodot("Target IP", nat_rule.target_ip);
			IPACMDBG("Private Port:%d \t Target Port: %d\n", nat_rule.private_port, nat_rule.target_port);
			IPACMDBG("Public Port:%d\n", nat_rule.public_port);
			IPACMDBG("protocol: %d\n", nat_rule.protocol);

		}
	}

	return 0;
}

void NatApp::AddTempEntry(const nat_table_entry *new_entry)
{
	int cnt;

	IPACMDBG("Received below Temp Nat entry\n");
	iptodot("Private IP", new_entry->private_ip);
	iptodot("Target IP", new_entry->target_ip);
	IPACMDBG("Private Port: %d\t Target Port: %d\t", new_entry->private_port, new_entry->target_port);
	IPACMDBG("protocol: %d\n", new_entry->protocol);

	if(ChkForDup(new_entry))
	{
		return;
	}

	for(cnt=0; cnt<MAX_TEMP_ENTRIES; cnt++)
	{
		if(temp[cnt].private_ip == new_entry->private_ip &&
			 temp[cnt].target_ip == new_entry->target_ip &&
			 temp[cnt].private_port ==  new_entry->private_port  &&
			 temp[cnt].target_port == new_entry->target_port &&
			 temp[cnt].protocol == new_entry->protocol)
		{
			IPACMDBG("Received duplicate Temp entry\n");
			return;
		}
	}

	for(cnt=0; cnt<MAX_TEMP_ENTRIES; cnt++)
	{
		if(temp[cnt].private_ip == 0 &&
			 temp[cnt].target_ip == 0)
		{
			memcpy(&temp[cnt], new_entry, sizeof(nat_table_entry));
			if(ChkSWAllow(new_entry))
			{
				temp[cnt].sw_allow = true;
			}
			IPACMDBG("Added Temp Entry\n");
			return;
		}
	}

	IPACMDBG("Unable to add temp entry, cache full\n");
	return;
}

void NatApp::DeleteTempEntry(const nat_table_entry *entry)
{
	int cnt;

	IPACMDBG("Received below nat entry\n");
	iptodot("Private IP", entry->private_ip);
	iptodot("Target IP", entry->target_ip);
	IPACMDBG("Private Port: %d\t Target Port: %d\n", entry->private_port, entry->target_port);
	IPACMDBG("protocol: %d\n", entry->protocol);

	for(cnt=0; cnt<MAX_TEMP_ENTRIES; cnt++)
	{
		if(temp[cnt].private_ip == entry->private_ip &&
			 temp[cnt].target_ip == entry->target_ip &&
			 temp[cnt].private_port ==  entry->private_port  &&
			 temp[cnt].target_port == entry->target_port &&
			 temp[cnt].protocol == entry->protocol)
		{
			memset(&temp[cnt], 0, sizeof(nat_table_entry));
			IPACMDBG("Delete Temp Entry\n");
			return;
		}
	}

	IPACMDBG("No Such Temp Entry exists\n");
	return;
}

#ifdef FEATURE_VLAN_MPDN
void NatApp::FlushAndCacheVlanTempEntries(uint32_t ip_addr, bool *entry_exists, uint32_t *public_ip)
{
	int cnt;
	int ret;

	IPACMDBG("searching temp entries for ");
	iptodot("IP Address: ", ip_addr);
	if(!entry_exists)
	{
		IPACMERR("got NULL for entry_exists\n");
		return;
	}

	if(!public_ip)
	{
		IPACMERR("got NULL for public_ip\n");
		return;
	}

	*entry_exists = false;
	*public_ip = 0;
	for(cnt = 0; cnt < MAX_TEMP_ENTRIES; cnt++)
	{
		if(temp[cnt].private_ip == ip_addr ||
			temp[cnt].target_ip == ip_addr)
		{
			ret = AddEntry(&temp[cnt], true);
			if(ret)
			{
				IPACMERR("unable to add temp entry: %d\n", ret);
				continue;
			}
			/* all entries should have the same public ip (each vlan mapped to single pdn) */
			*entry_exists = true;
			*public_ip = temp[cnt].public_ip;
		}
		memset(&temp[cnt], 0, sizeof(nat_table_entry));
	}

	return;
}
#endif

void NatApp::FlushTempEntries(uint32_t ip_addr, bool isAdd,
		bool isDummy)
{
	int cnt;
	int ret;

	IPACMDBG_H("Received below with isAdd:%d ", isAdd);
	iptodot("IP Address: ", ip_addr);

	for(cnt=0; cnt<MAX_TEMP_ENTRIES; cnt++)
	{
		if(temp[cnt].private_ip == ip_addr ||
			 temp[cnt].target_ip == ip_addr)
		{
			if(isAdd)
			{
#ifdef FEATURE_VLAN_MPDN
				/*
				 * We dont need pub_ip_addr check in MPDN support.
				 * But, we shouldn't flush the entries
				 * if pub_ip_addr doesn't match any of our pdns.
				 * And this we are taken care in AddEntry
				 * using ipa_nat_get_pdn_index
				 */
#else
				if(temp[cnt].public_ip == pub_ip_addr)
#endif
				{
					if (isDummy) {
						/* To avoild DL expections for non IPA path */
						temp[cnt].private_ip = temp[cnt].public_ip;
						temp[cnt].private_port = temp[cnt].public_port;
						IPACMDBG("Flushing dummy temp rule");
						iptodot("Private IP", temp[cnt].private_ip);
					}

					ret = AddEntry(&temp[cnt]);
					if(ret)
					{
						IPACMERR("unable to add temp entry: %d\n", ret);
						continue;
					}
				}
			}
			memset(&temp[cnt], 0, sizeof(nat_table_entry));
		}
	}

	return;
}

void NatApp::DeleteTempEntry_port(uint16_t port)
{
	int cnt;

	IPACMDBG_H("Received port:%d\n", port);

	for(cnt=0; cnt<MAX_TEMP_ENTRIES; cnt++)
	{
		if(temp[cnt].private_port == port ||
			 temp[cnt].target_port == port)
		{
			IPACMDBG_H("Clean nat temp entry %d\n", cnt);
			memset(&temp[cnt], 0, sizeof(nat_table_entry));
		}
	}

	return;
}

int NatApp::DelEntriesOnClntDiscon(uint32_t ip_addr)
{
	int cnt, tmp = 0;
	IPACMDBG_H("Received IP address: 0x%x\n", ip_addr);

	if(ip_addr == INVALID_IP_ADDR)
	{
		IPACMERR("Invalid ip address received\n");
		return -1;
	}

	for(cnt = 0; cnt < IPA_MAX_NUM_WIFI_CLIENTS; cnt++)
	{
		if(PwrSaveIfs[cnt] == ip_addr)
		{
			PwrSaveIfs[cnt] = 0;
			IPACMDBG("Remove %d power save entry\n", cnt);
			break;
		}
	}

	for(cnt = 0; cnt < max_entries; cnt++)
	{
		if(cache[cnt].private_ip == ip_addr)
		{
			if(cache[cnt].enabled == true)
			{
				if(ipa_nat_del_ipv4_rule(nat_table_hdl, cache[cnt].rule_hdl) < 0)
				{
					IPACMERR("unable to delete the rule\n");
					continue;
				}
				else
				{
					IPACMDBG("won't delete the rule\n");
					cache[cnt].enabled = false;
					tmp++;
				}
			}
			IPACMDBG("won't delete the rule for entry %d, enabled %d\n",cnt, cache[cnt].enabled);
		}
	}

	IPACMDBG("Deleted (but cached) %d entries\n", tmp);
	return 0;
}

/* Delete the entry from Nat table for port */
int NatApp::DeleteEntry_port(uint16_t port)
{
	int cnt = 0;
	IPACMDBG_H("Received port: %d\n", port);

	for(; cnt < max_entries; cnt++)
	{
		if(cache[cnt].private_port ==  port ||
			 cache[cnt].target_port == port)
		{
			if(cache[cnt].enabled == true)
			{
				log_nat(cache[cnt].protocol,cache[cnt].private_ip,cache[cnt].target_ip,cache[cnt].private_port,\
					cache[cnt].public_port,cache[cnt].target_port,cache[cnt].src_only,cache[cnt].dst_only,"for deletion\n");
				if(ipa_nat_del_ipv4_rule(nat_table_hdl, cache[cnt].rule_hdl) < 0)
				{
					IPACMERR("%s() %d deletion failed\n", __FUNCTION__, __LINE__);
				}
				else
				{
					IPACMDBG_H("Deleted Nat entry(%d) Successfully\n", cnt);
				}
			}
			else
			{
				IPACMDBG_H("Deleted Nat entry(%d) only from cache\n", cnt);
			}

			memset(&cache[cnt], 0, sizeof(cache[cnt]));
			curCnt--;
			break;
		}
	}

	return 0;
}

int NatApp::DelDummyNatEntries(uint32_t ip_addr)
{
	int cnt, tmp = 0;
	IPACMDBG_H("Received IP address: 0x%x\n", ip_addr);

	if(ip_addr == INVALID_IP_ADDR)
	{
		IPACMERR("Invalid ip address received\n");
		return -1;
	}

	for(cnt = 0; cnt < max_entries; cnt++)
	{
		if(cache[cnt].public_ip == ip_addr)
		{
			if((cache[cnt].enabled == true) && (cache[cnt].dummy_nat == true))
			{
				if(ipa_nat_del_ipv4_rule(nat_table_hdl, cache[cnt].rule_hdl) < 0)
				{
					IPACMERR("unable to delete the rule\n");
					continue;
				}
				else
				{
					IPACMDBG("delete the rule\n");
					memset(&cache[cnt], 0, sizeof(cache[cnt]));
					curCnt--;
					tmp++;
				}
			}
			IPACMDBG("won't delete the rule for entry %d, enabled %d, dummy %d\n",cnt, cache[cnt].enabled, cache[cnt].dummy_nat);
		}
	}

	IPACMDBG("Deleted %d dummy nat entries for wan ip 0x%x\n", tmp, ip_addr);
	return 0;
}


int NatApp::DelEntriesOnSTAClntDiscon(uint32_t ip_addr)
{
	int cnt, tmp = curCnt;
	IPACMDBG_H("Received IP address: 0x%x\n", ip_addr);

	if(ip_addr == INVALID_IP_ADDR)
	{
		IPACMERR("Invalid ip address received\n");
		return -1;
	}


	for(cnt = 0; cnt < max_entries; cnt++)
	{
		if(cache[cnt].target_ip == ip_addr)
		{
			if(cache[cnt].enabled == true)
			{
				if(ipa_nat_del_ipv4_rule(nat_table_hdl, cache[cnt].rule_hdl) < 0)
				{
					IPACMERR("unable to delete the rule\n");
					continue;
				}
			}

			memset(&cache[cnt], 0, sizeof(cache[cnt]));
			curCnt--;
		}
	}

	IPACMDBG("Deleted %d entries\n", (tmp - curCnt));
	return 0;
}

void NatApp::CacheEntry(const nat_table_entry *rule)
{
	int cnt;

	if(rule->private_ip == 0 ||
		 rule->target_ip == 0 ||
		 rule->private_port == 0  ||
		 rule->target_port == 0 ||
		 rule->protocol == 0)
	{
		IPACMERR("Invalid Connection, ignoring it\n");
		return;
	}

	if(!ChkForDup(rule))
	{
		for(cnt=0; cnt < max_entries; cnt++)
		{
			if(cache[cnt].private_ip == 0 &&
				 cache[cnt].target_ip == 0 &&
				 cache[cnt].private_port == 0  &&
				 cache[cnt].target_port == 0 &&
				 cache[cnt].protocol == 0)
			{
				break;
			}
		}

		if(max_entries == cnt)
		{
			IPACMERR("Error: Unable to add, reached maximum rules\n");
			return;
		}
		else
		{
			cache[cnt].enabled = false;
			cache[cnt].rule_hdl = 0;
			cache[cnt].private_ip = rule->private_ip;
			cache[cnt].target_ip = rule->target_ip;
			cache[cnt].target_port = rule->target_port;
			cache[cnt].private_port = rule->private_port;
			cache[cnt].protocol = rule->protocol;
			cache[cnt].timestamp = 0;
			cache[cnt].public_port = rule->public_port;
			cache[cnt].public_ip = rule->public_ip;
			cache[cnt].uc_activation_index = rule->uc_activation_index;
			cache[cnt].ucp = rule->ucp;
			cache[cnt].s = rule->s;
#ifdef FEATURE_VLAN_MPDN
			cache[cnt].pdn_index = rule->pdn_index;
#endif
			cache[cnt].dst_nat = rule->dst_nat;
			cache[cnt].ip_pass_entry = rule->ip_pass_entry;
			curCnt++;
		}

	}
	else
	{
		IPACMERR("Duplicate rule. Ignore it\n");
		return;
	}

	IPACMDBG("Cached rule(%d) successfully\n", cnt);
	return;
}

void NatApp::Read_TcpUdp_Timeout(void) {
#ifdef FEATURE_IPA_ANDROID
	tcp_timeout = 432000;
	udp_timeout = 180;
	gre_timeout = 180;
	IPACMDBG_H("udp timeout value: %d\n", udp_timeout);
	IPACMDBG_H("tcp timeout value: %d\n", tcp_timeout);
	IPACMDBG_H("gre timeout value: %d\n", gre_timeout);
#else
	tcp_timeout = 3600;
	udp_timeout = 60;
	gre_timeout = 30;
	IPACMDBG_H("udp timeout value: %d\n", udp_timeout);
	IPACMDBG_H("tcp timeout value: %d\n", tcp_timeout);
	IPACMDBG_H("gre timeout value: %d\n", gre_timeout);
	FILE *udp_fd = NULL, *tcp_fd = NULL, *gre_fd=NULL;
	char kernel_ver[KERNEL_VERSION_LENGTH];

	if (kernel_ver_updated == false) {

		get_kernel_version(kernel_ver);

		IPACMDBG_H("Kernel Version %s\n", kernel_ver);

		is_kernel_ver_upgraded = is_kernel_version_newer_than(kernel_ver,
		KERNEL_VERSION_4_9);

		kernel_ver_updated = true;

		IPACMDBG_H("Kernel Version %s compare to %s\n",
			is_kernel_ver_upgraded?"upgraded":"non upgraded", KERNEL_VERSION_4_9);
	}

	if (is_kernel_ver_upgraded) {
		/* Read UDP timeout value */
		udp_fd = fopen(IPACM_UDP_FULL_FILE_NAME_NEW, "r");
		if (udp_fd == NULL) {
			IPACMERR("unable to open %s\n", IPACM_UDP_FULL_FILE_NAME_NEW);
			goto fail;
		}
	} else {
		/* Read UDP timeout value */
		udp_fd = fopen(IPACM_UDP_FULL_FILE_NAME, "r");
		if (udp_fd == NULL) {
			IPACMERR("unable to open %s\n", IPACM_UDP_FULL_FILE_NAME);
			goto fail;
		}
	}

	if (fscanf(udp_fd, "%d", &udp_timeout) != 1) {
		IPACMERR("Error reading udp timeout\n");
	}
	IPACMDBG_H("udp timeout value: %d\n", udp_timeout);

	if (is_kernel_ver_upgraded) {
		/* Read TCP timeout value */
		tcp_fd = fopen(IPACM_TCP_FULL_FILE_NAME_NEW, "r");
		if (tcp_fd == NULL) {
			IPACMERR("unable to open %s\n", IPACM_TCP_FULL_FILE_NAME_NEW);
			goto fail;
		}
	} else {
		/* Read TCP timeout value */
		tcp_fd = fopen(IPACM_TCP_FULL_FILE_NAME, "r");
		if (tcp_fd == NULL) {
			IPACMERR("unable to open %s\n", IPACM_TCP_FULL_FILE_NAME);
			goto fail;
		}
	}

	if (fscanf(tcp_fd, "%d", &tcp_timeout) != 1) {
		IPACMERR("Error reading tcp timeout\n");
	}
	IPACMDBG_H("tcp timeout value: %d\n", tcp_timeout);


	if (is_kernel_ver_upgraded) {
		/* Read UDP timeout value */
		gre_fd = fopen(IPACM_GRE_FULL_FILE_NAME_NEW, "r");
		if (gre_fd == NULL) {
			IPACMERR("unable to open %s\n", IPACM_GRE_FULL_FILE_NAME_NEW);
			goto fail;
		}
	} else {
		/* Read UDP timeout value */
		gre_fd = fopen(IPACM_GRE_FULL_FILE_NAME, "r");
		if (gre_fd == NULL) {
			IPACMERR("unable to open %s\n", IPACM_GRE_FULL_FILE_NAME);
			goto fail;
		}
	}
	if (fscanf(gre_fd, "%d", &gre_timeout) != 1) {
		IPACMERR("Error reading gre timeout\n");
	}
	IPACMDBG_H("gre timeout value: %d\n", gre_timeout);

fail:
	if (udp_fd) {
		fclose(udp_fd);
	}
	if (tcp_fd) {
		fclose(tcp_fd);
	}
	if (gre_fd) {
		fclose(gre_fd);
	}
#endif //FEATURE_IPA_ANDROID
	return;
}

IpAddress::IpAddress(ipa_ip_type type) : m_type(type)
{
	IPACMDBG_H("\n");
}

IpAddress::~IpAddress()
{
	IPACMDBG_H("\n");
}

Ipv6IpAddress::Ipv6IpAddress() : IpAddress(IPA_IP_v6), m_msb(0), m_lsb(0)
{
	IPACMDBG_H("\n");
}

Ipv6IpAddress::~Ipv6IpAddress()
{
	DebugDump("destroying ");
}

Ipv6IpAddress::Ipv6IpAddress(const uint32_t* addr, bool inputNetworkEndianness) :
	IpAddress(IPA_IP_v6),
	m_msb(Convert2x32to64(addr, inputNetworkEndianness)),
	m_lsb(Convert2x32to64(addr + 2, inputNetworkEndianness))
{
	IPACMDBG_H("\n");
}

bool Ipv6IpAddress::Compare(const IpAddress& other) const
{
	if (other.GetType() != IPA_IP_v6)
	{
		IPACMERR("Wrong IP type\n");
		return false;
	}

	const Ipv6IpAddress& ip = static_cast<const Ipv6IpAddress&>(other);
	bool ret = m_lsb == ip.m_lsb && m_msb == ip.m_msb;
	return ret;
}

bool Ipv6IpAddress::IsSameSubnet(const IpAddress& other) const
{
	IPACMDBG_H("\n");
	if (other.GetType() != IPA_IP_v6)
	{
		IPACMERR("Wrong IP type\n");
		return false;
	}

	const Ipv6IpAddress& ip = static_cast<const Ipv6IpAddress&>(other);
	bool ret = m_msb == ip.m_msb;
	IPACMDBG_H("return\n");
	return ret;
}

void Ipv6IpAddress::Copy(const IpAddress& other)
{
	IPACMDBG_H("\n");
	if (other.GetType() != IPA_IP_v6)
	{
		IPACMERR("Wrong IP type\n");
		return;
	}

	const Ipv6IpAddress& ip = static_cast<const Ipv6IpAddress&>(other);
	m_msb = ip.m_msb;
	m_lsb = ip.m_lsb;
	IPACMDBG_H("return\n");
}

void Ipv6IpAddress::Clear()
{
	IPACMDBG_H("\n");
	m_msb = 0;
	m_lsb = 0;
	IPACMDBG_H("return\n");
}

bool Ipv6IpAddress::Valid() const
{
	return m_lsb != 0 || m_msb != 0;
}

void Ipv6IpAddress::DebugDump(const char* msg_prefix) const
{
	IPACMDBG_H("%s IPv6 address msb:0x%llX lsb:%0xllX\n", msg_prefix, m_msb, m_lsb);
}

bool Ipv6IpAddress::IsSameSubnet(uint32_t* prefix) const
{
	IPACMDBG_H("\n");
	return m_msb == Convert2x32to64(prefix, false);
}

void Ipv6IpAddress::CreateFromArray(const uint32_t* addr, bool inputNetworkEndianness)
{
	IPACMDBG_H("\n");
	m_msb = Convert2x32to64(addr, inputNetworkEndianness);
	m_lsb = Convert2x32to64(addr + 2, inputNetworkEndianness);
	DebugDump("Ipv6IpAddress::CreateFromArray received");
}

void Ipv6IpAddress::ToArray(uint32_t* addr, bool outputNetworkEndianness) const
{
	IPACMDBG_H("\n");
	Convert64to2x32(m_msb, addr, outputNetworkEndianness);
	Convert64to2x32(m_lsb, addr + 2, outputNetworkEndianness);
	IPACMDBG_H("return\n");
}

uint64_t Ipv6IpAddress::Convert2x32to64(const uint32_t* pair32, bool inputNetworkEndianness)
{
	IPACMDBG_H("\n");
	uint32_t msb = pair32[0], lsb = pair32[1];
	if (inputNetworkEndianness)
	{
		msb = ntohl(msb);
		lsb = ntohl(lsb);
	}
	IPACMDBG_H("return\n");
	return static_cast<uint64_t>(msb) << 32 | lsb;
}
#ifdef FEATURE_IPV6_NAT
uint64_t Ipv6IpAddress::Get64EndianSwaped(uint64_t Addr) const
{
	return (((uint64_t)htonl((Addr)& 0xFFFFFFFF) << 32) | htonl((Addr) >> 32));
}
#endif
void Ipv6IpAddress::Convert64to2x32(uint64_t in, uint32_t* pair32, bool outputNetworkEndianness)
{
	IPACMDBG_H("\n");
	pair32[0] = in >> 32;
	pair32[1] = static_cast<uint32_t>(in);
	if (outputNetworkEndianness)
	{
		pair32[0] = htonl(pair32[0]);
		pair32[1] = htonl(pair32[1]);
	}
	IPACMDBG_H("return\n");
}

bool Ipv6IpAddress::IsGlobalAddr() const
{
	uint64_t ipv6_link_local_prefix, ipv6_link_local_prefix_mask, ipv6_ula_prefix, ipv6_ula_mask;
	ipv6_link_local_prefix = 0xFE80000000000000;
	ipv6_link_local_prefix_mask = 0xFFC0000000000000;
	ipv6_ula_prefix = 0xFD00000000000000;
	ipv6_ula_mask = 0xFF00000000000000;

	if((m_msb & ipv6_link_local_prefix_mask) == (ipv6_link_local_prefix & ipv6_link_local_prefix_mask))
	{
		IPACMDBG_H("This IPv6 address is link local.\n");
		return false;
	}

	if((m_msb & ipv6_ula_mask) == (ipv6_ula_prefix & ipv6_ula_mask))
	{
		IPACMDBG_H("This IPv6 address is unique local.\n");
		return false;
	}

	return true;
}

NatEntryBase::NatEntryBase(ipa_ip_type type) :
	m_type(type),
	m_timestamp(0),
	m_direction(DirectionUnknown),
	m_ruleHandle(0),
	m_protocol(0),
	m_enabled(false),
	m_isDummy(false),
	m_uc_activation_index(0),
	m_ucp(0),
	m_s(0)
{
	IPACMDBG_H("%d \n", type);
}

NatEntryBase::~NatEntryBase()
{
	IPACMDBG_H("\n");
}

bool NatEntryBase::Compare(const NatEntryBase& other) const
{
	return m_protocol == other.m_protocol;
}

void NatEntryBase::Copy(const NatEntryBase& other)
{
	IPACMDBG_H("NatEntryBase\n");
	m_timestamp = other.m_timestamp;
	m_direction = other.m_direction;
	m_ruleHandle = other.m_ruleHandle;
	m_protocol = other.m_protocol;
	m_enabled = other.m_enabled;
	m_isDummy = other.m_isDummy;
	m_uc_activation_index = other.m_uc_activation_index;
	m_ucp = other.m_ucp;
	m_s = other.m_s;
	IPACMDBG_H("copied uc activation data: idx %d, ucp:%d s: %d", m_uc_activation_index, m_ucp, m_s);
	IPACMDBG_H("return\n");
}

void NatEntryBase::Clear()
{
	IPACMDBG_H("\n");
	m_timestamp = 0;
	m_direction = DirectionUnknown;
	m_ruleHandle = 0;
	m_protocol = 0;
	m_enabled = false;
	m_isDummy = false;
	m_uc_activation_index = 0;
	m_ucp = false;
	m_s = false;
	IPACMDBG_H("return\n");
}

void NatEntryBase::DebugDump(const char* msg_prefix) const
{
	IPACMDBG_H("%s protocol %d direction %s\n", msg_prefix, m_protocol, DirectionToStr(m_direction));
}

/*
 * This function recognize entry direction based on client IP address - client can be private client or STA client.
 * Mostly required for IPv6CT, because contract library cannot determine direction for IPv6 connections.
 */
bool NatEntryBase::UpdateDirection(const IpAddress& clientIp, bool isStaClientIp)
{
	/* Direction of IPV4 connections is generally known before the function is called. */
	if (m_direction != DirectionUnknown)
	{
		IPACMDBG_H("The direction already specified. Nothing to do\n");
		return true;
	}

	IPACMDBG_H("The received client is%s an STA client\n", (isStaClientIp) ? "" : " not");
	clientIp.DebugDump("The received client\n");
	DebugDump("Convert direction of the following entry according to the received client IP\n");

	if (GetClientIp() == clientIp)
	{
		if (isStaClientIp)
		{
			m_direction = DirectionInbound;
			InvertDirection();
		}
		else
		{
			m_direction = DirectionOutbound;
		}
	}
	else if (GetTargetIp() == clientIp)
	{
		if (isStaClientIp)
		{
			m_direction = DirectionOutbound;
		}
		else
		{
			m_direction = DirectionInbound;
			InvertDirection();
		}
	}
	else
	{
		return false;
	}

	IPACMDBG_H("return\n");
	return true;
}

const char* NatEntryBase::DirectionToStr(NatEntryBase::Direction direction)
{
	switch (direction)
	{
	case DirectionUnknown:
		return "unknown";
	case DirectionOutbound:
		return "outbound";
	case DirectionInbound:
		return "inbound";
	default:
		IPACMERR("Unsupported direction %d\n", direction);
	}
	return "unknown";
}

Ipv6ctEntry::Ipv6ctEntry() : NatEntryBase(IPA_IP_v6), m_dstPort(0), m_srcPort(0)
{
	IPACMDBG_H("\n");
}

bool Ipv6ctEntry::Compare(const NatEntryBase& other) const
{
	IPACMDBG_H("\n");
	if (other.m_type != IPA_IP_v6)
	{
		IPACMERR("Wrong IP type\n");
		return false;
	}

	const Ipv6ctEntry& entry = static_cast<const Ipv6ctEntry&>(other);
	return NatEntryBase::Compare(other) &&
		m_srcAddr == entry.m_srcAddr &&
		m_dstAddr == entry.m_dstAddr &&
		m_dstPort == entry.m_dstPort &&
		m_srcPort == entry.m_srcPort;
}

void Ipv6ctEntry::Copy(const NatEntryBase& other)
{
	IPACMDBG_H("Ipv6ctEntry\n");
	if (other.m_type != IPA_IP_v6)
	{
		IPACMERR("Wrong IP type\n");
		return;
	}

	NatEntryBase::Copy(other);

	const Ipv6ctEntry& entry = static_cast<const Ipv6ctEntry&>(other);
	m_srcAddr = entry.m_srcAddr;
	m_dstAddr = entry.m_dstAddr;
	m_dstPort = entry.m_dstPort;
	m_srcPort = entry.m_srcPort;
	m_isDummy = entry.m_isDummy;
	IPACMDBG_H("return\n");
}

void Ipv6ctEntry::Clear()
{
	IPACMDBG_H("\n");
	NatEntryBase::Clear();

	m_srcAddr.Clear();
	m_dstAddr.Clear();
	m_dstPort = 0;
	m_srcPort = 0;
	IPACMDBG_H("return\n");
}

bool Ipv6ctEntry::Valid() const
{
	//Only if the protocol is GRE, the ports are allowed to be zero
	return ((m_dstPort && m_srcPort) || IPPROTO_GRE == m_protocol)  && m_srcAddr.Valid() && m_dstAddr.Valid();
}

void Ipv6ctEntry::DebugDump(const char* msg_prefix) const
{
	NatEntryBase::DebugDump(msg_prefix);
	m_srcAddr.DebugDump("Source");
	m_dstAddr.DebugDump("Destination");
	IPACMDBG_H("Source port %d\n", m_srcPort);
	IPACMDBG_H("Destination port %d\n", m_dstPort);
}

void Ipv6ctEntry::InvertDirection()
{
	std::swap(m_srcAddr, m_dstAddr);
	std::swap(m_srcPort, m_dstPort);
}

const IpAddress& Ipv6ctEntry::GetClientIp() const
{
	return m_srcAddr;
}

const IpAddress& Ipv6ctEntry::GetTargetIp() const
{
	return m_dstAddr;
}

const uint16_t& Ipv6ctEntry::GetSrcPort() const
{
	return m_srcPort;
}

const uint16_t& Ipv6ctEntry::GetDstPort() const
{
	return m_dstPort;
}
#ifdef FEATURE_IPV6_NAT
Ipv6NatEntry:: Ipv6NatEntry() : Ipv6ctEntry(), m_publicPort(0)
{
	IPACMDBG_H("\n");
}

bool Ipv6NatEntry::Compare(const NatEntryBase& other) const
{
	if(other.m_type != IPA_IP_v6)
	{
		IPACMERR("Wrong IP type\n");
		return false;
	}

	const Ipv6NatEntry& entry = static_cast<const Ipv6NatEntry&>(other);
	return (NatEntryBase::Compare(other) &&
		m_srcAddr == entry.m_srcAddr &&
		m_public_address == entry.m_public_address &&
		m_dstAddr == entry.m_dstAddr &&
		m_dstPort == entry.m_dstPort &&
		m_srcPort == entry.m_srcPort &&
		m_publicPort == entry.m_publicPort);
}

void Ipv6NatEntry::Copy(const NatEntryBase& other)
{
	IPACMDBG_H("Ipv6NatEntry\n");
	if(other.m_type != IPA_IP_v6)
	{
		IPACMERR("Wrong IP type\n");
		return;
	}

	Ipv6ctEntry::Copy(other);

	const Ipv6NatEntry& entry = static_cast<const Ipv6NatEntry&>(other);
	m_public_address = entry.m_public_address;
	m_publicPort = entry.m_publicPort;
	IPACMDBG_H("return\n");
}

bool Ipv6NatEntry::Valid() const
{
	return m_dstPort && m_srcPort && m_publicPort &&
		m_srcAddr.Valid() && m_public_address.Valid() &&
		m_dstAddr.Valid();
}

void Ipv6NatEntry::Clear()
{
	IPACMDBG_H("\n");
	Ipv6ctEntry::Clear();
	m_public_address.Clear();
	m_publicPort = 0;
	IPACMDBG_H("return\n");
}

void Ipv6NatEntry::DebugDump(const char* msg_prefix) const
{
	NatEntryBase::DebugDump(msg_prefix);
	m_srcAddr.DebugDump("private");
	m_public_address.DebugDump("public");
	m_dstAddr.DebugDump("Destination");
	IPACMDBG_H("Private port %d\n", m_srcPort);
	IPACMDBG_H("Public port %d\n", m_publicPort);
	IPACMDBG_H("Destination port %d\n", m_dstPort);
}

void Ipv6NatEntry::InvertDirection()
{
	IPACMERR("we shouldn't get here for IPv6 NAT\n");
}

const IpAddress& Ipv6NatEntry::GetPublicIp() const
{
	return m_public_address;
}

const uint16_t& Ipv6NatEntry::GetPublicPort() const
{
	return m_publicPort;
}
#endif
CollectionBase::CollectionBase(int max_entries) : m_maxEntries(max_entries)
{
	IPACMDBG_H("max_entries %d\n", max_entries);
}

CollectionBase::~CollectionBase()
{
	IPACMDBG_H("\n");
}

uint32_t ConntrackTimestampUtil::tcp_timeout = 432000;
uint32_t ConntrackTimestampUtil::udp_timeout = 180;
uint32_t ConntrackTimestampUtil::gre_timeout = 180;

struct nf_conntrack* ConntrackTimestampUtil::ct = NULL;
struct nfct_handle* ConntrackTimestampUtil::ct_hdl = NULL;

ConntrackTimestampUtil::ConntrackTimestampUtil()
{
	IPACMDBG_H("\n");
}

ConntrackTimestampUtil::~ConntrackTimestampUtil()
{
	IPACMDBG_H("\n");
}

void ConntrackTimestampUtil::Init()
{
	IPACMDBG_H("\n");

	if (ct_hdl == NULL)
	{
		ct_hdl = nfct_open(CONNTRACK, 0);
		if (ct_hdl == NULL)
		{
			PERROR("nfct_open");
			return;
		}
	}

	if (ct == NULL)
	{
		ct = nfct_new();
		if (ct == NULL)
		{
			PERROR("nfct_new");
			return;
		}
	}

	IPACMDBG_H("return\n");
}

#ifndef FEATURE_IPA_ANDROID
/*
 * ConntrackTimestampUtil::ReadTcpUdpTimeout() is equivalent to NatApp::Read_TcpUdp_Timeout()
 *
 * NOTE: Kernel version check is omitted from the function, because the function is called only if IPv6CT is enabled.
 */
void ConntrackTimestampUtil::ReadTcpUdpTimeout()
{
	IPACMDBG_H("\n");

	FILE *udp_fd = NULL, *tcp_fd = NULL, *gre_fd = NULL;

	/* Read UDP timeout value */
	udp_fd = fopen(IPACM_UDP_FULL_FILE_NAME_NEW, "r");
	if (udp_fd == NULL)
	{
		IPACMERR("unable to open %s\n", IPACM_UDP_FULL_FILE_NAME_NEW);
		goto bail;
	}

	if (fscanf(udp_fd, "%d", &udp_timeout) != 1)
	{
		IPACMERR("Error reading udp timeout\n");
	}
	IPACMDBG_H("udp timeout value: %d\n", udp_timeout);

	/* Read TCP timeout value */
	tcp_fd = fopen(IPACM_TCP_FULL_FILE_NAME_NEW, "r");
	if (tcp_fd == NULL)
	{
		IPACMERR("unable to open %s\n", IPACM_TCP_FULL_FILE_NAME_NEW);
		goto bail;
	}

	if (fscanf(tcp_fd, "%d", &tcp_timeout) != 1)
	{
		IPACMERR("Error reading tcp timeout\n");
	}
	IPACMDBG_H("tcp timeout value: %d\n", tcp_timeout);


	/* Read UDP timeout value */
	gre_fd = fopen(IPACM_GRE_FULL_FILE_NAME_NEW, "r");
	if (gre_fd == NULL)
	{
		IPACMERR("unable to open %s\n", IPACM_GRE_FULL_FILE_NAME_NEW);
		goto bail;
	}

	if (fscanf(gre_fd, "%d", &gre_timeout) != 1)
	{
		IPACMERR("Error reading udp timeout\n");
	}
	IPACMDBG_H("udp timeout value: %d\n", gre_timeout);

bail:
	if (udp_fd != NULL)
	{
		fclose(udp_fd);
	}
	if (tcp_fd != NULL)
	{
		fclose(tcp_fd);
	}
	if (gre_fd != NULL)
	{
		fclose(gre_fd);
	}

	IPACMDBG_H("return\n");
}
#endif

int ConntrackTimestampUtil::UpdateConntrackTimeStamp(const NatEntryBase& entry)
{
	IPACMDBG_H("\n");

	entry.DebugDump("Going to update timestamp for following entry");
	uint32_t timeout=0;
	if(entry.m_protocol == IPPROTO_UDP)
		timeout= udp_timeout;
	else if(entry.m_protocol == IPPROTO_GRE)
		timeout = gre_timeout;
	else
		timeout = tcp_timeout;
	
	nfct_set_attr_u8(ct, ATTR_L4PROTO, entry.m_protocol);
	nfct_set_attr_u32(ct, ATTR_TIMEOUT,timeout);

	SetConnectionDetails(entry);

	int ret = nfct_query(ct_hdl, NFCT_Q_UPDATE, ct);

	IPACMDBG_H("return value %d\n", ret);
	return ret;
}

void Ipv6ctConntrackTimestampUtil::SetConnectionDetails(const NatEntryBase& entry)
{
	IPACMDBG_H("\n");
	if (entry.m_type != IPA_IP_v6)
	{
		IPACMERR("Wrong IP type\n");
		return;
	}

	uint16_t src_port, dst_port;
	struct nfct_attr_grp_ipv6 attr_grp;

	switch (entry.m_direction)
	{
	case NatEntryBase::DirectionOutbound:
		static_cast<const Ipv6IpAddress&>(entry.GetClientIp()).ToArray(attr_grp.src, true);
		src_port = entry.GetSrcPort();

		static_cast<const Ipv6IpAddress&>(entry.GetTargetIp()).ToArray(attr_grp.dst, true);
		dst_port = entry.GetDstPort();
		break;
	case NatEntryBase::DirectionInbound:
#ifdef FEATURE_IPV6_NAT
		if(entry.GetClientIp() != entry.GetPublicIp())
		{
			IPACMDBG_H("IPv6 NAT case, use public addresses\n");
			static_cast<const Ipv6IpAddress&>(entry.GetPublicIp()).ToArray(attr_grp.dst, true);
			dst_port = entry.GetPublicPort();
		}
		else
#endif
		{
			static_cast<const Ipv6IpAddress&>(entry.GetClientIp()).ToArray(attr_grp.dst, true);
			dst_port = entry.GetSrcPort();
		}

		static_cast<const Ipv6IpAddress&>(entry.GetTargetIp()).ToArray(attr_grp.src, true);
		src_port = entry.GetDstPort();
		break;
	default:
		IPACMERR("Unknown direction in an offloaded connection\n");
		entry.DebugDump("Unknown direction in following connection\n");
		return;
	}

	nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6);
	nfct_set_attr_grp(ct, ATTR_GRP_ORIG_IPV6, &attr_grp);
	nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(src_port));
	nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(dst_port));

	IPACMDBG_H("return\n");
}

NatProxyBase::NatProxyBase() : m_tableHandle(0)
{
	table_created = false;
	IPACMDBG_H("\n");
}

NatProxyBase::~NatProxyBase()
{
	IPACMDBG_H("\n");
}

int NatProxyBase::AddTable(uint16_t number_of_entries, const char* mem_type)
{
	IPACMDBG_H("\n");
	uint32_t table_handle;

	if(table_created)
	{
		IPACMDBG_H("Table already created return\n");
		return 0;
	}

	int ret = DoAddTable(number_of_entries, mem_type, table_handle);
	if (!ret)
	{
		m_tableHandle = table_handle;
		table_created = true;
	}
	IPACMDBG_H("return\n");
	return ret;
}

int NatProxyBase::DeleteTable()
{
	IPACMDBG_H("\n");
	if (!m_tableHandle)
	{
		IPACMERR("The table wasn't allocated by AddTable\n");
		return -EINVAL;
	}

	int ret = DoDeleteTable();
	m_tableHandle = 0;
	table_created = false;
	IPACMDBG_H("return\n");
	return ret;
}

int NatProxyBase::AddEntry(NatEntryBase& entry)
{
	IPACMDBG_H("\n");
	if (!m_tableHandle)
	{
		IPACMERR("The table wasn't allocated by AddTable\n");
		return -EINVAL;
	}

	uint32_t entry_handle = 0, additional_handle = 0;
	int uc_act_handle;
	int ret = DoAddEntry(entry, entry_handle, additional_handle, uc_act_handle);
	if (!ret)
	{
		entry.m_ruleHandle = entry_handle;
		entry.m_timestamp = 0;
		entry.m_enabled = true;
#ifdef FEATURE_IPV6_NAT
		if(entry.GetClientIp() != entry.GetPublicIp())
		{
			Ipv6NatEntry &ipv6nat = static_cast<Ipv6NatEntry&>(entry);

			ipv6nat.m_inboundRuleHandle = additional_handle;
		}

		if(uc_act_handle >= 0)
		{
			entry.m_uc_activation_index = (uint16_t)uc_act_handle;
			entry.m_ucp = true;
			entry.m_s = true;
		}
#endif
	}
	IPACMDBG_H("return\n");
	return ret;
}

int NatProxyBase::DelEntry(NatEntryBase& entry)
{
	IPACMDBG_H("\n");
	if (!m_tableHandle)
	{
		IPACMERR("The table wasn't allocated by AddTable\n");
		return -EINVAL;
	}

	int ret = DoDelEntry(entry);
	if(!entry.sw_allow)
	{
		entry.Clear();
	}
	else
	{
		IPACMDBG_H("not deleting sw allow rule\n");
	}

	IPACMDBG_H("return\n");
	return ret;
}

int Ipv6ctProxy::DoAddTable(uint16_t number_of_entries, const char* mem_type, uint32_t& table_handle)
{
	IPACMDBG_H("\n");

	int ret = ipa_ct_add_ipv6_tbl(number_of_entries, mem_type, &table_handle);
	IPACMDBG_H("return\n");
	return ret;
}

int Ipv6ctProxy::DoDeleteTable()
{
	IPACMDBG_H("\n");
	int ret = ipa_ct_del_ipv6_tbl(m_tableHandle);
	IPACMDBG_H("return\n");
	return ret;
}
#ifdef FEATURE_IPV6_NAT
int Ipv6ctProxy::AddIpv6NatUcAct(uint16_t privatePort, Ipv6IpAddress privateIp,
	uint16_t publicPort, Ipv6IpAddress PublicIp)
{
	union ipa_ioc_uc_activation_entry u;
	int handle = 0;

	u.ipv6_nat.cmd_id = IPA_IPv6_NAT_COM_ID;
	u.ipv6_nat.private_address_lsb = privateIp.GetLsbNetOrder();
	u.ipv6_nat.private_address_msb = privateIp.GetMsbNetOrder();
	u.ipv6_nat.public_address_lsb = PublicIp.GetLsbNetOrder();
	u.ipv6_nat.public_address_msb = PublicIp.GetMsbNetOrder();
	u.ipv6_nat.private_port = htons(privatePort);
	u.ipv6_nat.public_port = htons(publicPort);
	if(ipa_ipv6ct_add_uc_act_entry(&u)) {
		IPACMERR("failed adding IPv6 NAT uc activation entry\n");
		handle = -1;
		return handle;
	}
	IPACMDBG_H("added uc activation entries with paramters: priv_lsb 0x%llX, priv_msb 0x%llX, pub_lsb 0x%llX, pub_msb 0x%llX, priv_port %u pub_port %u\n",
		u.ipv6_nat.private_address_lsb, u.ipv6_nat.private_address_msb, u.ipv6_nat.public_address_lsb, u.ipv6_nat.public_address_msb,
		u.ipv6_nat.private_port, u.ipv6_nat.public_port);
	IPACMDBG_H("uc activation index %d\n", u.ipv6_nat.index);
	handle = u.ipv6_nat.index;

	return handle;
}

void Ipv6ctProxy::DelIpv6NatUcAct(uint16_t handle)
{

	IPACMDBG_H("handle %d\n", handle);

	if(ipa_ipv6ct_del_uc_act_entry(handle))
	{
		IPACMERR("failed deleting uc activation entry %d\n", handle);
	}
	else
	{
		IPACMDBG_H("deleted entry in %d", handle);
	}
	IPACMDBG_H("return\n");
}
#endif

int Ipv6ctProxy::DoAddEntry(const NatEntryBase& entry, uint32_t& entry_handle,
	uint32_t& additional_entry_handle, int& uc_act_handle)
{
	int ret;
	ipa_ipv6ct_rule rule;

	IPACMDBG_H("\n");
	if (entry.m_type != IPA_IP_v6)
	{
		IPACMERR("Wrong IP type\n");
		return -EINVAL;
	}

	uc_act_handle = -1;

	/* IPV6CT case or dummy ipv6 nat*/
#ifdef FEATURE_IPV6_NAT
	if((IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_5) ||
		(entry.GetPublicIp() == entry.GetClientIp()) || entry.m_isDummy)
#endif
	{
		IPACMDBG_H("IPv6CT case\n");
		IPACMDBG_H("ver %d\n", IPACM_Iface::ipacmcfg->GetIPAVer());
		IPACMDBG_H("is dummy = %d\n", entry.m_isDummy);
#ifdef FEATURE_IPV6_NAT
		entry.GetPublicIp().DebugDump("public ip");
#endif
		entry.GetClientIp().DebugDump("client ip");
		entry.GetTargetIp().DebugDump("target ip");

		// using the base class entry reference since object might be ipv6ct or dummy ipv6nat
		rule.src_ipv6_lsb = ((Ipv6IpAddress &)entry.GetClientIp()).GetLsb();
		rule.src_ipv6_msb = ((Ipv6IpAddress &)entry.GetClientIp()).GetMsb();
		rule.dest_ipv6_lsb = ((Ipv6IpAddress &)entry.GetTargetIp()).GetLsb();
		rule.dest_ipv6_msb = ((Ipv6IpAddress &)entry.GetTargetIp()).GetMsb();
		rule.direction_settings = IPA_IPV6CT_DIRECTION_ALLOW_ALL;
		rule.src_port = entry.GetSrcPort();
		rule.dest_port = entry.GetDstPort();
		rule.protocol = entry.m_protocol;
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_5) {
			rule.ucp = entry.m_ucp;
			rule.uc_activation_index = entry.m_uc_activation_index;
			rule.s = entry.m_s;
			IPACMDBG_H("ucp: en %d, idx %d, s %d\n", entry.m_ucp, entry.m_uc_activation_index, entry.m_s);
		}

		ret = ipa_ct_add_ipv6_rule(m_tableHandle, &rule, &entry_handle);

		IPACMDBG("added ipv6CT entry, src_lsb 0x%llX, src_msb 0x%llX, src_port %u, dst_lsb 0x%llX, dst_msb 0x%llX, dst_port %u, dir %d, prot %d, handle %d\n",
			rule.src_ipv6_lsb, rule.src_ipv6_msb, rule.src_port, rule.dest_ipv6_lsb, rule.dest_ipv6_msb, rule.dest_port, rule.direction_settings, rule.protocol, entry_handle);
	}
#ifdef FEATURE_IPV6_NAT
	/* IPv6 NAT case - add OUTBOUND and INBOUND rules*/
	else
	{
		const Ipv6NatEntry& ipv6nat_entry = static_cast<const Ipv6NatEntry&>(entry);
		IPACMDBG_H("IPv6 NAT case\n");
		IPACMDBG_H("ver %d\n", IPACM_Iface::ipacmcfg->GetIPAVer());
		IPACMDBG_H("is dummy = %d\n", entry.m_isDummy);
		entry.GetPublicIp().DebugDump("public ip");
		entry.GetClientIp().DebugDump("client ip");
		entry.GetTargetIp().DebugDump("target ip");
		IPACMDBG_H("direction %d\n", entry.m_direction);

		/* first add uc activation rule, it shall be pointed by both IPv6ct rules*/
		uc_act_handle = AddIpv6NatUcAct(ipv6nat_entry.m_srcPort, ipv6nat_entry.m_srcAddr,
			ipv6nat_entry.m_publicPort, ipv6nat_entry.m_public_address);

		if (uc_act_handle < 0) {
			IPACMERR("failed adding IPv6 NAT uc activation entry\n");
			entry.DebugDump("failed IPv6NAT connection details: ");
			return IPACM_FAILURE;
		}

		/* ucp params applies for both inbound and outbound */
		rule.ucp = true;
		rule.uc_activation_index = (uint16_t)uc_act_handle;
		rule.s = true;

		/* OUTBOUND rule*/
		rule.src_ipv6_lsb = ipv6nat_entry.m_srcAddr.GetLsb();
		rule.src_ipv6_msb = ipv6nat_entry.m_srcAddr.GetMsb();
		rule.dest_ipv6_lsb = ipv6nat_entry.m_dstAddr.GetLsb();
		rule.dest_ipv6_msb = ipv6nat_entry.m_dstAddr.GetMsb();
		rule.direction_settings = IPA_IPV6CT_DIRECTION_ALLOW_OUT;
		rule.src_port = ipv6nat_entry.m_srcPort;
		rule.dest_port = ipv6nat_entry.m_dstPort;
		rule.protocol = ipv6nat_entry.m_protocol;

		ret = ipa_ct_add_ipv6_rule(m_tableHandle, &rule, &entry_handle);
		if(ret)
		{
			IPACMERR("failed adding outbound rule, bail\n");
			goto clean_ucp;
		}

		IPACMDBG("added OUTBOUND IPv6 NAT entry, src_lsb 0x%llX, src_msb 0x%llX, src_port %u, dst_lsb 0x%llX, dst_msb 0x%llX, dst_port %u, dir %d, prot %d, handle %d\n",
			rule.src_ipv6_lsb, rule.src_ipv6_msb, rule.src_port,
			rule.dest_ipv6_lsb, rule.dest_ipv6_msb, rule.dest_port,
			rule.direction_settings, rule.protocol, entry_handle);

		/* INBOUND rule - src and dst are filled as outbound connection, use public address */
		rule.src_ipv6_lsb = ipv6nat_entry.m_public_address.GetLsb();
		rule.src_ipv6_msb = ipv6nat_entry.m_public_address.GetMsb();
		rule.dest_ipv6_lsb = ipv6nat_entry.m_dstAddr.GetLsb();
		rule.dest_ipv6_msb = ipv6nat_entry.m_dstAddr.GetMsb();
		rule.direction_settings = IPA_IPV6CT_DIRECTION_ALLOW_IN;
		rule.src_port = ipv6nat_entry.m_publicPort;
		rule.dest_port = ipv6nat_entry.m_dstPort;
		rule.protocol = ipv6nat_entry.m_protocol;

		ret = ipa_ct_add_ipv6_rule(m_tableHandle, &rule, &additional_entry_handle);
		if(ret)
		{
			IPACMERR("failed adding outbound rule, bail\n");
			goto inbound_fail;
		}

		IPACMDBG("added INBOUND IPv6 NAT entry, src_lsb 0x%llX, src_msb 0x%llX, src_port %u, dst_lsb 0x%llX, dst_msb 0x%llX, dst_port %u, dir %d, prot %d, handle %d\n",
			rule.src_ipv6_lsb, rule.src_ipv6_msb, rule.src_port,
			rule.dest_ipv6_lsb, rule.dest_ipv6_msb, rule.dest_port,
			rule.direction_settings, rule.protocol, additional_entry_handle);
	}
#endif
	IPACMDBG_H("return\n");
	return ret;
#ifdef FEATURE_IPV6_NAT
inbound_fail:
	ipa_ct_del_ipv6_rule(m_tableHandle, entry_handle);
clean_ucp:
	DelIpv6NatUcAct(rule.uc_activation_index);
	return ret;
#endif
}

int Ipv6ctProxy::DoDelEntry(const NatEntryBase& entry)
{
	int ret;

	IPACMDBG_H("\n");
	if (entry.m_type != IPA_IP_v6)
	{
		IPACMERR("Wrong IP type\n");
		return -EINVAL;
	}

	ret = ipa_ct_del_ipv6_rule(m_tableHandle, entry.m_ruleHandle);
	if(ret)
	{
		IPACMERR("failed deleting ipv6ct rule\n");
	}
#ifdef FEATURE_IPV6_NAT
	if((IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_5))
	{
		if(entry.GetClientIp() != entry.GetPublicIp())
		{
			const Ipv6NatEntry &ipv6nat = static_cast<const Ipv6NatEntry&>(entry);

			IPACMDBG_H("this is ipv6 nat entry, delete inbound rule\n");

			ret = ipa_ct_del_ipv6_rule(m_tableHandle, ipv6nat.m_inboundRuleHandle);
			if(ret)
			{
				IPACMERR("failed deleting inbound ipv6 nat rule\n");
			}
			DelIpv6NatUcAct(entry.m_uc_activation_index);
		} else

		// using the base class entry reference since object might be ipv6ct or dummy ipv6nat
		if(entry.m_ucp)
		{
			ret = ipa_ipv6ct_del_uc_act_entry(entry.m_uc_activation_index);
			if(ret)
				IPACMERR("failed deleting uc activation entry %d\n", entry.m_uc_activation_index);
		}
	}
#endif
	IPACMDBG_H("return\n");
	return ret;
}

int Ipv6ctProxy::QueryTimestamp(const NatEntryBase& entry, uint32_t& time_stamp) const
{
	IPACMDBG_H("\n");
	if (entry.m_type != IPA_IP_v6)
	{
		IPACMERR("Wrong IP type\n");
		return -EINVAL;
	}

	int ret = ipa_ct_query_timestamp(m_tableHandle, entry.m_ruleHandle, &time_stamp);
#ifdef FEATURE_IPV6_NAT
	if(ret)
	{
		IPACMERR("query failed, return\n");
		return ret;
	}
	// since IPv6 NAT entry is actually two IPv6ct entries we need to take the latest of them
	if(entry.GetPublicIp() != entry.GetClientIp())
	{
		uint32_t additional_timestamp = 0;
		const Ipv6NatEntry &ipv6nat = static_cast<const Ipv6NatEntry&>(entry);

		IPACMDBG_H("ipv6 nat entry, check inbound handle\n");
		ret = ipa_ct_query_timestamp(m_tableHandle, ipv6nat.m_inboundRuleHandle, &additional_timestamp);
		if(ret)
		{
			IPACMERR(" inbound query failed, return\n");
			return ret;
		}
		if(additional_timestamp > time_stamp)
		{
			IPACMDBG_H("inbound handle (%u) later than outbound handle (%u), update\n", additional_timestamp, time_stamp);
			time_stamp = additional_timestamp;
		}
	}
#endif
	IPACMDBG_H("return\n");
	return ret;
}

void Ipv6ctProxy::DumpTable()
{
	IPACMDBG_H("\n");
	ipa_ipv6ct_dump_table(m_tableHandle);
	IPACMDBG_H("return\n");
}

NatObjectsGeneratorBase::NatObjectsGeneratorBase()
{
	IPACMDBG_H("\n");
}

NatObjectsGeneratorBase::~NatObjectsGeneratorBase()
{
	IPACMDBG_H("\n");
}

NatProxyBase& Ipv6ctObjectsGenerator::GetProxy() const
{
	IPACMDBG_H("\n");
	return *new Ipv6ctProxy;
}

NatEntriesCollectionBase& Ipv6ctObjectsGenerator::GetEntriesCollection(int max_entries) const
{
	IPACMDBG_H("\n");
	return *new Ipv6ctEntriesCollection(max_entries);
}

IpAddressesCollectionBase& Ipv6ctObjectsGenerator::GetIpAddressesCollection(int max_entries) const
{
	IPACMDBG_H("\n");
	return *new Ipv6IpAddressesCollection(max_entries);
}

IpAddress& Ipv6ctObjectsGenerator::GetIpAddress() const
{
	IPACMDBG_H("\n");
	return *new Ipv6IpAddress;
}

ConntrackTimestampUtil& Ipv6ctObjectsGenerator::GetConntrackTimestampUtil() const
{
	IPACMDBG_H("\n");
	return *new Ipv6ctConntrackTimestampUtil;
}
#ifdef FEATURE_IPV6_NAT
NatEntriesCollectionBase& Ipv6NatObjectsGenerator::GetEntriesCollection(int max_entries) const
{
	IPACMDBG_H("\n");
	return *new Ipv6NatEntriesCollection(max_entries);
}
#endif

NatBase::NatBase(ipa_ip_type type, int max_entries, const char* mem_type, const NatObjectsGeneratorBase& objectsGenerator)
	:
	m_type(type),
	m_temp(objectsGenerator.GetEntriesCollection(MAX_TEMP_ENTRIES)),
	m_pwrSaveIfs(objectsGenerator.GetIpAddressesCollection(IPA_MAX_NUM_WIFI_CLIENTS)),
	m_maxEntries(max_entries),
	m_curCnt(0),
	m_proxy(objectsGenerator.GetProxy()),
	m_ctTimestampUtil(objectsGenerator.GetConntrackTimestampUtil()),
	m_cache(objectsGenerator.GetEntriesCollection(max_entries)),
	m_previousWanAddress(objectsGenerator.GetIpAddress()),
	ct_mem_type(mem_type)
{
	IPACMDBG_H("\n");
}

NatBase::~NatBase()
{
	IPACMDBG_H("\n");
	delete &m_temp;
	delete &m_pwrSaveIfs;
	delete &m_proxy;
	delete &m_ctTimestampUtil;
	delete &m_cache;
	delete &m_previousWanAddress;
	IPACMDBG_H("return\n");
}

#ifdef FEATURE_IPV6_NAT
int NatBase::Init(void)
{
	IPACM_Config *pConfig;
	int size = 0;

	pConfig = IPACM_Config::GetInstance();
	if(pConfig == NULL)
	{
		IPACMERR("Unable to get Config instance\n");
		return IPACM_FAILURE;
	}

	nALGPort = pConfig->GetAlgPortCnt();
	if(nALGPort > 0)
	{
		pALGPorts = (ipacm_alg *)malloc(sizeof(ipacm_alg) * nALGPort);
		if(pALGPorts == NULL)
		{
			IPACMERR("Unable to allocate memory for alg prots\n");
			goto fail;
		}
		memset(pALGPorts, 0, sizeof(ipacm_alg) * nALGPort);

		if(pConfig->GetAlgPorts(nALGPort, pALGPorts) != 0)
		{
			IPACMERR("Unable to retrieve ALG prots\n");
			goto fail;
		}

		IPACMDBG("Printing %d alg ports information\n", nALGPort);
		for(int cnt=0; cnt<nALGPort; cnt++)
		{
			IPACMDBG("%d: Proto[%d], port[%d]\n", cnt, pALGPorts[cnt].protocol, pALGPorts[cnt].port);
		}
	}

	return IPACM_SUCCESS;

fail:
	free(pALGPorts);
	return IPACM_FAILURE;
}

bool NatBase::isAlgPort(uint8_t proto, uint16_t port)
{
	int cnt;
	for(cnt = 0; cnt < nALGPort; cnt++)
	{
		if(proto == pALGPorts[cnt].protocol &&
			 port == pALGPorts[cnt].port)
		{
			IPACMDBG_H("%d %d\n",proto, port);
			return true;
		}
	}
	IPACMDBG_H("%d %d\n",proto, port);
	return false;
}
#endif

int NatBase::AddTable(const uint32_t v6_prefix[2])
{
	IPACMDBG_H("\n");
	int ret = m_proxy.AddTable(m_maxEntries, ct_mem_type);
	if (ret)
	{
		IPACMERR("unable to create the table Error:%d\n", ret);
		return ret;
	}
#ifndef FEATURE_SOCKSv5
	/* Add back the cached NAT-entry */
	IPACMDBG_H("Restore the cache to ipa NAT-table\n");
	for (int cnt = 0; cnt < m_maxEntries; ++cnt)
	{
		NatEntryBase& entry = m_cache[cnt];
		if (entry.Valid())
		{
			uint64_t src_ipv6_msb = 0;

			if(!(IPACM_Iface::ipacmcfg->ipv6_nat_enable))
			{
				if (entry.m_direction == NatEntryBase::DirectionOutbound ||
					entry.m_direction == NatEntryBase::DirectionUnknown ||
					entry.m_direction == NatEntryBase::DirectionInbound)
				{
					src_ipv6_msb =
						((Ipv6IpAddress &)entry.GetClientIp()).GetMsb();
				}
			}
			else
			{
				if (entry.m_direction == NatEntryBase::DirectionOutbound ||
					entry.m_direction == NatEntryBase::DirectionUnknown ||
					entry.m_direction == NatEntryBase::DirectionInbound)
				{
					src_ipv6_msb =
						((Ipv6IpAddress &)entry.GetPublicIp()).GetMsb();
				}
			}
			if(ipv6prefixmatch(src_ipv6_msb, v6_prefix))
			{
				if (m_proxy.AddEntry(entry))
				{
					IPACMERR("unable to add the rule delete from cache\n");
					entry.Clear();
					--m_curCnt;
					continue;
				}
				entry.DebugDump("On wan-iface reset added below rule successfully\n");
			}
		}
	}
#endif

	IPACMDBG_H("return\n");
	return 0;
}

int NatBase::DeleteTable(const uint32_t v6_prefix[2],int num_v6_vlan_pdns)
{
	IPACMDBG_H("\n");

	for (int cnt = 0; cnt < m_maxEntries; ++cnt)
	{
		NatEntryBase& entry = m_cache[cnt];
		if (entry.Valid())
		{
			uint64_t src_ipv6_msb = 0;

			if(!(IPACM_Iface::ipacmcfg->ipv6_nat_enable))
			{
				if (entry.m_direction == NatEntryBase::DirectionOutbound ||
					entry.m_direction == NatEntryBase::DirectionUnknown ||
					entry.m_direction == NatEntryBase::DirectionInbound)
				{
					src_ipv6_msb =
						((Ipv6IpAddress &)entry.GetClientIp()).GetMsb();
				}
			}
			else
			{
				if (entry.m_direction == NatEntryBase::DirectionOutbound ||
					entry.m_direction == NatEntryBase::DirectionUnknown ||
					entry.m_direction == NatEntryBase::DirectionInbound)
				{
					src_ipv6_msb =
						((Ipv6IpAddress &)entry.GetPublicIp()).GetMsb();
				}
			}

			if(ipv6prefixmatch(src_ipv6_msb, v6_prefix))
			{
				if (m_proxy.DelEntry(entry))
				{
					IPACMERR("unable to delete the rule delete from cache\n");
					entry.Clear();
					--m_curCnt;
					continue;
				}

				entry.DebugDump("On wan-iface reset deleted below rule successfully\n");
			}
		}
	}

	if(num_v6_vlan_pdns == 0)
	{
		int ret = m_proxy.DeleteTable();
		if (ret)
		{
			IPACMERR("unable to delete the table Error: %d\n", ret);;
			return ret;
		}
 
		Reset();
	}

	IPACMDBG_H("return\n");
	return 0;
}

int NatBase::AddEntry(const NatEntryBase& entry)
{
	IPACMDBG_H("\n");
#ifdef FEATURE_SOCKSv5
	Ipv6ctEntry new_entry;

	memcpy(&new_entry, &entry, sizeof(Ipv6ctEntry));

	if (m_proxy.AddEntry(new_entry))
	{
		IPACMERR("unable to add the v6-ct entry\n");
		return -EPERM;
	}
	IPACMDBG_H("Added entry successfully handle (%d)\n", new_entry.m_ruleHandle);
	socksv5_v6_conn.push_front(new_entry);
#else
	entry.DebugDump("The new entry to add");

	if (!entry.Valid())
	{
		IPACMERR("Invalid Connection, ignoring it\n");
		return 0;
	}

	if (m_cache.Find(entry) != NULL)
	{
		IPACMERR("Duplicate rule. Ignore it\n");
		return -EPERM;
	}

	NatEntryBase* new_entry = m_cache.GetFirstEmpty();
	if(new_entry == NULL)
	{
		IPACMERR("Error: Unable to add, reached maximum rules\n");
		return -EPERM;
	}

	*new_entry = entry;
		if (ChkSWAllow(entry))
		{
			IPACMERR("SwAllow Entry added swallow flag\n");
			new_entry->sw_allow = true;
			new_entry->m_enabled = true;
		}
		else if(m_pwrSaveIfs.Find(new_entry->GetClientIp()) != NULL || m_pwrSaveIfs.Find(new_entry->GetTargetIp()) != NULL)
	{
		IPACMDBG_H("Device is Power Save mode: Don't send to HW but successfully cached\n");
	}
	else
	{
		if(m_proxy.AddEntry(*new_entry))
		{
			IPACMERR("unable to add the rule\n");
			new_entry->Clear();
			return -EPERM;
		}
		IPACMDBG_H("Added entry successfully\n");
	}
#endif
	IPACMDBG_H("\n");
	++m_curCnt;
	IPACMDBG_H("return\n");
	return 0;
}

void NatBase::DeleteEntry(const NatEntryBase& entry)
{
	IPACMDBG_H("\n");
#ifdef FEATURE_SOCKSv5
	Ipv6ctEntry new_entry;
	list<Ipv6ctEntry>::iterator it_mapping;

	memcpy(&new_entry, &entry, sizeof(Ipv6ctEntry));

	/* find the entry and clean up*/
	for(it_mapping = socksv5_v6_conn.begin(); it_mapping != socksv5_v6_conn.end(); it_mapping++)
	{
		if((it_mapping->m_srcAddr == new_entry.m_srcAddr) && (it_mapping->m_dstAddr == new_entry.m_dstAddr) &&
			(it_mapping->m_srcPort == new_entry.m_srcPort) && (it_mapping->m_dstPort == new_entry.m_dstPort) &&
			(it_mapping->m_protocol == new_entry.m_protocol))
		{
			new_entry.m_ruleHandle = it_mapping->m_ruleHandle;
			IPACMDBG_H("Found the matched handle (%d)\n",
				new_entry.m_ruleHandle);

			if (m_proxy.DelEntry(new_entry))
			{
				IPACMERR("unable to delete the v6-ct entry\n");
				return;
			}
			IPACMDBG_H("Deleted entry successfully\n");

			/* delete the entry */
			socksv5_v6_conn.erase(it_mapping);
			break;
		}
	}

	if (it_mapping == socksv5_v6_conn.end())
	{
		IPACMERR("Can't find the matched socksv5_v6_conn!\n");
	}
#else
	entry.DebugDump("The entry to delete");

	NatEntryBase* entryDelete = m_cache.Find(entry);
	if (entryDelete == NULL)
	{
		IPACMDBG_H("No Such Entry exists\n");
		return;
	}

	if (entryDelete->m_enabled)
	{
		if (m_proxy.DelEntry(*entryDelete))
		{
			IPACMERR("Deletion failed\n");
		}
		else
		{
			IPACMDBG_H("Deleted NAT entry successfully\n");
		}
	}
		if(entryDelete->sw_allow && entry.sw_allow)
		{
			IPACMDBG_H("Don't Deleted NAT entry for swallow rule\n");
		}
		else
		{
			entryDelete->Clear();
			--m_curCnt;
		}
#endif
	IPACMDBG_H("return\n");
}

void NatBase::CacheEntry(const NatEntryBase& entry)
{
	IPACMDBG_H("\n");
	entry.DebugDump("The new entry to cache");

	if (!entry.Valid())
	{
		IPACMERR("Invalid Connection, ignoring it\n");
		return;
	}

	if (m_cache.Find(entry) != NULL)
	{
		IPACMERR("Duplicate rule. Ignore it\n");
		return;
	}

	if (ChkSWAllow(entry))
	{
		IPACMERR("SwAllow Entry. Ignore it\n");
		return;
	}

	NatEntryBase* new_entry = m_cache.GetFirstEmpty();
	if (new_entry == NULL)
	{
		IPACMERR("Error: Unable to add, reached maximum rules\n");
		return;
	}

	*new_entry = entry;
	++m_curCnt;
	IPACMDBG_H("Cached rule successfully\n");
}

void NatBase::AddTempEntry(const NatEntryBase& entry)
{
	IPACMDBG_H("\n");
	entry.DebugDump("Received Temp Nat entry to add\n");

	if (m_cache.Find(entry) != NULL || m_temp.Find(entry) != NULL)
	{
		IPACMERR("Duplicate rule. Ignore it\n");
		return;
	}

	if (ChkSWAllow(entry))
	{
		IPACMERR("SwAllow Entry. Ignore it\n");
		return;
	}

	NatEntryBase* new_entry = m_temp.GetFirstEmpty();
	if (new_entry == NULL)
	{
		IPACMERR("Error: Unable to add, reached maximum temp rules\n");
		return;
	}

	*new_entry = entry;
	IPACMDBG_H("Added Temp Entry\n");
}

void NatBase::DeleteTempEntry(const NatEntryBase& entry)
{
	IPACMDBG_H("\n");
	entry.DebugDump("Received Temp Nat entry to delete\n");

	NatEntryBase* entryDelete = m_temp.Find(entry);
	if (entryDelete == NULL)
	{
		IPACMDBG_H("No Such Temp Entry exists\n");
		return;
	}

	entryDelete->Clear();
	IPACMDBG_H("The Temp Entry successfully deleted\n");
}

void NatBase::FlushTempEntries(const IpAddress& clientIp, bool isAdd, bool isDummy, bool isStaClientIp)
{
	IPACMDBG_H("\n");
	clientIp.DebugDump("Flush temp entries for");

	for (int cnt = 0; cnt < MAX_TEMP_ENTRIES; ++cnt)
	{
		NatEntryBase& curr = m_temp[cnt];
		if (!curr.UpdateDirection(clientIp, isStaClientIp))
		{
			continue;
		}
		curr.DebugDump((isAdd) ? "Add temp entry to cache" : "Delete temp entry");

		if (isAdd)
		{
			if (isDummy)
			{
				IPACMDBG("setting to dummy\n");
				curr.m_isDummy = true;
			}

			int ret = AddEntry(curr);
			if (ret)
			{
				IPACMERR("unable to add temp entry: %d\n", ret);
				continue;
			}
			IPACMDBG_H("Successfully flushed the entry\n");
		}

		curr.Clear();
	}
	IPACMDBG_H("return\n");
}

void NatBase::FlushAndCacheVlanTempEntries_v6(uint32_t* ipv6_addr, bool isAdd, bool isDummy, bool isStaClientIp)
{
	IPACMDBG_H("\n");
	const IpAddress& clientIp = Ipv6IpAddress(ipv6_addr, false);
	clientIp.DebugDump("Flush temp entries for");

	int valid = 0;

	for (int cnt = 0; cnt < MAX_TEMP_ENTRIES; ++cnt)
	{
		NatEntryBase& curr = m_temp[cnt];
		if (!curr.UpdateDirection(clientIp, isStaClientIp))
		{
			continue;
		}
		curr.DebugDump((isAdd) ? "Add temp entry to cache" : "Delete temp entry");

		uint64_t src_ipv6_msb = 0;

		if (curr.m_direction == NatEntryBase::DirectionOutbound || curr.m_direction == NatEntryBase::DirectionUnknown)
		{
			src_ipv6_msb = ((Ipv6IpAddress &)curr.GetClientIp()).GetMsb();
		}
		else if (curr.m_direction == NatEntryBase::DirectionInbound)
		{
			src_ipv6_msb = ((Ipv6IpAddress &)curr.GetTargetIp()).GetMsb();
		}

		if(((src_ipv6_msb >> 32) == ipv6_addr[0]) && ((src_ipv6_msb & 0x00000000FFFFFFFF) == ipv6_addr[1]))
		{
			valid = 1;
		}

		if (isAdd && valid)
		{
			if (isDummy)
			{
				IPACMDBG("setting to dummy\n");
				curr.m_isDummy = true;
			}

			int ret = AddEntry(curr);
			if (ret)
			{
				IPACMERR("unable to add temp entry: %d\n", ret);
				continue;
			}

			IPACMDBG_H("Successfully flushed the entry\n");
		}

		curr.Clear();
	}
	IPACMDBG_H("return\n");
}

void NatBase::UpdateTcpUdpTimeStamps(bool& isTcpUdpTimeoutUpToDate)
{
	IPACMDBG_H("\n");
	int ret;
	uint32_t timestamp;
	bool keep_awake;

	keep_awake = ( m_maxEntries && CT_SRAM_IN_USE() && ipa_ct_is_sram_supported() );

	if ( keep_awake )
	{
		IPACMDBG("Voting clock on\n");

		if ( ipa_nat_vote_clock(IPA_APP_CLK_VOTE) != 0 )
		{
			IPACMERR("Voting clock on failed\n");
			return;
		}
	}


	for (int cnt = 0; cnt < m_maxEntries; ++cnt)
	{
		NatEntryBase& curr = m_cache[cnt];
		if (!curr.m_enabled || curr.m_isDummy)
		{
			continue;
		}
		if (m_proxy.QueryTimestamp(curr, timestamp))
		{
			IPACMERR("unable to retrieve timeout for rule handle: %d\n", curr.m_ruleHandle);
			continue;
		}

		if (curr.m_timestamp == timestamp)
		{
			continue;
		}

#ifndef FEATURE_IPA_ANDROID
		if (!isTcpUdpTimeoutUpToDate)
		{
			m_ctTimestampUtil.ReadTcpUdpTimeout();
			isTcpUdpTimeoutUpToDate = true;
		}
#endif
		ret = m_ctTimestampUtil.UpdateConntrackTimeStamp(curr);
		if (ret)
		{
			IPACMERR("unable to update time stamp");
			m_proxy.DelEntry(curr);
			continue;
		}

		curr.m_timestamp = timestamp;
		IPACMDBG("Updated time stamp successfully\n");
	}

	if ( keep_awake )
	{
		IPACMDBG("Voting clock off\n");

		if ( ipa_nat_vote_clock(IPA_APP_CLK_DEVOTE) != 0 )
		{
			IPACMERR("Voting clock off failed\n");
		}
	}

	IPACMDBG_H("return\n");
}

int NatBase::UpdatePwrSaveIf(const IpAddress& client_lan_ip)
{
	IPACMDBG_H("\n");

	client_lan_ip.DebugDump("Received");

	if (!client_lan_ip.Valid())
	{
		IPACMERR("Invalid ip address received\n");
		return -EINVAL;
	}

	if (m_pwrSaveIfs.Find(client_lan_ip) != NULL)
	{
		IPACMDBG("The client is already in power save\n");
		return 0;
	}

	IpAddress* entry = m_pwrSaveIfs.GetFirstEmpty();
	if (entry == NULL)
	{
		IPACMERR("Power save clients collection is full\n");
		return -EPERM;
	}
	*entry = client_lan_ip;

	for (int cnt = 0; cnt < m_maxEntries; ++cnt)
	{
		NatEntryBase& curr = m_cache[cnt];
		if (curr.GetClientIp() != client_lan_ip || !curr.m_enabled)
		{
			continue;
		}

		curr.DebugDump("Going to disable following entry for power save\n");

		if (m_proxy.DelEntry(curr))
		{
			IPACMERR("unable to delete the rule\n");
			continue;
		}

		curr.m_enabled = false;
		curr.m_ruleHandle = 0;
	}
	IPACMDBG_H("return\n");
	return 0;
}

int NatBase::ResetPwrSaveIf(const IpAddress& client_lan_ip)
{
	IPACMDBG_H("\n");
	client_lan_ip.DebugDump("Received");

	if (!client_lan_ip.Valid())
	{
		IPACMERR("Invalid ip address received\n");
		return -EINVAL;
	}

	IpAddress* entry = m_pwrSaveIfs.Find(client_lan_ip);
	if (entry != NULL)
	{
		entry->Clear();
	}

	for (int cnt = 0; cnt < m_maxEntries; ++cnt)
	{
		NatEntryBase& curr = m_cache[cnt];
		if (curr.GetClientIp() != client_lan_ip || curr.m_enabled)
		{
			continue;
		}

		curr.DebugDump("Going to enable following entry after power save\n");

		if (m_proxy.AddEntry(curr))
		{
			IPACMERR("unable to add the rule delete from cache\n");
			curr.Clear();
			--m_curCnt;
			continue;
		}
		curr.m_enabled = true;
	}

	IPACMDBG_H("return\n");
	return 0;
}

int NatBase::DelEntriesOnClntDiscon(const IpAddress& client_lan_ip)
{
	IPACMDBG_H("\n");

	client_lan_ip.DebugDump("Received");

	if (!client_lan_ip.Valid())
	{
		IPACMERR("Invalid ip address received\n");
		return -EINVAL;
	}

	IpAddress* entry = m_pwrSaveIfs.Find(client_lan_ip);
	if (entry != NULL)
	{
		entry->Clear();
		IPACMDBG("Remove power save entry\n");
	}

	int tmp = 0;
	for (int cnt = 0; cnt < m_maxEntries; ++cnt)
	{
		NatEntryBase& curr = m_cache[cnt];
		if (curr.GetClientIp() != client_lan_ip)
		{
			continue;
		}

		if (!curr.m_enabled)
		{
			continue;
		}

		curr.DebugDump("Going to disable following entry upon client disconnection\n");

		if (m_proxy.DelEntry(curr))
		{
			IPACMERR("unable to delete the rule\n");
			continue;
		}

		curr.m_enabled = false;
		++tmp;
	}

	IPACMDBG_H("Deleted (but cached) %d entries\n", tmp);
	return 0;
}

int NatBase::DelEntriesOnSTAClntDiscon(const IpAddress& client_lan_ip)
{
	IPACMDBG_H("\n");

	client_lan_ip.DebugDump("Received");

	if (!client_lan_ip.Valid())
	{
		IPACMERR("Invalid ip address received\n");
		return -EINVAL;
	}

	int tmp = m_curCnt;
	for (int cnt = 0; cnt < m_maxEntries; ++cnt)
	{
		NatEntryBase& curr = m_cache[cnt];
		if (curr.GetTargetIp() != client_lan_ip)
		{
			continue;
		}

		if (!curr.m_enabled)
		{
			continue;
		}

		curr.DebugDump("Going to disable following entry upon STA client disconnection\n");

		if (m_proxy.DelEntry(curr))
		{
			IPACMERR("unable to delete the rule\n");
			continue;
		}

		curr.Clear();
		--m_curCnt;
	}

	IPACMDBG_H("Deleted %d entries\n", (tmp - m_curCnt));
	return 0;
}

void NatBase::DelEntriesOnWanDown()
{
	IPACMDBG_H("\n");

	int tmp = m_curCnt;
	for(int cnt = 0; cnt < m_maxEntries; ++cnt)
	{
		NatEntryBase& curr = m_cache[cnt];

		if(!curr.m_enabled)
		{
			continue;
		}

		curr.DebugDump("Going to disable following entry upon Wan Down\n");

		if(m_proxy.DelEntry(curr))
		{
			IPACMERR("unable to delete the rule\n");
			continue;
		}

		curr.Clear();
		--m_curCnt;
	}

	IPACMDBG_H("Deleted %d entries\n", (tmp - m_curCnt));
}

void NatBase::Reset()
{
	IPACMDBG_H("\n");
	for (int cnt = 0; cnt < m_maxEntries; ++cnt)
	{
		m_cache[cnt].m_enabled = false;
	}
	IPACMDBG_H("return\n");
}

bool NatBase::ChkSWAllow(const NatEntryBase& rule)
{
	int i, j;
	uint64_t rule_ipv6_msb, fw_ipv6_msb;
	Ipv6ctEntry rule_entry;
	IPACMDBG("Entry\n");

	if(!IPACM_Iface::ipacmcfg->ipacm_msgflt_enable)
	{
		IPACMERR("msg filtering feature is not enabled\n");
		return false;
	}
	if(!IPACM_Iface::ipacmcfg->sw_filter_cfg)
	{
		IPACMERR("SW Config not updated/pdn index not updated!\n");
		return false;
	}

	rule_ipv6_msb = ((Ipv6IpAddress &)rule.GetClientIp()).GetMsb();

	for(i = 0; i < sw_filter_cfg.pdn_count;i++)
	{
		fw_ipv6_msb = sw_filter_cfg.pdns[i].ipv6_prefix[0];
		fw_ipv6_msb = (fw_ipv6_msb << 32) | sw_filter_cfg.pdns[i].ipv6_prefix[1];
		/* PDN not up yet or PDN IP is different than rule public IP */
		if(sw_filter_cfg.pdns[i].v6_up != TRUE || memcmp(&fw_ipv6_msb, &rule_ipv6_msb, sizeof(rule_ipv6_msb)))
		{
			continue;
		}

		for(j = 0; j < sw_filter_cfg.pdns[i].num_extd_swallow_entries;j++)
		{
			/* Check if entry is v6 */
			if(sw_filter_cfg.pdns[i].extd_swallow_entries[j].ip_vsn != IP_V6)
				continue;

			/* Check if rule protocol matches with entry protocol */
			if(sw_filter_cfg.pdns[i].extd_swallow_entries[j].protocol &&
			(!(((sw_filter_cfg.pdns[i].extd_swallow_entries[j].protocol &  IPPROTO_UDP) == rule.m_protocol) ||
			((sw_filter_cfg.pdns[i].extd_swallow_entries[j].protocol & IPPROTO_TCP) == rule.m_protocol))))
			{
				continue;
			}


			memcpy(&rule_entry, &rule, sizeof(Ipv6ctEntry));

			if(firewall_tuple_match_with_nat(sw_filter_cfg.pdns[i].extd_swallow_entries[j], &rule_entry))
			{
				((Ipv6IpAddress &)rule_entry.GetClientIp()).DebugDump("srcAddr (private ip):");
				((Ipv6IpAddress &)rule_entry.GetTargetIp()).DebugDump("dstAddr (target ip):");
				IPACMDBG_H("srcPort (private Port): %d\n", rule_entry.GetSrcPort());
				IPACMDBG_H("dstPort (target Port): %d\n", rule_entry.GetDstPort());
				IPACMDBG("SW Allow Rule - Do not add\n");
				return true;
			}
		}
	}
	IPACMDBG("Exit\n");
	return false;
}

void NatBase::restore_nat_for_sw_flt_entries(IPACM_extd_swallow_entry_conf_t extd_firewall_entries)
{
	int i;
	char iptype[4]={0}, cmd[100];
	uint64_t src_ipv6[2], src_ipv6_lsb;
  	uint64_t dst_ipv6[2], dst_ipv6_lsb;
  	Ipv6ctEntry new_entry;

	for(i = 0; i< m_maxEntries; i++)
	{
		if(m_cache[i].sw_allow &&  m_cache[i].m_enabled)
		{
			memset(&new_entry, 0, sizeof(Ipv6ctEntry));
			memcpy(&new_entry, &m_cache[i], sizeof(Ipv6ctEntry));
			if(firewall_tuple_match_with_nat(extd_firewall_entries, &new_entry))
			{
				if(m_pwrSaveIfs.Find(m_cache[i].GetClientIp()) != NULL ||
				m_pwrSaveIfs.Find(m_cache[i].GetTargetIp()) != NULL)
				{
					IPACMDBG_H("Device is Power Save mode: Don't send to HW but successfully cached\n");
				}
				else
				{
					m_cache[i].sw_allow = false;
					if(m_proxy.AddEntry(m_cache[i]))
					{
						IPACMERR("unable to add the rule\n");
						m_cache[i].Clear();
					}
					IPACMDBG_H("Added entry successfully\n");
				}
			}
		}
	}
}

void NatBase::firewall_compare(IPACM_swallow_conf_t *backup_firewall_config, IPACM_swallow_conf_t *firewall_config)
{
	int i,j;
	IPACMDBG_H("enter\n");
	if(backup_firewall_config->num_extd_swallow_entries == 0)
	{
		IPACMERR("backup firewall entry is zero, so no need to check further\n");
		goto end;
	}
	for(i = 0; i < backup_firewall_config->num_extd_swallow_entries; i++)
	{
		if(backup_firewall_config->extd_swallow_entries[i].ip_vsn != IP_V6)
		{
			IPACMDBG_H("not v6 rule\n");
			continue;
		}
		for(j = 0; j < firewall_config->num_extd_swallow_entries; j++)
		{
			if(firewall_config->extd_swallow_entries[i].ip_vsn != IP_V6 ||
			(firewall_config->extd_swallow_entries[j].direction !=
			(backup_firewall_config->extd_swallow_entries[i].direction)))
			{
				IPACMDBG_H("protocol direction is not match\n");
				continue;
			}

			if((firewall_config->extd_swallow_entries[j].direction ==
				backup_firewall_config->extd_swallow_entries[j].direction) &&
				firewall_config->extd_swallow_entries[j].attrib.src_port_lo ==
				backup_firewall_config->extd_swallow_entries[i].attrib.src_port_lo &&
				firewall_config->extd_swallow_entries[j].attrib.src_port_hi ==
				backup_firewall_config->extd_swallow_entries[i].attrib.src_port_hi &&
				firewall_config->extd_swallow_entries[j].attrib.dst_port_lo ==
				backup_firewall_config->extd_swallow_entries[i].attrib.dst_port_lo &&
				firewall_config->extd_swallow_entries[j].attrib.dst_port_hi ==
				backup_firewall_config->extd_swallow_entries[i].attrib.dst_port_hi &&
				firewall_config->extd_swallow_entries[j].attrib.src_port ==
				backup_firewall_config->extd_swallow_entries[i].attrib.src_port &&
				firewall_config->extd_swallow_entries[j].attrib.dst_port ==
				backup_firewall_config->extd_swallow_entries[i].attrib.dst_port &&
				(!memcmp(firewall_config->extd_swallow_entries[j].attrib.u.v6.src_addr,
				backup_firewall_config->extd_swallow_entries[i].attrib.u.v6.src_addr,
				sizeof(firewall_config->extd_swallow_entries[j].attrib.u.v6.src_addr))) &&
				(!memcmp(firewall_config->extd_swallow_entries[j].attrib.u.v6.dst_addr,
				backup_firewall_config->extd_swallow_entries[i].attrib.u.v6.dst_addr,
				sizeof(backup_firewall_config->extd_swallow_entries[i].attrib.u.v6.dst_addr))))
			{
				IPACMDBG("firewall entry is matched\n");
				break;
			}
			else
			{
				IPACMDBG("firewall entry is not present\n");
				continue;
			}
		}
		if((j == firewall_config->num_extd_swallow_entries) ||
			(firewall_config->num_extd_swallow_entries == 0))
		{
			IPACMDBG_H("flushing\n");
			restore_nat_for_sw_flt_entries(backup_firewall_config->extd_swallow_entries[i]);
		}
	}
end:
	IPACMERR("reaching end of the firewall\n");
}
void NatBase::GetIpAddress_firewall(uint64_t* src_ipv6_msb, uint64_t* src_ipv6_lsb, uint64_t* dst_ipv6_msb, uint64_t* dst_ipv6_lsb, struct ipa_rule_attrib attrib)
{
	*src_ipv6_msb = attrib.u.v6.src_addr[0];
	*src_ipv6_msb = ((*src_ipv6_msb) << 32 | attrib.u.v6.src_addr[1]);
	*src_ipv6_lsb = attrib.u.v6.src_addr[2];
	*src_ipv6_lsb = ((*src_ipv6_lsb) << 32 | attrib.u.v6.src_addr[3]);
	*dst_ipv6_msb = attrib.u.v6.dst_addr[0];
	*dst_ipv6_msb = ((*dst_ipv6_msb) << 32 | attrib.u.v6.dst_addr[1]);
	*dst_ipv6_lsb = attrib.u.v6.dst_addr[2];
	*dst_ipv6_lsb = ((*dst_ipv6_lsb) << 32 | attrib.u.v6.dst_addr[3]);
}

bool NatBase::firewall_tuple_match_with_nat(IPACM_extd_swallow_entry_conf_t extd_firewall_entries, const Ipv6ctEntry *del_entry)
{
	/* src, dst are for fw entried and fsrc and fdst for rule */
	uint64_t src_ipv6_msb, src_ipv6_lsb,fsrc_ipv6_msb, fsrc_ipv6_lsb;
  	uint64_t dst_ipv6_msb, dst_ipv6_lsb,fdst_ipv6_msb, fdst_ipv6_lsb;
	bool src_range = false,dst_range = false;

	if(extd_firewall_entries.attrib.attrib_mask & IPA_FLT_SRC_PORT_RANGE)
	{
		src_range = true;
	}
	if(extd_firewall_entries.attrib.attrib_mask & IPA_FLT_DST_PORT_RANGE)
	{
		dst_range = true;
	}

	GetIpAddress_firewall(&src_ipv6_msb, &src_ipv6_lsb, &dst_ipv6_msb, &dst_ipv6_lsb, extd_firewall_entries.attrib);
	if(extd_firewall_entries.direction == IPACM_MSGR_UL_FIREWALL &&
		del_entry->m_direction == NatEntryBase::DirectionOutbound)
	{
		fsrc_ipv6_msb = ((Ipv6IpAddress &)del_entry->GetClientIp()).GetMsb();
		fsrc_ipv6_lsb = ((Ipv6IpAddress &)del_entry->GetClientIp()).GetLsb();
		fdst_ipv6_msb = ((Ipv6IpAddress &)del_entry->GetTargetIp()).GetMsb();
		fdst_ipv6_lsb = ((Ipv6IpAddress &)del_entry->GetTargetIp()).GetLsb();
	}
	else
	{
		fsrc_ipv6_msb = ((Ipv6IpAddress &)del_entry->GetTargetIp()).GetMsb();
		fsrc_ipv6_lsb = ((Ipv6IpAddress &)del_entry->GetTargetIp()).GetLsb();
		fdst_ipv6_msb = ((Ipv6IpAddress &)del_entry->GetClientIp()).GetMsb();
		fdst_ipv6_lsb = ((Ipv6IpAddress &)del_entry->GetClientIp()).GetLsb();
	}

	if(extd_firewall_entries.direction == IPACM_MSGR_UL_FIREWALL &&
		del_entry->m_direction == NatEntryBase::DirectionOutbound)
	{
		if(((extd_firewall_entries.attrib.u.v6.src_addr[0] == 0) &&
			(extd_firewall_entries.attrib.u.v6.dst_addr[0] == 0) &&
			(!src_range)  && (!dst_range) &&
			(extd_firewall_entries.attrib.src_port == 0) &&
			(extd_firewall_entries.attrib.dst_port == 0)))
		{
			IPACMERR("Matched in UL wildcard entry\n");
			return true;
		}

		else if((!((extd_firewall_entries.attrib.u.v6.src_addr[0] != 0) ^ ((memcmp(&src_ipv6_msb, &fsrc_ipv6_msb, sizeof(uint64_t))==0) &&
			(memcmp(&src_ipv6_lsb, &fsrc_ipv6_lsb,sizeof(uint64_t))) == 0))) &&
			(!((extd_firewall_entries.attrib.u.v6.dst_addr[0] != 0 ) ^ ((memcmp(&dst_ipv6_msb, &fdst_ipv6_msb, sizeof(uint64_t)) == 0) &&
			(memcmp(&dst_ipv6_lsb , &fdst_ipv6_lsb,sizeof(uint64_t)))==0))) &&
			!((src_range) ^ (extd_firewall_entries.attrib.src_port_lo <=  del_entry->GetSrcPort() &&
			extd_firewall_entries.attrib.src_port_hi >=  del_entry->GetSrcPort())) &&
			!((dst_range) ^ ((extd_firewall_entries.attrib.dst_port_lo <=  del_entry->GetDstPort()) &&
			(extd_firewall_entries.attrib.dst_port_hi >=  del_entry->GetDstPort()))) &&
			!((extd_firewall_entries.attrib.src_port != 0) ^ (extd_firewall_entries.attrib.src_port ==  del_entry->GetSrcPort())) &&
			!((extd_firewall_entries.attrib.dst_port != 0) ^ (extd_firewall_entries.attrib.dst_port ==  del_entry->GetDstPort())))
		{
			IPACMERR("Matched in UL\n");
			return true;
		}
		else
		{
			IPACMERR("not matching Matched in UL\n");
		}
	}
	else if(extd_firewall_entries.direction == IPACM_MSGR_DL_FIREWALL &&
			del_entry->m_direction == NatEntryBase::DirectionInbound)
	{
		if(((extd_firewall_entries.attrib.u.v6.src_addr[0] == 0)) &&
			(extd_firewall_entries.attrib.u.v6.dst_addr[0] == 0) &&
			(!src_range)  && (!dst_range) &&
			(extd_firewall_entries.attrib.src_port == 0) &&
			(extd_firewall_entries.attrib.dst_port == 0))
		{
			IPACMERR("Matched in DL wildcard entry\n");
			return true;
		}
		else if((!((extd_firewall_entries.attrib.u.v6.src_addr[0] != 0) ^ ((memcmp(&src_ipv6_msb, &fsrc_ipv6_msb, sizeof(uint64_t))==0) &&
			(memcmp(&src_ipv6_lsb, &fsrc_ipv6_lsb,sizeof(uint64_t))) == 0))) &&
			(!((extd_firewall_entries.attrib.u.v6.dst_addr[0] != 0 ) ^ ((memcmp(&dst_ipv6_msb, &fdst_ipv6_msb, sizeof(uint64_t)) == 0) &&
			(memcmp(&dst_ipv6_lsb , &fdst_ipv6_lsb,sizeof(uint64_t)))==0))) &&
			!((src_range) ^ (extd_firewall_entries.attrib.src_port_lo <=  del_entry->GetDstPort() &&
			extd_firewall_entries.attrib.src_port_hi >=  del_entry->GetDstPort())) &&
			!((dst_range) ^ ((extd_firewall_entries.attrib.dst_port_lo <=  del_entry->GetSrcPort()) &&
			(extd_firewall_entries.attrib.dst_port_hi >=  del_entry->GetSrcPort()))) &&
			!((extd_firewall_entries.attrib.src_port != 0) ^ (extd_firewall_entries.attrib.src_port ==  del_entry->GetDstPort())) &&
			!((extd_firewall_entries.attrib.dst_port != 0) ^ (extd_firewall_entries.attrib.dst_port ==  del_entry->GetSrcPort())))
		{
			IPACMERR("Matched in UL\n");
			return true;
		}
		else
		{
			IPACMERR("not matching Matched in UL\n");
		}

	}
	return false;
}

void NatBase::HandleSWAllowEntries(void)
{
	int i, j, cnt;
	/* src, dst are for fw entried and fsrc and fdst for rule */
	uint64_t src_ipv6_msb, src_ipv6_lsb, fsrc_ipv6_msb, fsrc_ipv6_lsb;
	uint64_t dst_ipv6_msb, dst_ipv6_lsb;
	Ipv6ctEntry new_entry;
	IPACMDBG("Entry\n");

	if(!IPACM_Iface::ipacmcfg->sw_filter_cfg)
	{
		IPACMERR("SW Config not updated/pdn index not updated!\n");
		return;
	}
	memset(&backup_sw_filter_cfg, 0, sizeof(backup_sw_filter_cfg));
	memcpy(&backup_sw_filter_cfg, &sw_filter_cfg, sizeof(IPACM_swallow_t));

	memset(&sw_filter_cfg, 0, sizeof(sw_filter_cfg));
	memcpy(&sw_filter_cfg, IPACM_Iface::ipacmcfg->sw_filter_cfg, sizeof(IPACM_swallow_t));

	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		firewall_compare(&backup_sw_filter_cfg.pdns[i], &sw_filter_cfg.pdns[i]);
	}
	for(i = 0; i < sw_filter_cfg.pdn_count;i++)
	{
		/* PDN not up yet */
		if(sw_filter_cfg.pdns[i].v6_up != TRUE)
		{
			continue;
		}
		dst_ipv6_msb = sw_filter_cfg.pdns[i].ipv6_prefix[0];
		dst_ipv6_msb = (dst_ipv6_msb << 32) | sw_filter_cfg.pdns[i].ipv6_prefix[1];

		for(j = 0; j < sw_filter_cfg.pdns[i].num_extd_swallow_entries; j++)
		{
			/* Check if entry is v6 */
			if(sw_filter_cfg.pdns[i].extd_swallow_entries[j].ip_vsn != 6)
				continue;
			for(cnt = 0; cnt < m_maxEntries; cnt++)
			{
				/* Check if cache entry is enabled */
				if(!m_cache[cnt].m_enabled || m_cache[cnt].sw_allow)
					continue;

				memcpy(&new_entry, &(m_cache[cnt]), sizeof(Ipv6ctEntry));
					fsrc_ipv6_msb = ((Ipv6IpAddress &)new_entry.GetClientIp()).GetMsb();

				/* Check if rule protocol matches with entry protocol */
				if((sw_filter_cfg.pdns[i].extd_swallow_entries[j].protocol &&
					(!(((sw_filter_cfg.pdns[i].extd_swallow_entries[j].protocol & IPPROTO_UDP) == new_entry.m_protocol) ||
					((sw_filter_cfg.pdns[i].extd_swallow_entries[j].protocol & IPPROTO_TCP) == new_entry.m_protocol)))) ||
					(memcmp(&fsrc_ipv6_msb, &dst_ipv6_msb, sizeof(dst_ipv6_msb))))
				{
					continue;
				}
				if(firewall_tuple_match_with_nat(sw_filter_cfg.pdns[i].extd_swallow_entries[j], &new_entry))
				{
					((Ipv6IpAddress &)new_entry.GetClientIp()).DebugDump("srcAddr (private ip):");
					((Ipv6IpAddress &)new_entry.GetTargetIp()).DebugDump("dstAddr (target ip):");
					IPACMDBG_H("srcPort (private Port): %d\n", new_entry.GetSrcPort());
					IPACMDBG_H("dstPort (target Port): %d\n", new_entry.GetDstPort());
					IPACMDBG("SW Allow V6 Rule - Deleting Rule\n");
					m_cache[cnt].sw_allow = true;
					new_entry.sw_allow = true;
					DeleteEntry(new_entry);
				}
			}
		}
	}
	IPACMDBG("Exit\n");
}

Ipv6ct* Ipv6ct::m_instance = NULL;

NatBase* Ipv6ct::GetInstance()
{
	IPACMDBG_H("\n");

	IPACM_Config *pConfig = IPACM_Config::GetInstance();
	if (pConfig == NULL)
	{
		IPACMERR("Unable to get Config instance\n");
		return NULL;
	}
#ifdef FEATURE_IPV6_NAT
	if(pConfig->ipv6_nat_enable)
		return Ipv6Nat::GetInstance();
#endif
	if(m_instance != NULL)
	{
		return m_instance;
	}

	if (!pConfig->IsIpv6CTEnabled())
	{
		IPACMDBG_H("IPv6 Connection tracking is disabled\n");
		return NULL;
	}

	m_instance = new Ipv6ct(pConfig->GetIpv6CTMaxEntries(), pConfig->GetCTMemType());
	IPACMDBG_H("return\n");
	return m_instance;
}

Ipv6ct::Ipv6ct(int max_entries, const char* mem_type) : NatBase(IPA_IP_v6, max_entries, mem_type, Ipv6ctObjectsGenerator())
{
	IPACMDBG_H("\n");
}

#ifdef FEATURE_IPV6_NAT
Ipv6Nat* Ipv6Nat::m_instance = NULL;

Ipv6Nat* Ipv6Nat::GetInstance()
{
	IPACMDBG_H("\n");
	if(m_instance != NULL)
	{
		return m_instance;
	}

	IPACM_Config *pConfig = IPACM_Config::GetInstance();
	if(pConfig == NULL)
	{
		IPACMERR("Unable to get Config instance\n");
		return NULL;
	}

	if(!pConfig->ipv6_nat_enable)
	{
		IPACMDBG_H("IPv6 Nat tracking is disabled\n");
		return NULL;
	}

	m_instance = new Ipv6Nat(pConfig->GetIpv6CTMaxEntries(), pConfig->GetCTMemType());
	if(m_instance->Init() == IPACM_FAILURE)
	{
		delete m_instance;
		return NULL;
	}

	IPACMDBG_H("return\n");
	return m_instance;
}

Ipv6Nat::Ipv6Nat(int max_entries, const char* mem_type) : NatBase(IPA_IP_v6, max_entries, mem_type, Ipv6NatObjectsGenerator())
{
	IPACMDBG_H("\n");
}
#endif
