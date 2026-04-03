/*
 * Copyright (c) 2013-2020, The Linux Foundation. All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *	* Redistributions of source code must retain the above copyright
	  notice, this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above
	  copyright notice, this list of conditions and the following
	  disclaimer in the documentation and/or other materials provided
	  with the distribution.
	* Neither the name of The Linux Foundation nor the names of its
	  contributors may be used to endorse or promote products derived
	  from this software without specific prior written permission.

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
#include "IPACM_Conntrack_NATApp.h"
#include "IPACM_ConntrackClient.h"
#include "IPACM_Iface.h"

extern "C"
{
#include <ipa_ipv6ct.h>
#include <ipa_nat_drv.h>
}

#include <algorithm>

#define INVALID_IP_ADDR 0x0

#define HDR_METADATA_MUX_ID_BMASK 0x00FF0000
#define HDR_METADATA_MUX_ID_SHFT 0x10

#undef strcasesame
#define strcasesame(a, b) (!strcasecmp(a, b))

#undef  SRAM_IN_USE
#define SRAM_IN_USE() \
	( strcasesame(mem_type, "HYBRID" ) || \
	  strcasesame(mem_type, "SRAM" ) )

/* NatApp class Implementation */
NatApp *NatApp::pInstance = NULL;

bool NatApp::kernel_ver_updated = false;
bool NatApp::is_kernel_ver_upgraded = false;

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
		IPACM_LOG(IPACM_LOG_ERR, "Unable to get Config instance\n");
		return -1;
	}

	mem_type = pConfig->GetNatMemType();

	max_entries = pConfig->GetNatMaxEntries();

	size = (sizeof(nat_table_entry) * max_entries);
	cache = (nat_table_entry *)malloc(size);
	if(cache == NULL)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Unable to allocate memory for cache\n");
		goto fail;
	}
	IPACM_LOG(IPACM_LOG_DEBUG,"Allocated %d bytes for config manager nat cache\n", size);
	memset(cache, 0, size);

	nALGPort = pConfig->GetAlgPortCnt();
	if(nALGPort > 0)
	{
		pALGPorts = (ipacm_alg *)malloc(sizeof(ipacm_alg) * nALGPort);
		if(pALGPorts == NULL)
		{
			IPACM_LOG(IPACM_LOG_ERR, "Unable to allocate memory for alg prots\n");
			goto fail;
		}
		memset(pALGPorts, 0, sizeof(ipacm_alg) * nALGPort);

		if(pConfig->GetAlgPorts(nALGPort, pALGPorts) != 0)
		{
			IPACM_LOG(IPACM_LOG_ERR, "Unable to retrieve ALG prots\n");
			goto fail;
		}

		IPACM_LOG(IPACM_LOG_DEBUG,"Printing %d alg ports information\n", nALGPort);
		for(int cnt=0; cnt<nALGPort; cnt++)
		{
			IPACM_LOG(IPACM_LOG_DEBUG,"%d: Proto[%d], port[%d]\n", cnt, pALGPorts[cnt].protocol, pALGPorts[cnt].port);
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
int NatApp::AddPdn(uint32_t pub_ip, uint8_t mux_id, bool is_sta)
{
	int ret;
	int cnt = 0;
	ipa_nat_ipv4_rule nat_rule;
	ipa_nat_pdn_entry entry;
	uint8_t pdn_index;
	uint8_t pdn_count = 0;
	bool new_entry = false;
	IPACM_LOG(IPACM_LOG_DEBUG, "%s() %d\n", __FUNCTION__, __LINE__);

	entry.dst_metadata = 0;
	entry.public_ip = 0;
	entry.is_sta = false;

	ret = ipa_nat_get_pdn_count(&pdn_count);

	if(ret)
	{
		IPACM_LOG(IPACM_LOG_ERR, "unable to get pdn count Error:%d\n", ret);
		return ret;
	}
	IPACM_LOG(IPACM_LOG_INFO, "is_sta: %d, pdn_count: %d ipv4 address PDN 0x%X\n",is_sta, pdn_count, pub_ip);

	if(!pdn_count)
	{
		/* create the NAT table, the PDN will be stored in index 0 */
		ret = ipa_nat_add_ipv4_tbl(entry.public_ip, mem_type, max_entries, &nat_table_hdl);
		if(ret)
		{
			IPACM_LOG(IPACM_LOG_INFO, "ERROR:unable to create nat table Error:%d\n", ret);
				return ret;
		}
		IPACM_LOG(IPACM_LOG_INFO, "succeesfully created NAT table for ip 0x%X\n", pub_ip);
		entry.public_ip = pub_ip;
		if(!is_sta)
		{
			entry.src_metadata = GenerateMetdata(mux_id);
			/* modify PDN 1 so it will hold the mux ID in the src metadata field */
			pdn_index = 1;
		}
		else
		{
                        /* modify PDN 0 so it will hold the mux ID in the src metadata field */
			pdn_index = 0;
			entry.src_metadata = 0;
			entry.is_sta = true;
		}

		ret = ipa_nat_modify_pdn(nat_table_hdl, pdn_index, &entry);
		if(ret)
		{
			IPACM_LOG(IPACM_LOG_INFO, "ERROR:unable to modify PDN %d entry Error:%d\n", pdn_index, ret);
			return ret;
		}
		new_entry = true;
	}
	else
	{
		if(is_sta)
		{
			pdn_index = 0;
			entry.public_ip = pub_ip;
			entry.src_metadata = 0;
			entry.is_sta = true;
			ret = ipa_nat_alloc_pdn(&entry, &pdn_index);

			if(ret)
			{
				IPACM_LOG(IPACM_LOG_ERR, "unable to modify PDN 0 entry Error:%d\n", ret);
				return ret;
			}
			new_entry = true;
		}
		else
		{
			entry.public_ip = pub_ip;
			entry.src_metadata = GenerateMetdata(mux_id);
			/* only allocate a PDN if it is a new one */
			if(ipa_nat_get_pdn_index(pub_ip, &pdn_index) < 0)
			{
				ret = ipa_nat_alloc_pdn(&entry, &pdn_index);
				if(ret)
				{
					IPACM_LOG(IPACM_LOG_ERR, "ERROR: couldn't allocate a pdn index\n");
					return ret;
				}
				IPACM_LOG(IPACM_LOG_DEBUG, "successfully allocated index %d for ip 0x%X\n", pdn_index, pub_ip);
				new_entry = true;
			}
			else
			{
				IPACM_LOG(IPACM_LOG_DEBUG, "pdn already existed with index %d\n", pdn_index);
			}
		}
	}
	IPACM_LOG(IPACM_LOG_INFO, "Newly added? %d, pdn_index: %d, is_sta: %d, ipv4 address PDN 0x%X, pdn_count: %d\n",
			new_entry, pdn_index, entry.is_sta, pub_ip, pdn_count);
	/* now traverse cache and add the PDN entries */
	for(cnt = 0; cnt < max_entries; cnt++)
	{
		if((cache[cnt].private_ip != 0)
			/* flush only entries which are related to this PDN */
			&& (cache[cnt].public_ip == pub_ip) && (cache[cnt].enabled == false))
		{
			if(is_sta && (isAlgPort(cache[cnt].protocol, cache[cnt].private_port) ||
				isAlgPort(cache[cnt].protocol, cache[cnt].target_port))) {
				IPACM_LOG(IPACM_LOG_ERR, "STA backhaul: connection using ALG Port, ignore\n");
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
				IPACM_LOG(IPACM_LOG_ERR, "unable to add the rule delete from cache\n");
				memset(&cache[cnt], 0, sizeof(cache[cnt]));
				curCnt--;
				continue;
			}
			IPACM_LOG(IPACM_LOG_DEBUG,"cache entry %d rule handle %d\n", cnt, cache[cnt].rule_hdl);
			cache[cnt].enabled = true;
			log_nat_syslog(nat_rule.protocol,nat_rule.private_ip,nat_rule.target_ip,\
						nat_rule.private_port, nat_rule.public_port, \
						nat_rule.target_port, nat_rule.src_only,\
						nat_rule.dst_only, cache[cnt].rule_hdl);
			IPACM_LOG(IPACM_LOG_DEBUG,"new pdn added below rule successfully\n");
			iptodot("Private IP", nat_rule.private_ip);
			iptodot("Target IP", nat_rule.target_ip);
			IPACM_LOG(IPACM_LOG_DEBUG,"Private Port:%d \t Target Port: %d\n", nat_rule.private_port, nat_rule.target_port);
			IPACM_LOG(IPACM_LOG_DEBUG,"Public Port:%d\n", nat_rule.public_port);
			IPACM_LOG(IPACM_LOG_DEBUG,"protocol: %d\n", nat_rule.protocol);
			IPACM_LOG(IPACM_LOG_DEBUG,"pdn index: %d\n", nat_rule.pdn_index);
		}

	}

	return IPACM_SUCCESS;
}
#endif
int NatApp::AddTable(uint32_t pub_ip, uint8_t mux_id, bool is_sta)
{
	int ret;
	int cnt = 0;
	ipa_nat_ipv4_rule nat_rule;
	IPACM_LOG(IPACM_LOG_DEBUG, "Input params: IP: 0x%x, Mux: %d, is_sta %d\n", pub_ip, mux_id, is_sta);

	/* Not reset the cache wait it timeout by destroy event */
#if 0
	if (pub_ip != pub_ip_addr_pre)
	{
		IPACM_LOG(IPACM_LOG_DEBUG,"Reset the cache because NAT-ipv4 different\n");
		memset(cache, 0, sizeof(nat_table_entry) * max_entries);
		curCnt = 0;
	}
#endif
	ret = ipa_nat_add_ipv4_tbl(pub_ip, mem_type, max_entries, &nat_table_hdl);
	if(ret)
	{
		IPACM_LOG(IPACM_LOG_ERR, "unable to create nat table Error:%d\n", ret);
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
			IPACM_LOG(IPACM_LOG_ERR, "unable to modify PDN 0 entry Error:%d INIT_HDR_METADATA register values will be used!\n", ret);
		}
	}

	/* Add back the cached NAT-entry */
	if (pub_ip == pub_ip_addr_pre)
	{
		IPACM_LOG(IPACM_LOG_DEBUG, "Restore the cache to ipa NAT-table\n");
		for(cnt = 0; cnt < max_entries; cnt++)
		{
			if((cache[cnt].private_ip !=0))
			{
				if(is_sta && (isAlgPort(cache[cnt].protocol, cache[cnt].private_port) ||
					isAlgPort(cache[cnt].protocol, cache[cnt].target_port))) {
					IPACM_LOG(IPACM_LOG_ERR, "STA backhaul: connection using ALG Port, ignore\n");
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
					IPACM_LOG(IPACM_LOG_ERR, "unable to add the rule delete from cache\n");
					memset(&cache[cnt], 0, sizeof(cache[cnt]));
					curCnt--;
					continue;
				}
				IPACM_LOG(IPACM_LOG_DEBUG,"cache entry %d rule handle %d\n", cnt, cache[cnt].rule_hdl);
				cache[cnt].enabled = true;

				IPACM_LOG(IPACM_LOG_DEBUG,"On wan-iface reset added below rule successfully\n");
				iptodot("Private IP", nat_rule.private_ip);
				iptodot("Target IP", nat_rule.target_ip);
				IPACM_LOG(IPACM_LOG_DEBUG,"Private Port:%d \t Target Port: %d\n", nat_rule.private_port, nat_rule.target_port);
				IPACM_LOG(IPACM_LOG_DEBUG,"Public Port:%d\n", nat_rule.public_port);
				IPACM_LOG(IPACM_LOG_DEBUG,"protocol: %d\n", nat_rule.protocol);
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
	ipa_nat_pdn_entry entry;

	CHK_TBL_HDL();

	IPACM_LOG(IPACM_LOG_INFO, "Remove PDN IP: 0x%x\n", pub_ip);

	ret = ipa_nat_get_pdn_index(pub_ip, &pdn_index);
	if(ret)
	{
		IPACM_LOG(IPACM_LOG_ERR, "pdn doesn't exist on pdn table\n");
		return IPACM_FAILURE;
	}
	IPACM_LOG(IPACM_LOG_INFO, "pdn ip 0x%x found at pdn_index:%d\n", pub_ip, pdn_index);
	/* remove all PDN entries */
	for(int cnt = 0; cnt < max_entries; cnt++)
	{
		if((cache[cnt].pdn_index == pdn_index) &&
			(cache[cnt].enabled == true))
		{
			if(ipa_nat_del_ipv4_rule(nat_table_hdl, cache[cnt].rule_hdl) < 0)
			{
				IPACM_LOG(IPACM_LOG_ERR, "unable to delete rule with private ip 0x%X\n", cache[cnt].private_ip);
				continue;
			}
			memset(&cache[cnt], 0, sizeof(cache[cnt]));
		}
	}

	ret = ipa_nat_dealloc_pdn(pdn_index);
	if(ret)
	{
		IPACM_LOG(IPACM_LOG_ERR, "ERROR: couldn't deallocate PDN in index %d Error:%d\n\n",pdn_index, ret);
		return IPACM_FAILURE;
	}

	ret = ipa_nat_get_pdn_count(&pdn_cnt);
	if(ret)
	{
		IPACM_LOG(IPACM_LOG_ERR, " couldn't acquire number of PDNs\n");
		return IPACM_FAILURE;
	}

	if(!pdn_cnt)
	{
		ret = ipa_nat_del_ipv4_tbl(nat_table_hdl);
		if(ret)
		{
			IPACM_LOG(IPACM_LOG_INFO, "ERROR:unable to delete nat table Error: %d\n", ret);
			return ret;
		}
		IPACM_LOG(IPACM_LOG_INFO, "NAT table with PDN index: %d and IP: 0x%x deleted\n", pdn_index, pub_ip);
		Reset();
	}

	return 0;
}
#endif

int NatApp::DeleteTable(uint32_t pub_ip)
{
	int ret;
	IPACM_LOG(IPACM_LOG_DEBUG, "%s() %d\n", __FUNCTION__, __LINE__);

	CHK_TBL_HDL();

	if(pub_ip_addr != pub_ip)
	{
		IPACM_LOG(IPACM_LOG_WARN, "unable to delete the nat table\n");
		return -1;
	}

	ret = ipa_nat_del_ipv4_tbl(nat_table_hdl);
	if(ret)
	{
		IPACM_LOG(IPACM_LOG_ERR, "unable to delete nat table Error: %d\n", ret);;
		return ret;
	}

	pub_ip_addr_pre = pub_ip_addr;
	Reset();
	return 0;
}

/* Check for duplicate entries */
bool NatApp::ChkForDup(const nat_table_entry *rule)
{
	int cnt = 0;
	IPACM_LOG(IPACM_LOG_DEBUG,"%s() %d\n", __FUNCTION__, __LINE__);

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

/* Delete the entry from Nat table on connection close */
int NatApp::DeleteEntry(const nat_table_entry *rule)
{
	int cnt = 0;
	IPACM_LOG(IPACM_LOG_DEBUG,"%s() %d\n", __FUNCTION__, __LINE__);

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
					IPACM_LOG(IPACM_LOG_ERR, "%s() %d deletion failed\n", __FUNCTION__, __LINE__);
				}
				else
				{
					IPACM_LOG(IPACM_LOG_INFO, "Deleted Nat entry(%d) Successfully\n", cnt);
				}
			}
			else
			{
				IPACM_LOG(IPACM_LOG_DEBUG, "Deleted Nat entry(%d) only from cache\n", cnt);
			}

			memset(&cache[cnt], 0, sizeof(cache[cnt]));
			curCnt--;
			break;
		}
	}

	return 0;
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

	IPACM_LOG(IPACM_LOG_DEBUG,"%s() %d\n", __FUNCTION__, __LINE__);

	CHK_TBL_HDL();
	log_nat(rule->protocol,rule->private_ip,rule->target_ip,rule->private_port,\
	rule->public_port,rule->target_port,rule->src_only,rule->dst_only,"for addition\n");

	if(rule->private_ip == 0 ||
		 rule->target_ip == 0 ||
		 rule->private_port == 0  ||
		 rule->target_port == 0 ||
		 rule->protocol == 0)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Invalid Connection, ignoring it\n");
		return 0;
	}
#ifdef FEATURE_VLAN_MPDN
	if(ipa_nat_get_pdn_index(rule->public_ip, &pdn_index))
	{
		if(isVlan)
		{
			IPACM_LOG(IPACM_LOG_DEBUG, "vlan iface doesn't have a valid pdn, only moving to cache");
			iptodot("private ip", rule->private_ip);
			iptodot("target ip", rule->target_ip);
			iptodot("public ip", rule->public_ip);
			cacheOnly = true;
		}
		else
		{
			IPACM_LOG(IPACM_LOG_ERR, "couldn't acquire PDN index for public ip 0x%X\n", rule->public_ip);
			return IPACM_FAILURE;
		}
	}
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
				IPACM_LOG(IPACM_LOG_DEBUG, "found free cache entry %d\n", cnt);
				break;
			}
		}

		if(max_entries == cnt)
		{
			IPACM_LOG(IPACM_LOG_ERR, "Error: Unable to add, reached maximum rules\n");
			return -1;
		}
		else
		{
			memset(&nat_rule, 0, sizeof(nat_rule));
			nat_rule.private_ip = rule->private_ip;
			nat_rule.target_ip = rule->target_ip;
			nat_rule.target_port = rule->target_port;
			nat_rule.private_port = rule->private_port;
			nat_rule.public_port = rule->public_port;
			nat_rule.protocol = rule->protocol;

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
					IPACM_LOG(IPACM_LOG_DEBUG,"only caching vlan rule\n");
				}
				else
#endif
				{
					IPACM_LOG(IPACM_LOG_DEBUG,"Device is Power Save mode: Dont insert into nat table but cache\n");
				}
				cache[cnt].enabled = false;
				cache[cnt].rule_hdl = 0;
			}
			else
			{
				if(ipa_nat_add_ipv4_rule(nat_table_hdl, &nat_rule, &cache[cnt].rule_hdl) < 0)
				{
					IPACM_LOG(IPACM_LOG_ERR, "unable to add the rule\n");
					return -1;
				}
				log_nat_syslog(nat_rule.protocol,nat_rule.private_ip,nat_rule.target_ip,\
						nat_rule.private_port, nat_rule.public_port, \
						nat_rule.target_port, nat_rule.src_only,\
						nat_rule.dst_only, cache[cnt].rule_hdl);
				IPACM_LOG(IPACM_LOG_DEBUG, "cache entry %d rule handle %d\n", cnt, cache[cnt].rule_hdl);
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
			curCnt++;
		}

	}
	else
	{
		IPACM_LOG(IPACM_LOG_WARN, "Duplicate rule. Ignore it\n");
		return -1;
	}

	if(cache[cnt].enabled == true)
	{
		IPACM_LOG(IPACM_LOG_DEBUG, "Added rule(%d) successfully handle (%d)\n", cnt, cache[cnt].rule_hdl);
	}
	else
	{
		IPACM_LOG(IPACM_LOG_DEBUG, "Cached rule(%d) successfully\n", cnt);
	}

	return 0;
}

void NatApp::UpdateCTUdpTs(nat_table_entry *rule, uint32_t new_ts)
{
	int ret;

	iptodot("Private IP:", rule->private_ip);
	iptodot("Target IP:",  rule->target_ip);
	IPACM_LOG(IPACM_LOG_DEBUG,"Private Port: %d, Target Port: %d\n", rule->private_port, rule->target_port);

	if(!ct_hdl)
	{
		ct_hdl = nfct_open(CONNTRACK, 0);
		if(!ct_hdl)
		{
			perror("nfct_open");
			IPACM_LOG(IPACM_LOG_ERR, "nfct_open");
			return;
		}
	}

	if(!ct)
	{
		ct = nfct_new();
		if(!ct)
		{
			perror("nfct_new");
			IPACM_LOG(IPACM_LOG_ERR, "nfct_new");
			return;
		}
	}

	nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
	if(rule->protocol == IPPROTO_UDP)
	{
		nfct_set_attr_u8(ct, ATTR_L4PROTO, rule->protocol);
		nfct_set_attr_u32(ct, ATTR_TIMEOUT, udp_timeout);
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

		IPACM_LOG(IPACM_LOG_DEBUG,"dst nat is not set\n");
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

		IPACM_LOG(IPACM_LOG_DEBUG,"dst nat is set\n");
	}

	iptodot("Source IP:", nfct_get_attr_u32(ct, ATTR_IPV4_SRC));
	iptodot("Destination IP:",  nfct_get_attr_u32(ct, ATTR_IPV4_DST));
	IPACM_LOG(IPACM_LOG_DEBUG,"Source Port: %d, Destination Port: %d\n",
					 nfct_get_attr_u16(ct, ATTR_PORT_SRC), nfct_get_attr_u16(ct, ATTR_PORT_DST));

	IPACM_LOG(IPACM_LOG_DEBUG,"updating %d connection with time: %d\n",
					 rule->protocol, nfct_get_attr_u32(ct, ATTR_TIMEOUT));

	ret = nfct_query(ct_hdl, NFCT_Q_UPDATE, ct);
	if(ret == -1)
	{
		IPACM_LOG(IPACM_LOG_ERR, "unable to update time stamp");
		DeleteEntry(rule);
	}
	else
	{
		rule->timestamp = new_ts;
		IPACM_LOG(IPACM_LOG_DEBUG,"Updated time stamp successfully\n");
	}

	return;
}

void NatApp::UpdateUDPTimeStamp()
{
	int cnt;
	uint32_t ts;
	bool read_to = false;
	bool keep_awake;
	uint32_t redirect;

	keep_awake = ( max_entries && SRAM_IN_USE() && ipa_nat_is_sram_supported() );

	if ( keep_awake )
	{
		IPACM_LOG(IPACM_LOG_DEBUG, "Voting clock on\n");

		if ( ipa_nat_vote_clock(IPA_APP_CLK_VOTE) != 0 )
		{
			IPACM_LOG(IPACM_LOG_ERR, "Voting clock on failed\n");
			return;
		}
	}

	for(cnt = 0; cnt < max_entries; cnt++)
	{
		ts = 0;
		redirect = 0;
		if(cache[cnt].enabled == true &&
		   (cache[cnt].private_ip != cache[cnt].public_ip))
		{
			IPACM_LOG(IPACM_LOG_DEBUG,"\n");
			if(ipa_nat_query_timestamp_redirect(nat_table_hdl, cache[cnt].rule_hdl, &ts, &redirect) < 0)
			{
				IPACM_LOG(IPACM_LOG_WARN, "unable to retrieve timeout for rule handle: %d\n", cache[cnt].rule_hdl);
				continue;
			}

			if(redirect)
			{
				IPACM_LOG(IPACM_LOG_DEBUG,"Got RST/FIN req for connection, NAT entry redirect flag is %d\n", redirect);
				continue;
			}

			if(cache[cnt].timestamp == ts)
			{
				IPACM_LOG(IPACM_LOG_DEBUG,"No Change in Time Stamp: cahce:%d, ipahw:%d\n",
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
		IPACM_LOG(IPACM_LOG_DEBUG, "Voting clock off\n");

		if ( ipa_nat_vote_clock(IPA_APP_CLK_DEVOTE) != 0 )
		{
			IPACM_LOG(IPACM_LOG_ERR, "Voting clock off failed\n");
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
	IPACM_LOG(IPACM_LOG_DEBUG, "Received IP address: 0x%x\n", client_lan_ip);

	if(client_lan_ip == INVALID_IP_ADDR)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Invalid ip address received\n");
		return -1;
	}

	/* check for duplicate events */
	for(cnt = 0; cnt < IPA_MAX_NUM_WIFI_CLIENTS; cnt++)
	{
		if(PwrSaveIfs[cnt] == client_lan_ip)
		{
			IPACM_LOG(IPACM_LOG_DEBUG,"The client 0x%x is already in power save\n", client_lan_ip);
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
				IPACM_LOG(IPACM_LOG_ERR, "unable to delete the rule\n");
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

	IPACM_LOG(IPACM_LOG_DEBUG, "Received ip address: 0x%x\n", client_lan_ip);

	if(client_lan_ip == INVALID_IP_ADDR)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Invalid ip address received\n");
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
		IPACM_LOG(IPACM_LOG_DEBUG,"cache (%d): enable %d, ip 0x%x\n", cnt, cache[cnt].enabled, cache[cnt].private_ip);

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
			nat_rule.pdn_index = cache[cnt].pdn_index;
#endif

			if(ipa_nat_add_ipv4_rule(nat_table_hdl, &nat_rule, &cache[cnt].rule_hdl) < 0)
			{
				IPACM_LOG(IPACM_LOG_ERR, "unable to add the rule delete from cache\n");
				memset(&cache[cnt], 0, sizeof(cache[cnt]));
				curCnt--;
				continue;
			}

			IPACM_LOG(IPACM_LOG_DEBUG, "cache entry %d rule handle %d\n", cnt, cache[cnt].rule_hdl);
			cache[cnt].enabled = true;

			IPACM_LOG(IPACM_LOG_DEBUG,"On power reset added below rule successfully\n");
			iptodot("Private IP", nat_rule.private_ip);
			iptodot("Target IP", nat_rule.target_ip);
			IPACM_LOG(IPACM_LOG_DEBUG,"Private Port:%d \t Target Port: %d\n", nat_rule.private_port, nat_rule.target_port);
			IPACM_LOG(IPACM_LOG_DEBUG,"Public Port:%d\n", nat_rule.public_port);
			IPACM_LOG(IPACM_LOG_DEBUG,"protocol: %d\n", nat_rule.protocol);

		}
	}

	return 0;
}

void NatApp::AddTempEntry(const nat_table_entry *new_entry)
{
	int cnt;

	IPACM_LOG(IPACM_LOG_DEBUG,"Received below Temp Nat entry\n");
	iptodot("Private IP", new_entry->private_ip);
	iptodot("Target IP", new_entry->target_ip);
	IPACM_LOG(IPACM_LOG_DEBUG,"Private Port: %d\t Target Port: %d\t", new_entry->private_port, new_entry->target_port);
	IPACM_LOG(IPACM_LOG_DEBUG,"protocol: %d\n", new_entry->protocol);

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
			IPACM_LOG(IPACM_LOG_DEBUG,"Received duplicate Temp entry\n");
			return;
		}
	}

	for(cnt=0; cnt<MAX_TEMP_ENTRIES; cnt++)
	{
		if(temp[cnt].private_ip == 0 &&
			 temp[cnt].target_ip == 0)
		{
			memcpy(&temp[cnt], new_entry, sizeof(nat_table_entry));
			IPACM_LOG(IPACM_LOG_DEBUG,"Added Temp Entry\n");
			return;
		}
	}

	IPACM_LOG(IPACM_LOG_DEBUG,"Unable to add temp entry, cache full\n");
	return;
}

void NatApp::DeleteTempEntry(const nat_table_entry *entry)
{
	int cnt;

	IPACM_LOG(IPACM_LOG_DEBUG,"Received below nat entry\n");
	iptodot("Private IP", entry->private_ip);
	iptodot("Target IP", entry->target_ip);
	IPACM_LOG(IPACM_LOG_DEBUG,"Private Port: %d\t Target Port: %d\n", entry->private_port, entry->target_port);
	IPACM_LOG(IPACM_LOG_DEBUG,"protocol: %d\n", entry->protocol);

	for(cnt=0; cnt<MAX_TEMP_ENTRIES; cnt++)
	{
		if(temp[cnt].private_ip == entry->private_ip &&
			 temp[cnt].target_ip == entry->target_ip &&
			 temp[cnt].private_port ==  entry->private_port  &&
			 temp[cnt].target_port == entry->target_port &&
			 temp[cnt].protocol == entry->protocol)
		{
			memset(&temp[cnt], 0, sizeof(nat_table_entry));
			IPACM_LOG(IPACM_LOG_DEBUG,"Delete Temp Entry\n");
			return;
		}
	}

	IPACM_LOG(IPACM_LOG_DEBUG,"No Such Temp Entry exists\n");
	return;
}

#ifdef FEATURE_VLAN_MPDN
void NatApp::FlushAndCacheVlanTempEntries(uint32_t ip_addr, bool *entry_exists, uint32_t *public_ip)
{
	int cnt;
	int ret;

	IPACM_LOG(IPACM_LOG_DEBUG,"searching temp entries for ");
	iptodot("IP Address: ", ip_addr);
	if(!entry_exists)
	{
		IPACM_LOG(IPACM_LOG_ERR, "got NULL for entry_exists\n");
		return;
	}

	if(!public_ip)
	{
		IPACM_LOG(IPACM_LOG_ERR, "got NULL for public_ip\n");
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
				IPACM_LOG(IPACM_LOG_ERR, "unable to add temp entry: %d\n", ret);
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

	IPACM_LOG(IPACM_LOG_DEBUG, "Received below with isAdd:%d ", isAdd);
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
						IPACM_LOG(IPACM_LOG_DEBUG,"Flushing dummy temp rule");
						iptodot("Private IP", temp[cnt].private_ip);
					}

					ret = AddEntry(&temp[cnt]);
					if(ret)
					{
						IPACM_LOG(IPACM_LOG_ERR, "unable to add temp entry: %d\n", ret);
						continue;
					}
				}
			}
			memset(&temp[cnt], 0, sizeof(nat_table_entry));
		}
	}

	return;
}

int NatApp::DelEntriesOnClntDiscon(uint32_t ip_addr)
{
	int cnt, tmp = 0;
	IPACM_LOG(IPACM_LOG_DEBUG, "Received IP address: 0x%x\n", ip_addr);

	if(ip_addr == INVALID_IP_ADDR)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Invalid ip address received\n");
		return -1;
	}

	for(cnt = 0; cnt < IPA_MAX_NUM_WIFI_CLIENTS; cnt++)
	{
		if(PwrSaveIfs[cnt] == ip_addr)
		{
			PwrSaveIfs[cnt] = 0;
			IPACM_LOG(IPACM_LOG_DEBUG,"Remove %d power save entry\n", cnt);
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
					IPACM_LOG(IPACM_LOG_ERR, "unable to delete the rule\n");
					continue;
				}
				else
				{
					IPACM_LOG(IPACM_LOG_DEBUG,"won't delete the rule\n");
					cache[cnt].enabled = false;
					tmp++;
				}
			}
			IPACM_LOG(IPACM_LOG_DEBUG,"won't delete the rule for entry %d, enabled %d\n",cnt, cache[cnt].enabled);
		}
	}

	IPACM_LOG(IPACM_LOG_DEBUG,"Deleted (but cached) %d entries\n", tmp);
	return 0;
}

int NatApp::DelEntriesOnSTAClntDiscon(uint32_t ip_addr)
{
	int cnt, tmp = curCnt;
	IPACM_LOG(IPACM_LOG_DEBUG, "Received IP address: 0x%x\n", ip_addr);

	if(ip_addr == INVALID_IP_ADDR)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Invalid ip address received\n");
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
					IPACM_LOG(IPACM_LOG_ERR, "unable to delete the rule\n");
					continue;
				}
			}

			memset(&cache[cnt], 0, sizeof(cache[cnt]));
			curCnt--;
		}
	}

	IPACM_LOG(IPACM_LOG_DEBUG,"Deleted %d entries\n", (tmp - curCnt));
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
		IPACM_LOG(IPACM_LOG_ERR, "Invalid Connection, ignoring it\n");
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
			IPACM_LOG(IPACM_LOG_ERR, "Error: Unable to add, reached maximum rules\n");
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
			curCnt++;
		}

	}
	else
	{
		IPACM_LOG(IPACM_LOG_ERR, "Duplicate rule. Ignore it\n");
		return;
	}

	IPACM_LOG(IPACM_LOG_DEBUG,"Cached rule(%d) successfully\n", cnt);
	return;
}

void NatApp::Read_TcpUdp_Timeout(void) {
#ifdef FEATURE_IPA_ANDROID
	tcp_timeout = 432000;
	udp_timeout = 180;
	IPACM_LOG(IPACM_LOG_DEBUG, "udp timeout value: %d\n", udp_timeout);
	IPACM_LOG(IPACM_LOG_DEBUG, "tcp timeout value: %d\n", tcp_timeout);
#else
	tcp_timeout = 3600;
	udp_timeout = 60;
	IPACM_LOG(IPACM_LOG_DEBUG, "udp timeout value: %d\n", udp_timeout);
	IPACM_LOG(IPACM_LOG_DEBUG, "tcp timeout value: %d\n", tcp_timeout);
	FILE *udp_fd = NULL, *tcp_fd = NULL;
	char kernel_ver[KERNEL_VERSION_LENGTH];

	if (kernel_ver_updated == false) {

		get_kernel_version(kernel_ver);

		IPACM_LOG(IPACM_LOG_DEBUG, "Kernel Version %s\n", kernel_ver);

		is_kernel_ver_upgraded = is_kernel_version_newer_than(kernel_ver,
		KERNEL_VERSION_4_9);

		kernel_ver_updated = true;

		IPACM_LOG(IPACM_LOG_DEBUG, "Kernel Version %s compare to %s\n",
			is_kernel_ver_upgraded?"upgraded":"non upgraded", KERNEL_VERSION_4_9);
	}

	if (is_kernel_ver_upgraded) {
		/* Read UDP timeout value */
		udp_fd = fopen(IPACM_UDP_FULL_FILE_NAME_NEW, "r");
		if (udp_fd == NULL) {
			IPACM_LOG(IPACM_LOG_ERR, "unable to open %s\n", IPACM_UDP_FULL_FILE_NAME_NEW);
			goto fail;
		}
	} else {
		/* Read UDP timeout value */
		udp_fd = fopen(IPACM_UDP_FULL_FILE_NAME, "r");
		if (udp_fd == NULL) {
			IPACM_LOG(IPACM_LOG_ERR, "unable to open %s\n", IPACM_UDP_FULL_FILE_NAME);
			goto fail;
		}
	}

	if (fscanf(udp_fd, "%d", &udp_timeout) != 1) {
		IPACM_LOG(IPACM_LOG_ERR, "Error reading udp timeout\n");
	}
	IPACM_LOG(IPACM_LOG_DEBUG, "udp timeout value: %d\n", udp_timeout);

	if (is_kernel_ver_upgraded) {
		/* Read TCP timeout value */
		tcp_fd = fopen(IPACM_TCP_FULL_FILE_NAME_NEW, "r");
		if (tcp_fd == NULL) {
			IPACM_LOG(IPACM_LOG_ERR, "unable to open %s\n", IPACM_TCP_FULL_FILE_NAME_NEW);
			goto fail;
		}
	} else {
		/* Read TCP timeout value */
		tcp_fd = fopen(IPACM_TCP_FULL_FILE_NAME, "r");
		if (tcp_fd == NULL) {
			IPACM_LOG(IPACM_LOG_ERR, "unable to open %s\n", IPACM_TCP_FULL_FILE_NAME);
			goto fail;
		}
	}

	if (fscanf(tcp_fd, "%d", &tcp_timeout) != 1) {
		IPACM_LOG(IPACM_LOG_ERR, "Error reading tcp timeout\n");
	}
	IPACM_LOG(IPACM_LOG_DEBUG, "tcp timeout value: %d\n", tcp_timeout);

fail:
	if (udp_fd) {
		fclose(udp_fd);
	}
	if (tcp_fd) {
		fclose(tcp_fd);
	}
#endif //FEATURE_IPA_ANDROID
	return;
}

IpAddress::IpAddress(ipa_ip_type type) : m_type(type) {}

IpAddress::~IpAddress() {}

Ipv6IpAddress::Ipv6IpAddress() : IpAddress(IPA_IP_v6), m_msb(0), m_lsb(0) {}

Ipv6IpAddress::Ipv6IpAddress(const uint32_t* addr, bool inputNetworkEndianness) :
	IpAddress(IPA_IP_v6),
	m_msb(Convert2x32to64(addr, inputNetworkEndianness)),
	m_lsb(Convert2x32to64(addr + 2, inputNetworkEndianness))
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
}

bool Ipv6IpAddress::Compare(const IpAddress& other) const
{
	if (other.GetType() != IPA_IP_v6)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Wrong IP type\n");
		return false;
	}

	const Ipv6IpAddress& ip = static_cast<const Ipv6IpAddress&>(other);
	bool ret = m_lsb == ip.m_lsb && m_msb == ip.m_msb;
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return ret;
}

bool Ipv6IpAddress::IsSameSubnet(const IpAddress& other) const
{
	if (other.GetType() != IPA_IP_v6)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Wrong IP type\n");
		return false;
	}

	const Ipv6IpAddress& ip = static_cast<const Ipv6IpAddress&>(other);
	bool ret = m_msb == ip.m_msb;
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return ret;
}

void Ipv6IpAddress::Copy(const IpAddress& other)
{
	if (other.GetType() != IPA_IP_v6)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Wrong IP type\n");
		return;
	}

	const Ipv6IpAddress& ip = static_cast<const Ipv6IpAddress&>(other);
	m_msb = ip.m_msb;
	m_lsb = ip.m_lsb;
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

void Ipv6IpAddress::Clear()
{
	m_msb = 0;
	m_lsb = 0;
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

bool Ipv6IpAddress::Valid() const
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	return m_lsb != 0 || m_msb != 0;
}

void Ipv6IpAddress::DebugDump(const char* msg_prefix) const
{
	IPACM_LOG(IPACM_LOG_DEBUG, "%s IPv6 address 0x%llx%llx\n", msg_prefix, m_msb, m_lsb);
}

bool Ipv6IpAddress::IsSameSubnet(uint32_t* prefix) const
{
	return m_msb == Convert2x32to64(prefix, false);
}

void Ipv6IpAddress::CreateFromArray(const uint32_t* addr, bool inputNetworkEndianness)
{
	m_msb = Convert2x32to64(addr, inputNetworkEndianness);
	m_lsb = Convert2x32to64(addr + 2, inputNetworkEndianness);
	DebugDump("Ipv6IpAddress::CreateFromArray received");
}

void Ipv6IpAddress::ToArray(uint32_t* addr, bool outputNetworkEndianness) const
{
	Convert64to2x32(m_msb, addr, outputNetworkEndianness);
	Convert64to2x32(m_lsb, addr + 2, outputNetworkEndianness);
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

uint64_t Ipv6IpAddress::Convert2x32to64(const uint32_t* pair32, bool inputNetworkEndianness)
{
	uint32_t msb = pair32[0], lsb = pair32[1];
	if (inputNetworkEndianness)
	{
		msb = ntohl(msb);
		lsb = ntohl(lsb);
	}
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return static_cast<uint64_t>(msb) << 32 | lsb;
}

void Ipv6IpAddress::Convert64to2x32(uint64_t in, uint32_t* pair32, bool outputNetworkEndianness)
{
	pair32[0] = in >> 32;
	pair32[1] = static_cast<uint32_t>(in);
	if (outputNetworkEndianness)
	{
		pair32[0] = htonl(pair32[0]);
		pair32[1] = htonl(pair32[1]);
	}
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

NatEntryBase::NatEntryBase(ipa_ip_type type) :
	m_type(type),
	m_timestamp(0),
	m_direction(DirectionUnknown),
	m_ruleHandle(0),
	m_protocol(0),
	m_enabled(false),
	m_isDummy(false)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "%d \n", type);
}

NatEntryBase::~NatEntryBase() {}

bool NatEntryBase::Compare(const NatEntryBase& other) const
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	return m_protocol == other.m_protocol;
}

void NatEntryBase::Copy(const NatEntryBase& other)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	m_timestamp = other.m_timestamp;
	m_direction = other.m_direction;
	m_ruleHandle = other.m_ruleHandle;
	m_protocol = other.m_protocol;
	m_enabled = other.m_enabled;
	m_isDummy = other.m_isDummy;
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

void NatEntryBase::Clear()
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	m_timestamp = 0;
	m_direction = DirectionUnknown;
	m_ruleHandle = 0;
	m_protocol = 0;
	m_enabled = false;
	m_isDummy = false;
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

void NatEntryBase::DebugDump(const char* msg_prefix) const
{
	IPACM_LOG(IPACM_LOG_DEBUG, "%s protocol %d direction %s\n", msg_prefix, m_protocol, DirectionToStr(m_direction));
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
		IPACM_LOG(IPACM_LOG_DEBUG, "The direction already specified. Nothing to do\n");
		return true;
	}

	IPACM_LOG(IPACM_LOG_DEBUG, "The received client is%s an STA client\n", (isStaClientIp) ? "" : " not");
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

	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
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
		IPACM_LOG(IPACM_LOG_ERR, "Unsupported direction %d\n", direction);
	}
	return "unknown";
}

Ipv6ctEntry::Ipv6ctEntry() : NatEntryBase(IPA_IP_v6), m_dstPort(0), m_srcPort(0) {}

bool Ipv6ctEntry::Compare(const NatEntryBase& other) const
{
	if (other.m_type != IPA_IP_v6)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Wrong IP type\n");
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
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	if (other.m_type != IPA_IP_v6)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Wrong IP type\n");
		return;
	}

	NatEntryBase::Copy(other);

	const Ipv6ctEntry& entry = static_cast<const Ipv6ctEntry&>(other);
	m_srcAddr = entry.m_srcAddr;
	m_dstAddr = entry.m_dstAddr;
	m_dstPort = entry.m_dstPort;
	m_srcPort = entry.m_srcPort;
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

void Ipv6ctEntry::Clear()
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	NatEntryBase::Clear();

	m_srcAddr.Clear();
	m_dstAddr.Clear();
	m_dstPort = 0;
	m_srcPort = 0;
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

bool Ipv6ctEntry::Valid() const
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	return m_dstPort && m_srcPort && m_srcAddr.Valid() && m_dstAddr.Valid();
}

void Ipv6ctEntry::DebugDump(const char* msg_prefix) const
{
	NatEntryBase::DebugDump(msg_prefix);
	m_srcAddr.DebugDump("Source");
	m_dstAddr.DebugDump("Destination");
	IPACM_LOG(IPACM_LOG_DEBUG, "Source port %d\n", m_srcPort);
	IPACM_LOG(IPACM_LOG_DEBUG, "Destination port %d\n", m_dstPort);
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

CollectionBase::CollectionBase(int max_entries) : m_maxEntries(max_entries)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "max_entries %d\n", max_entries);
}

CollectionBase::~CollectionBase()
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
}

uint32_t ConntrackTimestampUtil::tcp_timeout = 432000;
uint32_t ConntrackTimestampUtil::udp_timeout = 180;
struct nf_conntrack* ConntrackTimestampUtil::ct = NULL;
struct nfct_handle* ConntrackTimestampUtil::ct_hdl = NULL;

ConntrackTimestampUtil::ConntrackTimestampUtil()
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
}

ConntrackTimestampUtil::~ConntrackTimestampUtil() {}

void ConntrackTimestampUtil::Init()
{
	if (ct_hdl == NULL)
	{
		ct_hdl = nfct_open(CONNTRACK, 0);
		if (ct_hdl == NULL)
		{
			perror("nfct_open");
			IPACM_LOG(IPACM_LOG_ERR, "nfct_open");
			return;
		}
	}

	if (ct == NULL)
	{
		ct = nfct_new();
		if (ct == NULL)
		{
			perror("nfct_new");
			IPACM_LOG(IPACM_LOG_ERR, "nfct_new");
			return;
		}
	}

	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

#ifndef FEATURE_IPA_ANDROID
/*
 * ConntrackTimestampUtil::ReadTcpUdpTimeout() is equivalent to NatApp::Read_TcpUdp_Timeout()
 *
 * NOTE: Kernel version check is omitted from the function, because the function is called only if IPv6CT is enabled.
 */
void ConntrackTimestampUtil::ReadTcpUdpTimeout()
{
	FILE *udp_fd = NULL, *tcp_fd = NULL;

	/* Read UDP timeout value */
	udp_fd = fopen(IPACM_UDP_FULL_FILE_NAME_NEW, "r");
	if (udp_fd == NULL)
	{
		IPACM_LOG(IPACM_LOG_ERR, "unable to open %s\n", IPACM_UDP_FULL_FILE_NAME_NEW);
		goto bail;
	}

	if (fscanf(udp_fd, "%d", &udp_timeout) != 1)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Error reading udp timeout\n");
	}
	IPACM_LOG(IPACM_LOG_DEBUG, "udp timeout value: %d\n", udp_timeout);

	/* Read TCP timeout value */
	tcp_fd = fopen(IPACM_TCP_FULL_FILE_NAME_NEW, "r");
	if (tcp_fd == NULL)
	{
		IPACM_LOG(IPACM_LOG_ERR, "unable to open %s\n", IPACM_TCP_FULL_FILE_NAME_NEW);
		goto bail;
	}

	if (fscanf(tcp_fd, "%d", &tcp_timeout) != 1)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Error reading tcp timeout\n");
	}
	IPACM_LOG(IPACM_LOG_DEBUG, "tcp timeout value: %d\n", tcp_timeout);

bail:
	if (udp_fd != NULL)
	{
		fclose(udp_fd);
	}
	if (tcp_fd != NULL)
	{
		fclose(tcp_fd);
	}

	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}
#endif

int ConntrackTimestampUtil::UpdateConntrackTimeStamp(const NatEntryBase& entry)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");

	entry.DebugDump("Going to update timestamp for following entry");

	nfct_set_attr_u8(ct, ATTR_L4PROTO, entry.m_protocol);
	nfct_set_attr_u32(ct, ATTR_TIMEOUT, (entry.m_protocol == IPPROTO_UDP) ? udp_timeout : tcp_timeout);

	SetConnectionDetails(entry);

	int ret = nfct_query(ct_hdl, NFCT_Q_UPDATE, ct);

	IPACM_LOG(IPACM_LOG_DEBUG, "return value %d\n", ret);
	return ret;
}

void Ipv6ctConntrackTimestampUtil::SetConnectionDetails(const NatEntryBase& entry)
{
	if (entry.m_type != IPA_IP_v6)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Wrong IP type\n");
		return;
	}

	uint16_t src_port, dst_port;
	struct nfct_attr_grp_ipv6 attr_grp;
	const Ipv6ctEntry& ipv6_entry = static_cast<const Ipv6ctEntry&>(entry);

	switch (ipv6_entry.m_direction)
	{
	case NatEntryBase::DirectionOutbound:
		ipv6_entry.m_srcAddr.ToArray(attr_grp.src, true);
		src_port = ipv6_entry.m_srcPort;

		ipv6_entry.m_dstAddr.ToArray(attr_grp.dst, true);
		dst_port = ipv6_entry.m_dstPort;
		break;
	case NatEntryBase::DirectionInbound:
		ipv6_entry.m_srcAddr.ToArray(attr_grp.dst, true);
		src_port = ipv6_entry.m_dstPort;

		ipv6_entry.m_dstAddr.ToArray(attr_grp.src, true);
		dst_port = ipv6_entry.m_srcPort;
		break;
	default:
		IPACM_LOG(IPACM_LOG_ERR, "Unknown direction in an offloaded connection\n");
		entry.DebugDump("Unknown direction in following connection\n");
		return;
	}

	nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6);
	nfct_set_attr_grp(ct, ATTR_GRP_ORIG_IPV6, &attr_grp);
	nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(src_port));
	nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(dst_port));

	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

NatProxyBase::NatProxyBase() : m_tableHandle(0) {}

NatProxyBase::~NatProxyBase() {}

int NatProxyBase::AddTable(uint16_t number_of_entries)
{
	uint32_t table_handle;
	int ret = DoAddTable(number_of_entries, table_handle);
	if (!ret)
	{
		m_tableHandle = table_handle;
	}
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return ret;
}

int NatProxyBase::DeleteTable()
{
	if (!m_tableHandle)
	{
		IPACM_LOG(IPACM_LOG_ERR, "The table wasn't allocated by AddTable\n");
		return -EINVAL;
	}

	int ret = DoDeleteTable();
	m_tableHandle = 0;
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return ret;
}

int NatProxyBase::AddEntry(NatEntryBase& entry)
{
	if (!m_tableHandle)
	{
		IPACM_LOG(IPACM_LOG_ERR, "The table wasn't allocated by AddTable\n");
		return -EINVAL;
	}

	uint32_t entry_handle;
	int ret = DoAddEntry(entry, entry_handle);
	if (!ret)
	{
		entry.m_ruleHandle = entry_handle;
		entry.m_timestamp = 0;
		entry.m_enabled = true;
	}
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return ret;
}

int NatProxyBase::DelEntry(NatEntryBase& entry)
{
	if (!m_tableHandle)
	{
		IPACM_LOG(IPACM_LOG_ERR, "The table wasn't allocated by AddTable\n");
		return -EINVAL;
	}

	int ret = DoDelEntry(entry);
	entry.Clear();
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return ret;
}

int Ipv6ctProxy::DoAddTable(uint16_t number_of_entries, uint32_t& table_handle)
{
	int ret = ipa_ipv6ct_add_tbl(number_of_entries, &table_handle);
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return ret;
}

int Ipv6ctProxy::DoDeleteTable()
{
	int ret = ipa_ipv6ct_del_tbl(m_tableHandle);
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return ret;
}

int Ipv6ctProxy::DoAddEntry(const NatEntryBase& entry, uint32_t& entry_handle)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	if (entry.m_type != IPA_IP_v6)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Wrong IP type\n");
		return -EINVAL;
	}

	ipa_ipv6ct_rule rule;
	const Ipv6ctEntry& ipv6ct_entry = static_cast<const Ipv6ctEntry&>(entry);
	rule.src_ipv6_lsb = ipv6ct_entry.m_srcAddr.GetLsb();
	rule.src_ipv6_msb = ipv6ct_entry.m_srcAddr.GetMsb();
	rule.dest_ipv6_lsb = ipv6ct_entry.m_dstAddr.GetLsb();
	rule.dest_ipv6_msb = ipv6ct_entry.m_dstAddr.GetMsb();
	rule.direction_settings = IPA_IPV6CT_DIRECTION_ALLOW_ALL;
	rule.src_port = ipv6ct_entry.m_srcPort;
	rule.dest_port = ipv6ct_entry.m_dstPort;
	rule.protocol = ipv6ct_entry.m_protocol;
	if (IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_5) {
		rule.ucp = ipv6ct_entry.m_ucp;
		rule.uc_activation_index = ipv6ct_entry.m_uc_activation_index;
		rule.s = ipv6ct_entry.m_s;
	}
	int ret = ipa_ipv6ct_add_rule(m_tableHandle, &rule, &entry_handle);
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return ret;
}

int Ipv6ctProxy::DoDelEntry(const NatEntryBase& entry)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	if (entry.m_type != IPA_IP_v6)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Wrong IP type\n");
		return -EINVAL;
	}

	int ret = ipa_ipv6ct_del_rule(m_tableHandle, entry.m_ruleHandle);
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return ret;
}

int Ipv6ctProxy::QueryTimestamp(const NatEntryBase& entry, uint32_t& time_stamp) const
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	if (entry.m_type != IPA_IP_v6)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Wrong IP type\n");
		return -EINVAL;
	}

	int ret = ipa_ipv6ct_query_timestamp(m_tableHandle, entry.m_ruleHandle, &time_stamp);
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return ret;
}

void Ipv6ctProxy::DumpTable()
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	ipa_ipv6ct_dump_table(m_tableHandle);
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

NatObjectsGeneratorBase::NatObjectsGeneratorBase()
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
}

NatObjectsGeneratorBase::~NatObjectsGeneratorBase()
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
}

NatProxyBase& Ipv6ctObjectsGenerator::GetProxy() const
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	return *new Ipv6ctProxy;
}

NatEntriesCollectionBase& Ipv6ctObjectsGenerator::GetEntriesCollection(int max_entries) const
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	return *new Ipv6ctEntriesCollection(max_entries);
}

IpAddressesCollectionBase& Ipv6ctObjectsGenerator::GetIpAddressesCollection(int max_entries) const
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	return *new Ipv6IpAddressesCollection(max_entries);
}

IpAddress& Ipv6ctObjectsGenerator::GetIpAddress() const
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	return *new Ipv6IpAddress;
}

ConntrackTimestampUtil& Ipv6ctObjectsGenerator::GetConntrackTimestampUtil() const
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	return *new Ipv6ctConntrackTimestampUtil;
}

NatBase::NatBase(ipa_ip_type type, int max_entries, const NatObjectsGeneratorBase& objectsGenerator)
	:
	m_type(type),
	m_temp(objectsGenerator.GetEntriesCollection(MAX_TEMP_ENTRIES)),
	m_pwrSaveIfs(objectsGenerator.GetIpAddressesCollection(IPA_MAX_NUM_WIFI_CLIENTS)),
	m_maxEntries(max_entries),
	m_curCnt(0),
	m_proxy(objectsGenerator.GetProxy()),
	m_ctTimestampUtil(objectsGenerator.GetConntrackTimestampUtil()),
	m_cache(objectsGenerator.GetEntriesCollection(max_entries)),
	m_previousWanAddress(objectsGenerator.GetIpAddress())
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
}

NatBase::~NatBase()
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	delete &m_temp;
	delete &m_pwrSaveIfs;
	delete &m_proxy;
	delete &m_ctTimestampUtil;
	delete &m_cache;
	delete &m_previousWanAddress;
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

int NatBase::AddTable(const IpAddress& wan_ip)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	int ret = m_proxy.AddTable(m_maxEntries);
	if (ret)
	{
		IPACM_LOG(IPACM_LOG_ERR, "unable to create the table Error:%d\n", ret);
		return ret;
	}
#ifndef FEATURE_SOCKSv5
	/* Add back the cached NAT-entry */
	if (wan_ip == m_previousWanAddress)
	{
		IPACM_LOG(IPACM_LOG_INFO, "Restore the cache to ipa NAT-table\n");
		for (int cnt = 0; cnt < m_maxEntries; ++cnt)
		{
			NatEntryBase& entry = m_cache[cnt];
			if (entry.Valid())
			{
				if (m_proxy.AddEntry(entry))
				{
					IPACM_LOG(IPACM_LOG_ERR, "unable to add the rule delete from cache\n");
					entry.Clear();
					--m_curCnt;
					continue;
				}
				entry.DebugDump("On wan-iface reset added below rule successfully\n");
			}
		}
	}
#endif

	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return 0;
}

int NatBase::DeleteTable(const IpAddress& wan_addr)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	int ret = m_proxy.DeleteTable();
	if (ret)
	{
		IPACM_LOG(IPACM_LOG_ERR, "unable to delete the table Error: %d\n", ret);;
		return ret;
	}

	m_previousWanAddress = wan_addr;
	Reset();
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return 0;
}

int NatBase::AddEntry(const NatEntryBase& entry)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
#ifdef FEATURE_SOCKSv5
	Ipv6ctEntry new_entry;

	memcpy(&new_entry, &entry, sizeof(Ipv6ctEntry));

	if (m_proxy.AddEntry(new_entry))
	{
		IPACM_LOG(IPACM_LOG_ERR, "unable to add the v6-ct entry\n");
		return -EPERM;
	}
	IPACM_LOG(IPACM_LOG_DEBUG, "Added entry successfully handle (%d)\n", new_entry.m_ruleHandle);
	socksv5_v6_conn.push_front(new_entry);
#else
	entry.DebugDump("The new entry to add");

	if (!entry.Valid())
	{
		IPACM_LOG(IPACM_LOG_ERR, "Invalid Connection, ignoring it\n");
		return 0;
	}

	if (m_cache.Find(entry) != NULL)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Duplicate rule. Ignore it\n");
		return -EPERM;
	}

	NatEntryBase* new_entry = m_cache.GetFirstEmpty();
	if (new_entry == NULL)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Error: Unable to add, reached maximum rules\n");
		return -EPERM;
	}

	*new_entry = entry;

	if (m_pwrSaveIfs.Find(new_entry->GetClientIp()) != NULL || m_pwrSaveIfs.Find(new_entry->GetTargetIp()) != NULL)
	{
		IPACM_LOG(IPACM_LOG_DEBUG, "Device is Power Save mode: Don't send to HW but successfully cached\n");
	}
	else
	{
		if (m_proxy.AddEntry(*new_entry))
		{
			IPACM_LOG(IPACM_LOG_ERR, "unable to add the rule\n");
			new_entry->Clear();
			return -EPERM;
		}
		IPACM_LOG(IPACM_LOG_DEBUG, "Added entry successfully\n");
	}
#endif
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	++m_curCnt;
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return 0;
}

void NatBase::DeleteEntry(const NatEntryBase& entry)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
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
			IPACM_LOG(IPACM_LOG_DEBUG, "Found the matched handle (%d)\n",
				new_entry.m_ruleHandle);

			if (m_proxy.DelEntry(new_entry))
			{
				IPACM_LOG(IPACM_LOG_ERR, "unable to delete the v6-ct entry\n");
				return;
			}
			IPACM_LOG(IPACM_LOG_DEBUG, "Deleted entry successfully\n");

			/* delete the entry */
			socksv5_v6_conn.erase(it_mapping);
			break;
		}
	}

	if (it_mapping == socksv5_v6_conn.end())
	{
		IPACM_LOG(IPACM_LOG_ERR, "Can't find the matched socksv5_v6_conn!\n");
	}
#else
	entry.DebugDump("The entry to delete");

	NatEntryBase* entryDelete = m_cache.Find(entry);
	if (entryDelete == NULL)
	{
		IPACM_LOG(IPACM_LOG_DEBUG, "No Such Entry exists\n");
		return;
	}

	if (entryDelete->m_enabled)
	{
		if (m_proxy.DelEntry(*entryDelete))
		{
			IPACM_LOG(IPACM_LOG_ERR, "Deletion failed\n");
		}
		else
		{
			IPACM_LOG(IPACM_LOG_DEBUG, "Deleted NAT entry successfully\n");
		}
	}
	entryDelete->Clear();
#endif
	--m_curCnt;

	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

void NatBase::CacheEntry(const NatEntryBase& entry)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	entry.DebugDump("The new entry to cache");

	if (!entry.Valid())
	{
		IPACM_LOG(IPACM_LOG_ERR, "Invalid Connection, ignoring it\n");
		return;
	}

	if (m_cache.Find(entry) != NULL)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Duplicate rule. Ignore it\n");
		return;
	}

	NatEntryBase* new_entry = m_cache.GetFirstEmpty();
	if (new_entry == NULL)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Error: Unable to add, reached maximum rules\n");
		return;
	}

	*new_entry = entry;
	++m_curCnt;
	IPACM_LOG(IPACM_LOG_DEBUG, "Cached rule successfully\n");
}

void NatBase::AddTempEntry(const NatEntryBase& entry)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	entry.DebugDump("Received Temp Nat entry to add\n");

	if (m_cache.Find(entry) != NULL || m_temp.Find(entry) != NULL)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Duplicate rule. Ignore it\n");
		return;
	}

	NatEntryBase* new_entry = m_temp.GetFirstEmpty();
	if (new_entry == NULL)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Error: Unable to add, reached maximum temp rules\n");
		return;
	}

	*new_entry = entry;
	IPACM_LOG(IPACM_LOG_DEBUG, "Added Temp Entry\n");
}

void NatBase::DeleteTempEntry(const NatEntryBase& entry)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	entry.DebugDump("Received Temp Nat entry to delete\n");

	NatEntryBase* entryDelete = m_temp.Find(entry);
	if (entryDelete == NULL)
	{
		IPACM_LOG(IPACM_LOG_DEBUG, "No Such Temp Entry exists\n");
		return;
	}

	entryDelete->Clear();
	IPACM_LOG(IPACM_LOG_DEBUG, "The Temp Entry successfully deleted\n");
}

void NatBase::FlushTempEntries(const IpAddress& clientIp, bool isAdd, bool isDummy, bool isStaClientIp)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
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
				curr.m_isDummy = true;
			}

			int ret = AddEntry(curr);
			if (ret)
			{
				IPACM_LOG(IPACM_LOG_ERR, "unable to add temp entry: %d\n", ret);
				continue;
			}
			IPACM_LOG(IPACM_LOG_DEBUG, "Successfully flushed the entrty\n");
		}

		curr.Clear();
	}
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

void NatBase::UpdateTcpUdpTimeStamps(bool& isTcpUdpTimeoutUpToDate)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	int ret;
	uint32_t timestamp;

	for (int cnt = 0; cnt < m_maxEntries; ++cnt)
	{
		NatEntryBase& curr = m_cache[cnt];
		if (!curr.m_enabled || curr.m_isDummy)
		{
			continue;
		}

		if (m_proxy.QueryTimestamp(curr, timestamp))
		{
			IPACM_LOG(IPACM_LOG_ERR, "unable to retrieve timeout for rule handle: %d\n", curr.m_ruleHandle);
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
			IPACM_LOG(IPACM_LOG_ERR, "unable to update time stamp");
			m_proxy.DelEntry(curr);
			continue;
		}

		curr.m_timestamp = timestamp;
		IPACM_LOG(IPACM_LOG_DEBUG,"Updated time stamp successfully\n");
	}
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

int NatBase::UpdatePwrSaveIf(const IpAddress& client_lan_ip)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");

	client_lan_ip.DebugDump("Received");

	if (!client_lan_ip.Valid())
	{
		IPACM_LOG(IPACM_LOG_ERR, "Invalid ip address received\n");
		return -EINVAL;
	}

	if (m_pwrSaveIfs.Find(client_lan_ip) != NULL)
	{
		IPACM_LOG(IPACM_LOG_DEBUG,"The client is already in power save\n");
		return 0;
	}

	IpAddress* entry = m_pwrSaveIfs.GetFirstEmpty();
	if (entry == NULL)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Power save clients collection is full\n");
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
			IPACM_LOG(IPACM_LOG_ERR, "unable to delete the rule\n");
			continue;
		}

		curr.m_enabled = false;
		curr.m_ruleHandle = 0;
	}
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return 0;
}

int NatBase::ResetPwrSaveIf(const IpAddress& client_lan_ip)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	client_lan_ip.DebugDump("Received");

	if (!client_lan_ip.Valid())
	{
		IPACM_LOG(IPACM_LOG_ERR, "Invalid ip address received\n");
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
			IPACM_LOG(IPACM_LOG_ERR, "unable to add the rule delete from cache\n");
			curr.Clear();
			--m_curCnt;
			continue;
		}
		curr.m_enabled = true;
	}

	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return 0;
}

int NatBase::DelEntriesOnClntDiscon(const IpAddress& client_lan_ip)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");

	client_lan_ip.DebugDump("Received");

	if (!client_lan_ip.Valid())
	{
		IPACM_LOG(IPACM_LOG_ERR, "Invalid ip address received\n");
		return -EINVAL;
	}

	IpAddress* entry = m_pwrSaveIfs.Find(client_lan_ip);
	if (entry != NULL)
	{
		entry->Clear();
		IPACM_LOG(IPACM_LOG_DEBUG,"Remove power save entry\n");
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
			IPACM_LOG(IPACM_LOG_ERR, "unable to delete the rule\n");
			continue;
		}

		curr.m_enabled = false;
		++tmp;
	}

	IPACM_LOG(IPACM_LOG_DEBUG, "Deleted (but cached) %d entries\n", tmp);
	return 0;
}

int NatBase::DelEntriesOnSTAClntDiscon(const IpAddress& client_lan_ip)
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");

	client_lan_ip.DebugDump("Received");

	if (!client_lan_ip.Valid())
	{
		IPACM_LOG(IPACM_LOG_ERR, "Invalid ip address received\n");
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
			IPACM_LOG(IPACM_LOG_ERR, "unable to delete the rule\n");
			continue;
		}

		curr.Clear();
		--m_curCnt;
	}

	IPACM_LOG(IPACM_LOG_DEBUG, "Deleted %d entries\n", (tmp - m_curCnt));
	return 0;
}

void NatBase::Reset()
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	for (int cnt = 0; cnt < m_maxEntries; ++cnt)
	{
		m_cache[cnt].m_enabled = false;
	}
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
}

Ipv6ct* Ipv6ct::m_instance = NULL;

Ipv6ct* Ipv6ct::GetInstance()
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
	if (m_instance != NULL)
	{
		return m_instance;
	}

	IPACM_Config *pConfig = IPACM_Config::GetInstance();
	if (pConfig == NULL)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Unable to get Config instance\n");
		return NULL;
	}

	if (!pConfig->IsIpv6CTEnabled())
	{
		IPACM_LOG(IPACM_LOG_INFO, "IPv6 Connection tracking is disabled\n");
		return NULL;
	}

	m_instance = new Ipv6ct(pConfig->GetIpv6CTMaxEntries());
	IPACM_LOG(IPACM_LOG_DEBUG, "return\n");
	return m_instance;
}

Ipv6ct::Ipv6ct(int max_entries) : NatBase(IPA_IP_v6, max_entries, Ipv6ctObjectsGenerator())
{
	IPACM_LOG(IPACM_LOG_DEBUG, "\n");
}

