/*
Copyright (c) 2013-2020, The Linux Foundation. All rights reserved.
Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.

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
*
 * Changes from Qualcomm Innovation Center are provided under the following license:
 *
 * Copyright (c) 2022-2023 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted (subject to the limitations in the
 * disclaimer below) provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 *   * Neither the name of Qualcomm Innovation Center, Inc. nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE
 * GRANTED BY THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
 * HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

/* NatApp class Implementation. */
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
int NatApp::AddPdn(uint32_t pub_ip, uint8_t mux_id, bool is_sta)
{
	int ret = IPACM_SUCCESS;
	int cnt = 0;
	ipa_nat_ipv4_rule nat_rule;
	ipa_nat_pdn_entry entry;
	uint8_t pdn_index;
	uint8_t pdn_count = 0;
	IPACMDBG_H("%s() %d\n", __FUNCTION__, __LINE__);

	entry.dst_metadata = 0;
	entry.public_ip = 0;
	entry.is_sta = false;

	ret = ipa_nat_get_pdn_count(&pdn_count);
	if(ret)
	{
		IPACMERR("unable to get pdn count Error:%d\n", ret);
		return ret;
	}

	IPACMDBG_H("is_sta: %d, pdn_count: %d\n", is_sta, pdn_count);
	IPACMDBG_H("ipv4 address PDN 0x%X\n", pub_ip);

	if(!pdn_count)
	{
		/* create the NAT table, the PDN will be stored in index 0 */
		ret = ipa_nat_add_ipv4_tbl(entry.public_ip, mem_type, max_entries, &nat_table_hdl);
		if(ret)
		{
			IPACMERR("unable to create nat table Error:%d\n", ret);
			return ret;
		}
		IPACMDBG_H("succeesfully created NAT table for ip 0x%X\n", pub_ip);
		entry.public_ip = pub_ip;
		if(!is_sta)
		{
			entry.src_metadata = GenerateMetdata(mux_id);
			/* Modify PDN 1 so it will hold the mux ID in the src metadata field */
			pdn_index = 1;
		}
		else
		{
			/* Modify PDN 0 so it will hold the mux ID in the src metadata field */
			pdn_index = 0;
			entry.src_metadata = 0;
			entry.is_sta = true;
		}

		ret = ipa_nat_modify_pdn(nat_table_hdl, pdn_index, &entry);
		if(ret)
		{
			IPACMERR("unable to modify PDN %d entry Error:%d\n", pdn_index, ret);
			return ret;
		}
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
				IPACMERR("Unable to modify PDN 0 entry Error: %d\n", ret);
				return ret;
			}
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
					IPACMERR("couldn't allocate a pdn index\n");
					return ret;
				}
				IPACMDBG_H("successfully allocated index %d for ip 0x%X\n", pdn_index, pub_ip);
			}
			else
			{
				IPACMDBG_H("pdn already exists with index %d\n", pdn_index);
			}
		}
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
	ipa_nat_pdn_entry entry;
	IPACMDBG_H("%s() %d\n", __FUNCTION__, __LINE__);

	CHK_TBL_HDL();

	IPACMDBG_H("Remove PDN IP: 0x%x\n", pub_ip);
	ret = ipa_nat_get_pdn_index(pub_ip, &pdn_index);
	if(ret)
	{
		IPACMERR("pdn doesn't exist on pdn table\n");
		return IPACM_FAILURE;
	}
	IPACMDBG_H("pdn ip found at pdn_index:%d\n",pdn_index);
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

/* Check for sw allow entries */
bool NatApp::ChkSWAllow(const nat_table_entry *rule)
{
	int i, j;
	IPACM_extd_swallow_entry_conf_t entry;
	IPACM_swallow_t sw_filter_cfg;
	IPACMDBG("Entry\n");

	if(!IPACM_Iface::ipacmcfg->sw_filter_cfg || !IPACM_Iface::ipacmcfg->sw_allow_flag)
	{
		IPACMERR("SW Config not updated/pdn index not updated!\n");
		return false;
	}

	memcpy(&sw_filter_cfg, IPACM_Iface::ipacmcfg->sw_filter_cfg, sizeof(IPACM_swallow_t));

	for(i = 0; i < sw_filter_cfg.pdn_count;i++)
	{
		/* PDN Not yet up */
		if(sw_filter_cfg.pdns[i].v4_up != TRUE)
			continue;

		for(j = 0; j < sw_filter_cfg.pdns[i].num_extd_swallow_entries;j++)
		{
			entry = sw_filter_cfg.pdns[i].extd_swallow_entries[j];

			/* Check if entry is v4 */
			if(entry.ip_vsn != IP_V4)
				continue;

			/* Check if rule protocol matches with entry protocol */
			if(!(((entry.protocol &  IPPROTO_UDP) == rule->protocol) ||
			((entry.protocol &	IPPROTO_TCP) == rule->protocol)))
				continue;

			/* UL */
			if(!rule->dst_nat && (entry.direction == IPACM_MSGR_UL_FIREWALL))
			{
				if(entry.attrib.u.v4.src_addr == rule->private_ip &&
					 entry.attrib.u.v4.dst_addr == rule->target_ip &&
					 entry.attrib.src_port ==  rule->private_port  &&
					 entry.attrib.dst_port == rule->target_port)
				{
					log_nat(rule->protocol,rule->private_ip,rule->target_ip,rule->private_port,\
					rule->public_port,rule->target_port,rule->src_only,rule->dst_only,"SW Allow UL V4 Rule - Do not add\n");
					return true;
				}
			}
			/* DL */
			else if(rule->dst_nat && (entry.direction == IPACM_MSGR_DL_FIREWALL))
			{
				if(entry.attrib.u.v4.src_addr == rule->target_ip &&
					 entry.attrib.u.v4.dst_addr == rule->private_ip &&
					 entry.attrib.src_port ==  rule->target_port  &&
					 entry.attrib.dst_port == rule->private_port)
				{
					log_nat(rule->protocol,rule->private_ip,rule->target_ip,rule->private_port,\
					rule->public_port,rule->target_port,rule->src_only,rule->dst_only,"SW Allow DL V4 Rule - Do not add\n");
					return true;
				}
			}
		}
	}
	IPACMDBG("Exit\n");
	/* No pdn found */
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
			memset(&cache[cnt], 0, sizeof(cache[cnt]));
			curCnt--;
			break;
		}
	}

	return 0;
}

void NatApp::HandleSWAllowEntries(void)
{
	int i, j, cnt;
	IPACM_swallow_conf_t entry;
	const nat_table_entry *del_entry;
	IPACM_swallow_t sw_filter_cfg;
	IPACMDBG("Entry\n");

	if(!IPACM_Iface::ipacmcfg->sw_filter_cfg || !IPACM_Iface::ipacmcfg->sw_allow_flag)
	{
		IPACMERR("SW Config not updated/pdn index not updated!\n");
		return;
	}

	memcpy(&sw_filter_cfg, IPACM_Iface::ipacmcfg->sw_filter_cfg, sizeof(IPACM_swallow_t));

	for(i = 0; i < sw_filter_cfg.pdn_count;i++)
	{
		/* PDN not up yet */
		if(sw_filter_cfg.pdns[i].v4_up != TRUE)
			continue;

		for(j = 0; j < sw_filter_cfg.pdns[i].num_extd_swallow_entries;j++)
		{
			entry = sw_filter_cfg.pdns[i];

			/* Check if entry is v4 */
			if(entry.extd_swallow_entries[j].ip_vsn != IP_V4)
				continue;

			for(cnt = 0; cnt < max_entries; cnt++)
			{
				/* Check if cache protocol matches with entry protocol */
				if(!(((entry.extd_swallow_entries[j].protocol &  IPPROTO_UDP) == cache[cnt].protocol) ||
				((entry.extd_swallow_entries[j].protocol &	IPPROTO_TCP) == cache[cnt].protocol)))
					continue;

				/* UL */
				if(!cache[cnt].dst_nat && (entry.extd_swallow_entries[j].direction == IPACM_MSGR_UL_FIREWALL))
				{
					if(entry.extd_swallow_entries[j].attrib.u.v4.src_addr == cache[cnt].private_ip &&
						 entry.extd_swallow_entries[j].attrib.u.v4.dst_addr == cache[cnt].target_ip &&
						 entry.extd_swallow_entries[j].attrib.src_port ==  cache[cnt].private_port  &&
						 entry.extd_swallow_entries[j].attrib.dst_port == cache[cnt].target_port)
					{
						log_nat(cache[cnt].protocol,cache[cnt].private_ip,cache[cnt].target_ip,cache[cnt].private_port,\
						cache[cnt].public_port,cache[cnt].target_port,cache[cnt].src_only,cache[cnt].dst_only,"SW Allow UL V4 Rule - Deleting Rule\n");
						del_entry = &cache[cnt];
						DeleteEntry(del_entry);
					}
				}
				/* DL */
				else if(cache[cnt].dst_nat && (entry.extd_swallow_entries[j].direction == IPACM_MSGR_DL_FIREWALL))
				{
					if(entry.extd_swallow_entries[j].attrib.u.v4.src_addr == cache[cnt].target_ip &&
						 entry.extd_swallow_entries[j].attrib.u.v4.dst_addr == cache[cnt].private_ip &&
						 entry.extd_swallow_entries[j].attrib.src_port ==  cache[cnt].target_port	&&
						 entry.extd_swallow_entries[j].attrib.dst_port == cache[cnt].private_port)
					{
						log_nat(cache[cnt].protocol,cache[cnt].private_ip,cache[cnt].target_ip,cache[cnt].private_port,\
						cache[cnt].public_port,cache[cnt].target_port,cache[cnt].src_only,cache[cnt].dst_only,"SW Allow DL V4 Rule - Deleting Rule\n");
						del_entry = &cache[cnt];
						DeleteEntry(del_entry);
					}
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
	if(ipa_nat_get_pdn_index(rule->public_ip, &pdn_index))
	{
		if(isVlan)
		{
			IPACMDBG_H("vlan iface doesn't have a valid pdn, only moving to cache");
			iptodot("private ip", rule->private_ip);
			iptodot("target ip", rule->target_ip);
			iptodot("public ip", rule->public_ip);
			cacheOnly = true;
		}
		else
		{
			IPACMERR("couldn't acquire PDN index for public ip 0x%X\n", rule->public_ip);
			return IPACM_FAILURE;
		}
	}
#endif

	if(!ChkForDup(rule) && !ChkSWAllow(rule))
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
		   (cache[cnt].private_ip != cache[cnt].public_ip))
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
			nat_rule.pdn_index = cache[cnt].pdn_index;
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

	if(ChkForDup(new_entry) || ChkSWAllow(new_entry))
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

	if(!ChkForDup(rule) && !ChkSWAllow(rule))
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
	IPACMDBG_H("udp timeout value: %d\n", udp_timeout);
	IPACMDBG_H("tcp timeout value: %d\n", tcp_timeout);
#else
	tcp_timeout = 3600;
	udp_timeout = 60;
	IPACMDBG_H("udp timeout value: %d\n", udp_timeout);
	IPACMDBG_H("tcp timeout value: %d\n", tcp_timeout);
	FILE *udp_fd = NULL, *tcp_fd = NULL;
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
	IPACMDBG_H("%s IPv6 address 0x%llx%llx\n", msg_prefix, m_msb, m_lsb);
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
		(m_srcAddr == entry.m_srcAddr || m_srcAddr == entry.m_dstAddr) &&
		(m_dstAddr == entry.m_dstAddr || m_dstAddr == entry.m_srcAddr) &&
		(m_dstPort == entry.m_dstPort || m_dstPort == entry.m_srcPort) &&
		(m_srcPort == entry.m_srcPort || m_srcPort == entry.m_dstPort);
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
	return m_dstPort && m_srcPort && m_srcAddr.Valid() && m_dstAddr.Valid();
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

	FILE *udp_fd = NULL, *tcp_fd = NULL;

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

bail:
	if (udp_fd != NULL)
	{
		fclose(udp_fd);
	}
	if (tcp_fd != NULL)
	{
		fclose(tcp_fd);
	}

	IPACMDBG_H("return\n");
}
#endif

int ConntrackTimestampUtil::UpdateConntrackTimeStamp(const NatEntryBase& entry)
{
	IPACMDBG_H("\n");

	entry.DebugDump("Going to update timestamp for following entry");

	nfct_set_attr_u8(ct, ATTR_L4PROTO, entry.m_protocol);
	nfct_set_attr_u32(ct, ATTR_TIMEOUT, (entry.m_protocol == IPPROTO_UDP) ? udp_timeout : tcp_timeout);

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

int NatProxyBase::AddTable(uint16_t number_of_entries)
{
	IPACMDBG_H("\n");
	uint32_t table_handle;

	if(table_created)
	{
		IPACMDBG_H("Table already created return\n");
		return 0;
	}

	int ret = DoAddTable(number_of_entries, table_handle);
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
	entry.Clear();
	IPACMDBG_H("return\n");
	return ret;
}

int Ipv6ctProxy::DoAddTable(uint16_t number_of_entries, uint32_t& table_handle)
{
	IPACMDBG_H("\n");
	int ret = ipa_ipv6ct_add_tbl(number_of_entries, &table_handle);
	IPACMDBG_H("return\n");
	return ret;
}

int Ipv6ctProxy::DoDeleteTable()
{
	IPACMDBG_H("\n");
	int ret = ipa_ipv6ct_del_tbl(m_tableHandle);
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

		ret = ipa_ipv6ct_add_rule(m_tableHandle, &rule, &entry_handle);

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

		ret = ipa_ipv6ct_add_rule(m_tableHandle, &rule, &entry_handle);
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

		ret = ipa_ipv6ct_add_rule(m_tableHandle, &rule, &additional_entry_handle);
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
	ipa_ipv6ct_del_rule(m_tableHandle, entry_handle);
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

	ret = ipa_ipv6ct_del_rule(m_tableHandle, entry.m_ruleHandle);
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

			ret = ipa_ipv6ct_del_rule(m_tableHandle, ipv6nat.m_inboundRuleHandle);
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

	int ret = ipa_ipv6ct_query_timestamp(m_tableHandle, entry.m_ruleHandle, &time_stamp);
#ifdef FEATURE_IPV6_NAT
	if(ret)
	{
		IPACMERR("query failed, return\n");
		return ret;
	}
	// since IPv6 NAT entry is actually two IPv6ct entries we need to take the latest of them
	if(entry.GetPublicIp() != entry.GetClientIp())
	{
		uint32_t additional_timestamp;
		const Ipv6NatEntry &ipv6nat = static_cast<const Ipv6NatEntry&>(entry);

		IPACMDBG_H("ipv6 nat entry, check inbound handle\n");
		ret = ipa_ipv6ct_query_timestamp(m_tableHandle, ipv6nat.m_inboundRuleHandle, &additional_timestamp);
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

int NatBase::AddTable(const uint32_t v6_prefix[2])
{
	IPACMDBG_H("\n");
	int ret = m_proxy.AddTable(m_maxEntries);
	if (ret)
	{
		IPACMERR("unable to create the table Error:%d\n", ret);
		return ret;
	}

	/* Add back the cached NAT-entry */
	IPACMDBG_H("Restore the cache to ipa NAT-table\n");
	for (int cnt = 0; cnt < m_maxEntries; ++cnt)
	{
		NatEntryBase& entry = m_cache[cnt];
		if (entry.Valid())
		{
			uint64_t src_ipv6_msb = 0;

			if (entry.m_direction == NatEntryBase::DirectionOutbound || entry.m_direction == NatEntryBase::DirectionUnknown)
			{
				src_ipv6_msb = ((Ipv6IpAddress &)entry.GetClientIp()).GetMsb();
			}
			else if (entry.m_direction == NatEntryBase::DirectionInbound)
			{
				src_ipv6_msb = ((Ipv6IpAddress &)entry.GetTargetIp()).GetMsb();
			}

			if(((src_ipv6_msb >> 32) == v6_prefix[0]) && ((src_ipv6_msb & 0x00000000FFFFFFFF) == v6_prefix[1]))
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

			if (entry.m_direction == NatEntryBase::DirectionOutbound || entry.m_direction == NatEntryBase::DirectionUnknown)
			{
				src_ipv6_msb = ((Ipv6IpAddress &)entry.GetClientIp()).GetMsb();
			}
			else if (entry.m_direction == NatEntryBase::DirectionInbound)
			{
				src_ipv6_msb = ((Ipv6IpAddress &)entry.GetTargetIp()).GetMsb();
			}

			if(src_ipv6_msb && ipv6prefixmatch(src_ipv6_msb, v6_prefix))
			{
				if (m_proxy.DelEntry(entry))
				{
					IPACMERR("unable to delete the rule delete from cache\n");
					entry.Clear();
					--m_curCnt;
					continue;
				}

				entry.DebugDump("On wan-iface reset added below rule successfully\n");
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

bool NatBase::is_SocksV5_CT(const NatEntryBase& entry)
{
	list<Ipv6ctEntry>::iterator it_mapping;
	Ipv6ctEntry new_entry;

	memcpy(&new_entry, &entry, sizeof(Ipv6ctEntry));

	/* find the entry in the cache */
	for(it_mapping = socksv5_v6_conn.begin(); it_mapping != socksv5_v6_conn.end(); it_mapping++)
	{
		if((it_mapping->m_srcAddr == new_entry.m_srcAddr || it_mapping->m_srcAddr == new_entry.m_dstAddr) &&
			(it_mapping->m_dstAddr == new_entry.m_dstAddr || it_mapping->m_dstAddr == new_entry.m_srcAddr) &&
			(it_mapping->m_srcPort == new_entry.m_srcPort || it_mapping->m_srcPort == new_entry.m_dstPort) &&
			(it_mapping->m_dstPort == new_entry.m_dstPort || it_mapping->m_dstPort == new_entry.m_srcPort) &&
			(it_mapping->m_protocol == new_entry.m_protocol))
				return true;
	}

	return false;
}

int NatBase::AddEntry(const NatEntryBase& entry)
{
	IPACMDBG_H("\n");
	Ipv6ctEntry new_entry;
	NatEntryBase* del_entry = NULL;
	Ipv6ctEntry del;

	if(entry.isSocksV5 && IPACM_Iface::ipacmcfg->ipacm_socksv5_enable)
	{
		IPACMDBG("Socks Entry to add\n");

		/* Clean up previous v6ct entries if v6ct comes 
		 * before socksv5 events from tcp-splice 
		 */
		if(del_entry = m_cache.Find(entry))
		{
			memcpy(&del, del_entry, sizeof(Ipv6ctEntry));
			DeleteEntry(del);
		}

		/* Add SocksV5 connection */
		memcpy(&new_entry, &entry, sizeof(Ipv6ctEntry));

		if (m_proxy.AddEntry(new_entry))
		{
			IPACMERR("unable to add the v6-ct entry\n");
			return -EPERM;
		}
		IPACMDBG_H("Added entry successfully handle (%d)\n", new_entry.m_ruleHandle);
		socksv5_v6_conn.push_front(new_entry);
	}
	else
	{
		if (is_SocksV5_CT(entry))
		{
			IPACMERR("Socks V5 Connection do not add normal CT\n");
			return -EPERM;
		}

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

		if (ChkSWAllow(entry))
		{
			IPACMERR("SwAllow Entry. Ignore it\n");
			return -EPERM;
		}

		NatEntryBase* new_entry = m_cache.GetFirstEmpty();
		if(new_entry == NULL)
		{
			IPACMERR("Error: Unable to add, reached maximum rules\n");
			return -EPERM;
		}

		*new_entry = entry;

		if(m_pwrSaveIfs.Find(new_entry->GetClientIp()) != NULL || m_pwrSaveIfs.Find(new_entry->GetTargetIp()) != NULL)
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
	}
	IPACMDBG_H("\n");
	++m_curCnt;
	IPACMDBG_H("return\n");
	return 0;
}

void NatBase::DeleteEntry(const NatEntryBase& entry)
{
	IPACMDBG_H("\n");
	if(entry.isSocksV5 && IPACM_Iface::ipacmcfg->ipacm_socksv5_enable)
	{
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
	}
	else
	{
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
		entryDelete->Clear();
	}
	--m_curCnt;

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
	uint64_t src_ipv6_msb, src_ipv6_lsb;
	uint64_t dst_ipv6_msb, dst_ipv6_lsb;
	Ipv6ctEntry rule_entry;
	IPACM_swallow_t sw_filter_cfg;
	IPACMDBG("Entry\n");

	if(!IPACM_Iface::ipacmcfg->sw_filter_cfg || !IPACM_Iface::ipacmcfg->sw_allow_flag)
	{
		IPACMERR("SW Config not updated/pdn index not updated!\n");
		return false;
	}

	memcpy(&sw_filter_cfg, IPACM_Iface::ipacmcfg->sw_filter_cfg, sizeof(IPACM_swallow_t));

	for(i = 0; i < sw_filter_cfg.pdn_count;i++)
	{
		/* PDN not up yet */
		if(sw_filter_cfg.pdns[i].v6_up != TRUE)
			continue;

		for(j = 0; j < sw_filter_cfg.pdns[i].num_extd_swallow_entries;j++)
		{
			/* Check if entry is v6 */
			if(sw_filter_cfg.pdns[i].extd_swallow_entries[j].ip_vsn != IP_V6)
				continue;

			/* Check if rule protocol matches with entry protocol */
			if(!(((sw_filter_cfg.pdns[i].extd_swallow_entries[j].protocol &  IPPROTO_UDP) == rule.m_protocol) ||
			((sw_filter_cfg.pdns[i].extd_swallow_entries[j].protocol &	IPPROTO_TCP) == rule.m_protocol)))
				continue;

			src_ipv6_msb = sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.src_addr[0];
			src_ipv6_msb = (src_ipv6_msb << 32) | sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.src_addr[1];
			src_ipv6_lsb = sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.src_addr[2];
			src_ipv6_lsb = (src_ipv6_lsb << 32) | sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.src_addr[3];

			dst_ipv6_msb = sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.dst_addr[0];
			dst_ipv6_msb = (dst_ipv6_msb << 32) | sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.dst_addr[1];
			dst_ipv6_lsb = sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.dst_addr[2];
			dst_ipv6_lsb = (dst_ipv6_lsb << 32) | sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.dst_addr[3];

			memcpy(&rule_entry, &rule, sizeof(Ipv6ctEntry));

			/* UL */
			if((rule.m_direction == NatEntryBase::DirectionOutbound) &&
					(sw_filter_cfg.pdns[i].extd_swallow_entries[j].direction == IPACM_MSGR_UL_FIREWALL))
			{
				if(src_ipv6_msb == ((Ipv6IpAddress &)rule_entry.GetClientIp()).GetMsb() &&
					src_ipv6_lsb == ((Ipv6IpAddress &)rule_entry.GetClientIp()).GetLsb() &&
					 dst_ipv6_msb == ((Ipv6IpAddress &)rule_entry.GetTargetIp()).GetMsb() &&
					 dst_ipv6_lsb == ((Ipv6IpAddress &)rule_entry.GetTargetIp()).GetLsb() &&
					 sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.src_port == rule_entry.GetSrcPort() &&
					 sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.dst_port == rule_entry.GetDstPort())
				{
					((Ipv6IpAddress &)rule_entry.GetClientIp()).DebugDump("srcAddr (private ip):");
					((Ipv6IpAddress &)rule_entry.GetTargetIp()).DebugDump("dstAddr (target ip):");
					IPACMDBG_H("srcPort (private Port): %d\n", rule_entry.GetSrcPort());
					IPACMDBG_H("dstPort (target Port): %d\n", rule_entry.GetDstPort());
					IPACMDBG("SW Allow UL Rule - Do not add\n");
					return true;
				}
			}
			/* DL */
			else if((rule.m_direction == NatEntryBase::DirectionInbound) &&
					(sw_filter_cfg.pdns[i].extd_swallow_entries[j].direction == IPACM_MSGR_DL_FIREWALL))
			{
				if(src_ipv6_msb == ((Ipv6IpAddress &)rule_entry.GetTargetIp()).GetMsb() &&
					src_ipv6_lsb == ((Ipv6IpAddress &)rule_entry.GetTargetIp()).GetLsb() &&
					 dst_ipv6_msb == ((Ipv6IpAddress &)rule_entry.GetClientIp()).GetMsb() &&
					 dst_ipv6_lsb == ((Ipv6IpAddress &)rule_entry.GetClientIp()).GetLsb() &&
					 sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.src_port == rule_entry.GetDstPort() &&
					 sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.dst_port == rule_entry.GetSrcPort())
				{
					((Ipv6IpAddress &)rule_entry.GetClientIp()).DebugDump("srcAddr (private ip):");
					((Ipv6IpAddress &)rule_entry.GetTargetIp()).DebugDump("dstAddr (target ip):");
					IPACMDBG_H("srcPort (private Port): %d\n", rule_entry.GetSrcPort());
					IPACMDBG_H("dstPort (target Port): %d\n", rule_entry.GetDstPort());
					IPACMDBG("SW Allow DL Rule - Do not add\n");
					return true;
				}
			}
		}
	}
	IPACMDBG("Exit\n");
	return false;
}

void NatBase::HandleSWAllowEntries(void)
{
	int i, j, cnt;
	uint64_t src_ipv6_msb, src_ipv6_lsb;
	uint64_t dst_ipv6_msb, dst_ipv6_lsb;
	Ipv6ctEntry new_entry;
	IPACM_swallow_t sw_filter_cfg;
	IPACMDBG("Entry\n");

	if(!IPACM_Iface::ipacmcfg->sw_filter_cfg || !IPACM_Iface::ipacmcfg->sw_allow_flag)
	{
		IPACMERR("SW Config not updated/pdn index not updated!\n");
		return;
	}

	memcpy(&sw_filter_cfg, IPACM_Iface::ipacmcfg->sw_filter_cfg, sizeof(IPACM_swallow_t));

	for(i = 0; i < sw_filter_cfg.pdn_count;i++)
	{
		/* PDN not up yet */
		if(sw_filter_cfg.pdns[i].v6_up != TRUE)
			continue;

		for(j = 0; j < sw_filter_cfg.pdns[i].num_extd_swallow_entries;j++)
		{
			/* Check if entry is v6 */
			if(sw_filter_cfg.pdns[i].extd_swallow_entries[j].ip_vsn != 6)
				continue;

			src_ipv6_msb = sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.src_addr[0];
			src_ipv6_msb = (src_ipv6_msb << 32) | sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.src_addr[1];
			src_ipv6_lsb = sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.src_addr[2];
			src_ipv6_lsb = (src_ipv6_lsb << 32) | sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.src_addr[3];

			dst_ipv6_msb = sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.dst_addr[0];
			dst_ipv6_msb = (dst_ipv6_msb << 32) | sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.dst_addr[1];
			dst_ipv6_lsb = sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.dst_addr[2];
			dst_ipv6_lsb = (dst_ipv6_lsb << 32) | sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.u.v6.dst_addr[3];

			for(cnt = 0; cnt < m_maxEntries; cnt++)
			{
				/* Check if cache entry is enabled */
				if(!m_cache[cnt].m_enabled)
					continue;

				/* Check if cache protocol matches with entry protocol */
				if(!(((sw_filter_cfg.pdns[i].extd_swallow_entries[j].protocol &  IPPROTO_UDP) == m_cache[cnt].m_protocol) ||
				((sw_filter_cfg.pdns[i].extd_swallow_entries[j].protocol &	IPPROTO_TCP) == m_cache[cnt].m_protocol)))
					continue;

				memcpy(&new_entry, &(m_cache[cnt]), sizeof(Ipv6ctEntry));

				/* UL */
				if((m_cache[cnt].m_direction == NatEntryBase::DirectionOutbound) &&
						(sw_filter_cfg.pdns[i].extd_swallow_entries[j].direction == IPACM_MSGR_UL_FIREWALL))
				{
					if(src_ipv6_msb == ((Ipv6IpAddress &)new_entry.GetClientIp()).GetMsb() &&
						 src_ipv6_lsb == ((Ipv6IpAddress &)new_entry.GetClientIp()).GetLsb() &&
						 dst_ipv6_msb == ((Ipv6IpAddress &)new_entry.GetTargetIp()).GetMsb() &&
						 dst_ipv6_lsb == ((Ipv6IpAddress &)new_entry.GetTargetIp()).GetLsb() &&
						 sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.src_port ==  new_entry.GetSrcPort() &&
						 sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.dst_port == new_entry.GetDstPort())
					{
						((Ipv6IpAddress &)new_entry.GetClientIp()).DebugDump("srcAddr (private ip):");
						((Ipv6IpAddress &)new_entry.GetTargetIp()).DebugDump("dstAddr (target ip):");
						IPACMDBG_H("srcPort (private Port): %d\n", new_entry.GetSrcPort());
						IPACMDBG_H("dstPort (target Port): %d\n", new_entry.GetDstPort());
						IPACMDBG("SW Allow UL V6 Rule - Deleting Rule\n");
						DeleteEntry(new_entry);
					}
				}
				/* DL */
				else if((m_cache[cnt].m_direction == NatEntryBase::DirectionInbound) &&
						(sw_filter_cfg.pdns[i].extd_swallow_entries[j].direction == IPACM_MSGR_DL_FIREWALL))
				{
					if(src_ipv6_msb == ((Ipv6IpAddress &)new_entry.GetTargetIp()).GetMsb() &&
						 src_ipv6_lsb == ((Ipv6IpAddress &)new_entry.GetTargetIp()).GetLsb() &&
						 dst_ipv6_msb == ((Ipv6IpAddress &)new_entry.GetClientIp()).GetMsb() &&
						 dst_ipv6_lsb == ((Ipv6IpAddress &)new_entry.GetClientIp()).GetLsb() &&
						 sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.src_port ==  new_entry.GetDstPort() &&
						 sw_filter_cfg.pdns[i].extd_swallow_entries[j].attrib.dst_port == new_entry.GetSrcPort())
					{
						((Ipv6IpAddress &)new_entry.GetClientIp()).DebugDump("srcAddr (private ip):");
						((Ipv6IpAddress &)new_entry.GetTargetIp()).DebugDump("dstAddr (target ip):");
						IPACMDBG_H("srcPort (private Port): %d\n", new_entry.GetSrcPort());
						IPACMDBG_H("dstPort (target Port): %d\n", new_entry.GetDstPort());
						IPACMDBG("SW Allow DL V6 Rule - Deleting Rule\n");
						DeleteEntry(new_entry);
					}
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

	m_instance = new Ipv6ct(pConfig->GetIpv6CTMaxEntries());
	IPACMDBG_H("return\n");
	return m_instance;
}

Ipv6ct::Ipv6ct(int max_entries) : NatBase(IPA_IP_v6, max_entries, Ipv6ctObjectsGenerator())
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

	m_instance = new Ipv6Nat(pConfig->GetIpv6CTMaxEntries());
	IPACMDBG_H("return\n");
	return m_instance;
}

Ipv6Nat::Ipv6Nat(int max_entries) : NatBase(IPA_IP_v6, max_entries, Ipv6NatObjectsGenerator())
{
	IPACMDBG_H("\n");
}
#endif
