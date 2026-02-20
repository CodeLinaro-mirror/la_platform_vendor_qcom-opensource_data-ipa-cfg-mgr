/*
 * Copyright (c) 2013-2021 The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name of The Linux Foundation nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
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
 * Changes from Qualcomm Innovation Center are provided under the following license:
 *
 * Copyright (c) 2022, 2025 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted (subject to the limitations in the
 * disclaimer below) provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *
 *     * Neither the name of Qualcomm Innovation Center, Inc. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
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
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
 */
/*!
		@file
		IPACM_Wlan.h

		@brief
		This file implements the WLAN iface functionality.

		@Author
		Skylar Chang

*/
#ifndef IPACM_WLAN_H
#define IPACM_WLAN_H

#include <stdio.h>
#include <IPACM_CmdQueue.h>
#include <linux/msm_ipa.h>
#include "IPACM_Routing.h"
#include "IPACM_Filtering.h"
#include "IPACM_Lan.h"
#include "IPACM_Iface.h"
#include "IPACM_Conntrack_NATApp.h"

#define __stringify(x...) #x

typedef struct _wlan_client_rt_hdl
{
	uint32_t wifi_rt_rule_hdl_v4;
}wlan_client_rt_hdl;

struct ap_dflt_rules{
	int iface_cnt[IPA_IP_MAX];
	int src_pipe;
	uint32_t eth_bridge_flt_rule_hdl[IPA_MAX_NUM_PROPS][IPA_IP_MAX];
	uint32_t mtu_flt_rule_hdl[IPA_MAX_NUM_PROPS][IPA_IP_MAX];
	uint32_t tcp_syn_flt_rule_hdl[IPA_MAX_NUM_PROPS][IPA_IP_MAX];
	uint32_t ipv4_icmp_flt_rule_hdl[IPA_MAX_NUM_PROPS][NUM_IPV4_ICMP_FLT_RULE];
	uint32_t dft_v4fl_rule_hdl[IPA_MAX_NUM_PROPS][IPV4_DEFAULT_FILTERTING_RULES];
	uint8_t m_ipv4_default_filterting_rules_count[IPA_MAX_NUM_PROPS];
	uint32_t ipv6_icmp_flt_rule_hdl[IPA_MAX_NUM_PROPS][NUM_IPV6_ICMP_FLT_RULE];
	uint32_t dft_v6fl_rule_hdl[IPA_MAX_NUM_PROPS][IPV6_DEFAULT_FILTERTING_RULES + IPV6_DEFAULT_LAN_FILTERTING_RULES];
	uint8_t m_ipv6_default_filterting_rules_count[IPA_MAX_NUM_PROPS];
	uint32_t private_flt_rule_hdl[IPA_MAX_NUM_PROPS][IPA_MAX_PRIVATE_SUBNET_ENTRIES + IPA_MAX_MTU_ENTRIES];
	bool wan_private_flt_rules_present,wan_private_v6flt_rules_present;
#ifdef FEATURE_VLAN_MPDN
	uint32_t ipv6_prefix_flt_rule_hdl[IPA_MAX_NUM_PROPS][IPA_MAX_IPV6_NO_OFFLOAD_PREFIX_FLT_RULE + IPA_MAX_MTU_ENTRIES];
#else
	uint32_t ipv6_prefix_flt_rule_hdl[IPA_MAX_NUM_PROPS][IPA_MAX_IPV6_PREFIX_FLT_RULE + IPA_MAX_MTU_ENTRIES];
#endif
	int num_wan_prefix_rules[IPA_MAX_NUM_PROPS];
};

typedef struct _ipa_wlan_client
{
	ipacm_event_data_wlan_ex* p_hdr_info;
	uint8_t mac[IPA_MAC_ADDR_SIZE];
	uint32_t v4_addr;
	uint32_t hdr_hdl_v4;
	uint32_t hdr_hdl_v6;
	uint32_t hpc_hdr_hdl_v4;
	uint32_t hpc_hdr_hdl_v6;
	bool route_rule_set_v4;
	int route_rule_set_v6;
	bool ipv4_set;
	int ipv6_set;
	bool ipv4_header_set;
	bool ipv6_header_set;
	bool ipv4_hpc_set;
	bool ipv6_hpc_set;
#ifdef FEATURE_STATIC_POLICY
	uint32_t dscp_hpc_hdr_hdl_v4[IPA_UC_MAX_PDN_DSCP_VAL];
	uint32_t dscp_hpc_hdr_hdl_v6[IPA_UC_MAX_PDN_DSCP_VAL];
	bool dscp_route_rule_set_v4[IPA_UC_MAX_PDN_DSCP_VAL];
	bool dscp_ipv4_hpc_set[IPA_UC_MAX_PDN_DSCP_VAL];
	bool dscp_ipv6_hpc_set[IPA_UC_MAX_PDN_DSCP_VAL];
	int dscp_ipv4_hpc_count[IPA_UC_MAX_PDN_DSCP_VAL];
	int dscp_ipv6_hpc_count[IPA_UC_MAX_PDN_DSCP_VAL];
	wlan_client_rt_hdl dscp_wifi_rt_hdl[IPA_UC_MAX_PDN_DSCP_VAL];
#endif
	bool power_save_set;
	bool is_vlan;
	/* default vlan support in wlan */
	uint16_t vlan_id;
	int if_index;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	bool ipv4_ul_rules_set;
	bool ipv6_ul_rules_set;
	/* store ipv4 UL filter rule handlers from Q6*/
	uint32_t wan_ul_fl_rule_hdl_v4[MAX_WAN_UL_FILTER_RULES];
	/* store ipv6 UL filter rule handlers from Q6*/
#ifdef IPA_V6_UL_WL_FIREWALL_HANDLE
	uint32_t wan_ul_fl_rule_hdl_v6[IPACM_MAX_V6_UL_WL_FIREWALL_ENTRIES];
#else
	uint32_t wan_ul_fl_rule_hdl_v6[MAX_WAN_UL_FILTER_RULES];
#endif
	int8_t lan_stats_idx;
#ifdef IPA_HW_FNR_STATS
	int ul_cnt_idx;
	int dl_cnt_idx;
	bool index_populated;
#endif //IPA_HW_FNR_STATS
#endif
	uint16_t ta_peer_id;
	/* store ipv4 LAN2LAN filter rule handle when ast update is needed. */
	uint32_t lan2lan_fl_rule_hdl_v4;
	/* store ipv6 LAN2LAN filter rule handle when ast update is needed. */
	uint32_t lan2lan_fl_rule_hdl_v6;
	//Keep below structure as last declaration.
	wlan_client_rt_hdl wifi_rt_hdl[0]; /* depends on number of tx properties */
}ipa_wlan_client;

typedef struct _ipa_wlan_primary_client
{
	uint8_t mac[IPA_MAC_ADDR_SIZE];
	ipacm_event_data_wlan_ex* p_hdr_info;
	uint32_t num_vlan_clients;
}ipa_wlan_primary_client;


/* wlan iface */
class IPACM_Wlan : public IPACM_Lan
{

public:

	IPACM_Wlan(char *iface_name, int iface_index, bool    ast_update = false);
	virtual ~IPACM_Wlan(void);

	static int total_num_wifi_clients;

	void event_callback(ipa_cm_event_id event, void *data);

	bool is_guest_ap();

	bool ast_update_needed();

	bool is_svap_iface();
	void add_dscp_pcp_mapping();
	void handle_hpc_rt_rules_for_easymesh_R3(struct ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table, struct ipa_hdr_proc_ctx_add *hdr_proc_ctx, int clt_idx);
	int set_svap_iface_mode(bool enable);
	void update_svap_state();
	int handle_wlan_vlan_neighbor(ipacm_event_new_neigh_vlan *param);
	int add_rt_rules_for_ast_update_ifaces();

	bool is_vlan_iface();
	int handle_wlan_del_ipv6_addr(ipacm_event_data_all *data);
	static struct ap_dflt_rules wlan_ap_dflt_rules[MAX_SUPPORTED_WLAN_PIPES];


#if defined(FEATURE_IPACM_PER_CLIENT_STATS) || defined(IPA_WDI_AST_UPDATE)
	/* install UL filter rule from Q6 per client */
	int install_uplink_filter_rule_per_client
	(
		ipacm_ext_prop* prop,
		ipa_ip_type iptype,
		uint8_t xlat_mux_id,
		uint8_t *mac_addr,
		uint16_t ta_peer_id = 0
	);
#ifdef IPA_HW_FNR_STATS
	int install_uplink_filter_rule_per_client_v2
	(
		ipacm_ext_prop* prop,
		ipa_ip_type iptype,
		uint8_t xlat_mux_id,
		uint8_t *mac_addr,
		uint8_t ul_cnt_idx,
		ipa_ioc_add_flt_rule *fw_q6_rules = NULL,
		bool isFirewall = false,
		uint16_t ta_peer_id = 0
	);

#endif //IPA_HW_FNR_STATS

#ifdef IPA_V6_UL_WL_FIREWALL_HANDLE
	int config_dft_firewall_rules_ul_ex(IPACM_firewall_conf_t* firewall_conf, int vid);
	int disable_dft_firewall_rules_ul_ex_per_wlan_client(int vid);
	void configure_v6_ul_firewall_wlan();
#endif //IPA_V6_UL_WL_FIREWALL_HANDLE

	int handle_wlan_client_route_rule_ext_v2(uint8_t *mac_addr, ipa_ip_type iptype, uint16_t vlan_id = 0);

	/* install UL filter rule from Q6 for all clients */
	int install_uplink_filter_rule
	(
		ipacm_ext_prop* prop,
		ipa_ip_type iptype,
		uint8_t xlat_mux_id
	);

	/* Delete UL filter rule from Q6 for all clients */
	int delete_uplink_filter_rule
	(
		ipa_ip_type iptype
	);

	/* Delet UL filter rule from Q6 per client */
	int delete_uplink_filter_rule_per_client
	(
		ipa_ip_type iptype,
		uint8_t *mac_addr
	);

	/* handle lan client connect event. */
	int handle_lan_client_connect(uint8_t *mac_addr);

	/* handle lan client disconnect event. */
	int handle_lan_client_disconnect(uint8_t *mac_addr);

#endif

	/* add filtering rule and return handle to lan2lan controller */
	int eth_bridge_add_flt_rule(uint8_t *mac, uint32_t rt_tbl_hdl, ipa_ip_type iptype, uint32_t *flt_rule_hdl, uint16_t vlan_id = 0);

	int install_wlan_client_lan2lan_flt_rule(uint8_t *mac, ipa_ip_type iptype, bool is_vlan);

	int delete_wlan_client_lan2lan_flt_rule(uint8_t *mac, ipa_ip_type iptype);

	int add_dummy_routing_rule(char *routingTableName, ipa_ip_type iptype);

private:

	bool ast_update;

	bool m_is_guest_ap;

	/* handle wlan access mode switch in ethernet bridging*/
	void eth_bridge_handle_wlan_mode_switch();


	int wlan_client_len;

	ipa_wlan_client *wlan_client;

	ipa_wlan_primary_client *wlan_primary_client;

	int header_name_count;
	int num_wifi_client;
	int num_wifi_primary_client;

	int wlan_ap_index;

	static int num_wlan_ap_iface;

	NatApp *Nat_App;
	NatBase* const ipv6ct_inst;

	bool svap_iface;

	uint32_t svap_dummy_route_rule_v4_hdl;

	uint32_t svap_dummy_route_rule_v6_hdl;

	bool vlan_enabled_ap;

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	static bool lan_stats_inited;
	/* Clients which take HW path. */
	static ipa_lan_client_idx active_lan_client_index[IPA_MAX_NUM_HW_PATH_CLIENTS];
	/* Clients which take SW path. */
	static ipa_lan_client_idx inactive_lan_client_index[IPA_MAX_NUM_HW_PATH_CLIENTS];
#endif

	inline ipa_wlan_client* get_client_memptr(ipa_wlan_client *param, int cnt)
	{
	    char *ret = ((char *)param) + (wlan_client_len * cnt);
		return (ipa_wlan_client *)ret;
	}

	inline int get_wlan_client_index(uint8_t *mac_addr, uint16_t vlan_id = 0)
	{
		int cnt;
		int num_wifi_client_tmp = num_wifi_client;

		IPACMDBG_H("Passed MAC %02x:%02x:%02x:%02x:%02x:%02x, left client: %d\n",
						 mac_addr[0], mac_addr[1], mac_addr[2],
						 mac_addr[3], mac_addr[4], mac_addr[5],
						 num_wifi_client);

		for(cnt = 0; cnt < num_wifi_client_tmp; cnt++)
		{
			IPACMDBG_H("stored MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
							 get_client_memptr(wlan_client, cnt)->mac[0],
							 get_client_memptr(wlan_client, cnt)->mac[1],
							 get_client_memptr(wlan_client, cnt)->mac[2],
							 get_client_memptr(wlan_client, cnt)->mac[3],
							 get_client_memptr(wlan_client, cnt)->mac[4],
							 get_client_memptr(wlan_client, cnt)->mac[5]);

			if(memcmp(get_client_memptr(wlan_client, cnt)->mac,
								mac_addr,
								sizeof(get_client_memptr(wlan_client, cnt)->mac)) == 0)
			{
#ifdef FEATURE_VLAN_MPDN
				if(vlan_id)
				{
					IPACMDBG("VLAN IF MAC match, looking for vlan ID %d, current %d\n", vlan_id,
						get_client_memptr(wlan_client, cnt)->vlan_id);
					if(get_client_memptr(wlan_client, cnt)->vlan_id == vlan_id)
					{
						IPACMDBG_H("Matched client index: %d for vid %d\n", cnt, vlan_id);
						return cnt;
					}
				}
				else
#endif
				{
					IPACMDBG_H("Matched client index: %d\n", cnt);
					return cnt;
				}
			}
		}

		return IPACM_INVALID_INDEX;
	}

	inline int get_wlan_client_ip4_addr(uint8_t *mac_addr, uint32_t &ip_addr, uint8_t vlan_id = 0)
	{
		int clnt_indx;

		clnt_indx = get_wlan_client_index(mac_addr, vlan_id);
		if(clnt_indx == IPACM_INVALID_INDEX)
		{
			IPACMERR("eth client not found/attached \n");
			return IPACM_FAILURE;
		}

		if (get_client_memptr(wlan_client, clnt_indx)->ipv4_set)
		{
			ip_addr = get_client_memptr(wlan_client, clnt_indx)->v4_addr;
			IPACMDBG_H("ip addr is 0x%X\n", ip_addr);
			return IPACM_SUCCESS;
		}
		else
		{
			IPACMDBG_H("ipv4 address not set\n");
			return IPACM_FAILURE;
		}
	}

	inline int get_wlan_client_index_from_if_index(int if_index)
	{
		int cnt;
		int num_wifi_client_tmp = num_wifi_client;

		for(cnt = 0; cnt < num_wifi_client_tmp; cnt++)
		{
			if(if_index == get_client_memptr(wlan_client, cnt)->if_index)
			{
				IPACMDBG_H("if_index %d is used by client %d\n", if_index, cnt);
				return cnt;
			}
		}
		IPACMERR("could not find client with if_index %d\n", if_index);
		return IPACM_INVALID_INDEX;
	}

	inline ipa_wlan_primary_client* get_primary_client_memptr(ipa_wlan_primary_client *param, int cnt)
	{
	    char *ret = ((char *)param) + (sizeof(ipa_wlan_primary_client) * cnt);
		return (ipa_wlan_primary_client *)ret;
	}

	inline int get_wlan_primary_client_index(uint8_t *mac_addr)
	{
		int cnt;
		int num_wifi_client_tmp = num_wifi_primary_client;

		IPACMDBG_H("Passed MAC %02x:%02x:%02x:%02x:%02x:%02x, left client: %d\n",
						 mac_addr[0], mac_addr[1], mac_addr[2],
						 mac_addr[3], mac_addr[4], mac_addr[5],
						 num_wifi_primary_client);

		for(cnt = 0; cnt < num_wifi_client_tmp; cnt++)
		{
			IPACMDBG_H("stored MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
							 get_primary_client_memptr(wlan_primary_client, cnt)->mac[0],
							 get_primary_client_memptr(wlan_primary_client, cnt)->mac[1],
							 get_primary_client_memptr(wlan_primary_client, cnt)->mac[2],
							 get_primary_client_memptr(wlan_primary_client, cnt)->mac[3],
							 get_primary_client_memptr(wlan_primary_client, cnt)->mac[4],
							 get_primary_client_memptr(wlan_primary_client, cnt)->mac[5]);

			if(memcmp(get_primary_client_memptr(wlan_primary_client, cnt)->mac,
								mac_addr,
								sizeof(get_primary_client_memptr(wlan_primary_client, cnt)->mac)) == 0)
			{
				IPACMDBG_H("Matched client index: %d\n", cnt);
				return cnt;
			}
		}

		return IPACM_INVALID_INDEX;
	}

	inline int delete_default_qos_rtrules(int clt_indx, ipa_ip_type iptype)
	{
		uint32_t tx_index;
		uint32_t rt_hdl;
		int num_v6 = 0;

		if(iptype == IPA_IP_v4)
		{

		    for(tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		    {
		        if((tx_prop->tx[tx_index].ip == IPA_IP_v4) && (get_client_memptr(wlan_client, clt_indx)->route_rule_set_v4==true)) /* for ipv4 */
			{
				IPACMDBG_H("Delete client index %d ipv4 Qos rules for tx:%d \n",clt_indx,tx_index);
				rt_hdl = get_client_memptr(wlan_client, clt_indx)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4;

				if(m_routing.DeleteRoutingHdl(rt_hdl, IPA_IP_v4) == false)
				{
					return IPACM_FAILURE;
				}
			}
		     } /* end of for loop */

		     /* clean the 4 Qos ipv4 RT rules for client:clt_indx */
		     if(get_client_memptr(wlan_client, clt_indx)->route_rule_set_v4==true) /* for ipv4 */
		     {
				get_client_memptr(wlan_client, clt_indx)->route_rule_set_v4 = false;
		     }
		}

		if(iptype == IPA_IP_v6)
		{
			IPACMDBG_H("Current %d client has %d ipv6 route_set %d,ipa_num_clients_ipv6:%d\n",
				clt_indx, get_client_memptr(wlan_client, clt_indx)->ipv6_set,
				get_client_memptr(wlan_client, clt_indx)->route_rule_set_v6,
					IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
			if (get_client_memptr(wlan_client, clt_indx)->route_rule_set_v6 != 0)
			{
				for (auto it = rt_hdl_v6_list[clt_indx].begin(); it != rt_hdl_v6_list[clt_indx].end(); ++it)
				{
					num_v6++;
					if(it->second.route_rule_set_v6 == true)
					{
						IPACMDBG_H("v6 addr : 0x%08x:%08x:%08x:%08x\n",
							it->first[0], it->first[1], it->first[2], it->first[3]);

						for(tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
						{
							if(tx_prop->tx[tx_index].ip == IPA_IP_v6) /* for ipv6 */
							{
								IPACMDBG_H("Delete client index %d ipv6 Qos rules for %d-st ipv6 for tx:%d\n", clt_indx,num_v6,tx_index);
								rt_hdl = it->second.hdl_v6[tx_index].rt_rule_hdl_v6;
								if(m_routing.DeleteRoutingHdl(rt_hdl, IPA_IP_v6) == false)
								{
									return IPACM_FAILURE;
								}
								rt_hdl = it->second.hdl_v6[tx_index].rt_rule_hdl_v6_wan;
								if(m_routing.DeleteRoutingHdl(rt_hdl, IPA_IP_v6) == false)
								{
									return IPACM_FAILURE;
								}
							}
						} /* end of tx loop */
						it->second.route_rule_set_v6 = false;
						get_client_memptr(wlan_client, clt_indx)->route_rule_set_v6 = 0;;
					} /* end of route_rule_set_v6 */
				} /* end of for loop */
			}
			IPACMDBG_H("Current clnt-index:%d ipv6_set= %d, route_rule_set_v6= %d, update ipa_num_clients_ipv6:%d\n",
				clt_indx, get_client_memptr(wlan_client, clt_indx)->ipv6_set,
				get_client_memptr(wlan_client, clt_indx)->route_rule_set_v6,
				IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
		}
		return IPACM_SUCCESS;
	}

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		inline bool is_lan_stats_index_available()
		{
			int cnt;

			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (IPACM_Wlan::active_lan_client_index[cnt].lan_stats_idx == -1) {
					IPACMDBG_H("Available free index :%d\n", cnt);
					return true;
				}
			}

			IPACMDBG_H("No free index available\n");
			return false;
		}

		inline int8_t get_free_active_lan_stats_index(uint8_t *mac_addr, int ipa_if_num)
		{
			int cnt;

			if (!IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable)
			{
				IPACMDBG_H("LAN stats functionality is not enabled.\n");
				return -1;
			}

			IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					mac_addr[0], mac_addr[1], mac_addr[2],
					mac_addr[3], mac_addr[4], mac_addr[5]);

			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (IPACM_Wlan::active_lan_client_index[cnt].lan_stats_idx == -1) {
					IPACMDBG_H("Got active lan stats index :%d, reserve it\n", cnt);
					IPACM_Wlan::active_lan_client_index[cnt].lan_stats_idx = cnt;
					memcpy(IPACM_Wlan::active_lan_client_index[cnt].mac,
							mac_addr,
							IPA_MAC_ADDR_SIZE);
					IPACM_Wlan::active_lan_client_index[cnt].ipa_if_num = ipa_if_num;
					return cnt;
				}
			}

			IPACMDBG_H("index not available\n");
			return -1;
		}

		inline int8_t get_free_inactive_lan_stats_index(uint8_t *mac_addr)
		{
			int cnt;

			if (!IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable)
			{
				IPACMDBG_H("LAN stats functionality is not enabled.\n");
				return -1;
			}

			IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					mac_addr[0], mac_addr[1], mac_addr[2],
					mac_addr[3], mac_addr[4], mac_addr[5]);

			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (IPACM_Wlan::inactive_lan_client_index[cnt].lan_stats_idx == -1) {
					IPACMDBG_H("Got inactive lan stats index :%d, reserve it\n", cnt);
					IPACM_Wlan::inactive_lan_client_index[cnt].lan_stats_idx = cnt;
					memcpy(IPACM_Wlan::inactive_lan_client_index[cnt].mac,
							mac_addr,
							IPA_MAC_ADDR_SIZE);
					IPACM_Wlan::inactive_lan_client_index[cnt].ipa_if_num = ipa_if_num;
					return cnt;
				}
			}

			IPACMDBG_H("index not available\n");
			return -1;
		}

		inline int8_t get_lan_stats_index(uint8_t *mac_addr)
		{
			int cnt;

			if (!IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable)
			{
				IPACMDBG_H("LAN stats functionality is not enabled.\n");
				return -1;
			}

			IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					mac_addr[0], mac_addr[1], mac_addr[2],
					mac_addr[3], mac_addr[4], mac_addr[5]);

			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if ((memcmp(IPACM_Wlan::active_lan_client_index[cnt].mac,
						mac_addr,
						IPA_MAC_ADDR_SIZE) == 0) &&
						(IPACM_Wlan::active_lan_client_index[cnt].ipa_if_num
						== ipa_if_num)) {
					IPACMDBG_H("Got lan stats index :%d, return\n", cnt);
					IPACM_Wlan::active_lan_client_index[cnt].lan_stats_idx = cnt;
					memcpy(IPACM_Wlan::active_lan_client_index[cnt].mac,
							mac_addr,
							IPA_MAC_ADDR_SIZE);
					return cnt;
				}
			}

			IPACMDBG_H("index not available\n");
			return -1;
		}

		inline int get_available_inactive_lan_client(uint8_t *mac_addr, int *ipa_if_num)
		{
			int cnt;

			if (!IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable)
			{
				IPACMDBG_H("LAN stats functionality is not enabled.\n");
				return IPACM_FAILURE;
			}

			IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					mac_addr[0], mac_addr[1], mac_addr[2],
					mac_addr[3], mac_addr[4], mac_addr[5]);

			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (IPACM_Wlan::inactive_lan_client_index[cnt].lan_stats_idx != -1) {
					IPACMDBG_H("Got inactive lan stats index :%d, return the mac\n", cnt);
					memcpy(mac_addr, IPACM_Wlan::inactive_lan_client_index[cnt].mac, IPA_MAC_ADDR_SIZE);
					*ipa_if_num = IPACM_Wlan::inactive_lan_client_index[cnt].ipa_if_num;
					return IPACM_SUCCESS;
				}
			}

			IPACMDBG_H("No inactive client\n");
			return IPACM_FAILURE;
		}

		inline int8_t reset_active_lan_stats_index(int8_t idx, uint8_t *mac_addr)
		{
			if (!IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable)
			{
				IPACMDBG_H("LAN stats functionality is not enabled.\n");
				return IPACM_FAILURE;
			}

			IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					mac_addr[0], mac_addr[1], mac_addr[2],
					mac_addr[3], mac_addr[4], mac_addr[5]);

			if (idx < 0 || idx >= IPA_MAX_NUM_HW_PATH_CLIENTS ||
				memcmp(IPACM_Wlan::active_lan_client_index[idx].mac,
								mac_addr,
								IPA_MAC_ADDR_SIZE))
			{
				IPACMDBG_H("Index :%d invalid\n", idx);
				return IPACM_FAILURE;
			}
			memset(&IPACM_Wlan::active_lan_client_index[idx], -1, sizeof(ipa_lan_client_idx));
			return IPACM_SUCCESS;
		}

		inline int8_t reset_inactive_lan_stats_index(uint8_t *mac_addr)
		{
			int cnt;

			if (!IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable)
			{
				IPACMDBG_H("LAN stats functionality is not enabled.\n");
				return IPACM_FAILURE;
			}

			IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					mac_addr[0], mac_addr[1], mac_addr[2],
					mac_addr[3], mac_addr[4], mac_addr[5]);

			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (memcmp(IPACM_Wlan::inactive_lan_client_index[cnt].mac,
								mac_addr,
								IPA_MAC_ADDR_SIZE) == 0)
				{
					memset(&IPACM_Wlan::inactive_lan_client_index[cnt], -1, sizeof(ipa_lan_client_idx));
					return IPACM_SUCCESS;
				}
			}
			return IPACM_FAILURE;
		}

		inline void reset_lan_stats_index()
		{
			int i;

			if (!IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable)
			{
				IPACMDBG_H("LAN stats functionality is not enabled.\n");
				return;
			}

			/* Reset everything based on ipa_if_num. */
			for (i = 0; i < IPA_MAX_NUM_HW_PATH_CLIENTS; i++)
			{
				if (IPACM_Wlan::active_lan_client_index[i].ipa_if_num == ipa_if_num)
					memset(&IPACM_Wlan::active_lan_client_index[i], -1, sizeof(ipa_lan_client_idx));
				if (IPACM_Wlan::inactive_lan_client_index[i].ipa_if_num == ipa_if_num)
					memset(&IPACM_Wlan::inactive_lan_client_index[i], -1, sizeof(ipa_lan_client_idx));
			}
		}

#endif

	/* for handle wifi client initial,copy all partial headers (tx property) */
	int handle_wlan_client_init_ex(ipacm_event_data_wlan_ex *data, bool delay_init, uint16_t vlan_id = 0);

	/* for handle primary wifi client, copy wifi data. */
	int handle_wlan_primary_client_init_ex(ipacm_event_data_wlan_ex *data);


	int handle_wlan_vlan_client_init(int client_idx, ipacm_bridge *bridge, uint16_t vlan_id);

	/*handle wifi client */
	int handle_wlan_client_ipaddr(ipacm_event_data_all *data);

	/*handle wifi client routing rule*/
	int handle_wlan_client_route_rule(uint8_t *mac_addr, ipa_ip_type iptype, uint16_t vlan_id = 0);

#ifdef FEATURE_STATIC_POLICY
		/* handle wlan client PDN<->DSCP based routing rule addition*/
		int handle_pdn_dscp_wlan_client_route_rule(uint8_t *mac_addr,
			ipa_ip_type iptype, uint32_t trigger, uint16_t vlan_id = 0,
			uint8_t mux_id = 0, uint8_t dscp_val = 0, uint32_t* ipv6_addr = 0);
#ifdef IPA_HW_FNR_STATS
		/* handle wlan client PDN<->DSCP based routing rule addition when LAN Stats is enabled*/
		int handle_pdn_dscp_wlan_client_route_rule_ext_v2(uint8_t *mac_addr,
			ipa_ip_type iptype, uint32_t trigger, uint32_t* ipv6_addr = 0,
			uint16_t vlan_id = 0, uint8_t mux_id = 0, uint8_t dscp_val = 0);
#endif //IPA_HW_FNR_STATS
		/* handle wlan client PDN<->DSCP based routing rule deletion*/
		int delete_pdn_dscp_wlan_rtrules(ipa_ip_type iptype,
			uint32_t trigger, int clnt_idx = -1, int mux_id = 0);
#endif //FEATURE_STATIC_POLICY

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	/*handle wifi client routing rule with rule id*/
	int handle_wlan_client_route_rule_ext(uint8_t *mac_addr, ipa_ip_type iptype, uint16_t vlan_id = 0);
#endif

	/*handle wifi client power-save mode*/
	int handle_wlan_client_pwrsave(uint8_t *mac_addr);

	/*handle wifi client del mode*/
	int handle_wlan_client_down_evt(uint8_t *mac_addr, uint16_t vlan_id = 0);

	/*handle primary wifi client del mode*/
	int handle_wlan_primary_client_down_evt(uint8_t *mac_addr);

	/*handle wlan iface down event*/
	int handle_down_evt();

	/*handle new ipaddr delete event*/
	void HandleNeighIpAddrDelEvt(int clt_indx);

	/*handle reset wifi-client rt-rules */
	int handle_wlan_client_reset_rt(ipa_ip_type iptype);

	void handle_SCC_MCC_switch(ipa_ip_type);

	int extract_instance_id_from_wlan_iface(char*);

/* functions to handle wlan client mac based filtering */
	int handle_wlan_mac_flt_event();
	void delete_wlan_mac_flt_rules();
	int handle_wlan_client_mac_flt_route_rule(ipa_ip_type iptype, int clt_index, bool is_blacklist);
	int handle_wlan_mac_flt_conn_disc(uint8_t * mac_addr, bool con_state_flag);

	/* refresh default filtering rules */
	int handle_refresh_filtering_rules(bool wlan_vlan_mpdn_enable = false);

	int handle_wlan_qos_route_rule(uint8_t *client_mac, uint16_t vlan_id,
		ipa_ip_type iptype, list<qos_param_info>::iterator qos_param,
		uint32_t *ipv6_addr = NULL);
	int handle_wlan_qos_route_rule_ext_v2(uint8_t *client_mac, uint16_t vlan_id,
		ipa_ip_type iptype, list<qos_param_info>::iterator qos_param,
		uint32_t *ipv6_addr = NULL);
	int install_all_wlan_qos_route_rule(uint8_t * client_mac,
		uint16_t vlan_id, uint32_t *ipv6_addr = NULL);
	int if_wlan_client_qos_rule_needed(uint8_t *client_mac,
		uint16_t vlan_id, list<qos_param_info>::iterator qos_param,
		uint32_t *ipv6_addr = NULL);
	int delete_wlan_client_qos_rule(uint8_t *client_mac, uint16_t vlan_id,
		ipa_ip_type iptype, uint32_t *ipv6_addr = NULL);
	int delete_wlan_client_info_from_qos(uint8_t *client_mac,
		uint16_t vlan_id, list<qos_param_info>::iterator qos_param,
		uint32_t *ipv6_addr = NULL);
	int delete_all_wlan_client_qos_rules();
	int delete_all_wlan_client_info_from_qos(
		list<qos_param_info>::iterator qos_param);
	int handle_wlan_r2_subnet(ipacm_event_new_neigh_vlan *param);
};


#endif /* IPACM_WLAN_H */
