/*
 * Copyright (c) 2013-2021, The Linux Foundation. All rights reserved.
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
 * Copyright (c) 2022-2025 Qualcomm Innovation Center, Inc. All rights reserved.
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
	IPACM_Wlan.cpp

	@brief
	This file implements the WLAN iface functionality.

	@Author
	Skylar Chang
*/

#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <IPACM_Wlan.h>
#include <IPACM_Netlink.h>
#include <fcntl.h>
#include <sys/inotify.h>
#include <IPACM_Wan.h>
#include <IPACM_Lan.h>
#include <IPACM_IfaceManager.h>
#include <IPACM_ConntrackListener.h>


/* static member to store the number of total wifi clients within all APs*/
int IPACM_Wlan::total_num_wifi_clients = 0;

int IPACM_Wlan::num_wlan_ap_iface = 0;

#define BSSTYPE_SVAP 72
#define VLAN_TPID_SIZE 2
#define VLAN_VID_MASK 0x0FFF

#ifndef IPA_LAN_RX_HDR_NAME
#define IPA_LAN_RX_HDR_NAME "ipa_lan_hdr"
#endif

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
bool IPACM_Wlan::lan_stats_inited = false;
ipa_lan_client_idx IPACM_Wlan::active_lan_client_index[IPA_MAX_NUM_HW_PATH_CLIENTS];
ipa_lan_client_idx IPACM_Wlan::inactive_lan_client_index[IPA_MAX_NUM_HW_PATH_CLIENTS];
#endif

extern char *ipa_l2_hdr_type[];
ap_dflt_rules IPACM_Wlan::wlan_ap_dflt_rules[MAX_SUPPORTED_WLAN_PIPES];


IPACM_Wlan::IPACM_Wlan(char *iface_name, int iface_index, bool ast_update_needed) :
		IPACM_Lan(iface_name, iface_index), ipv6ct_inst(Ipv6ct::GetInstance())
{
	int i = 0;
#define WLAN_AMPDU_DEFAULT_FILTER_RULES 3

	wlan_ap_index = IPACM_Wlan::num_wlan_ap_iface;
	/* In EM config, we support 14 VAPs in total. */
	if(wlan_ap_index < 0 || wlan_ap_index >= IPA_MAX_ACTIVE_WLAN_IFACE )
	{
		IPACMERR("Wlan_ap_index is not correct: %d, not support %d APs .\n", wlan_ap_index, wlan_ap_index + 1);
		if (tx_prop != NULL)
		{
			free(tx_prop);
			tx_prop = NULL;
		}
		if (rx_prop != NULL)
		{
			free(rx_prop);
			rx_prop = NULL;
		}
		if (iface_query != NULL)
		{
			free(iface_query);
			iface_query = NULL;
		}

		/* reset tx_prop & rx_prop and ifaceMGR will delete instance */
		return;
	}

	num_wifi_client = 0;
	num_wifi_primary_client = 0;
	header_name_count = 0;
	wlan_client = NULL;
	wlan_primary_client = NULL;
	wlan_client_len = 0;
	svap_iface = false;
	vlan_enabled_ap = false;
	svap_dummy_route_rule_v4_hdl = 0;
	svap_dummy_route_rule_v6_hdl = 0;

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		if (lan_stats_inited == false)
		{
			for (i = 0; i < IPA_MAX_NUM_HW_PATH_CLIENTS; i++)
			{
				active_lan_client_index[i].lan_stats_idx = -1;
				memset(active_lan_client_index[i].mac, 0, IPA_MAC_ADDR_SIZE);
				inactive_lan_client_index[i].lan_stats_idx = -1;
				memset(inactive_lan_client_index[i].mac, 0, IPA_MAC_ADDR_SIZE);
			}
			lan_stats_inited = true;
		}
#endif

	if(iface_query != NULL)
	{
		wlan_client_len = (sizeof(ipa_wlan_client)) + (iface_query->num_tx_props * sizeof(wlan_client_rt_hdl));
		wlan_client = (ipa_wlan_client *)calloc(IPA_MAX_NUM_WIFI_CLIENTS, wlan_client_len);
		if (wlan_client == NULL)
		{
			IPACMERR("unable to allocate memory\n");
			return;
		}
		wlan_primary_client = (ipa_wlan_primary_client *)calloc(IPA_MAX_NUM_WIFI_CLIENTS,
			(sizeof(ipa_wlan_primary_client)));
		if (wlan_primary_client == NULL)
		{
			IPACMERR("unable to allocate memory\n");
			return;
		}
		IPACMDBG_H("index:%d constructor: Tx properties:%d\n", iface_index, iface_query->num_tx_props);
	}
	Nat_App = NatApp::GetInstance();
	if (Nat_App == NULL)
	{
		IPACMERR("unable to get Nat App instance \n");
		return;
	}

	IPACM_Wlan::num_wlan_ap_iface++;
	IPACMDBG_H("Now the number of wlan AP iface is %d\n", IPACM_Wlan::num_wlan_ap_iface);

	m_is_guest_ap = false;
	if (IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].wlan_mode == INTERNET)
	{
		m_is_guest_ap = true;
	}
	IPACMDBG_H("%s: guest ap enable: %d \n",
		IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name, m_is_guest_ap);

#ifdef FEATURE_IPA_ANDROID
	/* set the IPA-client pipe enum */
	if(ipa_if_cate == WLAN_IF)
	{
		handle_tethering_client(false, IPACM_CLIENT_WLAN);
	}
#endif

	/* Update the device type. */
	device_type = IPACM_CLIENT_DEVICE_TYPE_WLAN;

	IPACMDBG_H ("Device type %d\n", device_type);

	ast_update = ast_update_needed;
	IPACMDBG_H ("AST update needed %d\n", ast_update);

	/* Update if the interface is SVAP or not if the mesh R2 or greater is enabled */
	if (IPACM_Iface::ipacmcfg->ipacm_emesh_enable && IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 2) {
		update_svap_state();
		/* Update DSCP PCP mapping if the mesh R3 */
		if(is_svap_iface() && IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 3)
		{
			add_dscp_pcp_mapping();
		}
	}
	IPACMDBG_H("Svap interface %d for wlan ap index %d\n", is_svap_iface(), wlan_ap_index);

	/* install dummy rules if AST upate is required */
	if (ast_update) {
		add_rt_rules_for_ast_update_ifaces();
	}
	return;
}


IPACM_Wlan::~IPACM_Wlan()
{
	if(wlan_client != NULL)
	{
		free(wlan_client);
	}
	if (wlan_primary_client != NULL)
	{
		free(wlan_primary_client);
	}
	IPACM_EvtDispatcher::deregistr(this);
	IPACM_IfaceManager::deregistr(this);
	IPACM_Wlan::num_wlan_ap_iface--;
	return;
}

void IPACM_Wlan::event_callback(ipa_cm_event_id event, void *param)
{
	if(is_active == false && event != IPA_LAN_DELETE_SELF)
	{
		IPACMDBG_H("The interface is no longer active, return.\n");
		return;
	}

	int ipa_interface_index;
	int if_index;
	int wlan_index, cnt, primary_wlan_index;
	ipacm_ext_prop* ext_prop;
	ipacm_event_iface_up* data_wan;
	ipacm_event_iface_up_tehter* data_wan_tether;
	list <ipacm_event_data_all>::iterator it;
	ipacm_event_data_all *data_all=NULL;
	ipacm_cmd_q_data evt_data;
	int m_fd;
	struct ipa_ioc_dscp_pcp_map_info dscp_pcp_map_info;
#ifdef FEATURE_STATIC_POLICY
	ipacm_event_pdn_dscp_info* pdn_dscp_data;
	uint8_t mux_id;
	uint8_t dscp_val;
#endif
#ifdef FEATURE_IPA_IPSEC
	struct ipa_ioc_ipsec_ul_flt_attr *uf;
#endif

	switch (event)
	{
	/* support eth pdu ipacm disable */
	case IPA_IPACM_DISABLE:
		IPACMDBG_H("Received IPA_IPACM_DISABLE, treat as IPA_WLAN_LINK_DOWN_EVENT\n");
	case IPA_WLAN_LINK_DOWN_EVENT:
		{
			ipacm_event_data_fid *data = (ipacm_event_data_fid *)param;
			if (event != IPA_IPACM_DISABLE)
			{
				ipa_interface_index = iface_ipa_index_query(data->if_index);
			}
			if (((ipa_interface_index == ipa_if_num) && (!strncmp(data->iface_name,dev_name,
										strlen(dev_name)))) || event == IPA_IPACM_DISABLE)
			{
				IPACMDBG_H("Received IPA_WLAN_LINK_DOWN_EVENT\n");
				if (is_svap_iface() &&
				    IPACM_Iface::ipacmcfg->ipacm_emesh_mode >=
					    3 &&
				    IPACM_Iface::ipacmcfg->dscp_pcp_config_cache
						    .add == 1) {
					dscp_pcp_map_info.add = 0;
					IPACMDBG_H(
						"Issuing DSCP PCP delete command\n");
					m_fd = open(IPA_DEVICE_NAME, O_RDWR);
					if (0 !=
					    ioctl(m_fd,
						  IPA_IOC_ADD_DEL_DSCP_PCP_MAPPING,
						  &dscp_pcp_map_info)) {
						IPACMDBG_H(
							"Failed ioctl IPA_IOC_ADD_DEL_DSCP_PCP_MAPPING\n");
						close(m_fd);
						return;
					}
					IPACM_Iface::ipacmcfg
						->dscp_pcp_config_cache.add = 0;
				}
				handle_down_evt();
				/* reset the AP-iface category to unknown */
				IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_cat = UNKNOWN_IF;
				IPACM_Iface::ipacmcfg->DelNatIfaces(dev_name); // delete NAT-iface
				IPACM_Wlan::total_num_wifi_clients = (IPACM_Wlan::total_num_wifi_clients) - \
                                                                     (num_wifi_client);

				return;
			}
		}
		break;

	case IPA_PRIVATE_SUBNET_CHANGE_EVENT:
		{
			ipacm_event_data_fid *data = (ipacm_event_data_fid *)param;
			/* internel event: data->if_index is ipa_if_index */
			if (data->if_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_PRIVATE_SUBNET_CHANGE_EVENT from itself posting, ignore\n");
				return;
			}
			else
			{
				IPACMDBG_H("Received IPA_PRIVATE_SUBNET_CHANGE_EVENT from other LAN iface \n");
#if defined(FEATURE_IPA_ANDROID) || defined(FEATURE_VLAN_MPDN)
				handle_private_subnet_android(IPA_IP_v4);
#endif
				IPACMDBG_H(" delete old private subnet rules, use new sets \n");
				return;
			}
		}
		break;

	case IPA_LAN_DELETE_SELF:
	{
		ipacm_event_data_fid *data = (ipacm_event_data_fid *)param;
		if((data->if_index == ipa_if_num) && (!strncmp(data->iface_name, dev_name, strlen(dev_name))))
		{
			IPACMDBG_H("Now the number of wlan AP iface is %d\n", IPACM_Wlan::num_wlan_ap_iface);

			IPACMDBG_H("Received IPA_LAN_DELETE_SELF event.\n");
			IPACMDBG_H("ipa_WLAN (%s):ipa_index (%d) instance close \n", IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name, ipa_if_num);
#ifdef FEATURE_ETH_BRIDGE_LE
			if(rx_prop != NULL)
			{
				free(rx_prop);
				rx_prop = NULL;
			}
			if(tx_prop != NULL)
			{
				free(tx_prop);
				tx_prop = NULL;
			}
			if(iface_query != NULL)
			{
				free(iface_query);
				iface_query = NULL;
			}
#endif
			delete this;
		}
		break;
	}

#ifdef FEATURE_IPACM_UL_FIREWALL
	case IPA_FIREWALL_CHANGE_EVENT:
	{
		IPACMDBG_H("Received IPA_FIREWALL_CHANGE_EVENT\n");

		if(ip_type != IPA_IP_v4)
		{
			IPACMDBG_H ("iface_ul_firewall Addr = (%p)\n", &iface_ul_firewall);
#ifdef FEATURE_IPv6CT_DISABLED
#ifdef IPA_V6_UL_WL_FIREWALL_HANDLE
			configure_v6_ul_firewall_wlan();
#else
			configure_v6_ul_firewall();
#endif
#endif
		}
		else
		{
			IPACMERR("IP type is not valid.\n");
		}
		break;
	}
#endif //FEATURE_IPACM_UL_FIREWALL

	case IPA_ADDR_ADD_EVENT:
		{
			ipacm_event_data_addr *data = (ipacm_event_data_addr *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);

			if ( (data->iptype == IPA_IP_v4 && data->ipv4_addr == 0) ||
					 (data->iptype == IPA_IP_v6 &&
						data->ipv6_addr[0] == 0 && data->ipv6_addr[1] == 0 &&
					  data->ipv6_addr[2] == 0 && data->ipv6_addr[3] == 0) )
			{
				IPACMDBG_H("Invalid address, ignore IPA_ADDR_ADD_EVENT event\n");
				return;
			}

			if (ipa_interface_index == ipa_if_num)
			{
				/* check v4 not setup before, v6 can have 2 iface ip */
				if( ((data->iptype != ip_type) && (ip_type != IPA_IP_MAX))
				    || ((data->iptype==IPA_IP_v6) && (num_dft_rt_v6!=MAX_DEFAULT_v6_ROUTE_RULES)))
				{
					IPACMDBG_H("Got IPA_ADDR_ADD_EVENT ip-family:%d, v6 num %d: \n",data->iptype,num_dft_rt_v6);

					/* Post event to NAT */
					if (post_lan_up_event(data) || handle_addr_evt(data) == IPACM_FAILURE)
					{
						return;
					}

#if defined(FEATURE_IPA_ANDROID) || defined(FEATURE_VLAN_MPDN)
					handle_private_subnet_android(data->iptype);
#else
					handle_private_subnet(data->iptype);
#endif

#ifdef FEATURE_VLAN_MPDN
					if(data->iptype == IPA_IP_v6)
					{
						/* if there are any v6 calls up, update rules */
						modify_ipv6_prefix_flt_rule();
					}
#endif

					if (!IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name))
					{
#ifdef FEATURE_STATIC_POLICY
						if(IPACM_Wan::isWanUP(ipa_if_num) &&
							!IPACM_Iface::ipacmcfg->ipacm_static_policy_enable) /* Modem v4 call is UP?*/
#else
						if(IPACM_Wan::isWanUP(ipa_if_num)) /* Modem v4 call is UP?*/
#endif
						{
							if(data->iptype == IPA_IP_v4 || data->iptype == IPA_IP_MAX)
							{
								if(IPACM_Wan::backhaul_is_sta_mode == false)
								{
									ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
									IPACM_Lan::handle_wan_up_ex(ext_prop, IPA_IP_v4,
													IPACM_Wan::getXlat_Mux_Id());
								}
								else
								{
									IPACM_Lan::handle_wan_up(IPA_IP_v4);
								}
							}
						}
					}
#ifdef FEATURE_IPv6CT_DISABLED
#ifdef FEATURE_IPACM_UL_FIREWALL
						IPACM_Wan::read_firewall_filter_rules_ul();
#endif //FEATURE_IPACM_UL_FIREWALL
#endif
#ifdef FEATURE_STATIC_POLICY
					if(IPACM_Wan::isWanUP_V6(ipa_if_num) &&
						!IPACM_Iface::ipacmcfg->ipacm_static_policy_enable) /* Modem v6 call is UP?*/
#else
					if(IPACM_Wan::isWanUP_V6(ipa_if_num)) /* Modem v6 call is UP?*/
#endif
					{
						if(data->iptype == IPA_IP_v6)
						{
							memcpy(ipv6_prefix, IPACM_Wan::backhaul_ipv6_prefix, sizeof(ipv6_prefix));
							install_ipv6_prefix_flt_rule(IPACM_Wan::backhaul_ipv6_prefix);
#ifdef FEATURE_IPv6CT_DISABLED
#ifdef FEATURE_IPACM_UL_FIREWALL
#ifdef IPA_V6_UL_WL_FIREWALL_HANDLE
								configure_v6_ul_firewall_wlan();
#else
								configure_v6_ul_firewall();
#endif
#endif //FEATURE_IPACM_UL_FIREWALL
#endif
						}
						if((data->iptype == IPA_IP_v6 || data->iptype == IPA_IP_MAX) && num_dft_rt_v6 == 1)
						{
							if(IPACM_Wan::backhaul_is_sta_mode == false)
							{
								ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
								IPACM_Lan::handle_wan_up_ex(ext_prop, IPA_IP_v6, 0);
							}
							else
							{
								IPACM_Lan::handle_wan_up(IPA_IP_v6);
							}
						}
#ifdef FEATURE_IPACM_UL_FIREWALL
						else
							IPACMDBG_H("WAN v6 is not UP\n");
#endif //FEATURE_IPACM_UL_FIREWALL
					}
					else
					{
						IPACMDBG_H("Checking for V6 VLAN PDN\n");
						check_vlan_PDNUp(IPA_IP_v6);
					}
					IPACMDBG_H("Finished checking wan_up\n");
					/* checking if SW-RT_enable */
					if (IPACM_Iface::ipacmcfg->ipa_sw_rt_enable == true)
					{
						/* handle software routing enable event*/
						IPACMDBG_H("IPA_SW_ROUTING_ENABLE for iface: %s \n",IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name);
						handle_software_routing_enable();
					}
				}
			}
		}
		break;
#ifdef FEATURE_IPA_ANDROID
	case IPA_HANDLE_WAN_UP_TETHER:
		IPACMDBG_H("Received IPA_HANDLE_WAN_UP_TETHER event\n");

		data_wan_tether = (ipacm_event_iface_up_tehter*)param;
		if(data_wan_tether == NULL)
		{
			IPACMERR("No event data is found.\n");
			return;
		}
		IPACMDBG_H("Backhaul is sta mode?%d, if_index_tether:%d tether_if_name:%s\n", data_wan_tether->is_sta,
					data_wan_tether->if_index_tether,
					IPACM_Iface::ipacmcfg->iface_table[data_wan_tether->if_index_tether].iface_name);
		if (data_wan_tether->if_index_tether == ipa_if_num)
		{
			if(ip_type == IPA_IP_v4 || ip_type == IPA_IP_MAX)
			{
				if(data_wan_tether->is_sta == false)
				{
					ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
					IPACM_Lan::handle_wan_up_ex(ext_prop, IPA_IP_v4, 0);
				}
				else
				{
					IPACM_Lan::handle_wan_up(IPA_IP_v4);
				}
			}
		}
		break;

	case IPA_HANDLE_WAN_UP_V6_TETHER:
		IPACMDBG_H("Received IPA_HANDLE_WAN_UP_V6_TETHER event\n");

		data_wan_tether = (ipacm_event_iface_up_tehter*)param;
		if(data_wan_tether == NULL)
		{
			IPACMERR("No event data is found.\n");
			return;
		}
		IPACMDBG_H("Backhaul is sta mode?%d, if_index_tether:%d tether_if_name:%s\n", data_wan_tether->is_sta,
					data_wan_tether->if_index_tether,
					IPACM_Iface::ipacmcfg->iface_table[data_wan_tether->if_index_tether].iface_name);
		if (data_wan_tether->if_index_tether == ipa_if_num)
		{
			if(ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX)
			{
				memcpy(ipv6_prefix, data_wan_tether->ipv6_prefix, sizeof(ipv6_prefix));
				install_ipv6_prefix_flt_rule(data_wan_tether->ipv6_prefix);
				if(data_wan_tether->is_sta == false)
				{
					ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
					IPACM_Lan::handle_wan_up_ex(ext_prop, IPA_IP_v6, 0);
				}
				else
				{
					IPACM_Lan::handle_wan_up(IPA_IP_v6);
				}
			}
		}
		break;

	case IPA_HANDLE_WAN_DOWN_TETHER:
		IPACMDBG_H("Received IPA_HANDLE_WAN_DOWN_TETHER event\n");
		data_wan_tether = (ipacm_event_iface_up_tehter*)param;
		if(data_wan_tether == NULL)
		{
			IPACMERR("No event data is found.\n");
			return;
		}
		IPACMDBG_H("Backhaul is sta mode?%d, if_index_tether:%d tether_if_name:%s\n", data_wan_tether->is_sta,
					data_wan_tether->if_index_tether,
					IPACM_Iface::ipacmcfg->iface_table[data_wan_tether->if_index_tether].iface_name);
		if (data_wan_tether->if_index_tether == ipa_if_num)
		{
			if(data_wan_tether->is_sta == false && wlan_ap_index > 0)
			{
				IPACMDBG_H("This is not the first AP instance and not STA mode, ignore WAN_DOWN event.\n");
				return;
			}
			if (rx_prop != NULL)
			{
				if(ip_type == IPA_IP_v4 || ip_type == IPA_IP_MAX)
				{
					handle_wan_down(data_wan_tether->is_sta);
				}
			}
		}
		break;

	case IPA_HANDLE_WAN_DOWN_V6_TETHER:
		IPACMDBG_H("Received IPA_HANDLE_WAN_DOWN_V6_TETHER event\n");
		data_wan_tether = (ipacm_event_iface_up_tehter*)param;
		if(data_wan_tether == NULL)
		{
			IPACMERR("No event data is found.\n");
			return;
		}
		IPACMDBG_H("Backhaul is sta mode?%d, if_index_tether:%d tether_if_name:%s\n", data_wan_tether->is_sta,
					data_wan_tether->if_index_tether,
					IPACM_Iface::ipacmcfg->iface_table[data_wan_tether->if_index_tether].iface_name);
		if (data_wan_tether->if_index_tether == ipa_if_num)
		{
			/* clean up v6 RT rules*/
			IPACMDBG_H("Received IPA_WAN_V6_DOWN in WLAN-instance and need clean up client IPv6 address \n");
			/* reset wifi-client ipv6 rt-rules */
			handle_wlan_client_reset_rt(IPA_IP_v6);

			if (rx_prop != NULL)
			{
				if(ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX)
				{
					handle_wan_down_v6(data_wan_tether->is_sta, false);
				}
			}
		}
		break;
#ifdef IPA_MTU_EVENT_MAX
	case IPA_MTU_UPDATE:
	{
		IPACMDBG_H("Received IPA_MTU_UPDATE");
		ipacm_event_mtu_info *evt_data = (ipacm_event_mtu_info *)param;
		ipa_mtu_info *data = &(evt_data->mtu_info);

		/* IPA_IP_MAX means both ipv4 and ipv6 */
		if ((data->ip_type == IPA_IP_v4 || data->ip_type == IPA_IP_MAX) && IPACM_Wan::isWanUP(ipa_if_num))
		{
			modify_private_subnet();
		}

		/* IPA_IP_MAX means both ipv4 and ipv6 */
		if ((data->ip_type == IPA_IP_v6 || data->ip_type == IPA_IP_MAX) && IPACM_Wan::isWanUP_V6(ipa_if_num))
		{
			modify_ipv6_prefix_flt_rule();
		}
	}
	break;
#endif

#else
	case IPA_HANDLE_WAN_UP:
		IPACMDBG_H("Received IPA_HANDLE_WAN_UP event\n");

		data_wan = (ipacm_event_iface_up*)param;
		if(data_wan == NULL)
		{
			IPACMERR("No event data is found.\n");
			return;
		}

#ifdef FEATURE_VLAN_MPDN
		/* VLAN IFACES don't care about default route */
		if((IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name)) &&
			(IPACM_Iface::ipacmcfg->wlan_vlan_mpdn_enabled == TRUE))
		{
			if(data_wan->is_sta == false)
			{
				handle_backhaul_switch_vlan_mode(false);
			}
			else
			{
				handle_backhaul_switch_vlan_mode(true);
			}
			return;
		}
#endif

		//Static policy mode dont care about default route. Rules will be installed by conntrack
		if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
		{
			IPACMDBG_H("IPACM in static policy enable mode. Dont need to install UL rules\n");
			return;
		}

		IPACMDBG_H("Backhaul is sta mode?%d\n", data_wan->is_sta);
		if(ip_type == IPA_IP_v4 || ip_type == IPA_IP_MAX)
		{
			if(data_wan->is_sta == false)
			{
				ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
				IPACM_Lan::handle_wan_up_ex(ext_prop, IPA_IP_v4, data_wan->xlat_mux_id);
			}
			else
			{
				IPACM_Lan::handle_wan_up(IPA_IP_v4);
			}
		}
		break;

	case IPA_HANDLE_WAN_UP_V6:
		IPACMDBG_H("Received IPA_HANDLE_WAN_UP_V6 event\n");

		data_wan = (ipacm_event_iface_up*)param;
		if(data_wan == NULL)
		{
			IPACMERR("No event data is found.\n");
			return;
		}
		IPACMDBG_H("Backhaul is sta mode?%d\n", data_wan->is_sta);
#ifdef FEATURE_VLAN_MPDN
		/* VLAN IFACES don't care about default route */
		if((IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name)) &&
			(IPACM_Iface::ipacmcfg->wlan_vlan_mpdn_enabled == TRUE))
		{
			if(data_wan->is_sta == false)
			{
				handle_backhaul_switch_vlan_mode(false);
			}
			else
			{
				handle_backhaul_switch_vlan_mode(true);
			}
			return;
		}
#endif
#ifdef FEATURE_STATIC_POLICY
		//Static policy mode dont care about default route. Rules will be installed by conntrack
		if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
		{
			IPACMDBG_H("IPACM in static policy enable mode. Dont need to install UL rules for v6\n");
			return;
		}
#endif
		if(ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX)
		{
			memcpy(ipv6_prefix, data_wan->ipv6_prefix, sizeof(ipv6_prefix));
			install_ipv6_prefix_flt_rule(data_wan->ipv6_prefix);
#ifdef FEATURE_IPv6CT_DISABLED
#ifdef FEATURE_IPACM_UL_FIREWALL
			IPACM_Wan::read_firewall_filter_rules_ul();
			if(IPACM_Wan::isWanUP_V6(ipa_if_num))
			{
#ifdef IPA_V6_UL_WL_FIREWALL_HANDLE
				configure_v6_ul_firewall_wlan();
#else
				configure_v6_ul_firewall();
#endif
			}
			else
				IPACMDBG_H("WAN v6 is not UP\n");
#endif //FEATURE_IPACM_UL_FIREWALL
#endif
			if(data_wan->is_sta == false)
			{
				ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
				IPACM_Lan::handle_wan_up_ex(ext_prop, IPA_IP_v6, 0);
			}
			else
			{
				IPACM_Lan::handle_wan_up(IPA_IP_v6);
			}

			it = neigh_cache.begin();
			while (it != neigh_cache.end())
			{
				if (it->ipv6_addr[0] == data_wan->ipv6_prefix[0] && it->ipv6_addr[1] == data_wan->ipv6_prefix[1])
				{
					evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT;
					data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
					if (data_all == NULL)
					{
						IPACMERR("Unable to allocate memory\n");
						break;
					}
					memset(data_all, 0, sizeof(ipacm_event_data_all));
					data_all->iptype = IPA_IP_v6;
					data_all->if_index = it->if_index;
					memcpy(data_all->ipv6_addr,it->ipv6_addr, 4*sizeof(uint32_t));
					memcpy(data_all->mac_addr, it->mac_addr, IPA_MAC_ADDR_SIZE);
					memcpy(data_all->iface_name, it->iface_name, IPA_IFACE_NAME_LEN);
					evt_data.evt_data = (void *)data_all;
					IPACM_EvtDispatcher::PostEvt(&evt_data);
					IPACMDBG_H("Posted event %d, with %s for ipv6 client\n",
						evt_data.event, data_all->iface_name);
					IPACMDBG_H("v6 addr : 0x%08x:%08x:%08x:%08x MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
						it->ipv6_addr[0], it->ipv6_addr[1], it->ipv6_addr[2], it->ipv6_addr[3],
						it->mac_addr[0], it->mac_addr[1], it->mac_addr[2], it->mac_addr[3], it->mac_addr[4], it->mac_addr[5]);
					it = neigh_cache.erase(it);
				}
				else
					it++;
			}
		}
		break;

	case IPA_HANDLE_WAN_DOWN:
		IPACMDBG_H("Received IPA_HANDLE_WAN_DOWN event\n");
		data_wan = (ipacm_event_iface_up*)param;
		if(data_wan == NULL)
		{
			IPACMERR("No event data is found.\n");
			return;
		}
		IPACMDBG_H("Backhaul is sta mode?%d\n", data_wan->is_sta);
		if (rx_prop != NULL)
		{
			if(ip_type == IPA_IP_v4 || ip_type == IPA_IP_MAX)
			{
				handle_wan_down(data_wan->is_sta);
			}
		}
		break;

	case IPA_HANDLE_WAN_DOWN_V6:
		IPACMDBG_H("Received IPA_HANDLE_WAN_DOWN_V6 event\n");
		data_wan = (ipacm_event_iface_up*)param;
		if(data_wan == NULL)
		{
			IPACMERR("No event data is found.\n");
			return;
		}
		/* clean up v6 RT rules*/
		IPACMDBG_H("Received IPA_WAN_V6_DOWN in WLAN-instance and need clean up client IPv6 address \n");
		/* reset wifi-client ipv6 rt-rules */
		handle_wlan_client_reset_rt(IPA_IP_v6);
		it = neigh_cache.begin();
		while (it != neigh_cache.end())
		{
			if (it->ipv6_addr[0] == data_wan->ipv6_prefix[0] && it->ipv6_addr[1] == data_wan->ipv6_prefix[1])
				it = neigh_cache.erase(it);
			else
				it++;
		}

		IPACMDBG_H("Backhaul is sta mode ? %d\n", data_wan->is_sta);
		if (rx_prop != NULL)
		{
			if(ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX)
			{
#ifdef FEATURE_UL_FIREWALL
				// pdn is down, disable its Q6 UL firewall and reconfigure for all others
				disable_dft_firewall_rules_ul_ex(0);
#ifdef FEATURE_IPv6CT_DISABLED
#ifdef IPA_V6_UL_WL_FIREWALL_HANDLE
				configure_v6_ul_firewall_wlan();
#else
				configure_v6_ul_firewall();
#endif
#endif
#endif
				handle_wan_down_v6(data_wan->is_sta, false);
			}
		}
		break;
#endif

	case IPA_WLAN_CLIENT_ADD_EVENT_EX:
		{
			ipacm_event_data_wlan_ex *data = (ipacm_event_data_wlan_ex *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			bool delay_init = false;
			if ((ipa_interface_index == ipa_if_num) &&
						(strncmp(data->iface_name, dev_name, strlen(dev_name))== 0))
			{
				int i;
				for(i=0; i<data->num_of_attribs; i++)
				{
					if (is_svap_iface() || is_vlan_iface()) {
						IPACMDBG_H("Wlan iface is SVAP, delay IPA_ETH_BRIDGE_CLIENT_ADD posting\n");
						break;
					}
					if (data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_MAC_ADDR)
					{
						IPACMDBG_H("Will post IPA_ETH_BRIDGE_CLIENT_ADD\n");
						if(IPACM_Iface::ipacmcfg->mac_addr_in_blacklist(data->attribs[i].u.mac_addr) == false)
						{
							eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_ADD, IPA_IP_MAX, data->attribs[i].u.mac_addr, NULL, dev_name);
							break;
						}
						else
						{
							IPACMDBG_H("Client is blacklisted for mac based filtering, avoid adding to lan2lan offload \n");
							break;
						}
					}
				}
				IPACMDBG_H("Received IPA_WLAN_CLIENT_ADD_EVENT\n");
				if (is_svap_iface()) {
					IPACMDBG_H("Wlan iface is SVAP, delay client init ex\n");
					delay_init = true;
				}
				if (is_vlan_iface())
				{
					IPACMDBG_H("Wlan iface is VLAN, this is primary client. Initialize. \n");
					/* VLAN client initialization will happen later. */
					handle_wlan_primary_client_init_ex(data);
				}
				else
				{
					handle_wlan_client_init_ex(data, delay_init);
				}
			}
		}
		break;

	case IPA_WLAN_CLIENT_DEL_EVENT:
		{
			ipacm_event_data_mac *data = (ipacm_event_data_mac *)param;
			int clnt_indx;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			if ((ipa_interface_index == ipa_if_num) &&
							(!strncmp(data->iface_name, dev_name, strlen(dev_name))))
			{
				IPACMDBG_H("Received IPA_WLAN_CLIENT_DEL_EVENT\n");
				if (!is_vlan_iface())
				{
					if (is_svap_iface())
					{
						clnt_indx = get_wlan_client_index(data->mac_addr);
						if (clnt_indx == IPACM_INVALID_INDEX)
						{
							IPACMERR("wlan client not found/attached \n");
							return;
						}
						eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_DEL, IPA_IP_MAX, data->mac_addr, NULL, dev_name,
							get_client_memptr(wlan_client, clnt_indx)->vlan_id);
					}
					else
					{
						eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_DEL, IPA_IP_MAX, data->mac_addr, NULL, dev_name);
					}
					/* clear wlan mac flt rules */
					if(IPACM_Iface::ipacmcfg->mac_addr_in_blacklist(data->mac_addr))
						 handle_wlan_mac_flt_conn_disc(data->mac_addr, false);

					delete_wlan_client_qos_rule(data->mac_addr, 0, IPA_IP_v4, NULL);
					delete_wlan_client_qos_rule(data->mac_addr, 0, IPA_IP_v6, NULL);
					handle_wlan_client_down_evt(data->mac_addr);
				}
				else
				{
					/* Delete all the VLAN clients associated with Primary client. */
					handle_wlan_primary_client_down_evt(data->mac_addr);
				}
			}
		}
		break;

	case IPA_WLAN_CLIENT_POWER_SAVE_EVENT:
		{
			ipacm_event_data_mac *data = (ipacm_event_data_mac *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_WLAN_CLIENT_POWER_SAVE_EVENT\n");
				handle_wlan_client_pwrsave(data->mac_addr);
			}
		}
		break;

	case IPA_WLAN_CLIENT_RECOVER_EVENT:
		{
			ipacm_event_data_mac *data = (ipacm_event_data_mac *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			uint32_t ipv6_temp[4] = {0};
			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_WLAN_CLIENT_RECOVER_EVENT\n");

				wlan_index = get_wlan_client_index(data->mac_addr);
				if ((wlan_index != IPACM_INVALID_INDEX) &&
						(get_client_memptr(wlan_client, wlan_index)->power_save_set == true))
				{

					IPACMDBG_H("change wlan client out of  power safe mode \n");
					get_client_memptr(wlan_client, wlan_index)->power_save_set = false;

					/* First add route rules and then nat rules */
					if(get_client_memptr(wlan_client, wlan_index)->ipv4_set == true) /* for ipv4 */
					{
						     IPACMDBG_H("recover client index(%d):ipv4 address: 0x%x\n",
										 wlan_index,
										 get_client_memptr(wlan_client, wlan_index)->v4_addr);

						IPACMDBG_H("Adding Route Rules\n");
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
						if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
						{
							handle_wlan_client_route_rule(data->mac_addr, IPA_IP_v4);
#ifdef FEATURE_STATIC_POLICY
							if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
							{
								handle_pdn_dscp_wlan_client_route_rule(data->mac_addr,
									IPA_IP_v4, 0, 0, 0);
							}
#endif
						}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
						else
						{
#ifdef IPA_HW_FNR_STATS
							if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
							{
								handle_wlan_client_route_rule_ext_v2(data->mac_addr, IPA_IP_v4);
#ifdef FEATURE_STATIC_POLICY
								if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
								{
									handle_pdn_dscp_wlan_client_route_rule_ext_v2(data->mac_addr,
									IPA_IP_v4, 0);
								}
#endif
							}
							else
#endif //IPA_HW_FNR_STATS
								handle_wlan_client_route_rule_ext(data->mac_addr, IPA_IP_v4);
						}
#endif
						IPACMDBG_H("Adding Nat Rules\n");
						Nat_App->ResetPwrSaveIf(get_client_memptr(wlan_client, wlan_index)->v4_addr);
					}

					if(get_client_memptr(wlan_client, wlan_index)->ipv6_set != 0) /* for ipv6 */
					{
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
						if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
						{
							handle_wlan_client_route_rule(data->mac_addr, IPA_IP_v6);
#ifdef FEATURE_STATIC_POLICY
							if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
							{
								for (auto it = rt_hdl_v6_list[wlan_index].begin();
									it != rt_hdl_v6_list[wlan_index].end();++it)
								{
									std::copy(std::begin(it->first), std::end(it->first), std::begin(ipv6_temp));
									handle_pdn_dscp_wlan_client_route_rule(data->mac_addr,
										IPA_IP_v6, 0, 0, 0, 0, ipv6_temp);
								}
							}
#endif
						}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
						else
						{
#ifdef IPA_HW_FNR_STATS
							if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
							{
								handle_wlan_client_route_rule_ext_v2(data->mac_addr, IPA_IP_v6);
#ifdef FEATURE_STATIC_POLICY
								if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
								{
									for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end();++it)
									{
										std::copy(std::begin(it->first), std::end(it->first), std::begin(ipv6_temp));
										handle_pdn_dscp_wlan_client_route_rule_ext_v2(data->mac_addr,
											IPA_IP_v6, 0, ipv6_temp);
									}
								}
#endif
							}
							else
#endif //IPA_HW_FNR_STATS
								handle_wlan_client_route_rule_ext(data->mac_addr, IPA_IP_v6);
						}
#endif
						if (ipv6ct_inst != NULL)
						{
							for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end();++it)
							{
								std::copy(std::begin(it->first), std::end(it->first), std::begin(ipv6_temp));
								ipv6ct_inst->ResetPwrSaveIf(Ipv6IpAddress(ipv6_temp, false));
							}
						}
					}
				}
			}
		}
		break;

	case IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT:
		{
			ipacm_event_new_neigh_vlan *new_neigh_data = (ipacm_event_new_neigh_vlan *)param;
			ipacm_event_data_all *data = (ipacm_event_data_all *)param;
			tether_client_info client_info;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			uint16_t vlan_id = 0;
			ipacm_event_data_wlan_ex *cached_data;
#ifdef FEATURE_STATIC_POLICY
			uint32_t temp_ipv6[4] = {0};
#endif

			/* Ignore physical iface handling for VLAN ifaces. */
			if (ipa_interface_index == ipa_if_num && !is_vlan_iface() &&
							(!strncmp(data->iface_name, dev_name, strlen(dev_name))) )
			{
				IPACMDBG_H("Received IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT\n");
				/* add to tether-client-lists */

				wlan_index = get_wlan_client_index(data->mac_addr);
				memset(&client_info, 0, sizeof(tether_client_info));
				if (data->iptype == IPA_IP_v4)
				{
					client_info.v4_addr = data->ipv4_addr;
				}
				else if  (data->iptype == IPA_IP_v6)
				{
					client_info.v4_addr = 0;
				}
				IPACMDBG_H(" iface name %s  dev %s\n", data->iface_name, dev_name);
				memcpy(client_info.iface, dev_name, IPA_IFACE_NAME_LEN);
				if(wlan_index != IPACM_INVALID_INDEX)
					IPACM_Iface::ipacmcfg->update_client_info(data->mac_addr, &client_info, true);

				if (handle_wlan_client_ipaddr(data) == IPACM_FAILURE)
				{
					return;
				}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
				if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
				{
					/* Do not add rt and NAT rule if mac flt enable for client */
					if(IPACM_Iface::ipacmcfg->mac_addr_in_blacklist(data->mac_addr) == false)
					{
						handle_wlan_client_route_rule(data->mac_addr, data->iptype);
#ifdef FEATURE_STATIC_POLICY
						if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && data->iptype == IPA_IP_v4)
						{
							handle_pdn_dscp_wlan_client_route_rule(data->mac_addr, data->iptype, 0, 0, 0);
						}
						else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && data->iptype == IPA_IP_v6)
						{
							handle_pdn_dscp_wlan_client_route_rule(data->mac_addr, data->iptype, 0, 0, 0, 0, data->ipv6_addr);
						}
#endif
						install_all_wlan_qos_route_rule(data->mac_addr, 0, data->ipv6_addr);
						/* Add NAT/IPv6CT rules after RT rules are set */
						HandleNeighIpAddrAddEvt(data);
					}
				}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
				else
				{
#ifdef IPA_HW_FNR_STATS
					if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support &&
							IPACM_Iface::ipacmcfg->mac_addr_in_blacklist(data->mac_addr) == false)
					{
						handle_wlan_client_route_rule_ext_v2(data->mac_addr, data->iptype);
#ifdef FEATURE_STATIC_POLICY
						if (data->iptype == IPA_IP_v4 && IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
						{
							handle_pdn_dscp_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client, wlan_index)->mac,
								IPA_IP_v4, 0);
						}
						else if  (data->iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
						{
							for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end(); ++it)
							{
								std::copy(std::begin(it->first), std::end(it->first), std::begin(temp_ipv6));
								handle_pdn_dscp_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client, wlan_index)->mac,
								IPA_IP_v6, 0, temp_ipv6);
							}
						}
#endif
						install_all_wlan_qos_route_rule(data->mac_addr, 0);
						HandleNeighIpAddrAddEvt(data);
					}
					else
#endif //IPA_HW_FNR_STATS
					{
						if(IPACM_Iface::ipacmcfg->mac_addr_in_blacklist(data->mac_addr) == false)
						{
							handle_wlan_client_route_rule_ext(data->mac_addr, data->iptype);
							install_all_wlan_qos_route_rule(data->mac_addr, 0);
							HandleNeighIpAddrAddEvt(data);
						}
					}
				}
#endif
				if (wlan_index == IPACM_INVALID_INDEX)
				{
					IPACMDBG_H("wlan client not found/attached \n");
					return;
				}
				get_client_memptr(wlan_client, wlan_index)->if_index = data->if_index;
				IPACMDBG_H("index %d if_index %d \n", wlan_index, get_client_memptr(wlan_client, wlan_index)->if_index);
				/* add mac balcklist rule if client is added after mac flt event is received */
				if(IPACM_Iface::ipacmcfg->mac_addr_in_blacklist(data->mac_addr) == true)
				{
					handle_wlan_mac_flt_conn_disc(data->mac_addr, true);
				}
			}
			// easy mesh R2 or vlan case
			if (IPACM_Iface::ipacmcfg->iface_in_vlan_mode(
				    data->iface_name) &&
			    is_vlan_event(data->iface_name)) {
				IPACMDBG_H("Client is a vlan wlan client \n");
				handle_wlan_vlan_neighbor(new_neigh_data);
			}
#ifdef FEATURE_VLAN_MPDN
			else {
				if (IPACM_Iface::ipacmcfg->ipacm_emesh_enable &&
				    IPACM_Iface::ipacmcfg->ipacm_emesh_mode >=
					    2 && (strstr(data->iface_name,"ath") ||
						strstr(data->iface_name,"wlan"))) {
					handle_wlan_r2_subnet(new_neigh_data);
				}
			}
#endif
		}
		break;

	case IPA_NEIGH_CLIENT_IP_ADDR_DEL_EVENT:
		{
			ipacm_event_data_all *data = (ipacm_event_data_all *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);

			IPACMDBG_H("Received IPA_NEIGH_CLIENT_IP_ADDR_DEL_EVENT event for ip_type: %d \n", data->iptype);
			IPACMDBG_H("check iface %s category: %d\n", dev_name, ipa_if_cate);

			if ((IPACM_Iface::ipacmcfg->wlan_vlan_mpdn_enabled == TRUE) &&
						is_vlan_event(data->iface_name) && is_vlan_iface())
			{
				uint16_t vlan_id = 0;
				if (data->iptype == IPA_IP_v6)
				{
					handle_wlan_del_ipv6_addr(data);
					return;
				}

				IPACMDBG_H("handling vlan WLAN client del v4 ip address for iface %s\n",
					data->iface_name);
				if(IPACM_Iface::ipacmcfg->get_vlan_id(data->iface_name, &vlan_id))
				{
					IPACMERR("failed getting vlan id for iface %s\n",
						data->iface_name);
					return;
				}

				IPACMDBG_H("WLAN iface delete client \n");
				/* Delete QOS rules. */
				if (IPACM_Iface::ipacmcfg->ipacm_qos_enable) {
					delete_wlan_client_qos_rule(data->mac_addr, vlan_id, IPA_IP_v4, NULL);
					delete_wlan_client_qos_rule(data->mac_addr, vlan_id, IPA_IP_v6, NULL);
				}

				handle_wlan_client_down_evt(data->mac_addr, vlan_id);
				eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_DEL, IPA_IP_MAX, data->mac_addr, NULL, data->iface_name, vlan_id);
				/* Update Primary client info. */
				primary_wlan_index = get_wlan_primary_client_index(data->mac_addr);
				if (primary_wlan_index != IPACM_INVALID_INDEX) {
					get_primary_client_memptr(wlan_primary_client, primary_wlan_index)->num_vlan_clients--;
					IPACMDBG_H("Num remaining VLAN clients: %d\n",
						get_primary_client_memptr(wlan_primary_client, primary_wlan_index)->num_vlan_clients);
				}
				return;
			}
		}
		break;


		/* handle software routing enable event, iface will update softwarerouting_act to true*/
	case IPA_SW_ROUTING_ENABLE:
		IPACMDBG_H("Received IPA_SW_ROUTING_ENABLE\n");
		IPACM_Iface::handle_software_routing_enable();
		break;

		/* handle software routing disable event, iface will update softwarerouting_act to false*/
	case IPA_SW_ROUTING_DISABLE:
		IPACMDBG_H("Received IPA_SW_ROUTING_DISABLE\n");
		IPACM_Iface::handle_software_routing_disable();
		break;

	case IPA_WLAN_SWITCH_TO_SCC:
		IPACMDBG_H("Received IPA_WLAN_SWITCH_TO_SCC\n");
		if(ip_type == IPA_IP_MAX)
		{
			handle_SCC_MCC_switch(IPA_IP_v4);
			handle_SCC_MCC_switch(IPA_IP_v6);
		}
		else
		{
			handle_SCC_MCC_switch(ip_type);
		}
		eth_bridge_post_event(IPA_ETH_BRIDGE_WLAN_SCC_MCC_SWITCH, IPA_IP_MAX, NULL, NULL, NULL);
		break;

	case IPA_WLAN_SWITCH_TO_MCC:
		IPACMDBG_H("Received IPA_WLAN_SWITCH_TO_MCC\n");
		/* check if alt_dst_pipe set or not */
		for (cnt = 0; cnt < tx_prop->num_tx_props; cnt++)
		{
			if (tx_prop->tx[cnt].alt_dst_pipe == 0)
			{
				IPACMERR("Tx(%d): wrong tx property: alt_dst_pipe: 0. \n", cnt);
				return;
			}
		}

		if(ip_type == IPA_IP_MAX)
		{
			handle_SCC_MCC_switch(IPA_IP_v4);
			handle_SCC_MCC_switch(IPA_IP_v6);
		}
		else
		{
			handle_SCC_MCC_switch(ip_type);
		}
		eth_bridge_post_event(IPA_ETH_BRIDGE_WLAN_SCC_MCC_SWITCH, IPA_IP_MAX, NULL, NULL, NULL);
		break;

	case IPA_CRADLE_WAN_MODE_SWITCH:
	{
		IPACMDBG_H("Received IPA_CRADLE_WAN_MODE_SWITCH event.\n");
		ipacm_event_cradle_wan_mode* wan_mode = (ipacm_event_cradle_wan_mode*)param;
		if(wan_mode == NULL)
		{
			IPACMERR("Event data is empty.\n");
			return;
		}

		if(wan_mode->cradle_wan_mode == BRIDGE)
		{
			handle_cradle_wan_mode_switch(true);
		}
		else
		{
			handle_cradle_wan_mode_switch(false);
		}
	}
	break;
	case IPA_CFG_CHANGE_EVENT:
	{
		IPACMDBG_H("Received IPA_CFG_CHANGE_EVENT event for %s with new wlan-mode: %s old wlan-mode: %s\n",
				IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name,
				(IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].wlan_mode == 0) ? "full" : "internet",
				(m_is_guest_ap == true) ? "internet" : "full");

		if (IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_cat != ipa_if_cate) {
			IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_cat = ipa_if_cate;
			IPACMDBG_H(" if_cat resetted to %d \n", IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_cat);
		}

		/* Add Natting iface to IPACM_Config if there is  Rx/Tx property */
		if (rx_prop != NULL || tx_prop != NULL)
		{
			IPACMDBG_H(" Has rx/tx properties registered for iface %s, add for NATTING \n", dev_name);
			IPACM_Iface::ipacmcfg->AddNatIfaces(dev_name);
#ifdef FEATURE_VLAN_MPDN
			if (IPACM_Iface::ipacmcfg->wlan_vlan_mpdn_enabled == TRUE && is_vlan_iface())
			{
				IPACM_Iface::ipacmcfg->restore_vlan_nat_ifaces(dev_name);
				IPACM_Iface::ipacmcfg->SetWlanVlanAp(dev_name);
			}
#endif
		}

		if (m_is_guest_ap == true && (IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].wlan_mode == FULL))
		{
			m_is_guest_ap = false;
			IPACMDBG_H("wlan mode is switched to full access mode. \n");
			eth_bridge_handle_wlan_mode_switch();
		}
		else if (m_is_guest_ap == false && (IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].wlan_mode == INTERNET))
		{
			m_is_guest_ap = true;
			IPACMDBG_H("wlan mode is switched to internet only access mode. \n");
			eth_bridge_handle_wlan_mode_switch();
		}
		else
		{
			IPACMDBG_H("No change in %s access mode. \n",
					IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name);
		}
	}
	break;
	case IPA_TETHERING_STATS_UPDATE_EVENT:
	{
		IPACMDBG_H("Received IPA_TETHERING_STATS_UPDATE_EVENT event.\n");
		if (IPACM_Wan::isWanUP(ipa_if_num) || IPACM_Wan::isWanUP_V6(ipa_if_num))
		{
			if(IPACM_Wan::backhaul_is_sta_mode == false) /* LTE */
			{
				ipa_get_data_stats_resp_msg_v01 *data = (ipa_get_data_stats_resp_msg_v01 *)param;
				if (data->ipa_stats_type != QMI_IPA_STATS_TYPE_PIPE_V01)
				{
					IPACMERR("not valid pipe stats\n");
					return;
				}
				handle_tethering_stats_event(data);
			};
		}
	}
	break;
	case IPA_DSCP_PCP_CONFIG_CHANGE_EVENT:
	{
		IPACMDBG_H("Received IPA_DSCP_PCP_CONFIG_CHANGE_EVENT event.\n");

		int num_wifi_client_tmp = num_wifi_client;
		int clt_indx, size;
		struct ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table = NULL;
		struct ipa_hdr_proc_ctx_add *hdr_proc_ctx = NULL;

		if (!is_svap_iface()) {
			IPACMDBG_H("Just storing the recent config change\n");
			return;
		}

		/* Issue add/delete ioctl and update cache */
		IPACMDBG_H("Issuing DSCP PCP %s command\n", (dscp_pcp_map_info.add)?"add":"delete");
		dscp_pcp_map_info.add = IPACM_Iface::ipacmcfg->dscp_pcp_config.add;
		memcpy(&(dscp_pcp_map_info.dscp_pcp_map[0]), IPACM_Iface::ipacmcfg->dscp_pcp_config.dscp_pcp_map,
			sizeof(IPACM_Iface::ipacmcfg->dscp_pcp_config.dscp_pcp_map));
		m_fd = open(IPA_DEVICE_NAME, O_RDWR);
		if (0 != ioctl(m_fd, IPA_IOC_ADD_DEL_DSCP_PCP_MAPPING, &dscp_pcp_map_info))
		{
			IPACMDBG_H("Failed ioctl IPA_IOC_ADD_DEL_DSCP_PCP_MAPPING\n");
			close(m_fd);
			return;
		}
		close(m_fd);

		IPACM_Iface::ipacmcfg->dscp_pcp_config_cache.add = IPACM_Iface::ipacmcfg->dscp_pcp_config.add;
		memcpy(IPACM_Iface::ipacmcfg->dscp_pcp_config_cache.dscp_pcp_map, IPACM_Iface::ipacmcfg->dscp_pcp_config.dscp_pcp_map,
 									sizeof(IPACM_Iface::ipacmcfg->dscp_pcp_config.dscp_pcp_map));
		size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
		hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx *)malloc(size);
		if (hdr_proc_ctx_table == NULL) {
			IPACMERR("Failed to allocate memory.\n");
			return;
		}

		/* Delete wlan client header */
		for (clt_indx = 0; clt_indx < num_wifi_client_tmp; clt_indx++)
		{
			if (get_client_memptr(wlan_client, clt_indx)->is_vlan)
			{
				handle_hpc_rt_rules_for_easymesh_R3(hdr_proc_ctx_table, hdr_proc_ctx, clt_indx);
			}
		}

end:
	free(hdr_proc_ctx_table);
	}
	break;

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	/* QCMAP sends this event whenever a client is connected. */
	case IPA_LAN_CLIENT_CONNECT_EVENT:
	{
		ipacm_event_data_mac *data = (ipacm_event_data_mac *)param;
		ipa_interface_index = iface_ipa_index_query(data->if_index);
		if (ipa_interface_index == ipa_if_num)
		{
			IPACMDBG_H("Received IPA_LAN_CLIENT_CONNECT_EVENT wlan\n");
			/* Check if we can add this to the active list. */
			/* Active List:- Clients for which index is less than IPA_MAX_NUM_HW_PATH_CLIENTS. */
			if (get_free_active_lan_stats_index(data->mac_addr, ipa_if_num) == -1)
			{
					IPACMDBG_H("Failed to reserve active lan_stats index, try inactive list. \n");
					/* Try to get the inactive index which can be used later. */
				if (get_free_inactive_lan_stats_index(data->mac_addr) == -1)
				{
					IPACMDBG_H("Failed to reserve inactive lan_stats index, return\n");
				}
				return;
			}
			/* Check if the client is inactive list and remove it*/
			if (reset_inactive_lan_stats_index(data->mac_addr) == -1)
			{
				IPACMDBG_H("Failed to reset inactive lan_stats index, return\n");
			}
			/* Check if the client is already initialized and add filter/routing rules. */
			IPACM_Wlan::handle_lan_client_connect(data->mac_addr);
		}
	}
	break;

	/* QCMAP sends this event whenever a client is disconnected. */
	case IPA_LAN_CLIENT_DISCONNECT_EVENT:
	{
		ipacm_event_data_mac *data = (ipacm_event_data_mac *)param;
		ipa_interface_index = iface_ipa_index_query(data->if_index);
		if (ipa_interface_index == ipa_if_num)
		{
			IPACMDBG_H("Received IPA_LAN_CLIENT_DISCONNECT_EVENT\n");
			IPACM_Wlan::handle_lan_client_disconnect(data->mac_addr);
		}
	}
	break;

	case IPA_LAN_CLIENT_UPDATE_EVENT:
	{
		ipacm_event_data_mac *data = (ipacm_event_data_mac *)param;
		ipa_interface_index = data->if_index;
		if (ipa_interface_index == ipa_if_num)
		{
			IPACMDBG_H("Received IPA_LAN_CLIENT_UPDATE_EVENT\n");
			IPACM_Wlan::handle_lan_client_connect(data->mac_addr);
		}
	}
	break;

#endif

	case IPA_MAC_ADD_DEL_FLT_EVENT:
		{
			IPACMDBG_H(" IPA_MAC_ADD_DEL_FLT_EVENT received\n");
			if(handle_wlan_mac_flt_event())
			{
				IPACMERR("failed to handle IPA_MAC_ADD_DEL_FLT_EVENT \n");
			}
		}
	break;

	case IPA_WLAN_SWITCH_VLAN_MODE:
	{
		ipacm_event_vlan_mode *data = (ipacm_event_vlan_mode *)param;
		ipa_interface_index = iface_ipa_index_query(data->if_index);
		if (ipa_interface_index == ipa_if_num) {
			IPACMDBG_H("Received IPA_WLAN_SWITCH_VLAN_MODE\n");

			if (handle_refresh_filtering_rules(data->wlan_vlan_mpdn_enable)) {
				IPACMERR("failed to handle IPA_WLAN_SWITCH_VLAN_MODE \n");
			}
		}
	}
	break;

	case IPA_PREFIX_CHANGE_EVENT:
	{
		ipacm_event_data_fid *data = (ipacm_event_data_fid *)param;

		IPACMDBG_H("Received IPA_PREFIX_CHANGE_EVENT\n");
		if(ipa_if_num != data->if_index)
			modify_ipv6_prefix_flt_rule();
		else
			IPACMDBG_H("matching if index, ignoring. ipa_if_num:%d\n", ipa_if_num);
	}
	break;

	case IPA_HANDLE_WAN_VLAN_PDN_UP:
	{
		ipacm_event_vlan_pdn *data = (ipacm_event_vlan_pdn *)param;

		IPACMDBG_H("Received IPA_HANDLE_WAN_VLAN_PDN_UP for VID %d, iptype %d\n",
		   data->VlanID,
			data->iptype);
		if(is_vlan_IF(data->VlanID))
		{
			if(data->iptype == IPA_IP_v6)
			{
				/* new prefix was added - update flt rules */
				modify_ipv6_prefix_flt_rule();
#ifdef FEATURE_IPACM_UL_FIREWALL
				configure_v6_ul_firewall();
#endif
			}
			handle_vlan_pdn_up(data);
		}

		//can add if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable
		if(IPACM_Iface::ipa_get_if_index(dev_name, &if_index))
		{
			IPACMERR("Error while getting if index for %s device", dev_name);
			break;
		}
		IPACMDBG_H("if_index = %d, vlan_id = %d\n", if_index, data->VlanID);

		//Handle for the right LAN instance for static policy case
		if (data->iptype == IPA_IP_v4 && data->VlanID == if_index + IPA_STATIC_POLICY_VLAN_ID)
		{
			IPACM_Lan::total_vlan_pdn_cnt++;
			IPACMDBG_H("Handling static policy PDN up for %s\n", dev_name);
			IPACMDBG_H("total_vlan_pdn_cnt = %d\n",IPACM_Lan::total_vlan_pdn_cnt);

			//modify private subnet_rules
			if (modify_private_subnet())
			{
				IPACMERR("failed to modify private subnet \n");
				break;
			}

			//dont need to install uplink rules twice
			if (modem_ul_v4_set[0] && !data->is_xlat)
			{
				IPACMDBG_H("Modem UL v4 rules already installed\n");
			}
			else
			{
				//If XLAT, need to delete the UL rules first so no duplicates
				if (data->is_xlat && modem_ul_v4_set[0])
					del_ul_flt_rules(IPA_IP_v4);

				//modify the UL rules to pass to route and install XLAT rules if needed
				if (handle_uplink_filter_rule(
					IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4),
					data->iptype, data->mux_id, false,
					data->is_xlat, false, true))
				{
					IPACMERR("Modem UL v4 rules not installed, error\n");
					break;
				}
				else
					modem_ul_v4_set[0] = true;
			}

			//Add per client stats rules for all active WLAN clients if feature is enabled
#ifdef IPA_HW_FNR_STATS
			if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
				if (install_uplink_filter_rule(IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4), data->iptype, data->mux_id))
					IPACMDBG_H("failed to install per client rules for V4 UL\n");
#endif
			//add proc_ctx and rt_rule for 1st static policy client
			if (!IPACM_Lan::static_policy_proc_ctx_hdl && !IPACM_Lan::static_policy_rt_rule_hdl)
				if (handle_static_policy_rt_rule_add())
					IPACMERR("failed to add 1st pass static policy rt rule\n");

			//add new flt rule for every new WLAN iface
			if (!static_policy_flt_rule_hdl)
			{
				int clnt_indx = get_wlan_client_index_from_if_index(if_index);
				uint32_t ipv4_addr = get_client_memptr(wlan_client, clnt_indx)->v4_addr;

				if (handle_static_policy_flt_rule_add(ipv4_addr) == IPACM_FAILURE)
					IPACMERR("failed to add 1st pass static policy flt rule\n")
			}
			if(set_mux_up(data->mux_id, data->iptype, data->VlanID))
			{
				IPACMERR("couldn't set mux up for %d, iptype %d\n", data->mux_id, data->iptype);
				break;
			}
		}
#ifdef FEATURE_STATIC_POLICY
		else if (data->iptype == IPA_IP_v6 && data->VlanID == if_index + IPA_STATIC_POLICY_VLAN_ID)
		{
			IPACM_Lan::total_vlan_pdn_cnt_v6++;
			IPACMDBG_H("Handling static policy PDN up for %s\n", dev_name);
			IPACMDBG_H("total_vlan_pdn_cnt = %d\n",IPACM_Lan::total_vlan_pdn_cnt_v6);

			/*install MTU rule */
			modify_ipv6_prefix_flt_rule();

			//add new flt rule for every new LAN client
			if (!static_policy_flt_rule_hdl_v6)
			{
				if (add_ipv6_nat_ula_prefix_flt_rule() == IPACM_FAILURE)
					IPACMERR("failed to add 1st pass static policy flt rule for v6\n")
			}

			//dont need to install uplink rules twice
			if (modem_ul_v6_set[0])
			{
				IPACMDBG_H("Modem UL v6 rules already installed\n");
			}
			else
			{
				//modify the UL rules to pass to route and install XLAT rules if needed
				if (handle_uplink_filter_rule(
					IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6),
					data->iptype, data->mux_id, false,
					false, false, true))
				{
					IPACMERR("Modem UL v6 rules not installed, error\n");
					break;
				}
				else
					modem_ul_v6_set[0] = true;
			}

			//Add per client stats rules for all active WLAN clients if feature is enabled
#ifdef IPA_HW_FNR_STATS
			if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
				if (install_uplink_filter_rule(IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6), data->iptype, data->mux_id))
					IPACMDBG_H("Failed to install per client rules for v6 UL\n");
#endif

			if(set_mux_up(data->mux_id, data->iptype, data->VlanID))
			{
				IPACMERR("couldn't set mux up for %d, iptype %d\n", data->mux_id, data->iptype);
				break;
			}
		}
#endif
	}
	break;

	case IPA_HANDLE_WAN_VLAN_PDN_DOWN:
	{
		ipacm_event_vlan_pdn *data = (ipacm_event_vlan_pdn *)param;

		IPACMDBG_H("Received IPA_HANDLE_WAN_VLAN_PDN_DOWN for VID %d, iptype %d\n",
			data->VlanID,
			data->iptype);
		if(is_vlan_IF(data->VlanID))
		{
#ifdef FEATURE_IPACM_UL_FIREWALL
			if(data->iptype == IPA_IP_v6)
			{
				// vlan pdn is down, disable its Q6 UL firewall and reconfigure
				disable_dft_firewall_rules_ul_ex(data->VlanID);
				configure_v6_ul_firewall();
			}
#endif
			handle_vlan_pdn_down(data);
		}

		if(IPACM_Iface::ipa_get_if_index(dev_name, &if_index))
		{
			IPACMERR("Error while getting if index for %s device", dev_name);
			break;
		}
		IPACMDBG_H("if_index = %d, vlan_id = %d\n", if_index, data->VlanID);

		/* clean static policy rules */
		if (data->iptype == IPA_IP_v4 && data->VlanID == if_index + IPA_STATIC_POLICY_VLAN_ID)
		{
			IPACM_Lan::total_vlan_pdn_cnt--;
			IPACMDBG_H("Handling static policy PDN down for %s\n", dev_name);
			IPACMDBG_H("total_vlan_pdn_cnt = %d\n",IPACM_Lan::total_vlan_pdn_cnt);

			if(data->VlanID)
			{
				handle_vlan_pdn_down(data);
			}

			if (is_any_mux_up(data->iptype))
			{
				IPACMDBG_H("There are still PDNs associated with %s, don't delete static policy rules\n",
					dev_name);
				break;
			}

			if (handle_static_policy_rule_delete())
			{
				IPACMERR("failed to delete static policy rules.\n");
				break;
			}
			IPACMDBG_H("Deleted static policy PDN rules for %s\n", dev_name);
		}
#ifdef FEATURE_STATIC_POLICY
		else if (data->iptype == IPA_IP_v6 && data->VlanID == if_index + IPA_STATIC_POLICY_VLAN_ID)
		{
			IPACM_Lan::total_vlan_pdn_cnt_v6--;
			IPACMDBG_H("Handling static policy PDN down for %s for v6\n", dev_name);
			IPACMDBG_H("total_vlan_pdn_cnt = %d\n",IPACM_Lan::total_vlan_pdn_cnt_v6);

			if(data->VlanID)
			{
				handle_vlan_pdn_down(data);
			}

			if (is_any_mux_up(data->iptype))
			{
				IPACMDBG_H("There are still PDNs associated with %s, don't delete static policy rules\n",
					dev_name);
				break;
			}

			if(IPACM_Iface::ipacmcfg->ipv6_nat_enable)
				delete_ipv6_nat_ula_prefix_flt_rule();

			IPACMDBG_H("Deleted static policy PDN rules for %s for v6\n", dev_name);
		}
#endif
	}
	break;

#ifdef FEATURE_STATIC_POLICY
	case IPA_PDN_DSCP_UPDATE_EVENT:
	{
		IPACMDBG_H("Received IPA_PDN_DSCP_UPDATE_EVENT\n");
		pdn_dscp_data = (ipacm_event_pdn_dscp_info *)param;
		IPACMDBG_H("Received IPA_PDN_DSCP_UPDATE_EVENT enable:%d mux_id:%d dscp_val:%d\n",
			pdn_dscp_data->enable,
			pdn_dscp_data->mux_id,
			pdn_dscp_data->dscp_val);
		mux_id = pdn_dscp_data->mux_id;
		dscp_val = pdn_dscp_data->dscp_val;
		if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && pdn_dscp_data->enable &&
			!IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
		{
			handle_pdn_dscp_wlan_client_route_rule(0, IPA_IP_v4, 1, 0, mux_id, dscp_val);
			handle_pdn_dscp_wlan_client_route_rule(0, IPA_IP_v6, 1, 0, mux_id, dscp_val);
		}
		else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && !pdn_dscp_data->enable)
		{
			delete_pdn_dscp_wlan_rtrules(IPA_IP_v4, 1, -1, mux_id);
			delete_pdn_dscp_wlan_rtrules(IPA_IP_v6, 1, -1, mux_id);
		}
		else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && pdn_dscp_data->enable &&
			IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
		{
			handle_pdn_dscp_wlan_client_route_rule_ext_v2(0, IPA_IP_v4, 1, 0, 0,
				mux_id, dscp_val);
			handle_pdn_dscp_wlan_client_route_rule_ext_v2(0, IPA_IP_v6, 1, 0, 0,
				mux_id, dscp_val);
		}
	}
	break;

	case IPA_QOS_RULE_ADD_EVENT:
	{
		IPACMDBG_H("Received and will process an IPA_QOS_RULE_ADD_EVENT\n");
		for (int cnt = 0; cnt < num_wifi_client; cnt++)
		{
			IPACMDBG_H("Install qos for clnt idx %d with vlan id %d\n", cnt, get_client_memptr(wlan_client, cnt)->vlan_id);
			install_all_wlan_qos_route_rule(get_client_memptr(wlan_client, cnt)->mac,
				get_client_memptr(wlan_client, cnt)->vlan_id, NULL);
		}
		break;
	}

	case IPA_QOS_RULE_DEL_EVENT:
	{
		qos_delete_param_info *qos_param;
		qos_param = (qos_delete_param_info *)param;
		IPACMDBG_H("Received and will process an IPA_QOS_RULE_DEL_EVENT\n");

		IPACMDBG_H("Deleting %d qos eth clients \n", qos_param->client_cnt);

		//for (it_qos_client = qos_param->qos_client_list.begin(); it_qos_client != qos_param->qos_client_list.end(); ++it_qos_client)
		for (int i = 0; i < qos_param->client_cnt; i++)
		{
			IPACMDBG_H("QOS is v4 set %d for hdl %d\n",
					 qos_param->qos_client_list[i].route_rule_set_v4, qos_param->qos_client_list[i].qos_rt_rule_hdl_v4);

			if (qos_param->qos_client_list[i].route_rule_set_v4 &&
				(m_routing.DeleteRoutingHdl(qos_param->qos_client_list[i].qos_rt_rule_hdl_v4, IPA_IP_v4) == false))
			{
				return;
			}

			// Delete respective header processing contexts
			if (qos_param->qos_client_list[i].dscp_hpc_hdl_v4)
			{
				IPACMDBG_H("Deleting dscp v4 hpc 0x%x\n", qos_param->qos_client_list[i].dscp_hpc_hdl_v4);
				if (m_header.DeleteHeaderProcCtx(qos_param->qos_client_list[i].dscp_hpc_hdl_v4)
					== false)
				{
					IPACMERR("Failed to delete qos dscp hpc v4 hdl 0x%x\n",
					qos_param->qos_client_list[i].dscp_hpc_hdl_v4);
					return;
				}
			}

			IPACMDBG_H("QOS is v6 set %d hdl %d\n",
					qos_param->qos_client_list[i].route_rule_set_v6,
					qos_param->qos_client_list[i].qos_rt_rule_hdl_v6);
			if (qos_param->qos_client_list[i].route_rule_set_v6 &&
					(m_routing.DeleteRoutingHdl(qos_param->qos_client_list[i].qos_rt_rule_hdl_v6, IPA_IP_v6) == false))
					return;

			if (qos_param->qos_client_list[i].dscp_hpc_hdl_v6)
			{
				IPACMDBG_H("Deleting dscp v6 hpc 0x%x\n", qos_param->qos_client_list[i].dscp_hpc_hdl_v6);
				if (m_header.DeleteHeaderProcCtx(qos_param->qos_client_list[i].dscp_hpc_hdl_v6)
					== false)
				{
					IPACMERR("Failed to delete qos dscp hpc v6 hdl 0x%x\n",
					qos_param->qos_client_list[i].dscp_hpc_hdl_v6);
					return;
				}
			}
		}

		break;
	}

#endif

#ifdef FEATURE_IPA_IPSEC
	case IPA_HANDLE_IPSEC_UL_FLT_ADD:
		IPACMDBG_H("Received and will process IPA_HANDLE_IPSEC_UL_FLT_ADD\n");
		uf = (ipa_ioc_ipsec_ul_flt_attr *)param;

		if(handleIpsecUlFltAddEvt(uf) == IPACM_FAILURE)
			IPACMERR("failed adding IPsec UL filtering rule\n");

		break;

	case IPA_HANDLE_IPSEC_UL_FLT_DEL:
		IPACMDBG_H("Received and will process IPA_HANDLE_IPSEC_UL_FLT_DEL\n");
		uf = (ipa_ioc_ipsec_ul_flt_attr *)param;

		if(handleIpsecUlFltDelEvt(uf) == IPACM_FAILURE)
			IPACMERR("failed deleting IPsec UL filtering rule\n");

		break;
#endif

	default:
		break;
	}
	return;
}

int IPACM_Wlan::handle_wlan_mac_flt_event()
{
	IPACMDBG_H("handle_wlan_mac_flt_event\n ");
	uint8_t mac_addr[6] ={0};
	int wlan_index;

	/* work on copy list to avoid concurrency issues*/
	auto macFltListsCopy = IPACM_Iface::ipacmcfg->getMacFltListsCopySafe();

	auto it = macFltListsCopy.begin();
	while (it != macFltListsCopy.end())
	{
		std::copy(std::begin(it->first), std::end(it->first), std::begin(mac_addr));
		wlan_index = get_wlan_client_index(mac_addr);
		if(wlan_index != IPACM_INVALID_INDEX)
		{
			if(it->second->is_blacklist)
			{
				//v4 case
				if(get_client_memptr(wlan_client, wlan_index)->ipv4_set && !it->second->mac_v4_rt_del_flt_set)
				{
					/* add a new ul flt rule for s/w path, del NAT and route rule for client */
					if(IPACM_Lan::add_mac_flt_blacklist_rule(mac_addr,IPA_IP_v4, &(it->second->mac_v4_flt_rule_hdl)))
					{
						IPACMERR("unable to add mac flt blacklist v4 UL rule for index: %d\n", wlan_index);
						return IPACM_FAILURE;
					}
					CtList->HandleNeighIpAddrDelEvt(get_client_memptr(wlan_client, wlan_index)->v4_addr);
					if(handle_wlan_client_mac_flt_route_rule(IPA_IP_v4, wlan_index, it->second->is_blacklist))
					{
						IPACMERR("unable to del v4 rt rule for index: %d\n", wlan_index);
						return IPACM_FAILURE;
					}
					it->second->mac_v4_rt_del_flt_set = true;
				}
				//v6 case
				if (get_client_memptr(wlan_client, wlan_index)->ipv6_set && !it->second->mac_v6_rt_del_flt_set)
				{
					/* add a new ul flt rule for s/w path & del route rule for client */
					if(IPACM_Lan::add_mac_flt_blacklist_rule(mac_addr,IPA_IP_v6, &(it->second->mac_v6_flt_rule_hdl)))
					{
						IPACMERR("unable to add mac flt blacklist v6 UL rule for index: %d\n", wlan_index);
						return IPACM_FAILURE;
					}
					if(handle_wlan_client_mac_flt_route_rule(IPA_IP_v6, wlan_index, it->second->is_blacklist))
					{
						IPACMERR("unable to del v6 rt rule for index: %d\n", wlan_index);
						return IPACM_FAILURE;
					}
					it->second->mac_v6_rt_del_flt_set = true;
				}
				it->second->current_blocked = true;
				/* remove from lan2lan offload module */
				eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_DEL, IPA_IP_MAX, mac_addr, NULL, NULL);
				/* In case of client blackklisted, update config mac list with copy mac flt list value */
				IPACM_Iface::ipacmcfg->update_mac_flt_lists(mac_addr, it->second);
				it++;
			}
			else
			{
				/* delete UL mac flt rules and add DL rt rules */
				if(it->second->mac_v4_rt_del_flt_set)
				{
					/* del ul flt rule for s/w path & add route/Nat rule for client */
					if(IPACM_Lan::del_mac_flt_blacklist_rule(it->second->mac_v4_flt_rule_hdl,  IPA_IP_v4))
					{
						IPACMERR("unable to del mac flt blacklist v4 UL rule for index: %d\n", wlan_index);
						return IPACM_FAILURE;
					}
					if(handle_wlan_client_mac_flt_route_rule(IPA_IP_v4, wlan_index, it->second->is_blacklist))
					{
						IPACMERR("unable to add v4 rt rule for index: %d\n", wlan_index);
						return IPACM_FAILURE;
					}
					it->second->mac_v4_rt_del_flt_set = false;
				}
				if(it->second->mac_v6_rt_del_flt_set)
				{
					/* del ul flt rule for s/w path & add route rule for client */
					if(IPACM_Lan::del_mac_flt_blacklist_rule(it->second->mac_v6_flt_rule_hdl,  IPA_IP_v6))
					{
						IPACMERR("unable to del mac flt blacklist v6 UL rule for index: %d\n", wlan_index);
						return IPACM_FAILURE;
					}
					if(handle_wlan_client_mac_flt_route_rule(IPA_IP_v6, wlan_index, it->second->is_blacklist))
					{
						IPACMERR("unable to add v6 rt rule for index: %d\n", wlan_index);
						return IPACM_FAILURE;
					}
					it->second->mac_v6_rt_del_flt_set = false;
				}
				/* add back to the lan2lan offload module */
				eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_ADD, IPA_IP_MAX, mac_addr, NULL, NULL);
				/* remove from original/copy client list as whitelisted client */
				IPACM_Iface::ipacmcfg->clear_whitelist_mac_add(mac_addr);
				it = macFltListsCopy.erase(it);
			}
		}
		else
		{
			IPACMERR("wlan client not found/attached \n");
			it++;
		}
	}
	return IPACM_SUCCESS;
}


int IPACM_Wlan::handle_wlan_client_mac_flt_route_rule(ipa_ip_type ip_type, int clt_index, bool is_blacklist)
{

	ipacm_event_data_all data;
#ifdef FEATURE_STATIC_POLICY
	uint32_t temp_ipv6[4] = {0};
#endif
	/* if client is blacklisted, delete route rules*/
	if(is_blacklist)
	{
		if(ip_type == IPA_IP_v4 )
		{
			if (delete_default_qos_rtrules(clt_index, IPA_IP_v4))
			{
				IPACMERR("unable to delete v4 default qos route rules for index: %d\n", clt_index);
				return IPACM_FAILURE;
			}
#ifdef FEATURE_STATIC_POLICY
			if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
			{
				if (delete_pdn_dscp_wlan_rtrules(IPA_IP_v4, 2, clt_index))
				{
					IPACMERR("unable to delete v4 PDN DSCP route rules for index: %d\n", clt_index);
					return IPACM_FAILURE;
				}
			}
#endif
		}

		if(ip_type ==  IPA_IP_v6)
		{
			if (delete_default_qos_rtrules(clt_index, IPA_IP_v6))
			{
				IPACMERR("unable to delete v6 default qos route rules for index: %d\n", clt_index);
				return IPACM_FAILURE;
			}
#ifdef FEATURE_STATIC_POLICY
			if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
			{
				if (delete_pdn_dscp_wlan_rtrules(IPA_IP_v6, 2, clt_index))
				{
					IPACMERR("unable to delete v6 PDN DSCP route rules for index: %d\n", clt_index);
					return IPACM_FAILURE;
				}
			}
#endif
		}
	}
	else
	{/* client is whitelisted, add route rule*/
		if(ip_type == IPA_IP_v4)
		{
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
			if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
			{
				if(handle_wlan_client_route_rule(get_client_memptr(wlan_client, clt_index)->mac, IPA_IP_v4))
				{
						IPACMERR("unable to add v4 route rules for index: %d\n", clt_index);
						return IPACM_FAILURE;
				}
#ifdef FEATURE_STATIC_POLICY
				if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
				{
					handle_pdn_dscp_wlan_client_route_rule(get_client_memptr(wlan_client, clt_index)->mac,
						IPA_IP_v4, 0, 0, 0);
				}
#endif
				memset(&data, 0, sizeof(data));
				data.ipv4_addr = get_client_memptr(wlan_client, clt_index)->v4_addr,
				data.if_index =  get_client_memptr(wlan_client, clt_index)->if_index;
				data.iptype = IPA_IP_v4;
				CtList->HandleNeighIpAddrAddEvt(&data);
			}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
			else
			{
#ifdef IPA_HW_FNR_STATS
				if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
				{
					if(handle_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client, clt_index)->mac,IPA_IP_v4))
					{
						IPACMERR("unable to add v4 route rules for index: %d\n", clt_index);
						return IPACM_FAILURE;
					}
#ifdef FEATURE_STATIC_POLICY
					if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
					{
						if(handle_pdn_dscp_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client,
							clt_index)->mac, IPA_IP_v4, 0))
						{
							IPACMERR("unable to add v4 route rules for index: %d\n", clt_index);
							return IPACM_FAILURE;
						}
					}
#endif
				}
				else
#endif //IPA_HW_FNR_STATS
				{
					if(handle_wlan_client_route_rule_ext(get_client_memptr(wlan_client, clt_index)->mac, IPA_IP_v4))
					{
						IPACMERR("unable to add v4 route rules for index: %d\n", clt_index);
						return IPACM_FAILURE;
					}
				}
			}
#endif
		}

		if(ip_type == IPA_IP_v6)
		{
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
			if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
			{
				if(handle_wlan_client_route_rule(get_client_memptr(wlan_client, clt_index)->mac, IPA_IP_v6))
				{
					IPACMERR("unable to add v6 route rules for index: %d\n", clt_index);
					return IPACM_FAILURE;
				}
#ifdef FEATURE_STATIC_POLICY
				if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
				{
					for (auto it = rt_hdl_v6_list[clt_index].begin();
						it != rt_hdl_v6_list[clt_index].end();++it)
					{
						std::copy(std::begin(it->first), std::end(it->first), std::begin(temp_ipv6));
						handle_pdn_dscp_wlan_client_route_rule(get_client_memptr(wlan_client, clt_index)->mac,
							IPA_IP_v6, 0, 0, 0, 0, temp_ipv6);
					}
				}
#endif
			}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
			else
			{
#ifdef IPA_HW_FNR_STATS
				if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
				{
					if(handle_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client, clt_index)->mac,IPA_IP_v6))
					{
						IPACMERR("unable to add v6 route rules for index: %d\n", clt_index);
						return IPACM_FAILURE;
					}
#ifdef FEATURE_STATIC_POLICY
					if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
					{
						for (auto it = rt_hdl_v6_list[clt_index].begin(); it != rt_hdl_v6_list[clt_index].end(); ++it)
						{
							std::copy(std::begin(it->first), std::end(it->first), std::begin(temp_ipv6));
							if(handle_pdn_dscp_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client, clt_index)->mac,
								IPA_IP_v6, 0, temp_ipv6))
							{
								IPACMERR("unable to add v6 route rules for index: %d\n", clt_index);
								return IPACM_FAILURE;
							}
						}
					}
#endif
				}
				else
#endif //IPA_HW_FNR_STATS
				{
					if(handle_wlan_client_route_rule_ext(get_client_memptr(wlan_client, clt_index)->mac, IPA_IP_v6))
					{
						IPACMERR("unable to add v6 route rules for index: %d\n", clt_index);
						return IPACM_FAILURE;
					}
				}
			}
#endif
		}
	}
return IPACM_SUCCESS;
}

/* del all mac rules for wlan client if wlan is down */
void IPACM_Wlan::delete_wlan_mac_flt_rules()
{

	uint8_t mac_addr[6]={0};
	int wlan_index;

	/* copy current list to avoid concurrency issues*/
	auto macFltListsCopy = IPACM_Iface::ipacmcfg->getMacFltListsCopySafe();

	for (auto it = macFltListsCopy.begin(); it != macFltListsCopy.end(); ++it)
	{
		std::copy(std::begin(it->first), std::end(it->first), std::begin(mac_addr));
		wlan_index = get_wlan_client_index(mac_addr);
		if(wlan_index != IPACM_INVALID_INDEX && it->second->is_blacklist)
		{
			handle_wlan_mac_flt_conn_disc(mac_addr, false);
		}
	}
 }

/* handle_wlan_mac_flt_conn_disc handles the scenario when mac flt ioctl is received before the client
	structure is created */
int IPACM_Wlan::handle_wlan_mac_flt_conn_disc(uint8_t *mac_addr, bool conn_state)
{

	uint8_t mac_a[6];
	std::map<std::array<uint8_t, 6>, mac_flt_type * >::iterator it;
	int wlan_index;
	std::array<uint8_t, 6> mac = {0};

	memcpy(mac_a,mac_addr,IPA_MAC_ADDR_SIZE);
	std::copy(std::begin(mac_a), std::end(mac_a), std::begin(mac));

	it = IPACM_Iface::ipacmcfg->mac_flt_lists.find(mac);
	wlan_index = get_wlan_client_index(mac_addr);

	if(wlan_index != IPACM_INVALID_INDEX)
	{
		if(conn_state)
		{
			IPACMDBG_H("Client connected \n");
			/* install UL rules*/
			if(get_client_memptr(wlan_client, wlan_index)->ipv4_set && !it->second->mac_v4_rt_del_flt_set)
			{
				if(IPACM_Lan::add_mac_flt_blacklist_rule(mac_addr,IPA_IP_v4, &(it->second->mac_v4_flt_rule_hdl)))
				{
					IPACMERR("unable to add mac flt blacklist v4 UL rule for index: %d\n", wlan_index);
					return IPACM_FAILURE;
				}
				CtList->HandleNeighIpAddrDelEvt(get_client_memptr(wlan_client, wlan_index)->v4_addr);
				if(handle_wlan_client_mac_flt_route_rule(IPA_IP_v4, wlan_index, it->second->is_blacklist))
				{
					IPACMERR("unable to del v4 rt rule for index: %d\n", wlan_index);
					return IPACM_FAILURE;
				}

				it->second->mac_v4_rt_del_flt_set = true;
			}
			if (get_client_memptr(wlan_client, wlan_index)->ipv6_set && !it->second->mac_v6_rt_del_flt_set)
			{
				if(IPACM_Lan::add_mac_flt_blacklist_rule(mac_addr,IPA_IP_v6, &(it->second->mac_v6_flt_rule_hdl)))
				{
					IPACMERR("unable to add mac flt blacklist v6 UL rule for index: %d\n", wlan_index);
					return IPACM_FAILURE;
				}
				if(handle_wlan_client_mac_flt_route_rule(IPA_IP_v6, wlan_index, it->second->is_blacklist))
				{
					IPACMERR("unable to del v6 rt rule for index: %d\n", wlan_index);
					return IPACM_FAILURE;
				}
				it->second->mac_v6_rt_del_flt_set = true;
			}
			it->second->current_blocked = true;
		}
		else
		{
			IPACMDBG_H("Client disconnected \n");
			/*del UL rules*/
			if(it->second->mac_v4_rt_del_flt_set)
			{
				if(IPACM_Lan::del_mac_flt_blacklist_rule(it->second->mac_v4_flt_rule_hdl,  IPA_IP_v4))
				{
					IPACMERR("unable to del mac flt blacklist v4 UL rule for index: %d\n", wlan_index);
					return IPACM_FAILURE;
				}
				it->second->mac_v4_rt_del_flt_set = false;
			}
			if(it->second->mac_v6_rt_del_flt_set)
			{
				if(IPACM_Lan::del_mac_flt_blacklist_rule(it->second->mac_v6_flt_rule_hdl,  IPA_IP_v6))
				{
					IPACMERR("unable to del mac flt blacklist v6 UL rule for index: %d\n", wlan_index);
					return IPACM_FAILURE;
				}
				it->second->mac_v6_rt_del_flt_set = false;
			}
			it->second->current_blocked = false;
		}
		/* In case of client blackklisted, update config mac list with copy mac flt list value */
		IPACM_Iface::ipacmcfg->update_mac_flt_lists(mac_addr, it->second);
	}
	return IPACM_SUCCESS;
}

/* handle wifi client initial,copy all partial headers (tx property) */
int IPACM_Wlan::handle_wlan_client_init_ex(ipacm_event_data_wlan_ex *data, bool delay_init, uint16_t vlan_id)
{

#define WLAN_IFACE_INDEX_LEN 10

	int res = IPACM_SUCCESS, len = 0, i, evt_size;
	char index[WLAN_IFACE_INDEX_LEN];
	struct ipa_ioc_copy_hdr sCopyHeader;
	struct ipa_ioc_add_hdr *pHeaderDescriptor = NULL;
	uint32_t cnt;
	int wlan_index;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	ipacm_ext_prop* ext_prop;
	struct wan_ioctl_lan_client_info *client_info;
	int cnt_idx;
#endif
	int max_clients = IPA_MAX_NUM_WIFI_CLIENTS;
	uint16_t ta_peer_id = 0;

	/* start of adding header */
	IPACMDBG_H("Wifi client number for this iface: %d & total number of wlan clients: %d\n",
                 num_wifi_client,IPACM_Wlan::total_num_wifi_clients);

	if ((num_wifi_client >= max_clients) ||
			(IPACM_Wlan::total_num_wifi_clients >= max_clients))
	{
		IPACMERR("Reached maximum number of wlan clients\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Wifi client number: %d\n", num_wifi_client);

	/* add header to IPA */
	if(tx_prop != NULL)
	{
		len = sizeof(struct ipa_ioc_add_hdr) + (1 * sizeof(struct ipa_hdr_add));
		pHeaderDescriptor = (struct ipa_ioc_add_hdr *)calloc(1, len);
		if (pHeaderDescriptor == NULL)
		{
			IPACMERR("calloc failed to allocate pHeaderDescriptor\n");
			return IPACM_FAILURE;
		}

		evt_size = sizeof(ipacm_event_data_wlan_ex) + data->num_of_attribs * sizeof(struct ipa_wlan_hdr_attrib_val);
		get_client_memptr(wlan_client, num_wifi_client)->p_hdr_info = (ipacm_event_data_wlan_ex*)malloc(evt_size);
		memcpy(get_client_memptr(wlan_client, num_wifi_client)->p_hdr_info, data, evt_size);

		/* copy partial header for v4*/
		for (cnt=0; cnt<tx_prop->num_tx_props; cnt++)
		{
			if(tx_prop->tx[cnt].ip==IPA_IP_v4)
			{
				if (is_svap_iface() || is_vlan_iface()) {
					if (cnt < IPA_IP_v4_VLAN)
						continue;
				} else {
					if (cnt >= IPA_IP_v4_VLAN)
						continue;
				}

				IPACMDBG_H("Got partial v4-header name from %d tx props\n", cnt);
				memset(&sCopyHeader, 0, sizeof(sCopyHeader));
				memcpy(sCopyHeader.name,
							 tx_prop->tx[cnt].hdr_name,
							 sizeof(sCopyHeader.name));

				IPACMDBG_H("header name: %s in tx:%d\n", sCopyHeader.name,cnt);
				if (m_header.CopyHeader(&sCopyHeader) == false)
				{
					PERROR("ioctl copy header failed");
					res = IPACM_FAILURE;
					goto fail;
				}

				IPACMDBG_H("header length: %d, partial: %d\n", sCopyHeader.hdr_len, sCopyHeader.is_partial);
				if (sCopyHeader.hdr_len > IPA_HDR_MAX_SIZE)
				{
					IPACMERR("header oversize\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				else
				{
					memcpy(pHeaderDescriptor->hdr[0].hdr,
								 sCopyHeader.hdr,
								 sCopyHeader.hdr_len);
				}

				for(i = 0; i < data->num_of_attribs; i++)
				{
					if((data->attribs[i].offset < (IPA_HDR_MAX_SIZE - IPA_MAC_ADDR_SIZE)) && (data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_MAC_ADDR))
					{
						memcpy(get_client_memptr(wlan_client, num_wifi_client)->mac,
								data->attribs[i].u.mac_addr,
								sizeof(get_client_memptr(wlan_client, num_wifi_client)->mac));

						/* copy client mac_addr to partial header */
						memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset],
									 get_client_memptr(wlan_client, num_wifi_client)->mac,
									 IPA_MAC_ADDR_SIZE);
						/* replace src mac to bridge mac_addr if any  */
						if ((data->attribs[i].offset < (IPA_HDR_MAX_SIZE - 2*IPA_MAC_ADDR_SIZE)) && IPACM_Iface::ipacmcfg->ipa_bridge_enable)
						{
							memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset+IPA_MAC_ADDR_SIZE],
									 IPACM_Iface::ipacmcfg->bridge_mac,
									 IPA_MAC_ADDR_SIZE);
							IPACMDBG_H("device is in bridge mode \n");
						}

					}
					else if((data->attribs[i].offset < (IPA_HDR_MAX_SIZE - sizeof(data->attribs[i].u.sta_id))) && (data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_STA_ID))
					{
						/* copy client id to header */
						memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset],
									&data->attribs[i].u.sta_id, sizeof(data->attribs[i].u.sta_id));
					}
#ifdef WLAN_HDR_ATTRIB_TA_PEER_ID
					else if(data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_TA_PEER_ID)
					{
						/* copy ta_peer_id */
						ta_peer_id =
							data->attribs[i].u.ta_peer_id;
					}
#endif
					else
					{
						IPACMDBG_H("The attribute type is not expected!\n");
					}
				}

				if (delay_init) {
					IPACMDBG_H("Skip the header init, will be performed later with IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT\n");
					break;
				}

				pHeaderDescriptor->commit = true;
				pHeaderDescriptor->num_hdrs = 1;

				memset(pHeaderDescriptor->hdr[0].name, 0,
							 sizeof(pHeaderDescriptor->hdr[0].name));

				snprintf(index,sizeof(index), "%d_", ipa_if_num);
				strlcpy(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name));
				pHeaderDescriptor->hdr[0].name[IPA_RESOURCE_NAME_MAX-1] = '\0';

				if (strlcat(pHeaderDescriptor->hdr[0].name, IPA_WLAN_PARTIAL_HDR_NAME_v4, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
				{
					IPACMERR(" header name construction failed exceed length (%zu)\n", strlen(pHeaderDescriptor->hdr[0].name));
					res = IPACM_FAILURE;
					goto fail;
				}
				snprintf(index,sizeof(index), "_%d", header_name_count);
				if (strlcat(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
				{
					IPACMERR(" header name construction failed exceed length (%zu)\n", strlen(pHeaderDescriptor->hdr[0].name));
					res = IPACM_FAILURE;
					goto fail;
				}


				pHeaderDescriptor->hdr[0].hdr_len = sCopyHeader.hdr_len;
				hdr_len = sCopyHeader.hdr_len;
				pHeaderDescriptor->hdr[0].hdr_hdl = -1;
				pHeaderDescriptor->hdr[0].is_partial = 0;
				pHeaderDescriptor->hdr[0].status = -1;

				if (m_header.AddHeader(pHeaderDescriptor) == false ||
						pHeaderDescriptor->hdr[0].status != 0)
				{
					IPACMERR("ioctl IPA_IOC_ADD_HDR failed: %d\n", pHeaderDescriptor->hdr[0].status);
					res = IPACM_FAILURE;
					goto fail;
				}

				get_client_memptr(wlan_client, num_wifi_client)->hdr_hdl_v4 = pHeaderDescriptor->hdr[0].hdr_hdl;
				IPACMDBG_H("client(%d) v4 full header name:%s header handle:(0x%x) Len:%d\n",
								 num_wifi_client,
								 pHeaderDescriptor->hdr[0].name,
								 get_client_memptr(wlan_client, num_wifi_client)->hdr_hdl_v4,
								 hdr_len);
				get_client_memptr(wlan_client, num_wifi_client)->ipv4_header_set=true;
				break;
			}
		}

		/* copy partial header for v6*/
		for (cnt=0; cnt<tx_prop->num_tx_props; cnt++)
		{
			if(tx_prop->tx[cnt].ip==IPA_IP_v6)
			{
				if (is_svap_iface() || is_vlan_iface()) {
					if (cnt < IPA_IP_v4_VLAN)
						continue;
				} else {
					if (cnt >= IPA_IP_v4_VLAN)
						continue;
				}

				IPACMDBG_H("Got partial v6-header name from %d tx props\n", cnt);
				memset(&sCopyHeader, 0, sizeof(sCopyHeader));
				memcpy(sCopyHeader.name,
							 tx_prop->tx[cnt].hdr_name,
							 sizeof(sCopyHeader.name));

				IPACMDBG_H("header name: %s in tx:%d\n", sCopyHeader.name,cnt);
				if (m_header.CopyHeader(&sCopyHeader) == false)
				{
					PERROR("ioctl copy header failed");
					res = IPACM_FAILURE;
					goto fail;
				}

				IPACMDBG_H("header length: %d, paritial: %d\n", sCopyHeader.hdr_len, sCopyHeader.is_partial);
				if (sCopyHeader.hdr_len > IPA_HDR_MAX_SIZE)
				{
					IPACMERR("header oversize\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				else
				{
					memcpy(pHeaderDescriptor->hdr[0].hdr,
								 sCopyHeader.hdr,
								 sCopyHeader.hdr_len);
				}

				for(i = 0; i < data->num_of_attribs; i++)
				{
					if((data->attribs[i].offset < (IPA_HDR_MAX_SIZE - IPA_MAC_ADDR_SIZE)) && (data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_MAC_ADDR))
					{
						memcpy(get_client_memptr(wlan_client, num_wifi_client)->mac,
								data->attribs[i].u.mac_addr,
								sizeof(get_client_memptr(wlan_client, num_wifi_client)->mac));

						/* copy client mac_addr to partial header */
						memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset],
								get_client_memptr(wlan_client, num_wifi_client)->mac,
								IPA_MAC_ADDR_SIZE);

						/* replace src mac to bridge mac_addr if any  */
						if ((data->attribs[i].offset < (IPA_HDR_MAX_SIZE - 2*IPA_MAC_ADDR_SIZE)) && IPACM_Iface::ipacmcfg->ipa_bridge_enable)
						{
							memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset+IPA_MAC_ADDR_SIZE],
									 IPACM_Iface::ipacmcfg->bridge_mac,
									 IPA_MAC_ADDR_SIZE);
							IPACMDBG_H("device is in bridge mode \n");
						}
					}
					else if ((data->attribs[i].offset < (IPA_HDR_MAX_SIZE - sizeof(data->attribs[i].u.sta_id))) && data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_STA_ID)
					{
						/* copy client id to header */
						memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset],
								&data->attribs[i].u.sta_id, sizeof(data->attribs[i].u.sta_id));
					}
#ifdef WLAN_HDR_ATTRIB_TA_PEER_ID
					else if(data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_TA_PEER_ID)
					{
						/* copy ta_peer_id */
						ta_peer_id =
							data->attribs[i].u.ta_peer_id;
					}
#endif
					else
					{
						IPACMDBG_H("The attribute type is not expected!\n");
					}
				}

				if (delay_init) {
					IPACMDBG_H("Skip the header init, will be performed later with IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT\n");
					break;
				}

				pHeaderDescriptor->commit = true;
				pHeaderDescriptor->num_hdrs = 1;

				memset(pHeaderDescriptor->hdr[0].name, 0,
							 sizeof(pHeaderDescriptor->hdr[0].name));

				snprintf(index,sizeof(index), "%d_", ipa_if_num);
				strlcpy(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name));
				pHeaderDescriptor->hdr[0].name[IPA_RESOURCE_NAME_MAX-1] = '\0';
				if (strlcat(pHeaderDescriptor->hdr[0].name, IPA_WLAN_PARTIAL_HDR_NAME_v6, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
				{
					IPACMERR(" header name construction failed exceed length (%zu)\n", strlen(pHeaderDescriptor->hdr[0].name));
					res = IPACM_FAILURE;
					goto fail;
				}

				snprintf(index,sizeof(index), "_%d", header_name_count);
				if (strlcat(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
				{
					IPACMERR(" header name construction failed exceed length (%zu)\n", strlen(pHeaderDescriptor->hdr[0].name));
					res = IPACM_FAILURE;
					goto fail;
				}

				pHeaderDescriptor->hdr[0].hdr_len = sCopyHeader.hdr_len;
				hdr_len = sCopyHeader.hdr_len;
				pHeaderDescriptor->hdr[0].hdr_hdl = -1;
				pHeaderDescriptor->hdr[0].is_partial = 0;
				pHeaderDescriptor->hdr[0].status = -1;

				if (m_header.AddHeader(pHeaderDescriptor) == false ||
						pHeaderDescriptor->hdr[0].status != 0)
				{
					IPACMERR("ioctl IPA_IOC_ADD_HDR failed: %d\n", pHeaderDescriptor->hdr[0].status);
					res = IPACM_FAILURE;
					goto fail;
				}

				get_client_memptr(wlan_client, num_wifi_client)->hdr_hdl_v6 = pHeaderDescriptor->hdr[0].hdr_hdl;
				IPACMDBG_H("client(%d) v6 full header name:%s header handle:(0x%x) Len:%d\n",
								 num_wifi_client,
								 pHeaderDescriptor->hdr[0].name,
											 get_client_memptr(wlan_client, num_wifi_client)->hdr_hdl_v6,
											 hdr_len);

				get_client_memptr(wlan_client, num_wifi_client)->ipv6_header_set=true;
				break;
			}
		}

		/* initialize wifi client*/
		if (delay_init)
		{
			get_client_memptr(wlan_client, num_wifi_client)->v4_addr = 0;
			get_client_memptr(wlan_client, num_wifi_client)->hdr_hdl_v4 = 0;
			get_client_memptr(wlan_client, num_wifi_client)->hdr_hdl_v6 = 0;
			get_client_memptr(wlan_client, num_wifi_client)->ipv4_header_set = false;
			get_client_memptr(wlan_client, num_wifi_client)->ipv6_header_set = false;
		}
		get_client_memptr(wlan_client, num_wifi_client)->route_rule_set_v4 = false;
		get_client_memptr(wlan_client, num_wifi_client)->route_rule_set_v6 = 0;
		get_client_memptr(wlan_client, num_wifi_client)->ipv4_set = false;
		get_client_memptr(wlan_client, num_wifi_client)->ipv6_set = 0;
		get_client_memptr(wlan_client, num_wifi_client)->hpc_hdr_hdl_v4 = 0;
		get_client_memptr(wlan_client, num_wifi_client)->hpc_hdr_hdl_v6 = 0;
		get_client_memptr(wlan_client, num_wifi_client)->ipv4_hpc_set = false;
		get_client_memptr(wlan_client, num_wifi_client)->ipv6_hpc_set = false;

		get_client_memptr(wlan_client, num_wifi_client)->power_save_set=false;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		get_client_memptr(wlan_client, num_wifi_client)->ipv4_ul_rules_set = false;
		get_client_memptr(wlan_client, num_wifi_client)->ipv6_ul_rules_set = false;
		get_client_memptr(wlan_client, num_wifi_client)->lan_stats_idx = get_lan_stats_index(get_client_memptr(wlan_client, num_wifi_client)->mac);
		memset(get_client_memptr(wlan_client, num_wifi_client)->wan_ul_fl_rule_hdl_v4, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
		memset(get_client_memptr(wlan_client, num_wifi_client)->wan_ul_fl_rule_hdl_v6, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
#ifdef IPA_HW_FNR_STATS
		get_client_memptr(wlan_client, num_wifi_client)->ul_cnt_idx = -1;
		get_client_memptr(wlan_client, num_wifi_client)->dl_cnt_idx = -1;
		get_client_memptr(wlan_client, num_wifi_client)->index_populated = false;
#endif //IPA_HW_FNR_STATS
#endif
#ifdef FEATURE_STATIC_POLICY
		memset(get_client_memptr(wlan_client, num_wifi_client)->dscp_hpc_hdr_hdl_v4,
			0,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(uint32_t));
		memset(get_client_memptr(wlan_client, num_wifi_client)->dscp_hpc_hdr_hdl_v6,
			0,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(uint32_t));
		memset(get_client_memptr(wlan_client, num_wifi_client)->dscp_route_rule_set_v4,
			0,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(bool));
		memset(get_client_memptr(wlan_client, num_wifi_client)->dscp_ipv4_hpc_set,
			0,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(bool));
		memset(get_client_memptr(wlan_client, num_wifi_client)->dscp_ipv6_hpc_set,
			0,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(bool));
		memset(get_client_memptr(wlan_client, num_wifi_client)->dscp_ipv4_hpc_count,
			0,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(int));
		memset(get_client_memptr(wlan_client, num_wifi_client)->dscp_ipv6_hpc_count,
			0,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(int));
		memset(get_client_memptr(wlan_client, num_wifi_client)->dscp_wifi_rt_hdl,
			0,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(wlan_client_rt_hdl));
#endif
		get_client_memptr(wlan_client, num_wifi_client)->ta_peer_id = ta_peer_id;
		IPACMDBG_H("ta_peer_id for the client: %d\n", ta_peer_id);
		if (vlan_id)
		{
			get_client_memptr(wlan_client, num_wifi_client)->vlan_id = vlan_id;
			get_client_memptr(wlan_client, num_wifi_client)->is_vlan = true;
			IPACMDBG_H("Wlan client at index %d is a VLAN client with vlan id: %d\n",
				num_wifi_client, vlan_id);
		}
		else
		{
			get_client_memptr(wlan_client, num_wifi_client)->vlan_id = 0;
			get_client_memptr(wlan_client, num_wifi_client)->is_vlan = false;
		}
		wlan_index = num_wifi_client;
		num_wifi_client++;
#if defined(FEATURE_IPACM_PER_CLIENT_STATS) || defined(IPA_WDI_AST_UPDATE)
		if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == true &&
			get_client_memptr(wlan_client, wlan_index)->lan_stats_idx != -1)
		{
			client_info = (struct wan_ioctl_lan_client_info *)malloc(sizeof(struct wan_ioctl_lan_client_info));
			if (client_info == NULL)
			{
				IPACMERR("Unable to allocate memory\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			memset(client_info, 0, sizeof(struct wan_ioctl_lan_client_info));
			client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_WLAN;
			memcpy(client_info->mac,
					get_client_memptr(wlan_client, wlan_index)->mac,
					IPA_MAC_ADDR_SIZE);
			client_info->client_init = 1;
			client_info->client_idx = get_client_memptr(wlan_client, wlan_index)->lan_stats_idx;
			client_info->ul_src_pipe = (enum ipa_client_type) IPA_CLIENT_MAX;
			client_info->hdr_len = hdr_len;
#ifdef IPA_HW_FNR_STATS
			IPACMERR("Client counter index (%d) ul/ul = (%d/%d) dl/dl = (%d/%d)\n",
				get_client_memptr(wlan_client, wlan_index)->index_populated,
				client_info->ul_cnt_idx,
				get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx,
				client_info->dl_cnt_idx,
				get_client_memptr(wlan_client, wlan_index)->dl_cnt_idx);
			if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support && !get_client_memptr(wlan_client, wlan_index)->index_populated)
			{
				pthread_mutex_lock(&IPACM_Iface::ipacmcfg->cnt_idx_lock);
				cnt_idx = IPACM_Wan::ipacmcfg->get_free_cnt_idx();
				pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->cnt_idx_lock);
				if (cnt_idx == -1)
				{
					IPACMERR("Got invalid cnt_idx. Abort\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx = cnt_idx;
				get_client_memptr(wlan_client, wlan_index)->dl_cnt_idx = cnt_idx + 1;
				client_info->ul_cnt_idx = get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx;
				client_info->dl_cnt_idx = get_client_memptr(wlan_client, wlan_index)->dl_cnt_idx;
				get_client_memptr(wlan_client, wlan_index)->index_populated = true;
			}
#endif //IPA_HW_FNR_STATS
			if (rx_prop)
			{
				client_info->ul_src_pipe = rx_prop->rx[0].src_pipe;
			}
			if (set_lan_client_info(client_info))
			{
				res = IPACM_FAILURE;
				free(client_info);
				/* Reset the mac from active list. */
				reset_active_lan_stats_index(get_client_memptr(wlan_client, wlan_index)->lan_stats_idx, get_client_memptr(wlan_client, wlan_index)->mac);
				/* Add the mac to inactive list. */
				get_free_inactive_lan_stats_index(get_client_memptr(wlan_client, wlan_index)->mac);
				get_client_memptr(wlan_client, wlan_index)->lan_stats_idx = -1;
				goto fail;
			}
			free(client_info);

#ifdef FEATURE_STATIC_POLICY
			//if IPACM is in static policy mode, we will install rules later based on conntrack evt
			if (IPACM_Wan::isWanUP(ipa_if_num) ||
				(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && IPACM_Wan::isVlanWanUP()))
#else
			if (IPACM_Wan::isWanUP(ipa_if_num))
#endif
			{
				if(IPACM_Wan::backhaul_is_sta_mode == false)
				{
#ifdef IPA_HW_FNR_STATS
					if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
					{
						ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
						install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v4, IPACM_Wan::getXlat_Mux_Id(), get_client_memptr(wlan_client, wlan_index)->mac,
							get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx, NULL, false, get_client_memptr(wlan_client, wlan_index)->ta_peer_id);
					}
					else
#endif //IPA_HW_FNR_STATS
					{
						ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
						install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v4, IPACM_Wan::getXlat_Mux_Id(), get_client_memptr(wlan_client, wlan_index)->mac,
							get_client_memptr(wlan_client, wlan_index)->ta_peer_id);
					}
					get_client_memptr(wlan_client, wlan_index)->ipv4_ul_rules_set = true;
				}
			}
#ifdef FEATURE_STATIC_POLICY
			if(IPACM_Wan::isWanUP_V6(ipa_if_num) ||
				(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && IPACM_Wan::isVlanWanUP_V6()))
#else
			if(IPACM_Wan::isWanUP_V6(ipa_if_num))
#endif
			{
				if(IPACM_Wan::backhaul_is_sta_mode == false)
				{
#ifdef IPA_HW_FNR_STATS
					if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
					{
						ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
						install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v6, 0, get_client_memptr(wlan_client, wlan_index)->mac,
							get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx, NULL, false, get_client_memptr(wlan_client, wlan_index)->ta_peer_id);
					}
					else
#endif //IPA_HW_FNR_STATS
					{
						ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
						install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v6, 0, get_client_memptr(wlan_client, wlan_index)->mac,
							get_client_memptr(wlan_client, wlan_index)->ta_peer_id);
					}
					get_client_memptr(wlan_client, wlan_index)->ipv6_ul_rules_set = true;
				}
			}
		}
		// AST update is not dependent on per client stats.
		else if (ast_update_needed())
		{
			if (IPACM_Wan::isWanUP(ipa_if_num))
			{
				if(IPACM_Wan::backhaul_is_sta_mode == false)
				{
#ifdef IPA_HW_FNR_STATS
					if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
					{
						ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
						install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v4, IPACM_Wan::getXlat_Mux_Id(), get_client_memptr(wlan_client, wlan_index)->mac,
							get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx, NULL, false, get_client_memptr(wlan_client, wlan_index)->ta_peer_id);
					}
					else
#endif //IPA_HW_FNR_STATS
					{
						ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
						install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v4, IPACM_Wan::getXlat_Mux_Id(), get_client_memptr(wlan_client, wlan_index)->mac,
							get_client_memptr(wlan_client, wlan_index)->ta_peer_id);
					}
					get_client_memptr(wlan_client, wlan_index)->ipv4_ul_rules_set = true;
				}
			}
			if(IPACM_Wan::isWanUP_V6(ipa_if_num))
			{
				if(IPACM_Wan::backhaul_is_sta_mode == false)
				{
#ifdef IPA_HW_FNR_STATS
					if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
					{
						ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
						install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v6, 0, get_client_memptr(wlan_client, wlan_index)->mac,
							get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx, NULL, false, get_client_memptr(wlan_client, wlan_index)->ta_peer_id);
					}
					else
#endif //IPA_HW_FNR_STATS
					{
						ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
						install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v6, 0, get_client_memptr(wlan_client, wlan_index)->mac,
							get_client_memptr(wlan_client, wlan_index)->ta_peer_id);
					}
					get_client_memptr(wlan_client, wlan_index)->ipv6_ul_rules_set = true;
				}
			}
		}
#endif
		if (!delay_init)
			header_name_count++; //keep increasing header_name_count
		IPACM_Wlan::total_num_wifi_clients++;
		res = IPACM_SUCCESS;
		IPACMDBG_H("Wifi client number: %d\n", num_wifi_client);
	}
	else
	{
		return res;
	}

fail:
	free(pHeaderDescriptor);
	return res;
}

/* handle wifi client initial,copy all partial headers (tx property) */
int IPACM_Wlan::handle_wlan_primary_client_init_ex(ipacm_event_data_wlan_ex *data)
{
	int res = IPACM_FAILURE, cnt = 0, i, evt_size;

	/* start of adding header */
	IPACMDBG_H("Primary Wifi client number for this iface: %d, total number of wlan clients: %d\n",
                 num_wifi_primary_client, -1/*todo: add the correct variable here*/);

	IPACMDBG_H("Primary Wifi client number: %d\n", num_wifi_primary_client);

	evt_size = sizeof(ipacm_event_data_wlan_ex) + data->num_of_attribs * sizeof(struct ipa_wlan_hdr_attrib_val);
	get_primary_client_memptr(wlan_primary_client, num_wifi_primary_client)->p_hdr_info = (ipacm_event_data_wlan_ex*)malloc(evt_size);
	memcpy(get_primary_client_memptr(wlan_primary_client, num_wifi_primary_client)->p_hdr_info, data, evt_size);

	/* add header to IPA */
	if(tx_prop != NULL)
	{
		/* copy partial header for v4*/
		for (cnt=0; cnt<tx_prop->num_tx_props; cnt++)
		{
			if(tx_prop->tx[cnt].ip==IPA_IP_v4)
			{
				if (is_vlan_iface()) {
					if (cnt < IPA_IP_v4_VLAN)
						continue;
				} else {
					if (cnt >= IPA_IP_v4_VLAN)
						continue;
				}

				for(i = 0; i < data->num_of_attribs; i++)
				{
					if(data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_MAC_ADDR)
					{
						memcpy(get_primary_client_memptr(wlan_primary_client, num_wifi_primary_client)->mac,
								data->attribs[i].u.mac_addr,
								sizeof(get_primary_client_memptr(wlan_primary_client, num_wifi_primary_client)->mac));
					}
				}
				break;
			}
		}

		/* copy partial header for v6*/
		for (cnt=0; cnt<tx_prop->num_tx_props; cnt++)
		{
			if(tx_prop->tx[cnt].ip==IPA_IP_v6)
			{
				if (is_vlan_iface()) {
					if (cnt < IPA_IP_v4_VLAN)
						continue;
				} else {
					if (cnt >= IPA_IP_v4_VLAN)
						continue;
				}

				for(i = 0; i < data->num_of_attribs; i++)
				{
					if(data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_MAC_ADDR)
					{
						memcpy(get_primary_client_memptr(wlan_primary_client, num_wifi_primary_client)->mac,
								data->attribs[i].u.mac_addr,
								sizeof(get_primary_client_memptr(wlan_primary_client, num_wifi_primary_client)->mac));
					}
				}
				break;
			}
		}
		num_wifi_primary_client++;
		res = IPACM_SUCCESS;
		IPACMDBG_H("Primary Wifi client number: %d\n", num_wifi_primary_client);
	}
	else
	{
		return res;
	}

fail:
	return res;
}


/*handle wifi client */
int IPACM_Wlan::handle_wlan_client_ipaddr(ipacm_event_data_all *data)
{
	int clnt_indx, size = 0;
	uint32_t ipv6_link_local_prefix = 0xFE800000;
	uint32_t ipv6_link_local_prefix_mask = 0xFFC00000;
	ipacm_event_data_all data_all;
	std::list <ipacm_event_data_all>::iterator it;
	std::array<uint32_t, 4> ipv6 = {0};
	uint16_t vlan_id = 0;

	IPACMDBG_H("number of wifi clients: %d\n", num_wifi_client);
	IPACMDBG_H(" event MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 data->mac_addr[0],
					 data->mac_addr[1],
					 data->mac_addr[2],
					 data->mac_addr[3],
					 data->mac_addr[4],
					 data->mac_addr[5]);

#ifdef FEATURE_VLAN_MPDN
	if(is_vlan_event(data->iface_name))
	{
		IPACMDBG_H("handling vlan ETH client ip address for iface %s\n", data->iface_name);
		if(IPACM_Iface::ipacmcfg->get_vlan_id(data->iface_name, &vlan_id))
		{
			IPACMERR("failed getting vlan id for iface %s\n", data->iface_name);
			return IPACM_FAILURE;
		}
	}
#endif

	clnt_indx = get_wlan_client_index(data->mac_addr, vlan_id);
	if (clnt_indx == IPACM_INVALID_INDEX)
	{
		IPACMERR("wlan client not found/attached \n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Ip-type received %d\n", data->iptype);
	if (data->iptype == IPA_IP_v4)
	{
		IPACMDBG_H("ipv4 address: 0x%x, vlan-id: %d, device_type %d\n", data->ipv4_addr, vlan_id, device_type);
		if (data->ipv4_addr != 0) /* not 0.0.0.0 */
		{
			/* Special handling for Passthrough IP. */
			if (IPACM_Iface::ipacmcfg->is_ip_pass_enabled(device_type, data->mac_addr, vlan_id))
			{

				if (check_neigh_ipv4(data) == IPACM_SUCCESS)
				{
					IPACMDBG_H("Client is in IP passthrough mode, got IP: 0x%x\n", data->ipv4_addr);
				}
				else
				{
					IPACMERR("IP address %x mismatch for client but current one is different", data->ipv4_addr);
					return IPACM_FAILURE;
				}
			}
			else
			{
				if (check_neigh_ipv4(data) == IPACM_SUCCESS)
				{
					IPACMDBG_H("Client is not in IP passthrough mode, got IP: 0x%x\n", data->ipv4_addr);
				}
				else
				{
					IPACMERR("Client is not in IP passthrough mode, but got wrong IP: 0x%x\n", data->ipv4_addr);
					return IPACM_FAILURE;
				}
			}

			if (get_client_memptr(wlan_client, clnt_indx)->ipv4_set == false)
			{
				get_client_memptr(wlan_client, clnt_indx)->v4_addr = data->ipv4_addr;
				get_client_memptr(wlan_client, clnt_indx)->ipv4_set = true;
			}
			else
			{
			   /* check if client got new IPv4 address*/
			   if(data->ipv4_addr == get_client_memptr(wlan_client, clnt_indx)->v4_addr)
			   {
			     IPACMDBG_H("Already setup ipv4 addr for client:%d, ipv4 address didn't change\n", clnt_indx);
				 return IPACM_FAILURE;
			   }
			   else
			   {
			     IPACMDBG_H("ipv4 addr for client:%d is changed \n", clnt_indx);
				 /* delete NAT rules first */
				 CtList->HandleNeighIpAddrDelEvt(get_client_memptr(wlan_client, clnt_indx)->v4_addr);
			     delete_default_qos_rtrules(clnt_indx,IPA_IP_v4);
#ifdef FEATURE_STATIC_POLICY
				if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
				{
					delete_pdn_dscp_wlan_rtrules(IPA_IP_v4, 2, clnt_indx);
				}
#endif
		         get_client_memptr(wlan_client, clnt_indx)->route_rule_set_v4 = false;
			     get_client_memptr(wlan_client, clnt_indx)->v4_addr = data->ipv4_addr;
				 if (ast_update_needed())
				 	delete_wlan_client_lan2lan_flt_rule(data->mac_addr, IPA_IP_v4);
				}
			}
			if (ast_update_needed())
				install_wlan_client_lan2lan_flt_rule(data->mac_addr, IPA_IP_v4, get_client_memptr(wlan_client, clnt_indx)->is_vlan);
		}
		else
		{
		    IPACMDBG_H("Invalid client IPv4 address \n");
		    return IPACM_FAILURE;
		}
	}
	else
	{
		if ((data->ipv6_addr[0] != 0) || (data->ipv6_addr[1] != 0) ||
				(data->ipv6_addr[2] != 0) || (data->ipv6_addr[3] || 0)) /* check if all 0 not valid ipv6 address */
		{
			IPACMDBG_H("ipv6 address: 0x%x:%x:%x:%x\n", data->ipv6_addr[0], data->ipv6_addr[1], data->ipv6_addr[2], data->ipv6_addr[3]);
#ifdef FEATURE_IPV6_NAT
			if(IPACM_Iface::ipacmcfg->ipv6_nat_enable && is_unique_local_ipv6_addr(data->ipv6_addr))
			{
				IPACMDBG_H("ipv6 nat enabled - add ULA ip address\n")
			}
			else
#endif
			if((((data->ipv6_addr[0] & ipv6_link_local_prefix_mask) != (ipv6_link_local_prefix & ipv6_link_local_prefix_mask)) &&
#ifdef FEATURE_VLAN_MPDN
					/* returns true if a VLAN PDN or default PDN should be offloaded */
					IPACM_Iface::ipacmcfg->is_offload_ipv6_prefix(data->ipv6_addr) != true)
#ifdef FEATURE_IPV6_NAT
					&& (!(IPACM_Iface::ipacmcfg->ipv6_nat_enable && is_unique_local_ipv6_addr(data->ipv6_addr))))
#else
					)
#endif
#else
					memcmp(ipv6_prefix, data->ipv6_addr, sizeof(ipv6_prefix)) != 0)
#ifdef FEATURE_IPV6_NAT
					&& (!(IPACM_Iface::ipacmcfg->ipv6_nat_enable && is_unique_local_ipv6_addr(data->ipv6_addr))))
#else
					)
#endif
#endif
			{
				if (neigh_cache.size() < 2*IPA_MAX_NUM_WIFI_CLIENTS)
				{
					for (it = neigh_cache.begin(); it != neigh_cache.end(); ++it)
					{
						if ((it->ipv6_addr[0] == data->ipv6_addr[0]) && (it->ipv6_addr[1] == data->ipv6_addr[1])
							&& (it->ipv6_addr[2] == data->ipv6_addr[2])  && (it->ipv6_addr[3] == data->ipv6_addr[3]))
							break;
					}
					if (it == neigh_cache.end())
					{
						memcpy(&data_all, data, sizeof(ipacm_event_data_all));
						neigh_cache.push_back(data_all);
						IPACMDBG_H("Caching v6 addr : 0x%08x:%08x:%08x:%08x MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
							data_all.ipv6_addr[0], data_all.ipv6_addr[1], data_all.ipv6_addr[2], data_all.ipv6_addr[3],
							data_all.mac_addr[0], data_all.mac_addr[1], data_all.mac_addr[2], data_all.mac_addr[3], data_all.mac_addr[4], data_all.mac_addr[5]);
					}
				}
				IPACMDBG_H("This IPv6 address is not global IPv6 address with correct prefix, ignore.\n");
				return IPACM_FAILURE;
			}

			if(IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6 < IPA_MAX_NUM_CLIENTS_IPV6)
			{
				IPACMDBG_H("eth client:%d, current ipv6:%d, v6_route_set:%d, total_client_ipv6: %d, limit %d\n",
					clnt_indx, get_client_memptr(wlan_client, clnt_indx)->ipv6_set,
					get_client_memptr(wlan_client, clnt_indx)->route_rule_set_v6,
					IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6, IPA_MAX_NUM_CLIENTS_IPV6);
				std::copy(std::begin(data->ipv6_addr), std::end(data->ipv6_addr), std::begin(ipv6));

				/* never see this ipv6, insert to the map*/
				if(rt_hdl_v6_list[clnt_indx].count(ipv6) == 0 && ((data->ipv6_addr[0] & ipv6_link_local_prefix_mask) != (ipv6_link_local_prefix & ipv6_link_local_prefix_mask)))
				{
					/*
					 * The client got new IPv6 address.
					 * NOTE: The new address doesn't replace the existing one but being added (up to IPA_MAX_NUM_CLIENTS_IPV6),
					 *       so the previous IPv6 addresses of the client will not be deleted.
					 */
					rt_hdl_v6_list[clnt_indx].insert(std::make_pair(ipv6, handleTypeV6(iface_query->num_tx_props)));
					/* indicate how many ipv6 client gets */
					get_client_memptr(wlan_client, clnt_indx)->ipv6_set++;
					IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6++;
					/* Add the LAN2LAN filter only for Global IPv6 address. */
					if (ast_update_needed() &&
						((data->ipv6_addr[0] & ipv6_link_local_prefix_mask) !=
						(ipv6_link_local_prefix & ipv6_link_local_prefix_mask)) &&
						!get_client_memptr(wlan_client, clnt_indx)->lan2lan_fl_rule_hdl_v6)

						install_wlan_client_lan2lan_flt_rule(data->mac_addr, IPA_IP_v6, get_client_memptr(wlan_client, clnt_indx)->is_vlan);
				}
				else
				{
					IPACMDBG_H("Already got ipv6 addr 0x%08x:%08x:%08x:%08x for client:%d\n", data->ipv6_addr[0], data->ipv6_addr[1], data->ipv6_addr[2], data->ipv6_addr[3], clnt_indx);
					return IPACM_FAILURE;
				}
		    }
		    else
		    {
				IPACMDBG_H("Already got %d ipv6 addr (max: %d) for client:%d\n", IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6, IPA_MAX_NUM_CLIENTS_IPV6, clnt_indx);
				return IPACM_FAILURE; /* not setup the RT rules*/
		    }
		}
	}

	return IPACM_SUCCESS;
}

/*handle wifi client routing rule*/
int IPACM_Wlan::handle_wlan_client_route_rule(uint8_t *mac_addr, ipa_ip_type iptype, uint16_t vlan_id)
{
	struct ipa_ioc_add_rt_rule *rt_rule;
	struct ipa_rt_rule_add *rt_rule_entry;
#ifdef FEATURE_IPA_IPSEC
	ipa_ip_type *iptype_p = NULL;
	ipacm_cmd_q_data evt_data;
#endif
	uint32_t tx_index;
	int wlan_index;
	const int NUM = 1;

	if(tx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
			mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5]);

	wlan_index = get_wlan_client_index(mac_addr, vlan_id);

	if (wlan_index == IPACM_INVALID_INDEX)
	{
		IPACMDBG_H("wlan client not found/attached \n");
		return IPACM_SUCCESS;
	}

	/* during power_save mode, even receive IP_ADDR_ADD, not setting RT rules*/
	if (get_client_memptr(wlan_client, wlan_index)->power_save_set == true)
	{
		IPACMDBG_H("wlan client is in power safe mode \n");
		return IPACM_SUCCESS;
	}

	if (iptype==IPA_IP_v4)
	{
		IPACMDBG_H("wlan client index: %d, ip-type: %d, ipv4_set:%d, ipv4_rule_set:%d ipv4_hpc_set: %d\n", wlan_index, iptype,
				get_client_memptr(wlan_client, wlan_index)->ipv4_set,
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4,
				get_client_memptr(wlan_client, wlan_index)->ipv4_hpc_set);
	}
	else
	{
		IPACMDBG_H("wlan client index: %d, ip-type: %d, ipv6_set:%d, ipv6_rule_num:%d ipv6_hpc_set:%d\n", wlan_index, iptype,
				get_client_memptr(wlan_client, wlan_index)->ipv6_set,
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6,
				get_client_memptr(wlan_client, wlan_index)->ipv6_hpc_set);
	}


	/* Add default  Qos routing rules if not set yet */
	if ((iptype == IPA_IP_v4
				&& get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4 == false
				&& get_client_memptr(wlan_client, wlan_index)->ipv4_set == true)
			|| (iptype == IPA_IP_v6
				&& get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6 < get_client_memptr(wlan_client, wlan_index)->ipv6_set
			   ))
	{
		rt_rule = (struct ipa_ioc_add_rt_rule *)
			calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
					NUM * sizeof(struct ipa_rt_rule_add));

		if (rt_rule == NULL)
		{
			PERROR("Error Locate ipa_ioc_add_rt_rule memory...\n");
			return IPACM_FAILURE;
		}

		rt_rule->commit = 1;
		rt_rule->num_rules = (uint8_t)NUM;
		rt_rule->ip = iptype;


		for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		{
#ifdef IPA_HDR_L2_802_1Q_AST
			/* skip to the next tx index if the client type and hdr_l2_type are not matching */
			if ((get_client_memptr(wlan_client, wlan_index)->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q_AST && tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q)) ||
					(!get_client_memptr(wlan_client, wlan_index)->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q_AST || tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q)))
			{
				continue;
			}
#endif

			if (iptype != tx_prop->tx[tx_index].ip)
			{
				IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip,iptype);
				continue;
			}

			rt_rule_entry = &rt_rule->rules[0];
			rt_rule_entry->at_rear = 0;

			if (iptype == IPA_IP_v4)
			{
				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", wlan_index,
						get_client_memptr(wlan_client, wlan_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
						wlan_index,
						get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4);
				strlcpy(rt_rule->rt_tbl_name,
						IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
						sizeof(rt_rule->rt_tbl_name));
				rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';

				if(IPACM_Iface::ipacmcfg->isMCC_Mode)
				{
					IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
							tx_prop->tx[tx_index].alt_dst_pipe);
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
				}
				else
				{
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
				}

				memcpy(&rt_rule_entry->rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry->rule.attrib));
				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;

				if (get_client_memptr(wlan_client, wlan_index)->ipv4_hpc_set)
					rt_rule_entry->rule.hdr_proc_ctx_hdl = get_client_memptr(wlan_client, wlan_index)->hpc_hdr_hdl_v4;
				else
					rt_rule_entry->rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4;

				rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(wlan_client, wlan_index)->v4_addr;
				rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;

				if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
				{
					rt_rule_entry->rule.hashable = true;
				}
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
				if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
					if (iptype == IPA_IP_v6)
						rt_rule_entry->rule.ttl_update =
							IPACM_Wan::is_global_ipv6_addr(rt_rule_entry->rule.attrib.u.v6.dst_addr);
					else
						rt_rule_entry->rule.ttl_update = true;
				}
#endif
				if (false == m_routing.AddRoutingRule(rt_rule))
				{
					IPACMERR("Routing rule addition failed!\n");
					free(rt_rule);
					return IPACM_FAILURE;
				}

				/* copy ipv4 RT hdl */
				get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4 =
					rt_rule->rules[0].rt_rule_hdl;
				IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
						get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4, iptype);
			}
			else
			{
				for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end();++it)
				{
					if (it->second.route_rule_set_v6 == true)
					{
						IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set (%d)\n",
						wlan_index, it->first[0], it->first[1], it->first[2], it->first[3],
						it->second.route_rule_set_v6);
						continue;
					}

					IPACMDBG_H("client(%d): v6 header handle:(0x%x)\n",
							wlan_index,
							get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6);

					/* v6 LAN_RT_TBL */
					strlcpy(rt_rule->rt_tbl_name,
							IPACM_Iface::ipacmcfg->rt_tbl_v6.name,
							sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Support QCMAP LAN traffic feature, send to A5 */
					rt_rule_entry->rule.dst = iface_query->excp_pipe;
					memset(&rt_rule_entry->rule.attrib, 0, sizeof(rt_rule_entry->rule.attrib));
					rt_rule_entry->rule.hdr_hdl = 0;
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = it->first[0];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = it->first[1];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = it->first[2];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = it->first[3];
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
#ifdef FEATURE_IPA_V3
					rt_rule_entry->rule.hashable = true;
#endif
					if (false == m_routing.AddRoutingRule(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						free(rt_rule);
						return IPACM_FAILURE;
					}

					it->second.hdl_v6[tx_index].rt_rule_hdl_v6 = rt_rule->rules[0].rt_rule_hdl;
					IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
							it->second.hdl_v6[tx_index].rt_rule_hdl_v6, iptype);

					/*Copy same rule to v6 WAN RT TBL*/
					strlcpy(rt_rule->rt_tbl_name,
							IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name,
							sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Downlink traffic from Wan iface, directly through IPA */
					if(IPACM_Iface::ipacmcfg->isMCC_Mode)
					{
						IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
								tx_prop->tx[tx_index].alt_dst_pipe);
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
					}
					else
					{
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
					}
					memcpy(&rt_rule_entry->rule.attrib,
							&tx_prop->tx[tx_index].attrib,
							sizeof(rt_rule_entry->rule.attrib));

					if (get_client_memptr(wlan_client, wlan_index)->ipv6_hpc_set)
						rt_rule_entry->rule.hdr_proc_ctx_hdl = get_client_memptr(wlan_client, wlan_index)->hpc_hdr_hdl_v6;
					else
						rt_rule_entry->rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6;

					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = it->first[0];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = it->first[1];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = it->first[2];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = it->first[3];
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
#ifdef FEATURE_IPA_V3
					rt_rule_entry->rule.hashable = true;
#endif
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
					if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
						if (iptype == IPA_IP_v6)
							rt_rule_entry->rule.ttl_update = IPACM_Wan::is_global_ipv6_addr(rt_rule_entry->rule.attrib.u.v6.dst_addr);
						else
							rt_rule_entry->rule.ttl_update = true;
					}
#endif
					if (false == m_routing.AddRoutingRule(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						free(rt_rule);
						return IPACM_FAILURE;
					}

					it->second.hdl_v6[tx_index].rt_rule_hdl_v6_wan = rt_rule->rules[0].rt_rule_hdl;
					IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
							it->second.hdl_v6[tx_index].rt_rule_hdl_v6_wan, iptype);
					/* mark as route_rule_set_v6 = true*/
					if (tx_index + 1 == iface_query->num_tx_props)
						it->second.route_rule_set_v6 = true;
				} /* v6 map loop */
			} /* ipv6 handling */
		} /* end of for loop */

		free(rt_rule);

		if (iptype == IPA_IP_v4)
		{
			get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4 = true;
		}
		else
		{
			get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6 = get_client_memptr(wlan_client, wlan_index)->ipv6_set;
		}
	}

#ifdef FEATURE_IPA_IPSEC
	iptype_p = (ipa_ip_type *)malloc(sizeof(*iptype_p));
	if (!iptype_p) {
		IPACMERR("Failed allocating memory for IPA_IPSEC_LAN_CLIENT_ROUTE_ADD_EVENT\n");
		return IPACM_FAILURE;
	}
	*iptype_p = iptype;
	evt_data.event = IPA_IPSEC_LAN_CLIENT_ROUTE_ADD_EVENT;
	evt_data.evt_data = (void *)iptype_p;
	IPACM_EvtDispatcher::PostEvt(&evt_data);
#endif

	return IPACM_SUCCESS;
}

#ifdef FEATURE_STATIC_POLICY
/*handle wlan client routing rule based on PDN and DSCP value for traffic prioritization*/
int IPACM_Wlan::handle_pdn_dscp_wlan_client_route_rule(uint8_t *mac_addr,
               ipa_ip_type iptype, uint32_t trigger, uint16_t vlan_id, uint8_t mux_id,
               uint8_t dscp_val, uint32_t* ipv6_addr)
{
	struct ipa_ioc_add_rt_rule *rt_rule;
	struct ipa_rt_rule_add *rt_rule_entry;
#ifdef FEATURE_IPA_IPSEC
	ipa_ip_type *iptype_p = NULL;
	ipacm_cmd_q_data evt_data;
#endif
	uint32_t tx_index;
	int wlan_index;
	int NUM = 0;
	uint8_t valid_mux[IPA_UC_MAX_PDN_DSCP_VAL];
	struct ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table = NULL;
	struct ipa_hdr_proc_ctx_add *hdr_proc_ctx = NULL;
	int size = 0, mux_idx = 0, i = 0, j = 0, idx = 0;

	IPACMDBG_H("trigger:%d iptype:%d mux_id:%d dscp_val:%d\n", trigger, iptype, mux_id, dscp_val);

	if(trigger == 0)
	{
		if(tx_prop == NULL)
		{
			IPACMDBG_H("No tx properties registered for iface %s\n", dev_name);
			return IPACM_SUCCESS;
		}

		IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
			mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5]);

		wlan_index = get_wlan_client_index(mac_addr, vlan_id);
		if (wlan_index == IPACM_INVALID_INDEX)
		{
			IPACMDBG_H("wlan client not found/attached\n");
			return IPACM_SUCCESS;
		}

		if (iptype==IPA_IP_v4) {
			IPACMDBG_H("wlan client index: %d, ip-type: %d, ipv4_set:%d, ipv4_rule_set:%d \n", wlan_index, iptype,
				get_client_memptr(wlan_client, wlan_index)->ipv4_set,
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4);
		} else {
			IPACMDBG_H("wlan client index: %d, ip-type: %d, ipv6_set:%d, ipv6_rule_num:%d \n", wlan_index, iptype,
				get_client_memptr(wlan_client, wlan_index)->ipv6_set,
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6);
		}

		if (get_client_memptr(wlan_client, wlan_index)->power_save_set == true)
		{
			IPACMDBG_H("wlan client is in power safe mode\n");
			return IPACM_SUCCESS;
		}

		if (iptype == IPA_IP_v4 &&
			get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4 == false)
		{
			IPACMERR("route rule has not been set for wlan client\n");
			return IPACM_FAILURE;
		}

		if (iptype == IPA_IP_v6 &&
			get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6 == 0)
		{
			IPACMERR("v6 route rule has not been set for wlan client index:%d\n",
				wlan_index);
			return IPACM_FAILURE;
		}

		size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
		hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx *)malloc(size);
		if (hdr_proc_ctx_table == NULL) {
			IPACMERR("Failed to allocate memory for hdr_proc_ctx\n");
			return IPACM_FAILURE;
		}

		for(i=0; i<IPA_UC_MAX_PDN_DSCP_VAL; i++)
		{
			if(iptype == IPA_IP_v4 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2 &&
				get_client_memptr(wlan_client, wlan_index)->dscp_ipv4_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == false)
			{
				memset(hdr_proc_ctx_table, 0, size);
				hdr_proc_ctx_table->commit = 1;
				hdr_proc_ctx_table->num_proc_ctxs = 1;
				hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
				hdr_proc_ctx->type = IPA_HDR_PROC_MARK_DSCP;

				if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 0)
				{
					hdr_proc_ctx->pdn_dscp_params.valid = 0;
				}
				else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 1)
				{
					hdr_proc_ctx->pdn_dscp_params.valid = 1;
					hdr_proc_ctx->pdn_dscp_params.dscp_val = IPACM_Iface::ipacmcfg->pdn_dscp_table[i].dscp_val;
				}

				hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4;
				IPACMDBG_H("hdr_proc_ctx->hdr_hdl v4 0x%x\n", hdr_proc_ctx->hdr_hdl);

				if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
					hdr_proc_ctx_table->proc_ctx[0].status != 0) {
					IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
					free(hdr_proc_ctx_table);
					return IPACM_FAILURE;
				}

				get_client_memptr(wlan_client, wlan_index)->dscp_hpc_hdr_hdl_v4
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] =
						hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
				get_client_memptr(wlan_client, wlan_index)->dscp_ipv4_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] = true;
				IPACMDBG_H("v4 hpc header handle for mux_id %d:(0x%x)\n",
					IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id,
					get_client_memptr(wlan_client, wlan_index)->dscp_hpc_hdr_hdl_v4[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id]);
			}

			if(iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2 &&
				get_client_memptr(wlan_client, wlan_index)->dscp_ipv6_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == false)
			{
				memset(hdr_proc_ctx_table, 0, size);
				hdr_proc_ctx_table->commit = 1;
				hdr_proc_ctx_table->num_proc_ctxs = 1;
				hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
				hdr_proc_ctx->type = IPA_HDR_PROC_MARK_DSCP;

				if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 0)
				{
					hdr_proc_ctx->pdn_dscp_params.valid = 0;
				}
				else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 1)
				{
					hdr_proc_ctx->pdn_dscp_params.valid = 1;
					hdr_proc_ctx->pdn_dscp_params.dscp_val =
						IPACM_Iface::ipacmcfg->pdn_dscp_table[i].dscp_val;
				}

				hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6;
				IPACMDBG_H("hdr_proc_ctx->hdr_hdl v6 0x%x\n", hdr_proc_ctx->hdr_hdl);
				if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
						hdr_proc_ctx_table->proc_ctx[0].status != 0) {
					IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
					free(hdr_proc_ctx_table);
					return IPACM_FAILURE;
				}

				get_client_memptr(wlan_client, wlan_index)->dscp_hpc_hdr_hdl_v6
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] =
						hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
				get_client_memptr(wlan_client, wlan_index)->dscp_ipv6_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] = true;
				IPACMDBG_H("v6 hpc header handle for mux_id %d:(0x%x)\n",
					IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id,
					get_client_memptr(wlan_client, wlan_index)->dscp_hpc_hdr_hdl_v6[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id]);
			}

			if(iptype == IPA_IP_v4 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2
				&& get_client_memptr(wlan_client, wlan_index)->dscp_route_rule_set_v4
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == false &&
				get_client_memptr(wlan_client, wlan_index)->dscp_ipv4_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == true)
			{
				valid_mux[NUM++] = IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id;
			}
			else if(iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2)
			{
				for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end(); ++it)
				{
					for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
					{
						if (iptype != tx_prop->tx[tx_index].ip)
						{
							IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
								tx_index, tx_prop->tx[tx_index].ip, iptype);
							continue;
						}
						if(get_client_memptr(wlan_client, wlan_index)->dscp_ipv6_hpc_set
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == false)
						{
							continue;
						}
						if(it->first[0] == ipv6_addr[0] && it->first[1] == ipv6_addr[1] && it->first[2] == ipv6_addr[2]
							&& it->first[3] == ipv6_addr[3]
							&& it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6
								[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == false &&
							it->second.route_rule_set_v6 == true)
						{
							valid_mux[NUM++] = IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id;
						}
					}
				}
			}
		}

		if (iptype == IPA_IP_v4 && NUM >= 1)
		{
			rt_rule = (struct ipa_ioc_add_rt_rule *)
				calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
				NUM * sizeof(struct ipa_rt_rule_add));

			if (rt_rule == NULL)
			{
				PERROR("Error allocating ipa_ioc_add_rt_rule memory...\n");
				free(hdr_proc_ctx_table);
				return IPACM_FAILURE;
			}

			rt_rule->commit = 1;
			rt_rule->num_rules = (uint8_t)NUM;
			rt_rule->ip = iptype;
			for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
				if (iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}
				if ((tx_index >= 2 && sIface && !vlan_id) ||
					tx_index < 2 && sIface && vlan_id) {
					IPACMDBG_H("Tx:%d, ip-type: %d duplicate rule ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}

				strlcpy(rt_rule->rt_tbl_name,
					IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
					sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';

				for (i = 0; i < rt_rule->num_rules; i++)
				{
					if(!valid_mux[i])
					{
						continue;
					}

					rt_rule_entry = &rt_rule->rules[i];
					rt_rule_entry->at_rear = false;
					IPACMDBG_H("client index(%d):ipv4 address: 0x%x v4 header handle:(0x%x)\n",
						wlan_index,
						get_client_memptr(wlan_client, wlan_index)->v4_addr,
						get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4);

					if(IPACM_Iface::ipacmcfg->isMCC_Mode)
					{
						IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
							tx_prop->tx[tx_index].alt_dst_pipe);
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
					}
					else
					{
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
					}

					memcpy(&rt_rule_entry->rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry->rule.attrib));
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_META_DATA;
					if (get_client_memptr(wlan_client, wlan_index)->dscp_ipv4_hpc_set[valid_mux[i]])
						rt_rule_entry->rule.hdr_proc_ctx_hdl =
							get_client_memptr(wlan_client, wlan_index)->dscp_hpc_hdr_hdl_v4[valid_mux[i]];
					else
						rt_rule_entry->rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4;
					rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(wlan_client, wlan_index)->v4_addr;
					rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.meta_data =
						valid_mux[i] << MUX_ID_DL_METADATA_SHIFT;
					rt_rule_entry->rule.attrib.meta_data_mask =
						MUX_ID_DL_METADATA_MASK << MUX_ID_DL_METADATA_SHIFT;
					if (IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
					{
						rt_rule_entry->rule.hashable = true;
					}
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
					if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
						if (iptype == IPA_IP_v6)
							rt_rule_entry->rule.ttl_update =
								IPACM_Wan::is_global_ipv6_addr(rt_rule_entry->rule.attrib.u.v6.dst_addr);
						else
							rt_rule_entry->rule.ttl_update = true;
					}
#endif
				}
				if (false == m_routing.AddRoutingRule(rt_rule))
				{
					IPACMERR("Routing rule addition has failed for v4!\n");
					goto fail;
				}

				/* copy ipv4 RT hdl */
				for(j=0; j<rt_rule->num_rules; j++)
				{
					get_client_memptr(wlan_client, wlan_index)->dscp_wifi_rt_hdl[valid_mux[j]].wifi_rt_rule_hdl_v4 =
						rt_rule->rules[j].rt_rule_hdl;
					IPACMDBG_H("v4: tx:%d, rt_rule_hdl=%x ip-type:%d\n", tx_index,
						get_client_memptr(wlan_client, wlan_index)->dscp_wifi_rt_hdl[valid_mux[j]].wifi_rt_rule_hdl_v4, iptype);
					get_client_memptr(wlan_client, wlan_index)->dscp_route_rule_set_v4[valid_mux[j]] = true;
					get_client_memptr(wlan_client, wlan_index)->dscp_ipv4_hpc_count[valid_mux[j]]++;
				}
			}
			free(hdr_proc_ctx_table);
			free(rt_rule);
		}
		else if (iptype == IPA_IP_v6 && NUM >= 1)
		{
			rt_rule = (struct ipa_ioc_add_rt_rule *)
				calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
				NUM  *
				sizeof(struct ipa_rt_rule_add));

			if (rt_rule == NULL)
			{
				PERROR("Error allocating ipa_ioc_add_rt_rule memory...\n");
				free(hdr_proc_ctx_table);
				return IPACM_FAILURE;
			}

			rt_rule->commit = 1;
			rt_rule->num_rules = (uint8_t)(NUM);
			rt_rule->ip = iptype;
			for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
				if (iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}
				if ((tx_index >= 2 && sIface && !vlan_id) ||
					tx_index < 2 && sIface && vlan_id) {
						IPACMDBG_H("Tx:%d, ip-type: %d duplicate rule ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
						continue;
				}

				strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';

				for (i = 0; i < NUM; i++)
				{
					if(!valid_mux[i])
					{
						continue;
					}
					for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end(); ++it)
					{
						if(it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[valid_mux[i]] == true)
						{
							IPACMERR("dscp v6 route rule has been set for wlan client already\n");
							IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d)\n",
								wlan_index, it->first[0], it->first[1], it->first[2], it->first[3],
								it->second.route_rule_set_v6);
							continue;
						}

						if(it->first[0] == ipv6_addr[0] && it->first[1] == ipv6_addr[1] && it->first[2] == ipv6_addr[2]
							&& it->first[3] == ipv6_addr[3] && it->second.route_rule_set_v6 == true)
						{
							IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d)\n",
								wlan_index, it->first[0], it->first[1], it->first[2], it->first[3],
								it->second.route_rule_set_v6);
								IPACMDBG_H("client-index(%d): v6 header handle:(0x%x)\n",
									wlan_index,
									get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6);

							/* Downlink traffic from Wan iface, directly through IPA */
							rt_rule_entry = &rt_rule->rules[i];
							rt_rule_entry->at_rear = false;
							if(IPACM_Iface::ipacmcfg->isMCC_Mode)
							{
								IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
									tx_prop->tx[tx_index].alt_dst_pipe);
								rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
							}
							else
							{
								rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
							}

							memcpy(&rt_rule_entry->rule.attrib,
								&tx_prop->tx[tx_index].attrib,
								sizeof(rt_rule_entry->rule.attrib));
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[valid_mux[i]] =
								get_client_memptr(wlan_client, wlan_index)->dscp_hpc_hdr_hdl_v6[valid_mux[i]];
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[valid_mux[i]] = true;

							if (it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[valid_mux[i]])
								rt_rule_entry->rule.hdr_proc_ctx_hdl =
									it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[valid_mux[i]];
							else
								rt_rule_entry->rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6;

							rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
							rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_META_DATA;
							rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = it->first[0];
							rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = it->first[1];
							rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = it->first[2];
							rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = it->first[3];
							rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
							rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
							rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
							rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
							rt_rule_entry->rule.attrib.meta_data =
								valid_mux[i] << MUX_ID_DL_METADATA_SHIFT;
							rt_rule_entry->rule.attrib.meta_data_mask =
								MUX_ID_DL_METADATA_MASK << MUX_ID_DL_METADATA_SHIFT;
#ifdef FEATURE_IPA_V3
							rt_rule_entry->rule.hashable = true;
#endif
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
							if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
								if (iptype == IPA_IP_v6)
									rt_rule_entry->rule.ttl_update =
									IPACM_Wan::is_global_ipv6_addr(rt_rule_entry->rule.attrib.u.v6.dst_addr);
								else
									rt_rule_entry->rule.ttl_update = true;
								}
#endif
						}
					}
				}
				if (false == m_routing.AddRoutingRule(rt_rule))
				{
					IPACMERR("Routing rule addition has failed for v6!\n");
					goto fail;
				}

				for (i = 0; i < NUM; i++)
				{
					for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end(); ++it)
					{
						if(it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[valid_mux[i]] == true)
						{
							IPACMERR("dscp v6 route rule has been set for wlan client already\n");
							continue;
						}

						if(it->first[0] == ipv6_addr[0] && it->first[1] == ipv6_addr[1] && it->first[2] == ipv6_addr[2]
							&& it->first[3] == ipv6_addr[3] && it->second.route_rule_set_v6 == true)
						{
							it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan[valid_mux[i]] = rt_rule->rules[i].rt_rule_hdl;
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[valid_mux[i]] = true;
							IPACMDBG_H("v6: tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
								it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan[valid_mux[i]], iptype);
							get_client_memptr(wlan_client, wlan_index)->dscp_ipv6_hpc_count[valid_mux[i]]++;
						}
					}
				}
			}
			free(hdr_proc_ctx_table);
			free(rt_rule);
		}
	}
	else if(trigger == 1)
	{
		if(iptype == IPA_IP_v4)
		{
			size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
			hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx *)malloc(size);
			if (hdr_proc_ctx_table == NULL) {
				IPACMERR("Failed to allocate memory for hdrproc_ctx\n");
				free(hdr_proc_ctx_table);
				return IPACM_FAILURE;
			}

			NUM = 0;

			for (i = 0; i < num_wifi_client; i++)
			{
				if(get_client_memptr(wlan_client, i)->route_rule_set_v4 == false ||
					get_client_memptr(wlan_client, i)->power_save_set == true ||
					get_client_memptr(wlan_client, i)->dscp_route_rule_set_v4[mux_id] == true)
				{
					continue;
				}

				if(false == get_client_memptr(wlan_client, i)->dscp_ipv4_hpc_set[mux_id])
				{
					memset(hdr_proc_ctx_table, 0, size);
					hdr_proc_ctx_table->commit = 1;
					hdr_proc_ctx_table->num_proc_ctxs = 1;
					hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
					hdr_proc_ctx->type = IPA_HDR_PROC_MARK_DSCP;

					if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 0)
					{
						hdr_proc_ctx->pdn_dscp_params.valid = 0;
					}
					else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 1)
					{
						hdr_proc_ctx->pdn_dscp_params.valid = 1;
						hdr_proc_ctx->pdn_dscp_params.dscp_val = dscp_val;
					}

					hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, i)->hdr_hdl_v4;
					IPACMDBG_H("hdr_proc_ctx->hdr_hdl v4 0x%x\n", hdr_proc_ctx->hdr_hdl);

					if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
						hdr_proc_ctx_table->proc_ctx[0].status != 0) {
						IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n",
							hdr_proc_ctx_table->proc_ctx[0].status);
						free(hdr_proc_ctx_table);
						return IPACM_FAILURE;
					}

					get_client_memptr(wlan_client, i)->dscp_hpc_hdr_hdl_v4[mux_id] =
						hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
					get_client_memptr(wlan_client, i)->dscp_ipv4_hpc_set[mux_id] = true;
					IPACMDBG_H("v4 hpc header handle for mux_id %d:(0x%x)\n",
						i, get_client_memptr(wlan_client, i)->dscp_hpc_hdr_hdl_v4[mux_id]);
				}
				NUM++;
			}

			if(NUM <= 0)
			{
				free(hdr_proc_ctx_table);
				return IPACM_FAILURE;
			}

			rt_rule = (struct ipa_ioc_add_rt_rule *)
				calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
				NUM * sizeof(struct ipa_rt_rule_add));

			if (rt_rule == NULL)
			{
				PERROR("Error allocating ipa_ioc_add_rt_rule memory...\n");
				free(hdr_proc_ctx_table);
				return IPACM_FAILURE;
			}

			rt_rule->commit = 1;
			rt_rule->ip = IPA_IP_v4;
			rt_rule->num_rules = (uint8_t)NUM;

			for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
				if (iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}
				if ((tx_index >= 2 && sIface && !vlan_id) ||
					tx_index < 2 && sIface && vlan_id) {
					IPACMDBG_H("Tx:%d, ip-type: %d duplicate rule ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}

				strlcpy(rt_rule->rt_tbl_name,
				IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
					sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';

				for (i = 0; i < num_wifi_client; i++)
				{
					if(get_client_memptr(wlan_client, i)->route_rule_set_v4 == false ||
						get_client_memptr(wlan_client, i)->power_save_set == true ||
						get_client_memptr(wlan_client, i)->dscp_route_rule_set_v4[mux_id] == true)
					{
						continue;
					}
					rt_rule_entry = &rt_rule->rules[i];
					rt_rule_entry->at_rear = false;
					IPACMDBG_H("client index(%d):ipv4 address: 0x%x v4 header handle:(0x%x)\n",
						i,
						get_client_memptr(wlan_client, i)->v4_addr,
						get_client_memptr(wlan_client, i)->hdr_hdl_v4);
					if(IPACM_Iface::ipacmcfg->isMCC_Mode)
					{
						IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
								tx_prop->tx[tx_index].alt_dst_pipe);
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
					}
					else
					{
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
					}

					memcpy(&rt_rule_entry->rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry->rule.attrib));
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_META_DATA;
					if (get_client_memptr(wlan_client, i)->dscp_ipv4_hpc_set[mux_id])
						rt_rule_entry->rule.hdr_proc_ctx_hdl =
							get_client_memptr(wlan_client, i)->dscp_hpc_hdr_hdl_v4[mux_id];
					else
						rt_rule_entry->rule.hdr_hdl = get_client_memptr(wlan_client, i)->hdr_hdl_v4;

					rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(wlan_client, i)->v4_addr;
					rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.meta_data =
						mux_id << MUX_ID_DL_METADATA_SHIFT;
					rt_rule_entry->rule.attrib.meta_data_mask =
						MUX_ID_DL_METADATA_MASK << MUX_ID_DL_METADATA_SHIFT;
					if (IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
					{
						rt_rule_entry->rule.hashable = true;
					}
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
					if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
						if (iptype == IPA_IP_v6)
							rt_rule_entry->rule.ttl_update =
								IPACM_Wan::is_global_ipv6_addr(rt_rule_entry->rule.attrib.u.v6.dst_addr);
						else
							rt_rule_entry->rule.ttl_update = true;
					}
#endif
				}

				if (false == m_routing.AddRoutingRule(rt_rule))
				{
					IPACMERR("Routing rule addition has failed for v4!\n");
					goto fail;
				}

				idx = 0;
				for (j=0; j < num_wifi_client; j++)
				{
					if(get_client_memptr(wlan_client, j)->route_rule_set_v4 == false ||
						get_client_memptr(wlan_client, j)->power_save_set == true ||
						get_client_memptr(wlan_client, j)->dscp_route_rule_set_v4[mux_id] == true)
					{
						continue;
					}
					get_client_memptr(wlan_client, j)->dscp_wifi_rt_hdl[mux_id].wifi_rt_rule_hdl_v4 =
						rt_rule->rules[idx].rt_rule_hdl;
					get_client_memptr(wlan_client, j)->dscp_route_rule_set_v4[mux_id] = true;
					IPACMDBG_H("v4: tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
					get_client_memptr(wlan_client, j)->dscp_wifi_rt_hdl[mux_id].wifi_rt_rule_hdl_v4, iptype);
					get_client_memptr(wlan_client, j)->dscp_ipv4_hpc_count[mux_id]++;
					idx++;
				}
			}
			free(hdr_proc_ctx_table);
			free(rt_rule);
		}
		else if (iptype == IPA_IP_v6)
		{
			NUM = 0;
			for (j=0; j < num_wifi_client; j++)
			{
				if(get_client_memptr(wlan_client, j)->route_rule_set_v6 == 0 ||
					get_client_memptr(wlan_client, j)->power_save_set == true)
				{
					continue;
				}
				for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
				{
					if (iptype != tx_prop->tx[tx_index].ip)
					{
						IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
							tx_index, tx_prop->tx[tx_index].ip, iptype);
						continue;
					}
					for (auto it = rt_hdl_v6_list[j].begin(); it != rt_hdl_v6_list[j].end(); ++it)
					{
						IPACMDBG_H("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d) dscp:%d\n",
							j, it->first[0], it->first[1], it->first[2], it->first[3],
							it->second.route_rule_set_v6, it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id]);
						if (it->second.route_rule_set_v6 == false ||
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id] == true)
						{
							continue;
						}
						IPACMDBG_H("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d) dscp:%d\n",
							j, it->first[0], it->first[1], it->first[2], it->first[3],
							it->second.route_rule_set_v6, it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id]);

						NUM++;
					}
				}
			}

			if(NUM <= 0)
			{
				return IPACM_FAILURE;
			}

			size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
			hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx *)malloc(size);
			if (hdr_proc_ctx_table == NULL) {
				IPACMERR("Failed to allocate memory for hdr_proc_ctx.\n");
				return IPACM_FAILURE;
			}

			rt_rule = (struct ipa_ioc_add_rt_rule *)
				calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
				NUM  *
				sizeof(struct ipa_rt_rule_add));

			if (rt_rule == NULL)
			{
				PERROR("Error allocating ipa_ioc_add_rt_rule memory...\n");
				free(hdr_proc_ctx_table);
				return IPACM_FAILURE;
			}

			rt_rule->commit = 1;
			rt_rule->num_rules = (uint8_t)(NUM);
			rt_rule->ip = iptype;
			for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
				if (iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}
				if ((tx_index >= 2 && sIface && !vlan_id) ||
					tx_index < 2 && sIface && vlan_id) {
						IPACMDBG_H("Tx:%d, ip-type: %d duplicate rule ip-type: %d no RT-rule added\n",
							tx_index, tx_prop->tx[tx_index].ip, iptype);
						continue;
				}

				strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';

				idx = 0;

				for (j=0; j < num_wifi_client; j++)
				{
					if(get_client_memptr(wlan_client, j)->route_rule_set_v6 == 0 ||
						get_client_memptr(wlan_client, j)->power_save_set == true)
					{
						continue;
					}

					if(false == get_client_memptr(wlan_client, j)->dscp_ipv6_hpc_set[mux_id])
					{
						memset(hdr_proc_ctx_table, 0, size);
						hdr_proc_ctx_table->commit = 1;
						hdr_proc_ctx_table->num_proc_ctxs = 1;
						hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
						hdr_proc_ctx->type = IPA_HDR_PROC_MARK_DSCP;

						if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 0)
						{
							hdr_proc_ctx->pdn_dscp_params.valid = 0;
						}
						else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 1)
						{
							hdr_proc_ctx->pdn_dscp_params.valid = 1;
							hdr_proc_ctx->pdn_dscp_params.dscp_val = dscp_val;
						}

						hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, j)->hdr_hdl_v6;
						IPACMDBG_H("hdr_proc_ctx->hdr_hdl v6 0x%x\n", hdr_proc_ctx->hdr_hdl);

						if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
							hdr_proc_ctx_table->proc_ctx[0].status != 0) {
							IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
							goto fail;
						}

						get_client_memptr(wlan_client, j)->dscp_hpc_hdr_hdl_v6[mux_id] = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
						get_client_memptr(wlan_client, j)->dscp_ipv6_hpc_set[mux_id] = true;
						IPACMDBG_H("v6 hpc header handle for mux_id %d:(0x%x)\n",
							mux_id, get_client_memptr(wlan_client, j)->dscp_hpc_hdr_hdl_v6[mux_id]);

					}

					for (auto it = rt_hdl_v6_list[j].begin(); it != rt_hdl_v6_list[j].end(); ++it)
					{
						if(it->second.route_rule_set_v6 == false ||
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id] == true)
						{
							IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d)\n",
								j, it->first[0], it->first[1], it->first[2], it->first[3],
								it->second.route_rule_set_v6);
								continue;
						}

						IPACMDBG_H("client-index(%d): v6 header handle:(0x%x), v6 addr : 0x%08x:%08x:%08x:%08x\n",
							j,
							get_client_memptr(wlan_client, j)->hdr_hdl_v6,
							it->first[0], it->first[1], it->first[2], it->first[3]);

						/* Downlink traffic from Wan iface, directly through IPA */
						rt_rule_entry = &rt_rule->rules[idx];
						rt_rule_entry->at_rear = false;
						if(IPACM_Iface::ipacmcfg->isMCC_Mode)
						{
							IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
									tx_prop->tx[tx_index].alt_dst_pipe);
							rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
						}
						else
						{
							rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
						}

						memcpy(&rt_rule_entry->rule.attrib,
							&tx_prop->tx[tx_index].attrib,
							sizeof(rt_rule_entry->rule.attrib));

						it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[mux_id] =
							get_client_memptr(wlan_client, j)->dscp_hpc_hdr_hdl_v6[mux_id];
						it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[mux_id] = true;

						if (it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[mux_id] == true)
							rt_rule_entry->rule.hdr_proc_ctx_hdl =
								it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[mux_id];
						else
							rt_rule_entry->rule.hdr_hdl = get_client_memptr(wlan_client, j)->hdr_hdl_v6;

						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_META_DATA;
						rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = it->first[0];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = it->first[1];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = it->first[2];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = it->first[3];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
						rt_rule_entry->rule.attrib.meta_data =
							mux_id << MUX_ID_DL_METADATA_SHIFT;
						rt_rule_entry->rule.attrib.meta_data_mask =
							MUX_ID_DL_METADATA_MASK << MUX_ID_DL_METADATA_SHIFT;
#ifdef FEATURE_IPA_V3
						rt_rule_entry->rule.hashable = true;
#endif
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
						if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
							if (iptype == IPA_IP_v6)
								rt_rule_entry->rule.ttl_update =
									IPACM_Wan::is_global_ipv6_addr(rt_rule_entry->rule.attrib.u.v6.dst_addr);
							else
								rt_rule_entry->rule.ttl_update = true;
						}
#endif
						idx++;
					}
				}
				if (false == m_routing.AddRoutingRule(rt_rule))
				{
					IPACMERR("Routing rule addition has failed for v6!\n");
					goto fail;
				}

				idx = 0;

				for (j=0; j < num_wifi_client; j++)
				{
					if(get_client_memptr(wlan_client, j)->route_rule_set_v6 == 0 ||
						get_client_memptr(wlan_client, j)->power_save_set == true)
					{
						continue;
					}
					for (auto it = rt_hdl_v6_list[j].begin(); it != rt_hdl_v6_list[j].end(); ++it)
					{
						if(it->second.route_rule_set_v6 == false ||
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id] == true)
						{
							continue;
						}
						it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan[mux_id] = rt_rule->rules[idx].rt_rule_hdl;
						it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id] = true;
						IPACMDBG_H("v6: tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
							it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan[mux_id], iptype);
						get_client_memptr(wlan_client, j)->dscp_ipv6_hpc_count[mux_id]++;
						idx++;
					}
				}
			}
			free(hdr_proc_ctx_table);
			free(rt_rule);
		}
	}
#ifdef FEATURE_IPA_IPSEC
	iptype_p = (ipa_ip_type *)malloc(sizeof(*iptype_p));
	if (!iptype_p) {
		IPACMERR("Failed allocating memory for IPA_IPSEC_LAN_CLIENT_ROUTE_ADD_EVENT\n");
		return IPACM_FAILURE;
	}
	*iptype_p = iptype;
	evt_data.event = IPA_IPSEC_LAN_CLIENT_ROUTE_ADD_EVENT;
	evt_data.evt_data = (void *)iptype_p;
	IPACM_EvtDispatcher::PostEvt(&evt_data);
#endif
	return IPACM_SUCCESS;
fail:
	free(hdr_proc_ctx_table);
	free(rt_rule);
	return IPACM_FAILURE;
}

/*handle wlan client routing rule based on PDN and DSCP value for
 *traffic prioritization when LAN Stats is enabled
*/
int IPACM_Wlan::handle_pdn_dscp_wlan_client_route_rule_ext_v2(uint8_t *mac_addr,
               ipa_ip_type iptype, uint32_t trigger, uint32_t* ipv6_addr, uint16_t vlan_id,
               uint8_t mux_id, uint8_t dscp_val)
{
	struct ipa_ioc_add_rt_rule_ext_v2 *rt_rule;
	struct ipa_rt_rule_add_ext_v2 rt_rule_entry;
#ifdef FEATURE_IPA_IPSEC
	ipa_ip_type *iptype_p = NULL;
	ipacm_cmd_q_data evt_data;
#endif
	uint32_t tx_index;
	int wlan_index;
	int NUM = 0;
	uint8_t valid_mux[IPA_UC_MAX_PDN_DSCP_VAL];
	struct ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table = NULL;
	struct ipa_hdr_proc_ctx_add *hdr_proc_ctx = NULL;
	int size = 0, mux_idx = 0, i = 0, j = 0, idx = 0;

	IPACMDBG_H("trigger:%d iptype:%d mux_id:%d dscp_val:%d\n", trigger, iptype, mux_id, dscp_val);

	if(trigger == 0)
	{
		if(tx_prop == NULL)
		{
			IPACMDBG_H("No tx properties registered for iface %s\n", dev_name);
			return IPACM_SUCCESS;
		}

		IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
			mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5]);

		wlan_index = get_wlan_client_index(mac_addr, vlan_id);
		if (wlan_index == IPACM_INVALID_INDEX)
		{
			IPACMDBG_H("wlan client not found/attached\n");
			return IPACM_SUCCESS;
		}

		if (get_client_memptr(wlan_client, wlan_index)->lan_stats_idx == -1)
		{
			IPACMDBG_H("Lan client index not attached.\n");
			return IPACM_SUCCESS;
		}

		if (iptype==IPA_IP_v4) {
			IPACMDBG_H("wlan client index: %d, ip-type: %d, ipv4_set:%d, ipv4_rule_set:%d \n", wlan_index, iptype,
				get_client_memptr(wlan_client, wlan_index)->ipv4_set,
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4);
		} else {
			IPACMDBG_H("wlan client index: %d, ip-type: %d, ipv6_set:%d, ipv6_rule_num:%d \n", wlan_index, iptype,
				get_client_memptr(wlan_client, wlan_index)->ipv6_set,
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6);
		}

		if (get_client_memptr(wlan_client, wlan_index)->power_save_set == true)
		{
			IPACMDBG_H("wlan client is in power safe mode\n");
			return IPACM_SUCCESS;
		}

		if (iptype == IPA_IP_v4 &&
			get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4 == false)
		{
			IPACMERR("route rule has not been set for wlan client\n");
			return IPACM_FAILURE;
		}

		if (iptype == IPA_IP_v6 &&
			get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6 == 0)
		{
			IPACMERR("v6 route rule has not been set for wlan client index:%d\n",
				wlan_index);
			return IPACM_FAILURE;
		}

		size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
		hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx *)malloc(size);
		if (hdr_proc_ctx_table == NULL) {
			IPACMERR("Failed to allocate memory for hdr_proc_ctx\n");
			return IPACM_FAILURE;
		}

		for(i=0; i<IPA_UC_MAX_PDN_DSCP_VAL; i++)
		{
			if(iptype == IPA_IP_v4 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2 &&
				get_client_memptr(wlan_client, wlan_index)->dscp_ipv4_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == false)
			{
				memset(hdr_proc_ctx_table, 0, size);
				hdr_proc_ctx_table->commit = 1;
				hdr_proc_ctx_table->num_proc_ctxs = 1;
				hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
				hdr_proc_ctx->type = IPA_HDR_PROC_MARK_DSCP;

				if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 0)
				{
					hdr_proc_ctx->pdn_dscp_params.valid = 0;
				}
				else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 1)
				{
					hdr_proc_ctx->pdn_dscp_params.valid = 1;
					hdr_proc_ctx->pdn_dscp_params.dscp_val = IPACM_Iface::ipacmcfg->pdn_dscp_table[i].dscp_val;
				}

				hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4;
				IPACMDBG_H("hdr_proc_ctx->hdr_hdl v4 0x%x\n", hdr_proc_ctx->hdr_hdl);

				if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
					hdr_proc_ctx_table->proc_ctx[0].status != 0) {
					IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
					free(hdr_proc_ctx_table);
					return IPACM_FAILURE;
				}

				get_client_memptr(wlan_client, wlan_index)->dscp_hpc_hdr_hdl_v4
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] =
						hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
				get_client_memptr(wlan_client, wlan_index)->dscp_ipv4_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] = true;
				IPACMDBG_H("v4 hpc header handle for mux_id %d:(0x%x)\n",
					IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id,
					get_client_memptr(wlan_client, wlan_index)->dscp_hpc_hdr_hdl_v4[i]);
			}

			if(iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2 &&
				get_client_memptr(wlan_client, wlan_index)->dscp_ipv6_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == false)
			{
				memset(hdr_proc_ctx_table, 0, size);
				hdr_proc_ctx_table->commit = 1;
				hdr_proc_ctx_table->num_proc_ctxs = 1;
				hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
				hdr_proc_ctx->type = IPA_HDR_PROC_MARK_DSCP;

				if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 0)
				{
					hdr_proc_ctx->pdn_dscp_params.valid = 0;
				}
				else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 1)
				{
					hdr_proc_ctx->pdn_dscp_params.valid = 1;
					hdr_proc_ctx->pdn_dscp_params.dscp_val =
						IPACM_Iface::ipacmcfg->pdn_dscp_table[i].dscp_val;
				}

				hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6;
				IPACMDBG_H("hdr_proc_ctx->hdr_hdl v6 0x%x\n", hdr_proc_ctx->hdr_hdl);
				if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
						hdr_proc_ctx_table->proc_ctx[0].status != 0) {
					IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
					free(hdr_proc_ctx_table);
					return IPACM_FAILURE;
				}

				get_client_memptr(wlan_client, wlan_index)->dscp_hpc_hdr_hdl_v6
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] =
						hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
				get_client_memptr(wlan_client, wlan_index)->dscp_ipv6_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] = true;
				IPACMDBG_H("v6 hpc header handle for mux_id %d:(0x%x)\n",
					IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id,
					get_client_memptr(wlan_client, wlan_index)->dscp_hpc_hdr_hdl_v6[i]);
			}

			if(iptype == IPA_IP_v4 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2
				&& get_client_memptr(wlan_client, wlan_index)->dscp_route_rule_set_v4
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == false &&
				get_client_memptr(wlan_client, wlan_index)->dscp_ipv4_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == true)
			{
				valid_mux[NUM++] = IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id;
			}
			else if(iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2)
			{
				for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end(); ++it)
				{
					for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
					{
						if (iptype != tx_prop->tx[tx_index].ip)
						{
							IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
								tx_index, tx_prop->tx[tx_index].ip, iptype);
							continue;
						}
						if(get_client_memptr(wlan_client, wlan_index)->dscp_ipv6_hpc_set
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == false)
						{
							continue;
						}
						if(it->first[0] == ipv6_addr[0] && it->first[1] == ipv6_addr[1] && it->first[2] == ipv6_addr[2]
							&& it->first[3] == ipv6_addr[3]
							&& it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6
								[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == false &&
							it->second.route_rule_set_v6 == true)
						{
							valid_mux[NUM++] = IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id;
						}
					}
				}
			}
		}

		if (iptype == IPA_IP_v4 && NUM >= 1)
		{
			rt_rule = (struct ipa_ioc_add_rt_rule_ext_v2 *)
				calloc(1, sizeof(struct ipa_ioc_add_rt_rule_ext_v2));

			if (rt_rule == NULL)
			{
				PERROR("Error allocating ipa_ioc_add_rt_rule memory...\n");
				free(hdr_proc_ctx_table);
				return IPACM_FAILURE;
			}

			rt_rule->rules = (uintptr_t)calloc(NUM, sizeof(struct ipa_rt_rule_add_ext_v2));
			if (!rt_rule->rules) {
				IPACMERR("Error allocating memory for routing rule\n");
				free(hdr_proc_ctx_table);
				free(rt_rule);
				return IPACM_FAILURE;
			}

			rt_rule->commit = 1;
			rt_rule->num_rules = (uint8_t)NUM;
			rt_rule->ip = iptype;
			rt_rule->rule_add_ext_size = sizeof(struct ipa_rt_rule_add_ext_v2);

			for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
				if (iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}
				if ((tx_index >= 2 && sIface && !vlan_id) ||
					tx_index < 2 && sIface && vlan_id) {
					IPACMDBG_H("Tx:%d, ip-type: %d duplicate rule ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}

				strlcpy(rt_rule->rt_tbl_name,
					IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
					sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';

				for (i = 0; i < rt_rule->num_rules; i++)
				{
					if(!valid_mux[i])
					{
						continue;
					}
					memset(&rt_rule_entry, 0, sizeof(struct ipa_rt_rule_add_ext_v2));
					rt_rule_entry.at_rear = false;
					IPACMDBG_H("client index(%d):ipv4 address: 0x%x v4 header handle:(0x%x)\n",
						wlan_index,
						get_client_memptr(wlan_client, wlan_index)->v4_addr,
						get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4);

					if(IPACM_Iface::ipacmcfg->isMCC_Mode)
					{
						IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
							tx_prop->tx[tx_index].alt_dst_pipe);
						rt_rule_entry.rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
					}
					else
					{
						rt_rule_entry.rule.dst = tx_prop->tx[tx_index].dst_pipe;
					}

					memcpy(&rt_rule_entry.rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry.rule.attrib));
					rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_META_DATA;
					if (get_client_memptr(wlan_client, wlan_index)->dscp_ipv4_hpc_set[valid_mux[i]])
						rt_rule_entry.rule.hdr_proc_ctx_hdl =
							get_client_memptr(wlan_client, wlan_index)->dscp_hpc_hdr_hdl_v4[valid_mux[i]];
					else
						rt_rule_entry.rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4;
					rt_rule_entry.rule.attrib.u.v4.dst_addr = get_client_memptr(wlan_client, wlan_index)->v4_addr;
					rt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.meta_data =
						valid_mux[i] << MUX_ID_DL_METADATA_SHIFT;
					rt_rule_entry.rule.attrib.meta_data_mask =
						MUX_ID_DL_METADATA_MASK << MUX_ID_DL_METADATA_SHIFT;
					rt_rule_entry.rule.enable_stats = true;
					rt_rule_entry.rule.cnt_idx = get_client_memptr(wlan_client, wlan_index)->dl_cnt_idx;
					rt_rule_entry.rule_id = 0;
					if (IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
					{
						rt_rule_entry.rule.hashable = true;
					}
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
					if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
						if (iptype == IPA_IP_v6)
							rt_rule_entry.rule.ttl_update =
								IPACM_Wan::is_global_ipv6_addr(rt_rule_entry.rule.attrib.u.v6.dst_addr);
						else
							rt_rule_entry.rule.ttl_update = true;
					}
#endif

					memcpy((void *)rt_rule->rules + (i * sizeof(struct ipa_rt_rule_add_ext_v2)),
						&rt_rule_entry, sizeof(ipa_rt_rule_add_ext_v2));
				}
				if (false == m_routing.AddRoutingRuleExt_v2(rt_rule))
				{
					IPACMERR("Routing rule addition has failed for v4!\n");
					goto fail;
				}

				/* copy ipv4 RT hdl */
				for(j=0; j<rt_rule->num_rules; j++)
				{
					get_client_memptr(wlan_client, wlan_index)->dscp_wifi_rt_hdl[valid_mux[j]].wifi_rt_rule_hdl_v4 =
						((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[j].rt_rule_hdl;
					IPACMDBG_H("v4: tx:%d, rt_rule_hdl=%x ip-type:%d\n", tx_index,
						get_client_memptr(wlan_client, wlan_index)->dscp_wifi_rt_hdl[valid_mux[j]].wifi_rt_rule_hdl_v4,
						iptype);
					get_client_memptr(wlan_client, wlan_index)->dscp_route_rule_set_v4[valid_mux[j]] = true;
					get_client_memptr(wlan_client, wlan_index)->dscp_ipv4_hpc_count[valid_mux[j]]++;
				}
			}
			free(hdr_proc_ctx_table);
			free((void *)rt_rule->rules);
			free(rt_rule);
		}
		else if (iptype == IPA_IP_v6 && NUM >= 1)
		{
			rt_rule = (struct ipa_ioc_add_rt_rule_ext_v2 *)
				calloc(1, sizeof(struct ipa_ioc_add_rt_rule_ext_v2) +
				NUM  *
				sizeof(struct ipa_rt_rule_add_ext_v2));

			if (rt_rule == NULL)
			{
				PERROR("Error allocating ipa_ioc_add_rt_rule memory...\n");
				free(hdr_proc_ctx_table);
				return IPACM_FAILURE;
			}

			rt_rule->rules = (uintptr_t)calloc(NUM, sizeof(struct ipa_rt_rule_add_ext_v2));
			if (!rt_rule->rules) {
				IPACMERR("Error allocating memory for routing rule\n");
				free(hdr_proc_ctx_table);
				free(rt_rule);
				return IPACM_FAILURE;
			}

			rt_rule->commit = 1;
			rt_rule->num_rules = (uint8_t)(NUM);
			rt_rule->ip = iptype;
			rt_rule->rule_add_ext_size = sizeof(struct ipa_rt_rule_add_ext_v2);

			for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
				if (iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}
				if ((tx_index >= 2 && sIface && !vlan_id) ||
					tx_index < 2 && sIface && vlan_id) {
						IPACMDBG_H("Tx:%d, ip-type: %d duplicate rule ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
						continue;
				}

				strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';

				for (i = 0; i < NUM; i++)
				{
					if(!valid_mux[i])
					{
						continue;
					}
					for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end(); ++it)
					{
						if(it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[valid_mux[i]] == true)
						{
							IPACMERR("dscp v6 route rule has been set for wlan client already\n");
							IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d)\n",
								wlan_index, it->first[0], it->first[1], it->first[2], it->first[3],
								it->second.route_rule_set_v6);
							continue;
						}

						if(it->first[0] == ipv6_addr[0] && it->first[1] == ipv6_addr[1] && it->first[2] == ipv6_addr[2]
							&& it->first[3] == ipv6_addr[3] && it->second.route_rule_set_v6 == true)
						{
							IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d)\n",
								wlan_index, it->first[0], it->first[1], it->first[2], it->first[3],
								it->second.route_rule_set_v6);
							IPACMDBG_H("client-index(%d): v6 header handle:(0x%x)\n",
								wlan_index,
								get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6);

							/* Downlink traffic from Wan iface, directly through IPA */
							memset(&rt_rule_entry, 0, sizeof(struct ipa_rt_rule_add_ext_v2));
							rt_rule_entry.at_rear = false;
							if(IPACM_Iface::ipacmcfg->isMCC_Mode)
							{
								IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
									tx_prop->tx[tx_index].alt_dst_pipe);
								rt_rule_entry.rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
							}
							else
							{
								rt_rule_entry.rule.dst = tx_prop->tx[tx_index].dst_pipe;
							}
							memcpy(&rt_rule_entry.rule.attrib,
								&tx_prop->tx[tx_index].attrib,
								sizeof(rt_rule_entry.rule.attrib));
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[valid_mux[i]] =
								get_client_memptr(wlan_client, wlan_index)->dscp_hpc_hdr_hdl_v6[valid_mux[i]];
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[valid_mux[i]] = true;

							if (it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[valid_mux[i]])
								rt_rule_entry.rule.hdr_proc_ctx_hdl =
									it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[valid_mux[i]];
							else
								rt_rule_entry.rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6;

							rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
							rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_META_DATA;
							rt_rule_entry.rule.attrib.u.v6.dst_addr[0] = it->first[0];
							rt_rule_entry.rule.attrib.u.v6.dst_addr[1] = it->first[1];
							rt_rule_entry.rule.attrib.u.v6.dst_addr[2] = it->first[2];
							rt_rule_entry.rule.attrib.u.v6.dst_addr[3] = it->first[3];
							rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
							rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
							rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
							rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
							rt_rule_entry.rule.attrib.meta_data =
								valid_mux[i] << MUX_ID_DL_METADATA_SHIFT;
							rt_rule_entry.rule.attrib.meta_data_mask =
								MUX_ID_DL_METADATA_MASK << MUX_ID_DL_METADATA_SHIFT;
							rt_rule_entry.rule.enable_stats = true;
							rt_rule_entry.rule.cnt_idx = get_client_memptr(wlan_client, wlan_index)->dl_cnt_idx;
							rt_rule_entry.rule_id = 0;
#ifdef FEATURE_IPA_V3
							rt_rule_entry.rule.hashable = true;
#endif
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
							if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
								if (iptype == IPA_IP_v6)
									rt_rule_entry.rule.ttl_update =
									IPACM_Wan::is_global_ipv6_addr(rt_rule_entry.rule.attrib.u.v6.dst_addr);
								else
									rt_rule_entry.rule.ttl_update = true;
								}
#endif
							memcpy((void *)rt_rule->rules + (i * sizeof(struct ipa_rt_rule_add_ext_v2)),
								&rt_rule_entry, sizeof(ipa_rt_rule_add_ext_v2));
						}
					}
				}
				if (false == m_routing.AddRoutingRuleExt_v2(rt_rule))
				{
					IPACMERR("Routing rule addition has failed for v6!\n");
					goto fail;
				}

				for (i = 0; i < NUM; i++)
				{
					for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end(); ++it)
					{
						if(it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[valid_mux[i]] == true)
						{
							IPACMERR("dscp v6 route rule has been set for wlan client already\n");
							continue;
						}

						if(it->first[0] == ipv6_addr[0] && it->first[1] == ipv6_addr[1] && it->first[2] == ipv6_addr[2]
							&& it->first[3] == ipv6_addr[3] && it->second.route_rule_set_v6 == true)
						{
							it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan[valid_mux[i]] =
								((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[i].rt_rule_hdl;
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[valid_mux[i]] = true;
							IPACMDBG_H("v6: tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
								it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan[valid_mux[i]], iptype);
							get_client_memptr(wlan_client, wlan_index)->dscp_ipv6_hpc_count[valid_mux[i]]++;
						}
					}
				}
			}
			free(hdr_proc_ctx_table);
			free((void *)rt_rule->rules);
			free(rt_rule);
		}
	}
	else if(trigger == 1)
	{
		if(iptype == IPA_IP_v4)
		{
			size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
			hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx *)malloc(size);
			if (hdr_proc_ctx_table == NULL) {
				IPACMERR("Failed to allocate memory for hdrproc_ctx\n");
				free(hdr_proc_ctx_table);
				return IPACM_FAILURE;
			}

			NUM = 0;

			for (i = 0; i < num_wifi_client; i++)
			{
				if(get_client_memptr(wlan_client, i)->route_rule_set_v4 == false ||
					get_client_memptr(wlan_client, i)->power_save_set == true ||
					get_client_memptr(wlan_client, i)->dscp_route_rule_set_v4[mux_id] == true ||
					get_client_memptr(wlan_client, i)->lan_stats_idx == -1)
				{
					continue;
				}

				if(false == get_client_memptr(wlan_client, i)->dscp_ipv4_hpc_set[mux_id])
				{
					memset(hdr_proc_ctx_table, 0, size);
					hdr_proc_ctx_table->commit = 1;
					hdr_proc_ctx_table->num_proc_ctxs = 1;
					hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
					hdr_proc_ctx->type = IPA_HDR_PROC_MARK_DSCP;

					if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 0)
					{
						hdr_proc_ctx->pdn_dscp_params.valid = 0;
					}
					else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 1)
					{
						hdr_proc_ctx->pdn_dscp_params.valid = 1;
						hdr_proc_ctx->pdn_dscp_params.dscp_val = dscp_val;
					}

					hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, i)->hdr_hdl_v4;
					IPACMDBG_H("hdr_proc_ctx->hdr_hdl v4 0x%x\n", hdr_proc_ctx->hdr_hdl);

					if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
						hdr_proc_ctx_table->proc_ctx[0].status != 0) {
						IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n",
							hdr_proc_ctx_table->proc_ctx[0].status);
						free(hdr_proc_ctx_table);
						return IPACM_FAILURE;
					}

					get_client_memptr(wlan_client, i)->dscp_hpc_hdr_hdl_v4[mux_id] =
						hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
					get_client_memptr(wlan_client, i)->dscp_ipv4_hpc_set[mux_id] = true;
					IPACMDBG_H("v4 hpc header handle for mux_id %d:(0x%x)\n",
						i, get_client_memptr(wlan_client, i)->dscp_hpc_hdr_hdl_v4[mux_id]);
				}
				NUM++;
			}

			if(NUM <= 0)
			{
				free(hdr_proc_ctx_table);
				return IPACM_FAILURE;
			}

			rt_rule = (struct ipa_ioc_add_rt_rule_ext_v2 *)
				calloc(1, sizeof(struct ipa_ioc_add_rt_rule_ext_v2));

			if (rt_rule == NULL)
			{
				PERROR("Error allocating ipa_ioc_add_rt_rule memory...\n");
				free(hdr_proc_ctx_table);
				return IPACM_FAILURE;
			}

			rt_rule->rules = (uintptr_t)calloc(NUM, sizeof(struct ipa_rt_rule_add_ext_v2));
			if (!rt_rule->rules) {
				IPACMERR("Error allocating memory for routing rule\n");
				free(hdr_proc_ctx_table);
				free(rt_rule);
				return IPACM_FAILURE;
			}

			rt_rule->commit = 1;
			rt_rule->ip = IPA_IP_v4;
			rt_rule->num_rules = (uint8_t)NUM;
			rt_rule->rule_add_ext_size = sizeof(struct ipa_rt_rule_add_ext_v2);

			for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
				if (iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}
				if ((tx_index >= 2 && sIface && !vlan_id) ||
					tx_index < 2 && sIface && vlan_id) {
					IPACMDBG_H("Tx:%d, ip-type: %d duplicate rule ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}

				strlcpy(rt_rule->rt_tbl_name,
				IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
					sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';

				for (i = 0; i < num_wifi_client; i++)
				{
					if(get_client_memptr(wlan_client, i)->route_rule_set_v4 == false ||
						get_client_memptr(wlan_client, i)->power_save_set == true ||
						get_client_memptr(wlan_client, i)->lan_stats_idx == -1 ||
						get_client_memptr(wlan_client, i)->dscp_route_rule_set_v4[mux_id] == true)
					{
						continue;
					}
					memset(&rt_rule_entry, 0, sizeof(struct ipa_rt_rule_add_ext_v2));
					rt_rule_entry.at_rear = false;
					IPACMDBG_H("client index(%d):ipv4 address: 0x%x v4 header handle:(0x%x)\n",
						i,
						get_client_memptr(wlan_client, i)->v4_addr,
						get_client_memptr(wlan_client, i)->hdr_hdl_v4);
					if(IPACM_Iface::ipacmcfg->isMCC_Mode)
					{
						IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
								tx_prop->tx[tx_index].alt_dst_pipe);
						rt_rule_entry.rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
					}
					else
					{
						rt_rule_entry.rule.dst = tx_prop->tx[tx_index].dst_pipe;
					}

					memcpy(&rt_rule_entry.rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry.rule.attrib));
					rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_META_DATA;
					if (get_client_memptr(wlan_client, i)->dscp_ipv4_hpc_set[mux_id])
						rt_rule_entry.rule.hdr_proc_ctx_hdl =
							get_client_memptr(wlan_client, i)->dscp_hpc_hdr_hdl_v4[mux_id];
					else
						rt_rule_entry.rule.hdr_hdl = get_client_memptr(wlan_client, i)->hdr_hdl_v4;

					rt_rule_entry.rule.attrib.u.v4.dst_addr = get_client_memptr(wlan_client, i)->v4_addr;
					rt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.meta_data =
						mux_id << MUX_ID_DL_METADATA_SHIFT;
					rt_rule_entry.rule.attrib.meta_data_mask =
						MUX_ID_DL_METADATA_MASK << MUX_ID_DL_METADATA_SHIFT;
					rt_rule_entry.rule.enable_stats = true;
					rt_rule_entry.rule.cnt_idx = get_client_memptr(wlan_client, i)->dl_cnt_idx;
					rt_rule_entry.rule_id = 0;
					if (IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
					{
						rt_rule_entry.rule.hashable = true;
					}
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
					if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
						if (iptype == IPA_IP_v6)
							rt_rule_entry.rule.ttl_update =
								IPACM_Wan::is_global_ipv6_addr(rt_rule_entry.rule.attrib.u.v6.dst_addr);
						else
							rt_rule_entry.rule.ttl_update = true;
					}
#endif
					memcpy((void *)rt_rule->rules + (i * sizeof(struct ipa_rt_rule_add_ext_v2)),
						&rt_rule_entry, sizeof(ipa_rt_rule_add_ext_v2));
				}

				if (false == m_routing.AddRoutingRuleExt_v2(rt_rule))
				{
					IPACMERR("Routing rule addition has failed for v4!\n");
					goto fail;
				}

				idx = 0;
				for (j=0; j < num_wifi_client; j++)
				{
					if(get_client_memptr(wlan_client, j)->route_rule_set_v4 == false ||
						get_client_memptr(wlan_client, j)->power_save_set == true ||
						get_client_memptr(wlan_client, j)->lan_stats_idx == -1 ||
						get_client_memptr(wlan_client, j)->dscp_route_rule_set_v4[mux_id] == true)
					{
						continue;
					}
					get_client_memptr(wlan_client, j)->dscp_wifi_rt_hdl[mux_id].wifi_rt_rule_hdl_v4 =
						((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[j].rt_rule_hdl;
					get_client_memptr(wlan_client, j)->dscp_route_rule_set_v4[mux_id] = true;
					IPACMDBG_H("v4: tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
					get_client_memptr(wlan_client, j)->dscp_wifi_rt_hdl[mux_id].wifi_rt_rule_hdl_v4, iptype);
					get_client_memptr(wlan_client, j)->dscp_ipv4_hpc_count[mux_id]++;
					idx++;
				}
			}
			free(hdr_proc_ctx_table);
			free((void *)rt_rule->rules);
			free(rt_rule);
		}
		else if (iptype == IPA_IP_v6)
		{
			NUM = 0;
			for (j=0; j < num_wifi_client; j++)
			{
				if(get_client_memptr(wlan_client, j)->route_rule_set_v6 == 0 ||
					get_client_memptr(wlan_client, j)->power_save_set == true ||
					get_client_memptr(wlan_client, j)->lan_stats_idx == -1)
				{
					continue;
				}
				for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
				{
					if (iptype != tx_prop->tx[tx_index].ip)
					{
						IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
							tx_index, tx_prop->tx[tx_index].ip, iptype);
						continue;
					}
					for (auto it = rt_hdl_v6_list[j].begin(); it != rt_hdl_v6_list[j].end(); ++it)
					{
						IPACMDBG_H("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d) dscp:%d\n",
							j, it->first[0], it->first[1], it->first[2], it->first[3],
							it->second.route_rule_set_v6, it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id]);
						if (it->second.route_rule_set_v6 == false ||
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id] == true)
						{
							continue;
						}
						IPACMDBG_H("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d) dscp:%d\n",
							j, it->first[0], it->first[1], it->first[2], it->first[3],
							it->second.route_rule_set_v6, it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id]);

						NUM++;
					}
				}
			}

			if(NUM <= 0)
			{
				return IPACM_FAILURE;
			}

			size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
			hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx *)malloc(size);
			if (hdr_proc_ctx_table == NULL) {
				IPACMERR("Failed to allocate memory for hdr_proc_ctx.\n");
				return IPACM_FAILURE;
			}

			rt_rule = (struct ipa_ioc_add_rt_rule_ext_v2 *)
				calloc(1, sizeof(struct ipa_ioc_add_rt_rule_ext_v2));

			if (rt_rule == NULL)
			{
				PERROR("Error allocating ipa_ioc_add_rt_rule memory.\n");
				free(hdr_proc_ctx_table);
				return IPACM_FAILURE;
			}

			rt_rule->rules = (uintptr_t)calloc(NUM, sizeof(struct ipa_rt_rule_add_ext_v2));
			if (!rt_rule->rules) {
				IPACMERR("Error allocating memory for routing rule\n");
				free(hdr_proc_ctx_table);
				free(rt_rule);
				return IPACM_FAILURE;
			}

			rt_rule->commit = 1;
			rt_rule->num_rules = (uint8_t)(NUM);
			rt_rule->ip = iptype;
			rt_rule->rule_add_ext_size = sizeof(struct ipa_rt_rule_add_ext_v2);

			for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
				if (iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}
				if ((tx_index >= 2 && sIface && !vlan_id) ||
					tx_index < 2 && sIface && vlan_id) {
						IPACMDBG_H("Tx:%d, ip-type: %d duplicate rule ip-type: %d no RT-rule added\n",
							tx_index, tx_prop->tx[tx_index].ip, iptype);
						continue;
				}

				strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';

				idx = 0;

				for (j=0; j < num_wifi_client; j++)
				{
					if(get_client_memptr(wlan_client, j)->route_rule_set_v6 == 0 ||
						get_client_memptr(wlan_client, j)->power_save_set == true ||
						get_client_memptr(wlan_client, j)->lan_stats_idx == -1)
					{
						continue;
					}

					if(false == get_client_memptr(wlan_client, j)->dscp_ipv6_hpc_set[mux_id])
					{
						memset(hdr_proc_ctx_table, 0, size);
						hdr_proc_ctx_table->commit = 1;
						hdr_proc_ctx_table->num_proc_ctxs = 1;
						hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
						hdr_proc_ctx->type = IPA_HDR_PROC_MARK_DSCP;

						if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 0)
						{
							hdr_proc_ctx->pdn_dscp_params.valid = 0;
						}
						else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_dscp_mark_mode == 1)
						{
							hdr_proc_ctx->pdn_dscp_params.valid = 1;
							hdr_proc_ctx->pdn_dscp_params.dscp_val = dscp_val;
						}

						hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, j)->hdr_hdl_v6;
						IPACMDBG_H("hdr_proc_ctx->hdr_hdl v6 0x%x\n", hdr_proc_ctx->hdr_hdl);

						if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
							hdr_proc_ctx_table->proc_ctx[0].status != 0) {
							IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n",
								hdr_proc_ctx_table->proc_ctx[0].status);
							goto fail;
						}

						get_client_memptr(wlan_client, j)->dscp_hpc_hdr_hdl_v6[mux_id] =
							hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
						get_client_memptr(wlan_client, j)->dscp_ipv6_hpc_set[mux_id] = true;
						IPACMDBG_H("v6 hpc header handle for mux_id %d:(0x%x)\n",
							mux_id, get_client_memptr(wlan_client, j)->dscp_hpc_hdr_hdl_v6[mux_id]);

					}

					for (auto it = rt_hdl_v6_list[j].begin(); it != rt_hdl_v6_list[j].end(); ++it)
					{
						if(it->second.route_rule_set_v6 == false ||
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id] == true)
						{
							IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d)\n",
								j, it->first[0], it->first[1], it->first[2], it->first[3],
								it->second.route_rule_set_v6);
								continue;
						}

						IPACMDBG_H("client-index(%d): v6 header handle:(0x%x), v6 addr : 0x%08x:%08x:%08x:%08x\n",
							j,
							get_client_memptr(wlan_client, j)->hdr_hdl_v6,
							it->first[0], it->first[1], it->first[2], it->first[3]);

						/* Downlink traffic from Wan iface, directly through IPA */
						memset(&rt_rule_entry, 0, sizeof(struct ipa_rt_rule_add_ext_v2));
						rt_rule_entry.at_rear = false;
						if(IPACM_Iface::ipacmcfg->isMCC_Mode)
						{
							IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
									tx_prop->tx[tx_index].alt_dst_pipe);
							rt_rule_entry.rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
						}
						else
						{
							rt_rule_entry.rule.dst = tx_prop->tx[tx_index].dst_pipe;
						}

						memcpy(&rt_rule_entry.rule.attrib,
							&tx_prop->tx[tx_index].attrib,
							sizeof(rt_rule_entry.rule.attrib));

						it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[mux_id] =
							get_client_memptr(wlan_client, j)->dscp_hpc_hdr_hdl_v6[mux_id];
						it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[mux_id] = true;

						if (it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[mux_id] == true)
							rt_rule_entry.rule.hdr_proc_ctx_hdl =
								it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[mux_id];
						else
							rt_rule_entry.rule.hdr_hdl = get_client_memptr(wlan_client, j)->hdr_hdl_v6;

						rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
						rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_META_DATA;
						rt_rule_entry.rule.attrib.u.v6.dst_addr[0] = it->first[0];
						rt_rule_entry.rule.attrib.u.v6.dst_addr[1] = it->first[1];
						rt_rule_entry.rule.attrib.u.v6.dst_addr[2] = it->first[2];
						rt_rule_entry.rule.attrib.u.v6.dst_addr[3] = it->first[3];
						rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
						rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
						rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
						rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
						rt_rule_entry.rule.attrib.meta_data =
							mux_id << MUX_ID_DL_METADATA_SHIFT;
						rt_rule_entry.rule.attrib.meta_data_mask =
							MUX_ID_DL_METADATA_MASK << MUX_ID_DL_METADATA_SHIFT;
						rt_rule_entry.rule.enable_stats = true;
						rt_rule_entry.rule.cnt_idx = get_client_memptr(wlan_client, j)->dl_cnt_idx;
						rt_rule_entry.rule_id = 0;
#ifdef FEATURE_IPA_V3
						rt_rule_entry.rule.hashable = true;
#endif
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
						if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
							if (iptype == IPA_IP_v6)
								rt_rule_entry.rule.ttl_update =
									IPACM_Wan::is_global_ipv6_addr(rt_rule_entry.rule.attrib.u.v6.dst_addr);
							else
								rt_rule_entry.rule.ttl_update = true;
						}
#endif
						memcpy((void *)rt_rule->rules + (idx * sizeof(struct ipa_rt_rule_add_ext_v2)),
												&rt_rule_entry, sizeof(ipa_rt_rule_add_ext_v2));
						idx++;
					}
				}
				if (false == m_routing.AddRoutingRuleExt_v2(rt_rule))
				{
					IPACMERR("Routing rule addition has failed for v6!\n");
					goto fail;
				}

				idx = 0;

				for (j=0; j < num_wifi_client; j++)
				{
					if(get_client_memptr(wlan_client, j)->route_rule_set_v6 == 0 ||
						get_client_memptr(wlan_client, j)->power_save_set == true ||
						get_client_memptr(wlan_client, j)->lan_stats_idx == -1)
					{
						continue;
					}
					for (auto it = rt_hdl_v6_list[j].begin(); it != rt_hdl_v6_list[j].end(); ++it)
					{
						if(it->second.route_rule_set_v6 == false ||
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id] == true)
						{
							continue;
						}
						it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan[mux_id] =
							((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[idx].rt_rule_hdl;
						it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id] = true;
						IPACMDBG_H("v6: tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
							it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan[mux_id], iptype);
						get_client_memptr(wlan_client, j)->dscp_ipv6_hpc_count[mux_id]++;
						idx++;
					}
				}
			}
			free(hdr_proc_ctx_table);
			free((void *)rt_rule->rules);
			free(rt_rule);
		}
	}
#ifdef FEATURE_IPA_IPSEC
	iptype_p = (ipa_ip_type *)malloc(sizeof(*iptype_p));
	if (!iptype_p) {
		IPACMERR("Failed allocating memory for IPA_IPSEC_LAN_CLIENT_ROUTE_ADD_EVENT\n");
		return IPACM_FAILURE;
	}
	*iptype_p = iptype;
	evt_data.event = IPA_IPSEC_LAN_CLIENT_ROUTE_ADD_EVENT;
	evt_data.evt_data = (void *)iptype_p;
	IPACM_EvtDispatcher::PostEvt(&evt_data);
#endif
	return IPACM_SUCCESS;
fail:
	free(hdr_proc_ctx_table);
	free((void *)rt_rule->rules);
	free(rt_rule);
	return IPACM_FAILURE;
}

int IPACM_Wlan::delete_pdn_dscp_wlan_rtrules(ipa_ip_type iptype, uint32_t trigger, int clnt_idx, int mux_id)
{
	uint32_t tx_index;
	uint32_t rt_hdl;
	int num_v6 = 0, i = 0, j = 0;

	IPACMDBG_H("iptype:%d trigger:%d clnt_idx:%d mux_id:%d\n", iptype, trigger, clnt_idx, mux_id);

	if(trigger == 1)
	{
		if(iptype == IPA_IP_v4)
		{
			for (i = 0; i < num_wifi_client; i++)
			{
				for(tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
				{
					if((tx_prop->tx[tx_index].ip == IPA_IP_v4) &&
						(get_client_memptr(wlan_client, i)->dscp_route_rule_set_v4[mux_id]==true))
					{
						IPACMDBG_H("Delete client index %d ipv4 RT-rules for tx:%d\n", i, tx_index);

						rt_hdl = get_client_memptr(wlan_client, i)->dscp_wifi_rt_hdl[mux_id].wifi_rt_rule_hdl_v4;
						if(m_routing.DeleteRoutingHdl(rt_hdl, IPA_IP_v4) == false)
						{
							return IPACM_FAILURE;
						}
						get_client_memptr(wlan_client, i)->dscp_wifi_rt_hdl[mux_id].wifi_rt_rule_hdl_v4 = 0;
						get_client_memptr(wlan_client, i)->dscp_route_rule_set_v4[mux_id] = false;
						get_client_memptr(wlan_client, i)->dscp_ipv4_hpc_count[mux_id]--;
					}
					if(get_client_memptr(wlan_client, i)->dscp_ipv4_hpc_count[mux_id] == 0 &&
						get_client_memptr(wlan_client, i)->dscp_ipv4_hpc_set[mux_id] == true)
					{
						IPACMDBG_H("v4 proc_ctx handle passed:(0x%x)\n",
							get_client_memptr(wlan_client, i)->dscp_hpc_hdr_hdl_v4[mux_id]);

						if(m_header.DeleteHeaderProcCtx(get_client_memptr(wlan_client, i)->dscp_hpc_hdr_hdl_v4[mux_id]) == false)
						{
							IPACMERR("Failed to delete PDN<->DSCP hdr_proc_ctx for v4\n");
							return IPACM_FAILURE;
						}
						get_client_memptr(wlan_client, i)->dscp_hpc_hdr_hdl_v4[mux_id] = 0;
						get_client_memptr(wlan_client, i)->dscp_ipv4_hpc_set[mux_id] = false;
					}
				}
			}
		}
		if(iptype == IPA_IP_v6)
		{
			for (i = 0; i < num_wifi_client; i++)
			{
				for(tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
				{
					for (auto it = rt_hdl_v6_list[i].begin(); it != rt_hdl_v6_list[i].end(); ++it)
					{
						if((tx_prop->tx[tx_index].ip == IPA_IP_v6) &&
							(it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id] == true))
						{
							IPACMDBG_H("Delete client index %d ipv6 RT-rules for tx:%d\n",i,tx_index);

							rt_hdl = it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan[mux_id];
							if(m_routing.DeleteRoutingHdl(rt_hdl, IPA_IP_v6) == false)
							{
								IPACMERR("Failed to delete v6 routing rule for v6.\n");
								return IPACM_FAILURE;
							}
							it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan[mux_id] = 0;
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id] = false;
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[mux_id] = 0;
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[mux_id] = false;
							get_client_memptr(wlan_client, i)->dscp_ipv6_hpc_count[mux_id]--;
						}
					}
					if(get_client_memptr(wlan_client, i)->dscp_ipv6_hpc_count[mux_id] == 0 &&
						get_client_memptr(wlan_client, i)->dscp_ipv6_hpc_set[mux_id] == true)
					{
						IPACMDBG_H("v6 proc_ctx handle passed:(0x%x)\n",
							get_client_memptr(wlan_client, i)->dscp_hpc_hdr_hdl_v6[mux_id]);

						if(m_header.DeleteHeaderProcCtx(get_client_memptr(wlan_client, i)->dscp_hpc_hdr_hdl_v6[mux_id]) == false)
						{
							IPACMERR("Failed to delete PDN<->DSCP hdr_proc_ctx for v6\n");
							return IPACM_FAILURE;
						}
						get_client_memptr(wlan_client, i)->dscp_hpc_hdr_hdl_v6[mux_id] = 0;
						get_client_memptr(wlan_client, i)->dscp_ipv6_hpc_set[mux_id] = false;
					}
				}

			}
		}
	}
	else if(trigger == 2)
	{
		if(iptype == IPA_IP_v4)
		{
			for(j = 0; j <  IPA_UC_MAX_PDN_DSCP_VAL; j++)
			{
				for(tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
				{
					if((tx_prop->tx[tx_index].ip == IPA_IP_v4) &&
						(get_client_memptr(wlan_client, clnt_idx)->dscp_route_rule_set_v4
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] == true))
					{
						IPACMDBG_H("Delete client index %d ipv4 RT-rules for tx:%d\n",  clnt_idx, tx_index);

						rt_hdl = get_client_memptr(wlan_client, clnt_idx)->dscp_wifi_rt_hdl
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id].wifi_rt_rule_hdl_v4;
						if(m_routing.DeleteRoutingHdl(rt_hdl, IPA_IP_v4) == false)
						{
							return IPACM_FAILURE;
						}
						get_client_memptr(wlan_client, clnt_idx)->dscp_wifi_rt_hdl
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id].wifi_rt_rule_hdl_v4 = 0;
						get_client_memptr(wlan_client, clnt_idx)->dscp_route_rule_set_v4
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] = false;
						get_client_memptr(wlan_client, clnt_idx)->dscp_ipv4_hpc_count
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id]--;
					}
				}
				if(get_client_memptr(wlan_client, clnt_idx)->dscp_ipv4_hpc_count
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] == 0 &&
					get_client_memptr(wlan_client, clnt_idx)->dscp_ipv4_hpc_set
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] == true)
				{
					IPACMDBG_H("v4 proc_ctx handle passed:(0x%x)\n",
						get_client_memptr(wlan_client, clnt_idx)->dscp_hpc_hdr_hdl_v4
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id]);

					if(m_header.DeleteHeaderProcCtx(get_client_memptr(wlan_client, clnt_idx)->dscp_hpc_hdr_hdl_v4
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id]) == false)
					{
						IPACMERR("Failed to delete PDN<->DSCP hdr_proc_ctx for v4\n");
						return IPACM_FAILURE;
					}
					get_client_memptr(wlan_client, clnt_idx)->dscp_hpc_hdr_hdl_v4
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] = 0;
					get_client_memptr(wlan_client, clnt_idx)->dscp_ipv4_hpc_set
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] = false;
				}
			}
		}
		else if(iptype == IPA_IP_v6)
		{
			for(j = 0; j < IPA_UC_MAX_PDN_DSCP_VAL; j++)
			{
				for(tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
				{
					for (auto it = rt_hdl_v6_list[clnt_idx].begin(); it != rt_hdl_v6_list[clnt_idx].end(); ++it)
					{
						if((tx_prop->tx[tx_index].ip == IPA_IP_v6) &&
							(it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6
								[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] == true))
						{
							IPACMDBG_H("Delete client index %d ipv6 RT-rules for tx:%d\n", clnt_idx,  tx_index);

							rt_hdl = it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan
								[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id];
							if(m_routing.DeleteRoutingHdl(rt_hdl, IPA_IP_v6) == false)
							{
								IPACMERR("Failed to delete v6 routing rule for v6.\n");
								return IPACM_FAILURE;
							}
							it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan
								[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] = 0;
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6
								[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] = false;
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6
								[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] = 0;
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set
								[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] = false;
							get_client_memptr(wlan_client, clnt_idx)->dscp_ipv6_hpc_count
								[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id]--;
						}
					}
				}
				if(get_client_memptr(wlan_client, clnt_idx)->dscp_ipv6_hpc_count
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] == 0 &&
					get_client_memptr(wlan_client, clnt_idx)->dscp_ipv6_hpc_set
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] == true)
				{
					IPACMDBG_H("v6 proc_ctx handle passed:(0x%x)\n",
						get_client_memptr(wlan_client, clnt_idx)->dscp_hpc_hdr_hdl_v6
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id]);

					if(m_header.DeleteHeaderProcCtx(get_client_memptr(wlan_client, clnt_idx)->dscp_hpc_hdr_hdl_v6
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id]) == false)
					{
						IPACMERR("Failed to delete PDN<->DSCP hdr_proc_ctx for v6\n");
						return IPACM_FAILURE;
					}
					get_client_memptr(wlan_client, clnt_idx)->dscp_hpc_hdr_hdl_v6
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] = 0;
					get_client_memptr(wlan_client, clnt_idx)->dscp_ipv6_hpc_set
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] = false;
				}
			}
		}
	}
	return IPACM_SUCCESS;
}
#endif

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
int IPACM_Wlan::handle_lan_client_connect(uint8_t *mac_addr)
{
	int wlan_index, res = IPACM_SUCCESS;
	ipacm_ext_prop* ext_prop;
	struct wan_ioctl_lan_client_info *client_info;
#ifdef FEATURE_STATIC_POLICY
	uint32_t temp_ipv6[4] = {0};
#endif
#ifdef IPA_HW_FNR_STATS
	uint8_t cnt_idx;
#endif //IPA_HW_FNR_STATS

	IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
			mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5]);

	wlan_index = get_wlan_client_index(mac_addr);
	if (wlan_index == IPACM_INVALID_INDEX)
	{
		IPACMDBG_H("wlan client not found/attached \n");
		return IPACM_SUCCESS;
	}

	if (get_client_memptr(wlan_client, wlan_index)->lan_stats_idx != -1)
	{
		IPACMDBG_H("wlan client already has lan_stats index. \n");
		return IPACM_FAILURE;
	}

	get_client_memptr(wlan_client, wlan_index)->lan_stats_idx = get_lan_stats_index(mac_addr);

	if (get_client_memptr(wlan_client, wlan_index)->lan_stats_idx == -1)
	{
		IPACMDBG_H("No active index..abort \n");
		return IPACM_FAILURE;
	}

	if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == true)
	{
		client_info = (struct wan_ioctl_lan_client_info *)malloc(sizeof(struct wan_ioctl_lan_client_info));
		if (client_info == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		memset(client_info, 0, sizeof(struct wan_ioctl_lan_client_info));
		client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_WLAN;
		memcpy(client_info->mac,
				get_client_memptr(wlan_client, wlan_index)->mac,
				IPA_MAC_ADDR_SIZE);
		client_info->client_init = 1;
		client_info->client_idx = get_client_memptr(wlan_client, wlan_index)->lan_stats_idx;
		client_info->ul_src_pipe = (enum ipa_client_type) IPA_CLIENT_MAX;
		client_info->hdr_len = hdr_len;
#ifdef IPA_HW_FNR_STATS
		IPACMERR("Client counter index (%d) ul/ul = (%d/%d) dl/dl = (%d/%d)\n",
			get_client_memptr(wlan_client, wlan_index)->index_populated,
			client_info->ul_cnt_idx,
			get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx,
			client_info->dl_cnt_idx,
			get_client_memptr(wlan_client, wlan_index)->dl_cnt_idx);
		if (IPACM_Wan::ipacmcfg->hw_fnr_stats_support && !get_client_memptr(wlan_client, wlan_index)->index_populated) {
			pthread_mutex_lock(&IPACM_Wan::ipacmcfg->cnt_idx_lock);
			cnt_idx = IPACM_Wan::ipacmcfg->get_free_cnt_idx();
			pthread_mutex_unlock(&IPACM_Wan::ipacmcfg->cnt_idx_lock);
			if (cnt_idx == -1)
			{
				IPACMERR("Got invalid cnt_idx. Abort\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			client_info->ul_cnt_idx = cnt_idx;
			client_info->dl_cnt_idx = cnt_idx + 1;
			/* maintain a copy of this in IPACM_Config so that we can use it later if requried */
			get_client_memptr(wlan_client, wlan_index)->dl_cnt_idx = client_info->dl_cnt_idx;
			get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx = client_info->ul_cnt_idx;
			get_client_memptr(wlan_client, wlan_index)->index_populated = true;
		}
#endif //IPA_HW_FNR_STATS
		if (rx_prop)
		{
			client_info->ul_src_pipe = rx_prop->rx[0].src_pipe;
		}
		if (set_lan_client_info(client_info))
		{
			res = IPACM_FAILURE;
			free(client_info);
			goto fail;
		}
		free(client_info);
		if (IPACM_Wan::isWanUP(ipa_if_num) ||
			(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && IPACM_Wan::isVlanWanUP()))
		{
			if(IPACM_Wan::backhaul_is_sta_mode == false)
			{
				ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
#ifdef IPA_HW_FNR_STATS
				if (IPACM_Wan::ipacmcfg->hw_fnr_stats_support)
					install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v4, IPACM_Wan::getXlat_Mux_Id(),
						get_client_memptr(wlan_client, wlan_index)->mac,
						get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx, NULL, false,
						get_client_memptr(wlan_client, wlan_index)->ta_peer_id);
				else
#endif //IPA_HW_FNR_STATS
					install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v4, IPACM_Wan::getXlat_Mux_Id(),
						get_client_memptr(wlan_client, wlan_index)->mac,
						get_client_memptr(wlan_client, wlan_index)->ta_peer_id);
				get_client_memptr(wlan_client, wlan_index)->ipv4_ul_rules_set = true;
			}
		}
		if(IPACM_Wan::isWanUP_V6(ipa_if_num) ||
			(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && IPACM_Wan::isVlanWanUP_V6()))
		{
			if(IPACM_Wan::backhaul_is_sta_mode == false)
			{
				ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
#ifdef IPA_HW_FNR_STATS
				if (IPACM_Wan::ipacmcfg->hw_fnr_stats_support)
					install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v6, 0, get_client_memptr(wlan_client, wlan_index)->mac,
							get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx, NULL, false,
							get_client_memptr(wlan_client, wlan_index)->ta_peer_id);
				else
#endif //IPA_HW_FNR_STATS
					install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v6, 0, get_client_memptr(wlan_client, wlan_index)->mac,
						get_client_memptr(wlan_client, wlan_index)->ta_peer_id);
				get_client_memptr(wlan_client, wlan_index)->ipv6_ul_rules_set = true;
			}
		}
#ifdef IPA_HW_FNR_STATS
		if (IPACM_Wan::ipacmcfg->hw_fnr_stats_support)
		{
			handle_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client, wlan_index)->mac, IPA_IP_v4);
			handle_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client, wlan_index)->mac, IPA_IP_v6);
#ifdef FEATURE_STATIC_POLICY
			if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
			{
				handle_pdn_dscp_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client, wlan_index)->mac,
					IPA_IP_v4, 0);
				for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end(); ++it)
				{
					std::copy(std::begin(it->first), std::end(it->first), std::begin(temp_ipv6));
					handle_pdn_dscp_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client, wlan_index)->mac,
					IPA_IP_v6, 0, temp_ipv6);
				}
			}
#endif
		}
		else
#endif //IPA_HW_FNR_STATS
		{
			handle_wlan_client_route_rule_ext(get_client_memptr(wlan_client, wlan_index)->mac, IPA_IP_v4);
			handle_wlan_client_route_rule_ext(get_client_memptr(wlan_client, wlan_index)->mac, IPA_IP_v6);
		}
	}
	return IPACM_SUCCESS;
fail:
	/* Reset the mac from active list. */
	reset_active_lan_stats_index(get_client_memptr(wlan_client, wlan_index)->lan_stats_idx, mac_addr);
	/* Add the mac to inactive list. */
	get_free_inactive_lan_stats_index(mac_addr);
	get_client_memptr(wlan_client, wlan_index)->lan_stats_idx = -1;
	return IPACM_FAILURE;
}

int IPACM_Wlan::handle_lan_client_disconnect(uint8_t *mac_addr)
{
	int ipa_if_num1;
	uint8_t mac[IPA_MAC_ADDR_SIZE];
	ipacm_event_data_mac *data;
	ipacm_cmd_q_data evt_data;

	/* Check if the client is in active list and remove it. */
	if (reset_active_lan_stats_index(get_lan_stats_index(mac_addr), mac_addr) == -1)
	{
		IPACMDBG_H("Failed to reset active lan_stats index, try inactive list. \n");
		/* If it is not in active list, check inactive list and remove it. */
		if (reset_inactive_lan_stats_index(mac_addr) == -1)
		{
			IPACMDBG_H("Failed to reserve inactive lan_stats index, return\n");
		}
		return IPACM_SUCCESS;
	}
	/* As we have free lan stats index. */
		/* Go through the inactive list and pick the first available one to add it to active list. */
	if (get_available_inactive_lan_client(mac, &ipa_if_num1) == IPACM_FAILURE)
	{
		IPACMDBG_H("Error in getting in active client.\n");
		return IPACM_FAILURE;
	}

	/* Add the mac to the active list. */
	if (get_free_active_lan_stats_index(mac, ipa_if_num1) == -1)
	{
		IPACMDBG_H("Free active index not available. Abort\n");
		return IPACM_FAILURE;
	}

	/* Remove the mac from inactive list. */
	if (reset_inactive_lan_stats_index(mac) == IPACM_FAILURE)
	{
		IPACMDBG_H("Unable to remove the client from inactive list. Check\n");
	}

	/* Check if the client is attached to the same Interface. */
	if (ipa_if_num1 == ipa_if_num)
	{
		/* Process the new lan stats index. */
		return handle_lan_client_connect(mac);
	}
	else
	{
		/* Post an event to other to Interface to add the client to the HW path. */
		data = (ipacm_event_data_mac *)malloc(sizeof(ipacm_event_data_mac));
		if(data == NULL)
		{
			IPACMERR("unable to allocate memory for event data\n");
			return IPACM_FAILURE;
		}
		memcpy(data->mac_addr,
					 mac,
					 sizeof(data->mac_addr));
		data->if_index = ipa_if_num1;
		evt_data.event = IPA_LAN_CLIENT_UPDATE_EVENT;
		evt_data.evt_data = data;
		IPACMDBG_H("Posting event:%d\n", evt_data.event);
		IPACM_EvtDispatcher::PostEvt(&evt_data);
	}
	return IPACM_SUCCESS;
}

/*handle wifi client routing rule with rule id*/
int IPACM_Wlan::handle_wlan_client_route_rule_ext(uint8_t *mac_addr, ipa_ip_type iptype, uint16_t vlan_id)
{
	struct ipa_ioc_add_rt_rule_ext *rt_rule;
	struct ipa_rt_rule_add_ext *rt_rule_entry;
#ifdef FEATURE_IPA_IPSEC
	ipa_ip_type *iptype_p = NULL;
	ipacm_cmd_q_data evt_data;
#endif
	uint32_t tx_index;
	int wlan_index;
	const int NUM = 1;
	ipacm_event_data_all data;

	if(tx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
			mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5]);

	wlan_index = get_wlan_client_index(mac_addr, vlan_id);
	if (wlan_index == IPACM_INVALID_INDEX ||
		get_client_memptr(wlan_client, wlan_index)->lan_stats_idx == -1)
	{
		IPACMDBG_H("wlan client not found/attached \n");
		return IPACM_SUCCESS;
	}

	/* during power_save mode, even receive IP_ADDR_ADD, not setting RT rules*/
	if (get_client_memptr(wlan_client, wlan_index)->power_save_set == true)
	{
		IPACMDBG_H("wlan client is in power safe mode \n");
		return IPACM_SUCCESS;
	}

	if (iptype==IPA_IP_v4)
	{
		IPACMDBG_H("wlan client index: %d, ip-type: %d, ipv4_set:%d, ipv4_rule_set:%d \n", wlan_index, iptype,
				get_client_memptr(wlan_client, wlan_index)->ipv4_set,
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4);
	}
	else
	{
		IPACMDBG_H("wlan client index: %d, ip-type: %d, ipv6_set:%d, ipv6_rule_num:%d \n", wlan_index, iptype,
				get_client_memptr(wlan_client, wlan_index)->ipv6_set,
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6);
	}


	/* Add default  Qos routing rules if not set yet */
	if ((iptype == IPA_IP_v4
				&& get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4 == false
				&& get_client_memptr(wlan_client, wlan_index)->ipv4_set == true)
			|| (iptype == IPA_IP_v6
				&& get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6 < get_client_memptr(wlan_client, wlan_index)->ipv6_set
			   ))
	{
		rt_rule = (struct ipa_ioc_add_rt_rule_ext *)
			calloc(1, sizeof(struct ipa_ioc_add_rt_rule_ext) +
					NUM * sizeof(struct ipa_rt_rule_add_ext));

		if (rt_rule == NULL)
		{
			PERROR("Error Locate ipa_ioc_add_rt_rule memory...\n");
			return IPACM_FAILURE;
		}

		rt_rule->commit = 1;
		rt_rule->num_rules = (uint8_t)NUM;
		rt_rule->ip = iptype;


		for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		{
			/* skip to the next tx index if the client type and hdr_l2_type are not matching */
#ifdef IPA_HDR_L2_802_1Q_AST
			if ((get_client_memptr(wlan_client, wlan_index)->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q_AST && tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q)) ||
					(!get_client_memptr(wlan_client, wlan_index)->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q_AST || tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q)))
			{
				continue;
			}
#endif

			if(iptype != tx_prop->tx[tx_index].ip)
			{
				IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip,iptype);
				continue;
			}

			rt_rule_entry = &rt_rule->rules[0];
			rt_rule_entry->at_rear = 0;

			if (iptype == IPA_IP_v4)
			{
				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", wlan_index,
						get_client_memptr(wlan_client, wlan_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
						wlan_index,
						get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4);
				strlcpy(rt_rule->rt_tbl_name,
						IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
						sizeof(rt_rule->rt_tbl_name));
				rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';

				if(IPACM_Iface::ipacmcfg->isMCC_Mode)
				{
					IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
							tx_prop->tx[tx_index].alt_dst_pipe);
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
				}
				else
				{
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
				}

				memcpy(&rt_rule_entry->rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry->rule.attrib));
				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;

				if (get_client_memptr(wlan_client, wlan_index)->ipv4_hpc_set)
					rt_rule_entry->rule.hdr_proc_ctx_hdl = get_client_memptr(wlan_client, wlan_index)->hpc_hdr_hdl_v4;
				else
					rt_rule_entry->rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4;

				rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(wlan_client, wlan_index)->v4_addr;
				rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;

				if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
				{
					rt_rule_entry->rule.hashable = true;
				}

				rt_rule_entry->rule_id = 0;
				if (get_client_memptr(wlan_client, wlan_index)->lan_stats_idx != -1) {
					rt_rule_entry->rule_id = get_client_memptr(wlan_client, wlan_index)->lan_stats_idx | 0x300;
				}
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
				if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
					if (iptype == IPA_IP_v6)
						rt_rule_entry->rule.ttl_update =
							IPACM_Wan::is_global_ipv6_addr(rt_rule_entry->rule.attrib.u.v6.dst_addr);
					else
						rt_rule_entry->rule.ttl_update = true;
				}
#endif
				if (false == m_routing.AddRoutingRuleExt(rt_rule))
				{
					IPACMERR("Routing rule addition failed!\n");
					free(rt_rule);
					return IPACM_FAILURE;
				}

				/* copy ipv4 RT hdl */
				get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4 =
					rt_rule->rules[0].rt_rule_hdl;
				IPACMDBG_H("tx:%d, rt rule id=%x ip-type: %d\n", tx_index,
						rt_rule_entry->rule_id, iptype);

				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4 = true;
				/* Add NAT rules after ipv4 RT rules are set */
				memset(&data, 0, sizeof(data));
				data.if_index = IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].netlink_interface_index;
				data.iptype = IPA_IP_v4;
				data.ipv4_addr = get_client_memptr(wlan_client, wlan_index)->v4_addr;
				CtList->HandleNeighIpAddrAddEvt(&data);
			}
			else
			{
				for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end();++it)
				{
					if (it->second.route_rule_set_v6 == true)
					{
						IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set (%d)\n",
						wlan_index, it->first[0], it->first[1], it->first[2], it->first[3],
						it->second.route_rule_set_v6);
						continue;
					}

					IPACMDBG_H("client(%d): v6 header handle:(0x%x)\n",
							wlan_index,
							get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6);

					/* v6 LAN_RT_TBL */
					strlcpy(rt_rule->rt_tbl_name,
							IPACM_Iface::ipacmcfg->rt_tbl_v6.name,
							sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Support QCMAP LAN traffic feature, send to A5 */
					rt_rule_entry->rule.dst = iface_query->excp_pipe;
					memset(&rt_rule_entry->rule.attrib, 0, sizeof(rt_rule_entry->rule.attrib));
					rt_rule_entry->rule.hdr_hdl = 0;
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = it->first[0];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = it->first[1];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = it->first[2];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = it->first[3];
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
#ifdef FEATURE_IPA_V3
					rt_rule_entry->rule.hashable = true;
#endif
					rt_rule_entry->rule_id = 0;
					if (false == m_routing.AddRoutingRuleExt(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						free(rt_rule);
						return IPACM_FAILURE;
					}

					it->second.hdl_v6[tx_index].rt_rule_hdl_v6 = rt_rule->rules[0].rt_rule_hdl;
					IPACMDBG_H("tx:%d, rt rule id=%x rt rule hdl=%x ip-type: %d\n", tx_index,
							rt_rule_entry->rule_id,
							it->second.hdl_v6[tx_index].rt_rule_hdl_v6, iptype);

					/*Copy same rule to v6 WAN RT TBL*/
					strlcpy(rt_rule->rt_tbl_name,
							IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name,
							sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Downlink traffic from Wan iface, directly through IPA */
					if(IPACM_Iface::ipacmcfg->isMCC_Mode)
					{
						IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
								tx_prop->tx[tx_index].alt_dst_pipe);
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
					}
					else
					{
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
					}
					memcpy(&rt_rule_entry->rule.attrib,
							&tx_prop->tx[tx_index].attrib,
							sizeof(rt_rule_entry->rule.attrib));

					if (get_client_memptr(wlan_client, wlan_index)->ipv6_hpc_set)
						rt_rule_entry->rule.hdr_proc_ctx_hdl = get_client_memptr(wlan_client, wlan_index)->hpc_hdr_hdl_v6;
					else
						rt_rule_entry->rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6;

					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = it->first[0];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = it->first[1];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = it->first[2];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = it->first[3];
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
#ifdef FEATURE_IPA_V3
					rt_rule_entry->rule.hashable = true;
#endif
					rt_rule_entry->rule_id = 0;
					if (get_client_memptr(wlan_client, wlan_index)->lan_stats_idx != -1) {
						rt_rule_entry->rule_id = get_client_memptr(wlan_client, wlan_index)->lan_stats_idx | 0x300;
					}
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
					if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
						if (iptype == IPA_IP_v6)
							rt_rule_entry->rule.ttl_update =
								IPACM_Wan::is_global_ipv6_addr(rt_rule_entry->rule.attrib.u.v6.dst_addr);
						else
							rt_rule_entry->rule.ttl_update = true;
					}
#endif
					if (false == m_routing.AddRoutingRuleExt(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						free(rt_rule);
						return IPACM_FAILURE;
					}

					it->second.hdl_v6[tx_index].rt_rule_hdl_v6_wan = rt_rule->rules[0].rt_rule_hdl;
					/* mark as route_rule_set_v6 = true*/
					if (tx_index + 1 == iface_query->num_tx_props)
						it->second.route_rule_set_v6 = true;

					IPACMDBG_H("tx:%d, rt rule id=%x, rt rule hdl=%x, ip-type: %d route_rule_set_v6(map) %d\n", tx_index,
							rt_rule_entry->rule_id, it->second.hdl_v6[tx_index].rt_rule_hdl_v6_wan, iptype,
							it->second.route_rule_set_v6);

					/* Add IPv6CT rules after ipv6 RT rules are set */
					memset(&data, 0, sizeof(data));
					data.if_index = IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].netlink_interface_index;
					data.iptype = IPA_IP_v6;
					data.ipv6_addr[0] = it->first[0];
					data.ipv6_addr[1] = it->first[1];
					data.ipv6_addr[2] = it->first[2];
					data.ipv6_addr[3] = it->first[3];
					CtList->HandleNeighIpAddrAddEvt_v6(&data);
				}
			}/* end of for loop */
		} /* end of txx loop */
		get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6 = get_client_memptr(wlan_client, wlan_index)->ipv6_set;
		free(rt_rule);
	}

#ifdef FEATURE_IPA_IPSEC
	iptype_p = (ipa_ip_type *)malloc(sizeof(*iptype_p));
	if (!iptype_p) {
		IPACMERR("Failed allocating memory for IPA_IPSEC_LAN_CLIENT_ROUTE_ADD_EVENT\n");
		return IPACM_FAILURE;
	}
	*iptype_p = iptype;
	evt_data.event = IPA_IPSEC_LAN_CLIENT_ROUTE_ADD_EVENT;
	evt_data.evt_data = (void *)iptype_p;
	IPACM_EvtDispatcher::PostEvt(&evt_data);
#endif

	return IPACM_SUCCESS;
}

#ifdef IPA_HW_FNR_STATS
int IPACM_Wlan::handle_wlan_client_route_rule_ext_v2(uint8_t *mac_addr, ipa_ip_type iptype, uint16_t vlan_id)
{
	struct ipa_ioc_add_rt_rule_ext_v2 *rt_rule;
	struct ipa_rt_rule_add_ext_v2 *rt_rule_entry;
#ifdef FEATURE_IPA_IPSEC
	ipa_ip_type *iptype_p = NULL;
	ipacm_cmd_q_data evt_data;
#endif
	uint32_t tx_index;
	int wlan_index;
	const int NUM = 1;
	ipacm_event_data_all data;
	uint64_t rules;

	if(tx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
			mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5]);

	wlan_index = get_wlan_client_index(mac_addr, vlan_id);
	if (wlan_index == IPACM_INVALID_INDEX ||
		get_client_memptr(wlan_client, wlan_index)->lan_stats_idx == -1)
	{
		IPACMDBG_H("wlan client not found/attached \n");
		return IPACM_SUCCESS;
	}

	/* during power_save mode, even receive IP_ADDR_ADD, not setting RT rules*/
	if (get_client_memptr(wlan_client, wlan_index)->power_save_set == true)
	{
		IPACMDBG_H("wlan client is in power safe mode \n");
		return IPACM_SUCCESS;
	}

	if (iptype==IPA_IP_v4)
	{
		IPACMDBG_H("wlan client index: %d, ip-type: %d, ipv4_set:%d, ipv4_rule_set:%d \n", wlan_index, iptype,
				get_client_memptr(wlan_client, wlan_index)->ipv4_set,
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4);
	}
	else
	{
		IPACMDBG_H("wlan client index: %d, ip-type: %d, ipv6_set:%d, ipv6_rule_num:%d \n", wlan_index, iptype,
				get_client_memptr(wlan_client, wlan_index)->ipv6_set,
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6);
	}


	/* Add default  Qos routing rules if not set yet */
	if ((iptype == IPA_IP_v4
				&& get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4 == false
				&& get_client_memptr(wlan_client, wlan_index)->ipv4_set == true)
			|| (iptype == IPA_IP_v6
				&& get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6 < get_client_memptr(wlan_client, wlan_index)->ipv6_set
			   ))
	{
		rt_rule = (struct ipa_ioc_add_rt_rule_ext_v2 *)
			calloc(1, sizeof(struct ipa_ioc_add_rt_rule_ext_v2));

		if (rt_rule == NULL)
		{
			PERROR("Error Locate ipa_ioc_add_rt_rule memory...\n");
			return IPACM_FAILURE;
		}

		rt_rule->rules = (uintptr_t)calloc(NUM, sizeof(struct ipa_rt_rule_add_ext_v2));
		if (!rt_rule->rules) {
			IPACMERR("Failed to allocate memory.\n");
			free(rt_rule);
			return IPACM_FAILURE;
		}
		rt_rule->rule_add_ext_size = sizeof(struct ipa_rt_rule_add_ext_v2);
		rt_rule->commit = 1;
		rt_rule->num_rules = (uint8_t)NUM;
		rt_rule->ip = iptype;
		for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		{
			/* skip to the next tx index if the client type and hdr_l2_type are not matching */
#ifdef IPA_HDR_L2_802_1Q_AST
			if ((get_client_memptr(wlan_client, wlan_index)->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q_AST && tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q)) ||
					(!get_client_memptr(wlan_client, wlan_index)->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q_AST || tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q)))
			{
				continue;
			}
#endif

			if(iptype != tx_prop->tx[tx_index].ip)
			{
				IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip,iptype);
				continue;
			}

			rules = rt_rule->rules;
			rt_rule_entry = (struct ipa_rt_rule_add_ext_v2 *)rules;
			rt_rule_entry->at_rear = 0;

			if (iptype == IPA_IP_v4)
			{
				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", wlan_index,
						get_client_memptr(wlan_client, wlan_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
						wlan_index,
						get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4);
				strlcpy(rt_rule->rt_tbl_name,
						IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
						sizeof(rt_rule->rt_tbl_name));
				rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';

				if(IPACM_Iface::ipacmcfg->isMCC_Mode)
				{
					IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
							tx_prop->tx[tx_index].alt_dst_pipe);
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
				}
				else
				{
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
				}

				memcpy(&rt_rule_entry->rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry->rule.attrib));
				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;

				if (get_client_memptr(wlan_client, wlan_index)->ipv4_hpc_set)
					rt_rule_entry->rule.hdr_proc_ctx_hdl = get_client_memptr(wlan_client, wlan_index)->hpc_hdr_hdl_v4;
				else
					rt_rule_entry->rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4;

				rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(wlan_client, wlan_index)->v4_addr;
				rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
				rt_rule_entry->rule.enable_stats = true;
				rt_rule_entry->rule.cnt_idx =
					get_client_memptr(wlan_client, wlan_index)->dl_cnt_idx;
				IPACMDBG_H("wlan_client dl index (%d) \n", rt_rule_entry->rule.cnt_idx);
				if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
				{
					rt_rule_entry->rule.hashable = true;
				}

				rt_rule_entry->rule_id = 0;
				if (false == m_routing.AddRoutingRuleExt_v2(rt_rule))
				{
					IPACMERR("Routing rule addition failed!\n");
					free((void *)rt_rule->rules);
					free(rt_rule);
					return IPACM_FAILURE;
				}

				/* copy ipv4 RT hdl */
				get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4 =
					((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[0].rt_rule_hdl;
				IPACMDBG_H("tx:%d, rt rule id=%x ip-type: %d\n", tx_index,
						rt_rule_entry->rule_id, iptype);

				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4 = true;
				/* Add NAT rules after ipv4 RT rules are set */
				memset(&data, 0, sizeof(data));
				data.if_index = IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].netlink_interface_index;
				data.iptype = IPA_IP_v4;
				data.ipv4_addr = get_client_memptr(wlan_client, wlan_index)->v4_addr;
				CtList->HandleNeighIpAddrAddEvt(&data);
			}
			else
			{
				for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end();++it)
				{
					if (it->second.route_rule_set_v6 == true)
					{
						IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set (%d)\n",
						wlan_index,
						it->first[0], it->first[1], it->first[2], it->first[3],
						it->second.route_rule_set_v6);
						continue;
					}

					IPACMDBG_H("client(%d): v6 header handle:(0x%x)\n",
							wlan_index,
							get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6);

					/* v6 LAN_RT_TBL */
					strlcpy(rt_rule->rt_tbl_name,
							IPACM_Iface::ipacmcfg->rt_tbl_v6.name,
							sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Support QCMAP LAN traffic feature, send to A5 */
					rt_rule_entry->rule.dst = iface_query->excp_pipe;
					memset(&rt_rule_entry->rule.attrib, 0, sizeof(rt_rule_entry->rule.attrib));
					rt_rule_entry->rule.hdr_hdl = 0;
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = it->first[0];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = it->first[1];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = it->first[2];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = it->first[3];
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
					rt_rule_entry->rule.enable_stats = true;
					rt_rule_entry->rule.cnt_idx =
						get_client_memptr(wlan_client, wlan_index)->dl_cnt_idx;
					rt_rule_entry->rule.hashable = true;
					rt_rule_entry->rule_id = 0;
					if (false == m_routing.AddRoutingRuleExt_v2(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						free((void *)rt_rule->rules);
						free(rt_rule);
						return IPACM_FAILURE;
					}

					it->second.hdl_v6[tx_index].rt_rule_hdl_v6 = ((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[0].rt_rule_hdl;
					IPACMDBG_H("tx:%d, rt rule id=%x rt rule hdl=%x  ip-type: %d\n", tx_index,
							rt_rule_entry->rule_id, it->second.hdl_v6[tx_index].rt_rule_hdl_v6, iptype);

					/*Copy same rule to v6 WAN RT TBL*/
					strlcpy(rt_rule->rt_tbl_name,
							IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name,
							sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Downlink traffic from Wan iface, directly through IPA */
					if(IPACM_Iface::ipacmcfg->isMCC_Mode)
					{
						IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
								tx_prop->tx[tx_index].alt_dst_pipe);
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
					}
					else
					{
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
					}
					memcpy(&rt_rule_entry->rule.attrib,
							&tx_prop->tx[tx_index].attrib,
							sizeof(rt_rule_entry->rule.attrib));

					if (get_client_memptr(wlan_client, wlan_index)->ipv6_hpc_set)
						rt_rule_entry->rule.hdr_proc_ctx_hdl = get_client_memptr(wlan_client, wlan_index)->hpc_hdr_hdl_v6;
					else
						rt_rule_entry->rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6;

					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = it->first[0];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = it->first[1];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = it->first[2];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = it->first[3];
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
					rt_rule_entry->rule.enable_stats = true;
					rt_rule_entry->rule.cnt_idx = get_client_memptr(wlan_client, wlan_index)->dl_cnt_idx;
#ifdef FEATURE_IPA_V3
					rt_rule_entry->rule.hashable = true;
#endif
					rt_rule_entry->rule_id = 0;
					if (false == m_routing.AddRoutingRuleExt_v2(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						free((void *)rt_rule->rules);
						free(rt_rule);
						return IPACM_FAILURE;
					}

					it->second.hdl_v6[tx_index].rt_rule_hdl_v6_wan = ((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[0].rt_rule_hdl;
					/* mark as route_rule_set_v6 = true*/
					if (tx_index + 1 == iface_query->num_tx_props)
						it->second.route_rule_set_v6 = true;

					IPACMDBG_H("tx:%d, rt rule id=%x rt rule hdl=%x ip-type: %d route_rule_set_v6(map) %d\n", tx_index,
							rt_rule_entry->rule_id,
							it->second.hdl_v6[tx_index].rt_rule_hdl_v6_wan, iptype,
							it->second.route_rule_set_v6);

					/* Add IPv6CT rules after ipv6 RT rules are set */
					memset(&data, 0, sizeof(data));
					data.if_index = IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].netlink_interface_index;
					data.iptype = IPA_IP_v6;
					data.ipv6_addr[0] = it->first[0];
					data.ipv6_addr[1] = it->first[1];
					data.ipv6_addr[2] = it->first[2];
					data.ipv6_addr[3] = it->first[3];
					CtList->HandleNeighIpAddrAddEvt_v6(&data);
				}
				IPACMDBG_H("rt rule entry enable stats = %d, dl cnt index = %u\n", rt_rule_entry->rule.enable_stats, rt_rule_entry->rule.cnt_idx);
			}/* end of for loop */
		} /* end of tx loop */
		get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6 = get_client_memptr(wlan_client, wlan_index)->ipv6_set;
		free(rt_rule);
	}

#ifdef FEATURE_IPA_IPSEC
	iptype_p = (ipa_ip_type *)malloc(sizeof(*iptype_p));
	if (!iptype_p) {
		IPACMERR("Failed allocating memory for IPA_IPSEC_LAN_CLIENT_ROUTE_ADD_EVENT\n");
		return IPACM_FAILURE;
	}
	*iptype_p = iptype;
	evt_data.event = IPA_IPSEC_LAN_CLIENT_ROUTE_ADD_EVENT;
	evt_data.evt_data = (void *)iptype_p;
	IPACM_EvtDispatcher::PostEvt(&evt_data);
#endif


	return IPACM_SUCCESS;
}
#endif //IPA_HW_FNR_STATS
#endif
/*handle wifi client power-save mode*/
int IPACM_Wlan::handle_wlan_client_pwrsave(uint8_t *mac_addr)
{
	int clt_indx;
	IPACMDBG_H("wlan->handle_wlan_client_pwrsave();\n");
	uint32_t ipv6_temp[4] = {0};

	clt_indx = get_wlan_client_index(mac_addr);
	if (clt_indx == IPACM_INVALID_INDEX)
	{
		IPACMDBG_H("wlan client not attached\n");
		return IPACM_SUCCESS;
	}

	if (get_client_memptr(wlan_client, clt_indx)->power_save_set == false)
	{
		/* First reset NAT/IPv6CT rules and then route rules */
		if (get_client_memptr(wlan_client, clt_indx)->ipv4_set == true)
		{
			IPACMDBG_H("Deleting Nat Rules\n");
			Nat_App->UpdatePwrSaveIf(get_client_memptr(wlan_client, clt_indx)->v4_addr);
		}
		if (ipv6ct_inst != NULL)
		{
			for (auto it = rt_hdl_v6_list[clt_indx].begin(); it != rt_hdl_v6_list[clt_indx].end();++it)
			{
				std::copy(std::begin(it->first), std::end(it->first), std::begin(ipv6_temp));
				ipv6ct_inst->UpdatePwrSaveIf(Ipv6IpAddress(ipv6_temp, false));
			}
		}

		IPACMDBG_H("Deleting default qos Route Rules\n");
		delete_default_qos_rtrules(clt_indx, IPA_IP_v4);
		delete_default_qos_rtrules(clt_indx, IPA_IP_v6);
#ifdef FEATURE_STATIC_POLICY
		if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
		{
			delete_pdn_dscp_wlan_rtrules(IPA_IP_v4, 2, clt_indx);
			delete_pdn_dscp_wlan_rtrules(IPA_IP_v6, 2, clt_indx);
		}
#endif
		get_client_memptr(wlan_client, clt_indx)->power_save_set = true;
	}
	else
	{
		IPACMDBG_H("wlan client already in power-save mode\n");
	}
    return IPACM_SUCCESS;
}

/*handle wifi client del mode*/
int IPACM_Wlan::handle_wlan_client_down_evt(uint8_t *mac_addr, uint16_t vlan_id)
{
	int clt_indx;
	uint32_t tx_index;
	int num_wifi_client_tmp = num_wifi_client;
	int num_v6;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	struct wan_ioctl_lan_client_info *client_info;
#endif
	std::list <ipacm_event_data_all>::iterator it;

	IPACMDBG_H("total client: %d\n", num_wifi_client_tmp);

	clt_indx = get_wlan_client_index(mac_addr, vlan_id);
	if (clt_indx == IPACM_INVALID_INDEX)
	{
		IPACMDBG_H("wlan client not attached\n");
		return IPACM_SUCCESS;
	}
	IPACMDBG_H("client_index %d\n",clt_indx);
	/* First reset NAT/IPv6CT rules and then route rules */
	HandleNeighIpAddrDelEvt(clt_indx);

	if (ast_update_needed())
	{
		if (delete_wlan_client_lan2lan_flt_rule(get_client_memptr(wlan_client, clt_indx)->mac, IPA_IP_v4))
		{
			IPACMERR("unable to delete v4 lan2lan flt rule for index: %d\n", clt_indx);
			return IPACM_FAILURE;
		}

		if (delete_wlan_client_lan2lan_flt_rule(get_client_memptr(wlan_client, clt_indx)->mac, IPA_IP_v6))
		{
			IPACMERR("unable to delete v6 lan2lan flt rule for index: %d\n", clt_indx);
			return IPACM_FAILURE;
		}
	}

	if (delete_default_qos_rtrules(clt_indx, IPA_IP_v4))
	{
		IPACMERR("unable to delete v4 default qos route rules for index: %d\n", clt_indx);
		return IPACM_FAILURE;
	}

	if (delete_default_qos_rtrules(clt_indx, IPA_IP_v6))
	{
		IPACMERR("unable to delete v6 default qos route rules for index: %d\n", clt_indx);
		return IPACM_FAILURE;
	}
#ifdef FEATURE_STATIC_POLICY
	if((IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
		&& (delete_pdn_dscp_wlan_rtrules(IPA_IP_v4, 2, clt_indx)))
	{
		IPACMERR("unable to delete v4 PDN DSCP route rules for index: %d\n", clt_indx);
		return IPACM_FAILURE;
	}

	if((IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
		&& (delete_pdn_dscp_wlan_rtrules(IPA_IP_v6, 2, clt_indx)))
	{
		IPACMERR("unable to delete v6 PDN DSCP route rules for index: %d\n", clt_indx);
		return IPACM_FAILURE;
	}
#endif
	/* Delete wlan client header */
	if (get_client_memptr(wlan_client, clt_indx)->ipv4_hpc_set == true)
	{
		IPACMDBG_H("Deleting proc_ctx v4 handle %d\n",get_client_memptr(wlan_client, clt_indx)->hpc_hdr_hdl_v4);
	if (m_header.DeleteHeaderProcCtx(get_client_memptr(wlan_client, clt_indx)->hpc_hdr_hdl_v4)
			== false)
		{
			IPACMERR("unable to delete v4 header hpc rules for index: %d\n", clt_indx);
			return IPACM_FAILURE;
		}
		get_client_memptr(wlan_client, clt_indx)->ipv4_hpc_set = false;
	}

	if (get_client_memptr(wlan_client, clt_indx)->ipv6_hpc_set == true)
	{
		IPACMDBG_H("Deleting proc_ctx v6 handle %d\n",get_client_memptr(wlan_client, clt_indx)->hpc_hdr_hdl_v6);
	if (m_header.DeleteHeaderProcCtx(get_client_memptr(wlan_client, clt_indx)->hpc_hdr_hdl_v6)
			== false)
		{
			IPACMERR("unable to delete v6 header hpc rules for index: %d\n", clt_indx);
			return IPACM_FAILURE;
		}
		get_client_memptr(wlan_client, clt_indx)->ipv6_hpc_set = false;
	}

	if(get_client_memptr(wlan_client, clt_indx)->ipv4_header_set == true)
	{
	if (m_header.DeleteHeaderHdl(get_client_memptr(wlan_client, clt_indx)->hdr_hdl_v4)
			== false)
	{
		IPACMERR("unable to delete v4 header rules for index: %d\n", clt_indx);
		return IPACM_FAILURE;
	}
		get_client_memptr(wlan_client, clt_indx)->ipv4_header_set = false;
	}

	if(get_client_memptr(wlan_client, clt_indx)->ipv6_header_set == true)
	{
	if (m_header.DeleteHeaderHdl(get_client_memptr(wlan_client, clt_indx)->hdr_hdl_v6)
			== false)
	{
		IPACMERR("unable to delete v6 header rules for index: %d\n", clt_indx);
		return IPACM_FAILURE;
	}
		get_client_memptr(wlan_client, clt_indx)->ipv6_header_set = false;
	}

#ifdef IPA_IOC_SET_SW_FLT
	/* clean-up the tether-client-list */
	IPACM_Iface::ipacmcfg->update_client_info(get_client_memptr(wlan_client, clt_indx)->mac, NULL, false);
#endif

#if defined(FEATURE_IPACM_PER_CLIENT_STATS) || defined(IPA_WDI_AST_UPDATE)
	if (get_client_memptr(wlan_client, clt_indx)->ipv4_ul_rules_set == true)
	{
		if (delete_uplink_filter_rule_per_client(IPA_IP_v4, get_client_memptr(wlan_client, clt_indx)->mac))
		{
			IPACMERR("unable to delete uplink v4 filter rules for index: %d\n", clt_indx);
			return IPACM_FAILURE;
		}
	}

	if (get_client_memptr(wlan_client, clt_indx)->ipv6_ul_rules_set == true)
	{
		if (delete_uplink_filter_rule_per_client(IPA_IP_v6, get_client_memptr(wlan_client, clt_indx)->mac))
		{
			IPACMERR("unable to delete uplink v6 filter rules for index: %d\n", clt_indx);
			return IPACM_FAILURE;
		}
	}
#endif

	for (auto it1 = rt_hdl_v6_list[clt_indx].begin(); it1 != rt_hdl_v6_list[clt_indx].end();++it1)
	{
		for (it = neigh_cache.begin(); it != neigh_cache.end(); ++it)
		{
			if( it->ipv6_addr[0] == it1->first[0] &&
				it->ipv6_addr[1] == it1->first[1] &&
				it->ipv6_addr[2] == it1->first[2] &&
				it->ipv6_addr[3] == it1->first[3])
			{
				neigh_cache.erase(it);
				break;
			}
		}
	}

	IPACMDBG_H("client %d has %d ipv6 with rt: %d, current total_v6=%d \n", clt_indx,
		get_client_memptr(wlan_client, clt_indx)->ipv6_set,
		get_client_memptr(wlan_client, clt_indx)->route_rule_set_v6,
		IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
	IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6 -= get_client_memptr(wlan_client, clt_indx)->ipv6_set;
	IPACMDBG_H("update ipa_num_clients_ipv6 = %d\n", IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
	rt_hdl_v6_list[clt_indx].clear();

	/* Reset ip_set to 0*/
	get_client_memptr(wlan_client, clt_indx)->ipv4_set = false;
	get_client_memptr(wlan_client, clt_indx)->ipv6_set = 0;
	get_client_memptr(wlan_client, clt_indx)->ipv4_header_set = false;
	get_client_memptr(wlan_client, clt_indx)->ipv6_header_set = false;
	get_client_memptr(wlan_client, clt_indx)->ipv4_hpc_set = false;
	get_client_memptr(wlan_client, clt_indx)->ipv6_hpc_set = false;
	get_client_memptr(wlan_client, clt_indx)->route_rule_set_v4 = false;
	get_client_memptr(wlan_client, clt_indx)->route_rule_set_v6 = 0;
	free(get_client_memptr(wlan_client, clt_indx)->p_hdr_info);
	get_client_memptr(wlan_client, clt_indx)->ta_peer_id = 0;
	get_client_memptr(wlan_client, clt_indx)->vlan_id = 0;
	get_client_memptr(wlan_client, clt_indx)->is_vlan = 0;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	get_client_memptr(wlan_client, clt_indx)->ipv4_ul_rules_set = false;
	get_client_memptr(wlan_client, clt_indx)->ipv6_ul_rules_set = false;
	if (get_client_memptr(wlan_client, clt_indx)->lan_stats_idx != -1)
	{
		/* Clear the lan client info. */
		client_info = (struct wan_ioctl_lan_client_info *)malloc(sizeof(struct wan_ioctl_lan_client_info));
		if (client_info == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			return IPACM_FAILURE;
		}
		memset(client_info, 0, sizeof(struct wan_ioctl_lan_client_info));
		client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_WLAN;
		memcpy(client_info->mac,
				get_client_memptr(wlan_client, clt_indx)->mac,
				IPA_MAC_ADDR_SIZE);
		client_info->client_init = 0;
		client_info->client_idx = get_client_memptr(wlan_client, clt_indx)->lan_stats_idx;
		client_info->ul_src_pipe = (enum ipa_client_type) IPA_CLIENT_MAX;
#ifdef IPA_HW_FNR_STATS
		client_info->ul_cnt_idx = get_client_memptr(wlan_client, clt_indx)->ul_cnt_idx;
		client_info->dl_cnt_idx = get_client_memptr(wlan_client, clt_indx)->dl_cnt_idx;
		if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
		{
			get_client_memptr(wlan_client, clt_indx)->ul_cnt_idx = -1;
			get_client_memptr(wlan_client, clt_indx)->dl_cnt_idx = -1;
			get_client_memptr(wlan_client, clt_indx)->index_populated = false;
			pthread_mutex_lock(&IPACM_Wan::ipacmcfg->cnt_idx_lock);
			if (IPACM_Wan::ipacmcfg->reset_cnt_idx(client_info->ul_cnt_idx, false))
				IPACMERR("Failed to reset counter index %u\n", client_info->ul_cnt_idx);
			pthread_mutex_unlock(&IPACM_Wan::ipacmcfg->cnt_idx_lock);
		}
#endif //IPA_HW_FNR_STATS
		if (rx_prop)
		{
			client_info->ul_src_pipe = rx_prop->rx[0].src_pipe;
		}
		clear_lan_client_info(client_info);
		free(client_info);
	}
	get_client_memptr(wlan_client, clt_indx)->lan_stats_idx = -1;
	memset(get_client_memptr(wlan_client, clt_indx)->wan_ul_fl_rule_hdl_v4, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
	memset(get_client_memptr(wlan_client, clt_indx)->wan_ul_fl_rule_hdl_v6, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
#endif

	for (; clt_indx < num_wifi_client_tmp - 1; clt_indx++)
	{
		get_client_memptr(wlan_client, clt_indx)->p_hdr_info = get_client_memptr(wlan_client, (clt_indx + 1))->p_hdr_info;

		memcpy(get_client_memptr(wlan_client, clt_indx)->mac,
					 get_client_memptr(wlan_client, (clt_indx + 1))->mac,
					 sizeof(get_client_memptr(wlan_client, clt_indx)->mac));

		get_client_memptr(wlan_client, clt_indx)->hdr_hdl_v4 = get_client_memptr(wlan_client, (clt_indx + 1))->hdr_hdl_v4;
		get_client_memptr(wlan_client, clt_indx)->hdr_hdl_v6 = get_client_memptr(wlan_client, (clt_indx + 1))->hdr_hdl_v6;
		get_client_memptr(wlan_client, clt_indx)->hpc_hdr_hdl_v4 = get_client_memptr(wlan_client, (clt_indx + 1))->hpc_hdr_hdl_v4;
		get_client_memptr(wlan_client, clt_indx)->hpc_hdr_hdl_v6 = get_client_memptr(wlan_client, (clt_indx + 1))->hpc_hdr_hdl_v6;
		get_client_memptr(wlan_client, clt_indx)->v4_addr = get_client_memptr(wlan_client, (clt_indx + 1))->v4_addr;

		get_client_memptr(wlan_client, clt_indx)->ipv4_set = get_client_memptr(wlan_client, (clt_indx + 1))->ipv4_set;
		get_client_memptr(wlan_client, clt_indx)->ipv6_set = get_client_memptr(wlan_client, (clt_indx + 1))->ipv6_set;
		get_client_memptr(wlan_client, clt_indx)->ipv4_header_set = get_client_memptr(wlan_client, (clt_indx + 1))->ipv4_header_set;
		get_client_memptr(wlan_client, clt_indx)->ipv6_header_set = get_client_memptr(wlan_client, (clt_indx + 1))->ipv6_header_set;
		get_client_memptr(wlan_client, clt_indx)->ipv4_hpc_set = get_client_memptr(wlan_client, (clt_indx + 1))->ipv4_hpc_set;
		get_client_memptr(wlan_client, clt_indx)->ipv6_hpc_set = get_client_memptr(wlan_client, (clt_indx + 1))->ipv6_hpc_set;

		get_client_memptr(wlan_client, clt_indx)->route_rule_set_v4 = get_client_memptr(wlan_client, (clt_indx + 1))->route_rule_set_v4;
		get_client_memptr(wlan_client, clt_indx)->route_rule_set_v6 = get_client_memptr(wlan_client, (clt_indx + 1))->route_rule_set_v6;

		rt_hdl_v6_list[clt_indx] = rt_hdl_v6_list[clt_indx + 1];

		for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		{
			/* skip to the next tx index if the client type and hdr_l2_type are not matching */
#ifdef IPA_HDR_L2_802_1Q_AST
			IPACMDBG_H("next client hdls %d tx index %d\n",get_client_memptr(wlan_client, (clt_indx + 1))->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4,tx_index);
			if ((get_client_memptr(wlan_client, (clt_indx + 1))->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q_AST && tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q)) ||
					(!get_client_memptr(wlan_client, (clt_indx + 1))->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q_AST || tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q)))
			{
				IPACMDBG_H("vlan and l2 mismatch %d is vlan %d\n",tx_prop->tx[tx_index].hdr_l2_type,get_client_memptr(wlan_client, clt_indx)->is_vlan);
				continue;
			}
#endif

			get_client_memptr(wlan_client, clt_indx)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4 =
				 get_client_memptr(wlan_client, (clt_indx + 1))->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4;
		}
		get_client_memptr(wlan_client, clt_indx)->ta_peer_id = get_client_memptr(wlan_client, (clt_indx + 1))->ta_peer_id;
		get_client_memptr(wlan_client, clt_indx)->vlan_id = get_client_memptr(wlan_client, (clt_indx + 1))->vlan_id;
		get_client_memptr(wlan_client, clt_indx)->is_vlan = get_client_memptr(wlan_client, (clt_indx + 1))->is_vlan;
		get_client_memptr(wlan_client, clt_indx)->lan2lan_fl_rule_hdl_v4 =
			get_client_memptr(wlan_client, (clt_indx + 1))->lan2lan_fl_rule_hdl_v4;
		get_client_memptr(wlan_client, clt_indx)->lan2lan_fl_rule_hdl_v6 =
			get_client_memptr(wlan_client, (clt_indx + 1))->lan2lan_fl_rule_hdl_v6;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		memcpy(get_client_memptr(wlan_client, clt_indx)->wan_ul_fl_rule_hdl_v4,
			get_client_memptr(wlan_client, clt_indx + 1)->wan_ul_fl_rule_hdl_v4,
			MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
		memcpy(get_client_memptr(wlan_client, clt_indx)->wan_ul_fl_rule_hdl_v6,
			get_client_memptr(wlan_client, clt_indx + 1)->wan_ul_fl_rule_hdl_v6,
			MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
		get_client_memptr(wlan_client, clt_indx)->lan_stats_idx =
			get_client_memptr(wlan_client, clt_indx + 1)->lan_stats_idx;
#ifdef IPA_HW_FNR_STATS
		get_client_memptr(wlan_client, clt_indx)->ul_cnt_idx =
			get_client_memptr(wlan_client, clt_indx + 1)->ul_cnt_idx;
		get_client_memptr(wlan_client, clt_indx)->dl_cnt_idx =
			get_client_memptr(wlan_client, clt_indx + 1)->dl_cnt_idx;
		get_client_memptr(wlan_client, clt_indx)->index_populated =
			get_client_memptr(wlan_client, clt_indx + 1)->index_populated;
#endif //IPA_HW_FNR_STATS
#endif
#ifdef FEATURE_STATIC_POLICY
		memcpy(get_client_memptr(wlan_client, clt_indx)->dscp_hpc_hdr_hdl_v4,
			get_client_memptr(wlan_client, clt_indx + 1)->dscp_hpc_hdr_hdl_v4,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(uint32_t));
		memcpy(get_client_memptr(wlan_client, clt_indx)->dscp_hpc_hdr_hdl_v6,
			get_client_memptr(wlan_client, clt_indx + 1)->dscp_hpc_hdr_hdl_v6,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(uint32_t));
		memcpy(get_client_memptr(wlan_client, clt_indx)->dscp_route_rule_set_v4,
			get_client_memptr(wlan_client, clt_indx + 1)->dscp_route_rule_set_v4,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(bool));
		memcpy(get_client_memptr(wlan_client, clt_indx)->dscp_ipv4_hpc_set,
			get_client_memptr(wlan_client, clt_indx + 1)->dscp_ipv4_hpc_set,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(bool));
		memcpy(get_client_memptr(wlan_client, clt_indx)->dscp_ipv6_hpc_set,
			get_client_memptr(wlan_client, clt_indx + 1)->dscp_ipv6_hpc_set,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(bool));
		memcpy(get_client_memptr(wlan_client, clt_indx)->dscp_ipv4_hpc_count,
			get_client_memptr(wlan_client, clt_indx + 1)->dscp_ipv4_hpc_count,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(int));
		memcpy(get_client_memptr(wlan_client, clt_indx)->dscp_ipv6_hpc_count,
			get_client_memptr(wlan_client, clt_indx + 1)->dscp_ipv6_hpc_count,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(int));
		memcpy(get_client_memptr(wlan_client, clt_indx)->dscp_wifi_rt_hdl,
			get_client_memptr(wlan_client, clt_indx + 1)->dscp_wifi_rt_hdl,
			IPA_UC_MAX_PDN_DSCP_VAL * sizeof(wlan_client_rt_hdl));
#endif
	}
	/* Clean up the last entry */
	rt_hdl_v6_list[num_wifi_client_tmp - 1].clear();

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	get_client_memptr(wlan_client, clt_indx)->lan_stats_idx = -1;
#ifdef IPA_HW_FNR_STATS
	get_client_memptr(wlan_client, clt_indx)->ul_cnt_idx = -1;
	get_client_memptr(wlan_client, clt_indx)->dl_cnt_idx = -1;
	get_client_memptr(wlan_client, clt_indx)->index_populated = false;
#endif
	memset(get_client_memptr(wlan_client, clt_indx)->wan_ul_fl_rule_hdl_v4, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
	memset(get_client_memptr(wlan_client, clt_indx)->wan_ul_fl_rule_hdl_v6, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
#endif
#ifdef FEATURE_STATIC_POLICY
	memset(get_client_memptr(wlan_client, clt_indx)->dscp_hpc_hdr_hdl_v4,
		0,
		IPA_UC_MAX_PDN_DSCP_VAL * sizeof(uint32_t));
	memset(get_client_memptr(wlan_client, clt_indx)->dscp_hpc_hdr_hdl_v6,
		0,
		IPA_UC_MAX_PDN_DSCP_VAL * sizeof(uint32_t));
	memset(get_client_memptr(wlan_client, clt_indx)->dscp_route_rule_set_v4,
		0,
		IPA_UC_MAX_PDN_DSCP_VAL * sizeof(bool));
	memset(get_client_memptr(wlan_client, clt_indx)->dscp_ipv4_hpc_set,
		0,
		IPA_UC_MAX_PDN_DSCP_VAL * sizeof(bool));
	memset(get_client_memptr(wlan_client, clt_indx)->dscp_ipv6_hpc_set,
		0,
		IPA_UC_MAX_PDN_DSCP_VAL * sizeof(bool));
	memset(get_client_memptr(wlan_client, clt_indx)->dscp_ipv4_hpc_count,
		0,
		IPA_UC_MAX_PDN_DSCP_VAL * sizeof(int));
	memset(get_client_memptr(wlan_client, clt_indx)->dscp_ipv6_hpc_count,
		0,
		IPA_UC_MAX_PDN_DSCP_VAL * sizeof(int));
	memset(get_client_memptr(wlan_client, clt_indx)->dscp_wifi_rt_hdl,
		0,
		IPA_UC_MAX_PDN_DSCP_VAL * sizeof(wlan_client_rt_hdl));
#endif
	IPACMDBG_H(" %d wifi client deleted successfully \n", num_wifi_client);
	num_wifi_client = num_wifi_client - 1;
	IPACM_Wlan::total_num_wifi_clients = IPACM_Wlan::total_num_wifi_clients - 1;
	IPACMDBG_H(" Number of wifi client: %d\n", num_wifi_client);

	return IPACM_SUCCESS;
}

/*handle primary wifi client del mode*/
int IPACM_Wlan::handle_wlan_primary_client_down_evt(uint8_t *mac_addr)
{
	int primary_clt_indx, clnt_idx;
	int num_wifi_client_tmp = num_wifi_primary_client;

	IPACMDBG_H("total primary client: %d\n", num_wifi_client_tmp);

	primary_clt_indx = get_wlan_primary_client_index(mac_addr);
	if (primary_clt_indx == IPACM_INVALID_INDEX)
	{
		IPACMDBG_H("Primary wlan client not attached\n");
		return IPACM_SUCCESS;
	}

	free(get_primary_client_memptr(wlan_primary_client, primary_clt_indx)->p_hdr_info);

	while (get_primary_client_memptr(wlan_primary_client, primary_clt_indx)->num_vlan_clients > 0)
	{
		/* Get first VLAN client index. */
		clnt_idx = get_wlan_client_index(mac_addr);
		if (clnt_idx != IPACM_INVALID_INDEX)
		{
			IPACMDBG_H("Delete client with VLAN ID: %d\n", get_client_memptr(wlan_client, clnt_idx)->vlan_id);
			eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_DEL, IPA_IP_MAX, mac_addr, NULL, NULL,
				get_client_memptr(wlan_client, clnt_idx)->vlan_id);

			delete_wlan_client_qos_rule(mac_addr, get_client_memptr(wlan_client, clnt_idx)->vlan_id, IPA_IP_v4, NULL);
			delete_wlan_client_qos_rule(mac_addr, get_client_memptr(wlan_client, clnt_idx)->vlan_id, IPA_IP_v6, NULL);
			handle_wlan_client_down_evt(mac_addr, get_client_memptr(wlan_client, clnt_idx)->vlan_id);
			get_primary_client_memptr(wlan_primary_client, primary_clt_indx)->num_vlan_clients--;
			IPACMDBG_H("VLAN Clients left: %d\n",
				get_primary_client_memptr(wlan_primary_client, primary_clt_indx)->num_vlan_clients);
		}

	}

	for (; primary_clt_indx < num_wifi_client_tmp - 1; primary_clt_indx++)
	{
		get_primary_client_memptr(wlan_primary_client, primary_clt_indx)->p_hdr_info =
			get_primary_client_memptr(wlan_primary_client, (primary_clt_indx + 1))->p_hdr_info;

		memcpy(get_primary_client_memptr(wlan_primary_client, primary_clt_indx)->mac,
					 get_primary_client_memptr(wlan_primary_client, (primary_clt_indx + 1))->mac,
					 sizeof(get_primary_client_memptr(wlan_primary_client, primary_clt_indx)->mac));

		get_primary_client_memptr(wlan_primary_client, primary_clt_indx)->num_vlan_clients =
			get_primary_client_memptr(wlan_primary_client, (primary_clt_indx + 1))->num_vlan_clients;
	}
	IPACMDBG_H(" %d Primary wifi client deleted successfully \n", num_wifi_primary_client);
	num_wifi_primary_client = num_wifi_primary_client - 1;
	IPACMDBG_H(" Number of Primary wifi client: %d\n", num_wifi_primary_client);

	return IPACM_SUCCESS;
}


/*handle wlan iface down event*/
int IPACM_Wlan::handle_down_evt()
{
	int res = IPACM_SUCCESS, i, num_private_subnet_fl_rule, idx = 0;
	int wlan_pipe_index;
	uint32_t tcp_syn_filter_rule_hdl = 0;
	uint32_t *private_flt_rule_hdl = NULL;
	bool skip_flt_rule_del= false;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	struct wan_ioctl_lan_client_info *client_info;
#endif
#ifdef FEATURE_STATIC_POLICY
	ipacm_event_vlan_pdn *wandown_vlan_data;
	ipacm_cmd_q_data evt_data;
	int if_index = 0;
#endif

	IPACMDBG_H("WLAN ip-type: %d \n", ip_type);

#ifdef FEATURE_IPACM_UL_FIREWALL
	/* Clear IPv6 UL firewall rules: LAN pipe frag, catch all and FW rules if installed */
	 if (ip_type != IPA_IP_v4)
	 	IPACM_Lan::delete_uplink_filter_rule_ul(&iface_ul_firewall);
#endif

	/* no iface address up, directly close iface*/
	if (ip_type == IPACM_IP_NULL)
	{
		IPACMERR("Invalid iptype: 0x%x\n", ip_type);
		goto fail;
	}

	if ((is_if_svap || is_wlan_if_vlan) && (rx_prop && rx_prop->num_rx_props > 2)) {
		idx = 2;
		IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx pipe at idx %d \n", idx);
	}

	for(wlan_pipe_index=0;wlan_pipe_index<MAX_SUPPORTED_WLAN_PIPES;wlan_pipe_index++){
		if(rx_prop && wlan_ap_dflt_rules[wlan_pipe_index].src_pipe == rx_prop->rx[idx].src_pipe ){
			if (wlan_ap_dflt_rules[wlan_pipe_index].iface_cnt[ip_type] == 0 ) {
					IPACMDBG_H(" rules already deleted \n");
					return IPACM_SUCCESS;
				}
			if (ip_type == IPA_IP_MAX) {
				if (wlan_ap_dflt_rules[wlan_pipe_index].iface_cnt[IPA_IP_v4] == 0 &&
					wlan_ap_dflt_rules[wlan_pipe_index].iface_cnt[IPA_IP_v6] == 0) {
					IPACMDBG_H(" rules already deleted \n");
					return IPACM_SUCCESS;
				}
				wlan_ap_dflt_rules[wlan_pipe_index].iface_cnt[IPA_IP_v4]--;
				wlan_ap_dflt_rules[wlan_pipe_index].iface_cnt[IPA_IP_v6]--;
			}
			else{
				wlan_ap_dflt_rules[wlan_pipe_index].iface_cnt[ip_type]--;
			}

			if(wlan_ap_dflt_rules[wlan_pipe_index].iface_cnt[IPA_IP_v4] > 0 &&
				wlan_ap_dflt_rules[wlan_pipe_index].iface_cnt[IPA_IP_v6] > 0 ) {
				IPACMDBG_H(" Iface is disconnected \n");
				skip_flt_rule_del = true;
			}
			break;
		}
	}

#ifdef FEATURE_VLAN_MPDN
	if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
	{
		if(handle_vlan_phys_if_down())
		{
			IPACMERR("failed to handle interface down (static policy mode)\n");
			res = IPACM_FAILURE;
			goto fail;
		}
	}
	else
#endif
	{
		/* delete wan filter rule */
		if (IPACM_Wan::isWanUP(ipa_if_num) && rx_prop != NULL)
		{
			IPACMDBG_H("LAN IF goes down, backhaul type %d\n",
					IPACM_Wan::backhaul_is_sta_mode);
			IPACM_Lan::handle_wan_down(IPACM_Wan::backhaul_is_sta_mode);
		}

		if (IPACM_Wan::isWanUP_V6(ipa_if_num) && rx_prop != NULL)
		{
			IPACMDBG_H("LAN IF goes down, backhaul type %d\n",
					IPACM_Wan::backhaul_is_sta_mode);
			handle_wan_down_v6(IPACM_Wan::backhaul_is_sta_mode, false);
		}
	}
	IPACMDBG_H("finished deleting wan filtering rules\n ");

	/* Delete v4 filtering rules */
	if (ip_type != IPA_IP_v6 && rx_prop != NULL && !skip_flt_rule_del)
	{
		/* delete IPv4 icmp filter rules */
		res = delete_icmp_filter_rule(IPA_IP_v4);
		if (res == IPACM_FAILURE)
		{
			IPACMERR("delete_icmp_filter_rule failed\n");
			goto fail;
		}

		res = delete_dflt_filter_rules(IPA_IP_v4);
		if (res == IPACM_FAILURE)
		{
			IPACMERR("delete_dflt_filter_rules failed\n");
			goto fail;
		}
		if (ipa_if_cate == WLAN_IF && wlan_pipe_index<MAX_SUPPORTED_WLAN_PIPES ) {
			private_flt_rule_hdl = wlan_ap_dflt_rules[wlan_pipe_index].private_flt_rule_hdl[idx/2];
		}
		else {
			private_flt_rule_hdl = private_fl_rule_hdl[idx/2];
		}

		/* delete private-ipv4 filter rules */
#if defined(FEATURE_IPA_ANDROID) || defined(FEATURE_VLAN_MPDN)
		if(m_filtering.DeleteFilteringHdls(private_flt_rule_hdl, IPA_IP_v4, IPA_MAX_PRIVATE_SUBNET_ENTRIES + IPA_MAX_MTU_ENTRIES) == false)
		{
			IPACMERR("Error deleting private subnet IPv4 flt rules.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, IPA_MAX_PRIVATE_SUBNET_ENTRIES + IPA_MAX_MTU_ENTRIES);
#else
		num_private_subnet_fl_rule = IPACM_Iface::ipacmcfg->ipa_num_private_subnet > (IPA_MAX_PRIVATE_SUBNET_ENTRIES + IPA_MAX_MTU_ENTRIES)?
			(IPA_MAX_PRIVATE_SUBNET_ENTRIES + IPA_MAX_MTU_ENTRIES): IPACM_Iface::ipacmcfg->ipa_num_private_subnet;
		if(m_filtering.DeleteFilteringHdls(private_flt_rule_hdl, IPA_IP_v4, num_private_subnet_fl_rule) == false)
		{
			IPACMERR("Error deleting private subnet flt rules, aborting...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, num_private_subnet_fl_rule);
#endif
		IPACMDBG_H("Deleted private subnet v4 filter rules successfully.\n");
		if (ipa_if_cate == WLAN_IF && wlan_pipe_index<MAX_SUPPORTED_WLAN_PIPES ) {
			tcp_syn_filter_rule_hdl = wlan_ap_dflt_rules[wlan_pipe_index].tcp_syn_flt_rule_hdl[idx/2][IPA_IP_v4];
		}else {
			tcp_syn_filter_rule_hdl = tcp_syn_flt_rule_hdl[idx/2][IPA_IP_v4];
		}

		if(m_filtering.DeleteFilteringHdls(&tcp_syn_filter_rule_hdl, IPA_IP_v4, 1) == false)
		{
			IPACMERR("Error deleting tcp syn flt rule, aborting...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, 1);
		IPACMDBG_H("Deleted TCP syn v4 filter rules successfully.\n");
	}

	/* Delete v6 filtering rules */
	if (ip_type != IPA_IP_v4 && rx_prop != NULL && !skip_flt_rule_del)
	{
		/* delete icmp filter rules */
		res = delete_icmp_filter_rule(IPA_IP_v6);
		if (res == IPACM_FAILURE)
		{
			IPACMERR("delete_icmp_filter_rule failed\n");
			goto fail;
		}

		res = delete_dflt_filter_rules(IPA_IP_v6);
		if (res == IPACM_FAILURE)
		{
			IPACMERR("delete_dflt_filter_rules failed\n");
			goto fail;
		}

		if (ipa_if_cate == WLAN_IF && wlan_pipe_index<MAX_SUPPORTED_WLAN_PIPES ) {
			tcp_syn_filter_rule_hdl = wlan_ap_dflt_rules[wlan_pipe_index].tcp_syn_flt_rule_hdl[idx/2][IPA_IP_v6];
		} else {
			tcp_syn_filter_rule_hdl = tcp_syn_flt_rule_hdl[idx/2][IPA_IP_v6];
		}

		if(m_filtering.DeleteFilteringHdls(&tcp_syn_filter_rule_hdl, IPA_IP_v6, 1) == false)
		{
			IPACMERR("Error deleting tcp syn flt rule, aborting...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, 1);
		IPACMDBG_H("Deleted TCP syn v6 filter rules successfully.\n");

	}
	IPACMDBG_H("finished delete filtering rules\n ");

	/* Delete default v4 RT rule */
	if (ip_type != IPA_IP_v6)
	{
		IPACMDBG_H("Delete default v4 routing rules\n");
		if (m_routing.DeleteRoutingHdl(dft_rt_rule_hdl[0], IPA_IP_v4)
				== false)
		{
			IPACMERR("Routing rule deletion failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
	}

	/* Delete default v6 RT rule */
	if (ip_type != IPA_IP_v4)
	{
		IPACMDBG_H("Delete default v6 routing rules\n");
		/* May have multiple ipv6 iface-RT rules */
		for (i = 0; i < 2*num_dft_rt_v6; i++)
		{
			if (m_routing.DeleteRoutingHdl(dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES+i], IPA_IP_v6)
					== false)
			{
				IPACMERR("Routing rule deletion failed!\n");
				res = IPACM_FAILURE;
				goto fail;
			}
		}
	}
	IPACMDBG_H("finished deleting default RT rules\n ");

	/* Delete dummy rt rules for Svap iface */
	if (m_routing.DeleteRoutingHdl(svap_dummy_route_rule_v4_hdl, IPA_IP_v4)
		== false) {
		IPACMERR("svap_dummy_route_rule_v4_hdl deletion failed!\n");
	} else {
		IPACMDBG_H("svap_dummy_route_rule_v4_hdl deletd = 0x%x\n", svap_dummy_route_rule_v4_hdl);
		svap_dummy_route_rule_v4_hdl = 0;
	}

	if (m_routing.DeleteRoutingHdl(svap_dummy_route_rule_v6_hdl, IPA_IP_v6)
		== false) {
		IPACMERR("svap_dummy_route_rule_v6_hdl deletion failed!\n");
	} else {
		IPACMDBG_H("svap_dummy_route_rule_v6_hdl deletd = 0x%x\n", svap_dummy_route_rule_v6_hdl);
		svap_dummy_route_rule_v6_hdl = 0;
	}



	eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_DOWN, IPA_IP_MAX, NULL, NULL, NULL);
	/* del wlan client mac flt rules if any*/
	delete_wlan_mac_flt_rules();
	/* free the wlan clients cache */
	IPACMDBG_H("Free wlan clients cache\n");

	/* Delete private subnet*/
#ifdef FEATURE_IPA_ANDROID
	if (ip_type != IPA_IP_v6)
	{
		IPACMDBG_H("current IPACM private subnet_addr number(%d)\n", IPACM_Iface::ipacmcfg->ipa_num_private_subnet);
		IPACMDBG_H(" Delete IPACM private subnet_addr as: 0x%x \n", if_ipv4_subnet);
		if(IPACM_Iface::ipacmcfg->DelPrivateSubnet(if_ipv4_subnet, ipa_if_num) == false)
		{
			IPACMERR(" can't Delete IPACM private subnet_addr as: 0x%x \n", if_ipv4_subnet);
		}
	}
	/* reset the IPA-client pipe enum */
	handle_tethering_client(true, IPACM_CLIENT_WLAN);
#endif /* defined(FEATURE_IPA_ANDROID)*/

	neigh_cache.clear();
fail:
	/* clean wifi-client header, routing rules */
	/* clean wifi client rule*/
	IPACMDBG_H("left %d wifi clients need to be deleted \n ", num_wifi_client);
	for (i = 0; i < num_wifi_client; i++)
	{
		/* First reset NAT/IPv6CT rules and then route rules */
		HandleNeighIpAddrDelEvt(i);

		if (ast_update_needed())
		{
			if (delete_wlan_client_lan2lan_flt_rule(get_client_memptr(wlan_client, i)->mac, IPA_IP_v4))
			{
				IPACMERR("unable to delete v4 lan2lan flt rule for index: %d\n", i);
				res = IPACM_FAILURE;
			}

			if (delete_wlan_client_lan2lan_flt_rule(get_client_memptr(wlan_client, i)->mac, IPA_IP_v6))
			{
				IPACMERR("unable to delete v6 lan2lan flt rule for index: %d\n", i);
				res = IPACM_FAILURE;
			}
		}

		if (delete_default_qos_rtrules(i, IPA_IP_v4))
		{
			IPACMERR("unable to delete v4 default qos route rules for index: %d\n", i);
			res = IPACM_FAILURE;
		}

		if (delete_default_qos_rtrules(i, IPA_IP_v6))
		{
			IPACMERR("unable to delete v6 default qos route rules for index: %d\n", i);
			res = IPACM_FAILURE;
		}
#ifdef FEATURE_STATIC_POLICY
		if((IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
			&& (delete_pdn_dscp_wlan_rtrules(IPA_IP_v4, 2, i)))
		{
			IPACMERR("unable to delete v4 PDN DSCP route rules for index: %d\n", i);
			return IPACM_FAILURE;
		}

		if((IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
			&& (delete_pdn_dscp_wlan_rtrules(IPA_IP_v6, 2, i)))
		{
			IPACMERR("unable to delete v6 PDN DSCP route rules for index: %d\n", i);
			return IPACM_FAILURE;
		}
#endif
		IPACMDBG_H("Delete %d out of %d client header\n", i,  num_wifi_client);

		if(get_client_memptr(wlan_client, i)->ipv4_header_set == true)
		{
			if (m_header.DeleteHeaderHdl(get_client_memptr(wlan_client, i)->hdr_hdl_v4)
				== false)
			{
				res = IPACM_FAILURE;
			}
		}

		if(get_client_memptr(wlan_client, i)->ipv6_header_set == true)
		{
			if (m_header.DeleteHeaderHdl(get_client_memptr(wlan_client, i)->hdr_hdl_v6)
					== false)
			{
				res = IPACM_FAILURE;
			}
		}

		IPACMDBG_H("client %d has %d ipv6 with rt: %d, current total_v6=%d \n", i,
			get_client_memptr(wlan_client, i)->ipv6_set,
			get_client_memptr(wlan_client, i)->route_rule_set_v6,
			IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
		/* clean up the map and release the memory */
		for (auto it = rt_hdl_v6_list[i].begin(); it != rt_hdl_v6_list[i].end(); ++it)
		{
			IPACMDBG_H("v6 addr : 0x%08x:%08x:%08x:%08x\n",
				it->first[0], it->first[1], it->first[2], it->first[3]);
		}

		IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6 -= get_client_memptr(wlan_client, i)->ipv6_set;
		IPACMDBG_H("update ipa_num_clients_ipv6 = %d\n", IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
		get_client_memptr(wlan_client, i)->ipv6_set = 0;
		/* clear the map */
		rt_hdl_v6_list[i].clear();

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		if (get_client_memptr(wlan_client, i)->lan_stats_idx != -1)
		{
			/* Clear the lan client info. */
			client_info = (struct wan_ioctl_lan_client_info *)malloc(sizeof(struct wan_ioctl_lan_client_info));
			if (client_info == NULL)
			{
				IPACMERR("Unable to allocate memory\n");
				res = IPACM_FAILURE;
			}
			else
			{
				memset(client_info, 0, sizeof(struct wan_ioctl_lan_client_info));
				client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_WLAN;
				memcpy(client_info->mac,
						get_client_memptr(wlan_client, i)->mac,
						IPA_MAC_ADDR_SIZE);
				client_info->client_init = 0;
				client_info->client_idx = get_client_memptr(wlan_client, i)->lan_stats_idx;
				client_info->ul_src_pipe = (enum ipa_client_type) IPA_CLIENT_MAX;
#ifdef IPA_HW_FNR_STATS
				if (IPACM_Wan::ipacmcfg->hw_fnr_stats_support)
				{
					client_info->ul_cnt_idx = get_client_memptr(wlan_client, i)->ul_cnt_idx;
					client_info->dl_cnt_idx = get_client_memptr(wlan_client, i)->dl_cnt_idx;
					get_client_memptr(wlan_client, i)->ul_cnt_idx = -1;
					get_client_memptr(wlan_client, i)->dl_cnt_idx = -1;
					get_client_memptr(wlan_client, i)->index_populated = false;
					pthread_mutex_lock(&IPACM_Wan::ipacmcfg->cnt_idx_lock);
					if (IPACM_Wan::ipacmcfg->reset_cnt_idx(client_info->ul_cnt_idx, false))
						IPACMERR("Failed to reset counter index = %u\n", client_info->ul_cnt_idx);
					pthread_mutex_unlock(&IPACM_Wan::ipacmcfg->cnt_idx_lock);
				}
#endif //IPA_HW_FNR_STATS
				if (rx_prop)
				{
					client_info->ul_src_pipe = rx_prop->rx[0].src_pipe;
				}
				if (clear_lan_client_info(client_info))
				{
					res = IPACM_FAILURE;
				}
				free(client_info);
			}
			get_client_memptr(wlan_client, i)->lan_stats_idx = -1;
		}
#endif
	} /* end of for loop */

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		/* Reset the lan stats indices belonging to this object. */
		if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable)
		{
			IPACMDBG_H("Resetting lan stats indices. \n");
			reset_lan_stats_index();
		}
#endif

	/* check software routing fl rule hdl */
	if (softwarerouting_act == true && rx_prop != NULL )
	{
		IPACMDBG_H("Delete sw routing filtering rules\n");
		IPACM_Iface::handle_software_routing_disable();
	}
	IPACMDBG_H("finished delete software-routing filtering rules\n ");

#ifdef FEATURE_STATIC_POLICY
	//delete static policy rules here if mode is enabled
	if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
	{
		if (handle_static_policy_rule_delete())
		{
			IPACMERR("failed to delete static policy rules for v4.\n");
		}

		if_index = IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].netlink_interface_index;

		wandown_vlan_data = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
		if(wandown_vlan_data == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			res = IPACM_FAILURE;
			goto end;
		}
		memset(wandown_vlan_data, 0, sizeof(ipacm_event_vlan_pdn));
		wandown_vlan_data->iptype = IPA_IP_MAX;
		wandown_vlan_data->VlanID = IPA_STATIC_POLICY_VLAN_ID + if_index;

		evt_data.event = IPA_HANDLE_LAN_VLAN_PDN_DOWN_STATIC;
		evt_data.evt_data = (void *)wandown_vlan_data;
		IPACM_EvtDispatcher::PostEvt(&evt_data);
		IPACMDBG_H("Posted event IPA_HANDLE_LAN_VLAN_PDN_DOWN_STATIC with "
			"iptype %d and vlan_id:%d\n", wandown_vlan_data->iptype,
			wandown_vlan_data->VlanID);
	}
#endif
end:
	for (i = 0; i < num_wifi_client; i++)
	{
		if(get_client_memptr(wlan_client, i)->p_hdr_info != NULL)
		{
			free(get_client_memptr(wlan_client, i)->p_hdr_info);
		}
	}
	if(wlan_client != NULL)
	{
		free(wlan_client);
		wlan_client = NULL;
	}

	is_active = false;
	post_del_self_evt();

	return res;
}

/*handle reset wifi-client rt-rules */
int IPACM_Wlan::handle_wlan_client_reset_rt(ipa_ip_type iptype)
{
	int i, res = IPACM_SUCCESS;

	/* clean wifi-client routing rules */
	IPACMDBG_H("left %d wifi clients to reset ip-type(%d) rules \n ", num_wifi_client, iptype);

	for (i = 0; i < num_wifi_client; i++)
	{
		/* Reset RT rules */
		res = delete_default_qos_rtrules(i, iptype);
		if (res != IPACM_SUCCESS)
		{
			IPACMERR("Failed to delete old iptype(%d) rules.\n", iptype);
			return res;
		}
#ifdef FEATURE_STATIC_POLICY
		if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
		{
			delete_pdn_dscp_wlan_rtrules(iptype, 2, i);
		}
#endif
		/* Delete QOS rules. */
		if (IPACM_Iface::ipacmcfg->ipacm_qos_enable)
			delete_client_qos_rule(get_client_memptr(wlan_client, i)->mac,
				0, iptype, NULL);
		/* Reset ip-address */
		if(iptype == IPA_IP_v4)
		{
			get_client_memptr(wlan_client, i)->ipv4_set = false;
		}
		else
		{
			get_client_memptr(wlan_client, i)->ipv6_set = 0;
			/* clear the map of client */
			rt_hdl_v6_list[i].clear();
			if (ast_update_needed())
				delete_wlan_client_lan2lan_flt_rule(get_client_memptr(wlan_client, i)->mac, IPA_IP_v6);
		}
	} /* end of for loop */
	return res;
}

void IPACM_Wlan::handle_SCC_MCC_switch(ipa_ip_type iptype)
{
	struct ipa_ioc_mdfy_rt_rule *rt_rule = NULL;
	struct ipa_rt_rule_mdfy *rt_rule_entry;
	uint32_t tx_index;
	int wlan_index;
	const int NUM = 1;
	int num_wifi_client_tmp = IPACM_Wlan::num_wifi_client;
	bool isAdded = false;

	if (tx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return;
	}

	if (rt_rule == NULL)
	{
		rt_rule = (struct ipa_ioc_mdfy_rt_rule *)
			calloc(1, sizeof(struct ipa_ioc_mdfy_rt_rule) +
					NUM * sizeof(struct ipa_rt_rule_mdfy));

		if (rt_rule == NULL)
		{
			PERROR("Error Locate ipa_ioc_mdfy_rt_rule memory...\n");
			return;
		}

		rt_rule->commit = 0;
		rt_rule->num_rules = NUM;
		rt_rule->ip = iptype;
	}
	rt_rule_entry = &rt_rule->rules[0];

	/* modify ipv4 routing rule */
	if (iptype == IPA_IP_v4)
	{
		for (wlan_index = 0; wlan_index < num_wifi_client_tmp; wlan_index++)
		{
			IPACMDBG_H("wlan client index: %d, ip-type: %d, ipv4_set:%d, ipv4_rule_set:%d \n",
					wlan_index, iptype,
					get_client_memptr(wlan_client, wlan_index)->ipv4_set,
					get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4);

			if (get_client_memptr(wlan_client, wlan_index)->power_save_set == true ||
					get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4 == false)
			{
				IPACMDBG_H("client %d route rules not set\n", wlan_index);
				continue;
			}

			IPACMDBG_H("Modify client %d route rule\n", wlan_index);
			for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
				/* skip to the next tx index if the client type and hdr_l2_type are not matching */
#ifdef IPA_HDR_L2_802_1Q_AST
				if ((get_client_memptr(wlan_client, wlan_index)->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q_AST && tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q)) ||
					(!get_client_memptr(wlan_client, wlan_index)->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q_AST || tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q)))
				{
					continue;
				}
#endif

				if (iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d ip-type not matching: %d ignore\n",
							tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}

				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", wlan_index,
						get_client_memptr(wlan_client, wlan_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
						wlan_index,
						get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4);

				if (IPACM_Iface::ipacmcfg->isMCC_Mode)
				{
					IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
							tx_prop->tx[tx_index].alt_dst_pipe);
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
				}
				else
				{
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
				}

				memcpy(&rt_rule_entry->rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry->rule.attrib));

				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
				rt_rule_entry->rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4;

				rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(wlan_client, wlan_index)->v4_addr;
				rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;

				IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
						get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4, iptype);

				rt_rule_entry->rt_rule_hdl =
					get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4;

				if (false == m_routing.ModifyRoutingRule(rt_rule))
				{
					IPACMERR("Routing rule modify failed!\n");
					free(rt_rule);
					return;
				}
				isAdded = true;
			}

		}
	}

	/* modify ipv6 routing rule */
	if (iptype == IPA_IP_v6)
	{
		for (wlan_index = 0; wlan_index < num_wifi_client_tmp; wlan_index++)
		{

			IPACMDBG_H("wlan client index: %d, ip-type: %d, ipv6_set:%d, ipv6_rule_num:%d \n", wlan_index, iptype,
					get_client_memptr(wlan_client, wlan_index)->ipv6_set,
					get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6);

			if (get_client_memptr(wlan_client, wlan_index)->power_save_set == true ||
					(get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6 <
					 get_client_memptr(wlan_client, wlan_index)->ipv6_set) )
			{
				IPACMDBG_H("client %d route rules not set\n", wlan_index);
				continue;
			}

			IPACMDBG_H("Modify client %d route rule\n", wlan_index);
			for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
#ifdef IPA_HDR_L2_802_1Q_AST
				/* skip to the next tx index if the client type and hdr_l2_type are not matching */
				if ((get_client_memptr(wlan_client, wlan_index)->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q_AST && tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q)) ||
					(!get_client_memptr(wlan_client, wlan_index)->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q_AST || tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q)))
				{
					continue;
				}
#endif
				if (iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d ip-type not matching: %d Ignore\n",
							tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}

				for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end(); ++it)
				{
					IPACMDBG_H("client(%d): v6 header handle:(0x%x)\n",
							wlan_index,
							get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6);

					if (IPACM_Iface::ipacmcfg->isMCC_Mode)
					{
						IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
								tx_prop->tx[tx_index].alt_dst_pipe);
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
					}
					else
					{
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
					}

					memcpy(&rt_rule_entry->rule.attrib,
							&tx_prop->tx[tx_index].attrib,
							sizeof(rt_rule_entry->rule.attrib));

					rt_rule_entry->rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6;
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;

					rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = it->first[0];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = it->first[1];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = it->first[2];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = it->first[3];
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;

					rt_rule_entry->rt_rule_hdl = it->second.hdl_v6[tx_index].rt_rule_hdl_v6;

					if (false == m_routing.ModifyRoutingRule(rt_rule))
					{
						IPACMERR("Routing rule modify failed!\n");
						free(rt_rule);
						return;
					}
					rt_rule_entry->rt_rule_hdl = it->second.hdl_v6[tx_index].rt_rule_hdl_v6_wan;
					if (false == m_routing.ModifyRoutingRule(rt_rule))
					{
						IPACMERR("Routing rule modify failed!\n");
						free(rt_rule);
						return;
					}
					isAdded = true;
				}
			}

		}
	}


	if (isAdded)
	{
		if (false == m_routing.Commit(iptype))
		{
			IPACMERR("Routing rule modify commit failed!\n");
			free(rt_rule);
			return;
		}

		IPACMDBG("Routing rule modified successfully \n");
	}

	if(rt_rule)
	{
		free(rt_rule);
	}
	return;
}

void IPACM_Wlan::eth_bridge_handle_wlan_mode_switch()
{
	int i;

	/* ====== post events to mimic WLAN interface goes down/up when AP mode is changing ====== */

	/* first post IFACE_DOWN event */
	eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_DOWN, IPA_IP_MAX, NULL, NULL, dev_name);

	/* then post IFACE_UP event */
	if(ip_type == IPA_IP_v4 || ip_type == IPA_IP_MAX)
	{
		eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_UP, IPA_IP_v4, NULL, NULL, dev_name);
	}
	if(ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX)
	{
		eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_UP, IPA_IP_v6, NULL, NULL, dev_name);
	}

	/* at last post CLIENT_ADD event */
	for(i = 0; i < num_wifi_client; i++)
	{
		eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_ADD, IPA_IP_MAX,
			get_client_memptr(wlan_client, i)->mac, NULL, dev_name);
	}

	return;
}

void IPACM_Wlan::HandleNeighIpAddrDelEvt(int clt_indx)
{
	uint32_t ipv6_temp[4] = {0};
	if (get_client_memptr(wlan_client, clt_indx)->ipv4_set)
	{
		CtList->HandleNeighIpAddrDelEvt(get_client_memptr(wlan_client, clt_indx)->v4_addr);
	}

	if(IPACM_Iface::ipacmcfg->wlan_vlan_mpdn_enabled || IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
	{
		for (auto it = rt_hdl_v6_list[clt_indx].begin(); it != rt_hdl_v6_list[clt_indx].end();++it)
		{
			std::copy(std::begin(it->first), std::end(it->first), std::begin(ipv6_temp));
			CtList->HandleNeighIpAddrDelEvt_v6(Ipv6IpAddress(ipv6_temp, false));
		}
	}
}

bool IPACM_Wlan::is_guest_ap()
{
	return m_is_guest_ap;
}

bool IPACM_Wlan::ast_update_needed()
{
	return ast_update;
}

#if defined(FEATURE_IPACM_PER_CLIENT_STATS) || defined(IPA_WDI_AST_UPDATE)
#ifdef IPA_V6_UL_WL_FIREWALL_HANDLE

/*
 * Config and installing (UL + v6 ul wl firewall) rules on
 * AP lan rx table with replication effort.
 * 1. delete UL rules
 * 2. Have v6 Q6 UL rules
 * 3. Prepare rules with replicate effort
 * 4. Install the modified rules.
 * R --> Indicate the rule to be replicated
 * Eg. I/p ==> 1, 2(R), 3, 4(R), 5 || with 2 UL firewall rules
 *     O/p ==> 1, 2(1), 2(2), 3, 4(1), 4(2), 5
 * Send the indices of all rules to Q6.
 */

int IPACM_Wlan::config_dft_firewall_rules_ul_ex(IPACM_firewall_conf_t* firewall_conf, int vid)
{
	ipacm_ext_prop* ext_prop = NULL;
	int fd = 0, i = 0, j = 0, k = 0, wlan_idx = 0;
	int ret = 0, len = 0, index = 0, idx = 0;
	struct ipa_fltr_installed_notif_req_msg_v01 flt_index;
	int q6_v6_ul_rules = 0, replicate_rules = 0;
	int v6_ul_wl_rules = 0, total_rules = 0;
	struct ipa_ioc_add_flt_rule *pFilteringTable = NULL;
	struct ipa_flt_rule_add flt_rule_entry, flt_rule_entry_r, flt_rule_entry_fw, temp_rule;
	struct ipa_ioc_add_flt_rule_v2 *pFilteringTable_v2 = NULL;
	struct ipa_flt_rule_add_v2 flt_rule_entry_v2;

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	if ((is_if_svap || is_wlan_if_vlan) && (rx_prop && rx_prop->num_rx_props > 2)) {
		idx = 2;
		IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx pipe at idx %d \n", idx);
	}

	/* 1. Delete: Already expected to be taken care */
	/* 2: ext_prop will have a Q6 UL rules*/
	ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);

	if(ext_prop == NULL || ext_prop->num_ext_props <= 0)
	{
		IPACMDBG_H("No extended property.\n");
		return IPACM_SUCCESS;
	}

	fd = open(IPA_DEVICE_NAME, O_RDWR);
	if (0 == fd)
	{
		IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	if (ext_prop->num_ext_props > MAX_WAN_UL_FILTER_RULES)
	{
		IPACMERR("number of modem UL rules > MAX_WAN_UL_FILTER_RULES, aborting...\n");
		close(fd);
		return IPACM_FAILURE;
	}

	/* 3: Prepare rules with replicate effort*/
	/*
	 * Calc total number of rules
	 * Eg:
	 * N --> Q6 # number of UL rules
	 * M --> Replicate # rule (M <= N)
	 * X --> v6 UL WL rule
	 * Total = ((M * X) + (N - M))
	 *
	 */
	/* Q6 # of v6 UL rules */
	q6_v6_ul_rules = ext_prop->num_ext_props;
	IPACMDBG_H("q6_v6_ul_rules %d\n", q6_v6_ul_rules);

	/* Get replicate count */
	for (i = 0; i < q6_v6_ul_rules; i++)
		if (ext_prop->prop[i].replicate_needed == true)
			replicate_rules++;

	IPACMDBG_H("replicate_rules %d\n", replicate_rules);

	/* Calc v6 UL WL rule*/
	for (i = 0; i < firewall_conf->num_extd_firewall_entries; i++)
	{
		if (firewall_conf->extd_firewall_entries[i].ip_vsn == 6 &&
				firewall_conf->extd_firewall_entries[i].firewall_direction
				== IPACM_MSGR_UL_FIREWALL
#ifdef FEATURE_IPV6_NAT
			// IPV6 NAT FW rule, valid only when ipv6 NAT enabled (and then we don't install FW rules)
			&& !firewall_conf->extd_firewall_entries[i].IPV6NatEnabledfw
#endif
		)
		{
			v6_ul_wl_rules++;
			if (firewall_conf->extd_firewall_entries[i].attrib.u.v6.next_hdr ==
				IPACM_FIREWALL_IPPROTO_TCP_UDP)
			{
				v6_ul_wl_rules++; //rule should be installed for TCP and UDP both
			}
		}
	}

	IPACMDBG_H("v6_ul_wl_rules %d\n", v6_ul_wl_rules);

	if ((v6_ul_wl_rules == 0) || (replicate_rules == 0))
	{
		/*
		 * There is no rule to WL
		 * Dont install any UL rules
		 * Take all in exception path
		 * Will be dropped in linux kernel
		 */
		modem_ul_v6_set[0] = true;
		ret = IPACM_SUCCESS;
		goto close_fd;
	}

	total_rules = ((replicate_rules * v6_ul_wl_rules) +
			(q6_v6_ul_rules - replicate_rules));

	IPACMDBG_H("total_rules %d\n", total_rules);

	/* ***** */
	memset(&flt_index, 0, sizeof(flt_index));

	flt_index.source_pipe_index = ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, rx_prop->rx[0].src_pipe);
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	if (tx_prop && IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable)
	{
		flt_index.dst_pipe_id_valid = 1;
		flt_index.dst_pipe_id_len = tx_prop->num_tx_props;
		for (i = 0; i < tx_prop->num_tx_props && i < QMI_IPA_MAX_CLIENT_DST_PIPES; i++)
		{
			flt_index.dst_pipe_id[i] = ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, tx_prop->tx[i].dst_pipe);
		}
	}
#endif
	flt_index.install_status = IPA_QMI_RESULT_SUCCESS_V01;
	flt_index.rule_id_ex_valid = 1;
	flt_index.rule_id_ex_len = total_rules - 1;

	flt_index.embedded_pipe_index_valid = 1;
	flt_index.embedded_pipe_index = ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, IPA_CLIENT_APPS_LAN_WAN_PROD);
	flt_index.retain_header_valid = 1;
	flt_index.retain_header = 0;
	flt_index.embedded_call_mux_id_valid = 1;
	flt_index.embedded_call_mux_id = IPACM_Iface::ipacmcfg->GetQmapId();

	len = sizeof(struct ipa_ioc_add_flt_rule) + total_rules * sizeof(struct ipa_flt_rule_add);
	pFilteringTable = (struct ipa_ioc_add_flt_rule*)malloc(len);
	if (pFilteringTable == NULL)
	{
		IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
		close(fd);
		return IPACM_FAILURE;
	}
	memset(pFilteringTable, 0, len);

	pFilteringTable->commit = 1;
	pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
	pFilteringTable->global = false;
	pFilteringTable->ip = IPA_IP_v6;
	pFilteringTable->num_rules = total_rules;

	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
	flt_rule_entry.at_rear = true;
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;
	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.eq_attrib_type = 1;

	index = IPACM_Iface::ipacmcfg->getFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6);

	/* Traverse all q6_v6_ul_rules */
	for (i = 0; i < q6_v6_ul_rules; i++)
	{
		memcpy(&flt_rule_entry.rule.eq_attrib,
				&ext_prop->prop[i].eq_attrib,
				sizeof(ext_prop->prop[i].eq_attrib));
		flt_rule_entry.rule.rt_tbl_idx = ext_prop->prop[i].rt_tbl_idx;
		flt_rule_entry.rule.hashable = ext_prop->prop[i].is_rule_hashable;
		flt_rule_entry.rule.rule_id = ext_prop->prop[i].rule_id;

		if(!idx && rx_prop->rx[idx].attrib.attrib_mask & IPA_FLT_META_DATA) //turn on meta-data equation
		{
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<9);
			flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.value |= rx_prop->rx[idx].attrib.meta_data;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.mask |= rx_prop->rx[idx].attrib.meta_data_mask;
		}
		/* Is this rule needed replication w.r.t v6 UL WL rule ?*/
		if (ext_prop->prop[i].replicate_needed == true)
		{
			/* Replicate logic */
			for (j = 0; j < firewall_conf->num_extd_firewall_entries; j++)
			{
				if (firewall_conf->extd_firewall_entries[j].ip_vsn == 6 &&
						firewall_conf->extd_firewall_entries[j].firewall_direction
						== IPACM_MSGR_UL_FIREWALL)
				{
#ifdef FEATURE_IPV6_NAT
					// IPV6 NAT FW rule, valid only when ipv6 NAT enabled (and then we don't install FW rules)
					if(firewall_conf->extd_firewall_entries[i].IPV6NatEnabledfw)
						continue;
#endif
					memset(&flt_rule_entry_fw, 0, sizeof(struct ipa_flt_rule_add));
					flt_rule_entry_fw.at_rear = 1;
					flt_rule_entry_fw.flt_rule_hdl = -1;
					flt_rule_entry_fw.status = -1;
					flt_rule_entry_fw.rule.hashable = true;
					flt_rule_entry_fw.rule.eq_attrib_type = 1;

					flt_rule_entry.rule.rt_tbl_hdl =
						IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.hdl;

					memcpy(&flt_rule_entry_fw.rule.attrib,
							&firewall_conf->extd_firewall_entries[j].attrib,
							sizeof(struct ipa_rule_attrib));

					flt_rule_entry_fw.rule.attrib.attrib_mask |= rx_prop->rx[idx].attrib.attrib_mask;
					flt_rule_entry_fw.rule.attrib.attrib_mask &= ~IPA_FLT_META_DATA;
					flt_rule_entry_fw.rule.attrib.meta_data_mask = rx_prop->rx[idx].attrib.meta_data_mask;
					flt_rule_entry_fw.rule.attrib.meta_data = rx_prop->rx[idx].attrib.meta_data;

					memcpy(&temp_rule.rule.attrib,
							&flt_rule_entry_fw.rule.attrib,
							sizeof(struct ipa_rule_attrib));

					flt_rule_entry_fw.rule.attrib.u.v6.src_addr[3] =
						temp_rule.rule.attrib.u.v6.src_addr[0];
					flt_rule_entry_fw.rule.attrib.u.v6.src_addr[2] =
						temp_rule.rule.attrib.u.v6.src_addr[1];
					flt_rule_entry_fw.rule.attrib.u.v6.src_addr[1] =
						temp_rule.rule.attrib.u.v6.src_addr[2];
					flt_rule_entry_fw.rule.attrib.u.v6.src_addr[0] =
						temp_rule.rule.attrib.u.v6.src_addr[3];

					flt_rule_entry_fw.rule.attrib.u.v6.src_addr_mask[3] =
						temp_rule.rule.attrib.u.v6.src_addr_mask[0];
					flt_rule_entry_fw.rule.attrib.u.v6.src_addr_mask[2] =
						temp_rule.rule.attrib.u.v6.src_addr_mask[1];
					flt_rule_entry_fw.rule.attrib.u.v6.src_addr_mask[1] =
						temp_rule.rule.attrib.u.v6.src_addr_mask[2];
					flt_rule_entry_fw.rule.attrib.u.v6.src_addr_mask[0] =
						temp_rule.rule.attrib.u.v6.src_addr_mask[3];

					/* check if the rule is define as TCP/UDP */
					if (firewall_conf->extd_firewall_entries[j].attrib.u.v6.next_hdr == IPACM_FIREWALL_IPPROTO_TCP_UDP)
					{
						/* insert TCP rule*/
						flt_rule_entry_fw.rule.attrib.u.v6.next_hdr = IPACM_FIREWALL_IPPROTO_TCP;

						/* Actual replication happens here*/
						if (replicate_flt_rule(&flt_rule_entry_r, &flt_rule_entry, &flt_rule_entry_fw) == false)
							continue;
						memcpy(&pFilteringTable->rules[k], &flt_rule_entry_r, sizeof(flt_rule_entry));
						IPACMDBG_H("Modem UL filtering rule %d has index %d\n", i, index);
						flt_index.rule_id_ex[k] = ext_prop->prop[i].rule_id;
						index++; k++;

						/* insert UDP rule*/
						flt_rule_entry_fw.rule.attrib.u.v6.next_hdr = IPACM_FIREWALL_IPPROTO_UDP;

						/* Actual replication happens here*/
						if (replicate_flt_rule(&flt_rule_entry_r, &flt_rule_entry, &flt_rule_entry_fw) == false)
							continue;
						memcpy(&pFilteringTable->rules[k], &flt_rule_entry_r, sizeof(flt_rule_entry));
						IPACMDBG_H("Modem UL filtering rule %d has index %d\n", i, index);
						flt_index.rule_id_ex[k] = ext_prop->prop[i].rule_id;
						index++; k++;
					}
					else
					{
						/* Actual replication happens here*/
						if (replicate_flt_rule(&flt_rule_entry_r, &flt_rule_entry, &flt_rule_entry_fw) == false)
							continue;
						IPACMDBG_H("Modem UL filtering rule %d has index %d\n", i, index);
						memcpy(&pFilteringTable->rules[k], &flt_rule_entry_r, sizeof(flt_rule_entry));
						flt_index.rule_id_ex[k] = ext_prop->prop[i].rule_id;
						index++; k++;
					}
				} /* if loop -->WL rule is there */
			} /* for loop */
		}
		else
		{	/* No? just install as it is */
			flt_rule_entry.rule.action = IPA_PASS_TO_EXCEPTION;
			flt_rule_entry.rule.rt_tbl_idx = 0;
			memcpy(&pFilteringTable->rules[k], &flt_rule_entry, sizeof(flt_rule_entry));
			IPACMDBG_H("Modem UL filtering rule %d has index %d\n", i, index);
			flt_index.rule_id_ex[k] = ext_prop->prop[i].rule_id;
			index++; k++;
		}
	}

	if(false == m_filtering.SendFilteringRuleIndex(&flt_index))
	{
		IPACMERR("Error sending filtering rule index, aborting...\n");
		ret = IPACM_FAILURE;
		goto alloc_fail;
	}


#if defined(FEATURE_IPACM_PER_CLIENT_STATS) && defined(IPA_HW_FNR_STATS)
	/* Install v6 ul firewall rules per client*/
	/************************/
#if 0
	/* Catch-all rule*/
	len = sizeof(struct ipa_ioc_add_flt_rule_v2);

	pFilteringTable_v2 = (struct ipa_ioc_add_flt_rule_v2*)malloc(len);
	if (pFilteringTable_v2 == NULL)
	{
		IPACMERR("Error ipa_ioc_add_flt_rule_v2 memory...\n");
		ret = IPACM_FAILURE;
		goto alloc_fail;
	}
	memset(pFilteringTable_v2, 0, len);

	pFilteringTable_v2->rules = (uintptr_t)calloc(1, sizeof(struct ipa_flt_rule_add_v2));
	if (!pFilteringTable_v2->rules)
	{
		IPACMERR("Failed to allocate memory for filtering rules\n");
		ret = IPACM_FAILURE;
		free(pFilteringTable_v2);
		goto alloc_fail;
	}
	pFilteringTable_v2->commit = 1;
	pFilteringTable_v2->ep = rx_prop->rx[idx].src_pipe;
	pFilteringTable_v2->global = false;
	pFilteringTable_v2->ip = IPA_IP_v6;
	pFilteringTable_v2->num_rules = 1;
	pFilteringTable_v2->flt_rule_size = sizeof(struct ipa_flt_rule_add_v2);

	memset(&flt_rule_entry_v2, 0, sizeof(struct ipa_flt_rule_add_v2)); // Zero All Fields
	flt_rule_entry_v2.at_rear = true;
	flt_rule_entry_v2.flt_rule_hdl = -1;
	flt_rule_entry_v2.status = -1;
	flt_rule_entry_v2.rule.retain_hdr = 1;

	flt_rule_entry_v2.rule.action = IPA_PASS_TO_EXCEPTION;
	memcpy((void *)pFilteringTable_v2->rules, &flt_rule_entry_v2, sizeof(flt_rule_entry_v2));

	if(false == m_filtering.AddFilteringRule_v2(pFilteringTable_v2))
	{
		IPACMERR("Error Adding RuleTable to Filtering, aborting...\n");
		ret = IPACM_FAILURE;
		free((void *)pFilteringTable_v2->rules);
		free(pFilteringTable_v2);
		goto alloc_fail;
	}
	else
	{
			wan_ul_fl_rule_hdl_v6[num_wan_ul_fl_rule_v6] =
				((struct ipa_flt_rule_add_v2 *)pFilteringTable_v2->rules)[i].flt_rule_hdl;
			num_wan_ul_fl_rule_v6++;
			IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, 1);
	}
#endif
	/*All rules installation */
	num_wan_ul_fl_rule_v6[0] = pFilteringTable->num_rules;
	for (wlan_idx = 0; wlan_idx < num_wifi_client; wlan_idx++)
	{
		install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v6, IPACM_Wan::getXlat_Mux_Id(),
			get_client_memptr(wlan_client, wlan_idx)->mac,
			get_client_memptr(wlan_client, wlan_idx)->ul_cnt_idx,
			pFilteringTable, true);
	}
	/************************/
#else
	num_wan_ul_fl_rule_v6[0] = pFilteringTable->num_rules;
#endif

alloc_fail:
	free(pFilteringTable);
close_fd:
	close(fd);
	return ret;
}

int IPACM_Wlan::disable_dft_firewall_rules_ul_ex_per_wlan_client(int vid)
{
	int ret;

	/* for firewall change event, install original rules */
	if (IPACM_Wan::isWanUP_V6(ipa_if_num))
	{
#ifdef IPA_HW_FNR_STATS
		/* Install Q6 UL rules for all the clients. */
		IPACMDBG_H("Install original per client V6 UL filter rules \n");
		ret = install_uplink_filter_rule(IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6), IPA_IP_v6, IPACM_Iface::ipacmcfg->GetQmapId());
		if (ret == IPACM_FAILURE)
		{
			IPACMDBG_H(" failed to install per client rules for V6 UL\n");
			return ret;
		}
#endif // IPA_HW_FNR_STATS
	}

	if(IPACM_Wan::set_pdn_num_fw_rules_by_vid(vid, 0))
	{
		IPACMERR("failed setting num of Q6 rules for VID %d\n", vid);
		return IPACM_FAILURE;
	}
	return IPACM_SUCCESS;
}

/*Configure v6 ul rules for wlan clients */
void IPACM_Wlan::configure_v6_ul_firewall_wlan()
{
	IPACM_firewall_conf_t *firewall_config = NULL;
	int default_vid = 0;

	if (IPACM_Iface::ipacmcfg->ipv6_nat_enable)
	{
		IPACMDBG_H("IPv6 NAT is enable. Don't configure firewall rule\n");
		return;
	}

	if(IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
	{
		/* IPACM_Lan already handles lan_stats disabled */
		configure_v6_ul_firewall();
		return;
	}

	/*Drop rules: First of all clear LAN pipe frag, catch all and FW rules if installed */
	delete_uplink_filter_rule_ul(&iface_ul_firewall);

	/* now read XML and rebuild FW for all PDNs */
	if(IPACM_Wan::read_firewall_filter_rules_ul())
	{
		IPACMERR("failed configuring UL firewall\n");
		return;
	}

#ifdef IPA_V6_UL_WL_FIREWALL_HANDLE
	/* Delete Q6 UL rules of clients */
	delete_uplink_filter_rule(IPA_IP_v6);
#endif

	if(IPACM_Wan::isWanUP_V6(ipa_if_num))
	{
		firewall_config = IPACM_Wan::get_default_profile_firewall_conf_ul(&default_vid);
		if(!firewall_config)
		{
			IPACMERR("failed getting default profile config\n");
			return;
		}

		if((firewall_config->firewall_enable == true) &&
			((!firewall_config->rule_action_accept) ||
			(IPACM_Wan::backhaul_is_sta_mode == true)))
		{
			/* Insert original rules back*/
			disable_dft_firewall_rules_ul_ex_per_wlan_client(default_vid);
			/* Insert Drop rules */
			config_dft_firewall_rules_ul(firewall_config, &iface_ul_firewall, default_vid);
			return;
		}

		if(firewall_config->firewall_enable)
		{
			/* LTE && whitelist  */

			IPACMDBG_H("firewall for vid %d shall be installed on Q6 side\n", default_vid);
			/* Configure and send the firewall filter table to Q6*/
			if(config_dft_firewall_rules_ul_ex(firewall_config, default_vid))
			{
				IPACMERR("failed configuring default profile UL firewall, vid %d\n", default_vid);
			}
		}
		else
		{
			IPACMDBG_H("default profile firewall is disabled, disable Q6 firewall\n");
			disable_dft_firewall_rules_ul_ex_per_wlan_client(default_vid);
		}
	}
#ifdef FEATURE_VLAN_MPDN
#if 0
		uint16_t Ids[IPA_MAX_NUM_HW_PDNS];

		if(IPACM_Iface::ipacmcfg->get_iface_vlan_ids(dev_name, Ids))
		{
			IPACMERR("failed getting vlan ids for iface %s\n", dev_name);
			return;
		}

		for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
		{
			if(Ids[i] != 0)
			{
				if(Ids[i] == default_vid)
				{
					IPACMDBG_H("already handled default pdn, skip...\n");
					continue;
				}
				firewall_config = IPACM_Wan::get_firewall_conf_by_vid_ul(Ids[i]);
				if(!firewall_config)
				{
					IPACMDBG_H("no v6 vlan up PDN for Id %d\n", Ids[i]);
					continue;
				}
				if(firewall_config->firewall_enable)
				{
					if(configure_v6_ul_firewall_one_profile(firewall_config, false, Ids[i]))
					{
						IPACMERR("failed configuring default profile UL firewall, vid %d\n", Ids[i]);
					}
				}
				else
				{
					IPACMDBG_H("firewall is disabled for VID %d, disable Q6 firewall\n",Ids[i]);
					disable_dft_firewall_rules_ul_ex(Ids[i]);
				}
			}
		}
#endif
#endif //FEATURE_VLAN_MPDN

}
#endif //IPA_V6_UL_WL_FIREWALL_HANDLE

/* install UL filter rule from Q6 per client */
int IPACM_Wlan::install_uplink_filter_rule_per_client
(
	ipacm_ext_prop* prop,
	ipa_ip_type iptype,
	uint8_t xlat_mux_id,
	uint8_t *mac_addr,
	uint16_t ta_peer_id
)
{
	ipa_flt_rule_add flt_rule_entry;
	int len = 0, cnt, ret = IPACM_SUCCESS;
	ipa_ioc_add_flt_rule *pFilteringTable;
	int fd;
	int i, index = 0, idx = 0;
	uint32_t value = 0;
	int clnt_indx;
	uint8_t num_offset_meq_128;
	struct ipa_ipfltr_mask_eq_128 *offset_meq_128 = NULL;
	int total_rules, v6_xlat_ul_rules = 0;
	enum ipa_flt_action action_cache;

	IPACMDBG_H("Set modem UL flt rules\n");

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	if (is_if_svap && (rx_prop && rx_prop->num_rx_props > 2)) {
		idx = 2;
		IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx pipe at idx %d \n", idx);
	}


	if(prop == NULL || prop->num_ext_props <= 0)
	{
		IPACMDBG_H("No extended property.\n");
		return IPACM_SUCCESS;
	}

	clnt_indx = get_wlan_client_index(mac_addr);

	if (clnt_indx == IPACM_INVALID_INDEX)
	{
		IPACMERR("wlan client not found/attached \n");
		return IPACM_FAILURE;
	}

	if (get_client_memptr(wlan_client, clnt_indx)->lan_stats_idx == -1 && !ast_update_needed())
	{
		IPACMERR("Invalid LAN Stats idx for wlan client:%d \n", clnt_indx);
		return IPACM_FAILURE;
	}

	fd = open(IPA_DEVICE_NAME, O_RDWR);
	if (0 == fd)
	{
		IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
		return IPACM_FAILURE;
	}
	if (prop->num_ext_props > MAX_WAN_UL_FILTER_RULES)
	{
		IPACMERR("number of modem UL rules > MAX_WAN_UL_FILTER_RULES, aborting...\n");
		close(fd);
		return IPACM_FAILURE;
	}

	total_rules = prop->num_ext_props;
	/*for IPv6CT enabled mode, duplicate the pass to NAT modem UL rules and change to pass to route for XLAT packets */
	if (iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->IsIpv6CTEnabled())
	{
		IPACMDBG("IPv6CT is enabled, need pass to route modem UL rules for XLAT packets\n");
		for(i = 0; i < total_rules; i++)
			if(prop->prop[i].action != IPA_PASS_TO_EXCEPTION)
				v6_xlat_ul_rules++;

		total_rules = total_rules + v6_xlat_ul_rules;
		IPACMDBG("Need %d additional XLAT rules\n", v6_xlat_ul_rules);
	}

	len = sizeof(struct ipa_ioc_add_flt_rule) + total_rules * sizeof(struct ipa_flt_rule_add);
	pFilteringTable = (struct ipa_ioc_add_flt_rule*)malloc(len);
	if (pFilteringTable == NULL)
	{
		IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
		close(fd);
		return IPACM_FAILURE;
	}
	memset(pFilteringTable, 0, len);

	pFilteringTable->commit = 1;
	pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
	pFilteringTable->global = false;
	pFilteringTable->ip = iptype;
	pFilteringTable->num_rules = total_rules;

	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add)); // Zero All Fields
	flt_rule_entry.at_rear = 1;
	if (flt_rule_entry.rule.eq_attrib.ipv4_frag_eq_present)
		flt_rule_entry.at_rear = 0;
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.eq_attrib_type = 1;
	if(iptype == IPA_IP_v4)
	{
		if (ipa_if_cate == ODU_IF && IPACM_Wan::isWan_Bridge_Mode() ||
			IPACM_Iface::ipacmcfg->is_public_ip_support_enabled)
		{
			IPACMDBG_H(
					"%s%s\n",
					(ipa_if_cate == ODU_IF && IPACM_Wan::isWan_Bridge_Mode()) ? "[WAN, ODU are in bridge mode] " : "",
					(IPACM_Iface::ipacmcfg->is_public_ip_support_enabled) ? "[Public IP enabled]" : "");
			flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
		}
		else
		{
			flt_rule_entry.rule.action = IPA_PASS_TO_SRC_NAT;

			/* NAT block will set the proper MUX ID in the metadata according to the relevant PDN */
			if (IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
				flt_rule_entry.rule.set_metadata = false;
		}
	}
	else if(iptype == IPA_IP_v6)
	{
#ifdef FEATURE_IPV6_NAT
		/* for v6 nat, second pass should go directly to RT block */
		if(IPACM_Iface::ipacmcfg->ipv6_nat_enable)
			flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
		else
#endif
			flt_rule_entry.rule.action = IPACM_Iface::ipacmcfg->IsIpv6CTEnabled() ?
				IPA_PASS_TO_SRC_NAT : IPA_PASS_TO_ROUTING;
	}
	else
	{
		IPACMERR("IP type is not expected.\n");
		ret = IPACM_FAILURE;
		goto fail;
	}
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
	if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
		if (iptype == IPA_IP_v6)
			flt_rule_entry.rule.ttl_update = IPACM_Wan::is_global_ipv6_addr(flt_rule_entry.rule.attrib.u.v6.dst_addr);
		else
			flt_rule_entry.rule.ttl_update = true;
	}
#endif

	action_cache = flt_rule_entry.rule.action;

	for(cnt=0; prop->num_ext_props && index < total_rules; cnt++)
	{
		memcpy(&flt_rule_entry.rule.eq_attrib,
				&prop->prop[cnt].eq_attrib,
				sizeof(prop->prop[cnt].eq_attrib));
		/* Check if we can add the MAC address rule. */
		if (flt_rule_entry.rule.eq_attrib.num_offset_meq_128 == IPA_IPFLTR_NUM_MEQ_128_EQNS)
		{
			IPACMERR("128 bit equations not available.\n");
			ret = IPACM_FAILURE;
			goto fail;
		}
		num_offset_meq_128 = flt_rule_entry.rule.eq_attrib.num_offset_meq_128;
		offset_meq_128 = &flt_rule_entry.rule.eq_attrib.offset_meq_128[num_offset_meq_128];
		if(rx_prop->rx[idx].hdr_l2_type == IPA_HDR_L2_ETHERNET_II
#ifdef IPA_HDR_L2_ETHERNET_II_AST
			|| rx_prop->rx[idx].hdr_l2_type == IPA_HDR_L2_ETHERNET_II_AST
#endif
		  )
		{
			offset_meq_128->offset = -8;
		}
		else if (rx_prop->rx[idx].hdr_l2_type == IPA_HDR_L2_802_1Q_AST)
		{
			offset_meq_128->offset = -12;
		}
		else
		{
			offset_meq_128->offset = -16;
		}

		for (i = 0; i < 10; i++)
		{
			offset_meq_128->mask[i] = 0;
			offset_meq_128->value[i] = 0;
		}

		memset(&offset_meq_128->mask[10], 0xFF, ETH_ALEN);

		for ( i = 0; i < ETH_ALEN; i++)
			offset_meq_128->value[10+i] = mac_addr[ETH_ALEN-(i+1)];

		if (num_offset_meq_128 == 0)
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<3);
		else
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<4);

		flt_rule_entry.rule.eq_attrib.num_offset_meq_128++;
		flt_rule_entry.rule.rt_tbl_idx = prop->prop[cnt].rt_tbl_idx;

		/* Handle XLAT configuration */
		if ((iptype == IPA_IP_v4) && prop->prop[cnt].is_xlat_rule && (xlat_mux_id != 0))
		{
			/* for static policy, xlat rules will be installed with src_addr = XLAT PDN subnet */
			if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
			{
				int meq32_n = flt_rule_entry.rule.eq_attrib.num_offset_meq_32;

				//check if over max meq32 equatipons
				if (meq32_n + 1 > IPA_IPFLTR_NUM_MEQ_32_EQNS)
				{
					IPACMERR("Can't add another meq_32 equation to this rule: %d index %d\n", cnt, index);
					continue;
				}
				flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].offset = 12;  //SRC ADDR
				flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].value =  0xC0000000;  //XLAT PDN
				flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].mask = 0xFFFFFF00;

				//Add the bitmap that will point to the new meq32 eq
				if (meq32_n == 0)
					flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<5);
				else
					flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<6);

				flt_rule_entry.rule.eq_attrib.num_offset_meq_32++;

				//clear metadata bit
				flt_rule_entry.rule.eq_attrib.rule_eq_bitmap &= ~(1<<9);
				flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 0;

				//change to pass to route since NATting is already done on 1st pass
				flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;

				IPACMDBG_H("xlat meta-data is modified for rule: %d has index %d with src subnet: 0x%X\n",
						   cnt, index, flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].value);
			}
			else
			{
				/* fill the value of meta-data */
				value = xlat_mux_id;
				flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.value = (value & 0xFF) << 16;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.mask = 0x00FF0000;
				IPACMDBG_H("xlat meta-data is modified for rule: %d has rule_id %d with xlat_mux_id: %d\n",
						index, prop->prop[cnt].rule_id, xlat_mux_id);
			}
		}
		IPACMDBG_H("rule: %d has rule_id %d\n",
				index, prop->prop[cnt].rule_id);
		flt_rule_entry.rule.hashable = prop->prop[cnt].is_rule_hashable;
		flt_rule_entry.rule.rule_id = prop->prop[cnt].rule_id;
		if (!ast_update_needed())
		{
			flt_rule_entry.rule.rule_id = (prop->prop[cnt].rule_id & 0x1F) |
				(get_client_memptr(wlan_client, clnt_indx)->lan_stats_idx << 5) | 0x200;
			IPACMDBG_H("Modified rule: %d has rule_id %d\n",
					index, flt_rule_entry.rule.rule_id);
		}
		if(rx_prop->rx[idx].attrib.attrib_mask & IPA_FLT_META_DATA &&
			!(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && prop->prop[cnt].is_xlat_rule)) //turn on meta-data equation
		{
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<9);
			flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.value |= rx_prop->rx[idx].attrib.meta_data;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.mask |= rx_prop->rx[idx].attrib.meta_data_mask;
			IPACMDBG_H("turn on meta-data equation with value 0x%x\n", rx_prop->rx[idx].attrib.meta_data);
			/* Match TA peer id */
			if (ast_update_needed())
			{
				flt_rule_entry.rule.eq_attrib.metadata_meq32.value |=  (ta_peer_id & 0XFFF);
				flt_rule_entry.rule.eq_attrib.metadata_meq32.mask |= 0XFFF;
			}
		}
		memcpy(&pFilteringTable->rules[index], &flt_rule_entry, sizeof(flt_rule_entry));

		IPACMDBG_H("Modem UL filtering rule %d has rule_id %d\n", index, prop->prop[cnt].rule_id);
		index++;

		//for IPv6CT enabled and XLAT, add a duplicate rule above that will let XLAT packets go to routing instead of NAT
		if (iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->IsIpv6CTEnabled() &&
			prop->prop[cnt].action != IPA_PASS_TO_EXCEPTION)
		{
			//duplicate the old rule to new index
			memcpy(&pFilteringTable->rules[index], &flt_rule_entry, sizeof(flt_rule_entry));

			//change old rule to pass to route and non hashable
			flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
			flt_rule_entry.rule.hashable = false;

			//add the eth header equation for v4 to the old rule
			int meq32_n = flt_rule_entry.rule.eq_attrib.num_offset_meq_32;

			if (meq32_n + 1 > IPA_IPFLTR_NUM_MEQ_32_EQNS)
			{
				IPACMERR("Can't add another meq_32 equation to this rule");
				memcpy(&pFilteringTable->rules[index], &flt_rule_entry, sizeof(flt_rule_entry));
				continue;
			}

			flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].offset = -4;
			flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].mask = 0xFFFF;
			flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].value = ETH_P_IP;

			//Add the bitmap that will point to the new meq32 eq
			if (meq32_n == 0)
				flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<5);
			else
				flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<6);

			flt_rule_entry.rule.eq_attrib.num_offset_meq_32++;

			//overwrite the old rule and increment the rule count
			memcpy(&pFilteringTable->rules[index - 1], &flt_rule_entry, sizeof(flt_rule_entry));
			index++;
			flt_rule_entry.rule.action = action_cache;
		}
	}

	if(false == m_filtering.AddFilteringRule(pFilteringTable))
	{
		IPACMERR("Error Adding RuleTable to Filtering, aborting...\n");
		ret = IPACM_FAILURE;
		goto fail;
	}
	else
	{
		if(iptype == IPA_IP_v4)
		{
			for(i = 0; i < pFilteringTable->num_rules; i++)
			{
				get_client_memptr(wlan_client, clnt_indx)->wan_ul_fl_rule_hdl_v4[i] = pFilteringTable->rules[i].flt_rule_hdl;
			}
			get_client_memptr(wlan_client, clnt_indx)->ipv4_ul_rules_set = true;
			num_wan_ul_fl_rule_v4[0] = pFilteringTable->num_rules;
		}
		else if(iptype == IPA_IP_v6)
		{
			for(i=0; i < pFilteringTable->num_rules; i++)
			{
				get_client_memptr(wlan_client, clnt_indx)->wan_ul_fl_rule_hdl_v6[i] = pFilteringTable->rules[i].flt_rule_hdl;
			}
			get_client_memptr(wlan_client, clnt_indx)->ipv6_ul_rules_set = true;
			num_wan_ul_fl_rule_v6[0] = pFilteringTable->num_rules;
		}
		else
		{
			IPACMERR("IP type is not expected.\n");
			goto fail;
		}
	}

fail:
	free(pFilteringTable);
	close(fd);
	return ret;
}

#ifdef IPA_HW_FNR_STATS
int IPACM_Wlan::install_uplink_filter_rule_per_client_v2
(
	ipacm_ext_prop* prop,
	ipa_ip_type iptype,
	uint8_t xlat_mux_id,
	uint8_t *mac_addr,
	uint8_t ul_cnt_idx,
	ipa_ioc_add_flt_rule *fw_q6_rules,
	bool isFirewall,
	uint16_t ta_peer_id
)
{
	struct ipa_flt_rule_add_v2 flt_rule_entry;
	int len = 0, cnt, ret = IPACM_SUCCESS;
	struct ipa_ioc_add_flt_rule_v2 *pFilteringTable;
	int fd;
	int i, index = 0, idx = 0;
	uint32_t value = 0;
	int clnt_indx;
	uint8_t num_offset_meq_128;
	struct ipa_ipfltr_mask_eq_128 *offset_meq_128 = NULL;
	int total_rules = 0, v6_xlat_ul_rules = 0;
	enum ipa_flt_action action_cache;

	IPACMDBG_H("Set modem UL flt rules\n");

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	if (is_if_svap && (rx_prop && rx_prop->num_rx_props > 2)) {
		idx = 2;
		IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx pipe at idx %d \n", idx);
	}

	if(isFirewall)
	{
		IPACMDBG_H("Per client rules to be installed for V6 UL firewall\n");
		if ((fw_q6_rules == NULL) || (fw_q6_rules->num_rules <= 0))
		{
			IPACMDBG_H("No firewall rules\n");
			return IPACM_SUCCESS;
		}
		if (fw_q6_rules->num_rules > IPACM_MAX_V6_UL_WL_FIREWALL_ENTRIES)
		{
			IPACMERR("number of modem UL rules > IPACM_MAX_V6_UL_WL_FIREWALL_ENTRIES, aborting...\n");
			return IPACM_FAILURE;
		}
		total_rules =  fw_q6_rules->num_rules;
	}
	else
	{
		if(prop == NULL || prop->num_ext_props <= 0)
		{
			IPACMDBG_H("No extended property.\n");
			return IPACM_SUCCESS;
		}
		if (prop->num_ext_props > MAX_WAN_UL_FILTER_RULES)
		{
			IPACMERR("number of modem UL rules > MAX_WAN_UL_FILTER_RULES, aborting...\n");
			return IPACM_FAILURE;
		}
		total_rules = prop->num_ext_props;
	}
	/*for IPv6CT enabled mode, duplicate the pass to NAT modem UL rules and change to pass to route for XLAT packets */
	if (iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->IsIpv6CTEnabled())
	{
		IPACMDBG("IPv6CT is enabled, need pass to route modem UL rules for XLAT packets\n");
		for(i = 0; i < total_rules; i++)
			if(prop->prop[i].action != IPA_PASS_TO_EXCEPTION)
				v6_xlat_ul_rules++;

		total_rules = total_rules + v6_xlat_ul_rules;
		IPACMDBG("Need %d additional XLAT rules\n", v6_xlat_ul_rules);
	}
	clnt_indx = get_wlan_client_index(mac_addr);

	if (clnt_indx == IPACM_INVALID_INDEX)
	{
		IPACMERR("wlan client not found/attached \n");
		return IPACM_FAILURE;
	}

	if (get_client_memptr(wlan_client, clnt_indx)->lan_stats_idx == -1 && !ast_update_needed())
	{
		IPACMERR("Invalid LAN Stats idx for wlan client:%d \n", clnt_indx);
		return IPACM_FAILURE;
	}

	fd = open(IPA_DEVICE_NAME, O_RDWR);
	if (fd < 0)
	{
		IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	len = sizeof(struct ipa_ioc_add_flt_rule_v2);
	pFilteringTable = (struct ipa_ioc_add_flt_rule_v2*)malloc(len);
	if (pFilteringTable == NULL)
	{
		IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
		close(fd);
		return IPACM_FAILURE;
	}
	memset(pFilteringTable, 0, len);
	pFilteringTable->rules = (uintptr_t)calloc(total_rules, sizeof(struct ipa_flt_rule_add_v2));
	if (!pFilteringTable->rules) {
		IPACMERR("Failed to allocate memory for filtering rules\n");
		ret = IPACM_FAILURE;
		goto fail;
	}
	pFilteringTable->commit = 1;
	pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
	pFilteringTable->global = false;
	pFilteringTable->ip = iptype;
	pFilteringTable->num_rules = total_rules;
	pFilteringTable->flt_rule_size = sizeof(struct ipa_flt_rule_add_v2);

	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add_v2)); // Zero All Fields
	flt_rule_entry.at_rear = 1;
	if (flt_rule_entry.rule.eq_attrib.ipv4_frag_eq_present)
		flt_rule_entry.at_rear = 0;
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.eq_attrib_type = 1;
	flt_rule_entry.rule.enable_stats = true;
	/* When AST update is needed, we do not need stats per client. */
	flt_rule_entry.rule.cnt_idx = (ul_cnt_idx != -1) ? ul_cnt_idx : (ast_update_needed()) ? 0 : ul_cnt_idx;
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
	if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
		if (iptype == IPA_IP_v6)
			flt_rule_entry.rule.ttl_update = IPACM_Wan::is_global_ipv6_addr(flt_rule_entry.rule.attrib.u.v6.dst_addr);
		else
			flt_rule_entry.rule.ttl_update = true;
	}
#endif
	if(iptype == IPA_IP_v4)
	{
		if (ipa_if_cate == ODU_IF && IPACM_Wan::isWan_Bridge_Mode() ||
			IPACM_Iface::ipacmcfg->is_public_ip_support_enabled)
		{
			IPACMDBG_H(
					"%s%s\n",
					(ipa_if_cate == ODU_IF && IPACM_Wan::isWan_Bridge_Mode()) ? "[WAN, ODU are in bridge mode] " : "",
					(IPACM_Iface::ipacmcfg->is_public_ip_support_enabled) ? "[Public IP enabled]" : "");
			flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
		}
		else if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
		{
			IPACMDBG_H("Static policy is enabled, modem UL rule pass to route\n");
			flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
		}
		else
		{
			flt_rule_entry.rule.action = IPA_PASS_TO_SRC_NAT;

			/* NAT block will set the proper MUX ID in the metadata according to the relevant PDN */
			if (IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
				flt_rule_entry.rule.set_metadata = true;
		}
	}
	else if(iptype == IPA_IP_v6)
	{
#ifdef FEATURE_IPV6_NAT
		/* for v6 nat, second pass should go directly to RT block */
		if(IPACM_Iface::ipacmcfg->ipv6_nat_enable)
			flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
		else
#endif
			flt_rule_entry.rule.action = IPACM_Iface::ipacmcfg->IsIpv6CTEnabled() ?
				IPA_PASS_TO_SRC_NAT : IPA_PASS_TO_ROUTING;
	}
	else
	{
		IPACMERR("IP type is not expected.\n");
		ret = IPACM_FAILURE;
		goto fail;
	}

	action_cache = flt_rule_entry.rule.action;

	for(cnt=0; cnt < prop->num_ext_props && index < total_rules; cnt++)
	{
		if (isFirewall)
		{
			memcpy(&flt_rule_entry.rule.eq_attrib,
					&fw_q6_rules->rules[cnt].rule.eq_attrib,
					sizeof(fw_q6_rules->rules[cnt].rule.eq_attrib));
			flt_rule_entry.rule.rt_tbl_idx = fw_q6_rules->rules[cnt].rule.rt_tbl_idx;

			IPACMDBG_H("rule: %d has rule_id %d\n",
					index, fw_q6_rules->rules[cnt].rule.rule_id);

			flt_rule_entry.rule.hashable = fw_q6_rules->rules[cnt].rule.hashable;
			flt_rule_entry.rule.rule_id = fw_q6_rules->rules[cnt].rule.rule_id;
		}
		else
		{
			memcpy(&flt_rule_entry.rule.eq_attrib,
					&prop->prop[cnt].eq_attrib,
					sizeof(prop->prop[cnt].eq_attrib));
			flt_rule_entry.rule.rt_tbl_idx = prop->prop[cnt].rt_tbl_idx;

			IPACMDBG_H("rule: %d has rule_id %d\n",
					index, prop->prop[cnt].rule_id);

			flt_rule_entry.rule.hashable = prop->prop[cnt].is_rule_hashable;
			flt_rule_entry.rule.rule_id = prop->prop[cnt].rule_id;
		}
		IPACMDBG_H("Modified rule: %d has rule_id %d\n",
				index, flt_rule_entry.rule.rule_id);

		/* Check if we can add the MAC address rule. */
		if (flt_rule_entry.rule.eq_attrib.num_offset_meq_128 == IPA_IPFLTR_NUM_MEQ_128_EQNS)
		{
			IPACMERR("128 bit equations not available.\n");
			ret = IPACM_FAILURE;
			goto fail;
		}
		num_offset_meq_128 = flt_rule_entry.rule.eq_attrib.num_offset_meq_128;
		offset_meq_128 = &flt_rule_entry.rule.eq_attrib.offset_meq_128[num_offset_meq_128];
		if(rx_prop->rx[idx].hdr_l2_type == IPA_HDR_L2_ETHERNET_II
#ifdef IPA_HDR_L2_ETHERNET_II_AST
			|| rx_prop->rx[idx].hdr_l2_type == IPA_HDR_L2_ETHERNET_II_AST
#endif
			)

		{
			offset_meq_128->offset = -8;
		}
		else if (rx_prop->rx[idx].hdr_l2_type == IPA_HDR_L2_802_1Q_AST)
		{
			offset_meq_128->offset = -12;
		}
		else
		{
			offset_meq_128->offset = -16;
		}

		for (i = 0; i < 10; i++)
		{
			offset_meq_128->mask[i] = 0;
			offset_meq_128->value[i] = 0;
		}

		memset(&offset_meq_128->mask[10], 0xFF, ETH_ALEN);

		for ( i = 0; i < ETH_ALEN; i++)
			offset_meq_128->value[10+i] = mac_addr[ETH_ALEN-(i+1)];

		if (num_offset_meq_128 == 0)
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<3);
		else
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<4);

		flt_rule_entry.rule.eq_attrib.num_offset_meq_128++;

		/* Handle XLAT configuration */
		if ((!isFirewall) && (iptype == IPA_IP_v4) && prop->prop[cnt].is_xlat_rule && (xlat_mux_id != 0))
		{
			/* for static policy, xlat rules will be installed with src_addr = XLAT PDN subnet */
			if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
			{
				int meq32_n = flt_rule_entry.rule.eq_attrib.num_offset_meq_32;

				//check if over max meq32 equatipons
				if (meq32_n + 1 > IPA_IPFLTR_NUM_MEQ_32_EQNS)
				{
					IPACMERR("Can't add another meq_32 equation to this rule: %d index %d\n", cnt, index);
					continue;
				}
				flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].offset = 12;  //SRC ADDR
				flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].value =  0xC0000000;  //XLAT PDN
				flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].mask = 0xFFFFFF00;

				//Add the bitmap that will point to the new meq32 eq
				if (meq32_n == 0)
					flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<5);
				else
					flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<6);

				flt_rule_entry.rule.eq_attrib.num_offset_meq_32++;

				//clear metadata bit
				flt_rule_entry.rule.eq_attrib.rule_eq_bitmap &= ~(1<<9);
				flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 0;

				//change to pass to route since NATting is already done on 1st pass
				flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;

				IPACMDBG_H("xlat meta-data is modified for rule: %d has index %d with src subnet: 0x%X\n",
						   cnt, index, flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].value);
			}
			else
			{
				/* fill the value of meta-data */
				value = xlat_mux_id;
				flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.value = (value & 0xFF) << 16;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.mask = 0x00FF0000;
				IPACMDBG_H("xlat meta-data is modified for rule: %d has rule_id %d with xlat_mux_id: %d\n",
						index, prop->prop[cnt].rule_id, xlat_mux_id);
			}
		}

		if(rx_prop->rx[idx].attrib.attrib_mask & IPA_FLT_META_DATA &&
			!(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && prop->prop[cnt].is_xlat_rule)) //turn on meta-data equation
		{
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<9);
			flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.value |= rx_prop->rx[idx].attrib.meta_data;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.mask |= rx_prop->rx[idx].attrib.meta_data_mask;
			IPACMDBG_H("turn on meta-data equation with value 0x%x\n", rx_prop->rx[idx].attrib.meta_data);
			/* Match TA peer id */
			if (ast_update_needed())
			{
				flt_rule_entry.rule.eq_attrib.metadata_meq32.value |=  (ta_peer_id & 0XFFF);
				flt_rule_entry.rule.eq_attrib.metadata_meq32.mask |= 0XFFF;
			}
		}

		memcpy((void *)pFilteringTable->rules + (index * sizeof(struct ipa_flt_rule_add_v2)),
			&flt_rule_entry, sizeof(flt_rule_entry));
		index++;

		//for IPv6CT enabled and XLAT, add a duplicate rule above that will let XLAT packets go to routing instead of NAT
		if (iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->IsIpv6CTEnabled() &&
			prop->prop[cnt].action != IPA_PASS_TO_EXCEPTION)
		{
			//duplicate the old rule to new index
			memcpy((void *)pFilteringTable->rules + (index * sizeof(struct ipa_flt_rule_add_v2)),
				&flt_rule_entry, sizeof(flt_rule_entry));

			//change old rule to pass to route and non hashable
			flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
			flt_rule_entry.rule.hashable = false;

			//add the eth header equation for v4 to the old rule
			int meq32_n = flt_rule_entry.rule.eq_attrib.num_offset_meq_32;

			if (meq32_n + 1 > IPA_IPFLTR_NUM_MEQ_32_EQNS)
			{
				IPACMERR("Can't add another meq_32 equation to this rule");
				memcpy((void *)pFilteringTable->rules + (index * sizeof(struct ipa_flt_rule_add_v2)),
					&flt_rule_entry, sizeof(flt_rule_entry));
				continue;
			}

			flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].offset = -4;
			flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].mask = 0xFFFF;
			flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].value = ETH_P_IP;

			//Add the bitmap that will point to the new meq32 eq
			if (meq32_n == 0)
				flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<5);
			else
				flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<6);

			flt_rule_entry.rule.eq_attrib.num_offset_meq_32++;

			//overwrite the old rule and increment the rule count
			memcpy((void *)pFilteringTable->rules + ((index -1) * sizeof(struct ipa_flt_rule_add_v2)),
				&flt_rule_entry, sizeof(flt_rule_entry));
			index++;
			flt_rule_entry.rule.action = action_cache;
		}
	}

	if(false == m_filtering.AddFilteringRule_v2(pFilteringTable))
	{
		IPACMERR("Error Adding RuleTable to Filtering, aborting...\n");
		ret = IPACM_FAILURE;
		goto fail;
	}
	else
	{
		if(iptype == IPA_IP_v4)
		{
			for(i = 0; i < pFilteringTable->num_rules; i++)
			{
				get_client_memptr(wlan_client, clnt_indx)->wan_ul_fl_rule_hdl_v4[i] =
					((struct ipa_flt_rule_add_v2 *)pFilteringTable->rules)[i].flt_rule_hdl;
			}
			get_client_memptr(wlan_client, clnt_indx)->ipv4_ul_rules_set = true;
		}
		else if(iptype == IPA_IP_v6)
		{
			for(i=0; i < pFilteringTable->num_rules; i++)
			{
				get_client_memptr(wlan_client, clnt_indx)->wan_ul_fl_rule_hdl_v6[i] =
					((struct ipa_flt_rule_add_v2 *)pFilteringTable->rules)[i].flt_rule_hdl;
			}
			get_client_memptr(wlan_client, clnt_indx)->ipv6_ul_rules_set = true;
		}
		else
		{
			IPACMERR("IP type is not expected.\n");
			goto fail;
		}
	}

fail:
	free((void *)pFilteringTable->rules);
	free(pFilteringTable);
	close(fd);
	return ret;
}
#endif //IPA_HW_FNR_STATS

/* install UL filter rule from Q6 for all clients */
int IPACM_Wlan::install_uplink_filter_rule
(
	ipacm_ext_prop* prop,
	ipa_ip_type iptype,
	uint8_t xlat_mux_id
)
{
	int ret = IPACM_SUCCESS, i=0;
#ifdef IPA_HW_FNR_STATS
		bool hw_fnr_stats_support = IPACM_Iface::ipacmcfg->hw_fnr_stats_support;
#endif //IPA_HW_FNR_STATS
	IPACMDBG_H("xlat_mux_id: %d, iptype %d\n", xlat_mux_id, iptype);
	for (i = 0; i < num_wifi_client; i++)
	{
		if (iptype == IPA_IP_v4)
		{
			if (get_client_memptr(wlan_client, i)->ipv4_ul_rules_set == false)
			{
#ifdef IPA_HW_FNR_STATS
				if (hw_fnr_stats_support)
				{
					ret = install_uplink_filter_rule_per_client_v2(prop, iptype, xlat_mux_id, get_client_memptr(wlan_client, i)->mac,
						get_client_memptr(wlan_client, i)->ul_cnt_idx, NULL, false, get_client_memptr(wlan_client, i)->ta_peer_id);
					IPACMDBG_H("fnr : IPA_IP_v4 xlat_mux_id: %d, modem_ul_v4_set %d, ul cnt idx = %d\n", xlat_mux_id,
						get_client_memptr(wlan_client, i)->ipv4_ul_rules_set, get_client_memptr(wlan_client, i)->ul_cnt_idx);
				}
				else
#endif //IPA_HW_FNR_STATS
				{
					IPACMDBG_H("IPA_IP_v4 xlat_mux_id: %d, modem_ul_v4_set %d\n", xlat_mux_id, modem_ul_v4_set[0]);
					ret = install_uplink_filter_rule_per_client(prop, iptype, xlat_mux_id, get_client_memptr(wlan_client, i)->mac,
						get_client_memptr(wlan_client, i)->ta_peer_id);
				}
			}
		}
		else if (iptype == IPA_IP_v6)
		{
			if (num_dft_rt_v6 ==1 && get_client_memptr(wlan_client, i)->ipv6_ul_rules_set == false)
			{
#ifdef IPA_HW_FNR_STATS
				if (hw_fnr_stats_support)
				{
					ret = install_uplink_filter_rule_per_client_v2(prop, iptype, xlat_mux_id, get_client_memptr(wlan_client, i)->mac,
							get_client_memptr(wlan_client, i)->ul_cnt_idx, NULL, false, get_client_memptr(wlan_client, i)->ta_peer_id);
					IPACMDBG_H("IPA_IP_v6 num_dft_rt_v6 %d xlat_mux_id: %d modem_ul_v6_set: %d, ul_cnt_idx = %d\n", num_dft_rt_v6, xlat_mux_id,
						get_client_memptr(wlan_client, i)->ipv6_ul_rules_set, get_client_memptr(wlan_client, i)->ul_cnt_idx);
				}
				else
#endif //IPA_HW_FNR_STATS
				{
					IPACMDBG_H("IPA_IP_v6 num_dft_rt_v6 %d xlat_mux_id: %d modem_ul_v6_set: %d\n", num_dft_rt_v6, xlat_mux_id, modem_ul_v6_set[0]);
					ret = install_uplink_filter_rule_per_client(prop, iptype, xlat_mux_id, get_client_memptr(wlan_client, i)->mac,
						get_client_memptr(wlan_client, i)->ta_peer_id);
				}
			}
		} else {
			IPACMDBG_H("ip-type: %d modem_ul_v4_set: %d, modem_ul_v6_set %d\n",
				iptype, modem_ul_v4_set[0], modem_ul_v6_set[0]);
		}
	} /* end of for loop */
	return ret;
}

/* Delete UL filter rule from Q6 per client */
int IPACM_Wlan::delete_uplink_filter_rule_per_client
(
	ipa_ip_type iptype,
	uint8_t *mac_addr
)
{
	int fd;
	int clnt_indx;

	fd = open(IPA_DEVICE_NAME, O_RDWR);
	if (0 == fd)
	{
		IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	clnt_indx = get_wlan_client_index(mac_addr);

	if (clnt_indx == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached \n");
		return IPACM_FAILURE;
	}

	if (get_client_memptr(wlan_client, clnt_indx)->lan_stats_idx == -1 && !ast_update_needed())
	{
		IPACMERR("Invalid LAN Stats idx for ethernet client:%d \n", clnt_indx);
		return IPACM_FAILURE;
	}

#ifndef IPA_V6_UL_WL_FIREWALL_HANDLE
	if (((iptype == IPA_IP_v4) && num_wan_ul_fl_rule_v4[0] > MAX_WAN_UL_FILTER_RULES) ||
		((iptype == IPA_IP_v6) && num_wan_ul_fl_rule_v6[0] > MAX_WAN_UL_FILTER_RULES))
#else
	if (((iptype == IPA_IP_v4) && num_wan_ul_fl_rule_v4[0] > MAX_WAN_UL_FILTER_RULES) ||
		((iptype == IPA_IP_v6) && num_wan_ul_fl_rule_v6[0] > IPACM_MAX_V6_UL_WL_FIREWALL_ENTRIES))
#endif
	{
		IPACMERR("number of wan_ul_fl_rule_v4 (%d)/wan_ul_fl_rule_v6 (%d) > MAX_WAN_UL_FILTER_RULES (%d), aborting...\n",
			num_wan_ul_fl_rule_v4[0],
			num_wan_ul_fl_rule_v6[0],
			MAX_WAN_UL_FILTER_RULES);
#ifdef IPA_V6_UL_WL_FIREWALL_HANDLE
		IPACMERR("IPACM_MAX_V6_UL_WL_FIREWALL_ENTRIES %d\n", IPACM_MAX_V6_UL_WL_FIREWALL_ENTRIES);
#endif
		return IPACM_FAILURE;
	}

	if ((iptype == IPA_IP_v4) && get_client_memptr(wlan_client, clnt_indx)->ipv4_ul_rules_set)
	{
		IPACMDBG_H("Del (%d) num of v4 UL rules for cliend idx:%d\n", num_wan_ul_fl_rule_v4[0], clnt_indx);
		if (m_filtering.DeleteFilteringHdls(get_client_memptr(wlan_client, clnt_indx)->wan_ul_fl_rule_hdl_v4,
				iptype, num_wan_ul_fl_rule_v4[0]) == false)
		{
			IPACMERR("Error Deleting RuleTable(1) to Filtering, aborting...\n");
			close(fd);
			return IPACM_FAILURE;
		}
		memset(get_client_memptr(wlan_client, clnt_indx)->wan_ul_fl_rule_hdl_v4, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
		get_client_memptr(wlan_client, clnt_indx)->ipv4_ul_rules_set = false;
	}

	if ((iptype == IPA_IP_v6) && get_client_memptr(wlan_client, clnt_indx)->ipv6_ul_rules_set)
	{
		IPACMDBG_H("Del (%d) num of v6 UL rules for cliend idx:%d\n", num_wan_ul_fl_rule_v6[0], clnt_indx);
		if (m_filtering.DeleteFilteringHdls(get_client_memptr(wlan_client, clnt_indx)->wan_ul_fl_rule_hdl_v6,
				iptype, num_wan_ul_fl_rule_v6[0]) == false)
		{
			IPACMERR("Error Deleting RuleTable(1) to Filtering, aborting...\n");
			close(fd);
			return IPACM_FAILURE;
		}
#ifndef IPA_V6_UL_WL_FIREWALL_HANDLE
		memset(get_client_memptr(wlan_client, clnt_indx)->wan_ul_fl_rule_hdl_v6, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
#else
		memset(get_client_memptr(wlan_client, clnt_indx)->wan_ul_fl_rule_hdl_v6, 0, IPACM_MAX_V6_UL_WL_FIREWALL_ENTRIES * sizeof(uint32_t));
#endif
		get_client_memptr(wlan_client, clnt_indx)->ipv6_ul_rules_set = false;
	}

	return IPACM_SUCCESS;

}

/* Delete UL filter rule from Q6 for all clients */
int IPACM_Wlan::delete_uplink_filter_rule
(
	ipa_ip_type iptype
)
{
	int ret = IPACM_SUCCESS, i=0;

	for (i = 0; i < num_wifi_client; i++)
	{
		if (iptype == IPA_IP_v4)
		{
			if (get_client_memptr(wlan_client, i)->ipv4_ul_rules_set == true)
			{
				IPACMDBG_H("IPA_IP_v4 Client id: %d, modem_ul_v4_set %d\n", i, get_client_memptr(wlan_client, i)->ipv4_ul_rules_set);
				ret = delete_uplink_filter_rule_per_client(iptype, get_client_memptr(wlan_client, i)->mac);
			}
		}
		else if (iptype == IPA_IP_v6)
		{
			if (get_client_memptr(wlan_client, i)->ipv6_ul_rules_set == true)
			{
				IPACMDBG_H("IPA_IP_v6 Cliend id: %d modem_ul_v6_set: %d\n", i, get_client_memptr(wlan_client, i)->ipv6_ul_rules_set);
				ret = delete_uplink_filter_rule_per_client(iptype, get_client_memptr(wlan_client, i)->mac);
			}
		} else {
			IPACMDBG_H("ip-type: %d lan_stats_idx: %d modem_ul_v4_set: %d, modem_ul_v6_set %d\n",
				iptype, get_client_memptr(wlan_client, i)->lan_stats_idx, get_client_memptr(wlan_client, i)->ipv4_ul_rules_set, get_client_memptr(wlan_client, i)->ipv6_ul_rules_set);
		}
	} /* end of for loop */

	return ret;
}
#endif

int IPACM_Wlan::install_wlan_client_lan2lan_flt_rule(uint8_t *mac, ipa_ip_type iptype, bool is_vlan)
{
	int len, res = IPACM_SUCCESS, clnt_indx, idx = 0;
	struct ipa_flt_rule_add flt_rule_entry;
	struct ipa_ioc_add_flt_rule_after *pFilteringTable = NULL;
	ipa_ioc_get_rt_tbl rt_tbl;
	ipa_private_subnet *private_subnet = NULL;
	ipa_hdr_l2_type hdr_type;

#ifdef FEATURE_IPA_V3
	if (rx_prop == NULL || tx_prop == NULL)
	{
		IPACMDBG_H("No rx or tx properties registered for iface %s\n", dev_name);
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Received client MAC 0x%02x%02x%02x%02x%02x%02x with vlan:%d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], is_vlan);

	clnt_indx = get_wlan_client_index(mac);

	if (clnt_indx == IPACM_INVALID_INDEX)
	{
		IPACMERR("wlan client not found/attached \n");
		return IPACM_FAILURE;
	}

	if ( ! VALID_IPA_IP_TYPE(iptype) )
	{
		IPACMERR("Bad iptype(%u)\n", iptype);
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Ip-type received %d\n", iptype);


	len = sizeof(struct ipa_ioc_add_flt_rule_after) + sizeof(struct ipa_flt_rule_add);
	pFilteringTable = (struct ipa_ioc_add_flt_rule_after*)malloc(len);
	if (!pFilteringTable)
	{
		IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
		return IPACM_FAILURE;
	}
	memset(pFilteringTable, 0, len);

	rt_tbl.ip = iptype;

	if (is_vlan) {
		idx = 2;
		if (iptype == IPA_IP_v4)
			snprintf(rt_tbl.name, IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
				ipa_l2_hdr_type[tx_prop->tx[2].hdr_l2_type]);
		else
			snprintf(rt_tbl.name, IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
				ipa_l2_hdr_type[tx_prop->tx[2].hdr_l2_type]);
	}
	else {
		if (iptype == IPA_IP_v4)
			snprintf(rt_tbl.name, IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
				ipa_l2_hdr_type[tx_prop->tx[0].hdr_l2_type]);
		else
			snprintf(rt_tbl.name, IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
				ipa_l2_hdr_type[tx_prop->tx[0].hdr_l2_type]);
	}

	IPACMDBG_H("This flt rule points to rt tbl %s.\n", rt_tbl.name);

	if(IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false)
	{
		IPACMERR("Failed to get routing table.\n");
		res = IPACM_FAILURE;
		if (!add_dummy_routing_rule(rt_tbl.name, iptype)) {
			goto end;
		}
	}

	/* add mac based rule*/
	pFilteringTable->commit = 1;

	pFilteringTable->ep = rx_prop->rx[idx].src_pipe;

	pFilteringTable->ip = iptype;
	pFilteringTable->num_rules = 1;

	pFilteringTable->add_after_hdl = eth_bridge_flt_rule_offset[idx/2][iptype];
	IPACMDBG_H("pFilteringTable->add_after_hdl 0x%x.\n", pFilteringTable->add_after_hdl);

	memset(&flt_rule_entry, 0, sizeof(flt_rule_entry));
	flt_rule_entry.at_rear = 1;

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
	flt_rule_entry.rule.eq_attrib_type = 0;
	flt_rule_entry.rule.rt_tbl_hdl = rt_tbl.hdl;
	flt_rule_entry.rule.hashable = true;

	memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[idx].attrib, sizeof(flt_rule_entry.rule.attrib));
	if(rx_prop->rx[idx].attrib.attrib_mask & IPA_FLT_META_DATA)	//turn on meta-data equation
	{
		/* Match TA peer id */
		flt_rule_entry.rule.attrib.meta_data |=
			(get_client_memptr(wlan_client, clnt_indx)->ta_peer_id & 0XFFF);
		flt_rule_entry.rule.attrib.meta_data_mask |= 0XFFF;
	}

	hdr_type = is_vlan ? tx_prop->tx[2].hdr_l2_type : tx_prop->tx[0].hdr_l2_type;
	switch(hdr_type)
	{
#ifdef IPA_HDR_L2_ETHERNET_II_AST
	case IPA_HDR_L2_ETHERNET_II_AST:
#endif
	case IPA_HDR_L2_ETHERNET_II:
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_MAC_SRC_ADDR_ETHER_II;
		break;
	case IPA_HDR_L2_802_3:
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_MAC_SRC_ADDR_802_3;
		break;
#ifdef IPA_HDR_L2_802_1Q_AST
		case IPA_HDR_L2_802_1Q_AST:
#endif
	case IPA_HDR_L2_802_1Q:
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_MAC_SRC_ADDR_802_1Q;
		break;
	default:
		IPACMERR("unknown header type\n");
		res = IPACM_FAILURE;
		goto end;
	}

	memcpy(flt_rule_entry.rule.attrib.src_mac_addr, mac, sizeof(flt_rule_entry.rule.attrib.dst_mac_addr));
	memset(flt_rule_entry.rule.attrib.src_mac_addr_mask, 0xFF, sizeof(flt_rule_entry.rule.attrib.dst_mac_addr_mask));
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
	if (iptype == IPA_IP_v4)
	{
		memset(&private_subnet, 0, sizeof (private_subnet));
		if ((private_subnet = IPACM_Iface::ipacmcfg->getPrivateSubnet(get_client_memptr(wlan_client, clnt_indx)->v4_addr)) == NULL)
		{
			IPACMERR("Failed to add client filtering rule for LAN2LAN traffic.\n");
			res = IPACM_FAILURE;
			goto end;
		}

		flt_rule_entry.rule.attrib.u.v4.dst_addr_mask = private_subnet->subnet_mask;
		flt_rule_entry.rule.attrib.u.v4.dst_addr = private_subnet->subnet_addr;
	}
	else
	{
		flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = ipv6_prefix[0];
		flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = ipv6_prefix[1];
		flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = 0x0;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = 0x0;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0x0;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0x0;
	}

	memcpy(&(pFilteringTable->rules[0]), &flt_rule_entry, sizeof(flt_rule_entry));
	if (false == m_filtering.AddFilteringRuleAfter(pFilteringTable))
	{
		IPACMERR("Failed to add client filtering rules.\n");
		res = IPACM_FAILURE;
		goto end;
	}
	if (iptype == IPA_IP_v4)
		get_client_memptr(wlan_client, clnt_indx)->lan2lan_fl_rule_hdl_v4 = pFilteringTable->rules[0].flt_rule_hdl;
	else
		get_client_memptr(wlan_client, clnt_indx)->lan2lan_fl_rule_hdl_v6 = pFilteringTable->rules[0].flt_rule_hdl;

end:
	free(pFilteringTable);
#endif
	return res;
}

int IPACM_Wlan::delete_wlan_client_lan2lan_flt_rule(uint8_t *mac, ipa_ip_type iptype)
{
	int clnt_indx;

	if ( ! VALID_IPA_IP_TYPE(iptype) )
	{
		IPACMERR("Bad iptype(%u)\n", iptype);
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Ip-type received %d\n", iptype);

	IPACMDBG_H("Received client MAC 0x%02x%02x%02x%02x%02x%02x.\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	clnt_indx = get_wlan_client_index(mac);

	if (clnt_indx == IPACM_INVALID_INDEX)
	{
		IPACMERR("wlan client not found/attached \n");
		return IPACM_FAILURE;
	}

	if ( iptype == IPA_IP_v4 )
	{
		if (get_client_memptr(wlan_client, clnt_indx)->lan2lan_fl_rule_hdl_v4)
		{
			IPACMDBG_H("Attempting to delete v4 lan2lan filter rule.\n");

			if(m_filtering.DeleteFilteringHdls(
				   &get_client_memptr(wlan_client, clnt_indx)->lan2lan_fl_rule_hdl_v4, IPA_IP_v4, 1) == true)
			{
				IPACMDBG_H("Deleted v4 lan2lan filter rule successfully.\n");
				get_client_memptr(wlan_client, clnt_indx)->lan2lan_fl_rule_hdl_v4 = 0;
			}
			else
			{
				IPACMERR("Error deleting v4 icmp filter rule...\n");
				return IPACM_FAILURE;
			}
		}
	}
	else /* iptype == IPA_IP_v6 */
	{
		if (get_client_memptr(wlan_client, clnt_indx)->lan2lan_fl_rule_hdl_v6)
		{
			IPACMDBG_H("Attempting to delete v6 lan2lan filter rule.\n");

			if(m_filtering.DeleteFilteringHdls(
				   &get_client_memptr(wlan_client, clnt_indx)->lan2lan_fl_rule_hdl_v6, IPA_IP_v6, 1) == true)
			{
				IPACMDBG_H("Deleted v6 lan2lan filter rule successfully.\n");
				get_client_memptr(wlan_client, clnt_indx)->lan2lan_fl_rule_hdl_v6 = 0;
			}
			else
			{
				IPACMERR("Error deleting v6 icmp filter rule...\n");
				return IPACM_FAILURE;
			}
		}
	}

	return IPACM_SUCCESS;
}

void IPACM_Wlan::add_dscp_pcp_mapping()
{
	int m_fd;
	struct ipa_ioc_dscp_pcp_map_info dscp_pcp_map_info;

	/* Ignoring DSCP PCP addition/deletion if it already issued and there is no change in config */
	if((memcmp(&(IPACM_Iface::ipacmcfg->dscp_pcp_config), &(IPACM_Iface::ipacmcfg->dscp_pcp_config_cache),
		sizeof(IPACM_Iface::ipacmcfg->dscp_pcp_config)) == 0))
	{
		IPACMDBG_H("Ignore Config file change as there is no change in the config\n");
		return;
	}

	if (IPACM_Iface::ipacmcfg->dscp_pcp_config.add == 1)
	{
		/* Issue add ioctl and update cache */
		IPACMDBG_H("Issuing DSCP PCP add command\n");
		dscp_pcp_map_info.add = 1;
		memcpy(&(dscp_pcp_map_info.dscp_pcp_map[0]), IPACM_Iface::ipacmcfg->dscp_pcp_config.dscp_pcp_map,
			sizeof(IPACM_Iface::ipacmcfg->dscp_pcp_config.dscp_pcp_map));
		m_fd = open(IPA_DEVICE_NAME, O_RDWR);
		if (0 != ioctl(m_fd, IPA_IOC_ADD_DEL_DSCP_PCP_MAPPING, &dscp_pcp_map_info))
		{
			IPACMDBG_H("Failed ioctl IPA_IOC_ADD_DEL_DSCP_PCP_MAPPING\n");
			close(m_fd);
			return;
		}

		IPACM_Iface::ipacmcfg->dscp_pcp_config_cache.add = 1;
		memcpy(IPACM_Iface::ipacmcfg->dscp_pcp_config_cache.dscp_pcp_map, IPACM_Iface::ipacmcfg->dscp_pcp_config.dscp_pcp_map,
			sizeof(IPACM_Iface::ipacmcfg->dscp_pcp_config.dscp_pcp_map));
		close(m_fd);
	}
	else
	{
		IPACMDBG_H("Ignoring addition of DSCP PCP mapping\n");
	}
	return;
}

void IPACM_Wlan::handle_hpc_rt_rules_for_easymesh_R3(struct ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table,
	struct ipa_hdr_proc_ctx_add *hdr_proc_ctx,
	int clt_indx)
{
	int size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);

	if (hdr_proc_ctx_table == NULL || hdr_proc_ctx == NULL)
	{
		IPACMDBG_H("Header proc ctx table or header proc ctx is NULL\n");
		return;
	}
	if (get_client_memptr(wlan_client, clt_indx)->ipv4_hpc_set == true)
	{
		/* Deleting route rule */
		delete_default_qos_rtrules(clt_indx, IPA_IP_v4);

		if (m_header.DeleteHeaderProcCtx(get_client_memptr(wlan_client, clt_indx)->hpc_hdr_hdl_v4)
				== false)
		{
			return;
		}

		memset(hdr_proc_ctx_table, 0, size);
		hdr_proc_ctx_table->commit = 1;
		hdr_proc_ctx_table->num_proc_ctxs = 1;
		hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
		if (IPACM_Iface::ipacmcfg->dscp_pcp_config.add)
		{
			hdr_proc_ctx->type = IPA_HDR_PROC_WWAN_TO_ETHII_EX;
			hdr_proc_ctx->generic_params_v2.output_dscp_pcp_update = 1;
			hdr_proc_ctx->generic_params_v2.input_ethhdr_valid = 0;
			hdr_proc_ctx->generic_params_v2.output_ethhdr_negative_offset = 18;
			hdr_proc_ctx->generic_params_v2.input_ethhdr_negative_offset = 0;
		}
		else
		{
			hdr_proc_ctx->type = IPA_HDR_PROC_NONE;
		}

		hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, clt_indx)->hdr_hdl_v4;
		IPACMDBG_H("hdr_proc_ctx->hdr_hdl v4 0x%x\n", hdr_proc_ctx->hdr_hdl);

		if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
			hdr_proc_ctx_table->proc_ctx[0].status != 0) {
			IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
			return;
		}

		get_client_memptr(wlan_client, clt_indx)->hpc_hdr_hdl_v4 = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
		IPACMDBG_H("client(%d) v4 hpc header handle:(0x%x)\n",
				   clt_indx,
				   get_client_memptr(wlan_client, clt_indx)->hpc_hdr_hdl_v4);
		get_client_memptr(wlan_client, clt_indx)->ipv4_hpc_set = true;

		/* Adding route rule again */
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
		{
			handle_wlan_client_route_rule(get_client_memptr(wlan_client, clt_indx)->mac, IPA_IP_v4);
		}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		else
		{
#ifdef IPA_HW_FNR_STATS
		if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
			handle_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client, clt_indx)->mac, IPA_IP_v4);
		else
#endif //IPA_HW_FNR_STATS
			handle_wlan_client_route_rule_ext(get_client_memptr(wlan_client, clt_indx)->mac, IPA_IP_v4);
		}
#endif
	}

	if (get_client_memptr(wlan_client, clt_indx)->ipv6_hpc_set == true)
	{
		/* Deleting route rule */
		delete_default_qos_rtrules(clt_indx, IPA_IP_v6);

		if (m_header.DeleteHeaderProcCtx(get_client_memptr(wlan_client, clt_indx)->hpc_hdr_hdl_v6)
				== false)
		{
			return;
		}

		memset(hdr_proc_ctx_table, 0, size);
		hdr_proc_ctx_table->commit = 1;
		hdr_proc_ctx_table->num_proc_ctxs = 1;
		hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
		if (IPACM_Iface::ipacmcfg->dscp_pcp_config.add)
		{
			hdr_proc_ctx->type = IPA_HDR_PROC_WWAN_TO_ETHII_EX;
			hdr_proc_ctx->generic_params_v2.output_dscp_pcp_update = 1;
			hdr_proc_ctx->generic_params_v2.input_ethhdr_valid = 0;
			hdr_proc_ctx->generic_params_v2.output_ethhdr_negative_offset = 18;
			hdr_proc_ctx->generic_params_v2.input_ethhdr_negative_offset = 0;
		}
		else
		{
			hdr_proc_ctx->type = IPA_HDR_PROC_NONE;
		}

		hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, clt_indx)->hdr_hdl_v6;
		IPACMDBG_H("hdr_proc_ctx->hdr_hdl v6 0x%x\n", hdr_proc_ctx->hdr_hdl);

		if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
			hdr_proc_ctx_table->proc_ctx[0].status != 0) {
			IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
			return;
		}

		get_client_memptr(wlan_client, clt_indx)->hpc_hdr_hdl_v6 = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
		IPACMDBG_H("client(%d) v6 hpc header handle:(0x%x)\n",
				   clt_indx,
				   get_client_memptr(wlan_client, clt_indx)->hpc_hdr_hdl_v6);
		get_client_memptr(wlan_client, clt_indx)->ipv6_hpc_set =  true;

		/* Adding route rule again */
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
		{
			handle_wlan_client_route_rule(get_client_memptr(wlan_client, clt_indx)->mac, IPA_IP_v6);
		}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
			else
		{
#ifdef IPA_HW_FNR_STATS
		if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
			handle_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client, clt_indx)->mac, IPA_IP_v6);
		else
#endif //IPA_HW_FNR_STATS
			handle_wlan_client_route_rule_ext(get_client_memptr(wlan_client, clt_indx)->mac, IPA_IP_v6);
		}
#endif
	}
		return;
}

int IPACM_Wlan::handle_wlan_vlan_client_init(int client_idx, ipacm_bridge *bridge, uint16_t vlan_id)
{
	struct ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table = NULL;
	struct ipa_hdr_proc_ctx_add *hdr_proc_ctx = NULL;
	struct ipa_ioc_add_hdr *pHeaderDescriptor = NULL;
	struct ipa_ioc_copy_hdr sCopyHeader;
	int size = 0, len = 0;
	char index[WLAN_IFACE_INDEX_LEN];
	uint16_t vlan_tci;
	ipacm_event_data_wlan_ex *data;
	int res = IPACM_SUCCESS;

	data = get_client_memptr(wlan_client, client_idx)->p_hdr_info;
	IPACMDBG_H("client_index %d\n",client_idx);
	size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
	hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx *)malloc(size);
	if (hdr_proc_ctx_table == NULL) {
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}

	if (tx_prop != NULL)
	{
		len = sizeof(struct ipa_ioc_add_hdr) + (1 * sizeof(struct ipa_hdr_add));
		pHeaderDescriptor = (struct ipa_ioc_add_hdr *)calloc(1, len);
		if (pHeaderDescriptor == NULL) {
			IPACMERR("calloc failed to allocate pHeaderDescriptor\n");
			return IPACM_FAILURE;
		}

		if (tx_prop->tx[2].ip == IPA_IP_v4) {
			/* IPV4 handling */
			IPACMDBG_H("Got partial v4-header name from tx props\n");
			memset(&sCopyHeader, 0, sizeof(sCopyHeader));
			memcpy(sCopyHeader.name,
				   tx_prop->tx[2].hdr_name,
				   sizeof(sCopyHeader.name));

			IPACMDBG_H("header name: %s in tx\n", sCopyHeader.name);
			if (m_header.CopyHeader(&sCopyHeader) == false) {
				PERROR("ioctl copy header failed");
				res = IPACM_FAILURE;
				goto fail;
			}

			IPACMDBG_H("header length: %d, partial: %d\n", sCopyHeader.hdr_len, sCopyHeader.is_partial);
			IPACMDBG_H("header eth2_ofst_valid: %d, eth2_ofst: %d\n", sCopyHeader.is_eth2_ofst_valid, sCopyHeader.eth2_ofst);
			if (sCopyHeader.hdr_len > IPA_HDR_MAX_SIZE) {
				IPACMERR("header oversize\n");
				res = IPACM_FAILURE;
				goto fail;
			} else {
				memcpy(pHeaderDescriptor->hdr[0].hdr,
					   sCopyHeader.hdr,
					   sCopyHeader.hdr_len);
			}

			for (int i = 0; i < data->num_of_attribs; i++) {
				if ((data->attribs[i].offset < (IPA_HDR_MAX_SIZE - IPA_MAC_ADDR_SIZE)) && (data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_MAC_ADDR)) {
					/* copy client mac_addr to partial header */
					memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset],
						   get_client_memptr(wlan_client, client_idx)->mac,
						   IPA_MAC_ADDR_SIZE);
					/* replace src mac to bridge mac_addr if any  */
					if ((data->attribs[i].offset < (IPA_HDR_MAX_SIZE - 2*IPA_MAC_ADDR_SIZE)) && IPACM_Iface::ipacmcfg->ipa_bridge_enable) {
						memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset + IPA_MAC_ADDR_SIZE],
							   IPACM_Iface::ipacmcfg->bridge_mac,
							   IPA_MAC_ADDR_SIZE);
						IPACMDBG_H("device is in bridge mode \n");
					}

				} else if ((data->attribs[i].offset < (IPA_HDR_MAX_SIZE - sizeof(data->attribs[i].u.sta_id))) && data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_STA_ID) {
					/* copy client id to header */
					memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset],
						   &data->attribs[i].u.sta_id, sizeof(data->attribs[i].u.sta_id));
				} else {
					IPACMDBG_H("The attribute type is not expected!\n");
				}
			}

			pHeaderDescriptor->commit = true;
			pHeaderDescriptor->num_hdrs = 1;

			memset(pHeaderDescriptor->hdr[0].name, 0,
				   sizeof(pHeaderDescriptor->hdr[0].name));

			snprintf(index, sizeof(index), "%d_", ipa_if_num);
			strlcpy(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name));
			pHeaderDescriptor->hdr[0].name[IPA_RESOURCE_NAME_MAX - 1] = '\0';

			if (strlcat(pHeaderDescriptor->hdr[0].name, IPA_WLAN_PARTIAL_HDR_NAME_v4, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX) {
				IPACMERR(" header name construction failed exceed length (%zu)\n", strlen(pHeaderDescriptor->hdr[0].name));
				res = IPACM_FAILURE;
				goto fail;
			}
			snprintf(index, sizeof(index), "_%d", header_name_count);
			if (strlcat(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX) {
				IPACMERR(" header name construction failed exceed length (%zu)\n", strlen(pHeaderDescriptor->hdr[0].name));
				res = IPACM_FAILURE;
				goto fail;
			}


			pHeaderDescriptor->hdr[0].hdr_len = sCopyHeader.hdr_len;
			hdr_len = sCopyHeader.hdr_len;
			pHeaderDescriptor->hdr[0].hdr_hdl = -1;
			pHeaderDescriptor->hdr[0].is_partial = 0;
			pHeaderDescriptor->hdr[0].status = -1;


			vlan_tci = (*((uint16_t *)&(pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
																	  2 * IPA_MAC_ADDR_SIZE +
																	  VLAN_TPID_SIZE])));
			vlan_tci = (vlan_tci & ~VLAN_VID_MASK) | (vlan_id & VLAN_VID_MASK);
			/* change vlan_tci to HW format */
			vlan_tci = htons(vlan_tci);
			memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
												  2 * IPA_MAC_ADDR_SIZE + VLAN_TPID_SIZE],
				   &vlan_tci,
				   sizeof(vlan_tci));
			IPACMDBG_H("v4: updated the vlan_tci, now 0x%X, vlan tag is 0x%X\n", vlan_tci,
					   *((uint32_t *)&(pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
																	 2 * IPA_MAC_ADDR_SIZE])));

			if (bridge) {
				memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
													  IPA_MAC_ADDR_SIZE],
					   bridge->bridge_mac,
					   IPA_MAC_ADDR_SIZE);
				IPACMDBG_H("device is in bridge mode (VLAN), MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
						   bridge->bridge_mac[0],
						   bridge->bridge_mac[1],
						   bridge->bridge_mac[2],
						   bridge->bridge_mac[3],
						   bridge->bridge_mac[4],
						   bridge->bridge_mac[5]);
			}

			if (m_header.AddHeader(pHeaderDescriptor) == false ||
				pHeaderDescriptor->hdr[0].status != 0) {
				IPACMERR("ioctl IPA_IOC_ADD_HDR failed: %d\n", pHeaderDescriptor->hdr[0].status);
				res = IPACM_FAILURE;
				goto fail;
			}

			get_client_memptr(wlan_client, client_idx)->hdr_hdl_v4 = pHeaderDescriptor->hdr[0].hdr_hdl;
			IPACMDBG_H("client(%d) v4 full header name:%s header handle:(0x%x) Len:%d\n",
					   client_idx,
					   pHeaderDescriptor->hdr[0].name,
					   get_client_memptr(wlan_client, client_idx)->hdr_hdl_v4,
					   hdr_len);
			get_client_memptr(wlan_client, client_idx)->ipv4_header_set = true;


			if (false == get_client_memptr(wlan_client, client_idx)->ipv4_hpc_set) {
				memset(hdr_proc_ctx_table, 0, size);
				hdr_proc_ctx_table->commit = 1;
				hdr_proc_ctx_table->num_proc_ctxs = 1;
				hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
				hdr_proc_ctx->type = IPA_HDR_PROC_NONE;

				if ((IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 3) && (IPACM_Iface::ipacmcfg->dscp_pcp_config_cache.add == 1))
				{
					hdr_proc_ctx->type = IPA_HDR_PROC_WWAN_TO_ETHII_EX;
					hdr_proc_ctx->generic_params_v2.output_dscp_pcp_update = 1;
					hdr_proc_ctx->generic_params_v2.input_ethhdr_valid = 0;
					hdr_proc_ctx->generic_params_v2.output_ethhdr_negative_offset = 18;
					hdr_proc_ctx->generic_params_v2.input_ethhdr_negative_offset = 0;
				}

				hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, client_idx)->hdr_hdl_v4;
				IPACMDBG_H("hdr_proc_ctx->hdr_hdl v4 0x%x\n", hdr_proc_ctx->hdr_hdl);

				if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
					hdr_proc_ctx_table->proc_ctx[0].status != 0) {
					IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
					res = IPACM_FAILURE;
					goto end;
				}

				get_client_memptr(wlan_client, client_idx)->hpc_hdr_hdl_v4 = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
				IPACMDBG_H("client(%d) v4 hpc header handle:(0x%x) Len:%d\n",
						   client_idx,
						   get_client_memptr(wlan_client, client_idx)->hpc_hdr_hdl_v4,
						   hdr_len);
				get_client_memptr(wlan_client, client_idx)->ipv4_hpc_set = true;
			}
		}


		/* IPV6 handling */
		if (tx_prop->tx[3].ip == IPA_IP_v6) {
			IPACMDBG_H("Got partial v6-header name from tx props\n");
			memset(&sCopyHeader, 0, sizeof(sCopyHeader));
			memcpy(sCopyHeader.name,
				   tx_prop->tx[3].hdr_name,
				   sizeof(sCopyHeader.name));

			IPACMDBG_H("header name: %s\n", sCopyHeader.name);
			if (m_header.CopyHeader(&sCopyHeader) == false) {
				PERROR("ioctl copy header failed");
				res = IPACM_FAILURE;
				goto fail;
			}

			IPACMDBG_H("header length: %d, paritial: %d\n", sCopyHeader.hdr_len, sCopyHeader.is_partial);
			if (sCopyHeader.hdr_len > IPA_HDR_MAX_SIZE) {
				IPACMERR("header oversize\n");
				res = IPACM_FAILURE;
				goto fail;
			} else {
				memcpy(pHeaderDescriptor->hdr[0].hdr,
					   sCopyHeader.hdr,
					   sCopyHeader.hdr_len);
			}

			for (int i = 0; i < data->num_of_attribs; i++) {
				if ((data->attribs[i].offset < (IPA_HDR_MAX_SIZE - IPA_MAC_ADDR_SIZE)) && (data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_MAC_ADDR)) {
					memcpy(get_client_memptr(wlan_client, client_idx)->mac,
						   data->attribs[i].u.mac_addr,
						   sizeof(get_client_memptr(wlan_client, client_idx)->mac));

					/* copy client mac_addr to partial header */
					memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset],
						   get_client_memptr(wlan_client, client_idx)->mac,
						   IPA_MAC_ADDR_SIZE);

					/* replace src mac to bridge mac_addr if any  */
					if ((data->attribs[i].offset < (IPA_HDR_MAX_SIZE - 2*IPA_MAC_ADDR_SIZE)) && IPACM_Iface::ipacmcfg->ipa_bridge_enable) {
						memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset + IPA_MAC_ADDR_SIZE],
							   IPACM_Iface::ipacmcfg->bridge_mac,
							   IPA_MAC_ADDR_SIZE);
						IPACMDBG_H("device is in bridge mode \n");
					}
				} else if ((data->attribs[i].offset < (IPA_HDR_MAX_SIZE - sizeof(data->attribs[i].u.sta_id))) && data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_STA_ID) {
					/* copy client id to header */
					memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset],
						   &data->attribs[i].u.sta_id, sizeof(data->attribs[i].u.sta_id));
				} else {
					IPACMDBG_H("The attribute type is not expected!\n");
				}
			}

			pHeaderDescriptor->commit = true;
			pHeaderDescriptor->num_hdrs = 1;

			memset(pHeaderDescriptor->hdr[0].name, 0,
				   sizeof(pHeaderDescriptor->hdr[0].name));

			snprintf(index, sizeof(index), "%d_", ipa_if_num);
			strlcpy(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name));
			pHeaderDescriptor->hdr[0].name[IPA_RESOURCE_NAME_MAX - 1] = '\0';

			if (strlcat(pHeaderDescriptor->hdr[0].name, IPA_WLAN_PARTIAL_HDR_NAME_v6, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX) {
				IPACMERR(" header name construction failed exceed length (%zu)\n", strlen(pHeaderDescriptor->hdr[0].name));
				res = IPACM_FAILURE;
				goto fail;
			}

			snprintf(index, sizeof(index), "_%d", header_name_count);
			if (strlcat(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX) {
				IPACMERR(" header name construction failed exceed length (%zu)\n", strlen(pHeaderDescriptor->hdr[0].name));
				res = IPACM_FAILURE;
				goto fail;
			}

			pHeaderDescriptor->hdr[0].hdr_len = sCopyHeader.hdr_len;
			hdr_len = sCopyHeader.hdr_len;
			pHeaderDescriptor->hdr[0].hdr_hdl = -1;
			pHeaderDescriptor->hdr[0].is_partial = 0;
			pHeaderDescriptor->hdr[0].status = -1;

			vlan_tci = (*((uint16_t *)&(pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
																	  2 * IPA_MAC_ADDR_SIZE +
																	  VLAN_TPID_SIZE])));
			vlan_tci = (vlan_tci & ~VLAN_VID_MASK) | (vlan_id & VLAN_VID_MASK);
			/* change vlan_tci to HW format */
			vlan_tci = htons(vlan_tci);
			memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
												  2 * IPA_MAC_ADDR_SIZE + VLAN_TPID_SIZE],
				   &vlan_tci,
				   sizeof(vlan_tci));
			IPACMDBG_H("v4: updated the vlan_tci, now 0x%X, vlan tag is 0x%X\n", vlan_tci,
					   *((uint32_t *)&(pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
																	 2 * IPA_MAC_ADDR_SIZE])));

			if (bridge) {
				memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
													  IPA_MAC_ADDR_SIZE],
					   bridge->bridge_mac,
					   IPA_MAC_ADDR_SIZE);
				IPACMDBG_H("device is in bridge mode (VLAN), MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
						   bridge->bridge_mac[0],
						   bridge->bridge_mac[1],
						   bridge->bridge_mac[2],
						   bridge->bridge_mac[3],
						   bridge->bridge_mac[4],
						   bridge->bridge_mac[5]);

				if (m_header.AddHeader(pHeaderDescriptor) == false ||
					pHeaderDescriptor->hdr[0].status != 0) {
					IPACMERR("ioctl IPA_IOC_ADD_HDR failed: %d\n", pHeaderDescriptor->hdr[0].status);
					res = IPACM_FAILURE;
					goto fail;
				}

				get_client_memptr(wlan_client, client_idx)->hdr_hdl_v6 = pHeaderDescriptor->hdr[0].hdr_hdl;
				IPACMDBG_H("client(%d) v6 full header name:%s header handle:(0x%x) Len:%d\n",
						   client_idx,
						   pHeaderDescriptor->hdr[0].name,
						   get_client_memptr(wlan_client, client_idx)->hdr_hdl_v6,
						   hdr_len);

				get_client_memptr(wlan_client, client_idx)->ipv6_header_set = true;

				if (false == get_client_memptr(wlan_client, client_idx)->ipv6_hpc_set) {
					memset(hdr_proc_ctx_table, 0, size);
					hdr_proc_ctx_table->commit = 1;
					hdr_proc_ctx_table->num_proc_ctxs = 1;
					hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
					hdr_proc_ctx->type = IPA_HDR_PROC_NONE;

					if ((IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 3) && (IPACM_Iface::ipacmcfg->dscp_pcp_config_cache.add == 1))
					{
						hdr_proc_ctx->type = IPA_HDR_PROC_WWAN_TO_ETHII_EX;
						hdr_proc_ctx->generic_params_v2.output_dscp_pcp_update = 1;
						hdr_proc_ctx->generic_params_v2.input_ethhdr_valid = 0;
						hdr_proc_ctx->generic_params_v2.output_ethhdr_negative_offset = 18;
						hdr_proc_ctx->generic_params_v2.input_ethhdr_negative_offset = 0;
					}

					hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, client_idx)->hdr_hdl_v6;
					IPACMDBG_H("hdr_proc_ctx->hdr_hdl v6 0x%x\n", hdr_proc_ctx->hdr_hdl);

					if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
						hdr_proc_ctx_table->proc_ctx[0].status != 0) {
						IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
						res = IPACM_FAILURE;
						goto end;
					}

					get_client_memptr(wlan_client, client_idx)->hpc_hdr_hdl_v6 = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
					IPACMDBG_H("client(%d) v6 hpc header handle:(0x%x) Len:%d\n",
							   client_idx,
							   get_client_memptr(wlan_client, client_idx)->hpc_hdr_hdl_v6,
							   hdr_len);
					get_client_memptr(wlan_client, client_idx)->ipv6_hpc_set =  true;
				}
			}
		}
	}
	/* Header init for vlan client */
	header_name_count++;

end:
	free(hdr_proc_ctx_table);
fail:
	free(pHeaderDescriptor);
	return res;
}

void IPACM_Wlan::update_svap_state() {
	FILE *fp = NULL;
	char MapBSSType_row[10] = { 0 }, cmd[200] = { 0 };

	IPACMDBG_H("dev_name %s\n", dev_name);

	snprintf(cmd, 200, "cfg80211tool_mesh %s get_MapBSSType| awk -F ':' '{print $2}' > /tmp/data_ipa/ipa_vap.txt", dev_name);
	system(cmd);

	fp = fopen("/tmp/data_ipa/ipa_vap.txt", "r");
	if (fp == NULL) {
		IPACMERR("can't open fdb file\n");
		return;
	}

	if (fgets(MapBSSType_row, 10, fp) == NULL) {
		IPACMERR("fgets failed\n");
		goto end;
	}

	if (BSSTYPE_SVAP == atoi(MapBSSType_row)) {
		set_svap_iface_mode(true);
		is_if_svap = true;
	} else {
		set_svap_iface_mode(false);
	}
	IPACMDBG_H("get_MapBSSType %d\n", atoi(MapBSSType_row));

end:
	fclose(fp);
}

bool IPACM_Wlan::is_svap_iface(){
	return svap_iface;
}

int IPACM_Wlan::set_svap_iface_mode(bool enable){
	svap_iface = enable;
	IPACMDBG_H("Svap set to %d\n", svap_iface);
	return 0;
}

bool IPACM_Wlan::is_vlan_iface(){
	IPACMDBG_H("Is vlan %d iface %s\n", vlan_enabled_ap, dev_name);
	return vlan_enabled_ap;
}

int IPACM_Wlan::handle_wlan_r2_subnet(ipacm_event_new_neigh_vlan *param)
{
	ipacm_event_new_neigh_vlan *new_neigh_data =
		(ipacm_event_new_neigh_vlan *)param;
	if (new_neigh_data->data_all.iptype == IPA_IP_v4) {
		if(new_neigh_data->bridge == NULL)
		{
			IPACMERR("NULL bridge\n");
			return IPACM_FAILURE;
		}
		IPACMDBG_H("adding r2 subnet\n");
		add_vlan_private_subnet(new_neigh_data->bridge);
	}
	return IPACM_SUCCESS;
}

int IPACM_Wlan::handle_wlan_vlan_neighbor(ipacm_event_new_neigh_vlan *param) {
	ipacm_event_new_neigh_vlan *new_neigh_data = (ipacm_event_new_neigh_vlan *)param;
	ipacm_event_data_all *data = (ipacm_event_data_all *)param;
	tether_client_info client_info;
	uint16_t vlan_id = 0;
	ipacm_event_data_wlan_ex *cached_data;
	int wlan_index, wlan_primary_index;
	ipacm_bridge *bridge = NULL;
	std::list <ipacm_event_data_all>::iterator it;
	ipacm_event_data_all data_all;

	IPACMDBG_H(" iface name %s  dev %s\n", data->iface_name, dev_name);

	if (is_vlan_iface())
	{
		/* Check if Primary client is associated. */
		wlan_primary_index = get_wlan_primary_client_index(data->mac_addr);
		if (IPACM_INVALID_INDEX == wlan_primary_index)
		{
			IPACMERR("Cannot find wlan index for client MAC %02x:%02x:%02x:%02x:%02x:%02x \n",
					 data->mac_addr[0], data->mac_addr[1], data->mac_addr[2],
					 data->mac_addr[3], data->mac_addr[4], data->mac_addr[5]);
			return -1;
		}
	}

	if (IPACM_SUCCESS != IPACM_Iface::ipacmcfg->get_vlan_id(data->iface_name, &vlan_id))
	{
			IPACMERR("failed getting vlan ID of iface %s \n", data->iface_name);
			return IPACM_FAILURE;
	}

	memset(&client_info, 0, sizeof(tether_client_info));
	if (new_neigh_data->bridge)
	{
		bridge = new_neigh_data->bridge;
		client_info.is_vlan = true;
	}
	else
	{
		IPACMDBG_H("Bridge info not available for Vlan Client..exit\n");
		return IPACM_FAILURE;
	}

	wlan_index = get_wlan_client_index(data->mac_addr, vlan_id);

	if (is_vlan_iface() && wlan_index == IPACM_INVALID_INDEX)
	{
		/* Initialize WLAN client based on Primary client. */
		handle_wlan_client_init_ex(
				get_primary_client_memptr(wlan_primary_client, wlan_primary_index)->p_hdr_info,
				true, vlan_id);

		wlan_index = get_wlan_client_index(data->mac_addr, vlan_id);
		if (wlan_index == IPACM_INVALID_INDEX)
		{
			IPACMERR("wlan client not found/attached \n");
			return IPACM_FAILURE;
		}
		get_primary_client_memptr(wlan_primary_client, wlan_primary_index)->num_vlan_clients++;
	}

	if (is_svap_iface() && wlan_index == IPACM_INVALID_INDEX)
	{
		wlan_index = get_wlan_client_index(data->mac_addr);
		if (IPACM_INVALID_INDEX == wlan_index)
		{
			IPACMERR("Cannot find wlan index for client MAC %02x:%02x:%02x:%02x:%02x:%02x \n",
					 data->mac_addr[0], data->mac_addr[1], data->mac_addr[2],
					 data->mac_addr[3], data->mac_addr[4], data->mac_addr[5]);

			return -1;
		}
		get_client_memptr(wlan_client, wlan_index)->vlan_id = vlan_id;
		get_client_memptr(wlan_client, wlan_index)->is_vlan = true;
	}

	if (data->iptype == IPA_IP_v4)
	{
		client_info.v4_addr = data->ipv4_addr;
	} else if  (data->iptype == IPA_IP_v6) {
		client_info.v4_addr = 0;
	}

	memcpy(client_info.iface, dev_name, IPA_IFACE_NAME_LEN);
	if(wlan_index != IPACM_INVALID_INDEX)
		IPACM_Iface::ipacmcfg->update_client_info(data->mac_addr, &client_info, true);

	if(IPACM_Iface::ipacmcfg->wlan_vlan_mpdn_enabled) {
		if(new_neigh_data->data_all.iptype == IPA_IP_v6)
		{
			if(IPACM_Wan::is_global_ipv6_addr(new_neigh_data->data_all.ipv6_addr))
			{
				if (!IPACM_Wan::isWan_active_with_prefix(new_neigh_data->data_all.ipv6_addr) &&
					!(IPACM_Iface::ipacmcfg->ipv6_nat_enable && is_unique_local_ipv6_addr(data->ipv6_addr)))
				{
					if (neigh_cache.size() < 2*IPA_MAX_NUM_HW_PATH_CLIENTS)
					{
						for (it = neigh_cache.begin(); it != neigh_cache.end(); ++it)
						{
							if ((it->ipv6_addr[0] == data->ipv6_addr[0]) && (it->ipv6_addr[1] == data->ipv6_addr[1])
								&& (it->ipv6_addr[2] == data->ipv6_addr[2])  && (it->ipv6_addr[3] == data->ipv6_addr[3]))
							{
								IPACMDBG_H("Already cached client v6 addr : 0x%08x:%08x:%08x:%08x MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
								data->ipv6_addr[0], data->ipv6_addr[1], data->ipv6_addr[2], data->ipv6_addr[3],
								data->mac_addr[0], data->mac_addr[1], data->mac_addr[2], data->mac_addr[3], data->mac_addr[4], data->mac_addr[5]);
								break;
							}
						}
						if (it == neigh_cache.end())
						{
							memcpy(&data_all, data, sizeof(ipacm_event_data_all));
							neigh_cache.push_back(data_all);
							IPACMDBG_H("Caching v6 addr : 0x%08x:%08x:%08x:%08x MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
								data_all.ipv6_addr[0], data_all.ipv6_addr[1], data_all.ipv6_addr[2], data_all.ipv6_addr[3],
								data_all.mac_addr[0], data_all.mac_addr[1], data_all.mac_addr[2], data_all.mac_addr[3], data_all.mac_addr[4], data_all.mac_addr[5]);
						}
					}
					return IPACM_FAILURE;
				}
				/* add ipv6 prefix */
				IPACM_Iface::ipacmcfg->add_vlan_ipv6_prefix(new_neigh_data->data_all.ipv6_addr, ipa_if_num, vlan_id);
			}

		}
		else if(new_neigh_data->data_all.iptype == IPA_IP_v4)
		{
			add_vlan_private_subnet(bridge);
		}
	}
	/* Complete the header init procedure for vlan client */
	if (client_info.is_vlan && !get_client_memptr(wlan_client, wlan_index)->ipv4_hpc_set &&
		handle_wlan_vlan_client_init(wlan_index, new_neigh_data->bridge, vlan_id) == IPACM_FAILURE) {
		IPACMDBG_H("handle_wlan_vlan_client_init failed.\n");
	}

	if (handle_wlan_client_ipaddr(data) == IPACM_FAILURE) {
		return -1;
	}

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
	{
		handle_wlan_client_route_rule(data->mac_addr, data->iptype, vlan_id);
	}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	else
	{
#ifdef IPA_HW_FNR_STATS
	if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
		handle_wlan_client_route_rule_ext_v2(data->mac_addr, data->iptype, vlan_id);
	else
#endif //IPA_HW_FNR_STATS
		handle_wlan_client_route_rule_ext(data->mac_addr, data->iptype, vlan_id);
	}
#endif

	if (wlan_index == IPACM_INVALID_INDEX) {
		IPACMDBG_H("wlan client not found/attached \n");
		return -1;
	}
	get_client_memptr(wlan_client, wlan_index)->if_index = data->if_index;
	IPACMDBG_H("index %d if_index %d \n", wlan_index, get_client_memptr(wlan_client, wlan_index)->if_index);
	/* add mac balcklist rule if client is added after mac flt event is received */
	if (IPACM_Iface::ipacmcfg->mac_addr_in_blacklist(data->mac_addr) == true) {
		handle_wlan_mac_flt_conn_disc(data->mac_addr, true);
	}

	install_all_wlan_qos_route_rule(data->mac_addr, vlan_id, data->ipv6_addr);

	/* Add NAT rules after ipv4 RT rules are set */
	HandleNeighIpAddrAddEvt(data);

	if(IPACM_Iface::ipacmcfg->wlan_vlan_mpdn_enabled) {
		/* Special handling for VLAN clients in IP passthrough mode.
		 * simillar to IPA_HANDLE_WAN_VLAN_PDN_UP.
		 */
		if ((data->iptype == IPA_IP_v4) &&
			IPACM_Iface::ipacmcfg->is_ip_pass_enabled(device_type,
					data->mac_addr, vlan_id))
		{
			/* Special handling for IPACM_CLIENT_DEVICE_TYPE_USB*/
			if ((!IPACM_Iface::ipacmcfg->isPrivateSubnet(data->ipv4_addr)))
			{
				/* Check if VLAN PDN is already up and add UL rules. */
				uint8_t mux_id = 0;
				if(!(IPACM_Wan::GetMuxByVid(vlan_id, &mux_id, IPA_IP_v4)))
				{
					ipacm_event_vlan_pdn vlan_data;
					/* create event data and call the handler */
					vlan_data.iptype = IPA_IP_v4;
					vlan_data.mux_id = mux_id;
					vlan_data.VlanID = vlan_id;
					if (IPACM_Wan::is_xlat_by_vid(vlan_id))
						vlan_data.is_xlat = true;

					if(handle_vlan_pdn_up(&vlan_data))
					{
						IPACMERR("failed handling v4 VLAN up for VID %d, dev %s\n",
							vlan_id,
							dev_name);
					}
					else
					{
						IPACMDBG_H("handled v4 vlan pdn up for VID %d, dev %s\n",
							vlan_id,
							dev_name);

						// Check if xlat, then add v6 handling first
						if (IPACM_Wan::is_xlat_by_vid(vlan_id))
						{
							vlan_data.iptype = IPA_IP_v6;
							if(handle_vlan_pdn_up(&vlan_data))
							{
								IPACMERR("failed handling v6 VLAN up for VID %d, dev %s\n",
									vlan_id,
									dev_name);
							}
							else
							{
								IPACMDBG_H("handled v6 vlan pdn up for VID %d, dev %s\n",
								vlan_id,
								dev_name);
							}
						}
					}
				}
				else
				{
					IPACMERR("VLAN PDN not up for VID %d, dev %s\n",
						vlan_id,
						dev_name);
				}
			}
		}
	}

	/* Post the delayed IPA_ETH_BRIDGE_CLIENT_ADD event*/
	cached_data = get_client_memptr(wlan_client, wlan_index)->p_hdr_info;
	for (int i = 0; i < cached_data->num_of_attribs; i++) {
		if (!is_svap_iface() && !is_vlan_iface()) {
			IPACMDBG_H("Wlan iface is NON-SVAP, break\n");
			break;
		}
		if (cached_data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_MAC_ADDR) {
			if (IPACM_Iface::ipacmcfg->mac_addr_in_blacklist(cached_data->attribs[i].u.mac_addr) == false) {
				eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_ADD, IPA_IP_MAX, cached_data->attribs[i].u.mac_addr, NULL, NULL, vlan_id);
				break;
			} else {
				IPACMDBG_H("Client is blacklisted for mac based filtering, avoid adding to lan2lan offload \n");
				break;
			}
		}
	}

	return 0;
}

int IPACM_Wlan::add_dummy_routing_rule(char *routingTableName, ipa_ip_type iptype)
{
	/* add default WAN route */
	struct ipa_ioc_add_rt_rule *rt_rule;
	struct ipa_rt_rule_add *rt_rule_entry;
	uint32_t tx_index;
	const int NUM = 1;
	struct ipa_ioc_get_hdr hdr;

	if(tx_prop == NULL)
	{
	  IPACMDBG_H("No tx properties, ignore default route setting\n");
	  return IPACM_SUCCESS;
	}

	rt_rule = (struct ipa_ioc_add_rt_rule *)
		 calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
						NUM * sizeof(struct ipa_rt_rule_add));

	if (!rt_rule)
	{
		IPACMERR("Error Locate ipa_ioc_add_rt_rule memory...\n");
		return IPACM_FAILURE;
	}

	rt_rule->commit = 1;
	rt_rule->num_rules = (uint8_t)NUM;
	rt_rule->ip = iptype;

	IPACMDBG_H("WAN table created %s \n", rt_rule->rt_tbl_name);
	rt_rule_entry = &rt_rule->rules[0];
	rt_rule_entry->at_rear = true;
	rt_rule_entry->rule.retain_hdr = 1;

	memset(&hdr, 0, sizeof(hdr));
	strlcpy(hdr.name, IPA_LAN_RX_HDR_NAME, sizeof(IPA_LAN_RX_HDR_NAME));
	hdr.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
	if(m_header.GetHeaderHandle(&hdr) == false)
	{
		IPACMERR("Failed to get LAN RX header hdl.\n");
		return IPACM_FAILURE;
	}
	rt_rule_entry->rule.hdr_hdl = hdr.hdl;

	rt_rule_entry->rule.dst = IPA_CLIENT_APPS_LAN_CONS;  //go to A5
	rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR;

	strlcpy(rt_rule->rt_tbl_name, routingTableName, sizeof(rt_rule->rt_tbl_name));

	if (IPA_IP_v4 == iptype)
	{
		rt_rule_entry->rule.attrib.u.v4.dst_addr      = 0;
		rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0;
#ifdef FEATURE_IPA_V3
		rt_rule_entry->rule.hashable = true;
#endif
		if (false == m_routing.AddRoutingRule(rt_rule)) {
			IPACMERR("Routing rule addition failed!\n");
			free(rt_rule);
			return IPACM_FAILURE;
		}
		svap_dummy_route_rule_v4_hdl = rt_rule_entry->rt_rule_hdl;
		IPACMDBG_H("Got ipv4 Svap dummy route rule hdl:0x%x,ip-type: %d \n",
				   svap_dummy_route_rule_v4_hdl,
				   IPA_IP_v4);
	}
	else
	{
		rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = 0;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = 0;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = 0;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = 0;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0;
#ifdef FEATURE_IPA_V3
		rt_rule_entry->rule.hashable = true;
#endif
		if (false == m_routing.AddRoutingRule(rt_rule)) {
			IPACMERR("Routing rule addition failed!\n");
			free(rt_rule);
			return IPACM_FAILURE;
		}
		svap_dummy_route_rule_v6_hdl = rt_rule_entry->rt_rule_hdl;
		IPACMDBG_H("Got ipv4 Svap dummy route rule hdl for v6_lan_table:0x%x,ip-type: %d \n",
				   svap_dummy_route_rule_v6_hdl,
				   IPA_IP_v6);
	}

	free(rt_rule);
	return IPACM_SUCCESS;
}

int IPACM_Wlan::add_rt_rules_for_ast_update_ifaces()
{
	ipa_ioc_get_rt_tbl rt_tbl;

	snprintf(rt_tbl.name, IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
				ipa_l2_hdr_type[tx_prop->tx[0].hdr_l2_type]);
	rt_tbl.ip = IPA_IP_v4;
	if (IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false || svap_dummy_route_rule_v4_hdl == 0) {
		IPACMDBG_H("Installing v4 dummy rt lan_table: %s \n", rt_tbl.name);
		add_dummy_routing_rule(rt_tbl.name, IPA_IP_v4);
	} else {
		IPACMDBG_H("v4 dummy rt lan_table: %s  already installed\n", rt_tbl.name);
	}

	memset(&rt_tbl, 0, sizeof(ipa_ioc_get_rt_tbl));
	snprintf(rt_tbl.name, IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
				ipa_l2_hdr_type[tx_prop->tx[0].hdr_l2_type]);
	rt_tbl.ip = IPA_IP_v6;
	if (IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false || svap_dummy_route_rule_v6_hdl == 0) {
		IPACMDBG_H("Installing v6 dummy rt lan_table: %s \n", rt_tbl.name);
		add_dummy_routing_rule(rt_tbl.name, IPA_IP_v6);
	} else {
		IPACMDBG_H("v6 dummy rt lan_table: %s  already installed\n", rt_tbl.name);
	}

	if (is_svap_iface()) {
		memset(&rt_tbl, 0, sizeof(ipa_ioc_get_rt_tbl));
		snprintf(rt_tbl.name, IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
				 ipa_l2_hdr_type[tx_prop->tx[2].hdr_l2_type]);
		rt_tbl.ip = IPA_IP_v4;
		if (IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false || svap_dummy_route_rule_v4_hdl == 0) {
			IPACMDBG_H("Installing v4 dummy rt lan_table: %s \n", rt_tbl.name);
			add_dummy_routing_rule(rt_tbl.name, IPA_IP_v4);
		} else {
			IPACMDBG_H("v4 dummy rt lan_table: %s  already installed\n", rt_tbl.name);
		}

		memset(&rt_tbl, 0, sizeof(ipa_ioc_get_rt_tbl));
		snprintf(rt_tbl.name, IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
				 ipa_l2_hdr_type[tx_prop->tx[2].hdr_l2_type]);
		rt_tbl.ip = IPA_IP_v6;
		if (IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false || svap_dummy_route_rule_v6_hdl == 0) {
			IPACMDBG_H("Installing v6 dummy rt lan_table: %s \n", rt_tbl.name);
			add_dummy_routing_rule(rt_tbl.name, IPA_IP_v6);
		} else {
			IPACMDBG_H("v6 dummy rt lan_table: %s  already installed\n", rt_tbl.name);
		}

	}

	return IPACM_SUCCESS;
}

int IPACM_Wlan::handle_refresh_filtering_rules(bool wlan_vlan_mpdn_enable)
{
	int res = IPACM_FAILURE;
	int idx = vlan_enabled_ap ? 2 : 0;

	IPACMDBG_H("Disabling/Enabling VLAN, vlan:%d, use pipe idx:%d\n",vlan_enabled_ap, idx);

	/* first post IFACE_DOWN event */
	eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_DOWN, IPA_IP_MAX, NULL, NULL, NULL);

	/* Delete v4 filtering rules */
	if (ip_type != IPA_IP_v6 && rx_prop != NULL) {
		/* delete IPv4 icmp filter rules */
		res = delete_icmp_filter_rule(IPA_IP_v4);
		if (res == IPACM_FAILURE) {
			IPACMERR("delete_icmp_filter_rule failed\n");
			goto fail;
		}

		res = delete_dflt_filter_rules(IPA_IP_v4);
		if (res == IPACM_FAILURE) {
			IPACMERR("delete_dflt_filter_rules failed\n");
			goto fail;
		}

		/* delete private-ipv4 filter rules */
#if defined(FEATURE_IPA_ANDROID) || defined(FEATURE_VLAN_MPDN)
		if (m_filtering.DeleteFilteringHdls(private_fl_rule_hdl[0], IPA_IP_v4, num_wan_subnet_rules[0]) == false) {
			IPACMERR("Error deleting private subnet IPv4 flt rules.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, num_wan_subnet_rules[0]);
		num_wan_subnet_rules[0] = 0;
#else
		num_private_subnet_fl_rule = IPACM_Iface::ipacmcfg->ipa_num_private_subnet > (IPA_MAX_PRIVATE_SUBNET_ENTRIES + IPA_MAX_MTU_ENTRIES) ?
			(IPA_MAX_PRIVATE_SUBNET_ENTRIES + IPA_MAX_MTU_ENTRIES) : IPACM_Iface::ipacmcfg->ipa_num_private_subnet;
		if (m_filtering.DeleteFilteringHdls(private_fl_rule_hdl, IPA_IP_v4, num_private_subnet_fl_rule) == false) {
			IPACMERR("Error deleting private subnet flt rules, aborting...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, num_private_subnet_fl_rule);
#endif
		IPACMDBG_H("Deleted private subnet v4 filter rules successfully.\n");

		if (m_filtering.DeleteFilteringHdls(&tcp_syn_flt_rule_hdl[0][IPA_IP_v4], IPA_IP_v4, 1) == false) {
			IPACMERR("Error deleting tcp syn flt rule, aborting...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, 1);
		IPACMDBG_H("Deleted TCP syn v4 filter rules successfully.\n");
	}

	/* Delete v6 filtering rules */
	if (ip_type != IPA_IP_v4 && rx_prop != NULL) {
		/* delete icmp filter rules */
		res = delete_icmp_filter_rule(IPA_IP_v6);
		if (res == IPACM_FAILURE) {
			IPACMERR("delete_icmp_filter_rule failed\n");
			goto fail;
		}

		res = delete_dflt_filter_rules(IPA_IP_v6);
		if (res == IPACM_FAILURE) {
			IPACMERR("delete_dflt_filter_rules failed\n");
			goto fail;
		}

		if (m_filtering.DeleteFilteringHdls(&tcp_syn_flt_rule_hdl[0][IPA_IP_v6], IPA_IP_v6, 1) == false) {
			IPACMERR("Error deleting tcp syn flt rule, aborting...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, 1);
		IPACMDBG_H("Deleted TCP syn v6 filter rules successfully.\n");

	}
	IPACMDBG_H("finished delete filtering rules\n ");

	vlan_enabled_ap = wlan_vlan_mpdn_enable;
	is_wlan_if_vlan = vlan_enabled_ap;

	/* ICMP rule is 1st to keep consistent with v6 and to use as offset for L2L rules */
	install_ipv4_icmp_flt_rule();

	add_tcp_syn_flt_rule(IPA_IP_v4);
	add_tcp_syn_flt_rule(IPA_IP_v6);

	/* initial fragment/multicast/broadcast/filter rule. Fragment has set_rear = false, will be above icmp rule */
	init_fl_rule(IPA_IP_v4);

	/* populate the flt rule offset for eth bridge */
	eth_bridge_flt_rule_offset[0][IPA_IP_v4] = ipv4_icmp_flt_rule_hdl[0][0];
	/* populate the flt rule offset for mtu_offset (offset = broadcast rule)*/
	if (m_ipv4_default_filterting_rules_count[0] > 0 && m_ipv4_default_filterting_rules_count[0] <= IPV4_DEFAULT_FILTERTING_RULES) {
		mtu_flt_rule_offset[0][IPA_IP_v4] =
			dft_v4fl_rule_hdl[0][m_ipv4_default_filterting_rules_count[0] - 1];
	}

	/* Always adding tcp syn SW-exception rule for MSS clamping support */
	add_tcp_syn_flt_rule(IPA_IP_v4);

#ifdef FEATURE_L2TP
	if (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) {
		if (ipa_if_cate == ODU_IF) {
#ifndef IPA_L2TP_TUNNEL_UDP
			add_tcp_syn_flt_rule_l2tp(IPA_IP_v4);
			add_tcp_syn_flt_rule_l2tp(IPA_IP_v6);
#endif
		}
	}
#endif
	install_ipv6_icmp_flt_rule();

	/* populate the flt rule offset for eth bridge */
	eth_bridge_flt_rule_offset[0][IPA_IP_v6] = ipv6_icmp_flt_rule_hdl[0][0];
#ifdef FEATURE_L2TP
	if (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) {
#ifdef IPA_L2TP_TUNNEL_UDP
		if (ipa_if_cate == ODU_IF) add_l2tp_udp_dflt_flt_rules(l2tp_udp_dflt_flt_rule_hdl);
#endif
	}
#endif
	/* post IFACE_UP event */
	if(ip_type == IPA_IP_v4 || ip_type == IPA_IP_MAX)
	{
		eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_UP, IPA_IP_v4, NULL, NULL, NULL);
	}
	if(ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX)
	{
		eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_UP, IPA_IP_v6, NULL, NULL, NULL);
	}

	init_fl_rule(IPA_IP_v6);

	/* populate the mtu_rule_offset */
	if (m_ipv6_default_filterting_rules_count[0] > 0 && m_ipv6_default_filterting_rules_count[0] <= (IPV6_DEFAULT_FILTERTING_RULES + IPV6_DEFAULT_LAN_FILTERTING_RULES)) {
		mtu_flt_rule_offset[0][IPA_IP_v6] =
			dft_v6fl_rule_hdl[0][m_ipv6_default_filterting_rules_count[0] - 1];
	}
	fail:
	return res;
}

int IPACM_Wlan::handle_wlan_del_ipv6_addr(ipacm_event_data_all *data)
{
	uint32_t tx_index;
	uint32_t rt_hdl;
	int num_v6 =0, clnt_indx;
	uint16_t vlan_id = 0;
	std::list <ipacm_event_data_all>::iterator it;
	std::array<uint32_t, 4> ipv6 = {0};

#ifdef FEATURE_VLAN_MPDN
	if(is_vlan_event(data->iface_name))
	{
		IPACMDBG_H("handling vlan WLAN client del v6 ip address for iface %s\n", data->iface_name);
		if(IPACM_Iface::ipacmcfg->get_vlan_id(data->iface_name, &vlan_id))
		{
			IPACMERR("failed getting vlan id for iface %s\n", data->iface_name);
			return IPACM_FAILURE;
		}
	}
#endif

	clnt_indx = get_wlan_client_index(data->mac_addr, vlan_id);
	if (clnt_indx == IPACM_INVALID_INDEX)
	{
		IPACMERR("wlan client not found/attached with MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
			data->mac_addr[0], data->mac_addr[1], data->mac_addr[2], data->mac_addr[3], data->mac_addr[4], data->mac_addr[5]);
		return IPACM_FAILURE;
	}

	if(data->iptype == IPA_IP_v6)
	{
		if ((data->ipv6_addr[0] == 0) && (data->ipv6_addr[1] == 0) &&
			(data->ipv6_addr[2] == 0) || (data->ipv6_addr[3] == 0))
		{
			IPACMDBG_H("Received invalid IPv6 address\n");
		}

		IPACMDBG_H("ipv6 address got: 0x%x:%x:%x:%x\n",
			data->ipv6_addr[0], data->ipv6_addr[1], data->ipv6_addr[2], data->ipv6_addr[3]);

		/* Delete QOS rules. */
		if (IPACM_Iface::ipacmcfg->ipacm_qos_enable)
			delete_wlan_client_qos_rule(data->mac_addr, vlan_id, IPA_IP_v6, data->ipv6_addr);
		for (it = neigh_cache.begin(); it != neigh_cache.end(); ++it)
		{
			if ((it->ipv6_addr[0] == data->ipv6_addr[0]) && (it->ipv6_addr[1] == data->ipv6_addr[1])
				&& (it->ipv6_addr[2] == data->ipv6_addr[2]) && (it->ipv6_addr[3] == data->ipv6_addr[3]))
			{
				neigh_cache.erase(it);
				break;
			}
		}

		/* remove the mapping from the client list */
		std::copy(std::begin(data->ipv6_addr), std::end(data->ipv6_addr), std::begin(ipv6));

		if(rt_hdl_v6_list[clnt_indx].count(ipv6) > 0)
		{
			IPACMDBG_H("ipv6 addr is found for client:%d, ipa_num_clients_ipv6 = %d\n",
				clnt_indx, IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
			if (rt_hdl_v6_list[clnt_indx].at(ipv6).route_rule_set_v6)
			{
				IPACMDBG_H("clean ipv6 rt-rules for client:%d\n", clnt_indx);
				for(tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
				{
					if((tx_prop->tx[tx_index].ip == IPA_IP_v6) &&
						(rt_hdl_v6_list[clnt_indx].at(ipv6).hdl_v6[tx_index].rt_rule_hdl_v6 != 0))
					{
						IPACMDBG_H("Delete client index %d ipv6 RT-rules for %d-st ipv6 for tx:%d\n", clnt_indx, num_v6, tx_index);
						rt_hdl = rt_hdl_v6_list[clnt_indx].at(ipv6).hdl_v6[tx_index].rt_rule_hdl_v6;
						if(m_routing.DeleteRoutingHdl(rt_hdl, IPA_IP_v6) == false)
						{
							return IPACM_FAILURE;
						}
						rt_hdl = rt_hdl_v6_list[clnt_indx].at(ipv6).hdl_v6[tx_index].rt_rule_hdl_v6_wan;
						if(m_routing.DeleteRoutingHdl(rt_hdl, IPA_IP_v6) == false)
						{
							return IPACM_FAILURE;
						}
					}
				} /* tx_index loop */
			} /* clean ipv6 rt-rules */
			rt_hdl_v6_list[clnt_indx].erase(ipv6);
			get_client_memptr(wlan_client, clnt_indx)->ipv6_set--;
			get_client_memptr(wlan_client, clnt_indx)->route_rule_set_v6--;
			IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6--;
			IPACMDBG_H("update ipa_num_clients_ipv6 = %d\n", IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
		} /* found ipv6 on this client */
	}
	return IPACM_SUCCESS;
}

/*handle qos routing rules */
int IPACM_Wlan::handle_wlan_qos_route_rule(uint8_t *client_mac,
	uint16_t client_vlan_id, ipa_ip_type iptype,
	list<qos_param_info>::iterator qos_param,
	uint32_t *ipv6_addr)
{
	struct ipa_ioc_add_rt_rule *rt_rule;
	struct ipa_rt_rule_add *rt_rule_entry;
	uint32_t tx_index;
	int wlan_index;
	const int NUM = 1;
	qos_client_info new_client_info;
	uint8_t zero_mac_array[IPA_MAC_ADDR_SIZE] = { 0 };
	int v6_num = 0, size = 0;
	struct ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table = NULL;
	struct ipa_hdr_proc_ctx_add *hdr_proc_ctx = NULL;

	if(tx_prop == NULL)
	{
		IPACMERR("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 client_mac[0], client_mac[1], client_mac[2],
					 client_mac[3], client_mac[4], client_mac[5]);

	wlan_index = get_wlan_client_index(client_mac, client_vlan_id);
	if (wlan_index == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached \n");
		return IPACM_SUCCESS;
	}

	if (iptype==IPA_IP_v4) {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv4_set:%d \n",
			wlan_index, iptype, qos_param->route_rule_set_v4);
	} else {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv6_set:%d \n",
			wlan_index, iptype, qos_param->route_rule_set_v6);
	}
	/* Add default routing rules if not set yet */
	if ((iptype == IPA_IP_v4
			 && qos_param->route_rule_set_v4 == false)
			|| (iptype == IPA_IP_v6
		            && qos_param->route_rule_set_v6 == false
					))
	{
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >=
			IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Add corresponding ipa_rm_resource_name of TX-endpoint up
			   before IPV6 RT-rule set */
			IPACMDBG_H("dev %s add producer dependency\n", dev_name);
			if (tx_prop != NULL)
			{
				IPACMDBG_H("depend Got pipe %d rm index : %d \n",
				tx_prop->tx[0].dst_pipe,
				IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
				IPACM_Iface::ipacmcfg->AddRmDepend(
				IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe],false);
			}
		}
		rt_rule = (struct ipa_ioc_add_rt_rule *)
			 calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
						NUM * sizeof(struct ipa_rt_rule_add));

		if (rt_rule == NULL)
		{
			PERROR("Error Locate ipa_ioc_add_rt_rule memory...\n");
			return IPACM_FAILURE;
		}

		size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
		hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx *)malloc(size);
		if (hdr_proc_ctx_table == NULL) {
			IPACMERR("Failed to allocate memory for hdr_proc_ctx.\n");
			free(rt_rule);
			return IPACM_FAILURE;
		}

		rt_rule->commit = false; /* Install all qos route rules together */
		rt_rule->num_rules = (uint8_t)NUM;
		rt_rule->ip = iptype;

		for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		{
#ifdef IPA_HDR_L2_802_1Q_AST
			/* skip to the next tx index if the client type and hdr_l2_type are not matching */
			if ((get_client_memptr(wlan_client, wlan_index)->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q_AST && tx_prop->tx[tx_index].hdr_l2_type != IPA_HDR_L2_802_1Q)) ||
					(!get_client_memptr(wlan_client, wlan_index)->is_vlan &&
					(tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q_AST || tx_prop->tx[tx_index].hdr_l2_type == IPA_HDR_L2_802_1Q)))
			{
				continue;
			}
#endif
			if (iptype != tx_prop->tx[tx_index].ip)
			{
				IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule"
				" added\n", tx_index, tx_prop->tx[tx_index].ip, iptype);
				continue;
			}

			/*if (tx_prop->tx[tx_index].tc_bmap == 0)
			{
				IPACMDBG("Tx:%d with pipe tc 0x%x is not for qos traffic... skip and continue\n",
					tx_index, tx_prop->tx[tx_index].tc_bmap);
				continue;
			}*/

			IPACMDBG_H("Pipe Tx:%d, ip-type: %d debug traffic class 0x%x "
					"bmap_tc 0x%x to be compared with pipe tc 0x%x\n",
					tx_index, tx_prop->tx[tx_index].ip,
					qos_param->traffic_class,
					get_u8_bitmap_from_tc(qos_param->traffic_class),
					tx_prop->tx[tx_index].tc_bmap);

			IPACMDBG_H("Qos params, sport_start %d sport_end %d dport_start %d"
				", dport_end %d, dscp_mark %d\n", qos_param->ip_tup.sport_start,
				qos_param->ip_tup.sport_end, qos_param->ip_tup.dport_start,
				qos_param->ip_tup.dport_end, qos_param->dscp_mark_val);

			IPACMDBG_H("Qos params, protocol %d, src_ip_addr 0x%x, dst_ip_addr"
				" 0x%x, dscp %d\n", qos_param->ip_tup.protocol,
				qos_param->ip_tup.src_ip_addr, qos_param->ip_tup.dst_ip_addr, qos_param->dscp);

			IPACMERR("Qos params, src ipv6 addr: 0x%x:%x:%x:%x, dst ipv6 addr:0x%x:%x:%x:%x\n",
				qos_param->ip_tup.src_v6_ip_addr[0],
				qos_param->ip_tup.src_v6_ip_addr[1],
				qos_param->ip_tup.src_v6_ip_addr[2],
				qos_param->ip_tup.src_v6_ip_addr[3],
				qos_param->ip_tup.dst_v6_ip_addr[0],
				qos_param->ip_tup.dst_v6_ip_addr[1],
				qos_param->ip_tup.dst_v6_ip_addr[2],
				qos_param->ip_tup.dst_v6_ip_addr[3]);

			/*if (!(tx_prop->tx[tx_index].tc_bmap &
				get_u8_bitmap_from_tc(qos_param->traffic_class)))
			{
				IPACMDBG_H("Pipe Tx:%d, ip-type: %d conflicting traffic class "
					"0x%x with pipe tc 0x%x\n", tx_index,
					tx_prop->tx[tx_index].ip, qos_param->traffic_class,
					tx_prop->tx[tx_index].tc_bmap);
				continue;
			}*/

			rt_rule_entry = &rt_rule->rules[0];
			rt_rule_entry->at_rear = false;

			if (iptype == IPA_IP_v4)
			{
				if (!get_client_memptr(wlan_client, wlan_index)->ipv4_header_set ||
					!get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4)
				{
					IPACMERR("Client v4 set %d hdl %d is not a valid v4 handle to install qos rule\n",
							   get_client_memptr(wlan_client, wlan_index)->ipv4_header_set,
							   get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4);
				}

				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", wlan_index,
					get_client_memptr(wlan_client, wlan_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
					wlan_index,
					get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4);
				strlcpy(rt_rule->rt_tbl_name,
					IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
					sizeof(rt_rule->rt_tbl_name));
				rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
				rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
				memcpy(&rt_rule_entry->rule.attrib,
					&tx_prop->tx[tx_index].attrib,
					sizeof(rt_rule_entry->rule.attrib));
				if (IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
				{
					rt_rule_entry->rule.hashable = true;
				}
				//Client ip is required to differentiate different clients, else hdr collision will happen
				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
				rt_rule_entry->rule.attrib.u.v4.dst_addr =
					get_client_memptr(wlan_client, wlan_index)->v4_addr;
				rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xffffffff;

				// IP Tuple
				if (qos_param->ip_tup.src_ip_addr)
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
					rt_rule_entry->rule.attrib.u.v4.src_addr =
						qos_param->ip_tup.src_ip_addr;
					rt_rule_entry->rule.attrib.u.v4.src_addr_mask =
						qos_param->ip_tup.src_sub_mask;
				}

				if (qos_param->ip_tup.dst_ip_addr)
				{
					if (qos_param->ip_tup.dst_ip_addr !=
						get_client_memptr(wlan_client, wlan_index)->v4_addr)
					{
						IPACMERR("Mismatched destination qos ip addr 0x%x with "
						"client ip 0x%x\n", qos_param->ip_tup.dst_ip_addr,
						get_client_memptr(wlan_client, wlan_index)->v4_addr);
						return IPACM_SUCCESS;
					}
				}

				// If single port is provided
				if (qos_param->ip_tup.sport_start &&
					(qos_param->ip_tup.sport_start == qos_param->ip_tup.sport_end))
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_PORT;
					rt_rule_entry->rule.attrib.src_port = qos_param->ip_tup.sport_start;
				}
				// If port range is provided
				else if (qos_param->ip_tup.sport_start && qos_param->ip_tup.sport_end)
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_PORT_RANGE;
					rt_rule_entry->rule.attrib.src_port_lo = qos_param->ip_tup.sport_start;
					rt_rule_entry->rule.attrib.src_port_hi = qos_param->ip_tup.sport_end;
				}

				// If single port is provided
				if (qos_param->ip_tup.dport_start &&
					(qos_param->ip_tup.dport_start == qos_param->ip_tup.dport_end))
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_PORT;
					rt_rule_entry->rule.attrib.dst_port = qos_param->ip_tup.dport_start;
				}
				else if (qos_param->ip_tup.dport_start && qos_param->ip_tup.dport_end)
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_PORT_RANGE;
					rt_rule_entry->rule.attrib.dst_port_lo = qos_param->ip_tup.dport_start;
					rt_rule_entry->rule.attrib.dst_port_hi = qos_param->ip_tup.dport_end;
				}

				if (qos_param->ip_tup.protocol)
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_PROTOCOL;
					rt_rule_entry->rule.attrib.u.v4.protocol = qos_param->ip_tup.protocol;
				}

				if (qos_param->vlan_id)
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.u.v4.dst_addr =
						get_client_memptr(wlan_client, wlan_index)->v4_addr;
					rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xffffffff;
				}

				if (qos_param->dscp)
				{
					rt_rule_entry->rule.hashable = false;
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_TOS_MASKED;
					rt_rule_entry->rule.attrib.tos_value = qos_param->dscp << 2;
					rt_rule_entry->rule.attrib.tos_mask = 0xFC;
				}

				if (qos_param->pcp)
				{
					IPACMERR("QOS param PCP no action from IPA \n");
				}

				memset(hdr_proc_ctx_table, 0, size);
				hdr_proc_ctx_table->commit = 1;
				hdr_proc_ctx_table->num_proc_ctxs = 1;
				hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
				hdr_proc_ctx->type = IPA_HDR_PROC_MARK_DSCP;

				hdr_proc_ctx->pdn_dscp_params.valid = 1;
				hdr_proc_ctx->pdn_dscp_params.dscp_val = qos_param->dscp_mark_val;

				hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4;
				IPACMDBG_H("hdr_proc_ctx->hdr_hdl v4 0x%x\n", hdr_proc_ctx->hdr_hdl);

				if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
					hdr_proc_ctx_table->proc_ctx[0].status != 0) {
					IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX for dscp marking failed: %d\n",
						hdr_proc_ctx_table->proc_ctx[0].status);
					free(hdr_proc_ctx_table);
					free(rt_rule);
					return IPACM_FAILURE;
				}

				rt_rule_entry->rule.hdr_proc_ctx_hdl = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
				IPACMDBG_H("rt->hdr_proc_ctx_hdl v4 0x%x\n", rt_rule_entry->rule.hdr_proc_ctx_hdl);

				if (false == m_routing.AddRoutingRule(rt_rule))
				{
					IPACMERR("Routing rule addition failed!\n");
					free(rt_rule);
					return IPACM_FAILURE;
				}

				/* copy ipv4 RT hdl */
				memset(&new_client_info, 0 , sizeof(new_client_info));

				new_client_info.qos_rt_rule_hdl_v4 = rt_rule->rules[0].rt_rule_hdl;
				new_client_info.route_rule_set_v4 = true;
				new_client_info.v4_ip_addr = rt_rule_entry->rule.attrib.u.v4.dst_addr;
				new_client_info.dscp_hpc_hdl_v4 = rt_rule_entry->rule.hdr_proc_ctx_hdl;
				new_client_info.client_iface = ipa_if_num;

				memcpy(new_client_info.mac,
					get_client_memptr(wlan_client, wlan_index)->mac, IPA_MAC_ADDR_SIZE);

				qos_param->qos_client_list.push_front(new_client_info);
				qos_param->client_cnt++;
				IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d client cnt %d, iface %d\n",
					tx_index, new_client_info.qos_rt_rule_hdl_v4, iptype,
					qos_param->client_cnt, new_client_info.client_iface);
			}
			else
			{
				if (get_client_memptr(wlan_client, wlan_index)->ipv6_header_set &&
						get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6)
				{
					IPACMDBG_H("client(%d): v6 header handle:(0x%x)\n",
						wlan_index,
						get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6);

					/*Copy same rule to v6 WAN RT TBL*/
					strlcpy(rt_rule->rt_tbl_name,
						IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name,
						sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
					/* Downlink traffic from Wan iface, directly through IPA */
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
					memcpy(&rt_rule_entry->rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry->rule.attrib));
					if (IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
						rt_rule_entry->rule.hashable = true;
					if ((ipv6_addr[0] || ipv6_addr[1] || ipv6_addr[2] ||
						ipv6_addr[3]))
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
						rt_rule_entry->rule.attrib.u.v6.dst_addr[0] =
							ipv6_addr[0];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[1] =
							ipv6_addr[1];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[2] =
							ipv6_addr[2];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[3] =
							ipv6_addr[3];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xffffffff;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xffffffff;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xffffffff;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xffffffff;
					}

					// IP Tuple V6 params
					if (qos_param->ip_tup.src_v6_ip_addr[0] ||
						qos_param->ip_tup.src_v6_ip_addr[1])
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
						rt_rule_entry->rule.attrib.u.v6.src_addr[0] =
							qos_param->ip_tup.src_v6_ip_addr[0];
						rt_rule_entry->rule.attrib.u.v6.src_addr[1] =
							qos_param->ip_tup.src_v6_ip_addr[1];
						rt_rule_entry->rule.attrib.u.v6.src_addr[2] =
							qos_param->ip_tup.src_v6_ip_addr[2];
						rt_rule_entry->rule.attrib.u.v6.src_addr[3] =
							qos_param->ip_tup.src_v6_ip_addr[3];
						rt_rule_entry->rule.attrib.u.v6.src_addr_mask[0] =
							qos_param->ip_tup.src_v6_sub_mask[0];
						rt_rule_entry->rule.attrib.u.v6.src_addr_mask[1] =
							qos_param->ip_tup.src_v6_sub_mask[1];
						rt_rule_entry->rule.attrib.u.v6.src_addr_mask[2] =
							qos_param->ip_tup.src_v6_sub_mask[2];
						rt_rule_entry->rule.attrib.u.v6.src_addr_mask[3] =
							qos_param->ip_tup.src_v6_sub_mask[3];
					}

					if (qos_param->ip_tup.dst_v6_ip_addr[0] ||
						qos_param->ip_tup.dst_v6_ip_addr[1])
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
						rt_rule_entry->rule.attrib.u.v6.dst_addr[0] =
							qos_param->ip_tup.dst_v6_ip_addr[0];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[1] =
							qos_param->ip_tup.dst_v6_ip_addr[1];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[2] =
							qos_param->ip_tup.dst_v6_ip_addr[2];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[3] =
							qos_param->ip_tup.dst_v6_ip_addr[3];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] =
							qos_param->ip_tup.dst_v6_sub_mask[0];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] =
							qos_param->ip_tup.dst_v6_sub_mask[1];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] =
							qos_param->ip_tup.dst_v6_sub_mask[2];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] =
							qos_param->ip_tup.dst_v6_sub_mask[3];
					}

					// If single port is provided
					if (qos_param->ip_tup.sport_start &&
						(qos_param->ip_tup.sport_start == qos_param->ip_tup.sport_end))
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_PORT;
						rt_rule_entry->rule.attrib.src_port = qos_param->ip_tup.sport_start;
					}
					else if (qos_param->ip_tup.sport_start &&
						qos_param->ip_tup.sport_end) // If port range is provided
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_PORT_RANGE;
						rt_rule_entry->rule.attrib.src_port_lo = qos_param->ip_tup.sport_start;
						rt_rule_entry->rule.attrib.src_port_hi = qos_param->ip_tup.sport_end;
					}

					// If single port is provided
					if (qos_param->ip_tup.dport_start &&
						(qos_param->ip_tup.dport_start == qos_param->ip_tup.dport_end))
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_PORT;
						rt_rule_entry->rule.attrib.dst_port = qos_param->ip_tup.dport_start;
					}
					else if (qos_param->ip_tup.dport_start && qos_param->ip_tup.dport_end)
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_PORT_RANGE;
						rt_rule_entry->rule.attrib.dst_port_lo = qos_param->ip_tup.dport_start;
						rt_rule_entry->rule.attrib.dst_port_hi = qos_param->ip_tup.dport_end;
					}

					if (qos_param->vlan_id)
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
						rt_rule_entry->rule.attrib.u.v6.dst_addr[0] =
							ipv6_addr[0];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[1] =
							ipv6_addr[1];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[2] =
							ipv6_addr[2];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[3] =
							ipv6_addr[3];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xffffffff;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xffffffff;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xffffffff;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xffffffff;
					}

					if (qos_param->dscp)
					{
						rt_rule_entry->rule.hashable = false;
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_TOS_MASKED;
						rt_rule_entry->rule.attrib.tos_value = qos_param->dscp << 2;
						rt_rule_entry->rule.attrib.tos_mask = 0xFC;
					}

					if (qos_param->pcp)
					{
						IPACMERR("QOS param PCP no v6 route rule action from IPA \n");
					}

					memset(hdr_proc_ctx_table, 0, size);
					hdr_proc_ctx_table->commit = 1;
					hdr_proc_ctx_table->num_proc_ctxs = 1;
					hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
					hdr_proc_ctx->type = IPA_HDR_PROC_MARK_DSCP;

					hdr_proc_ctx->pdn_dscp_params.valid = 1;
					hdr_proc_ctx->pdn_dscp_params.dscp_val = qos_param->dscp_mark_val;

					hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6;
					IPACMDBG_H("hdr_proc_ctx->hdr_hdl v6 0x%x\n", hdr_proc_ctx->hdr_hdl);

					if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
						hdr_proc_ctx_table->proc_ctx[0].status != 0) {
						IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX for dscp marking failed: %d\n",
							hdr_proc_ctx_table->proc_ctx[0].status);
						free(hdr_proc_ctx_table);
						free(rt_rule);
						return IPACM_FAILURE;
					}

					rt_rule_entry->rule.hdr_proc_ctx_hdl = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
					IPACMDBG_H("rt->hdr_proc_ctx_hdl v6 0x%x\n", rt_rule_entry->rule.hdr_proc_ctx_hdl);

					if (false == m_routing.AddRoutingRule(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						free(rt_rule);
						return IPACM_FAILURE;
					}

					/* copy ipv6 RT hdl */
					memset(&new_client_info, 0 , sizeof(new_client_info));
					new_client_info.qos_rt_rule_hdl_v6 = rt_rule->rules[0].rt_rule_hdl;
					new_client_info.route_rule_set_v6 = true;
					new_client_info.dscp_hpc_hdl_v6 = rt_rule_entry->rule.hdr_proc_ctx_hdl;
					new_client_info.client_iface = ipa_if_num;

					new_client_info.v6_ip_addr[0] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[0];
					new_client_info.v6_ip_addr[1] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[1];
					new_client_info.v6_ip_addr[2] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[2];
					new_client_info.v6_ip_addr[3] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[3];

					memcpy(new_client_info.mac,
						get_client_memptr(wlan_client, wlan_index)->mac,
						IPA_MAC_ADDR_SIZE);

					IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d iface %d\n", tx_index,
							   new_client_info.qos_rt_rule_hdl_v6, iptype,
							   new_client_info.client_iface);
					qos_param->qos_client_list.push_front(new_client_info);
					qos_param->client_cnt++;
				}
			}
		} /* end of for loop */

		free(rt_rule);
	}
	return IPACM_SUCCESS;
}

/*handle qos routing rules for v2*/
int IPACM_Wlan::handle_wlan_qos_route_rule_ext_v2(uint8_t *client_mac,
	uint16_t client_vlan_id, ipa_ip_type iptype,
	list<qos_param_info>::iterator qos_param,
	uint32_t *ipv6_addr)
{
	struct ipa_ioc_add_rt_rule_ext_v2 *rt_rule;
	struct ipa_rt_rule_add_ext_v2 *rt_rule_entry;
	uint32_t tx_index;
	int wlan_index;
	const int NUM = 1;
	qos_client_info new_client_info;
	uint8_t zero_mac_array[IPA_MAC_ADDR_SIZE] = { 0 };
	int v6_num = 0;
	struct ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table = NULL;
	struct ipa_hdr_proc_ctx_add *hdr_proc_ctx = NULL;
	uint64_t rules, size = 0;

	if(tx_prop == NULL)
	{
		IPACMERR("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 client_mac[0], client_mac[1], client_mac[2],
					 client_mac[3], client_mac[4], client_mac[5]);

	wlan_index = get_wlan_client_index(client_mac, client_vlan_id);
	if (wlan_index == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached \n");
		return IPACM_SUCCESS;
	}

	if (iptype==IPA_IP_v4) {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv4_set:%d \n",
			wlan_index, iptype, qos_param->route_rule_set_v4);
	} else {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv6_set:%d \n",
			wlan_index, iptype, qos_param->route_rule_set_v6);
	}
	/* Add default routing rules if not set yet */
	if ((iptype == IPA_IP_v4
			 && qos_param->route_rule_set_v4 == false)
			|| (iptype == IPA_IP_v6
		            && qos_param->route_rule_set_v6 == false
					))
	{
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >=
			IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Add corresponding ipa_rm_resource_name of TX-endpoint up
			   before IPV6 RT-rule set */
			IPACMDBG_H("dev %s add producer dependency\n", dev_name);
			if (tx_prop != NULL)
			{
				IPACMDBG_H("depend Got pipe %d rm index : %d \n",
				tx_prop->tx[0].dst_pipe,
				IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
				IPACM_Iface::ipacmcfg->AddRmDepend(
				IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe],false);
			}
		}
		rt_rule = (struct ipa_ioc_add_rt_rule_ext_v2 *)
			 calloc(1, sizeof(struct ipa_ioc_add_rt_rule_ext_v2));

		if (rt_rule == NULL)
		{
			PERROR("Error Locate ipa_ioc_add_rt_rule memory...\n");
			return IPACM_FAILURE;
		}

		size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
		hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx *)malloc(size);
		if (hdr_proc_ctx_table == NULL) {
			IPACMERR("Failed to allocate memory for hdr_proc_ctx.\n");
			free(rt_rule);
			return IPACM_FAILURE;
		}

		rt_rule->rules = (uintptr_t)calloc(NUM, sizeof(struct ipa_rt_rule_add_ext_v2));
		if (!rt_rule->rules) {
			IPACMERR("Failed to allocate memory.\n");
			free(rt_rule);
			return IPACM_FAILURE;
		}
		rt_rule->rule_add_ext_size = sizeof(struct ipa_rt_rule_add_ext_v2);

		rt_rule->commit = false; /* Install all qos route rules together */
		rt_rule->num_rules = (uint8_t)NUM;
		rt_rule->ip = iptype;

		for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		{
			if (iptype != tx_prop->tx[tx_index].ip)
			{
				IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule"
				" added\n", tx_index, tx_prop->tx[tx_index].ip, iptype);
				continue;
			}

			/*if (tx_prop->tx[tx_index].tc_bmap == 0)
			{
				IPACMDBG("Tx:%d with pipe tc 0x%x is not for qos traffic... skip and continue\n",
					tx_index, tx_prop->tx[tx_index].tc_bmap);
				continue;
			}*/

			IPACMDBG_H("Pipe Tx:%d, ip-type: %d debug traffic class 0x%x "
					"bmap_tc 0x%x to be compared with pipe tc 0x%x\n",
					tx_index, tx_prop->tx[tx_index].ip,
					qos_param->traffic_class,
					get_u8_bitmap_from_tc(qos_param->traffic_class),
					tx_prop->tx[tx_index].tc_bmap);

			IPACMDBG_H("Qos params, sport_start %d sport_end %d dport_start %d"
				", dport_end %d, \n", qos_param->ip_tup.sport_start,
				qos_param->ip_tup.sport_end, qos_param->ip_tup.dport_start,
				qos_param->ip_tup.dport_end);

			IPACMDBG_H("Qos params, protocol %d, src_ip_addr 0x%x, dst_ip_addr"
				" 0x%x, dscp %d\n", qos_param->ip_tup.protocol,
				qos_param->ip_tup.src_ip_addr, qos_param->ip_tup.dst_ip_addr, qos_param->dscp);

			IPACMERR("Qos params, src ipv6 addr: 0x%x:%x:%x:%x, dst ipv6 addr:0x%x:%x:%x:%x\n",
				qos_param->ip_tup.src_v6_ip_addr[0],
				qos_param->ip_tup.src_v6_ip_addr[1],
				qos_param->ip_tup.src_v6_ip_addr[2],
				qos_param->ip_tup.src_v6_ip_addr[3],
				qos_param->ip_tup.dst_v6_ip_addr[0],
				qos_param->ip_tup.dst_v6_ip_addr[1],
				qos_param->ip_tup.dst_v6_ip_addr[2],
				qos_param->ip_tup.dst_v6_ip_addr[3]);

			/*if (!(tx_prop->tx[tx_index].tc_bmap &
				get_u8_bitmap_from_tc(qos_param->traffic_class)))
			{
				IPACMDBG_H("Pipe Tx:%d, ip-type: %d conflicting traffic class "
					"0x%x with pipe tc 0x%x\n", tx_index,
					tx_prop->tx[tx_index].ip, qos_param->traffic_class,
					tx_prop->tx[tx_index].tc_bmap);
				continue;
			}*/

			rules = rt_rule->rules;
			rt_rule_entry = (struct ipa_rt_rule_add_ext_v2 *)rules;
			rt_rule_entry->at_rear = false;

			if (iptype == IPA_IP_v4)
			{
				if (!get_client_memptr(wlan_client, wlan_index)->ipv4_header_set ||
					!get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4)
				{
					IPACMERR("Client v4 set %d hdl %d is not a valid v4 handle to install qos rule\n",
							   get_client_memptr(wlan_client, wlan_index)->ipv4_header_set,
							   get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4);
				}

				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", wlan_index,
					get_client_memptr(wlan_client, wlan_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
					wlan_index,
					get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4);
				strlcpy(rt_rule->rt_tbl_name,
					IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
					sizeof(rt_rule->rt_tbl_name));
				rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
				rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
				memcpy(&rt_rule_entry->rule.attrib,
					&tx_prop->tx[tx_index].attrib,
					sizeof(rt_rule_entry->rule.attrib));
				if (IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
				{
					rt_rule_entry->rule.hashable = true;
				}
				rt_rule_entry->rule.enable_stats = true;
				rt_rule_entry->rule.cnt_idx =
					get_client_memptr(wlan_client, wlan_index)->dl_cnt_idx;
				IPACMDBG_H("wlan_client dl index (%d) \n", rt_rule_entry->rule.cnt_idx);

				//Client ip is required to differentiate different clients, else hdr collision will happen
				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
				rt_rule_entry->rule.attrib.u.v4.dst_addr =
					get_client_memptr(wlan_client, wlan_index)->v4_addr;
				rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xffffffff;

				// IP Tuple
				if (qos_param->ip_tup.src_ip_addr)
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
					rt_rule_entry->rule.attrib.u.v4.src_addr =
						qos_param->ip_tup.src_ip_addr;
					rt_rule_entry->rule.attrib.u.v4.src_addr_mask =
						qos_param->ip_tup.src_sub_mask;
				}

				if (qos_param->ip_tup.dst_ip_addr)
				{
					if (qos_param->ip_tup.dst_ip_addr !=
						get_client_memptr(wlan_client, wlan_index)->v4_addr)
					{
						IPACMERR("Mismatched destination qos ip addr 0x%x with "
						"client ip 0x%x\n", qos_param->ip_tup.dst_ip_addr,
						get_client_memptr(wlan_client, wlan_index)->v4_addr);
						return IPACM_SUCCESS;
					}
				}

				// If single port is provided
				if (qos_param->ip_tup.sport_start &&
					(qos_param->ip_tup.sport_start == qos_param->ip_tup.sport_end))
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_PORT;
					rt_rule_entry->rule.attrib.src_port = qos_param->ip_tup.sport_start;
				}
				// If port range is provided
				else if (qos_param->ip_tup.sport_start && qos_param->ip_tup.sport_end)
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_PORT_RANGE;
					rt_rule_entry->rule.attrib.src_port_lo = qos_param->ip_tup.sport_start;
					rt_rule_entry->rule.attrib.src_port_hi = qos_param->ip_tup.sport_end;
				}

				// If single port is provided
				if (qos_param->ip_tup.dport_start &&
					(qos_param->ip_tup.dport_start == qos_param->ip_tup.dport_end))
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_PORT;
					rt_rule_entry->rule.attrib.dst_port = qos_param->ip_tup.dport_start;
				}
				else if (qos_param->ip_tup.dport_start && qos_param->ip_tup.dport_end)
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_PORT_RANGE;
					rt_rule_entry->rule.attrib.dst_port_lo = qos_param->ip_tup.dport_start;
					rt_rule_entry->rule.attrib.dst_port_hi = qos_param->ip_tup.dport_end;
				}

				if (qos_param->ip_tup.protocol)
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_PROTOCOL;
					rt_rule_entry->rule.attrib.u.v4.protocol = qos_param->ip_tup.protocol;
				}

				if (qos_param->vlan_id)
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.u.v4.dst_addr =
						get_client_memptr(wlan_client, wlan_index)->v4_addr;
					rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xffffffff;
				}

				if (qos_param->dscp)
				{
					rt_rule_entry->rule.hashable = false;
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_TOS_MASKED;
					rt_rule_entry->rule.attrib.tos_value = qos_param->dscp << 2;
					rt_rule_entry->rule.attrib.tos_mask = 0xFC;
				}

				if (qos_param->pcp)
				{
					IPACMERR("QOS param PCP no action from IPA \n");
				}

				memset(hdr_proc_ctx_table, 0, size);
				hdr_proc_ctx_table->commit = 1;
				hdr_proc_ctx_table->num_proc_ctxs = 1;
				hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
				hdr_proc_ctx->type = IPA_HDR_PROC_MARK_DSCP;

				hdr_proc_ctx->pdn_dscp_params.valid = 1;
				hdr_proc_ctx->pdn_dscp_params.dscp_val = qos_param->dscp_mark_val;

				hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4;
				IPACMDBG_H("hdr_proc_ctx->hdr_hdl v4 0x%x\n", hdr_proc_ctx->hdr_hdl);

				if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
					hdr_proc_ctx_table->proc_ctx[0].status != 0) {
					IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX for dscp marking failed: %d\n",
						hdr_proc_ctx_table->proc_ctx[0].status);
					free(hdr_proc_ctx_table);
					free(rt_rule);
					return IPACM_FAILURE;
				}

				rt_rule_entry->rule.hdr_proc_ctx_hdl = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
				IPACMDBG_H("rt->hdr_proc_ctx_hdl v4 0x%x\n", rt_rule_entry->rule.hdr_proc_ctx_hdl);

				if (false == m_routing.AddRoutingRuleExt_v2(rt_rule))
				{
					IPACMERR("Routing rule addition failed!\n");
					free(rt_rule);
					return IPACM_FAILURE;
				}

				/* copy ipv4 RT hdl */
				memset(&new_client_info, 0 , sizeof(new_client_info));

				new_client_info.qos_rt_rule_hdl_v4 = ((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[0].rt_rule_hdl;
				new_client_info.route_rule_set_v4 = true;
				new_client_info.v4_ip_addr = rt_rule_entry->rule.attrib.u.v4.dst_addr;
				new_client_info.dscp_hpc_hdl_v4 = rt_rule_entry->rule.hdr_proc_ctx_hdl;
				new_client_info.client_iface = ipa_if_num;

				memcpy(new_client_info.mac,
					get_client_memptr(wlan_client, wlan_index)->mac, IPA_MAC_ADDR_SIZE);

				qos_param->qos_client_list.push_front(new_client_info);
				qos_param->client_cnt++;
				IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d client cnt %d iface %d\n",
					tx_index, new_client_info.qos_rt_rule_hdl_v4, iptype,
					qos_param->client_cnt, new_client_info.client_iface);
			}
			else
			{
				if (get_client_memptr(wlan_client, wlan_index)->ipv6_header_set &&
						get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6)
				{
					IPACMDBG_H("client(%d): v6 header handle:(0x%x)\n",
						wlan_index,
						get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6);

					/*Copy same rule to v6 WAN RT TBL*/
					strlcpy(rt_rule->rt_tbl_name,
						IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name,
						sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
					/* Downlink traffic from Wan iface, directly through IPA */
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
					memcpy(&rt_rule_entry->rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry->rule.attrib));
					if (IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
						rt_rule_entry->rule.hashable = true;
					rt_rule_entry->rule.enable_stats = true;
					rt_rule_entry->rule.cnt_idx =
						get_client_memptr(wlan_client, wlan_index)->dl_cnt_idx;
					IPACMDBG_H("wlan_client v6 dl index (%d) \n", rt_rule_entry->rule.cnt_idx);

					if ((ipv6_addr[0] || ipv6_addr[1] || ipv6_addr[2] ||
						ipv6_addr[3]))
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
						rt_rule_entry->rule.attrib.u.v6.dst_addr[0] =
							ipv6_addr[0];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[1] =
							ipv6_addr[1];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[2] =
							ipv6_addr[2];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[3] =
							ipv6_addr[3];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xffffffff;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xffffffff;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xffffffff;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xffffffff;
					}

					// IP Tuple V6 params
					if (qos_param->ip_tup.src_v6_ip_addr[0] ||
						qos_param->ip_tup.src_v6_ip_addr[1])
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
						rt_rule_entry->rule.attrib.u.v6.src_addr[0] =
							qos_param->ip_tup.src_v6_ip_addr[0];
						rt_rule_entry->rule.attrib.u.v6.src_addr[1] =
							qos_param->ip_tup.src_v6_ip_addr[1];
						rt_rule_entry->rule.attrib.u.v6.src_addr[2] =
							qos_param->ip_tup.src_v6_ip_addr[2];
						rt_rule_entry->rule.attrib.u.v6.src_addr[3] =
							qos_param->ip_tup.src_v6_ip_addr[3];
						rt_rule_entry->rule.attrib.u.v6.src_addr_mask[0] =
							qos_param->ip_tup.src_v6_sub_mask[0];
						rt_rule_entry->rule.attrib.u.v6.src_addr_mask[1] =
							qos_param->ip_tup.src_v6_sub_mask[1];
						rt_rule_entry->rule.attrib.u.v6.src_addr_mask[2] =
							qos_param->ip_tup.src_v6_sub_mask[2];
						rt_rule_entry->rule.attrib.u.v6.src_addr_mask[3] =
							qos_param->ip_tup.src_v6_sub_mask[3];
					}

					if (qos_param->ip_tup.dst_v6_ip_addr[0] ||
						qos_param->ip_tup.dst_v6_ip_addr[1])
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
						rt_rule_entry->rule.attrib.u.v6.dst_addr[0] =
							qos_param->ip_tup.dst_v6_ip_addr[0];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[1] =
							qos_param->ip_tup.dst_v6_ip_addr[1];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[2] =
							qos_param->ip_tup.dst_v6_ip_addr[2];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[3] =
							qos_param->ip_tup.dst_v6_ip_addr[3];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] =
							qos_param->ip_tup.dst_v6_sub_mask[0];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] =
							qos_param->ip_tup.dst_v6_sub_mask[1];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] =
							qos_param->ip_tup.dst_v6_sub_mask[2];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] =
							qos_param->ip_tup.dst_v6_sub_mask[3];
					}

					// If single port is provided
					if (qos_param->ip_tup.sport_start &&
						(qos_param->ip_tup.sport_start == qos_param->ip_tup.sport_end))
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_PORT;
						rt_rule_entry->rule.attrib.src_port = qos_param->ip_tup.sport_start;
					}
					else if (qos_param->ip_tup.sport_start &&
						qos_param->ip_tup.sport_end) // If port range is provided
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_PORT_RANGE;
						rt_rule_entry->rule.attrib.src_port_lo = qos_param->ip_tup.sport_start;
						rt_rule_entry->rule.attrib.src_port_hi = qos_param->ip_tup.sport_end;
					}

					// If single port is provided
					if (qos_param->ip_tup.dport_start &&
						(qos_param->ip_tup.dport_start == qos_param->ip_tup.dport_end))
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_PORT;
						rt_rule_entry->rule.attrib.dst_port = qos_param->ip_tup.dport_start;
					}
					else if (qos_param->ip_tup.dport_start && qos_param->ip_tup.dport_end)
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_PORT_RANGE;
						rt_rule_entry->rule.attrib.dst_port_lo = qos_param->ip_tup.dport_start;
						rt_rule_entry->rule.attrib.dst_port_hi = qos_param->ip_tup.dport_end;
					}

					if (qos_param->vlan_id)
					{
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
						rt_rule_entry->rule.attrib.u.v6.dst_addr[0] =
							ipv6_addr[0];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[1] =
							ipv6_addr[1];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[2] =
							ipv6_addr[2];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[3] =
							ipv6_addr[3];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xffffffff;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xffffffff;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xffffffff;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xffffffff;
					}

					if (qos_param->dscp)
					{					
						rt_rule_entry->rule.hashable = false;
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_TOS_MASKED;
						rt_rule_entry->rule.attrib.tos_value = qos_param->dscp << 2;
						rt_rule_entry->rule.attrib.tos_mask = 0xFC;
					}

					if (qos_param->pcp)
					{
						IPACMERR("QOS param PCP no v6 route rule action from IPA \n");
					}

					memset(hdr_proc_ctx_table, 0, size);
					hdr_proc_ctx_table->commit = 1;
					hdr_proc_ctx_table->num_proc_ctxs = 1;
					hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
					hdr_proc_ctx->type = IPA_HDR_PROC_MARK_DSCP;

					hdr_proc_ctx->pdn_dscp_params.valid = 1;
					hdr_proc_ctx->pdn_dscp_params.dscp_val = qos_param->dscp_mark_val;

					hdr_proc_ctx->hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6;
					IPACMDBG_H("hdr_proc_ctx->hdr_hdl v6 0x%x\n", hdr_proc_ctx->hdr_hdl);

					if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
						hdr_proc_ctx_table->proc_ctx[0].status != 0) {
						IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX for dscp marking failed: %d\n",
							hdr_proc_ctx_table->proc_ctx[0].status);
						free(hdr_proc_ctx_table);
						free(rt_rule);
						return IPACM_FAILURE;
					}

					rt_rule_entry->rule.hdr_proc_ctx_hdl = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
					IPACMDBG_H("rt->hdr_proc_ctx_hdl v6 0x%x\n", rt_rule_entry->rule.hdr_proc_ctx_hdl);

					if (false == m_routing.AddRoutingRuleExt_v2(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						free(rt_rule);
						return IPACM_FAILURE;
					}

					/* copy ipv6 RT hdl */
					memset(&new_client_info, 0 , sizeof(new_client_info));
					new_client_info.qos_rt_rule_hdl_v6 = ((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[0].rt_rule_hdl;
					new_client_info.route_rule_set_v6 = true;
					new_client_info.dscp_hpc_hdl_v6 = rt_rule_entry->rule.hdr_proc_ctx_hdl;
					new_client_info.client_iface = ipa_if_num;

					new_client_info.v6_ip_addr[0] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[0];
					new_client_info.v6_ip_addr[1] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[1];
					new_client_info.v6_ip_addr[2] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[2];
					new_client_info.v6_ip_addr[3] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[3];

					memcpy(new_client_info.mac,
						get_client_memptr(wlan_client, wlan_index)->mac,
						IPA_MAC_ADDR_SIZE);

					IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d iface %d\n", tx_index,
							   new_client_info.qos_rt_rule_hdl_v6, iptype, new_client_info.client_iface);
					qos_param->qos_client_list.push_front(new_client_info);
					qos_param->client_cnt++;
				}
			}

		} /* end of for loop */

		free(rt_rule);
	}
	return IPACM_SUCCESS;
}

int IPACM_Wlan::if_wlan_client_qos_rule_needed(uint8_t * client_mac,
	uint16_t client_vlan_id, list<qos_param_info>::iterator qos_param,
	uint32_t *ipv6_addr)
{
	int ret = false;
	int i = 0;
	list<qos_client_info>::iterator it_qos_client;
	int wlan_index;
	uint8_t null_mac[IPA_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};

	wlan_index = get_wlan_client_index(client_mac, client_vlan_id);
	if (wlan_index == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached\n");
		return ret;
	}

	if (!qos_param->dscp_mark_val)
	{
		IPACMERR("dscp marking not available for this qos config: %d .."
			"skip this qos config\n", qos_param->dscp_mark_val);
		return ret;
	}

	// Check if vlan type is matching, if client is non-vlan then qos param can't be vlan and vice versa
	if (qos_param->vlan_id &&
		(client_vlan_id != qos_param->vlan_id))
	{
		IPACMDBG_H("Vlan client for non-vlan qos param or vice-versa,"
				   "client vlan id %d , qos vlanid %d\n",
				   client_vlan_id, qos_param->vlan_id);
		return ret;
	}

	// Check if mac id is matching the qos rule mac id
	if (memcmp(qos_param->dst_mac_addr, null_mac, sizeof(null_mac)) &&
		memcmp(qos_param->dst_mac_addr,
		get_client_memptr(wlan_client, wlan_index)->mac, IPA_MAC_ADDR_SIZE))
	{
		IPACMDBG_H("Destination qos mac address %x:%x:%x:%x:%x:%x requested "
				   "does not match client mac %x:%x:%x:%x:%x:%x, client vlanid %d\n",
					 qos_param->dst_mac_addr[0], qos_param->dst_mac_addr[1],
					 qos_param->dst_mac_addr[2], qos_param->dst_mac_addr[3],
					 qos_param->dst_mac_addr[4], qos_param->dst_mac_addr[5],
					 get_client_memptr(wlan_client, wlan_index)->mac[0],
					 get_client_memptr(wlan_client, wlan_index)->mac[1],
					 get_client_memptr(wlan_client, wlan_index)->mac[2],
					 get_client_memptr(wlan_client, wlan_index)->mac[3],
					 get_client_memptr(wlan_client, wlan_index)->mac[4],
					 get_client_memptr(wlan_client, wlan_index)->mac[5],
					 client_vlan_id);
		return ret;
	}

	//don't install qos rules if client rules are not set
	if (qos_param->ip_type == IPA_IP_v4)
	{
		if (!get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4)
		{
			IPACMDBG_H("v4 client rule is not set: %d, "
					"cannot install qos v4 rule for this client\n",
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4);
			return ret;
		}
		if (qos_param->ip_tup.dst_ip_addr)
		{
			if (qos_param->ip_tup.dst_ip_addr !=
				get_client_memptr(wlan_client, wlan_index)->v4_addr)
			{
				IPACMERR("Mismatched destination qos ip addr 0x%x with client ip 0x%x\n",
					qos_param->ip_tup.dst_ip_addr,
					get_client_memptr(wlan_client, wlan_index)->v4_addr);
				return ret;
			}
		}
	}

	if (qos_param->ip_type == IPA_IP_v6)
	{
		if (!get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6)
		{
			IPACMDBG_H("v6 client rule is not set: %d, "
				"cannot install qos v6 rule for this client\n",
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6);
			return ret;
		}
		if (qos_param->ip_tup.dst_v6_ip_addr[0] ||
			qos_param->ip_tup.dst_v6_ip_addr[1])
		{
			if (!ipv6_addr)
			{
				IPACMDBG_H("NULL IPv6 addr received, cannot install.\n");
				return ret;
			}
			if (qos_param->ip_tup.dst_v6_ip_addr[0] != ipv6_addr[0] ||
				qos_param->ip_tup.dst_v6_ip_addr[1] != ipv6_addr[1] ||
				qos_param->ip_tup.dst_v6_ip_addr[2] != ipv6_addr[2] ||
				qos_param->ip_tup.dst_v6_ip_addr[3] != ipv6_addr[3])
			{
				IPACMERR("Mismatched destination qos ip addr "
					"0x%x:%x:%x:%x with client ip 0x%x:%x:%x:%x\n",
					qos_param->ip_tup.dst_v6_ip_addr[0],
					qos_param->ip_tup.dst_v6_ip_addr[1],
					qos_param->ip_tup.dst_v6_ip_addr[2],
					qos_param->ip_tup.dst_v6_ip_addr[3],
					ipv6_addr[0],
					ipv6_addr[1],
					ipv6_addr[2],
					ipv6_addr[3]);
				return ret;
			}
		}
	}

	for (it_qos_client = qos_param->qos_client_list.begin();
		it_qos_client != qos_param->qos_client_list.end(); ++it_qos_client)
	{
		if (it_qos_client->v4_ip_addr &&
			(it_qos_client->v4_ip_addr ==
				get_client_memptr(wlan_client, wlan_index)->v4_addr))
		{
			IPACMDBG_H("v4 Client already exists in qos list,"
					   "Client vlan id %d , qos vlanid %d\n",
					 client_vlan_id, qos_param->vlan_id);
			return ret;
		}

		if (it_qos_client->v6_ip_addr[0] && ipv6_addr &&
			it_qos_client->v6_ip_addr[0] == ipv6_addr[0] &&
			it_qos_client->v6_ip_addr[1] == ipv6_addr[1] &&
			it_qos_client->v6_ip_addr[2] == ipv6_addr[2] &&
			it_qos_client->v6_ip_addr[3] == ipv6_addr[3]
			)
		{
			IPACMDBG_H("v6 Client already exists in qos list, Client vlan id %d , qos vlanid %d\n",
					 client_vlan_id, qos_param->vlan_id);
			return ret;
		}
	}

	ret = true;
	IPACMDBG_H("No qos rule exists for this client, Adding qos rule for client "
		"at idx %d\n", wlan_index);
	return ret;
}

int IPACM_Wlan::install_all_wlan_qos_route_rule(uint8_t * client_mac,
	uint16_t client_vlan_id, uint32_t *ipv6_addr)
{

	list<qos_param_info>::iterator it_qos_params;
	int client_idx = 0;
	int wlan_index = 0;
	bool commit_rule = false;

	IPACMDBG_H("Install_all_qos_route_rule called start 0x%x, end 0x%x \n",
				IPACM_Iface::ipacmcfg->m_qos_params.begin(),
				IPACM_Iface::ipacmcfg->m_qos_params.end());

	wlan_index = get_wlan_client_index(client_mac, client_vlan_id);
	if (wlan_index == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached\n");
		return 0;
	}

	if(pthread_mutex_lock(&IPACM_Iface::ipacmcfg->qos_param_list_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return IPACM_FAILURE;
	}

	for (it_qos_params = IPACM_Iface::ipacmcfg->m_qos_params.begin();
		it_qos_params != IPACM_Iface::ipacmcfg->m_qos_params.end(); ++it_qos_params)
	{
		IPACMDBG_H("Individual qos rules with ip type: %d and tc: %d\n",
			(ipa_ip_type)it_qos_params->ip_type, it_qos_params->traffic_class);
		IPACMDBG("Install_all_qos_route_rule it_qos_params called start 0x%x\n",
			   it_qos_params);

		if (!it_qos_params->dscp_mark_val)
		{
			IPACMDBG_H("No dscp marking info passed: %d .. skip this rule\n",
				it_qos_params->dscp_mark_val);
		}

		if (it_qos_params->ip_type == IPA_IP_v4)
		{
			if (if_wlan_client_qos_rule_needed(client_mac, client_vlan_id,
				it_qos_params, NULL))
			{
				commit_rule = true;
				IPACMDBG_H("Install qos rules with ip type: %d and tc: %d\n",
					(ipa_ip_type)it_qos_params->ip_type,
					it_qos_params->traffic_class);

				if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == true)
				{
					handle_wlan_qos_route_rule_ext_v2(client_mac, client_vlan_id,
					(ipa_ip_type)it_qos_params->ip_type, it_qos_params, NULL);
				}
				else
				{
					handle_wlan_qos_route_rule(client_mac, client_vlan_id,
					(ipa_ip_type)it_qos_params->ip_type, it_qos_params, NULL);
				}
			}
		}
		else
		{
			if (ipv6_addr != NULL)
			{
				if (if_wlan_client_qos_rule_needed(client_mac, client_vlan_id,
					it_qos_params, ipv6_addr))
				{
					commit_rule = true;
					IPACMDBG_H("Install qos rules with ip type: %d and tc: %d\n",
						(ipa_ip_type)it_qos_params->ip_type,
						it_qos_params->traffic_class);

					if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == true)
					{
						handle_wlan_qos_route_rule_ext_v2(client_mac, client_vlan_id,
						(ipa_ip_type)it_qos_params->ip_type, it_qos_params, ipv6_addr);
					}
					else
					{
						handle_wlan_qos_route_rule(client_mac, client_vlan_id,
						(ipa_ip_type)it_qos_params->ip_type, it_qos_params, ipv6_addr);
					}
				}
			}
			else
			{
				for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end(); ++it)
				{
					uint32_t ip6[4];
					ip6[0] = it->first[0];
					ip6[1] = it->first[1];
					ip6[2] = it->first[2];
					ip6[3] = it->first[3];
					if (if_wlan_client_qos_rule_needed(client_mac, client_vlan_id,
						it_qos_params,
						ip6))
					{
						commit_rule = true;
						IPACMDBG_H("Install qos rules with ip type: %d and tc: %d\n",
							(ipa_ip_type)it_qos_params->ip_type,
							it_qos_params->traffic_class);

						if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == true)
						{
							handle_wlan_qos_route_rule_ext_v2(client_mac, client_vlan_id,
							(ipa_ip_type)it_qos_params->ip_type, it_qos_params,
							ip6);
						}
						else
						{
							handle_wlan_qos_route_rule(client_mac, client_vlan_id,
							(ipa_ip_type)it_qos_params->ip_type, it_qos_params,
							ip6);
						}
					}
				}
			}
		}
	}
	pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->qos_param_list_lock);

	if(commit_rule == false)
	{
		IPACMDBG_H("No rule needs to be committed.. Exit\n");
		return IPACM_SUCCESS;
	}

	if (false == m_routing.Commit(IPA_IP_v4))
	{
		IPACMERR("QOS Routing rule v4 commit failed!\n");
		return IPACM_FAILURE;
	}

	if (false == m_routing.Commit(IPA_IP_v6))
	{
		IPACMERR("QOS Routing rule v6 commit failed!\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("QOS Routing rule added successfully \n");

	return IPACM_SUCCESS;
}

int IPACM_Wlan::delete_wlan_client_info_from_qos(uint8_t *client_mac,
				uint16_t vlan_id, list<qos_param_info>::iterator qos_param,
				uint32_t *ipv6_addr)
{
	list<qos_client_info>::iterator it_qos_client;
	int wlan_index;

	wlan_index = get_wlan_client_index(client_mac, vlan_id);
	if (wlan_index == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Attempting to delete qos entry for client at idx %d"
		" with vlan %d\n", wlan_index, vlan_id);

	for (it_qos_client = qos_param->qos_client_list.begin();
		it_qos_client != qos_param->qos_client_list.end(); )
	{
		if (qos_param->ip_type == IPA_IP_v4)
		{
			if (it_qos_client->v4_ip_addr &&
				(it_qos_client->v4_ip_addr ==
					get_client_memptr(wlan_client, wlan_index)->v4_addr))
			{
				IPACMDBG_H("Found a matching vlan %d entry in qos rule list "
					"for client with ipv4: 0x\n",
					vlan_id, it_qos_client->v4_ip_addr);

				//Delete the respective route handles
				IPACMDBG_H("Delete client rule from index %d is v4 set %d for hdl %d\n",
					wlan_index, it_qos_client->route_rule_set_v4,
					it_qos_client->qos_rt_rule_hdl_v4);

				if (it_qos_client->route_rule_set_v4 &&
					(m_routing.DeleteRoutingHdl(it_qos_client->qos_rt_rule_hdl_v4,
						IPA_IP_v4) == false)) {
					IPACMERR("Failed to delete v4 qos routing rule hdl %d\n",
						it_qos_client->qos_rt_rule_hdl_v4);
					return IPACM_FAILURE;
				}

				// Delete respective header processing contexts
				IPACMDBG_H("Deleting dscp v4 hpc 0x%x\n", it_qos_client->dscp_hpc_hdl_v4);
				if (it_qos_client->dscp_hpc_hdl_v4)
				{
					if (m_header.DeleteHeaderProcCtx(it_qos_client->dscp_hpc_hdl_v4)
						== false)
					{
						IPACMERR("Failed to delete qos dscp hpc v4 hdl 0x%x\n",
						it_qos_client->qos_rt_rule_hdl_v4);
						return IPACM_FAILURE;
					}
				}

				it_qos_client =
					qos_param->qos_client_list.erase(it_qos_client);
				qos_param->client_cnt--;
				IPACMDBG_H("Current client_cnt %d\n", qos_param->client_cnt);
			}
			else
			{
				it_qos_client++;
			}
		}

		else
		{
			if (ipv6_addr == NULL)
			{
				/* Check all v6 addresses of the client. */
				for (auto it = rt_hdl_v6_list[wlan_index].begin(); it != rt_hdl_v6_list[wlan_index].end(); ++it)
				{
					if (it_qos_client->v6_ip_addr[0] &&
						it_qos_client->v6_ip_addr[0] ==
						it->first[0] &&
						it_qos_client->v6_ip_addr[1] ==
						it->first[1] &&
						it_qos_client->v6_ip_addr[2] ==
						it->first[2] &&
						it_qos_client->v6_ip_addr[3] ==
						it->first[3])
					{
						IPACMDBG_H("Delete client rule from index %d is"
						" v6 set %d for hdl %d\n", wlan_index,
						it_qos_client->route_rule_set_v6,
						it_qos_client->qos_rt_rule_hdl_v6);
						if (it_qos_client->route_rule_set_v6 &&
							(m_routing.DeleteRoutingHdl(
								it_qos_client->qos_rt_rule_hdl_v6,
								IPA_IP_v6) == false)) {
							IPACMERR("Failed to delete v6 qos routing rule hdl %d\n",
								it_qos_client->qos_rt_rule_hdl_v6);
							return IPACM_FAILURE;
						}

						IPACMDBG_H("Deleting dscp v6 hpc 0x%x\n", it_qos_client->dscp_hpc_hdl_v6);
						if (it_qos_client->dscp_hpc_hdl_v6)
						{
							if (m_header.DeleteHeaderProcCtx(it_qos_client->dscp_hpc_hdl_v6)
								== false)
							{
								IPACMERR("Failed to delete qos dscp hpc v6 hdl 0x%x\n",
								it_qos_client->qos_rt_rule_hdl_v6);
								return IPACM_FAILURE;
							}
						}

						it_qos_client =
							qos_param->qos_client_list.erase(it_qos_client);
						qos_param->client_cnt--;
						IPACMDBG_H("After V6 NULL delete, client_cnt %d\n",
							qos_param->client_cnt);
						continue;
					}
				}
				it_qos_client++;
			}
			else
			{
				if (it_qos_client->v6_ip_addr[0] &&
					it_qos_client->v6_ip_addr[0] == ipv6_addr[0] &&
					it_qos_client->v6_ip_addr[1] == ipv6_addr[1] &&
					it_qos_client->v6_ip_addr[2] == ipv6_addr[2] &&
					it_qos_client->v6_ip_addr[3] == ipv6_addr[3])
				{
					IPACMDBG_H("Delete client rule from index %d is"
					" v6 set %d for hdl %d\n", wlan_index,
					it_qos_client->route_rule_set_v6,
					it_qos_client->qos_rt_rule_hdl_v6);
					if (it_qos_client->route_rule_set_v6 &&
						(m_routing.DeleteRoutingHdl(
							it_qos_client->qos_rt_rule_hdl_v6,
							IPA_IP_v6) == false)) {
						IPACMERR("Failed to delete v6 qos routing rule hdl %d\n",
							it_qos_client->qos_rt_rule_hdl_v6);
						return IPACM_FAILURE;
					}

					IPACMDBG_H("Deleting dscp v6 hpc 0x%x\n", it_qos_client->dscp_hpc_hdl_v6);
					if (it_qos_client->dscp_hpc_hdl_v6)
					{
						if (m_header.DeleteHeaderProcCtx(it_qos_client->dscp_hpc_hdl_v6)
							== false)
						{
							IPACMERR("Failed to delete qos dscp hpc v6 hdl 0x%x\n",
							it_qos_client->qos_rt_rule_hdl_v6);
							return IPACM_FAILURE;
						}
					}

					it_qos_client =
						qos_param->qos_client_list.erase(it_qos_client);
					qos_param->client_cnt--;
					IPACMDBG_H("After v6 delete, client_cnt %d\n",
						qos_param->client_cnt);
				}
				else
				{
					it_qos_client++;
				}
			}
		}
	}
	IPACMDBG_H("Final client_cnt %d\n", qos_param->client_cnt);
	return IPACM_SUCCESS;
}

int IPACM_Wlan::delete_wlan_client_qos_rule(uint8_t *client_mac,
	uint16_t vlan_id, ipa_ip_type iptype, uint32_t *ipv6_addr)
{
	list<qos_param_info>::iterator it_qos_params;

	if(pthread_mutex_lock(&IPACM_Iface::ipacmcfg->qos_param_list_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return IPACM_FAILURE;
	}

	for (it_qos_params = IPACM_Iface::ipacmcfg->m_qos_params.begin();
		(it_qos_params != IPACM_Iface::ipacmcfg->m_qos_params.end()); ++it_qos_params)
	{
		if (it_qos_params->ip_type != iptype)
		{
			continue;
		}
		delete_wlan_client_info_from_qos(client_mac, vlan_id, it_qos_params, ipv6_addr);
	}

	pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->qos_param_list_lock);
	return IPACM_SUCCESS;
}

int IPACM_Wlan::delete_all_wlan_client_info_from_qos(list<qos_param_info>::iterator qos_param)
{
	list<qos_client_info>::iterator it_qos_client;
	int ret = IPACM_SUCCESS;

	for (it_qos_client = qos_param->qos_client_list.begin();
		it_qos_client != qos_param->qos_client_list.end(); )
	{
		if (it_qos_client->client_iface != ipa_if_num)
		{
			IPACMDBG("client associated to 0x%d current iface %d ..continue ..\n",
				it_qos_client->client_iface, ipa_if_num);
			++it_qos_client;
			continue;
		}
		//Delete the respective route handles
		IPACMDBG_H("Delete client rule from is v4 set %d for hdl %d\n",
				   it_qos_client->route_rule_set_v4,
				   it_qos_client->qos_rt_rule_hdl_v4);

		if (it_qos_client->route_rule_set_v4 &&
			(m_routing.DeleteRoutingHdl(it_qos_client->qos_rt_rule_hdl_v4,
				IPA_IP_v4) == false)) {
			IPACMERR("Failed to delete v4 qos routing rule hdl %d\n",
				it_qos_client->qos_rt_rule_hdl_v4);
			ret =  IPACM_FAILURE;
		}

		// Delete respective header processing contexts
		IPACMDBG_H("Deleting dscp hpc 0x%x\n", it_qos_client->dscp_hpc_hdl_v4);
		if (it_qos_client->dscp_hpc_hdl_v4)
		{
			if (m_header.DeleteHeaderProcCtx(it_qos_client->dscp_hpc_hdl_v4)
					== false)
			{
				IPACMERR("Failed to delete qos dscp hpc v4 hdl 0x%x\n",
				it_qos_client->qos_rt_rule_hdl_v4);
				return IPACM_FAILURE;
			}
		}

		IPACMDBG_H("Delete client rule from is v6 set %d for hdl %d\n",
				   it_qos_client->route_rule_set_v6,
				   it_qos_client->qos_rt_rule_hdl_v6);
		if (it_qos_client->route_rule_set_v6 &&
			it_qos_client->qos_rt_rule_hdl_v6 &&
			(m_routing.DeleteRoutingHdl(it_qos_client->qos_rt_rule_hdl_v6, IPA_IP_v6) == false)) {
			IPACMERR("Failed to delete v6 qos routing rule hdl %d\n", it_qos_client->qos_rt_rule_hdl_v6);
			ret = IPACM_FAILURE;
		}

		if (it_qos_client->dscp_hpc_hdl_v6)
		{
			if (m_header.DeleteHeaderProcCtx(it_qos_client->dscp_hpc_hdl_v6)
					== false)
			{
				IPACMERR("Failed to delete qos dscp hpc v6 hdl 0x%x\n",
				it_qos_client->qos_rt_rule_hdl_v6);
				return IPACM_FAILURE;
			}
		}

		it_qos_client = qos_param->qos_client_list.erase(it_qos_client);
		qos_param->client_cnt--;
	}

	IPACMDBG_H("Qos client list size:%d cnt %d\n",
		qos_param->qos_client_list.size(), qos_param->client_cnt);
	return ret;
}

int IPACM_Wlan::delete_all_wlan_client_qos_rules()
{
	list<qos_param_info>::iterator it_qos_params;

	IPACMDBG_H("Deleting all client rules from qos config\n");
	if(pthread_mutex_lock(&IPACM_Iface::ipacmcfg->qos_param_list_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return IPACM_FAILURE;
	}

	for (it_qos_params = IPACM_Iface::ipacmcfg->m_qos_params.begin();
		it_qos_params != IPACM_Iface::ipacmcfg->m_qos_params.end();
		++it_qos_params)
	{
		delete_all_wlan_client_info_from_qos(it_qos_params);
	}

	IPACMDBG_H("Qos params list size after deleting client is now :%d \n",
		IPACM_Iface::ipacmcfg->m_qos_params.size());
	pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->qos_param_list_lock);
	return IPACM_SUCCESS;
}
