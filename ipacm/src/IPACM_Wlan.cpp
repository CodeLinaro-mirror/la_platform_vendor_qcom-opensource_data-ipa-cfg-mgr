/*
 * Copyright (c) 2013-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * Changes from Qualcomm Technologies, Inc. are provided under the following license:
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
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
#include "utilities/uapi_helper.h"


/* static member to store the number of total wifi clients within all APs*/
int IPACM_Wlan::total_num_wifi_clients = 0;

int IPACM_Wlan::num_wlan_ap_iface = 0;

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
bool IPACM_Wlan::lan_stats_inited = false;
ipa_lan_client_idx IPACM_Wlan::active_lan_client_index[IPA_MAX_NUM_HW_PATH_CLIENTS];
ipa_lan_client_idx IPACM_Wlan::inactive_lan_client_index[IPA_MAX_NUM_HW_PATH_CLIENTS];
#endif

IPACM_Wlan::IPACM_Wlan(int iface_index) : IPACM_Lan(iface_index), ipv6ct_inst(Ipv6ct::GetInstance())
{
	int i = 0;
#define WLAN_AMPDU_DEFAULT_FILTER_RULES 3

	wlan_ap_index = IPACM_Wlan::num_wlan_ap_iface;
	if(wlan_ap_index < 0 || wlan_ap_index > 2)
	{
		IPACMERR("Wlan_ap_index is not correct: %d, not creating instance.\n", wlan_ap_index);
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
		delete this;
		return;
	}

	num_wifi_client = 0;
	header_name_count = 0;
	wlan_client = NULL;
	wlan_client_len = 0;

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

	return;
}


IPACM_Wlan::~IPACM_Wlan()
{
	if(wlan_client != NULL)
	{
		free(wlan_client);
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
	int wlan_index, cnt;
	ipacm_ext_prop* ext_prop;
	ipacm_event_iface_up* data_wan;
	ipacm_event_iface_up_tehter* data_wan_tether;
	list <ipacm_event_data_all>::iterator it;
	ipacm_event_data_all *data_all=NULL;
	ipacm_event_data_vlan *vlan_data = NULL;
	ipacm_cmd_q_data evt_data;
	uint16_t vlan_id = 0;
	uint16_t bridge_if_id = 0;
	uint8_t priority = 0;
	ipa_bridge_vlan_mapping_info mapping_info;
	ipacm_event_route_vlan *vid_data;
	char master_dev_name[IF_NAME_LEN]={0};

	switch (event)
	{

	case IPA_WLAN_LINK_DOWN_EVENT:
		{
			ipacm_event_data_fid *data = (ipacm_event_data_fid *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_WLAN_LINK_DOWN_EVENT\n");
				handle_down_evt();
				if(!IPACM_Iface::ipacmcfg->get_vlan_id(dev_name, &vlan_id))
				{
					memset(master_dev_name,0,IF_NAME_LEN);
					memset(&mapping_info, 0, sizeof(mapping_info));
					mapping_info.vlan_id = DUMMY_VLAN_ID_BASE + data->if_index;
					if(!IPACM_Iface::ipacmcfg->get_bridge_vlan_mapping(&mapping_info, true))
					{
						IPACM_Iface::ipacmcfg->del_dummy_vlan_mapping(mapping_info.bridge_name,
							dev_name, data->if_index);
						bridge_if_id = mapping_info.master_if_index;
						IPACM_Iface::ipacmcfg->del_bridge_vlan_mapping(&bridge_if_id);
					}
					vid_data = (ipacm_event_route_vlan *)malloc(sizeof(ipacm_event_route_vlan));
					if(vid_data != NULL)
					{
						memset(vid_data, 0, sizeof(ipacm_event_route_vlan));
						memset(&evt_data, 0, sizeof(ipacm_cmd_q_data));
						vid_data->VlanID = DUMMY_VLAN_ID_BASE + data->if_index;
						evt_data.evt_data = vid_data;
						evt_data.event = IPA_DUMMY_VLAN_DOWN_EVENT;
						IPACMDBG_H("Posting event %s with vlan_id: %d\n",
							IPACM_Iface::ipacmcfg->getEventName(evt_data.event), vid_data->VlanID);
						if(IPACM_EvtDispatcher::PostEvt(&evt_data) != IPACM_SUCCESS) {
							free(vid_data);
							IPACMERR("Failed to post event\n");
						}
					}
				}
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
		if(data->if_index == ipa_if_num)
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
			IPACMDBG_H ("iface_ul_firewall Addr = (0x%x)\n", &iface_ul_firewall);
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

					if(IPACM_Wan::isWanUP(ipa_if_num) &&
						!IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
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
#ifdef FEATURE_IPv6CT_DISABLED
#ifdef FEATURE_IPACM_UL_FIREWALL
					IPACM_Wan::read_firewall_filter_rules_ul();
#endif //FEATURE_IPACM_UL_FIREWALL
#endif
					if(IPACM_Wan::isWanUP_V6(ipa_if_num) &&
						!IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
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
					}
#ifdef FEATURE_IPACM_UL_FIREWALL
					else
						IPACMDBG_H("WAN v6 is not UP\n");
#endif //FEATURE_IPACM_UL_FIREWALL
					IPACMDBG_H("Finished checking wan_up\n");

					if(IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
					{
						if(data->iptype == IPA_IP_v4)
						{
							IPACMDBG_H("Checking for V4 VLAN PDN\n");
							check_vlan_PDNUp(IPA_IP_v4);
						}
						if(data->iptype == IPA_IP_v6)
						{
							IPACMDBG_H("Checking for V6 VLAN PDN\n");
							check_vlan_PDNUp(IPA_IP_v6);
						}
					}
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
#else
	case IPA_HANDLE_WAN_VLAN_PDN_UP:
		{
			ipacm_event_vlan_pdn *data = (ipacm_event_vlan_pdn *)param;
			bool set_mux = true;

			if(data == NULL)
			{
				IPACMERR("No event data is found.\n");
				return;
			}

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
				/* Remove the modem flt rules installed as part of
				   IPA_ADDR_ADD_EVENT event, which wouldn't have
				   correct mux_id and re-install them in
				   handle_vlan_pdn_up */
				if(IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
				{
					if((data->iptype == IPA_IP_v4) && IPACM_Wan::isWanUP(ipa_if_num))
						handle_wan_down(false, IPACM_Wan::getXlat_Mux_Id());
					if((data->iptype == IPA_IP_v6) && IPACM_Wan::isWanUP_V6(ipa_if_num))
						handle_wan_down_v6(false);
				}
				if(is_mux_up(data->mux_id, data->iptype, data->VlanID))
				{
					set_mux = false;
				}
				handle_vlan_pdn_up(data, set_mux);
			}
		}
		break;

	case IPA_HANDLE_WAN_VLAN_PDN_DOWN:
		{
			ipacm_event_vlan_pdn *data = (ipacm_event_vlan_pdn *)param;

			if(data == NULL)
			{
				IPACMERR("No event data is found.\n");
				return;
			}

			IPACMDBG_H("Received IPA_HANDLE_WAN_VLAN_PDN_DOWN for VID %d, iptype %d\n",
				data->VlanID,
				data->iptype);
			if(!data->VlanID || is_vlan_IF(data->VlanID))
			{
#ifdef FEATURE_IPACM_UL_FIREWALL
				if(data->iptype == IPA_IP_v6)
				{
					// vlan pdn is down, disable its Q6 UL firewall and reconfigure
					disable_dft_firewall_rules_ul_ex(data->VlanID);
					configure_v6_ul_firewall();
				}
#endif
				//LTE case delete routing rule of client with associated vlan_id
				for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
				{
					IPACMDBG_H("i = %d, v6_mux_up.mux_d = %d, data.mux_id = %d\n", i, v6_mux_up[i].mux_id, data->mux_id);
					if(v6_mux_up[i].mux_id == data->mux_id)
					{
						for(int j = 0; j < IPA_MAX_NUM_SW_PDNS; j++)
						{
							if(v6_mux_up[i].associated_VIDs[j] != 0)
							{
								IPACMDBG_H("j = %d, vid = %d\n", j, v6_mux_up[i].associated_VIDs[j]);
								if(IPACM_Iface::ipacmcfg->is_dummy_VID(v6_mux_up[i].associated_VIDs[j]))
								{
									/* reset vlan client ipv6 rt-rules */
									handle_wlan_client_reset_rt(IPA_IP_v6);
									IPACMDBG_H("successfully deleted v6 rt: vid %d for mux id %d, dev %s, i = %d, j = %d, VID_cnt = %d \n",
										v6_mux_up[i].associated_VIDs[j], v6_mux_up[i].mux_id, dev_name, i, j, v6_mux_up[i].VID_cnt);
								}
							}
						}
					}
				}

				handle_vlan_pdn_down(data);
			}
		}
		break;

	case IPA_HANDLE_WAN_ADDR_ADD_V6:
		{
			data_wan = (ipacm_event_iface_up*)param;
			IPACMDBG_H("Received IPA_HANDLE_WAN_ADDR_ADD_V6 \n");
			if(data_wan == NULL)
			{
				IPACMERR("No event data is found.\n");
				break;
			}
			if(ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX)
			{
				IPACMERR("IPV6 %x %x.\n", data_wan->ipv6_prefix[0], data_wan->ipv6_prefix[1]);
				if(handle_neigh_cache_ops(POST_NEIGH_CLIENT_IP_ADDR_EVT, data_wan->ipv6_prefix) == IPACM_SUCCESS)
				{
					IPACMDBG_H("Posted Neighbor event from neigh cache with prefix 0x%08x:%08x\n",
						data_wan->ipv6_prefix[0],data_wan->ipv6_prefix[1]);
				}
			}
		}
		break;

	case IPA_HANDLE_WAN_UP:
		IPACMDBG_H("Received IPA_HANDLE_WAN_UP event\n");

		data_wan = (ipacm_event_iface_up*)param;
		if(data_wan == NULL)
		{
			IPACMERR("No event data is found.\n");
			return;
		}

		/* if dummy vlan present for iface, don't handle via default route */
		if (IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
		{
			IPACMDBG_H("Iface in dumm VLAN do not handle default route\n");
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

		/* if dummy vlan present for iface, don't handle via default route */
		if (IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
		{
			IPACMDBG_H("Iface in dumm VLAN do not handle default route\n");
			return;
		}

		IPACMDBG_H("Backhaul is sta mode?%d\n", data_wan->is_sta);
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

			if(handle_neigh_cache_ops(POST_NEIGH_CLIENT_IP_ADDR_EVT, data_wan->ipv6_prefix) == IPACM_SUCCESS)
			{
				IPACMDBG_H("Posted Neighbor event from neigh cache with prefix 0x%08x:%08x\n",
					data_wan->ipv6_prefix[0],data_wan->ipv6_prefix[1]);
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

		/* if dummy vlan present for iface, don't handle via default route */
		if (IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
		{
			IPACMDBG_H("Iface in dumm VLAN do not handle default route\n");
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

		/* if dummy vlan present for iface, don't handle via default route */
		if (IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
		{
			IPACMDBG_H("Iface in dumm VLAN do not handle default route\n");
			return;
		}

		/* clean up v6 RT rules*/
		IPACMDBG_H("Received IPA_WAN_V6_DOWN in WLAN-instance and need clean up client IPv6 address \n");
		/* reset wifi-client ipv6 rt-rules */
		handle_wlan_client_reset_rt(IPA_IP_v6);
		if(handle_neigh_cache_ops(NEIGH_CLIENT_DEL_PREFIX, data_wan->ipv6_prefix) == IPACM_SUCCESS)
		{
			IPACMDBG_H("Deleted ipv6 address from neigh cache with prefix 0x%08x:%08x\n",
				data_wan->ipv6_prefix[0],data_wan->ipv6_prefix[1]);
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
			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_WLAN_CLIENT_ADD_EVENT\n");
				handle_wlan_client_init_ex(data);
			}
		}
		break;

	case IPA_WLAN_CLIENT_DEL_EVENT:
		{
			ipacm_event_data_mac *data = (ipacm_event_data_mac *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			IPACMDBG_H("check iface %s category: %d\n", dev_name, ipa_if_cate);
			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_WLAN_CLIENT_DEL_EVENT\n");
#ifdef IPA_VLAN_PRIORITY
				if(IPACM_Iface::ipacmcfg->get_vlan_id(dev_name, &vlan_id, &priority))
#else
				if(IPACM_Iface::ipacmcfg->get_vlan_id(dev_name, &vlan_id))
#endif
				{
					IPACMDBG_H("Unable to find VLAN ID for Dev %s\n", dev_name);
					eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_DEL, IPA_IP_MAX, data->mac_addr, NULL, NULL);
				}
				else
				{
					eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_DEL, IPA_IP_MAX, data->mac_addr, NULL, NULL, vlan_id);
				}
				handle_wlan_client_down_evt(data->mac_addr);
#ifdef IPA_VLAN_PRIORITY
				if(IPACM_Iface::ipacmcfg->get_vlan_id(dev_name, &vlan_id, &priority))
#else
				if(IPACM_Iface::ipacmcfg->get_vlan_id(dev_name, &vlan_id))
#endif
				{
					IPACMERR("Unable to find VLAN ID for Dev %s\n", dev_name);
					eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_DEL, IPA_IP_MAX, data->mac_addr, NULL, NULL);
				}
				else
				{
					eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_DEL, IPA_IP_MAX, data->mac_addr, NULL, NULL, vlan_id);
				}
			}
		}
		break;

	case IPA_LAN_CLIENT_ADD_EVENT:
		{
			ipacm_event_data_all *data = (ipacm_event_data_all *)param;
			char iface_dev_name[IF_NAME_LEN]={0};
			IPACMDBG_H("Received IPA_LAN_CLIENT_ADD_EVENT\n");
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			IPACMDBG_H("check iface %s category: %d\n", dev_name, ipa_if_cate);
			if (ipa_interface_index == ipa_if_num)
			{
#ifdef IPA_VLAN_PRIORITY
				if(IPACM_Iface::ipacmcfg->get_vlan_id(data->iface_name, &vlan_id, &priority))
#else
				if(IPACM_Iface::ipacmcfg->get_vlan_id(data->iface_name, &vlan_id))
#endif
				{
					IPACMERR("Unable to find VLAN ID for Dev %s\n", data->iface_name);
					eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_ADD, IPA_IP_MAX, data->mac_addr, NULL, NULL);
				}
				else
				{
					eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_ADD, IPA_IP_MAX, data->mac_addr, NULL, NULL, vlan_id);
				}
				eth_bridge_post_event(IPA_CLIENT_CROSS_PRC_CTX, IPA_IP_MAX, data->mac_addr, NULL, data->iface_name, NULL);
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
						}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
						else
						{
#ifdef IPA_HW_FNR_STATS
							if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
								handle_wlan_client_route_rule_ext_v2(data->mac_addr, IPA_IP_v4);
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
						}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
						else
						{
#ifdef IPA_HW_FNR_STATS
							if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
								handle_wlan_client_route_rule_ext_v2(data->mac_addr, IPA_IP_v6);
							else
#endif //IPA_HW_FNR_STATS
								handle_wlan_client_route_rule_ext(data->mac_addr, IPA_IP_v6);
						}
#endif
						if (ipv6ct_inst != NULL)
						{
							for (int i = 0; i < get_client_memptr(wlan_client, wlan_index)->ipv6_set; ++i)
							{
								IPACMDBG_H("Adding IPv6 address %d IPv6CT Rules\n", i);
								ipv6ct_inst->ResetPwrSaveIf(
									Ipv6IpAddress(get_client_memptr(wlan_client, wlan_index)->v6_addr[i], false));
							}
						}
					}
				}
			}
		}
		break;

	case IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT:
		{
			ipacm_event_data_all *data = (ipacm_event_data_all *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT\n");

				/* Non Vlan with dummy VLAN handling */
				if (IPACM_Iface::ipacmcfg->is_added_vlan_iface(data->iface_name))
				{
					handle_wlan_vlan_neighbor(data);
				}
				else
				{
					if (handle_wlan_client_ipaddr(data) == IPACM_FAILURE)
					{
						return;
					}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
					if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
					{
						handle_wlan_client_route_rule(data->mac_addr, data->iptype);

						/* Add NAT/IPv6CT rules after RT rules are set */
						HandleNeighIpAddrAddEvt(data);
					}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
					else
					{
#ifdef IPA_HW_FNR_STATS
						if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
						{
							handle_wlan_client_route_rule_ext_v2(data->mac_addr, data->iptype);
							HandleNeighIpAddrAddEvt(data);
						}
						else
#endif //IPA_HW_FNR_STATS
						{
							handle_wlan_client_route_rule_ext(data->mac_addr, data->iptype);
							HandleNeighIpAddrAddEvt(data);
						}
					}
#endif

				}
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
		/* Add Natting iface to IPACM_Config if there is  Rx/Tx property */
		if (rx_prop != NULL || tx_prop != NULL)
		{
			IPACMDBG_H(" Has rx/tx properties registered for iface %s, add for NATTING \n", dev_name);
			IPACM_Iface::ipacmcfg->AddNatIfaces(dev_name);
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

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	/* QCMAP sends this event whenever a client is connected. */
	case IPA_LAN_CLIENT_CONNECT_EVENT:
	{
		ipacm_event_data_mac *data = (ipacm_event_data_mac *)param;
		ipa_interface_index = iface_ipa_index_query(data->if_index);
		if (ipa_interface_index == ipa_if_num)
		{
			IPACMDBG_H("Received IPA_LAN_CLIENT_CONNECT_EVENT wlan\n");

			for (int i = 0; i < IPA_MAX_NUM_HW_PATH_CLIENTS; i++)
			{
				if (memcmp(active_lan_client_index[i].mac, data->mac_addr, IPA_MAC_ADDR_SIZE) == 0)
				{
					IPACMDBG_H("MAC %02x:%02x:%02x:%02x:%02x:%02x has been received already, return\n",
						data->mac_addr[0], data->mac_addr[1], data->mac_addr[2],
						data->mac_addr[3], data->mac_addr[4], data->mac_addr[5]);
					return; // MAC found
				}
			}

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

	case IPA_NOTIFY_VLAN_UP:
	{
		IPACMDBG_H("Received IPA_NOTIFY_VLAN_UP\n");
		uint8_t mux_id = 0;
		vlan_data = (ipacm_event_data_vlan *)param;
		if (is_vlan_IF(vlan_data->vlan_id))
		{
			/* Remove the modem flt rules installed as part of
			   IPA_ADDR_ADD_EVENT event, which wouldn't have
			   correct mux_id and re-install them in
			   handle_vlan_pdn_up in check_vlan_PDNUp*/
			if(IPACM_Wan::backhaul_is_sta_mode == false)
			{
				if(IPACM_Wan::isWanUP(ipa_if_num) &&
				   (IPACM_FAILURE == IPACM_Wan::GetMuxByVid(vlan_data->vlan_id, &mux_id, IPA_IP_v4)))
				{
					handle_wan_down(false, IPACM_Wan::getXlat_Mux_Id());
				}
				if(IPACM_Wan::isWanUP_V6(ipa_if_num) &&
				   (IPACM_FAILURE == IPACM_Wan::GetMuxByVid(vlan_data->vlan_id, &mux_id, IPA_IP_v6)))
				{
					handle_wan_down_v6(false);
				}
			}
			if(IPACM_Wan::isVlanWanUP())
			{
				IPACMDBG_H("Check any missed v4 VLAN handling in v4 new ADDR\n");
				check_vlan_PDNUp(IPA_IP_v4);
			}
			if (IPACM_Wan::isVlanWanUP_V6())
			{
				IPACMDBG_H("Check any missed v6 VLAN handling in v6 new ADDR\n");
				check_vlan_PDNUp(IPA_IP_v6);
			}
		}
	}
	break;

#endif

	default:
		break;
	}
	return;
}

/* handle wifi client initial,copy all partial headers (tx property) */
int IPACM_Wlan::handle_wlan_client_init_ex(ipacm_event_data_wlan_ex *data)
{

#define WLAN_IFACE_INDEX_LEN 2

	int res = IPACM_SUCCESS, len = 0, i, evt_size, sta_id_size = 0;
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
	memset(get_client_memptr(wlan_client, num_wifi_client), 0, sizeof(ipa_wlan_client));
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

		/* copy partial header for v4*/
		for (cnt=0; cnt<tx_prop->num_tx_props; cnt++)
		{
			if(tx_prop->tx[cnt].ip==IPA_IP_v4)
			{
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
					if(data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_MAC_ADDR)
					{
						memcpy(get_client_memptr(wlan_client, num_wifi_client)->mac,
								data->attribs[i].u.mac_addr,
								IPA_MAC_ADDR_SIZE);

						/* copy client mac_addr to partial header */
						if (data->attribs[i].offset < (IPA_HDR_MAX_SIZE - IPA_MAC_ADDR_SIZE))
						{
							memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset],
									 get_client_memptr(wlan_client, num_wifi_client)->mac,
									 IPA_MAC_ADDR_SIZE);
							/* replace src mac to bridge mac_addr if any  */
							if (IPACM_Iface::ipacmcfg->ipa_bridge_enable)
							{
								memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset+IPA_MAC_ADDR_SIZE],
									 IPACM_Iface::ipacmcfg->bridge_mac,
									 IPA_MAC_ADDR_SIZE);
								IPACMDBG_H("device is in bridge mode \n");
							}
						}

					}
					else if(data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_STA_ID)
					{
						sta_id_size = sizeof(data->attribs[i].u.sta_id);
						/* copy client id to header */
						if (data->attribs[i].offset < (IPA_HDR_MAX_SIZE - sta_id_size))
						{
							memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset],
									&data->attribs[i].u.sta_id, sta_id_size);
						}
					}
					else
					{
						IPACMDBG_H("The attribute type is not expected!\n");
					}
				}

				pHeaderDescriptor->commit = true;
				pHeaderDescriptor->num_hdrs = 1;

				memset(pHeaderDescriptor->hdr[0].name, 0,
							 sizeof(pHeaderDescriptor->hdr[0].name));

				snprintf(index,sizeof(index), "%d", ipa_if_num);
				strlcpy(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name));
				pHeaderDescriptor->hdr[0].name[IPA_RESOURCE_NAME_MAX-1] = '\0';

				if (strlcat(pHeaderDescriptor->hdr[0].name, IPA_WLAN_PARTIAL_HDR_NAME_v4, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
				{
					IPACMERR(" header name construction failed exceed length (%d)\n", strlen(pHeaderDescriptor->hdr[0].name));
					res = IPACM_FAILURE;
					goto fail;
				}
				snprintf(index,sizeof(index), "%d", header_name_count);
				if (strlcat(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
				{
					IPACMERR(" header name construction failed exceed length (%d)\n", strlen(pHeaderDescriptor->hdr[0].name));
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
					if(data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_MAC_ADDR)
					{
						memcpy(get_client_memptr(wlan_client, num_wifi_client)->mac,
								data->attribs[i].u.mac_addr,
								IPA_MAC_ADDR_SIZE);

						/* copy client mac_addr to partial header */
						if (data->attribs[i].offset < (IPA_HDR_MAX_SIZE - IPA_MAC_ADDR_SIZE))
						{
							memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset],
								get_client_memptr(wlan_client, num_wifi_client)->mac,
								IPA_MAC_ADDR_SIZE);

							/* replace src mac to bridge mac_addr if any  */
							if (IPACM_Iface::ipacmcfg->ipa_bridge_enable)
							{
								memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset+IPA_MAC_ADDR_SIZE],
									 IPACM_Iface::ipacmcfg->bridge_mac,
									 IPA_MAC_ADDR_SIZE);
								IPACMDBG_H("device is in bridge mode \n");
							}
						}
					}
					else if (data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_STA_ID)
					{
						sta_id_size = sizeof(data->attribs[i].u.sta_id);
						/* copy client id to header */
						if (data->attribs[i].offset < (IPA_HDR_MAX_SIZE - sta_id_size))
						{
							memcpy(&pHeaderDescriptor->hdr[0].hdr[data->attribs[i].offset],
								&data->attribs[i].u.sta_id, sta_id_size);
						}
					}
					else
					{
						IPACMDBG_H("The attribute type is not expected!\n");
					}
				}

				pHeaderDescriptor->commit = true;
				pHeaderDescriptor->num_hdrs = 1;

				memset(pHeaderDescriptor->hdr[0].name, 0,
							 sizeof(pHeaderDescriptor->hdr[0].name));

				snprintf(index,sizeof(index), "%d", ipa_if_num);
				strlcpy(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name));
				pHeaderDescriptor->hdr[0].name[IPA_RESOURCE_NAME_MAX-1] = '\0';
				if (strlcat(pHeaderDescriptor->hdr[0].name, IPA_WLAN_PARTIAL_HDR_NAME_v6, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
				{
					IPACMERR(" header name construction failed exceed length (%d)\n", strlen(pHeaderDescriptor->hdr[0].name));
					res = IPACM_FAILURE;
					goto fail;
				}

				snprintf(index,sizeof(index), "%d", header_name_count);
				if (strlcat(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
				{
					IPACMERR(" header name construction failed exceed length (%d)\n", strlen(pHeaderDescriptor->hdr[0].name));
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
		get_client_memptr(wlan_client, num_wifi_client)->route_rule_set_v4 = false;
		get_client_memptr(wlan_client, num_wifi_client)->route_rule_set_v6 = 0;
		get_client_memptr(wlan_client, num_wifi_client)->ipv4_set = false;
		get_client_memptr(wlan_client, num_wifi_client)->ipv6_set = 0;
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
		wlan_index = num_wifi_client;
		num_wifi_client++;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
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
			if (IPACM_Wan::isWanUP(ipa_if_num))
			{
				if(IPACM_Wan::backhaul_is_sta_mode == false)
				{
#ifdef IPA_HW_FNR_STATS
					if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
					{
						ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
						install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v4, IPACM_Wan::getXlat_Mux_Id(), get_client_memptr(wlan_client, wlan_index)->mac,
							get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx);
					}
					else
#endif //IPA_HW_FNR_STATS
					{
						ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
						install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v4, IPACM_Wan::getXlat_Mux_Id(), get_client_memptr(wlan_client, wlan_index)->mac);
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
							get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx);
					}
					else
#endif //IPA_HW_FNR_STATS
					{
						ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
						install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v6, 0, get_client_memptr(wlan_client, wlan_index)->mac);
					}
					get_client_memptr(wlan_client, wlan_index)->ipv6_ul_rules_set = true;
				}
			}
		}
#endif
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

/*handle wifi client */
int IPACM_Wlan::handle_wlan_client_ipaddr(ipacm_event_data_all *data)
{
	int clnt_indx;
	int v6_num;
	uint32_t ipv6_link_local_prefix = 0xFE800000;
	uint32_t ipv6_link_local_prefix_mask = 0xFFC00000;
	ipacm_event_data_all data_all;
	std::list <ipacm_event_data_all>::iterator it;

	IPACMDBG_H("number of wifi clients: %d\n", num_wifi_client);
	IPACMDBG_H(" event MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 data->mac_addr[0],
					 data->mac_addr[1],
					 data->mac_addr[2],
					 data->mac_addr[3],
					 data->mac_addr[4],
					 data->mac_addr[5]);

	clnt_indx = get_wlan_client_index(data->mac_addr);

		if (clnt_indx == IPACM_INVALID_INDEX)
		{
			IPACMERR("wlan client not found/attached \n");
			return IPACM_FAILURE;
		}

	IPACMDBG_H("Ip-type received %d\n", data->iptype);
	if (data->iptype == IPA_IP_v4)
	{
		IPACMDBG_H("ipv4 address: 0x%x\n", data->ipv4_addr);
		if (data->ipv4_addr != 0) /* not 0.0.0.0 */
		{
			/* Special handling for Passthrough IP. */
			if (IPACM_Iface::ipacmcfg->is_ip_pass_enabled(device_type, data->mac_addr, 0))
			{

				/* check if the ip is in private subnet and ignore. */
				if (IPACM_Iface::ipacmcfg->isPrivateSubnet(data->ipv4_addr))
				{
					IPACMDBG_H("Client is in IP passthrough mode, but got private IP: 0x%x\n", data->ipv4_addr);
					return IPACM_FAILURE;
				}
			}
			else
			{
				/* Check if the IP is not in private subnet and ignore. */
				if (!IPACM_Iface::ipacmcfg->isPrivateSubnet(data->ipv4_addr))
				{
					IPACMDBG_H("Client is not in IP passthrough mode, but got public IP: 0x%x\n", data->ipv4_addr);
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
		         get_client_memptr(wlan_client, clnt_indx)->route_rule_set_v4 = false;
			     get_client_memptr(wlan_client, clnt_indx)->v4_addr = data->ipv4_addr;
			}
		}
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
				if(handle_neigh_cache_ops(NEIGH_CLIENT_ADD, data) != IPACM_SUCCESS)
				{
					IPACMDBG_H("Failed to add data in neigh cache\n");
				}
				IPACMDBG_H("This IPv6 address is not global IPv6 address with correct prefix, ignore.\n");
				return IPACM_FAILURE;
			}

			if(get_client_memptr(wlan_client, clnt_indx)->ipv6_set < IPV6_NUM_ADDR)
			{

		       for(v6_num=0;v6_num < get_client_memptr(wlan_client, clnt_indx)->ipv6_set;v6_num++)
				{
					if( data->ipv6_addr[0] == get_client_memptr(wlan_client, clnt_indx)->v6_addr[v6_num][0] &&
			           data->ipv6_addr[1] == get_client_memptr(wlan_client, clnt_indx)->v6_addr[v6_num][1] &&
			  	        data->ipv6_addr[2]== get_client_memptr(wlan_client, clnt_indx)->v6_addr[v6_num][2] &&
			  	         data->ipv6_addr[3] == get_client_memptr(wlan_client, clnt_indx)->v6_addr[v6_num][3])
					{
			  	    IPACMDBG_H("Already see this ipv6 addr for client:%d\n", clnt_indx);
			  	    return IPACM_FAILURE; /* not setup the RT rules*/
			  		break;
					}
				}

				/*
				 * The client got new IPv6 address.
				 * NOTE: The new address doesn't replace the existing one but being added (up to IPV6_NUM_ADDR),
				 *       so the previous IPv6 addresses of the client will not be deleted.
				 */
			   get_client_memptr(wlan_client, clnt_indx)->v6_addr[get_client_memptr(wlan_client, clnt_indx)->ipv6_set][0] = data->ipv6_addr[0];
			   get_client_memptr(wlan_client, clnt_indx)->v6_addr[get_client_memptr(wlan_client, clnt_indx)->ipv6_set][1] = data->ipv6_addr[1];
			   get_client_memptr(wlan_client, clnt_indx)->v6_addr[get_client_memptr(wlan_client, clnt_indx)->ipv6_set][2] = data->ipv6_addr[2];
			   get_client_memptr(wlan_client, clnt_indx)->v6_addr[get_client_memptr(wlan_client, clnt_indx)->ipv6_set][3] = data->ipv6_addr[3];
			   get_client_memptr(wlan_client, clnt_indx)->ipv6_set++;
		    }
		    else
		    {
				IPACMDBG_H("Already got %d ipv6 addr for client:%d\n", IPV6_NUM_ADDR, clnt_indx);
				return IPACM_FAILURE; /* not setup the RT rules*/
		    }
		}
	}

	return IPACM_SUCCESS;
}

/*handle wifi client routing rule*/
int IPACM_Wlan::handle_wlan_client_route_rule(uint8_t *mac_addr, ipa_ip_type iptype)
{
	struct ipa_ioc_add_rt_rule_v2 rt_rule{};
	struct ipa_rt_rule_add_v2 rt_rule_entry{}, *rulesPtr = nullptr;
	uint32_t tx_index;
	int wlan_index,v6_num;
	const int NUM = 1;

	if(tx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
			mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5]);

	wlan_index = get_wlan_client_index(mac_addr);
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
		rulesPtr = reinterpret_cast<decltype(rulesPtr)>(malloc(sizeof(rt_rule_entry) * NUM));
		if (!rulesPtr) {
			IPACMERR("malloc failed: %zu\n", sizeof(rt_rule_entry) * NUM);
			return IPACM_FAILURE;
		}
		memset(rulesPtr, 0, sizeof(*rulesPtr) * NUM);
		rt_rule.rules = reinterpret_cast<decltype(rt_rule.rules)>(rulesPtr);

		rt_rule.commit = 1;
		rt_rule.num_rules = (uint8_t)NUM;
		rt_rule.ip = iptype;
		rt_rule.rule_add_size = sizeof(rt_rule_entry);

		for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		{

			if(iptype != tx_prop->tx[tx_index].ip)
			{
				IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip,iptype);
				continue;
			}

			rt_rule_entry.at_rear = 0;

			if (iptype == IPA_IP_v4)
			{
				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", wlan_index,
						get_client_memptr(wlan_client, wlan_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
						wlan_index,
						get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4);
				strlcpy(rt_rule.rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
					sizeof(rt_rule.rt_tbl_name));
				rt_rule.rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';

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

				memcpy(&rt_rule_entry.rule.attrib, &tx_prop->tx[tx_index].attrib,
					sizeof(rt_rule_entry.rule.attrib));
				rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
				rt_rule_entry.rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4;
				rt_rule_entry.rule.attrib.u.v4.dst_addr = get_client_memptr(wlan_client, wlan_index)->v4_addr;
				rt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;

				if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
					rt_rule_entry.rule.hashable = true;
				UapiHelper::ruleTtlUpdateSet(rt_rule_entry.rule);
				IPACMDBG_H("ttl_update = %u\n", rt_rule_entry.rule.ttl_update);
				rulesPtr[0] = rt_rule_entry;
				if (!m_routing.addRules(&rt_rule))
				{
					IPACMERR("Routing rule addition failed!\n");
					free(rulesPtr);
					return IPACM_FAILURE;
				}

				/* copy ipv4 RT hdl */
				get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4 =
					rulesPtr[0].rt_rule_hdl;
				IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
						get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4, iptype);
			}
			else
			{
				for(v6_num = get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6;v6_num < get_client_memptr(wlan_client, wlan_index)->ipv6_set;v6_num++)
				{
					IPACMDBG_H("client(%d): v6 header handle:(0x%x)\n",
							wlan_index,
							get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6);

					/* v6 LAN_RT_TBL */
					strlcpy(rt_rule.rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_v6.name,
						sizeof(rt_rule.rt_tbl_name));
					rt_rule.rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Support QCMAP LAN traffic feature, send to A5 */
					rt_rule_entry.rule.dst = iface_query->excp_pipe;
					memset(&rt_rule_entry.rule.attrib, 0, sizeof(rt_rule_entry.rule.attrib));
					rt_rule_entry.rule.hdr_hdl = 0;
					rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry.rule.attrib.u.v6.dst_addr[0] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][0];
					rt_rule_entry.rule.attrib.u.v6.dst_addr[1] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][1];
					rt_rule_entry.rule.attrib.u.v6.dst_addr[2] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][2];
					rt_rule_entry.rule.attrib.u.v6.dst_addr[3] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][3];
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
#ifdef FEATURE_IPA_V3
					rt_rule_entry.rule.hashable = true;
#endif
					rulesPtr[0] = rt_rule_entry;
					if (!m_routing.addRules(&rt_rule)) {
						IPACMERR("Routing rule addition failed!\n");
						free(rulesPtr);
						return IPACM_FAILURE;
					}

					get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v6[v6_num] =
						rulesPtr[0].rt_rule_hdl;
					IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
							get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v6[v6_num], iptype);

					/*Copy same rule to v6 WAN RT TBL*/
					strlcpy(rt_rule.rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name,
						sizeof(rt_rule.rt_tbl_name));
					rt_rule.rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Downlink traffic from Wan iface, directly through IPA */
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
					memcpy(&rt_rule_entry.rule.attrib, &tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry.rule.attrib));
					rt_rule_entry.rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6;
					rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry.rule.attrib.u.v6.dst_addr[0] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][0];
					rt_rule_entry.rule.attrib.u.v6.dst_addr[1] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][1];
					rt_rule_entry.rule.attrib.u.v6.dst_addr[2] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][2];
					rt_rule_entry.rule.attrib.u.v6.dst_addr[3] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][3];
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
#ifdef FEATURE_IPA_V3
					rt_rule_entry.rule.hashable = true;
#endif
					UapiHelper::ruleTtlUpdateSet(rt_rule_entry.rule);
					IPACMDBG_H("ttl_update = %u\n", rt_rule_entry.rule.ttl_update);
					rulesPtr[0] = rt_rule_entry;
					if (!m_routing.addRules(&rt_rule)) {
						IPACMERR("Routing rule addition failed!\n");
						free(rulesPtr);
						return IPACM_FAILURE;
					}

					get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v6_wan[v6_num] =
						rulesPtr[0].rt_rule_hdl;

					IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
							get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v6_wan[v6_num], iptype);
				}
			}

		} /* end of for loop */

		free(rulesPtr);

		if (iptype == IPA_IP_v4)
		{
			get_client_memptr(wlan_client, wlan_index)->route_rule_set_v4 = true;
		}
		else
		{
			get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6 = get_client_memptr(wlan_client, wlan_index)->ipv6_set;
		}
	}

	return IPACM_SUCCESS;
}

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
int IPACM_Wlan::handle_lan_client_connect(uint8_t *mac_addr)
{
	int wlan_index, res = IPACM_SUCCESS;
	ipacm_ext_prop* ext_prop;
	struct wan_ioctl_lan_client_info *client_info;
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
		if (IPACM_Wan::isWanUP(ipa_if_num))
		{
			if(IPACM_Wan::backhaul_is_sta_mode == false)
			{
				ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
#ifdef IPA_HW_FNR_STATS
				if (IPACM_Wan::ipacmcfg->hw_fnr_stats_support)
					install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v4, IPACM_Wan::getXlat_Mux_Id(), 
						get_client_memptr(wlan_client, wlan_index)->mac,
						get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx);
				else
#endif //IPA_HW_FNR_STATS
					install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v4, IPACM_Wan::getXlat_Mux_Id(),
						get_client_memptr(wlan_client, wlan_index)->mac);
				get_client_memptr(wlan_client, wlan_index)->ipv4_ul_rules_set = true;
			}
		}
		if(IPACM_Wan::isWanUP_V6(ipa_if_num))
		{
			if(IPACM_Wan::backhaul_is_sta_mode == false)
			{
				ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
#ifdef IPA_HW_FNR_STATS
				if (IPACM_Wan::ipacmcfg->hw_fnr_stats_support)
					install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v6, 0, get_client_memptr(wlan_client, wlan_index)->mac,
							get_client_memptr(wlan_client, wlan_index)->ul_cnt_idx);
				else
#endif //IPA_HW_FNR_STATS
					install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v6, 0, get_client_memptr(wlan_client, wlan_index)->mac);
				get_client_memptr(wlan_client, wlan_index)->ipv6_ul_rules_set = true;
			}
		}
#ifdef IPA_HW_FNR_STATS
		if (IPACM_Wan::ipacmcfg->hw_fnr_stats_support)
		{
			handle_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client, wlan_index)->mac, IPA_IP_v4);
			handle_wlan_client_route_rule_ext_v2(get_client_memptr(wlan_client, wlan_index)->mac, IPA_IP_v6);
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
	int i, ipa_if_num1;
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
int IPACM_Wlan::handle_wlan_client_route_rule_ext(uint8_t *mac_addr, ipa_ip_type iptype)
{
	struct ipa_ioc_add_rt_rule_ext_v2 rt_rule{};
	struct ipa_rt_rule_add_ext_v2 rt_rule_entry{}, *rulesPtr = nullptr;
	uint32_t tx_index;
	int wlan_index,v6_num;
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

	wlan_index = get_wlan_client_index(mac_addr);
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
		rulesPtr = reinterpret_cast<decltype(rulesPtr)>(malloc(sizeof(rt_rule_entry) * NUM));
		if (!rulesPtr) {
			IPACMERR("malloc failed: %zu\n", sizeof(rt_rule_entry) * NUM);
			return IPACM_FAILURE;
		}
		memset(rulesPtr, 0, sizeof(*rulesPtr) * NUM);
		rt_rule.rules = reinterpret_cast<decltype(rt_rule.rules)>(rulesPtr);

		rt_rule.commit = 1;
		rt_rule.num_rules = (uint8_t)NUM;
		rt_rule.ip = iptype;
		rt_rule.rule_add_ext_size = sizeof(rt_rule_entry);

		for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		{

			if(iptype != tx_prop->tx[tx_index].ip)
			{
				IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip,iptype);
				continue;
			}

			rt_rule_entry.at_rear = 0;

			if (iptype == IPA_IP_v4)
			{
				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", wlan_index,
						get_client_memptr(wlan_client, wlan_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
						wlan_index,
						get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4);
				strlcpy(rt_rule.rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
					sizeof(rt_rule.rt_tbl_name));
				rt_rule.rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';

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

				memcpy(&rt_rule_entry.rule.attrib, &tx_prop->tx[tx_index].attrib,
					sizeof(rt_rule_entry.rule.attrib));
				rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
				rt_rule_entry.rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v4;
				rt_rule_entry.rule.attrib.u.v4.dst_addr = get_client_memptr(wlan_client, wlan_index)->v4_addr;
				rt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;

				if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
					rt_rule_entry.rule.hashable = true;

				rt_rule_entry.rule_id = 0;
				if (get_client_memptr(wlan_client, wlan_index)->lan_stats_idx != -1)
					rt_rule_entry.rule_id = get_client_memptr(wlan_client, wlan_index)->lan_stats_idx | 0x200;
				UapiHelper::ruleTtlUpdateSet(rt_rule_entry.rule);
				IPACMDBG_H("ttl_update = %u\n", rt_rule_entry.rule.ttl_update);
				rulesPtr[0] = rt_rule_entry;
				if (!m_routing.AddRoutingRuleExt_v2(&rt_rule))
				{
					IPACMERR("Routing rule addition failed!\n");
					free(rulesPtr);
					return IPACM_FAILURE;
				}

				/* copy ipv4 RT hdl */
				get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4 =
					rulesPtr[0].rt_rule_hdl;
				IPACMDBG_H("tx:%d, rt rule id=%x ip-type: %d\n", tx_index, rt_rule_entry.rule_id, iptype);

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
				for(v6_num = get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6;v6_num < get_client_memptr(wlan_client, wlan_index)->ipv6_set;v6_num++)
				{
					IPACMDBG_H("client(%d): v6 header handle:(0x%x)\n",
							wlan_index,
							get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6);

					/* v6 LAN_RT_TBL */
					strlcpy(rt_rule.rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_v6.name,
						sizeof(rt_rule.rt_tbl_name));
					rt_rule.rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Support QCMAP LAN traffic feature, send to A5 */
					rt_rule_entry.rule.dst = iface_query->excp_pipe;
					memset(&rt_rule_entry.rule.attrib, 0, sizeof(rt_rule_entry.rule.attrib));
					rt_rule_entry.rule.hdr_hdl = 0;
					rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry.rule.attrib.u.v6.dst_addr[0] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][0];
					rt_rule_entry.rule.attrib.u.v6.dst_addr[1] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][1];
					rt_rule_entry.rule.attrib.u.v6.dst_addr[2] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][2];
					rt_rule_entry.rule.attrib.u.v6.dst_addr[3] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][3];
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
#ifdef FEATURE_IPA_V3
					rt_rule_entry.rule.hashable = true;
#endif
					rt_rule_entry.rule_id = 0;
					rulesPtr[0] = rt_rule_entry;
					if (!m_routing.AddRoutingRuleExt_v2(&rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						free(rulesPtr);
						return IPACM_FAILURE;
					}

					get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v6[v6_num] = rulesPtr[0].rt_rule_hdl;
					IPACMDBG_H("tx:%d, rt rule id=%x ip-type: %d\n", tx_index, rt_rule_entry.rule_id, iptype);

					/*Copy same rule to v6 WAN RT TBL*/
					strlcpy(rt_rule.rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name,
						sizeof(rt_rule.rt_tbl_name));
					rt_rule.rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Downlink traffic from Wan iface, directly through IPA */
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
					memcpy(&rt_rule_entry.rule.attrib, &tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry.rule.attrib));
					rt_rule_entry.rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6;
					rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry.rule.attrib.u.v6.dst_addr[0] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][0];
					rt_rule_entry.rule.attrib.u.v6.dst_addr[1] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][1];
					rt_rule_entry.rule.attrib.u.v6.dst_addr[2] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][2];
					rt_rule_entry.rule.attrib.u.v6.dst_addr[3] =
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][3];
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
#ifdef FEATURE_IPA_V3
					rt_rule_entry.rule.hashable = true;
#endif
					rt_rule_entry.rule_id = 0;
					if (get_client_memptr(wlan_client, wlan_index)->lan_stats_idx != -1) {
						rt_rule_entry.rule_id = get_client_memptr(wlan_client, wlan_index)->lan_stats_idx | 0x200;
					}
					UapiHelper::ruleTtlUpdateSet(rt_rule_entry.rule);
					IPACMDBG_H("ttl_update = %u\n", rt_rule_entry.rule.ttl_update);
					rulesPtr[0] = rt_rule_entry;
					if (!m_routing.AddRoutingRuleExt_v2(&rt_rule)) {
						IPACMERR("Routing rule addition failed!\n");
						free(rulesPtr);
						return IPACM_FAILURE;
					}

					get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v6_wan[v6_num] =
						rulesPtr[0].rt_rule_hdl;

					IPACMDBG_H("tx:%d, rt rule id=%x ip-type: %d\n", tx_index, rt_rule_entry.rule_id, iptype);

					/* Add IPv6CT rules after ipv6 RT rules are set */
					memset(&data, 0, sizeof(data));
					data.if_index = IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].netlink_interface_index;
					data.iptype = IPA_IP_v6;
                                        memcpy(data.ipv6_addr,
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num], sizeof(data.ipv6_addr));
                                       CtList->HandleNeighIpAddrAddEvt_v6(&data);
				}
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6 = get_client_memptr(wlan_client, wlan_index)->ipv6_set;
			}

		} /* end of for loop */

		free(rulesPtr);
	}

	return IPACM_SUCCESS;
}

#ifdef IPA_HW_FNR_STATS
int IPACM_Wlan::handle_wlan_client_route_rule_ext_v2(uint8_t *mac_addr, ipa_ip_type iptype)
{
	struct ipa_ioc_add_rt_rule_ext_v2 *rt_rule;
	struct ipa_rt_rule_add_ext_v2 *rt_rule_entry;
	uint32_t tx_index;
	int wlan_index,v6_num;
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

	wlan_index = get_wlan_client_index(mac_addr);
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
				for(v6_num = get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6;v6_num < get_client_memptr(wlan_client, wlan_index)->ipv6_set;v6_num++)
				{
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
					rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][0];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][1];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][2];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][3];
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

					get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v6[v6_num] =
						((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[0].rt_rule_hdl;
					IPACMDBG_H("tx:%d, rt rule id=%x ip-type: %d\n", tx_index,
							rt_rule_entry->rule_id, iptype);

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
					rt_rule_entry->rule.hdr_hdl = get_client_memptr(wlan_client, wlan_index)->hdr_hdl_v6;
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][0];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][1];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][2];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][3];
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

					get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v6_wan[v6_num] =
						((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[0].rt_rule_hdl;

					IPACMDBG_H("tx:%d, rt rule id=%x ip-type: %d\n", tx_index,
							rt_rule_entry->rule_id, iptype);

					/* Add IPv6CT rules after ipv6 RT rules are set */
					memset(&data, 0, sizeof(data));
					data.if_index = IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].netlink_interface_index;
					data.iptype = IPA_IP_v6;
					memcpy(data.ipv6_addr,
						get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num], sizeof(data.ipv6_addr));
					CtList->HandleNeighIpAddrAddEvt_v6(&data);
				}
				get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6 = get_client_memptr(wlan_client, wlan_index)->ipv6_set;
			}

		} /* end of for loop */

		free(rt_rule);
	}

	return IPACM_SUCCESS;
}
#endif //IPA_HW_FNR_STATS
#endif
/*handle wifi client power-save mode*/
int IPACM_Wlan::handle_wlan_client_pwrsave(uint8_t *mac_addr)
{
	int clt_indx;
	IPACMDBG_H("wlan->handle_wlan_client_pwrsave();\n");

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
			for (int i = 0; i < get_client_memptr(wlan_client, clt_indx)->ipv6_set; ++i)
			{
				IPACMDBG_H("Deleting IPv6 address %d IPv6CT Rules\n", i);
				ipv6ct_inst->UpdatePwrSaveIf(
					Ipv6IpAddress(get_client_memptr(wlan_client, clt_indx)->v6_addr[i], false));
			}
		}

		IPACMDBG_H("Deleting default qos Route Rules\n");
		delete_default_qos_rtrules(clt_indx, IPA_IP_v4);
		delete_default_qos_rtrules(clt_indx, IPA_IP_v6);
		get_client_memptr(wlan_client, clt_indx)->power_save_set = true;
	}
	else
	{
		IPACMDBG_H("wlan client already in power-save mode\n");
	}
    return IPACM_SUCCESS;
}

/*handle wifi client del mode*/
int IPACM_Wlan::handle_wlan_client_down_evt(uint8_t *mac_addr)
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

	clt_indx = get_wlan_client_index(mac_addr);
	if (clt_indx == IPACM_INVALID_INDEX)
	{
		IPACMDBG_H("wlan client not attached\n");
		return IPACM_SUCCESS;
	}

	/* First reset NAT/IPv6CT rules and then route rules */
	HandleNeighIpAddrDelEvt(
		get_client_memptr(wlan_client, clt_indx)->ipv4_set,
		get_client_memptr(wlan_client, clt_indx)->v4_addr,
		get_client_memptr(wlan_client, clt_indx)->ipv6_set,
		get_client_memptr(wlan_client, clt_indx)->v6_addr);

	if (delete_default_qos_rtrules(clt_indx, IPA_IP_v4))
	{
		IPACMERR("unbale to delete v4 default qos route rules for index: %d\n", clt_indx);
		return IPACM_FAILURE;
	}

	if (delete_default_qos_rtrules(clt_indx, IPA_IP_v6))
	{
		IPACMERR("unbale to delete v6 default qos route rules for indexn: %d\n", clt_indx);
		return IPACM_FAILURE;
	}

	/* Delete wlan client header */
	if(get_client_memptr(wlan_client, clt_indx)->ipv4_header_set == true)
	{
	if (m_header.DeleteHeaderHdl(get_client_memptr(wlan_client, clt_indx)->hdr_hdl_v4)
			== false)
	{
		return IPACM_FAILURE;
	}
		get_client_memptr(wlan_client, clt_indx)->ipv4_header_set = false;
	}

	if(get_client_memptr(wlan_client, clt_indx)->ipv6_header_set == true)
	{
	if (m_header.DeleteHeaderHdl(get_client_memptr(wlan_client, clt_indx)->hdr_hdl_v6)
			== false)
	{
		return IPACM_FAILURE;
	}
		get_client_memptr(wlan_client, clt_indx)->ipv6_header_set = false;
	}

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	if (get_client_memptr(wlan_client, clt_indx)->ipv4_ul_rules_set == true)
	{
		if (delete_uplink_filter_rule_per_client(IPA_IP_v4, get_client_memptr(wlan_client, clt_indx)->mac))
		{
			IPACMERR("unbale to delete uplink v4 filter rules for index: %d\n", clt_indx);
			return IPACM_FAILURE;
		}
	}

	if (get_client_memptr(wlan_client, clt_indx)->ipv6_ul_rules_set == true)
	{
		if (delete_uplink_filter_rule_per_client(IPA_IP_v6, get_client_memptr(wlan_client, clt_indx)->mac))
		{
			IPACMERR("unbale to delete uplink v6 filter rules for index: %d\n", clt_indx);
			return IPACM_FAILURE;
		}
	}
#endif

	for(num_v6=0;num_v6 < get_client_memptr(wlan_client, clt_indx)->ipv6_set;num_v6++)
	{
		handle_neigh_cache_ops(NEIGH_CLIENT_DEL, get_client_memptr(wlan_client, clt_indx)->v6_addr[num_v6]);
	}
	/* Reset ip_set to 0*/
	get_client_memptr(wlan_client, clt_indx)->ipv4_set = false;
	get_client_memptr(wlan_client, clt_indx)->ipv6_set = 0;
	get_client_memptr(wlan_client, clt_indx)->ipv4_header_set = false;
	get_client_memptr(wlan_client, clt_indx)->ipv6_header_set = false;
	get_client_memptr(wlan_client, clt_indx)->route_rule_set_v4 = false;
	get_client_memptr(wlan_client, clt_indx)->route_rule_set_v6 = 0;
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

		memcpy(get_client_memptr(wlan_client, clt_indx)->mac,
					 get_client_memptr(wlan_client, (clt_indx + 1))->mac,
					 IPA_MAC_ADDR_SIZE);

		get_client_memptr(wlan_client, clt_indx)->hdr_hdl_v4 = get_client_memptr(wlan_client, (clt_indx + 1))->hdr_hdl_v4;
		get_client_memptr(wlan_client, clt_indx)->hdr_hdl_v6 = get_client_memptr(wlan_client, (clt_indx + 1))->hdr_hdl_v6;
		get_client_memptr(wlan_client, clt_indx)->v4_addr = get_client_memptr(wlan_client, (clt_indx + 1))->v4_addr;

		get_client_memptr(wlan_client, clt_indx)->ipv4_set = get_client_memptr(wlan_client, (clt_indx + 1))->ipv4_set;
		get_client_memptr(wlan_client, clt_indx)->ipv6_set = get_client_memptr(wlan_client, (clt_indx + 1))->ipv6_set;
		get_client_memptr(wlan_client, clt_indx)->ipv4_header_set = get_client_memptr(wlan_client, (clt_indx + 1))->ipv4_header_set;
		get_client_memptr(wlan_client, clt_indx)->ipv6_header_set = get_client_memptr(wlan_client, (clt_indx + 1))->ipv6_header_set;

		get_client_memptr(wlan_client, clt_indx)->route_rule_set_v4 = get_client_memptr(wlan_client, (clt_indx + 1))->route_rule_set_v4;
		get_client_memptr(wlan_client, clt_indx)->route_rule_set_v6 = get_client_memptr(wlan_client, (clt_indx + 1))->route_rule_set_v6;

                for(num_v6=0;num_v6< get_client_memptr(wlan_client, clt_indx)->ipv6_set;num_v6++)
	        {
		    get_client_memptr(wlan_client, clt_indx)->v6_addr[num_v6][0] = get_client_memptr(wlan_client, (clt_indx + 1))->v6_addr[num_v6][0];
		    get_client_memptr(wlan_client, clt_indx)->v6_addr[num_v6][1] = get_client_memptr(wlan_client, (clt_indx + 1))->v6_addr[num_v6][1];
		    get_client_memptr(wlan_client, clt_indx)->v6_addr[num_v6][2] = get_client_memptr(wlan_client, (clt_indx + 1))->v6_addr[num_v6][2];
		    get_client_memptr(wlan_client, clt_indx)->v6_addr[num_v6][3] = get_client_memptr(wlan_client, (clt_indx + 1))->v6_addr[num_v6][3];
                }

		for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		{
			get_client_memptr(wlan_client, clt_indx)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4 =
				 get_client_memptr(wlan_client, (clt_indx + 1))->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v4;

			for(num_v6=0;num_v6< get_client_memptr(wlan_client, clt_indx)->route_rule_set_v6;num_v6++)
			{
			  get_client_memptr(wlan_client, clt_indx)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v6[num_v6] =
			   	 get_client_memptr(wlan_client, (clt_indx + 1))->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v6[num_v6];
			  get_client_memptr(wlan_client, clt_indx)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v6_wan[num_v6] =
			   	 get_client_memptr(wlan_client, (clt_indx + 1))->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v6_wan[num_v6];
		    }
		}
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
	}

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
	IPACMDBG_H(" %d wifi client deleted successfully \n", num_wifi_client);
	num_wifi_client = num_wifi_client - 1;
	IPACM_Wlan::total_num_wifi_clients = IPACM_Wlan::total_num_wifi_clients - 1;
	IPACMDBG_H(" Number of wifi client: %d\n", num_wifi_client);

	return IPACM_SUCCESS;
}

/*handle wlan iface down event*/
int IPACM_Wlan::handle_down_evt()
{
	int res = IPACM_SUCCESS, i, num_private_subnet_fl_rule;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	struct wan_ioctl_lan_client_info *client_info;
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

	if(!IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
	{
		/* delete wan filter rule */
		if (IPACM_Wan::isWanUP(ipa_if_num) && rx_prop != NULL)
		{
			IPACMDBG_H("LAN IF goes down, backhaul type %d\n", IPACM_Wan::backhaul_is_sta_mode);
			IPACM_Lan::handle_wan_down(IPACM_Wan::backhaul_is_sta_mode);
		}

		if (IPACM_Wan::isWanUP_V6(ipa_if_num) && rx_prop != NULL)
		{
			IPACMDBG_H("LAN IF goes down, backhaul type %d\n", IPACM_Wan::backhaul_is_sta_mode);
			handle_wan_down_v6(IPACM_Wan::backhaul_is_sta_mode, false);
		}
	}
	IPACMDBG_H("finished deleting wan filtering rules\n ");

	/* Delete v4 filtering rules */
	if (ip_type != IPA_IP_v6 && rx_prop != NULL)
	{
		/* delete IPv4 icmp filter rules */
		if(m_filtering.DeleteFilteringHdls(ipv4_icmp_flt_rule_hdl[0], IPA_IP_v4, NUM_IPV4_ICMP_FLT_RULE) == false)
		{
			IPACMERR("Error Deleting ICMPv4 Filtering Rule, aborting...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v4, NUM_IPV4_ICMP_FLT_RULE);
		if (dft_v4fl_rule_hdl[0] != 0)
		{
			if (m_filtering.DeleteFilteringHdls(dft_v4fl_rule_hdl[0], IPA_IP_v4, IPV4_DEFAULT_FILTERTING_RULES) == false)
			{
				IPACMERR("Error Deleting Filtering Rule, aborting...\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v4, IPV4_DEFAULT_FILTERTING_RULES);
			IPACMDBG_H("Deleted default v4 filter rules successfully.\n");
		}
		/* delete private-ipv4 filter rules */
#if defined(FEATURE_IPA_ANDROID) || defined(FEATURE_VLAN_MPDN)
		if(m_filtering.DeleteFilteringHdls(private_fl_rule_hdl[0], IPA_IP_v4, num_wan_subnet_rules[0]) == false)
		{
			IPACMERR("Error deleting private subnet IPv4 flt rules.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v4, num_wan_subnet_rules[0]);
#else
		num_private_subnet_fl_rule = IPACM_Iface::ipacmcfg->ipa_num_private_subnet > (IPA_MAX_PRIVATE_SUBNET_ENTRIES + IPA_MAX_MTU_ENTRIES)?
			(IPA_MAX_PRIVATE_SUBNET_ENTRIES + IPA_MAX_MTU_ENTRIES): IPACM_Iface::ipacmcfg->ipa_num_private_subnet;
		if(m_filtering.DeleteFilteringHdls(private_fl_rule_hdl[0], IPA_IP_v4, num_private_subnet_fl_rule) == false)
		{
			IPACMERR("Error deleting private subnet flt rules, aborting...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v4, num_private_subnet_fl_rule);
#endif
		IPACMDBG_H("Deleted private subnet v4 filter rules successfully.\n");

		if(m_filtering.DeleteFilteringHdls(&tcp_syn_flt_rule_hdl[0][IPA_IP_v4], IPA_IP_v4, 1) == false)
		{
			IPACMERR("Error deleting tcp syn flt rule, aborting...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v4, 1);
		IPACMDBG_H("Deleted TCP syn v4 filter rules successfully.\n");
	}

	/* Delete v6 filtering rules */
	if (ip_type != IPA_IP_v4 && rx_prop != NULL)
	{
		/* delete icmp filter rules */
		if(m_filtering.DeleteFilteringHdls(ipv6_icmp_flt_rule_hdl[0], IPA_IP_v6, NUM_IPV6_ICMP_FLT_RULE) == false)
		{
			IPACMERR("Error Deleting ICMPv6 Filtering Rule, aborting...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, NUM_IPV6_ICMP_FLT_RULE);

		if (dft_v6fl_rule_hdl[0][0] != 0)
		{
			if (!m_filtering.DeleteFilteringHdls(dft_v6fl_rule_hdl[0], IPA_IP_v6, m_ipv6_default_filterting_rules_count[0]))
			{
				IPACMERR("Error Adding RuleTable(1) to Filtering, aborting...\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(
				rx_prop->rx[0].src_pipe, IPA_IP_v6, m_ipv6_default_filterting_rules_count[0]);
			IPACMDBG_H("Deleted default v6 filter rules successfully.\n");
		}

		if(m_filtering.DeleteFilteringHdls(&tcp_syn_flt_rule_hdl[0][IPA_IP_v6], IPA_IP_v6, 1) == false)
		{
			IPACMERR("Error deleting tcp syn flt rule, aborting...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);
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

	eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_DOWN, IPA_IP_MAX, NULL, NULL, NULL);

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

	/* remove modem UL rules and notify */
	if(is_any_mux_up(IPA_IP_v4))
	{
		ipacm_event_vlan_pdn *data_vlan = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));

		if (data_vlan == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		IPACMDBG_H("MUX is up for V4\n");
		for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
		{
			if(v4_mux_up[i].mux_id)
			{
				data_vlan->mux_id = v4_mux_up[i].mux_id;
				data_vlan->iptype = IPA_IP_v4;
				IPACMDBG_H("mux %d up, delete v4 flt rules\n", v4_mux_up[i].mux_id);
				handle_vlan_pdn_down(data_vlan);
			}
		}
		free(data_vlan);
	}
	if(is_any_mux_up(IPA_IP_v6))
	{
		ipacm_event_vlan_pdn *data_vlan = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));

		if (data_vlan == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		IPACMDBG_H("MUX is up for V6\n");
		for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
		{
			if(v6_mux_up[i].mux_id)
			{
				data_vlan->mux_id = v6_mux_up[i].mux_id;
				data_vlan->iptype = IPA_IP_v6;
				IPACMDBG_H("mux %d up, delete v6 flt rules\n", v6_mux_up[i].mux_id);
				handle_vlan_pdn_down(data_vlan);
			}
		}
		free(data_vlan);
	}

	/* Remove STA case UL rules */
	for(int i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
	{
		if((vlan_sta_info[i].vlan_id != 0) && (vlan_sta_info[i].v4_flt_hdl != 0))
		{
			IPACMDBG_H("Deleting v4 filter rule for vlan_id %d during iface down\n",vlan_sta_info[i].vlan_id);
			ipacm_event_vlan_pdn *data_vlan = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));

			if (data_vlan == NULL)
			{
				IPACMERR("Unable to allocate memory\n");
				res = IPACM_FAILURE;
				goto fail;
			}

			data_vlan->mux_id = 0;
			data_vlan->iptype = IPA_IP_v4;
			IPACMDBG_H("mux %d up, delete v6 flt rules\n", v6_mux_up[i].mux_id);
			handle_vlan_pdn_down(data_vlan);
			free(data_vlan);
		}
		if((vlan_sta_info[i].vlan_id != 0) && (vlan_sta_info[i].v6_flt_hdl != 0))
		{
			IPACMDBG_H("Deleting v6 filter rule for vlan_id %d during iface down\n",vlan_sta_info[i].vlan_id);
			ipacm_event_vlan_pdn *data_vlan = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));

			if (data_vlan == NULL)
			{
				IPACMERR("Unable to allocate memory\n");
				res = IPACM_FAILURE;
				goto fail;
			}

			data_vlan->mux_id = 0;
			data_vlan->iptype = IPA_IP_v6;
			IPACMDBG_H("mux %d up, delete v6 flt rules\n", v6_mux_up[i].mux_id);
			handle_vlan_pdn_down(data_vlan);
			free(data_vlan);
		}
	}

fail:
	/* clean wifi-client header, routing rules */
	/* clean wifi client rule*/
	IPACMDBG_H("left %d wifi clients need to be deleted \n ", num_wifi_client);
	for (i = 0; i < num_wifi_client; i++)
	{
		/* First reset NAT/IPv6CT rules and then route rules */
		HandleNeighIpAddrDelEvt(
			get_client_memptr(wlan_client, i)->ipv4_set,
			get_client_memptr(wlan_client, i)->v4_addr,
			get_client_memptr(wlan_client, i)->ipv6_set,
			get_client_memptr(wlan_client, i)->v6_addr);

		if (delete_default_qos_rtrules(i, IPA_IP_v4))
		{
			IPACMERR("unbale to delete v4 default qos route rules for index: %d\n", i);
			res = IPACM_FAILURE;
		}

		if (delete_default_qos_rtrules(i, IPA_IP_v6))
		{
			IPACMERR("unbale to delete v6 default qos route rules for index: %d\n", i);
			res = IPACM_FAILURE;
		}

		IPACMDBG_H("Delete %d client header\n", num_wifi_client);

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

		/* Reset ip-address */
		if(iptype == IPA_IP_v4)
		{
			get_client_memptr(wlan_client, i)->ipv4_set = false;
		}
		else
		{
			get_client_memptr(wlan_client, i)->ipv6_set = 0;
		}
	} /* end of for loop */
	return res;
}

void IPACM_Wlan::handle_SCC_MCC_switch(ipa_ip_type iptype)
{
	struct ipa_ioc_mdfy_rt_rule *rt_rule = NULL;
	struct ipa_rt_rule_mdfy *rt_rule_entry;
	uint32_t tx_index;
	int wlan_index, v6_num;
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
				if (iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d ip-type not matching: %d Ignore\n",
							tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}

				for (v6_num = get_client_memptr(wlan_client, wlan_index)->route_rule_set_v6;
						v6_num < get_client_memptr(wlan_client, wlan_index)->ipv6_set;
						v6_num++)
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

					rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][0];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][1];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][2];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = get_client_memptr(wlan_client, wlan_index)->v6_addr[v6_num][3];
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;

					rt_rule_entry->rt_rule_hdl =
						get_client_memptr(wlan_client, wlan_index)->wifi_rt_hdl[tx_index].wifi_rt_rule_hdl_v6_wan[v6_num];

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
	eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_DOWN, IPA_IP_MAX, NULL, NULL, NULL);

	/* then post IFACE_UP event */
	if(ip_type == IPA_IP_v4 || ip_type == IPA_IP_MAX)
	{
		eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_UP, IPA_IP_v4, NULL, NULL, NULL);
	}
	if(ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX)
	{
		eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_UP, IPA_IP_v6, NULL, NULL, NULL);
	}

	/* at last post CLIENT_ADD event */
	for(i = 0; i < num_wifi_client; i++)
	{
		eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_ADD, IPA_IP_MAX,
			get_client_memptr(wlan_client, i)->mac, NULL, NULL);
	}

	return;
}

bool IPACM_Wlan::is_guest_ap()
{
	return m_is_guest_ap;
}

#ifdef FEATURE_VLAN_MPDN
int IPACM_Wlan::handle_wlan_vlan_neighbor(ipacm_event_data_all *data)
{
	ipacm_event_new_neigh_vlan *data_vlan;
	bool new_prefix = false;
	ipacm_event_data_all data_all;
	std::list <ipacm_event_data_all>::iterator it;
	uint16_t vlan_id = 0;
	uint8_t priority = 0;

	IPACMDBG_H("\n");
	memset(&data_all, 0, sizeof(ipacm_event_data_all));
#ifdef IPA_VLAN_PRIORITY
	if (IPACM_Iface::ipacmcfg->get_vlan_id(data->iface_name, &vlan_id, &priority))
#else
	if (IPACM_Iface::ipacmcfg->get_vlan_id(data->iface_name, &vlan_id))
#endif
	{
		if(!IPACM_Iface::ipacmcfg->is_added_vlan_iface(data->iface_name))
		{
			IPACMDBG_H("ignoring neighbor of not added IF %s \n", data->iface_name);
			return 0;
		}
		IPACMERR("failed getting vlan ID of iface %s \n", data->iface_name);
		return IPACM_FAILURE;
	}
#ifdef IPA_VLAN_PRIORITY
	IPACMDBG_H("VLAN IF %s got client, vlan id %d priority %d\n", data->iface_name, vlan_id, priority);
#else
	IPACMDBG_H("VLAN IF %s got client, vlan id %d \n", data->iface_name, vlan_id);
#endif
	data_vlan = (ipacm_event_new_neigh_vlan *)data;

	if(data_vlan->bridge == NULL && data_vlan->data_all.iptype == IPA_IP_v4)
	{
		IPACMERR("Got v4 Neighbor with no bridge return\n");
		return IPACM_FAILURE;
	}
	if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable) {
		if(data_vlan->data_all.iptype == IPA_IP_v6)
		{
			if(IPACM_Wan::is_global_ipv6_addr(data_vlan->data_all.ipv6_addr))
			{
				if (!IPACM_Wan::isWan_active_with_prefix(data_vlan->data_all.ipv6_addr))
				{
					if(handle_neigh_cache_ops(NEIGH_CLIENT_ADD, data) != IPACM_SUCCESS)
					{
						IPACMDBG_H("Failed to add data in neigh cache\n");
					}
					return IPACM_FAILURE;
				}

				/* add ipv6 prefix */
				new_prefix = IPACM_Iface::ipacmcfg->add_vlan_ipv6_prefix(data_vlan->data_all.ipv6_addr, ipa_if_num, vlan_id);
			}
		}
		else if(data_vlan->data_all.iptype == IPA_IP_v4)
		{
			add_vlan_private_subnet(data_vlan->bridge);
		}
	}

	/* Associate with IP and construct RT-rule */
	if(handle_wlan_client_ipaddr(data) == IPACM_FAILURE)
	{
		IPACMERR("Failed handle_wlan_client_ipaddr, continue\n");
		return IPACM_FAILURE;
	}

	handle_wlan_client_route_rule(data->mac_addr, data->iptype);

	if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
	{
		/* Add NAT rules after ipv4 RT rules are set */
		HandleNeighIpAddrAddEvt(data);

		/*
		* if this is the first time we have this global ipv6 prefix (or this
		* is the default pdn prefix) we can notify WAN that it is a v6 vlan pdn
		*/
		if(new_prefix ||
			((IPACM_Wan::backhaul_ipv6_prefix[0] || IPACM_Wan::backhaul_ipv6_prefix[1]) &&
				(IPACM_Wan::backhaul_ipv6_prefix[0] == data_vlan->data_all.ipv6_addr[0]) &&
				(IPACM_Wan::backhaul_ipv6_prefix[1] == data_vlan->data_all.ipv6_addr[1])))
		{
			ipacm_cmd_q_data evt_data;
			ipacm_event_route_vlan *data;

			check_vlan_PDNUp(IPA_IP_v6);

			IPACMDBG_H("generating IPA_ROUTE_ADD_VLAN_PDN_EVENT, new_prefix %d\n", new_prefix);
			IPACMDBG_H("prefixes 0x[%X][%X], 0x[%X][%X]\n",
				IPACM_Wan::backhaul_ipv6_prefix[0],
				IPACM_Wan::backhaul_ipv6_prefix[1],
				data_vlan->data_all.ipv6_addr[0],
				data_vlan->data_all.ipv6_addr[1]);

			evt_data.event = IPA_ROUTE_ADD_VLAN_PDN_EVENT;
			data = (ipacm_event_route_vlan *)malloc(sizeof(ipacm_event_route_vlan));
			if(!data)
			{
				IPACMERR("couldn't allocate memory for new vlan pdn event\n");
				return IPACM_FAILURE;
			}
			memset(data, 0, sizeof(ipacm_event_route_vlan));

			uint32_t ip4_addr;
			if(get_wlan_client_ip4_addr(data_vlan->data_all.mac_addr, ip4_addr, vlan_id) == IPACM_SUCCESS) {
				IPACMDBG_H("ipv4 address 0x%X is valid, generate IPA_ROUTE_ADD_VLAN_PDN_EVENT v4 as well\n", ip4_addr);
				data->iptype = IPA_IP_MAX;
				data->wan_ipv4_addr = IPA_DUMMY_PREFIX;
			}
			else {
				data->iptype = IPA_IP_v6;
				IPACMDBG_H("ipv4 address is not valid, don't generate IPA_ROUTE_ADD_VLAN_PDN_EVENT v4\n");
			}
			data->VlanID = vlan_id;
			data->wan_ipv6_prefix[0] = data_vlan->data_all.ipv6_addr[0];
			data->wan_ipv6_prefix[1] = data_vlan->data_all.ipv6_addr[1];
			evt_data.evt_data = data;
			IPACM_EvtDispatcher::PostEvt(&evt_data);
		}

	}

	return IPACM_SUCCESS;
}
#endif

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
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
	int ret = 0, len = 0, index = 0;
	struct ipa_fltr_installed_notif_req_msg_v01 flt_index;
	int q6_v6_ul_rules = 0, replicate_rules = 0;
	int v6_ul_wl_rules = 0, total_rules = 0;
	struct ipa_ioc_add_flt_rule *pFilteringTable = NULL;
	struct ipa_flt_rule_add flt_rule_entry, flt_rule_entry_r, flt_rule_entry_fw, temp_rule;
	struct ipa_ioc_generate_flt_eq flt_eq;
	uint8_t xlat_mux_id;
	struct ipa_ioc_add_flt_rule_v2 *pFilteringTable_v2 = NULL;
	struct ipa_flt_rule_add_v2 flt_rule_entry_v2;

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
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
	pFilteringTable->ep = rx_prop->rx[0].src_pipe;
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

	index = IPACM_Iface::ipacmcfg->getFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6);

	/* Traverse all q6_v6_ul_rules */
	for (i = 0; i < q6_v6_ul_rules; i++)
	{
		memcpy(&flt_rule_entry.rule.eq_attrib,
				&ext_prop->prop[i].eq_attrib,
				sizeof(ext_prop->prop[i].eq_attrib));
		flt_rule_entry.rule.rt_tbl_idx = ext_prop->prop[i].rt_tbl_idx;
		flt_rule_entry.rule.hashable = ext_prop->prop[i].is_rule_hashable;
		flt_rule_entry.rule.rule_id = ext_prop->prop[i].rule_id;

		if(rx_prop->rx[0].attrib.attrib_mask & IPA_FLT_META_DATA) //turn on meta-data equation
		{
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<9);
			flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.value |= rx_prop->rx[0].attrib.meta_data;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.mask |= rx_prop->rx[0].attrib.meta_data_mask;
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
					// if sw-allowed then do not replicate rules here
					if(firewall_conf->extd_firewall_entries[i].SWAllowed_ex)
						continue;

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

					flt_rule_entry_fw.rule.attrib.attrib_mask |= rx_prop->rx[0].attrib.attrib_mask;
					flt_rule_entry_fw.rule.attrib.attrib_mask &= ~IPA_FLT_META_DATA;
					flt_rule_entry_fw.rule.attrib.meta_data_mask = rx_prop->rx[0].attrib.meta_data_mask;
					flt_rule_entry_fw.rule.attrib.meta_data = rx_prop->rx[0].attrib.meta_data;

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
	pFilteringTable_v2->ep = rx_prop->rx[0].src_pipe;
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

	if(false == m_filtering.addRules(pFilteringTable_v2))
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
			IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);
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
	int default_vid = 0, ret;

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

	/* now read XML and rebuild FW for all PDNs */
	if(IPACM_Wan::read_firewall_filter_rules_ul())
	{
		IPACMERR("failed configuring UL firewall\n");
		return;
	}

	/*Drop rules: First of all clear LAN pipe frag, catch all and FW rules if installed */
	delete_uplink_filter_rule_ul(&iface_ul_firewall);

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

		if(firewall_config->SWAllowed)
		{
			config_sw_allow_excep_flt_rules_ul(firewall_config, &iface_ul_firewall, default_vid);
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
	uint8_t *mac_addr
)
{
	struct ipa_flt_rule_add_v2 flt_rule_entry{}, *rulesPtr = nullptr;
	int len = 0, cnt, ret = IPACM_SUCCESS;
	struct ipa_ioc_add_flt_rule_v2 pFilteringTable{};
	int fd;
	int i, index = 0;
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

	if (get_client_memptr(wlan_client, clnt_indx)->lan_stats_idx == -1)
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

	rulesPtr = reinterpret_cast<decltype(rulesPtr)>(malloc(sizeof(flt_rule_entry) * total_rules));
	if (!rulesPtr) {
		IPACMERR("malloc failed: %zu\n", sizeof(flt_rule_entry) * total_rules);
		close(fd);
		return IPACM_FAILURE;
	}
	memset(rulesPtr, 0, sizeof(flt_rule_entry) * total_rules);
	pFilteringTable.rules = reinterpret_cast<decltype(pFilteringTable.rules)>(rulesPtr);
	pFilteringTable.commit = 1;
	pFilteringTable.ep = rx_prop->rx[0].src_pipe;
	pFilteringTable.global = false;
	pFilteringTable.ip = iptype;
	pFilteringTable.num_rules = total_rules;
	pFilteringTable.flt_rule_size = sizeof(flt_rule_entry);
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
		if (ipa_if_cate == ODU_IF && IPACM_Wan::isWan_Bridge_Mode())
		{
			IPACMDBG_H("WAN, ODU are in bridge mode \n");
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
	UapiHelper::ruleTtlUpdateSet(flt_rule_entry.rule);
	IPACMDBG_H("ttl_update = %u\n", flt_rule_entry.rule.ttl_update);

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
		if(rx_prop->rx[0].hdr_l2_type == IPA_HDR_L2_ETHERNET_II)
		{
			offset_meq_128->offset = -8;
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
			/* fill the value of meta-data */
			value = xlat_mux_id;
			flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.value = (value & 0xFF) << 16;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.mask = 0x00FF0000;
			IPACMDBG_H("xlat meta-data is modified for rule: %d has rule_id %d with xlat_mux_id: %d\n",
					index, prop->prop[cnt].rule_id, xlat_mux_id);
		}
		IPACMDBG_H("rule: %d has rule_id %d\n",
				index, prop->prop[cnt].rule_id);
		flt_rule_entry.rule.hashable = prop->prop[cnt].is_rule_hashable;
		flt_rule_entry.rule.rule_id = (prop->prop[cnt].rule_id & 0x1F) |
			(get_client_memptr(wlan_client, clnt_indx)->lan_stats_idx << 5) | 0x200;
		IPACMDBG_H("Modified rule: %d has rule_id %d\n",
				cnt, flt_rule_entry.rule.rule_id);
		if(rx_prop->rx[0].attrib.attrib_mask & IPA_FLT_META_DATA)	//turn on meta-data equation
		{
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<9);
			flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.value |= rx_prop->rx[0].attrib.meta_data;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.mask |= rx_prop->rx[0].attrib.meta_data_mask;
		}
		rulesPtr[index] = flt_rule_entry;

		IPACMDBG_H("Modem UL filtering rule %d has rule_id %d\n", index, prop->prop[cnt].rule_id);
		index++;

		//for IPv6CT enabled and XLAT, add a duplicate rule above that will let XLAT packets go to routing instead of NAT
		if (iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->IsIpv6CTEnabled() &&
			prop->prop[cnt].action != IPA_PASS_TO_EXCEPTION)
		{
			//duplicate the old rule to new index
			rulesPtr[index] = flt_rule_entry;

			//change old rule to pass to route and non hashable
			flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
			flt_rule_entry.rule.hashable = false;

			//add the eth header equation for v4 to the old rule
			int meq32_n = flt_rule_entry.rule.eq_attrib.num_offset_meq_32;

			if (meq32_n + 1 > IPA_IPFLTR_NUM_MEQ_32_EQNS)
			{
				IPACMERR("Can't add another meq_32 equation to this rule");
				rulesPtr[index] = flt_rule_entry;
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
			rulesPtr[index - 1] = flt_rule_entry;
			index++;
			flt_rule_entry.rule.action = action_cache;
		}
	}

	if (!m_filtering.addRules(&pFilteringTable))
	{
		IPACMERR("Error Adding RuleTable to Filtering, aborting...\n");
		ret = IPACM_FAILURE;
		goto fail;
	}
	else
	{
		if(iptype == IPA_IP_v4)
		{
			for(i = 0; i < pFilteringTable.num_rules; i++)
			{
				get_client_memptr(wlan_client, clnt_indx)->wan_ul_fl_rule_hdl_v4[i] = rulesPtr[i].flt_rule_hdl;
			}
			get_client_memptr(wlan_client, clnt_indx)->ipv4_ul_rules_set = true;
		}
		else if(iptype == IPA_IP_v6)
		{
			for(i=0; i < pFilteringTable.num_rules; i++)
			{
				get_client_memptr(wlan_client, clnt_indx)->wan_ul_fl_rule_hdl_v6[i] = rulesPtr[i].flt_rule_hdl;
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
	free(rulesPtr);
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
	bool isFirewall
)
{
	struct ipa_flt_rule_add_v2 flt_rule_entry;
	int len = 0, cnt, ret = IPACM_SUCCESS;
	struct ipa_ioc_add_flt_rule_v2 *pFilteringTable;
	int fd;
	int i, index = 0;
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

	if (get_client_memptr(wlan_client, clnt_indx)->lan_stats_idx == -1)
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
	pFilteringTable->ep = rx_prop->rx[0].src_pipe;
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
	flt_rule_entry.rule.cnt_idx = ul_cnt_idx;
	UapiHelper::ruleTtlUpdateSet(flt_rule_entry.rule);
	IPACMDBG_H("ttl_update = %u\n", flt_rule_entry.rule.ttl_update);
	if(iptype == IPA_IP_v4)
	{
		if (ipa_if_cate == ODU_IF && IPACM_Wan::isWan_Bridge_Mode())
		{
			IPACMDBG_H("WAN, ODU are in bridge mode \n");
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
				cnt, flt_rule_entry.rule.rule_id);

		/* Check if we can add the MAC address rule. */
		if (flt_rule_entry.rule.eq_attrib.num_offset_meq_128 == IPA_IPFLTR_NUM_MEQ_128_EQNS)
		{
			IPACMERR("128 bit equations not available.\n");
			ret = IPACM_FAILURE;
			goto fail;
		}
		num_offset_meq_128 = flt_rule_entry.rule.eq_attrib.num_offset_meq_128;
		offset_meq_128 = &flt_rule_entry.rule.eq_attrib.offset_meq_128[num_offset_meq_128];
		if(rx_prop->rx[0].hdr_l2_type == IPA_HDR_L2_ETHERNET_II)
		{
			offset_meq_128->offset = -8;
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
			/* fill the value of meta-data */
			value = xlat_mux_id;
			flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.value = (value & 0xFF) << 16;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.mask = 0x00FF0000;
			IPACMDBG_H("xlat meta-data is modified for rule: %d has rule_id %d with xlat_mux_id: %d\n",
					index, prop->prop[cnt].rule_id, xlat_mux_id);
		}

		if(rx_prop->rx[0].attrib.attrib_mask & IPA_FLT_META_DATA)	//turn on meta-data equation
		{
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<9);
			flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.value |= rx_prop->rx[0].attrib.meta_data;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.mask |= rx_prop->rx[0].attrib.meta_data_mask;
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

	if(false == m_filtering.addRules(pFilteringTable))
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
						get_client_memptr(wlan_client, i)->ul_cnt_idx);
					IPACMDBG_H("fnr : IPA_IP_v4 xlat_mux_id: %d, modem_ul_v4_set %d, ul cnt idx = %d\n", xlat_mux_id,
						get_client_memptr(wlan_client, i)->ipv4_ul_rules_set, get_client_memptr(wlan_client, i)->ul_cnt_idx);
				}
				else
#endif //IPA_HW_FNR_STATS
				{
					IPACMDBG_H("IPA_IP_v4 xlat_mux_id: %d, modem_ul_v4_set %d\n", xlat_mux_id, modem_ul_v4_set[0]);
					ret = install_uplink_filter_rule_per_client(prop, iptype, xlat_mux_id, get_client_memptr(wlan_client, i)->mac);
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
							get_client_memptr(wlan_client, i)->ul_cnt_idx);
					IPACMDBG_H("IPA_IP_v6 num_dft_rt_v6 %d xlat_mux_id: %d modem_ul_v6_set: %d, ul_cnt_idx = %d\n", num_dft_rt_v6, xlat_mux_id,
						get_client_memptr(wlan_client, i)->ipv6_ul_rules_set, get_client_memptr(wlan_client, i)->ul_cnt_idx);
				}
				else
#endif //IPA_HW_FNR_STATS
				{
					IPACMDBG_H("IPA_IP_v6 num_dft_rt_v6 %d xlat_mux_id: %d modem_ul_v6_set: %d\n", num_dft_rt_v6, xlat_mux_id, modem_ul_v6_set[0]);
					ret = install_uplink_filter_rule_per_client(prop, iptype, xlat_mux_id, get_client_memptr(wlan_client, i)->mac);
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
	ipa_fltr_installed_notif_req_msg_v01 flt_index;
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

	if (get_client_memptr(wlan_client, clnt_indx)->lan_stats_idx == -1)
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
