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
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
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
	IPACM_Lan.cpp

	@brief
	This file implements the LAN iface functionality.

	@Author
	Skylar Chang

*/
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "IPACM_Netlink.h"
#include "IPACM_Lan.h"
#include "IPACM_Wan.h"
#include "IPACM_Wlan.h"
#include "IPACM_IfaceManager.h"
#include "linux/rmnet_ipa_fd_ioctl.h"
#include "linux/ipa_qmi_service_v01.h"
#include "linux/msm_ipa.h"
#include "IPACM_ConntrackListener.h"
#include <sys/ioctl.h>
#include <fcntl.h>
#include <memory>
#include <cstdio>
#include <iostream>
#include <vector>
#include <cctype>


using std::string;
using std::vector;


bool IPACM_Lan::odu_up = false;
uint32_t IPACM_Lan::static_policy_rt_rule_hdl = 0;
uint32_t IPACM_Lan::static_policy_proc_ctx_hdl = 0;
uint32_t IPACM_Lan::total_vlan_pdn_cnt = 0;
#ifdef FEATURE_STATIC_POLICY
uint32_t IPACM_Lan::total_vlan_pdn_cnt_v6 = 0;
#endif

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
bool IPACM_Lan::lan_stats_inited = false;
ipa_lan_client_idx IPACM_Lan::active_lan_client_index_odu[IPA_MAX_NUM_HW_PATH_CLIENTS];
ipa_lan_client_idx IPACM_Lan::inactive_lan_client_index_odu[IPA_MAX_NUM_HW_PATH_CLIENTS];
#endif

/* for default single pdn use-case: 1 prefix+1 mtu*/
#define IPv6_PREFIX_DEFAULT_PDN_RULE_NUM 2

#define MAX_IPNS_ROW_LEN 200
#define IPA_SYS_CMD_LEN 200
#define IPA_TMP_DIR "/tmp/data_ipa"
#define MAX_IPNS_ROW_LEN 200
#define MAX_IPNS_PARAM_CNT 5
#define MAX_IPNS_PARAM_LEN 50

#define IPA_NS_TABLE IPA_TMP_DIR"/ipa_ns_table.txt"

IPACM_Lan::IPACM_Lan(int iface_index) : IPACM_Iface(iface_index)
{
	sIface = false;
	num_eth_client = 0;
	header_name_count = 0;
	ipv6_set = 0;
	ipv4_header_set = false;
	ipv6_header_set = false;
	odu_route_rule_v4_hdl = NULL;
	odu_route_rule_v6_hdl = NULL;
	eth_client = NULL;
	int i, m_fd_odu, ret = IPACM_SUCCESS;
	eth_client_len = 0;
	is_l2tp_iface = false;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	int max_clients = (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable) ? IPA_MAX_NUM_HW_PATH_CLIENTS:
		IPA_MAX_NUM_ETH_CLIENTS;
	is_odu = false;
#else
	int max_clients = IPA_MAX_NUM_ETH_CLIENTS;
#endif
#ifdef FEATURE_VLAN_MPDN
	if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
		max_clients = IPA_MAX_NUM_VLAN_CLIENTS;
#endif
	Nat_App = NatApp::GetInstance();
	if (Nat_App == NULL)
	{
		IPACMERR("unable to get Nat App instance \n");
		return;
	}

	memset(num_wan_ul_fl_rule_v4, 0, sizeof(num_wan_ul_fl_rule_v4));
	memset(num_wan_ul_fl_rule_v6, 0, sizeof(num_wan_ul_fl_rule_v6));
	memset(num_wan_subnet_rules, 0, sizeof(num_wan_subnet_rules));
	memset(num_wan_prefix_rules, 0, sizeof(num_wan_prefix_rules));
	hdr_len = 0;
	memset(wan_ul_fl_rule_hdl_v4, 0, sizeof(wan_ul_fl_rule_hdl_v4));
	memset(wan_ul_fl_rule_hdl_v6, 0, sizeof(wan_ul_fl_rule_hdl_v6));

#ifdef FEATURE_IPACM_UL_FIREWALL
	IPACMDBG_H("Mem-setting iface_ul_firewall of size %zu\n", sizeof(iface_ul_firewall));
	memset(&iface_ul_firewall, 0, sizeof(iface_ul_firewall));
#endif

	is_active = true;
	memset(ipv4_icmp_flt_rule_hdl, 0, sizeof(ipv4_icmp_flt_rule_hdl));

	is_mode_switch = false;
	if_ipv4_subnet =0;
	memset(private_fl_rule_hdl, 0, sizeof(private_fl_rule_hdl));
	memset(ipv6_prefix_flt_rule_hdl, 0, sizeof(ipv6_prefix_flt_rule_hdl));
	memset(ipv6_icmp_flt_rule_hdl, 0, sizeof(ipv6_icmp_flt_rule_hdl));
	memset(modem_ul_v4_set, 0, sizeof(modem_ul_v4_set));
	memset(modem_ul_v6_set, 0, sizeof(modem_ul_v6_set));
	memset(ipv6_prefix, 0, sizeof(ipv6_prefix));
	memset(&xlat_ctx, 0, sizeof(xlat_context));

#ifdef FEATURE_VLAN_MPDN
	is_vlan_offload_disabled = false;
	memset(v4_mux_up, 0, sizeof(v4_mux_up[0]) * IPA_MAX_NUM_HW_PDNS);
	memset(v6_mux_up, 0, sizeof(v6_mux_up[0]) * IPA_MAX_NUM_HW_PDNS);
#endif

#ifdef FEATURE_L2TP
#ifdef IPA_L2TP_TUNNEL_UDP
	l2tp_udp_dflt_flt_tule_offset = 0;
	memset(tcp_syn_flt_rule_hdl, 0, sizeof(tcp_syn_flt_rule_hdl));
	memset(l2tp_udp_dflt_flt_rule_hdl, 0, sizeof(l2tp_udp_dflt_flt_rule_hdl));
#endif
#endif

#ifdef FEATURE_SOCKSv5
        socksv5_flt_hdl_v6 = 0;
#endif

#ifdef IPA_IOCTL_SET_EXT_ROUTER_MODE
        /* support one router case. Need to extend for multi router*/
	ext_router_rmnet_ipv6_hdl = 0;
	ext_router_flt_rule_hdl = 0;
	memset(ext_router_pdn_name, 0, sizeof(ext_router_pdn_name));
#endif

	/* support eth multiple clients */
	if(iface_query != NULL)
	{
		if(ipa_if_cate != WLAN_IF)
		{
			eth_client_len = (sizeof(ipa_eth_client)) + (iface_query->num_tx_props * sizeof(eth_client_rt_hdl));
			eth_client = (ipa_eth_client *)calloc(max_clients, eth_client_len);
			if (eth_client == NULL)
			{
				IPACMERR("unable to allocate memory\n");
				return;
			}
		}

		IPACMDBG_H(" IPACM->IPACM_Lan(%d) constructor: Tx:%d Rx:%d \n", ipa_if_num,
					 iface_query->num_tx_props, iface_query->num_rx_props);

		/* ODU routing table initilization */
		if(ipa_if_cate == ODU_IF)
		{
			odu_route_rule_v4_hdl = (uint32_t *)calloc(iface_query->num_tx_props, sizeof(uint32_t));
			odu_route_rule_v6_hdl = (uint32_t *)calloc(iface_query->num_tx_props, sizeof(uint32_t));
			if ((odu_route_rule_v4_hdl == NULL) || (odu_route_rule_v6_hdl == NULL))
			{
				IPACMERR("unable to allocate memory\n");
				if(odu_route_rule_v4_hdl != NULL)
				{
					free(odu_route_rule_v4_hdl);
				}
				else if(odu_route_rule_v6_hdl != NULL)
				{
					free(odu_route_rule_v6_hdl);
				}
				return;
			}
		}
	}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	if (rx_prop)
	{
		if (rx_prop->rx[0].src_pipe == IPA_CLIENT_ODU_PROD)
			is_odu = true;
		else
			is_odu = false;
	}

	/* Update the device type. */
	if (ipa_if_cate == LAN_IF)
	{
		device_type = IPACM_CLIENT_DEVICE_TYPE_USB;
	}
	else if (ipa_if_cate == ODU_IF && is_odu)
	{
		device_type = IPACM_CLIENT_DEVICE_TYPE_ODU;
	}
	else if (ipa_if_cate == ODU_IF || ipa_if_cate == ETH_IF)
	{
#ifdef DUAL_NIC_OFFLOAD
		if (strstr(dev_name, STR_ETH1_IFACE))
		{
			device_type = IPACM_CLIENT_DEVICE_TYPE_ETH1;
		}
		else
#endif
			device_type = IPACM_CLIENT_DEVICE_TYPE_ETH;
	}
	else
		IPACMERR ("Invalid iface category %d\n", ipa_if_cate);


	IPACMDBG_H ("Device type %d\n", device_type);

	for (i = 0; i < IPA_MAX_NUM_HW_PATH_CLIENTS; i++)
	{
		active_lan_client_index[i].lan_stats_idx = -1;
		memset(active_lan_client_index[i].mac, 0, IPA_MAC_ADDR_SIZE);
		inactive_lan_client_index[i].lan_stats_idx = -1;
		memset(inactive_lan_client_index[i].mac, 0, IPA_MAC_ADDR_SIZE);
	}
	if (lan_stats_inited == false)
	{
		for (i = 0; i < IPA_MAX_NUM_HW_PATH_CLIENTS; i++)
		{
			active_lan_client_index_odu[i].lan_stats_idx = -1;
			memset(active_lan_client_index_odu[i].mac, 0, IPA_MAC_ADDR_SIZE);
			inactive_lan_client_index_odu[i].lan_stats_idx = -1;
			memset(inactive_lan_client_index_odu[i].mac, 0, IPA_MAC_ADDR_SIZE);
		}
		lan_stats_inited = true;
	}

#endif
	/* ODU routing table initilization */
	if(ipa_if_cate == ODU_IF)
	{
		/* only do one time ioctl to odu-driver to infrom in router or bridge mode*/
		if (IPACM_Lan::odu_up != true)
		{
				m_fd_odu = open(IPACM_Iface::ipacmcfg->DEVICE_NAME_ODU, O_RDWR);
				if (0 == m_fd_odu)
				{
					IPACMERR("Failed opening %s.\n", IPACM_Iface::ipacmcfg->DEVICE_NAME_ODU);
					return ;
				}

				if(IPACM_Iface::ipacmcfg->ipacm_odu_router_mode == true)
				{
					ret = ioctl(m_fd_odu, ODU_BRIDGE_IOC_SET_MODE, ODU_BRIDGE_MODE_ROUTER);
					IPACM_Iface::ipacmcfg->ipacm_odu_enable = true;
				}
				else
				{
					ret = ioctl(m_fd_odu, ODU_BRIDGE_IOC_SET_MODE, ODU_BRIDGE_MODE_BRIDGE);
					IPACM_Iface::ipacmcfg->ipacm_odu_enable = true;
				}

				if (ret)
				{
					IPACMERR("Failed tell odu-driver the mode\n");
				}
				IPACMDBG("Tell odu-driver in router-mode(%d)\n", IPACM_Iface::ipacmcfg->ipacm_odu_router_mode);
				IPACMDBG_H("odu is up: odu-driver in router-mode(%d) \n", IPACM_Iface::ipacmcfg->ipacm_odu_router_mode);
				close(m_fd_odu);
				IPACM_Lan::odu_up = true;
		}
	}

	each_client_rt_rule_count[IPA_IP_v4] = 0;
	each_client_rt_rule_count[IPA_IP_v6] = 0;
	if(iface_query != NULL && tx_prop != NULL)
	{
		for(i=0; i<iface_query->num_tx_props; i++)
			each_client_rt_rule_count[tx_prop->tx[i].ip]++;
	}
	IPACMDBG_H("Need to add %d IPv4 and %d IPv6 routing rules for eth bridge for each client.\n", each_client_rt_rule_count[IPA_IP_v4], each_client_rt_rule_count[IPA_IP_v6]);

#ifdef FEATURE_IPA_ANDROID
	/* set the IPA-client pipe enum */
	if(ipa_if_cate == LAN_IF)
	{
		handle_tethering_client(false, IPACM_CLIENT_USB);
	}
#endif

#ifdef FEATURE_L2TP
	if(ipa_if_cate == ODU_IF && IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E)
	{
		install_l2tp_ul_hdr_proc_ctx();
	}
#endif

#ifdef FEATURE_EoGRE
	eogre_route_data_init(IPA_IP_v4);
	eogre_route_data_init(IPA_IP_v6);
#endif

	if (IPACM_Iface::ipacmcfg->ipacm_emesh_enable && IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 2)
	{
		if (device_type == IPACM_CLIENT_DEVICE_TYPE_ETH && rx_prop && rx_prop->num_rx_props > 2)
		{
			sIface = true;
			IPACM_Iface::ipacmcfg->SetSpclIface(dev_name);
			IPACMDBG("Ezmesh is enabled for dev name %s, Iface cat %d device type IPACM_CLIENT_DEVICE_TYPE_ETH %d\n", dev_name, ipa_if_cate, device_type);
			IPACMDBG("Device rx_prop->num_rx_props %d\n", rx_prop->num_rx_props);
		}
		else
			sIface = false;
	}
	IPACMDBG_H("Is %s an sIface: %d\n", dev_name, sIface);

	return;
}

IPACM_Lan::~IPACM_Lan()
{
	/* free the client details*/
	if(eth_client != NULL)
	{
		free(eth_client);
	}
	if(odu_route_rule_v4_hdl != NULL)
	{
		free(odu_route_rule_v4_hdl);
	}
	if(odu_route_rule_v6_hdl != NULL)
	{
		free(odu_route_rule_v6_hdl);
	}

#ifdef FEATURE_EoGRE
	eogre_clear_route_data(IPA_IP_v4);
	eogre_clear_route_data(IPA_IP_v6);
#endif

	IPACM_EvtDispatcher::deregistr(this);
	IPACM_IfaceManager::deregistr(this);

	return;
}

/* LAN-iface's callback function */
void IPACM_Lan::event_callback(ipa_cm_event_id event, void *param)
{
	if(is_active == false && event != IPA_LAN_DELETE_SELF)
	{
		IPACMDBG_H("The interface is no longer active, return.\n");
		return;
	}

	int ipa_interface_index;
	int if_index;
	ipacm_ext_prop* ext_prop;
	ipacm_event_iface_up* data_wan;
	ipacm_event_iface_up_tehter* data_wan_tether;
	list <ipacm_event_data_all>::iterator it;
	ipacm_event_data_all *data_all=NULL;
	ipacm_cmd_q_data evt_data;
	int clnt_indx;
	ipa_macsec_map *map;
	ipa_ioc_ext_router_info *info;
#ifdef FEATURE_IPA_IPSEC
	struct ipa_ioc_ipsec_ul_flt_attr *uf;
#endif
	int idx = 0;
	int j = 0;
#ifdef FEATURE_STATIC_POLICY
	ipacm_event_pdn_dscp_info* pdn_dscp_data;
	uint8_t mux_id;
	uint8_t dscp_val;
#endif

	switch (event)
	{
	case IPA_IPACM_DISABLE:
		IPACMDBG_H("Received IPA_IPACM_DISABLE, treat as IPA_LINK_DOWN_EVENT\n");
	case IPA_LINK_DOWN_EVENT:
		{
			if (event != IPA_IPACM_DISABLE)
			{
				ipacm_event_data_fid *data = (ipacm_event_data_fid *)param;
				ipa_interface_index = iface_ipa_index_query(data->if_index);
			}
			if (ipa_interface_index == ipa_if_num || event == IPA_IPACM_DISABLE)
			{
				IPACMDBG_H("Received IPA_LINK_DOWN_EVENT\n");
				handle_down_evt();
				IPACM_Iface::ipacmcfg->DelNatIfaces(dev_name); // delete NAT-iface
				return;
			}
		}
		break;

	case IPA_CFG_CHANGE_EVENT:
		{
			if ( IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_cat != ipa_if_cate)
			{
				IPACMDBG_H("Received IPA_CFG_CHANGE_EVENT and category changed\n");
				/* delete previous instance */
				handle_down_evt();
				IPACM_Iface::ipacmcfg->DelNatIfaces(dev_name); // delete NAT-iface
				is_mode_switch = true; // need post internal usb-link up event
				return;
			}
			/* Add Natting iface to IPACM_Config if there is  Rx/Tx property */
			if (rx_prop != NULL || tx_prop != NULL)
			{
				IPACMDBG_H(" Has rx/tx properties registered for iface %s, add for NATTING \n", dev_name);
				IPACM_Iface::ipacmcfg->AddNatIfaces(dev_name);
#ifdef FEATURE_VLAN_MPDN
				if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
				{
					IPACM_Iface::ipacmcfg->restore_vlan_nat_ifaces(dev_name);
				}
#endif
			}
		}
		break;
#ifdef FEATURE_IPv6CT_DISABLED
#ifdef FEATURE_IPACM_UL_FIREWALL
	case IPA_FIREWALL_CHANGE_EVENT:
		IPACMDBG_H("Received IPA_FIREWALL_CHANGE_EVENT\n");

		if(ip_type != IPA_IP_v4)
		{
			IPACMDBG_H ("iface_ul_firewall Addr = (0x%x)\n", &iface_ul_firewall);
			configure_v6_ul_firewall();
		}
		else
		{
			IPACMERR("IP type is not valid.\n");
		}
		break;
#endif
#endif
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
			IPACMDBG_H("Received IPA_LAN_DELETE_SELF event.\n");
			IPACMDBG_H("ipa_LAN (%s):ipa_index (%d) instance close \n", IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name, ipa_if_num);
			/* posting link-up event for cradle use-case */
			if(is_mode_switch)
			{
				IPACMDBG_H("Posting IPA_USB_LINK_UP_EVENT event for (%s)\n", dev_name);
				ipacm_cmd_q_data evt_data;
				memset(&evt_data, 0, sizeof(evt_data));

				ipacm_event_data_fid *data_fid = NULL;
				data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
				if(data_fid == NULL)
				{
					IPACMERR("unable to allocate memory for IPA_USB_LINK_UP_EVENT data_fid\n");
					return;
				}
				if(IPACM_Iface::ipa_get_if_index(dev_name, &(data_fid->if_index)))
				{
					IPACMERR("Error while getting interface index for %s device", dev_name);
				}
				evt_data.event = IPA_USB_LINK_UP_EVENT;
				evt_data.evt_data = data_fid;
				IPACM_EvtDispatcher::PostEvt(&evt_data);
			}
#ifndef FEATURE_IPA_ANDROID
			if(rx_prop != NULL)
			{

				for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++){	
					/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
					if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
						if (j != 1) {
							IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
							continue;
						} else {
							idx = 2;
							IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
						} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
					} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
						if (j == 0) {
							idx = 0;
						} else {
							IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
							continue;
						}
					} else {
						idx = j * 2;
						IPACMDBG_H("Install rules at idx %d\n", idx);
					}

					if (IPACM_Iface::ipacmcfg->getFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4) != 0) {
						IPACMDBG_DMESG("### WARNING ### num ipv4 flt rules on client %d is not expected: %d expected value: 0",
									   rx_prop->rx[idx].src_pipe, IPACM_Iface::ipacmcfg->getFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4));
					}
					if (IPACM_Iface::ipacmcfg->getFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6) != 0) {
						IPACMDBG_DMESG("### WARNING ### num ipv6 flt rules on client %d is not expected: %d expected value: 0",
									   rx_prop->rx[idx].src_pipe, IPACM_Iface::ipacmcfg->getFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6));
					}
				}
			}
#endif

			if (rx_prop != NULL)
			{
				if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None &&
					IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
				{
					/* Delete corresponding ipa_rm_resource_name of RX-endpoint after delete all IPV4V6 FT-rule */
					IPACMDBG_H("dev %s delete producer dependency\n", dev_name);
					IPACMDBG_H("depend Got pipe %d rm index : %d \n",rx_prop->rx[0].src_pipe,
						IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[rx_prop->rx[0].src_pipe]);
						IPACM_Iface::ipacmcfg->DelRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[rx_prop->rx[0].src_pipe]);
					IPACMDBG_H("Finished delete dependency \n ");
				}
#ifndef FEATURE_ETH_BRIDGE_LE
				free(rx_prop);
				rx_prop = NULL;
#endif
			}

#ifndef FEATURE_ETH_BRIDGE_LE
			if (tx_prop != NULL)
			{
				free(tx_prop);
				tx_prop = NULL;
			}
			if (iface_query != NULL)
			{
				free(iface_query);
				iface_query = NULL;
			}
#endif
			delete this;
		}
		break;
	}

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
#if defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
			if(is_vlan_event(data->iface_name)) {
				if(data->iptype == IPA_IP_v6

					// for VLAN_MPDN we only have link local addresses
					&& (is_unique_local_ipv6_addr(data->ipv6_addr) &&
						(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == false) &&
						(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) ||
						(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E)))
				{
					IPACMDBG_H("Got IPv6 new addr event for a vlan iface %s.\n", data->iface_name);
					IPACM_Iface::ipacmcfg->handle_vlan_iface_info(data);
					return;
				}
			}
#endif
			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_ADDR_ADD_EVENT\n");

				/* only call ioctl for ODU iface with bridge mode */
				if(IPACM_Iface::ipacmcfg->ipacm_odu_enable == true && IPACM_Iface::ipacmcfg->ipacm_odu_router_mode == false
						&& ipa_if_cate == ODU_IF)
				{
					if((data->iptype == IPA_IP_v6) && (num_dft_rt_v6 == 0))
					{
						handle_addr_evt_odu_bridge(data);
					}
#if defined(FEATURE_IPA_ANDROID) || defined(FEATURE_VLAN_MPDN)
					if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
					{
						handle_private_subnet_android(data->iptype);
					}
					else
					{
						handle_private_subnet(data->iptype);
					}
#else
					handle_private_subnet(data->iptype);
#endif
				}
				else
				{

					/* check v4 not setup before, v6 can have 2 iface ip */
					if( ((data->iptype != ip_type) && (ip_type != IPA_IP_MAX))
						|| ((data->iptype==IPA_IP_v6) && (num_dft_rt_v6!=MAX_DEFAULT_v6_ROUTE_RULES)))
					{
						IPACMDBG_H("Got IPA_ADDR_ADD_EVENT ip-family:%d, v6 num %d, LAN ip_type:%d \n",data->iptype,num_dft_rt_v6, ip_type);
						if(handle_addr_evt(data) == IPACM_FAILURE)
						{
							IPACMDBG_H("failed handle_addr_evt for ip-family:%d\n",data->iptype);
							return;
						}
#if defined(FEATURE_IPA_ANDROID) || defined(FEATURE_VLAN_MPDN) || defined(FEATURE_L2TP)
						if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
						{
							handle_private_subnet_android(data->iptype);
						}
						else
						{
#ifdef FEATURE_L2TP
							if ((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E)
								&& (num_dft_rt_v6 == 1) && (data->iptype == IPA_IP_v6))
							{
								if(ipa_if_cate == ODU_IF)
								{
									install_l2tp_inner_private_subnet_flt_rule(); /* encapsulated IPv4 private subnet rule */
								}
							}
							handle_private_subnet(data->iptype);
#endif
						}
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
#ifdef FEATURE_VLAN_MPDN
						/* VLAN IFACES don't care about default route */
						if(!(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name)))
#endif
						{
							if(IPACM_Wan::isWanUP(ipa_if_num) &&
								!IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
							{
								if(data->iptype == IPA_IP_v4 || data->iptype == IPA_IP_MAX)
								{
									if(IPACM_Wan::backhaul_is_sta_mode == false)
									{
										ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
										handle_wan_up_ex(ext_prop, IPA_IP_v4,
											IPACM_Wan::getXlat_Mux_Id());
									}
									else
									{
										handle_wan_up(IPA_IP_v4);
									}
								}
							}
						}
#ifdef FEATURE_VLAN_MPDN


#ifdef FEATURE_SOCKSv5
						/* handle socksv5 MPDN logic */
						else if(!IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
						{
							if(IPACM_Wan::isWanUP(ipa_if_num) || IPACM_Wan::isVlanWanUP())
							{
								if(data->iptype == IPA_IP_v4 || data->iptype == IPA_IP_MAX)
								{
									if(IPACM_Wan::backhaul_is_sta_mode == false)
									{
										ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
										handle_wan_up_ex(ext_prop, IPA_IP_v4,
											IPACM_Wan::getXlat_Mux_Id());
									}
									else
									{
										handle_wan_up(IPA_IP_v4);
									}
								}
							}
						}
#endif //FEATURE_SOCKSv5
						else
						{
							if(data->iptype == IPA_IP_v4 || data->iptype == IPA_IP_MAX)
							{
								IPACMDBG_H("Checking for V4 VLAN PDN\n");
								check_vlan_PDNUp(IPA_IP_v4);
							}
						}
						/* VLAN IFACES don't care about default route */
						if(!(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name)))
#endif //FEATURE_VLAN_MPDN
						{
#ifdef FEATURE_STATIC_POLICY
							if(IPACM_Wan::isWanUP_V6(ipa_if_num) &&
								!IPACM_Iface::ipacmcfg->ipacm_static_policy_enable) /* Modem v6 call is UP?*/
#else
							if(IPACM_Wan::isWanUP_V6(ipa_if_num)) /* Modem v6 call is UP?*/
#endif
							{
#ifdef FEATURE_IPv6CT_DISABLED
#ifdef FEATURE_IPACM_UL_FIREWALL
								if(data->iptype == IPA_IP_v6)
									configure_v6_ul_firewall();
#endif //FEATURE_IPACM_UL_FIREWALL
#endif
								if((data->iptype == IPA_IP_v6 || data->iptype == IPA_IP_MAX) && num_dft_rt_v6 == 1)
								{
									memcpy(ipv6_prefix, IPACM_Wan::backhaul_ipv6_prefix, sizeof(ipv6_prefix));
#ifndef FEATURE_VLAN_MPDN
									install_ipv6_prefix_flt_rule(IPACM_Wan::backhaul_ipv6_prefix);
#else
									modify_ipv6_prefix_flt_rule();
#endif
									if(IPACM_Wan::backhaul_is_sta_mode == false)
									{
										ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
										handle_wan_up_ex(ext_prop, IPA_IP_v6, 0);
									}
									else
									{
										handle_wan_up(IPA_IP_v6);
									}
								}
							}
#ifdef FEATURE_IPACM_UL_FIREWALL
							else
								IPACMDBG_H("WAN v6 is not UP\n");
#endif //FEATURE_IPACM_UL_FIREWALL
						}
#ifdef FEATURE_VLAN_MPDN
#ifdef FEATURE_SOCKSv5
						/* handle socksv5 MPDN logic */
						else if(!IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
						{
							if(IPACM_Wan::isWanUP_V6(ipa_if_num) ||  IPACM_Wan::isVlanWanUP_V6()) /* Modem v6 call is UP?*/
							{
#ifdef FEATURE_IPv6CT_DISABLED
#ifdef FEATURE_IPACM_UL_FIREWALL
								if(data->iptype == IPA_IP_v6)
									configure_v6_ul_firewall();
#endif //FEATURE_IPACM_UL_FIREWALL
#endif
								if((data->iptype == IPA_IP_v6 || data->iptype == IPA_IP_MAX) && num_dft_rt_v6 == 1)
								{
									memcpy(ipv6_prefix, IPACM_Wan::backhaul_ipv6_prefix, sizeof(ipv6_prefix));
									modify_ipv6_prefix_flt_rule();

									if(IPACM_Wan::backhaul_is_sta_mode == false)
									{
										ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
										handle_wan_up_ex(ext_prop, IPA_IP_v6, 0);
									}
									else
									{
										handle_wan_up(IPA_IP_v6);
									}
								}
							}
						}
#endif //FEATURE_SOCKSv5
						else
						{
							IPACMDBG_H("Checking for V6 VLAN PDN\n");
							check_vlan_PDNUp(IPA_IP_v6);
						}
#endif //FEATURE_VLAN_MPDN

						/* Post event to NAT */
						if (post_lan_up_event(data))
						{
							return;
						}

						IPACMDBG_H("Finish handling IPA_ADDR_ADD_EVENT for ip-family(%d)\n", data->iptype);
					}

#ifdef FEATURE_EoGRE
					if ( IPACM_Iface::ipacmcfg->eogre_enabled )
					{
						IPACMDBG_H(
							"A previous eogre enable needs to be undone, then redone. "
							"Need to call eogre_down followed by an eogre_up\n");
						eogre_down();
						eogre_up();
					}
#endif
					IPACMDBG_H("Finish handling IPA_ADDR_ADD_EVENT for ip-family(%d)\n", data->iptype);

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
					handle_wan_up_ex(ext_prop, IPA_IP_v4, 0);
				}
				else
				{
					handle_wan_up(IPA_IP_v4);
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
						handle_wan_up_ex(ext_prop, IPA_IP_v6, 0);
					}
					else
					{
						handle_wan_up(IPA_IP_v6);
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
			if(ip_type == IPA_IP_v4 || ip_type == IPA_IP_MAX)
			{
				handle_wan_down(data_wan_tether->is_sta);
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
			IPACMDBG_H("Received IPA_HANDLE_WAN_DOWN_V6_TETHER in LAN-instance and need clean up client IPv6 address \n");
			/* reset usb-client ipv6 rt-rules */
			handle_lan_client_reset_rt(IPA_IP_v6);

			if(ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX)
			{
				handle_wan_down_v6(data_wan_tether->is_sta);
			}
		}
		break;
#else
	case IPA_HANDLE_WAN_UP:
		IPACMDBG_H("Received IPA_HANDLE_WAN_UP event\n");

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
		   (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE) &&
		   !sIface)
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


		if(ip_type == IPA_IP_v4 || ip_type == IPA_IP_MAX)
		{
			if(data_wan->is_sta == false)
			{
				ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
				handle_wan_up_ex(ext_prop, IPA_IP_v4, data_wan->xlat_mux_id);
			}
			else
			{
				handle_wan_up(IPA_IP_v4);
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
			(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE))
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
			IPACMDBG_H("IPACM in static policy enable mode. Dont need to install UL rules\n");
			return;
		}
#endif
		if(ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX)
		{
#ifdef FEATURE_IPv6CT_DISABLED
#ifdef FEATURE_IPACM_UL_FIREWALL
			configure_v6_ul_firewall();
#endif //FEATURE_IPACM_UL_FIREWALL
#endif
			memcpy(ipv6_prefix, data_wan->ipv6_prefix, sizeof(ipv6_prefix));
#ifdef FEATURE_VLAN_MPDN
			if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
				modify_ipv6_prefix_flt_rule();
			else
				install_ipv6_prefix_flt_rule(data_wan->ipv6_prefix);
#else
			install_ipv6_prefix_flt_rule(data_wan->ipv6_prefix);
#endif
			if(data_wan->is_sta == false)
			{
				ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
				handle_wan_up_ex(ext_prop, IPA_IP_v6, 0);
			}
			else
			{
				handle_wan_up(IPA_IP_v6);
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
#ifdef FEATURE_VLAN_MPDN
		/* VLAN IFACES don't care about default route */
		if(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name) &&
			(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE ||
			IPACM_Wan::isVlanWanUP()))
		{
			IPACMDBG_H("IF %s is vlan IF, ignoring IPA_HANDLE_WAN_DOWN\n", dev_name);
			return;
		}
#endif
		if(ip_type == IPA_IP_v4 || ip_type == IPA_IP_MAX)
		{
			handle_wan_down(data_wan->is_sta);
		}

		/* reset GRE flag */
		if (IPACM_Iface::ipacmcfg->ipacm_gre_enable == true)
		{
			int i;

			for (i = 0; i < num_eth_client; i++)
			{
				if (get_client_memptr(eth_client, i)->ipv4_set == true)
					IPACMDBG_H("Resettng eth client %d gre_nat_set to false", i);
					get_client_memptr(eth_client, clnt_indx)->gre_nat_set = false;
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
		IPACMDBG_H("Received IPA_WAN_V6_DOWN in LAN-instance and need clean up client IPv6 address \n");
#ifdef FEATURE_VLAN_MPDN
		/* VLAN IFACES don't care about default route */
		if(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name) &&
			(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE ||
			IPACM_Wan::isVlanWanUP_V6()))
		{
			IPACMDBG_H("IF %s is vlan IF, ignoring IPA_HANDLE_WAN_DOWN_V6\n", dev_name);
			return;
		}
#endif
		/* reset usb-client ipv6 rt-rules */
		handle_lan_client_reset_rt(IPA_IP_v6);
		it = neigh_cache.begin();
		while (it != neigh_cache.end())
		{
			if (it->ipv6_addr[0] == data_wan->ipv6_prefix[0] && it->ipv6_addr[1] == data_wan->ipv6_prefix[1])
				it = neigh_cache.erase(it);
			else
				it++;
		}

		IPACMDBG_H("Backhaul is sta mode?%d\n", data_wan->is_sta);
		if(ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX)
		{
#ifdef FEATURE_UL_FIREWALL
			// pdn is down, disable its Q6 UL firewall and reconfigure for all others
			disable_dft_firewall_rules_ul_ex(0);
#ifdef FEATURE_IPv6CT_DISABLED
			configure_v6_ul_firewall();
#endif
#endif
			handle_wan_down_v6(data_wan->is_sta);
		}
		break;
#endif

	case IPA_LAN_CLIENT_ADD_EVENT:
		{
			ipacm_event_data_all *data = (ipacm_event_data_all *)param;
			IPACMDBG_H("Received IPA_LAN_CLIENT_ADD_EVENT event \n");
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			IPACMDBG_H("check iface %s category: %d\n", dev_name, ipa_if_cate);
			if(ipa_interface_index == ipa_if_num)
			{
				/* first construc ETH full header */
				if (handle_eth_hdr_init(data->mac_addr) == IPACM_FAILURE)
				{
					IPACMERR("Failed to create header and No event IPA_ETH_BRIDGE_CLIENT_ADD posted.\n");
					return;
				}
				IPACMDBG_H("construct ETH header and route rules \n");
				if(IPACM_Iface::ipacmcfg->mac_addr_in_blacklist(data->mac_addr) == false)
				{
					IPACMDBG_H("Posting IPA_ETH_BRIDGE_CLIENT_ADD for Static IP MAC:0x%x iface_name: %s\n",data->mac_addr,data->iface_name);
					eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_ADD, IPA_IP_MAX, data->mac_addr, NULL, data->iface_name);
				}
				else
					IPACMDBG_H("Client is blacklisted for mac based filtering, avoid adding to lan2lan offload \n");

				IPACMDBG_H("Handled IPA_LAN_CLIENT_ADD_EVENT event ip-type:%d\n",data->iptype);
			}
		}
		break;

	case IPA_LAN_CLIENT_DEL_EVENT:
		{
			ipacm_event_data_all *data = (ipacm_event_data_all *)param;
			uint16_t vlan_id = 0;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			IPACMDBG_H("Received IPA_LAN_CLIENT_DEL_EVENT event \n");
			IPACMDBG_H("check iface %s category: %d\n", dev_name, ipa_if_cate);
			if(ipa_interface_index == ipa_if_num)
			{
				/* clear mac flt rules for client if any */
				if(IPACM_Iface::ipacmcfg->mac_addr_in_blacklist(data->mac_addr))
					handle_eth_mac_flt_conn_disc(data->mac_addr, false);

				delete_client_qos_rule(data->mac_addr, vlan_id, data->iptype, NULL);
				IPACMDBG_H("LAN iface delete client \n");
				handle_eth_client_down_evt(data->mac_addr, vlan_id, data);
				IPACMDBG_H("Posting IPA_ETH_BRIDGE_CLIENT_DEL for Static IP MaC:0x%x iface_name: %s\n",data->mac_addr,data->iface_name);
				eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_DEL, data->iptype, data->mac_addr, NULL, data->iface_name, vlan_id);
				IPACMDBG_H("Handled IPA_LAN_CLIENT_DEL_EVENT event ip-type:%d\n",data->iptype);
			}
		}
		break;


	case IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT:
		{
			int eth_index;
			tether_client_info client_info;
#if defined(FEATURE_IPACM_PER_CLIENT_STATS) && defined(IPA_HW_FNR_STATS)
			int retval;
#endif //IPA_HW_FNR_STATS
			ipacm_event_data_all *data = (ipacm_event_data_all *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			IPACMDBG_H("Received IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT event \n");
			IPACMDBG_H("check iface %s category: %d\n", dev_name, ipa_if_cate);
			if (ipa_interface_index == ipa_if_num && ipa_if_cate == ODU_IF)
			{
				IPACMDBG_H("ODU iface got v4-ip \n");
				/* first construc ODU full header */
				if ((ipv4_header_set == false) && (ipv6_header_set == false))
				{
					/* construct ODU RT tbl */
					handle_odu_hdr_init(data->mac_addr);
					if (IPACM_Iface::ipacmcfg->ipacm_odu_embms_enable == true)
					{
						handle_odu_route_add();
						IPACMDBG_H("construct ODU header and route rules, embms_flag (%d) \n", IPACM_Iface::ipacmcfg->ipacm_odu_embms_enable);
					}
					else
					{
						IPACMDBG_H("construct ODU header only, embms_flag (%d) \n", IPACM_Iface::ipacmcfg->ipacm_odu_embms_enable);
					}
				}
				/* if ODU in bridge mode, directly return */
				if(IPACM_Iface::ipacmcfg->ipacm_odu_router_mode == false)
				{
					IPACMDBG_H("ODU is in bridge mode, no action \n");
					return;
				}
			}

			if(ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("ETH iface got client \n");
#ifdef FEATURE_VLAN_MPDN
				if(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name) && !sIface)
				{
					IPACMDBG_H("physical iface in vlan mode got neighbor event with iptype %d, ip4 0x%X, ip6 pref [0x%X] [0x%X]\n",
						data->iptype, data->ipv4_addr, data->ipv6_addr[0], data->ipv6_addr[1]);
					IPACMDBG_H("ignoring non vlan neighbor event for vlan device\n");
					return;
				}
#endif
				/* add to tether-client-lists */
				memset(&client_info, 0, sizeof(tether_client_info));
				if (data->iptype == IPA_IP_v4)
				{
					client_info.v4_addr = data->ipv4_addr;
				}
				else if (data->iptype == IPA_IP_v6)
				{
					client_info.v4_addr = 0;
				}
				IPACMDBG_H(" iface name %s  dev %s\n", data->iface_name, dev_name);
				memcpy(client_info.iface, dev_name, IPA_IFACE_NAME_LEN);
				IPACM_Iface::ipacmcfg->update_client_info(data->mac_addr, &client_info, true);

				/* Associate with IP and construct RT-rule */
				if (handle_eth_client_ipaddr(data) == IPACM_FAILURE)
				{
					IPACMERR("Failed handle_eth_client_ipaddr, continue\n");
					return;
				}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
				if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
				{
					/* Do not add rt and NAT rule if mac flt enable for client */
					if(IPACM_Iface::ipacmcfg->mac_addr_in_blacklist(data->mac_addr) == false)
					{
						handle_eth_client_route_rule(data->mac_addr, data->iptype);
#ifdef FEATURE_STATIC_POLICY
						if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && data->iptype == IPA_IP_v4)
						{
							handle_pdn_dscp_eth_client_route_rule(data->mac_addr, data->iptype, 0, 0, 0);
						}
						else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && data->iptype == IPA_IP_v6)
						{
							handle_pdn_dscp_eth_client_route_rule(data->mac_addr, data->iptype, 0, 0, 0, 0, data->ipv6_addr);
						}
#endif
						install_all_qos_route_rule(data->mac_addr, 0, data->ipv6_addr);
						IPACM_Iface::ipacmcfg->AddNatIfaces(data->iface_name);
						/* Add NAT rules after RT rules are set */
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
						eth_index = get_eth_client_index(data->mac_addr);
						retval = handle_eth_client_route_rule_ext_v2(data->mac_addr, data->iptype,
							get_client_memptr(eth_client, eth_index)->dl_cnt_idx);
						IPACMDBG_H("Route install retval = %d\n", retval);
#ifdef FEATURE_STATIC_POLICY
						if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
						{
							if(data->iptype == IPA_IP_v4)
							{
								retval = handle_pdn_dscp_eth_client_route_rule_ext_v2(data->mac_addr,
									data->iptype, 0);
							}
							else if(data->iptype == IPA_IP_v6)
							{
								retval = handle_pdn_dscp_eth_client_route_rule_ext_v2(data->mac_addr,
									data->iptype, 0, data->ipv6_addr);
							}
							IPACMDBG_H("Route install retval = %d\n", retval);
						}
#endif
						HandleNeighIpAddrAddEvt(data);
					}
					else
#endif //IPA_HW_FNR_STATS
					{
						if(IPACM_Iface::ipacmcfg->mac_addr_in_blacklist(data->mac_addr) == false)
						{
							handle_eth_client_route_rule_ext(data->mac_addr, data->iptype);
							HandleNeighIpAddrAddEvt(data);
						}
					}
				}
#endif
			}
#ifdef FEATURE_L2TP
			if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E ||
				IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) &&
				is_l2tp_event(data->iface_name) && ipa_if_cate == ODU_IF)
			{
				handle_l2tp_neigh(data);
			}
#endif
#if defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
			if(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name) && is_vlan_event(data->iface_name))
			{
				IPACMDBG_H("vlan neighbor event for iface %s\n", data->iface_name);
				/* in VLAN_MPDN we handle all VLAN neighbors */
				if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E ||
					IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) &&
					data->iptype == IPA_IP_v6 && is_unique_local_ipv6_addr(data->ipv6_addr))
				{
					IPACM_Iface::ipacmcfg->handle_vlan_client_info(data);
					IPACMDBG_H("ipacm_socksv5_enable %d\n", IPACM_Iface::ipacmcfg->ipacm_socksv5_enable);
				}

				IPACMDBG_H("construct DL rt-rule for socksv5 MPDN clients\n");
				handle_vlan_neighbor(data);
			}
#endif
			eth_index = get_eth_client_index(data->mac_addr);
			if (eth_index == IPACM_INVALID_INDEX)
			{
				IPACMERR("eth client not found/attached \n");
				return;
			}
			get_client_memptr(eth_client, eth_index)->if_index = data->if_index;
			IPACMDBG_H("index %d if_index %d \n", eth_index, get_client_memptr(eth_client, eth_index)->if_index);

			/* add mac balcklist rule if client is added after mac flt event is received */
			if(IPACM_Iface::ipacmcfg->mac_addr_in_blacklist(data->mac_addr) == true)
					handle_eth_mac_flt_conn_disc(data->mac_addr, true);
			return;
		}
		break;

	case IPA_NEIGH_CLIENT_IP_ADDR_DEL_EVENT:
		{
			ipacm_event_data_all *data = (ipacm_event_data_all *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);

			IPACMDBG_H("Received IPA_NEIGH_CLIENT_IP_ADDR_DEL_EVENT event for ip_type: %d \n", data->iptype);
			IPACMDBG_H("check iface %s category: %d\n", dev_name, ipa_if_cate);
			/* if ODU in bridge mode, directly return */
			if (ipa_if_cate == ODU_IF && IPACM_Iface::ipacmcfg->ipacm_odu_router_mode == false)
			{
				IPACMDBG_H("ODU is in bridge mode, no action \n");
				return;
			}

			if (ipa_interface_index == ipa_if_num
#ifdef FEATURE_L2TP
				|| ((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E ||
					IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) &&
					is_l2tp_event(data->iface_name) && ipa_if_cate == ODU_IF)
#endif
#ifdef FEATURE_VLAN_MPDN
				|| ((IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE) &&
						is_vlan_event(data->iface_name))
#endif
				)
			{
				if (
#ifdef FEATURE_VLAN_MPDN
					(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
					||
#endif
#ifdef FEATURE_L2TP
					 (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable) &&
#endif
					(ipa_interface_index == ipa_if_num)
					)
				{
					uint16_t vlan_id = 0;

					if (data->iptype == IPA_IP_v6)
					{
						handle_del_ipv6_addr(data);
						return;
					}
#ifdef FEATURE_VLAN_MPDN
					if((IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE) &&
						is_vlan_event(data->iface_name))
					{
						IPACMDBG_H("handling vlan ETH client del v4 ip address for iface %s\n",
							data->iface_name);
						if(IPACM_Iface::ipacmcfg->get_vlan_id(data->iface_name, &vlan_id))
						{
							IPACMERR("failed getting vlan id for iface %s\n",
								data->iface_name);
							return;
						}
					}
#endif
					/* Delete QOS rules. */
					if (IPACM_Iface::ipacmcfg->ipacm_qos_enable) {
						delete_client_qos_rule(data->mac_addr, vlan_id, IPA_IP_v4, NULL);
						delete_client_qos_rule(data->mac_addr, vlan_id, IPA_IP_v6, NULL);
					}
				}
#ifdef FEATURE_L2TP
				else
				{

					if (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP &&
						data->iptype == IPA_IP_v4)
					{
						eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_DEL,
							data->iptype, data->mac_addr, NULL, data->iface_name);
					}

					if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E) &&
						data->iptype == IPA_IP_v4)
					{
						uninstall_l2tp_rules(data);
					}
				}
#endif
				return;
			}
		}
		break;

#ifdef FEATURE_SOCKSv5
	case IPA_HANDLE_SOCKSv5_READY:
		{
			IPACMDBG_H("Received IPA_HANDLE_SOCKSv5_READY %d\n", IPA_HANDLE_SOCKSv5_READY);
			ipacm_event_connection *data_evt_conn = (ipacm_event_connection *)param;
			add_socksv5_flt_rule(data_evt_conn);
		}
		break;

	case IPA_HANDLE_SOCKSv5_DOWN:
		IPACMDBG_H("Received IPA_HANDLE_SOCKSv5_DOWN, %d\n", IPA_HANDLE_SOCKSv5_DOWN);
		del_socksv5_flt_rule();
		break;
#endif

	case IPA_SW_ROUTING_ENABLE:
		IPACMDBG_H("Received IPA_SW_ROUTING_ENABLE\n");
		/* handle software routing enable event*/
		handle_software_routing_enable();
		break;

	case IPA_SW_ROUTING_DISABLE:
		IPACMDBG_H("Received IPA_SW_ROUTING_DISABLE\n");
		/* handle software routing disable event*/
		handle_software_routing_disable();
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

	case IPA_TETHERING_STATS_UPDATE_EVENT:
	{
		IPACMDBG_H("Received IPA_TETHERING_STATS_UPDATE_EVENT event.\n");
		if (IPACM_Wan::isWanUP(ipa_if_num) || IPACM_Wan::isWanUP_V6(ipa_if_num))
		{
			if(IPACM_Wan::backhaul_is_sta_mode == false) /* LTE */
			{
				ipa_get_data_stats_resp_msg_v01 *data = (ipa_get_data_stats_resp_msg_v01 *)param;
				IPACMDBG("Received IPA_TETHERING_STATS_UPDATE_STATS ipa_stats_type: %d\n",data->ipa_stats_type);
				IPACMDBG("Received %d UL, %d DL pipe stats\n",data->ul_src_pipe_stats_list_len,
					data->dl_dst_pipe_stats_list_len);
				if (data->ipa_stats_type != QMI_IPA_STATS_TYPE_PIPE_V01)
				{
					IPACMERR("not valid pipe stats enum(%d)\n", data->ipa_stats_type);
					return;
				}
				handle_tethering_stats_event(data);
			}
		}
	}
	break;

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	/* QCMAP sends this event whenever a client is connected. */
	case IPA_LAN_CLIENT_CONNECT_EVENT:
		{
			IPACMDBG_H("Got LAN client connect event\n");
			ipacm_event_data_mac *data = (ipacm_event_data_mac *)param;
			if (!IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable)
			{
				IPACMDBG_H("LAN stats functionality is not enabled, ignore IPA_LAN_CLIENT_CONNECT_EVENT.\n");
				return;
			}
			IPACM_Lan::handle_stats_client_connect(data->if_index, data->mac_addr);
		}
		break;
	/* QCMAP sends this event whenever a client is disconnected. */
	case IPA_LAN_CLIENT_DISCONNECT_EVENT:
		{
			ipacm_event_data_mac *data = (ipacm_event_data_mac *)param;
			if (!IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable)
			{
				IPACMDBG_H("LAN stats functionality is not enabled, ignore IPA_LAN_CLIENT_DISCONNECT_EVENT.\n");
				return;
			}
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_LAN_CLIENT_DISCONNECT_EVENT\n");
				IPACM_Lan::handle_lan_client_disconnect(data->mac_addr);
			}
		}
		break;
#endif
#ifdef FEATURE_VLAN_MPDN
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
#ifdef FEATURE_IPv6CT_DISABLED
#ifdef FEATURE_IPACM_UL_FIREWALL
					configure_v6_ul_firewall();
#endif
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

				//Add per client stats rules for all active LAN clients if feature is enabled
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
					int clnt_indx = get_eth_client_index_from_if_index(if_index);
					uint32_t ipv4_addr = get_client_memptr(eth_client, clnt_indx)->v4_addr;

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

				//Add per client stats rules for all active LAN clients if feature is enabled
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
#ifdef FEATURE_IPv6CT_DISABLED
					configure_v6_ul_firewall();
#endif
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
	case IPA_NOTIFY_VLAN_UP:
		{
			IPACMDBG_H("Received IPA_NOTIFY_VLAN_UP\n");
			if(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name))
			{
				if(IPACM_Wan::isVlanWanUP() && !modem_ul_v4_set[0])
				{
					IPACMDBG_H("Check any missed v4 VLAN handling in v4 new ADDR\n");
					check_vlan_PDNUp(IPA_IP_v4);
				}
				else if (IPACM_Wan::isVlanWanUP_V6() && !modem_ul_v6_set[0])
				{
					IPACMDBG_H("Check any missed v6 VLAN handling in v6 new ADDR\n");
					check_vlan_PDNUp(IPA_IP_v6);
				}
			}
		}
		break;
#endif
	case IPA_MAC_ADD_DEL_FLT_EVENT:
		{
			IPACMDBG_H(" IPA_MAC_ADD_DEL_FLT_EVENT received\n");
			if(handle_eth_mac_flt_event())
			{
				IPACMERR("failed to handle IPA_MAC_ADD_DEL_FLT_EVENT \n");
			}
		}
		break;
	/* only need for vlan supported lan instance */
	case IPA_HANDLE_WAN_ADDR_ADD_V6:
		{
			data_wan = (ipacm_event_iface_up*)param;
			if(data_wan == NULL)
			{
				IPACMERR("No event data is found.\n");
				break;
			}
#ifdef FEATURE_VLAN_MPDN
			/* non VLAN IFACES will receive WAN_UP from wan instance */
			if((!IPACM_Iface::ipacmcfg->ipacm_mpdn_enable) ||
				(!IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name)))
				break;
#endif
			if (is_mux_up(data_wan->mux_id, IPA_IP_v6, 0)) //0 is to just check for mux without VLANS
			{
				IPACMERR("mux id %d is already up for v6 ignore\n", data_wan->mux_id);
				break;
			}

			if(ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX)
			{
				it = neigh_cache.begin();
				while (it != neigh_cache.end())
				{
					if (it->ipv6_addr[0] == data_wan->ipv6_prefix[0] &&
							it->ipv6_addr[1] == data_wan->ipv6_prefix[1])
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
						IPACMDBG_H("Posted event %d, with %s for ipv6 client \n",
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
		}
		break;
#ifdef IPA_MTU_EVENT_MAX
	case IPA_MTU_UPDATE:
	{
		IPACMDBG_H("Received IPA_MTU_UPDATE");
		ipacm_event_mtu_info *evt_data = (ipacm_event_mtu_info *)param;
		ipa_mtu_info *data = &(evt_data->mtu_info);

		/* IPA_IP_MAX means both ipv4 and ipv6 */
#ifdef FEATURE_VLAN_MPDN
		if ((data->ip_type == IPA_IP_v4 || data->ip_type == IPA_IP_MAX) && (IPACM_Wan::isWanUP(ipa_if_num) || IPACM_Wan::isVlanWanUP()))
#else
		if ((data->ip_type == IPA_IP_v4 || data->ip_type == IPA_IP_MAX) && IPACM_Wan::isWanUP(ipa_if_num))
#endif
		{
			modify_private_subnet();
		}

		/* IPA_IP_MAX means both ipv4 and ipv6 */
#ifdef FEATURE_VLAN_MPDN
		if ((data->ip_type == IPA_IP_v6 || data->ip_type == IPA_IP_MAX) && (IPACM_Wan::isWanUP_V6(ipa_if_num) || IPACM_Wan::isVlanWanUP_V6()))
		{
			modify_ipv6_prefix_flt_rule();
		}
#else
		if ((data->ip_type == IPA_IP_v6 || data->ip_type == IPA_IP_MAX) && IPACM_Wan::isWanUP_V6(ipa_if_num))
		{
			delete_ipv6_prefix_flt_rule();
			install_ipv6_prefix_flt_rule(IPACM_Wan::backhaul_ipv6_prefix);
		}
#endif

#ifdef FEATURE_EoGRE
		/* if GRE is enabled, update both v4 and v6 MTU */
		if (IPACM_Iface::ipacmcfg->ipacm_gre_enable)
		{
			modify_private_subnet();
#ifdef FEATURE_VLAN_MPDN
			modify_ipv6_prefix_flt_rule();
#else
			delete_ipv6_prefix_flt_rule();
			install_ipv6_prefix_flt_rule(IPACM_Wan::backhaul_ipv6_prefix);
#endif
		}
#endif
	}
	break;
#endif

#ifdef FEATURE_EoGRE
	case IPA_HANDLE_EoGRE_UP:
		IPACMDBG_H("Received and will process an IPA_HANDLE_EoGRE_UP\n");
		IPACM_Iface::ipacmcfg->eogre_enabled = true;
		eogre_up();
		break;

	case IPA_HANDLE_EoGRE_DOWN:
		IPACMDBG_H("Received and will process an IPA_HANDLE_EoGRE_DOWN\n");
		IPACM_Iface::ipacmcfg->eogre_enabled = false;
		eogre_down();
		break;
#endif
	case IPA_HANDLE_MACSEC_ADD:
		IPACMDBG_H("Received and will process an IPA_HANDLE_MACSEC_ADD\n");
		map = (ipa_macsec_map *)param;

		/*
		 * Check, whether the mapping change is addressed to this interface,
		 * and if yes, rename it to the macsec interface.
		 */
		if (virtual_iface && strncmp(map->phy_name, phy_dev_name, sizeof(phy_dev_name)) == 0 ||
		    strncmp(map->phy_name, dev_name, sizeof(dev_name)) == 0)
		{
			strlcpy(phy_dev_name, map->phy_name, sizeof(phy_dev_name));
			strlcpy(dev_name, map->macsec_name, sizeof(dev_name));
			virtual_iface = true;
		}
		break;

	case IPA_HANDLE_MACSEC_DEL:
		IPACMDBG_H("Received and will process an IPA_HANDLE_MACSEC_DEL\n");
		map = (ipa_macsec_map *)param;

		/*
		 * Check, whether the mapping change is addressed to this interface,
		 * and if yes, rename it to the eth interface.
		 */
		if (virtual_iface && strncmp(map->macsec_name, dev_name, sizeof(dev_name)) == 0)
		{
			strlcpy(dev_name, phy_dev_name, sizeof(dev_name));
			virtual_iface = false;
			phy_dev_name[0] = '\0';
		}
		break;

	case IPA_QOS_RULE_ADD_EVENT:
		{
			IPACMDBG_H("Received and will process an IPA_QOS_RULE_ADD_EVENT\n");
			delete_all_client_qos_rules();
			for (int cnt = 0; cnt < num_eth_client; cnt++)
			{
				IPACMDBG_H("Install qos for clnt idx %d with vlan id %d\n", cnt, get_client_memptr(eth_client, cnt)->vlan_id);
				install_all_qos_route_rule(get_client_memptr(eth_client, cnt)->mac,
					get_client_memptr(eth_client, cnt)->vlan_id, NULL);
			}
			break;
		}

	case IPA_QOS_RULE_DEL_EVENT:
		{
			qos_delete_param_info *qos_param;
			qos_param = (qos_delete_param_info *)param;
			IPACMDBG_H("Received and will process an IPA_QOS_RULE_DEL_EVENT\n");

			IPACMDBG_H("Deleting %d qos eth clients \n", qos_param->client_cnt);

			for (int i = 0; i < qos_param->client_cnt; i++)
			{
				IPACMDBG_H("QOS is v4 set %d for hdl %d\n",
						 qos_param->qos_client_list[i].route_rule_set_v4, qos_param->qos_client_list[i].qos_rt_rule_hdl_v4);

				if (qos_param->qos_client_list[i].route_rule_set_v4 &&
					(m_routing.DeleteRoutingHdl(qos_param->qos_client_list[i].qos_rt_rule_hdl_v4, IPA_IP_v4) == false))
				{
					return;
				}

				IPACMDBG_H("QOS is v6 set %d hdl %d\n",
					qos_param->qos_client_list[i].route_rule_set_v6,
					qos_param->qos_client_list[i].qos_rt_rule_hdl_v6);
				if (qos_param->qos_client_list[i].route_rule_set_v6 &&
					(m_routing.DeleteRoutingHdl(qos_param->qos_client_list[i].qos_rt_rule_hdl_v6, IPA_IP_v6) == false))
					return;
			}

			break;
		}

	case IPA_ADD_EXT_ROUTER_RULES:
		IPACMDBG_H("Received and will process IPA_ADD_EXT_ROUTER_RULES\n");

		for (it = neigh_cache.begin(); it != neigh_cache.end(); ++it)
		{
			if (IPACM_Iface::ipacmcfg->is_ext_route_ipv6_prefix(it->ipv6_addr))
			{
				IPACMDBG_H("Found cached client v6 addr : 0x%08x:%08x:%08x:%08x MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					it->ipv6_addr[0], it->ipv6_addr[1], it->ipv6_addr[2], it->ipv6_addr[3],
					it->mac_addr[0], it->mac_addr[1], it->mac_addr[2], it->mac_addr[3], it->mac_addr[4], it->mac_addr[5]);
				handle_ext_router_add_evt((char*)param, it->mac_addr, it->ipv6_addr, 0); //can query vlan id instead of 0 for future vlan support
				return; //for MVLAN might need to remove the return to handle all the prefixes
			}
		}
		IPACMDBG_H("Dummy prefix neighbor hasn't been added yet, wait until new neighbor to install ext route rules\n");
		break;

	case IPA_DEL_EXT_ROUTER_RULES:
		IPACMDBG_H("Received and will process IPA_DEL_EXT_ROUTER_RULES\n");

		if(strncmp(ext_router_pdn_name, (char*)param, sizeof(ext_router_pdn_name)) == 0)
		{
			IPACMDBG_H("Deleting ext route rules for lan client %s, pdn %s\n", dev_name, ext_router_pdn_name);

			if(handle_ext_router_del_evt() == IPACM_FAILURE)
				IPACMERR("failed deleting ext route mode rules");
		}
		break;

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

#ifdef FEATURE_STATIC_POLICY
	case IPA_PDN_DSCP_UPDATE_EVENT:
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
			handle_pdn_dscp_eth_client_route_rule(0, IPA_IP_v4, 1, 0, mux_id, dscp_val);
			handle_pdn_dscp_eth_client_route_rule(0, IPA_IP_v6, 1, 0, mux_id, dscp_val);
		}
		else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && !pdn_dscp_data->enable)
		{
			delete_pdn_dscp_eth_rtrules(IPA_IP_v4, 1, -1, mux_id);
			delete_pdn_dscp_eth_rtrules(IPA_IP_v6, 1, -1, mux_id);
		}
		else if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && pdn_dscp_data->enable &&
			IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
		{
			handle_pdn_dscp_eth_client_route_rule_ext_v2(0, IPA_IP_v4, 1, 0, 0,
				mux_id, dscp_val);
			handle_pdn_dscp_eth_client_route_rule_ext_v2(0, IPA_IP_v6, 1, 0, 0,
				mux_id, dscp_val);
		}
		break;
#endif

	default:
		break;
	}

	return;
}

/* handle_eth_mac_flt_event add/del rule based on mac addr and their flt state */
int IPACM_Lan::handle_eth_mac_flt_event()
{
	IPACMDBG_H("handle_eth_mac_flt_event\n ");
	uint8_t mac_addr[6]= {0};
	int eth_index;
	ipacm_event_data_all data;
	/* work on copy list to avoid concurrency issues*/
	auto macFltListsCopy = IPACM_Iface::ipacmcfg->getMacFltListsCopySafe();

	auto it = macFltListsCopy.begin();
	while (it != macFltListsCopy.end())
	{
		std::copy(std::begin(it->first), std::end(it->first), std::begin(mac_addr));
		eth_index = get_eth_client_index(mac_addr);
		if(eth_index != IPACM_INVALID_INDEX)
		{
			if(it->second->is_blacklist)
			{
				if(get_client_memptr(eth_client, eth_index)->ipv4_set && !it->second->mac_v4_rt_del_flt_set)
				{
					/* add a new UL flt rule, del NAT and route rule for client */
					if(add_mac_flt_blacklist_rule(mac_addr,IPA_IP_v4, &(it->second->mac_v4_flt_rule_hdl)))
					{
						IPACMERR("unbale to add mac flt blacklist v4 UL rule for index: %d\n", eth_index);
						return IPACM_FAILURE;
					}
					/* ongoing/new allowing connections will have NAT-miss issue, will optimize future */
					CtList->HandleNeighIpAddrDelEvt(get_client_memptr(eth_client, eth_index)->v4_addr);
					if(handle_eth_client_mac_flt_route_rule(IPA_IP_v4, eth_index, it->second->is_blacklist))
					{
						IPACMERR("unbale to del v4 rt rule for index: %d\n", eth_index);
						return IPACM_FAILURE;
					}
					it->second->mac_v4_rt_del_flt_set = true;
				}
				if (get_client_memptr(eth_client, eth_index)->ipv6_set && !it->second->mac_v6_rt_del_flt_set)
				{
					/* add a new ul flt rule for s/w path & del route rule for client */
					if(add_mac_flt_blacklist_rule(mac_addr,IPA_IP_v6, &(it->second->mac_v6_flt_rule_hdl)))
					{
						IPACMERR("unbale to add mac flt blacklist v6 UL rule for index: %d\n", eth_index);
						return IPACM_FAILURE;
					}
					if(handle_eth_client_mac_flt_route_rule(IPA_IP_v6, eth_index, it->second->is_blacklist))
					{
						IPACMERR("unbale to del v6 rt rule for index: %d\n", eth_index);
						return IPACM_FAILURE;
					}
					it->second->mac_v6_rt_del_flt_set = true;
				}
				it->second->current_blocked = true;
				/* remove from lan2lan offload module */
				eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_DEL, IPA_IP_MAX, mac_addr, NULL, dev_name);
				/* In case of client blackklisted, update config mac list with copy mac flt list value */
				IPACM_Iface::ipacmcfg->update_mac_flt_lists(mac_addr, it->second);
				it++;
			}
			else
			{
				if(it->second->mac_v4_rt_del_flt_set)
				{
					/* del ul flt rule for s/w path & add route/Nat rule for client */
					if(del_mac_flt_blacklist_rule(it->second->mac_v4_flt_rule_hdl,	IPA_IP_v4))
					{
						IPACMERR("unbale to del mac flt blacklist v4 UL rule for index: %d\n", eth_index);
						return IPACM_FAILURE;
					}
					if(handle_eth_client_mac_flt_route_rule(IPA_IP_v4, eth_index, it->second->is_blacklist))
					{
						IPACMERR("unbale to add v4 rt rule for index: %d\n", eth_index);
						return IPACM_FAILURE;
					}
					it->second->mac_v4_rt_del_flt_set = false;
				}
				if(it->second->mac_v6_rt_del_flt_set)
				{
					/* del ul flt rule for s/w path & add route rule for client */
					if(del_mac_flt_blacklist_rule(it->second->mac_v6_flt_rule_hdl,	IPA_IP_v6))
					{
						IPACMERR("unbale to del mac flt blacklist v6 UL rule for index: %d\n", eth_index);
						return IPACM_FAILURE;
					}
					if(handle_eth_client_mac_flt_route_rule(IPA_IP_v6, eth_index, it->second->is_blacklist))
					{
						IPACMERR("unbale to add v6 rt rule for index: %d\n", eth_index);
						return IPACM_FAILURE;
					}
					it->second->mac_v6_rt_del_flt_set = false;
				}
				/* add back to the lan2lan offload module */
				eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_ADD, IPA_IP_MAX, mac_addr, NULL, dev_name);
				/* remove from original/copy client list as whitelisted client */
				IPACM_Iface::ipacmcfg->clear_whitelist_mac_add(mac_addr);
				it = macFltListsCopy.erase(it);
			}
		}
		else
		{
			IPACMERR("eth client not found/attached \n");
			it++;
		}
	}
	return IPACM_SUCCESS;
}

/* add_mac_flt_ul_rule add UL rule for mac based filtering on top */
int IPACM_Lan::add_mac_flt_blacklist_rule(uint8_t *mac_addr, ipa_ip_type iptype, uint32_t *flt_rule_hdl)
{
	IPACMDBG_H(" mac_flt_add_rule \n");

	int len =0, idx = 0;
	struct ipa_ioc_add_flt_rule_v2 *pFilteringTable_v2 = NULL;
	struct ipa_flt_rule_add_v2 flt_rule_entry_v2;
	uint8_t mac_a[6] = {0};
	std::array<uint8_t, 6> mac = {0};
	std::map<std::array<uint8_t, 6>, mac_flt_type * >::iterator it;
	int j = 0;

	memcpy(mac_a,mac_addr,IPA_MAC_ADDR_SIZE);
	std::copy(std::begin(mac_a), std::end(mac_a), std::begin(mac));

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered\n");
		return IPACM_FAILURE;
	}

	if(rx_prop->num_rx_props <= 0)
	{
		IPACMDBG_H("No RX property.\n");
		return IPACM_FAILURE;
	}

	len = sizeof(struct ipa_ioc_add_flt_rule_v2);
	pFilteringTable_v2 = (struct ipa_ioc_add_flt_rule_v2*)calloc(1, len);

	if (!pFilteringTable_v2)
	{
		IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_v2 memory...\n");
		return IPACM_FAILURE;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++){   
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		memset(pFilteringTable_v2, 0, len);
		pFilteringTable_v2->rules = (uintptr_t)calloc(1, sizeof(struct ipa_flt_rule_add_v2));
		if (!pFilteringTable_v2->rules) {
			IPACMERR("Failed to allocate ipa_flt_rule_add_v2 memory...\n");
			free(pFilteringTable_v2);
			return IPACM_FAILURE;
		}

		pFilteringTable_v2->commit = 1;
		pFilteringTable_v2->ep = rx_prop->rx[idx].src_pipe;
		pFilteringTable_v2->global = false;
		pFilteringTable_v2->num_rules = 1;
		pFilteringTable_v2->ip = iptype;
		pFilteringTable_v2->flt_rule_size = sizeof(struct ipa_flt_rule_add_v2);

		memset(&flt_rule_entry_v2, 0, sizeof(struct ipa_flt_rule_add_v2)); // Zero All Fields
		flt_rule_entry_v2.at_rear = false;
		flt_rule_entry_v2.flt_rule_hdl = -1;
		flt_rule_entry_v2.status = -1;
		flt_rule_entry_v2.rule.retain_hdr = 1;
		flt_rule_entry_v2.rule.action = IPA_PASS_TO_EXCEPTION;
		flt_rule_entry_v2.rule.hashable = false;

		flt_rule_entry_v2.rule.attrib.attrib_mask |= IPA_FLT_MAC_SRC_ADDR_ETHER_II;
		memset(flt_rule_entry_v2.rule.attrib.src_mac_addr_mask, 0xFF, sizeof(flt_rule_entry_v2.rule.attrib.src_mac_addr_mask));
		memcpy(flt_rule_entry_v2.rule.attrib.src_mac_addr, mac_addr, sizeof(flt_rule_entry_v2.rule.attrib.src_mac_addr));

		memcpy((void *)pFilteringTable_v2->rules, &flt_rule_entry_v2, sizeof(flt_rule_entry_v2));

		if (false == m_filtering.AddFilteringRule_v2(pFilteringTable_v2)) {
			IPACMERR("Error Adding RuleTable to Filtering, aborting...\n");
			free((void *)pFilteringTable_v2->rules);
			free(pFilteringTable_v2);
			return IPACM_FAILURE;
		} else {
			*flt_rule_hdl = ((struct ipa_flt_rule_add_v2 *)pFilteringTable_v2->rules)[0].flt_rule_hdl;
		}
	}

free((void *)pFilteringTable_v2->rules);
free(pFilteringTable_v2);
return IPACM_SUCCESS;
}

int IPACM_Lan::handle_eth_client_mac_flt_route_rule(ipa_ip_type ip_type, int clt_index, bool is_blacklist)
{
	ipacm_event_data_all data;
#ifdef FEATURE_STATIC_POLICY
	uint32_t temp_ipv6[4] = {0};
#endif

	if(is_blacklist)
	{
		if(ip_type == IPA_IP_v4 )
		{
			if(delete_eth_rtrules(clt_index,IPA_IP_v4))
			{
					IPACMERR("unable to delete v4 rt rules for index: %d\n", clt_index);
					return IPACM_FAILURE;
			}
#ifdef FEATURE_STATIC_POLICY
			if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
			{
				if(delete_pdn_dscp_eth_rtrules(IPA_IP_v4, 2, clt_index))
				{
					IPACMERR("unable to delete v4 PDN DSCP rt rules for index: %d\n", clt_index);
					return IPACM_FAILURE;
				}
			}
#endif
		}

		if(ip_type ==  IPA_IP_v6)
		{
			if(delete_eth_rtrules(clt_index,IPA_IP_v6))
			{
					IPACMERR("unable to delete v6 rt rules for index: %d\n", clt_index);
					return IPACM_FAILURE;
			}
#ifdef FEATURE_STATIC_POLICY
			if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
			{
				if(delete_pdn_dscp_eth_rtrules(IPA_IP_v6, 2, clt_index))
				{
					IPACMERR("unable to delete v6 PDN DSCP rt rules for index: %d\n", clt_index);
					return IPACM_FAILURE;
				}
			}
#endif
		}
	}
	else
	{
		if(ip_type == IPA_IP_v4)
		{
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
			if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
			{
				if(handle_eth_client_route_rule(get_client_memptr(eth_client, clt_index)->mac, IPA_IP_v4))
				{
					IPACMERR("unable to add v4 route rules for index: %d\n", clt_index);
					return IPACM_FAILURE;
				}
#ifdef FEATURE_STATIC_POLICY
				if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
				{
					handle_pdn_dscp_eth_client_route_rule(get_client_memptr(eth_client, clt_index)->mac,
						IPA_IP_v4, 0, 0, 0);
				}
#endif
				memset(&data, 0, sizeof(data));
				data.ipv4_addr = get_client_memptr(eth_client, clt_index)->v4_addr,
				data.if_index =  get_client_memptr(eth_client, clt_index)->if_index;
				data.iptype = IPA_IP_v4;
				CtList->HandleNeighIpAddrAddEvt(&data);
			}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
			else
			{
#ifdef IPA_HW_FNR_STATS
				if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
				{
					if(handle_eth_client_route_rule_ext_v2(get_client_memptr(eth_client, clt_index)->mac,IPA_IP_v4,
					get_client_memptr(eth_client, clt_index)->dl_cnt_idx))
					{
						IPACMERR("unable to add v4 route rules for index: %d\n", clt_index);
						return IPACM_FAILURE;
					}
#ifdef FEATURE_STATIC_POLICY
					if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
					{
						if(handle_pdn_dscp_eth_client_route_rule_ext_v2(get_client_memptr(eth_client,
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
					if(handle_eth_client_route_rule_ext(get_client_memptr(eth_client, clt_index)->mac, IPA_IP_v4))
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
				if(handle_eth_client_route_rule(get_client_memptr(eth_client, clt_index)->mac, IPA_IP_v6))
				{
					IPACMERR("unable to add v6 route rules for index: %d\n", clt_index);
					return IPACM_FAILURE;
				}
#ifdef FEATURE_STATIC_POLICY
				if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
				{
					for (auto it = rt_hdl_v6_list[clt_index].begin(); it != rt_hdl_v6_list[clt_index].end(); ++it)
					{
						std::copy(std::begin(it->first), std::end(it->first), std::begin(temp_ipv6));
						handle_pdn_dscp_eth_client_route_rule(get_client_memptr(eth_client, clt_index)->mac,
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
					if(handle_eth_client_route_rule_ext_v2(get_client_memptr(eth_client, clt_index)->mac,IPA_IP_v6,
					get_client_memptr(eth_client, clt_index)->dl_cnt_idx))
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
							if(handle_pdn_dscp_eth_client_route_rule_ext_v2(get_client_memptr(eth_client, clt_index)->mac,
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
					if(handle_eth_client_route_rule_ext(get_client_memptr(eth_client, clt_index)->mac, IPA_IP_v6))
					{
						IPACMERR("unbale to add v4 route rules for index: %d\n", clt_index);
						return IPACM_FAILURE;
					}
				}
			}
#endif
		}
	}
	return IPACM_SUCCESS;
}
int IPACM_Lan::del_mac_flt_blacklist_rule(uint32_t flt_rule_hdl, ipa_ip_type iptype)
{
	if(m_filtering.DeleteFilteringHdls(&flt_rule_hdl, iptype, 1) == false)
	{
		IPACMDBG("mac flt rule deletion failed\n");
		return IPACM_FAILURE;
	}
		return IPACM_SUCCESS;
}

/* del all mac rules for wan client */
void IPACM_Lan::delete_eth_mac_flt_rules()
{
	uint8_t mac_addr[6]= {0};
	int eth_index;
	/* copy current list to avoid concurrency issues*/
	auto macFltListsCopy = IPACM_Iface::ipacmcfg->getMacFltListsCopySafe();
	for (auto it = macFltListsCopy.begin(); it != macFltListsCopy.end(); ++it)
	{
		std::copy(std::begin(it->first), std::end(it->first), std::begin(mac_addr));
		eth_index = get_eth_client_index(mac_addr);
		if(eth_index != IPACM_INVALID_INDEX && it->second->is_blacklist)
		{
			handle_eth_mac_flt_conn_disc(mac_addr, false);
		}
	}
 }

/* handle_wlan_mac_flt_conn_disc handles the scenario when mac flt ioctl is received before the client
	structure is created */
int IPACM_Lan::handle_eth_mac_flt_conn_disc(uint8_t *mac_addr, bool eth_client_conn)
{

	uint8_t mac_a[6];
	std::map<std::array<uint8_t, 6>, mac_flt_type * >::iterator it;
	auto macFltListsCopy = IPACM_Iface::ipacmcfg->getMacFltListsCopySafe();
	int eth_index;
	std::array<uint8_t, 6> mac = {0};

	memcpy(mac_a,mac_addr,IPA_MAC_ADDR_SIZE);
	std::copy(std::begin(mac_a), std::end(mac_a), std::begin(mac));

	it = IPACM_Iface::ipacmcfg->mac_flt_lists.find(mac);
	eth_index = get_eth_client_index(mac_addr);

	if(eth_index != IPACM_INVALID_INDEX)
	{
		if(eth_client_conn)
		{
			/* install UL and rt rules */
			if(get_client_memptr(eth_client, eth_index)->ipv4_set && !it->second->mac_v4_rt_del_flt_set)
			{
				if(add_mac_flt_blacklist_rule(mac_addr,IPA_IP_v4, &(it->second->mac_v4_flt_rule_hdl)))
				{
					IPACMERR("unable to add mac flt blacklist v4 UL rule for index: %d\n", eth_index);
					return IPACM_FAILURE;
				}
				CtList->HandleNeighIpAddrDelEvt(get_client_memptr(eth_client, eth_index)->v4_addr);
				if(handle_eth_client_mac_flt_route_rule(IPA_IP_v4, eth_index, it->second->is_blacklist))
				{
					IPACMERR("unable to del v4 rt rule for index: %d\n", eth_index);
					return IPACM_FAILURE;
				}
				it->second->mac_v4_rt_del_flt_set = true;
			}
			if (get_client_memptr(eth_client, eth_index)->ipv6_set && !it->second->mac_v6_rt_del_flt_set)
			{
				if(add_mac_flt_blacklist_rule(mac_addr,IPA_IP_v6, &(it->second->mac_v6_flt_rule_hdl)))
				{
					IPACMERR("unable to add mac flt blacklist v6 UL rule for index: %d\n", eth_index);
					return IPACM_FAILURE;
				}
				if(handle_eth_client_mac_flt_route_rule(IPA_IP_v6, eth_index, it->second->is_blacklist))
				{
					IPACMERR("unable to del v6 rt rule for index: %d\n", eth_index);
					return IPACM_FAILURE;
				}
				it->second->mac_v6_rt_del_flt_set = true;
			}
			it->second->current_blocked = true;
		}
		else
		{
			if(it->second->mac_v4_rt_del_flt_set)
			{
				if(del_mac_flt_blacklist_rule(it->second->mac_v4_flt_rule_hdl,  IPA_IP_v4))
				{
					IPACMERR("unable to del mac flt blacklist v4 UL rule for index: %d\n", eth_index);
					return IPACM_FAILURE;
				}
				it->second->mac_v4_rt_del_flt_set = false;
			}
			if(it->second->mac_v6_rt_del_flt_set)
			{
				if(del_mac_flt_blacklist_rule(it->second->mac_v4_flt_rule_hdl,  IPA_IP_v6))
				{
					IPACMERR("unable to del mac flt blacklist v6 UL rule for index: %d\n", eth_index);
					return IPACM_FAILURE;
				}
				it->second->mac_v6_rt_del_flt_set = false;
			}
			it->second->current_blocked = false;
		}
		/* In case of client blackklisted, update config mac list with copy mac flt list value */
		IPACM_Iface::ipacmcfg->update_mac_flt_lists(mac_addr, it->second);
	}
	else
	{
		IPACMERR("eth client not found/attached \n");
		return IPACM_FAILURE;
	}
	return IPACM_SUCCESS;
}

#ifdef FEATURE_L2TP
int IPACM_Lan::handle_l2tp_neigh(ipacm_event_data_all *data)
{
	if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
	{
		/* Add corresponding ipa_rm_resource_name of TX-endpoint up before IPV6 RT-rule set */
		IPACMDBG_H("dev %s add producer dependency\n", dev_name);
		if(tx_prop != NULL)
		{
			IPACMDBG_H("add rm dependency for L2TP interface.\n");
			IPACM_Iface::ipacmcfg->AddRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe], false);
		}
	}
	if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E) &&
		data->iptype == IPA_IP_v4)
	{
		int index;

		index = get_eth_client_index(data->mac_addr);
		if(index != IPACM_INVALID_INDEX)
		{
			IPACMERR("eth client is found/attached already with index %d \n", index);
			return IPACM_FAILURE;
		}
		if(num_eth_client >= IPA_MAX_NUM_ETH_CLIENTS)
		{
			IPACMERR("Reached maximum number(%d) of eth clients\n", IPA_MAX_NUM_ETH_CLIENTS);
			return IPACM_FAILURE;
		}

		/* Add NAT rules after ipv4 RT rules are set */
		CtList->HandleNeighIpAddrAddEvt(data);

		index = num_eth_client;
		if(install_l2tp_dl_rules(data, index) != IPACM_SUCCESS)
		{
			IPACMERR("Failed to add l2tp dl rules.\n");
			return IPACM_FAILURE;
		}

		if(install_l2tp_ul_rules(data, index) != IPACM_SUCCESS)
		{
			IPACMERR("Failed to add l2tp ul rules.\n");
			/* delete dl rules */
			m_routing.DeleteRoutingHdl(get_client_memptr(eth_client, index)->dl_first_pass_rt_rule_hdl, IPA_IP_v4);
			m_routing.DeleteRoutingHdl(get_client_memptr(eth_client, index)->dl_second_pass_rt_rule_hdl, IPA_IP_v6);
			m_header.DeleteHeaderProcCtx(get_client_memptr(eth_client, index)->dl_first_pass_hdr_proc_ctx_hdl);
			m_header.DeleteHeaderHdl(get_client_memptr(eth_client, index)->dl_first_pass_hdr_hdl);
			m_header.DeleteHeaderHdl(get_client_memptr(eth_client, index)->dl_second_pass_hdr_hdl);
			return IPACM_FAILURE;
		}
		num_eth_client++;
	}
#ifdef FEATURE_L2TP
	if(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP)
	{
		eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_ADD,
			IPA_IP_MAX, data->mac_addr, NULL, data->iface_name);
	}
#endif
	return 0;
}
#endif


#ifdef FEATURE_SOCKSv5
/* add socksv5 flt rule */
int IPACM_Lan::add_socksv5_flt_rule(ipacm_event_connection *data_event_conn)
{
	int len;
	int fd_ipa = 0;
	struct ipa_flt_rule_add flt_rule_entry;
	struct ipa_ioc_add_flt_rule_after *pFilteringTable = NULL;
	int ret = IPACM_SUCCESS;

	if (rx_prop == NULL || tx_prop == NULL)
	{
		IPACMDBG_H("No rx or tx properties registered for iface %s\n", dev_name);
		return IPACM_FAILURE;
	}

	len = sizeof(struct ipa_ioc_add_flt_rule_after) + sizeof(struct ipa_flt_rule_add);
	pFilteringTable = (struct ipa_ioc_add_flt_rule_after*)malloc(len);
	if (!pFilteringTable)
	{
		IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
		return IPACM_FAILURE;
	}
	memset(pFilteringTable, 0, len);

	pFilteringTable->commit = 1;
	pFilteringTable->ep = rx_prop->rx[0].src_pipe;
	pFilteringTable->ip = IPA_IP_v6;
	pFilteringTable->num_rules = 1;
	/* since socksv5 is tcp, should be compatible to l2tp over udp*/

	pFilteringTable->add_after_hdl = eth_bridge_flt_rule_offset[0][IPA_IP_v6];

	fd_ipa = open(IPA_DEVICE_NAME, O_RDWR);
	if(fd_ipa == 0)
	{
		IPACMERR("Failed to open %s\n",IPA_DEVICE_NAME);
		ret = IPACM_FAILURE;
		goto end;
	}

	memset(&flt_rule_entry, 0, sizeof(flt_rule_entry));
	flt_rule_entry.at_rear = 1;
	flt_rule_entry.rule.action = IPA_PASS_TO_SRC_NAT;
	flt_rule_entry.rule.hashable = true;
	memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[0].attrib, sizeof(flt_rule_entry.rule.attrib));

	/* Match src/dst ipv6 */
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = data_event_conn->dst_ipv6_addr[0];
	flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = data_event_conn->dst_ipv6_addr[1];
	flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = data_event_conn->dst_ipv6_addr[2];
	flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = data_event_conn->dst_ipv6_addr[3];
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;

	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_NEXT_HDR;
	flt_rule_entry.rule.attrib.u.v6.next_hdr = (uint8_t)IPACM_FIREWALL_IPPROTO_TCP;

	/* get rt_tbl_v6 handle */
	if (false == m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_v6))
	{
		IPACMERR("m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_v6=0x%p) Failed.\n", &IPACM_Iface::ipacmcfg->rt_tbl_v6);
		ret = IPACM_FAILURE;
		goto end;
	}
	flt_rule_entry.rule.rt_tbl_hdl = IPACM_Iface::ipacmcfg->rt_tbl_v6.hdl;
	IPACMDBG_H("rt_tbl_v6.hdl %d\n", flt_rule_entry.rule.rt_tbl_hdl);

	memcpy(&(pFilteringTable->rules[0]), &flt_rule_entry, sizeof(flt_rule_entry));
	if(m_filtering.AddFilteringRuleAfter(pFilteringTable) == false)
	{
		IPACMERR("Failed to add client filtering rules.\n");
		ret = IPACM_FAILURE;
		goto end;
	}
	socksv5_flt_hdl_v6 = pFilteringTable->rules[0].flt_rule_hdl;

end:
	if (pFilteringTable)
		free(pFilteringTable);
	if (fd_ipa)
		close(fd_ipa);
	return ret;
}

/* del socksv5 flt rule */
int IPACM_Lan::del_socksv5_flt_rule(void)
{
	if(socksv5_flt_hdl_v6 != 0)
	{
		if(m_filtering.DeleteFilteringHdls(&socksv5_flt_hdl_v6, IPA_IP_v6, 1) == false)
		{
			return IPACM_FAILURE;
		}
	}
	socksv5_flt_hdl_v6 = 0;
	return IPACM_SUCCESS;
}
#endif


int IPACM_Lan::del_ul_flt_rules(enum ipa_ip_type iptype)
{
	int idx = 0;
	int j = 0;

	IPACMDBG_H("Deleting modem UL flt rules for iptype(%d)\n", iptype);

	if (rx_prop == NULL)
	{
		IPACMERR("Rx prop is NULL, return\n");
		return IPACM_SUCCESS;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++){	
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		if (iptype == IPA_IP_v4) {
			if (num_wan_ul_fl_rule_v4[j] == 0) {
				IPACMERR("No modem UL rules were installed, return...\n");
				modem_ul_v4_set[j] = false;
				return IPACM_SUCCESS;
			}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
			if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
			{
				if (num_wan_ul_fl_rule_v4[j] > MAX_WAN_UL_FILTER_RULES) {
					IPACMERR("number of wan_ul_fl_rule_v4 (%d) > MAX_WAN_UL_FILTER_RULES (%d), aborting...\n", num_wan_ul_fl_rule_v4[j], MAX_WAN_UL_FILTER_RULES);
					return IPACM_FAILURE;
				}

				if (m_filtering.DeleteFilteringHdls(wan_ul_fl_rule_hdl_v4[j],
													IPA_IP_v4, num_wan_ul_fl_rule_v4[j]) == false) {
					IPACMERR("Error Deleting RuleTable(1) to Filtering, aborting...\n");
					return IPACM_FAILURE;
				}
				IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, num_wan_ul_fl_rule_v4[j]);

				memset(wan_ul_fl_rule_hdl_v4[j], 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
				memset(xlat_ctx.ul_rule_id_hdl_map[j], 0, MAX_WAN_UL_FILTER_RULES * sizeof(rule_id_hdl_map));
				num_wan_ul_fl_rule_v4[j] = 0;
			}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
			else {
				IPACMDBG_H("deleting uplink filter rule\n");
				if (delete_uplink_filter_rule(IPA_IP_v4) == IPACM_FAILURE) {
					IPACMERR("Error delete_uplink_filter_rule, aborting...\n");
					return IPACM_FAILURE;
				}
				num_wan_ul_fl_rule_v4[j] = 0;
			}
#endif
			modem_ul_v4_set[j] = false;
		} else {

#ifdef FEATURE_IPV6_NAT
			if(IPACM_Iface::ipacmcfg->ipv6_nat_enable)
				delete_ipv6_nat_ula_prefix_flt_rule();
#endif

			if (num_wan_ul_fl_rule_v6[j] == 0) {
				IPACMERR("No modem UL rules were installed, return...\n");
				modem_ul_v6_set[j] = false;
				return IPACM_SUCCESS;
			}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
			if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
			{
#ifndef IPA_V6_UL_WL_FIREWALL_HANDLE
				if (num_wan_ul_fl_rule_v6[j] > MAX_WAN_UL_FILTER_RULES)
#else
				if (num_wan_ul_fl_rule_v6[j] > IPACM_MAX_V6_UL_WL_FIREWALL_ENTRIES)
#endif
					{
						IPACMERR(" the number of rules (%d) are bigger than array (%d), aborting...\n", num_wan_ul_fl_rule_v6[j], MAX_WAN_UL_FILTER_RULES);
						return IPACM_FAILURE;
					}

#ifdef FEATURE_L2TP
				if (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable != IPACM_L2TP_E2E)
#endif
				{
					/* When OCU is enabled, no need to delete modem UL IPv6 rules. */
					if (m_filtering.DeleteFilteringHdls(wan_ul_fl_rule_hdl_v6[j],
														IPA_IP_v6, num_wan_ul_fl_rule_v6[j]) == false) {
						IPACMERR("Error Deleting RuleTable(1) to Filtering, aborting...\n");
						return IPACM_FAILURE;
					}
					IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, num_wan_ul_fl_rule_v6[j]);
#ifndef IPA_V6_UL_WL_FIREWALL_HANDLE
					memset(wan_ul_fl_rule_hdl_v6[j], 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
#else
					memset(wan_ul_fl_rule_hdl_v6[j], 0, IPACM_MAX_V6_UL_WL_FIREWALL_ENTRIES * sizeof(uint32_t));
#endif
					num_wan_ul_fl_rule_v6[j] = 0;
				}
			}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
else {
				IPACMDBG_H("deleting uplink filter rule v6\n");
				if (delete_uplink_filter_rule(IPA_IP_v6) == IPACM_FAILURE) {
					IPACMERR("Error delete_uplink_filter_rule, aborting...\n");
					return IPACM_FAILURE;
				}
				num_wan_ul_fl_rule_v6[j] = 0;
			}
#endif
			modem_ul_v6_set[j] = false;
		}
	}

	return IPACM_SUCCESS;
}

#ifdef FEATURE_VLAN_MPDN
int IPACM_Lan::handle_vlan_neighbor(ipacm_event_data_all *data)
{
	ipacm_event_new_neigh_vlan *data_vlan;
	uint16_t vlan_id = 0;
	ipacm_event_data_all data_all;
	std::list <ipacm_event_data_all>::iterator it;
	ipacm_bridge *bridge;
	int skip_nat_set = 0;
	IPACMDBG_H("\n");

	if (IPACM_Iface::ipacmcfg->get_vlan_id(data->iface_name, &vlan_id))
	{
		if(!IPACM_Iface::ipacmcfg->is_added_vlan_iface(data->iface_name))
		{
			IPACMDBG_H("ignoring neighbor of not added IF %s \n", data->iface_name);
			return 0;
		}
		IPACMERR("failed getting vlan ID of iface %s \n", data->iface_name);
		return IPACM_FAILURE;
	}

	/* get bridge from vlan id */
	bridge = IPACM_Iface::ipacmcfg->get_vlan_bridge_from_vid(vlan_id);
	if (!bridge)
	{
		IPACMDBG_H("bridge is NULL with vlan (%s) vid (%d), ignoring!\n", data->iface_name, vlan_id);
		return IPACM_FAILURE;
	}

	IPACMDBG_H("VLAN IF %s got client, vlan id %d \n", data->iface_name, vlan_id);
	data_vlan = (ipacm_event_new_neigh_vlan *)data;

	if((data_vlan->data_all.iptype != ip_type) && (ip_type != IPA_IP_MAX))
	{
		IPACMERR("inconsistent iptype. iptype = %d, instance ip_type = %d\n", data_vlan->data_all.iptype,
			ip_type);
		return IPACM_FAILURE;
	}

	if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable) {
		if(data_vlan->data_all.iptype == IPA_IP_v6)
		{
			if(IPACM_Wan::is_global_ipv6_addr(data_vlan->data_all.ipv6_addr))
			{
				if (!IPACM_Wan::isWan_active_with_prefix(data_vlan->data_all.ipv6_addr) &&
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
				IPACM_Iface::ipacmcfg->add_vlan_ipv6_prefix(data_vlan->data_all.ipv6_addr, ipa_if_num, vlan_id);
			}

		}
		else if(data_vlan->data_all.iptype == IPA_IP_v4)
		{
			/*	This is to avoid installing IPA private subnet Filter rules in case of
				IPPT without NAT scenario to avoid packets taking SW path because we
				are installing private subnet rules with public IP assigned to bridge
				since bridge has no longer the private IP assigned. */

			for (int i = 0; i < MAX_NUM_IP_PASS_MPDN; i++)
			{
				if(IPACM_Iface::ipacmcfg->ip_pass_mpdn_table[i].valid_entry == true &&
					IPACM_Iface::ipacmcfg->ip_pass_mpdn_table[i].ip_pass_skip_nat == 1)
				{
					skip_nat_set = 1;
					break;
				}
			}
			if(!skip_nat_set)
			{
				add_vlan_private_subnet(bridge);
			}
		}
		skip_nat_set = 0;
		/* first construc ETH full header */
		handle_eth_hdr_init(data->mac_addr, bridge, vlan_id, true);
	}
	else
	{
		/* first construc ETH full header */
		handle_eth_hdr_init(data->mac_addr, NULL, vlan_id, true);
	}

	IPACMDBG_H("construct ETH header and route rules \n");
	/* Associate with IP and construct RT-rule */
	if(handle_eth_client_ipaddr(data) == IPACM_FAILURE)
	{
		IPACMERR("Failed handle_eth_client_ipaddr, continue\n");
		return IPACM_FAILURE;
	}

	/* TODO for VLAN: Need to return success above and handle the ext router info here */

	handle_eth_client_route_rule(data->mac_addr, data->iptype, vlan_id);
	install_all_qos_route_rule(data->mac_addr, vlan_id, data->ipv6_addr);

	if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable) {
		/* Add NAT rules after ipv4 RT rules are set */
		HandleNeighIpAddrAddEvt(data);

		/* Special handling for VLAN clients in IP passthrough mode.
		 * simillar to IPA_HANDLE_WAN_VLAN_PDN_UP.
		 */
		if ((data->iptype == IPA_IP_v4) &&
			IPACM_Iface::ipacmcfg->is_ip_pass_enabled(device_type,
					data->mac_addr, vlan_id))
		{
			/* Special handling for IPACM_CLIENT_DEVICE_TYPE_USB*/
			if ((device_type != IPACM_CLIENT_DEVICE_TYPE_USB) ||
			!IPACM_Wan::check_client_ipv4_with_pdn_ipv4(data->ipv4_addr, vlan_id))
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
		eth_bridge_post_event(IPA_ETH_BRIDGE_CLIENT_ADD, IPA_IP_MAX, data->mac_addr, NULL, data->iface_name, vlan_id);
	}

	return IPACM_SUCCESS;
}

bool IPACM_Lan::is_vlan_IF(uint16_t vlan_id)
{
	char vlan_iface_name[IPA_RESOURCE_NAME_MAX];
	char vlan_suffix[6];

#ifdef FEATURE_SOCKSv5
	/* handle socksv5 MPDN logic */
	if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == false)
	{
		IPACMDBG_H("MPDN is disabled, return true\n");
		return true;
	}
#endif //FEATURE_SOCKSv5

	/* concatenate the vlan id to the IF name and check iface exists */
	snprintf(vlan_suffix, sizeof(vlan_suffix), ".%d", vlan_id);
	strlcpy(vlan_iface_name, dev_name, sizeof(vlan_iface_name));
	if(strlcat(vlan_iface_name, vlan_suffix, sizeof(vlan_iface_name)) > IPA_RESOURCE_NAME_MAX)
	{
		IPACMERR("vlan IF name construction failed exceed length (%zu)\n", strlen(vlan_iface_name));
		return false;
	}

	if(IPACM_Iface::ipacmcfg->is_added_vlan_iface(vlan_iface_name))
	{
		IPACMDBG_H("found VLAN IF named %s\n", vlan_iface_name);
		return true;
	}
	else
	{
		IPACMDBG_H("couldn't find VLAN IF named %s\n", vlan_iface_name);
	}

	return false;
}

int IPACM_Lan::check_vlan_PDNUp(enum ipa_ip_type iptype)
{
	int i = 0;
	ipacm_event_vlan_pdn vlan_data;
	uint16_t Ids[IPA_MAX_NUM_OFFLOAD_VLANS];
	uint8_t cnt = 0;

	if(IPACM_Iface::ipacmcfg->get_iface_vlan_ids(dev_name, Ids))
	{
		IPACMERR("failed getting vlan ids for iface %s\n", dev_name);
		return IPACM_FAILURE;
	}

	if(iptype == IPA_IP_v4)
	{
		for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
		{
			uint8_t mux_id;

			if(Ids[i] != 0)
			{
				if(IPACM_Wan::GetMuxByVid(Ids[i], &mux_id, iptype))
				{
					IPACMDBG_H("no v4 vlan up PDN for Id %d\n", Ids[i]);
					continue;
				}

				/* create event data and call the handler */
				memset(&vlan_data, 0, sizeof(vlan_data));
				vlan_data.iptype = iptype;
				vlan_data.mux_id = mux_id;
				vlan_data.VlanID = Ids[i];
				if (IPACM_Wan::is_xlat_by_vid(Ids[i]))
					vlan_data.is_xlat = true;

				IPACMDBG_H("Push ipv4 handle_vlan_pdn_up mux:%d, VlanID:%d is_xlat: %d\n",
					vlan_data.mux_id, vlan_data.VlanID, vlan_data.is_xlat);
				if(handle_vlan_pdn_up(&vlan_data))
				{
					IPACMERR("failed handling v4 VLAN up for VID %d, dev %s\n",
						Ids[i],
						dev_name);
				}
				else
				{
					IPACMDBG_H("handled v4 vlan pdn up for VID %d, dev %s\n",
						Ids[i],
						dev_name);
				}

				cnt++;
				if(cnt == IPA_MAX_NUM_HW_PDNS)
				{
					IPACMDBG_H("reached max num of v4 offload PDNs, not sending more events\n");
					break;
				}
			}
		}
	}
	else if(iptype == IPA_IP_v6)
	{
#ifdef FEATURE_IPv6CT_DISABLED
		bool firewall_updated = false;
#endif
		for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
		{
			uint8_t mux_id;

			if(Ids[i] != 0)
			{
				if(IPACM_Wan::GetMuxByVid(Ids[i], &mux_id, iptype))
				{
					IPACMDBG_H("no v6 vlan up PDN for Id %d\n", Ids[i]);
					continue;
				}
#ifdef FEATURE_IPv6CT_DISABLED
				if(!firewall_updated)
				{
					configure_v6_ul_firewall();
					firewall_updated = true;
				}
#endif
				modify_ipv6_prefix_flt_rule();

				/* create event data and call the handler */
				memset(&vlan_data, 0, sizeof(vlan_data));
				vlan_data.iptype = iptype;
				vlan_data.mux_id = mux_id;
				vlan_data.VlanID = Ids[i];
				if (IPACM_Wan::is_xlat_by_vid(Ids[i]))
					vlan_data.is_xlat = true;

				IPACMDBG_H("Push ipv6 handle_vlan_pdn_up mux:%d, VlanID:%d is_xlat: %d\n",
					vlan_data.mux_id, vlan_data.VlanID, vlan_data.is_xlat);

				if(handle_vlan_pdn_up(&vlan_data))
				{
					IPACMERR("failed handling v6 VLAN up for VID %d, dev %s\n",
						Ids[i],
						dev_name);
				}
				else
				{
					IPACMDBG_H("handled v6 vlan pdn up for VID %d, dev %s\n",
						Ids[i],
						dev_name);
				}

				cnt++;
				if(cnt == IPA_MAX_NUM_HW_PDNS)
				{
					IPACMDBG_H("reached max num of v6 offload PDNs, not sending more events\n");
					break;
				}
			}
		}
	}
	else
	{
		IPACMERR("invalid iptype\n");
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

int IPACM_Lan::handle_vlan_pdn_up(ipacm_event_vlan_pdn *data, bool set_mux)
{
	int ret = IPACM_SUCCESS;
#ifdef FEATURE_STATIC_POLICY
	int if_index;
#endif

	if(is_vlan_offload_disabled)
	{
		/* only cache mux id, once backhaul changes back to LTE we will install UL rules*/
		set_mux_up(data->mux_id, data->iptype, data->VlanID);
		return IPACM_SUCCESS;
	}

	/* check only add static UL filter rule once */
	if(data->iptype == IPA_IP_v6)
	{
		IPACMDBG_H("IPA_IP_v6 num_dft_rt_v6 %d mux_id: %d modem_ul_v6_set: %d\n", num_dft_rt_v6, data->mux_id, modem_ul_v6_set[0]);
		if(is_mux_up(data->mux_id, data->iptype, data->VlanID))
		{
			IPACMERR("mux id %d is already up\n", data->mux_id);
			return IPACM_FAILURE;
		}

		/*install MTU rule */
		modify_ipv6_prefix_flt_rule();

		/* for the first PDN install UL filtering rules */
		if(num_dft_rt_v6 == 1 && modem_ul_v6_set[0] == FALSE)
		{

#ifdef FEATURE_IPV6_NAT
			if (IPACM_Iface::ipacmcfg->ipv6_nat_enable)
			{
				/* construct 1st pass v6NAT flt-rule */
				add_ipv6_nat_ula_prefix_flt_rule();
			}
#endif
			ret = handle_uplink_filter_rule(IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6), data->iptype, data->mux_id, false);
			modem_ul_v6_set[0] = !!num_wan_ul_fl_rule_v6[0];
			if (sIface)
				modem_ul_v6_set[1] = !!num_wan_ul_fl_rule_v6[1];
		}
		/* for the next PDNs only notify modem about new MUX IDs */
		else
		{
			ret = handle_uplink_filter_rule(IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6), data->iptype, data->mux_id, true);
		}
	}
	else
	{
		IPACMDBG_H("IPA_IP_v4 mux_id: %d, modem_ul_v4_set %d\n", data->mux_id, modem_ul_v4_set[0]);
		if(is_mux_up(data->mux_id, data->iptype, data->VlanID))
		{
			IPACMERR("mux id %d is already up for VID %d\n", data->mux_id, data->VlanID);
			return IPACM_FAILURE;
		}

		/*install MTU rule */
		modify_private_subnet();

		/* for the first PDN install UL filtering rules */
		if(modem_ul_v4_set[0] == false)
		{
			ret = handle_uplink_filter_rule(IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4), data->iptype, data->mux_id, false, true);
			modem_ul_v4_set[0] = !!num_wan_ul_fl_rule_v4[0];
			if (sIface)
				modem_ul_v4_set[1] = !!num_wan_ul_fl_rule_v4[1];
		}
		/* for the next PDNs only notify modem about new MUX IDs */
		else
		{
			ret = handle_uplink_filter_rule(IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4), data->iptype, data->mux_id, true, true);
		}

		if (data->is_xlat)
		{
			if (get_pdn_xlat_ctx(data->mux_id, data->VlanID) == IPACM_FAILURE)
			{
				add_pdn_xlat_ctx(data->mux_id, data->VlanID);
				if (handle_mpdn_ul_xlat_filter_rule(IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4),
							data->iptype, data->mux_id, data->VlanID))
				{
					remove_pdn_xlat_ctx(data->mux_id);
					IPACMDBG_H("Failed to install xlat rules\n");
					return IPACM_FAILURE;
				}
			}
			else
				IPACMDBG_H("XLAT filter rules already set for PDN : %d, vlan : %d\n",data->mux_id, data->VlanID);
		}
	}

	if (ret == IPACM_SUCCESS)
	{
		if(set_mux && set_mux_up(data->mux_id, data->iptype, data->VlanID))
		{
			IPACMERR("couldn't set mux up for %d, iptype %d\n", data->mux_id, data->iptype);
			return IPACM_FAILURE;
		}
	}
	else
	{
		IPACMERR("Failed installing UL rules. Don't set mux up for mux id %d\n", data->mux_id);
		if(data->iptype == IPA_IP_v6)
		{

			modem_ul_v6_set[0] = false;
		}
		else
			modem_ul_v4_set[0] = false;
	}
	IPACMDBG_H("ret: %d, modem_ul_v4_set: %d, modem_ul_v6_set: %d\n", ret, modem_ul_v4_set[0], modem_ul_v6_set[0]);

	return ret;
}

int IPACM_Lan::handle_vlan_pdn_down(ipacm_event_vlan_pdn *data)
{
	bool notif_only = false;
	int xlat_pdn_ctx_id;

	if(data->iptype == IPA_IP_v4)
	{
		/* if we still have vlan pdns up notify only */
		if(set_mux_down(data->mux_id, data->iptype))
			return IPACM_FAILURE;

		if(is_any_mux_up(data->iptype) == true)
			notif_only = true;

#ifdef FEATURE_SOCKSv5
		/* socksv5 case */
		if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == false &&
			(IPACM_Wan::isWanUP(ipa_if_num) || IPACM_Wan::isVlanWanUP()))
			notif_only = true;
#endif //FEATURE_SOCKSv5
		xlat_pdn_ctx_id = get_pdn_xlat_ctx(data->mux_id, 0);
		if (xlat_pdn_ctx_id != -1)
		{
			delete_mdpn_ul_xlat_filter_rule(data->mux_id);
			remove_pdn_xlat_ctx(data->mux_id);
		}

		/* Clean up MTU rule */
		modify_private_subnet();

		if(!notif_only)
		{
			if(del_ul_flt_rules(IPA_IP_v4))
			{
				return IPACM_FAILURE;
			}
		}

		if(notify_flt_removed(data->mux_id))
		{
			return IPACM_FAILURE;
		}
	}
	else if (data->iptype == IPA_IP_v6)
	{
		/* if we still have vlan pdns up notify only */
		if(set_mux_down(data->mux_id, data->iptype))
			return IPACM_FAILURE;

		if(is_any_mux_up(data->iptype) == true)
			notif_only = true;

#ifdef FEATURE_SOCKSv5
		/* socksv5 case */
		if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == false &&
			(IPACM_Wan::isWanUP_V6(ipa_if_num) || IPACM_Wan::isVlanWanUP_V6()))
			notif_only = true;
#endif //FEATURE_SOCKSv5

		/* prefixes list updated, install rules accordingly */
		modify_ipv6_prefix_flt_rule();

		if(!notif_only)
		{
			/* reset usb-client ipv6 rt-rules */
			handle_lan_client_reset_rt(IPA_IP_v6);

			if(del_ul_flt_rules(IPA_IP_v6))
			{
				return IPACM_FAILURE;
			}
		}

		if(notify_flt_removed(data->mux_id))
			return IPACM_FAILURE;
	}
	/* v4 and v6 were up and now down (rmnet_dataX is down)*/
	else
	{
		bool notif_only_v6 = false;

		/* if we still have vlan pdns up notify only */
		if(set_mux_down(data->mux_id, IPA_IP_v4))
			return IPACM_FAILURE;

		if(is_any_mux_up(IPA_IP_v4) == true)
			notif_only = true;

		/* if we still have vlan pdns up notify only */
		if(set_mux_down(data->mux_id, IPA_IP_v6))
			return IPACM_FAILURE;

		if(is_any_mux_up(IPA_IP_v6) == true)
			notif_only_v6 = true;

#ifdef FEATURE_SOCKSv5
		/* socksv5 case */
		if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == false &&
			((IPACM_Wan::isWanUP(ipa_if_num) || IPACM_Wan::isVlanWanUP()) ||
			(IPACM_Wan::isWanUP(ipa_if_num) || IPACM_Wan::isVlanWanUP())))
			notif_only = true;
#endif //FEATURE_SOCKSv5

		/* prefixes list updated, install rules accordingly */
		modify_ipv6_prefix_flt_rule();

		xlat_pdn_ctx_id = get_pdn_xlat_ctx(data->mux_id, 0);
		if (xlat_pdn_ctx_id != -1)
		{
			delete_mdpn_ul_xlat_filter_rule(data->mux_id);
			remove_pdn_xlat_ctx(data->mux_id);
		}

		/* Clean up MTU rule */
		modify_private_subnet();

		if(!notif_only)
		{
			if(del_ul_flt_rules(IPA_IP_v4))
			{
				return IPACM_FAILURE;
			}
		}

		/* need to notify once for v4 */
		if(notify_flt_removed(data->mux_id))
			return IPACM_FAILURE;

		if(!notif_only_v6)
		{
			/* reset usb-client ipv6 rt-rules */
			handle_lan_client_reset_rt(IPA_IP_v6);

			if(del_ul_flt_rules(IPA_IP_v6))
			{
				return IPACM_FAILURE;
			}
		}

		/* need to notify once for v6 */
		if(notify_flt_removed(data->mux_id))
			return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}
#endif

int IPACM_Lan::handle_del_ipv6_addr(ipacm_event_data_all *data)
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
		IPACMDBG_H("handling vlan ETH client del v6 ip address for iface %s\n", data->iface_name);
		if(IPACM_Iface::ipacmcfg->get_vlan_id(data->iface_name, &vlan_id))
		{
			IPACMERR("failed getting vlan id for iface %s\n", data->iface_name);
			return IPACM_FAILURE;
		}
	}
#endif

	clnt_indx = get_eth_client_index(data->mac_addr, vlan_id);
	if (clnt_indx == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached with MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
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
			delete_client_qos_rule(data->mac_addr, vlan_id, IPA_IP_v6, data->ipv6_addr);
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
			get_client_memptr(eth_client, clnt_indx)->ipv6_set--;
			get_client_memptr(eth_client, clnt_indx)->route_rule_set_v6--;
			IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6--;
			IPACMDBG_H("update ipa_num_clients_ipv6 = %d\n", IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
		} /* found ipv6 on this client */
	}
	return IPACM_SUCCESS;
}

int IPACM_Lan::notify_flt_removed(uint8_t mux_id)
{
	ipa_fltr_installed_notif_req_msg_v01 flt_index;
	int fd, idx = 0;
	int j = 0;

	fd = open(IPA_DEVICE_NAME, O_RDWR);
	if(0 == fd)
	{
		IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	if (rx_prop == NULL)
	{
		IPACMERR("Rx prop is NULL, return\n");
		return IPACM_SUCCESS;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++){	
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		memset(&flt_index, 0, sizeof(flt_index));
		flt_index.source_pipe_index = ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, rx_prop->rx[idx].src_pipe);
		flt_index.install_status = IPA_QMI_RESULT_SUCCESS_V01;
#ifndef FEATURE_IPA_V3
		flt_index.filter_index_list_len = 0;
#else /* defined (FEATURE_IPA_V3) */
		flt_index.rule_id_valid = 1;
		flt_index.rule_id_len = 0;
#endif
		flt_index.embedded_pipe_index_valid = 1;
		flt_index.embedded_pipe_index = ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, IPA_CLIENT_APPS_LAN_WAN_PROD);
		flt_index.retain_header_valid = 1;
		flt_index.retain_header = 0;
		flt_index.embedded_call_mux_id_valid = 1;
		flt_index.embedded_call_mux_id = mux_id;

		if (false == m_filtering.SendFilteringRuleIndex(&flt_index)) {
			IPACMERR("Error sending filtering rule index, aborting...\n");
			close(fd);
			return IPACM_FAILURE;
		}
	}

	close(fd);
	return IPACM_SUCCESS;
}

/* delete filter rule for wan_down event for IPv4*/
int IPACM_Lan::handle_wan_down(bool is_sta_mode)
{
	int idx = 0;
	int j;

	if (rx_prop == NULL)
	{
		IPACMERR("Rx prop is NULL, return\n");
		return IPACM_SUCCESS;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++){	
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		if (is_sta_mode == false) {
			if (del_ul_flt_rules(IPA_IP_v4)) return IPACM_FAILURE;

			if (notify_flt_removed(IPACM_Iface::ipacmcfg->GetQmapId())) return IPACM_FAILURE;
		} else {
			if (m_filtering.DeleteFilteringHdls(&lan_wan_fl_rule_hdl[j][0], IPA_IP_v4, 1) == false) {
				IPACMERR("Error Adding RuleTable(1) to Filtering, aborting...\n");
				return IPACM_FAILURE;
			}
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, 1);
		}
	}
	/* clean MTU rules if needed */
	modify_private_subnet();

#ifdef FEATURE_IPA_IPSEC
	return handleIpsecUlFltDelAll(IPA_IP_v4);
#else
	return IPACM_SUCCESS;
#endif
}

/* handle new_address event*/
int IPACM_Lan::handle_addr_evt(ipacm_event_data_addr *data)
{
	struct ipa_ioc_add_rt_rule *rt_rule;
	struct ipa_rt_rule_add *rt_rule_entry;
	const int NUM_RULES = 1;
	int num_ipv6_addr;
	int res = IPACM_SUCCESS;
	int j = 0;
	ipacm_cmd_q_data evt_data;
	ipacm_event_data_fid *data_fid = NULL;

	IPACMDBG_H("set route/filter rule ip-type: %d \n", data->iptype);
	if (rx_prop == NULL)
	{
		IPACMERR("rx/tx properties empty...exit\n");
		return IPACM_FAILURE;
	}

/* Add private subnet*/
#ifdef FEATURE_IPA_ANDROID
	if (data->iptype == IPA_IP_v4)
	{
		IPACMDBG_H("current IPACM private subnet_addr number(%d)\n", IPACM_Iface::ipacmcfg->ipa_num_private_subnet);
		if_ipv4_subnet = (data->ipv4_addr >> 8) << 8;
		IPACMDBG_H(" Add IPACM private subnet_addr as: 0x%x \n", if_ipv4_subnet);
		if(IPACM_Iface::ipacmcfg->AddPrivateSubnet(if_ipv4_subnet, ipa_if_num) == false)
		{
			IPACMERR(" can't Add IPACM private subnet_addr as: 0x%x \n", if_ipv4_subnet);
		}
	}
#endif /* defined(FEATURE_IPA_ANDROID)*/

	/* Update the IP Type. */
	config_ip_type(data->iptype);

	if (data->iptype == IPA_IP_v4)
	{
		rt_rule = (struct ipa_ioc_add_rt_rule *)
			 calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
							NUM_RULES * sizeof(struct ipa_rt_rule_add));

		if (!rt_rule)
		{
			IPACMERR("Error Locate ipa_ioc_add_rt_rule memory...\n");
			return IPACM_FAILURE;
		}

		rt_rule->commit = 1;
		rt_rule->num_rules = NUM_RULES;
		rt_rule->ip = data->iptype;
		rt_rule_entry = &rt_rule->rules[0];
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.dst = IPA_CLIENT_APPS_LAN_CONS;  //go to A5
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR;
		strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name, sizeof(rt_rule->rt_tbl_name));
		rt_rule_entry->rule.attrib.u.v4.dst_addr      = data->ipv4_addr;
		rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
#ifdef FEATURE_IPA_V3
		rt_rule_entry->rule.hashable = true;
#endif
		if (false == m_routing.AddRoutingRule(rt_rule))
		{
			IPACMERR("Routing rule addition failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		else if (rt_rule_entry->status)
		{
			IPACMERR("rt rule adding failed. Result=%d\n", rt_rule_entry->status);
			res = rt_rule_entry->status;
			goto fail;
		}
		dft_rt_rule_hdl[0] = rt_rule_entry->rt_rule_hdl;
		IPACMDBG_H("ipv4 iface rt-rule hdl1=0x%x\n", dft_rt_rule_hdl[0]);

		add_tcp_syn_flt_rule(data->iptype);

		/* ICMP rule to be use as offset for L2L rules */
		install_ipv4_icmp_flt_rule();

		/* initial fragment/multicast/broadcast/filter rule. Fragment has set_rear = false, will be above icmp rule */
		init_fl_rule(data->iptype);

		for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++)
		{
			if (j > 2 && !sIface) {
				IPACMDBG_H("Iface is not Special iface, no need to install v4 rules on 2nd rx pipe\n", num_dft_rt_v6);
				continue;
			}
			/* populate the flt rule offset for eth bridge */
			eth_bridge_flt_rule_offset[j][data->iptype] = ipv4_icmp_flt_rule_hdl[j][0];
			fixed_mac_prio_val[j][IPA_IP_v4] = ++prio[j][IPA_IP_v4];

			/* populate the flt rule offset for mtu_offset (offset = broadcast rule)*/
			if (m_ipv4_default_filterting_rules_count[j] && m_ipv4_default_filterting_rules_count[j] <= IPV4_DEFAULT_FILTERTING_RULES)
			{
				mtu_flt_rule_offset[j][data->iptype] =
					dft_v4fl_rule_hdl[j][m_ipv4_default_filterting_rules_count[j] - 1];
			}
		}

		eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_UP, IPA_IP_v4, NULL, NULL, NULL);
	}
	else
	{
		/* check if see that v6-addr already or not*/
		for(num_ipv6_addr=0;num_ipv6_addr<num_dft_rt_v6;num_ipv6_addr++)
		{
			if((ipv6_addr[num_ipv6_addr][0] == data->ipv6_addr[0]) &&
			   (ipv6_addr[num_ipv6_addr][1] == data->ipv6_addr[1]) &&
			   (ipv6_addr[num_ipv6_addr][2] == data->ipv6_addr[2]) &&
			   (ipv6_addr[num_ipv6_addr][3] == data->ipv6_addr[3]))
			{
				IPACMDBG_H("ipv6_addr already added\n");
				return IPACM_FAILURE;
			}
		}

		rt_rule = (struct ipa_ioc_add_rt_rule *)
			 calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
							NUM_RULES * sizeof(struct ipa_rt_rule_add));

		if (!rt_rule)
		{
			IPACMERR("Error Locate ipa_ioc_add_rt_rule memory...\n");
			return IPACM_FAILURE;
		}

		rt_rule->commit = 1;
		rt_rule->num_rules = NUM_RULES;
		rt_rule->ip = data->iptype;
		strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_v6.name, sizeof(rt_rule->rt_tbl_name));

		rt_rule_entry = &rt_rule->rules[0];
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.dst = IPA_CLIENT_APPS_LAN_CONS;  //go to A5
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = data->ipv6_addr[0];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = data->ipv6_addr[1];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = data->ipv6_addr[2];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = data->ipv6_addr[3];
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
		ipv6_addr[num_dft_rt_v6][0] = data->ipv6_addr[0];
		ipv6_addr[num_dft_rt_v6][1] = data->ipv6_addr[1];
		ipv6_addr[num_dft_rt_v6][2] = data->ipv6_addr[2];
		ipv6_addr[num_dft_rt_v6][3] = data->ipv6_addr[3];
#ifdef FEATURE_IPA_V3
		rt_rule_entry->rule.hashable = true;
#endif
		if (false == m_routing.AddRoutingRule(rt_rule))
		{
			IPACMERR("Routing rule addition failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		else if (rt_rule_entry->status)
		{
			IPACMERR("rt rule adding failed. Result=%d\n", rt_rule_entry->status);
			res = rt_rule_entry->status;
			goto fail;
		}
		dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES + 2*num_dft_rt_v6] = rt_rule_entry->rt_rule_hdl;

		/* setup same rule for v6_wan table*/
		strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule->rt_tbl_name));
		if (false == m_routing.AddRoutingRule(rt_rule))
		{
			IPACMERR("Routing rule addition failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		else if (rt_rule_entry->status)
		{
			IPACMERR("rt rule adding failed. Result=%d\n", rt_rule_entry->status);
			res = rt_rule_entry->status;
			goto fail;
		}
		dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES + 2*num_dft_rt_v6+1] = rt_rule_entry->rt_rule_hdl;

		IPACMDBG_H("ipv6 wan iface rt-rule hdl=0x%x hdl=0x%x, num_dft_rt_v6: %d \n",
			dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES + 2*num_dft_rt_v6],
			dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES + 2*num_dft_rt_v6+1],num_dft_rt_v6);

		if (num_dft_rt_v6 == 0)
		{
			/* Always adding tcp syn SW-exception rule for MSS clamping support */
			add_tcp_syn_flt_rule(data->iptype);

#ifdef FEATURE_L2TP
			if (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP)
			{
				if(ipa_if_cate == ODU_IF)
				{
#ifndef IPA_L2TP_TUNNEL_UDP
					add_tcp_syn_flt_rule_l2tp(IPA_IP_v4);
					add_tcp_syn_flt_rule_l2tp(IPA_IP_v6);
#endif
				}
			}
#endif
			install_ipv6_icmp_flt_rule();

#ifdef FEATURE_L2TP
			if (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP)
			{
#ifdef IPA_L2TP_TUNNEL_UDP
				if (ipa_if_cate == ODU_IF)
					add_l2tp_udp_dflt_flt_rules(l2tp_udp_dflt_flt_rule_hdl);
#endif
			}
#endif
			eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_UP, IPA_IP_v6, NULL, NULL, NULL);

			init_fl_rule(data->iptype);

			for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++)
			{
				if (j > 2 && !sIface)
				{
					IPACMDBG_H("Iface is not Special iface, no need to install v6 rules on 2nd rx pipe\n", num_dft_rt_v6);
					continue;
				}
				/* populate the flt rule offset for eth bridge */
				eth_bridge_flt_rule_offset[j][IPA_IP_v6] = ipv6_icmp_flt_rule_hdl[j][0];
				fixed_mac_prio_val[j][IPA_IP_v6] = ++prio[j][IPA_IP_v6];

				/* populate the mtu_rule_offset */
				if (m_ipv6_default_filterting_rules_count[j] && m_ipv6_default_filterting_rules_count[j] <= (IPV6_DEFAULT_FILTERTING_RULES + IPV6_DEFAULT_LAN_FILTERTING_RULES))
				{
					mtu_flt_rule_offset[j][data->iptype] =
						dft_v6fl_rule_hdl[j][m_ipv6_default_filterting_rules_count[j] - 1];
				}
			}
		}
		num_dft_rt_v6++;
		IPACMDBG_H("number of default route rules %d\n", num_dft_rt_v6);
	}

	IPACMDBG_H("finish route/filter rule ip-type: %d, res(%d)\n", data->iptype, res);

	data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
	if(data_fid == NULL)
	{
		IPACMERR("unable to allocate memory for IPA_HANDLE_NEW_NEIGH_EVENT data_fid\n");
		res = IPACM_FAILURE;
		goto fail;
	}
	data_fid->if_index = data->if_index;
	evt_data.event = IPA_HANDLE_NEW_NEIGH_EVENT;
	evt_data.evt_data = data_fid;
	IPACMDBG_H("Posting IPA_HANDLE_NEW_NEIGH_EVENT event:%d\n", evt_data.event);
	IPACM_EvtDispatcher::PostEvt(&evt_data);
	/* TODO: get default MTU here instead of using 1500 */

fail:
	free(rt_rule);
	return res;
}

/* configure private subnet filter rules*/
int IPACM_Lan::handle_private_subnet(ipa_ip_type iptype)
{
	struct ipa_flt_rule_add flt_rule_entry;
	int i, j, idx = 0;

	ipa_ioc_add_flt_rule *m_pFilteringTable;

	IPACMDBG_H("lan->handle_private_subnet(); set route/filter rule \n");

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		if (iptype == IPA_IP_v4) {

			m_pFilteringTable = (struct ipa_ioc_add_flt_rule *)
				calloc(1,
					   sizeof(struct ipa_ioc_add_flt_rule) +
					   (IPACM_Iface::ipacmcfg->ipa_num_private_subnet) * sizeof(struct ipa_flt_rule_add)
					  );
			if (!m_pFilteringTable) {
				PERROR("Error Locate ipa_flt_rule_add memory...\n");
				return IPACM_FAILURE;
			}
			m_pFilteringTable->commit = 1;
			m_pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
			m_pFilteringTable->global = false;
			m_pFilteringTable->ip = IPA_IP_v4;
			m_pFilteringTable->num_rules = (uint8_t)IPACM_Iface::ipacmcfg->ipa_num_private_subnet;

			/* Make LAN-traffic always go A5, use default IPA-RT table */
			if (false == m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_default_v4)) {
				IPACMERR("LAN m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_default_v4=0x%p) Failed.\n", &IPACM_Iface::ipacmcfg->rt_tbl_default_v4);
				free(m_pFilteringTable);
				return IPACM_FAILURE;
			}

			for (i = 0; i < (IPACM_Iface::ipacmcfg->ipa_num_private_subnet); i++) {
				memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
				flt_rule_entry.at_rear = true;
				flt_rule_entry.rule.retain_hdr = 1;
				flt_rule_entry.flt_rule_hdl = -1;
				flt_rule_entry.status = -1;
				flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#ifdef FEATURE_IPA_V3
				flt_rule_entry.rule.hashable = true;
#endif
				/* Support private subnet feature including guest-AP can't talk to primary AP etc */
				flt_rule_entry.rule.rt_tbl_hdl = IPACM_Iface::ipacmcfg->rt_tbl_default_v4.hdl;
				IPACMDBG_H(" private filter rule use table: %s\n", IPACM_Iface::ipacmcfg->rt_tbl_default_v4.name);

				memcpy(&flt_rule_entry.rule.attrib,
					   &rx_prop->rx[idx].attrib,
					   sizeof(flt_rule_entry.rule.attrib));
				flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
				flt_rule_entry.rule.attrib.u.v4.dst_addr_mask = IPACM_Iface::ipacmcfg->private_subnet_table[i].subnet_mask;
				flt_rule_entry.rule.attrib.u.v4.dst_addr = IPACM_Iface::ipacmcfg->private_subnet_table[i].subnet_addr;
				memcpy(&(m_pFilteringTable->rules[i]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
				IPACMDBG_H("Loop %d  5\n", i);
			}

			if (false == m_filtering.AddFilteringRule(m_pFilteringTable)) {
				IPACMERR("Error Adding RuleTable(0) to Filtering, aborting...\n");
				free(m_pFilteringTable);
				return IPACM_FAILURE;
			}
			IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, IPACM_Iface::ipacmcfg->ipa_num_private_subnet);

			/* copy filter rule hdls */
			for (i = 0; i < IPACM_Iface::ipacmcfg->ipa_num_private_subnet; i++) {
				private_fl_rule_hdl[idx/2][i] = m_pFilteringTable->rules[i].flt_rule_hdl;
				IPACMDBG("Adding filter hdl:(0x%x)\n", private_fl_rule_hdl[idx/2][i]);
			}
			free(m_pFilteringTable);
		} else {
			IPACMDBG_H("No private subnet rules for ipv6 iface %s\n", dev_name);
		}

	}
	return IPACM_SUCCESS;
}

#ifdef FEATURE_VLAN_MPDN
int IPACM_Lan::add_vlan_private_subnet(ipacm_bridge *bridge)
{
	int i;
	struct ipa_flt_rule_add flt_rule_entry;
	ipa_ioc_add_flt_rule *m_pFilteringTable;
	ipacm_event_data_fid *data_fid;
	ipacm_cmd_q_data evt_data;

	if(rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	IPACMDBG_H("(%s) handle_vlan_private_subnet (0x%X & 0x%X)\n",
		bridge->bridge_name,
		bridge->bridge_netmask,
		bridge->bridge_ipv4_addr);

	for(i = 0; i < IPACM_Iface::ipacmcfg->ipa_num_private_subnet; i++)
	{
		if((IPACM_Iface::ipacmcfg->private_subnet_table[i].subnet_mask &
			IPACM_Iface::ipacmcfg->private_subnet_table[i].subnet_addr) ==
			(bridge->bridge_netmask & bridge->bridge_ipv4_addr))
		{
			IPACMDBG_H("(%s) private subnet was already added for (0x%X & 0x%X)\n",
				bridge->bridge_name,
				IPACM_Iface::ipacmcfg->private_subnet_table[i].subnet_mask,
				IPACM_Iface::ipacmcfg->private_subnet_table[i].subnet_addr);
			return IPACM_SUCCESS;
		}
	}

	IPACMDBG("current num private subnets %d\n", IPACM_Iface::ipacmcfg->ipa_num_private_subnet);

	if(IPACM_Iface::ipacmcfg->ipa_num_private_subnet >= IPA_MAX_PRIVATE_SUBNET_ENTRIES)
	{
		IPACMERR("IPACM private subnet_addr overflow, total entry(%d) existing:\n", IPACM_Iface::ipacmcfg->ipa_num_private_subnet);
		for(i = 0; i < IPACM_Iface::ipacmcfg->ipa_num_private_subnet; i++)
		{
			IPACMERR("0x%X\n", IPACM_Iface::ipacmcfg->private_subnet_table[i].subnet_addr);
		}
		IPACMERR("not adding: 0x%X\n", bridge->bridge_ipv4_addr & bridge->bridge_netmask);
		return IPACM_FAILURE;
	}

	IPACM_Iface::ipacmcfg->private_subnet_table[IPACM_Iface::ipacmcfg->ipa_num_private_subnet].subnet_mask = bridge->bridge_netmask;
	IPACM_Iface::ipacmcfg->private_subnet_table[IPACM_Iface::ipacmcfg->ipa_num_private_subnet].subnet_addr = bridge->bridge_ipv4_addr & bridge->bridge_netmask;
	IPACM_Iface::ipacmcfg->ipa_num_private_subnet++;

	/* notify other ifaces about this subnet */
	data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
	if(data_fid == NULL)
	{
		IPACMERR("unable to allocate memory for event data_fid\n");
		return IPACM_FAILURE;
	}
	data_fid->if_index = ipa_if_num; // already ipa index, not fid index
	evt_data.event = IPA_PRIVATE_SUBNET_CHANGE_EVENT;
	evt_data.evt_data = data_fid;

	/* Insert IPA_PRIVATE_SUBNET_CHANGE_EVENT to command queue */
	IPACM_EvtDispatcher::PostEvt(&evt_data);

	return IPACM_SUCCESS;
}
#endif


int IPACM_Lan::handle_backhaul_switch_vlan_mode(bool to_sta)
{
	int xlat_pdn_ctx_id;
	if(to_sta)
	{
		/* remove modem UL rules and notify */
		if(is_any_mux_up(IPA_IP_v4))
		{
			IPACMDBG_H("backhaul switch to STA and VLAN PDN up, delete modem ul rules (v4)\n");
			del_ul_flt_rules(IPA_IP_v4);
			for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
			{
				if(v4_mux_up[i].mux_id)
				{
					IPACMDBG_H("mux %d up, notify modem we deleted v4 flt rules in STA mode\n", v4_mux_up[i].mux_id);
					notify_flt_removed(v4_mux_up[i].mux_id);
				}
				xlat_pdn_ctx_id = get_pdn_xlat_ctx(v4_mux_up[i].mux_id, 0);
				if (xlat_pdn_ctx_id != -1)
				{
					delete_mdpn_ul_xlat_filter_rule(v4_mux_up[i].mux_id);
					remove_pdn_xlat_ctx(v4_mux_up[i].mux_id);
				}
			}
		}
		if(is_any_mux_up(IPA_IP_v6))
		{
			IPACMDBG_H("backhaul switch to STA and VLAN PDN up, delete modem ul rules (v6)\n");
			del_ul_flt_rules(IPA_IP_v6);
			for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
			{
				if(v6_mux_up[i].mux_id)
				{
					IPACMDBG_H("mux %d up, notify modem we deleted v6 flt rules in STA mode\n", v6_mux_up[i].mux_id);
					notify_flt_removed(v6_mux_up[i].mux_id);
				}
			}
		}
		is_vlan_offload_disabled = true;
	}
	else
	{
		ipacm_event_vlan_pdn data;

		if(!is_vlan_offload_disabled)
		{
			IPACMDBG_H("not a backhaul switch, return\n");
			return IPACM_SUCCESS;
		}
		is_vlan_offload_disabled = false;
		/* restore modem ul rules */
		if(is_any_mux_up(IPA_IP_v4))
		{
			IPACMDBG_H("backhaul switch to LTE and VLAN PDN up, restore modem ul rules (v4)\n");
			for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
			{
				data.iptype = IPA_IP_v4;
				if(v4_mux_up[i].mux_id)
				{
					IPACMDBG_H("mux %d up, restore v4 VLAN PDN on transition to LTE\n", v4_mux_up[i].mux_id);
					data.mux_id = v4_mux_up[i].mux_id;
					if (IPACM_Wan::is_xlat_by_vid(v4_mux_up[i].mux_id))
						data.is_xlat = true;
					handle_vlan_pdn_up(&data, false);
				}
			}
		}
		if(is_any_mux_up(IPA_IP_v6))
		{
			IPACMDBG_H("backhaul switch to LTE and VLAN PDN up, restore modem ul rules (v6)\n");
			for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
			{
				data.iptype = IPA_IP_v6;
				if(v6_mux_up[i].mux_id)
				{
					IPACMDBG_H("mux %d up, restore v6 VLAN PDN on transition to LTE\n", v6_mux_up[i].mux_id);
					data.mux_id = v6_mux_up[i].mux_id;
					handle_vlan_pdn_up(&data, false);
				}
			}
		}
	}

	return IPACM_SUCCESS;
}
/* for STA mode wan up:  configure filter rule for wan_up event*/
int IPACM_Lan::handle_wan_up(ipa_ip_type ip_type)
{
	struct ipa_flt_rule_add flt_rule_entry;
	int len = 0, idx = 0;
	ipa_ioc_add_flt_rule *m_pFilteringTable;
	int j = 0;

	IPACMDBG_H("set WAN interface as default filter rule\n");

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		if (ip_type == IPA_IP_v4) {

			/* add MTU rules for ipv4 */
			modify_private_subnet();

			len = sizeof(struct ipa_ioc_add_flt_rule) + (1 * sizeof(struct ipa_flt_rule_add));
			m_pFilteringTable = (struct ipa_ioc_add_flt_rule *)calloc(1, len);
			if (m_pFilteringTable == NULL) {
				PERROR("Error Locate ipa_flt_rule_add memory...\n");
				return IPACM_FAILURE;
			}

			m_pFilteringTable->commit = 1;
			m_pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
			m_pFilteringTable->global = false;
			m_pFilteringTable->ip = IPA_IP_v4;
			m_pFilteringTable->num_rules = (uint8_t)1;

			IPACMDBG_H("Retrieving routing hanle for table: %s\n",
					   IPACM_Iface::ipacmcfg->rt_tbl_wan_v4.name);
			if (false == m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_wan_v4)) {
				IPACMERR("m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_wan_v4=0x%p) Failed.\n",
						 &IPACM_Iface::ipacmcfg->rt_tbl_wan_v4);
				free(m_pFilteringTable);
				return IPACM_FAILURE;
			}
			IPACMDBG_H("Routing hanle for table: %d\n", IPACM_Iface::ipacmcfg->rt_tbl_wan_v4.hdl);


			memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
			flt_rule_entry.at_rear = true;
			flt_rule_entry.flt_rule_hdl = -1;
			flt_rule_entry.status = -1;
			if (IPACM_Wan::isWan_Bridge_Mode()) {
				flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
			} else {
				flt_rule_entry.rule.action = IPA_PASS_TO_SRC_NAT;
			}
#ifdef FEATURE_IPA_V3
			flt_rule_entry.rule.hashable = true;
#endif
			flt_rule_entry.rule.rt_tbl_hdl = IPACM_Iface::ipacmcfg->rt_tbl_wan_v4.hdl;

			memcpy(&flt_rule_entry.rule.attrib,
				   &rx_prop->rx[idx].attrib,
				   sizeof(flt_rule_entry.rule.attrib));

			flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
			flt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0x0;
			flt_rule_entry.rule.attrib.u.v4.dst_addr = 0x0;

			memcpy(&m_pFilteringTable->rules[0], &flt_rule_entry, sizeof(flt_rule_entry));
			if (false == m_filtering.AddFilteringRule(m_pFilteringTable)) {
				IPACMERR("Error Adding RuleTable(0) to Filtering, aborting...\n");
				free(m_pFilteringTable);
				return IPACM_FAILURE;
			} else {
				IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, 1);
				IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n",
						   m_pFilteringTable->rules[0].flt_rule_hdl,
						   m_pFilteringTable->rules[0].status);
			}


			/* copy filter hdls  */
			lan_wan_fl_rule_hdl[j][0] = m_pFilteringTable->rules[0].flt_rule_hdl;
			free(m_pFilteringTable);
		} else if (ip_type == IPA_IP_v6) {
			/* add ipv6_mtu rule */
			modify_ipv6_prefix_flt_rule();

			/* MTU might have changed. Need to update ipv4 MTU rule if up */
			if (IPACM_Wan::isWanUP(ipa_if_num)) modify_private_subnet();
#ifndef FEATURE_IPV6_NAT
			if (IPACM_Iface::ipacmcfg->ipv6_nat_enable) {
				IPACMDBG_H("IPV6 NAT is enabled. Don't install v6 rules\n");
				return IPACM_SUCCESS;
			}
#endif
			/* add default v6 filter rule */
			m_pFilteringTable = (struct ipa_ioc_add_flt_rule *)
				calloc(1, sizeof(struct ipa_ioc_add_flt_rule) +
					   1 * sizeof(struct ipa_flt_rule_add));

			if (!m_pFilteringTable) {
				PERROR("Error Locate ipa_flt_rule_add memory...\n");
				return IPACM_FAILURE;
			}

			m_pFilteringTable->commit = 1;
			m_pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
			m_pFilteringTable->global = false;
			m_pFilteringTable->ip = IPA_IP_v6;
			m_pFilteringTable->num_rules = (uint8_t)1;

			if (false == m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_v6)) {
				IPACMERR("m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_v6=0x%p) Failed.\n", &IPACM_Iface::ipacmcfg->rt_tbl_v6);
				free(m_pFilteringTable);
				return IPACM_FAILURE;
			}

			memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

			flt_rule_entry.at_rear = true;
			flt_rule_entry.flt_rule_hdl = -1;
			flt_rule_entry.status = -1;
#ifdef FEATURE_IPV6_NAT
			if (IPACM_Iface::ipacmcfg->ipv6_nat_enable) {
				/* construct 1st pass v6NAT flt-rule */
				add_ipv6_nat_ula_prefix_flt_rule();

				/* 2nd pass rule - go to RT block */
				flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
			} else
#endif
				if (IPACM_Iface::ipacmcfg->IsIpv6CTEnabled() && !IPACM_Wan::isWan_Bridge_Mode()) {
#ifndef FEATURE_SOCKSv5
					/* for v6nat, need to revisit all v6ct related logic*/
					flt_rule_entry.rule.action = IPA_PASS_TO_SRC_NAT;
#else
					flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#endif
				} else {
					flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
				}

#ifdef FEATURE_IPA_V3
			flt_rule_entry.rule.hashable = true;
#endif
			flt_rule_entry.rule.rt_tbl_hdl = IPACM_Iface::ipacmcfg->rt_tbl_v6.hdl;

			memcpy(&flt_rule_entry.rule.attrib,
				   &rx_prop->rx[idx].attrib,
				   sizeof(flt_rule_entry.rule.attrib));

			flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
			flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = 0X00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = 0X00000000;

			memcpy(&(m_pFilteringTable->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
			if (false == m_filtering.AddFilteringRule(m_pFilteringTable)) {
				IPACMERR("Error Adding Filtering rule, aborting...\n");
				free(m_pFilteringTable);
				return IPACM_FAILURE;
			} else {
				IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, 1);
				IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n", m_pFilteringTable->rules[0].flt_rule_hdl, m_pFilteringTable->rules[0].status);
			}

			/* copy filter hdls */
			dft_v6fl_rule_hdl[j][m_ipv6_default_filterting_rules_count[j]] = m_pFilteringTable->rules[0].flt_rule_hdl;
			free(m_pFilteringTable);
		}
	}

	return IPACM_SUCCESS;
}

int IPACM_Lan::handle_wan_up_ex(ipacm_ext_prop *ext_prop, ipa_ip_type iptype, uint8_t xlat_mux_id)
{
	int fd, ret = IPACM_SUCCESS, cnt;
	IPACM_Config* ipacm_config = IPACM_Iface::ipacmcfg;
	struct ipa_ioc_write_qmapid mux;
	int i=0;
	bool notif_only = false;
	bool ast_update = false;

	if(rx_prop != NULL)
	{
		/* give mux ID of the default PDN to IPA-driver for WLAN/LAN pkts */
		fd = open(IPA_DEVICE_NAME, O_RDWR);
		if (0 == fd)
		{
			IPACMDBG_H("Failed opening %s.\n", IPA_DEVICE_NAME);
			return IPACM_FAILURE;
		}

		mux.qmap_id = ipacm_config->GetQmapId();
		for(cnt=0; cnt<rx_prop->num_rx_props; cnt++)
		{
			mux.client = rx_prop->rx[cnt].src_pipe;
			IPACMDBG("mux.client %d.\n", mux.client);
			ret = ioctl(fd, IPA_IOC_WRITE_QMAPID, &mux);
			if (ret)
			{
				IPACMERR("Failed to write mux id %d\n", mux.qmap_id);
				close(fd);
				return IPACM_FAILURE;
			}
		}
		close(fd);
	}

	/* Chck if AST update is needed for WLAN interfaces. */
	if ((ipa_if_cate == WLAN_IF))
	{
		ast_update = ((IPACM_Wlan *)this)->ast_update_needed();
	}

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	/* Install filter rules for the client. */
	if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == true)
	{
		IPACMDBG_H("feature enabled, enabling per-client stats\n");
		if (enable_per_client_stats(&IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable))
		{
			IPACMERR("Failed to enable per client stats %d\n", IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable);
			return IPACM_FAILURE;
		}
	}
#endif
	/* check only add static UL filter rule once */
	if(iptype == IPA_IP_v6)
	{
		/* add ipv6_mtu rule */
		modify_ipv6_prefix_flt_rule();

		if(num_dft_rt_v6 == 1 && modem_ul_v6_set[0] == FALSE)
		{
			IPACMDBG_H("IPA_IP_v6 num_dft_rt_v6 %d xlat_mux_id: %d modem_ul_v6_set: %d\n", num_dft_rt_v6, xlat_mux_id, modem_ul_v6_set[0]);
#ifdef FEATURE_L2TP
			if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E) &&
				ipa_if_cate == ODU_IF)
			{
				IPACMDBG_H("not installing modem UL IPv6 rules in L2TP E2E use case.\n");
				return IPACM_SUCCESS;
			}
#endif
			if (IPACM_Iface::ipacmcfg->ipv6_nat_enable)
			{
#ifdef FEATURE_IPV6_NAT
				add_ipv6_nat_ula_prefix_flt_rule();
#else
				IPACMDBG_H("IPV6 NAT is enabled. Don't install v6 rules\n");
				return IPACM_SUCCESS;
#endif
			}
#ifdef FEATURE_VLAN_MPDN
			notif_only = false;
			ret = handle_uplink_filter_rule(ext_prop, iptype, xlat_mux_id, false, true, ast_update);
#else
			ret = handle_uplink_filter_rule(ext_prop, iptype, xlat_mux_id, ast_update);
#endif
			if (num_wan_ul_fl_rule_v6[0] != 0) {
				modem_ul_v6_set[0] = true;
				if (sIface)
					modem_ul_v6_set[1] = true;

				if (IPACM_Iface::ipacmcfg->ipacm_qos_enable)
				{
					modem_ul_v6_set[1] = true;
					modem_ul_v6_set[2] = true;
					modem_ul_v6_set[3] = true;
					modem_ul_v6_set[4] = true;
				}
			}
			else {
				IPACMERR("Modem UL v6 rules not installed, error: %d \n",ret);
				goto fail;
			}
		}
#ifdef FEATURE_VLAN_MPDN
		else
		{
			notif_only = true;
			ret = handle_uplink_filter_rule(ext_prop, iptype, xlat_mux_id, true, true, ast_update);
			if (num_wan_ul_fl_rule_v6[0] == 0) {
				IPACMERR("Modem UL v6 rules not installed, error: %d \n",ret);
				goto fail;
			}
		}
#endif
	}
	else if(iptype == IPA_IP_v4)
	{
		/* add MTU rules for ipv4 */
		modify_private_subnet();
		/* MTU might have changed. Need to update ipv6 MTU rule if up */
		if (IPACM_Wan::isWanUP_V6(ipa_if_num))
			modify_ipv6_prefix_flt_rule();

		if(modem_ul_v4_set[0] == false)
		{
			IPACMDBG_H("IPA_IP_v4 xlat_mux_id: %d, modem_ul_v4_set %d\n", xlat_mux_id, modem_ul_v4_set[0]);
#ifdef FEATURE_VLAN_MPDN
			/* for v4, always install the rules like before */
			notif_only = false;
			ret = handle_uplink_filter_rule(ext_prop, iptype, xlat_mux_id, false, true, ast_update);
#else
			ret = handle_uplink_filter_rule(ext_prop, iptype, xlat_mux_id, ast_update);
#endif
			if (num_wan_ul_fl_rule_v4[0] != 0) {
				modem_ul_v4_set[0] = true;
				if (sIface)
					modem_ul_v4_set[1] = true;

				if (IPACM_Iface::ipacmcfg->ipacm_qos_enable)
				{
					modem_ul_v4_set[1] = true;
					modem_ul_v4_set[2] = true;
					modem_ul_v4_set[3] = true;
					modem_ul_v4_set[4] = true;
				}
			}
			else {
				IPACMERR("Modem UL v4 rules not installed, error: %d \n",ret);
				goto fail;
			}
		}
#ifdef FEATURE_VLAN_MPDN
		else
		{
			/* for v4, always install the rules like before */
			notif_only = false;
			ret = handle_uplink_filter_rule(ext_prop, iptype, xlat_mux_id, true	, true, ast_update);
			if (num_wan_ul_fl_rule_v4[0] == 0) {
				IPACMERR("Modem UL v4 rules not installed, error: %d \n",ret);
				goto fail;
			}
		}
#endif
	}
	else
	{
		IPACMDBG_H("ip-type: %d modem_ul_v4_set: %d, modem_ul_v6_set %d\n",
			iptype, modem_ul_v4_set[0], modem_ul_v6_set[0]);
	}

#if defined(FEATURE_IPACM_PER_CLIENT_STATS) || defined(IPA_WDI_AST_UPDATE)
	/* Install filter rules for the client. */
	if (!notif_only && (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == true || ast_update))
	{
		IPACMDBG_H("xlat_mux_id: %d, iptype %d\n", xlat_mux_id, iptype);
		ret = install_uplink_filter_rule(ext_prop, iptype, xlat_mux_id);
		if (ret != IPACM_SUCCESS)
			goto fail;
	}
	else if (notif_only == true)
	{
		IPACMDBG_H("UL filtering rules already installed for %s, only sent notification for modem (mux %d)\n",
						dev_name, xlat_mux_id);
		ret = IPACM_SUCCESS;
	}
#endif

#ifdef FEATURE_IPA_IPSEC
	/* Install cached IPsec UL filtering rules */
	ret = handleIpsecUlFltAddAll(iptype);
#endif

fail:
	return ret;
}

/* handle ETH client initial, construct full headers (tx property) */
int IPACM_Lan::handle_eth_hdr_init(uint8_t *mac_addr, ipacm_bridge *bridge, uint16_t vlan_id, bool isVlan)
{

#define ETH_IFACE_INDEX_LEN 10
#define VLAN_TPID_SIZE 2
#define VLAN_VID_MASK 0x0FFF

	int res = IPACM_SUCCESS, len = 0;
	char index[ETH_IFACE_INDEX_LEN];
	struct ipa_ioc_copy_hdr sCopyHeader;
	struct ipa_ioc_add_hdr *pHeaderDescriptor = NULL;
	uint32_t cnt;
	int clnt_indx;
	struct ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table = NULL;
	struct ipa_hdr_proc_ctx_add *hdr_proc_ctx = NULL;
	int size = 0;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	struct wan_ioctl_lan_client_info *client_info;
	ipacm_ext_prop* ext_prop;
	int max_clients = (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable) ? IPA_MAX_NUM_HW_PATH_CLIENTS:
		IPA_MAX_NUM_ETH_CLIENTS;
#else
	int max_clients = IPA_MAX_NUM_ETH_CLIENTS;
#endif
#ifdef FEATURE_VLAN_MPDN
	uint16_t vlan_tci;
	if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
		max_clients = IPA_MAX_NUM_VLAN_CLIENTS;
	if(isVlan)
	{
		clnt_indx = get_eth_client_index(mac_addr, vlan_id);
	}
	else
#endif
	{
		clnt_indx = get_eth_client_index(mac_addr);
	}

	if (clnt_indx != IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client is found/attached already with index %d \n", clnt_indx);
		return IPACM_FAILURE;
	}

	/* add header to IPA */
	if (num_eth_client >= max_clients)
	{
		IPACMERR("Reached maximum number(%d) of eth clients\n", max_clients);
		return IPACM_FAILURE;
	}

	IPACMDBG_H("ETH client number: %d\n", num_eth_client);

	memcpy(get_client_memptr(eth_client, num_eth_client)->mac,
				 mac_addr,
				 sizeof(get_client_memptr(eth_client, num_eth_client)->mac));
#ifdef FEATURE_VLAN_MPDN
	if (isVlan)
	{
		get_client_memptr(eth_client, num_eth_client)->vlan_id = vlan_id;
	}
#endif
	IPACMDBG_H("Received Client MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 mac_addr[0], mac_addr[1], mac_addr[2],
					 mac_addr[3], mac_addr[4], mac_addr[5]);

	IPACMDBG_H("stored MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 get_client_memptr(eth_client, num_eth_client)->mac[0],
					 get_client_memptr(eth_client, num_eth_client)->mac[1],
					 get_client_memptr(eth_client, num_eth_client)->mac[2],
					 get_client_memptr(eth_client, num_eth_client)->mac[3],
					 get_client_memptr(eth_client, num_eth_client)->mac[4],
					 get_client_memptr(eth_client, num_eth_client)->mac[5]);
#ifdef FEATURE_VLAN_MPDN
	IPACMDBG_H("isvlan %d, vlan_id %d\n", isVlan, vlan_id);
#endif

	size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
	hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx *)malloc(size);
	if (hdr_proc_ctx_table == NULL) {
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}

	/* add header to IPA */
	if(tx_prop != NULL)
	{

		if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
		{
#ifdef FEATURE_VLAN_MPDN
			if(isVlan && !bridge)
			{
				IPACMERR("vlan with NULL bridge\n");
				return IPACM_FAILURE;
			}
#endif
		}

		len = sizeof(struct ipa_ioc_add_hdr) + (1 * sizeof(struct ipa_hdr_add));
		pHeaderDescriptor = (struct ipa_ioc_add_hdr *)calloc(1, len);
		if (pHeaderDescriptor == NULL)
		{
			IPACMERR("calloc failed to allocate pHeaderDescriptor\n");
			return IPACM_FAILURE;
		}

		/* copy partial header for v4*/
		for (cnt=0; cnt<tx_prop->num_tx_props; cnt++)
		{
			if (!sIface && cnt >= 2  || (sIface && !vlan_id && cnt >= 2)) {
				IPACMDBG_H("Only special interface can have more than 2 properties.. else continue cnt %d\n", cnt);
				continue;
			}
			if (sIface && vlan_id && cnt < 2) {
				IPACMDBG_H("Vlan event for special interface ignore non-vlan properties cnt %d\n", cnt);
				continue;
			}
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

				IPACMDBG_H("header length: %d, partial: %d\n", sCopyHeader.hdr_len, sCopyHeader.is_partial);
				IPACMDBG_H("header eth2_ofst_valid: %d, eth2_ofst: %d\n", sCopyHeader.is_eth2_ofst_valid, sCopyHeader.eth2_ofst);
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

				/* copy client mac_addr to partial header */
				if (sCopyHeader.is_eth2_ofst_valid)
				{
					memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst],
					mac_addr,
					IPA_MAC_ADDR_SIZE);
				}
				/* replace src mac to bridge mac_addr if any  */
#ifdef FEATURE_VLAN_MPDN
				/* 802.1Q header (comes after dst and src MAC)
				   --------------------------------------------
				   |    0   |    1   |     2    |    3        |
				   --------------------------------------------
				   |       TPID(2B)  |       TCI(2B)          |
				   --------------------------------------------
				   |                 |   PCP+|  VLAN ID(12b)  |
				   |                 |DEI(4b)|                |
				   --------------------------------------------
				*/
				if(isVlan)
				{
					vlan_tci =
						(*((uint16_t *)&(pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
							2 * IPA_MAC_ADDR_SIZE +
							VLAN_TPID_SIZE])));
					vlan_tci = (vlan_tci & ~VLAN_VID_MASK) | (vlan_id & VLAN_VID_MASK);
					/* change vlan_tci to HW format */
					vlan_tci = htons(vlan_tci);
					memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
						2 * IPA_MAC_ADDR_SIZE +
						VLAN_TPID_SIZE],
						&vlan_tci,
						sizeof(vlan_tci));
					IPACMDBG_H("v4: updated the vlan_tci, now 0x%X, vlan tag is 0x%X\n", vlan_tci,
						*((uint32_t *)&(pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
							2 * IPA_MAC_ADDR_SIZE])));
				}

				/* VLAN case */
				if(bridge)
				{
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
				/* non VLAN case */
				else
#endif

				if((IPACM_Iface::ipacmcfg->ipa_bridge_enable) && (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable))
				{
					memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst + IPA_MAC_ADDR_SIZE],
						IPACM_Iface::ipacmcfg->bridge_mac,
						IPA_MAC_ADDR_SIZE);
					IPACMDBG_H("device is in bridge mode (XML), MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
						IPACM_Iface::ipacmcfg->bridge_mac[0],
						IPACM_Iface::ipacmcfg->bridge_mac[1],
						IPACM_Iface::ipacmcfg->bridge_mac[2],
						IPACM_Iface::ipacmcfg->bridge_mac[3],
						IPACM_Iface::ipacmcfg->bridge_mac[4],
						IPACM_Iface::ipacmcfg->bridge_mac[5]);
				}

				pHeaderDescriptor->commit = true;
				pHeaderDescriptor->num_hdrs = 1;

				memset(pHeaderDescriptor->hdr[0].name, 0,
								sizeof(pHeaderDescriptor->hdr[0].name));

				snprintf(index,sizeof(index), "%d_", ipa_if_num);
				strlcpy(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name));
				pHeaderDescriptor->hdr[0].name[IPA_RESOURCE_NAME_MAX-1] = '\0';
				if (strlcat(pHeaderDescriptor->hdr[0].name, IPA_ETH_HDR_NAME_v4, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
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

#ifdef FEATURE_VLAN_MPDN
				if(isVlan)
				{
					snprintf(index,sizeof(index), "_%d", vlan_id);
					if (strlcat(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
					{
						IPACMERR(" header name construction failed exceed length (%zu)\n", strlen(pHeaderDescriptor->hdr[0].name));
						res = IPACM_FAILURE;
						goto fail;
					}
				}
#endif

				pHeaderDescriptor->hdr[0].hdr_len = sCopyHeader.hdr_len;
				hdr_len = sCopyHeader.hdr_len;
				pHeaderDescriptor->hdr[0].type = sCopyHeader.type;
				pHeaderDescriptor->hdr[0].hdr_hdl = -1;
				pHeaderDescriptor->hdr[0].is_partial = 0;
				pHeaderDescriptor->hdr[0].status = -1;

				if(m_header.AddHeader(pHeaderDescriptor) == false ||
					pHeaderDescriptor->hdr[0].status != 0)
				{
					IPACMERR("ioctl IPA_IOC_ADD_HDR failed: %d\n", pHeaderDescriptor->hdr[0].status);
					res = IPACM_FAILURE;
					goto fail;
				}

				get_client_memptr(eth_client, num_eth_client)->hdr_hdl_v4 = pHeaderDescriptor->hdr[0].hdr_hdl;
				IPACMDBG_H("eth-client(%d) v4 full header name:%s header handle:(0x%x), Len:%d\n",
												num_eth_client,
												pHeaderDescriptor->hdr[0].name,
												get_client_memptr(eth_client, num_eth_client)->hdr_hdl_v4,
												hdr_len);
				get_client_memptr(eth_client, num_eth_client)->ipv4_header_set=true;

				if (vlan_id && false == get_client_memptr(eth_client, num_eth_client)->ipv4_hpc_set)
				{
					memset(hdr_proc_ctx_table, 0, size);
					hdr_proc_ctx_table->commit = 1;
					hdr_proc_ctx_table->num_proc_ctxs = 1;
					hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
					hdr_proc_ctx->type = IPA_HDR_PROC_NONE;

					if ((IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 3) && (IPACM_Iface::ipacmcfg->dscp_pcp_config_cache.add == 1)) {
						hdr_proc_ctx->type = IPA_HDR_PROC_WWAN_TO_ETHII_EX;
						hdr_proc_ctx->generic_params_v2.output_dscp_pcp_update = 1;
						hdr_proc_ctx->generic_params_v2.input_ethhdr_valid = 0;
						hdr_proc_ctx->generic_params_v2.output_ethhdr_negative_offset = 18;
						hdr_proc_ctx->generic_params_v2.input_ethhdr_negative_offset = 0;
					}

					hdr_proc_ctx->hdr_hdl = get_client_memptr(eth_client, num_eth_client)->hdr_hdl_v4;
					IPACMDBG_H("hdr_proc_ctx->hdr_hdl v4 0x%x\n", hdr_proc_ctx->hdr_hdl);

					if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
						hdr_proc_ctx_table->proc_ctx[0].status != 0) {
						IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
						res = IPACM_FAILURE;
						goto fail;
					}

					get_client_memptr(eth_client, num_eth_client)->hpc_hdr_hdl_v4 = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
					IPACMDBG_H("client(%d) v4 hpc header handle:(0x%x) Len:%d\n",
							   num_eth_client,
							   get_client_memptr(eth_client, num_eth_client)->hpc_hdr_hdl_v4,
							   hdr_len);
					get_client_memptr(eth_client, num_eth_client)->ipv4_hpc_set = true;
				}

				break;
			}
		}


		/* copy partial header for v6*/
		for (cnt=0; cnt<tx_prop->num_tx_props; cnt++)
		{
			if (!sIface && cnt >= 2  || (sIface && !vlan_id && cnt >= 2)) {
				IPACMDBG_H("Only special interface can have more than 2 properties.. else continue cnt %d\n", cnt);
				continue;
			}
			if (sIface && vlan_id && cnt < 2) {
				IPACMDBG_H("Vlan event for special interface ignore non-vlan properties cnt %d\n", cnt);
				continue;
			}

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

				IPACMDBG_H("header length: %d, partial: %d\n", sCopyHeader.hdr_len, sCopyHeader.is_partial);
				IPACMDBG_H("header eth2_ofst_valid: %d, eth2_ofst: %d\n", sCopyHeader.is_eth2_ofst_valid, sCopyHeader.eth2_ofst);
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

				/* copy client mac_addr to partial header */
				if (sCopyHeader.is_eth2_ofst_valid)
				{
					memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst],
						mac_addr,
						IPA_MAC_ADDR_SIZE);
				}
#ifdef FEATURE_VLAN_MPDN
				/* 802.1Q header (comes after dst and src MAC)
				   --------------------------------------------
				   |    0   |    1   |     2    |    3        |
				   --------------------------------------------
				   |       TPID(2B)  |       TCI(2B)          |
				   --------------------------------------------
				   |                 |   PCP+|  VLAN ID(12b)  |
				   |                 |DEI(4b)|                |
				   --------------------------------------------
				*/
				if(isVlan)
				{
					vlan_tci =
						(*((uint16_t *)&(pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
							2 * IPA_MAC_ADDR_SIZE +
							VLAN_TPID_SIZE])));
					vlan_tci = (vlan_tci & ~VLAN_VID_MASK) | (vlan_id & VLAN_VID_MASK);
					/* change vlan_tci to HW format */
					vlan_tci = htons(vlan_tci);

					memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
						2 * IPA_MAC_ADDR_SIZE +
						VLAN_TPID_SIZE],
						&vlan_tci,
						sizeof(vlan_tci));

					IPACMDBG_H("v6 updated the vlan_tci, now 0x%X, vlan tag is 0x%X\n", vlan_tci,
						*((uint32_t *)&(pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst +
							2 * IPA_MAC_ADDR_SIZE])));
				}
				/* VLAN case */
				if(bridge)
				{
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
				/* non VLAN case */
				else
#endif
				if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
				{
					/* replace src mac to bridge mac_addr if any  */
					if (IPACM_Iface::ipacmcfg->ipa_bridge_enable)
					{
						memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst+IPA_MAC_ADDR_SIZE],
								IPACM_Iface::ipacmcfg->bridge_mac,
								IPA_MAC_ADDR_SIZE);
						IPACMDBG_H("device is in bridge mode (XML), MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
							IPACM_Iface::ipacmcfg->bridge_mac[0],
							IPACM_Iface::ipacmcfg->bridge_mac[1],
							IPACM_Iface::ipacmcfg->bridge_mac[2],
							IPACM_Iface::ipacmcfg->bridge_mac[3],
							IPACM_Iface::ipacmcfg->bridge_mac[4],
							IPACM_Iface::ipacmcfg->bridge_mac[5]);
					}
				}

				pHeaderDescriptor->commit = true;
				pHeaderDescriptor->num_hdrs = 1;

				memset(pHeaderDescriptor->hdr[0].name, 0,
					 sizeof(pHeaderDescriptor->hdr[0].name));

				snprintf(index,sizeof(index), "%d_", ipa_if_num);
				strlcpy(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name));
				pHeaderDescriptor->hdr[0].name[IPA_RESOURCE_NAME_MAX-1] = '\0';
				if (strlcat(pHeaderDescriptor->hdr[0].name, IPA_ETH_HDR_NAME_v6, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
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

#ifdef FEATURE_VLAN_MPDN
				if(isVlan)
				{
					snprintf(index,sizeof(index), "_%d", vlan_id);
					if (strlcat(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
					{
						IPACMERR(" header name construction failed exceed length (%zu)\n", strlen(pHeaderDescriptor->hdr[0].name));
						res = IPACM_FAILURE;
						goto fail;
					}
				}
#endif

				pHeaderDescriptor->hdr[0].hdr_len = sCopyHeader.hdr_len;
				hdr_len = sCopyHeader.hdr_len;
				pHeaderDescriptor->hdr[0].type = sCopyHeader.type;
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

				get_client_memptr(eth_client, num_eth_client)->hdr_hdl_v6 = pHeaderDescriptor->hdr[0].hdr_hdl;
				IPACMDBG_H("eth-client(%d) v6 full header name:%s header handle:(0x%x) Len:%d\n",
						 num_eth_client,
						 pHeaderDescriptor->hdr[0].name,
									 get_client_memptr(eth_client, num_eth_client)->hdr_hdl_v6,
									 hdr_len);

				get_client_memptr(eth_client, num_eth_client)->ipv6_header_set=true;

				if (vlan_id && false == get_client_memptr(eth_client, num_eth_client)->ipv6_hpc_set)
				{
					memset(hdr_proc_ctx_table, 0, size);
					hdr_proc_ctx_table->commit = 1;
					hdr_proc_ctx_table->num_proc_ctxs = 1;
					hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];
					hdr_proc_ctx->type = IPA_HDR_PROC_NONE;

					if ((IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 3) && (IPACM_Iface::ipacmcfg->dscp_pcp_config_cache.add == 1)) {
						hdr_proc_ctx->type = IPA_HDR_PROC_WWAN_TO_ETHII_EX;
						hdr_proc_ctx->generic_params_v2.output_dscp_pcp_update = 1;
						hdr_proc_ctx->generic_params_v2.input_ethhdr_valid = 0;
						hdr_proc_ctx->generic_params_v2.output_ethhdr_negative_offset = 18;
						hdr_proc_ctx->generic_params_v2.input_ethhdr_negative_offset = 0;
					}

					hdr_proc_ctx->hdr_hdl = get_client_memptr(eth_client, num_eth_client)->hdr_hdl_v6;
					IPACMDBG_H("hdr_proc_ctx->hdr_hdl v6 0x%x\n", hdr_proc_ctx->hdr_hdl);

					if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
						hdr_proc_ctx_table->proc_ctx[0].status != 0) {
						IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
						res = IPACM_FAILURE;
						goto fail;
					}

					get_client_memptr(eth_client, num_eth_client)->hpc_hdr_hdl_v6 = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
					IPACMDBG_H("client(%d) v6 hpc header handle:(0x%x) Len:%d\n",
							   num_eth_client,
							   get_client_memptr(eth_client, num_eth_client)->hpc_hdr_hdl_v6,
							   hdr_len);
					get_client_memptr(eth_client, num_eth_client)->ipv6_hpc_set = true;
				}

				break;

			}
		}
		/* initialize lan client */
		get_client_memptr(eth_client, num_eth_client)->route_rule_set_v4 = false;
		get_client_memptr(eth_client, num_eth_client)->route_rule_set_v6 = 0;
		get_client_memptr(eth_client, num_eth_client)->ipv4_set = false;
		get_client_memptr(eth_client, num_eth_client)->ipv6_set = 0;
		get_client_memptr(eth_client, num_eth_client)->gre_nat_set = false;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		IPACMDBG_H ("Is ODU client? %s\n", is_odu?"Yes":"No");
		/* to handle scenario if stats event received from QCMAP first and later ECM connect is received */
		if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == true &&
			get_lan_stats_index(get_client_memptr(eth_client, num_eth_client)->mac) == -1 &&
			IPACM_Iface::ipacmcfg->client_in_stats_cache(mac_addr) == true)
		{
			handle_stats_client_connect(IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].netlink_interface_index, mac_addr);
		}
		get_client_memptr(eth_client, num_eth_client)->ipv4_ul_rules_set = false;
		get_client_memptr(eth_client, num_eth_client)->ipv4_ul_rules_set = false;
		get_client_memptr(eth_client, num_eth_client)->lan_stats_idx = get_lan_stats_index(get_client_memptr(eth_client, num_eth_client)->mac);
		memset(get_client_memptr(eth_client, num_eth_client)->wan_ul_fl_rule_hdl_v4, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
		memset(get_client_memptr(eth_client, num_eth_client)->wan_ul_fl_rule_hdl_v6, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
#endif
		clnt_indx = num_eth_client;
		num_eth_client++;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == true &&
			get_client_memptr(eth_client, clnt_indx)->lan_stats_idx != -1)
		{
			/* Store the client info at WAN driver. */
			client_info = (struct wan_ioctl_lan_client_info *)malloc(sizeof(struct wan_ioctl_lan_client_info));
			if (client_info == NULL)
			{
				IPACMERR("Unable to allocate memory\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			memset(client_info, 0, sizeof(struct wan_ioctl_lan_client_info));
			if (ipa_if_cate == LAN_IF)
			{
				client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_USB;
			}
			else if (ipa_if_cate == ODU_IF && is_odu == true)
			{
				client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_ODU;
			}
			else if (ipa_if_cate == ODU_IF)
			{
#ifdef DUAL_NIC_OFFLOAD
				if (strstr(dev_name, STR_ETH1_IFACE))
					client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_ETH1;
				else
#endif
					client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_ETH;
			}
			else
			{
				IPACMERR("Unsupported interface category: %d\n", ipa_if_cate);
				res = IPACM_FAILURE;
				goto fail;
			}
			memcpy(client_info->mac,
					mac_addr,
					IPA_MAC_ADDR_SIZE);
			client_info->client_init = 1;
			client_info->client_idx = get_client_memptr(eth_client, clnt_indx)->lan_stats_idx;
			client_info->ul_src_pipe = (enum ipa_client_type) IPA_CLIENT_MAX;
			client_info->hdr_len = hdr_len;
#ifdef IPA_HW_FNR_STATS
			if (IPACM_Wan::ipacmcfg->hw_fnr_stats_support && !get_client_memptr(eth_client, clnt_indx)->index_populated)
			{
				int cnt_idx;
				pthread_mutex_lock(&IPACM_Iface::ipacmcfg->cnt_idx_lock);
				cnt_idx = IPACM_Iface::ipacmcfg->get_free_cnt_idx();
				pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->cnt_idx_lock);
				if (cnt_idx == -1)
				{
					IPACMERR("Got invalid cnt_idx. Abort\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				client_info->ul_cnt_idx = cnt_idx;
				client_info->dl_cnt_idx = cnt_idx + 1;
				get_client_memptr(eth_client, clnt_indx)->ul_cnt_idx = client_info->ul_cnt_idx;
				get_client_memptr(eth_client, clnt_indx)->dl_cnt_idx = client_info->dl_cnt_idx;
				get_client_memptr(eth_client, clnt_indx)->index_populated = true;
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
				reset_active_lan_stats_index(get_client_memptr(eth_client, clnt_indx)->lan_stats_idx, mac_addr);
				/* Add the mac to inactive list. */
				get_free_inactive_lan_stats_index(mac_addr);
				get_client_memptr(eth_client, clnt_indx)->lan_stats_idx = -1;
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
							get_client_memptr(eth_client, clnt_indx)->mac,
							get_client_memptr(eth_client, clnt_indx)->ul_cnt_idx);
					else
#endif //IPA_HW_FNR_STATS
						install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v4, IPACM_Wan::getXlat_Mux_Id(),
							get_client_memptr(eth_client, clnt_indx)->mac);
					get_client_memptr(eth_client, clnt_indx)->ipv4_ul_rules_set = true;
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
						install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v6, 0,
						 get_client_memptr(eth_client, clnt_indx)->mac, get_client_memptr(eth_client, clnt_indx)->ul_cnt_idx);
					else
#endif //IPA_HW_FNR_STATS
						install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v6, 0,
						 get_client_memptr(eth_client, clnt_indx)->mac);
					get_client_memptr(eth_client, clnt_indx)->ipv6_ul_rules_set = true;
				}
			}
		}
#endif
		header_name_count++; //keep increasing header_name_count
		res = IPACM_SUCCESS;
		IPACMDBG_H("header_name_count: %d\n", header_name_count);
		IPACMDBG_H("eth client number: %d\n", num_eth_client);
	}
	else
	{
		return res;
	}
fail:
	free(pHeaderDescriptor);
	return res;
}

/* Check neighbor client IPv4 address with ip n s output*/
int IPACM_Lan::check_neigh_ipv4(ipacm_event_data_all *data)
{
	FILE *fp = NULL;
	char *tok = NULL, *ptr = NULL;
	char *params[MAX_IPNS_PARAM_CNT] = { NULL };
	char ip[IPA_IFACE_NAME_LEN], ipns_row[MAX_IPNS_ROW_LEN] = {0}, cmd[IPA_SYS_CMD_LEN] = {0};
	int i;

	snprintf(cmd, IPA_SYS_CMD_LEN, "ip n s | grep %02x:%02x:%02x:%02x:%02x:%02x > %s\n",data->mac_addr[0],
				data->mac_addr[1], data->mac_addr[2], data->mac_addr[3], data->mac_addr[4], data->mac_addr[5],IPA_NS_TABLE);

	system(cmd);

	fp = fopen(IPA_NS_TABLE, "r");
	if (fp == NULL)
	{
		IPACMERR("can't open ns file\n");
		return IPACM_FAILURE;
	}

	while (fgets(ipns_row, MAX_IPNS_ROW_LEN, fp) != NULL)
	{
		if (strstr(ipns_row,"::")) {
			continue;
		}

		/*parse the ip n s entry*/
		tok = strtok_r(ipns_row, " ", &ptr);
		for (i = 0; (tok != NULL) && i < MAX_IPNS_PARAM_CNT; ++i )
		{
			params[i] = tok;
			tok = strtok_r(NULL, " ", &ptr);
		}

		for(i = 0; i < MAX_IPNS_PARAM_CNT; ++i)
		{
			if (strstr(params[i],"."))
			{
				strlcpy(ip, params[i], IPA_IFACE_NAME_LEN);
				IPACMDBG("IP Passthrough IP : %s\n",ip);
				if(data->ipv4_addr == ntohl(inet_addr(ip)))
				{
					IPACMDBG_H("IP Passthrough client IP %s - 0x%x matches\n",
								ip,ntohl(inet_addr(ip)));
					fclose(fp);
					return IPACM_SUCCESS;
				}
			}
		}
	}

	fclose(fp);
	return IPACM_FAILURE;
}

/*handle eth client */
int IPACM_Lan::handle_eth_client_ipaddr(ipacm_event_data_all *data)
{
	int clnt_indx, size = 0;
	int v6_num;
	uint32_t ipv6_link_local_prefix = 0xFE800000;
	uint32_t ipv6_link_local_prefix_mask = 0xFFC00000;
	uint16_t vlan_id = 0;
	ipacm_event_data_all data_all;
	std::list <ipacm_event_data_all>::iterator it;
	std::array<uint32_t, 4> ipv6 = {0};

	IPACMDBG_H("number of eth clients: %d\n", num_eth_client);
	IPACMDBG_H("event MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 data->mac_addr[0],
					 data->mac_addr[1],
					 data->mac_addr[2],
					 data->mac_addr[3],
					 data->mac_addr[4],
					 data->mac_addr[5]);

	/* checking instance ip_type */
	if((data->iptype != ip_type) && (ip_type != IPA_IP_MAX))
	{
		IPACMERR("inconsistent iptype. iptype = %d, instance ip_type = %d\n", data->iptype, ip_type);
		return IPACM_FAILURE;
	}

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

	clnt_indx = get_eth_client_index(data->mac_addr, vlan_id);
	if(clnt_indx == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached \n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Ip-type received %d\n", data->iptype);
	if (data->iptype == IPA_IP_v4)
	{
		IPACMDBG_H("ipv4 address: 0x%x, vlan-id: %d, device_type %d\n", data->ipv4_addr, vlan_id, device_type);
		if (data->ipv4_addr != 0) /* not 0.0.0.0 */
		{
			if (IPACM_Iface::ipacmcfg->is_ip_pass_enabled(device_type,
				data->mac_addr, vlan_id))
			{
				if (check_neigh_ipv4(data) == IPACM_SUCCESS)
				{
					/* Special handling for USB for IPPT NAT-enable */
					/* In IPPT with collision client IP will be in private subnet
					   so checking if client IP same as PDN IP before IPPT */
					if(device_type != IPACM_CLIENT_DEVICE_TYPE_USB &&
						!IPACM_Wan::check_client_ipv4_with_pdn_ipv4(data->ipv4_addr, vlan_id))
					{
						IPACMDBG_H("Client is in IP passthrough mode, but IP is mismatched with WAN IP: 0x%x\n",
							data->ipv4_addr);
						return IPACM_FAILURE;
					}
				}
				else
				{
					IPACMDBG_H("IP address %x mismatch for client but current one is different", data->ipv4_addr);
					return IPACM_FAILURE;
				}
			}
			else
			{
				/* Check if the received address is a valid one. */
				if (check_neigh_ipv4(data) == IPACM_FAILURE)
				{
					IPACMDBG_H("Client is not in IP passthrough mode, but got IP: 0x%x\n", data->ipv4_addr);
					return IPACM_FAILURE;
				}
			}

			if (get_client_memptr(eth_client, clnt_indx)->ipv4_set == false)
			{
				get_client_memptr(eth_client, clnt_indx)->v4_addr = data->ipv4_addr;
				get_client_memptr(eth_client, clnt_indx)->ipv4_set = true;
			}
			else
			{
				/* check if client got new IPv4 address*/
				if(data->ipv4_addr == get_client_memptr(eth_client, clnt_indx)->v4_addr)
				{
					IPACMDBG_H("Already setup ipv4 addr for client:%d, ipv4 address didn't change\n", clnt_indx);
					/* INSTALL GRE NAT rules */
					if (IPACM_Iface::ipacmcfg->ipacm_gre_enable == true)
					{
						if(IPACM_Iface::ipacmcfg->ipacm_gre_autolearn == true)
						{
							IPACMDBG_H("Will not add gre NAT from XML, because GRE Autolearn is enabled\n");
						}
						else
						{
							IPACMDBG_H(" check route_rule_set_v4 %d isWanUP %d gre_nat_set %d\n",
							get_client_memptr(eth_client, clnt_indx)->route_rule_set_v4, IPACM_Wan::isWanUP(ipa_if_num),
							get_client_memptr(eth_client, clnt_indx)->gre_nat_set);
							if (get_client_memptr(eth_client, clnt_indx)->route_rule_set_v4 == true &&
								IPACM_Wan::isWanUP(ipa_if_num) == true && get_client_memptr(eth_client, clnt_indx)->gre_nat_set == false)
							{
								IPACMDBG_H(" setup GRE ipv4 NAT for client:%d ip:0x%x\n", clnt_indx, data->ipv4_addr);
								CtList->HandleGREIpAddrAddEvt(data->ipv4_addr, IPACM_Iface::ipacmcfg->ipacm_gre_server_ipv4);
								get_client_memptr(eth_client, clnt_indx)->gre_nat_set = true;
							}
						}
						//need to figure out what to do for static policy.
						// client1 -> PDN1. client2 -> PDN2. PDN 2 down. Client2 -> PDN1
						if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && !is_any_mux_up(data->iptype))
						{
							IPACMDBG_H("Static policy is enabled. need to send VLAN UP for client:%d\n", clnt_indx);
							return IPACM_SUCCESS;
						}
					}
					return IPACM_FAILURE;
				}
				else
				{
					IPACMDBG_H("ipv4 addr for client:%d is changed \n", clnt_indx);
					/* delete NAT rules first */
					CtList->HandleNeighIpAddrDelEvt(get_client_memptr(eth_client, clnt_indx)->v4_addr);
					delete_eth_rtrules(clnt_indx,IPA_IP_v4);
#ifdef FEATURE_STATIC_POLICY
					if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
					{
						delete_pdn_dscp_eth_rtrules(IPA_IP_v4, 2, clnt_indx);
					}
#endif
					get_client_memptr(eth_client, clnt_indx)->route_rule_set_v4 = false;
					get_client_memptr(eth_client, clnt_indx)->v4_addr = data->ipv4_addr;
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
			if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
			{
#ifdef FEATURE_IPV6_NAT
				if(IPACM_Iface::ipacmcfg->ipv6_nat_enable && is_unique_local_ipv6_addr(data->ipv6_addr))
				{
					IPACMDBG_H("ipv6 nat enabled - add ULA ip address\n")
				} else
#endif
#ifdef IPA_IOCTL_SET_EXT_ROUTER_MODE
				/* Need to move this code for VLAN */
				if(((data->ipv6_addr[0] & ipv6_link_local_prefix_mask) != (ipv6_link_local_prefix & ipv6_link_local_prefix_mask)) &&
					IPACM_Iface::ipacmcfg->ext_router_mode != IPA_PREFIX_DISABLED)
				{
					char* pdn_name = IPACM_Iface::ipacmcfg->is_ext_route_ipv6_prefix(data->ipv6_addr);
					if (pdn_name != NULL)
					{
						if(handle_ext_router_add_evt(pdn_name, data->mac_addr, data->ipv6_addr, vlan_id) == IPACM_FAILURE)
						{
							IPACMERR("failed to handle handle_ext_router_add_evt\n");
							return IPACM_FAILURE;
						}
					}
				}
#endif
				if( (((data->ipv6_addr[0] & ipv6_link_local_prefix_mask) != (ipv6_link_local_prefix & ipv6_link_local_prefix_mask)) &&
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

					/* TODO: Do we need to add neighbor to cache? do we need to update neighbor and rt_hdl_v6_list? */
					if(IPACM_Iface::ipacmcfg->ext_router_mode != IPA_PREFIX_DISABLED)
					{
						char* pdn_name = IPACM_Iface::ipacmcfg->is_ext_route_ipv6_prefix(data->ipv6_addr);
						if (pdn_name != NULL)
						{
							if(handle_ext_router_add_evt(pdn_name, data->mac_addr, data->ipv6_addr, vlan_id) == IPACM_FAILURE)
								IPACMERR("failed to handle handle_ext_router_add_evt\n");

							return IPACM_FAILURE;  /* if yes then we can take this out */
						}
					}

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
					IPACMDBG_H("This global IPv6 address is not with correct prefix, ignore.\n");
					return IPACM_FAILURE;
				}
			}

			if(IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6 < IPA_MAX_NUM_CLIENTS_IPV6)
			{
				IPACMDBG_H("eth client:%d, current ipv6:%d, v6_route_set:%d, total_client_ipv6: %d, limit %d\n",
					clnt_indx, get_client_memptr(eth_client, clnt_indx)->ipv6_set,
					get_client_memptr(eth_client, clnt_indx)->route_rule_set_v6,
					IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6, IPA_MAX_NUM_CLIENTS_IPV6);
				std::copy(std::begin(data->ipv6_addr), std::end(data->ipv6_addr), std::begin(ipv6));

				/* never see this ipv6, insert to the map*/
				if(rt_hdl_v6_list[clnt_indx].count(ipv6) == 0 && ((data->ipv6_addr[0] & ipv6_link_local_prefix_mask) != (ipv6_link_local_prefix & ipv6_link_local_prefix_mask)))
				{
					IPACMDBG_H("can't find client\n");
					/*
					 * The client got new IPv6 address.
					 * NOTE: The new address doesn't replace the existing one but being added (up to IPA_MAX_NUM_CLIENTS_IPV6),
					 *       so the previous IPv6 addresses of the client will not be deleted.
					 */
					rt_hdl_v6_list[clnt_indx].insert(std::make_pair(ipv6, handleTypeV6(iface_query->num_tx_props)));
					/* indicate how many ipv6 client gets */
					get_client_memptr(eth_client, clnt_indx)->ipv6_set++;
					IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6++;
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

/*handle eth client routing rule*/
int IPACM_Lan::handle_eth_client_route_rule(uint8_t *mac_addr, ipa_ip_type iptype, uint16_t vlan_id)
{
	struct ipa_ioc_add_rt_rule *rt_rule;
	struct ipa_rt_rule_add *rt_rule_entry;
#ifdef FEATURE_IPA_IPSEC
	ipa_ip_type *iptype_p = NULL;
	ipacm_cmd_q_data evt_data;
#endif
	uint32_t tx_index;
	int eth_index,v6_num;
	const int NUM = 1;

	if(tx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 mac_addr[0], mac_addr[1], mac_addr[2],
					 mac_addr[3], mac_addr[4], mac_addr[5]);

	eth_index = get_eth_client_index(mac_addr, vlan_id);
	if (eth_index == IPACM_INVALID_INDEX)
	{
		IPACMDBG_H("eth client not found/attached \n");
		return IPACM_SUCCESS;
	}

	if (iptype==IPA_IP_v4) {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv4_set:%d, ipv4_rule_set:%d \n", eth_index, iptype,
					 get_client_memptr(eth_client, eth_index)->ipv4_set,
					 get_client_memptr(eth_client, eth_index)->route_rule_set_v4);
	} else {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv6_set:%d, ipv6_rule_num:%d \n", eth_index, iptype,
					 get_client_memptr(eth_client, eth_index)->ipv6_set,
					 get_client_memptr(eth_client, eth_index)->route_rule_set_v6);
	}
	/* Add default routing rules if not set yet */
	if ((iptype == IPA_IP_v4
			 && get_client_memptr(eth_client, eth_index)->route_rule_set_v4 == false
			 && get_client_memptr(eth_client, eth_index)->ipv4_set == true)
			|| (iptype == IPA_IP_v6
		            && get_client_memptr(eth_client, eth_index)->route_rule_set_v6 < get_client_memptr(eth_client, eth_index)->ipv6_set
					))
	{
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Add corresponding ipa_rm_resource_name of TX-endpoint up before IPV6 RT-rule set */
			IPACMDBG_H("dev %s add producer dependency\n", dev_name);
			if (tx_prop != NULL)
			{
				IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
				IPACM_Iface::ipacmcfg->AddRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe],false);
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

		rt_rule->commit = 1;
		rt_rule->num_rules = (uint8_t)NUM;
		rt_rule->ip = iptype;

		for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		{
			if (IPACM_Iface::ipacmcfg->ipacm_qos_enable && tx_index >= 2)
			{
				IPACMDBG_H("Qos is enabled, install client rule only on default pipe, current tx_idx %d\n",tx_index);
				continue;
			}

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

			rt_rule_entry = &rt_rule->rules[0];
			rt_rule_entry->at_rear = 0;

			if (iptype == IPA_IP_v4)
			{
				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", eth_index,
					get_client_memptr(eth_client, eth_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
					eth_index,
					get_client_memptr(eth_client, eth_index)->hdr_hdl_v4);
				strlcpy(rt_rule->rt_tbl_name,
					IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
					sizeof(rt_rule->rt_tbl_name));
				rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
				rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
				memcpy(&rt_rule_entry->rule.attrib,
					&tx_prop->tx[tx_index].attrib,
					sizeof(rt_rule_entry->rule.attrib));
				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
				if (get_client_memptr(eth_client, eth_index)->ipv4_hpc_set)
					rt_rule_entry->rule.hdr_proc_ctx_hdl = get_client_memptr(eth_client, eth_index)->hpc_hdr_hdl_v4;
				else
					rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v4;
				rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(eth_client, eth_index)->v4_addr;
				rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;

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
				if (false == m_routing.AddRoutingRule(rt_rule))
				{
					IPACMERR("Routing rule addition failed!\n");
					free(rt_rule);
					return IPACM_FAILURE;
				}

				/* copy ipv4 RT hdl */
				get_client_memptr(eth_client, eth_index)->eth_rt_hdl[tx_index].eth_rt_rule_hdl_v4 =
					rt_rule->rules[0].rt_rule_hdl;
				IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
					get_client_memptr(eth_client, eth_index)->eth_rt_hdl[tx_index].eth_rt_rule_hdl_v4, iptype);
			}
			else
			{
				for (auto it = rt_hdl_v6_list[eth_index].begin(); it != rt_hdl_v6_list[eth_index].end(); ++it)
				{
					if (it->second.route_rule_set_v6 == true)
					{
						IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d)\n",
						eth_index, it->first[0], it->first[1], it->first[2], it->first[3],
						it->second.route_rule_set_v6);
						continue;
					}

					IPACMDBG_H("client-index(%d): v6 header handle:(0x%x), v6 addr : 0x%08x:%08x:%08x:%08x\n",
						eth_index,
						get_client_memptr(eth_client, eth_index)->hdr_hdl_v6,
						it->first[0], it->first[1], it->first[2], it->first[3]);

					/* v6 LAN_RT_TBL */
					strlcpy(rt_rule->rt_tbl_name,
						IPACM_Iface::ipacmcfg->rt_tbl_v6.name,
						sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
					/* Support QCMAP LAN traffic feature, send to A5 */
					rt_rule_entry->rule.dst = IPA_CLIENT_APPS_LAN_CONS;
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
					strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
					/* Downlink traffic from Wan iface, directly through IPA */
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
					memcpy(&rt_rule_entry->rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry->rule.attrib));
					if (get_client_memptr(eth_client, eth_index)->ipv6_hpc_set)
						rt_rule_entry->rule.hdr_proc_ctx_hdl = get_client_memptr(eth_client, eth_index)->hpc_hdr_hdl_v6;
					else
						rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v6;
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

					it->second.hdl_v6[tx_index].rt_rule_hdl_v6_wan = rt_rule->rules[0].rt_rule_hdl;
					IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
						it->second.hdl_v6[tx_index].rt_rule_hdl_v6_wan, iptype);
					/* mark as route_rule_set_v6 = true*/
					if ((tx_index + 1 == iface_query->num_tx_props) ||
						IPACM_Iface::ipacmcfg->ipacm_qos_enable)
						it->second.route_rule_set_v6 = true;
				} /* v6 map loop */
			} /* ipv6 handling */
		} /* end of tx for loop */

		free(rt_rule);

		if (iptype == IPA_IP_v4)
		{
			get_client_memptr(eth_client, eth_index)->route_rule_set_v4 = true;
		}
		else
		{
			get_client_memptr(eth_client, eth_index)->route_rule_set_v6 = get_client_memptr(eth_client, eth_index)->ipv6_set;
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
/*handle eth client routing rule based on PDN and DSCP value for traffic prioritization*/
int IPACM_Lan::handle_pdn_dscp_eth_client_route_rule(uint8_t *mac_addr,
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
	int eth_index;
	int NUM = 0;
	uint8_t valid_mux[IPA_UC_MAX_PDN_DSCP_VAL];
	struct ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table = NULL;
	struct ipa_hdr_proc_ctx_add *hdr_proc_ctx = NULL;
	int size = 0, mux_idx = 0, i = 0, j = 0, idx = 0;

	IPACMDBG_H("trigger:%d iptype:%d mux_id:%d dscp_val:%d\n",
			trigger, iptype, mux_id, dscp_val);

	/* trigger = 0 will be executed when client gets connected.
         * trigger = 1 will be executed when it is invoked from IPA_PDN_DSCP_UPDATE_EVENT.
         */
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

		eth_index = get_eth_client_index(mac_addr, vlan_id);
		if (eth_index == IPACM_INVALID_INDEX)
		{
			IPACMDBG_H("eth client not found/attached\n");
			return IPACM_SUCCESS;
		}

		if (iptype==IPA_IP_v4) {
			IPACMDBG_H("eth client index: %d, ip-type: %d, ipv4_set:%d, ipv4_rule_set:%d \n", eth_index, iptype,
				get_client_memptr(eth_client, eth_index)->ipv4_set,
				get_client_memptr(eth_client, eth_index)->route_rule_set_v4);
		} else {
			IPACMDBG_H("eth client index: %d, ip-type: %d, ipv6_set:%d, ipv6_rule_num:%d \n", eth_index, iptype,
				get_client_memptr(eth_client, eth_index)->ipv6_set,
				get_client_memptr(eth_client, eth_index)->route_rule_set_v6);
		}

		if (iptype == IPA_IP_v4 &&
			get_client_memptr(eth_client, eth_index)->route_rule_set_v4 == false)
		{
			IPACMERR("route rule has not been set for eth client\n");
			return IPACM_FAILURE;
		}

		if (iptype == IPA_IP_v6 &&
			get_client_memptr(eth_client, eth_index)->route_rule_set_v6 == 0)
		{
			IPACMERR("v6 route rule has not been set for eth client index:%d\n",
				eth_index);
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
				get_client_memptr(eth_client, eth_index)->dscp_ipv4_hpc_set
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

				hdr_proc_ctx->hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v4;
				IPACMDBG_H("hdr_proc_ctx->hdr_hdl v4 0x%x\n", hdr_proc_ctx->hdr_hdl);

				if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
					hdr_proc_ctx_table->proc_ctx[0].status != 0) {
					IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
					free(hdr_proc_ctx_table);
					return IPACM_FAILURE;
				}

				get_client_memptr(eth_client, eth_index)->dscp_hpc_hdr_hdl_v4
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] =
						hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
				get_client_memptr(eth_client, eth_index)->dscp_ipv4_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] = true;
				IPACMDBG_H("v4 hpc header handle for mux_id %d:(0x%x)\n",
					IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id,
					get_client_memptr(eth_client, eth_index)->dscp_hpc_hdr_hdl_v4[i]);
			}

			if(iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2 &&
				get_client_memptr(eth_client, eth_index)->dscp_ipv6_hpc_set
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

				hdr_proc_ctx->hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v6;
				IPACMDBG_H("hdr_proc_ctx->hdr_hdl v6 0x%x\n", hdr_proc_ctx->hdr_hdl);
				if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
						hdr_proc_ctx_table->proc_ctx[0].status != 0) {
					IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
					free(hdr_proc_ctx_table);
					return IPACM_FAILURE;
				}

				get_client_memptr(eth_client, eth_index)->dscp_hpc_hdr_hdl_v6
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] =
						hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
				get_client_memptr(eth_client, eth_index)->dscp_ipv6_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] = true;
				IPACMDBG_H("v6 hpc header handle for mux_id %d:(0x%x)\n",
					IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id,
					get_client_memptr(eth_client, eth_index)->dscp_hpc_hdr_hdl_v6[i]);
			}

			if(iptype == IPA_IP_v4 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2
				&& get_client_memptr(eth_client, eth_index)->dscp_route_rule_set_v4
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == false &&
				get_client_memptr(eth_client, eth_index)->dscp_ipv4_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == true)
			{
				valid_mux[NUM++] = IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id;
			}
			else if(iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2)
			{
				for (auto it = rt_hdl_v6_list[eth_index].begin(); it != rt_hdl_v6_list[eth_index].end(); ++it)
				{
					for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
					{
						if (iptype != tx_prop->tx[tx_index].ip)
						{
							IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
								tx_index, tx_prop->tx[tx_index].ip, iptype);
							continue;
						}
						if(get_client_memptr(eth_client, eth_index)->dscp_ipv6_hpc_set
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
						eth_index,
						get_client_memptr(eth_client, eth_index)->v4_addr,
						get_client_memptr(eth_client, eth_index)->hdr_hdl_v4);

					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
					memcpy(&rt_rule_entry->rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry->rule.attrib));
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_META_DATA;
					if (get_client_memptr(eth_client, eth_index)->dscp_ipv4_hpc_set[valid_mux[i]])
						rt_rule_entry->rule.hdr_proc_ctx_hdl =
							get_client_memptr(eth_client, eth_index)->dscp_hpc_hdr_hdl_v4[valid_mux[i]];
					else
						rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v4;
					rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(eth_client, eth_index)->v4_addr;
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
					get_client_memptr(eth_client, eth_index)->dscp_eth_rt_hdl[valid_mux[j]].eth_rt_rule_hdl_v4 =
						rt_rule->rules[j].rt_rule_hdl;
					IPACMDBG_H("v4: tx:%d, rt_rule_hdl=%x ip-type:%d\n", tx_index,
						get_client_memptr(eth_client, eth_index)->dscp_eth_rt_hdl[valid_mux[j]].eth_rt_rule_hdl_v4, iptype);
					get_client_memptr(eth_client, eth_index)->dscp_route_rule_set_v4[valid_mux[j]] = true;
					get_client_memptr(eth_client, eth_index)->dscp_ipv4_hpc_count[valid_mux[j]]++;
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
					for (auto it = rt_hdl_v6_list[eth_index].begin(); it != rt_hdl_v6_list[eth_index].end(); ++it)
					{
						if(it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[valid_mux[i]] == true)
						{
							IPACMERR("dscp v6 route rule has been set for eth client already\n");
							continue;
						}

						if(it->first[0] == ipv6_addr[0] && it->first[1] == ipv6_addr[1] && it->first[2] == ipv6_addr[2]
							&& it->first[3] == ipv6_addr[3] && it->second.route_rule_set_v6 == true)
						{
							IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d)\n",
								eth_index, it->first[0], it->first[1], it->first[2], it->first[3],
								it->second.route_rule_set_v6);
							IPACMDBG_H("client-index(%d): v6 header handle:(0x%x)\n",
								eth_index,
								get_client_memptr(eth_client, eth_index)->hdr_hdl_v6);

							/* Downlink traffic from Wan iface, directly through IPA */
							rt_rule_entry = &rt_rule->rules[i];
							rt_rule_entry->at_rear = false;
							rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
							memcpy(&rt_rule_entry->rule.attrib,
								&tx_prop->tx[tx_index].attrib,
								sizeof(rt_rule_entry->rule.attrib));
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[valid_mux[i]] =
								get_client_memptr(eth_client, eth_index)->dscp_hpc_hdr_hdl_v6[valid_mux[i]];
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[valid_mux[i]] = true;

							if (it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[valid_mux[i]])
								rt_rule_entry->rule.hdr_proc_ctx_hdl =
									it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[valid_mux[i]];
							else
								rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v6;

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
					for (auto it = rt_hdl_v6_list[eth_index].begin(); it != rt_hdl_v6_list[eth_index].end(); ++it)
					{
						if(it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[valid_mux[i]] == true)
						{
							IPACMERR("dscp v6 route rule has been set for eth client already\n");
							continue;
						}

						if(it->first[0] == ipv6_addr[0] && it->first[1] == ipv6_addr[1] && it->first[2] == ipv6_addr[2]
							&& it->first[3] == ipv6_addr[3] && it->second.route_rule_set_v6 == true)
						{
							it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan[valid_mux[i]] =
								rt_rule->rules[i].rt_rule_hdl;
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[valid_mux[i]] = true;
							IPACMDBG_H("v6: tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
								it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan[valid_mux[i]], iptype);
							get_client_memptr(eth_client, eth_index)->dscp_ipv6_hpc_count[valid_mux[i]]++;
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
				IPACMERR("Failed to allocate memory for hdr_proc_ctx\n");
				free(hdr_proc_ctx_table);
				return IPACM_FAILURE;
			}

			NUM = 0;

			for (i = 0; i < num_eth_client; i++)
			{
				if(get_client_memptr(eth_client, i)->route_rule_set_v4 == false ||
					get_client_memptr(eth_client, i)->dscp_route_rule_set_v4[mux_id] == true)
				{
					continue;
				}

				if(false == get_client_memptr(eth_client, i)->dscp_ipv4_hpc_set[mux_id])
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

					hdr_proc_ctx->hdr_hdl = get_client_memptr(eth_client, i)->hdr_hdl_v4;
					IPACMDBG_H("hdr_proc_ctx->hdr_hdl v4 0x%x\n", hdr_proc_ctx->hdr_hdl);

					if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
						hdr_proc_ctx_table->proc_ctx[0].status != 0) {
						IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n",
							hdr_proc_ctx_table->proc_ctx[0].status);
						free(hdr_proc_ctx_table);
						return IPACM_FAILURE;
					}

					get_client_memptr(eth_client, i)->dscp_hpc_hdr_hdl_v4[mux_id] =
						hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
					get_client_memptr(eth_client, i)->dscp_ipv4_hpc_set[mux_id] = true;
					IPACMDBG_H("v4 hpc header handle for mux_id %d:(0x%x)\n",
						mux_id, get_client_memptr(eth_client, i)->dscp_hpc_hdr_hdl_v4[mux_id]);
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

				for (i = 0; i < num_eth_client; i++)
				{
					if(get_client_memptr(eth_client, i)->route_rule_set_v4 == false ||
						get_client_memptr(eth_client, i)->dscp_route_rule_set_v4[mux_id] == true)
					{
						continue;
					}
					rt_rule_entry = &rt_rule->rules[i];
					rt_rule_entry->at_rear = false;
					IPACMDBG_H("client index(%d):ipv4 address: 0x%x v4 header handle:(0x%x)\n",
						i,
						get_client_memptr(eth_client, i)->v4_addr,
						get_client_memptr(eth_client, i)->hdr_hdl_v4);
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
					memcpy(&rt_rule_entry->rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry->rule.attrib));
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_META_DATA;
					if (get_client_memptr(eth_client, i)->dscp_ipv4_hpc_set[mux_id])
						rt_rule_entry->rule.hdr_proc_ctx_hdl =
							get_client_memptr(eth_client, i)->dscp_hpc_hdr_hdl_v4[mux_id];
					else
						rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, i)->hdr_hdl_v4;

					rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(eth_client, i)->v4_addr;
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
				for (j=0; j < num_eth_client; j++)
				{
					if(get_client_memptr(eth_client, j)->route_rule_set_v4 == false ||
						get_client_memptr(eth_client, j)->dscp_route_rule_set_v4[mux_id] == true)
					{
						continue;
					}
					get_client_memptr(eth_client, j)->dscp_eth_rt_hdl[mux_id].eth_rt_rule_hdl_v4 =
						rt_rule->rules[idx].rt_rule_hdl;
					get_client_memptr(eth_client, j)->dscp_route_rule_set_v4[mux_id] = true;
					IPACMDBG_H("v4: tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
						get_client_memptr(eth_client, j)->dscp_eth_rt_hdl[mux_id].eth_rt_rule_hdl_v4, iptype);
						get_client_memptr(eth_client, j)->dscp_ipv4_hpc_count[mux_id]++;
					idx++;
				}
			}
			free(hdr_proc_ctx_table);
			free(rt_rule);
		}
		else if (iptype == IPA_IP_v6)
		{
			NUM = 0;
			for (j=0; j < num_eth_client; j++)
			{
				if(get_client_memptr(eth_client, j)->route_rule_set_v6 == 0)
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

				for (j=0; j < num_eth_client; j++)
				{
					if(get_client_memptr(eth_client, j)->route_rule_set_v6 == 0)
					{
						continue;
					}

					if(false == get_client_memptr(eth_client, j)->dscp_ipv6_hpc_set[mux_id])
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

						hdr_proc_ctx->hdr_hdl = get_client_memptr(eth_client, j)->hdr_hdl_v6;
						IPACMDBG_H("hdr_proc_ctx->hdr_hdl v6 0x%x\n", hdr_proc_ctx->hdr_hdl);

						if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
							hdr_proc_ctx_table->proc_ctx[0].status != 0) {
							IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n",
								hdr_proc_ctx_table->proc_ctx[0].status);
							goto fail;
						}

						get_client_memptr(eth_client, j)->dscp_hpc_hdr_hdl_v6[mux_id] =
							hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
						get_client_memptr(eth_client, j)->dscp_ipv6_hpc_set[mux_id] = true;
						IPACMDBG_H("v6 hpc header handle for mux_id %d:(0x%x)\n",
							mux_id, get_client_memptr(eth_client, j)->dscp_hpc_hdr_hdl_v6[mux_id]);

					}

					for (auto it = rt_hdl_v6_list[j].begin(); it != rt_hdl_v6_list[j].end(); ++it)
					{
						if(it->second.route_rule_set_v6 == false ||
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id] == true)
						{
							IPACMDBG_H("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d)\n",
								j, it->first[0], it->first[1], it->first[2], it->first[3],
								it->second.route_rule_set_v6);
								continue;
						}

						IPACMDBG_H("client-index(%d): v6 header handle:(0x%x), v6 addr : 0x%08x:%08x:%08x:%08x\n",
							j,
							get_client_memptr(eth_client, j)->hdr_hdl_v6,
							it->first[0], it->first[1], it->first[2], it->first[3]);

						/* Downlink traffic from Wan iface, directly through IPA */
						rt_rule_entry = &rt_rule->rules[idx];
						rt_rule_entry->at_rear = false;
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;

						memcpy(&rt_rule_entry->rule.attrib,
							&tx_prop->tx[tx_index].attrib,
							sizeof(rt_rule_entry->rule.attrib));

						it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[mux_id] =
							get_client_memptr(eth_client, j)->dscp_hpc_hdr_hdl_v6[mux_id];
						it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[mux_id] = true;

						if (it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[mux_id] == true)
							rt_rule_entry->rule.hdr_proc_ctx_hdl =
								it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[mux_id];
						else
							rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, j)->hdr_hdl_v6;

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

				for (j=0; j < num_eth_client; j++)
				{
					if(get_client_memptr(eth_client, j)->route_rule_set_v6 == 0)
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
							rt_rule->rules[idx].rt_rule_hdl;
						it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[mux_id] = true;
						IPACMDBG_H("v6: tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
							it->second.dscp_pdn_hdl_v6[tx_index].rt_rule_hdl_v6_wan[mux_id], iptype);
						get_client_memptr(eth_client, j)->dscp_ipv6_hpc_count[mux_id]++;
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

/*handle eth client routing rule based on PDN and DSCP value for
 *traffic prioritization when LAN Stats is enabled
*/
int IPACM_Lan::handle_pdn_dscp_eth_client_route_rule_ext_v2(uint8_t *mac_addr,
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
	int eth_index;
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

		eth_index = get_eth_client_index(mac_addr, vlan_id);
		if (eth_index == IPACM_INVALID_INDEX)
		{
			IPACMDBG_H("eth client not found/attached\n");
			return IPACM_SUCCESS;
		}

		if (get_client_memptr(eth_client, eth_index)->lan_stats_idx == -1)
		{
			IPACMDBG_H("Lan client index not attached.\n");
			return IPACM_SUCCESS;
		}

		if (iptype==IPA_IP_v4) {
			IPACMDBG_H("eth client index: %d, ip-type: %d, ipv4_set:%d, ipv4_rule_set:%d \n",
				eth_index, iptype,
				get_client_memptr(eth_client, eth_index)->ipv4_set,
				get_client_memptr(eth_client, eth_index)->route_rule_set_v4);
		} else {
			IPACMDBG_H("eth client index: %d, ip-type: %d, ipv6_set:%d, ipv6_rule_num:%d \n",
				eth_index, iptype,
				get_client_memptr(eth_client, eth_index)->ipv6_set,
				get_client_memptr(eth_client, eth_index)->route_rule_set_v6);
		}

		if (iptype == IPA_IP_v4 &&
			get_client_memptr(eth_client, eth_index)->route_rule_set_v4 == false)
		{
			IPACMERR("route rule has not been set for eth client\n");
			return IPACM_FAILURE;
		}

		if (iptype == IPA_IP_v6 &&
			get_client_memptr(eth_client, eth_index)->route_rule_set_v6 == 0)
		{
			IPACMERR("v6 route rule has not been set for eth client index:%d\n",
				eth_index);
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
				get_client_memptr(eth_client, eth_index)->dscp_ipv4_hpc_set
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

				hdr_proc_ctx->hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v4;
				IPACMDBG_H("hdr_proc_ctx->hdr_hdl v4 0x%x\n", hdr_proc_ctx->hdr_hdl);

				if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
					hdr_proc_ctx_table->proc_ctx[0].status != 0) {
					IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
					free(hdr_proc_ctx_table);
					return IPACM_FAILURE;
				}

				get_client_memptr(eth_client, eth_index)->dscp_hpc_hdr_hdl_v4
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] =
						hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
				get_client_memptr(eth_client, eth_index)->dscp_ipv4_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] = true;
				IPACMDBG_H("v4 hpc header handle for mux_id %d:(0x%x)\n",
					IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id,
					get_client_memptr(eth_client, eth_index)->dscp_hpc_hdr_hdl_v4[i]);
			}

			if(iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2 &&
				get_client_memptr(eth_client, eth_index)->dscp_ipv6_hpc_set
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

				hdr_proc_ctx->hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v6;
				IPACMDBG_H("hdr_proc_ctx->hdr_hdl v6 0x%x\n", hdr_proc_ctx->hdr_hdl);
				if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
						hdr_proc_ctx_table->proc_ctx[0].status != 0) {
					IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
					free(hdr_proc_ctx_table);
					return IPACM_FAILURE;
				}

				get_client_memptr(eth_client, eth_index)->dscp_hpc_hdr_hdl_v6
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] =
						hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
				get_client_memptr(eth_client, eth_index)->dscp_ipv6_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] = true;
				IPACMDBG_H("v6 hpc header handle for mux_id %d:(0x%x)\n",
					IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id,
					get_client_memptr(eth_client, eth_index)->dscp_hpc_hdr_hdl_v6[i]);
			}

			if(iptype == IPA_IP_v4 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2
				&& get_client_memptr(eth_client, eth_index)->dscp_route_rule_set_v4
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == false &&
				get_client_memptr(eth_client, eth_index)->dscp_ipv4_hpc_set
					[IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id] == true)
			{
				valid_mux[NUM++] = IPACM_Iface::ipacmcfg->pdn_dscp_table[i].mux_id;
			}
			else if(iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->pdn_dscp_table[i].status == 2)
			{
				for (auto it = rt_hdl_v6_list[eth_index].begin(); it != rt_hdl_v6_list[eth_index].end(); ++it)
				{
					for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
					{
						if (iptype != tx_prop->tx[tx_index].ip)
						{
							IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
								tx_index, tx_prop->tx[tx_index].ip, iptype);
							continue;
						}
						if(get_client_memptr(eth_client, eth_index)->dscp_ipv6_hpc_set
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
						eth_index,
						get_client_memptr(eth_client, eth_index)->v4_addr,
						get_client_memptr(eth_client, eth_index)->hdr_hdl_v4);

					rt_rule_entry.rule.dst = tx_prop->tx[tx_index].dst_pipe;
					memcpy(&rt_rule_entry.rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry.rule.attrib));
					rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_META_DATA;
					if (get_client_memptr(eth_client, eth_index)->dscp_ipv4_hpc_set[valid_mux[i]])
						rt_rule_entry.rule.hdr_proc_ctx_hdl =
							get_client_memptr(eth_client, eth_index)->dscp_hpc_hdr_hdl_v4[valid_mux[i]];
					else
						rt_rule_entry.rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v4;
					rt_rule_entry.rule.attrib.u.v4.dst_addr = get_client_memptr(eth_client, eth_index)->v4_addr;
					rt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.meta_data =
						valid_mux[i] << MUX_ID_DL_METADATA_SHIFT;
					rt_rule_entry.rule.attrib.meta_data_mask =
						MUX_ID_DL_METADATA_MASK << MUX_ID_DL_METADATA_SHIFT;
					rt_rule_entry.rule.enable_stats = true;
					rt_rule_entry.rule.cnt_idx = get_client_memptr(eth_client, eth_index)->dl_cnt_idx;
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
					get_client_memptr(eth_client, eth_index)->dscp_eth_rt_hdl[valid_mux[j]].eth_rt_rule_hdl_v4 =
						((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[j].rt_rule_hdl;
					IPACMDBG_H("v4: tx:%d, rt_rule_hdl=%x ip-type:%d\n", tx_index,
						get_client_memptr(eth_client, eth_index)->dscp_eth_rt_hdl[valid_mux[j]].eth_rt_rule_hdl_v4,
						iptype);
					get_client_memptr(eth_client, eth_index)->dscp_route_rule_set_v4[valid_mux[j]] = true;
					get_client_memptr(eth_client, eth_index)->dscp_ipv4_hpc_count[valid_mux[j]]++;
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
					for (auto it = rt_hdl_v6_list[eth_index].begin(); it != rt_hdl_v6_list[eth_index].end(); ++it)
					{
						if(it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[valid_mux[i]] == true)
						{
							IPACMERR("dscp v6 route rule has been set for eth client already\n");
							IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d)\n",
								eth_index, it->first[0], it->first[1], it->first[2], it->first[3],
								it->second.route_rule_set_v6);
							continue;
						}

						if(it->first[0] == ipv6_addr[0] && it->first[1] == ipv6_addr[1] && it->first[2] == ipv6_addr[2]
							&& it->first[3] == ipv6_addr[3] && it->second.route_rule_set_v6 == true)
						{
							IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d)\n",
								eth_index, it->first[0], it->first[1], it->first[2], it->first[3],
								it->second.route_rule_set_v6);
							IPACMDBG_H("client-index(%d): v6 header handle:(0x%x)\n",
								eth_index,
								get_client_memptr(eth_client, eth_index)->hdr_hdl_v6);

							/* Downlink traffic from Wan iface, directly through IPA */
							memset(&rt_rule_entry, 0, sizeof(struct ipa_rt_rule_add_ext_v2));
							rt_rule_entry.at_rear = false;
							rt_rule_entry.rule.dst = tx_prop->tx[tx_index].dst_pipe;
							memcpy(&rt_rule_entry.rule.attrib,
								&tx_prop->tx[tx_index].attrib,
								sizeof(rt_rule_entry.rule.attrib));
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[valid_mux[i]] =
								get_client_memptr(eth_client, eth_index)->dscp_hpc_hdr_hdl_v6[valid_mux[i]];
							it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[valid_mux[i]] = true;

							if (it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[valid_mux[i]])
								rt_rule_entry.rule.hdr_proc_ctx_hdl =
									it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[valid_mux[i]];
							else
								rt_rule_entry.rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v6;

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
							rt_rule_entry.rule.cnt_idx = get_client_memptr(eth_client, eth_index)->dl_cnt_idx;
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
					for (auto it = rt_hdl_v6_list[eth_index].begin(); it != rt_hdl_v6_list[eth_index].end(); ++it)
					{
						if(it->second.dscp_pdn_hdl_v6[tx_index].dscp_route_rule_set_v6[valid_mux[i]] == true)
						{
							IPACMERR("dscp v6 route rule has been set for eth client already\n");
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
							get_client_memptr(eth_client, eth_index)->dscp_ipv6_hpc_count[valid_mux[i]]++;
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

			for (i = 0; i < num_eth_client; i++)
			{
				if(get_client_memptr(eth_client, i)->route_rule_set_v4 == false ||
					get_client_memptr(eth_client, i)->dscp_route_rule_set_v4[mux_id] == true ||
					get_client_memptr(eth_client, eth_index)->lan_stats_idx == -1)
				{
					continue;
				}

				if(false == get_client_memptr(eth_client, i)->dscp_ipv4_hpc_set[mux_id])
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

					hdr_proc_ctx->hdr_hdl = get_client_memptr(eth_client, i)->hdr_hdl_v4;
					IPACMDBG_H("hdr_proc_ctx->hdr_hdl v4 0x%x\n", hdr_proc_ctx->hdr_hdl);

					if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
						hdr_proc_ctx_table->proc_ctx[0].status != 0) {
						IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n",
							hdr_proc_ctx_table->proc_ctx[0].status);
						free(hdr_proc_ctx_table);
						return IPACM_FAILURE;
					}

					get_client_memptr(eth_client, i)->dscp_hpc_hdr_hdl_v4[mux_id] =
						hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
					get_client_memptr(eth_client, i)->dscp_ipv4_hpc_set[mux_id] = true;
					IPACMDBG_H("v4 hpc header handle for mux_id %d:(0x%x)\n",
						i, get_client_memptr(eth_client, i)->dscp_hpc_hdr_hdl_v4[mux_id]);
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

				for (i = 0; i < num_eth_client; i++)
				{
					if(get_client_memptr(eth_client, i)->route_rule_set_v4 == false ||
						get_client_memptr(eth_client, i)->dscp_route_rule_set_v4[mux_id] == true ||
						get_client_memptr(eth_client, eth_index)->lan_stats_idx == -1)
					{
						continue;
					}
					memset(&rt_rule_entry, 0, sizeof(struct ipa_rt_rule_add_ext_v2));
					rt_rule_entry.at_rear = false;
					IPACMDBG_H("client index(%d):ipv4 address: 0x%x v4 header handle:(0x%x)\n",
						i,
						get_client_memptr(eth_client, i)->v4_addr,
						get_client_memptr(eth_client, i)->hdr_hdl_v4);
					rt_rule_entry.rule.dst = tx_prop->tx[tx_index].dst_pipe;
					memcpy(&rt_rule_entry.rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry.rule.attrib));
					rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_META_DATA;
					if (get_client_memptr(eth_client, i)->dscp_ipv4_hpc_set[mux_id])
						rt_rule_entry.rule.hdr_proc_ctx_hdl =
							get_client_memptr(eth_client, i)->dscp_hpc_hdr_hdl_v4[mux_id];
					else
						rt_rule_entry.rule.hdr_hdl = get_client_memptr(eth_client, i)->hdr_hdl_v4;

					rt_rule_entry.rule.attrib.u.v4.dst_addr = get_client_memptr(eth_client, i)->v4_addr;
					rt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
					rt_rule_entry.rule.attrib.meta_data =
						mux_id << MUX_ID_DL_METADATA_SHIFT;
					rt_rule_entry.rule.attrib.meta_data_mask =
						MUX_ID_DL_METADATA_MASK << MUX_ID_DL_METADATA_SHIFT;
					rt_rule_entry.rule.enable_stats = true;
					rt_rule_entry.rule.cnt_idx = get_client_memptr(eth_client, i)->dl_cnt_idx;
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
				for (j=0; j < num_eth_client; j++)
				{
					if(get_client_memptr(eth_client, j)->route_rule_set_v4 == false ||
						get_client_memptr(eth_client, i)->dscp_route_rule_set_v4[mux_id] == true ||
						get_client_memptr(eth_client, eth_index)->lan_stats_idx == -1)
					{
						continue;
					}
					get_client_memptr(eth_client, j)->dscp_eth_rt_hdl[mux_id].eth_rt_rule_hdl_v4 =
						((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[j].rt_rule_hdl;
					get_client_memptr(eth_client, j)->dscp_route_rule_set_v4[mux_id] = true;
					IPACMDBG_H("v4: tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
					get_client_memptr(eth_client, j)->dscp_eth_rt_hdl[mux_id].eth_rt_rule_hdl_v4, iptype);
					get_client_memptr(eth_client, j)->dscp_ipv4_hpc_count[mux_id]++;
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
			for (j=0; j < num_eth_client; j++)
			{
				if(get_client_memptr(eth_client, j)->route_rule_set_v6 == 0 ||
					get_client_memptr(eth_client, eth_index)->lan_stats_idx == -1)
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

				for (j=0; j < num_eth_client; j++)
				{
					if(get_client_memptr(eth_client, j)->route_rule_set_v6 == 0 ||
						get_client_memptr(eth_client, eth_index)->lan_stats_idx == -1)
					{
						continue;
					}

					if(false == get_client_memptr(eth_client, j)->dscp_ipv6_hpc_set[mux_id])
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

						hdr_proc_ctx->hdr_hdl = get_client_memptr(eth_client, j)->hdr_hdl_v6;
						IPACMDBG_H("hdr_proc_ctx->hdr_hdl v6 0x%x\n", hdr_proc_ctx->hdr_hdl);

						if (m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false ||
							hdr_proc_ctx_table->proc_ctx[0].status != 0) {
							IPACMERR("ioctl IPA_IOC_ADD_HDR_PROC_CTX failed: %d\n",
								hdr_proc_ctx_table->proc_ctx[0].status);
							goto fail;
						}

						get_client_memptr(eth_client, j)->dscp_hpc_hdr_hdl_v6[mux_id] =
							hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
						get_client_memptr(eth_client, j)->dscp_ipv6_hpc_set[mux_id] = true;
						IPACMDBG_H("v6 hpc header handle for mux_id %d:(0x%x)\n",
							mux_id, get_client_memptr(eth_client, j)->dscp_hpc_hdr_hdl_v6[mux_id]);

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
							get_client_memptr(eth_client, j)->hdr_hdl_v6,
							it->first[0], it->first[1], it->first[2], it->first[3]);

						/* Downlink traffic from Wan iface, directly through IPA */
						memset(&rt_rule_entry, 0, sizeof(struct ipa_rt_rule_add_ext_v2));
						rt_rule_entry.at_rear = false;
						rt_rule_entry.rule.dst = tx_prop->tx[tx_index].dst_pipe;

						memcpy(&rt_rule_entry.rule.attrib,
							&tx_prop->tx[tx_index].attrib,
							sizeof(rt_rule_entry.rule.attrib));

						it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[mux_id] =
							get_client_memptr(eth_client, j)->dscp_hpc_hdr_hdl_v6[mux_id];
						it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[mux_id] = true;

						if (it->second.dscp_pdn_hdl_v6[tx_index].dscp_ipv6_hpc_set[mux_id] == true)
							rt_rule_entry.rule.hdr_proc_ctx_hdl =
								it->second.dscp_pdn_hdl_v6[tx_index].dscp_hpc_hdr_hdl_v6[mux_id];
						else
							rt_rule_entry.rule.hdr_hdl = get_client_memptr(eth_client, j)->hdr_hdl_v6;

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
						rt_rule_entry.rule.cnt_idx = get_client_memptr(eth_client, eth_index)->dl_cnt_idx;
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

				for (j=0; j < num_eth_client; j++)
				{
					if(get_client_memptr(eth_client, j)->route_rule_set_v6 == 0 ||
						get_client_memptr(eth_client, eth_index)->lan_stats_idx == -1)
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
						get_client_memptr(eth_client, j)->dscp_ipv6_hpc_count[mux_id]++;
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

int IPACM_Lan::delete_pdn_dscp_eth_rtrules(ipa_ip_type iptype, uint32_t trigger, int clnt_idx, int mux_id)
{
	uint32_t tx_index;
	uint32_t rt_hdl;
	int num_v6 = 0, i = 0, j = 0;

	IPACMDBG_H("iptype:%d trigger:%d clnt_idx:%d mux_id:%d\n", iptype, trigger, clnt_idx, mux_id);

	if(trigger == 1)
	{
		if(iptype == IPA_IP_v4)
		{
			for (i = 0; i < num_eth_client; i++)
			{
				for(tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
				{
					if((tx_prop->tx[tx_index].ip == IPA_IP_v4) &&
						(get_client_memptr(eth_client, i)->dscp_route_rule_set_v4[mux_id]==true))
					{
						IPACMDBG_H("Delete client index %d ipv4 RT-rules for tx:%d\n", i, tx_index);

						rt_hdl = get_client_memptr(eth_client, i)->dscp_eth_rt_hdl[mux_id].eth_rt_rule_hdl_v4;
						if(m_routing.DeleteRoutingHdl(rt_hdl, IPA_IP_v4) == false)
						{
							return IPACM_FAILURE;
						}
						get_client_memptr(eth_client, i)->dscp_eth_rt_hdl[mux_id].eth_rt_rule_hdl_v4 = 0;
						get_client_memptr(eth_client, i)->dscp_route_rule_set_v4[mux_id] = false;
						get_client_memptr(eth_client, i)->dscp_ipv4_hpc_count[mux_id]--;
					}
					if(get_client_memptr(eth_client, i)->dscp_ipv4_hpc_count[mux_id] == 0 &&
						get_client_memptr(eth_client, i)->dscp_ipv4_hpc_set[mux_id] == true)
					{
						if(m_header.DeleteHeaderProcCtx(get_client_memptr(eth_client, i)->dscp_hpc_hdr_hdl_v4[mux_id]) == false)
						{
							IPACMERR("Failed to delete PDN<->DSCP hdr_proc_ctx for v4\n");
							return IPACM_FAILURE;
						}
						get_client_memptr(eth_client, i)->dscp_hpc_hdr_hdl_v4[mux_id] = 0;
						get_client_memptr(eth_client, i)->dscp_ipv4_hpc_set[mux_id] = false;
					}
				}
			}
		}
		if(iptype == IPA_IP_v6)
		{
			for (i = 0; i < num_eth_client; i++)
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
							get_client_memptr(eth_client, i)->dscp_ipv6_hpc_count[mux_id]--;
						}
					}
					if(get_client_memptr(eth_client, i)->dscp_ipv6_hpc_count[mux_id] == 0 &&
						get_client_memptr(eth_client, i)->dscp_ipv6_hpc_set[mux_id] == true)
						{
						if(m_header.DeleteHeaderProcCtx(get_client_memptr(eth_client, i)->dscp_hpc_hdr_hdl_v6[mux_id]) == false)
						{
							IPACMERR("Failed to delete PDN<->DSCP hdr_proc_ctx for v6\n");
							return IPACM_FAILURE;
						}
						get_client_memptr(eth_client, i)->dscp_hpc_hdr_hdl_v6[mux_id] = 0;
						get_client_memptr(eth_client, i)->dscp_ipv6_hpc_set[mux_id] = false;
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
						(get_client_memptr(eth_client, clnt_idx)->dscp_route_rule_set_v4
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] == true))
					{
						IPACMDBG_H("Delete client index %d ipv4 RT-rules for tx:%d\n",  clnt_idx, tx_index);

						rt_hdl = get_client_memptr(eth_client, clnt_idx)->dscp_eth_rt_hdl
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id].eth_rt_rule_hdl_v4;
						if(m_routing.DeleteRoutingHdl(rt_hdl, IPA_IP_v4) == false)
						{
							return IPACM_FAILURE;
						}
						get_client_memptr(eth_client, clnt_idx)->dscp_eth_rt_hdl
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id].eth_rt_rule_hdl_v4 = 0;
						get_client_memptr(eth_client, clnt_idx)->dscp_route_rule_set_v4
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] = false;
						get_client_memptr(eth_client, clnt_idx)->dscp_ipv4_hpc_count
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id]--;
					}
				}
				if(get_client_memptr(eth_client, clnt_idx)->dscp_ipv4_hpc_count
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] == 0 &&
					get_client_memptr(eth_client, clnt_idx)->dscp_ipv4_hpc_set
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] == true)
				{
					if(m_header.DeleteHeaderProcCtx(get_client_memptr(eth_client, clnt_idx)->dscp_hpc_hdr_hdl_v4
							[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id]) == false)
					{
						IPACMERR("Failed to delete PDN<->DSCP hdr_proc_ctx for v4\n");
						return IPACM_FAILURE;
					}
					get_client_memptr(eth_client, clnt_idx)->dscp_hpc_hdr_hdl_v4
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] = 0;
					get_client_memptr(eth_client, clnt_idx)->dscp_ipv4_hpc_set
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
							get_client_memptr(eth_client, clnt_idx)->dscp_ipv6_hpc_count
								[IPACM_Iface::ipacmcfg->pdn_dscp_table
								[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id].mux_id]--;
						}
					}
				}
				if(get_client_memptr(eth_client, clnt_idx)->dscp_ipv6_hpc_count
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] == 0 &&
					get_client_memptr(eth_client, clnt_idx)->dscp_ipv6_hpc_set
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] == true)
				{
					if(m_header.DeleteHeaderProcCtx(get_client_memptr(eth_client, clnt_idx)->dscp_hpc_hdr_hdl_v6
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id]) == false)
					{
						IPACMERR("Failed to delete PDN<->DSCP hdr_proc_ctx for v6\n");
						return IPACM_FAILURE;
					}
					get_client_memptr(eth_client, clnt_idx)->dscp_hpc_hdr_hdl_v6
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] = 0;
					get_client_memptr(eth_client, clnt_idx)->dscp_ipv6_hpc_set
						[IPACM_Iface::ipacmcfg->pdn_dscp_table[j].mux_id] = false;
				}
			}
		}
	}
	return IPACM_SUCCESS;
}
#endif

uint32_t IPACM_Lan::get_u8_bitmap_from_tc(uint8_t traffic_class)
{
	if (traffic_class < 0 || traffic_class > 31)
	{
		return 0;
	}

	return (1 << traffic_class);
}

/*handle qos routing rules */
int IPACM_Lan::handle_qos_route_rule(uint8_t *client_mac, uint16_t client_vlan_id,
					ipa_ip_type iptype, list<qos_param_info>::iterator qos_param,
					uint32_t *ipv6_addr)
{
	struct ipa_ioc_add_rt_rule *rt_rule;
	struct ipa_rt_rule_add *rt_rule_entry;
	uint32_t tx_index;
	int eth_index;
	const int NUM = 1;
	qos_client_info new_client_info;
	uint8_t zero_mac_array[IPA_MAC_ADDR_SIZE] = { 0 };
	int v6_num = 0;

	if(tx_prop == NULL)
	{
		IPACMERR("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 client_mac[0], client_mac[1], client_mac[2],
					 client_mac[3], client_mac[4], client_mac[5]);

	eth_index = get_eth_client_index(client_mac, client_vlan_id);
	if (eth_index == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached \n");
		return IPACM_SUCCESS;
	}

	if (iptype==IPA_IP_v4) {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv4_set:%d \n", eth_index, iptype,
					 qos_param->route_rule_set_v4);
	} else {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv6_set:%d \n", eth_index, iptype,
					 qos_param->route_rule_set_v6);
	}
	/* Add default routing rules if not set yet */
	if ((iptype == IPA_IP_v4
			 && qos_param->route_rule_set_v4 == false)
			|| (iptype == IPA_IP_v6
		            && qos_param->route_rule_set_v6 == false
					))
	{
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Add corresponding ipa_rm_resource_name of TX-endpoint up before IPV6 RT-rule set */
			IPACMDBG_H("dev %s add producer dependency\n", dev_name);
			if (tx_prop != NULL)
			{
				IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
				IPACM_Iface::ipacmcfg->AddRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe],false);
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

		rt_rule->commit = false; /* Install all qos route rules together */
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

			if (tx_prop->tx[tx_index].tc_bmap == 0)
			{
				IPACMDBG("Tx:%d with pipe tc 0x%x is not for qos traffic... skip and continue\n",
					tx_index, tx_prop->tx[tx_index].tc_bmap);
				continue;
			}

			IPACMDBG_H("Pipe Tx:%d, ip-type: %d debug traffic class 0x%x bmap_tc 0x%x to be compared with pipe tc 0x%x\n",
					tx_index, tx_prop->tx[tx_index].ip, qos_param->traffic_class, get_u8_bitmap_from_tc(qos_param->traffic_class), tx_prop->tx[tx_index].tc_bmap);

			IPACMDBG_H("Qos params, sport_start %d sport_end %d dport_start %d, dport_end %d, \n",
					 qos_param->ip_tup.sport_start, qos_param->ip_tup.sport_end, qos_param->ip_tup.dport_start, qos_param->ip_tup.dport_end);

			IPACMDBG_H("Qos params, protocol %d, src_ip_addr 0x%x, dst_ip_addr 0x%x \n",
					 qos_param->ip_tup.protocol, qos_param->ip_tup.src_ip_addr, qos_param->ip_tup.dst_ip_addr);
			IPACMERR("Qos params, src ipv6 addr: 0x%x:%x:%x:%x, dst ipv6 addr:0x%x:%x:%x:%x\n",
				qos_param->ip_tup.src_v6_ip_addr[0],
				qos_param->ip_tup.src_v6_ip_addr[1],
				qos_param->ip_tup.src_v6_ip_addr[2],
				qos_param->ip_tup.src_v6_ip_addr[3],
				qos_param->ip_tup.dst_v6_ip_addr[0],
				qos_param->ip_tup.dst_v6_ip_addr[1],
				qos_param->ip_tup.dst_v6_ip_addr[2],
				qos_param->ip_tup.dst_v6_ip_addr[3]);

			if (!(tx_prop->tx[tx_index].tc_bmap & get_u8_bitmap_from_tc(qos_param->traffic_class)))
			{
				IPACMDBG_H("Pipe Tx:%d, ip-type: %d conflicting traffic class 0x%x with pipe tc 0x%x\n",
					tx_index, tx_prop->tx[tx_index].ip, qos_param->traffic_class, tx_prop->tx[tx_index].tc_bmap);
				continue;
			}

			rt_rule_entry = &rt_rule->rules[0];
			rt_rule_entry->at_rear = false;

			if (iptype == IPA_IP_v4)
			{
				if (!get_client_memptr(eth_client, eth_index)->ipv4_header_set ||
					!get_client_memptr(eth_client, eth_index)->hdr_hdl_v4)
				{
					IPACMERR("Client v4 set %d hdl %d is not a valid v4 handle to install qos rule\n",
							   get_client_memptr(eth_client, eth_index)->ipv4_header_set,
							   get_client_memptr(eth_client, eth_index)->hdr_hdl_v4);
				}

				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", eth_index,
					get_client_memptr(eth_client, eth_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
					eth_index,
					get_client_memptr(eth_client, eth_index)->hdr_hdl_v4);
				strlcpy(rt_rule->rt_tbl_name,
					IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
					sizeof(rt_rule->rt_tbl_name));
				rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
				rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
				memcpy(&rt_rule_entry->rule.attrib,
					&tx_prop->tx[tx_index].attrib,
					sizeof(rt_rule_entry->rule.attrib));

				rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v4;


				//Client ip is required to differentiate different clients, else hdr collision will happen
				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
				rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(eth_client, eth_index)->v4_addr;
				rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xffffffff;

				// IP Tuple
				if (qos_param->ip_tup.src_ip_addr)
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
					rt_rule_entry->rule.attrib.u.v4.src_addr = qos_param->ip_tup.src_ip_addr;
					rt_rule_entry->rule.attrib.u.v4.src_addr_mask = qos_param->ip_tup.src_sub_mask;
				}

				if (qos_param->ip_tup.dst_ip_addr)
				{
					if (qos_param->ip_tup.dst_ip_addr != get_client_memptr(eth_client, eth_index)->v4_addr)
					{
						IPACMERR("Mismatched destination qos ip addr 0x%x with client ip 0x%x\n", qos_param->ip_tup.dst_ip_addr, get_client_memptr(eth_client, eth_index)->v4_addr);
						return IPACM_SUCCESS;
					}
				}

				// If single port is provided
				if (qos_param->ip_tup.sport_start && (qos_param->ip_tup.sport_start == qos_param->ip_tup.sport_end))
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_PORT;
					rt_rule_entry->rule.attrib.src_port = qos_param->ip_tup.sport_start;
				}
				else if (qos_param->ip_tup.sport_start && qos_param->ip_tup.sport_end) // If port range is provided
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_PORT_RANGE;
					rt_rule_entry->rule.attrib.src_port_lo = qos_param->ip_tup.sport_start;
					rt_rule_entry->rule.attrib.src_port_hi = qos_param->ip_tup.sport_end;
				}

				// If single port is provided
				if (qos_param->ip_tup.dport_start && (qos_param->ip_tup.dport_start == qos_param->ip_tup.dport_end))
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
					rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(eth_client, eth_index)->v4_addr;
					rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xffffffff;
				}

				if (qos_param->dscp)
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_TOS;
					rt_rule_entry->rule.attrib.tos_value = qos_param->dscp;
					rt_rule_entry->rule.attrib.tos_mask = 0xFF;
				}

				if (qos_param->pcp)
				{
					IPACMERR("QOS param PCP no action from IPA \n");
				}

				if (IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
				{
					rt_rule_entry->rule.hashable = true;
				}

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

				memcpy(new_client_info.mac, get_client_memptr(eth_client, eth_index)->mac, IPA_MAC_ADDR_SIZE);

				qos_param->qos_client_list.push_front(new_client_info);
				qos_param->client_cnt++;
				IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d client cnt %d\n", tx_index,
					new_client_info.qos_rt_rule_hdl_v4, iptype, qos_param->client_cnt);
			}
			else
			{
				if (get_client_memptr(eth_client, eth_index)->ipv6_header_set &&
						get_client_memptr(eth_client, eth_index)->hdr_hdl_v6)
				{
					IPACMDBG_H("client(%d): v6 header handle:(0x%x)\n",
						eth_index,
						get_client_memptr(eth_client, eth_index)->hdr_hdl_v6);

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
					rt_rule_entry->rule.hdr_hdl =
						get_client_memptr(eth_client, eth_index)->hdr_hdl_v6;

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
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_TOS;
						rt_rule_entry->rule.attrib.tos_value = qos_param->dscp;
						rt_rule_entry->rule.attrib.tos_mask = 0xFF;
					}

					if (qos_param->pcp)
					{
						IPACMERR("QOS param PCP no v6 route rule action from IPA \n");
					}

#ifdef FEATURE_IPA_V3
					rt_rule_entry->rule.hashable = true;
#endif
					if (false == m_routing.AddRoutingRule(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						free(rt_rule);
						return IPACM_FAILURE;
					}

					new_client_info.qos_rt_rule_hdl_v6 = rt_rule->rules[0].rt_rule_hdl;
					new_client_info.route_rule_set_v6 = true;

					new_client_info.v6_ip_addr[0] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[0];
					new_client_info.v6_ip_addr[1] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[1];
					new_client_info.v6_ip_addr[2] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[2];
					new_client_info.v6_ip_addr[3] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[3];

					memcpy(new_client_info.mac,
						get_client_memptr(eth_client, eth_index)->mac,
						IPA_MAC_ADDR_SIZE);

					IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
							   new_client_info.qos_rt_rule_hdl_v6, iptype);
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
int IPACM_Lan::handle_qos_route_rule_ext_v2(uint8_t *client_mac,
	uint16_t client_vlan_id, ipa_ip_type iptype,
	list<qos_param_info>::iterator qos_param, uint32_t *ipv6_addr)
{
	struct ipa_ioc_add_rt_rule_ext_v2 *rt_rule;
	struct ipa_rt_rule_add_ext_v2 *rt_rule_entry;
	uint32_t tx_index;
	int eth_index;
	const int NUM = 1;
	qos_client_info new_client_info;
	uint8_t zero_mac_array[IPA_MAC_ADDR_SIZE] = { 0 };
	int v6_num = 0;
	uint64_t rules, size = 0;

	if(tx_prop == NULL)
	{
		IPACMERR("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 client_mac[0], client_mac[1], client_mac[2],
					 client_mac[3], client_mac[4], client_mac[5]);

	eth_index = get_eth_client_index(client_mac, client_vlan_id);
	if (eth_index == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached \n");
		return IPACM_SUCCESS;
	}

	if (iptype==IPA_IP_v4) {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv4_set:%d \n",
			eth_index, iptype, qos_param->route_rule_set_v4);
	} else {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv6_set:%d \n",
			eth_index, iptype, qos_param->route_rule_set_v6);
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

			if (tx_prop->tx[tx_index].tc_bmap == 0)
			{
				IPACMDBG("Tx:%d with pipe tc 0x%x is not for qos traffic... skip and continue\n",
					tx_index, tx_prop->tx[tx_index].tc_bmap);
				continue;
			}

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
				" 0x%x \n", qos_param->ip_tup.protocol,
				qos_param->ip_tup.src_ip_addr, qos_param->ip_tup.dst_ip_addr);

			IPACMERR("Qos params, src ipv6 addr: 0x%x:%x:%x:%x, dst ipv6 addr:0x%x:%x:%x:%x\n",
				qos_param->ip_tup.src_v6_ip_addr[0],
				qos_param->ip_tup.src_v6_ip_addr[1],
				qos_param->ip_tup.src_v6_ip_addr[2],
				qos_param->ip_tup.src_v6_ip_addr[3],
				qos_param->ip_tup.dst_v6_ip_addr[0],
				qos_param->ip_tup.dst_v6_ip_addr[1],
				qos_param->ip_tup.dst_v6_ip_addr[2],
				qos_param->ip_tup.dst_v6_ip_addr[3]);

			if (!(tx_prop->tx[tx_index].tc_bmap &
				get_u8_bitmap_from_tc(qos_param->traffic_class)))
			{
				IPACMDBG_H("Pipe Tx:%d, ip-type: %d conflicting traffic class "
					"0x%x with pipe tc 0x%x\n", tx_index,
					tx_prop->tx[tx_index].ip, qos_param->traffic_class,
					tx_prop->tx[tx_index].tc_bmap);
				continue;
			}

			rules = rt_rule->rules;
			rt_rule_entry = (struct ipa_rt_rule_add_ext_v2 *)rules;
			rt_rule_entry->at_rear = false;

			if (iptype == IPA_IP_v4)
			{
				if (!get_client_memptr(eth_client, eth_index)->ipv4_header_set ||
					!get_client_memptr(eth_client, eth_index)->hdr_hdl_v4)
				{
					IPACMERR("Client v4 set %d hdl %d is not a valid v4 handle to install qos rule\n",
							   get_client_memptr(eth_client, eth_index)->ipv4_header_set,
							   get_client_memptr(eth_client, eth_index)->hdr_hdl_v4);
				}

				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", eth_index,
					get_client_memptr(eth_client, eth_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
					eth_index,
					get_client_memptr(eth_client, eth_index)->hdr_hdl_v4);
				strlcpy(rt_rule->rt_tbl_name,
					IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
					sizeof(rt_rule->rt_tbl_name));
				rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
				rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
				memcpy(&rt_rule_entry->rule.attrib,
					&tx_prop->tx[tx_index].attrib,
					sizeof(rt_rule_entry->rule.attrib));
					
				rt_rule_entry->rule.enable_stats = true;
				rt_rule_entry->rule.cnt_idx =
					get_client_memptr(eth_client, eth_index)->dl_cnt_idx;
				IPACMDBG_H("eth_client dl index (%d) \n", rt_rule_entry->rule.cnt_idx);

				//Client ip is required to differentiate different clients, else hdr collision will happen
				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
				rt_rule_entry->rule.attrib.u.v4.dst_addr =
					get_client_memptr(eth_client, eth_index)->v4_addr;
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
						get_client_memptr(eth_client, eth_index)->v4_addr)
					{
						IPACMERR("Mismatched destination qos ip addr 0x%x with "
						"client ip 0x%x\n", qos_param->ip_tup.dst_ip_addr,
						get_client_memptr(eth_client, eth_index)->v4_addr);
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
						get_client_memptr(eth_client, eth_index)->v4_addr;
					rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xffffffff;
				}

				if (qos_param->dscp)
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_TOS;
					rt_rule_entry->rule.attrib.tos_value = qos_param->dscp;
					rt_rule_entry->rule.attrib.tos_mask = 0xFF;
				}

				if (qos_param->pcp)
				{
					IPACMERR("QOS param PCP no action from IPA \n");
				}

				if (IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
				{
					rt_rule_entry->rule.hashable = true;
				}


				rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v4;
				IPACMDBG_H("rt->hdr_hdl v4 0x%x\n", rt_rule_entry->rule.hdr_hdl);

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

				memcpy(new_client_info.mac,
					get_client_memptr(eth_client, eth_index)->mac, IPA_MAC_ADDR_SIZE);

				qos_param->qos_client_list.push_front(new_client_info);
				qos_param->client_cnt++;
				IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d client cnt %d\n",
					tx_index, new_client_info.qos_rt_rule_hdl_v4, iptype,
					qos_param->client_cnt);
			}
			else
			{
				if (get_client_memptr(eth_client, eth_index)->ipv6_header_set &&
						get_client_memptr(eth_client, eth_index)->hdr_hdl_v6)
				{
					IPACMDBG_H("client(%d): v6 header handle:(0x%x)\n",
						eth_index,
						get_client_memptr(eth_client, eth_index)->hdr_hdl_v6);

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
					rt_rule_entry->rule.hdr_hdl =
						get_client_memptr(eth_client, eth_index)->hdr_hdl_v6;

					rt_rule_entry->rule.enable_stats = true;
					rt_rule_entry->rule.cnt_idx =
						get_client_memptr(eth_client, eth_index)->dl_cnt_idx;
					IPACMDBG_H("eth_client v6 dl index (%d) \n", rt_rule_entry->rule.cnt_idx);

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
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_TOS;
						rt_rule_entry->rule.attrib.tos_value = qos_param->dscp;
						rt_rule_entry->rule.attrib.tos_mask = 0xFF;
					}

					if (qos_param->pcp)
					{
						IPACMERR("QOS param PCP no v6 route rule action from IPA \n");
					}

#ifdef FEATURE_IPA_V3
					rt_rule_entry->rule.hashable = true;
#endif
					if (false == m_routing.AddRoutingRuleExt_v2(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						free(rt_rule);
						return IPACM_FAILURE;
					}

					new_client_info.qos_rt_rule_hdl_v6 = ((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[0].rt_rule_hdl;
					new_client_info.route_rule_set_v6 = true;

					new_client_info.v6_ip_addr[0] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[0];
					new_client_info.v6_ip_addr[1] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[1];
					new_client_info.v6_ip_addr[2] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[2];
					new_client_info.v6_ip_addr[3] =
						rt_rule_entry->rule.attrib.u.v6.dst_addr[3];

					memcpy(new_client_info.mac,
						get_client_memptr(eth_client, eth_index)->mac,
						IPA_MAC_ADDR_SIZE);

					IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
							   new_client_info.qos_rt_rule_hdl_v6, iptype);
					qos_param->qos_client_list.push_front(new_client_info);
					qos_param->client_cnt++;
				}
			}
		} /* end of for loop */

		free(rt_rule);
	}
	return IPACM_SUCCESS;
}

int IPACM_Lan::if_client_qos_rule_needed(uint8_t * client_mac,
	uint16_t client_vlan_id, list<qos_param_info>::iterator qos_param,
	uint32_t *ipv6_addr)
{
	int ret = false;
	int i = 0;
	list<qos_client_info>::iterator it_qos_client;
	int eth_index;
	uint8_t null_mac[IPA_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};

	eth_index = get_eth_client_index(client_mac, client_vlan_id);
	if (eth_index == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached\n");
		return ret;
	}

	// Check if vlan type is matching, if client is non-vlan then qos param can't be vlan and vice versa
	if (qos_param->vlan_id &&
		(client_vlan_id != qos_param->vlan_id))
	{
		IPACMDBG_H("Vlan client for non-vlan qos param or vice-versa, client vlan id %d , qos vlanid %d\n",
						 client_vlan_id, qos_param->vlan_id);
		return ret;
	}

	// Check if mac id is matching the qos rule mac id
	if (memcmp(qos_param->dst_mac_addr, null_mac, sizeof(null_mac)) &&
		memcmp(qos_param->dst_mac_addr, get_client_memptr(eth_client, eth_index)->mac, IPA_MAC_ADDR_SIZE))
	{
		IPACMDBG_H("Destination qos mac address %x:%x:%x:%x:%x:%x requested does not match client mac %x:%x:%x:%x:%x:%x, client vlanid %d\n",
					 qos_param->dst_mac_addr[0], qos_param->dst_mac_addr[1], qos_param->dst_mac_addr[2],
					 qos_param->dst_mac_addr[3], qos_param->dst_mac_addr[4], qos_param->dst_mac_addr[5],
					 get_client_memptr(eth_client, eth_index)->mac[0], get_client_memptr(eth_client, eth_index)->mac[1],
					 get_client_memptr(eth_client, eth_index)->mac[2], get_client_memptr(eth_client, eth_index)->mac[3],
					 get_client_memptr(eth_client, eth_index)->mac[4], get_client_memptr(eth_client, eth_index)->mac[5],
					 client_vlan_id);
		return ret;
	}

	//don't install qos rules if client rules are not set
	if (qos_param->ip_type == IPA_IP_v4)
	{
		if (!get_client_memptr(eth_client, eth_index)->route_rule_set_v4)
		{
			IPACMDBG_H("v4 client rule is not set: %d, "
					"cannot install qos v4 rule for this client\n",
				get_client_memptr(eth_client, eth_index)->route_rule_set_v4);
			return ret;
		}
		if (qos_param->ip_tup.dst_ip_addr)
		{
			if (qos_param->ip_tup.dst_ip_addr !=
				get_client_memptr(eth_client, eth_index)->v4_addr)
			{
				IPACMERR("Mismatched destination qos ip addr 0x%x with client ip 0x%x\n",
					qos_param->ip_tup.dst_ip_addr,
					get_client_memptr(eth_client, eth_index)->v4_addr);
				return ret;
			}
		}
	}

	if (qos_param->ip_type == IPA_IP_v6)
	{
		if (!get_client_memptr(eth_client, eth_index)->route_rule_set_v6)
		{
			IPACMDBG_H("v6 client rule is not set: %d, "
				"cannot install qos v6 rule for this client\n",
				get_client_memptr(eth_client, eth_index)->route_rule_set_v6);
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

	for (it_qos_client = qos_param->qos_client_list.begin(); it_qos_client != qos_param->qos_client_list.end(); ++it_qos_client)
	{
		if (it_qos_client->v4_ip_addr &&
			(it_qos_client->v4_ip_addr == get_client_memptr(eth_client, eth_index)->v4_addr))
		{
			IPACMDBG_H("v4 Client already exists in qos list, Client vlan id %d , qos vlanid %d\n",
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
	IPACMDBG_H("No qos rule exists for this client, Adding qos rule for client at idx %d\n", eth_index);
	return ret;
}

int IPACM_Lan::install_all_qos_route_rule(uint8_t * client_mac,
	uint16_t client_vlan_id, uint32_t *ipv6_addr)
{

	list<qos_param_info>::iterator it_qos_params;
	int client_idx = 0;
	int eth_index;

	IPACMDBG_H("Install_all_qos_route_rule called start 0x%x, end 0x%x \n",
				IPACM_Iface::ipacmcfg->m_qos_params.begin(),
				IPACM_Iface::ipacmcfg->m_qos_params.end());

	eth_index = get_eth_client_index(client_mac, client_vlan_id);
	if (eth_index == IPACM_INVALID_INDEX)
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

		if (it_qos_params->ip_type == IPA_IP_v4)
		{
			if (if_client_qos_rule_needed(client_mac, client_vlan_id,
				it_qos_params, NULL))
			{
				IPACMDBG_H("Install qos rules with ip type: %d and tc: %d\n",
					(ipa_ip_type)it_qos_params->ip_type,
					it_qos_params->traffic_class);

				if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == true)
				{
					handle_qos_route_rule_ext_v2(client_mac, client_vlan_id,
					(ipa_ip_type)it_qos_params->ip_type, it_qos_params, NULL);
				}
				else
				{
					handle_qos_route_rule(client_mac, client_vlan_id,
					(ipa_ip_type)it_qos_params->ip_type, it_qos_params, NULL);
				}
			}
		}
		else
		{
			if (ipv6_addr != NULL)
			{
				if (if_client_qos_rule_needed(client_mac, client_vlan_id,
					it_qos_params, ipv6_addr))
				{
					IPACMDBG_H("Install qos rules with ip type: %d and tc: %d\n",
						(ipa_ip_type)it_qos_params->ip_type,
						it_qos_params->traffic_class);

					if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == true)
					{
						handle_qos_route_rule_ext_v2(client_mac, client_vlan_id,
						(ipa_ip_type)it_qos_params->ip_type, it_qos_params, ipv6_addr);
					}
					else
					{
						handle_qos_route_rule(client_mac, client_vlan_id,
						(ipa_ip_type)it_qos_params->ip_type, it_qos_params, ipv6_addr);
					}
				}
			}
			else
			{
				for (auto it = rt_hdl_v6_list[eth_index].begin(); it != rt_hdl_v6_list[eth_index].end(); ++it)
				{
					uint32_t ip6[4];
					ip6[0] = it->first[0];
					ip6[1] = it->first[1];
					ip6[2] = it->first[2];
					ip6[3] = it->first[3];
					if (if_client_qos_rule_needed(client_mac, client_vlan_id,
						it_qos_params,
						ip6))
					{
						IPACMDBG_H("Install qos rules with ip type: %d and tc: %d\n",
							(ipa_ip_type)it_qos_params->ip_type,
							it_qos_params->traffic_class);

						if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == true)
						{
							handle_qos_route_rule_ext_v2(client_mac, client_vlan_id,
							(ipa_ip_type)it_qos_params->ip_type, it_qos_params,
							ip6);
						}
						else
						{
							handle_qos_route_rule(client_mac, client_vlan_id,
							(ipa_ip_type)it_qos_params->ip_type, it_qos_params,
							ip6);
						}
					}
				}
			}
		}
	}

	if (false == m_routing.Commit(IPA_IP_v4))
	{
		IPACMERR("QOS Routing rule v4 commit failed!\n");
		pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->qos_param_list_lock);
		return IPACM_FAILURE;
	}

	if (false == m_routing.Commit(IPA_IP_v6))
	{
		IPACMERR("QOS Routing rule v6 commit failed!\n");
		pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->qos_param_list_lock);
		return IPACM_FAILURE;
	}

	IPACMDBG_H("QOS Routing rule added successfully \n");
	pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->qos_param_list_lock);
	return IPACM_SUCCESS;
}

int IPACM_Lan::delete_client_info_from_qos(uint8_t *client_mac,
				uint16_t vlan_id, list<qos_param_info>::iterator qos_param,
				uint32_t *ipv6_addr)
{
	list<qos_client_info>::iterator it_qos_client;
	int eth_index;
	int v6_num = 0;

	eth_index = get_eth_client_index(client_mac, vlan_id);
	if (eth_index == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Attempting to delete qos entry for client at idx %d"
		" with vlan %d\n", eth_index, vlan_id);

	for (it_qos_client = qos_param->qos_client_list.begin();
		it_qos_client != qos_param->qos_client_list.end(); )
	{
		if (qos_param->ip_type == IPA_IP_v4)
		{
			if (it_qos_client->v4_ip_addr &&
				(it_qos_client->v4_ip_addr ==
					get_client_memptr(eth_client, eth_index)->v4_addr))
			{
				IPACMDBG_H("Found a matching vlan %d entry in qos rule list "
					"for client with ipv4: 0x\n",
					vlan_id, it_qos_client->v4_ip_addr);

				//Delete the respective route handles
				IPACMDBG_H("Delete client rule from index %d is v4 set %d for hdl %d\n",
					eth_index, it_qos_client->route_rule_set_v4,
					it_qos_client->qos_rt_rule_hdl_v4);

				if (it_qos_client->route_rule_set_v4 &&
					(m_routing.DeleteRoutingHdl(it_qos_client->qos_rt_rule_hdl_v4,
						IPA_IP_v4) == false)) {
					IPACMERR("Failed to delete v4 qos routing rule hdl %d\n",
						it_qos_client->qos_rt_rule_hdl_v4);
					return IPACM_FAILURE;
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
				for (auto it = rt_hdl_v6_list[eth_index].begin(); it != rt_hdl_v6_list[eth_index].end(); ++it)
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
						" v6 set %d for hdl %d\n", eth_index,
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
					" v6 set %d for hdl %d\n", eth_index,
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

int IPACM_Lan::delete_client_qos_rule(uint8_t *client_mac, uint16_t vlan_id,
	ipa_ip_type iptype, uint32_t *ipv6_addr)
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
		delete_client_info_from_qos(client_mac, vlan_id, it_qos_params, ipv6_addr);
	}

	pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->qos_param_list_lock);
	return IPACM_SUCCESS;
}

int IPACM_Lan::delete_all_client_info_from_qos(list<qos_param_info>::iterator qos_param)
{
	list<qos_client_info>::iterator it_qos_client;
	int ret = IPACM_SUCCESS;

	for (it_qos_client = qos_param->qos_client_list.begin();
		it_qos_client != qos_param->qos_client_list.end(); )
	{
		//Delete the respective route handles
		IPACMDBG_H("Delete client rule from is v4 set %d for hdl %d\n",
				   it_qos_client->route_rule_set_v4, it_qos_client->qos_rt_rule_hdl_v4);

		if (it_qos_client->route_rule_set_v4 &&
			(m_routing.DeleteRoutingHdl(it_qos_client->qos_rt_rule_hdl_v4, IPA_IP_v4) == false)) {
			IPACMERR("Failed to delete v4 qos routing rule hdl %d\n", it_qos_client->qos_rt_rule_hdl_v4);
			ret =  IPACM_FAILURE;
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

		it_qos_client = qos_param->qos_client_list.erase(it_qos_client);
		qos_param->client_cnt--;
	}

	IPACMDBG_H("Qos client list size:%d cnt %d\n",
		qos_param->qos_client_list.size(), qos_param->client_cnt);
	return ret;
}

int IPACM_Lan::delete_all_client_qos_rules()
{
	list<qos_param_info>::iterator it_qos_params;

	IPACMDBG_H("Deleting all client rules from qos config\n");
	if(pthread_mutex_lock(&IPACM_Iface::ipacmcfg->qos_param_list_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return IPACM_FAILURE;
	}

	for (it_qos_params = IPACM_Iface::ipacmcfg->m_qos_params.begin(); it_qos_params != IPACM_Iface::ipacmcfg->m_qos_params.end(); ++it_qos_params)
	{
		delete_all_client_info_from_qos(it_qos_params);
	}

	IPACMDBG_H("Qos params list size after deleting client is now :%d \n", IPACM_Iface::ipacmcfg->m_qos_params.size());
	pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->qos_param_list_lock);
	return IPACM_SUCCESS;
}

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
void IPACM_Lan::handle_stats_client_connect(int if_index, uint8_t *mac_addr)
{
	int ipa_interface_index = -1;

	ipa_interface_index = iface_ipa_index_query(if_index);
	if (ipa_interface_index == ipa_if_num)
	{
		IPACMDBG_H("Received IPA_LAN_CLIENT_CONNECT_EVENT\n");
		/* Check if we can add this to the active list. */
		/* Active List:- Clients for which index is less than IPA_MAX_NUM_HW_PATH_CLIENTS. */
		if (get_free_active_lan_stats_index(mac_addr) == -1)
		{
			IPACMDBG_H("Failed to reserve active lan_stats index, try inactive list. \n");
			/* Try to get the inactive index which can be used later. */
			if (get_free_inactive_lan_stats_index(mac_addr) == -1)
			{
				IPACMDBG_H("Failed to reserve inactive lan_stats index, return\n");
			}
			return;
		}
		/* Check if the client is inactive list and remove it*/
		if (reset_inactive_lan_stats_index(mac_addr) == -1)
		{
			IPACMDBG_H("Failed to reset inactive lan_stats index, return\n");
		}
		/* Check if the client is already initialized and add filter/routing rules. */
		IPACM_Lan::handle_lan_client_connect(mac_addr);
	}

}
int IPACM_Lan::handle_lan_client_connect(uint8_t *mac_addr)
{
	int eth_index, res = IPACM_SUCCESS;
	ipacm_ext_prop* ext_prop;
	struct wan_ioctl_lan_client_info *client_info;
#ifdef IPA_HW_FNR_STATS
	uint8_t cnt_idx;
#endif //IPA_HW_FNR_STATS
#ifdef FEATURE_STATIC_POLICY
	uint32_t temp_ipv6[4] = {0};
#endif

	IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
			mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5]);

	eth_index = get_eth_client_index(mac_addr);
	if (eth_index == IPACM_INVALID_INDEX)
	{
		IPACMDBG_H("wlan client not found/attached \n");
		return IPACM_SUCCESS;
	}

	if (get_client_memptr(eth_client, eth_index)->lan_stats_idx != -1)
	{
		IPACMDBG_H("wlan client already has lan_stats index. \n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H ("Is ODU client? %s\n", is_odu?"Yes":"No");
	get_client_memptr(eth_client, eth_index)->lan_stats_idx = get_lan_stats_index(mac_addr);

	if (get_client_memptr(eth_client, eth_index)->lan_stats_idx == -1)
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
		if (ipa_if_cate == LAN_IF)
		{
			client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_USB;
		}
		else if (ipa_if_cate == ODU_IF && is_odu == true)
		{
			client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_ODU;
		}
		else if (ipa_if_cate == ODU_IF)
		{
#ifdef DUAL_NIC_OFFLOAD
			if (strstr(dev_name, STR_ETH1_IFACE))
				client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_ETH1;
			else
#endif
				client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_ETH;
		}
		else
		{
			IPACMERR("Unsupported interface category: %d\n", ipa_if_cate);
			res = IPACM_FAILURE;
			goto fail;
		}
		memcpy(client_info->mac,
				get_client_memptr(eth_client, eth_index)->mac,
				IPA_MAC_ADDR_SIZE);
		client_info->client_init = 1;
		client_info->client_idx = get_client_memptr(eth_client, eth_index)->lan_stats_idx;
		client_info->ul_src_pipe = (enum ipa_client_type) IPA_CLIENT_MAX;
		client_info->hdr_len = hdr_len;
		if (rx_prop)
		{
			client_info->ul_src_pipe = rx_prop->rx[0].src_pipe;
		}
#ifdef IPA_HW_FNR_STATS
		/* Set UL and DL cnt_idx based on version check */
		if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support && !get_client_memptr(eth_client, eth_index)->index_populated) {
			pthread_mutex_lock(&IPACM_Iface::ipacmcfg->cnt_idx_lock);
			cnt_idx = IPACM_Iface::ipacmcfg->get_free_cnt_idx();
			pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->cnt_idx_lock);
			if (cnt_idx == -1)
			{
				IPACMERR("Got invalid cnt_idx. Abort\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			client_info->ul_cnt_idx = cnt_idx;
			client_info->dl_cnt_idx = cnt_idx + 1;
			/* Store this in the client specific strcuture */
			get_client_memptr(eth_client, eth_index)->dl_cnt_idx = client_info->dl_cnt_idx;
			get_client_memptr(eth_client, eth_index)->ul_cnt_idx = client_info->ul_cnt_idx;
			get_client_memptr(eth_client, eth_index)->index_populated = true;
			IPACMDBG_H("Got lan connect event. UL/DL indices set %u, %u\n", client_info->ul_cnt_idx, client_info->dl_cnt_idx);
		}
#endif //IPA_HW_FNR_STATS
		if (set_lan_client_info(client_info))
		{
			res = IPACM_FAILURE;
			free(client_info);
			goto fail;
		}
		free(client_info);

		//if IPACM is in static policy mode, we will install rules later based on conntrack evt
		if (IPACM_Wan::isWanUP(ipa_if_num) ||
			(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && IPACM_Wan::isVlanWanUP()))
		{
			if(IPACM_Wan::backhaul_is_sta_mode == false)
			{
				ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v4);
#ifdef IPA_HW_FNR_STATS
				if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
						install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v4, IPACM_Wan::getXlat_Mux_Id(),
							get_client_memptr(eth_client, eth_index)->mac,
							get_client_memptr(eth_client, eth_index)->ul_cnt_idx);
				else
#endif //IPA_HW_FNR_STATS
					install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v4, IPACM_Wan::getXlat_Mux_Id(), get_client_memptr(eth_client, eth_index)->mac);
				get_client_memptr(eth_client, eth_index)->ipv4_ul_rules_set = true;
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
				ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);
#ifdef IPA_HW_FNR_STATS
				if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
					install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v6, 0, get_client_memptr(eth_client, eth_index)->mac,
							get_client_memptr(eth_client, eth_index)->ul_cnt_idx);
				else
#endif //IPA_HW_FNR_STATS
					install_uplink_filter_rule_per_client(ext_prop, IPA_IP_v6, 0, get_client_memptr(eth_client, eth_index)->mac);
				get_client_memptr(eth_client, eth_index)->ipv6_ul_rules_set = true;
			}
		}
#ifdef IPA_HW_FNR_STATS
		if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support) {
			handle_eth_client_route_rule_ext_v2(get_client_memptr(eth_client, eth_index)->mac, IPA_IP_v4,
				get_client_memptr(eth_client, eth_index)->dl_cnt_idx);
			handle_eth_client_route_rule_ext_v2(get_client_memptr(eth_client, eth_index)->mac, IPA_IP_v6,
				get_client_memptr(eth_client, eth_index)->dl_cnt_idx);
#ifdef FEATURE_STATIC_POLICY
			if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
			{
				handle_pdn_dscp_eth_client_route_rule_ext_v2(get_client_memptr(eth_client, eth_index)->mac,
					IPA_IP_v4, 0);
				for (auto it = rt_hdl_v6_list[eth_index].begin(); it != rt_hdl_v6_list[eth_index].end(); ++it)
				{
					std::copy(std::begin(it->first), std::end(it->first), std::begin(temp_ipv6));
					handle_pdn_dscp_eth_client_route_rule_ext_v2(get_client_memptr(eth_client, eth_index)->mac,
					IPA_IP_v6, 0, temp_ipv6);
				}
			}
#endif
		}
		else
#endif //IPA_HW_FNR_STATS
		{
			handle_eth_client_route_rule_ext(get_client_memptr(eth_client, eth_index)->mac, IPA_IP_v4);
			handle_eth_client_route_rule_ext(get_client_memptr(eth_client, eth_index)->mac, IPA_IP_v6);
		}
	}
	return IPACM_SUCCESS;
fail:
	/* Reset the mac from active list. */
	reset_active_lan_stats_index(get_client_memptr(eth_client, eth_index)->lan_stats_idx, mac_addr);
	/* Add the mac to inactive list. */
	get_free_inactive_lan_stats_index(mac_addr);
	get_client_memptr(eth_client, eth_index)->lan_stats_idx = -1;
	return IPACM_FAILURE;
}

int IPACM_Lan::handle_lan_client_disconnect(uint8_t *mac_addr)
{
	int i;
	uint8_t mac[IPA_MAC_ADDR_SIZE];

	IPACMDBG_H ("Is ODU client? %s\n", is_odu?"Yes":"No");

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
	if (get_available_inactive_lan_client(mac) == IPACM_FAILURE)
	{
		IPACMDBG_H("Error in getting in active client.\n");
		return IPACM_FAILURE;
	}

	/* Add the mac to the active list. */
	if (get_free_active_lan_stats_index(mac) == -1)
	{
		IPACMDBG_H("Free active index not available. Abort\n");
		return IPACM_FAILURE;
	}

	/* Remove the mac from inactive list. */
	if (reset_inactive_lan_stats_index(mac) == IPACM_FAILURE)
	{
		IPACMDBG_H("Unable to remove the client from inactive list. Check\n");
	}

	/* Process the new lan stats index. */
	return handle_lan_client_connect(mac);
}

#ifdef IPA_HW_FNR_STATS
int IPACM_Lan::handle_eth_client_route_rule_ext_v2(uint8_t *mac_addr, ipa_ip_type iptype, uint8_t dl_cnt_idx)
{
	struct ipa_ioc_add_rt_rule_ext_v2 *rt_rule;
	struct ipa_rt_rule_add_ext_v2 *rt_rule_entry;
#ifdef FEATURE_IPA_IPSEC
	ipa_ip_type *iptype_p = NULL;
	ipacm_cmd_q_data evt_data;
#endif
	uint32_t tx_index;
	int eth_index,v6_num;
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

	eth_index = get_eth_client_index(mac_addr);
	if (eth_index == IPACM_INVALID_INDEX)
	{
		IPACMDBG_H("eth client not found/attached \n");
		return IPACM_SUCCESS;
	}

	if (get_client_memptr(eth_client, eth_index)->lan_stats_idx == -1)
	{
		IPACMDBG_H("Lan client index not attached. \n");
		return IPACM_SUCCESS;
	}

	if (iptype==IPA_IP_v4) {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv4_set:%d, ipv4_rule_set:%d \n", eth_index, iptype,
					 get_client_memptr(eth_client, eth_index)->ipv4_set,
					 get_client_memptr(eth_client, eth_index)->route_rule_set_v4);
	} else {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv6_set:%d, ipv6_rule_num:%d \n", eth_index, iptype,
					 get_client_memptr(eth_client, eth_index)->ipv6_set,
					 get_client_memptr(eth_client, eth_index)->route_rule_set_v6);
	}
	/* Add default routing rules if not set yet */
	if ((iptype == IPA_IP_v4
			 && get_client_memptr(eth_client, eth_index)->route_rule_set_v4 == false
			 && get_client_memptr(eth_client, eth_index)->ipv4_set == true)
			|| (iptype == IPA_IP_v6
		            && get_client_memptr(eth_client, eth_index)->route_rule_set_v6 < get_client_memptr(eth_client, eth_index)->ipv6_set
					))
	{
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Add corresponding ipa_rm_resource_name of TX-endpoint up before IPV6 RT-rule set */
			IPACMDBG_H("dev %s add producer dependency\n", dev_name);
			if (tx_prop != NULL)
			{
				IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
				IPACM_Iface::ipacmcfg->AddRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe],false);
			}
		}
		rt_rule = (struct ipa_ioc_add_rt_rule_ext_v2 *)
			 calloc(1, sizeof(struct ipa_ioc_add_rt_rule_ext_v2));
		if (rt_rule == NULL)
		{
			IPACMERR("Error allocating ipa_ioc_add_rt_rule memory...\n");
			return IPACM_FAILURE;
		}

		rt_rule->rules = (uintptr_t)calloc(NUM, sizeof(struct ipa_rt_rule_add_ext_v2));
		if (!rt_rule->rules) {
			IPACMERR("Error allocating memory for routing rule\n");
			free(rt_rule);
			return IPACM_FAILURE;
		}

		rt_rule->commit = 1;
		rt_rule->num_rules = (uint8_t)NUM;
		rt_rule->ip = iptype;
		rt_rule->rule_add_ext_size = sizeof(struct ipa_rt_rule_add_ext_v2);
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
			rt_rule_entry->rule.enable_stats = true;
			rt_rule_entry->rule.cnt_idx = dl_cnt_idx;

			if (iptype == IPA_IP_v4)
			{
				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", eth_index,
					get_client_memptr(eth_client, eth_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
						 eth_index,
						 get_client_memptr(eth_client, eth_index)->hdr_hdl_v4);
				strlcpy(rt_rule->rt_tbl_name,
								IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
								sizeof(rt_rule->rt_tbl_name));
				rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
				rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
				memcpy(&rt_rule_entry->rule.attrib,
						 &tx_prop->tx[tx_index].attrib,
						 sizeof(rt_rule_entry->rule.attrib));
				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
				rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v4;
				rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(eth_client, eth_index)->v4_addr;
				rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
				rt_rule_entry->rule.enable_stats = true;
				rt_rule_entry->rule.cnt_idx = dl_cnt_idx;
				rt_rule_entry->rule.hashable = true;
				rt_rule_entry->rule_id = 0;
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
				if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
					if (iptype == IPA_IP_v6)
						rt_rule_entry->rule.ttl_update =
							IPACM_Wan::is_global_ipv6_addr(rt_rule_entry->rule.attrib.u.v6.dst_addr);
					else
						rt_rule_entry->rule.ttl_update = true;
				}
#endif
				IPACMDBG_H("Add v4 route rule table %s\n", rt_rule->rt_tbl_name);
			    if (false == m_routing.AddRoutingRuleExt_v2(rt_rule))
				{
					IPACMERR("Routing rule addition failed!\n");
					free((void *)rt_rule->rules);
					free(rt_rule);
					return IPACM_FAILURE;
			    }

			    /* copy ipv4 RT hdl */
			    get_client_memptr(eth_client, eth_index)->eth_rt_hdl[tx_index].eth_rt_rule_hdl_v4 =
				    ((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[0].rt_rule_hdl;
			    IPACMDBG_H("tx:%d, rt rule id=%x ip-type: %d\n", tx_index,
					    rt_rule_entry->rule_id, iptype);

			    get_client_memptr(eth_client, eth_index)->route_rule_set_v4 = true;
			    /* Add NAT rules after ipv4 RT rules are set */
			    memset(&data, 0, sizeof(data));
			    data.if_index = IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].netlink_interface_index;
			    data.iptype = IPA_IP_v4;
			    data.ipv4_addr = get_client_memptr(eth_client, eth_index)->v4_addr;
			    HandleNeighIpAddrAddEvt(&data);
			} else {
				for (auto it = rt_hdl_v6_list[eth_index].begin(); it != rt_hdl_v6_list[eth_index].end(); ++it)
				{
					if (it->second.route_rule_set_v6 == true)
					{
						IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set (%d)\n",
						eth_index, it->first[0], it->first[1], it->first[2], it->first[3],
						it->second.route_rule_set_v6);
						continue;
					}

					IPACMDBG_H("client(%d): v6 header handle:(0x%x)\n",
							eth_index,
							get_client_memptr(eth_client, eth_index)->hdr_hdl_v6);
					/* v6 LAN_RT_TBL */
					strlcpy(rt_rule->rt_tbl_name,
							IPACM_Iface::ipacmcfg->rt_tbl_v6.name,
							sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Support QCMAP LAN traffic feature, send to A5 */
					rt_rule_entry->rule.dst = IPA_CLIENT_APPS_LAN_CONS;
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
					rt_rule_entry->rule.cnt_idx = dl_cnt_idx;
					rt_rule_entry->rule.hashable = true;
					rt_rule_entry->rule_id = 0;
					IPACMERR("Add v6 route rule table nanme = %s\n", rt_rule->rt_tbl_name);
					if (false == m_routing.AddRoutingRuleExt_v2(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						free((void *)rt_rule->rules);
						free(rt_rule);
						return IPACM_FAILURE;
					}

					it->second.hdl_v6[tx_index].rt_rule_hdl_v6 = ((struct ipa_rt_rule_add_ext_v2 *)rt_rule->rules)[0].rt_rule_hdl;
					IPACMDBG_H("tx:%d, rt rule id=%x, rt rule hdl=%x ip-type: %d\n", tx_index,
						rt_rule_entry->rule_id,
						it->second.hdl_v6[tx_index].rt_rule_hdl_v6, iptype);

					/*Copy same rule to v6 WAN RT TBL*/
					strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Downlink traffic from Wan iface, directly through IPA */
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
					memcpy(&rt_rule_entry->rule.attrib,
							&tx_prop->tx[tx_index].attrib,
							sizeof(rt_rule_entry->rule.attrib));
					rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v6;
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
					rt_rule_entry->rule.cnt_idx = dl_cnt_idx;
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
					if ((tx_index + 1 == iface_query->num_tx_props) ||
						IPACM_Iface::ipacmcfg->ipacm_qos_enable)
						it->second.route_rule_set_v6 = true;

					IPACMDBG_H("tx:%d, rt rule id=%x, rt rule hdl=%x ip-type: %d route_rule_set_v6(map) %d\n", tx_index,
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
					HandleNeighIpAddrAddEvt(&data);
				}
				IPACMDBG_H("rt rule entry enable stats = %d, dl cnt index = %u\n", rt_rule_entry->rule.enable_stats, rt_rule_entry->rule.cnt_idx);
			} /* end of for loop */
		} /* end of tx loop */
		get_client_memptr(eth_client, eth_index)->route_rule_set_v6 = get_client_memptr(eth_client, eth_index)->ipv6_set;
		free((void *)rt_rule->rules);
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

/* handle eth client routing rule with rule id */
int IPACM_Lan::handle_eth_client_route_rule_ext(uint8_t *mac_addr, ipa_ip_type iptype)
{
	struct ipa_ioc_add_rt_rule_ext *rt_rule;
	struct ipa_rt_rule_add_ext *rt_rule_entry;
#ifdef FEATURE_IPA_IPSEC
	ipa_ip_type *iptype_p = NULL;
	ipacm_cmd_q_data evt_data;
#endif
	uint32_t tx_index;
	int eth_index,v6_num;
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

	eth_index = get_eth_client_index(mac_addr);
	if (eth_index == IPACM_INVALID_INDEX)
	{
		IPACMDBG_H("eth client not found/attached \n");
		return IPACM_SUCCESS;
	}

	if (get_client_memptr(eth_client, eth_index)->lan_stats_idx == -1)
	{
		IPACMDBG_H("Lan client index not attached. \n");
		return IPACM_SUCCESS;
	}

	if (iptype==IPA_IP_v4) {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv4_set:%d, ipv4_rule_set:%d \n", eth_index, iptype,
					 get_client_memptr(eth_client, eth_index)->ipv4_set,
					 get_client_memptr(eth_client, eth_index)->route_rule_set_v4);
	} else {
		IPACMDBG_H("eth client index: %d, ip-type: %d, ipv6_set:%d, ipv6_rule_num:%d \n", eth_index, iptype,
					 get_client_memptr(eth_client, eth_index)->ipv6_set,
					 get_client_memptr(eth_client, eth_index)->route_rule_set_v6);
	}
	/* Add default routing rules if not set yet */
	if ((iptype == IPA_IP_v4
			 && get_client_memptr(eth_client, eth_index)->route_rule_set_v4 == false
			 && get_client_memptr(eth_client, eth_index)->ipv4_set == true)
			|| (iptype == IPA_IP_v6
		            && get_client_memptr(eth_client, eth_index)->route_rule_set_v6 < get_client_memptr(eth_client, eth_index)->ipv6_set
					))
	{
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Add corresponding ipa_rm_resource_name of TX-endpoint up before IPV6 RT-rule set */
			IPACMDBG_H("dev %s add producer dependency\n", dev_name);
			if (tx_prop != NULL)
			{
				IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
				IPACM_Iface::ipacmcfg->AddRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe],false);
			}
		}
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
			if (IPACM_Iface::ipacmcfg->ipacm_qos_enable && tx_index >= 2)
			{
				IPACMDBG_H("Qos is enabled, install client rule only on default pipe, current tx_idx %d\n",tx_index);
				continue;
			}

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
				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", eth_index,
					get_client_memptr(eth_client, eth_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
						 eth_index,
						 get_client_memptr(eth_client, eth_index)->hdr_hdl_v4);
				strlcpy(rt_rule->rt_tbl_name,
								IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
								sizeof(rt_rule->rt_tbl_name));
				rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
				rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
				memcpy(&rt_rule_entry->rule.attrib,
						 &tx_prop->tx[tx_index].attrib,
						 sizeof(rt_rule_entry->rule.attrib));
				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
				rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v4;
				rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(eth_client, eth_index)->v4_addr;
				rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;

				if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
				{
					rt_rule_entry->rule.hashable = true;
				}

				rt_rule_entry->rule_id = 0;
				rt_rule_entry->rule_id = (get_client_memptr(eth_client, eth_index)->lan_stats_idx) | 0x300;
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
		        get_client_memptr(eth_client, eth_index)->eth_rt_hdl[tx_index].eth_rt_rule_hdl_v4 =
				rt_rule->rules[0].rt_rule_hdl;
		        IPACMDBG_H("tx:%d, rt rule id=%x ip-type: %d\n", tx_index,
				rt_rule_entry->rule_id, iptype);

				get_client_memptr(eth_client, eth_index)->route_rule_set_v4 = true;
				/* Add NAT rules after ipv4 RT rules are set */
				memset(&data, 0, sizeof(data));
				data.if_index = IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].netlink_interface_index;
				data.iptype = IPA_IP_v4;
				data.ipv4_addr = get_client_memptr(eth_client, eth_index)->v4_addr;
				HandleNeighIpAddrAddEvt(&data);
			} else {
				for (auto it = rt_hdl_v6_list[eth_index].begin(); it != rt_hdl_v6_list[eth_index].end(); ++it)
				{
					if (it->second.route_rule_set_v6 == true)
					{
						IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set (%d)\n",
						eth_index, it->first[0], it->first[1], it->first[2], it->first[3],
						it->second.route_rule_set_v6);
						continue;
					}

                    IPACMDBG_H("client(%d): v6 header handle:(0x%x)\n", eth_index, get_client_memptr(eth_client, eth_index)->hdr_hdl_v6);

		            /* v6 LAN_RT_TBL */
				strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_v6.name, sizeof(rt_rule->rt_tbl_name));
				rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
		            /* Support QCMAP LAN traffic feature, send to A5 */
					rt_rule_entry->rule.dst = IPA_CLIENT_APPS_LAN_CONS;
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
					IPACMDBG_H("tx:%d, rt rule id=%x, rt rule hdl=%x, ip-type: %d\n", tx_index,
						rt_rule_entry->rule_id, it->second.hdl_v6[tx_index].rt_rule_hdl_v6, iptype);

			        /*Copy same rule to v6 WAN RT TBL*/
				strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule->rt_tbl_name));
				rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
				/* Downlink traffic from Wan iface, directly through IPA */
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
			        memcpy(&rt_rule_entry->rule.attrib,
						 &tx_prop->tx[tx_index].attrib,
						 sizeof(rt_rule_entry->rule.attrib));
		   	        rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v6;
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
					rt_rule_entry->rule_id = get_client_memptr(eth_client, eth_index)->lan_stats_idx | 0x300;
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
					if ((tx_index + 1 == iface_query->num_tx_props) ||
						IPACM_Iface::ipacmcfg->ipacm_qos_enable)
						it->second.route_rule_set_v6 = true;

					IPACMDBG_H("tx:%d, rt rule id=%x, rt rule hdl=%x ip-type: %d route_rule_set_v6(map) %d\n", tx_index,
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
					HandleNeighIpAddrAddEvt(&data);
				}
			} /* end of for loop */
		} /* end of tx loop */
		get_client_memptr(eth_client, eth_index)->route_rule_set_v6 = get_client_memptr(eth_client, eth_index)->ipv6_set;
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
#endif

/* handle odu client initial, construct full headers (tx property) */
int IPACM_Lan::handle_odu_hdr_init(uint8_t *mac_addr)
{
#define ETH_IFACE_INDEX_LEN 10

	int res = IPACM_SUCCESS, len = 0;
	struct ipa_ioc_copy_hdr sCopyHeader;
	struct ipa_ioc_add_hdr *pHeaderDescriptor = NULL;
	uint32_t cnt;
	char index[ETH_IFACE_INDEX_LEN];

	IPACMDBG("Received Client MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 mac_addr[0], mac_addr[1], mac_addr[2],
					 mac_addr[3], mac_addr[4], mac_addr[5]);

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

		/* copy partial header for v4*/
		for (cnt=0; cnt<tx_prop->num_tx_props; cnt++)
		{
				if(tx_prop->tx[cnt].ip==IPA_IP_v4 && !ipv4_header_set)
				{
					IPACMDBG("Got partial v4-header name from %d tx props\n", cnt);
					memset(&sCopyHeader, 0, sizeof(sCopyHeader));
					memcpy(sCopyHeader.name, tx_prop->tx[cnt].hdr_name, sizeof(sCopyHeader.name));
					IPACMDBG("header name: %s in tx:%d\n", sCopyHeader.name,cnt);
					if (m_header.CopyHeader(&sCopyHeader) == false)
					{
						PERROR("ioctl copy header failed");
						res = IPACM_FAILURE;
						goto fail;
					}
					IPACMDBG("header length: %d, partial: %d\n", sCopyHeader.hdr_len, sCopyHeader.is_partial);
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
					/* copy client mac_addr to partial header */
					if (sCopyHeader.is_eth2_ofst_valid)
					{
						memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst],
								mac_addr,
								IPA_MAC_ADDR_SIZE);
					}
					/* replace src mac to bridge mac_addr if any  */
					if (IPACM_Iface::ipacmcfg->ipa_bridge_enable)
					{
						memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst+IPA_MAC_ADDR_SIZE],
								IPACM_Iface::ipacmcfg->bridge_mac,
								IPA_MAC_ADDR_SIZE);
						IPACMDBG_H("device is in bridge mode \n");
					}

					pHeaderDescriptor->commit = true;
					pHeaderDescriptor->num_hdrs = 1;

					memset(pHeaderDescriptor->hdr[0].name, 0,
								 sizeof(pHeaderDescriptor->hdr[0].name));

					pHeaderDescriptor->hdr[0].hdr_len = sCopyHeader.hdr_len;
					pHeaderDescriptor->hdr[0].type = sCopyHeader.type;
					pHeaderDescriptor->hdr[0].hdr_hdl = -1;
					pHeaderDescriptor->hdr[0].is_partial = 0;
					pHeaderDescriptor->hdr[0].status = -1;

					/* add interface num to the header name */
					snprintf(index,sizeof(index), "%d_", ipa_if_num);
					strlcpy(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name));
					pHeaderDescriptor->hdr[0].name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					if (strlcat(pHeaderDescriptor->hdr[0].name, IPA_ODU_HDR_NAME_v4, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
					{
						IPACMERR(" header name construction failed exceed length (%zu)\n", strlen(pHeaderDescriptor->hdr[0].name));
						res = IPACM_FAILURE;
						goto fail;
					}

					 if (m_header.AddHeader(pHeaderDescriptor) == false ||
							pHeaderDescriptor->hdr[0].status != 0)
					 {
						IPACMERR("ioctl IPA_IOC_ADD_HDR failed: %d\n", pHeaderDescriptor->hdr[0].status);
						res = IPACM_FAILURE;
						goto fail;
					 }

					ODU_hdr_hdl_v4 = pHeaderDescriptor->hdr[0].hdr_hdl;
					ipv4_header_set = true;
					IPACMDBG(" ODU v4 full header name:%s header handle:(0x%x)\n",
						pHeaderDescriptor->hdr[0].name,
						ODU_hdr_hdl_v4);
					break;
				}
		}


		/* copy partial header for v6*/
		for (cnt=0; cnt<tx_prop->num_tx_props; cnt++)
		{
			if(tx_prop->tx[cnt].ip==IPA_IP_v6 && !ipv6_header_set)
			{

				IPACMDBG("Got partial v6-header name from %d tx props\n", cnt);
				memset(&sCopyHeader, 0, sizeof(sCopyHeader));
				memcpy(sCopyHeader.name, tx_prop->tx[cnt].hdr_name, sizeof(sCopyHeader.name));

				IPACMDBG("header name: %s in tx:%d\n", sCopyHeader.name,cnt);
				if (m_header.CopyHeader(&sCopyHeader) == false)
				{
					PERROR("ioctl copy header failed");
					res = IPACM_FAILURE;
					goto fail;
				}

				IPACMDBG("header length: %d, partial: %d\n", sCopyHeader.hdr_len, sCopyHeader.is_partial);
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

				/* copy client mac_addr to partial header */
				if (sCopyHeader.is_eth2_ofst_valid)
				{
					memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst],
						mac_addr,
						IPA_MAC_ADDR_SIZE);
				}
				/* replace src mac to bridge mac_addr if any  */
				if (IPACM_Iface::ipacmcfg->ipa_bridge_enable)
				{
					memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst+IPA_MAC_ADDR_SIZE],
							IPACM_Iface::ipacmcfg->bridge_mac,
							IPA_MAC_ADDR_SIZE);
					IPACMDBG_H("device is in bridge mode \n");
				}

				pHeaderDescriptor->commit = true;
				pHeaderDescriptor->num_hdrs = 1;

				memset(pHeaderDescriptor->hdr[0].name, 0,
					 sizeof(pHeaderDescriptor->hdr[0].name));

				pHeaderDescriptor->hdr[0].hdr_len = sCopyHeader.hdr_len;
				pHeaderDescriptor->hdr[0].type = sCopyHeader.type;
				pHeaderDescriptor->hdr[0].hdr_hdl = -1;
				pHeaderDescriptor->hdr[0].is_partial = 0;
				pHeaderDescriptor->hdr[0].status = -1;

				/* add interface num to the header name */
				snprintf(index,sizeof(index), "%d_", ipa_if_num);
				strlcpy(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name));
				pHeaderDescriptor->hdr[0].name[IPA_RESOURCE_NAME_MAX-1] = '\0';
				if (strlcat(pHeaderDescriptor->hdr[0].name, IPA_ODU_HDR_NAME_v6, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
				{
					IPACMERR(" header name construction failed exceed length (%zu)\n", strlen(pHeaderDescriptor->hdr[0].name));
					res = IPACM_FAILURE;
					goto fail;
				}

				if (m_header.AddHeader(pHeaderDescriptor) == false ||
						pHeaderDescriptor->hdr[0].status != 0)
				{
					IPACMERR("ioctl IPA_IOC_ADD_HDR failed: %d\n", pHeaderDescriptor->hdr[0].status);
					res = IPACM_FAILURE;
					goto fail;
				}
				ODU_hdr_hdl_v6 = pHeaderDescriptor->hdr[0].hdr_hdl;
				ipv6_header_set = true;
				IPACMDBG(" ODU v6 full header name:%s header handle:(0x%x)\n",
						pHeaderDescriptor->hdr[0].name,
						ODU_hdr_hdl_v6);
				break;
			}
		}
	}
fail:
	free(pHeaderDescriptor);
	return res;
}


/* handle odu default route rule configuration */
int IPACM_Lan::handle_odu_route_add()
{
	/* add default WAN route */
	struct ipa_ioc_add_rt_rule *rt_rule;
	struct ipa_rt_rule_add *rt_rule_entry;
	uint32_t tx_index;
	const int NUM = 1;

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


	IPACMDBG_H("WAN table created %s \n", rt_rule->rt_tbl_name);
	rt_rule_entry = &rt_rule->rules[0];
	rt_rule_entry->at_rear = true;

	for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
	{

		if (IPA_IP_v4 == tx_prop->tx[tx_index].ip)
		{
			strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_odu_v4.name, sizeof(rt_rule->rt_tbl_name));
			rt_rule_entry->rule.hdr_hdl = ODU_hdr_hdl_v4;
			rt_rule->ip = IPA_IP_v4;
		}
		else
		{
			strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_odu_v6.name, sizeof(rt_rule->rt_tbl_name));
			rt_rule_entry->rule.hdr_hdl = ODU_hdr_hdl_v6;
			rt_rule->ip = IPA_IP_v6;
		}

		rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
		memcpy(&rt_rule_entry->rule.attrib,
					 &tx_prop->tx[tx_index].attrib,
					 sizeof(rt_rule_entry->rule.attrib));

		rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
		if (IPA_IP_v4 == tx_prop->tx[tx_index].ip)
		{
			rt_rule_entry->rule.attrib.u.v4.dst_addr      = 0;
			rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0;
#ifdef FEATURE_IPA_V3
			rt_rule_entry->rule.hashable = true;
#endif
			if (false == m_routing.AddRoutingRule(rt_rule))
			{
				IPACMERR("Routing rule addition failed!\n");
				free(rt_rule);
				return IPACM_FAILURE;
			}
			odu_route_rule_v4_hdl[tx_index] = rt_rule_entry->rt_rule_hdl;
			IPACMDBG_H("Got ipv4 ODU-route rule hdl:0x%x,tx:%d,ip-type: %d \n",
						 odu_route_rule_v4_hdl[tx_index],
						 tx_index,
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
			if (false == m_routing.AddRoutingRule(rt_rule))
			{
				IPACMERR("Routing rule addition failed!\n");
				free(rt_rule);
				return IPACM_FAILURE;
			}
			odu_route_rule_v6_hdl[tx_index] = rt_rule_entry->rt_rule_hdl;
			IPACMDBG_H("Set ipv6 ODU-route rule hdl for v6_lan_table:0x%x,tx:%d,ip-type: %d \n",
					odu_route_rule_v6_hdl[tx_index],
					tx_index,
					IPA_IP_v6);
		}
	}
	free(rt_rule);
	return IPACM_SUCCESS;
}

/* handle odu default route rule deletion */
int IPACM_Lan::handle_odu_route_del()
{
	uint32_t tx_index;

	if(tx_prop == NULL)
	{
		IPACMDBG_H("No tx properties, ignore delete default route setting\n");
		return IPACM_SUCCESS;
	}

	for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
	{
		if (tx_prop->tx[tx_index].ip == IPA_IP_v4)
		{
			IPACMDBG_H("Tx:%d, ip-type: %d match ip-type: %d, RT-rule deleted\n",
					tx_index, tx_prop->tx[tx_index].ip,IPA_IP_v4);

			if (m_routing.DeleteRoutingHdl(odu_route_rule_v4_hdl[tx_index], IPA_IP_v4)
					== false)
			{
				IPACMERR("IP-family:%d, Routing rule(hdl:0x%x) deletion failed with tx_index %d!\n", IPA_IP_v4, odu_route_rule_v4_hdl[tx_index], tx_index);
				return IPACM_FAILURE;
			}
		}
		else
		{
			IPACMDBG_H("Tx:%d, ip-type: %d match ip-type: %d, RT-rule deleted\n",
					tx_index, tx_prop->tx[tx_index].ip,IPA_IP_v6);

			if (m_routing.DeleteRoutingHdl(odu_route_rule_v6_hdl[tx_index], IPA_IP_v6)
					== false)
			{
				IPACMERR("IP-family:%d, Routing rule(hdl:0x%x) deletion failed with tx_index %d!\n", IPA_IP_v6, odu_route_rule_v6_hdl[tx_index], tx_index);
				return IPACM_FAILURE;
			}
		}
	}

	return IPACM_SUCCESS;
}

/*handle eth client del mode*/
int IPACM_Lan::handle_eth_client_down_evt(uint8_t *mac_addr, uint16_t vlan_id, ipacm_event_data_all *data)
{
	int clt_indx;
	uint32_t tx_index;
	int num_eth_client_tmp = num_eth_client;
	int num_v6;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	struct wan_ioctl_lan_client_info *client_info;
#endif

	IPACMDBG_H("total client: %d\n", num_eth_client_tmp);

	clt_indx = get_eth_client_index(mac_addr, vlan_id);
	if (clt_indx == IPACM_INVALID_INDEX)
	{
		IPACMDBG_H("eth client not attached\n");
		return IPACM_SUCCESS;
	}

	if (get_client_memptr(eth_client, clt_indx)->ipv4_set &&
		get_client_memptr(eth_client, clt_indx)->v4_addr &&
		data->ipv4_addr)
	{
		if (data->ipv4_addr != get_client_memptr(eth_client, clt_indx)->v4_addr)
		{
			IPACMERR("IPv4 address not matching, do not delete: %d\n", clt_indx);
			return IPACM_FAILURE;
		}
	}

	/* First reset NAT rules and then route rules */
	HandleNeighIpAddrDelEvt(clt_indx);

	if (delete_eth_rtrules(clt_indx, IPA_IP_v4))
	{
		IPACMERR("unbale to delete ecm-client v4 route rules for index: %d\n", clt_indx);
		return IPACM_FAILURE;
	}

	if (delete_eth_rtrules(clt_indx, IPA_IP_v6))
	{
		IPACMERR("unbale to delete ecm-client v6 route rules for index: %d\n", clt_indx);
		return IPACM_FAILURE;
	}

#ifdef FEATURE_STATIC_POLICY
	if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
	{
		delete_pdn_dscp_eth_rtrules(IPA_IP_v4, 2, clt_indx);
		delete_pdn_dscp_eth_rtrules(IPA_IP_v6, 2, clt_indx);
	}
#endif

	//delete ext route rules if set
	if(get_client_memptr(eth_client, clt_indx)->ext_router_prefix_rt_hdl)
	{
		IPACMDBG("deleting rt_rule_hdl = %d\n", get_client_memptr(eth_client, clt_indx)->ext_router_prefix_rt_hdl);
		if(m_routing.DeleteRoutingHdl(get_client_memptr(eth_client, clt_indx)->ext_router_prefix_rt_hdl, IPA_IP_v6) == false)
		{
			IPACMERR("Failed to del ext_route rt_rule\n");
			return IPACM_FAILURE;
		}
		get_client_memptr(eth_client, clt_indx)->ext_router_prefix_rt_hdl = 0; //do we need or will it be cleared automatically?
	}

	/* Delete eth client header */
	if(get_client_memptr(eth_client, clt_indx)->ipv4_header_set == true)
	{
		if (m_header.DeleteHeaderHdl(get_client_memptr(eth_client, clt_indx)->hdr_hdl_v4)
				== false)
		{
			return IPACM_FAILURE;
		}
		get_client_memptr(eth_client, clt_indx)->ipv4_header_set = false;
	}

	if(get_client_memptr(eth_client, clt_indx)->ipv6_header_set == true)
	{
		if (m_header.DeleteHeaderHdl(get_client_memptr(eth_client, clt_indx)->hdr_hdl_v6)
				== false)
		{
			return IPACM_FAILURE;
		}
		get_client_memptr(eth_client, clt_indx)->ipv6_header_set = false;
	}

#ifdef IPA_IOC_SET_SW_FLT
	/* clean-up the tether-client-list */
	IPACM_Iface::ipacmcfg->update_client_info(get_client_memptr(eth_client, clt_indx)->mac, NULL, false);
#endif

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	if (get_client_memptr(eth_client, clt_indx)->ipv4_ul_rules_set == true)
	{
		if (delete_uplink_filter_rule_per_client(IPA_IP_v4, get_client_memptr(eth_client, clt_indx)->mac))
		{
			IPACMERR("unbale to delete uplink v4 filter rules for index: %d\n", clt_indx);
			return IPACM_FAILURE;
		}
	}

	if (get_client_memptr(eth_client, clt_indx)->ipv6_ul_rules_set == true)
	{
		if (delete_uplink_filter_rule_per_client(IPA_IP_v6, get_client_memptr(eth_client, clt_indx)->mac))
		{
			IPACMERR("unbale to delete uplink v6 filter rules for index: %d\n", clt_indx);
			return IPACM_FAILURE;
		}
	}
#endif

	IPACMDBG_H("client %d has %d ipv6 with rt: %d, current total_v6=%d \n", clt_indx,
		get_client_memptr(eth_client, clt_indx)->ipv6_set,
		get_client_memptr(eth_client, clt_indx)->route_rule_set_v6,
		IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
	IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6 -= get_client_memptr(eth_client, clt_indx)->ipv6_set;
	IPACMDBG_H("update ipa_num_clients_ipv6 = %d\n", IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
	rt_hdl_v6_list[clt_indx].clear();

	/* Reset ip_set to 0*/
	get_client_memptr(eth_client, clt_indx)->ipv4_set = false;
	get_client_memptr(eth_client, clt_indx)->ipv6_set = 0;
	get_client_memptr(eth_client, clt_indx)->ipv4_header_set = false;
	get_client_memptr(eth_client, clt_indx)->ipv6_header_set = false;
	get_client_memptr(eth_client, clt_indx)->route_rule_set_v4 = false;
	get_client_memptr(eth_client, clt_indx)->route_rule_set_v6 = 0;
	get_client_memptr(eth_client, clt_indx)->gre_nat_set = false;
#ifdef FEATURE_VLAN_MPDN
	get_client_memptr(eth_client, clt_indx)->vlan_id = 0;
#endif
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	get_client_memptr(eth_client, clt_indx)->ipv4_ul_rules_set = false;
	get_client_memptr(eth_client, clt_indx)->ipv6_ul_rules_set = false;
	if (get_client_memptr(eth_client, clt_indx)->lan_stats_idx != -1)
	{
		/* Clear the lan client info. */
		client_info = (struct wan_ioctl_lan_client_info *)malloc(sizeof(struct wan_ioctl_lan_client_info));
		if (client_info == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			return IPACM_FAILURE;
		}
		memset(client_info, 0, sizeof(struct wan_ioctl_lan_client_info));
		if (ipa_if_cate == LAN_IF)
		{
			client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_USB;
		}
		else if (ipa_if_cate == ODU_IF && is_odu == true)
		{
				client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_ODU;
		}
		else if (ipa_if_cate == ODU_IF)
		{
#ifdef DUAL_NIC_OFFLOAD
			if (strstr(dev_name, STR_ETH1_IFACE))
			{
				client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_ETH1;
			}
			else
#endif
				client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_ETH;
		}
		memcpy(client_info->mac,
				get_client_memptr(eth_client, clt_indx)->mac,
				IPA_MAC_ADDR_SIZE);
		client_info->client_init = 0;
		client_info->client_idx = get_client_memptr(eth_client, clt_indx)->lan_stats_idx;
		client_info->ul_src_pipe = (enum ipa_client_type) IPA_CLIENT_MAX;
#ifdef IPA_HW_FNR_STATS
		if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
		{
			client_info->ul_cnt_idx = get_client_memptr(eth_client, clt_indx)->ul_cnt_idx;
			client_info->dl_cnt_idx = get_client_memptr(eth_client, clt_indx)->dl_cnt_idx;
			get_client_memptr(eth_client, clt_indx)->ul_cnt_idx = -1;
			get_client_memptr(eth_client, clt_indx)->dl_cnt_idx = -1;
			get_client_memptr(eth_client, clt_indx)->index_populated = false;
			pthread_mutex_lock(&IPACM_Iface::ipacmcfg->cnt_idx_lock);
			if (IPACM_Iface::ipacmcfg->reset_cnt_idx(client_info->ul_cnt_idx, false))
				IPACMERR("Failed to reset counter index %u\n", client_info->ul_cnt_idx);
			pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->cnt_idx_lock);
		}
#endif //IPA_HW_FNR_STATS
		if (rx_prop)
		{
			client_info->ul_src_pipe = rx_prop->rx[0].src_pipe;
		}
		clear_lan_client_info(client_info);
		free(client_info);
	}
	get_client_memptr(eth_client, clt_indx)->lan_stats_idx = -1;
	memset(get_client_memptr(eth_client, clt_indx)->wan_ul_fl_rule_hdl_v4, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
	memset(get_client_memptr(eth_client, clt_indx)->wan_ul_fl_rule_hdl_v6, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
#endif

	for (; clt_indx < num_eth_client_tmp - 1; clt_indx++)
	{
		memcpy(get_client_memptr(eth_client, clt_indx)->mac,
					 get_client_memptr(eth_client, (clt_indx + 1))->mac,
					 sizeof(get_client_memptr(eth_client, clt_indx)->mac));

		get_client_memptr(eth_client, clt_indx)->hdr_hdl_v4 = get_client_memptr(eth_client, (clt_indx + 1))->hdr_hdl_v4;
		get_client_memptr(eth_client, clt_indx)->hdr_hdl_v6 = get_client_memptr(eth_client, (clt_indx + 1))->hdr_hdl_v6;
		get_client_memptr(eth_client, clt_indx)->v4_addr = get_client_memptr(eth_client, (clt_indx + 1))->v4_addr;

		get_client_memptr(eth_client, clt_indx)->ipv4_set = get_client_memptr(eth_client, (clt_indx + 1))->ipv4_set;
		get_client_memptr(eth_client, clt_indx)->ipv6_set = get_client_memptr(eth_client, (clt_indx + 1))->ipv6_set;
		get_client_memptr(eth_client, clt_indx)->ipv4_header_set = get_client_memptr(eth_client, (clt_indx + 1))->ipv4_header_set;
		get_client_memptr(eth_client, clt_indx)->ipv6_header_set = get_client_memptr(eth_client, (clt_indx + 1))->ipv6_header_set;

		get_client_memptr(eth_client, clt_indx)->route_rule_set_v4 = get_client_memptr(eth_client, (clt_indx + 1))->route_rule_set_v4;
		get_client_memptr(eth_client, clt_indx)->route_rule_set_v6 = get_client_memptr(eth_client, (clt_indx + 1))->route_rule_set_v6;

		get_client_memptr(eth_client, clt_indx)->gre_nat_set = get_client_memptr(eth_client, (clt_indx + 1))->gre_nat_set;
#ifdef FEATURE_VLAN_MPDN
		get_client_memptr(eth_client, clt_indx)->vlan_id = get_client_memptr(eth_client, (clt_indx + 1))->vlan_id;
#endif

		rt_hdl_v6_list[clt_indx] = rt_hdl_v6_list[clt_indx + 1];

		for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		{
			get_client_memptr(eth_client, clt_indx)->eth_rt_hdl[tx_index].eth_rt_rule_hdl_v4 =
				 get_client_memptr(eth_client, (clt_indx + 1))->eth_rt_hdl[tx_index].eth_rt_rule_hdl_v4;

		}

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		memcpy(get_client_memptr(eth_client, clt_indx)->wan_ul_fl_rule_hdl_v4,
			get_client_memptr(eth_client, clt_indx + 1)->wan_ul_fl_rule_hdl_v4,
			MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
		memcpy(get_client_memptr(eth_client, clt_indx)->wan_ul_fl_rule_hdl_v6,
			get_client_memptr(eth_client, clt_indx + 1)->wan_ul_fl_rule_hdl_v6,
			MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
		get_client_memptr(eth_client, clt_indx)->lan_stats_idx =
			get_client_memptr(eth_client, clt_indx + 1)->lan_stats_idx;
#ifdef IPA_HW_FNR_STATS
		get_client_memptr(eth_client, clt_indx)->ul_cnt_idx =
			get_client_memptr(eth_client, clt_indx + 1)->ul_cnt_idx;
		get_client_memptr(eth_client, clt_indx)->dl_cnt_idx =
			get_client_memptr(eth_client, clt_indx + 1)->dl_cnt_idx;
		get_client_memptr(eth_client, clt_indx)->index_populated =
			get_client_memptr(eth_client, clt_indx + 1)->index_populated;
#endif //IPA_HW_FNR_STATS
#endif
	}
	/* Clean up the last entry */
	rt_hdl_v6_list[num_eth_client_tmp - 1].clear();

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	get_client_memptr(eth_client, clt_indx)->lan_stats_idx = -1;
#ifdef IPA_HW_FNR_STATS
	get_client_memptr(eth_client, clt_indx)->ul_cnt_idx = -1;
	get_client_memptr(eth_client, clt_indx)->dl_cnt_idx = -1;
	get_client_memptr(eth_client, clt_indx)->index_populated = false;
#endif
	memset(get_client_memptr(eth_client, clt_indx)->wan_ul_fl_rule_hdl_v4, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
	memset(get_client_memptr(eth_client, clt_indx)->wan_ul_fl_rule_hdl_v6, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
#endif
	IPACMDBG_H(" %d eth client deleted successfully \n", num_eth_client);
	num_eth_client = num_eth_client - 1;
	IPACMDBG_H(" Number of eth client: %d\n", num_eth_client);

	/* Del RM dependency */
	if(num_eth_client == 0)
	{
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Delete corresponding ipa_rm_resource_name of TX-endpoint after delete all IPV4V6 RT-rule*/
			IPACMDBG_H("dev %s delete producer dependency\n", dev_name);
			if (tx_prop != NULL)
			{
				IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
				IPACM_Iface::ipacmcfg->DelRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			}
		}
	}

	return IPACM_SUCCESS;
}

#ifdef FEATURE_VLAN_MPDN
/* handle LINK DOWN of a physical IF in vlan mode */
int IPACM_Lan::handle_vlan_phys_if_down()
{
	int xlat_pdn_ctx_id;
#ifdef FEATURE_SOCKSv5
	/* socksv5 case */
	if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == false)
	{
		if(IPACM_Wan::isWanUP(ipa_if_num) || IPACM_Wan::isVlanWanUP())
		{
			if(del_ul_flt_rules(IPA_IP_v4))
			{
				return IPACM_FAILURE;
			}
		}
		if(IPACM_Wan::isWanUP_V6(ipa_if_num) || IPACM_Wan::isVlanWanUP_V6())
		{
			/* reset usb-client ipv6 rt-rules */
			handle_lan_client_reset_rt(IPA_IP_v6);

			if(del_ul_flt_rules(IPA_IP_v6))
			{
				return IPACM_FAILURE;
			}
		}
	}
#endif //FEATURE_SOCKSv5

	/* delete rules once for each iptype */
	if(is_any_mux_up(IPA_IP_v4))
	{
		if(del_ul_flt_rules(IPA_IP_v4))
		{
			return IPACM_FAILURE;
		}
	}

	if(is_any_mux_up(IPA_IP_v6))
	{
		/* reset usb-client ipv6 rt-rules */
		handle_lan_client_reset_rt(IPA_IP_v6);

		if(del_ul_flt_rules(IPA_IP_v6))
		{
			return IPACM_FAILURE;
		}
	}

	/* notify once per each mux ID per each ip type */
	for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
	{
		if(v4_mux_up[i].mux_id)
		{
			IPACMDBG_H("notifying flt removed for mux %d, ipv4\n", v4_mux_up[i].mux_id);
			notify_flt_removed(v4_mux_up[i].mux_id);
			xlat_pdn_ctx_id = get_pdn_xlat_ctx(v4_mux_up[i].mux_id, 0);
			if (xlat_pdn_ctx_id != -1)
			{
				if (delete_mdpn_ul_xlat_filter_rule(v4_mux_up[i].mux_id)) //need to remove all associated with the mux
				{
					IPACMDBG_H("Failed to delete xlat rules \n");
				}
				remove_pdn_xlat_ctx(v4_mux_up[i].mux_id);
			}
			v4_mux_up[i].mux_id = 0;
			v4_mux_up[i].VID_cnt = 0;
			memset(v4_mux_up[i].associated_VIDs, 0, sizeof(v4_mux_up[i].associated_VIDs[0]) * IPA_MAX_NUM_SW_PDNS);
		}

		if(v6_mux_up[i].mux_id)
		{
			IPACMDBG_H("notifying flt removed for mux %d, ipv6\n", v6_mux_up[i].mux_id);
			notify_flt_removed(v6_mux_up[i].mux_id);
			v6_mux_up[i].mux_id = 0;
			v6_mux_up[i].VID_cnt = 0;
			memset(v6_mux_up[i].associated_VIDs, 0, sizeof(v6_mux_up[i].associated_VIDs[0]) * IPA_MAX_NUM_SW_PDNS);
		}
	}

	return IPACM_SUCCESS;
}
#endif

/*handle LAN iface down event*/
int IPACM_Lan::handle_down_evt()
{
	int i, j;
	int res = IPACM_SUCCESS, idx = 0;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
/* Link down event */
	struct wan_ioctl_lan_client_info *client_info;
#endif
	list<l2tp_client_info>::iterator it;
	ipacm_cmd_q_data evt_data;
	ipacm_event_data_all *data_all;
#ifdef FEATURE_STATIC_POLICY
	ipacm_event_vlan_pdn *wandown_vlan_data;
	int if_index = 0;
#endif

	IPACMDBG_H("lan handle_down_evt\n ");

	if (rx_prop == NULL){
		IPACMERR("rx property NULL...exit\n");
		return IPACM_FAILURE;
	}

#ifdef FEATURE_IPACM_UL_FIREWALL
	/* Clear IPv6 UL firewall rules: LAN pipe frag, catch all and FW rules if installed */
	if (ip_type != IPA_IP_v4)
		delete_uplink_filter_rule_ul(&iface_ul_firewall);
#endif

	if (IPACM_Iface::ipacmcfg->ipacm_qos_enable)
	{
		delete_all_client_qos_rules();
	}

	if (ipa_if_cate == ODU_IF)
	{
		/* delete ODU default RT rules */
		if (IPACM_Iface::ipacmcfg->ipacm_odu_embms_enable == true)
		{
			IPACMDBG_H("eMBMS enable, delete eMBMS DL RT rule\n");
			handle_odu_route_del();
		}

		/* delete full header */
		if (ipv4_header_set)
		{
			if (m_header.DeleteHeaderHdl(ODU_hdr_hdl_v4)
					== false)
			{
					IPACMERR("ODU ipv4 header delete fail\n");
					res = IPACM_FAILURE;
					goto fail;
			}
			IPACMDBG_H("ODU ipv4 header delete success\n");
		}

		if (ipv6_header_set)
		{
			if (m_header.DeleteHeaderHdl(ODU_hdr_hdl_v6)
					== false)
			{
				IPACMERR("ODU ipv6 header delete fail\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			IPACMERR("ODU ipv6 header delete success\n");
		}
#ifdef FEATURE_SOCKSv5
		/* clean up socksv5 v6-rules*/
		del_socksv5_flt_rule();
#endif
	}

#ifdef FEATURE_L2TP
	if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E) &&
		ipa_if_cate == ODU_IF)
	{
		if(m_header.DeleteHeaderProcCtx(l2tp_ul_hdr_proc_ctx_hdl) == false)
		{
			IPACMERR("Failed to delete l2tp ul hdr proc ctx.\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		if(m_header.DeleteHeaderHdl(l2tp_ul_dummy_hdr_hdl) == false)
		{
			IPACMERR("Failed to delete l2tp ul dummy hdr.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
	}
#endif

	/* no iface address up, directly close iface*/
	if (ip_type == IPACM_IP_NULL)
	{
		goto fail;
	}

#ifdef FEATURE_VLAN_MPDN
	if(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name)
		|| IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
	{
		if(handle_vlan_phys_if_down())
		{
			IPACMERR("failed to handle IF down (vlan mode)\n");
			res = IPACM_FAILURE;
			goto fail;
		}
	}
	else
#endif
	{
		/* delete wan filter rule */
		if(IPACM_Wan::isWanUP(ipa_if_num) && rx_prop != NULL)
		{
			IPACMDBG_H("LAN IF goes down, backhaul type %d\n", IPACM_Wan::backhaul_is_sta_mode);
			handle_wan_down(IPACM_Wan::backhaul_is_sta_mode);
		}

		if(IPACM_Wan::isWanUP_V6(ipa_if_num) && rx_prop != NULL)
		{
			IPACMDBG_H("LAN IF goes down, backhaul type %d\n", IPACM_Wan::backhaul_is_sta_mode);
			handle_wan_down_v6(IPACM_Wan::backhaul_is_sta_mode);
		}
	}

#ifdef FEATURE_EoGRE
	if(IPACM_Iface::ipacmcfg->eogre_enabled)
	{
		IPACMDBG_H("eogre is enabled, need to clean up eogre rules.\n");
		eogre_down();
	}
#endif

	if (rx_prop == NULL){
		IPACMERR("rx property NULL...exit\n");
		return IPACM_FAILURE;
		goto fail;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++){
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		/* Delete v4 default filtering rules */
		if (ip_type != IPA_IP_v6 && rx_prop != NULL) {
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

			/* free private-subnet ipv4 + mtu filter rules */
			if (num_wan_subnet_rules[j] > IPA_MAX_PRIVATE_SUBNET_ENTRIES + IPA_MAX_MTU_ENTRIES) {
				IPACMERR(" the number of rules are bigger than array, aborting...\n");
				res = IPACM_FAILURE;
				goto fail;
			}

			if (m_filtering.DeleteFilteringHdls(private_fl_rule_hdl[j], IPA_IP_v4, num_wan_subnet_rules[j]) == false) {
				IPACMERR("Error deleting private subnet IPv4 flt rules.\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, num_wan_subnet_rules[j]);
			num_wan_subnet_rules[j] = 0;
			IPACMDBG_H("Deleted private subnet v4 filter rules successfully.\n");

			if (m_filtering.DeleteFilteringHdls(&tcp_syn_flt_rule_hdl[j][IPA_IP_v4], IPA_IP_v4, 1) == false) {
				IPACMERR("Error deleting tcp syn flt rule, aborting...\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, 1);
			IPACMDBG_H("Deleted TCP syn v4 filter rules successfully.\n");
		}
		IPACMDBG_H("Finished delete default iface ipv4 filtering rules \n ");

		/* Delete v6 filtering rules */
		if (ip_type != IPA_IP_v4 && rx_prop != NULL) {
			res = delete_icmp_filter_rule(IPA_IP_v6);
			if (res == IPACM_FAILURE) {
				IPACMERR("delete_icmp_filter_rule failed\n");
				goto fail;
			}

#ifdef FEATURE_VLAN_MPDN
			if (m_filtering.DeleteFilteringHdls(ipv6_prefix_flt_rule_hdl[j], IPA_IP_v6,
												num_wan_prefix_rules[j]) == false) {
				IPACMERR("Error Deleting Filtering, aborting...\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, num_wan_prefix_rules[j]);
			num_wan_prefix_rules[j] = 0;
			IPACMDBG_H("Deleted private prefix v6 filter rules successfully.\n");
#endif

#ifdef FEATURE_L2TP
			if ((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E) &&
				ipa_if_cate == ODU_IF) {
				if (m_filtering.DeleteFilteringHdls(l2tp_inner_private_subnet_flt_rule_hdl[j], IPA_IP_v6,
													IPACM_Iface::ipacmcfg->ipa_num_private_subnet) == false) {
					IPACMERR("Error Deleting Filtering, aborting...\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, IPACM_Iface::ipacmcfg->ipa_num_private_subnet);
			}
#endif
			res = delete_dflt_filter_rules(IPA_IP_v6);
			if (res == IPACM_FAILURE) {
				IPACMERR("delete_dflt_filter_rules failed\n");
				goto fail;
			}

			if (m_filtering.DeleteFilteringHdls(&tcp_syn_flt_rule_hdl[j][IPA_IP_v6], IPA_IP_v6, 1) == false) {
				IPACMERR("Error deleting tcp syn flt rule, aborting...\n");
				res = IPACM_FAILURE;
				goto fail;
			}

			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, 1);
			IPACMDBG_H("Deleted TCP syn v6 filter rules successfully.\n");

#ifdef FEATURE_L2TP
			if ((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) &&
				ipa_if_cate == ODU_IF) {
#ifdef IPA_L2TP_TUNNEL_UDP
				if (del_l2tp_udp_dflt_flt_rules(l2tp_udp_dflt_flt_rule_hdl) == IPACM_FAILURE) {
					IPACMERR("Error Deleting default L2TP UDP rules, aborting...\n");
					res = IPACM_FAILURE;
					goto fail;
				}
#endif
			}
#endif
		}
		IPACMDBG_H("Finished delete default iface ipv6 filtering rules \n ");
	}

	if (ip_type != IPA_IP_v6)
	{
		if (m_routing.DeleteRoutingHdl(dft_rt_rule_hdl[0], IPA_IP_v4)
			== false) {
			IPACMERR("Routing rule deletion failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
	}
	IPACMDBG_H("Finished delete default iface ipv4 rules \n ");

	/* delete default v6 routing rule */
	if (ip_type != IPA_IP_v4)
	{
		/* may have multiple ipv6 iface-RT rules*/
		for (i = 0; i < 2 * num_dft_rt_v6; i++) {
			if (m_routing.DeleteRoutingHdl(dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES + i], IPA_IP_v6)
				== false) {
				IPACMERR("Routing rule deletion failed!\n");
				res = IPACM_FAILURE;
				goto fail;
			}
		}
	}

	IPACMDBG_H("Finished delete default iface ipv6 rules \n ");

	/* free the edm clients cache */
	IPACMDBG_H("Free ecm clients cache\n");

	if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
	{
		/* Delete corresponding ipa_rm_resource_name of TX-endpoint after delete all IPV4V6 RT-rule */
		IPACMDBG_H("dev %s delete producer dependency\n", dev_name);
		if (tx_prop != NULL)
		{
			IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			IPACM_Iface::ipacmcfg->DelRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
		}
	}
	eth_bridge_post_event(IPA_ETH_BRIDGE_IFACE_DOWN, IPA_IP_MAX, NULL, NULL, NULL);
	/* delete eth client mac rules if any */
	delete_eth_mac_flt_rules();
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
	if(ipa_if_cate != WAN_IF)
	{
		handle_tethering_client(true, IPACM_CLIENT_USB);
	}
#endif /* defined(FEATURE_IPA_ANDROID)*/
fail:
	/* clean eth-client header, routing rules */
	IPACMDBG_H("left %d eth clients need to be deleted \n ", num_eth_client);
	for (i = 0; i < num_eth_client; i++)
	{
		if(is_l2tp_iface == false)
		{
			/* First reset NAT/IPv6CT rules and then route rules */
			HandleNeighIpAddrDelEvt(i);

			if (delete_eth_rtrules(i, IPA_IP_v4))
			{
				IPACMERR("unbale to delete ecm-client v4 route rules for index %d\n", i);
				res = IPACM_FAILURE;
			}

#ifdef FEATURE_STATIC_POLICY
			if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
			{
				delete_pdn_dscp_eth_rtrules(IPA_IP_v4, 2, i);
			}
#endif

			if (delete_eth_rtrules(i, IPA_IP_v6))
			{
				IPACMERR("unbale to delete ecm-client v6 route rules for index %d\n", i);
				res = IPACM_FAILURE;
			}

#ifdef FEATURE_STATIC_POLICY
			if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
			{
				delete_pdn_dscp_eth_rtrules(IPA_IP_v6, 2, i);
			}
#endif

			IPACMDBG_H("Delete %d out of %d client header\n", i,  num_eth_client);

			if(get_client_memptr(eth_client, i)->ipv4_header_set == true)
			{
				if (m_header.DeleteHeaderHdl(get_client_memptr(eth_client, i)->hdr_hdl_v4)
					== false)
				{
					res = IPACM_FAILURE;
				}
			}

			if(get_client_memptr(eth_client, i)->ipv6_header_set == true)
			{
				if (m_header.DeleteHeaderHdl(get_client_memptr(eth_client, i)->hdr_hdl_v6)
						== false)
				{
					res = IPACM_FAILURE;
				}
			}

			IPACMDBG_H("client %d has %d ipv6 with rt: %d, current total_v6=%d \n", i,
				get_client_memptr(eth_client, i)->ipv6_set,
				get_client_memptr(eth_client, i)->route_rule_set_v6,
				IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
#ifdef FEATURE_VLAN_MPDN
			IPACMDBG_H("vlan_id %d\n", get_client_memptr(eth_client, i)->vlan_id);
#endif

			/* clean up the map and release the memory */
			if (get_client_memptr(eth_client, i)->ipv6_set != 0)
			{
				IPACMDBG_H("ipv6_set %d\n", get_client_memptr(eth_client, i)->ipv6_set);
				for (auto &it : rt_hdl_v6_list[i]) {
					IPACMDBG_H("v6 addr : 0x%08x:%08x:%08x:%08x\n", it.first[0], it.first[1],
						   it.first[2], it.first[3]);
				}
			}

			IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6 -= get_client_memptr(eth_client, i)->ipv6_set;
			IPACMDBG_H("update ipa_num_clients_ipv6 = %d\n", IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
			get_client_memptr(eth_client, i)->ipv6_set = 0;

			/* clear the map */
			rt_hdl_v6_list[i].clear();

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
			if (get_client_memptr(eth_client, i)->lan_stats_idx != -1)
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
					if (ipa_if_cate == LAN_IF)
					{
						client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_USB;
					}
					else if (ipa_if_cate == ODU_IF && is_odu == true)
					{
						client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_ODU;
					}
					else if (ipa_if_cate == ODU_IF)
					{
#ifdef DUAL_NIC_OFFLOAD
						if (strstr(dev_name, STR_ETH1_IFACE))
						{
							client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_ETH1;
						}
						else
#endif
							client_info->device_type = IPACM_CLIENT_DEVICE_TYPE_ETH;
					}
					memcpy(client_info->mac,
							get_client_memptr(eth_client, i)->mac,
							IPA_MAC_ADDR_SIZE);
					client_info->client_init = 0;
					client_info->client_idx = get_client_memptr(eth_client, i)->lan_stats_idx;
					client_info->ul_src_pipe = (enum ipa_client_type) IPA_CLIENT_MAX;
#ifdef IPA_HW_FNR_STATS
					if (IPACM_Iface::ipacmcfg->hw_fnr_stats_support)
					{
						client_info->ul_cnt_idx = get_client_memptr(eth_client, i)->ul_cnt_idx;
						client_info->dl_cnt_idx = get_client_memptr(eth_client, i)->dl_cnt_idx;
						get_client_memptr(eth_client, i)->ul_cnt_idx = -1;
						get_client_memptr(eth_client, i)->dl_cnt_idx = -1;
						get_client_memptr(eth_client, i)->index_populated = false;
						pthread_mutex_lock(&IPACM_Iface::ipacmcfg->cnt_idx_lock);
						if (IPACM_Iface::ipacmcfg->reset_cnt_idx(client_info->ul_cnt_idx, false))
							IPACMERR("Failed to reset counter index %u\n", client_info->ul_cnt_idx);
						pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->cnt_idx_lock);
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
				get_client_memptr(eth_client, i)->lan_stats_idx = -1;
			}
#endif
		}
#ifdef FEATURE_L2TP
		else
		{
			if(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E)
			{
				HandleNeighIpAddrDelEvt(clt_indx);

				/* delete dl rules */
				if(m_routing.DeleteRoutingHdl(get_client_memptr(eth_client, i)->dl_first_pass_rt_rule_hdl, IPA_IP_v4) == false)
				{
					IPACMERR("Failed to delete first pass rt rule.\n");
					return IPACM_FAILURE;
				}

				if(m_routing.DeleteRoutingHdl(get_client_memptr(eth_client, i)->dl_second_pass_rt_rule_hdl, IPA_IP_v6) == false)
				{
					IPACMERR("Failed to delete second pass rt rule.\n");
					return IPACM_FAILURE;
				}

				if(m_header.DeleteHeaderProcCtx(get_client_memptr(eth_client, i)->dl_first_pass_hdr_proc_ctx_hdl) == false)
				{
					IPACMERR("Failed to delete first pass hdr proc ctx.\n");
					return IPACM_FAILURE;
				}

				if(m_header.DeleteHeaderHdl(get_client_memptr(eth_client, i)->dl_first_pass_hdr_hdl) == false)
				{
					IPACMERR("Failed to delete first pass hdr.\n");
					return IPACM_FAILURE;
				}

				if(m_header.DeleteHeaderHdl(get_client_memptr(eth_client, i)->dl_second_pass_hdr_hdl) == false)
				{
					IPACMERR("Failed to delete second pass hdr.\n");
					return IPACM_FAILURE;
				}
				/* delete ul rules */
				if(m_filtering.DeleteFilteringHdls(&get_client_memptr(eth_client, i)->ul_first_pass_flt_rule_hdl, IPA_IP_v6, 1) == false)
				{
					IPACMERR("Failed to delete ul flt rule.\n");
					return IPACM_FAILURE;
				}
				IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);

				if(m_routing.DeleteRoutingHdl(get_client_memptr(eth_client, i)->ul_first_pass_rt_rule_hdl, IPA_IP_v6) == false)
				{
					IPACMERR("Failed to delete ul rt rule.\n");
					return IPACM_FAILURE;
				}
			}
		}
#endif
	} /* end of for loop */
#ifdef FEATURE_L2TP
	if(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E)
	{
		/* post IPA_DEL_L2TP_CLIENT event */
		for(it = IPACM_Iface::ipacmcfg->l2tp_client.begin(); it != IPACM_Iface::ipacmcfg->l2tp_client.end(); it++)
		{
			memset(&evt_data, 0, sizeof(evt_data));
			data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
			if(data_all == NULL)
			{
				IPACMERR("Unable to allocate memory for event data.\n");
				return IPACM_FAILURE;
			}
			strlcpy(data_all->iface_name, it->client_iface_name, sizeof(data_all->iface_name));
			evt_data.event = IPA_DEL_L2TP_CLIENT;
			evt_data.evt_data = data_all;
			IPACM_EvtDispatcher::PostEvt(&evt_data);
		}
		IPACM_Iface::ipacmcfg->l2tp_client.clear();
	}
#endif

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		/* Reset the lan stats indices belonging to this object. */
		if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable)
		{
			IPACMDBG_H("Resetting lan stats indices. \n");
			reset_lan_stats_index();
		}
#endif

	//delete ext_route_rules here if mode is enabled
	if (IPACM_Iface::ipacmcfg->ext_router_mode != IPA_PREFIX_DISABLED)
		if(handle_ext_router_del_evt() == IPACM_FAILURE)
			IPACMERR("failed deleting ext route mode rules");

#ifdef FEATURE_STATIC_POLICY
	//delete static policy rules here if mode is enabled
	if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
	{
		if (handle_static_policy_rule_delete())
		{
			IPACMERR("failed to delete static policy rules.\n");
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
	neigh_cache.clear();
	/* check software routing fl rule hdl */
	if (softwarerouting_act == true && rx_prop != NULL)
	{
		handle_software_routing_disable();
	}

	if (odu_route_rule_v4_hdl != NULL)
	{
		free(odu_route_rule_v4_hdl);
		odu_route_rule_v4_hdl = NULL;
	}
	if (odu_route_rule_v6_hdl != NULL)
	{
		free(odu_route_rule_v6_hdl);
		odu_route_rule_v6_hdl = NULL;
	}

	if (eth_client != NULL)
	{
		free(eth_client);
		eth_client = NULL;
	}

	is_active = false;
	post_del_self_evt();

	return res;
}

/* install UL filter rule from Q6 */
#ifdef FEATURE_VLAN_MPDN
int IPACM_Lan::handle_uplink_filter_rule(ipacm_ext_prop *prop, ipa_ip_type iptype, uint8_t pdn_mux_id, bool notif_only, bool is_xlat, bool ast_update, bool static_policy)
#else
int IPACM_Lan::handle_uplink_filter_rule(ipacm_ext_prop *prop, ipa_ip_type iptype, uint8_t xlat_mux_id, bool ast_update)
#endif
{
	ipa_flt_rule_add flt_rule_entry;
	int len = 0, cnt, ret = IPACM_SUCCESS;
	ipa_ioc_add_flt_rule *pFilteringTable = NULL;
	ipa_fltr_installed_notif_req_msg_v01 flt_index;
	int fd;
	int i, j, index, idx = 0;
	uint32_t value = 0, total_rules = 0, v6_xlat_ul_rules = 0;
	bool is_dev_in_vlan_mode=false;
	enum ipa_flt_action action_cache;

	IPACMDBG_H("Set modem UL flt rules for iptype(%d)\n", iptype);

	if ( ! VALID_IPA_IP_TYPE(iptype) )
	{
		IPACMERR("Invalid IP type passed to function\n");
		return IPACM_FAILURE;
	}

	/* checking instance ip_type */
	if((iptype != ip_type) && (ip_type != IPA_IP_MAX))
	{
		IPACMERR("inconsistent iptype. iptype = %d, instance ip_type = %d\n", iptype, ip_type);
		return IPACM_FAILURE;
	}

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

#ifdef FEATURE_EoGRE
	ipa_ipgre_info ipgre_info = IPACM_Iface::ipacmcfg->eogre_info;
	/*
	 * If we're doing eogre and the iptype in the eogre matches what's
	 * been passed to this function, we've got relevant eogre work to
	 * do...
	 */
	bool compatible_eogre =
		( IPACM_Iface::ipacmcfg->eogre_enabled && iptype == ipgre_info.iptype );
#else
	bool compatible_eogre = false;
#endif /* #ifdef FEATURE_EoGRE */

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

#ifdef FEATURE_VLAN_MPDN
	is_dev_in_vlan_mode = IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name);

	/* MPDN is not enabled in ezmesh mode */
	if (is_dev_in_vlan_mode && IPACM_Iface::ipacmcfg->ipacm_mpdn_enable && !sIface) {
		IPACMDBG_H("number of xlat rules %d \n", prop->num_v4_xlat_props);
		total_rules = prop->num_ext_props - prop->num_v4_xlat_props;
	}
	else
#endif
		total_rules = prop->num_ext_props;

#ifdef FEATURE_EoGRE
	if (compatible_eogre)
	{
		IPACMDBG_H("eogre is enabled, dont need XLAT rules\n");
		total_rules = prop->num_ext_props;
	}
#endif

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

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		memset(&flt_index, 0, sizeof(flt_index));
		flt_index.source_pipe_index = ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, rx_prop->rx[idx].src_pipe);
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		if (tx_prop && IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable) {
			flt_index.dst_pipe_id_valid = 1;
			flt_index.dst_pipe_id_len = tx_prop->num_tx_props;
			for (i = 0; i < tx_prop->num_tx_props && i < QMI_IPA_MAX_CLIENT_DST_PIPES; i++) {
				flt_index.dst_pipe_id[i] = ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, tx_prop->tx[i].dst_pipe);
			}
		}
#endif
		flt_index.install_status = IPA_QMI_RESULT_SUCCESS_V01;
#ifndef FEATURE_IPA_V3
		flt_index.filter_index_list_len = prop->num_ext_props;
#else /* defined (FEATURE_IPA_V3) */
		flt_index.rule_id_valid = 1;
		flt_index.rule_id_len = total_rules;
#endif
		flt_index.embedded_pipe_index_valid = 1;
		flt_index.embedded_pipe_index = ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, IPA_CLIENT_APPS_LAN_WAN_PROD);
		flt_index.retain_header_valid = 1;
		flt_index.retain_header = 0;
		flt_index.embedded_call_mux_id_valid = 1;
#ifdef FEATURE_VLAN_MPDN
		if (is_xlat &&
		   (!(is_dev_in_vlan_mode || static_policy) &&
		   IPACM_Iface::ipacmcfg->ipacm_mpdn_enable))
			flt_index.embedded_call_mux_id = IPACM_Iface::ipacmcfg->GetQmapId();
		else
			flt_index.embedded_call_mux_id = pdn_mux_id;
#else
		flt_index.embedded_call_mux_id = IPACM_Iface::ipacmcfg->GetQmapId();
#endif
#ifndef FEATURE_IPA_V3
		IPACMDBG_H("flt_index: src pipe: %d, num of rules: %d, ebd pipe: %d, mux id: %d\n",
				   flt_index.source_pipe_index, flt_index.filter_index_list_len, flt_index.embedded_pipe_index, flt_index.embedded_call_mux_id);
#else /* defined (FEATURE_IPA_V3) */
		IPACMDBG_H("flt_index: src pipe: %d, num of rules: %d, ebd pipe: %d, mux id: %d\n",
				   flt_index.source_pipe_index, flt_index.rule_id_len, flt_index.embedded_pipe_index, flt_index.embedded_call_mux_id);
#endif

		len = sizeof(struct ipa_ioc_add_flt_rule) +
			total_rules * sizeof(struct ipa_flt_rule_add);

		pFilteringTable =
			(struct ipa_ioc_add_flt_rule *)calloc(len, sizeof(uint8_t));

		if (pFilteringTable == NULL) {
			IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
			close(fd);
			return IPACM_FAILURE;
		}

		pFilteringTable->commit = 1;
		pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
		pFilteringTable->global = false;
		pFilteringTable->ip = iptype;
		pFilteringTable->num_rules = total_rules;

		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add)); // Zero All Fields
		flt_rule_entry.at_rear = 1;
#ifdef FEATURE_IPA_V3
		if (flt_rule_entry.rule.eq_attrib.ipv4_frag_eq_present) flt_rule_entry.at_rear = 0;
#endif
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;

		flt_rule_entry.rule.retain_hdr = 0;
		flt_rule_entry.rule.to_uc = 0;
		flt_rule_entry.rule.eq_attrib_type = 1;

		if (iptype == IPA_IP_v4) {
			bool wan_odu_bridge = (ipa_if_cate == ODU_IF && IPACM_Wan::isWan_Bridge_Mode());

			if (wan_odu_bridge || compatible_eogre || IPACM_Iface::ipacmcfg->is_public_ip_support_enabled) {
				IPACMDBG_H(
					"%s%s%s\n",
					(wan_odu_bridge) ? "[WAN, ODU are in bridge mode] " : "",
					(compatible_eogre) ? "[EoGRE enabled]"                : "",
					(IPACM_Iface::ipacmcfg->is_public_ip_support_enabled) ? "[Public IP enabled]" : "");
				flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
			} else {
				flt_rule_entry.rule.action = IPA_PASS_TO_SRC_NAT;

				/* NAT block will set the proper MUX ID in the metadata according to the relevant PDN */
				if ((IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0) &&
					((ipa_if_cate != WLAN_IF) || ((ipa_if_cate == WLAN_IF) && is_wlan_if_vlan)))
					flt_rule_entry.rule.set_metadata = true;
			}
		} else { /* (iptype == IPA_IP_v6) */
			if (compatible_eogre) {
				flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
			} else
#if defined(FEATURE_IPV6_NAT) && !defined(FEATURE_SOCKSv5)
				/* for v6 nat, second pass should go directly to RT block */
				if (IPACM_Iface::ipacmcfg->ipv6_nat_enable) flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
				else
#endif
					flt_rule_entry.rule.action = IPACM_Iface::ipacmcfg->IsIpv6CTEnabled() ?
						IPA_PASS_TO_SRC_NAT : IPA_PASS_TO_ROUTING;
		}

		index = IPACM_Iface::ipacmcfg->getFltRuleCount(rx_prop->rx[idx].src_pipe, iptype);

		/* cache the flt action */
		action_cache = flt_rule_entry.rule.action;
		for (cnt = i = 0; cnt < prop->num_ext_props && i < total_rules; cnt++)
		{
			memcpy(&flt_rule_entry.rule.eq_attrib,
				   &prop->prop[cnt].eq_attrib,
				   sizeof(prop->prop[cnt].eq_attrib));

			/* Populate the flt rule action from ext_prop */
			if (prop->prop[cnt].action == IPA_PASS_TO_EXCEPTION) {
				/* Override the rule action if Q6 can't handle it, go A7 exception */
				flt_rule_entry.rule.action = prop->prop[cnt].action;
				flt_rule_entry.rule.rt_tbl_idx = 0;
				IPACMDBG_H("Override rule index %d to act: %d, rt_tbl_idx: %d to %d\n",
						   cnt, flt_rule_entry.rule.action,
						   prop->prop[cnt].rt_tbl_idx,
						   flt_rule_entry.rule.rt_tbl_idx);
			} else {
				/* restore the rule action */
				flt_rule_entry.rule.action = action_cache;
				flt_rule_entry.rule.rt_tbl_idx = prop->prop[cnt].rt_tbl_idx;
				IPACMDBG_H("Restore rule index %d to act: %d, rt_tbl_idx: %d \n",
						   cnt, flt_rule_entry.rule.action,
						   flt_rule_entry.rule.rt_tbl_idx);
			}

#ifndef FEATURE_VLAN_MPDN
			/* Handle XLAT configuration */
			if ((iptype == IPA_IP_v4) && prop->prop[cnt].is_xlat_rule && (xlat_mux_id != 0)) {
				/* fill the value of meta-data */
				value = xlat_mux_id;
				flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.value = (value & 0xFF) << 16;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.mask = 0x00FF0000;
				IPACMDBG_H("xlat meta-data is modified for rule: %d has index %d with xlat_mux_id: %d\n",
						   cnt, index, xlat_mux_id);
			}
#else
			/* Handle XLAT configuration */
			if ((iptype == IPA_IP_v4) && prop->prop[cnt].is_xlat_rule && (pdn_mux_id || sIface) && is_xlat) {
				/* For vlan mpdn xlat rules will be installed with vlan id as metadata */
				if (is_dev_in_vlan_mode && IPACM_Iface::ipacmcfg->ipacm_mpdn_enable) {
					IPACMDBG("skip xlat mpdn rule id %d ext prop no. %d i %d\n",
							 prop->prop[cnt].rule_id, cnt, i);
					continue;
				}

				/* for static policy, xlat rules will be installed with src_addr = XLAT PDN subnet */
				if (static_policy)
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
					flt_rule_entry.rule.set_metadata = false;

					IPACMDBG_H("xlat meta-data is modified for rule: %d has index %d with src subnet: 0x%X\n",
							   cnt, index, flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].value);
				}
				else
				{

					/* fill the value of meta-data */
					value = pdn_mux_id;
					flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
					flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
					flt_rule_entry.rule.eq_attrib.metadata_meq32.value = (value & 0xFF) << 16;
					flt_rule_entry.rule.eq_attrib.metadata_meq32.mask = 0x00FF0000;
					IPACMDBG_H("xlat meta-data is modified for rule: %d has index %d with xlat_mux_id: %d\n",
							   cnt, index, pdn_mux_id);
				}
			}
#endif
#ifdef FEATURE_IPA_V3
			flt_rule_entry.rule.hashable = prop->prop[cnt].is_rule_hashable;
			flt_rule_entry.rule.rule_id = prop->prop[cnt].rule_id;
			/* Skip Metadata equation for WLAN VLAN and static policy scenarios to handle XLAT. */
			if (!idx && rx_prop->rx[idx].attrib.attrib_mask & IPA_FLT_META_DATA && !(static_policy && is_xlat)) { //turn on meta-data equation
				flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1 << 9);
				flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.value |= rx_prop->rx[idx].attrib.meta_data;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.mask |= rx_prop->rx[idx].attrib.meta_data_mask;
			}
#endif

#ifdef FEATURE_EoGRE
			if (compatible_eogre)
			{
				ipa_ioc_generate_flt_eq flt_eq;

				memset(&flt_eq, 0, sizeof(flt_eq));

				memcpy(&flt_rule_entry.rule.attrib,
					   &rx_prop->rx[idx].attrib,
					   sizeof(flt_rule_entry.rule.attrib));

				flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;

				if (ipgre_info.iptype == IPA_IP_v4) {
					flt_rule_entry.rule.attrib.u.v4.src_addr_mask = 0xFFFFFFFF;
					flt_rule_entry.rule.attrib.u.v4.src_addr      = ipgre_info.ipv4_src;
				} else {
					memset(
						&flt_rule_entry.rule.attrib.u.v6.src_addr_mask,
						0xFFFFFFFF,
						sizeof(flt_rule_entry.rule.attrib.u.v6.src_addr_mask));

					flt_rule_entry.rule.attrib.u.v6.src_addr[0] = ipgre_info.ipv6_src[3];
					flt_rule_entry.rule.attrib.u.v6.src_addr[1] = ipgre_info.ipv6_src[2];
					flt_rule_entry.rule.attrib.u.v6.src_addr[2] = ipgre_info.ipv6_src[1];
					flt_rule_entry.rule.attrib.u.v6.src_addr[3] = ipgre_info.ipv6_src[0];
				}

				/*
				 * Generate eq
				 */
				flt_eq.ip = iptype;

				memcpy(&flt_eq.attrib,
					   &flt_rule_entry.rule.attrib,
					   sizeof(flt_eq.attrib));

				/*
				 * The following ioctl will convert our parameters to an
				 * equation format. The eqation data will be passed back
				 * in flt_eq...
				 */
				if (0 != ioctl(fd, IPA_IOC_GENERATE_FLT_EQ, &flt_eq)) {
					IPACMERR("Failed to get eq_attrib\n");
					ret = IPACM_FAILURE;
					goto fail;
				}

				if (ipgre_info.iptype == IPA_IP_v4) {
					if ((flt_rule_entry.rule.eq_attrib.num_offset_meq_32 + 1) >
							IPA_IPFLTR_NUM_MEQ_32_EQNS) { //MAX is 2 currently
						IPACMERR("Can't add another meq_32 equation to this rule");
					} else { //add the extra src_addr rule
						flt_rule_entry.rule.eq_attrib.offset_meq_32[
							flt_rule_entry.rule.eq_attrib.num_offset_meq_32] =
							flt_eq.eq_attrib.offset_meq_32[0];

						/*
						 * Add the bitmap that will point to the new meq32
						 * equation
						 */
						flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |=
							(flt_eq.eq_attrib.rule_eq_bitmap << flt_rule_entry.rule.eq_attrib.num_offset_meq_32);

						flt_rule_entry.rule.eq_attrib.num_offset_meq_32++;
					}
				} else {
					if ((flt_rule_entry.rule.eq_attrib.num_offset_meq_128 + 1) >
							IPA_IPFLTR_NUM_MEQ_128_EQNS) { //MAX is 2 currently
						IPACMERR("Can't add another meq_128 equation to this rule");
					} else { //add the extra src_addr rule
						flt_rule_entry.rule.eq_attrib.offset_meq_128[
							flt_rule_entry.rule.eq_attrib.num_offset_meq_128] =
							flt_eq.eq_attrib.offset_meq_128[0];

						/*
						 * Add the bitmap that will point to the new
						 * meq128 equation
						 */
						flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |=
							(flt_eq.eq_attrib.rule_eq_bitmap << flt_rule_entry.rule.eq_attrib.num_offset_meq_128);

						flt_rule_entry.rule.eq_attrib.num_offset_meq_128++;
					}
				}
			}
#endif /* #ifdef FEATURE_EoGRE */
			/* if enabled, modem UL rules will be 2nd pass and NAT will be done by add. 1st pass rule */
			if (static_policy && iptype == IPA_IP_v4)
			{
				if(flt_rule_entry.rule.action != IPA_PASS_TO_EXCEPTION)
				{
					IPACMDBG_H("Changing rule to pass to route\n");
					flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
					flt_rule_entry.rule.set_metadata = false;
				}
			}
			memcpy(&pFilteringTable->rules[i], &flt_rule_entry, sizeof(flt_rule_entry));

			IPACMDBG_H("Modem UL filtering rule %d has index %d installed at %d\n", cnt, index, i);
#ifndef FEATURE_IPA_V3
			flt_index.filter_index_list[cnt].filter_index = index;
			flt_index.filter_index_list[cnt].filter_handle = prop->prop[cnt].filter_hdl;
#else /* defined (FEATURE_IPA_V3) */
			flt_index.rule_id[i] = prop->prop[cnt].rule_id;
#endif
			index++;
			i++;

			//for IPv6CT enabled and XLAT, add a duplicate rule above that will let XLAT packets go to routing instead of NAT
			if (iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->IsIpv6CTEnabled() &&
				flt_rule_entry.rule.action != IPA_PASS_TO_EXCEPTION) {
				//duplicate the old rule to new index
				memcpy(&pFilteringTable->rules[i], &flt_rule_entry, sizeof(flt_rule_entry));

				//change old rule to pass to route and non hashable
				flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
				flt_rule_entry.rule.hashable = false;

				//add the eth header equation for v4 to the old rule
				int meq32_n = flt_rule_entry.rule.eq_attrib.num_offset_meq_32;

				if (meq32_n + 1 > IPA_IPFLTR_NUM_MEQ_32_EQNS) {
					IPACMERR("Can't add another meq_32 equation to this rule");
					memcpy(&pFilteringTable->rules[cnt], &flt_rule_entry, sizeof(flt_rule_entry));
					continue;
				}

				flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].offset = -4;
				flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].mask = 0xFFFF;
				flt_rule_entry.rule.eq_attrib.offset_meq_32[meq32_n].value = ETH_P_IP;

				//Add the bitmap that will point to the new meq32 eq
				if (meq32_n == 0) flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1 << 5);
				else flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1 << 6);

				flt_rule_entry.rule.eq_attrib.num_offset_meq_32++;

				//overwrite the old rule and increment the rule count
				memcpy(&pFilteringTable->rules[i - 1], &flt_rule_entry, sizeof(flt_rule_entry));
				index++;
				i++;
			}
		}

		if (false == m_filtering.SendFilteringRuleIndex(&flt_index)) {
			IPACMERR("Error sending filtering rule index, aborting...\n");
			ret = IPACM_FAILURE;
			goto fail;
		}
#ifdef FEATURE_VLAN_MPDN
		if (notif_only) {
			IPACMDBG_H("UL filtering rules already installed for %s, only sent notification for modem (mux %d)\n",
					   dev_name, pdn_mux_id);
			ret = IPACM_SUCCESS;
			goto finish_notif;
		} else {
			IPACMDBG_H("this is the first PDN for dev %s, commiting modem UL rules, mux %d\n", dev_name, pdn_mux_id);
		}
#endif
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false && !ast_update)
#else
		if (!ast_update)
#endif
		{
			if (false == m_filtering.AddFilteringRule(pFilteringTable)) {
				IPACMERR("Error Adding RuleTable to Filtering, aborting...\n");
				ret = IPACM_FAILURE;
				goto fail;
			} else {
				if (iptype == IPA_IP_v4) {
					for (i = 0; i < pFilteringTable->num_rules; i++) {
						wan_ul_fl_rule_hdl_v4[j][num_wan_ul_fl_rule_v4[j]] = pFilteringTable->rules[i].flt_rule_hdl;
						num_wan_ul_fl_rule_v4[j]++;
						/*Map for dynamic insertion of xlat rules */
						if (is_dev_in_vlan_mode && IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
						{
							xlat_ctx.ul_rule_id_hdl_map[j][i].rule_id = pFilteringTable->rules[i].rule.rule_id;
							xlat_ctx.ul_rule_id_hdl_map[j][i].flt_hdl = pFilteringTable->rules[i].flt_rule_hdl;
						}
					}
					IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, iptype, pFilteringTable->num_rules);
				} else { /* (iptype == IPA_IP_v6) */
					for (i = 0; i < pFilteringTable->num_rules; i++) {
						wan_ul_fl_rule_hdl_v6[j][num_wan_ul_fl_rule_v6[j]] = pFilteringTable->rules[i].flt_rule_hdl;
						num_wan_ul_fl_rule_v6[j]++;

					}
					IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, iptype, pFilteringTable->num_rules);
				}
			}
		}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		else
		{
			/*per client stats will be disabled when vlan is enabled */
			if (iptype == IPA_IP_v4) {
				num_wan_ul_fl_rule_v4[j] = pFilteringTable->num_rules;
			} else { /* (iptype == IPA_IP_v6) */
				num_wan_ul_fl_rule_v6[j] = pFilteringTable->num_rules;
			}
		}
#endif
		if (pFilteringTable)
		{
			free(pFilteringTable);
			pFilteringTable = NULL;
		}
	}
fail:
finish_notif:
	if(pFilteringTable != NULL)
		free(pFilteringTable);
	close(fd);
	return ret;
}

#ifdef FEATURE_IPACM_UL_FIREWALL
/* clean UL firewall filter rules (IPv6 only) from LAN prod pipe, Q6 rules handled separately*/
int IPACM_Lan::delete_uplink_filter_rule_ul(ul_firewall_t *ul_firewall)
{
	uint32_t *flt_rule_hdls = NULL;
	int num_of_rules = 0, idx = 0;
	int j = 0;

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++){	
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		IPACMDBG_H("Deleting UL firewall rules for pipe (%d)\n", rx_prop->rx[idx].src_pipe);
#ifdef FEATURE_VLAN_MPDN
		if (ul_firewall->num_ul_frag_installed[j]) {
			IPACMDBG_H("deleting %d UL frag flt rules\n", ul_firewall->num_ul_frag_installed[j]);
			if (ul_firewall->num_ul_frag_installed[j] > IPA_MAX_NUM_HW_PDNS) {
				IPACMDBG_H("Invalid number of UL fragment rules\n");
				return IPACM_FAILURE;
			}
			flt_rule_hdls = ul_firewall->ul_frag_handle[j];
			if (m_filtering.DeleteFilteringHdls(flt_rule_hdls, IPA_IP_v6, ul_firewall->num_ul_frag_installed[j]) == false) {
				IPACMERR("Error deleting IPv6 UL frag filtering rules.\n");
				return IPACM_FAILURE;
			}
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, ul_firewall->num_ul_frag_installed[j]);
			ul_firewall->num_ul_frag_installed[j] = 0;
		} else {
			IPACMDBG_H("no UL frag flt rules were installed\n");
		}
#else
		if (true == ul_firewall->ul_frag_installed[j]) {
			flt_rule_hdls = &ul_firewall->ul_frag_handle[j];

			if (m_filtering.DeleteFilteringHdls(flt_rule_hdls, IPA_IP_v6, 1) == false) {
				IPACMERR("Error deleting IPv6 UL frag filtering rules.\n");
				return IPACM_FAILURE;
			}
			ul_firewall->ul_frag_installed[j] = false;
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, 1);
			IPACMDBG_H("Frag deleted successfully\n");
		}
#endif

		if (ul_firewall->num_ul_firewall_installed[j] &&
			ul_firewall->num_ul_firewall_installed[j] < IPACM_MAX_FIREWALL_ENTRIES) {
			flt_rule_hdls = ul_firewall->ul_firewall_handle[j];
			if (m_filtering.DeleteFilteringHdls(flt_rule_hdls,
												IPA_IP_v6, ul_firewall->num_ul_firewall_installed[j]) == false) {
				IPACMERR("Error Deleting UL Filtering rules, aborting...\n");
				return IPACM_FAILURE;
			}
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe,
														IPA_IP_v6,
														ul_firewall->num_ul_firewall_installed[j]);
			IPACMDBG_H("%d num UL rules on pipe (%d) deleted successfully\n",
					   ul_firewall->num_ul_firewall_installed[j],
					   rx_prop->rx[idx].src_pipe);
		} else if (ul_firewall->num_ul_firewall_installed[j] > IPACM_MAX_FIREWALL_ENTRIES) {
			IPACMDBG_H("The number of ul firewall rules exceed limit.\n");
		} else {
			IPACMDBG_H("No UL Firewall filter rule to delete\n");
		}
	}
	memset(ul_firewall, 0, sizeof (ul_firewall_t));
	return IPACM_SUCCESS;
}

/* Send UL firewall WhiteListing rules to Q6 */
int IPACM_Lan::install_wan_firewall_rule_ul(bool enable, int vid, int num_of_ul_rules)
{
	int len, res = IPACM_SUCCESS, idx = 0;
	uint8_t mux_id;
	ipa_ioc_add_flt_rule *pFilteringTable_v6 = NULL;
	int j = 0;

	mux_id = IPACM_Iface::ipacmcfg->GetQmapId();
	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_FAILURE;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++){	
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

#ifdef FEATURE_VLAN_MPDN
		if (vid && IPACM_Wan::GetMuxByVid(vid, &mux_id, IPA_IP_v6)) {
			IPACMERR("failed getting mux for vid %d\n", vid);
			return IPACM_FAILURE;
		}
#endif

		/* Not considering is_sw_routing and embm is on or off */

		if (num_of_ul_rules >= 0) {
			len = sizeof(struct ipa_ioc_add_flt_rule) + num_of_ul_rules * sizeof(struct ipa_flt_rule_add);
			pFilteringTable_v6 = (struct ipa_ioc_add_flt_rule *)malloc(len);

			IPACMDBG_H("Total number of WAN UL filtering rule for IPv6 is %d : mux_id (%d), vid (%d)\n", num_of_ul_rules,
					   mux_id, vid);

			if (pFilteringTable_v6 == NULL) {
				IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
				return IPACM_FAILURE;
			}
			memset(pFilteringTable_v6, 0, len);
			pFilteringTable_v6->commit = 1;
			pFilteringTable_v6->ep = rx_prop->rx[idx].src_pipe;
			pFilteringTable_v6->global = false;
			pFilteringTable_v6->ip = IPA_IP_v6;
			pFilteringTable_v6->num_rules = (uint8_t)num_of_ul_rules;

			memcpy(pFilteringTable_v6->rules, IPACM_Wan::firewall_flt_rule_v6_ul, num_of_ul_rules * sizeof(ipa_flt_rule_add));
		}
		if (false == m_filtering.AddWanULFilteringRule(pFilteringTable_v6, mux_id, enable)) {
			IPACMERR("Failed to install WAN UL filtering table.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
	}

fail:
	if (pFilteringTable_v6 != NULL)
	{
		free (pFilteringTable_v6);
	}
	return res;
}

/* Config UL frag firewall filter rules */
int IPACM_Lan::config_wan_frag_firewall_rule_ul_ex(ul_firewall_t *ul_firewall, int vid)
{
	struct ipa_flt_rule_add flt_rule_entry;
	int len = 0, index, rule_v6_ul = 0, idx = 0;
	uint32_t *flt_rule_hdls = NULL;
	int j = 0;

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {	
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		if (ipacmcfg->IsIpv6CTEnabled()) {
			IPACMDBG_H("The fragment rule already installed. Nothing to do\n");
			return IPACM_SUCCESS;
		}
#ifdef FEATURE_VLAN_MPDN
		uint8_t mux_id = 0;
		if (IPACM_Wan::GetMuxByVid(vid, &mux_id, IPA_IP_v6)) {
			IPACMERR("couldn't get MUX for VID %d, dev %s\n", vid, dev_name);
			return IPACM_FAILURE;
		}
#endif

		/* Frag rule installation */
		/* construct ipa_ioc_add_flt_rule with 1 frag rule */
		ipa_ioc_add_flt_rule *m_pFilteringTable = NULL;
		len = sizeof(struct ipa_ioc_add_flt_rule) + 1 * sizeof(struct ipa_flt_rule_add);
		m_pFilteringTable = (struct ipa_ioc_add_flt_rule *)calloc(1, len);

		if (!m_pFilteringTable) {
			IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
			return IPACM_FAILURE;
		}

		memset(m_pFilteringTable, 0, len);

		m_pFilteringTable->commit = 1;
		m_pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
		m_pFilteringTable->global = false;
		m_pFilteringTable->ip = IPA_IP_v6;
		m_pFilteringTable->num_rules = (uint8_t)1;

		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
		flt_rule_entry.at_rear = false;
		flt_rule_entry.rule.hashable = false;
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;
		flt_rule_entry.rule.action = IPA_PASS_TO_EXCEPTION;
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_FRAGMENT;
#ifdef FEATURE_VLAN_MPDN
		uint32_t v6_prefix[2];
		if (IPACM_Wan::GetV6PrefixByVid(vid, v6_prefix)) {
			IPACMERR("couldn't get v6 prefix for vid %d\n", vid);
			return IPACM_FAILURE;
		}
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
		flt_rule_entry.rule.attrib.u.v6.src_addr[0] = v6_prefix[0];
		flt_rule_entry.rule.attrib.u.v6.src_addr[1] = v6_prefix[1];
		flt_rule_entry.rule.attrib.u.v6.src_addr[2] = 0x0;
		flt_rule_entry.rule.attrib.u.v6.src_addr[3] = 0x0;
		flt_rule_entry.rule.attrib.u.v6.src_addr_mask[0] = 0xFFFFFFFF;
		flt_rule_entry.rule.attrib.u.v6.src_addr_mask[1] = 0xFFFFFFFF;
		flt_rule_entry.rule.attrib.u.v6.src_addr_mask[2] = 0x0;
		flt_rule_entry.rule.attrib.u.v6.src_addr_mask[3] = 0x0;
#endif

		memcpy(&(m_pFilteringTable->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));

		if (false == m_filtering.AddFilteringRule(m_pFilteringTable)) {
			IPACMERR("Error Adding RuleTable(0) to Filtering, aborting...\n");
			free(m_pFilteringTable);
			return IPACM_FAILURE;
		} else {
			IPACM_Iface::ipacmcfg->increaseFltRuleCount(m_pFilteringTable->ep, IPA_IP_v6, 1);
			IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n", m_pFilteringTable->rules[0].flt_rule_hdl, m_pFilteringTable->rules[0].status);
		}
#ifdef FEATURE_VLAN_MPDN
		ul_firewall->ul_frag_handle[j][ul_firewall->num_ul_frag_installed[j]] = m_pFilteringTable->rules[0].flt_rule_hdl;
		ul_firewall->num_ul_frag_installed[j]++;
#else
		ul_firewall->ul_frag_handle[j] = m_pFilteringTable->rules[0].flt_rule_hdl;
		ul_firewall->ul_frag_installed[j] = true;
#endif
	}
	return IPACM_SUCCESS;
}

#ifdef IPA_V6_UL_WL_FIREWALL_HANDLE

bool IPACM_Lan::replicate_flt_rule(ipa_flt_rule_add *replicate_rule,
		ipa_flt_rule_add *q6_rule,
		ipa_flt_rule_add *fw_rule)
{
	bool ret;
	/* Combine both Q6 UL and FW rule equations */
	memset(replicate_rule, 0, sizeof(ipa_flt_rule_add));
	memcpy(replicate_rule, fw_rule, sizeof(ipa_flt_rule_add));
	ret = m_filtering.combine_flt_attribute(replicate_rule, q6_rule);
	if (ret == false)
		goto exit;
	replicate_rule->rule.rt_tbl_idx = q6_rule->rule.rt_tbl_idx;
	replicate_rule->rule.hashable = q6_rule->rule.hashable;
	replicate_rule->rule.rule_id = q6_rule->rule.rule_id;
	replicate_rule->rule.rt_tbl_hdl = q6_rule->rule.rt_tbl_hdl;
#ifndef FEATURE_SOCKSv5
	replicate_rule->rule.action = IPACM_Iface::ipacmcfg->IsIpv6CTEnabled()?
		IPA_PASS_TO_SRC_NAT : IPA_PASS_TO_ROUTING;
#else
	replicate_rule->rule.action = IPA_PASS_TO_ROUTING;
#endif
exit:
	return ret;
}

/*
 * Config and installing (UL + v6 ul wl firewall) rules on
 * AP lan rx table with replication effort.
 * 1. delete UL rules
 * 2. Have v6 Q6 UL rules
 * 3. Prepare rules with replicate effort
 * 4. Install the modified rules.
 * 5. Send the indices to Q6.
 * R --> Indicate the rule to be replicated
 * Eg. I/p ==> 1, 2(R), 3, 4(R), 5 || with 2 UL firewall rules
 *     O/p ==> 1, 2(1), 2(2), 3, 4(1), 4(2), 5
 * Send the indices of all rules to Q6.
 */

int IPACM_Lan::config_dft_firewall_rules_ul_ex(IPACM_firewall_conf_t* firewall_conf,
		struct ipa_flt_rule_add *rules, int vid)
{
	ipacm_ext_prop* ext_prop = NULL;
	int fd = 0, i = 0, j = 0, k = 0, eth_idx = 0;
	int ret = 0, len = 0, index = 0, idx = 0;
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

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		/* 1. Delete: Already expected to be taken care */
		/* 2: ext_prop will have a Q6 UL rules*/
		ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);

		if (ext_prop == NULL || ext_prop->num_ext_props <= 0) {
			IPACMDBG_H("No extended property.\n");
			return IPACM_SUCCESS;
		}

		fd = open(IPA_DEVICE_NAME, O_RDWR);
		if (0 == fd) {
			IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
			return IPACM_FAILURE;
		}

		if (ext_prop->num_ext_props > MAX_WAN_UL_FILTER_RULES) {
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
		for (i = 0; i < q6_v6_ul_rules; i++) if (ext_prop->prop[i].replicate_needed == true) replicate_rules++;

		IPACMDBG_H("replicate_rules %d\n", replicate_rules);

		/* Calc v6 UL WL rule*/
		for (i = 0; i < firewall_conf->num_extd_firewall_entries; i++) {
			if (firewall_conf->extd_firewall_entries[i].ip_vsn == 6 &&
				firewall_conf->extd_firewall_entries[i].firewall_direction
				== IPACM_MSGR_UL_FIREWALL
#ifdef FEATURE_IPV6_NAT
				&& !firewall_conf->extd_firewall_entries[i].IPV6NatEnabledfw
#endif
			   ) {
				v6_ul_wl_rules++;
				if (firewall_conf->extd_firewall_entries[i].attrib.u.v6.next_hdr ==
						IPACM_FIREWALL_IPPROTO_TCP_UDP) {
					v6_ul_wl_rules++; //rule should be installed for TCP and UDP both
				}
			}
		}

		IPACMDBG_H("v6_ul_wl_rules %d\n", v6_ul_wl_rules);

		if ((v6_ul_wl_rules == 0) || (replicate_rules == 0)) {
			/*
			 * There is no rule to WL
			 * Dont install any UL rules
			 * Take all in exception path
			 * Will be dropped in linux kernel
			 */
			modem_ul_v6_set[j] = true;
			ret = IPACM_SUCCESS;
			goto close_fd;
		}

		total_rules = ((replicate_rules * v6_ul_wl_rules) +
					   (q6_v6_ul_rules - replicate_rules));
		IPACMDBG_H("total_rules %d\n", total_rules);

		/* ***** */

		memset(&flt_index, 0, sizeof(flt_index));
		flt_index.source_pipe_index = ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, rx_prop->rx[idx].src_pipe);
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		if (tx_prop && IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable) {
			flt_index.dst_pipe_id_valid = 1;
			flt_index.dst_pipe_id_len = tx_prop->num_tx_props;
			for (i = 0; i < tx_prop->num_tx_props && i < QMI_IPA_MAX_CLIENT_DST_PIPES; i++) {
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
		pFilteringTable = (struct ipa_ioc_add_flt_rule *)malloc(len);
		if (pFilteringTable == NULL) {
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
		for (i = 0; i < q6_v6_ul_rules; i++) {
			memcpy(&flt_rule_entry.rule.eq_attrib,
				   &ext_prop->prop[i].eq_attrib,
				   sizeof(ext_prop->prop[i].eq_attrib));
			flt_rule_entry.rule.rt_tbl_idx = ext_prop->prop[i].rt_tbl_idx;
			flt_rule_entry.rule.hashable = ext_prop->prop[i].is_rule_hashable;
			flt_rule_entry.rule.rule_id = ext_prop->prop[i].rule_id;

			/* Skip Meatadata rules for VLAN Pipe. */
			if (!idx && rx_prop->rx[idx].attrib.attrib_mask & IPA_FLT_META_DATA) { //turn on meta-data equation
				flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1 << 9);
				flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.value |= rx_prop->rx[idx].attrib.meta_data;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.mask |= rx_prop->rx[idx].attrib.meta_data_mask;
			}
			/* Is this rule needed replication w.r.t v6 UL WL rule ?*/
			if (ext_prop->prop[i].replicate_needed == true) {
				/* Replicate logic */
				for (j = 0; j < firewall_conf->num_extd_firewall_entries; j++) {
					if (firewall_conf->extd_firewall_entries[j].ip_vsn == 6 &&
						firewall_conf->extd_firewall_entries[j].firewall_direction
						== IPACM_MSGR_UL_FIREWALL) {
#ifdef FEATURE_IPV6_NAT
						// in ipv6_nat_enable=false case, ignore the firewall rules if it's specific to v6nat
						if (firewall_conf->extd_firewall_entries[j].IPV6NatEnabledfw) continue;
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

						flt_rule_entry_fw.rule.attrib.u.v6.dst_addr[3] =
							temp_rule.rule.attrib.u.v6.dst_addr[0];
						flt_rule_entry_fw.rule.attrib.u.v6.dst_addr[2] =
							temp_rule.rule.attrib.u.v6.dst_addr[1];
						flt_rule_entry_fw.rule.attrib.u.v6.dst_addr[1] =
							temp_rule.rule.attrib.u.v6.dst_addr[2];
						flt_rule_entry_fw.rule.attrib.u.v6.dst_addr[0] =
							temp_rule.rule.attrib.u.v6.dst_addr[3];

						flt_rule_entry_fw.rule.attrib.u.v6.dst_addr_mask[3] =
							temp_rule.rule.attrib.u.v6.dst_addr_mask[0];
						flt_rule_entry_fw.rule.attrib.u.v6.dst_addr_mask[2] =
							temp_rule.rule.attrib.u.v6.dst_addr_mask[1];
						flt_rule_entry_fw.rule.attrib.u.v6.dst_addr_mask[1] =
							temp_rule.rule.attrib.u.v6.dst_addr_mask[2];
						flt_rule_entry_fw.rule.attrib.u.v6.dst_addr_mask[0] =
							temp_rule.rule.attrib.u.v6.dst_addr_mask[3];

						/* check if the rule is define as TCP/UDP */
						if (firewall_conf->extd_firewall_entries[j].attrib.u.v6.next_hdr == IPACM_FIREWALL_IPPROTO_TCP_UDP) {
							/* insert TCP rule*/
							flt_rule_entry_fw.rule.attrib.u.v6.next_hdr = IPACM_FIREWALL_IPPROTO_TCP;

							/* Actual replication happens here*/
							if (replicate_flt_rule(&flt_rule_entry_r, &flt_rule_entry, &flt_rule_entry_fw) == false) continue;
							memcpy(&pFilteringTable->rules[k], &flt_rule_entry_r, sizeof(flt_rule_entry));
							IPACMDBG_H("Modem UL filtering rule %d has index %d\n", i, index);
							/* Rule ID of replicate is same as Q6 rule I.D still */
							flt_index.rule_id_ex[k] = ext_prop->prop[i].rule_id;
							index++; k++;

							/* insert UDP rule*/
							flt_rule_entry_fw.rule.attrib.u.v6.next_hdr = IPACM_FIREWALL_IPPROTO_UDP;

							/* Actual replication happens here*/
							if (replicate_flt_rule(&flt_rule_entry_r, &flt_rule_entry, &flt_rule_entry_fw) == false) continue;
							memcpy(&pFilteringTable->rules[k], &flt_rule_entry_r, sizeof(flt_rule_entry));
							IPACMDBG_H("Modem UL filtering rule %d has index %d\n", i, index);
							/* Rule ID of replicate is same as Q6 rule I.D still */
							flt_index.rule_id_ex[k] = ext_prop->prop[i].rule_id;
							index++; k++;
						} else {
							/* Actual replication happens here*/
							if (replicate_flt_rule(&flt_rule_entry_r, &flt_rule_entry, &flt_rule_entry_fw) == false) continue;
							IPACMDBG_H("Modem UL filtering rule %d has index %d\n", i, index);
							memcpy(&pFilteringTable->rules[k], &flt_rule_entry_r, sizeof(flt_rule_entry));
							/* Rule ID of replicate is same as Q6 rule I.D still */
							flt_index.rule_id_ex[k] = ext_prop->prop[i].rule_id;
							index++; k++;
						}
					} /* if loop -->WL rule is there */
				} /* for loop */
			} else {   /* No? just install as it is */
				flt_rule_entry.rule.action = IPACM_Iface::ipacmcfg->IsIpv6CTEnabled() ?
					IPA_PASS_TO_SRC_NAT : IPA_PASS_TO_ROUTING;
				memcpy(&pFilteringTable->rules[k], &flt_rule_entry, sizeof(flt_rule_entry));
				IPACMDBG_H("Modem UL filtering rule %d has index %d\n", i, index);
				flt_index.rule_id_ex[k] = ext_prop->prop[i].rule_id;
				index++; k++;
			}
		}

		if (false == m_filtering.SendFilteringRuleIndex(&flt_index)) {
			IPACMERR("Error sending filtering rule index, aborting...\n");
			ret = IPACM_FAILURE;
			goto alloc_fail;
		}

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == false)
#endif
		{
			if (false == m_filtering.AddFilteringRule(pFilteringTable)) {
				IPACMERR("Error Adding RuleTable to Filtering, aborting...\n");
				ret = IPACM_FAILURE;
				goto alloc_fail;
			} else {
				for (i = 0; i < pFilteringTable->num_rules; i++) {
					wan_ul_fl_rule_hdl_v6[j][num_wan_ul_fl_rule_v6[j]] = pFilteringTable->rules[i].flt_rule_hdl;
					num_wan_ul_fl_rule_v6[j]++;
				}
				IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6,
															pFilteringTable->num_rules);
			}
		}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		else {
#if defined(FEATURE_IPACM_PER_CLIENT_STATS) && defined(IPA_HW_FNR_STATS)
			/* Install v6 ul firewall rules per client*/
			/************************/
#if 0
			/* Catch-all rule*/
			len = sizeof(struct ipa_ioc_add_flt_rule_v2);

			pFilteringTable_v2 = (struct ipa_ioc_add_flt_rule_v2*)malloc(len);
			if (pFilteringTable_v2 == NULL){
				IPACMERR("Error ipa_ioc_add_flt_rule_v2 memory...\n");
				ret = IPACM_FAILURE;
				goto alloc_fail;
			}
			memset(pFilteringTable_v2, 0, len);

			pFilteringTable_v2->rules = (uintptr_t)calloc(1, sizeof(struct ipa_flt_rule_add_v2));
			if (!pFilteringTable->rules) {
				IPACMERR("Failed to allocate memory for filtering rules\n");
				ret = IPACM_FAILURE;
				free(pFilteringTable_v2);
				goto alloc_fail; //Todo: Free pFilteringTable_v2 memory
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

			if(false == m_filtering.AddFilteringRule_v2(pFilteringTable_v2)){
				IPACMERR("Error Adding RuleTable to Filtering, aborting...\n");
				free((void *)pFilteringTable_v2->rules);
				free(pFilteringTable_v2);
				ret = IPACM_FAILURE;
				goto alloc_fail;
			} else {
				wan_ul_fl_rule_hdl_v6[num_wan_ul_fl_rule_v6] =
				((struct ipa_flt_rule_add_v2 *)pFilteringTable_v2->rules)[i].flt_rule_hdl;
				num_wan_ul_fl_rule_v6++;
				IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);
			}
#endif
			/*All rules installation */
			num_wan_ul_fl_rule_v6[j] = pFilteringTable->num_rules;
			for (eth_idx = 0; eth_idx < num_eth_client; eth_idx++) {
				install_uplink_filter_rule_per_client_v2(ext_prop, IPA_IP_v6, IPACM_Wan::getXlat_Mux_Id(),
														 get_client_memptr(eth_client, eth_idx)->mac,
														 get_client_memptr(eth_client, eth_idx)->ul_cnt_idx,
														 pFilteringTable, true);
			}
			/************************/
#else
			num_wan_ul_fl_rule_v6[j] = pFilteringTable->num_rules;
#endif
		}
#endif

		modem_ul_v6_set[j] = true;
	}

alloc_fail:
	free(pFilteringTable);
close_fd:
	close(fd);
	return ret;
}

#else //IPA_V6_UL_WL_FIREWALL_HANDLE

/* Configure UL firewall rules, to be sent to Q6 side*/
int IPACM_Lan::config_dft_firewall_rules_ul_ex(IPACM_firewall_conf_t* firewall_conf,
	struct ipa_flt_rule_add *rules, int vid)
{
	struct ipa_flt_rule_add flt_rule_entry;
	ipa_ioc_get_rt_tbl_indx rt_tbl_idx;
	ipa_ioc_generate_flt_eq flt_eq;
	int i, len = 0, rule_v6_ul = 0, idx = 0;
	int orig_num_q6_rules = 0;

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {

		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		if (IPACM_Wan::get_pdn_num_fw_rules_by_vid(vid, &orig_num_q6_rules)) {
			IPACMERR("failed getting num of Q6 rules for VID %d\n", vid);
			return IPACM_FAILURE;
		}

		for (i = 0; i < firewall_conf->num_extd_firewall_entries; i++) {
			if (firewall_conf->extd_firewall_entries[i].ip_vsn == 6 &&
				firewall_conf->extd_firewall_entries[i].firewall_direction
				== IPACM_MSGR_UL_FIREWALL) {
#ifdef FEATURE_IPV6_NAT
				// in ipv6_nat_enable=false case, ignore the firewall rules if it's specific to v6nat
				if (firewall_conf->extd_firewall_entries[i].IPV6NatEnabledfw) continue;
#endif
				memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
				flt_rule_entry.at_rear = true;
				flt_rule_entry.flt_rule_hdl = -1;
				flt_rule_entry.status = -1;
				flt_rule_entry.rule.retain_hdr = 1;
				flt_rule_entry.rule.to_uc = 0;
				flt_rule_entry.rule.eq_attrib_type = 1;
				flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;

				flt_rule_entry.rule.hashable = true;

				memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
				rt_tbl_idx.ip = IPA_IP_v6;
				/* matched rules for v6 go PASS_TO_ROUTE */
				if (firewall_conf->rule_action_accept == true) {
					strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, IPA_RESOURCE_NAME_MAX);
				} else {
					strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_wan_dl.name, IPA_RESOURCE_NAME_MAX);
				}
				rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
				if (0 != ioctl(IPACM_Wan::m_fd_ipa_ul, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx)) {
					IPACMERR("Failed to get routing table index from name\n");
					return IPACM_FAILURE;
				}
				flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;
				IPACMDBG_H("Routing table %s has index %d\n", rt_tbl_idx.name, rt_tbl_idx.idx);


				memcpy(&flt_rule_entry.rule.attrib,
					   &firewall_conf->extd_firewall_entries[i].attrib,
					   sizeof(struct ipa_rule_attrib));
				flt_rule_entry.rule.attrib.attrib_mask |= rx_prop->rx[idx].attrib.attrib_mask;
				flt_rule_entry.rule.attrib.attrib_mask &= ~IPA_FLT_META_DATA;
				flt_rule_entry.rule.attrib.meta_data_mask = rx_prop->rx[idx].attrib.meta_data_mask;
				flt_rule_entry.rule.attrib.meta_data = rx_prop->rx[idx].attrib.meta_data;
				change_to_network_order(IPA_IP_v6, &flt_rule_entry.rule.attrib);

				/* check if the rule is define as TCP/UDP */
				if (firewall_conf->extd_firewall_entries[i].attrib.u.v6.next_hdr == IPACM_FIREWALL_IPPROTO_TCP_UDP) {
					/* insert TCP rule*/
					flt_rule_entry.rule.attrib.u.v6.next_hdr = IPACM_FIREWALL_IPPROTO_TCP;
					memset(&flt_eq, 0, sizeof(flt_eq));
					memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
					flt_eq.ip = IPA_IP_v6;
					if (0 != ioctl(IPACM_Wan::m_fd_ipa_ul, IPA_IOC_GENERATE_FLT_EQ, &flt_eq)) {
						IPACMERR("Failed to get eq_attrib\n");
						return IPACM_FAILURE;
					}

					memcpy(&flt_rule_entry.rule.eq_attrib,
						   &flt_eq.eq_attrib,
						   sizeof(flt_rule_entry.rule.eq_attrib));
					memcpy(&(rules[rule_v6_ul]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
					rule_v6_ul++;

					/* insert UDP rule*/
					flt_rule_entry.rule.attrib.u.v6.next_hdr = IPACM_FIREWALL_IPPROTO_UDP;
					memset(&flt_eq, 0, sizeof(flt_eq));
					memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
					flt_eq.ip = IPA_IP_v6;
					if (0 != ioctl(IPACM_Wan::m_fd_ipa_ul, IPA_IOC_GENERATE_FLT_EQ, &flt_eq)) {
						IPACMERR("Failed to get eq_attrib\n");
						return IPACM_FAILURE;
					}

					memcpy(&flt_rule_entry.rule.eq_attrib,
						   &flt_eq.eq_attrib,
						   sizeof(flt_rule_entry.rule.eq_attrib));
					memcpy(&(rules[rule_v6_ul]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
					rule_v6_ul++;
				} else {
					memset(&flt_eq, 0, sizeof(flt_eq));
					memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
					flt_eq.ip = IPA_IP_v6;
					if (0 != ioctl(IPACM_Wan::m_fd_ipa_ul, IPA_IOC_GENERATE_FLT_EQ, &flt_eq)) {
						IPACMERR("Failed to get eq_attrib\n");
						return IPACM_FAILURE;
					}

					memcpy(&flt_rule_entry.rule.eq_attrib,
						   &flt_eq.eq_attrib,
						   sizeof(flt_rule_entry.rule.eq_attrib));
					memcpy(&(rules[rule_v6_ul]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
					rule_v6_ul++;
				}
			}
		} /* end of firewall ipv6 filter rule add for loop*/

		if (IPACM_Wan::num_firewall_v6_ul - orig_num_q6_rules + rule_v6_ul > IPACM_MAX_FIREWALL_ENTRIES) {
			IPACMERR("exceeded overall number of possible Q6 firewall rules for all PDNs, aborting\n");
			return IPACM_FAILURE;
		}

		if (IPACM_Lan::install_wan_firewall_rule_ul(true, vid, rule_v6_ul)) {
			IPACMERR("failed sending QMI to Q6\n");
			return IPACM_FAILURE;
		}

		if (IPACM_Wan::set_pdn_num_fw_rules_by_vid(vid, rule_v6_ul)) {
			IPACMERR("failed setting num of Q6 rules for VID %d\n", vid);
		}
		IPACMDBG_H("total %d Q6 UL firewall rules sent to Q6, %d just sent for vid %d\n ",
				   IPACM_Wan::num_firewall_v6_ul,
				   rule_v6_ul,
				   vid);
	}
	return IPACM_SUCCESS;
}
#endif //IPA_V6_UL_WL_FIREWALL_HANDLE
/* delete UL firewall rules, to be sent to Q6 side*/
int IPACM_Lan::disable_dft_firewall_rules_ul_ex(int vid)
{
	int ret;
	ipacm_event_vlan_pdn data;

	if(IPACM_Iface::ipacmcfg->ipv6_nat_enable)
	{
		IPACMDBG_H("IPv6 NAT is enable. No change needed for firewall rule\n");
		return IPACM_SUCCESS;
	}
#ifndef IPA_V6_UL_WL_FIREWALL_HANDLE
	if(IPACM_Lan::install_wan_firewall_rule_ul(false, vid, 0))
	{
		IPACMERR("failed sending QMI to Q6\n");
		return IPACM_FAILURE;
	}
#else //IPA_V6_UL_WL_FIREWALL_HANDLE
#ifdef FEATURE_VLAN_MPDN
	/* Install the deleted UL rules back, since the firewall is disabled */
	if((IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name)) &&
				(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == true))
	{
		if(is_any_mux_up(IPA_IP_v6))
		{
			IPACMDBG_H("firewall disabled & VLAN PDN up, restore modem ul rules (v6)\n");
			for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
			{
				data.iptype = IPA_IP_v6;
				if(v6_mux_up[i].mux_id)
				{
					IPACMDBG_H("mux %d up, restore v6 VLAN PDN rules\n", v6_mux_up[i].mux_id);
					data.mux_id = v6_mux_up[i].mux_id;
					handle_vlan_pdn_up(&data, false);
				}
			}
		}
	}
	else if (IPACM_Wan::isWanUP_V6(ipa_if_num)) {
		if(!handle_uplink_filter_rule(IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6),
			IPA_IP_v6, IPACM_Iface::ipacmcfg->GetQmapId(), false, true))
			modem_ul_v6_set[0] = true;
			modem_ul_v6_set[1] = true;
			modem_ul_v6_set[2] = true;
			modem_ul_v6_set[3] = true;
#else
	if (IPACM_Wan::isWanUP_V6(ipa_if_num)) {
		if(!handle_uplink_filter_rule(IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6),
			IPA_IP_v6, IPACM_Iface::ipacmcfg->GetQmapId()))
			modem_ul_v6_set[0] = true;
			modem_ul_v6_set[1] = true;
			modem_ul_v6_set[2] = true;
			modem_ul_v6_set[3] = true;
#endif //FEATURE_VLAN_MPDN
#if defined FEATURE_IPACM_PER_CLIENT_STATS && defined IPA_HW_FNR_STATS
		/* Install Q6 UL rules for all the clients. */
		if (IPACM_Iface::ipacmcfg->ipacm_lan_stats_enable == true)
		{
			IPACMDBG_H("Install original per client V6 UL filter rules \n");
			ret = install_uplink_filter_rule(IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6), IPA_IP_v6, IPACM_Iface::ipacmcfg->GetQmapId());
			if (ret == IPACM_FAILURE)
			{
				IPACMDBG_H(" failed to install per client rules for V6 UL\n");
				return ret;
			}
			modem_ul_v6_set[0] = true;
			modem_ul_v6_set[1] = true;
			modem_ul_v6_set[2] = true;
			modem_ul_v6_set[3] = true;
		}
#endif //FEATURE_IPACM_PER_CLIENT_STATS && IPA_HW_FNR_STATS
	}
#endif //IPA_V6_UL_WL_FIREWALL_HANDLE

	if(IPACM_Wan::set_pdn_num_fw_rules_by_vid(vid, 0))
	{
		IPACMERR("failed setting num of Q6 rules for VID %d\n", vid);
		return IPACM_FAILURE;
	}
	return IPACM_SUCCESS;
}

/* Configure and install UL firewall rules, to be installed on client side */
int IPACM_Lan::config_dft_firewall_rules_ul(IPACM_firewall_conf_t* firewall_conf,
				ul_firewall_t *ul_firewall, int vid)
{
	struct ipa_flt_rule_add flt_rule_entry;
	int len = 0, i, idx = 0;
	int res = IPACM_SUCCESS;
	int j = 0;

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	/* construct ipa_ioc_add_flt_rule with N firewall rules */
	ipa_ioc_add_flt_rule *m_pFilteringTable = NULL;
	len = sizeof(struct ipa_ioc_add_flt_rule) + 1 * sizeof(struct ipa_flt_rule_add);
	m_pFilteringTable = (struct ipa_ioc_add_flt_rule *)calloc(1, len);

	if (!m_pFilteringTable)
	{
		IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
		return IPACM_FAILURE;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {

		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		IPACMDBG_H("num rules %d, pdn dev_name %s, accept %d\n",
				   firewall_conf->num_extd_firewall_entries,
				   firewall_conf->net_dev,
				   firewall_conf->rule_action_accept);

#ifdef FEATURE_VLAN_MPDN
		uint32_t v6_prefix[2];
		if (IPACM_Wan::GetV6PrefixByVid(vid, v6_prefix)) {
			IPACMERR("couldn't get v6 prefix for vid %d\n", vid);
			return IPACM_FAILURE;
		}
#endif

		if (false == m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_wan_v6)) {
			IPACMERR("m_routing.GetRoutingTable(rt_tbl_wan_v6) Failed.\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		if (ul_firewall->num_ul_firewall_installed[j] >= IPACM_MAX_FIREWALL_ENTRIES) {
			IPACMERR("reached MAX num of UL FW rules for ep, skipping pdn firewall (vid %d)\n", vid);
			res = IPACM_FAILURE;
			goto fail;
		}

		/* Catch-all filter rule in case of whitelisting case, redirecting packets to exception path */
		if (firewall_conf->rule_action_accept == true) {
			memset(m_pFilteringTable, 0, len);
			m_pFilteringTable->commit = 1;

			m_pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
			m_pFilteringTable->global = false;
			m_pFilteringTable->ip = IPA_IP_v6;
			m_pFilteringTable->num_rules = (uint8_t)1;

			IPACMDBG_H("Catch all rule to drop all in excep path\n");

			memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
			flt_rule_entry.at_rear = false;
			flt_rule_entry.flt_rule_hdl = -1;
			flt_rule_entry.status = -1;
			flt_rule_entry.rule.action = IPA_PASS_TO_EXCEPTION;
			flt_rule_entry.rule.hashable = true;
#ifdef FEATURE_VLAN_MPDN
			flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
			flt_rule_entry.rule.attrib.u.v6.src_addr[0] = v6_prefix[0];
			flt_rule_entry.rule.attrib.u.v6.src_addr[1] = v6_prefix[1];
			flt_rule_entry.rule.attrib.u.v6.src_addr[2] = 0x0;
			flt_rule_entry.rule.attrib.u.v6.src_addr[3] = 0x0;
			flt_rule_entry.rule.attrib.u.v6.src_addr_mask[0] = 0xFFFFFFFF;
			flt_rule_entry.rule.attrib.u.v6.src_addr_mask[1] = 0xFFFFFFFF;
			flt_rule_entry.rule.attrib.u.v6.src_addr_mask[2] = 0x0;
			flt_rule_entry.rule.attrib.u.v6.src_addr_mask[3] = 0x0;
#endif
			memcpy(&(m_pFilteringTable->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));

			if (false == m_filtering.AddFilteringRule(m_pFilteringTable)) {
				IPACMERR("Error Adding Filtering rules, aborting...\n");
				res = IPACM_FAILURE;
				goto fail;
			} else {
				IPACM_Iface::ipacmcfg->increaseFltRuleCount(m_pFilteringTable->ep, IPA_IP_v6, 1);
				/* save v6 firewall filter rule handler */
				IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n", m_pFilteringTable->rules[0].flt_rule_hdl, m_pFilteringTable->rules[0].status);
			}

			ul_firewall->ul_firewall_handle[j][ul_firewall->num_ul_firewall_installed[j]++] = m_pFilteringTable->rules[0].flt_rule_hdl;
		}

		memset(m_pFilteringTable, 0, len);
		m_pFilteringTable->commit = 1;
		m_pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
		m_pFilteringTable->global = false;
		m_pFilteringTable->ip = IPA_IP_v6;
		m_pFilteringTable->num_rules = (uint8_t)1;

		for (i = 0; i < firewall_conf->num_extd_firewall_entries; i++) {
			if (ul_firewall->num_ul_firewall_installed[j] >= (IPACM_MAX_FIREWALL_ENTRIES - 1)) {
				IPACMERR("reached MAX num of UL FW rules for ep, breaking\n");
				break;
			}
			if (firewall_conf->extd_firewall_entries[i].ip_vsn == 6 &&
				firewall_conf->extd_firewall_entries[i].firewall_direction ==
					IPACM_MSGR_UL_FIREWALL) {

#ifdef FEATURE_IPV6_NAT
				// in ipv6_nat_enable=false case, ignore the firewall rules if it's specific to v6nat
				if (firewall_conf->extd_firewall_entries[i].IPV6NatEnabledfw) continue;
#endif
				memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
				flt_rule_entry.at_rear = false;
				flt_rule_entry.flt_rule_hdl = -1;
				flt_rule_entry.status = -1;

				if (firewall_conf->rule_action_accept == true) {
#ifndef FEATURE_SOCKSv5
					flt_rule_entry.rule.action =
						IPACM_Iface::ipacmcfg->IsIpv6CTEnabled() ? IPA_PASS_TO_SRC_NAT : IPA_PASS_TO_ROUTING;
#else
					flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#endif
				} else {
					flt_rule_entry.rule.action = IPA_PASS_TO_EXCEPTION;
				}

				flt_rule_entry.rule.hashable = true;

				flt_rule_entry.rule.rt_tbl_hdl = IPACM_Iface::ipacmcfg->rt_tbl_v6.hdl;
				memcpy(&flt_rule_entry.rule.attrib,
					   &firewall_conf->extd_firewall_entries[i].attrib,
					   sizeof(struct ipa_rule_attrib));

				flt_rule_entry.rule.attrib.attrib_mask |= rx_prop->rx[idx].attrib.attrib_mask;
				flt_rule_entry.rule.attrib.meta_data_mask = rx_prop->rx[idx].attrib.meta_data_mask;
				flt_rule_entry.rule.attrib.meta_data = rx_prop->rx[idx].attrib.meta_data;
#ifdef FEATURE_VLAN_MPDN
				flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
				flt_rule_entry.rule.attrib.u.v6.src_addr[0] = v6_prefix[0];
				flt_rule_entry.rule.attrib.u.v6.src_addr[1] = v6_prefix[1];
				flt_rule_entry.rule.attrib.u.v6.src_addr[2] = 0x0;
				flt_rule_entry.rule.attrib.u.v6.src_addr[3] = 0x0;
				flt_rule_entry.rule.attrib.u.v6.src_addr_mask[0] = 0xFFFFFFFF;
				flt_rule_entry.rule.attrib.u.v6.src_addr_mask[1] = 0xFFFFFFFF;
				flt_rule_entry.rule.attrib.u.v6.src_addr_mask[2] = 0x0;
				flt_rule_entry.rule.attrib.u.v6.src_addr_mask[3] = 0x0;
#endif

				/* check if the rule is define as TCP/UDP */
				if (firewall_conf->extd_firewall_entries[i].attrib.u.v6.next_hdr == IPACM_FIREWALL_IPPROTO_TCP_UDP) {
					/* insert TCP rule*/
					flt_rule_entry.rule.attrib.u.v6.next_hdr = IPACM_FIREWALL_IPPROTO_TCP;
					memcpy(&(m_pFilteringTable->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
					if (false == m_filtering.AddFilteringRule(m_pFilteringTable)) {
						IPACMERR("Error Adding Filtering rules, aborting...\n");
						res = IPACM_FAILURE;
						goto fail;
					} else {
						IPACM_Iface::ipacmcfg->increaseFltRuleCount(m_pFilteringTable->ep, IPA_IP_v6, 1);
						/* save v4 firewall filter rule handler */
						IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n", m_pFilteringTable->rules[0].flt_rule_hdl, m_pFilteringTable->rules[0].status);
						ul_firewall->ul_firewall_handle[j][ul_firewall->num_ul_firewall_installed[j]++] = m_pFilteringTable->rules[0].flt_rule_hdl;
					}

					/* insert UDP rule*/
					flt_rule_entry.rule.attrib.u.v6.next_hdr = IPACM_FIREWALL_IPPROTO_UDP;
					memcpy(&(m_pFilteringTable->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
					if (false == m_filtering.AddFilteringRule(m_pFilteringTable)) {
						IPACMERR("Error Adding Filtering rules, aborting...\n");
						res = IPACM_FAILURE;
						goto fail;
					} else {
						IPACM_Iface::ipacmcfg->increaseFltRuleCount(m_pFilteringTable->ep, IPA_IP_v6, 1);
						/* save v6 firewall filter rule handler */
						IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n", m_pFilteringTable->rules[0].flt_rule_hdl, m_pFilteringTable->rules[0].status);
						ul_firewall->ul_firewall_handle[j][ul_firewall->num_ul_firewall_installed[j]++] = m_pFilteringTable->rules[0].flt_rule_hdl;
					}
				} else {
					memcpy(&(m_pFilteringTable->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
					if (false == m_filtering.AddFilteringRule(m_pFilteringTable)) {
						IPACMERR("Error Adding Filtering rules, aborting...\n");
						res = IPACM_FAILURE;
						goto fail;
					} else {
						IPACM_Iface::ipacmcfg->increaseFltRuleCount(m_pFilteringTable->ep, IPA_IP_v6, 1);
						/* save v6 firewall filter rule handler */
						IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n", m_pFilteringTable->rules[0].flt_rule_hdl, m_pFilteringTable->rules[0].status);
						ul_firewall->ul_firewall_handle[j][ul_firewall->num_ul_firewall_installed[j]++] = m_pFilteringTable->rules[0].flt_rule_hdl;
					}
				}
			}
		} /* end of firewall ipv6 filter rule add for loop*/

		if (!ipacmcfg->IsIpv6CTEnabled() &&
			(IPACM_Wan::check_dft_firewall_rules_attr_mask_ul(firewall_conf) ||
			 firewall_conf->rule_action_accept)) {
#ifndef FEATURE_VLAN_MPDN
			ul_firewall->ul_frag_installed[j] = true;
#endif
			memset(m_pFilteringTable, 0, len);

			m_pFilteringTable->commit = 1;
			m_pFilteringTable->ep = rx_prop->rx[idx].src_pipe;

			memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

			if (firewall_conf->rule_action_accept != true) memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[idx].attrib, sizeof(struct ipa_rule_attrib));

			m_pFilteringTable->global = false;
			m_pFilteringTable->ip = IPA_IP_v6;
			m_pFilteringTable->num_rules = (uint8_t)1;

			flt_rule_entry.at_rear = false;

			flt_rule_entry.rule.hashable = false;

			flt_rule_entry.flt_rule_hdl = -1;
			flt_rule_entry.status = -1;
			flt_rule_entry.rule.action = IPA_PASS_TO_EXCEPTION;

			flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_FRAGMENT;
#ifdef FEATURE_VLAN_MPDN
			flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
			flt_rule_entry.rule.attrib.u.v6.src_addr[0] = v6_prefix[0];
			flt_rule_entry.rule.attrib.u.v6.src_addr[1] = v6_prefix[1];
			flt_rule_entry.rule.attrib.u.v6.src_addr[2] = 0x0;
			flt_rule_entry.rule.attrib.u.v6.src_addr[3] = 0x0;
			flt_rule_entry.rule.attrib.u.v6.src_addr_mask[0] = 0xFFFFFFFF;
			flt_rule_entry.rule.attrib.u.v6.src_addr_mask[1] = 0xFFFFFFFF;
			flt_rule_entry.rule.attrib.u.v6.src_addr_mask[2] = 0x0;
			flt_rule_entry.rule.attrib.u.v6.src_addr_mask[3] = 0x0;
#endif
			memcpy(&(m_pFilteringTable->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
			if (false == m_filtering.AddFilteringRule(m_pFilteringTable)) {
				IPACMERR("Error Adding RuleTable(0) to Filtering, aborting...\n");
				res = IPACM_FAILURE;
				goto fail;
			} else {
				IPACM_Iface::ipacmcfg->increaseFltRuleCount(m_pFilteringTable->ep, IPA_IP_v6, 1);
				IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n", m_pFilteringTable->rules[0].flt_rule_hdl, m_pFilteringTable->rules[0].status);
#ifdef FEATURE_VLAN_MPDN
				ul_firewall->ul_frag_handle[j][ul_firewall->num_ul_frag_installed[j]++] = m_pFilteringTable->rules[0].flt_rule_hdl;
#else
				ul_firewall->ul_frag_handle[j] = m_pFilteringTable->rules[0].flt_rule_hdl;
#endif
			}
		}

		IPACMDBG_H("Configured and installed (%d) UL firewall rules on pipe (%d)\n ",
				   ul_firewall->num_ul_firewall_installed[j],
				   (int)m_pFilteringTable->ep);
		IPACMDBG_H("Firewall Status (%d)\n", firewall_conf->firewall_enable);

	}
fail:
	if(m_pFilteringTable != NULL)
	{
		free(m_pFilteringTable);
	}
	return res;
}

int IPACM_Lan::configure_v6_ul_firewall_one_profile(IPACM_firewall_conf_t* firewall_conf, bool isDefault, int vid)
{
	bool q6_firewall = false;

	if(isDefault)
	{
		/* default profile might be in STA mode */
		if(IPACM_Wan::backhaul_is_sta_mode == false && firewall_conf->rule_action_accept)
			q6_firewall = true;
		IPACMDBG("default: STA %d, action %d\n", IPACM_Wan::backhaul_is_sta_mode, firewall_conf->rule_action_accept);
	}
	else
	{
		if(firewall_conf->rule_action_accept)
			q6_firewall = true;
		IPACMDBG("non default: action %d\n", firewall_conf->rule_action_accept);
	}

	memset(IPACM_Wan::firewall_flt_rule_v6_ul,
		0, (IPACM_MAX_FIREWALL_ENTRIES + 1) * sizeof(ipa_flt_rule_add));

	if(q6_firewall) /* LTE && whitelist ?? */
	{
		IPACMDBG_H("firewall for vid %d shall be installed on Q6 side\n", vid);
		/* Configure and send the firewall filter table to Q6*/
		if(config_dft_firewall_rules_ul_ex(firewall_conf, IPACM_Wan::firewall_flt_rule_v6_ul, vid))
		{
			IPACMERR("failed configuring Q6 firewall for vid %d\n", vid);
			return IPACM_FAILURE;
		}
#ifndef IPA_V6_UL_WL_FIREWALL_HANDLE
		/* send fragments to exception since Q6 FW doesn't handle fragments */
		config_wan_frag_firewall_rule_ul_ex(&iface_ul_firewall, vid);
		IPACMDBG_H("New config rules sent to Q6\n");
#endif //IPA_V6_UL_WL_FIREWALL_HANDLE
	}
	else
	{
		IPACMDBG_H("firewall for vid %d shall be installed on %s prod pipe\n", vid, dev_name);
		/* Config and install it on pipes directly, since it is Blacklisted */
		IPACMDBG_H("Send indication to Q6 to disable UL firewall\n");
		disable_dft_firewall_rules_ul_ex(vid);
		config_dft_firewall_rules_ul(firewall_conf, &iface_ul_firewall, vid);
	}

	IPACMDBG_H("finished configuring UL FW for vid %d on %s, is_default %d\n", vid, q6_firewall?"Q6":"LAN prod", isDefault);
	return IPACM_SUCCESS;
}

/*
 * configure IPv6 UL firewall for all PDNs relevant for this LAN from scratch.
 * rules are installed either on this LAN prod pipe or on Q6 routing table
 * depends on the specific PDN configuration.
 */
void IPACM_Lan::configure_v6_ul_firewall(void)
{
	IPACM_firewall_conf_t *firewall_config = NULL;
	int default_vid = 0, ret;

	if (IPACM_Iface::ipacmcfg->ipv6_nat_enable)
	{
		IPACMDBG_H("IPv6 NAT is enable. Don't configure firewall rule\n");
		return;
	}

	/* first of all clear LAN pipe frag, catch all and FW rules if installed */
	delete_uplink_filter_rule_ul(&iface_ul_firewall);

	/* now read XML and rebuild FW for all PDNs */
	if(IPACM_Wan::read_firewall_filter_rules_ul())
	{
		IPACMERR("failed configuring UL firewall\n");
		return;
	}

#ifdef IPA_V6_UL_WL_FIREWALL_HANDLE
	/* Delete Q6 UL rules */
#ifdef FEATURE_VLAN_MPDN
	if((IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name)) &&
				(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE))
	{
		if(is_any_mux_up(IPA_IP_v6))
		{
			IPACMDBG_H("Vlan config - delete all modem ul rules (v6) to handle new firewall config\n");
			if(del_ul_flt_rules(IPA_IP_v6))
				return;

			for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
			{
				if(v6_mux_up[i].mux_id)
				{
					IPACMDBG_H("mux %d up, notify modem we deleted v6 flt rules\n", v6_mux_up[i].mux_id);
					if (notify_flt_removed(v6_mux_up[i].mux_id))
						return;
				}
			}
		}
	}
	else
#endif
	{
		IPACMDBG_H(" delete all modem ul rules (v6) to handle new frewall config\n");
		if(del_ul_flt_rules(IPA_IP_v6))
			return;

		if(notify_flt_removed(IPACM_Iface::ipacmcfg->GetQmapId()))
			return;
	}

#endif

	if(IPACM_Wan::isWanUP_V6(ipa_if_num))
	{
		firewall_config = IPACM_Wan::get_default_profile_firewall_conf_ul(&default_vid);
		if(!firewall_config)
		{
			IPACMERR("failed getting default profile config\n");
			return;
		}
		if(firewall_config->firewall_enable)
		{
			if(configure_v6_ul_firewall_one_profile(firewall_config, true, default_vid))
			{
				IPACMERR("failed configuring default profile UL firewall, vid %d\n", default_vid);
			}
		}
		else
		{
			IPACMDBG_H("default profile firewall is disabled, disable Q6 firewall\n");
			disable_dft_firewall_rules_ul_ex(default_vid);
		}
	}
#ifdef FEATURE_VLAN_MPDN
	uint16_t Ids[IPA_MAX_NUM_OFFLOAD_VLANS];

	if(IPACM_Iface::ipacmcfg->get_iface_vlan_ids(dev_name, Ids))
	{
		IPACMERR("failed getting vlan ids for iface %s\n", dev_name);
		return;
	}

	for(int i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
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
}
#endif //FEATURE_IPACM_UL_FIREWALL
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
#ifdef IPA_HW_FNR_STATS
int IPACM_Lan::install_uplink_filter_rule_per_client_v2
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
	uint8_t num_offset_meq_128 = 0;
	struct ipa_ipfltr_mask_eq_128 *offset_meq_128 = NULL;
	int total_rules = 0, v6_xlat_ul_rules = 0, install_total_rules = 0;
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

		install_total_rules = total_rules + v6_xlat_ul_rules;
		IPACMDBG_H("Need %d additional XLAT rules %d total_rules and %d rules_to_install\n", v6_xlat_ul_rules, total_rules, install_total_rules);
	}
	else
	{
		install_total_rules = total_rules;
		IPACMDBG_H("Need %d additional XLAT rules %d total_rules and %d rules_to_install\n", v6_xlat_ul_rules, total_rules, install_total_rules);
	}
	clnt_indx = get_eth_client_index(mac_addr);

	if (clnt_indx == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached \n");
		return IPACM_FAILURE;
	}

	if (get_client_memptr(eth_client, clnt_indx)->lan_stats_idx == -1)
	{
		IPACMERR("Invalid LAN Stats idx for ethernet client:%d \n", clnt_indx);
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

	pFilteringTable->rules = (uintptr_t)calloc(install_total_rules, sizeof(struct ipa_flt_rule_add_v2));
	if (!pFilteringTable->rules) {
		IPACMERR("Failed to allocate memory for filtering rules\n");
		ret = IPACM_FAILURE;
		goto fail;
	}

	pFilteringTable->commit = 1;
	pFilteringTable->ep = rx_prop->rx[0].src_pipe;
	pFilteringTable->global = false;
	pFilteringTable->ip = iptype;
	pFilteringTable->num_rules = install_total_rules;
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
	IPACMERR("fnr : top: flt enable stats = %d, ul cnt index = %u, ep = %d\n", flt_rule_entry.rule.enable_stats, flt_rule_entry.rule.cnt_idx,
		pFilteringTable->ep);

	if(iptype == IPA_IP_v4)
	{
		
		if (ipa_if_cate == ODU_IF && IPACM_Wan::isWan_Bridge_Mode() ||
			IPACM_Iface::ipacmcfg->is_public_ip_support_enabled)
		{
			IPACMDBG_H("WAN, ODU are in bridge mode \n");
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
			if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
				flt_rule_entry.rule.set_metadata = true;
		}
	}
	else if(iptype == IPA_IP_v6)
	{
#if defined(FEATURE_IPV6_NAT) && !defined(FEATURE_SOCKSv5)
		/* for v6 nat, second pass should go directly to RT block */
		if(IPACM_Iface::ipacmcfg->ipv6_nat_enable)
			flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
		else
#endif
			flt_rule_entry.rule.action = IPACM_Iface::ipacmcfg->IsIpv6CTEnabled()?
					IPA_PASS_TO_SRC_NAT : IPA_PASS_TO_ROUTING;
	}
	else
	{
		IPACMERR("IP type is not expected.\n");
		ret = IPACM_FAILURE;
		goto fail;
	}

	action_cache = flt_rule_entry.rule.action;

	for(cnt=0; cnt < total_rules && index < install_total_rules ; cnt++)
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
		IPACMDBG_H("Modified rule: %d has rule_id %d\n", index, flt_rule_entry.rule.rule_id);

		/* Check if we can add the MAC address rule. */
		if (num_offset_meq_128 == IPA_IPFLTR_NUM_MEQ_128_EQNS)
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
#ifdef IPA_HDR_L2_ETHERNET_II_AST
		else if (rx_prop->rx[0].hdr_l2_type == IPA_HDR_L2_ETHERNET_II_AST)
		{
			offset_meq_128->offset = -8;
		}
#endif
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
		flt_rule_entry.rule.enable_stats = true;
		flt_rule_entry.rule.cnt_idx = ul_cnt_idx;
		IPACMERR("fnr : top: flt rule entry enable stats = %d, ul cnt index = %u\n", flt_rule_entry.rule.enable_stats, flt_rule_entry.rule.cnt_idx);
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

		if(rx_prop->rx[0].attrib.attrib_mask & IPA_FLT_META_DATA)	//turn on meta-data equation
		{
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<9);
			flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.value |= rx_prop->rx[0].attrib.meta_data;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.mask |= rx_prop->rx[0].attrib.meta_data_mask;
		}
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
		if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
			if (iptype == IPA_IP_v6)
				flt_rule_entry.rule.ttl_update = IPACM_Wan::is_global_ipv6_addr(flt_rule_entry.rule.attrib.u.v6.dst_addr);
			else
				flt_rule_entry.rule.ttl_update = true;
		}
#endif
		memcpy((void *)pFilteringTable->rules + (index * sizeof(struct ipa_flt_rule_add_v2)),
			&flt_rule_entry, sizeof(flt_rule_entry));
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
		flt_rule_entry.rule.ttl_update = false;
#endif
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
			for(i=0; i < pFilteringTable->num_rules; i++)
			{
				get_client_memptr(eth_client, clnt_indx)->wan_ul_fl_rule_hdl_v4[i] =
					((struct ipa_flt_rule_add_v2 *)pFilteringTable->rules)[i].flt_rule_hdl;
			}
			get_client_memptr(eth_client, clnt_indx)->ipv4_ul_rules_set = true;
		}
		else if(iptype == IPA_IP_v6)
		{
			for(i=0; i < pFilteringTable->num_rules; i++)
			{
				get_client_memptr(eth_client, clnt_indx)->wan_ul_fl_rule_hdl_v6[i] =
					((struct ipa_flt_rule_add_v2 *)pFilteringTable->rules)[i].flt_rule_hdl;
			}
			get_client_memptr(eth_client, clnt_indx)->ipv6_ul_rules_set = true;
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

/* install UL filter rule from Q6 per client */
int IPACM_Lan::install_uplink_filter_rule_per_client
(
	ipacm_ext_prop* prop,
	ipa_ip_type iptype,
	uint8_t xlat_mux_id,
	uint8_t *mac_addr
)
{
	ipa_flt_rule_add flt_rule_entry;
	int len = 0, cnt, ret = IPACM_SUCCESS;
	ipa_ioc_add_flt_rule *pFilteringTable;
	int fd;
	int i, index = 0;
	uint32_t value = 0;
	int clnt_indx;
	uint8_t num_offset_meq_128 = 0;
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

	clnt_indx = get_eth_client_index(mac_addr);

	if (clnt_indx == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached \n");
		return IPACM_FAILURE;
	}

	if (get_client_memptr(eth_client, clnt_indx)->lan_stats_idx == -1)
	{
		IPACMERR("Invalid LAN Stats idx for ethernet client:%d \n", clnt_indx);
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
	pFilteringTable->ep = rx_prop->rx[0].src_pipe;
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
			IPACMDBG_H("WAN, ODU are in bridge mode \n");
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
			if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_v4_0)
				flt_rule_entry.rule.set_metadata = true;
		}
	}
	else if(iptype == IPA_IP_v6)
	{
#if defined(FEATURE_IPV6_NAT) && !defined(FEATURE_SOCKSv5)
		/* for v6 nat, second pass should go directly to RT block */
		if(IPACM_Iface::ipacmcfg->ipv6_nat_enable)
			flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
		else
#endif
			flt_rule_entry.rule.action = IPACM_Iface::ipacmcfg->IsIpv6CTEnabled()?
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
#ifdef IPA_HDR_L2_ETHERNET_II_AST
		else if (rx_prop->rx[0].hdr_l2_type == IPA_HDR_L2_ETHERNET_II_AST)
		{
			offset_meq_128->offset = -8;
		}
#endif
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
			(get_client_memptr(eth_client, clnt_indx)->lan_stats_idx << 5) | 0x200;
		IPACMDBG_H("Modified rule: %d has rule_id %d\n",
			index, flt_rule_entry.rule.rule_id);
		if(rx_prop->rx[0].attrib.attrib_mask & IPA_FLT_META_DATA)	//turn on meta-data equation
		{
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<9);
			flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.value |= rx_prop->rx[0].attrib.meta_data;
			flt_rule_entry.rule.eq_attrib.metadata_meq32.mask |= rx_prop->rx[0].attrib.meta_data_mask;
		}
#if defined IPA_FLTRT_TTL_UPDATE && defined IPA_TTL_UPDATE_OFFLOAD
		if (IPACM_Iface::ipacmcfg->ttlHwSupport()) {
			if (iptype == IPA_IP_v6)
				flt_rule_entry.rule.ttl_update = IPACM_Wan::is_global_ipv6_addr(flt_rule_entry.rule.attrib.u.v6.dst_addr);
			else
				flt_rule_entry.rule.ttl_update = true;
		}
#endif
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
				IPACMERR("Can't add another meq_32 equation to this rule\n");
				memcpy(&pFilteringTable->rules[i], &flt_rule_entry, sizeof(flt_rule_entry));
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
			for(i=0; i < pFilteringTable->num_rules; i++)
			{
				get_client_memptr(eth_client, clnt_indx)->wan_ul_fl_rule_hdl_v4[i] = pFilteringTable->rules[i].flt_rule_hdl;
			}
			get_client_memptr(eth_client, clnt_indx)->ipv4_ul_rules_set = true;
		}
		else if(iptype == IPA_IP_v6)
		{
			for(i=0; i < pFilteringTable->num_rules; i++)
			{
				get_client_memptr(eth_client, clnt_indx)->wan_ul_fl_rule_hdl_v6[i] = pFilteringTable->rules[i].flt_rule_hdl;
			}
			get_client_memptr(eth_client, clnt_indx)->ipv6_ul_rules_set = true;
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

/* install UL filter rule from Q6 for all clients */
int IPACM_Lan::install_uplink_filter_rule
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
	for (i = 0; i < num_eth_client; i++)
		{
			if (iptype == IPA_IP_v4)
			{
				if (get_client_memptr(eth_client, i)->ipv4_ul_rules_set == false)
				{
#ifdef IPA_HW_FNR_STATS
					if (hw_fnr_stats_support)
					{
						ret = install_uplink_filter_rule_per_client_v2(prop, iptype, xlat_mux_id, get_client_memptr(eth_client, i)->mac,
							get_client_memptr(eth_client, i)->ul_cnt_idx);
						IPACMDBG_H("fnr : IPA_IP_v4 xlat_mux_id: %d, modem_ul_v4_set %d, ul cnt idx = %d\n", xlat_mux_id,
								get_client_memptr(eth_client, i)->ipv4_ul_rules_set, get_client_memptr(eth_client, i)->ul_cnt_idx);
					}
					else
#endif //IPA_HW_FNR_STATS
					{
						ret = install_uplink_filter_rule_per_client(prop, iptype, xlat_mux_id, get_client_memptr(eth_client, i)->mac);
						IPACMDBG_H("IPA_IP_v4 xlat_mux_id: %d, modem_ul_v4_set %d\n", xlat_mux_id, get_client_memptr(eth_client, i)->ipv4_ul_rules_set);
					}
				}
			}
			else if (iptype == IPA_IP_v6)
			{
#ifdef IPA_HW_FNR_STATS
				if (hw_fnr_stats_support)
				{
					if (num_dft_rt_v6 ==1 && get_client_memptr(eth_client, i)->ipv6_ul_rules_set == false)
					{
						ret = install_uplink_filter_rule_per_client_v2(prop, iptype, xlat_mux_id, get_client_memptr(eth_client, i)->mac,
							get_client_memptr(eth_client, i)->ul_cnt_idx);
						IPACMDBG_H("IPA_IP_v6 num_dft_rt_v6 %d xlat_mux_id: %d modem_ul_v6_set: %d, ul_cnt_idx = %d\n", num_dft_rt_v6, xlat_mux_id,
							get_client_memptr(eth_client, i)->ipv6_ul_rules_set, get_client_memptr(eth_client, i)->ul_cnt_idx);
					}
				}
				else
#endif //IPA_HW_FNR_STATS
				{
					if (num_dft_rt_v6 ==1 && get_client_memptr(eth_client, i)->ipv6_ul_rules_set == false)
					{
						ret = install_uplink_filter_rule_per_client(prop, iptype, xlat_mux_id, get_client_memptr(eth_client, i)->mac);
						IPACMDBG_H("IPA_IP_v6 num_dft_rt_v6 %d xlat_mux_id: %d modem_ul_v6_set: %d\n", num_dft_rt_v6, xlat_mux_id,
							get_client_memptr(eth_client, i)->ipv6_ul_rules_set);
					}
				}
			}
			else
			{
				IPACMDBG_H("ip-type: %d modem_ul_v4_set: %d, modem_ul_v6_set %d\n",
					iptype, get_client_memptr(eth_client, i)->ipv4_ul_rules_set, get_client_memptr(eth_client, i)->ipv6_ul_rules_set);

			}
		} /* end of for loop */

	return ret;
}

/* Delete UL filter rule from Q6 per client */
int IPACM_Lan::delete_uplink_filter_rule_per_client
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

	clnt_indx = get_eth_client_index(mac_addr);

	if (clnt_indx == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached \n");
		close(fd);
		return IPACM_FAILURE;
	}

	if (get_client_memptr(eth_client, clnt_indx)->lan_stats_idx == -1)
	{
		IPACMERR("Invalid LAN Stats idx for ethernet client:%d \n", clnt_indx);
		close(fd);
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
		close(fd);
		return IPACM_FAILURE;
	}

	if ((iptype == IPA_IP_v4) && get_client_memptr(eth_client, clnt_indx)->ipv4_ul_rules_set)
	{
		IPACMDBG_H("Del (%d) num of v4 UL rules for cliend idx:%d\n", num_wan_ul_fl_rule_v4[0], clnt_indx);
		if (m_filtering.DeleteFilteringHdls(get_client_memptr(eth_client, clnt_indx)->wan_ul_fl_rule_hdl_v4,
				iptype, num_wan_ul_fl_rule_v4[0]) == false)
		{
			IPACMERR("Error Deleting RuleTable(1) to Filtering, aborting...\n");
			close(fd);
			return IPACM_FAILURE;
		}
		memset(get_client_memptr(eth_client, clnt_indx)->wan_ul_fl_rule_hdl_v4, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
		get_client_memptr(eth_client, clnt_indx)->ipv4_ul_rules_set = false;
	}

	if ((iptype == IPA_IP_v6) && get_client_memptr(eth_client, clnt_indx)->ipv6_ul_rules_set)
	{
		IPACMDBG_H("Del (%d) num of v6 UL rules for cliend idx:%d\n", num_wan_ul_fl_rule_v6[0], clnt_indx);
		if (m_filtering.DeleteFilteringHdls(get_client_memptr(eth_client, clnt_indx)->wan_ul_fl_rule_hdl_v6,
				iptype, num_wan_ul_fl_rule_v6[0]) == false)
		{
			IPACMERR("Error Deleting RuleTable(1) to Filtering, aborting...\n");
			close(fd);
			return IPACM_FAILURE;
		}
#ifndef IPA_V6_UL_WL_FIREWALL_HANDLE
		memset(get_client_memptr(eth_client, clnt_indx)->wan_ul_fl_rule_hdl_v6, 0, MAX_WAN_UL_FILTER_RULES * sizeof(uint32_t));
#else
		memset(get_client_memptr(eth_client, clnt_indx)->wan_ul_fl_rule_hdl_v6, 0, IPACM_MAX_V6_UL_WL_FIREWALL_ENTRIES * sizeof(uint32_t));
#endif
		get_client_memptr(eth_client, clnt_indx)->ipv6_ul_rules_set = false;
	}
	close(fd);
	return IPACM_SUCCESS;
}

/* Delete UL filter rule from Q6 for all clients */
int IPACM_Lan::delete_uplink_filter_rule
(
	ipa_ip_type iptype
)
{
	int ret = IPACM_SUCCESS, i=0;

	for (i = 0; i < num_eth_client; i++)
	{
		if (iptype == IPA_IP_v4)
		{
			if (get_client_memptr(eth_client, i)->ipv4_ul_rules_set == true)
			{
				IPACMDBG_H("IPA_IP_v4 Client id: %d, modem_ul_v4_set %d\n", i, get_client_memptr(eth_client, i)->ipv4_ul_rules_set);
				ret = delete_uplink_filter_rule_per_client(iptype, get_client_memptr(eth_client, i)->mac);
			}
		}
		else if (iptype == IPA_IP_v6)
		{
			if (get_client_memptr(eth_client, i)->ipv6_ul_rules_set == true)
			{
				IPACMDBG_H("IPA_IP_v6 Cliend id: %d modem_ul_v6_set: %d\n", i, get_client_memptr(eth_client, i)->ipv6_ul_rules_set);
				ret = delete_uplink_filter_rule_per_client(iptype, get_client_memptr(eth_client, i)->mac);
			}
		} else {
			ret = IPACM_FAILURE;
			IPACMDBG_H("ip-type: %d lan_stats_idx: %d modem_ul_v4_set: %d, modem_ul_v6_set %d\n",
				iptype, get_client_memptr(eth_client, i)->lan_stats_idx, get_client_memptr(eth_client, i)->ipv4_ul_rules_set, get_client_memptr(eth_client, i)->ipv6_ul_rules_set);
		}
	} /* end of for loop */

	return ret;
}

/* Set lan client info. */
int IPACM_Lan::set_lan_client_info(struct wan_ioctl_lan_client_info *client_info)
{
	int ret = IPACM_SUCCESS;
	int fd_wwan_ioctl;

	if (client_info == NULL)
	{
		IPACMERR("Client info NULL.\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Client MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 client_info->mac[0], client_info->mac[1], client_info->mac[2],
					 client_info->mac[3], client_info->mac[4], client_info->mac[5]);

	fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);

	if(fd_wwan_ioctl < 0)
	{
		IPACMERR("Failed to open %s.\n",WWAN_QMI_IOCTL_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	ret = ioctl(fd_wwan_ioctl, WAN_IOC_SET_LAN_CLIENT_INFO, client_info);
	if (ret != 0)
	{
		IPACMERR("Failed to set client info %p\n ", client_info);
	}
	IPACMDBG("Set Client info: %p\n", client_info);
	close(fd_wwan_ioctl);
	return ret;
}

/* Clear lan client info. */
int IPACM_Lan::clear_lan_client_info(struct wan_ioctl_lan_client_info *client_info)
{
	int ret = IPACM_SUCCESS;
	int fd_wwan_ioctl;

	if (client_info == NULL)
	{
		IPACMERR("Client info NULL.\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Client MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 client_info->mac[0], client_info->mac[1], client_info->mac[2],
					 client_info->mac[3], client_info->mac[4], client_info->mac[5]);

	fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);

	if(fd_wwan_ioctl < 0)
	{
		IPACMERR("Failed to open %s.\n",WWAN_QMI_IOCTL_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	ret = ioctl(fd_wwan_ioctl, WAN_IOC_CLEAR_LAN_CLIENT_INFO, client_info);
	if (ret != 0)
	{
		IPACMERR("Failed to set client info %p\n ", client_info);
	}
	IPACMDBG("Set Client info: %p\n", client_info);
	close(fd_wwan_ioctl);
	return ret;
}

/* Enable per client stats. */
int IPACM_Lan::enable_per_client_stats(bool *status)
{
	int ret = IPACM_SUCCESS;
	int fd_wwan_ioctl;

	if (status == NULL)
	{
		IPACMERR("Status is NULL.\n");
		return IPACM_FAILURE;
	}

	fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);

	if(fd_wwan_ioctl < 0)
	{
		IPACMERR("Failed to open %s.\n",WWAN_QMI_IOCTL_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	ret = ioctl(fd_wwan_ioctl, WAN_IOC_ENABLE_PER_CLIENT_STATS, status);
	if (ret != 0)
	{
		IPACMERR("Failed to enable per client stats %p\n ", status);
	}
	IPACMDBG("Enabled per client stats: %p\n", status);
	close(fd_wwan_ioctl);
	return ret;
}
#endif
int IPACM_Lan::handle_wan_down_v6(bool is_sta_mode, bool is_support_mpdn)
{
	int idx = 0;
	int j;
	if (rx_prop == NULL)
	{
		IPACMERR("Rx prop is NULL, return\n");
		return IPACM_SUCCESS;
	}

#ifdef FEATURE_VLAN_MPDN
	/* prefixes list updated, install rules accordingly */
	if (is_support_mpdn == true)
		modify_ipv6_prefix_flt_rule();
	else
		delete_ipv6_prefix_flt_rule();
#else
	delete_ipv6_prefix_flt_rule();
#endif
	memset(ipv6_prefix, 0, sizeof(ipv6_prefix));
#ifdef FEATURE_IPV6_NAT
	if(IPACM_Iface::ipacmcfg->ipv6_nat_enable)
		delete_ipv6_nat_ula_prefix_flt_rule();
#endif
	if(is_sta_mode == false)
	{
		if(del_ul_flt_rules(IPA_IP_v6))
			return IPACM_FAILURE;

		if(notify_flt_removed(IPACM_Iface::ipacmcfg->GetQmapId()))
			return IPACM_FAILURE;
	}
	else {
		for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {
			/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
			if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
				if (j != 1) {
					IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
					continue;
				} else {
					idx = 2;
					IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
				} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
			} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
				if (j == 0) {
					idx = 0;
				} else {
					IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
					continue;
				}
			} else {
				idx = j * 2;
				IPACMDBG_H("Install rules at idx %d\n", idx);
			}
			if (!m_filtering.DeleteFilteringHdls(&dft_v6fl_rule_hdl[j][m_ipv6_default_filterting_rules_count[j]], IPA_IP_v6, 1)) {
				IPACMERR("Error Deleting last default flt rule, aborting...\n");
				return IPACM_FAILURE;
			}
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, 1);
			dft_v6fl_rule_hdl[j][m_ipv6_default_filterting_rules_count[j]] = 0;
		}
	}

#ifdef FEATURE_IPA_IPSEC
	return handleIpsecUlFltDelAll(IPA_IP_v6);
#else
	return IPACM_SUCCESS;
#endif
}

int IPACM_Lan::reset_to_dummy_flt_rule(ipa_ip_type iptype, uint32_t rule_hdl)
{
	int len, res = IPACM_SUCCESS;
	struct ipa_flt_rule_mdfy flt_rule;
	struct ipa_ioc_mdfy_flt_rule* pFilteringTable;

	IPACMDBG_H("Reset flt rule to dummy, IP type: %d, hdl: %d\n", iptype, rule_hdl);
	len = sizeof(struct ipa_ioc_mdfy_flt_rule) + sizeof(struct ipa_flt_rule_mdfy);
	pFilteringTable = (struct ipa_ioc_mdfy_flt_rule*)malloc(len);

	if (pFilteringTable == NULL)
	{
		IPACMERR("Error allocate flt rule memory...\n");
		return IPACM_FAILURE;
	}
	memset(pFilteringTable, 0, len);

	pFilteringTable->commit = 1;
	pFilteringTable->ip = iptype;
	pFilteringTable->num_rules = 1;

	memset(&flt_rule, 0, sizeof(struct ipa_flt_rule_mdfy));
	flt_rule.status = -1;
	flt_rule.rule_hdl = rule_hdl;

	flt_rule.rule.retain_hdr = 0;
	flt_rule.rule.action = IPA_PASS_TO_EXCEPTION;

	if(iptype == IPA_IP_v4)
	{
		IPACMDBG_H("Reset IPv4 flt rule to dummy\n");

		flt_rule.rule.attrib.attrib_mask = IPA_FLT_SRC_ADDR | IPA_FLT_DST_ADDR;
		flt_rule.rule.attrib.u.v4.dst_addr = ~0;
		flt_rule.rule.attrib.u.v4.dst_addr_mask = ~0;
		flt_rule.rule.attrib.u.v4.src_addr = ~0;
		flt_rule.rule.attrib.u.v4.src_addr_mask = ~0;

		memcpy(&(pFilteringTable->rules[0]), &flt_rule, sizeof(struct ipa_flt_rule_mdfy));
		if (false == m_filtering.ModifyFilteringRule(pFilteringTable))
		{
			IPACMERR("Error modifying filtering rule.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		else
		{
			IPACMDBG_H("Flt rule reset to dummy, hdl: 0x%x, status: %d\n", pFilteringTable->rules[0].rule_hdl,
						pFilteringTable->rules[0].status);
		}
	}
	else if(iptype == IPA_IP_v6)
	{
		IPACMDBG_H("Reset IPv6 flt rule to dummy\n");

		flt_rule.rule.attrib.attrib_mask = IPA_FLT_SRC_ADDR | IPA_FLT_DST_ADDR;
		flt_rule.rule.attrib.u.v6.src_addr[0] = ~0;
		flt_rule.rule.attrib.u.v6.src_addr[1] = ~0;
		flt_rule.rule.attrib.u.v6.src_addr[2] = ~0;
		flt_rule.rule.attrib.u.v6.src_addr[3] = ~0;
		flt_rule.rule.attrib.u.v6.src_addr_mask[0] = ~0;
		flt_rule.rule.attrib.u.v6.src_addr_mask[1] = ~0;
		flt_rule.rule.attrib.u.v6.src_addr_mask[2] = ~0;
		flt_rule.rule.attrib.u.v6.src_addr_mask[3] = ~0;
		flt_rule.rule.attrib.u.v6.dst_addr[0] = ~0;
		flt_rule.rule.attrib.u.v6.dst_addr[1] = ~0;
		flt_rule.rule.attrib.u.v6.dst_addr[2] = ~0;
		flt_rule.rule.attrib.u.v6.dst_addr[3] = ~0;
		flt_rule.rule.attrib.u.v6.dst_addr_mask[0] = ~0;
		flt_rule.rule.attrib.u.v6.dst_addr_mask[1] = ~0;
		flt_rule.rule.attrib.u.v6.dst_addr_mask[2] = ~0;
		flt_rule.rule.attrib.u.v6.dst_addr_mask[3] = ~0;


		memcpy(&(pFilteringTable->rules[0]), &flt_rule, sizeof(struct ipa_flt_rule_mdfy));
		if (false == m_filtering.ModifyFilteringRule(pFilteringTable))
		{
			IPACMERR("Error modifying filtering rule.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		else
		{
			IPACMDBG_H("Flt rule reset to dummy, hdl: 0x%x, status: %d\n", pFilteringTable->rules[0].rule_hdl,
						pFilteringTable->rules[0].status);
		}
	}
	else
	{
		IPACMERR("IP type is not expected.\n");
		res = IPACM_FAILURE;
		goto fail;
	}

fail:
	free(pFilteringTable);
	return res;
}

void IPACM_Lan::post_del_self_evt()
{
	ipacm_cmd_q_data evt;
	ipacm_event_data_fid* fid;
	fid = (ipacm_event_data_fid*)malloc(sizeof(ipacm_event_data_fid));
	if(fid == NULL)
	{
		IPACMERR("Failed to allocate fid memory.\n");
		return;
	}
	memset(fid, 0, sizeof(ipacm_event_data_fid));
	memset(&evt, 0, sizeof(ipacm_cmd_q_data));

	fid->if_index = ipa_if_num;

	evt.evt_data = (void*)fid;
	evt.event = IPA_LAN_DELETE_SELF;

	IPACMDBG_H("Posting event IPA_LAN_DELETE_SELF\n");
	IPACM_EvtDispatcher::PostEvt(&evt);

	if (rx_prop != NULL)
	{
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None &&
			IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Delete corresponding ipa_rm_resource_name of RX-endpoint after delete all IPV4V6 FT-rule */
			IPACMDBG_H("dev %s add producer dependency\n", dev_name);
			IPACMDBG_H("depend Got pipe %d rm index : %d \n", rx_prop->rx[0].src_pipe,
				IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[rx_prop->rx[0].src_pipe]);
			IPACM_Iface::ipacmcfg->DelRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[rx_prop->rx[0].src_pipe]);
		}
#ifndef FEATURE_ETH_BRIDGE_LE
		free(rx_prop);
		rx_prop = NULL;
#endif
	}

#ifndef FEATURE_ETH_BRIDGE_LE
	if (tx_prop != NULL)
	{
		free(tx_prop);
		tx_prop = NULL;
	}

	if (iface_query != NULL)
	{
		free(iface_query);
		iface_query = NULL;
	}
#endif

}

/*handle reset usb-client rt-rules */
int IPACM_Lan::handle_lan_client_reset_rt(ipa_ip_type iptype)
{
	int i, res = IPACM_SUCCESS;

	/* clean eth-client routing rules */
	IPACMDBG_H("left %d eth clients need to be deleted \n ", num_eth_client);
	for (i = 0; i < num_eth_client; i++)
	{
		res = delete_eth_rtrules(i, iptype);
		if (res != IPACM_SUCCESS)
		{
			IPACMERR("Failed to delete old iptype(%d) rules.\n", iptype);
			return res;
		}

#ifdef FEATURE_STATIC_POLICY
	if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
	{
		delete_pdn_dscp_eth_rtrules(iptype, 2, i);
	}
#endif
		/* Delete QOS rules. */
		if (IPACM_Iface::ipacmcfg->ipacm_qos_enable)
			delete_client_qos_rule(get_client_memptr(eth_client, i)->mac,
				0, iptype, NULL);
	} /* end of for loop */

	/* Reset ip-address */
	for (i = 0; i < num_eth_client; i++)
	{
		if(iptype == IPA_IP_v4)
		{
			get_client_memptr(eth_client, i)->ipv4_set = false;
		}
		else
		{
			/* clean up the map and release the memory */
			for (auto &it : rt_hdl_v6_list[i]) {
				IPACMDBG_H("v6 addr : 0x%08x:%08x:%08x:%08x\n", it.first[0], it.first[1],
					   it.first[2], it.first[3]);
			}
			IPACMDBG_H("client %d has %d ipv6 with rt: %d, current total_v6=%d \n", i,
				get_client_memptr(eth_client, i)->ipv6_set,
				get_client_memptr(eth_client, i)->route_rule_set_v6,
				IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
			IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6 -= get_client_memptr(eth_client, i)->ipv6_set;
			IPACMDBG_H("update ipa_num_clients_ipv6 = %d\n", IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
			get_client_memptr(eth_client, i)->ipv6_set = 0;
			rt_hdl_v6_list[i].clear();
		}
	} /* end of for loop */
	return res;
}

int IPACM_Lan::install_ipv4_icmp_flt_rule()
{
	int ret = IPACM_SUCCESS;
	struct ipa_ioc_add_flt_rule_v2 *flt_rule = NULL;
	struct ipa_flt_rule_add_v2 *flt_rule_entry = NULL;
	int idx = 0;
	int j = 0;

	if (rx_prop == NULL)
	{
		IPACMERR("rx/tx properties empty...exit\n");
		return IPACM_FAILURE;
	}
	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++)
	{
		IPACMDBG_H("Will attempt to add v4 icmp filter rule for prop idx %d\n", idx);
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		static const int NUM_RULES = 1;

		char buf1[sizeof(struct ipa_ioc_add_flt_rule_v2)];

		flt_rule = (struct ipa_ioc_add_flt_rule_v2 *)buf1;

		char buf2[NUM_RULES * sizeof(struct ipa_flt_rule_add_v2)];

		flt_rule_entry = (struct ipa_flt_rule_add_v2 *)buf2;

		memset(buf1, 0, sizeof(buf1));
		memset(buf2, 0, sizeof(buf2));

		flt_rule->rules = (uint64_t)flt_rule_entry;

		prio[j][IPA_IP_v4]++;
		flt_rule->commit = 1;
		flt_rule->ep = rx_prop->rx[idx].src_pipe;
		flt_rule->global = false;
		flt_rule->ip = IPA_IP_v4;
		flt_rule->num_rules = NUM_RULES;
		flt_rule->flt_rule_size = sizeof(struct ipa_flt_rule_add_v2);

		flt_rule_entry->rule.retain_hdr = 1;
		flt_rule_entry->rule.to_uc = 0;
		flt_rule_entry->rule.eq_attrib_type = 0;
		flt_rule_entry->at_rear = true;
		flt_rule_entry->flt_rule_hdl = -1;
		flt_rule_entry->status = -1;
		flt_rule_entry->rule.action = IPA_PASS_TO_EXCEPTION;
#ifdef FEATURE_IPA_V3
		flt_rule_entry->rule.hashable = true;
#endif
		flt_rule_entry->rule.close_aggr_irq_mod = true;
		memcpy(&flt_rule_entry->rule.attrib, &rx_prop->rx[idx].attrib, sizeof(flt_rule_entry->rule.attrib));

		flt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_PROTOCOL;
		flt_rule_entry->rule.attrib.u.v4.protocol = (uint8_t)IPACM_FIREWALL_IPPROTO_ICMP;

		if (m_filtering.AddFilteringRule_v2(flt_rule) == false) {
			IPACMERR("Error Adding Filtering rule, aborting...\n");
			ret = IPACM_FAILURE;
		} else {
			IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, NUM_RULES);
			ipv4_icmp_flt_rule_hdl[j][0] = flt_rule_entry->flt_rule_hdl;
			IPACMDBG_H("IPv4 icmp filter rule HDL:0x%x\n", ipv4_icmp_flt_rule_hdl[j][0]);
		}
	}

	return ret;
}

int IPACM_Lan::install_ipv6_icmp_flt_rule()
{
	int ret = IPACM_SUCCESS;
	struct ipa_ioc_add_flt_rule_v2 *flt_rule;
	struct ipa_flt_rule_add_v2 *flt_rule_entry;
	int idx = 0, j;

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return ret;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		IPACMDBG_H("Will attempt to add v6 icmp filter rule for prop idx %d\n", idx);

		static const int NUM_RULES = 1;

		char buf1[sizeof(struct ipa_ioc_add_flt_rule_v2)];

		flt_rule = (struct ipa_ioc_add_flt_rule_v2 *)buf1;

		char buf2[NUM_RULES * sizeof(struct ipa_flt_rule_add_v2)];

		flt_rule_entry = (struct ipa_flt_rule_add_v2 *)buf2;

		memset(buf1, 0, sizeof(buf1));
		memset(buf2, 0, sizeof(buf2));

		flt_rule->rules = (uint64_t)flt_rule_entry;

		flt_rule->commit = 1;
		flt_rule->ep = rx_prop->rx[idx].src_pipe;
		flt_rule->global = false;
		flt_rule->ip = IPA_IP_v6;
		flt_rule->num_rules = NUM_RULES;
		flt_rule->flt_rule_size = sizeof(struct ipa_flt_rule_add_v2);

		prio[j][IPA_IP_v6]++;
		flt_rule_entry->rule.retain_hdr = 1;
		flt_rule_entry->rule.to_uc = 0;
		flt_rule_entry->rule.eq_attrib_type = 0;
		flt_rule_entry->at_rear = true;
		flt_rule_entry->flt_rule_hdl = -1;
		flt_rule_entry->status = -1;
		flt_rule_entry->rule.action = IPA_PASS_TO_EXCEPTION;
#ifdef FEATURE_IPA_V3
		flt_rule_entry->rule.hashable = false;
#endif
		flt_rule_entry->rule.close_aggr_irq_mod = true;
		memcpy(&flt_rule_entry->rule.attrib, &rx_prop->rx[idx].attrib, sizeof(flt_rule_entry->rule.attrib));

		flt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_NEXT_HDR;
		flt_rule_entry->rule.attrib.u.v6.next_hdr = (uint8_t)IPACM_FIREWALL_IPPROTO_ICMP6;

		if (m_filtering.AddFilteringRule_v2(flt_rule) == false) {
			IPACMERR("Error Adding Filtering rule, aborting...\n");
			ret = IPACM_FAILURE;
		} else {
			IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, NUM_RULES);
			ipv6_icmp_flt_rule_hdl[j][0] = flt_rule_entry->flt_rule_hdl;
			IPACMDBG_H("IPv6 icmp filter rule HDL:0x%x\n", ipv6_icmp_flt_rule_hdl[0]);
		}
	}

	return ret;
}

#ifdef FEATURE_L2TP
int IPACM_Lan::install_l2tp_inner_private_subnet_flt_rule()
{
	int i;
	ipa_ioc_add_flt_rule *m_pFilteringTable;
	ipa_flt_rule_add *flt_rule_entry;

	if(rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	m_pFilteringTable = (struct ipa_ioc_add_flt_rule *)
		 calloc(1, sizeof(struct ipa_ioc_add_flt_rule) +
			(IPACM_Iface::ipacmcfg->ipa_num_private_subnet) * sizeof(struct ipa_flt_rule_add));
	if(!m_pFilteringTable)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	m_pFilteringTable->commit = 1;
	m_pFilteringTable->ep = rx_prop->rx[0].src_pipe;
	m_pFilteringTable->global = false;
	m_pFilteringTable->ip = IPA_IP_v6;
	m_pFilteringTable->num_rules = (uint8_t)IPACM_Iface::ipacmcfg->ipa_num_private_subnet;

	for(i = 0; i < (IPACM_Iface::ipacmcfg->ipa_num_private_subnet); i++)
	{
		flt_rule_entry = &m_pFilteringTable->rules[i];
		flt_rule_entry->at_rear = true;
		flt_rule_entry->rule.retain_hdr = 1;
		flt_rule_entry->flt_rule_hdl = -1;
		flt_rule_entry->status = -1;
		flt_rule_entry->rule.action = IPA_PASS_TO_EXCEPTION;

		memcpy(&flt_rule_entry->rule.attrib, &rx_prop->rx[1].attrib,
			sizeof(flt_rule_entry->rule.attrib));
		flt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_NEXT_HDR;
		flt_rule_entry->rule.attrib.u.v6.next_hdr = 0x73;
		flt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_L2TP_INNER_IP_TYPE;
		flt_rule_entry->rule.attrib.type = 0x40;
		flt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_L2TP_INNER_IPV4_DST_ADDR;
		flt_rule_entry->rule.attrib.u.v4.dst_addr_mask = IPACM_Iface::ipacmcfg->private_subnet_table[i].subnet_mask;
		flt_rule_entry->rule.attrib.u.v4.dst_addr = IPACM_Iface::ipacmcfg->private_subnet_table[i].subnet_addr;
	}

	if(false == m_filtering.AddFilteringRule(m_pFilteringTable))
	{
		IPACMERR("Error Adding Filtering, aborting...\n");
		free(m_pFilteringTable);
		return IPACM_FAILURE;
	}
	IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, IPACM_Iface::ipacmcfg->ipa_num_private_subnet);

	/* copy filter rule hdls */
	for (i = 0; i < IPACM_Iface::ipacmcfg->ipa_num_private_subnet; i++)
	{
		l2tp_inner_private_subnet_flt_rule_hdl[i] = m_pFilteringTable->rules[i].flt_rule_hdl;
	}
	free(m_pFilteringTable);
	return IPACM_SUCCESS;
}
#endif

int IPACM_Lan::modify_private_subnet(bool eogre_enabled)
{
	int i, j, len, res = IPACM_SUCCESS;
	struct ipa_flt_rule_add flt_rule;
	struct ipa_ioc_add_flt_rule_after* pFilteringTable = NULL;
	int mtu_rule_cnt = 0;
	uint16_t mtu[IPA_MAX_MTU_ENTRIES] = { };
	uint16_t vid[IPA_MAX_MTU_ENTRIES] = { };
	uint32_t wan_ipv4_addr[IPA_MAX_MTU_ENTRIES] = { };
	int mtu_rule_idx = IPACM_Iface::ipacmcfg->ipa_num_private_subnet;
	int idx = 0;
	int is_if_eth_ezmesh = false;

	if(ip_type == IPA_IP_v6)
	{
		IPACMERR("inconsistent iptype. iptype = %d\n", ip_type);
		return IPACM_FAILURE;
	}

	if(rx_prop == NULL)
	{
		IPACMERR("no rx props\n");
		return IPACM_FAILURE;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		mtu_rule_cnt = i = 0;
		mtu_rule_idx = IPACM_Iface::ipacmcfg->ipa_num_private_subnet;

		if (num_wan_subnet_rules[j] > 0) {
			if (m_filtering.DeleteFilteringHdls(private_fl_rule_hdl[j], IPA_IP_v4, num_wan_subnet_rules[j]) == false) {
				IPACMERR("Error deleting private subnet IPv4 flt rules.\n");
				return IPACM_FAILURE;
			}
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, num_wan_subnet_rules[j]);
			memset(private_fl_rule_hdl[j], 0, (IPA_MAX_PRIVATE_SUBNET_ENTRIES + IPA_MAX_MTU_ENTRIES) * sizeof(uint32_t));
			num_wan_subnet_rules[j] = 0;
		}

		if (IPACM_Iface::ipacmcfg->ipa_num_private_subnet == 0) {
			IPACMDBG("no need configure subnet rules \n");
			return IPACM_SUCCESS;
		}

		if (dft_v4fl_rule_hdl[j][0] == 0  && eogre_enabled == false)
		{
			IPACMERR("install v4 default rules first.Subnet + MTU rule will be installed later\n");
			return IPACM_FAILURE;
		}

		/* for single PDN case, only add MTU rule for first subnet */
		if (IPACM_Wan::isWanUP(ipa_if_num) &&
			(!IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name) || is_if_eth_ezmesh)) {
			/* first subnet is reserved for default PDN */
			mtu[0] = IPACM_Wan::queryMTU(ipa_if_num, IPA_IP_v4);
			IPACMDBG_H("defaut PDN mtu = %d\n", mtu[0]);
			mtu_rule_cnt++;

		}

		//In the future, can use GetWanPDNinfo for all usecases
		if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
		{
			mtu_rule_cnt = IPACM_Wan::GetWanPDNinfo(mtu, wan_ipv4_addr, IPA_IP_v4);
			IPACMDBG_H("total %d MTU rules are needed\n", mtu_rule_cnt);
		}

#ifdef FEATURE_EoGRE
		/* if in GRE mode, also query MTU since WanUP flag is false but WAN is up */
		if (IPACM_Iface::ipacmcfg->eogre_enabled) {
			/* re-calculate the ipv4 mtu based on GRE tunnel type*/
			if (IPACM_Iface::ipacmcfg->eogre_info.iptype == IPA_IP_v4)
				/* mtu_v4_new = mtu_v4 - 20(ipv4) - 4(gre) - 18(eth + VLAN) */
				mtu[0] = IPACM_Wan::queryMTU(ipa_if_num, IPA_IP_v4) - sizeof(v4_gre_hdr_t) - 18;
			else if (IPACM_Iface::ipacmcfg->eogre_info.iptype == IPA_IP_v6 && 
					IPACM_Iface::ipacmcfg->v6options_enabled == true)
				/* mtu_v4_new = mtu_v6 - 40(ipv6) - 8(opt) - 4(gre) - 18(eth + VLAN) */
				mtu[0] = IPACM_Wan::queryMTU(ipa_if_num, IPA_IP_v6) - sizeof(v6_gre_hdr_t) - 18;
			else if (IPACM_Iface::ipacmcfg->eogre_info.iptype == IPA_IP_v6 &&
					IPACM_Iface::ipacmcfg->v6options_enabled == false)
				mtu[0] = IPACM_Wan::queryMTU(ipa_if_num, IPA_IP_v6) - sizeof(v6_eogre_hdr_s) - 18;
			else
				IPACMERR("invalid iptype = %d\n", IPACM_Iface::ipacmcfg->eogre_info.iptype);

			IPACMDBG("GRE v4 PDN mtu = %d\n", mtu[0]);
			IPACMDBG("num_wan_ul_fl_rule_v4= %d\n", num_wan_ul_fl_rule_v4);

			//add the MTU rule after the 2nd pass rules but before the 1st pass rule
			if (num_wan_ul_fl_rule_v4) {
				IPACMDBG("v4 GRE MTU rule will be installed after v4 modem UL rules\n");
				mtu_flt_rule_offset[j][IPA_IP_v4] = wan_ul_fl_rule_hdl_v4[j][num_wan_ul_fl_rule_v4[j] - 1];
			} else {
				IPACMDBG("v4 GRE MTU rule will be installed after v4 default rules\n");
				mtu_flt_rule_offset[j][IPA_IP_v4] = dft_v4fl_rule_hdl[j][m_ipv4_default_filterting_rules_count[j] - 1];
			}
			mtu_rule_cnt++;
		}
#endif

#ifdef FEATURE_VLAN_MPDN
		/* for MPDN case, need to query VLAN and mtus */
		if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
		{
			if (IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name) && IPACM_Wan::isVlanWanUP())
			{
				for (i = mtu_rule_cnt; i < IPACM_Iface::ipacmcfg->ipa_num_private_subnet; i++)
				{
					vid[i] = IPACM_Iface::ipacmcfg->get_bridge_vlan_mapping_from_subnet(
						IPACM_Iface::ipacmcfg->private_subnet_table[i].subnet_addr);

					if (!vid[i])
						mtu[i] = DEFAULT_MTU_SIZE;
					else
						IPACM_Wan::GetMTUByVid(&mtu[i], vid[i], IPA_IP_v4);

					IPACMDBG_H("mtu = %d for subnet %d\n", mtu[i], i);
					mtu_rule_cnt++;
				}
				IPACMDBG_H("total %d MTU rules are needed\n", mtu_rule_cnt);
			}
		}
#endif
		IPACMDBG_H("Memory allocating for ipa_num_private_subnet = %d mtu_rule_cnt = %d\n", IPACM_Iface::ipacmcfg->ipa_num_private_subnet, mtu_rule_cnt);
		len = sizeof(struct ipa_ioc_add_flt_rule_after) + (IPACM_Iface::ipacmcfg->ipa_num_private_subnet + mtu_rule_cnt) * sizeof(struct ipa_flt_rule_add);
		pFilteringTable = (struct ipa_ioc_add_flt_rule_after *)malloc(len);
		if (!pFilteringTable) {
			IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
			return IPACM_FAILURE;
		}
		memset(pFilteringTable, 0, len);

		pFilteringTable->commit = 1;
		pFilteringTable->ip = IPA_IP_v4;
		pFilteringTable->num_rules = num_wan_subnet_rules[j] = (uint8_t)IPACM_Iface::ipacmcfg->ipa_num_private_subnet + mtu_rule_cnt;
		pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
		pFilteringTable->add_after_hdl = mtu_flt_rule_offset[j][IPA_IP_v4];
		IPACMDBG_H("pFilteringTable->add_after_hdl 0x%x\n", pFilteringTable->add_after_hdl);

		/* Make LAN-traffic always go A5, use default IPA-RT table */
		if (false == m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_default_v4)) {
			IPACMERR("Failed to get routing table handle.\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		memset(&flt_rule, 0, sizeof(struct ipa_flt_rule_add));
		flt_rule.status = -1;
		flt_rule.at_rear = 1;

		flt_rule.rule.retain_hdr = 1;
		flt_rule.rule.to_uc = 0;
		flt_rule.rule.action = IPA_PASS_TO_ROUTING;
		flt_rule.rule.eq_attrib_type = 0;
		flt_rule.rule.rt_tbl_hdl = IPACM_Iface::ipacmcfg->rt_tbl_default_v4.hdl;
		IPACMDBG_H("Private filter rule use table: %s\n", IPACM_Iface::ipacmcfg->rt_tbl_default_v4.name);

		for (i = 0; i < (IPACM_Iface::ipacmcfg->ipa_num_private_subnet); i++) {
			/* add private subnet rule for ipv4 */
			flt_rule.rule.action = IPA_PASS_TO_ROUTING;
			flt_rule.rule.eq_attrib_type = 0;
			flt_rule.rule.hashable = true;
			memcpy(&flt_rule.rule.attrib, &rx_prop->rx[idx].attrib, sizeof(flt_rule.rule.attrib));
			flt_rule.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
			flt_rule.rule.attrib.u.v4.dst_addr_mask = IPACM_Iface::ipacmcfg->private_subnet_table[i].subnet_mask;
			flt_rule.rule.attrib.u.v4.dst_addr = IPACM_Iface::ipacmcfg->private_subnet_table[i].subnet_addr;
			memcpy(&(pFilteringTable->rules[i]), &flt_rule, sizeof(struct ipa_flt_rule_add));
			IPACMDBG_H(" IPACM private subnet_addr as: 0x%x entry(%d)\n", flt_rule.rule.attrib.u.v4.dst_addr, i);
		}
		flt_rule.rule.hashable = false;
		/* add MTU rules for ipv4 */
		for(i = 0; i < mtu_rule_cnt; i++)
		{

			/* add corresponding MTU rule for ipv4 */
			if (mtu[i] > 0)
			{

				memcpy(&flt_rule.rule.attrib, &rx_prop->rx[idx].attrib, sizeof(flt_rule.rule.attrib));

				/* if Vlan enabled, add vlan id as a parameter of the MTU rule*/
				if (vid[i])
				{
					flt_rule.rule.attrib.attrib_mask |= IPA_FLT_VLAN_ID;
					flt_rule.rule.attrib.vlan_id = vid[i];
				}

				/* if static policy enabled. use PDN addr as src addr */
				if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)   //should use this for everything in future
				{
					flt_rule.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
					flt_rule.rule.attrib.u.v4.src_addr_mask = 0xFFFFFFFF;
					flt_rule.rule.attrib.u.v4.src_addr = wan_ipv4_addr[i];
				}

				if (construct_mtu_rule(&flt_rule.rule, IPA_IP_v4, mtu[i]))
					IPACMERR("Failed to modify MTU filtering rule.\n");
				memcpy(&(pFilteringTable->rules[mtu_rule_idx]), &flt_rule, sizeof(struct ipa_flt_rule_add));
				IPACMDBG_H("Succesfully constructed v4 MTU rule for vlan id %d entry(%d)\n", vid[i], mtu_rule_idx); //maybe update this print
				mtu_rule_idx++;
			}
		}

#ifdef FEATURE_EoGRE
		//Case where eogre is enabled for opposite iptype. Need to install MTU rule with no subnets
		if (IPACM_Iface::ipacmcfg->ipa_num_private_subnet == 0 && IPACM_Iface::ipacmcfg->eogre_enabled && IPACM_Iface::ipacmcfg->eogre_info.iptype == IPA_IP_v6) {
			if (construct_mtu_rule(&flt_rule.rule, IPA_IP_v4, mtu[0])) IPACMERR("Failed to modify MTU filtering rule.\n");
			memcpy(&(pFilteringTable->rules[mtu_rule_idx++]), &flt_rule, sizeof(struct ipa_flt_rule_add));
			IPACMDBG_H("Succesfully constructed GRE v4 MTU rule\n");
		}
#endif

		if (false == m_filtering.AddFilteringRuleAfter(pFilteringTable)) {
			IPACMERR("Failed to modify private subnet filtering rules.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, num_wan_subnet_rules[j]);

		/* save the rule hdls */
		for (i = 0; i < num_wan_subnet_rules[j]; i++) {
			private_fl_rule_hdl[j][i] = pFilteringTable->rules[i].flt_rule_hdl;
			IPACMDBG("Adding filter hdl:(0x%x)\n", private_fl_rule_hdl[j][i]);
		}

		if (pFilteringTable != NULL)
		{
			free(pFilteringTable);
			pFilteringTable = NULL;
		}
	}

fail:
	if(pFilteringTable != NULL)
	{
		free(pFilteringTable);
	}
	return res;
}

int IPACM_Lan::handle_private_subnet_android(ipa_ip_type iptype)
{
	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	if(iptype == IPA_IP_v6)
	{
		IPACMDBG_H("There is no ipv6 dummy filter rules needed for iface %s\n", dev_name);
		return 0;
	}
	else
	{
		return modify_private_subnet();
	}

	return IPACM_FAILURE;
}

#ifdef FEATURE_VLAN_MPDN
int IPACM_Lan::modify_ipv6_prefix_flt_rule(bool eogre_enabled)
{
	int i, len, res = IPACM_SUCCESS;
	struct ipa_flt_rule_add flt_rule;
	struct ipa_ioc_add_flt_rule_after* pFilteringTable = NULL;
	int mtu_rule_cnt = 0, idx = 0;
	uint16_t mtu[IPA_MAX_MTU_ENTRIES] = { };
	uint16_t vid[IPA_MAX_MTU_ENTRIES] = { };
#ifdef FEATURE_STATIC_POLICY
	uint32_t wan_ipv6_addr[IPA_MAX_MTU_ENTRIES][2] = { };
#endif
	int mtu_rule_idx = IPACM_Iface::ipacmcfg->num_ipv6_prefixes +
						IPACM_Iface::ipacmcfg->num_no_offload_ipv6_prefix;
	int j;

	if(rx_prop == NULL)
	{
		IPACMERR("no rx props\n");
		return IPACM_FAILURE;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		mtu_rule_cnt = i = 0;
		mtu_rule_idx = IPACM_Iface::ipacmcfg->num_ipv6_prefixes +
						IPACM_Iface::ipacmcfg->num_no_offload_ipv6_prefix;
		IPACMDBG_H("Install rules at idx %d\n", idx);

		if (ip_type == IPA_IP_v4)
		{
			IPACMERR("inconsistent iptype. iptype = %d\n", ip_type);
			return IPACM_FAILURE;
		}

		/* not supported for wlan vlan for now */
		if (ipa_if_cate == WLAN_IF && !is_wlan_if_vlan &&
					!IPACM_Iface::ipacmcfg->ipacm_static_policy_enable) {
			IPACMERR("not supported for wlan without vlan in"
						" non-static policy mode.\n");
			return IPACM_SUCCESS;
		}

		if (dft_v6fl_rule_hdl[j][0] == 0 && eogre_enabled == false)
		{
			IPACMERR("install v6 default rules first.Prefix + MTU rule will be installed later\n");
			return IPACM_FAILURE;
		}

		IPACMDBG_H("modifying offload prefixes, num %d\n", IPACM_Iface::ipacmcfg->num_ipv6_prefixes);
		IPACMDBG_H("modifying no offload prefixes, num %d\n", IPACM_Iface::ipacmcfg->num_no_offload_ipv6_prefix);

		if (num_wan_prefix_rules[j] > 0) {
			if (m_filtering.DeleteFilteringHdls(ipv6_prefix_flt_rule_hdl[j], IPA_IP_v6,
												num_wan_prefix_rules[j]) == false) {
				IPACMERR("Error Deleting Filtering, aborting...\n");
				return IPACM_FAILURE;
			}
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, num_wan_prefix_rules[j]);
			num_wan_prefix_rules[j] = 0;
		}

		if (IPACM_Iface::ipacmcfg->num_ipv6_prefixes == 0 && IPACM_Iface::ipacmcfg->num_no_offload_ipv6_prefix == 0) {
#ifdef FEATURE_EoGRE
			if (IPACM_Iface::ipacmcfg->eogre_enabled) {
				IPACMDBG("GRE is enabled, need to configure v6 MTU \n");
			} else {
				IPACMDBG("no need configure prefix rules \n");
				return IPACM_SUCCESS;
			}
#else
			IPACMDBG("no need configure prefix rules \n");
			continue;
#endif
		}

	/* for single PDN case, only add MTU rule for first prefix */
	if(IPACM_Wan::isWanUP_V6(ipa_if_num) && !IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name))
	{
		/* first prefix is reserved for default PDN */
		mtu[0] = IPACM_Wan::queryMTU(ipa_if_num, IPA_IP_v6);
		IPACMDBG_H("defaut PDN mtu = %d\n", mtu[0]);
		mtu_rule_cnt++;
	}

	/* for MPDN case, need to query VLAN and mtus */
	if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
	{
		if(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name) && IPACM_Wan::isVlanWanUP_V6())
		{
			for(i = 0; i < IPACM_Iface::ipacmcfg->num_ipv6_prefixes; i++)
			{
				vid[i] = IPACM_Iface::ipacmcfg->ipa_ipv6_prefixes[i].vlan_id;
				if (!vid[i])
					mtu[i] = DEFAULT_MTU_SIZE;
				else
					IPACM_Wan::GetV6MTUByPrefix(&mtu[i], IPACM_Iface::ipacmcfg->ipa_ipv6_prefixes[i].addr); //might be able to get MTU by vid now
				IPACMDBG_H("mtu = %d for prefix %d\n", mtu[i], i);
				mtu_rule_cnt++;
			}
			IPACMDBG_H("total %d MTU rules are needed\n", mtu_rule_cnt);
		}
	}

#ifdef FEATURE_STATIC_POLICY
	//In the future, can use GetWanPDNinfo for all usecases
	if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
	{
		mtu_rule_cnt = IPACM_Wan::GetWanPDNinfo_v6(mtu, wan_ipv6_addr, IPA_IP_v6);
		IPACMDBG_H("total %d MTU rules are needed\n", mtu_rule_cnt);
	}
#endif

#ifdef FEATURE_EoGRE
		/* if in GRE mode, also query MTU since WANup_v6 flag is false but WANv6 is up*/
		if (IPACM_Iface::ipacmcfg->eogre_enabled)
		{
			/* re-calculate the ipv6 mtu based on GRE tunnel type*/
			if (IPACM_Iface::ipacmcfg->eogre_info.iptype == IPA_IP_v4)
				/* mtu_v6_new = mtu_v4 - 20(ipv4) - 4(gre) - 18(eth + vlan) - 40(inner_ipv6) */
				mtu[0] = IPACM_Wan::queryMTU(ipa_if_num, IPA_IP_v4) - sizeof(v4_gre_hdr_t) - 18;
			else if (IPACM_Iface::ipacmcfg->eogre_info.iptype == IPA_IP_v6 &&
					IPACM_Iface::ipacmcfg->v6options_enabled == true)
				/* mtu_v6_new = mtu_v6 - 40(ipv6) - 8(opt) - 4(gre)- 18(eth + vlan) - 40(inner_ipv6) */
				mtu[0] = IPACM_Wan::queryMTU(ipa_if_num, IPA_IP_v6) - sizeof(v6_gre_hdr_t) - 18;
			else if (IPACM_Iface::ipacmcfg->eogre_info.iptype == IPA_IP_v6 &&
					IPACM_Iface::ipacmcfg->v6options_enabled == false)
				mtu[0] = IPACM_Wan::queryMTU(ipa_if_num, IPA_IP_v6) -
							 sizeof(v6_eogre_hdr_s) - 18;
			else
				IPACMERR("invalid iptype = %d\n", IPACM_Iface::ipacmcfg->eogre_info.iptype);

			IPACMDBG("GRE v6 PDN mtu = %d\n", mtu[0]);
			IPACMDBG("num_wan_ul_fl_rule_v6= %d\n", num_wan_ul_fl_rule_v6[j]);

			//add the MTU rule after the 2nd pass rules but before the 1st pass rule
			if (num_wan_ul_fl_rule_v6[j]) {
				IPACMDBG("v6 GRE MTU rule will be installed after v6 modem UL rules\n");
				mtu_flt_rule_offset[j][IPA_IP_v6] = wan_ul_fl_rule_hdl_v6[j][num_wan_ul_fl_rule_v6[j] - 1];
			} else {
				IPACMDBG("v6 GRE MTU rule will be installed after v6 default rules\n");
				mtu_flt_rule_offset[j][IPA_IP_v6] = dft_v6fl_rule_hdl[j][m_ipv6_default_filterting_rules_count[j] - 1];
			}

			mtu_rule_cnt++;
		}
#endif
		IPACMDBG_H("Memory allocating for num_ipv6_prefixes rules = %d num_no_offload_ipv6_prefix rules = %d mtu_rule_cnt = %d\n", IPACM_Iface::ipacmcfg->num_ipv6_prefixes, IPACM_Iface::ipacmcfg->num_no_offload_ipv6_prefix, mtu_rule_cnt);
		len = sizeof(struct ipa_ioc_add_flt_rule_after) + (IPACM_Iface::ipacmcfg->num_ipv6_prefixes + IPACM_Iface::ipacmcfg->num_no_offload_ipv6_prefix + mtu_rule_cnt) * sizeof(struct ipa_flt_rule_add);
		pFilteringTable = (struct ipa_ioc_add_flt_rule_after *)malloc(len);
		if (!pFilteringTable) {
			IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
			return IPACM_FAILURE;
		}
		memset(pFilteringTable, 0, len);

		pFilteringTable->commit = 1;
		pFilteringTable->ip = IPA_IP_v6;
		pFilteringTable->num_rules = num_wan_prefix_rules[j] = (uint8_t)IPACM_Iface::ipacmcfg->num_ipv6_prefixes + IPACM_Iface::ipacmcfg->num_no_offload_ipv6_prefix + mtu_rule_cnt;
		if (pFilteringTable->num_rules > IPA_MAX_IPV6_NO_OFFLOAD_PREFIX_FLT_RULE + IPA_MAX_MTU_ENTRIES) {
			IPACMERR("Number of rules crossed the maximum available space");
			return IPACM_FAILURE;
		}
		pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
		pFilteringTable->add_after_hdl = mtu_flt_rule_offset[j][IPA_IP_v6];

		/* Make LAN-traffic always go to Apps, use default IPA-RT table */
		if (false == m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_default_v6)) {
			IPACMERR("LAN m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_default_v6=0x%p) Failed.\n",
						&IPACM_Iface::ipacmcfg->rt_tbl_default_v6);
			free(pFilteringTable);
			return IPACM_FAILURE;
		}

		memset(&flt_rule, 0, sizeof(struct ipa_flt_rule_add));
		flt_rule.status = -1;
		flt_rule.at_rear = 1;
		flt_rule.rule.retain_hdr = 1;
		flt_rule.rule.to_uc = 0;
		flt_rule.rule.action = IPA_PASS_TO_ROUTING;
		flt_rule.rule.rt_tbl_hdl = IPACM_Iface::ipacmcfg->rt_tbl_default_v6.hdl;
		flt_rule.rule.eq_attrib_type = 0;
		/* first install DST address exception rules for offloaded PDNs */
		for (i = 0; i < (IPACM_Iface::ipacmcfg->num_ipv6_prefixes); i++) {
			/* add private prefix rule for ipv6 */
			flt_rule.rule.eq_attrib_type = 0;
			memcpy(&flt_rule.rule.attrib, &rx_prop->rx[idx].attrib, sizeof(flt_rule.rule.attrib));
			flt_rule.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
			flt_rule.rule.attrib.u.v6.dst_addr[0] = IPACM_Iface::ipacmcfg->ipa_ipv6_prefixes[i].addr[0];
			flt_rule.rule.attrib.u.v6.dst_addr[1] = IPACM_Iface::ipacmcfg->ipa_ipv6_prefixes[i].addr[1];
			flt_rule.rule.attrib.u.v6.dst_addr[2] = 0x0;
			flt_rule.rule.attrib.u.v6.dst_addr[3] = 0x0;
			flt_rule.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
			flt_rule.rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
			flt_rule.rule.attrib.u.v6.dst_addr_mask[2] = 0x0;
			flt_rule.rule.attrib.u.v6.dst_addr_mask[3] = 0x0;
			memcpy(&(pFilteringTable->rules[i]), &flt_rule, sizeof(struct ipa_flt_rule_add));
			IPACMDBG_H(" IPACM v6 prefix as: 0x[%X][%X] entry(%d)\n",
					   flt_rule.rule.attrib.u.v6.dst_addr[0],
					   flt_rule.rule.attrib.u.v6.dst_addr[1], i);

			/* add corresponding MTU rule for ipv6 */
			if (mtu[i] > 0 && mtu[i] ) {
				memcpy(&flt_rule.rule.attrib, &rx_prop->rx[idx].attrib, sizeof(flt_rule.rule.attrib));

				/* if Vlan enabled, add vlan id as a parameter of the MTU rule*/
				if (vid[i]) {
					flt_rule.rule.attrib.attrib_mask |= IPA_FLT_VLAN_ID;
					flt_rule.rule.attrib.vlan_id = vid[i];
				}

#ifdef FEATURE_STATIC_POLICY
				/* if static policy enabled. use PDN addr as src addr */
				if (IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)   //should use this for everything in future
				{
					flt_rule.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
					flt_rule.rule.attrib.u.v6.src_addr[0] = wan_ipv6_addr[i][0];
					flt_rule.rule.attrib.u.v6.src_addr[1] = wan_ipv6_addr[i][1];
					flt_rule.rule.attrib.u.v6.src_addr[2] = 0x0;
					flt_rule.rule.attrib.u.v6.src_addr[3] = 0x0;
					flt_rule.rule.attrib.u.v6.src_addr_mask[0] = 0xFFFFFFFF;
					flt_rule.rule.attrib.u.v6.src_addr_mask[1] = 0xFFFFFFFF;
					flt_rule.rule.attrib.u.v6.src_addr_mask[2] = 0x0;
					flt_rule.rule.attrib.u.v6.src_addr_mask[3] = 0x0;
				}
#endif

				if (construct_mtu_rule(&flt_rule.rule, IPA_IP_v6, mtu[i])) IPACMERR("Failed to modify MTU filtering rule.\n");
				memcpy(&(pFilteringTable->rules[mtu_rule_idx]), &flt_rule, sizeof(struct ipa_flt_rule_add));

				IPACMDBG_H("Succesfully constructed v6 MTU rule for vlan id %d entry(%d)\n", vid[i], mtu_rule_idx);
				mtu_rule_idx++;
			}
		}

		/* reset the attrib for no offload prefix rules */
		flt_rule.rule.eq_attrib_type = 0;
		memcpy(&flt_rule.rule.attrib, &rx_prop->rx[idx].attrib, sizeof(flt_rule.rule.attrib));
		flt_rule.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
		/* now install SRC address exception rules for no offload PDNs */
		for (i = 0; i < (IPACM_Iface::ipacmcfg->num_no_offload_ipv6_prefix); i++) {
			flt_rule.rule.attrib.u.v6.src_addr[0] = IPACM_Iface::ipacmcfg->ipa_no_offload_ipv6_prefixes[i][0];
			flt_rule.rule.attrib.u.v6.src_addr[1] = IPACM_Iface::ipacmcfg->ipa_no_offload_ipv6_prefixes[i][1];
			flt_rule.rule.attrib.u.v6.src_addr[2] = 0x0;
			flt_rule.rule.attrib.u.v6.src_addr[3] = 0x0;
			flt_rule.rule.attrib.u.v6.src_addr_mask[0] = 0xFFFFFFFF;
			flt_rule.rule.attrib.u.v6.src_addr_mask[1] = 0xFFFFFFFF;
			flt_rule.rule.attrib.u.v6.src_addr_mask[2] = 0x0;
			flt_rule.rule.attrib.u.v6.src_addr_mask[3] = 0x0;
			memcpy(&(pFilteringTable->rules[IPACM_Iface::ipacmcfg->num_ipv6_prefixes + i]), &flt_rule, sizeof(struct ipa_flt_rule_mdfy));
			IPACMDBG_H(" IPACM v6 no offload prefix as: 0x[%X][%X] entry(%d)\n",
					   flt_rule.rule.attrib.u.v6.src_addr[0],
					   flt_rule.rule.attrib.u.v6.src_addr[1],
					   IPACM_Iface::ipacmcfg->num_ipv6_prefixes + i);
			flt_rule.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
		}

#ifdef FEATURE_EoGRE
		//Case where eogre is enabled for opposite iptype. Need to install MTU rule with no prefixes
		if (IPACM_Iface::ipacmcfg->num_ipv6_prefixes == 0 && IPACM_Iface::ipacmcfg->eogre_enabled && IPACM_Iface::ipacmcfg->eogre_info.iptype == IPA_IP_v4) {
			memcpy(
				&flt_rule.rule.attrib,
				&rx_prop->rx[idx].attrib,
				sizeof(flt_rule.rule.attrib));
			if (construct_mtu_rule(&flt_rule.rule, IPA_IP_v6, mtu[0])) IPACMERR("Failed to modify MTU filtering rule.\n");
			memcpy(&(pFilteringTable->rules[mtu_rule_idx++]), &flt_rule, sizeof(struct ipa_flt_rule_add));
			IPACMDBG_H("Succesfully constructed GRE v6 MTU rule\n");
		}
#endif

		if (false == m_filtering.AddFilteringRuleAfter(pFilteringTable)) {
			IPACMERR("Failed to add prefix filtering rules.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, num_wan_prefix_rules[j]);

		/* save the rule hdls */
		for (i = 0; i < num_wan_prefix_rules[j]; i++)
			ipv6_prefix_flt_rule_hdl[j][i] = pFilteringTable->rules[i].flt_rule_hdl;

		if (pFilteringTable != NULL)
		{
			free(pFilteringTable);
			pFilteringTable = NULL;
		}
	}
fail:
	if(pFilteringTable != NULL)
	{
		free(pFilteringTable);
	}
	return res;
}
#endif

#ifdef FEATURE_IPV6_NAT
/* construct 1st pass v6NAT flt-rule to trigger v6ct */
int IPACM_Lan::add_ipv6_nat_ula_prefix_flt_rule()
{
	int len;
	struct ipa_ioc_add_flt_rule* flt_rule;
	struct ipa_flt_rule_add flt_rule_entry;
	int rule_cnt = 1, idx = 0;
	ipacm_ext_prop* ext_prop = NULL;
	int res = IPACM_SUCCESS;

	if(rx_prop == NULL || tx_prop == NULL)
	{
		IPACMERR("no valid props\n");
		return IPACM_FAILURE;
	}
	IPACMDBG_H("adding ULA prefix rule to send packets to IPv6 NAT\n");

	if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop && rx_prop->num_rx_props > 2)) {
		idx = 2;
		IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx pipe at idx %d \n", idx);
	}

	len = sizeof(struct ipa_ioc_add_flt_rule) + rule_cnt * sizeof(struct ipa_flt_rule_add);

	flt_rule = (struct ipa_ioc_add_flt_rule *)calloc(rule_cnt, len);
	if(!flt_rule)
	{
		IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
		return IPACM_FAILURE;
	}

	ext_prop = IPACM_Iface::ipacmcfg->GetExtProp(IPA_IP_v6);

	flt_rule->commit = 1;
	flt_rule->ep = rx_prop->rx[idx].src_pipe;
	flt_rule->global = false;
	flt_rule->ip = IPA_IP_v6;
	flt_rule->num_rules = rule_cnt;

	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

	flt_rule_entry.rule.retain_hdr = 1;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.eq_attrib_type = 0;
	flt_rule_entry.at_rear = true;
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;
	flt_rule_entry.rule.action = IPA_PASS_TO_SRC_NAT;
	/*
	 * this is the first pass rule, packet shall do another pass
	 * before reaching the RT block but we must provide valid rt table hdl
	 */
	 /* get rt_tbl_v6 handle */
	if(false == m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_v6))
	{
		IPACMERR("m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_v6=0x%p) Failed.\n", &IPACM_Iface::ipacmcfg->rt_tbl_v6);
		res = IPACM_FAILURE;
		goto fail;
	}
	flt_rule_entry.rule.rt_tbl_hdl = IPACM_Iface::ipacmcfg->rt_tbl_v6.hdl;
	IPACMDBG_H("rt_tbl_v6.hdl %d\n", flt_rule_entry.rule.rt_tbl_hdl);
#ifdef FEATURE_IPA_V3
	flt_rule_entry.rule.hashable = true;
#endif
	memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[idx].attrib, sizeof(flt_rule_entry.rule.attrib));
	flt_rule_entry.rule.attrib.u.v6.src_addr[0] = 0xFD000000;
	flt_rule_entry.rule.attrib.u.v6.src_addr[1] = 0x0;
	flt_rule_entry.rule.attrib.u.v6.src_addr[2] = 0x0;
	flt_rule_entry.rule.attrib.u.v6.src_addr[3] = 0x0;
	flt_rule_entry.rule.attrib.u.v6.src_addr_mask[0] = 0xFF000000;
	flt_rule_entry.rule.attrib.u.v6.src_addr_mask[1] = 0x0;
	flt_rule_entry.rule.attrib.u.v6.src_addr_mask[2] = 0x0;
	flt_rule_entry.rule.attrib.u.v6.src_addr_mask[3] = 0x0;
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
	memcpy(&(flt_rule->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));

	if(m_filtering.AddFilteringRule(flt_rule) == false)
	{
		IPACMERR("Error Adding Filtering rule, aborting...\n");
		res = IPACM_FAILURE;
		goto fail;
	}
	else
	{
		IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, 1);
#ifdef FEATURE_STATIC_POLICY
		if (!IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
		{
			ipv6_nat_ula_prefix_flt_rule_hdl = flt_rule->rules[0].flt_rule_hdl;
			IPACMDBG_H("IPv6 ULA prefix filter rule HDL:0x%x\n", ipv6_nat_ula_prefix_flt_rule_hdl);
		}
		else
		{
			static_policy_flt_rule_hdl_v6 = flt_rule->rules[0].flt_rule_hdl;
			IPACMDBG_H("IPv6 ULA prefix filter rule HDL:0x%x\n", static_policy_flt_rule_hdl_v6);
		}
#else
		ipv6_nat_ula_prefix_flt_rule_hdl = flt_rule->rules[0].flt_rule_hdl;
		IPACMDBG_H("IPv6 ULA prefix filter rule HDL:0x%x\n", ipv6_nat_ula_prefix_flt_rule_hdl);
#endif
	}
fail:
	free(flt_rule);
	return res;
}

void IPACM_Lan::delete_ipv6_nat_ula_prefix_flt_rule()
{
	int idx = 0;
	if (rx_prop == NULL)
	{
		IPACMDBG_H("No RX property.\n");
		return;
	}
	if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop && rx_prop->num_rx_props > 2)) {
		idx = 2;
		IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx pipe at idx %d \n", idx);
	}

#ifdef FEATURE_STATIC_POLICY
	if (!IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
	{
		if(m_filtering.DeleteFilteringHdls(&ipv6_nat_ula_prefix_flt_rule_hdl, IPA_IP_v6, 1) == false)
		{
			IPACMERR("Failed to delete ipv6 prefix flt rule.\n");
			return;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, 1);
	}
	else
	{
		if(m_filtering.DeleteFilteringHdls(&static_policy_flt_rule_hdl_v6, IPA_IP_v6, 1) == false)
		{
			IPACMERR("Failed to delete ipv6 prefix flt rule.\n");
			return;
		}
		static_policy_flt_rule_hdl_v6 = 0;
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, 1);
		IPACMERR("Deleted IPv6 NAT prefix flt rule.\n");
	}
#else
	if(m_filtering.DeleteFilteringHdls(&ipv6_nat_ula_prefix_flt_rule_hdl, IPA_IP_v6, 1) == false)
	{
		IPACMERR("Failed to delete ipv6 prefix flt rule.\n");
		return;
	}
	IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, 1);
#endif
	return;
}
#endif
int IPACM_Lan::install_ipv6_prefix_flt_rule(uint32_t* prefix)
{
	if(prefix == NULL)
	{
		IPACMERR("IPv6 prefix is empty.\n");
		return IPACM_FAILURE;
	}
	IPACMDBG_H("Receive IPv6 prefix: 0x%08x%08x.\n", prefix[0], prefix[1]);

	int len;
	struct ipa_ioc_add_flt_rule* flt_rule;
	struct ipa_flt_rule_add flt_rule_entry;
	int rule_cnt = 1, idx = 0;
	int j = 0;

	uint16_t mtu = IPACM_Wan::queryMTU(ipa_if_num, IPA_IP_v6);
	if (mtu > 0)
		rule_cnt ++;

	if(rx_prop == NULL || tx_prop == NULL)
	{
		IPACMERR("no valid props\n");
		return IPACM_FAILURE;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++)
	{
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		len = sizeof(struct ipa_ioc_add_flt_rule) + rule_cnt * sizeof(struct ipa_flt_rule_add);

		flt_rule = (struct ipa_ioc_add_flt_rule *)calloc(rule_cnt, len);
		if (!flt_rule)
		{
			IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
			return IPACM_FAILURE;
		}

		flt_rule->commit = 1;
		flt_rule->ep = rx_prop->rx[idx].src_pipe;
		flt_rule->global = false;
		flt_rule->ip = IPA_IP_v6;
		flt_rule->num_rules = rule_cnt;

		/* Make LAN-traffic always go to Apps, use default IPA-RT table */
		if (false == m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_default_v6)) {
			IPACMERR("LAN m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_default_v6=0x%p) Failed.\n",
						&IPACM_Iface::ipacmcfg->rt_tbl_default_v6);
			return IPACM_FAILURE;
		}

		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

		flt_rule_entry.rule.retain_hdr = 1;
		flt_rule_entry.rule.to_uc = 0;
		flt_rule_entry.rule.eq_attrib_type = 0;
		flt_rule_entry.at_rear = true;
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;
		flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
		flt_rule_entry.rule.rt_tbl_hdl = IPACM_Iface::ipacmcfg->rt_tbl_default_v6.hdl;

#ifdef FEATURE_IPA_V3
		flt_rule_entry.rule.hashable = true;
#endif
		memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[idx].attrib, sizeof(flt_rule_entry.rule.attrib));
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = prefix[0];
		flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = prefix[1];
		flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = 0x0;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = 0x0;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0x0;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0x0;
		memcpy(&(flt_rule->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));

		memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[idx].attrib, sizeof(flt_rule_entry.rule.attrib)); // this will remove the IPA_FLT_DST_ADDR
		flt_rule_entry.rule.attrib.u.v6.src_addr[3] = prefix[0];
		flt_rule_entry.rule.attrib.u.v6.src_addr[2] = prefix[1];
		flt_rule_entry.rule.attrib.u.v6.src_addr[1] = 0x0;
		flt_rule_entry.rule.attrib.u.v6.src_addr[0] = 0x0;
		flt_rule_entry.rule.attrib.u.v6.src_addr_mask[3] = 0xFFFFFFFF;
		flt_rule_entry.rule.attrib.u.v6.src_addr_mask[2] = 0xFFFFFFFF;
		flt_rule_entry.rule.attrib.u.v6.src_addr_mask[1] = 0x0;
		flt_rule_entry.rule.attrib.u.v6.src_addr_mask[0] = 0x0;
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;

		/* Add an MTU rule with every new private prefix */
		if (mtu > 0)
		{
			if (construct_mtu_rule(&flt_rule_entry.rule, IPA_IP_v6, mtu))
				IPACMERR("Failed to add MTU filtering rule.\n")
			else
				memcpy(&(flt_rule->rules[1]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
		}

		if (m_filtering.AddFilteringRule(flt_rule) == false)
		{
			IPACMERR("Error Adding Filtering rule, aborting...\n");
			free(flt_rule);
			return IPACM_FAILURE;
		}
		else
		{
			IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe,
				IPA_IP_v6, IPv6_PREFIX_DEFAULT_PDN_RULE_NUM);
			ipv6_prefix_flt_rule_hdl[j][0] = flt_rule->rules[0].flt_rule_hdl;
			IPACMDBG_H("IPv6 prefix filter rule HDL:0x%x\n", ipv6_prefix_flt_rule_hdl[j][0]);
			if (rule_cnt > 1)
			{
				ipv6_prefix_flt_rule_hdl[j][1] = flt_rule->rules[1].flt_rule_hdl;
				IPACMDBG_H("IPv6 prefix MTU filter rule HDL:0x%x\n", ipv6_prefix_flt_rule_hdl[j][1]);
			}
			free(flt_rule);
		}
	}
	return IPACM_SUCCESS;
}

void IPACM_Lan::delete_ipv6_prefix_flt_rule()
{
	int idx = 0;
	int j = 0;

	if (rx_prop == NULL)
	{
		IPACMERR("rx/tx properties empty...exit\n");
		return;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		if (m_filtering.DeleteFilteringHdls(&ipv6_prefix_flt_rule_hdl[j][0], IPA_IP_v6, IPv6_PREFIX_DEFAULT_PDN_RULE_NUM) == false) {
			IPACMERR("Failed to delete ipv6 prefix flt rule.\n");
			return;
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, IPv6_PREFIX_DEFAULT_PDN_RULE_NUM);
	}
	return;
}

int IPACM_Lan::handle_addr_evt_odu_bridge(ipacm_event_data_addr* data)
{
	int fd, res = IPACM_SUCCESS;
	struct in6_addr ipv6_addr;
	if(data == NULL)
	{
		IPACMERR("Failed to get interface IP address.\n");
		return IPACM_FAILURE;
	}

	if(data->iptype == IPA_IP_v6)
	{
		fd = open(IPACM_Iface::ipacmcfg->DEVICE_NAME_ODU, O_RDWR);
		if(fd == 0)
		{
			IPACMERR("Failed to open %s.\n", IPACM_Iface::ipacmcfg->DEVICE_NAME_ODU);
			return IPACM_FAILURE;
		}

		memcpy(&ipv6_addr, data->ipv6_addr, sizeof(struct in6_addr));

		if( ioctl(fd, ODU_BRIDGE_IOC_SET_LLV6_ADDR, &ipv6_addr) )
		{
			IPACMERR("Failed to write IPv6 address to odu driver.\n");
			res = IPACM_FAILURE;
		}
		num_dft_rt_v6++;
		close(fd);
	}

	return res;
}

ipa_hdr_proc_type IPACM_Lan::eth_bridge_get_hdr_proc_type(ipa_hdr_l2_type t1,
	ipa_hdr_l2_type t2,
	struct ipa_eth_II_to_eth_II_ex_procparams &generic_params)
{
	switch(t1) {
	case IPA_HDR_L2_ETHERNET_II:
		if(t2 == IPA_HDR_L2_ETHERNET_II)
			return IPA_HDR_PROC_ETHII_TO_ETHII;
		if(t2 == IPA_HDR_L2_802_3)
			return IPA_HDR_PROC_ETHII_TO_802_3;
		if(t2 == IPA_HDR_L2_802_1Q) {
			generic_params.input_ethhdr_negative_offset = 14;
			generic_params.output_ethhdr_negative_offset = 18;
			return IPA_HDR_PROC_ETHII_TO_ETHII_EX;
		}

#ifdef IPA_HDR_L2_ETHERNET_II_AST
		if(t2 == IPA_HDR_L2_ETHERNET_II_AST)
			return IPA_HDR_PROC_ETHII_TO_ETHII;
		if (t2 == IPA_HDR_L2_802_1Q_AST) {
			generic_params.input_ethhdr_negative_offset = 14;
			generic_params.output_ethhdr_negative_offset = 18;
			return IPA_HDR_PROC_ETHII_TO_ETHII_EX;
		}
#endif
		break;
	case IPA_HDR_L2_802_3:
		if(t2 == IPA_HDR_L2_ETHERNET_II)
			return IPA_HDR_PROC_802_3_TO_ETHII;
		if(t2 == IPA_HDR_L2_802_3)
			return IPA_HDR_PROC_802_3_TO_802_3;
		break;
	case IPA_HDR_L2_802_1Q:
		if(t2 == IPA_HDR_L2_802_1Q || t2 == IPA_HDR_L2_802_1Q_AST) {
			generic_params.input_ethhdr_negative_offset = 18;
			generic_params.output_ethhdr_negative_offset = 18;
			return IPA_HDR_PROC_ETHII_TO_ETHII_EX;
		}
		if (t2 == IPA_HDR_L2_ETHERNET_II || t2 == IPA_HDR_L2_ETHERNET_II_AST) {
			generic_params.input_ethhdr_negative_offset = 18;
			generic_params.output_ethhdr_negative_offset = 14;
			return IPA_HDR_PROC_ETHII_TO_ETHII_EX;
		}
		break;
	case IPA_HDR_L2_ETHERNET_II_AST:
		if(t2 == IPA_HDR_L2_ETHERNET_II || t2 == IPA_HDR_L2_ETHERNET_II_AST) {
			generic_params.input_ethhdr_negative_offset = 14;
			generic_params.output_ethhdr_negative_offset = 14;
			return IPA_HDR_PROC_ETHII_TO_ETHII_EX;
		}
		else if(t2 == IPA_HDR_L2_802_1Q_AST){
			generic_params.input_ethhdr_negative_offset = 14;
			generic_params.output_ethhdr_negative_offset = 18;
			return IPA_HDR_PROC_ETHII_TO_ETHII_EX;
		}
		break;
	case IPA_HDR_L2_802_1Q_AST:
		if (t2 == IPA_HDR_L2_ETHERNET_II || t2 == IPA_HDR_L2_ETHERNET_II_AST) {
			generic_params.input_ethhdr_negative_offset = 18;
			generic_params.output_ethhdr_negative_offset = 14;
			return IPA_HDR_PROC_ETHII_TO_ETHII_EX;
		}
		break;
	default:
		return IPA_HDR_PROC_NONE;
	}

	return IPA_HDR_PROC_NONE;
}

int IPACM_Lan::eth_bridge_get_hdr_template_hdl(uint32_t* hdr_hdl)
{
	if(hdr_hdl == NULL)
	{
		IPACMDBG_H("Hdr handle pointer is empty.\n");
		return IPACM_FAILURE;
	}

	struct ipa_ioc_get_hdr hdr;
	memset(&hdr, 0, sizeof(hdr));

	memcpy(hdr.name, tx_prop->tx[0].hdr_name, sizeof(hdr.name));
	if(m_header.GetHeaderHandle(&hdr) == false)
	{
		IPACMERR("Failed to get template hdr hdl.\n");
		return IPACM_FAILURE;
	}

	*hdr_hdl = hdr.hdl;
	return IPACM_SUCCESS;
}

int IPACM_Lan::handle_cradle_wan_mode_switch(bool is_wan_bridge_mode)
{
	struct ipa_flt_rule_mdfy flt_rule_entry;
	int len = 0;
	ipa_ioc_mdfy_flt_rule *m_pFilteringTable;
	int j, idx = 0;

	IPACMDBG_H("Handle wan mode swtich: is wan bridge mode?%d\n", is_wan_bridge_mode);

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	len = sizeof(struct ipa_ioc_mdfy_flt_rule) + (1 * sizeof(struct ipa_flt_rule_mdfy));
	m_pFilteringTable = (struct ipa_ioc_mdfy_flt_rule *)calloc(1, len);
	if (m_pFilteringTable == NULL)
	{
		PERROR("Error Locate ipa_ioc_mdfy_flt_rule memory...\n");
		return IPACM_FAILURE;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if ( j == 0 ) {
				idx = 0 ;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}
		m_pFilteringTable->commit = 1;
		m_pFilteringTable->ip = IPA_IP_v4;
		m_pFilteringTable->num_rules = (uint8_t)1;

		IPACMDBG_H("Retrieving routing hanle for table: %s\n",
				   IPACM_Iface::ipacmcfg->rt_tbl_wan_v4.name);
		if (false == m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_wan_v4)) {
			IPACMERR("m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_wan_v4=0x%p) Failed.\n",
					 &IPACM_Iface::ipacmcfg->rt_tbl_wan_v4);
			free(m_pFilteringTable);
			return IPACM_FAILURE;
		}
		IPACMDBG_H("Routing handle for table: %d\n", IPACM_Iface::ipacmcfg->rt_tbl_wan_v4.hdl);


		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_mdfy)); // Zero All Fields
		flt_rule_entry.status = -1;
		flt_rule_entry.rule_hdl = lan_wan_fl_rule_hdl[j][0];

		flt_rule_entry.rule.retain_hdr = 0;
		flt_rule_entry.rule.to_uc = 0;
		flt_rule_entry.rule.eq_attrib_type = 0;
		if (is_wan_bridge_mode) {
			flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
		} else {
			flt_rule_entry.rule.action = IPA_PASS_TO_SRC_NAT;
		}
		flt_rule_entry.rule.rt_tbl_hdl = IPACM_Iface::ipacmcfg->rt_tbl_wan_v4.hdl;

		memcpy(&flt_rule_entry.rule.attrib,
			   &rx_prop->rx[idx].attrib,
			   sizeof(flt_rule_entry.rule.attrib));

		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
		flt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0x0;
		flt_rule_entry.rule.attrib.u.v4.dst_addr = 0x0;

		memcpy(&m_pFilteringTable->rules[0], &flt_rule_entry, sizeof(flt_rule_entry));
		if (false == m_filtering.ModifyFilteringRule(m_pFilteringTable)) {
			IPACMERR("Error Modifying RuleTable(0) to Filtering, aborting...\n");
			free(m_pFilteringTable);
			return IPACM_FAILURE;
		} else {
			IPACMDBG_H("flt rule hdl = %d, status = %d\n",
					   m_pFilteringTable->rules[0].rule_hdl,
					   m_pFilteringTable->rules[0].status);
		}
	}
	free(m_pFilteringTable);
	return IPACM_SUCCESS;
}

/*handle reset usb-client rt-rules */
int IPACM_Lan::handle_tethering_stats_event(ipa_get_data_stats_resp_msg_v01 *data)
{
	int cnt, pipe_len, fd;
	uint64_t num_ul_packets, num_ul_bytes;
	uint64_t num_dl_packets, num_dl_bytes;
	bool ul_pipe_found, dl_pipe_found;
	FILE *fp = NULL;

	fd = open(IPA_DEVICE_NAME, O_RDWR);
	if (fd < 0)
	{
		IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
		return IPACM_FAILURE;
	}


	ul_pipe_found = false;
	dl_pipe_found = false;
	num_ul_packets = 0;
	num_dl_packets = 0;
	num_ul_bytes = 0;
	num_dl_bytes = 0;

	if (data->dl_dst_pipe_stats_list_valid)
	{
		if(tx_prop != NULL)
		{
			for (pipe_len = 0; pipe_len < data->dl_dst_pipe_stats_list_len; pipe_len++)
			{
				IPACMDBG_H("Check entry(%d) dl_dst_pipe(%d)\n", pipe_len, data->dl_dst_pipe_stats_list[pipe_len].pipe_index);
				for (cnt=0; cnt<tx_prop->num_tx_props; cnt++)
				{
					IPACMDBG_H("Check Tx_prop_entry(%d) pipe(%d)\n", cnt, ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, tx_prop->tx[cnt].dst_pipe));
					if(ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, tx_prop->tx[cnt].dst_pipe) == data->dl_dst_pipe_stats_list[pipe_len].pipe_index)
					{
						/* update the DL stats */
						dl_pipe_found = true;
						num_dl_packets += data->dl_dst_pipe_stats_list[pipe_len].num_ipv4_packets;
						num_dl_packets += data->dl_dst_pipe_stats_list[pipe_len].num_ipv6_packets;
						num_dl_bytes += data->dl_dst_pipe_stats_list[pipe_len].num_ipv4_bytes;
						num_dl_bytes += data->dl_dst_pipe_stats_list[pipe_len].num_ipv6_bytes;
						IPACMDBG_H("Got matched dst-pipe (%d) from %d tx props\n", data->dl_dst_pipe_stats_list[pipe_len].pipe_index, cnt);
						IPACMDBG_H("DL_packets:(%lu) DL_bytes:(%lu) \n", num_dl_packets, num_dl_bytes);
						break;
					}
				}
			}
		}
	}

	if (data->ul_src_pipe_stats_list_valid)
	{
		if(rx_prop != NULL)
		{
			for (pipe_len = 0; pipe_len < data->ul_src_pipe_stats_list_len; pipe_len++)
			{
				IPACMDBG_H("Check entry(%d) dl_dst_pipe(%d)\n", pipe_len, data->ul_src_pipe_stats_list[pipe_len].pipe_index);
				for (cnt=0; cnt < rx_prop->num_rx_props; cnt++)
				{
					IPACMDBG_H("Check Rx_prop_entry(%d) pipe(%d)\n", cnt, ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, rx_prop->rx[cnt].src_pipe));
					if(ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, rx_prop->rx[cnt].src_pipe) == data->ul_src_pipe_stats_list[pipe_len].pipe_index)
					{
						/* update the UL stats */
						ul_pipe_found = true;
						num_ul_packets += data->ul_src_pipe_stats_list[pipe_len].num_ipv4_packets;
						num_ul_packets += data->ul_src_pipe_stats_list[pipe_len].num_ipv6_packets;
						num_ul_bytes += data->ul_src_pipe_stats_list[pipe_len].num_ipv4_bytes;
						num_ul_bytes += data->ul_src_pipe_stats_list[pipe_len].num_ipv6_bytes;
						IPACMDBG_H("Got matched dst-pipe (%d) from %d tx props\n", data->ul_src_pipe_stats_list[pipe_len].pipe_index, cnt);
						IPACMDBG_H("UL_packets:(%lu) UL_bytes:(%lu) \n", num_ul_packets, num_ul_bytes);
						break;
					}
				}
			}
		}
	}
	close(fd);

	if (ul_pipe_found || dl_pipe_found)
	{
		IPACMDBG_H("Update IPA_TETHERING_STATS_UPDATE_EVENT, TX(P%lu/B%lu) RX(P%lu/B%lu) DEV(%s) to LTE(%s) \n",
					num_ul_packets,
						num_ul_bytes,
							num_dl_packets,
								num_dl_bytes,
									dev_name,
										IPACM_Wan::wan_up_dev_name);
		fp = fopen(IPA_PIPE_STATS_FILE_NAME, "w");
		if ( fp == NULL )
		{
			IPACMERR("Failed to write pipe stats to %s, error is %d - %s\n",
					IPA_PIPE_STATS_FILE_NAME, errno, strerror(errno));
			return IPACM_FAILURE;
		}

		fprintf(fp, PIPE_STATS,
				dev_name,
					IPACM_Wan::wan_up_dev_name,
						num_ul_bytes,
						num_ul_packets,
							    num_dl_bytes,
							num_dl_packets);
		fclose(fp);
	}
	return IPACM_SUCCESS;
}

/*handle tether client */
int IPACM_Lan::handle_tethering_client(bool reset, ipacm_client_enum ipa_client)
{
	int cnt, fd, ret = IPACM_SUCCESS;
	int fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
	wan_ioctl_set_tether_client_pipe tether_client;

	if(fd_wwan_ioctl < 0)
	{
		IPACMERR("Failed to open %s.\n",WWAN_QMI_IOCTL_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	fd = open(IPA_DEVICE_NAME, O_RDWR);
	if (fd < 0)
	{
		IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
		close(fd_wwan_ioctl);
		return IPACM_FAILURE;
	}

	memset(&tether_client, 0, sizeof(tether_client));
	tether_client.reset_client = reset;
	tether_client.ipa_client = ipa_client;

	if(tx_prop != NULL)
	{
		tether_client.dl_dst_pipe_len = tx_prop->num_tx_props;
		for (cnt = 0; cnt < tx_prop->num_tx_props; cnt++)
		{
			IPACMDBG_H("Tx(%d), dst_pipe: %d, ipa_pipe: %d\n",
					cnt, tx_prop->tx[cnt].dst_pipe,
						ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, tx_prop->tx[cnt].dst_pipe));
			tether_client.dl_dst_pipe_list[cnt] = ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, tx_prop->tx[cnt].dst_pipe);
		}
	}

	if(rx_prop != NULL)
	{
		tether_client.ul_src_pipe_len = rx_prop->num_rx_props;
		for (cnt = 0; cnt < rx_prop->num_rx_props; cnt++)
		{
			IPACMDBG_H("Rx(%d), src_pipe: %d, ipa_pipe: %d\n",
					cnt, rx_prop->rx[cnt].src_pipe,
						ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, rx_prop->rx[cnt].src_pipe));
			tether_client.ul_src_pipe_list[cnt] = ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, rx_prop->rx[cnt].src_pipe);
		}
	}

	ret = ioctl(fd_wwan_ioctl, WAN_IOC_SET_TETHER_CLIENT_PIPE, &tether_client);
	if (ret != 0)
	{
		IPACMERR("Failed set tether-client-pipe %p with ret %d\n ", &tether_client, ret);
	}
	IPACMDBG("Set tether-client-pipe %p\n", &tether_client);
	close(fd);
	close(fd_wwan_ioctl);
	return ret;
}

/* mac address has to be provided for client related events */
void IPACM_Lan::eth_bridge_post_event(ipa_cm_event_id evt, ipa_ip_type iptype, uint8_t *mac, uint32_t *ipv6_addr, char *iface_name,
	uint16_t VlanID)
{
	ipacm_cmd_q_data eth_bridge_evt;
	ipacm_event_eth_bridge *evt_data_eth_bridge;
	ipacm_event_data_all *evt_data_all;
	const char* eventName;

	memset(&eth_bridge_evt, 0, sizeof(ipacm_cmd_q_data));
	eth_bridge_evt.event = evt;

	evt_data_eth_bridge = (ipacm_event_eth_bridge*)malloc(sizeof(*evt_data_eth_bridge));
	if(evt_data_eth_bridge == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return;
	}
	memset(evt_data_eth_bridge, 0, sizeof(*evt_data_eth_bridge));

	evt_data_eth_bridge->p_iface = this;
	evt_data_eth_bridge->iptype = iptype;
	if(mac)
	{
		IPACMDBG_H("Mac: 0x%02x%02x%02x%02x%02x%02x \n",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		memcpy(evt_data_eth_bridge->mac_addr, mac, sizeof(evt_data_eth_bridge->mac_addr));
	}
	if(iface_name)
	{
		IPACMDBG_H("Iface: %s\n", iface_name);
		memcpy(evt_data_eth_bridge->iface_name, iface_name,
			sizeof(evt_data_eth_bridge->iface_name));
	}
	evt_data_eth_bridge->VlanID = VlanID;
	eth_bridge_evt.evt_data = (void*)evt_data_eth_bridge;
	eventName = IPACM_Iface::ipacmcfg->getEventName(evt);
	if (eventName != NULL)
		IPACMDBG_H("Posting event %s\n", eventName);
	IPACM_EvtDispatcher::PostEvt(&eth_bridge_evt);
}

/* add header processing context and return handle to lan2lan controller */
int IPACM_Lan::eth_bridge_add_hdr_proc_ctx(ipa_hdr_l2_type peer_l2_hdr_type, uint32_t *hdl, uint16_t vlan_id)
{
	int len, res = IPACM_SUCCESS;
	uint32_t hdr_template;
	ipa_ioc_add_hdr_proc_ctx* pHeaderProcTable = NULL;
	ipa_hdr_l2_type t2_hdr;

	if(tx_prop == NULL)
	{
		IPACMERR("No tx prop.\n");
		return IPACM_FAILURE;
	}

	if (ipa_if_cate == WLAN_IF &&
		(((IPACM_Wlan *)this)->is_svap_iface() || ((IPACM_Wlan *)this)->is_vlan_iface()) ||
		sIface && vlan_id) {
		t2_hdr = tx_prop->tx[2].hdr_l2_type;
	} else {
		t2_hdr = tx_prop->tx[0].hdr_l2_type;
	}

	len = sizeof(struct ipa_ioc_add_hdr_proc_ctx) + sizeof(struct ipa_hdr_proc_ctx_add);
	pHeaderProcTable = (ipa_ioc_add_hdr_proc_ctx*)malloc(len);
	if(pHeaderProcTable == NULL)
	{
		IPACMERR("Cannot allocate header processing context table.\n");
		return IPACM_FAILURE;
	}

	memset(pHeaderProcTable, 0, len);
	pHeaderProcTable->commit = 1;
	pHeaderProcTable->num_proc_ctxs = 1;
	pHeaderProcTable->proc_ctx[0].type =
		eth_bridge_get_hdr_proc_type(peer_l2_hdr_type,
			t2_hdr,
			pHeaderProcTable->proc_ctx[0].generic_params);

	if (vlan_id) {
		/*
		 * Add header proc context with output dscp_pcp_update irrespective of
		 * DSCP PCP update needed or not for easy mesh R3
		 */
		if (ipa_if_cate == WLAN_IF && ((IPACM_Wlan *)this)->is_svap_iface() &&
			(IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 3))
		{
			pHeaderProcTable->proc_ctx[0].generic_params.output_dscp_pcp_update = 1;
		}
		eth_bridge_get_vlan_hdr_template_hdl(&hdr_template, vlan_id);
	}
	else
		eth_bridge_get_hdr_template_hdl(&hdr_template);

	pHeaderProcTable->proc_ctx[0].hdr_hdl = hdr_template;
	if (m_header.AddHeaderProcCtx(pHeaderProcTable) == false)
	{
		IPACMERR("Adding hdr proc ctx failed with status: %d\n", pHeaderProcTable->proc_ctx[0].status);
		res = IPACM_FAILURE;
		goto end;
	}

	hdl[0] = pHeaderProcTable->proc_ctx[0].proc_ctx_hdl;

end:
	free(pHeaderProcTable);
	return res;
}

/* add routing rule and return handle to lan2lan controller */
int IPACM_Lan::eth_bridge_add_rt_rule(uint8_t *mac, char *rt_tbl_name, uint32_t hdr_proc_ctx_hdl,
		ipa_hdr_l2_type peer_l2_hdr_type, ipa_ip_type iptype, uint32_t *rt_rule_hdl, int *rt_rule_count)
{
	int i, len, res = IPACM_SUCCESS;
	struct ipa_ioc_add_rt_rule* rt_rule_table = NULL;
	struct ipa_rt_rule_add rt_rule;
	int position, num_rt_rule;

	*rt_rule_count = 0;

	IPACMDBG_H("Received client MAC 0x%02x%02x%02x%02x%02x%02x.\n",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	num_rt_rule = each_client_rt_rule_count[iptype];

	len = sizeof(ipa_ioc_add_rt_rule) + num_rt_rule * sizeof(ipa_rt_rule_add);
	rt_rule_table = (ipa_ioc_add_rt_rule*)malloc(len);
	if (rt_rule_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(rt_rule_table, 0, len);

	rt_rule_table->commit = 1;
	rt_rule_table->ip = iptype;
	strlcpy(rt_rule_table->rt_tbl_name, rt_tbl_name, sizeof(rt_rule_table->rt_tbl_name));
	rt_rule_table->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = 0;


	IPACMDBG_H("Installing rt table rule %s\n", rt_tbl_name);

	memset(&rt_rule, 0, sizeof(ipa_rt_rule_add));
	rt_rule.at_rear = false;
	rt_rule.status = -1;
	rt_rule.rt_rule_hdl = -1;
#ifdef FEATURE_IPA_V3
	rt_rule.rule.hashable = true;
#endif
	rt_rule.rule.hdr_hdl = 0;
	rt_rule.rule.hdr_proc_ctx_hdl = hdr_proc_ctx_hdl;

	position = 0;
	for(i=0; i<iface_query->num_tx_props; i++)
	{
		if(tx_prop->tx[i].ip == iptype)
		{
			if (IPACM_Iface::ipacmcfg->ipacm_emesh_enable && IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 2) {
				if (is_if_svap || is_wlan_if_vlan) {
					if (i < IPA_IP_v4_VLAN) continue;
				} else {
					if (i >= IPA_IP_v4_VLAN) continue;
				}
			}

			if(position >= num_rt_rule || position >= MAX_NUM_PROP)
			{
				IPACMERR("Number of routing rules already exceeds limit.\n");
				res = IPACM_FAILURE;
				goto end;
			}

			if(ipa_if_cate == WLAN_IF && IPACM_Iface::ipacmcfg->isMCC_Mode)
			{
				IPACMDBG_H("In WLAN MCC mode, use alt dst pipe: %d\n",
						tx_prop->tx[i].alt_dst_pipe);
				rt_rule.rule.dst = tx_prop->tx[i].alt_dst_pipe;
			}
			else
			{
				IPACMDBG_H("It is not WLAN MCC mode, use dst pipe: %d\n",
						tx_prop->tx[i].dst_pipe);
				rt_rule.rule.dst = tx_prop->tx[i].dst_pipe;
			}

			memcpy(&rt_rule.rule.attrib, &tx_prop->tx[i].attrib, sizeof(rt_rule.rule.attrib));

			switch(peer_l2_hdr_type)
			{
#ifdef IPA_HDR_L2_ETHERNET_II_AST
			case IPA_HDR_L2_ETHERNET_II_AST:
#endif
			case IPA_HDR_L2_ETHERNET_II:
				rt_rule.rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_ETHER_II;
				break;
			case IPA_HDR_L2_802_3:
				rt_rule.rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_802_3;
				break;
#ifdef IPA_HDR_L2_802_1Q_AST
			case IPA_HDR_L2_802_1Q_AST:
#endif
			case IPA_HDR_L2_802_1Q:
				rt_rule.rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_802_1Q;
				break;
			default:
				IPACMERR("unknown header type\n");
				res = IPACM_FAILURE;
				goto end;
			}
			memcpy(rt_rule.rule.attrib.dst_mac_addr, mac, sizeof(rt_rule.rule.attrib.dst_mac_addr));
			memset(rt_rule.rule.attrib.dst_mac_addr_mask, 0xFF, sizeof(rt_rule.rule.attrib.dst_mac_addr_mask));

			memcpy(&(rt_rule_table->rules[position]), &rt_rule, sizeof(rt_rule_table->rules[position]));
			position++;
		}
	}
	rt_rule_table->num_rules = position;
	if(false == m_routing.AddRoutingRule(rt_rule_table))
	{
		IPACMERR("Routing rule addition failed!\n");
		res = IPACM_FAILURE;
		goto end;
	}
	else
	{
		*rt_rule_count = position;
		for(i=0; i<position; i++)
			rt_rule_hdl[i] = rt_rule_table->rules[i].rt_rule_hdl;
	}

end:
	free(rt_rule_table);
	return res;
}

/* modify routing rule*/
int IPACM_Lan::eth_bridge_modify_rt_rule(uint8_t *mac, uint32_t hdr_proc_ctx_hdl,
		ipa_hdr_l2_type peer_l2_hdr_type, ipa_ip_type iptype, uint32_t *rt_rule_hdl, int rt_rule_count)
{
	struct ipa_ioc_mdfy_rt_rule *rt_rule = NULL;
	struct ipa_rt_rule_mdfy *rt_rule_entry;
	int len, index, res = IPACM_SUCCESS;

	if(tx_prop == NULL)
	{
		IPACMDBG_H("No tx properties \n");
		return IPACM_FAILURE;
	}

	if(ipa_if_cate != WLAN_IF)
	{
		IPACMDBG_H("This is not WLAN IF, no need to modify rt rule.\n");
		return IPACM_SUCCESS;
	}

	IPACMDBG_H("Receive WLAN client MAC 0x%02x%02x%02x%02x%02x%02x.\n",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	len = sizeof(struct ipa_ioc_mdfy_rt_rule) + rt_rule_count * sizeof(struct ipa_rt_rule_mdfy);
	rt_rule = (struct ipa_ioc_mdfy_rt_rule *)malloc(len);
	if(rt_rule == NULL)
	{
		IPACMERR("Unable to allocate memory for modify rt rule\n");
		return IPACM_FAILURE;
	}
	memset(rt_rule, 0, len);

	rt_rule->commit = 1;
	rt_rule->num_rules = 0;
	rt_rule->ip = iptype;

	for (index = 0; index < tx_prop->num_tx_props; index++)
	{
		if (tx_prop->tx[index].ip == iptype)
		{
			if (rt_rule->num_rules >= rt_rule_count ||
				rt_rule->num_rules >= MAX_NUM_PROP)
			{
				IPACMERR("Number of routing rules exceeds limit.\n");
				res = IPACM_FAILURE;
				goto end;
			}

			rt_rule_entry = &rt_rule->rules[rt_rule->num_rules];

			if (IPACM_Iface::ipacmcfg->isMCC_Mode)
			{
				IPACMDBG_H("In WLAN MCC mode, use alt dst pipe: %d\n",
						tx_prop->tx[index].alt_dst_pipe);
				rt_rule_entry->rule.dst = tx_prop->tx[index].alt_dst_pipe;
			}
			else
			{
				IPACMDBG_H("In WLAN SCC mode, use dst pipe: %d\n",
						tx_prop->tx[index].dst_pipe);
				rt_rule_entry->rule.dst = tx_prop->tx[index].dst_pipe;
			}

			rt_rule_entry->rule.hdr_hdl = 0;
			rt_rule_entry->rule.hdr_proc_ctx_hdl = hdr_proc_ctx_hdl;
#ifdef FEATURE_IPA_V3
			rt_rule_entry->rule.hashable = true;
#endif
			memcpy(&rt_rule_entry->rule.attrib, &tx_prop->tx[index].attrib,
					sizeof(rt_rule_entry->rule.attrib));

			switch(peer_l2_hdr_type)
			{
#ifdef IPA_HDR_L2_ETHERNET_II_AST
			case IPA_HDR_L2_ETHERNET_II_AST:
#endif
			case IPA_HDR_L2_ETHERNET_II:
				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_ETHER_II;
				break;
			case IPA_HDR_L2_802_3:
				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_802_3;
				break;
#ifdef IPA_HDR_L2_802_1Q_AST
			case IPA_HDR_L2_802_1Q_AST:
#endif
			case IPA_HDR_L2_802_1Q:
				rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_802_1Q;
				break;
			default:
				IPACMERR("unknown header type\n");
				res = IPACM_FAILURE;
				goto end;
			}
			memcpy(rt_rule_entry->rule.attrib.dst_mac_addr, mac,
					sizeof(rt_rule_entry->rule.attrib.dst_mac_addr));
			memset(rt_rule_entry->rule.attrib.dst_mac_addr_mask, 0xFF,
					sizeof(rt_rule_entry->rule.attrib.dst_mac_addr_mask));

			rt_rule_entry->rt_rule_hdl = rt_rule_hdl[rt_rule->num_rules];
			rt_rule->num_rules++;
		}
	}

	if(m_routing.ModifyRoutingRule(rt_rule) == false)
	{
		IPACMERR("Failed to modify routing rules.\n");
		res = IPACM_FAILURE;
		goto end;
	}
	if(m_routing.Commit(iptype) == false)
	{
		IPACMERR("Failed to commit routing rules.\n");
		res = IPACM_FAILURE;
		goto end;
	}
	IPACMDBG("Modified routing rules successfully.\n");

end:
	free(rt_rule);
	return res;
}

int IPACM_Lan::eth_bridge_add_flt_rule(uint8_t *mac, uint32_t rt_tbl_hdl, ipa_ip_type iptype, uint32_t *flt_rule_hdl, uint16_t vlan_id, uint16_t pipe_idx) {
	int len, res = IPACM_SUCCESS, idx = 0;
	struct ipa_flt_rule_add flt_rule_entry;
	struct ipa_ioc_add_flt_rule_after *pFilteringTable = NULL;
	int j = 0;

#ifdef FEATURE_IPA_V3
	if (rx_prop == NULL || tx_prop == NULL) {
		IPACMDBG_H("No rx or tx properties registered for iface %s\n", dev_name);
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Received client MAC 0x%02x%02x%02x%02x%02x%02x.\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	len = sizeof(struct ipa_ioc_add_flt_rule_after) + sizeof(struct ipa_flt_rule_add);
	pFilteringTable = (struct ipa_ioc_add_flt_rule_after *)malloc(len);
	if (!pFilteringTable) {
		IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
		return IPACM_FAILURE;
	}
	if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop && rx_prop->num_rx_props > 2)) {
			idx = 2;
			IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx pipe at idx %d \n", idx);
	} else {
			idx = pipe_idx;
			IPACMDBG_H("Install rules on Rx pipe at idx %d \n", idx);
	}
	IPACMDBG_H("Install rules on Rx pipe at idx %d \n", idx);
	memset(pFilteringTable, 0, len);

	/* add mac based rule*/
	pFilteringTable->commit = 1;
	pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
	pFilteringTable->ip = iptype;
	pFilteringTable->num_rules = 1;
	pFilteringTable->add_after_hdl = eth_bridge_flt_rule_offset[idx / 2][iptype];

	memset(&flt_rule_entry, 0, sizeof(flt_rule_entry));

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
	flt_rule_entry.rule.eq_attrib_type = 0;
	flt_rule_entry.rule.rt_tbl_hdl = rt_tbl_hdl;
	flt_rule_entry.rule.hashable = true;

	flt_rule_entry.rule.max_prio = fixed_mac_prio_val[idx][iptype];
	memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[idx].attrib, sizeof(flt_rule_entry.rule.attrib));
	switch (tx_prop->tx[idx].hdr_l2_type) {

#ifdef IPA_HDR_L2_ETHERNET_II_AST
	case IPA_HDR_L2_ETHERNET_II_AST:
#endif
	case IPA_HDR_L2_ETHERNET_II:
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_ETHER_II;
		break;
	case IPA_HDR_L2_802_3:
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_802_3;
		break;
#ifdef IPA_HDR_L2_802_1Q_AST
	case IPA_HDR_L2_802_1Q_AST:
#endif
	case IPA_HDR_L2_802_1Q:
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_802_1Q;
		break;
	default:
		IPACMERR("unknown header type\n");
		res = IPACM_FAILURE;
		goto end;
	}

	memcpy(flt_rule_entry.rule.attrib.dst_mac_addr, mac, sizeof(flt_rule_entry.rule.attrib.dst_mac_addr));
	memset(flt_rule_entry.rule.attrib.dst_mac_addr_mask, 0xFF, sizeof(flt_rule_entry.rule.attrib.dst_mac_addr_mask));

#ifdef FEATURE_VLAN_MPDN
	if ((IPACM_Iface::ipacmcfg->iface_in_vlan_mode(dev_name)) && (vlan_id != 0)) {
		if (!vlan_id) {
			IPACMERR("got vlan id 0 for vlan iface %s\n", dev_name);
			res = IPACM_FAILURE;
			goto end;
		}

		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_VLAN_ID;
		flt_rule_entry.rule.attrib.vlan_id = vlan_id;
	} else if (vlan_id) {
		IPACMERR("vlan id is not 0 (%d) for non vlan iface %s!\n", vlan_id, dev_name);
	}
#endif //FEATURE_VLAN_MPDN

	memcpy(&(pFilteringTable->rules[0]), &flt_rule_entry, sizeof(flt_rule_entry));
	if (false == m_filtering.AddFilteringRuleAfter(pFilteringTable)) {
		IPACMERR("Failed to add client filtering rules.\n");
		res = IPACM_FAILURE;
		goto end;
	}
	*flt_rule_hdl = pFilteringTable->rules[0].flt_rule_hdl;

end:
	free(pFilteringTable);
#endif
	return res;
}

int IPACM_Lan::eth_bridge_del_flt_rule(uint32_t flt_rule_hdl, ipa_ip_type iptype)
{
	if(m_filtering.DeleteFilteringHdls(&flt_rule_hdl, iptype, 1) == false)
	{
		IPACMERR("Failed to delete the client specific flt rule.\n");
		return IPACM_FAILURE;
	}
	return IPACM_SUCCESS;
}

int IPACM_Lan::eth_bridge_del_rt_rule(uint32_t rt_rule_hdl, ipa_ip_type iptype)
{
	if(m_routing.DeleteRoutingHdl(rt_rule_hdl, iptype) == false)
	{
		IPACMERR("Failed to delete routing rule.\n");
		return IPACM_FAILURE;
	}
	return IPACM_SUCCESS;
}

/* delete header processing context */
int IPACM_Lan::eth_bridge_del_hdr_proc_ctx(uint32_t hdr_proc_ctx_hdl)
{
	if(m_header.DeleteHeaderProcCtx(hdr_proc_ctx_hdl) == false)
	{
		IPACMERR("Failed to delete hdr proc ctx.\n");
		return IPACM_FAILURE;
	}
	return IPACM_SUCCESS;
}

#if defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
/* check if the event is associated with vlan interface */
bool IPACM_Lan::is_vlan_event(char *event_iface_name)
{
	string selfDevName(dev_name), eventInterfaceName(event_iface_name);
	if (eventInterfaceName.find(selfDevName) == std::string::npos) {
		IPACMDBG("dev_name %s is not a substring of event_iface_name %s\n", dev_name, event_iface_name);
		return false;
	}

	vector<string> tokens;
	string delimiter = ".", tmpName = eventInterfaceName;
	size_t pos = 0;
	while ((pos = tmpName.find(delimiter)) != std::string::npos) {
		string token = tmpName.substr(0, pos);
		tokens.emplace_back(token);
		tmpName.erase(0, pos + delimiter.length());
		IPACMDBG("token = %s tmpName = %s\n", token.c_str(), tmpName.c_str());
	}
	IPACMDBG("Insert last token tmpName = %s\n", tmpName.c_str());
	tokens.emplace_back(tmpName);

	IPACMDBG("return value = %d\n", tokens.size() > 1 && !tokens.back().empty() && std::isdigit(tokens.back()[0]));
	if (tokens.size() > 1 && !tokens.back().empty() && std::isdigit(tokens.back()[0]) && (strncmp(((const char *)tokens[0].c_str()),  dev_name,strlen(tokens[0].c_str())) == 0)) {
			return true;
	}
	else {
			return false;
	}
}
#ifdef FEATURE_L2TP
/* check if the event is associated with l2tp interface */
bool IPACM_Lan::is_l2tp_event(char *event_iface_name)
{
	if(event_iface_name == NULL)
	{
		IPACMERR("Invalid input\n");
		return false;
	}

	IPACMDBG_H("Self iface %s, event iface %s\n", dev_name, event_iface_name);
	if(strncmp(event_iface_name, "l2tp", 4) == 0)
	{
		IPACMDBG_H("This is l2tp event.\n");
		return true;
	}
	return false;
}
#endif //#ifdef FEATURE_L2TP
#endif //defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
#ifdef FEATURE_L2TP
/* add l2tp rt rule for l2tp client */
int IPACM_Lan::add_l2tp_rt_rule(ipa_ip_type iptype, uint8_t *dst_mac, ipa_hdr_l2_type peer_l2_hdr_type,
	uint32_t l2tp_session_id, uint32_t vlan_id, uint8_t *vlan_client_mac, uint32_t *vlan_iface_ipv6_addr,
	uint32_t *vlan_client_ipv6_addr, uint32_t *first_pass_hdr_hdl, uint32_t *first_pass_hdr_proc_ctx_hdl,
	uint32_t *second_pass_hdr_hdl, int *num_rt_hdl, uint32_t *first_pass_rt_rule_hdl, uint32_t *second_pass_rt_rule_hdl)
{
	int i, size, position;
	uint32_t vlan_iface_ipv6_addr_network[4], vlan_client_ipv6_addr_network[4];
	ipa_ioc_add_hdr *hdr_table;
	ipa_hdr_add *hdr;
	ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table;
	ipa_hdr_proc_ctx_add *hdr_proc_ctx;
	ipa_ioc_add_rt_rule* rt_rule_table;
	ipa_rt_rule_add *rt_rule;
	ipa_ioc_copy_hdr copy_hdr;

	if(tx_prop == NULL)
	{
		IPACMERR("No tx prop.\n");
		return IPACM_FAILURE;
	}

	/* =========== install first pass hdr template (IPv6 + L2TP + inner ETH header = 62 bytes) ============= */
	if(*first_pass_hdr_hdl != 0)
	{
		IPACMDBG_H("First pass hdr template was added before.\n");
	}
	else
	{
		size = sizeof(ipa_ioc_add_hdr) + sizeof(ipa_hdr_add);
		hdr_table = (ipa_ioc_add_hdr*)malloc(size);
		if(hdr_table == NULL)
		{
			IPACMERR("Failed to allocate memory.\n");
			return IPACM_FAILURE;
		}
		memset(hdr_table, 0, size);

		hdr_table->commit = 1;
		hdr_table->num_hdrs = 1;
		hdr = &hdr_table->hdr[0];

		if(iptype == IPA_IP_v4)
		{
			snprintf(hdr->name, sizeof(hdr->name), "vlan_%d_l2tp_%d_v4", vlan_id, l2tp_session_id);
		}
		else
		{
			snprintf(hdr->name, sizeof(hdr->name), "vlan_%d_l2tp_%d_v6", vlan_id, l2tp_session_id);
		}
		hdr->hdr_len = 62;
		hdr->type = IPA_HDR_L2_ETHERNET_II;
		hdr->is_partial = 0;

		hdr->hdr[0] = 0x60;	/* version */
		hdr->hdr[6] = 0x73; /* next header = L2TP */
		hdr->hdr[7] = 0x40; /* hop limit = 64 */
		for(i = 0; i < 4; i++)
		{
			vlan_iface_ipv6_addr_network[i] = htonl(vlan_iface_ipv6_addr[i]);
			vlan_client_ipv6_addr_network[i] = htonl(vlan_client_ipv6_addr[i]);
		}
		memcpy(hdr->hdr + 8, vlan_iface_ipv6_addr_network, 16); /* source IPv6 addr */
		memcpy(hdr->hdr + 24, vlan_client_ipv6_addr_network, 16); /* dest IPv6 addr */
		hdr->hdr[43] = (uint8_t)(l2tp_session_id & 0xFF); /* l2tp header */
		hdr->hdr[42] = (uint8_t)(l2tp_session_id >> 8 & 0xFF);
		hdr->hdr[41] = (uint8_t)(l2tp_session_id >> 16 & 0xFF);
		hdr->hdr[40] = (uint8_t)(l2tp_session_id >> 24 & 0xFF);

		if(m_header.AddHeader(hdr_table) == false)
		{
			IPACMERR("Failed to add hdr with status: %d\n", hdr_table->hdr[0].status);
			free(hdr_table);
			return IPACM_FAILURE;
		}
		*first_pass_hdr_hdl = hdr_table->hdr[0].hdr_hdl;
		IPACMDBG_H("Installed first pass hdr: hdl %d\n", *first_pass_hdr_hdl);
		free(hdr_table);
	}

	/* =========== install first pass hdr proc ctx (populate src/dst MAC and Ether type) ============= */
	size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
	hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx*)malloc(size);
	if(hdr_proc_ctx_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(hdr_proc_ctx_table, 0, size);

	hdr_proc_ctx_table->commit = 1;
	hdr_proc_ctx_table->num_proc_ctxs = 1;
	hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];

	hdr_proc_ctx->type = IPA_HDR_PROC_L2TP_HEADER_ADD;
	hdr_proc_ctx->hdr_hdl = *first_pass_hdr_hdl;
	hdr_proc_ctx->l2tp_params.hdr_add_param.eth_hdr_retained = 1;
	hdr_proc_ctx->l2tp_params.hdr_add_param.input_ip_version = iptype;
	hdr_proc_ctx->l2tp_params.hdr_add_param.output_ip_version = IPA_IP_v6;
	if(m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false)
	{
		IPACMERR("Failed to add hdr proc ctx with status: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
		free(hdr_proc_ctx_table);
		return IPACM_FAILURE;
	}
	*first_pass_hdr_proc_ctx_hdl = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
	IPACMDBG_H("Installed first pass hdr proc ctx: hdl %d\n", *first_pass_hdr_proc_ctx_hdl);
	free(hdr_proc_ctx_table);

	/* =========== install first pass rt rules (match dst MAC then doing UCP) ============= */
	*num_rt_hdl = each_client_rt_rule_count[iptype];
	size = sizeof(ipa_ioc_add_rt_rule) + (*num_rt_hdl) * sizeof(ipa_rt_rule_add);
	rt_rule_table = (ipa_ioc_add_rt_rule*)malloc(size);
	if (rt_rule_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(rt_rule_table, 0, size);

	rt_rule_table->commit = 1;
	rt_rule_table->ip = iptype;
	rt_rule_table->num_rules = *num_rt_hdl;
	snprintf(rt_rule_table->rt_tbl_name, sizeof(rt_rule_table->rt_tbl_name), "l2tp");
	rt_rule_table->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = 0;

	position = 0;
	for(i = 0; i < iface_query->num_tx_props; i++)
	{
		if(tx_prop->tx[i].ip == iptype)
		{
			if(position >= *num_rt_hdl || position >= MAX_NUM_PROP)
			{
				IPACMERR("Number of routing rules already exceeds limit.\n");
				free(rt_rule_table);
				return IPACM_FAILURE;
			}

			rt_rule = &rt_rule_table->rules[position];
			rt_rule->at_rear = false;
			rt_rule->status = -1;
			rt_rule->rt_rule_hdl = -1;
			rt_rule->rule.hashable = false;	//WLAN->ETH direction rules are set to non-hashable to keep consistent with the other direction
			rt_rule->rule.hdr_hdl = 0;
			rt_rule->rule.hdr_proc_ctx_hdl = *first_pass_hdr_proc_ctx_hdl;
			rt_rule->rule.dst = IPA_CLIENT_DUMMY_CONS;

			memcpy(&rt_rule->rule.attrib, &tx_prop->tx[i].attrib, sizeof(rt_rule->rule.attrib));
			if(peer_l2_hdr_type == IPA_HDR_L2_ETHERNET_II)
				rt_rule->rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_ETHER_II;
			else
				rt_rule->rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_802_3;
			memcpy(rt_rule->rule.attrib.dst_mac_addr, dst_mac, sizeof(rt_rule->rule.attrib.dst_mac_addr));
			memset(rt_rule->rule.attrib.dst_mac_addr_mask, 0xFF, sizeof(rt_rule->rule.attrib.dst_mac_addr_mask));
			position++;
		}
	}
	if(m_routing.AddRoutingRule(rt_rule_table) == false)
	{
		IPACMERR("Failed to add first pass rt rules.\n");
		free(rt_rule_table);
		return IPACM_FAILURE;
	}
	for(i = 0; i < position; i++)
	{
		first_pass_rt_rule_hdl[i] = rt_rule_table->rules[i].rt_rule_hdl;
	}
	free(rt_rule_table);

	/* =========== install second pass hdr (Ethernet header with L2TP tag = 18 bytes) ============= */
	if(*second_pass_hdr_hdl != 0)
	{
		IPACMDBG_H("Second pass hdr was added before.\n");
	}
	else
	{
		size = sizeof(ipa_ioc_add_hdr) + sizeof(ipa_hdr_add);
		hdr_table = (ipa_ioc_add_hdr*)malloc(size);
		if(hdr_table == NULL)
		{
			IPACMERR("Failed to allocate memory.\n");
			return IPACM_FAILURE;
		}
		memset(hdr_table, 0, size);

		hdr_table->commit = 1;
		hdr_table->num_hdrs = 1;
		hdr = &hdr_table->hdr[0];

		if(iptype == IPA_IP_v4)
		{
			snprintf(hdr->name, sizeof(hdr->name), "vlan_%d_v4", vlan_id);
		}
		else
		{
			snprintf(hdr->name, sizeof(hdr->name), "vlan_%d_v6", vlan_id);
		}
		hdr->type = IPA_HDR_L2_ETHERNET_II;
		hdr->is_partial = 0;
		for(i = 0; i < tx_prop->num_tx_props; i++)
		{
			if(tx_prop->tx[i].ip == IPA_IP_v6)
			{
				memset(&copy_hdr, 0, sizeof(copy_hdr));
				strlcpy(copy_hdr.name, tx_prop->tx[i].hdr_name,
					sizeof(copy_hdr.name));
				IPACMDBG_H("Header name: %s in tx:%d\n", copy_hdr.name, i);
				if(m_header.CopyHeader(&copy_hdr) == false)
				{
					IPACMERR("Failed to get partial header.\n");
					free(hdr_table);
					return IPACM_FAILURE;
				}
				IPACMDBG_H("Header length: %d\n", copy_hdr.hdr_len);
				hdr->hdr_len = copy_hdr.hdr_len;
				memcpy(hdr->hdr, copy_hdr.hdr, hdr->hdr_len);
				break;
			}
		}
		/* copy vlan client mac */
		memcpy(hdr->hdr + hdr->hdr_len - 18, vlan_client_mac, 6);
		hdr->hdr[hdr->hdr_len - 3] = (uint8_t)vlan_id & 0xFF;
		hdr->hdr[hdr->hdr_len - 4] = (uint8_t)(vlan_id >> 8) & 0xFF;

		if(m_header.AddHeader(hdr_table) == false)
		{
			IPACMERR("Failed to add hdr with status: %d\n", hdr->status);
			free(hdr_table);
			return IPACM_FAILURE;
		}
		*second_pass_hdr_hdl = hdr->hdr_hdl;
		IPACMDBG_H("Installed second pass hdr: hdl %d\n", *second_pass_hdr_hdl);
		free(hdr_table);
	}

	/* =========== install second pass rt rules (match VLAN interface IPv6 address at dst client side) ============= */
	if(second_pass_rt_rule_hdl[0] != 0)
	{
		IPACMDBG_H("Second pass rt rule was added before, return.\n");
		return IPACM_SUCCESS;
	}

	*num_rt_hdl = each_client_rt_rule_count[IPA_IP_v6];
	size = sizeof(ipa_ioc_add_rt_rule) + (*num_rt_hdl) * sizeof(ipa_rt_rule_add);
	rt_rule_table = (ipa_ioc_add_rt_rule*)malloc(size);
	if (rt_rule_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(rt_rule_table, 0, size);

	rt_rule_table->commit = 1;
	rt_rule_table->ip = IPA_IP_v6;
	rt_rule_table->num_rules = *num_rt_hdl;
	snprintf(rt_rule_table->rt_tbl_name, sizeof(rt_rule_table->rt_tbl_name), "l2tp");
	rt_rule_table->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = 0;

	position = 0;
	for(i = 0; i < iface_query->num_tx_props; i++)
	{
		if(tx_prop->tx[i].ip == IPA_IP_v6)
		{
			if(position >= *num_rt_hdl || position >= MAX_NUM_PROP)
			{
				IPACMERR("Number of routing rules already exceeds limit.\n");
				free(rt_rule_table);
				return IPACM_FAILURE;
			}

			rt_rule = &rt_rule_table->rules[position];
			rt_rule->at_rear = false;
			rt_rule->status = -1;
			rt_rule->rt_rule_hdl = -1;
			rt_rule->rule.hashable = false;	//WLAN->ETH direction rules are set to non-hashable to keep consistent with the other direction
			rt_rule->rule.hdr_hdl = *second_pass_hdr_hdl;
			rt_rule->rule.hdr_proc_ctx_hdl = 0;
			rt_rule->rule.dst = tx_prop->tx[i].dst_pipe;

			memcpy(&rt_rule->rule.attrib, &tx_prop->tx[i].attrib, sizeof(rt_rule->rule.attrib));
			rt_rule->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
			memcpy(rt_rule->rule.attrib.u.v6.dst_addr, vlan_client_ipv6_addr,
				sizeof(rt_rule->rule.attrib.u.v6.dst_addr));
			memset(rt_rule->rule.attrib.u.v6.dst_addr_mask, 0xFF, sizeof(rt_rule->rule.attrib.u.v6.dst_addr_mask));
			position++;
		}
	}
	if(m_routing.AddRoutingRule(rt_rule_table) == false)
	{
		IPACMERR("Failed to add second pass rt rules.\n");
		free(rt_rule_table);
		return IPACM_FAILURE;
	}
	for(i = 0; i < position; i++)
	{
		second_pass_rt_rule_hdl[i] = rt_rule_table->rules[i].rt_rule_hdl;
	}
	free(rt_rule_table);

	return IPACM_SUCCESS;
}

/* delete l2tp rt rule for l2tp client */
int IPACM_Lan::del_l2tp_rt_rule(ipa_ip_type iptype, uint32_t first_pass_hdr_hdl, uint32_t first_pass_hdr_proc_ctx_hdl,
	uint32_t second_pass_hdr_hdl, int num_rt_hdl, uint32_t *first_pass_rt_rule_hdl, uint32_t *second_pass_rt_rule_hdl)
{
	int i;

	if(num_rt_hdl < 0)
	{
		IPACMERR("Invalid num rt rule: %d\n", num_rt_hdl);
		return IPACM_FAILURE;
	}

	for(i = 0; i < num_rt_hdl; i++)
	{
		if(first_pass_rt_rule_hdl != NULL)
		{
			if(m_routing.DeleteRoutingHdl(first_pass_rt_rule_hdl[i], iptype) == false)
			{
				return IPACM_FAILURE;
			}
		}
		if(second_pass_rt_rule_hdl != NULL)
		{
			if(m_routing.DeleteRoutingHdl(second_pass_rt_rule_hdl[i], IPA_IP_v6) == false)
			{
				return IPACM_FAILURE;
			}
		}
	}

	if(first_pass_hdr_proc_ctx_hdl != 0)
	{
		if(m_header.DeleteHeaderProcCtx(first_pass_hdr_proc_ctx_hdl) == false)
		{
			return IPACM_FAILURE;
		}
	}

	if(first_pass_hdr_hdl != 0)
	{
		if(m_header.DeleteHeaderHdl(first_pass_hdr_hdl) == false)
		{
			return IPACM_FAILURE;
		}
	}
	if(second_pass_hdr_hdl != 0)
	{
		if(m_header.DeleteHeaderHdl(second_pass_hdr_hdl) == false)
		{
			return IPACM_FAILURE;
		}
	}

	return IPACM_SUCCESS;
}

/* add l2tp rt rule for non l2tp client */
int IPACM_Lan::add_l2tp_rt_rule(ipa_ip_type iptype, uint8_t *dst_mac, uint32_t *hdr_proc_ctx_hdl,
	int *num_rt_hdl, uint32_t *rt_rule_hdl)
{
	int i, size, position;
	ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table;
	ipa_hdr_proc_ctx_add *hdr_proc_ctx;
	ipa_ioc_add_rt_rule* rt_rule_table;
	ipa_rt_rule_add *rt_rule;
	ipa_ioc_get_hdr hdr;

	if(tx_prop == NULL)
	{
		IPACMERR("No tx prop.\n");
		return IPACM_FAILURE;
	}

	memset(&hdr, 0, sizeof(hdr));
	for(i = 0; i < tx_prop->num_tx_props; i++)
	{
		if(tx_prop->tx[i].ip == iptype)
		{
			strlcpy(hdr.name, tx_prop->tx[i].hdr_name,
				sizeof(hdr.name));
			break;
		}
	}
	if(m_header.GetHeaderHandle(&hdr) == false)
	{
		IPACMERR("Failed to get template hdr hdl.\n");
		return IPACM_FAILURE;
	}

	/* =========== install hdr proc ctx (uc needs to remove IPv6 + L2TP + inner ETH header = 62 bytes) ============= */
	if(*hdr_proc_ctx_hdl != 0)
	{
		IPACMDBG_H("Hdr proc ctx was added before.\n");
	}
	else
	{
		size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
		hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx*)malloc(size);
		if(hdr_proc_ctx_table == NULL)
		{
			IPACMERR("Failed to allocate memory.\n");
			return IPACM_FAILURE;
		}
		memset(hdr_proc_ctx_table, 0, size);

		hdr_proc_ctx_table->commit = 1;
		hdr_proc_ctx_table->num_proc_ctxs = 1;
		hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];

		hdr_proc_ctx->type = IPA_HDR_PROC_L2TP_HEADER_REMOVE;
		hdr_proc_ctx->hdr_hdl = hdr.hdl;
		hdr_proc_ctx->l2tp_params.hdr_remove_param.hdr_len_remove = 62;
		hdr_proc_ctx->l2tp_params.hdr_remove_param.eth_hdr_retained = 1;
		hdr_proc_ctx->l2tp_params.is_dst_pipe_valid = 1;
		hdr_proc_ctx->l2tp_params.dst_pipe = tx_prop->tx[0].dst_pipe;
		IPACMDBG_H("Header_remove: hdr len %d, hdr retained %d, dst client: %d\n",
			hdr_proc_ctx->l2tp_params.hdr_remove_param.hdr_len_remove,
			hdr_proc_ctx->l2tp_params.hdr_remove_param.eth_hdr_retained,
			hdr_proc_ctx->l2tp_params.dst_pipe);
		if(m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false)
		{
			IPACMERR("Failed to add hdr proc ctx with status: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
			free(hdr_proc_ctx_table);
			return IPACM_FAILURE;
		}
		*hdr_proc_ctx_hdl = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
		IPACMDBG_H("Installed hdr proc ctx: hdl %d\n", *hdr_proc_ctx_hdl);
		free(hdr_proc_ctx_table);
	}

	/* =========== install rt rules (match dst MAC within 62 bytes header) ============= */
	*num_rt_hdl = each_client_rt_rule_count[iptype];
	size = sizeof(ipa_ioc_add_rt_rule) + (*num_rt_hdl) * sizeof(ipa_rt_rule_add);
	rt_rule_table = (ipa_ioc_add_rt_rule*)malloc(size);
	if (rt_rule_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(rt_rule_table, 0, size);

	rt_rule_table->commit = 1;
	rt_rule_table->ip = iptype;
	rt_rule_table->num_rules = *num_rt_hdl;
	snprintf(rt_rule_table->rt_tbl_name, sizeof(rt_rule_table->rt_tbl_name), "l2tp");
	rt_rule_table->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = 0;

	position = 0;
	for(i = 0; i < iface_query->num_tx_props; i++)
	{
		if(tx_prop->tx[i].ip == iptype)
		{
			if(position >= *num_rt_hdl || position >= MAX_NUM_PROP)
			{
				IPACMERR("Number of routing rules already exceeds limit.\n");
				free(rt_rule_table);
				return IPACM_FAILURE;
			}

			rt_rule = &rt_rule_table->rules[position];
			rt_rule->at_rear = false;
			rt_rule->status = -1;
			rt_rule->rt_rule_hdl = -1;
			rt_rule->rule.hashable = false;	//ETH->WLAN direction rules need to be non-hashable due to encapsulation

			rt_rule->rule.hdr_hdl = 0;
			rt_rule->rule.hdr_proc_ctx_hdl = *hdr_proc_ctx_hdl;
			rt_rule->rule.dst = tx_prop->tx[i].dst_pipe;

			memcpy(&rt_rule->rule.attrib, &tx_prop->tx[i].attrib, sizeof(rt_rule->rule.attrib));

			rt_rule->rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_L2TP;
			memset(rt_rule->rule.attrib.dst_mac_addr_mask, 0xFF, sizeof(rt_rule->rule.attrib.dst_mac_addr_mask));
			memcpy(rt_rule->rule.attrib.dst_mac_addr, dst_mac, sizeof(rt_rule->rule.attrib.dst_mac_addr));

			position++;
		}
	}
	if(m_routing.AddRoutingRule(rt_rule_table) == false)
	{
		IPACMERR("Failed to add first pass rt rules.\n");
		free(rt_rule_table);
		return IPACM_FAILURE;
	}
	for(i = 0; i < position; i++)
		rt_rule_hdl[i] = rt_rule_table->rules[i].rt_rule_hdl;

	free(rt_rule_table);
	return IPACM_SUCCESS;
}

int IPACM_Lan::del_l2tp_rt_rule(ipa_ip_type iptype, int num_rt_hdl, uint32_t *rt_rule_hdl)
{
	int i;

	if(num_rt_hdl < 0)
	{
		IPACMERR("Invalid num rt rule: %d\n", num_rt_hdl);
		return IPACM_FAILURE;
	}

	for(i = 0; i < num_rt_hdl; i++)
	{
		if(m_routing.DeleteRoutingHdl(rt_rule_hdl[i], iptype) == false)
		{
			return IPACM_FAILURE;
		}
	}

	return IPACM_SUCCESS;
}

/* add l2tp flt rule on l2tp interface */
int IPACM_Lan::add_l2tp_flt_rule(uint8_t *dst_mac, uint32_t *flt_rule_hdl)
{
	int len;
	int fd_ipa;
	struct ipa_flt_rule_add flt_rule_entry;
	struct ipa_ioc_add_flt_rule_after *pFilteringTable = NULL;
	ipa_ioc_get_rt_tbl rt_tbl;

#ifdef FEATURE_IPA_V3
	if (rx_prop == NULL || tx_prop == NULL)
	{
		IPACMDBG_H("No rx or tx properties registered for iface %s\n", dev_name);
		return IPACM_FAILURE;
	}

	len = sizeof(struct ipa_ioc_add_flt_rule_after) + sizeof(struct ipa_flt_rule_add);
	pFilteringTable = (struct ipa_ioc_add_flt_rule_after*)malloc(len);
	if (!pFilteringTable)
	{
		IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
		return IPACM_FAILURE;
	}
	memset(pFilteringTable, 0, len);

	pFilteringTable->commit = 1;
	pFilteringTable->ep = rx_prop->rx[0].src_pipe;
	pFilteringTable->ip = IPA_IP_v6;
	pFilteringTable->num_rules = 1;
	pFilteringTable->add_after_hdl = eth_bridge_flt_rule_offset[0][IPA_IP_v6];

	fd_ipa = open(IPA_DEVICE_NAME, O_RDWR);
	if(fd_ipa == 0)
	{
		IPACMERR("Failed to open %s\n",IPA_DEVICE_NAME);
		free(pFilteringTable);
		return IPACM_FAILURE;
	}

	rt_tbl.ip = IPA_IP_v6;
	snprintf(rt_tbl.name, sizeof(rt_tbl.name), "l2tp");
	rt_tbl.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
	IPACMDBG_H("This flt rule points to rt tbl %s.\n", rt_tbl.name);
	if(m_routing.GetRoutingTable(&rt_tbl) == false)
	{
		IPACMERR("Failed to get routing table from name\n");
		free(pFilteringTable);
		close(fd_ipa);
		return IPACM_FAILURE;
	}

	memset(&flt_rule_entry, 0, sizeof(flt_rule_entry));
	flt_rule_entry.at_rear = 1;

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
	flt_rule_entry.rule.eq_attrib_type = 0;
	flt_rule_entry.rule.rt_tbl_hdl = rt_tbl.hdl;
	flt_rule_entry.rule.hashable = false;	//ETH->WLAN direction rules need to be non-hashable due to encapsulation

	memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[0].attrib, sizeof(flt_rule_entry.rule.attrib));

	/* flt rule is matching dst MAC within 62 bytes header */
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_L2TP;
	memset(flt_rule_entry.rule.attrib.dst_mac_addr_mask, 0xFF, sizeof(flt_rule_entry.rule.attrib.dst_mac_addr_mask));
	memcpy(flt_rule_entry.rule.attrib.dst_mac_addr, dst_mac, sizeof(flt_rule_entry.rule.attrib.dst_mac_addr));

	memcpy(&(pFilteringTable->rules[0]), &flt_rule_entry, sizeof(flt_rule_entry));
	if(m_filtering.AddFilteringRuleAfter(pFilteringTable) == false)
	{
		IPACMERR("Failed to add client filtering rules.\n");
		free(pFilteringTable);
		close(fd_ipa);
		return IPACM_FAILURE;
	}
	*flt_rule_hdl = pFilteringTable->rules[0].flt_rule_hdl;

	free(pFilteringTable);
	close(fd_ipa);
#endif
	return IPACM_SUCCESS;
}

/* delete l2tp flt rule on l2tp interface */
int IPACM_Lan::del_l2tp_flt_rule(uint32_t flt_rule_hdl)
{
	if(m_filtering.DeleteFilteringHdls(&(flt_rule_hdl), IPA_IP_v6, 1) == false)
	{
		return IPACM_FAILURE;
	}
	return IPACM_SUCCESS;
}

/* add l2tp flt rule on non l2tp interface */
int IPACM_Lan::add_l2tp_flt_rule(ipa_ip_type iptype, uint8_t *dst_mac, uint32_t *vlan_client_ipv6_addr,
	uint32_t *first_pass_flt_rule_hdl, uint32_t *second_pass_flt_rule_hdl)
{
	int len;
	struct ipa_flt_rule_add flt_rule_entry;
	struct ipa_ioc_add_flt_rule_after *pFilteringTable = NULL;
	ipa_ioc_get_rt_tbl rt_tbl;

#ifdef FEATURE_IPA_V3
	if (rx_prop == NULL || tx_prop == NULL)
	{
		IPACMDBG_H("No rx or tx properties registered for iface %s\n", dev_name);
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Dst client MAC 0x%02x%02x%02x%02x%02x%02x.\n", dst_mac[0], dst_mac[1],
		dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

	len = sizeof(struct ipa_ioc_add_flt_rule_after) + sizeof(struct ipa_flt_rule_add);
	pFilteringTable = (struct ipa_ioc_add_flt_rule_after*)malloc(len);
	if (!pFilteringTable)
	{
		IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
		return IPACM_FAILURE;
	}
	memset(pFilteringTable, 0, len);

	pFilteringTable->commit = 1;
	pFilteringTable->ep = rx_prop->rx[0].src_pipe;
	pFilteringTable->ip = iptype;
	pFilteringTable->num_rules = 1;
	pFilteringTable->add_after_hdl = eth_bridge_flt_rule_offset[0][iptype];

	/* =========== add first pass flt rule (match dst MAC) ============= */
	rt_tbl.ip = iptype;
	snprintf(rt_tbl.name, sizeof(rt_tbl.name), "l2tp");
	IPACMDBG_H("This flt rule points to rt tbl %s.\n", rt_tbl.name);

	if(m_routing.GetRoutingTable(&rt_tbl) == false)
	{
		IPACMERR("Failed to get routing table.\n");
		return IPACM_FAILURE;
	}

	memset(&flt_rule_entry, 0, sizeof(flt_rule_entry));
	flt_rule_entry.at_rear = 1;

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
	flt_rule_entry.rule.eq_attrib_type = 0;
	flt_rule_entry.rule.rt_tbl_hdl = rt_tbl.hdl;
	flt_rule_entry.rule.hashable = false;	//WLAN->ETH direction rules are set to non-hashable to keep consistent with the other direction

	memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[0].attrib, sizeof(flt_rule_entry.rule.attrib));
	if(tx_prop->tx[0].hdr_l2_type == IPA_HDR_L2_ETHERNET_II)
	{
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_ETHER_II;
	}
	else
	{
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_802_3;
	}

	memcpy(flt_rule_entry.rule.attrib.dst_mac_addr, dst_mac, sizeof(flt_rule_entry.rule.attrib.dst_mac_addr));
	memset(flt_rule_entry.rule.attrib.dst_mac_addr_mask, 0xFF, sizeof(flt_rule_entry.rule.attrib.dst_mac_addr_mask));

	memcpy(&(pFilteringTable->rules[0]), &flt_rule_entry, sizeof(flt_rule_entry));
	if (false == m_filtering.AddFilteringRuleAfter(pFilteringTable))
	{
		IPACMERR("Failed to add first pass filtering rules.\n");
		free(pFilteringTable);
		return IPACM_FAILURE;
	}
	*first_pass_flt_rule_hdl = pFilteringTable->rules[0].flt_rule_hdl;

	/* =========== add second pass flt rule (match VLAN interface IPv6 address at client side) ============= */
	if(*second_pass_flt_rule_hdl != 0)
	{
		IPACMDBG_H("Second pass flt rule was added before, return.\n");
		free(pFilteringTable);
		return IPACM_SUCCESS;
	}

	rt_tbl.ip = IPA_IP_v6;
	snprintf(rt_tbl.name, sizeof(rt_tbl.name), "l2tp");
	IPACMDBG_H("This flt rule points to rt tbl %s.\n", rt_tbl.name);

	if(m_routing.GetRoutingTable(&rt_tbl) == false)
	{
		IPACMERR("Failed to get routing table.\n");
		return IPACM_FAILURE;
	}

	pFilteringTable->ip = IPA_IP_v6;
	pFilteringTable->add_after_hdl = eth_bridge_flt_rule_offset[0][IPA_IP_v6];

	memset(&flt_rule_entry, 0, sizeof(flt_rule_entry));
	flt_rule_entry.at_rear = 1;

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
	flt_rule_entry.rule.eq_attrib_type = 0;
	flt_rule_entry.rule.rt_tbl_hdl = rt_tbl.hdl;
	flt_rule_entry.rule.hashable = false;	//WLAN->ETH direction rules are set to non-hashable to keep consistent with the other direction

	memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[0].attrib, sizeof(flt_rule_entry.rule.attrib));
	flt_rule_entry.rule.attrib.attrib_mask = IPA_FLT_DST_ADDR;

	memcpy(flt_rule_entry.rule.attrib.u.v6.dst_addr, vlan_client_ipv6_addr, sizeof(flt_rule_entry.rule.attrib.u.v6.dst_addr));
	memset(flt_rule_entry.rule.attrib.u.v6.dst_addr_mask, 0xFF, sizeof(flt_rule_entry.rule.attrib.u.v6.dst_addr_mask));

	memcpy(&(pFilteringTable->rules[0]), &flt_rule_entry, sizeof(flt_rule_entry));
	if (false == m_filtering.AddFilteringRuleAfter(pFilteringTable))
	{
		IPACMERR("Failed to add client filtering rules.\n");
		free(pFilteringTable);
		return IPACM_FAILURE;
	}
	*second_pass_flt_rule_hdl = pFilteringTable->rules[0].flt_rule_hdl;

	free(pFilteringTable);
#endif
	return IPACM_SUCCESS;
}

/* delete l2tp flt rule on non l2tp interface */
int IPACM_Lan::del_l2tp_flt_rule(ipa_ip_type iptype, uint32_t first_pass_flt_rule_hdl, uint32_t second_pass_flt_rule_hdl)
{
	if (first_pass_flt_rule_hdl != 0)
	{
		if(m_filtering.DeleteFilteringHdls(&first_pass_flt_rule_hdl, iptype, 1) == false)
		{
			return IPACM_FAILURE;
		}
	}

	if(second_pass_flt_rule_hdl != 0)
	{
		if(m_filtering.DeleteFilteringHdls(&second_pass_flt_rule_hdl, iptype, 1) == false)
		{
			return IPACM_FAILURE;
		}
	}

	return IPACM_SUCCESS;
}

#ifdef IPA_L2TP_TUNNEL_UDP
/* add l2tp rt rule for l2tp client */
int IPACM_Lan::add_l2tp_udp_rt_rule(ipa_ip_type iptype, uint8_t *dst_mac, ipa_hdr_l2_type peer_l2_hdr_type,
	ipa_l2tp_tunnel_type tunnel_type, uint32_t l2tp_session_id, uint16_t src_port, uint16_t dst_port,
	uint32_t vlan_id, uint8_t *vlan_client_mac, uint32_t *vlan_iface_ipv6_addr,
	uint32_t *vlan_client_ipv6_addr, uint32_t *hdr_hdl, uint32_t *hdr_proc_ctx_hdl, int *num_rt_hdl,
	uint32_t *rt_rule_hdl)
{
	int i, size, position;
	uint32_t vlan_iface_ipv6_addr_network[4], vlan_client_ipv6_addr_network[4];
	ipa_ioc_add_hdr *hdr_table;
	ipa_hdr_add *hdr;
	ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table;
	ipa_hdr_proc_ctx_add *hdr_proc_ctx;
	ipa_ioc_add_rt_rule* rt_rule_table;
	ipa_rt_rule_add *rt_rule;
	ipa_ioc_copy_hdr copy_hdr;

	if(tx_prop == NULL)
	{
		IPACMERR("No tx prop.\n");
		return IPACM_FAILURE;
	}

/* =========== install hdr template (Outer VLAN Header(18) + IPv6(40) + UDP(8) + L2TP(16) + inner ETH header(14) = 96 bytes) ============= */
	size = sizeof(ipa_ioc_add_hdr) + sizeof(ipa_hdr_add);
	hdr_table = (ipa_ioc_add_hdr*)malloc(size);
	if(hdr_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(hdr_table, 0, size);

	hdr_table->commit = 1;
	hdr_table->num_hdrs = 1;
	hdr = &hdr_table->hdr[0];

	if(iptype == IPA_IP_v4)
	{
		snprintf(hdr->name, sizeof(hdr->name), "vlan_%d_l2tp_%d_v4", vlan_id, l2tp_session_id);
	}
	else
	{
		snprintf(hdr->name, sizeof(hdr->name), "vlan_%d_l2tp_%d_v6", vlan_id, l2tp_session_id);
	}
	hdr->hdr_len = 96;
	hdr->type = IPA_HDR_L2_ETHERNET_II;
	hdr->is_partial = 0;

	/* Update the VLAN header. */
	for(i = 0; i < tx_prop->num_tx_props; i++)
	{
		if(tx_prop->tx[i].ip == IPA_IP_v6)
		{
			memset(&copy_hdr, 0, sizeof(copy_hdr));
			strlcpy(copy_hdr.name, tx_prop->tx[i].hdr_name,
				sizeof(copy_hdr.name));
			IPACMDBG_H("Header name: %s in tx:%d\n", copy_hdr.name, i);
			if(m_header.CopyHeader(&copy_hdr) == false)
			{
				IPACMERR("Failed to get partial header.\n");
				free(hdr_table);
				return IPACM_FAILURE;
			}
			IPACMDBG_H("Header length: %d\n", copy_hdr.hdr_len);
			memcpy(hdr->hdr, copy_hdr.hdr, hdr->hdr_len);
			break;
		}
	}
	/* copy vlan client mac */
	memcpy(hdr->hdr, vlan_client_mac, 6);
	/* VLAN ID is 12 bits. So update accordingly. */
	hdr->hdr[15] = (uint8_t)vlan_id & 0xFF;
	hdr->hdr[14] = (uint8_t)(vlan_id >> 8) & 0x0F;

	/* Update IPv6 Version. */
	hdr->hdr[18] = 0x60;	/* version */
	hdr->hdr[24] = 0x11; /* next header = UDP */
	hdr->hdr[25] = 0x40; /* hop limit = 64 */
	for(i = 0; i < 4; i++)
	{
		vlan_iface_ipv6_addr_network[i] = htonl(vlan_iface_ipv6_addr[i]);
		vlan_client_ipv6_addr_network[i] = htonl(vlan_client_ipv6_addr[i]);
	}
	memcpy(hdr->hdr + 26, vlan_iface_ipv6_addr_network, 16); /* source IPv6 addr */
	memcpy(hdr->hdr + 42, vlan_client_ipv6_addr_network, 16); /* dest IPv6 addr */
	/* Update UDP source port and Destination Port*/
	*(uint16_t *)(&hdr->hdr[58]) = htons(src_port);
	*(uint16_t *)(&hdr->hdr[60]) = htons(dst_port);
	/* Update the UDP Version info. */
	*(uint32_t *)(&hdr->hdr[66]) = 0x0300;
	/* Updated the Session ID. */
	hdr->hdr[73] = (uint8_t)(l2tp_session_id & 0xFF); /* l2tp header */
	hdr->hdr[72] = (uint8_t)(l2tp_session_id >> 8 & 0xFF);
	hdr->hdr[71] = (uint8_t)(l2tp_session_id >> 16 & 0xFF);
	hdr->hdr[70] = (uint8_t)(l2tp_session_id >> 24 & 0xFF);

	if(iptype == IPA_IP_v4)
	{
		/* Update Inner Ether Type to 0x800.*/
		hdr->hdr[94] = 0x08;
		hdr->hdr[95] = 0x00;
	}
	else
	{
		/* Update Inner Ether Type to 0x86dd.*/
		hdr->hdr[94] = 0x86;
		hdr->hdr[95] = 0xdd;
	}

	if(m_header.AddHeader(hdr_table) == false)
	{
		IPACMERR("Failed to add hdr with status: %d\n", hdr_table->hdr[0].status);
		free(hdr_table);
		return IPACM_FAILURE;
	}
	*hdr_hdl = hdr_table->hdr[0].hdr_hdl;
	IPACMDBG_H("Installed L2TP over UDP hdr: hdl %d\n", *hdr_hdl);
	free(hdr_table);

	/* =========== install hdr proc ctx (populate src/dst MAC and Ether type) ============= */
	size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
	hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx*)malloc(size);
	if(hdr_proc_ctx_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(hdr_proc_ctx_table, 0, size);

	hdr_proc_ctx_table->commit = 1;
	hdr_proc_ctx_table->num_proc_ctxs = 1;
	hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];

	hdr_proc_ctx->type = IPA_HDR_PROC_L2TP_UDP_HEADER_ADD;
	hdr_proc_ctx->hdr_hdl = *hdr_hdl;
	hdr_proc_ctx->l2tp_params.hdr_add_param.eth_hdr_retained = 1;
	/* Boolean to indicate whether uC needs to perform second pass or not. */
	hdr_proc_ctx->l2tp_params.hdr_add_param.second_pass = 0;
	hdr_proc_ctx->l2tp_params.hdr_add_param.input_ip_version = iptype;
	hdr_proc_ctx->l2tp_params.hdr_add_param.output_ip_version = IPA_IP_v6;
	if(m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false)
	{
		IPACMERR("Failed to add hdr proc ctx with status: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
		free(hdr_proc_ctx_table);
		return IPACM_FAILURE;
	}
	*hdr_proc_ctx_hdl = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
	IPACMDBG_H("Installed hdr proc ctx: hdl %d\n", *hdr_proc_ctx_hdl);
	free(hdr_proc_ctx_table);

	/* =========== install routing rules (match dst MAC then doing UCP) ============= */
	*num_rt_hdl = each_client_rt_rule_count[iptype];
	size = sizeof(ipa_ioc_add_rt_rule) + (*num_rt_hdl) * sizeof(ipa_rt_rule_add);
	rt_rule_table = (ipa_ioc_add_rt_rule*)malloc(size);
	if (rt_rule_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(rt_rule_table, 0, size);

	rt_rule_table->commit = 1;
	rt_rule_table->ip = iptype;
	rt_rule_table->num_rules = *num_rt_hdl;
	snprintf(rt_rule_table->rt_tbl_name, sizeof(rt_rule_table->rt_tbl_name), "l2tp");
	rt_rule_table->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = 0;

	position = 0;
	for(i = 0; i < iface_query->num_tx_props; i++)
	{
		if(tx_prop->tx[i].ip == iptype)
		{
			if(position >= *num_rt_hdl || position >= MAX_NUM_PROP)
			{
				IPACMERR("Number of routing rules already exceeds limit.\n");
				free(rt_rule_table);
				return IPACM_FAILURE;
			}

			rt_rule = &rt_rule_table->rules[position];
			rt_rule->at_rear = false;
			rt_rule->status = -1;
			rt_rule->rt_rule_hdl = -1;
			rt_rule->rule.hashable = false;	//WLAN->ETH direction rules are set to non-hashable to keep consistent with the other direction
			rt_rule->rule.hdr_hdl = 0;
			rt_rule->rule.hdr_proc_ctx_hdl = *hdr_proc_ctx_hdl;
			rt_rule->rule.dst = tx_prop->tx[i].dst_pipe;

			memcpy(&rt_rule->rule.attrib, &tx_prop->tx[i].attrib, sizeof(rt_rule->rule.attrib));
			/* This is to maintain backward compatibility. Currently WLAN header is only Ethernet header. */
			if(peer_l2_hdr_type == IPA_HDR_L2_ETHERNET_II)
				rt_rule->rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_ETHER_II;
			else
				rt_rule->rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_802_3;
			memcpy(rt_rule->rule.attrib.dst_mac_addr, dst_mac, sizeof(rt_rule->rule.attrib.dst_mac_addr));
			memset(rt_rule->rule.attrib.dst_mac_addr_mask, 0xFF, sizeof(rt_rule->rule.attrib.dst_mac_addr_mask));
			position++;
		}
	}
	if(m_routing.AddRoutingRule(rt_rule_table) == false)
	{
		IPACMERR("Failed to add first pass rt rules.\n");
		free(rt_rule_table);
		return IPACM_FAILURE;
	}
	for(i = 0; i < position; i++)
	{
		rt_rule_hdl[i] = rt_rule_table->rules[i].rt_rule_hdl;
	}
	free(rt_rule_table);

	return IPACM_SUCCESS;
}

/* delete l2tp udp rt rule for l2tp client */
int IPACM_Lan::del_l2tp_udp_rt_rule(ipa_ip_type iptype, uint32_t hdr_hdl, uint32_t hdr_proc_ctx_hdl,
	int num_rt_hdl, uint32_t *rt_rule_hdl)
{
	int i;

	if(num_rt_hdl < 0)
	{
		IPACMERR("Invalid num rt rule: %d\n", num_rt_hdl);
		return IPACM_FAILURE;
	}

	for(i = 0; i < num_rt_hdl; i++)
	{
		if(rt_rule_hdl != NULL)
		{
			if(m_routing.DeleteRoutingHdl(rt_rule_hdl[i], iptype) == false)
			{
				return IPACM_FAILURE;
			}
		}
	}

	if(hdr_proc_ctx_hdl != 0)
	{
		if(m_header.DeleteHeaderProcCtx(hdr_proc_ctx_hdl) == false)
		{
			return IPACM_FAILURE;
		}
	}

	if(hdr_hdl != 0)
	{
		if(m_header.DeleteHeaderHdl(hdr_hdl) == false)
		{
			return IPACM_FAILURE;
		}
	}

	return IPACM_SUCCESS;
}

/* add l2tp udp rt rule for non l2tp client */
int IPACM_Lan::add_l2tp_udp_rt_rule(ipa_ip_type iptype, uint8_t *dst_mac, uint32_t *hdr_proc_ctx_hdl,
	int *num_rt_hdl, uint32_t *rt_rule_hdl)
{
	int i, size, position;
	ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table;
	ipa_hdr_proc_ctx_add *hdr_proc_ctx;
	ipa_ioc_add_rt_rule* rt_rule_table;
	ipa_rt_rule_add *rt_rule;
	ipa_ioc_get_hdr hdr;

	if(tx_prop == NULL)
	{
		IPACMERR("No tx prop.\n");
		return IPACM_FAILURE;
	}

	memset(&hdr, 0, sizeof(hdr));
	for(i = 0; i < tx_prop->num_tx_props; i++)
	{
		if(tx_prop->tx[i].ip == iptype)
		{
			strlcpy(hdr.name, tx_prop->tx[i].hdr_name,
				sizeof(hdr.name));
			break;
		}
	}
	if(m_header.GetHeaderHandle(&hdr) == false)
	{
		IPACMERR("Failed to get template hdr hdl.\n");
		return IPACM_FAILURE;
	}

	/* =========== install hdr proc ctx (uC needs to remove IPv6(40) + UDP (8) +L2TP (16) header + Inner ETH (14) = 78 bytes) ============= */
	if(*hdr_proc_ctx_hdl != 0)
	{
		IPACMDBG_H("Hdr proc ctx was added before.\n");
	}
	else
	{
		size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
		hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx*)malloc(size);
		if(hdr_proc_ctx_table == NULL)
		{
			IPACMERR("Failed to allocate memory.\n");
			return IPACM_FAILURE;
		}
		memset(hdr_proc_ctx_table, 0, size);

		hdr_proc_ctx_table->commit = 1;
		hdr_proc_ctx_table->num_proc_ctxs = 1;
		hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];

		hdr_proc_ctx->type = IPA_HDR_PROC_L2TP_UDP_HEADER_REMOVE;
		hdr_proc_ctx->hdr_hdl = hdr.hdl;
		hdr_proc_ctx->l2tp_params.hdr_remove_param.hdr_len_remove = 78;
		hdr_proc_ctx->l2tp_params.hdr_remove_param.eth_hdr_retained = 1;
		hdr_proc_ctx->l2tp_params.is_dst_pipe_valid = 1;
		hdr_proc_ctx->l2tp_params.dst_pipe = tx_prop->tx[0].dst_pipe;
		IPACMDBG_H("Header_remove: hdr len %d, hdr retained %d, dst client: %d\n",
			hdr_proc_ctx->l2tp_params.hdr_remove_param.hdr_len_remove,
			hdr_proc_ctx->l2tp_params.hdr_remove_param.eth_hdr_retained,
			hdr_proc_ctx->l2tp_params.dst_pipe);
		if(m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false)
		{
			IPACMERR("Failed to add hdr proc ctx with status: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
			free(hdr_proc_ctx_table);
			return IPACM_FAILURE;
		}
		*hdr_proc_ctx_hdl = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
		IPACMDBG_H("Installed hdr proc ctx: hdl %d\n", *hdr_proc_ctx_hdl);
		free(hdr_proc_ctx_table);
	}

	/* =========== install rt rules (match dst MAC within 64 bytes header) ============= */
	*num_rt_hdl = each_client_rt_rule_count[iptype];
	size = sizeof(ipa_ioc_add_rt_rule) + (*num_rt_hdl) * sizeof(ipa_rt_rule_add);
	rt_rule_table = (ipa_ioc_add_rt_rule*)malloc(size);
	if (rt_rule_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(rt_rule_table, 0, size);

	rt_rule_table->commit = 1;
	rt_rule_table->ip = iptype;
	rt_rule_table->num_rules = *num_rt_hdl;
	snprintf(rt_rule_table->rt_tbl_name, sizeof(rt_rule_table->rt_tbl_name), "l2tp");
	rt_rule_table->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = 0;

	position = 0;
	for(i = 0; i < iface_query->num_tx_props; i++)
	{
		if(tx_prop->tx[i].ip == iptype)
		{
			if(position >= *num_rt_hdl || position >= MAX_NUM_PROP)
			{
				IPACMERR("Number of routing rules already exceeds limit.\n");
				free(rt_rule_table);
				return IPACM_FAILURE;
			}

			rt_rule = &rt_rule_table->rules[position];
			rt_rule->at_rear = false;
			rt_rule->status = -1;
			rt_rule->rt_rule_hdl = -1;
			rt_rule->rule.hashable = false;	//ETH->WLAN direction rules need to be non-hashable due to encapsulation

			rt_rule->rule.hdr_hdl = 0;
			rt_rule->rule.hdr_proc_ctx_hdl = *hdr_proc_ctx_hdl;
			rt_rule->rule.dst = tx_prop->tx[i].dst_pipe;

			memcpy(&rt_rule->rule.attrib, &tx_prop->tx[i].attrib, sizeof(rt_rule->rule.attrib));

			rt_rule->rule.attrib.attrib_mask |= IPA_FLT_L2TP_UDP_INNER_MAC_DST_ADDR;
			memset(rt_rule->rule.attrib.dst_mac_addr_mask, 0xFF, sizeof(rt_rule->rule.attrib.dst_mac_addr_mask));
			memcpy(rt_rule->rule.attrib.dst_mac_addr, dst_mac, sizeof(rt_rule->rule.attrib.dst_mac_addr));

			position++;
		}
	}
	if(m_routing.AddRoutingRule(rt_rule_table) == false)
	{
		IPACMERR("Failed to add first pass rt rules.\n");
		free(rt_rule_table);
		return IPACM_FAILURE;
	}
	for(i = 0; i < position; i++)
		rt_rule_hdl[i] = rt_rule_table->rules[i].rt_rule_hdl;

	free(rt_rule_table);
	return IPACM_SUCCESS;
}

/* add l2tp udp flt rule on l2tp interface */
int IPACM_Lan::add_l2tp_udp_flt_rule(uint8_t *dst_mac, uint32_t *vlan_iface_ipv6_addr,
	uint32_t *vlan_client_ipv6_addr, uint16_t src_port, uint16_t dst_port, uint32_t *flt_rule_hdl)
{
	int len;
	int fd_ipa = 0;
	struct ipa_flt_rule_add flt_rule_entry;
	struct ipa_ioc_add_flt_rule_after *pFilteringTable = NULL;
	ipa_ioc_get_rt_tbl rt_tbl;
	int ret = IPACM_SUCCESS;

	if (rx_prop == NULL || tx_prop == NULL)
	{
		IPACMDBG_H("No rx or tx properties registered for iface %s\n", dev_name);
		return IPACM_FAILURE;
	}

	len = sizeof(struct ipa_ioc_add_flt_rule_after) + sizeof(struct ipa_flt_rule_add);
	pFilteringTable = (struct ipa_ioc_add_flt_rule_after*)malloc(len);
	if (!pFilteringTable)
	{
		IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
		return IPACM_FAILURE;
	}
	memset(pFilteringTable, 0, len);

	pFilteringTable->commit = 1;
	pFilteringTable->ep = rx_prop->rx[0].src_pipe;
	pFilteringTable->ip = IPA_IP_v6;
	pFilteringTable->num_rules = 1;
	pFilteringTable->add_after_hdl = l2tp_udp_dflt_flt_tule_offset;

	fd_ipa = open(IPA_DEVICE_NAME, O_RDWR);
	if(fd_ipa == 0)
	{
		IPACMERR("Failed to open %s\n",IPA_DEVICE_NAME);
		ret = IPACM_FAILURE;
		goto end;
	}

	rt_tbl.ip = IPA_IP_v6;
	snprintf(rt_tbl.name, sizeof(rt_tbl.name), "l2tp");
	rt_tbl.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
	IPACMDBG_H("This flt rule points to rt tbl %s.\n", rt_tbl.name);
	if(m_routing.GetRoutingTable(&rt_tbl) == false)
	{
		IPACMERR("Failed to get routing table from name\n");
		ret = IPACM_FAILURE;
		goto end;
	}

	memset(&flt_rule_entry, 0, sizeof(flt_rule_entry));
	flt_rule_entry.at_rear = 1;

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
	flt_rule_entry.rule.eq_attrib_type = 0;
	flt_rule_entry.rule.rt_tbl_hdl = rt_tbl.hdl;
	flt_rule_entry.rule.hashable = false;	//ETH->WLAN direction rules need to be non-hashable due to encapsulation

	memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[0].attrib, sizeof(flt_rule_entry.rule.attrib));

	/* Match if it is an L2TP packet and then match the desination mac. */
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
	memcpy(flt_rule_entry.rule.attrib.u.v6.dst_addr, vlan_iface_ipv6_addr,
		sizeof(flt_rule_entry.rule.attrib.u.v6.dst_addr));
	memset(flt_rule_entry.rule.attrib.u.v6.dst_addr_mask, 0xFF,
		sizeof(flt_rule_entry.rule.attrib.u.v6.dst_addr_mask));

	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
	memcpy(flt_rule_entry.rule.attrib.u.v6.src_addr, vlan_client_ipv6_addr,
		sizeof(flt_rule_entry.rule.attrib.u.v6.src_addr));
	memset(flt_rule_entry.rule.attrib.u.v6.src_addr_mask, 0xFF,
		sizeof(flt_rule_entry.rule.attrib.u.v6.src_addr_mask));

	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_PORT;
	flt_rule_entry.rule.attrib.dst_port = dst_port;

	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_SRC_PORT;
	flt_rule_entry.rule.attrib.src_port = src_port;

	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_NEXT_HDR;
	flt_rule_entry.rule.attrib.u.v6.next_hdr = (uint8_t)IPACM_FIREWALL_IPPROTO_UDP;

	/* flt rule is matching dst MAC within 62 bytes header */
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_L2TP_UDP_INNER_MAC_DST_ADDR;
	memset(flt_rule_entry.rule.attrib.dst_mac_addr_mask, 0xFF, sizeof(flt_rule_entry.rule.attrib.dst_mac_addr_mask));
	memcpy(flt_rule_entry.rule.attrib.dst_mac_addr, dst_mac, sizeof(flt_rule_entry.rule.attrib.dst_mac_addr));

	memcpy(&(pFilteringTable->rules[0]), &flt_rule_entry, sizeof(flt_rule_entry));
	if(m_filtering.AddFilteringRuleAfter(pFilteringTable) == false)
	{
		IPACMERR("Failed to add client filtering rules.\n");
		ret = IPACM_FAILURE;
		goto end;
	}
	*flt_rule_hdl = pFilteringTable->rules[0].flt_rule_hdl;

end:
	if (pFilteringTable)
		free(pFilteringTable);
	if (fd_ipa)
		close(fd_ipa);
	return ret;
}

/* add default exception rules for l2tp udp client */
int IPACM_Lan::add_l2tp_udp_dflt_flt_rules(uint32_t *l2tp_dflt_rules)
{
	int len, i =0;
	int fd_ipa;
	struct ipa_flt_rule_add flt_rule_entry;
	struct ipa_ioc_add_flt_rule_after *pFilteringTable = NULL;
	int ret = IPACM_SUCCESS;

	if (rx_prop == NULL || tx_prop == NULL)
	{
		IPACMDBG_H("No rx or tx properties registered for iface %s\n", dev_name);
		return IPACM_FAILURE;
	}

	len = sizeof(struct ipa_ioc_add_flt_rule_after) + NUM_L2TP_UDP_DFLT_RULES*sizeof(struct ipa_flt_rule_add);
	pFilteringTable = (struct ipa_ioc_add_flt_rule_after*)malloc(len);
	if (!pFilteringTable)
	{
		IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
		return IPACM_FAILURE;
	}
	memset(pFilteringTable, 0, len);

	pFilteringTable->commit = 1;
	pFilteringTable->ep = rx_prop->rx[0].src_pipe;
	pFilteringTable->ip = IPA_IP_v6;
	pFilteringTable->num_rules = NUM_L2TP_UDP_DFLT_RULES;
	pFilteringTable->add_after_hdl = eth_bridge_flt_rule_offset[0][IPA_IP_v6];

	fd_ipa = open(IPA_DEVICE_NAME, O_RDWR);
	if(fd_ipa == 0)
	{
		IPACMERR("Failed to open %s\n",IPA_DEVICE_NAME);
		ret = IPACM_FAILURE;
		goto end;
	}

	memset(&flt_rule_entry, 0, sizeof(flt_rule_entry));
	flt_rule_entry.at_rear = 0;

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.action = IPA_PASS_TO_EXCEPTION;
	flt_rule_entry.rule.eq_attrib_type = 0;
	flt_rule_entry.rule.hashable = false;	//ETH->WLAN direction rules need to be non-hashable due to encapsulation

	memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[0].attrib, sizeof(flt_rule_entry.rule.attrib));

	/* Add Frag exception rule for external packet. In L2TP scenario, there can be frag packets
	 * with only frag exception header and do not containing the offset or MF bit. These packets
	 * will not match IS_FRAG equation. We need to explicitly match the next header byte.
	 */
	flt_rule_entry.rule.attrib.ext_attrib_mask |= IPA_FLT_EXT_NEXT_HDR;
	flt_rule_entry.rule.attrib.u.v6.next_hdr = (uint8_t)IPACM_FIREWALL_IPPROTO_FRAG_HDR;
	memcpy(&(pFilteringTable->rules[0]), &flt_rule_entry, sizeof(flt_rule_entry));

	/* ARP Exception rule. */
	flt_rule_entry.rule.attrib.ext_attrib_mask &= ~IPA_FLT_EXT_NEXT_HDR;
	flt_rule_entry.rule.attrib.ext_attrib_mask |= IPA_FLT_EXT_L2TP_UDP_INNER_ETHER_TYPE;
	flt_rule_entry.rule.attrib.ether_type = ETH_P_ARP;
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_NEXT_HDR;
	flt_rule_entry.rule.attrib.u.v6.next_hdr = (uint8_t)IPACM_FIREWALL_IPPROTO_UDP;
	memcpy(&(pFilteringTable->rules[1]), &flt_rule_entry, sizeof(flt_rule_entry));

	/* TCP SYN Exception rule for inner IPv4 packet. */
	flt_rule_entry.rule.attrib.ext_attrib_mask |= IPA_FLT_EXT_L2TP_UDP_TCP_SYN;
	flt_rule_entry.rule.attrib.ether_type = ETH_P_IP;
	memcpy(&(pFilteringTable->rules[2]), &flt_rule_entry, sizeof(flt_rule_entry));

	/* TCP SYN Exception rule for inner IPv6 packet. */
	flt_rule_entry.rule.attrib.ext_attrib_mask |= IPA_FLT_EXT_L2TP_UDP_TCP_SYN;
	flt_rule_entry.rule.attrib.ether_type = ETH_P_IPV6;
	memcpy(&(pFilteringTable->rules[3]), &flt_rule_entry, sizeof(flt_rule_entry));

	/* ICMPv6 Exception rule for inner IPv6 packet. */
	flt_rule_entry.rule.attrib.ext_attrib_mask &= ~IPA_FLT_EXT_L2TP_UDP_TCP_SYN;
	flt_rule_entry.rule.attrib.ext_attrib_mask |= IPA_FLT_EXT_L2TP_UDP_INNER_NEXT_HDR;
	flt_rule_entry.rule.attrib.l2tp_udp_next_hdr = (uint8_t)IPACM_FIREWALL_IPPROTO_ICMP6;
	memcpy(&(pFilteringTable->rules[4]), &flt_rule_entry, sizeof(flt_rule_entry));

	if(m_filtering.AddFilteringRuleAfter(pFilteringTable) == false)
	{
		IPACMERR("Failed to add client filtering rules.\n");
		ret = IPACM_FAILURE;
		goto end;
	}
	for (i = 0; i < NUM_L2TP_UDP_DFLT_RULES; i++)
		l2tp_dflt_rules[i] = pFilteringTable->rules[i].flt_rule_hdl;

	/* Update the dflt flt rule offset so that client rules are added after this rule. */
	l2tp_udp_dflt_flt_tule_offset = l2tp_dflt_rules[NUM_L2TP_UDP_DFLT_RULES-1];

end:
	if (pFilteringTable)
		free(pFilteringTable);
	if (fd_ipa)
		close(fd_ipa);

	return ret;
}

/* delete l2tp flt rule on l2tp interface */
int IPACM_Lan::del_l2tp_udp_dflt_flt_rules(uint32_t *dflt_rules)
{

	if(m_filtering.DeleteFilteringHdls(dflt_rules, IPA_IP_v6, NUM_L2TP_UDP_DFLT_RULES) == false)
	{
		return IPACM_FAILURE;
	}
	l2tp_udp_dflt_flt_tule_offset = eth_bridge_flt_rule_offset[0][IPA_IP_v6];
	return IPACM_SUCCESS;
}


/* add l2tp udp flt rule on non l2tp interface */
int IPACM_Lan::add_l2tp_udp_flt_rule(ipa_ip_type iptype, uint8_t *dst_mac,
	uint16_t mtu, uint32_t *flt_rule_hdl)
{
	int len;
	struct ipa_flt_rule_add flt_rule_entry;
	struct ipa_ioc_add_flt_rule_after *pFilteringTable = NULL;
	struct ipa_ioc_get_rt_tbl_indx rt_tbl_idx;
	int fd_ipa = 0;
	ipa_ioc_get_rt_tbl rt_tbl;
	int ret = IPACM_SUCCESS;

	if (rx_prop == NULL || tx_prop == NULL)
	{
		IPACMDBG_H("No rx or tx properties registered for iface %s\n", dev_name);
		return IPACM_FAILURE;
	}

	fd_ipa = open(IPA_DEVICE_NAME, O_RDWR);
	if(0 == fd_ipa)
	{
		IPACMERR("Failed to open %s\n",IPA_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Dst client MAC 0x%02x%02x%02x%02x%02x%02x.\n", dst_mac[0], dst_mac[1],
		dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

	len = sizeof(struct ipa_ioc_add_flt_rule_after) + sizeof(struct ipa_flt_rule_add);
	pFilteringTable = (struct ipa_ioc_add_flt_rule_after*)malloc(len);
	if (!pFilteringTable)
	{
		IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
		ret = IPACM_FAILURE;
		goto end;
	}
	memset(pFilteringTable, 0, len);

	pFilteringTable->commit = 1;
	pFilteringTable->ep = rx_prop->rx[0].src_pipe;
	pFilteringTable->ip = iptype;
	pFilteringTable->num_rules = 1;
	pFilteringTable->add_after_hdl = eth_bridge_flt_rule_offset[0][iptype];

	/* =========== add flt rule (match dst MAC) ============= */
	rt_tbl.ip = iptype;
	snprintf(rt_tbl.name, sizeof(rt_tbl.name), "l2tp");
	IPACMDBG_H("This flt rule points to rt tbl %s.\n", rt_tbl.name);

	if(m_routing.GetRoutingTable(&rt_tbl) == false)
	{
		IPACMERR("Failed to get routing table.\n");
		ret = IPACM_FAILURE;
		goto end;
	}

	memset(&flt_rule_entry, 0, sizeof(flt_rule_entry));
	flt_rule_entry.at_rear = 1;

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
	flt_rule_entry.rule.eq_attrib_type = 0;
	flt_rule_entry.rule.rt_tbl_hdl = rt_tbl.hdl;
	flt_rule_entry.rule.hashable = false;	//WLAN->ETH direction rules are set to non-hashable to keep consistent with the other direction

	memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[0].attrib, sizeof(flt_rule_entry.rule.attrib));
	if(tx_prop->tx[0].hdr_l2_type == IPA_HDR_L2_ETHERNET_II)
	{
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_ETHER_II;
	}
	else
	{
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_MAC_DST_ADDR_802_3;
	}

	memcpy(flt_rule_entry.rule.attrib.dst_mac_addr, dst_mac, sizeof(flt_rule_entry.rule.attrib.dst_mac_addr));
	memset(flt_rule_entry.rule.attrib.dst_mac_addr_mask, 0xFF, sizeof(flt_rule_entry.rule.attrib.dst_mac_addr_mask));
	/* Make sure packets are within MTU range. */
	flt_rule_entry.rule.attrib.ext_attrib_mask |= IPA_FLT_EXT_MTU;
	/* Update the payload length based on IP type. For IPv4, length field includes the header.
	 * For IPv6, length field doesn't include header so we need to subtract IPv6 header length
	 * of 40 bytes.
	 */
	flt_rule_entry.rule.attrib.payload_length = (iptype == IPA_IP_v4) ? mtu : (mtu - 40);
	memcpy(&(pFilteringTable->rules[0]), &flt_rule_entry, sizeof(flt_rule_entry));
	if (false == m_filtering.AddFilteringRuleAfter(pFilteringTable))
	{
		IPACMERR("Failed to add first pass filtering rules.\n");
		ret = IPACM_FAILURE;
		goto end;
	}
	*flt_rule_hdl = pFilteringTable->rules[0].flt_rule_hdl;

end:
	if (pFilteringTable)
		free(pFilteringTable);
	if (fd_ipa)
		close(fd_ipa);

	return ret;
}

/* delete l2tp udp flt rule on non l2tp interface */
int IPACM_Lan::del_l2tp_udp_flt_rule(ipa_ip_type iptype, uint32_t flt_rule_hdl)
{
	if(flt_rule_hdl != 0)
	{
		if(m_filtering.DeleteFilteringHdls(&flt_rule_hdl, iptype, 1) == false)
		{
			return IPACM_FAILURE;
		}
	}
	return IPACM_SUCCESS;
}

#endif

#endif
bool IPACM_Lan::is_unique_local_ipv6_addr(uint32_t* ipv6_addr)
{
	uint32_t ipv6_unique_local_prefix, ipv6_unique_local_prefix_mask;

	if(ipv6_addr == NULL)
	{
		IPACMERR("IPv6 address is empty.\n");
		return false;
	}
	IPACMDBG_H("Get ipv6 address with first word 0x%08x.\n", ipv6_addr[0]);

	ipv6_unique_local_prefix = 0xFD000000;
	ipv6_unique_local_prefix_mask = 0xFF000000;
	if((ipv6_addr[0] & ipv6_unique_local_prefix_mask) == (ipv6_unique_local_prefix & ipv6_unique_local_prefix_mask))
	{
		IPACMDBG_H("This IPv6 address is unique local IPv6 address.\n");
		return true;
	}
	return false;
}


/* add tcp syn flt rule */
int IPACM_Lan::add_tcp_syn_flt_rule(ipa_ip_type iptype)
{
	int len, idx = 0;
	struct ipa_flt_rule_add flt_rule_entry;
	ipa_ioc_add_flt_rule *m_pFilteringTable;
	int j;

	if(rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	len = sizeof(struct ipa_ioc_add_flt_rule) + sizeof(struct ipa_flt_rule_add);
	m_pFilteringTable = (struct ipa_ioc_add_flt_rule *)malloc(len);
	if(!m_pFilteringTable)
	{
		PERROR("Not enough memory.\n");
		return IPACM_FAILURE;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if ( j == 0 ) {
				idx = 0 ;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		prio[j][iptype]++;
		memset(m_pFilteringTable, 0, len);

		m_pFilteringTable->commit = 1;
		m_pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
		m_pFilteringTable->global = false;
		m_pFilteringTable->ip = iptype;
		m_pFilteringTable->num_rules = 1;

		memset(&flt_rule_entry, 0, sizeof(flt_rule_entry));
		flt_rule_entry.at_rear = true;
		flt_rule_entry.rule.retain_hdr = 1;
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;
		flt_rule_entry.rule.action = IPA_PASS_TO_EXCEPTION;

		memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[idx].attrib,
			   sizeof(flt_rule_entry.rule.attrib));
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_TCP_SYN;
		if (iptype == IPA_IP_v4)
		{
			flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_PROTOCOL;
			flt_rule_entry.rule.attrib.u.v4.protocol = 6;
		}
		else
		{
#ifdef FEATURE_EOGRE
			if(IPACM_Iface::ipacmcfg->eogre_enabled)
			{
				flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_NEXT_HDR;
				flt_rule_entry.rule.attrib.u.v6.next_hdr = 6;
			}
			else
#endif
			{
				flt_rule_entry.rule.eq_attrib_type = 1;
				flt_rule_entry.rule.eq_attrib.rule_eq_bitmap = 0;
				flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= 0x20<<flt_rule_entry.rule.eq_attrib.num_offset_meq_32;
				flt_rule_entry.rule.eq_attrib.offset_meq_32[flt_rule_entry.rule.eq_attrib.num_offset_meq_32].offset = 6;
				flt_rule_entry.rule.eq_attrib.offset_meq_32[flt_rule_entry.rule.eq_attrib.num_offset_meq_32].mask = 0xFF000000;
				flt_rule_entry.rule.eq_attrib.offset_meq_32[flt_rule_entry.rule.eq_attrib.num_offset_meq_32].value = 6 << 24;
				flt_rule_entry.rule.eq_attrib.num_offset_meq_32 ++;
				flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<8);
				flt_rule_entry.rule.eq_attrib.num_ihl_offset_meq_32 = 1;
				flt_rule_entry.rule.eq_attrib.ihl_offset_meq_32[0].offset = 12;

				/* add TCP SYN rule*/
				flt_rule_entry.rule.eq_attrib.ihl_offset_meq_32[0].value = (((uint32_t)1)<<TCP_SYN_SHIFT);
				flt_rule_entry.rule.eq_attrib.ihl_offset_meq_32[0].mask = (((uint32_t)1)<<TCP_SYN_SHIFT);

			}
		}

		memcpy(&(m_pFilteringTable->rules[0]), &flt_rule_entry, sizeof(flt_rule_entry));

		if (false == m_filtering.AddFilteringRule(m_pFilteringTable)) {
			IPACMERR("Error Adding RuleTable(0) to Filtering, aborting...\n");
			free(m_pFilteringTable);
			return IPACM_FAILURE;
		}

		tcp_syn_flt_rule_hdl[j][iptype] = m_pFilteringTable->rules[0].flt_rule_hdl;
		IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, iptype, 1);
		IPACMDBG_H("ip type: %d pFilteringTable->add_after_hdl 0x%x\n", iptype,
			   tcp_syn_flt_rule_hdl[j][iptype]);
	}

	free(m_pFilteringTable);
	return IPACM_SUCCESS;
}

/* add tcp syn flt rule for l2tp interface*/
int IPACM_Lan::add_tcp_syn_flt_rule_l2tp(ipa_ip_type inner_ip_type)
{
	int len;
	struct ipa_flt_rule_add flt_rule_entry;
	ipa_ioc_add_flt_rule *m_pFilteringTable;

	if(rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	len = sizeof(struct ipa_ioc_add_flt_rule) + sizeof(struct ipa_flt_rule_add);
	m_pFilteringTable = (struct ipa_ioc_add_flt_rule *)malloc(len);
	if(!m_pFilteringTable)
	{
		PERROR("Not enough memory.\n");
		return IPACM_FAILURE;
	}
	memset(m_pFilteringTable, 0, len);

	m_pFilteringTable->commit = 1;
	m_pFilteringTable->ep = rx_prop->rx[0].src_pipe;
	m_pFilteringTable->global = false;
	m_pFilteringTable->ip = IPA_IP_v6;
	m_pFilteringTable->num_rules = 1;

	memset(&flt_rule_entry, 0, sizeof(flt_rule_entry));
	flt_rule_entry.at_rear = true;
	flt_rule_entry.rule.retain_hdr = 1;
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;
	flt_rule_entry.rule.action = IPA_PASS_TO_EXCEPTION;

	memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[0].attrib,
		sizeof(flt_rule_entry.rule.attrib));
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_TCP_SYN_L2TP;
	if(inner_ip_type == IPA_IP_v4)
	{
		flt_rule_entry.rule.attrib.ether_type = 0x0800;
	}
	else
	{
		flt_rule_entry.rule.attrib.ether_type = 0x86dd;
	}

	memcpy(&(m_pFilteringTable->rules[0]), &flt_rule_entry, sizeof(flt_rule_entry));

	if(false == m_filtering.AddFilteringRule(m_pFilteringTable))
	{
		IPACMERR("Error Adding RuleTable(0) to Filtering, aborting...\n");
		free(m_pFilteringTable);
		return IPACM_FAILURE;
	}

	tcp_syn_flt_rule_hdl[0][inner_ip_type] = m_pFilteringTable->rules[0].flt_rule_hdl;
	free(m_pFilteringTable);
	return IPACM_SUCCESS;
}

#ifdef FEATURE_L2TP
/* install l2tp dl rules */
int IPACM_Lan::install_l2tp_dl_rules(ipacm_event_data_all *data, int index)
{
	int i, size;
	ipa_ioc_add_hdr *hdr_table;
	ipa_hdr_add *hdr;
	ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table;
	ipa_hdr_proc_ctx_add *hdr_proc_ctx;
	ipa_ioc_add_rt_rule* rt_rule_table;
	ipa_rt_rule_add *rt_rule;
	ipa_ioc_copy_hdr copy_hdr;
	l2tp_vlan_mapping_info info;
	uint32_t vlan_iface_ipv6_addr_network[4], vlan_client_ipv6_addr_network[4];
	l2tp_client_info new_client_info;
	ipacm_cmd_q_data evt_data;
	ipacm_event_data_all *data_all;

	if(tx_prop == NULL)
	{
		IPACMERR("No tx prop.\n");
		return IPACM_FAILURE;
	}

	if(IPACM_Iface::ipacmcfg->get_vlan_l2tp_mapping(data->iface_name, info) == IPACM_FAILURE)
	{
		IPACMERR("Fail to get vlan-l2tp mapping.\n");
		return IPACM_FAILURE;
	}

	get_client_memptr(eth_client, index)->v4_addr = data->ipv4_addr;
	is_l2tp_iface = true;
	memcpy(get_client_memptr(eth_client, index)->mac, data->mac_addr,
		sizeof(get_client_memptr(eth_client, index)->mac));

	/* =========== install first pass hdr template (IPv6 + L2TP + inner ETH header = 62 bytes) ============= */
	size = sizeof(ipa_ioc_add_hdr) + sizeof(ipa_hdr_add);
	hdr_table = (ipa_ioc_add_hdr*)malloc(size);
	if(hdr_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(hdr_table, 0, size);

	hdr_table->commit = 1;
	hdr_table->num_hdrs = 1;
	hdr = &hdr_table->hdr[0];

	snprintf(hdr->name, sizeof(hdr->name), "vlan_%d_l2tp_%d_v4", info.vlan_id, info.l2tp_session_id);

	hdr->hdr_len = 62;
	hdr->type = IPA_HDR_L2_ETHERNET_II;
	hdr->is_partial = 0;

	hdr->hdr[0] = 0x60;	/* version */
	hdr->hdr[6] = 0x73; /* next header = L2TP */
	hdr->hdr[7] = 0x40; /* hop limit = 64 */
	for(i = 0; i < 4; i++)
	{
		vlan_iface_ipv6_addr_network[i] = htonl(info.vlan_iface_ipv6_addr[i]);
		vlan_client_ipv6_addr_network[i] = htonl(info.vlan_client_ipv6_addr[i]);
	}
	memcpy(hdr->hdr + 8, vlan_iface_ipv6_addr_network, 16); /* source IPv6 addr */
	memcpy(hdr->hdr + 24, vlan_client_ipv6_addr_network, 16); /* dest IPv6 addr */
	hdr->hdr[43] = (uint8_t)(info.l2tp_session_id & 0xFF); /* l2tp header */
	hdr->hdr[42] = (uint8_t)(info.l2tp_session_id >> 8 & 0xFF);
	hdr->hdr[41] = (uint8_t)(info.l2tp_session_id >> 16 & 0xFF);
	hdr->hdr[40] = (uint8_t)(info.l2tp_session_id >> 24 & 0xFF);
	/* inner ETH header */
	memcpy(hdr->hdr + 48, data->mac_addr, 6); /* dst mac */
	hdr->hdr[60] = 0x08; /* Ether type */
	hdr->hdr[61] = 0x00;

	if(m_header.AddHeader(hdr_table) == false)
	{
		IPACMERR("Failed to add hdr with status: %d\n", hdr_table->hdr[0].status);
		free(hdr_table);
		return IPACM_FAILURE;
	}
	get_client_memptr(eth_client, index)->dl_first_pass_hdr_hdl = hdr_table->hdr[0].hdr_hdl;
	IPACMDBG_H("Installed first pass hdr: hdl %d\n", hdr_table->hdr[0].hdr_hdl);
	free(hdr_table);

	/* =========== install first pass hdr proc ctx ============= */
	size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
	hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx*)malloc(size);
	if(hdr_proc_ctx_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(hdr_proc_ctx_table, 0, size);

	hdr_proc_ctx_table->commit = 1;
	hdr_proc_ctx_table->num_proc_ctxs = 1;
	hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];

	hdr_proc_ctx->type = IPA_HDR_PROC_L2TP_HEADER_ADD;
	hdr_proc_ctx->hdr_hdl = get_client_memptr(eth_client, index)->dl_first_pass_hdr_hdl;
	hdr_proc_ctx->l2tp_params.hdr_add_param.eth_hdr_retained = 0;
	hdr_proc_ctx->l2tp_params.hdr_add_param.input_ip_version = IPA_IP_v4;
	hdr_proc_ctx->l2tp_params.hdr_add_param.output_ip_version = IPA_IP_v6;
	if(m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false)
	{
		IPACMERR("Failed to add hdr proc ctx with status: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
		free(hdr_proc_ctx_table);
		return IPACM_FAILURE;
	}
	get_client_memptr(eth_client, index)->dl_first_pass_hdr_proc_ctx_hdl =
		hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
	IPACMDBG_H("Installed first pass hdr proc ctx: hdl %d\n", hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl);
	free(hdr_proc_ctx_table);

	/* =========== install first pass rt rules (match dst MAC then doing UCP) ============= */
	size = sizeof(ipa_ioc_add_rt_rule) + sizeof(ipa_rt_rule_add);
	rt_rule_table = (ipa_ioc_add_rt_rule*)malloc(size);
	if (rt_rule_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(rt_rule_table, 0, size);

	rt_rule_table->commit = 1;
	rt_rule_table->ip = IPA_IP_v4;
	rt_rule_table->num_rules = 1;

	strlcpy(rt_rule_table->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
		sizeof(rt_rule_table->rt_tbl_name));
	rt_rule_table->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = 0;

	rt_rule = &rt_rule_table->rules[0];
	for(i = 0; i < iface_query->num_tx_props; i++)
	{
		if(tx_prop->tx[i].ip == IPA_IP_v4)
		{
			rt_rule->at_rear = false;
			rt_rule->status = -1;
			rt_rule->rt_rule_hdl = -1;
			rt_rule->rule.hashable = true;
			rt_rule->rule.hdr_hdl = 0;
			rt_rule->rule.hdr_proc_ctx_hdl =
				get_client_memptr(eth_client, index)->dl_first_pass_hdr_proc_ctx_hdl;
			rt_rule->rule.dst = IPA_CLIENT_DUMMY_CONS;

			memcpy(&rt_rule->rule.attrib, &tx_prop->tx[i].attrib, sizeof(rt_rule->rule.attrib));
			rt_rule->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
			rt_rule->rule.attrib.u.v4.dst_addr = data->ipv4_addr;
			rt_rule->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
			break;
		}
	}
	if(m_routing.AddRoutingRule(rt_rule_table) == false)
	{
		IPACMERR("Failed to add first pass rt rules.\n");
		free(rt_rule_table);
		return IPACM_FAILURE;
	}
	get_client_memptr(eth_client, index)->dl_first_pass_rt_rule_hdl =
		rt_rule_table->rules[0].rt_rule_hdl;
	free(rt_rule_table);

	/* =========== install second pass hdr (Ethernet header with L2TP tag = 18 bytes) ============= */
	size = sizeof(ipa_ioc_add_hdr) + sizeof(ipa_hdr_add);
	hdr_table = (ipa_ioc_add_hdr*)malloc(size);
	if(hdr_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(hdr_table, 0, size);

	hdr_table->commit = 1;
	hdr_table->num_hdrs = 1;
	hdr = &hdr_table->hdr[0];

	snprintf(hdr->name, sizeof(hdr->name), "vlan_%d_v6", info.vlan_id);

	hdr->type = IPA_HDR_L2_ETHERNET_II;
	hdr->is_partial = 0;
	for(i = 0; i < tx_prop->num_tx_props; i++)
	{
		if(tx_prop->tx[i].ip == IPA_IP_v6)
		{
			memset(&copy_hdr, 0, sizeof(copy_hdr));
			strlcpy(copy_hdr.name, tx_prop->tx[i].hdr_name,
				sizeof(copy_hdr.name));
			IPACMDBG_H("Header name: %s in tx:%d\n", copy_hdr.name, i);
			if(m_header.CopyHeader(&copy_hdr) == false)
			{
				IPACMERR("Failed to get partial header.\n");
				free(hdr_table);
				return IPACM_FAILURE;
			}
			IPACMDBG_H("Header length: %d\n", copy_hdr.hdr_len);
			hdr->hdr_len = copy_hdr.hdr_len;
			memcpy(hdr->hdr, copy_hdr.hdr, hdr->hdr_len);
			break;
		}
	}
	/* copy vlan client mac */
	memcpy(hdr->hdr, info.vlan_client_mac, 6);
	hdr->hdr[hdr->hdr_len - 3] = (uint8_t)info.vlan_id & 0xFF;
	hdr->hdr[hdr->hdr_len - 4] = (uint8_t)(info.vlan_id >> 8) & 0xFF;

	if(m_header.AddHeader(hdr_table) == false)
	{
		IPACMERR("Failed to add hdr with status: %d\n", hdr->status);
		free(hdr_table);
		return IPACM_FAILURE;
	}
	get_client_memptr(eth_client, index)->dl_second_pass_hdr_hdl = hdr->hdr_hdl;
	IPACMDBG_H("Installed second pass hdr: hdl %d\n",
		get_client_memptr(eth_client, index)->dl_second_pass_hdr_hdl);
	free(hdr_table);

	/* =========== install second pass rt rules (match VLAN interface IPv6 address at dst client side) ============= */
	size = sizeof(ipa_ioc_add_rt_rule) + sizeof(ipa_rt_rule_add);
	rt_rule_table = (ipa_ioc_add_rt_rule*)malloc(size);
	if (rt_rule_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(rt_rule_table, 0, size);

	rt_rule_table->commit = 1;
	rt_rule_table->ip = IPA_IP_v6;
	rt_rule_table->num_rules = 1;

	strlcpy(rt_rule_table->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule_table->rt_tbl_name));
	rt_rule_table->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';

	rt_rule = &rt_rule_table->rules[0];
	for(i = 0; i < iface_query->num_tx_props; i++)
	{
		if(tx_prop->tx[i].ip == IPA_IP_v6)
		{
			rt_rule->at_rear = false;
			rt_rule->status = -1;
			rt_rule->rt_rule_hdl = -1;
			rt_rule->rule.hashable = true;
			rt_rule->rule.hdr_hdl = get_client_memptr(eth_client, index)->dl_second_pass_hdr_hdl;
			rt_rule->rule.hdr_proc_ctx_hdl = 0;
			rt_rule->rule.dst = tx_prop->tx[i].dst_pipe;

			memcpy(&rt_rule->rule.attrib, &tx_prop->tx[i].attrib, sizeof(rt_rule->rule.attrib));
			rt_rule->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
			memcpy(rt_rule->rule.attrib.u.v6.dst_addr, info.vlan_client_ipv6_addr,
				sizeof(rt_rule->rule.attrib.u.v6.dst_addr));
			memset(rt_rule->rule.attrib.u.v6.dst_addr_mask, 0xFF, sizeof(rt_rule->rule.attrib.u.v6.dst_addr_mask));
			break;
		}
	}
	if(m_routing.AddRoutingRule(rt_rule_table) == false)
	{
		IPACMERR("Failed to add second pass rt rules.\n");
		free(rt_rule_table);
		return IPACM_FAILURE;
	}
	get_client_memptr(eth_client, index)->dl_second_pass_rt_rule_hdl =
		rt_rule_table->rules[0].rt_rule_hdl;
	free(rt_rule_table);

	strlcpy(new_client_info.client_iface_name, data->iface_name, sizeof(new_client_info.client_iface_name));
	IPACM_Iface::ipacmcfg->l2tp_client.push_back(new_client_info);

	/* post IPA_ADD_L2TP_CLIENT event */
	memset(&evt_data, 0, sizeof(evt_data));
	data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
	if(data_all == NULL)
	{
		IPACMERR("Unable to allocate memory for event data.\n");
		return IPACM_FAILURE;
	}
	strlcpy(data_all->iface_name, data->iface_name, sizeof(data_all->iface_name));
	evt_data.event = IPA_ADD_L2TP_CLIENT;
	evt_data.evt_data = data_all;
	IPACM_EvtDispatcher::PostEvt(&evt_data);

	return IPACM_SUCCESS;
}

/* install l2tp ul rules */
int IPACM_Lan::install_l2tp_ul_rules(ipacm_event_data_all *data, int index)
{
	int i, size;
	ipa_ioc_add_rt_rule* rt_rule_table;
	ipa_rt_rule_add *rt_rule;
	ipa_ioc_add_flt_rule_after *pFilteringTable;
	ipa_flt_rule_add *flt_rule_entry;
	l2tp_vlan_mapping_info info;
	l2tp_client_info new_client_info;

	if(tx_prop == NULL || rx_prop == NULL)
	{
		IPACMERR("No tx/rx prop.\n");
		return IPACM_FAILURE;
	}

	if(IPACM_Iface::ipacmcfg->get_vlan_l2tp_mapping(data->iface_name, info) == IPACM_FAILURE)
	{
		IPACMERR("Fail to get vlan-l2tp mapping.\n");
		return IPACM_FAILURE;
	}

	if(l2tp_ul_hdr_proc_ctx_hdl == 0)
	{
		IPACMERR("Ul hdr proc ctx was not installed.\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Installing l2tp ul rt rules.\n");

	/* =========== install ul rt rule ============= */
	size = sizeof(ipa_ioc_add_rt_rule) + sizeof(ipa_rt_rule_add);
	rt_rule_table = (ipa_ioc_add_rt_rule*)malloc(size);
	if (rt_rule_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(rt_rule_table, 0, size);

	rt_rule_table->commit = 1;
	rt_rule_table->ip = IPA_IP_v6;
	rt_rule_table->num_rules = 1;

	strlcpy(rt_rule_table->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_v6.name,
		sizeof(rt_rule_table->rt_tbl_name));
	rt_rule_table->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';

	rt_rule = &rt_rule_table->rules[0];
	for(i = 0; i < iface_query->num_tx_props; i++)
	{
		if(tx_prop->tx[i].ip == IPA_IP_v6)
		{
			rt_rule->at_rear = false;
			rt_rule->status = -1;
			rt_rule->rt_rule_hdl = -1;
			rt_rule->rule.hashable = false;
			rt_rule->rule.hdr_hdl = 0;
			rt_rule->rule.hdr_proc_ctx_hdl =
				l2tp_ul_hdr_proc_ctx_hdl;
			rt_rule->rule.dst = IPA_CLIENT_DUMMY_CONS;

			memcpy(&rt_rule->rule.attrib, &tx_prop->tx[i].attrib, sizeof(rt_rule->rule.attrib));
			rt_rule->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
			memcpy(rt_rule->rule.attrib.u.v6.dst_addr, info.vlan_iface_ipv6_addr,
				sizeof(rt_rule->rule.attrib.u.v6.dst_addr));
			memset(rt_rule->rule.attrib.u.v6.dst_addr_mask, 0xFF,
				sizeof(rt_rule->rule.attrib.u.v6.dst_addr_mask));
			break;
		}
	}
	if(m_routing.AddRoutingRule(rt_rule_table) == false)
	{
		IPACMERR("Failed to add first pass rt rules.\n");
		free(rt_rule_table);
		return IPACM_FAILURE;
	}
	get_client_memptr(eth_client, index)->ul_first_pass_rt_rule_hdl =
		rt_rule_table->rules[0].rt_rule_hdl;
	free(rt_rule_table);

	IPACMDBG_H("Installing l2tp ul flt rules.\n");

	/* =========== install ul flt rule ============= */
	size = sizeof(struct ipa_ioc_add_flt_rule_after) + sizeof(struct ipa_flt_rule_add);
	pFilteringTable = (struct ipa_ioc_add_flt_rule_after*)malloc(size);
	if (!pFilteringTable)
	{
		IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
		return IPACM_FAILURE;
	}
	memset(pFilteringTable, 0, size);

	pFilteringTable->commit = 1;
	pFilteringTable->ep = rx_prop->rx[0].src_pipe;
	pFilteringTable->ip = IPA_IP_v6;
	pFilteringTable->num_rules = 1;
	pFilteringTable->add_after_hdl = ipv6_icmp_flt_rule_hdl[0][0];

	if(false == m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_v6))
	{
		IPACMERR("m_routing.GetRoutingTable Failed.\n");
		free(pFilteringTable);
		return IPACM_FAILURE;
	}

	flt_rule_entry = &pFilteringTable->rules[0];
	flt_rule_entry->at_rear = 1;

	flt_rule_entry->rule.retain_hdr = 0;
	flt_rule_entry->rule.to_uc = 0;
	flt_rule_entry->rule.action = IPA_PASS_TO_ROUTING;
	flt_rule_entry->rule.eq_attrib_type = 0;
	flt_rule_entry->rule.rt_tbl_hdl = IPACM_Iface::ipacmcfg->rt_tbl_v6.hdl;
	flt_rule_entry->rule.hashable = false;

	memcpy(&flt_rule_entry->rule.attrib, &rx_prop->rx[0].attrib, sizeof(flt_rule_entry->rule.attrib));
	flt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
	memcpy(flt_rule_entry->rule.attrib.u.v6.dst_addr, info.vlan_iface_ipv6_addr,
		sizeof(flt_rule_entry->rule.attrib.u.v6.dst_addr));
	memset(flt_rule_entry->rule.attrib.u.v6.dst_addr_mask, 0xFF,
		sizeof(flt_rule_entry->rule.attrib.u.v6.dst_addr_mask));
	flt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_NEXT_HDR;
	flt_rule_entry->rule.attrib.u.v6.next_hdr = 0x73;
	flt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_L2TP_INNER_IP_TYPE;
	flt_rule_entry->rule.attrib.type = 0x40;

	if(m_filtering.AddFilteringRuleAfter(pFilteringTable) == false)
	{
		IPACMERR("Failed to add l2tp ul flt rule.\n");
		free(pFilteringTable);
		return IPACM_FAILURE;
	}

	IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);
	get_client_memptr(eth_client, index)->ul_first_pass_flt_rule_hdl =
		pFilteringTable->rules[0].flt_rule_hdl;
	free(pFilteringTable);
	return IPACM_SUCCESS;
}

/* uninstall l2tp rules */
int IPACM_Lan::uninstall_l2tp_rules(ipacm_event_data_all *data)
{
	int index;
	list<l2tp_client_info>::iterator it;
	ipacm_cmd_q_data evt_data;
	ipacm_event_data_all *data_all;

	index = get_eth_client_index(data->mac_addr);
	if(index == IPACM_INVALID_INDEX)
	{
		IPACMDBG_H("Eth client not attached\n");
		return IPACM_SUCCESS;
	}

	if(is_l2tp_iface == false)
	{
		IPACMDBG_H("This is not L2TP client.\n");
		return IPACM_SUCCESS;
	}

	HandleNeighIpAddrDelEvt(clt_indx);
	/* delete dl rules */
	if(m_routing.DeleteRoutingHdl(get_client_memptr(eth_client, index)->dl_first_pass_rt_rule_hdl, IPA_IP_v4) == false)
	{
		IPACMERR("Failed to delete first pass rt rule.\n");
		return IPACM_FAILURE;
	}

	if(m_routing.DeleteRoutingHdl(get_client_memptr(eth_client, index)->dl_second_pass_rt_rule_hdl, IPA_IP_v6) == false)
	{
		IPACMERR("Failed to delete second pass rt rule.\n");
		return IPACM_FAILURE;
	}

	if(m_header.DeleteHeaderProcCtx(get_client_memptr(eth_client, index)->dl_first_pass_hdr_proc_ctx_hdl) == false)
	{
		IPACMERR("Failed to delete first pass hdr proc ctx.\n");
		return IPACM_FAILURE;
	}

	if(m_header.DeleteHeaderHdl(get_client_memptr(eth_client, index)->dl_first_pass_hdr_hdl) == false)
	{
		IPACMERR("Failed to delete first pass hdr.\n");
		return IPACM_FAILURE;
	}

	if(m_header.DeleteHeaderHdl(get_client_memptr(eth_client, index)->dl_second_pass_hdr_hdl) == false)
	{
		IPACMERR("Failed to delete second pass hdr.\n");
		return IPACM_FAILURE;
	}

	/* delete ul rules */
	if(m_filtering.DeleteFilteringHdls(&get_client_memptr(eth_client, index)->ul_first_pass_flt_rule_hdl, IPA_IP_v6, 1) == false)
	{
		IPACMERR("Failed to delete ul flt rule.\n");
		return IPACM_FAILURE;
	}
	IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);

	if(m_routing.DeleteRoutingHdl(get_client_memptr(eth_client, index)->ul_first_pass_rt_rule_hdl, IPA_IP_v6) == false)
	{
		IPACMERR("Failed to delete ul rt rule.\n");
		return IPACM_FAILURE;
	}

	for(; index < num_eth_client-1; index++)
	{
		*get_client_memptr(eth_client, index) = *get_client_memptr(eth_client, index+1);
	}
	num_eth_client--;

	for(it = IPACM_Iface::ipacmcfg->l2tp_client.begin(); it != IPACM_Iface::ipacmcfg->l2tp_client.end(); it++)
	{
		if(strncmp(it->client_iface_name, data->iface_name, sizeof(it->client_iface_name)) == 0)
		{
			IPACM_Iface::ipacmcfg->l2tp_client.erase(it);
			break;
		}
	}

	/* post IPA_DEL_L2TP_CLIENT event */
	memset(&evt_data, 0, sizeof(evt_data));
	data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
	if(data_all == NULL)
	{
		IPACMERR("Unable to allocate memory for event data.\n");
		return IPACM_FAILURE;
	}
	strlcpy(data_all->iface_name, data->iface_name, sizeof(data_all->iface_name));
	evt_data.event = IPA_DEL_L2TP_CLIENT;
	evt_data.evt_data = data_all;
	IPACM_EvtDispatcher::PostEvt(&evt_data);

	/* Del RM dependency */
	if(num_eth_client == 0)
	{
		IPACMDBG_H("Netdev %s delete dependency\n", dev_name);
		if(tx_prop != NULL)
		{
			IPACMDBG_H("Dependency pipe: %d, rm index: %d\n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			IPACM_Iface::ipacmcfg->DelRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
		}
	}

	return IPACM_SUCCESS;
}

int IPACM_Lan::install_l2tp_ul_hdr_proc_ctx()
{
	int size;
	ipa_ioc_add_hdr *hdr_table;
	ipa_hdr_add *hdr;
	ipa_ioc_add_hdr_proc_ctx *hdr_proc_ctx_table;
	ipa_hdr_proc_ctx_add *hdr_proc_ctx;

	/* =========== install l2tp ul dummy header ============= */
	size = sizeof(ipa_ioc_add_hdr) + sizeof(ipa_hdr_add);
	hdr_table = (ipa_ioc_add_hdr*)malloc(size);
	if(hdr_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(hdr_table, 0, size);

	hdr_table->commit = 1;
	hdr_table->num_hdrs = 1;
	hdr = &hdr_table->hdr[0];
	snprintf(hdr->name, sizeof(hdr->name), "l2tp_ul");

	hdr->hdr_len = 4;
	hdr->type = IPA_HDR_L2_ETHERNET_II;
	hdr->is_partial = 0;

	if(m_header.AddHeader(hdr_table) == false)
	{
		IPACMERR("Failed to add hdr with status: %d\n", hdr_table->hdr[0].status);
		free(hdr_table);
		return IPACM_FAILURE;
	}
	l2tp_ul_dummy_hdr_hdl = hdr_table->hdr[0].hdr_hdl;
	IPACMDBG_H("Installed l2tp ul hdr: hdl %d\n", l2tp_ul_dummy_hdr_hdl);
	free(hdr_table);

	/* =========== install l2tp ul hdr proc ctx ============= */
	size = sizeof(ipa_ioc_add_hdr_proc_ctx) + sizeof(ipa_hdr_proc_ctx_add);
	hdr_proc_ctx_table = (ipa_ioc_add_hdr_proc_ctx*)malloc(size);
	if(hdr_proc_ctx_table == NULL)
	{
		IPACMERR("Failed to allocate memory.\n");
		return IPACM_FAILURE;
	}
	memset(hdr_proc_ctx_table, 0, size);

	hdr_proc_ctx_table->commit = 1;
	hdr_proc_ctx_table->num_proc_ctxs = 1;
	hdr_proc_ctx = &hdr_proc_ctx_table->proc_ctx[0];

	hdr_proc_ctx->type = IPA_HDR_PROC_L2TP_HEADER_REMOVE;
	hdr_proc_ctx->hdr_hdl = l2tp_ul_dummy_hdr_hdl;
	hdr_proc_ctx->l2tp_params.hdr_remove_param.hdr_len_remove = 62;
	hdr_proc_ctx->l2tp_params.hdr_remove_param.eth_hdr_retained = 0;
	if(m_header.AddHeaderProcCtx(hdr_proc_ctx_table) == false)
	{
		IPACMERR("Failed to add hdr proc ctx with status: %d\n", hdr_proc_ctx_table->proc_ctx[0].status);
		free(hdr_proc_ctx_table);
		return IPACM_FAILURE;
	}
	l2tp_ul_hdr_proc_ctx_hdl = hdr_proc_ctx_table->proc_ctx[0].proc_ctx_hdl;
	IPACMDBG_H("Installed l2tp ul hdr proc ctx: hdl %d\n", l2tp_ul_hdr_proc_ctx_hdl);
	free(hdr_proc_ctx_table);

	return IPACM_SUCCESS;
}
#endif

int IPACM_Lan::post_lan_up_event(const ipacm_event_data_addr* data) const
{
	ipacm_cmd_q_data evt_data;
	ipacm_event_iface_up* info;

	evt_data.evt_data = malloc(sizeof(ipacm_event_iface_up));
	if (evt_data.evt_data == NULL)
	{
		IPACMERR("Unable to allocate memory\n");
		return -ENOMEM;
	}

	info = static_cast<ipacm_event_iface_up*>(evt_data.evt_data);
	memcpy(info->ifname, dev_name, IF_NAME_LEN);

	switch (data->iptype)
	{
	case IPA_IP_v4:
		info->ipv4_addr = data->ipv4_addr;
		info->addr_mask = IPACM_Iface::ipacmcfg->private_subnet_table[0].subnet_mask;
		evt_data.event = IPA_HANDLE_LAN_WLAN_UP;

		IPACMDBG_H("posting client interface up for IPv4 with below information\n");
		IPACMDBG_H("IPv4 address:0x%x, IPv4 address mask:0x%x\n", info->ipv4_addr, info->addr_mask);
		break;
	case IPA_IP_v6:
		memcpy(info->ipv6_addr, data->ipv6_addr, sizeof(info->ipv6_addr));
		evt_data.event = IPA_HANDLE_LAN_WLAN_UP_V6;

		IPACMDBG_H("posting client interface up for IPv6 with below information\n");
		IPACMDBG_H("IPv6 address:0x%x%x%x%x\n",
			info->ipv6_addr[0], info->ipv6_addr[1], info->ipv6_addr[2], info->ipv6_addr[3]);
		break;
	default:
		IPACMERR("Unsupported IP type %d\n", data->iptype);
		return -EINVAL;
	}

	IPACM_EvtDispatcher::PostEvt(&evt_data);
	return 0;
}

void IPACM_Lan::HandleNeighIpAddrAddEvt(ipacm_event_data_all *data)
{
	switch (data->iptype)
	{
	case IPA_IP_v4:
		CtList->HandleNeighIpAddrAddEvt(data);
		break;

	case IPA_IP_v6:
	{
		if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
		{
			CtList->HandleNeighIpAddrAddEvt_v6(data);
			break;
		}
	}

	default:
		IPACMERR("Not supported IP type %d", data->iptype);
	}
}

void IPACM_Lan::HandleNeighIpAddrDelEvt(int clt_indx)
{
	uint32_t ipv6_temp[4] = {0};

	if (get_client_memptr(eth_client, clt_indx)->ipv4_set)
	{
		CtList->HandleNeighIpAddrDelEvt(get_client_memptr(eth_client, clt_indx)->v4_addr);
	}

	if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
	{
		for (auto it = rt_hdl_v6_list[clt_indx].begin(); it != rt_hdl_v6_list[clt_indx].end();++it)
		{
			std::copy(std::begin(it->first), std::end(it->first), std::begin(ipv6_temp));
			CtList->HandleNeighIpAddrDelEvt_v6(Ipv6IpAddress(ipv6_temp, false));
		}
	}
}

int IPACM_Lan::construct_mtu_rule(struct ipa_flt_rule *rule, ipa_ip_type iptype, uint16_t mtu)
{
	int fd;
	ipa_ioc_generate_flt_eq flt_eq;

	if (rule == NULL)
	{
		IPACMERR("rule is empty\n");
		return IPACM_FAILURE;
	}

	if (mtu == 0)
	{
		IPACMERR("mtu is uninitialized\n");
		return IPACM_FAILURE;
	}

	if (iptype >= IPA_IP_MAX)
	{
		IPACMERR("invalid iptype\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Constructing MTU rule for iptype = %d\n", iptype);

	rule->eq_attrib_type = 1;
	rule->eq_attrib.rule_eq_bitmap = 0;
	rule->action = IPA_PASS_TO_EXCEPTION;

	/* generate eq */
	memset(&flt_eq, 0, sizeof(flt_eq));
	memcpy(&flt_eq.attrib, &rule->attrib, sizeof(flt_eq.attrib));
	flt_eq.ip = iptype;

	if (rule->attrib.attrib_mask)
	{
		fd = open(IPA_DEVICE_NAME, O_RDWR);
		if (fd < 0)
		{
			IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
			return IPACM_FAILURE;
		}

		if (0 != ioctl(fd, IPA_IOC_GENERATE_FLT_EQ, &flt_eq)) //define and cpy attribute to this struct
		{
			IPACMERR("Failed to get eq_attrib\n");
			close(fd);
			return IPACM_FAILURE;
		}
		close(fd);
		memcpy(&rule->eq_attrib,
			&flt_eq.eq_attrib, sizeof(rule->eq_attrib));
	}

	//add IHL offsets
	rule->eq_attrib.rule_eq_bitmap |= (1<<10);
	rule->eq_attrib.num_ihl_offset_range_16 = 1;
	if (iptype == IPA_IP_v4)
	{
		rule->eq_attrib.ihl_offset_range_16[0].offset = 0x82;
		rule->eq_attrib.ihl_offset_range_16[0].range_low = mtu + 1;
	}
	else
	{
		rule->eq_attrib.ihl_offset_range_16[0].offset = 0x84;
		//v6 uses payload length which doesnt include v6 header
		rule->eq_attrib.ihl_offset_range_16[0].range_low = mtu + 1 - IPV6_HEADER_SIZE;
	}


	rule->eq_attrib.ihl_offset_range_16[0].range_high = UINT16_MAX; //0xFFFF

	return IPACM_SUCCESS;
}

#if defined (FEATURE_IPA_V3) && defined(FEATURE_VLAN_MPDN)
int IPACM_Lan::handle_mpdn_ul_xlat_filter_rule(ipacm_ext_prop * prop,
				ipa_ip_type iptype, int pdn_mux_id, uint16_t vlan_id)
{
	int len = 0, fd, ret = IPACM_SUCCESS;
	ipa_flt_rule_add flt_rule_entry;
	ipa_ioc_add_flt_rule_after *pFilteringTable = NULL;
	ipa_fltr_installed_notif_req_msg_v01 flt_index;
	int i, j, k, cnt, entry_idx = 0, prev =0, curr =0, pos, idx_q6 = 0, idx = 0;
	uint16_t value = 0, mask = 0;
	int xlat_pdn_ctx_id;

	IPACMDBG_H("Set modem UL flt rules for xlat mode in MPDN config with vlan: %d\n", vlan_id);

	if (iptype != IPA_IP_v4 || !modem_ul_v4_set[0])
	{
		IPACMERR("Invalid params\n");
		return IPACM_FAILURE;
	}

	if (rx_prop == NULL)
	{
		IPACMERR("rx/tx properties empty...exit\n");
		return IPACM_FAILURE;
	}

	if(prop == NULL || prop->num_ext_props <= 0)
	{
		IPACMDBG_H("No extended property.\n");
		return IPACM_FAILURE;
	}
	else if (prop->num_ext_props > MAX_WAN_UL_FILTER_RULES)
	{
		IPACMERR("number of modem UL rules > MAX_WAN_UL_FILTER_RULES, aborting...\n");
		return IPACM_FAILURE;
	}

	fd = open(IPA_DEVICE_NAME, O_RDWR);
	if (0 == fd)
	{
		IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
		ret = IPACM_FAILURE;
		goto fail;
	}

	xlat_pdn_ctx_id = get_pdn_xlat_ctx(pdn_mux_id, vlan_id);
	if (xlat_pdn_ctx_id == IPACM_FAILURE)
	{
		IPACMDBG_H("pdn not added in xlat ctx \n");
		ret = IPACM_FAILURE;
		goto fail;
	}


	IPACMDBG_H("Number of - xlat rules : %d \n", prop->num_v4_xlat_props);

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if ( j == 0 ) {
				idx = 0 ;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		memset(&flt_index, 0, sizeof(flt_index));
		if (rx_prop == NULL) {
			IPACMERR("no rx props\n");
			return IPACM_FAILURE;
		}
		flt_index.source_pipe_index = ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, rx_prop->rx[idx].src_pipe);
		flt_index.install_status = IPA_QMI_RESULT_SUCCESS_V01;
		flt_index.rule_id_ex_valid = 1;
		flt_index.rule_id_ex_len = prop->num_v4_xlat_props;
		flt_index.embedded_pipe_index_valid = 1;
		flt_index.embedded_pipe_index = ioctl(fd, IPA_IOC_QUERY_EP_MAPPING, IPA_CLIENT_APPS_LAN_WAN_PROD);
		flt_index.retain_header_valid = 1;
		flt_index.retain_header = 0;
		flt_index.embedded_call_mux_id_valid = 1;
		flt_index.embedded_call_mux_id = pdn_mux_id;

		IPACMDBG_H("flt_index: src pipe: %d, num of rules: %d, ebd pipe: %d, mux id: %d\n",
				   flt_index.source_pipe_index, flt_index.rule_id_ex_len,
				   flt_index.embedded_pipe_index, flt_index.embedded_call_mux_id);

		len = sizeof(struct ipa_ioc_add_flt_rule_after) + prop->num_v4_xlat_props * sizeof(struct ipa_flt_rule_add);
		pFilteringTable = (struct ipa_ioc_add_flt_rule_after *)malloc(len);
		if (pFilteringTable == NULL) {
			IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
			ret = IPACM_FAILURE;
			goto fail;
		}
		memset(pFilteringTable, 0, len);

		pFilteringTable->commit = 1;
		pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
		pFilteringTable->ip = iptype;
		pFilteringTable->num_rules = 0;

		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add)); // Zero All Fields
		flt_rule_entry.at_rear = true;
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;
		flt_rule_entry.rule.retain_hdr = 0;
		flt_rule_entry.rule.to_uc = 0;
		flt_rule_entry.rule.eq_attrib_type = 1;
		flt_rule_entry.rule.action = IPA_PASS_TO_SRC_NAT;
		flt_rule_entry.rule.set_metadata = false;

		IPACMDBG_H("filter rule count :%d\n",
				   IPACM_Iface::ipacmcfg->getFltRuleCount(rx_prop->rx[idx].src_pipe, iptype));

		for (cnt = 0; cnt < prop->num_ext_props; cnt++) {
			if (prop->prop[cnt].is_xlat_rule) {
				memcpy(&flt_rule_entry.rule.eq_attrib,
					   &prop->prop[cnt].eq_attrib,
					   sizeof(prop->prop[cnt].eq_attrib));
				flt_rule_entry.rule.rt_tbl_idx = prop->prop[cnt].rt_tbl_idx;
				flt_rule_entry.rule.hashable = prop->prop[cnt].is_rule_hashable;
				flt_rule_entry.rule.rule_id = prop->prop[cnt].rule_id;
				/* Rule ID of replicate is same as Q6 rule I.D */
				flt_index.rule_id_ex[idx_q6] = prop->prop[cnt].rule_id;

				value = vlan_id;
				flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1 << 9);
				flt_rule_entry.rule.eq_attrib.metadata_meq32_present = 1;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.offset = 0;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.value = (value & 0xFFF) << 16;
				flt_rule_entry.rule.eq_attrib.metadata_meq32.mask = 0x0FFF0000;

				/* start with prev = curr = 0
				 * find smallest q6 rule id greater than current xlat filter's rule id,
				 * commit set of rules formed till now excluding curr rule based on prev pointer
				 * make prev = curr i.e prev stores smallest rule id > max xlat rule id current consecutive set
				 */
				for (; curr < num_wan_ul_fl_rule_v4[j] && curr < MAX_NUM_EXT_PROPS; ++curr) {
					if (xlat_ctx.ul_rule_id_hdl_map[j][curr].rule_id > flt_rule_entry.rule.rule_id) break;
				}

				/* commit consecutive rules with single ioctl */
				if (curr != prev && pFilteringTable->num_rules != 0) {
					/* Starting Q6 rules after private subnet rules and rest maintains serial order
					 * private subnet rule -> 512(pdn2)->513(2)->514(1)->512(pdn1)->513(1)->514(1)->515->516...
					 */
					if (prev == 0) {
						/* add the XLAT rule after the dynamic subnet/MTU rules */
						pFilteringTable->add_after_hdl = private_fl_rule_hdl[j][num_wan_subnet_rules[j] - 1];
						if (!pFilteringTable->add_after_hdl) {
							for (int k = 0; k < MAX_NUM_IP_PASS_MPDN; k++) {
								if (IPACM_Iface::ipacmcfg->ip_pass_mpdn_table[k].valid_entry == true &&
									IPACM_Iface::ipacmcfg->ip_pass_mpdn_table[k].ip_pass_skip_nat == 1) {
									pFilteringTable->add_after_hdl = dft_v4fl_rule_hdl[j][m_ipv4_default_filterting_rules_count[j] - 1];
									IPACMDBG_H("Add after handle 0x%x j %d\n", pFilteringTable->add_after_hdl, j);
									break;
								}
							}
						}
					} else
						pFilteringTable->add_after_hdl = xlat_ctx.ul_rule_id_hdl_map[j][prev - 1].flt_hdl;

					IPACMDBG("Installing after 0x%x\n", pFilteringTable->add_after_hdl);

					if (!pFilteringTable->add_after_hdl) {
						IPACMDBG("Bad add_after_hdl = 0\n");
						ret = IPACM_FAILURE;
						goto fail;
					}

					if (false == m_filtering.AddFilteringRuleAfter(pFilteringTable)) {
						IPACMERR("Error Adding RuleTable to Filtering, aborting...\n");
						ret = IPACM_FAILURE;
						goto fail;
					} else {
						for (i = 0; i < pFilteringTable->num_rules; i++) {
							if (xlat_ctx.active_pdn_list[xlat_pdn_ctx_id].num_wan_mpdn_ul_xlat_fl_rule_v4[j] > MAX_WAN_UL_FILTER_RULES) {
								IPACMERR("Number of rules installed exceeded capacity\n");
								goto fail;
							}

							pos = xlat_ctx.active_pdn_list[xlat_pdn_ctx_id].num_wan_mpdn_ul_xlat_fl_rule_v4[j]++;
							xlat_ctx.active_pdn_list[xlat_pdn_ctx_id].wan_mpdn_ul_xlat_fl_rule_hdl_v4[j][pos] =
								pFilteringTable->rules[i].flt_rule_hdl;
							IPACMDBG("flt rule id %d flt hdl %d\n", pFilteringTable->rules[i].rule.rule_id,
									 xlat_ctx.active_pdn_list[xlat_pdn_ctx_id].wan_mpdn_ul_xlat_fl_rule_hdl_v4[j][pos]);
						}
						IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, iptype, pFilteringTable->num_rules);
					}
					entry_idx = 0;
					pFilteringTable->num_rules = 0;
					prev = curr;
				}

				memcpy(&pFilteringTable->rules[entry_idx], &flt_rule_entry, sizeof(flt_rule_entry));
				pFilteringTable->num_rules++;
				IPACMDBG_H("xlat meta-data is modified for rule: %d index %d metadata : 0x%x rule_id %d\n",
						   cnt, entry_idx, flt_rule_entry.rule.eq_attrib.metadata_meq32.value, flt_index.rule_id_ex[idx_q6]);
				entry_idx++;
				idx_q6++;
			}
		}

		if (pFilteringTable->num_rules != 0) {
			if (prev == 0)
			/* add the XLAT rule after the dynamic subnet/MTU rules */
			{
				pFilteringTable->add_after_hdl = private_fl_rule_hdl[j][num_wan_subnet_rules[j] - 1];
				if (!pFilteringTable->add_after_hdl) {
					for (int k = 0; k < MAX_NUM_IP_PASS_MPDN; k++) {
						if (IPACM_Iface::ipacmcfg->ip_pass_mpdn_table[k].valid_entry == true &&
							IPACM_Iface::ipacmcfg->ip_pass_mpdn_table[k].ip_pass_skip_nat == 1) {
							pFilteringTable->add_after_hdl = dft_v4fl_rule_hdl[j][m_ipv4_default_filterting_rules_count[j] - 1];
							IPACMDBG("Add after handle 0x%x j %d\n", pFilteringTable->add_after_hdl, j);
							break;
						}
					}
				}
			} else pFilteringTable->add_after_hdl = xlat_ctx.ul_rule_id_hdl_map[j][prev - 1].flt_hdl;

			IPACMDBG("Installing after 0x%x\n", pFilteringTable->add_after_hdl);

			if (!pFilteringTable->add_after_hdl) {
				IPACMDBG("Bad add_after_hdl = 0\n");
				ret = IPACM_FAILURE;
				goto fail;
			}

			if (false == m_filtering.AddFilteringRuleAfter(pFilteringTable)) {
				IPACMERR("Error Adding RuleTable to Filtering, aborting...\n");
				ret = IPACM_FAILURE;
				goto fail;
			} else {
				for (i = 0; i < pFilteringTable->num_rules; i++) {
					if (xlat_ctx.active_pdn_list[xlat_pdn_ctx_id].num_wan_mpdn_ul_xlat_fl_rule_v4[j] > MAX_WAN_UL_FILTER_RULES) {
						IPACMERR("Number of rules installed exceeded capacity\n");
						goto fail;
					}
					pos = xlat_ctx.active_pdn_list[xlat_pdn_ctx_id].num_wan_mpdn_ul_xlat_fl_rule_v4[j]++;
					xlat_ctx.active_pdn_list[xlat_pdn_ctx_id].wan_mpdn_ul_xlat_fl_rule_hdl_v4[j][pos] =
						pFilteringTable->rules[i].flt_rule_hdl;
					IPACMDBG("flt rule id %d flt hdl %d\n", pFilteringTable->rules[i].rule.rule_id,
							 xlat_ctx.active_pdn_list[xlat_pdn_ctx_id].wan_mpdn_ul_xlat_fl_rule_hdl_v4[j][pos]);
				}
				IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, iptype, pFilteringTable->num_rules);
			}
		}

		if (false == m_filtering.SendFilteringRuleIndex(&flt_index)) {
			IPACMERR("Error sending filtering rule index, aborting...\n");
			ret = IPACM_FAILURE;
			goto fail;
		}

		if (pFilteringTable != NULL)
		{
			free(pFilteringTable);
			pFilteringTable = NULL;
		}
	}

fail:
	if (pFilteringTable != NULL)
		free(pFilteringTable);
	close(fd);
	return ret;
}

int IPACM_Lan::delete_mdpn_ul_xlat_filter_rule(int mux_id)
{
	int j, ret = IPACM_SUCCESS, xlat_pdn_ctx_id, idx = 0;

	xlat_pdn_ctx_id = get_pdn_xlat_ctx(mux_id, 0);
	if (xlat_pdn_ctx_id == IPACM_FAILURE)
	{
		IPACMERR("pdn not found in xlat ctx \n");
		return IPACM_FAILURE;
	}

	if(rx_prop == NULL)
	{
		IPACMERR("no rx props\n");
		return IPACM_FAILURE;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++)
	{
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		if (xlat_ctx.active_pdn_list[xlat_pdn_ctx_id].num_wan_mpdn_ul_xlat_fl_rule_v4[j] == 0)
		{
			if (xlat_ctx.active_pdn_list[xlat_pdn_ctx_id].num_wan_mpdn_ul_xlat_fl_rule_v4[j] == 0)
			{
				IPACMERR("No modem mpdn UL xlat rules were installed \n");
			}
			IPACMDBG_H("Deleted xlat mpdn rules for pdn mux : %d\n", mux_id);

			if(rx_prop == NULL){
				IPACMERR("no rx props\n");
				return IPACM_FAILURE;
			}
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4,
					xlat_ctx.active_pdn_list[xlat_pdn_ctx_id].num_wan_mpdn_ul_xlat_fl_rule_v4[j]);
			memset(xlat_ctx.active_pdn_list[xlat_pdn_ctx_id].wan_mpdn_ul_xlat_fl_rule_hdl_v4[j],
					0, MAX_WAN_UL_FILTER_RULES*sizeof(uint32_t));
			xlat_ctx.active_pdn_list[xlat_pdn_ctx_id].num_wan_mpdn_ul_xlat_fl_rule_v4[j] = 0;
		}
	}

fail:
	return ret;
}

#endif

int IPACM_Lan::delete_icmp_filter_rule(
	ipa_ip_type iptype )
{
	int idx = 0;
	int j = 0;
	if ( ! VALID_IPA_IP_TYPE(iptype) )
	{
		IPACMERR("Bad iptype(%u)\n", iptype);
		return IPACM_FAILURE;
	}

	if(rx_prop == NULL){
		IPACMERR("no rx props\n");
		return IPACM_FAILURE;
	}

	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++) {
		/* Easymesh vlan/svap pipe condition need to install for in 2nd handle in array  and idx 2*/
		if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
			if (j != 1) {
				IPACMDBG_H("Interface is WLAN Svap or w-vlan, dont install rules on pipe %d..... continue\n", idx);
				continue;
			} else {
				idx = 2;
				IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx1 pipe at idx %d \n", idx);
			} /* Easymesh Not Vlan pipe condition need to install for 1st handle of array and idx 0 */
		} else if ((ipa_if_cate == WLAN_IF) && (rx_prop->num_rx_props > 2)){
			if (j == 0) {
				idx = 0;
			} else {
				IPACMDBG_H("Interface is non vlan, dont install rule with index 2\n");
				continue;
			}
		} else {
			idx = j * 2;
			IPACMDBG_H("Install rules at idx %d\n", idx);
		}

		if (iptype == IPA_IP_v4) {
			if (ipv4_icmp_flt_rule_hdl[j][0]) {
				IPACMDBG_H("Attempting to delete v4 icmp filter rule.\n");

				if (m_filtering.DeleteFilteringHdls(
						ipv4_icmp_flt_rule_hdl[j], IPA_IP_v4, NUM_IPV4_ICMP_FLT_RULE) == true) {
					IPACMDBG_H("Deleted v4 icmp filter rule successfully.\n");
					IPACM_Iface::ipacmcfg->decreaseFltRuleCount(
						rx_prop->rx[idx].src_pipe, IPA_IP_v4, NUM_IPV4_ICMP_FLT_RULE);
					memset(
						ipv4_icmp_flt_rule_hdl[j],
						0,
						sizeof(uint32_t) * NUM_IPV4_ICMP_FLT_RULE);
				} else {
					IPACMERR("Error deleting v4 icmp filter rule...\n");
					return IPACM_FAILURE;
				}
			}
		} else { /* iptype == IPA_IP_v6 */
			if (ipv6_icmp_flt_rule_hdl[j][0]) {
				IPACMDBG_H("Attempting to delete v6 icmp filter rule.\n");

				if (m_filtering.DeleteFilteringHdls(
						ipv6_icmp_flt_rule_hdl[j], IPA_IP_v6, NUM_IPV6_ICMP_FLT_RULE) == true) {
					IPACMDBG_H("Deleted v6 icmp filter rule successfully.\n");
					IPACM_Iface::ipacmcfg->decreaseFltRuleCount(
						rx_prop->rx[idx].src_pipe, IPA_IP_v6, NUM_IPV6_ICMP_FLT_RULE);
					memset(
						ipv6_icmp_flt_rule_hdl[j],
						0,
						sizeof(uint32_t) * NUM_IPV6_ICMP_FLT_RULE);
				} else {
					IPACMERR("Error deleting v6 icmp filter rule...\n");
					return IPACM_FAILURE;
				}
			}
		}
	}

	return IPACM_SUCCESS;
}

#ifdef FEATURE_EoGRE

void IPACM_Lan::eogre_up()
{
	ipa_ipgre_info ipgre_info = IPACM_Iface::ipacmcfg->eogre_info;
	ipa_ip_type    iptype     = ipgre_info.iptype;
	int            ret, fd;

	IPACMDBG_H(
		"There's eogre enable work to be done for iptype(%d)\n",
		iptype);

	// REMINDER: The logic below needs to be tested with more than
	// one wan instance...

	uint8_t muxid = IPACM_Iface::ipacmcfg->GetQmapId();

	if ( muxid == 0xFF )
	{
		if ( ipgre_info.iptype == IPA_IP_v4 )
		{
			ret = IPACM_Wan::GetMuxByAddr(IPA_IP_v4, &ipgre_info.ipv4_src, muxid);
		}
		else
		{
			ret = IPACM_Wan::GetMuxByAddr(IPA_IP_v6, &ipgre_info.ipv6_src, muxid);
		}

		if ( ret == IPACM_SUCCESS )
		{
			IPACM_Iface::ipacmcfg->SetQmapId(muxid);
		}
		else
		{
			IPACMERR("GetMuxByAddr did not succeed.\n");
			return;
		}
	}

	IPACMDBG_H("The eogre backhaul is using muxid(%u)\n", muxid);

	if ( rx_prop != NULL )
	{
		/*
		 * Give mux ID of the default PDN to IPA-driver for WLAN/LAN
		 * pkts
		 */
		struct ipa_ioc_write_qmapid mux;

		fd = open(IPA_DEVICE_NAME, O_RDWR);

		if (fd < 0)
		{
			IPACMDBG_H("Failed opening %s.\n", IPA_DEVICE_NAME);
			return;
		}

		memset(&mux, 0, sizeof(mux));

		mux.qmap_id = muxid;
		mux.client  = rx_prop->rx[0].src_pipe;

		IPACMDBG_H(
			"Issuing IPA_IOC_WRITE_QMAPID ioctl -> "
			"mux.qmap_id(%u) mux.client(%u)\n",
			mux.qmap_id,
			mux.client);

		ret = ioctl(fd, IPA_IOC_WRITE_QMAPID, &mux);

		close(fd);

		if ( ret )
		{
			IPACMERR("Failed to write mux id %d\n", mux.qmap_id);
			return;
		}
	}

	/*
	 * Create eogre specific route rules...
	 */
	IPACMDBG_H(
		"Adding eogre specific route rules for iptype(%d)\n",
		iptype);

	if ( eogre_do_rt_work(ipgre_info) != IPACM_SUCCESS )
	{
		IPACMERR("eogre_do_rt_work failed\n");
		return;
	}

	/*
	 * In an attempt to get symmetric message flow for exception
	 * rules, the following will ensure some rules are deleted to aid
	 * in this effort.
	 */
	if ( IPACM_Iface::ip_type == IPA_IP_v4 || IPACM_Iface::ip_type == IPA_IP_MAX )
	{
		/*
		 * Will delete all exception rules.
		 */
		if ( delete_dflt_filter_rules(IPA_IP_v4) == IPACM_FAILURE )
		{
			IPACMERR("delete_dflt_filter_rules failed\n");
			return;
		}
		/*
		 * The following will install only the frag rule given eogre
		 * state.
		 */
		if ( init_fl_rule(IPA_IP_v4, true) == IPACM_FAILURE )
		{
			IPACMERR("init_fl_rule failed\n");
			return;
		}
	}

	if ( IPACM_Iface::ip_type == IPA_IP_v6 || IPACM_Iface::ip_type == IPA_IP_MAX )
	{
		/*
		 * Intentionally leaving icmp..
		 *
		 * But, will delete all exception rules.
		 */
		if ( delete_dflt_filter_rules(IPA_IP_v6) == IPACM_FAILURE )
		{
			IPACMERR("delete_dflt_filter_rules failed\n");
			return;
		}
		/*
		 * The following will install only the frag rule given eogre
		 * state.
		 */
		if ( init_fl_rule(IPA_IP_v6, true) == IPACM_FAILURE )
		{
			IPACMERR("init_fl_rule failed\n");
			return;
		}
	}

	/*
	 * Since we're doing eogre, we need to embellish existing
	 * rules to support eogre. The following does this...
	 */
	IPACMDBG_H(
		"Embellishing existing filter rules for eogre iptype(%d)\n",
		iptype);

#ifdef FEATURE_VLAN_MPDN
	handle_uplink_filter_rule(
		IPACM_Iface::ipacmcfg->GetExtProp(iptype),
		iptype,
		IPACM_Iface::ipacmcfg->GetQmapId(),
		false,
		false);
#else
	handle_uplink_filter_rule(
		IPACM_Iface::ipacmcfg->GetExtProp(iptype),
		iptype,
		IPACM_Iface::ipacmcfg->GetQmapId());
#endif
	/*
	 * Need to add the one final rule, which is the eogre catchup
	 * rule...
	 */
	if ( eogre_add_catchup_rule(iptype) != 0 )
	{
		IPACMERR("eogre_add_catchup_rule failed\n");
		return;
	}

	//need to add mtu rules when eogre is enabled
	modify_private_subnet(true);
#ifdef FEATURE_VLAN_MPDN
	modify_ipv6_prefix_flt_rule(true);
#else
	delete_ipv6_prefix_flt_rule();
	install_ipv6_prefix_flt_rule(IPACM_Wan::backhaul_ipv6_prefix);
#endif

	IPACMDBG("Finished handling eogre_up\n");
}

void IPACM_Lan::eogre_down()
{
	ipa_ipgre_info ipgre_info = IPACM_Iface::ipacmcfg->eogre_info;
	ipa_ip_type    iptype     = ipgre_info.iptype;
	int            res;
	int j = 0;

	if((iptype != IPA_IP_v4) && (iptype != IPA_IP_v6))
	{
		IPACMDBG("Invalid ip type is passed\n");
		return;
	}

	IPACMDBG_H(
		"There's eogre disable work to be done for iptype(%d)\n",
		iptype);

	IPACMDBG_H(
		"Clearing route rules for eogre iptype(%d)\n",
		iptype);

	if (rx_prop == NULL)
	{
		IPACMERR("rx/tx properties empty...exit\n");
		return;
	}

	eogre_clear_route_data(IPA_IP_v4, rx_prop);
	eogre_clear_route_data(IPA_IP_v6, rx_prop);

	IPACMDBG_H(
		"Clearing filter rules for eogre iptype(%d)\n",
		iptype);

	del_ul_flt_rules(iptype);

	if ( IPACM_Iface::ip_type == IPA_IP_v4 || IPACM_Iface::ip_type == IPA_IP_MAX )
	{
		/*
		 * Will delete any installed exception rules.
		 */
		if ( delete_dflt_filter_rules(IPA_IP_v4) == IPACM_FAILURE )
		{
			IPACMERR("delete_dflt_filter_rules failed\n");
			return;
		}
		/*
		 * The icmp rule was removed on eogre_up; needs to be added
		 * back now.
		 */
		res = install_ipv4_icmp_flt_rule();
		if ( res == IPACM_FAILURE )
		{
			IPACMERR("install_ipv4_icmp_flt_rule failed\n");
			return;
		}
		/*
		 * Will reinstall the exception rules.
		 */
		if ( init_fl_rule(IPA_IP_v4, false) == IPACM_FAILURE )
		{
			IPACMERR("init_fl_rule failed\n");
			return;
		}
	}

	if ( IPACM_Iface::ip_type == IPA_IP_v6 || IPACM_Iface::ip_type == IPA_IP_MAX )
	{
		/*
		 * Will delete any installed exception rules.
		 */
		if ( delete_dflt_filter_rules(IPA_IP_v6) == IPACM_FAILURE )
		{
			IPACMERR("delete_dflt_filter_rules failed\n");
			return;
		}
		/*
		 * Will reinstall the exception rules.
		 */
		if ( init_fl_rule(IPA_IP_v6, false) == IPACM_FAILURE )
		{
			IPACMERR("init_fl_rule failed\n");
			return;
		}
	}


	for (j = 0; j < rx_prop->num_rx_props / 2 && j < IPA_MAX_NUM_PROPS; j++)
	{
		if (j > 2 && !sIface) {
			IPACMDBG_H("Iface is not Special iface, no need to install rules on 2nd rx pipe\n", num_dft_rt_v6);
			continue;
		}
		/*
		 * Below we'll do two things:
		 *
		 *  1) Populate the flt rule offset for eth bridge (offset = icmp)
		 *
		 *  2) Populate the flt rule offset for mtu_offset (offset = broadcast rule)
		 */
		if (iptype == IPA_IP_v4)
		{
			eth_bridge_flt_rule_offset[j][iptype] =
				ipv4_icmp_flt_rule_hdl[j][0];

			if (m_ipv4_default_filterting_rules_count[j])
			{
				mtu_flt_rule_offset[j][iptype] =
					dft_v4fl_rule_hdl[j][m_ipv4_default_filterting_rules_count[j] - 1];
			}
			IPACMDBG(
				"Prepping for modify_private_subnet(): "
				"eth_bridge_flt_rule_offset[v4]=%u, "
				"m_ipv4_default_filterting_rules_count=%u "
				"mtu_flt_rule_offset[v4]=%u\n",
				eth_bridge_flt_rule_offset[j][iptype],
				m_ipv4_default_filterting_rules_count[j],
				mtu_flt_rule_offset[j][iptype]);
		} else {
			eth_bridge_flt_rule_offset[j][iptype] =
				ipv6_icmp_flt_rule_hdl[j][0];

			if (m_ipv6_default_filterting_rules_count[j])
			{
				mtu_flt_rule_offset[j][iptype] =
					dft_v6fl_rule_hdl[j][m_ipv6_default_filterting_rules_count[j] - 1];
			}
			IPACMDBG(
				"Prepping for modify_private_subnet(): "
				"eth_bridge_flt_rule_offset[v6]=%u, "
				"m_ipv6_default_filterting_rules_count=%u "
				"mtu_flt_rule_offset[v6]=%u\n",
				eth_bridge_flt_rule_offset[j][iptype],
				m_ipv6_default_filterting_rules_count[j],
				mtu_flt_rule_offset[j][iptype]);
		}
	}

	IPACM_Iface::ipacmcfg->SetQmapId(0xFF);

	//need to clean mtu rules when eogre is disabled
	modify_private_subnet();
#ifdef FEATURE_VLAN_MPDN
	modify_ipv6_prefix_flt_rule();
#else
	delete_ipv6_prefix_flt_rule();
	install_ipv6_prefix_flt_rule(IPACM_Wan::backhaul_ipv6_prefix);
#endif

	IPACMDBG("finished handling eogre_down\n");
}

int IPACM_Lan::eogre_do_rt_work(
	ipa_ipgre_info& ipgre_info )
{
	enum ipa_ip_type iptype = ipgre_info.iptype;

	IPACMDBG_H(
		"Attempting to create compatible eogre routing info for ip-type: %d\n",
		iptype);

	if ( eogre_make_hdr_for_add_ctx(ipgre_info)    != 0 ||
		 eogre_make_hdr_add_ctx(ipgre_info)        != 0 ||
		 eogre_make_hdr_rem_ctx(ipgre_info)        != 0 ||
		 eogre_make_header_add_rt_rule(ipgre_info) != 0 ||
		 eogre_make_header_rem_rt_rule(ipgre_info) != 0 )
	{
		IPACMERR("Failed to create and/or add eogre data and rules\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H(
		"Finished creating compatible eogre routing info for ip-type: %d\n",
		iptype);

	/*
	 * The following test is because eogre is enabled, but we
	 * don't know what the iptype will be of the Eth/Vlan
	 * encapsulated IP packets. A clue as to what the encapsulated
	 * iptype might be can be indicated by which wan interfaces
	 * is/are up; if both are, then the encapsulated packet's
	 * iptype might be v4 or v6.  To be safe, and to prepare for
	 * the tunnel's type being different, let's add another route
	 * entry in the complimentary route table.  In other words,
	 * and just to be sure, we'll prepare as if they will differ.
	 */
	if ( IPACM_Iface::ip_type == IPA_IP_MAX )
	{
		/*
		 * Both interfaces are up, so...
		 */
		uint32_t hdr = eogre_route_data[iptype].header_hdl;

		ipa_ipgre_info copy = ipgre_info;

		/*
		 * Invert the type to be the complimentary one...
		 */
		copy.iptype = iptype =
			(ipgre_info.iptype == IPA_IP_v4) ? IPA_IP_v6 : IPA_IP_v4;

		IPACMDBG_H(
			"Attempting to create complimentary eogre routing info for ip-type: %d\n",
			iptype);

		if ( eogre_make_hdr_add_ctx(copy, hdr)   != 0 ||
			 eogre_make_header_add_rt_rule(copy) != 0 )
		{
			IPACMERR("Failed to create complimentary eogre rule\n");
			return IPACM_FAILURE;
		}

		IPACMDBG_H(
			"Finished creating complimentary eogre routing info for ip-type: %d\n",
			iptype);
	}

	return IPACM_SUCCESS;
}

int IPACM_Lan::eogre_add_catchup_rule(
	enum ipa_ip_type iptype )
{
	if ( ! VALID_IPA_IP_TYPE(iptype) )
	{
		IPACMERR("Invalid IP type passed to function\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H(
		"Attempting to add eogre catchup rule for iptype(%d)\n",
		iptype);

	static const int NUM_RULES = 1;

	uint8_t buf[
		sizeof(ipa_ioc_add_flt_rule) +
		(NUM_RULES * sizeof(ipa_flt_rule_add)) ];

	memset(buf, 0, sizeof(buf));

	ipa_ioc_add_flt_rule* pFilteringTable =
		(ipa_ioc_add_flt_rule*) buf;

	pFilteringTable->commit    = 1;
	pFilteringTable->ep        = rx_prop->rx[0].src_pipe;
	pFilteringTable->global    = false;
	pFilteringTable->ip        = iptype;
	pFilteringTable->num_rules = NUM_RULES;

	ipa_flt_rule_add flt_rule_entry;

	memset(&flt_rule_entry, 0, sizeof(flt_rule_entry));

	flt_rule_entry.at_rear                  = true;
	flt_rule_entry.flt_rule_hdl             = -1;
	flt_rule_entry.status                   = -1;

	flt_rule_entry.rule.retain_hdr          = 1;
	flt_rule_entry.rule.to_uc               = 1;
	flt_rule_entry.rule.action              = IPA_PASS_TO_ROUTING;
	flt_rule_entry.rule.rt_tbl_hdl          = eogre_get_rt_tbl_hdl(iptype);
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;

#ifdef FEATURE_IPA_V3
	flt_rule_entry.rule.hashable = true;
#endif

	memcpy(pFilteringTable->rules,
		   &flt_rule_entry,
		   sizeof(flt_rule_entry));

	/*
	 * The following test will be to see if we need to call
	 * update_complementary_table() (ie. add a rule to the
	 * opposite/complimentary table).  We'll do this when both the
	 * v4 and v6 interfaces are up.  When they are, there's a
	 * possibility that the eogre requested tunnel type
	 * (ie. ipgre_info.iptype) and the iptype of the Eth/Vlan
	 * encapsulated IP packet might differ.
	 */
	if ( IPACM_Iface::ip_type == IPA_IP_MAX )
	{
		/*
		 * Both interfaces up. Let's prepare the other
		 * table.
		 */
		ipa_ip_type other = (iptype == IPA_IP_v4) ? IPA_IP_v6 : IPA_IP_v4;

		int ret = update_complementary_table(flt_rule_entry, other);

		if ( ret != IPACM_SUCCESS )
		{
			return ret;
		}
	}

	if ( m_filtering.AddFilteringRule(pFilteringTable) == false )
	{
		IPACMERR("Error adding catchup rul\n");
		return IPACM_FAILURE;
	}

	/*
	 * Save handle for subsequent cleanup.
	 */
	eogre_route_data[iptype].flt_eogre_1st_pass_hdl =
		pFilteringTable->rules[0].flt_rule_hdl;

	IPACM_Iface::ipacmcfg->increaseFltRuleCount(
		rx_prop->rx[0].src_pipe, iptype, 1);

	return IPACM_SUCCESS;
}

int IPACM_Lan::update_complementary_table(
	ipa_flt_rule_add& flt_rule_entry,
	ipa_ip_type       iptype )
{
	if ( rx_prop != NULL )
	{
		if ( eogre_route_data[iptype].flt_eogre_1st_pass_hdl )
		{
			IPACMDBG_H(
				"Rule already added to table of complementary iptype(%d)\n",
				iptype);

			return IPACM_SUCCESS;
		}

		/*
		 * Delete the table before we add our rule..
		 */
		del_ul_flt_rules(iptype);

		const int NUM_RULES = 1;

		IPACMDBG_H(
			"Will add same rule to table of complementary iptype(%d)\n",
			iptype);

		uint8_t buf[
			sizeof(struct ipa_ioc_add_flt_rule) +
			(NUM_RULES * sizeof(struct ipa_flt_rule_add)) ];

		memset(buf, 0, sizeof(buf));

		struct ipa_ioc_add_flt_rule* flt_rule =
			(struct ipa_ioc_add_flt_rule *) buf;

		flt_rule->commit    = 1;
		flt_rule->ep        = rx_prop->rx[0].src_pipe;
		flt_rule->global    = false;
		flt_rule->ip        = iptype;
		flt_rule->num_rules = NUM_RULES;

		memcpy(
			&(flt_rule->rules[0]),
			&flt_rule_entry,
			sizeof(ipa_flt_rule_add));

		flt_rule->rules[0].rule.rt_tbl_hdl = eogre_get_rt_tbl_hdl(iptype);

		if ( m_filtering.AddFilteringRule(flt_rule) == true )
		{
			IPACMDBG_H(
				"Rule added to table of complementary iptype(%d)\n",
				iptype);

			IPACM_Iface::ipacmcfg->increaseFltRuleCount(
				rx_prop->rx[0].src_pipe, iptype, 1);

			/*
			 * Save handle for subsequent cleanup.
			 */
			eogre_route_data[iptype].flt_eogre_1st_pass_hdl =
				flt_rule->rules[0].flt_rule_hdl;
		}
		else
		{
			IPACMERR("Error Adding Filtering rule, aborting...\n");
			return IPACM_FAILURE;
		}
	}

	return IPACM_SUCCESS;
}

void IPACM_Lan::eogre_route_data_init(
	enum ipa_ip_type iptype )
{
	if ( ! VALID_IPA_IP_TYPE(iptype) )
	{
		IPACMERR("Invalid IP type passed to function\n");
		return;
	}

	memset(&(eogre_route_data[iptype]),
		   0,
		   sizeof(eogre_route_data_t));
}

uint32_t IPACM_Lan::eogre_get_rt_tbl_hdl(
	enum ipa_ip_type iptype )
{
	if ( ! VALID_IPA_IP_TYPE(iptype) )
	{
		IPACMERR("Invalid IP type passed to function\n");
		return 0;
	}

	if ( eogre_route_data[iptype].rt_tbl_hdl == 0 )
	{
		struct ipa_ioc_get_rt_tbl routing_table;

		memset(&routing_table, 0, sizeof(routing_table));

		routing_table.ip = iptype;

		snprintf(
			routing_table.name,
			sizeof(routing_table.name),
			"%s",
			( iptype == IPA_IP_v4 )                   ?
			IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name :
			IPACM_Iface::ipacmcfg->rt_tbl_v6.name);

		IPACMDBG_H(
			"Attempting to get routing table(%s) handle for eogre iptype(%d)\n",
			routing_table.name,
			iptype);

		if ( m_routing.GetRoutingTable(&routing_table) == true )
		{
			IPACMDBG_H(
				"The routing table(%s) handle(%d) successfully retrieved for eogre iptype(%d)\n",
				routing_table.name,
				routing_table.hdl,
				iptype);

			eogre_route_data[iptype].rt_tbl_hdl = routing_table.hdl;
		}
		else
		{
			IPACMERR("GetRoutingTable failed\n");
		}
	}

	return eogre_route_data[iptype].rt_tbl_hdl;
}

int IPACM_Lan::eogre_make_hdr_for_add_ctx(
	ipa_ipgre_info& ipgre_info )
{
	enum ipa_ip_type iptype = ipgre_info.iptype;

	IPACMDBG_H(
		"Attempting to create iptype(%d) context header for eogre routing\n",
		iptype);

	/*
	 * Create, the add, header for "header add" proc_ctx...
	 */
	const uint8_t v4_header[] = {
		0x45, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x40, 0x00,
		0x3f, 0x2f, 0x00, 0x00, // 0x2f Protocol (Generic Routing Encapsulation)
		0x00, 0x00, 0x00, 0x00, // src address here
		0x00, 0x00, 0x00, 0x00, // dest address here
		// GRE header here
		0x00, 0x00, 0x00, 0x00
	};

	const uint8_t v6_header[] = {
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x3c, 0x40, // 0x3c Protocol (destination option) hop limit to 64
		0x00, 0x00, 0x00, 0x00, // src address here
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // dest address here
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		// options header
		0x2f, 0x00, 0x04, 0x01,
		0x04, 0x01, 0x01, 0x00,
		// GRE header here
		0x00, 0x00, 0x00, 0x00
	};

	const uint8_t v6_eogre_header[] = {
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x2f, 0x40, // 0x2f Protocol (Generic Routing Encapsulation)
		0x00, 0x00, 0x00, 0x00, // src address here
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // dest address here
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		// GRE header here
		0x00, 0x00, 0x00, 0x00
	};

	uint8_t  hdr_data_buf[64];
	uint32_t hdr_data_len;

	char addr_buf[128];

	if ( iptype == IPA_IP_v4 )
	{
		v4_gre_hdr_t* hdr = (v4_gre_hdr_t*) hdr_data_buf;

		memcpy(hdr_data_buf, v4_header, sizeof(v4_header));

		hdr->words[IPV4_GRE_PROT_IDX] = htonl(ipgre_info.gre_protocol);

		hdr->words[IPV4_SRC_ADDR_IDX] = ipgre_info.ipv4_src;
		hdr->words[IPV4_DST_ADDR_IDX] = ipgre_info.ipv4_dst;

		addr2network(iptype, &(hdr->words[IPV4_SRC_ADDR_IDX]));
		addr2network(iptype, &(hdr->words[IPV4_DST_ADDR_IDX]));

		IPACM_LOG_IP_ADDR(
			"The src addr added to eogre header template:",
			iptype,
			&(hdr->words[IPV4_SRC_ADDR_IDX]));

		IPACM_LOG_IP_ADDR(
			"The dst addr added to eogre header template:",
			iptype,
			&(hdr->words[IPV4_DST_ADDR_IDX]));

		hdr_data_len = sizeof(v4_gre_hdr_t);
		IPACMDBG_H("Sending to uC, v4 header length : %d\n", hdr_data_len);
	}
	else /*iptype == IPA_IP_v6*/
	{
		if (IPACM_Iface::ipacmcfg->v6options_enabled == true)
		{
			v6_gre_hdr_t* hdr = (v6_gre_hdr_t*) hdr_data_buf;

			memcpy(hdr_data_buf, v6_header, sizeof(v6_header));

			hdr->words[IPV6_GRE_PROT_IDX] = htonl(ipgre_info.gre_protocol);

			memcpy(&(hdr->words[IPV6_SRC_ADDR_IDX]),
				&ipgre_info.ipv6_src,
				sizeof(ipgre_info.ipv6_src));

			memcpy(&(hdr->words[IPV6_DST_ADDR_IDX]),
				&ipgre_info.ipv6_dst,
				sizeof(ipgre_info.ipv6_dst));

			addr2network(iptype, &(hdr->words[IPV6_SRC_ADDR_IDX]));
			addr2network(iptype, &(hdr->words[IPV6_DST_ADDR_IDX]));

			IPACM_LOG_IP_ADDR(
				"The src addr added to eogre header template:",
				iptype,
				&(hdr->words[IPV6_SRC_ADDR_IDX]));

			IPACM_LOG_IP_ADDR(
				"The dst addr added to eogre header template:",
				iptype,
				&(hdr->words[IPV6_DST_ADDR_IDX]));

			hdr_data_len = sizeof(v6_gre_hdr_t);
			IPACMDBG_H("Sending to uC, v6 header length with options: %d\n",
								hdr_data_len);
		}
		else
		{
			v6_eogre_hdr_t* hdr = (v6_eogre_hdr_t*) hdr_data_buf;

			memcpy(hdr_data_buf, v6_eogre_header, sizeof(v6_eogre_header));

			hdr->words[IPV6_GRE_PROT] = htonl(ipgre_info.gre_protocol);

			memcpy(&(hdr->words[IPV6_SRC_ADDR_IDX]),
				&ipgre_info.ipv6_src,
				sizeof(ipgre_info.ipv6_src));

			memcpy(&(hdr->words[IPV6_DST_ADDR_IDX]),
				&ipgre_info.ipv6_dst,
				sizeof(ipgre_info.ipv6_dst));

			addr2network(iptype, &(hdr->words[IPV6_SRC_ADDR_IDX]));
			addr2network(iptype, &(hdr->words[IPV6_DST_ADDR_IDX]));

			IPACM_LOG_IP_ADDR(
				"The src addr added to eogre header template:",
				iptype,
				&(hdr->words[IPV6_SRC_ADDR_IDX]));

			IPACM_LOG_IP_ADDR(
				"The dst addr added to eogre header template:",
				iptype,
				&(hdr->words[IPV6_DST_ADDR_IDX]));

			hdr_data_len = sizeof(v6_eogre_hdr_t);
			IPACMDBG_H("Sending to uC, v6 header length without options: %d\n",
								hdr_data_len);
		}
	}

	/*
	 * Add the header...
	 */
	static const int NUM_OF_HEADERS = 1;

	uint8_t buf[
		sizeof(struct ipa_ioc_add_hdr) +
		(NUM_OF_HEADERS * sizeof(struct ipa_hdr_add)) ];

	memset(buf, 0, sizeof(buf));

	struct ipa_ioc_add_hdr *hdrTable =
		(struct ipa_ioc_add_hdr *) buf;

	struct ipa_hdr_add *hdr = &(hdrTable->hdr[0]);

	// init hdr table
	hdrTable->commit   = true;
	hdrTable->num_hdrs = NUM_OF_HEADERS;

	// init the hdr common fields
	hdr->is_partial = false;
	hdr->hdr_hdl    = -1; // Return Value
	hdr->status     = -1; // Return Parameter

	snprintf(
		hdr->name,
		sizeof(hdr->name),
		IPA_EOGRE_HDR_NAME,
		( iptype == IPA_IP_v4 ) ? 4 : 6);

	hdr->type    = IPA_HDR_L2_802_1Q;
	hdr->hdr_len = hdr_data_len;

	memcpy(hdr->hdr, hdr_data_buf, hdr->hdr_len);

	if ( m_header.AddHeader(hdrTable) && hdr->status == 0 )
	{
		IPACMDBG_H(
			"Successfully added %d bytes for IP/eogre header %s\n",
			hdr->hdr_len,
			hdr->name);
		eogre_route_data[iptype].header_hdl = hdr->hdr_hdl;
	}
	else
	{
		IPACMERR("AddHeader failed: %d\n", hdr->status);
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

int IPACM_Lan::eogre_make_hdr_add_ctx(
	ipa_ipgre_info& ipgre_info,
	uint32_t        hdr_2use )
{
	enum ipa_ip_type iptype = ipgre_info.iptype;

	IPACMDBG_H(
		"Attempting to create iptype(%d) \"header add\" context for eogre routing\n",
		iptype);

	hdr_2use = (hdr_2use) ? hdr_2use : eogre_route_data[iptype].header_hdl;

	if ( hdr_2use == 0 )
	{
		IPACMERR("Can't create \"header add\" context without creating header first.\n");
		return IPACM_FAILURE;
	}

	/*
	 * Make "header add" process context...
	 */
	static const int NUM_OF_PROC_CTX = 1;

	uint8_t buf[
		sizeof(struct ipa_ioc_add_hdr_proc_ctx) +
		(NUM_OF_PROC_CTX * sizeof(struct ipa_hdr_proc_ctx_add)) ];

	memset(buf, 0, sizeof(buf));

	struct ipa_ioc_add_hdr_proc_ctx *procCtxTable =
		(struct ipa_ioc_add_hdr_proc_ctx *) buf;

	struct ipa_hdr_proc_ctx_add *procCtx = &(procCtxTable->proc_ctx[0]);

	// init proc ctx table
	procCtxTable->commit        = true;
	procCtxTable->num_proc_ctxs = NUM_OF_PROC_CTX;

	// init proc_ctx common fields
	procCtx->proc_ctx_hdl = -1; // return value
	procCtx->status       = -1; // Return parameter
	procCtx->type         = IPA_HDR_PROC_EoGRE_HEADER_ADD;
	procCtx->hdr_hdl      = hdr_2use;
	procCtx->eogre_params.hdr_add_param.eth_hdr_retained = 1;
	procCtx->eogre_params.hdr_add_param.input_ip_version = iptype;
	procCtx->eogre_params.hdr_add_param.output_ip_version =
		IPACM_Iface::ipacmcfg->eogre_info.iptype;
	procCtx->eogre_params.hdr_add_param.second_pass = 1;

	if ( m_header.AddHeaderProcCtx(procCtxTable) == true )
	{
		IPACMDBG_H(
			"EoGRE header context successfully installed\n");

		eogre_route_data[iptype].proc_ctx_eogre_add_hdl =
			procCtx->proc_ctx_hdl;
	}
	else
	{
		IPACMERR("AddHeaderProcCtx failed\n");
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

int IPACM_Lan::eogre_make_hdr_rem_ctx(
	ipa_ipgre_info& ipgre_info )
{
	enum ipa_ip_type iptype = ipgre_info.iptype;

	IPACMDBG_H(
		"Attempting to create iptype(%d) \"header remove\" context for eogre routing\n",
		iptype);

	/*
	 * Make "header remove" process context...
	 */
	static const int NUM_OF_PROC_CTX = 1;

	uint8_t buf[
		sizeof(struct ipa_ioc_add_hdr_proc_ctx) +
		(NUM_OF_PROC_CTX * sizeof(struct ipa_hdr_proc_ctx_add)) ];

	memset(buf, 0, sizeof(buf));

	struct ipa_ioc_add_hdr_proc_ctx *procCtxTable =
		(struct ipa_ioc_add_hdr_proc_ctx *) buf;

	struct ipa_hdr_proc_ctx_add *procCtx = &(procCtxTable->proc_ctx[0]);

	// init proc ctx table
	procCtxTable->commit        = true;
	procCtxTable->num_proc_ctxs = NUM_OF_PROC_CTX;

	// init proc_ctx common fields
	procCtx->proc_ctx_hdl = -1; // return value
	procCtx->status       = -1; // Return parameter
	procCtx->type         = IPA_HDR_PROC_EoGRE_HEADER_REMOVE;
	procCtx->eogre_params.hdr_remove_param.hdr_len_remove =
		( iptype == IPA_IP_v4 ) ? sizeof(v4_gre_hdr_t) :
		(IPACM_Iface::ipacmcfg->v6options_enabled == true) ? sizeof(v6_gre_hdr_t) :
							sizeof(v6_eogre_hdr_t);
		IPACMDBG_H("Sending to uC, Remove header length :c%d\n",
				procCtx->eogre_params.hdr_remove_param.hdr_len_remove);

	if ( m_header.AddHeaderProcCtx(procCtxTable) == true )
	{
		IPACMDBG_H(
			"EoGRE header context successfully installed\n");

		eogre_route_data[iptype].proc_ctx_eogre_rmv_hdl =
			procCtx->proc_ctx_hdl;
	}
	else
	{
		IPACMERR("AddHeaderProcCtx failed\n");
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

int IPACM_Lan::eogre_make_header_add_rt_rule(
	ipa_ipgre_info& ipgre_info,
	uint32_t        ctx_2use )
{
	enum ipa_ip_type iptype = ipgre_info.iptype;

	IPACMDBG_H(
		"Attempting to create iptype(%d) \"header add\" route rule for eogre routing\n",
		iptype);

	ctx_2use = (ctx_2use) ? ctx_2use : eogre_route_data[iptype].proc_ctx_eogre_add_hdl;

	if ( ctx_2use == 0 )
	{
		IPACMERR("Can't create a \"header add\" route rule without a context.\n");
		return IPACM_FAILURE;
	}

	/*
	 * Make "header add" route rule...
	 */
	static const int NUM_RT_RULE = 1;

	uint8_t buf[
		sizeof(struct ipa_ioc_add_rt_rule) +
		(NUM_RT_RULE * sizeof(struct ipa_rt_rule_add)) ];

	memset(buf, 0, sizeof(buf));

	struct ipa_ioc_add_rt_rule* rt_table =
		(struct ipa_ioc_add_rt_rule*) buf;

	struct ipa_rt_rule_add* rt_rule_entry = &(rt_table->rules[0]);

	rt_table->commit    = true;
	rt_table->num_rules = NUM_RT_RULE;
	rt_table->ip        = iptype;

	snprintf(
		rt_table->rt_tbl_name,
		sizeof(rt_table->rt_tbl_name),
		"%s",
		( iptype == IPA_IP_v4 )                   ?
		IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name :
		IPACM_Iface::ipacmcfg->rt_tbl_v6.name);

	rt_rule_entry->at_rear                 = true;
	rt_rule_entry->rule.dst                = IPA_CLIENT_DUMMY_CONS;
	rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR;
	rt_rule_entry->rule.hdr_proc_ctx_hdl   = ctx_2use;

#ifdef FEATURE_IPA_V3
	rt_rule_entry->rule.hashable           = true;
#endif
	rt_rule_entry->rule.retain_hdr         = 1;

	/*
	 * Addresses need to be zero, hence..
	 */
	memset(
		&rt_rule_entry->rule.attrib.u,
		0,
		sizeof(rt_rule_entry->rule.attrib.u));

	if ( m_routing.AddRoutingRule(rt_table) == true )
	{
		IPACMDBG_H(
			"EoGRE route rule for \"header add\" successfully installed in %s\n",
			rt_table->rt_tbl_name);
		eogre_route_data[iptype].rt_eogre_add_hdl =
			rt_rule_entry->rt_rule_hdl;
	}
	else
	{
		IPACMERR("AddRoutingRule failed\n");
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

int IPACM_Lan::eogre_make_header_rem_rt_rule(
	ipa_ipgre_info& ipgre_info )
{
	enum ipa_ip_type iptype = ipgre_info.iptype;

	IPACMDBG_H(
		"Attempting to create iptype(%d) \"header remove\" route rule for eogre routing\n",
		iptype);

	if ( eogre_route_data[iptype].proc_ctx_eogre_rmv_hdl == 0 )
	{
		IPACMERR("Can't create a \"header remove\" route rule without a context.\n");
		return IPACM_FAILURE;
	}

	/*
	 * Make "header remove" route rule...
	 */
	static const int NUM_RT_RULE = 1;

	uint8_t buf[
		sizeof(struct ipa_ioc_add_rt_rule) +
		(NUM_RT_RULE * sizeof(struct ipa_rt_rule_add)) ];

	memset(buf, 0, sizeof(buf));

	struct ipa_ioc_add_rt_rule* rt_table =
		(struct ipa_ioc_add_rt_rule*) buf;

	struct ipa_rt_rule_add* rt_rule_entry = &(rt_table->rules[0]);;

	rt_table->commit    = true;
	rt_table->num_rules = NUM_RT_RULE;
	rt_table->ip        = iptype;

	snprintf(
		rt_table->rt_tbl_name,
		sizeof(rt_table->rt_tbl_name),
		"%s",
		( iptype == IPA_IP_v4 )                   ?
		IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name :
		IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name);

	rt_rule_entry->at_rear                 = false;
	rt_rule_entry->rule.dst                = tx_prop->tx[0].dst_pipe;
	rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_SRC_ADDR | IPA_FLT_DST_ADDR;
	rt_rule_entry->rule.hdr_proc_ctx_hdl   =
		eogre_route_data[iptype].proc_ctx_eogre_rmv_hdl;
#ifdef FEATURE_IPA_V3
	rt_rule_entry->rule.hashable           = true;
#endif
	rt_rule_entry->rule.retain_hdr         = 1;

	if ( ipgre_info.iptype == IPA_IP_v4 )
	{
		rt_rule_entry->rule.attrib.u.v4.src_addr_mask = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.u.v4.src_addr      = ipgre_info.ipv4_dst;
		rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.u.v4.dst_addr      = ipgre_info.ipv4_src;
	}
	else
	{
		memset(
			&rt_rule_entry->rule.attrib.u.v6.src_addr_mask,
			0xFFFFFFFF,
			sizeof(rt_rule_entry->rule.attrib.u.v6.src_addr_mask));
		memcpy(
			&rt_rule_entry->rule.attrib.u.v6.src_addr,
			&ipgre_info.ipv6_dst,
			sizeof(rt_rule_entry->rule.attrib.u.v6.src_addr));
		memset(
			&rt_rule_entry->rule.attrib.u.v6.dst_addr_mask,
			0xFFFFFFFF,
			sizeof(rt_rule_entry->rule.attrib.u.v6.dst_addr_mask));
		memcpy(
			&rt_rule_entry->rule.attrib.u.v6.dst_addr,
			&ipgre_info.ipv6_src,
			sizeof(rt_rule_entry->rule.attrib.u.v6.dst_addr));
	}

	if ( m_routing.AddRoutingRule(rt_table) == true )
	{
		IPACMDBG_H(
			"EoGRE route rule for \"header remove\" successfully installed in %s\n",
			rt_table->rt_tbl_name);
		eogre_route_data[iptype].rt_eogre_rmv_hdl = rt_rule_entry->rt_rule_hdl;
	}
	else
	{
		IPACMERR("AddRoutingRule failed\n");
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

void IPACM_Lan::eogre_clear_route_data(
	enum ipa_ip_type             iptype,
	ipa_ioc_query_intf_rx_props* rx_prop )
{
	if ( VALID_IPA_IP_TYPE(iptype) )
	{
		if ( eogre_route_data[iptype].header_hdl )
		{
			m_header.DeleteHeaderHdl(
				eogre_route_data[iptype].header_hdl);
		}

		if ( eogre_route_data[iptype].proc_ctx_eogre_add_hdl )
		{
			m_header.DeleteHeaderProcCtx(
				eogre_route_data[iptype].proc_ctx_eogre_add_hdl);
		}

		if ( eogre_route_data[iptype].proc_ctx_eogre_rmv_hdl )
		{
			m_header.DeleteHeaderProcCtx(
				eogre_route_data[iptype].proc_ctx_eogre_rmv_hdl);
		}

		if ( eogre_route_data[iptype].rt_eogre_add_hdl )
		{
			m_routing.DeleteRoutingHdl(
				eogre_route_data[iptype].rt_eogre_add_hdl, iptype);
		}

		if ( eogre_route_data[iptype].rt_eogre_rmv_hdl )
		{
			m_routing.DeleteRoutingHdl(
				eogre_route_data[iptype].rt_eogre_rmv_hdl, iptype);
		}

		if ( eogre_route_data[iptype].flt_eogre_1st_pass_hdl )
		{
			m_filtering.DeleteFilteringHdls(
				&(eogre_route_data[iptype].flt_eogre_1st_pass_hdl), iptype, 1);

			if ( rx_prop )
			{
				IPACM_Iface::ipacmcfg->decreaseFltRuleCount(
					rx_prop->rx[0].src_pipe, iptype, 1);
			}
		}

		eogre_route_data_init(iptype);
	}
}

#endif /* #ifdef FEATURE_EoGRE */

int IPACM_Lan::eth_bridge_get_vlan_hdr_template_hdl(uint32_t* hdr_hdl, uint16_t vlan_id)
{
	struct ipa_ioc_copy_hdr sCopyHeader;
	struct ipa_ioc_add_hdr hdr;
	uint8_t hdr_len;
	struct ipa_ioc_add_hdr *pHeaderDescriptor = NULL;
	int len = 0;

	memset(&hdr, 0, sizeof(hdr));
	memset(&sCopyHeader, 0, sizeof(sCopyHeader));
	memcpy(sCopyHeader.name,
				tx_prop->tx[2].hdr_name,
				sizeof(sCopyHeader.name));

	IPACMDBG_H("header name: %s\n", sCopyHeader.name);
	if (m_header.CopyHeader(&sCopyHeader) == false)
	{
		PERROR("ioctl copy header failed");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("header length: %d, partial: %d\n", sCopyHeader.hdr_len, sCopyHeader.is_partial);

	hdr_len = sCopyHeader.hdr_len;
	len = sizeof(struct ipa_ioc_add_hdr) + (1 * sizeof(struct ipa_hdr_add));
		pHeaderDescriptor = (struct ipa_ioc_add_hdr *)calloc(1, len);
		if (pHeaderDescriptor == NULL)
	{
			IPACMERR("calloc failed to allocate pHeaderDescriptor\n");
			return IPACM_FAILURE;
	}
	pHeaderDescriptor->hdr[0].hdr_len = sCopyHeader.hdr_len;
	memcpy(pHeaderDescriptor->hdr[0].hdr,
					sCopyHeader.hdr,
					pHeaderDescriptor->hdr[0].hdr_len);
	pHeaderDescriptor->num_hdrs = 1;
	pHeaderDescriptor->hdr[0].type = sCopyHeader.type;
	pHeaderDescriptor->hdr[0].hdr_hdl = -1;
	pHeaderDescriptor->hdr[0].is_partial = sCopyHeader.is_partial;
	pHeaderDescriptor->hdr[0].status = -1;
	pHeaderDescriptor->hdr[0].hdr[hdr_len - 3] = (uint8_t)vlan_id & 0xFF;
	pHeaderDescriptor->hdr[0].hdr[hdr_len - 4] = (uint8_t)(vlan_id >> 8) & 0xFF;
	memset(pHeaderDescriptor->hdr[0].name, 0,
					 sizeof(pHeaderDescriptor->hdr[0].name));
	snprintf(pHeaderDescriptor->hdr[0].name, sizeof(pHeaderDescriptor->hdr[0].name),
		"ath12_ipv4_vlan%d", vlan_id);
	if(m_header.AddHeader(pHeaderDescriptor) == false ||
			pHeaderDescriptor->hdr[0].status != 0)
	{
		IPACMERR("ioctl IPA_IOC_ADD_HDR failed: %d\n", pHeaderDescriptor->hdr[0].status);
		free(pHeaderDescriptor);
		return IPACM_FAILURE;
	}

	*hdr_hdl = pHeaderDescriptor->hdr[0].hdr_hdl;

	free(pHeaderDescriptor);
	return IPACM_SUCCESS;
}

/* handle ext_route new_address event*/
int IPACM_Lan::handle_ext_router_add_evt(char* pdn_name, uint8_t *mac_addr, uint32_t *idu_v6_addr, uint16_t vid = 0)
{
	struct ipa_ioc_add_rt_rule *rt_rule = NULL;
	struct ipa_rt_rule_add *rt_rule_entry;
	struct ext_router_prefix_info info;
	int eth_idx, res = IPACM_SUCCESS;
	const int NUM_RULES = 1;
	struct ipa_ioc_get_hdr hdr;
	struct ipa_flt_rule_add flt_rule;
	struct ipa_ioc_add_flt_rule_after* pFilteringTable = NULL;
	int len, idx = 0;
	uint32_t wan_ipv6_addr[4];
	memset(&hdr, 0, sizeof(hdr));

	strlcpy(info.pdn_name, pdn_name, sizeof(info.pdn_name));
	if(IPACM_Iface::ipacmcfg->get_ext_router_info(&info) == IPACM_FAILURE)
	{
		IPACMERR("failed to get ext_router_info\n");
		return IPACM_FAILURE;
	}

	eth_idx = get_eth_client_index(mac_addr, vid); //if non vlan, it will use 0
	if(eth_idx == IPACM_INVALID_INDEX)
	{
		IPACMERR("Eth client not attached\n");
		res = IPACM_FAILURE;
		goto fail;
	}

	if (get_client_memptr(eth_client, eth_idx)->ext_router_prefix_rt_hdl  != 0)
	{
		IPACMDBG("External router rules already installed\n");
		return IPACM_SUCCESS;
	}

	if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop && rx_prop->num_rx_props > 2)) {
		idx = 2;
		IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx pipe at idx %d \n", idx);
	}

	IPACMDBG_H("set route/filter rule for v6_external router\n");
	rt_rule = (struct ipa_ioc_add_rt_rule *)
		 calloc(1, sizeof(struct ipa_ioc_add_rt_rule) + NUM_RULES * sizeof(struct ipa_rt_rule_add));
	if (!rt_rule)
	{
		IPACMERR("Error Locate ipa_ioc_add_rt_rule memory...\n");
		return IPACM_FAILURE;
	}

	rt_rule->commit = 1;
	rt_rule->num_rules = NUM_RULES;
	rt_rule->ip = IPA_IP_v6;
	strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule->rt_tbl_name));
	rt_rule_entry = &rt_rule->rules[0];
	rt_rule_entry->at_rear = false;
	rt_rule_entry->rule.dst = tx_prop->tx[0].dst_pipe;
	rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR;

	rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, eth_idx)->hdr_hdl_v6;

	if (IPACM_Iface::ipacmcfg->ext_router_mode == IPA_PREFIX_SHARING)
	{
		//For prefix sharing, need to query PDN v6 addr from pdn_name for prefix sharing since we dont want IDU dummy prefix
		if (IPACM_Wan::Getv6addrByName(pdn_name, wan_ipv6_addr) == IPACM_FAILURE)
		{
			IPACMERR("Failed to get v6 addr\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = wan_ipv6_addr[0] & info.ipv6_mask[0];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = wan_ipv6_addr[1] & info.ipv6_mask[1];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = wan_ipv6_addr[2] & info.ipv6_mask[2];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = wan_ipv6_addr[3] & info.ipv6_mask[3];

		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = info.ipv6_mask[0];
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = info.ipv6_mask[1];
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = info.ipv6_mask[2];
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = info.ipv6_mask[3];
	}
	else if (IPACM_Iface::ipacmcfg->ext_router_mode == IPA_PREFIX_DELEGATION)
	{
		//for prefix delegation the client needs to find the prefix mapped to the idu prefix
		int del_prefix_idx = IPACM_Iface::ipacmcfg->get_mapped_delegated_prefix_idx(idu_v6_addr);
		if (del_prefix_idx == IPA_PREFIX_MAPPING_MAX)
		{
			IPACMERR("Failed to get mapped_prefix\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = info.idu_client_prefix[del_prefix_idx][0];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = info.idu_client_prefix[del_prefix_idx][1];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = info.idu_client_prefix[del_prefix_idx][2];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = info.idu_client_prefix[del_prefix_idx][3];

		//NOTE: per current MBB design for dhcpv6, all IDUS will have clients with 64 bit netmask.
		//If this changes, will need another parameter to take the client netmasks and use those values here
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0;
	}


#ifdef FEATURE_IPA_V3
	rt_rule_entry->rule.hashable = true;
#endif
	if (false == m_routing.AddRoutingRule(rt_rule))
	{
		IPACMERR("Routing rule addition failed!\n");
		res = IPACM_FAILURE;
		goto fail;
	}
	else if (rt_rule_entry->status)
	{
		IPACMERR("ext rt rule adding failed. Result=%d\n", rt_rule_entry->status);
		res = rt_rule_entry->status;
		goto fail;
	}
	get_client_memptr(eth_client, eth_idx)->ext_router_prefix_rt_hdl =  rt_rule_entry->rt_rule_hdl;

	/* if in prefix sharing mode, need to add 1 more rt and flt exception rule as per design*/
	if (IPACM_Iface::ipacmcfg->ext_router_mode == IPA_PREFIX_SHARING)
	{
		uint32_t hdl = IPACM_Wan::GetQCMAPhdrByName(pdn_name);
		if (hdl == 0)
		{
			res = IPACM_FAILURE;
			goto fail;
		}
		rt_rule_entry->rule.hdr_hdl = hdl;
		rt_rule_entry->rule.dst = IPA_CLIENT_APPS_WAN_CONS;
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = wan_ipv6_addr[0];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = wan_ipv6_addr[1];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = wan_ipv6_addr[2];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = wan_ipv6_addr[3];
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
			res = IPACM_FAILURE;
			goto fail;
		}
		else if (rt_rule_entry->status)
		{
			IPACMERR("ext rt rule adding failed. Result=%d\n", rt_rule_entry->status);
			res = rt_rule_entry->status;
			goto fail;
		}
		ext_router_rmnet_ipv6_hdl = rt_rule_entry->rt_rule_hdl;

		//construct flt rule
		len = sizeof(struct ipa_ioc_add_flt_rule_after) + sizeof(struct ipa_flt_rule_add);
		pFilteringTable = (struct ipa_ioc_add_flt_rule_after*)malloc(len);
		if(!pFilteringTable)
		{
			IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		if(rx_prop == NULL){
			IPACMERR("no rx props\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		memset(pFilteringTable, 0, len);

		pFilteringTable->commit = 1;
		pFilteringTable->ip = IPA_IP_v6;
		pFilteringTable->num_rules = 1;
		pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
		pFilteringTable->add_after_hdl = mtu_flt_rule_offset[0][IPA_IP_v6];

		memset(&flt_rule, 0, sizeof(struct ipa_flt_rule_add));
		flt_rule.status = -1;
		flt_rule.at_rear = 1;
		flt_rule.rule.retain_hdr = 1;
		flt_rule.rule.to_uc = 0;
		flt_rule.rule.action = IPA_PASS_TO_EXCEPTION;
		flt_rule.rule.eq_attrib_type = 0;

		memcpy(&flt_rule.rule.attrib, &rx_prop->rx[idx].attrib, sizeof(flt_rule.rule.attrib));
		flt_rule.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
		flt_rule.rule.attrib.u.v6.src_addr[0] = info.ipv6_addr[0];
		flt_rule.rule.attrib.u.v6.src_addr[1] = info.ipv6_addr[1];
		flt_rule.rule.attrib.u.v6.src_addr[2] = info.ipv6_addr[2];
		flt_rule.rule.attrib.u.v6.src_addr[3] = info.ipv6_addr[3];
		flt_rule.rule.attrib.u.v6.src_addr_mask[0] = info.ipv6_mask[0];
		flt_rule.rule.attrib.u.v6.src_addr_mask[1] = info.ipv6_mask[1];
		flt_rule.rule.attrib.u.v6.src_addr_mask[2] = info.ipv6_mask[2];
		flt_rule.rule.attrib.u.v6.src_addr_mask[3] = info.ipv6_mask[3];
		memcpy(&(pFilteringTable->rules[0]), &flt_rule, sizeof(struct ipa_flt_rule_add));
		IPACMDBG_H("IPACM v6 prefix as: 0x[%X][%X]\n",
			flt_rule.rule.attrib.u.v6.src_addr[0],
			flt_rule.rule.attrib.u.v6.src_addr[1]);

		if(false == m_filtering.AddFilteringRuleAfter(pFilteringTable))
		{
			IPACMERR("Failed to add prefix filtering rules.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, 1);
		ext_router_flt_rule_hdl = pFilteringTable->rules[0].flt_rule_hdl;
	}

	/* copy pdn name when everything is succesful. this will be used as a key */
	strlcpy(ext_router_pdn_name, pdn_name, sizeof(ext_router_pdn_name));

	IPACMDBG_H("finished handle_ext_router_add_evt for pdn:%s\n",ext_router_pdn_name);
fail:
	if(pFilteringTable != NULL)
		free(pFilteringTable);

	if(rt_rule != NULL)
		free(rt_rule);

	return res;
}

/* handle ext_route delete event*/
int IPACM_Lan::handle_ext_router_del_evt(void)
{
	IPACMDBG("entering handle_ext_router_del_evt\n")
	int cnt, idx = 0;

	if(rx_prop == NULL){
		IPACMERR("no rx props\n");
		return IPACM_FAILURE;
	}
	if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
		idx = 2;
		IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx pipe at idx %d \n", idx);
	}

	if(ext_router_rmnet_ipv6_hdl)
	{
		IPACMDBG("deleting ext_router_rmnet_ipv6_hdl = %d\n", ext_router_rmnet_ipv6_hdl);
		if(m_routing.DeleteRoutingHdl(ext_router_rmnet_ipv6_hdl, IPA_IP_v6) == false)
		{
			IPACMERR("Failed to del ext_router_rmnet_ipv6 rt rule\n");
			return IPACM_FAILURE;
		}
		ext_router_rmnet_ipv6_hdl = 0;
	}

	if(ext_router_flt_rule_hdl)
	{
		IPACMDBG("deleting flt_rule_hdl = %d\n", ext_router_flt_rule_hdl);
		if(m_filtering.DeleteFilteringHdls(&ext_router_flt_rule_hdl, IPA_IP_v6, 1) == false)
		{
			IPACMERR("Failed to del ext_router_flt_rule.\n");
			return IPACM_FAILURE;
		}
		ext_router_flt_rule_hdl = 0;
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v6, 1);
	}

	/* delete all ext prefix rt_rule */
	for(cnt = 0; cnt < num_eth_client; cnt++)
	{
		if(get_client_memptr(eth_client, cnt)->ext_router_prefix_rt_hdl)
		{
			IPACMDBG("deleting rt_rule_hdl = %d\n", get_client_memptr(eth_client, cnt)->ext_router_prefix_rt_hdl);
			if(m_routing.DeleteRoutingHdl(get_client_memptr(eth_client, cnt)->ext_router_prefix_rt_hdl, IPA_IP_v6) == false)
			{
				IPACMERR("Failed to del ext_route rt_rule\n");
				return IPACM_FAILURE;
			}
			get_client_memptr(eth_client, cnt)->ext_router_prefix_rt_hdl = 0;
		}
	}
	IPACMDBG("Finished handle_ext_router_del_evt\n")
	return IPACM_SUCCESS;
}

#ifdef FEATURE_IPA_IPSEC
/* handle IPsec UL flt add event*/
int IPACM_Lan::handleIpsecUlFltAddEvt(struct ipa_ioc_ipsec_ul_flt_attr *uf)
{
	int res = IPACM_SUCCESS;
	struct ipa_flt_rule_add *pFltRule;
	struct ipa_ioc_add_flt_rule_after* pFilteringTable = NULL;
	struct ipa_ioc_get_rt_tbl rtTblHdl;
	int len, idx = 0;

	memset(&rtTblHdl, 0, sizeof(rtTblHdl));
	rtTblHdl.ip = uf->ip;
	strlcpy(rtTblHdl.name, (uf->ip == IPA_IP_v4) ? "IPSEC_ENCAP_v4" : "IPSEC_ENCAP_v6", sizeof(rtTblHdl.name));
	rtTblHdl.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
	if(m_routing.GetRoutingTable(&rtTblHdl) == false)
	{
		IPACMERR("Failed to get routing table handle from name\n");
		return IPACM_FAILURE;
	}
	IPACMDBG_H("Routing table %s has handle %d\n", rtTblHdl.name, rtTblHdl.hdl);

	if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2))
	{
		idx = 2;
		IPACMDBG_H("Interface is WLAN Svap or vlan, install rule on Rx1 pipe at idx %d \n", idx);
	}

	len = sizeof(struct ipa_ioc_add_flt_rule_after) + sizeof(struct ipa_flt_rule_add);
	pFilteringTable = (struct ipa_ioc_add_flt_rule_after*)malloc(len);
	if(!pFilteringTable)
	{
		IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
		res = IPACM_FAILURE;
		goto fail;
	}
	memset(pFilteringTable, 0, len);

	pFilteringTable->commit = 1;
	pFilteringTable->ip = uf->ip;
	pFilteringTable->num_rules = 1;
	pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
	pFilteringTable->add_after_hdl = mtu_flt_rule_offset[0][uf->ip];

	pFltRule = &(pFilteringTable->rules[0]);
	pFltRule->status = -1;
	pFltRule->rule.action = IPA_PASS_TO_ROUTING;
	pFltRule->rule.hashable = true;
	pFltRule->rule.rt_tbl_hdl = rtTblHdl.hdl;

	memcpy(&pFltRule->rule.attrib, &uf->attr, sizeof(uf->attr));

	if(false == m_filtering.AddFilteringRuleAfter(pFilteringTable))
	{
		IPACMERR("Failed to add IPsec UL filtering rule\n");
		res = IPACM_FAILURE;
		goto fail;
	}
	IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, uf->ip, 1);

	ipsecUlFltHdlList[uf->ip].push_back({uf->attr, pFltRule->flt_rule_hdl});

	IPACMDBG_H("finished handle_ipsec_ul_flt_add_evt. ipsec_ul_flt_hdl_list contains %d entries.\n",
		ipsecUlFltHdlList[uf->ip].size());
fail:
	if(pFilteringTable != NULL)
		free(pFilteringTable);

	return res;
}

/* handle IPsec UL flt del event*/
int IPACM_Lan::handleIpsecUlFltDelEvt(struct ipa_ioc_ipsec_ul_flt_attr *uf)
{
	int res = IPACM_SUCCESS;
	struct ipa_ioc_del_flt_rule* pFltRule = NULL;
	int len, idx = 0;
	uint32_t hdl = ~0x0;

	for (const auto& UlFltHdl: ipsecUlFltHdlList[uf->ip])
	{
		if (UlFltHdl.attr == uf->attr)
		{
			hdl = UlFltHdl.hdl;
		}
	}

	if (hdl == ~0x0)
	{
		IPACMDBG_H("No rule to delete found\n");
		return IPACM_SUCCESS;
	}

	if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2))
	{
		idx = 2;
		IPACMDBG_H("Interface is WLAN Svap or vlan, remove rule from Rx1 pipe at idx %d \n", idx);
	}

	len = sizeof(struct ipa_ioc_del_flt_rule) + sizeof(struct ipa_flt_rule_del);
	pFltRule = (struct ipa_ioc_del_flt_rule *)malloc(len);
	if(!pFltRule)
	{
		IPACMERR("Failed to allocate ipa_ioc_del_flt_rule memory...\n");
		res = IPACM_FAILURE;
		goto fail;
	}
	memset(pFltRule, 0, len);

	pFltRule->commit = 1;
	pFltRule->ip = uf->ip;
	pFltRule->num_hdls = 1;
	pFltRule->hdl[0].hdl = hdl;
	pFltRule->hdl[0].status = -1;

	if(false == m_filtering.DeleteFilteringRule(pFltRule))
	{
		IPACMERR("Failed to delete IPsec UL filtering rule\n");
		res = IPACM_FAILURE;
		goto fail;
	}
	IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, uf->ip, 1);

	ipsecUlFltHdlList[uf->ip].remove({uf->attr, hdl});

	IPACMDBG_H("finished handle_ipsec_ul_flt_del_evt. ipsec_ul_flt_hdl_list contains %d entries.\n",
		ipsecUlFltHdlList[uf->ip].size());
fail:
	if(pFltRule != NULL)
		free(pFltRule);

	return res;
}

/* handle IPsec UL flt add all from config*/
int IPACM_Lan::handleIpsecUlFltAddAll(enum ipa_ip_type ip)
{
	int res = IPACM_SUCCESS;
	struct ipa_flt_rule_add *pFltRule;
	struct ipa_ioc_add_flt_rule_after* pFilteringTable = NULL;
	struct ipa_ioc_get_rt_tbl rtTblHdl;
	int len, idx = 0;

	if (IPACM_Iface::ipacmcfg->ipsecUlFlt.size() == 0)
	{
		IPACMERR("Nothing to add\n");
		return IPACM_SUCCESS;
	}

	memset(&rtTblHdl, 0, sizeof(rtTblHdl));
	rtTblHdl.ip = ip;
	strlcpy(rtTblHdl.name, (ip == IPA_IP_v4) ? "IPSEC_ENCAP_v4" : "IPSEC_ENCAP_v6", sizeof(rtTblHdl.name));
	rtTblHdl.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
	if(m_routing.GetRoutingTable(&rtTblHdl) == false)
	{
		IPACMERR("Failed to get routing table handle from name\n");
		return IPACM_FAILURE;
	}
	IPACMDBG_H("Routing table %s has handle %d\n", rtTblHdl.name, rtTblHdl.hdl);

	if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2))
	{
		idx = 2;
		IPACMDBG_H("Interface is WLAN Svap or vlan, install rule on Rx1 pipe at idx %d \n", idx);
	}

	len = sizeof(struct ipa_ioc_add_flt_rule_after) +
		sizeof(struct ipa_flt_rule_add) * IPACM_Iface::ipacmcfg->ipsecUlFlt.size();
	pFilteringTable = (struct ipa_ioc_add_flt_rule_after*)malloc(len);
	if(!pFilteringTable)
	{
		IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
		res = IPACM_FAILURE;
		goto fail;
	}
	memset(pFilteringTable, 0, len);

	pFilteringTable->commit = 1;
	pFilteringTable->ip = ip;
	pFilteringTable->num_rules = 0;
	pFilteringTable->ep = rx_prop->rx[idx].src_pipe;
	pFilteringTable->add_after_hdl = mtu_flt_rule_offset[0][ip];

	for (const auto& UlFlt: IPACM_Iface::ipacmcfg->ipsecUlFlt)
	{
		if (UlFlt.ip == ip)
		{
			pFltRule = &(pFilteringTable->rules[pFilteringTable->num_rules++]);
			pFltRule->status = -1;
			pFltRule->rule.action = IPA_PASS_TO_ROUTING;
			pFltRule->rule.hashable = true;
			pFltRule->rule.rt_tbl_hdl = rtTblHdl.hdl;

			memcpy(&pFltRule->rule.attrib, &UlFlt.attr, sizeof(UlFlt.attr));
		}
	}

	if(false == m_filtering.AddFilteringRuleAfter(pFilteringTable))
	{
		IPACMERR("Failed to add %d IPsec UL filtering rules\n", pFilteringTable->num_rules);
		res = IPACM_FAILURE;
		goto fail;
	}
	IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, ip, pFilteringTable->num_rules);

	for (auto i = 0; i < pFilteringTable->num_rules; i++)
	{
		pFltRule = &(pFilteringTable->rules[i]);
		ipsecUlFltHdlList[ip].push_back({pFltRule->rule.attrib, pFltRule->flt_rule_hdl });
	}

	IPACMDBG_H("finished handle_ipsec_ul_flt_add_all. ipsec_ul_flt_hdl_list contains %d entries.\n",
		ipsecUlFltHdlList[ip].size());
fail:
	if(pFilteringTable != NULL)
		free(pFilteringTable);

	return res;
}

/* handle IPsec UL flt delete all */
int IPACM_Lan::handleIpsecUlFltDelAll(enum ipa_ip_type ip)
{
	int res = IPACM_SUCCESS;
	struct ipa_ioc_del_flt_rule* pFltRule = NULL;
	int len, idx = 0;

	if (ipsecUlFltHdlList[ip].size() == 0)
	{
		IPACMERR("Nothing to delete\n");
		return IPACM_SUCCESS;
	}

	if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2))
	{
		idx = 2;
		IPACMDBG_H("Interface is WLAN Svap or vlan, install rule on Rx1 pipe at idx %d \n", idx);
	}

	len = sizeof(struct ipa_ioc_del_flt_rule) +
		sizeof(struct ipa_flt_rule_del) * ipsecUlFltHdlList[ip].size();
	pFltRule = (struct ipa_ioc_del_flt_rule *)malloc(len);
	if(!pFltRule)
	{
		IPACMERR("Failed to allocate ipa_ioc_del_flt_rule memory...\n");
		res = IPACM_FAILURE;
		goto fail;
	}
	memset(pFltRule, 0, len);

	pFltRule->commit = 1;
	pFltRule->ip = ip;
	pFltRule->num_hdls = 0;

	for (const auto& UlFltHdl: ipsecUlFltHdlList[ip])
	{
		pFltRule->hdl[pFltRule->num_hdls].hdl = UlFltHdl.hdl;
		pFltRule->hdl[pFltRule->num_hdls++].status = -1;
	}

	if(false == m_filtering.DeleteFilteringRule(pFltRule))
	{
		IPACMERR("Failed to delete %d IPsec UL filtering rules\n", pFltRule->num_hdls);
		res = IPACM_FAILURE;
		goto fail;
	}
	IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, ip, pFltRule->num_hdls);

	ipsecUlFltHdlList[ip].clear();

	IPACMDBG_H("finished handle_ipsec_ul_flt_del_all. ipsec_ul_flt_hdl_list contains %d entries.\n",
		ipsecUlFltHdlList[ip].size());
fail:
	if(pFltRule != NULL)
		free(pFltRule);

	return res;
}
#endif

int IPACM_Lan::handle_static_policy_rt_rule_add()
{
	IPACMDBG_H("Enter handle_static_policy_rt_rule_add\n")
	int res = IPACM_SUCCESS;
	uint8_t buf[sizeof(struct ipa_ioc_add_hdr_proc_ctx) + sizeof(struct ipa_hdr_proc_ctx_add)];
	memset(buf, 0, sizeof(buf));
	struct ipa_ioc_add_hdr_proc_ctx *procCtxTable =
		(struct ipa_ioc_add_hdr_proc_ctx *) buf;
	struct ipa_hdr_proc_ctx_add *procCtx = &(procCtxTable->proc_ctx[0]);

	// init proc ctx table
	procCtxTable->commit        = true;
	procCtxTable->num_proc_ctxs = 1;

	// init proc_ctx common fields
	procCtx->proc_ctx_hdl = -1; // return value
	procCtx->status       = -1; // Return parameter
	procCtx->type         = IPA_HDR_PROC_2ND_PASS;

	if ( m_header.AddHeaderProcCtx(procCtxTable) == true )
	{
		IPACM_Lan::static_policy_proc_ctx_hdl = procCtx->proc_ctx_hdl;
		IPACMDBG_H("static policy proc ctx installed. hdl:%d\n",
			procCtx->proc_ctx_hdl);
	}
	else
	{
		IPACMERR("AddHeaderProcCtx failed\n");
		res = IPACM_FAILURE;
		return res;
	}

	/*add rt rule*/
	struct ipa_ioc_add_rt_rule *rt_rule;
	struct ipa_rt_rule_add *rt_rule_entry;
	const int NUM_RULES = 1;

	rt_rule = (struct ipa_ioc_add_rt_rule *)
		calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
		NUM_RULES * sizeof(struct ipa_rt_rule_add));

	if (!rt_rule)
	{
		IPACMERR("Error Locate ipa_ioc_add_rt_rule memory...\n");
		return IPACM_FAILURE;
	}

	rt_rule->commit = 1;
	rt_rule->num_rules = NUM_RULES;
	rt_rule->ip = IPA_IP_v4;
	rt_rule_entry = &rt_rule->rules[0];
	rt_rule_entry->rule.dst = IPA_CLIENT_TEST_CONS;  //theres no dummy for ipa 6.0 //pipe 35
	strlcpy(rt_rule->rt_tbl_name, "static_policy_rt", sizeof(rt_rule->rt_tbl_name));
#ifdef FEATURE_IPA_V3
	rt_rule_entry->rule.hashable = true;
#endif
	rt_rule_entry->rule.hdr_proc_ctx_hdl = IPACM_Lan::static_policy_proc_ctx_hdl;
	if (false == m_routing.AddRoutingRule(rt_rule))
	{
		IPACMERR("Routing rule addition failed!\n");
		res = IPACM_FAILURE;
		free(rt_rule);
		return res;
	}
	else if (rt_rule_entry->status)
	{
		IPACMERR("rt rule adding failed. Result=%d\n", rt_rule_entry->status);
		res = rt_rule_entry->status;
		free(rt_rule);
		return res;
	}
	IPACM_Lan::static_policy_rt_rule_hdl  = rt_rule_entry->rt_rule_hdl;
	IPACMDBG_H("Added static policy rt rule. Rule hdl:%d\n", IPACM_Lan::static_policy_rt_rule_hdl );

	return res;
}


int IPACM_Lan::handle_static_policy_flt_rule_add(uint32_t ipv4_addr)
{
	IPACMDBG_H("Enter handle_static_policy_flt_rule_add\n")

	struct ipa_flt_rule_add *pFltRule;
	struct ipa_ioc_add_flt_rule_after* pFilteringTable = NULL;
	struct ipa_ioc_get_rt_tbl rtTblHdl;
	int len, idx = 0, res = 0;
	ipa_private_subnet *private_subnet = NULL;

	memset(&private_subnet, 0, sizeof (private_subnet));
	if ((private_subnet = IPACM_Iface::ipacmcfg->getPrivateSubnet(ipv4_addr)) == NULL)
	{
		IPACMERR("Failed to extract private subnet for static policy rule.\n");
		res = IPACM_FAILURE;
		return res;
	}

	memset(&rtTblHdl, 0, sizeof(rtTblHdl));
	snprintf(rtTblHdl.name, sizeof(rtTblHdl.name),"static_policy_rt");
	rtTblHdl.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
	IPACMDBG_H("This flt rule points to rt tbl %s.\n", rtTblHdl.name);
	if(m_routing.GetRoutingTable(&rtTblHdl) == false)
	{
		IPACMERR("Failed to get routing table handle from name\n");
		return IPACM_FAILURE;
	}
	IPACMDBG_H("Routing table %s has handle %d\n", rtTblHdl.name, rtTblHdl.hdl);

	len = sizeof(struct ipa_ioc_add_flt_rule_after) + sizeof(struct ipa_flt_rule_add);
	pFilteringTable = (struct ipa_ioc_add_flt_rule_after*)malloc(len);
	if(!pFilteringTable)
	{
		IPACMERR("Failed to allocate ipa_ioc_add_flt_rule_after memory...\n");
		res = IPACM_FAILURE;
		free(pFilteringTable);
		return res;
	}
	memset(pFilteringTable, 0, len);

	pFilteringTable->commit = 1;
	pFilteringTable->ip = IPA_IP_v4;
	pFilteringTable->num_rules = 1;
	pFilteringTable->ep = rx_prop->rx[0].src_pipe;
	//Note: probably need to do idx handling for ipsec/easymesh
	pFilteringTable->add_after_hdl = mtu_flt_rule_offset[0][IPA_IP_v4];

	pFltRule = &(pFilteringTable->rules[0]);
	pFltRule->status = -1;
	pFltRule->rule.action = IPA_PASS_TO_SRC_NAT;
	pFltRule->rule.hashable = true;
	pFltRule->rule.rt_tbl_hdl = rtTblHdl.hdl;
	pFltRule->rule.retain_hdr = 1;
	pFltRule->rule.attrib.u.v4.src_addr = private_subnet->subnet_addr;
	pFltRule->rule.attrib.u.v4.src_addr_mask = private_subnet->subnet_mask;
	pFltRule->rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
	pFltRule->rule.set_metadata = true;

	if(false == m_filtering.AddFilteringRuleAfter(pFilteringTable))
	{
		IPACMERR("Failed to add static policy UL filtering rule\n");
		res = IPACM_FAILURE;
		free(pFilteringTable);
		return res;
	}
	IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, 1);

	static_policy_flt_rule_hdl = pFltRule->flt_rule_hdl;

	IPACMDBG_H("Finished handle_static_policy_flt_rule_add. Rule hdl = %d\n",
		static_policy_flt_rule_hdl);

	return res;
}

int IPACM_Lan::handle_static_policy_rule_delete()
{
	IPACMDBG_H("Enter rule deletion for static policy\n")
	int idx = 0;

	//check if this is needed for add/delete
	if ((ipa_if_cate == WLAN_IF) && (is_if_svap || is_wlan_if_vlan) && (rx_prop->num_rx_props > 2)) {
		idx = 2;
		IPACMDBG_H("Interface is WLAN Svap or vlan, install rules on Rx pipe at idx %d \n", idx);
	}

	if (m_filtering.DeleteFilteringHdls(&static_policy_flt_rule_hdl, IPA_IP_v4, 1) == false)
	{
		IPACMERR("Failed to delete filtering rule, aborting...\n");
		return IPACM_FAILURE;
	}
	IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[idx].src_pipe, IPA_IP_v4, 1);
	static_policy_flt_rule_hdl = 0;

	if (IPACM_Lan::total_vlan_pdn_cnt > 0)
	{
		IPACMDBG_H("rt rule and proc_ctx still being used by another vlan client\n");
		return IPACM_SUCCESS;
	}

	if(m_routing.DeleteRoutingHdl(IPACM_Lan::static_policy_rt_rule_hdl, IPA_IP_v4) == false)
	{
		IPACMERR("Failed to delete routing rule, aborting...\n");
		return IPACM_FAILURE;
	}
	IPACM_Lan::static_policy_rt_rule_hdl = 0;

	if(m_header.DeleteHeaderProcCtx(IPACM_Lan::static_policy_proc_ctx_hdl) == false)
	{
		IPACMERR("Failed to delete hdr proc ctx, aborting...\n");
		return IPACM_FAILURE;
	}
	IPACM_Lan::static_policy_proc_ctx_hdl = 0;

	return IPACM_SUCCESS;
}

int IPACM_Lan::install_default_qos_rt_rules(uint8_t *client_mac, uint16_t client_vlan_id, enum ipa_ip_type iptype)
{
	struct ipa_ioc_add_rt_rule *rt_rule = NULL;
	struct ipa_rt_rule_add *rt_rule_entry;
	const int NUM_RULES = 1;
	int res = IPACM_SUCCESS;
	int idx = 0;
	enum ipa_client_type max_prio_pipe;
	uint32_t min_tc_bmap = 0xffffffff;
	int eth_index = 0;

	IPACMDBG_H("set default qos tcp ack rule ip-type: %d \n", iptype);

	if (tx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	eth_index = get_eth_client_index(client_mac, client_vlan_id);
	if (eth_index == IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client not found/attached \n");
		return IPACM_SUCCESS;
	}


	// delete previous rules . required because qos ack rules should go on top of client rules.
	if (iptype == IPA_IP_v4)
	{
		IPACMDBG("Deleting dft qos v4 rt hdl 0x%x\n", dft_qos_rt_rule_hdl[0]);
		if (m_routing.DeleteRoutingHdl(dft_qos_rt_rule_hdl[0], IPA_IP_v4)
				== false)
		{
			IPACMERR("Routing rule deletion failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		dft_qos_rt_rule_hdl[0] = 0;
	}
	IPACMDBG_H("Finished delete default qos ipv4 rules \n");

	/* delete default v6 routing rule */
	if (iptype == IPA_IP_v6)
	{
		for (int i = 1; i < 3; i++)
		{
			IPACMDBG("Deleting dft qos v6 rt hdl 0x%x\n", dft_qos_rt_rule_hdl[i]);
			if (m_routing.DeleteRoutingHdl(dft_qos_rt_rule_hdl[i], IPA_IP_v6)
				== false) {
				IPACMERR("Routing rule deletion failed!\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			dft_qos_rt_rule_hdl[i] = 0;
		}
	}
	IPACMDBG("Finished delete default qos ipv6 rules \n");

	for (int j = 0; j < tx_prop->num_tx_props / 2 && j < IPA_MAX_NUM_PROPS; j++)
	{
		if (tx_prop->tx[2*j].tc_bmap &&
			(tx_prop->tx[2*j].tc_bmap < min_tc_bmap))
		{
			min_tc_bmap = tx_prop->tx[2 * j].tc_bmap;
			max_prio_pipe = tx_prop->tx[2 * j].dst_pipe;
		}
	}

	if (0xffffffff == min_tc_bmap)
	{
		IPACMDBG_H("No qos pipes exist, skip %d \n", iptype);
		return res;
	}
	IPACMDBG_H("Qos default rule to be installed on dst pipe %d with tc 0x%x \n", max_prio_pipe, min_tc_bmap);

	if (iptype == IPA_IP_v4)
	{
		rt_rule = (struct ipa_ioc_add_rt_rule *)
			 calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
							NUM_RULES * sizeof(struct ipa_rt_rule_add));

		if (!rt_rule)
		{
			IPACMERR("Error Locate ipa_ioc_add_rt_rule memory...\n");
			return IPACM_FAILURE;
		}

		rt_rule->commit = 1;
		rt_rule->num_rules = NUM_RULES;
		rt_rule->ip = iptype;
		rt_rule_entry = &rt_rule->rules[0];
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.dst = max_prio_pipe;  //go to A5
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_IS_PURE_ACK;
		strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name, sizeof(rt_rule->rt_tbl_name));
		rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v4;

		if (false == m_routing.AddRoutingRule(rt_rule))
		{
			IPACMERR("Routing rule addition failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		else if (rt_rule_entry->status)
		{
			IPACMERR("rt rule adding failed. Result=%d\n", rt_rule_entry->status);
			res = rt_rule_entry->status;
			goto fail;
		}
		dft_qos_rt_rule_hdl[0] = rt_rule_entry->rt_rule_hdl;
		IPACMDBG_H("ipv4 iface qos default rt-rule hdl1=0x%x\n", dft_qos_rt_rule_hdl[0]);
	}
	else
	{
		rt_rule = (struct ipa_ioc_add_rt_rule *)
			calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
				   NUM_RULES * sizeof(struct ipa_rt_rule_add));

		if (!rt_rule)
		{
			IPACMERR("Error Locate ipa_ioc_add_rt_rule memory...\n");
			return IPACM_FAILURE;
		}

		rt_rule->commit = 1;
		rt_rule->num_rules = NUM_RULES;
		rt_rule->ip = iptype;
		strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_v6.name, sizeof(rt_rule->rt_tbl_name));
		rt_rule_entry = &rt_rule->rules[0];
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.dst = max_prio_pipe;  //go to A5
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_IS_PURE_ACK;
		rt_rule_entry->rule.hdr_hdl = 0;

		if (false == m_routing.AddRoutingRule(rt_rule))
		{
			IPACMERR("Routing rule addition failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		} else if (rt_rule_entry->status)
		{
			IPACMERR("rt rule adding failed. Result=%d\n", rt_rule_entry->status);
			res = rt_rule_entry->status;
			goto fail;
		}
		dft_qos_rt_rule_hdl[1] = rt_rule_entry->rt_rule_hdl;

		/* setup same rule for v6_wan table*/
		strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule->rt_tbl_name));
		rt_rule_entry->rule.hdr_hdl = get_client_memptr(eth_client, eth_index)->hdr_hdl_v6;
		if (false == m_routing.AddRoutingRule(rt_rule))
		{
			IPACMERR("Routing rule addition failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		} else if (rt_rule_entry->status)
		{
			IPACMERR("rt rule adding failed. Result=%d\n", rt_rule_entry->status);
			res = rt_rule_entry->status;
			goto fail;
		}
		dft_qos_rt_rule_hdl[2] = rt_rule_entry->rt_rule_hdl;

		IPACMDBG_H("ipv6 wan iface rt-rule hdl=0x%x hdl=0x%x, \n",
				   dft_qos_rt_rule_hdl[1],
				   dft_qos_rt_rule_hdl[2]);

	}
	IPACMDBG_H("finish route/filter rule ip-type: %d, res(%d)\n", iptype, res);

fail:
	if(rt_rule != NULL)
	{
		free(rt_rule);
	}
	return res;
}
