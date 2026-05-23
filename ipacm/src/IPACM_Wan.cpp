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
 * Copyright (c) 2022-2025 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
/*!
		@file
		IPACM_Wan.cpp

		@brief
		This file implements the WAN iface functionality.

		@Author
		Skylar Chang

*/
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <IPACM_Wan.h>
#include <IPACM_Xml.h>
#include <IPACM_Log.h>
#include "IPACM_EvtDispatcher.h"
#include <IPACM_IfaceManager.h>
#include "linux/rmnet_ipa_fd_ioctl.h"
#include "IPACM_Config.h"
#include "IPACM_Defs.h"
#include <IPACM_ConntrackListener.h>
#include "linux/ipa_qmi_service_v01.h"
#include <IPACM_Netlink.h>

#define META_IS_IPSEC 0x10
#define META_IPSEC_MASK 0xF0
#define META_SA_MASK  0xF
#define META_SA_SHIFT 0

#define GRE_PROTOCOL_TYPE_v6 0x86DD
#define GRE_PROTOCOL_TYPE_v4 0x0800
#define GRE_PROTOCOL_TYPE_v6_WITH_KEY 0x200086DD
#define GRE_PROTOCOL_TYPE_v4_WITH_KEY 0x20000800


const uint8_t IPACM_Wan::v4_gre_header[] = {
	0x45, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x40, 0x00,
	0x3f, 0x2f, 0x00, 0x00, // 0x2f Protocol (Generic Routing Encapsulation)
	0x00, 0x00, 0x00, 0x00, // src address here
	0x00, 0x00, 0x00, 0x00, // dest address here
	// GRE header here
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x05 //Key hardcoded according to PMIPV6 opensource code for now
};

const uint8_t IPACM_Wan::v4_ipogre_header[] = {
	0x45, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x40, 0x00,
	0x3f, 0x2f, 0x00, 0x00, // 0x2f Protocol (Generic Routing Encapsulation)
	0x00, 0x00, 0x00, 0x00, // src address here
	0x00, 0x00, 0x00, 0x00, // dest address here
	// GRE header here
	0x00, 0x00, 0x00, 0x00,
};

const uint8_t IPACM_Wan::v6_ipogre_header[] = {
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
	0x2f, 0x00, 0x04, 0x01,
	0x04, 0x01, 0x01, 0x00,
	// GRE header here
	0x00, 0x00, 0x00, 0x00,
};

const uint8_t IPACM_Wan::v6_gre_header[] = {
	0x60, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x2f, 0x40, // 0x3c Protocol (destination option) hop limit to 64
	0x00, 0x00, 0x00, 0x00, // src address here
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, // dest address here
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	// GRE header here
	0x00, 0x00, 0x00, 0x00,
	0x05, 0x00, 0x00, 0x00 //Key hardcoded according to PMIPV6 opensource code for now
};

bool IPACM_Wan::wan_up = false;
bool IPACM_Wan::wan_up_v6 = false;
uint8_t IPACM_Wan::xlat_mux_id = 0;

uint32_t IPACM_Wan::curr_wan_ip = 0;
int IPACM_Wan::num_v4_flt_rule = 0;
int IPACM_Wan::num_v6_flt_rule = 0;
#ifdef FEATURE_VLAN_MPDN
int IPACM_Wan::ipv6_mpdn_default_filterting_rules_count = 0;
#endif

int IPACM_Wan::ipa_pm_q6_check = 0;

#ifdef FEATURE_IPACM_UL_FIREWALL
int IPACM_Wan::num_firewall_v6_ul = 0;
#endif //FEATURE_IPACM_UL_FIREWALL

#ifdef FEATURE_VLAN_MPDN
struct ipacm_pdn_flt_rule IPACM_Wan::pdn_flt_rule_v4[IPA_MAX_FLT_RULE];
struct ipacm_pdn_flt_rule IPACM_Wan::pdn_flt_rule_v6[IPA_MAX_FLT_RULE];
#endif
#ifdef FEATURE_PMIPV6
ipgre_route_data_t IPACM_Wan::ipgre_route_data[IPA_IP_MAX];
#endif
struct ipa_flt_rule_add IPACM_Wan::flt_rule_v4[IPA_MAX_FLT_RULE];
struct ipa_flt_rule_add IPACM_Wan::flt_rule_v6[IPA_MAX_FLT_RULE];

#ifdef FEATURE_IPACM_UL_FIREWALL
struct ipa_flt_rule_add IPACM_Wan::firewall_flt_rule_v6_ul[IPACM_MAX_FIREWALL_ENTRIES+1];
#endif //FEATURE_IPACM_UL_FIREWALL

char IPACM_Wan::wan_up_dev_name[IF_NAME_LEN];

bool IPACM_Wan::backhaul_is_sta_mode = false;
bool IPACM_Wan::is_ext_prop_set = false;

uint32_t IPACM_Wan::wan_route_rule_wan_v6_hdl_a5 = 0;
uint32_t IPACM_Wan::wan_route_rule_lan_v6_hdl_a5 = 0;

uint32_t IPACM_Wan::pppoe_route_rule_hdl_v4 = 0;
uint32_t IPACM_Wan::pppoe_route_rule_hdl_v6 = 0;

int IPACM_Wan::num_ipv4_modem_pdn = 0;
int IPACM_Wan::num_ipv6_modem_pdn = 0;
int IPACM_Wan::num_ipv4_sta_pdn = 0;
int IPACM_Wan::num_ipv6_sta_pdn = 0;

bool IPACM_Wan::embms_is_on = false;
bool IPACM_Wan::backhaul_is_wan_bridge = false;

uint32_t IPACM_Wan::backhaul_ipv6_prefix[2];

#ifdef FEATURE_DUAL_BACKHAUL
uint32_t IPACM_Wan::second_backhaul_ipv4=0;
bool IPACM_Wan::second_backhaul_active=false;
#endif

#ifdef FEATURE_IPACM_UL_FIREWALL
#ifdef FEATURE_VLAN_MPDN
IPACM_firewall_t IPACM_Wan::firewall_mpdn_config_ul;
#endif
IPACM_firewall_conf_t IPACM_Wan::firewall_config_ul;

int IPACM_Wan::m_fd_ipa_ul = 0;
#endif //FEATURE_IPACM_UL_FIREWALL

#ifdef FEATURE_IPA_ANDROID
int	IPACM_Wan::ipa_if_num_tether_v4_total = 0;
int	IPACM_Wan::ipa_if_num_tether_v6_total = 0;

int	IPACM_Wan::ipa_if_num_tether_v4[IPA_MAX_IFACE_ENTRIES];
int	IPACM_Wan::ipa_if_num_tether_v6[IPA_MAX_IFACE_ENTRIES];
#endif
#ifdef FEATURE_VLAN_MPDN
ipacm_ipv4_wan_iface IPACM_Wan::ipv4_to_iface[IPA_MAX_NUM_SW_PDNS];
ipacm_ipv6_wan_iface IPACM_Wan::ipv6_to_iface[IPA_MAX_NUM_SW_PDNS];
uint8_t IPACM_Wan::num_offloaded_pdns = 0;
int IPACM_Wan::wlan_v4_vlan_index = -1;
int IPACM_Wan::wlan_v6_vlan_index = -1;
int IPACM_Wan::eth_sta_v4_vlan_index = -1;
int IPACM_Wan::eth_sta_v6_vlan_index = -1;
#endif

uint16_t IPACM_Wan::mtu_default_wan_v4 = DEFAULT_MTU_SIZE;
uint16_t IPACM_Wan::mtu_default_wan_v6 = DEFAULT_MTU_SIZE;

#if defined(FEATURE_EoGRE) || defined(FEATURE_PMIPV6)
uint16_t IPACM_Wan::mtu_gre_v4 = DEFAULT_MTU_SIZE;
uint16_t IPACM_Wan::mtu_gre_v6 = DEFAULT_MTU_SIZE;
#endif

#ifdef FEATURE_IPA_IPSEC
uint32_t IPACM_Wan::ipsec_post_pol_rt_hdls[IPA_IP_MAX][IPA_MAX_FLT_RULE] = { 0 };
int IPACM_Wan::num_ipsec_post_pol_rt[IPA_IP_MAX] = { 0 };
#endif

int bool_dual_backhaul = 0;

#define MOBILE_FIREWALL_FILE "/etc/data/mobileap_firewall.xml"

IPACM_Wan::IPACM_Wan(int iface_index,
	ipacm_wan_iface_type is_sta_mode,
	uint8_t *mac_addr, bool is_ppp_iface) : IPACM_Iface(NULL, iface_index, is_ppp_iface)
{
	num_firewall_v4 = 0;
	num_firewall_v6 = 0;
	wan_route_rule_v4_hdl = NULL;
	wan_route_rule_v6_hdl = NULL;
	wan_client = NULL;
	wan_client_len = 0;
	is_default_gateway = true;

	if(iface_query != NULL)
	{
		wan_route_rule_v4_hdl = (uint32_t *)calloc(iface_query->num_tx_props, sizeof(uint32_t));
		wan_route_rule_v6_hdl = (uint32_t *)calloc(iface_query->num_tx_props, sizeof(uint32_t));
		IPACMDBG_H("IPACM->IPACM_Wan(%d) constructor: Tx:%d\n", ipa_if_num, iface_query->num_tx_props);
	}
	m_is_sta_mode = is_sta_mode;

	/* Used to store the Public IP info in IP passthrough mode. */
	wan_v4_addr = 0;
	wan_v4_addr_gw = 0;
	public_wan_v4_addr = 0;
	public_wan_v4_addr_set = false;
	wan_v4_addr_set = false;
	wan_v4_addr_gw_set = false;
	wan_v6_addr_gw_set = false;
	wan_v4_is_default_gw = true;
	wan_v6_is_default_gw = true;
	active_v4 = false;
	active_v6 = false;
	header_set_v4 = false;
	header_set_v6 = false;
#ifdef FEATURE_PPPOE
	v4_p_ctx_2use = 0;
	v6_p_ctx_2use = 0;
#endif
	header_partial_default_wan_v4 = false;
	header_partial_default_wan_v6 = false;
	hdr_hdl_sta_v4 = 0;
	hdr_hdl_sta_v6 = 0;
	num_ipv6_dest_flt_rule = 0;
	memset(ipv6_dest_flt_rule_hdl, 0, MAX_DEFAULT_v6_ROUTE_RULES*sizeof(uint32_t));
	memset(dft_wan_fl_hdl, 0, IPA_NUM_DEFAULT_WAN_FILTER_RULES*sizeof(uint32_t));
	memset(ipv6_prefix, 0, sizeof(ipv6_prefix));
	memset(m_ipv6_addr, 0, sizeof(m_ipv6_addr));
	memset(wan_v6_addr_gw, 0, sizeof(wan_v6_addr_gw));
	ext_prop = NULL;
	is_ipv6_frag_firewall_flt_rule_installed = false;
#ifdef FEATURE_IPV6_NAT
	ipv6_ula_prefix_hdl = 0;
#endif

	mtu_v4 = DEFAULT_MTU_SIZE;
	mtu_v4_set = false;
	mtu_v6 = DEFAULT_MTU_SIZE;
	mtu_v6_set = false;
	memset(&ip_pass_pdn_info, 0 ,sizeof(ip_pass_pdn_info));
	memset(&ip_collision_pdn_info, 0 ,sizeof(ip_collision_pdn_info));
#ifdef FEATURE_IPACM_UL_FIREWALL
#ifdef FEATURE_VLAN_MPDN
	num_firewall_v6_ul_pdn = 0;
#endif
#endif //FEATURE_IPACM_UL_FIREWALL
	ipv6_frag_firewall_flt_rule_hdl = 0;

	num_wan_client = 0;
	header_name_count = 0;
	memset(invalid_mac, 0, sizeof(invalid_mac));

	is_xlat = false;
	hdr_hdl_dummy_v6 = 0;
	hdr_proc_hdl_dummy_v6 = 0;

#ifdef IPA_MTU_EVENT_MAX
	/* Query WAN MTU to handle IPACM restart scenarios. */
	if(is_sta_mode == Q6_WAN)
	{
		int fd_wwan_ioctl;
		ipa_mtu_info *mtu_info = (ipa_mtu_info *)malloc(sizeof(ipa_mtu_info));
		if (mtu_info)
		{
			memset(mtu_info, 0, sizeof(ipa_mtu_info));
			memcpy(mtu_info->if_name, dev_name, IPA_IFACE_NAME_LEN);
			fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
			if(fd_wwan_ioctl < 0)
			{
				IPACMERR("Failed to open %s.\n",WWAN_QMI_IOCTL_DEVICE_NAME);
			}
			else
			{
				IPACMDBG_H("send WAN_IOC_GET_WAN_MTU for %s\n", mtu_info->if_name);
				if(ioctl(fd_wwan_ioctl, WAN_IOC_GET_WAN_MTU, mtu_info))
				{
					IPACMERR("Failed to send WAN_IOC_GET_WAN_MTU\n ");
				}
				else
				{
					/* Updated MTU values.*/
					if (mtu_info->mtu_v4)
					{
						mtu_v4 = mtu_info->mtu_v4;
						mtu_v4_set = true;
						IPACMDBG_H("Updated v4 mtu=[%d] for (%s)\n",
							mtu_v4, mtu_info->if_name);
					}
					if (mtu_info->mtu_v6)
					{
						mtu_v6 = mtu_info->mtu_v6;
						mtu_v6_set = true;
						IPACMDBG_H("Updated v6 mtu=[%d] for (%s)\n",
							mtu_v6, mtu_info->if_name);
					}
				}
				close(fd_wwan_ioctl);
			}
			free(mtu_info);
		}
	}
#endif

	modem_ipv6_pdn_index = -1;
	modem_ipv4_pdn_index = -1;

	sta_ipv6_pdn_index = -1;
	sta_ipv4_pdn_index = -1;
	sta_vlan_id = 0;
#ifdef FEATURE_VLAN_MPDN
	associated_VID = 0;
#endif

	if(m_is_sta_mode == Q6_WAN)
	{
		IPACMDBG_H("The new WAN interface is modem.\n");
		is_default_gateway = false;
		query_ext_prop();
	}
	else
	{
		IPACMDBG_H("The new WAN interface is WLAN STA.\n");
	}

	m_fd_ipa = open(IPA_DEVICE_NAME, O_RDWR);
	if(m_fd_ipa < 0)
	{
		IPACMERR("Failed to open %s\n",IPA_DEVICE_NAME);
	}
	if(iface_query != NULL)
	{
		wan_client_len = (sizeof(ipa_wan_client)) + (iface_query->num_tx_props * sizeof(wan_client_rt_hdl));
		wan_client = (ipa_wan_client *)calloc(IPA_MAX_NUM_WAN_CLIENTS, wan_client_len);
		if (wan_client == NULL)
		{
			IPACMERR("unable to allocate memory\n");
			close(m_fd_ipa);
			return;
		}
		IPACMDBG_H("index:%d constructor: Tx properties:%d\n", iface_index, iface_query->num_tx_props);
	}
#ifdef FEATURE_IPACM_UL_FIREWALL
	m_fd_ipa_ul = m_fd_ipa;
#endif //FEATURE_IPACM_UL_FIREWALL
	if(IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_cat == EMBMS_IF)
	{
		IPACMDBG(" IPACM->IPACM_Wan_eMBMS(%d)\n", ipa_if_num);
		embms_is_on = true;
		install_wan_filtering_rule(false);
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Add corresponding ipa_rm_resource_name of TX-endpoint up before IPV6 RT-rule set */
			if(tx_prop != NULL)
			{
				IPACMDBG_H("dev %s add producer dependency\n", dev_name);
				IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
				IPACM_Iface::ipacmcfg->AddRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe],false);
			}
		}
	}
	else
	{
		IPACMDBG(" IPACM->IPACM_Wan(%d)\n", ipa_if_num);
	}

#ifdef IPA_IOC_FLT_MEM_PERIPHERAL_SET_PRIO_HIGH
	if (strstr(dev_name, STR_ETH0_IFACE))
		IPACM_Wan::m_filtering.setFltSramPrioHigh(IPA_CLIENT_ETHERNET_PROD);
	else if (strstr(dev_name, STR_ETH1_IFACE))
		IPACM_Wan::m_filtering.setFltSramPrioHigh(IPA_CLIENT_ETHERNET2_PROD);
#endif
#ifdef FEATURE_PMIPV6
	ipgre_route_data_init(IPA_IP_v4);
	ipgre_route_data_init(IPA_IP_v6);
#endif

#ifdef FEATURE_PPPOE
	if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable && is_ppp_iface)
	{
		IPACM_Iface::ipacmcfg->get_pppoe_vlan_id(dev_name, &sta_vlan_id);
	}
#endif
	if(IPACM_Iface::ipacmcfg->get_vlan_id(dev_name, &sta_vlan_id))
	{
		IPACMERR("failed to get iface vlan ID\n");
	}

	return;
}

IPACM_Wan::~IPACM_Wan()
{
	if (wan_route_rule_v4_hdl != NULL)
	{
		free(wan_route_rule_v4_hdl);
	}
	if (wan_route_rule_v6_hdl != NULL)
	{
		free(wan_route_rule_v6_hdl);
	}
	if (wan_client != NULL)
	{
		free(wan_client);
	}
	if (ext_prop != NULL)
	{
		free(ext_prop);
	}
#ifdef FEATURE_PMIPV6
	ipgre_clear_route_data(IPA_IP_v4);
	ipgre_clear_route_data(IPA_IP_v6);
#endif
	IPACM_EvtDispatcher::deregistr(this);
	IPACM_IfaceManager::deregistr(this);
	if(m_fd_ipa)
		close(m_fd_ipa);
	return;
}
#ifdef FEATURE_PMIPV6
void IPACM_Wan::ipgre_route_data_init(
	enum ipa_ip_type iptype )
{
	if ( ! VALID_IPA_IP_TYPE(iptype) )
	{
		IPACMERR("Invalid IP type passed to function\n");
		return;
	}

	memset(&(IPACM_Wan::ipgre_route_data[iptype]),
		   0,
		   sizeof(ipgre_route_data_t));
}
#endif
#ifdef FEATURE_VLAN_MPDN

int IPACM_Wan::GetMuxByVid(uint16_t vlan_id, uint8_t *mux_id, ipa_ip_type iptype)
{
	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		if(iptype == IPA_IP_v4)
		{
			if (!(IPACM_Wan::ipv4_to_iface[i].pIface))
			{
				IPACMERR("couldn't find MUX for VID %d\n", vlan_id);
				continue;
			}
			if(IPACM_Wan::ipv4_to_iface[i].ipv4_addr)
			{
				for(int j = 0; j <  ipv4_to_iface[i].VID_cnt; j++)
				{
					if(IPACM_Wan::ipv4_to_iface[i].associated_VIDs[j] == vlan_id)
					{
						if(IPACM_Wan::ipv4_to_iface[i].pIface->ext_prop)
						{
							*mux_id = IPACM_Wan::ipv4_to_iface[i].pIface->ext_prop->ext[0].mux_id;
							return IPACM_SUCCESS;
						}
						else if((IPACM_Wan::ipv4_to_iface[i].pIface->m_is_sta_mode == WLAN_WAN) ||
							(IPACM_Wan::ipv4_to_iface[i].pIface->m_is_sta_mode == ECM_WAN))
						{
							*mux_id = 0;
							return IPACM_SUCCESS;
						}
					}
				}
			}
		}
		else
		{
			if(!(IPACM_Wan::ipv6_to_iface[i].pIface))
			{
				IPACMERR("couldn't find MUX for VID %d\n", vlan_id);
				continue;
			}
			if(IPACM_Wan::ipv6_to_iface[i].ipv6_prefix[0] || IPACM_Wan::ipv6_to_iface[i].ipv6_prefix[1])
			{
				for(int j = 0; j < ipv6_to_iface[i].VID_cnt; j++)
				{
					if(IPACM_Wan::ipv6_to_iface[i].associated_VIDs[j] == vlan_id)
					{
						if(IPACM_Wan::ipv6_to_iface[i].pIface->ext_prop)
						{
							*mux_id = IPACM_Wan::ipv6_to_iface[i].pIface->ext_prop->ext[0].mux_id;
							return IPACM_SUCCESS;
						}
						else if((IPACM_Wan::ipv6_to_iface[i].pIface->m_is_sta_mode == WLAN_WAN) ||
							(IPACM_Wan::ipv6_to_iface[i].pIface->m_is_sta_mode == ECM_WAN))
						{
							*mux_id = 0;
							return IPACM_SUCCESS;
						}
					}
				}
			}
		}
	}
	IPACMERR("couldn't find MUX for VID %d\n", vlan_id);
	return IPACM_FAILURE;
}

int IPACM_Wan::GetMTUByVid(uint16_t *mtu, uint16_t vlan_id, ipa_ip_type iptype)
{
	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		if(iptype == IPA_IP_v4)
		{
			if(IPACM_Wan::ipv4_to_iface[i].ipv4_addr)
			{
				for(int j = 0; j < ipv4_to_iface[i].VID_cnt; j++)
				{
					if(IPACM_Wan::ipv4_to_iface[i].associated_VIDs[j] == vlan_id)
					{
						*mtu = IPACM_Wan::ipv4_to_iface[i].pIface->mtu_v4;
						return IPACM_SUCCESS;
					}
				}
			}
		}
		else
		{
			if(IPACM_Wan::ipv6_to_iface[i].ipv6_prefix[0] || IPACM_Wan::ipv6_to_iface[i].ipv6_prefix[1])
			{
				for(int j = 0; j < ipv6_to_iface[i].VID_cnt; j++)
				{
					if(IPACM_Wan::ipv6_to_iface[i].associated_VIDs[j] == vlan_id)
					{
						*mtu = IPACM_Wan::ipv6_to_iface[i].pIface->mtu_v6;
						return IPACM_SUCCESS;
					}
				}
			}
		}
	}
	IPACMERR("couldn't find MTU for VID %d for ip_type %d, using default size:%d \n", vlan_id, iptype, DEFAULT_MTU_SIZE);
	*mtu = DEFAULT_MTU_SIZE;
	return IPACM_FAILURE;
}

int IPACM_Wan::GetWanPDNinfo(uint16_t *mtu, uint32_t *ipv4_addr, ipa_ip_type iptype)
{
	int num_mtu = 0;

	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
			if(ipv4_to_iface[i].ipv4_addr)
			{
				mtu[num_mtu] = ipv4_to_iface[i].pIface->mtu_v4;
				ipv4_addr[num_mtu] = ipv4_to_iface[i].ipv4_addr;
				IPACMERR("iface %s has MTU %d and ipv4_addr 0x%x\n",
					ipv4_to_iface[i].pIface->dev_name,
					mtu[num_mtu], ipv4_addr[num_mtu]);
				num_mtu++;
			}
	}
	IPACMDBG_H("Found %d MTUs for ip_type %d\n", num_mtu, iptype);
	return num_mtu;
}


int IPACM_Wan::GetWanPDNinfo_v6(uint16_t *mtu, uint32_t (*ipv6_prefix)[2], ipa_ip_type iptype)
{
	int num_mtu = 0;

	for (int j = 0; j < (IPACM_Iface::ipacmcfg->num_ipv6_prefixes); j++)
	{
		for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
		{
			if((ipv6_to_iface[i].ipv6_prefix[0] ||
				ipv6_to_iface[i].ipv6_prefix[1]) &&
				(ipv6_to_iface[i].ipv6_prefix[0] ==
					IPACM_Iface::ipacmcfg->ipa_ipv6_prefixes[j].addr[0]) &&
				(ipv6_to_iface[i].ipv6_prefix[1] ==
					IPACM_Iface::ipacmcfg->ipa_ipv6_prefixes[j].addr[1]))
			{
				mtu[num_mtu] = ipv6_to_iface[i].pIface->mtu_v6;
				ipv6_prefix[num_mtu][0] = ipv6_to_iface[i].ipv6_prefix[0];
				ipv6_prefix[num_mtu][1] = ipv6_to_iface[i].ipv6_prefix[1];
				IPACMERR("iface %s has MTU %d and ipv6_addr 0x%08x:%08x\n",
					ipv6_to_iface[i].pIface->dev_name,
					mtu[num_mtu], ipv6_prefix[num_mtu][0], ipv6_prefix[num_mtu][1]);
				num_mtu++;
			}
		}
	}
	IPACMDBG_H("Found %d MTUs for ip_type %d\n", num_mtu, iptype);
	return num_mtu;
}

int IPACM_Wan::Getv6addrByName(char* pdn_name, uint32_t* ipv6_addr)
{
	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		if(ipv6_to_iface[i].pIface == NULL)
		{
			IPACMERR("PDN %s is down\n", pdn_name);
			continue;
		}
		if(strncmp(pdn_name, ipv6_to_iface[i].pIface->dev_name, sizeof(pdn_name)) == 0)
		{
			memcpy(ipv6_addr, ipv6_to_iface[i].pIface->m_ipv6_addr, sizeof(ipv6_to_iface[i].pIface->m_ipv6_addr));
			return IPACM_SUCCESS;
		}
	}
	IPACMERR("couldn't find PDN for name %s\n", pdn_name);
	return IPACM_FAILURE;
}

uint32_t IPACM_Wan::GetQCMAPhdrByName(char* pdn_name)
{
	struct ipa_ioc_get_hdr hdr;

	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		if(strncmp(pdn_name, ipv6_to_iface[i].pIface->dev_name, sizeof(pdn_name)) == 0)
		{
			strlcpy(hdr.name, ipv6_to_iface[i].pIface->tx_prop->tx[0].hdr_name, sizeof(hdr.name));
			hdr.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
			if(m_header.GetHeaderHandle(&hdr) == false)
			{
				IPACMERR("Failed to get QMAP header.\n");
				return 0;
			}
			return hdr.hdl;
		}
	}
	IPACMERR("couldn't find PDN for name %s\n", pdn_name);
	return 0;
}

/* Find first rmnet_dataX interface that has a proper QMAP header */
uint32_t IPACM_Wan::GetQCMAPhdrOfFirstRmnet(ipa_ip_type ipType)
{
	struct ipa_ioc_get_hdr hdr;
	ipacm_ipv4_wan_iface *it4;
	ipacm_ipv6_wan_iface *it6;

	switch (ipType) {
	case IPA_IP_v4:
		it4 = std::find_if(ipv4_to_iface, ipv4_to_iface + IPA_MAX_NUM_SW_PDNS,
			[](const decltype(ipv4_to_iface[0])& i) {
			return i.pIface && strstr(i.pIface->dev_name, RMNET_IFACE_NAME);});

		if (it4 >= ipv4_to_iface + IPA_MAX_NUM_SW_PDNS) {
			IPACMERR("couldn't find QMAP header for name %s...\n", RMNET_IFACE_NAME);
			return 0;
		}

		IPACMDBG_H("PDN name = %s\n", it4->pIface->dev_name);
		strlcpy(hdr.name, it4->pIface->tx_prop->tx[0].hdr_name, sizeof(hdr.name));
		break;
	case IPA_IP_v6:
		it6 = std::find_if(ipv6_to_iface, ipv6_to_iface + IPA_MAX_NUM_SW_PDNS,
			[](const decltype(ipv6_to_iface[0])& i) {
			return i.pIface && strstr(i.pIface->dev_name, RMNET_IFACE_NAME);});

		if (it6 >= ipv6_to_iface + IPA_MAX_NUM_SW_PDNS) {
			IPACMERR("couldn't find QMAP header for name %s...\n", RMNET_IFACE_NAME);
			return 0;
		}

		IPACMDBG_H("PDN name = %s\n", it6->pIface->dev_name);
		strlcpy(hdr.name, it6->pIface->tx_prop->tx[0].hdr_name, sizeof(hdr.name));
		break;
	default:
		IPACMERR("Invalid IP type.\n");
		return 0;
	}

	hdr.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
	if(m_header.GetHeaderHandle(&hdr) == false)
	{
		IPACMERR("Failed to get QMAP header.\n");
		return 0;
	}

	return hdr.hdl;
}

bool IPACM_Wan::is_xlat_by_vid(uint16_t vlan_id)
{
	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		if(IPACM_Wan::ipv4_to_iface[i].ipv4_addr)
		{
			for(int j = 0; j < ipv4_to_iface[i].VID_cnt; j++)
			{
				if(IPACM_Wan::ipv4_to_iface[i].associated_VIDs[j] == vlan_id)
					return IPACM_Wan::ipv4_to_iface[i].is_xlat;
			}
		}
	}
	IPACMERR("couldn't find MUX xlat info for VID %d\n", vlan_id);
	return false;
}

int IPACM_Wan::get_vid_index_for_iface_v6(ipacm_ipv6_wan_iface iface, uint16_t vlan_id)
{
	for(int i = 0; i < iface.VID_cnt;i++)
	{
		iface.associated_VIDs[i] == vlan_id;
		return i;
	}

	IPACMDBG("couldn't find VID %d\n in VID array", vlan_id);
	return IPACM_FAILURE;
}

bool IPACM_Wan::is_xlat_by_ipv4(uint32_t ipv4_addr)
{
	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		if(IPACM_Wan::ipv4_to_iface[i].ipv4_addr == ipv4_addr)
			return IPACM_Wan::ipv4_to_iface[i].is_xlat;
	}
	IPACMERR("couldn't find MUX xlat info for ipv4 %d\n", ipv4_addr);
	return false;
}
#endif

#ifdef FEATURE_IPA_IPSEC
/**
* del_ipsec_wan_dl_rt_rules() - Delete IPsec Default Wan DL Routing rules
*
* @iptype: IP type v4 or v6
*
* Returns:	IPACM_SUCCESS on success, IPACM_FAILURE on failure
*/
int IPACM_Wan::del_ipsec_wan_dl_rt_rules(enum ipa_ip_type iptype)
{
	int rt_idx;

	if (iptype == IPA_IP_v6) {
		IPACMDBG_H("Delete default IPsec v6 routing rules\n");
		for (rt_idx = 0; rt_idx < MAX_DEFAULT_IPSEC_v6_ROUTE_RULES; rt_idx++)
		{
			IPACMDBG_H("Delete default IPsec v6 routing handle = %d\n", dft_ipsec_rt_rule_hdl[rt_idx + MAX_DEFAULT_IPSEC_v4_ROUTE_RULES]);
			if (m_routing.DeleteRoutingHdl(dft_ipsec_rt_rule_hdl[rt_idx + MAX_DEFAULT_IPSEC_v4_ROUTE_RULES], iptype) == false)
			{
				IPACMERR("IPv6 IPsec Routing rule(idx:0x%x) deletion failed!\n", rt_idx);
				return IPACM_FAILURE;
			}
			dft_ipsec_rt_rule_hdl[rt_idx + MAX_DEFAULT_IPSEC_v4_ROUTE_RULES] = 0;
		}
	} else {
		IPACMDBG_H("Delete default IPsec v4 routing rules\n");
		for (rt_idx = 0; rt_idx < MAX_DEFAULT_IPSEC_v4_ROUTE_RULES; rt_idx++)
		{
			if (m_routing.DeleteRoutingHdl(dft_ipsec_rt_rule_hdl[rt_idx], iptype) == false)
			{
				IPACMERR("IPv4 IPsec Routing rule(idx:0x%x) deletion failed!\n", rt_idx);
				return IPACM_FAILURE;
			}
			dft_ipsec_rt_rule_hdl[rt_idx] = 0;
		}
	}

	return IPACM_SUCCESS;
}

/**
* add_ipsec_wan_dl_rt_rules() - Add IPsec Default Wan DL Routing rules
*
* @data: data of the address event contains the ip type and ip address
* @tx_prop_hdr_hdl: header hdl for the IPsec rmnet_dataX IP rule
*
* Returns:	IPACM_SUCCESS on success, IPACM_FAILURE on failure
*/
int IPACM_Wan::add_ipsec_wan_dl_rt_rules(ipacm_event_data_addr *data,
	uint32_t tx_prop_hdr_hdl)
{
	struct ipa_ioc_add_rt_rule *rt_rule = NULL;
	struct ipa_rt_rule_add *rt_rule_entry = NULL;
	const int NUM_RULES = 1;
	int res = IPACM_SUCCESS, rt_idx;

	rt_rule = (struct ipa_ioc_add_rt_rule *)
			calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
				NUM_RULES * sizeof(struct ipa_rt_rule_add));
	if (!rt_rule)
	{
		IPACMERR("Error allocating ipa_ioc_add_rt_rule memory\n");
		return IPACM_FAILURE;
	}

	rt_rule->commit = 1;
	rt_rule->num_rules = NUM_RULES;
	rt_rule->ip = data->iptype;
	if (data->iptype == IPA_IP_v6)
		strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule->rt_tbl_name));
	else
		strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name, sizeof(rt_rule->rt_tbl_name));

	/* IPsec post-decap + dest-IP = rmnet_dataX IP */
	rt_rule_entry = &rt_rule->rules[0];
	rt_rule_entry->rule.hdr_hdl = tx_prop_hdr_hdl;
	rt_rule_entry->rule.dst = IPA_CLIENT_IPSEC_APPS_WAN_CONS;
	rt_rule_entry->at_rear = false;
	rt_rule_entry->rule.hashable = true;
	rt_rule_entry->rule.attrib.meta_data = META_IS_IPSEC;
	rt_rule_entry->rule.attrib.meta_data_mask = META_IPSEC_MASK;
	rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR | IPA_FLT_META_DATA;

	if (data->iptype == IPA_IP_v6) {
		rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = data->ipv6_addr[0];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = data->ipv6_addr[1];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = data->ipv6_addr[2];
		rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = data->ipv6_addr[3];
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
	} else { //IPv4
		rt_rule_entry->rule.attrib.u.v4.dst_addr      = data->ipv4_addr;
		rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
	}

	if (false == m_routing.AddRoutingRule(rt_rule))
	{
		IPACMERR("Routing rule addition failed!\n");
		res = IPACM_FAILURE;
		goto bail;
	}

	if (data->iptype == IPA_IP_v6) {
		for (rt_idx = 0; rt_idx < MAX_DEFAULT_IPSEC_v6_ROUTE_RULES; rt_idx++)
		{
			dft_ipsec_rt_rule_hdl[MAX_DEFAULT_IPSEC_v4_ROUTE_RULES + rt_idx] = rt_rule->rules[rt_idx].rt_rule_hdl;
			IPACMDBG_H("Add default IPsec v6 routing handle = %d\n", dft_ipsec_rt_rule_hdl[rt_idx + MAX_DEFAULT_IPSEC_v4_ROUTE_RULES]);
		}
	} else {
		for (rt_idx = 0; rt_idx < MAX_DEFAULT_IPSEC_v4_ROUTE_RULES; rt_idx++)
		{
			dft_ipsec_rt_rule_hdl[rt_idx] = rt_rule->rules[rt_idx].rt_rule_hdl;
		}
	}

bail:
	free(rt_rule);

	return res;
}
#endif

/* handle new_address event */
int IPACM_Wan::handle_addr_evt(ipacm_event_data_addr *data)
{
	struct ipa_ioc_add_rt_rule *rt_rule = NULL;
	struct ipa_rt_rule_add *rt_rule_entry = NULL;
	struct ipa_ioc_add_flt_rule *flt_rule = NULL;
	struct ipa_ioc_add_flt_rule_after *flt_rule_after = NULL;
	struct ipa_flt_rule_add flt_rule_entry = {0};
	struct ipa_ioc_get_hdr hdr = {0};

	const int NUM_RULES = 1;
	int num_ipv6_addr, len;
	int res = IPACM_SUCCESS;
	ipacm_cmd_q_data evt_data;
	ipacm_event_data_fid *data_fid = NULL;
#ifdef FEATURE_STATIC_POLICY
	struct ipa_ioc_pdn_dscp_map_info pdn_dscp_map_info;
#endif

	memset(&hdr, 0, sizeof(hdr));
	if(tx_prop == NULL || rx_prop == NULL)
	{
		IPACMDBG_H("Either tx or rx property is NULL, return.\n");
		return IPACM_SUCCESS;
	}

	/* Update the IP Type. */
	config_ip_type(data->iptype);

#ifdef FEATURE_STATIC_POLICY
	if(pthread_mutex_lock(&IPACM_Iface::ipacmcfg->pdn_dscp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return IPACM_FAILURE;
	}
	for(int indx = 0; indx < IPA_UC_MAX_PDN_DSCP_VAL; indx++)
	{
		if(IPACM_Iface::ipacmcfg->pdn_dscp_table[indx].status == 1)
		{
			IPACM_Iface::ipacmcfg->pdn_dscp_table[indx].mux_id = ext_prop->ext[0].mux_id;
			IPACM_Iface::ipacmcfg->pdn_dscp_table[indx].status = 2;
		}

		if(IPACM_Iface::ipacmcfg->pdn_dscp_table[indx].status == 2)
		{
			ipacm_event_pdn_dscp_info* pdn_dscp_data = (ipacm_event_pdn_dscp_info *)
				malloc(sizeof(ipacm_event_pdn_dscp_info));
			if(pdn_dscp_data == NULL)
			{
				IPACMERR("unable to allocate memory for event pdn_dscp_data\n");
				pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->pdn_dscp_lock);
				return IPACM_FAILURE;
			}

			memset(pdn_dscp_data, 0, sizeof(ipacm_event_pdn_dscp_info));
			pdn_dscp_data->enable = 1;
			pdn_dscp_data->dscp_val =IPACM_Iface::ipacmcfg->pdn_dscp_table[indx].dscp_val;
			pdn_dscp_data->mux_id = IPACM_Iface::ipacmcfg->pdn_dscp_table[indx].mux_id;

			IPACMDBG_H("Posting IPA_PDN_DSCP_UPDATE_EVENT event!\n");

			evt_data.event = IPA_PDN_DSCP_UPDATE_EVENT;
			evt_data.evt_data = pdn_dscp_data;
			IPACM_EvtDispatcher::PostEvt(&evt_data);

			memset(&pdn_dscp_map_info, 0, sizeof(pdn_dscp_map_info));
			memset(&pdn_dscp_map_info.pdn_dscp_map, 255,
				sizeof(pdn_dscp_map_info.pdn_dscp_map));
			pdn_dscp_map_info.add = 1;
			pdn_dscp_map_info.pdn_dscp_map[IPACM_Iface::ipacmcfg->pdn_dscp_table[indx].mux_id] =
				IPACM_Iface::ipacmcfg->pdn_dscp_table[indx].dscp_val;
			if(0 != ioctl(m_fd_ipa, IPA_IOC_UPDATE_PDN_DSCP_MAPPING, &pdn_dscp_map_info))
			{
				IPACMERR("ioctl to IPA driver failed for setting PDN-DSCP Mapping\n");
			}
		}
	}
	pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->pdn_dscp_lock);
#endif

	if (data->iptype == IPA_IP_v6)
	{
		for(num_ipv6_addr=0;num_ipv6_addr<num_dft_rt_v6;num_ipv6_addr++)
		{
			if((ipv6_addr[num_ipv6_addr][0] == data->ipv6_addr[0]) &&
			   (ipv6_addr[num_ipv6_addr][1] == data->ipv6_addr[1]) &&
			   (ipv6_addr[num_ipv6_addr][2] == data->ipv6_addr[2]) &&
			   (ipv6_addr[num_ipv6_addr][3] == data->ipv6_addr[3]))
			{
				IPACMDBG_H("find matched ipv6 address, index:%d \n", num_ipv6_addr);
				return IPACM_SUCCESS;
				break;
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
		if(m_is_sta_mode == Q6_WAN)
		{
			strlcpy(hdr.name, tx_prop->tx[0].hdr_name, sizeof(hdr.name));
			hdr.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
			if(m_header.GetHeaderHandle(&hdr) == false)
			{
				IPACMERR("Failed to get QMAP header.\n");
				res = IPACM_FAILURE;
				goto fail;
			}
		}

		rt_rule_entry = &rt_rule->rules[0];
		rt_rule_entry->at_rear = false;
		if(m_is_sta_mode == Q6_WAN)
		{
			rt_rule_entry->rule.hdr_hdl = hdr.hdl;
			rt_rule_entry->rule.dst = IPA_CLIENT_APPS_WAN_CONS;
		}
		else
		{
			rt_rule_entry->rule.dst = IPA_CLIENT_APPS_LAN_CONS;
		}
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
#ifdef FEATURE_IPA_IPSEC
		if(m_is_sta_mode == Q6_WAN && is_global_ipv6_addr(data->ipv6_addr)) {
			res = add_ipsec_wan_dl_rt_rules(data, hdr.hdl);
			if (res == IPACM_FAILURE)
				goto fail;
		}
#endif
		IPACMDBG_H("Now the number of modem ipv6 pdn is %d, num_dft_rt_v6 %d.\n", num_ipv6_modem_pdn, num_dft_rt_v6);
		/* add default filtering rules when wan-iface get global v6-prefix,
		 */
		if (num_dft_rt_v6 == 1)
		{
			if(m_is_sta_mode == Q6_WAN)
			{
				num_ipv6_modem_pdn++;
				IPACMDBG_H("Now the number of modem ipv6 pdn is %d.\n", num_ipv6_modem_pdn);
				init_fl_rule_ex(data->iptype);
			}
			else
			{
				num_ipv6_sta_pdn++;
				IPACMDBG_H("Now the number of STA ipv6 pdn is %d.\n", num_ipv6_sta_pdn);
				init_fl_rule(data->iptype);
			}
		}

		/* Add default filtering rules when wan-iface get link local when eth_wan_pppoe_enable */
		if(!is_global_ipv6_addr(data->ipv6_addr) && IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable)
		{
			if(m_is_sta_mode != Q6_WAN)
			{
				IPACMDBG_H("Add dft rule with link local addr handling, Now the number of STA ipv6 pdn is %d.\n", num_ipv6_sta_pdn);
				init_fl_rule(data->iptype);
			}
		}

		/* store ipv6 prefix if the ipv6 address is not link local */
		if(is_global_ipv6_addr(data->ipv6_addr))
		{
			memcpy(ipv6_prefix, data->ipv6_addr, sizeof(ipv6_prefix));
			memcpy(m_ipv6_addr, data->ipv6_addr, sizeof(m_ipv6_addr));
#ifdef FEATURE_VLAN_MPDN
			if(m_is_sta_mode == Q6_WAN)
			{
				if (modem_ipv6_pdn_index == -1) {
					modem_ipv6_pdn_index = getFreePDNIndex_V6();
					if (modem_ipv6_pdn_index == -1)
					{
						IPACMERR("No Free index available.!\n");
						res = IPACM_FAILURE;
						goto fail;
					}
				}
				memcpy(ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix, data->ipv6_addr, sizeof(uint32_t) * 2);
				ipv6_to_iface[modem_ipv6_pdn_index].pIface = this;
				IPACMDBG_H("index %d prefix: 0x%08x%08x\n", modem_ipv6_pdn_index,
					ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[0],
					ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[1]);

			}
			else if(m_is_sta_mode == WLAN_WAN || m_is_sta_mode == ECM_WAN)
			{
				if(sta_ipv6_pdn_index == -1)
				{
					sta_ipv6_pdn_index = getFreePDNIndex_V6();
					if(sta_ipv6_pdn_index == -1)
					{
						//add this prefix to no_offload_ipv6_prefix
						IPACM_Iface::ipacmcfg->add_no_offload_ipv6_prefix(ipv6_prefix);
						IPACMERR("No Free index available!\n");
						res = IPACM_FAILURE;
						goto fail;
					}
				}
				memcpy(ipv6_to_iface[sta_ipv6_pdn_index].ipv6_prefix, data->ipv6_addr, sizeof(uint32_t) * 2);
				ipv6_to_iface[sta_ipv6_pdn_index].pIface = this;
				ipv6_to_iface[sta_ipv6_pdn_index].wan_up_vlan_v6 = false;
				IPACM_Iface::ipacmcfg->add_no_offload_ipv6_prefix(ipv6_to_iface[sta_ipv6_pdn_index].ipv6_prefix);
				IPACMDBG_H("index %d prefix: 0x%08x%08x\n", sta_ipv6_pdn_index,
					ipv6_to_iface[sta_ipv6_pdn_index].ipv6_prefix[0],
					ipv6_to_iface[sta_ipv6_pdn_index].ipv6_prefix[1]);
			}
#endif
			/* Check to handle the race-cond, if route_add recevied before handle_addr_evt */
			IPACMDBG_H("is_xlat :%d, active_v6: %d, wan_v6_addr_gw_set: %d \n", is_xlat, active_v6, wan_v6_addr_gw_set);
			if(is_xlat && active_v6 && ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[0] && ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[1])
			{
				IPACM_Iface::ipacmcfg->add_vlan_ipv6_prefix(ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix, ipa_if_num, associated_VID);

				if(m_is_sta_mode == Q6_WAN)
				{
					config_wan_firewall_rule(IPA_IP_v6);
					install_wan_filtering_rule(false);
				}
				else
				{
					del_dft_firewall_rules(IPA_IP_v6);
					config_dft_firewall_rules(IPA_IP_v6);
				}

				//need to post handle_wan_up_v6 to enable conntrack for XLAT mode
				ipacm_cmd_q_data evt_data;
				ipacm_event_iface_up *wanup_data;

				memset(&evt_data, 0, sizeof(evt_data));
				wanup_data = (ipacm_event_iface_up *)malloc(sizeof(ipacm_event_iface_up));
				if (wanup_data == NULL)
				{
					IPACMERR("Unable to allocate memory\n");
					free(rt_rule);
					return IPACM_FAILURE;
				}
				memset(wanup_data, 0, sizeof(ipacm_event_iface_up));

				memcpy(wanup_data->ifname, dev_name, sizeof(wanup_data->ifname));
				if (m_is_sta_mode!=Q6_WAN)
				{
					wanup_data->is_sta = true;
				}
				else
				{
					wanup_data->is_sta = false;
				}

				memcpy(wanup_data->ipv6_prefix, ipv6_prefix, sizeof(wanup_data->ipv6_prefix));
				memcpy(wanup_data->ipv6_addr, m_ipv6_addr, sizeof(wanup_data->ipv6_addr));

				IPACMDBG_H("Posting IPA_HANDLE_WAN_UP_V6 with below information:\n");
				IPACMDBG_H("if_name:%s, is sta mode: %d\n", wanup_data->ifname, wanup_data->is_sta);
				IPACMDBG_H("ipv6 prefix: 0x%08x%08x.\n", ipv6_prefix[0], ipv6_prefix[1]);
				IPACMDBG_H("ipv6 addr: 0x%08x%08x%08x%08x\n", m_ipv6_addr[0], m_ipv6_addr[1], m_ipv6_addr[2], m_ipv6_addr[3]);
				memset(&evt_data, 0, sizeof(evt_data));
				evt_data.event = IPA_HANDLE_WAN_UP_V6;
				evt_data.evt_data = (void *)wanup_data;
				IPACM_EvtDispatcher::PostEvt(&evt_data);
			}
		}

		/* add WAN DL interface IP specific flt rule for IPv6 when backhaul is not Q6 */
		if(m_is_sta_mode != Q6_WAN  && num_dft_rt_v6 == 1)
		{
			if(is_xlat && active_v6 && ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[0] && ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[1])
			{
				del_dft_firewall_rules(IPA_IP_v6);
				config_dft_firewall_rules(IPA_IP_v6);
			}
			IPACMDBG_H("odu_subnet_fl_rule_hdl: %d\n", IPACM_Iface::odu_subnet_fl_rule_hdl[IPA_IP_v6]);
			if(rx_prop != NULL
				&& num_ipv6_dest_flt_rule < MAX_DEFAULT_v6_ROUTE_RULES)
			{
				if(IPACM_Iface::ipacmcfg->get_eth_vlan_wan_up(ipa_if_num) == IPACM_SUCCESS &&
					IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_cat == WAN_IF &&
					IPACM_Iface::odu_subnet_fl_rule_hdl[IPA_IP_v6] &&
					(IPACM_Iface::ipacmcfg->eth_vlan_wan_enable == true))
				{
					len = sizeof(struct ipa_ioc_add_flt_rule_after) + sizeof(struct ipa_flt_rule_add);
					flt_rule_after = (struct ipa_ioc_add_flt_rule_after *)calloc(1, len);
					if (!flt_rule_after)
					{
						IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
						return IPACM_FAILURE;
					}
					flt_rule_after->add_after_hdl = IPACM_Iface::odu_subnet_fl_rule_hdl[IPA_IP_v6];
					flt_rule_after->commit = 1;
					flt_rule_after->ep = rx_prop->rx[0].src_pipe;
					flt_rule_after->ip = IPA_IP_v6;
					flt_rule_after->num_rules = 1;
				}
				else
				{
					len = sizeof(struct ipa_ioc_add_flt_rule) + sizeof(struct ipa_flt_rule_add);
					flt_rule = (struct ipa_ioc_add_flt_rule *)calloc(1, len);
					if (!flt_rule)
					{
						IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
						return IPACM_FAILURE;
					}
					flt_rule->global = false;
					flt_rule->commit = 1;
					flt_rule->ep = rx_prop->rx[0].src_pipe;
					flt_rule->ip = IPA_IP_v6;
					flt_rule->num_rules = 1;
				}
				memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

				flt_rule_entry.rule.retain_hdr = 1;
				flt_rule_entry.rule.to_uc = 0;
				flt_rule_entry.rule.eq_attrib_type = 0;
				flt_rule_entry.at_rear = true;
				flt_rule_entry.flt_rule_hdl = -1;
				flt_rule_entry.status = -1;
				flt_rule_entry.rule.action = IPA_PASS_TO_EXCEPTION;
#ifdef FEATURE_IPA_V3
				flt_rule_entry.rule.hashable = true;
#endif
				memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[0].attrib, sizeof(flt_rule_entry.rule.attrib));

				flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
				memcpy(flt_rule_entry.rule.attrib.u.v6.dst_addr, m_ipv6_addr, sizeof(flt_rule_entry.rule.attrib.u.v6.dst_addr));
				flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
				flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
				flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
				flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;

				if(IPACM_Iface::ipacmcfg->get_eth_vlan_wan_up(ipa_if_num) == IPACM_SUCCESS &&
					IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_cat == WAN_IF &&
					IPACM_Iface::odu_subnet_fl_rule_hdl[IPA_IP_v6] &&
					(IPACM_Iface::ipacmcfg->eth_vlan_wan_enable == true))
				{
					memcpy(&(flt_rule_after->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
					if (m_filtering.AddFilteringRuleAfter(flt_rule_after) == false)
					{
						IPACMERR("Error Adding Filtering rule, aborting...\n");
						free(flt_rule_after);
						res = IPACM_FAILURE;
						goto fail;
					}
					else
					{
						IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);
						ipv6_dest_flt_rule_hdl[num_ipv6_dest_flt_rule] = flt_rule_after->rules[0].flt_rule_hdl;
						IPACMDBG_H("IPv6 dest filter rule %d HDL:0x%x\n", num_ipv6_dest_flt_rule, ipv6_dest_flt_rule_hdl[num_ipv6_dest_flt_rule]);
						num_ipv6_dest_flt_rule++;
						free(flt_rule_after);
					}
				}
				else
				{
					memcpy(&(flt_rule->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
					if (m_filtering.AddFilteringRule(flt_rule) == false)
					{
						IPACMERR("Error Adding Filtering rule, aborting...\n");
						free(flt_rule);
						res = IPACM_FAILURE;
						goto fail;
					}
					else
					{
						IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);
						ipv6_dest_flt_rule_hdl[num_ipv6_dest_flt_rule] = flt_rule->rules[0].flt_rule_hdl;
						IPACMDBG_H("IPv6 dest filter rule %d HDL:0x%x\n", num_ipv6_dest_flt_rule, ipv6_dest_flt_rule_hdl[num_ipv6_dest_flt_rule]);
						num_ipv6_dest_flt_rule++;
						free(flt_rule);
					}
				}
			}
		}
		else if((m_is_sta_mode == Q6_WAN) && is_xlat && active_v6 &&
			 ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[0] &&
			 ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[1])
		{
			config_wan_firewall_rule(IPA_IP_v6);
			install_wan_filtering_rule(false);
		}
		num_dft_rt_v6++;
	}
	else
	{
#if defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
		if(m_is_sta_mode == Q6_WAN)
		{
			/* add qmuxd mapping*/
			rmnet_mux_id_info info;
			info.ipv4_addr = data->ipv4_addr;
			if(ext_prop != NULL)
				info.mux_id = ext_prop->ext[0].mux_id;;
			memcpy(info.iface_name, dev_name, sizeof(dev_name));
			IPACM_Iface::ipacmcfg->add_mux_id_mapping(&info);
		}
#endif // defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
		if(wan_v4_addr_set)
		{
			/* check iface ipv4 same or not */
			if(data->ipv4_addr == wan_v4_addr)
			{
				IPACMDBG_H("Already setup device (%s) ipv4 and it didn't change(0x%x)\n", dev_name, data->ipv4_addr);
				return IPACM_SUCCESS;
			}
			else
			{
				IPACMDBG_H(" device (%s) ipv4 addr is changed\n", dev_name);
				/*Don't remove route for WAN IP in IP Passthrough or Collision mode
				it may lead to stall as NAT entry is still pointing to
				default route entry*/
				if (!ip_pass_pdn_info.enable && !ip_collision_pdn_info.enable)
				{
					/* Delete default v4 RT rule */
					IPACMDBG_H("Delete default v4 routing rules\n");
					if (m_routing.DeleteRoutingHdl(dft_rt_rule_hdl[0],
									 IPA_IP_v4) == false)
					{
						IPACMERR("Routing old RT rule deletion failed!\n");
						res = IPACM_FAILURE;
						goto fail;
					}
					dft_rt_rule_hdl[0] = 0;
#ifdef FEATURE_IPA_IPSEC
					/* Delete default IPsec v4 RT rules */
					IPACMDBG_H("Delete IPsec default v4 routing rules\n");
					if (del_ipsec_wan_dl_rt_rules(IPA_IP_v4) == IPACM_FAILURE)
					{
						IPACMERR("Routing old IPsec RT rules deletion failed!\n");
						res = IPACM_FAILURE;
						goto fail;
					}
#endif
				}
				else
				{
					/* In IPPT or IP Collision mode don't replace the wan-ip RT rule to dummy ipv4 */
					/*Store the public ip address when in passthrough mode which will be used when wan is down.*/
					if (m_is_sta_mode == Q6_WAN)
					{
						curr_wan_ip = data->ipv4_addr;
						public_wan_v4_addr = wan_v4_addr;
						public_wan_v4_addr_set = true;
						IPACMDBG_H("Received wan ipv4-addr:0x%x\n",data->ipv4_addr);
						IPACMDBG_H("In Passthrough mode, Storing previous wan ipv4-addr:0x%x\n",public_wan_v4_addr);
						return IPACM_SUCCESS;
					}
				}
#if defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
				if(m_is_sta_mode == Q6_WAN)
				{
					rmnet_mux_id_info info;
					/* clean old mapping */
					info.ipv4_addr = wan_v4_addr;
					if (ext_prop != NULL)
						info.mux_id = ext_prop->ext[0].mux_id;;
					memcpy(info.iface_name, dev_name, sizeof(dev_name));
					IPACM_Iface::ipacmcfg->del_mux_id_mapping(&info);
					/* add qmuxd mapping*/
					info.ipv4_addr = data->ipv4_addr;
					if (ext_prop != NULL)
						info.mux_id = ext_prop->ext[0].mux_id;;
					IPACM_Iface::ipacmcfg->add_mux_id_mapping(&info);
				}
#endif // defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
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
		if(m_is_sta_mode == Q6_WAN)
		{
			strlcpy(hdr.name, tx_prop->tx[0].hdr_name, sizeof(hdr.name));
			hdr.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
			if(m_header.GetHeaderHandle(&hdr) == false)
			{
				IPACMERR("Failed to get QMAP header.\n");
				res = IPACM_FAILURE;
				goto fail;
			}
		}

		rt_rule_entry = &rt_rule->rules[0];
		if(m_is_sta_mode == Q6_WAN)
		{
			rt_rule_entry->rule.hdr_hdl = hdr.hdl;
			rt_rule_entry->rule.dst = IPA_CLIENT_APPS_WAN_CONS;
		}
		else
		{
			rt_rule_entry->rule.dst = IPA_CLIENT_APPS_LAN_CONS;
		}
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR;
		/* still need setup v4 default routing rule to A5*/
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
		IPACMDBG_H("ipv4 wan iface rt-rule hdll=0x%x\n", dft_rt_rule_hdl[0]);
#ifdef FEATURE_IPA_IPSEC
		if(m_is_sta_mode == Q6_WAN) {
			res = add_ipsec_wan_dl_rt_rules(data, hdr.hdl);
			if (res == IPACM_FAILURE)
				goto fail;
		}
#endif

		/* initial multicast/broadcast/fragment filter rule */
		/* only do one time */
		if(!wan_v4_addr_set)
		{
			/* initial multicast/broadcast/fragment filter rule */
			if(m_is_sta_mode == Q6_WAN)
			{
#ifdef FEATURE_VLAN_MPDN
				modem_ipv4_pdn_index = getFreePDNIndex_V4();
				if (modem_ipv4_pdn_index == -1)
				{
					IPACMERR("No Free index available.!\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				ipv4_to_iface[modem_ipv4_pdn_index].ipv4_addr = data->ipv4_addr;
				ipv4_to_iface[modem_ipv4_pdn_index].pIface = this;
#endif
				num_ipv4_modem_pdn++;
				IPACMDBG_H("Now the number of modem ipv4 pdn is %d.\n", num_ipv4_modem_pdn);
				init_fl_rule_ex(data->iptype);
				if (is_xlat)
					IPACM_Wan::ipv4_to_iface[modem_ipv4_pdn_index].is_xlat = true;
			}
			if (m_is_sta_mode == WLAN_WAN || m_is_sta_mode == ECM_WAN)
			{
				sta_ipv4_pdn_index = getFreePDNIndex_V4();

				if (sta_ipv4_pdn_index == -1)
				{
					IPACMERR("No Free index available.!\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				ipv4_to_iface[sta_ipv4_pdn_index].ipv4_addr = data->ipv4_addr;
				ipv4_to_iface[sta_ipv4_pdn_index].pIface = this;
				num_ipv4_sta_pdn++;
				ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan = false;
				IPACMDBG_H("STA %d ipv4 pdn is index:%d num:%d.\n", m_is_sta_mode, sta_ipv4_pdn_index, num_ipv4_sta_pdn);

				init_fl_rule(data->iptype);
			}
		}

		/* Store the public ip address when in passthrough mode which will be used when wan is down. */
		if ((m_is_sta_mode == Q6_WAN) &&
			((ip_pass_pdn_info.enable)||
			(ip_collision_pdn_info.enable)))
		{
			curr_wan_ip = data->ipv4_addr;
			public_wan_v4_addr = wan_v4_addr;
			public_wan_v4_addr_set = true;
			IPACMDBG_H("In Passthrough mode, Storing previous wan ipv4-addr:0x%x\n",public_wan_v4_addr);
		}
		else
		{
			IPACMDBG_H("Not in passthrough mode, reset previous wan ipv4-addr:0x%x\n",public_wan_v4_addr);
			public_wan_v4_addr = 0;
			public_wan_v4_addr_set = false;
			wan_v4_addr = data->ipv4_addr;
			wan_v4_addr_set = true;
		}

		IPACMDBG_H("Received wan ipv4-addr:0x%x\n",wan_v4_addr);
	}

	IPACMDBG_H("number of v6 default route rules %d\n", num_dft_rt_v6);

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
fail:
	if(rt_rule)
		free(rt_rule);

	return res;
}

/* handle del_address event */
int IPACM_Wan::handle_addr_del_evt(ipacm_event_data_addr *data)
{
	uint32_t num_ipv6_addr, num_v6_value;
	int res = IPACM_SUCCESS;
	int i = 0;

	if (tx_prop == NULL || rx_prop == NULL)
	{
		IPACMDBG_H("Either tx or rx property is NULL, return.\n");
		return IPACM_SUCCESS;
	}

	if (data->iptype == IPA_IP_v6 && m_is_sta_mode == Q6_WAN)
	{
		num_v6_value = num_dft_rt_v6;
		/* Check the address deleted. */
		for (num_ipv6_addr = 0; num_ipv6_addr < MAX_DEFAULT_v6_ROUTE_RULES; num_ipv6_addr++)
		{
			if((ipv6_addr[num_ipv6_addr][0] == data->ipv6_addr[0]) &&
			(ipv6_addr[num_ipv6_addr][1] == data->ipv6_addr[1]) &&
			(ipv6_addr[num_ipv6_addr][2] == data->ipv6_addr[2]) &&
			(ipv6_addr[num_ipv6_addr][3] == data->ipv6_addr[3]))
			{
				IPACMDBG_H("find matched ipv6 address, index:%d \n", num_ipv6_addr);
				for (i = 0; i < MAX_DEFAULT_v6_ROUTE_RULES; i++)
				{
					if (m_routing.DeleteRoutingHdl(dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES+2*num_ipv6_addr+i], IPA_IP_v6) == false)
					{
						IPACMERR("Routing rule deletion failed!\n");
						res = IPACM_FAILURE;
						goto fail;
					}
					dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES+2*num_ipv6_addr+i] = 0;
				}
#ifdef FEATURE_VLAN_MPDN
				if ((data->ipv6_addr[0] == ipv6_prefix[0]) && (data->ipv6_addr[1] == ipv6_prefix[1]))
				{
					IPACMDBG_H("Del vlan ipv6_prefix:0x%x%x\n", ipv6_prefix[0], ipv6_prefix[1]);
					if (is_xlat)
						IPACM_Iface::ipacmcfg->del_vlan_ipv6_prefix(ipv6_prefix, -1, true);
					else
						IPACM_Iface::ipacmcfg->del_vlan_ipv6_prefix(ipv6_prefix, -1);
				}
#endif
				if (num_dft_rt_v6 > 0)
					num_dft_rt_v6--;
				IPACMDBG_H("v6 num: %d\n",num_dft_rt_v6);
			}
		}
	}
	else if (data->iptype == IPA_IP_v4)
	{
		if (m_is_sta_mode == Q6_WAN)
		{
			IPACMDBG_H("IPv4 addr del evt is not handled.\n");
		}
		else
		{
			if(wan_v4_addr_set)
			{
				/* Delete default v4 RT rule */
				IPACMDBG_H("Delete default v4 routing rules\n");
				if (m_routing.DeleteRoutingHdl(dft_rt_rule_hdl[0],
					IPA_IP_v4) == false)
				{
					IPACMERR("Routing old RT rule deletion failed!\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				dft_rt_rule_hdl[0] = 0;
#ifdef FEATURE_IPA_IPSEC
				/* Delete default IPsec v4 RT rules */
				IPACMDBG_H("Delete IPsec default v4 routing rules\n");
				if (del_ipsec_wan_dl_rt_rules(IPA_IP_v4) == IPACM_FAILURE)
				{
					IPACMERR("Routing old IPsec RT rules deletion failed!\n");
					res = IPACM_FAILURE;
					goto fail;
				}
#endif
				ipv4_to_iface[sta_ipv4_pdn_index].ipv4_addr = 0;
				ipv4_to_iface[sta_ipv4_pdn_index].pIface = NULL;
				ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan = false;
				sta_ipv4_pdn_index = -1;
				num_ipv4_sta_pdn--;
				public_wan_v4_addr = 0;
				public_wan_v4_addr_set = false;
				wan_v4_addr = 0;
				wan_v4_addr_set = false;

				if (rx_prop != NULL && num_ipv4_sta_pdn == 0)
				{
					res = delete_dflt_filter_rules(IPA_IP_v4);
					if (res == IPACM_FAILURE)
					{
						IPACMERR("delete_dflt_filter_rules failed\n");
						goto fail;
					}
				}
			}
			IPACM_Iface::iface_addr_query(data->if_index);
		}
	}
fail:
	return res;
}

void IPACM_Wan::event_callback(ipa_cm_event_id event, void *param)
{
	int if_index = 0;
	int ipa_interface_index, cnt;

	switch (event)
	{
	case IPA_WLAN_LINK_DOWN_EVENT:
		{
			if(m_is_sta_mode == WLAN_WAN)
			{
				ipacm_event_data_fid *data = (ipacm_event_data_fid *)param;
				ipa_interface_index = iface_ipa_index_query(data->if_index);
				if (ipa_interface_index == ipa_if_num)
				{
					IPACMDBG_H("Received IPA_WLAN_LINK_DOWN_EVENT\n");
					handle_down_evt();
					/* reset the STA-iface category to unknown */
					IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_cat = UNKNOWN_IF;
					IPACMDBG_H("IPA_WAN_STA (%s):ipa_index (%d) instance close \n", IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name, ipa_if_num);
					IPACM_Iface::ipacmcfg->DelNatIfaces(dev_name); // delete NAT-iface
					delete this;
					return;
				}
			}
		}
		break;

#ifdef FEATURE_DUAL_BACKHAUL
	case IPA_HANDLE_WAN_DOWN:
	{
		ipacm_event_iface_up* data_wan = (ipacm_event_iface_up*)param;
		IPACMDBG_H("Received IPA_HANDLE_WAN_DOWN isSta: %d, devname: %s\n",
				data_wan->is_sta,dev_name);
		if(!data_wan->is_sta)
		{
			/*If a non STA WAN instance goes down, bringdown second backhaul*/
			handle_dual_backhaul_disable();
		}
		break;
	}
	case IPA_HANDLE_WAN_UP:
	{
		ipacm_event_iface_up* data_wan = (ipacm_event_iface_up*)param;
		IPACMDBG_H("Received IPA_HANDLE_WAN_UP isSta: %d, devname: %s\n",
				data_wan->is_sta,dev_name);
		if(!data_wan->is_sta)
		{
			/*If a non STA WAN instance comes up, then re-evaluate second backhaul*/
			handle_dual_backhaul_enable(NULL, false);
		}
		break;
	}
#endif

	case IPA_CFG_CHANGE_EVENT:
		{
#ifdef FEATURE_DUAL_BACKHAUL
			if(IPACM_Iface::ipacmcfg->second_backhaul_info.enable)
			{
				handle_dual_backhaul_enable(NULL, false);
			}
			else
                        {
				if(IPACM_Wan::second_backhaul_active)
				{
					handle_dual_backhaul_disable();
				}
			}
#endif
			if ( (IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_cat == ipa_if_cate) &&
					(m_is_sta_mode ==ECM_WAN))
			{
				IPACMDBG_H("Received IPA_CFG_CHANGE_EVENT and category did not change(wan_mode:%d)\n", m_is_sta_mode);
				IPACMDBG_H("Now the cradle wan mode is %d.\n", IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_mode);
				if(is_default_gateway == true)
				{
					if(backhaul_is_wan_bridge == false && IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_mode == BRIDGE)
					{
						IPACMDBG_H("Cradle wan mode switch to bridge mode.\n");
						backhaul_is_wan_bridge = true;
					}
					else if(backhaul_is_wan_bridge == true && IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_mode == ROUTER)
					{
						IPACMDBG_H("Cradle wan mode switch to router mode.\n");
						backhaul_is_wan_bridge = false;
					}
					else
					{
						IPACMDBG_H("No cradle mode switch, return.\n");
						return;
					}
					/* post wan mode change event to LAN/WLAN */
					if(IPACM_Wan::wan_up == true)
					{
						IPACMDBG_H("This interface is default GW.\n");
						ipacm_cmd_q_data evt_data;
						memset(&evt_data, 0, sizeof(evt_data));

						ipacm_event_cradle_wan_mode *data_wan_mode = NULL;
						data_wan_mode = (ipacm_event_cradle_wan_mode *)malloc(sizeof(ipacm_event_cradle_wan_mode));
						if(data_wan_mode == NULL)
						{
							IPACMERR("unable to allocate memory.\n");
							return;
						}
						data_wan_mode->cradle_wan_mode = IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_mode;
						evt_data.event = IPA_CRADLE_WAN_MODE_SWITCH;
						evt_data.evt_data = data_wan_mode;
						IPACMDBG_H("Posting IPA_CRADLE_WAN_MODE_SWITCH event.\n");
						IPACM_EvtDispatcher::PostEvt(&evt_data);
					}
					/* update the firewall flt rule actions */
					if(active_v4)
					{
						del_dft_firewall_rules(IPA_IP_v4);
						config_dft_firewall_rules(IPA_IP_v4);
					}
					if(active_v6)
					{
						del_dft_firewall_rules(IPA_IP_v6);
						config_dft_firewall_rules(IPA_IP_v6);
					}
				}
				else
				{
					IPACMDBG_H("This interface is not default GW, ignore.\n");
				}
			}
			else if ( (IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_cat != ipa_if_cate) &&
					(m_is_sta_mode ==ECM_WAN))
			{
				IPACMDBG_H("Received IPA_CFG_CHANGE_EVENT and category changed(wan_mode:%d)\n", m_is_sta_mode);
				/* posting link-up event for cradle use-case */
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
				IPACMDBG_H("Posting event:%d\n", evt_data.event);
				IPACM_EvtDispatcher::PostEvt(&evt_data);

				/* delete previous instance */
				handle_down_evt();
				IPACM_Iface::ipacmcfg->DelNatIfaces(dev_name); // delete NAT-iface
				delete this;
				return;
			}
			else if (ip_pass_pdn_info.enable || ip_collision_pdn_info.enable)
			{
				/* In Passthrough or Collision mode, config will be updated after WAN is up.
				 * restore the WAN netdev index.
				 */
				if(IPACM_Iface::ipa_get_if_index(dev_name, &(if_index)))
				{
					IPACMERR("Error while getting interface index for %s device", dev_name);
					break;
				}
				/* Map the interface index. */
				ipa_interface_index = IPACM_Iface::iface_ipa_index_query(if_index);
				if (ipa_interface_index == ipa_if_num)
				{
					IPACMDBG_H("In passthrough mode, mapping complete: WAN-LTE (%s) link up, iface: %d\n",
							IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].iface_name,
							ipa_if_num);
				}
				else
				{
					IPACMERR("In passthrough mode, Error while mapping interface index for %s device, ipa_if_num:%d,"
						 "ipa_interface_index:%d", dev_name, ipa_if_num, ipa_interface_index);
				}
			}
		}
		break;

	case IPA_LINK_DOWN_EVENT:
		{
			ipacm_event_data_fid *data = (ipacm_event_data_fid *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
#ifdef FEATURE_SOCKSv5
			rmnet_mux_id_info info;
#endif
			if (ipa_interface_index == ipa_if_num)
			{
				if(m_is_sta_mode == Q6_WAN)
				{
						IPACMDBG_H("Received IPA_LINK_DOWN_EVENT\n");
						handle_down_evt_ex();
						IPACMDBG_H("IPA_WAN_Q6 (%s):ipa_index (%d) instance close \n", IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name, ipa_if_num);
#if defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
						info.ipv4_addr = wan_v4_addr;
						info.mux_id = ext_prop->ext[0].mux_id;;
						memcpy(info.iface_name, dev_name, sizeof(dev_name));
						/* add qmuxd mapping*/
						IPACM_Iface::ipacmcfg->del_mux_id_mapping(&info);
#endif //defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
						IPACM_Iface::ipacmcfg->DelNatIfaces(dev_name); // delete NAT-iface
						delete this;
						return;
				}
				else if (m_is_sta_mode == ECM_WAN)
				{
					IPACMDBG_H("Received IPA_LINK_DOWN_EVENT(wan_mode:%d)\n", m_is_sta_mode);
					/* delete previous instance */
					handle_down_evt();
					IPACMDBG_H("IPA_WAN_CRADLE (%s):ipa_index (%d) instance close \n", IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name, ipa_if_num);
					IPACM_Iface::ipacmcfg->DelNatIfaces(dev_name); // delete NAT-iface
					delete this;
					return;
				}
			}
		}
		break;

	case IPA_ADDR_ADD_EVENT:
		{
			ipacm_event_data_addr *data = (ipacm_event_data_addr *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			ipacm_event_iface_up *wanup_data = NULL;
			ipacm_cmd_q_data evt_data;

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
				IPACMDBG_H("Get IPA_ADDR_ADD_EVENT: IF ip type %d, incoming ip type %d\n", ip_type, data->iptype);
				/* check v4 not setup before, v6 can have 2 iface ip */
				if( (data->iptype == IPA_IP_v4)
				    || ((data->iptype==IPA_IP_v6) && (num_dft_rt_v6!=MAX_DEFAULT_v6_ROUTE_RULES)))
				{
					IPACMDBG_H("Got IPA_ADDR_ADD_EVENT ip-family:%d, v6 num: %d \n",data->iptype, num_dft_rt_v6);

					if (data->iptype == IPA_IP_v4)
					{
						IPACM_Iface::iface_addr_query(data->if_index, false, &data->ipv4_addr);

						IPACMDBG_H("ipv4_addr : 0x%x subnet_mask : 0x%x result: 0x%x xlat_ip : 0x%x\n",
							data->ipv4_addr, data->ipv4_addr_mask, data->ipv4_addr & data->ipv4_addr_mask, XLAT_IP);

						if((data->ipv4_addr & data->ipv4_addr_mask) == XLAT_IP && (m_is_sta_mode == Q6_WAN))
						{
							is_xlat = true;
							if (modem_ipv4_pdn_index != -1)
							{
								IPACM_Wan::ipv4_to_iface[modem_ipv4_pdn_index].is_xlat = true;
							}
							IPACMDBG_H("WAN-LTE (%s) link up, iface: %d is_xlat: %d \n",
							IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].iface_name,data->if_index, is_xlat);
						}
					}

					handle_addr_evt(data);
					/* checking if SW-RT_enable */
					if (IPACM_Iface::ipacmcfg->ipa_sw_rt_enable == true &&
							m_is_sta_mode != Q6_WAN)
					{
						/* handle software routing enable event*/
						IPACMDBG_H("IPA_SW_ROUTING_ENABLE for iface: %s \n",IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name);
						handle_software_routing_enable();
					}

					if(data->iptype == IPA_IP_v6)
					{
						wanup_data = (ipacm_event_iface_up *)malloc(sizeof(ipacm_event_iface_up));
						if (wanup_data == NULL)
						{
							IPACMERR("Unable to allocate memory\n");
							break;
						}
						memset(wanup_data, 0, sizeof(ipacm_event_iface_up));
						memcpy(wanup_data->ifname, dev_name, sizeof(wanup_data->ifname));
						if (m_is_sta_mode == Q6_WAN && ext_prop != NULL)
							wanup_data->mux_id = ext_prop->ext[0].mux_id;
						wanup_data->ipv6_prefix[0] = data->ipv6_addr[0];
						wanup_data->ipv6_prefix[1] = data->ipv6_addr[1];
						wanup_data->vlanID = 0;
						IPACMDBG_H("Posting IPA_HANDLE_WAN_ADDR_ADD_V6 with below information:\n");
						IPACMDBG_H("if_name:%s ipv6 prefix: 0x%08x%08x mux_id %d\n", wanup_data->ifname,
							wanup_data->ipv6_prefix[0], wanup_data->ipv6_prefix[1], wanup_data->mux_id);
						memset(&evt_data, 0, sizeof(evt_data));
						evt_data.event = IPA_HANDLE_WAN_ADDR_ADD_V6;
						evt_data.evt_data = (void *)wanup_data;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
					}
#ifdef FEATURE_VLAN_MPDN
					else
					{
						if((IPACM_Iface::ipacmcfg->ipacm_mpdn_enable) && (associated_VID != 0))
						{
							IPACMDBG_H("PDN already associated with VLAN ID via V6 address (0x[%X][%X]), add V4 vlan pdn\n",
								ipv6_prefix[0], ipv6_prefix[1]);

							/* in case of ip passthrough we receive a link local address and shouldn't add a vlan v4 pdn */
							if (is_link_local_ipv4_addr(data->ipv4_addr)) {
								IPACMDBG_H("ipv4 address is link local, don't add v4 vlan pdn\n");
								break;
							}

							/* generate IPA_ROUTE_ADD_VLAN_PDN_EVENT for v4 PDN as v6 PDN already has associated vlan*/
							ipacm_cmd_q_data evt_data;
							ipacm_event_route_vlan *vlan_data;

							evt_data.event = IPA_ROUTE_ADD_VLAN_PDN_EVENT;
							vlan_data = (ipacm_event_route_vlan *)malloc(sizeof(ipacm_event_route_vlan));
							if(!vlan_data)
							{
								IPACMERR("couldn't allocate memory for new vlan pdn event\n");
								return;
							}
							vlan_data->iptype = IPA_IP_v4;
							vlan_data->VlanID = associated_VID;
							vlan_data->wan_ipv4_addr = data->ipv4_addr;
							evt_data.evt_data = vlan_data;
							IPACMDBG_H("sending IPA_ROUTE_ADD_VLAN_PDN_EVENT vlan id %d, iptype %d,\n",
								vlan_data->VlanID,
								vlan_data->iptype);
							IPACMDBG_H("pdn ip 0x%X\n", data->ipv4_addr);

							IPACM_EvtDispatcher::PostEvt(&evt_data);
						}
					}
#endif
					/*to handle if we have missed new route events before
                                        creation of interface*/
					ipa_nl_send_getroute(data->iptype);
				}
			}
		}
		break;

	case IPA_ADDR_DEL_EVENT:
		{
			ipacm_event_data_addr *data = (ipacm_event_data_addr *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);

			if ( (data->iptype == IPA_IP_v4 && data->ipv4_addr == 0) ||
				(data->iptype == IPA_IP_v6 &&
				data->ipv6_addr[0] == 0 && data->ipv6_addr[1] == 0 &&
				data->ipv6_addr[2] == 0 && data->ipv6_addr[3] == 0) )
			{
				IPACMDBG_H("Invalid address, ignore IPA_ADDR_DEL_EVENT event\n");
				return;
			}

			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Get IPA_ADDR_DEL_EVENT: IF ip type %d, incoming ip type %d\n", ip_type, data->iptype);
				IPACMDBG_H("v6 num: %d\n",num_dft_rt_v6);
				handle_addr_del_evt(data);
			}
		}
		break;

	case IPA_WAN_UPSTREAM_ROUTE_ADD_EVENT:
		{
			ipacm_event_data_iptype *data = (ipacm_event_data_iptype *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_WAN_UPSTREAM_ROUTE_ADD_EVENT (Android) for ip-type (%d)\n", data->iptype);
				/* The special below condition is to handle default gateway */
				if ((data->iptype == IPA_IP_v4) && (ip_type == IPA_IP_v4 || ip_type == IPA_IP_MAX))
				{
					if (active_v4 == false)
					{
						IPACMDBG_H("adding routing table(upstream), dev (%s) ip-type(%d)\n", dev_name,data->iptype);
						handle_route_add_evt(data->iptype);
					}
#ifdef FEATURE_IPA_ANDROID
					/* using ipa_if_index, not netdev_index */
					post_wan_up_tether_evt(data->iptype, iface_ipa_index_query(data->if_index_tether));
#endif
				}
				else if ((data->iptype == IPA_IP_v6) && (ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX))
				{
					if(ipv6_prefix[0] == 0 && ipv6_prefix[1] == 0)
					{
						IPACMDBG_H("IPv6 default route comes earlier than global IP, ignore.\n");
						return;
					}

					if (active_v6 == false)
					{
						IPACMDBG_H("\n get default v6 route (dst:00.00.00.00) upstream\n");
						handle_route_add_evt(data->iptype);
					}
#ifdef FEATURE_IPA_ANDROID
					/* using ipa_if_index, not netdev_index */
					post_wan_up_tether_evt(data->iptype, iface_ipa_index_query(data->if_index_tether));
#endif
				}
			}
			else /* double check if current default iface is not itself */
			{
				if ((data->iptype == IPA_IP_v4) && (active_v4 == true))
				{
					IPACMDBG_H("Received v4 IPA_WAN_UPSTREAM_ROUTE_ADD_EVENT for other iface (%s)\n", IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].iface_name);
					IPACMDBG_H("need clean default v4 route (dst:0.0.0.0) for old iface (%s)\n", dev_name);
					if(m_is_sta_mode == Q6_WAN)
					{
						del_wan_firewall_rule(IPA_IP_v4);
						install_wan_filtering_rule(false);
						handle_route_del_evt_ex(IPA_IP_v4);
					}
					else
					{
						del_dft_firewall_rules(IPA_IP_v4);
						handle_route_del_evt(IPA_IP_v4);
					}
				}
				else if ((data->iptype == IPA_IP_v6) && (active_v6 == true))
				{
				    IPACMDBG_H("Received v6 IPA_WAN_UPSTREAM_ROUTE_ADD_EVENT for other iface (%s)\n", IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].iface_name);
					IPACMDBG_H("need clean default v6 route for old iface (%s)\n", dev_name);
					if(m_is_sta_mode == Q6_WAN)
					{
						del_wan_firewall_rule(IPA_IP_v6);
						install_wan_filtering_rule(false);
						handle_route_del_evt_ex(IPA_IP_v6);
					}
					else
					{
						del_dft_firewall_rules(IPA_IP_v6);
						handle_route_del_evt(IPA_IP_v6);
					}
				}
			}
		}
		break;

	case IPA_WAN_UPSTREAM_ROUTE_DEL_EVENT:
		{
			ipacm_event_data_iptype *data = (ipacm_event_data_iptype *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_WAN_UPSTREAM_ROUTE_DEL_EVENT\n");
				if ((data->iptype == IPA_IP_v4) && (active_v4 == true))
				{
					IPACMDBG_H("get del default v4 route (dst:0.0.0.0)\n");
#ifdef FEATURE_IPA_ANDROID
					/* using ipa_if_index, not netdev_index */
					post_wan_down_tether_evt(data->iptype, iface_ipa_index_query(data->if_index_tether));
					/* no any ipv4 tether iface support*/
					if(IPACM_Wan::ipa_if_num_tether_v4_total != 0)
					{
						IPACMDBG_H("still have tether ipv4 client on upsteam iface\n");
						return;
					}
#endif
					if(m_is_sta_mode == Q6_WAN)
					{
						del_wan_firewall_rule(IPA_IP_v4);
						install_wan_filtering_rule(false);
						handle_route_del_evt_ex(IPA_IP_v4);
					}
					else
					{
						del_dft_firewall_rules(IPA_IP_v4);
						handle_route_del_evt(IPA_IP_v4);
					}
				}
				else if ((data->iptype == IPA_IP_v6) && (active_v6 == true))
				{
#ifdef FEATURE_IPA_ANDROID
					/* using ipa_if_index, not netdev_index */
					post_wan_down_tether_evt(data->iptype, iface_ipa_index_query(data->if_index_tether));
					/* no any ipv6 tether iface support*/
					if(IPACM_Wan::ipa_if_num_tether_v6_total != 0)
					{
						IPACMDBG_H("still have tether ipv6 client on upsteam iface\n");
						return;
					}
#endif
					if(m_is_sta_mode == Q6_WAN)
					{
						del_wan_firewall_rule(IPA_IP_v6);
						install_wan_filtering_rule(false);
						handle_route_del_evt_ex(IPA_IP_v6);
					}
					else
					{
						del_dft_firewall_rules(IPA_IP_v6);
						handle_route_del_evt(IPA_IP_v6);
					}
				}
			}
		}
		break;
	case IPA_NETWORK_STATS_UPDATE_EVENT:
		{
			ipa_get_apn_data_stats_resp_msg_v01 *data = (ipa_get_apn_data_stats_resp_msg_v01 *)param;
			if (!data->apn_data_stats_list_valid)
			{
				IPACMERR("not valid APN\n");
				return;
			}
			else
			{
				handle_network_stats_update(data);
			}
		}
		break;
	case IPA_ROUTE_ADD_EVENT:
		{
			ipacm_event_data_addr *data = (ipacm_event_data_addr *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);

			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_ROUTE_ADD_EVENT for dev_name:%s iptype:%d ip_type:%d\n",
					dev_name, data->iptype, ip_type);
				IPACMDBG_H("ipv4 addr 0x%x\n", data->ipv4_addr);
				IPACMDBG_H("ipv4 addr mask 0x%x\n", data->ipv4_addr_mask);
#ifdef FEATURE_STATIC_POLICY
				if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable && m_is_sta_mode == Q6_WAN)
				{
					IPACMDBG_H("Ignore IPA_ROUTE_ADD_EVENT when Static policy is enabled.\n", dev_name);
					return;
				}
#endif
				IPACMDBG_H("IPV6 dst: %08x:%08x:%08x:%08x active:%d\n",
							data->ipv6_addr[0], data->ipv6_addr[1], data->ipv6_addr[2], data->ipv6_addr[3], active_v6);
				IPACMDBG_H("IPV6 gateway: %08x:%08x:%08x:%08x\n",
							data->ipv6_addr_gw[0], data->ipv6_addr_gw[1], data->ipv6_addr_gw[2], data->ipv6_addr_gw[3]);
				IPACMDBG_H("m_is_sta_mode (%d) at route_add_event.\n", m_is_sta_mode);

				/* The special below condition is to handle default gateway */
				if ((data->iptype == IPA_IP_v4) && (!data->ipv4_addr) && (!data->ipv4_addr_mask) && (active_v4 == false)
					&& (ip_type == IPA_IP_v4 || ip_type == IPA_IP_MAX))
				{
					IPACMDBG_H("get default v4 route (dst:0.0.0.0)\n");

					wan_v4_addr_gw = data->ipv4_addr_gw;
					wan_v4_addr_gw_set = true;
					wan_v4_is_default_gw = true;
					IPACMDBG_H("adding routing table, dev (%s) ip-type(%d), default gw (%x)\n", dev_name,data->iptype, wan_v4_addr_gw);
					/* Check & construct STA header */
					handle_sta_header_add_evt();
					handle_route_add_evt(data->iptype);
					/* Add IPv6 routing table if XLAT is enabled */
					if(is_xlat && (m_is_sta_mode == Q6_WAN) && (active_v6 == false))
					{
						IPACMDBG_H("XLAT enabled: adding IPv6 routing table dev (%s)\n", dev_name);
						handle_route_add_evt(IPA_IP_v6);
					}

					if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable && data->iptype == IPA_IP_v4)
					{
						ipacm_cmd_q_data evt_data1;
						ipacm_event_data_all *data_all;
						data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
						if(data_all == NULL)
						{
						 	IPACMERR("unable to allocate memory for event data_all\n");
							return;
						}

						memset(data_all, 0, sizeof(ipacm_event_data_all));
						data_all->if_index = data->if_index;
						strlcpy(data_all->iface_name, dev_name, sizeof(data_all->iface_name));
						data_all->ipv4_addr = wan_v4_addr_gw;
		    			data_all->iptype = IPA_IP_v4;

						IPACMDBG_H("Posting IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT for dev_name:%s iptype:%d ip_type:%d\n", dev_name, data->iptype, ip_type);
						evt_data1.event = IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT;
						evt_data1.evt_data = data_all;
						IPACM_EvtDispatcher::PostEvt(&evt_data1);
					}
				}
				else if ((data->iptype == IPA_IP_v6) &&
						(!data->ipv6_addr[0]) && (!data->ipv6_addr[1]) && (!data->ipv6_addr[2]) && (!data->ipv6_addr[3]) &&
						(active_v6 == false) &&	(ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX))
				{
					if(ipv6_prefix[0] == 0 && ipv6_prefix[1] == 0)
					{
						IPACMDBG_H("IPv6 default route comes earlier than global IP, ignore.\n");
						return;
					}
					IPACMDBG_H("\n get default v6 route (dst:00.00.00.00)\n");

					IPACMDBG_H("\n get default v6 route (dst:00.00.00.00)\n");
					IPACMDBG_H(" IPV6 dst: %08x:%08x:%08x:%08x \n",
							data->ipv6_addr[0], data->ipv6_addr[1], data->ipv6_addr[2], data->ipv6_addr[3]);
					IPACMDBG_H(" IPV6 gateway: %08x:%08x:%08x:%08x \n",
							data->ipv6_addr_gw[0], data->ipv6_addr_gw[1], data->ipv6_addr_gw[2], data->ipv6_addr_gw[3]);
					wan_v6_addr_gw[0] = data->ipv6_addr_gw[0];
					wan_v6_addr_gw[1] = data->ipv6_addr_gw[1];
					wan_v6_addr_gw[2] = data->ipv6_addr_gw[2];
					wan_v6_addr_gw[3] = data->ipv6_addr_gw[3];
					wan_v6_addr_gw_set = true;
					wan_v6_is_default_gw = true;
					/* Check & construct STA header */
					handle_sta_header_add_evt();
					handle_route_add_evt(data->iptype);

					if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable && data->iptype == IPA_IP_v6)
					{
						ipacm_cmd_q_data evt_data1;
						ipacm_event_data_all *data_all;
						data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
						if(data_all == NULL)
						{
							IPACMERR("unable to allocate memory for event data_all\n");
							return;
						}

						memset(data_all, 0, sizeof(ipacm_event_data_all));
						data_all->if_index = data->if_index;;
						strlcpy(data_all->iface_name, dev_name, sizeof(data_all->iface_name));

						data_all->ipv6_addr[0] = data->ipv6_addr_gw[0];
						data_all->ipv6_addr[1] = data->ipv6_addr_gw[1];
						data_all->ipv6_addr[2] = data->ipv6_addr_gw[2];
						data_all->ipv6_addr[3] = data->ipv6_addr_gw[3];
						data_all->iptype = IPA_IP_v6;

						IPACMDBG_H("Posting IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT for dev_name:%s iptype:%d ip_type:%d\n", dev_name, data->iptype, ip_type);
						evt_data1.event = IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT;
						evt_data1.evt_data = data_all;
						IPACM_EvtDispatcher::PostEvt(&evt_data1);
					}
				}
			}
			else /* double check if current default iface is not itself */
			{
				if ((data->iptype == IPA_IP_v4) && (!data->ipv4_addr) && (!data->ipv4_addr_mask) && (active_v4 == true))
				{
					IPACMDBG_H("Received v4 IPA_ROUTE_ADD_EVENT for other iface (%s)\n", IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].iface_name);
					IPACMDBG_H("ipv4 addr 0x%x\n", data->ipv4_addr);
					IPACMDBG_H("ipv4 addr mask 0x%x\n", data->ipv4_addr_mask);
					IPACMDBG_H("need clean default v4 route (dst:0.0.0.0) for old iface (%s)\n", dev_name);
					wan_v4_addr_gw_set = false;
					if(m_is_sta_mode == Q6_WAN)
					{
						handle_route_del_evt_ex(IPA_IP_v4);
						del_wan_firewall_rule(IPA_IP_v4);
						if(isVlanWanUP())
						{
							config_wan_firewall_rule(IPA_IP_v4);
						}
						install_wan_filtering_rule(false);
					}
					else
					{
						if(sta_ipv4_pdn_index >= 0 && ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan == false)
						{
							del_dft_firewall_rules(IPA_IP_v4);
						}
						handle_route_del_evt(IPA_IP_v4);
					}
				}
				else if ((data->iptype == IPA_IP_v6) && (!data->ipv6_addr[0]) && (!data->ipv6_addr[1]) && (!data->ipv6_addr[2]) && (!data->ipv6_addr[3]) && (active_v6 == true))
				{
				    IPACMDBG_H("Received v6 IPA_ROUTE_ADD_EVENT for other iface (%s)\n", IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].iface_name);
					IPACMDBG_H("need clean default v6 route for old iface (%s)\n", dev_name);
					if(m_is_sta_mode == Q6_WAN)
					{
						handle_route_del_evt_ex(IPA_IP_v6);
						del_wan_firewall_rule(IPA_IP_v6);
						if(isVlanWanUP_V6())
						{
								config_wan_firewall_rule(IPA_IP_v6);
						}
						install_wan_filtering_rule(false);
					}
					else
					{
						if(sta_ipv6_pdn_index >= 0 && ipv6_to_iface[sta_ipv6_pdn_index].wan_up_vlan_v6 == false)
						{
							del_dft_firewall_rules(IPA_IP_v6);
						}
						handle_route_del_evt(IPA_IP_v6);
					}
				}
			}
		}
		break;
	case IPA_IP_PASS_UPDATE_EVENT:
		{
			ipacm_event_ip_pass_pdn_info *data = (ipacm_event_ip_pass_pdn_info *)param;
			ipacm_event_vlan_pdn *pdn_update = NULL;
			ipacm_cmd_q_data evt_data;

			ipa_interface_index = iface_ipa_index_query(data->if_index);
			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("received v4 IPA_IP_PASS_UPDATE_EVENT for wan %s, %d\n", dev_name, ipa_if_num);
				ip_pass_pdn_info.enable = data->enable;
				if (ip_pass_pdn_info.enable)
				{
					ip_pass_pdn_info.pdn_ip_addr = data->pdn_ip_addr;
					ip_pass_pdn_info.skip_nat = data->skip_nat;
					ip_pass_pdn_info.VlanID = data->VlanID;
					IPACMDBG_H("IP Passthrough enabled: IP 0x%x, Skip NAT: %d, VlanID: %d\n",
						ip_pass_pdn_info.pdn_ip_addr,
						ip_pass_pdn_info.skip_nat,
						data->VlanID);
				}
				else
				{
					IPACMDBG_H("IP Passthrough disabled, reset config\n");
					ip_pass_pdn_info.pdn_ip_addr = 0;
					ip_pass_pdn_info.skip_nat = 0;
					ip_pass_pdn_info.VlanID = 0;
				}
				/* Need to update the IPPassthrough information when passthrough is disabled or
                                 * non VLAN scenario and PDN is up.
				 */
				if (!ip_pass_pdn_info.enable || (ip_pass_pdn_info.enable && (active_v4 ||
					ipv4_to_iface[modem_ipv4_pdn_index].wan_up_vlan)))
				{
					pdn_update = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
					if(pdn_update == NULL)
					{
						IPACMERR("Unable to allocate memory\n");
						break;
					}
					memset(pdn_update, 0, sizeof(ipacm_event_vlan_pdn));
					pdn_update->ipv4_addr = wan_v4_addr;
					pdn_update->ip_pass_enable = ip_pass_pdn_info.enable;
					pdn_update->ip_pass_dummy_ip = (ip_pass_pdn_info.enable) ?
						ip_pass_pdn_info.pdn_ip_addr : 0;
					pdn_update->ip_pass_skip_nat = (ip_pass_pdn_info.enable) ? ip_pass_pdn_info.skip_nat : 0;
					IPACMDBG_H("Posting IPA_HANDLE_IP_PASS_PDN_INFO_UPDATE_EVENT\n");
					IPACMDBG_H("IP Passthrough enabled:%d WAN IP: 0x%x, Dummy IP 0x%x, Skip NAT: %d\n",
						pdn_update->ip_pass_enable,
						pdn_update->ipv4_addr,
						pdn_update->ip_pass_dummy_ip,
						pdn_update->ip_pass_skip_nat);
					evt_data.event = IPA_HANDLE_IP_PASS_PDN_INFO_UPDATE_EVENT;
					evt_data.evt_data = (void *)pdn_update;
					IPACM_EvtDispatcher::PostEvt(&evt_data);
				}

				/* Post the VLAN PDN up event in case of non default PDNs or default pdn with valid vlan-id. */
				/* We get conntrack events without SRC_NAT and DST_NAT flags, so if
				 * we don't post the event now in a way it is a deadlock where PDN_NAT event will never be posted.
				 */

				if (ip_pass_pdn_info.enable &&
					(ip_pass_pdn_info.VlanID != 0))
				{
					/* check if it's xlat call */
					if (is_xlat)
					{
						IPACMDBG_H(" IP Passthrough xlat(%d), hadling v6-route_add_pdn\n", is_xlat);
						handle_route_add_vlan_pdn_evt(IPA_IP_v6, ip_pass_pdn_info.VlanID);
					}
					handle_route_add_vlan_pdn_evt(IPA_IP_v4, ip_pass_pdn_info.VlanID);
					num_offloaded_pdns++;
					IPACMDBG_H("Num of offloaded PDN increased to %d\n", num_offloaded_pdns);
				}
			}
			break;
		}
	case IPA_IP_COLLISION_UPDATE_EVENT:
		{
			ipacm_event_ip_collision_pdn_info *data = (ipacm_event_ip_collision_pdn_info *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("received v4 IPA_IP_COLLISION_UPDATE_EVENT for wan %s, %s ,%d\n", dev_name, data->dev_name, ipa_if_num);
				ip_collision_pdn_info.enable = data->enable;
				strlcpy(ip_collision_pdn_info.dev_name, data->dev_name, IPA_RESOURCE_NAME_MAX);

				if (ip_collision_pdn_info.enable)
				{
					ip_collision_pdn_info.pdn_ip_addr = data->pdn_ip_addr;
					ip_collision_pdn_info.VlanID = data->VlanID;
				}
				else
				{
					IPACMDBG_H("IP Collision disabled, reset config\n");
					ip_collision_pdn_info.pdn_ip_addr = 0;
					ip_collision_pdn_info.VlanID = 0;
				}
				IPACMDBG_H("IP Collision enabled: IP 0x%x, VlanId: %d\n",ip_collision_pdn_info.pdn_ip_addr, ip_collision_pdn_info.VlanID);
			}
		}
		break;
		case IPA_WAN_GW_ADDR_ADD_EVENT:
		{
			ipacm_event_data_addr *data = (ipacm_event_data_addr *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);

			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_WAN_GW_ADDR_ADD_EVENT\n");
				if(data->iptype == IPA_IP_v4)
					IPACMDBG_H("ipv4 addr 0x%x\n", data->ipv4_addr_gw);
				if(data->iptype == IPA_IP_v6)
					IPACMDBG_H("ipv6 addr 0x%x 0x%x 0x%x 0x%x\n", data->ipv6_addr_gw[0], data->ipv6_addr_gw[1],
						data->ipv6_addr_gw[2], data->ipv6_addr_gw[3]);
				if(m_is_sta_mode == WLAN_WAN || m_is_sta_mode == ECM_WAN)
				{
					IPACMDBG_H("GW info for WAN Iface\n");

					if ((data->iptype == IPA_IP_v4 || data->iptype == IPA_IP_MAX) && data->ipv4_addr_gw != 0 &&  wan_v4_addr_gw_set != true)
					{
						IPACMDBG_H("ipv4 addr 0x%x\n", data->ipv4_addr_gw);
						wan_v4_is_default_gw = false;
						wan_v4_addr_gw = data->ipv4_addr_gw;
						wan_v4_addr_gw_set = true;
						wan_v6_is_default_gw = false;
						IPACMDBG_H("adding header, dev (%s) ip-type(%d), default gw (%x)\n", dev_name,data->iptype, wan_v4_addr_gw);
					}
					if ((data->iptype == IPA_IP_v6 || data->iptype == IPA_IP_MAX) &&  wan_v6_addr_gw_set != true &&
						(data->ipv6_addr_gw[0] != 0) || (data->ipv6_addr_gw[1] != 0) || (data->ipv6_addr_gw[2] != 0) || (data->ipv6_addr_gw[3] != 0))
					{

						IPACMDBG_H("IPV6 gateway: %08x:%08x:%08x:%08x \n",
							data->ipv6_addr_gw[0], data->ipv6_addr_gw[1], data->ipv6_addr_gw[2], data->ipv6_addr_gw[3]);
						wan_v6_addr_gw[0] = data->ipv6_addr_gw[0];
						wan_v6_addr_gw[1] = data->ipv6_addr_gw[1];
						wan_v6_addr_gw[2] = data->ipv6_addr_gw[2];
						wan_v6_addr_gw[3] = data->ipv6_addr_gw[3];
						wan_v6_addr_gw_set = true;
						wan_v4_is_default_gw = false;
						wan_v6_is_default_gw = false;
					}
					/* Check & construct STA header */
					handle_sta_header_add_evt();

					if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable && data->iptype == IPA_IP_v4)
					{
						ipacm_cmd_q_data evt_data1;
						ipacm_event_data_all *data_all;
						data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
						if(data_all == NULL)
						{
						 	IPACMERR("unable to allocate memory for event data_all\n");
							return;
						}

						memset(data_all, 0, sizeof(ipacm_event_data_all));
						data_all->if_index = data->if_index;
						strlcpy(data_all->iface_name, dev_name, sizeof(data_all->iface_name));
						data_all->ipv4_addr = wan_v4_addr_gw;
		    			data_all->iptype = IPA_IP_v4;

						IPACMDBG_H("Posting IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT for dev_name:%s iptype:%d ip_type:%d\n", dev_name, data->iptype, ip_type);
						evt_data1.event = IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT;
						evt_data1.evt_data = data_all;
						IPACM_EvtDispatcher::PostEvt(&evt_data1);
					}
					else if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable && data->iptype == IPA_IP_v6)
					{
						ipacm_cmd_q_data evt_data1;
						ipacm_event_data_all *data_all;
						data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
						if(data_all == NULL)
						{
								IPACMERR("unable to allocate memory for event data_all\n");
							return;
						}

						memset(data_all, 0, sizeof(ipacm_event_data_all));
						data_all->if_index = data->if_index;;
						strlcpy(data_all->iface_name, dev_name, sizeof(data_all->iface_name));

						data_all->ipv6_addr[0] = data->ipv6_addr_gw[0];
						data_all->ipv6_addr[1] = data->ipv6_addr_gw[1];
						data_all->ipv6_addr[2] = data->ipv6_addr_gw[2];
						data_all->ipv6_addr[3] = data->ipv6_addr_gw[3];
						data_all->iptype = IPA_IP_v6;

						IPACMDBG_H("Posting IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT for dev_name:%s iptype:%d ip_type:%d\n", dev_name, data->iptype, ip_type);
						evt_data1.event = IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT;
						evt_data1.evt_data = data_all;
						IPACM_EvtDispatcher::PostEvt(&evt_data1);
					}
				}
			}
		}
		break;

#ifdef FEATURE_VLAN_MPDN
	case IPA_ROUTE_ADD_VLAN_PDN_EVENT:
		{
			IPACMDBG_H("Received IPA_ROUTE_ADD_VLAN_PDN_EVENT event\n");
			ipacm_event_route_vlan *data = (ipacm_event_route_vlan *)param;
			enum ipa_ip_type iptype = data->iptype;
			uint32_t prefix[2];
			int ret;

			ret = check_vlan_pdn(iptype, data);
			/* If event for this->pIface, process the other iptype with local info*/
			if(ret == IPACM_SUCCESS && iptype == IPA_IP_MAX)
			{
				if(data->wan_ipv4_addr == IPA_DUMMY_PREFIX)
				{
					IPACMDBG_H("Received event for v4 & v6, handled v4 part\n");
					if (wan_v4_addr_set) {
						IPACMDBG_H("wan instance has public v4 address 0x%X add v4 event\n", wan_v4_addr);
						/* IPA_IP_MAX doesn't come with valid ipv4 address as LAN instance doesn't know this info */
						data->wan_ipv4_addr = wan_v4_addr;
						check_vlan_pdn(IPA_IP_v4, data);
					} else
						IPACMDBG_H("wan instance doesn't have public v4 address no need to add v4 event\n");
				}
				if(data->wan_ipv6_prefix[0] == IPA_DUMMY_PREFIX)
				{
					/* handling xlat pdn case */
					IPACMDBG_H("Received event for v4 & v6, handled v6 part\n");
					if (modem_ipv6_pdn_index != -1){
						memcpy(data->wan_ipv6_prefix, ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix, 2*sizeof(uint32_t));
						IPACM_Iface::ipacmcfg->add_vlan_ipv6_prefix(ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix, ipa_if_num, data->VlanID);
						check_vlan_pdn(IPA_IP_v6, data);
					} else if (is_xlat){
						IPACMDBG_H("wan instance doesnt have global v6 address but is_xlat : %d\n",is_xlat);
						prefix[0] = IPA_DUMMY_PREFIX;
						prefix[1] = IPA_DUMMY_PREFIX;
						IPACM_Iface::ipacmcfg->add_vlan_ipv6_prefix(prefix, ipa_if_num, data->VlanID);
						check_vlan_pdn(IPA_IP_v6, data, true);
					} else
						IPACMDBG_H("wan instance doesnt have global v6 address ,ignore\n");
				}
			}
		}
		break;
#endif

	case IPA_ROUTE_DEL_EVENT:
		{
			ipacm_event_data_addr *data = (ipacm_event_data_addr *)param;
			ipa_interface_index = iface_ipa_index_query(data->if_index);
			if (ipa_interface_index == ipa_if_num)
			{
				IPACMDBG_H("Received IPA_ROUTE_DEL_EVENT\n");
				if ((data->iptype == IPA_IP_v4) && (!data->ipv4_addr) && (!data->ipv4_addr_mask) && (active_v4 == true))
				{
					IPACMDBG_H("get del default v4 route (dst:0.0.0.0)\n");
					wan_v4_addr_gw_set = false;
					if(m_is_sta_mode == Q6_WAN)
					{
						handle_route_del_evt_ex(IPA_IP_v4);
						del_wan_firewall_rule(IPA_IP_v4);
						if(isVlanWanUP())
						{
							config_wan_firewall_rule(IPA_IP_v4);
						}
						install_wan_filtering_rule(false);

						if(is_xlat && active_v6 == true)
						{
							IPACMDBG_H("XLAT enabled: Delete IPv6 routing table dev (%s)\n", dev_name);
							handle_route_del_evt_ex(IPA_IP_v6);
							del_wan_firewall_rule(IPA_IP_v6);
							if(isVlanWanUP_V6())
							{
								config_wan_firewall_rule(IPA_IP_v6);
							}
							install_wan_filtering_rule(false);
						}
					}
					else
					{
						if(sta_ipv4_pdn_index >= 0 && ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan == false)
						{
							del_dft_firewall_rules(IPA_IP_v4);
						}
						handle_route_del_evt(IPA_IP_v4);
					}
				}
				else if ((data->iptype == IPA_IP_v6) && (!data->ipv6_addr[0]) && (!data->ipv6_addr[1]) && (!data->ipv6_addr[2]) && (!data->ipv6_addr[3]) && (active_v6 == true))
				{
					IPACMDBG_H("get del default v6 route (dst:00.00.00.00)\n");

					if(m_is_sta_mode == Q6_WAN)
					{
						if (is_xlat && active_v4 == true) {
							IPACMDBG_H("xlat v4 pdn active, dont post WAN_DOWN_V6\n");
						} else {
							handle_route_del_evt_ex(IPA_IP_v6);
							del_wan_firewall_rule(IPA_IP_v6);
							if(isVlanWanUP_V6())
							{
								config_wan_firewall_rule(IPA_IP_v6);
							}
							install_wan_filtering_rule(false);
						}
					}
					else
					{
						if(sta_ipv6_pdn_index >= 0 && ipv6_to_iface[sta_ipv6_pdn_index].wan_up_vlan_v6 == false)
						{
							del_dft_firewall_rules(IPA_IP_v6);
						}
						handle_route_del_evt(IPA_IP_v6);
					}
				}
			}
		}
		break;

	case IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT:
		{
			ipacm_event_data_all *data = (ipacm_event_data_all *)param;
			bool gw_addr = false;
			int indx = IPACM_FAILURE;

			ipa_interface_index = iface_ipa_index_query(data->if_index);

			IPACMDBG_H("Received IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT in STA mode (ipa:%d) %d ip:%d data:%d\n",
				ipa_interface_index, ipa_if_num, data->iptype, data->if_index);

			if (ipa_interface_index == ipa_if_num)
			{
#ifdef FEATURE_PPPOE
				if(is_ppp_iface)
				{
					if((indx = IPACM_Iface::ipacmcfg->get_pppoe_indx(dev_name)) != IPACM_FAILURE)
					{
						IPACMDBG_H("Received IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT in STA mode for indx (%d) of dev_name %s\n",
							indx, dev_name);
						memcpy(data->mac_addr,
							IPACM_Iface::ipacmcfg->pppoe_mpdn_table[indx].mac_addr,
							sizeof(IPACM_Iface::ipacmcfg->pppoe_mpdn_table[indx].mac_addr));
					}
					else
					{
						IPACMDBG_H("Received IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT in STA mode (%d)\n", m_is_sta_mode);
						return;
					}
				}
#endif
				IPACMDBG_H("Received IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT in STA mode (%d)\n", m_is_sta_mode);

				if (m_is_sta_mode == WLAN_WAN || m_is_sta_mode == ECM_WAN)
				{
					if (data->iptype == IPA_IP_v4 && data->ipv4_addr == wan_v4_addr)
					{
						IPACMDBG_H("Ignore IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT in STA mode\n");
						IPACMDBG_H("for its own ipv4 address\n");
						return;
					}
					else if (data->iptype == IPA_IP_v6)
					{
						for (int num_ipv6_addr = 0; num_ipv6_addr < num_dft_rt_v6; num_ipv6_addr++)
						{
							if ((ipv6_addr[num_ipv6_addr][0] == data->ipv6_addr[0]) &&
								(ipv6_addr[num_ipv6_addr][1] == data->ipv6_addr[1]) &&
								(ipv6_addr[num_ipv6_addr][2] == data->ipv6_addr[2]) &&
								(ipv6_addr[num_ipv6_addr][3] == data->ipv6_addr[3]))
							{
								IPACMDBG_H("Ignore IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT in STA mode\n");
								IPACMDBG_H("for its own ipv6 address\n");
								return;
							}
						}
					}
				}

				IPACMDBG_H("wan-iface got client \n");
				/* first construc WAN-client full header */
				if(memcmp(data->mac_addr,
						invalid_mac,
						sizeof(data->mac_addr)) == 0)
				{
					IPACMDBG_H("Received invalid Client MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 data->mac_addr[0], data->mac_addr[1], data->mac_addr[2],
					 data->mac_addr[3], data->mac_addr[4], data->mac_addr[5]);
					return;
				}

				if ((data->iptype == IPA_IP_v4) && wan_v4_addr_gw_set && (data->ipv4_addr == wan_v4_addr_gw))
					gw_addr = true;

				if ((data->iptype == IPA_IP_v6) && wan_v6_addr_gw_set)
				{
					if(data->ipv6_addr[0] == wan_v6_addr_gw[0] &&
					   data->ipv6_addr[1] == wan_v6_addr_gw[1] &&
					   data->ipv6_addr[2] == wan_v6_addr_gw[2] &&
					   data->ipv6_addr[3] == wan_v6_addr_gw[3])
					   	gw_addr = true;
				}

				handle_wan_hdr_init(data->mac_addr, gw_addr);
				IPACMDBG_H("construct wan-client header and route rules \n");
				/* Associate with IP and construct RT-rule */
				if (handle_wan_client_ipaddr(data) == IPACM_FAILURE)
				{
					return;
				}
				handle_wan_client_route_rule(data->mac_addr, data->iptype);
				/* Check & construct STA header */
				handle_sta_header_add_evt();
#ifdef FEATURE_DUAL_BACKHAUL
				if (data->iptype == IPA_IP_v4)
				{
					IPACM_Iface::ipacmcfg->second_backhaul_info.gateway_ipv4 =
									data->ipv4_addr;
					IPACMDBG_H("DEBUG_FR second_backhaul_info_gateway_ipv4 \
						0x%x\n", IPACM_Iface::ipacmcfg->
						second_backhaul_info.gateway_ipv4);
				}
				handle_dual_backhaul_enable(data,true);
#endif
				return;
			}
		}
		break;

	case IPA_SW_ROUTING_ENABLE:
		IPACMDBG_H("Received IPA_SW_ROUTING_ENABLE\n");
		/* handle software routing enable event */
		if(m_is_sta_mode == Q6_WAN)
		{
			install_wan_filtering_rule(true);
		}
		else
		{
			handle_software_routing_enable();
		}
		break;

	case IPA_SW_ROUTING_DISABLE:
		IPACMDBG_H("Received IPA_SW_ROUTING_DISABLE\n");
		/* handle software routing disable event */
		if(m_is_sta_mode == Q6_WAN)
		{
			/* send current DL rules to modem */
			install_wan_filtering_rule(false);
			softwarerouting_act = false;
		}
		else
		{
			handle_software_routing_disable();
		}
		break;

	case IPA_FIREWALL_CHANGE_EVENT:
		IPACMDBG_H("Received IPA_FIREWALL_CHANGE_EVENT\n");

		if(m_is_sta_mode == Q6_WAN)
		{
#ifdef FEATURE_VLAN_MPDN
			if (ipacmcfg->vlan_firewall_change_handle)
			{
				ipacmcfg->vlan_firewall_change_handle = false;
			}
			else
			{
				break;
			}

			del_wan_firewall_rule(IPA_IP_v4);
			config_wan_firewall_rule(IPA_IP_v4);

			del_wan_firewall_rule(IPA_IP_v6);
			config_wan_firewall_rule(IPA_IP_v6);
			install_wan_filtering_rule(false);
#else
			if (is_default_gateway == false)
			{
				IPACMDBG_H("Interface %s is not default gw, return.\n", dev_name);
				return;
			}

			if(ip_type == IPA_IP_v4)
			{
				del_wan_firewall_rule(IPA_IP_v4);
				config_wan_firewall_rule(IPA_IP_v4);
				install_wan_filtering_rule(false);
			}
			else if(ip_type == IPA_IP_v6)
			{
				del_wan_firewall_rule(IPA_IP_v6);
				config_wan_firewall_rule(IPA_IP_v6);
				install_wan_filtering_rule(false);
			}
			else if(ip_type == IPA_IP_MAX)
			{
				del_wan_firewall_rule(IPA_IP_v4);
				config_wan_firewall_rule(IPA_IP_v4);

				del_wan_firewall_rule(IPA_IP_v6);
				config_wan_firewall_rule(IPA_IP_v6);
				install_wan_filtering_rule(false);
			}
			else
			{
				IPACMERR("IP type is not expected.\n");
			}
#endif
		}
		else
		{
			if (active_v4)
			{
				del_dft_firewall_rules(IPA_IP_v4);
				config_dft_firewall_rules(IPA_IP_v4);
			}
			if (active_v6)
			{

				del_dft_firewall_rules(IPA_IP_v6);
				config_dft_firewall_rules(IPA_IP_v6);
			}
		}
		break;

	case IPA_WLAN_SWITCH_TO_SCC:
		if(IPACM_Wan::backhaul_is_sta_mode == true)
		{
			IPACMDBG_H("Received IPA_WLAN_SWITCH_TO_SCC\n");
			if(ip_type == IPA_IP_MAX)
			{
				handle_wlan_SCC_MCC_switch(true, IPA_IP_v4);
				handle_wlan_SCC_MCC_switch(true, IPA_IP_v6);
				handle_wan_client_SCC_MCC_switch(true, IPA_IP_v4);
				handle_wan_client_SCC_MCC_switch(true, IPA_IP_v6);
			}
			else
			{
				handle_wlan_SCC_MCC_switch(true, ip_type);
				handle_wan_client_SCC_MCC_switch(true, ip_type);
			}
		}
		break;

	case IPA_WLAN_SWITCH_TO_MCC:
		/* check if alt_dst_pipe set or not */
		for (cnt = 0; cnt < tx_prop->num_tx_props; cnt++)
		{
			if (tx_prop->tx[cnt].alt_dst_pipe == 0)
			{
				IPACMERR("Tx(%d): wrong tx property: alt_dst_pipe: 0. \n", cnt);
				return;
			}
		}

		if(IPACM_Wan::backhaul_is_sta_mode == true)
		{
			IPACMDBG_H("Received IPA_WLAN_SWITCH_TO_MCC\n");
			if(ip_type == IPA_IP_MAX)
			{
				handle_wlan_SCC_MCC_switch(false, IPA_IP_v4);
				handle_wlan_SCC_MCC_switch(false, IPA_IP_v6);
				handle_wan_client_SCC_MCC_switch(false, IPA_IP_v4);
				handle_wan_client_SCC_MCC_switch(false, IPA_IP_v6);
			}
			else
			{
				handle_wlan_SCC_MCC_switch(false, ip_type);
				handle_wan_client_SCC_MCC_switch(false, ip_type);
			}
		}
		break;
#ifdef FEATURE_L2TP
	case IPA_ADD_L2TP_CLIENT:
		if(active_v4)
		{
			ipacm_event_data_all *data = (ipacm_event_data_all *)param;
			handle_l2tp_client_add(data->iface_name);
			install_wan_filtering_rule(false);
		}
		break;

	case IPA_DEL_L2TP_CLIENT:
		if(active_v4)
		{
			ipacm_event_data_all *data = (ipacm_event_data_all *)param;
			handle_l2tp_client_del(data->iface_name);
			install_wan_filtering_rule(false);
		}
		break;
#endif
#ifdef FEATURE_SOCKSv5
	case IPA_UPDATE_SOCKSv5_v6_CONN:
		IPACMDBG_H(" Received IPA_UPDATE_SOCKSv5_v6_CONN\n");
	case IPA_HANDLE_SOCKSv5_UP:
		IPACMDBG_H(" Received IPA_HANDLE_SOCKSv5_UP\n");
		/* handle IPA_HANDLE_SOCKSv5_UP event */
		if(m_is_sta_mode == Q6_WAN)
		{
			/* send current DL rules to modem */
			install_wan_filtering_rule(false, true);
		}
		break;
	case IPA_HANDLE_SOCKSv5_DOWN:
		{
			IPACMDBG_H("Received IPA_HANDLE_SOCKSv5_DOWN\n");
			/* handle IPA_HANDLE_SOCKSv5_DOWN event */
			if(m_is_sta_mode == Q6_WAN)
			{
				/* send current DL rules to modem */
				install_wan_filtering_rule(false, false);
			}
		}
		break;
#endif
#ifdef IPA_MTU_EVENT_MAX
	case IPA_MTU_SET:
	{
		ipacm_event_mtu_info *data = (ipacm_event_mtu_info *)param;
		ipa_mtu_info *mtu_info = &(data->mtu_info);
		ipa_interface_index = iface_ipa_index_query(data->if_index);
		bool post_mtu_update_event = false;

		if (ipa_interface_index == ipa_if_num)
		{
			IPACMDBG_H("Received IPA_MTU_SET for interface (%d)\n",
				ipa_interface_index);
			if (mtu_info->ip_type == IPA_IP_v4 || mtu_info->ip_type == IPA_IP_MAX)
			{
				/* Update v4_mtu. */
				mtu_v4 = mtu_info->mtu_v4;
				mtu_v4_set = true;
				if (active_v4)
				{
					/* upstream interface. update default MTU. */
					mtu_default_wan_v4 = mtu_v4;
					post_mtu_update_event = true;
				}

#if defined(FEATURE_EoGRE) || defined(FEATURE_PMIPV6)
				/*Always update MTU for GRE since initial MTU set will come before GRE is enabled, post if GRE is enabled */
				mtu_gre_v4 = mtu_v4;
				if (IPACM_Iface::ipacmcfg->eogre_enabled || IPACM_Iface::ipacmcfg->pmip_details.pmipv6_enabled)
					post_mtu_update_event = true;
#endif

				IPACMDBG_H("Updated v4 mtu=[%d] for (%s), upstream_mtu=[%d]\n",
					mtu_v4, mtu_info->if_name, mtu_default_wan_v4);
			}
			if (mtu_info->ip_type == IPA_IP_v6 || mtu_info->ip_type == IPA_IP_MAX)
			{
				/* Update v6_mtu. */
				mtu_v6 = mtu_info->mtu_v6;
				mtu_v6_set = true;
				if (active_v6)
				{
					/* upstream interface. update default MTU. */
					mtu_default_wan_v6 = mtu_v6;
					post_mtu_update_event = true;
				}

#if defined(FEATURE_EoGRE) || defined(FEATURE_PMIPV6)
				/*Always update MTU for GRE since initial MTU set will come before GRE is enabled, post if GRE is enabled */
				mtu_gre_v6 = mtu_v6;
				if (IPACM_Iface::ipacmcfg->eogre_enabled || IPACM_Iface::ipacmcfg->pmip_details.pmipv6_enabled)
					post_mtu_update_event = true;
#endif
				IPACMDBG_H("Updated v6 mtu=[%d] for (%s), upstream_mtu=[%d]\n",
					mtu_v6, mtu_info->if_name, mtu_default_wan_v6);
			}

			if (post_mtu_update_event)
			{
				ipacm_event_mtu_info *mtu_event;
				ipacm_cmd_q_data evt_data;
				mtu_event = (ipacm_event_mtu_info *)malloc(sizeof(*mtu_event));
				if(mtu_event == NULL)
				{
					IPACMERR("Failed to allocate memory.\n");
					return;
				}
				memcpy(&mtu_event->mtu_info, mtu_info, sizeof(ipa_mtu_info));
				evt_data.event = IPA_MTU_UPDATE;
				evt_data.evt_data = mtu_event;
				/* finish command queue */
				IPACMDBG_H("Posting IPA_MTU_UPDATE event\n");
				IPACM_EvtDispatcher::PostEvt(&evt_data);
			}
		}
	}
	break;
#endif

#ifdef FEATURE_EoGRE
	case IPA_WAN_HANDLE_EoGRE_UP:
		IPACMDBG_H("Received and will process an IPA_HANDLE_EoGRE_UP\n");
		eogre_up();
		break;

	case IPA_WAN_HANDLE_EoGRE_DOWN:
		IPACMDBG_H("Received and will process an IPA_HANDLE_EoGRE_DOWN\n");
		eogre_down();
		break;
#endif
#ifdef FEATURE_PMIPV6
	case IPA_HANDLE_GRE_UP:
		IPACMDBG_H("Received and will process an IPA_HANDLE_EoGRE_UP\n");
		gre_up();
		break;

	case IPA_HANDLE_GRE_DOWN:
		IPACMDBG_H("Received and will process an IPA_HANDLE_EoGRE_DOWN\n");
		gre_down();
		break;
#endif
#ifdef FEATURE_IPoGRE
	case IPA_HANDLE_IPOGRE_UP:
	{
		ipa_ipgre_info ipgre_info = IPACM_Iface::ipacmcfg->ipgre_info;
		if (ipgre_info.iptype == IPA_IP_v4 &&
			ipgre_info.ipv4_src == wan_v4_addr)
		{
			IPACMDBG_H("Received and will process an IPA_HANDLE_GRE_UP\n");
			gre_up();
		}
		else if (ipgre_info.iptype == IPA_IP_v6 &&
			memcmp(ipgre_info.ipv6_src, m_ipv6_addr, sizeof(ipgre_info.ipv6_src)) == 0)
		{
			IPACMDBG_H("Received and will process an IPA_HANDLE_GRE_UP\n");
			gre_up();
		}
		else {
			IPACMDBG_H("Received and will process an IPA_HANDLE_GRE_UP for differenct instance\n");
			IPACM_Iface::ipacmcfg->ipogre_enabled = false;
		}
		break;
	}

	case IPA_HANDLE_IPOGRE_DOWN:
		IPACMDBG_H("Received and will process an IPA_HANDLE_GRE_DOWN\n");
		gre_down();
		break;
#endif

#ifdef FEATURE_IPA_IPSEC
	case IPA_IPSEC_LAN_CLIENT_ROUTE_ADD_EVENT:
		{
			ipa_ip_type iptype = *(ipa_ip_type *)param;
			IPACMDBG_H("New client RT rule added. Calling installWanPostIpsecRt(%s)\n", iptype == IPA_IP_v4 ? "IPA_IP_v4" : "IPA_IP_v6");
			if (installWanPostIpsecRt(iptype) != IPACM_SUCCESS)
				IPACMERR("installWanPostIpsecRt(%s) failed\n", iptype == IPA_IP_v4 ? "IPA_IP_v4" : "IPA_IP_v6");
		}
		break;
#endif

	case IPA_IPACM_DISABLE:
		if(m_is_sta_mode == WLAN_WAN)
		{
			IPACMDBG_H("Received IPA_IPACM_DISABLE\n");
			handle_down_evt();
			/* reset the STA-iface category to unknown */
			IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_cat = UNKNOWN_IF;
			IPACMDBG_H("IPA_WAN_STA (%s):ipa_index (%d) instance close \n", IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name, ipa_if_num);
			IPACM_Iface::ipacmcfg->DelNatIfaces(dev_name); // delete NAT-iface
			delete this;
			return;
		}
		else if(m_is_sta_mode == Q6_WAN)
		{
			IPACMDBG_H("Received IPA_IPACM_DISABLE\n");
			handle_down_evt_ex();
			IPACMDBG_H("IPA_WAN_Q6 (%s):ipa_index (%d) instance close \n", IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name, ipa_if_num);
#if defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
			info.ipv4_addr = wan_v4_addr;
			info.mux_id = ext_prop->ext[0].mux_id;;
			memcpy(info.iface_name, dev_name, sizeof(dev_name));
			/* add qmuxd mapping*/
			IPACM_Iface::ipacmcfg->del_mux_id_mapping(&info);
#endif //defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
			IPACM_Iface::ipacmcfg->DelNatIfaces(dev_name); // delete NAT-iface
			delete this;
			return;
		}
		else if (m_is_sta_mode == ECM_WAN)
		{
			IPACMDBG_H("Received IPA_IPACM_DISABLE(wan_mode:%d)\n", m_is_sta_mode);
			/* delete previous instance */
			handle_down_evt();
			IPACMDBG_H("IPA_WAN_CRADLE (%s):ipa_index (%d) instance close \n", IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name, ipa_if_num);
			IPACM_Iface::ipacmcfg->DelNatIfaces(dev_name); // delete NAT-iface
			delete this;
			return;
		}
		break;

#ifdef FEATURE_STATIC_POLICY
	case IPA_PDN_MUX_ID_UPDATE:
	{
		struct ipa_ioc_pdn_dscp_map_info pdn_dscp_map_info;
		ipacm_event_pdn_mux_info *data = (ipacm_event_pdn_mux_info *)param;
		ipacm_cmd_q_data evt_data;

		if (strncmp(dev_name, data->pdn_name, IPA_IFACE_NAME_LEN) == 0)
		{
			if(pthread_mutex_lock(&IPACM_Iface::ipacmcfg->pdn_dscp_lock) != 0)
			{
				IPACMERR("Unable to lock the mutex\n");
				return;
			}
			if(IPACM_Iface::ipacmcfg->pdn_dscp_table[data->indx].status == 1)
			{
				IPACM_Iface::ipacmcfg->pdn_dscp_table[data->indx].mux_id = ext_prop->ext[0].mux_id;
				IPACM_Iface::ipacmcfg->pdn_dscp_table[data->indx].status = 2;
			}

			if(IPACM_Iface::ipacmcfg->pdn_dscp_table[data->indx].status == 2)
			{
				ipacm_event_pdn_dscp_info* pdn_dscp_data = (ipacm_event_pdn_dscp_info *)
					malloc(sizeof(ipacm_event_pdn_dscp_info));
				if(pdn_dscp_data == NULL)
				{
					IPACMERR("unable to allocate memory for event pdn_dscp_data\n");
					pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->pdn_dscp_lock);
					return;
				}

				memset(pdn_dscp_data, 0, sizeof(ipacm_event_pdn_dscp_info));
				pdn_dscp_data->enable = 1;
				pdn_dscp_data->dscp_val = IPACM_Iface::ipacmcfg->pdn_dscp_table[data->indx].dscp_val;
				pdn_dscp_data->mux_id = IPACM_Iface::ipacmcfg->pdn_dscp_table[data->indx].mux_id;

				IPACMDBG_H("Posting IPA_PDN_DSCP_UPDATE_EVENT event!\n");

				evt_data.event = IPA_PDN_DSCP_UPDATE_EVENT;
				evt_data.evt_data = pdn_dscp_data;
				IPACM_EvtDispatcher::PostEvt(&evt_data);

				memset(&pdn_dscp_map_info, 0, sizeof(pdn_dscp_map_info));
				memset(&pdn_dscp_map_info.pdn_dscp_map, 255, sizeof(pdn_dscp_map_info));
				pdn_dscp_map_info.add = 1;
				pdn_dscp_map_info.pdn_dscp_map[IPACM_Iface::ipacmcfg->pdn_dscp_table[data->indx].mux_id] =
					IPACM_Iface::ipacmcfg->pdn_dscp_table[data->indx].dscp_val;
				if(0 != ioctl(m_fd_ipa, IPA_IOC_UPDATE_PDN_DSCP_MAPPING, &pdn_dscp_map_info))
				{
					IPACMERR("ioctl to IPA driver failed for setting PDN-DSCP Mapping\n");
				}
			}
			pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->pdn_dscp_lock);
		}
	}
	break;

		case IPA_HANDLE_LAN_VLAN_PDN_DOWN_STATIC:
		{
			IPACMDBG_H("Received IPA_HANDLE_LAN_VLAN_PDN_DOWN_STATIC event:%s\n", dev_name);
			ipacm_event_vlan_pdn *vlandown = (ipacm_event_vlan_pdn *)param;
			int j = 0, k = 0;

			if(vlandown == NULL)
			{
				IPACMERR("Invalid lanvlandown data\n");
				return;
			}
			if(vlandown->iptype == IPA_IP_v4)
			{
				IPACMDBG_H("Received IPA_HANDLE_LAN_VLAN_PDN_DOWN_STATIC event for IPv4\n");

				if(modem_ipv4_pdn_index < 0 || modem_ipv4_pdn_index >= IPA_MAX_NUM_SW_PDNS)
				{
					IPACMDBG_H("modem_ipv4_pdn_index:%d not valid\n", modem_ipv4_pdn_index);
					return;
				}

				for(j = 0; j < IPA_MAX_NUM_SW_PDNS; j++)
				{
					if(ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs[j] == vlandown->VlanID)
					{
						IPACMDBG_H("removing v4 pdn entry in %d with IP:0x%X, vid:%d and vid_cnt:%d\n",
							j, ipv4_to_iface[modem_ipv4_pdn_index].ipv4_addr,
							ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs[j],
							ipv4_to_iface[modem_ipv4_pdn_index].VID_cnt);
						ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs[j] = 0;
						ipv4_to_iface[modem_ipv4_pdn_index].VID_cnt--;
						break;
					}
				}
				for(k = j; k < IPA_MAX_NUM_SW_PDNS - 1; k++)
				{
					ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs[k] =
						ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs[k+1];
				}
				ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs[k] = 0;
			}
			else if(vlandown->iptype == IPA_IP_v6)
			{
				IPACMDBG_H("Received IPA_HANDLE_LAN_VLAN_PDN_DOWN_STATIC event for IPv6\n");

				if(modem_ipv6_pdn_index < 0 || modem_ipv6_pdn_index >= IPA_MAX_NUM_SW_PDNS)
				{
					IPACMDBG_H("modem_ipv6_pdn_index:%d not valid\n", modem_ipv6_pdn_index);
					return;
				}

				for(j = 0; j < IPA_MAX_NUM_SW_PDNS; j++)
				{
					if(ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[j] == vlandown->VlanID)
					{
						IPACMDBG_H("removing v6 pdn entry in %d with prefix:0x%08x%08x, vid:%d and vid_cnt:%d\n",
							j, ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[0],
							ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[1],
							ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[j],
							ipv6_to_iface[modem_ipv6_pdn_index].VID_cnt);
						ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[j] = 0;
						ipv6_to_iface[modem_ipv6_pdn_index].VID_cnt--;
						break;
					}
				}
				for(k = j; k < IPA_MAX_NUM_SW_PDNS - 1; k++)
				{
					ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[k] =
						ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[k+1];
				}
				ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[k] = 0;
			}
			else if(vlandown->iptype == IPA_IP_MAX)
			{
				IPACMDBG_H("Received IPA_HANDLE_LAN_VLAN_PDN_DOWN_STATIC event for IPV4 and IPv6\n");

				if(modem_ipv4_pdn_index < 0 || modem_ipv4_pdn_index >= IPA_MAX_NUM_SW_PDNS)
				{
					IPACMDBG_H("modem_ipv4_pdn_index:%d not valid\n", modem_ipv4_pdn_index);
					return;
				}

				for(j = 0; j < IPA_MAX_NUM_SW_PDNS; j++)
				{
					if(ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs[j] == vlandown->VlanID)
					{
						IPACMDBG_H("removing v4 pdn entry in %d with IP:0x%X, vid:%d and vid_cnt:%d\n",
							j, ipv4_to_iface[modem_ipv4_pdn_index].ipv4_addr,
							ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs[j],
							ipv4_to_iface[modem_ipv4_pdn_index].VID_cnt);
						ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs[j] = 0;
						ipv4_to_iface[modem_ipv4_pdn_index].VID_cnt--;
						break;
					}
				}
				for(k = j; k < IPA_MAX_NUM_SW_PDNS - 1; k++)
				{
					ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs[k] =
						ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs[k+1];
				}
				ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs[k] = 0;

				if(modem_ipv6_pdn_index < 0 || modem_ipv6_pdn_index >= IPA_MAX_NUM_SW_PDNS)
				{
					IPACMDBG_H("modem_ipv6_pdn_index:%d not valid\n", modem_ipv6_pdn_index);
					return;
				}

				for(j = 0; j < IPA_MAX_NUM_SW_PDNS; j++)
				{
					if(ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[j] == vlandown->VlanID)
					{
						IPACMDBG_H("removing v6 pdn entry in %d with prefix:0x%08x%08x, vid:%d and vid_cnt:%d\n",
							j, ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[0],
							ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[1],
							ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[j],
							ipv6_to_iface[modem_ipv6_pdn_index].VID_cnt);
						ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[j] = 0;
						ipv6_to_iface[modem_ipv6_pdn_index].VID_cnt--;
						break;
					}
				}
				for(k = j; k < IPA_MAX_NUM_SW_PDNS - 1; k++)
				{
					ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[k] =
						ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[k+1];
				}
				ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[k] = 0;
			}
		}
		break;
#endif

		default:
		break;
	}

	return;
}

#ifdef FEATURE_VLAN_MPDN
int IPACM_Wan::get_wan_v4_index(ipacm_wan_iface_type sta_mode)
{
	if(sta_mode == WLAN_WAN)
		return IPACM_Wan::wlan_v4_vlan_index;
	else if(sta_mode == ECM_WAN)
		return IPACM_Wan::eth_sta_v4_vlan_index;
	return IPACM_FAILURE;
}

int IPACM_Wan::get_wan_v6_index(ipacm_wan_iface_type sta_mode)
{
	if(sta_mode == WLAN_WAN)
		return IPACM_Wan::wlan_v6_vlan_index;
	else if(sta_mode == ECM_WAN)
		return IPACM_Wan::eth_sta_v6_vlan_index;
	return IPACM_FAILURE;
}

void IPACM_Wan::get_vlan_association_info(ipacm_vlan_association_info* vlan_info)
{
	bool v4_found = false;
	bool v6_found = false;

	vlan_info->v6_idx[WLAN_WAN] = IPACM_Wan::get_wan_v6_index(WLAN_WAN);
	vlan_info->v4_idx[WLAN_WAN] = IPACM_Wan::get_wan_v4_index(WLAN_WAN);
	vlan_info->v6_idx[ECM_WAN] = IPACM_Wan::get_wan_v6_index(ECM_WAN);
	vlan_info->v4_idx[ECM_WAN] = IPACM_Wan::get_wan_v4_index(ECM_WAN);

	/* check if vlan-id associated with wlan/eth-STA wan index for ipv4 */
	if((vlan_info->v4_idx[WLAN_WAN] >= 0) && ipv4_to_iface[vlan_info->v4_idx[WLAN_WAN]].VID_cnt > 0)
	{
		for (int vlan_idx = 0; vlan_idx < ipv4_to_iface[vlan_info->v4_idx[WLAN_WAN]].VID_cnt; vlan_idx++)
		{
			if(ipv4_to_iface[vlan_info->v4_idx[WLAN_WAN]].associated_VIDs[vlan_idx] == vlan_info->vlan_id)
			{
				IPACMDBG_H("VlanID found in associated_VIDs in V4 WLAN STA BH\n");
				vlan_info->v4_association = WLAN_WAN;
				vlan_info->v4_vlan_idx[WLAN_WAN] = vlan_idx;
				v4_found = true;
				break;
			}
		}
	}

	if(!v4_found && (vlan_info->v4_idx[ECM_WAN] >= 0) && ipv4_to_iface[vlan_info->v4_idx[ECM_WAN]].VID_cnt > 0)
	{
		for (int vlan_idx = 0; vlan_idx < ipv4_to_iface[vlan_info->v4_idx[ECM_WAN]].VID_cnt; vlan_idx++)
		{
			if(ipv4_to_iface[vlan_info->v4_idx[ECM_WAN]].associated_VIDs[vlan_idx] == vlan_info->vlan_id)
			{
				IPACMDBG_H("VlanID found in associated_VIDs in V4 ETH STA BH\n");
				vlan_info->v4_association = ECM_WAN;
				vlan_info->v4_vlan_idx[ECM_WAN] = vlan_idx;
				v4_found = true;
				break;
			}
		}
	}

	/* check if vlan-id associated with wlan/eth-STA wan index for ipv6 */
	if((vlan_info->v6_idx[WLAN_WAN] >= 0) && ipv6_to_iface[vlan_info->v6_idx[WLAN_WAN]].VID_cnt > 0)
	{
		for (int vlan_idx = 0; vlan_idx < ipv6_to_iface[vlan_info->v6_idx[WLAN_WAN]].VID_cnt; vlan_idx++)
		{
			if(ipv6_to_iface[vlan_info->v6_idx[WLAN_WAN]].associated_VIDs[vlan_idx] == vlan_info->vlan_id)
			{
				IPACMDBG_H("VlanID found in associated_VIDs in V6 STA BH\n");
				vlan_info->v6_association = WLAN_WAN;
				vlan_info->v6_vlan_idx[WLAN_WAN] = vlan_idx;
				v6_found = true;
				goto end;
			}
		}
	}

	if(!v6_found && (vlan_info->v6_idx[ECM_WAN] >= 0) && ipv6_to_iface[vlan_info->v6_idx[ECM_WAN]].VID_cnt > 0)
	{
		for (int vlan_idx = 0; vlan_idx < ipv6_to_iface[vlan_info->v6_idx[ECM_WAN]].VID_cnt; vlan_idx++)
		{
			if(ipv6_to_iface[vlan_info->v6_idx[ECM_WAN]].associated_VIDs[vlan_idx] == vlan_info->vlan_id)
			{
				IPACMDBG_H("VlanID found in associated_VIDs in V6 STA BH\n");
				vlan_info->v6_association = ECM_WAN;
				vlan_info->v6_vlan_idx[ECM_WAN] = vlan_idx;
				v6_found = true;
				goto end;
			}
		}
	}


	/* check if vlan-id associated with LTE wan index for ipv4+ipv6 */
	if(!v4_found || !v6_found)
	{
		for(int pdn_idx = 0; pdn_idx < IPA_MAX_NUM_SW_PDNS; pdn_idx++)
		{
			for(int vlan_idx = 0;(pdn_idx != vlan_info->v4_idx[WLAN_WAN] &&
					pdn_idx != vlan_info->v4_idx[ECM_WAN]) &&
					!v4_found && vlan_idx < ipv4_to_iface[pdn_idx].VID_cnt; vlan_idx++)
			{
				if(ipv4_to_iface[pdn_idx].associated_VIDs[vlan_idx] == vlan_info->vlan_id)
				{
					IPACMDBG_H("VlanID found in associated_VIDs in V4 LTE BH\n");
					vlan_info->v4_association = Q6_WAN;
					vlan_info->v4_idx[Q6_WAN] = pdn_idx;
					vlan_info->v4_vlan_idx[Q6_WAN] = vlan_idx;
					v4_found = true;
					break;
				}
			}
			for(int vlan_idx = 0;(pdn_idx != vlan_info->v6_idx[WLAN_WAN] &&
				pdn_idx != vlan_info->v6_idx[ECM_WAN]) &&
			 	!v6_found && vlan_idx < ipv6_to_iface[pdn_idx].VID_cnt; vlan_idx++)
			{
				if(ipv6_to_iface[pdn_idx].associated_VIDs[vlan_idx] == vlan_info->vlan_id)
				{
					IPACMDBG_H("VlanID found in associated_VIDs in V6 LTE BH\n");
					vlan_info->v6_association = Q6_WAN;
					vlan_info->v6_idx[Q6_WAN] = pdn_idx;
					vlan_info->v6_vlan_idx[Q6_WAN] = vlan_idx;
					v6_found = true;
					break;
				}
			}
			if(v4_found && v6_found)
				break;
		}
	}

end:
	IPACMDBG_H("Values on exit: \n");
	IPACMDBG_H("<LTE> VLAN <%d>: V4 -->PDN [%d] VLAN [%d] V6 -->PDN[%d] VLAN[%d]\n",
			vlan_info->vlan_id, vlan_info->v4_idx[Q6_WAN], vlan_info->v4_vlan_idx[Q6_WAN],
			vlan_info->v6_idx[Q6_WAN], vlan_info->v6_vlan_idx[Q6_WAN]);
	IPACMDBG_H("<WLAN> VLAN <%d>: V4 -->PDN [%d] VLAN [%d] V6 -->PDN[%d] VLAN[%d]\n",
			vlan_info->vlan_id, vlan_info->v4_idx[WLAN_WAN], vlan_info->v4_vlan_idx[WLAN_WAN],
			vlan_info->v6_idx[WLAN_WAN], vlan_info->v6_vlan_idx[WLAN_WAN]);
	IPACMDBG_H("<ECM> VLAN <%d>: V4 -->PDN [%d] VLAN [%d] V6 -->PDN[%d] VLAN[%d]\n",
			vlan_info->vlan_id, vlan_info->v4_idx[ECM_WAN], vlan_info->v4_vlan_idx[ECM_WAN],
			vlan_info->v6_idx[ECM_WAN], vlan_info->v6_vlan_idx[ECM_WAN]);
	return;
}

/*
 * iptype: IPA_IP_v4 or IPA_IP_v6
 * pdn_idx: Index in ipv4_to_iface or ipv6_to_iface
 * vlan_idx: Index in associated_VIDs of ipv4_to_iface[pdn_idx] or ipv6_to_iface[pdn_idx]
 * vlan_id: VLAN ID
 * vlan_up: True to post IPA_HANDLE_WAN_VLAN_PDN_UP. False to post IPA_HANDLE_WAN_VLAN_PDN_DOWN
 */
void IPACM_Wan::post_wan_vlan_pdn_event(ipa_ip_type iptype, int pdn_idx, int vlan_idx, uint16_t vlan_id, bool vlan_up)
{
	uint8_t mux_id = 0;
	int idx = vlan_idx + 1;
	ipacm_cmd_q_data evt_data;
	ipacm_event_vlan_pdn *vlan_data = NULL;

	if((vlan_idx < 0) || (vlan_idx >= IPA_MAX_NUM_SW_PDNS))
	{
		IPACMERR("Invalid VLAN Index\n");
		return;
	}

	if(pdn_idx < 0 || vlan_idx < 0 || vlan_id <= 0)
	{
		IPACMERR("Wrong param pdn_idx:%d, vlan_idx:%d, vlan_id:%d\n", pdn_idx, vlan_idx, vlan_id);
		return;
	}

	vlan_data = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
	if(vlan_data == NULL)
	{
		IPACMERR("vlan_data allocation failed\n");
		return;
	}
	memset(vlan_data, 0, sizeof(ipacm_event_vlan_pdn));
	vlan_data->VlanID = vlan_id;

	if(!vlan_up)
	{
		/* currently only support all vlans moved to WIFI not backhaul concurrency */
		if(iptype == IPA_IP_v6)
		{
			GetMuxByVid(vlan_id, &mux_id, IPA_IP_v6);
			ipv6_to_iface[pdn_idx].associated_VIDs[vlan_idx] = 0;
			while(idx < IPA_MAX_NUM_SW_PDNS && ipv6_to_iface[pdn_idx].associated_VIDs[idx] != 0)
			{
				ipv6_to_iface[pdn_idx].associated_VIDs[vlan_idx] =
						ipv6_to_iface[pdn_idx].associated_VIDs[idx];
				ipv6_to_iface[pdn_idx].associated_VIDs[idx] = 0;
				idx++;
				vlan_idx++;
			}
			ipv6_to_iface[pdn_idx].VID_cnt--;
			if(ipv6_to_iface[pdn_idx].VID_cnt == 0)
				ipv6_to_iface[pdn_idx].wan_up_vlan_v6 = false;

			if((ipv6_to_iface[pdn_idx].pIface && ipv6_to_iface[pdn_idx].pIface->m_is_sta_mode == WLAN_WAN ||
				ipv6_to_iface[pdn_idx].pIface->m_is_sta_mode == ECM_WAN) &&
				!ipv6_to_iface[pdn_idx].wan_up_vlan_v6 &&
				!(IPACM_Wan::backhaul_is_sta_mode == true && wan_up_v6))
			{
				for(int tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
				{
					if(IPA_IP_v6 == tx_prop->tx[tx_index].ip)
					{
						if (m_routing.DeleteRoutingHdl(ipv6_to_iface[pdn_idx].pIface->wan_route_rule_v6_hdl[tx_index],
											 IPA_IP_v6) == false)
						{
							IPACMDBG_H("IP-family:%d, Routing rule(hdl:0x%x) deletion failed with tx_index %d!\n",
								IPA_IP_v6, ipv6_to_iface[pdn_idx].pIface->wan_route_rule_v6_hdl[tx_index], tx_index);
						}
						else
						{
							ipv6_to_iface[pdn_idx].pIface->wan_route_rule_v6_hdl[tx_index] = 0;
						}
					}
				}
			}

			if((ipv6_to_iface[pdn_idx].pIface && ipv6_to_iface[pdn_idx].pIface->m_is_sta_mode == Q6_WAN) &&
				!isVlanWanUP_V6() && !(IPACM_Wan::backhaul_is_sta_mode == false && wan_up_v6))
			{
				if(wan_route_rule_wan_v6_hdl_a5)
				{
					IPACMDBG_H("ip-type %d: default v6 wan RT-rule deleted\n", ip_type);
					if(m_routing.DeleteRoutingHdl(wan_route_rule_wan_v6_hdl_a5, IPA_IP_v6) == false)
					{
						IPACMDBG_H("IP-family:%d, Routing rule(hdl:0x%x) deletion failed!\n", IPA_IP_v6, wan_route_rule_wan_v6_hdl_a5);
					}
					else
					{
						wan_route_rule_wan_v6_hdl_a5 = 0;
					}
				}
			}
			else
			{
				IPACMDBG_H("not deleting default v6 RT rule, default route or vlan v6 PDN is up\n");
			}
			vlan_data->mux_id = mux_id;
			vlan_data->iptype = IPA_IP_v6;
			memcpy(vlan_data->ipv6_prefix, ipv6_to_iface[pdn_idx].ipv6_prefix,
						sizeof(ipv6_to_iface[pdn_idx].ipv6_prefix));

			IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_DOWN (V6) with below information:\n");
			IPACMDBG_H("iptype V6, VlanID %d, mux_id %d, if num %d\n",
						vlan_data->VlanID, vlan_data->mux_id, ipa_if_num);
		}

		else if(iptype == IPA_IP_v4)
		{
			GetMuxByVid(vlan_id, &mux_id, IPA_IP_v4);
			ipv4_to_iface[pdn_idx].associated_VIDs[vlan_idx] = 0;
			while(idx < IPA_MAX_NUM_SW_PDNS && ipv4_to_iface[pdn_idx].associated_VIDs[idx] != 0)
			{
				ipv4_to_iface[pdn_idx].associated_VIDs[vlan_idx] =
					ipv4_to_iface[pdn_idx].associated_VIDs[idx];
				ipv4_to_iface[pdn_idx].associated_VIDs[idx] = 0;
				idx++;
				vlan_idx++;
			}
			ipv4_to_iface[pdn_idx].VID_cnt--;
			if(ipv4_to_iface[pdn_idx].VID_cnt == 0)
				ipv4_to_iface[pdn_idx].wan_up_vlan = false;

			if((ipv4_to_iface[pdn_idx].pIface && ipv4_to_iface[pdn_idx].pIface->m_is_sta_mode == WLAN_WAN ||
				ipv4_to_iface[pdn_idx].pIface->m_is_sta_mode == ECM_WAN) &&
				!ipv4_to_iface[pdn_idx].wan_up_vlan &&
				!(IPACM_Wan::backhaul_is_sta_mode == true && wan_up))
			{
				for(int tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
				{
					if(IPA_IP_v4 == tx_prop->tx[tx_index].ip)
					{
						if (m_routing.DeleteRoutingHdl(ipv4_to_iface[pdn_idx].pIface->wan_route_rule_v4_hdl[tx_index],
											 IPA_IP_v4) == false)
						{
							IPACMDBG_H("IP-family:%d, Routing rule(hdl:0x%x) deletion failed with tx_index %d!\n",
								IPA_IP_v4, ipv4_to_iface[pdn_idx].pIface->wan_route_rule_v4_hdl[tx_index], tx_index);
						}
						else
						{
							ipv4_to_iface[pdn_idx].pIface->wan_route_rule_v4_hdl[tx_index] = 0;
						}
					}
				}
			}
			vlan_data->mux_id = mux_id;
			vlan_data->iptype = IPA_IP_v4;
			vlan_data->ipv4_addr = ipv4_to_iface[pdn_idx].ipv4_addr;

			IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_DOWN (V4) with below information:\n");
			IPACMDBG_H("iptype V4, VlanID %d, mux_id %d, if num %d\n",
					vlan_data->VlanID, vlan_data->mux_id, ipa_if_num);
		}
		evt_data.event = IPA_HANDLE_WAN_VLAN_PDN_DOWN;
		evt_data.evt_data = (void *)vlan_data;

		IPACM_EvtDispatcher::PostEvt(&evt_data);
	}
	else
	{
		if(iptype == IPA_IP_v6)
		{
			IPACMDBG_H("new VLAN PDN prefix is 0x%08x%08x.\n", ipv6_prefix[0], ipv6_prefix[1]);
			ipv6_to_iface[pdn_idx].wan_up_vlan_v6 = true;
			if (ipv6_to_iface[pdn_idx].VID_cnt < IPA_MAX_NUM_SW_PDNS)
			{
				ipv6_to_iface[pdn_idx].associated_VIDs[vlan_idx] = vlan_id;
				ipv6_to_iface[pdn_idx].VID_cnt++;
				ipv6_to_iface[pdn_idx].pIface = this;
			}
			else
			{
				IPACMERR("Exceeded maximum supported VLAN IDs\n");
				free(vlan_data);
				return;
			}
			vlan_data->iptype = IPA_IP_v6;
			memcpy(vlan_data->ipv6_prefix, ipv6_prefix, sizeof(ipv6_prefix));
			if(m_is_sta_mode == WLAN_WAN)
			{
				vlan_data->mux_id = 0;
				IPACM_Wan::wlan_v6_vlan_index = pdn_idx;
				IPACMDBG_H("IPACM_Wan::wlan_v6_vlan_index: %d\n", IPACM_Wan::wlan_v6_vlan_index);
			}
			else if(m_is_sta_mode == ECM_WAN)
			{
				vlan_data->mux_id = 0;
				IPACM_Wan::eth_sta_v6_vlan_index = pdn_idx;
				IPACMDBG_H("IPACM_Wan::eth_sta_v6_vlan_index: %d\n", IPACM_Wan::eth_sta_v6_vlan_index);
			}
			else
			{
				if(ext_prop != NULL)
					vlan_data->mux_id = ext_prop->ext[0].mux_id;
				if (is_xlat && ipv6_to_iface[pdn_idx].ipv6_prefix[0] && ipv6_to_iface[pdn_idx].ipv6_prefix[1])
				{
					IPACM_Iface::ipacmcfg->add_vlan_ipv6_prefix(ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix, ipa_if_num, vlan_id);
				}
				else if (is_xlat)
				{
					ipv6_to_iface[pdn_idx].ipv6_prefix[0] = IPA_DUMMY_PREFIX;
					ipv6_to_iface[pdn_idx].ipv6_prefix[1] = IPA_DUMMY_PREFIX;
					IPACMDBG_H("XLAT case, new VLAN PDN prefix is 0x%08x%08x.\n",
							ipv6_to_iface[pdn_idx].ipv6_prefix[0],
							ipv6_to_iface[pdn_idx].ipv6_prefix[1]);
				}
			}

			IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_UP (V6) with below info:\n");
			IPACMDBG_H("iptype IPA_IP_v6, VlanID %d, mux_id %d, if num %d\n",
					vlan_id, vlan_data->mux_id, ipa_if_num);
		}

		else if(iptype == IPA_IP_v4)
		{
			ipv4_to_iface[pdn_idx].wan_up_vlan = true;
			if (ipv4_to_iface[pdn_idx].VID_cnt < IPA_MAX_NUM_SW_PDNS)
			{
				ipv4_to_iface[pdn_idx].associated_VIDs[vlan_idx] = vlan_id;
				ipv4_to_iface[pdn_idx].VID_cnt++;
				ipv4_to_iface[pdn_idx].pIface = this;
			}
			else
			{
				IPACMERR("Exceeded maximum supported VLAN IDs\n");
				free(vlan_data);
				return;
			}
			vlan_data->iptype = IPA_IP_v4;
			if(m_is_sta_mode == WLAN_WAN)
			{
				vlan_data->ipv4_addr = wan_v4_addr;
				vlan_data->mux_id = 0;
				IPACM_Wan::wlan_v4_vlan_index = pdn_idx;
				IPACMDBG_H("IPACM_Wan::wlan_v4_vlan_index: %d\n", IPACM_Wan::wlan_v4_vlan_index);
			}
			else if(m_is_sta_mode == ECM_WAN)
			{
				vlan_data->ipv4_addr = wan_v4_addr;
				vlan_data->mux_id = 0;
				IPACM_Wan::eth_sta_v4_vlan_index = pdn_idx;
				IPACMDBG_H("IPACM_Wan::eth_sta_v4_vlan_index: %d\n", IPACM_Wan::eth_sta_v4_vlan_index);
			}
			else
			{
				vlan_data->ipv4_addr = (public_wan_v4_addr_set) ?
					public_wan_v4_addr : wan_v4_addr;
				vlan_data->ip_pass_enable = ip_pass_pdn_info.enable;
				vlan_data->ip_pass_dummy_ip = (ip_pass_pdn_info.enable) ?
					ip_pass_pdn_info.pdn_ip_addr : 0;
				vlan_data->ip_pass_skip_nat = (ip_pass_pdn_info.enable) ?
					ip_pass_pdn_info.skip_nat : 0;
				if(ext_prop != NULL)
					vlan_data->mux_id = ext_prop->ext[0].mux_id;
				/* send xlat configuration for installing uplink rules */
				if (is_xlat)
				{
					vlan_data->is_xlat = true;
					ipv4_to_iface[modem_ipv4_pdn_index].is_xlat=true;
					IPACMDBG_H("xlat config enabled\n");
				}
			}

			IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_UP (V4) with below information:\n");
			IPACMDBG_H("iptype IPA_IP_v4, VlanID %d, mux_id %d, if num %d\n", vlan_id,
					 vlan_data->mux_id, ipa_if_num);
		}
		evt_data.event = IPA_HANDLE_WAN_VLAN_PDN_UP;
		evt_data.evt_data = (void *)vlan_data;

		IPACM_EvtDispatcher::PostEvt(&evt_data);
	}
}

/**
 * --STA--
 *  1. Check if it is LTE to STA switch.
 *  2. Check if the intended action of V6 association to STA is done.
 *  3. Check if V4 is already associated. Proceed to add V6
 *  4. Both V4 and V6 association is not available. Add new PDN.
 * --LTE--
 *  1. Check if it is STA to LTE switch.
 *  2. Check if the intended action of V6 association to this LTE instance is done. If so, return.
 *  3. Check if the Vlan is mapped to another V6 PDN. If so, return.
 *  4. Check if the Vlan is mapped to another V4 PDN. If so, return.
 *  5. Both V4 and V6 association is not available. Add new PDN.
 */
int IPACM_Wan::handle_vlan_backhaul_switch_v6(ipacm_event_route_vlan *data, bool v4_only_xlat)
{
	int ret = IPACM_FAILURE;
	ipacm_vlan_association_info *vlan_info = NULL;
	ipacm_event_iface_up* wanup_data = NULL;
	ipacm_cmd_q_data evt_data;

	IPACMDBG_H("num_offloaded_pdns: %d\n", num_offloaded_pdns);

	if(data == NULL)
	{
		IPACMDBG_H("Received invalid data\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Process IPA_ROUTE_ADD_VLAN_PDN_EVENT for IPV6\n");

	if((data->wan_ipv6_prefix[0] == ipv6_prefix[0]) &&
		(data->wan_ipv6_prefix[1] == ipv6_prefix[1]) || v4_only_xlat)
	{
		IPACMDBG_H("received v6 IPA_ROUTE_ADD_VLAN_PDN_EVENT for VID %d, %d\n", data->VlanID, ipa_if_num);

		IPACMDBG_H("received v6 IPA_ROUTE_ADD_VLAN_PDN_EVENT for VID %d, wan %s, %d with prefix %x:%x\n",
				data->VlanID, dev_name, ipa_if_num,
				IPACM_Wan::ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[0],
				IPACM_Wan::ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[1]);

		IPACMDBG_H("num_offloaded_pdns: %d\n", num_offloaded_pdns);
		IPACMDBG_H("data->wan_ipv6_prefix: 0x%08x%08x\n", data->wan_ipv6_prefix[0], data->wan_ipv6_prefix[1]);

		vlan_info = (ipacm_vlan_association_info *)malloc(sizeof(ipacm_vlan_association_info));
		if(vlan_info == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			return IPACM_FAILURE;
		}
		memset(vlan_info, -1, sizeof(ipacm_vlan_association_info));
		vlan_info->vlan_id = data->VlanID;

		if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
		{
			if((modem_ipv4_pdn_index >= 0) &&
					ipv4_to_iface[modem_ipv4_pdn_index].wan_up_vlan)
			{
				IPACMDBG("iface already has v4 vlan association not new\n");
			}
			goto v6_skip;
		}

		get_vlan_association_info(vlan_info);

		if (m_is_sta_mode == WLAN_WAN)
		{
			IPACMDBG_H("WLAN STA\n");
			if(vlan_info->v6_association == Q6_WAN)
			{
				IPACMDBG_H("Backhaul switch from LTE to STA - V6\n");
				if(ipv6_to_iface[vlan_info->v6_idx[Q6_WAN]].wan_up_vlan_v6 &&
					vlan_info->v6_vlan_idx[Q6_WAN] >= 0)
				{
					post_wan_vlan_pdn_event(IPA_IP_v6, vlan_info->v6_idx[Q6_WAN],
							 vlan_info->v6_vlan_idx[Q6_WAN], data->VlanID, false);
					if(vlan_info->v4_association == Q6_WAN && ipv4_to_iface[vlan_info->v4_idx[Q6_WAN]].wan_up_vlan &&
						vlan_info->v4_vlan_idx[Q6_WAN] >= 0)
							post_wan_vlan_pdn_event(IPA_IP_v4, vlan_info->v4_idx[Q6_WAN],
							 	vlan_info->v4_vlan_idx[Q6_WAN], data->VlanID, false);
					if((vlan_info->v4_idx[Q6_WAN] == -1 || ((vlan_info->v4_idx[Q6_WAN] >= 0) &&
						ipv4_to_iface[vlan_info->v4_idx[Q6_WAN]].wan_up_vlan == false)) &&
						((vlan_info->v6_idx[Q6_WAN] >= 0) && ipv6_to_iface[vlan_info->v6_idx[Q6_WAN]].wan_up_vlan_v6 == false))
					{
						num_offloaded_pdns--;
						IPACMDBG_H("Num of offloaded PDN decreased to %d\n", num_offloaded_pdns);
					}
				}
				else
				{
					IPACMDBG_H("Already posted IPA_HANDLE_WAN_VLAN_PDN_DOWN (v6) and (v4) for LTE\n");
				}
			}
			else if(vlan_info->v6_association == WLAN_WAN)
			{
				IPACMERR("v6 vlan wan is already up for %s, vlan id: %d\n", dev_name, data->VlanID);
				goto fail;
			}
			else if(vlan_info->v4_association == WLAN_WAN)
			{
				IPACMDBG("iface already has v4 vlan association, not new\n");
			}
			else if(vlan_info->v4_idx[WLAN_WAN] == -1 && vlan_info->v6_idx[WLAN_WAN] == -1 &&
				(sta_ipv4_pdn_index == -1 || ((sta_ipv4_pdn_index >= 0) && ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan == false)) &&
				((sta_ipv6_pdn_index >= 0) && ipv6_to_iface[sta_ipv6_pdn_index].wan_up_vlan_v6 == false))
			{
				if(num_offloaded_pdns >= IPA_MAX_NUM_HW_PDNS)
				{
					IPACMERR("number of offloaded PDNs %d can't add more than %d, ignoring\n",
							 num_offloaded_pdns, IPA_MAX_NUM_HW_PDNS);
					goto fail;
				}
				num_offloaded_pdns++;
				IPACMDBG_H("this is a new PDN, num of offloaded PDN increased to %d\n", num_offloaded_pdns);
			}
		}
		else if(m_is_sta_mode == ECM_WAN)
		{
			/* In future need to support ETH_WAN <-> WLAN_WAN Switching here*/
			IPACMDBG_H("ECM STA\n");
			if(vlan_info->v6_association == Q6_WAN)
			{
				IPACMDBG_H("Backhaul switch from LTE to STA - V6\n");
				if(ipv6_to_iface[vlan_info->v6_idx[Q6_WAN]].wan_up_vlan_v6 &&
					vlan_info->v6_vlan_idx[Q6_WAN] >= 0)
				{
					post_wan_vlan_pdn_event(IPA_IP_v6, vlan_info->v6_idx[Q6_WAN],
							 vlan_info->v6_vlan_idx[Q6_WAN], data->VlanID, false);
					if(vlan_info->v4_association == Q6_WAN && ipv4_to_iface[vlan_info->v4_idx[Q6_WAN]].wan_up_vlan &&
						vlan_info->v4_vlan_idx[Q6_WAN] >= 0)
						post_wan_vlan_pdn_event(IPA_IP_v4, vlan_info->v4_idx[Q6_WAN],
							 vlan_info->v4_vlan_idx[Q6_WAN], data->VlanID, false);
					if((vlan_info->v4_idx[Q6_WAN] == -1 && ((vlan_info->v4_idx[Q6_WAN] >= 0) &&
						ipv4_to_iface[vlan_info->v4_idx[Q6_WAN]].wan_up_vlan == false)) &&
						((vlan_info->v6_idx[Q6_WAN] >= 0) && ipv6_to_iface[vlan_info->v6_idx[Q6_WAN]].wan_up_vlan_v6 == false))
					{
						num_offloaded_pdns--;
						IPACMDBG_H("Num of offloaded PDN decreased to %d\n", num_offloaded_pdns);
					}
				}
				else
				{
					IPACMDBG_H("Already posted IPA_HANDLE_WAN_VLAN_PDN_DOWN (v6) and (v4) for LTE\n");
				}
			}
			else if(vlan_info->v6_association == ECM_WAN)
			{
				IPACMERR("v6 vlan wan is already up for %s, vlan id: %d\n", dev_name, data->VlanID);
				goto fail;
			}
			else if(vlan_info->v4_association == ECM_WAN)
			{
				IPACMDBG("iface already has v4 vlan association, not new\n");
			}
			else if(vlan_info->v4_idx[ECM_WAN] == -1 && vlan_info->v6_idx[ECM_WAN] == -1 &&
				(sta_ipv4_pdn_index == -1 || ((sta_ipv4_pdn_index >= 0) && ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan == false)) &&
				((sta_ipv6_pdn_index >= 0) && ipv6_to_iface[sta_ipv6_pdn_index].wan_up_vlan_v6 == false))
			{
				if(num_offloaded_pdns >= IPA_MAX_NUM_HW_PDNS)
				{
					IPACMERR("number of offloaded PDNs %d can't add more than %d, ignoring\n",
							 num_offloaded_pdns, IPA_MAX_NUM_HW_PDNS);
					goto fail;
				}
				num_offloaded_pdns++;
				IPACMDBG_H("this is a new PDN, num of offloaded PDN increased to %d\n", num_offloaded_pdns);
			}
		}
		else
		{
			IPACMDBG_H("LTE\n");
			IPACMDBG_H("modem_ipv4_pdn_index: %d\n", modem_ipv4_pdn_index);
			IPACMDBG_H("modem_ipv6_pdn_index: %d\n", modem_ipv6_pdn_index);
			if(vlan_info->v6_association == WLAN_WAN || vlan_info->v6_association == ECM_WAN)
			{
				IPACMDBG_H("Backhaul switch from STA to LTE - V6\n");
				if(ipv6_to_iface[vlan_info->v6_idx[vlan_info->v6_association]].wan_up_vlan_v6 &&
					vlan_info->v6_vlan_idx[vlan_info->v6_association] >= 0)
				{
					post_wan_vlan_pdn_event(IPA_IP_v6, vlan_info->v6_idx[vlan_info->v6_association],
							 vlan_info->v6_vlan_idx[vlan_info->v6_association], data->VlanID, false);
					if(vlan_info->v4_idx[vlan_info->v6_association] >= 0 &&
						ipv4_to_iface[vlan_info->v4_idx[vlan_info->v6_association]].wan_up_vlan &&
						vlan_info->v4_vlan_idx[vlan_info->v6_association] >= 0)
							post_wan_vlan_pdn_event(IPA_IP_v4, vlan_info->v4_idx[vlan_info->v6_association],
							 	vlan_info->v4_vlan_idx[vlan_info->v6_association], data->VlanID, false);
					if((vlan_info->v4_idx[vlan_info->v6_association] == -1 || ((vlan_info->v4_idx[vlan_info->v6_association] >= 0) &&
						ipv4_to_iface[vlan_info->v4_idx[vlan_info->v6_association]].wan_up_vlan == false)) &&
						((vlan_info->v6_idx[vlan_info->v6_association] >= 0) &&
						ipv6_to_iface[vlan_info->v6_idx[vlan_info->v6_association]].wan_up_vlan_v6 == false))
					{
						num_offloaded_pdns--;
						IPACMDBG_H("Num of offloaded PDN decreased to %d\n", num_offloaded_pdns);
					}
				}
				else
				{
					IPACMDBG_H("Already posted IPA_HANDLE_WAN_VLAN_PDN_DOWN (v6) and (v4) for STA\n");
				}
			}
			else if(vlan_info->v6_association == Q6_WAN && vlan_info->v6_idx[Q6_WAN] == modem_ipv6_pdn_index)
			{
				IPACMERR("v6 vlan wan is already up for %s, vlan id: %d\n", dev_name, data->VlanID);
				goto fail;
			}
			else if(vlan_info->v6_association == Q6_WAN && vlan_info->v6_idx[Q6_WAN] != modem_ipv6_pdn_index)
			{
				IPACMERR("VID (%d) already mapped to v6 PDN %d, can't map to v6 PDN %d\n",data->VlanID,
				vlan_info->v6_idx[Q6_WAN], modem_ipv6_pdn_index);
				goto fail;
			}
			else if(vlan_info->v4_idx[Q6_WAN] != -1 && vlan_info->v4_idx[Q6_WAN] != modem_ipv4_pdn_index)
			{
				IPACMERR("VID (%d) already mapped to v4 PDN %d, can't map to v6 PDN %d\n",data->VlanID,
					 	vlan_info->v4_idx[Q6_WAN], modem_ipv6_pdn_index);
				goto fail;
			}
v6_skip:
			if(vlan_info->v4_idx[Q6_WAN] == -1 && vlan_info->v6_idx[Q6_WAN] == -1 &&
				(modem_ipv4_pdn_index == -1 || ((modem_ipv4_pdn_index >= 0) && ipv4_to_iface[modem_ipv4_pdn_index].wan_up_vlan == false)) &&
				((modem_ipv6_pdn_index >= 0) && ipv6_to_iface[modem_ipv6_pdn_index].wan_up_vlan_v6 == false))
			{
				if(num_offloaded_pdns >= IPA_MAX_NUM_HW_PDNS)
				{
					IPACMERR("number of offloaded PDNs %d can't add more than %d, ignoring\n",
							 num_offloaded_pdns, IPA_MAX_NUM_HW_PDNS);
					goto fail;
				}
				num_offloaded_pdns++;
				IPACMDBG_H("this is a new PDN, num of offloaded PDN increased to %d\n", num_offloaded_pdns);
			}
		}
		/* VLAN associated with PDN now add client backhaul prefix for vlan clients and flush neigh_cache */
		wanup_data = (ipacm_event_iface_up *)malloc(sizeof(ipacm_event_iface_up));
		if (wanup_data == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			goto fail;
		}
		memset(wanup_data, 0, sizeof(ipacm_event_iface_up));
		memcpy(wanup_data->ifname, dev_name, sizeof(wanup_data->ifname));
		if (m_is_sta_mode == Q6_WAN && ext_prop != NULL)
				wanup_data->mux_id = ext_prop->ext[0].mux_id;
		wanup_data->ipv6_prefix[0] = ipv6_prefix[0];
		wanup_data->ipv6_prefix[1] = ipv6_prefix[1];
		wanup_data->vlanID = data->VlanID;
		IPACMDBG_H("Posting IPA_HANDLE_WAN_ADDR_ADD_V6 with below information:\n");
		IPACMDBG_H("if_name:%s ipv6 prefix: 0x%08x%08x mux_id %d\n", wanup_data->ifname,
				wanup_data->ipv6_prefix[0], wanup_data->ipv6_prefix[1], wanup_data->mux_id);
		memset(&evt_data, 0, sizeof(evt_data));
		evt_data.event = IPA_HANDLE_WAN_ADDR_ADD_V6;
		evt_data.evt_data = (void *)wanup_data;
		IPACM_EvtDispatcher::PostEvt(&evt_data);

		handle_route_add_vlan_pdn_evt(IPA_IP_v6, data->VlanID);
		ret = IPACM_SUCCESS;
	}
fail:
	if(vlan_info != NULL)
		free(vlan_info);
        return ret;
}

/**
 * --STA--
 *  1. Check if it is LTE to STA switch.
 *  2. Check if the intended action of V4 association to STA is done.
 *  3. Check if V6 is already associated. Proceed to add V4
 *  4. Both V4 and V6 association is not available. Add new PDN.
 * --LTE--
 *  1. Check if it is STA to LTE switch.
 *  2. Check if the intended action of V4 association to this LTE instance is done. If so, return.
 *  3. Check if the Vlan is mapped to another V4 PDN. If so, return.
 *  4. Check if the Vlan is mapped to another V6 PDN. If so, return.
 *  5. Both V4 and V6 association is not available. Add new PDN.
 */
int IPACM_Wan::handle_vlan_backhaul_switch_v4(ipacm_event_route_vlan *data)
{
	int ret = IPACM_FAILURE;
	ipacm_vlan_association_info *vlan_info = NULL;

	if(data == NULL)
	{
		IPACMDBG_H("Received invalid data\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Process IPA_ROUTE_ADD_VLAN_PDN_EVENT for IPV4\n");

	if(data->wan_ipv4_addr == wan_v4_addr)
	{
		IPACMDBG_H("received v4 IPA_ROUTE_ADD_VLAN_PDN_EVENT for VID %d, wan %s, if %d\n", data->VlanID, dev_name, ipa_if_num);

		vlan_info = (ipacm_vlan_association_info *)malloc(sizeof(ipacm_vlan_association_info));
		if(vlan_info == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			return IPACM_FAILURE;
		}
		memset(vlan_info, -1, sizeof(ipacm_vlan_association_info));
		vlan_info->vlan_id = data->VlanID;

		if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
		{
			if((modem_ipv6_pdn_index >= 0) &&
					ipv6_to_iface[modem_ipv6_pdn_index].wan_up_vlan_v6)
			{
				IPACMDBG("iface already has v6 vlan association not new\n");
			}
			goto v4_skip;
		}

		get_vlan_association_info(vlan_info);

		if (m_is_sta_mode == WLAN_WAN)
		{
			IPACMDBG_H("WLAN STA\n");
			if(vlan_info->v4_association == Q6_WAN)
			{
				IPACMDBG_H("Backhaul switch from LTE to STA - V4\n");
				if(ipv4_to_iface[vlan_info->v4_idx[Q6_WAN]].wan_up_vlan &&
					vlan_info->v4_vlan_idx[Q6_WAN] >= 0)
				{
					post_wan_vlan_pdn_event(IPA_IP_v4, vlan_info->v4_idx[Q6_WAN],
						 vlan_info->v4_vlan_idx[Q6_WAN], data->VlanID, false);
					if(vlan_info->v6_association == Q6_WAN && ipv6_to_iface[vlan_info->v6_idx[Q6_WAN]].wan_up_vlan_v6 &&
						vlan_info->v6_vlan_idx[Q6_WAN] >= 0)
						post_wan_vlan_pdn_event(IPA_IP_v6, vlan_info->v6_idx[Q6_WAN],
						 vlan_info->v6_vlan_idx[Q6_WAN], data->VlanID, false);
					if(((vlan_info->v4_idx[Q6_WAN] >= 0) && ipv4_to_iface[vlan_info->v4_idx[Q6_WAN]].wan_up_vlan == false) &&
						(vlan_info->v6_idx[Q6_WAN] == -1 || ((vlan_info->v6_idx[Q6_WAN] >= 0) &&
						ipv6_to_iface[vlan_info->v6_idx[Q6_WAN]].wan_up_vlan_v6 == false)))
					{
						num_offloaded_pdns--;
						IPACMDBG_H("Num of offloaded PDN decreased to %d\n", num_offloaded_pdns);
					}
				}
				else
				{
					IPACMDBG_H("Already posted IPA_HANDLE_WAN_VLAN_PDN_DOWN (v4) and (v6) for LTE\n");
				}
			}
			else if(vlan_info->v4_association == WLAN_WAN)
			{
				IPACMERR("v4 vlan wan is already up for %s, vlan id: %d\n", dev_name, data->VlanID);
				goto fail;
			}
			else if(vlan_info->v6_association == WLAN_WAN)
			{
				IPACMDBG("iface already has v6 vlan association, not new\n");		
			}
			else if(vlan_info->v4_idx[WLAN_WAN] == -1 && vlan_info->v6_idx[WLAN_WAN] == -1 &&
				((sta_ipv4_pdn_index >= 0) && ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan == false) &&
				(sta_ipv6_pdn_index == -1 || ((sta_ipv6_pdn_index >= 0) && ipv6_to_iface[sta_ipv6_pdn_index].wan_up_vlan_v6 == false)))
			{
				if(num_offloaded_pdns >= IPA_MAX_NUM_HW_PDNS)
				{
					IPACMERR("number of offloaded PDNs %d can't add more than %d, ignoring\n",
							 num_offloaded_pdns, IPA_MAX_NUM_HW_PDNS);
					goto fail;
				}
				num_offloaded_pdns++;
				IPACMDBG_H("this is a new PDN, num of offloaded PDN increased to %d\n", num_offloaded_pdns);
			}
		}
		else if (m_is_sta_mode == ECM_WAN)
		{
			/* In future need to support ETH_WAN <-> WLAN_WAN Switching here*/
			IPACMDBG_H("ECM STA\n");
			if(vlan_info->v4_association == Q6_WAN)
			{
				IPACMDBG_H("Backhaul switch from LTE to ECM STA - V4\n");
				if(ipv4_to_iface[vlan_info->v4_idx[Q6_WAN]].wan_up_vlan &&
					vlan_info->v4_vlan_idx[Q6_WAN] >= 0)
				{
					post_wan_vlan_pdn_event(IPA_IP_v4, vlan_info->v4_idx[Q6_WAN],
						 vlan_info->v4_vlan_idx[Q6_WAN], data->VlanID, false);
					if(vlan_info->v6_association == Q6_WAN && ipv6_to_iface[vlan_info->v6_idx[Q6_WAN]].wan_up_vlan_v6 &&
						vlan_info->v6_vlan_idx[Q6_WAN] >= 0)
							post_wan_vlan_pdn_event(IPA_IP_v6, vlan_info->v6_idx[Q6_WAN],
						 		vlan_info->v6_vlan_idx[Q6_WAN], data->VlanID, false);
					if(((vlan_info->v4_idx[Q6_WAN] >= 0) && ipv4_to_iface[vlan_info->v4_idx[Q6_WAN]].wan_up_vlan == false) &&
						(vlan_info->v6_idx[Q6_WAN] == -1 || ((vlan_info->v6_idx[Q6_WAN] >= 0) &&
						ipv6_to_iface[vlan_info->v6_idx[Q6_WAN]].wan_up_vlan_v6 == false)))
					{
						num_offloaded_pdns--;
						IPACMDBG_H("Num of offloaded PDN decreased to %d\n", num_offloaded_pdns);
					}
				}
				else
				{
					IPACMDBG_H("Already posted IPA_HANDLE_WAN_VLAN_PDN_DOWN (v4) and (v6) for LTE\n");
				}
			}
			else if(vlan_info->v4_association == ECM_WAN)
			{
				IPACMERR("v4 vlan wan is already up for %s, vlan id: %d\n", dev_name, data->VlanID);
				goto fail;
			}
			else if(vlan_info->v6_association == ECM_WAN)
			{
				IPACMDBG("iface already has v6 vlan association, not new\n");
			}
			else if(vlan_info->v4_idx[ECM_WAN] == -1 && vlan_info->v6_idx[ECM_WAN] == -1 &&
				((sta_ipv4_pdn_index >= 0) && ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan == false) &&
				(sta_ipv6_pdn_index == -1 || ((sta_ipv6_pdn_index >= 0) && ipv6_to_iface[sta_ipv6_pdn_index].wan_up_vlan_v6 == false)))
			{
				if(num_offloaded_pdns >= IPA_MAX_NUM_HW_PDNS)
				{
					IPACMERR("number of offloaded PDNs %d can't add more than %d, ignoring\n",
							 num_offloaded_pdns, IPA_MAX_NUM_HW_PDNS);
					goto fail;
				}
				num_offloaded_pdns++;
				IPACMDBG_H("this is a new PDN, num of offloaded PDN increased to %d\n", num_offloaded_pdns);
			}
		}
		else
		{
			IPACMDBG_H("LTE\n");
			IPACMDBG_H("modem_ipv4_pdn_index: %d\n", modem_ipv4_pdn_index);
			IPACMDBG_H("modem_ipv6_pdn_index: %d\n", modem_ipv6_pdn_index);
			if(vlan_info->v4_association == WLAN_WAN || vlan_info->v4_association == ECM_WAN)
			{
				IPACMDBG_H("Backhaul switch from STA to LTE - V4\n");
				if(ipv4_to_iface[vlan_info->v4_idx[vlan_info->v4_association]].wan_up_vlan &&
					vlan_info->v4_vlan_idx[vlan_info->v4_association] >= 0)
				{
					post_wan_vlan_pdn_event(IPA_IP_v4, vlan_info->v4_idx[vlan_info->v4_association],
							 vlan_info->v4_vlan_idx[vlan_info->v4_association], data->VlanID, false);
					if(vlan_info->v6_idx[vlan_info->v4_association] >= 0 &&
						ipv6_to_iface[vlan_info->v6_idx[vlan_info->v4_association]].wan_up_vlan_v6 &&
						vlan_info->v6_vlan_idx[vlan_info->v4_association] >= 0)
							post_wan_vlan_pdn_event(IPA_IP_v6, vlan_info->v6_idx[vlan_info->v4_association],
							 	vlan_info->v6_vlan_idx[vlan_info->v4_association], data->VlanID, false);
					if(((vlan_info->v4_idx[vlan_info->v4_association] >= 0) &&
						ipv4_to_iface[vlan_info->v4_idx[vlan_info->v4_association]].wan_up_vlan == false) &&
						(vlan_info->v6_idx[vlan_info->v4_association] == -1 || ((vlan_info->v6_idx[vlan_info->v4_association] >= 0) &&
						ipv6_to_iface[vlan_info->v6_idx[vlan_info->v4_association]].wan_up_vlan_v6 == false)))
					{
						num_offloaded_pdns--;
						IPACMDBG_H("Num of offloaded PDN decreased to %d\n", num_offloaded_pdns);
					}
				}
				else
				{
					IPACMDBG_H("Already posted IPA_HANDLE_WAN_VLAN_PDN_DOWN (v4) and (v6) for STA\n");
				}
			}
			else if(vlan_info->v4_idx[Q6_WAN] != -1 && vlan_info->v4_idx[Q6_WAN] == modem_ipv4_pdn_index)
			{
				IPACMERR("v4 vlan wan is already up for %s, vlan id: %d\n", dev_name, data->VlanID);
				goto fail;
			}
			else if(vlan_info->v4_idx[Q6_WAN] != -1 && vlan_info->v4_idx[Q6_WAN] != modem_ipv4_pdn_index)
			{
				IPACMERR("VID (%d) already mapped to v4 PDN %d, can't map to v4 PDN %d\n",data->VlanID,
						vlan_info->v4_idx[Q6_WAN], modem_ipv4_pdn_index);
				goto fail;
			}
			else if(vlan_info->v6_idx[Q6_WAN] != -1 && vlan_info->v6_idx[Q6_WAN] != modem_ipv6_pdn_index)
			{
				IPACMERR("VID (%d) already mapped to v6 PDN %d, can't map to v4 PDN %d\n",data->VlanID,
						 vlan_info->v6_idx[Q6_WAN], modem_ipv4_pdn_index);
				goto fail;
			}
v4_skip:
			if(vlan_info->v4_idx[Q6_WAN] == -1 && vlan_info->v6_idx[Q6_WAN] == -1 &&
				((modem_ipv4_pdn_index >= 0) && ipv4_to_iface[modem_ipv4_pdn_index].wan_up_vlan == false) &&
				(modem_ipv6_pdn_index == -1 || ((modem_ipv6_pdn_index >= 0) && ipv6_to_iface[modem_ipv6_pdn_index].wan_up_vlan_v6 == false)))
			{
				if(num_offloaded_pdns >= IPA_MAX_NUM_HW_PDNS)
				{
					IPACMERR("number of offloaded PDNs %d can't add more than %d, ignoring\n",
							 num_offloaded_pdns, IPA_MAX_NUM_HW_PDNS);
					goto fail;
				}
				num_offloaded_pdns++;
				IPACMDBG_H("this is a new PDN, num of offloaded PDN increased to %d\n", num_offloaded_pdns);
			}
		}
		handle_route_add_vlan_pdn_evt(IPA_IP_v4, data->VlanID);
		ret = IPACM_SUCCESS;
	}
fail:
	if(vlan_info != NULL)
	        free(vlan_info);
        return ret;
}

/**
 * This is a wrapper function to handle IPA_ROUTE_ADD_VLAN_PDN_EVENT 
 */
int IPACM_Wan::check_vlan_pdn(ipa_ip_type iptype, ipacm_event_route_vlan *data, bool v4_only_xlat)
{
	int ret = IPACM_FAILURE;
	std::list<uint16_t>::iterator it;

	IPACMDBG_H("iptype: %d\n", iptype);
	IPACMDBG_H("num_offloaded_pdns: %d\n", num_offloaded_pdns);

	if(data == NULL)
	{
		IPACMDBG_H("Received invalid data\n");
		return IPACM_FAILURE;
	}

	if (m_is_sta_mode !=Q6_WAN)
	{
		IPACMDBG_H("STA backhaul\n");
		if((iptype==IPA_IP_v4) && (header_set_v4 != true))
		{
			header_partial_default_wan_v4 = true;
			IPACMDBG_H("STA ipv4-header haven't constructed \n");
			return IPACM_SUCCESS;
		}
		else if((iptype==IPA_IP_v6 || iptype == IPA_IP_MAX) && (header_set_v6 != true))
		{
			header_partial_default_wan_v6 = true;
			IPACMDBG_H("STA ipv6-header haven't constructed \n");
			if((data->wan_ipv6_prefix[0] == ipv6_prefix[0]) &&
				(data->wan_ipv6_prefix[1] == ipv6_prefix[1]))
			{
				/* Adding pending vid to pending-STA-VID list */
				for(it = pending_VID_STA.begin(); it != pending_VID_STA.end(); ++it)
				{
					if (data->VlanID == *it)
					{
						IPACMDBG_H("Already added vlan_id: %d as pending_VID_STA \n", data->VlanID);
					 	return IPACM_SUCCESS;
					}
				}
				pending_VID_STA.push_back(data->VlanID);
				IPACMDBG_H("Added vlan_id: %d as pending_VID_STA\n", data->VlanID);
			}
			return IPACM_SUCCESS;
		}
	}

	IPACMDBG_H("Process IPA_ROUTE_ADD_VLAN_PDN_EVENT for iptype: %d\n", iptype);
	IPACMDBG_H("data->wan_ipv6_prefix: 0x%08x%08x\n", data->wan_ipv6_prefix[0], data->wan_ipv6_prefix[1]);
	IPACMDBG_H("ipv6_prefix: 0x%08x%08x\n", ipv6_prefix[0], ipv6_prefix[1]);

	if(iptype == IPA_IP_v6 || iptype == IPA_IP_MAX)
	{
		ret = handle_vlan_backhaul_switch_v6(data, v4_only_xlat);
	}
	if(iptype == IPA_IP_v4 || iptype == IPA_IP_MAX)
	{
		ret = handle_vlan_backhaul_switch_v4(data);
	}
	return ret;
}

int IPACM_Wan::handle_route_add_vlan_pdn_evt(ipa_ip_type iptype, uint16_t vlan_id)
{
	struct ipa_ioc_add_rt_rule *rt_rule = NULL;
	struct ipa_rt_rule_add *rt_rule_entry;
	struct ipa_ioc_get_hdr hdr;
	const int NUM = 1;
	ipacm_cmd_q_data evt_data;
	bool FullConfig = false;
	ipacm_event_vlan_pdn *pdn_update = NULL;
	int ret = IPACM_FAILURE;

	/* copy header from tx-property, see if partial or not */
	/* assume all tx-property uses the same header name for v4 or v6*/
	if(tx_prop == NULL)
	{
		IPACMDBG_H("No tx properties, ignore new vlan PDN event\n");
		return IPACM_FAILURE;
	}

	rt_rule = (struct ipa_ioc_add_rt_rule *)
			calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
			NUM * sizeof(struct ipa_rt_rule_add));
	if(!rt_rule)
	{
		IPACMERR("Error locating ipa_ioc_add_rt_rule_memory...\n");
		return IPACM_FAILURE;
	}

	rt_rule->commit = 1;
	rt_rule->num_rules = (uint8_t)NUM;
	rt_rule->ip = iptype;

	rt_rule_entry = &rt_rule->rules[0];
	rt_rule_entry->at_rear = true;

	if(iptype == IPA_IP_v6)
	{
		if(wan_up_v6 || isVlanWanUP_V6())
		{
			IPACMDBG_H("a v6 PDN is already up, don't create default rt rule\n");
		}
		else
		{
			FullConfig = true;
		}
		if(m_is_sta_mode == WLAN_WAN || m_is_sta_mode == ECM_WAN)
		{
			IPACMDBG_H(" WAN instance is in STA mode \n");

			/* Do not install route rules if this WLAN PDN is already up */
			if (ipv6_to_iface[sta_ipv6_pdn_index].wan_up_vlan_v6 == true)
			{
				IPACMDBG_H("WLAN V6 WAN [%d] is already up with prefix: 0x%08x%08x\n",
						sta_ipv6_pdn_index,
						ipv6_to_iface[sta_ipv6_pdn_index].ipv6_prefix[0],
						ipv6_to_iface[sta_ipv6_pdn_index].ipv6_prefix[1]);
				goto PostWanUpV6;
			}

			if((iptype==IPA_IP_v6) && (header_set_v6 != true))
			{
				header_partial_default_wan_v6 = true;
				IPACMDBG_H("STA ipv6-header haven't constructed \n");
				ret = IPACM_SUCCESS;
				goto fail;
			}
			/* Need to take different routing table when two STA ifaces same time */
			strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_v6.name, sizeof(rt_rule->rt_tbl_name));
			IPACMDBG_H(" WAN table created %s \n", rt_rule->rt_tbl_name);
			if (IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable ){
				rt_rule_entry->rule.hdr_proc_ctx_hdl = v6_p_ctx_2use;
			} else {
				/* use the STA-header handler */
				rt_rule_entry->rule.hdr_hdl = hdr_hdl_sta_v6;
			}

			for (int tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
				if(iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip,iptype);
					continue;
				}
				if(IPACM_Iface::ipacmcfg->isMCC_Mode == true)
				{
					IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
					tx_prop->tx[tx_index].alt_dst_pipe);
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
				}
				else
				{
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
				}
				if(!wan_route_rule_v6_hdl[tx_index])
				{
					memcpy(&rt_rule_entry->rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry->rule.attrib));
					if (IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable ){
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
						rt_rule_entry->rule.attrib.u.v6.src_addr[0] = ipv6_prefix[0];
						rt_rule_entry->rule.attrib.u.v6.src_addr[1] = ipv6_prefix[1];
						rt_rule_entry->rule.attrib.u.v6.src_addr[2] = 0x00000000;
						rt_rule_entry->rule.attrib.u.v6.src_addr[3] = 0x00000000;
						rt_rule_entry->rule.attrib.u.v6.src_addr_mask[0] = 0xFFFFFFFF;
						rt_rule_entry->rule.attrib.u.v6.src_addr_mask[1] = 0xFFFFFFFF;
						rt_rule_entry->rule.attrib.u.v6.src_addr_mask[2] = 0x00000000;
						rt_rule_entry->rule.attrib.u.v6.src_addr_mask[3] = 0x00000000;
					} else {
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
						rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = 0;
						rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = 0;
						rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = 0;
						rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = 0;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0;
					}
#ifdef FEATURE_IPA_V3
					rt_rule_entry->rule.hashable = true;
#endif
					if (false == m_routing.AddRoutingRule(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						ret = IPACM_FAILURE;
						goto fail;
					}
					wan_route_rule_v6_hdl[tx_index] = rt_rule_entry->rt_rule_hdl;
					IPACMDBG_H("Set ipv6 wan-route rule hdl for v6_lan_table:0x%x,tx:%d,ip-type: %d \n",
						wan_route_rule_v6_hdl[tx_index],
						tx_index,
						iptype);
				}
			}
PostWanUpV6:
			post_wan_vlan_pdn_event(IPA_IP_v6, sta_ipv6_pdn_index, ipv6_to_iface[sta_ipv6_pdn_index].VID_cnt, vlan_id, true);
			/* for STA mode: add firewall rules */
			del_dft_firewall_rules(IPA_IP_v6, true);
			config_dft_firewall_rules(IPA_IP_v6);
			FullConfig = false;
		}
		else
		{
			if(!wan_route_rule_wan_v6_hdl_a5)
			{
				IPACMDBG_H("v6 PDN is up, create default rt rule\n");
				FullConfig = true;

				/* add a catch-all rule in wan dl routing table */
				/* Need to take different routing table when two STA ifaces same time */
				strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule->rt_tbl_name));
				IPACMDBG_H(" WAN table created %s \n", rt_rule->rt_tbl_name);
				memset(rt_rule_entry, 0, sizeof(struct ipa_rt_rule_add));
				rt_rule_entry->at_rear = true;

				memset(&hdr, 0, sizeof(hdr));
				strlcpy(hdr.name, tx_prop->tx[0].hdr_name, sizeof(hdr.name));
				hdr.name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
				if(m_header.GetHeaderHandle(&hdr) == false)
				{
					IPACMERR("Failed to get QMAP header.\n");
					ret = IPACM_FAILURE;
					goto fail;
				}
				rt_rule_entry->rule.hdr_hdl = hdr.hdl;
				rt_rule_entry->rule.dst = IPA_CLIENT_APPS_WAN_CONS;

				rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR;
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
				if(false == m_routing.AddRoutingRule(rt_rule))
				{
					IPACMERR("Routing rule addition failed!\n");
					ret = IPACM_FAILURE;
					goto fail;
				}
				wan_route_rule_wan_v6_hdl_a5 = rt_rule_entry->rt_rule_hdl;
				IPACMDBG_H("Set ipv6 wan-route rule hdl for v6_wan_table:0x%x,tx:%d,ip-type: %d \n",
					wan_route_rule_wan_v6_hdl_a5, 0, iptype);
			}

			/* Xlat case pdn_index might not be populated*/
			if (modem_ipv6_pdn_index == -1) {
				modem_ipv6_pdn_index = getFreePDNIndex_V6();
				if (modem_ipv6_pdn_index == -1)
				{
					IPACMERR("No Free index available.!\n");
					ret = IPACM_FAILURE;
					goto fail;
				}

				ipv6_to_iface[modem_ipv6_pdn_index].pIface = this;
				IPACMDBG_H("index allocated %d \n", modem_ipv6_pdn_index);
			}
			post_wan_vlan_pdn_event(IPA_IP_v6, modem_ipv6_pdn_index, ipv6_to_iface[modem_ipv6_pdn_index].VID_cnt, vlan_id, true);
			/*config_wan_firewall_rule traverses all active wan IF and configures them*/
			config_wan_firewall_rule(IPA_IP_v6);
			install_wan_filtering_rule(false);
		}
	}
	else
	{
		if(m_is_sta_mode == WLAN_WAN || m_is_sta_mode == ECM_WAN)
		{
			IPACMDBG_H(" WAN instance is in STA mode header_set_v4 %d \n", header_set_v4);
			//Construct STA header 1st

			/* Do not install route rules if V4 WLAN PDN is already up */
			if (ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan == true)
			{
                                IPACMDBG_H("WLAN V4 WAN [%d] is already up with address: 0x%X\n",
						sta_ipv4_pdn_index,
						ipv4_to_iface[sta_ipv4_pdn_index].ipv4_addr);
				goto PostWanUp;
			}

			if((iptype==IPA_IP_v4) && (header_set_v4 != true))
			{
				header_partial_default_wan_v4 = true;
				IPACMDBG_H("STA ipv4-header haven't constructed \n");
				ret = IPACM_SUCCESS;
				goto fail;
			}

			for (int tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
				if(iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
						tx_index, tx_prop->tx[tx_index].ip,iptype);
					continue;
				}
				/* use the STA-header handler */
				strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v4.name, sizeof(rt_rule->rt_tbl_name));
				rt_rule_entry->rule.hdr_hdl = hdr_hdl_sta_v4;

				if(IPACM_Iface::ipacmcfg->isMCC_Mode == true)
				{
					IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
					tx_prop->tx[tx_index].alt_dst_pipe);
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
				}
				else
				{
					rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
				}
				if(!wan_route_rule_v4_hdl[tx_index])
				{
					memcpy(&rt_rule_entry->rule.attrib,
						&tx_prop->tx[tx_index].attrib,
						sizeof(rt_rule_entry->rule.attrib));

					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.u.v4.dst_addr      = 0;
					rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0;
#ifdef FEATURE_IPA_V3
					rt_rule_entry->rule.hashable = true;
#endif
					if (false == m_routing.AddRoutingRule(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						ret = IPACM_FAILURE;
						goto fail;
					}
					wan_route_rule_v4_hdl[tx_index] = rt_rule_entry->rt_rule_hdl;
					IPACMDBG_H("Got ipv4 wan-route rule hdl:0x%x,tx:%d,ip-type: %d \n",
						wan_route_rule_v4_hdl[tx_index],
						tx_index,
						iptype);
				}
			}
PostWanUp:
			post_wan_vlan_pdn_event(IPA_IP_v4, sta_ipv4_pdn_index, ipv4_to_iface[sta_ipv4_pdn_index].VID_cnt, vlan_id, true);
			/* for STA mode: add firewall rules */
			del_dft_firewall_rules(IPA_IP_v4, true);
			config_dft_firewall_rules(IPA_IP_v4);
			FullConfig = false;
		}
		else
		{
			if(!(wan_up || isVlanWanUP()))
			{
				IPACMDBG_H("a v4 PDN is already up, minimal configuration is needed\n");
				FullConfig = true;
			}
			post_wan_vlan_pdn_event(IPA_IP_v4, modem_ipv4_pdn_index, ipv4_to_iface[modem_ipv4_pdn_index].VID_cnt, vlan_id, true);
			config_wan_firewall_rule(IPA_IP_v4);
			install_wan_filtering_rule(false);

			/* This is to handle out-of-order events from Netlink like route events
                   	and IPA CLI command received from QCMAP to configure IPPT since
                   	we have received RTM_DELROUTE from kernel before to Passthrough
                   	configuration sent from QCMAP and we were not posting below event to
                   	Conntrack as active_v4 was false. */

			if (ip_pass_pdn_info.enable)
			{
				pdn_update = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
				if(pdn_update == NULL)
				{
					IPACMERR("Unable to allocate memory\n");
					return IPACM_FAILURE;
				}
				memset(pdn_update, 0, sizeof(ipacm_event_vlan_pdn));
				pdn_update->ipv4_addr = wan_v4_addr;
				pdn_update->ip_pass_enable = ip_pass_pdn_info.enable;
				pdn_update->ip_pass_dummy_ip = (ip_pass_pdn_info.enable) ?
					ip_pass_pdn_info.pdn_ip_addr : 0;
				pdn_update->ip_pass_skip_nat = (ip_pass_pdn_info.enable) ? ip_pass_pdn_info.skip_nat : 0;
				IPACMDBG_H("Posting IPA_HANDLE_IP_PASS_PDN_INFO_UPDATE_EVENT\n");
				IPACMDBG_H("IP Passthrough enabled:%d WAN IP: 0x%x, Dummy IP 0x%x, Skip NAT: %d\n",
					pdn_update->ip_pass_enable,
					pdn_update->ipv4_addr,
					pdn_update->ip_pass_dummy_ip,
					pdn_update->ip_pass_skip_nat);
				evt_data.event = IPA_HANDLE_IP_PASS_PDN_INFO_UPDATE_EVENT;
				evt_data.evt_data = (void *)pdn_update;
				IPACM_EvtDispatcher::PostEvt(&evt_data);
			}
		}
	}

	associated_VID = vlan_id;

	if(FullConfig)
	{
		/* Add corresponding ipa_rm_resource_name of TX-endpoint up before IPV6 RT-rule set */
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			IPACMDBG_H("dev %s add producer dependency\n", dev_name);
			IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			IPACM_Iface::ipacmcfg->AddRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe], false);
		}
		else
		{
			if(m_is_sta_mode == Q6_WAN && ipa_pm_q6_check == 0)
			{
				struct wan_ioctl_notify_wan_state wan_state;

				memset(&wan_state, 0, sizeof(wan_state));

				int fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
				if(fd_wwan_ioctl < 0)
				{
					IPACMERR("Failed to open %s.\n", WWAN_QMI_IOCTL_DEVICE_NAME);
					ret = IPACM_FAILURE;
					goto fail;
				}
				IPACMDBG_H("send WAN_IOC_NOTIFY_WAN_STATE up to IPA_PM\n");
				wan_state.up = true;
				if(ioctl(fd_wwan_ioctl, WAN_IOC_NOTIFY_WAN_STATE, &wan_state))
				{
					IPACMERR("Failed to send WAN_IOC_NOTIFY_WAN_STATE as up %d\n ", wan_state.up);
				}
				close(fd_wwan_ioctl);
			}
			ipa_pm_q6_check++;
			IPACMDBG_H("update ipa_pm_q6_check to %d\n", ipa_pm_q6_check);
		}
	}
	else
	{
		IPACMDBG_H("don't AddRmDepend, a PDN is already up\n");
	}

fail:
	if(rt_rule)
		free(rt_rule);
	return ret;
}

IPACM_firewall_conf_t* IPACM_Wan::get_curr_pdn_firewall_config(IPACM_firewall_t &firewall_configs, const char* curr_dev_name)
{
	if (!firewall_configs.pdn_count)
	{
		return NULL;
	}

	if (!firewall_configs.default_profile)
	{
		if (firewall_configs.pdn_count != 1)
		{
			IPACMERR("The XML %s is not valid. Please add %s tag\n", MOBILE_FIREWALL_FILE, DefaultProfile_TAG);
			return NULL;
		}
		return &firewall_configs.pdns[0];
	}

	size_t len = strlen(curr_dev_name);

	IPACMDBG_H("looking for dev %s\n", curr_dev_name);
	for (uint8_t i = 0; i < firewall_configs.pdn_count; ++i)
	{
		if (strncmp(firewall_configs.pdns[i].net_dev, curr_dev_name, len) == 0)
		{
			IPACMDBG_H("found dev %s, entry %d\n", curr_dev_name, i);
			return &firewall_configs.pdns[i];
		}
		else
		{
			IPACMDBG("dev %s doesn't match\n", firewall_configs.pdns[i].net_dev);
		}
	}

	if(firewall_configs.pdn_count == 1)
	{
		if(!strncmp(firewall_configs.pdns[0].net_dev, "UNKNOWN", strlen("UNKNOWN")))
		{
			IPACMDBG_H("only one profile in file and no name, return it");
			return &firewall_configs.pdns[0];
		}
		IPACMERR("one pdn with a differnet name (%s) != (%s), return it\n",
			firewall_configs.pdns[0].net_dev,
			curr_dev_name);
		return &firewall_configs.pdns[0];
	}

	return NULL;
}
#endif

/* wan default route/filter rule configuration */
int IPACM_Wan::handle_route_add_evt(ipa_ip_type iptype)
{
	/* add default WAN route */
	struct ipa_ioc_add_rt_rule *rt_rule = NULL;
	struct ipa_rt_rule_add *rt_rule_entry;
	struct ipa_ioc_get_hdr sRetHeader;
	uint32_t cnt, tx_index = 0;
	const int NUM = 1;
	ipacm_cmd_q_data evt_data;
	struct ipa_ioc_copy_hdr sCopyHeader; /* checking if partial header*/
	struct ipa_ioc_get_hdr hdr;
	ipacm_event_vlan_pdn *pdn_update = NULL;
#ifdef FEATURE_VLAN_MPDN
	bool FullConfig = true;
#endif
	struct wan_ioctl_notify_wan_state wan_state;
	int fd_wwan_ioctl;
	memset(&wan_state, 0, sizeof(wan_state));
	IPACMDBG_H("ip-type:%d\n", iptype);

	/* copy header from tx-property, see if partial or not */
	/* assume all tx-property uses the same header name for v4 or v6*/

	if(tx_prop == NULL)
	{
		IPACMDBG_H("No tx properties, ignore default route setting\n");
		return IPACM_SUCCESS;
	}

	is_default_gateway = true;
	IPACMDBG_H("Default route is added to iface %s.\n", dev_name);

	if(IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_mode == BRIDGE)
	{
		IPACM_Wan::backhaul_is_wan_bridge = true;
	}
	else
	{
		IPACM_Wan::backhaul_is_wan_bridge = false;
	}
	IPACMDBG_H("backhaul_is_wan_bridge ?: %d \n", IPACM_Wan::backhaul_is_wan_bridge);

	/* query MTU size of the interface if MTU is not set via ioctl. */
	if (!mtu_v4_set && !mtu_v6_set)
	{
		if(query_mtu_size())
		{
			IPACMERR("Failed to query mtu");
		}
	}

	if (m_is_sta_mode != Q6_WAN)
	{
		IPACM_Wan::backhaul_is_sta_mode	= true;
		if((iptype==IPA_IP_v4) && (header_set_v4 != true))
		{
			header_partial_default_wan_v4 = true;
			IPACMDBG_H("STA ipv4-header haven't constructed \n");
			return IPACM_SUCCESS;
		}
		else if((iptype==IPA_IP_v6) && (header_set_v6 != true))
		{
			header_partial_default_wan_v6 = true;
			IPACMDBG_H("STA ipv6-header haven't constructed \n");
			return IPACM_SUCCESS;
		}
	}
	else
	{
		IPACM_Wan::backhaul_is_sta_mode	= false;
		IPACMDBG_H("reset backhaul to LTE \n");

		if (iface_query != NULL && iface_query->num_ext_props > 0)
		{
			if(ext_prop == NULL)
			{
				IPACMERR("Extended property is empty.\n");
				return IPACM_FAILURE;
			}
			else
			{
				IPACM_Iface::ipacmcfg->SetQmapId(ext_prop->ext[0].mux_id);
				IPACMDBG_H("Setting up QMAP ID %d.\n", ext_prop->ext[0].mux_id);
			}
		}
		else
		{
			IPACMERR("iface_query is empty.\n");
			return IPACM_FAILURE;
		}
	}
#if 0
    for (cnt=0; cnt<tx_prop->num_tx_props; cnt++)
	{
		if(tx_prop->tx[cnt].ip==iptype)
		break;
	}

	if(tx_prop->tx[cnt].hdr_name != NULL)
	{
	    memset(&sCopyHeader, 0, sizeof(sCopyHeader));
	    memcpy(sCopyHeader.name,
	    			 tx_prop->tx[cnt].hdr_name,
	    			 sizeof(sCopyHeader.name));

	    IPACMDBG_H("header name: %s\n", sCopyHeader.name);
	    if (m_header.CopyHeader(&sCopyHeader) == false)
	    {
	    	IPACMERR("ioctl copy header failed");
	    	return IPACM_FAILURE;
	    }
	    IPACMDBG_H("header length: %d, paritial: %d\n", sCopyHeader.hdr_len, sCopyHeader.is_partial);
	    if(sCopyHeader.is_partial)
	    {
		IPACMDBG_H("Not setup default WAN routing rules cuz the header is not complete\n");
            if(iptype==IPA_IP_v4)
			{
				header_partial_default_wan_v4 = true;
            }
			else
			{
				header_partial_default_wan_v6 = true;
			}
			return IPACM_SUCCESS;
	    }
	    else
	    {
            if(iptype==IPA_IP_v4)
			{
				header_partial_default_wan_v4 = false;
            }
			else
			{
				header_partial_default_wan_v6 = false;
			}
	    }
    }
#endif

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


	IPACMDBG_H(" WAN table created %s \n", rt_rule->rt_tbl_name);
	rt_rule_entry = &rt_rule->rules[0];
	rt_rule_entry->at_rear = true;

	if(m_is_sta_mode != Q6_WAN)
	{
		IPACMDBG_H(" WAN instance is in STA mode \n");
		for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		{
			if(iptype != tx_prop->tx[tx_index].ip)
			{
				IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d no RT-rule added\n",
									tx_index, tx_prop->tx[tx_index].ip,iptype);
				continue;
			}

			/* use the STA-header handler */
			if (iptype == IPA_IP_v4)
			{
				strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v4.name, sizeof(rt_rule->rt_tbl_name));
				rt_rule_entry->rule.hdr_hdl = hdr_hdl_sta_v4;
			}
			else
			{
				strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_v6.name, sizeof(rt_rule->rt_tbl_name));
				rt_rule_entry->rule.hdr_hdl = hdr_hdl_sta_v6;
			}

			if(IPACM_Iface::ipacmcfg->isMCC_Mode == true)
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
			if (iptype == IPA_IP_v4)
			{
				if(!wan_route_rule_v4_hdl[tx_index])
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
					wan_route_rule_v4_hdl[tx_index] = rt_rule_entry->rt_rule_hdl;
					IPACMDBG_H("Got ipv4 wan-route rule hdl:0x%x,tx:%d,ip-type: %d \n",
								 wan_route_rule_v4_hdl[tx_index],
								 tx_index,
								 iptype);
				}
			}
			else
			{
				if(!wan_route_rule_v6_hdl[tx_index])
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
					wan_route_rule_v6_hdl[tx_index] = rt_rule_entry->rt_rule_hdl;
					IPACMDBG_H("Set ipv6 wan-route rule hdl for v6_lan_table:0x%x,tx:%d,ip-type: %d \n",
								 wan_route_rule_v6_hdl[tx_index],
								 tx_index,
								 iptype);
				}
			}
		}
	}

	/* add a catch-all rule in wan dl routing table */

	if (iptype == IPA_IP_v6)
	{
		IPACMDBG_H("WAN rt rule iptype %d.m_is_sta_mode %d \n", iptype, m_is_sta_mode);
		strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, sizeof(rt_rule->rt_tbl_name));
		memset(rt_rule_entry, 0, sizeof(struct ipa_rt_rule_add));
		rt_rule_entry->at_rear = true;
		if(m_is_sta_mode == Q6_WAN)
		{
			memset(&hdr, 0, sizeof(hdr));
			strlcpy(hdr.name, tx_prop->tx[0].hdr_name, sizeof(hdr.name));
			hdr.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
			if(m_header.GetHeaderHandle(&hdr) == false)
			{
				IPACMERR("Failed to get QMAP header.\n");
				return IPACM_FAILURE;
			}
			rt_rule_entry->rule.hdr_hdl = hdr.hdl;
			rt_rule_entry->rule.dst = IPA_CLIENT_APPS_WAN_CONS;
		}
		else
		{
			/* create dummy ethernet header for v6 RX path */
			IPACMDBG_H("Construct dummy ethernet_header\n");
			if (add_dummy_rx_hdr())
			{
				IPACMERR("Construct dummy ethernet_header failed!\n");
				free(rt_rule);
				return IPACM_FAILURE;
			}
			rt_rule_entry->rule.hdr_proc_ctx_hdl = hdr_proc_hdl_dummy_v6;
			rt_rule_entry->rule.dst = IPA_CLIENT_APPS_LAN_CONS;
		}
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR;
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

		if(m_is_sta_mode == Q6_WAN)
		{
			if(!wan_route_rule_wan_v6_hdl_a5)
			{
				if(false == m_routing.AddRoutingRule(rt_rule))
				{
					IPACMERR("Routing rule addition failed!\n");
					free(rt_rule);
					return IPACM_FAILURE;
				}
				wan_route_rule_wan_v6_hdl_a5 = rt_rule_entry->rt_rule_hdl;
				IPACMDBG_H("Set ipv6 wan-route rule hdl for v6_wan_table:0x%x,tx:%d,ip-type: %d \n",
					wan_route_rule_wan_v6_hdl_a5, 0, iptype);
			}
		}
		else
		{
			if(!wan_route_rule_lan_v6_hdl_a5)
			{
				if(false == m_routing.AddRoutingRule(rt_rule))
				{
					IPACMERR("Routing rule addition failed!\n");
					free(rt_rule);
					return IPACM_FAILURE;
				}
				wan_route_rule_lan_v6_hdl_a5 = rt_rule_entry->rt_rule_hdl;
				IPACMDBG_H("Set ipv6 wan-route rule hdl for v6_wan_table:0x%x,tx:%d,ip-type: %d \n",
					wan_route_rule_lan_v6_hdl_a5, 0, iptype);
			}
		}
	}

	ipacm_event_iface_up *wanup_data;
	wanup_data = (ipacm_event_iface_up *)malloc(sizeof(ipacm_event_iface_up));
	if (wanup_data == NULL)
	{
		IPACMERR("Unable to allocate memory\n");
		free(rt_rule);
		return IPACM_FAILURE;
	}
	memset(wanup_data, 0, sizeof(ipacm_event_iface_up));

	if (iptype == IPA_IP_v4)
	{
		/* set mtu_default_wan to current default wan instance */
		mtu_default_wan_v4 = mtu_v4;
		IPACMDBG_H("replace the mtu_wan to %d\n", mtu_default_wan_v4);

		IPACM_Wan::wan_up = true;
		active_v4 = true;
		IPACMDBG_H("set isWANUP %d\n", IPACM_Wan::wan_up);
		memcpy(IPACM_Wan::wan_up_dev_name,
			dev_name,
				sizeof(IPACM_Wan::wan_up_dev_name));

		if(m_is_sta_mode == Q6_WAN)
		{
			config_wan_firewall_rule(IPA_IP_v4);

#ifdef FEATURE_IPA_IPSEC
			memset(&wan_state, 0, sizeof(wan_state));
			fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
			if(fd_wwan_ioctl < 0)
			{
				IPACMERR("FailFailed to open %s.\n", WWAN_QMI_IOCTL_DEVICE_NAME);
				free(wanup_data);
				free(rt_rule);
				return IPACM_FAILURE;
			}
			IPACMDBG_H("send WAN_IOC_NOTIFY_WAN_STATE up to IPA_PM\n");
			wan_state.up = true;
			memcpy(wan_state.upstreamIface, dev_name, sizeof(wan_state.upstreamIface));
			if(ioctl(fd_wwan_ioctl, WAN_IOC_NOTIFY_WAN_STATE, &wan_state))
			{
				IPACMERR("Failed to send WAN_IOC_NOTIFY_WAN_STATE as up %d\n ", wan_state.up);
			}
			close(fd_wwan_ioctl);
#endif
			install_wan_filtering_rule(false);
#ifdef FEATURE_PMIPV6
			if(IPACM_Iface::ipacmcfg->pmip_details.pmipv6_enabled)
			{
				gre_up();
			}
#endif
#ifdef FEATURE_VLAN_MPDN
			if(isVlanWanUP())
				FullConfig = false;
#endif
		}
		else
		{
			/* STA Backhaul */
			del_dft_firewall_rules(IPA_IP_v4);
			config_dft_firewall_rules(IPA_IP_v4);
		}

		memcpy(wanup_data->ifname, dev_name, sizeof(wanup_data->ifname));
		wanup_data->ipv4_addr = (public_wan_v4_addr_set) ? public_wan_v4_addr : wan_v4_addr;
		if (m_is_sta_mode!=Q6_WAN)
		{
			wanup_data->is_sta = true;
		}
		else
		{
			wanup_data->is_sta = false;
		}
		IPACMDBG_H("Posting IPA_HANDLE_WAN_UP with below information:\n");
		IPACMDBG_H("if_name:%s, ipv4_address:0x%x, is sta mode:%d\n",
				wanup_data->ifname, wanup_data->ipv4_addr, wanup_data->is_sta);
		memset(&evt_data, 0, sizeof(evt_data));

		/* send xlat configuration for installing uplink rules */
		if(is_xlat && (m_is_sta_mode == Q6_WAN))
		{
			if(ext_prop != NULL)
				IPACM_Wan::xlat_mux_id = ext_prop->ext[0].mux_id;
			wanup_data->xlat_mux_id = IPACM_Wan::xlat_mux_id;
			IPACMDBG_H("Set xlat configuraiton with below information:\n");
			IPACMDBG_H("xlat_enabled: %d, xlat_mux_id: %d\n",
					is_xlat, xlat_mux_id);
		}
		else
		{
			IPACM_Wan::xlat_mux_id = 0;
			wanup_data->xlat_mux_id = 0;
			if(m_is_sta_mode == Q6_WAN && ext_prop != NULL)
				wanup_data->mux_id = ext_prop->ext[0].mux_id;
			else
				wanup_data->mux_id = 0;
			IPACMDBG_H("No xlat configuration\n");
		}
		evt_data.event = IPA_HANDLE_WAN_UP;
		evt_data.evt_data = (void *)wanup_data;
		IPACM_EvtDispatcher::PostEvt(&evt_data);

		/* This is to handle out-of-order events from Netlink like route events
                   and IPA CLI command received from QCMAP to configure IPPT since
                   we have received RTM_DELROUTE from kernel before to Passthrough
                   configuration sent from QCMAP and we were not posting below event to
                   Conntrack as active_v4 was false. */

		if (ip_pass_pdn_info.enable)
		{
			pdn_update = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
			if(pdn_update == NULL)
			{
				IPACMERR("Unable to allocate memory\n");
				return IPACM_FAILURE;
			}
			memset(pdn_update, 0, sizeof(ipacm_event_vlan_pdn));
			pdn_update->ipv4_addr = wan_v4_addr;
			pdn_update->ip_pass_enable = ip_pass_pdn_info.enable;
			pdn_update->ip_pass_dummy_ip = (ip_pass_pdn_info.enable) ?
				ip_pass_pdn_info.pdn_ip_addr : 0;
			pdn_update->ip_pass_skip_nat = (ip_pass_pdn_info.enable) ? ip_pass_pdn_info.skip_nat : 0;
			IPACMDBG_H("Posting IPA_HANDLE_IP_PASS_PDN_INFO_UPDATE_EVENT\n");
			IPACMDBG_H("IP Passthrough enabled:%d WAN IP: 0x%x, Dummy IP 0x%x, Skip NAT: %d\n",
				pdn_update->ip_pass_enable,
				pdn_update->ipv4_addr,
				pdn_update->ip_pass_dummy_ip,
				pdn_update->ip_pass_skip_nat);
			evt_data.event = IPA_HANDLE_IP_PASS_PDN_INFO_UPDATE_EVENT;
			evt_data.evt_data = (void *)pdn_update;
			IPACM_EvtDispatcher::PostEvt(&evt_data);
		}
	}
	else
	{
		/* set mtu_default_wan to current default wan instance */
		mtu_default_wan_v6 = mtu_v6;
		IPACMDBG_H("replace the mtu_wan to %d\n", mtu_default_wan_v6);

		memcpy(backhaul_ipv6_prefix, ipv6_prefix, sizeof(backhaul_ipv6_prefix));
		IPACMDBG_H("Setup backhaul ipv6 prefix to be 0x%08x%08x.\n", backhaul_ipv6_prefix[0], backhaul_ipv6_prefix[1]);

		IPACM_Wan::wan_up_v6 = true;
		active_v6 = true;
		memcpy(IPACM_Wan::wan_up_dev_name,
			dev_name,
				sizeof(IPACM_Wan::wan_up_dev_name));

		if(m_is_sta_mode == Q6_WAN)
		{
			config_wan_firewall_rule(IPA_IP_v6);

#ifdef FEATURE_IPA_IPSEC
			memset(&wan_state, 0, sizeof(wan_state));
			fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
			if(fd_wwan_ioctl < 0)
			{
				IPACMERR("FailFailed to open %s.\n", WWAN_QMI_IOCTL_DEVICE_NAME);
				free(wanup_data);
				free(rt_rule);
				return IPACM_FAILURE;
			}
			IPACMDBG_H("send WAN_IOC_NOTIFY_WAN_STATE up to IPA_PM\n");
			wan_state.up = true;
			memcpy(wan_state.upstreamIface, dev_name, sizeof(wan_state.upstreamIface));
			if(ioctl(fd_wwan_ioctl, WAN_IOC_NOTIFY_WAN_STATE, &wan_state))
			{
				IPACMERR("Failed to send WAN_IOC_NOTIFY_WAN_STATE as up %d\n ", wan_state.up);
			}
			close(fd_wwan_ioctl);
#endif
			install_wan_filtering_rule(false);
#ifdef FEATURE_PMIPV6
			if(IPACM_Iface::ipacmcfg->pmip_details.pmipv6_enabled)
			{
				gre_up();
			}
#endif
		}
		else
		{
			del_dft_firewall_rules(IPA_IP_v6);
			config_dft_firewall_rules(IPA_IP_v6);
		}

		memcpy(wanup_data->ifname, dev_name, sizeof(wanup_data->ifname));
		if (m_is_sta_mode!=Q6_WAN)
		{
			wanup_data->is_sta = true;
		}
		else
		{
			wanup_data->is_sta = false;
		}
		memcpy(wanup_data->ipv6_prefix, ipv6_prefix, sizeof(wanup_data->ipv6_prefix));
		memcpy(wanup_data->ipv6_addr, m_ipv6_addr, sizeof(wanup_data->ipv6_addr));
#ifdef FEATURE_VLAN_MPDN
		IPACM_Iface::ipacmcfg->add_vlan_ipv6_prefix(wanup_data->ipv6_prefix, ipa_if_num, associated_VID);
#endif
		IPACMDBG_H("Posting IPA_HANDLE_WAN_UP_V6 with below information:\n");
		IPACMDBG_H("if_name:%s, is sta mode: %d\n", wanup_data->ifname, wanup_data->is_sta);
		IPACMDBG_H("ipv6 prefix: 0x%08x%08x.\n", ipv6_prefix[0], ipv6_prefix[1]);
		IPACMDBG_H("ipv6 addr: 0x%08x%08x%08x%08x\n", m_ipv6_addr[0], m_ipv6_addr[1], m_ipv6_addr[2], m_ipv6_addr[3]);
		memset(&evt_data, 0, sizeof(evt_data));
		evt_data.event = IPA_HANDLE_WAN_UP_V6;
		evt_data.evt_data = (void *)wanup_data;
		IPACM_EvtDispatcher::PostEvt(&evt_data);
	}
#ifdef FEATURE_VLAN_MPDN
	if(FullConfig)
#endif
	{
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Add corresponding ipa_rm_resource_name of TX-endpoint up before IPV6 RT-rule set */
			IPACMDBG_H("dev %s add producer dependency\n", dev_name);
			IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			IPACM_Iface::ipacmcfg->AddRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe],false);
		} else {
			if (m_is_sta_mode == Q6_WAN && ipa_pm_q6_check == 0)
			{
				fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
				if(fd_wwan_ioctl < 0)
				{
					IPACMERR("Failed to open %s.\n",WWAN_QMI_IOCTL_DEVICE_NAME);
					return false;
				}
				IPACMDBG_H("send WAN_IOC_NOTIFY_WAN_STATE up to IPA_PM\n");
				wan_state.up = true;
				if(ioctl(fd_wwan_ioctl, WAN_IOC_NOTIFY_WAN_STATE, &wan_state))
				{
					IPACMERR("Failed to send WAN_IOC_NOTIFY_WAN_STATE as up %d\n ", wan_state.up);
				}
				close(fd_wwan_ioctl);
			}
			ipa_pm_q6_check++;
			IPACMDBG_H("update ipa_pm_q6_check to %d\n", ipa_pm_q6_check);

		}
	}
#ifdef FEATURE_VLAN_MPDN
	else
	{
		IPACMDBG_H("don't AddRmDepend, vlan PDN already up, iptype:%d\n", iptype);
	}
#endif
	if(rt_rule != NULL)
	{
		free(rt_rule);
	}
	return IPACM_SUCCESS;
}

#ifdef FEATURE_IPA_ANDROID
/* wan default route/filter rule configuration */
int IPACM_Wan::post_wan_up_tether_evt(ipa_ip_type iptype, int ipa_if_num_tether)
{
	ipacm_cmd_q_data evt_data;
	ipacm_event_iface_up_tehter *wanup_data;

	wanup_data = (ipacm_event_iface_up_tehter *)malloc(sizeof(ipacm_event_iface_up_tehter));
	if (wanup_data == NULL)
	{
		IPACMERR("Unable to allocate memory\n");
		return IPACM_FAILURE;
	}
	memset(wanup_data, 0, sizeof(ipacm_event_iface_up_tehter));

	wanup_data->if_index_tether = ipa_if_num_tether;
	if (m_is_sta_mode!=Q6_WAN)
	{
		wanup_data->is_sta = true;
	}
	else
	{
		wanup_data->is_sta = false;
	}
	IPACMDBG_H("Posting IPA_HANDLE_WAN_UP_TETHER with below information:\n");
	IPACMDBG_H("tether_if_name:%s, is sta mode:%d\n",
			IPACM_Iface::ipacmcfg->iface_table[ipa_if_num_tether].iface_name, wanup_data->is_sta);
	memset(&evt_data, 0, sizeof(evt_data));

	if (iptype == IPA_IP_v4)
	{
		evt_data.event = IPA_HANDLE_WAN_UP_TETHER;
		/* Add support tether ifaces to its array*/
		IPACM_Wan::ipa_if_num_tether_v4[IPACM_Wan::ipa_if_num_tether_v4_total] = ipa_if_num_tether;
		IPACMDBG_H("adding tether iface(%s) ipa_if_num_tether_v4_total(%d) on wan_iface(%s)\n",
			IPACM_Iface::ipacmcfg->iface_table[ipa_if_num_tether].iface_name,
			IPACM_Wan::ipa_if_num_tether_v4_total,
			IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name);
		IPACM_Wan::ipa_if_num_tether_v4_total++;
	}
	else
	{
		evt_data.event = IPA_HANDLE_WAN_UP_V6_TETHER;
		memcpy(wanup_data->ipv6_prefix, ipv6_prefix, sizeof(wanup_data->ipv6_prefix));
		/* Add support tether ifaces to its array*/
		IPACM_Wan::ipa_if_num_tether_v6[IPACM_Wan::ipa_if_num_tether_v6_total] = ipa_if_num_tether;
		IPACMDBG_H("adding tether iface(%s) ipa_if_num_tether_v6_total(%d) on wan_iface(%s)\n",
			IPACM_Iface::ipacmcfg->iface_table[ipa_if_num_tether].iface_name,
			IPACM_Wan::ipa_if_num_tether_v6_total,
			IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name);
		IPACM_Wan::ipa_if_num_tether_v6_total++;
	}
		evt_data.evt_data = (void *)wanup_data;
		IPACM_EvtDispatcher::PostEvt(&evt_data);

	return IPACM_SUCCESS;
}

/* wan default route/filter rule configuration */
int IPACM_Wan::post_wan_down_tether_evt(ipa_ip_type iptype, int ipa_if_num_tether)
{
	ipacm_cmd_q_data evt_data;
	ipacm_event_iface_up_tehter *wandown_data;
	int i, j;

	wandown_data = (ipacm_event_iface_up_tehter *)malloc(sizeof(ipacm_event_iface_up_tehter));
	if (wandown_data == NULL)
	{
		IPACMERR("Unable to allocate memory\n");
		return IPACM_FAILURE;
	}
	memset(wandown_data, 0, sizeof(ipacm_event_iface_up_tehter));

	wandown_data->if_index_tether = ipa_if_num_tether;
	if (m_is_sta_mode!=Q6_WAN)
	{
		wandown_data->is_sta = true;
	}
	else
	{
		wandown_data->is_sta = false;
	}
	IPACMDBG_H("Posting IPA_HANDLE_WAN_DOWN_TETHER with below information:\n");
	IPACMDBG_H("tether_if_name:%s, is sta mode:%d\n",
			IPACM_Iface::ipacmcfg->iface_table[ipa_if_num_tether].iface_name, wandown_data->is_sta);
	memset(&evt_data, 0, sizeof(evt_data));

	if (iptype == IPA_IP_v4)
	{
		evt_data.event = IPA_HANDLE_WAN_DOWN_TETHER;
		/* delete support tether ifaces to its array*/
		for (i=0; i < IPACM_Wan::ipa_if_num_tether_v4_total; i++)
		{
			if(IPACM_Wan::ipa_if_num_tether_v4[i] == ipa_if_num_tether)
			{
				IPACMDBG_H("Found tether client at position %d name(%s)\n", i,
				IPACM_Iface::ipacmcfg->iface_table[ipa_if_num_tether].iface_name);
				break;
			}
		}
		if(i == IPACM_Wan::ipa_if_num_tether_v4_total)
		{
			IPACMDBG_H("Not finding the tether client.\n");
			free(wandown_data);
			return IPACM_SUCCESS;
		}
		for(j = i+1; j < IPACM_Wan::ipa_if_num_tether_v4_total; j++)
		{
			IPACM_Wan::ipa_if_num_tether_v4[j-1] = IPACM_Wan::ipa_if_num_tether_v4[j];
		}
		IPACM_Wan::ipa_if_num_tether_v4_total--;
		IPACMDBG_H("Now the total num of ipa_if_num_tether_v4_total is %d on wan-iface(%s)\n",
			IPACM_Wan::ipa_if_num_tether_v4_total,
			IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name);
	}
	else
	{
		evt_data.event = IPA_HANDLE_WAN_DOWN_V6_TETHER;
		/* delete support tether ifaces to its array*/
		for (i=0; i < IPACM_Wan::ipa_if_num_tether_v6_total; i++)
		{
			if(IPACM_Wan::ipa_if_num_tether_v6[i] == ipa_if_num_tether)
			{
				IPACMDBG_H("Found tether client at position %d name(%s)\n", i,
				IPACM_Iface::ipacmcfg->iface_table[ipa_if_num_tether].iface_name);
				break;
			}
		}
		if(i == IPACM_Wan::ipa_if_num_tether_v6_total)
		{
			IPACMDBG_H("Not finding the tether client.\n");
			free(wandown_data);
			return IPACM_SUCCESS;
		}
		for(j = i+1; j < IPACM_Wan::ipa_if_num_tether_v6_total; j++)
		{
			IPACM_Wan::ipa_if_num_tether_v6[j-1] = IPACM_Wan::ipa_if_num_tether_v6[j];
		}
		IPACM_Wan::ipa_if_num_tether_v6_total--;
		IPACMDBG_H("Now the total num of ipa_if_num_tether_v6_total is %d on wan-iface(%s)\n",
			IPACM_Wan::ipa_if_num_tether_v6_total,
			IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name);
	}
		evt_data.evt_data = (void *)wandown_data;
		IPACM_EvtDispatcher::PostEvt(&evt_data);
	return IPACM_SUCCESS;
}
#endif

/* construct complete ethernet header */
int IPACM_Wan::handle_sta_header_add_evt()
{
	int res = IPACM_SUCCESS, index = IPACM_INVALID_INDEX;
	std::list<uint16_t>::iterator it;

	if (header_set_v4 == true && header_set_v6 == true)
	{
		IPACMDBG_H("Both V4 and V6 headers are added\n");
		return res;
	}

	if (header_set_v4 != true)
	{
		/* checking if the ipv4 same as default route */
		if(wan_v4_addr_gw_set)
		{
			index = get_wan_client_index_ipv4(wan_v4_addr_gw);
		}

		if (index != IPACM_INVALID_INDEX)
		{
			IPACMDBG_H("Matched client index: %d\n", index);
			IPACMDBG_H("Received Client MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
				get_client_memptr(wan_client, index)->mac[0],
				get_client_memptr(wan_client, index)->mac[1],
				get_client_memptr(wan_client, index)->mac[2],
				get_client_memptr(wan_client, index)->mac[3],
				get_client_memptr(wan_client, index)->mac[4],
				get_client_memptr(wan_client, index)->mac[5]);

			if(get_client_memptr(wan_client, index)->ipv4_header_set)
			{
				hdr_hdl_sta_v4 = get_client_memptr(wan_client, index)->hdr_hdl_v4;
				header_set_v4 = true;
				IPACMDBG_H("add full ipv4 header hdl: (%x)\n", get_client_memptr(wan_client, index)->hdr_hdl_v4);
				/* store external_ap's MAC */
				memcpy(ext_router_mac_addr, get_client_memptr(wan_client, index)->mac, sizeof(ext_router_mac_addr));
			}
			else
			{
				IPACMERR(" wan-client got ipv4 however didn't construct complete ipv4 header \n");
				return IPACM_FAILURE;
			}

			if(get_client_memptr(wan_client, index)->ipv6_header_set)
			{
				hdr_hdl_sta_v6 = get_client_memptr(wan_client, index)->hdr_hdl_v6;
				header_set_v6 = true;
				IPACMDBG_H("add full ipv6 header hdl: (%x)\n", get_client_memptr(wan_client, index)->hdr_hdl_v6);
			}
		}
		else if(m_is_sta_mode == Q6_WAN)
		{
			IPACMDBG_H("currently can't find matched wan-client's MAC-addr, waiting for header construction\n");
			res = IPACM_SUCCESS;
		}
	}
	else
	{
		IPACMDBG_H("Already added STA V4 full header\n");
	}

	if (header_set_v6 != true)
	{
		/* checking if the ipv6 same as default route */
		if(wan_v6_addr_gw_set)
		{
			index = get_wan_client_index_ipv6(wan_v6_addr_gw);
			if (index != IPACM_INVALID_INDEX)
			{
				IPACMDBG_H("Matched client index: %d\n", index);
				IPACMDBG_H("Received Client MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
						 get_client_memptr(wan_client, index)->mac[0],
						 get_client_memptr(wan_client, index)->mac[1],
						 get_client_memptr(wan_client, index)->mac[2],
						 get_client_memptr(wan_client, index)->mac[3],
						 get_client_memptr(wan_client, index)->mac[4],
						 get_client_memptr(wan_client, index)->mac[5]);

				if(get_client_memptr(wan_client, index)->ipv6_header_set)
				{
					hdr_hdl_sta_v6 = get_client_memptr(wan_client, index)->hdr_hdl_v6;
					header_set_v6 = true;
					IPACMDBG_H("add full ipv6 header hdl: (%x)\n", get_client_memptr(wan_client, index)->hdr_hdl_v6);
					/* store external_ap's MAC */
					memcpy(ext_router_mac_addr, get_client_memptr(wan_client, index)->mac, sizeof(ext_router_mac_addr));
				}
				else
				{
					IPACMERR("wan-client got ipv6 however didn't construct complete ipv4 header \n");
					return IPACM_FAILURE;
				}

				if(get_client_memptr(wan_client, index)->ipv4_header_set)
				{
					hdr_hdl_sta_v4 = get_client_memptr(wan_client, index)->hdr_hdl_v4;
					header_set_v4 = true;
					IPACMDBG_H("add full ipv4 header hdl: (%x)\n", get_client_memptr(wan_client, index)->hdr_hdl_v4);
				}
			}
			else
			{
				IPACMDBG_H("currently can't find matched wan-client's MAC-addr, waiting for header construction\n");
				res = IPACM_SUCCESS;
			}
		}
	}
	else
	{
		IPACMDBG_H("Already added STA V6 full header\n");
	}

	/* see if default routes are setup before constructing full header */

	if(header_partial_default_wan_v4 == true && wan_v4_is_default_gw)
	{
		handle_route_add_evt(IPA_IP_v4);
	}

	if(header_partial_default_wan_v6 == true && wan_v6_is_default_gw)
	{
		handle_route_add_evt(IPA_IP_v6);
	}
	else if(sta_ipv6_pdn_index != -1 && header_set_v6 == true &&
		header_partial_default_wan_v6 == true &&
		!pending_VID_STA.empty())
	{
		/* start associate pending_sta_vid to STA-WAN */
		for(it = pending_VID_STA.begin(); it != pending_VID_STA.end(); ++it)
		{
			ipacm_event_route_vlan *data;
			data = (ipacm_event_route_vlan *)malloc(sizeof(ipacm_event_route_vlan));
			if(!data)
			{
				IPACMERR("couldn't allocate memory for new vlan pdn event\n");
				return IPACM_FAILURE;
			}
			memset(data, 0, sizeof(ipacm_event_route_vlan));
			data->iptype = IPA_IP_v6;
			data->VlanID = *it;
			data->wan_ipv6_prefix[0] = ipv6_to_iface[sta_ipv6_pdn_index].ipv6_prefix[0];
			data->wan_ipv6_prefix[1] = ipv6_to_iface[sta_ipv6_pdn_index].ipv6_prefix[1];
			check_vlan_pdn(IPA_IP_v6, data);
		}
		pending_VID_STA.clear();
		header_partial_default_wan_v6 = false;
	}
	return res;
}

/* For checking attribute mask field in firewall rules for IPv6 only */
bool IPACM_Wan::check_dft_firewall_rules_attr_mask(IPACM_firewall_conf_t *firewall_config)
{
	uint32_t attrib_mask = 0ul;
	attrib_mask =	IPA_FLT_SRC_PORT_RANGE |
			IPA_FLT_DST_PORT_RANGE |
			IPA_FLT_TYPE |
			IPA_FLT_CODE |
			IPA_FLT_SPI |
			IPA_FLT_SRC_PORT |
			IPA_FLT_DST_PORT;

	for (int i = 0; i < firewall_config->num_extd_firewall_entries; i++)
	{
#ifndef FEATURE_IPACM_UL_FIREWALL
		if (firewall_config->extd_firewall_entries[i].ip_vsn == 6)
#else //n FEATURE_IPACM_UL_FIREWALL
		if (firewall_config->extd_firewall_entries[i].ip_vsn == 6 &&
			firewall_config->extd_firewall_entries[i].firewall_direction
			!= IPACM_MSGR_UL_FIREWALL)
#endif //n FEATURE_IPACM_UL_FIREWALL
		{
#ifdef FEATURE_IPV6_NAT
			// in ipv6_nat_enable=false case, ignore the firewall rules if it's specific to v6nat
			if(firewall_config->extd_firewall_entries[i].IPV6NatEnabledfw)
				continue;
#endif
			if (firewall_config->extd_firewall_entries[i].attrib.attrib_mask & attrib_mask)
			{
				IPACMDBG_H("IHL based attribute mask is found: install IPv6 frag firewall rule \n");
				return true;
			}
		}
	}
	IPACMDBG_H("IHL based attribute mask is not found: no IPv6 frag firewall rule \n");
	return false;
}

#ifdef FEATURE_IPACM_UL_FIREWALL
/* For checking attribute mask field in firewall rules for IPv6 UL only */
bool IPACM_Wan::check_dft_firewall_rules_attr_mask_ul(IPACM_firewall_conf_t *firewall_config)
{
	uint32_t attrib_mask = 0ul;
	attrib_mask =	IPA_FLT_SRC_PORT_RANGE |
			IPA_FLT_DST_PORT_RANGE |
			IPA_FLT_TYPE |
			IPA_FLT_CODE |
			IPA_FLT_SPI |
			IPA_FLT_SRC_PORT |
			IPA_FLT_DST_PORT;

	for (int i = 0; i < firewall_config->num_extd_firewall_entries; i++)
	{
		if (firewall_config->extd_firewall_entries[i].ip_vsn == 6 &&
			firewall_config->extd_firewall_entries[i].firewall_direction
			== IPACM_MSGR_UL_FIREWALL)
		{
#ifdef FEATURE_IPV6_NAT
			// in ipv6_nat_enable=false case, ignore the firewall rules if it's specific to v6nat
			if(firewall_config->extd_firewall_entries[i].IPV6NatEnabledfw)
				continue;
#endif
			if (firewall_config->extd_firewall_entries[i].attrib.attrib_mask & attrib_mask)
			{
				IPACMDBG_H("IHL based attribute mask is found: install IPv6 frag firewall rule \n");
				return true;
			}
		}
	}
	IPACMDBG_H("IHL based attribute mask is not found: no IPv6 frag firewall rule \n");
	return false;
}
#endif //FEATURE_IPACM_UL_FIREWALL

/* for STA mode: add firewall rules */
int IPACM_Wan::config_dft_firewall_rules(ipa_ip_type iptype)
{
	ipa_ioc_add_flt_rule *m_pFilteringTable = NULL;
	ipa_ioc_add_flt_rule_after *m_pFilteringTableafter = NULL;
	struct ipa_flt_rule_add flt_rule_entry;
	int i, rule_v4 = 0, rule_v6 = 0, len;
	int res = IPACM_SUCCESS;
#ifdef FEATURE_IPACM_UL_FIREWALL
	int rule_v4_ul = 0, rule_v6_ul = 0;
#endif //FEATURE_IPACM_UL_FIREWALL
	IPACMDBG_H("ip-family: %d; \n", iptype);

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}
#ifndef FEATURE_IPV6_NAT
	if(iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->ipv6_nat_enable)
	{
		IPACMDBG_H("IPv6 NAT is enable. Don't configure firewall rule\n");
		return IPACM_SUCCESS;
	}
#endif
	IPACMDBG_H("dev_name %s, is_ppp_iface %d\n",dev_name, is_ppp_iface);
	if(sta_vlan_id > 0 && IPACM_Iface::ipacmcfg->get_eth_vlan_wan_up(ipa_if_num) == IPACM_SUCCESS &&
		IPACM_Iface::odu_subnet_fl_rule_hdl[IPA_IP_v4] && (IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable == false))
	{
		len = sizeof(struct ipa_ioc_add_flt_rule_after) + 1 * sizeof(struct ipa_flt_rule_add);
		m_pFilteringTableafter = (struct ipa_ioc_add_flt_rule_after *)calloc(1, len);
		if (!m_pFilteringTableafter)
		{
			IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
			return IPACM_FAILURE;
		}
	}
	else
	{
		/* construct ipa_ioc_add_flt_rule with N firewall rules */
		len = sizeof(struct ipa_ioc_add_flt_rule) + 1 * sizeof(struct ipa_flt_rule_add);
		m_pFilteringTable = (struct ipa_ioc_add_flt_rule *)calloc(1, len);
		if (!m_pFilteringTable)
		{
			IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
			return IPACM_FAILURE;
		}
	}

	if (iptype == IPA_IP_v4)
	{
		if((rule_v4 == 0 && !is_ppp_iface) ||
			(rule_v4 == 0 && is_ppp_iface && !pppoe_route_rule_hdl_v4))
		{
			if(sta_vlan_id > 0 && IPACM_Iface::ipacmcfg->get_eth_vlan_wan_up(ipa_if_num) == IPACM_SUCCESS &&
				IPACM_Iface::odu_subnet_fl_rule_hdl[IPA_IP_v4] && (IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable == false))
			{
				memset(m_pFilteringTableafter, 0, len);
				m_pFilteringTableafter->commit = 1;
				m_pFilteringTableafter->ep = rx_prop->rx[0].src_pipe;
				m_pFilteringTableafter->ip = IPA_IP_v4;
				m_pFilteringTableafter->num_rules = (uint8_t)1;
				m_pFilteringTableafter->add_after_hdl = IPACM_Iface::odu_subnet_fl_rule_hdl[IPA_IP_v4];
			}
			else
			{
				memset(m_pFilteringTable, 0, len);
				m_pFilteringTable->commit = 1;
				m_pFilteringTable->ep = rx_prop->rx[0].src_pipe;
				m_pFilteringTable->global = false;
				m_pFilteringTable->ip = IPA_IP_v4;
				m_pFilteringTable->num_rules = (uint8_t)1;
			}

			memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
			if (false == m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_lan_v4))
			{
				IPACMERR("m_routing.GetRoutingTable(rt_tbl_lan_v4) Failed.\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			flt_rule_entry.flt_rule_hdl = -1;
			flt_rule_entry.status = -1;
			flt_rule_entry.at_rear = true;
			if(IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_mode == ROUTER)
			{
				flt_rule_entry.rule.action = IPA_PASS_TO_DST_NAT;
			}
			else
			{
				flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
			}
#ifdef FEATURE_IPA_V3
			flt_rule_entry.at_rear = true;
			flt_rule_entry.rule.hashable = true;
#endif
			flt_rule_entry.rule.rt_tbl_hdl = IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.hdl;
			memcpy(&flt_rule_entry.rule.attrib,
				&rx_prop->rx[0].attrib,
				sizeof(struct ipa_rule_attrib));
			flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
			flt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0x00000000;
			flt_rule_entry.rule.attrib.u.v4.dst_addr = 0x00000000;
			if(sta_vlan_id > 0 && IPACM_Iface::ipacmcfg->get_eth_vlan_wan_up(ipa_if_num) == IPACM_SUCCESS &&
				IPACM_Iface::odu_subnet_fl_rule_hdl[IPA_IP_v4] && (IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable == false))
			{
				if(!is_ppp_iface)
				{
					flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_VLAN_ID;
					flt_rule_entry.rule.attrib.vlan_id = sta_vlan_id;
				}
				memcpy(&(m_pFilteringTableafter->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
				if (false == m_filtering.AddFilteringRuleAfter(m_pFilteringTableafter))
				{
					IPACMERR("Error Adding RuleTable(0) to Filtering, aborting...\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				else
				{
					IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v4, 1);
					IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n",
						m_pFilteringTableafter->rules[0].flt_rule_hdl,
						m_pFilteringTableafter->rules[0].status);
				}
				/* copy filter hdls */
				dft_wan_fl_hdl[0] = m_pFilteringTableafter->rules[0].flt_rule_hdl;
#ifdef FEATURE_PPPOE
				if(is_ppp_iface)
				{
					pppoe_route_rule_hdl_v4 = m_pFilteringTableafter->rules[0].flt_rule_hdl;
				}
#endif
			}
			else
			{
				memcpy(&(m_pFilteringTable->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
				if (false == m_filtering.AddFilteringRule(m_pFilteringTable))
				{
					IPACMERR("Error Adding RuleTable(0) to Filtering, aborting...\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				else
				{
					IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v4, 1);
					IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n", m_pFilteringTable->rules[0].flt_rule_hdl, m_pFilteringTable->rules[0].status);
				}
				/* copy filter hdls */
				dft_wan_fl_hdl[0] = m_pFilteringTable->rules[0].flt_rule_hdl;
#ifdef FEATURE_PPPOE
				if(is_ppp_iface)
				{
					pppoe_route_rule_hdl_v4 = m_pFilteringTable->rules[0].flt_rule_hdl;
				}
#endif
			}
		}
	}
	else
	{
		if ((rule_v6 == 0 && !is_ppp_iface) ||
			(rule_v6 == 0 && is_ppp_iface && !pppoe_route_rule_hdl_v6))
		{
			if(sta_vlan_id > 0 && IPACM_Iface::ipacmcfg->get_eth_vlan_wan_up(ipa_if_num) == IPACM_SUCCESS
				&& (IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable == false))
			{
				m_pFilteringTableafter = (struct ipa_ioc_add_flt_rule_after *)calloc(1, len);
				if (!m_pFilteringTableafter)
				{
					IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
					return IPACM_FAILURE;
				}
				memset(m_pFilteringTableafter, 0, len);
				m_pFilteringTableafter->commit = 1;
				m_pFilteringTableafter->ep = rx_prop->rx[0].src_pipe;
				m_pFilteringTableafter->ip = IPA_IP_v6;
				m_pFilteringTableafter->num_rules = (uint8_t)1;
				m_pFilteringTableafter->add_after_hdl = ipv6_dest_flt_rule_hdl[num_ipv6_dest_flt_rule - 1];
			}
			else
			{
				m_pFilteringTable = (struct ipa_ioc_add_flt_rule *)calloc(1, len);
				if (!m_pFilteringTable)
				{
					IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
					return IPACM_FAILURE;
				}
				memset(m_pFilteringTable, 0, len);
				m_pFilteringTable->commit = 1;
				m_pFilteringTable->ep = rx_prop->rx[0].src_pipe;
				m_pFilteringTable->global = false;
				m_pFilteringTable->ip = IPA_IP_v6;
				m_pFilteringTable->num_rules = (uint8_t)1;
			}

			/* Construct ICMP rule */
			memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
			flt_rule_entry.at_rear = true;
			flt_rule_entry.flt_rule_hdl = -1;
			flt_rule_entry.status = -1;
			flt_rule_entry.rule.retain_hdr = 1;
			flt_rule_entry.rule.eq_attrib_type = 0;
			flt_rule_entry.rule.action = IPA_PASS_TO_EXCEPTION;
#ifdef FEATURE_IPA_V3
			flt_rule_entry.rule.hashable = true;
#endif
			memcpy(&flt_rule_entry.rule.attrib,
				&rx_prop->rx[0].attrib,
				sizeof(struct ipa_rule_attrib));
			flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_NEXT_HDR;
			flt_rule_entry.rule.attrib.u.v6.next_hdr = (uint8_t)IPACM_FIREWALL_IPPROTO_ICMP6;
			if(sta_vlan_id > 0 && IPACM_Iface::ipacmcfg->get_eth_vlan_wan_up(ipa_if_num) == IPACM_SUCCESS
				&& (IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable == false))
			{
				if(!is_ppp_iface)
				{
					flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_VLAN_ID;
					flt_rule_entry.rule.attrib.vlan_id = sta_vlan_id;
				}
				memcpy(&(m_pFilteringTableafter->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
				if (false == m_filtering.AddFilteringRuleAfter(m_pFilteringTableafter))
				{
					IPACMERR("Error Adding RuleTable(0) to Filtering, aborting...\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				else
				{
					IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);
					IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n", m_pFilteringTableafter->rules[0].flt_rule_hdl, m_pFilteringTableafter->rules[0].status);
				}
				/* copy filter hdls */
				dft_wan_fl_hdl[2] = m_pFilteringTableafter->rules[0].flt_rule_hdl;
			}
			else
			{
				memcpy(&(m_pFilteringTable->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
				if (false == m_filtering.AddFilteringRule(m_pFilteringTable))
				{
					IPACMERR("Error Adding Filtering rules, aborting...\n");
					free(m_pFilteringTable);
					return IPACM_FAILURE;
				}
				else
				{
					IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);
					IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n", m_pFilteringTable->rules[0].flt_rule_hdl, m_pFilteringTable->rules[0].status);
				}
				/* copy filter hdls */
				dft_wan_fl_hdl[2] = m_pFilteringTable->rules[0].flt_rule_hdl;
			}
			/* End of construct ICMP rule */
			/* v6 default route */
			memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
			if (false == m_routing.GetRoutingTable(&IPACM_Iface::ipacmcfg->rt_tbl_wan_v6)) //rt_tbl_wan_v6 rt_tbl_v6
			{
				IPACMERR("m_routing.GetRoutingTable(rt_tbl_wan_v6) Failed.\n");
				free(m_pFilteringTable);
				return IPACM_FAILURE;
			}
			flt_rule_entry.flt_rule_hdl = -1;
			flt_rule_entry.status = -1;
			flt_rule_entry.rule.rt_tbl_hdl = IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.hdl;
			flt_rule_entry.at_rear = true;
#ifdef FEATURE_IPV6_NAT
			if(IPACM_Iface::ipacmcfg->ipv6_nat_enable)
			{
				/* add 2nd pass rule ULA address go to RT for STA mode */
				if(IPACM_Iface::ipacmcfg->ipv6_nat_enable && m_pFilteringTable != NULL)
					add_ipv6_nat_ula_prefix_flt_rule(m_pFilteringTable);

				/* 1st pass rule - go to DST NAT */
				flt_rule_entry.rule.action = IPA_PASS_TO_DST_NAT;
			}
			else
#endif
			{
				flt_rule_entry.at_rear = true;
				if (IPACM_Iface::ipacmcfg->IsIpv6CTEnabled() &&
					IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_mode == ROUTER)
				{
					flt_rule_entry.rule.action = IPA_PASS_TO_DST_NAT;
				}
				else
				{
					flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
				}
			}
#ifdef FEATURE_IPA_V3
			flt_rule_entry.rule.hashable = false;
#endif
			memcpy(&flt_rule_entry.rule.attrib,
				&rx_prop->rx[0].attrib,
				sizeof(struct ipa_rule_attrib));
			flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
			flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = 0X00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = 0X00000000;
			if(sta_vlan_id > 0 && IPACM_Iface::ipacmcfg->get_eth_vlan_wan_up(ipa_if_num) == IPACM_SUCCESS
				&& (IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable == false))
			{
				m_pFilteringTableafter->add_after_hdl = dft_wan_fl_hdl[2];//after ICMP rule above
				if(!is_ppp_iface)
				{
					flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_VLAN_ID;
					flt_rule_entry.rule.attrib.vlan_id = sta_vlan_id;
				}
				memcpy(&(m_pFilteringTableafter->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
				if (false == m_filtering.AddFilteringRuleAfter(m_pFilteringTableafter))
				{
					IPACMERR("Error Adding RuleTable(0) to Filtering, aborting...\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				else
				{
					IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);
					IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n", m_pFilteringTableafter->rules[0].flt_rule_hdl, m_pFilteringTableafter->rules[0].status);
				}
				/* copy filter hdls */
				dft_wan_fl_hdl[1] = m_pFilteringTableafter->rules[0].flt_rule_hdl;
				if(is_ppp_iface)
				{
					pppoe_route_rule_hdl_v6 = m_pFilteringTableafter->rules[0].flt_rule_hdl;
				}
			}
			else
			{
				memcpy(&(m_pFilteringTable->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
				if (false == m_filtering.AddFilteringRule(m_pFilteringTable))
				{
					IPACMERR("Error Adding Filtering rules, aborting...\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				else
				{
					IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);
					IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n", m_pFilteringTable->rules[0].flt_rule_hdl, m_pFilteringTable->rules[0].status);
				}
				/* copy filter hdls */
				dft_wan_fl_hdl[1] = m_pFilteringTable->rules[0].flt_rule_hdl;
				if(is_ppp_iface)
				{
					pppoe_route_rule_hdl_v6 = m_pFilteringTable->rules[0].flt_rule_hdl;
				}
			}
		}
	}
fail:
	if (m_pFilteringTableafter != NULL)
	{
		free(m_pFilteringTableafter);
	}
	if (m_pFilteringTable != NULL)
	{
		free(m_pFilteringTable);
	}
	return res;
}

#ifdef FEATURE_VLAN_MPDN
int IPACM_Wan::get_v6_pdn_firewall_configs(
	std::pair<IPACM_firewall_conf_t*, ipacm_ipv6_wan_iface*> wan_firewall_pair[],
	IPACM_firewall_t &firewall_configs)
{
	int num_v6_pdns = 0;

	for(uint32_t i = 0;
	i < IPA_MAX_NUM_SW_PDNS && num_v6_pdns < IPA_MAX_NUM_HW_PDNS;
		++i)
	{
		if(ipv6_to_iface[i].pIface &&
			(ipv6_to_iface[i].wan_up_vlan_v6 || isDefaultGatewayIfaceUp_v6(ipv6_to_iface[i].pIface)))
		{
			IPACMDBG_H("identified v6 pdn (%s): wan_up_v6: %d, wan_up_vlan_v6: %d, getting FW config\n",
				ipv6_to_iface[i].pIface->dev_name,
				isDefaultGatewayIfaceUp_v6(ipv6_to_iface[i].pIface),
				ipv6_to_iface[i].wan_up_vlan_v6);

			IPACM_firewall_conf_t* curr_pdn_firewall_config =
				get_curr_pdn_firewall_config(firewall_configs, ipv6_to_iface[i].pIface->dev_name);
			if(curr_pdn_firewall_config != NULL)
			{
				std::pair<IPACM_firewall_conf_t*, ipacm_ipv6_wan_iface*>* curr =
					&wan_firewall_pair[num_v6_pdns++];
				curr->first = curr_pdn_firewall_config;
				curr->second = &ipv6_to_iface[i];
			}
		}
	}
	IPACMDBG_H("found %d v6 pdns in firewall file\n", num_v6_pdns);
	return num_v6_pdns;
}
#endif

/* configure the initial firewall filter rules */
#ifdef FEATURE_VLAN_MPDN
int IPACM_Wan::config_dft_firewall_rules_ex(struct ipacm_pdn_flt_rule* rules, int rule_offset, ipa_ip_type iptype,  bool isPmipv6)
{
#else
int IPACM_Wan::config_dft_firewall_rules_ex(struct ipa_flt_rule_add *rules, int rule_offset, ipa_ip_type iptype,  bool isPmipv6)
{
#endif
	int num_rules = 0, original_num_rules = 0, res, pos = rule_offset;

	IPACMDBG_H("ip-family: %d; \n", iptype);

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	if (rules == NULL || rule_offset < 0)
	{
		IPACMERR("No filtering table is available.\n");
		return IPACM_FAILURE;
	}

#ifdef FEATURE_VLAN_MPDN
	uint32_t offloaded_pdns_count_v4 = 0;
	ipacm_ipv4_wan_iface* offloaded_pdns_v4[IPA_MAX_NUM_HW_PDNS];
	for (uint32_t i = 0;
		(i < IPA_MAX_NUM_SW_PDNS) && (offloaded_pdns_count_v4 < IPA_MAX_NUM_HW_PDNS);
		++i)
	{
		if (ipv4_to_iface[i].pIface && ipv4_to_iface[i].pIface->ext_prop != NULL &&
			(ipv4_to_iface[i].wan_up_vlan || isDefaultGatewayIfaceUp(ipv4_to_iface[i].pIface)))
		{
			IPACMDBG_H("identified pdn (%s): wan_up: %d, wan_up_vlan: %d, getting FW config\n",
				ipv4_to_iface[i].pIface->dev_name,
				isDefaultGatewayIfaceUp(ipv4_to_iface[i].pIface),
				ipv4_to_iface[i].wan_up_vlan);

			offloaded_pdns_v4[offloaded_pdns_count_v4++]=&ipv4_to_iface[i];
		}
	}
	IPACMDBG_H("found %d v4 pdns\n", offloaded_pdns_count_v4);

	uint32_t offloaded_pdns_count_v6 = 0;
	ipacm_ipv6_wan_iface* offloaded_pdns_v6[IPA_MAX_NUM_HW_PDNS];
	for (uint32_t i = 0;
		(i < IPA_MAX_NUM_SW_PDNS) && (offloaded_pdns_count_v6 < IPA_MAX_NUM_HW_PDNS);
		++i)
	{
		if (ipv6_to_iface[i].pIface && ipv6_to_iface[i].pIface->ext_prop != NULL &&
			(ipv6_to_iface[i].wan_up_vlan_v6 || isDefaultGatewayIfaceUp_v6(ipv6_to_iface[i].pIface)))
		{
			IPACMDBG_H("identified v6 pdn (%s): wan_up_v6: %d, wan_up_vlan_v6: %d, getting FW config\n",
				ipv6_to_iface[i].pIface->dev_name,
				isDefaultGatewayIfaceUp_v6(ipv6_to_iface[i].pIface),
				ipv6_to_iface[i].wan_up_vlan_v6);

			offloaded_pdns_v6[offloaded_pdns_count_v6++]=&ipv6_to_iface[i];
		}
	}
	IPACMDBG_H("found %d v6 pdns\n", offloaded_pdns_count_v6);
#endif

	if (iptype == IPA_IP_v4)
	{
		original_num_rules = IPACM_Wan::num_v4_flt_rule;
		IPACM_Wan::num_firewall_v4 = 0;

#ifdef FEATURE_VLAN_MPDN
		/* default rule for all PDNs which are up */
		for (uint32_t i = 0; i < offloaded_pdns_count_v4; ++i)
		{
			IPACM_Wan* curr_interface = offloaded_pdns_v4[i]->pIface;
			if(!curr_interface)
			{
				IPACMDBG_H("curr_interface is NULL\n");
				return IPACM_FAILURE;
			}

			IPACMDBG_H("adding default rule for iface %s\n", curr_interface->dev_name);
			if (IPACM_Iface::ipacmcfg->ipogre_enabled)
			{
				res = add_ipogre_frag_flt_rule_ex(curr_interface->rx_prop->rx[0].attrib,
					rules[pos].flt_rule, pos, iptype, false);
				rules[pos].mux_id = curr_interface->ext_prop->ext[0].mux_id;
				++pos;
			}
			res = add_catchup_all_filtering_rule_each_pdn(iptype,
				curr_interface->rx_prop->rx[0].attrib, rules[pos].flt_rule, pos, isPmipv6);
			if((isPmipv6 || IPACM_Iface::ipacmcfg->ipogre_enabled) && iptype==IPACM_Iface::ipacmcfg->ipgre_info.iptype)
			{
				rules[pos].mux_id = curr_interface->ext_prop->ext[0].mux_id;
				++pos;
				/*Need to add the catchall rule that was inserted during WAN up, for second pass*/
				res = add_catchup_all_filtering_rule_each_pdn(iptype,
				curr_interface->rx_prop->rx[0].attrib, rules[pos].flt_rule, pos,false);
			}
			if (res != IPACM_SUCCESS)
			{
				return res;
			}
			IPACMDBG_H("m_is_sta_mode %d\n", m_is_sta_mode);
			if(m_is_sta_mode == WLAN_WAN || m_is_sta_mode == ECM_WAN)
				rules[pos].mux_id = 0;
			else if(curr_interface->ext_prop != NULL)
				rules[pos].mux_id = curr_interface->ext_prop->ext[0].mux_id;
			++pos;
		}
		if(offloaded_pdns_count_v4)
			num_rules = IPACM_Wan::num_v4_flt_rule - original_num_rules;
		else
			num_rules = 0;
#else
		res = add_catchup_all_filtering_rule_each_pdn(iptype, rx_prop->rx[0].attrib, rules[pos], pos, isPmipv6);
		if (res != IPACM_SUCCESS)
		{
			return res;
		}
		++pos;
		if(wan_up)
			num_rules = IPACM_Wan::num_v4_flt_rule - original_num_rules;
		else
			num_rules = 0;
#endif
	}
	else
	{
		original_num_rules = IPACM_Wan::num_v6_flt_rule;
		IPACM_Wan::num_firewall_v6 = 0;

#ifdef FEATURE_IPV6_NAT
		if(IPACM_Iface::ipacmcfg->ipv6_nat_enable && (wan_up_v6 || isVlanWanUP_V6()))
		{
			/*
			 * construct 2nd pass DL v6nat flt rule to send all ULA
			 * destination address (after NAT) packets to routing
			 */
			res = add_ipv6_nat_ula_prefix_flt_rule_ex(rx_prop->rx[1].attrib, rules, pos);
			if(res != IPACM_SUCCESS)
			{
				return res;
			}

#ifdef FEATURE_VLAN_MPDN
			/* this rule shall apply to all PDNs, but we must send some MUX ID in the QMI */
			if(ext_prop != NULL)
				rules[pos].mux_id = ext_prop->ext[0].mux_id;
#endif
			++pos;
		}
#endif
#ifdef FEATURE_VLAN_MPDN
		/* default rule for all PDNs which are up */
		for (uint32_t i = 0; i < offloaded_pdns_count_v6; ++i)
		{
			IPACM_Wan* curr_interface = offloaded_pdns_v6[i]->pIface;
			IPACMDBG_H("adding default rule for iface %s ip-type %d\n", curr_interface->dev_name, iptype);
			/* for ipv6 nat case this shall be the 2nd pass catch all rule to send to v6 LAN RT table*/
			/* Add IPoGRE frag filter rule when ipogre is enabled */
			if (IPACM_Iface::ipacmcfg->ipogre_enabled)
			{
				res = add_ipogre_frag_flt_rule_ex(curr_interface->rx_prop->rx[0].attrib,
					rules[pos].flt_rule, pos, iptype, true);
				rules[pos].mux_id = curr_interface->ext_prop->ext[0].mux_id;
				++pos;
				res = add_ipogre_frag_flt_rule_ex(curr_interface->rx_prop->rx[0].attrib,
					rules[pos].flt_rule, pos, iptype, false);
				rules[pos].mux_id = curr_interface->ext_prop->ext[0].mux_id;
				++pos;
			}

			res = add_catchup_all_filtering_rule_each_pdn(iptype,
				curr_interface->rx_prop->rx[0].attrib, rules[pos].flt_rule, pos,true);
			if(isPmipv6 || IPACM_Iface::ipacmcfg->ipogre_enabled)
			{
				rules[pos].mux_id = curr_interface->ext_prop->ext[0].mux_id;
				++pos;
				/*Need to add the catchall rule that was inserted during WAN up, for second pass*/
				res = add_catchup_all_filtering_rule_each_pdn( iptype,
				curr_interface->rx_prop->rx[0].attrib, rules[pos].flt_rule, pos,false);
			}
			if (res != IPACM_SUCCESS)
			{
				return res;
			}
			if(m_is_sta_mode == Q6_WAN && curr_interface->ext_prop != NULL)
			{
				rules[pos].mux_id = curr_interface->ext_prop->ext[0].mux_id;
				++pos;
			}
		}

		if(offloaded_pdns_count_v6)
			num_rules = IPACM_Wan::num_v6_flt_rule - original_num_rules;
		else
			num_rules = 0;
#else
		res = add_catchup_all_filtering_rule_each_pdn(iptype, rx_prop->rx[1].attrib, rules[pos], pos, isPmipv6);
		if (res != IPACM_SUCCESS)
		{
			return res;
		}
		++pos;
		if(wan_up_v6)
			num_rules = IPACM_Wan::num_v6_flt_rule - original_num_rules;
		else
			num_rules = 0;
#endif
	}
	IPACMDBG_H("Constructed %d firewall rules for ip type %d\n", num_rules, iptype);
	return IPACM_SUCCESS;
}

#ifdef FEATURE_IPACM_UL_FIREWALL

typedef struct
{
	uint8_t profile;
	bool firewall_enabled;
}_firewall_state_t;

int IPACM_Wan::read_firewall_filter_rules_ul(void)
{
	int i = 0;
#ifdef FEATURE_VLAN_MPDN
	std::pair<IPACM_firewall_conf_t*, ipacm_ipv6_wan_iface*> offloaded_pdns_v6[IPA_MAX_NUM_HW_PDNS];
	_firewall_state_t firewall_state[IPA_MAX_NUM_HW_PDNS];
	int firewall_profile_cnt;
	bool has_firewall_changed = false;
	int firewall_num_v6_pdns_ul = 0;
	int num_mpdn_firewall_v6_ul[IPA_MAX_NUM_HW_PDNS];
#endif
	IPACMDBG_H("Firewall XML file is %s\n", MOBILE_FIREWALL_FILE);
#ifdef FEATURE_VLAN_MPDN
	/* Save current state of firewall */
	memset(&firewall_state, 0, IPA_MAX_NUM_HW_PDNS*sizeof(_firewall_state_t));
	firewall_profile_cnt = firewall_mpdn_config_ul.pdn_count;
	for (i = 0; i < firewall_profile_cnt; ++i)
	{
		firewall_state[i].profile = firewall_mpdn_config_ul.pdns[i].profile;
		firewall_state[i].firewall_enabled = firewall_mpdn_config_ul.pdns[i].firewall_enable;
	}

	if(IPACM_read_firewall_xml(MOBILE_FIREWALL_FILE, firewall_mpdn_config_ul) == IPACM_SUCCESS)
#else
	if(IPACM_read_firewall_xml(MOBILE_FIREWALL_FILE, firewall_config_ul) == IPACM_SUCCESS)
#endif
	{
		IPACMDBG_H("QCMAP Firewall XML read OK \n");
	}
	else
	{
		IPACMERR("QCMAP Firewall XML read failed, no such file, use default configuration \n");
		return IPACM_FAILURE;
	}
#ifdef FEATURE_VLAN_MPDN
	firewall_num_v6_pdns_ul = get_v6_pdn_firewall_configs(offloaded_pdns_v6, firewall_mpdn_config_ul);

	for(int j = 0; j < firewall_num_v6_pdns_ul; j++)
	{
		IPACM_firewall_conf_t* curr_conf = offloaded_pdns_v6[j].first;
		char *dev = offloaded_pdns_v6[j].second->pIface->dev_name;
		/* find the number of IPv6 UL firewall rules */
		if(curr_conf->firewall_enable)
		{
			has_firewall_changed = true;
			num_mpdn_firewall_v6_ul[j] = 0;
			for(int i = 0; i < curr_conf->num_extd_firewall_entries; i++)
			{
#ifdef FEATURE_IPV6_NAT
				// in ipv6_nat_enable=false case, ignore the firewall rules if it's specific to v6nat
				if(curr_conf->extd_firewall_entries[i].IPV6NatEnabledfw)
					continue;
#endif
				if(curr_conf->extd_firewall_entries[i].ip_vsn == 6 &&
					curr_conf->extd_firewall_entries[i].firewall_direction ==
					IPACM_MSGR_UL_FIREWALL)
				{
					num_mpdn_firewall_v6_ul[j]++;
				}
				/* limit the total number of firewall entries for this pdn,
				 * another limitation is applied when we install the rules on LAN prod or send to Q6
				 */
				if(num_mpdn_firewall_v6_ul[j] == IPACM_MAX_FIREWALL_ENTRIES)
				{
					IPACMERR("reached MAX num firewall rules, dev %s, j %d, num pdns %d\n",
						dev,
						j, firewall_num_v6_pdns_ul);
					break;
				}
			}
			IPACMDBG_H("dev %s, num ul firewall %d\n",
				dev,
				num_mpdn_firewall_v6_ul[j]);
		}
		else
		{
			/*Dont handle if firewall disabled state hasnt changed, ignore hoax notification */
			for (i = 0 ; i < firewall_profile_cnt; ++i)
			{
				if (curr_conf->profile == firewall_state[i].profile)
				{
					if (!firewall_state[i].firewall_enabled)
					{
						IPACMDBG_H("For pdn %s fw state is disabled & hasnt changed, ignore the event\n ", dev);
					}
					else
					{
						IPACMDBG_H("firewall disabled, dev %s\n",dev);
						has_firewall_changed = true;
					}
					break;
				}
			}
			num_mpdn_firewall_v6_ul[j] = 0;
		}
	}
	if (!has_firewall_changed)
		return IPACM_FAILURE;
#else
	int total_num_firewall_v6_ul = 0;

	/* find the number of IPv6 UL firewall rules */
	for(i = 0; i < firewall_config_ul.num_extd_firewall_entries; i++)
	{
		if(firewall_config_ul.extd_firewall_entries[i].ip_vsn == 6 &&
			firewall_config_ul.extd_firewall_entries[i].firewall_direction ==
			IPACM_MSGR_UL_FIREWALL)
		{
#ifdef FEATURE_IPV6_NAT
			// in ipv6_nat_enable=false case, ignore the firewall rules if it's specific to v6nat
			if(firewall_config_ul.extd_firewall_entries[i].IPV6NatEnabledfw)
				continue;
#endif
			total_num_firewall_v6_ul++;
		}

		/* limit the total number of firewall entries for all pdns */
		if(total_num_firewall_v6_ul == IPACM_MAX_FIREWALL_ENTRIES)
		{
			IPACMDBG_H("reached maximal number of FW rules\n");
			break;
		}
	}
	IPACMDBG_H("firewall rule v6_ul:%d total:%d\n", total_num_firewall_v6_ul, firewall_config_ul.num_extd_firewall_entries);
#endif
	return IPACM_SUCCESS;
}

int IPACM_Wan::set_pdn_num_fw_rules_by_vid(int vid, int num_fw_rules)
{
#ifdef FEATURE_VLAN_MPDN
	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		if(ipv6_to_iface[i].pIface &&
			(ipv6_to_iface[i].wan_up_vlan_v6 || isDefaultGatewayIfaceUp_v6(ipv6_to_iface[i].pIface)))
		{
			if(get_vid_index_for_iface_v6(ipv6_to_iface[i], vid) != IPACM_FAILURE ||
				(isDefaultGatewayIfaceUp_v6(ipv6_to_iface[i].pIface) && !vid))
			{
				IPACMDBG_H("found dev %s, vid %d, num_ul_fw_rules %d update to %d\n",
					ipv6_to_iface[i].pIface->dev_name,
					vid,
					ipv6_to_iface[i].pIface->num_firewall_v6_ul_pdn,
					num_fw_rules);
				int orig_num = IPACM_Wan::num_firewall_v6_ul;
				IPACM_Wan::num_firewall_v6_ul -= ipv6_to_iface[i].pIface->num_firewall_v6_ul_pdn;
				IPACM_Wan::num_firewall_v6_ul += num_fw_rules;
				IPACMDBG_H("num_firewall_v6_ul (%d)->(%d)\n", orig_num, IPACM_Wan::num_firewall_v6_ul);

				ipv6_to_iface[i].pIface->num_firewall_v6_ul_pdn = num_fw_rules;
				return IPACM_SUCCESS;
			}
		}
	}
#else
	if(vid == 0)
	{
		num_firewall_v6_ul = num_fw_rules;
		return IPACM_SUCCESS;
	}
#endif
	IPACMERR("couldn't find match for vid %d\n", vid);
	return IPACM_FAILURE;
}




int IPACM_Wan::get_pdn_num_fw_rules_by_vid(int vid, int *num_fw_rules)
{
#ifdef FEATURE_VLAN_MPDN
	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		if(ipv6_to_iface[i].pIface &&
			(ipv6_to_iface[i].wan_up_vlan_v6 || isDefaultGatewayIfaceUp_v6(ipv6_to_iface[i].pIface)))
		{
			if(get_vid_index_for_iface_v6(ipv6_to_iface[i], vid) != IPACM_FAILURE ||
				(isDefaultGatewayIfaceUp_v6(ipv6_to_iface[i].pIface) && !vid))
			{
				IPACMDBG_H("found dev %s, vid %d, num_ul_fw_rules %d\n",
					ipv6_to_iface[i].pIface->dev_name,
					vid,
					ipv6_to_iface[i].pIface->num_firewall_v6_ul_pdn);
				*num_fw_rules = ipv6_to_iface[i].pIface->num_firewall_v6_ul_pdn;
				return IPACM_SUCCESS;
			}
		}
	}
#else
	if(vid == 0)
	{
		*num_fw_rules = num_firewall_v6_ul;
		return IPACM_SUCCESS;
	}
#endif
	IPACMERR("couldn't find match for vid %d\n", vid);
	return IPACM_FAILURE;
}

#ifdef FEATURE_VLAN_MPDN
int IPACM_Wan::GetV6PrefixByVid(int vid, uint32_t *v6_prefix)
{
	if(!vid)
	{
		v6_prefix[0] = backhaul_ipv6_prefix[0];
		v6_prefix[1] = backhaul_ipv6_prefix[1];
		return IPACM_SUCCESS;
	}

	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		if(ipv6_to_iface[i].pIface && ipv6_to_iface[i].wan_up_vlan_v6)
		{
			for(int j = 0; j < ipv6_to_iface[i].VID_cnt; j++)
			{
				if((ipv6_to_iface[i].associated_VIDs[j] == vid))
				{
					IPACMDBG_H("found dev %s, vid %d, v6_prefix 0x[%X][%X]\n",
						ipv6_to_iface[i].pIface->dev_name,
						ipv6_to_iface[i].associated_VIDs[j],
						ipv6_to_iface[i].pIface->ipv6_prefix[0],
						ipv6_to_iface[i].pIface->ipv6_prefix[1]);
					v6_prefix[0] = ipv6_to_iface[i].pIface->ipv6_prefix[0];
					v6_prefix[1] = ipv6_to_iface[i].pIface->ipv6_prefix[1];
					return IPACM_SUCCESS;
				}
			}
		}
	}
	IPACMERR("couldn't find match for vid %d\n", vid);
	return IPACM_FAILURE;
}

int IPACM_Wan::GetV6MTUByPrefix(uint16_t *mtu, uint32_t *v6_prefix)
{
	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		if(IPACM_Wan::ipv6_to_iface[i].ipv6_prefix[0] || IPACM_Wan::ipv6_to_iface[i].ipv6_prefix[1])
		{
			if(IPACM_Wan::ipv6_to_iface[i].ipv6_prefix[0] == v6_prefix[0]
				&& IPACM_Wan::ipv6_to_iface[i].ipv6_prefix[1] == v6_prefix[1])
			{
				IPACMDBG_H("IPACM v6 prefix as: 0x[%X][%X] entry(%d)\n",
					IPACM_Wan::ipv6_to_iface[i].ipv6_prefix[0],
					IPACM_Wan::ipv6_to_iface[i].ipv6_prefix[1], i);
				if(IPACM_Wan::ipv6_to_iface[i].wan_up_vlan_v6 || IPACM_Wan::ipv6_to_iface[i].pIface->active_v6)
					*mtu = IPACM_Wan::ipv6_to_iface[i].pIface->mtu_v6;
				else
					*mtu = DEFAULT_MTU_SIZE;
				return IPACM_SUCCESS;
			}
		}
	}
	IPACMERR("couldn't find MTU for v6_prefix 0x[%X][%X], using default size:%d\n", v6_prefix[0],  v6_prefix[1], DEFAULT_MTU_SIZE);
	*mtu = DEFAULT_MTU_SIZE;
	return IPACM_FAILURE;
}
#endif //FEATURE_VLAN_MPDN

IPACM_firewall_conf_t* IPACM_Wan::get_default_profile_firewall_conf_ul(int *default_vid)
{
	IPACM_firewall_conf_t* firewall_conf = NULL;
#ifdef FEATURE_VLAN_MPDN
	int idx = 0;
	int num_pdns = firewall_mpdn_config_ul.pdn_count;

	if(firewall_mpdn_config_ul.default_profile == 0)
	{
		if(firewall_mpdn_config_ul.pdn_count != 1)
		{
			IPACMERR("can't identify default pdn\n");
			return NULL;
		}
		idx = 0;
	}
	else
	{
		for(idx = 0; idx < num_pdns; ++idx)
		{
			if(firewall_mpdn_config_ul.default_profile == firewall_mpdn_config_ul.pdns[idx].profile)
			{
				break;
			}
		}
		if(idx == num_pdns)
		{
			IPACMERR("The XML is not valid. The default profile %d wasn't located\n",
				firewall_mpdn_config_ul.default_profile);
			return NULL;
		}
	}
	firewall_conf = &firewall_mpdn_config_ul.pdns[idx];
	*default_vid = 0;
	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		if(ipv6_to_iface[i].pIface &&
			(ipv6_to_iface[i].wan_up_vlan_v6 || isDefaultGatewayIfaceUp_v6(ipv6_to_iface[i].pIface)))
		{
			if(!strcmp(firewall_mpdn_config_ul.pdns[idx].net_dev,
				ipv6_to_iface[i].pIface->dev_name))
			{
				IPACMDBG("found %s dev in index %d, VID %d\n",
					firewall_mpdn_config_ul.pdns[idx].net_dev,
					i,
					ipv6_to_iface[i].associated_VIDs[0]);
				*default_vid = ipv6_to_iface[i].associated_VIDs[0];
			}
		}
	}
#else
	firewall_conf = &firewall_config_ul;
	*default_vid = 0;
#endif
	return firewall_conf;
}

#ifdef FEATURE_VLAN_MPDN
IPACM_firewall_conf_t* IPACM_Wan::get_firewall_conf_by_vid_ul(int vid)
{
	int num_pdns = firewall_mpdn_config_ul.pdn_count;

	for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
	{
		if(ipv6_to_iface[i].pIface &&
			(ipv6_to_iface[i].wan_up_vlan_v6 || isDefaultGatewayIfaceUp_v6(ipv6_to_iface[i].pIface)))
		{
			if(get_vid_index_for_iface_v6(ipv6_to_iface[i], vid) != IPACM_FAILURE)
			{
				IPACMDBG("found %s dev in index %d, VID %d\n",
					ipv6_to_iface[i].pIface->dev_name,
					i,
					vid);
				for(int j = 0; j < num_pdns; j++)
				{
					if(!strcmp(firewall_mpdn_config_ul.pdns[j].net_dev,
						ipv6_to_iface[i].pIface->dev_name))
					{
						IPACMDBG("found %s dev in index %d\n",
							firewall_mpdn_config_ul.pdns[j].net_dev, j);
						return &firewall_mpdn_config_ul.pdns[j];
					}
				}
			}
		}
	}
	return NULL;
}
#endif //FEATURE_VLAN_MPDN

#endif //FEATURE_IPACM_UL_FIREWALL
int IPACM_Wan::init_fl_rule_ex(ipa_ip_type iptype)
{
	int res = IPACM_SUCCESS;

	/* ADD corresponding ipa_rm_resource_name of RX-endpoint before adding all IPV4V6 FT-rules */
	IPACMDBG_H(" dun add producer dependency from %s with registered rx-prop\n", dev_name);

	if(iptype == IPA_IP_v4)
	{
		if(num_ipv4_modem_pdn == 1)	/* install ipv4 default modem DL filtering rules only once */
		{
			/* reset the num_v4_flt_rule*/
			IPACM_Wan::num_v4_flt_rule = 0;
#ifdef FEATURE_VLAN_MPDN
			add_dft_filtering_rule(pdn_flt_rule_v4, IPACM_Wan::num_v4_flt_rule, IPA_IP_v4);
#else
			add_dft_filtering_rule(flt_rule_v4, IPACM_Wan::num_v4_flt_rule, IPA_IP_v4);
#endif
			install_wan_filtering_rule(false);
		}
	}
	else if(iptype == IPA_IP_v6)
	{
		IPACMDBG_H("modem_ipv6_pdn_index: %d\n", modem_ipv6_pdn_index);

		if(num_ipv6_modem_pdn == 1)	/* install ipv6 default modem DL filtering rules only once */
		{
			/* reset the num_v6_flt_rule*/
			IPACM_Wan::num_v6_flt_rule = 0;
#ifdef FEATURE_VLAN_MPDN
			add_dft_filtering_rule(pdn_flt_rule_v6, IPACM_Wan::num_v6_flt_rule, IPA_IP_v6);
#else
			add_dft_filtering_rule(flt_rule_v6, IPACM_Wan::num_v6_flt_rule, IPA_IP_v6);
#endif
			install_wan_filtering_rule(false);
		}
	}
	else
	{
		IPACMERR("IP type is not expected.\n");
		res = IPACM_FAILURE;
		goto fail;
	}

fail:
	return res;
}

#ifdef FEATURE_VLAN_MPDN
int IPACM_Wan::add_icmp_alg_rules(struct ipacm_pdn_flt_rule *rules, int rule_offset, ipa_ip_type iptype)
#else
int IPACM_Wan::add_icmp_alg_rules(struct ipa_flt_rule_add *rules, int rule_offset, ipa_ip_type iptype)
#endif
{
	int res = IPACM_SUCCESS, i, original_num_rules = 0, num_rules = 0;
#ifdef FEATURE_VLAN_MPDN
	int num_icmp_rules = 0;
#endif
	struct ipa_flt_rule_add flt_rule_entry;
	IPACM_Config* ipacm_config = IPACM_Iface::ipacmcfg;
	ipa_ioc_generate_flt_eq flt_eq;
	ipa_ioc_get_rt_tbl_indx rt_tbl_idx;

	if(rules == NULL || rule_offset < 0)
	{
		IPACMERR("No filtering table is available.\n");
		return IPACM_FAILURE;
	}

	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	if(iptype == IPA_IP_v4)
	{
		original_num_rules = IPACM_Wan::num_v4_flt_rule;

		memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
		strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_wan_dl.name, IPA_RESOURCE_NAME_MAX);
		rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
		rt_tbl_idx.ip = iptype;
		if(0 != ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx))
		{
			IPACMERR("Failed to get routing table index from name\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		IPACMDBG_H("WAN DL routing table %s has index %d\n", IPACM_Iface::ipacmcfg->rt_tbl_wan_dl.name, rt_tbl_idx.idx);

		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

		flt_rule_entry.at_rear = true;
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;

		flt_rule_entry.rule.retain_hdr = 1;
		flt_rule_entry.rule.to_uc = 0;
		flt_rule_entry.rule.eq_attrib_type = 1;
		flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#ifdef FEATURE_IPA_V3
		flt_rule_entry.rule.hashable = true;
#endif
		flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;

		/* Configuring ICMP filtering rule */
		memcpy(&flt_rule_entry.rule.attrib,
					 &rx_prop->rx[0].attrib,
					 sizeof(flt_rule_entry.rule.attrib));
		/* Multiple PDNs may exist so keep meta-data */
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_PROTOCOL;
		flt_rule_entry.rule.attrib.u.v4.protocol = (uint8_t)IPACM_FIREWALL_IPPROTO_ICMP;

		memset(&flt_eq, 0, sizeof(flt_eq));
		memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
		flt_eq.ip = iptype;
		if(0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
		{
			IPACMERR("Failed to get eq_attrib\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		memcpy(&flt_rule_entry.rule.eq_attrib,
					 &flt_eq.eq_attrib,
					 sizeof(flt_rule_entry.rule.eq_attrib));
#ifdef FEATURE_VLAN_MPDN
		num_icmp_rules = 0;
		for(i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
		{
			if(ipv4_to_iface[i].pIface &&
				(ipv4_to_iface[i].wan_up_vlan || isDefaultGatewayIfaceUp(ipv4_to_iface[i].pIface)))
			{
				IPACMDBG_H("adding ICMP rule for IF %s ipv4\n", ipv4_to_iface[i].pIface->dev_name);
				if(m_is_sta_mode == Q6_WAN && ipv4_to_iface[i].pIface->ext_prop != NULL)
				{
					rules[rule_offset + i].mux_id = ipv4_to_iface[i].pIface->ext_prop->ext[0].mux_id;
					memcpy(&(rules[rule_offset + i].flt_rule), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
					IPACM_Wan::num_v4_flt_rule++;
					num_icmp_rules++;
					IPACMDBG_H("num_icmp_rules: %d\n", num_icmp_rules);
				}
			}
		}
#else
		memcpy(&(rules[rule_offset]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
		IPACM_Wan::num_v4_flt_rule++;
#endif

		/*
		 * Removed from here the code to general filtering rules for
		 * ALG ports. ALG ports are now handled by NAT exception for UL
		 * and NAT dummy rules for DL.
		 *
		 */

		num_rules = IPACM_Wan::num_v4_flt_rule - original_num_rules;
	}
	else /* IPv6 case */
	{
		original_num_rules = IPACM_Wan::num_v6_flt_rule;

		memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
		strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_wan_dl.name, IPA_RESOURCE_NAME_MAX);
		rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
		rt_tbl_idx.ip = iptype;
		if(0 != ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx))
		{
			IPACMERR("Failed to get routing table index from name\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		IPACMDBG_H("WAN DL routing table %s has index %d\n", IPACM_Iface::ipacmcfg->rt_tbl_wan_dl.name, rt_tbl_idx.idx);

		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

		flt_rule_entry.at_rear = true;
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;

		flt_rule_entry.rule.retain_hdr = 1;
		flt_rule_entry.rule.to_uc = 0;
		flt_rule_entry.rule.eq_attrib_type = 1;
		flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#ifdef FEATURE_IPA_V3
		flt_rule_entry.rule.hashable = true;
#endif
		flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;

		/* Configuring ICMP filtering rule */
		memcpy(&flt_rule_entry.rule.attrib,
					 &rx_prop->rx[1].attrib,
					 sizeof(flt_rule_entry.rule.attrib));
		/* Multiple PDNs may exist so keep meta-data */
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_NEXT_HDR;
		flt_rule_entry.rule.attrib.u.v6.next_hdr = (uint8_t)IPACM_FIREWALL_IPPROTO_ICMP6;

		memset(&flt_eq, 0, sizeof(flt_eq));
		memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
		flt_eq.ip = iptype;
		if(0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
		{
			IPACMERR("Failed to get eq_attrib\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		memcpy(&flt_rule_entry.rule.eq_attrib,
					 &flt_eq.eq_attrib,
					 sizeof(flt_rule_entry.rule.eq_attrib));
#ifdef FEATURE_VLAN_MPDN
		num_icmp_rules = 0;
		for(i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
		{
			if(ipv6_to_iface[i].pIface && (ipv6_to_iface[i].wan_up_vlan_v6 || isDefaultGatewayIfaceUp_v6(ipv6_to_iface[i].pIface)))
			{
				IPACMDBG_H("adding ICMPv6 rule for IF %s \n", ipv6_to_iface[i].pIface->dev_name);
				if (m_is_sta_mode == Q6_WAN && ipv6_to_iface[i].pIface->ext_prop != NULL)
					rules[rule_offset + i].mux_id = ipv6_to_iface[i].pIface->ext_prop->ext[0].mux_id;
				memcpy(&(rules[rule_offset + i].flt_rule), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
				IPACM_Wan::num_v6_flt_rule++;
				num_icmp_rules++;
			}
		}
#else
		memcpy(&(rules[rule_offset]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
		IPACM_Wan::num_v6_flt_rule++;
#endif

		num_rules = IPACM_Wan::num_v6_flt_rule - original_num_rules;
	}

fail:
	IPACMDBG_H("Constructed %d ICMP/ALG rules for ip type %d\n", num_rules, iptype);
		return res;
}

int IPACM_Wan::query_ext_prop()
{
	int fd, ret = IPACM_SUCCESS, cnt;

	if (iface_query->num_ext_props > 0)
	{
		fd = open(IPA_DEVICE_NAME, O_RDWR);
		IPACMDBG_H("iface query-property \n");
		if (fd < 0)
		{
			IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
			return IPACM_FAILURE;
		}

		ext_prop = (struct ipa_ioc_query_intf_ext_props *)
			 calloc(1, sizeof(struct ipa_ioc_query_intf_ext_props) +
							iface_query->num_ext_props * sizeof(struct ipa_ioc_ext_intf_prop));
		if(ext_prop == NULL)
		{
			IPACMERR("Unable to allocate memory.\n");
			close(fd);
			return IPACM_FAILURE;
		}
		memcpy(ext_prop->name, dev_name,
					 sizeof(dev_name));
		ext_prop->num_ext_props = iface_query->num_ext_props;

		IPACMDBG_H("Query extended property for iface %s\n", ext_prop->name);

		ret = ioctl(fd, IPA_IOC_QUERY_INTF_EXT_PROPS, ext_prop);
		if (ret < 0)
		{
			IPACMERR("ioctl IPA_IOC_QUERY_INTF_EXT_PROPS failed\n");
			/* ext_prop memory will free when iface-down*/
			free(ext_prop);
			ext_prop = NULL;
			close(fd);
			return ret;
		}

		IPACMDBG_H("Wan interface has %d tx props, %d rx props and %d ext props\n",
				iface_query->num_tx_props, iface_query->num_rx_props, iface_query->num_ext_props);

		for (cnt = 0; cnt < ext_prop->num_ext_props; cnt++)
		{
#ifndef FEATURE_IPA_V3
			IPACMDBG_H("Ex(%d): ip-type: %d, mux_id: %d, flt_action: %d\n, rt_tbl_idx: %d, is_xlat_rule: %d flt_hdl: %d\n",
				cnt, ext_prop->ext[cnt].ip, ext_prop->ext[cnt].mux_id, ext_prop->ext[cnt].action,
				ext_prop->ext[cnt].rt_tbl_idx, ext_prop->ext[cnt].is_xlat_rule, ext_prop->ext[cnt].filter_hdl);
#else /* defined (FEATURE_IPA_V3) */
			IPACMDBG_H("Ex(%d): ip-type: %d, mux_id: %d, flt_action: %d\n, rt_tbl_idx: %d, is_xlat_rule: %d rule_id: %d\n",
				cnt, ext_prop->ext[cnt].ip, ext_prop->ext[cnt].mux_id, ext_prop->ext[cnt].action,
				ext_prop->ext[cnt].rt_tbl_idx, ext_prop->ext[cnt].is_xlat_rule, ext_prop->ext[cnt].rule_id);
#endif
		}

		if(IPACM_Wan::is_ext_prop_set == false)
		{
			IPACM_Iface::ipacmcfg->SetExtProp(ext_prop);
			IPACM_Wan::is_ext_prop_set = true;
		}
		close(fd);
	}
	return IPACM_SUCCESS;
}

int IPACM_Wan::config_wan_firewall_rule(ipa_ip_type iptype,bool isPmipv6)
{
	list<l2tp_client_info>::iterator it;
	int res = IPACM_SUCCESS;

#if !defined(FEATURE_SOCKSv5) && !defined(FEATURE_IPV6_NAT)
	if(iptype == IPA_IP_v6 && IPACM_Iface::ipacmcfg->ipv6_nat_enable)
	{
		IPACMDBG_H("IPv6 NAT is enable. Don't configure firewall rule\n");
		return IPACM_SUCCESS;
	}
#endif

	IPACMDBG_H("Configure WAN DL firewall rules.\n");

	if(iptype == IPA_IP_v4)
	{
		IPACM_Wan::num_v4_flt_rule = IPA_V2_NUM_DEFAULT_WAN_FILTER_RULE_IPV4;
#ifdef FEATURE_VLAN_MPDN
		if(IPACM_FAILURE == add_icmp_alg_rules(pdn_flt_rule_v4, IPACM_Wan::num_v4_flt_rule, IPA_IP_v4))
#else
		if(IPACM_FAILURE == add_icmp_alg_rules(flt_rule_v4, IPACM_Wan::num_v4_flt_rule, IPA_IP_v4))
#endif
		{
			IPACMERR("Failed to add ICMP and ALG port filtering rules.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACMDBG_H("Succeded in constructing ICMP/ALG rules for ip type %d\n", iptype);

#ifdef FEATURE_VLAN_MPDN
		if(IPACM_FAILURE == config_dft_firewall_rules_ex(pdn_flt_rule_v4, IPACM_Wan::num_v4_flt_rule, IPA_IP_v4, isPmipv6))
#else
		if(IPACM_FAILURE == config_dft_firewall_rules_ex(flt_rule_v4, IPACM_Wan::num_v4_flt_rule, IPA_IP_v4, isPmipv6))
#endif
		{
			IPACMERR("Failed to add firewall filtering rules.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACMDBG_H("Succeded in constructing firewall rules for ip type %d\n", iptype);
#ifdef FEATURE_L2TP
		for(it = IPACM_Iface::ipacmcfg->l2tp_client.begin();
			it != IPACM_Iface::ipacmcfg->l2tp_client.end() &&
			(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E); it++)
		{
			handle_l2tp_client_add(it->client_iface_name);
		}
#endif
	}
	else if(iptype == IPA_IP_v6)
	{
#ifdef FEATURE_VLAN_MPDN
		IPACM_Wan::num_v6_flt_rule = IPACM_Wan::ipv6_mpdn_default_filterting_rules_count;
#else
		IPACM_Wan::num_v6_flt_rule = m_ipv6_default_filterting_rules_count[0];
#endif
#ifdef FEATURE_L2TP
		if(active_v4 && (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E))
		{
			IPACM_Wan::num_v6_flt_rule += IPACM_Iface::ipacmcfg->l2tp_client.size();
		}
#endif
#ifdef FEATURE_VLAN_MPDN
		if(IPACM_FAILURE == add_icmp_alg_rules(pdn_flt_rule_v6, IPACM_Wan::num_v6_flt_rule, IPA_IP_v6))
#else
		if(IPACM_FAILURE == add_icmp_alg_rules(flt_rule_v6, IPACM_Wan::num_v6_flt_rule, IPA_IP_v6))
#endif
		{
			IPACMERR("Failed to add ICMP and ALG port filtering rules.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACMDBG_H("Succeded in constructing ICMP/ALG rules for ip type %d\n", iptype);

#ifdef FEATURE_VLAN_MPDN
		if(IPACM_FAILURE == config_dft_firewall_rules_ex(pdn_flt_rule_v6, IPACM_Wan::num_v6_flt_rule, IPA_IP_v6,isPmipv6))
#else
		if(IPACM_FAILURE == config_dft_firewall_rules_ex(flt_rule_v6, IPACM_Wan::num_v6_flt_rule, IPA_IP_v6,isPmipv6))
#endif
		{
			IPACMERR("Failed to add firewall filtering rules.\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACMDBG_H("Succeded in constructing firewall rules for ip type %d\n", iptype);
	}
	else
	{
		IPACMERR("IP type is not expected.\n");
		return IPACM_FAILURE;
	}

fail:
	return res;
}

#ifdef FEATURE_VLAN_MPDN
int IPACM_Wan::add_dft_filtering_rule(ipacm_pdn_flt_rule *rules, int rule_offset, ipa_ip_type iptype)
#else
int IPACM_Wan::add_dft_filtering_rule(struct ipa_flt_rule_add *rules, int rule_offset, ipa_ip_type iptype)
#endif
{
	struct ipa_ioc_get_rt_tbl_indx rt_tbl_idx;
	struct ipa_flt_rule_add flt_rule_entry;
	struct ipa_ioc_generate_flt_eq flt_eq;
	int res = IPACM_SUCCESS;

	IPACMDBG_H("ip-type: %d\n", iptype);

	if(rules == NULL)
	{
		IPACMERR("No filtering table available.\n");
		return IPACM_FAILURE;
	}
	if(rx_prop == NULL)
	{
		IPACMERR("No tx property.\n");
		return IPACM_FAILURE;
	}

	if (iptype == IPA_IP_v4)
	{
		memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
		strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_wan_dl.name, IPA_RESOURCE_NAME_MAX);
		rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
		rt_tbl_idx.ip = iptype;
		if(0 != ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx))
		{
			IPACMERR("Failed to get routing table index from name\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		IPACMDBG_H("Routing table %s has index %d\n", rt_tbl_idx.name, rt_tbl_idx.idx);

		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

		flt_rule_entry.at_rear = true;
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;

		flt_rule_entry.rule.retain_hdr = 1;
		flt_rule_entry.rule.to_uc = 0;
		flt_rule_entry.rule.eq_attrib_type = 1;
		flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#ifdef FEATURE_IPA_V3
		flt_rule_entry.rule.hashable = true;
#endif
		flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;

		IPACMDBG_H("rx property attrib mask:0x%x\n", rx_prop->rx[0].attrib.attrib_mask);

		/* Configuring Multicast Filtering Rule */
		memcpy(&flt_rule_entry.rule.attrib,
					 &rx_prop->rx[0].attrib,
					 sizeof(flt_rule_entry.rule.attrib));
		/* remove meta data mask since we only install default flt rules once for all modem PDN*/
		flt_rule_entry.rule.attrib.attrib_mask &= ~((uint32_t)IPA_FLT_META_DATA);
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
		flt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0xF0000000;
		flt_rule_entry.rule.attrib.u.v4.dst_addr = 0xE0000000;

		change_to_network_order(IPA_IP_v4, &flt_rule_entry.rule.attrib);

		memset(&flt_eq, 0, sizeof(flt_eq));
		memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
		flt_eq.ip = iptype;
		if(0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
		{
			IPACMERR("Failed to get eq_attrib\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		memcpy(&flt_rule_entry.rule.eq_attrib,
					 &flt_eq.eq_attrib,
					 sizeof(flt_rule_entry.rule.eq_attrib));
#ifdef FEATURE_VLAN_MPDN
		/* default rules are not metadata dependant - mux_id is not relevant */
		rules[rule_offset].mux_id = 0;
		memcpy(&(rules[rule_offset].flt_rule), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#else
		memcpy(&(rules[rule_offset]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#endif

		/* Configuring Broadcast Filtering Rule */
		flt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
		flt_rule_entry.rule.attrib.u.v4.dst_addr = 0xFFFFFFFF;

		change_to_network_order(IPA_IP_v4, &flt_rule_entry.rule.attrib);

		memset(&flt_eq, 0, sizeof(flt_eq));
		memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
		flt_eq.ip = iptype;
		if(0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
		{
			IPACMERR("Failed to get eq_attrib\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		memcpy(&flt_rule_entry.rule.eq_attrib,
					 &flt_eq.eq_attrib,
					 sizeof(flt_rule_entry.rule.eq_attrib));
#ifdef FEATURE_VLAN_MPDN
		/* default rules are not metadata dependant - mux_id is not relevant */
		rules[rule_offset + 1].mux_id = 0;
		memcpy(&(rules[rule_offset + 1].flt_rule), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#else
		memcpy(&(rules[rule_offset + 1]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#endif

		/* Always adding tcp syn SW-exception rule for MSS clamping support */
		IPACMDBG_H("Add v4 TCP sync rules\n");
		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
		flt_rule_entry.at_rear = true;
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;
		flt_rule_entry.rule.hashable = false;
		flt_rule_entry.rule.retain_hdr = 1;
		flt_rule_entry.rule.to_uc = 0;
		flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
		flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;
		flt_rule_entry.rule.eq_attrib_type = 1;
		flt_rule_entry.rule.eq_attrib.rule_eq_bitmap = 0;

		flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<1);
		flt_rule_entry.rule.eq_attrib.protocol_eq_present = 1;
		flt_rule_entry.rule.eq_attrib.protocol_eq = IPACM_FIREWALL_IPPROTO_TCP;
		flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<8);
		flt_rule_entry.rule.eq_attrib.num_ihl_offset_meq_32 = 1;
		flt_rule_entry.rule.eq_attrib.ihl_offset_meq_32[0].offset = 12;

		/* add TCP SYN rule*/
		flt_rule_entry.rule.eq_attrib.ihl_offset_meq_32[0].value = (((uint32_t)1)<<TCP_SYN_SHIFT);
		flt_rule_entry.rule.eq_attrib.ihl_offset_meq_32[0].mask = (((uint32_t)1)<<TCP_SYN_SHIFT);

#ifdef FEATURE_VLAN_MPDN
		rules[rule_offset + 2].mux_id = 0;
		memcpy(&(rules[rule_offset + 2].flt_rule),
		&flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#else
		memcpy(&(rules[rule_offset + 2]),
		&flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#endif
		IPACM_Wan::num_v4_flt_rule += IPA_V2_NUM_DEFAULT_WAN_FILTER_RULE_IPV4;
		IPACMDBG_H("Constructed DEBUG tcp\n");
		IPACMDBG_H("Constructed %d default filtering rules for ip type %d\n", IPACM_Wan::num_v4_flt_rule, iptype);
	}
	else	/*insert rules for ipv6*/
	{
		m_ipv6_default_filterting_rules_count[0] = 0;
		memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
		strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_wan_dl.name, IPA_RESOURCE_NAME_MAX);
		rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
		rt_tbl_idx.ip = iptype;
		if(0 != ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx))
		{
			IPACMERR("Failed to get routing table index from name\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		IPACMDBG_H("Routing table %s has index %d\n", rt_tbl_idx.name, rt_tbl_idx.idx);

		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

		flt_rule_entry.at_rear = true;
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;

		flt_rule_entry.rule.retain_hdr = 1;
		flt_rule_entry.rule.to_uc = 0;
		flt_rule_entry.rule.eq_attrib_type = 1;
		flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;

		IPACMDBG_H("rx property attrib mask:0x%x\n", rx_prop->rx[0].attrib.attrib_mask);

		flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;

		if (ipacmcfg->IsIpv6CTEnabled())
		{
			/* Configuring Fragment Filtering Rule */
#ifdef FEATURE_IPA_V3
			flt_rule_entry.rule.hashable = false;
#endif
			memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[0].attrib, sizeof(flt_rule_entry.rule.attrib));
			/* remove meta data mask since we only install default flt rules once for all modem PDN*/
			flt_rule_entry.rule.attrib.attrib_mask &= ~((uint32_t)IPA_FLT_META_DATA);
			flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_FRAGMENT;

			change_to_network_order(IPA_IP_v6, &flt_rule_entry.rule.attrib);

			memset(&flt_eq, 0, sizeof(flt_eq));
			memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
			flt_eq.ip = iptype;
			if (ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
			{
				IPACMERR("Failed to get eq_attrib\n");
				res = IPACM_FAILURE;
				goto fail;
			}

			memcpy(&flt_rule_entry.rule.eq_attrib, &flt_eq.eq_attrib, sizeof(flt_rule_entry.rule.eq_attrib));
#ifdef FEATURE_VLAN_MPDN
			/* default rules are not metadata dependant - mux_id is not relevant */
			rules[rule_offset + m_ipv6_default_filterting_rules_count[0]].mux_id = 0;
			memcpy(&(rules[rule_offset + m_ipv6_default_filterting_rules_count[0]++].flt_rule),
				&flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#else
			memcpy(&(rules[rule_offset + m_ipv6_default_filterting_rules_count[0]++]),
				&flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#endif
		}

#ifdef FEATURE_IPA_V3
		flt_rule_entry.rule.hashable = true;
#endif

		/* Configuring Multicast Filtering Rule */
		memcpy(&flt_rule_entry.rule.attrib,
					 &rx_prop->rx[0].attrib,
					 sizeof(flt_rule_entry.rule.attrib));
		/* remove meta data mask since we only install default flt rules once for all modem PDN*/
		flt_rule_entry.rule.attrib.attrib_mask &= ~((uint32_t)IPA_FLT_META_DATA);
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFF000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = 0xFF000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = 0x00000000;

		change_to_network_order(IPA_IP_v6, &flt_rule_entry.rule.attrib);

		memset(&flt_eq, 0, sizeof(flt_eq));
		memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
		flt_eq.ip = iptype;
		if(0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
		{
			IPACMERR("Failed to get eq_attrib\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		memcpy(&flt_rule_entry.rule.eq_attrib,
					 &flt_eq.eq_attrib,
					 sizeof(flt_rule_entry.rule.eq_attrib));
#ifdef FEATURE_VLAN_MPDN
		/* default rules are not metadata dependant - mux_id is not relevant */
		rules[rule_offset + m_ipv6_default_filterting_rules_count[0]].mux_id = 0;
		memcpy(&(rules[rule_offset + m_ipv6_default_filterting_rules_count[0]++].flt_rule),
			&flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#else
		memcpy(&(rules[rule_offset + m_ipv6_default_filterting_rules_count[0]++]),
			&flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#endif

		/* Configuring fe80::/10 Link-Scoped Unicast Filtering Rule */
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFC00000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = 0xFE800000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = 0x00000000;

		change_to_network_order(IPA_IP_v6, &flt_rule_entry.rule.attrib);

		memset(&flt_eq, 0, sizeof(flt_eq));
		memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
		flt_eq.ip = iptype;
		if(0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
		{
			IPACMERR("Failed to get eq_attrib\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		memcpy(&flt_rule_entry.rule.eq_attrib,
					 &flt_eq.eq_attrib,
					 sizeof(flt_rule_entry.rule.eq_attrib));

#ifdef FEATURE_VLAN_MPDN
		/* default rules are not metadata dependant - mux_id is not relevant */
		rules[rule_offset + m_ipv6_default_filterting_rules_count[0]].mux_id = 0;
		memcpy(&(rules[rule_offset + m_ipv6_default_filterting_rules_count[0]++].flt_rule),
			&flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#else
		memcpy(&(rules[rule_offset + m_ipv6_default_filterting_rules_count[0]++]),
			&flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#endif

		/* Configuring fec0::/10 Reserved by IETF Filtering Rule */
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFC00000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = 0xFEC00000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = 0x00000000;
		flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = 0x00000000;

		change_to_network_order(IPA_IP_v6, &flt_rule_entry.rule.attrib);

		memset(&flt_eq, 0, sizeof(flt_eq));
		memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
		flt_eq.ip = iptype;
		if(0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
		{
			IPACMERR("Failed to get eq_attrib\n");
			res = IPACM_FAILURE;
			goto fail;
		}

		memcpy(&flt_rule_entry.rule.eq_attrib,
					 &flt_eq.eq_attrib,
					 sizeof(flt_rule_entry.rule.eq_attrib));

#ifdef FEATURE_VLAN_MPDN
		/* default rules are not metadata dependant - mux_id is not relevant */
		rules[rule_offset + m_ipv6_default_filterting_rules_count[0]].mux_id = 0;
		memcpy(&(rules[rule_offset + m_ipv6_default_filterting_rules_count[0]++].flt_rule),
			&flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#else
		memcpy(&(rules[rule_offset + m_ipv6_default_filterting_rules_count[0]++]),
			&flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#endif

		/* Always adding tcp syn SW-exception rule for MSS clamping support */
		IPACMDBG_H("Add TCP sync rules\n");
		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

		flt_rule_entry.at_rear = true;
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;

		flt_rule_entry.rule.retain_hdr = 1;
		flt_rule_entry.rule.to_uc = 0;
		flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
		flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;
		flt_rule_entry.rule.eq_attrib_type = 1;

		flt_rule_entry.rule.eq_attrib.rule_eq_bitmap = 0;

#ifdef FEATURE_EoGRE
		if(IPACM_Iface::ipacmcfg->eogre_enabled)
		{
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<1);
			flt_rule_entry.rule.eq_attrib.protocol_eq_present = 1;
			flt_rule_entry.rule.eq_attrib.protocol_eq = IPACM_FIREWALL_IPPROTO_TCP;
		}
		else
#endif
		{
			flt_rule_entry.rule.eq_attrib.protocol_eq = IPACM_FIREWALL_IPPROTO_TCP;
			flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= 0x20<<flt_rule_entry.rule.eq_attrib.num_offset_meq_32;
			flt_rule_entry.rule.eq_attrib.offset_meq_32[flt_rule_entry.rule.eq_attrib.num_offset_meq_32].offset = 6;
			flt_rule_entry.rule.eq_attrib.offset_meq_32[flt_rule_entry.rule.eq_attrib.num_offset_meq_32].mask = 0xFF000000;
			flt_rule_entry.rule.eq_attrib.offset_meq_32[flt_rule_entry.rule.eq_attrib.num_offset_meq_32].value = 6 << 24;
			flt_rule_entry.rule.eq_attrib.num_offset_meq_32 ++;
		}

		flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= (1<<8);
		flt_rule_entry.rule.eq_attrib.num_ihl_offset_meq_32 = 1;
		flt_rule_entry.rule.eq_attrib.ihl_offset_meq_32[0].offset = 12;

		/* add TCP SYN rule*/
		flt_rule_entry.rule.eq_attrib.ihl_offset_meq_32[0].value = (((uint32_t)1)<<TCP_SYN_SHIFT);
		flt_rule_entry.rule.eq_attrib.ihl_offset_meq_32[0].mask = (((uint32_t)1)<<TCP_SYN_SHIFT);
		memcpy(&(rules[rule_offset + m_ipv6_default_filterting_rules_count[0]++]),
			&flt_rule_entry, sizeof(struct ipa_flt_rule_add));

#if defined(FEATURE_IPA_ANDROID)
		IPACMDBG_H("Add TCP other ctrl rules\n");

		/* add TCP FIN rule*/
		flt_rule_entry.rule.eq_attrib.ihl_offset_meq_32[0].value = (((uint32_t)1)<<TCP_FIN_SHIFT);
		flt_rule_entry.rule.eq_attrib.ihl_offset_meq_32[0].mask = (((uint32_t)1)<<TCP_FIN_SHIFT);
		memcpy(&(rules[rule_offset + m_ipv6_default_filterting_rules_count[0]++]),
			&flt_rule_entry, sizeof(struct ipa_flt_rule_add));

		/* add TCP RST rule*/
		flt_rule_entry.rule.eq_attrib.ihl_offset_meq_32[0].value = (((uint32_t)1)<<TCP_RST_SHIFT);
		flt_rule_entry.rule.eq_attrib.ihl_offset_meq_32[0].mask = (((uint32_t)1)<<TCP_RST_SHIFT);
		memcpy(&(rules[rule_offset + m_ipv6_default_filterting_rules_count[0]++]),
			&flt_rule_entry, sizeof(struct ipa_flt_rule_add));
#endif

		IPACM_Wan::num_v6_flt_rule += m_ipv6_default_filterting_rules_count[0];
#ifdef FEATURE_VLAN_MPDN
		/**
		 * store the default filtering rules count since on each WAN IFACE construction
		 * this variable is zeroed, but it is incremented only at this init function which is called with the first pdn
		 */
		IPACM_Wan::ipv6_mpdn_default_filterting_rules_count = m_ipv6_default_filterting_rules_count[0];
#endif
		IPACMDBG_H("Constructed %d default filtering rules for ip type %d\n",
			m_ipv6_default_filterting_rules_count[0], iptype);
	}

fail:
	return res;
}

int IPACM_Wan::del_wan_firewall_rule(ipa_ip_type iptype)
{
	list<l2tp_client_info>::iterator it;
	if(iptype == IPA_IP_v4)
	{
		IPACM_Wan::num_v4_flt_rule = IPA_V2_NUM_DEFAULT_WAN_FILTER_RULE_IPV4;
#ifdef FEATURE_VLAN_MPDN
		memset(&IPACM_Wan::pdn_flt_rule_v4[IPA_V2_NUM_DEFAULT_WAN_FILTER_RULE_IPV4], 0,
			(IPA_MAX_FLT_RULE - IPA_V2_NUM_DEFAULT_WAN_FILTER_RULE_IPV4) * sizeof(struct ipacm_pdn_flt_rule));
#else
		memset(&IPACM_Wan::flt_rule_v4[IPA_V2_NUM_DEFAULT_WAN_FILTER_RULE_IPV4], 0,
			(IPA_MAX_FLT_RULE - IPA_V2_NUM_DEFAULT_WAN_FILTER_RULE_IPV4) * sizeof(struct ipa_flt_rule_add));
#endif
#ifdef FEATURE_L2TP
		for(it = IPACM_Iface::ipacmcfg->l2tp_client.begin(); it != IPACM_Iface::ipacmcfg->l2tp_client.end() &&
			(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E); it++)
		{
			handle_l2tp_client_del(it->client_iface_name);
		}
#endif
	}
	else if(iptype == IPA_IP_v6)
	{
#ifdef FEATURE_VLAN_MPDN
		IPACM_Wan::num_v6_flt_rule = IPACM_Wan::ipv6_mpdn_default_filterting_rules_count;
#else
		IPACM_Wan::num_v6_flt_rule = m_ipv6_default_filterting_rules_count[0];
#endif
#ifdef FEATURE_L2TP
		if(active_v4 && (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E))
		{
			IPACM_Wan::num_v6_flt_rule += IPACM_Iface::ipacmcfg->l2tp_client.size();
		}
#endif
#ifdef FEATURE_VLAN_MPDN
		memset(&IPACM_Wan::pdn_flt_rule_v6[IPACM_Wan::num_v6_flt_rule], 0,
			(IPA_MAX_FLT_RULE - IPACM_Wan::num_v6_flt_rule) * sizeof(struct ipacm_pdn_flt_rule));
#else
		memset(&IPACM_Wan::flt_rule_v6[IPACM_Wan::num_v6_flt_rule], 0,
			(IPA_MAX_FLT_RULE - IPACM_Wan::num_v6_flt_rule) * sizeof(struct ipa_flt_rule_add));
#endif
	}
	else
	{
		IPACMERR("IP type is not expected.\n");
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

/*for STA mode: clean firewall filter rules */
int IPACM_Wan::del_dft_firewall_rules(ipa_ip_type iptype, bool wan_up_vlan)
{
	/* free v4 firewall filter rule */
	if (rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	if (((iptype == IPA_IP_v4) && (active_v4 == true)) || ((iptype == IPA_IP_v4) && wan_up_vlan))
	{
		if (num_firewall_v4 > IPACM_MAX_FIREWALL_ENTRIES)
		{
			IPACMERR("the number of v4 firewall entries overflow, aborting...\n");
			return IPACM_FAILURE;
		}
		if (num_firewall_v4 != 0)
		{
			if (m_filtering.DeleteFilteringHdls(firewall_hdl_v4, IPA_IP_v4, num_firewall_v4) == false)
			{
				IPACMERR("Error Deleting Filtering rules, aborting...\n");
				return IPACM_FAILURE;
			}
			for(int i = 0; i < num_firewall_v4; i++)
				firewall_hdl_v4[i] = 0;
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v4, num_firewall_v4);
		}
		else
		{
			IPACMDBG_H("No ipv4 firewall rules, no need deleted\n");
		}

		if (m_filtering.DeleteFilteringHdls(&dft_wan_fl_hdl[0], IPA_IP_v4, 1) == false)
		{
			IPACMERR("Error Deleting Filtering rules, aborting...\n");
			return IPACM_FAILURE;
		}
		dft_wan_fl_hdl[0] = 0;
		if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable && is_ppp_iface)
		{
			pppoe_route_rule_hdl_v4 = 0;
			IPACMDBG_H("deleted flt rule pppoe_route_rule_hdl_v4=0x%x \n",pppoe_route_rule_hdl_v4);
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v4, 1);

		num_firewall_v4 = 0;
	}

	/* free v6 firewall filter rule */
	if (((iptype == IPA_IP_v6) && (active_v6 == true)) || ((iptype == IPA_IP_v6) && wan_up_vlan))
	{
#ifndef FEATURE_IPV6_NAT
		if(IPACM_Iface::ipacmcfg->ipv6_nat_enable)
		{
			IPACMDBG_H("IPv6 NAT is enable. No change needed for firewall rules\n");
			return IPACM_SUCCESS;
		}
#endif
		if (num_firewall_v6 > IPACM_MAX_FIREWALL_ENTRIES)
		{
			IPACMERR("the number of v6 firewall entries overflow, aborting...\n");
			return IPACM_FAILURE;
		}
		if (num_firewall_v6 != 0)
		{
			if (m_filtering.DeleteFilteringHdls(firewall_hdl_v6,
				IPA_IP_v6, num_firewall_v6) == false)
			{
				IPACMERR("Error Deleting Filtering rules, aborting...\n");
				return IPACM_FAILURE;
			}
			for(int i = 0; i < num_firewall_v6; i++)
				firewall_hdl_v6[i] = 0;
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, num_firewall_v6);
		}
		else
		{
			IPACMDBG_H("No ipv6 firewall rules, no need deleted\n");
		}
#ifdef FEATURE_IPV6_NAT
		if(IPACM_Iface::ipacmcfg->ipv6_nat_enable)
		{
			if(m_filtering.DeleteFilteringHdls(&ipv6_ula_prefix_hdl, IPA_IP_v6, 1) == false)
			{
				IPACMERR("Error Deleting Filtering rules, aborting...\n");
				return IPACM_FAILURE;
			}
			ipv6_ula_prefix_hdl = 0;
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);
		}
#endif
		if (m_filtering.DeleteFilteringHdls(&dft_wan_fl_hdl[1], IPA_IP_v6, 1) == false)
		{
			IPACMERR("Error Deleting Filtering rules, aborting...\n");
			return IPACM_FAILURE;
		}
		dft_wan_fl_hdl[1] = 0;
		if(is_ppp_iface)
		{
			pppoe_route_rule_hdl_v6 = 0;
			IPACMDBG_H("deleted flt rule pppoe_route_rule_hdl_v6=0x%x \n",pppoe_route_rule_hdl_v6);
		}
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);

		if (m_filtering.DeleteFilteringHdls(&dft_wan_fl_hdl[2], IPA_IP_v6, 1) == false)
		{
			IPACMERR("Error Deleting Filtering rules, aborting...\n");
			return IPACM_FAILURE;
		}
		dft_wan_fl_hdl[2] = 0;
		IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);

		if (is_ipv6_frag_firewall_flt_rule_installed)
		{
			if (m_filtering.DeleteFilteringHdls(&ipv6_frag_firewall_flt_rule_hdl, IPA_IP_v6, 1) == false)
			{
				IPACMERR("Error deleting IPv6 frag filtering rules.\n");
				return IPACM_FAILURE;
			}
			ipv6_frag_firewall_flt_rule_hdl = 0;
			is_ipv6_frag_firewall_flt_rule_installed = false;
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);
		}
		num_firewall_v6 = 0;
	}

	return IPACM_SUCCESS;
}

/* for STA mode: wan default route/filter rule delete */
int IPACM_Wan::handle_route_del_evt(ipa_ip_type iptype, bool wan_up_vlan)
{
	uint32_t tx_index;
	ipacm_cmd_q_data evt_data;

	IPACMDBG_H("got handle_route_del_evt for STA-mode with ip-family:%d \n", iptype);

	if(tx_prop == NULL)
	{
		IPACMDBG_H("No tx properties, ignore delete default route setting\n");
		return IPACM_SUCCESS;
	}
	is_default_gateway = false;
	IPACMDBG_H("Default route is deleted to iface %s.\n", dev_name);

	// Delete route rule in case of default route or if vlan is up on-demand PDN
	if (((iptype == IPA_IP_v4) && (active_v4 == true)) ||
			((iptype == IPA_IP_v6) && (active_v6 == true)) || wan_up_vlan)
	{
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Delete corresponding ipa_rm_resource_name of TX-endpoint after delete IPV4/V6 RT-rule */
			IPACMDBG_H("dev %s delete producer dependency\n", dev_name);
			IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			IPACM_Iface::ipacmcfg->DelRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
		}
		for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		{
		    if(iptype != tx_prop->tx[tx_index].ip)
		    {
		    	IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d, no RT-rule deleted\n",
		    					    tx_index, tx_prop->tx[tx_index].ip,iptype);
		    	continue;
		    }

			if (iptype == IPA_IP_v4)
			{
				if(sta_ipv4_pdn_index >= 0 && ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan == false)
				{
		    		IPACMDBG_H("Tx:%d, ip-type: %d match ip-type: %d, RT-rule deleted\n", tx_index, tx_prop->tx[tx_index].ip,iptype);

					if (m_routing.DeleteRoutingHdl(wan_route_rule_v4_hdl[tx_index], IPA_IP_v4) == false)
					{
						IPACMDBG_H("IP-family:%d, Routing rule(hdl:0x%x) deletion failed with tx_index %d!\n", IPA_IP_v4, wan_route_rule_v4_hdl[tx_index], tx_index);
						return IPACM_FAILURE;
					}
					else
					{
						wan_route_rule_v4_hdl[tx_index] = 0;
					}
				}
				else
				{
					IPACMDBG_H("STA v4 vlan wan up don't delete rule\n");
				}
			}
			else
			{
				if(sta_ipv6_pdn_index >= 0 && ipv6_to_iface[sta_ipv6_pdn_index].wan_up_vlan_v6 == false)
				{
		    		IPACMDBG_H("Tx:%d, ip-type: %d match ip-type: %d, RT-rule deleted\n", tx_index, tx_prop->tx[tx_index].ip,iptype);

					if (m_routing.DeleteRoutingHdl(wan_route_rule_v6_hdl[tx_index], IPA_IP_v6) == false)
					{
						IPACMDBG_H("IP-family:%d, Routing rule(hdl:0x%x) deletion failed with tx_index %d!\n", IPA_IP_v6, wan_route_rule_v6_hdl[tx_index], tx_index);
						return IPACM_FAILURE;
					}
					else
					{
						wan_route_rule_v6_hdl[tx_index] = 0;
					}
				}
				else
				{
					IPACMDBG_H("STA v6 vlan wan up don't delete rule\n");
				}
			}
		}

		/* Delete the default wan route*/
		if (iptype == IPA_IP_v6)
		{
		   	IPACMDBG_H("ip-type %d: default v6 wan RT-rule deleted\n",iptype);
			if (m_routing.DeleteRoutingHdl(wan_route_rule_lan_v6_hdl_a5, IPA_IP_v6) == false)
			{
			IPACMDBG_H("IP-family:%d, Routing rule(hdl:0x%x) deletion failed!\n",IPA_IP_v6,wan_route_rule_lan_v6_hdl_a5);
				return IPACM_FAILURE;
			}
			else
			{
				wan_route_rule_lan_v6_hdl_a5 = 0;
			}
		}
		if(wan_up_vlan)
		{
			IPACMDBG_H("Don't post IPA_HANDLE_WAN_DOWN event if vlan id on demand PDN\n");
			IPACM_Iface::ipacmcfg->del_vlan_ipv6_prefix(ipv6_prefix, -1);
			return IPACM_SUCCESS;
		}
		ipacm_event_iface_up *wandown_data;
		wandown_data = (ipacm_event_iface_up *)malloc(sizeof(ipacm_event_iface_up));
		if (wandown_data == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			return IPACM_FAILURE;
		}
		memset(wandown_data, 0, sizeof(ipacm_event_iface_up));

		if (iptype == IPA_IP_v4)
		{
			wandown_data->ipv4_addr = (public_wan_v4_addr_set) ? public_wan_v4_addr : wan_v4_addr;
			if (m_is_sta_mode!=Q6_WAN)
			{
				wandown_data->is_sta = true;
			}
			else
			{
				wandown_data->is_sta = false;
			}
			evt_data.event = IPA_HANDLE_WAN_DOWN;
			evt_data.evt_data = (void *)wandown_data;
			/* Insert IPA_HANDLE_WAN_DOWN to command queue */
			IPACMDBG_H("posting IPA_HANDLE_WAN_DOWN for IPv4 (%d.%d.%d.%d) \n",
					(unsigned char)(wandown_data->ipv4_addr),
					(unsigned char)(wandown_data->ipv4_addr >> 8),
					(unsigned char)(wandown_data->ipv4_addr >> 16),
					(unsigned char)(wandown_data->ipv4_addr >> 24));

			IPACM_EvtDispatcher::PostEvt(&evt_data);
			IPACMDBG_H("setup wan_up/active_v4= false \n");
			IPACM_Wan::wan_up = false;
			active_v4 = false;
			if(IPACM_Wan::wan_up_v6)
			{
				IPACMDBG_H("modem v6-call still up(%s), not reset\n", IPACM_Wan::wan_up_dev_name);
			}
			else
			{
				memset(IPACM_Wan::wan_up_dev_name, 0, sizeof(IPACM_Wan::wan_up_dev_name));
			}
		}
		else
		{
			if (m_is_sta_mode!=Q6_WAN)
			{
				wandown_data->is_sta = true;
			}
			else
			{
				wandown_data->is_sta = false;
			}
			memcpy(wandown_data->ipv6_prefix, ipv6_prefix, sizeof(wandown_data->ipv6_prefix));
			memcpy(wandown_data->ipv6_addr, m_ipv6_addr, sizeof(wandown_data->ipv6_addr));
#ifdef FEATURE_VLAN_MPDN
			IPACM_Iface::ipacmcfg->del_vlan_ipv6_prefix(ipv6_prefix, -1);
#endif
			evt_data.event = IPA_HANDLE_WAN_DOWN_V6;
			evt_data.evt_data = (void *)wandown_data;
			/* Insert IPA_HANDLE_WAN_DOWN to command queue */
			IPACMDBG_H("posting IPA_HANDLE_WAN_DOWN for IPv6 with prefix 0x%08x%08x\n", ipv6_prefix[0], ipv6_prefix[1]);
			IPACM_EvtDispatcher::PostEvt(&evt_data);
			IPACMDBG_H("setup wan_up_v6/active_v6= false \n");
			IPACM_Wan::wan_up_v6 = false;
			active_v6 = false;
			if(IPACM_Wan::wan_up)
			{
				IPACMDBG_H("modem v4-call still up(%s), not reset\n", IPACM_Wan::wan_up_dev_name);
			}
			else
			{
				memset(IPACM_Wan::wan_up_dev_name, 0, sizeof(IPACM_Wan::wan_up_dev_name));
			}
		}
	}
	else
	{
		IPACMDBG_H(" The default WAN routing rules are deleted already \n");
	}

	return IPACM_SUCCESS;
}

int IPACM_Wan::handle_route_del_evt_ex(ipa_ip_type iptype)
{
	ipacm_cmd_q_data evt_data;
	struct wan_ioctl_notify_wan_state wan_state;
	int fd_wwan_ioctl;
	memset(&wan_state, 0, sizeof(wan_state));

	IPACMDBG_H("got handle_route_del_evt_ex with ip-family:%d \n", iptype);

	if(tx_prop == NULL)
	{
		IPACMDBG_H("No tx properties, ignore delete default route setting\n");
		return IPACM_SUCCESS;
	}

	IPACMDBG_H("Default route is deleted to iface %s.\n", dev_name);

#ifdef FEATURE_STATIC_POLICY
	if(IPACM_Iface::ipacmcfg->ipacm_static_policy_enable)
	{
		IPACMDBG_H("Static policy feature is enabled, dont handle default route deletion for %s.\n",
			dev_name);
		return IPACM_SUCCESS;
	}
#endif

	if (((iptype == IPA_IP_v4) && (active_v4 == true)) ||
		((iptype == IPA_IP_v6) && (active_v6 == true)))
	{
#ifdef FEATURE_VLAN_MPDN
		if( !isVlanWanUP() && !isVlanWanUP_V6() )
#endif
	{
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Delete corresponding ipa_rm_resource_name of TX-endpoint after delete IPV4/V6 RT-rule */
			IPACMDBG_H("dev %s delete producer dependency\n", dev_name);
			IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			IPACM_Iface::ipacmcfg->DelRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
		} else {
			IPACMDBG_H("ipa_pm_q6_check to %d\n", ipa_pm_q6_check);
			if(ipa_pm_q6_check == 1)
			{
				fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
				if(fd_wwan_ioctl < 0)
				{
					IPACMERR("Failed to open %s.\n",WWAN_QMI_IOCTL_DEVICE_NAME);
					return false;
				}
				IPACMDBG_H("send WAN_IOC_NOTIFY_WAN_STATE down to IPA_PM\n");
				if(ioctl(fd_wwan_ioctl, WAN_IOC_NOTIFY_WAN_STATE, &wan_state))
				{
					IPACMERR("Failed to send WAN_IOC_NOTIFY_WAN_STATE as up %d\n ", wan_state.up);
				}
				close(fd_wwan_ioctl);
			}
			if (ipa_pm_q6_check > 0)
				ipa_pm_q6_check--;
			else
				IPACMERR(" ipa_pm_q6_check becomes negative !!!\n");
		}
	}
#ifdef FEATURE_VLAN_MPDN
	else
	{
		IPACMDBG_H("not deleting rm depend for default rt, a VLAN PDN is still up, iptype %d\n", iptype);
	}
#endif
		/* Delete the default route*/
		if (iptype == IPA_IP_v6)
		{
#ifdef FEATURE_VLAN_MPDN
			if(!isVlanWanUP_V6())
#endif
			{
				if(wan_route_rule_wan_v6_hdl_a5)
				{
					IPACMDBG_H("ip-type %d: default v6 wan RT-rule deleted\n",iptype);
					if (m_routing.DeleteRoutingHdl(wan_route_rule_wan_v6_hdl_a5, IPA_IP_v6) == false)
					{
						IPACMDBG_H("IP-family:%d, Routing rule(hdl:0x%x) deletion failed!\n",IPA_IP_v6,wan_route_rule_wan_v6_hdl_a5);
						return IPACM_FAILURE;
					}
					else
					{
						wan_route_rule_wan_v6_hdl_a5 = 0;
					}
				}
			}
#ifdef FEATURE_VLAN_MPDN
			else
			{
				IPACMDBG_H("not deleting default v6 RT rule, vlan v6 PDN is up\n");
			}
#endif
		}
		ipacm_event_iface_up *wandown_data;
		wandown_data = (ipacm_event_iface_up *)malloc(sizeof(ipacm_event_iface_up));
		if (wandown_data == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			return IPACM_FAILURE;
		}
		memset(wandown_data, 0, sizeof(ipacm_event_iface_up));

		if (iptype == IPA_IP_v4)
		{
			if (public_wan_v4_addr_set)
				wandown_data->ipv4_addr = public_wan_v4_addr;
			else
				wandown_data->ipv4_addr = wan_v4_addr;
			if (m_is_sta_mode!=Q6_WAN)
			{
				wandown_data->is_sta = true;
			}
			else
			{
				wandown_data->is_sta = false;
				wandown_data->mux_id = ext_prop->ext[0].mux_id;
			}
			evt_data.event = IPA_HANDLE_WAN_DOWN;
			evt_data.evt_data = (void *)wandown_data;
			/* Insert IPA_HANDLE_WAN_DOWN to command queue */
			IPACMDBG_H("posting IPA_HANDLE_WAN_DOWN for IPv4 with address: 0x%x\n", wan_v4_addr);
			IPACM_EvtDispatcher::PostEvt(&evt_data);

			IPACMDBG_H("setup wan_up/active_v4= false \n");
			IPACM_Wan::wan_up = false;
			active_v4 = false;
			if(IPACM_Wan::wan_up_v6)
			{
				IPACMDBG_H("modem v6-call still up(%s), not reset\n", IPACM_Wan::wan_up_dev_name);
			}
			else
			{
				memset(IPACM_Wan::wan_up_dev_name, 0, sizeof(IPACM_Wan::wan_up_dev_name));
				is_default_gateway = false;
			}
		}
		else
		{
			if (m_is_sta_mode!=Q6_WAN)
			{
				wandown_data->is_sta = true;
			}
			else
			{
				wandown_data->is_sta = false;
				wandown_data->mux_id = ext_prop->ext[0].mux_id;
			}

			memcpy(wandown_data->ipv6_addr, m_ipv6_addr, sizeof(wandown_data->ipv6_addr));
#ifdef FEATURE_VLAN_MPDN
			if (is_xlat)
				IPACM_Iface::ipacmcfg->del_vlan_ipv6_prefix(ipv6_prefix, -1, true);
			else
				IPACM_Iface::ipacmcfg->del_vlan_ipv6_prefix(ipv6_prefix, -1);
#endif
			evt_data.event = IPA_HANDLE_WAN_DOWN_V6;
			evt_data.evt_data = (void *)wandown_data;
			IPACMDBG_H("posting IPA_HANDLE_WAN_DOWN_V6 for IPv6 with prefix 0x%08x%08x\n", wandown_data->ipv6_addr[0], wandown_data->ipv6_addr[1]);
			IPACM_EvtDispatcher::PostEvt(&evt_data);

			IPACMDBG_H("setup wan_up_v6/active_v6= false \n");
			IPACM_Wan::wan_up_v6 = false;
			active_v6 = false;
			if(IPACM_Wan::wan_up)
			{
				IPACMDBG_H("modem v4-call still up(%s), not reset\n", IPACM_Wan::wan_up_dev_name);
			}
			else
			{
				memset(IPACM_Wan::wan_up_dev_name, 0, sizeof(IPACM_Wan::wan_up_dev_name));
				is_default_gateway = false;
			}
		}
	}
	else
	{
		IPACMDBG_H(" The default WAN routing rules are deleted already \n");
	}

	return IPACM_SUCCESS;
}

/* configure the initial embms filter rules */
int IPACM_Wan::config_dft_embms_rules(ipa_ioc_add_flt_rule *pFilteringTable_v4, ipa_ioc_add_flt_rule *pFilteringTable_v6)
{
	struct ipa_flt_rule_add flt_rule_entry;
	struct ipa_ioc_get_rt_tbl_indx rt_tbl_idx;
	struct ipa_ioc_generate_flt_eq flt_eq;

	if (rx_prop == NULL)
	{
		IPACMDBG("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	if(pFilteringTable_v4 == NULL || pFilteringTable_v6 == NULL)
	{
		IPACMERR("Either v4 or v6 filtering table is empty.\n");
		return IPACM_FAILURE;
	}

	/* set up ipv4 odu rule*/
	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

	/* get eMBMS ODU tbl index*/
	memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
	strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_odu_v4.name, IPA_RESOURCE_NAME_MAX);
	rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
	rt_tbl_idx.ip = IPA_IP_v4;
	if(0 != ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx))
	{
		IPACMERR("Failed to get routing table index from name\n");
		return IPACM_FAILURE;
	}
	IPACMDBG_H("Odu routing table %s has index %d\n", rt_tbl_idx.name, rt_tbl_idx.idx);

	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;
	flt_rule_entry.at_rear = false;

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.eq_attrib_type = 1;
	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#ifdef FEATURE_IPA_V3
	flt_rule_entry.rule.hashable = true;
#endif
	flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;

	memcpy(&flt_rule_entry.rule.attrib,
				 &rx_prop->rx[0].attrib,
				 sizeof(struct ipa_rule_attrib));
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
	flt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0x00000000;
	flt_rule_entry.rule.attrib.u.v4.dst_addr = 0x00000000;

	memset(&flt_eq, 0, sizeof(flt_eq));
	memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
	flt_eq.ip = IPA_IP_v4;
	if(0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
	{
		IPACMERR("Failed to get eq_attrib\n");
		return IPACM_FAILURE;
	}
	memcpy(&flt_rule_entry.rule.eq_attrib,
				 &flt_eq.eq_attrib,
				 sizeof(flt_rule_entry.rule.eq_attrib));

	memcpy(&(pFilteringTable_v4->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));

	/* construc v6 rule */
	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
	/* get eMBMS ODU tbl*/
	memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
	strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_odu_v6.name, IPA_RESOURCE_NAME_MAX);
	rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
	rt_tbl_idx.ip = IPA_IP_v6;
	if(0 != ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx))
	{
		IPACMERR("Failed to get routing table index from name\n");
		return IPACM_FAILURE;
	}
	IPACMDBG_H("Odu routing table %s has index %d\n", rt_tbl_idx.name, rt_tbl_idx.idx);

	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;
	flt_rule_entry.at_rear = false;

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.eq_attrib_type = 1;
	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#ifdef FEATURE_IPA_V3
	flt_rule_entry.rule.hashable = true;
#endif
	flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;

	memcpy(&flt_rule_entry.rule.attrib,
				 &rx_prop->rx[0].attrib,
				 sizeof(struct ipa_rule_attrib));
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = 0X00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = 0X00000000;

	memset(&flt_eq, 0, sizeof(flt_eq));
	memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
	flt_eq.ip = IPA_IP_v6;
	if(0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
	{
		IPACMERR("Failed to get eq_attrib\n");
		return IPACM_FAILURE;
	}
	memcpy(&flt_rule_entry.rule.eq_attrib,
				 &flt_eq.eq_attrib,
				 sizeof(flt_rule_entry.rule.eq_attrib));

	memcpy(&(pFilteringTable_v6->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));

	return IPACM_SUCCESS;
}

#ifdef FEATURE_SOCKSv5
/* configure the socksv5 dl rules */
int IPACM_Wan::config_socksv5_rules(ipa_ioc_add_flt_rule *pFilteringTable_v6)
{
	struct ipa_flt_rule_add flt_rule_entry;
	struct ipa_ioc_get_rt_tbl_indx rt_tbl_idx;
	struct ipa_ioc_generate_flt_eq flt_eq;
	int i = 0, pdn_ipv6_in_use_chk = 0;

	if (rx_prop == NULL)
	{
		IPACMDBG("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	if(pFilteringTable_v6 == NULL)
	{
		IPACMERR("v6 filtering table is empty.\n");
		return IPACM_FAILURE;
	}


	/* construc v6-socksv5 client rule */
	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
	memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
	strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, IPA_RESOURCE_NAME_MAX);
	rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
	rt_tbl_idx.ip = IPA_IP_v6;
	if(0 != ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx))
	{
		IPACMERR("Failed to get routing table index from name\n");
		return IPACM_FAILURE;
	}
	IPACMDBG_H("v6wan routing table %s has index %d\n", rt_tbl_idx.name, rt_tbl_idx.idx);

	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;
	flt_rule_entry.at_rear = false;

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.eq_attrib_type = 1;
	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#ifdef FEATURE_IPA_V3
	flt_rule_entry.rule.hashable = true;
#endif
	flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;

	memcpy(&flt_rule_entry.rule.attrib,
				 &rx_prop->rx[0].attrib,
				 sizeof(struct ipa_rule_attrib));
	/* remove meta data mask since we only install default flt rules once for all modem PDN*/
	flt_rule_entry.rule.attrib.attrib_mask &= ~((uint32_t)IPA_FLT_META_DATA);
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = htonl(IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[0]);
	flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = htonl(IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[1]);
	flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = htonl(IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[2]);
	flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = htonl(IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[3]);
	IPACMDBG_H(" socksv5_client_v6_addr: 0x%X:%X:%X:%X \n", IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[0],
	IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[1], IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[2], IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[3]);

	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_NEXT_HDR;
	flt_rule_entry.rule.attrib.u.v6.next_hdr = (uint8_t)IPACM_FIREWALL_IPPROTO_TCP;

	memset(&flt_eq, 0, sizeof(flt_eq));
	memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
	flt_eq.ip = IPA_IP_v6;
	if(0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
	{
		IPACMERR("Failed to get eq_attrib\n");
		return IPACM_FAILURE;
	}
	memcpy(&flt_rule_entry.rule.eq_attrib,
				 &flt_eq.eq_attrib,
				 sizeof(flt_rule_entry.rule.eq_attrib));

	memcpy(&(pFilteringTable_v6->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));

	/* construc v6-socksv5 DL filter rule */
	for (i=0; i < IPACM_Iface::ipacmcfg->socksv5_v6_pdn; i++)
	{
		/* ref count >0, currently used*/
		if (IPACM_Iface::ipacmcfg->pdn_ipv6_in_use[i] > 0)
		{
			pdn_ipv6_in_use_chk ++;
			IPACMDBG_H(" pdn_ipv6_in_use ind:%d 0x%X:%X:%X:%X,total %d\n",
				IPACM_Iface::ipacmcfg->pdn_ipv6_in_use[i],
				IPACM_Iface::ipacmcfg->pdn_ipv6[i][0],
				IPACM_Iface::ipacmcfg->pdn_ipv6[i][1],
				IPACM_Iface::ipacmcfg->pdn_ipv6[i][2],
				IPACM_Iface::ipacmcfg->pdn_ipv6[i][3],
				pdn_ipv6_in_use_chk);

			flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = htonl(IPACM_Iface::ipacmcfg->pdn_ipv6[i][0]);
			flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = htonl(IPACM_Iface::ipacmcfg->pdn_ipv6[i][1]);
			flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = htonl(IPACM_Iface::ipacmcfg->pdn_ipv6[i][2]);
			flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = htonl(IPACM_Iface::ipacmcfg->pdn_ipv6[i][3]);
			flt_rule_entry.rule.action = IPA_PASS_TO_SRC_NAT;
			flt_rule_entry.rule.rt_tbl_idx = 0;
			memset(&flt_eq, 0, sizeof(flt_eq));
			memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
			flt_eq.ip = IPA_IP_v6;
			if(0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
			{
				IPACMERR("Failed to get eq_attrib\n");
				return IPACM_FAILURE;
			}
			memcpy(&flt_rule_entry.rule.eq_attrib,
						&flt_eq.eq_attrib,
						sizeof(flt_rule_entry.rule.eq_attrib));
			if (pdn_ipv6_in_use_chk <= IPACM_Iface::ipacmcfg->total_pdn_ipv6_in_use)
			{
				IPACMDBG_H(" pdn_ipv6_in_use_chk %d,total %d\n", pdn_ipv6_in_use_chk, IPACM_Iface::ipacmcfg->total_pdn_ipv6_in_use);
				memcpy(&(pFilteringTable_v6->rules[pdn_ipv6_in_use_chk]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
			}
			else
			{
				IPACMERR("pdn_ipv6_in_use_chk %d > total %d, not adding rule\n", pdn_ipv6_in_use_chk, IPACM_Iface::ipacmcfg->total_pdn_ipv6_in_use);
			}
		}
	}

	return IPACM_SUCCESS;
}
#endif

/*for STA mode: handle wan-iface down event */
int IPACM_Wan::handle_down_evt()
{
	int res = IPACM_SUCCESS;
	int i;
#ifdef FEATURE_DUAL_BACKHAUL
	bool isSecondBackhaul;
#endif

	IPACMDBG_H(" wan handle_down_evt \n");
	if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
	{
		/* Delete corresponding ipa_rm_resource_name of TX-endpoint after delete IPV4/V6 RT-rule */
		IPACMDBG_H("dev %s delete producer dependency\n", dev_name);
		if (tx_prop != NULL)
		{
			IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			IPACM_Iface::ipacmcfg->DelRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
		}
	}
	/* no iface address up, directly close iface*/
	if (ip_type == IPACM_IP_NULL)
	{
		goto fail;
	}

	/*Post v4 Vlan PDN_DOWN event if associated*/

	IPACMDBG_H("ip_type: %d\n", ip_type);

	IPACMDBG_H("sta_ipv4_pdn_index: %d ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan :%d\n", sta_ipv4_pdn_index, ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan);

	IPACMDBG_H(" STA wan ipv4-addr:0x%x\n", wan_v4_addr);

	if(ip_type == IPA_IP_v4)
	{
		num_ipv4_sta_pdn--;
		IPACMDBG_H("Now the number of STA ipv4 pdn is %d.\n", num_ipv4_sta_pdn);
	}
	else if(ip_type == IPA_IP_v6)
	{
		if(num_dft_rt_v6 > 1)
		{
			num_ipv6_sta_pdn--;
		}
		IPACMDBG_H("Now the number of STA ipv6 pdn is %d.\n", num_ipv6_sta_pdn);
	}
	else if(ip_type == IPA_IP_MAX)
	{
		num_ipv4_sta_pdn--;
		IPACMDBG_H("Now the number of STA ipv4 pdn is %d.\n", num_ipv4_sta_pdn);
		if (num_dft_rt_v6 > 1)
			num_ipv6_sta_pdn--;
		IPACMDBG_H("Now the number of STA ipv6 pdn is %d.\n", num_ipv6_sta_pdn);
	}

	if(ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan && ipv6_to_iface[sta_ipv6_pdn_index].wan_up_vlan_v6)
	{
		ipacm_cmd_q_data evt_data;
		ipacm_event_vlan_pdn *vlandown_data;

		ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan = false;
		ipv6_to_iface[sta_ipv6_pdn_index].wan_up_vlan_v6 = false;

		wan_v4_is_default_gw = true;
		wan_v6_is_default_gw = true;
		num_offloaded_pdns--;

		vlandown_data = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
		if(vlandown_data == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		memset(vlandown_data, 0, sizeof(ipacm_event_vlan_pdn));
		vlandown_data->iptype = IPA_IP_MAX;
		vlandown_data->ipv4_addr = wan_v4_addr;
		vlandown_data->VlanID = 0; /* Wan is down. setting this value to 0, to delete all rules. */
		memcpy(vlandown_data->ipv6_prefix, ipv6_to_iface[sta_ipv6_pdn_index].ipv6_prefix, sizeof(ipv6_to_iface[sta_ipv6_pdn_index].ipv6_prefix));
		memset(ipv4_to_iface[sta_ipv4_pdn_index].associated_VIDs, 0, sizeof(ipv4_to_iface[sta_ipv4_pdn_index].associated_VIDs));
		ipv4_to_iface[sta_ipv4_pdn_index].VID_cnt = 0;
		memset(ipv6_to_iface[sta_ipv6_pdn_index].associated_VIDs, 0, sizeof(ipv6_to_iface[sta_ipv6_pdn_index].associated_VIDs));
		ipv6_to_iface[sta_ipv6_pdn_index].VID_cnt = 0;
		vlandown_data->mux_id = 0;

		IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_DOWN with below information:\n");
		IPACMDBG_H("iptype V4 V6, VlanID %d, mux_id %d, if num %d\n", vlandown_data->VlanID, vlandown_data->mux_id, ipa_if_num);

		evt_data.event = IPA_HANDLE_WAN_VLAN_PDN_DOWN;
		evt_data.evt_data = (void *)vlandown_data;

		IPACM_EvtDispatcher::PostEvt(&evt_data);
	}
	else if(sta_ipv6_pdn_index >= 0 && ipv6_to_iface[sta_ipv6_pdn_index].wan_up_vlan_v6)
	{
		ipacm_cmd_q_data evt_data;
		ipacm_event_vlan_pdn *vlandown_data;

		ipv6_to_iface[sta_ipv6_pdn_index].wan_up_vlan_v6 = false;

		wan_v6_is_default_gw = true;
		if (sta_ipv4_pdn_index == -1)
			num_offloaded_pdns--;

		vlandown_data = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
		if(vlandown_data == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		memset(vlandown_data, 0, sizeof(ipacm_event_vlan_pdn));

		vlandown_data->iptype = IPA_IP_v6;
		vlandown_data->VlanID = 0; /* Wan is down. setting this value to 0, to delete all rules. */
		memcpy(vlandown_data->ipv6_prefix, ipv6_to_iface[sta_ipv6_pdn_index].ipv6_prefix, sizeof(ipv6_to_iface[sta_ipv6_pdn_index].ipv6_prefix));
		memset(ipv6_to_iface[sta_ipv6_pdn_index].associated_VIDs, 0, sizeof(ipv6_to_iface[sta_ipv6_pdn_index].associated_VIDs));
		ipv6_to_iface[sta_ipv6_pdn_index].VID_cnt = 0;
		vlandown_data->mux_id = 0;

		IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_DOWN (v6) with below information:\n");
		IPACMDBG_H("iptype IPA_IP_v6, VlanID %d, mux_id %d, if num %d\n", vlandown_data->VlanID, vlandown_data->mux_id, ipa_if_num);

		evt_data.event = IPA_HANDLE_WAN_VLAN_PDN_DOWN;
		evt_data.evt_data = (void *)vlandown_data;

		IPACM_EvtDispatcher::PostEvt(&evt_data);
	}
	else if (sta_ipv4_pdn_index >= 0 && ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan)
	{
		ipacm_cmd_q_data evt_data;
		ipacm_event_vlan_pdn *vlandown_data;

		ipv4_to_iface[sta_ipv4_pdn_index].wan_up_vlan = false;
		wan_v4_is_default_gw = true;
		if (sta_ipv6_pdn_index == -1)
			num_offloaded_pdns--;

		vlandown_data = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
		if(vlandown_data == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		memset(vlandown_data, 0, sizeof(ipacm_event_vlan_pdn));

		vlandown_data->iptype = IPA_IP_v4;
		vlandown_data->VlanID = 0; /* Wan is down. setting this value to 0, to delete all rules. */
		vlandown_data->ipv4_addr = wan_v4_addr;
		memset(ipv4_to_iface[sta_ipv4_pdn_index].associated_VIDs, 0, sizeof(ipv4_to_iface[sta_ipv4_pdn_index].associated_VIDs));
		ipv4_to_iface[sta_ipv4_pdn_index].VID_cnt = 0;
		vlandown_data->mux_id = 0;

		IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_DOWN with below information:\n");
		IPACMDBG_H("iptype IPA_IP_v4, VlanID %d, mux_id %d, if num %d\n", vlandown_data->VlanID, vlandown_data->mux_id, ipa_if_num);

		evt_data.event = IPA_HANDLE_WAN_VLAN_PDN_DOWN;
		evt_data.evt_data = (void *)vlandown_data;

		IPACM_EvtDispatcher::PostEvt(&evt_data);
	}
	else
	{
		IPACMDBG_H("Not Any vlan is Up..:\n");
	}

	/* make sure default routing rules and firewall rules are deleted*/
	if (active_v4)
	{
		if (rx_prop != NULL)
		{
			del_dft_firewall_rules(IPA_IP_v4);
		}
		handle_route_del_evt(IPA_IP_v4);
		IPACMDBG_H("Delete default v4 routing rules\n");
	}
	else if (ip_type == IPA_IP_v4 || ip_type == IPA_IP_MAX)
	{
		if (rx_prop != NULL)
		{
			del_dft_firewall_rules(IPA_IP_v4, true);
		}
		if(handle_route_del_evt(IPA_IP_v4, true))
		{
			IPACMDBG_H("Route Del event for v4 failed\n");
		}
		IPACMDBG_H("Delete default v4 routing rules vlan case\n");
	}

	if (active_v6)
	{
		if (rx_prop != NULL)
		{
			del_dft_firewall_rules(IPA_IP_v6);
		}
		handle_route_del_evt(IPA_IP_v6);
		IPACMDBG_H("Delete default v6 routing rules\n");
	}
	else if (ip_type == IPA_IP_v6 || ip_type == IPA_IP_MAX)
	{
		if (rx_prop != NULL)
		{
			del_dft_firewall_rules(IPA_IP_v6, true);
		}
		if(handle_route_del_evt(IPA_IP_v6, true))
		{
			IPACMDBG_H("Route Del event for v6 failed\n");
		}
		IPACMDBG_H("Delete default v6 routing rules vlan case\n");
	}

#ifdef FEATURE_DUAL_BACKHAUL
	isSecondBackhaul=IPACM_Wan::second_backhaul_active &&
		IPACM_Wan::second_backhaul_ipv4 == wan_v4_addr;

	if(isSecondBackhaul){
		if (rx_prop != NULL)
		{
			del_dft_firewall_rules(IPA_IP_v4);
		}
		IPACM_Wan::second_backhaul_active=false;
		IPACM_Wan::second_backhaul_ipv4=0;
	}
#endif
	/* Delete default v4 RT rule */
	if (ip_type != IPA_IP_v6)
	{
		IPACMDBG_H("Delete default v4 routing rules\n");
		if (m_routing.DeleteRoutingHdl(dft_rt_rule_hdl[0], IPA_IP_v4) == false)
		{
		   IPACMERR("Routing rule deletion failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		ipv4_to_iface[sta_ipv4_pdn_index].ipv4_addr = 0;
		ipv4_to_iface[sta_ipv4_pdn_index].pIface = NULL;
		sta_ipv4_pdn_index = -1;
		dft_rt_rule_hdl[0] = 0;
#ifdef FEATURE_IPA_IPSEC
		/* Delete default IPsec v4 RT rules */
		IPACMDBG_H("Delete IPsec default v4 routing rules\n");
		if (del_ipsec_wan_dl_rt_rules(IPA_IP_v4) == IPACM_FAILURE)
		{
			IPACMERR("Routing old IPsec RT rules deletion failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
#endif
	}

	/* delete default v6 RT rule */
	if (ip_type != IPA_IP_v4)
	{
		IPACMDBG_H("Delete default v6 routing rules\n");
		/* May have multiple ipv6 iface-routing rules*/
		for (i = 0; i < 2*num_dft_rt_v6; i++)
		{
			if (m_routing.DeleteRoutingHdl(dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES+i], IPA_IP_v6) == false)
			{
				IPACMERR("Routing rule deletion failed!\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES+i] = 0;
		}
#ifdef FEATURE_IPA_IPSEC
		/* Delete default IPsec v6 RT rules */
		IPACMDBG_H("Delete IPsec default v6 routing rules\n");
		if (del_ipsec_wan_dl_rt_rules(IPA_IP_v6) == IPACM_FAILURE)
		{
			IPACMERR("Routing old IPsec RT rules deletion failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
#endif
		ipv6_to_iface[sta_ipv6_pdn_index].pIface = NULL;
		memset(&ipv6_to_iface[sta_ipv6_pdn_index].ipv6_prefix, 0, sizeof(uint32_t) * 2);
		sta_ipv6_pdn_index = -1;
		IPACMDBG_H("finished delete default v6 RT rules\n ");
	}


	/* clean wan-client header, routing rules */
	IPACMDBG_H("left %d wan clients need to be deleted \n ", num_wan_client);
	for (i = 0; i < num_wan_client; i++)
	{
		/* Del NAT rules before RT rules are delete */
		HandleSTAClientDelEvt(get_client_memptr(wan_client, i), i);

		if (delete_wan_rtrules(i, IPA_IP_v4))
		{
			IPACMERR("unbale to delete wan-client v4 route rules for index %d\n", i);
			res = IPACM_FAILURE;
			goto fail;
		}

		if (delete_wan_rtrules(i, IPA_IP_v6))
		{
			IPACMERR("unable to delete ecm-client v6 route rules for index %d\n", i);
			res = IPACM_FAILURE;
			goto fail;
		}

		IPACMDBG_H("Delete %d out of %d client header\n", i,  num_wan_client);

		if (get_client_memptr(wan_client, i)->ipv4_header_set == true)
		{
			if (m_header.DeleteHeaderHdl(get_client_memptr(wan_client, i)->hdr_hdl_v4)
				== false)
			{
				res = IPACM_FAILURE;
				goto fail;
			}
		}

		if (get_client_memptr(wan_client, i)->ipv6_header_set == true)
		{
			if (m_header.DeleteHeaderHdl(get_client_memptr(wan_client, i)->hdr_hdl_v6)
				== false)
			{
				res = IPACM_FAILURE;
				goto fail;
			}
		}


		IPACMDBG_H("client %d has %d ipv6 with rt: %d, current total_v6=%d \n", i,
			get_client_memptr(wan_client, i)->ipv6_set,
			get_client_memptr(wan_client, i)->route_rule_set_v6,
			IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);

		/* clean up the map and release the memory */
		for (auto it = rt_hdl_v6_list[i].begin(); it != rt_hdl_v6_list[i].end();++it)
		{
			IPACMDBG_H("v6 addr : 0x%08x:%08x:%08x:%08x\n", it->first[0], it->first[1], it->first[2], it->first[3]);
		}
		IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6 -= get_client_memptr(wan_client, i)->ipv6_set;
		IPACMDBG_H("update ipa_num_clients_ipv6 = %d\n", IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
		get_client_memptr(wan_client, i)->ipv6_set = 0;
		/* clear the map */
		rt_hdl_v6_list[i].clear();
	} /* end of for loop */

	/* free the edm clients cache */
	IPACMDBG_H("Free wan clients cache\n");

#ifdef FEATURE_PPPOE
	if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable && is_ppp_iface)
	{
		pppoe_del_hdr_proc_ctx(ip_type);
	}
#endif

	/* check software routing fl rule hdl */
	if (softwarerouting_act == true)
	{
		handle_software_routing_disable();
	}

	/* free dft ipv4 filter rule handlers if any */
	if (ip_type != IPA_IP_v6 && rx_prop != NULL && num_ipv4_sta_pdn == 0)
	{
		res = delete_dflt_filter_rules(IPA_IP_v4);
		if (res == IPACM_FAILURE)
		{
			IPACMERR("delete_dflt_filter_rules failed\n");
			goto fail;
		}
	}

	/* free dft ipv6 filter rule handlers if any */
	if (ip_type != IPA_IP_v4 && rx_prop != NULL && num_ipv6_sta_pdn == 0)
	{
		res = delete_dflt_filter_rules(IPA_IP_v6);
		if (res == IPACM_FAILURE)
		{
			IPACMERR("delete_dflt_filter_rules failed\n");
			goto fail;
		}

		if(num_ipv6_dest_flt_rule > 0 && num_ipv6_dest_flt_rule <= MAX_DEFAULT_v6_ROUTE_RULES)
		{
			if(m_filtering.DeleteFilteringHdls(ipv6_dest_flt_rule_hdl,  IPA_IP_v6, num_ipv6_dest_flt_rule) == false)
			{
				IPACMERR("Failed to delete ipv6 dest flt rules.\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, num_ipv6_dest_flt_rule);
			memset(ipv6_dest_flt_rule_hdl, 0, MAX_DEFAULT_v6_ROUTE_RULES*sizeof(uint32_t));
			num_ipv6_dest_flt_rule = 0;
		}
		IPACMDBG_H("finished delete default v6 filtering rules\n ");
	}
	if(hdr_proc_hdl_dummy_v6)
	{
		if(m_header.DeleteHeaderProcCtx(hdr_proc_hdl_dummy_v6) == false)
		{
			IPACMERR("Failed to delete hdr_proc_hdl_dummy_v6\n");
			res = IPACM_FAILURE;
			goto fail;
		}
	}
	if(hdr_hdl_dummy_v6)
	{
		if (m_header.DeleteHeaderHdl(hdr_hdl_dummy_v6) == false)
		{
			IPACMERR("Failed to delete hdr_hdl_dummy_v6\n");
			res = IPACM_FAILURE;
			goto fail;
		}
	}
fail:
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
	if (wan_route_rule_v4_hdl != NULL)
	{
		free(wan_route_rule_v4_hdl);
		wan_route_rule_v4_hdl = NULL;
	}
	if (wan_route_rule_v6_hdl != NULL)
	{
		free(wan_route_rule_v6_hdl);
		wan_route_rule_v6_hdl = NULL;
	}
	if (wan_client != NULL)
	{
		free(wan_client);
		wan_client = NULL;
	}
	close(m_fd_ipa);
	return res;
}

int IPACM_Wan::handle_down_evt_ex()
{
	int res = IPACM_SUCCESS;
	int i, tether_total;
	int ipa_if_num_tether_tmp[IPA_MAX_IFACE_ENTRIES];
	uint32_t dummy_prefix[2];
	bool xlat_cfg = false;

	IPACMDBG_H(" wan handle_down_evt \n");

	/* free ODU filter rule handlers */
	if(IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].if_cat == EMBMS_IF)
	{
		embms_is_on = false;
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Delete corresponding ipa_rm_resource_name of TX-endpoint after delete IPV4/V6 RT-rule */
			IPACMDBG_H("dev %s delete producer dependency\n", dev_name);
			if (tx_prop != NULL)
			{
				IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
				IPACM_Iface::ipacmcfg->DelRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			}
		}
		if (rx_prop != NULL)
		{
			install_wan_filtering_rule(false);
			IPACMDBG("finished delete embms filtering rule\n ");
		}
		goto fail;
	}

	/* no iface address up, directly close iface*/
	if (ip_type == IPACM_IP_NULL)
	{
		goto fail;
	}

#ifndef IPA_MTU_EVENT_MAX
	/* reset the mtu size */
	mtu_v4 = DEFAULT_MTU_SIZE;
	mtu_v4_set = false;
	mtu_v6 = DEFAULT_MTU_SIZE;
	mtu_v6_set = false;
#endif
#ifdef FEATURE_IPoGRE
	if(IPACM_Iface::ipacmcfg->ipogre_enabled == true)
	{
		gre_down();
	}
#endif
	if(ip_type == IPA_IP_v4)
	{
		num_ipv4_modem_pdn--;
		IPACMDBG_H("Now the number of modem ipv4 pdn is %d.\n", num_ipv4_modem_pdn);
#ifdef FEATURE_VLAN_MPDN
		if((modem_ipv4_pdn_index >= 0) && (ipv4_to_iface[modem_ipv4_pdn_index].wan_up_vlan))
		{
			ipacm_cmd_q_data evt_data;
			ipacm_event_vlan_pdn *vlandown_data;

			//post multiple WAN DOWNS if there are multiple clients associated with the PDN
			if (ipv4_to_iface[modem_ipv4_pdn_index].VID_cnt)
			{
				for (i = 0; i < ipv4_to_iface[modem_ipv4_pdn_index].VID_cnt; i++)
				{
					vlandown_data = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
					if(vlandown_data == NULL)
					{
						IPACMERR("Unable to allocate memory\n");
						res = IPACM_FAILURE;
						goto fail;
					}
					memset(vlandown_data, 0, sizeof(ipacm_event_vlan_pdn));

					vlandown_data->iptype = IPA_IP_v4;
					vlandown_data->VlanID = associated_VID; //this should just be array
					vlandown_data->ipv4_addr = (public_wan_v4_addr_set) ? public_wan_v4_addr : wan_v4_addr;
					vlandown_data->mux_id = ext_prop->ext[0].mux_id;
					vlandown_data->VlanID =
						ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs[i];
					IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_DOWN with below information:\n");
					IPACMDBG_H("iptype IPA_IP_v4, VlanID %d, mux_id %d, if num %d\n",
						vlandown_data->VlanID, ext_prop->ext[0].mux_id, ipa_if_num);
					evt_data.event = IPA_HANDLE_WAN_VLAN_PDN_DOWN;
					evt_data.evt_data = (void *)vlandown_data;

					//the memory will be freed by handler of the evt
					IPACM_EvtDispatcher::PostEvt(&evt_data);
				}
			}
			else //remove this in future. Should always be consistent with array.
			{
				vlandown_data = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
				if(vlandown_data == NULL)
				{
					IPACMERR("Unable to allocate memory\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				memset(vlandown_data, 0, sizeof(ipacm_event_vlan_pdn));

				vlandown_data->iptype = IPA_IP_v4;
				vlandown_data->VlanID = associated_VID; //this should just be array
				vlandown_data->ipv4_addr = (public_wan_v4_addr_set) ? public_wan_v4_addr : wan_v4_addr;
				vlandown_data->mux_id = ext_prop->ext[0].mux_id;
				evt_data.event = IPA_HANDLE_WAN_VLAN_PDN_DOWN;
				evt_data.evt_data = (void *)vlandown_data;
				IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_DOWN with below information:\n");
				IPACMDBG_H("iptype IPA_IP_v4, VlanID %d, mux_id %d, if num %d\n",
					associated_VID, ext_prop->ext[0].mux_id, ipa_if_num);
				IPACM_EvtDispatcher::PostEvt(&evt_data);
			}

			ipv4_to_iface[modem_ipv4_pdn_index].wan_up_vlan = false;
			ipv4_to_iface[modem_ipv4_pdn_index].is_xlat = false;
			memset(ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs, 0, sizeof(ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs));
			ipv4_to_iface[modem_ipv4_pdn_index].VID_cnt = 0;

			num_offloaded_pdns--;
			IPACMDBG_H("now num offloaded PDNs is %d\n", num_offloaded_pdns);

			/* clear reserved slot for offloading v6 prefix */
			if (is_xlat) {
				dummy_prefix[0] = IPA_DUMMY_PREFIX;
				dummy_prefix[1] = IPA_DUMMY_PREFIX;
				IPACM_Iface::ipacmcfg->del_vlan_ipv6_prefix(dummy_prefix, -1);
				xlat_cfg = true;
			}

			/* in also default gateway, DL filtering rules will be reconfigured later */
			if(!is_default_gateway)
			{
				del_wan_firewall_rule(IPA_IP_v4);
				/* if there are still PDNs up we need to reconfigure firewall */
				if(isVlanWanUP() || wan_up)
				{
					config_wan_firewall_rule(IPA_IP_v4);
				}
				install_wan_filtering_rule(false);
			}
		}

		ipv4_to_iface[modem_ipv4_pdn_index].ipv4_addr = 0;
		ipv4_to_iface[modem_ipv4_pdn_index].pIface = NULL;

		/* if no PDN is up, remove rm dependencies */
		if(!isVlanWanUP() && !isVlanWanUP_V6() && !wan_up && !wan_up_v6)
		{
			if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
			{
				/* Delete corresponding ipa_rm_resource_name of TX-endpoint after delete IPV4/V6 RT-rule */
				IPACMDBG_H("dev %s delete producer dependency\n", dev_name);
				IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
				IPACM_Iface::ipacmcfg->DelRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			}
			else {
				IPACMDBG_H("ipa_pm_q6_check to %d\n", ipa_pm_q6_check);
				if(ipa_pm_q6_check == 1)
				{
					struct wan_ioctl_notify_wan_state wan_state;

					memset(&wan_state, 0, sizeof(wan_state));

					int fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
					if(fd_wwan_ioctl < 0)
					{
						IPACMERR("Failed to open %s.\n", WWAN_QMI_IOCTL_DEVICE_NAME);
						return false;
					}
					IPACMDBG_H("send WAN_IOC_NOTIFY_WAN_STATE down to IPA_PM\n");
					if(ioctl(fd_wwan_ioctl, WAN_IOC_NOTIFY_WAN_STATE, &wan_state))
					{
						IPACMERR("Failed to send WAN_IOC_NOTIFY_WAN_STATE as up %d\n ", wan_state.up);
					}
					close(fd_wwan_ioctl);
				}
				if(ipa_pm_q6_check > 0)
					ipa_pm_q6_check--;
				else
					IPACMERR(" ipa_pm_q6_check becomes negative !!!\n");
			}
		}
		else
		{
			IPACMDBG_H("not deleting rm depend for default rt, a v4 VLAN PDN is still up, iptype %d\n", ip_type);
		}
#endif
		/* only when default gw goes down we post WAN_DOWN event*/
		if(is_default_gateway == true)
		{
			IPACM_Wan::wan_up = false;
			del_wan_firewall_rule(IPA_IP_v4);
#ifdef FEATURE_VLAN_MPDN
			/* if there are still secondary PDNs up we need to reconfigure firewall */
			if(isVlanWanUP())
			{
				config_wan_firewall_rule(IPA_IP_v4);
			}
#endif
			install_wan_filtering_rule(false);
			handle_route_del_evt_ex(IPA_IP_v4);
#ifdef FEATURE_IPA_ANDROID
			/* posting wan_down_tether for all lan clients */
			for (i=0; i < IPACM_Wan::ipa_if_num_tether_v4_total; i++)
			{
				ipa_if_num_tether_tmp[i] = IPACM_Wan::ipa_if_num_tether_v4[i];
			}
			tether_total = IPACM_Wan::ipa_if_num_tether_v4_total;
			for (i=0; i < tether_total; i++)
			{
				post_wan_down_tether_evt(IPA_IP_v4, ipa_if_num_tether_tmp[i]);
				IPACMDBG_H("post_wan_down_tether_v4 iface(%d: %s)\n",
					i, IPACM_Iface::ipacmcfg->iface_table[ipa_if_num_tether_tmp[i]].iface_name);
			}
#endif
			if(IPACM_Wan::wan_up_v6)
			{
				IPACMDBG_H("modem v6-call still up(%s), not reset\n", IPACM_Wan::wan_up_dev_name);
			}
			else
			{
				memset(IPACM_Wan::wan_up_dev_name, 0, sizeof(IPACM_Wan::wan_up_dev_name));
			}
		}

		/* only when the last ipv4 modem interface goes down, delete ipv4 default flt rules*/
		if(num_ipv4_modem_pdn == 0)
		{
			IPACMDBG_H("Now the number of modem ipv4 interface is 0, delete default flt rules.\n");
			IPACM_Wan::num_v4_flt_rule = 0;
#ifdef FEATURE_VLAN_MPDN
			memset(IPACM_Wan::pdn_flt_rule_v4, 0, IPA_MAX_FLT_RULE * sizeof(struct ipacm_pdn_flt_rule));
#else
			memset(IPACM_Wan::flt_rule_v4, 0, IPA_MAX_FLT_RULE * sizeof(struct ipa_flt_rule_add));
#endif
			install_wan_filtering_rule(false);
#ifdef FEATURE_IPA_IPSEC
			IPACMDBG_H("Calling installWanPostIpsecRt(IPA_IP_v4)\n");
			if (installWanPostIpsecRt(IPA_IP_v4) != IPACM_SUCCESS)
				IPACMERR("installWanPostIpsecRt(IPA_IP_v4) failed\n");
#endif
		}

		IPACMDBG_H("Delete dft v4 rt rule\n");
		if (m_routing.DeleteRoutingHdl(dft_rt_rule_hdl[0], IPA_IP_v4) == false)
		{
			IPACMERR("Routing rule deletion failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		dft_rt_rule_hdl[0] = 0;
#ifdef FEATURE_IPA_IPSEC
		/* Delete default IPsec v4 RT rules */
		IPACMDBG_H("Delete IPsec default v4 routing rules\n");
		if (del_ipsec_wan_dl_rt_rules(IPA_IP_v4) == IPACM_FAILURE)
		{
			IPACMERR("Routing old IPsec RT rules deletion failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
#endif
	}
	if(ip_type == IPA_IP_v6 || xlat_cfg)
	{
		if(num_dft_rt_v6 > 1)
		{
			num_ipv6_modem_pdn--;
		}
		IPACMDBG_H("Now the number of modem ipv6 pdn is %d.\n", num_ipv6_modem_pdn);
		/* only when default gw goes down we post WAN_DOWN event*/

#ifdef FEATURE_VLAN_MPDN
		IPACM_Iface::ipacmcfg->del_vlan_ipv6_prefix(ipv6_prefix, -1);

		if((modem_ipv6_pdn_index >= 0) && ipv6_to_iface[modem_ipv6_pdn_index].wan_up_vlan_v6)
		{
			ipacm_cmd_q_data evt_data;
			ipacm_event_vlan_pdn *vlandown_data;

			/* Xlat cfg offload pdn count is updated during v4 handling */
			if (!xlat_cfg)
				num_offloaded_pdns--;

			IPACMDBG_H("now num offloaded PDNs is %d\n", num_offloaded_pdns);

			if(!isVlanWanUP_V6())
			{
				if(wan_route_rule_wan_v6_hdl_a5)
				{
					IPACMDBG_H("ip-type %d: default v6 wan RT-rule deleted\n", ip_type);
					if(m_routing.DeleteRoutingHdl(wan_route_rule_wan_v6_hdl_a5, IPA_IP_v6) == false)
					{
						IPACMDBG_H("IP-family:%d, Routing rule(hdl:0x%x) deletion failed!\n", IPA_IP_v6, wan_route_rule_wan_v6_hdl_a5);
						return IPACM_FAILURE;
					}
					else
					{
						wan_route_rule_wan_v6_hdl_a5 = 0;
					}
				}
			}
			else
			{
				IPACMDBG_H("not deleting default v6 RT rule, vlan v6 PDN is up\n");
			}

			if (ipv6_to_iface[modem_ipv6_pdn_index].VID_cnt)
			{
				for (i = 0; i < ipv6_to_iface[modem_ipv6_pdn_index].VID_cnt; i++)
				{
					vlandown_data = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
					if(vlandown_data == NULL)
					{
						IPACMERR("Unable to allocate memory\n");
						res = IPACM_FAILURE;
						goto fail;
					}
					memset(vlandown_data, 0, sizeof(ipacm_event_vlan_pdn));

					vlandown_data->iptype = IPA_IP_v6;
					vlandown_data->mux_id = ext_prop->ext[0].mux_id;
					vlandown_data->VlanID =
						ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[i];
					vlandown_data->ipv6_prefix[0] = ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[0];
					vlandown_data->ipv6_prefix[1] = ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[1];
					IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_DOWN with below information:\n");
					IPACMDBG_H("iptype IPA_IP_v6, VlanID %d, mux_id %d, if num %d ipv6 prefix 0x%08x:%08x\n\n",
						associated_VID, ext_prop->ext[0].mux_id, ipa_if_num, vlandown_data->ipv6_prefix[0],
						vlandown_data->ipv6_prefix[1]);
					evt_data.event = IPA_HANDLE_WAN_VLAN_PDN_DOWN;
					evt_data.evt_data = (void *)vlandown_data;

					//the memory will be freed by handler of the evt
					IPACM_EvtDispatcher::PostEvt(&evt_data);
				}
			}
			else //remove this in future. Should always be consistent with array.
			{
				vlandown_data = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
				if(vlandown_data == NULL)
				{
					IPACMERR("Unable to allocate memory\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				memset(vlandown_data, 0, sizeof(ipacm_event_vlan_pdn));

				vlandown_data->iptype = IPA_IP_v6;
				vlandown_data->VlanID = associated_VID; //this should just be array
				vlandown_data->mux_id = ext_prop->ext[0].mux_id;
				vlandown_data->ipv6_prefix[0] = ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[0];
				vlandown_data->ipv6_prefix[1] = ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix[1];
				evt_data.event = IPA_HANDLE_WAN_VLAN_PDN_DOWN;
				evt_data.evt_data = (void *)vlandown_data;
				IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_DOWN with below information:\n");
				IPACMDBG_H("iptype IPA_IP_v6, VlanID %d, mux_id %d, if num %d ipv6 prefix 0x%08x:%08x\n",
					associated_VID, ext_prop->ext[0].mux_id, ipa_if_num, vlandown_data->ipv6_prefix[0], vlandown_data->ipv6_prefix[1]);
				IPACM_EvtDispatcher::PostEvt(&evt_data);
			}

			ipv6_to_iface[modem_ipv6_pdn_index].wan_up_vlan_v6 = false;
			memset(ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs, 0, sizeof(ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs));
			ipv6_to_iface[modem_ipv6_pdn_index].VID_cnt = 0;

			/* in also default gateway, DL filtering rules will be reconfigured later */
			if(!is_default_gateway)
			{
				del_wan_firewall_rule(IPA_IP_v6);
				/* if there are still PDNs up we need to reconfigure firewall */
				if(isVlanWanUP_V6() || wan_up_v6)
				{
					config_wan_firewall_rule(IPA_IP_v6);
				}
				install_wan_filtering_rule(false);
			}
		}
		memset(&ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix, 0, sizeof(uint32_t) * 2);
		ipv6_to_iface[modem_ipv6_pdn_index].pIface = NULL;

		/* if no PDN is up, remove rm dependencies */
		if(!isVlanWanUP() && !isVlanWanUP_V6() && !wan_up && !wan_up_v6)
		{
			if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
			{
				/* Delete corresponding ipa_rm_resource_name of TX-endpoint after delete IPV4/V6 RT-rule */
				IPACMDBG_H("dev %s delete producer dependency\n", dev_name);
				IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
				IPACM_Iface::ipacmcfg->DelRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			}
			else {
				IPACMDBG_H("ipa_pm_q6_check to %d\n", ipa_pm_q6_check);
				if(ipa_pm_q6_check == 1)
				{
					struct wan_ioctl_notify_wan_state wan_state;

					memset(&wan_state, 0, sizeof(wan_state));

					int fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
					if(fd_wwan_ioctl < 0)
					{
						IPACMERR("Failed to open %s.\n", WWAN_QMI_IOCTL_DEVICE_NAME);
						return false;
					}
					IPACMDBG_H("send WAN_IOC_NOTIFY_WAN_STATE down to IPA_PM\n");
					if(ioctl(fd_wwan_ioctl, WAN_IOC_NOTIFY_WAN_STATE, &wan_state))
					{
						IPACMERR("Failed to send WAN_IOC_NOTIFY_WAN_STATE as up %d\n ", wan_state.up);
					}
					close(fd_wwan_ioctl);
				}
				if(ipa_pm_q6_check > 0)
					ipa_pm_q6_check--;
				else
					IPACMERR(" ipa_pm_q6_check becomes negative !!!\n");
			}
		}
		else
		{
			IPACMDBG_H("not deleting rm depend for default rt, a v6 VLAN PDN is still up, iptype %d\n", ip_type);
		}
#endif
		//Note: check for static policy xlat case, if we need to do
		if(is_default_gateway == true)
		{
			IPACM_Wan::wan_up_v6 = false;
			del_wan_firewall_rule(IPA_IP_v6);
#ifdef FEATURE_VLAN_MPDN
			/* if there are still secondary PDNs up we need to reconfigure firewall */
			if(isVlanWanUP_V6())
			{
				config_wan_firewall_rule(IPA_IP_v6);
			}
#endif
			install_wan_filtering_rule(false);
			handle_route_del_evt_ex(IPA_IP_v6);
#ifdef FEATURE_IPA_ANDROID
			/* posting wan_down_tether for all lan clients */
			for (i=0; i < IPACM_Wan::ipa_if_num_tether_v6_total; i++)
			{
				ipa_if_num_tether_tmp[i] = IPACM_Wan::ipa_if_num_tether_v6[i];
			}
			tether_total = IPACM_Wan::ipa_if_num_tether_v6_total;
			for (i=0; i < tether_total; i++)
			{
				post_wan_down_tether_evt(IPA_IP_v6, ipa_if_num_tether_tmp[i]);
				IPACMDBG_H("post_wan_down_tether_v6 iface(%d: %s)\n",
					i, IPACM_Iface::ipacmcfg->iface_table[ipa_if_num_tether_tmp[i]].iface_name);
			}
#endif
			if(IPACM_Wan::wan_up)
			{
				IPACMDBG_H("modem v4-call still up(%s), not reset\n", IPACM_Wan::wan_up_dev_name);
			}
			else
			{
				memset(IPACM_Wan::wan_up_dev_name, 0, sizeof(IPACM_Wan::wan_up_dev_name));
			}
		}

		/* only when the last ipv6 modem interface goes down, delete ipv6 default flt rules*/
		if(num_ipv6_modem_pdn == 0)
		{
			IPACMDBG_H("Now the number of modem ipv6 interface is 0, delete default flt rules.\n");
			IPACM_Wan::num_v6_flt_rule = 0;
#ifdef FEATURE_VLAN_MPDN
			IPACM_Wan::ipv6_mpdn_default_filterting_rules_count = 0;
			memset(IPACM_Wan::pdn_flt_rule_v6, 0, IPA_MAX_FLT_RULE * sizeof(struct ipacm_pdn_flt_rule));
#else
			memset(IPACM_Wan::flt_rule_v6, 0, IPA_MAX_FLT_RULE * sizeof(struct ipa_flt_rule_add));
#endif
			install_wan_filtering_rule(false);
#ifdef FEATURE_IPA_IPSEC
			IPACMDBG_H("Calling installWanPostIpsecRt(IPA_IP_v6)\n");
			if (installWanPostIpsecRt(IPA_IP_v6) != IPACM_SUCCESS)
				IPACMERR("installWanPostIpsecRt(IPA_IP_v6) failed\n");
#endif

			/* clean the ipv6 wan-route rule hdl for v6_wan_table */
			if (wan_route_rule_wan_v6_hdl_a5 != 0)
			{
				IPACMDBG_H("Delete ipv6 default v6 wan RT-rule 0x%x\n", wan_route_rule_wan_v6_hdl_a5);
				if (m_routing.DeleteRoutingHdl(wan_route_rule_wan_v6_hdl_a5, IPA_IP_v6) == false)
				{
					IPACMDBG_H("IP-family:%d, Routing rule(hdl:0x%x) deletion failed!\n",IPA_IP_v6,wan_route_rule_wan_v6_hdl_a5);
					return IPACM_FAILURE;
				}
				wan_route_rule_wan_v6_hdl_a5 = 0;
			}
		}

		IPACMDBG_H("Delete dft v6 rt rule\n");
		for (i = 0; i < 2*num_dft_rt_v6; i++)
		{
			if (m_routing.DeleteRoutingHdl(dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES+i], IPA_IP_v6) == false)
			{
				IPACMERR("Routing rule deletion failed!\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES+i] = 0;
		}
#ifdef FEATURE_IPA_IPSEC
		/* Delete default IPsec v6 RT rules */
		IPACMDBG_H("Delete IPsec default v6 routing rules\n");
		if (del_ipsec_wan_dl_rt_rules(IPA_IP_v6) == IPACM_FAILURE)
		{
			IPACMERR("Routing old IPsec RT rules deletion failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
#endif
	}
	if (ip_type == IPA_IP_MAX)
	{
		num_ipv4_modem_pdn--;
		IPACMDBG_H("Now the number of modem ipv4 pdn is %d.\n", num_ipv4_modem_pdn);
		if (num_dft_rt_v6 > 1)
			num_ipv6_modem_pdn--;
		IPACMDBG_H("Now the number of modem ipv6 pdn is %d.\n", num_ipv6_modem_pdn);

#ifdef FEATURE_VLAN_MPDN
		IPACM_Iface::ipacmcfg->del_vlan_ipv6_prefix(ipv6_prefix, -1);

		if(ipv4_to_iface[modem_ipv4_pdn_index].wan_up_vlan ||
			ipv6_to_iface[modem_ipv6_pdn_index].wan_up_vlan_v6)
		{
			ipacm_cmd_q_data evt_data;
			ipacm_event_vlan_pdn *vlandown_data;

			vlandown_data = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
			if(vlandown_data == NULL)
			{
				IPACMERR("Unable to allocate memory\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			memset(vlandown_data, 0, sizeof(ipacm_event_vlan_pdn));

			if(ipv4_to_iface[modem_ipv4_pdn_index].wan_up_vlan &&
				ipv6_to_iface[modem_ipv6_pdn_index].wan_up_vlan_v6)
			{
				vlandown_data->iptype = IPA_IP_MAX;
				vlandown_data->VlanID = ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[0];
				memcpy(vlandown_data->ipv6_prefix, ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix, sizeof(ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix));
				vlandown_data->ipv4_addr = (public_wan_v4_addr_set) ? public_wan_v4_addr : wan_v4_addr;
				ipv4_to_iface[modem_ipv4_pdn_index].wan_up_vlan = false;
				memset(ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs, 0, sizeof(ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs));
				ipv4_to_iface[modem_ipv4_pdn_index].VID_cnt = 0;
				ipv6_to_iface[modem_ipv6_pdn_index].wan_up_vlan_v6 = false;
				memset(ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs, 0, sizeof(ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs));
				ipv6_to_iface[modem_ipv6_pdn_index].VID_cnt = 0;

			}
			else if(ipv4_to_iface[modem_ipv4_pdn_index].wan_up_vlan)
			{
				vlandown_data->iptype = IPA_IP_v4;
				vlandown_data->VlanID = associated_VID;
				vlandown_data->ipv4_addr = (public_wan_v4_addr_set) ? public_wan_v4_addr : wan_v4_addr;
				ipv4_to_iface[modem_ipv4_pdn_index].wan_up_vlan = false;
				memset(ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs, 0, sizeof(ipv4_to_iface[modem_ipv4_pdn_index].associated_VIDs));
				ipv4_to_iface[modem_ipv4_pdn_index].VID_cnt = 0;
			}
			else
			{
				vlandown_data->iptype = IPA_IP_v6;
				vlandown_data->VlanID = ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs[0];
				memcpy(vlandown_data->ipv6_prefix, ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix, sizeof(ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix));
				ipv6_to_iface[modem_ipv6_pdn_index].wan_up_vlan_v6 = false;
				memset(ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs, 0, sizeof(ipv6_to_iface[modem_ipv6_pdn_index].associated_VIDs));
				ipv6_to_iface[modem_ipv6_pdn_index].VID_cnt = 0;
			}

			num_offloaded_pdns--;
			IPACMDBG_H("now num offloaded PDNs is %d\n", num_offloaded_pdns);

			vlandown_data->VlanID = associated_VID; /* Wan is down. setting this value to 0, to delete all rules. */
			vlandown_data->mux_id = ext_prop->ext[0].mux_id;

			IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_DOWN with below information:\n");
			IPACMDBG_H("iptype %d, VlanID %d, mux_id %d, if num %d ipv6 prefix 0x%08x:%08x\n\n",
				vlandown_data->iptype, vlandown_data->VlanID, ext_prop->ext[0].mux_id, ipa_if_num,
				vlandown_data->ipv6_prefix[0], vlandown_data->ipv6_prefix[1]);

			evt_data.event = IPA_HANDLE_WAN_VLAN_PDN_DOWN;
			evt_data.evt_data = (void *)vlandown_data;

			IPACM_EvtDispatcher::PostEvt(&evt_data);
		}

		ipv4_to_iface[modem_ipv4_pdn_index].ipv4_addr = 0;
		ipv4_to_iface[modem_ipv4_pdn_index].pIface = NULL;
		memset(&ipv6_to_iface[modem_ipv6_pdn_index].ipv6_prefix, 0, sizeof(uint32_t) * 2);
		ipv6_to_iface[modem_ipv6_pdn_index].pIface = NULL;

		if(!isVlanWanUP())
		{
			if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
			{
				/* Delete corresponding ipa_rm_resource_name of TX-endpoint after delete IPV4/V6 RT-rule */
				IPACMDBG_H("dev %s delete producer dependency\n", dev_name);
				IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
				IPACM_Iface::ipacmcfg->DelRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			}
			else {
				IPACMDBG_H("ipa_pm_q6_check to %d\n", ipa_pm_q6_check);
				if(ipa_pm_q6_check == 1)
				{
					struct wan_ioctl_notify_wan_state wan_state;

					memset(&wan_state, 0, sizeof(wan_state));

					int fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
					if(fd_wwan_ioctl < 0)
					{
						IPACMERR("Failed to open %s.\n", WWAN_QMI_IOCTL_DEVICE_NAME);
						return false;
					}
					IPACMDBG_H("send WAN_IOC_NOTIFY_WAN_STATE down to IPA_PM\n");
					if(ioctl(fd_wwan_ioctl, WAN_IOC_NOTIFY_WAN_STATE, &wan_state))
					{
						IPACMERR("Failed to send WAN_IOC_NOTIFY_WAN_STATE as up %d\n ", wan_state.up);
					}
					close(fd_wwan_ioctl);
				}
				if(ipa_pm_q6_check > 0)
					ipa_pm_q6_check--;
				else
					IPACMERR(" ipa_pm_q6_check becomes negative !!!\n");
			}
		}
		else
		{
			IPACMDBG_H("not deleting rm depend for default rt, a v4 VLAN PDN is still up, iptype %d\n", ip_type);
		}

		if(!isVlanWanUP_V6())
		{
			if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
			{
				/* Delete corresponding ipa_rm_resource_name of TX-endpoint after delete IPV4/V6 RT-rule */
				IPACMDBG_H("dev %s delete producer dependency\n", dev_name);
				IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
				IPACM_Iface::ipacmcfg->DelRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			}
			else {
				IPACMDBG_H("ipa_pm_q6_check to %d\n", ipa_pm_q6_check);
				if(ipa_pm_q6_check == 1)
				{
					struct wan_ioctl_notify_wan_state wan_state;

					memset(&wan_state, 0, sizeof(wan_state));

					int fd_wwan_ioctl = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);
					if(fd_wwan_ioctl < 0)
					{
						IPACMERR("Failed to open %s.\n", WWAN_QMI_IOCTL_DEVICE_NAME);
						return false;
					}
					IPACMDBG_H("send WAN_IOC_NOTIFY_WAN_STATE down to IPA_PM\n");
					if(ioctl(fd_wwan_ioctl, WAN_IOC_NOTIFY_WAN_STATE, &wan_state))
					{
						IPACMERR("Failed to send WAN_IOC_NOTIFY_WAN_STATE as up %d\n ", wan_state.up);
					}
					close(fd_wwan_ioctl);
				}
				if(ipa_pm_q6_check > 0)
					ipa_pm_q6_check--;
				else
					IPACMERR(" ipa_pm_q6_check becomes negative !!!\n");
			}
		}
		else
		{
			IPACMDBG_H("not deleting rm depend for default rt, a v6 VLAN PDN is still up, iptype %d\n", ip_type);
		}
#endif
		/* only when default gw goes down we post WAN_DOWN event*/
		if(is_default_gateway == true)
		{
			IPACM_Wan::wan_up = false;
			del_wan_firewall_rule(IPA_IP_v4);
#ifdef FEATURE_VLAN_MPDN
			/* if there are still secondary PDNs up we need to reconfigure firewall */
			if(isVlanWanUP())
			{
				config_wan_firewall_rule(IPA_IP_v4);
			}
#endif
			handle_route_del_evt_ex(IPA_IP_v4);
#ifdef FEATURE_IPA_ANDROID
			/* posting wan_down_tether for all lan clients */
			for (i=0; i < IPACM_Wan::ipa_if_num_tether_v4_total; i++)
			{
				ipa_if_num_tether_tmp[i] = IPACM_Wan::ipa_if_num_tether_v4[i];
			}
			tether_total = IPACM_Wan::ipa_if_num_tether_v4_total;
			for (i=0; i < tether_total; i++)
			{
				post_wan_down_tether_evt(IPA_IP_v4, ipa_if_num_tether_tmp[i]);
				IPACMDBG_H("post_wan_down_tether_v4 iface(%d: %s)\n",
					i, IPACM_Iface::ipacmcfg->iface_table[ipa_if_num_tether_tmp[i]].iface_name);
			}
#endif
			IPACM_Wan::wan_up_v6 = false;
			del_wan_firewall_rule(IPA_IP_v6);
#ifdef FEATURE_VLAN_MPDN
			/* if there are still secondary PDNs up we need to reconfigure firewall */
			if(isVlanWanUP_V6())
			{
				config_wan_firewall_rule(IPA_IP_v6);
			}
#endif
			handle_route_del_evt_ex(IPA_IP_v6);
#ifdef FEATURE_IPA_ANDROID
			/* posting wan_down_tether for all lan clients */
			for (i=0; i < IPACM_Wan::ipa_if_num_tether_v6_total; i++)
			{
				ipa_if_num_tether_tmp[i] = IPACM_Wan::ipa_if_num_tether_v6[i];
			}
			tether_total = IPACM_Wan::ipa_if_num_tether_v6_total;
			for (i=0; i < tether_total; i++)
			{
				post_wan_down_tether_evt(IPA_IP_v6, ipa_if_num_tether_tmp[i]);
				IPACMDBG_H("post_wan_down_tether_v6 iface(%d: %s)\n",
					i, IPACM_Iface::ipacmcfg->iface_table[ipa_if_num_tether_tmp[i]].iface_name);
			}
#endif
			memset(IPACM_Wan::wan_up_dev_name, 0, sizeof(IPACM_Wan::wan_up_dev_name));

			install_wan_filtering_rule(false);
		}

		/* only when the last ipv4 modem interface goes down, delete ipv4 default flt rules*/
		if(num_ipv4_modem_pdn == 0)
		{
			IPACMDBG_H("Now the number of modem ipv4 interface is 0, delete default flt rules.\n");
			IPACM_Wan::num_v4_flt_rule = 0;
#ifdef FEATURE_VLAN_MPDN
			memset(IPACM_Wan::pdn_flt_rule_v4, 0, IPA_MAX_FLT_RULE * sizeof(struct ipacm_pdn_flt_rule));
#else
			memset(IPACM_Wan::flt_rule_v4, 0, IPA_MAX_FLT_RULE * sizeof(struct ipa_flt_rule_add));
#endif
			install_wan_filtering_rule(false);
#ifdef FEATURE_IPA_IPSEC
			IPACMDBG_H("Calling installWanPostIpsecRt(IPA_IP_v4)\n");
			if (installWanPostIpsecRt(IPA_IP_v4) != IPACM_SUCCESS)
				IPACMERR("installWanPostIpsecRt(IPA_IP_v4) failed\n");
#endif
		}
		/* only when the last ipv6 modem interface goes down, delete ipv6 default flt rules*/
		if(num_ipv6_modem_pdn == 0)
		{
			IPACMDBG_H("Now the number of modem ipv6 interface is 0, delete default flt rules.\n");
			IPACM_Wan::num_v6_flt_rule = 0;
#ifdef FEATURE_VLAN_MPDN
			memset(IPACM_Wan::pdn_flt_rule_v6, 0, IPA_MAX_FLT_RULE * sizeof(struct ipacm_pdn_flt_rule));
#else
			memset(IPACM_Wan::flt_rule_v6, 0, IPA_MAX_FLT_RULE * sizeof(struct ipa_flt_rule_add));
#endif
			install_wan_filtering_rule(false);
#ifdef FEATURE_IPA_IPSEC
			IPACMDBG_H("Calling installWanPostIpsecRt(IPA_IP_v6)\n");
			if (installWanPostIpsecRt(IPA_IP_v6) != IPACM_SUCCESS)
				IPACMERR("installWanPostIpsecRt(IPA_IP_v6) failed\n");
#endif

			/* clean the ipv6 wan-route rule hdl for v6_wan_table */
			if (wan_route_rule_wan_v6_hdl_a5 != 0)
			{
				IPACMDBG_H("Delete ipv6 default v6 wan RT-rule 0x%x\n", wan_route_rule_wan_v6_hdl_a5);
				if (m_routing.DeleteRoutingHdl(wan_route_rule_wan_v6_hdl_a5, IPA_IP_v6) == false)
				{
					IPACMDBG_H("IP-family:%d, Routing rule(hdl:0x%x) deletion failed!\n",IPA_IP_v6,wan_route_rule_wan_v6_hdl_a5);
					return IPACM_FAILURE;
				}
				wan_route_rule_wan_v6_hdl_a5 = 0;
			}
		}

		IPACMDBG_H("Delete dft v4 rt rule\n");
		if (m_routing.DeleteRoutingHdl(dft_rt_rule_hdl[0], IPA_IP_v4) == false)
		{
			IPACMERR("Routing rule deletion failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		dft_rt_rule_hdl[0] = 0;
#ifdef FEATURE_IPA_IPSEC
		/* Delete default IPsec v4 RT rules */
		IPACMDBG_H("Delete IPsec default v4 routing rules\n");
		if (del_ipsec_wan_dl_rt_rules(IPA_IP_v4) == IPACM_FAILURE)
		{
			IPACMERR("Routing old IPsec RT rules deletion failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
#endif

		IPACMDBG_H("Delete dft v6 rt rule\n");
		for (i = 0; i < 2*num_dft_rt_v6; i++)
		{
			if (m_routing.DeleteRoutingHdl(dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES+i], IPA_IP_v6) == false)
			{
				IPACMERR("Routing rule deletion failed!\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES+i] = 0;
		}
#ifdef FEATURE_IPA_IPSEC
		/* Delete default IPsec v6 RT rules */
		IPACMDBG_H("Delete IPsec default v6 routing rules\n");
		if (del_ipsec_wan_dl_rt_rules(IPA_IP_v6) == IPACM_FAILURE)
		{
			IPACMERR("Routing old IPsec RT rules deletion failed!\n");
			res = IPACM_FAILURE;
			goto fail;
		}
#endif

	}

	/* check software routing fl rule hdl */
	if (softwarerouting_act == true)
	{
		handle_software_routing_disable();
	}

fail:
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
	if (ext_prop != NULL)
	{
		free(ext_prop);
		ext_prop = NULL;
	}
	if (iface_query != NULL)
	{
		free(iface_query);
		iface_query = NULL;
	}
	if (wan_route_rule_v4_hdl != NULL)
	{
		free(wan_route_rule_v4_hdl);
		wan_route_rule_v4_hdl = NULL;
	}
	if (wan_route_rule_v6_hdl != NULL)
	{
		free(wan_route_rule_v6_hdl);
		wan_route_rule_v6_hdl = NULL;
	}
	if (wan_client != NULL)
	{
		free(wan_client);
		wan_client = NULL;
	}
	close(m_fd_ipa);
	return res;
}

#ifdef FEATURE_IPA_IPSEC
int IPACM_Wan::installWanPostIpsecRt(ipa_ip_type ipType)
{
	const int NUM_RT6_RULES = 6;
	bool commit_delete = false;
	int i, num_rules, res = IPACM_SUCCESS;
	uint32_t qmapHdrHdl;
	struct ipa_ioc_add_rt_rule *rt_rule = NULL;
	struct ipa_rt_rule_add *rt_rule_entry = NULL;

	/* Clean old rules without commiting them */
	if (num_ipsec_post_pol_rt[ipType] > 0)
	{
		for (int i = 0; i < num_ipsec_post_pol_rt[ipType]; i++)
		{
			IPACMDBG_H("Deleting Route hdl:(0x%x) with ip type: %d\n", ipsec_post_pol_rt_hdls[ipType][i], ipType);
			if (false == m_routing.DeleteRoutingHdl(ipsec_post_pol_rt_hdls[ipType][i], ipType, 0))
			{
				IPACMERR("Routing rule deletion failed!\n");
				return IPACM_FAILURE;
			}
			ipsec_post_pol_rt_hdls[ipType][i] = -1;
		}
		num_ipsec_post_pol_rt[ipType] = 0;
		commit_delete = true;
	}

	num_rules = (ipType == IPA_IP_v4) ? IPACM_Wan::num_v4_flt_rule : IPACM_Wan::num_v6_flt_rule;

	/* Nothing to be done, if there are no DL exception rules. */
	/* Only commit, if there were deleted rules */
	if (commit_delete && num_rules == 0) {
		IPACMDBG_H("No DL rules yet. Just commit the deletion.\n");
		m_routing.Commit(ipType);
		return IPACM_SUCCESS;
	}

	qmapHdrHdl = GetQCMAPhdrOfFirstRmnet(ipType);
	if(qmapHdrHdl == 0)
	{
		IPACMERR("Failed to get QMAP header.\n");
		res = IPACM_FAILURE;
		goto end;
	}

	rt_rule = (struct ipa_ioc_add_rt_rule *)
		calloc(1, sizeof(struct ipa_ioc_add_rt_rule) +
			NUM_RT6_RULES * sizeof(struct ipa_rt_rule_add));
	if (!rt_rule)
	{
		IPACMERR("Error allocating ipa_ioc_add_rt_rule memory.\n");
		res = IPACM_FAILURE;
		goto end;
	}

	rt_rule->commit = 1;
	rt_rule->ip = ipType;
	rt_rule->num_rules = 0;

	/* Frag (same for IPv4 and IPv6) */
	rt_rule_entry = &rt_rule->rules[rt_rule->num_rules++];
	memset(rt_rule_entry, 0, sizeof(*rt_rule_entry));
	rt_rule_entry->rule.hdr_hdl = qmapHdrHdl;
	rt_rule_entry->rule.dst = IPA_CLIENT_IPSEC_APPS_WAN_CONS;
	rt_rule_entry->at_rear = false;
	rt_rule_entry->rule.hashable = false; /* metadata + non 5-tuple */
	rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_FRAGMENT|IPA_FLT_META_DATA;
	rt_rule_entry->rule.attrib.meta_data = META_IS_IPSEC;
	rt_rule_entry->rule.attrib.meta_data_mask = META_IPSEC_MASK;

	IPACMDBG_H("rt_rule_entry->rule.attrib.attrib_mask = 0x%X\n", rt_rule_entry->rule.attrib.attrib_mask);

	switch (ipType) {
	case IPA_IP_v4:
		strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_lan_v4.name,
			sizeof(rt_rule->rt_tbl_name));

		/* Multicast */
		rt_rule_entry = &rt_rule->rules[rt_rule->num_rules++];
		memset(rt_rule_entry, 0, sizeof(*rt_rule_entry));
		rt_rule_entry->rule.hdr_hdl = qmapHdrHdl;
		rt_rule_entry->rule.dst = IPA_CLIENT_IPSEC_APPS_WAN_CONS;
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.hashable = true;
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR|IPA_FLT_META_DATA;
		rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xF0000000;
		rt_rule_entry->rule.attrib.u.v4.dst_addr = 0xE0000000;
		rt_rule_entry->rule.attrib.meta_data = META_IS_IPSEC;
		rt_rule_entry->rule.attrib.meta_data_mask = META_IPSEC_MASK;

		IPACMDBG_H("rt_rule_entry->rule.attrib.attrib_mask = 0x%X\n", rt_rule_entry->rule.attrib.attrib_mask);

		/* Broadcast */
		rt_rule_entry = &rt_rule->rules[rt_rule->num_rules++];
		memset(rt_rule_entry, 0, sizeof(*rt_rule_entry));
		rt_rule_entry->rule.hdr_hdl = qmapHdrHdl;
		rt_rule_entry->rule.dst = IPA_CLIENT_IPSEC_APPS_WAN_CONS;
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.hashable = true;
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR|IPA_FLT_META_DATA;
		rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.u.v4.dst_addr = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.meta_data = META_IS_IPSEC;
		rt_rule_entry->rule.attrib.meta_data_mask = META_IPSEC_MASK;

		IPACMDBG_H("rt_rule_entry->rule.attrib.attrib_mask = 0x%X\n", rt_rule_entry->rule.attrib.attrib_mask);

		/* TCP syn */
		rt_rule_entry = &rt_rule->rules[rt_rule->num_rules++];
		memset(rt_rule_entry, 0, sizeof(*rt_rule_entry));
		rt_rule_entry->rule.hdr_hdl = qmapHdrHdl;
		rt_rule_entry->rule.dst = IPA_CLIENT_IPSEC_APPS_WAN_CONS;
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.hashable = false; /* metadata + non 5-tuple */
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_PROTOCOL|IPA_FLT_TCP_SYN|IPA_FLT_META_DATA;
		rt_rule_entry->rule.attrib.u.v4.protocol = IPACM_FIREWALL_IPPROTO_TCP;
		rt_rule_entry->rule.attrib.meta_data = META_IS_IPSEC;
		rt_rule_entry->rule.attrib.meta_data_mask = META_IPSEC_MASK;

		IPACMDBG_H("rt_rule_entry->rule.attrib.attrib_mask = 0x%X\n", rt_rule_entry->rule.attrib.attrib_mask);

		/* ICMP */
		rt_rule_entry = &rt_rule->rules[rt_rule->num_rules++];
		memset(rt_rule_entry, 0, sizeof(*rt_rule_entry));
		rt_rule_entry->rule.hdr_hdl = qmapHdrHdl;
		rt_rule_entry->rule.dst = IPA_CLIENT_IPSEC_APPS_WAN_CONS;
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.hashable = true;
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_PROTOCOL|IPA_FLT_META_DATA;
		rt_rule_entry->rule.attrib.u.v4.protocol = IPACM_FIREWALL_IPPROTO_ICMP;
		rt_rule_entry->rule.attrib.meta_data = META_IS_IPSEC;
		rt_rule_entry->rule.attrib.meta_data_mask = META_IPSEC_MASK;

		IPACMDBG_H("rt_rule_entry->rule.attrib.attrib_mask = 0x%X\n", rt_rule_entry->rule.attrib.attrib_mask);

		break;

	case IPA_IP_v6:
		strlcpy(rt_rule->rt_tbl_name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name,
			sizeof(rt_rule->rt_tbl_name));

		/* Multicast */
		rt_rule_entry = &rt_rule->rules[rt_rule->num_rules++];
		memset(rt_rule_entry, 0, sizeof(*rt_rule_entry));
		rt_rule_entry->rule.hdr_hdl = qmapHdrHdl;
		rt_rule_entry->rule.dst = IPA_CLIENT_IPSEC_APPS_WAN_CONS;
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.hashable = true;
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR|IPA_FLT_META_DATA;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFF000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = 0xFF000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = 0x00000000;
		rt_rule_entry->rule.attrib.meta_data = META_IS_IPSEC;
		rt_rule_entry->rule.attrib.meta_data_mask = META_IPSEC_MASK;

		IPACMDBG_H("rt_rule_entry->rule.attrib.attrib_mask = 0x%X\n", rt_rule_entry->rule.attrib.attrib_mask);

		/* fe80::/10 Link-Scoped Unicast */
		rt_rule_entry = &rt_rule->rules[rt_rule->num_rules++];
		memset(rt_rule_entry, 0, sizeof(*rt_rule_entry));
		rt_rule_entry->rule.hdr_hdl = qmapHdrHdl;
		rt_rule_entry->rule.dst = IPA_CLIENT_IPSEC_APPS_WAN_CONS;
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.hashable = true;
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR|IPA_FLT_META_DATA;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFC00000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = 0xFE800000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = 0x00000000;
		rt_rule_entry->rule.attrib.meta_data = META_IS_IPSEC;
		rt_rule_entry->rule.attrib.meta_data_mask = META_IPSEC_MASK;

		IPACMDBG_H("rt_rule_entry->rule.attrib.attrib_mask = 0x%X\n", rt_rule_entry->rule.attrib.attrib_mask);

		/* fec0::/10 Reserved by IETF */
		rt_rule_entry = &rt_rule->rules[rt_rule->num_rules++];
		memset(rt_rule_entry, 0, sizeof(*rt_rule_entry));
		rt_rule_entry->rule.hdr_hdl = qmapHdrHdl;
		rt_rule_entry->rule.dst = IPA_CLIENT_IPSEC_APPS_WAN_CONS;
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.hashable = true;
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR|IPA_FLT_META_DATA;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFC00000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = 0xFEC00000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = 0x00000000;
		rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = 0x00000000;
		rt_rule_entry->rule.attrib.meta_data = META_IS_IPSEC;
		rt_rule_entry->rule.attrib.meta_data_mask = META_IPSEC_MASK;

		IPACMDBG_H("rt_rule_entry->rule.attrib.attrib_mask = 0x%X\n", rt_rule_entry->rule.attrib.attrib_mask);

		/* TCP syn */
		rt_rule_entry = &rt_rule->rules[rt_rule->num_rules++];
		memset(rt_rule_entry, 0, sizeof(*rt_rule_entry));
		rt_rule_entry->rule.hdr_hdl = qmapHdrHdl;
		rt_rule_entry->rule.dst = IPA_CLIENT_IPSEC_APPS_WAN_CONS;
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.hashable = false; /* metadata + non 5-tuple */
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_NEXT_HDR|IPA_FLT_TCP_SYN|IPA_FLT_META_DATA;
		rt_rule_entry->rule.attrib.u.v6.next_hdr = IPACM_FIREWALL_IPPROTO_TCP;
		rt_rule_entry->rule.attrib.meta_data = META_IS_IPSEC;
		rt_rule_entry->rule.attrib.meta_data_mask = META_IPSEC_MASK;

		IPACMDBG_H("rt_rule_entry->rule.attrib.attrib_mask = 0x%X\n", rt_rule_entry->rule.attrib.attrib_mask);

		/* ICMP */
		rt_rule_entry = &rt_rule->rules[rt_rule->num_rules++];
		memset(rt_rule_entry, 0, sizeof(*rt_rule_entry));
		rt_rule_entry->rule.hdr_hdl = qmapHdrHdl;
		rt_rule_entry->rule.dst = IPA_CLIENT_IPSEC_APPS_WAN_CONS;
		rt_rule_entry->at_rear = false;
		rt_rule_entry->rule.hashable = true;
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_NEXT_HDR|IPA_FLT_META_DATA;
		rt_rule_entry->rule.attrib.u.v6.next_hdr = IPACM_FIREWALL_IPPROTO_ICMP;
		rt_rule_entry->rule.attrib.meta_data = META_IS_IPSEC;
		rt_rule_entry->rule.attrib.meta_data_mask = META_IPSEC_MASK;

		IPACMDBG_H("rt_rule_entry->rule.attrib.attrib_mask = 0x%X\n", rt_rule_entry->rule.attrib.attrib_mask);

		break;
	default:
		IPACMERR("Invalid IP type: %d\n", ipType);
		res =  IPACM_FAILURE;
		goto end;
	}

	IPACMDBG_H("rt_tbl_name = %s num_rules = %d\n",
		rt_rule->rt_tbl_name, rt_rule->num_rules);


	if (false == m_routing.AddRoutingRule(rt_rule))
	{
		IPACMERR("Routing rule addition failed!\n");
		res = IPACM_FAILURE;
		goto end;
	}
	else if ((rt_rule_entry != NULL) && (rt_rule_entry->status))
	{
		IPACMERR("rt rule adding failed. Result=%d\n", rt_rule_entry->status);
		res = rt_rule_entry->status;
		goto end;
	}

	for (i = 0; i < rt_rule->num_rules; i++)
		ipsec_post_pol_rt_hdls[ipType][i] = rt_rule->rules[i].rt_rule_hdl;

	num_ipsec_post_pol_rt[ipType] = rt_rule->num_rules;

end:
	if (rt_rule)
		free(rt_rule);
	return res;
}
#endif

int IPACM_Wan::install_wan_filtering_rule(bool is_sw_routing, bool is_socksv5_en)
{
	int len, res = IPACM_SUCCESS;
	uint8_t mux_id;
	ipa_ioc_add_flt_rule *pFilteringTable_v4 = NULL;
	ipa_ioc_add_flt_rule *pFilteringTable_v6 = NULL;
	int num_v6_flt_rule_socksv5_sum = 0;
#ifdef FEATURE_VLAN_MPDN
	uint8_t *mux_id_v4 = NULL;
	uint8_t *mux_id_v6 = NULL;
#endif

	mux_id = IPACM_Iface::ipacmcfg->GetQmapId();
	if(rx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}
	if (is_sw_routing == true ||
			IPACM_Iface::ipacmcfg->ipa_sw_rt_enable == true)
	{
		/* contruct SW-RT rules to Q6*/
		struct ipa_flt_rule_add flt_rule_entry;
		struct ipa_ioc_get_rt_tbl_indx rt_tbl_idx;
		ipa_ioc_generate_flt_eq flt_eq;

		IPACMDBG("\n");
		if (softwarerouting_act == true)
		{
			IPACMDBG("already setup software_routing rule for (%s)iface ip-family %d\n",
								IPACM_Iface::ipacmcfg->iface_table[ipa_if_num].iface_name, ip_type);
			return IPACM_SUCCESS;
		}

		len = sizeof(struct ipa_ioc_add_flt_rule) + sizeof(struct ipa_flt_rule_add);
		pFilteringTable_v4 = (struct ipa_ioc_add_flt_rule*)malloc(len);
		if (pFilteringTable_v4 == NULL)
		{
			IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
			return IPACM_FAILURE;
		}
		memset(pFilteringTable_v4, 0, len);
#ifdef FEATURE_VLAN_MPDN
		mux_id_v4 = (uint8_t*)malloc(sizeof(uint8_t));
		if(mux_id_v4 == NULL)
		{
			IPACMERR("Error Locate mux_id_v4 memory...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		/* use the default PDN mux ID */
		mux_id_v4[0] = IPACM_Iface::ipacmcfg->GetQmapId();
#endif
		IPACMDBG_H("Total number of WAN DL filtering rule for IPv4 is 1\n");

		pFilteringTable_v4->commit = 1;
		pFilteringTable_v4->ep = rx_prop->rx[0].src_pipe;
		pFilteringTable_v4->global = false;
		pFilteringTable_v4->ip = IPA_IP_v4;
		pFilteringTable_v4->num_rules = (uint8_t)1;

		/* Configuring Software-Routing Filtering Rule */
		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
		memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
		strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_wan_dl.name, IPA_RESOURCE_NAME_MAX);
		rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
		rt_tbl_idx.ip = IPA_IP_v4;
		if(ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx) < 0)
		{
			IPACMERR("Failed to get routing table index from name\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACMDBG_H("Routing table %s has index %d\n", rt_tbl_idx.name, rt_tbl_idx.idx);

		flt_rule_entry.at_rear = false;
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;
		flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#ifdef FEATURE_IPA_V3
		flt_rule_entry.rule.hashable = true;
#endif

		flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;

		memcpy(&flt_rule_entry.rule.attrib,
					&rx_prop->rx[0].attrib,
					sizeof(flt_rule_entry.rule.attrib));
		flt_rule_entry.rule.retain_hdr = 0;
		flt_rule_entry.rule.to_uc = 0;
		flt_rule_entry.rule.eq_attrib_type = 1;

		memset(&flt_eq, 0, sizeof(flt_eq));
		memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
		flt_eq.ip = IPA_IP_v4;
		if(0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
		{
			IPACMERR("Failed to get eq_attrib\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		memcpy(&flt_rule_entry.rule.eq_attrib,
			&flt_eq.eq_attrib,
			sizeof(flt_rule_entry.rule.eq_attrib));
		memcpy(&(pFilteringTable_v4->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));

		len = sizeof(struct ipa_ioc_add_flt_rule) + sizeof(struct ipa_flt_rule_add);
		pFilteringTable_v6 = (struct ipa_ioc_add_flt_rule*)malloc(len);
		if (pFilteringTable_v6 == NULL)
		{
			IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		memset(pFilteringTable_v6, 0, len);
#ifdef FEATURE_VLAN_MPDN
		mux_id_v6 = (uint8_t*)malloc(sizeof(uint8_t));
		if(mux_id_v6 == NULL)
		{
			IPACMERR("Error Locate mux_id_v6 memory...\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		/* use the default PDN mux ID */
		mux_id_v6[0] = IPACM_Iface::ipacmcfg->GetQmapId();
#endif
		IPACMDBG_H("Total number of WAN DL filtering rule for IPv6 is 1\n");

		pFilteringTable_v6->commit = 1;
		pFilteringTable_v6->ep = rx_prop->rx[0].src_pipe;
		pFilteringTable_v6->global = false;
		pFilteringTable_v6->ip = IPA_IP_v6;
		pFilteringTable_v6->num_rules = (uint8_t)1;

		/* Configuring Software-Routing Filtering Rule */
		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
		memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
		strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_wan_dl.name, IPA_RESOURCE_NAME_MAX);
		rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
		rt_tbl_idx.ip = IPA_IP_v6;
		if(ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx) < 0)
		{
			IPACMERR("Failed to get routing table index from name\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		IPACMDBG_H("Routing table %s has index %d\n", rt_tbl_idx.name, rt_tbl_idx.idx);

		flt_rule_entry.at_rear = false;
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;
		flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#ifdef FEATURE_IPA_V3
		flt_rule_entry.rule.hashable = true;
#endif
		flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;
		memcpy(&flt_rule_entry.rule.attrib,
					&rx_prop->rx[0].attrib,
					sizeof(flt_rule_entry.rule.attrib));
		flt_rule_entry.rule.retain_hdr = 0;
		flt_rule_entry.rule.to_uc = 0;
		flt_rule_entry.rule.eq_attrib_type = 1;

		memset(&flt_eq, 0, sizeof(flt_eq));
		memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
		flt_eq.ip = IPA_IP_v6;
		if(0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
		{
			IPACMERR("Failed to get eq_attrib\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		memcpy(&flt_rule_entry.rule.eq_attrib,
			&flt_eq.eq_attrib,
			sizeof(flt_rule_entry.rule.eq_attrib));
		memcpy(&(pFilteringTable_v6->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
		softwarerouting_act = true;
		/* end of contruct SW-RT rules to Q6*/
	}
#ifdef FEATURE_SOCKSv5
	else if (is_socksv5_en == true ||
		IPACM_Iface::ipacmcfg->ipacm_socksv5_enable == true) {
		/* socksv5 handling */
		/* allocate ipv4 filtering table */
		if(IPACM_Wan::num_v4_flt_rule > 0)
		{
			len = sizeof(struct ipa_ioc_add_flt_rule) + IPACM_Wan::num_v4_flt_rule * sizeof(struct ipa_flt_rule_add);
			pFilteringTable_v4 = (struct ipa_ioc_add_flt_rule*)malloc(len);

			IPACMDBG_H("Total number of WAN DL filtering rule for IPv4 is %d\n", IPACM_Wan::num_v4_flt_rule);

			if (pFilteringTable_v4 == NULL)
			{
				IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
				return IPACM_FAILURE;
			}
			memset(pFilteringTable_v4, 0, len);
#ifdef FEATURE_VLAN_MPDN
			mux_id_v4 = (uint8_t*)malloc(IPACM_Wan::num_v4_flt_rule * sizeof(uint8_t));
			if(mux_id_v4 == NULL)
			{
				IPACMERR("Error allocate mux_id_v4 memory...\n");
				res = IPACM_FAILURE;
				goto fail;
			}
#endif
			pFilteringTable_v4->commit = 1;
			pFilteringTable_v4->ep = rx_prop->rx[0].src_pipe;
			pFilteringTable_v4->global = false;
			pFilteringTable_v4->ip = IPA_IP_v4;
			pFilteringTable_v4->num_rules = (uint8_t)IPACM_Wan::num_v4_flt_rule;
#ifdef FEATURE_VLAN_MPDN
			for(int i = 0; i < IPACM_Wan::num_v4_flt_rule; i++)
			{
				mux_id_v4[i] = IPACM_Wan::pdn_flt_rule_v4[i].mux_id;
				memcpy(&pFilteringTable_v4->rules[i],
					&IPACM_Wan::pdn_flt_rule_v4[i].flt_rule,
					sizeof(ipa_flt_rule_add));
			}
#else
			memcpy(pFilteringTable_v4->rules, IPACM_Wan::flt_rule_v4, IPACM_Wan::num_v4_flt_rule * sizeof(ipa_flt_rule_add));
#endif
		}

		/* allocate ipv6 filtering table */
		/* find how many v6 DL socksv5 pdn needed */
		if(pthread_mutex_lock(&IPACM_Iface::ipacmcfg->socksv5_lock) != 0)
		{
			IPACMERR("Unable to lock the mutex\n");
			res = IPACM_FAILURE;
			goto fail;
		}
		num_v6_flt_rule_socksv5_sum = 1 + IPACM_Iface::ipacmcfg->total_pdn_ipv6_in_use + IPACM_Wan::num_v6_flt_rule;
		if(num_v6_flt_rule_socksv5_sum > 0)
		{
#ifdef FEATURE_VLAN_MPDN
			mux_id_v6 = (uint8_t*)malloc(num_v6_flt_rule_socksv5_sum * sizeof(uint8_t));
			if(mux_id_v6 == NULL)
			{
				IPACMERR("Error allocate mux_id_v6 memory...\n");
				pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->socksv5_lock);
				res = IPACM_FAILURE;
				goto fail;
			}
#endif
			len = sizeof(struct ipa_ioc_add_flt_rule) + num_v6_flt_rule_socksv5_sum * sizeof(struct ipa_flt_rule_add);
			pFilteringTable_v6 = (struct ipa_ioc_add_flt_rule*)malloc(len);
			IPACMDBG_H("Total number of WAN DL filtering rule for IPv6 is wan_flt:%d + socksv5_v6:%d, total %d\n",
				IPACM_Wan::num_v6_flt_rule, IPACM_Iface::ipacmcfg->total_pdn_ipv6_in_use,
				num_v6_flt_rule_socksv5_sum);
			if (pFilteringTable_v6 == NULL)
			{
				IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
				pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->socksv5_lock);
				res = IPACM_FAILURE;
				goto fail;
			}
			memset(pFilteringTable_v6, 0, len);
			pFilteringTable_v6->commit = 1;
			pFilteringTable_v6->ep = rx_prop->rx[0].src_pipe;
			pFilteringTable_v6->global = false;
			pFilteringTable_v6->ip = IPA_IP_v6;
			pFilteringTable_v6->num_rules = (uint8_t)num_v6_flt_rule_socksv5_sum;
			/* configure socksv5 DL ipv6 client filter rule*/
			if (config_socksv5_rules(pFilteringTable_v6))
			{
				IPACMERR("config_socksv5_rules failed\n");
				pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->socksv5_lock);
				res = IPACM_FAILURE;
				goto fail;
			}
#ifdef FEATURE_VLAN_MPDN
			if (mux_id_v6 != NULL)
			{
				/* use the default PDN mux ID */
				for(int i = 0; i < IPACM_Iface::ipacmcfg->total_pdn_ipv6_in_use + 1; i++)
				{
					mux_id_v6[i] = IPACM_Iface::ipacmcfg->GetQmapId();
					IPACMDBG_H("mux_id_v6[%d] = %d\n", i, mux_id_v6[i]);
				}

				for(int i = 0; i < IPACM_Wan::num_v6_flt_rule; i++)
				{
					mux_id_v6[IPACM_Iface::ipacmcfg->total_pdn_ipv6_in_use + 1 + i] = IPACM_Wan::pdn_flt_rule_v6[i].mux_id;
					IPACMDBG_H("mux_id_v6[%d] = %d\n", IPACM_Iface::ipacmcfg->total_pdn_ipv6_in_use + 1 + i, mux_id_v6[IPACM_Iface::ipacmcfg->total_pdn_ipv6_in_use + 1 + i]);
					memcpy(&pFilteringTable_v6->rules[IPACM_Iface::ipacmcfg->total_pdn_ipv6_in_use + 1 + i],
						&IPACM_Wan::pdn_flt_rule_v6[i].flt_rule,
						sizeof(ipa_flt_rule_add));
				}
			}
#else
			memcpy(&(pFilteringTable_v6->rules[IPACM_Iface::ipacmcfg->total_pdn_ipv6_in_use + 1]),
				IPACM_Wan::flt_rule_v6, IPACM_Wan::num_v6_flt_rule * sizeof(ipa_flt_rule_add));
#endif
			pthread_mutex_unlock(&IPACM_Iface::ipacmcfg->socksv5_lock);
		}
	} //end of socksv5_enable handling
#endif //#ifdef FEATURE_SOCKSv5
	else
	{
		if(embms_is_on == false)
		{
			if(IPACM_Wan::num_v4_flt_rule > 0)
			{
				len = sizeof(struct ipa_ioc_add_flt_rule) + IPACM_Wan::num_v4_flt_rule * sizeof(struct ipa_flt_rule_add);
				pFilteringTable_v4 = (struct ipa_ioc_add_flt_rule*)malloc(len);

				IPACMDBG_H("Total number of WAN DL filtering rule for IPv4 is %d\n", IPACM_Wan::num_v4_flt_rule);

				if (pFilteringTable_v4 == NULL)
				{
					IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
					return IPACM_FAILURE;
				}
				memset(pFilteringTable_v4, 0, len);
#ifdef FEATURE_VLAN_MPDN
				mux_id_v4 = (uint8_t*)malloc(IPACM_Wan::num_v4_flt_rule * sizeof(uint8_t));
				if(mux_id_v4 == NULL)
				{
					IPACMERR("Error allocate mux_id_v4 memory...\n");
					res = IPACM_FAILURE;
					goto fail;
				}
#endif
				pFilteringTable_v4->commit = 1;
				pFilteringTable_v4->ep = rx_prop->rx[0].src_pipe;
				pFilteringTable_v4->global = false;
				pFilteringTable_v4->ip = IPA_IP_v4;
				pFilteringTable_v4->num_rules = (uint8_t)IPACM_Wan::num_v4_flt_rule;

#ifdef FEATURE_VLAN_MPDN
				for(int i = 0; i < IPACM_Wan::num_v4_flt_rule; i++)
				{
					mux_id_v4[i] = IPACM_Wan::pdn_flt_rule_v4[i].mux_id;
					memcpy(&pFilteringTable_v4->rules[i],
						&IPACM_Wan::pdn_flt_rule_v4[i].flt_rule,
						sizeof(ipa_flt_rule_add));
				}
#else
				memcpy(pFilteringTable_v4->rules, IPACM_Wan::flt_rule_v4, IPACM_Wan::num_v4_flt_rule * sizeof(ipa_flt_rule_add));
#endif
			}

			if(IPACM_Wan::num_v6_flt_rule > 0)
			{
				len = sizeof(struct ipa_ioc_add_flt_rule) + IPACM_Wan::num_v6_flt_rule * sizeof(struct ipa_flt_rule_add);
				pFilteringTable_v6 = (struct ipa_ioc_add_flt_rule*)malloc(len);

				IPACMDBG_H("Total number of WAN DL filtering rule for IPv6 is %d\n", IPACM_Wan::num_v6_flt_rule);

				if (pFilteringTable_v6 == NULL)
				{
					IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
					res = IPACM_FAILURE;
					goto fail;
				}
				memset(pFilteringTable_v6, 0, len);
#ifdef FEATURE_VLAN_MPDN
				mux_id_v6 = (uint8_t*)malloc(IPACM_Wan::num_v6_flt_rule * sizeof(uint8_t));
				if(mux_id_v6 == NULL)
				{
					IPACMERR("Error allocate mux_id_v6 memory...\n");
					res = IPACM_FAILURE;
					goto fail;
				}
#endif
				pFilteringTable_v6->commit = 1;
				pFilteringTable_v6->ep = rx_prop->rx[0].src_pipe;
				pFilteringTable_v6->global = false;
				pFilteringTable_v6->ip = IPA_IP_v6;
				pFilteringTable_v6->num_rules = (uint8_t)IPACM_Wan::num_v6_flt_rule;

#ifdef FEATURE_VLAN_MPDN
				for(int i = 0; i < IPACM_Wan::num_v6_flt_rule; i++)
				{
					mux_id_v6[i] = IPACM_Wan::pdn_flt_rule_v6[i].mux_id;
					memcpy(&pFilteringTable_v6->rules[i],
						&IPACM_Wan::pdn_flt_rule_v6[i].flt_rule,
						sizeof(ipa_flt_rule_add));
				}
#else
				memcpy(pFilteringTable_v6->rules, IPACM_Wan::flt_rule_v6, IPACM_Wan::num_v6_flt_rule * sizeof(ipa_flt_rule_add));
#endif
			}
		}
		else	//embms is on, always add 1 embms rule on top of WAN DL flt table
		{
			/* allocate ipv4 filtering table */
			len = sizeof(struct ipa_ioc_add_flt_rule) + (1 + IPACM_Wan::num_v4_flt_rule) * sizeof(struct ipa_flt_rule_add);
			pFilteringTable_v4 = (struct ipa_ioc_add_flt_rule*)malloc(len);
			IPACMDBG_H("Total number of WAN DL filtering rule for IPv4 is %d\n", IPACM_Wan::num_v4_flt_rule + 1);
			if (pFilteringTable_v4 == NULL)
			{
				IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
				return IPACM_FAILURE;
			}
			memset(pFilteringTable_v4, 0, len);
#ifdef FEATURE_VLAN_MPDN
			mux_id_v4 = (uint8_t*)malloc((IPACM_Wan::num_v4_flt_rule + 1) * sizeof(uint8_t));
			if(mux_id_v4 == NULL)
			{
				IPACMERR("Error allocate mux_id_v4 memory...\n");
				res = IPACM_FAILURE;
				goto fail;
			}
#endif
			pFilteringTable_v4->commit = 1;
			pFilteringTable_v4->ep = rx_prop->rx[0].src_pipe;
			pFilteringTable_v4->global = false;
			pFilteringTable_v4->ip = IPA_IP_v4;
			pFilteringTable_v4->num_rules = (uint8_t)IPACM_Wan::num_v4_flt_rule + 1;

			/* allocate ipv6 filtering table */
			len = sizeof(struct ipa_ioc_add_flt_rule) + (1 + IPACM_Wan::num_v6_flt_rule) * sizeof(struct ipa_flt_rule_add);
			pFilteringTable_v6 = (struct ipa_ioc_add_flt_rule*)malloc(len);
			IPACMDBG_H("Total number of WAN DL filtering rule for IPv6 is %d\n", IPACM_Wan::num_v6_flt_rule + 1);
			if (pFilteringTable_v6 == NULL)
			{
				IPACMERR("Error Locate ipa_flt_rule_add memory...\n");
				res = IPACM_FAILURE;
				goto fail;
			}
			memset(pFilteringTable_v6, 0, len);
			pFilteringTable_v6->commit = 1;
			pFilteringTable_v6->ep = rx_prop->rx[0].src_pipe;
			pFilteringTable_v6->global = false;
			pFilteringTable_v6->ip = IPA_IP_v6;
			pFilteringTable_v6->num_rules = (uint8_t)IPACM_Wan::num_v6_flt_rule + 1;

			if (config_dft_embms_rules(pFilteringTable_v4, pFilteringTable_v6))
			{
				IPACMERR("config_dft_embms_rules failed \n");
				res = IPACM_FAILURE;
				goto fail;
			}
			if(IPACM_Wan::num_v4_flt_rule > 0)
			{
#ifdef FEATURE_VLAN_MPDN
				/* embms get's the mux ID of the default PDN */
				mux_id_v4[0] = IPACM_Iface::ipacmcfg->GetQmapId();
				for(int i = 1; i < IPACM_Wan::num_v4_flt_rule + 1; i++)
				{
					mux_id_v4[i] = IPACM_Wan::pdn_flt_rule_v4[i].mux_id;
					memcpy(&pFilteringTable_v4->rules[i],
						&IPACM_Wan::pdn_flt_rule_v4[i].flt_rule,
						sizeof(ipa_flt_rule_add));
				}
#else
				memcpy(&(pFilteringTable_v4->rules[1]), IPACM_Wan::flt_rule_v4, IPACM_Wan::num_v4_flt_rule * sizeof(ipa_flt_rule_add));
#endif
			}

			if(IPACM_Wan::num_v6_flt_rule > 0)
			{
#ifdef FEATURE_VLAN_MPDN
				/* embms get's the mux ID of the default PDN */
				if (mux_id_v6 != NULL)
				{
					mux_id_v6[0] = IPACM_Iface::ipacmcfg->GetQmapId();
					for(int i = 1; i < IPACM_Wan::num_v6_flt_rule + 1; i++)
					{
						mux_id_v6[i] = IPACM_Wan::pdn_flt_rule_v6[i].mux_id;
						memcpy(&pFilteringTable_v6->rules[i],
							&IPACM_Wan::pdn_flt_rule_v6[i].flt_rule,
							sizeof(ipa_flt_rule_add));
					}
				}
#else
					memcpy(&(pFilteringTable_v6->rules[1]), IPACM_Wan::flt_rule_v6, IPACM_Wan::num_v6_flt_rule * sizeof(ipa_flt_rule_add));

#endif
			}
		}
	}

#ifdef FEATURE_VLAN_MPDN
	if(false == m_filtering.AddWanDLFilteringRule(pFilteringTable_v4, pFilteringTable_v6, mux_id_v4, mux_id_v6))
#else
	if(false == m_filtering.AddWanDLFilteringRule(pFilteringTable_v4, pFilteringTable_v6, mux_id))
#endif
	{
		IPACMERR("Failed to install WAN DL filtering table.\n");
		res = IPACM_FAILURE;
		goto fail;
	}
#ifdef FEATURE_IPA_IPSEC
	IPACMDBG_H("Calling installWanPostIpsecRt(IPA_IP_v4)\n");
	if (installWanPostIpsecRt(IPA_IP_v4) != IPACM_SUCCESS)
		IPACMERR("installWanPostIpsecRt(IPA_IP_v4) failed\n");
	IPACMDBG_H("Calling installWanPostIpsecRt(IPA_IP_v6)\n");
	if (installWanPostIpsecRt(IPA_IP_v6) != IPACM_SUCCESS)
		IPACMERR("installWanPostIpsecRt(IPA_IP_v6) failed\n");
#endif

fail:
	if(pFilteringTable_v4 != NULL)
	{
		free(pFilteringTable_v4);
	}
	if(pFilteringTable_v6 != NULL)
	{
		free(pFilteringTable_v6);
	}
#ifdef FEATURE_VLAN_MPDN
	if(mux_id_v4)
	{
		free(mux_id_v4);
	}
	if(mux_id_v6)
	{
		free(mux_id_v6);
	}
#endif
	return res;
}

bool IPACM_Wan::is_link_local_ipv4_addr(uint32_t ipv4_addr)
{
	uint32_t link_local_prefix = 0xA9FE0000;
	uint32_t link_local_prefix_mask = 0xFFFF0000;

	IPACMDBG_H("checking ipv4 address 0x%X\n", ipv4_addr);

	if((ipv4_addr & link_local_prefix_mask) == link_local_prefix) {
		IPACMDBG_H("this address is link local\n");
		return true;
	}

	IPACMDBG_H("this address is not link local\n");
	return false;
}

bool IPACM_Wan::is_global_ipv6_addr(uint32_t* ipv6_addr)
{
	if(ipv6_addr == NULL)
	{
		IPACMERR("IPv6 address is empty.\n");
		return false;
	}
	IPACMDBG_H("Get ipv6 address with first word 0x%08x.\n", ipv6_addr[0]);

	uint32_t ipv6_link_local_prefix, ipv6_link_local_prefix_mask;
	ipv6_link_local_prefix = 0xFE800000;
	ipv6_link_local_prefix_mask = 0xFFC00000;
	if((ipv6_addr[0] & ipv6_link_local_prefix_mask) == (ipv6_link_local_prefix & ipv6_link_local_prefix_mask))
	{
		IPACMDBG_H("This IPv6 address is link local.\n");
		return false;
	}
	else
	{
		IPACMDBG_H("This IPv6 address is not link local.\n");
		return true;
	}
}

#ifdef FEATURE_DUAL_BACKHAUL
/*evt will be 1 for new_neigh, and 0 for XML CFG chg*/
int IPACM_Wan::handle_dual_backhaul_enable(ipacm_event_data_all *data, bool evt)
{

	if((evt && data->iptype != IPA_IP_v4) || !wan_v4_addr_set || !wan_v4_addr)
	{
		IPACMDBG_H("check dualback fail\n");
		return IPACM_FAILURE;
	}
	IPACMDBG_H("Second backhaul function entered\n");
	ipa_dual_backhaul_info backhaul_info  = IPACM_Iface::ipacmcfg->second_backhaul_info;
	char iface_name[IPA_IFACE_NAME_LEN] = {0};
	uint32_t cnt;
	uint32_t backhaul_ip;
	int clnt_indx;
	struct ipa_ioc_copy_hdr sCopyHeader;
	ipacm_cmd_q_data evt_data;
	/*Check if Dual Backhaul is enabled in XML*/
	if(!backhaul_info.enable)
	{
		IPACMDBG_H("There is no need to enter the function, \
				Dual backhaul is not enabled\n");
		return IPACM_FAILURE;
	}
	/*Check if this interface is configured as the second backhaul*/
	if(!strstr(dev_name, STR_ETH_IFACE))
	{
		IPACMDBG_H("This is not the interface that is meant to be the \
				backhaul. IF of this instance: %s\n",dev_name);
		return IPACM_FAILURE;
	}
	/*We need to get the mac address of Gateway router. For this,
	 * if this function is triggered by new_neigh, then we fetch
	 * it from the event data itself.
	 * But if this function was triggered by XML change, then we
	 * check in cache, and fetch from there.
	 */
	if(evt)
	{
		if (data->iptype == IPA_IP_v4)
		{
			IPACMDBG_H("the IP that has come now: %x\n",data->ipv4_addr);
			if (data->ipv4_addr != 0 && (backhaul_info.gateway_ipv4 == data->ipv4_addr))
			{
				IPACMDBG_H("Gateway IP for Second backhaul available, and found: %x\n",
					backhaul_info.gateway_ipv4);
			}
			else
			{
				IPACMDBG_H("Gateway IP for Second backhaul not found: %x, %x\n",
					backhaul_info.gateway_ipv4, data->ipv4_addr );
				return IPACM_FAILURE;
			}
		}
		else
		{
			IPACMDBG_H("Second IPV6 not supported\n" );
			return IPACM_FAILURE;
		}

		/*copy client mac address to dst_mac*/
		memcpy(backhaul_info.dst_mac,data->mac_addr, IPA_MAC_ADDR_SIZE);
	}
	else
	{
		/*This means this function has been triggered by XML_CFG_CHANGE event*/
		/*We have to see if we can find a WAN client in the cache with ipv4=gateway ipv4*/
		clnt_indx=get_wan_client_index_ipv4(backhaul_info.gateway_ipv4);
		if (clnt_indx == IPACM_INVALID_INDEX)
		{
			IPACMDBG_H("This IP not found in cache. Will wait. %x\n",
					backhaul_info.gateway_ipv4);
			return IPACM_FAILURE;
		}
		memcpy(backhaul_info.dst_mac,get_client_memptr(wan_client, clnt_indx)->mac, IPA_MAC_ADDR_SIZE);
	}
	/*So, by this point, we have filled dst mac with the gateway router's mac, now have to fill src mac*/
	/*Get src mac from tx_prop, partial header*/
	for (cnt=0; cnt<tx_prop->num_tx_props; cnt++)
	{
		if(tx_prop->tx[cnt].ip==IPA_IP_v4)
		{
			IPACMDBG_H("Got partial v4-header name from %d tx props\n", cnt);
			memset(&sCopyHeader, 0, sizeof(sCopyHeader));
			memcpy(sCopyHeader.name, tx_prop->tx[cnt].hdr_name,
					sizeof(sCopyHeader.name));

			IPACMDBG_H("header name: %s in tx:%d\n", sCopyHeader.name,cnt);
			if (m_header.CopyHeader(&sCopyHeader) == false)
			{
				PERROR("ioctl copy header failed");
				return IPACM_FAILURE;
			}

			IPACMDBG_H("header length: %d, partial: %d\n",
					sCopyHeader.hdr_len, sCopyHeader.is_partial);
			IPACMDBG_H("header eth2_ofst_valid: %d, eth2_ofst: %d\n",
					sCopyHeader.is_eth2_ofst_valid, sCopyHeader.eth2_ofst);
			if (sCopyHeader.hdr_len > IPA_HDR_MAX_SIZE)
			{
				IPACMERR("header oversize\n");
				return IPACM_FAILURE;
			}
			else
			{
				if(sCopyHeader.is_eth2_ofst_valid)
				memcpy(backhaul_info.src_mac,
					(sCopyHeader.hdr)+(sCopyHeader.eth2_ofst)+6,
					IPA_MAC_ADDR_SIZE);
				else
				memcpy(backhaul_info.src_mac, (sCopyHeader.hdr)+6,
					IPA_MAC_ADDR_SIZE);
			}
			break;
		}
	}

	backhaul_ip=wan_v4_addr;
	uint8_t backhaul_ep=tx_prop->tx[0].dst_pipe;
	IPACMDBG_H("Sending QMI to modem for second backhaul netdev:%s, \
			backhaul_ip:%x, backhaul_ep: %d \n",
			dev_name,backhaul_ip,backhaul_ep);
	IPACMDBG_H("SrcMAC %02x:%02x:%02x:%02x:%02x:%02x\n",
		backhaul_info.src_mac[0], backhaul_info.src_mac[1],backhaul_info.src_mac[2],
		backhaul_info.src_mac[3], backhaul_info.src_mac[4], backhaul_info.src_mac[5]);
	IPACMDBG_H("DstMAC %02x:%02x:%02x:%02x:%02x:%02x\n",
		backhaul_info.dst_mac[0], backhaul_info.dst_mac[1],backhaul_info.dst_mac[2],
		backhaul_info.dst_mac[3], backhaul_info.dst_mac[4], backhaul_info.dst_mac[5]);
	/*Send WAN_VLAN_UP to add NAT entry*/
	ipacm_event_vlan_pdn *wanup_vlan_data;
	wanup_vlan_data = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
	if(wanup_vlan_data == NULL)
	{
		IPACMERR("Unable to allocate memory\n");
		return IPACM_FAILURE;
	}

	memset(wanup_vlan_data, 0, sizeof(ipacm_event_vlan_pdn));
	wanup_vlan_data->mux_id = 0;
        wanup_vlan_data->iptype = IPA_IP_v4;
        wanup_vlan_data->VlanID = 0;
        wanup_vlan_data->ipv4_addr = (public_wan_v4_addr_set) ? public_wan_v4_addr : wan_v4_addr;
        IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_UP with below information:\n");
        IPACMDBG_H("iptype IPA_IP_v4, VlanID %d, mux_id %d, if num %d\n", 0, 0, ipa_if_num);
	evt_data.event = IPA_HANDLE_WAN_VLAN_PDN_UP;
        evt_data.evt_data = (void *)wanup_vlan_data;

        IPACM_EvtDispatcher::PostEvt(&evt_data);

	if(IPACM_Wan::second_backhaul_active==true)
	{
		IPACMDBG_H("Already sent QMI\n");
		return IPACM_SUCCESS;
	}

	if(false == m_filtering.Send_Second_backhaul_qmi(backhaul_info.src_mac,backhaul_info.dst_mac,backhaul_ip,backhaul_ep))
	{
		IPACMDBG_H("Send QMI to modem for second backhaul failed\n");
		return IPACM_FAILURE;
	}
	IPACMDBG_H("Sent QMI to modem for second backhaul Success\n");
	/*Now, after sending QMI, install DL filter rule on 2nd backhaul(ETH) pipe*/
	config_dft_firewall_rules(IPA_IP_v4);

	IPACM_Wan::second_backhaul_ipv4=backhaul_ip;
	IPACM_Wan::second_backhaul_active=true;
	return IPACM_SUCCESS;
}

int IPACM_Wan::handle_dual_backhaul_disable()
{
	if(IPACM_Wan::second_backhaul_active && IPACM_Wan::second_backhaul_ipv4 == wan_v4_addr)
	{
		ipa_dual_backhaul_info backhaul_info  = IPACM_Iface::ipacmcfg->second_backhaul_info;
		IPACMDBG_H("isWANUp: %d\n", IPACM_Wan::isWanUP(0));
		if(!strstr(dev_name, STR_ETH_IFACE))
		{
			IPACMDBG_H("Wrong WAN interface, ignore WAN_DOWN");
			return IPACM_FAILURE;
		}
		IPACMDBG_H("Disable second backhaul\n");
		if (rx_prop != NULL)
		{
			del_dft_firewall_rules(IPA_IP_v4);
		}
		ipacm_cmd_q_data evt_data;
		ipacm_event_vlan_pdn *vlandown_data;
		vlandown_data = (ipacm_event_vlan_pdn *)malloc(sizeof(ipacm_event_vlan_pdn));
		if(vlandown_data == NULL)
		{
			IPACMERR("Unable to allocate vlandown_data memory\n");
			return IPACM_FAILURE;
		}
		memset(vlandown_data, 0, sizeof(ipacm_event_vlan_pdn));

		vlandown_data->iptype = IPA_IP_v4;
		vlandown_data->VlanID = 0;
		vlandown_data->ipv4_addr = second_backhaul_ipv4;
		vlandown_data->mux_id = 0;

		IPACMDBG_H("Posting IPA_HANDLE_WAN_VLAN_PDN_DOWN with below information:\n");
		IPACMDBG_H("iptype IPA_IP_v4, if num %d\n", ipa_if_num);

		IPACM_Wan::second_backhaul_active=false;
		IPACM_Wan::second_backhaul_ipv4=0;

		evt_data.event = IPA_HANDLE_WAN_VLAN_PDN_DOWN;
		evt_data.evt_data = (void *)vlandown_data;

		bool_dual_backhaul = 1;

		IPACM_EvtDispatcher::PostEvt(&evt_data);
	}
	return IPACM_SUCCESS;
}
#endif
/* handle STA WAN-client */
/* handle WAN client initial, construct full headers (tx property) */
int IPACM_Wan::handle_wan_hdr_init(uint8_t *mac_addr, bool gw_addr)
{

#define WAN_IFACE_INDEX_LEN 10

	int res = IPACM_SUCCESS, len = 0;
	char index[WAN_IFACE_INDEX_LEN];
	struct ipa_ioc_copy_hdr sCopyHeader;
	struct ipa_ioc_add_hdr *pHeaderDescriptor = NULL;
	uint32_t cnt;
	int clnt_indx;
	uint16_t session_id;

	clnt_indx = get_wan_client_index(mac_addr);

	if (clnt_indx != IPACM_INVALID_INDEX)
	{
		IPACMERR("eth client is found/attached already with index %d \n", clnt_indx);
		return IPACM_FAILURE;
	}

	/* add header to IPA */
	if (num_wan_client >= IPA_MAX_NUM_WAN_CLIENTS)
	{
		IPACMERR("Reached maximum number(%d) of eth clients\n", IPA_MAX_NUM_WAN_CLIENTS);
		return IPACM_FAILURE;
	}

	/* Reserve entry for storing the GW address. */
	if ((num_wan_client >= (IPA_MAX_NUM_WAN_CLIENTS - 1)) && !gw_addr)
	{
		IPACMERR("Reached maximum number(%d) of eth clients without GW address\n", num_wan_client);
		return IPACM_FAILURE;
	}

	IPACMDBG_H("WAN client number: %d\n", num_wan_client);

	memcpy(get_client_memptr(wan_client, num_wan_client)->mac,
				 mac_addr,
				 sizeof(get_client_memptr(wan_client, num_wan_client)->mac));

	IPACMDBG_H("Received Client MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 mac_addr[0], mac_addr[1], mac_addr[2],
					 mac_addr[3], mac_addr[4], mac_addr[5]);

	IPACMDBG_H("stored MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 get_client_memptr(wan_client, num_wan_client)->mac[0],
					 get_client_memptr(wan_client, num_wan_client)->mac[1],
					 get_client_memptr(wan_client, num_wan_client)->mac[2],
					 get_client_memptr(wan_client, num_wan_client)->mac[3],
					 get_client_memptr(wan_client, num_wan_client)->mac[4],
					 get_client_memptr(wan_client, num_wan_client)->mac[5]);

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
#ifdef FEATURE_PPPOE
									/*Non-VLAN PPPoE*/
									if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable == true && is_ppp_iface)
									{
										session_id = IPACM_Iface::ipacmcfg->pppoe_get_session_id(dev_name);
										sCopyHeader.hdr_len = 22;
										pHeaderDescriptor->hdr[0].hdr[12] = (PPPOE_SESSION_ETH_TYPE >> 8) & 0xFF;
										pHeaderDescriptor->hdr[0].hdr[13] = PPPOE_SESSION_ETH_TYPE & 0xFF;
										pHeaderDescriptor->hdr[0].hdr[14] = 0x11;
										pHeaderDescriptor->hdr[0].hdr[15] = 0x00;
										pHeaderDescriptor->hdr[0].hdr[16] = (session_id >> 8) & 0xFF;
										pHeaderDescriptor->hdr[0].hdr[17] = session_id & 0xFF;
										pHeaderDescriptor->hdr[0].hdr[18] = 0x00;/* Payload length 2bytes update by uC */
										pHeaderDescriptor->hdr[0].hdr[19] = 0x00;
										pHeaderDescriptor->hdr[0].hdr[20] = (PPPOE_PROTOCOL_V4_TYPE >> 8) & 0xFF;/* PPPoE protocol 2bytes size */
										pHeaderDescriptor->hdr[0].hdr[21] = PPPOE_PROTOCOL_V4_TYPE & 0xFF;
									}
#endif
									if(sta_vlan_id > 0)
									{
											sCopyHeader.hdr_len = 18;
											/* VLAN ID is 12 bits. So update accordingly. */
											pHeaderDescriptor->hdr[0].hdr[15] = (uint8_t)sta_vlan_id & 0xFF;
											pHeaderDescriptor->hdr[0].hdr[14] = (uint8_t)(sta_vlan_id >> 8) & 0x0F;
											pHeaderDescriptor->hdr[0].hdr[13] = 0x00;
											pHeaderDescriptor->hdr[0].hdr[12] = 0x81;
											/* Update Ether Type to 0x800.*/
											pHeaderDescriptor->hdr[0].hdr[16] = 0x08;
											pHeaderDescriptor->hdr[0].hdr[17] = 0x00;
#ifdef FEATURE_PPPOE
											/*PPPoE*/
											if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable == true && is_ppp_iface)
											{
												session_id = IPACM_Iface::ipacmcfg->pppoe_get_session_id(dev_name);
												sCopyHeader.hdr_len = 26;
												pHeaderDescriptor->hdr[0].hdr[16] = (PPPOE_SESSION_ETH_TYPE >> 8) & 0xFF;
												pHeaderDescriptor->hdr[0].hdr[17] = PPPOE_SESSION_ETH_TYPE & 0xFF;
												pHeaderDescriptor->hdr[0].hdr[18] = 0x11;
												pHeaderDescriptor->hdr[0].hdr[19] = 0x00;
												pHeaderDescriptor->hdr[0].hdr[20] = (session_id >> 8) & 0xFF;
												pHeaderDescriptor->hdr[0].hdr[21] = session_id & 0xFF;
												pHeaderDescriptor->hdr[0].hdr[22] = 0x00;/* Payload length 2bytes update by uC */
												pHeaderDescriptor->hdr[0].hdr[23] = 0x00;
												pHeaderDescriptor->hdr[0].hdr[24] = (PPPOE_PROTOCOL_V4_TYPE >> 8) & 0xFF;/* PPPoE protocol 2bytes size */
												pHeaderDescriptor->hdr[0].hdr[25] = PPPOE_PROTOCOL_V4_TYPE & 0xFF;
											}
#endif
									}
									IPACMDBG_H("v4 sta_vlan_id %d \n",sta_vlan_id);
								}

								/* copy client mac_addr to partial header */
								IPACMDBG_H("header eth2_ofst_valid: %d, eth2_ofst: %d\n",
										sCopyHeader.is_eth2_ofst_valid, sCopyHeader.eth2_ofst);

								/* only copy 6 bytes mac-address */
								if(sCopyHeader.is_eth2_ofst_valid == false)
								{
									memcpy(&pHeaderDescriptor->hdr[0].hdr[0],
											mac_addr, IPA_MAC_ADDR_SIZE);
								}
								else
								{
									memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst],
											mac_addr, IPA_MAC_ADDR_SIZE);
								}


								pHeaderDescriptor->commit = true;
								pHeaderDescriptor->num_hdrs = 1;

								memset(pHeaderDescriptor->hdr[0].name, 0,
											 sizeof(pHeaderDescriptor->hdr[0].name));

								snprintf(index,sizeof(index), "%d_", ipa_if_num);
								strlcpy(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name));
								pHeaderDescriptor->hdr[0].name[IPA_RESOURCE_NAME_MAX-1] = '\0';
								if (strlcat(pHeaderDescriptor->hdr[0].name, IPA_WAN_PARTIAL_HDR_NAME_v4, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
								{
									IPACMERR(" header name construction failed exceed length (%d)\n", strlen(pHeaderDescriptor->hdr[0].name));
									res = IPACM_FAILURE;
									goto fail;
								}

								snprintf(index,sizeof(index), "_%d", header_name_count);
								if (strlcat(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
								{
									IPACMERR(" header name construction failed exceed length (%d)\n", strlen(pHeaderDescriptor->hdr[0].name));
									res = IPACM_FAILURE;
									goto fail;
								}

								pHeaderDescriptor->hdr[0].hdr_len = sCopyHeader.hdr_len;
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
					IPACMDBG_H("v4 pHeaderDescriptor->hdr[0].hdr_hdl : %x\n",pHeaderDescriptor->hdr[0].hdr_hdl);
					get_client_memptr(wan_client, num_wan_client)->hdr_hdl_v4 = pHeaderDescriptor->hdr[0].hdr_hdl;
					IPACMDBG_H("eth-client(%d) v4 full header name:%s header handle:(0x%x)\n",
												 num_wan_client,
												 pHeaderDescriptor->hdr[0].name,
												 get_client_memptr(wan_client, num_wan_client)->hdr_hdl_v4);
									get_client_memptr(wan_client, num_wan_client)->ipv4_header_set=true;

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
#ifdef FEATURE_PPPOE
					/*Non-VLAN PPPoE*/
					if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable == true && is_ppp_iface)
					{
						session_id = IPACM_Iface::ipacmcfg->pppoe_get_session_id(dev_name);
						sCopyHeader.hdr_len = 22;
						pHeaderDescriptor->hdr[0].hdr[12] = (PPPOE_SESSION_ETH_TYPE >> 8) & 0xFF;
						pHeaderDescriptor->hdr[0].hdr[13] = PPPOE_SESSION_ETH_TYPE & 0xFF;
						pHeaderDescriptor->hdr[0].hdr[14] = 0x11;
						pHeaderDescriptor->hdr[0].hdr[15] = 0x00;
						pHeaderDescriptor->hdr[0].hdr[16] = (session_id >> 8) & 0xFF;
						pHeaderDescriptor->hdr[0].hdr[17] = session_id & 0xFF;
						pHeaderDescriptor->hdr[0].hdr[18] = 0x00;/* Payload length 2bytes update by uC */
						pHeaderDescriptor->hdr[0].hdr[19] = 0x00;
						pHeaderDescriptor->hdr[0].hdr[20] = (PPPOE_PROTOCOL_V6_TYPE >> 8) & 0xFF;/* PPPoE protocol 2bytes size */
						pHeaderDescriptor->hdr[0].hdr[21] = PPPOE_PROTOCOL_V6_TYPE & 0xFF;
					}
#endif
					if(sta_vlan_id > 0)
					{
						sCopyHeader.hdr_len = 18;
						/* VLAN ID is 12 bits. So update accordingly. */
						pHeaderDescriptor->hdr[0].hdr[15] = (uint8_t)sta_vlan_id & 0xFF;
						pHeaderDescriptor->hdr[0].hdr[14] = (uint8_t)(sta_vlan_id >> 8) & 0x0F;
						pHeaderDescriptor->hdr[0].hdr[13] = 0x00;
						pHeaderDescriptor->hdr[0].hdr[12] = 0x81;
						/* Update Ether Type to 0x86dd.*/
						pHeaderDescriptor->hdr[0].hdr[16] = 0x86;
						pHeaderDescriptor->hdr[0].hdr[17] = 0xdd;
#ifdef FEATURE_PPPOE
						/*PPPoE*/
						if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable == true && is_ppp_iface)
						{
							session_id = IPACM_Iface::ipacmcfg->pppoe_get_session_id(dev_name);
							sCopyHeader.hdr_len = 26;
							pHeaderDescriptor->hdr[0].hdr[16] = (PPPOE_SESSION_ETH_TYPE >> 8) & 0xFF;
							pHeaderDescriptor->hdr[0].hdr[17] = PPPOE_SESSION_ETH_TYPE & 0xFF;
							pHeaderDescriptor->hdr[0].hdr[18] = 0x11;
							pHeaderDescriptor->hdr[0].hdr[19] = 0x00;
							pHeaderDescriptor->hdr[0].hdr[20] = (session_id >> 8) & 0xFF;
							pHeaderDescriptor->hdr[0].hdr[21] = session_id & 0xFF;
							pHeaderDescriptor->hdr[0].hdr[22] = 0x00;/* Payload length 2bytes update by uC */
							pHeaderDescriptor->hdr[0].hdr[23] = 0x00;
							pHeaderDescriptor->hdr[0].hdr[24] = (PPPOE_PROTOCOL_V6_TYPE >> 8) & 0xFF;/* PPPoE protocol 2bytes size */
							pHeaderDescriptor->hdr[0].hdr[25] = PPPOE_PROTOCOL_V6_TYPE & 0xFF;
						}
#endif
					}
					IPACMDBG_H("v6 sta_vlan_id %d \n",sta_vlan_id);
				}

				/* copy client mac_addr to partial header */
				if(sCopyHeader.is_eth2_ofst_valid == false)
				{
					memcpy(&pHeaderDescriptor->hdr[0].hdr[0],
								 mac_addr, IPA_MAC_ADDR_SIZE); /* only copy 6 bytes mac-address */
				}
				else
				{
					memcpy(&pHeaderDescriptor->hdr[0].hdr[sCopyHeader.eth2_ofst],
								 mac_addr, IPA_MAC_ADDR_SIZE); /* only copy 6 bytes mac-address */
				}


				pHeaderDescriptor->commit = true;
				pHeaderDescriptor->num_hdrs = 1;

				memset(pHeaderDescriptor->hdr[0].name, 0,
					 sizeof(pHeaderDescriptor->hdr[0].name));

				snprintf(index,sizeof(index), "%d_", ipa_if_num);
				strlcpy(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name));
				pHeaderDescriptor->hdr[0].name[IPA_RESOURCE_NAME_MAX-1] = '\0';
				if (strlcat(pHeaderDescriptor->hdr[0].name, IPA_WAN_PARTIAL_HDR_NAME_v6, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
				{
					IPACMERR(" header name construction failed exceed length (%d)\n", strlen(pHeaderDescriptor->hdr[0].name));
					res = IPACM_FAILURE;
					goto fail;
				}
				snprintf(index,sizeof(index), "_%d", header_name_count);
				if (strlcat(pHeaderDescriptor->hdr[0].name, index, sizeof(pHeaderDescriptor->hdr[0].name)) > IPA_RESOURCE_NAME_MAX)
				{
					IPACMERR(" header name construction failed exceed length (%d)\n", strlen(pHeaderDescriptor->hdr[0].name));
					res = IPACM_FAILURE;
					goto fail;
				}

				pHeaderDescriptor->hdr[0].hdr_len = sCopyHeader.hdr_len;
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
				IPACMDBG_H("v6 pHeaderDescriptor->hdr[0].hdr_hdl : %x\n",pHeaderDescriptor->hdr[0].hdr_hdl);
				get_client_memptr(wan_client, num_wan_client)->hdr_hdl_v6 = pHeaderDescriptor->hdr[0].hdr_hdl;
				IPACMDBG_H("eth-client(%d) v6 full header name:%s header handle:(0x%x)\n",
						 num_wan_client,
						 pHeaderDescriptor->hdr[0].name,
									 get_client_memptr(wan_client, num_wan_client)->hdr_hdl_v6);

									get_client_memptr(wan_client, num_wan_client)->ipv6_header_set=true;

				break;

			}
		}
#ifdef FEATURE_PPPOE
			/* Construct PPPoE ProcCtx */
			if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable == true && is_ppp_iface)
			{
				pppoe_make_hdr_add_ctx(IPA_IP_v4);
				pppoe_make_hdr_add_ctx(IPA_IP_v6);
			}
#endif
		/* initialize STA-WAN client*/
		get_client_memptr(wan_client, num_wan_client)->route_rule_set_v4 = false;
		get_client_memptr(wan_client, num_wan_client)->route_rule_set_v6 = 0;
		get_client_memptr(wan_client, num_wan_client)->ipv4_set = false;
		get_client_memptr(wan_client, num_wan_client)->ipv6_set = 0;
		num_wan_client++;
		header_name_count++; //keep increasing header_name_count
		res = IPACM_SUCCESS;
		IPACMDBG_H("eth client number: %d\n", num_wan_client);
	}
	else
	{
		return res;
	}
fail:
	free(pHeaderDescriptor);

	return res;
}

/*handle eth client */
int IPACM_Wan::handle_wan_client_ipaddr(ipacm_event_data_all *data)
{
	int clnt_indx, size = 0;
	int v6_num;
	std::array<uint32_t, 4> ipv6 = {0};

	IPACMDBG_H("number of wan clients: %d\n", num_wan_client);
	IPACMDBG_H(" event MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
					 data->mac_addr[0],
					 data->mac_addr[1],
					 data->mac_addr[2],
					 data->mac_addr[3],
					 data->mac_addr[4],
					 data->mac_addr[5]);

	clnt_indx = get_wan_client_index(data->mac_addr);

		if (clnt_indx == IPACM_INVALID_INDEX)
		{
			IPACMERR("wan client not found/attached \n");
			return IPACM_FAILURE;
		}

	IPACMDBG_H("Ip-type received %d\n", data->iptype);
	if (data->iptype == IPA_IP_v4)
	{
		IPACMDBG_H("ipv4 address: 0x%x\n", data->ipv4_addr);
		if (data->ipv4_addr != 0) /* not 0.0.0.0 */
		{
			if (get_client_memptr(wan_client, clnt_indx)->ipv4_set == false)
			{
				get_client_memptr(wan_client, clnt_indx)->v4_addr = data->ipv4_addr;
				get_client_memptr(wan_client, clnt_indx)->ipv4_set = true;
				/* Add NAT rules after ipv4 RT rules are set */
				CtList->HandleSTAClientAddEvt(data->ipv4_addr);
			}
			else
			{
			   /* check if client got new IPv4 address*/
			   if(data->ipv4_addr == get_client_memptr(wan_client, clnt_indx)->v4_addr)
			   {
			     IPACMDBG_H("Already setup ipv4 addr for client:%d, ipv4 address didn't change\n", clnt_indx);
				 return IPACM_FAILURE;
			   }
			   else
			   {
					IPACMDBG_H("ipv4 addr for client:%d is changed \n", clnt_indx);
					/* Del NAT rules before ipv4 RT rules are delete */
					CtList->HandleSTAClientDelEvt(get_client_memptr(wan_client, clnt_indx)->v4_addr);
					delete_wan_rtrules(clnt_indx,IPA_IP_v4);
					get_client_memptr(wan_client, clnt_indx)->route_rule_set_v4 = false;
					get_client_memptr(wan_client, clnt_indx)->v4_addr = data->ipv4_addr;
					/* Add NAT rules after ipv4 RT rules are set */
					CtList->HandleSTAClientAddEvt(data->ipv4_addr);
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
		/* check if all 0 not valid ipv6 address */
		if (data->ipv6_addr[0] || data->ipv6_addr[1] || data->ipv6_addr[2] || data->ipv6_addr[3])
		{
			IPACMDBG_H("ipv6 address: 0x%x:%x:%x:%x\n", data->ipv6_addr[0], data->ipv6_addr[1], data->ipv6_addr[2], data->ipv6_addr[3]);
			if(IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6 < IPA_MAX_NUM_CLIENTS_IPV6)
			{
				IPACMDBG_H("eth client:%d, current ipv6:%d, v6_route_set:%d, total_client_ipv6: %d, limit %d\n",
					clnt_indx, get_client_memptr(wan_client, clnt_indx)->ipv6_set,
					get_client_memptr(wan_client, clnt_indx)->route_rule_set_v6,
					IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6, IPA_MAX_NUM_CLIENTS_IPV6);
				std::copy(std::begin(data->ipv6_addr), std::end(data->ipv6_addr), std::begin(ipv6));

				/* never see this ipv6, insert to the map*/
				if(rt_hdl_v6_list[clnt_indx].count(ipv6) == 0)
				{
					/*
					 * The client got new IPv6 address.
					 * NOTE: The new address doesn't replace the existing one but being added (up to IPA_MAX_NUM_CLIENTS_IPV6),
					 *       so the previous IPv6 addresses of the client will not be deleted.
					 */
					rt_hdl_v6_list[clnt_indx].insert(std::make_pair(ipv6, handleTypeV6(iface_query->num_tx_props)));
					/* indicate how many ipv6 client gets */
					get_client_memptr(wan_client, clnt_indx)->ipv6_set++;
					IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6++;
					CtList->HandleSTAClientAddEvt_v6(Ipv6IpAddress(data->ipv6_addr, false));
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

/*handle wan client routing rule*/
int IPACM_Wan::handle_wan_client_route_rule(uint8_t *mac_addr, ipa_ip_type iptype)
{
	struct ipa_ioc_add_rt_rule *rt_rule;
	struct ipa_rt_rule_add *rt_rule_entry;
	uint32_t tx_index;
	int wan_index,v6_num;
	const int NUM = 1;

	if(tx_prop == NULL)
	{
		IPACMDBG_H("No rx properties registered for iface %s\n", dev_name);
		return IPACM_SUCCESS;
	}

	IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
			mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5]);

	wan_index = get_wan_client_index(mac_addr);
	if (wan_index == IPACM_INVALID_INDEX)
	{
		IPACMDBG_H("wan client not found/attached \n");
		return IPACM_SUCCESS;
	}

	if (iptype==IPA_IP_v4) {
		IPACMDBG_H("wan client index: %d, ip-type: %d, ipv4_set:%d, ipv4_rule_set:%d \n", wan_index, iptype,
				get_client_memptr(wan_client, wan_index)->ipv4_set,
				get_client_memptr(wan_client, wan_index)->route_rule_set_v4);
	} else {
		IPACMDBG_H("wan client index: %d, ip-type: %d, ipv6_set:%d, ipv6_rule_num:%d \n", wan_index, iptype,
				get_client_memptr(wan_client, wan_index)->ipv6_set,
				get_client_memptr(wan_client, wan_index)->route_rule_set_v6);
	}

	/* Add default routing rules if not set yet */
	if ((iptype == IPA_IP_v4
				&& get_client_memptr(wan_client, wan_index)->route_rule_set_v4 == false
				&& get_client_memptr(wan_client, wan_index)->ipv4_set == true)
			|| (iptype == IPA_IP_v6
				&& get_client_memptr(wan_client, wan_index)->route_rule_set_v6 < get_client_memptr(wan_client, wan_index)->ipv6_set
			   ))
	{
		if(IPACM_Iface::ipacmcfg->GetIPAVer() >= IPA_HW_None && IPACM_Iface::ipacmcfg->GetIPAVer() < IPA_HW_v4_0)
		{
			/* Add corresponding ipa_rm_resource_name of TX-endpoint up before IPV6 RT-rule set */
			IPACMDBG_H("dev %s add producer dependency\n", dev_name);
			IPACMDBG_H("depend Got pipe %d rm index : %d \n", tx_prop->tx[0].dst_pipe, IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe]);
			IPACM_Iface::ipacmcfg->AddRmDepend(IPACM_Iface::ipacmcfg->ipa_client_rm_map_tbl[tx_prop->tx[0].dst_pipe],false);
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
				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", wan_index,
						get_client_memptr(wan_client, wan_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
						wan_index,
						get_client_memptr(wan_client, wan_index)->hdr_hdl_v4);
				strlcpy(rt_rule->rt_tbl_name,
						IPACM_Iface::ipacmcfg->rt_tbl_wan_v4.name,
						sizeof(rt_rule->rt_tbl_name));
				rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
				if (IPACM_Iface::ipacmcfg->isMCC_Mode == true)
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
#ifdef FEATURE_PPPOE
				if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable == true && is_ppp_iface)
				{
					rt_rule_entry->rule.hdr_proc_ctx_hdl = v4_p_ctx_2use;
					IPACMDBG_H("v4 rt_rule_entry->rule.hdr_proc_ctx_hdl %x\n",rt_rule_entry->rule.hdr_proc_ctx_hdl);
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
					/*With Wan IP*/
					rt_rule_entry->rule.attrib.u.v4.src_addr = wan_v4_addr;
					rt_rule_entry->rule.attrib.u.v4.src_addr_mask = 0xFFFFFFFF;
				}
				else
#endif
				{
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.hdr_hdl = get_client_memptr(wan_client, wan_index)->hdr_hdl_v4;
					rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(wan_client, wan_index)->v4_addr;
					rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
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

				/* copy ipv4 RT hdl */
				get_client_memptr(wan_client, wan_index)->wan_rt_hdl[tx_index].wan_rt_rule_hdl_v4 =
					rt_rule->rules[0].rt_rule_hdl;
				IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
						get_client_memptr(wan_client, wan_index)->wan_rt_hdl[tx_index].wan_rt_rule_hdl_v4, iptype);
			} else {
				for (auto it = rt_hdl_v6_list[wan_index].begin(); it != rt_hdl_v6_list[wan_index].end(); ++it)
				{
					if (it->second.route_rule_set_v6 == true)
					{
						IPACMDBG("client(%d): v6 addr : 0x%08x:%08x:%08x:%08x, v6_set already (%d)\n",
						wan_index,
						it->first[0], it->first[1], it->first[2], it->first[3],
						it->second.route_rule_set_v6);
						continue;
					}

					IPACMDBG_H("client-index(%d): v6 header handle:(0x%x), v6 addr : 0x%08x:%08x:%08x:%08x\n",
						wan_index, get_client_memptr(wan_client, wan_index)->hdr_hdl_v6,
						it->first[0], it->first[1], it->first[2], it->first[3]);

					/* v6 LAN_RT_TBL */
					strlcpy(rt_rule->rt_tbl_name,
							IPACM_Iface::ipacmcfg->rt_tbl_v6.name,
							sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Uplink going to wan clients should go to IPA */
					if (IPACM_Iface::ipacmcfg->isMCC_Mode == true)
					{
						IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
								tx_prop->tx[tx_index].alt_dst_pipe);
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
					}
					else
					{
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
					}
					memset(&rt_rule_entry->rule.attrib, 0, sizeof(rt_rule_entry->rule.attrib));
#ifdef FEATURE_PPPOE
					if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable == true)
					{
						rt_rule_entry->rule.hdr_proc_ctx_hdl = v6_p_ctx_2use;
						IPACMDBG_H("v6 rt_rule_entry->rule.hdr_proc_ctx_hdl %x\n",rt_rule_entry->rule.hdr_proc_ctx_hdl);
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
						rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
						if(active_v6)
						{
							rt_rule_entry->rule.attrib.u.v6.src_addr[0] = m_ipv6_addr[0];
							rt_rule_entry->rule.attrib.u.v6.src_addr[1] = m_ipv6_addr[1];
							rt_rule_entry->rule.attrib.u.v6.src_addr[2] = 0x00000000;
							rt_rule_entry->rule.attrib.u.v6.src_addr[3] = 0x00000000;
							rt_rule_entry->rule.attrib.u.v6.src_addr_mask[0] = 0xFFFFFFFF;
							rt_rule_entry->rule.attrib.u.v6.src_addr_mask[1] = 0xFFFFFFFF;
							rt_rule_entry->rule.attrib.u.v6.src_addr_mask[2] = 0x00000000;
							rt_rule_entry->rule.attrib.u.v6.src_addr_mask[3] = 0x00000000;
						}
						else
						{
							IPACMERR("v6 STA WAN s not up yet!!!(%d)\n", active_v6);
							free(rt_rule);
							return IPACM_FAILURE;
						}
					}
					else
#endif
					{
						rt_rule_entry->rule.hdr_hdl = get_client_memptr(wan_client, wan_index)->hdr_hdl_v6;
						rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
						rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = it->first[0];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = it->first[1];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = it->first[2];
						rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = it->first[3];
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
						rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
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

					it->second.hdl_v6[tx_index].rt_rule_hdl_v6 = rt_rule->rules[0].rt_rule_hdl;
					IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d\n", tx_index,
							it->second.hdl_v6[tx_index].rt_rule_hdl_v6, iptype);

					/*Copy same rule to v6 WAN RT TBL*/
					strlcpy(rt_rule->rt_tbl_name,
							IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name,
							sizeof(rt_rule->rt_tbl_name));
					rt_rule->rt_tbl_name[IPA_RESOURCE_NAME_MAX-1] = '\0';
					/* Downlink traffic from Wan clients, should go exception */
					rt_rule_entry->rule.dst = iface_query->excp_pipe;
					memcpy(&rt_rule_entry->rule.attrib,
							&tx_prop->tx[tx_index].attrib,
							sizeof(rt_rule_entry->rule.attrib));
					rt_rule_entry->rule.hdr_hdl = 0;
					rt_rule_entry->rule.hdr_proc_ctx_hdl = 0;
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = it->first[0];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = it->first[1];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = it->first[2];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = it->first[3];
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;
					if (false == m_routing.AddRoutingRule(rt_rule))
					{
						IPACMERR("Routing rule addition failed!\n");
						free(rt_rule);
						return IPACM_FAILURE;
					}

					it->second.hdl_v6[tx_index].rt_rule_hdl_v6_wan = rt_rule->rules[0].rt_rule_hdl;
					/* mark as route_rule_set_v6 = true*/
					if (tx_index + 1 == iface_query->num_tx_props)
						it->second.route_rule_set_v6 = true;

					IPACMDBG_H("tx:%d, rt rule hdl=%x ip-type: %d route_rule_set_v6(map) %d\n", tx_index,
							it->second.hdl_v6[tx_index].rt_rule_hdl_v6_wan, iptype,
							it->second.route_rule_set_v6);
				} /* v6 map loop */
			} /* ipv6 handling */
		} /* end of for loop */

		free(rt_rule);

		if (iptype == IPA_IP_v4)
		{
			get_client_memptr(wan_client, wan_index)->route_rule_set_v4 = true;
		}
		else
		{
			get_client_memptr(wan_client, wan_index)->route_rule_set_v6 = get_client_memptr(wan_client, wan_index)->ipv6_set;
		}
	}

	return IPACM_SUCCESS;
}

/* TODO Handle wan client routing rules also */
void IPACM_Wan::handle_wlan_SCC_MCC_switch(bool isSCCMode, ipa_ip_type iptype)
{
	struct ipa_ioc_mdfy_rt_rule *rt_rule = NULL;
	struct ipa_rt_rule_mdfy *rt_rule_entry;
	uint32_t tx_index = 0;

	IPACMDBG("\n");
	if (tx_prop == NULL || is_default_gateway == false)
	{
		IPACMDBG_H("No tx properties or no default route set yet\n");
		return;
	}

	const int NUM = tx_prop->num_tx_props;

	for (tx_index = 0; tx_index < tx_prop->num_tx_props; tx_index++)
	{
		if (tx_prop->tx[tx_index].ip != iptype)
		{
			IPACMDBG_H("Tx:%d, ip-type: %d ip-type not matching: %d Ignore\n",
					tx_index, tx_prop->tx[tx_index].ip, iptype);
			continue;
		}

		if (rt_rule == NULL)
		{
			rt_rule = (struct ipa_ioc_mdfy_rt_rule *)
				calloc(1, sizeof(struct ipa_ioc_mdfy_rt_rule) +
						NUM * sizeof(struct ipa_rt_rule_mdfy));

			if (rt_rule == NULL)
			{
				IPACMERR("Unable to allocate memory for modify rt rule\n");
				return;
			}
			IPACMDBG("Allocated memory for %d rules successfully\n", NUM);

			rt_rule->commit = 1;
			rt_rule->num_rules = 0;
			rt_rule->ip = iptype;
		}

		rt_rule_entry = &rt_rule->rules[rt_rule->num_rules];

		memcpy(&rt_rule_entry->rule.attrib,
				&tx_prop->tx[tx_index].attrib,
				sizeof(rt_rule_entry->rule.attrib));
		rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;

		if (iptype == IPA_IP_v4)
		{
			rt_rule_entry->rule.attrib.u.v4.dst_addr      = 0;
			rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0;
			rt_rule_entry->rule.hdr_hdl = hdr_hdl_sta_v4;
			rt_rule_entry->rt_rule_hdl = wan_route_rule_v4_hdl[tx_index];
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

			rt_rule_entry->rule.hdr_hdl = hdr_hdl_sta_v6;
			rt_rule_entry->rt_rule_hdl = wan_route_rule_v6_hdl[tx_index];
		}
		IPACMDBG_H("Header handle: 0x%x\n", rt_rule_entry->rule.hdr_hdl);

		if (isSCCMode)
		{
			rt_rule_entry->rule.dst = tx_prop->tx[tx_index].dst_pipe;
		}
		else
		{
			IPACMDBG_H("In MCC mode, use alt dst pipe: %d\n",
					tx_prop->tx[tx_index].alt_dst_pipe);
			rt_rule_entry->rule.dst = tx_prop->tx[tx_index].alt_dst_pipe;
		}

		rt_rule->num_rules++;
	}

	if (rt_rule != NULL)
	{

		if (rt_rule->num_rules > 0)
		{
			if (false == m_routing.ModifyRoutingRule(rt_rule))
			{
				IPACMERR("Routing rule modify failed!\n");
				free(rt_rule);
				return;
			}

			IPACMDBG("Routing rule modified successfully \n");
		}

		free(rt_rule);
	}

	return;
}

void IPACM_Wan::handle_wan_client_SCC_MCC_switch(bool isSCCMode, ipa_ip_type iptype)
{
	struct ipa_ioc_mdfy_rt_rule *rt_rule = NULL;
	struct ipa_rt_rule_mdfy *rt_rule_entry;

	uint32_t tx_index = 0, clnt_index =0;
	int v6_num = 0;
	const int NUM_RULES = 1;

	int size = sizeof(struct ipa_ioc_mdfy_rt_rule) +
		NUM_RULES * sizeof(struct ipa_rt_rule_mdfy);

	IPACMDBG("\n");

	if (tx_prop == NULL || is_default_gateway == false)
	{
		IPACMDBG_H("No tx properties or no default route set yet\n");
		return;
	}

	rt_rule = (struct ipa_ioc_mdfy_rt_rule *)calloc(1, size);
	if (rt_rule == NULL)
	{
		IPACMERR("Unable to allocate memory for modify rt rule\n");
		return;
	}


	for (clnt_index = 0; clnt_index < num_wan_client; clnt_index++)
	{
		if (iptype == IPA_IP_v4)
		{
			IPACMDBG_H("wan client index: %d, ip-type: %d, ipv4_set:%d, ipv4_rule_set:%d \n",
					clnt_index, iptype,
					get_client_memptr(wan_client, clnt_index)->ipv4_set,
					get_client_memptr(wan_client, clnt_index)->route_rule_set_v4);

			if( get_client_memptr(wan_client, clnt_index)->route_rule_set_v4 == false ||
					get_client_memptr(wan_client, clnt_index)->ipv4_set == false)
			{
				continue;
			}

			for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
				if (iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d skip\n",
							tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}

				memset(rt_rule, 0, size);
				rt_rule->commit = 1;
				rt_rule->num_rules = NUM_RULES;
				rt_rule->ip = iptype;
				rt_rule_entry = &rt_rule->rules[0];

				IPACMDBG_H("client index(%d):ipv4 address: 0x%x\n", clnt_index,
						get_client_memptr(wan_client, clnt_index)->v4_addr);

				IPACMDBG_H("client(%d): v4 header handle:(0x%x)\n",
						clnt_index,
						get_client_memptr(wan_client, clnt_index)->hdr_hdl_v4);

				if (IPACM_Iface::ipacmcfg->isMCC_Mode == true)
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

				rt_rule_entry->rule.hdr_hdl = get_client_memptr(wan_client, clnt_index)->hdr_hdl_v4;
				rt_rule_entry->rule.attrib.u.v4.dst_addr = get_client_memptr(wan_client, clnt_index)->v4_addr;
				rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;

				/* copy ipv4 RT rule hdl */
				IPACMDBG_H("rt rule hdl=%x\n",
						get_client_memptr(wan_client, clnt_index)->wan_rt_hdl[tx_index].wan_rt_rule_hdl_v4);

				rt_rule_entry->rt_rule_hdl =
					get_client_memptr(wan_client, clnt_index)->wan_rt_hdl[tx_index].wan_rt_rule_hdl_v4;

				if (false == m_routing.ModifyRoutingRule(rt_rule))
				{
					IPACMERR("Routing rule modify failed!\n");
					free(rt_rule);
					return;
				}
			}
		}
		else
		{
			IPACMDBG_H("wan client index: %d, ip-type: %d, ipv6_set:%d, ipv6_rule_num:%d \n", clnt_index, iptype,
					get_client_memptr(wan_client, clnt_index)->ipv6_set,
					get_client_memptr(wan_client, clnt_index)->route_rule_set_v6);

			if( get_client_memptr(wan_client, clnt_index)->route_rule_set_v6 == 0)
			{
				continue;
			}

			for (tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
			{
				if (iptype != tx_prop->tx[tx_index].ip)
				{
					IPACMDBG_H("Tx:%d, ip-type: %d conflict ip-type: %d skip\n",
							tx_index, tx_prop->tx[tx_index].ip, iptype);
					continue;
				}

				memset(rt_rule, 0, size);
				rt_rule->commit = 1;
				rt_rule->num_rules = NUM_RULES;
				rt_rule->ip = iptype;
				rt_rule_entry = &rt_rule->rules[0];

				/* Modify only rules in v6 WAN RT TBL*/
				for (auto it = rt_hdl_v6_list[clnt_index].begin(); it != rt_hdl_v6_list[clnt_index].end();++it)
				{
					IPACMDBG_H("client(%d): v6 header handle:(0x%x)\n",
							clnt_index,
							get_client_memptr(wan_client, clnt_index)->hdr_hdl_v6);

					/* Downlink traffic from Wan iface, directly through IPA */
					if (IPACM_Iface::ipacmcfg->isMCC_Mode == true)
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

					rt_rule_entry->rule.hdr_hdl = get_client_memptr(wan_client, clnt_index)->hdr_hdl_v6;
					rt_rule_entry->rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					rt_rule_entry->rule.attrib.u.v6.dst_addr[0] = it->first[0];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[1] = it->first[1];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[2] = it->first[2];
					rt_rule_entry->rule.attrib.u.v6.dst_addr[3] = it->first[3];
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[0] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[1] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[2] = 0xFFFFFFFF;
					rt_rule_entry->rule.attrib.u.v6.dst_addr_mask[3] = 0xFFFFFFFF;

					IPACMDBG_H("rt rule hdl=%x rt rule hdl_wan=%x\n",
						it->second.hdl_v6[tx_index].rt_rule_hdl_v6,
						it->second.hdl_v6[tx_index].rt_rule_hdl_v6_wan);

					rt_rule_entry->rt_rule_hdl = it->second.hdl_v6[tx_index].rt_rule_hdl_v6;
					if (false == m_routing.ModifyRoutingRule(rt_rule))
					{
						IPACMERR("Routing rule Modify failed!\n");
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
				}
			} /* end of for loop */
		}

	}

	if(rt_rule)
	{
		free(rt_rule);
	}
	return;
}

/*handle eth client */
int IPACM_Wan::handle_network_stats_update(ipa_get_apn_data_stats_resp_msg_v01 *data)
{
	FILE *fp = NULL;

	for (int apn_index =0; apn_index < data->apn_data_stats_list_len; apn_index++)
	{
		if(data->apn_data_stats_list[apn_index].mux_id == ext_prop->ext[0].mux_id)
		{
			IPACMDBG_H("Received IPA_TETHERING_STATS_UPDATE_NETWORK_STATS, MUX ID %u TX (P%llu/B%llu) RX (P%llu/B%llu)\n",
				data->apn_data_stats_list[apn_index].mux_id,
					data->apn_data_stats_list[apn_index].num_ul_packets,
						data->apn_data_stats_list[apn_index].num_ul_bytes,
							data->apn_data_stats_list[apn_index].num_dl_packets,
								data->apn_data_stats_list[apn_index].num_dl_bytes);
			fp = fopen(IPA_NETWORK_STATS_FILE_NAME, "w");
			if ( fp == NULL )
			{
				IPACMERR("Failed to write pipe stats to %s, error is %d - %s\n",
						IPA_NETWORK_STATS_FILE_NAME, errno, strerror(errno));
				return IPACM_FAILURE;
			}

			fprintf(fp, NETWORK_STATS,
				dev_name,
					data->apn_data_stats_list[apn_index].num_ul_packets,
						data->apn_data_stats_list[apn_index].num_ul_bytes,
							data->apn_data_stats_list[apn_index].num_dl_packets,
								data->apn_data_stats_list[apn_index].num_dl_bytes);
			fclose(fp);
			break;
		};
	}
	return IPACM_SUCCESS;
}

int IPACM_Wan::add_dummy_rx_hdr()
{

#define IFACE_INDEX_LEN 2
	char index[IFACE_INDEX_LEN];
	struct ipa_ioc_add_hdr *pHeaderDescriptor = NULL;
	int len = 0;
	struct ipa_ioc_copy_hdr sCopyHeader;
	struct ipa_hdr_add *ipv6_hdr;
	struct ethhdr *eth_ipv6;
	struct ipa_ioc_add_hdr_proc_ctx* pHeaderProcTable = NULL;
	uint32_t cnt;

	/* get netdev-mac */
	if(tx_prop != NULL)
	{
		/* copy partial header for v6 */
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
									return IPACM_FAILURE;
								}

								IPACMDBG_H("header length: %d, paritial: %d\n", sCopyHeader.hdr_len, sCopyHeader.is_partial);
								IPACMDBG_H("header eth2_ofst_valid: %d, eth2_ofst: %d\n", sCopyHeader.is_eth2_ofst_valid, sCopyHeader.eth2_ofst);
								if (sCopyHeader.hdr_len > IPA_HDR_MAX_SIZE)
								{
									IPACMERR("header oversize\n");
									return IPACM_FAILURE;
								}
								else
								{
									/* copy client mac_addr to partial header */
									IPACMDBG_H("header eth2_ofst_valid: %d, eth2_ofst: %d\n",
											sCopyHeader.is_eth2_ofst_valid, sCopyHeader.eth2_ofst);
									/* only copy 6 bytes mac-address */
									if(sCopyHeader.is_eth2_ofst_valid == false)
									{
										memcpy(netdev_mac, &sCopyHeader.hdr[0+IPA_MAC_ADDR_SIZE],
												sizeof(netdev_mac));
									}
									else
									{
										memcpy(netdev_mac, &sCopyHeader.hdr[sCopyHeader.eth2_ofst+IPA_MAC_ADDR_SIZE],
												sizeof(netdev_mac));
									}
								}
					break;
				}
		}
	}

	len = sizeof(struct ipa_ioc_add_hdr) + (1 * sizeof(struct ipa_hdr_add));
	pHeaderDescriptor = (struct ipa_ioc_add_hdr *)calloc(1, len);
	if (pHeaderDescriptor == NULL)
	{
		IPACMERR("calloc failed to allocate pHeaderDescriptor\n");
		return IPACM_FAILURE;
	}
	ipv6_hdr = &pHeaderDescriptor->hdr[0];
	/* copy ethernet type to header */
	eth_ipv6 = (struct ethhdr *) (ipv6_hdr->hdr +2);
	memcpy(eth_ipv6->h_dest, netdev_mac, ETH_ALEN);
	memcpy(eth_ipv6->h_source, ext_router_mac_addr, ETH_ALEN);
	eth_ipv6->h_proto = htons(ETH_P_IPV6);
	pHeaderDescriptor->commit = true;
	pHeaderDescriptor->num_hdrs = 1;

	memset(ipv6_hdr->name, 0,
			 sizeof(pHeaderDescriptor->hdr[0].name));

	snprintf(index,sizeof(index), "%d", ipa_if_num);
	strlcpy(ipv6_hdr->name, index, sizeof(ipv6_hdr->name));
	ipv6_hdr->name[IPA_RESOURCE_NAME_MAX-1] = '\0';

	if (strlcat(ipv6_hdr->name, IPA_DUMMY_ETH_HDR_NAME_v6, sizeof(ipv6_hdr->name)) > IPA_RESOURCE_NAME_MAX)
	{
		IPACMERR(" header name construction failed exceed length (%zu)\n", strlen(ipv6_hdr->name));
		return IPACM_FAILURE;
	}

	ipv6_hdr->hdr_len = ETH_HLEN + 2;
	ipv6_hdr->hdr_hdl = -1;
	ipv6_hdr->is_partial = 0;
	ipv6_hdr->status = -1;
	ipv6_hdr->type = IPA_HDR_L2_ETHERNET_II;

	if (m_header.AddHeader(pHeaderDescriptor) == false ||
			ipv6_hdr->status != 0)
	{
		IPACMERR("ioctl IPA_IOC_ADD_HDR failed: %d\n", ipv6_hdr->status);
		return IPACM_FAILURE;
	}

	hdr_hdl_dummy_v6 = ipv6_hdr->hdr_hdl;
	IPACMDBG_H("dummy v6 full header name:%s header handle:(0x%x)\n",
								 ipv6_hdr->name,
								 hdr_hdl_dummy_v6);
	/* add dummy hdr_proc_hdl */
	len = sizeof(struct ipa_ioc_add_hdr_proc_ctx) + sizeof(struct ipa_hdr_proc_ctx_add);
	pHeaderProcTable = (ipa_ioc_add_hdr_proc_ctx*)malloc(len);
	if(pHeaderProcTable == NULL)
	{
		IPACMERR("Cannot allocate header processing table.\n");
		return IPACM_FAILURE;
	}

	memset(pHeaderProcTable, 0, len);
	pHeaderProcTable->commit = 1;
	pHeaderProcTable->num_proc_ctxs = 1;
	pHeaderProcTable->proc_ctx[0].hdr_hdl = hdr_hdl_dummy_v6;
	if (m_header.AddHeaderProcCtx(pHeaderProcTable) == false)
	{
		IPACMERR("Adding dummy hhdr_proc_hdl failed with status: %d\n", pHeaderProcTable->proc_ctx[0].status);
		return IPACM_FAILURE;
	}
	else
	{
		hdr_proc_hdl_dummy_v6 = pHeaderProcTable->proc_ctx[0].proc_ctx_hdl;
		IPACMDBG_H("dummy hhdr_proc_hdl is added successfully. (0x%x)\n", hdr_proc_hdl_dummy_v6);
	}
	return IPACM_SUCCESS;
}
#ifdef FEATURE_L2TP
void IPACM_Wan::handle_l2tp_client_add(char *iface_name)
{
	int i;

	if(IPACM_Wan::num_v4_flt_rule >= IPA_MAX_FLT_RULE)
	{
		IPACMERR("Model DL flt rule has reached cap.\n");
		return;
	}

	for (i = IPACM_Wan::num_v4_flt_rule - 1; i >= m_ipv6_default_filterting_rules_count[0]; --i)
	{
#ifdef FEATURE_VLAN_MPDN
		pdn_flt_rule_v6[i+1] = pdn_flt_rule_v6[i];
#else
		flt_rule_v6[i+1] = flt_rule_v6[i];
#endif
	}
#ifdef FEATURE_VLAN_MPDN
	install_l2tp_flt_rule(pdn_flt_rule_v6, m_ipv6_default_filterting_rules_count[0], iface_name);
#else
	install_l2tp_flt_rule(flt_rule_v6, m_ipv6_default_filterting_rules_count[0], iface_name);
#endif
	IPACM_Wan::num_v6_flt_rule++;
	IPACMDBG_H("Now num of v6 dl flt rule is %d.\n", IPACM_Wan::num_v6_flt_rule);
	return;
}

void IPACM_Wan::handle_l2tp_client_del(char *iface_name)
{
	int i;
	l2tp_vlan_mapping_info info;
	uint32_t ipv6_addr[4];

	if(IPACM_Iface::ipacmcfg->get_vlan_l2tp_mapping(iface_name, info) == IPACM_FAILURE)
	{
		IPACMERR("Failed to find vlan-l2tp mapping.\n");
		return;
	}

	memcpy(ipv6_addr, info.vlan_client_ipv6_addr, sizeof(ipv6_addr));
	for(i=0; i<4; i++)
	{
		ipv6_addr[i] = htonl(ipv6_addr[i]);
	}

	for (i = m_ipv6_default_filterting_rules_count[0]; i < IPACM_Wan::num_v6_flt_rule; ++i)
	{
#ifdef FEATURE_VLAN_MPDN
		if( (pdn_flt_rule_v6[i].flt_rule.rule.attrib.attrib_mask | IPA_FLT_DST_ADDR)
			&& memcmp(pdn_flt_rule_v6[i].flt_rule.rule.attrib.u.v6.dst_addr, ipv6_addr,
				sizeof(pdn_flt_rule_v6[i].flt_rule.rule.attrib.u.v6.dst_addr)) == 0)
#else
		if( (flt_rule_v6[i].rule.attrib.attrib_mask | IPA_FLT_DST_ADDR)
			&& memcmp(flt_rule_v6[i].rule.attrib.u.v6.dst_addr, ipv6_addr,
				sizeof(flt_rule_v6[i].rule.attrib.u.v6.dst_addr)) == 0)
#endif
		{
			IPACMDBG_H("Found modem DL flt rule at position %d.\n", i);
			break;
		}
	}

	if(i == IPACM_Wan::num_v6_flt_rule)
	{
		IPACMERR("Failed to find the flt rule.\n");
		return;
	}

	for(; i < IPACM_Wan::num_v6_flt_rule - 1; i++)
	{
#ifdef FEATURE_VLAN_MPDN
		pdn_flt_rule_v6[i] = pdn_flt_rule_v6[i+1];
#else
		flt_rule_v6[i] = flt_rule_v6[i+1];
#endif
	}

	IPACM_Wan::num_v6_flt_rule--;
	IPACMDBG_H("Now the num of v6 dl flt rule is %d.\n", IPACM_Wan::num_v6_flt_rule);
	return;
}
#ifdef FEATURE_VLAN_MPDN
void IPACM_Wan::install_l2tp_flt_rule(ipacm_pdn_flt_rule* rules, int rule_offset, char *iface_name)
#else
void IPACM_Wan::install_l2tp_flt_rule(ipa_flt_rule_add* rules, int rule_offset, char *iface_name)
#endif
{
	l2tp_vlan_mapping_info info;
	ipa_flt_rule_add flt_rule_entry;
	ipa_ioc_generate_flt_eq flt_eq;
	ipa_ioc_get_rt_tbl_indx rt_tbl_idx;

	if(IPACM_Iface::ipacmcfg->get_vlan_l2tp_mapping(iface_name, info) == IPACM_FAILURE)
	{
		IPACMERR("Failed to find vlan-l2tp mapping.\n");
		return;
	}

	memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
	strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, IPA_RESOURCE_NAME_MAX);
	rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX-1] = '\0';
	rt_tbl_idx.ip = IPA_IP_v6;
	if(ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx) != 0)
	{
		IPACMERR("Failed to get routing table index from name\n");
		return;
	}

	IPACMDBG_H("WAN DL routing table %s has index %d\n", IPACM_Iface::ipacmcfg->rt_tbl_wan_v6.name, rt_tbl_idx.idx);

	memset(&flt_rule_entry, 0, sizeof(ipa_flt_rule_add));

	flt_rule_entry.at_rear = true;
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;

	flt_rule_entry.rule.retain_hdr = 0;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.eq_attrib_type = 1;
	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#ifdef FEATURE_IPA_V3
	flt_rule_entry.rule.hashable = true;
#endif
	flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;

	/* Configuring dest IP based filtering rule */
	memcpy(&flt_rule_entry.rule.attrib, &rx_prop->rx[1].attrib,
		sizeof(flt_rule_entry.rule.attrib));
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
	memcpy(flt_rule_entry.rule.attrib.u.v6.dst_addr, info.vlan_client_ipv6_addr,
		sizeof(flt_rule_entry.rule.attrib.u.v6.dst_addr));
	memset(flt_rule_entry.rule.attrib.u.v6.dst_addr_mask, 0xFF,
		sizeof(flt_rule_entry.rule.attrib.u.v6.dst_addr_mask));

	change_to_network_order(IPA_IP_v6, &flt_rule_entry.rule.attrib);

	memset(&flt_eq, 0, sizeof(flt_eq));
	memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
	flt_eq.ip = IPA_IP_v6;
	if(ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq) != 0)
	{
		IPACMERR("Failed to get eq_attrib\n");
		return;
	}

	memcpy(&flt_rule_entry.rule.eq_attrib, &flt_eq.eq_attrib,
		sizeof(flt_rule_entry.rule.eq_attrib));

	memcpy(&(rules[rule_offset]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));

	return;
}
#endif

void IPACM_Wan::HandleSTAClientDelEvt(const ipa_wan_client* client, int index)
{
	uint32_t ipv6_temp[4] = {0};

	if (client->ipv4_set == true)
	{
		CtList->HandleSTAClientDelEvt(client->v4_addr);
	}

	for (auto it = rt_hdl_v6_list[index].begin(); it != rt_hdl_v6_list[index].end();++it)
	{
		std::copy(std::begin(it->first), std::end(it->first), std::begin(ipv6_temp));
		CtList->HandleSTAClientDelEvt_v6(Ipv6IpAddress(ipv6_temp, false));
	}
}
#ifdef FEATURE_IPV6_NAT
/* Construct 2nd-pass v6NAT flt rule to send ULA destined packets to RT for STA mode */
int IPACM_Wan::add_ipv6_nat_ula_prefix_flt_rule(ipa_ioc_add_flt_rule *m_pFilteringTable)
{
	struct ipa_flt_rule_add flt_rule_entry;

	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

	const char* rt_tbl_name;
	ipa_ioc_get_rt_tbl_indx rt_tbl_idx;
	rt_tbl_name = ipacmcfg->rt_tbl_wan_v6.name;
	memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
	rt_tbl_idx.ip = IPA_IP_v6;
	strlcpy(rt_tbl_idx.name, rt_tbl_name, IPA_RESOURCE_NAME_MAX);
	rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
	if(ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx))
	{
		IPACMERR("Failed to get routing table index from name\n");
		return IPACM_FAILURE;
	}
	flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;
	IPACMDBG_H("Routing table %s has index %d\n", rt_tbl_idx.name, rt_tbl_idx.idx);

	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;

	flt_rule_entry.at_rear = true;
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;

	flt_rule_entry.rule.retain_hdr = 1;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.eq_attrib_type = 1;
#ifdef FEATURE_IPA_V3
	flt_rule_entry.rule.hashable = true;
#endif
	memcpy(&flt_rule_entry.rule.attrib,
		&rx_prop->rx[0].attrib,
		sizeof(struct ipa_rule_attrib));
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;

	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFF000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = 0xFD000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = 0X00000000;

	change_to_network_order(IPA_IP_v6, &flt_rule_entry.rule.attrib);

	memcpy(&(m_pFilteringTable->rules[0]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));

	if(false == m_filtering.AddFilteringRule(m_pFilteringTable))
	{
		IPACMERR("Error Adding Filtering rules, aborting...\n");
		return IPACM_FAILURE;
	}
	else
	{
		IPACM_Iface::ipacmcfg->increaseFltRuleCount(rx_prop->rx[0].src_pipe, IPA_IP_v6, 1);
		IPACMDBG_H("flt rule hdl0=0x%x, status=0x%x\n", m_pFilteringTable->rules[0].flt_rule_hdl, m_pFilteringTable->rules[0].status);
	}
	/* copy filter hdl */
	ipv6_ula_prefix_hdl = m_pFilteringTable->rules[0].flt_rule_hdl;
	return IPACM_SUCCESS;
}

/* Construct 2nd-pass v6NAT flt rule to send all ula destination address packets to routing */
#ifdef FEATURE_VLAN_MPDN
int IPACM_Wan::add_ipv6_nat_ula_prefix_flt_rule_ex(
	const struct ipa_rule_attrib& rx_prop_attrib,
	ipacm_pdn_flt_rule* rules, int fltr_rule_number)
#else
int IPACM_Wan::add_ipv6_nat_ula_prefix_flt_rule_ex(
	const struct ipa_rule_attrib& rx_prop_attrib,
	struct ipa_flt_rule_add *rules, int fltr_rule_number)
#endif

{
	IPACMDBG_H("\n");
	/* Check for "out of boundary" failure before adding a rule */
	if(fltr_rule_number >= IPA_MAX_FLT_RULE)
	{
		IPACMERR("Filtering table is full. Number of rules %d allowed %d\n", fltr_rule_number + 1, IPA_MAX_FLT_RULE);
		return IPACM_FAILURE;
	}

	struct ipa_flt_rule_add flt_rule_entry;
	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

	const char* rt_tbl_name;
	ipa_ioc_get_rt_tbl_indx rt_tbl_idx;
	rt_tbl_name = ipacmcfg->rt_tbl_wan_v6.name;
	memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
	rt_tbl_idx.ip = IPA_IP_v6;
	strlcpy(rt_tbl_idx.name, rt_tbl_name, IPA_RESOURCE_NAME_MAX);
	rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
	if(ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx))
	{
		IPACMERR("Failed to get routing table index from name\n");
		return IPACM_FAILURE;
	}
	flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;
	IPACMDBG_H("Routing table %s has index %d\n", rt_tbl_idx.name, rt_tbl_idx.idx);

	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;

	flt_rule_entry.at_rear = true;
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;

	flt_rule_entry.rule.retain_hdr = 1;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.eq_attrib_type = 1;
#ifdef FEATURE_IPA_V3
	flt_rule_entry.rule.hashable = true;
#endif
	memcpy(&flt_rule_entry.rule.attrib, &rx_prop_attrib, sizeof(struct ipa_rule_attrib));
	/* catch all rule applies to all NATed PDNs */
	flt_rule_entry.rule.attrib.attrib_mask = IPA_FLT_DST_ADDR;

	int *num_flt_rule;

	num_flt_rule = &num_v6_flt_rule;

	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0xFF000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = 0xFD000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = 0x00000000;
	flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = 0X00000000;
	change_to_network_order(IPA_IP_v6, &flt_rule_entry.rule.attrib);

	ipa_ioc_generate_flt_eq flt_eq;
	memset(&flt_eq, 0, sizeof(flt_eq));
	memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
	flt_eq.ip = IPA_IP_v6;
	if(ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
	{
		IPACMERR("Failed to get eq_attrib\n");
		return IPACM_FAILURE;
	}

	memcpy(&flt_rule_entry.rule.eq_attrib, &flt_eq.eq_attrib, sizeof(flt_rule_entry.rule.eq_attrib));
#ifdef FEATURE_VLAN_MPDN
	memcpy(&(rules[fltr_rule_number].flt_rule), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
	IPACMDBG_H("Filter rule attrib mask: 0x%x\n", rules[fltr_rule_number].flt_rule.rule.attrib.attrib_mask);
#else
	memcpy(&(rules[fltr_rule_number]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
	IPACMDBG_H("Filter rule attrib mask: 0x%x\n", rules[fltr_rule_number].rule.attrib.attrib_mask);
#endif

	++(*num_flt_rule);
	return IPACM_SUCCESS;
}
#endif // FEATURE_IPV6_NAT

int IPACM_Wan::add_catchup_all_filtering_rule_each_pdn(
	ipa_ip_type                   iptype,
	const struct ipa_rule_attrib& rx_prop_attrib,
	struct ipa_flt_rule_add&      flt_rule_add,
	int                           fltr_rule_number, bool isPmipv6 )
{
	if ( ! VALID_IPA_IP_TYPE(iptype) )
	{
		IPACMERR("Invalid IP type passed to function\n");
		return IPACM_FAILURE;
	}

	/* Check for "out of boundary" failure before adding a rule */
	if (fltr_rule_number >= IPA_MAX_FLT_RULE)
	{
		IPACMERR(
			"Filtering table is full. Number of rules %d allowed %d\n",
			fltr_rule_number + 1, IPA_MAX_FLT_RULE);
		return IPACM_FAILURE;
	}

#if defined(FEATURE_EoGRE) || defined(FEATURE_PMIPV6) || defined(FEATURE_IPoGRE)
	ipa_ipgre_info ipgre_info;
	if(isPmipv6){
		ipgre_info  = IPACM_Iface::ipacmcfg->ipgre_info;
	}
	else{
		ipgre_info  = IPACM_Iface::ipacmcfg->eogre_info;
	}
#endif
#ifdef FEATURE_EoGRE
	bool           doing_eogre = IPACM_Iface::ipacmcfg->eogre_enabled;
	/*
	 * If we're doing eogre and the iptype in the eogre matches what's
	 * been passed to this function, we've got relevant eogre work to
	 * do...
	 */
	bool compatible_eogre = ( doing_eogre && iptype == ipgre_info.iptype );
#else
	bool compatible_eogre = false;
#endif
#if defined(FEATURE_EoGRE) || defined(FEATURE_PMIPV6) || defined(FEATURE_IPoGRE)
	bool           doing_ipgre = isPmipv6;
	/*
	 * If we're doing eogre and the iptype in the eogre matches what's
	 * been passed to this function, we've got relevant eogre work to
	 * do...
	 */
	bool compatible_gre = ( doing_ipgre && iptype == ipgre_info.iptype && isPmipv6);
#else
	bool compatible_gre = false;
#endif
	IPACMDBG_H("Add catchup rule: isPmipv6:%d, compatible_gre:%d, pmipv6_enabled: %d \n",isPmipv6,compatible_gre,IPACM_Iface::ipacmcfg->pmip_details.pmipv6_enabled);
	struct ipa_flt_rule_add flt_rule_entry;
	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

	flt_rule_entry.at_rear = true;
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;

	flt_rule_entry.rule.retain_hdr = 1;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.eq_attrib_type = 1;
#ifdef FEATURE_IPA_V3
	flt_rule_entry.rule.hashable = true;
#endif
	memcpy(
		&flt_rule_entry.rule.attrib,
		&rx_prop_attrib,
		sizeof(struct ipa_rule_attrib));

	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;

	int *num_firewall, *num_flt_rule;
	const char* rt_tbl_name;

	if (iptype == IPA_IP_v4)
	{
		num_firewall = &num_firewall_v4;
		num_flt_rule = &num_v4_flt_rule;
#if defined(FEATURE_EoGRE) || defined(FEATURE_PMIPV6) || defined(FEATURE_IPoGRE)
		if (compatible_gre || compatible_eogre){
			flt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
			flt_rule_entry.rule.attrib.u.v4.dst_addr = ipgre_info.ipv4_src;

			flt_rule_entry.rule.attrib.u.v4.src_addr_mask = 0xFFFFFFFF;
			flt_rule_entry.rule.attrib.u.v4.src_addr = ipgre_info.ipv4_dst;

			flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
			if(isPmipv6)
			{
				flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_PROTOCOL;
				flt_rule_entry.rule.attrib.u.v4.protocol=(uint8_t)IPACM_FIREWALL_IPPROTO_GRE;
			}
			IPACMDBG_H("Adding GRE check v4\n");
			flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;

			rt_tbl_name = ipacmcfg->rt_tbl_lan_v4.name;
		}
		else{
#endif
flt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0x00000000;
			flt_rule_entry.rule.attrib.u.v4.dst_addr = 0x00000000;

				if (isWan_Bridge_Mode())
				{
					IPACMDBG_H("ODU is in bridge mode. \n");
					flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
					rt_tbl_name = ipacmcfg->rt_tbl_wan_dl.name;
				}
				else if (IPACM_Iface::ipacmcfg->is_public_ip_support_enabled)
				{
					IPACMDBG_H("Public IP enabled mode\n");
					flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
					rt_tbl_name = ipacmcfg->rt_tbl_lan_v4.name;
				}
				else
				{
					flt_rule_entry.rule.action = IPA_PASS_TO_DST_NAT;
					rt_tbl_name = ipacmcfg->rt_tbl_lan_v4.name;
				}
#if defined(FEATURE_EoGRE) || defined(FEATURE_PMIPV6) || defined(FEATURE_IPoGRE)
		}
			if(isPmipv6 || doing_ipgre)
			{
				flt_rule_entry.rule.action = IPA_PASS_TO_DST_NAT;
			}
#endif /* #ifdef FEATURE_EoGRE */
	}
	else /* (iptype == IPA_IP_v6) */
	{
		num_firewall = &num_firewall_v6;
		num_flt_rule = &num_v6_flt_rule;

		if ( ! (compatible_gre || compatible_eogre) )
		{
			flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[0] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[1] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[2] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr_mask[3] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr[0] = 0X00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr[1] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr[2] = 0x00000000;
			flt_rule_entry.rule.attrib.u.v6.dst_addr[3] = 0X00000000;
#ifdef FEATURE_IPV6_NAT
			if(IPACM_Iface::ipacmcfg->ipv6_nat_enable)
			{
				/* 1st pass rule, send all packets to destination nat */
				flt_rule_entry.rule.action = IPA_PASS_TO_DST_NAT;
				rt_tbl_name = ipacmcfg->rt_tbl_wan_v6.name;
			}
			else
#endif
			{

#ifndef FEATURE_SOCKSv5
					flt_rule_entry.rule.action = IPACM_Iface::ipacmcfg->IsIpv6CTEnabled() ?
						IPA_PASS_TO_DST_NAT : IPA_PASS_TO_ROUTING;

#else
					flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#endif
					rt_tbl_name = ipacmcfg->rt_tbl_wan_v6.name;
			}
		}
#if defined(FEATURE_EoGRE) || defined(FEATURE_PMIPV6) || defined(FEATURE_IPoGRE)
		else /* ( compatible_eogre ) */
		{
			memset(
				&flt_rule_entry.rule.attrib.u.v6.dst_addr_mask,
				0xFFFFFFFF,
				sizeof(flt_rule_entry.rule.attrib.u.v6.dst_addr_mask));
			memcpy(
				&flt_rule_entry.rule.attrib.u.v6.dst_addr,
				&ipgre_info.ipv6_src,
				sizeof(flt_rule_entry.rule.attrib.u.v6.dst_addr));
			memset(
				&flt_rule_entry.rule.attrib.u.v6.src_addr_mask,
				0xFFFFFFFF,
				sizeof(flt_rule_entry.rule.attrib.u.v6.src_addr_mask));
			memcpy(
				&flt_rule_entry.rule.attrib.u.v6.src_addr,
				&ipgre_info.ipv6_dst,
				sizeof(flt_rule_entry.rule.attrib.u.v6.src_addr));

			flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
			if(IPACM_Iface::ipacmcfg->eogre_enabled)
			{
				flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_NEXT_HDR;
				flt_rule_entry.rule.attrib.u.v6.next_hdr=(uint8_t)IPACM_FIREWALL_IPPROTO_GRE;
			}
			if(isPmipv6)
			{
				flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_NEXT_HDR;
				flt_rule_entry.rule.attrib.u.v6.next_hdr=(uint8_t)IPACM_FIREWALL_IPPROTO_GRE;
			}
			IPACMDBG_H("Adding GRE check v6\n");
			flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;

			rt_tbl_name = ipacmcfg->rt_tbl_wan_v6.name;
		}
#endif /* #ifdef FEATURE_EoGRE */
	}

	ipa_ioc_get_rt_tbl_indx rt_tbl_idx;
	memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
	rt_tbl_idx.ip = iptype;
	strlcpy(rt_tbl_idx.name, rt_tbl_name, IPA_RESOURCE_NAME_MAX);
	rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
	if (ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx))
	{
		IPACMERR("Failed to get routing table index from name\n");
		return IPACM_FAILURE;
	}
	flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;
	IPACMDBG_H("Routing table %s has index %d\n", rt_tbl_idx.name, rt_tbl_idx.idx);

	change_to_network_order(iptype, &flt_rule_entry.rule.attrib);

	ipa_ioc_generate_flt_eq flt_eq;
	memset(&flt_eq, 0, sizeof(flt_eq));
	memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
	flt_eq.ip = iptype;
	if (ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
	{
		IPACMERR("Failed to get eq_attrib\n");
		return IPACM_FAILURE;
	}

	memcpy(&flt_rule_entry.rule.eq_attrib, &flt_eq.eq_attrib, sizeof(flt_rule_entry.rule.eq_attrib));
	memcpy(&flt_rule_add, &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
	IPACMDBG_H("Filter rule attrib mask: 0x%x\n", flt_rule_add.rule.attrib.attrib_mask);

	++(*num_firewall);
	++(*num_flt_rule);

	return IPACM_SUCCESS;
}

int IPACM_Wan::add_ipv6_frag_filtering_rule_ex(const struct ipa_rule_attrib& rx_prop_attrib,
	struct ipa_flt_rule_add& flt_rule_add, int fltr_rule_number)
{
	/* Check for "out of boundary" failure before adding a rule */
	if (fltr_rule_number >= IPA_MAX_FLT_RULE)
	{
		IPACMERR("Filtering table is full. Number of rules %d allowed %d\n", fltr_rule_number + 1, IPA_MAX_FLT_RULE);
		return IPACM_FAILURE;
	}

	struct ipa_flt_rule_add flt_rule_entry;
	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));
	flt_rule_entry.at_rear = true;
#ifdef FEATURE_IPA_V3
	flt_rule_entry.at_rear = false;
#endif
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;

	flt_rule_entry.rule.retain_hdr = 1;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.eq_attrib_type = 1;
	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#ifdef FEATURE_IPA_V3
	flt_rule_entry.at_rear = false;
	flt_rule_entry.rule.hashable = false;
#endif

	ipa_ioc_get_rt_tbl_indx rt_tbl_idx;
	memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
	rt_tbl_idx.ip = IPA_IP_v6;
	strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_wan_dl.name, IPA_RESOURCE_NAME_MAX);
	rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
	if (ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx))
	{
		IPACMERR("Failed to get routing table index from name\n");
		return IPACM_FAILURE;
	}

	flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;
	IPACMDBG_H("IPv6 frag flt rule uses routing table index %d\n", rt_tbl_idx.idx);

	flt_rule_entry.rule.attrib.attrib_mask |= rx_prop_attrib.attrib_mask;
	flt_rule_entry.rule.attrib.meta_data_mask = rx_prop_attrib.meta_data_mask;
	flt_rule_entry.rule.attrib.meta_data = rx_prop_attrib.meta_data;
	flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_FRAGMENT;

	change_to_network_order(IPA_IP_v6, &flt_rule_entry.rule.attrib);

	ipa_ioc_generate_flt_eq flt_eq;
	memset(&flt_eq, 0, sizeof(flt_eq));
	memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
	flt_eq.ip = IPA_IP_v6;
	if (ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
	{
		IPACMERR("Failed to get eq_attrib\n");
		return IPACM_FAILURE;
	}

	memcpy(&flt_rule_entry.rule.eq_attrib, &flt_eq.eq_attrib, sizeof(flt_rule_entry.rule.eq_attrib));
	memcpy(&flt_rule_add, &flt_rule_entry, sizeof(struct ipa_flt_rule_add));

	++IPACM_Wan::num_v6_flt_rule;

	return IPACM_SUCCESS;
}

int IPACM_Wan::add_ipogre_frag_flt_rule_ex(
	const struct ipa_rule_attrib& rx_prop_attrib,
	struct ipa_flt_rule_add& flt_rule_add,
	int fltr_rule_number,
	ipa_ip_type iptype, bool outer, bool last_frag)
{
	ipa_ipgre_info ipgre_info = IPACM_Iface::ipacmcfg->ipgre_info;
	struct ipa_flt_rule_add flt_rule_entry;
	ipa_ioc_generate_flt_eq flt_eq;
	ipa_ioc_get_rt_tbl_indx rt_tbl_idx;

	IPACMDBG_H("Adding IPoGRE frag filter rule for iptype %d at position %d, last_frag %d\n",
		iptype, fltr_rule_number, last_frag);

	if (fltr_rule_number >= IPA_MAX_FLT_RULE)
	{
		IPACMERR("Filtering table is full. Number of rules %d allowed %d\n",
			fltr_rule_number + 1, IPA_MAX_FLT_RULE);
		return IPACM_FAILURE;
	}

	memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

	flt_rule_entry.at_rear = false;
	flt_rule_entry.flt_rule_hdl = -1;
	flt_rule_entry.status = -1;
	flt_rule_entry.rule.retain_hdr = 1;
	flt_rule_entry.rule.to_uc = 0;
	flt_rule_entry.rule.eq_attrib_type = 1;
	flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
#ifdef FEATURE_IPA_V3
	flt_rule_entry.rule.hashable = false;
#endif

	/* Set up src/dst address attributes matching the tunnel endpoints */
	memcpy(&flt_rule_entry.rule.attrib, &rx_prop_attrib,
		sizeof(flt_rule_entry.rule.attrib));
	if(outer == true)
	{
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_DST_ADDR;
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_SRC_ADDR;

		if (iptype == IPA_IP_v6)
		{
			memset(flt_rule_entry.rule.attrib.u.v6.src_addr_mask, 0xFF,
					sizeof(flt_rule_entry.rule.attrib.u.v6.src_addr_mask));
			memcpy(flt_rule_entry.rule.attrib.u.v6.src_addr, ipgre_info.ipv6_dst,
					sizeof(flt_rule_entry.rule.attrib.u.v6.src_addr));
			memset(flt_rule_entry.rule.attrib.u.v6.dst_addr_mask, 0xFF,
					sizeof(flt_rule_entry.rule.attrib.u.v6.dst_addr_mask));
			memcpy(flt_rule_entry.rule.attrib.u.v6.dst_addr, ipgre_info.ipv6_src,
					sizeof(flt_rule_entry.rule.attrib.u.v6.dst_addr));
		}
		else /* IPA_IP_v4 */
		{
			flt_rule_entry.rule.attrib.u.v4.src_addr_mask = 0xFFFFFFFF;
			flt_rule_entry.rule.attrib.u.v4.src_addr      = ipgre_info.ipv4_dst;
			flt_rule_entry.rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
			flt_rule_entry.rule.attrib.u.v4.dst_addr      = ipgre_info.ipv4_src;
		}

		/*
		 * For IPv4 last-fragment rules, include IPA_FLT_FRAGMENT in the attrib
		 * so that IPA_IOC_GENERATE_FLT_EQ generates the "any fragment" detection
		 * equation (offset!=0 OR MF=1) together with the address equations in a
		 * single call.  The MF=0 offset_meq_32 check added below then narrows
		 * the match to last fragments only (offset!=0 AND MF=0).
		 */
		if (last_frag && iptype == IPA_IP_v4)
		{
			flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_FRAGMENT;
		}

		/*
		 * Generate equation attributes from the attrib structure.
		 * For IPv6: converts src/dst tunnel addresses into offset_meq_128 entries.
		 * For IPv4: converts src/dst tunnel addresses into offset_meq_32 entries.
		 * Both are required when eq_attrib_type = 1.
		 */
		memset(&flt_eq, 0, sizeof(flt_eq));
		memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
		flt_eq.ip = iptype;
		if (0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
		{
			IPACMERR("Failed to get eq_attrib for IPoGRE frag rule\n");
			return IPACM_FAILURE;
		}
		memcpy(&flt_rule_entry.rule.eq_attrib, &flt_eq.eq_attrib,
			sizeof(flt_rule_entry.rule.eq_attrib));
	}
	else if (last_frag && iptype == IPA_IP_v4)
	{
		/*
		 * IPv4 last-fragment rule without outer tunnel endpoint matching.
		 * Use IPA_FLT_FRAGMENT to detect any fragment (offset!=0 OR MF=1).
		 * The MF=0 offset_meq_32 check added below narrows the match to
		 * last fragments only (offset!=0 AND MF=0).
		 */
		flt_rule_entry.rule.attrib.attrib_mask |= IPA_FLT_FRAGMENT;

		memset(&flt_eq, 0, sizeof(flt_eq));
		memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
		flt_eq.ip = iptype;
		if (0 != ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
		{
			IPACMERR("Failed to get eq_attrib for IPoGRE last-frag rule\n");
			return IPACM_FAILURE;
		}
		memcpy(&flt_rule_entry.rule.eq_attrib, &flt_eq.eq_attrib,
			sizeof(flt_rule_entry.rule.eq_attrib));
	}

	/*
	 * Add fragment packet check on top of the generated equation attributes.
	 * All checks use offset_meq_32 at offset 6 in the outer tunnel IP header.
	 *
	 * IPv6:
	 *   Next Header field (byte 6) = 0x2C (44 = Fragment extension header).
	 *   mask=0xFF000000, value=0x2C000000
	 *
	 * IPv4 non-last fragments (last_frag == false):
	 *   More Fragments (MF) bit = bit 29 of the 32-bit word at offset 6.
	 *   mask=0x20000000, value=0x20000000  (MF=1)
	 *
	 * IPv4 last fragments (last_frag == true):
	 *   IPA_FLT_FRAGMENT already detects any fragment (offset!=0 OR MF=1).
	 *   Adding MF=0 check excludes non-last fragments:
	 *     (offset!=0 OR MF=1) AND MF=0  =>  offset!=0 AND MF=0  =  last fragment
	 *   mask=0x20000000, value=0x00000000  (MF=0)
	 */
	if (iptype == IPA_IP_v6)
	{
		/* IPv6 Fragment extension header: Next Header = 0x2C at byte 6 */
		if (flt_rule_entry.rule.eq_attrib.num_offset_meq_32 >= IPA_IPFLTR_NUM_MEQ_32_EQNS)
		{
			IPACMERR("Cannot add IPv6 fragment check: offset_meq_32 array full\n");
			return IPACM_FAILURE;
		}
		flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= 0x20 << flt_rule_entry.rule.eq_attrib.num_offset_meq_32;
		flt_rule_entry.rule.eq_attrib.offset_meq_32[flt_rule_entry.rule.eq_attrib.num_offset_meq_32].offset = 6;
		flt_rule_entry.rule.eq_attrib.offset_meq_32[flt_rule_entry.rule.eq_attrib.num_offset_meq_32].mask  = 0xFF000000;
		flt_rule_entry.rule.eq_attrib.offset_meq_32[flt_rule_entry.rule.eq_attrib.num_offset_meq_32].value = 0x2C000000;
		flt_rule_entry.rule.eq_attrib.num_offset_meq_32++;
	}
	else /* IPA_IP_v4 */
	{
		if (flt_rule_entry.rule.eq_attrib.num_offset_meq_32 >= IPA_IPFLTR_NUM_MEQ_32_EQNS)
		{
			IPACMERR("Cannot add IPv4 fragment check: offset_meq_32 array full\n");
			return IPACM_FAILURE;
		}
		flt_rule_entry.rule.eq_attrib.rule_eq_bitmap |= 0x20 << flt_rule_entry.rule.eq_attrib.num_offset_meq_32;
		flt_rule_entry.rule.eq_attrib.offset_meq_32[flt_rule_entry.rule.eq_attrib.num_offset_meq_32].offset = 6;
		flt_rule_entry.rule.eq_attrib.offset_meq_32[flt_rule_entry.rule.eq_attrib.num_offset_meq_32].mask  = 0x20000000;
		if (!last_frag)
		{
			/* Non-last fragments: MF=1 */
			flt_rule_entry.rule.eq_attrib.offset_meq_32[flt_rule_entry.rule.eq_attrib.num_offset_meq_32].value = 0x20000000;
		}
		else
		{
			/* Last fragments: MF=0 (combined with IPA_FLT_FRAGMENT for offset!=0) */
			flt_rule_entry.rule.eq_attrib.offset_meq_32[flt_rule_entry.rule.eq_attrib.num_offset_meq_32].value = 0x00000000;
		}
		flt_rule_entry.rule.eq_attrib.num_offset_meq_32++;
	}


	/* Get routing table index */
	memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
	strlcpy(rt_tbl_idx.name, IPACM_Iface::ipacmcfg->rt_tbl_wan_dl.name, IPA_RESOURCE_NAME_MAX);
	rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
	rt_tbl_idx.ip = iptype;
	if (0 != ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx))
	{
		IPACMERR("Failed to get routing table index from name\n");
		return IPACM_FAILURE;
	}
	flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;
	IPACMDBG_H("IPoGRE frag rule routing table %s has index %d\n",
		rt_tbl_idx.name, rt_tbl_idx.idx);
	memcpy(&flt_rule_add, &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
	IPACMDBG_H("IPoGRE frag filter rule attrib mask: 0x%x, num_offset_meq_32: %d\n",
		flt_rule_add.rule.attrib.attrib_mask,
		flt_rule_add.rule.eq_attrib.num_offset_meq_32);

	if(iptype == IPA_IP_v6)
		IPACM_Wan::num_v6_flt_rule++;
	else
		IPACM_Wan::num_v4_flt_rule++;

	IPACMDBG_H("IPoGRE frag filter rule added successfully\n");
	return IPACM_SUCCESS;
}

#ifdef FEATURE_VLAN_MPDN
int IPACM_Wan::add_firewall_rules_ex(
	const IPACM_firewall_conf_t& firewall_config,
	ipa_ip_type iptype,
	uint8_t curr_mux_id,
	const struct ipa_rule_attrib& rx_prop_attrib,
	ipacm_pdn_flt_rule* rules,
	int rules_size, int& pos)
#else
int IPACM_Wan::add_firewall_rules_ex(const IPACM_firewall_conf_t& firewall_config, ipa_ip_type iptype,
	const struct ipa_rule_attrib& rx_prop_attrib, struct ipa_flt_rule_add *rules, int rules_size, int& pos)
#endif
{
	if (!firewall_config.firewall_enable)
	{
		return IPACM_SUCCESS;
	}

	for (uint8_t i = 0; i < firewall_config.num_extd_firewall_entries; ++i)
	{
		struct ipa_flt_rule_add flt_rule_entry;
		memset(&flt_rule_entry, 0, sizeof(struct ipa_flt_rule_add));

		flt_rule_entry.at_rear = true;
		flt_rule_entry.flt_rule_hdl = -1;
		flt_rule_entry.status = -1;

		flt_rule_entry.rule.retain_hdr = 1;
		flt_rule_entry.rule.to_uc = 0;
		flt_rule_entry.rule.eq_attrib_type = 1;

#ifdef FEATURE_IPA_V3
		flt_rule_entry.rule.hashable = true;
#endif

		int *num_firewall, *num_flt_rule;
		const char* rt_tbl_name;
		uint8_t* rule_protocol;
		const uint8_t* firewall_config_protocol;
		if (iptype == IPA_IP_v4)
		{
			if (firewall_config.extd_firewall_entries[i].ip_vsn != 4)
			{
				continue;
			}

			num_firewall = &num_firewall_v4;
			num_flt_rule = &num_v4_flt_rule;
			rule_protocol = &flt_rule_entry.rule.attrib.u.v4.protocol;
			firewall_config_protocol = &firewall_config.extd_firewall_entries[i].attrib.u.v4.protocol;

			if (firewall_config.rule_action_accept)
			{
				flt_rule_entry.rule.action = IPA_PASS_TO_DST_NAT;
				rt_tbl_name = ipacmcfg->rt_tbl_lan_v4.name;
			}
			else
			{
				flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
				rt_tbl_name = ipacmcfg->rt_tbl_wan_dl.name;
			}
		}
		else if (iptype == IPA_IP_v6)
		{
#ifndef FEATURE_IPACM_UL_FIREWALL
			if (firewall_config.extd_firewall_entries[i].ip_vsn != 6)
#else // n FEATURE_IPACM_UL_FIREWALL
			if (firewall_config.extd_firewall_entries[i].ip_vsn != 6 ||
				firewall_config.extd_firewall_entries[i].firewall_direction == IPACM_MSGR_UL_FIREWALL)
#endif //n FEATURE_IPACM_UL_FIREWALL
			{
				continue;
			}

#ifdef FEATURE_IPV6_NAT
			// in ipv6_nat_enable=false case, ignore the firewall rules if it's specific to v6nat
			if(firewall_config.extd_firewall_entries[i].IPV6NatEnabledfw)
				continue;
#endif

			num_firewall = &num_firewall_v6;
			num_flt_rule = &num_v6_flt_rule;
			rule_protocol = &flt_rule_entry.rule.attrib.u.v6.next_hdr;
			firewall_config_protocol = &firewall_config.extd_firewall_entries[i].attrib.u.v6.next_hdr;

			if (firewall_config.rule_action_accept)
			{
				flt_rule_entry.rule.action =
					IPACM_Iface::ipacmcfg->IsIpv6CTEnabled() ? IPA_PASS_TO_DST_NAT : IPA_PASS_TO_ROUTING;
				rt_tbl_name = ipacmcfg->rt_tbl_wan_v6.name;
			}
			else
			{
				flt_rule_entry.rule.action = IPA_PASS_TO_ROUTING;
				rt_tbl_name = ipacmcfg->rt_tbl_wan_dl.name;
			}
		}
		else
		{
			IPACMERR("IP type is not expected.\n");
			return IPACM_FAILURE;
		}

		ipa_ioc_get_rt_tbl_indx rt_tbl_idx;
		memset(&rt_tbl_idx, 0, sizeof(rt_tbl_idx));
		rt_tbl_idx.ip = iptype;
		strlcpy(rt_tbl_idx.name, rt_tbl_name, IPA_RESOURCE_NAME_MAX);
		rt_tbl_idx.name[IPA_RESOURCE_NAME_MAX - 1] = '\0';
		if (ioctl(m_fd_ipa, IPA_IOC_QUERY_RT_TBL_INDEX, &rt_tbl_idx))
		{
			IPACMERR("Failed to get routing table index from name\n");
			return IPACM_FAILURE;
		}
		flt_rule_entry.rule.rt_tbl_idx = rt_tbl_idx.idx;
		IPACMDBG_H("Routing table %s has index %d\n", rt_tbl_idx.name, rt_tbl_idx.idx);

		memcpy(&flt_rule_entry.rule.attrib, &firewall_config.extd_firewall_entries[i].attrib,
			sizeof(struct ipa_rule_attrib));

		flt_rule_entry.rule.attrib.attrib_mask |= rx_prop_attrib.attrib_mask;
		flt_rule_entry.rule.attrib.meta_data_mask = rx_prop_attrib.meta_data_mask;
		flt_rule_entry.rule.attrib.meta_data = rx_prop_attrib.meta_data;

		change_to_network_order(iptype, &flt_rule_entry.rule.attrib);

		ipa_ioc_generate_flt_eq flt_eq;

		/* check if the rule is define as TCP_UDP, split into 2 rules, 1 for TCP and 1 UDP */
		if (*firewall_config_protocol == IPACM_FIREWALL_IPPROTO_TCP_UDP)
		{
			/* Check for "out of boundary" failure before adding two rules */
			if (pos + 1 >= rules_size)
			{
				IPACMERR("Filtering table is full. Number of rules %d allowed %d\n", pos + 2, rules_size);
				return IPACM_SUCCESS;
			}

			/* insert TCP rule*/
			*rule_protocol = IPACM_FIREWALL_IPPROTO_TCP;

			memset(&flt_eq, 0, sizeof(flt_eq));
			memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
			flt_eq.ip = iptype;
			if (ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
			{
				IPACMERR("Failed to get eq_attrib\n");
				return IPACM_FAILURE;
			}
			memcpy(&flt_rule_entry.rule.eq_attrib, &flt_eq.eq_attrib, sizeof(flt_rule_entry.rule.eq_attrib));

#ifdef FEATURE_VLAN_MPDN
			rules[pos].mux_id = curr_mux_id;
			memcpy(&(rules[pos].flt_rule), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
			IPACMDBG_H("Filter rule attrib mask: 0x%x\n", rules[pos].flt_rule.rule.attrib.attrib_mask);
#else
			memcpy(&(rules[pos]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
			IPACMDBG_H("Filter rule attrib mask: 0x%x\n", rules[pos].rule.attrib.attrib_mask);
#endif
			++pos;
			++(*num_firewall);
			++(*num_flt_rule);

			/* insert UDP rule*/
			*rule_protocol = IPACM_FIREWALL_IPPROTO_UDP;

			memset(&flt_eq, 0, sizeof(flt_eq));
			memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
			flt_eq.ip = iptype;
			if (ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
			{
				IPACMERR("Failed to get eq_attrib\n");
				return IPACM_FAILURE;
			}
			memcpy(&flt_rule_entry.rule.eq_attrib, &flt_eq.eq_attrib, sizeof(flt_rule_entry.rule.eq_attrib));

#ifdef FEATURE_VLAN_MPDN
			rules[pos].mux_id = curr_mux_id;
			memcpy(&(rules[pos].flt_rule), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
			IPACMDBG_H("Filter rule attrib mask: 0x%x\n", rules[pos].flt_rule.rule.attrib.attrib_mask);
#else
			memcpy(&(rules[pos]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
			IPACMDBG_H("Filter rule attrib mask: 0x%x\n", rules[pos].rule.attrib.attrib_mask);
#endif
			++pos;
			++(*num_firewall);
			++(*num_flt_rule);
		}
		else
		{
			/* Check for "out of boundary" failure before adding a rule */
			if (pos >= rules_size)
			{
				IPACMERR("Filtering table is full. Number of rules %d allowed %d\n", pos + 1, rules_size);
				return IPACM_SUCCESS;
			}

			memset(&flt_eq, 0, sizeof(flt_eq));
			memcpy(&flt_eq.attrib, &flt_rule_entry.rule.attrib, sizeof(flt_eq.attrib));
			flt_eq.ip = iptype;
			if (ioctl(m_fd_ipa, IPA_IOC_GENERATE_FLT_EQ, &flt_eq))
			{
				IPACMERR("Failed to get eq_attrib\n");
				return IPACM_FAILURE;
			}
			memcpy(&flt_rule_entry.rule.eq_attrib, &flt_eq.eq_attrib, sizeof(flt_rule_entry.rule.eq_attrib));

#ifdef FEATURE_VLAN_MPDN
			rules[pos].mux_id = curr_mux_id;
			memcpy(&(rules[pos].flt_rule), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
			IPACMDBG_H("Filter rule attrib mask: 0x%x\n", rules[pos].flt_rule.rule.attrib.attrib_mask);
#else
			memcpy(&(rules[pos]), &flt_rule_entry, sizeof(struct ipa_flt_rule_add));
			IPACMDBG_H("Filter rule attrib mask: 0x%x\n", rules[pos].rule.attrib.attrib_mask);
#endif
			++pos;
			++(*num_firewall);
			++(*num_flt_rule);
		}
	} /* end of firewall filter rule add for loop*/
	return IPACM_SUCCESS;
}

int IPACM_Wan::query_mtu_size()
{
	int fd;
	struct ifreq if_mtu;
	char iface_name[IPA_IFACE_NAME_LEN] = {0};

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if ( fd < 0 ) {
		IPACMERR("ipacm: socket open failed [%d]\n", fd);
		return IPACM_FAILURE;
	}

	strlcpy(if_mtu.ifr_name, dev_name, IFNAMSIZ);

	if (strstr(dev_name, RMNET_IFACE_NAME))
	{
		for (int i = 0; i < IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces; i++)
		{
			if (strncmp(dev_name, IPACM_Iface::ipacmcfg->iface_table[i].iface_name, IPA_IFACE_NAME_LEN) == 0)
			{
				IPACMDBG_H("Interface (%s) found: linux(%d)\n",
							 	IPACM_Iface::ipacmcfg->iface_table[i].iface_name,
							 	IPACM_Iface::ipacmcfg->iface_table[i].netlink_interface_index);
				ipa_get_if_name(iface_name, IPACM_Iface::ipacmcfg->iface_table[i].netlink_interface_index);
				strlcpy(if_mtu.ifr_name, iface_name, IFNAMSIZ);
				break;
			}
		}
	}

	if_mtu.ifr_name[IFNAMSIZ - 1] = '\0';
	IPACMDBG_H("device name: %s\n", if_mtu.ifr_name);

	if ( ioctl(fd, SIOCGIFMTU, &if_mtu) < 0 ) {
		IPACMERR("ioctl failed to get mtu\n");
		close(fd);
		return IPACM_FAILURE;
	}
	IPACMDBG_H("mtu=[%d]\n", if_mtu.ifr_mtu);
	if (if_mtu.ifr_mtu <= DEFAULT_MTU_SIZE) {
		mtu_v4 = mtu_v6 = if_mtu.ifr_mtu;
	}else {
		mtu_v4 = mtu_v6 = DEFAULT_MTU_SIZE;
	}
	IPACMDBG_H("Updated mtu=[%d] for (%s)\n", mtu_v4, dev_name);

	close(fd);
	return IPACM_SUCCESS;
}

int IPACM_Wan::GetMuxByAddr(
	enum ipa_ip_type iptype,
	void*            addr,
	uint8_t&         mux_id )
{
	if ( ! VALID_IPA_IP_TYPE(iptype) || addr == NULL )
	{
		IPACMERR("Invalid iptype(%d) of addr(%p) passed to function\n",
				 iptype, addr);
		return IPACM_FAILURE;
	}

	bool found = false;

#if defined(IPV6_EoGRE_TEST)
	found = true;
	mux_id = 1;
	goto done;
#endif

	for ( int i = 0; i < IPA_MAX_NUM_SW_PDNS && ! found; i++ )
	{
		if ( iptype == IPA_IP_v4 )
		{
			IPACM_LOG_IP_ADDR("Searching for:", iptype, addr);

			IPACM_LOG_IP_ADDR(
				"Interface has:",
				iptype,
				&IPACM_Wan::ipv4_to_iface[i].ipv4_addr);

			if( *((uint32_t*) addr) == IPACM_Wan::ipv4_to_iface[i].ipv4_addr )
			{
				mux_id = IPACM_Wan::ipv4_to_iface[i].pIface->ext_prop->ext[0].mux_id;
				found = true;
			}
		}
		else /* IPA_IP_v6 */
		{
			if ( IPACM_Wan::ipv6_to_iface[i].pIface )
			{
				IPACM_LOG_IP_ADDR("Searching for:", iptype, addr);

				IPACM_LOG_IP_ADDR(
					"Interface has:",
					iptype,
					&IPACM_Wan::ipv6_to_iface[i].pIface->m_ipv6_addr);

				bool equal = ! memcmp(
					addr,
					&IPACM_Wan::ipv6_to_iface[i].pIface->m_ipv6_addr,
					sizeof(IPACM_Wan::ipv6_to_iface[i].pIface->m_ipv6_addr));

				if ( equal )
				{
					mux_id = IPACM_Wan::ipv6_to_iface[i].pIface->ext_prop->ext[0].mux_id;
					found = true;
				}
			}
		}
	}

done:
	if ( found )
	{
		IPACMDBG_H(
			"MUX ID(%u) found\n",
			mux_id);

		return IPACM_SUCCESS;
	}
	else
	{
		IPACMERR("No MUX ID found\n");

		return IPACM_FAILURE;
	}
}

#ifdef FEATURE_EoGRE

void IPACM_Wan::eogre_up()
{
	IPACMDBG_H("Into eogre_up\n");

	ipa_ip_type iptype = IPACM_Iface::ipacmcfg->eogre_info.iptype;

	bool        eogre_enable = true;

	IPACMDBG_H(
		"About to enable eogre. Will do default catchup rule work for iptype(%d).\n",
		iptype);

	if ( eogre_notify_wan_state(eogre_enable) != IPACM_SUCCESS )
	{
		IPACMERR("eogre_notify_wan_state failed\n");
		return;
	}

	if ( iptype == IPA_IP_v4 )
	{
		if ( eogre_v4_work(eogre_enable) != IPACM_SUCCESS )
		{
			IPACMERR("eogre_v4_work failed\n");
			return;
		}
	}
	else
	{
		if ( eogre_v6_work(eogre_enable) != IPACM_SUCCESS )
		{
			IPACMERR("eogre_v6_work failed\n");
			return;
		}
	}

	IPACMDBG_H(
		"Success with the enable for iptype(%d)\n",
		iptype);
}

void IPACM_Wan::eogre_down()
{
	IPACMDBG_H("Into eogre_down\n");

	ipa_ip_type iptype = IPACM_Iface::ipacmcfg->eogre_info.iptype;

	bool        eogre_enable = false;

	IPACMDBG_H(
		"About to disable eogre. Will do default catchup rule work for iptype(%d).\n",
		iptype);

	if ( eogre_notify_wan_state(eogre_enable) != IPACM_SUCCESS )
	{
		IPACMERR("eogre_notify_wan_state failed\n");
		return;
	}

	if ( iptype == IPA_IP_v4 )
	{
		if ( eogre_v4_work(eogre_enable) != IPACM_SUCCESS )
		{
			IPACMERR("eogre_v4_work failed\n");
			return;
		}
	}
	else
	{
		if ( eogre_v6_work(eogre_enable) != IPACM_SUCCESS )
		{
			IPACMERR("eogre_v6_work failed\n");
			return;
		}
	}

	IPACMDBG_H(
		"Success with the disable for iptype(%d)\n",
		iptype);
}

int IPACM_Wan::eogre_v4_work(
	bool eogre_enable )
{
	if ( eogre_enable )
	{
		IPACMDBG_H("Adding v4 modem DL rules on eogre enable.\n");

		wan_up = is_default_gateway = true;

		if ( config_wan_firewall_rule(IPA_IP_v4) != IPACM_SUCCESS )
		{
			IPACMERR(
				"config_wan_firewall_rule failed\n");
			wan_up = is_default_gateway = false;
			return IPACM_FAILURE;
		}

		if ( install_wan_filtering_rule(false) != IPACM_SUCCESS )
		{
			IPACMERR(
				"install_wan_filtering_rule failed\n");
			wan_up = is_default_gateway = false;
			return IPACM_FAILURE;
		}
	}
	else
	{
		IPACMDBG_H("Deleting v4 modem DL rules on eogre disable.\n");

		IPACM_Wan::num_v4_flt_rule = 0;

#ifdef FEATURE_VLAN_MPDN
		memset(IPACM_Wan::pdn_flt_rule_v4,
			   0,
			   sizeof(IPACM_Wan::pdn_flt_rule_v4));
#else
		memset(IPACM_Wan::flt_rule_v4,
			   0,
			   sizeof(IPACM_Wan::flt_rule_v4));
#endif
		if ( install_wan_filtering_rule(false) != IPACM_SUCCESS )
		{
			IPACMERR(
				"install_wan_filtering_rule failed\n");
			wan_up = is_default_gateway = false;
			return IPACM_FAILURE;
		}

		wan_up = is_default_gateway = false;
	}

	return IPACM_SUCCESS;
}

int IPACM_Wan::eogre_v6_work(
	bool eogre_enable )
{
	if ( eogre_enable )
	{
		IPACMDBG_H("Adding v6 modem DL rules on eogre enable.\n");

		wan_up_v6 = is_default_gateway = true;

		if ( config_wan_firewall_rule(IPA_IP_v6) != IPACM_SUCCESS )
		{
			IPACMERR(
				"config_wan_firewall_rule failed\n");
			wan_up_v6 = is_default_gateway = false;
			return IPACM_FAILURE;
		}

		if ( install_wan_filtering_rule(false) != IPACM_SUCCESS )
		{
			IPACMERR(
				"install_wan_filtering_rule failed\n");
			wan_up_v6 = is_default_gateway = false;
			return IPACM_FAILURE;
		}
	}
	else
	{
		IPACMDBG_H("Deleting v6 modem DL rules on eogre disable.\n");

		IPACM_Wan::num_v6_flt_rule = 0;

#ifdef FEATURE_VLAN_MPDN
		memset(IPACM_Wan::pdn_flt_rule_v6,
			   0,
			   sizeof(IPACM_Wan::pdn_flt_rule_v6));
#else
		memset(IPACM_Wan::flt_rule_v6,
			   0,
			   sizeof(IPACM_Wan::flt_rule_v6));
#endif
		if ( install_wan_filtering_rule(false) != IPACM_SUCCESS )
		{
			IPACMERR(
				"install_wan_filtering_rule failed\n");
			wan_up_v6 = is_default_gateway = false;
			return IPACM_FAILURE;
		}

		wan_up_v6 = is_default_gateway = false;
	}

	return IPACM_SUCCESS;
}

int IPACM_Wan::eogre_notify_wan_state(
	bool eogre_enable )
{
	IPACMDBG_H("In\n");

	struct wan_ioctl_notify_wan_state wan_state;

	int fd;

	IPACMDBG_H(
		"Send WAN_IOC_NOTIFY_WAN_STATE %s to IPA_PM\n",
		(eogre_enable) ? "up" : "down");

	fd = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);

	if ( fd < 0 )
	{
		IPACMERR(
			"Failed to open %s.\n",
			WWAN_QMI_IOCTL_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	memset(&wan_state, 0, sizeof(wan_state));

	wan_state.up = eogre_enable;

	if ( ioctl(fd, WAN_IOC_NOTIFY_WAN_STATE, &wan_state) )
	{
		IPACMERR("The ioctl to send WAN_IOC_NOTIFY_WAN_STATE failed\n");
		close(fd);
		return IPACM_FAILURE;
	}

	close(fd);

	IPACMDBG_H("Out\n");

	return IPACM_SUCCESS;
}

#endif /* #ifdef FEATURE_EoGRE */

#ifdef FEATURE_PPPOE
int IPACM_Wan::pppoe_make_hdr_add_ctx(enum ipa_ip_type iptype)
{
	IPACMDBG_H("Attempting to create \"header add\" context for PPPoE UL routing\n");
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

	procCtx->type         = IPA_HDR_PROC_PPPOE_HEADER_ADD;
	if (iptype == IPA_IP_v4)
		procCtx->hdr_hdl = get_client_memptr(wan_client, num_wan_client)->hdr_hdl_v4;
	else
		procCtx->hdr_hdl = get_client_memptr(wan_client, num_wan_client)->hdr_hdl_v6;

	IPACMDBG_H("procCtx->hdr_hdl %x\n",procCtx->hdr_hdl);

	if ( m_header.AddHeaderProcCtx(procCtxTable) == true )
	{
		IPACMDBG_H(
			"PPPoE header context successfully installed, hdl %d\n",procCtx->proc_ctx_hdl);
		if (iptype == IPA_IP_v4)
			v4_p_ctx_2use = procCtx->proc_ctx_hdl;
		else
			v6_p_ctx_2use = procCtx->proc_ctx_hdl;
	}
	else
	{
		IPACMERR("AddHeaderProcCtx failed\n");
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

int IPACM_Wan::pppoe_del_hdr_proc_ctx(enum ipa_ip_type ip_type)
{
	IPACMDBG_H("Enter rule deletion for PPPoE WAN: %s ip_type: %d\n",
		dev_name, ip_type);

	if(ip_type == IPA_IP_v4)
	{
		if(m_header.DeleteHeaderProcCtx(v4_p_ctx_2use) == false)
		{
			IPACMERR("Failed to delete v4 PPPoE hdr proc ctx, aborting...\n");
			return IPACM_FAILURE;
		}
		v4_p_ctx_2use = 0;
	}

	if(ip_type == IPA_IP_v6)
	{
		if(m_header.DeleteHeaderProcCtx(v6_p_ctx_2use) == false)
		{
			IPACMERR("Failed to delete v6 PPPoE hdr proc ctx, aborting...\n");
			return IPACM_FAILURE;
		}
		v6_p_ctx_2use = 0;
	}

	if(ip_type == IPA_IP_MAX)
	{
		if(m_header.DeleteHeaderProcCtx(v4_p_ctx_2use) == false)
		{
			IPACMERR("Failed to delete v4 PPPoE hdr proc ctx, aborting...\n");
			return IPACM_FAILURE;
		}
		v4_p_ctx_2use = 0;
		if(m_header.DeleteHeaderProcCtx(v6_p_ctx_2use) == false)
		{
			IPACMERR("Failed to delete v6 PPPoE hdr proc ctx, aborting...\n");
			return IPACM_FAILURE;
		}
		v6_p_ctx_2use = 0;
	}
	return IPACM_SUCCESS;
}
#endif /*#ifdef FEATURE_PPPOE*/


#ifdef FEATURE_PMIPV6 || FEATURE_IPoGRE
void IPACM_Wan::gre_up()
{
	if(!IPACM_Iface::ipacmcfg->ipogre_enabled)
	{
		if(IPACM_Iface::ipacmcfg->pmip_details.pmipv6_up_wan == true){
			IPACMDBG_H("GRE UP already received once, RT work is done\n");
			return;
		}
		if(IPACM_Iface::ipacmcfg->pmip_details.pmipv6_tunnel_setup == false){
			IPACMDBG_H("Tunnel info is not yet loaded. Let's wait for tunnel\n");
			return;
		}
	}
	ipa_ipgre_info ipgre_info;
	ipgre_info = IPACM_Iface::ipacmcfg->ipgre_info;
	IPACMDBG_H("Into gre_up\n");
	IPACM_Iface::ipacmcfg->pmip_details.pmipv6_up_wan=true;

	ipa_ip_type iptype = IPACM_Iface::ipacmcfg->ipgre_info.iptype;

	bool        gre_enable = true;

	IPACMDBG_H(
		"About to enable gre. Will do default catchup rule work for iptype(%d).\n",
		iptype);

	if ( gre_notify_wan_state(gre_enable) != IPACM_SUCCESS )
	{
		IPACMERR("gre_notify_wan_state failed\n");
		return;
	}

	/*
	 * Create gre specific route rules...
	 */
	IPACMDBG_H(
		"Adding gre specific route rules for iptype(%d)\n",
		iptype);

	if ( ipgre_do_rt_work(ipgre_info) != IPACM_SUCCESS )
	{
		IPACMERR("ipgre_do_rt_work failed\n");
		return;
	}

	if ( iptype == IPA_IP_v4 )
	{
		if ( gre_v4_work(gre_enable) != IPACM_SUCCESS )
		{
			IPACMERR("gre_v4_work failed\n");
			return;
		}
	}
	else
	{
		if ( gre_v6_work(gre_enable) != IPACM_SUCCESS )
		{
			IPACMERR("gre_v6_work failed\n");
			return;
		}
	}

	ipacm_cmd_q_data evt_data;
	memset(&evt_data, 0, sizeof(evt_data));
	evt_data.event = IPA_WAN_HANDLE_IPOGRE_UP;
	evt_data.evt_data = 0;
	IPACMDBG_H("Posting event: IPA_WAN_HANDLE_EoGRE_UP.\n");
	IPACM_EvtDispatcher::PostEvt(&evt_data);
	IPACMDBG_H(
		"Success with the enable for iptype(%d)\n",
		iptype);
}

void IPACM_Wan::gre_down()
{
	IPACMDBG_H("Into gre_down\n");

	IPACM_Iface::ipacmcfg->pmip_details.pmipv6_up_wan=false;
	ipa_ip_type iptype = IPACM_Iface::ipacmcfg->ipgre_info.iptype;

	bool        gre_enable = false;

	IPACMDBG_H(
		"About to disable eogre. Will do default catchup rule work for iptype(%d).\n",
		iptype);

	if ( gre_notify_wan_state(gre_enable) != IPACM_SUCCESS )
	{
		IPACMERR("eogre_notify_wan_state failed\n");
		return;
	}

	if ( iptype == IPA_IP_v4 )
	{
		if ( gre_v4_work(gre_enable) != IPACM_SUCCESS )
		{
			IPACMERR("gre_v4_work failed\n");
			return;
		}
	}
	else
	{
		if ( gre_v6_work(gre_enable) != IPACM_SUCCESS )
		{
			IPACMERR("gre_v6_work failed\n");
			return;
		}
	}
	ipgre_clear_route_data(IPA_IP_v4);
	ipgre_clear_route_data(IPA_IP_v6);

	ipacm_cmd_q_data evt_data;
	memset(&evt_data, 0, sizeof(evt_data));
	evt_data.event = IPA_WAN_HANDLE_IPOGRE_DOWN;
	IPACMDBG_H("Posting event: IPA_WAN_HANDLE_IPoGRE_DOWN\n");
	IPACM_EvtDispatcher::PostEvt(&evt_data);
	IPACMDBG_H(
		"Success with the disable for iptype(%d)\n",
		iptype);
}

int IPACM_Wan::gre_v4_work(
	bool gre_enable )
{
	if ( gre_enable )
	{
		IPACMDBG_H("Adding v4 modem DL rules on eogre enable.\n");

		wan_up = is_default_gateway = true;
		/*Inserting First pass downlink rule above the default catchall rule*/
		if ( config_wan_firewall_rule(IPA_IP_v4,true) != IPACM_SUCCESS )
		{
			IPACMERR(
				"config_wan_firewall_rule failed\n");
			wan_up = is_default_gateway = false;
			return IPACM_FAILURE;
		}
		if ( install_wan_filtering_rule(false) != IPACM_SUCCESS )
		{
			IPACMERR(
				"install_wan_filtering_rule failed\n");
			wan_up = is_default_gateway = false;
			return IPACM_FAILURE;
		}
	}
	else
	{
		IPACMDBG_H("Deleting v4 PMIP DL rules on gre disable.\n");
		if ( config_wan_firewall_rule(IPA_IP_v4,false) != IPACM_SUCCESS )
		{
			IPACMERR(
				"config_wan_firewall_rule failed\n");
			wan_up = is_default_gateway = false;
			return IPACM_FAILURE;
		}
		if ( install_wan_filtering_rule(false) != IPACM_SUCCESS )
		{
			IPACMERR(
				"install_wan_filtering_rule failed\n");
			wan_up = is_default_gateway = false;
			return IPACM_FAILURE;
		}
	}

	return IPACM_SUCCESS;
}

int IPACM_Wan::gre_v6_work(
	bool gre_enable )
{
	if ( gre_enable )
	{
		IPACMDBG_H("Adding v6 modem DL rules on gre enable.\n");

		wan_up_v6 = is_default_gateway = true;
		/*Inserting First pass downlink rule above the default catchall rule*/
		if ( config_wan_firewall_rule(IPA_IP_v6,true) != IPACM_SUCCESS )
		{
			IPACMERR(
				"config_wan_firewall_rule failed\n");
			wan_up_v6 = is_default_gateway = false;
			return IPACM_FAILURE;
		}
		/*Now, we have to also make sure that for v4, the catchall rule does not point to DST_NAT */
		if ( config_wan_firewall_rule(IPA_IP_v4,true) != IPACM_SUCCESS )
		{
			IPACMERR(
				"config_wan_firewall_rule for V4 failed\n");
		}

		if ( install_wan_filtering_rule(false) != IPACM_SUCCESS )
		{
			IPACMERR(
				"install_wan_filtering_rule failed\n");
			wan_up_v6 = is_default_gateway = false;
			return IPACM_FAILURE;
		}
	}
	else
	{
		IPACMDBG_H("Deleting v6 modem PMIP DL rules on gre disable.\n");

		if ( config_wan_firewall_rule(IPA_IP_v6) != IPACM_SUCCESS )
		{
			IPACMERR(
				"config_wan_firewall_rule failed\n");
			wan_up_v6 = is_default_gateway = false;
			return IPACM_FAILURE;
		}
		if ( install_wan_filtering_rule(false) != IPACM_SUCCESS )
		{
			IPACMERR(
				"install_wan_filtering_rule failed\n");
			wan_up_v6 = is_default_gateway = false;
			return IPACM_FAILURE;
		}
	}

	return IPACM_SUCCESS;
}

int IPACM_Wan::gre_notify_wan_state(
	bool gre_enable )
{
	IPACMDBG_H("In\n");

	struct wan_ioctl_notify_wan_state wan_state;

	int fd;

	IPACMDBG_H(
		"Send WAN_IOC_NOTIFY_WAN_STATE %s to IPA_PM\n",
		(gre_enable) ? "up" : "down");

	fd = open(WWAN_QMI_IOCTL_DEVICE_NAME, O_RDWR);

	if ( fd < 0 )
	{
		IPACMERR(
			"Failed to open %s.\n",
			WWAN_QMI_IOCTL_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	memset(&wan_state, 0, sizeof(wan_state));

	wan_state.up = gre_enable;

	if ( ioctl(fd, WAN_IOC_NOTIFY_WAN_STATE, &wan_state) )
	{
		IPACMERR("The ioctl to send WAN_IOC_NOTIFY_WAN_STATE failed\n");
		close(fd);
		return IPACM_FAILURE;
	}

	close(fd);

	IPACMDBG_H("Out\n");

	return IPACM_SUCCESS;
}

int IPACM_Wan::ipgre_do_rt_work(
	ipa_ipgre_info& ipgre_info)
{
	enum ipa_ip_type iptype = ipgre_info.iptype;

	IPACMDBG_H(
		"Attempting to create compatible gre routing info for ip-type: %d\n",
		iptype);

	if ( ipgre_make_hdr_for_add_ctx(ipgre_info)    != 0 ||
		 ipgre_make_hdr_add_ctx(ipgre_info)        != 0 ||
		 ipgre_make_hdr_for_rmv_ctx(ipgre_info)    != 0 ||
		 ipgre_make_hdr_rmv_ctx(ipgre_info)        != 0 ||
		 ipgre_make_header_add_rt_rule(ipgre_info) != 0 ||
		 ipgre_make_header_rmv_rt_rule(ipgre_info) != 0 )
	{
		IPACMERR("Failed to create and/or add gre data and rules\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H(
		"Finished creating compatible gre routing info for ip-type: %d\n",
		iptype);

	/*
	 * The following test is because gre is enabled, but we
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
		uint32_t hdr = IPACM_Wan::ipgre_route_data[iptype].ul_header_hdl_c;
		ipa_ipgre_info copy = ipgre_info;

		/*
		 * Invert the type to be the complimentary one...
		 */
		copy.iptype = iptype =
			(ipgre_info.iptype == IPA_IP_v4) ? IPA_IP_v6 : IPA_IP_v4;

		IPACMDBG_H(
			"Attempting to create complimentary gre routing info for ip-type: %d\n",
			iptype);

		if ( ipgre_make_hdr_add_ctx(copy, hdr)   != 0 ||
			 ipgre_make_header_add_rt_rule(copy) != 0 )
		{
			IPACMERR("Failed to create complimentary gre rule\n");
			return IPACM_FAILURE;
		}

		IPACMDBG_H(
			"Finished creating complimentary gre routing info for ip-type: %d\n",
			iptype);
	}

	return IPACM_SUCCESS;
}
uint32_t IPACM_Wan::ipgre_get_rt_tbl_hdl(
	enum ipa_ip_type iptype)
{
	if ( ! VALID_IPA_IP_TYPE(iptype) )
	{
		IPACMERR("Invalid IP type passed to function\n");
		return 0;
	}
	if ( IPACM_Wan::ipgre_route_data[iptype].rt_tbl_hdl == 0 )
		{
			struct ipa_ioc_get_rt_tbl routing_table;

			memset(&routing_table, 0, sizeof(routing_table));

			routing_table.ip = iptype;

			snprintf(
				routing_table.name,
				sizeof(routing_table.name),
				"%s",
				( iptype == IPA_IP_v4 )                   ?
				"GREV4RT" :
				"GREV6RT");

			IPACMDBG_H(
				"Attempting to get routing table(%s) handle for gre iptype(%d)\n",
				routing_table.name,
				iptype);

			if ( m_routing.GetRoutingTable(&routing_table) == true )
			{
				IPACMDBG_H(
					"The routing table(%s) handle(%d) successfully retrieved for gre iptype(%d)\n",
					routing_table.name,
					routing_table.hdl,
					iptype);

				IPACM_Wan::ipgre_route_data[iptype].rt_tbl_hdl = routing_table.hdl;
			}
			else
			{
				//Create routing table
				return -1;
			}
		}
	return IPACM_Wan::ipgre_route_data[iptype].rt_tbl_hdl;
}
int IPACM_Wan::ipgre_make_hdr_for_add_ctx(
	ipa_ipgre_info& ipgre_info)
{
	enum ipa_ip_type iptype = ipgre_info.iptype;
	IPACMDBG_H("Attempting to create iptype(%d) context header for gre routing\n",iptype);
	/*
	 * Create, the add, header for "header add" proc_ctx...
	 */
	char     addr_buf[128];
	uint8_t  hdr_data_buf[128];
	uint32_t hdr_data_len;

	if ( iptype == IPA_IP_v4 )
	{
		v4_ipgre_hdr_t* hdr = (v4_ipgre_hdr_t*) hdr_data_buf;
		memcpy(hdr_data_buf, v4_gre_header, sizeof(v4_gre_header));
		hdr->words[IPV4_GRE_PROT_IDX] = htonl(GRE_PROTOCOL_TYPE_v4_WITH_KEY);
		hdr_data_len = sizeof(v4_gre_header);
		hdr->words[IPV4_SRC_ADDR_IDX] = ipgre_info.ipv4_src;
		hdr->words[IPV4_DST_ADDR_IDX] = ipgre_info.ipv4_dst;
		addr2network(iptype, &(hdr->words[IPV4_SRC_ADDR_IDX]));
		addr2network(iptype, &(hdr->words[IPV4_DST_ADDR_IDX]));
		IPACM_LOG_IP_ADDR(
			"The src addr added to gre header template:",
			iptype,
			&(hdr->words[IPV4_SRC_ADDR_IDX]));

		IPACM_LOG_IP_ADDR(
			"The dst addr added to gre header template:",
			iptype,
			&(hdr->words[IPV4_DST_ADDR_IDX]));
	}
	else
	{
		v6_ipgre_hdr_t* hdr = (v6_ipgre_hdr_t*) hdr_data_buf;
		if(IPACM_Iface::ipacmcfg->ipogre_enabled)
		{
			memcpy(hdr_data_buf, v6_ipogre_header, sizeof(v6_ipogre_header));
			hdr_data_len = sizeof(v6_ipogre_header);
			hdr->words[IPV6_GRE_PROT_IDX] = htonl(GRE_PROTOCOL_TYPE_v6);
		}
		else
		{
			memcpy(hdr_data_buf, v6_gre_header, sizeof(v6_gre_header));
			hdr->words[IPV6_GRE_PMIP_PROT_IDX] = htonl(GRE_PROTOCOL_TYPE_v6_WITH_KEY);
			hdr_data_len = sizeof(v6_gre_header);
		}

		memcpy(&(hdr->words[IPV6_SRC_ADDR_IDX]),
			   &ipgre_info.ipv6_src,
			   sizeof(ipgre_info.ipv6_src));
		memcpy(&(hdr->words[IPV6_DST_ADDR_IDX]),
			   &ipgre_info.ipv6_dst,
			   sizeof(ipgre_info.ipv6_dst));
		addr2network(iptype, &(hdr->words[IPV6_SRC_ADDR_IDX]));
		addr2network(iptype, &(hdr->words[IPV6_DST_ADDR_IDX]));

		IPACM_LOG_IP_ADDR(
			"The src addr added to gre header template:",
			iptype,
			&(hdr->words[IPV6_SRC_ADDR_IDX]));

		IPACM_LOG_IP_ADDR(
			"The dst addr added to gre header template:",
			iptype,
			&(hdr->words[IPV6_DST_ADDR_IDX]));
	}

	/*
	 * Add the header...
	 */
	static const int NUM_OF_HEADERS = 2;

	uint8_t buf[
		sizeof(struct ipa_ioc_add_hdr) +
		(NUM_OF_HEADERS * sizeof(struct ipa_hdr_add)) ];

	memset(buf, 0, sizeof(buf));

	struct ipa_ioc_add_hdr *hdrTable =
		(struct ipa_ioc_add_hdr *) buf;

	struct ipa_hdr_add *hdr = &(hdrTable->hdr[0]);
	struct ipa_hdr_add *hdr_c = &(hdrTable->hdr[1]);/* Header for complimentary table */

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
	IPA_GRE_HDR_NAME,
	( iptype == IPA_IP_v4 )      ? 4                     : 6);

	hdr->type    = IPA_HDR_L2_ETHERNET_II;
	hdr->hdr_len = hdr_data_len;
	memcpy(hdr->hdr, hdr_data_buf, hdr->hdr_len);

	if(iptype == IPA_IP_v4)
	{
					v4_ipgre_hdr_t* hdr2 = (v4_ipgre_hdr_t*) hdr_data_buf;
					if(IPACM_Iface::ipacmcfg->ipogre_enabled)
						hdr2->words[IPV4_GRE_PROT_IDX] = htonl(GRE_PROTOCOL_TYPE_v6);
					else
						hdr2->words[IPV4_GRE_PROT_IDX] = htonl(GRE_PROTOCOL_TYPE_v6_WITH_KEY);   //V4  tunnel carrying v6 payload
	}
	else{
					v6_ipgre_hdr_t* hdr2 = (v6_ipgre_hdr_t*) hdr_data_buf;
					if(IPACM_Iface::ipacmcfg->ipogre_enabled)
						hdr2->words[IPV6_GRE_PROT_IDX] = htonl(GRE_PROTOCOL_TYPE_v4);
					else
						hdr2->words[IPV6_GRE_PROT_IDX] = htonl(GRE_PROTOCOL_TYPE_v4_WITH_KEY);  //V6 tunnel carrying v4 payload
	}

	hdr_c->is_partial = false;
	hdr_c->hdr_hdl    = -1; // Return Value
	hdr_c->status     = -1; // Return Parameter

	snprintf(
	hdr_c->name,
	sizeof(hdr_c->name),
	IPA_GRE_C_HDR_NAME,
	( iptype == IPA_IP_v4 )      ? 4                     : 6);

	hdr_c->type    = IPA_HDR_L2_ETHERNET_II;
	hdr_c->hdr_len = hdr_data_len;

	memcpy(hdr_c->hdr, hdr_data_buf, hdr_c->hdr_len);

	if ( m_header.AddHeader(hdrTable) && hdr->status == 0 && hdr_c->status == 0)
	{
		IPACMDBG_H(
			"Successfully added %d bytes for IP/gre header %s\n",
			hdr->hdr_len,
			hdr->name);
		IPACMDBG_H(
			"Successfully added %d bytes for IP/gre header %s\n",
			hdr_c->hdr_len,
			hdr_c->name);
		IPACM_Wan::ipgre_route_data[iptype].ul_header_hdl = hdr->hdr_hdl;
		IPACM_Wan::ipgre_route_data[iptype].ul_header_hdl_c = hdr_c->hdr_hdl;
	}
	else
	{
		IPACMERR("AddHeader failed: %d\n", hdr->status);
		IPACMERR("AddHeader failed: %d\n", hdr_c->status);
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

int IPACM_Wan::ipgre_make_hdr_add_ctx(
	ipa_ipgre_info& ipgre_info,
	uint32_t        hdr_2use)
{
	enum ipa_ip_type iptype = ipgre_info.iptype;

	IPACMDBG_H(
		"Attempting to create \"header add\" context "
		"(outer ip(%d) header) for uplink gre traffic.\n",
		iptype);

	hdr_2use = (hdr_2use) ? hdr_2use : IPACM_Wan::ipgre_route_data[iptype].ul_header_hdl;

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
	IPACMDBG_H("Initialising PMIP proc ctx add\n");
	procCtx->proc_ctx_hdl = -1; // return value
	procCtx->status       = -1; // Return parameter
	procCtx->hdr_hdl      = hdr_2use;
	if(IPACM_Iface::ipacmcfg->ipogre_enabled)
	{
		procCtx->type         = IPA_HDR_PROC_IPOGRE_HEADER_ADD;
		procCtx->ipogre_params.hdr_add_param.input_ip_version = iptype;
		procCtx->ipogre_params.hdr_add_param.output_ip_version =IPACM_Iface::ipacmcfg->ipgre_info.iptype;
		procCtx->ipogre_params.hdr_add_param.Mux_Id = ext_prop->ext[0].mux_id;
		procCtx->ipogre_params.hdr_add_param.non_ipogre = 0;
	}
	else
	{
		procCtx->type         = IPA_HDR_PROC_GRE_HEADER_ADD;
		procCtx->gre_params.hdr_add_param.eth_hdr_retained = 0;
		procCtx->gre_params.hdr_add_param.input_ip_version = iptype;
		procCtx->gre_params.hdr_add_param.output_ip_version =IPACM_Iface::ipacmcfg->ipgre_info.iptype;
		procCtx->gre_params.hdr_add_param.second_pass = 1;
	}

	if ( m_header.AddHeaderProcCtx(procCtxTable) == true )
	{
		IPACMDBG_H(
			"GRE header context successfully installed\n");

		IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl =
			procCtx->proc_ctx_hdl;
	}
	else
	{
		IPACMERR("AddHeaderProcCtx failed\n");
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

int IPACM_Wan::ipgre_make_hdr_for_rmv_ctx(
	ipa_ipgre_info& ipgre_info)
{
	/*No header required for Header remove context*/
	return IPACM_SUCCESS;
}

int IPACM_Wan::ipgre_make_hdr_rmv_ctx(
	ipa_ipgre_info& ipgre_info,
	uint32_t        hdr_2use)
{
	enum ipa_ip_type iptype = ipgre_info.iptype;

	IPACMDBG_H(
		"Attempting to create \"header remove\" context "
		"(outer ip(%d) header) for downlink gre traffic.\n",
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
	procCtx->proc_ctx_hdl = -1; // return value
	procCtx->status       = -1; // Return parameter
	if(IPACM_Iface::ipacmcfg->ipogre_enabled)
	{
		procCtx->type         = IPA_HDR_PROC_IPOGRE_HEADER_REMOVE;
		procCtx->ipogre_params.hdr_remove_param.hdr_len_remove =
			( iptype == IPA_IP_v4 ) ? sizeof(v4_ipogre_header) : sizeof(v6_ipogre_header);
	}
	else
	{
		procCtx->type         = IPA_HDR_PROC_GRE_HEADER_REMOVE;
		procCtx->gre_params.hdr_remove_param.hdr_len_remove =
			( iptype == IPA_IP_v4 ) ? sizeof(v4_ipogre_header) : sizeof(v6_ipogre_header);
	}

	if ( m_header.AddHeaderProcCtx(procCtxTable) == true )
	{
		IPACMDBG_H(
			"GRE header context successfully installed\n");

		IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_rmv_hdl =
			procCtx->proc_ctx_hdl;
	}
	else
	{
		IPACMERR("AddHeaderProcCtx failed\n");
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

int IPACM_Wan::ipgre_make_header_add_rt_rule(
	ipa_ipgre_info& ipgre_info,
	uint32_t        ctx_2use)
{
	enum ipa_ip_type iptype = ipgre_info.iptype;

	IPACMDBG_H(
		"Attempting to create iptype(%d) \"header add\" route rule for gre routing\n",
		iptype);

	ctx_2use = (ctx_2use) ? ctx_2use : IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl;

	if ( ctx_2use == 0 )
	{
		IPACMERR("Can't create a \"header add\" route rule without a context.\n");
		return IPACM_FAILURE;
	}

	if ( iptype == IPA_IP_v4 )
	{
		/*
		* For v4: install 1 rule matching rmnet data v4 src IP via dedicated API.
		* The rgip src-based rule is installed separately via ipgre_add_rgip_rt_rule().
		*/

		/* Install the wan_v4_addr src-based route rule via dedicated API */
		if ( ipgre_add_wan_v4_addr_rt_rule(ipgre_info) != IPACM_SUCCESS )
		{
			IPACMERR("ipgre_add_wan_v4_addr_rt_rule failed\n");
			return IPACM_FAILURE;
		}

		/* Install the rgip src-based route rule via dedicated API */
		if ( ipgre_add_rgip_rt_rule(ipgre_info) != IPACM_SUCCESS )
		{
			IPACMERR("ipgre_add_rgip_rt_rule failed\n");
			return IPACM_FAILURE;
		}
	}
	else
	{
		/*
		* Make "header add" route rule for v6...
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
			"GREV6RT");

		rt_rule_entry->at_rear                 = true;
		rt_rule_entry->rule.dst                = IPA_CLIENT_DUMMY_CONS;
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_DST_ADDR;
		rt_rule_entry->rule.hdr_proc_ctx_hdl   = ctx_2use;

#ifdef FEATURE_IPA_V3
		rt_rule_entry->rule.hashable           = true;
#endif
		rt_rule_entry->rule.retain_hdr         = 0;
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
				"GRE route rule for \"header add\" successfully installed in %s\n",
				rt_table->rt_tbl_name);
			IPACM_Wan::ipgre_route_data[iptype].rt_gre_add_hdl = rt_rule_entry->rt_rule_hdl;
		}
		else
		{
			IPACMERR("AddRoutingRule failed\n");
			return IPACM_FAILURE;
		}
	}

	return IPACM_SUCCESS;
}

int IPACM_Wan::ipgre_add_wan_v4_addr_rt_rule(
	ipa_ipgre_info& ipgre_info)
{
	enum ipa_ip_type iptype = ipgre_info.iptype;

	IPACMDBG_H(
		"Attempting to add wan_v4_addr src-based route rule for iptype(%d)\n",
		iptype);

	/* This rule is only applicable for IPv4 tunnels */
	if ( iptype != IPA_IP_v4 )
	{
		IPACMDBG_H("wan_v4_addr route rule is only applicable for IPv4, skipping\n");
		return IPACM_SUCCESS;
	}

	uint32_t hdr_2use = IPACM_Wan::ipgre_route_data[iptype].ul_header_hdl;

	/* Create a dedicated proc ctx for the wan_v4_addr rule */
	static const int NUM_OF_PROC_CTX = 1;

	uint8_t ctx_buf[
		sizeof(struct ipa_ioc_add_hdr_proc_ctx) +
		(NUM_OF_PROC_CTX * sizeof(struct ipa_hdr_proc_ctx_add)) ];

	memset(ctx_buf, 0, sizeof(ctx_buf));

	struct ipa_ioc_add_hdr_proc_ctx *procCtxTable =
		(struct ipa_ioc_add_hdr_proc_ctx *) ctx_buf;

	struct ipa_hdr_proc_ctx_add *procCtx = &(procCtxTable->proc_ctx[0]);

	procCtxTable->commit        = true;
	procCtxTable->num_proc_ctxs = NUM_OF_PROC_CTX;
	procCtx->proc_ctx_hdl       = -1; /* return value */
	procCtx->status             = -1; /* return parameter */
	procCtx->hdr_hdl            = hdr_2use;

	if ( IPACM_Iface::ipacmcfg->ipogre_enabled )
	{
		procCtx->type = IPA_HDR_PROC_IPOGRE_HEADER_ADD;
		procCtx->ipogre_params.hdr_add_param.input_ip_version  = iptype;

		procCtx->ipogre_params.hdr_add_param.Mux_Id = ext_prop->ext[0].mux_id;
		procCtx->ipogre_params.hdr_add_param.non_ipogre = 1;
	}
	else
        {
		procCtx->type = IPA_HDR_PROC_GRE_HEADER_ADD;
		procCtx->gre_params.hdr_add_param.eth_hdr_retained    = 0;
		procCtx->gre_params.hdr_add_param.input_ip_version    = iptype;
		procCtx->gre_params.hdr_add_param.output_ip_version   =
			IPACM_Iface::ipacmcfg->ipgre_info.iptype;
		procCtx->gre_params.hdr_add_param.second_pass         = 1;
	}

	if ( m_header.AddHeaderProcCtx(procCtxTable) == false )
	{
		IPACMERR("AddHeaderProcCtx for wan_v4_addr proc ctx failed\n");
		return IPACM_FAILURE;
	}

	IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl_wan_v4_addr =
		procCtx->proc_ctx_hdl;

	IPACMDBG_H(
		"wan_v4_addr proc ctx successfully installed, hdl 0x%x\n",
		IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl_wan_v4_addr);

	/* Now install the wan_v4_addr src-based route rule */
	static const int NUM_RT_RULE = 1;

	uint8_t rt_buf[
		sizeof(struct ipa_ioc_add_rt_rule) +
		(NUM_RT_RULE * sizeof(struct ipa_rt_rule_add)) ];

	memset(rt_buf, 0, sizeof(rt_buf));

	struct ipa_ioc_add_rt_rule *rt_table =
		(struct ipa_ioc_add_rt_rule *) rt_buf;

	rt_table->commit    = true;
	rt_table->num_rules = NUM_RT_RULE;
	rt_table->ip        = iptype;

	snprintf(rt_table->rt_tbl_name, sizeof(rt_table->rt_tbl_name),
		"%s", "GREV4RT");

	struct ipa_rt_rule_add *rt_rule_entry = &(rt_table->rules[0]);
	rt_rule_entry->at_rear                          = true;
	rt_rule_entry->rule.dst                         = IPA_CLIENT_DUMMY_CONS;
	rt_rule_entry->rule.attrib.attrib_mask          = IPA_FLT_SRC_ADDR;
	rt_rule_entry->rule.attrib.u.v4.src_addr        = wan_v4_addr;
	rt_rule_entry->rule.attrib.u.v4.src_addr_mask   = 0xFFFFFFFF;
	rt_rule_entry->rule.hdr_proc_ctx_hdl            =
		IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl_wan_v4_addr;
#ifdef FEATURE_IPA_V3
	rt_rule_entry->rule.hashable                    = true;
#endif
	rt_rule_entry->rule.retain_hdr                  = 0;

	IPACMDBG_H("Adding wan_v4_addr route rule with src_addr 0x%x\n", wan_v4_addr);

	if ( m_routing.AddRoutingRule(rt_table) == false )
	{
		IPACMERR("AddRoutingRule for wan_v4_addr failed\n");
		return IPACM_FAILURE;
	}

	IPACM_Wan::ipgre_route_data[iptype].rt_gre_add_hdl =
		rt_rule_entry->rt_rule_hdl;

	IPACMDBG_H(
		"wan_v4_addr route rule successfully installed in %s, hdl 0x%x\n",
		rt_table->rt_tbl_name,
		IPACM_Wan::ipgre_route_data[iptype].rt_gre_add_hdl);

	return IPACM_SUCCESS;
}

int IPACM_Wan::ipgre_add_rgip_rt_rule(
        ipa_ipgre_info& ipgre_info)
{
	enum ipa_ip_type iptype = ipgre_info.iptype;

	IPACMDBG_H(
		"Attempting to add rgip src-based route rule for iptype(%d)\n",
		iptype);

	/* This rule is only applicable for IPv4 tunnels */
	if ( iptype != IPA_IP_v4 )
	{
		IPACMDBG_H("rgip route rule is only applicable for IPv4, skipping\n");
		return IPACM_SUCCESS;
	}

	uint32_t hdr_2use = IPACM_Wan::ipgre_route_data[IPA_IP_v6].ul_header_hdl_c;


	/* Create a dedicated proc ctx for the rgip rule (mirrors ipgre_make_hdr_add_ctx) */
	static const int NUM_OF_PROC_CTX = 1;

	uint8_t ctx_buf[
		sizeof(struct ipa_ioc_add_hdr_proc_ctx) +
		(NUM_OF_PROC_CTX * sizeof(struct ipa_hdr_proc_ctx_add)) ];

	memset(ctx_buf, 0, sizeof(ctx_buf));

	struct ipa_ioc_add_hdr_proc_ctx *procCtxTable =
		(struct ipa_ioc_add_hdr_proc_ctx *) ctx_buf;

	struct ipa_hdr_proc_ctx_add *procCtx = &(procCtxTable->proc_ctx[0]);

	procCtxTable->commit        = true;
	procCtxTable->num_proc_ctxs = NUM_OF_PROC_CTX;
	procCtx->proc_ctx_hdl       = -1; /* return value */
	procCtx->status             = -1; /* return parameter */
	procCtx->hdr_hdl            = hdr_2use;

	if ( IPACM_Iface::ipacmcfg->ipogre_enabled )
	{
		procCtx->type = IPA_HDR_PROC_IPOGRE_HEADER_ADD;
		procCtx->ipogre_params.hdr_add_param.input_ip_version  = iptype;
		procCtx->ipogre_params.hdr_add_param.output_ip_version =
			IPACM_Iface::ipacmcfg->ipgre_info.iptype;
		procCtx->ipogre_params.hdr_add_param.non_ipogre = 0;
	}
	else
	{
		procCtx->type = IPA_HDR_PROC_GRE_HEADER_ADD;
		procCtx->gre_params.hdr_add_param.eth_hdr_retained    = 0;
		procCtx->gre_params.hdr_add_param.input_ip_version    = iptype;
		procCtx->gre_params.hdr_add_param.output_ip_version   =
			IPACM_Iface::ipacmcfg->ipgre_info.iptype;
		procCtx->gre_params.hdr_add_param.second_pass         = 1;
	}

	if ( m_header.AddHeaderProcCtx(procCtxTable) == false )
	{
		IPACMERR("AddHeaderProcCtx for rgip proc ctx failed\n");
		return IPACM_FAILURE;
	}

	IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl_rgip =
		procCtx->proc_ctx_hdl;

	IPACMDBG_H(
		"rgip proc ctx successfully installed, hdl 0x%x\n",
		IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl_rgip);

	/* Now install the rgip src-based route rule */
	static const int NUM_RT_RULE = 1;

	uint8_t rt_buf[
		sizeof(struct ipa_ioc_add_rt_rule) +
		(NUM_RT_RULE * sizeof(struct ipa_rt_rule_add)) ];

	memset(rt_buf, 0, sizeof(rt_buf));

	struct ipa_ioc_add_rt_rule *rt_table =
		(struct ipa_ioc_add_rt_rule *) rt_buf;

	rt_table->commit    = true;
	rt_table->num_rules = NUM_RT_RULE;
	rt_table->ip        = iptype;

	snprintf(rt_table->rt_tbl_name, sizeof(rt_table->rt_tbl_name),
		"%s", "GREV4RT");

	struct ipa_rt_rule_add *rt_rule_entry = &(rt_table->rules[0]);
	rt_rule_entry->at_rear                          = true;
	rt_rule_entry->rule.dst                         = IPA_CLIENT_DUMMY_CONS;
	rt_rule_entry->rule.attrib.attrib_mask          = IPA_FLT_SRC_ADDR;
	rt_rule_entry->rule.attrib.u.v4.src_addr        = IPACM_Iface::ipacmcfg->rgip_ip;
	rt_rule_entry->rule.attrib.u.v4.src_addr_mask   = 0xFFFFFFFF;
	rt_rule_entry->rule.hdr_proc_ctx_hdl            =
		IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl_rgip;
#ifdef FEATURE_IPA_V3
	rt_rule_entry->rule.hashable                    = true;
#endif
	rt_rule_entry->rule.retain_hdr                  = 0;

	IPACMDBG_H("Adding rgip route rule with src_addr 0x%x\n",
		IPACM_Iface::ipacmcfg->rgip_ip);

	if ( m_routing.AddRoutingRule(rt_table) == false )
	{
		IPACMERR("AddRoutingRule for rgip failed\n");
		return IPACM_FAILURE;
	}

	IPACM_Wan::ipgre_route_data[iptype].rt_gre_add_hdl_rgip =
		rt_rule_entry->rt_rule_hdl;

	IPACMDBG_H(
		"rgip route rule successfully installed in %s, hdl 0x%x\n",
		rt_table->rt_tbl_name,
		IPACM_Wan::ipgre_route_data[iptype].rt_gre_add_hdl_rgip);

	return IPACM_SUCCESS;
}

int IPACM_Wan::ipgre_make_header_rmv_rt_rule(
	ipa_ipgre_info& ipgre_info)
{
	enum ipa_ip_type iptype = ipgre_info.iptype;

	IPACMDBG_H(
		"Attempting to create iptype(%d) \"header remove\" route rule for gre routing\n",
		iptype);

	if ( IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_rmv_hdl == 0 )
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
	rt_rule_entry->rule.hdr_proc_ctx_hdl   =
		IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_rmv_hdl;
#ifdef FEATURE_IPA_V3
	rt_rule_entry->rule.hashable           = true;
#endif
	rt_rule_entry->rule.retain_hdr         = 0;
	rt_rule_entry->rule.dst                = IPA_CLIENT_DUMMY_CONS;

	if ( ipgre_info.iptype == IPA_IP_v4 )
	{
		rt_rule_entry->rule.attrib.u.v4.src_addr_mask = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.u.v4.src_addr      = ipgre_info.ipv4_dst;
		rt_rule_entry->rule.attrib.u.v4.dst_addr_mask = 0xFFFFFFFF;
		rt_rule_entry->rule.attrib.u.v4.dst_addr      = ipgre_info.ipv4_src;
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_SRC_ADDR | IPA_FLT_DST_ADDR| IPA_FLT_PROTOCOL;
		rt_rule_entry->rule.attrib.u.v4.protocol=(uint8_t)IPACM_FIREWALL_IPPROTO_GRE;/* Adding additional GRE protocol check*/
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
		rt_rule_entry->rule.attrib.attrib_mask = IPA_FLT_SRC_ADDR | IPA_FLT_DST_ADDR| IPA_FLT_NEXT_HDR;
		rt_rule_entry->rule.attrib.u.v6.next_hdr=(uint8_t)IPACM_FIREWALL_IPPROTO_GRE;
	}

	if ( m_routing.AddRoutingRule(rt_table) == true )
	{
		IPACMDBG_H(
			"GRE route rule for \"header remove\" successfully installed in %s\n",
			rt_table->rt_tbl_name);
		IPACM_Wan::ipgre_route_data[iptype].rt_gre_rmv_hdl = rt_rule_entry->rt_rule_hdl;
	}
	else
	{
		IPACMERR("AddRoutingRule failed\n");
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

void IPACM_Wan::ipgre_clear_route_data(
	enum ipa_ip_type             iptype)
{
	if ( VALID_IPA_IP_TYPE(iptype) )
	{
		if ( IPACM_Wan::ipgre_route_data[iptype].ul_header_hdl )
		{
			m_header.DeleteHeaderHdl(
				IPACM_Wan::ipgre_route_data[iptype].ul_header_hdl);
		}

		if ( IPACM_Wan::ipgre_route_data[iptype].dl_header_hdl )
		{
			m_header.DeleteHeaderHdl(
				IPACM_Wan::ipgre_route_data[iptype].dl_header_hdl);
		}

		if ( IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl )
		{
			m_header.DeleteHeaderProcCtx(
				IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl);
		}

		if ( IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl_rgip )
		{
			m_header.DeleteHeaderProcCtx(
				IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl_rgip);
		}

		if ( IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl_wan_v4_addr )
		{
			m_header.DeleteHeaderProcCtx(
				IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_add_hdl_wan_v4_addr);
		}

		if ( IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_rmv_hdl )
		{
			m_header.DeleteHeaderProcCtx(
				IPACM_Wan::ipgre_route_data[iptype].proc_ctx_gre_rmv_hdl);
		}

		if ( IPACM_Wan::ipgre_route_data[iptype].rt_gre_add_hdl )
		{
			m_routing.DeleteRoutingHdl(
				IPACM_Wan::ipgre_route_data[iptype].rt_gre_add_hdl, iptype);
		}

		if ( IPACM_Wan::ipgre_route_data[iptype].rt_gre_add_hdl_rgip )
		{
			m_routing.DeleteRoutingHdl(
				IPACM_Wan::ipgre_route_data[iptype].rt_gre_add_hdl_rgip, iptype);
		}

		if ( IPACM_Wan::ipgre_route_data[iptype].rt_gre_rmv_hdl )
		{
			m_routing.DeleteRoutingHdl(
				IPACM_Wan::ipgre_route_data[iptype].rt_gre_rmv_hdl, iptype);
		}

		if(IPACM_Wan::ipgre_route_data[iptype].ul_header_hdl_c){
			m_header.DeleteHeaderHdl(IPACM_Wan::ipgre_route_data[iptype].ul_header_hdl_c);
		}
		ipgre_route_data_init(iptype);
	}
}

#endif // endif pmipv6
