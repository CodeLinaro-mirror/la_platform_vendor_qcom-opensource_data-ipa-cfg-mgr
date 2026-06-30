/*
Copyright (c) 2013, 2018-2021, The Linux Foundation. All rights reserved.

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
/*!
	@file
	IPACM_Wan.cpp

	@brief
	This file implements the WAN iface functionality.

	@Author
	Skylar Chang

*/
#ifndef IPACM_WAN_H
#define IPACM_WAN_H

#include <stdio.h>
#include <IPACM_CmdQueue.h>
#include <linux/msm_ipa.h>
#include "IPACM_Routing.h"
#include "IPACM_Filtering.h"
#include <IPACM_Iface.h>
#include <IPACM_Defs.h>
#include <IPACM_Xml.h>

#define IPA_NUM_DEFAULT_WAN_FILTER_RULES 6 /*best effort pipe-> 0 for v4, 1 for v6, 4 for v6 icmp; QoS pipe-> 2 for v4, 3 for v6, 5 for v6 icmp*/
#define IPA_V2_NUM_DEFAULT_WAN_FILTER_RULE_IPV4 3 /*Multicast rule + broadcast rule + tcp syn bit rule */
#define XLAT_IP 0xc0000000

#define MAX_IPv4_PREFIX_LEN 32
#define MAX_PREFIX_LEN 64

#define NETWORK_STATS "%s %llu %llu %llu %llu"
#ifdef FEATURE_IPA_ANDROID
#define IPA_NETWORK_STATS_FILE_NAME "/data/misc/ipa/network_stats"
#else
#define IPA_NETWORK_STATS_FILE_NAME "/tmp/network_stats"
#endif

extern int bool_dual_backhaul;

typedef struct _wan_client_rt_hdl
{
	uint32_t wan_rt_rule_hdl_v4;
}wan_client_rt_hdl;

typedef struct _ipa_wan_client
{
	ipacm_event_data_wlan_ex* p_hdr_info;
	uint8_t mac[IPA_MAC_ADDR_SIZE];
	uint32_t v4_addr;
	uint32_t hdr_hdl_v4;
	uint32_t hdr_hdl_v6;
	bool route_rule_set_v4;
	int route_rule_set_v6;
	bool ipv4_set;
	int ipv6_set;
	bool ipv4_header_set;
	bool ipv6_header_set;
	uint32_t sta_hdr_proc_hdl_v4;
	uint32_t sta_hdr_proc_hdl_v6;
	bool sta_hdr_proc_ctx_set;
	bool power_save_set;
	wan_client_rt_hdl wan_rt_hdl[0]; /* depends on number of tx properties */
}ipa_wan_client;

typedef struct {
	int rule_number;
	int fmr;
	uint32_t ipv4prefix;
	uint32_t ipv6prefix[4];
	int ipv4prefixlen;
	int ipv6prefixlen;
	uint8_t ea_len;
	uint8_t offset;
	uint8_t psid_len;
	uint32_t route_rule_hdl;
	uint8_t mac[IPA_MAC_ADDR_SIZE];
	uint32_t fmr_proc_ctx_hdl;
	uint32_t mape_fmr_hdr_hdl;
	int ref_count;
} MapeFMR;

struct MapRule {
	std::vector<MapeFMR> fmr_rules;
	uint32_t br_ipaddr[4];
	uint8_t mac[IPA_MAC_ADDR_SIZE];
	bool draft03;
};

class IPACM_Wan;

typedef struct
{
	uint32_t ipv4_addr;
	bool wan_up_vlan;
	bool is_xlat;
	uint16_t associated_VIDs[IPA_MAX_NUM_SW_PDNS];
	uint8_t VID_cnt = 0;
	IPACM_Wan *pIface;
}ipacm_ipv4_wan_iface;

typedef struct
{
	uint32_t ipv6_prefix[2];
	bool wan_up_vlan_v6;
	uint16_t associated_VIDs[IPA_MAX_NUM_SW_PDNS];
	uint8_t VID_cnt = 0;
	IPACM_Wan *pIface;
}ipacm_ipv6_wan_iface;

/*
 *  * v4_association: The WAN interface V4 VLAN is associated to
 *  * v6_association: The WAN interface V6 VLAN is associated to
 *  * v4_idx: Index of the WAN interface in ipv4_to_iface to which VLAN is associated
 *  * v6_idx: Index of the WAN interface in ipv6_to_iface to which VLAN is associated
 *  * v4_vlan_idx: Index of vlan_id in the associated_VIDs[] of ipv4_to_iface[v6_idx]
 *  * v6_vlan_idx: Index of vlan_id in the associated_VIDs[] of ipv6_to_iface[v6_idx]
 *  * vlan_id : VLAN ID
 */
typedef struct
{
	ipacm_wan_iface_type v4_association;
	ipacm_wan_iface_type v6_association;
	int v4_idx[IFACE_MAX];
	int v6_idx[IFACE_MAX];
	int v4_vlan_idx[IFACE_MAX];
	int v6_vlan_idx[IFACE_MAX];
	uint16_t vlan_id;
#ifdef FEATURE_PPPOE
	uint32_t wan_v4_addr;
	uint32_t ipv6_prefix[2];
#endif
}ipacm_vlan_association_info;

struct ipacm_pdn_flt_rule
{
	struct ipa_flt_rule_add flt_rule;
	uint8_t mux_id;
};
#ifdef FEATURE_PPPOE
/*
 * PPPoE header..
 * 1st word: version + type
 * 2nd word: session id
 * 3rd word: payload length
 * 4th word: protocol type
 */
typedef struct pppoe_hdr_s
{
	uint16_t words[4];
} pppoe_hdr_t;


/*
 *  * Where things reside in the struct above...
 *   */
#define PPPOE_SESSION_ID_IDX	1
#define PPPOE_PAYLOAD_LEN_IDX	2
#define PPPOE_PROTOCOL_ID_IDX	3
#define PPPOE_PROTOCOL_V4_TYPE	0x0021
#define PPPOE_PROTOCOL_V6_TYPE	0x0057
#define PPPOE_SESSION_ETH_TYPE	0x8864
#endif

typedef struct ipgre_route_data_s
{
	uint32_t ul_header_hdl;
	uint32_t ul_header_hdl_c; /* Complementary hdr handle. For v4 tunnel and v6 data, and v6 tunnel and v4 data */
	uint32_t dl_header_hdl;
	uint32_t proc_ctx_gre_add_hdl;
	uint32_t proc_ctx_gre_add_hdl_rgip; /* v4 only: separate proc ctx for rgip src-based rule */
	uint32_t proc_ctx_gre_add_hdl_wan_v4_addr; /* v4 only: separate proc ctx for wan_v4_addr src-based rule */
	uint32_t proc_ctx_gre_rmv_hdl;
	uint32_t rt_gre_add_hdl;
	uint32_t rt_gre_add_hdl_rgip; /* v4 only: rule matching rgip src addr */
	uint32_t rt_gre_rmv_hdl;
	uint32_t rt_tbl_hdl;
} ipgre_route_data_t;
/*
 * Enough space for:
 *
 * -> An IP v4 header (five 32-bit words),
 * -> A GRE header (one 32-bit word), and
 * -> An MPLS header (one 32-bit word).
 */
typedef struct v4_ipgre_hdr_s
{
	uint32_t words[7];
} v4_ipgre_hdr_t;


/*
 * Where things reside in the struct above...
 */
#define IPV4_SRC_ADDR_IDX  3
#define IPV4_DST_ADDR_IDX  4
#define IPV4_GRE_PROT_IDX  5
#define IPV4_MPLS_PROT_IDX 6

/*
 * Enough space for:
 *
 * -> An IP v6 header (ten 32-bit words),
 * -> An IP v6 extension header (two 32-bit words),
 * -> A GRE header (one 32-bit word), and
 * -> An MPLS header (one 32-bit word).
 */
typedef struct v6_ipgre_hdr_s
{
	uint32_t words[14];
} v6_ipgre_hdr_t;

/*
 * Where things reside in the struct above...
 */
#define IPV6_SRC_ADDR_IDX   2
#define IPV6_DST_ADDR_IDX   6
#define IPV6_GRE_PROT_IDX  10
#define IPV6_GRE_PROT_IDX_OP  12
#define IPV6_GRE_PMIP_PROT_IDX  10

/* wan iface */
class IPACM_Wan : public IPACM_Iface
{

public:
	/* IPACM pm_depency q6 check*/
	static int ipa_pm_q6_check;
	static bool wan_up;
	static bool wan_up_v6;
	static uint8_t xlat_mux_id;
#ifdef FEATURE_VLAN_MPDN
#ifdef FEATURE_IPACM_UL_FIREWALL
	int num_firewall_v6_ul_pdn;
#endif
	uint16_t associated_VID;
	/* once STA up, need associated pending VID to STA-WAN */
	std::list<uint16_t> pending_VID_STA;
#endif
	static uint16_t mtu_default_wan_v4;
	static uint16_t mtu_default_wan_v6;

#if defined(FEATURE_EoGRE) || defined(FEATURE_PMIPV6)
	static uint16_t mtu_gre_v4;
	static uint16_t mtu_gre_v6;
#endif
#if defined(FEATURE_PMIPV6) || defined(FEATURE_IPoGRE)
	/*
	 * The following is for keeping gre route rule state...
	 *
	 * We're using two below (one for v4, one for v6) because there
	 * may be a mismatch between the tunnel iptype (ie. the one
	 * specified in the gre enable) and the Vlan Ethernet packet's
	 * IP payload type. In other words:
	 *
	 *   The tunnel may be v4, while the Vlan Ethernet packet's IP
	 *   type is v6; or
	 *
	 *   The tunnel may be v6, while the Vlan Ethernet packet's IP
	 *   type is v4...
	 */
	static ipgre_route_data_t ipgre_route_data[IPA_IP_MAX];

	int ipgre_do_rt_work(
		ipa_ipgre_info& ipgre_info);

	void ipgre_route_data_init(
		enum ipa_ip_type iptype );

	static uint32_t ipgre_get_rt_tbl_hdl(
		enum ipa_ip_type iptype);

	int ipgre_make_hdr_for_add_ctx(
		ipa_ipgre_info& ipgre_info);

	int ipgre_make_hdr_add_ctx(
		ipa_ipgre_info& ipgre_info,
		uint32_t        hdr_2use = 0);

	int ipgre_make_hdr_for_rmv_ctx(
		ipa_ipgre_info& ipgre_info);

	int ipgre_make_hdr_rmv_ctx(
		ipa_ipgre_info& ipgre_info,
		uint32_t        hdr_2use = 0);

	int ipgre_make_header_add_rt_rule(
		ipa_ipgre_info& ipgre_info,
		uint32_t        ctx_2use = 0);

	int ipgre_add_rgip_rt_rule(
		ipa_ipgre_info& ipgre_info);

	int ipgre_add_wan_v4_addr_rt_rule(
		ipa_ipgre_info& ipgre_info);

	int ipgre_make_header_rmv_rt_rule(
		ipa_ipgre_info& ipgre_info);

	int ipgre_install_dl_exception_flt_rule(
		const struct ipa_rule_attrib& rx_prop_attrib, struct ipa_flt_rule_add& flt_rule_add,
		int fltr_rule_number, enum ipa_ip_type iptype);

	void ipgre_clear_route_data(
		enum ipa_ip_type             iptype);
#endif

	/* IPACM interface name */
	static char wan_up_dev_name[IF_NAME_LEN];
	static uint32_t curr_wan_ip;
	static int num_ipv4_sta_pdn;
	static int num_ipv6_sta_pdn;

	/* MAPE details */
	static uint32_t mape_wan_rt_rule_hdl_v6;
	static uint32_t mape_wan_rt_rule_hdl_v4;
	static struct MapRule mape_rules;
	static uint32_t mape_wan_ipv4_addr;
	static uint32_t mape_wan_ipv6_addr[4];
	static uint32_t mape_fmr_hdr_hdl;
	static pthread_mutex_t m_fmr_mutex;
	static bool mape_rules_initialized;
	uint32_t mape_wan_fl_hdl;

	IPACM_Wan(int, ipacm_wan_iface_type, uint8_t *, bool is_ppp_iface = true);
	virtual ~IPACM_Wan();
#ifdef FEATURE_IPACM_UL_FIREWALL
	/* IPACM firewall Configuration file*/
	static IPACM_firewall_conf_t firewall_config_ul;
#ifdef FEATURE_VLAN_MPDN
	static IPACM_firewall_t firewall_mpdn_config_ul;
#endif //FEATURE_VLAN_MPDN
	static int read_firewall_filter_rules_ul(void);

	static bool check_dft_firewall_rules_attr_mask_ul(IPACM_firewall_conf_t *firewall_config);
	uint32_t v4_p_ctx_2use;
	uint32_t v6_p_ctx_2use;
#ifdef FEATURE_PPPOE
	int pppoe_make_hdr_add_ctx(enum ipa_ip_type iptype);
	int pppoe_del_hdr_proc_ctx(enum ipa_ip_type ip_type);
#endif
	int mape_make_hdr_add_ctx(enum ipa_ip_type iptype);
	int mape_del_hdr_proc_ctx(enum ipa_ip_type ip_type);
	int mape_make_fmr_hdr_add_ctx(MapeFMR* fmr_rule);
	int mape_fmr_route_rule_add(uint32_t ip_addr);
	int mape_fmr_route_rule_del(uint32_t ip_addr);
#ifdef FEATURE_VLAN_MPDN
	static int get_v6_pdn_firewall_configs(
		std::pair<IPACM_firewall_conf_t*, ipacm_ipv6_wan_iface*> wan_firewall_pair[],
		IPACM_firewall_t &firewall_configs);

	static IPACM_firewall_conf_t* get_firewall_conf_by_vid_ul(int vid);

	void set_swallow_pdn_up(void);
#endif //FEATURE_VLAN_MPDN
	static IPACM_firewall_conf_t* get_default_profile_firewall_conf_ul(int *default_vid);

	static int set_pdn_num_fw_rules_by_vid(int vid, int num_fw_rules);

	static int get_pdn_num_fw_rules_by_vid(int vid, int *num_fw_rules);
#endif //FEATURE_IPACM_UL_FIREWALL
#ifdef FEATURE_VLAN_MPDN
	static int GetV6PrefixByVid(int vid, uint32_t *v6_prefix);
	static int GetV6MTUByPrefix(uint16_t *mtu, uint32_t *v6_prefix);
	static IPACM_firewall_conf_t* get_curr_pdn_firewall_config(IPACM_firewall_t &firewall_configs, const char* dev_name);
#endif
	static bool isWanUP(int ipa_if_num_tether)
	{
#ifdef FEATURE_IPA_ANDROID
		int i;
		for (i=0; i < ipa_if_num_tether_v4_total;i++)
		{
			if (ipa_if_num_tether_v4[i] == ipa_if_num_tether)
			{
				IPACMDBG_H("support ipv4 tether_iface(%s)\n",
					IPACM_Iface::ipacmcfg->iface_table[ipa_if_num_tether].iface_name);
				return wan_up;
				break;
			}
		}
		return false;
#else
		IPACMDBG_H("return wan_up %d\n", wan_up);
		return wan_up;
#endif
	}

	static uint16_t queryMTU(int ipa_if_num_tether, enum ipa_ip_type iptype)
	{
		if (iptype == IPA_IP_v4)
		{
#ifdef FEATURE_EoGRE
			if (IPACM_Iface::ipacmcfg->eogre_enabled)
			{
				IPACMDBG_H("got mtu_gre_v4\n")
				return mtu_gre_v4;
			}
#endif
#ifdef FEATURE_PMIPV6
			if (IPACM_Iface::ipacmcfg->pmip_details.pmipv6_enabled)
			{
				IPACMDBG_H("got mtu_gre_v4\n")
				return mtu_gre_v4;
			}
#endif
			if (isWanUP(ipa_if_num_tether))
			{
				IPACMDBG_H("got mtu_default_v4\n")
				return mtu_default_wan_v4;
			}
		}
		else if (iptype == IPA_IP_v6)
		{
#ifdef FEATURE_EoGRE
			if (IPACM_Iface::ipacmcfg->eogre_enabled)
			{
				IPACMDBG_H("got mtu_gre_v6\n")
				return mtu_gre_v6;
			}
#endif
#ifdef FEATURE_PMIPV6
			if (IPACM_Iface::ipacmcfg->pmip_details.pmipv6_enabled)
			{
				IPACMDBG_H("got mtu_gre_v6\n")
				return mtu_gre_v6;
			}
#endif
			if (isWanUP_V6(ipa_if_num_tether))
			{
				IPACMDBG_H("got mtu_default_v6\n")
				return mtu_default_wan_v6;
			}
		}

		IPACMDBG_H("No conditions hit. Return default value %d", DEFAULT_MTU_SIZE);
		return DEFAULT_MTU_SIZE;
	}

#ifdef FEATURE_VLAN_MPDN
	static bool isVlanWanUP(bool any_backhaul = false)
	{
		for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
		{
			if(ipv4_to_iface[i].ipv4_addr && ipv4_to_iface[i].wan_up_vlan && ipv4_to_iface[i].pIface != NULL)
			{
				if(ipv4_to_iface[i].pIface->m_is_sta_mode == Q6_WAN || any_backhaul)
				{
					IPACMDBG_H("iface %s is vlan up\n", ipv4_to_iface[i].pIface->dev_name);
					return true;
				}
			}
		}
		IPACMDBG_H("No v4 vlan WAN is up\n");
		return false;
	}

	static bool isVlanWanUP_V6(bool any_backhaul = false)
	{
		for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
		{
			if(ipv6_to_iface[i].wan_up_vlan_v6  && ipv6_to_iface[i].pIface != NULL)
			{
				if(ipv6_to_iface[i].pIface->m_is_sta_mode == Q6_WAN || any_backhaul)
				{
					IPACMDBG_H("iface %s is vlan up v6\n", ipv6_to_iface[i].pIface->dev_name);
					return true;
				}
			}
		}
		IPACMDBG_H("No v6 vlan WAN is up\n");
		return false;
	}

	static int getFreePDNIndex_V4()
	{
		for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
		{
			if(!ipv4_to_iface[i].pIface)
			{
				IPACMDBG_H("iface index %d is free\n", i);
				return i;
			}
		}
		return -1;
	}

	static int getFreePDNIndex_V6()
	{
		for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
		{
			if(!ipv6_to_iface[i].pIface)
			{
				IPACMDBG_H("iface index %d is free\n", i);
				return i;
			}
		}
		return -1;
	}

	static bool isDefaultGatewayIfaceUp(IPACM_Wan *iface)
	{
		if(wan_up && iface->is_default_gateway)
		{
			IPACMDBG("iface %s, wan_up %d, is_default_gateway %d\n",
				iface->dev_name, wan_up, iface->is_default_gateway);
			return true;
		}
		return false;
	}

	static bool isDefaultGatewayIfaceUp_v6(IPACM_Wan *iface)
	{
		if(wan_up_v6 && iface->is_default_gateway)
		{
			IPACMDBG("iface %s, wan_up_v6 %d, is_default_gateway %d\n",
				iface->dev_name, wan_up_v6, iface->is_default_gateway);
			return true;
		}
		return false;
	}
#endif

	static bool isWanUP_V6(int ipa_if_num_tether)
	{
#ifdef FEATURE_IPA_ANDROID
		int i;
		for (i=0; i < ipa_if_num_tether_v6_total;i++)
		{
			if (ipa_if_num_tether_v6[i] == ipa_if_num_tether)
			{
				IPACMDBG_H("support ipv6 tether_iface(%s)\n",
					IPACM_Iface::ipacmcfg->iface_table[ipa_if_num_tether].iface_name);
				return wan_up_v6;
				break;
			}
		}
		return false;
#else
		return wan_up_v6;
#endif
	}

	static bool isWan_active_with_prefix(uint32_t *v6_addr)
	{
		if(v6_addr == NULL)
		{
			IPACMERR("IPv6 address is empty.\n");
			return false;
		}

		IPACMDBG_H("Received prefix: 0x%08x%08x\n", v6_addr[0], v6_addr[1]);

		for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
		{
			if(ipv6_to_iface[i].ipv6_prefix[0] == v6_addr[0] &&
				ipv6_to_iface[i].ipv6_prefix[1] == v6_addr[1] &&
				((v6_addr[0] != 0) && (v6_addr[1] != 0)))
			{
				IPACMDBG_H("v6 prefix mached pdn %s\n", ipv6_to_iface[i].pIface->dev_name);
				return true;
			}
			else
			{
				IPACMDBG_H("index: %d Current prefix: 0x%08x%08x\n", i,
					ipv6_to_iface[i].ipv6_prefix[0],
					ipv6_to_iface[i].ipv6_prefix[1]);
			}
		}
		IPACMDBG_H("V6 prefix didnt match any active wan iface\n");
		return false;
	}

	static uint32_t getWANIP()
	{
		return curr_wan_ip;
	}

	static uint8_t getXlat_Mux_Id()
	{
		return xlat_mux_id;
	}

	static bool check_client_ipv4_with_pdn_ipv4(uint32_t client_ip, uint16_t vlan_id)
	{
		IPACMDBG_H("vlan_id %d \n", vlan_id);
		IPACMDBG_H("Client IP: 0x%x\n", client_ip);
		for(int i = 0; i < IPA_MAX_NUM_SW_PDNS; i++)
		{
			IPACMDBG_H("IPACM_Wan::ipv4_to_iface[%d].ipv4_addr: 0x%x\n", i, IPACM_Wan::ipv4_to_iface[i].ipv4_addr);
			if(IPACM_Wan::ipv4_to_iface[i].ipv4_addr &&
					ipv4_to_iface[i].ipv4_addr == client_ip)
			{
				IPACMDBG_H("Client IP Matched With Wan IP! at index %d \n", i);
				return true;
			}
		}
		return false;
	}

	void event_callback(ipa_cm_event_id event, void *data);

#ifdef FEATURE_VLAN_MPDN
	static struct ipacm_pdn_flt_rule pdn_flt_rule_v4[IPA_MAX_FLT_RULE];
	static struct ipacm_pdn_flt_rule pdn_flt_rule_v6[IPA_MAX_FLT_RULE];
	static int wlan_v4_vlan_index;
	static int wlan_v6_vlan_index;
	static int eth_sta_v4_vlan_index;
	static int eth_sta_v6_vlan_index;
#endif
	static struct ipa_flt_rule_add flt_rule_v4[IPA_MAX_FLT_RULE];
	static struct ipa_flt_rule_add flt_rule_v6[IPA_MAX_FLT_RULE];

#ifdef FEATURE_IPACM_UL_FIREWALL
	static struct ipa_flt_rule_add firewall_flt_rule_v6_ul[IPACM_MAX_FIREWALL_ENTRIES+1];
#endif

	static int num_v4_flt_rule;
	static int num_v6_flt_rule;
#ifdef FEATURE_VLAN_MPDN
	static int ipv6_mpdn_default_filterting_rules_count;
#endif
#ifdef FEATURE_IPACM_UL_FIREWALL
	static int num_firewall_v6_ul;
#endif
#ifdef FEATURE_IPA_IPSEC
	static uint32_t ipsec_post_pol_rt_hdls[IPA_IP_MAX][IPA_MAX_FLT_RULE];
	static int num_ipsec_post_pol_rt[IPA_IP_MAX];
#endif
	ipacm_wan_iface_type m_is_sta_mode;
	static bool backhaul_is_sta_mode;
	ipacm_event_ip_pass_pdn_info ip_pass_pdn_info;
	ipacm_event_ip_collision_pdn_info ip_collision_pdn_info;
	static bool is_ext_prop_set;
	static uint32_t backhaul_ipv6_prefix[2];

#ifdef FEATURE_DUAL_BACKHAUL
	static uint32_t second_backhaul_ipv4;
	static bool second_backhaul_active;
#endif

#ifdef FEATURE_IPACM_UL_FIREWALL
	static int m_fd_ipa_ul;
#endif

	static bool embms_is_on;
	static bool backhaul_is_wan_bridge;

	static bool isWan_Bridge_Mode()
	{
		return backhaul_is_wan_bridge;
	}
#ifdef FEATURE_IPA_ANDROID
	/* IPACM interface id */
	static int ipa_if_num_tether_v4_total;
	static int ipa_if_num_tether_v4[IPA_MAX_IFACE_ENTRIES];
	static int ipa_if_num_tether_v6_total;
	static int ipa_if_num_tether_v6[IPA_MAX_IFACE_ENTRIES];
#endif

	static bool is_global_ipv6_addr(uint32_t* ipv6_addr);
	static bool is_link_local_ipv4_addr(uint32_t ipv4_addr);
#ifdef FEATURE_VLAN_MPDN
	static ipacm_ipv4_wan_iface ipv4_to_iface[IPA_MAX_NUM_SW_PDNS];
	static ipacm_ipv6_wan_iface ipv6_to_iface[IPA_MAX_NUM_SW_PDNS];
	static uint8_t num_offloaded_pdns;
	static int GetMuxByVid(uint16_t vlan_id, uint8_t *mux_id, ipa_ip_type iptype);
	static int GetMTUByVid(uint16_t *mtu, uint16_t vlan_id, ipa_ip_type iptype);
	static int GetWanPDNinfo(uint16_t *mtu, uint32_t *ipv4_addr, ipa_ip_type iptype);
	static int GetWanPDNinfo_v6(uint16_t *mtu, uint32_t (*ipv6_prefix)[2], ipa_ip_type iptype);
	static int Getv6addrByName(char* pdn_name, uint32_t* ipv6_addr);
	static uint32_t GetQCMAPhdrByName(char* pdn_name);
	static uint32_t GetQCMAPhdrOfFirstRmnet(ipa_ip_type ipType);
	static bool is_xlat_by_vid(uint16_t vlan_id);
	static int get_vid_index_for_iface_v6(ipacm_ipv6_wan_iface iface, uint16_t vlan_id);
	static bool is_xlat_by_ipv4(uint32_t ipv4_addr);
#endif

#ifdef FEATURE_EoGRE
	void eogre_up();

	void eogre_down();

	int eogre_v4_work(
		bool eogre_enable );

	int eogre_v6_work(
		bool eogre_enable );

	int eogre_notify_wan_state(
		bool eogre_enable );
#endif
#ifdef FEATURE_PMIPV6
	void gre_up();

	void gre_down();

	int gre_v4_work(
		bool gre_enable );

	int gre_v6_work(
		bool gre_enable );

	int gre_notify_wan_state(
		bool gre_enable );
#endif
	static const uint8_t v4_gre_header[];
	static const uint8_t v6_gre_header[];
	static const uint8_t v4_ipogre_header[];
	static const uint8_t v6_ipogre_header[];
	static const uint8_t v6_ipogre_header_op[];
	static int GetMuxByAddr(
		enum ipa_ip_type iptype,
		void*            addr,
		uint8_t&         mux_id );

#ifdef FEATURE_IPA_IPSEC
	/*
	 * The FLT rules that we send to Q6 via QMI are being skipped by IPsec packets.
	 * Therefore we have to add these rules after IPsec DL policying. Since the policying is done
	 * In 3rd round filtering table, the rules have to go to the DL routing table.
	 * This method creates all routing rules for an IP type and installs them.
	 *
	 * @ipType: IP type
	 */
	static int installWanPostIpsecRt(ipa_ip_type ipType);
#endif
	void read_from_mape_rules_file(void);
	MapeFMR* get_rule_by_ipv4(uint32_t input_ipv4_host_order);
	MapeFMR* get_rule_by_ipv6(uint32_t input_ipv6_host_order[4]);

private:

	bool is_ipv6_frag_firewall_flt_rule_installed;
	uint32_t ipv6_frag_firewall_flt_rule_hdl;
	uint32_t *wan_route_rule_v4_hdl;
	uint32_t *wan_route_rule_v6_hdl;
	uint32_t hdr_hdl_sta_v4;
	uint32_t hdr_hdl_sta_v6;
	uint32_t proc_hdl_sta_v4;
	uint32_t proc_hdl_sta_v6;
	uint32_t firewall_hdl_v4[IPACM_MAX_FIREWALL_ENTRIES];
	uint32_t firewall_hdl_v6[IPACM_MAX_FIREWALL_ENTRIES];
	uint32_t dft_wan_fl_hdl[IPA_NUM_DEFAULT_WAN_FILTER_RULES];
#ifdef FEATURE_IPV6_NAT
	uint32_t ipv6_ula_prefix_hdl;
#endif
	uint32_t ipv6_dest_flt_rule_hdl[MAX_DEFAULT_v6_ROUTE_RULES];
	int num_ipv6_dest_flt_rule;
	uint32_t ODU_fl_hdl[IPA_NUM_DEFAULT_WAN_FILTER_RULES];
	int num_firewall_v4,num_firewall_v6;
	uint32_t wan_v4_addr;
	uint32_t public_wan_v4_addr;
	uint32_t wan_v4_addr_gw;
	uint32_t wan_v6_addr_gw[4];
	bool wan_v4_addr_set;
	bool public_wan_v4_addr_set;
	bool wan_v4_addr_gw_set;
	bool wan_v6_addr_gw_set;
	bool wan_v4_is_default_gw;
	bool wan_v6_is_default_gw;
	bool active_v4;
	bool active_v6;
	bool header_set_v4;
	bool header_set_v6;
	bool hdr_proc_set_v4;
	bool hdr_proc_set_v6;
	bool header_partial_default_wan_v4;
	bool header_partial_default_wan_v6;
	uint8_t ext_router_mac_addr[IPA_MAC_ADDR_SIZE];
	uint8_t netdev_mac[IPA_MAC_ADDR_SIZE];

	static uint32_t wan_route_rule_lan_v6_hdl_a5;
	static uint32_t wan_route_rule_wan_v6_hdl_a5;

	static uint32_t pppoe_route_rule_hdl_v4;
	static uint32_t pppoe_route_rule_hdl_v6;

	static int num_ipv4_modem_pdn;

	static int num_ipv6_modem_pdn;

	int modem_ipv4_pdn_index;

	int modem_ipv6_pdn_index;

	int sta_ipv4_pdn_index;

	int sta_ipv6_pdn_index;

	uint16_t sta_vlan_id;

	uint8_t sta_vlan_pcp;

	bool is_default_gateway;

	uint32_t ipv6_prefix[2];
	uint32_t m_ipv6_addr[IPA_IPV6_ADDR_SIZE_IN_WORDS];

	/* STA mode wan-client*/
	int wan_client_len;
	ipa_wan_client *wan_client;
	int header_name_count;
	int num_wan_client;
	uint8_t invalid_mac[IPA_MAC_ADDR_SIZE];
	bool is_xlat;

	/* update network stats for CNE */
	uint32_t hdr_hdl_dummy_v6;
	uint32_t hdr_proc_hdl_dummy_v6;

	/* V4 MTU value. */
	uint16_t mtu_v4;
	bool mtu_v4_set;

	/* V6 MTU value. */
	uint16_t mtu_v6;
	bool mtu_v6_set;

	inline ipa_wan_client* get_client_memptr(ipa_wan_client *param, int cnt)
	{
	    char *ret = ((char *)param) + (wan_client_len * cnt);
		return (ipa_wan_client *)ret;
	}

	inline int get_wan_client_index(uint8_t *mac_addr)
	{
		int cnt;
		int num_wan_client_tmp = num_wan_client;

		IPACMDBG_H("Passed MAC %02x:%02x:%02x:%02x:%02x:%02x, left client: %d\n",
						 mac_addr[0], mac_addr[1], mac_addr[2],
						 mac_addr[3], mac_addr[4], mac_addr[5],
						 num_wan_client);

		for(cnt = 0; cnt < num_wan_client_tmp; cnt++)
		{
			IPACMDBG_H("stored MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
							 get_client_memptr(wan_client, cnt)->mac[0],
							 get_client_memptr(wan_client, cnt)->mac[1],
							 get_client_memptr(wan_client, cnt)->mac[2],
							 get_client_memptr(wan_client, cnt)->mac[3],
							 get_client_memptr(wan_client, cnt)->mac[4],
							 get_client_memptr(wan_client, cnt)->mac[5]);

			if(memcmp(get_client_memptr(wan_client, cnt)->mac,
								mac_addr,
								sizeof(get_client_memptr(wan_client, cnt)->mac)) == 0)
			{
				IPACMDBG_H("Matched client index: %d\n", cnt);
				return cnt;
			}
		}

		return IPACM_INVALID_INDEX;
	}

	inline int get_wan_client_index_ipv4(uint32_t ipv4_addr)
	{
		int cnt;
		int num_wan_client_tmp = num_wan_client;

		IPACMDBG_H("Passed IPv4 %x\n", ipv4_addr);

		for(cnt = 0; cnt < num_wan_client_tmp; cnt++)
		{
			if (get_client_memptr(wan_client, cnt)->ipv4_set)
			{
				IPACMDBG_H("stored IPv4 %x\n", get_client_memptr(wan_client, cnt)->v4_addr);

				if(ipv4_addr == get_client_memptr(wan_client, cnt)->v4_addr)
				{
					IPACMDBG_H("Matched client index: %d\n", cnt);
					IPACMDBG_H("The MAC is %02x:%02x:%02x:%02x:%02x:%02x\n",
							get_client_memptr(wan_client, cnt)->mac[0],
							get_client_memptr(wan_client, cnt)->mac[1],
							get_client_memptr(wan_client, cnt)->mac[2],
							get_client_memptr(wan_client, cnt)->mac[3],
							get_client_memptr(wan_client, cnt)->mac[4],
							get_client_memptr(wan_client, cnt)->mac[5]);
					IPACMDBG_H("header set ipv4(%d) ipv6(%d)\n",
							get_client_memptr(wan_client, cnt)->ipv4_header_set,
							get_client_memptr(wan_client, cnt)->ipv6_header_set);
					return cnt;
				}
			}
		}
		return IPACM_INVALID_INDEX;
	}

	inline int get_wan_client_index_ipv6(uint32_t* ipv6_addr)
	{
		int cnt, v6_num;
		int num_wan_client_tmp = num_wan_client;

		IPACMDBG_H("Get ipv6 address 0x%08x.0x%08x.0x%08x.0x%08x\n", ipv6_addr[0], ipv6_addr[1], ipv6_addr[2], ipv6_addr[3]);

		for(cnt = 0; cnt < num_wan_client_tmp; cnt++)
		{
			if (get_client_memptr(wan_client, cnt)->ipv6_set)
			{
				for (auto it = rt_hdl_v6_list[cnt].begin(); it != rt_hdl_v6_list[cnt].end(); ++it)
	            {
					IPACMDBG_H("stored IPv6 0x%08x.0x%08x.0x%08x.0x%08x\n", it->first[0],
						it->first[1],
						it->first[2],
						it->first[3]);

					if(ipv6_addr[0] == it->first[0] &&
					   ipv6_addr[1] == it->first[1] &&
					   ipv6_addr[2]== it->first[2] &&
					   ipv6_addr[3] == it->first[3])
					{
						IPACMDBG_H("Matched client index: %d\n", cnt);
						IPACMDBG_H("The MAC is %02x:%02x:%02x:%02x:%02x:%02x\n",
								get_client_memptr(wan_client, cnt)->mac[0],
								get_client_memptr(wan_client, cnt)->mac[1],
								get_client_memptr(wan_client, cnt)->mac[2],
								get_client_memptr(wan_client, cnt)->mac[3],
								get_client_memptr(wan_client, cnt)->mac[4],
								get_client_memptr(wan_client, cnt)->mac[5]);
						IPACMDBG_H("header set ipv4(%d) ipv6(%d)\n",
								get_client_memptr(wan_client, cnt)->ipv4_header_set,
								get_client_memptr(wan_client, cnt)->ipv6_header_set);
						return cnt;
					}
				}
			}
		}
		return IPACM_INVALID_INDEX;
	}

	inline int delete_wan_rtrules(int clt_indx, ipa_ip_type iptype)
	{
		uint32_t tx_index;
		uint32_t rt_hdl;
		int num_v6 = 0;

		if(iptype == IPA_IP_v4)
		{
		     for(tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		     {
		        if((tx_prop->tx[tx_index].ip == IPA_IP_v4) && (get_client_memptr(wan_client, clt_indx)->route_rule_set_v4==true)) /* for ipv4 */
			{
				IPACMDBG_H("Delete client index %d ipv4 Qos rules for tx:%d \n",clt_indx,tx_index);
				rt_hdl = get_client_memptr(wan_client, clt_indx)->wan_rt_hdl[tx_index].wan_rt_rule_hdl_v4;

				if(m_routing.DeleteRoutingHdl(rt_hdl, IPA_IP_v4) == false)
				{
					return IPACM_FAILURE;
				}
			}
		     } /* end of for loop */

		     /* clean the 4 Qos ipv4 RT rules for client:clt_indx */
		     if(get_client_memptr(wan_client, clt_indx)->route_rule_set_v4==true) /* for ipv4 */
		     {
				get_client_memptr(wan_client, clt_indx)->route_rule_set_v4 = false;
		     }
		}

		if(iptype == IPA_IP_v6)
		{
			IPACMDBG_H("Current %d client has %d ipv6 route_set %d,ipa_num_clients_ipv6:%d\n",
				clt_indx, get_client_memptr(wan_client, clt_indx)->ipv6_set,
				get_client_memptr(wan_client, clt_indx)->route_rule_set_v6,
					IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
			if (get_client_memptr(wan_client, clt_indx)->route_rule_set_v6 != 0)
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
						get_client_memptr(wan_client, clt_indx)->route_rule_set_v6 = 0;
					} /* end of for loop */
				} /* end of for loop */
			}
			IPACMDBG_H("Current clnt-index:%d ipv6_set= %d, route_rule_set_v6= %d, update ipa_num_clients_ipv6:%d\n",
				clt_indx, get_client_memptr(wan_client, clt_indx)->ipv6_set,
				get_client_memptr(wan_client, clt_indx)->route_rule_set_v6,
				IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
		}
		return IPACM_SUCCESS;
	}

	int handle_wan_hdr_init(uint8_t *mac_addr, bool gw_addr);
	int handle_mape_wan_fmr_hdr_init(uint8_t *mac_addr, MapeFMR* fmr_rule);
	int handle_wan_client_ipaddr(ipacm_event_data_all *data);
	int handle_wan_client_route_rule(uint8_t *mac_addr, ipa_ip_type iptype);
#ifdef FEATURE_DUAL_BACKHAUL
	int handle_dual_backhaul_enable(ipacm_event_data_all *data, bool evt);
	int handle_dual_backhaul_disable();
#endif

	int install_ul_qos_route_rules(ipa_ip_type iptype);
	int handle_ul_qos_route_rule(ipa_ip_type iptype, list<qos_param_info>::iterator qos_param);
	int delete_all_UL_info_from_qos(list<qos_param_info>::iterator qos_param, ipa_ip_type iptype);
	int delete_all_UL_qos_rules(ipa_ip_type iptype);
	uint32_t get_u8_bitmap_from_tc(uint8_t traffic_class);

	/* handle new_address event */
	int handle_addr_evt(ipacm_event_data_addr *data);

	/* handle del_address event */
	int handle_addr_del_evt(ipacm_event_data_addr *data);

	/* wan default route/filter rule configuration */
	int handle_route_add_evt(ipa_ip_type iptype);

#ifdef FEATURE_VLAN_MPDN
	void get_vlan_association_info(ipacm_vlan_association_info* vlan_info);
	void get_vlan_pdn_associated_info(ipacm_vlan_association_info* vlan_info, ipacm_wan_iface_type sta_mode,
		int ip_type, bool* v4_found, bool* v6_found);
	void post_wan_vlan_pdn_event(ipa_ip_type iptype, int pdn_idx, int vlan_idx, uint16_t vlan_id, bool vlan_up);
	int handle_vlan_backhaul_switch_v4(ipacm_event_route_vlan *data);
	int handle_vlan_backhaul_switch_v6(ipacm_event_route_vlan *data, bool xlat_cfg = false);
	int check_vlan_pdn(ipa_ip_type iptype, ipacm_event_route_vlan *data, bool xlat_cfg = false, bool del_vlan_route = false);
	int handle_route_add_vlan_pdn_evt(ipa_ip_type iptype, uint16_t vlan_id);
#endif

	/* construct complete STA ethernet header */
	int handle_sta_header_add_evt();

	bool check_dft_firewall_rules_attr_mask(IPACM_firewall_conf_t *firewall_config);

#ifdef FEATURE_IPA_ANDROID
	/* wan posting supported tether_iface */
	int post_wan_up_tether_evt(ipa_ip_type iptype, int ipa_if_num_tether);

	int post_wan_down_tether_evt(ipa_ip_type iptype, int ipa_if_num_tether);
#endif
	int config_dft_firewall_rules(ipa_ip_type iptype);

	/* configure the initial firewall filter rules */
	int config_dft_embms_rules(ipa_ioc_add_flt_rule *pFilteringTable_v4, ipa_ioc_add_flt_rule *pFilteringTable_v6);

#ifdef FEATURE_SOCKSv5
	/* configure the socksv5 dl rules */
	int config_socksv5_rules(ipa_ioc_add_flt_rule *pFilteringTable_v6);
#endif
	int handle_route_del_evt(ipa_ip_type iptype, bool wan_up_vlan = false);

	int del_dft_firewall_rules(ipa_ip_type iptype, bool wan_up_vlan = false);

	int handle_down_evt();

	/*handle wan-iface down event */
	int handle_down_evt_ex();

	/* wan default route/filter rule delete */
	int handle_route_del_evt_ex(ipa_ip_type iptype);

	/* configure the initial firewall filter rules */
#ifdef FEATURE_VLAN_MPDN
	int config_dft_firewall_rules_ex(struct ipacm_pdn_flt_rule* rules, int rule_offset,
		ipa_ip_type iptype, bool isPmipv6=false);
#else
	int config_dft_firewall_rules_ex(struct ipa_flt_rule_add* rules, int rule_offset,
		ipa_ip_type iptype, bool isPmipv6=false);
#endif
	/* init filtering rule in wan dl filtering table */
	int init_fl_rule_ex(ipa_ip_type iptype);

	/* add ICMP and ALG rules in wan dl filtering table */
#ifdef FEATURE_VLAN_MPDN
	int add_icmp_alg_rules(struct ipacm_pdn_flt_rule *rules, int rule_offset, ipa_ip_type iptype);
#else
	int add_icmp_alg_rules(struct ipa_flt_rule_add* rules, int rule_offset, ipa_ip_type iptype);
#endif

	/* query extended property */
	int query_ext_prop();

	ipa_ioc_query_intf_ext_props *ext_prop;

	int config_wan_firewall_rule(ipa_ip_type iptype,bool isPmipv6=false);

	int del_wan_firewall_rule(ipa_ip_type iptype);

#ifdef FEATURE_VLAN_MPDN
	int add_dft_filtering_rule(struct ipacm_pdn_flt_rule *rules, int rule_offset, ipa_ip_type iptype);
#else
	int add_dft_filtering_rule(struct ipa_flt_rule_add* rules, int rule_offset, ipa_ip_type iptype);
#endif

	int install_wan_filtering_rule(bool is_sw_routing, bool is_socksv5_en = false);

	void handle_wlan_SCC_MCC_switch(bool, ipa_ip_type);

	void handle_wan_client_SCC_MCC_switch(bool, ipa_ip_type);
#ifdef FEATURE_L2TP
	void handle_l2tp_client_add(char *iface_name);

	void handle_l2tp_client_del(char *iface_name);
#ifdef FEATURE_VLAN_MPDN
	void install_l2tp_flt_rule(ipacm_pdn_flt_rule* rules, int rule_offset, char *iface_name);
#else
	void install_l2tp_flt_rule(ipa_flt_rule_add* rules, int rule_offset, char *iface_name);
#endif

#endif
	int handle_network_stats_evt();

	int m_fd_ipa;

	int handle_network_stats_update(ipa_get_apn_data_stats_resp_msg_v01 *data);

	/* construct dummy ethernet header */
	int add_dummy_rx_hdr();

	void HandleSTAClientDelEvt(const ipa_wan_client* client, int index);

	int add_catchup_all_filtering_rule_each_pdn(ipa_ip_type iptype,
		const struct ipa_rule_attrib& rx_prop_attrib, struct ipa_flt_rule_add& flt_rule_add, int fltr_rule_number, bool isPmipv6 = false);

#ifdef FEATURE_IPV6_NAT
#ifdef FEATURE_VLAN_MPDN
	int add_ipv6_nat_ula_prefix_flt_rule_ex(const struct ipa_rule_attrib& rx_prop_attrib,
		ipacm_pdn_flt_rule* rules, int fltr_rule_number);
#else
	int add_ipv6_nat_ula_prefix_flt_rule_ex(const struct ipa_rule_attrib& rx_prop_attrib,
	struct ipa_flt_rule_add *rules, int fltr_rule_number);
#endif

	int add_ipv6_nat_ula_prefix_flt_rule(ipa_ioc_add_flt_rule *m_pFilteringTable);
#endif // FEATURE_IPV6_NAT
	int add_ipv6_frag_filtering_rule_ex(const struct ipa_rule_attrib& rx_prop_attrib,
		struct ipa_flt_rule_add& flt_rule_add, int fltr_rule_number);

	int add_ipogre_frag_flt_rule_ex(const struct ipa_rule_attrib& rx_prop_attrib,
		struct ipa_flt_rule_add& flt_rule_add, int fltr_rule_number,
		ipa_ip_type iptype, bool outer, bool last_frag = false);
#ifndef FEATURE_VLAN_MPDN
	int add_firewall_rules_ex(const IPACM_firewall_conf_t& firewall_config, ipa_ip_type iptype,
		const struct ipa_rule_attrib& rx_prop_attrib, struct ipa_flt_rule_add *rules, int rules_size, int& pos);
#else
	int add_firewall_rules_ex(const IPACM_firewall_conf_t& firewall_config, ipa_ip_type iptype, uint8_t curr_mux_id,
		const struct ipa_rule_attrib& rx_prop_attrib, ipacm_pdn_flt_rule* rules, int rules_size, int& pos);
#endif

	/* MTU helper functions */
	int query_mtu_size();

#ifdef FEATURE_IPA_IPSEC
	int del_ipsec_wan_dl_rt_rules(enum ipa_ip_type iptype);

	int add_ipsec_wan_dl_rt_rules(ipacm_event_data_addr *data,
	uint32_t tx_prop_hdr_hdl);
#endif
};

#endif /* IPACM_WAN_H */
