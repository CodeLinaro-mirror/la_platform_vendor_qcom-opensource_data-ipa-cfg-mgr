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
 * Changes from Qualcomm Technologies, Inc. are provided under the following license:
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 */
/*!
	@file
	IPACM_Config.h

	@brief
	This file implements the IPACM Configuration from XML file

	@Author
	Skylar Chang

*/
#ifndef IPACM_CONFIG_H
#define IPACM_CONFIG_H

#include "IPACM_Defs.h"
#include "IPACM_Xml.h"
#include "IPACM_EvtDispatcher.h"
#include <linux/rmnet_ipa_fd_ioctl.h>
#ifdef FEATURE_IPA_ANDROID
#include <libxml/list.h>
#else
#include <list>
#endif
#include <map>
#include <set>
#include <unordered_set>
#include <algorithm>
#include <string>


using std::string;


typedef struct
{
  char iface_name[IPA_IFACE_NAME_LEN];
}NatIfaces;

/* for IPACM rm dependency use*/
typedef struct _ipa_rm_client
{
    ipa_rm_resource_name producer_rm1;
    ipa_rm_resource_name consumer_rm1;
    ipa_rm_resource_name producer_rm2;
    ipa_rm_resource_name consumer_rm2;
    bool producer1_up;            /* only monitor producer_rm1, not monitor producer_rm2 */
    bool consumer1_up;            /* only monitor consumer_rm1, not monitor consumer_rm2 */
    bool rm_set;                  /* once producer1_up and consumer1_up, will add bi-directional dependency */
    bool rx_bypass_ipa;          /* support WLAN may not register RX-property, should not add dependency */
}ipa_rm_client;

#define MAX_NUM_EXT_PROPS 25
#define MAX_NUM_IP_PASS_MPDN 15
#define MAX_NUM_PPPOE_MPDN 9      /* 8 pppoe pdn over vlan + 1 dhcp pdn over vlan */
#define EOGRE_PROTOCOL_TYPE 0x6558
#define IPA_TMP_DIR "/tmp/data_ipa"

#ifdef FEATURE_PPPOE
#define IPA_PPPOE_TABLE IPA_TMP_DIR"/ipa_pppoe_table.txt"
#define MAX_PPPOE_ROW_LEN 200
#define MAX_PPPOE_PARAM_CNT 3
#define MAX_PPPOE_PARAM_LEN 50
#define IPA_SYS_CMD_LEN 200
#endif

#define IPA_QoS_DL_RULE 0
#define IPA_QoS_UL_RULE 1

/* used to hold extended properties */
typedef struct
{
	uint8_t num_ext_props;
	uint8_t num_v4_xlat_props;
	ipa_ioc_ext_intf_prop prop[MAX_NUM_EXT_PROPS];
} ipacm_ext_prop;

/* used to store the PDN info for IP passthrough */
typedef struct
{
	bool valid_entry;

	/* Store interface name */
	char dev_name[IPA_RESOURCE_NAME_MAX];

	/* Flag indicating default pdn. */
	uint8_t is_default_pdn;

	/* Store ip_passthrough mac */
	uint8_t ip_pass_mac[IPA_MAC_ADDR_SIZE];

	/* Store ip_passthrough device type. */
	ipacm_per_client_device_type ip_pass_dev_type;

	/* PDN IP Address assigned in IP Passthrough mode. */
	uint32_t ip_pass_pdn_ip_addr;

	/* Skip NAT configuration. */
	uint8_t ip_pass_skip_nat;

	/* Store vlan ID */
	uint16_t vlan_id;
} ipacm_ip_pass_mpdn_info;

/* used to store the PDN info for IP collision */
typedef struct
{
	bool valid_entry;

	/* Store interface name */
	char dev_name[IPA_RESOURCE_NAME_MAX];

	/* Flag indicating default pdn. */
	uint8_t is_default_pdn;

	/* PDN IP Address assigned in IP Collision mode. */
	uint32_t ip_collision_pdn_ip_addr;

	/* Store vlan ID */
	uint16_t vlan_id;
} ipacm_ip_collision_mpdn_info;

#ifdef FEATURE_STATIC_POLICY
typedef struct
{
	/* Store the status of the entry
         * status = 1 when pdn name and dscp value is stored.
         * status = 2 when mux id is updated and entry is valid now.*/
	int status;
	/* Store interface name */
	char pdn_name[IPA_RESOURCE_NAME_MAX];
	/* Store mux id */
	uint8_t mux_id;
	/* Store dscp_value */
	uint8_t dscp_val;
}ipacm_pdn_dscp_info;
#endif

#ifdef FEATURE_PPPOE
/* used to store the PPPoE PDN info */
typedef struct
{
	/* Store the status of the entry
         * status = 1 when PPPoE pdn name, eth phy name and vlan id are stored.
         * status = 2 when session id is updated and entry is valid now.*/
	uint8_t status;

	/* Store PPPoE interface name */
	char pppoe_dev_name[IPA_RESOURCE_NAME_MAX];

	/* Store eth physical interface name */
	char phy_dev_name[IPA_RESOURCE_NAME_MAX];

	/* Store vlan ID */
	uint16_t vlan_id;

	/* Store PPPoE session ID */
	uint16_t session_id;

	/* Store mac address of the gateway STA WAN client */
	uint8_t mac_addr[IPA_MAC_ADDR_SIZE];

	/* storing iface_index for iface table */
	uint32_t iface_index;
} ipacm_pppoe_mpdn_info;
#endif

#if defined(FEATURE_IPACM_PER_CLIENT_STATS) && defined(IPA_HW_FNR_STATS)
/* Used to keep track of free and used
 * h/w counter indices
 * @in_use : set to "true" in case an index is being used
 * @counter_index : index value, range 1-120
 * */
struct cnt_idx {
	bool in_use;
	uint8_t counter_index;
};
#endif //IPA_HW_FNR_STATS

/*use to keep track of blacklisted mac addrs
 * @is_blacklist : true to blacklist , false to whitelist
 * @mac_v4_rt_del_flt_set : true to represent v4 UL rule added rt/NAT rule deleted
 * @mac_v6_rt_del_flt_set : true to represnet v6 UL rule added & rt deleted
*/
typedef struct {
	bool is_blacklist;
	bool mac_v4_rt_del_flt_set;
	bool mac_v6_rt_del_flt_set;
	uint32_t mac_v4_flt_rule_hdl;
	uint32_t mac_v6_flt_rule_hdl;
	bool mac_sw_enabled;
	bool current_blocked;
} mac_flt_type;

typedef struct {
	char iface[IPA_IFACE_NAME_LEN];
	uint32_t v4_addr;
	bool is_vlan;
} tether_client_info;

/* struct to keep prefix info
 */
struct ipa_prefix_info {
	uint32_t addr[2];
	uint16_t vlan_id;
	bool     is_bridge;
};

#ifdef FEATURE_IPA_IPSEC
struct IpsecUlFltHash {
public:
	size_t operator()(const ipa_ioc_ipsec_ul_flt_attr uf) const
	{
		switch (uf.ip) {
		case IPA_IP_v4:
			return 	std::hash<uint32_t>()(uf.ip) ^
				std::hash<uint32_t>()((uint32_t)uf.attr.src_port |
						      ((uint32_t)uf.attr.dst_port << 16)) ^
				std::hash<uint32_t>()((uint32_t)uf.attr.src_port_lo |
						      ((uint32_t)uf.attr.src_port_hi << 16)) ^
				std::hash<uint32_t>()((uint32_t)uf.attr.dst_port_lo |
						      ((uint32_t)uf.attr.dst_port_hi << 16)) ^
				std::hash<uint32_t>()((uint32_t)uf.attr.u.v4.protocol) ^
				std::hash<uint32_t>()(uf.attr.u.v4.src_addr) ^
				std::hash<uint32_t>()(uf.attr.u.v4.dst_addr);
		case IPA_IP_v6:
			return 	std::hash<uint32_t>()(uf.ip) ^
				std::hash<uint32_t>()((uint32_t)uf.attr.src_port |
						      ((uint32_t)uf.attr.dst_port << 16)) ^
				std::hash<uint32_t>()((uint32_t)uf.attr.src_port_lo |
						      ((uint32_t)uf.attr.src_port_hi << 16)) ^
				std::hash<uint32_t>()((uint32_t)uf.attr.dst_port_lo |
						      ((uint32_t)uf.attr.dst_port_hi << 16)) ^
				std::hash<uint32_t>()(((uint32_t)uf.attr.u.v6.next_hdr)) ^
				std::hash<uint32_t>()(uf.attr.u.v6.src_addr[0]) ^
				std::hash<uint32_t>()(uf.attr.u.v6.src_addr[1]) ^
				std::hash<uint32_t>()(uf.attr.u.v6.src_addr[2]) ^
				std::hash<uint32_t>()(uf.attr.u.v6.src_addr[3]) ^
				std::hash<uint32_t>()(uf.attr.u.v6.dst_addr[0]) ^
				std::hash<uint32_t>()(uf.attr.u.v6.dst_addr[1]) ^
				std::hash<uint32_t>()(uf.attr.u.v6.dst_addr[2]) ^
				std::hash<uint32_t>()(uf.attr.u.v6.dst_addr[3]);
		default:
			IPACMERR("Got illegal uf.ip = %d\n", uf.ip);
			return 0;
		}
	}
};

struct IpsecUlFltKeyEquals {
public:
	bool operator()( const ipa_ioc_ipsec_ul_flt_attr& lhs, const ipa_ioc_ipsec_ul_flt_attr& rhs ) const {
		switch (lhs.ip) {
		case IPA_IP_v4:
			return 	(lhs.ip == rhs.ip) &&
				(lhs.attr.src_port == rhs.attr.src_port) &&
				(lhs.attr.dst_port == rhs.attr.dst_port) &&
				(lhs.attr.src_port_lo == rhs.attr.src_port_lo) &&
				(lhs.attr.src_port_hi == rhs.attr.src_port_hi) &&
				(lhs.attr.dst_port_lo == rhs.attr.dst_port_lo) &&
				(lhs.attr.dst_port_hi == rhs.attr.dst_port_hi) &&
				(lhs.attr.u.v4.protocol == rhs.attr.u.v4.protocol) &&
				(lhs.attr.u.v4.src_addr == rhs.attr.u.v4.src_addr) &&
				(lhs.attr.u.v4.dst_addr == rhs.attr.u.v4.dst_addr);
		case IPA_IP_v6:
			return 	(lhs.ip == rhs.ip) &&
				(lhs.attr.src_port == rhs.attr.src_port) &&
				(lhs.attr.dst_port == rhs.attr.dst_port) &&
				(lhs.attr.src_port_lo == rhs.attr.src_port_lo) &&
				(lhs.attr.src_port_hi == rhs.attr.src_port_hi) &&
				(lhs.attr.dst_port_lo == rhs.attr.dst_port_lo) &&
				(lhs.attr.dst_port_hi == rhs.attr.dst_port_hi) &&
				(lhs.attr.u.v6.next_hdr == rhs.attr.u.v6.next_hdr) &&
				(lhs.attr.u.v6.src_addr[0] == rhs.attr.u.v6.src_addr[0]) &&
				(lhs.attr.u.v6.src_addr[1] == rhs.attr.u.v6.src_addr[1]) &&
				(lhs.attr.u.v6.src_addr[2] == rhs.attr.u.v6.src_addr[2]) &&
				(lhs.attr.u.v6.src_addr[3] == rhs.attr.u.v6.src_addr[3]) &&
				(lhs.attr.u.v6.dst_addr[0] == rhs.attr.u.v6.dst_addr[0]) &&
				(lhs.attr.u.v6.dst_addr[1] == rhs.attr.u.v6.dst_addr[1]) &&
				(lhs.attr.u.v6.dst_addr[2] == rhs.attr.u.v6.dst_addr[2]) &&
				(lhs.attr.u.v6.dst_addr[3] == rhs.attr.u.v6.dst_addr[3]);
		default:
			IPACMERR("Got illegal lhs.ip = %d\n", lhs.ip);
			return false;
		}
	}
};
#endif

#ifdef FEATURE_DUAL_BACKHAUL
/* Struct used to store 2nd backhaul details for dual backhaul
*/
typedef struct {
	bool enable;
	uint32_t gateway_ipv4;
	char net_dev[IPA_IFACE_NAME_LEN];
	uint8_t src_mac[6];
	uint8_t dst_mac[6];
}ipa_dual_backhaul_info;
#endif

struct qos_client_info
{
	uint8_t mac[IPA_MAC_ADDR_SIZE];
	uint32_t qos_rt_rule_hdl_v4;
	uint32_t qos_rt_rule_hdl_v6;
	int client_iface;

	uint32_t dscp_hpc_hdl_v4;
	uint32_t dscp_hpc_hdl_v6;

	bool route_rule_set_v4;
	bool route_rule_set_v6;

	uint32_t v4_ip_addr;
	uint32_t v6_ip_addr[4];
};

struct qos_param_info {
	char iface_name[IPA_RESOURCE_NAME_MAX];
	enum ipa_qos_iface_category cat;
	uint8_t dir;
	uint8_t ip_type;
	uint8_t traffic_class;

	struct ip_tuple ip_tup;
	uint8_t src_mac_addr[IPA_MAC_ADDR_SIZE];
	uint8_t dst_mac_addr[IPA_MAC_ADDR_SIZE];
	uint16_t vlan_id;
	uint8_t dscp;
	uint8_t pcp;
	uint8_t dscp_mark_val;

	uint32_t qos_rt_rule_hdl_v4;
	uint32_t qos_rt_rule_hdl_v6;

	bool route_rule_set_v4;
	bool route_rule_set_v6;

	std::list<qos_client_info> qos_client_list;
	uint32_t client_cnt;

	/* clear the qos client list if the qos_param_info is erased */
	~qos_param_info() {
		qos_client_list.clear();
	}
};

struct qos_delete_param_info {
	uint8_t dir;
	uint32_t client_cnt;
	qos_client_info qos_client_list[];
};

/* iface */
class IPACM_Config
{
public:

	int max_file_size;

	/* IPACM ipa_client map to rm_resource*/
	ipa_rm_resource_name ipa_client_rm_map_tbl[IPA_CLIENT_MAX];

	/* IPACM monitored rm_depency table */
	ipa_rm_client ipa_rm_tbl[IPA_MAX_RM_ENTRY];

	/* IPACM rm_depency a2 endpoint check*/
	int ipa_rm_a2_check;

	/* Store interested interface and their configuration from XML file */
	ipa_ifi_dev_name_t *iface_table;

	/* Store interested ALG port from XML file */
	ipacm_alg *alg_table;

	/* Store private subnet configuration from XML file */
	ipa_private_subnet private_subnet_table[IPA_MAX_PRIVATE_SUBNET_ENTRIES + IPA_MAX_MTU_ENTRIES];

#ifdef FEATURE_DUAL_BACKHAUL
	/* Store the second backhaul info. Fetch gateway,enabled, and netdev details from XML file */
	ipa_dual_backhaul_info second_backhaul_info;
#endif

	/* Store Software allow tuple information */
	IPACM_swallow_t *sw_filter_cfg;

#ifdef FEATURE_VLAN_MPDN
	int num_ipv6_prefixes;
	struct ipa_prefix_info ipa_ipv6_prefixes[IPA_MAX_IPV6_PREFIX_FLT_RULE + IPA_MAX_MTU_ENTRIES];
	int num_no_offload_ipv6_prefix;
	uint32_t ipa_no_offload_ipv6_prefixes[IPA_MAX_IPV6_NO_OFFLOAD_PREFIX_FLT_RULE + IPA_MAX_MTU_ENTRIES][2];
#endif

	/* Store DSCP<->PCP mapping configuration. */
	IPACM_dscp_pcp_conf_t dscp_pcp_config;

	/* Store DSCP<->PCP mapping cache configuration. */
	IPACM_dscp_pcp_conf_t dscp_pcp_config_cache;

	char    IPACM_config_ext_file[IPA_MAX_FILE_LEN];

	/* Store the non nat iface names */
	NatIfaces *pNatIfaces;

	/* Store the bridge iface names */
	char ipa_virtual_iface_name[IPA_IFACE_NAME_LEN];

	/* ETH WAN iface indices */
	int eth_wan_iface_table_idx[MAX_NUM_PPPOE_MPDN];

	/*MAPE iface index */
	int mape_wan_iface_table_index;
	bool mape_enable;
	/* MAPE iface name */
	const char* mape_wan_iface_name;

	/* Store the number of interface IPACM read from XML file */
	int ipa_num_ipa_interfaces;

	int ipa_num_private_subnet;

	int ipa_num_alg_ports;

	const char* ipa_nat_memtype;
	int ipa_nat_max_entries;
	int ipa_ipv6ct_max_entries;
	const char* ipa_ct_memtype;

	bool ipacm_odu_router_mode;

	bool ipacm_odu_enable;

	bool ipacm_odu_embms_enable;
	/* Table containing ip_passthrough mpdn info */
	ipacm_ip_pass_mpdn_info ip_pass_mpdn_table[MAX_NUM_IP_PASS_MPDN];
	ipacm_ip_collision_mpdn_info ip_collision_mpdn_table[MAX_NUM_IP_PASS_MPDN];

#ifdef FEATURE_STATIC_POLICY
	ipacm_pdn_dscp_info pdn_dscp_table[IPA_UC_MAX_PDN_DSCP_VAL];
	pthread_mutex_t pdn_dscp_lock;
#endif

#ifdef FEATURE_PPPOE
	ipacm_pppoe_mpdn_info pppoe_mpdn_table[MAX_NUM_PPPOE_MPDN];
	pthread_mutex_t pppoe_map_lock;
#endif

	pthread_mutex_t ip_pass_mpdn_lock;

	/* nat_iface_lock */
	pthread_mutex_t nat_iface_lock;

	/* get_vlan_association_lock */
	pthread_mutex_t get_vlan_association_lock;

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	/* store each lan client index along with MAC. */
	typedef struct ipa_lan_client_idx
	{
		int8_t lan_stats_idx;
		uint8_t mac[IPA_MAC_ADDR_SIZE];
		/* IPACM interface id */
		int ipa_if_num;
	} ipa_lan_client_idx;

	bool ipacm_lan_stats_enable;
	bool ipacm_lan_stats_enable_set;
	bool ipacm_lan2lan_stats_enable;
	bool ipacm_lan2lan_stats_enable_set;
	/* Clients which take HW path/ stats V2. */
	bool lan_stats_inited;
	static ipa_lan_client_idx active_lan_client_index[IPA_MAX_NUM_HW_PATH_CLIENTS_V2];
	/* Clients which take SW path. This will be used as a place holder to move clients back to HW path. */
	static ipa_lan_client_idx inactive_lan_client_index[IPA_MAX_NUM_HW_PATH_CLIENTS_V2];
#ifdef IPA_HW_FNR_STATS
	struct ipa_ioc_flt_rt_counter_alloc fnr_counters;
	/* Setting an index to 1 would mean that it is under use and 0, unused*/
	struct cnt_idx cnt_idx[IPA_MAX_FLT_RT_CLIENTS_V2];
	pthread_mutex_t cnt_idx_lock;
	bool hw_fnr_stats_support;
#endif //IPA_HW_FNR_STATS
#endif
	bool ipacm_msgflt_enable;

	bool ipv6_nat_enable;

	bool ipacm_gre_enable;
	bool ipacm_gre_autolearn;

	uint32_t ipacm_gre_server_ipv4;

	int ipa_nat_iface_entries;

	/* Store the total number of wlan guest ap configured */
	int ipa_num_wlan_guest_ap;

	/* Max valid rm entry */
	int ipa_max_valid_rm_entry;

	/* Store SW-enable or not */
	bool ipa_sw_rt_enable;

	/* Store bridge mode or not */
	bool ipa_bridge_enable;

	/* Store bridge netdev mac */
	uint8_t bridge_mac[IPA_MAC_ADDR_SIZE];

	/* Indicates whether l2tp is enabled or not. */
	int ipacm_l2tp_enable;

	/* Indicates whether mpdn is enabled or not. */
	bool ipacm_mpdn_enable;

	/* Indicates easy mesh enabled state and the mode */
	bool ipacm_emesh_enable;
	uint32_t ipacm_emesh_mode;

	bool ipacm_easy_mesh_traffic_separation_enable;

	/* Indicates whether qos is enabled or not. */
	bool ipacm_qos_enable;

	/* Indicates whether socksv5 is enabled or not. */
	bool ipacm_socksv5_enable;

	/* Indicates whether l2tp is enabled or not. */
	int ipacm_flt_enable;

	/* Indicates whether public ip support is enabled */
	bool is_public_ip_support_enabled;

	/* Indicates whether vlan mpdn for WLAN is enabled */
	bool wlan_vlan_mpdn_enabled;

	/* Indicates whether static policy mode is enabled */
	bool ipacm_static_policy_enable;

#ifdef FEATURE_STATIC_POLICY
	/* Indicates static policy DSCP marking mode
         * Mode 0 - uc uses pdn_dscp_map table
         * Mode 1 - uc uses proc params */
	uint32_t ipacm_static_policy_dscp_mark_mode;
#endif
	uint32_t rgip_ip;
	char rgip_iface_name[IPA_IFACE_NAME_LEN];
	/* Indicates whether PPPOE mode is enabled on WAN interface */
	bool eth_wan_pppoe_enable;
	/* Indicates whether Eth VLAN mode is enabled on WAN interface */
	bool eth_vlan_wan_enable;
	/* Indicates the interface on which Eth VLAN LAN-WAN mode is enabled */
	const char* eth_lan_wan_iface_name;
	/* Indicates whether Multi VLAN to Single Bridge mode is enabled */
	bool multi_vlan_bridge_config_enable;
	/* Indicates whether Inter Bridge lantolan is enabled */
	bool inter_bridge_lantolan_config_enable;
	/* br-wan mode flag */
	bool eth_wan_br_wan_enable;
#ifdef FEATURE_EoGRE
	ipa_ipgre_info eogre_info;
	bool           eogre_enabled;
	char eogre_tunnel_name[IPA_IFACE_NAME_LEN];
	bool v6options_enabled;
#endif
	ipa_ipgre_info ipgre_info;
	typedef struct pmipv6_status
	{
		char tunnel_name[IPA_IFACE_NAME_LEN];
		bool pmipv6_enabled;
		bool pmipv6_up;
		bool pmipv6_tunnel_setup;
		bool pmipv6_gre_event_posted;
		bool pmipv6_up_wan;
	}pmipv6_status;
	pmipv6_status pmip_details;

	bool ipogre_enabled;
	bool eth_pdu_enabled;
	typedef struct ipgre_tunnel_id_info {
		bool ipogre_enabled;
		bool ipogre_up;
		bool ipogre_tunnel_setup;
		bool ipogre_gre_event_posted;
		bool ipogre_up_wan;
	}ipgre_tunnel_id_info;
	ipgre_tunnel_id_info ipogre_details;

#ifdef FEATURE_VLAN_MPDN
	bool vlan_firewall_change_handle;

	ipacm_bridge vlan_bridges[IPA_MAX_NUM_BRIDGES];
	bool vlan_devices[IPA_VLAN_IF_MAX];
#endif
	/* Store the flt rule count for each producer client*/
	int flt_rule_count_v4[IPA_CLIENT_MAX];
	int flt_rule_count_v6[IPA_CLIENT_MAX];

	/* IPACM routing table name for v4/v6 */
	struct ipa_ioc_get_rt_tbl rt_tbl_lan_v4, rt_tbl_wan_v4, rt_tbl_default_v4, rt_tbl_v6, rt_tbl_wan_v6, rt_tbl_lan_v6;
	struct ipa_ioc_get_rt_tbl rt_tbl_wan_dl, rt_tbl_default_v6;
	struct ipa_ioc_get_rt_tbl rt_tbl_odu_v4, rt_tbl_odu_v6;
	struct ipa_ioc_get_rt_tbl rt_tbl_inter_l2l_v4, rt_tbl_inter_l2l_v6;
	bool rt_tbl_inter_l2l_v4_set;
	bool rt_tbl_inter_l2l_v6_set;

	uint32_t ipv6_blackhole_prefix[4];
	uint32_t ipv6_blackhole_len;
	bool blackhole_valid;
	/* Indicates current number of client ipv6 */
	int ipa_num_clients_ipv6;

	bool isMCC_Mode;
	pthread_mutex_t mac_flt_info_lock;

	/* map to store whitelisted and blacklisted unique mac adrrs */
	std::map<std::array<uint8_t, 6>, mac_flt_type *> mac_flt_lists;
#ifdef IPA_IOC_SET_MAC_FLT
	void mac_flt_info(ipa_ioc_mac_client_list_type *mac_flt_data);
#endif
	bool mac_addr_in_blacklist(uint8_t *mac_addr);
	void clear_whitelist_mac_add(uint8_t *mac_addr);

	decltype(mac_flt_lists) getMacFltListsCopySafe() {
		if(pthread_mutex_lock(&mac_flt_info_lock) != 0) {
			IPACMERR("Unable to lock the mutex\n");
			return {};
		}
		decltype(mac_flt_lists) copyMap(mac_flt_lists);
		pthread_mutex_unlock(&mac_flt_info_lock);
		return copyMap;
	}

	void update_mac_flt_lists(uint8_t *mac_addr, mac_flt_type *mac_flt_value);
	/* To return the instance */
	static IPACM_Config* GetInstance();

	/* save client info */
	std::map<std::array<uint8_t, 6>, tether_client_info *> client_lists;
#ifdef IPA_IOC_SET_SW_FLT
	struct ipa_sw_flt_list_type sw_flt_list;
	void sw_flt_info(ipa_sw_flt_list_type *sw_flt);
	void update_client_info(uint8_t *mac_addr, tether_client_info *client_info, bool is_add);
#endif

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	/* list to capture mac addrs of clients for which stats are enabled */
	std::set<std::array<uint8_t, 6>> mac_addrs_stats_cache;
	void stats_client_info(uint8_t *mac_addr, bool is_add);
	bool client_in_stats_cache(uint8_t *mac_addr);
	pthread_mutex_t stats_client_info_lock;
#endif
#if defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
	pthread_mutex_t vlan_l2tp_lock;
	std::list<vlan_iface_info> m_vlan_iface;

	void add_vlan_iface(ipa_vlan_iface_info *data);

	void del_vlan_iface(ipa_vlan_iface_info *data);

	void restore_vlan_nat_ifaces(const char *phys_iface_name);

	void handle_vlan_iface_info(ipacm_event_data_addr *data);

	void handle_vlan_client_info(ipacm_event_data_all *data);

	int find_matching_vlan(uint16_t interface_index, struct vlan_iface_info *vlan_data);

	void update_repeater_iface(char *interface_name);
	pthread_mutex_t qos_param_list_lock;
	std::list<qos_param_info> m_qos_params;
	void add_qos_params_info(ipa_ioc_qos_config *data);
	void delete_qos_params_info(ipa_ioc_qos_config *data);
	void flush_qos_params_info(ipa_ioc_qos_config *data);

#ifdef FEATURE_L2TP
	std::list<l2tp_vlan_mapping_info> m_l2tp_vlan_mapping;
	std::list<l2tp_client_info> l2tp_client;

	void add_l2tp_vlan_mapping(ipa_ioc_l2tp_vlan_mapping_info *data);

	void del_l2tp_vlan_mapping(ipa_ioc_l2tp_vlan_mapping_info *data);

	int get_vlan_l2tp_mapping(char *client_iface, l2tp_vlan_mapping_info& info);
#endif //#ifdef FEATURE_L2TP
#endif //defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)

#ifdef FEATURE_VLAN_MPDN
	std::list<bridge_vlan_mapping_info> m_bridge_vlan_mapping;
	void add_bridge_vlan_mapping(ipa_bridge_vlan_mapping_info *data);
	int get_bridge_vlan_mapping_from_vid(ipacm_bridge *data, uint16_t vlan_id);
	void del_bridge_vlan_mapping(uint16_t *data);
	int get_bridge_vlan_mapping(ipa_bridge_vlan_mapping_info_new *data);
	uint16_t get_bridge_vlan_mapping_from_subnet(uint32_t ipv4_subnet);
	void add_vlan_bridge(ipacm_event_data_all * data_all);
	ipacm_bridge *get_vlan_bridge(char *name);
	ipacm_bridge *get_vlan_bridge_from_vid(uint16_t vlan_id);
	bool is_added_vlan_iface(char *iface_name);
	bool iface_in_vlan_mode(const char * interfaceName);
	bool iface_in_vlan_mode_v2(const char * interfaceName);
	int get_iface_vlan_ids(char *phys_iface_name, uint16_t *Ids);
	int get_vlan_id(char *iface_name, uint16_t *vlan_id);
	void get_vlan_mode_ifaces();
#endif
	int get_master_interface_index(const char *interface_name);
	int get_bridge_info_iface(char * iface, struct ipa_bridge_vlan_mapping_info *data);
	int get_bridge_info_iface_wlan_mld(const char *interface_name ,struct ipa_bridge_vlan_mapping_info *data);
	ipacm_iface_type get_iface_category(const char *dev_name);
	int get_eth_vlan_wan_up(int ipa_if_num);

#ifdef FEATURE_PPPOE
	uint16_t pppoe_get_session_id(const char *pppoe_dev_name);
	void get_pppoe_session_info(const char *pppoe_dev_name, const char *phy_dev_name = NULL, uint16_t vlan_id = 0);
	void update_pppoe_session_info(const char *pppoe_dev_name, char *params[MAX_PPPOE_PARAM_CNT]);
	int get_pppoe_vlan_id(char *pppoe_dev_name, uint16_t *vlan_id);
	int get_pppoe_indx(char *pppoe_dev_name);
	int get_phy_name_from_bridge_iface(const char *p_dev_name, char phy_name[ETH_PHY_IFACE_LEN]);
#endif
	bool is_svap_related(const char *phy_inf);

#if defined(FEATURE_SOCKSv5) && defined(IPA_SOCKV5_EVENT_MAX)
	pthread_mutex_t socksv5_lock;
	std::list<socksv5_conn_info> socksv5_conn;
	std::list<rmnet_mux_id_info> mux_id_mapping;

	void update_socksv5_client_v6_addr(uint32_t* ipv6_addr);
	void add_socksv5_conn(ipa_socksv5_msg *add_socksv5_info);
	void del_socksv5_conn(uint32_t *socksv5_handle);
	int socksv5_v4_pdn;
	int socksv5_v6_pdn;
	uint32_t socksv5_client_v6_addr[4];
	int pdn_ipv4[IPA_MAX_NUM_HW_PDNS];
	uint32_t pdn_ipv6[IPA_MAX_NUM_HW_PDNS][4];
	int pdn_ipv6_in_use[IPA_MAX_NUM_HW_PDNS];
	/* less impact on v6-embedded traffic */
	int total_pdn_ipv6_in_use;
	void add_mux_id_mapping(rmnet_mux_id_info *add_muxd_info);
	void del_mux_id_mapping(rmnet_mux_id_info *del_muxd_info);
	int query_mux_id(rmnet_mux_id_info *muxd_info);
#endif //defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)

#ifdef FEATURE_IPA_IPSEC
	std::unordered_multiset<ipa_ioc_ipsec_ul_flt_attr,IpsecUlFltHash, IpsecUlFltKeyEquals> ipsecUlFlt;
	using ipsecUlFltSetType = decltype(ipsecUlFlt);

	static ipsecUlFltSetType::size_type eraseOne(ipsecUlFltSetType& uSet, const ipsecUlFltSetType::key_type& key){
		auto it = uSet.find(key);
		if (it != uSet.end()) {
			uSet.erase(it);
			return 1;
		}
		return 0;
	}
#endif

#if defined(FEATURE_IPACM_PER_CLIENT_STATS) && defined(IPA_HW_FNR_STATS)
	int ipacm_alloc_fnr_counters(struct ipa_ioc_flt_rt_counter_alloc *fnr_counters);
	int reset_cnt_idx(int index, bool reset_all);
	int get_free_cnt_idx(void);
	int ipacm_reset_hw_fnr_counters(const uint8_t start_id, const uint8_t end_id);
#endif

	inline int get_free_ip_pass_pdn_index(char *dev_name)
	{
		int indx;

		/* Check if the entry already exists for this iface. */
		for (indx=0; indx < MAX_NUM_IP_PASS_MPDN; indx++)
		{
			if (ip_pass_mpdn_table[indx].valid_entry &&
				strncmp(dev_name,
						ip_pass_mpdn_table[indx].dev_name,
						sizeof(ip_pass_mpdn_table[indx].dev_name)) == 0)
			{
				IPACMDBG("Interface (%s) is already present in IP Pass table\n", dev_name);
				return MAX_NUM_IP_PASS_MPDN;
			}
		}

		for (indx=0; indx < MAX_NUM_IP_PASS_MPDN; indx++)
			if (!ip_pass_mpdn_table[indx].valid_entry)
				return indx;

		return indx;
	}

	inline int get_free_ip_collision_pdn_index(char *dev_name)
	{
		int indx;

		/* Check if the entry already exists for this iface. */
		for (indx=0; indx < MAX_NUM_IP_PASS_MPDN; indx++)
		{
			if (ip_collision_mpdn_table[indx].valid_entry &&
				strncmp(dev_name,
						ip_pass_mpdn_table[indx].dev_name,
						sizeof(ip_pass_mpdn_table[indx].dev_name)) == 0)
			{
				IPACMDBG("Interface (%s) is already present in IP Collision table\n", dev_name);
				return MAX_NUM_IP_PASS_MPDN;
			}
		}

		for (indx=0; indx < MAX_NUM_IP_PASS_MPDN; indx++)
			if (!ip_collision_mpdn_table[indx].valid_entry)
				return indx;

		return indx;
	}

#ifdef FEATURE_PPPOE
	inline int get_free_pppoe_pdn_index(char *pppoe_dev_name)
	{
		int indx;

		/* Check if the entry already exists for this iface. */
		for (indx=0; indx < MAX_NUM_PPPOE_MPDN; indx++)
		{
			if ((pppoe_mpdn_table[indx].status == 1 ||
				pppoe_mpdn_table[indx].status == 2) &&
				strncmp(pppoe_dev_name,
						pppoe_mpdn_table[indx].pppoe_dev_name,
						sizeof(pppoe_mpdn_table[indx].pppoe_dev_name)) == 0)
			{
				IPACMDBG("Interface (%s) is already present in PPPoE table at index %d\n", pppoe_dev_name, indx);
				return indx;
			}
		}
		/* Get free index */
		for (indx=0; indx < MAX_NUM_PPPOE_MPDN; indx++)
		{
			if (!pppoe_mpdn_table[indx].status)
			{
				IPACMDBG("Got free index %d for %s \n", indx, pppoe_dev_name);
				return indx;
			}
		}

		IPACMDBG("No free index %d. Reached to MAX\n", indx);
		return MAX_NUM_PPPOE_MPDN;
	}

	inline int get_pppoe_pdn_index(char *pppoe_dev_name)
	{
		int indx;

		for (indx=0; indx < MAX_NUM_PPPOE_MPDN; indx++)
		{
			if ((pppoe_mpdn_table[indx].status == 1 ||
				pppoe_mpdn_table[indx].status == 2))
				{
					if(strncmp(pppoe_dev_name,
						pppoe_mpdn_table[indx].pppoe_dev_name,
						sizeof(pppoe_mpdn_table[indx].pppoe_dev_name)) == 0)
						{
							IPACMDBG("Got pdn %s at index %d \n", pppoe_dev_name, indx);
							return indx;
						}
				}
		}
		IPACMDBG("No pdn %s stored.\n", pppoe_dev_name);
		return MAX_NUM_PPPOE_MPDN;
	}

	inline uint16_t pppoe_get_session_id(char *pppoe_dev_name)
	{
		int indx;
		if(!pppoe_dev_name)
			return 0;
		for(indx=0; indx < MAX_NUM_PPPOE_MPDN; indx++)
		{
			if(strcmp(pppoe_mpdn_table[indx].pppoe_dev_name, pppoe_dev_name) == 0)
			{
				IPACMDBG("PPPoe dev %s session_id found %d\n",
						pppoe_dev_name, pppoe_mpdn_table[indx].session_id);
				return pppoe_mpdn_table[indx].session_id;
			}
		}
		IPACMERR("PPPoe devname %s not found\n", pppoe_dev_name);
		return 0;
	}
#endif

#ifdef FEATURE_STATIC_POLICY
	inline int get_free_pdn_dscp_index(char *pdn_name)
	{
		int indx;

		/* Check if the entry already exists for this iface. */
		for (indx=0; indx < IPA_UC_MAX_PDN_DSCP_VAL; indx++)
		{
			if ((pdn_dscp_table[indx].status == 1 ||
				pdn_dscp_table[indx].status == 2) &&
				strncmp(pdn_name,
						pdn_dscp_table[indx].pdn_name,
						sizeof(pdn_dscp_table[indx].pdn_name)) == 0)
			{
				IPACMDBG("Interface (%s) is already present in PDN DSCP table\n",
					pdn_name);
				return IPA_UC_MAX_PDN_DSCP_VAL;
			}
		}

		for (indx=0; indx < IPA_UC_MAX_PDN_DSCP_VAL; indx++)
			if (!pdn_dscp_table[indx].status)
				return indx;

		return indx;
	}

	inline int get_pdn_dscp_index(char *pdn_name)
	{
		int indx;

		for (indx=0; indx < IPA_UC_MAX_PDN_DSCP_VAL; indx++)
		{
			if ((pdn_dscp_table[indx].status == 1 ||
				pdn_dscp_table[indx].status == 2) &&
				(strncmp(pdn_name, pdn_dscp_table[indx].pdn_name,
					IPA_RESOURCE_NAME_MAX) == 0))
				return indx;
		}
		return indx;
	}
#endif

	inline int get_ip_pass_pdn_index(ipa_ioc_pdn_config *pdn_config)
	{
		int indx;
		uint32_t ip_addr = htonl(pdn_config->u.passthrough_cfg.pdn_ip_addr);

		for (indx=0; indx < MAX_NUM_IP_PASS_MPDN; indx++)
		{
			if (ip_pass_mpdn_table[indx].valid_entry &&
				(ip_pass_mpdn_table[indx].ip_pass_pdn_ip_addr == ip_addr) &&
				(ip_pass_mpdn_table[indx].ip_pass_dev_type ==
					pdn_config->u.passthrough_cfg.device_type) &&
				ip_pass_mpdn_table[indx].vlan_id == pdn_config->u.passthrough_cfg.vlan_id)
				return indx;
		}
		return indx;
	}

	inline int get_ip_collision_pdn_index(ipa_ioc_pdn_config *pdn_config)
	{
		int indx;
		uint32_t ip_addr = htonl(pdn_config->u.collison_cfg.pdn_ip_addr);

		for (indx=0; indx < MAX_NUM_IP_PASS_MPDN; indx++)
		{
			if (ip_collision_mpdn_table[indx].valid_entry &&
				(ip_collision_mpdn_table[indx].ip_collision_pdn_ip_addr == ip_addr) &&
				(ip_collision_mpdn_table[indx].vlan_id == pdn_config->u.collison_cfg.vlan_id))
				return indx;
		}
		return indx;
	}

	inline bool is_ip_pass_enabled(ipacm_per_client_device_type dev_type, uint8_t client_mac[IPA_MAC_ADDR_SIZE], uint16_t vlan_id)
	{
		int indx;
		bool ret = false;
		uint8_t null_mac[IPA_MAC_ADDR_SIZE] = {0};

		if(pthread_mutex_lock(&ip_pass_mpdn_lock) != 0)
		{
			IPACMERR("Unable to lock the mutex\n");
			return ret;
		}

		for (indx = 0; indx < MAX_NUM_IP_PASS_MPDN; indx++)
		{
			if (ip_pass_mpdn_table[indx].valid_entry)
			{
				/* QCMAP will always provide dev_type as "IPACM_CLIENT_DEVICE_TYPE_ETH" for eth1 however
					internally ipacm recognize eth1 as IPACM_CLIENT_DEVICE_TYPE_ETH1 */
				if (((ip_pass_mpdn_table[indx].ip_pass_dev_type == IPACM_CLIENT_DEVICE_TYPE_ETH &&
					dev_type == IPACM_CLIENT_DEVICE_TYPE_ETH1) ||
					(ip_pass_mpdn_table[indx].ip_pass_dev_type == dev_type)) &&
					(memcmp(ip_pass_mpdn_table[indx].ip_pass_mac, client_mac, IPA_MAC_ADDR_SIZE) == 0) &&
					(ip_pass_mpdn_table[indx].vlan_id == vlan_id))
				{
						ret = true;
						break;
				}

	            /* Special case when mac is NULL. Passthrough will be enabled for first client. */
				/* Device type will be specified as MAX to support WLAN/USB/ETH clients and
				 * VLAN id can be 0 in case of WLAN or non VLAN interface. */
				if ((memcmp(ip_pass_mpdn_table[indx].ip_pass_mac, null_mac, IPA_MAC_ADDR_SIZE) == 0) &&
					(ip_pass_mpdn_table[indx].ip_pass_dev_type == IPACM_CLIENT_DEVICE_MAX) &&
					((ip_pass_mpdn_table[indx].vlan_id == vlan_id) ||
					(ip_pass_mpdn_table[indx].is_default_pdn && vlan_id == 0)))
				{
						ret = true;
						break;
				}

				/* Special case for IPACM_CLIENT_DEVICE_TYPE_USB with mac is NULL. */
				if ((ip_pass_mpdn_table[indx].ip_pass_dev_type == dev_type) &&
					(dev_type == IPACM_CLIENT_DEVICE_TYPE_USB) &&
					(memcmp(ip_pass_mpdn_table[indx].ip_pass_mac, null_mac, IPA_MAC_ADDR_SIZE) == 0) &&
					((ip_pass_mpdn_table[indx].vlan_id == vlan_id) ||
					(ip_pass_mpdn_table[indx].is_default_pdn && vlan_id == 0)))
				{
						ret = true;
						break;
				}
			}
		}

		pthread_mutex_unlock(&ip_pass_mpdn_lock);
		return ret;
	}

	inline bool is_ip_collision_enabled(uint32_t ip_addr)
	{
		int indx;
		bool ret = false;
		if(pthread_mutex_lock(&ip_pass_mpdn_lock) != 0)
		{
			IPACMERR("Unable to lock the mutex\n");
			return ret;
		}
		IPACMDBG_H("ip_addr: 0x%x \n", ip_addr);
		for (indx = 0; indx < MAX_NUM_IP_PASS_MPDN; indx++)
		{
			if (ip_collision_mpdn_table[indx].valid_entry)
			{
				if (ip_collision_mpdn_table[indx].ip_collision_pdn_ip_addr == ip_addr)
				{
					ret = true;
					break;
				}
			}
		}

		pthread_mutex_unlock(&ip_pass_mpdn_lock);
		return ret;
	}

	void ip_pass_config_update(ipa_ioc_pdn_config *pdn_config);

	void ip_collision_config_update(ipa_ioc_pdn_config *pdn_config);

#ifdef FEATURE_PPPOE
	void pppoe_config_update(ipa_ioc_pppoe_info *pppoe_config, uint8_t to_add, uint16_t session_id = 0, uint8_t *mac_addr = NULL);
#endif

#ifdef FEATURE_STATIC_POLICY
	void pdn_dscp_config_update(ipa_ioc_pdn_dscp_map_info *pdn_dscp_config);
#endif

	const char* getEventName(ipa_cm_event_id event_id);

	inline void increaseFltRuleCount(int index, ipa_ip_type iptype, int increment)
	{
		if((index >= IPA_CLIENT_MAX) || (index < 0))
		{
			IPACMERR("Index is out of range: %d.\n", index);
			return;
		}
		if(iptype == IPA_IP_v4)
		{
			flt_rule_count_v4[index] += increment;
			IPACMDBG_H("Now num of v4 flt rules on client %d is %d.\n", index, flt_rule_count_v4[index]);
		}
		else
		{
			flt_rule_count_v6[index] += increment;
			IPACMDBG_H("Now num of v6 flt rules on client %d is %d.\n", index, flt_rule_count_v6[index]);
		}
		return;
	}

	inline void decreaseFltRuleCount(int index, ipa_ip_type iptype, int decrement)
	{
		if((index >= IPA_CLIENT_MAX) || (index < 0))
		{
			IPACMERR("Index is out of range: %d.\n", index);
			return;
		}
		if(iptype == IPA_IP_v4)
		{
			flt_rule_count_v4[index] -= decrement;
			IPACMDBG_H("Now num of v4 flt rules on client %d is %d.\n", index, flt_rule_count_v4[index]);
		}
		else
		{
			flt_rule_count_v6[index] -= decrement;
			IPACMDBG_H("Now num of v6 flt rules on client %d is %d.\n", index, flt_rule_count_v6[index]);
		}
		return;
	}

	inline int getFltRuleCount(int index, ipa_ip_type iptype)
	{
		if((index >= IPA_CLIENT_MAX) || (index < 0))
		{
			IPACMERR("Index is out of range: %d.\n", index);
			return -1;
		}
		if(iptype == IPA_IP_v4)
		{
			return flt_rule_count_v4[index];
		}
		else
		{
			return flt_rule_count_v6[index];
		}
	}

	inline int GetAlgPortCnt()
	{
		return ipa_num_alg_ports;
	}

	int GetAlgPorts(int nPorts, ipacm_alg *pAlgPorts);

	inline int GetNatMaxEntries(void)
	{
		return ipa_nat_max_entries;
	}

	inline const char* GetNatMemType(void)
	{
		return ipa_nat_memtype;
	}

	inline const char* GetCTMemType(void)
	{
		return ipa_ct_memtype;
	}

	inline int GetIpv6CTMaxEntries(void)
	{
		return ipa_ipv6ct_max_entries;
	}

	inline bool IsIpv6CTEnabled(void)
	{
		return ipa_ipv6ct_max_entries != 0 && GetIPAVer() >= IPA_HW_v4_0;
	}

	inline int GetNatIfacesCnt()
	{
		int nat_iface_entries;

		if(pthread_mutex_lock(&nat_iface_lock) != 0)
		{
			IPACMERR("Unable to lock the mutex\n");
			return 0;
		}
		nat_iface_entries = ipa_nat_iface_entries;
		pthread_mutex_unlock(&nat_iface_lock);
		return nat_iface_entries;
	}
	int GetNatIfaces(int nPorts, NatIfaces *ifaces);

	/* for IPACM resource manager dependency usage */
	void AddRmDepend(ipa_rm_resource_name rm1, bool rx_bypass_ipa);

	void DelRmDepend(ipa_rm_resource_name rm1);

	int AddNatIfaces(char *dev_name);

	int DelNatIfaces(char *dev_name);

	/* To change the WLAN AP from Non-vlan to vlan and vice-a-versa */
	int SwitchAPVlanMode(char *dev_name, bool vlan_mpdn);

	bool IsWlanIfVlan(const char *dev_name);
	int SetWlanVlanAp(char *event_iface_name);

	/* Special Inteface handles both vlan and non-vlan clients*/
	bool IsSpclIface(const char *dev_name);
	int SetSpclIface(char *event_iface_name);

	inline void SetQmapId(uint8_t id)
	{
		qmap_id = id;
	}

	inline uint8_t GetQmapId()
	{
		return qmap_id;
	}
	int Load_tunnel_xml_details();
	int SetExtProp(ipa_ioc_query_intf_ext_props *prop);

	ipacm_ext_prop* GetExtProp(ipa_ip_type ip_type);

	int DelExtProp(ipa_ip_type ip_type);

	enum ipa_hw_type GetIPAVer(bool get = false);

	bool ttlHwSupport() {
		return GetIPAVer() >= IPA_HW_v6_0;
	}

	int ResetClkVote(void);

	int ReadSwAllow(void);

	int Init(void);

	inline bool isPrivateSubnet(uint32_t ip_addr)
	{
		for(int cnt = 0; cnt < ipa_num_private_subnet; cnt++)
		{
			if(private_subnet_table[cnt].subnet_addr ==
				(private_subnet_table[cnt].subnet_mask & ip_addr))
			{
				return true;
			}
		}

		return false;
	}

	inline ipa_private_subnet *getPrivateSubnet(uint32_t ip_addr)
	{
		for(int cnt = 0; cnt < ipa_num_private_subnet; cnt++)
		{
			if(private_subnet_table[cnt].subnet_addr ==
				(private_subnet_table[cnt].subnet_mask & ip_addr))
			{
				return &private_subnet_table[cnt];
			}
		}

		return NULL;
	}

	inline ipa_private_subnet *getPrivateSubnetByIfIndex(int ipa_if_index)
	{
		for(int cnt = 0; cnt < ipa_num_private_subnet; cnt++)
		{
			if(private_subnet_table[cnt].if_index == ipa_if_index)
			{
				return &private_subnet_table[cnt];
			}
		}

		return NULL;
	}

	inline bool AddPrivateSubnet(uint32_t ip_addr, uint32_t ipv4_addr_mask, int ipa_if_index)
	{
		ipacm_cmd_q_data evt_data;
		ipacm_event_data_fid *data_fid;
		uint32_t subnet_mask = ~0;
		ipacm_bridge *bridge = NULL;
		for(int cnt = 0; cnt < ipa_num_private_subnet; cnt++)
		{
			if(private_subnet_table[cnt].subnet_addr == ip_addr)
			{
				IPACMDBG("Already has private subnet_addr as: 0x%x in entry(%d) \n", ip_addr, cnt);
				return true;
			}
		}

		if(ipa_num_private_subnet < IPA_MAX_PRIVATE_SUBNET_ENTRIES)
		{
			IPACMDBG("Add IPACM private subnet_addr as: 0x%x in entry(%d) \n", ip_addr, ipa_num_private_subnet);
			private_subnet_table[ipa_num_private_subnet].subnet_addr = ip_addr;
			private_subnet_table[ipa_num_private_subnet].subnet_mask = ipv4_addr_mask;
			private_subnet_table[ipa_num_private_subnet].if_index = ipa_if_index;
			ipa_num_private_subnet++;

			/* IPACM private subnet set changes */
			data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
			if(data_fid == NULL)
			{
				IPACMERR("unable to allocate memory for event data_fid\n");
				return IPACM_FAILURE;
			}

			bridge = get_vlan_bridge(ipa_virtual_iface_name);
			if(bridge)
			{
				IPACMERR("IPACM private subnet_addr entry(%d) name:%s\n", ipa_num_private_subnet,
					ipa_virtual_iface_name);
				IPACMDBG("Updated bridge private subnet_addr as: 0x%x \n", ip_addr);
				bridge->bridge_ipv4_addr = ip_addr;
				bridge->bridge_netmask = ipv4_addr_mask;
			}
			else
			{
				IPACMERR("bridge %s not up\n", ipa_virtual_iface_name);
			}

			data_fid->if_index = ipa_if_index; // already ipa index, not fid index
			evt_data.event = IPA_PRIVATE_SUBNET_CHANGE_EVENT;
			evt_data.evt_data = data_fid;

			/* Insert IPA_PRIVATE_SUBNET_CHANGE_EVENT to command queue */
			IPACM_EvtDispatcher::PostEvt(&evt_data);
			return true;
		}
		IPACMERR("IPACM private subnet_addr overflow, total entry(%d)\n", ipa_num_private_subnet);
		return false;
	}

	inline bool DelPrivateSubnet(uint32_t ip_addr, int ipa_if_index)
	{
		ipacm_cmd_q_data evt_data;
		ipacm_event_data_fid *data_fid;
		for(int cnt = 0; cnt < ipa_num_private_subnet; cnt++)
		{
			if(private_subnet_table[cnt].subnet_addr == ip_addr)
			{
				IPACMDBG("Found private subnet_addr as: 0x%x in entry(%d) \n", ip_addr, cnt);
				for(; cnt < ipa_num_private_subnet - 1; cnt++)
				{
					private_subnet_table[cnt].subnet_addr = private_subnet_table[cnt + 1].subnet_addr;
					private_subnet_table[cnt].subnet_mask = private_subnet_table[cnt + 1].subnet_mask;
					private_subnet_table[cnt].if_index = private_subnet_table[cnt + 1].if_index;
				}
				ipa_num_private_subnet = ipa_num_private_subnet - 1;

				/* IPACM private subnet set changes */
				data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
				if(data_fid == NULL)
				{
					IPACMERR("unable to allocate memory for event data_fid\n");
					return IPACM_FAILURE;
				}
				data_fid->if_index = ipa_if_index; // already ipa index, not fid index
				evt_data.event = IPA_PRIVATE_SUBNET_CHANGE_EVENT;
				evt_data.evt_data = data_fid;

				/* Insert IPA_PRIVATE_SUBNET_CHANGE_EVENT to command queue */
				IPACM_EvtDispatcher::PostEvt(&evt_data);
				return true;
			}
		}
		IPACMDBG("can't find private subnet_addr as: 0x%x \n", ip_addr);
		return false;
	}
	inline bool DelPrivateSubnetByIfIndex(int ipa_if_index)
	{
		ipacm_cmd_q_data evt_data;
		ipacm_event_data_fid *data_fid;
		for(int cnt = 0; cnt < ipa_num_private_subnet; cnt++)
		{
			if(private_subnet_table[cnt].if_index == ipa_if_index)
			{
				IPACMDBG("Found private subnet_addr as: 0x%x in entry(%d) \n", private_subnet_table[cnt].subnet_addr, cnt);
				for(; cnt < ipa_num_private_subnet - 1; cnt++)
				{
					private_subnet_table[cnt].subnet_addr = private_subnet_table[cnt + 1].subnet_addr;
					private_subnet_table[cnt].subnet_mask = private_subnet_table[cnt + 1].subnet_mask;
					private_subnet_table[cnt].if_index = private_subnet_table[cnt + 1].if_index;
				}
				ipa_num_private_subnet = ipa_num_private_subnet - 1;

				/* IPACM private subnet set changes */
				data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
				if(data_fid == NULL)
				{
					IPACMERR("unable to allocate memory for event data_fid\n");
					return IPACM_FAILURE;
				}
				data_fid->if_index = ipa_if_index; // already ipa index, not fid index
				evt_data.event = IPA_PRIVATE_SUBNET_CHANGE_EVENT;
				evt_data.evt_data = data_fid;

				/* Insert IPA_PRIVATE_SUBNET_CHANGE_EVENT to command queue */
				IPACM_EvtDispatcher::PostEvt(&evt_data);
				return true;
			}
		}
		IPACMDBG("can't find entry %d \n", ipa_if_index);
		return false;
	}

#ifdef FEATURE_VLAN_MPDN
	inline void SendPrefixChangeEvent(int ipa_if_num)
	{
		ipacm_event_data_fid *data_fid;
		ipacm_cmd_q_data evt_data;
		data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
		if(data_fid == NULL)
		{
			IPACMERR("unable to allocate memory for event data_fid\n");
			return ;
		}
		data_fid->if_index = ipa_if_num;
		evt_data.event = IPA_PREFIX_CHANGE_EVENT;
		evt_data.evt_data = data_fid;
		/* Insert IPA_PREFIX_CHANGE_EVENT to command queue */
		IPACMDBG("posting IPA_PREFIX_CHANGE_EVENT\n");
		IPACM_EvtDispatcher::PostEvt(&evt_data);
	}

	/* do not offload this pdn until we get route add\ new vlan neighbor */
	inline bool add_no_offload_ipv6_prefix(uint32_t *prefix)
	{

		if(prefix == NULL)
		{
			IPACMERR("Null prefix passed\n");
			return false;
		}

		IPACMDBG("prefix 0x[%X][%X] to add in no offload list\n", prefix[0], prefix[1]);

		/* prefix shouldn't be present in offload list - this is a bug */
		for(int i = 0; i < num_ipv6_prefixes; i++)
		{
			if((prefix[0] == ipa_ipv6_prefixes[i].addr[0]) && (prefix[1] == ipa_ipv6_prefixes[i].addr[1]))
			{
				IPACMERR("prefix 0x[%X][%X] already exists in offload list at %d\n", prefix[0], prefix[1],i);
				return false;
			}
		}
		/* Check if no offload prefix already present in no offload list*/
		for(int i = 0; i < num_no_offload_ipv6_prefix; i++)
		{
			if((prefix[0] == ipa_no_offload_ipv6_prefixes[i][0]) && (prefix[1] == ipa_no_offload_ipv6_prefixes[i][1]))
			{
				IPACMERR("prefix 0x[%X][%X] already exists in no offload list at %d\n", prefix[0], prefix[1],i);
				return false;
			}
		}
		/* Add in no offload list */
		if (num_no_offload_ipv6_prefix < IPA_MAX_IPV6_NO_OFFLOAD_PREFIX_FLT_RULE )
		{
			ipa_no_offload_ipv6_prefixes[num_no_offload_ipv6_prefix][0] = prefix[0];
			ipa_no_offload_ipv6_prefixes[num_no_offload_ipv6_prefix][1] = prefix[1];
			num_no_offload_ipv6_prefix++;
		}
		else
		{
			IPACMERR("Reached maximum No offload PDN, unable to add pdn into list:prefix 0x[%X][%X]\n",
				prefix[0], prefix[1]);
			return false;
		}

		IPACMDBG("added no offload v6 prefix 0x[%X][%X], now number of no offload pdn %d\n",
			prefix[0], prefix[1],num_no_offload_ipv6_prefix);

		/* tell all LAN interfaces that we have a change in v6 prefixes */
		SendPrefixChangeEvent(-1);
		return true;
	}

	/* add to prefixes list if needed and notify LAN objects to modify rules*/
	inline bool add_vlan_ipv6_prefix(uint32_t *prefix, int ipa_if_num, uint16_t vlan_id, bool is_bridge = false)
	{
		int i = 0;
		int no_offload_temp = num_no_offload_ipv6_prefix;
		bool updated_reserved_slot = false;

		if(prefix == NULL)
		{
			IPACMERR("Null prefix passed\n");
			return false;
		}

		IPACMDBG("prefix 0x[%X][%X] to add in offload list\n", prefix[0], prefix[1]);

		/* check for duplication */
		for(i = 0; i < num_ipv6_prefixes; i++)
		{
			if((prefix[0] == ipa_ipv6_prefixes[i].addr[0])
				&& (prefix[1] == ipa_ipv6_prefixes[i].addr[1])
				&& (vlan_id == ipa_ipv6_prefixes[i].vlan_id)
			    && (is_bridge == ipa_ipv6_prefixes[i].is_bridge))
			{
				IPACMDBG_H("prefix 0x[%X][%X] already exists vlan_id inp %d saved %d\n is_bridge %d",
					prefix[0], prefix[1], vlan_id, ipa_ipv6_prefixes[i].vlan_id, ipa_ipv6_prefixes[i].is_bridge);
				return false;
			}
		}

		/* remove from no offload list */
		for(i = 0; i < num_no_offload_ipv6_prefix; i++)
		{
			if((prefix[0] == ipa_no_offload_ipv6_prefixes[i][0]) && (prefix[1] == ipa_no_offload_ipv6_prefixes[i][1]))
			{
				for(; i < (num_no_offload_ipv6_prefix - 1); i++)
				{
					ipa_no_offload_ipv6_prefixes[i][0] = ipa_no_offload_ipv6_prefixes[i + 1][0];
					ipa_no_offload_ipv6_prefixes[i][1] = ipa_no_offload_ipv6_prefixes[i + 1][1];
				}
				num_no_offload_ipv6_prefix--;
				IPACMDBG_H("removed prefix 0x[%X][%X] from no offload list\n", prefix[0], prefix[1]);
				break;
			}
		}

		if(no_offload_temp == num_no_offload_ipv6_prefix && prefix[0] != IPA_DUMMY_PREFIX)
		{
			IPACMERR("could not find prefix 0x[%X][%X] in no offload list\n", prefix[0], prefix[1]);
		}
		/* Update v6_prefix/vlan id if slot is reserved*/
		for(i = 0; i < num_ipv6_prefixes; i++)
		{
			if (ipa_ipv6_prefixes[i].addr[0] == IPA_DUMMY_PREFIX && vlan_id == ipa_ipv6_prefixes[i].vlan_id)
			{
				IPACMDBG_H("Updating old prefix 0x[%X][%X] of vlan_id %d\n",
					ipa_ipv6_prefixes[i].addr[0], ipa_ipv6_prefixes[i].addr[1], ipa_ipv6_prefixes[i].vlan_id);
				ipa_ipv6_prefixes[i].addr[0] = prefix[0];
				ipa_ipv6_prefixes[i].addr[1] = prefix[1];
				updated_reserved_slot =true;
				IPACMDBG_H("Updated v6 prefix 0x[%X][%X] for vlan id %d\n", prefix[0], prefix[1], ipa_ipv6_prefixes[i].vlan_id);
			}
			else if ((prefix[0] == ipa_ipv6_prefixes[i].addr[0])
				&& (prefix[1] == ipa_ipv6_prefixes[i].addr[1])
				&& (ipa_ipv6_prefixes[i].vlan_id ==0)
				&& (ipa_ipv6_prefixes[i].is_bridge == is_bridge)) {
				/* Update the vlan id if prefix already saved but vlan id not associated
				 * e.g Wlan for default pdn reserves a slot with vlan id 0, then eth vlan
				 * for default pdn associates with vlan id */
				IPACMDBG_H("Updating vlan id %d for prefix 0x[%X][%X] \n", ipa_ipv6_prefixes[i].vlan_id, ipa_ipv6_prefixes[i].addr[0], ipa_ipv6_prefixes[i].addr[1]);
				ipa_ipv6_prefixes[i].vlan_id = vlan_id;
				updated_reserved_slot =true;
				IPACMDBG_H("Updated vlan id %d v6 prefix 0x[%X][%X] for vlan id %d\n",ipa_ipv6_prefixes[i].vlan_id, prefix[0], prefix[1]);
			}
		}

		if (!updated_reserved_slot) {
			if(num_ipv6_prefixes >= IPA_MAX_IPV6_PREFIX_FLT_RULE)
			{
				IPACMERR("we already reached maximum prefix rules\n");
				return false;
			}
			ipa_ipv6_prefixes[num_ipv6_prefixes].addr[0] = prefix[0];
			ipa_ipv6_prefixes[num_ipv6_prefixes].addr[1] = prefix[1];
			ipa_ipv6_prefixes[num_ipv6_prefixes].vlan_id = vlan_id;
			ipa_ipv6_prefixes[num_ipv6_prefixes].is_bridge = is_bridge;
			num_ipv6_prefixes++;
			IPACMDBG("added v6 prefix 0x[%X][%X] for vlan id %d is_bridge: %d\n", prefix[0], prefix[1], ipa_ipv6_prefixes[i].vlan_id, ipa_ipv6_prefixes[i].is_bridge);
		}

		/* tell other LAN interfaces that we have a change in v6 prefixes */
		SendPrefixChangeEvent(ipa_if_num);
		return true;
	}

	/* remove from prefixes list if needed and notify LAN objects to modify rules*/
	inline int del_vlan_ipv6_prefix(uint32_t* prefix, int ipa_if_num, bool reserve_slot = false, bool is_bridge = false)
	{
		int i = 0;

		if(prefix == NULL)
		{
			IPACMERR("Null prefix passed\n");
			return false;
		}

		IPACMDBG("prefix 0x[%X][%X] to del offload list\n", prefix[0], prefix[1]);

		for(i = 0; i < num_ipv6_prefixes; i++)
		{
			if((prefix[0] == ipa_ipv6_prefixes[i].addr[0]) && (prefix[1] == ipa_ipv6_prefixes[i].addr[1])
				&& is_bridge == ipa_ipv6_prefixes[i].is_bridge)
			{
				if (reserve_slot) {
					IPACMDBG_H("Reserve slot for ipa_if_num %d\n", ipa_if_num);
					ipa_ipv6_prefixes[i].addr[0] = IPA_DUMMY_PREFIX;
					ipa_ipv6_prefixes[i].addr[1] = IPA_DUMMY_PREFIX;
					ipa_ipv6_prefixes[i].is_bridge = is_bridge;
				}
				else {
					IPACMDBG_H("prefix installed by is_bridge %d 0x[%X][%X] will be removed\n", is_bridge, prefix[0], prefix[1]);
					for(; i < (num_ipv6_prefixes - 1); i++)
					{
						ipa_ipv6_prefixes[i].addr[0] = ipa_ipv6_prefixes[i + 1].addr[0];
						ipa_ipv6_prefixes[i].addr[1] = ipa_ipv6_prefixes[i + 1].addr[1];
						ipa_ipv6_prefixes[i].vlan_id = ipa_ipv6_prefixes[i + 1].vlan_id;
						ipa_ipv6_prefixes[i].is_bridge = ipa_ipv6_prefixes[i + 1].is_bridge;
					}
					num_ipv6_prefixes--;
				}

				/* tell other LAN interfaces that we have a change in v6 prefixes */
				SendPrefixChangeEvent(ipa_if_num);
				return IPACM_SUCCESS;
			}
		}
		/* remove from no offload list */
		for(i = 0; i < num_no_offload_ipv6_prefix; i++)
		{
			if((prefix[0] == ipa_no_offload_ipv6_prefixes[i][0]) && (prefix[1] == ipa_no_offload_ipv6_prefixes[i][1]))
			{
				for(; i < (num_no_offload_ipv6_prefix - 1); i++)
				{
					ipa_no_offload_ipv6_prefixes[i][0] = ipa_no_offload_ipv6_prefixes[i + 1][0];
					ipa_no_offload_ipv6_prefixes[i][1] = ipa_no_offload_ipv6_prefixes[i + 1][1];
				}
				num_no_offload_ipv6_prefix--;
				IPACMDBG_H("removed prefix 0x[%X][%X] from no offload list\n", prefix[1], prefix[2]);
				/* tell other LAN interfaces that we have a change in v6 prefixes */
				SendPrefixChangeEvent(ipa_if_num);
				return IPACM_SUCCESS;
			}
		}
		IPACMERR("couldn't find prefix 0x[%X][%X] in either no offload nor offload list\n", prefix[0], prefix[1]);
		return IPACM_FAILURE;
	}

	/* returns true if a VLAN PDN or default PDN should be offloaded */
	inline bool is_offload_ipv6_prefix(uint32_t *prefix)
	{
		IPACMDBG_H("checking prefix 0x[%X][%X]\n", prefix[0], prefix[1]);
		for(int i = 0; i < num_ipv6_prefixes; i++)
		{
			if((prefix[0] == ipa_ipv6_prefixes[i].addr[0]) && (prefix[1] == ipa_ipv6_prefixes[i].addr[1]))
			{
				IPACMDBG_H("prefix 0x[%X][%X] is a known ipv6 prefix for vlan id %d\n",
					prefix[0], prefix[1], ipa_ipv6_prefixes[i].vlan_id);
				return true;
			}
			else
			{
				IPACMDBG("no match with [%X][%X]\n", ipa_ipv6_prefixes[i].addr[0], ipa_ipv6_prefixes[i].addr[1]);
			}
		}
		int len  = ipv6_blackhole_len;
		if(blackhole_valid == true)
		{
			for (int i = 0; i < 4; ++i) {
				/* Note: Assuming incoming prefix =  2001:0db8:85a3:0099:1111:2222:3333:4444
				 * prefix[0] = 0x20010db8
				 * prefix[1] = 0x85a30099
				 * and Blackhole Prefix: 2001:0db8:85a3:0000::/56
				 * example len = 56
				 * If no bits left to check, it's a match
				 * ITERATION 1 (i=0): len is 56. (Skip)
				 * ITERATION 2 (i=1): len is 24. (Skip)
				 * ITERATION 3 (i=2): len is 0. Condition met! Returns true.
				 */
				if (len == 0) {
					return true;
				}

				/* Determine how many bits to check in this specific 32-bit block
				 * ITERATION 1 (i=0): len (56) >= 32, so check_bits = 32
				 * ITERATION 2 (i=1): len (24) < 32, so check_bits = 24
				 */
				int check_bits = (len >= 32) ? 32 : len;

				/* Create mask */
				uint32_t mask;
				if (check_bits == 32) {
					mask = 0xFFFFFFFFU;
				} else {
					/* ITERATION 1 (i=0): We need the full block. 
					 * mask = 0xFFFFFFFF
					 */
					mask = ~(0xFFFFFFFFU >> check_bits);
					/* ITERATION 2 (i=1): check_bits is 24.
					 * 0xFFFFFFFFU >> 24 = 0x000000FF.
					 * Bitwise NOT (~) flips it to 0xFFFFFF00.
					 * mask = 0xFFFFFF00
					 */
				}

				/* Compare the masked values
				 * ITERATION 1 (i=0):
				 * prefix[0] & mask: 0x20010db8 & 0xFFFFFFFF = 0x20010db8
				 * ipv6_blackhole_prefix[0] & mask:     0x20010db8 & 0xFFFFFFFF = 0x20010db8
				 * They match! Continue loop.
				 *
				 * ITERATION 2 (i=1):
				 * prefix[1] & mask: 0x85a30099 & 0xFFFFFF00 = 0x85a30000
				 * ipv6_blackhole_prefix[1] & mask:     0x85a30000 & 0xFFFFFF00 = 0x85a30000
				 * They match! Continue loop.
				 */
				if ((prefix[i] & mask) != (ipv6_blackhole_prefix[i] & mask)) {
					return false;
				}

				/* Decrement length by the bits we just checked (max 32)
				 * ITERATION 1 (i=0): len = 56 - 32 = 24
				 * ITERATION 2 (i=1): len = 24 - 24 = 0
				 */
				len -= check_bits;
			}
			return true;
		}
		return false;
	}

	inline bool get_ipv6_prefix_for_vlan_id(uint8_t vlan_id , uint32_t *prefix)
	{
		IPACMDBG_H("checking for vlan id %d\n", vlan_id);
		/*MVLAN PDN is not supported in easymesh so check for default bridge prefix*/
		if(ipacm_emesh_enable == true && ipacm_emesh_mode >= 2)
			vlan_id = 0;
		for(int i = 0; i < num_ipv6_prefixes; i++)
		{
			if(vlan_id == ipa_ipv6_prefixes[i].vlan_id)
			{
				IPACMDBG_H("prefix 0x[%X][%X] is a known ipv6 prefix for vlan id %d\n",
					ipa_ipv6_prefixes[i].addr[0], ipa_ipv6_prefixes[i].addr[1], ipa_ipv6_prefixes[i].vlan_id);
				prefix[0] = ipa_ipv6_prefixes[i].addr[0];
				prefix[1] = ipa_ipv6_prefixes[i].addr[1];
				return true;
			}
			else
			{
				IPACMDBG("no match with vlan id %d\n", ipa_ipv6_prefixes[i].vlan_id);
			}
		}
		return false;
	}

	inline bool ipv6_prefix_for_vlan_id(uint8_t vlan_id)
	{
		IPACMDBG_H("checking for vlan id %d\n", vlan_id);
		for(int i = 0; i < num_ipv6_prefixes; i++)
		{
			if(vlan_id == ipa_ipv6_prefixes[i].vlan_id)
			{
				IPACMDBG_H("prefix 0x[%X][%X] is a known ipv6 prefix for vlan id %d\n", ipa_ipv6_prefixes[i].addr[0], ipa_ipv6_prefixes[i].addr[1], ipa_ipv6_prefixes[i].vlan_id);
				return true;
			}
			else
			{
				IPACMDBG("no match with vlan id %d\n", ipa_ipv6_prefixes[i].vlan_id);
			}
		}
		return false;
	}
#endif

#if defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
	/* post IPA_UPDATE_SOCKSv5_v6_CONN msg */
	inline int post_socksv5_v6_evt(void)
	{
		/* tell wan we have v6 pdn-update */
		ipacm_cmd_q_data evt_data;

		evt_data.event = IPA_UPDATE_SOCKSv5_v6_CONN;
		evt_data.evt_data = NULL;
		IPACMDBG("posting IPA_UPDATE_SOCKSv5_v6_CONN\n");
		IPACM_EvtDispatcher::PostEvt(&evt_data);
		return IPACM_SUCCESS;
	}

	/* post IPA_ADD_SOCKSv5_CONN msg */
	inline int post_socksv5_evt(ipa_socksv5_msg *socksv5_info, bool is_add)
	{
		/* tell other LAN interfaces that we have a new private subnet */
		ipa_socksv5_msg *data_socksv5;
		ipacm_cmd_q_data evt_data;

		data_socksv5 = (ipa_socksv5_msg *)malloc(sizeof(ipa_socksv5_msg));
		if(data_socksv5 == NULL)
		{
			IPACMERR("unable to allocate memory for event data_socksv5\n");
			return IPACM_FAILURE;
		}
		memcpy(data_socksv5, socksv5_info, sizeof(ipa_socksv5_msg));
		evt_data.evt_data = data_socksv5;

		if (is_add == true)
		{
			evt_data.event = IPA_ADD_SOCKSv5_CONN;
			IPACMDBG("posting IPA_ADD_SOCKSv5_CONN\n");
		}
		else
		{
			evt_data.event = IPA_DEL_SOCKSv5_CONN;
			IPACMDBG("posting IPA_DEL_SOCKSv5_CONN\n");
		}
		/* Insert IPA_ADD/DEL_SOCKSv5_CONN to command queue */
		IPACM_EvtDispatcher::PostEvt(&evt_data);
		return IPACM_SUCCESS;
	}

	/* post IPA_ROUTE_ADD_VLAN_PDN_EVENT msg */
	inline int post_socksv5_add_vlan_evt(ipa_ip_type iptype, uint32_t public_ip, uint32_t *prefix)
	{
		ipacm_cmd_q_data evt_data;
		ipacm_event_route_vlan *vlan_data;

		evt_data.event = IPA_ROUTE_ADD_VLAN_PDN_EVENT;
		vlan_data = (ipacm_event_route_vlan *)malloc(sizeof(ipacm_event_route_vlan));
		if(vlan_data == NULL)
		{
			IPACMERR("unable to allocate memory for event data_socksv5\n");
			return IPACM_FAILURE;
		}
		memset(vlan_data, 0, sizeof(ipacm_event_route_vlan));

		if (iptype == IPA_IP_v4)
		{
			vlan_data->iptype = IPA_IP_v4;
			vlan_data->wan_ipv4_addr = public_ip;
		}
		else if (iptype == IPA_IP_v6)
		{
			vlan_data->iptype = IPA_IP_v6;
			vlan_data->wan_ipv6_prefix[0] = prefix[0];
			vlan_data->wan_ipv6_prefix[1] = prefix[1];
		}
		else
		{
			IPACMERR("wrong ip-type %d\n", vlan_data->iptype);
			free(vlan_data);
			return IPACM_FAILURE;
		}

		evt_data.evt_data = vlan_data;
		IPACMDBG("sending IPA_ROUTE_ADD_VLAN_PDN_EVENT vlan id %d, iptype %d,\n",
						vlan_data->VlanID,
						vlan_data->iptype);
		IPACM_EvtDispatcher::PostEvt(&evt_data);
		return IPACM_SUCCESS;
	}
#endif //defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
	/**
	 * Insert a new MACSEC map to the configuration table and mark
	 * this interface as virtual. in case the a MACSEC map is
	 * already present for the interface provided, the old MACSEC
	 * map is replaced with the provided MACSEC map.
	 *
	 * @param macsecMap: MACSEC map to add to an interface
	 *      	   configuration.
	 *
	 * @return bool: true on success, false otherwise.
	 */
	bool insertOrAssignMacsecMap(struct ipa_macsec_map *macsecMap);
	/**
	 * Reset the given interface MACSEC configuration and mark it as
	 * non-virtual interface.
	 *
	 * @param macsecMap: MACSEC map of the interface to mark as
	 *      	   non-virtual.
	 *
	 * @return bool: true on success, false otherwise.
	 */
	bool delMacsecMap(struct ipa_macsec_map *macsecMap);
	/**
	 * Populate macsec mapping information by Linux interface index
	 * if such an interface exist.
	 *
	 * @param interfaceIndex Linux interface index.
	 * @param macsecMap      Pointer to MACsec mapping information
	 *      		 allocated by the caller.
	 *
	 * @return bool true when mapping is populated successfully,
	 *         false otherwise.
	 */
	bool populateMacsecMap(const int interfaceIndex, struct ipa_macsec_map *macsecMap) {
		if (!macsecMap)
			return false;
		auto ipaInterfaceInfo = getMacsecInterface(interfaceIndex);
		if (ipaInterfaceInfo) {
			strlcpy(macsecMap->macsec_name, ipaInterfaceInfo->iface_name, sizeof(macsecMap->macsec_name));
			strlcpy(macsecMap->phy_name, ipaInterfaceInfo->phy_dev_name, sizeof(macsecMap->phy_name));
			return true;
		}
		return false;
	}

#ifdef IPA_IOCTL_SET_EXT_ROUTER_MODE
	enum ipa_ext_router_mode ext_router_mode;
	std::list<ext_router_prefix_info> ext_router_prefix;
	bool add_ext_router_info(struct ipa_ioc_ext_router_info *data);
	bool del_ext_router_info(char* pdn_name);
	bool get_ext_router_info(struct ext_router_prefix_info *data);
	char* is_ext_route_ipv6_prefix(uint32_t *addr);
	int get_mapped_delegated_prefix_idx(uint32_t *addr);
#endif
#ifdef FEATURE_IPA_IPSEC
	bool AddIpsecUlFlt(struct ipa_ioc_ipsec_ul_flt_attr uf);
	bool DelIpsecUlFlt(struct ipa_ioc_ipsec_ul_flt_attr uf);
#endif

	static const char *DEVICE_NAME_ODU;

private:

	static const int DEFAULT_IPV6CT_MAX_ENTRIES = 500;
	const char* DEFAULT_NAT_MEMTYPE = "DDR";
	const char* DEFAULT_CT_MEMTYPE = "DDR";

	enum ipa_hw_type ver;
	static IPACM_Config *pInstance;
	static const char *DEVICE_NAME;
	IPACM_Config(void);
	int m_fd; /* File descriptor of the IPA device node /dev/ipa */
	uint8_t qmap_id;
	ipacm_ext_prop ext_prop_v4;
	ipacm_ext_prop ext_prop_v6;

	/**
	 * Return the physical device name if the interface is marked as
	 * virtual.
	 *
	 * @param interfaceName name of the interface.
	 *
	 * @return string physical device name if device is virtual,
	 *         interfaceName otherwise.
	 */
	string getNameForVlanQuery(const string &interfaceName) {
		IPACMDBG("interfaceName = %s\n", interfaceName.c_str());
		for (int i = 0; i < ipa_num_ipa_interfaces; i++) {
			if (string(iface_table[i].iface_name).length() != 0 && string(interfaceName).rfind(string(iface_table[i].iface_name), 0) == 0 &&
				iface_table[i].virtual_iface) {
				return string(iface_table[i].phy_dev_name);
			}
		}
		IPACMDBG_H("passed string %s\n", interfaceName.c_str());
		return interfaceName;
	}
	/**
	 * Get MACsec interface information by Linux interface index.
	 *
	 * @param interfaceIndex Linux interface index.
	 *
	 * @return ipa_ifi_dev_name_t* pointer to MACsec interface
	 *         information if such an interface exist, nullptr
	 *         otherwise.
	 */
	ipa_ifi_dev_name_t* getMacsecInterface(const int interfaceIndex) const {
		if (!iface_table)
			return nullptr;
		/* eth_wan_iface_table_idx reserved for ETH VLAN WAN instances*/
		for (int i = 0; i < ipa_num_ipa_interfaces; i++)
		{
			for (int j = 0; j < MAX_NUM_PPPOE_MPDN; j++)
			{
				if(iface_table[i].netlink_interface_index == interfaceIndex &&
					i == eth_wan_iface_table_idx[j])
				{
					return nullptr;
				}
			}
			if (iface_table[i].netlink_interface_index == interfaceIndex &&
					i == mape_wan_iface_table_index ){
				return nullptr;
			}
		}

		auto it = std::find_if(iface_table, iface_table + ipa_num_ipa_interfaces,
			[interfaceIndex](const decltype(iface_table[0])& item) {
				IPACMDBG("iface_name:%s, phy_dev_name:%s, virtual_iface:%d, netlink_interface_index:%d\n", item.iface_name,
					item.phy_dev_name, item.virtual_iface, item.netlink_interface_index);
				return item.netlink_interface_index == interfaceIndex && item.virtual_iface;
		});
		if (it < iface_table + ipa_num_ipa_interfaces) {
			return it;
		}
		return nullptr;
	}
};

#endif /* IPACM_CONFIG */
