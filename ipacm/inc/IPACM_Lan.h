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
	IPACM_Lan.h

	@brief
	This file implements the LAN iface definitions

	@Author
	Skylar Chang

*/
#ifndef IPACM_LAN_H
#define IPACM_LAN_H

#include <stdio.h>
#include <linux/msm_ipa.h>

#include "IPACM_CmdQueue.h"
#include "IPACM_Iface.h"
#include "IPACM_Routing.h"
#include "IPACM_Filtering.h"
#include "IPACM_Config.h"
#include "IPACM_Conntrack_NATApp.h"

#define IPA_WAN_DEFAULT_FILTER_RULE_HANDLES  1
#define IPA_NUM_ODU_ROUTE_RULES 2
#define MAX_WAN_UL_FILTER_RULES MAX_NUM_EXT_PROPS
#define NUM_IPV4_ICMP_FLT_RULE 1
#define NUM_IPV6_ICMP_FLT_RULE 1
#if defined(FEATURE_L2TP)
#ifdef IPA_L2TP_TUNNEL_UDP
/* Default rules to route 1) Frag packets, 2) ARP, 3) IP TCP SYN, 4) IPv6 TCP SYN and
 * 5) ICMPv6 packets to exception. */
#define NUM_L2TP_UDP_DFLT_RULES 5
#endif
#endif

/* ndc bandwidth ipatetherstats <ifaceIn> <ifaceOut> */
/* <in->out_bytes> <in->out_pkts> <out->in_bytes> <out->in_pkts */

#define PIPE_STATS "%s %s %lu %lu %lu %lu"
#ifdef FEATURE_IPA_ANDROID
#define IPA_PIPE_STATS_FILE_NAME "/data/misc/ipa/tether_stats"
#else
#define IPA_PIPE_STATS_FILE_NAME "/tmp/tether_stats"
#endif

/* store each lan-iface unicast routing rule and its handler*/
struct ipa_lan_rt_rule
{
	ipa_ip_type ip;
	uint32_t v4_addr;
	uint32_t v4_addr_mask;
	uint32_t v6_addr[4];
	uint32_t rt_rule_hdl[0];
};

/* Support multiple eth client */
typedef struct _eth_client_rt_hdl
{
	uint32_t eth_rt_rule_hdl_v4;
}eth_client_rt_hdl;

typedef struct _ipa_eth_client
{
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
#endif
	int if_index;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	bool ipv4_ul_rules_set;
	bool ipv6_ul_rules_set;
	/* store ipv4 UL filter rule handlers from Q6*/
	uint32_t wan_ul_fl_rule_hdl_v4[MAX_WAN_UL_FILTER_RULES];
	/* store ipv6 UL filter rule handlers from Q6*/
#ifndef IPA_V6_UL_WL_FIREWALL_HANDLE
	uint32_t wan_ul_fl_rule_hdl_v6[MAX_WAN_UL_FILTER_RULES];
#else
	uint32_t wan_ul_fl_rule_hdl_v6[IPACM_MAX_V6_UL_WL_FIREWALL_ENTRIES];
#endif
	int8_t lan_stats_idx;
#ifdef IPA_HW_FNR_STATS
	/* H/w counters */
	int ul_cnt_idx;
	int dl_cnt_idx;
	bool index_populated;
#endif //IPA_HW_FNR_STATS
#endif
#ifdef FEATURE_L2TP
	uint32_t dl_first_pass_hdr_hdl;
	uint32_t dl_first_pass_hdr_proc_ctx_hdl;
	uint32_t dl_first_pass_rt_rule_hdl;
	uint32_t dl_second_pass_hdr_hdl;
	uint32_t dl_second_pass_rt_rule_hdl;
	uint32_t ul_first_pass_rt_rule_hdl;
	uint32_t ul_first_pass_flt_rule_hdl;
#endif

#ifdef FEATURE_VLAN_MPDN
	uint16_t vlan_id;
#endif
	bool gre_nat_set;
#ifdef IPA_IOCTL_SET_EXT_ROUTER_MODE
	uint32_t ext_router_prefix_rt_hdl;
#endif
	eth_client_rt_hdl eth_rt_hdl[0]; /* depends on number of tx properties */
#ifdef FEATURE_STATIC_POLICY
	eth_client_rt_hdl dscp_eth_rt_hdl[IPA_UC_MAX_PDN_DSCP_VAL];
#endif
}ipa_eth_client;

#ifdef FEATURE_IPACM_UL_FIREWALL
typedef struct ul_firewall {
	uint32_t ul_firewall_handle[IPA_MAX_NUM_PROPS][IPACM_MAX_FIREWALL_ENTRIES];
	int num_ul_firewall_installed[IPA_MAX_NUM_PROPS];
#ifdef FEATURE_VLAN_MPDN
	int num_ul_frag_installed[IPA_MAX_NUM_PROPS];
	uint32_t ul_frag_handle[IPA_MAX_NUM_PROPS][IPA_MAX_NUM_HW_PDNS];
#else
	bool ul_frag_installed[IPA_MAX_NUM_PROPS];
	uint32_t ul_frag_handle[IPA_MAX_NUM_PROPS];
#endif
} ul_firewall_t;
#endif

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
/* store each lan client index along with MAC. */
typedef struct ipa_lan_client_idx
{
	int8_t lan_stats_idx;
	uint8_t mac[IPA_MAC_ADDR_SIZE];
	/* IPACM interface id */
	int ipa_if_num;
}ipa_lan_client_idx;
#endif

typedef struct rule_id_hdl_map
{
	uint32_t flt_hdl;
	uint16_t rule_id;
}rule_id_hdl_map;

typedef struct pdn_context
{
	int pdn_mux_id;
	uint16_t associated_VIDs[IPA_MAX_NUM_SW_PDNS];
	uint32_t active_vlan_count;
	uint32_t wan_mpdn_ul_xlat_fl_rule_hdl_v4[MAX_WAN_UL_FILTER_RULES];
	uint32_t num_wan_mpdn_ul_xlat_fl_rule_v4;
}pdn_context;

typedef struct _xlat_context
{
	rule_id_hdl_map ul_rule_id_hdl_map[MAX_WAN_UL_FILTER_RULES];

	/* PDN's for which UL filter installed */
	pdn_context active_pdn_list[IPA_MAX_NUM_HW_PDNS];
	uint32_t active_pdn_count;
}xlat_context;

#ifdef FEATURE_EoGRE
/*
 * Structure for maintaining state associated with eogre route
 * contexts and rules...
 */
typedef struct eogre_route_data_s
{
	uint32_t header_hdl;
	uint32_t proc_ctx_eogre_add_hdl;
	uint32_t proc_ctx_eogre_rmv_hdl;
	uint32_t rt_eogre_add_hdl;
	uint32_t rt_eogre_rmv_hdl;
	uint32_t rt_tbl_hdl;
	uint32_t flt_eogre_1st_pass_hdl;
} eogre_route_data_t;

/*
 * An IP v4 plus GRE header..
 */
typedef struct v4_gre_hdr_s
{
	uint32_t words[6]; /* extra (ie. last) uint32_t for gre header */
} v4_gre_hdr_t;

/*
 * Where things reside in the struct above...
 */
#define IPV4_SRC_ADDR_IDX  3
#define IPV4_DST_ADDR_IDX  4
#define IPV4_GRE_PROT_IDX  5

/*
 * An IP v6 + options + GRE header.
 */
typedef struct v6_gre_hdr_s
{
	uint32_t words[13]; /* 10 words for header 2 words for options + 1 word for gre header */
} v6_gre_hdr_t;

/*
 * Where things reside in the struct above...
 */
#define IPV6_SRC_ADDR_IDX  2
#define IPV6_DST_ADDR_IDX  6
#define IPV6_GRE_PROT_IDX 12
#define IPV6_GRE_PROT     10

/*
 * An IP v6 + GRE header.
 */
typedef struct v6_eogre_hdr_s
{
	uint32_t words[11]; /* 10 words for header + 1 word for gre header */
} v6_eogre_hdr_t;

#endif /* #ifdef FEATURE_EoGRE */

/* lan iface */
class IPACM_Lan : public IPACM_Iface
{
public:

	IPACM_Lan(int iface_index);
	~IPACM_Lan();

	/* store lan's wan-up filter rule handlers */
	uint32_t lan_wan_fl_rule_hdl[IPA_MAX_NUM_PROPS][IPA_WAN_DEFAULT_FILTER_RULE_HANDLES];

	/* store private-subnet filter rule handlers */
	uint32_t private_fl_rule_hdl[IPA_MAX_NUM_PROPS][IPA_MAX_PRIVATE_SUBNET_ENTRIES + IPA_MAX_MTU_ENTRIES];

#ifdef FEATURE_IPACM_UL_FIREWALL
	ul_firewall_t iface_ul_firewall;
#endif
	/* Number of Q6 UL IPv4 rules. */
	int num_wan_ul_fl_rule_v4[IPA_MAX_NUM_PROPS];
	/* Number of Q6 UL IPv6 rules. */
	int num_wan_ul_fl_rule_v6[IPA_MAX_NUM_PROPS];
	/* Number of UL subnet IPv4 rules. */
	int num_wan_subnet_rules[IPA_MAX_NUM_PROPS];
	/* Number of UL prefix IPv6 rules. */
	int num_wan_prefix_rules[IPA_MAX_NUM_PROPS];

	/* Header length. */
	uint8_t hdr_len;

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	/* Clients which take HW path. */
	ipa_lan_client_idx active_lan_client_index[IPA_MAX_NUM_HW_PATH_CLIENTS];
	/* Clients which take SW path. This will be used as a place holder to move clients back to HW path. */
	ipa_lan_client_idx inactive_lan_client_index[IPA_MAX_NUM_HW_PATH_CLIENTS];
	bool is_odu;
#endif
#ifdef FEATURE_VLAN_MPDN
	bool is_vlan_offload_disabled;
#endif

	/* To determine if an interface is special interface */
	bool sIface;

	std::list <ipacm_event_data_all> neigh_cache;

	/* LAN-iface's callback function */
	void event_callback(ipa_cm_event_id event, void *data);

	virtual int handle_wan_up(ipa_ip_type ip_type);

	/* configure filter rule for wan_up event*/
	virtual int handle_wan_up_ex(ipacm_ext_prop* ext_prop, ipa_ip_type iptype, uint8_t xlat_mux_id);

	/* send notification about UL filtering rules removal */
	virtual int notify_flt_removed(uint8_t mux_id);

	/* delete filter rule for wan_down event*/
	virtual int handle_wan_down(bool is_sta_mode);

	/* delete filter rule for wan_down event*/
	virtual int handle_wan_down_v6(bool is_sta_mode, bool is_support_mpdn = true);

	/* configure private subnet filter rules*/
	int modify_private_subnet();
	virtual int handle_private_subnet(ipa_ip_type iptype);
	int eth_bridge_get_vlan_hdr_template_hdl(uint32_t *hdr_hdl, uint16_t vlan_id);
#ifdef FEATURE_VLAN_MPDN
	int add_vlan_private_subnet(ipacm_bridge *bridge);
	int modify_ipv6_prefix_flt_rule();
	int handle_backhaul_switch_vlan_mode(bool to_sta);
#endif

	/* handle new_address event*/
	int handle_addr_evt(ipacm_event_data_addr *data);

	int handle_addr_evt_odu_bridge(ipacm_event_data_addr* data);

	int handle_del_ipv6_addr(ipacm_event_data_all *data);

	int check_neigh_ipv4(ipacm_event_data_all *data);

	int handle_ext_router_add_evt(char* pdn_name, uint8_t *mac_addr, uint32_t *idu_v6_addr, uint16_t vid);

	int handle_ext_router_del_evt(void);

#ifdef FEATURE_IPA_IPSEC
	int handleIpsecUlFltAddEvt(struct ipa_ioc_ipsec_ul_flt_attr *uf);
	int handleIpsecUlFltDelEvt(struct ipa_ioc_ipsec_ul_flt_attr *uf);
	int handleIpsecUlFltAddAll(enum ipa_ip_type ip);
	int handleIpsecUlFltDelAll(enum ipa_ip_type ip);
#endif

	int handle_static_policy_rt_rule_add();
	int handle_static_policy_flt_rule_add(uint32_t ipv4_addr);
	int handle_static_policy_rule_delete();

	uint32_t static_policy_flt_rule_hdl;
	uint32_t static_policy_flt_rule_hdl_v6;
	static uint32_t static_policy_rt_rule_hdl;
	static uint32_t static_policy_proc_ctx_hdl;
	static uint32_t total_vlan_pdn_cnt;
	static uint32_t total_vlan_pdn_cnt_v6;

	static bool odu_up;

#ifdef FEATURE_EoGRE
	/*
	 * The following is for keeping eogre route rule state...
	 *
	 * We're using two below (one for v4, one for v6) because there
	 * may be a mismatch between the tunnel iptype (ie. the one
	 * specified in the eogre enable) and the Vlan Ethernet packet's
	 * IP payload type. In other words:
	 *
	 *   The tunnel may be v4, while the Vlan Ethernet packet's IP
	 *   type is v6; or
	 *
	 *   The tunnel may be v6, while the Vlan Ethernet packet's IP
	 *   type is v4...
	 */
	eogre_route_data_t eogre_route_data[IPA_IP_MAX];

	void eogre_up();

	void eogre_down();

	int eogre_do_rt_work(
		ipa_ipgre_info& ipgre_info );

	void eogre_route_data_init(
		enum ipa_ip_type iptype );

	uint32_t eogre_get_rt_tbl_hdl(
		enum ipa_ip_type iptype );

	int eogre_make_hdr_for_add_ctx(
		ipa_ipgre_info& ipgre_info );

	int eogre_make_hdr_add_ctx(
		ipa_ipgre_info& ipgre_info,
		uint32_t        hdr_2use = 0 );

	int eogre_make_hdr_rem_ctx(
		ipa_ipgre_info& ipgre_info );

	int eogre_make_header_add_rt_rule(
		ipa_ipgre_info& ipgre_info,
		uint32_t        ctx_2use = 0 );

	int eogre_make_header_rem_rt_rule(
		ipa_ipgre_info& ipgre_info );

	void eogre_clear_route_data(
		enum ipa_ip_type             iptype,
		ipa_ioc_query_intf_rx_props* rx_prop = 0 );

	int eogre_add_catchup_rule(
		enum ipa_ip_type iptype );

	int update_complementary_table(
		ipa_flt_rule_add& flt_rule_entry,
		ipa_ip_type       iptype );
#endif

	/* install UL filter rule from Q6 */
#ifdef FEATURE_VLAN_MPDN
	virtual int handle_uplink_filter_rule(ipacm_ext_prop *prop, ipa_ip_type iptype, uint8_t pdn_mux_id, bool notif_only, bool is_xlat = false, bool ast_update = false, bool static_policy = false);

	virtual int handle_mpdn_ul_xlat_filter_rule(ipacm_ext_prop *prop, ipa_ip_type iptype, int pdn_mux_id, uint16_t vlan_id);

	virtual int delete_mdpn_ul_xlat_filter_rule(int mux_id);
#else
	virtual int handle_uplink_filter_rule(ipacm_ext_prop* prop, ipa_ip_type iptype, uint8_t xlat_mux_id, bool ast_update = false);
#endif

	virtual int del_ul_flt_rules(enum ipa_ip_type iptype);

#ifdef FEATURE_IPACM_UL_FIREWALL
	/* configure UL firewalls for all PDNs relevant for this LAN */
	virtual void configure_v6_ul_firewall(void);

	/* configure UL firewall for a single profile\pdn */
	virtual int configure_v6_ul_firewall_one_profile(IPACM_firewall_conf_t* firewall_conf, bool isDefault, int vid);

	/* Configure and install the UL firewall rules on the LAN prod pipe */
	virtual int config_dft_firewall_rules_ul(
		IPACM_firewall_conf_t* firewall_conf,
		ul_firewall_t *ul_firewall,
		int vid);

	/* Config WL UL firewall filter rules on LTE BH (FW on Q6 routing table) */
	virtual int config_dft_firewall_rules_ul_ex(
		IPACM_firewall_conf_t* firewall_conf,
		struct ipa_flt_rule_add *rules,
		int vid);

	void prepare_v6_ul_fw_flt_rules (
		int fd, ipacm_ext_prop *ext_prop,
		IPACM_firewall_conf_t *firewall_conf,
		struct ipa_fltr_installed_notif_req_msg_v01 *flt_index,
		struct ipa_ioc_add_flt_rule *pFilteringTable
	);

	int install_v6_ul_fw_flt_rule_per_client (
		ipa_ioc_add_flt_rule* prop,
		ipa_ip_type iptype,
		uint8_t *mac_addr,
		uint8_t ul_cnt_idx
	);

	int config_dft_firewall_rules_ul_ex_per_client (
		IPACM_firewall_conf_t* firewall_conf,
		struct ipa_flt_rule_add *rules, int vid
	);

#ifdef IPA_V6_UL_WL_FIREWALL_HANDLE
	virtual bool replicate_flt_rule(ipa_flt_rule_add *replicate_rule,
			ipa_flt_rule_add *q6_rule,
			ipa_flt_rule_add *fw_rule);
#endif
	/* send fragments to exception when UL FW is installed on Q6 routing table*/
	virtual int config_wan_frag_firewall_rule_ul_ex(ul_firewall_t *ul_firewall, int vid);

	/* Send the UL firewall rules to Q6 via QMI */
	virtual int install_wan_firewall_rule_ul(bool enable, int vid, int num_of_ul_rules);

	/* Delete UL firewall filter rules from LAN prod pipe */
	virtual int delete_uplink_filter_rule_ul(ul_firewall_t *ul_firewall);

	/* delete UL firewall rules, to be sent to Q6 side*/
	virtual int disable_dft_firewall_rules_ul_ex(int vid);
#endif
#ifdef FEATURE_IPACM_PER_CLIENT_STATS

	void handle_stats_client_connect(int if_index, uint8_t *mac_addr );
	/* handle lan client connect event. */
	virtual int handle_lan_client_connect(uint8_t *mac_addr);

	/* handle lan client disconnect event. */
	virtual int handle_lan_client_disconnect(uint8_t *mac_addr);

	/* install UL filter rule from Q6 per client */
	virtual int install_uplink_filter_rule_per_client
	(
		ipacm_ext_prop* prop,
		ipa_ip_type iptype,
		uint8_t xlat_mux_id,
		uint8_t *mac_addr
	);
#ifdef IPA_HW_FNR_STATS
	virtual int install_uplink_filter_rule_per_client_v2
	(
		ipacm_ext_prop* prop,
		ipa_ip_type iptype,
		uint8_t xlat_mux_id,
		uint8_t *mac_addr,
		uint8_t ul_cnt_idx,
		ipa_ioc_add_flt_rule *fw_q6_rules = NULL,
		bool isFirewall = false
	);

#endif //IPA_HW_FNR_STATS
	/* install UL filter rule from Q6 for all clients */
	virtual int install_uplink_filter_rule
	(
		ipacm_ext_prop* prop,
		ipa_ip_type iptype,
		uint8_t xlat_mux_id
	);

	/* Delete UL filter rule from Q6 for all clients */
	virtual int delete_uplink_filter_rule
	(
		ipa_ip_type iptype
	);

	/* Delet UL filter rule from Q6 per client */
	virtual int delete_uplink_filter_rule_per_client
	(
		ipa_ip_type iptype,
		uint8_t *mac_addr
	);

	/* set lan client info. */
	virtual int set_lan_client_info(struct wan_ioctl_lan_client_info *client_info);

	/* set lan client info. */
	virtual int clear_lan_client_info(struct wan_ioctl_lan_client_info *client_info);

	/* Enable per client stats. */
	virtual int enable_per_client_stats(bool *status);
#endif

	int handle_cradle_wan_mode_switch(bool is_wan_bridge_mode);

	int install_ipv4_icmp_flt_rule();

	/* add header processing context and return handle to lan2lan controller */
	int eth_bridge_add_hdr_proc_ctx(ipa_hdr_l2_type peer_l2_hdr_type, uint32_t *hdl, uint16_t vlan_id);

	/* add routing rule and return handle to lan2lan controller */
	int eth_bridge_add_rt_rule(uint8_t *mac, char *rt_tbl_name, uint32_t hdr_proc_ctx_hdl,
		ipa_hdr_l2_type peer_l2_hdr_type, ipa_ip_type iptype, uint32_t *rt_rule_hdl, int *rt_rule_count);

	/* modify routing rule*/
	int eth_bridge_modify_rt_rule(uint8_t *mac, uint32_t hdr_proc_ctx_hdl,
		ipa_hdr_l2_type peer_l2_hdr_type, ipa_ip_type iptype, uint32_t *rt_rule_hdl, int rt_rule_count);

	/* add filtering rule and return handle to lan2lan controller */
	int eth_bridge_add_flt_rule(uint8_t *mac, uint32_t rt_tbl_hdl, ipa_ip_type iptype, uint32_t *flt_rule_hdl, uint16_t vlan_id = 0, uint16_t pipe_idx = 0);

	/* delete filtering rule */
	int eth_bridge_del_flt_rule(uint32_t flt_rule_hdl, ipa_ip_type iptype);

	/* delete routing rule */
	int eth_bridge_del_rt_rule(uint32_t rt_rule_hdl, ipa_ip_type iptype);

	/* delete header processing context */
	int eth_bridge_del_hdr_proc_ctx(uint32_t hdr_proc_ctx_hdl);

#ifdef FEATURE_L2TP
	/* add l2tp rt rule for l2tp client */
	int add_l2tp_rt_rule(ipa_ip_type iptype, uint8_t *dst_mac, ipa_hdr_l2_type peer_l2_hdr_type,
		uint32_t l2tp_session_id, uint32_t vlan_id, uint8_t *vlan_client_mac, uint32_t *vlan_iface_ipv6_addr,
		uint32_t *vlan_client_ipv6_addr, uint32_t *first_pass_hdr_hdl, uint32_t *first_pass_hdr_proc_ctx_hdl,
		uint32_t *second_pass_hdr_hdl, int *num_rt_hdl, uint32_t *first_pass_rt_rule_hdl, uint32_t *second_pass_rt_rule_hdl);

	/* delete l2tp rt rule for l2tp client */
	int del_l2tp_rt_rule(ipa_ip_type iptype, uint32_t first_pass_hdr_hdl, uint32_t first_pass_hdr_proc_ctx_hdl,
		uint32_t second_pass_hdr_hdl, int num_rt_hdl, uint32_t *first_pass_rt_rule_hdl, uint32_t *second_pass_rt_rule_hdl);

	/* add l2tp rt rule for non l2tp client */
	int add_l2tp_rt_rule(ipa_ip_type iptype, uint8_t *dst_mac, uint32_t *hdr_proc_ctx_hdl,
		int *num_rt_hdl, uint32_t *rt_rule_hdl);

	/* delete l2tp rt rule for non l2tp client */
	int del_l2tp_rt_rule(ipa_ip_type iptype, int num_rt_hdl, uint32_t *rt_rule_hdl);

	/* add l2tp flt rule on l2tp interface */
	int add_l2tp_flt_rule(uint8_t *dst_mac, uint32_t *flt_rule_hdl);

	/* delete l2tp flt rule on l2tp interface */
	int del_l2tp_flt_rule(uint32_t flt_rule_hdl);

	/* add l2tp flt rule on non l2tp interface */
	int add_l2tp_flt_rule(ipa_ip_type iptype, uint8_t *dst_mac, uint32_t *vlan_client_ipv6_addr,
		uint32_t *first_pass_flt_rule_hdl, uint32_t *second_pass_flt_rule_hdl);

	/* delete l2tp flt rule on non l2tp interface */
	int del_l2tp_flt_rule(ipa_ip_type iptype, uint32_t first_pass_flt_rule_hdl, uint32_t second_pass_flt_rule_hdl);

#ifdef IPA_L2TP_TUNNEL_UDP
		/* add l2tp udp rt rule for l2tp client to add the L2TP header. */
		int add_l2tp_udp_rt_rule(ipa_ip_type iptype, uint8_t *dst_mac, ipa_hdr_l2_type peer_l2_hdr_type,
			ipa_l2tp_tunnel_type tunnel_type, uint32_t l2tp_session_id, uint16_t src_port, uint16_t dst_port,
			uint32_t vlan_id, uint8_t *vlan_client_mac, uint32_t *vlan_iface_ipv6_addr,
			uint32_t *vlan_client_ipv6_addr, uint32_t *hdr_hdl, uint32_t *hdr_proc_ctx_hdl, int *num_rt_hdl,
			uint32_t *rt_rule_hdl);

		/* add default rules for l2tp udp client */
		int add_l2tp_udp_dflt_flt_rules(uint32_t *l2tp_dflt_rules);

		/* delete default rules for l2tp udp client */
		int del_l2tp_udp_dflt_flt_rules(uint32_t *dflt_rules);

		/* add l2tp udp rt rule for non l2tp client */
		int add_l2tp_udp_rt_rule(ipa_ip_type iptype, uint8_t *dst_mac, uint32_t *hdr_proc_ctx_hdl,
			int *num_rt_hdl, uint32_t *rt_rule_hdl);

		/* add l2tp udp flt rule on l2tp interface */
		int add_l2tp_udp_flt_rule(uint8_t *dst_mac, uint32_t *vlan_iface_ipv6_addr,
			uint32_t *vlan_client_ipv6_addr, uint16_t src_port, uint16_t dst_port, uint32_t *flt_rule_hdl);

		/* add l2tp udp flt rule on non l2tp interface */
		int add_l2tp_udp_flt_rule(ipa_ip_type iptype, uint8_t *dst_mac, uint16_t mtu,
			uint32_t *flt_rule_hdl);

		/* delete l2tp udp rt rule for l2tp client */
		int del_l2tp_udp_rt_rule(ipa_ip_type iptype, uint32_t hdr_hdl, uint32_t hdr_proc_ctx_hdl,
			int num_rt_hdl, uint32_t *rt_rule_hdl);

		/* delete l2tp udp flt rule on non l2tp interface */
		int del_l2tp_udp_flt_rule(ipa_ip_type iptype, uint32_t flt_rule_hdl);
#endif

	/* Handle L2TP Neigh events. */
	int handle_l2tp_neigh(ipacm_event_data_all *data);
#endif


#ifdef FEATURE_SOCKSv5
	/* add socksv5 flt rule */
	int add_socksv5_flt_rule(ipacm_event_connection *data_event_conn);
	int del_socksv5_flt_rule(void);
#endif

	int install_default_qos_rt_rules(uint8_t *client_mac, uint16_t client_vlan_id, enum ipa_ip_type iptype);

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
private:
	static bool lan_stats_inited;
	static ipa_lan_client_idx active_lan_client_index_odu[IPA_MAX_NUM_HW_PATH_CLIENTS];
	/* Clients which take SW path. */
	static ipa_lan_client_idx inactive_lan_client_index_odu[IPA_MAX_NUM_HW_PATH_CLIENTS];
#endif

protected:

	int each_client_rt_rule_count[IPA_IP_MAX];

	uint32_t eth_bridge_flt_rule_offset[IPA_MAX_NUM_PROPS][IPA_IP_MAX];
	uint32_t mtu_flt_rule_offset[IPA_MAX_NUM_PROPS][IPA_IP_MAX];

#ifdef FEATURE_L2TP
#ifdef IPA_L2TP_TUNNEL_UDP
	uint32_t l2tp_udp_dflt_flt_tule_offset;
#endif
#endif
	/* mac address has to be provided for client related events */
	void eth_bridge_post_event(ipa_cm_event_id evt, ipa_ip_type iptype, uint8_t *mac,
		uint32_t *ipv6_addr, char *iface_name, uint16_t VlanID = 0);

#if defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
	/**
	 * Determine if the interface name is a vlan interface and
	 * related to event of this instance. Interface name is
	 * considered a vlan interface name for this matter if its
	 * structure is: [a-z,0-9]+(\.[a-z,0-9]*)*\.[0-9]*
	 * vlan interface name is relevant if it's a substring of this
	 * instance dev_name.
	 *
	 * @param event_iface_name the name of the interface associated
	 *      		   with the event.
	 *
	 * @return bool true if event_iface_name is a vlan interface and
	 *         is related to this instance.
	 */
	bool is_vlan_event(char *event_iface_name);
#ifdef FEATURE_L2TP
	/* check if the event is associated with l2tp interface */
	bool is_l2tp_event(char *event_iface_name);
#endif //#ifdef FEATURE_L2TP
#endif //#if defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
	/* check if the IPv6 address is unique local address */
	bool is_unique_local_ipv6_addr(uint32_t *ipv6_addr);

	int handle_private_subnet_android(ipa_ip_type iptype);

	int reset_to_dummy_flt_rule(ipa_ip_type iptype, uint32_t rule_hdl);
#ifdef FEATURE_IPV6_NAT
	int add_ipv6_nat_ula_prefix_flt_rule();
	void delete_ipv6_nat_ula_prefix_flt_rule();
#endif
	virtual int install_ipv6_prefix_flt_rule(uint32_t* prefix);

	virtual void delete_ipv6_prefix_flt_rule();

	int install_ipv6_icmp_flt_rule();

#ifdef FEATURE_L2TP
	int install_l2tp_inner_private_subnet_flt_rule();
#endif

	void post_del_self_evt();

	/* handle tethering stats */
	int handle_tethering_stats_event(ipa_get_data_stats_resp_msg_v01 *data);

	/* handle tethering client */
	int handle_tethering_client(bool reset, ipacm_client_enum ipa_client);

	/* add tcp syn flt rule */
	int add_tcp_syn_flt_rule(ipa_ip_type iptype);

	/* add tcp syn flt rule for l2tp interface*/
	int add_tcp_syn_flt_rule_l2tp(ipa_ip_type inner_ip_type);

	void HandleNeighIpAddrAddEvt(ipacm_event_data_all *data);
	virtual void HandleNeighIpAddrDelEvt(int clt_indx);

	int add_mac_flt_blacklist_rule(uint8_t *mac_addr, ipa_ip_type iptype, uint32_t *flt_rule_hdl);
	int del_mac_flt_blacklist_rule(uint32_t flt_rule_hdl, ipa_ip_type iptype);

#ifdef FEATURE_IPACM_PER_CLIENT_STATS

	inline bool is_lan_stats_index_available()
	{
		int cnt;

		IPACMDBG_H ("Is ODU client? %s\n", is_odu?"Yes":"No");
		if (is_odu)
		{
			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (active_lan_client_index_odu[cnt].lan_stats_idx == -1) {
					IPACMDBG_H("Available free index :%d\n", cnt);
					return true;
				}
			}
		}
		else
		{
			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (active_lan_client_index[cnt].lan_stats_idx == -1) {
					IPACMDBG_H("Available free index :%d\n", cnt);
					return true;
				}
			}
		}

		IPACMDBG_H("No free index available\n");
		return false;
	}

	inline int8_t get_free_active_lan_stats_index(uint8_t *mac_addr)
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

		IPACMDBG_H ("Is ODU client? %s\n", is_odu?"Yes":"No");
		if (is_odu)
		{
			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (active_lan_client_index_odu[cnt].lan_stats_idx == -1) {
					IPACMDBG_H("Got active lan stats index :%d, reserve it\n", cnt);
					active_lan_client_index_odu[cnt].lan_stats_idx = cnt;
					memcpy(active_lan_client_index_odu[cnt].mac,
							mac_addr,
							IPA_MAC_ADDR_SIZE);
					active_lan_client_index_odu[cnt].ipa_if_num = ipa_if_num;
					return cnt;
				}
			}
		}
		else
		{
			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (active_lan_client_index[cnt].lan_stats_idx == -1) {
					IPACMDBG_H("Got active lan stats index :%d, reserve it\n", cnt);
					active_lan_client_index[cnt].lan_stats_idx = cnt;
					memcpy(active_lan_client_index[cnt].mac,
							mac_addr,
							IPA_MAC_ADDR_SIZE);
					active_lan_client_index[cnt].ipa_if_num = ipa_if_num;
					return cnt;
				}
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

		IPACMDBG_H ("Is ODU client? %s\n", is_odu?"Yes":"No");
		if (is_odu)
		{
			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (inactive_lan_client_index_odu[cnt].lan_stats_idx == -1) {
					IPACMDBG_H("Got inactive lan stats index :%d, reserve it\n", cnt);
					inactive_lan_client_index_odu[cnt].lan_stats_idx = cnt;
					memcpy(inactive_lan_client_index_odu[cnt].mac,
							mac_addr,
							IPA_MAC_ADDR_SIZE);
					inactive_lan_client_index_odu[cnt].ipa_if_num = ipa_if_num;
					return cnt;
				}
			}
		}
		else
		{
			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (inactive_lan_client_index[cnt].lan_stats_idx == -1) {
					IPACMDBG_H("Got inactive lan stats index :%d, reserve it\n", cnt);
					inactive_lan_client_index[cnt].lan_stats_idx = cnt;
					memcpy(inactive_lan_client_index[cnt].mac,
							mac_addr,
							IPA_MAC_ADDR_SIZE);
					inactive_lan_client_index[cnt].ipa_if_num = ipa_if_num;
					return cnt;
				}
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

		IPACMDBG_H ("Is ODU client? %s\n", is_odu?"Yes":"No");
		if (is_odu)
		{
			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if ((memcmp(active_lan_client_index_odu[cnt].mac,
						mac_addr,
						IPA_MAC_ADDR_SIZE) == 0) &&
						(active_lan_client_index_odu[cnt].ipa_if_num
						== ipa_if_num)) {
					IPACMDBG_H("Got lan stats index :%d, return\n", cnt);
					active_lan_client_index_odu[cnt].lan_stats_idx = cnt;
					memcpy(active_lan_client_index_odu[cnt].mac,
							mac_addr,
							IPA_MAC_ADDR_SIZE);
					return cnt;
				}
			}
		}
		else
		{
			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if ((memcmp(active_lan_client_index[cnt].mac,
						mac_addr,
						IPA_MAC_ADDR_SIZE) == 0) &&
						(active_lan_client_index[cnt].ipa_if_num
						== ipa_if_num)) {
					IPACMDBG_H("Got lan stats index :%d, return\n", cnt);
					active_lan_client_index[cnt].lan_stats_idx = cnt;
					memcpy(active_lan_client_index[cnt].mac,
							mac_addr,
							IPA_MAC_ADDR_SIZE);
					return cnt;
				}
			}
			}

		IPACMDBG_H("index not available\n");
		return -1;
	}

	inline int get_available_inactive_lan_client(uint8_t *mac_addr)
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
		IPACMDBG_H ("Is ODU client? %s\n", is_odu?"Yes":"No");
		if (is_odu)
		{
			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (inactive_lan_client_index_odu[cnt].lan_stats_idx != -1) {
					IPACMDBG_H("Got inactive lan stats index :%d, return the mac\n", cnt);
					memcpy(mac_addr, inactive_lan_client_index_odu[cnt].mac, IPA_MAC_ADDR_SIZE);
					return IPACM_SUCCESS;
				}
			}
		}
		else
		{
			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (inactive_lan_client_index[cnt].lan_stats_idx != -1) {
					IPACMDBG_H("Got inactive lan stats index :%d, return the mac\n", cnt);
					memcpy(mac_addr, inactive_lan_client_index[cnt].mac, IPA_MAC_ADDR_SIZE);
					return IPACM_SUCCESS;
				}
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

		IPACMDBG_H ("Is ODU client? %s\n", is_odu?"Yes":"No");
		if (is_odu)
		{
			if (idx < 0 || idx >= IPA_MAX_NUM_HW_PATH_CLIENTS ||
				memcmp(active_lan_client_index_odu[idx].mac,
								mac_addr,
								IPA_MAC_ADDR_SIZE))
			{
				IPACMDBG_H("Index :%d invalid\n", idx);
				return IPACM_FAILURE;
			}
			memset(&active_lan_client_index_odu[idx], -1, sizeof(ipa_lan_client_idx));
		}
		else
		{
			if (idx < 0 || idx >= IPA_MAX_NUM_HW_PATH_CLIENTS ||
				memcmp(active_lan_client_index[idx].mac,
								mac_addr,
								IPA_MAC_ADDR_SIZE))
			{
				IPACMDBG_H("Index :%d invalid\n", idx);
				return IPACM_FAILURE;
			}
			memset(&active_lan_client_index[idx], -1, sizeof(ipa_lan_client_idx));
		}
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

		IPACMDBG_H ("Is ODU client? %s\n", is_odu?"Yes":"No");
		if (is_odu)
		{
			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (memcmp(inactive_lan_client_index_odu[cnt].mac,
								mac_addr,
								IPA_MAC_ADDR_SIZE) == 0)
				{
					memset(&inactive_lan_client_index_odu[cnt], -1, sizeof(ipa_lan_client_idx));
					return IPACM_SUCCESS;
				}
			}
		}
		else
		{
			for(cnt = 0; cnt < IPA_MAX_NUM_HW_PATH_CLIENTS; cnt++)
			{
				if (memcmp(inactive_lan_client_index[cnt].mac,
								mac_addr,
								IPA_MAC_ADDR_SIZE) == 0)
				{
					memset(&inactive_lan_client_index[cnt], -1, sizeof(ipa_lan_client_idx));
					return IPACM_SUCCESS;
				}
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
		IPACMDBG_H ("Is ODU client? %s\n", is_odu?"Yes":"No");
		if (is_odu)
		{
			for (i = 0; i < IPA_MAX_NUM_HW_PATH_CLIENTS; i++)
			{
				if (active_lan_client_index_odu[i].ipa_if_num == ipa_if_num)
					memset(&active_lan_client_index_odu[i], -1, sizeof(ipa_lan_client_idx));
				if (inactive_lan_client_index_odu[i].ipa_if_num == ipa_if_num)
					memset(&inactive_lan_client_index_odu[i], -1, sizeof(ipa_lan_client_idx));
			}
		}
		else
		{
			for (i = 0; i < IPA_MAX_NUM_HW_PATH_CLIENTS; i++)
			{
				if (active_lan_client_index[i].ipa_if_num == ipa_if_num)
					memset(&active_lan_client_index[i], -1, sizeof(ipa_lan_client_idx));
				if (inactive_lan_client_index[i].ipa_if_num == ipa_if_num)
					memset(&inactive_lan_client_index[i], -1, sizeof(ipa_lan_client_idx));
			}
		}
	}

#endif

	/* store ipv4 UL filter rule handlers from Q6*/
	uint32_t wan_ul_fl_rule_hdl_v4[IPA_MAX_NUM_PROPS][MAX_WAN_UL_FILTER_RULES];

	/* store ipv6 UL filter rule handlers from Q6*/
#ifndef IPA_V6_UL_WL_FIREWALL_HANDLE
	uint32_t wan_ul_fl_rule_hdl_v6[IPA_MAX_NUM_PROPS][MAX_WAN_UL_FILTER_RULES];
#else
	uint32_t wan_ul_fl_rule_hdl_v6[IPA_MAX_NUM_PROPS][IPACM_MAX_V6_UL_WL_FIREWALL_ENTRIES];
#endif

	uint32_t ipv4_icmp_flt_rule_hdl[IPA_MAX_NUM_PROPS][NUM_IPV4_ICMP_FLT_RULE];
#ifdef FEATURE_VLAN_MPDN
	uint32_t ipv6_prefix_flt_rule_hdl[IPA_MAX_NUM_PROPS][IPA_MAX_IPV6_NO_OFFLOAD_PREFIX_FLT_RULE + IPA_MAX_MTU_ENTRIES];
#else
	uint32_t ipv6_prefix_flt_rule_hdl[IPA_MAX_NUM_PROPS][IPA_MAX_IPV6_PREFIX_FLT_RULE + IPA_MAX_MTU_ENTRIES];
#endif
#ifdef FEATURE_IPV6_NAT
	uint32_t ipv6_nat_ula_prefix_flt_rule_hdl;
#endif
	uint32_t ipv6_icmp_flt_rule_hdl[IPA_MAX_NUM_PROPS][NUM_IPV6_ICMP_FLT_RULE];
#ifdef FEATURE_L2TP
	uint32_t l2tp_inner_private_subnet_flt_rule_hdl[IPA_MAX_NUM_PROPS][IPA_MAX_PRIVATE_SUBNET_ENTRIES];
#endif

#ifdef FEATURE_SOCKSv5
	uint32_t socksv5_flt_hdl_v6;
#endif

	bool is_active;
	bool modem_ul_v4_set[IPA_MAX_NUM_PROPS];
	bool modem_ul_v6_set[IPA_MAX_NUM_PROPS];

	uint32_t if_ipv4_subnet;

	uint32_t ipv6_prefix[2];

	uint32_t tcp_syn_flt_rule_hdl[IPA_MAX_NUM_PROPS][IPA_IP_MAX];
#if defined(FEATURE_L2TP)
#ifdef IPA_L2TP_TUNNEL_UDP
	uint32_t l2tp_udp_dflt_flt_rule_hdl[NUM_L2TP_UDP_DFLT_RULES];
#endif
#endif

#ifdef IPA_IOCTL_SET_EXT_ROUTER_MODE
	/*Ext router mode hdls*/
	uint32_t ext_router_rmnet_ipv6_hdl;
	uint32_t ext_router_flt_rule_hdl;
	char ext_router_pdn_name[IPA_IFACE_NAME_LEN];
#endif

#ifdef FEATURE_IPA_IPSEC
	/* IPsec UL flt rule handles */
	std::list <IpsecUlFltHdl> ipsecUlFltHdlList[IPA_IP_MAX];
#endif

	int post_lan_up_event(const ipacm_event_data_addr* data) const;

	xlat_context xlat_ctx;

	inline void add_pdn_xlat_ctx(int pdn_mux_id, uint16_t vid)
	{
		//check if mux_id was already added but need to add VLAN
		for (int i = 0; i < IPA_MAX_NUM_HW_PDNS; ++i)
		{
			if (xlat_ctx.active_pdn_list[i].pdn_mux_id == pdn_mux_id)
			{
				for (int j = 0; j < IPA_MAX_NUM_SW_PDNS; ++j)
				{
					if (xlat_ctx.active_pdn_list[i].associated_VIDs[j] == 0) //add to the first empty
					{
						xlat_ctx.active_pdn_list[i].associated_VIDs[j] = vid;
						xlat_ctx.active_pdn_list[i].active_vlan_count++;

						IPACMDBG_H("Updating pdn with vlan id %d to xlat ctx mux id %d total active xlat pdn:%d vlan count %d\n",
							vid, pdn_mux_id, xlat_ctx.active_pdn_count, xlat_ctx.active_pdn_list[i].active_vlan_count);
						return;
					}
				}
			}
		}

		//Mux ID is new, add to the first open spot
		for (int i = 0; i < IPA_MAX_NUM_HW_PDNS; ++i)
		{
			if (xlat_ctx.active_pdn_list[i].pdn_mux_id == 0)
			{
				xlat_ctx.active_pdn_list[i].pdn_mux_id = pdn_mux_id;
				xlat_ctx.active_pdn_count++;
				xlat_ctx.active_pdn_list[i].associated_VIDs[0] = vid;
				xlat_ctx.active_pdn_list[i].active_vlan_count++;
				IPACMDBG_H("Adding new pdn with vlan id %d to xlat ctx mux id %d total active xlat pdn:%d\n",
					vid, pdn_mux_id, xlat_ctx.active_pdn_count);
				return;
			}
		}

		//neither case passed, which means pdn list is full
		IPACMDBG_H("Max number of pdns reached, can't add pdn to ctx!\n");
	}

	inline void remove_pdn_xlat_ctx(int pdn_mux_id)
	{
		for (int i = 0; i < IPA_MAX_NUM_HW_PDNS ; ++i)
		{
			if (xlat_ctx.active_pdn_list[i].pdn_mux_id == pdn_mux_id)
			{
				xlat_ctx.active_pdn_list[i].pdn_mux_id = 0;
				xlat_ctx.active_pdn_count--;
				memset(xlat_ctx.active_pdn_list[i].associated_VIDs, 0, IPA_MAX_NUM_SW_PDNS * sizeof(xlat_ctx.active_pdn_list[i].associated_VIDs[0]));
				xlat_ctx.active_pdn_list[i].active_vlan_count = 0;
				IPACMDBG_H("Removing pdn from xlat ctx mux id %d total active xlat pdn:%d\n",
					pdn_mux_id, xlat_ctx.active_pdn_count);
				return;
			}
		}
		IPACMDBG_H("Pdn not found in ctx!\n");
	}

	inline int get_pdn_xlat_ctx(int pdn_mux_id, uint16_t vid)
	{
		for (int i = 0; i < IPA_MAX_NUM_HW_PDNS ; ++i)
		{
			if (xlat_ctx.active_pdn_list[i].pdn_mux_id == pdn_mux_id)
			{
				for (int j = 0; j < xlat_ctx.active_pdn_list[i].active_vlan_count; ++j)
				{
					if (vid == 0 || xlat_ctx.active_pdn_list[i].associated_VIDs[j] == vid) //vid == 0 means we care only for the mux id not the vlan
					{
						IPACMDBG_H("got xlat ctx %d for mux id %d, vid %d\n", i, pdn_mux_id, vid);
						return i;
					}
				}
			}
		}
		IPACMDBG_H("PDN not found in ctx for mux id %d, vid %d\n", pdn_mux_id, vid);
		return IPACM_FAILURE;
	}

#ifdef FEATURE_VLAN_MPDN
	inline bool is_any_mux_up(ipa_ip_type iptype)
	{
		ipacm_mux_struct *mux = v4_mux_up;
		bool res = false;

		if(iptype == IPA_IP_v6)
			mux = v6_mux_up;

		for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
		{
			if(mux[i].mux_id)
			{
				IPACMDBG("mux id %d up for dev %s, i = %d, iptype %d\n", mux[i].mux_id, dev_name, i, iptype);
				res = true;
			}
		}

		if(res)
			return res;

		IPACMDBG_H("no vlan mux up for dev %s, iptype %d\n", dev_name, iptype);
		return false;
	}
#endif

private:

	/* get hdr proc ctx type given source and destination l2 hdr type */
	ipa_hdr_proc_type eth_bridge_get_hdr_proc_type(ipa_hdr_l2_type t1,
		ipa_hdr_l2_type t2,
	struct ipa_eth_II_to_eth_II_ex_procparams &generic_params);

	/* get partial header (header template of hdr proc ctx) */
	int eth_bridge_get_hdr_template_hdl(uint32_t* hdr_hdl);


	/* dynamically allocate lan iface's unicast routing rule structure */

	bool is_mode_switch; /* indicate mode switch, need post internal up event */

	int eth_client_len;

	ipa_eth_client *eth_client;

	int header_name_count;

	int num_eth_client;

	NatApp *Nat_App;

	int ipv6_set;

	uint32_t ODU_hdr_hdl_v4, ODU_hdr_hdl_v6;

	uint32_t *odu_route_rule_v4_hdl;

	uint32_t *odu_route_rule_v6_hdl;

	bool ipv4_header_set;

	bool ipv6_header_set;

	bool is_l2tp_iface;

#ifdef FEATURE_L2TP
	uint32_t l2tp_ul_dummy_hdr_hdl; /* 4-byte dummy header */

	uint32_t l2tp_ul_hdr_proc_ctx_hdl;
#endif

#ifdef FEATURE_VLAN_MPDN

	typedef struct ipacm_mux_struct
	{
		uint8_t mux_id = 0;
		uint16_t associated_VIDs[IPA_MAX_NUM_HW_PDNS] = { };
		uint8_t VID_cnt = 0;
	}ipacm_mux_struct;

	ipacm_mux_struct v4_mux_up[IPA_MAX_NUM_HW_PDNS];
	uint8_t num_v4_mux;
	ipacm_mux_struct v6_mux_up[IPA_MAX_NUM_HW_PDNS];
	uint8_t num_v6_mux;

	inline bool is_mux_up(uint8_t mux_id, ipa_ip_type iptype, uint16_t vid)
	{
		ipacm_mux_struct *mux = v4_mux_up;

		if(mux_id == 0)
			return false;
		if(iptype == IPA_IP_v6)
			mux = v6_mux_up;

		for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
		{
			if(mux[i].mux_id == mux_id)
			{
				//vid = 0 means just check if mux is up
				if(vid == 0)
				{
						IPACMDBG_H("mux id %d is up for dev %s, iptype %d\n", mux_id, dev_name, iptype);
						return true;
				}

				//vlan case
				for(int j = 0; j < mux[i].VID_cnt; j++)
				{
					if(mux[i].associated_VIDs[j] == vid)
					{
						IPACMDBG_H("mux id %d is up for dev %s, iptype %d, vid %d, VID_cnt = %d\n", mux_id, dev_name, iptype, vid, mux[i].VID_cnt);
						return true;
					}
				}
			}
		}
		IPACMDBG_H("mux id %d is not up for dev %s iptype %d, vid %d\n", mux_id, dev_name, iptype, vid);
		return false;
	}

	inline int set_mux_down(uint8_t mux_id, ipa_ip_type iptype)
	{
		ipacm_mux_struct *mux = v4_mux_up;

		if(mux_id == 0)
		{
			IPACMERR("0 mux id!\n");
			return IPACM_FAILURE;
		}

		if(iptype == IPA_IP_v6)
			mux = v6_mux_up;

		for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
		{
			if(mux[i].mux_id == mux_id)
			{
				memset(&mux[i], 0, sizeof(mux[i]));
				IPACMDBG_H("successfully removed mux id %d for dev %s, i = %d, iptype %d, VID_cnt = %d\n", mux_id, dev_name, i, iptype, mux[i].VID_cnt);
				return IPACM_SUCCESS;
			}
		}

		IPACMERR("could not find mux %d, iptype %d\n", mux_id, iptype);
		return IPACM_FAILURE;
	}

#endif
	inline ipa_eth_client* get_client_memptr(ipa_eth_client *param, int cnt)
	{
	    char *ret = ((char *)param) + (eth_client_len * cnt);
		return (ipa_eth_client *)ret;
	}

	inline int get_eth_client_index(uint8_t *mac_addr, uint16_t vlan_id = 0)
	{
		int cnt;
		int num_eth_client_tmp = num_eth_client;

		IPACMDBG_H("Passed MAC %02x:%02x:%02x:%02x:%02x:%02x, left client: %d\n",
						 mac_addr[0], mac_addr[1], mac_addr[2],
						 mac_addr[3], mac_addr[4], mac_addr[5],
						 num_eth_client);

		for(cnt = 0; cnt < num_eth_client_tmp; cnt++)
		{
			IPACMDBG_H("stored MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
							 get_client_memptr(eth_client, cnt)->mac[0],
							 get_client_memptr(eth_client, cnt)->mac[1],
							 get_client_memptr(eth_client, cnt)->mac[2],
							 get_client_memptr(eth_client, cnt)->mac[3],
							 get_client_memptr(eth_client, cnt)->mac[4],
							 get_client_memptr(eth_client, cnt)->mac[5]);

			if(memcmp(get_client_memptr(eth_client, cnt)->mac,
								mac_addr,
								sizeof(get_client_memptr(eth_client, cnt)->mac)) == 0)
			{
#ifdef FEATURE_VLAN_MPDN
				if(vlan_id)
				{
					IPACMDBG("VLAN IF MAC match, looking for vlan ID %d, current %d\n", vlan_id,
						get_client_memptr(eth_client, cnt)->vlan_id);
					if(get_client_memptr(eth_client, cnt)->vlan_id == vlan_id)
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

	inline int get_eth_client_index_from_if_index(int if_index)
	{
		int cnt;
		int num_eth_client_tmp = num_eth_client;

		for(cnt = 0; cnt < num_eth_client_tmp; cnt++)
		{
			if(if_index == get_client_memptr(eth_client, cnt)->if_index)
			{
				IPACMDBG_H("if_index %d is used by client %d\n", if_index, cnt);
				return cnt;
			}
		}
		IPACMERR("could not find client with if_index %d\n", if_index);
		return IPACM_INVALID_INDEX;
	}

	inline int get_eth_client_ip4_addr(uint8_t *mac_addr, uint32_t &ip_addr, uint8_t vlan_id = 0)
	{
		int clnt_indx;

		clnt_indx = get_eth_client_index(mac_addr, vlan_id);
		if(clnt_indx == IPACM_INVALID_INDEX)
		{
			IPACMERR("eth client not found/attached \n");
			return IPACM_FAILURE;
		}

		if(get_client_memptr(eth_client, clnt_indx)->ipv4_set)
		{
			ip_addr = get_client_memptr(eth_client, clnt_indx)->v4_addr;
			IPACMDBG_H("ip addr is 0x%X\n", ip_addr);
			return IPACM_SUCCESS;
		}
		else
		{
			IPACMDBG_H("ipv4 address not set\n");
			return IPACM_FAILURE;
		}
	}

	inline int delete_eth_rtrules(int clt_indx, ipa_ip_type iptype)
	{
		uint32_t tx_index;
		uint32_t rt_hdl;
		int num_v6 = 0;

		if(iptype == IPA_IP_v4)
		{
		    for(tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
		    {
		        if((tx_prop->tx[tx_index].ip == IPA_IP_v4) && (get_client_memptr(eth_client, clt_indx)->route_rule_set_v4==true)) /* for ipv4 */
				{
					IPACMDBG_H("Delete client index %d ipv4 RT-rules for tx:%d\n",clt_indx,tx_index);
					rt_hdl = get_client_memptr(eth_client, clt_indx)->eth_rt_hdl[tx_index].eth_rt_rule_hdl_v4;

					if(m_routing.DeleteRoutingHdl(rt_hdl, IPA_IP_v4) == false)
					{
						return IPACM_FAILURE;
					}
				}
		    } /* end of for loop */

		     /* clean the ipv4 RT rules for eth-client:clt_indx */
		     if(get_client_memptr(eth_client, clt_indx)->route_rule_set_v4==true) /* for ipv4 */
		     {
				get_client_memptr(eth_client, clt_indx)->route_rule_set_v4 = false;
		     }
		}

		if(iptype == IPA_IP_v6)
		{
			IPACMDBG_H("Current %d client has %d ipv6 route_set %d,ipa_num_clients_ipv6:%d\n",
				clt_indx, get_client_memptr(eth_client, clt_indx)->ipv6_set,
				get_client_memptr(eth_client, clt_indx)->route_rule_set_v6,
					IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
			if (get_client_memptr(eth_client, clt_indx)->route_rule_set_v6 != 0)
			{
				for (auto it = rt_hdl_v6_list[clt_indx].begin(); it != rt_hdl_v6_list[clt_indx].end();++it)
				{
					num_v6 ++;
					if(it->second.route_rule_set_v6 == true)
					{
						IPACMDBG_H("v6 addr : 0x%08x:%08x:%08x:%08x\n",
							it->first[0], it->first[1], it->first[2], it->first[3]);

						for(tx_index = 0; tx_index < iface_query->num_tx_props; tx_index++)
						{
							if(tx_prop->tx[tx_index].ip == IPA_IP_v6) /* for ipv6 */
							{
								IPACMDBG_H("Delete client index %d ipv6 RT-rules for %d-st ipv6 for tx:%d\n", clt_indx,num_v6,tx_index);
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
						get_client_memptr(eth_client, clt_indx)->route_rule_set_v6 = 0;
					} /* end of route_rule_set_v6 */
				} /* end of for loop */
			}
			IPACMDBG_H("Current clnt-index:%d ipv6_set= %d, route_rule_set_v6= %d, update ipa_num_clients_ipv6:%d\n",
				clt_indx, get_client_memptr(eth_client, clt_indx)->ipv6_set,
				get_client_memptr(eth_client, clt_indx)->route_rule_set_v6,
				IPACM_Iface::ipacmcfg->ipa_num_clients_ipv6);
		}
		return IPACM_SUCCESS;
	}

	/* handle eth client initial, construct full headers (tx property) */
	int handle_eth_hdr_init(uint8_t *mac_addr,
		ipacm_bridge *bridge = NULL,
		uint16_t vlan_id = 0, bool isVlan = false);

	/* handle eth client ip-address */
	int handle_eth_client_ipaddr(ipacm_event_data_all *data);

	/* handle eth client routing rule*/
	int handle_eth_client_route_rule(uint8_t *mac_addr, ipa_ip_type iptype, uint16_t vlan_id = 0);

#ifdef FEATURE_STATIC_POLICY
	/* handle eth client PDN<->DSCP based routing rule addition*/
	int handle_pdn_dscp_eth_client_route_rule(uint8_t *mac_addr,
		ipa_ip_type iptype, uint32_t trigger, uint16_t vlan_id = 0,
		uint8_t mux_id = 0, uint8_t dscp_val = 0, uint32_t* ipv6_addr = 0);
#ifdef IPA_HW_FNR_STATS
	/* handle eth client PDN<->DSCP based routing rule addition when LAN Stats is enabled*/
	int handle_pdn_dscp_eth_client_route_rule_ext_v2(uint8_t *mac_addr,
		ipa_ip_type iptype, uint32_t trigger, uint32_t* ipv6_addr = 0,
		uint16_t vlan_id = 0, uint8_t mux_id = 0, uint8_t dscp_val = 0);
#endif //IPA_HW_FNR_STATS
	/* handle eth client PDN<->DSCP based routing rule deletion*/
	int delete_pdn_dscp_eth_rtrules(ipa_ip_type iptype,
		uint32_t trigger, int clnt_idx = -1, int mux_id = 0);
#endif //FEATURE_STATIC_POLICY

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	/* handle eth client routing rule with rule id*/
	int handle_eth_client_route_rule_ext(uint8_t *mac_addr, ipa_ip_type iptype);
#ifdef IPA_HW_FNR_STATS
	int handle_eth_client_route_rule_ext_v2(uint8_t *mac_addr, ipa_ip_type iptype, uint8_t dl_cnt_idx);
#endif //IPA_HW_FNR_STATS
#endif

	/*handle eth client del mode*/
	int handle_eth_client_down_evt(uint8_t *mac_addr, uint16_t vlan_id = 0, ipacm_event_data_all *data = NULL);

	/* handle odu client initial, construct full headers (tx property) */
	int handle_odu_hdr_init(uint8_t *mac_addr);

	/* handle odu default route rule configuration */
	int handle_odu_route_add();

	/* handle odu default route rule deletion */
	int handle_odu_route_del();

	/*handle lan iface down event*/
	int handle_down_evt();

	/*handle reset usb-client rt-rules */
	int handle_lan_client_reset_rt(ipa_ip_type iptype);

#ifdef FEATURE_L2TP
	/* install l2tp dl rules */
	int install_l2tp_dl_rules(ipacm_event_data_all *data, int index);

	/* install l2tp ul rules */
	int install_l2tp_ul_rules(ipacm_event_data_all *data, int index);

	/* uninstall l2tp rules */
	int uninstall_l2tp_rules(ipacm_event_data_all *data);

	/* install UL hdr proc ctx for L2TP E2E use case */
	int install_l2tp_ul_hdr_proc_ctx();
#endif
#ifdef FEATURE_VLAN_MPDN
	int handle_vlan_neighbor(ipacm_event_data_all *data);
#endif

	int construct_mtu_rule(struct ipa_flt_rule *rule, enum ipa_ip_type iptype, uint16_t mtu);

/* functions to handle eth client mac flt based filetring*/
	int handle_eth_mac_flt_event();
	void delete_eth_mac_flt_rules();
	int handle_eth_client_mac_flt_route_rule(ipa_ip_type iptype, int clt_index, bool is_blacklist);
	int handle_eth_mac_flt_conn_disc(uint8_t * mac_addr, bool con_state_flag);

public:  //mike why we have 2 public. Why not just move this on top?
#ifdef FEATURE_VLAN_MPDN
	int handle_vlan_phys_if_down();
	int check_vlan_PDNUp(enum ipa_ip_type iptype);
	bool is_vlan_IF(uint16_t vlan_id);
	int handle_vlan_pdn_up(ipacm_event_vlan_pdn *data, bool set_mux = true);
	int handle_vlan_pdn_down(ipacm_event_vlan_pdn *data);

	inline int set_mux_up(uint8_t mux_id, ipa_ip_type iptype, uint16_t vid)
	{
		ipacm_mux_struct *mux = v4_mux_up;

		if(mux_id == 0)
		{
			IPACMERR("0 mux id!\n");
			return IPACM_FAILURE;
		}

		if(is_mux_up(mux_id, iptype, vid))
		{
			IPACMERR("mux id %d is already up, not setting it iptype %d\n", mux_id,
				iptype);
			return IPACM_FAILURE;
		}

		if(iptype == IPA_IP_v6)
			mux = v6_mux_up;

		//check if mux_id was already added but need to add VLAN
		for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
		{
			if(mux[i].mux_id == mux_id)
			{
				for(int j = 0; j < mux[i].VID_cnt; j++)
				{
					if(mux[i].associated_VIDs[j] == 0)
					{
						mux[i].associated_VIDs[j] = vid;
						mux[i].VID_cnt++;
						mux[i].mux_id = mux_id;
						IPACMDBG_H("successfully added vid %d for mux id "
							"%d, dev %s, i = %d, j = %d, iptype %d, "
							"VID_cnt = %d\n", vid, mux_id, dev_name,
							i, j, iptype, mux[i].VID_cnt);
						return IPACM_SUCCESS;
					}
				}
			}
		}

		//Mux ID is new, add to the first open spot
		for(int i = 0; i < IPA_MAX_NUM_HW_PDNS; i++)
		{
			if(mux[i].mux_id == 0)
			{
				mux[i].associated_VIDs[0] = vid;
				mux[i].VID_cnt++;
				mux[i].mux_id = mux_id;
				IPACMDBG_H("successfully added mux id %d with vid %d, dev %s, "
					"i = %d, iptype %d, VID_cnt = %d\n",
					mux_id, vid, dev_name, i, iptype, mux[i].VID_cnt);
				return IPACM_SUCCESS;
			}
		}
		IPACMERR("exceeded max num mux ids, couldn't set mux %d, iptype %d, "
			"vid %d\n", mux_id, iptype, vid);
		return IPACM_FAILURE;
	}
#endif
	int delete_icmp_filter_rule(
		ipa_ip_type iptype);

	uint32_t get_u8_bitmap_from_tc(uint8_t traffic_class);
	int handle_qos_route_rule(uint8_t *client_mac, uint16_t vlan_id, ipa_ip_type iptype, list<qos_param_info>::iterator qos_param);
	int handle_qos_route_rule_ext_v2(uint8_t *client_mac, uint16_t vlan_id,
		ipa_ip_type iptype, list<qos_param_info>::iterator qos_param);
	int install_all_qos_route_rule(uint8_t * client_mac, uint16_t vlan_id);
	int if_client_qos_rule_needed(uint8_t *client_mac, uint16_t vlan_id, list<qos_param_info>::iterator qos_param);
	int delete_client_qos_rule(uint8_t *client_mac, uint16_t vlan_id);
	int delete_client_info_from_qos(uint8_t *client_mac, uint16_t vlan_id, list<qos_param_info>::iterator qos_param);
	int delete_all_client_qos_rules();
	int delete_all_client_info_from_qos(list<qos_param_info>::iterator qos_param);
};

#endif /* IPACM_LAN_H */
