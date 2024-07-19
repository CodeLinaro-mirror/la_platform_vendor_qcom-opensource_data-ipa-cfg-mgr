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
		IPACM_Config.cpp

		@brief
		This file implements the IPACM Configuration from XML file

		@Author
		Skylar Chang

*/
#include <IPACM_Config.h>
#include <IPACM_Log.h>
#include <IPACM_Netlink.h>
#include <IPACM_Iface.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

IPACM_Config *IPACM_Config::pInstance = NULL;
const char *IPACM_Config::DEVICE_NAME = "/dev/ipa";
const char *IPACM_Config::DEVICE_NAME_ODU = "/dev/odu_ipa_bridge";

#define __stringify(x...) #x

#ifdef FEATURE_IPA_ANDROID
#define IPACM_CONFIG_FILE "/etc/IPACM_cfg.xml"
#else
#define IPACM_CONFIG_FACTORY_FILE "/etc/data/ipa/factory_IPACM_cfg.xml"
#define IPACM_CONFIG_FILE "/etc/data/ipa/IPACM_cfg.xml"
#define IPACM_CONFIG_EXT_FILE "/etc/data/ipa/IPACM_cfg_ext.xml"
#endif
#define MAX_RETRIES 5
const char *ipacm_event_name[] = {
	__stringify(IPA_CFG_CHANGE_EVENT),                     /* NULL */
	__stringify(IPA_PRIVATE_SUBNET_CHANGE_EVENT),          /* ipacm_event_data_fid */
	__stringify(IPA_FIREWALL_CHANGE_EVENT),                /* NULL */
	__stringify(IPA_LINK_UP_EVENT),                        /* ipacm_event_data_fid */
	__stringify(IPA_LINK_DOWN_EVENT),                      /* ipacm_event_data_fid */
	__stringify(IPA_USB_LINK_UP_EVENT),                    /* ipacm_event_data_fid */
	__stringify(IPA_BRIDGE_LINK_UP_EVENT),                 /* ipacm_event_data_all */
	__stringify(IPA_WAN_EMBMS_LINK_UP_EVENT),              /* ipacm_event_data_mac */
	__stringify(IPA_ADDR_ADD_EVENT),                       /* ipacm_event_data_addr */
	__stringify(IPA_ADDR_DEL_EVENT),                       /* no use */
	__stringify(IPA_ROUTE_ADD_EVENT),                      /* ipacm_event_data_addr */
	__stringify(IPA_ROUTE_DEL_EVENT),                      /* ipacm_event_data_addr */
	__stringify(IPA_WAN_UPSTREAM_ROUTE_ADD_EVENT),         /* ipacm_event_data_fid */
	__stringify(IPA_WAN_UPSTREAM_ROUTE_DEL_EVENT),         /* ipacm_event_data_fid */
	__stringify(IPA_WLAN_AP_LINK_UP_EVENT),                /* ipacm_event_data_mac */
	__stringify(IPA_WLAN_STA_LINK_UP_EVENT),               /* ipacm_event_data_mac */
	__stringify(IPA_WLAN_LINK_DOWN_EVENT),                 /* ipacm_event_data_mac */
	__stringify(IPA_WLAN_CLIENT_ADD_EVENT),                /* ipacm_event_data_mac */
	__stringify(IPA_WLAN_CLIENT_ADD_EVENT_EX),             /* ipacm_event_data_wlan_ex */
	__stringify(IPA_WLAN_CLIENT_DEL_EVENT),                /* ipacm_event_data_mac */
	__stringify(IPA_WLAN_CLIENT_POWER_SAVE_EVENT),         /* ipacm_event_data_mac */
	__stringify(IPA_WLAN_CLIENT_RECOVER_EVENT),            /* ipacm_event_data_mac */
	__stringify(IPA_NEW_NEIGH_EVENT),                      /* ipacm_event_data_all */
	__stringify(IPA_DEL_NEIGH_EVENT),                      /* ipacm_event_data_all */
	__stringify(IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT),       /* ipacm_event_data_all */
	__stringify(IPA_NEIGH_CLIENT_IP_ADDR_DEL_EVENT),       /* ipacm_event_data_all */
	__stringify(IPA_SW_ROUTING_ENABLE),                    /* NULL */
	__stringify(IPA_SW_ROUTING_DISABLE),                   /* NULL */
	__stringify(IPA_PROCESS_CT_MESSAGE),                   /* ipacm_ct_evt_data */
	__stringify(IPA_PROCESS_CT_MESSAGE_V6),                /* ipacm_ct_evt_data */
	__stringify(IPA_LAN_TO_LAN_NEW_CONNECTION),            /* ipacm_event_connection */
	__stringify(IPA_LAN_TO_LAN_DEL_CONNECTION),            /* ipacm_event_connection */
	__stringify(IPA_WLAN_SWITCH_TO_SCC),                   /* No Data */
	__stringify(IPA_WLAN_SWITCH_TO_MCC),                   /* No Data */
	__stringify(IPA_WLAN_SWITCH_VLAN_MODE),                /* ipacm_event_vlan_mode */
	__stringify(IPA_CRADLE_WAN_MODE_SWITCH),               /* ipacm_event_cradle_wan_mode */
	__stringify(IPA_TETHERING_STATS_UPDATE_EVENT),         /* ipacm_event_data_fid */
	__stringify(IPA_NETWORK_STATS_UPDATE_EVENT),           /* ipacm_event_data_fid */
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	__stringify(IPA_LAN_CLIENT_CONNECT_EVENT),             /* ipacm_event_data_mac */
	__stringify(IPA_LAN_CLIENT_DISCONNECT_EVENT),          /* ipacm_event_data_mac */
	__stringify(IPA_LAN_CLIENT_UPDATE_EVENT),              /* ipacm_event_data_mac */
#endif
	__stringify(IPA_EXTERNAL_EVENT_MAX),
	__stringify(IPA_HANDLE_WAN_UP),                        /* ipacm_event_iface_up  */
	__stringify(IPA_HANDLE_WAN_DOWN),                      /* ipacm_event_iface_up  */
	__stringify(IPA_HANDLE_WAN_UP_V6),                     /* NULL */
	__stringify(IPA_HANDLE_WAN_DOWN_V6),                   /* NULL */
	__stringify(IPA_HANDLE_WAN_UP_TETHER),                 /* ipacm_event_iface_up_tehter */
	__stringify(IPA_HANDLE_WAN_DOWN_TETHER),               /* ipacm_event_iface_up_tehter */
	__stringify(IPA_HANDLE_WAN_UP_V6_TETHER),              /* ipacm_event_iface_up_tehter */
	__stringify(IPA_HANDLE_WAN_DOWN_V6_TETHER),            /* ipacm_event_iface_up_tehter */
	__stringify(IPA_HANDLE_WAN_ADDR_ADD_V6),               /* ipacm_event_iface_up */
	__stringify(IPA_HANDLE_LAN_WLAN_UP),                   /* ipacm_event_iface_up */
	__stringify(IPA_HANDLE_LAN_WLAN_UP_V6),                /* ipacm_event_iface_up */
	__stringify(IPA_ETH_BRIDGE_IFACE_UP),                  /* ipacm_event_eth_bridge*/
	__stringify(IPA_ETH_BRIDGE_IFACE_DOWN),                /* ipacm_event_eth_bridge*/
	__stringify(IPA_ETH_BRIDGE_CLIENT_ADD),                /* ipacm_event_eth_bridge*/
	__stringify(IPA_ETH_BRIDGE_CLIENT_DEL),                /* ipacm_event_eth_bridge*/
	__stringify(IPA_ETH_BRIDGE_WLAN_SCC_MCC_SWITCH),       /* ipacm_event_eth_bridge*/
#ifdef FEATURE_VLAN_MPDN
	__stringify(IPA_ETH_BRIDGE_ADD_VLAN_ID),               /* ipacm_event_eth_bridge*/
	__stringify(IPA_ETH_BRIDGE_DEL_VLAN_ID),               /* ipacm_event_eth_bridge*/
#endif
	__stringify(IPA_LAN_DELETE_SELF),                      /* ipacm_event_data_fid */
#ifdef IPA_MTU_EVENT_MAX
	__stringify(IPA_MTU_SET),                              /* ipa_mtu_info */
	__stringify(IPA_MTU_UPDATE),                           /* ipacm_event_mtu_info */
#endif
#ifdef FEATURE_L2TP
	__stringify(IPA_ADD_L2TP_CLIENT),                      /* ipacm_event_data_all */
	__stringify(IPA_DEL_L2TP_CLIENT),                      /* ipacm_event_data_all */
#endif
#ifdef FEATURE_VLAN_MPDN
	__stringify(IPA_PREFIX_CHANGE_EVENT),                  /* ipacm_event_data_fid */
	__stringify(IPA_ROUTE_ADD_VLAN_PDN_EVENT),             /* ipacm_event_route_vlan */
	__stringify(IPA_HANDLE_WAN_VLAN_PDN_UP),               /* ipacm_event_vlan_pdn */
	__stringify(IPA_HANDLE_WAN_VLAN_PDN_DOWN),             /* ipacm_event_vlan_pdn */
	__stringify(IPA_NOTIFY_VLAN_UP),                       /* NULL */
#endif
#ifdef FEATURE_SOCKSv5
	__stringify(IPA_HANDLE_SOCKSv5_UP),                    /* ipacm_event_connection */
	__stringify(IPA_HANDLE_SOCKSv5_READY),                 /* ipacm_event_connection */
	__stringify(IPA_HANDLE_SOCKSv5_DOWN),                  /* NULL */
	__stringify(IPA_ADD_SOCKSv5_CONN),                     /* ipa_socksv5_msg */
	__stringify(IPA_DEL_SOCKSv5_CONN),                     /* ipa_socksv5_msg */
	__stringify(IPA_UPDATE_SOCKSv5_CONN),                  /* NULL */
#endif
	__stringify(IPA_MAC_ADD_DEL_FLT_EVENT),                /* ipacm_event_data_mac */
	__stringify(IPA_IP_COLLISION_UPDATE_EVENT),          /* ipacm_ip_collision_pdn_info */
	__stringify(IPA_IP_PASS_UPDATE_EVENT),          /* ipacm_ip_pass_pdn_info */
	__stringify(IPA_HANDLE_IP_PASS_PDN_INFO_UPDATE_EVENT),         /* Handle PDN info update.*/
#ifdef IPA_IOCTL_SET_PKT_THRESHOLD
	__stringify(IPA_PKT_THRESHOLD_UPDATE_EVENT),           /* ipa_set_pkt_threshold */
#endif
#ifdef IPA_IOC_SET_IPPT_SW_FLT
	__stringify(IPA_IPPT_SW_FLT_LIST_UPDATE_EVENT),        /* ipa_ippt_sw_flt_list_type */
#endif
	__stringify(IPA_MOVE_NAT_TBL_EVENT),                   /* ipacm_event_move_nat */
#ifdef FEATURE_EoGRE
	__stringify(IPA_HANDLE_EoGRE_UP),                      /* Handle eogre enable event. */
	__stringify(IPA_HANDLE_EoGRE_DOWN),                    /* Handle eogre disable event. */
#endif
	__stringify(IPA_DSCP_PCP_CONFIG_CHANGE_EVENT),         /* NULL */
	__stringify(IPA_HANDLE_MACSEC_ADD),                    /* Handle macsec map add event */
	__stringify(IPA_HANDLE_MACSEC_DEL),                    /* Handle macsec map delete event */
	__stringify(IPA_ADD_BRIDGE_VLAN_PHY_INTF),             /* Handle vlan details add for physical interface.  */
	__stringify(IPA_ADD_BRIDGE_VLAN_BR_INTF),              /* Handle vlan-bridge details add for bridge interface. */
	__stringify(IPA_ADD_EXT_ROUTER_RULES),                 /* Handle ext_route add event */
	__stringify(IPA_DEL_EXT_ROUTER_RULES),                 /* Handle ext_route del event */
	__stringify(IPA_IPACM_DISABLE),                       /* handle ipacm_disable event */
	__stringify(IPA_LAN_CLIENT_ADD_EVENT),                /* ipa lan2lan offload for static ip */
	__stringify(IPA_LAN_CLIENT_DEL_EVENT),                /* ipa lan2lan offload for static ip */
#ifdef FEATURE_IPA_IPSEC
	__stringify(IPA_HANDLE_IPSEC_UL_FLT_ADD),              /* Handle IPsec UL policy flt add */
	__stringify(IPA_HANDLE_IPSEC_UL_FLT_DEL),              /* Handle IPsec UL policy flt delete */
	__stringify(IPA_IPSEC_LAN_CLIENT_ROUTE_ADD_EVENT),     /* Internal event for a new LAN client route */
#endif
	__stringify(IPA_QOS_RULE_ADD_EVENT),                   /* ipacm_qos_rule_add_event */
	__stringify(IPA_QOS_RULE_DEL_EVENT),                   /* ipacm_qos_rule_del_event */
	__stringify(IPA_QOS_RULE_FLUSH_EVENT),                 /* ipacm_qos_rule_flush_event */
	__stringify(IPACM_EVENT_MAX)
};

IPACM_Config::IPACM_Config()
{
	iface_table = NULL;
	alg_table = NULL;
	pNatIfaces = NULL;
	memset(&ipa_client_rm_map_tbl, 0, sizeof(ipa_client_rm_map_tbl));
	memset(&ipa_rm_tbl, 0, sizeof(ipa_rm_tbl));
	ipa_rm_a2_check=0;
	ipacm_odu_enable = false;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	ipacm_lan_stats_enable = false;
	ipacm_lan_stats_enable_set = false;
	pthread_mutex_init(&stats_client_info_lock, NULL);
#ifdef IPA_HW_FNR_STATS
	memset(&fnr_counters, 0, sizeof(fnr_counters));
	memset(cnt_idx, 0, sizeof(cnt_idx));
	hw_fnr_stats_support = false;
	pthread_mutex_init(&cnt_idx_lock, NULL);
#endif //IPA_HW_FNR_STATS
#endif
	ipv6_nat_enable = false;
	ipacm_odu_router_mode = false;
	ipa_num_wlan_guest_ap = 0;

	ipa_num_ipa_interfaces = 0;
	ipa_num_private_subnet = 0;
	ipa_num_alg_ports = 0;
	ipa_nat_memtype = DEFAULT_NAT_MEMTYPE;
	ipa_nat_max_entries = 0;
	ipa_ipv6ct_max_entries = 0;
	ipa_nat_iface_entries = 0;
	ipa_sw_rt_enable = false;
	ipa_bridge_enable = false;
	ipa_num_clients_ipv6 = 0;
	isMCC_Mode = false;
	ipa_max_valid_rm_entry = 0;
	ipacm_l2tp_enable = 0;
	ipacm_mpdn_enable = TRUE;   /* default setting as mpdn enable/l2tp disable */
	ipacm_socksv5_enable = false;
	ipacm_flt_enable = 0;
	ipacm_qos_enable = false;

	memset(&rt_tbl_default_v4, 0, sizeof(rt_tbl_default_v4));
	memset(&rt_tbl_lan_v4, 0, sizeof(rt_tbl_lan_v4));
	memset(&rt_tbl_wan_v4, 0, sizeof(rt_tbl_wan_v4));
	memset(&rt_tbl_v6, 0, sizeof(rt_tbl_v6));
	memset(&rt_tbl_wan_v6, 0, sizeof(rt_tbl_wan_v6));
	memset(&rt_tbl_wan_dl, 0, sizeof(rt_tbl_wan_dl));
	memset(&rt_tbl_odu_v4, 0, sizeof(rt_tbl_odu_v4));
	memset(&rt_tbl_odu_v6, 0, sizeof(rt_tbl_odu_v6));

	memset(&ext_prop_v4, 0, sizeof(ext_prop_v4));
	memset(&ext_prop_v6, 0, sizeof(ext_prop_v6));

	qmap_id = ~0;

	memset(flt_rule_count_v4, 0, IPA_CLIENT_MAX*sizeof(int));
	memset(flt_rule_count_v6, 0, IPA_CLIENT_MAX*sizeof(int));
	memset(bridge_mac, 0, IPA_MAC_ADDR_SIZE*sizeof(uint8_t));
#if defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
	socksv5_v4_pdn = 0;
	socksv5_v6_pdn = 0;
	total_pdn_ipv6_in_use = 0;
	memset(socksv5_client_v6_addr, 0, 4*sizeof(uint32_t));
	memset(pdn_ipv4, 0, IPA_MAX_NUM_HW_PDNS*sizeof(int));
	memset(pdn_ipv6, 0, IPA_MAX_NUM_HW_PDNS*4*sizeof(int));
	memset(pdn_ipv6_in_use, 0, IPA_MAX_NUM_HW_PDNS*sizeof(int));
#endif //defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_ADD)
#ifdef FEATURE_VLAN_MPDN
	num_ipv6_prefixes = 0;
	num_no_offload_ipv6_prefix = 0;
	memset(ipa_ipv6_prefixes, 0, sizeof(ipa_ipv6_prefixes));
	memset(ipa_no_offload_ipv6_prefixes, 0, sizeof(ipa_no_offload_ipv6_prefixes));
	memset(vlan_bridges, 0, IPA_MAX_NUM_BRIDGES * sizeof(vlan_bridges[0]));
	memset(vlan_devices, 0, IPA_VLAN_IF_MAX * sizeof(vlan_devices[0]));
	memset(ip_pass_mpdn_table, 0, sizeof(ip_pass_mpdn_table));
#ifdef FEATURE_STATIC_POLICY
	memset(pdn_dscp_table, 0, sizeof(pdn_dscp_table));
	for(int i = 0; i<IPA_UC_MAX_PDN_DSCP_VAL;i++)
	{
		pdn_dscp_table[i].dscp_val = 255;
	}
	pthread_mutex_init(&pdn_dscp_lock, NULL);
#endif
	memset(&sw_flt_list, 0, sizeof(ipa_sw_flt_list_type));

	pthread_mutex_init(&ip_pass_mpdn_lock, NULL);
#endif
#if defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
	pthread_mutex_init(&vlan_l2tp_lock, NULL);
#endif
	pthread_mutex_init(&nat_iface_lock, NULL);
	pthread_mutex_init(&qos_param_list_lock, NULL);
	pthread_mutex_init(&qos_param_list_lock, NULL);
	IPACMDBG_H(" create IPACM_Config constructor\n");
	pthread_mutex_init(&mac_flt_info_lock, NULL);
#ifdef FEATURE_EoGRE
	memset(&eogre_info, 0, sizeof(eogre_info));
	eogre_enabled = false;
	eogre_tunnel_name[0] = '\0';
	v6options_enabled = false;
#endif
#ifdef FEATURE_DUAL_BACKHAUL
	memset(&second_backhaul_info,0,sizeof(second_backhaul_info));
#endif
	ext_router_mode = IPA_PREFIX_DISABLED;

	/* Clear the DSCP PCP mapping data during init */
	memset(&dscp_pcp_config, 0,
			sizeof(IPACM_dscp_pcp_conf_t));
	memset(&dscp_pcp_config_cache, 0,
			sizeof(IPACM_dscp_pcp_conf_t));

	strlcpy(IPACM_config_ext_file, IPACM_CONFIG_EXT_FILE, sizeof(IPACM_config_ext_file));
	IPACMDBG_H("\n IPACM CFG EXT XML file is %s \n", IPACM_config_ext_file);
	if (IPACM_SUCCESS == IPACM_read_cfg_ext_xml(IPACM_config_ext_file, &dscp_pcp_config))
	{
		IPACMDBG_H("\n IPACM XML EXT read OK \n");
	}
	else
	{
		IPACMERR("Config EXT (DSCP-PCP) XML read failed\n");
	}

	return;
}

#if defined(FEATURE_IPACM_PER_CLIENT_STATS) && defined(IPA_HW_FNR_STATS)
static int ipacm_fnr_v2_ioctl(const int fd, unsigned int request, void *arg)
{
	if (!fd) {
		IPACMERR("Invalid fd!\n");
		return -EFAULT;
	}
	return ioctl(fd, request, arg);
}

static void dump_fnr_counters(const struct ipa_ioc_flt_rt_counter_alloc *fnr)
{
	if (!fnr)
		return;
	IPACMERR("hw hdl = %d\n"
		"hw_num_counters = %hhu\n"
		"hw_start_id = %hhu\n, hw_allow_less = %hhu\n",
		fnr->hdl, fnr->hw_counter.num_counters, fnr->hw_counter.allow_less,
		fnr->hw_counter.start_id);
	IPACMERR("sw hdl = %d\n"
		"sw_num_counters = %hhu\n"
		"sw_start_id = %hhu\n, sw_allow_less = %hhu\n",
		fnr->hdl, fnr->sw_counter.num_counters, fnr->sw_counter.allow_less,
		fnr->sw_counter.start_id);
}

int IPACM_Config::get_free_cnt_idx(void)
{
	int i;

	for (i=0; i < IPA_MAX_FLT_RT_CLIENTS; i++) {
		if (cnt_idx[i].in_use ==  false) {
			cnt_idx[i].in_use = true;
			/* reset the counter index and counter index + 1 before sending it to client */
			ipacm_reset_hw_fnr_counters(cnt_idx[i].counter_index, cnt_idx[i].counter_index + 1);
			IPACMDBG_H("Returned free index = %d\n", cnt_idx[i].counter_index);
			return cnt_idx[i].counter_index;
		}
	}
	IPACMERR("No free/unused index found.\n");
	return IPACM_FAILURE;
}

int IPACM_Config::ipacm_reset_hw_fnr_counters(const uint8_t start_id, const uint8_t end_id)
{
	struct ipa_ioc_flt_rt_query *query;
	int ret = IPACM_SUCCESS;
	int num_counters, i;

	int fd = open(DEVICE_NAME, O_RDWR);

	if (fd < 0) {
		IPACMERR("fnr: Failed to open /dev/ipa\n");
		return IPACM_FAILURE;
	}
	query = (struct ipa_ioc_flt_rt_query *)malloc(sizeof(struct ipa_ioc_flt_rt_query));
	if (!query)
	{
		IPACMERR("Failed to allocate memory for fnr query\n");
		ret = -ENOMEM;
		goto fail;
	}

	/* Create a query with required params */
	query->start_id = start_id;
	query->end_id = end_id;
	query->reset = false;
	query->stats_size = sizeof(struct ipa_flt_rt_stats);
	num_counters = end_id - start_id + 1;

	query->stats = (uint64_t)calloc(num_counters, query->stats_size);
	if (!query->stats) {
		IPACMERR("fnr : Failed to allocate memory for query stats\n");
		free(query);
		ret = IPACM_FAILURE;
		goto fail;
	}
	/* For now just query the stats and print it here */
	if (fd  >= 0)
	{
		ret = ipacm_fnr_v2_ioctl(fd, IPA_IOC_FNR_COUNTER_QUERY, query);
		if (ret < 0)
			IPACMERR("IOCTL %lu failed\n", IPA_IOC_FNR_COUNTER_QUERY);
	}

	free(query);
fail:
	close(fd);
	return ret;
}

/**
 * @param in: index : The counter index ranging between 0-127
 * This is expected to be , i.e. UL index
 * UL % 2 == 0
 * DL = UL + 1
 */
int IPACM_Config::reset_cnt_idx(int index, bool reset_all)
{
	int i;

	if (reset_all) {
		for (i = 0; i < IPA_MAX_FLT_RT_CLIENTS; i++)
			cnt_idx[i].in_use = false;
		ipacm_reset_hw_fnr_counters(fnr_counters.hw_counter.start_id,
			fnr_counters.hw_counter.start_id +
				fnr_counters.hw_counter.num_counters - 1);
	}else {
		for (i = 0; i <  IPA_MAX_FLT_RT_CLIENTS; i++) {
			if (cnt_idx[i].counter_index == index &&
				cnt_idx[i].in_use) {
				cnt_idx[i].in_use = false;
				ipacm_reset_hw_fnr_counters(index, index + 1);
			}
		}
	}
	return IPACM_SUCCESS;
}

int IPACM_Config::ipacm_alloc_fnr_counters(struct ipa_ioc_flt_rt_counter_alloc *fnr_counters, const int fd)
{
	int i, ret = 0;
	int nfd = open(DEVICE_NAME, O_RDWR);
	int counter_idx;

	if (nfd < 0) {
		IPACMERR("fnr: error opening device file\n");
		return IPACM_FAILURE;
	}

	fnr_counters->hw_counter.num_counters = IPA_MAX_FLT_RT_CLIENTS * 2;
	fnr_counters->hw_counter.allow_less = false;

	IPACMDBG_H("Allocating %d counters, with start id %d\n", fnr_counters->hw_counter.num_counters,
		fnr_counters->hw_counter.start_id);
	/* reset all the counters after allocation */
	ret = ipacm_fnr_v2_ioctl(nfd, IPA_IOC_FNR_COUNTER_ALLOC, fnr_counters);
	if (ret < 0)
	{
		IPACMERR("Failed to execute ioctl %lu\n", IPA_IOC_FNR_COUNTER_ALLOC);
		goto bail;
	}

	IPACMDBG_H("Reset counters after allocation, start %u %u\n",
			fnr_counters->hw_counter.start_id, fnr_counters->hw_counter.start_id + fnr_counters->hw_counter.num_counters - 1);
	if (ipacm_reset_hw_fnr_counters(fnr_counters->hw_counter.start_id, fnr_counters->hw_counter.start_id + fnr_counters->hw_counter.num_counters - 1))
	{
		IPACMERR("Failed to reset hw counters, should return fail here\n");
	} else
		IPACMDBG_H("counter reset done\n");

	IPACMERR("Fnr counters allocated. Ret = %d, start id = %u\n", ret, fnr_counters->hw_counter.start_id);
	counter_idx = fnr_counters->hw_counter.start_id;
	memset(cnt_idx, 0xff, sizeof(cnt_idx));
	if (counter_idx == 0) {
			IPACMERR("Invalid counter id %u\n", counter_idx);
			ret = IPACM_FAILURE;
			goto bail;
	}
	for (i = 0; i < IPA_MAX_FLT_RT_CLIENTS; i++) {
		if (counter_idx > (fnr_counters->hw_counter.start_id + fnr_counters->hw_counter.num_counters)) {
			IPACMERR("Counter index not in range. Invalid start id %u, requested counters = %u\n",
				fnr_counters->hw_counter.start_id, fnr_counters->hw_counter.num_counters);
			memset(cnt_idx, 0xff, sizeof(cnt_idx));
			ret = IPACM_FAILURE;
			goto bail;
		}
		cnt_idx[i].in_use = false;
		cnt_idx[i].counter_index = counter_idx;
		counter_idx += 2;
	}
bail:
	close(nfd);
	return ret;
}

#endif //IPA_HW_FNR_STATS

int IPACM_Config::Init(void)
{
	static bool already_reset = false;
	/* Read IPACM Config file */
	char	IPACM_config_file[IPA_MAX_FILE_LEN];
	IPACM_conf_t	*cfg;
	uint8_t loop_count = 0;
	char cmd[200] = {'\0'};

	cfg = (IPACM_conf_t *)malloc(sizeof(IPACM_conf_t));
	if(cfg == NULL)
	{
		IPACMERR("Unable to allocate cfg memory.\n");
		return IPACM_FAILURE;
	}
	uint32_t subnet_addr;
	int i, ret = IPACM_SUCCESS;
	struct in_addr in_addr_print;

	m_fd = open(DEVICE_NAME, O_RDWR);
	if (0 > m_fd)
	{
		IPACMERR("Failed opening %s.\n", DEVICE_NAME);
	}

	ver = GetIPAVer(true);

	if ( ! already_reset )
	{
		if ( ResetClkVote() == 0 )
		{
			already_reset = true;
		}
	}
#ifdef FEATURE_VLAN_MPDN
	get_vlan_mode_ifaces();
#endif

	snprintf(cmd, 200,"cat " IPACM_CONFIG_FACTORY_FILE ">" IPACM_CONFIG_FILE);
	strlcpy(IPACM_config_file, IPACM_CONFIG_FILE, sizeof(IPACM_config_file));

	IPACMDBG_H("\n IPACM XML file is %s \n", IPACM_config_file);

reread:
	if (IPACM_SUCCESS == ipacm_read_cfg_xml(IPACM_config_file, cfg))
	{
		IPACMDBG_H("\n IPACM XML read OK \n");
	}
	else
	{
		if(loop_count < MAX_RETRIES) {
			IPACMERR("\nIPACM XML read failed,Updating the xml file\n");
			system(cmd);
			loop_count++;
			goto reread;
		}
		else {
			IPACMERR("Reached max count exiting\n");
			ret = IPACM_FAILURE;
			goto fail;
		}
	}

	/* Construct IPACM Iface table */
	ipa_num_ipa_interfaces = cfg->iface_config.num_iface_entries;
	if (iface_table != NULL)
	{
		free(iface_table);
		iface_table = NULL;
		IPACMDBG_H("RESET IPACM_Config::iface_table\n");
	}
	iface_table = (ipa_ifi_dev_name_t *)calloc(ipa_num_ipa_interfaces,
					sizeof(ipa_ifi_dev_name_t));
	if(iface_table == NULL)
	{
		IPACMERR("Unable to allocate iface_table memory.\n");
		ret = IPACM_FAILURE;
		goto fail;
	}

	for (i = 0; i < cfg->iface_config.num_iface_entries; i++)
	{
		strlcpy(iface_table[i].iface_name, cfg->iface_config.iface_entries[i].iface_name, sizeof(iface_table[i].iface_name));
		if (iface_table[i].virtual_iface = cfg->iface_config.iface_entries[i].virtual_iface) {
			strlcpy(iface_table[i].phy_dev_name, cfg->iface_config.iface_entries[i].phy_dev_name, sizeof(iface_table[i].phy_dev_name));
		}
		iface_table[i].if_cat = cfg->iface_config.iface_entries[i].if_cat;
		iface_table[i].if_mode = cfg->iface_config.iface_entries[i].if_mode;
		iface_table[i].wlan_mode = cfg->iface_config.iface_entries[i].wlan_mode;
		IPACMDBG_H("IPACM_Config::iface_table[%d] = %s, phy= %s, cat=%d, mode=%d wlan-mode=%d \n",
			i, iface_table[i].iface_name, iface_table[i].phy_dev_name,
			iface_table[i].if_cat, iface_table[i].if_mode, iface_table[i].wlan_mode);
		/* copy bridge interface name to ipacmcfg */
		if( iface_table[i].if_cat == VIRTUAL_IF)
		{
#ifdef FEATURE_RDKB
			strlcpy(iface_table[i].iface_name, DEFAULT_BRIDGE_IFACE_NAME, sizeof(iface_table[i].iface_name));
#endif
			strlcpy(ipa_virtual_iface_name, iface_table[i].iface_name, sizeof(ipa_virtual_iface_name));
			IPACMDBG_H("ipa_virtual_iface_name(%s) \n", ipa_virtual_iface_name);
		}
	}


	/* Construct IPACM ALG table */
	ipa_num_alg_ports = cfg->alg_config.num_alg_entries;
	if (alg_table != NULL)
	{
		free(alg_table);
		alg_table = NULL;
		IPACMDBG_H("RESET IPACM_Config::alg_table \n");
	}
	alg_table = (ipacm_alg *)calloc(ipa_num_alg_ports,
				sizeof(ipacm_alg));
	if(alg_table == NULL)
	{
		IPACMERR("Unable to allocate alg_table memory.\n");
		ret = IPACM_FAILURE;
		free(iface_table);
		goto fail;;
	}
	for (i = 0; i < cfg->alg_config.num_alg_entries; i++)
	{
		alg_table[i].protocol = cfg->alg_config.alg_entries[i].protocol;
		alg_table[i].port = cfg->alg_config.alg_entries[i].port;
		IPACMDBG_H("IPACM_Config::ipacm_alg[%d] = %d, port=%d\n", i, alg_table[i].protocol, alg_table[i].port);
	}

	ipa_nat_max_entries = cfg->nat_max_entries;
	IPACMDBG_H("Nat Maximum Entries %d\n", ipa_nat_max_entries);

	ipa_nat_memtype =
		(cfg->nat_table_memtype) ?
		cfg->nat_table_memtype   : DEFAULT_NAT_MEMTYPE;
	IPACMDBG_H("Nat Mem Type %s\n", ipa_nat_memtype);

	if (cfg->ipv6ct_enable > 0)
	{
		ipa_ipv6ct_max_entries = (cfg->ipv6ct_max_entries > 0) ? cfg->ipv6ct_max_entries : DEFAULT_IPV6CT_MAX_ENTRIES;
		IPACMDBG_H("IPv6CT Maximum Entries %d\n", ipa_ipv6ct_max_entries);

		ipa_ct_memtype =
			(cfg->ct_table_memtype) ?
			cfg->ct_table_memtype   : DEFAULT_CT_MEMTYPE;
		IPACMDBG_H("Ct Mem Type %s\n", ipa_ct_memtype);
	}
	else
	{
#ifdef FEATURE_IPV6_NAT
		if(cfg->ipv6_nat_enable)
		{
			ipa_ipv6ct_max_entries = (cfg->ipv6ct_max_entries > 0) ? cfg->ipv6ct_max_entries : DEFAULT_IPV6CT_MAX_ENTRIES;
			IPACMDBG_H("IPv6CT enabled due to ipv6nat\n");
		}
		else
#endif
		{
			ipa_ipv6ct_max_entries = 0;
			IPACMDBG_H("IPv6CT is disabled\n");
		}
	}

	/* Find ODU is either router mode or bridge mode*/
	ipacm_odu_enable = cfg->odu_enable;
	ipacm_odu_router_mode = cfg->router_mode_enable;
	ipacm_odu_embms_enable = cfg->odu_embms_enable;
	IPACMDBG_H("ipacm_odu_enable %d\n", ipacm_odu_enable);
	IPACMDBG_H("ipacm_odu_mode %d\n", ipacm_odu_router_mode);
	IPACMDBG_H("ipacm_odu_embms_enable %d\n", ipacm_odu_embms_enable);

	/* Get the Public IP suppport config info from XML */
	is_public_ip_support_enabled = cfg->public_ip_support_enable;
	IPACMDBG_H("Public IP support config %d\n", is_public_ip_support_enabled);

	/* Get the VLAN MPDN suppport config info from XML */
	wlan_vlan_mpdn_enabled = cfg->wlan_vlan_mpdn_enable;
	IPACMDBG_H("VLAN MPDN support config %d\n", wlan_vlan_mpdn_enabled);

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	if (!ipacm_lan_stats_enable_set)
	{
		/* Read the configuration only once. */
		ipacm_lan_stats_enable = cfg->lan_stats_enable;
		ipacm_lan_stats_enable_set = true;
		IPACMDBG_H("ipacm_lan_stats_enable %d. \n", ipacm_lan_stats_enable);
	}
#ifdef IPA_HW_FNR_STATS
	if(ipacm_lan_stats_enable && (GetIPAVer(true) >= IPA_HW_v4_5)) {
		if (hw_fnr_stats_support == true) {
			IPACMERR("FnR counter allocated already, skip dup allocation\n");
			goto skip_fnr_alloc;
		}
		if (ipacm_alloc_fnr_counters(&fnr_counters, m_fd))
		{
			IPACMERR("Failed to allocate fnr counters.\n");
			goto fail;
		} else
			IPACMDBG_H("Allocating fnr counters :  Done\n");

		hw_fnr_stats_support = true;
	}
skip_fnr_alloc:
#endif //IPA_HW_FNR_STATS
#endif
	ipv6_nat_enable = cfg->ipv6_nat_enable;
	ipacm_l2tp_enable = cfg->ipacm_l2tp_enable;
	ipacm_mpdn_enable = cfg->ipacm_mpdn_enable;

	ipacm_emesh_enable = cfg->ipacm_emesh_enable;
	ipacm_emesh_mode = cfg->ipacm_emesh_mode;

	ipacm_static_policy_enable = cfg->static_policy_enable;
#ifdef FEATURE_STATIC_POLICY
	ipacm_static_policy_dscp_mark_mode = cfg->static_policy_dscp_mark_mode;
#endif
	ipacm_qos_enable = cfg->qos_mode;

	if (ipacm_mpdn_enable == TRUE && ipacm_l2tp_enable != IPACM_L2TP_DISABLE)
	{
		IPACMERR("Not support both VLAN_MPDN and L2TP are enable \n");
		close(m_fd);
		exit(0);
	}

	/* Construct IPACM GRE info */
	ipacm_gre_enable = cfg->gre_conf.gre_enable;
	ipacm_gre_autolearn = cfg->gre_conf.gre_autolearn;
	IPACMDBG_H("ipacm_gre_enable %d. \n", ipacm_gre_enable);
	IPACMDBG_H("ipacm_gre_autolearn %d. \n", ipacm_gre_autolearn);
	memset(&ipacm_gre_server_ipv4, 0, sizeof(ipacm_gre_server_ipv4));

	memcpy(&ipacm_gre_server_ipv4,
					 &cfg->gre_conf.gre_server_ipv4,
					 sizeof(cfg->gre_conf.gre_server_ipv4));


	subnet_addr = htonl(ipacm_gre_server_ipv4);
	memcpy(&in_addr_print,&subnet_addr,sizeof(in_addr_print));
	IPACMDBG_H("GRE_SERVER_IPv4= %s \n ",
						 inet_ntoa(in_addr_print));

	ipa_num_wlan_guest_ap = cfg->num_wlan_guest_ap;
	IPACMDBG_H("ipa_num_wlan_guest_ap %d\n",ipa_num_wlan_guest_ap);

#ifdef FEATURE_DUAL_BACKHAUL
	/* Fetch second backhaul details */
	second_backhaul_info.enable = cfg->dual_backhaul_conf.dualbackhaul_enable;
	IPACMDBG_H("Second backhaul details enabled: %d, netdev: %s, gwipv4: %x\n",
		second_backhaul_info.enable, second_backhaul_info.net_dev,
		second_backhaul_info.gateway_ipv4);
#endif
#ifdef FEATURE_EoGRE
	/* Fetch v6options enable details */
	v6options_enabled = cfg->v6options_enable;
	IPACMDBG_H("v6options enabled is %d\n", v6options_enabled);
#endif

	/* Allocate more non-nat entries if the monitored iface dun have Tx/Rx properties */

	if(pthread_mutex_lock(&nat_iface_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		goto fail;
	}

	if (pNatIfaces != NULL)
	{
		free(pNatIfaces);
		pNatIfaces = NULL;
		IPACMDBG_H("RESET IPACM_Config::pNatIfaces \n");
	}
	ipa_nat_iface_entries = 0;
	pNatIfaces = (NatIfaces *)calloc(IPA_MAX_NAT_IFACE, sizeof(NatIfaces));
	if (pNatIfaces == NULL)
	{
		IPACMERR("unable to allocate nat ifaces\n");
		pthread_mutex_unlock(&nat_iface_lock);
		ret = IPACM_FAILURE;
		free(iface_table);
		free(alg_table);
		goto fail;
	}
	pthread_mutex_unlock(&nat_iface_lock);

	/* Construct the routing table ictol name in iface static member*/
	rt_tbl_default_v4.ip = IPA_IP_v4;
	strlcpy(rt_tbl_default_v4.name, V4_DEFAULT_ROUTE_TABLE_NAME, sizeof(rt_tbl_default_v4.name));

	rt_tbl_lan_v4.ip = IPA_IP_v4;
	strlcpy(rt_tbl_lan_v4.name, V4_LAN_ROUTE_TABLE_NAME, sizeof(rt_tbl_lan_v4.name));

	rt_tbl_wan_v4.ip = IPA_IP_v4;
	strlcpy(rt_tbl_wan_v4.name, V4_WAN_ROUTE_TABLE_NAME, sizeof(rt_tbl_wan_v4.name));

	rt_tbl_v6.ip = IPA_IP_v6;
	strlcpy(rt_tbl_v6.name, V6_COMMON_ROUTE_TABLE_NAME, sizeof(rt_tbl_v6.name));

	rt_tbl_wan_v6.ip = IPA_IP_v6;
	strlcpy(rt_tbl_wan_v6.name, V6_WAN_ROUTE_TABLE_NAME, sizeof(rt_tbl_wan_v6.name));

	rt_tbl_odu_v4.ip = IPA_IP_v4;
	strlcpy(rt_tbl_odu_v4.name, V4_ODU_ROUTE_TABLE_NAME, sizeof(rt_tbl_odu_v4.name));

	rt_tbl_odu_v6.ip = IPA_IP_v6;
	strlcpy(rt_tbl_odu_v6.name, V6_ODU_ROUTE_TABLE_NAME, sizeof(rt_tbl_odu_v6.name));

	rt_tbl_wan_dl.ip = IPA_IP_MAX;
	strlcpy(rt_tbl_wan_dl.name, WAN_DL_ROUTE_TABLE_NAME, sizeof(rt_tbl_wan_dl.name));

	/* Construct IPACM ipa_client map to rm_resource table */
	ipa_client_rm_map_tbl[IPA_CLIENT_WLAN1_PROD]= IPA_RM_RESOURCE_WLAN_PROD;
	ipa_client_rm_map_tbl[IPA_CLIENT_USB_PROD]= IPA_RM_RESOURCE_USB_PROD;
	ipa_client_rm_map_tbl[IPA_CLIENT_A5_WLAN_AMPDU_PROD]= IPA_RM_RESOURCE_HSIC_PROD;
	ipa_client_rm_map_tbl[IPA_CLIENT_A2_EMBEDDED_PROD]= IPA_RM_RESOURCE_Q6_PROD;
	ipa_client_rm_map_tbl[IPA_CLIENT_A2_TETHERED_PROD]= IPA_RM_RESOURCE_Q6_PROD;
	ipa_client_rm_map_tbl[IPA_CLIENT_APPS_LAN_WAN_PROD]= IPA_RM_RESOURCE_Q6_PROD;
	ipa_client_rm_map_tbl[IPA_CLIENT_WLAN1_CONS]= IPA_RM_RESOURCE_WLAN_CONS;
	ipa_client_rm_map_tbl[IPA_CLIENT_WLAN2_CONS]= IPA_RM_RESOURCE_WLAN_CONS;
	ipa_client_rm_map_tbl[IPA_CLIENT_WLAN3_CONS]= IPA_RM_RESOURCE_WLAN_CONS;
	ipa_client_rm_map_tbl[IPA_CLIENT_WLAN4_CONS]= IPA_RM_RESOURCE_WLAN_CONS;
	ipa_client_rm_map_tbl[IPA_CLIENT_USB_CONS]= IPA_RM_RESOURCE_USB_CONS;
	ipa_client_rm_map_tbl[IPA_CLIENT_A2_EMBEDDED_CONS]= IPA_RM_RESOURCE_Q6_CONS;
	ipa_client_rm_map_tbl[IPA_CLIENT_A2_TETHERED_CONS]= IPA_RM_RESOURCE_Q6_CONS;
	ipa_client_rm_map_tbl[IPA_CLIENT_APPS_WAN_CONS]= IPA_RM_RESOURCE_Q6_CONS;
	ipa_client_rm_map_tbl[IPA_CLIENT_ODU_PROD]= IPA_RM_RESOURCE_ODU_ADAPT_PROD;
	ipa_client_rm_map_tbl[IPA_CLIENT_ODU_EMB_CONS]= IPA_RM_RESOURCE_ODU_ADAPT_CONS;
	ipa_client_rm_map_tbl[IPA_CLIENT_ODU_TETH_CONS]= IPA_RM_RESOURCE_ODU_ADAPT_CONS;
	ipa_client_rm_map_tbl[IPA_CLIENT_ETHERNET_PROD]= IPA_RM_RESOURCE_ETHERNET_PROD;
	ipa_client_rm_map_tbl[IPA_CLIENT_ETHERNET_CONS]= IPA_RM_RESOURCE_ETHERNET_CONS;

	/* Create the entries which IPACM wants to add dependencies on */
	ipa_rm_tbl[0].producer_rm1 = IPA_RM_RESOURCE_WLAN_PROD;
	ipa_rm_tbl[0].consumer_rm1 = IPA_RM_RESOURCE_Q6_CONS;
	ipa_rm_tbl[0].producer_rm2 = IPA_RM_RESOURCE_Q6_PROD;
	ipa_rm_tbl[0].consumer_rm2 = IPA_RM_RESOURCE_WLAN_CONS;

	ipa_rm_tbl[1].producer_rm1 = IPA_RM_RESOURCE_USB_PROD;
	ipa_rm_tbl[1].consumer_rm1 = IPA_RM_RESOURCE_Q6_CONS;
	ipa_rm_tbl[1].producer_rm2 = IPA_RM_RESOURCE_Q6_PROD;
	ipa_rm_tbl[1].consumer_rm2 = IPA_RM_RESOURCE_USB_CONS;

	ipa_rm_tbl[2].producer_rm1 = IPA_RM_RESOURCE_WLAN_PROD;
	ipa_rm_tbl[2].consumer_rm1 = IPA_RM_RESOURCE_USB_CONS;
	ipa_rm_tbl[2].producer_rm2 = IPA_RM_RESOURCE_USB_PROD;
	ipa_rm_tbl[2].consumer_rm2 = IPA_RM_RESOURCE_WLAN_CONS;

	ipa_rm_tbl[3].producer_rm1 = IPA_RM_RESOURCE_ODU_ADAPT_PROD;
	ipa_rm_tbl[3].consumer_rm1 = IPA_RM_RESOURCE_Q6_CONS;
	ipa_rm_tbl[3].producer_rm2 = IPA_RM_RESOURCE_Q6_PROD;
	ipa_rm_tbl[3].consumer_rm2 = IPA_RM_RESOURCE_ODU_ADAPT_CONS;

	ipa_rm_tbl[4].producer_rm1 = IPA_RM_RESOURCE_WLAN_PROD;
	ipa_rm_tbl[4].consumer_rm1 = IPA_RM_RESOURCE_ODU_ADAPT_CONS;
	ipa_rm_tbl[4].producer_rm2 = IPA_RM_RESOURCE_ODU_ADAPT_PROD;
	ipa_rm_tbl[4].consumer_rm2 = IPA_RM_RESOURCE_WLAN_CONS;

	ipa_rm_tbl[5].producer_rm1 = IPA_RM_RESOURCE_ODU_ADAPT_PROD;
	ipa_rm_tbl[5].consumer_rm1 = IPA_RM_RESOURCE_USB_CONS;
	ipa_rm_tbl[5].producer_rm2 = IPA_RM_RESOURCE_USB_PROD;
	ipa_rm_tbl[5].consumer_rm2 = IPA_RM_RESOURCE_ODU_ADAPT_CONS;

	ipa_rm_tbl[6].producer_rm1 = IPA_RM_RESOURCE_ETHERNET_PROD;
	ipa_rm_tbl[6].consumer_rm1 = IPA_RM_RESOURCE_Q6_CONS;
	ipa_rm_tbl[6].producer_rm2 = IPA_RM_RESOURCE_Q6_PROD;
	ipa_rm_tbl[6].consumer_rm2 = IPA_RM_RESOURCE_ETHERNET_CONS;

	ipa_rm_tbl[7].producer_rm1 = IPA_RM_RESOURCE_ETHERNET_PROD;
	ipa_rm_tbl[7].consumer_rm1 = IPA_RM_RESOURCE_USB_CONS;
	ipa_rm_tbl[7].producer_rm2 = IPA_RM_RESOURCE_USB_PROD;
	ipa_rm_tbl[7].consumer_rm2 = IPA_RM_RESOURCE_ETHERNET_CONS;

	ipa_rm_tbl[8].producer_rm1 = IPA_RM_RESOURCE_WLAN_PROD;
	ipa_rm_tbl[8].consumer_rm1 = IPA_RM_RESOURCE_ETHERNET_CONS;
	ipa_rm_tbl[8].producer_rm2 = IPA_RM_RESOURCE_ETHERNET_PROD;
	ipa_rm_tbl[8].consumer_rm2 = IPA_RM_RESOURCE_WLAN_CONS;
	ipa_max_valid_rm_entry = 9; /* max is IPA_MAX_RM_ENTRY (9)*/

	IPACMDBG_H(" depend MAP-0 rm index %d to rm index: %d \n", IPA_RM_RESOURCE_WLAN_PROD, IPA_RM_RESOURCE_Q6_CONS);
	IPACMDBG_H(" depend MAP-1 rm index %d to rm index: %d \n", IPA_RM_RESOURCE_USB_PROD, IPA_RM_RESOURCE_Q6_CONS);
	IPACMDBG_H(" depend MAP-2 rm index %d to rm index: %d \n", IPA_RM_RESOURCE_WLAN_PROD, IPA_RM_RESOURCE_USB_CONS);
	IPACMDBG_H(" depend MAP-3 rm index %d to rm index: %d \n", IPA_RM_RESOURCE_ODU_ADAPT_PROD, IPA_RM_RESOURCE_Q6_CONS);
	IPACMDBG_H(" depend MAP-4 rm index %d to rm index: %d \n", IPA_RM_RESOURCE_WLAN_PROD, IPA_RM_RESOURCE_ODU_ADAPT_CONS);
	IPACMDBG_H(" depend MAP-5 rm index %d to rm index: %d \n", IPA_RM_RESOURCE_ODU_ADAPT_PROD, IPA_RM_RESOURCE_USB_CONS);
	IPACMDBG_H(" depend MAP-6 rm index %d to rm index: %d \n", IPA_RM_RESOURCE_ETHERNET_PROD, IPA_RM_RESOURCE_Q6_CONS);
	IPACMDBG_H(" depend MAP-7 rm index %d to rm index: %d \n", IPA_RM_RESOURCE_ETHERNET_PROD, IPA_RM_RESOURCE_USB_CONS);
	IPACMDBG_H(" depend MAP-8 rm index %d to rm index: %d \n", IPA_RM_RESOURCE_WLAN_PROD, IPA_RM_RESOURCE_ETHERNET_CONS);

fail:
	if (cfg != NULL)
	{
		free(cfg);
		cfg = NULL;
	}
	close(m_fd);
	return ret;
}

IPACM_Config* IPACM_Config::GetInstance()
{
	int res = IPACM_SUCCESS;

	if (pInstance == NULL)
	{
		pInstance = new IPACM_Config();

		res = pInstance->Init();
		if (res != IPACM_SUCCESS)
		{
			delete pInstance;
			IPACMERR("unable to initialize config instance\n");
			return NULL;
		}
	}

	return pInstance;
}

int IPACM_Config::GetAlgPorts(int nPorts, ipacm_alg *pAlgPorts)
{
	if (nPorts <= 0 || pAlgPorts == NULL)
	{
		IPACMERR("Invalid input\n");
		return -1;
	}

	for (int cnt = 0; cnt < nPorts; cnt++)
	{
		pAlgPorts[cnt].protocol = alg_table[cnt].protocol;
		pAlgPorts[cnt].port = alg_table[cnt].port;
	}

	return 0;
}

int IPACM_Config::GetNatIfaces(int nIfaces, NatIfaces *pIfaces)
{

	if (nIfaces <= 0 || pIfaces == NULL)
	{
		IPACMERR("Invalid input\n");
		return -1;
	}

	if(pthread_mutex_lock(&nat_iface_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return -1;
	}

	for (int cnt=0; cnt<nIfaces; cnt++)
	{
		memcpy(pIfaces[cnt].iface_name,
					 pNatIfaces[cnt].iface_name,
					 sizeof(pIfaces[cnt].iface_name));
	}

	pthread_mutex_unlock(&nat_iface_lock);
	return 0;
}

void IPACM_Config::update_repeater_iface(char *str) {


	char *first, *second;
	first = strstr(str,"sta");
	if (first == NULL) {
		IPACMDBG("Non wds-ext non-vlan interface\n");
		return;
	}
	second = strstr(first, ".");
	if(second == NULL) {
		IPACMDBG("wds-ext non-vlan interface\n");
		first = first-1;
		*first = '\0';
		return;
	}
	IPACMDBG("wds-ext vlan interface\n");
	strlcpy((first-1), second, sizeof(second));
	return;
}

int IPACM_Config::AddNatIfaces(char *dev_name)
{
	int i;

	if(pthread_mutex_lock(&nat_iface_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return 0;
	}

	/* Check if this iface already in NAT-iface*/
	for(i = 0; i < ipa_nat_iface_entries; i++)
	{
		if(strncmp(dev_name,
							 pNatIfaces[i].iface_name,
							 sizeof(pNatIfaces[i].iface_name)) == 0)
		{
			IPACMDBG("Interface (%s) is add to nat iface already\n", dev_name);
			pthread_mutex_unlock(&nat_iface_lock);
			return 0;
		}
	}

	IPACMDBG_H("Add iface %s to NAT-ifaces, origin it has %d nat ifaces\n",
					          dev_name, ipa_nat_iface_entries);

	if (ipa_nat_iface_entries < IPA_MAX_NAT_IFACE)
	{
		strlcpy(pNatIfaces[ipa_nat_iface_entries].iface_name,dev_name,
				IPA_IFACE_NAME_LEN);
		IPACMDBG_H("Added Nat Iface: %s\n",
			pNatIfaces[ipa_nat_iface_entries].iface_name);
		ipa_nat_iface_entries++;
		IPACMDBG_H("Update nat-ifaces number: %d\n",
			ipa_nat_iface_entries);
	}

	pthread_mutex_unlock(&nat_iface_lock);
	return 0;
}

int IPACM_Config::DelNatIfaces(char *dev_name)
{
	int i = 0;

	if(pthread_mutex_lock(&nat_iface_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return 0;
	}
	IPACMDBG_H("Del iface %s from NAT-ifaces, origin it has %d nat ifaces\n",
					 dev_name, ipa_nat_iface_entries);

	for (i = 0; i < ipa_nat_iface_entries; i++)
	{
		if (strcmp(dev_name, pNatIfaces[i].iface_name) == 0)
		{
			IPACMDBG_H("Find Nat IfaceName: %s ,previous nat-ifaces number: %d\n",
							 pNatIfaces[i].iface_name, ipa_nat_iface_entries);

			/* Reset the matched entry */
			memset(pNatIfaces[i].iface_name, 0, IPA_IFACE_NAME_LEN);

			for (; i < ipa_nat_iface_entries - 1; i++)
			{
				memcpy(pNatIfaces[i].iface_name,
							 pNatIfaces[i + 1].iface_name, IPA_IFACE_NAME_LEN);

				/* Reset the copied entry */
				memset(pNatIfaces[i + 1].iface_name, 0, IPA_IFACE_NAME_LEN);
			}
			ipa_nat_iface_entries--;
			IPACMDBG_H("Update nat-ifaces number: %d\n", ipa_nat_iface_entries);
			pthread_mutex_unlock(&nat_iface_lock);
			return 0;
		}
	}

	IPACMDBG_H("Can't find Nat IfaceName: %s with total nat-ifaces number: %d\n",
					    dev_name, ipa_nat_iface_entries);
	pthread_mutex_unlock(&nat_iface_lock);
	return 0;
}

/* for IPACM resource manager dependency usage
   add either Tx or Rx ipa_rm_resource_name and
   also indicate that endpoint property if valid */
void IPACM_Config::AddRmDepend(ipa_rm_resource_name rm1,bool rx_bypass_ipa)
{
	int retval = 0;
	struct ipa_ioc_rm_dependency dep;

	IPACMDBG_H(" Got rm add-depend index : %d \n", rm1);
	/* ipa_rm_a2_check: IPA_RM_RESOURCE_Q6_CONS*/
	if(rm1 == IPA_RM_RESOURCE_Q6_CONS)
	{
		ipa_rm_a2_check+=1;
		IPACMDBG_H("got %d times default RT routing from A2 \n", ipa_rm_a2_check);
	}

	for(int i=0;i<ipa_max_valid_rm_entry;i++)
	{
		if(rm1 == ipa_rm_tbl[i].producer_rm1)
		{
			ipa_rm_tbl[i].producer1_up = true;
			/* entry1's producer actually dun have registered Rx-property */
			ipa_rm_tbl[i].rx_bypass_ipa = rx_bypass_ipa;
			IPACMDBG_H("Matched RM_table entry: %d's producer_rm1 with non_rx_prop: %d \n", i,ipa_rm_tbl[i].rx_bypass_ipa);

			if(ipa_rm_tbl[i].consumer1_up == true && ipa_rm_tbl[i].rm_set == false)
			{
				IPACMDBG_H("SETUP RM_table entry %d's bi-direction dependency  \n", i);
				/* add bi-directional dependency*/
				if(ipa_rm_tbl[i].rx_bypass_ipa)
				{
					IPACMDBG_H("Skip ADD entry %d's dependency between WLAN-Pro: %d, Con: %d \n", i, ipa_rm_tbl[i].producer_rm1,ipa_rm_tbl[i].consumer_rm1);
				}
				else
				{
					memset(&dep, 0, sizeof(dep));
					dep.resource_name = ipa_rm_tbl[i].producer_rm1;
					dep.depends_on_name = ipa_rm_tbl[i].consumer_rm1;
					retval = ioctl(m_fd, IPA_IOC_RM_ADD_DEPENDENCY, &dep);
					IPACMDBG_H("ADD entry %d's dependency between Pro: %d, Con: %d \n", i,dep.resource_name,dep.depends_on_name);
					if (retval)
					{
						IPACMERR("Failed adding dependecny for RM_table entry %d's bi-direction dependency (error:%d) \n", i,retval);
					}
				}
				memset(&dep, 0, sizeof(dep));
				dep.resource_name = ipa_rm_tbl[i].producer_rm2;
				dep.depends_on_name = ipa_rm_tbl[i].consumer_rm2;
				retval = ioctl(m_fd, IPA_IOC_RM_ADD_DEPENDENCY, &dep);
				IPACMDBG_H("ADD entry %d's dependency between Pro: %d, Con: %d \n", i,dep.resource_name,dep.depends_on_name);
				if (retval)
				{
					IPACMERR("Failed adding dependecny for RM_table entry %d's bi-direction dependency (error:%d)  \n", i,retval);
				}
				ipa_rm_tbl[i].rm_set = true;
			}
			else
			{
				IPACMDBG_H("Not SETUP RM_table entry %d: prod_up:%d, cons_up:%d, rm_set: %d \n", i,ipa_rm_tbl[i].producer1_up, ipa_rm_tbl[i].consumer1_up, ipa_rm_tbl[i].rm_set);
			}
		}

		if(rm1 == ipa_rm_tbl[i].consumer_rm1)
		{
			ipa_rm_tbl[i].consumer1_up = true;
			IPACMDBG_H("Matched RM_table entry: %d's consumer_rm1 \n", i);

			if(ipa_rm_tbl[i].producer1_up == true && ipa_rm_tbl[i].rm_set == false)
			{
				IPACMDBG_H("SETUP RM_table entry %d's bi-direction dependency  \n", i);
				/* add bi-directional dependency*/
				if(ipa_rm_tbl[i].rx_bypass_ipa)
				{
					IPACMDBG_H("Skip ADD entry %d's dependency between WLAN-Pro: %d, Con: %d \n", i, ipa_rm_tbl[i].producer_rm1,ipa_rm_tbl[i].consumer_rm1);
				}
				else
				{
					memset(&dep, 0, sizeof(dep));
					dep.resource_name = ipa_rm_tbl[i].producer_rm1;
					dep.depends_on_name = ipa_rm_tbl[i].consumer_rm1;
					retval = ioctl(m_fd, IPA_IOC_RM_ADD_DEPENDENCY, &dep);
					IPACMDBG_H("ADD entry %d's dependency between Pro: %d, Con: %d \n", i,dep.resource_name,dep.depends_on_name);
					if (retval)
					{
						IPACMERR("Failed adding dependecny for RM_table entry %d's bi-direction dependency (error:%d)  \n", i,retval);
					}
				}

				memset(&dep, 0, sizeof(dep));
				dep.resource_name = ipa_rm_tbl[i].producer_rm2;
				dep.depends_on_name = ipa_rm_tbl[i].consumer_rm2;
				retval = ioctl(m_fd, IPA_IOC_RM_ADD_DEPENDENCY, &dep);
				IPACMDBG_H("ADD entry %d's dependency between Pro: %d, Con: %d \n", i,dep.resource_name,dep.depends_on_name);
				if (retval)
				{
					IPACMERR("Failed adding dependecny for RM_table entry %d's bi-direction dependency (error:%d)  \n", i,retval);
				}
				ipa_rm_tbl[i].rm_set = true;
			}
			else
			{
				IPACMDBG_H("Not SETUP RM_table entry %d: prod_up:%d, cons_up:%d, rm_set: %d \n", i,ipa_rm_tbl[i].producer1_up, ipa_rm_tbl[i].consumer1_up, ipa_rm_tbl[i].rm_set);
			}
	   }
   }
   return ;
}

/* for IPACM resource manager dependency usage
   delete either Tx or Rx ipa_rm_resource_name */

void IPACM_Config::DelRmDepend(ipa_rm_resource_name rm1)
{
	int retval = 0;
	struct ipa_ioc_rm_dependency dep;

	IPACMDBG_H(" Got rm del-depend index : %d \n", rm1);
	/* ipa_rm_a2_check: IPA_RM_RESOURCE_Q6_CONS*/
	if(rm1 == IPA_RM_RESOURCE_Q6_CONS)
	{
		ipa_rm_a2_check-=1;
		IPACMDBG_H("Left %d times default RT routing from A2 \n", ipa_rm_a2_check);
	}

	for(int i=0;i<ipa_max_valid_rm_entry;i++)
	{

		if(rm1 == ipa_rm_tbl[i].producer_rm1)
		{
			if(ipa_rm_tbl[i].rm_set == true)
			{
				IPACMDBG_H("Matched RM_table entry: %d's producer_rm1 and dependency is up \n", i);
				ipa_rm_tbl[i].rm_set = false;

				/* delete bi-directional dependency*/
				if(ipa_rm_tbl[i].rx_bypass_ipa)
				{
					IPACMDBG_H("Skip DEL entry %d's dependency between WLAN-Pro: %d, Con: %d \n", i, ipa_rm_tbl[i].producer_rm1,ipa_rm_tbl[i].consumer_rm1);
				}
				else
				{
					memset(&dep, 0, sizeof(dep));
					dep.resource_name = ipa_rm_tbl[i].producer_rm1;
					dep.depends_on_name = ipa_rm_tbl[i].consumer_rm1;
					retval = ioctl(m_fd, IPA_IOC_RM_DEL_DEPENDENCY, &dep);
					IPACMDBG_H("Delete entry %d's dependency between Pro: %d, Con: %d \n", i,dep.resource_name,dep.depends_on_name);
					if (retval)
					{
						IPACMERR("Failed deleting dependecny for RM_table entry %d's bi-direction dependency (error:%d) \n", i,retval);
					}
				}
				memset(&dep, 0, sizeof(dep));
				dep.resource_name = ipa_rm_tbl[i].producer_rm2;
				dep.depends_on_name = ipa_rm_tbl[i].consumer_rm2;
				retval = ioctl(m_fd, IPA_IOC_RM_DEL_DEPENDENCY, &dep);
				IPACMDBG_H("Delete entry %d's dependency between Pro: %d, Con: %d \n", i,dep.resource_name,dep.depends_on_name);
				if (retval)
				{
					IPACMERR("Failed deleting dependecny for RM_table entry %d's bi-direction dependency (error:%d) \n", i,retval);
				}
			}
			ipa_rm_tbl[i].producer1_up = false;
			ipa_rm_tbl[i].rx_bypass_ipa = false;
		}
		if(rm1 == ipa_rm_tbl[i].consumer_rm1)
		{
			/* ipa_rm_a2_check: IPA_RM_RESOURCE_!6_CONS*/
			if(ipa_rm_tbl[i].consumer_rm1 == IPA_RM_RESOURCE_Q6_CONS && ipa_rm_a2_check == 1)
			{
				IPACMDBG_H(" still have %d default RT routing from A2 \n", ipa_rm_a2_check);
				continue;
			}

			if(ipa_rm_tbl[i].rm_set == true)
			{
				IPACMDBG_H("Matched RM_table entry: %d's consumer_rm1 and dependency is up \n", i);
				ipa_rm_tbl[i].rm_set = false;
				/* delete bi-directional dependency*/
				if(ipa_rm_tbl[i].rx_bypass_ipa)
				{
					IPACMDBG_H("Skip DEL entry %d's dependency between WLAN-Pro: %d, Con: %d \n", i, ipa_rm_tbl[i].producer_rm1,ipa_rm_tbl[i].consumer_rm1);
				}
				else
				{
					memset(&dep, 0, sizeof(dep));
					dep.resource_name = ipa_rm_tbl[i].producer_rm1;
					dep.depends_on_name = ipa_rm_tbl[i].consumer_rm1;
					retval = ioctl(m_fd, IPA_IOC_RM_DEL_DEPENDENCY, &dep);
					IPACMDBG_H("Delete entry %d's dependency between Pro: %d, Con: %d \n", i,dep.resource_name,dep.depends_on_name);
					if (retval)
					{
						IPACMERR("Failed deleting dependecny for RM_table entry %d's bi-direction dependency (error:%d) \n", i,retval);
					}
				}

				memset(&dep, 0, sizeof(dep));
				dep.resource_name = ipa_rm_tbl[i].producer_rm2;
				dep.depends_on_name = ipa_rm_tbl[i].consumer_rm2;
				retval = ioctl(m_fd, IPA_IOC_RM_DEL_DEPENDENCY, &dep);
				IPACMDBG_H("Delete entry %d's dependency between Pro: %d, Con: %d \n", i,dep.resource_name,dep.depends_on_name);
				if (retval)
				{
					IPACMERR("Failed deleting dependecny for RM_table entry %d's bi-direction dependency (error:%d) \n", i,retval);
				}
			}
			ipa_rm_tbl[i].consumer1_up = false;
		}
	}
	return ;
}

int IPACM_Config::SetExtProp(ipa_ioc_query_intf_ext_props *prop)
{
	int i, num;

	if(prop == NULL || prop->num_ext_props <= 0)
	{
		IPACMERR("There is no extended property!\n");
		return IPACM_FAILURE;
	}

	num = prop->num_ext_props;
	ext_prop_v4.num_v4_xlat_props = 0;
	for(i=0; i<num; i++)
	{
		if(prop->ext[i].ip == IPA_IP_v4)
		{
			if(ext_prop_v4.num_ext_props >= MAX_NUM_EXT_PROPS)
			{
				IPACMERR("IPv4 extended property table is full!\n");
				continue;
			}
			memcpy(&ext_prop_v4.prop[ext_prop_v4.num_ext_props], &prop->ext[i], sizeof(struct ipa_ioc_ext_intf_prop));
			ext_prop_v4.num_ext_props++;
			if (prop->ext[i].is_xlat_rule)
				ext_prop_v4.num_v4_xlat_props++;
		}
		else if(prop->ext[i].ip == IPA_IP_v6)
		{
			if(ext_prop_v6.num_ext_props >= MAX_NUM_EXT_PROPS)
			{
				IPACMERR("IPv6 extended property table is full!\n");
				continue;
			}
			memcpy(&ext_prop_v6.prop[ext_prop_v6.num_ext_props], &prop->ext[i], sizeof(struct ipa_ioc_ext_intf_prop));
			ext_prop_v6.num_ext_props++;
		}
		else
		{
			IPACMERR("The IP type is not expected!\n");
			return IPACM_FAILURE;
		}
	}

	IPACMDBG_H("Set extended property succeeded.\n");

	return IPACM_SUCCESS;
}

ipacm_ext_prop* IPACM_Config::GetExtProp(ipa_ip_type ip_type)
{
	if(ip_type == IPA_IP_v4)
		return &ext_prop_v4;
	else if(ip_type == IPA_IP_v6)
		return &ext_prop_v6;
	else
	{
		IPACMERR("Failed to get extended property: the IP version is neither IPv4 nor IPv6!\n");
		return NULL;
	}
}

int IPACM_Config::DelExtProp(ipa_ip_type ip_type)
{
	if(ip_type != IPA_IP_v6)
	{
		memset(&ext_prop_v4, 0, sizeof(ext_prop_v4));
	}

	if(ip_type != IPA_IP_v4)
	{
		memset(&ext_prop_v6, 0, sizeof(ext_prop_v6));
	}

	return IPACM_SUCCESS;
}

const char* IPACM_Config::getEventName(ipa_cm_event_id event_id)
{
	if(event_id >= sizeof(ipacm_event_name)/sizeof(ipacm_event_name[0]))
	{
		IPACMERR("Event name array is not consistent with event array!\n");
		return NULL;
	}

	return ipacm_event_name[event_id];
}

enum ipa_hw_type IPACM_Config::GetIPAVer(bool get)
{
	int ret;

	if(!get)
		return ver;

	ret = ioctl(m_fd, IPA_IOC_GET_HW_VERSION, &ver);
	if(ret != 0)
	{
		IPACMERR("Failed to get IPA version with error %d.\n", ret);
		ver = IPA_HW_None;
		return IPA_HW_None;
	}
	IPACMDBG_H("IPA version is %d.\n", ver);
	return ver;
}

int IPACM_Config::ResetClkVote(void)
{
	int ret = -1;

	if ( m_fd > 0 )
	{
		ret = ioctl(m_fd, IPA_IOC_APP_CLOCK_VOTE, IPA_APP_CLK_RESET_VOTE);

		if ( ret )
		{
			IPACMERR("APP_CLOCK_VOTE ioctl failure %d on IPA fd %d\n",
					 ret, m_fd);
		}
	}

	return ret;
}

#ifdef FEATURE_VLAN_MPDN
void IPACM_Config::add_bridge_vlan_mapping(ipa_bridge_vlan_mapping_info *data)
{
	list<bridge_vlan_mapping_info>::iterator it_mapping;
	ipacm_bridge *bridge = NULL;
	char iface_name[IPA_IFACE_NAME_LEN] = {0};
	int ret = IPACM_FAILURE;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("Trying to add bridge vlan mapping status:%d\n", data->status);

	for(it_mapping = m_bridge_vlan_mapping.begin(); it_mapping != m_bridge_vlan_mapping.end(); it_mapping++)
	{
		if(it_mapping->bridge_if_index == data->master_if_index)
		{
			if((data->status == 1) && (it_mapping->status != 1))
			{
				strlcpy(it_mapping->bridge_iface_name, data->bridge_name,
					sizeof(it_mapping->bridge_iface_name));
				it_mapping->bridge_ipv4 = data->bridge_ipv4;
				it_mapping->subnet_mask = data->subnet_mask;
				it_mapping->status = 1;
				IPACMDBG("Bridge %s entry updated with vlan id %d IP: 0x%x subnet: 0x%x\n", it_mapping->bridge_iface_name, it_mapping->bridge_associated_VID, it_mapping->bridge_ipv4, it_mapping->subnet_mask);


				bridge = get_vlan_bridge(data->bridge_name);
				if(bridge)
				{
					IPACMDBG_H("bridge %s already added, update data\n",
						data->bridge_name);
					bridge->bridge_ipv4_addr = data->bridge_ipv4;
					bridge->bridge_netmask = data->subnet_mask;
				}
				goto bail;
			
			}

			IPACMDBG("The bridge %s was added before with vlan id: %d\n", data->bridge_name,
				it_mapping->bridge_associated_VID);
			goto bail;
		}
	}

	if (data->status == 1)
	{
		IPACMERR("No partial entry with vlan got added, Discarding the bridge data update\n");
		goto bail;
	}

	if(data->status == 0)
	{

		bridge_vlan_mapping_info new_mapping;
		memset(&new_mapping, 0, sizeof(new_mapping));
		new_mapping.bridge_associated_VID = data->vlan_id;
		new_mapping.bridge_if_index = data->master_if_index;
		new_mapping.status == 0;

		ret = ipa_get_if_name(iface_name, data->master_if_index);
		if(ret == IPACM_SUCCESS)
		{
			strlcpy(new_mapping.bridge_iface_name, iface_name,
				sizeof(new_mapping.bridge_iface_name));
		}

		m_bridge_vlan_mapping.push_front(new_mapping);
		bridge = get_vlan_bridge(data->bridge_name);
		if(bridge)
		{
			IPACMDBG_H("bridge %s already added, update data\n",
					data->bridge_name);
			bridge->associate_VID = data->vlan_id;
		}

	}

	IPACMDBG_H("added partial Entry with master interface index %d, VID %d\n", data->master_if_index, data->vlan_id);

bail:
	pthread_mutex_unlock(&vlan_l2tp_lock);
	return;
}

void IPACM_Config::del_bridge_vlan_mapping(uint16_t *data)
{
	list<bridge_vlan_mapping_info>::iterator it_mapping;
	ipacm_bridge *bridge = NULL;
	int ret = IPACM_FAILURE;
	char iface_name[IPA_IFACE_NAME_LEN] = {0};

	IPACMDBG_H("Deleting bridge vlan mapping with interface index %d\n",*data);

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	if(m_bridge_vlan_mapping.empty()) {

		IPACMERR("Bridge vlan mapping list is empty\n");
                pthread_mutex_unlock(&vlan_l2tp_lock);
		return;
	}

	for(it_mapping = m_bridge_vlan_mapping.begin(); it_mapping != m_bridge_vlan_mapping.end(); it_mapping++)
	{
		if(*data == it_mapping->bridge_if_index)
		{
			IPACMDBG_H("Found the bridge mapping (%s->%d)\n",
				it_mapping->bridge_iface_name,
				it_mapping->bridge_associated_VID);

			ret = ipa_get_if_name(iface_name, it_mapping->bridge_if_index);

			bridge = get_vlan_bridge(iface_name);
			if(bridge)
			{
				IPACMDBG_H("bridge %s - remove vlan id\n",
					it_mapping->bridge_iface_name);
				bridge->associate_VID = 0;
			}
			m_bridge_vlan_mapping.erase(it_mapping);
			break;
		}
	}

	IPACMDBG("Bridge-vlan mapping entry deleted\n");
	pthread_mutex_unlock(&vlan_l2tp_lock);
	return;
}

int IPACM_Config::get_bridge_vlan_mapping(ipa_bridge_vlan_mapping_info *data)
{
	list<bridge_vlan_mapping_info>::iterator it_mapping;
	int ret = IPACM_FAILURE;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return IPACM_FAILURE;
	}

	for(it_mapping = m_bridge_vlan_mapping.begin(); it_mapping != m_bridge_vlan_mapping.end(); it_mapping++)
	{
		if(strncmp(data->bridge_name, it_mapping->bridge_iface_name, sizeof(data->bridge_name)) == 0)
		{
			IPACMDBG_H("Found the bridge mapping (%s->%d)\n",
				data->bridge_name,
				it_mapping->bridge_associated_VID);

			data->vlan_id = it_mapping->bridge_associated_VID;
			data->bridge_ipv4 = it_mapping->bridge_ipv4;
			data->subnet_mask = it_mapping->subnet_mask;
			ret = IPACM_SUCCESS;
			break;
		}
	}

	pthread_mutex_unlock(&vlan_l2tp_lock);
	return ret;
}

uint16_t IPACM_Config::get_bridge_vlan_mapping_from_subnet(uint32_t ipv4_subnet)
{
	list<bridge_vlan_mapping_info>::iterator it_mapping;
	int ret = IPACM_FAILURE;
	uint16_t VlanID;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return IPACM_FAILURE;
	}

	for(it_mapping = m_bridge_vlan_mapping.begin(); it_mapping != m_bridge_vlan_mapping.end(); it_mapping++)
	{
		if(ipv4_subnet == (it_mapping->bridge_ipv4 & it_mapping->subnet_mask))
		{
			IPACMDBG_H("Found the bridge mapping for subnet 0x%X (vid = %d)\n",
				ipv4_subnet,
				it_mapping->bridge_associated_VID);
			VlanID = it_mapping->bridge_associated_VID;
			pthread_mutex_unlock(&vlan_l2tp_lock);
			return VlanID;
		}
	}

	pthread_mutex_unlock(&vlan_l2tp_lock);
	IPACMERR("Could not find subnet 0x%X\n", ipv4_subnet);

	return 0;
}
#endif



int IPACM_Config::find_matching_vlan(uint16_t interface_index, struct vlan_iface_info *vlan_data)
{
	list<vlan_iface_info>::iterator it_vlan;

	IPACMDBG("Extract vlan-id for interface index %d\n", interface_index);

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return IPACM_FAILURE;
	}
	if(m_vlan_iface.empty()) {
			IPACMERR("No vlan entry added\n");
			pthread_mutex_unlock(&vlan_l2tp_lock);
			return IPACM_FAILURE;
	}

	for(it_vlan = m_vlan_iface.begin(); it_vlan != m_vlan_iface.end(); it_vlan++)
	{
		if(it_vlan->vlan_interface_index == interface_index)
		{
			strlcpy(vlan_data->vlan_iface_name, it_vlan->vlan_iface_name, IPA_RESOURCE_NAME_MAX);
			vlan_data->vlan_id = it_vlan->vlan_id;
			IPACMDBG("Found vlan-id: %d for interface index: %d\n", it_vlan->vlan_id, interface_index);
			pthread_mutex_unlock(&vlan_l2tp_lock);
			return IPACM_SUCCESS;

		}
	}
	IPACMDBG("No matching vlan interface found for interface index: %d\n", interface_index);
	pthread_mutex_unlock(&vlan_l2tp_lock);
	return IPACM_FAILURE;
}

#if defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
void IPACM_Config::add_vlan_iface(ipa_vlan_iface_info *data)
{
	list<vlan_iface_info>::iterator it_vlan;
	vlan_iface_info new_vlan_info;
	ipacm_cmd_q_data evt_data;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("Vlan iface: %s vlan id: %d vlan if index %d\n", data->name, data->vlan_id, data->vlan_interface_index);
	for(it_vlan = m_vlan_iface.begin(); it_vlan != m_vlan_iface.end(); it_vlan++)
	{
		if(it_vlan->vlan_interface_index == data->vlan_interface_index)
		{
			IPACMERR("The vlan iface was added before with id %d\n", it_vlan->vlan_id);
			pthread_mutex_unlock(&vlan_l2tp_lock);
			return;
		}
	}
#ifdef FEATURE_L2TP
	if ((ipacm_mpdn_enable == false) && ((ipacm_l2tp_enable == IPACM_L2TP) || (ipacm_l2tp_enable == IPACM_L2TP_E2E)))
	{
		list<l2tp_vlan_mapping_info>::iterator it_mapping;
		for(it_mapping = m_l2tp_vlan_mapping.begin(); it_mapping != m_l2tp_vlan_mapping.end(); it_mapping++)
		{
			if(strncmp(data->name, it_mapping->vlan_iface_name, sizeof(data->name)) == 0)
			{
				IPACMDBG_H("Found a mapping: l2tp iface %s.\n", it_mapping->l2tp_iface_name);
				it_mapping->vlan_id = data->vlan_id;
			}
		}
	}
#endif
#ifdef FEATURE_VLAN_MPDN
	if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
	{
		AddNatIfaces(data->name);
		IPACMDBG_H("Add VLAN iface %s to nat ifaces.\n", data->name);
	}
#endif

	if (IPACM_Iface::ipacmcfg->wlan_vlan_mpdn_enabled == TRUE) {
		SwitchAPVlanMode(data->name, true);
		IPACMDBG_H("Switch AP %s to VLAN Mode\n", data->name);
	}

	memset(&new_vlan_info, 0, sizeof(new_vlan_info));
	strlcpy(new_vlan_info.vlan_iface_name, data->name, sizeof(new_vlan_info.vlan_iface_name));
	new_vlan_info.vlan_id = data->vlan_id;
	new_vlan_info.vlan_interface_index = data->vlan_interface_index;
	m_vlan_iface.push_front(new_vlan_info);
	pthread_mutex_unlock(&vlan_l2tp_lock);
#ifdef FEATURE_VLAN_MPDN
	if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
	{
		ipacm_event_eth_bridge *evt_data_eth_bridge;
		ipacm_cmd_q_data eth_bridge_evt;

		evt_data_eth_bridge = (ipacm_event_eth_bridge*)malloc(sizeof(*evt_data_eth_bridge));
		if(evt_data_eth_bridge == NULL)
		{
			IPACMERR("Failed to allocate memory.\n");
			return;
		}
		memset(evt_data_eth_bridge, 0, sizeof(*evt_data_eth_bridge));

		memcpy(evt_data_eth_bridge->iface_name, data->name,
			sizeof(evt_data_eth_bridge->iface_name));

		evt_data_eth_bridge->VlanID = data->vlan_id;

		eth_bridge_evt.evt_data = (void*)evt_data_eth_bridge;
		eth_bridge_evt.event = IPA_ETH_BRIDGE_ADD_VLAN_ID;

		IPACMDBG_H("Posting event %s\n",
			IPACM_Iface::ipacmcfg->getEventName(eth_bridge_evt.event));
		IPACM_EvtDispatcher::PostEvt(&eth_bridge_evt);
	}
	/*
	 * Call IPA_NOTIFY_VLAN_UP which will allow LAN to check if VLAN PDN is up.
	 * This will handle scenario where add_vlan_iface is received after
	 * LAN IPA_NEW_ADDR have already been processed.
	 */
	evt_data.event = IPA_NOTIFY_VLAN_UP;
	evt_data.evt_data = NULL;
	IPACMDBG_H("Posting %s\n", IPACM_Iface::ipacmcfg->getEventName(evt_data.event));
	IPACM_EvtDispatcher::PostEvt(&evt_data);

#endif
	return;
}

void IPACM_Config::restore_vlan_nat_ifaces(const char *phys_iface_name)
{
	list<vlan_iface_info>::iterator it_vlan;

	if(!phys_iface_name)
	{
		IPACMERR("got NULL iface_name\n");
		return;
	}

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("searching iface %s vlan interfaces to add to NAT devices\n", phys_iface_name)

	for(it_vlan = m_vlan_iface.begin(); it_vlan != m_vlan_iface.end(); it_vlan++)
	{
		if(strstr(it_vlan->vlan_iface_name, phys_iface_name))
		{
			AddNatIfaces(it_vlan->vlan_iface_name);
			IPACMDBG_H("restored VLAN iface %s to nat ifaces.\n", it_vlan->vlan_iface_name);
		}
	}

	pthread_mutex_unlock(&vlan_l2tp_lock);
	return;
}

void IPACM_Config::del_vlan_iface(ipa_vlan_iface_info *data)
{
	list<vlan_iface_info>::iterator it_vlan;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("Vlan iface: %s vlan id: %d\n", data->name, data->vlan_id);
	for(it_vlan = m_vlan_iface.begin(); it_vlan != m_vlan_iface.end(); it_vlan++)
	{
		if(it_vlan->vlan_interface_index == data->vlan_interface_index)
		{
			IPACMDBG_H("Found the vlan interface\n");
			m_vlan_iface.erase(it_vlan);
			break;
		}
	}

	if (IPACM_Iface::ipacmcfg->wlan_vlan_mpdn_enabled == TRUE) {
		SwitchAPVlanMode(data->name, false);
		IPACMDBG_H("Switch AP %s to Non-VLAN Mode\n", data->name);
	}

#ifdef FEATURE_VLAN_MPDN
	if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
	{
		DelNatIfaces(data->name);
		IPACMDBG_H("Del VLAN iface %s to nat ifaces.\n", data->name);
	}
#endif
#ifdef FEATURE_L2TP
	if ((ipacm_mpdn_enable == false) && ((ipacm_l2tp_enable == IPACM_L2TP) || (ipacm_l2tp_enable == IPACM_L2TP_E2E)))
	{
		list<l2tp_vlan_mapping_info>::iterator it_mapping;
		it_mapping = m_l2tp_vlan_mapping.begin();
		while(it_mapping != m_l2tp_vlan_mapping.end())
		{
			if(strncmp(data->name, it_mapping->vlan_iface_name, sizeof(data->name)) == 0)
			{
				IPACMDBG_H("Delete mapping with l2tp iface %s\n", it_mapping->l2tp_iface_name);
				it_mapping = m_l2tp_vlan_mapping.erase(it_mapping);
			}
			else
			{
				it_mapping++;
			}
		}
	}
#endif
	pthread_mutex_unlock(&vlan_l2tp_lock);

#ifdef FEATURE_VLAN_MPDN
	if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
	{
		ipacm_event_eth_bridge *evt_data_eth_bridge;
		ipacm_cmd_q_data eth_bridge_evt;

		evt_data_eth_bridge = (ipacm_event_eth_bridge*)malloc(sizeof(*evt_data_eth_bridge));
		if(evt_data_eth_bridge == NULL)
		{
			IPACMERR("Failed to allocate memory.\n");
			return;
		}
		memset(evt_data_eth_bridge, 0, sizeof(*evt_data_eth_bridge));

		memcpy(evt_data_eth_bridge->iface_name, data->name,
			sizeof(evt_data_eth_bridge->iface_name));

		evt_data_eth_bridge->VlanID = data->vlan_id;

		eth_bridge_evt.evt_data = (void*)evt_data_eth_bridge;
		eth_bridge_evt.event = IPA_ETH_BRIDGE_DEL_VLAN_ID;

		IPACMDBG_H("Posting event %s\n",
			IPACM_Iface::ipacmcfg->getEventName(eth_bridge_evt.event));
		IPACM_EvtDispatcher::PostEvt(&eth_bridge_evt);
	}
#endif

	return;
}

void IPACM_Config::handle_vlan_iface_info(ipacm_event_data_addr *data)
{
	list<vlan_iface_info>::iterator it_vlan;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("Incoming vlan iface: %s IPv6 address: 0x%08x%08x%08x%08x\n", data->iface_name,
		data->ipv6_addr[0], data->ipv6_addr[1], data->ipv6_addr[2], data->ipv6_addr[3]);

	for(it_vlan = m_vlan_iface.begin(); it_vlan != m_vlan_iface.end(); it_vlan++)
	{
		if(it_vlan->vlan_interface_index == data->if_index)
		{

			IPACMDBG_H("Found vlan iface: %s\n", it_vlan->vlan_iface_name);
			memcpy(it_vlan->vlan_iface_ipv6_addr, data->ipv6_addr,
				sizeof(it_vlan->vlan_iface_ipv6_addr));

#ifdef FEATURE_L2TP
			if ((ipacm_mpdn_enable == false) && ((ipacm_l2tp_enable == IPACM_L2TP) || (ipacm_l2tp_enable == IPACM_L2TP_E2E)))
			{
				list<l2tp_vlan_mapping_info>::iterator it_mapping;

				for(it_mapping = m_l2tp_vlan_mapping.begin(); it_mapping != m_l2tp_vlan_mapping.end(); it_mapping++)
				{
					if(strncmp(it_mapping->vlan_iface_name, it_vlan->vlan_iface_name,
						sizeof(it_mapping->vlan_iface_name)) == 0)
					{
						IPACMDBG_H("Found the l2tp-vlan mapping: l2tp %s\n", it_mapping->l2tp_iface_name);
						memcpy(it_mapping->vlan_iface_ipv6_addr, data->ipv6_addr,
							sizeof(it_mapping->vlan_iface_ipv6_addr));
					}
				}
				break;
			}
#endif
		}
	}

	if(it_vlan == m_vlan_iface.end())
	{
		IPACMDBG_H("Failed to find the vlan iface: %s\n", data->iface_name);
	}
	pthread_mutex_unlock(&vlan_l2tp_lock);

	return;
}

void IPACM_Config::handle_vlan_client_info(ipacm_event_data_all *data)
{
	list<l2tp_vlan_mapping_info>::iterator it_mapping;
	list<vlan_iface_info>::iterator it_vlan;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("Incoming vlan client iface: %s IPv6 address: 0x%08x%08x%08x%08x\n", data->iface_name,
		data->ipv6_addr[0], data->ipv6_addr[1], data->ipv6_addr[2], data->ipv6_addr[3]);
	IPACMDBG_H("MAC address: 0x%02x::%02x::%02x::%02x::%02x::%02x\n", data->mac_addr[0], data->mac_addr[1],
		data->mac_addr[2], data->mac_addr[3], data->mac_addr[4], data->mac_addr[5]);

	for(it_vlan = m_vlan_iface.begin(); it_vlan != m_vlan_iface.end(); it_vlan++)
	{
		if(it_vlan->vlan_interface_index == data->if_index)
		{
			IPACMDBG_H("Found vlan iface in vlan list: %s\n", it_vlan->vlan_iface_name);
			if(it_vlan->vlan_client_ipv6_addr[0] > 0 || it_vlan->vlan_client_ipv6_addr[1] > 0 ||
				it_vlan->vlan_client_ipv6_addr[2] > 0 || it_vlan->vlan_client_ipv6_addr[3] > 0)
			{
				IPACMDBG_H("Vlan client info has been populated before, return.\n");
				pthread_mutex_unlock(&vlan_l2tp_lock);
				return;
			}
			memcpy(it_vlan->vlan_client_mac, data->mac_addr, sizeof(it_vlan->vlan_client_mac));
			memcpy(it_vlan->vlan_client_ipv6_addr, data->ipv6_addr, sizeof(it_vlan->vlan_client_ipv6_addr));
			break;
		}
	}
#ifdef FEATURE_L2TP
	if ((ipacm_mpdn_enable == false) && (ipacm_l2tp_enable == IPACM_L2TP) || (ipacm_l2tp_enable == IPACM_L2TP_E2E))
	{
		for(it_mapping = m_l2tp_vlan_mapping.begin(); it_mapping != m_l2tp_vlan_mapping.end(); it_mapping++)
		{
			if(strncmp(it_mapping->vlan_iface_name, data->iface_name, sizeof(it_mapping->vlan_iface_name)) == 0)
			{
				IPACMDBG_H("Found vlan iface in l2tp mapping list: %s, l2tp iface: %s\n", it_mapping->vlan_iface_name,
					it_mapping->l2tp_iface_name);
				memcpy(it_mapping->vlan_client_mac, data->mac_addr, sizeof(it_mapping->vlan_client_mac));
				memcpy(it_mapping->vlan_client_ipv6_addr, data->ipv6_addr, sizeof(it_mapping->vlan_client_ipv6_addr));
			}
		}
	}
#endif
	pthread_mutex_unlock(&vlan_l2tp_lock);

	return;
}
#endif

#ifdef FEATURE_VLAN_MPDN

void IPACM_Config::get_vlan_mode_ifaces()
{
	struct ipa_ioc_get_vlan_mode vlan_mode;
	int retval;

	for(int i = 0; i < IPA_VLAN_IF_MAX; i++)
	{
		vlan_mode.iface = static_cast<ipa_vlan_ifaces>(i);
		retval = ioctl(m_fd, IPA_IOC_GET_VLAN_MODE, &vlan_mode);
		if(retval)
		{
			IPACMERR("failed reading vlan mode for %d, error %d\n", i ,retval);
			vlan_devices[i] = 0;
		}
		vlan_devices[i] = vlan_mode.is_vlan_mode;
	}

#if IPA_ETH_API_VER >= 2
	IPACMDBG("modes are EMAC %d, ETH0 %d, ETH1 %d, RNDIS %d, ECM %d\n",
		vlan_devices[IPA_VLAN_IF_EMAC],
		vlan_devices[IPA_VLAN_IF_ETH0],
		vlan_devices[IPA_VLAN_IF_ETH1],
		vlan_devices[IPA_VLAN_IF_RNDIS],
		vlan_devices[IPA_VLAN_IF_ECM]);
#else
	IPACMDBG("modes are EMAC %d, RNDIS %d, ECM %d\n",
		vlan_devices[IPA_VLAN_IF_EMAC],
		vlan_devices[IPA_VLAN_IF_RNDIS],
		vlan_devices[IPA_VLAN_IF_ECM]);
#endif
}

void IPACM_Config::add_vlan_bridge(ipacm_event_data_all *data_all)
{
	uint8_t testmac[IPA_MAC_ADDR_SIZE];
	ipa_bridge_vlan_mapping_info mapping_info;
	bool default_bridge = false;
	struct ifreq ifr;
	int fd;

	memset(testmac, 0, IPA_MAC_ADDR_SIZE * sizeof(uint8_t));
	memset(&mapping_info, 0, sizeof(mapping_info));

	strlcpy(mapping_info.bridge_name, data_all->iface_name, IF_NAME_LEN);

	for(int i = 0; i < IPA_MAX_NUM_BRIDGES; i++)
	{
		if(strcmp(data_all->iface_name, IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_name) == 0)
		{
			IPACMDBG_H("bridge %s already exist with MAC %02x:%02x:%02x:%02x:%02x:%02x, need to update MAC ADDR\n",
				data_all->iface_name, IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[0],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[1],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[2],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[3],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[4],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[5]);
			default_bridge = false;

			if(strcmp(ipa_virtual_iface_name, data_all->iface_name) == 0)
			{
				default_bridge = true;
			}

			if(get_bridge_vlan_mapping(&mapping_info))
			{
				if(default_bridge)
				{
					IPACMDBG_H("default bridge doesn't have vlan mapping\n");
				}
				else
				{
					/* mapping may arrive later and information will be updated then */
					IPACMERR("no bridge vlan mapping found for bridge %s, not adding\n", data_all->iface_name);
					return;
				}
			}


			fd = socket(AF_INET, SOCK_DGRAM, 0);
			if (fd < 0) {
					IPACMERR("get interface name socket create failed\n");
					return;
			}
			memset(&ifr, 0, sizeof(struct ifreq));
			ifr.ifr_addr.sa_family = AF_INET;
			strlcpy(ifr.ifr_name, data_all->iface_name, sizeof(ifr.ifr_name));
			if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
			{
				IPACMERR("unable to retrieve (%s) bridge MAC\n", ifr.ifr_name);
				vlan_bridges[i].bridge_netmask = 0;
				vlan_bridges[i].bridge_ipv4_addr = 0;
				vlan_bridges[i].associate_VID = 0;
				close(fd);
				return;
			}
			memcpy(vlan_bridges[i].bridge_mac,
				ifr.ifr_hwaddr.sa_data,
				sizeof(vlan_bridges[i].bridge_mac));
			IPACMDBG("got bridge MAC using IOCTL\n");
			if(default_bridge)
			{
				memcpy(IPACM_Iface::ipacmcfg->bridge_mac,
					ifr.ifr_hwaddr.sa_data,
					sizeof(IPACM_Iface::ipacmcfg->bridge_mac));

				IPACM_Iface::ipacmcfg->ipa_bridge_enable = true;

				IPACMDBG("set default bridge flag dev %s\n",
					data_all->iface_name);
			}
			close(fd);
			IPACMDBG_H("update bridge %s with MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_name,
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[0],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[1],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[2],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[3],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[4],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[5]);
			return;
		}
		/* no MAC was assigned before i.e. this is the first unused entry*/
		else if(!memcmp(IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac, testmac, sizeof(uint8_t) * IPA_MAC_ADDR_SIZE))
		{
			default_bridge = false;

			if(strcmp(ipa_virtual_iface_name, data_all->iface_name) == 0)
			{
				default_bridge = true;
			}

			if(get_bridge_vlan_mapping(&mapping_info))
			{
				if(default_bridge)
				{
					IPACMDBG_H("default bridge doesn't have vlan mapping\n");
				}
				else
				{
					/* mapping may arrive later and information will be updated then */
					IPACMERR("no bridge vlan mapping found for bridge %s, not adding\n", data_all->iface_name);
					return;
				}
			}

			vlan_bridges[i].bridge_netmask = mapping_info.subnet_mask;
			vlan_bridges[i].bridge_ipv4_addr = mapping_info.bridge_ipv4;
			strlcpy(vlan_bridges[i].bridge_name, data_all->iface_name, IF_NAME_LEN);
			vlan_bridges[i].associate_VID = mapping_info.vlan_id;
			IPACMDBG("bridge (%s) mask 0x%X, address 0x%X, VID %d\n", data_all->iface_name,
				mapping_info.subnet_mask,
				mapping_info.bridge_ipv4,
				mapping_info.vlan_id);

			fd = socket(AF_INET, SOCK_DGRAM, 0);
			if (fd < 0) {
					IPACMERR("get interface name socket create failed\n");
					return;
			}
			memset(&ifr, 0, sizeof(struct ifreq));
			ifr.ifr_addr.sa_family = AF_INET;
			strlcpy(ifr.ifr_name, data_all->iface_name, sizeof(ifr.ifr_name));
			if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
			{
				IPACMERR("unable to retrieve (%s) bridge MAC\n", ifr.ifr_name);
				vlan_bridges[i].bridge_netmask = 0;
				vlan_bridges[i].bridge_ipv4_addr = 0;
				vlan_bridges[i].associate_VID = 0;
				close(fd);
				return;
			}
			memcpy(vlan_bridges[i].bridge_mac,
				ifr.ifr_hwaddr.sa_data,
				sizeof(vlan_bridges[i].bridge_mac));
			IPACMDBG("got bridge MAC using IOCTL\n");
			if(default_bridge)
			{
				memcpy(IPACM_Iface::ipacmcfg->bridge_mac,
					ifr.ifr_hwaddr.sa_data,
					sizeof(IPACM_Iface::ipacmcfg->bridge_mac));

				IPACM_Iface::ipacmcfg->ipa_bridge_enable = true;

				IPACMDBG("set default bridge flag dev %s\n",
					data_all->iface_name);
			}
			close(fd);
			IPACMDBG_H("added bridge named %s, MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_name,
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[0],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[1],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[2],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[3],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[4],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[5]);
			return;
		}
	}
	IPACMERR("couldn't find an empty cell for new bridge\n");
}

ipacm_bridge *IPACM_Config::get_vlan_bridge(char *name)
{
	for(int i = 0; i < IPA_MAX_NUM_BRIDGES; i++)
	{
		if(strcmp(name, IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_name) == 0)
		{
			IPACMDBG_H("found bridge %s with MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_name,
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[0],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[1],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[2],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[3],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[4],
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[5]);

			return &IPACM_Iface::ipacmcfg->vlan_bridges[i];
		}
	}

	IPACMDBG_H("no bridge %s exists\n", name);
	return NULL;
}


ipacm_bridge *IPACM_Config::get_vlan_bridge_from_vid(uint16_t vlan_id)
{
	for(int i = 0; i < IPA_MAX_NUM_BRIDGES; i++)
	{
		if(vlan_id == IPACM_Iface::ipacmcfg->vlan_bridges[i].associate_VID)
		{
			IPACMDBG_H("found bridge %s with associate_VID %d\n",
				IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_name,
				IPACM_Iface::ipacmcfg->vlan_bridges[i].associate_VID);

			return &IPACM_Iface::ipacmcfg->vlan_bridges[i];
		}
	}

	IPACMDBG_H("no bridge with vlan-id %d exists\n", vlan_id);
	return NULL;
}

bool IPACM_Config::is_added_vlan_iface(char *iface_name)
{
	list<vlan_iface_info>::iterator it_vlan;
	bool ret = false;

	if (!iface_in_vlan_mode(iface_name))
	{
		IPACMDBG_H("Iface not in VLAN mode: %s\n", iface_name);
		return false;
	}

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return false;
	}

	for(it_vlan = m_vlan_iface.begin(); it_vlan != m_vlan_iface.end(); it_vlan++)
	{
		if(strncmp(it_vlan->vlan_iface_name, iface_name, sizeof(it_vlan->vlan_iface_name)) == 0)
		{
			IPACMDBG_H("Found vlan iface in vlan list: %s\n", it_vlan->vlan_iface_name);
			ret = true;
			break;
		}
	}

	pthread_mutex_unlock(&vlan_l2tp_lock);

	return ret;
}

bool IPACM_Config::iface_in_vlan_mode(const char *interfaceName) {
	IPACMDBG_H("iface %s is getting checked if it is vlan\n", interfaceName);
	string nameToCheck = getNameForVlanQuery(interfaceName);
#if IPA_ETH_API_VER >= 2
	/**
	 *  Differentiate Dual NIC mode where interface name is either
	 *  [eth0|eth1] and legacy while where name is always "eth0".
	 */
	if (strstr(nameToCheck.c_str(), "eth0")) {
		IPACMDBG("eth0 vlan mode %d\n", vlan_devices[IPA_VLAN_IF_ETH0]);
		IPACMDBG("eth0 vlan spcl mode %d\n", IsSpclIface(nameToCheck.c_str()));
		return vlan_devices[IPA_VLAN_IF_ETH0] || vlan_devices[IPA_VLAN_IF_EMAC] ||
			(IPACM_Iface::ipacmcfg->ipacm_emesh_enable && IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 2 && IsSpclIface(nameToCheck.c_str()));
	}
	if (strstr(nameToCheck.c_str(), "eth1")) {
		IPACMDBG("eth1 vlan mode %d\n", vlan_devices[IPA_VLAN_IF_ETH1]);
		return vlan_devices[IPA_VLAN_IF_ETH1] || vlan_devices[IPA_VLAN_IF_EMAC];
	}
#endif
	if (strstr(nameToCheck.c_str(), "eth") || strstr(nameToCheck.c_str(), "macsec")) {
		IPACMDBG("eth vlan mode %d\n", vlan_devices[IPA_VLAN_IF_EMAC]);
		return vlan_devices[IPA_VLAN_IF_EMAC];
	}
	if (strstr(nameToCheck.c_str(), "rndis")) {
		IPACMDBG("rndis vlan mode %d\n", vlan_devices[IPA_VLAN_IF_RNDIS]);
		return vlan_devices[IPA_VLAN_IF_RNDIS];
	}
	if (strstr(nameToCheck.c_str(), "ecm")) {
		IPACMDBG("ecm vlan mode %d\n", vlan_devices[IPA_VLAN_IF_ECM]);
		return vlan_devices[IPA_VLAN_IF_ECM];
	}
#ifdef IPA_VLAN_IF_WLAN
	if (strstr(nameToCheck.c_str(), "ath")) {
		IPACMDBG("ath vlan mode %d\n", vlan_devices[IPA_VLAN_IF_WLAN]);
		return (vlan_devices[IPA_VLAN_IF_WLAN] ||
			((IPACM_Iface::ipacmcfg->ipacm_emesh_enable && IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 2) &&
			is_svap_related(nameToCheck.c_str())) || IsWlanIfVlan(nameToCheck.c_str()));
	}
	if (strstr(nameToCheck.c_str(), "wlan")) {
		IPACMDBG("wlan vlan mode %d\n", vlan_devices[IPA_VLAN_IF_WLAN]);
		return (vlan_devices[IPA_VLAN_IF_WLAN] ||
			((IPACM_Iface::ipacmcfg->ipacm_emesh_enable &&
			  IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 2) &&
			 is_svap_related(nameToCheck.c_str())) ||
			IsWlanIfVlan(nameToCheck.c_str()));
	}
#endif

	IPACMDBG_H("iface %s did not match any known ifaces\n", nameToCheck.c_str());
	return false;
}

int IPACM_Config::get_iface_vlan_ids(char *phys_iface_name, uint16_t *Ids)
{
	list<vlan_iface_info>::iterator it_vlan;
	int cnt = 0;

	if(!Ids)
	{
		IPACMERR("got NULL Ids array\n");
		return IPACM_FAILURE;
	}

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return false;
	}

	for(it_vlan = m_vlan_iface.begin(); it_vlan != m_vlan_iface.end() && cnt < IPA_MAX_NUM_OFFLOAD_VLANS; it_vlan++)
	{
		if(strstr(it_vlan->vlan_iface_name, phys_iface_name))
		{
			IPACMDBG_H("Found vlan iface in vlan list: %s\n", it_vlan->vlan_iface_name);
			Ids[cnt] = it_vlan->vlan_id;
			cnt++;
		}
	}

	pthread_mutex_unlock(&vlan_l2tp_lock);

	IPACMDBG_H("found %d vlan interfaces for dev %s\n", cnt, phys_iface_name);

	while(cnt < IPA_MAX_NUM_OFFLOAD_VLANS)
	{
		Ids[cnt] = 0;
		cnt++;
	}

	return IPACM_SUCCESS;
}

int IPACM_Config::get_vlan_id(char *iface_name, uint16_t *vlan_id)
{
	list<vlan_iface_info>::iterator it_vlan;
	int ret = IPACM_FAILURE;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return IPACM_FAILURE;
	}

	for(it_vlan = m_vlan_iface.begin(); it_vlan != m_vlan_iface.end(); it_vlan++)
	{
		if(strncmp(it_vlan->vlan_iface_name, iface_name, sizeof(it_vlan->vlan_iface_name)) == 0)
		{
			IPACMDBG_H("Found vlan iface in vlan list: %s\n", it_vlan->vlan_iface_name);
			*vlan_id = it_vlan->vlan_id;
			ret = IPACM_SUCCESS;
			break;
		}
	}

	pthread_mutex_unlock(&vlan_l2tp_lock);

	return ret;
}
#endif

#if defined(FEATURE_L2TP)
void IPACM_Config::add_l2tp_vlan_mapping(ipa_ioc_l2tp_vlan_mapping_info *data)
{
	list<l2tp_vlan_mapping_info>::iterator it_mapping;
	list<vlan_iface_info>::iterator it_vlan;
	l2tp_vlan_mapping_info new_mapping;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("L2tp iface: %s session id: %d vlan iface: %s \n",
		data->l2tp_iface_name, data->l2tp_session_id, data->vlan_iface_name);
	for(it_mapping = m_l2tp_vlan_mapping.begin(); it_mapping != m_l2tp_vlan_mapping.end(); it_mapping++)
	{
		if(strncmp(data->l2tp_iface_name, it_mapping->l2tp_iface_name,
			sizeof(data->l2tp_iface_name)) == 0)
		{
			IPACMERR("L2tp mapping was added before mapped to vlan %s.\n", it_mapping->vlan_iface_name);
			pthread_mutex_unlock(&vlan_l2tp_lock);
			return;
		}
	}

	AddNatIfaces(data->l2tp_iface_name);
	IPACMDBG_H("Add l2tp iface %s to nat ifaces.\n", data->l2tp_iface_name);

	memset(&new_mapping, 0, sizeof(new_mapping));
	strlcpy(new_mapping.l2tp_iface_name, data->l2tp_iface_name,
		sizeof(new_mapping.l2tp_iface_name));
	strlcpy(new_mapping.vlan_iface_name, data->vlan_iface_name,
		sizeof(new_mapping.vlan_iface_name));
	new_mapping.l2tp_session_id = data->l2tp_session_id;
#ifdef IPA_L2TP_TUNNEL_UDP
	IPACMDBG_H("L2tp tunnel type %d: Source Port: %d Dest Port: %d MTU: %d\n",
	data->tunnel_type, data->src_port, data->dst_port, data->mtu);
	new_mapping.tunnel_type = data->tunnel_type;
	if (new_mapping.tunnel_type == IPA_L2TP_TUNNEL_UDP)
	{
		new_mapping.src_port = data->src_port;
		new_mapping.dst_port = data->dst_port;
		new_mapping.mtu = (data->mtu ? data->mtu : IPA_L2TP_UDP_DEFAULT_MTU_SIZE);
	}
#endif
	for(it_vlan = m_vlan_iface.begin(); it_vlan != m_vlan_iface.end(); it_vlan++)
	{
		if(strncmp(it_vlan->vlan_iface_name, data->vlan_iface_name, sizeof(it_vlan->vlan_iface_name)) == 0)
		{
			IPACMDBG_H("Found vlan iface with id %d\n", it_vlan->vlan_id);
			new_mapping.vlan_id = it_vlan->vlan_id;
			memcpy(new_mapping.vlan_iface_ipv6_addr, it_vlan->vlan_iface_ipv6_addr,
				sizeof(new_mapping.vlan_iface_ipv6_addr));
			memcpy(new_mapping.vlan_client_mac, it_vlan->vlan_client_mac,
				sizeof(new_mapping.vlan_client_mac));
			memcpy(new_mapping.vlan_client_ipv6_addr, it_vlan->vlan_client_ipv6_addr,
				sizeof(new_mapping.vlan_client_ipv6_addr));
			break;
		}
	}
	m_l2tp_vlan_mapping.push_front(new_mapping);
	pthread_mutex_unlock(&vlan_l2tp_lock);

	return;
}

void IPACM_Config::del_l2tp_vlan_mapping(ipa_ioc_l2tp_vlan_mapping_info *data)
{
	list<l2tp_vlan_mapping_info>::iterator it;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("L2tp iface: %s session id: %d vlan iface: %s \n",
		data->l2tp_iface_name, data->l2tp_session_id, data->vlan_iface_name);
	for(it = m_l2tp_vlan_mapping.begin(); it != m_l2tp_vlan_mapping.end(); it++)
	{
		if(strncmp(data->l2tp_iface_name, it->l2tp_iface_name,
			sizeof(data->l2tp_iface_name)) == 0)
		{
			IPACMDBG_H("Found l2tp iface mapped to vlan %s.\n", it->vlan_iface_name);
			if(strncmp(data->vlan_iface_name, it->vlan_iface_name,
				sizeof(data->vlan_iface_name)) == 0)
			{
				m_l2tp_vlan_mapping.erase(it);
				DelNatIfaces(data->l2tp_iface_name);
				IPACMDBG_H("Del l2tp iface %s to nat ifaces.\n", data->l2tp_iface_name);
			}
			else
			{
				IPACMERR("Incoming mapping is incorrect.\n");
			}
			break;
		}
	}
	pthread_mutex_unlock(&vlan_l2tp_lock);

	return;
}

int IPACM_Config::get_vlan_l2tp_mapping(char *client_iface, l2tp_vlan_mapping_info& info)
{
	list<l2tp_vlan_mapping_info>::iterator it_mapping;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Incoming client iface name: %s\n", client_iface);

	for(it_mapping = m_l2tp_vlan_mapping.begin(); it_mapping != m_l2tp_vlan_mapping.end(); it_mapping++)
	{
		if(strncmp(client_iface, it_mapping->l2tp_iface_name,
			strlen(client_iface)) == 0)
		{
			IPACMDBG_H("Found vlan-l2tp mapping.\n");
			info = *it_mapping;
			pthread_mutex_unlock(&vlan_l2tp_lock);
			return IPACM_SUCCESS;
		}
	}

	pthread_mutex_unlock(&vlan_l2tp_lock);
	return IPACM_FAILURE;
}
#endif

void IPACM_Config::ip_pass_config_update(ipa_ioc_pdn_config *pdn_config)
{
	int indx;
	int bridge_index;
	ipacm_bridge *bridge = NULL;

	if(pthread_mutex_lock(&ip_pass_mpdn_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	if (pdn_config->enable)
	{
		indx = get_free_ip_pass_pdn_index(pdn_config->dev_name);
		if (indx < MAX_NUM_IP_PASS_MPDN)
		{
			IPACMDBG_H("Enable IP Passthrough: table index %d\n", indx);
			ip_pass_mpdn_table[indx].valid_entry = true;
			memcpy(ip_pass_mpdn_table[indx].ip_pass_mac,
				pdn_config->u.passthrough_cfg.client_mac_addr, IPA_MAC_ADDR_SIZE);
			ip_pass_mpdn_table[indx].ip_pass_dev_type =
				pdn_config->u.passthrough_cfg.device_type;
			ip_pass_mpdn_table[indx].ip_pass_skip_nat =
				pdn_config->u.passthrough_cfg.skip_nat;
			ip_pass_mpdn_table[indx].ip_pass_pdn_ip_addr =
				htonl(pdn_config->u.passthrough_cfg.pdn_ip_addr);
			ip_pass_mpdn_table[indx].vlan_id = pdn_config->u.passthrough_cfg.vlan_id;
			strlcpy(ip_pass_mpdn_table[indx].dev_name,
			pdn_config->dev_name, IPA_RESOURCE_NAME_MAX);
			ip_pass_mpdn_table[indx].is_default_pdn = pdn_config->default_pdn;

			/*	This is to avoid installing IPA private subnet Filter rules in case of
				IPPT without NAT scenario to avoid packets taking SW path because we
				are installing private subnet rules with public IP assigned to bridge
				since bridge has no longer the private IP assigned. */

			if(pdn_config->u.passthrough_cfg.skip_nat)
			{
				bridge = IPACM_Iface::ipacmcfg->get_vlan_bridge_from_vid(pdn_config->u.passthrough_cfg.vlan_id);
				if (!bridge)
				{
					IPACMDBG_H("bridge is NULL with vid (%d), ignoring!\n",
						pdn_config->u.passthrough_cfg.vlan_id);
				}
				else
				{
					if (IPACM_Iface::ipa_get_if_index(bridge->bridge_name, &bridge_index) == IPACM_SUCCESS)
					{
						if(IPACM_Iface::ipacmcfg->DelPrivateSubnetByIfIndex(bridge_index) == true)
						{
							IPACMDBG_H("Deleted IPACM bridge private subnet_addr for %s\n", bridge->bridge_name);
						}
						else
						{
							IPACMERR("Can't Delete IPACM private subnet_addr for %s\n", bridge->bridge_name);
						}
					}
					else
					{
						IPACMERR("get interface index failed for %s\n", bridge->bridge_name);
					}
				}
			}
		}
		else
			IPACMERR("IP Passthrough supports only 15 PDNs\n");
	}
	else
	{
		indx = get_ip_pass_pdn_index(pdn_config);
		if (indx < MAX_NUM_IP_PASS_MPDN)
		{
			/* Reset the configuration */
			IPACMDBG_H("Reset IP Passthrough config: table index: %d devic_type: %d and PDN IP: 0x%x!\n",
				indx, pdn_config->pdn_cfg_type, htonl(pdn_config->u.passthrough_cfg.pdn_ip_addr));
			ip_pass_mpdn_table[indx].valid_entry = false;
			ip_pass_mpdn_table[indx].ip_pass_skip_nat = false;
			ip_pass_mpdn_table[indx].ip_pass_dev_type =
				IPACM_CLIENT_DEVICE_MAX;
			memset(ip_pass_mpdn_table[indx].ip_pass_mac, 0, IPA_MAC_ADDR_SIZE);
			ip_pass_mpdn_table[indx].vlan_id = 0;
			ip_pass_mpdn_table[indx].ip_pass_pdn_ip_addr = false;
			memset(ip_pass_mpdn_table[indx].dev_name, 0, IPA_RESOURCE_NAME_MAX);
			ip_pass_mpdn_table[indx].is_default_pdn = false;
		}
		else
			IPACMERR("IP Passthrough PDN not found\n");
	}

	pthread_mutex_unlock(&ip_pass_mpdn_lock);
}

void IPACM_Config::ip_collision_config_update(ipa_ioc_pdn_config *pdn_config)
{
	int indx;

	if(pthread_mutex_lock(&ip_pass_mpdn_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}
	if (pdn_config->enable)
	{
		indx = get_free_ip_collision_pdn_index(pdn_config->dev_name);
		if (indx < MAX_NUM_IP_PASS_MPDN)
		{
			IPACMDBG_H("Enable IP Collision: table index %d, default_pdn: %d\n", indx, pdn_config->default_pdn);
			strlcpy(ip_collision_mpdn_table[indx].dev_name,
			pdn_config->dev_name, IPA_RESOURCE_NAME_MAX);
			ip_collision_mpdn_table[indx].is_default_pdn = pdn_config->default_pdn;
			ip_collision_mpdn_table[indx].ip_collision_pdn_ip_addr =
				htonl(pdn_config->u.collison_cfg.pdn_ip_addr);
			ip_collision_mpdn_table[indx].vlan_id = pdn_config->u.collison_cfg.vlan_id;
			ip_collision_mpdn_table[indx].valid_entry = true;
		}
		else
			IPACMERR("IP Collision supports only 15 PDNs\n");
	}
	else
	{
	   indx = get_ip_collision_pdn_index(pdn_config);
		if (indx < MAX_NUM_IP_PASS_MPDN)
		{
			/* Reset the configuration */
			IPACMDBG("Disable IP collision config: table index: %d PDN IP: 0x%x Vlan ID: %u\n",
			indx, htonl(pdn_config->u.passthrough_cfg.pdn_ip_addr), pdn_config->u.collison_cfg.vlan_id);
			ip_collision_mpdn_table[indx].is_default_pdn = 0;
			ip_collision_mpdn_table[indx].ip_collision_pdn_ip_addr = 0;
			ip_collision_mpdn_table[indx].vlan_id = 0;
			ip_collision_mpdn_table[indx].valid_entry = false;
		}
		else
			IPACMERR("IP Collision PDN not found\n");
	}
	pthread_mutex_unlock(&ip_pass_mpdn_lock);
}

#ifdef FEATURE_STATIC_POLICY
void IPACM_Config::pdn_dscp_config_update(ipa_ioc_pdn_dscp_map_info *pdn_dscp_config)
{
	int indx;
	ipacm_cmd_q_data evt_data;
	ipacm_event_pdn_dscp_info *pdn_dscp_data;
	ipacm_event_pdn_mux_info *data_pdn_mux_info;
	struct ipa_ioc_pdn_dscp_map_info pdn_dscp_map_info;

	if(pthread_mutex_lock(&pdn_dscp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		goto fail;
	}

	/* On receiving the pdn and dscp value from user space through IPA driver, pdn name and
         * dscp value is stored in the first free entry available and status is set to 1 if it
         * is an add command.
         *
         * If it is a del command, all the fields of pdn_dscp_table of that particular index
         * will be reset.
         */

	if (pdn_dscp_config->add)
	{
		indx = get_free_pdn_dscp_index(pdn_dscp_config->pdn_name[0]);
		if (indx < IPA_UC_MAX_PDN_DSCP_VAL)
		{
			strlcpy(pdn_dscp_table[indx].pdn_name,
				pdn_dscp_config->pdn_name[0], IPA_RESOURCE_NAME_MAX);
			pdn_dscp_table[indx].status = 1;
			pdn_dscp_table[indx].mux_id = 0;
			pdn_dscp_table[indx].dscp_val = pdn_dscp_config->pdn_dscp_map[0];
			IPACMDBG_H("Updated PDN DSCP config for pdn_name:%s at %d with "
				"dscp_val:%d\n", pdn_dscp_table[indx].pdn_name,
				indx, pdn_dscp_config->pdn_dscp_map[0]);

			data_pdn_mux_info = (ipacm_event_pdn_mux_info *)malloc
				(sizeof(ipacm_event_pdn_mux_info));
			if(data_pdn_mux_info == NULL)
			{
				IPACMERR("unable to allocate memory for event data_pdn_mux_info\n");
				pthread_mutex_unlock(&pdn_dscp_lock);
				return;
			}

			memset(data_pdn_mux_info, 0, sizeof(ipacm_event_pdn_mux_info));
			data_pdn_mux_info->indx = indx;
			strlcpy(data_pdn_mux_info->pdn_name, pdn_dscp_table[indx].pdn_name,
				sizeof(data_pdn_mux_info->pdn_name));

			IPACMDBG_H("Posting IPA_PDN_MUX_ID_UPDATE with pdn_name:%s indx:%d\n",
				data_pdn_mux_info->pdn_name, indx);

			evt_data.event = IPA_PDN_MUX_ID_UPDATE;
			evt_data.evt_data = data_pdn_mux_info;
			IPACM_EvtDispatcher::PostEvt(&evt_data);
		}
	}
	else
	{
		indx = get_pdn_dscp_index(pdn_dscp_config->pdn_name[0]);
		if (indx < IPA_UC_MAX_PDN_DSCP_VAL)
		{
			if(pdn_dscp_table[indx].status == 2)
			{
				pdn_dscp_data = (ipacm_event_pdn_dscp_info *)malloc
					(sizeof(ipacm_event_pdn_dscp_info));
				if(!pdn_dscp_data)
				{
					IPACMERR("unable to allocate memory for pdn_dscp_data\n");
					pthread_mutex_unlock(&pdn_dscp_lock);
					goto fail;
				}

				memset(pdn_dscp_data, 0, sizeof(ipacm_event_pdn_dscp_info));
				pdn_dscp_data->mux_id = pdn_dscp_table[indx].mux_id;
				IPACMDBG_H("Posting IPA_PDN_DSCP_UPDATE_EVENT event!\n");
				evt_data.event = IPA_PDN_DSCP_UPDATE_EVENT;
				evt_data.evt_data = pdn_dscp_data;
				IPACM_EvtDispatcher::PostEvt(&evt_data);
			}

			memset(&pdn_dscp_map_info, 0, sizeof(pdn_dscp_map_info));
			pdn_dscp_map_info.pdn_dscp_map
				[IPACM_Iface::ipacmcfg->pdn_dscp_table[indx].mux_id] = 255;

			m_fd = open(DEVICE_NAME, O_RDWR);
			if (0 > m_fd)
			{
				IPACMERR("Failed opening %s.\n", DEVICE_NAME);
			}

			if(0 != ioctl(m_fd, IPA_IOC_UPDATE_PDN_DSCP_MAPPING, &pdn_dscp_map_info))
			{
				IPACMERR("ioctl to IPA driver failed for setting "
					"PDN-DSCP Mapping\n");
			}

			close(m_fd);

			/* Reset the configuration */
			IPACMDBG_H("Reset PDN DSCP config for pdn_name:%s at %d\n",
				pdn_dscp_table->pdn_name, indx);
			pdn_dscp_table[indx].status = 0;
			pdn_dscp_table[indx].dscp_val = 255;
			pdn_dscp_table[indx].mux_id = 0;
			memset(pdn_dscp_table[indx].pdn_name, 0, IPA_RESOURCE_NAME_MAX);
		}
	}

	pthread_mutex_unlock(&pdn_dscp_lock);
fail:
	return;
}
#endif

#if defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
void IPACM_Config::update_socksv5_client_v6_addr(uint32_t* ipv6_addr)
{
	IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[0] = ipv6_addr[0];
	IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[1] = ipv6_addr[1];
	IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[2] = ipv6_addr[2];
	IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[3] = ipv6_addr[3];
	IPACMDBG_H("socksv5_client_v6_addr addr:0x%x:%x:%x:%x\n",
		IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[0],
		IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[1],
		IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[2],
		IPACM_Iface::ipacmcfg->socksv5_client_v6_addr[3]);
	return ;
}

void IPACM_Config::add_socksv5_conn(ipa_socksv5_msg *add_socksv5_info)
{
	list<socksv5_conn_info>::iterator it_mapping;
	socksv5_conn_info new_mapping;
	int i = 0;
	bool SendVlanPDNUpEvent = true;
	int pdn_ipv6_in_use_temp = 0;

	if(pthread_mutex_lock(&socksv5_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	/* print the info */
	if(add_socksv5_info->ul_in.ip_type == IPA_IP_v4)
	{
		IPACMDBG_H("ul-in: ipv4 src:0x%X dst:0x%X\n",
		add_socksv5_info->ul_in.ipv4_src,
		add_socksv5_info->ul_in.ipv4_dst);
	}
	else
	{
		IPACMDBG_H("ul-in: ipv6 src address: 0x%x:%x:%x:%x\n",
		add_socksv5_info->ul_in.ipv6_src[0],
		add_socksv5_info->ul_in.ipv6_src[1],
		add_socksv5_info->ul_in.ipv6_src[2],
		add_socksv5_info->ul_in.ipv6_src[3]);
		IPACMDBG_H("ul-in: ipv6 dst address: 0x%x:%x:%x:%x\n",
		add_socksv5_info->ul_in.ipv6_dst[0],
		add_socksv5_info->ul_in.ipv6_dst[1],
		add_socksv5_info->ul_in.ipv6_dst[2],
		add_socksv5_info->ul_in.ipv6_dst[3]);
	}
	IPACMDBG_H("ul-in: src_port:%d dst_port:%d\n",
		add_socksv5_info->ul_in.src_port,
		add_socksv5_info->ul_in.dst_port);
	/* print the info */
	if(add_socksv5_info->dl_in.ip_type == IPA_IP_v4)
	{
		IPACMDBG_H("dl-in: ipv4 src:0x%X dst:0x%X\n",
		add_socksv5_info->dl_in.ipv4_src,
		add_socksv5_info->dl_in.ipv4_dst);
	}
	else
	{
		IPACMDBG_H("dl-in: ipv6 src address: 0x%x:%x:%x:%x\n",
		add_socksv5_info->dl_in.ipv6_src[0],
		add_socksv5_info->dl_in.ipv6_src[1],
		add_socksv5_info->dl_in.ipv6_src[2],
		add_socksv5_info->dl_in.ipv6_src[3]);
		IPACMDBG_H("dl-in: ipv6 dst address: 0x%x:%x:%x:%x\n",
		add_socksv5_info->dl_in.ipv6_dst[0],
		add_socksv5_info->dl_in.ipv6_dst[1],
		add_socksv5_info->dl_in.ipv6_dst[2],
		add_socksv5_info->dl_in.ipv6_dst[3]);
	}
	IPACMDBG_H("dl-in: src_port:%d dst_port:%d\n",
		add_socksv5_info->dl_in.src_port,
		add_socksv5_info->dl_in.dst_port);

	IPACMDBG_H("handle %d \n", add_socksv5_info->handle);

	/* check connection existed or not */
	for(it_mapping = socksv5_conn.begin(); it_mapping != socksv5_conn.end(); it_mapping++)
	{
		if(add_socksv5_info->dl_in.ip_type == IPA_IP_MAX)
		{
			IPACMERR("Invalid entry \n");
			goto fail;
		}
		else if(add_socksv5_info->dl_in.ip_type == IPA_IP_v4)
		{
			IPACMDBG_H("compare: ipv4 add_socksv5_info:0x%X it_mapping:0x%X\n",
				add_socksv5_info->dl_in.ipv4_dst,
				it_mapping->conn_info.dl_in.ipv4_dst);
			if (add_socksv5_info->dl_in.ipv4_dst == it_mapping->conn_info.dl_in.ipv4_dst)
			{
				IPACMDBG_H(" ipv4 same dst address\n");
				/* see this dst-ipv4 already */
				if ((add_socksv5_info->dl_in.ipv4_src == it_mapping->conn_info.dl_in.ipv4_src) &&
					(add_socksv5_info->dl_in.src_port == it_mapping->conn_info.dl_in.src_port) &&
					(add_socksv5_info->dl_in.dst_port == it_mapping->conn_info.dl_in.dst_port))
				{
					IPACMDBG_H("This connection was added before with index %d\n",
						it_mapping->conn_info.dl_in.index);
					goto fail;
				}
			}
		}
		else
		{
			if ((add_socksv5_info->dl_in.ipv6_src[0] == it_mapping->conn_info.dl_in.ipv6_src[0]) &&
				(add_socksv5_info->dl_in.ipv6_src[1] == it_mapping->conn_info.dl_in.ipv6_src[1]) &&
				(add_socksv5_info->dl_in.ipv6_src[2] == it_mapping->conn_info.dl_in.ipv6_src[2]) &&
				(add_socksv5_info->dl_in.ipv6_src[3] == it_mapping->conn_info.dl_in.ipv6_src[3]) &&
				(add_socksv5_info->dl_in.ipv6_dst[0] == it_mapping->conn_info.dl_in.ipv6_dst[0]) &&
				(add_socksv5_info->dl_in.ipv6_dst[1] == it_mapping->conn_info.dl_in.ipv6_dst[1]) &&
				(add_socksv5_info->dl_in.ipv6_dst[2] == it_mapping->conn_info.dl_in.ipv6_dst[2]) &&
				(add_socksv5_info->dl_in.ipv6_dst[3] == it_mapping->conn_info.dl_in.ipv6_dst[3]))
			{
				if ((add_socksv5_info->dl_in.src_port == it_mapping->conn_info.dl_in.src_port) &&
					(add_socksv5_info->dl_in.dst_port == it_mapping->conn_info.dl_in.dst_port))
				{
						IPACMERR("This connection was added before with index %d\n",
						it_mapping->conn_info.dl_in.index);
						goto fail;
				}
			}
		}
	}
	/* send vlan-pdn up */
	if (add_socksv5_info->dl_in.ip_type == IPA_IP_v4) {
		for ( i=0; i < socksv5_v4_pdn;i++)
		{
			if (add_socksv5_info->dl_in.ipv4_dst == pdn_ipv4[i])
			{
				IPACMERR(" PDN enry %d already added for 0x%X \n",
				i, add_socksv5_info->dl_in.ipv4_dst);
				SendVlanPDNUpEvent = false;
				break;
			}
		}
	}
	else if (add_socksv5_info->dl_in.ip_type == IPA_IP_v6)
	{
		for (i=0; i < socksv5_v6_pdn; i++)
		{
			if ((add_socksv5_info->dl_in.ipv6_dst[0] == pdn_ipv6[i][0])
				&& (add_socksv5_info->dl_in.ipv6_dst[1] == pdn_ipv6[i][1]))
			{
				IPACMERR(" PDN enry %d already add for prefix:0x%X:0x%X \n",
				i, add_socksv5_info->dl_in.ipv6_dst[0],
				add_socksv5_info->dl_in.ipv6_dst[1]);
				SendVlanPDNUpEvent = false;
				/* update the ipv6 */
				pdn_ipv6[i][2] = add_socksv5_info->dl_in.ipv6_dst[2];
				pdn_ipv6[i][3] = add_socksv5_info->dl_in.ipv6_dst[3];
				/* increase v6 in_use ref count */
				pdn_ipv6_in_use[i]++;
				break;
			}
		}
	}

	if (SendVlanPDNUpEvent == true)
	{
		/* check if reaching max, or cache it */
		if (add_socksv5_info->dl_in.ip_type == IPA_IP_v4)
		{
			if (socksv5_v4_pdn < IPA_MAX_NUM_HW_PDNS)
			{
				pdn_ipv4[socksv5_v4_pdn] = add_socksv5_info->dl_in.ipv4_dst;
				post_socksv5_add_vlan_evt(IPA_IP_v4, add_socksv5_info->dl_in.ipv4_dst, NULL);
				IPACMDBG_H(" ADD 0x%X to PDN entry %d, total %d\n",
				add_socksv5_info->dl_in.ipv4_dst, socksv5_v4_pdn, socksv5_v4_pdn+1);
				socksv5_v4_pdn++;
			}
			else
			{
				IPACMERR("This connection exceed max pdn support %d \n",
					IPA_MAX_NUM_HW_PDNS);
					goto fail;
			}
		}
		else if (add_socksv5_info->dl_in.ip_type == IPA_IP_v6)
		{
			if (socksv5_v6_pdn < IPA_MAX_NUM_HW_PDNS)
			{
				pdn_ipv6[socksv5_v6_pdn][0] = add_socksv5_info->dl_in.ipv6_dst[0];
				pdn_ipv6[socksv5_v6_pdn][1] = add_socksv5_info->dl_in.ipv6_dst[1];
				pdn_ipv6[socksv5_v6_pdn][2] = add_socksv5_info->dl_in.ipv6_dst[2];
				pdn_ipv6[socksv5_v6_pdn][3] = add_socksv5_info->dl_in.ipv6_dst[3];
				post_socksv5_add_vlan_evt(IPA_IP_v6, NULL, add_socksv5_info->dl_in.ipv6_dst);
				IPACMDBG_H(" ADD 0x%X:%X to PDN entry %d, total %d\n",
				add_socksv5_info->dl_in.ipv6_dst[0],
				add_socksv5_info->dl_in.ipv6_dst[1],
				socksv5_v6_pdn, socksv5_v6_pdn+1);
				/* start to use this ipv6 */
				pdn_ipv6_in_use[socksv5_v6_pdn] = 1;
				socksv5_v6_pdn++;
			}
			else
			{
				IPACMERR("This connection exceed max pdn support %d \n",
					IPA_MAX_NUM_HW_PDNS);
					goto fail;
			}
		}
	}

	/* Insert to the list*/
	memset(&new_mapping, 0, sizeof(new_mapping));
	memcpy(&new_mapping.conn_info, add_socksv5_info, sizeof(new_mapping.conn_info));

	IPACMDBG_H("ipv4 0x%X it_mapping:0x%X\n",
				new_mapping.conn_info.dl_in.ipv4_dst);

	socksv5_conn.push_front(new_mapping);

	/* push event for v6-ct to add the entry */
	post_socksv5_evt(add_socksv5_info, true);

	/* update the total_pdn_ipv6_in_use */
	for (i=0; i < socksv5_v6_pdn; i++)
	{
		if (pdn_ipv6_in_use[i] > 0)
		{
			pdn_ipv6_in_use_temp ++;
			IPACMDBG_H(" pdn_ipv6_in_use entry %d, ref %d, total\n", i, pdn_ipv6_in_use[i], pdn_ipv6_in_use_temp);
		}
	}

	/* if pdn_ipv6_in_use_temp != total_pdn_ipv6_in_use */
	if (pdn_ipv6_in_use_temp > total_pdn_ipv6_in_use)
	{
		IPACMDBG_H(" have new ipv6-socksv5: old %d, new %d\n",total_pdn_ipv6_in_use, pdn_ipv6_in_use_temp);
		total_pdn_ipv6_in_use = pdn_ipv6_in_use_temp;
		/* send v6-update event */
		post_socksv5_v6_evt();
	}

fail:
	pthread_mutex_unlock(&socksv5_lock);
	return;
}


void IPACM_Config::del_socksv5_conn(uint32_t *socksv5_handle)
{
	list<socksv5_conn_info>::iterator it_mapping;
	int i = 0;
	int pdn_ipv6_in_use_temp = 0;

	/* print the info */
	IPACMDBG_H("deleting the socksv5 conn handle %d\n",
		*socksv5_handle);

	if(pthread_mutex_lock(&socksv5_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	/* find the entry and clean up*/
	for(it_mapping = socksv5_conn.begin(); it_mapping != socksv5_conn.end(); it_mapping++)
	{
		if(it_mapping->conn_info.handle == *socksv5_handle)
		{
			IPACMDBG_H("Found the handle matched (%d)\n",
				it_mapping->conn_info.handle);

			/* decrease v6 in_use ref count */
			if (it_mapping->conn_info.dl_in.ip_type == IPA_IP_v6)
			{
				for (i=0; i < socksv5_v6_pdn; i++)
				{
					if ((it_mapping->conn_info.dl_in.ipv6_dst[0] == pdn_ipv6[i][0])
						&& (it_mapping->conn_info.dl_in.ipv6_dst[1] == pdn_ipv6[i][1]))
					{
						IPACMERR(" PDN enry %d found for prefix:0x%X:0x%X \n",
						i, it_mapping->conn_info.dl_in.ipv6_dst[0],
						it_mapping->conn_info.dl_in.ipv6_dst[1]);
						if (pdn_ipv6_in_use[i] > 0)
						{
							pdn_ipv6_in_use[i]--;
							IPACMDBG_H("update pdn_ipv6_in_use, entry %d, number %d \n",
								i, pdn_ipv6_in_use[i]);
						}
						else
						{
							IPACMERR("Potential negative pdn_ipv6_in_use, entry %d, number %d \n",
								i, pdn_ipv6_in_use[i]);
						}
						break;
					}
				}
			}

			/* push event for v6-ct to delete the entry */
			post_socksv5_evt(&(it_mapping->conn_info), false);
			socksv5_conn.erase(it_mapping);
			break;
		}
	}

	/* update the total_pdn_ipv6_in_use */
	for (i=0; i < socksv5_v6_pdn; i++)
	{
		if (pdn_ipv6_in_use[i] > 0)
		{
			pdn_ipv6_in_use_temp ++;
			IPACMDBG_H(" pdn_ipv6_in_use entry %d, ref %d, total\n", i, pdn_ipv6_in_use[i], pdn_ipv6_in_use_temp);
		}
	}
	/* if pdn_ipv6_in_use_temp != total_pdn_ipv6_in_use */
	if (pdn_ipv6_in_use_temp < total_pdn_ipv6_in_use)
	{
		IPACMDBG_H(" have new ipv6-socksv5: old %d, new %d\n",total_pdn_ipv6_in_use, pdn_ipv6_in_use_temp);
		total_pdn_ipv6_in_use = pdn_ipv6_in_use_temp;
		/* send v6-update event */
		post_socksv5_v6_evt();
	}

	if (it_mapping == socksv5_conn.end())
	{
		IPACMERR("Can't find the matched socksv5_conn!\n");
	}

	pthread_mutex_unlock(&socksv5_lock);
	return;
}

void IPACM_Config::add_mux_id_mapping(rmnet_mux_id_info *add_mux_id_info)
{
	list<rmnet_mux_id_info>::iterator it_mapping;
	rmnet_mux_id_info new_mapping;

	/* print the info */
	if (!add_mux_id_info)
	{
		IPACMDBG_H("add_mux_id_info is NULL\n");
		return;
	}

	IPACMDBG_H("adding the muxd name %s, addr 0x%X mudxd %d\n",
		add_mux_id_info->iface_name,
		add_mux_id_info->ipv4_addr,
		add_mux_id_info->mux_id);

	/* check entry existed or not */
	for(it_mapping = mux_id_mapping.begin(); it_mapping != mux_id_mapping.end(); it_mapping++)
	{

		if (add_mux_id_info->ipv4_addr == it_mapping->ipv4_addr)
		{
			IPACMERR("This qmuxd mapping was added before with muxd %d\n",
			it_mapping->mux_id);
			goto fail;
		}
	}

	/* Insert to the list*/
	memset(&new_mapping, 0, sizeof(new_mapping));
	memcpy(&new_mapping, add_mux_id_info, sizeof(new_mapping));

	IPACMDBG_H("ipv4 0x%X map to muxd:0x%d\n",
				new_mapping.ipv4_addr,
				new_mapping.mux_id);

	mux_id_mapping.push_front(new_mapping);

fail:
	return;
}

void IPACM_Config::del_mux_id_mapping(rmnet_mux_id_info *del_mux_id_info)
{
	list<rmnet_mux_id_info>::iterator it_mapping;

	/* print the info */
	if (!del_mux_id_info)
	{
		IPACMDBG_H("del_mux_id_info is NULL\n");
		return;
	}

	IPACMDBG_H("Removing the muxd name %s, addr 0x%X mudxd %d\n",
		del_mux_id_info->iface_name,
		del_mux_id_info->ipv4_addr,
		del_mux_id_info->mux_id);

	/* check entry exist */
	for(it_mapping = mux_id_mapping.begin(); it_mapping != mux_id_mapping.end(); it_mapping++)
	{
		if (del_mux_id_info->ipv4_addr == it_mapping->ipv4_addr)
		{
			IPACMDBG_H("Del this mapping with muxd %d\n",
			it_mapping->mux_id);
			mux_id_mapping.erase(it_mapping);
			break;
		}
	}

	if (it_mapping == mux_id_mapping.end())
	{
		IPACMERR("Can't find the matched rmnet_mux_id_info!\n");
	}

	return;
}

int IPACM_Config::query_mux_id(rmnet_mux_id_info *mux_id_info)
{
	list<rmnet_mux_id_info>::iterator it_mapping;

	/* print the info */
	if (!mux_id_info)
	{
		IPACMDBG_H("mux_id_info is NULL\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("try to find 0x%X qmuxd\n", mux_id_info->ipv4_addr);

	/* check entry*/
	for(it_mapping = mux_id_mapping.begin(); it_mapping != mux_id_mapping.end(); it_mapping++)
	{
		if (mux_id_info->ipv4_addr == it_mapping->ipv4_addr)
		{
			mux_id_info->mux_id = it_mapping->mux_id;
			IPACMDBG_H("Found the mapping with muxd %d\n",
			mux_id_info->mux_id);
			break;
		}
	}

	if (it_mapping == mux_id_mapping.end())
	{
		IPACMERR("Can't find the matched rmnet_mux_id_info!\n");
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

#endif //defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_ADD)

#ifdef IPA_IOC_SET_SW_FLT
/* mac_flt_info updates the map that contains mac addrs provided by QCMAP to be
   offloaded to S/W or HW path based on flt_state value */
void IPACM_Config::sw_flt_info(ipa_sw_flt_list_type *sw_flt)
{
	int i = 0;
	uint32_t mask = 0xFFFFFF00, net_lower = 0, net_upper = 0;
	std::list<std::array<uint8_t, 6>> mac_list;
	std::list<std::array<uint8_t, 6>>::iterator it_mac_list;
	std::array<uint8_t, 6> mac = {0};
	uint8_t mac_addr[6] = {0};

	if(pthread_mutex_lock(&mac_flt_info_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	/* check & print ipv4_segs range */
	if (sw_flt->ipv4_segs_enable)
	{
		net_lower = (sw_flt->ipv4_segs[0][0] & mask);
		net_upper = (net_lower | (~mask));
		IPACMDBG_H("ipv4_segs_enable number:%d\n", sw_flt->num_of_ipv4_segs);
		for(i = 0; i < sw_flt->num_of_ipv4_segs; i++)
		{
			IPACMDBG_H("%d IPv4-SEGS-flt ipv4 start:0x%X end:0x%X\n",
				i, sw_flt->ipv4_segs[i][0], sw_flt->ipv4_segs[i][1]);
			/* subnet check */
			if ((sw_flt->ipv4_segs[i][1] < net_lower) || (sw_flt->ipv4_segs[i][1] > net_upper) || (sw_flt->ipv4_segs[i][1] < sw_flt->ipv4_segs[i][0]))
			{
				sw_flt->ipv4_segs_enable = false;
				IPACMERR("wrong ipv4-segs-flt in entry(%d)!! disable ipv4_segs(%d) !\n", i, sw_flt->ipv4_segs_enable);
				break;
			}
		}
	}

	/* cache the sw_flt info after checking ipv4_segs */
	memcpy(&sw_flt_list, sw_flt, sizeof(ipa_sw_flt_list_type));

	/* print the mac-sw-flt info and add to the list */
	if (sw_flt_list.mac_enable)
	{
		IPACMDBG_H("MAC_enable number:%d\n", sw_flt_list.num_of_mac);
		for(i = 0; i < sw_flt_list.num_of_mac && sw_flt_list.num_of_mac <=IPA_MAX_NUM_MAC_FLT; i++)
		{
			IPACMDBG_H("%d MAC-flt %02x:%02x:%02x:%02x:%02x:%02x\n", i,
						sw_flt_list.mac_addr[i][0], sw_flt_list.mac_addr[i][1], sw_flt_list.mac_addr[i][2],
						sw_flt_list.mac_addr[i][3], sw_flt_list.mac_addr[i][4], sw_flt_list.mac_addr[i][5]);
			std::copy(std::begin(sw_flt_list.mac_addr[i]), std::end(sw_flt_list.mac_addr[i]), std::begin(mac));
			mac_list.push_front(mac);

			/* if client matched the mac_sw_flt, create a node of mac_flt_type
			   having is_blacklist state as true and insert it into map if not already
			   present */
			if(IPACM_Iface::ipacmcfg->mac_flt_lists.count(mac) == 0)
			{
				mac_flt_type *temp = (mac_flt_type *)malloc(sizeof(mac_flt_type));
				if(temp == NULL)
				{
					IPACMDBG_H("Failed to allocate memmory \n")
					goto UPDATE;
				}
				memset(temp, 0, sizeof(mac_flt_type));
				temp->is_blacklist = true;
				temp->mac_sw_enabled = true;
				IPACM_Iface::ipacmcfg->mac_flt_lists.insert(std::make_pair(mac, temp));
			}
		}
	}

	/* print the iface-sw-flt info and add clients to the list */
	if (sw_flt_list.iface_enable)
	{
		IPACMDBG_H("iface_enable number:%d\n", sw_flt_list.num_of_iface);
		for(i = 0; i < sw_flt_list.num_of_iface && sw_flt_list.num_of_iface <=IPA_MAX_NUM_IFACE_FLT; i++)
		{
			IPACMDBG_H("%d-entry Iface-flt %s\n",
				i, sw_flt_list.iface[i]);
		}

		for (auto it = IPACM_Iface::ipacmcfg->client_lists.begin(); it != IPACM_Iface::ipacmcfg->client_lists.end();++it)
		{
			for(i = 0; i < sw_flt_list.num_of_iface && sw_flt_list.num_of_iface <=IPA_MAX_NUM_IFACE_FLT; i++)
			{
				if(strncmp(it->second->iface, sw_flt_list.iface[i], sizeof(sw_flt_list.iface[i])) == 0)
				{
					std::copy(std::begin(it->first), std::end(it->first), std::begin(mac_addr));

					IPACMDBG_H("client mac %02x:%02x:%02x:%02x:%02x:%02x matches iface %s \n",
							mac_addr[0], mac_addr[1], mac_addr[2],
							mac_addr[3], mac_addr[4], mac_addr[5],
							sw_flt_list.iface[i]);

					mac_list.push_front(it->first);

					/* if client matched the iface_sw_flt, create a node of mac_flt_type
					   having is_blacklist state as true and insert it into map if not already
					   present */
					if(IPACM_Iface::ipacmcfg->mac_flt_lists.count(it->first) == 0)
					{
						mac_flt_type *temp = (mac_flt_type *)malloc(sizeof(mac_flt_type));
						if(temp == NULL)
						{
							IPACMDBG_H("Failed to allocate memmory \n")
							goto UPDATE;
						}
						memset(temp, 0, sizeof(mac_flt_type));
						temp->is_blacklist = true;
						IPACM_Iface::ipacmcfg->mac_flt_lists.insert(std::make_pair(it->first, temp));
					}
					break;
				}
			}
		}
	}

	/* add ipv4-seg-sw-flt clients to the list */
	if (sw_flt_list.ipv4_segs_enable)
	{
		for (auto it = IPACM_Iface::ipacmcfg->client_lists.begin(); it != IPACM_Iface::ipacmcfg->client_lists.end();++it)
		{
			for(i = 0; i < sw_flt_list.num_of_ipv4_segs && sw_flt_list.num_of_ipv4_segs <= IPA_MAX_NUM_IPv4_SEGS_FLT; i++)
			{
				/* check client ipv4 in the ipv4_segs range */
				if ((sw_flt_list.ipv4_segs[i][0] <= it->second->v4_addr) && (it->second->v4_addr <=sw_flt_list.ipv4_segs[i][1]))
				{
					IPACMDBG_H("client ipv4 0x%X inside range :0x%X to:0x%X\n",
						it->second->v4_addr, sw_flt_list.ipv4_segs[i][0], sw_flt_list.ipv4_segs[i][1]);
					std::copy(std::begin(it->first), std::end(it->first), std::begin(mac_addr));

					IPACMDBG_H("client mac %02x:%02x:%02x:%02x:%02x:%02x matches ipv4_segs\n",
							mac_addr[0], mac_addr[1], mac_addr[2],
							mac_addr[3], mac_addr[4], mac_addr[5]);

					mac_list.push_front(it->first);

					/* if client ipv4 matched the ipv4_seg_sw_flt, create a node of mac_flt_type
					   having is_blacklist state as true and insert it into map if not already
					   present */
					if(IPACM_Iface::ipacmcfg->mac_flt_lists.count(it->first) == 0)
					{
						mac_flt_type *temp = (mac_flt_type *)malloc(sizeof(mac_flt_type));
						if(temp == NULL)
						{
							IPACMDBG_H("Failed to allocate memmory \n")
							goto UPDATE;
						}
						memset(temp, 0, sizeof(mac_flt_type));
						temp->is_blacklist = true;
						IPACM_Iface::ipacmcfg->mac_flt_lists.insert(std::make_pair(it->first, temp));
					}
					break;
				}
			}
		}
	}

	/* List contains current mac addrs that needs to be offloaded to SW. if empty
	   then update is_blacklist as false for all stored mac addrs else update only for
	   those mac addrs that are not present in current list */
UPDATE:
	for (auto it = IPACM_Iface::ipacmcfg->mac_flt_lists.begin(); it != IPACM_Iface::ipacmcfg->mac_flt_lists.end();)
	{
		it_mac_list = std::find(mac_list.begin() , mac_list.end() , it->first);
			if(!(it_mac_list != mac_list.end()))
			{
				auto itr = it;
				std::copy(std::begin(it->first), std::end(it->first), std::begin(mac_addr));
				IPACMDBG_H("Previous  MAC addr to be whitelisted %02x:%02x:%02x:%02x:%02x:%02x\n",
						 mac_addr[0], mac_addr[1], mac_addr[2],
						 mac_addr[3], mac_addr[4], mac_addr[5]);
				if(it->second->current_blocked == false) {
					IPACMDBG_H("remove this client from the mac list as whitelisted\n");
					free(IPACM_Iface::ipacmcfg->mac_flt_lists.at(it->first));
					IPACM_Iface::ipacmcfg->mac_flt_lists.at(it->first) = NULL;
					++it;
					IPACM_Iface::ipacmcfg->mac_flt_lists.erase(itr->first);
				}
				else
				{
					it->second->is_blacklist = false;
					++it;
				}
			}
			else
			{
				++it;
			}
	}
	mac_list.clear();
	pthread_mutex_unlock(&mac_flt_info_lock);
	return ;
}
#endif

#ifdef IPA_IOC_SET_MAC_FLT
/* mac_flt_info updates the map that contains mac addrs provided by QCMAP to be
   offloaded to S/W or HW path based on flt_state value */
void IPACM_Config::mac_flt_info(ipa_ioc_mac_client_list_type *mac_flt_data)
{
	std::list<std::array<uint8_t, 6>> mac_list;
	std::list<std::array<uint8_t, 6>>::iterator it_mac_list;
	std::array<uint8_t, 6> mac = {0};
	uint8_t mac_addr[6]= {0};

	if(pthread_mutex_lock(&mac_flt_info_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("Mac filtering state enable (%d) num of clients %d\n", mac_flt_data->flt_state, mac_flt_data->num_of_clients);
	/* if flt state is true then only populate mac_list which contains mac addrs
	   to be blacklisted and num of clients should be max 32. If flt state is false
	   then do not add anything to list */
	if(mac_flt_data->flt_state)
	{
		for(int i=0; i<mac_flt_data->num_of_clients && mac_flt_data->num_of_clients <=IPA_MAX_NUM_MAC_FLT; i++)
		{
			IPACMDBG_H("Passed MAC addr to be blacklisted %02x:%02x:%02x:%02x:%02x:%02x\n",
						 mac_flt_data->mac_addr[i][0], mac_flt_data->mac_addr[i][1], mac_flt_data->mac_addr[i][2],
						 mac_flt_data->mac_addr[i][3], mac_flt_data->mac_addr[i][4], mac_flt_data->mac_addr[i][5]);
			std::copy(std::begin(mac_flt_data->mac_addr[i]), std::end(mac_flt_data->mac_addr[i]), std::begin(mac));
			mac_list.push_front(mac);

			/* if flt state provided by QCMAP is true then create a node of mac_flt_type
			   having is_blacklist state as true and insert it into map if not already
		   	   present */
			if(IPACM_Iface::ipacmcfg->mac_flt_lists.count(mac) == 0)
			{
				mac_flt_type *temp = (mac_flt_type *)malloc(sizeof(mac_flt_type));
				if(temp == NULL)
				{
					IPACMDBG_H("Failed to allocate memmory \n")
					goto UPDATE;
				}
				memset(temp, 0, sizeof(mac_flt_type));
				temp->is_blacklist = true;
				IPACM_Iface::ipacmcfg->mac_flt_lists.insert(std::make_pair(mac, temp));
			}
		}
	}

	/* List contains current mac addrs that needs to be offloaded to SW. if empty
	   then update is_blacklist as false for all stored mac addrs else update only for
	   those mac addrs that are not present in current list */
UPDATE:
	for (auto it = IPACM_Iface::ipacmcfg->mac_flt_lists.begin(); it != IPACM_Iface::ipacmcfg->mac_flt_lists.end();)
	{
		it_mac_list = std::find(mac_list.begin() , mac_list.end() , it->first);
			if(!(it_mac_list != mac_list.end()))
			{
				std::copy(std::begin(it->first), std::end(it->first), std::begin(mac_addr));
				IPACMDBG_H("Previous  MAC addr to be whitelisted %02x:%02x:%02x:%02x:%02x:%02x\n",
						 mac_addr[0], mac_addr[1], mac_addr[2],
						 mac_addr[3], mac_addr[4], mac_addr[5]);
				if(it->second->current_blocked == false) {
					IPACMDBG_H("remove this client from the mac list as whitelisted\n");
					free(IPACM_Iface::ipacmcfg->mac_flt_lists.at(it->first));
					IPACM_Iface::ipacmcfg->mac_flt_lists.at(it->first) = NULL;
					it = IPACM_Iface::ipacmcfg->mac_flt_lists.erase(it);
				}
				else
				{
					it->second->is_blacklist = false;
					it++;
				}
			} else {
				it++;
			}
	}
	mac_list.clear();
	pthread_mutex_unlock(&mac_flt_info_lock);
	return ;
}
#endif
/* mac_addr_in_blacklist checks whether a particular mac addr is blacklisted or not */
bool IPACM_Config::mac_addr_in_blacklist(uint8_t *mac_addr)
{
	uint8_t mac_a[6] = {0};
	std::map<std::array<uint8_t, 6>, mac_flt_type * >::iterator it;
	std::array<uint8_t, 6> mac = {0};

	if(pthread_mutex_lock(&mac_flt_info_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return false;
	}

	memcpy(mac_a,mac_addr,IPA_MAC_ADDR_SIZE);
	std::copy(std::begin(mac_a), std::end(mac_a), std::begin(mac));

	it = IPACM_Iface::ipacmcfg->mac_flt_lists.find(mac);
	if(it != IPACM_Iface::ipacmcfg->mac_flt_lists.end() && it->second->is_blacklist)
	{
		pthread_mutex_unlock(&mac_flt_info_lock);
		return true;
	}
	else
	{
		pthread_mutex_unlock(&mac_flt_info_lock);
		return false;
	}
}

/* clear_whitelist_mac_add removes whitelisted mac addr from the previous stored
   blacklisted mac addrs*/
void IPACM_Config::clear_whitelist_mac_add(uint8_t * mac_addr)
{
	uint8_t mac_a[6] = {0};
	std::array<uint8_t, 6> mac = {0};

	IPACMDBG_H("clear from mac_flt_list! \n")
	if(pthread_mutex_lock(&mac_flt_info_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	memcpy(mac_a,mac_addr,IPA_MAC_ADDR_SIZE);
	std::copy(std::begin(mac_a), std::end(mac_a), std::begin(mac));
	if(mac_flt_lists.count(mac) > 0 ) {
		if(mac_flt_lists.at(mac) != NULL)
		{
			free(mac_flt_lists.at(mac));
			mac_flt_lists.at(mac) = NULL;
		}
		mac_flt_lists.erase(mac);
		IPACMDBG_H("Cleared macaddr from map %02x:%02x:%02x:%02x:%02x:%02x\n",
						 mac_a[0], mac_a[1], mac_a[2],
						 mac_a[3], mac_a[4], mac_a[5]);
		pthread_mutex_unlock(&mac_flt_info_lock);
	}
	else
	{
		pthread_mutex_unlock(&mac_flt_info_lock);
		IPACMDBG_H(" Client not in mac flt list \n");
	}
	return;
}

/* upadte global config list with current state of mac addr */
void IPACM_Config::update_mac_flt_lists(uint8_t * mac_addr , mac_flt_type *mac_flt_value)
{
	IPACMDBG_H("update mac flt list \n");
	uint8_t mac_a[6] = {0};
	std::array<uint8_t, 6> mac = {0};

	if(pthread_mutex_lock(&mac_flt_info_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return ;
	}

	memcpy(mac_a,mac_addr,IPA_MAC_ADDR_SIZE);
	std::copy(std::begin(mac_a), std::end(mac_a), std::begin(mac));
	/*updating all values except flt state as it might change in new list */
	if(mac_flt_lists.count(mac) > 0 ) {
		mac_flt_lists.at(mac)->mac_v4_rt_del_flt_set  = mac_flt_value->mac_v4_rt_del_flt_set;
		mac_flt_lists.at(mac)->mac_v6_rt_del_flt_set  = mac_flt_value->mac_v6_rt_del_flt_set;
		mac_flt_lists.at(mac)->mac_v4_flt_rule_hdl = mac_flt_value->mac_v4_flt_rule_hdl;
		mac_flt_lists.at(mac)->mac_v6_flt_rule_hdl = mac_flt_value->mac_v6_flt_rule_hdl;
	}
	pthread_mutex_unlock(&mac_flt_info_lock);
	return;
}

/* support add/update/delete tether client info */
void IPACM_Config::update_client_info(uint8_t *mac_addr, tether_client_info *client_info, bool is_add)
{
	uint8_t mac_a[6] = {0};
	std::array<uint8_t, 6> mac = {0};
	int i;
	bool update_need = false;
	ipacm_cmd_q_data evt_data;

	if(pthread_mutex_lock(&mac_flt_info_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return ;
	}

	IPACMDBG_H(" updating client info \n");
	memcpy(mac_a,mac_addr,IPA_MAC_ADDR_SIZE);
	std::copy(std::begin(mac_a), std::end(mac_a), std::begin(mac));

	if (is_add)
	{
		if (!(sw_flt_list.iface_enable || sw_flt_list.mac_enable || sw_flt_list.ipv4_segs_enable))
		{
			IPACMDBG("None of SW Filtering is enabled \n");
			pthread_mutex_unlock(&mac_flt_info_lock);
			return;
		}
		IPACMDBG_H(" Adding client mac %02x:%02x:%02x:%02x:%02x:%02x ip4 0x%X, iface %s\n",
			 mac_a[0], mac_a[1], mac_a[2],
			 mac_a[3], mac_a[4], mac_a[5],
			 client_info->v4_addr,
			 client_info->iface);

		/* check client already in the list or not */
		if(IPACM_Iface::ipacmcfg->client_lists.count(mac) == 0)
		{
			tether_client_info *temp = (tether_client_info *)malloc(sizeof(tether_client_info));
			if(temp == NULL)
			{
				IPACMERR("Failed to allocate memmory \n");
					pthread_mutex_unlock(&mac_flt_info_lock);
					return;
			}
			memset(temp, 0, sizeof(tether_client_info));
			temp->v4_addr = client_info->v4_addr;
			memcpy(temp->iface, client_info->iface, IPA_IFACE_NAME_LEN);
			temp->is_vlan = client_info->is_vlan;
			IPACM_Iface::ipacmcfg->client_lists.insert(std::make_pair(mac, temp));
		}
		else
		{
			/*updating all values except flt state as it might change in new list */
			if (IPACM_Iface::ipacmcfg->client_lists.at(mac)->v4_addr == 0)
			{
				client_lists.at(mac)->v4_addr  = client_info->v4_addr;
				IPACMDBG_H(" Update client ip4 to 0x%X\n",
				client_lists.at(mac)->v4_addr);
				update_need = true;
			}
			client_lists.at(mac)->is_vlan = client_info->is_vlan;
		}

		/* check if client matched the iface SW-flt request */
		if (sw_flt_list.iface_enable)
		{
			for(i = 0; i < sw_flt_list.num_of_iface && sw_flt_list.num_of_iface <=IPA_MAX_NUM_IFACE_FLT; i++)
			{
				if(strncmp(client_info->iface, sw_flt_list.iface[i], sizeof(sw_flt_list.iface[i])) == 0)
				{
					/* if client matched the iface_sw_flt, create a node of mac_flt_type
					   having is_blacklist state as true and insert it into map if not already
					   present */
					if(IPACM_Iface::ipacmcfg->mac_flt_lists.count(mac) == 0)
					{
						mac_flt_type *temp2 = (mac_flt_type *)malloc(sizeof(mac_flt_type));
						if(temp2 == NULL)
						{
							IPACMDBG_H("Failed to allocate memmory \n")
							pthread_mutex_unlock(&mac_flt_info_lock);
							return;
						}
						memset(temp2, 0, sizeof(mac_flt_type));
						temp2->is_blacklist = true;
						IPACM_Iface::ipacmcfg->mac_flt_lists.insert(std::make_pair(mac, temp2));
					}
					break;
				}
			}
		}

		/* check if client matched the ipv4 seg SW-flt request */
		if (sw_flt_list.ipv4_segs_enable)
		{
			for(i = 0; i < sw_flt_list.num_of_ipv4_segs && sw_flt_list.num_of_ipv4_segs <= IPA_MAX_NUM_IPv4_SEGS_FLT; i++)
			{
				/* check client ipv4 in the ipv4_segs range */
				if ((sw_flt_list.ipv4_segs[i][0] <= client_info->v4_addr) && (client_info->v4_addr <=sw_flt_list.ipv4_segs[i][1]))
				{
					IPACMDBG_H("client ipv4 0x%X inside range :0x%X to:0x%X\n",
						client_info->v4_addr, sw_flt_list.ipv4_segs[i][0], sw_flt_list.ipv4_segs[i][1]);

					/* if client ipv4 matched the ipv4_seg_sw_flt, create a node of mac_flt_type
					   having is_blacklist state as true and insert it into map if not already
					   present */
					if(IPACM_Iface::ipacmcfg->mac_flt_lists.count(mac) == 0)
					{
						mac_flt_type *temp2 = (mac_flt_type *)malloc(sizeof(mac_flt_type));
						if(temp2 == NULL)
						{
							IPACMDBG_H("Failed to allocate memmory \n")
							pthread_mutex_unlock(&mac_flt_info_lock);
							return;
						}
						memset(temp2, 0, sizeof(mac_flt_type));
						temp2->is_blacklist = true;
						IPACM_Iface::ipacmcfg->mac_flt_lists.insert(std::make_pair(mac, temp2));
					}
					break;
				}
			}
		}

		/* Special handling for v6 already offload */
		if (update_need == true)
		{
			evt_data.event = IPA_MAC_ADD_DEL_FLT_EVENT;
			evt_data.evt_data = NULL;
			/* finish command queue */
			IPACMDBG_H("Posting IPA_MAC_ADD_DEL_FLT_EVENT event!\n", evt_data.event);
			IPACM_EvtDispatcher::PostEvt(&evt_data);
		}
	}
	else
	{
		if(IPACM_Iface::ipacmcfg->client_lists.count(mac) > 0)
		{
			/* erase client in the list */
			IPACMDBG_H("Cleared client mac %02x:%02x:%02x:%02x:%02x:%02x ip4 0x%X, iface %s\n",
					 mac_a[0], mac_a[1], mac_a[2],
					 mac_a[3], mac_a[4], mac_a[5],
					 client_lists.at(mac)->v4_addr,
					 client_lists.at(mac)->iface);
			free(client_lists.at(mac));
			client_lists.at(mac) = NULL;
			IPACM_Iface::ipacmcfg->client_lists.erase(mac);
		}
		/* Not delete client if it's in mac-flt list */
		if(sw_flt_list.mac_enable && IPACM_Iface::ipacmcfg->mac_flt_lists.count(mac) > 0
						&& IPACM_Iface::ipacmcfg->mac_flt_lists.at(mac)->mac_sw_enabled)
		{
			IPACMDBG_H("Don't remove the client from mac list as mac based flt is enabled for this client\n");
		}
		else
		{
			IPACMDBG_H("remove client from the mac list!\n");
			pthread_mutex_unlock(&mac_flt_info_lock);
			IPACM_Iface::ipacmcfg->clear_whitelist_mac_add(mac_addr);
			return;
		}
	}
	pthread_mutex_unlock(&mac_flt_info_lock);
	return;
}

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
void IPACM_Config::stats_client_info(uint8_t *mac_addr, bool is_add)
{
	uint8_t mac_a[6] = {0};
	std::array<uint8_t, 6> mac = {0};

	if(pthread_mutex_lock(&stats_client_info_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return ;
	}
	memcpy(mac_a,mac_addr,IPA_MAC_ADDR_SIZE);
	std::copy(std::begin(mac_a), std::end(mac_a), std::begin(mac));

	if(is_add) {
		mac_addrs_stats_cache.insert(mac);
	}
	else
	{
		if (mac_addrs_stats_cache.count(mac))
			mac_addrs_stats_cache.erase(mac);
	}
	pthread_mutex_unlock(&stats_client_info_lock);
	return;
}

bool IPACM_Config::client_in_stats_cache(uint8_t *mac_addr)
{
	bool is_enable = false;
	uint8_t mac_a[6] = {0};
	std::array<uint8_t, 6> mac = {0};

	if(pthread_mutex_lock(&stats_client_info_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return is_enable;
	}
	memcpy(mac_a,mac_addr,IPA_MAC_ADDR_SIZE);
	std::copy(std::begin(mac_a), std::end(mac_a), std::begin(mac));

	if (mac_addrs_stats_cache.count(mac))
	{
		is_enable = true;
		mac_addrs_stats_cache.erase(mac);
	}
	else
	{
		is_enable = false;
	}
	pthread_mutex_unlock(&stats_client_info_lock);
	return is_enable;
}
#endif

bool IPACM_Config::insertOrAssignMacsecMap(struct ipa_macsec_map *macsecMap) {
	int netlinkIdx, ifaceTableIdx;

	if (!macsecMap)
		return false;
	/* first check if we have macsec iface entry or not */
	if (IPACM_Iface::ipa_get_if_index(macsecMap->macsec_name, &netlinkIdx) == IPACM_SUCCESS &&
	    (ifaceTableIdx = IPACM_Iface::iface_ipa_index_query(netlinkIdx)) != INVALID_IFACE) {
		IPACMDBG_H("Will modify the existing macsec interface %s with new phy %s\n", macsecMap->macsec_name, macsecMap->phy_name);

		/* Modify an existing macsec interface macsec interface in the config table*/
		strlcpy(iface_table[ifaceTableIdx].phy_dev_name, macsecMap->phy_name, sizeof(iface_table[ifaceTableIdx].phy_dev_name));
	} else {
		IPACMDBG_H("Will add new macsec interface: %s instead of %s\n", macsecMap->macsec_name, macsecMap->phy_name);

		/* check if physical iface is valid */
		if (IPACM_Iface::ipa_get_if_index(macsecMap->phy_name, &netlinkIdx) == IPACM_FAILURE ||
		    (ifaceTableIdx = IPACM_Iface::iface_ipa_index_query(netlinkIdx)) == INVALID_IFACE) {
			/* can't find physical nic name, ignoring this macsec handling */
			IPACMERR("Got wrong physical NIC name: %s\n", macsecMap->phy_name);
			return false;
		}
		/* Replace a physical interface with macsec interface in the config table */
		iface_table[ifaceTableIdx].virtual_iface = true;
		strlcpy(iface_table[ifaceTableIdx].iface_name, macsecMap->macsec_name, sizeof(iface_table[ifaceTableIdx].iface_name));
		strlcpy(iface_table[ifaceTableIdx].phy_dev_name, macsecMap->phy_name, sizeof(iface_table[ifaceTableIdx].phy_dev_name));
		IPACM_Iface::ipa_get_if_index(macsecMap->macsec_name, &netlinkIdx);
		iface_table[ifaceTableIdx].netlink_interface_index = netlinkIdx;
	}

	return true;
}

bool IPACM_Config::delMacsecMap(struct ipa_macsec_map *macsecMap) {
	int netlinkIdx, ifaceTableIdx;

	if (!macsecMap)
		return false;
	/* Replace the requested macsec interface with physical interface */
	if (IPACM_Iface::ipa_get_if_index(macsecMap->macsec_name, &netlinkIdx) == IPACM_SUCCESS &&
	    (ifaceTableIdx = IPACM_Iface::iface_ipa_index_query(netlinkIdx)) != INVALID_IFACE) {
		IPACMDBG_H("Will replace the macsec interface: %s with %s\n", macsecMap->macsec_name, macsecMap->phy_name);
		iface_table[ifaceTableIdx].virtual_iface = false;
		strlcpy(iface_table[ifaceTableIdx].iface_name, iface_table[ifaceTableIdx].phy_dev_name,
			sizeof(iface_table[ifaceTableIdx].iface_name));
		iface_table[ifaceTableIdx].phy_dev_name[0] = '\0';
		IPACM_Iface::ipa_get_if_index(macsecMap->phy_name, &netlinkIdx);
		iface_table[ifaceTableIdx].netlink_interface_index = netlinkIdx;

		return true;
	}

	return false;
}

#ifdef FEATURE_IPA_IPSEC
bool operator==(const ipa_ioc_ipsec_ul_flt_attr &uf1, const ipa_ioc_ipsec_ul_flt_attr &uf2)
{
	if (memcmp(&uf1, &uf2, sizeof(ipa_ioc_ipsec_ul_flt_attr)) == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool IPACM_Config::AddIpsecUlFlt(struct ipa_ioc_ipsec_ul_flt_attr uf)
{
	ipsecUlFlt.insert(uf);
	IPACMDBG_H("Added an UL rule. Now the number of IPsec UL rules is %ld\n", ipsecUlFlt.size());

	return true;
}

bool IPACM_Config::DelIpsecUlFlt(struct ipa_ioc_ipsec_ul_flt_attr uf)
{
	ipsecUlFlt.erase(uf);
	IPACMDBG_H("Deleted an UL rule. Now the number of IPsec UL rules is %ld\n", ipsecUlFlt.size());

	return true;
}
#endif

bool IPACM_Config::is_svap_related(const char* phy_inf) {
	FILE *fp = NULL;
	char MapBSSType_row[10] = { 0 }, cmd[200] = { 0 };
	bool is_svap = false;

	char if_name[IPA_IFACE_NAME_LEN];
	strlcpy(if_name, phy_inf, IPA_IFACE_NAME_LEN);
	IPACMDBG_H("dev_name %s\n", phy_inf);

	char* char_idx =  strstr(if_name, ".");

	if (char_idx) {
		char_idx[0] = '\0';
		IPACMDBG_H("truncated iface name %s\n", if_name);
	}

	snprintf(cmd, 200, "cfg80211tool_mesh %s get_MapBSSType| awk -F ':' '{print $2}' > /tmp/data_ipa/ipa_vap.txt", if_name);
	system(cmd);

	fp = fopen("/tmp/data_ipa/ipa_vap.txt", "r");
	if (fp == NULL) {
		IPACMERR("can't open fdb file\n");
		return false;
	}

	if (fgets(MapBSSType_row, 10, fp) == NULL) {
		IPACMERR("fgets failed\n");
		goto end;
	}

	if (72 == atoi(MapBSSType_row)) {
		is_svap = true;
	}
	IPACMDBG_H("get_MapBSSType %d\n", atoi(MapBSSType_row));

end:
	fclose(fp);
	return is_svap;
}

#ifdef IPA_IOCTL_SET_EXT_ROUTER_MODE
bool IPACM_Config::add_ext_router_info(ipa_ioc_ext_router_info *data)
{
	list<ext_router_prefix_info>::iterator it;
	struct ext_router_prefix_info info;
	int i, j;

	for(it = ext_router_prefix.begin(); it != ext_router_prefix.end(); it++)
	{
		if(strncmp(it->pdn_name, data->pdn_name, sizeof(it->pdn_name)) == 0)
		{
			IPACMERR("The pdn %s already has ext_router ipv6 added\n", it->pdn_name);
			return false;
		}
	}

	memset(&info, 0, sizeof(ext_router_prefix_info));
	strlcpy(info.pdn_name, data->pdn_name, sizeof(info.pdn_name));

	/* for prefix sharing */
	info.ipv6_addr[0] = htonl(data->ipv6_addr[0]);
	info.ipv6_addr[1] = htonl(data->ipv6_addr[1]);
	info.ipv6_addr[2] = htonl(data->ipv6_addr[2]);
	info.ipv6_addr[3] = htonl(data->ipv6_addr[3]);
	info.ipv6_mask[0] = htonl(data->ipv6_mask[0]);
	info.ipv6_mask[1] = htonl(data->ipv6_mask[1]);
	info.ipv6_mask[2] = htonl(data->ipv6_mask[2]);
	info.ipv6_mask[3] = htonl(data->ipv6_mask[3]);

	/* for prefix_delegation */
	info.num_of_idu_prefix_mapping = data->num_of_idu_prefix_mapping;
	for (i = 0; i < info.num_of_idu_prefix_mapping; i++)
	{
		for (j = 0; j < 4; j ++)
		{
			info.idu_wan_ip[i][j] = htonl(data->idu_wan_ip[i][j]);
			//Note: currently using only 64 bits prefix, but can change in the future
			info.idu_client_prefix[i][j] = htonl(data->idu_client_prefix[i][j]);
		}
	}
	ext_router_prefix.push_front(info);

	IPACMDBG_H("succesfully added info - mode:%d, pdn_name:%s\nv6_addr:0x%08x:%08x:%08x:%08x\nv6_mask:0x%08x:%08x:%08x:%08x\n",
				data->mode, info.pdn_name,
				info.ipv6_addr[0], info.ipv6_addr[1], info.ipv6_addr[2], info.ipv6_addr[3],
				info.ipv6_mask[0], info.ipv6_mask[1], info.ipv6_mask[2], info.ipv6_mask[3]);

	return true;
}

bool IPACM_Config::del_ext_router_info(char* pdn_name)
{
	list<ext_router_prefix_info>::iterator it;
	struct ext_router_prefix_info info;

	for(it = ext_router_prefix.begin(); it != ext_router_prefix.end(); it++)
	{
		if(strncmp(it->pdn_name, pdn_name, sizeof(it->pdn_name)) == 0)
		{
			IPACMDBG_H("Found pdn %s\n", it->pdn_name)
			ext_router_prefix.erase(it);
			return true;
		}
	}

	IPACMERR("Cannot find pdn %s\n", it->pdn_name);
	return false;
}

bool IPACM_Config::get_ext_router_info(ext_router_prefix_info *data)
{
	list<ext_router_prefix_info>::iterator it;

	for(it = ext_router_prefix.begin(); it != ext_router_prefix.end(); it++)
	{
		if(strncmp(it->pdn_name, data->pdn_name, sizeof(it->pdn_name)) == 0)
		{
			IPACMDBG_H("Found pdn %s\n", data->pdn_name);
			memcpy(data->ipv6_addr, it->ipv6_addr, sizeof(data->ipv6_addr));
			memcpy(data->ipv6_mask, it->ipv6_mask, sizeof(data->ipv6_mask));
			memcpy(data->idu_wan_ip, it->idu_wan_ip, sizeof(data->idu_wan_ip));
			memcpy(data->idu_client_prefix, it->idu_client_prefix, sizeof(data->idu_client_prefix));
			data->num_of_idu_prefix_mapping = it->num_of_idu_prefix_mapping;
			return true;
		}
	}
	IPACMERR("Could not find pdn %s\n", data->pdn_name);

	return false;
}

/* returns pdn_name if addr prefix matches ext_route_prefix, -1 if not */
char* IPACM_Config::is_ext_route_ipv6_prefix(uint32_t *addr)
{
	list<ext_router_prefix_info>::iterator it;

	for(it = ext_router_prefix.begin(); it != ext_router_prefix.end(); it++)
	{
		if (((addr[0] & it->ipv6_mask[0]) == it->ipv6_addr[0]) &&
			((addr[1] & it->ipv6_mask[1]) == it->ipv6_addr[1]) &&
			((addr[2] & it->ipv6_mask[2]) == it->ipv6_addr[2]) &&
			((addr[3] & it->ipv6_mask[3]) == it->ipv6_addr[3]))
		{
			IPACMDBG_H("prefix [%X][%X] matches ext router prefix for pdn %s\n", addr[0], addr[1], it->pdn_name);
			return it->pdn_name;
		}
	}
	IPACMDBG("no match for [%X][%X]\n", addr[0], addr[1]);
	return NULL;
}

int IPACM_Config::get_mapped_delegated_prefix_idx(uint32_t *addr)
{
	list<ext_router_prefix_info>::iterator it;
	int i;

	for(it = ext_router_prefix.begin(); it != ext_router_prefix.end(); it++)
	{
		for(i = 0; i < it->num_of_idu_prefix_mapping; i++)
		{
			//todo: can use memcmp but there might be padding bits. is this safer?
			if ((addr[0] == it->idu_wan_ip[i][0]) && (addr[1] == it->idu_wan_ip[i][1]) &&
				(addr[2] == it->idu_wan_ip[i][2]) && (addr[3] == it->idu_wan_ip[i][3]))
			{
				IPACMDBG("IDU ip:[%X][%X][%X][%X] maps to del prefix %d:[%X][%X]\n",
					addr[0], addr[1], addr[2], addr[3], i,
					it->idu_client_prefix[i][0], it->idu_client_prefix[i][1]);
				return i;
			}
		}
	}

	IPACMDBG("no match for [%X][%X][%X][%X]\n", addr[0], addr[1], addr[2], addr[3]);
	return IPA_PREFIX_MAPPING_MAX;
}
#endif

int IPACM_Config::SwitchAPVlanMode(char *event_iface_name, bool vlan_mpdn) {
	int ipa_interface_index, if_index;
	int ret = IPACM_FAILURE;
	ipacm_cmd_q_data evt_data;
	ipacm_event_vlan_mode *data = NULL;
	char if_name[IPA_IFACE_NAME_LEN];

	if (event_iface_name == NULL) {
		IPACMERR("Invalid input\n");
		return IPACM_FAILURE;
	}

	/* extract the parent if_name from the vlan iface */
	strlcpy(if_name, event_iface_name, IPA_IFACE_NAME_LEN);
	IPACMDBG_H("iface %s, event iface %s\n", if_name, event_iface_name);

	char *char_idx =  strrchr(if_name, '.');
	if (char_idx) {
		char_idx[0] = '\0';
		IPACMDBG_H("truncated iface name %s\n", if_name);
	} else return IPACM_FAILURE;

	/* check if the AP iface already exists or not*/
	ret = IPACM_Iface::ipa_get_if_index(if_name, &(if_index));
	if (ret != IPACM_SUCCESS) {
		IPACMERR("Error while getting interface index for %s device", if_name);
		return IPACM_FAILURE;
	}

	/* Map the interface index. */
	ipa_interface_index = IPACM_Iface::iface_ipa_index_query(if_index);
	IPACMDBG_H("if_cat:%d, if_vlan: %d\n",
			   IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].if_cat,
			   IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].is_wlan_if_vlan);
	if (IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].if_cat == WLAN_IF &&
		!IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].is_wlan_if_vlan) {
		IPACMDBG_H("AP interface already exists, change it to VLAN mode %s\n", if_name);

		/* Function to bring lan2lan connection down and restart */
		data = (ipacm_event_vlan_mode *)malloc(sizeof(ipacm_event_vlan_mode));
		if (data == NULL) {
			IPACMERR("Unable to allocate memory\n");
			return IPACM_FAILURE;
		}
		data->wlan_vlan_mpdn_enable = vlan_mpdn;
		data->if_index = if_index;
		evt_data.event = IPA_WLAN_SWITCH_VLAN_MODE;
		evt_data.evt_data = data;

		/* finish command queue */
		IPACMDBG_H("Posting event:%s\n", IPACM_Iface::ipacmcfg->getEventName(evt_data.event));
		IPACM_EvtDispatcher::PostEvt(&evt_data);

		IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].is_wlan_if_vlan = vlan_mpdn;
	} else {
		IPACMDBG_H("AP interface doesn't exists, exiting switch mode %s\n", if_name);
	}

	return ret;
}

bool IPACM_Config::IsWlanIfVlan(const char *event_iface_name) {
	int ipa_interface_index, if_index;
	int ret = IPACM_FAILURE;
	bool res = false;
	char if_name[IPA_IFACE_NAME_LEN];

	if (event_iface_name == NULL) {
		IPACMERR("Invalid input\n");
		return IPACM_FAILURE;
	}

	/* extract the parent if_name from the vlan iface */
	strlcpy(if_name, event_iface_name, IPA_IFACE_NAME_LEN);
	IPACMDBG_H("iface %s, event iface %s\n", if_name, event_iface_name);

	char *char_idx =  strrchr(if_name, '.');
	if (char_idx) {
		char_idx[0] = '\0';
		IPACMDBG_H("truncated iface name %s\n", if_name);
	}

	/* check if the AP iface already exists or not*/
	ret = IPACM_Iface::ipa_get_if_index(if_name, &(if_index));
	if (ret != IPACM_SUCCESS) {
		IPACMERR("Error while getting interface index for %s device", if_name);
		return IPACM_FAILURE;
	}

	/* Map the interface index. */
	ipa_interface_index = IPACM_Iface::iface_ipa_index_query(if_index);

	if (IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].if_cat == WLAN_IF) {
		res = IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].is_wlan_if_vlan;
		IPACMDBG_H("AP is WLAN AP, vlan enabled %d\n", res);
	} else {
		IPACMDBG_H("AP %s interface is not WLAN AP, exiting\n", if_name);
	}

	return res;
}

int IPACM_Config::SetWlanVlanAp(char *event_iface_name) {
	int ipa_interface_index, if_index;
	int ret = IPACM_FAILURE;
	char if_name[IPA_IFACE_NAME_LEN];

	if (event_iface_name == NULL) {
		IPACMERR("Invalid input\n");
		return IPACM_FAILURE;
	}

	/* extract the parent if_name from the vlan iface */
	strlcpy(if_name, event_iface_name, IPA_IFACE_NAME_LEN);
	IPACMDBG_H("iface %s, event iface %s\n", if_name, event_iface_name);

	char *char_idx =  strrchr(if_name, '.');
	if (char_idx) {
		char_idx[0] = '\0';
		IPACMDBG_H("truncated iface name %s\n", if_name);
	}

	/* check if the AP iface already exists or not*/
	ret = IPACM_Iface::ipa_get_if_index(if_name, &(if_index));
	if (ret != IPACM_SUCCESS) {
		IPACMERR("Error while getting interface index for %s device", if_name);
		return IPACM_FAILURE;
	}

	/* Map the interface index. */
	ipa_interface_index = IPACM_Iface::iface_ipa_index_query(if_index);

	IPACMDBG_H("Debug logs, if_cat:%d\n", IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].if_cat);
	if (IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].if_cat == WLAN_IF) {
		IPACMDBG_H("VLAN AP interface already exists, change it to VLAN mode %s\n", if_name);

		IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].is_wlan_if_vlan = true;
	} else {
		IPACMDBG_H("AP interface doesn't exists, exiting switch mode %s\n", if_name);
	}

	return ret;
}

bool IPACM_Config::IsSpclIface(const char *event_iface_name) {
	int ipa_interface_index, if_index;
	int ret = IPACM_FAILURE;
	bool res = false;
	char if_name[IPA_IFACE_NAME_LEN];

	if (event_iface_name == NULL) {
		IPACMERR("Invalid input\n");
		return IPACM_FAILURE;
	}

	/* extract the parent if_name from the vlan iface */
	strlcpy(if_name, event_iface_name, IPA_IFACE_NAME_LEN);
	IPACMDBG_H("iface %s, event iface %s\n", if_name, event_iface_name);

	char *char_idx =  strrchr(if_name, '.');
	if (char_idx) {
		char_idx[0] = '\0';
		IPACMDBG_H("truncated iface name %s\n", if_name);
	}

	/* check if the AP iface already exists or not*/
	ret = IPACM_Iface::ipa_get_if_index(if_name, &(if_index));
	if (ret != IPACM_SUCCESS) {
		IPACMERR("Error while getting interface index for %s device", if_name);
		return IPACM_FAILURE;
	}

	/* Map the interface index. */
	ipa_interface_index = IPACM_Iface::iface_ipa_index_query(if_index);

	res = IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].is_spcl_if;
	IPACMDBG_H("%s is Ezmesh AP, vlan enabled special AP %d\n", if_name, res);

	return res;
}

int IPACM_Config::SetSpclIface(char *event_iface_name) {
	int ipa_interface_index, if_index;
	int ret = IPACM_FAILURE;
	char if_name[IPA_IFACE_NAME_LEN];

	if (event_iface_name == NULL) {
		IPACMERR("Invalid input\n");
		return IPACM_FAILURE;
	}

	/* extract the parent if_name from the vlan iface */
	strlcpy(if_name, event_iface_name, IPA_IFACE_NAME_LEN);
	IPACMDBG_H("iface %s, event iface %s\n", if_name, event_iface_name);

	char *char_idx =  strrchr(if_name, '.');
	if (char_idx) {
		char_idx[0] = '\0';
		IPACMDBG_H("truncated iface name %s\n", if_name);
	}

	/* check if the AP iface already exists or not*/
	ret = IPACM_Iface::ipa_get_if_index(if_name, &(if_index));
	if (ret != IPACM_SUCCESS) {
		IPACMERR("Error while getting interface index for %s device", if_name);
		return IPACM_FAILURE;
	}

	/* Map the interface index. */
	ipa_interface_index = IPACM_Iface::iface_ipa_index_query(if_index);

	IPACMDBG_H("ipa_interface_index %d, if_cat:%d\n",
			   ipa_interface_index ,IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].if_cat);
	IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].is_spcl_if = true;

	IPACMDBG("eth %s changed to special iface %d\n",
			    if_name, IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].is_spcl_if);

	return ret;
}

void IPACM_Config::add_qos_params_info(ipa_ioc_qos_config *data)
{
	list<qos_param_info>::iterator it_qos_params;
	qos_param_info new_qos_info = { 0 };
	ipacm_cmd_q_data evt_data;

	if (data->dir == 1)
	{
		IPACMDBG_H("UL qos add params requested, no actions from ipa, dir : %d \n",data->dir);
		return;
	}

	if(pthread_mutex_lock(&qos_param_list_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("add_qos_params_info called start 0x%x,       end 0x%x \n",
			   m_qos_params.begin(), m_qos_params.end());
	IPACMDBG_H("qos iface: %s vlan id: %d\n", data->dev_name, data->dir);
	for (it_qos_params = m_qos_params.begin(); it_qos_params != m_qos_params.end(); it_qos_params++)
	{
		if(strncmp(data->dev_name, it_qos_params->iface_name, sizeof(data->dev_name)) == 0 &&
		   (data->dir == it_qos_params->dir) &&
		   (data->ip_type == it_qos_params->ip_type) &&
		   (data->traffic_class == it_qos_params->traffic_class) &&
		   (data->src_ip_addr == it_qos_params->ip_tup.src_ip_addr) &&
		   (data->dst_ip_addr == it_qos_params->ip_tup.dst_ip_addr) &&
		   (data->src_port_start == it_qos_params->ip_tup.sport_start) &&
		   (data->src_port_end == it_qos_params->ip_tup.sport_end) &&
		   (data->dst_port_start == it_qos_params->ip_tup.dport_start) &&
		   (data->dst_port_end == it_qos_params->ip_tup.dport_end) &&
		   (data->protocol == it_qos_params->ip_tup.protocol) &&
		   (data->dscp == it_qos_params->dscp) &&
		   (data->pcp == it_qos_params->pcp)
		   )
		{
			if (data->vlan_count)
			{
				for (uint16_t i = 0; i < data->vlan_count;i++)
				{
					if (data->vlan_ids[i] == it_qos_params->vlan_id)
					{
						IPACMDBG_H("The qos param was added before with vlan id %d for tc %d\n", it_qos_params->vlan_id, it_qos_params->traffic_class);
						pthread_mutex_unlock(&qos_param_list_lock);
						return;
					}
				}
				IPACMERR("No matching vlan id %d for tc %d was found. Add a new entry\n", it_qos_params->vlan_id, it_qos_params->traffic_class);
			}
			else
			{
				IPACMERR("The qos param was added before with tc %d\n", it_qos_params->traffic_class);
				pthread_mutex_unlock(&qos_param_list_lock);
				return;
			}
		}
	}

	strlcpy(new_qos_info.iface_name, data->dev_name, sizeof(new_qos_info.iface_name));

	new_qos_info.cat = data->iface_cat;
	new_qos_info.dir = data->dir;
	new_qos_info.ip_type = data->ip_type;
	new_qos_info.traffic_class = data->traffic_class;

	new_qos_info.ip_tup.src_ip_addr = data->src_ip_addr;
	new_qos_info.ip_tup.src_sub_mask = data->src_subnet;
	new_qos_info.ip_tup.dst_ip_addr = data->dst_ip_addr;
	new_qos_info.ip_tup.dst_sub_mask = data->dst_subnet;

	new_qos_info.ip_tup.src_v6_ip_addr[0] = data->src_v6_ip_addr[0];
	new_qos_info.ip_tup.src_v6_ip_addr[1] = data->src_v6_ip_addr[1];
	new_qos_info.ip_tup.src_v6_ip_addr[2] = data->src_v6_ip_addr[2];
	new_qos_info.ip_tup.src_v6_ip_addr[3] = data->src_v6_ip_addr[3];
	new_qos_info.ip_tup.src_v6_sub_mask[0] = data->src_v6_ip_subnet[0];
	new_qos_info.ip_tup.src_v6_sub_mask[1] = data->src_v6_ip_subnet[1];
	new_qos_info.ip_tup.src_v6_sub_mask[2] = data->src_v6_ip_subnet[2];
	new_qos_info.ip_tup.src_v6_sub_mask[3] = data->src_v6_ip_subnet[3];

	new_qos_info.ip_tup.dst_v6_ip_addr[0] = data->dst_v6_ip_addr[0];
	new_qos_info.ip_tup.dst_v6_ip_addr[1] = data->dst_v6_ip_addr[1];
	new_qos_info.ip_tup.dst_v6_ip_addr[2] = data->dst_v6_ip_addr[2];
	new_qos_info.ip_tup.dst_v6_ip_addr[3] = data->dst_v6_ip_addr[3];
	new_qos_info.ip_tup.dst_v6_sub_mask[0] = data->dst_v6_ip_subnet[0];
	new_qos_info.ip_tup.dst_v6_sub_mask[1] = data->dst_v6_ip_subnet[1];
	new_qos_info.ip_tup.dst_v6_sub_mask[2] = data->dst_v6_ip_subnet[2];
	new_qos_info.ip_tup.dst_v6_sub_mask[3] = data->dst_v6_ip_subnet[3];

	new_qos_info.ip_tup.sport_start = data->src_port_start;
	new_qos_info.ip_tup.sport_end = data->src_port_end;
	new_qos_info.ip_tup.dport_start = data->dst_port_start;
	new_qos_info.ip_tup.dport_end = data->dst_port_end;

	new_qos_info.ip_tup.protocol = data->protocol;

	new_qos_info.ip_tup.vlan_count = data->vlan_count;

	if (data->vlan_count)
	{
		for (int i = 0; i < new_qos_info.ip_tup.vlan_count; i++)
		{
			new_qos_info.vlan_id = data->vlan_ids[0];
		}
	}

	memcpy(new_qos_info.src_mac_addr, data->src_mac_addr, sizeof(new_qos_info.src_mac_addr));
	memcpy(new_qos_info.dst_mac_addr, data->dst_mac_addr, sizeof(new_qos_info.dst_mac_addr));

	new_qos_info.dscp = data->dscp;
	new_qos_info.pcp = data->pcp;
	new_qos_info.dscp_mark_val = data->dscp_mark_val;

	m_qos_params.push_front(new_qos_info);
	pthread_mutex_unlock(&qos_param_list_lock);

	IPACMDBG_H("Added qos iface: %s vlan id: %d with traffic class :%d \n", data->dev_name, data->dir, data->traffic_class);
	IPACMDBG_H("qos params list size now :%d \n", m_qos_params.size());


	//Send qos rule add event
	evt_data.event = IPA_QOS_RULE_ADD_EVENT;
	qos_param_info *qos_param = NULL;
	qos_param = (qos_param_info *)malloc(sizeof(qos_param_info));
	if (qos_param == NULL)
	{
		IPACMERR("Unable to allocate memory\n");
		return;
	}
	memset(qos_param, 0, sizeof(qos_param_info));
	memcpy(qos_param, &new_qos_info, sizeof(qos_param_info));
	evt_data.evt_data = (void *)qos_param;

	IPACMDBG_H("Posting event %s\n",
			   IPACM_Iface::ipacmcfg->getEventName(evt_data.event));
	IPACM_EvtDispatcher::PostEvt(&evt_data);
	IPACMDBG_H("Posted IPA_QOS_RULE_ADD_EVENT.\n");
	return;
}

void IPACM_Config::delete_qos_params_info(ipa_ioc_qos_config *data)
{
	list<qos_param_info>::iterator it_qos_params;
	qos_param_info new_qos_info;
	qos_client_info new_client_info;
	ipacm_cmd_q_data evt_data;
	list<qos_client_info>::iterator it_qos_client;
	int i = 0;

	if (data->dir == 1)
	{
		IPACMDBG_H("UL qos delete params requested, no actions from ipa, dir : %d \n",data->dir);
		return;
	}

	if(pthread_mutex_lock(&qos_param_list_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("qos iface: %s vlan id: %d\n", data->dev_name, data->dir);
	for(it_qos_params = m_qos_params.begin(); it_qos_params != m_qos_params.end(); it_qos_params++)
	{
		if(strncmp(data->dev_name, it_qos_params->iface_name, sizeof(data->dev_name)) == 0 &&
		   (data->dir == it_qos_params->dir) &&
		   (data->ip_type == it_qos_params->ip_type) &&
		   (data->traffic_class == it_qos_params->traffic_class) &&
		   (data->src_ip_addr == it_qos_params->ip_tup.src_ip_addr) &&
		   (data->dst_ip_addr == it_qos_params->ip_tup.dst_ip_addr) &&
		   (data->src_port_start == it_qos_params->ip_tup.sport_start) &&
		   (data->src_port_end == it_qos_params->ip_tup.sport_end) &&
		   (data->dst_port_start == it_qos_params->ip_tup.dport_start) &&
		   (data->dst_port_end == it_qos_params->ip_tup.dport_end) &&
		   (data->protocol == it_qos_params->ip_tup.protocol) &&
		   (data->dscp == it_qos_params->dscp) &&
		   (data->pcp == it_qos_params->pcp)
		   )
		{
			//Send qos rule del event
			evt_data.event = IPA_QOS_RULE_DEL_EVENT;
			qos_delete_param_info *qos_param = NULL;
			qos_param = (qos_delete_param_info *)malloc(sizeof(qos_delete_param_info) + it_qos_params->qos_client_list.size() * sizeof(qos_client_info));
			if (qos_param == NULL)
			{
				IPACMERR("Unable to allocate memory\n");
				return;
			}

			qos_param->client_cnt = it_qos_params->qos_client_list.size();
			for (it_qos_client = it_qos_params->qos_client_list.begin(); it_qos_client != it_qos_params->qos_client_list.end(); ++it_qos_client)
			{
				qos_param->qos_client_list[i].qos_rt_rule_hdl_v4 = it_qos_client->qos_rt_rule_hdl_v4;

				for (int v6_num = 0; v6_num < IPV6_NUM_ADDR; v6_num++)
				{
					qos_param->qos_client_list[i].qos_rt_rule_hdl_v6[v6_num] = it_qos_client->qos_rt_rule_hdl_v6[v6_num];
					qos_param->qos_client_list[i].qos_rt_rule_hdl_wan_v6[v6_num] = it_qos_client->qos_rt_rule_hdl_wan_v6[v6_num];
					IPACMDBG("v6 rule to delete v6_num %d rt hdl %d, wan hdl %d\n", v6_num,
							 qos_param->qos_client_list[i].qos_rt_rule_hdl_v6[v6_num],
							 qos_param->qos_client_list[i].qos_rt_rule_hdl_wan_v6[v6_num]);
				}
				qos_param->qos_client_list[i].route_rule_set_v4 = it_qos_client->route_rule_set_v4;
				qos_param->qos_client_list[i].route_rule_set_v6 = it_qos_client->route_rule_set_v6;

				i++;
			}

			evt_data.evt_data = (void *)qos_param;

			IPACMDBG_H("Posting event %s\n",
			   IPACM_Iface::ipacmcfg->getEventName(evt_data.event));
			IPACM_EvtDispatcher::PostEvt(&evt_data);
			IPACMDBG_H("Posted IPA_QOS_RULE_DEL_EVENT.\n");


			m_qos_params.erase(it_qos_params);
			break;
		}
	}

	pthread_mutex_unlock(&qos_param_list_lock);

	IPACMDBG_H("Deleted qos iface: %s vlan id: %d with traffic class :%d \n", data->dev_name, data->dir, data->traffic_class);
	IPACMDBG_H("qos params list size now :%d \n", m_qos_params.size());
	return;
}

void IPACM_Config::flush_qos_params_info(ipa_ioc_qos_config *data)
{
	list<qos_param_info>::iterator it_qos_params;
	qos_param_info new_qos_info;
	ipacm_cmd_q_data evt_data;
	list<qos_client_info>::iterator it_qos_client;
	int i = 0;

	if(pthread_mutex_lock(&qos_param_list_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("qos iface: %s vlan id: %d\n", data->dev_name, data->dir);
	for (it_qos_params = m_qos_params.begin(); it_qos_params != m_qos_params.end(); )
	{
		IPACMDBG_H("Flusing the qos parameters \n");
		//Send qos rule del event
		evt_data.event = IPA_QOS_RULE_DEL_EVENT;
		qos_delete_param_info *qos_param = NULL;
		qos_param = (qos_delete_param_info *)malloc(sizeof(qos_delete_param_info) + it_qos_params->qos_client_list.size() * sizeof(qos_client_info));
		if (qos_param == NULL)
		{
			IPACMERR("Unable to allocate memory\n");
			return;
		}

		qos_param->client_cnt = it_qos_params->qos_client_list.size();
		for (it_qos_client = it_qos_params->qos_client_list.begin(); it_qos_client != it_qos_params->qos_client_list.end(); ++it_qos_client)
		{
			qos_param->qos_client_list[i].qos_rt_rule_hdl_v4 = it_qos_client->qos_rt_rule_hdl_v4;
			for (int v6_num = 0; v6_num < IPV6_NUM_ADDR; v6_num++)
			{
				qos_param->qos_client_list[i].qos_rt_rule_hdl_v6[v6_num] = it_qos_client->qos_rt_rule_hdl_v6[v6_num];
				qos_param->qos_client_list[i].qos_rt_rule_hdl_wan_v6[v6_num] = it_qos_client->qos_rt_rule_hdl_wan_v6[v6_num];
			}
			qos_param->qos_client_list[i].route_rule_set_v4 = it_qos_client->route_rule_set_v4;
			qos_param->qos_client_list[i].route_rule_set_v6 = it_qos_client->route_rule_set_v6;

			i++;
		}

		evt_data.evt_data = (void *)qos_param;

		IPACMDBG_H("Posting event %s\n",
				   IPACM_Iface::ipacmcfg->getEventName(evt_data.event));
		IPACM_EvtDispatcher::PostEvt(&evt_data);
		IPACMDBG_H("Posted IPA_QOS_RULE_DEL_EVENT.\n");

		it_qos_params = m_qos_params.erase(it_qos_params);
	}

	pthread_mutex_unlock(&qos_param_list_lock);

	IPACMDBG_H("Flushed qos params list size now :%d \n", m_qos_params.size());
	return;
}
