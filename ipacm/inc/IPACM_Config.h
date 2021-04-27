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
#include<algorithm>

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
} tether_client_info;

/* struct to keep prefix info
 */
struct ipa_prefix_info {
	uint32_t addr[2];
	uint16_t vlan_id;
};

/* iface */
class IPACM_Config
{
public:

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

#ifdef FEATURE_VLAN_MPDN
	int num_ipv6_prefixes;
	struct ipa_prefix_info ipa_ipv6_prefixes[IPA_MAX_IPV6_PREFIX_FLT_RULE + IPA_MAX_MTU_ENTRIES];
	int num_no_offload_ipv6_prefix;
	uint32_t ipa_no_offload_ipv6_prefixes[IPA_MAX_IPV6_NO_OFFLOAD_PREFIX_FLT_RULE + IPA_MAX_MTU_ENTRIES][2];
#endif

	/* Store the non nat iface names */
	NatIfaces *pNatIfaces;

	/* Store the bridge iface names */
	char ipa_virtual_iface_name[IPA_IFACE_NAME_LEN];

	/* Store the number of interface IPACM read from XML file */
	int ipa_num_ipa_interfaces;

	int ipa_num_private_subnet;

	int ipa_num_alg_ports;

	const char* ipa_nat_memtype;
	int ipa_nat_max_entries;
	int ipa_ipv6ct_max_entries;

	bool ipacm_odu_router_mode;

	bool ipacm_odu_enable;

	bool ipacm_odu_embms_enable;

	/* Table containing ip_passthrough mpdn info */
	ipacm_ip_pass_mpdn_info ip_pass_mpdn_table[MAX_NUM_IP_PASS_MPDN];

	pthread_mutex_t ip_pass_mpdn_lock;

	/* nat_iface_lock */
	pthread_mutex_t nat_iface_lock;

#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	bool ipacm_lan_stats_enable;
	bool ipacm_lan_stats_enable_set;
#ifdef IPA_HW_FNR_STATS
	struct ipa_ioc_flt_rt_counter_alloc fnr_counters;
	/* Setting an index to 1 would mean that it is under use and 0, unused*/
	struct cnt_idx cnt_idx[IPA_MAX_FLT_RT_CLIENTS];
	pthread_mutex_t cnt_idx_lock;
	bool hw_fnr_stats_support;
#endif //IPA_HW_FNR_STATS
#endif

	bool ipv6_nat_enable;

	bool ipacm_gre_enable;

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

	/* Indicates whether socksv5 is enabled or not. */
	bool ipacm_socksv5_enable;

	/* Indicated how many clients offload support */
	int ipa_max_num_wifi_clients;
	int ipa_max_num_eth_clients;
	int ipa_eth_num_ipv6_addr;
	bool ipacm_client_number_set;
	/* Indicates whether sw-filtering is enabled or not. */
	int ipacm_flt_enable;

#ifdef FEATURE_VLAN_MPDN
	bool vlan_firewall_change_handle;

	ipacm_bridge vlan_bridges[IPA_MAX_NUM_BRIDGES];
	bool vlan_devices[IPA_VLAN_IF_MAX];
#endif
	/* Store the flt rule count for each producer client*/
	int flt_rule_count_v4[IPA_CLIENT_MAX];
	int flt_rule_count_v6[IPA_CLIENT_MAX];

	/* IPACM routing table name for v4/v6 */
	struct ipa_ioc_get_rt_tbl rt_tbl_lan_v4, rt_tbl_wan_v4, rt_tbl_default_v4, rt_tbl_v6, rt_tbl_wan_v6;
	struct ipa_ioc_get_rt_tbl rt_tbl_wan_dl;
	struct ipa_ioc_get_rt_tbl rt_tbl_odu_v4, rt_tbl_odu_v6;

	bool isMCC_Mode;
	pthread_mutex_t mac_flt_info_lock;
	/* map to store whitelisted and blacklisted unique mac adrrs */
	std::map<std::array<uint8_t, 6>, mac_flt_type *> mac_flt_lists;
#ifdef IPA_IOC_SET_MAC_FLT
	void mac_flt_info(ipa_ioc_mac_client_list_type *mac_flt_data);
#endif
	bool mac_addr_in_blacklist(uint8_t *mac_addr);
	void clear_whitelist_mac_add(uint8_t *mac_addr);
	std::map<std::array<uint8_t, 6>, mac_flt_type *> get_mac_flt_lists();
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

	void add_vlan_iface(ipa_ioc_vlan_iface_info *data);

	void del_vlan_iface(ipa_ioc_vlan_iface_info *data);

	void restore_vlan_nat_ifaces(const char *phys_iface_name);

	void handle_vlan_iface_info(ipacm_event_data_addr *data);

	void handle_vlan_client_info(ipacm_event_data_all *data);

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
	void add_bridge_vlan_mapping(ipa_ioc_bridge_vlan_mapping_info *data);
	void del_bridge_vlan_mapping(ipa_ioc_bridge_vlan_mapping_info *data);
	int get_bridge_vlan_mapping(ipa_ioc_bridge_vlan_mapping_info *data);
	uint16_t get_bridge_vlan_mapping_from_subnet(uint32_t ipv4_subnet);
	void add_vlan_bridge(ipacm_event_data_all * data_all);
	ipacm_bridge *get_vlan_bridge(char *name);
	bool is_added_vlan_iface(char *iface_name);
	bool iface_in_vlan_mode(const char * phys_iface_name);
	int get_iface_vlan_ids(char *phys_iface_name, uint16_t *Ids);
	int get_vlan_id(char *iface_name, uint16_t *vlan_id);
	void get_vlan_mode_ifaces();
#endif


#if defined(FEATURE_SOCKSv5) && defined(IPA_SOCKV5_EVENT_MAX)
	pthread_mutex_t socksv5_lock;
	std::list<socksv5_conn_info> socksv5_conn;
	std::list<rmnet_mux_id_info> mux_id_mapping;

	void add_socksv5_conn(ipa_socksv5_msg *add_socksv5_info);
	void del_socksv5_conn(uint32_t *socksv5_handle);
	int socksv5_v4_pdn;
	int pdn_ipv4[IPA_MAX_NUM_HW_PDNS];
	void add_mux_id_mapping(rmnet_mux_id_info *add_muxd_info);
	void del_mux_id_mapping(rmnet_mux_id_info *del_muxd_info);
	int query_mux_id(rmnet_mux_id_info *muxd_info);
#endif //defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)

#if defined(FEATURE_IPACM_PER_CLIENT_STATS) && defined(IPA_HW_FNR_STATS)
	int ipacm_alloc_fnr_counters(struct ipa_ioc_flt_rt_counter_alloc *fnr_counters, const int fd);
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
				if ((ip_pass_mpdn_table[indx].ip_pass_dev_type == dev_type) &&
					(memcmp(ip_pass_mpdn_table[indx].ip_pass_mac, client_mac, IPA_MAC_ADDR_SIZE) == 0) &&
					(ip_pass_mpdn_table[indx].vlan_id == vlan_id))
				{
						ret = true;
						break;
				}

	            /* Special case when mac is NULL. Passthrough will be enabled for first client. */
				/* Device type will be specified as MAX to support WLAN/USB/ETH clients and
				 * VLAN id can be 0 in case of WLAN or non VLAN interface. */
				if (ip_pass_mpdn_table[indx].ip_pass_skip_nat &&
					(memcmp(ip_pass_mpdn_table[indx].ip_pass_mac, null_mac, IPA_MAC_ADDR_SIZE) == 0) &&
					(ip_pass_mpdn_table[indx].ip_pass_dev_type == IPACM_CLIENT_DEVICE_MAX) &&
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

	void ip_pass_config_update(ipa_ioc_pdn_config *pdn_config);

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

	inline void SetQmapId(uint8_t id)
	{
		qmap_id = id;
	}

	inline uint8_t GetQmapId()
	{
		return qmap_id;
	}

	int SetExtProp(ipa_ioc_query_intf_ext_props *prop);

	ipacm_ext_prop* GetExtProp(ipa_ip_type ip_type);

	int DelExtProp(ipa_ip_type ip_type);

	enum ipa_hw_type GetIPAVer(bool get = false);

	int ResetClkVote(void);

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
#ifdef FEATURE_IPA_ANDROID
	inline bool AddPrivateSubnet(uint32_t ip_addr, int ipa_if_index)
	{
		ipacm_cmd_q_data evt_data;
		ipacm_event_data_fid *data_fid;
		uint32_t subnet_mask = ~0;
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
			private_subnet_table[ipa_num_private_subnet].subnet_mask = (subnet_mask >> 8) << 8;
			ipa_num_private_subnet++;

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
#endif /* defined(FEATURE_IPA_ANDROID)*/

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
		/* prefix shouldn't be present in offload list - this is a bug */
		for(int i = 0; i < num_ipv6_prefixes; i++)
		{
			if((prefix[0] == ipa_ipv6_prefixes[i].addr[0]) && (prefix[1] == ipa_ipv6_prefixes[i].addr[1]))
			{
				IPACMERR("prefix 0x[%X][%X] already exists in offload list\n", prefix[0], prefix[1]);
				return false;
			}
		}
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

		IPACMDBG("added no offload v6 prefix 0x[%X][%X]\n", prefix[0], prefix[1]);

		/* tell all LAN interfaces that we have a change in v6 prefixes */
		SendPrefixChangeEvent(-1);
		return true;
	}

	/* add to prefixes list if needed and notify LAN objects to modify rules*/
	inline bool add_vlan_ipv6_prefix(uint32_t *prefix, int ipa_if_num, uint16_t vlan_id)
	{
		int i = 0;
		int no_offload_temp = num_no_offload_ipv6_prefix;
		bool updated_reserved_slot = false;

		/* check for duplication */
		for(i = 0; i < num_ipv6_prefixes; i++)
		{
			if((prefix[0] == ipa_ipv6_prefixes[i].addr[0])
				&& (prefix[1] == ipa_ipv6_prefixes[i].addr[1])
				&& (vlan_id == ipa_ipv6_prefixes[i].vlan_id))
			{
				IPACMDBG_H("prefix 0x[%X][%X] already exists vlan_id inp %d saved %d\n",
					prefix[0], prefix[1], vlan_id, ipa_ipv6_prefixes[i].vlan_id);
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
				IPACMDBG_H("removed prefix 0x[%X][%X] from no offload list\n", prefix[1], prefix[2]);
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
				&& (ipa_ipv6_prefixes[i].vlan_id ==0)) {
				/* Update the vlan id if prefix already saved but vlan id not associated
				 * e.g Wlan for default pdn reserves a slot with vlan id 0, then eth vlan
				 * for default pdn associates with vlan id */
				IPACMDBG_H("Updating vlan id %d for prefix 0x[%X][%X] \n",
					ipa_ipv6_prefixes[i].vlan_id, ipa_ipv6_prefixes[i].addr[0], ipa_ipv6_prefixes[i].addr[1]);
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
			num_ipv6_prefixes++;
			IPACMDBG("added v6 prefix 0x[%X][%X] for vlan id %d\n", prefix[0], prefix[1], ipa_ipv6_prefixes[i].vlan_id);
		}

		/* tell other LAN interfaces that we have a change in v6 prefixes */
		SendPrefixChangeEvent(ipa_if_num);
		return true;
	}

	/* remove from prefixes list if needed and notify LAN objects to modify rules*/
	inline int del_vlan_ipv6_prefix(uint32_t* prefix, int ipa_if_num, bool reserve_slot = false)
	{
		int i = 0;
		for(i = 0; i < num_ipv6_prefixes; i++)
		{
			if((prefix[0] == ipa_ipv6_prefixes[i].addr[0]) && (prefix[1] == ipa_ipv6_prefixes[i].addr[1]))
			{
				if (reserve_slot) {
					IPACMDBG_H("Reserve slot for ipa_if_num %d\n", ipa_if_num);
					ipa_ipv6_prefixes[i].addr[0] = IPA_DUMMY_PREFIX;
					ipa_ipv6_prefixes[i].addr[1] = IPA_DUMMY_PREFIX;
				}
				else {
					for(; i < (num_ipv6_prefixes - 1); i++)
					{
						IPACMDBG_H("prefix 0x[%X][%X] will be removed\n", prefix[0], prefix[1]);
						ipa_ipv6_prefixes[i].addr[0] = ipa_ipv6_prefixes[i + 1].addr[0];
						ipa_ipv6_prefixes[i].addr[1] = ipa_ipv6_prefixes[i + 1].addr[1];
						ipa_ipv6_prefixes[i].vlan_id = ipa_ipv6_prefixes[i + 1].vlan_id;
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
		return false;
	}
#endif

#if defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
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
	inline int post_socksv5_add_vlan_evt(uint32_t public_ip)
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
		vlan_data->iptype = IPA_IP_v4;
		vlan_data->wan_ipv4_addr = public_ip;
		evt_data.evt_data = vlan_data;
		IPACMDBG("sending IPA_ROUTE_ADD_VLAN_PDN_EVENT vlan id %d, iptype %d,\n",
						vlan_data->VlanID,
						vlan_data->iptype);
		IPACM_EvtDispatcher::PostEvt(&evt_data);
		return IPACM_SUCCESS;
	}
#endif //defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)

	static const char *DEVICE_NAME_ODU;

private:

	static const int DEFAULT_IPV6CT_MAX_ENTRIES = 500;
	const char* DEFAULT_NAT_MEMTYPE = "DDR";

	enum ipa_hw_type ver;
	static IPACM_Config *pInstance;
	static const char *DEVICE_NAME;
	IPACM_Config(void);
	int m_fd; /* File descriptor of the IPA device node /dev/ipa */
	uint8_t qmap_id;
	ipacm_ext_prop ext_prop_v4;
	ipacm_ext_prop ext_prop_v6;
};

#endif /* IPACM_CONFIG */
