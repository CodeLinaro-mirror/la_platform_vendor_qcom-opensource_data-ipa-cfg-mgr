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
 * Changes from Qualcomm Technologies, Inc. are provided under the following license:
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear.
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
#include <IPACM_Iface.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "IPACM_Netlink.h"

IPACM_Config *IPACM_Config::pInstance = NULL;
const char *IPACM_Config::DEVICE_NAME = "/dev/ipa";
const char *IPACM_Config::DEVICE_NAME_ODU = "/dev/odu_ipa_bridge";
uint8_t peer_addr_updated = 0;

#define __stringify(x...) #x

#ifdef FEATURE_IPA_ANDROID
#define IPACM_CONFIG_FILE "/etc/IPACM_cfg.xml"
#else
#ifdef DATA_CONFIG_DIR_PATH
#define IPACM_CONFIG_FILE DATA_CONFIG_DIR_PATH"/ipa/IPACM_cfg.xml"
#else
#define IPACM_CONFIG_FILE "/etc/data/ipa/IPACM_cfg.xml"
#endif
#endif


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
	__stringify(IPA_CRADLE_WAN_MODE_SWITCH),               /* ipacm_event_cradle_wan_mode */
	__stringify(IPA_WAN_XLAT_CONNECT_EVENT),               /* ipacm_event_data_fid */
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
#ifdef FEATURE_L2TP
	__stringify(IPA_ADD_L2TP_CLIENT),                      /* ipacm_event_data_all */
	__stringify(IPA_DEL_L2TP_CLIENT),                      /* ipacm_event_data_all */
#ifdef IPA_L2TP_TUNNEL_UDP
	__stringify(IPA_ROUTE_DEL_L2TP_VLAN_EVENT),            /* ipacm_event_route_vlan */
	__stringify(IPA_HANDLE_WAN_L2TP_VLAN_DOWN),            /* ipacm_event_route_vlan */
#endif
#endif
#ifdef FEATURE_VLAN_MPDN
	__stringify(IPA_PREFIX_CHANGE_EVENT),                  /* ipacm_event_data_fid */
	__stringify(IPA_ROUTE_ADD_VLAN_PDN_EVENT),             /* ipacm_event_route_vlan */
	__stringify(IPA_HANDLE_WAN_VLAN_PDN_UP),               /* ipacm_event_vlan_pdn */
	__stringify(IPA_HANDLE_WAN_VLAN_PDN_DOWN),             /* ipacm_event_vlan_pdn */
#endif
#ifdef FEATURE_SOCKSv5
	__stringify(IPA_HANDLE_SOCKSv5_UP),                    /* ipacm_event_connection */
	__stringify(IPA_HANDLE_SOCKSv5_DOWN),                  /* NULL */
	__stringify(IPA_ADD_SOCKSv5_CONN),                     /* ipa_socksv5_msg */
	__stringify(IPA_DEL_SOCKSv5_CONN),                     /* ipa_socksv5_msg */
#endif
	__stringify(IPACM_EVENT_MAX),
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
	isMCC_Mode = false;
	ipa_max_valid_rm_entry = 0;
	ipacm_l2tp_enable = 0;
	ipacm_mpdn_enable = TRUE;   /* default setting as mpdn enable/l2tp disable */
	ipacm_socksv5_enable = false;

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
#endif
#if defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
	pthread_mutex_init(&vlan_l2tp_lock, NULL);
#endif
	pthread_mutex_init(&nat_iface_lock, NULL);
	IPACMDBG_H(" create IPACM_Config constructor\n");
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
	IPACMERR("hw hdl = %d, 0x%x\n"
		 "hw_num_counters = %u\n"
	 	 "hw_start_id = %u\n, hw_allow_less = %u\n",
		 fnr->hdl, fnr->hw_counter.num_counters, fnr->hw_counter.allow_less,
		 fnr->hw_counter.start_id);
	IPACMERR("sw hdl = %d, 0x%x\n"
		 "sw_num_counters = %u\n"
	 	 "sw_start_id = %u\n, sw_allow_less = %u\n",
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
	query->reset = true;
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
			IPACMERR("IOCTL %d failed\n", IPA_IOC_FNR_COUNTER_QUERY);
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
		IPACMERR("Failed to execute ioctl %d\n", IPA_IOC_FNR_COUNTER_ALLOC);
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

	struct statvfs stat;
	int64_t available_partition_size_bytes = 0;
	int64_t quota_allowed_size_bytes = 0;
	char ipacm_log_file[] = IPACM_LOG_COLLECTION_FILE;
	char *ipacm_log_dir = NULL;

	cfg = (IPACM_conf_t *)malloc(sizeof(IPACM_conf_t));
	if(cfg == NULL)
	{
		IPACMERR("Unable to allocate cfg memory.\n");
		return IPACM_FAILURE;
	}
	uint32_t subnet_addr;
	uint32_t subnet_mask;
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

	strlcpy(IPACM_config_file, IPACM_CONFIG_FILE, sizeof(IPACM_config_file));

	IPACMDBG_H("\n IPACM XML file is %s \n", IPACM_config_file);
	if (IPACM_SUCCESS == ipacm_read_cfg_xml(IPACM_config_file, cfg))
	{
		IPACMDBG_H("\n IPACM XML read OK \n");
	}
	else
	{
		IPACMERR("\n IPACM XML read failed \n");
		ret = IPACM_FAILURE;
		goto fail;
	}

	if(cfg->max_file_size_quota > 100)
	{
		IPACMDBG_H("Invalid Quota Set[%d], changing to default[%d]\n",
				cfg->max_file_size_quota, IPACM_DEF_LOG_FILE_SIZE_QUOTA);
		cfg->max_file_size_quota = IPACM_DEF_LOG_FILE_SIZE_QUOTA;
	}
	ipacm_log_dir = dirname(ipacm_log_file);

	/* Read the available partition size */
	if (statvfs(ipacm_log_dir, &stat) != 0) {
		IPACMDBG_H("Failed to get available partition size\n");
		max_file_size = 0;
	}
	else
	{
		if (stat.f_frsize != 0 && (stat.f_bavail > (INT64_MAX / stat.f_frsize)))
			available_partition_size_bytes = INT64_MAX;
		else
			available_partition_size_bytes = (int64_t)(stat.f_bavail * stat.f_frsize);

		quota_allowed_size_bytes = (int64_t)((double)available_partition_size_bytes *
                                     ((double)cfg->max_file_size_quota / 100.0));

		IPACMDBG_H("APS[%lld Bytes], Configuring file size to min of max_filesz[%lld Bytes] & quota_allowed_size[%lld Bytes] \n",
				available_partition_size_bytes, cfg->max_file_size, quota_allowed_size_bytes);

		max_file_size = std::min({cfg->max_file_size, quota_allowed_size_bytes});
	}
	IPACMDBG_H("max_file_size %lld\n", max_file_size);

	log_init();

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
		iface_table[i].if_cat = cfg->iface_config.iface_entries[i].if_cat;
		iface_table[i].if_mode = cfg->iface_config.iface_entries[i].if_mode;
		iface_table[i].wlan_mode = cfg->iface_config.iface_entries[i].wlan_mode;
		IPACMDBG_H("IPACM_Config::iface_table[%d] = %s, cat=%d, mode=%d wlan-mode=%d \n", i, iface_table[i].iface_name,
				iface_table[i].if_cat, iface_table[i].if_mode, iface_table[i].wlan_mode);
		/* copy bridge interface name to ipacmcfg */
		if( iface_table[i].if_cat == VIRTUAL_IF)
		{
			strlcpy(ipa_virtual_iface_name, iface_table[i].iface_name, sizeof(ipa_virtual_iface_name));
			IPACMDBG_H("ipa_virtual_iface_name(%s) \n", ipa_virtual_iface_name);
		}
	}

	/* Construct IPACM Private_Subnet table */
	memset(&private_subnet_table, 0, sizeof(private_subnet_table));
	ipa_num_private_subnet = cfg->private_subnet_config.num_subnet_entries;

	for (i = 0; i < cfg->private_subnet_config.num_subnet_entries; i++)
	{
		memcpy(&private_subnet_table[i].subnet_addr,
					 &cfg->private_subnet_config.private_subnet_entries[i].subnet_addr,
					 sizeof(cfg->private_subnet_config.private_subnet_entries[i].subnet_addr));

		memcpy(&private_subnet_table[i].subnet_mask,
					 &cfg->private_subnet_config.private_subnet_entries[i].subnet_mask,
					 sizeof(cfg->private_subnet_config.private_subnet_entries[i].subnet_mask));

		subnet_addr = htonl(private_subnet_table[i].subnet_addr);
		memcpy(&in_addr_print,&subnet_addr,sizeof(in_addr_print));
		IPACMDBG_H("%dst::private_subnet_table= %s \n ", i,
						 inet_ntoa(in_addr_print));

		subnet_mask =  htonl(private_subnet_table[i].subnet_mask);
		memcpy(&in_addr_print,&subnet_mask,sizeof(in_addr_print));
		IPACMDBG_H("%dst::private_subnet_table= %s \n ", i,
						 inet_ntoa(in_addr_print));
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
	}
	else
	{
		ipa_ipv6ct_max_entries = 0;
		IPACMDBG_H("IPv6CT is disabled\n");
	}

	/* Find ODU is either router mode or bridge mode*/
	ipacm_odu_enable = cfg->odu_enable;
	ipacm_odu_router_mode = cfg->router_mode_enable;
	ipacm_odu_embms_enable = cfg->odu_embms_enable;
	IPACMDBG_H("ipacm_odu_enable %d\n", ipacm_odu_enable);
	IPACMDBG_H("ipacm_odu_mode %d\n", ipacm_odu_router_mode);
	IPACMDBG_H("ipacm_odu_embms_enable %d\n", ipacm_odu_embms_enable);

	ipacm_ip_passthrough_mode = cfg->ip_passthrough_mode;
	IPACMDBG_H("ipacm_ip_passthrough_mode %d. \n", ipacm_ip_passthrough_mode);

	memcpy(ipacm_ip_passthrough_mac, cfg->ip_passthrough_mac.ether_addr_octet, IPA_MAC_ADDR_SIZE);

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

#ifndef IPA_L2TP_TUNNEL_UDP
	if (ipacm_mpdn_enable == TRUE && ipacm_l2tp_enable != IPACM_L2TP_DISABLE)
	{
		IPACMERR("Not support both VLAN_MPDN and L2TP are enable \n");
		exit(0);
	}
#endif
	ipa_num_wlan_guest_ap = cfg->num_wlan_guest_ap;
	IPACMDBG_H("ipa_num_wlan_guest_ap %d\n",ipa_num_wlan_guest_ap);

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

	/* clear lists */
#if defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
	m_vlan_iface.clear();
#ifdef FEATURE_L2TP
	m_l2tp_vlan_mapping.clear();
	l2tp_session_gw_info.clear();
	l2tp_client.clear();
#endif //#ifdef FEATURE_L2TP
#endif //defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)

#ifdef FEATURE_VLAN_MPDN
	m_bridge_vlan_mapping.clear();
#endif

#if defined(FEATURE_SOCKSv5) && defined(IPA_SOCKV5_EVENT_MAX)
	socksv5_conn.clear();
	mux_id_mapping.clear();
#endif

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
void IPACM_Config::add_bridge_vlan_mapping(ipa_ioc_bridge_vlan_mapping_info *data)
{
	list<bridge_vlan_mapping_info>::iterator it_mapping;
	bridge_vlan_mapping_info new_mapping;
	ipacm_bridge *bridge = NULL;
#ifdef IPA_L2TP_TUNNEL_UDP
	list<l2tp_vlan_mapping_info>::iterator it_l2tp_mapping;
#endif

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("trying to add bridge %s -> VID %d mapping, subnet 0x%X & 0x%X\n",
		data->bridge_name,
		data->vlan_id,
		data->bridge_ipv4,
		data->subnet_mask);

	for(it_mapping = m_bridge_vlan_mapping.begin(); it_mapping != m_bridge_vlan_mapping.end(); it_mapping++)
	{
		if(strncmp(data->bridge_name, it_mapping->bridge_iface_name, sizeof(data->bridge_name)) == 0)
		{
			IPACMERR("The bridge %s was added before with vlan id %d\n", data->bridge_name,
				it_mapping->bridge_associated_VID);
			goto fail;
		}
	}

	memset(&new_mapping, 0, sizeof(new_mapping));
	strlcpy(new_mapping.bridge_iface_name, data->bridge_name,
		sizeof(new_mapping.bridge_iface_name));
	new_mapping.bridge_associated_VID = data->vlan_id;
	new_mapping.bridge_ipv4 = data->bridge_ipv4;
	new_mapping.subnet_mask = data->subnet_mask;
	new_mapping.lan2lan_sw = data->lan2lan_sw;

#ifdef IPA_L2TP_TUNNEL_UDP
	for(it_l2tp_mapping = m_l2tp_vlan_mapping.begin(); it_l2tp_mapping != m_l2tp_vlan_mapping.end(); it_l2tp_mapping++)
	{
		if(strncmp(data->bridge_name, it_l2tp_mapping->l2tp_bridge_iface_name,
			strlen(data->bridge_name)) == 0)
		{
			IPACMDBG_H("Found vlan-l2tp mapping, Adding Bridge info\n");
			/* updating vlan in the bridge vlan mapping also */
			new_mapping.bridge_associated_VID = it_l2tp_mapping->l2tp_bridge_vlan_id;
			data->vlan_id = it_l2tp_mapping->l2tp_bridge_vlan_id;
		}
	}
#endif

	m_bridge_vlan_mapping.push_front(new_mapping);
	IPACMDBG_H("added bridge %s with VID %d, lan2lan_sw=%d\n", data->bridge_name, data->vlan_id, data->lan2lan_sw);
	pthread_mutex_unlock(&vlan_l2tp_lock);

	bridge = get_vlan_bridge(data->bridge_name);
	if(bridge)
	{
		IPACMDBG_H("bridge %s already added, update data\n",
			data->bridge_name);
		bridge->associate_VID = data->vlan_id;
		bridge->bridge_ipv4_addr = data->bridge_ipv4;
		bridge->bridge_netmask = data->subnet_mask;
	}

	return;
fail:
	pthread_mutex_unlock(&vlan_l2tp_lock);
	return;
}

void IPACM_Config::del_bridge_vlan_mapping(ipa_ioc_bridge_vlan_mapping_info *data)
{
	list<bridge_vlan_mapping_info>::iterator it_mapping;
	ipacm_bridge *bridge = NULL;

	IPACMDBG_H("deleting bridge vlan mapping (%s)->(%d)\n",
		data->bridge_name,
		data->vlan_id);

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	for(it_mapping = m_bridge_vlan_mapping.begin(); it_mapping != m_bridge_vlan_mapping.end(); it_mapping++)
	{
		if(strncmp(data->bridge_name, it_mapping->bridge_iface_name, sizeof(data->bridge_name)) == 0)
		{
			IPACMDBG_H("Found the bridge mapping (%s->%d)\n",
				data->bridge_name,
				it_mapping->bridge_associated_VID);
			m_bridge_vlan_mapping.erase(it_mapping);

			bridge = get_vlan_bridge(data->bridge_name);
			if(bridge)
			{
				IPACMDBG_H("bridge %s - remove vlan id\n",
					data->bridge_name);
				bridge->associate_VID = 0;
			}
			break;
		}
	}

	pthread_mutex_unlock(&vlan_l2tp_lock);
	return;
}

int IPACM_Config::get_bridge_vlan_mapping(ipa_ioc_bridge_vlan_mapping_info *data)
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
			data->lan2lan_sw = it_mapping->lan2lan_sw;
			ret = IPACM_SUCCESS;
			break;
		}
	}

	pthread_mutex_unlock(&vlan_l2tp_lock);
	return ret;
}

bool IPACM_Config::is_lan2lan_sw_path(uint16_t vlan_id)
{
	list<bridge_vlan_mapping_info>::iterator it_mapping;
	bool ret = false;

	/* always offload non-vlan lan2lan */
	if (vlan_id == 0)
		return false;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return ret;
	}

	for(it_mapping = m_bridge_vlan_mapping.begin(); it_mapping != m_bridge_vlan_mapping.end(); it_mapping++)
	{
		if(it_mapping->bridge_associated_VID == vlan_id && it_mapping->lan2lan_sw)
		{
			IPACMDBG_H("lan2lan_sw is enabled for bridge %s, VID %D\n", it_mapping->bridge_iface_name, it_mapping->bridge_associated_VID);
			ret = true;
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

#if defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
void IPACM_Config::add_vlan_iface(ipa_ioc_vlan_iface_info *data)
{
	list<vlan_iface_info>::iterator it_vlan;
	vlan_iface_info new_vlan_info;
	int vlan_iface_index = 0;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("Vlan iface: %s vlan id: %d\n", data->name, data->vlan_id);
	for(it_vlan = m_vlan_iface.begin(); it_vlan != m_vlan_iface.end(); it_vlan++)
	{
		if(strncmp(it_vlan->vlan_iface_name, data->name, sizeof(it_vlan->vlan_iface_name)) == 0)
		{
			IPACMERR("The vlan iface was added before with id %d\n", it_vlan->vlan_id);
			pthread_mutex_unlock(&vlan_l2tp_lock);
			return;
		}
	}
#ifdef FEATURE_L2TP
	if ((ipacm_l2tp_enable == IPACM_L2TP) || (ipacm_l2tp_enable == IPACM_L2TP_E2E))
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
	memset(&new_vlan_info, 0 , sizeof(new_vlan_info));
	strlcpy(new_vlan_info.vlan_iface_name, data->name, sizeof(new_vlan_info.vlan_iface_name));
	new_vlan_info.vlan_id = data->vlan_id;
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
#endif
	/* Solve the issue in case NEWADDR comes before VLAN IOCTL */
	if(IPACM_Iface::ipa_get_if_index(data->name, &vlan_iface_index) == IPACM_SUCCESS)
	{
		IPACM_Iface::iface_addr_query(vlan_iface_index, true, NULL);
	}

	/* Sending Getneigh to receive missing neighbor in case if missed early */
	IPACMDBG_H("Query Getneigh for vlan ifaces\n");
	ipa_nl_query_newneigh(AF_BRIDGE);
	IPACMDBG_H("Query Getneigh for v4\n");
	ipa_nl_query_newneigh(AF_INET);
	IPACMDBG_H("Query Getneigh for v6\n");
	ipa_nl_query_newneigh(AF_INET6);
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

void IPACM_Config::del_vlan_iface(ipa_ioc_vlan_iface_info *data)
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
		if(strncmp(it_vlan->vlan_iface_name, data->name, sizeof(it_vlan->vlan_iface_name)) == 0)
		{
			IPACMDBG_H("Found the vlan interface\n");
			m_vlan_iface.erase(it_vlan);
			break;
		}
	}
#ifdef FEATURE_VLAN_MPDN
	if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
	{
		DelNatIfaces(data->name);
		IPACMDBG_H("Del VLAN iface %s to nat ifaces.\n", data->name);
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
		if(strncmp(it_vlan->vlan_iface_name, data->iface_name,
			sizeof(it_vlan->vlan_iface_name)) == 0)
		{
			IPACMDBG_H("Found vlan iface: %s\n", it_vlan->vlan_iface_name);
			memcpy(it_vlan->vlan_iface_ipv6_addr, data->ipv6_addr,
				sizeof(it_vlan->vlan_iface_ipv6_addr));

#ifdef FEATURE_L2TP
			if ((ipacm_l2tp_enable == IPACM_L2TP) || (ipacm_l2tp_enable == IPACM_L2TP_E2E))
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

void IPACM_Config::del_l2tp_client_gw_info(ipacm_event_data_all *data, uint32_t *l2tp_gw_addr)
{
	list<l2tp_client_gw_info>::iterator it_l2tp_gw;

	if(data == NULL || l2tp_gw_addr == NULL)
	{
		IPACMERR("Not valid GW info recieved\n");
		return;
	}
	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("Incoming vlan client iface: %s IPv6 address: 0x%08x%08x%08x%08x\n", data->iface_name,
		data->ipv6_addr[0], data->ipv6_addr[1], data->ipv6_addr[2], data->ipv6_addr[3]);

	for(it_l2tp_gw = l2tp_session_gw_info.begin(); it_l2tp_gw != l2tp_session_gw_info.end(); it_l2tp_gw++)
	{
		if(!(memcmp(it_l2tp_gw->client_iface_name,data->iface_name,sizeof(data->iface_name))) &&
		(!(memcmp(it_l2tp_gw->client_ipv6_addr, data->ipv6_addr, sizeof(data->ipv6_addr)))) &&
		(!(memcmp(it_l2tp_gw->client_ipv6_gw_addr, l2tp_gw_addr, sizeof(it_l2tp_gw->client_ipv6_gw_addr)))))
		{
			IPACMDBG_H("GW info is clearing from the list\n");
			l2tp_session_gw_info.erase(it_l2tp_gw);
			pthread_mutex_unlock(&vlan_l2tp_lock);
			return;
		}
	}
	if(it_l2tp_gw == l2tp_session_gw_info.end())
	{
		IPACMERR("GW info is not present in list\n");
	}
	pthread_mutex_unlock(&vlan_l2tp_lock);
	return;
}

void IPACM_Config::handle_l2tp_client_gw_info(ipacm_event_data_all *data, uint32_t *l2tp_gw_addr)
{
	list<l2tp_vlan_mapping_info>::iterator it_mapping;
	list<vlan_iface_info>::iterator it_vlan;
	list<l2tp_client_gw_info>::iterator it_l2tp_gw;
	l2tp_client_gw_info new_mapping;
	uint8_t mac_addr[6]={0}, peer_client_mac[6];
	int i;
	bool rt_info = false;

	if(data == NULL || l2tp_gw_addr == NULL)
	{
		IPACMERR("Not valid GW info recieved\n");
		return;
	}
	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	memset(&peer_client_mac, 0, sizeof(peer_client_mac));
	IPACMDBG_H("Incoming vlan client iface: %s IPv6 address: 0x%08x%08x%08x%08x\n", data->iface_name,
		data->ipv6_addr[0], data->ipv6_addr[1], data->ipv6_addr[2], data->ipv6_addr[3]);

	memset(&new_mapping, 0, sizeof(new_mapping));

	for(it_l2tp_gw = l2tp_session_gw_info.begin(); it_l2tp_gw != l2tp_session_gw_info.end(); it_l2tp_gw++)
	{
		if(!(memcmp(it_l2tp_gw->client_iface_name,data->iface_name,sizeof(data->iface_name))) &&
		(!(memcmp(it_l2tp_gw->client_ipv6_addr, data->ipv6_addr, sizeof(data->ipv6_addr)))) &&
		(!(memcmp(it_l2tp_gw->client_ipv6_gw_addr, l2tp_gw_addr, sizeof(it_l2tp_gw->client_ipv6_gw_addr)))))
		{
			IPACMERR("Already GW info is updated\n");
			pthread_mutex_unlock(&vlan_l2tp_lock);
			return;
		}
	}
	if(it_l2tp_gw == l2tp_session_gw_info.end())
	{
		memcpy(&new_mapping.client_iface_name,data->iface_name,sizeof(data->iface_name));
		memcpy(&new_mapping.client_ipv6_addr, data->ipv6_addr, sizeof(data->ipv6_addr));
		memcpy(&new_mapping.client_ipv6_gw_addr, l2tp_gw_addr, sizeof(new_mapping.client_ipv6_gw_addr));
		memset(&new_mapping.client_mac, 0, sizeof(new_mapping.client_mac));
		IPACMDBG_H("Added valid GW info to list\n");
	}

	for(it_vlan = m_vlan_iface.begin(); it_vlan != m_vlan_iface.end(); it_vlan++)
	{
		if(strncmp(it_vlan->vlan_iface_name, data->iface_name, sizeof(it_vlan->vlan_iface_name)) == 0)
		{
			for(i = 0 ; i < IPA_MAX_NUM_PEER_ULA; i++)
			{
				/* checking if neigh is already populated with peer client gw */
				if(memcmp(it_vlan->vlan_client_ipv6_addr[i], l2tp_gw_addr, sizeof(data->ipv6_addr)) == 0)
				{
					IPACMDBG_H("neigh is populated for peer neighour\n");
					memcpy(&peer_client_mac, &it_vlan->vlan_client_mac[i], sizeof(peer_client_mac));
					rt_info = true;
					break;
				}
			}
			if(rt_info == true)
			{
				break;
			}
		}
	}
	if((rt_info == false && ((memcmp(&peer_client_mac, &mac_addr, sizeof(peer_client_mac)) == 0) || (it_vlan == m_vlan_iface.end()))))
	{
		IPACMERR("neigh is not populated for peer neighour\n");
		goto end;
	}
	else
	{
		IPACMDBG("updated peer neighour mac %x:%x:%x:%x:%x:%x\n", peer_client_mac[0], peer_client_mac[1], peer_client_mac[2],
			peer_client_mac[3], peer_client_mac[4], peer_client_mac[5]);
		memcpy(&new_mapping.client_mac, &peer_client_mac, sizeof(peer_client_mac));
	}

	if ((ipacm_l2tp_enable == IPACM_L2TP) || (ipacm_l2tp_enable == IPACM_L2TP_E2E))
	{
		for(it_mapping = m_l2tp_vlan_mapping.begin(); it_mapping != m_l2tp_vlan_mapping.end(); it_mapping++)
		{
			/* checking if l2tp client addr and gw client addr matching or not to update mac */
			if((strncmp(it_mapping->vlan_iface_name, data->iface_name, sizeof(it_mapping->vlan_iface_name)) == 0) &&
			(!memcmp(it_mapping->vlan_client_ipv6_addr, data->ipv6_addr, sizeof(it_mapping->vlan_client_ipv6_addr))))
			{
				IPACMDBG_H("tunnel gateway ip and neigh mac is added\n");
				memcpy(it_mapping->vlan_client_ipv6_gw_addr, l2tp_gw_addr, sizeof(it_mapping->vlan_client_ipv6_gw_addr));
				memcpy(it_mapping->vlan_client_mac, &peer_client_mac, sizeof(it_mapping->vlan_client_mac));
			}
		}
	}
end:
	l2tp_session_gw_info.push_front(new_mapping);
	pthread_mutex_unlock(&vlan_l2tp_lock);
}

void IPACM_Config::del_l2tp_vlan_client_info(ipacm_event_data_all *data)
{
	list<vlan_iface_info>::iterator it_vlan;
	int i;

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
		if(strncmp(it_vlan->vlan_iface_name, data->iface_name, sizeof(it_vlan->vlan_iface_name)) == 0)
		{
			for(i = 0 ; i < IPA_MAX_NUM_PEER_ULA; i++)
			{
				if(memcmp(it_vlan->vlan_client_ipv6_addr[i], data->ipv6_addr, sizeof(data->ipv6_addr)) == 0 &&
				memcmp(it_vlan->vlan_client_mac[i], data->mac_addr, sizeof(data->mac_addr)) == 0)
				{
					IPACMDBG_H("Vlan client info found clearing the info\n");
					memset(it_vlan->vlan_client_mac[i], 0 , sizeof(data->mac_addr));
					memset(it_vlan->vlan_client_ipv6_addr[i], 0 , sizeof(it_vlan->vlan_client_ipv6_addr[i]));
					pthread_mutex_unlock(&vlan_l2tp_lock);
					return;
				}

			}
			/* updating new vlan info to the list */
			if(i == IPA_MAX_NUM_PEER_ULA)
			{
				IPACMDBG_H("no Vlan client info found to clear the info\n");
				break;
			}
		}
	}
	pthread_mutex_unlock(&vlan_l2tp_lock);
	return;
}

void IPACM_Config::handle_vlan_client_info(ipacm_event_data_all *data)
{
	list<l2tp_vlan_mapping_info>::iterator it_mapping;
	list<vlan_iface_info>::iterator it_vlan;
	list<l2tp_client_gw_info>::iterator it_l2tp_gw;
	uint8_t mac_addr[6]={0};
	int i, index = IPA_MAX_NUM_PEER_ULA;
	bool update_free_index = false;

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
		if(strncmp(it_vlan->vlan_iface_name, data->iface_name, sizeof(it_vlan->vlan_iface_name)) == 0)
		{
			for(i = 0 ; i < IPA_MAX_NUM_PEER_ULA; i++)
			{
				if(memcmp(it_vlan->vlan_client_ipv6_addr[i], data->ipv6_addr, sizeof(data->ipv6_addr)) == 0 &&
				memcmp(it_vlan->vlan_client_mac[i], data->mac_addr, sizeof(data->mac_addr)) == 0)
				{
					IPACMDBG_H("Vlan client info has been populated before, return.\n");
					pthread_mutex_unlock(&vlan_l2tp_lock);
					return;
				}
				else if((it_vlan->vlan_client_ipv6_addr[i][0] == 0) && (it_vlan->vlan_client_ipv6_addr[i][1] == 0) &&
				(it_vlan->vlan_client_ipv6_addr[i][2] == 0) && (it_vlan->vlan_client_ipv6_addr[i][3] == 0) && !update_free_index)
				{
					update_free_index = true;
					index = i;
				}
			}
			/* updating new vlan info to the list */
			if(index != IPA_MAX_NUM_PEER_ULA && update_free_index)
			{
				memcpy(&it_vlan->vlan_client_mac[index], data->mac_addr, sizeof(data->mac_addr));
				memcpy(&it_vlan->vlan_client_ipv6_addr[index], data->ipv6_addr, sizeof(data->ipv6_addr));
				break;
			}
		}
	}

	for(it_l2tp_gw = l2tp_session_gw_info.begin(); it_l2tp_gw != l2tp_session_gw_info.end(); it_l2tp_gw++)
	{
		IPACMDBG_H("GW vlan client iface: %s GW IPv6 address: 0x%08x%08x%08x%08x\n", it_l2tp_gw->client_iface_name,
		it_l2tp_gw->client_ipv6_gw_addr[0], it_l2tp_gw->client_ipv6_gw_addr[1], it_l2tp_gw->client_ipv6_gw_addr[2], it_l2tp_gw->client_ipv6_gw_addr[3]);
		/* checking if gw is populated or not, if populated updating mac to gw list */
		if(!(memcmp(it_l2tp_gw->client_iface_name, data->iface_name,sizeof(data->iface_name))) &&
		(!(memcmp(it_l2tp_gw->client_ipv6_gw_addr, data->ipv6_addr, sizeof(data->ipv6_addr)))))
		{
			if(memcmp(mac_addr, it_l2tp_gw->client_mac, sizeof(it_l2tp_gw->client_mac)) == 0)
			{
				IPACMDBG_H("Already GW info is updated , now mac is updating\n");
				memcpy(it_l2tp_gw->client_mac, data->mac_addr, sizeof(data->mac_addr));
			}
		}
	}

#ifdef FEATURE_L2TP
	if ((ipacm_l2tp_enable == IPACM_L2TP) || (ipacm_l2tp_enable == IPACM_L2TP_E2E))
	{
		for(it_mapping = m_l2tp_vlan_mapping.begin(); it_mapping != m_l2tp_vlan_mapping.end(); it_mapping++)
		{
			if(strncmp(it_mapping->vlan_iface_name, data->iface_name, sizeof(it_mapping->vlan_iface_name)) == 0)
			{
				IPACMDBG_H("Found vlan iface in l2tp mapping list: %s, l2tp iface: %s, peer_addr_updated: %d\n",
					it_mapping->vlan_iface_name, it_mapping->l2tp_iface_name, peer_addr_updated);
				if(!peer_addr_updated)
				{
					memcpy(it_mapping->vlan_client_mac, data->mac_addr, sizeof(data->mac_addr));
					memcpy(it_mapping->vlan_client_ipv6_addr, data->ipv6_addr, sizeof(data->ipv6_addr));
				}
				else
				{
					IPACMDBG_H("Already QCMAP has updated the IP address for l2tp iface: %s, (Copy vlan MAC)Ignore.\n",
						it_mapping->l2tp_iface_name);
					/* update mac address if client is immediate peer or it is found in l2tp_gw list */
					if(((memcmp(it_mapping->vlan_client_ipv6_addr, data->ipv6_addr, sizeof(data->ipv6_addr)) == 0) &&
					(memcmp(it_mapping->vlan_client_ipv6_gw_addr, data->ipv6_addr, sizeof(data->ipv6_addr)) == 0)))
					{
						IPACMDBG_H("Got the neighour for %s vlan iface, with proper v6 address So copying the mac.\n",
							it_mapping->l2tp_iface_name);
						memcpy(it_mapping->vlan_client_mac, data->mac_addr, sizeof(data->mac_addr));
						continue;
					}
					for(it_l2tp_gw = l2tp_session_gw_info.begin(); it_l2tp_gw != l2tp_session_gw_info.end(); it_l2tp_gw++)
					{
						IPACMDBG_H("GW vlan client iface: %s GW IPv6 address: 0x%08x%08x%08x%08x\n", it_l2tp_gw->client_iface_name,
							it_l2tp_gw->client_ipv6_gw_addr[0], it_l2tp_gw->client_ipv6_gw_addr[1], it_l2tp_gw->client_ipv6_gw_addr[2], it_l2tp_gw->client_ipv6_gw_addr[3]);
						/* checking if gw is populated or not, if populated updating mac to gw list */
						if(!(memcmp(it_l2tp_gw->client_iface_name, data->iface_name,sizeof(data->iface_name))) &&
							!(memcmp(it_l2tp_gw->client_ipv6_gw_addr, data->ipv6_addr, sizeof(data->ipv6_addr))) &&
							!(memcmp(it_mapping->vlan_client_ipv6_addr, it_l2tp_gw->client_ipv6_addr, sizeof(it_l2tp_gw->client_ipv6_addr))))
						{
							IPACMDBG_H("Got the neighour for %s vlan iface GW, with proper v6 address So copying the mac.\n",
								it_mapping->l2tp_iface_name);
							memcpy(it_mapping->vlan_client_mac, data->mac_addr, sizeof(data->mac_addr));
						}
					}
				}
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

	IPACMDBG("modes are EMAC %d, RNDIS %d, ECM %d\n",
		vlan_devices[IPA_VLAN_IF_EMAC],
		vlan_devices[IPA_VLAN_IF_RNDIS],
		vlan_devices[IPA_VLAN_IF_ECM]);
}

void IPACM_Config::add_vlan_bridge(ipacm_event_data_all *data_all)
{
	uint8_t testmac[IPA_MAC_ADDR_SIZE];
	ipa_ioc_bridge_vlan_mapping_info mapping_info;

	memset(testmac, 0, IPA_MAC_ADDR_SIZE * sizeof(uint8_t));
	memset(&mapping_info, 0, sizeof(mapping_info));

	strlcpy(mapping_info.bridge_name, data_all->iface_name, IF_NAME_LEN);

	for(int i = 0; i < IPA_MAX_NUM_BRIDGES; i++)
	{
		if(strcmp(data_all->iface_name, IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_name) == 0)
		{
			IPACMDBG_H("bridge %s already exist with MAC %02x:%02x:%02x:%02x:%02x:%02x\n ignoring\n",
				data_all->iface_name, IPACM_Iface::ipacmcfg->vlan_bridges[i].bridge_mac[0],
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
			bool default_bridge = false;

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
			IPACMDBG("bridge (%s) mask 0x%X, address 0x%X, VID %d, lan2lan_sw %d\n", data_all->iface_name,
				mapping_info.subnet_mask,
				mapping_info.bridge_ipv4,
				mapping_info.vlan_id,
				mapping_info.lan2lan_sw);

			struct ifreq ifr;
			int fd;

			fd = socket(AF_INET, SOCK_DGRAM, 0);
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

bool IPACM_Config::is_added_vlan_iface(char *iface_name)
{
	list<vlan_iface_info>::iterator it_vlan;
	bool ret = false;

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

bool IPACM_Config::iface_in_vlan_mode(const char *phys_iface_name)
{
	if(strstr(phys_iface_name, "eth"))
	{
		IPACMDBG("eth vlan mode %d\n", vlan_devices[IPA_VLAN_IF_EMAC]);
		return vlan_devices[IPA_VLAN_IF_EMAC];
	}

	if(strstr(phys_iface_name, "rndis"))
	{
		IPACMDBG("rndis vlan mode %d\n", vlan_devices[IPA_VLAN_IF_RNDIS]);
		return vlan_devices[IPA_VLAN_IF_RNDIS];
	}

	if(strstr(phys_iface_name, "ecm"))
	{
		IPACMDBG("ecm vlan mode %d\n", vlan_devices[IPA_VLAN_IF_ECM]);
		return vlan_devices[IPA_VLAN_IF_ECM];
	}

	IPACMDBG("iface %s did not match any known ifaces\n", phys_iface_name);
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
#ifdef IPA_L2TP_TUNNEL_UDP
	list<l2tp_vlan_mapping_info>::iterator it_mapping;
#endif
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

#ifdef IPA_L2TP_TUNNEL_UDP
	for(it_mapping = m_l2tp_vlan_mapping.begin(); it_mapping != m_l2tp_vlan_mapping.end(); it_mapping++)
	{
		if(strncmp(it_mapping->l2tp_iface_name, iface_name, sizeof(it_mapping->l2tp_iface_name)) == 0)
		{
			IPACMDBG_H("Found l2tp iface in l2tp vlan list: %s, l2tp vlan id: %d\n",
				it_mapping->l2tp_iface_name, it_mapping->l2tp_bridge_vlan_id);
			/* setting l2tp bridge vlan id */
			*vlan_id = it_mapping->l2tp_bridge_vlan_id;
			ret = IPACM_SUCCESS;
			break;
		}
	}
#endif

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
	list<l2tp_client_gw_info>::iterator it_l2tp_gw;
	uint8_t mac_addr[6];
	uint32_t l2tp_ipv6_addr[4];
	memset(mac_addr,0,sizeof(mac_addr));
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
	IPACMDBG_H("Add l2tp iface %s to nat ifaces, iptype: %d \n", data->l2tp_iface_name, data->iptype);
	IPACMDBG_H("is_peer_addr_updated : %d\n", data->is_peer_addr_updated);
	peer_addr_updated = data->is_peer_addr_updated;

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
			l2tp_ipv6_addr[0] = ntohl(data->addr.peer_ipv6_addr[0]);
			l2tp_ipv6_addr[1] = ntohl(data->addr.peer_ipv6_addr[1]);
			l2tp_ipv6_addr[2] = ntohl(data->addr.peer_ipv6_addr[2]);
			l2tp_ipv6_addr[3] = ntohl(data->addr.peer_ipv6_addr[3]);

			new_mapping.vlan_id = it_vlan->vlan_id;
			memcpy(new_mapping.vlan_iface_ipv6_addr, it_vlan->vlan_iface_ipv6_addr,
				sizeof(new_mapping.vlan_iface_ipv6_addr));
#ifdef IPA_PEER_ADDR_ENABLED
			if(data->is_peer_addr_updated == IPA_PEER_ADDR_ENABLED)
			{
			for(int i = 0; i < IPA_MAX_NUM_PEER_ULA; i++)
			{
				/*comparing if vlan populated before, if updated then updating the mac to the l2tp info*/
				if(memcmp(l2tp_ipv6_addr, it_vlan->vlan_client_ipv6_addr[i], sizeof(l2tp_ipv6_addr)) == 0)
				{
					IPACMDBG_H("Found vlan iface with id %d\n", it_vlan->vlan_id);
					memcpy(new_mapping.vlan_client_mac, it_vlan->vlan_client_mac[i],
						sizeof(new_mapping.vlan_client_mac));
					break;
				}
			}
			}
			else
#endif
			{
				IPACMDBG_H("Peer Addr not updated by QCmap\n");
				memcpy(new_mapping.vlan_client_ipv6_addr, it_vlan->vlan_client_ipv6_addr[0],
					sizeof(new_mapping.vlan_client_ipv6_addr));
			}
			break;
		}
	}
#ifdef IPA_PEER_ADDR_ENABLED
	if(data->is_peer_addr_updated == IPA_PEER_ADDR_ENABLED)
	{
		if(data->iptype == IPA_IP_v4)
		{
			memcpy(&new_mapping.vlan_client_ipv4_addr, &data->addr.peer_ipv4_addr,
				sizeof(new_mapping.vlan_client_ipv4_addr));
		}
		if(data->iptype == IPA_IP_v6)
		{
			new_mapping.vlan_client_ipv6_addr[0] = ntohl(data->addr.peer_ipv6_addr[0]);
			new_mapping.vlan_client_ipv6_addr[1] = ntohl(data->addr.peer_ipv6_addr[1]);
			new_mapping.vlan_client_ipv6_addr[2] = ntohl(data->addr.peer_ipv6_addr[2]);
			new_mapping.vlan_client_ipv6_addr[3] = ntohl(data->addr.peer_ipv6_addr[3]);
			IPACMDBG_H("Incoming IPv6 address:0x%08x%08x%08x%08x\n",
				new_mapping.vlan_client_ipv6_addr[0],new_mapping.vlan_client_ipv6_addr[1],
				new_mapping.vlan_client_ipv6_addr[2],new_mapping.vlan_client_ipv6_addr[3]);
			new_mapping.vlan_client_ipv6_gw_addr[0] = ntohl(data->addr.peer_ipv6_addr[0]);
			new_mapping.vlan_client_ipv6_gw_addr[1] = ntohl(data->addr.peer_ipv6_addr[1]);
			new_mapping.vlan_client_ipv6_gw_addr[2] = ntohl(data->addr.peer_ipv6_addr[2]);
			new_mapping.vlan_client_ipv6_gw_addr[3] = ntohl(data->addr.peer_ipv6_addr[3]);
		}
	}
#endif

	for(it_l2tp_gw = l2tp_session_gw_info.begin(); it_l2tp_gw != l2tp_session_gw_info.end(); it_l2tp_gw++)
	{
		IPACMDBG_H("Route IPv6 address:0x%08x%08x%08x%08x\n", it_l2tp_gw->client_ipv6_gw_addr[0],it_l2tp_gw->client_ipv6_gw_addr[1], it_l2tp_gw->client_ipv6_gw_addr[2],it_l2tp_gw->client_ipv6_gw_addr[3]);
		IPACMDBG_H("client IPv6 address:0x%08x%08x%08x%08x\n", it_l2tp_gw->client_ipv6_addr[0],it_l2tp_gw->client_ipv6_addr[1], it_l2tp_gw->client_ipv6_addr[2],it_l2tp_gw->client_ipv6_addr[3]);
		/* comparing l2tp session peer address is matching with route peer address */
		if(!(memcmp(it_l2tp_gw->client_iface_name, data->vlan_iface_name, sizeof(IPA_IFACE_NAME_LEN))) &&
		(!(memcmp(it_l2tp_gw->client_ipv6_addr, new_mapping.vlan_client_ipv6_addr, sizeof(it_l2tp_gw->client_ipv6_addr)))))
		{
			IPACMDBG_H("comparing GW and mac info is updating or not\n");

			if(memcmp(it_l2tp_gw->client_mac, &mac_addr, sizeof(mac_addr)) != 0)
			{

				IPACMDBG_H("updating GW and mac info is updating\n");
				memcpy(new_mapping.vlan_client_mac, it_l2tp_gw->client_mac, sizeof(it_l2tp_gw->client_mac));
				memcpy(new_mapping.vlan_client_ipv6_gw_addr, it_l2tp_gw->client_ipv6_gw_addr, sizeof(new_mapping.vlan_client_ipv6_gw_addr));
				break;
			}
		}
	}
	if(it_l2tp_gw == l2tp_session_gw_info.end())
	{
		IPACMERR("GW info is not populated\n");
	}

	m_l2tp_vlan_mapping.push_front(new_mapping);
	pthread_mutex_unlock(&vlan_l2tp_lock);

	return;
}
void IPACM_Config::remove_l2tp_vlan_pdn_mapping()
{
	list<l2tp_vlan_mapping_info>::iterator it;
	ipacm_event_route_vlan *vlan_data;
	ipacm_cmd_q_data vlan_down_evt;
	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}
	for(it = m_l2tp_vlan_mapping.begin(); it != m_l2tp_vlan_mapping.end(); it++)
	{
		if (it->l2tp_bridge_vlan_id != 0)
		{
			vlan_data = (ipacm_event_route_vlan *)malloc(sizeof(ipacm_event_route_vlan));
			if(vlan_data == NULL)
			{
				IPACMERR("Failed to allocate memory.\n");
				pthread_mutex_unlock(&vlan_l2tp_lock);
				return;
			}
			memset(vlan_data, 0, sizeof(ipacm_event_route_vlan));
			memset(&vlan_down_evt, 0, sizeof(ipacm_cmd_q_data));
			vlan_data->VlanID = it->l2tp_bridge_vlan_id;
			vlan_down_evt.evt_data = vlan_data;
			vlan_down_evt.event = IPA_ROUTE_DEL_L2TP_VLAN_EVENT;
			IPACMDBG_H("Posting event %s with vlan_id: %d\n",
			IPACM_Iface::ipacmcfg->getEventName(vlan_down_evt.event), vlan_data->VlanID);
			IPACM_EvtDispatcher::PostEvt(&vlan_down_evt);
		}
	}
	pthread_mutex_unlock(&vlan_l2tp_lock);
}
void IPACM_Config::del_l2tp_vlan_mapping(ipa_ioc_l2tp_vlan_mapping_info *data)
{
	list<l2tp_vlan_mapping_info>::iterator it;
	uint16_t l2tp_bridge_vlan = 0;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	IPACMDBG_H("L2tp iface: %s session id: %d vlan iface: %s peer_addr_updated: %d \n",
		data->l2tp_iface_name, data->l2tp_session_id, data->vlan_iface_name, peer_addr_updated);
	peer_addr_updated = 0;
	for(it = m_l2tp_vlan_mapping.begin(); it != m_l2tp_vlan_mapping.end(); it++)
	{
		if(strncmp(data->l2tp_iface_name, it->l2tp_iface_name,
			sizeof(data->l2tp_iface_name)) == 0)
		{
			IPACMDBG_H("Found l2tp iface mapped to vlan %s.\n", it->vlan_iface_name);
			if(strncmp(data->vlan_iface_name, it->vlan_iface_name,
				sizeof(data->vlan_iface_name)) == 0)
			{
				l2tp_bridge_vlan = it->l2tp_bridge_vlan_id;
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
	if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE && l2tp_bridge_vlan != 0)
	{
		ipacm_event_route_vlan *vlan_data;
		ipacm_cmd_q_data vlan_down_evt;

		vlan_data = (ipacm_event_route_vlan *)malloc(sizeof(ipacm_event_route_vlan));
		if(vlan_data == NULL)
		{
			IPACMERR("Failed to allocate memory.\n");
			return;
		}
		memset(vlan_data, 0, sizeof(ipacm_event_route_vlan));

		vlan_data->VlanID = l2tp_bridge_vlan;

		vlan_down_evt.evt_data = vlan_data;
		vlan_down_evt.event = IPA_ROUTE_DEL_L2TP_VLAN_EVENT;

		IPACMDBG_H("Posting event %s with vlan_id: %d\n",
			IPACM_Iface::ipacmcfg->getEventName(vlan_down_evt.event), vlan_data->VlanID);
		IPACM_EvtDispatcher::PostEvt(&vlan_down_evt);
	}
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

/* check if client iface is l2tp iface */
bool IPACM_Config::check_l2tp_iface(const char *client_iface)
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
			IPACMDBG_H("Matched l2tp iface.\n");
			pthread_mutex_unlock(&vlan_l2tp_lock);
			return true;
		}
	}

	/* To handle the case if del vlan l2tp IOCTL from QCMAP received before DELNEIGH on phy or Bridge iface */
	if(strncmp(client_iface, "l2tp", 4) == 0)
	{
		IPACMDBG_H("This is l2tp iface.\n");
		pthread_mutex_unlock(&vlan_l2tp_lock);
		return true;
	}

	pthread_mutex_unlock(&vlan_l2tp_lock);
	return false;
}

#ifdef IPA_L2TP_TUNNEL_UDP
/* add l2tp bridge dummy vlan mapping*/
void IPACM_Config::add_l2tp_dummy_bridge_vlan_mapping(const char *bridge_iface, const char* l2tp_client_iface, int if_index)
{
	list<l2tp_vlan_mapping_info>::iterator it_mapping;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return;
	}

	for(it_mapping = m_l2tp_vlan_mapping.begin(); it_mapping != m_l2tp_vlan_mapping.end(); it_mapping++)
	{
		if(strncmp(l2tp_client_iface, it_mapping->l2tp_iface_name,
			strlen(l2tp_client_iface)) == 0)
		{
			IPACMDBG_H("Found vlan-l2tp mapping for iface %s, checking bridge vlan info\n",
				l2tp_client_iface);
			strlcpy(it_mapping->l2tp_bridge_iface_name, bridge_iface, IF_NAME_LEN);
			/* We are getting vlan info also from QCMAP but recalculating dummy vlan again to not depend on QCMAP for future */
			/* Each l2tp session have seperate bridge */
			it_mapping->l2tp_bridge_vlan_id = L2TP_BRIDGE_VLAN_ID_START + if_index;
			IPACMDBG_H("Assigned l2tp iface %s, vlan id %d\n", it_mapping->l2tp_iface_name,
				it_mapping->l2tp_bridge_vlan_id);
			break;
		}
	}

	pthread_mutex_unlock(&vlan_l2tp_lock);
	return;

}

/* check if vlan id is l2tp bridge dummy vlan id */
bool IPACM_Config::check_l2tp_bridge_vlan_id(uint32_t vlan_id)
{
	list<l2tp_vlan_mapping_info>::iterator it_mapping;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return IPACM_FAILURE;
	}

	for(it_mapping = m_l2tp_vlan_mapping.begin(); it_mapping != m_l2tp_vlan_mapping.end(); it_mapping++)
	{
		if(it_mapping->l2tp_bridge_vlan_id == vlan_id)
		{
			IPACMDBG_H("Matched l2tp bridge vlan id %d with l2tp iface %s.\n",it_mapping->l2tp_bridge_vlan_id,
				it_mapping->l2tp_iface_name);
			pthread_mutex_unlock(&vlan_l2tp_lock);
			return true;
		}
	}

	pthread_mutex_unlock(&vlan_l2tp_lock);
	return false;
}

/* get l2tp vlan mapping info using dummy vlan id */
int IPACM_Config::get_l2tp_mapping_by_bridge_vlan_id(uint32_t vlan_id, l2tp_vlan_mapping_info& info)
{
	list<l2tp_vlan_mapping_info>::iterator it_mapping;

	if(pthread_mutex_lock(&vlan_l2tp_lock) != 0)
	{
		IPACMERR("Unable to lock the mutex\n");
		return IPACM_FAILURE;
	}

	IPACMDBG_H("Incoming client vlan id: %d\n", vlan_id);

	for(it_mapping = m_l2tp_vlan_mapping.begin(); it_mapping != m_l2tp_vlan_mapping.end(); it_mapping++)
	{
		if(vlan_id == it_mapping->l2tp_bridge_vlan_id)
		{
			IPACMDBG_H("Found vlan-l2tp mapping for l2tp bridge vlan id %d with l2tp iface %s.\n",
				vlan_id, it_mapping->l2tp_iface_name);
			info = *it_mapping;
			pthread_mutex_unlock(&vlan_l2tp_lock);
			return IPACM_SUCCESS;
		}
	}

	pthread_mutex_unlock(&vlan_l2tp_lock);
	return IPACM_FAILURE;
}

#endif
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

