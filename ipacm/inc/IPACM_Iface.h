/*
 * Copyright (c) 2013-2016, 2018, 2020-2021 The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *  * Neither the name of The Linux Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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
		IPACM_iface.h

		@brief
		This file implements the basis Iface definitions.

		@Author
		Skylar Chang

*/
#ifndef IPACM_IFACE_H
#define IPACM_IFACE_H

#include <stdio.h>
#include <IPACM_CmdQueue.h>
#include <linux/msm_ipa.h>
#include <vector>
#include "IPACM_Routing.h"
#include "IPACM_Filtering.h"
#include "IPACM_Header.h"
#include "IPACM_EvtDispatcher.h"
#include "IPACM_Xml.h"
#include "IPACM_Log.h"
#include "IPACM_Config.h"
#include "IPACM_Defs.h"
#include <string.h>
#include <array>

using std::vector;

/* current support 2 ipv6-address*/
#define MAX_DEFAULT_v4_ROUTE_RULES  1
#define MAX_DEFAULT_v6_ROUTE_RULES  2
#define IPV4_DEFAULT_FILTERTING_RULES 3

#ifdef FEATURE_IPA_IPSEC
#define MAX_DEFAULT_IPSEC_v4_ROUTE_RULES 1
#define MAX_DEFAULT_IPSEC_v6_ROUTE_RULES 1
#endif

#if defined(FEATURE_IPA_ANDROID) || defined(FEATURE_SOCKSv5)
#define IPV6_DEFAULT_FILTERTING_RULES 8
#else
#define IPV6_DEFAULT_FILTERTING_RULES 5
#endif

#define IPV6_DEFAULT_LAN_FILTERTING_RULES 1
#define MAX_SOFTWAREROUTING_FILTERTING_RULES 2
#define INVALID_IFACE -1


/* Support client v6 handles */
struct client_rt_hdl_v6 {
	uint32_t rt_rule_hdl_v6;
	uint32_t rt_rule_hdl_v6_wan;
};

#ifdef FEATURE_STATIC_POLICY
struct dscp_pdn_client_rt_hdl_v6 {
	uint32_t rt_rule_hdl_v6_wan[IPA_UC_MAX_PDN_DSCP_VAL];
	bool dscp_route_rule_set_v6[IPA_UC_MAX_PDN_DSCP_VAL];
	uint32_t dscp_hpc_hdr_hdl_v6[IPA_UC_MAX_PDN_DSCP_VAL];
	bool dscp_ipv6_hpc_set[IPA_UC_MAX_PDN_DSCP_VAL];
};
#endif

struct handleTypeV6 {
	bool route_rule_set_v6{false};
	vector<client_rt_hdl_v6> hdl_v6{};
	uint32_t dft_qos_ack_v6 = 0;
#ifdef FEATURE_STATIC_POLICY
	vector<dscp_pdn_client_rt_hdl_v6> dscp_pdn_hdl_v6{};
#endif
	handleTypeV6(size_t n) {
		hdl_v6.resize(n);
#ifdef FEATURE_STATIC_POLICY
		dscp_pdn_hdl_v6.resize(n);
#endif
	}
};

/* iface */
class IPACM_Iface :public IPACM_Listener
{
public:

	/* Static class for reading IPACM configuration from XML file*/
	static IPACM_Config *ipacmcfg;
	uint8_t prio[IPA_MAX_NUM_PROPS][IPA_IP_MAX];
	uint8_t fixed_mac_prio_val[IPA_MAX_NUM_PROPS][IPA_IP_MAX] = {0};
	/* IPACM interface id */
	int ipa_if_num;

	/* IPACM interface category */
	ipacm_iface_type ipa_if_cate;
	bool is_if_svap;

	/* is wlan iface is vlan or non-vlan */
	bool is_wlan_if_vlan;

	/* IPACM interface name */
	char dev_name[IF_NAME_LEN];

	bool virtual_iface = false;

	/* IPACM interface physical name (if applicable) */
	char phy_dev_name[IF_NAME_LEN] = "";

	/* IPACM Device type. */
	ipacm_per_client_device_type device_type;

	/* IPACM interface iptype v4, v6 or both */
	ipa_ip_type ip_type;

	/* IPACM interface v6 ip-address*/
	uint32_t ipv6_addr[MAX_DEFAULT_v6_ROUTE_RULES][4];

	uint32_t software_routing_fl_rule_hdl[MAX_SOFTWAREROUTING_FILTERTING_RULES];

	bool softwarerouting_act;

	/* IPACM number of default route rules for ipv6*/
	int num_dft_rt_v6;

	uint32_t dft_v4fl_rule_hdl[IPA_MAX_NUM_PROPS][IPV4_DEFAULT_FILTERTING_RULES];
	uint32_t dft_v6fl_rule_hdl[IPA_MAX_NUM_PROPS][IPV6_DEFAULT_FILTERTING_RULES + IPV6_DEFAULT_LAN_FILTERTING_RULES];
	/* create additional set of v6 RT-rules in Wanv6RT table*/

	uint32_t dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES + (2 * MAX_DEFAULT_v6_ROUTE_RULES)];
#ifdef FEATURE_IPA_IPSEC
	uint32_t dft_ipsec_rt_rule_hdl[MAX_DEFAULT_IPSEC_v4_ROUTE_RULES + MAX_DEFAULT_IPSEC_v6_ROUTE_RULES];
#endif

	/* save client ipv6 address info and rt handles */
	std::map<std::array<uint32_t, 4>, handleTypeV6> rt_hdl_v6_list[IPA_MAX_NUM_CLIENTS_IPV6];

	ipa_ioc_query_intf *iface_query;
	ipa_ioc_query_intf_tx_props *tx_prop;
	ipa_ioc_query_intf_rx_props *rx_prop;

	virtual int handle_down_evt() = 0;

	virtual int handle_addr_evt(ipacm_event_data_addr *data) = 0;

	IPACM_Iface(char *iface_name, int iface_index);

	virtual void event_callback(ipa_cm_event_id event, void *data) = 0;

	/* Query ipa_interface_index by given linux interface_index */
	static int iface_ipa_index_query(int interface_index);

	/* Query ipa_interface ipv4_addr by given linux interface_index */
	static void iface_addr_query(int interface_index, bool post_new_addr_event = true,
		uint32_t *curr_ip4_addr = 0);

	/*Query the IPA endpoint property */
	int query_iface_property(void);

	/*Configure the initial filter rules */
	virtual int init_fl_rule(
		ipa_ip_type iptype,
		bool        eogre_enabled = false);

	/* Change IP Type.*/
	void config_ip_type(ipa_ip_type iptype);

	/* Get interface index */
	static int ipa_get_if_index(char * if_name, int * if_index);

	static IPACM_Routing m_routing;
	static IPACM_Filtering m_filtering;
	static IPACM_Header m_header;

	/* software routing enable */
	virtual int handle_software_routing_enable(void);

	/* software routing disable */
	virtual int handle_software_routing_disable(void);
	void delete_iface(void);

	static inline void addr2host(
		enum ipa_ip_type addr_type,
		void*            addr ) {
		if ( VALID_IPA_IP_TYPE(addr_type) && addr ) {
			uint32_t* ptr = (uint32_t*) addr;

			if ( addr_type == IPA_IP_v4 ) {
				ptr[0] = ntohl(ptr[0]);
			} else {
				ptr[0] = ntohl(ptr[0]);
				ptr[1] = ntohl(ptr[1]);
				ptr[2] = ntohl(ptr[2]);
				ptr[3] = ntohl(ptr[3]);
			}
		}
	}

	static inline void addr2network(
		enum ipa_ip_type addr_type,
		void*            addr ) {
		if ( VALID_IPA_IP_TYPE(addr_type) && addr ) {
			uint32_t* ptr = (uint32_t*) addr;

			if ( addr_type == IPA_IP_v4 ) {
				ptr[0] = htonl(ptr[0]);
			} else {
				ptr[0] = htonl(ptr[0]);
				ptr[1] = htonl(ptr[1]);
				ptr[2] = htonl(ptr[2]);
				ptr[3] = htonl(ptr[3]);
			}
		}
	}

	void change_to_network_order(
		ipa_ip_type      iptype,
		ipa_rule_attrib* attrib ) {
		if ( ! VALID_IPA_IP_TYPE(iptype) || ! attrib ) {
			IPACMERR(
				"Bad iptype(%u) and/or attribute pointer(%p) is NULL.\n",
				iptype, attrib);
		}
		if ( iptype == IPA_IP_v6 ) {
			addr2network(iptype, attrib->u.v6.src_addr);
			addr2network(iptype, attrib->u.v6.src_addr_mask);
			addr2network(iptype, attrib->u.v6.dst_addr);
			addr2network(iptype, attrib->u.v6.dst_addr_mask);
		} else {
			IPACMDBG_H("IP type is not IPv6, do nothing: %d\n", iptype);
		}
	}

	int delete_dflt_filter_rules(
		ipa_ip_type iptype );

protected:

	uint8_t m_ipv4_default_filterting_rules_count[IPA_MAX_NUM_PROPS];
	uint8_t m_ipv6_default_filterting_rules_count[IPA_MAX_NUM_PROPS];

private:

	static const char *DEVICE_NAME;
};

#endif /* IPACM_IFACE_H */
