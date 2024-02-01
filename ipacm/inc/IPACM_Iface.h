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
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
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

using std::vector;

/* current support 2 ipv6-address*/
#define MAX_DEFAULT_v4_ROUTE_RULES  1
#define MAX_DEFAULT_v6_ROUTE_RULES  2
#define IPV4_DEFAULT_FILTERTING_RULES 3

#if defined(FEATURE_IPA_ANDROID) || defined(FEATURE_SOCKSv5)
#define IPV6_DEFAULT_FILTERTING_RULES 8
#else
#define IPV6_DEFAULT_FILTERTING_RULES 5
#endif

#define IPV6_DEFAULT_LAN_FILTERTING_RULES 1
#define IPV6_NUM_ADDR 3
#define MAX_SOFTWAREROUTING_FILTERTING_RULES 2
#define INVALID_IFACE -1


/* Support client v6 handles */
struct client_rt_hdl_v6 {
	uint32_t rt_rule_hdl_v6;
	uint32_t rt_rule_hdl_v6_wan;
};

struct handleTypeV6 {
	bool route_rule_set_v6{false};
	vector<client_rt_hdl_v6> hdl_v6{};

	handleTypeV6(size_t n) {
		hdl_v6.resize(n);
	}
};

/* iface */
class IPACM_Iface :public IPACM_Listener
{
public:

	/* Static class for reading IPACM configuration from XML file*/
	static IPACM_Config *ipacmcfg;

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

	uint32_t dft_v4fl_rule_hdl[IPV4_DEFAULT_FILTERTING_RULES];
	uint32_t dft_v6fl_rule_hdl[IPV6_DEFAULT_FILTERTING_RULES + IPV6_DEFAULT_LAN_FILTERTING_RULES];
	/* create additional set of v6 RT-rules in Wanv6RT table*/
	uint32_t dft_rt_rule_hdl[MAX_DEFAULT_v4_ROUTE_RULES+2*MAX_DEFAULT_v6_ROUTE_RULES];

	/* save client ipv6 address info and rt handles */
	std::map<std::array<uint32_t, 4>, handleTypeV6> rt_hdl_v6_list[IPA_MAX_NUM_CLIENTS_IPV6];

	ipa_ioc_query_intf *iface_query;
	ipa_ioc_query_intf_tx_props *tx_prop;
	ipa_ioc_query_intf_rx_props *rx_prop;

	virtual int handle_down_evt() = 0;

	virtual int handle_addr_evt(ipacm_event_data_addr *data) = 0;

	IPACM_Iface(int iface_index);

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

#ifdef IPA_FLT_EXT_MPLS_GRE_GENERAL
	static inline void addr2host(
		enum ipa_ip_type addr_type,
		void*            addr,
		ipa_data_flow_type flow = FLOW_DOWNLINK ) {
		if ( VALID_IPA_IP_TYPE(addr_type) && addr ) {
			uint32_t* ptr = (uint32_t*) addr;

			if ( addr_type == IPA_IP_v4 ) {
				ptr[0] = ntohl(ptr[0]);
			} else {
				if ( flow == FLOW_UPLINK ) {
					uint32_t tmp[4];
					memcpy(tmp, ptr, sizeof(tmp));
					ptr[0] = tmp[3];
					ptr[1] = tmp[2];
					ptr[2] = tmp[1];
					ptr[3] = tmp[0];
				} else { /* flow == FLOW_DOWNLINK */
					ptr[0] = ntohl(ptr[0]);
					ptr[1] = ntohl(ptr[1]);
					ptr[2] = ntohl(ptr[2]);
					ptr[3] = ntohl(ptr[3]);
				}
			}
		}
	}

	static inline void addr2network(
		enum ipa_ip_type   addr_type,
		void*              addr,
		ipa_data_flow_type flow = FLOW_DOWNLINK ) {
		if ( VALID_IPA_IP_TYPE(addr_type) && addr ) {
			uint32_t* ptr = (uint32_t*) addr;

			if ( addr_type == IPA_IP_v4 ) {
				ptr[0] = htonl(ptr[0]);
			} else {
				if ( flow == FLOW_UPLINK ) {
					/*
					 * For historical reasons, when v6 addresses are
					 * used in UL equations, the following is the form
					 * they need to take.  DL form is after the else.
					 */
					uint32_t tmp[4];
					memcpy(tmp, ptr, sizeof(tmp));
					ptr[0] = tmp[3];
					ptr[1] = tmp[2];
					ptr[2] = tmp[1];
					ptr[3] = tmp[0];
				} else { /* flow == FLOW_DOWNLINK */
					ptr[0] = htonl(ptr[0]);
					ptr[1] = htonl(ptr[1]);
					ptr[2] = htonl(ptr[2]);
					ptr[3] = htonl(ptr[3]);
				}
			}
		}
	}

	void change_to_network_order(
		ipa_ip_type      iptype,
		ipa_rule_attrib* attrib,
		ipa_data_flow_type flow = FLOW_DOWNLINK ) {
		if ( ! VALID_IPA_IP_TYPE(iptype) || ! attrib ) {
			IPACMERR(
				"Bad iptype(%u) and/or attribute pointer(%p) is NULL.\n",
				iptype, attrib);
		}
		if ( iptype == IPA_IP_v6 ) {
			addr2network(iptype, attrib->u.v6.src_addr, flow);
			addr2network(iptype, attrib->u.v6.src_addr_mask, flow);
			addr2network(iptype, attrib->u.v6.dst_addr, flow);
			addr2network(iptype, attrib->u.v6.dst_addr_mask, flow);
		} else {
			IPACMDBG_H("IP type is not IPv6, do nothing: %d\n", iptype);
		}
	}

#else

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

#endif /* IPA_FLT_EXT_MPLS_GRE_GENERAL */

	int delete_dflt_filter_rules(
		ipa_ip_type iptype );


protected:

	uint8_t m_ipv4_default_filterting_rules_count;
	uint8_t m_ipv6_default_filterting_rules_count;

private:

	static const char *DEVICE_NAME;
};

#ifdef IPA_FLT_EXT_MPLS_GRE_GENERAL
/*
 * A set of definitions for easily managing filter and route handles.
 */
typedef enum
{
	RULE_TYPE_FILTER = 1,
	RULE_TYPE_ROUTE  = 2,
	RULE_TYPE_MAX
} RuleType_t;

#define VALID_RULE_TYPE(t) \
	((t) >= RULE_TYPE_FILTER && (t) < RULE_TYPE_MAX)

typedef struct
{
	RuleType_t  type;
	ipa_ip_type iptype;
	uint32_t    handle;
	int			pipe_idx;
} RuleData_t;

class RuleHdlContainer
{
private:

	RuleData_t* rule_data;

public:

	RuleHdlContainer() :
		rule_data{nullptr} {
	};

	RuleHdlContainer(
		RuleType_t  t,
		ipa_ip_type ipt,
		uint32_t    hdl,
		int 		pipe ) :
		rule_data{nullptr} {
		if ( VALID_RULE_TYPE(t) && VALID_IPA_IP_TYPE(ipt) && hdl >= 0 ) {
			rule_data = new RuleData_t;
			if ( rule_data ) {
				IPACMDBG(
					"Taking control of \"%s\" hdl=(%u) with iptype=(%u)\n",
					(t == RULE_TYPE_FILTER) ? "filter" : "route",
					hdl,
					ipt);
				rule_data->type   = t;
				rule_data->iptype = ipt;
				rule_data->handle = hdl;
				rule_data->pipe_idx = pipe;
			} else {
				IPACMERR("Alloc of RuleData_t failed\n");
			}
		} else {
			IPACMERR(
				"Bad arg passed: RuleType_t(%u) and/or ipa_ip_type(%u) and/or rule hdl(%u)\n",
				t, ipt, hdl);
		}
	};

	// Copy Constructor
	RuleHdlContainer(
		const RuleHdlContainer& t) :
		rule_data(t.rule_data) {
			RuleHdlContainer& nct = const_cast<RuleHdlContainer&>(t);
			nct.rule_data = nullptr;
	};

	// Move Constructor
	RuleHdlContainer(
		RuleHdlContainer&& t) :
		rule_data(t.rule_data) {
			t.rule_data = nullptr;
	};

	~RuleHdlContainer() {
		if ( rule_data && VALID_RULE_TYPE(rule_data->type) ) {
			if ( rule_data->type == RULE_TYPE_FILTER ) {
				IPACMDBG(
					"Cleaning up \"filter\" hdl=(%u) with iptype=(%u)\n",
					rule_data->handle,
					rule_data->iptype);
				IPACM_Iface::m_filtering.DeleteFilteringHdls(&(rule_data->handle), rule_data->iptype, 1);
				IPACM_Iface::ipacmcfg->decreaseFltRuleCount(rule_data->pipe_idx, rule_data->iptype, 1);
			} else {
				IPACMDBG(
					"Cleaning up \"route\" hdl=(%u) with iptype=(%u)\n",
					rule_data->handle,
					rule_data->iptype);
				IPACM_Iface::m_routing.DeleteRoutingHdl(rule_data->handle, rule_data->iptype);
			}
			delete rule_data;
		}
	};

	uint32_t RuleHandle(void) {
		if ( rule_data ) {
			return rule_data->handle;
		}
		return 0;
	}
};

#endif /* IPA_FLT_EXT_MPLS_GRE_GENERAL */
#endif /* IPACM_IFACE_H */
