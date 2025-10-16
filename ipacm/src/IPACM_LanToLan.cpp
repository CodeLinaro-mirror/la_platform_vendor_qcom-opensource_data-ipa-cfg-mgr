/*
Copyright (c) 2014-2020, The Linux Foundation. All rights reserved.

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

 * Changes from Qualcomm Technologies, Inc. are provided under the following license:
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

/*!
	@file
	IPACM_LanToLan.cpp

	@brief
	This file implements the functionality of offloading LAN to LAN traffic.

	@Author
	Shihuan Liu

*/

#include <stdlib.h>
#include "IPACM_LanToLan.h"
#include "IPACM_Wlan.h"
#include "IPACM_ConntrackClient.h"
#include "IPACM_Wan.h"



const char *ipa_l2_hdr_type[] = {
	__stringify(NONE),
	__stringify(ETH_II),
	__stringify(802_3),
	__stringify(802_1Q),
	__stringify(ETH_II_AST),
	__stringify(802_1Q_AST),
	__stringify(L2_MAX)
};

IPACM_LanToLan* IPACM_LanToLan::p_instance;

IPACM_LanToLan_Iface::IPACM_LanToLan_Iface(IPACM_Lan *p_iface)
{
	int i;

	m_p_iface = p_iface;
	memset(m_is_ip_addr_assigned, 0, sizeof(m_is_ip_addr_assigned));
	m_support_inter_iface_offload = true;
	m_support_intra_iface_offload = false;
	m_intra_interface_info.peer = NULL;
	IPACMDBG_H("This is %s :inter_bridge_lantolan_config_enable %d \n", p_iface->dev_name, IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable);
	IPACMDBG_H("This is %s : multi_vlan_bridge_config_enable %d, ipacm_lan2lan_stats_enable %d \n",
		p_iface->dev_name, IPACM_Iface::ipacmcfg->multi_vlan_bridge_config_enable, IPACM_Iface::ipacmcfg->ipacm_lan2lan_stats_enable);

	if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
		m_intra_interface_info.is_vlan_peer = false;

	if(IPACM_Iface::ipacmcfg->multi_vlan_bridge_config_enable == 1 &&
			IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
	{
		m_support_intra_iface_offload = true;
	}
	m_is_l2tp_iface = false;
	m_is_svap_iface = false;
#ifdef FEATURE_VLAN_MPDN
	m_is_vlan = false;
#endif
	m_ast_update = false;
	m_is_sIface = false;
	pipe_idx = 0;
	for(i = 0; i < IPA_HDR_L2_MAX; i++)
	{
		ref_cnt_peer_l2_hdr_type[i] = 0;
		hdr_proc_ctx_for_inter_interface[i] = 0;
	}
	hdr_proc_ctx_for_intra_interface = 0;
	hdr_proc_ctx_for_l2tp = 0;
	num_of_wlan_svap_hpc_hdls = 0;
	memset(wlan_svap_hpc_hdls, 0, MAX_SVAP_VLAN * sizeof(svap_vlan_hpc_hdl));

	m_is_vlan_ap = false;

	if(p_iface->ipa_if_cate == WLAN_IF)
	{
		IPACMDBG_H("Interface %s is WLAN interface.\n", p_iface->dev_name);
		if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
			m_support_intra_iface_offload = true;
		if( ((IPACM_Wlan*)p_iface)->is_guest_ap() )
		{
			IPACMDBG_H("Interface %s is guest AP.\n", p_iface->dev_name);
			m_support_inter_iface_offload = false;
			m_support_intra_iface_offload = false;
		}

		max_num_clients = MAX_NUM_WLAN_CLIENT;
		if( ((IPACM_Wlan*)p_iface)->ast_update_needed() )
		{
			IPACMDBG_H("AST update needed for %s.\n", p_iface->dev_name);
			m_ast_update = true;
		}

		set_svap_iface(((IPACM_Wlan*)p_iface)->is_svap_iface());
		if (is_svap_iface()) {
			m_support_intra_iface_offload = false;
		}

		m_is_vlan_ap = ((IPACM_Wlan*)p_iface)->is_vlan_iface();
		if (is_ap_iface_vlan_enabled()) {
			m_support_intra_iface_offload = false;
		}
	}
	else if(p_iface->device_type == IPACM_CLIENT_DEVICE_TYPE_ETH && ((IPACM_Lan *)p_iface)->sIface)
	{
		IPACMDBG_H("Interface %s is sIface ETH interface.\n", p_iface->dev_name);
		if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
			m_support_intra_iface_offload = true;

		max_num_clients = MAX_NUM_CLIENT;
		m_is_sIface = ((IPACM_Lan *)p_iface)->sIface;

		if (is_spcl_iface()) {
			m_support_intra_iface_offload = false;
		}
	}
	else
	{
		max_num_clients = MAX_NUM_CLIENT;
	}
	if (true == m_support_intra_iface_offload && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false) {
		m_intra_interface_info.is_vlan_peer = false;
	}
	IPACMDBG_H("Interface %s, the max number of clients supported %d.\n",p_iface->dev_name, max_num_clients);
	IPACMDBG_H("m_support_inter_iface_offload %d, m_support_intra_iface_offload %d \n", m_support_inter_iface_offload, m_support_intra_iface_offload);
	return;
}

IPACM_LanToLan_Iface::~IPACM_LanToLan_Iface()
{
}

IPACM_LanToLan::IPACM_LanToLan()
{
	IPACM_EvtDispatcher::registr(IPA_ETH_BRIDGE_IFACE_UP, this);
	IPACM_EvtDispatcher::registr(IPA_ETH_BRIDGE_IFACE_DOWN, this);
	IPACM_EvtDispatcher::registr(IPA_ETH_BRIDGE_CLIENT_ADD, this);
	IPACM_EvtDispatcher::registr(IPA_ETH_BRIDGE_CLIENT_DEL, this);
	IPACM_EvtDispatcher::registr(IPA_ETH_BRIDGE_WLAN_SCC_MCC_SWITCH, this);
#ifdef FEATURE_VLAN_MPDN
	IPACM_EvtDispatcher::registr(IPA_ETH_BRIDGE_ADD_VLAN_ID, this);
	IPACM_EvtDispatcher::registr(IPA_ETH_BRIDGE_DEL_VLAN_ID, this);
#endif
	m_has_l2tp_iface = false;
	return;
}

IPACM_LanToLan::~IPACM_LanToLan()
{
	IPACMDBG_DMESG("WARNING: UNEXPECTEDLY KILL LAN2LAN CONTROLLER!\n");
	return;
}

IPACM_LanToLan* IPACM_LanToLan::get_instance()
{
	if(p_instance == NULL)
	{
		p_instance = new IPACM_LanToLan();
		IPACMDBG_H("Created LanToLan instance.\n");
	}
	return p_instance;
}

#ifdef FEATURE_L2TP
bool IPACM_LanToLan::has_l2tp_iface()
{
	list<IPACM_LanToLan_Iface>::iterator it;
	bool has_l2tp_iface = false;

	for(it = m_iface.begin(); it != m_iface.end(); it++)
	{
		if(it->is_l2tp_iface() == true)
		{
			has_l2tp_iface = true;
			break;
		}
	}
	return has_l2tp_iface;
}
#endif

void IPACM_LanToLan::event_callback(ipa_cm_event_id event, void* param)
{
	ipacm_event_eth_bridge *eth_bridge_data;
	const char* eventName;
	ipa_vlan_iface_info *vlan_iface_data;

#ifdef FEATURE_L2TP
	ipa_ioc_l2tp_vlan_mapping_info *l2tp_vlan_mapping_data;
#endif
	ipacm_event_data_all *vlan_data;
	eventName = IPACM_Iface::ipacmcfg->getEventName(event);
	if (eventName != NULL)
		IPACMDBG_H("Get %s event.\n", eventName);

	switch(event)
	{
		case IPA_ETH_BRIDGE_IFACE_UP:
		{
			eth_bridge_data = (ipacm_event_eth_bridge*)param;
			handle_iface_up(eth_bridge_data);
			break;
		}

		case IPA_ETH_BRIDGE_IFACE_DOWN:
		{
			eth_bridge_data = (ipacm_event_eth_bridge*)param;
			handle_iface_down(eth_bridge_data);
			break;
		}

		case IPA_ETH_BRIDGE_CLIENT_ADD:
		{
			eth_bridge_data = (ipacm_event_eth_bridge*)param;
			handle_client_add(eth_bridge_data);
			break;
		}

		case IPA_ETH_BRIDGE_CLIENT_DEL:
		{
			eth_bridge_data = (ipacm_event_eth_bridge*)param;
			handle_client_del(eth_bridge_data);
			break;
		}

		case IPA_ETH_BRIDGE_WLAN_SCC_MCC_SWITCH:
		{
			eth_bridge_data = (ipacm_event_eth_bridge*)param;
			handle_wlan_scc_mcc_switch(eth_bridge_data);
			break;
		}
#ifdef FEATURE_VLAN_MPDN
		case IPA_ETH_BRIDGE_ADD_VLAN_ID:
		{
			eth_bridge_data = (ipacm_event_eth_bridge*)param;
			handle_vlan_id_add(eth_bridge_data);
			break;
		}

		case IPA_ETH_BRIDGE_DEL_VLAN_ID:
		{
			eth_bridge_data = (ipacm_event_eth_bridge*)param;
			handle_vlan_id_del(eth_bridge_data);
			break;
		}
#endif
		default:
			break;
	}

	print_data_structure_info();
	return;
}

void IPACM_LanToLan::handle_iface_up(ipacm_event_eth_bridge *data)
{
	list<IPACM_LanToLan_Iface>::iterator it;
	list<l2tp_vlan_mapping_info>::iterator it_mapping;
	bool has_l2tp_iface = false;
#ifdef FEATURE_VLAN_MPDN
	bool IsVlan = (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable &&
		IPACM_Iface::ipacmcfg->iface_in_vlan_mode(data->p_iface->dev_name));
	uint16_t Ids[IPA_MAX_NUM_OFFLOAD_VLANS];
#endif

	IPACMDBG_H("Interface name: %s IP type: %d\n", data->p_iface->dev_name, data->iptype);
#ifdef FEATURE_VLAN_MPDN
	if(IsVlan)
		IPACMDBG_H("Vlan iface %s\n",data->p_iface->dev_name);
#endif

	for(it = m_iface.begin(); it != m_iface.end(); it++)
	{
		if(it->get_iface_pointer() == data->p_iface)
		{
			IPACMDBG_H("Found the interface.\n");

			if(it->get_m_is_ip_addr_assigned(data->iptype) == false)
			{
				IPACMDBG_H("IP type %d was not active before, activating it now.\n", data->iptype);
				it->set_m_is_ip_addr_assigned(data->iptype, true);
#ifdef FEATURE_VLAN_MPDN
				if(IsVlan)
				{
					if(IPACM_Iface::ipacmcfg->get_iface_vlan_ids(data->p_iface->dev_name, Ids))
					{
						IPACMERR("failed getting vlan ids for iface %s\n", data->p_iface->dev_name);
						return;
					}

					/* install inter-interface rules */
					if(it->get_m_support_inter_iface_offload() && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
						it->add_all_inter_interface_client_flt_rule(data->iptype, Ids);
				}
				else
#endif //FEATURE_VLAN_MPDN
				{
					if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
					{
						/* install inter-interface rules */
						if(it->get_m_support_inter_iface_offload())
							it->add_all_inter_interface_client_flt_rule(data->iptype);

						/* install intra-BSS rules */
						if(it->get_m_support_intra_iface_offload())
							it->add_all_intra_interface_client_flt_rule(data->iptype);
					}
				}
			}
			break;
		}
	}

	if(it == m_iface.end())	//If the interface has not been created before
	{
		if(m_iface.size() == MAX_NUM_IFACE)
		{
			IPACMERR("The number of interfaces has reached maximum %d.\n", MAX_NUM_IFACE);
			return;
		}

		if(!data->p_iface->tx_prop || !data->p_iface->rx_prop)
		{
			IPACMERR("The interface %s does not have tx_prop or rx_prop.\n", data->p_iface->dev_name);
			return;
		}

		if(data->p_iface->tx_prop->tx[0].hdr_l2_type == IPA_HDR_L2_NONE || data->p_iface->tx_prop->tx[0].hdr_l2_type == IPA_HDR_L2_MAX)
		{
			IPACMERR("Invalid l2 header type %s!\n", ipa_l2_hdr_type[data->p_iface->tx_prop->tx[0].hdr_l2_type]);
			return;
		}

		IPACMDBG_H("Does not find the interface, insert a new one.\n");
		IPACM_LanToLan_Iface new_iface(data->p_iface);
		new_iface.set_m_is_ip_addr_assigned(data->iptype, true);

		m_iface.push_front(new_iface);
		IPACMDBG_H("Now the total number of interfaces is %zu.\n", m_iface.size());

		IPACM_LanToLan_Iface &front_iface = m_iface.front();
#ifdef FEATURE_L2TP
		if (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP)
		{
			for(it_mapping = IPACM_Iface::ipacmcfg->m_l2tp_vlan_mapping.begin(); it_mapping != IPACM_Iface::ipacmcfg->m_l2tp_vlan_mapping.end(); it_mapping++)
			{
				if(front_iface.set_l2tp_iface(it_mapping->vlan_iface_name) == true)
				{
					has_l2tp_iface = true;
				}
			}

			if(m_has_l2tp_iface == false && has_l2tp_iface == true)
			{
				IPACMDBG_H("There is l2tp iface, add rt rules for l2tp iface.\n");
				m_has_l2tp_iface = true;
				for(it = ++m_iface.begin(); it != m_iface.end(); it++)
				{
					if(it->is_l2tp_iface() == false)
					{
						it->handle_l2tp_enable();
					}
				}
			}
		}
#endif
		IPACMDBG_H("front_iface (%s).get_m_support_inter_iface_offload() %d \n", front_iface.get_iface_pointer()->dev_name, front_iface.get_m_support_inter_iface_offload());
#ifdef FEATURE_VLAN_MPDN
		if(IsVlan)
		{
			front_iface.set_is_vlan(true);
			if(IPACM_Iface::ipacmcfg->get_iface_vlan_ids(front_iface.get_iface_pointer()->dev_name, Ids))
			{
				IPACMERR("failed getting vlan ids for iface %s\n", front_iface.get_iface_pointer()->dev_name);
				return;
			}

			/* add header processing context for peer VLAN interfaces */
			/* Install rules only when current iface is supporting inter offload */
			if(front_iface.get_m_support_inter_iface_offload())
			{
				for(it = ++m_iface.begin(); it != m_iface.end(); it++)
				{
					if(!it->get_is_vlan())
						IPACMDBG_H("iface %s is non VLAN iface - handle it\n", it->get_iface_pointer()->dev_name);

					if(it->get_is_vlan())
						IPACMDBG_H("iface %s is VLAN iface - handle it\n", it->get_iface_pointer()->dev_name);

					IPACMDBG_H("Lan2Lan_v2: it is %s, it->get_m_support_inter_iface_offload() %d \n", it->get_iface_pointer()->dev_name,it->get_m_support_inter_iface_offload());

					if (!IPACM_Iface::ipacmcfg->multi_vlan_bridge_config_enable && !it->get_is_vlan() && !front_iface.is_svap_iface() &&
							!front_iface.is_ap_iface_vlan_enabled() && !front_iface.is_spcl_iface() && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
					{
						IPACMDBG_H("iface %s is non VLAN iface - skipping\n", it->get_iface_pointer()->dev_name);
						continue;
					}

					/* add peer info only when both interfaces support inter-interface communication */
					if(it->get_m_support_inter_iface_offload())
					{
						/* populate hdr_proc_ctx and routing table handle */
						handle_new_iface_up(&front_iface, &(*it));

						/* add client specific routing rule on existing interface - regardless of vlan id*/
						it->add_client_rt_rule_for_new_iface();
					}
					if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
					{
						/* add client specific flt rule on existing interface - regardless of vlan id*/
						it->add_inter_interface_client_flt_rule_v2(&front_iface, data->iptype, Ids);
					}
				}
			}

			if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
			{
				/* add client specific filtering rule on new interface for matching vlan ids*/
				if (!front_iface.get_m_support_ast_update())
					front_iface.add_all_inter_interface_client_flt_rule(data->iptype, Ids);

				if(IPACM_Iface::ipacmcfg->multi_vlan_bridge_config_enable == 1)
				{
					/* populate the intra-interface information */
					if(front_iface.get_m_support_intra_iface_offload())
					{
						front_iface.handle_intra_interface_info();
					}
				}
			}

			if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
			{
				front_iface.handle_self_interface_info();
			}

			/* handle cached client add event */
			handle_cached_client_add_event(front_iface.get_iface_pointer());

			return;
		}
#endif //FEATURE_VLAN_MPDN

		/* install inter-interface rules */
		if(front_iface.get_m_support_inter_iface_offload())
		{
			for(it = ++m_iface.begin(); it != m_iface.end(); it++)
			{
				if(it->get_is_vlan())
					IPACMDBG_H("iface %s is VLAN iface - handle it\n", it->get_iface_pointer()->dev_name);
				if(!it->get_is_vlan())
					IPACMDBG_H("iface %s is non VLAN iface - handle it\n", it->get_iface_pointer()->dev_name);
				IPACMDBG_H("Lan2Lan_v2: it is %s, it->get_m_support_inter_iface_offload() %d \n", it->get_iface_pointer()->dev_name,it->get_m_support_inter_iface_offload());
#ifdef FEATURE_VLAN_MPDN
				/* non VLAN case - currently no support for non vlan <-> vlan offload */
				if(!IPACM_Iface::ipacmcfg->multi_vlan_bridge_config_enable && it->get_is_vlan() &&
						!it->is_svap_iface() && !it->is_spcl_iface() && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
					continue;
#endif
				/* add peer info only when both interfaces support inter-interface communication */
				if(it->get_m_support_inter_iface_offload())
				{
					/* populate hdr_proc_ctx and routing table handle */
					handle_new_iface_up(&front_iface, &(*it));

					/* add client specific routing rule on existing interface */
					it->add_client_rt_rule_for_new_iface();
				}
				if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
				{
					/* add client specific flt rule on existing interface - regardless of vlan id*/
					if(it->get_is_vlan())
					{
						if(IPACM_Iface::ipacmcfg->get_iface_vlan_ids(it->get_iface_pointer()->dev_name, Ids))
						{
							IPACMERR("failed getting vlan ids for iface %s\n", it->get_iface_pointer()->dev_name);
							return;
						}
						it->add_inter_interface_client_flt_rule_v2(&front_iface, data->iptype, Ids);
					}
					else
					{
						it->add_inter_interface_client_flt_rule_v2(&front_iface, data->iptype);
					}
				}
			}

			/* add client specific filtering rule on new interface */
			if (!front_iface.get_m_support_ast_update() && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
				front_iface.add_all_inter_interface_client_flt_rule(data->iptype);
		}

		/* populate the intra-interface information */
		if(front_iface.get_m_support_intra_iface_offload() && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
		{
			front_iface.handle_intra_interface_info();
		}
		if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
		{
			front_iface.handle_self_interface_info();
		}
		/* handle cached client add event */
		handle_cached_client_add_event(front_iface.get_iface_pointer());
	}
	return;
}

void IPACM_LanToLan::handle_iface_down(ipacm_event_eth_bridge *data)
{
	list<IPACM_LanToLan_Iface>::iterator it_target_iface;
	bool has_l2tp_iface = false;

	IPACMDBG_H("Interface name: %s\n", data->p_iface->dev_name);
	del_mac_addr(data, true);
	for(it_target_iface = m_iface.begin(); it_target_iface != m_iface.end(); it_target_iface++)
	{
		if(it_target_iface->get_iface_pointer() == data->p_iface)
		{
			IPACMDBG_H("Found the interface.\n");
			break;
		}
	}

	if(it_target_iface == m_iface.end())
	{
		IPACMDBG_H("The interface has not been found.\n");
		/* clear cached client add event for the unfound interface*/
		clear_cached_client_add_event(data->p_iface);
		return;
	}

	it_target_iface->handle_down_event();
	m_iface.erase(it_target_iface);
#ifdef FEATURE_L2TP
	if(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP)
	{
		for(it_target_iface = m_iface.begin(); it_target_iface != m_iface.end(); it_target_iface++)
		{
			if(it_target_iface->is_l2tp_iface() == true)
			{
				has_l2tp_iface = true;
				break;
			}
		}
		if(m_has_l2tp_iface == true && has_l2tp_iface == false)
		{
			IPACMDBG_H("There is no l2tp iface now, delete rt rules for l2tp iface.\n");
			m_has_l2tp_iface = false;
			for(it_target_iface = m_iface.begin(); it_target_iface != m_iface.end(); it_target_iface++)
			{
				if(it_target_iface->is_l2tp_iface() == false)
				{
					it_target_iface->handle_l2tp_disable();
				}
			}
		}
	}
#endif
	return;
}

void IPACM_LanToLan::handle_new_iface_up(IPACM_LanToLan_Iface *new_iface, IPACM_LanToLan_Iface *exist_iface)
{
	char rt_tbl_name_for_flt[IPA_IP_MAX][IPA_RESOURCE_NAME_MAX];
	char rt_tbl_name_for_rt[IPA_IP_MAX][IPA_RESOURCE_NAME_MAX];
	char lan_rt_tbl_name_for_flt[IPA_IP_MAX][IPA_RESOURCE_NAME_MAX];
	char lan_rt_tbl_name_for_rt[IPA_IP_MAX][IPA_RESOURCE_NAME_MAX];
	char lan_rt_tbl_name_for_flt_svap[IPA_IP_MAX][IPA_RESOURCE_NAME_MAX];
	char lan_rt_tbl_name_for_rt_svap[IPA_IP_MAX][IPA_RESOURCE_NAME_MAX];
	ipa_hdr_l2_type exist_iface_hdr, new_iface_hdr;
	int num_prop = 0, spcl_vlan_iface = 0;

	if (new_iface == NULL || exist_iface == NULL)
	{
		IPACMERR("Either new_iface or exist_iface is Invalid\n");
		return;
	}

	if (new_iface->is_spcl_iface()) {
		num_prop = new_iface->get_iface_pointer()->rx_prop->num_rx_props;
	}
	else if (exist_iface->is_spcl_iface()) {
		num_prop = exist_iface->get_iface_pointer()->rx_prop->num_rx_props;
	}
	else {
		num_prop = new_iface->get_iface_pointer()->rx_prop->num_rx_props;
	}

	IPACMDBG_H("DEBUG: Num of tx props %d\n",new_iface->get_iface_pointer()->tx_prop->num_tx_props);

	// If either new or existing iface is spcl iface, then IPACM will treat them as two separate peers
	// one with vlan properties and other with non-vlan
	for (int i = 0; i < num_prop/2; i++)
	{
		if (i >= 1 && !new_iface->is_spcl_iface() && !exist_iface->is_spcl_iface()) {
			IPACMDBG_H("Neither new_iface %s or exist_iface %s is eth special\n", new_iface->get_iface_pointer()->dev_name, exist_iface->get_iface_pointer()->dev_name);
			continue;
		}

		spcl_vlan_iface = i ? true : false;
		IPACMDBG_H("Is spcl_vlan_iface %d\n", spcl_vlan_iface);

		if (new_iface->is_svap_iface() || new_iface->is_ap_iface_vlan_enabled() || (new_iface->is_spcl_iface() && i))
		{
			if(new_iface->get_iface_pointer()->tx_prop->num_tx_props > 2)
			{
				new_iface_hdr = new_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type;
			}
			else
			{
				IPACMERR("Incorrect tx properties\n");
				return;
			}
		}
		else
		{
			new_iface_hdr = new_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
		}

		if (exist_iface->is_svap_iface() || exist_iface->is_ap_iface_vlan_enabled() || (exist_iface->is_spcl_iface() && i))
		{
			if(exist_iface->get_iface_pointer()->tx_prop->num_tx_props > 2)
			{
				exist_iface_hdr = exist_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type;
			}
			else
			{
				IPACMERR("Incorrect tx properties\n");
				return;
			}
		}
		else
		{
			exist_iface_hdr = exist_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
		}


		IPACMDBG_H("Populate peer info between: new_iface %s, existing iface %s\n", new_iface->get_iface_pointer()->dev_name,
				   exist_iface->get_iface_pointer()->dev_name);
		if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
		{
			/* populate the routing table information on source peer(vlan / non-vlan)*/
			snprintf(rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
					 ipa_l2_hdr_type[new_iface_hdr]);
			IPACMDBG_H("IPv4 routing table for flt name: %s\n", rt_tbl_name_for_flt[IPA_IP_v4]);

			snprintf(rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
					 ipa_l2_hdr_type[new_iface_hdr]);
			IPACMDBG_H("IPv6 routing table for flt name: %s\n", rt_tbl_name_for_flt[IPA_IP_v6]);

			snprintf(rt_tbl_name_for_rt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
					 ipa_l2_hdr_type[exist_iface_hdr]);
			IPACMDBG_H("IPv4 routing table for rt name: %s\n", rt_tbl_name_for_rt[IPA_IP_v4]);

			snprintf(rt_tbl_name_for_rt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
					 ipa_l2_hdr_type[exist_iface_hdr]);
			IPACMDBG_H("IPv6 routing table for rt name: %s\n", rt_tbl_name_for_rt[IPA_IP_v6]);

			snprintf(lan_rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
						ipa_l2_hdr_type[new_iface->get_iface_pointer()->rx_prop->rx[0].hdr_l2_type]);
			IPACMDBG_H("IPv4 LAN routing table for flt name: %s\n", lan_rt_tbl_name_for_flt[IPA_IP_v4]);

			snprintf(lan_rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
						ipa_l2_hdr_type[new_iface->get_iface_pointer()->rx_prop->rx[0].hdr_l2_type]);
			IPACMDBG_H("IPv6 LAN routing table for flt name: %s\n", lan_rt_tbl_name_for_flt[IPA_IP_v6]);

			snprintf(lan_rt_tbl_name_for_rt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
						ipa_l2_hdr_type[exist_iface->get_iface_pointer()->rx_prop->rx[0].hdr_l2_type]);
			IPACMDBG_H("IPv4 lan routing table for rt name: %s\n", lan_rt_tbl_name_for_rt[IPA_IP_v4]);

			snprintf(lan_rt_tbl_name_for_rt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
						ipa_l2_hdr_type[exist_iface->get_iface_pointer()->rx_prop->rx[0].hdr_l2_type]);
			IPACMDBG_H("IPv4 lan routing table for rt name: %s\n", lan_rt_tbl_name_for_rt[IPA_IP_v6]);

				/* populate the routing table information */
			if (new_iface->is_svap_iface() ||  new_iface->is_ap_iface_vlan_enabled() || (new_iface->is_spcl_iface()  && i) )  {
				snprintf(lan_rt_tbl_name_for_flt_svap[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
							ipa_l2_hdr_type[new_iface->get_iface_pointer()->rx_prop->rx[2].hdr_l2_type]);
				IPACMDBG_H("IPv4 LAN routing table for flt name: %s\n", lan_rt_tbl_name_for_flt_svap[IPA_IP_v4]);

				snprintf(lan_rt_tbl_name_for_flt_svap[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
							ipa_l2_hdr_type[new_iface->get_iface_pointer()->rx_prop->rx[2].hdr_l2_type]);
				IPACMDBG_H("IPv6 LAN routing table for flt name: %s\n", lan_rt_tbl_name_for_flt_svap[IPA_IP_v6]);
				}
			if(exist_iface->is_svap_iface() || exist_iface->is_ap_iface_vlan_enabled() || (exist_iface->is_spcl_iface() && i)) {
				snprintf(lan_rt_tbl_name_for_rt_svap[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
							ipa_l2_hdr_type[exist_iface->get_iface_pointer()->rx_prop->rx[2].hdr_l2_type]);
				IPACMDBG_H("IPv4 lan routing table for rt name: %s\n", lan_rt_tbl_name_for_rt_svap[IPA_IP_v4]);

				snprintf(lan_rt_tbl_name_for_rt_svap[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
							ipa_l2_hdr_type[exist_iface->get_iface_pointer()->rx_prop->rx[2].hdr_l2_type]);
				IPACMDBG_H("IPv4 lan routing table for rt name: %s\n", lan_rt_tbl_name_for_rt_svap[IPA_IP_v6]);
			}

			/* add new peer info in both new iface and existing iface */
			/*new iface <--> exist iface*/ /*for ast non ast*/
			if (new_iface->is_svap_iface() || new_iface->is_ap_iface_vlan_enabled()) {
				if (exist_iface->is_svap_iface() || exist_iface->is_ap_iface_vlan_enabled()) {
					/* ath02(svap) <--> ath12 (svap)*/
					exist_iface->handle_new_iface_up(lan_rt_tbl_name_for_rt_svap, lan_rt_tbl_name_for_rt_svap, new_iface,spcl_vlan_iface);
					new_iface->handle_new_iface_up(lan_rt_tbl_name_for_flt_svap, lan_rt_tbl_name_for_flt_svap, exist_iface,spcl_vlan_iface);
				} else {
					/* ath02 <--> ath12 (svap)  or ath02 <--> eth (siface)*/
					exist_iface->handle_new_iface_up(lan_rt_tbl_name_for_rt, lan_rt_tbl_name_for_rt, new_iface,spcl_vlan_iface);
					new_iface->handle_new_iface_up(lan_rt_tbl_name_for_flt_svap, lan_rt_tbl_name_for_flt_svap, exist_iface,spcl_vlan_iface);
				}
			} else {
				/* ath02(svap) <--> ath12 or eth (siface) <--> ath12 */
				if (exist_iface->is_svap_iface() || exist_iface->is_ap_iface_vlan_enabled()) {
					exist_iface->handle_new_iface_up(lan_rt_tbl_name_for_rt_svap, lan_rt_tbl_name_for_rt_svap, new_iface,spcl_vlan_iface);
					new_iface->handle_new_iface_up(lan_rt_tbl_name_for_flt, lan_rt_tbl_name_for_flt, exist_iface,spcl_vlan_iface);
				} else {
					/* ath02 <--> ath12 */
					exist_iface->handle_new_iface_up(lan_rt_tbl_name_for_rt, lan_rt_tbl_name_for_rt, new_iface,spcl_vlan_iface);
					new_iface->handle_new_iface_up(lan_rt_tbl_name_for_flt, lan_rt_tbl_name_for_flt, exist_iface,spcl_vlan_iface);
				}
			}
		}
		else
		{
			/* populate the routing table information */
			snprintf(rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_%s_to_%s",
					 ipa_l2_hdr_type[exist_iface_hdr],
					 ipa_l2_hdr_type[new_iface_hdr]);
			IPACMDBG_H("IPv4 routing table for flt name: %s\n", rt_tbl_name_for_flt[IPA_IP_v4]);

			snprintf(rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_%s_to_%s",
					 ipa_l2_hdr_type[exist_iface_hdr],
					 ipa_l2_hdr_type[new_iface_hdr]);
			IPACMDBG_H("IPv6 routing table for flt name: %s\n", rt_tbl_name_for_flt[IPA_IP_v6]);

			snprintf(rt_tbl_name_for_rt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_%s_to_%s",
					 ipa_l2_hdr_type[new_iface_hdr],
					 ipa_l2_hdr_type[exist_iface_hdr]);
			IPACMDBG_H("IPv4 routing table for rt name: %s\n", rt_tbl_name_for_rt[IPA_IP_v4]);

			snprintf(rt_tbl_name_for_rt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_%s_to_%s",
					 ipa_l2_hdr_type[new_iface_hdr],
					 ipa_l2_hdr_type[exist_iface_hdr]);
			IPACMDBG_H("IPv6 routing table for rt name: %s\n", rt_tbl_name_for_rt[IPA_IP_v6]);

			if (new_iface->get_m_support_ast_update()) {
				snprintf(lan_rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
						 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
				IPACMDBG_H("IPv4 LAN routing table for flt name: %s\n", lan_rt_tbl_name_for_flt[IPA_IP_v4]);

				snprintf(lan_rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
						 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
				IPACMDBG_H("IPv6 LAN routing table for flt name: %s\n", lan_rt_tbl_name_for_flt[IPA_IP_v6]);

				snprintf(lan_rt_tbl_name_for_rt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
						 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
				IPACMDBG_H("IPv4 lan routing table for rt name: %s\n", lan_rt_tbl_name_for_rt[IPA_IP_v4]);

				snprintf(lan_rt_tbl_name_for_rt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
						 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
				IPACMDBG_H("IPv4 lan routing table for rt name: %s\n", lan_rt_tbl_name_for_rt[IPA_IP_v6]);

				/* populate the routing table information */
				if (new_iface->is_svap_iface() || exist_iface->is_svap_iface() || new_iface->is_ap_iface_vlan_enabled() || exist_iface->is_ap_iface_vlan_enabled()) {
					snprintf(lan_rt_tbl_name_for_flt_svap[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv4 LAN routing table for flt name: %s\n", lan_rt_tbl_name_for_flt_svap[IPA_IP_v4]);

					snprintf(lan_rt_tbl_name_for_flt_svap[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv6 LAN routing table for flt name: %s\n", lan_rt_tbl_name_for_flt_svap[IPA_IP_v6]);

					snprintf(lan_rt_tbl_name_for_rt_svap[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv4 lan routing table for rt name: %s\n", lan_rt_tbl_name_for_rt_svap[IPA_IP_v4]);

					snprintf(lan_rt_tbl_name_for_rt_svap[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv4 lan routing table for rt name: %s\n", lan_rt_tbl_name_for_rt_svap[IPA_IP_v6]);
				}

				/* add new peer info in both new iface and existing iface */
				if (new_iface->is_svap_iface() || new_iface->is_ap_iface_vlan_enabled()) {
					if (exist_iface->get_m_support_ast_update()) {
						if (exist_iface->is_svap_iface() || exist_iface->is_ap_iface_vlan_enabled()) {
							/* ath02(svap) <--> ath12 (svap)*/
							exist_iface->handle_new_iface_up(lan_rt_tbl_name_for_flt_svap, lan_rt_tbl_name_for_rt_svap, new_iface);
							new_iface->handle_new_iface_up(lan_rt_tbl_name_for_rt_svap, lan_rt_tbl_name_for_flt_svap, exist_iface);
						} else {
							/* ath1(ast) <--> ath12 (svap) */
							exist_iface->handle_new_iface_up(lan_rt_tbl_name_for_flt, lan_rt_tbl_name_for_rt_svap, new_iface);
							new_iface->handle_new_iface_up(lan_rt_tbl_name_for_rt_svap, lan_rt_tbl_name_for_flt, exist_iface);
						}
					} else {
						/* eth1 <--> ath12(svap) */
						exist_iface->handle_new_iface_up(rt_tbl_name_for_flt, lan_rt_tbl_name_for_rt_svap, new_iface);
						new_iface->handle_new_iface_up(lan_rt_tbl_name_for_rt_svap, rt_tbl_name_for_flt, exist_iface);
					}
				} else {
					if (exist_iface->get_m_support_ast_update()) {
						if (exist_iface->is_svap_iface() || exist_iface->is_ap_iface_vlan_enabled()) {
							/* ath12(svap) <--> ath1(ast) */
							exist_iface->handle_new_iface_up(lan_rt_tbl_name_for_rt_svap, lan_rt_tbl_name_for_flt, new_iface);
							new_iface->handle_new_iface_up(lan_rt_tbl_name_for_flt, lan_rt_tbl_name_for_rt_svap, exist_iface);
						} else {
							/* ast <--> ast iface*/
							exist_iface->handle_new_iface_up(lan_rt_tbl_name_for_flt, lan_rt_tbl_name_for_rt, new_iface);
							new_iface->handle_new_iface_up(lan_rt_tbl_name_for_flt, lan_rt_tbl_name_for_flt, exist_iface);
						}
					} else {
						/* eth/usb <--> ath1(ast only) */
						exist_iface->handle_new_iface_up(rt_tbl_name_for_flt, lan_rt_tbl_name_for_rt, new_iface);
						new_iface->handle_new_iface_up(lan_rt_tbl_name_for_flt, rt_tbl_name_for_flt, exist_iface);
					}
				}
			} else if (exist_iface->get_m_support_ast_update()) {
				snprintf(lan_rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
						 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
				IPACMDBG_H("IPv4 LAN routing table for flt name: %s\n", lan_rt_tbl_name_for_flt[IPA_IP_v4]);

				snprintf(lan_rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
						 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
				IPACMDBG_H("IPv6 LAN routing table for flt name: %s\n", lan_rt_tbl_name_for_flt[IPA_IP_v6]);

				snprintf(lan_rt_tbl_name_for_rt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
						 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
				IPACMDBG_H("IPv4 lan routing table for rt name: %s\n", lan_rt_tbl_name_for_rt[IPA_IP_v4]);

				snprintf(lan_rt_tbl_name_for_rt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
						 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
				IPACMDBG_H("IPv4 lan routing table for rt name: %s\n", lan_rt_tbl_name_for_rt[IPA_IP_v6]);

				/* populate the routing table information */
				if (exist_iface->is_svap_iface() || exist_iface->is_ap_iface_vlan_enabled()) {
					snprintf(lan_rt_tbl_name_for_flt_svap[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv4 LAN routing table for flt name: %s\n", lan_rt_tbl_name_for_flt_svap[IPA_IP_v4]);

					snprintf(lan_rt_tbl_name_for_flt_svap[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv6 LAN routing table for flt name: %s\n", lan_rt_tbl_name_for_flt_svap[IPA_IP_v6]);

					snprintf(lan_rt_tbl_name_for_rt_svap[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv4 lan routing table for rt name: %s\n", lan_rt_tbl_name_for_rt_svap[IPA_IP_v4]);

					snprintf(lan_rt_tbl_name_for_rt_svap[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv4 lan routing table for rt name: %s\n", lan_rt_tbl_name_for_rt_svap[IPA_IP_v6]);
				}

				/* add new peer info in both new iface and existing iface
				   AST update flag is valid for all WLAN APs, at this point new iface can only be a interface
				   of non-AST type, hence default rt rules are used for new iface here */
				if (exist_iface->is_svap_iface() || exist_iface->is_ap_iface_vlan_enabled()) {
					/* ath12(svap) <--> eth1 */
					new_iface->handle_new_iface_up(rt_tbl_name_for_rt, lan_rt_tbl_name_for_flt_svap, exist_iface);
					exist_iface->handle_new_iface_up(lan_rt_tbl_name_for_flt_svap, rt_tbl_name_for_rt, new_iface);
				} else {
					/* ath1(ast) <--> eth1 */
					new_iface->handle_new_iface_up(rt_tbl_name_for_rt, lan_rt_tbl_name_for_flt, exist_iface);
					exist_iface->handle_new_iface_up(lan_rt_tbl_name_for_flt, rt_tbl_name_for_rt, new_iface);
				}
			} else {
				if (new_iface->is_svap_iface() || new_iface->is_ap_iface_vlan_enabled()) {
					snprintf(rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_%s_to_%s",
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type],
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv4 routing table for flt name: %s\n", rt_tbl_name_for_flt[IPA_IP_v4]);

					snprintf(rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_%s_to_%s",
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type],
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv6 routing table for flt name: %s\n", rt_tbl_name_for_flt[IPA_IP_v6]);

					snprintf(rt_tbl_name_for_rt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_%s_to_%s",
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type],
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
					IPACMDBG_H("IPv4 routing table for rt name: %s\n", rt_tbl_name_for_rt[IPA_IP_v4]);

					snprintf(rt_tbl_name_for_rt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_%s_to_%s",
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type],
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
					IPACMDBG_H("IPv6 routing table for rt name: %s\n", rt_tbl_name_for_rt[IPA_IP_v6]);
				} else if (exist_iface->is_svap_iface() || exist_iface->is_ap_iface_vlan_enabled()) {
					snprintf(rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_%s_to_%s",
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type],
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
					IPACMDBG_H("IPv4 routing table for flt name: %s\n", rt_tbl_name_for_flt[IPA_IP_v4]);

					snprintf(rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_%s_to_%s",
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type],
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
					IPACMDBG_H("IPv6 routing table for flt name: %s\n", rt_tbl_name_for_flt[IPA_IP_v6]);

					snprintf(rt_tbl_name_for_rt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_%s_to_%s",
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type],
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv4 routing table for rt name: %s\n", rt_tbl_name_for_rt[IPA_IP_v4]);

					snprintf(rt_tbl_name_for_rt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_%s_to_%s",
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type],
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv6 routing table for rt name: %s\n", rt_tbl_name_for_rt[IPA_IP_v6]);
				}

				if(new_iface->is_svap_iface() && exist_iface->is_svap_iface())
				{
					snprintf(rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_%s_to_%s",
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type],
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv4 routing table for flt name: %s\n", rt_tbl_name_for_flt[IPA_IP_v4]);

					snprintf(rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_%s_to_%s",
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type],
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv6 routing table for flt name: %s\n", rt_tbl_name_for_flt[IPA_IP_v6]);

					snprintf(rt_tbl_name_for_rt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_%s_to_%s",
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type],
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv4 routing table for rt name: %s\n", rt_tbl_name_for_rt[IPA_IP_v4]);

					snprintf(rt_tbl_name_for_rt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_%s_to_%s",
							 ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type],
							 ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type]);
					IPACMDBG_H("IPv6 routing table for rt name: %s\n", rt_tbl_name_for_rt[IPA_IP_v6]);

				}

				/* add new peer info in both new iface and existing iface (eth <--> eth)*/
				/* spcl_vlan_iface would be 0, when both ifaces are considered non-vlan and 1 when one of them
				   is a special-iface. By this way we will install 2 peer instance(vlan and non-vlan) of the
				   same interface */
				exist_iface->handle_new_iface_up(rt_tbl_name_for_flt, rt_tbl_name_for_rt, new_iface, spcl_vlan_iface);

				new_iface->handle_new_iface_up(rt_tbl_name_for_rt, rt_tbl_name_for_flt, exist_iface, spcl_vlan_iface);
			}
		}
	}
	return;
}

#ifdef FEATURE_VLAN_MPDN
void IPACM_LanToLan::handle_vlan_id_add(ipacm_event_eth_bridge *data)
{
	list<IPACM_LanToLan_Iface>::iterator it;

	IPACMDBG_H("got vlan_id add for %s, id %d\n", data->iface_name, data->VlanID);
	/* find physical iface */
	for(it = m_iface.begin(); it != m_iface.end(); it++)
	{
		/* iface name from ioctl is vlan iface name, look for phys iface */
		if (strstr(data->iface_name, it->get_iface_pointer()->dev_name))
		{
			IPACMDBG("iface %s physical iface %s is found\n",
				data->iface_name,
				it->get_iface_pointer()->dev_name);
			if(!IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it->get_iface_pointer()->dev_name))
			{
				IPACMERR("mismatch, iface not in vlan mode!\n");
				return;
			}

			/* install inter-interface rules */
			if(it->get_m_support_inter_iface_offload())
			{
				it->handle_vlan_id_add(data->VlanID);
			}
			break;
		}
	}

	if(it == m_iface.end())
	{
		/* probably got the ioctl before handle iface up event, once iface up event arrives rules shall be installed */
		IPACMDBG_H("the parent physical iface of %s was not added as Ethernet bridge iface\n", data->iface_name);
	}
	return;
}

void IPACM_LanToLan::handle_vlan_id_del(ipacm_event_eth_bridge *data)
{
	list<IPACM_LanToLan_Iface>::iterator it_to_del;

	/* find physical iface */
	for(it_to_del = m_iface.begin(); it_to_del != m_iface.end(); it_to_del++)
	{
		/* iface name from ioctl is vlan iface name, look for phys iface */
		if(strstr(data->iface_name, it_to_del->get_iface_pointer()->dev_name))
		{
			IPACMDBG_H("found physical iface %s for vlan iface %s\n", it_to_del->get_iface_pointer()->dev_name, data->iface_name);
			if(!IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_to_del->get_iface_pointer()->dev_name))
			{
				IPACMERR("mismatch, iface not in vlan mode!\n");
				return;
			}

			it_to_del->handle_vlan_id_del(data->VlanID);
			break;
		}
	}

	if(it_to_del == m_iface.end())
	{
		IPACMERR("iface %s was not added before gas Ethernet bridge iface\n", data->iface_name);
	}
}
#endif

void IPACM_LanToLan::add_mac_addr(ipacm_event_eth_bridge *data)
{
	list<add_iface_mac>::iterator it_client;
	add_iface_mac add_iface_macs;
	IPACMDBG_H("Adding Interface %s  to list\n", data->p_iface->dev_name);
	for(it_client = add_ifaces_mac.begin();
		it_client != add_ifaces_mac.end(); it_client++)
	{
		if((!memcmp(it_client->mac, data->mac_addr, sizeof(data->mac_addr))) &&
		!(memcmp(data->p_iface->dev_name, it_client->iface_name, sizeof(data->p_iface->dev_name))))
		{
			IPACMDBG_H("found the Interface name: %s in list\n",
				data->p_iface->dev_name);
			break;
		}
	}
	if(it_client == add_ifaces_mac.end())
	{
		memcpy(add_iface_macs.mac, data->mac_addr, sizeof(data->mac_addr));
		memcpy(add_iface_macs.iface_name, data->p_iface->dev_name,
			sizeof(data->p_iface->dev_name));

		IPACMDBG_H("Added Interface %s  successfully to list with client MAC 0x%02x%02x%02x%02x%02x%02x\n",
			add_iface_macs.iface_name, add_iface_macs.mac[0], add_iface_macs.mac[1], add_iface_macs.mac[2],
			add_iface_macs.mac[3],	add_iface_macs.mac[4], add_iface_macs.mac[5]);
		add_iface_macs.vlan_id = data->VlanID;
		add_ifaces_mac.push_back(add_iface_macs);

	}
}

void IPACM_LanToLan::handle_client_add(ipacm_event_eth_bridge *data)
{
	list<IPACM_LanToLan_Iface>::iterator it_iface;
	list<l2tp_vlan_mapping_info>::iterator it_mapping;
	l2tp_vlan_mapping_info *mapping_info = NULL;
	bool is_l2tp_client = false;
	list<IPACM_LanToLan_Iface>::iterator it;
	IPACMDBG_H("(%s)*************************>>\n",data->p_iface->dev_name);
	IPACMDBG_H("Incoming client MAC: 0x%02x%02x%02x%02x%02x%02x, interface: %s\n",
		data->mac_addr[0], data->mac_addr[1],
		data->mac_addr[2], data->mac_addr[3], data->mac_addr[4],
		data->mac_addr[5], data->p_iface->dev_name);

	add_mac_addr(data);
#ifdef FEATURE_L2TP
	if(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP)
	{
		for(it_mapping = IPACM_Iface::ipacmcfg->m_l2tp_vlan_mapping.begin();
			it_mapping != IPACM_Iface::ipacmcfg->m_l2tp_vlan_mapping.end(); it_mapping++)
		{
			if(strncmp(it_mapping->l2tp_iface_name, data->iface_name,
				sizeof(it_mapping->l2tp_iface_name)) == 0)
			{
				IPACMDBG_H("Found l2tp iface %s with l2tp client MAC 0x%02x%02x%02x%02x%02x%02x\n",
					it_mapping->l2tp_iface_name, it_mapping->l2tp_client_mac[0], it_mapping->l2tp_client_mac[1],
					it_mapping->l2tp_client_mac[2], it_mapping->l2tp_client_mac[3], it_mapping->l2tp_client_mac[4],
					it_mapping->l2tp_client_mac[5]);
				memcpy(it_mapping->l2tp_client_mac, data->mac_addr, sizeof(it_mapping->l2tp_client_mac));
				mapping_info = &(*it_mapping);
				is_l2tp_client = true;
				break;
			}
		}
	}
#endif
	IPACMDBG_H("m_iface.size() %d\n", m_iface.size());
	if(m_iface.size() >= 1)
	{
		for(it = m_iface.begin(); it != m_iface.end(); it++)
		{
			IPACMDBG_H("iface: %s \n", it->get_iface_pointer()->dev_name);
		}
	}

	for(it_iface = m_iface.begin(); it_iface != m_iface.end(); it_iface++)
	{
		if(it_iface->get_iface_pointer() == data->p_iface)	//find the interface
		{
			IPACMDBG_H("Found the interface.\n");
#ifdef FEATURE_VLAN_MPDN
			if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == true)
			{
				if (it_iface->is_spcl_iface())
				{
					IPACMDBG_H("Special interface, allow both vlan and non-vlan clients\n");
				}
				else if (it_iface->get_is_vlan())
				{
					if(!data->VlanID)
					{
						IPACMERR("got VlanID 0 for IF in VLAN mode\n");
						return;
					}
				}
				else if(data->VlanID)
				{
					IPACMERR("got event with vlan id for non VLAN IF");
					return;
				}
			}
#endif //FEATURE_VLAN_MPDN
			it_iface->handle_client_add(data->mac_addr, data->p_iface->dev_name, is_l2tp_client, mapping_info, data->VlanID);
			break;
		}
	}

	/* if the iface was not found, cache the client add event */
	if(it_iface == m_iface.end())
	{
		IPACMDBG_H("The interface is not found.\n");
		if(m_cached_client_add_event.size() < MAX_NUM_CACHED_CLIENT_ADD_EVENT)
		{
			IPACMDBG_H("Cached the client information.\n");
			m_cached_client_add_event.push_front(*data);
		}
		else
		{
			IPACMDBG_H("Cached client add event has reached maximum number.\n");
		}
	}
	IPACMDBG_H("(%s)*************************<<\n",data->p_iface->dev_name);
	return;
}

void IPACM_LanToLan::del_mac_addr(ipacm_event_eth_bridge *data, bool iface_down)
{
	list<add_iface_mac>::iterator it_client;

	IPACMDBG_H("deleting the Interface %s from list\n",
			data->p_iface->dev_name);
	for(it_client = add_ifaces_mac.begin();
		it_client != add_ifaces_mac.end(); it_client++)
	{
		if(((!iface_down && (!memcmp(it_client->mac, data->mac_addr, sizeof(it_client->mac)))) ||
		(iface_down)) &&
		!(memcmp(data->p_iface->dev_name, it_client->iface_name, sizeof(data->p_iface->dev_name))))
		{
			IPACMDBG_H("deleting the Interface: %s MAC: 0x%02x%02x%02x%02x%02x%02x\n", data->p_iface->dev_name,
			it_client->mac[0], it_client->mac[1], it_client->mac[2],
			it_client->mac[3], it_client->mac[4], it_client->mac[5]);
			if(iface_down)
			{
				memcpy(data->mac_addr, it_client->mac, sizeof(it_client->mac));
			}
			add_ifaces_mac.erase(it_client);
			handle_client_del(data, true);
			break;
		}
	}
	if(it_client == add_ifaces_mac.end())
	{
		IPACMERR(" Not found the Interface name: %s in list\n",
				data->p_iface->dev_name);
	}
}

void IPACM_LanToLan::handle_client_del(ipacm_event_eth_bridge *data, bool del_client)
{
	list<IPACM_LanToLan_Iface>::iterator it_iface;
	if(!del_client)
		del_mac_addr(data);
	IPACMDBG_H("Incoming client MAC: 0x%02x%02x%02x%02x%02x%02x, interface: %s\n",
			data->mac_addr[0], data->mac_addr[1], data->mac_addr[2],
			data->mac_addr[3], data->mac_addr[4], data->mac_addr[5],
			data->p_iface->dev_name);
#ifdef FEATURE_VLAN_MPDN
	if(data->VlanID)
		IPACMDBG_H("vlan client! ID %d\n", data->VlanID);
#endif

	for(it_iface = m_iface.begin(); it_iface != m_iface.end(); it_iface++)
	{
		if(it_iface->get_iface_pointer() == data->p_iface)	//found the interface
		{
			IPACMDBG_H("Found the interface.\n");
			it_iface->handle_client_del(data->mac_addr, data->VlanID);
			break;
		}
	}

	if(it_iface == m_iface.end())
	{
		IPACMDBG_H("The interface is not found.\n");
	}

	return;
}

void IPACM_LanToLan::handle_wlan_scc_mcc_switch(ipacm_event_eth_bridge *data)
{
	list<IPACM_LanToLan_Iface>::iterator it_iface;

	IPACMDBG_H("Incoming interface: %s\n", data->p_iface->dev_name);
	for(it_iface = m_iface.begin(); it_iface != m_iface.end(); it_iface++)
	{
		if(it_iface->get_iface_pointer() == data->p_iface)
		{
			it_iface->handle_wlan_scc_mcc_switch();
			break;
		}
	}
	return;
}

void IPACM_LanToLan::handle_cached_client_add_event(IPACM_Lan *p_iface)
{
	list<ipacm_event_eth_bridge>::iterator it;

	it = m_cached_client_add_event.begin();
	while(it != m_cached_client_add_event.end())
	{
		if(it->p_iface == p_iface)
		{
			IPACMDBG_H("Found client with MAC: 0x%02x%02x%02x%02x%02x%02x\n", it->mac_addr[0], it->mac_addr[1],
				it->mac_addr[2], it->mac_addr[3], it->mac_addr[4], it->mac_addr[5]);
			handle_client_add(&(*it));
			it = m_cached_client_add_event.erase(it);
		}
		else
		{
			it++;
		}
	}
	return;
}

char* IPACM_LanToLan::handle_cached_client_get_iface(uint8_t *mac)
{
	list<ipacm_event_eth_bridge>::iterator it;

	it = m_cached_client_add_event.begin();
	while(it != m_cached_client_add_event.end())
	{
		if(memcmp(it->mac_addr, mac, sizeof(it->mac_addr)) == 0)
		{
			IPACMDBG_H("Found client %s with MAC: 0x%02x%02x%02x%02x%02x%02x\n",
				it->iface_name, it->mac_addr[0], it->mac_addr[1],
				it->mac_addr[2], it->mac_addr[3], it->mac_addr[4], it->mac_addr[5]);
				return it->iface_name;
		}
	}
	return nullptr;
}

void IPACM_LanToLan::clear_cached_client_add_event(IPACM_Lan *p_iface)
{
	list<ipacm_event_eth_bridge>::iterator it;

	it = m_cached_client_add_event.begin();
	while(it != m_cached_client_add_event.end())
	{
		if(it->p_iface == p_iface)
		{
			IPACMDBG_H("Found client with MAC: 0x%02x%02x%02x%02x%02x%02x\n", it->mac_addr[0], it->mac_addr[1],
				it->mac_addr[2], it->mac_addr[3], it->mac_addr[4], it->mac_addr[5]);
			it = m_cached_client_add_event.erase(it);
		}
		else
		{
			it++;
		}
	}
	return;
}

void IPACM_LanToLan::print_data_structure_info()
{
	list<IPACM_LanToLan_Iface>::iterator it;
	list<ipacm_event_eth_bridge>::iterator it_event;
	list<vlan_iface_info>::iterator it_vlan;
	list<l2tp_vlan_mapping_info>::iterator it_mapping;
	int i;

	IPACMDBG_H("Is there l2tp interface? %d\n", m_has_l2tp_iface);
	IPACMDBG_H("There are %zu interfaces in total.\n", m_iface.size());
	for(it = m_iface.begin(); it != m_iface.end(); it++)
	{
		it->print_data_structure_info();
	}

	IPACMDBG_H("There are %zu cached client add events in total.\n", m_cached_client_add_event.size());

	i = 1;
	for(it_event = m_cached_client_add_event.begin(); it_event != m_cached_client_add_event.end(); it_event++)
	{
		IPACMDBG_H("Client %d MAC: 0x%02x%02x%02x%02x%02x%02x, interface: %s\n", i, it_event->mac_addr[0], it_event->mac_addr[1], it_event->mac_addr[2],
			it_event->mac_addr[3], it_event->mac_addr[4], it_event->mac_addr[5], it_event->p_iface->dev_name);
		i++;
	}

	return;
}

void IPACM_LanToLan_Iface::add_client_rt_rule_for_new_iface()
{
	list<client_info>::iterator it;
	ipa_hdr_l2_type peer_l2_type = IPA_HDR_L2_NONE;
	int num_prop = 0;
	peer_iface_info &peer = m_peer_iface_info.front();
	peer_iface_info& front_peer = m_peer_iface_info.front();
	list<peer_iface_info>::iterator itr;
	int i = 0;

	if (!peer.peer || !peer.peer->get_iface_pointer() || !peer.peer->get_iface_pointer()->rx_prop) {
		return;
	}

	num_prop = peer.peer->get_iface_pointer()->rx_prop->num_rx_props;
	IPACMDBG("Lan2Lan_v2:  This dev %s\n", this->get_iface_pointer()->dev_name);
	IPACMDBG("add client specific routing rule on existing interface - regardless of vlan id\n");
	for (itr = m_peer_iface_info.begin(); itr != m_peer_iface_info.end(); itr++)
	{
		/* For special interface, a client rule needs to be installed on both the vlan and non-vlan supported route tables.
		   Hence we need to iterate on both the peer interface(special vlan peer and special non-vlan peer) */
		IPACMDBG("rt_tbl %s \n flt %s\n", (*itr).rt_tbl_name_for_rt[IPA_IP_v4], (*itr).rt_tbl_name_for_flt[IPA_IP_v4]);
		IPACMDBG("Debug iterator %d\n", i);

		if (!(*itr).peer || !(*itr).peer->get_iface_pointer() || !(*itr).peer->get_iface_pointer()->tx_prop)
		{
			IPACMERR("Invalid peer info..\n", i);
			return;
		}

		if ((*itr).peer->is_svap_iface() || (*itr).peer->is_ap_iface_vlan_enabled() || ((*itr).peer->is_spcl_iface() && i)) {
			peer_l2_type = (*itr).peer->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type;
		} else {
			peer_l2_type = (*itr).peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
		}

		/* Special interface can have ref_count of 2 for a header type since eth_to_eth and 802_to_eth both will increase
		   the eth l2 hdr ref count resulting in 2 */
		if ((peer_l2_type < IPA_HDR_L2_MAX) &&
			(ref_cnt_peer_l2_hdr_type[peer_l2_type] == 1 || (m_is_sIface && ref_cnt_peer_l2_hdr_type[peer_l2_type] == 2) || (*itr).peer->ref_cnt_peer_l2_hdr_type[peer_l2_type] == 1)) {
			IPACMDBG_H("peer_iface %s MAC: has hdr_type: %d with ref count: %d\n",
				(*itr).peer->get_iface_pointer()->dev_name, peer_l2_type, ref_cnt_peer_l2_hdr_type[peer_l2_type]);

			for (it = m_client_info.begin(); it != m_client_info.end(); it++) {
				IPACMDBG("Client info iterator it %d\n", it);
#ifdef FEATURE_L2TP
				if (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) {
					if (it->is_l2tp_client == false) {
						add_client_rt_rule(&(*itr), &(*it));
					}
					/* add l2tp rt rules */
					add_l2tp_client_rt_rule(&(*itr), &(*it));
				} else add_client_rt_rule(&(*itr), &(*it));
#else
				if (is_spcl_iface())
				{
					/* Install vlan client on vlan peer only and similarly versa for non-vlan client */
					if (((*it).vlan_id && !(*itr).is_vlan_peer) ||
						(!(*it).vlan_id && (*itr).is_vlan_peer))
					{
						IPACMDBG("Vlan client with vlan id %d on non-vlan peer ..continue %d\n", (*it).vlan_id);
						continue;
					}
				}
				add_client_rt_rule(&(*itr), &(*it));
#endif
			}
		}
		i++;
	}

	if (peer.peer->pipe_idx ) {
		peer.peer->pipe_idx = 0;
	}
	auto l_front = m_peer_iface_info.begin();
	peer = *l_front;

	return;
}

void IPACM_LanToLan_Iface::add_client_rt_rule(peer_iface_info *peer_info, client_info *client)
{
	int i, ret, num_rt_rule = 0;
	uint32_t rt_rule_hdl[MAX_NUM_PROP];
	ipa_hdr_l2_type peer_l2_hdr_type, mac_ref_peer_l2_hdr_type;
	list<peer_iface_info>::iterator itr;
#ifdef FEATURE_VLAN_MPDN
	std::array<uint8_t, 6> mac = {0};
	std::map<std::array<uint8_t, 6>, int>::iterator it, it1;
	std::map<std::array<uint8_t, 6>, int>::iterator del_it;
#endif
	int mac_found = 0;
	uint32_t hdr_proc_ctx_hdl = 0;

	if (!peer_info || !peer_info->peer || !client) {
		IPACMDBG_H("Invalid peer or client info\n");
		return;
	}

	IPACMDBG_H("dev_name: %s \n", this->get_iface_pointer()->dev_name);
	IPACMDBG_H("client_vlan_id: %d\n", client->vlan_id);
	IPACMDBG_H("peer_info->peer->m_is_svap_iface: %d\n", peer_info->peer->m_is_svap_iface);
	IPACMDBG_H("peer_info->peer->m_is_sIface: %d\n", peer_info->peer->m_is_sIface);
	IPACMDBG_H("peer_info->peer->dev_name: %s\n", peer_info->peer->get_iface_pointer()->dev_name);
	IPACMDBG_H("peer_info->is_vlan_peer: %d\n", peer_info->is_vlan_peer);
	IPACMDBG_H("m_p_iface->dev_name: %s\n", m_p_iface->dev_name);

	if (peer_info->peer->m_is_svap_iface || (peer_info->peer->m_is_sIface && peer_info->is_vlan_peer))
	{
		peer_l2_hdr_type = peer_info->peer->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type;
	}
	else {
		peer_l2_hdr_type = peer_info->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
	}
	IPACMDBG_H("peer_l2_hdr_type: %d\n", peer_l2_hdr_type);

	if(peer_l2_hdr_type >= IPA_HDR_L2_MAX || peer_l2_hdr_type < 0)
	{
		IPACMDBG_H("Invalid peer_l2_hdr_type: %d\n", peer_l2_hdr_type);
		return;
	}

	/* if the peer info is not for intra interface communication */
	if(peer_info->peer != this)
	{
		IPACMDBG_H("This is for inter interface communication.\n");
#ifdef FEATURE_VLAN_MPDN
		if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
		{
			/* create mac as array and use it as key for a map that hold a reference count per MAC */
			std::copy(std::begin(client->mac_addr), std::end(client->mac_addr), std::begin(mac));
			if(client->vlan_id)
				IPACMDBG_H("client vlan id %d\n", client->vlan_id);

			it = peer_info->mac_rt_rule_ref.find(mac);
			if(it != peer_info->mac_rt_rule_ref.end() &&
				!peer_info->peer->is_spcl_iface())
			{
				IPACMDBG_H("return mac ref found on self\n");
				return;
			}

			IPACMDBG_H("peer_l2_hdr_type %d\n",peer_l2_hdr_type);
			/* check if peer already has rt rule for this mac address */
			for (itr = m_peer_iface_info.begin();
				itr != m_peer_iface_info.end(); itr++)
			{
				if (itr->peer->m_is_svap_iface || (itr->peer->is_spcl_iface() && itr->is_vlan_peer)) {
					mac_ref_peer_l2_hdr_type = itr->peer->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type;
				}
				else {
					mac_ref_peer_l2_hdr_type = itr->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
				}
				IPACMDBG_H("peer_l2_hdr_type %d mac_ref_peer_l2_hdr_type %d\n",peer_l2_hdr_type,mac_ref_peer_l2_hdr_type);
				it1 = (*itr).mac_rt_rule_ref.find(mac);
				if(it1 != (*itr).mac_rt_rule_ref.end() && peer_l2_hdr_type == mac_ref_peer_l2_hdr_type)
				{
					if(peer_info->peer->is_spcl_iface())
					{
						mac_found = 1;
						IPACMERR("Only possible in case of siface\n");
					}
					else
					{
						IPACMDBG_H("Already found ref on other peer with same l2 type\n");
						return;
					}
					break;
				}
			}

			/* Only special interface can have same mac address twice, one for eth_to_eth and other for 802_to_eth */
			if(mac_found == 1)
			{
				/* mac address already has rt rules, increase ref cnt and copy rt rules handles for future deletion*/
				(it->second)++;
				IPACMDBG_H("peer iface %s already has rt rule for mac 0x[%X][%X][%X][%X][%X][%X], ref now increases to %d, copy handles:\n",
					peer_info->peer->get_iface_pointer()->dev_name,
					client->mac_addr[0], client->mac_addr[1], client->mac_addr[2], client->mac_addr[3], client->mac_addr[4], client->mac_addr[5],
					it->second);
				/* find rt rule handle and copy handles */
				list<client_info>::iterator it_clients;
				for(it_clients = m_client_info.begin(); it_clients != m_client_info.end(); it_clients++)
				{
					if(memcmp(it_clients->mac_addr, client->mac_addr, sizeof(it_clients->mac_addr)) == 0)
					{
						if(it_clients->vlan_id == client->vlan_id)
						{
							IPACMDBG_H("same client with vid %d, skip\n", client->vlan_id);
							(it->second)--;
							continue;
						}
						num_rt_rule = it_clients->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v4];
						client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v4] = num_rt_rule;
						IPACMDBG_H("Number of IPv4 routing rules to copy is %d.\n", num_rt_rule);
						for(i = 0; i < num_rt_rule; i++)
						{
							IPACMDBG_H("copy IPv4 Routing rule %d handle %d\n", i, it_clients->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v4][i]);
							client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v4][i] = it_clients->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v4][i];
						}

						num_rt_rule = it_clients->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v6];
						client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v6] = num_rt_rule;
						IPACMDBG_H("Number of IPv6 routing rules to copy is %d.\n", num_rt_rule);
						for(i = 0; i < num_rt_rule; i++)
						{
							IPACMDBG_H("copy IPv6 Routing rule %d handle %d\n", i, it_clients->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v6][i]);
							client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v6][i] = it_clients->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v6][i];
						}
						break;
					}
				}
				return;
			}
			/* since this is the first time we see this mac, set ref cnt to 1
			 * next time a vlan client will be added it will only increase the ref count
			 */
			peer_info->mac_rt_rule_ref.insert(std::make_pair(mac, 1));
			IPACMDBG_H("peer iface %s insert rt rule for mac 0x[%X][%X][%X][%X][%X][%X], ref now increases to %d\n",
					peer_info->peer->get_iface_pointer()->dev_name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], it->second);
		}
#endif

		/* Special interface needs to install hpc twice once during handle_iface_up for non-vlan clients
		   and the again here for vlan clients */
		if (m_is_vlan || is_svap_iface() || is_ap_iface_vlan_enabled() || (is_spcl_iface() && client->vlan_id)) {
			IPACMDBG_H("Perform delayed add_hdr_proc_ctx for svap/spcl clients \n");
			add_hdr_proc_ctx_vlan(peer_l2_hdr_type, client->vlan_id);
		}

		IPACMDBG_H("peer iface %s doesn't have rt rule for mac 0x[%X][%X][%X][%X][%X][%X], adding now\n",
			peer_info->peer->get_iface_pointer()->dev_name,
			client->mac_addr[0], client->mac_addr[1], client->mac_addr[2], client->mac_addr[3], client->mac_addr[4], client->mac_addr[5]);

		if (m_is_vlan || is_svap_iface() || is_ap_iface_vlan_enabled() || (is_spcl_iface() && client->vlan_id)) {
			if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
			{
					IPACMDBG_H(" Called from here line. %s if_cat %d\n", m_p_iface->dev_name, m_p_iface->ipa_if_cate);
					if(m_p_iface->ipa_if_cate == WLAN_IF)
					{
						ret = ((IPACM_Wlan *)m_p_iface)->eth_bridge_add_rt_rule_v2(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v4], is_entry_present_wlan_svap_hpc_hdl(client->vlan_id, peer_l2_hdr_type),
							peer_l2_hdr_type, IPA_IP_v4, rt_rule_hdl, &num_rt_rule);
					}
					else
					{
						ret = m_p_iface->eth_bridge_add_rt_rule_v2(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v4], is_entry_present_wlan_svap_hpc_hdl(client->vlan_id, peer_l2_hdr_type),
							peer_l2_hdr_type, IPA_IP_v4, rt_rule_hdl, &num_rt_rule);
					}
			}
			else
			{
				m_p_iface->eth_bridge_add_rt_rule(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v4], is_entry_present_wlan_svap_hpc_hdl(client->vlan_id, peer_l2_hdr_type),
				peer_l2_hdr_type, IPA_IP_v4, rt_rule_hdl, &num_rt_rule);
			}
		}
		else {
			if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
			{
					IPACMDBG_H(" Called from here line. %s if_cat %d\n", m_p_iface->dev_name, m_p_iface->ipa_if_cate);
					if(m_p_iface->ipa_if_cate == WLAN_IF)
					{
						ret = ((IPACM_Wlan *)m_p_iface)->eth_bridge_add_rt_rule_v2(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v4], hdr_proc_ctx_for_inter_interface[peer_l2_hdr_type],
							peer_l2_hdr_type, IPA_IP_v4, rt_rule_hdl, &num_rt_rule);
					}
					else
					{
						ret = m_p_iface->eth_bridge_add_rt_rule_v2(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v4], hdr_proc_ctx_for_inter_interface[peer_l2_hdr_type],
							peer_l2_hdr_type, IPA_IP_v4, rt_rule_hdl, &num_rt_rule);
					}
			}
			else
			{
				m_p_iface->eth_bridge_add_rt_rule(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v4], hdr_proc_ctx_for_inter_interface[peer_l2_hdr_type],
					peer_l2_hdr_type, IPA_IP_v4, rt_rule_hdl, &num_rt_rule);
			}
		}

		client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v4] = num_rt_rule;
		IPACMDBG_H("Number of IPv4 routing rule is %d.\n", num_rt_rule);
		for(i=0; i<num_rt_rule; i++)
		{
			IPACMDBG_H("Routing rule %d handle %d\n", i, rt_rule_hdl[i]);
			client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v4][i] = rt_rule_hdl[i];
		}

		if (m_is_vlan || is_svap_iface() || is_ap_iface_vlan_enabled() || (is_spcl_iface() && client->vlan_id)) {
			if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
			{
					IPACMDBG_H(" Called from here line. %s if_cat %d\n", m_p_iface->dev_name, m_p_iface->ipa_if_cate);
					if(m_p_iface->ipa_if_cate == WLAN_IF)
					{
						ret = ((IPACM_Wlan *)m_p_iface)->eth_bridge_add_rt_rule_v2(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v6], is_entry_present_wlan_svap_hpc_hdl(client->vlan_id, peer_l2_hdr_type),
							peer_l2_hdr_type, IPA_IP_v6, rt_rule_hdl, &num_rt_rule);
					}
					else
					{
						ret = m_p_iface->eth_bridge_add_rt_rule_v2(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v6], is_entry_present_wlan_svap_hpc_hdl(client->vlan_id, peer_l2_hdr_type),
							peer_l2_hdr_type, IPA_IP_v6, rt_rule_hdl, &num_rt_rule);
					}
			}
			else
			{
				m_p_iface->eth_bridge_add_rt_rule(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v6], is_entry_present_wlan_svap_hpc_hdl(client->vlan_id, peer_l2_hdr_type),
				peer_l2_hdr_type, IPA_IP_v6, rt_rule_hdl, &num_rt_rule);
			}
		}
		else {
			if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
			{
					IPACMDBG_H(" Called from here line. %s if_cat %d\n", m_p_iface->dev_name, m_p_iface->ipa_if_cate);
					if(m_p_iface->ipa_if_cate == WLAN_IF)
					{
						ret = ((IPACM_Wlan *)m_p_iface)->eth_bridge_add_rt_rule_v2(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v6], hdr_proc_ctx_for_inter_interface[peer_l2_hdr_type],
							peer_l2_hdr_type, IPA_IP_v6, rt_rule_hdl, &num_rt_rule);
					}
					else
					{
						ret = m_p_iface->eth_bridge_add_rt_rule_v2(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v6], hdr_proc_ctx_for_inter_interface[peer_l2_hdr_type],
							peer_l2_hdr_type, IPA_IP_v6, rt_rule_hdl, &num_rt_rule);
					}
			}
			else
			{
				m_p_iface->eth_bridge_add_rt_rule(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v6], hdr_proc_ctx_for_inter_interface[peer_l2_hdr_type],
					peer_l2_hdr_type, IPA_IP_v6, rt_rule_hdl, &num_rt_rule);
			}
		}

		client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v6] = num_rt_rule;
		IPACMDBG_H("Number of IPv6 routing rule is %d.\n", num_rt_rule);
		for(i=0; i<num_rt_rule; i++)
		{
			IPACMDBG_H("Routing rule %d handle %d\n", i, rt_rule_hdl[i]);
			client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v6][i] = rt_rule_hdl[i];
		}
		if(ret == IPACM_SUCCESS)
		{
			IPACMERR("Successed to construct rt for client mac.\n");
		}
		/* check if failed to construct rt rule for this mac address */
		if(ret == IPACM_FAILURE)
		{
			IPACMERR("Failed to construct rt for client mac.\n");
			del_it = peer_info->mac_rt_rule_ref.find(mac);
			if(del_it == peer_info->mac_rt_rule_ref.end())
			{
				IPACMERR("couldn't find client rt rule ref count, peer %s, mac 0x[%X][%X][%X][%X][%X][%X]\n",
					peer_info->peer->get_iface_pointer()->dev_name,
					client->mac_addr[0], client->mac_addr[1], client->mac_addr[2],
					client->mac_addr[3], client->mac_addr[4], client->mac_addr[5]);
				return;
			}

			IPACMDBG_H("ref count is now %d, peer %s, mac 0x[%X][%X][%X][%X][%X][%X]\n", del_it->second, peer_info->peer->get_iface_pointer()->dev_name,
				client->mac_addr[0], client->mac_addr[1], client->mac_addr[2],
				client->mac_addr[3], client->mac_addr[4], client->mac_addr[5]);
			(del_it->second)--;
			IPACMDBG_H("reduce to %d", del_it->second);
			if(del_it->second)
			{
				IPACMDBG_H("ref count still positive, don't delete rt rules\n");
				return;
			}

			peer_info->mac_rt_rule_ref.erase(del_it);
		}
	}
	else
	{
		IPACMDBG_H("This is for intra interface communication for client"
			"wih mac 0x[%X][%X][%X][%X][%X][%X] vlan_id: %d\n",
			client->mac_addr[0], client->mac_addr[1], client->mac_addr[2], client->mac_addr[3],
			client->mac_addr[4], client->mac_addr[5], client->vlan_id);

		if(IPACM_Iface::ipacmcfg->multi_vlan_bridge_config_enable == 0 && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
		{
			IPACMDBG_H("This is for intra interface communication.\n");
			m_p_iface->eth_bridge_add_rt_rule(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v4],
				hdr_proc_ctx_for_intra_interface, peer_l2_hdr_type,
				IPA_IP_v4, rt_rule_hdl, &num_rt_rule);

			client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v4] = num_rt_rule;
			IPACMDBG_H("Number of IPv4 routing rule is %d.\n", num_rt_rule);
			for(i=0; i<num_rt_rule; i++)
			{
				IPACMDBG_H("Routing rule %d handle %d\n", i, rt_rule_hdl[i]);
				client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v4][i] = rt_rule_hdl[i];
			}

			m_p_iface->eth_bridge_add_rt_rule(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v6],
				hdr_proc_ctx_for_intra_interface, peer_l2_hdr_type,
				IPA_IP_v6, rt_rule_hdl, &num_rt_rule);

			client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v6] = num_rt_rule;
			IPACMDBG_H("Number of IPv6 routing rule is %d.\n", num_rt_rule);
			for(i=0; i<num_rt_rule; i++)
			{
				IPACMDBG_H("Routing rule %d handle %d\n", i, rt_rule_hdl[i]);
				client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v6][i] = rt_rule_hdl[i];
			}
		}
		else if(IPACM_Iface::ipacmcfg->multi_vlan_bridge_config_enable == 1 && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
		{
			m_p_iface->eth_bridge_add_hdr_proc_ctx(m_p_iface->tx_prop->tx[0].hdr_l2_type,
				&hdr_proc_ctx_hdl, client->vlan_id);
			client->hdr_proc_ctx_intra_interface = hdr_proc_ctx_hdl;
			IPACMDBG_H("Hdr proc ctx for intra-interface communication hdl: %d\n", hdr_proc_ctx_hdl);

			m_p_iface->eth_bridge_add_rt_rule(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v4],
				client->hdr_proc_ctx_intra_interface,
				peer_l2_hdr_type, IPA_IP_v4, rt_rule_hdl, &num_rt_rule);

			client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v4] = num_rt_rule;
			IPACMDBG_H("Number of IPv4 routing rule is %d.\n", num_rt_rule);
			for(i=0; i<num_rt_rule; i++)
			{
				IPACMDBG_H("Routing rule %d handle %d\n", i, rt_rule_hdl[i]);
				client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v4][i] = rt_rule_hdl[i];
			}

			m_p_iface->eth_bridge_add_rt_rule(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v6],
				client->hdr_proc_ctx_intra_interface,
				peer_l2_hdr_type, IPA_IP_v6, rt_rule_hdl, &num_rt_rule);

			client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v6] = num_rt_rule;
			IPACMDBG_H("Number of IPv6 routing rule is %d.\n", num_rt_rule);
			for(i=0; i<num_rt_rule; i++)
			{
				IPACMDBG_H("Routing rule %d handle %d\n", i, rt_rule_hdl[i]);
				client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v6][i] = rt_rule_hdl[i];
			}
		}
	}

	return;
}

#ifdef FEATURE_L2TP
void IPACM_LanToLan_Iface::add_l2tp_client_rt_rule(peer_iface_info *peer, client_info *client)
{
	ipa_hdr_l2_type peer_l2_hdr_type;
	l2tp_vlan_mapping_info *mapping_info;

	peer_l2_hdr_type = peer->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
	mapping_info = client->mapping_info;
	if(client->is_l2tp_client)
	{
#ifdef IPA_L2TP_TUNNEL_UDP
		if (mapping_info->tunnel_type == IPA_L2TP_TUNNEL_IP)
		{
#endif
			m_p_iface->add_l2tp_rt_rule(IPA_IP_v4, client->mac_addr, peer_l2_hdr_type, mapping_info->l2tp_session_id,
				mapping_info->vlan_id, mapping_info->vlan_client_mac, mapping_info->vlan_iface_ipv6_addr,
				mapping_info->vlan_client_ipv6_addr, &client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_hdr_hdl,
				&client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_hdr_proc_ctx_hdl[IPA_IP_v4], &client->l2tp_rt_rule_hdl[peer_l2_hdr_type].second_pass_hdr_hdl,
				&client->l2tp_rt_rule_hdl[peer_l2_hdr_type].num_rt_hdl[IPA_IP_v4], client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_rt_rule_hdl[IPA_IP_v4],
				client->l2tp_rt_rule_hdl[peer_l2_hdr_type].second_pass_rt_rule_hdl);

			m_p_iface->add_l2tp_rt_rule(IPA_IP_v6, client->mac_addr, peer_l2_hdr_type, mapping_info->l2tp_session_id,
				mapping_info->vlan_id, mapping_info->vlan_client_mac, mapping_info->vlan_iface_ipv6_addr,
				mapping_info->vlan_client_ipv6_addr, &client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_hdr_hdl,
				&client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_hdr_proc_ctx_hdl[IPA_IP_v6], &client->l2tp_rt_rule_hdl[peer_l2_hdr_type].second_pass_hdr_hdl,
				&client->l2tp_rt_rule_hdl[peer_l2_hdr_type].num_rt_hdl[IPA_IP_v6], client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_rt_rule_hdl[IPA_IP_v6],
				client->l2tp_rt_rule_hdl[peer_l2_hdr_type].second_pass_rt_rule_hdl);
#ifdef IPA_L2TP_TUNNEL_UDP
		}
		else
		{
			/* For L2TP over UDP, tunneling happens in single pass. */
			m_p_iface->add_l2tp_udp_rt_rule(IPA_IP_v4, client->mac_addr,
				peer_l2_hdr_type,mapping_info->tunnel_type, mapping_info->l2tp_session_id,
				mapping_info->src_port, mapping_info->dst_port, mapping_info->vlan_id,
				mapping_info->vlan_client_mac, mapping_info->vlan_iface_ipv6_addr,
				mapping_info->vlan_client_ipv6_addr, &client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_hdr_hdl,
				&client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_hdr_proc_ctx_hdl[IPA_IP_v4],
				&client->l2tp_rt_rule_hdl[peer_l2_hdr_type].num_rt_hdl[IPA_IP_v4],
				client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_rt_rule_hdl[IPA_IP_v4]);

			m_p_iface->add_l2tp_udp_rt_rule(IPA_IP_v6, client->mac_addr,
				peer_l2_hdr_type,mapping_info->tunnel_type,
				mapping_info->l2tp_session_id,
				mapping_info->src_port,mapping_info->dst_port,
				mapping_info->vlan_id, mapping_info->vlan_client_mac,
				mapping_info->vlan_iface_ipv6_addr,
				mapping_info->vlan_client_ipv6_addr, &client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_hdr_hdl,
				&client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_hdr_proc_ctx_hdl[IPA_IP_v6],
				&client->l2tp_rt_rule_hdl[peer_l2_hdr_type].num_rt_hdl[IPA_IP_v6],
				client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_rt_rule_hdl[IPA_IP_v6]);
		}
#endif
	}
	else
	{
#ifdef IPA_L2TP_TUNNEL_UDP
		if(IPACM_LanToLan::get_instance()->has_l2tp_iface() == true)
		{
			m_p_iface->add_l2tp_udp_rt_rule(IPA_IP_v6, client->mac_addr, &hdr_proc_ctx_for_l2tp, &client->l2tp_rt_rule_hdl[peer_l2_hdr_type].num_rt_hdl[IPA_IP_v6],
				client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_rt_rule_hdl[IPA_IP_v6]);
		}
#else
		if(IPACM_LanToLan::get_instance()->has_l2tp_iface() == true)
		{
			m_p_iface->add_l2tp_rt_rule(IPA_IP_v6, client->mac_addr, &hdr_proc_ctx_for_l2tp, &client->l2tp_rt_rule_hdl[peer_l2_hdr_type].num_rt_hdl[IPA_IP_v6],
				client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_rt_rule_hdl[IPA_IP_v6]);
		}
#endif
	}
	return;
}

#ifdef IPA_L2TP_TUNNEL_UDP
void IPACM_LanToLan_Iface::add_l2tp_udp_client_rules_new_mapping(peer_iface_info *peer, l2tp_vlan_mapping_info *mapping_info)
{
	uint32_t l2tp_flt_rule_hdl = 0;
	list<flt_rule_info>::iterator it_flt;

	IPACMDBG_H("Add rules for the peer clients with new mapping.\n");
	/* If in case WLAN client comes up first than L2TP client. We need to ensure L2TP rules are created. */
	for(it_flt = peer->flt_rule.begin(); it_flt != peer->flt_rule.end(); it_flt++)
	{
		IPACMDBG_H("Update l2tp rules for the client with..\n");
		IPACMDBG_H("MAC: 0x%02x%02x%02x%02x%02x%02x Pointer: 0x%08x\n", it_flt->p_client->mac_addr[0], it_flt->p_client->mac_addr[1],
			it_flt->p_client->mac_addr[2], it_flt->p_client->mac_addr[3], it_flt->p_client->mac_addr[4], it_flt->p_client->mac_addr[5], &(*it_flt->p_client));

		m_p_iface->add_l2tp_udp_flt_rule(it_flt->p_client->mac_addr,
			mapping_info->vlan_iface_ipv6_addr, mapping_info->vlan_client_ipv6_addr,
			mapping_info->dst_port, mapping_info->src_port,
			&l2tp_flt_rule_hdl);
			it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.push_front(l2tp_flt_rule_hdl);
			IPACMDBG_H("Added IPv6 flt rule %d.\n", l2tp_flt_rule_hdl);
	}

	return;
}
#endif
#endif

#ifdef FEATURE_VLAN_MPDN
void IPACM_LanToLan_Iface::add_all_inter_interface_client_flt_rule_one_vlan_id(ipa_ip_type iptype, uint16_t vlan_id)
{
	list<peer_iface_info>::iterator it_iface;
	list<client_info>::iterator it_client;

	/* go over all peers (must be vlan interfaces) */
	for(it_iface = m_peer_iface_info.begin(); it_iface != m_peer_iface_info.end(); it_iface++)
	{
		IPACMDBG_H("Add flt rules for clients of interface %s.\n", it_iface->peer->get_iface_pointer()->dev_name);

		/* look for specific client with this vlan id */
		for(it_client = it_iface->peer->m_client_info.begin(); it_client != it_iface->peer->m_client_info.end(); it_client++)
		{
			if ((vlan_id == it_client->vlan_id) || ((IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 2) && (it_iface->peer->get_m_support_inter_iface_offload())))
				add_client_flt_rule(&(*it_iface), &(*it_client), iptype);
		}
	}
}

void IPACM_LanToLan_Iface::del_all_inter_interface_client_flt_rule_one_vlan_id(uint16_t vlan_id)
{
	list<peer_iface_info>::iterator it_iface;
	list<client_info>::iterator it_client;

	/* go over all peers (must be vlan interfaces) */
	for(it_iface = m_peer_iface_info.begin(); it_iface != m_peer_iface_info.end(); it_iface++)
	{
		IPACMDBG_H("del flt rules for clients of interface %s with vlan id %d.\n", it_iface->peer->get_iface_pointer()->dev_name, vlan_id);

		/* look for specific client with this vlan id */
		for(it_client = it_iface->peer->m_client_info.begin(); it_client != it_iface->peer->m_client_info.end(); it_client++)
		{
			if(vlan_id == it_client->vlan_id)
				del_client_flt_rule(&(*it_iface), &(*it_client));
		}
	}
}
#endif

void IPACM_LanToLan_Iface::add_inter_interface_client_flt_rule_v2( IPACM_LanToLan_Iface *new_iface, ipa_ip_type iptype, uint16_t *Ids)
{
	list<peer_iface_info>::iterator it_iface;
	list<client_info>::iterator it_client;
	uint16_t vIds[IPA_MAX_NUM_OFFLOAD_VLANS];
	int i;
	struct ipa_bridge_vlan_mapping_info this_bridge_info, new_iface_bridge_info;
	char vlan_dev_name[IPA_RESOURCE_NAME_MAX] = {'\0'};
	char new_vlan_dev_name[IPA_RESOURCE_NAME_MAX] = {'\0'};
	client_info inter_client;


	IPACMDBG_H("Lan2Lan_v2:  This dev_name %s, has number of client %d\n", this->get_iface_pointer()->dev_name, this->m_client_info.size());
	if (new_iface == NULL)
	{
		IPACMERR("new_iface is Invalid\n");
		return;
	}
#ifdef FEATURE_VLAN_MPDN
	if(m_is_vlan && !Ids)
	{
		IPACMERR("vlan iface and no Ids array\n", m_is_vlan);
		return;
	}
	IPACMDBG_H("m_is_vlan %d, Print vlan id if any!\n", m_is_vlan);
	if(Ids != NULL)
	{
		for(i=0; i<IPA_MAX_NUM_OFFLOAD_VLANS; i++)
		{
			IPACMDBG_H("Ids %d\n",Ids[i]);
		}
	}
#endif

	for(it_client = this->m_client_info.begin(); it_client != this->m_client_info.end(); it_client++)
	{
		IPACMDBG_H("client MAC: 0x%02x%02x%02x%02x%02x%02x of interface: %s\n",
		it_client->mac_addr[0], it_client->mac_addr[1],
		it_client->mac_addr[2], it_client->mac_addr[3],
		it_client->mac_addr[4], it_client->mac_addr[5],
		this->get_iface_pointer()->dev_name);

		IPACMDBG_H("Get bridge info for this %s and new_iface %s \n", this->get_iface_pointer()->dev_name, new_iface->get_iface_pointer()->dev_name);
		IPACMDBG_H("m_is_vlan %d, new_iface in vlan mode %d \n", m_is_vlan, IPACM_Iface::ipacmcfg->iface_in_vlan_mode(new_iface->get_iface_pointer()->dev_name));

		/* if this is non-vlan and new_iface is vlan then enable inter_bridge */
		if(!this->m_is_vlan && IPACM_Iface::ipacmcfg->iface_in_vlan_mode(new_iface->get_iface_pointer()->dev_name))
		{
			/* Get bridge info fo this */
			if (IPACM_Iface::ipacmcfg->get_bridge_info_iface(this->get_iface_pointer()->dev_name, &this_bridge_info) != IPACM_SUCCESS)
			{
				/*if this is wlan if try to get the mld details*/
				if(IPACM_Iface::ipacmcfg->get_iface_category(this->get_iface_pointer()->dev_name) == WLAN_IF)
				{
					if(IPACM_Iface::ipacmcfg->get_bridge_info_iface_wlan_mld(this->get_iface_pointer()->dev_name, &this_bridge_info) != IPACM_SUCCESS)
					{
						IPACMERR("failed to query mld bridge details\n");
						return;
					}
				}
				else
				{
					IPACMERR("Failed to query bridge info for iface %s \n",this->get_iface_pointer()->dev_name);
					return;
				}
			}
			IPACMDBG_H(" This iface %s has bridge name %s \n", this->get_iface_pointer()->dev_name, this_bridge_info.bridge_name);

			/* Get bridge info fo new iface */
			if(Ids)
			{
				for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
				{
					if(Ids[i] != 0)
					{
						IPACMDBG_H("vlan id %d \n", Ids[i]);
						snprintf(vlan_dev_name,IPA_RESOURCE_NAME_MAX,"%s%s%d",new_iface->get_iface_pointer()->dev_name,".",Ids[i]);

						if (IPACM_Iface::ipacmcfg->get_bridge_info_iface(vlan_dev_name, &new_iface_bridge_info) != IPACM_SUCCESS)
						{
							/*if this is wlan if try to get the mld details*/
							if(IPACM_Iface::ipacmcfg->get_iface_category(new_iface->get_iface_pointer()->dev_name) == WLAN_IF)
							{
								if(IPACM_Iface::ipacmcfg->get_bridge_info_iface_wlan_mld(vlan_dev_name, &new_iface_bridge_info) != IPACM_SUCCESS)
								{
									IPACMERR("failed to query mld bridge details\n");
									return;
								}
							}
							else
							{
								IPACMERR("Failed to query bridge info for iface %s \n",vlan_dev_name);
								return;
							}
						}
						IPACMDBG_H(" New iface %s has bridge name %s \n", vlan_dev_name, new_iface_bridge_info.bridge_name);
					}
					if(Ids[i] == 0)
						break;
				}
			}
			/* Compare if need to install Inter bridge rule */
			if(memcmp(this_bridge_info.bridge_name, new_iface_bridge_info.bridge_name, IPA_RESOURCE_NAME_MAX) == 0)
			{
				IPACMDBG_H(" No Need of Inter bridge flt rule \n");
			}
			else
			{
				IPACMDBG_H("******************INSTALL INTER BRIDGE RULE***************************\n");
				IPACMDBG_H(" Install Inter bridge offload flt rule on self for new client with dest subnet\n");
				memset(&inter_client, 0, sizeof(inter_client));
				memcpy(inter_client.mac_addr, it_client->mac_addr, sizeof(inter_client.mac_addr));
				inter_client.vlan_id = 0;
				inter_client.bridge_ipv4 = new_iface_bridge_info.bridge_ipv4 ;
				inter_client.subnet_mask = new_iface_bridge_info.subnet_mask;
				add_client_flt_rule(&self, &inter_client, IPA_IP_v4, true);
			}
		}

		/* if this is vlan and new_iface is non-vlan then enable inter_bridge */
		if(this->m_is_vlan && !IPACM_Iface::ipacmcfg->iface_in_vlan_mode(new_iface->get_iface_pointer()->dev_name))
		{
			/* Get bridge vids info for this */
			if(IPACM_Iface::ipacmcfg->get_iface_vlan_ids(this->get_iface_pointer()->dev_name, vIds))
			{
				IPACMERR("failed getting vlan ids for iface %s\n", this->get_iface_pointer()->dev_name);
				return;
			}

			/* Get bridge info fo this */
			for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
			{
				if(vIds[i] != 0)
				{
					IPACMDBG_H("vlan id %d \n", Ids[i]);
					snprintf(vlan_dev_name,IPA_RESOURCE_NAME_MAX,"%s%s%d",this->get_iface_pointer()->dev_name,".",Ids[i]);

					if (IPACM_Iface::ipacmcfg->get_bridge_info_iface(vlan_dev_name, &this_bridge_info) != IPACM_SUCCESS)
					{
						/*if this is wlan if try to get the mld details*/
						if(IPACM_Iface::ipacmcfg->get_iface_category(this->get_iface_pointer()->dev_name) == WLAN_IF)
						{
							if(IPACM_Iface::ipacmcfg->get_bridge_info_iface_wlan_mld(vlan_dev_name, &this_bridge_info) != IPACM_SUCCESS)
							{
								IPACMERR("failed to query mld bridge details\n");
								return;
							}
						}
						else
						{
							IPACMERR("Failed to query bridge info for iface %s \n",vlan_dev_name);
							return;
						}
					}
					IPACMDBG_H(" This iface %s has bridge name %s \n", vlan_dev_name, this_bridge_info.bridge_name);
				}
				if(vIds[i] == 0)
					break;
			}

			if (IPACM_Iface::ipacmcfg->get_bridge_info_iface(new_iface->get_iface_pointer()->dev_name, &new_iface_bridge_info) != IPACM_SUCCESS)
			{
				/*if this is wlan if try to get the mld details*/
				if(IPACM_Iface::ipacmcfg->get_iface_category(new_iface->get_iface_pointer()->dev_name) == WLAN_IF)
				{
					if(IPACM_Iface::ipacmcfg->get_bridge_info_iface_wlan_mld(new_iface->get_iface_pointer()->dev_name, &new_iface_bridge_info) != IPACM_SUCCESS)
					{
						IPACMERR("failed to query mld bridge details\n");
						return;
					}
				}
				else
				{
					IPACMERR("Failed to query bridge info for iface %s \n",new_iface->get_iface_pointer()->dev_name);
					return;
				}
			}
			IPACMDBG_H(" New iface %s has bridge name %s \n", new_iface->get_iface_pointer()->dev_name, new_iface_bridge_info.bridge_name);

			/* Compare if need to install Inter bridge rule */
			if(memcmp(this_bridge_info.bridge_name, new_iface_bridge_info.bridge_name, IPA_RESOURCE_NAME_MAX) == 0)
			{
				IPACMDBG_H(" No Need of Inter bridge flt rule \n");
			}
			else
			{
				IPACMDBG_H("******************INSTALL INTER BRIDGE RULE***************************\n");
				IPACMDBG_H(" Install Inter bridge offload flt rule on self for new client with dest subnet\n");
				memset(&inter_client, 0, sizeof(inter_client));
				memcpy(inter_client.mac_addr, it_client->mac_addr, sizeof(inter_client.mac_addr));
				inter_client.vlan_id = vIds[i-1];
				inter_client.bridge_ipv4 = new_iface_bridge_info.bridge_ipv4 ;
				inter_client.subnet_mask = new_iface_bridge_info.subnet_mask;
				add_client_flt_rule(&self, &inter_client, IPA_IP_v4, true);
			}
		}

		/* if this is vlan and new_iface is vlan then enable inter_bridge */
		if(this->m_is_vlan && IPACM_Iface::ipacmcfg->iface_in_vlan_mode(new_iface->get_iface_pointer()->dev_name))
		{
			/*Get bridge info fo this*/
			if(IPACM_Iface::ipacmcfg->get_iface_vlan_ids(this->get_iface_pointer()->dev_name, vIds))
			{
				IPACMERR("failed getting vlan ids for iface %s\n", this->get_iface_pointer()->dev_name);
				return;
			}

			for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
			{
				if(vIds[i] != 0)
				{
					IPACMDBG_H("vlan id %d \n", Ids[i]);
					snprintf(vlan_dev_name,IPA_RESOURCE_NAME_MAX,"%s%s%d",this->get_iface_pointer()->dev_name,".",Ids[i]);

					if (IPACM_Iface::ipacmcfg->get_bridge_info_iface(vlan_dev_name, &this_bridge_info) != IPACM_SUCCESS)
					{
						/*if this is wlan if try to get the mld details*/
						if(IPACM_Iface::ipacmcfg->get_iface_category(this->get_iface_pointer()->dev_name) == WLAN_IF)
						{
							if(IPACM_Iface::ipacmcfg->get_bridge_info_iface_wlan_mld(vlan_dev_name, &this_bridge_info) != IPACM_SUCCESS)
							{
								IPACMERR("failed to query mld bridge details\n");
								return;
							}
						}
						else
						{
							IPACMERR("Failed to query bridge info for iface %s \n",vlan_dev_name);
							return;
						}
					}
					IPACMDBG_H(" This iface %s has bridge name %s \n", vlan_dev_name, this_bridge_info.bridge_name);
				}
				if(vIds[i] == 0)
					break;
			}

			/*Get bridge info fo new iface*/
			if(Ids)
			{
				for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
				{
					if(Ids[i] != 0)
					{
						IPACMDBG_H("vlan id %d \n", Ids[i]);
						snprintf(vlan_dev_name,IPA_RESOURCE_NAME_MAX,"%s%s%d",new_iface->get_iface_pointer()->dev_name,".",Ids[i]);

						if (IPACM_Iface::ipacmcfg->get_bridge_info_iface(vlan_dev_name, &new_iface_bridge_info) != IPACM_SUCCESS)
						{
							/*if this is wlan if try to get the mld details*/
							if(IPACM_Iface::ipacmcfg->get_iface_category(new_iface->get_iface_pointer()->dev_name) == WLAN_IF)
							{
								if(IPACM_Iface::ipacmcfg->get_bridge_info_iface_wlan_mld(vlan_dev_name, &new_iface_bridge_info) != IPACM_SUCCESS)
								{
									IPACMERR("failed to query mld bridge details\n");
									return;
								}
							}
							else
							{
								IPACMERR("Failed to query bridge info for iface %s \n",vlan_dev_name);
								return;
							}
						}
						IPACMDBG_H(" New iface %s has bridge name %s \n", vlan_dev_name, new_iface_bridge_info.bridge_name);
					}
					if(Ids[i] == 0)
						break;
				}
			}
			/* Compare if need to install Inter bridge rule*/
			if(memcmp(this_bridge_info.bridge_name, new_iface_bridge_info.bridge_name, IPA_RESOURCE_NAME_MAX) == 0)
			{
				IPACMDBG_H(" No Need of Inter bridge flt rule \n");
			}
			else
			{
				IPACMDBG_H("******************INSTALL INTER BRIDGE RULE***************************\n");
				IPACMDBG_H(" Install Inter bridge offload flt rule on self for new client with dest subnet\n");
				memset(&inter_client, 0, sizeof(inter_client));
				memcpy(inter_client.mac_addr, it_client->mac_addr, sizeof(inter_client.mac_addr));
				inter_client.vlan_id = vIds[i-1];
				inter_client.bridge_ipv4 = new_iface_bridge_info.bridge_ipv4 ;
				inter_client.subnet_mask = new_iface_bridge_info.subnet_mask;
				add_client_flt_rule(&self, &inter_client, IPA_IP_v4, true);
			}
		}

		/* if this is non-vlan and new_iface is non-vlan then not to enable inter_bridge */
		if(!this->m_is_vlan && !IPACM_Iface::ipacmcfg->iface_in_vlan_mode(new_iface->get_iface_pointer()->dev_name))
		{
			/* Get bridge info for this */
				if (IPACM_Iface::ipacmcfg->get_bridge_info_iface(this->get_iface_pointer()->dev_name, &this_bridge_info) != IPACM_SUCCESS)
				{
					/*if this is wlan if try to get the mld details*/
					if(IPACM_Iface::ipacmcfg->get_iface_category(this->get_iface_pointer()->dev_name) == WLAN_IF)
					{
						if(IPACM_Iface::ipacmcfg->get_bridge_info_iface_wlan_mld(this->get_iface_pointer()->dev_name, &this_bridge_info) != IPACM_SUCCESS)
						{
							IPACMERR("failed to query mld bridge details\n");
							return;
						}
					}
					else
					{
						IPACMERR("Failed to query bridge info for iface %s \n",this->get_iface_pointer()->dev_name);
						return;
					}
				}
				IPACMDBG_H(" This iface %s has bridge name %s \n", this->get_iface_pointer()->dev_name, this_bridge_info.bridge_name);
				/* Get bridge info for this new_iface */
				if (IPACM_Iface::ipacmcfg->get_bridge_info_iface(new_iface->get_iface_pointer()->dev_name, &new_iface_bridge_info) != IPACM_SUCCESS)
				{
					/*if this is wlan if try to get the mld details*/
					if(IPACM_Iface::ipacmcfg->get_iface_category(new_iface->get_iface_pointer()->dev_name) == WLAN_IF)
					{
						if(IPACM_Iface::ipacmcfg->get_bridge_info_iface_wlan_mld(new_iface->get_iface_pointer()->dev_name, &new_iface_bridge_info) != IPACM_SUCCESS)
						{
							IPACMERR("failed to query mld bridge details\n");
							return;
						}
					}
					else
					{
						IPACMERR("Failed to query bridge info for iface %s \n",new_iface->get_iface_pointer()->dev_name);
						return;
					}
				}
				IPACMDBG_H(" New iface %s has bridge name %s \n", new_iface->get_iface_pointer()->dev_name, new_iface_bridge_info.bridge_name);
				if(memcmp(this_bridge_info.bridge_name, new_iface_bridge_info.bridge_name, IPA_RESOURCE_NAME_MAX) == 0)
				{
					IPACMDBG_H("Both are on Same bridge : No Need of Inter bridge flt rule.\n");
					IPACMDBG_H(" No Need of Inter bridge flt rule \n");
				}
		}
	}
	return;
}

void IPACM_LanToLan_Iface::add_all_inter_interface_client_flt_rule(ipa_ip_type iptype, uint16_t *Ids)
{
	list<peer_iface_info>::iterator it_iface;
	list<client_info>::iterator it_client;
#ifdef FEATURE_VLAN_MPDN
	if(m_is_vlan && !Ids)
	{
		IPACMERR("vlan iface and no Ids array\n");
		return;
	}
#endif
	for(it_iface = m_peer_iface_info.begin(); it_iface != m_peer_iface_info.end(); it_iface++)
	{
		IPACMDBG_H("Add flt rules for clients of interface %s.\n", it_iface->peer->get_iface_pointer()->dev_name);
		for(it_client = it_iface->peer->m_client_info.begin(); it_client != it_iface->peer->m_client_info.end(); it_client++)
		{
#ifdef FEATURE_VLAN_MPDN
			if(Ids)
			{
				int i;
				for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
				{
					if(Ids[i] == it_client->vlan_id)
					{
						IPACMDBG_H("vlan id %d match\n", Ids[i]);
						break;
					}
				}

				/* iface VLAN IDs does not match the client vlan id */
				if(i >= IPA_MAX_NUM_OFFLOAD_VLANS)
				{
					IPACMDBG("no match for vlan id %d\n", it_client->vlan_id);
					continue;
				}
			}
#endif
			if (it_iface->peer->is_spcl_iface() && ((it_client->vlan_id != 0) != it_iface->is_vlan_peer))
			{
				IPACMDBG_H("Client has hdr type %d vlan id %d, is_vlan_peer %d continue ...\n", it_iface->peer_hdr_type, it_client->vlan_id, it_iface->is_vlan_peer);
				continue;
			}
			add_client_flt_rule(&(*it_iface), &(*it_client), iptype);
		}
	}
	return;
}

void IPACM_LanToLan_Iface::add_all_intra_interface_client_flt_rule(ipa_ip_type iptype)
{
	list<client_info>::iterator it_client;

	IPACMDBG_H("Add flt rules for own clients.\n");
	for(it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
	{
		add_client_flt_rule(&m_intra_interface_info, &(*it_client), iptype);
	}

	return;
}

static bool l2_hdr_is_802_1Q(int type) {
    return type == IPA_HDR_L2_802_1Q || type == IPA_HDR_L2_802_1Q_AST;
}

static bool l2_hdr_is_ethernet_II(int type) {
    return type == IPA_HDR_L2_ETHERNET_II || type == IPA_HDR_L2_ETHERNET_II_AST;
}
void IPACM_LanToLan_Iface::add_one_client_flt_rule(IPACM_LanToLan_Iface *peer_iface, client_info *client,ipa_hdr_l2_type l2_hdr_type)
{
	list<peer_iface_info>::iterator it;

	for(it = m_peer_iface_info.begin(); it != m_peer_iface_info.end(); it++)
	{
		if (it->peer == peer_iface)
		{
			if (client->vlan_id &&
				it->peer->is_spcl_iface() && !it->is_vlan_peer) {
				IPACMDBG_H("Client has hdr type %d vlan id %d, is_vlan_peer %d continue ...\n", it->peer_hdr_type, client->vlan_id, it->is_vlan_peer);
				continue;
			}
			if (is_spcl_iface() && ((l2_hdr_is_802_1Q(l2_hdr_type) && l2_hdr_is_ethernet_II(it->eth_vlan_instance)) ||
									(l2_hdr_is_ethernet_II(l2_hdr_type) && l2_hdr_is_802_1Q(it->eth_vlan_instance))))
			{
				IPACMDBG_H("siface %d find the correct l2 type peer %d\n",l2_hdr_type,it->eth_vlan_instance);
				continue;
			}
			IPACMDBG_H("Found the peer iface info.\n");
			if(m_is_ip_addr_assigned[IPA_IP_v4])
			{
				add_client_flt_rule(&(*it), client, IPA_IP_v4);
			}
			if(m_is_ip_addr_assigned[IPA_IP_v6])
			{
				add_client_flt_rule(&(*it), client, IPA_IP_v6);
			}

			break;
		}
	}
	return;
}

int IPACM_LanToLan_Iface::add_client_flt_rule(peer_iface_info *peer, client_info *client, ipa_ip_type iptype, bool inter_bridge)
{
	list<flt_rule_info>::iterator it_flt;
	//list<flt_rule_info>::iterator inter_it_flt;
	struct flt_rule_hdl_interbridge it_intr_brg_flt_rule;
	list<client_info>::iterator it;
	uint32_t flt_rule_hdl = 0, l2tp_flt_rule_hdl = 0, l2tp_second_pass_flt_rule_hdl = 0;
	list<uint32_t> flt_rule_hdls = std::list<uint32_t>();
	flt_rule_info new_flt_info = {0};
	ipa_ioc_get_rt_tbl rt_tbl;
	list<peer_iface_info>::iterator it_peer;
	int ret = 0, pipe_idx_siface = 0;
	struct ipa_bridge_vlan_mapping_info peer_bridge_info;

	if(m_is_l2tp_iface && iptype == IPA_IP_v4)
	{
		IPACMDBG_H("No need to install IPv4 flt rule on l2tp interface.\n");
		return IPACM_SUCCESS;
	}

	if (!peer || !peer->peer || !client) {
		IPACMDBG_H("Invalid peer or client info\n");
		return IPACM_FAILURE;
	}
	IPACMDBG_H("m_is_vlan: %d \n", m_is_vlan);
	IPACMDBG_H("iptype: %d \n", iptype);
	IPACMDBG_H("client_vlan_id: %d\n", client->vlan_id);
	IPACMDBG_H("m_p_iface->dev_name: %s\n", m_p_iface->dev_name);

	for(it_flt = peer->flt_rule.begin(); it_flt != peer->flt_rule.end(); it_flt++)
	{
		if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
		{
			if((memcmp(it_flt->p_client->mac_addr, client->mac_addr, sizeof(it_flt->p_client->mac_addr)) == 0) &&
				client->vlan_id == it_flt->p_client->vlan_id)	//the client is already in the flt info list
			{
				IPACMDBG_H("Lan2Lan_v2: The client is found in flt info list.\n");
				break;
			}
		}
		else
		{
			if(it_flt->p_client == client)	//the client is already in the flt info list
			{
				IPACMDBG_H("The client is found in flt info list.\n");
				break;
			}
		}
	}
#ifdef FEATURE_VLAN_MPDN
	if(m_is_vlan)
	{
		if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
		{
			if(iptype == IPA_IP_v6)
			{
				if(it_flt != peer->flt_rule.end())
				{
					if (it_flt->flt_rule_hdl[iptype] && !is_spcl_iface() &&
						((it_flt->ipv6_prefix[0] == client->ipv6_prefix[0]) && (it_flt->ipv6_prefix[1] == client->ipv6_prefix[1])) &&
						(client->vlan_id == it_flt->p_client->vlan_id)) {
						IPACMDBG_H("Lan2Lan_v2: not adding rule for already found client 0x[%X][%X][%X][%X][%X][%X] vlan %d, iptype %d\n",
							it_flt->p_client->mac_addr[0], it_flt->p_client->mac_addr[1], it_flt->p_client->mac_addr[2],
							it_flt->p_client->mac_addr[3], it_flt->p_client->mac_addr[4], it_flt->p_client->mac_addr[5],
							it_flt->p_client->vlan_id, iptype);
						return IPACM_SUCCESS;
					}

					IPACMDBG_H("Lan2Lan_v2: flt rule is already present for other iptype (not %d), continue\n", iptype);
				}
			}
			else
			{
				IPACMDBG_H("Lan2Lan_v2: flt rule is already present for other iptype (not %d), continue\n", iptype);
			}
		}
		else
		{
			if(it_flt != peer->flt_rule.end())
			{
				if (it_flt->flt_rule_hdl[iptype] && !is_spcl_iface()) {
					IPACMDBG_H("not adding rule for already found client 0x[%X][%X][%X][%X][%X][%X] vlan %d, iptype %d\n",
						it_flt->p_client->mac_addr[0], it_flt->p_client->mac_addr[1], it_flt->p_client->mac_addr[2],
						it_flt->p_client->mac_addr[3], it_flt->p_client->mac_addr[4], it_flt->p_client->mac_addr[5],
						it_flt->p_client->vlan_id, iptype);
					return IPACM_SUCCESS;
				}

				IPACMDBG_H("flt rule is already present for other iptype (not %d), continue\n", iptype);
			}
		}

		uint16_t Ids[IPA_MAX_NUM_OFFLOAD_VLANS];

		if(IPACM_Iface::ipacmcfg->get_iface_vlan_ids(get_iface_pointer()->dev_name, Ids))
		{
			IPACMERR("failed getting vlan ids for iface %s\n", get_iface_pointer()->dev_name);
			return IPACM_FAILURE;
		}

		int i;
		/* To avoid the vlan id 0 validations.*/
		if (client->vlan_id != 0)
		{
			for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
			{
				if(Ids[i] == client->vlan_id)
				{
					IPACMDBG_H("found vlan Id %d for dev %s, adding vlan client flt rule\n", Ids[i], get_iface_pointer()->dev_name);
					break;
				}
			}
			if(i >= IPA_MAX_NUM_OFFLOAD_VLANS)
			{
				IPACMDBG_H("client vlan Id %d doesn't match with iface %s VLAN ID list\n", client->vlan_id, get_iface_pointer()->dev_name);
				return IPACM_FAILURE;
			}
		}
	}
	IPACMDBG_H("This is m_p_iface %s m_is_vlan %d inter_bridge %d \n", m_p_iface->dev_name, m_is_vlan, inter_bridge);
#endif //FEATURE_VLAN_MPDN
	if(it_flt != peer->flt_rule.end())
	{
		flt_rule_hdls = it_flt->l2tp_first_pass_flt_rule_hdl[iptype].flt_rule_hdls;
		l2tp_second_pass_flt_rule_hdl = it_flt->l2tp_second_pass_flt_rule_hdl;
	}

#ifdef FEATURE_L2TP
	if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) && m_is_l2tp_iface)
	{
		IPACMDBG_H("Add l2tp rules for the client..\n");
#ifdef IPA_L2TP_TUNNEL_UDP
		for(it = m_client_info.begin(); it != m_client_info.end(); it++)
		{
			if (it->mapping_info->tunnel_type == IPA_L2TP_TUNNEL_IP)
			{
#endif
				m_p_iface->add_l2tp_flt_rule(client->mac_addr, &l2tp_flt_rule_hdl);
				flt_rule_hdls.push_front(l2tp_flt_rule_hdl);
#ifdef IPA_L2TP_TUNNEL_UDP
				break;
			}
			else
			{
				flt_rule_hdl = 0;
				m_p_iface->add_l2tp_udp_flt_rule(client->mac_addr,
					it->mapping_info->vlan_iface_ipv6_addr, it->mapping_info->vlan_client_ipv6_addr,
					it->mapping_info->dst_port, it->mapping_info->src_port,
					&l2tp_flt_rule_hdl);
				flt_rule_hdls.push_front(l2tp_flt_rule_hdl);
				IPACMDBG_H("Added flt rule %d.\n", l2tp_flt_rule_hdl);
			}
		}
#endif
	}
	else
#endif
	{
#ifdef FEATURE_L2TP
		if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) && client->is_l2tp_client)
		{
#ifdef IPA_L2TP_TUNNEL_UDP
			if (client->mapping_info->tunnel_type == IPA_L2TP_TUNNEL_IP)
			{
#endif
				m_p_iface->add_l2tp_flt_rule(iptype, client->mac_addr, client->mapping_info->vlan_client_ipv6_addr,
					&l2tp_flt_rule_hdl, &l2tp_second_pass_flt_rule_hdl);
				flt_rule_hdls.push_front(l2tp_flt_rule_hdl);
#ifdef IPA_L2TP_TUNNEL_UDP
			}
			else
			{
				m_p_iface->add_l2tp_udp_flt_rule(iptype, client->mac_addr,
					client->mapping_info->mtu, &l2tp_flt_rule_hdl);
				flt_rule_hdls.push_front(l2tp_flt_rule_hdl);
				IPACMDBG_H("Added flt rule %d for iptype: %d\n", l2tp_flt_rule_hdl, iptype);
			}
#endif
		}
		else
#endif
		{
			if (!this->get_m_support_ast_update())
			{
				if (!peer->peer)
				{
					IPACMERR("Invalid peer info\n");
					return IPACM_FAILURE;
				}
				if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
				{
					/* Assign interbridge route rule here */
					rt_tbl.ip = iptype;
					IPACMDBG_H("Lan2Lan_v2: Copy rt table of iptype %d table name, since inter bridge enabled? %d m_is_vlan %d \n", iptype, inter_bridge, m_is_vlan);

					if(iptype == IPA_IP_v4)
					{
						if(inter_bridge)
							memcpy(rt_tbl.name, IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v4.name, sizeof(IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v4));
						else
							memcpy(rt_tbl.name, peer->rt_tbl_name_for_flt[iptype], sizeof(rt_tbl.name));

						if(m_is_sIface)
						{
							memcpy(rt_tbl.name, IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v4.name, sizeof(IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v4));
							IPACMDBG_H("Overwriting rt table to inter only if m_is_sIface ? %d \n", m_is_sIface);
						}
					}
					else
					{
						memcpy(rt_tbl.name, IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v6.name, sizeof(IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v6));
					}
					if(m_is_sIface)
					{
						if(client->vlan_id == 0)
							pipe_idx_siface = 0;
						else
							pipe_idx_siface = 2;
					}
					IPACMDBG_H("m_is_sIface %d, pipe_idx_siface %d, client->vlan_id %d \n", m_is_sIface, pipe_idx_siface, client->vlan_id);
					IPACMDBG_H("This flt rule points to rt tbl %s.\n", rt_tbl.name);

					if(IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false)
					{
						IPACMERR("Failed to get routing table.\n");
						return IPACM_FAILURE;
					}
					IPACMDBG_H("Lan2Lan_v2: This flt rule points to rt tbl %s has hdl 0x%x.\n", rt_tbl.name, rt_tbl.hdl);
					IPACMDBG_H("Lan2Lan_v2: This flt rule for client->vlan_id %d inter_bridge %d\n", client->vlan_id, inter_bridge);
					IPACMDBG_H("Lan2Lan_v2: m_p_iface %s if_cat %d pipe_idx_siface %d\n", m_p_iface->dev_name, m_p_iface->ipa_if_cate, pipe_idx_siface);
					{
						if(m_p_iface->ipa_if_cate == WLAN_IF)
						{
							ret = ((IPACM_Wlan *)m_p_iface)->eth_bridge_add_flt_rule_v2(client->mac_addr, rt_tbl.hdl, rt_tbl.name, iptype, &flt_rule_hdl, client->vlan_id, pipe_idx_siface,
								client->bridge_ipv4, client->subnet_mask, inter_bridge, client->ipv6_prefix);
						}
						else
						{
							ret = m_p_iface->eth_bridge_add_flt_rule_v2(client->mac_addr, rt_tbl.hdl, rt_tbl.name, iptype, &flt_rule_hdl, client->vlan_id, pipe_idx_siface,
								client->bridge_ipv4, client->subnet_mask, inter_bridge, client->ipv6_prefix);
						}
					}
					if(ret == IPACM_FAILURE)
					{
						IPACMERR("filter rule addition failed\n");
						return IPACM_FAILURE;
					}
				}
				else
				{
					int pipe_idx = 0;
					/* While add peer interface eth-to_eth rule will be inserted followed by 802_to_eth
					   hence while poping out 802_to_eth will be popped first hence we install rules on
					   pipe idx 2 first and then on pipe idx 0 for special interface.	
					  filter rule was some time indicating to the wrong route due to wrong peer l2 type */
					if (peer->eth_vlan_instance == IPA_HDR_L2_802_1Q)
					{
						pipe_idx = 2;
						IPACMDBG_H("peer in eth vlan inst\n")
					}
					else
					{
						pipe_idx = 0;
						IPACMDBG_H("peer in eth non vlan inst\n")
					}
					rt_tbl.ip = iptype;
					memcpy(rt_tbl.name, peer->rt_tbl_name_for_flt[iptype], sizeof(rt_tbl.name));
					IPACMDBG_H("This flt rule points to rt tbl %s.\n", rt_tbl.name);

					if(IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false)
					{
						IPACMERR("Failed to get routing table.\n");
						return IPACM_FAILURE;
					}

					ret = m_p_iface->eth_bridge_add_flt_rule(client->mac_addr, rt_tbl.hdl,
						iptype, &flt_rule_hdl, client->vlan_id, pipe_idx);
					if(ret == IPACM_FAILURE)
					{
						IPACMERR("filter rule addition failed\n");
						return IPACM_FAILURE;
					}
				}
				peer->peer->pipe_idx = true;
			}
			IPACMDBG_H("Installed flt rule for IP type %d: handle %d\n", iptype, flt_rule_hdl);
		}
	}

	if(it_flt != peer->flt_rule.end())
	{
		if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true )
		{
			if(inter_bridge == false)
			{
				IPACMDBG_H("Lan2Lan_v2: The client is not found and not reached till end.\n");
				if(pipe_idx_siface == 2 && this->is_spcl_iface())
				{
					it_flt->flt_rule_hdl_siface[iptype] = flt_rule_hdl;
					if (iptype == IPA_IP_v4)
					{
						it_flt->bridge_ipv4 = client->bridge_ipv4;
						it_flt->subnet_mask = client->subnet_mask;
						bridges.insert({client->bridge_ipv4, client->subnet_mask});
					}
					else
					{
						memcpy(it_flt->ipv6_prefix, client->ipv6_prefix, sizeof(it_flt->ipv6_prefix));
						lan_client_v6_prefix.insert({client->ipv6_prefix[0], client->ipv6_prefix[1]});
					}
				}
				else
				{
					it_flt->flt_rule_hdl[iptype] = flt_rule_hdl;
					if(iptype == IPA_IP_v4)
					{
						it_flt->bridge_ipv4 = client->bridge_ipv4;
						it_flt->subnet_mask = client->subnet_mask;
						bridges.insert({client->bridge_ipv4,client->subnet_mask});
					}
					else
					{
						memcpy(it_flt->ipv6_prefix, client->ipv6_prefix, sizeof(it_flt->ipv6_prefix));
						lan_client_v6_prefix.insert({client->ipv6_prefix[0],client->ipv6_prefix[1]});
					}
				}
				it_flt->l2tp_first_pass_flt_rule_hdl[iptype].flt_rule_hdls = flt_rule_hdls;
				it_flt->l2tp_second_pass_flt_rule_hdl = l2tp_second_pass_flt_rule_hdl;
			}
		}
		else
		{
			it_flt->flt_rule_hdl[iptype] = flt_rule_hdl;
			it_flt->l2tp_first_pass_flt_rule_hdl[iptype].flt_rule_hdls = flt_rule_hdls;
			it_flt->l2tp_second_pass_flt_rule_hdl = l2tp_second_pass_flt_rule_hdl;
		}
	}
	else
	{
		IPACMDBG_H("The client is not found in flt info list, insert a new one.\n");
		if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
		{
			new_flt_info.flt_rule_hdl[IPA_IP_v6] = 0;
			new_flt_info.flt_rule_hdl[IPA_IP_v4] = 0;
			new_flt_info.flt_rule_hdl_siface[IPA_IP_v6] = 0;
			new_flt_info.flt_rule_hdl_siface[IPA_IP_v4] = 0;
			new_flt_info.p_client = client;
			if(pipe_idx_siface == 2 && this->is_spcl_iface())
			{
				new_flt_info.flt_rule_hdl_siface[iptype] = flt_rule_hdl;
				if (iptype == IPA_IP_v4)
				{
					new_flt_info.bridge_ipv4 = client->bridge_ipv4;
					new_flt_info.subnet_mask = client->subnet_mask;
					bridges.insert({client->bridge_ipv4, client->subnet_mask});
				}
				else
				{
					IPACMDBG_H("Copy ipv6_prefix to new_flt_info.\n");
					memcpy(new_flt_info.ipv6_prefix, client->ipv6_prefix, sizeof(new_flt_info.ipv6_prefix));
					lan_client_v6_prefix.insert({client->ipv6_prefix[0], client->ipv6_prefix[1]});
				}
			}
			else
			{
				new_flt_info.flt_rule_hdl[iptype] = flt_rule_hdl;
				if(iptype == IPA_IP_v4)
				{
					new_flt_info.bridge_ipv4 = client->bridge_ipv4;
					new_flt_info.subnet_mask = client->subnet_mask;
					bridges.insert({client->bridge_ipv4,client->subnet_mask});
				}
				else
				{
					IPACMDBG_H("Lan2Lan_v2: Copy ipv6_prefix to new_flt_info.\n");
					memcpy(new_flt_info.ipv6_prefix, client->ipv6_prefix, sizeof(new_flt_info.ipv6_prefix));
					lan_client_v6_prefix.insert({client->ipv6_prefix[0],client->ipv6_prefix[1]});
				}
			}
			IPACMDBG_H("Lan2Lan_v2: inter_bridge %d iptype %d\n",inter_bridge, iptype);
		}
		else
		{
			new_flt_info.p_client = client;
			new_flt_info.flt_rule_hdl[iptype] = flt_rule_hdl;
		}
		/* Create empty list. */
		new_flt_info.l2tp_first_pass_flt_rule_hdl[IPA_IP_v4].flt_rule_hdls = std::list<uint32_t>();
		new_flt_info.l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls = std::list<uint32_t>();
		new_flt_info.l2tp_first_pass_flt_rule_hdl[iptype].flt_rule_hdls = flt_rule_hdls;
		new_flt_info.l2tp_second_pass_flt_rule_hdl = l2tp_second_pass_flt_rule_hdl;
		peer->flt_rule.push_front(new_flt_info);
		IPACMDBG_H("Inserted the new client %zu.\n", sizeof(new_flt_info));
	}
	/* Store lan2lan v2 filter rule handles*/
	if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
	{
		IPACMDBG_H("Lan2Lan_v2: The Client is found in flt info list, with MAC: 0x%02x%02x%02x%02x%02x%02x, interface: %s on vlan_id %d\n",
			client->mac_addr[0], client->mac_addr[1], client->mac_addr[2], client->mac_addr[3], client->mac_addr[4], client->mac_addr[5],
			m_p_iface->dev_name, client->vlan_id);

		if(inter_bridge)
		{
			it_intr_brg_flt_rule.ip_type = iptype;
			it_intr_brg_flt_rule.flt_rule_hdl = flt_rule_hdl;
			if(iptype == IPA_IP_v4)
			{
				it_intr_brg_flt_rule.bridge_ipv4 = client->bridge_ipv4;
				it_intr_brg_flt_rule.subnet_mask = client->subnet_mask;
				bridges.insert({client->bridge_ipv4,client->subnet_mask});
			}
			if(iptype == IPA_IP_v6)
			{
				IPACMDBG_H("Copy ipv6_prefix to it_intr_brg_flt_rule.\n");
				memcpy(it_intr_brg_flt_rule.ipv6_prefix, client->ipv6_prefix, sizeof(it_intr_brg_flt_rule.ipv6_prefix));
				lan_client_v6_prefix.insert({client->ipv6_prefix[0],client->ipv6_prefix[1]});
			}
			it_flt->flt_rule_inter_bridge.push_front(it_intr_brg_flt_rule);
		}
		IPACMDBG_H("Lan2Lan_v2: This flt rule for inter_bridge %d, iptype %d flt_rule_hdl %x \n",  inter_bridge, iptype, flt_rule_hdl);
		IPACMDBG_H("Lan2Lan_v2: This flt rule for m_p_iface %s client->bridge_ipv4 ", m_p_iface->dev_name);
		iptodot("ip", client->bridge_ipv4);
		IPACMDBG_H("Lan2Lan_v2: This flt rule for m_p_iface %s client->subnet_mask ", m_p_iface->dev_name);
		iptodot("ip", client->subnet_mask);
		IPACMDBG_H("Lan2Lan_v2: This flt rule for client MAC: 0x%02x%02x%02x%02x%02x%02x, interface: %s on vlan_id %d\n",
			client->mac_addr[0], client->mac_addr[1], client->mac_addr[2], client->mac_addr[3], client->mac_addr[4], client->mac_addr[5],
			m_p_iface->dev_name, client->vlan_id);
		IPACMDBG_H("Lan2Lan_v2: prefix 0x[%X][%X] is pv6 prefix for vlan id %d\n", client->ipv6_prefix[0], client->ipv6_prefix[1], client->vlan_id);
	}
	return IPACM_SUCCESS;
}

void IPACM_LanToLan_Iface::del_one_client_flt_rule(IPACM_LanToLan_Iface *peer_iface, client_info *client,ipa_hdr_l2_type l2_hdr_type)
{
	list<peer_iface_info>::iterator it;

	for(it = m_peer_iface_info.begin(); it != m_peer_iface_info.end(); it++)
	{
		if(it->peer == peer_iface)
		{
			if (is_spcl_iface() && ((l2_hdr_is_802_1Q(l2_hdr_type) && l2_hdr_is_ethernet_II(it->eth_vlan_instance)) ||
									(l2_hdr_is_ethernet_II(l2_hdr_type) && l2_hdr_is_802_1Q(it->eth_vlan_instance))))
			{
				IPACMDBG_H("siface %d find the correct l2 type peer %d\n", l2_hdr_type, it->eth_vlan_instance);
				continue;
			}
			IPACMDBG_H("Found the peer iface info.\n");
			del_client_flt_rule(&(*it), client);
			break;
		}
	}
	return;
}

void IPACM_LanToLan_Iface::del_client_flt_rule(peer_iface_info *peer, client_info *client)
{
	list<flt_rule_info>::iterator it_flt;
	list<uint32_t>::iterator it_flt_hdl;
	list<flt_rule_hdl_interbridge>::iterator itr_flt_rule_inter_bridge;

	for(it_flt = peer->flt_rule.begin(); it_flt != peer->flt_rule.end(); it_flt++)
	{
		if(it_flt->p_client == client)	//found the client in flt info list
		{
			IPACMDBG_H("Found the client in flt info list.\n");
			if(m_is_ip_addr_assigned[IPA_IP_v4])
			{
				if(m_is_l2tp_iface)
				{
					IPACMDBG_H("No IPv4 client flt rule on l2tp iface.\n");
				}
				else
				{
#ifdef FEATURE_L2TP
					if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) && client->is_l2tp_client)
					{
						for(it_flt_hdl = it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v4].flt_rule_hdls.begin();
							(it_flt_hdl != it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v4].flt_rule_hdls.end()) &&
							(it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v4].flt_rule_hdls.size() != 0); ++it_flt_hdl)
						{
							m_p_iface->del_l2tp_flt_rule(IPA_IP_v4,
								*it_flt_hdl,
								it_flt->l2tp_second_pass_flt_rule_hdl);
							IPACMDBG_H("Deleted IPv4 first pass flt rule %d and second pass flt rule %d.\n",
								*it_flt_hdl, it_flt->l2tp_second_pass_flt_rule_hdl);
							*it_flt_hdl = 0;
							it_flt->l2tp_second_pass_flt_rule_hdl = 0;
						}
						/* Clear the list. */
						it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v4].flt_rule_hdls.clear();
					}
					else
#endif
					{
						if(m_p_iface->eth_bridge_del_flt_rule(it_flt->flt_rule_hdl[IPA_IP_v4], IPA_IP_v4) == IPACM_FAILURE)
						{
							IPACMERR("Failed to delete IPv4 flt rule %d.\n", it_flt->flt_rule_hdl[IPA_IP_v4]);
						}
						else
							IPACMDBG_H("Deleted IPv4 flt rule %d.\n", it_flt->flt_rule_hdl[IPA_IP_v4]);
						if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
						{
							for(itr_flt_rule_inter_bridge = it_flt->flt_rule_inter_bridge.begin();itr_flt_rule_inter_bridge != it_flt->flt_rule_inter_bridge.end();itr_flt_rule_inter_bridge++)
							{
								if(itr_flt_rule_inter_bridge->ip_type == IPA_IP_v4)
								{
									if(m_p_iface->eth_bridge_del_flt_rule(itr_flt_rule_inter_bridge->flt_rule_hdl, IPA_IP_v4) == IPACM_FAILURE)
									{
										IPACMERR("Failed to delete interbridge IPv4 flt rule %d.\n", itr_flt_rule_inter_bridge->flt_rule_hdl);
									}
									else
										IPACMDBG_H("Deleted interbridge IPv4 flt rule %d.\n", itr_flt_rule_inter_bridge->flt_rule_hdl);
								}
							}
						}
						if (this->is_spcl_iface())
						{
							m_p_iface->eth_bridge_del_flt_rule(it_flt->flt_rule_hdl_siface[IPA_IP_v4], IPA_IP_v4);
							IPACMDBG_H("Deleted IPv4 flt rule %d.\n", it_flt->flt_rule_hdl_siface[IPA_IP_v4]);
						}
					}
				}
			}
			if(m_is_ip_addr_assigned[IPA_IP_v6])
			{
#ifdef FEATURE_L2TP
				if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) && m_is_l2tp_iface)
				{
					for(it_flt_hdl = it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.begin();
						(it_flt_hdl != it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.end()) &&
						(it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.size() != 0); ++it_flt_hdl)
					{
						m_p_iface->del_l2tp_flt_rule(*it_flt_hdl);
						IPACMDBG_H("Deleted IPv6 flt rule id %d\n", *it_flt_hdl);
						*it_flt_hdl = 0;
					}
					/* Clear the list. */
					it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.clear();
				}
				else
#endif
				{
#ifdef FEATURE_L2TP
					if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) && client->is_l2tp_client)
					{
						for(it_flt_hdl = it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.begin();
							(it_flt_hdl != it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.end()) &&
							(it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.size() != 0); ++it_flt_hdl)
						{
							m_p_iface->del_l2tp_flt_rule(IPA_IP_v6, *it_flt_hdl,
								it_flt->l2tp_second_pass_flt_rule_hdl);
							IPACMDBG_H("Deleted IPv6 first pass flt rule %d and second pass flt rule %d.\n",
								*it_flt_hdl, it_flt->l2tp_second_pass_flt_rule_hdl);
								*it_flt_hdl = 0;
							it_flt->l2tp_second_pass_flt_rule_hdl = 0;
						}
						/* Clear the list. */
						it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.clear();
					}
					else
#endif
					{
						if(m_p_iface->eth_bridge_del_flt_rule(it_flt->flt_rule_hdl[IPA_IP_v6], IPA_IP_v6) == IPACM_FAILURE)
						{
							IPACMERR("Failed to delete IPv6 flt rule %d.\n", it_flt->flt_rule_hdl[IPA_IP_v6]);
						}
						IPACMDBG_H("Deleted IPv6 flt rule %d.\n", it_flt->flt_rule_hdl[IPA_IP_v6]);

						if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
						{
							for(itr_flt_rule_inter_bridge = it_flt->flt_rule_inter_bridge.begin();itr_flt_rule_inter_bridge != it_flt->flt_rule_inter_bridge.end();itr_flt_rule_inter_bridge++)
							{
								if(itr_flt_rule_inter_bridge->ip_type == IPA_IP_v6)
								{
									if(m_p_iface->eth_bridge_del_flt_rule(itr_flt_rule_inter_bridge->flt_rule_hdl, IPA_IP_v4) == IPACM_FAILURE)
									{
										IPACMERR("Failed to delete interbridge IPv4 flt rule %d.\n", itr_flt_rule_inter_bridge->flt_rule_hdl);
									}
									else
										IPACMDBG_H("Deleted interbridge IPv4 flt rule %d.\n", itr_flt_rule_inter_bridge->flt_rule_hdl);
								}
							}
						}
						if (this->is_spcl_iface())
						{
							m_p_iface->eth_bridge_del_flt_rule(it_flt->flt_rule_hdl_siface[IPA_IP_v6], IPA_IP_v6);
							IPACMDBG_H("Deleted IPv6 flt rule %d.\n", it_flt->flt_rule_hdl_siface[IPA_IP_v6]);
						}
					}
				}
			}
			peer->flt_rule.erase(it_flt);
			break;
		}
	}
	return;
}

void IPACM_LanToLan_Iface::del_client_rt_rule(peer_iface_info *peer, client_info *client)
{
	ipa_hdr_l2_type peer_l2_hdr_type;
	int i, num_rules;
#ifdef FEATURE_VLAN_MPDN
	std::array<uint8_t, 6> mac;
	std::map<std::array<uint8_t, 6>, int >::iterator it;
#endif

	if(peer == NULL || peer->peer == NULL ||
		peer->peer->get_iface_pointer() == NULL ||
		peer->peer->get_iface_pointer()->tx_prop == NULL)
	{
		IPACMERR("Failure null peer passed\n");
		return;
	}

	IPACMDBG_H("peer dev name :%s\n",peer->peer->get_iface_pointer()->dev_name);

	if(peer->is_vlan_peer && peer->peer->get_iface_pointer()->tx_prop->num_tx_props > 2)
	{
		peer_l2_hdr_type = peer->peer->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type;
	}
	else
	{
		peer_l2_hdr_type = peer->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
	}
	if (peer_l2_hdr_type >= IPA_HDR_L2_MAX || peer_l2_hdr_type < 0)
	{
		IPACMDBG_H("Invalid peer_l2_hdr_type: %d\n", peer_l2_hdr_type);
		return;
	}

	/* if the peer info is not for intra interface communication */
	if(peer->peer != this)
	{
		IPACMDBG_H("Delete routing rules for inter interface communication.\n");
#ifdef FEATURE_VLAN_MPDN
		if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
		{
			std::copy(std::begin(client->mac_addr), std::end(client->mac_addr), std::begin(mac));

			/* check if peer already has rt rule for this mac address */
			it = peer->mac_rt_rule_ref.find(mac);
			if(it == peer->mac_rt_rule_ref.end())
			{
				IPACMERR("couldn't find client rt rule ref count, peer %s, mac 0x[%X][%X][%X][%X][%X][%X]\n",
					peer->peer->get_iface_pointer()->dev_name,
					client->mac_addr[0], client->mac_addr[1], client->mac_addr[2],
					client->mac_addr[3], client->mac_addr[4], client->mac_addr[5]);
				return;
			}

			IPACMDBG_H("ref count is now %d, peer %s, mac 0x[%X][%X][%X][%X][%X][%X]\n", it->second, peer->peer->get_iface_pointer()->dev_name,
				client->mac_addr[0], client->mac_addr[1], client->mac_addr[2],
				client->mac_addr[3], client->mac_addr[4], client->mac_addr[5]);
			(it->second)--;
			IPACMDBG_H("reduce to %d", it->second);
			if(it->second)
			{
				IPACMDBG_H("ref count still positive, don't delete rt rules\n");
				return;
			}

			peer->mac_rt_rule_ref.erase(it);
		}
#endif
		if(client->is_l2tp_client == false)
		{
			num_rules = client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v4];
			for(i = 0; i < num_rules; i++)
			{
				m_p_iface->eth_bridge_del_rt_rule(client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v4][i], IPA_IP_v4);
				IPACMDBG_H("IPv4 rt rule %d is deleted.\n", client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v4][i]);
			}
			client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v4] = 0;

			num_rules = client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v6];
			for(i = 0; i < num_rules; i++)
			{
				m_p_iface->eth_bridge_del_rt_rule(client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v6][i], IPA_IP_v6);
				IPACMDBG_H("IPv6 rt rule %d is deleted.\n", client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v6][i]);
			}
			client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v6] = 0;

			if (m_is_vlan || is_svap_iface() || is_ap_iface_vlan_enabled() || (is_spcl_iface() &&  client->vlan_id)) {
				IPACMDBG_H("Perform del_hdr_proc_ctx_vlan for svap/spcl clients \n");
				del_hdr_proc_ctx_vlan(peer_l2_hdr_type, client->vlan_id);
			}
#ifdef FEATURE_L2TP
			if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) &&
				IPACM_LanToLan::get_instance()->has_l2tp_iface() == true)
			{
				m_p_iface->del_l2tp_rt_rule(IPA_IP_v6, client->l2tp_rt_rule_hdl[peer_l2_hdr_type].num_rt_hdl[IPA_IP_v6],
					client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_rt_rule_hdl[IPA_IP_v6]);
			}
#endif
		}
		else
		{
#ifdef FEATURE_L2TP
			if(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E ||
				IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP)
			{
				m_p_iface->del_l2tp_rt_rule(IPA_IP_v4, client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_hdr_hdl,
					client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_hdr_proc_ctx_hdl[IPA_IP_v4], client->l2tp_rt_rule_hdl[peer_l2_hdr_type].second_pass_hdr_hdl,
					client->l2tp_rt_rule_hdl[peer_l2_hdr_type].num_rt_hdl[IPA_IP_v4], client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_rt_rule_hdl[IPA_IP_v4],
					client->l2tp_rt_rule_hdl[peer_l2_hdr_type].second_pass_rt_rule_hdl);

				m_p_iface->del_l2tp_rt_rule(IPA_IP_v6, 0, client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_hdr_proc_ctx_hdl[IPA_IP_v6],
					0, client->l2tp_rt_rule_hdl[peer_l2_hdr_type].num_rt_hdl[IPA_IP_v6], client->l2tp_rt_rule_hdl[peer_l2_hdr_type].first_pass_rt_rule_hdl[IPA_IP_v6],
					NULL);
			}
#endif
		}
	}
	else
	{
		if(IPACM_Iface::ipacmcfg->multi_vlan_bridge_config_enable == 0 && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
		{
			IPACMDBG_H("Delete routing rules for intra interface communication.\n");
			num_rules = client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v4];
			for(i = 0; i < num_rules; i++)
			{
				m_p_iface->eth_bridge_del_rt_rule(client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v4][i], IPA_IP_v4);
				IPACMDBG_H("IPv4 rt rule %d is deleted.\n", client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v4][i]);
			}
			client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v4] = 0;

			num_rules = client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v6];
			for(i = 0; i < num_rules; i++)
			{
				m_p_iface->eth_bridge_del_rt_rule(client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v6][i], IPA_IP_v6);
					IPACMDBG_H("IPv6 rt rule %d is deleted.\n", client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v6][i]);
			}
			client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v6] = 0;
		}
		else if(IPACM_Iface::ipacmcfg->multi_vlan_bridge_config_enable == 1 && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
		{
			IPACMDBG_H("Delete routing rules for intra interface communication.\n");
			num_rules = client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v4];
			for(i = 0; i < num_rules; i++)
			{
				m_p_iface->eth_bridge_del_rt_rule(client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v4][i], IPA_IP_v4);
				IPACMDBG_H("IPv4 rt rule %d is deleted.\n", client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v4][i]);
			}
			client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v4] = 0;

			num_rules = client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v6];
			for(i = 0; i < num_rules; i++)
			{
				m_p_iface->eth_bridge_del_rt_rule(client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v6][i], IPA_IP_v6);
					IPACMDBG_H("IPv6 rt rule %d is deleted.\n", client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v6][i]);
			}
			client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v6] = 0;

			IPACMDBG_H("Delete hdr_proc_ctx: %d for intra interface communication.\n",
				client->hdr_proc_ctx_intra_interface);
			m_p_iface->eth_bridge_del_hdr_proc_ctx(client->hdr_proc_ctx_intra_interface);
		}
	}

	return;
}

void IPACM_LanToLan_Iface::handle_down_event()
{
	list<peer_iface_info>::iterator it_own_peer_info, it_other_iface_peer_info, it_other_mac_iface;
	IPACM_LanToLan_Iface *other_iface;
	ipa_hdr_l2_type it_own_peer_hdr_type,it_other_iface_peer_hdr_type,own_hdr_type;

	/* Update the peer l2 ref if this is svap */
	if (is_svap_iface() && this->get_iface_pointer()->tx_prop->num_tx_props > 2)
	{
		own_hdr_type = this->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type;
	}
	else
	{
		own_hdr_type = this->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
	}

	/* clear inter-interface rules */
	if(m_support_inter_iface_offload)
	{
		for(it_own_peer_info = m_peer_iface_info.begin(); it_own_peer_info != m_peer_iface_info.end();
			it_own_peer_info++)
		{
			if (!it_own_peer_info->peer)
			{
				IPACMERR("Invalid it_own_peer_info\n");
				continue;
			}
			IPACMDBG_H("it_own_peer %s\n",it_own_peer_info->peer->get_iface_pointer()->dev_name);
			if (it_own_peer_info->is_vlan_peer && it_own_peer_info->peer->get_iface_pointer()->tx_prop->num_tx_props > 2){
				it_own_peer_hdr_type = it_own_peer_info->peer->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type;
			}
			else {
				it_own_peer_hdr_type = it_own_peer_info->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
			}

			if ((it_own_peer_hdr_type >= IPA_HDR_L2_MAX) || (it_own_peer_hdr_type < 0))
			{
				IPACMDBG_H("Invalid peer_l2_hdr_type: %d\n", it_own_peer_hdr_type);
				continue;
			}

			/* decrement reference count of peer l2 header type on both interfaces*/
			decrement_ref_cnt_peer_l2_hdr_type(it_own_peer_hdr_type);
			if ((is_svap_iface() || is_ap_iface_vlan_enabled()) && m_p_iface->tx_prop->num_tx_props > 2)
			{
				it_own_peer_info->peer->decrement_ref_cnt_peer_l2_hdr_type(m_p_iface->tx_prop->tx[2].hdr_l2_type);
			}
			else if(is_spcl_iface() && m_p_iface->tx_prop->num_tx_props > 2)
			{
				/* Decrement for both l2 type as it was added as 2 interface with 2 different l2 type*/
				it_own_peer_info->peer->decrement_ref_cnt_peer_l2_hdr_type(m_p_iface->tx_prop->tx[2].hdr_l2_type);
				it_own_peer_info->peer->decrement_ref_cnt_peer_l2_hdr_type(m_p_iface->tx_prop->tx[0].hdr_l2_type);
			}
			else
			{
				it_own_peer_info->peer->decrement_ref_cnt_peer_l2_hdr_type(m_p_iface->tx_prop->tx[0].hdr_l2_type);
			}

			/* first clear all flt rule on target interface */
			IPACMDBG_H("Clear all flt rule on target interface.\n");
			if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
				clear_all_flt_rule_for_one_peer_iface(&(*it_own_peer_info));

			other_iface = it_own_peer_info->peer;
			/* then clear all flt/rt rule and hdr proc ctx for target interface on peer interfaces */
			IPACMDBG_H("Clear all flt/rt rules and hdr proc ctx for target interface on peer interfaces %s.\n",
				it_own_peer_info->peer->get_iface_pointer()->dev_name);
			for(it_other_iface_peer_info = other_iface->m_peer_iface_info.begin();
				it_other_iface_peer_info != other_iface->m_peer_iface_info.end();)
			{
				if(it_other_iface_peer_info->peer == this)	//found myself in other iface's peer info list
				{
					IPACMDBG_H("Found the right peer info on other iface.\n");

					if(!it_other_iface_peer_info->mac_rt_rule_ref.empty())
					{
						std::map<std::array<uint8_t, 6>, int >::iterator it;
						std::array<uint8_t, 6> mac = {0};
						uint8_t mac_addr[6];
						char *peer_iface_name;
						bool flag;
						IPACMDBG_H("iface name %s\n", it_other_iface_peer_info->peer->get_iface_pointer()->dev_name);
						for(it = it_other_iface_peer_info->mac_rt_rule_ref.begin();
							it != it_other_iface_peer_info->mac_rt_rule_ref.end(); it++)
						{
							IPACMDBG_H("Found  mac 0x[%X][%X][%X][%X][%X][%X] with mac ref cnt is %d\n",
								it->first[0],it->first[1],it->first[2],it->first[3],it->first[4],it->first[5],
								it->second);
							std::copy(std::begin(it->first), std::end(it->first), std::begin(mac));
							mac_addr[0]= mac[0];
							mac_addr[1]= mac[1];
							mac_addr[2]= mac[2];
							mac_addr[3]= mac[3];
							mac_addr[4]= mac[4];
							mac_addr[5]= mac[5];
							for(it_other_mac_iface = other_iface->m_peer_iface_info.begin();
							 it_other_mac_iface != other_iface->m_peer_iface_info.end();
							 it_other_mac_iface++)
							 {
								peer_iface_name =
									IPACM_LanToLan::get_instance()->handle_cached_client_get_iface(mac_addr);

								if(peer_iface_name &&
									(!strcmp(peer_iface_name, it_other_mac_iface->peer->get_iface_pointer()->dev_name)))
									flag = false;
								else
									flag = true;

								if (it_other_mac_iface->is_vlan_peer && it_other_mac_iface->peer->get_iface_pointer()->tx_prop->num_tx_props > 2)
								{
									it_other_iface_peer_hdr_type = it_other_mac_iface->peer->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type;
								}
								else
								{
									it_other_iface_peer_hdr_type = it_other_mac_iface->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
								}
								if ((it_other_iface_peer_hdr_type >= IPA_HDR_L2_MAX) || (it_other_iface_peer_hdr_type < 0))
								{
									IPACMDBG_H("Invalid peer_l2_hdr_type: %d\n", it_other_iface_peer_hdr_type);
									continue;
								}

								if ((it_other_iface_peer_hdr_type != own_hdr_type) && !is_spcl_iface())
								{
									IPACMDBG_H("l2 header mismatch\n");
									continue;
								}

								if(it_other_mac_iface->peer != this && flag)
								{
									IPACMDBG_H("copying the mac ref for iface name %s\n",
										it_other_mac_iface->peer->get_iface_pointer()->dev_name);
									it_other_mac_iface->mac_rt_rule_ref.insert(std::make_pair(mac, (it->second)));
									break;
								}

							}
						}
					}
					if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
						other_iface->clear_all_flt_rule_for_one_peer_iface(&(*it_other_iface_peer_info));
					other_iface->clear_all_rt_rule_for_one_peer_iface(&(*it_other_iface_peer_info));
					/* remove the peer info from the list */
					if (it_other_iface_peer_info->is_vlan_peer && it_other_iface_peer_info->peer->get_iface_pointer()->tx_prop->num_tx_props > 2)
					{
						it_other_iface_peer_hdr_type = it_other_iface_peer_info->peer->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type;
					}
					else
					{
						it_other_iface_peer_hdr_type = it_other_iface_peer_info->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
					}

					it_other_iface_peer_info = other_iface->m_peer_iface_info.erase(it_other_iface_peer_info);
					if ((it_other_iface_peer_hdr_type >= IPA_HDR_L2_MAX) || (it_other_iface_peer_hdr_type < 0))
					{
						IPACMDBG_H("Invalid peer_l2_hdr_type: %d\n", it_other_iface_peer_hdr_type);
						continue;
					}
					other_iface->del_hdr_proc_ctx(it_other_iface_peer_hdr_type);
				}
				else
				{
					it_other_iface_peer_info++;
				}
			}

			/* then clear rt rule and hdr proc ctx and release rt table on target interface */
			IPACMDBG_H("Clear rt rules and hdr proc ctx and release rt table on target interface.\n");
			clear_all_rt_rule_for_one_peer_iface(&(*it_own_peer_info));
			del_hdr_proc_ctx(it_own_peer_hdr_type);
		}
		m_peer_iface_info.clear();
	}

	/* clear intra interface rules */
	if(m_support_intra_iface_offload && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
	{
		IPACMDBG_H("Clear intra interface flt/rt rules and hdr proc ctx, release rt tables.\n");
		clear_all_flt_rule_for_one_peer_iface(&m_intra_interface_info);
		clear_all_rt_rule_for_one_peer_iface(&m_intra_interface_info);
		m_p_iface->eth_bridge_del_hdr_proc_ctx(hdr_proc_ctx_for_intra_interface);
		IPACMDBG_H("Hdr proc ctx with hdl %d is deleted.\n", hdr_proc_ctx_for_intra_interface);
	}

	/* then clear the client info list */
	m_client_info.clear();

	return;
}

#ifdef FEATURE_VLAN_MPDN
void IPACM_LanToLan_Iface::handle_vlan_id_add(uint16_t vlan_id)
{
	list<peer_iface_info>::iterator it_peer_info;

	IPACMDBG_H("adding vlan id %d to IF %s add flt rules for peers with matching vlan id\n",
		vlan_id, get_iface_pointer()->dev_name);
	if (get_m_is_ip_addr_assigned(IPA_IP_v4))
	{
		if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
		{
			add_self_flt_rule_one_vlan_id(IPA_IP_v4, vlan_id);
		}
		else
		{
			add_all_inter_interface_client_flt_rule_one_vlan_id(IPA_IP_v4, vlan_id);
		}
	}

	if(get_m_is_ip_addr_assigned(IPA_IP_v6))
	{
		if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
		{
			if(IPACM_Iface::ipacmcfg->ipv6_prefix_for_vlan_id(vlan_id) != true)
			{
				IPACMERR("v6 prefix not yet set install after it is set\n");
				return;
			}
			add_self_flt_rule_one_vlan_id(IPA_IP_v6, vlan_id);
		}
		else
		{
			add_all_inter_interface_client_flt_rule_one_vlan_id(IPA_IP_v6, vlan_id);
		}
	}
}

void IPACM_LanToLan_Iface::handle_vlan_id_del(uint16_t vlan_id)
{
	list<client_info>::iterator it_client;

	IPACMDBG_H("iface %s got vlan id %d del, looking for clients to remove\n",
		get_iface_pointer()->dev_name, vlan_id);

	/* go over all clients and remove those with the removed vlan id */
	IPACMDBG_H("There are %zu m_client_info in total.\n", m_client_info.size());
	it_client = m_client_info.begin();
	while (it_client != m_client_info.end())
	{
		if(it_client->vlan_id == vlan_id)
		{
			IPACMDBG_H("found client with MAC 0x[%X][%X][%X][%X][%X][%X] and vlan id %d, removing\n",
				it_client->mac_addr[0], it_client->mac_addr[1], it_client->mac_addr[2],
				it_client->mac_addr[3], it_client->mac_addr[4], it_client->mac_addr[5],
				vlan_id);
			it_client = handle_client_del(it_client->mac_addr, vlan_id);
		}
		else
		{
			IPACMDBG_H("skipping client with vlan id %d\n", it_client->vlan_id);
			++it_client;
		}
	}

	/* remove flt rules for clients with this vlan id */
	if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
		del_self_flt_rule_one_vlan_id(vlan_id);
	else
		del_all_inter_interface_client_flt_rule_one_vlan_id(vlan_id);
}
#endif

void IPACM_LanToLan_Iface::clear_all_flt_rule_for_one_peer_iface(peer_iface_info *peer)
{
	list<flt_rule_info>::iterator it;
	list<uint32_t>::iterator it_flt_hdl;

	for(it = peer->flt_rule.begin(); it != peer->flt_rule.end(); it++)
	{
		if(m_is_ip_addr_assigned[IPA_IP_v4])
		{
			if(m_is_l2tp_iface)
			{
				IPACMDBG_H("No IPv4 client flt rule on l2tp iface.\n");
			}
			else
			{
#ifdef FEATURE_L2TP
				if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) &&
					it->p_client->is_l2tp_client)
				{
					for(it_flt_hdl = it->l2tp_first_pass_flt_rule_hdl[IPA_IP_v4].flt_rule_hdls.begin();
						(it_flt_hdl != it->l2tp_first_pass_flt_rule_hdl[IPA_IP_v4].flt_rule_hdls.end()) &&
						(it->l2tp_first_pass_flt_rule_hdl[IPA_IP_v4].flt_rule_hdls.size() != 0); ++it_flt_hdl)
					{
						m_p_iface->del_l2tp_flt_rule(IPA_IP_v4,
							*it_flt_hdl,
							it->l2tp_second_pass_flt_rule_hdl);
						IPACMDBG_H("Deleted IPv4 first pass flt rule %d and second pass flt rule %d.\n",
							*it_flt_hdl, it->l2tp_second_pass_flt_rule_hdl);
						*it_flt_hdl = 0;
						it->l2tp_second_pass_flt_rule_hdl = 0;
					}
					/* Clear the list. */
					it->l2tp_first_pass_flt_rule_hdl[IPA_IP_v4].flt_rule_hdls.clear();
				}
				else
#endif
				{
					m_p_iface->eth_bridge_del_flt_rule(it->flt_rule_hdl[IPA_IP_v4], IPA_IP_v4);
					IPACMDBG_H("Deleted IPv4 flt rule %d.\n", it->flt_rule_hdl[IPA_IP_v4]);
#ifdef FEATURE_VLAN_MPDN
					if(m_is_vlan)
					{
						IPACMDBG_H("vlan id %d\n", it->p_client->vlan_id);
					}
#endif
				}
			}
		}
		if(m_is_ip_addr_assigned[IPA_IP_v6])
		{
#ifdef FEATURE_L2TP
			if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) && m_is_l2tp_iface)
			{
				for(it_flt_hdl = it->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.begin();
					(it_flt_hdl != it->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.end()) &&
					(it->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.size() != 0); ++it_flt_hdl)
				{
					m_p_iface->del_l2tp_flt_rule(*it_flt_hdl);
					IPACMDBG_H("Deleted IPv6 flt rule id %d\n", *it_flt_hdl);
					*it_flt_hdl = 0;
				}
				/* Clear the list. */
				it->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.clear();
			}
			else
#endif
			{
#ifdef FEATURE_L2TP
				if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) && it->p_client->is_l2tp_client)
				{
					for(it_flt_hdl = it->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.begin();
						(it_flt_hdl != it->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.end()) &&
						(it->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.size() != 0); ++it_flt_hdl)
					{
						m_p_iface->del_l2tp_flt_rule(IPA_IP_v6, *it_flt_hdl,
							it->l2tp_second_pass_flt_rule_hdl);
						IPACMDBG_H("Deleted IPv6 first pass flt rule %d and second pass flt rule %d.\n",
							*it_flt_hdl, it->l2tp_second_pass_flt_rule_hdl);
							*it_flt_hdl = 0;
						it->l2tp_second_pass_flt_rule_hdl = 0;
					}
					/* Clear the list. */
					it->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.clear();
				}
				else
#endif
				{
					m_p_iface->eth_bridge_del_flt_rule(it->flt_rule_hdl[IPA_IP_v6], IPA_IP_v6);
					IPACMDBG_H("Deleted IPv6 flt rule %d.\n", it->flt_rule_hdl[IPA_IP_v6]);
#ifdef FEATURE_VLAN_MPDN
					if(m_is_vlan)
					{
						IPACMDBG_H("vlan id %d\n", it->p_client->vlan_id);
					}
#endif
				}
			}
		}
	}
	peer->flt_rule.clear();
	return;
}

void IPACM_LanToLan_Iface::clear_all_rt_rule_for_one_peer_iface(peer_iface_info *peer)
{
	list<client_info>::iterator it;
	ipa_hdr_l2_type peer_l2_type = IPA_HDR_L2_NONE;

	if (peer != NULL)
	{
		IPACMDBG_H("peer->is_vlan_peer :%d\n", peer->is_vlan_peer);
	}
	else
	{
		IPACMDBG_H("peer->is_vlan_peer is NULL\n");
		return;
	}

	if(peer == NULL || peer->peer == NULL ||
		peer->peer->get_iface_pointer() == NULL ||
		peer->peer->get_iface_pointer()->tx_prop == NULL)
	{
		IPACMERR("Invalid peer pointer!");
		return;
	}

	if (peer->is_vlan_peer &&
		peer->peer->get_iface_pointer()->tx_prop->num_tx_props > 2)
		peer_l2_type = peer->peer->get_iface_pointer()
				       ->tx_prop->tx[2]
				       .hdr_l2_type;
	else
		peer_l2_type = peer->peer->get_iface_pointer()
				       ->tx_prop->tx[0]
				       .hdr_l2_type;

	if (peer_l2_type >= IPA_HDR_L2_MAX || peer_l2_type < 0)
	{
		IPACMDBG_H("Invalid peer_l2_type: %d\n", peer_l2_type);
		return;
	}
	IPACMDBG_H("Now peer %s the ref_cnt of peer l2 hdr type %s is %d.\n", peer->peer->get_iface_pointer()->dev_name, ipa_l2_hdr_type[peer_l2_type],
			   ref_cnt_peer_l2_hdr_type[peer_l2_type]);
	if(ref_cnt_peer_l2_hdr_type[peer_l2_type] == 0)
	{
		for(it = m_client_info.begin(); it != m_client_info.end(); it++)
		{
			del_client_rt_rule(peer, &(*it));
		}
#ifdef FEATURE_L2TP
		if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) &&
			IPACM_LanToLan::get_instance()->has_l2tp_iface() == true)
		{
			m_p_iface->eth_bridge_del_hdr_proc_ctx(hdr_proc_ctx_for_l2tp);
			hdr_proc_ctx_for_l2tp = 0;
		}
#endif
	}

	return;
}

void IPACM_LanToLan_Iface::handle_wlan_scc_mcc_switch()
{
	list<peer_iface_info>::iterator it_peer_info;
	list<client_info>::iterator it_client;
	ipa_hdr_l2_type peer_l2_hdr_type;
	bool flag[IPA_HDR_L2_MAX];
	int i;

	/* modify inter-interface routing rules */
	if(m_support_inter_iface_offload)
	{
		IPACMDBG_H("Modify rt rules for peer interfaces.\n");
		memset(flag, 0, sizeof(flag));
		for(it_peer_info = m_peer_iface_info.begin(); it_peer_info != m_peer_iface_info.end(); it_peer_info++)
		{
			peer_l2_hdr_type = it_peer_info->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
			if(peer_l2_hdr_type >= IPA_HDR_L2_MAX || peer_l2_hdr_type < 0)
			{
				IPACMDBG_H("Invalid peer_l2_hdr_type: %d\n", peer_l2_hdr_type);
				return;
			}

			if(flag[peer_l2_hdr_type] == false)
			{
				flag[peer_l2_hdr_type] = true;
				for(it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
				{
					m_p_iface->eth_bridge_modify_rt_rule(it_client->mac_addr, hdr_proc_ctx_for_inter_interface[peer_l2_hdr_type],
						peer_l2_hdr_type, IPA_IP_v4, it_client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v4],
						it_client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v4]);
					IPACMDBG_H("The following IPv4 routing rules are modified:\n");
					for(i = 0; i < it_client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v4]; i++)
					{
						IPACMDBG_H("%d\n", it_client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v4][i]);
					}

					m_p_iface->eth_bridge_modify_rt_rule(it_client->mac_addr, hdr_proc_ctx_for_inter_interface[peer_l2_hdr_type],
						peer_l2_hdr_type, IPA_IP_v6, it_client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v6],
						it_client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v6]);
					IPACMDBG_H("The following IPv6 routing rules are modified:\n");
					for(i = 0; i < it_client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v6]; i++)
					{
						IPACMDBG_H("%d\n", it_client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v6][i]);
					}
				}
			}
		}
	}

	/* modify routing rules for intra-interface communication */
	IPACMDBG_H("Modify rt rules for intra-interface communication.\n");
	if(m_support_intra_iface_offload && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
	{
		for(it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
		{
			m_p_iface->eth_bridge_modify_rt_rule(it_client->mac_addr, hdr_proc_ctx_for_intra_interface,
				m_p_iface->tx_prop->tx[0].hdr_l2_type, IPA_IP_v4, it_client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v4],
				it_client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v4]);
			IPACMDBG_H("The following IPv4 routing rules are modified:\n");
			for(i = 0; i < it_client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v4]; i++)
			{
				IPACMDBG_H("%d\n", it_client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v4][i]);
			}

			m_p_iface->eth_bridge_modify_rt_rule(it_client->mac_addr, hdr_proc_ctx_for_intra_interface,
				m_p_iface->tx_prop->tx[0].hdr_l2_type, IPA_IP_v6, it_client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v6],
				it_client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v6]);
			IPACMDBG_H("The following IPv6 routing rules are modified:\n");
			for(i = 0; i < it_client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v6]; i++)
			{
				IPACMDBG_H("%d\n", it_client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v6][i]);
			}
		}
	}

	return;
}

void IPACM_LanToLan_Iface::handle_intra_interface_info()
{
	uint32_t hdr_proc_ctx_hdl[IPA_MAX_NUM_PROPS] = { 0 };

	if(m_p_iface->tx_prop == NULL)
	{
		IPACMERR("No tx prop.\n");
		return;
	}

	m_intra_interface_info.peer = this;

	if (!this->get_m_support_ast_update())
	{
		snprintf(m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX,
			"eth_v4_intra_interface");
		IPACMDBG_H("IPv4 routing table for flt name: %s\n", m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v4]);
		snprintf(m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX,
			"eth_v6_intra_interface");
		IPACMDBG_H("IPv6 routing table for flt name: %s\n", m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v6]);
	}
	else
	{
		/* populate the routing table information */
		if (this->is_svap_iface()) {
			snprintf(m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
					 ipa_l2_hdr_type[m_p_iface->rx_prop->rx[2].hdr_l2_type]);
			IPACMDBG_H("IPv4 routing table for flt name: %s\n", m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v4]);

			snprintf(m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
					 ipa_l2_hdr_type[m_p_iface->rx_prop->rx[2].hdr_l2_type]);
			IPACMDBG_H("IPv6 routing table for flt name: %s\n", m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v6]);
		}
		else {
			snprintf(m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
				ipa_l2_hdr_type[m_p_iface->rx_prop->rx[0].hdr_l2_type]);
			IPACMDBG_H("IPv4 routing table for flt name: %s\n", m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v4]);

			snprintf(m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
				ipa_l2_hdr_type[m_p_iface->rx_prop->rx[0].hdr_l2_type]);
			IPACMDBG_H("IPv6 routing table for flt name: %s\n", m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v6]);
		}
	}

	memcpy(m_intra_interface_info.rt_tbl_name_for_rt[IPA_IP_v4], m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v4],
		IPA_RESOURCE_NAME_MAX);
	IPACMDBG_H("IPv4 routing table for rt name: %s\n", m_intra_interface_info.rt_tbl_name_for_rt[IPA_IP_v4]);
	memcpy(m_intra_interface_info.rt_tbl_name_for_rt[IPA_IP_v6], m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v6],
		IPA_RESOURCE_NAME_MAX);
	IPACMDBG_H("IPv6 routing table for rt name: %s\n", m_intra_interface_info.rt_tbl_name_for_rt[IPA_IP_v6]);

	m_p_iface->eth_bridge_add_hdr_proc_ctx(m_p_iface->tx_prop->tx[0].hdr_l2_type,
		hdr_proc_ctx_hdl, 0);
	hdr_proc_ctx_for_intra_interface = hdr_proc_ctx_hdl[0];
	IPACMDBG_H("Hdr proc ctx for intra-interface communication: hdl %d\n", hdr_proc_ctx_hdl[0]);

	return;
}

void IPACM_LanToLan_Iface::handle_self_interface_info()
{
	uint32_t hdr_proc_ctx_hdl[IPA_MAX_NUM_PROPS] = { 0 };

	if(m_p_iface->tx_prop == NULL || m_p_iface->rx_prop == NULL)
	{
		IPACMERR("No tx or rx prop.\n");
		return;
	}

	self.peer = this;
	IPACMDBG_H("Populate self iface info for: %s\n", this->get_iface_pointer()->dev_name);
	/* populate the routing table information */
	if (this->is_svap_iface() || this->is_ap_iface_vlan_enabled()) {
		snprintf(self.rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
					ipa_l2_hdr_type[m_p_iface->rx_prop->rx[2].hdr_l2_type]);
		IPACMDBG_H("IPv4 routing table for flt name: %s\n", self.rt_tbl_name_for_flt[IPA_IP_v4]);

		snprintf(self.rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
					ipa_l2_hdr_type[m_p_iface->rx_prop->rx[2].hdr_l2_type]);
		IPACMDBG_H("IPv6 routing table for flt name: %s\n", self.rt_tbl_name_for_flt[IPA_IP_v6]);
	}
	else {
		snprintf(self.rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_lan_to_lan_%s",
			ipa_l2_hdr_type[m_p_iface->rx_prop->rx[0].hdr_l2_type]);
		IPACMDBG_H("IPv4 routing table for flt name: %s\n", self.rt_tbl_name_for_flt[IPA_IP_v4]);

		snprintf(self.rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_lan_to_lan_%s",
			ipa_l2_hdr_type[m_p_iface->rx_prop->rx[0].hdr_l2_type]);
		IPACMDBG_H("IPv6 routing table for flt name: %s\n", self.rt_tbl_name_for_flt[IPA_IP_v6]);
	}
	memcpy(self.rt_tbl_name_for_rt[IPA_IP_v4], self.rt_tbl_name_for_flt[IPA_IP_v4],
		IPA_RESOURCE_NAME_MAX);
	IPACMDBG_H("IPv4 routing table for rt name: %s\n", self.rt_tbl_name_for_rt[IPA_IP_v4]);
	memcpy(self.rt_tbl_name_for_rt[IPA_IP_v6], self.rt_tbl_name_for_flt[IPA_IP_v6],
		IPA_RESOURCE_NAME_MAX);
	IPACMDBG_H("IPv6 routing table for rt name: %s\n", self.rt_tbl_name_for_rt[IPA_IP_v6]);
	return;
}

void IPACM_LanToLan_Iface::handle_new_iface_up(char rt_tbl_name_for_flt[][IPA_RESOURCE_NAME_MAX], char rt_tbl_name_for_rt[][IPA_RESOURCE_NAME_MAX],
		IPACM_LanToLan_Iface *peer_iface, int spcl_vlan_iface)
{
	peer_iface_info new_peer;
	ipa_hdr_l2_type peer_l2_hdr_type;

	if (!peer_iface) {
		IPACMERR("Invalid peer iface info\n");
		return;
	}
	IPACMDBG_H("This is iface %s,  m_is_vlan %d\n", this->get_iface_pointer()->dev_name, m_is_vlan);

	new_peer.peer = peer_iface;
	memcpy(new_peer.rt_tbl_name_for_rt[IPA_IP_v4], rt_tbl_name_for_rt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX);
	memcpy(new_peer.rt_tbl_name_for_rt[IPA_IP_v6], rt_tbl_name_for_rt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX);
	memcpy(new_peer.rt_tbl_name_for_flt[IPA_IP_v4], rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX);
	memcpy(new_peer.rt_tbl_name_for_flt[IPA_IP_v6], rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX);

	/* spcl_vlan_iface = 1 means that the interface needs to be treated as vlan supported and hence appropiate l2_hdr type
	   needs to be selected */
	if (peer_iface->is_svap_iface() || peer_iface->is_ap_iface_vlan_enabled() || (peer_iface->is_spcl_iface() && spcl_vlan_iface))
	{
		peer_l2_hdr_type = peer_iface->m_p_iface->tx_prop->tx[2].hdr_l2_type;
		new_peer.is_vlan_peer = true;
		IPACMDBG_H("Peer is vlan supported\n");
	}
	else {
		peer_l2_hdr_type = peer_iface->m_p_iface->tx_prop->tx[0].hdr_l2_type;
		new_peer.is_vlan_peer = false;
	}

	increment_ref_cnt_peer_l2_hdr_type(peer_l2_hdr_type);
	/* Skip adding hdr proc ctx for svap iface, will be performed during client add */
	if (!is_svap_iface() && !is_ap_iface_vlan_enabled() && !m_is_vlan) {
		add_hdr_proc_ctx(peer_l2_hdr_type);
	}


	/* is_vlan_peer is set to true for both the interfaces even if one of them is a special interface.
	   For example: ethii_to_802 and 802_to_eth both need be marked as vlan peer so that appropiate mac
	   based rules can be selected later */
	if (spcl_vlan_iface)
	{
		new_peer.is_vlan_peer = true;
	}
	if(m_is_sIface)
	{
		if(spcl_vlan_iface)
		{
			new_peer.eth_vlan_instance = IPA_HDR_L2_802_1Q; /* It is an 802_to_x peer */
			IPACMDBG_H("eth is vlan supported\n");
		}
		else{
			new_peer.eth_vlan_instance = IPA_HDR_L2_ETHERNET_II; /* It is an eth_to_x peer */
			IPACMDBG_H("eth is non vlan supported\n");
		}
	}
	new_peer.peer_hdr_type = peer_l2_hdr_type;
	/* push the new peer_iface_info into the list */
	m_peer_iface_info.push_front(new_peer);
	IPACMDBG_H("peer iface IsVlan %d and is_vlan_peer %d \n", m_is_vlan, new_peer.is_vlan_peer);

	return;
}

void IPACM_LanToLan_Iface::add_self_flt_rule_one_vlan_id(ipa_ip_type iptype, uint16_t vlan_id)
{
	list<client_info>::iterator it_client;
	/* go over all peers (must be vlan interfaces) */
	IPACMDBG_H("Add flt rules for clients of interface %s.\n", self.peer->get_iface_pointer()->dev_name);

	/* look for specific client with this vlan id */
	for(it_client = self.peer->m_client_info.begin(); it_client != self.peer->m_client_info.end(); it_client++)
	{
		if ((vlan_id == it_client->vlan_id) || ((IPACM_Iface::ipacmcfg->ipacm_emesh_mode >= 2) && (self.peer->get_m_support_inter_iface_offload())))
			add_client_flt_rule(&self, &(*it_client), iptype);
	}

}

void IPACM_LanToLan_Iface::del_self_flt_rule_one_vlan_id(uint16_t vlan_id)
{
	list<client_info>::iterator it_client;

	IPACMDBG_H("del flt rules for clients of interface %s with vlan id %d.\n", self.peer->get_iface_pointer()->dev_name, vlan_id);

	/* look for specific client with this vlan id */
	for(it_client = self.peer->m_client_info.begin(); it_client != self.peer->m_client_info.end(); it_client++)
	{
		if(vlan_id == it_client->vlan_id)
			del_client_flt_rule(&self, &(*it_client));
	}
}

void IPACM_LanToLan_Iface::handle_client_add(uint8_t *mac, char *iface_name, bool is_l2tp_client, l2tp_vlan_mapping_info *mapping_info, uint16_t vlan_id)
{
	list<client_info>::iterator it_client;
	list<client_info>::iterator del_it_client;
	list<peer_iface_info>::iterator it_peer_info;
	list<peer_iface_info>::iterator re_it_peer_info;
	client_info new_client, inter_client;
	ipa_ioc_get_rt_tbl rt_tbl;
	struct ipa_ioc_add_rt_rule* rt_rule_table = NULL;
	struct ipa_rt_rule_add rt_rule;
	bool flag[IPA_HDR_L2_MAX];
	ipa_hdr_l2_type l2_hdr_type;
	list<flt_rule_info>::iterator it_flt;
	struct ipa_bridge_vlan_mapping_info peer_bridge_info, client_iface_bridge_info;
	char client_iface_name[IPA_RESOURCE_NAME_MAX] = {'\0'};
	char peer_iface_name[IPA_RESOURCE_NAME_MAX] = {'\0'};
	uint16_t vIds[IPA_MAX_NUM_OFFLOAD_VLANS];
	int i, ret = IPACM_SUCCESS;
	uint32_t ipv6_prefix_vlanid[2] = {0};
	uint32_t this_ipv6_prefix_vlanid[2] = {0};
	uint32_t peer_ipv6_prefix_vlanid[2] = {0};

	IPACMDBG_H("Incoming client MAC: 0x%02x%02x%02x%02x%02x%02x, interface: %s on vlan_id %d\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], iface_name, vlan_id);

	for(it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
	{
		if((memcmp(it_client->mac_addr, mac, sizeof(it_client->mac_addr)) == 0)
#ifdef FEATURE_VLAN_MPDN
			&& (((IPACM_Iface::ipacmcfg->ipacm_mpdn_enable && m_is_vlan && (it_client->vlan_id == vlan_id))) ||
			!IPACM_Iface::ipacmcfg->ipacm_mpdn_enable || !m_is_vlan)
#endif
			)
		{
			if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
			{
				IPACMDBG_H("This client has been added before checking for v6 filter rule hdl.\n");
				/*as routes and v4 rule has been added before skip adding again.*/
				/* When bridge get v6 prefix add prefix based src mac rule */
				for(it_flt = self.flt_rule.begin(); it_flt != self.flt_rule.end(); it_flt++)
				{
					if (it_flt->flt_rule_hdl[IPA_IP_v6] && (memcmp(it_flt->p_client->mac_addr, mac, sizeof(it_flt->p_client->mac_addr)) == 0)
						&& (vlan_id == it_flt->p_client->vlan_id))
					{
						IPACMDBG_H("This client has been added and v6 filter rule also added before.\n");
						return;
					}
					else if(memcmp(it_flt->p_client->mac_addr, mac, sizeof(it_flt->p_client->mac_addr)) == 0)
					{
						IPACMDBG_H("is_l2tp_client: %d, mapping_info: %p, vlan id %d, is l2tp enable: %d\n",
							is_l2tp_client, mapping_info, vlan_id, IPACM_Iface::ipacmcfg->ipacm_l2tp_enable);
						if(m_is_ip_addr_assigned[IPA_IP_v6])
						{
							if(this->m_is_vlan)
							{
								if(IPACM_Iface::ipacmcfg->get_ipv6_prefix_for_vlan_id(vlan_id,ipv6_prefix_vlanid) != true)
								{
									IPACMERR("Lan2Lan_v2_IPA_IP_v6: failed to get v6 prefix for vlan id %d\n",vlan_id);
									return;
								}
							}
							else
							{
								vlan_id = 0;
								if(IPACM_Wan::GetV6PrefixByVid(vlan_id, ipv6_prefix_vlanid))
								{
									IPACMDBG_H("Couldn't get prefix for vid: %d\n", vlan_id);
									return;
								}
								else
								{
									IPACMDBG_H("prefix 0x[%X][%X] is ipv6 prefix for vlan id %d\n", ipv6_prefix_vlanid[0], ipv6_prefix_vlanid[1], vlan_id);
								}
							}
							IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6: vlan_id %d has perfix 0x%x:%x:%x:%x\n", vlan_id, ipv6_prefix_vlanid[0], ipv6_prefix_vlanid[1]);

							memcpy(it_client->ipv6_prefix, ipv6_prefix_vlanid, sizeof(it_client->ipv6_prefix));
							IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6: vlan_id %d prefix Queried and Copied to it_client.\n", vlan_id);
							rt_tbl.ip = IPA_IP_v6;
							memcpy(rt_tbl.name, self.rt_tbl_name_for_flt[rt_tbl.ip], sizeof(rt_tbl.name));
							if(IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false)
							{
								m_p_iface->add_dummy_routing_rule_lan2lan(rt_tbl.name,rt_tbl.ip);
							}
							IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6:  For Intra bridge offload (v6) flt rule. m_is_vlan %d \n", m_is_vlan);
							ret = add_client_flt_rule(&self, &(*it_client), IPA_IP_v6);
							if(ret == IPACM_FAILURE)
							{
								IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
							}
							for(re_it_peer_info = m_peer_iface_info.begin(); re_it_peer_info != m_peer_iface_info.end(); re_it_peer_info++)
							{
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6: Allow Peers to install (v6) flt rule for new client.\n");
								ret = re_it_peer_info->peer->add_peer_bridge_flt_rule(it_flt->bridge_ipv4, it_flt->subnet_mask, IPA_IP_v6, ipv6_prefix_vlanid);
								if(ret == IPACM_FAILURE)
								{
									IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
								}
							}
							if(this->m_is_vlan)
							{
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6: If New client is vlan, Allow self Peers vlan id to install (v6) flt rule for new client.\n");
								ret = add_peer_bridge_flt_rule(it_flt->bridge_ipv4, it_flt->subnet_mask, IPA_IP_v6, ipv6_prefix_vlanid);
								if(ret == IPACM_FAILURE)
								{
									IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
								}
							}
							IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6: This %s : Number of peer %d \n", this->get_iface_pointer()->dev_name, m_peer_iface_info.size());
							for(it_peer_info = m_peer_iface_info.begin(); it_peer_info != m_peer_iface_info.end(); it_peer_info++)
							{
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 : printing: peer %s \n",it_peer_info->peer->get_iface_pointer()->dev_name);
							}
							for(it_peer_info = m_peer_iface_info.begin(); it_peer_info != m_peer_iface_info.end(); it_peer_info++)
							{
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 : peer %s \n",it_peer_info->peer->get_iface_pointer()->dev_name);
								/*avoid installing rule 2 times in case of spcl_iface*/
								if (it_peer_info->peer->is_spcl_iface() && ((it_client->vlan_id && it_peer_info->peer_hdr_type == IPA_HDR_L2_ETHERNET_II) || (it_client->vlan_id == 0 && it_peer_info->peer_hdr_type == IPA_HDR_L2_802_1Q)))
								{
									IPACMDBG_H("siface mismatch client vlanid %d and l2 peer type%d \n", it_client->vlan_id, it_peer_info->peer_hdr_type);
									continue;
								}
								if (is_spcl_iface() && ((it_client->vlan_id && it_peer_info->eth_vlan_instance == IPA_HDR_L2_ETHERNET_II) || (it_client->vlan_id == 0 && it_peer_info->eth_vlan_instance == IPA_HDR_L2_802_1Q)))
								{
									IPACMDBG_H("siface mismatch client vlanid %d and l2 peer type%d \n", it_client->vlan_id, it_peer_info->eth_vlan_instance);
									continue;
								}

								rt_tbl.ip = IPA_IP_v6;
								memcpy(rt_tbl.name, IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v6.name, sizeof(IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v6));
								if(IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false)
								{
									if (IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v6_set == false)
									{
										m_p_iface->add_dummy_routing_rule_lan2lan(rt_tbl.name, rt_tbl.ip);
										IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v6_set = true;
									}
								}
								/* if this is vlan and peer is non vlan then enable inter_bridge */
								if(this->m_is_vlan && !IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
								{
									IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :if this is vlan and peer is non vlan then enable inter_bridge\n");
									/* Get prefix info for this and peer iface */
									if(this->m_is_vlan)
									{
										if(IPACM_Iface::ipacmcfg->get_ipv6_prefix_for_vlan_id(vlan_id,this_ipv6_prefix_vlanid) != true)
										{
											IPACMERR("Lan2Lan_v2_IPA_IP_v6: failed to get v6 prefix for vlan id %d\n",vlan_id);
											return;
										}
										IPACMDBG_H("This has prefix 0x[%X][%X] for vlan id %d\n", this_ipv6_prefix_vlanid[0], this_ipv6_prefix_vlanid[1], vlan_id);
										memcpy(it_client->ipv6_prefix, this_ipv6_prefix_vlanid, sizeof(it_client->ipv6_prefix));
									}
									if(!IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
									{
										vlan_id = 0;
										if(IPACM_Wan::GetV6PrefixByVid(vlan_id, peer_ipv6_prefix_vlanid))
										{
											IPACMDBG_H("Couldn't get prefix for vid: %d\n", vlan_id);
											return;
										}
										else
										{
											IPACMDBG_H("Peer has prefix 0x[%X][%X] for vlan id %d\n", peer_ipv6_prefix_vlanid[0], peer_ipv6_prefix_vlanid[1], vlan_id);
										}
									}
									IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :Compare Prefix between this and peer prefix \n");
									/* Compare if need to install Inter bridge rule for this_client_add and peer_iface */
									if((this_ipv6_prefix_vlanid[0] == peer_ipv6_prefix_vlanid[0]) && (this_ipv6_prefix_vlanid[1] == peer_ipv6_prefix_vlanid[1]))
									{
										IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 : Same Prefix ignore Inter bridge flt rule \n");
										return;
									}
									else
									{
										IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 : Install Inter bridge offload flt rule on self for client v6 prefix\n");
										ret = add_client_flt_rule(&self, &(*it_client), IPA_IP_v6, true);
										if(ret == IPACM_FAILURE)
										{
											IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
										}
										IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :re_it_peer_info size %d \n",m_peer_iface_info.size());
										for(re_it_peer_info = m_peer_iface_info.begin(); re_it_peer_info != m_peer_iface_info.end(); re_it_peer_info++)
										{
											IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :Allow Peers to install flt rule for new client.\n");
											ret = re_it_peer_info->peer->add_peer_bridge_flt_rule(it_client->bridge_ipv4, it_client->subnet_mask, IPA_IP_v6, peer_ipv6_prefix_vlanid);
											if(ret == IPACM_FAILURE)
											{
												IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
											}
										{
											IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
										}
										}
										ret = add_peer_bridge_flt_rule(it_client->bridge_ipv4, it_client->subnet_mask, IPA_IP_v6, peer_ipv6_prefix_vlanid);
										if(ret == IPACM_FAILURE)
										{
											IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
										}
									}
								}

								/* if this is non-vlan and peer is vlan then enable inter_bridge */
								if(!this->m_is_vlan && IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
								{
									IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :if this is non-vlan and peer is vlan then enable inter_bridge\n");
									/* Get prefix info for this and peer iface */
									if(!this->m_is_vlan)
									{
										vlan_id = 0;
										if(IPACM_Wan::GetV6PrefixByVid(vlan_id, this_ipv6_prefix_vlanid))
										{
											IPACMDBG_H("Couldn't get prefix for vid: %d\n", vlan_id);
											return;
										}
										else
										{
											IPACMDBG_H("This has prefix 0x[%X][%X] for vlan id %d\n", this_ipv6_prefix_vlanid[0], this_ipv6_prefix_vlanid[1], vlan_id);
											memcpy(it_client->ipv6_prefix, this_ipv6_prefix_vlanid, sizeof(it_client->ipv6_prefix));
										}
									}
									for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
									{
										if(vIds[i] != 0)
										{
											IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :vlan id %d \n", vIds[i]);
											snprintf(peer_iface_name,IPA_RESOURCE_NAME_MAX,"%s%s%d",it_peer_info->peer->get_iface_pointer()->dev_name,".",vIds[i]);
										}
										if(vIds[i] == 0)
											break;

										if(IPACM_Iface::ipacmcfg->get_ipv6_prefix_for_vlan_id(vIds[i],peer_ipv6_prefix_vlanid) != true)
										{
											IPACMERR("Lan2Lan_v2_IPA_IP_v6: failed to get v6 prefix for vlan id %d\n",vIds[i]);
											continue;
										}
										IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :Peer has prefix 0x[%X][%X] for vlan id %d\n", peer_ipv6_prefix_vlanid[0], peer_ipv6_prefix_vlanid[1], vIds[i]);
										if((this_ipv6_prefix_vlanid[0] == peer_ipv6_prefix_vlanid[0]) && (this_ipv6_prefix_vlanid[1] == peer_ipv6_prefix_vlanid[1]))
										{
											IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 : Same Prefix ignore Inter bridge flt rule \n");
											continue;
										}
										else
										{
											IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 : Install Inter bridge offload flt rule on self for client with dest v6 prefix\n");
											ret = add_client_flt_rule(&self, &(*it_client), IPA_IP_v6, true);
											if(ret == IPACM_FAILURE)
											{
												IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
											}
											IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :re_it_peer_info size %d \n",m_peer_iface_info.size());
											for(re_it_peer_info = m_peer_iface_info.begin(); re_it_peer_info != m_peer_iface_info.end(); re_it_peer_info++)
											{
												IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :Allow Peers to install flt rule for new client.\n");
												ret = re_it_peer_info->peer->add_peer_bridge_flt_rule(it_client->bridge_ipv4, it_client->subnet_mask, IPA_IP_v6, peer_ipv6_prefix_vlanid);
												if(ret == IPACM_FAILURE)
												{
													IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
												}
											}
										}
									}
								}

								/* if this is vlan and peer is vlan then enable inter_bridge */
								if(this->m_is_vlan && IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
								{
									IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :if this is vlan and peer is vlan then enable inter_bridge\n");
									/* Get prefix info for this and peer iface */
									if(this->m_is_vlan)
									{
										if(IPACM_Iface::ipacmcfg->get_ipv6_prefix_for_vlan_id(vlan_id,this_ipv6_prefix_vlanid) != true)
										{
											IPACMERR("Lan2Lan_v2_IPA_IP_v6: failed to get v6 prefix for vlan id %d\n",vlan_id);
											return;
										}
										IPACMDBG_H("This has prefix 0x[%X][%X] for vlan id %d\n", this_ipv6_prefix_vlanid[0], this_ipv6_prefix_vlanid[1], vlan_id);
										memcpy(it_client->ipv6_prefix, this_ipv6_prefix_vlanid, sizeof(it_client->ipv6_prefix));
									}
									for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
									{
										if(vIds[i] != 0)
										{
											IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :vlan id %d \n", vIds[i]);
											snprintf(peer_iface_name,IPA_RESOURCE_NAME_MAX,"%s%s%d",it_peer_info->peer->get_iface_pointer()->dev_name,".",vIds[i]);
										}
										if(vIds[i] == 0)
											break;

										if(IPACM_Iface::ipacmcfg->get_ipv6_prefix_for_vlan_id(vIds[i],peer_ipv6_prefix_vlanid) != true)
										{
											IPACMERR("Lan2Lan_v2_IPA_IP_v6: failed to get v6 prefix for vlan id %d\n",vIds[i]);
											continue;
										}
										IPACMDBG_H("Peer has prefix 0x[%X][%X] for vlan id %d\n", peer_ipv6_prefix_vlanid[0], peer_ipv6_prefix_vlanid[1], vIds[i]);
										if((this_ipv6_prefix_vlanid[0] == peer_ipv6_prefix_vlanid[0]) && (this_ipv6_prefix_vlanid[1] == peer_ipv6_prefix_vlanid[1]))
										{
											IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 : Same Prefix ignore Inter bridge flt rule \n");
											continue;
										}
										else
										{
											IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 : Install Inter bridge offload flt rule on self for client with v6 prefix\n");
											ret = add_client_flt_rule(&self, &(*it_client), IPA_IP_v6, true);
											if(ret == IPACM_FAILURE)
											{
												IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
											}
											IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :re_it_peer_info size %d \n",m_peer_iface_info.size());
											for(re_it_peer_info = m_peer_iface_info.begin(); re_it_peer_info != m_peer_iface_info.end(); re_it_peer_info++)
											{
												IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :Allow Peers to install flt rule for new client.\n");
												ret = re_it_peer_info->peer->add_peer_bridge_flt_rule(it_client->bridge_ipv4, it_client->subnet_mask, IPA_IP_v6, peer_ipv6_prefix_vlanid);
												if(ret == IPACM_FAILURE)
												{
													IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
												}
											}
											ret = add_peer_bridge_flt_rule(it_client->bridge_ipv4, it_client->subnet_mask, IPA_IP_v6, peer_ipv6_prefix_vlanid);
											if(ret == IPACM_FAILURE)
											{
												IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
											}
										}
									}
								}

								/* if this is non-vlan and peer is non-vlan then not to enable inter_bridge */
								if(!this->m_is_vlan && !IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
								{
									IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :Both are on Same bridge : No Need of Inter bridge flt rule. for both nonvlan/non-vlan \n");
								}
							}
							if(this->m_is_vlan)
							{
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :Check If any subnet prefix rule left on Self.\n");
								add_bridge_self_vlan_client(&(*it_client), IPA_IP_v6);
							}
						}
					}
					else
					{
						IPACMDBG_H("Cant find client\n");
					}
					return;
				}
			}
			else
			{
				IPACMDBG_H("This client has been added before.\n");
				return;
			}
		}
	}

	if(m_client_info.size() == max_num_clients)
	{
		IPACMDBG_H("The number of clients has reached maximum %d.\n", max_num_clients);
		return;
	}

	IPACMDBG_H("is_l2tp_client: %d, mapping_info: %p, vlan id %d, is l2tp enable: %d\n",
		is_l2tp_client, mapping_info, vlan_id, IPACM_Iface::ipacmcfg->ipacm_l2tp_enable);
	memset(&new_client, 0, sizeof(new_client));
	memcpy(new_client.mac_addr, mac, sizeof(new_client.mac_addr));
	new_client.is_l2tp_client = is_l2tp_client;
	new_client.mapping_info = mapping_info;
	new_client.vlan_id = vlan_id;
	IPACMDBG_H("Incoming New client MAC: 0x%02x%02x%02x%02x%02x%02x, interface: %s on vlan_id %d\n",
		new_client.mac_addr[0], new_client.mac_addr[1], new_client.mac_addr[2],new_client.mac_addr[3],
		new_client.mac_addr[4], new_client.mac_addr[5], iface_name, vlan_id);
	if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
	{
		if(vlan_id)
		{
			snprintf(client_iface_name,IPA_RESOURCE_NAME_MAX,"%s%s%d",iface_name,".",vlan_id);
		}
		else
		{
			snprintf(client_iface_name,IPA_RESOURCE_NAME_MAX,"%s",iface_name);
		}
		/* Get bridge info for new client add irrespective if vlan or non-vlan */
		if (IPACM_Iface::ipacmcfg->get_bridge_info_iface(client_iface_name, &client_iface_bridge_info) != IPACM_SUCCESS)
		{
			if(IPACM_Iface::ipacmcfg->get_iface_category(iface_name) == WLAN_IF)
			{
				if(IPACM_Iface::ipacmcfg->get_bridge_info_iface_wlan_mld(iface_name, &client_iface_bridge_info) != IPACM_SUCCESS)
				{
					IPACMERR("failed to query mld bridge details for %s\n", iface_name);
					return;
				}
			}
			else
			{
				IPACMERR("failed to query bridge details for %s\n", iface_name);
				return;
			}
			strlcpy(new_client.iface_name, iface_name, IPA_IFACE_NAME_LEN);
			new_client.bridge_ipv4 = client_iface_bridge_info.bridge_ipv4;
			new_client.subnet_mask = client_iface_bridge_info.subnet_mask;
		}
		else
		{
			strlcpy(new_client.iface_name, client_iface_name, IPA_IFACE_NAME_LEN);
			strlcpy(new_client.iface_bridge_name, client_iface_bridge_info.bridge_name, IPA_RESOURCE_NAME_MAX);
			new_client.bridge_ipv4 = client_iface_bridge_info.bridge_ipv4;
			new_client.subnet_mask = client_iface_bridge_info.subnet_mask;
		}
		IPACMDBG_H(" Client_add on iface %s bridge name %s \n", iface_name, client_iface_bridge_info.bridge_name);
		IPACMDBG_H(" Client iface %s bridge name %s \n", client_iface_name, client_iface_bridge_info.bridge_name);
	}

	m_client_info.push_front(new_client);

	client_info &front_client = m_client_info.front();

	/* install inter-interface rules */
	if(m_support_inter_iface_offload)
	{
		memset(flag, 0, sizeof(flag));
		if(m_peer_iface_info.empty())
			IPACMDBG_H("empty peer list for dev %s.\n", this->get_iface_pointer()->dev_name);

		for(it_peer_info = m_peer_iface_info.begin(); it_peer_info != m_peer_iface_info.end(); it_peer_info++)
		{
			if (it_peer_info->peer->is_svap_iface() || it_peer_info->peer->is_ap_iface_vlan_enabled() || (it_peer_info->peer->is_spcl_iface() && it_peer_info->is_vlan_peer))
				l2_hdr_type = it_peer_info->peer->get_iface_pointer()->rx_prop->rx[2].hdr_l2_type;
			else
				l2_hdr_type = it_peer_info->peer->get_iface_pointer()->rx_prop->rx[0].hdr_l2_type;

			if(l2_hdr_type >= IPA_HDR_L2_MAX || l2_hdr_type < 0)
			{
				IPACMDBG_H("Invalid l2_hdr_type: %d\n", l2_hdr_type);
				return;
			}
			IPACMDBG_H("l2_hdr_type : %d flag : %d \n",l2_hdr_type,flag[l2_hdr_type]  );
			/* make sure add routing rule only once for each peer l2 header type */
			if (flag[l2_hdr_type] == false || is_spcl_iface())
			{
				/* add client routing rule for each peer interface */
				if (front_client.is_l2tp_client == false)
				{
					IPACMDBG_H("Lan2Lan_v2: Add rt rule for client with %s \n",it_peer_info->peer->get_iface_pointer()->dev_name);
					add_client_rt_rule(&(*it_peer_info), &front_client);
				}
#ifdef FEATURE_L2TP
				if (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP)
				{
					/* add l2tp rt rules */
					add_l2tp_client_rt_rule(&(*it_peer_info), &front_client);
				}
#endif
				flag[l2_hdr_type] = true;
			}

			/* add client filtering rule on peer interfaces */
			if (!it_peer_info->peer->get_m_support_ast_update() && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
				it_peer_info->peer->add_one_client_flt_rule(this, &front_client,l2_hdr_type);

#ifdef FEATURE_L2TP
#ifdef IPA_L2TP_TUNNEL_UDP
			/* Update the rules for the client with new mapping. */
			if(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP && m_is_l2tp_iface &&
				is_l2tp_client && (mapping_info->tunnel_type == IPA_L2TP_TUNNEL_UDP))
			{
				add_l2tp_udp_client_rules_new_mapping(&(*it_peer_info), mapping_info);
			}
#endif
#endif

		}
	}

	/* install intra-interface rules */
	if(m_support_intra_iface_offload && IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == false)
	{
		/* add routing rule first */
		add_client_rt_rule(&m_intra_interface_info, &front_client);

		/* add filtering rule */
		if(m_is_ip_addr_assigned[IPA_IP_v4] && !get_m_support_ast_update())
		{
			add_client_flt_rule(&m_intra_interface_info, &front_client, IPA_IP_v4);
		}
		if(m_is_ip_addr_assigned[IPA_IP_v6] && !get_m_support_ast_update())
		{
			add_client_flt_rule(&m_intra_interface_info, &front_client, IPA_IP_v6);
		}
	}

	if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
	{
		if(!self.peer->get_m_support_ast_update() && m_support_inter_iface_offload)
		{
			if(m_is_ip_addr_assigned[IPA_IP_v4])
			{
				rt_tbl.ip = IPA_IP_v4;
				memcpy(rt_tbl.name, self.rt_tbl_name_for_flt[rt_tbl.ip], sizeof(rt_tbl.name));
				if(m_is_sIface)
				{
					memcpy(rt_tbl.name, IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v4.name, sizeof(IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v4));
					IPACMDBG_H("Overwriting v4 rt table to inter only if m_is_sIface ? %d \n", m_is_sIface);
				}
				if(IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false)
				{
					m_p_iface->add_dummy_routing_rule_lan2lan(rt_tbl.name, rt_tbl.ip);
				}
				IPACMDBG_H(" For Intra bridge offload v4 flt rule. m_is_vlan %d \n", m_is_vlan);
				ret = add_client_flt_rule(&self, &front_client, IPA_IP_v4);
				if(ret == IPACM_FAILURE)
				{
					IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
					goto erase_client;
				}
				for(re_it_peer_info = m_peer_iface_info.begin(); re_it_peer_info != m_peer_iface_info.end(); re_it_peer_info++)
				{
					IPACMDBG_H("Allow Peers to install flt rule for new client.\n");
					ret = re_it_peer_info->peer->add_peer_bridge_flt_rule(front_client.bridge_ipv4, front_client.subnet_mask, IPA_IP_v4, front_client.ipv6_prefix);
					if(ret == IPACM_FAILURE)
					{
						IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
					}
				}
				if(this->m_is_vlan)
				{
					IPACMDBG_H("New client is vlan, Allow self Peers vlan id to install flt rule for new client.\n");
					ret = add_peer_bridge_flt_rule(front_client.bridge_ipv4, front_client.subnet_mask, IPA_IP_v4, front_client.ipv6_prefix);
					if(ret == IPACM_FAILURE)
					{
						IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
					}
				}

				IPACMDBG_H("Lan2Lan_v2: This %s : Number of peer %d \n", this->get_iface_pointer()->dev_name, m_peer_iface_info.size());
				for(it_peer_info = m_peer_iface_info.begin(); it_peer_info != m_peer_iface_info.end(); it_peer_info++)
				{
					IPACMDBG_H("Lan2Lan_v2 :printing: peer %s \n",it_peer_info->peer->get_iface_pointer()->dev_name);
				}
				for(it_peer_info = m_peer_iface_info.begin(); it_peer_info != m_peer_iface_info.end(); it_peer_info++)
				{
					IPACMDBG_H("Lan2Lan_v2 : peer %s \n",it_peer_info->peer->get_iface_pointer()->dev_name);
					/*avoid installing rule 2 times in case of spcl_iface*/
					if (it_peer_info->peer->is_spcl_iface() && ((front_client.vlan_id && it_peer_info->peer_hdr_type == IPA_HDR_L2_ETHERNET_II) || (front_client.vlan_id == 0 && it_peer_info->peer_hdr_type == IPA_HDR_L2_802_1Q)))
					{
						IPACMDBG_H("siface mismatch client vlanid %d and l2 peer type%d \n", front_client.vlan_id, it_peer_info->peer_hdr_type);
						continue;
					}
					if (is_spcl_iface() && ((front_client.vlan_id && it_peer_info->eth_vlan_instance == IPA_HDR_L2_ETHERNET_II) || (front_client.vlan_id == 0 && it_peer_info->eth_vlan_instance == IPA_HDR_L2_802_1Q)))
					{
						IPACMDBG_H("siface mismatch client vlanid %d and l2 peer type%d \n", front_client.vlan_id, it_peer_info->eth_vlan_instance);
						continue;
					}
					rt_tbl.ip = IPA_IP_v4;
					memcpy(rt_tbl.name, IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v4.name, sizeof(IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v4));
					if(IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false)
					{
						if (IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v4_set == false)
						{
							m_p_iface->add_dummy_routing_rule_lan2lan(rt_tbl.name, rt_tbl.ip);
							IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v4_set = true;
						}
					}
					/* if this is vlan and peer is non vlan then enable inter_bridge */
					if(this->m_is_vlan && !IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
					{
						IPACMDBG_H("if this is vlan and peer is non vlan then enable inter_bridge\n");
						/* Get bridge info for peer iface */
						if (IPACM_Iface::ipacmcfg->get_bridge_info_iface(it_peer_info->peer->get_iface_pointer()->dev_name, &peer_bridge_info) != IPACM_SUCCESS)
						{
							if(IPACM_Iface::ipacmcfg->get_iface_category(it_peer_info->peer->get_iface_pointer()->dev_name) == WLAN_IF)
							{
								if(IPACM_Iface::ipacmcfg->get_bridge_info_iface_wlan_mld(it_peer_info->peer->get_iface_pointer()->dev_name, &peer_bridge_info) != IPACM_SUCCESS)
								{
									IPACMERR("failed to query mld bridge details\n");
									return;
								}
							}
							else
							{
								IPACMERR("failed to query  %s bridge details\n", it_peer_info->peer->get_iface_pointer()->dev_name);
								return;
							}
						}
						/* Compare if need to install Inter bridge rule for new_client_add and peer_iface */
						if(memcmp(front_client.iface_bridge_name, peer_bridge_info.bridge_name, IPA_RESOURCE_NAME_MAX) == 0)
						{
							IPACMDBG_H(" No Need of Inter bridge flt rule \n");
						}
						else
						{
							memset(&inter_client, 0, sizeof(inter_client));
							memcpy(inter_client.mac_addr, mac, sizeof(inter_client.mac_addr));
							inter_client.is_l2tp_client = is_l2tp_client;
							inter_client.mapping_info = mapping_info;
							inter_client.vlan_id = new_client.vlan_id;
							inter_client.bridge_ipv4 = peer_bridge_info.bridge_ipv4 ;
							inter_client.subnet_mask = peer_bridge_info.subnet_mask;
							ret = add_client_flt_rule(&self, &inter_client, IPA_IP_v4, true);
							if(ret == IPACM_FAILURE)
							{
								IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
							}
							IPACMDBG_H("re_it_peer_info size %d \n",m_peer_iface_info.size());
							for(re_it_peer_info = m_peer_iface_info.begin(); re_it_peer_info != m_peer_iface_info.end(); re_it_peer_info++)
							{
								IPACMDBG_H("Allow Peers to install flt rule for new client.\n");
								ret = re_it_peer_info->peer->add_peer_bridge_flt_rule(inter_client.bridge_ipv4, inter_client.subnet_mask, IPA_IP_v4, inter_client.ipv6_prefix);
								if(ret == IPACM_FAILURE)
								{
									IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
								}
							}
							ret = add_peer_bridge_flt_rule(inter_client.bridge_ipv4, inter_client.subnet_mask, IPA_IP_v4, inter_client.ipv6_prefix);
							if(ret == IPACM_FAILURE)
							{
								IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
							}
						}
					}

					/* if this is non-vlan and peer is vlan then enable inter_bridge */
					if(!this->m_is_vlan && IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
					{
						IPACMDBG_H("if this is non-vlan and peer is vlan then enable inter_bridge\n");
						/* Get bridge info for peer iface */
						if(IPACM_Iface::ipacmcfg->get_iface_vlan_ids(it_peer_info->peer->get_iface_pointer()->dev_name, vIds))
						{
							IPACMERR("failed getting vlan ids for iface %s\n", it_peer_info->peer->get_iface_pointer()->dev_name);
							return;
						}
						for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
						{
							if(vIds[i] != 0)
							{
								IPACMDBG_H("vlan id %d \n", vIds[i]);
								snprintf(peer_iface_name,IPA_RESOURCE_NAME_MAX,"%s%s%d",it_peer_info->peer->get_iface_pointer()->dev_name,".",vIds[i]);
							}
							if(vIds[i] == 0)
								break;

							if (IPACM_Iface::ipacmcfg->get_bridge_info_iface(peer_iface_name, &peer_bridge_info) != IPACM_SUCCESS)
							{
								if(IPACM_Iface::ipacmcfg->get_iface_category(peer_iface_name) == WLAN_IF)
								{
									if(IPACM_Iface::ipacmcfg->get_bridge_info_iface_wlan_mld(peer_iface_name, &peer_bridge_info) != IPACM_SUCCESS)
									{
										IPACMERR("failed to query mld bridge details\n");
										return;
									}
								}
								else
								{
									IPACMERR("failed to query  %s bridge details\n", peer_iface_name);
									return;
								}
							}
							/* Compare if need to install Inter bridge rule for new_client_add and peer_iface */
							if(memcmp(front_client.iface_bridge_name, peer_bridge_info.bridge_name, IPA_RESOURCE_NAME_MAX) == 0)
							{
								IPACMDBG_H(" No Need of Inter bridge flt rule \n");
							}
							else
							{
								memset(&inter_client, 0, sizeof(inter_client));
								memcpy(inter_client.mac_addr, mac, sizeof(inter_client.mac_addr));
								inter_client.is_l2tp_client = is_l2tp_client;
								inter_client.mapping_info = mapping_info;
								inter_client.vlan_id = 0;
								inter_client.bridge_ipv4 = peer_bridge_info.bridge_ipv4 ;
								inter_client.subnet_mask = peer_bridge_info.subnet_mask;
								ret = add_client_flt_rule(&self, &inter_client, IPA_IP_v4, true);
								if(ret == IPACM_FAILURE)
								{
									IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
								}
								IPACMDBG_H("re_it_peer_info size %d \n",m_peer_iface_info.size());
								for(re_it_peer_info = m_peer_iface_info.begin(); re_it_peer_info != m_peer_iface_info.end(); re_it_peer_info++)
								{
									IPACMDBG_H("Allow Peers to install flt rule for new client.\n");
									ret = re_it_peer_info->peer->add_peer_bridge_flt_rule(inter_client.bridge_ipv4, inter_client.subnet_mask, IPA_IP_v4, inter_client.ipv6_prefix);
									if(ret == IPACM_FAILURE)
									{
										IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
									}
								}
							}
						}
					}

					/* if this is vlan and peer is vlan then enable inter_bridge */
					if(this->m_is_vlan && IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
					{
						IPACMDBG_H("if this is vlan and peer is vlan then enable inter_bridge\n");
						/* Get bridge info for peer iface */
						if(IPACM_Iface::ipacmcfg->get_iface_vlan_ids(it_peer_info->peer->get_iface_pointer()->dev_name, vIds))
						{
							IPACMERR("failed getting vlan ids for iface %s\n", it_peer_info->peer->get_iface_pointer()->dev_name);
							return;
						}
						for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
						{
							if(vIds[i] != 0)
							{
								IPACMDBG_H("vlan id %d \n", vIds[i]);
								snprintf(peer_iface_name,IPA_RESOURCE_NAME_MAX,"%s%s%d",it_peer_info->peer->get_iface_pointer()->dev_name,".",vIds[i]);
							}
							if(vIds[i] == 0)
								break;

							if (IPACM_Iface::ipacmcfg->get_bridge_info_iface(peer_iface_name, &peer_bridge_info) != IPACM_SUCCESS)
							{
								if(IPACM_Iface::ipacmcfg->get_iface_category(peer_iface_name) == WLAN_IF)
								{
									if(IPACM_Iface::ipacmcfg->get_bridge_info_iface_wlan_mld(peer_iface_name, &peer_bridge_info) != IPACM_SUCCESS)
									{
										IPACMERR("failed to query mld bridge details\n");
										return;
									}
								}
								else
								{
									IPACMERR("failed to query  %s bridge details\n", peer_iface_name);
									return;
								}
							}
							/* Compare if need to install Inter bridge rule for new_client_add and peer_iface */
							if(memcmp(front_client.iface_bridge_name, peer_bridge_info.bridge_name, IPA_RESOURCE_NAME_MAX) == 0)
							{
								IPACMDBG_H(" No Need of Inter bridge flt rule \n");
							}
							else
							{
								memset(&inter_client, 0, sizeof(inter_client));
								memcpy(inter_client.mac_addr, mac, sizeof(inter_client.mac_addr));
								inter_client.is_l2tp_client = is_l2tp_client;
								inter_client.mapping_info = mapping_info;
								inter_client.vlan_id = new_client.vlan_id;
								inter_client.bridge_ipv4 = peer_bridge_info.bridge_ipv4 ;
								inter_client.subnet_mask = peer_bridge_info.subnet_mask;
								ret = add_client_flt_rule(&self, &inter_client, IPA_IP_v4, true);
								if(ret == IPACM_FAILURE)
								{
									IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
								}
								IPACMDBG_H("re_it_peer_info size %d \n",m_peer_iface_info.size());
								for(re_it_peer_info = m_peer_iface_info.begin(); re_it_peer_info != m_peer_iface_info.end(); re_it_peer_info++)
								{
									IPACMDBG_H("Allow Peers to install flt rule for new client.\n");
									ret = re_it_peer_info->peer->add_peer_bridge_flt_rule(inter_client.bridge_ipv4, inter_client.subnet_mask, IPA_IP_v4, inter_client.ipv6_prefix);
									if(ret == IPACM_FAILURE)
									{
										IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
									}
								}
								ret = add_peer_bridge_flt_rule(inter_client.bridge_ipv4, inter_client.subnet_mask, IPA_IP_v4, inter_client.ipv6_prefix);
								if(ret == IPACM_FAILURE)
								{
									IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
								}
							}
						}
					}

					/* if this is non-vlan and peer is non-vlan then not to enable inter_bridge */
					if(!this->m_is_vlan && !IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
					{
						IPACMDBG_H("Both are on Same bridge : No Need of Inter bridge flt rule. \n");
					}
				}
				if(this->m_is_vlan)
				{
					IPACMDBG_H("Check If any bridge subnet rule left on Self.\n");
					add_bridge_self_vlan_client(&front_client, IPA_IP_v4);
				}
			}
			if(m_is_ip_addr_assigned[IPA_IP_v6])
			{

				if(this->m_is_vlan)
				{
					if(IPACM_Iface::ipacmcfg->get_ipv6_prefix_for_vlan_id(vlan_id,ipv6_prefix_vlanid) != true)
					{
						IPACMERR("Lan2Lan_v2_IPA_IP_v6: failed to get v6 prefix for vlan id %d\n",vlan_id);
						return;
					}
				}
				else
				{
					if(IPACM_Wan::GetV6PrefixByVid(vlan_id, ipv6_prefix_vlanid))
					{
						IPACMERR("Lan2Lan_v2_IPA_IP_v6: Couldn't get prefix for vid: %d\n", vlan_id);
						return;
					}
					else
					{
						IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6: prefix 0x[%X][%X] is ipv6 prefix for vlan id %d\n", ipv6_prefix_vlanid[0], ipv6_prefix_vlanid[1], vlan_id);
					}
				}
				IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6: vlan_id %d has perfix 0x%x:%x:%x:%x\n", vlan_id, ipv6_prefix_vlanid[0], ipv6_prefix_vlanid[1]);
				memcpy(front_client.ipv6_prefix, ipv6_prefix_vlanid, sizeof(front_client.ipv6_prefix));
				rt_tbl.ip = IPA_IP_v6;
				memcpy(rt_tbl.name, IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v6.name, sizeof(IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v6));

				if(IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false)
				{
					m_p_iface->add_dummy_routing_rule_lan2lan(rt_tbl.name,rt_tbl.ip);
				}
				IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6: For Intra bridge offload (v6) flt rule. m_is_vlan %d \n", m_is_vlan);
				ret = add_client_flt_rule(&self, &front_client, IPA_IP_v6);
				if(ret == IPACM_FAILURE)
				{
					IPACMERR("Lan2Lan_v2_IPA_IP_v6: : Failed to install flt rule.\n");
					goto erase_client;
				}
				IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6: This %s : Number of peer %d \n", this->get_iface_pointer()->dev_name, m_peer_iface_info.size());
				for(re_it_peer_info = m_peer_iface_info.begin(); re_it_peer_info != m_peer_iface_info.end(); re_it_peer_info++)
				{
					IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6:  Allow Peers to install (v6) flt rule for new client.\n");
					ret = re_it_peer_info->peer->add_peer_bridge_flt_rule(front_client.bridge_ipv4, front_client.subnet_mask, IPA_IP_v6, ipv6_prefix_vlanid);
					if(ret == IPACM_FAILURE)
					{
						IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
					}
				}
				if(this->m_is_vlan)
				{
					IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6: If New client is vlan, Allow self Peers vlan id to install (v6) flt rule for new client.\n");
					ret = add_peer_bridge_flt_rule(front_client.bridge_ipv4, front_client.subnet_mask, IPA_IP_v6, ipv6_prefix_vlanid);
					if(ret == IPACM_FAILURE)
					{
						IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
					}
				}

				IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6: This %s : Number of peer %d \n", this->get_iface_pointer()->dev_name, m_peer_iface_info.size());
				for(it_peer_info = m_peer_iface_info.begin(); it_peer_info != m_peer_iface_info.end(); it_peer_info++)
				{
					IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 : peer %s \n",it_peer_info->peer->get_iface_pointer()->dev_name);
					/*avoid installing rule 2 times in case of spcl_iface*/
					if (it_peer_info->peer->is_spcl_iface() && ((front_client.vlan_id && it_peer_info->peer_hdr_type == IPA_HDR_L2_ETHERNET_II) || (front_client.vlan_id == 0 && it_peer_info->peer_hdr_type == IPA_HDR_L2_802_1Q)))
					{
						IPACMDBG_H("siface mismatch client vlanid %d and l2 peer type%d \n", front_client.vlan_id, it_peer_info->peer_hdr_type);
						continue;
					}
					if (is_spcl_iface() && ((front_client.vlan_id && it_peer_info->eth_vlan_instance == IPA_HDR_L2_ETHERNET_II) || (front_client.vlan_id == 0 && it_peer_info->eth_vlan_instance == IPA_HDR_L2_802_1Q)))
					{
						IPACMDBG_H("siface mismatch client vlanid %d and l2 peer type%d \n", front_client.vlan_id, it_peer_info->eth_vlan_instance);
						continue;
					}
					rt_tbl.ip = IPA_IP_v6;
					memcpy(rt_tbl.name, IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v6.name, sizeof(IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v6));
					if(IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false)
					{
						if (IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v6_set == false)
						{
							m_p_iface->add_dummy_routing_rule_lan2lan(rt_tbl.name, rt_tbl.ip);
							IPACM_Iface::ipacmcfg->rt_tbl_inter_l2l_v6_set = true;
						}
					}
					/* if this is vlan and peer is non vlan then enable inter_bridge */
					if(this->m_is_vlan && !IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
					{
						IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :if this is vlan and peer is non vlan then enable inter_bridge\n");
						/* Get prefix info for this and peer iface */
						if(this->m_is_vlan)
						{
							if(IPACM_Iface::ipacmcfg->get_ipv6_prefix_for_vlan_id(vlan_id,this_ipv6_prefix_vlanid) != true)
							{
								IPACMERR("Lan2Lan_v2_IPA_IP_v6: failed to get v6 prefix for vlan id %d\n",vlan_id);
								return;
							}
							IPACMDBG_H("This has prefix 0x[%X][%X] for vlan id %d\n", this_ipv6_prefix_vlanid[0], this_ipv6_prefix_vlanid[1], vlan_id);
						}
						if(!IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
						{
							vlan_id = 0;
							if(IPACM_Wan::GetV6PrefixByVid(vlan_id, peer_ipv6_prefix_vlanid))
							{
								IPACMDBG_H("Couldn't get prefix for vid: %d\n", vlan_id);
								return;
							}
							else
							{
								IPACMDBG_H("Peer has prefix 0x[%X][%X] for vlan id %d\n", peer_ipv6_prefix_vlanid[0], peer_ipv6_prefix_vlanid[1], vlan_id);
							}
						}
						/* Compare if need to install Inter bridge rule for this_client_add and peer_iface */
						if((this_ipv6_prefix_vlanid[0] == peer_ipv6_prefix_vlanid[0]) && (this_ipv6_prefix_vlanid[1] == peer_ipv6_prefix_vlanid[1]))
						{
							IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 : Same Prefix ignore Inter bridge flt rule \n");
							return;
						}
						else
						{
							memset(&inter_client, 0, sizeof(inter_client));
							memcpy(inter_client.mac_addr, mac, sizeof(inter_client.mac_addr));
							inter_client.is_l2tp_client = is_l2tp_client;
							inter_client.mapping_info = mapping_info;
							inter_client.vlan_id = new_client.vlan_id;
							inter_client.bridge_ipv4 = peer_bridge_info.bridge_ipv4 ;
							inter_client.subnet_mask = peer_bridge_info.subnet_mask;
							memcpy(&inter_client.ipv6_prefix, peer_ipv6_prefix_vlanid, sizeof(inter_client.ipv6_prefix));
							ret = add_client_flt_rule(&self, &inter_client, IPA_IP_v6, true);
							if(ret == IPACM_FAILURE)
							{
								IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
							}
							IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :re_it_peer_info size %d \n",m_peer_iface_info.size());
							for(re_it_peer_info = m_peer_iface_info.begin(); re_it_peer_info != m_peer_iface_info.end(); re_it_peer_info++)
							{
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :Allow Peers to install flt rule for new client.\n");
								ret = re_it_peer_info->peer->add_peer_bridge_flt_rule(inter_client.bridge_ipv4, inter_client.subnet_mask, IPA_IP_v6, inter_client.ipv6_prefix);
								if(ret == IPACM_FAILURE)
								{
									IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
								}
							}
							ret = add_peer_bridge_flt_rule(inter_client.bridge_ipv4, inter_client.subnet_mask, IPA_IP_v6, inter_client.ipv6_prefix);
							if(ret == IPACM_FAILURE)
							{
								IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
							}
						}
					}

					/* if this is non-vlan and peer is vlan then enable inter_bridge */
					if(!this->m_is_vlan && IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
					{
						IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :if this is non-vlan and peer is vlan then enable inter_bridge\n");
						/* Get prefix info for this and peer iface */
						if(!this->m_is_vlan)
						{
							vlan_id = 0;
							if(IPACM_Wan::GetV6PrefixByVid(vlan_id, this_ipv6_prefix_vlanid))
							{
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :Couldn't get prefix for vid: %d\n", vlan_id);
								return;
							}
							else
							{
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :This has prefix 0x[%X][%X] for vlan id %d\n", this_ipv6_prefix_vlanid[0], this_ipv6_prefix_vlanid[1], vlan_id);
							}
						}
						for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
						{
							if(vIds[i] != 0)
							{
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :vlan id %d \n", vIds[i]);
								snprintf(peer_iface_name,IPA_RESOURCE_NAME_MAX,"%s%s%d",it_peer_info->peer->get_iface_pointer()->dev_name,".",vIds[i]);
							}
							if(vIds[i] == 0)
								break;

							if(IPACM_Iface::ipacmcfg->get_ipv6_prefix_for_vlan_id(vIds[i],peer_ipv6_prefix_vlanid) != true)
							{
								IPACMERR("Lan2Lan_v2_IPA_IP_v6: failed to get v6 prefix for vlan id %d\n",vIds[i]);
								continue;
							}
							IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :Peer has prefix 0x[%X][%X] for vlan id %d\n", peer_ipv6_prefix_vlanid[0], peer_ipv6_prefix_vlanid[1], vIds[i]);
							if((this_ipv6_prefix_vlanid[0] == peer_ipv6_prefix_vlanid[0]) && (this_ipv6_prefix_vlanid[1] == peer_ipv6_prefix_vlanid[1]))
							{
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 : Same Prefix ignore Inter bridge flt rule \n");
								continue;
							}
							else
							{
								memset(&inter_client, 0, sizeof(inter_client));
								memcpy(inter_client.mac_addr, mac, sizeof(inter_client.mac_addr));
								inter_client.is_l2tp_client = is_l2tp_client;
								inter_client.mapping_info = mapping_info;
								inter_client.vlan_id = 0;
								inter_client.bridge_ipv4 = peer_bridge_info.bridge_ipv4 ;
								inter_client.subnet_mask = peer_bridge_info.subnet_mask;
								memcpy(&inter_client.ipv6_prefix, peer_ipv6_prefix_vlanid, sizeof(inter_client.ipv6_prefix));
								ret = add_client_flt_rule(&self, &inter_client, IPA_IP_v6, true);
								if(ret == IPACM_FAILURE)
								{
									IPACMERR("Lan2Lan_v2_IPA_IP_v6 : Failed to install flt rule.\n");
								}
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :re_it_peer_info size %d \n",m_peer_iface_info.size());
								for(re_it_peer_info = m_peer_iface_info.begin(); re_it_peer_info != m_peer_iface_info.end(); re_it_peer_info++)
								{
									IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :Allow Peers to install flt rule for new client.\n");
									ret = re_it_peer_info->peer->add_peer_bridge_flt_rule(inter_client.bridge_ipv4, inter_client.subnet_mask, IPA_IP_v6, inter_client.ipv6_prefix);
									if(ret == IPACM_FAILURE)
									{
										IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
									}
								}
							}
						}
					}

					/* if this is vlan and peer is vlan then enable inter_bridge */
					if(this->m_is_vlan && IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
					{
						IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :if this is vlan and peer is vlan then enable inter_bridge\n");
						/* Get prefix info for this and peer iface */
						if(this->m_is_vlan)
						{
							if(IPACM_Iface::ipacmcfg->get_ipv6_prefix_for_vlan_id(vlan_id,this_ipv6_prefix_vlanid) != true)
							{
								IPACMERR("Lan2Lan_v2_IPA_IP_v6: failed to get v6 prefix for vlan id %d\n",vlan_id);
								return;
							}
							IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6: This has prefix 0x[%X][%X] for vlan id %d\n", this_ipv6_prefix_vlanid[0], this_ipv6_prefix_vlanid[1], vlan_id);
						}
						for(i = 0; i < IPA_MAX_NUM_OFFLOAD_VLANS; i++)
						{
							if(vIds[i] != 0)
							{
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :vlan id %d \n", vIds[i]);
								snprintf(peer_iface_name,IPA_RESOURCE_NAME_MAX,"%s%s%d",it_peer_info->peer->get_iface_pointer()->dev_name,".",vIds[i]);
							}
							if(vIds[i] == 0)
								break;

							if(IPACM_Iface::ipacmcfg->get_ipv6_prefix_for_vlan_id(vIds[i],peer_ipv6_prefix_vlanid) != true)
							{
								IPACMERR("Lan2Lan_v2_IPA_IP_v6: failed to get v6 prefix for vlan id %d\n",vIds[i]);
								continue;
							}
							IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 : Peer has prefix 0x[%X][%X] for vlan id %d\n", peer_ipv6_prefix_vlanid[0], peer_ipv6_prefix_vlanid[1], vIds[i]);
							if((this_ipv6_prefix_vlanid[0] == peer_ipv6_prefix_vlanid[0]) && (this_ipv6_prefix_vlanid[1] == peer_ipv6_prefix_vlanid[1]))
							{
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 : Same Prefix ignore Inter bridge flt rule \n");
								continue;
							}
							else
							{
								memset(&inter_client, 0, sizeof(inter_client));
								memcpy(inter_client.mac_addr, mac, sizeof(inter_client.mac_addr));
								inter_client.is_l2tp_client = is_l2tp_client;
								inter_client.mapping_info = mapping_info;
								inter_client.vlan_id = new_client.vlan_id;
								inter_client.bridge_ipv4 = peer_bridge_info.bridge_ipv4 ;
								inter_client.subnet_mask = peer_bridge_info.subnet_mask;
								memcpy(&inter_client.ipv6_prefix, peer_ipv6_prefix_vlanid, sizeof(inter_client.ipv6_prefix));
								ret = add_client_flt_rule(&self, &inter_client, IPA_IP_v6, true);
								if(ret == IPACM_FAILURE)
								{
									IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
								}
								IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :re_it_peer_info size %d \n",m_peer_iface_info.size());
								for(re_it_peer_info = m_peer_iface_info.begin(); re_it_peer_info != m_peer_iface_info.end(); re_it_peer_info++)
								{
									IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :Allow Peers to install flt rule for new client.\n");
									ret = re_it_peer_info->peer->add_peer_bridge_flt_rule(inter_client.bridge_ipv4, inter_client.subnet_mask, IPA_IP_v6, inter_client.ipv6_prefix);
									if(ret == IPACM_FAILURE)
									{
										IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
									}
								}
								ret = add_peer_bridge_flt_rule(inter_client.bridge_ipv4, inter_client.subnet_mask, IPA_IP_v4, inter_client.ipv6_prefix);
								if(ret == IPACM_FAILURE)
								{
									IPACMERR("Lan2Lan_v2 : Failed to install flt rule.\n");
								}
							}
						}
					}

					/* if this is non-vlan and peer is non-vlan then not to enable inter_bridge */
					if(!this->m_is_vlan && !IPACM_Iface::ipacmcfg->iface_in_vlan_mode(it_peer_info->peer->get_iface_pointer()->dev_name))
					{
						IPACMDBG_H("Lan2Lan_v2_IPA_IP_v6 :Both are on Same bridge : No Need of Inter bridge flt rule. for both nonvlan/non-vlan \n");
					}
				}
				if(this->m_is_vlan)
				{
					IPACMDBG_H("Check If any subnet prefix rule left on Self.\n");
					add_bridge_self_vlan_client(&front_client, IPA_IP_v6);
				}
			}
		}
erase_client:
		if(ret == IPACM_FAILURE)
		{
			IPACMERR("Lan2Lan_v2: Failed to Install filter rule, erase new_client from m_client_info\n");

			for(del_it_client = m_client_info.begin(); del_it_client != m_client_info.end(); del_it_client++)
			{
				if((memcmp(del_it_client->mac_addr, new_client.mac_addr, sizeof(new_client.mac_addr)) == 0))
				{
					m_client_info.erase(del_it_client);
					IPACMERR("Lan2Lan_v2: Erased\n");
					return;
				}
			}
		}
	}
	return;
}

list<client_info>::iterator IPACM_LanToLan_Iface::handle_client_del(uint8_t *mac, uint16_t vlan_id)
{
	list<client_info>::iterator it_client;
	list<peer_iface_info>::iterator it_peer_info;
	bool flag[IPA_HDR_L2_MAX];
	std::array<uint8_t, 6> mac1;
	std::map<std::array<uint8_t, 6>, int >::iterator it;
	ipa_hdr_l2_type l2_hdr_type;

	if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
	{
#ifdef FEATURE_VLAN_MPDN
		if(((vlan_id && !m_is_vlan) || (!vlan_id && m_is_vlan)) && !is_spcl_iface())
		{
			IPACMDBG_H("vlan client (%d) and vlan mode(%d) mismatch, return\n", vlan_id, m_is_vlan);
			return m_client_info.end();
		}
#endif

		for(it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
		{
			if(memcmp(it_client->mac_addr, mac, sizeof(it_client->mac_addr)) == 0)	//found the client
			{
#ifdef FEATURE_VLAN_MPDN
				if(vlan_id)
				{
					if(it_client->vlan_id != vlan_id)
						continue;
				}
#endif
				IPACMDBG_H("Found the client.\n");
				break;
			}
		}

		if(it_client != m_client_info.end())	//if we found the client
		{
			/* uninstall inter-interface rules */
			if(m_support_inter_iface_offload)
			{
				memset(flag, 0, sizeof(flag));
				for(it_peer_info = m_peer_iface_info.begin(); it_peer_info != m_peer_iface_info.end();
					it_peer_info++)
				{
					if (it_peer_info->peer->is_svap_iface() || it_peer_info->peer->is_ap_iface_vlan_enabled() || (it_peer_info->peer->is_spcl_iface() && it_peer_info->is_vlan_peer))
						l2_hdr_type = it_peer_info->peer->get_iface_pointer()->rx_prop->rx[2].hdr_l2_type;
					else
						l2_hdr_type = it_peer_info->peer->get_iface_pointer()->rx_prop->rx[0].hdr_l2_type;

					if(l2_hdr_type >= IPA_HDR_L2_MAX || l2_hdr_type < 0)
					{
						IPACMDBG_H("Invalid l2_hdr_type: %d\n", l2_hdr_type);
					}

					/* make sure to delete routing rule only once for each peer l2 header type */
					if(flag[l2_hdr_type] == false)
					{
						std::copy(std::begin(it_client->mac_addr), std::end(it_client->mac_addr), std::begin(mac1));
						it = it_peer_info->mac_rt_rule_ref.find(mac1);
						if(it != it_peer_info->mac_rt_rule_ref.end())
						{
							IPACMDBG_H("Delete client routing rule for peer interface.\n");
							del_client_rt_rule(&(*it_peer_info), &(*it_client));
#ifdef FEATURE_L2TP
							if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) &&
								it_client->is_l2tp_client == false && IPACM_LanToLan::get_instance()->has_l2tp_iface() == true
								&& m_client_info.size() == 1)
							{
								m_p_iface->eth_bridge_del_hdr_proc_ctx(hdr_proc_ctx_for_l2tp);
								hdr_proc_ctx_for_l2tp = 0;
							}
#endif
							flag[l2_hdr_type] = true;
						}
						else
						{
							IPACMDBG_H("Delete client routing rule for peer interface not found.\n");
						}
					}
				}
			}

			if(!self.peer->get_m_support_ast_update() && m_support_inter_iface_offload)
			{
				IPACMDBG_H("Delete client filtering rule on self interface %s.\n",self.peer->get_iface_pointer()->dev_name);
				del_client_flt_rule(&self, &(*it_client));
			}
			/* erase the client from client info list, return the next element in the list */
			return m_client_info.erase(it_client);
		}
		else
		{
			IPACMDBG_H("The client is not found.\n");
		}

		return m_client_info.end();
	}
	else
	{
#ifdef FEATURE_VLAN_MPDN
		/*Skip this check in case of siface and svap */
		if(((vlan_id && !m_is_vlan ) || (!vlan_id && m_is_vlan)) && (!m_is_svap_iface && !m_is_sIface))
		{
			IPACMDBG_H("fail vlan client (%d) and vlan mode(%d) mismatch, return\n", vlan_id, m_is_vlan);
			return m_client_info.end();
		}
#endif

		for(it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
		{
			if(memcmp(it_client->mac_addr, mac, sizeof(it_client->mac_addr)) == 0)	//found the client
			{
#ifdef FEATURE_VLAN_MPDN
				if(vlan_id)
				{
					if(it_client->vlan_id != vlan_id)
						continue;
				}
#endif
				IPACMDBG_H("Found the client.\n");
				break;
			}
		}

		if(it_client != m_client_info.end())	//if we found the client
		{
			/* uninstall inter-interface rules */
			if(m_support_inter_iface_offload)
			{
				memset(flag, 0, sizeof(flag));
				for(it_peer_info = m_peer_iface_info.begin(); it_peer_info != m_peer_iface_info.end();
					it_peer_info++)
				{
					IPACMDBG_H("This is %s and m_support_inter_iface_offload %d has peer: %s\n",this->get_iface_pointer()->dev_name,m_support_intra_iface_offload,it_peer_info->peer->get_iface_pointer()->dev_name);
					if((it_peer_info->peer->is_svap_iface() || it_peer_info->peer->is_ap_iface_vlan_enabled() ||
						(it_peer_info->peer->is_spcl_iface() && it_peer_info->is_vlan_peer)))
						l2_hdr_type = it_peer_info->peer->get_iface_pointer()->rx_prop->rx[2].hdr_l2_type;
					else
						l2_hdr_type = it_peer_info->peer->get_iface_pointer()->rx_prop->rx[0].hdr_l2_type;

					if(l2_hdr_type >= IPA_HDR_L2_MAX || l2_hdr_type < 0)
					{
						IPACMDBG_H("Invalid l2_hdr_type: %d\n", l2_hdr_type);
					}
					IPACMDBG_H("l2_hdr_type : %d flag : %d \n",l2_hdr_type,flag[l2_hdr_type] );
					it_peer_info->peer->del_one_client_flt_rule(this, &(*it_client),l2_hdr_type);
					/* make sure to delete routing rule only once for each peer l2 header type */
					if(flag[l2_hdr_type] == false)
					{
						std::copy(std::begin(it_client->mac_addr), std::end(it_client->mac_addr), std::begin(mac1));
						it = it_peer_info->mac_rt_rule_ref.find(mac1);
						if(it != it_peer_info->mac_rt_rule_ref.end())
						{
							IPACMDBG_H("Delete client routing rule for peer interface l2_hdr_type : %d.\n",l2_hdr_type);
							del_client_rt_rule(&(*it_peer_info), &(*it_client));
#ifdef FEATURE_L2TP
							if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) &&
								it_client->is_l2tp_client == false && IPACM_LanToLan::get_instance()->has_l2tp_iface() == true
								&& m_client_info.size() == 1)
							{
								m_p_iface->eth_bridge_del_hdr_proc_ctx(hdr_proc_ctx_for_l2tp);
								hdr_proc_ctx_for_l2tp = 0;
							}
#endif
							flag[l2_hdr_type] = true;
						}
						else
						{
							IPACMDBG_H("Delete client routing rule for peer interface not found.\n");
						}
					}
					if((it_peer_info->peer->is_svap_iface() || it_peer_info->peer->is_ap_iface_vlan_enabled() ||
						(it_peer_info->peer->is_spcl_iface() && it_peer_info->is_vlan_peer)) &&
						(flag[it_peer_info->peer->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type] == false))
					{
							IPACMDBG_H("Delete client routing rule for peer interface.\n");
							del_client_rt_rule(&(*it_peer_info), &(*it_client));
#ifdef FEATURE_L2TP
							if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) &&
									it_client->is_l2tp_client == false && IPACM_LanToLan::get_instance()->has_l2tp_iface() == true
									&& m_client_info.size() == 1)
							{
									m_p_iface->eth_bridge_del_hdr_proc_ctx(hdr_proc_ctx_for_l2tp);
									hdr_proc_ctx_for_l2tp = 0;
							}
#endif
							flag[it_peer_info->peer->get_iface_pointer()->tx_prop->tx[2].hdr_l2_type] = true;
					}

				}
			}

			/* uninstall intra-interface rules */
			if(m_support_intra_iface_offload)
			{
				/* delete filtering rule first */
				IPACMDBG_H("Delete client filtering rule for intra-interface communication.\n");
				del_client_flt_rule(&m_intra_interface_info, &(*it_client));

				/* delete routing rule */
				IPACMDBG_H("Delete client routing rule for intra-interface communication.\n");
				del_client_rt_rule(&m_intra_interface_info, &(*it_client));
			}

			/* erase the client from client info list, return the next element in the list */
			return m_client_info.erase(it_client);
		}
		else
		{
			IPACMDBG_H("The client is not found.\n");
		}
		return m_client_info.end();
	}
}

void IPACM_LanToLan_Iface::add_hdr_proc_ctx(ipa_hdr_l2_type peer_l2_type)
{
	uint32_t hdr_proc_ctx_hdl[IPA_MAX_NUM_PROPS] = { 0 };

	if(ref_cnt_peer_l2_hdr_type[peer_l2_type] == 1)
	{
		m_p_iface->eth_bridge_add_hdr_proc_ctx(peer_l2_type, hdr_proc_ctx_hdl, 0);
		hdr_proc_ctx_for_inter_interface[peer_l2_type] = hdr_proc_ctx_hdl[0];
		IPACMDBG_H("Installed inter-interface hdr proc ctx on iface %s: handle %d\n", m_p_iface->dev_name, hdr_proc_ctx_hdl[0]);
	}
	return;
}

void IPACM_LanToLan_Iface::del_hdr_proc_ctx(ipa_hdr_l2_type peer_l2_type)
{
	if(ref_cnt_peer_l2_hdr_type[peer_l2_type] == 0)
	{
		m_p_iface->eth_bridge_del_hdr_proc_ctx(hdr_proc_ctx_for_inter_interface[peer_l2_type]);
		IPACMDBG_H("Hdr proc ctx with hdl %d is deleted.\n", hdr_proc_ctx_for_inter_interface[peer_l2_type]);
	}
	return;
}

void IPACM_LanToLan_Iface::add_hdr_proc_ctx_vlan(ipa_hdr_l2_type peer_l2_type, uint16_t vlan_id)
{
	uint32_t hdr_proc_ctx_hdl[IPA_MAX_NUM_PROPS] = { 0 };

	if (!is_entry_present_wlan_svap_hpc_hdl(vlan_id, peer_l2_type))
	{
		m_p_iface->eth_bridge_add_hdr_proc_ctx(peer_l2_type, hdr_proc_ctx_hdl, vlan_id);
		add_wlan_svap_hpc_hdl(vlan_id, peer_l2_type, hdr_proc_ctx_hdl);
		IPACMDBG_H("Installed inter-interface hdr proc ctx on iface %s: handle %d\n", m_p_iface->dev_name, hdr_proc_ctx_hdl);
	}
	return;
}

void IPACM_LanToLan_Iface::del_hdr_proc_ctx_vlan(ipa_hdr_l2_type peer_l2_type, uint16_t vlan_id)
{
	uint32_t hpc_hdl = is_entry_present_wlan_svap_hpc_hdl(vlan_id, peer_l2_type);
	if(hpc_hdl)
	{
		m_p_iface->eth_bridge_del_hdr_proc_ctx(hpc_hdl);
		IPACMDBG_H("Hdr proc ctx with hdl %d is deleted.\n", hpc_hdl);
		del_wlan_svap_hpc_hdl(vlan_id, peer_l2_type, &hpc_hdl);
	}
	return;
}

void IPACM_LanToLan_Iface::print_data_structure_info()
{
	list<peer_iface_info>::iterator it_peer;
	list<client_info>::iterator it_client;
	int i, j, k;

	if(IPACM_Iface::ipacmcfg->inter_bridge_lantolan_config_enable == true)
	{
				IPACMDBG_H("\n");
		IPACMDBG_H("Interface %s:\n", m_p_iface->dev_name);
		IPACMDBG_H("Is IPv4 addr assigned? %d\n", m_is_ip_addr_assigned[IPA_IP_v4]);
		IPACMDBG_H("Is IPv6 addr assigned? %d\n", m_is_ip_addr_assigned[IPA_IP_v6]);
		IPACMDBG_H("Support inter interface offload? %d\n", m_support_inter_iface_offload);
		IPACMDBG_H("Is l2tp interface? %d\n", m_is_l2tp_iface);
#ifdef FEATURE_VLAN_MPDN
		IPACMDBG_H("is_vlan ? %d\n", m_is_vlan);
#endif
		if(m_support_inter_iface_offload)
		{
			for(i = 0; i < IPA_HDR_L2_MAX; i++)
			{
				IPACMDBG_H("Ref_cnt of peer l2 type with index %d is %d.\n", i, ref_cnt_peer_l2_hdr_type[i]);
				if(ref_cnt_peer_l2_hdr_type[i] > 0)
				{
					IPACMDBG_H("Hdr proc ctx for peer l2 type %s: %d\n", ipa_l2_hdr_type[i], hdr_proc_ctx_for_inter_interface[i]);
				}
			}
		}

		IPACMDBG_H("Hdr proc ctx for l2tp: %d\n", hdr_proc_ctx_for_l2tp);

		i = 1;
		IPACMDBG_H("There are %zu clients in total.\n", m_client_info.size());
		for(it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
		{
			IPACMDBG_H("Client %d MAC: 0x%02x%02x%02x%02x%02x%02x Pointer: %p\n", i, it_client->mac_addr[0], it_client->mac_addr[1],
				it_client->mac_addr[2], it_client->mac_addr[3], it_client->mac_addr[4], it_client->mac_addr[5], &(*it_client));
			IPACMDBG_H("Is l2tp client? %d\n", it_client->is_l2tp_client);
			if(it_client->is_l2tp_client && it_client->mapping_info)
			{
				IPACMDBG_H("Vlan iface associated with this client: %s\n", it_client->mapping_info->vlan_iface_name);
			}
#ifdef FEATURE_VLAN_MPDN
			if(m_is_vlan)
			{
				IPACMDBG_H("vlan ID %d\n", it_client->vlan_id);
			}
#endif
			if(m_support_inter_iface_offload)
			{
				for(j = 0; j < IPA_HDR_L2_MAX; j++)
				{
					if(ref_cnt_peer_l2_hdr_type[j] > 0)
					{
						IPACMDBG_H("Printing routing rule info for inter-interface communication for peer l2 type %s.\n",
							ipa_l2_hdr_type[j]);
						IPACMDBG_H("Number of IPv4 routing rules is %d, handles:\n", it_client->inter_iface_rt_rule_hdl[j].num_hdl[IPA_IP_v4]);
						for(k = 0; k < it_client->inter_iface_rt_rule_hdl[j].num_hdl[IPA_IP_v4]; k++)
						{
							IPACMDBG_H("%d\n", it_client->inter_iface_rt_rule_hdl[j].rule_hdl[IPA_IP_v4][k]);
						}

						IPACMDBG_H("Number of IPv6 routing rules is %d, handles:\n", it_client->inter_iface_rt_rule_hdl[j].num_hdl[IPA_IP_v6]);
						for(k = 0; k < it_client->inter_iface_rt_rule_hdl[j].num_hdl[IPA_IP_v6]; k++)
						{
							IPACMDBG_H("%d\n", it_client->inter_iface_rt_rule_hdl[j].rule_hdl[IPA_IP_v6][k]);
						}

#ifdef FEATURE_L2TP
						if(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP)
						{
							if(it_client->is_l2tp_client)
							{
								IPACMDBG_H("Printing l2tp hdr info for l2tp client.\n");
								IPACMDBG_H("First pass hdr hdl: %d, IPv4 hdr proc ctx hdl: IPv6 hdr proc ctx hdl: %d\n",
									it_client->l2tp_rt_rule_hdl[j].first_pass_hdr_hdl, it_client->l2tp_rt_rule_hdl[j].first_pass_hdr_proc_ctx_hdl[IPA_IP_v4],
									it_client->l2tp_rt_rule_hdl[j].first_pass_hdr_proc_ctx_hdl[IPA_IP_v6]);
								IPACMDBG_H("Second pass hdr hdl: %d\n", it_client->l2tp_rt_rule_hdl[j].second_pass_hdr_hdl);

								IPACMDBG_H("Printing l2tp routing rule info for l2tp client.\n");
								IPACMDBG_H("Number of IPv4 routing rules is %d, first pass handles:\n", it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v4]);
								for(k = 0; k < it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v4]; k++)
								{
									IPACMDBG_H("%d\n", it_client->l2tp_rt_rule_hdl[j].first_pass_rt_rule_hdl[IPA_IP_v4][k]);
								}
								IPACMDBG_H("Number of IPv6 routing rules is %d, first pass handles:\n", it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v6]);
								for(k = 0; k < it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v6]; k++)
								{
									IPACMDBG_H("%d\n", it_client->l2tp_rt_rule_hdl[j].first_pass_rt_rule_hdl[IPA_IP_v6][k]);
								}
								IPACMDBG_H("Second pass handles:\n");
								for(k = 0; k < it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v6]; k++)
								{
									IPACMDBG_H("%d\n", it_client->l2tp_rt_rule_hdl[j].second_pass_rt_rule_hdl[k]);
								}
							}
							else
							{
								if(IPACM_LanToLan::get_instance()->has_l2tp_iface())
								{
									IPACMDBG_H("Printing l2tp hdr info for non l2tp client.\n");
									IPACMDBG_H("Hdr hdl: %d, IPv4 hdr proc ctx hdl: IPv6 hdr proc ctx hdl: %d\n",
										it_client->l2tp_rt_rule_hdl[j].first_pass_hdr_hdl, it_client->l2tp_rt_rule_hdl[j].first_pass_hdr_proc_ctx_hdl[IPA_IP_v4],
										it_client->l2tp_rt_rule_hdl[j].first_pass_hdr_proc_ctx_hdl[IPA_IP_v6]);

									IPACMDBG_H("Printing l2tp routing rule info for non l2tp client.\n");
									IPACMDBG_H("Number of IPv4 routing rules is %d, handles:\n", it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v4]);
									for(k = 0; k < it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v4]; k++)
									{
										IPACMDBG_H("%d\n", it_client->l2tp_rt_rule_hdl[j].first_pass_rt_rule_hdl[IPA_IP_v4][k]);
									}
									IPACMDBG_H("Number of IPv6 routing rules is %d, handles:\n", it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v6]);
									for(k = 0; k < it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v6]; k++)
									{
										IPACMDBG_H("%d\n", it_client->l2tp_rt_rule_hdl[j].first_pass_rt_rule_hdl[IPA_IP_v6][k]);
									}
								}
							}
						}
#endif
					}
				}
			}
			i++;
		}

		IPACMDBG_H("There are %zu peer interfaces in total.\n", m_peer_iface_info.size());
		for(it_peer = m_peer_iface_info.begin(); it_peer != m_peer_iface_info.end(); it_peer++)
		{
			print_peer_info(&(*it_peer), false);
		}
	}
	else
	{
		IPACMDBG_H("\n");
		IPACMDBG_H("Interface %s:\n", m_p_iface->dev_name);
		IPACMDBG_H("Is IPv4 addr assigned? %d\n", m_is_ip_addr_assigned[IPA_IP_v4]);
		IPACMDBG_H("Is IPv6 addr assigned? %d\n", m_is_ip_addr_assigned[IPA_IP_v6]);
		IPACMDBG_H("Support inter interface offload? %d\n", m_support_inter_iface_offload);
		IPACMDBG_H("Support intra interface offload? %d\n", m_support_intra_iface_offload);
		IPACMDBG_H("Is l2tp interface? %d\n", m_is_l2tp_iface);
#ifdef FEATURE_VLAN_MPDN
		IPACMDBG_H("is_vlan ? %d\n", m_is_vlan);
#endif

		if(m_support_inter_iface_offload)
		{
			for(i = 0; i < IPA_HDR_L2_MAX; i++)
			{
				IPACMDBG_H("Ref_cnt of peer l2 type with index %d is %d.\n", i, ref_cnt_peer_l2_hdr_type[i]);
				if(ref_cnt_peer_l2_hdr_type[i] > 0)
				{
					IPACMDBG_H("Hdr proc ctx for peer l2 type %s: %d\n", ipa_l2_hdr_type[i], hdr_proc_ctx_for_inter_interface[i]);
				}
			}
		}

		if(m_support_intra_iface_offload)
		{
			IPACMDBG_H("Hdr proc ctx for intra-interface: %d\n", hdr_proc_ctx_for_intra_interface);
		}

		IPACMDBG_H("Hdr proc ctx for l2tp: %d\n", hdr_proc_ctx_for_l2tp);

		i = 1;
		IPACMDBG_H("There are %zu clients in total.\n", m_client_info.size());
		for(it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
		{
			IPACMDBG_H("Client %d MAC: 0x%02x%02x%02x%02x%02x%02x Pointer: %p\n", i, it_client->mac_addr[0], it_client->mac_addr[1],
				it_client->mac_addr[2], it_client->mac_addr[3], it_client->mac_addr[4], it_client->mac_addr[5], &(*it_client));
			IPACMDBG_H("Is l2tp client? %d\n", it_client->is_l2tp_client);
			if(it_client->is_l2tp_client && it_client->mapping_info)
			{
				IPACMDBG_H("Vlan iface associated with this client: %s\n", it_client->mapping_info->vlan_iface_name);
			}
#ifdef FEATURE_VLAN_MPDN
			if(m_is_vlan)
			{
				IPACMDBG_H("vlan ID %d\n", it_client->vlan_id);
			}
#endif
			if(m_support_inter_iface_offload)
			{
				for(j = 0; j < IPA_HDR_L2_MAX; j++)
				{
					if(ref_cnt_peer_l2_hdr_type[j] > 0)
					{
						IPACMDBG_H("Printing routing rule info for inter-interface communication for peer l2 type %s.\n",
							ipa_l2_hdr_type[j]);
						IPACMDBG_H("Number of IPv4 routing rules is %d, handles:\n", it_client->inter_iface_rt_rule_hdl[j].num_hdl[IPA_IP_v4]);
						for(k = 0; k < it_client->inter_iface_rt_rule_hdl[j].num_hdl[IPA_IP_v4]; k++)
						{
							IPACMDBG_H("%d\n", it_client->inter_iface_rt_rule_hdl[j].rule_hdl[IPA_IP_v4][k]);
						}

						IPACMDBG_H("Number of IPv6 routing rules is %d, handles:\n", it_client->inter_iface_rt_rule_hdl[j].num_hdl[IPA_IP_v6]);
						for(k = 0; k < it_client->inter_iface_rt_rule_hdl[j].num_hdl[IPA_IP_v6]; k++)
						{
							IPACMDBG_H("%d\n", it_client->inter_iface_rt_rule_hdl[j].rule_hdl[IPA_IP_v6][k]);
						}

#ifdef FEATURE_L2TP
						if(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP)
						{
							if(it_client->is_l2tp_client)
							{
								IPACMDBG_H("Printing l2tp hdr info for l2tp client.\n");
								IPACMDBG_H("First pass hdr hdl: %d, IPv4 hdr proc ctx hdl: IPv6 hdr proc ctx hdl: %d\n",
									it_client->l2tp_rt_rule_hdl[j].first_pass_hdr_hdl, it_client->l2tp_rt_rule_hdl[j].first_pass_hdr_proc_ctx_hdl[IPA_IP_v4],
									it_client->l2tp_rt_rule_hdl[j].first_pass_hdr_proc_ctx_hdl[IPA_IP_v6]);
								IPACMDBG_H("Second pass hdr hdl: %d\n", it_client->l2tp_rt_rule_hdl[j].second_pass_hdr_hdl);

								IPACMDBG_H("Printing l2tp routing rule info for l2tp client.\n");
								IPACMDBG_H("Number of IPv4 routing rules is %d, first pass handles:\n", it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v4]);
								for(k = 0; k < it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v4]; k++)
								{
									IPACMDBG_H("%d\n", it_client->l2tp_rt_rule_hdl[j].first_pass_rt_rule_hdl[IPA_IP_v4][k]);
								}
								IPACMDBG_H("Number of IPv6 routing rules is %d, first pass handles:\n", it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v6]);
								for(k = 0; k < it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v6]; k++)
								{
									IPACMDBG_H("%d\n", it_client->l2tp_rt_rule_hdl[j].first_pass_rt_rule_hdl[IPA_IP_v6][k]);
								}
								IPACMDBG_H("Second pass handles:\n");
								for(k = 0; k < it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v6]; k++)
								{
									IPACMDBG_H("%d\n", it_client->l2tp_rt_rule_hdl[j].second_pass_rt_rule_hdl[k]);
								}
							}
							else
							{
								if(IPACM_LanToLan::get_instance()->has_l2tp_iface())
								{
									IPACMDBG_H("Printing l2tp hdr info for non l2tp client.\n");
									IPACMDBG_H("Hdr hdl: %d, IPv4 hdr proc ctx hdl: IPv6 hdr proc ctx hdl: %d\n",
										it_client->l2tp_rt_rule_hdl[j].first_pass_hdr_hdl, it_client->l2tp_rt_rule_hdl[j].first_pass_hdr_proc_ctx_hdl[IPA_IP_v4],
										it_client->l2tp_rt_rule_hdl[j].first_pass_hdr_proc_ctx_hdl[IPA_IP_v6]);

									IPACMDBG_H("Printing l2tp routing rule info for non l2tp client.\n");
									IPACMDBG_H("Number of IPv4 routing rules is %d, handles:\n", it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v4]);
									for(k = 0; k < it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v4]; k++)
									{
										IPACMDBG_H("%d\n", it_client->l2tp_rt_rule_hdl[j].first_pass_rt_rule_hdl[IPA_IP_v4][k]);
									}
									IPACMDBG_H("Number of IPv6 routing rules is %d, handles:\n", it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v6]);
									for(k = 0; k < it_client->l2tp_rt_rule_hdl[j].num_rt_hdl[IPA_IP_v6]; k++)
									{
										IPACMDBG_H("%d\n", it_client->l2tp_rt_rule_hdl[j].first_pass_rt_rule_hdl[IPA_IP_v6][k]);
									}
								}
							}
						}
#endif
					}
				}
			}

			if(m_support_intra_iface_offload)
			{
				if(IPACM_Iface::ipacmcfg->multi_vlan_bridge_config_enable == 1)
				{
					IPACMDBG_H("client hdr_proc_ctx handle: %d:\n",
						it_client->hdr_proc_ctx_intra_interface);
				}

				IPACMDBG_H("Printing routing rule info for intra-interface communication.\n");
				IPACMDBG_H("Number of IPv4 routing rules is %d, handles:\n", it_client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v4]);
				for(j = 0; j < it_client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v4]; j++)
				{
					IPACMDBG_H("%d\n", it_client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v4][j]);
				}

				IPACMDBG_H("Number of IPv6 routing rules is %d, handles:\n", it_client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v6]);
				for(j = 0; j < it_client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v6]; j++)
				{
					IPACMDBG_H("%d\n", it_client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v6][j]);
				}
			}
			i++;
		}

		IPACMDBG_H("There are %zu peer interfaces in total.\n", m_peer_iface_info.size());
		for(it_peer = m_peer_iface_info.begin(); it_peer != m_peer_iface_info.end(); it_peer++)
		{
			print_peer_info(&(*it_peer),false);
		}

		if(m_support_intra_iface_offload)
		{
			IPACMDBG_H("This interface supports intra-interface communication, printing info:\n");
			print_peer_info(&m_intra_interface_info,true);
		}
	}
	return;
}

void IPACM_LanToLan_Iface::print_peer_info(peer_iface_info *peer_info , bool intra)
{
	list<flt_rule_info>::iterator it_flt;
	list<rt_rule_info>::iterator it_rt;
	list<uint32_t>::iterator it_flt_hdl;

	if(peer_info == NULL)
	{
		IPACMERR("Peer info with NULL pointer\n");
		return;
	}
	if(peer_info->peer == NULL)
	{
		IPACMERR("Peer info peer with NULL pointer\n");
		return;
	}
	if(peer_info->peer->m_p_iface == NULL)
	{
		IPACMERR("Peer info m_p_iface with NULL pointer\n");
		return;
	}

	IPACMDBG_H("Printing peer info for iface %s:\n", peer_info->peer->m_p_iface->dev_name);

	IPACMDBG_H("There are %zu flt info in total.\n", peer_info->flt_rule.size());
	for(it_flt = peer_info->flt_rule.begin(); it_flt != peer_info->flt_rule.end(); it_flt++)
	{
		IPACMDBG_H("Flt rule handle for client %p:\n", it_flt->p_client);
		if(m_is_ip_addr_assigned[IPA_IP_v4])
		{
			IPACMDBG_H("IPv4 %d\n", it_flt->flt_rule_hdl[IPA_IP_v4]);
			for (it_flt_hdl = it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v4].flt_rule_hdls.begin();
				it_flt_hdl != it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v4].flt_rule_hdls.end(); ++it_flt_hdl)
				IPACMDBG_H("IPv4 l2tp flt rule handle: %d\n", *it_flt_hdl);
		}
		if(m_is_ip_addr_assigned[IPA_IP_v6])
		{
			IPACMDBG_H("IPv6 %d\n", it_flt->flt_rule_hdl[IPA_IP_v6]);
			for (it_flt_hdl = it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.begin();
				it_flt_hdl != it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.end(); ++it_flt_hdl)
				IPACMDBG_H("IPv6 l2tp flt rule handle: %d\n", *it_flt_hdl);
		}
		IPACMDBG_H("L2tp second pass flt rule: %d\n", it_flt->l2tp_second_pass_flt_rule_hdl);
	}

	if(intra == false)
	{
		for (const auto &pair : peer_info->mac_rt_rule_ref) {
				IPACMDBG_H("ref list mac MAC 0x[%X][%X][%X][%X][%X][%X] key %d\n",
				pair.first[0], pair.first[1], pair.first[2],
				pair.first[3], pair.first[4], pair.first[5],
				pair.second);
		}
	}

	return;
}

IPACM_Lan* IPACM_LanToLan_Iface::get_iface_pointer()
{
	return m_p_iface;
}

bool IPACM_LanToLan_Iface::get_m_is_ip_addr_assigned(ipa_ip_type iptype)
{
	IPACMDBG_H("Has IP address been assigned to interface %s for IP type %d? %d\n",
		m_p_iface->dev_name, iptype, m_is_ip_addr_assigned[iptype]);
	return m_is_ip_addr_assigned[iptype];
}

void IPACM_LanToLan_Iface::set_m_is_ip_addr_assigned(ipa_ip_type iptype, bool value)
{
	IPACMDBG_H("Is IP address of IP type %d assigned to interface %s? %d\n", iptype,
		m_p_iface->dev_name, value);
	m_is_ip_addr_assigned[iptype] = value;
}

bool IPACM_LanToLan_Iface::is_svap_iface()
{
	IPACMDBG_H("Is %s SVAP iface? %d\n", m_p_iface->dev_name,
		m_is_svap_iface);
	return m_is_svap_iface;
}

void  IPACM_LanToLan_Iface::set_svap_iface(bool enable) {
	IPACMDBG_H("Setting m_is_svap_iface mode %d\n", enable);
	m_is_svap_iface = enable;
}

bool IPACM_LanToLan_Iface::is_ap_iface_vlan_enabled() {
	IPACMDBG_H("Is %s AP Vlan iface? %d\n", m_p_iface->dev_name, m_is_vlan_ap);
	return m_is_vlan_ap;
}

bool IPACM_LanToLan_Iface::is_spcl_iface() {
	IPACMDBG_H("Is %s AP Special iface? %d\n", m_p_iface->dev_name, m_is_sIface);
	return m_is_sIface;
}

bool IPACM_LanToLan_Iface::get_m_support_inter_iface_offload()
{
	IPACMDBG_H("Support inter interface offload on %s? %d\n", m_p_iface->dev_name,
		m_support_inter_iface_offload);
	return m_support_inter_iface_offload;
}

bool IPACM_LanToLan_Iface::get_m_support_intra_iface_offload()
{
	IPACMDBG_H("Support intra interface offload on %s? %d\n", m_p_iface->dev_name,
		m_support_intra_iface_offload);
	return m_support_intra_iface_offload;
}

void IPACM_LanToLan_Iface::increment_ref_cnt_peer_l2_hdr_type(ipa_hdr_l2_type peer_l2_type)
{
	ref_cnt_peer_l2_hdr_type[peer_l2_type]++;
	IPACMDBG_H("Now the ref_cnt of peer l2 hdr type %s is %d.\n", ipa_l2_hdr_type[peer_l2_type],
		ref_cnt_peer_l2_hdr_type[peer_l2_type]);

	return;
}

void IPACM_LanToLan_Iface::decrement_ref_cnt_peer_l2_hdr_type(ipa_hdr_l2_type peer_l2_type)
{
	ref_cnt_peer_l2_hdr_type[peer_l2_type]--;
	IPACMDBG_H("Now the ref_cnt of peer l2 hdr type %s is %d.\n", ipa_l2_hdr_type[peer_l2_type],
		ref_cnt_peer_l2_hdr_type[peer_l2_type]);

	return;
}

bool IPACM_LanToLan_Iface::get_m_support_ast_update()
{
	IPACMDBG_H("Support AST update %s? %d\n", m_p_iface->dev_name,
		m_ast_update);
	return m_ast_update;
}

#ifdef FEATURE_L2TP
bool IPACM_LanToLan_Iface::set_l2tp_iface(char *vlan_iface_name)
{
	IPACMDBG_H("Self iface %s, vlan iface %s\n", m_p_iface->dev_name,
		vlan_iface_name);

	if(m_is_l2tp_iface == false)
	{
		if(strncmp(m_p_iface->dev_name, vlan_iface_name, strlen(m_p_iface->dev_name)) == 0)
		{
			IPACMDBG_H("This interface is l2tp interface.\n");
			m_is_l2tp_iface = true;
		}
	}
	return m_is_l2tp_iface;
}

bool IPACM_LanToLan_Iface::is_l2tp_iface()
{
	return m_is_l2tp_iface;
}

void IPACM_LanToLan_Iface::switch_to_l2tp_iface()
{
	list<peer_iface_info>::iterator it_peer;
	list<flt_rule_info>::iterator it_flt;
	uint32_t l2tp_flt_rule_hdl = 0;

	for(it_peer = m_peer_iface_info.begin(); it_peer != m_peer_iface_info.end(); it_peer++)
	{
		for(it_flt = it_peer->flt_rule.begin(); it_flt != it_peer->flt_rule.end(); it_flt++)
		{
			if(m_is_ip_addr_assigned[IPA_IP_v4])
			{
				m_p_iface->eth_bridge_del_flt_rule(it_flt->flt_rule_hdl[IPA_IP_v4], IPA_IP_v4);
				IPACMDBG_H("Deleted IPv4 flt rule %d.\n", it_flt->flt_rule_hdl[IPA_IP_v4]);
			}
			if(m_is_ip_addr_assigned[IPA_IP_v6])
			{
				m_p_iface->eth_bridge_del_flt_rule(it_flt->flt_rule_hdl[IPA_IP_v6], IPA_IP_v6);
				m_p_iface->add_l2tp_flt_rule(it_flt->p_client->mac_addr, &l2tp_flt_rule_hdl);
				IPACMDBG_H("Deleted IPv6 flt rule %d.\n", it_flt->flt_rule_hdl[IPA_IP_v6]);
				it_flt->l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls.push_front(l2tp_flt_rule_hdl);
			}
		}
	}
	return;
}
void IPACM_LanToLan_Iface::handle_l2tp_enable()
{
	int i;
	ipa_hdr_l2_type peer_l2_hdr_type;
	list<peer_iface_info>::iterator it_peer_info;
	list<client_info>::iterator it_client;
	bool flag[IPA_HDR_L2_MAX];

	if(m_support_inter_iface_offload)
	{
		memset(flag, 0, sizeof(flag));
		for(it_peer_info = m_peer_iface_info.begin(); it_peer_info != m_peer_iface_info.end(); it_peer_info++)
		{
			if(it_peer_info->peer->is_l2tp_iface())
			{
				peer_l2_hdr_type = it_peer_info->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
				flag[peer_l2_hdr_type] = true;
			}
		}

		for(i = 0; i < IPA_HDR_L2_MAX; i++)
		{
			if(flag[i] == true)
			{
				IPACMDBG_H("Add rt rule for peer l2 type %s\n", ipa_l2_hdr_type[i]);
				for(it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
				{
#ifdef IPA_L2TP_TUNNEL_UDP
					m_p_iface->add_l2tp_udp_rt_rule(IPA_IP_v6, it_client->mac_addr, &hdr_proc_ctx_for_l2tp,
						&it_client->l2tp_rt_rule_hdl[i].num_rt_hdl[IPA_IP_v6],
						it_client->l2tp_rt_rule_hdl[i].first_pass_rt_rule_hdl[IPA_IP_v6]);
#else
					m_p_iface->add_l2tp_rt_rule(IPA_IP_v6, it_client->mac_addr, &hdr_proc_ctx_for_l2tp,
						&it_client->l2tp_rt_rule_hdl[i].num_rt_hdl[IPA_IP_v6],
						it_client->l2tp_rt_rule_hdl[i].first_pass_rt_rule_hdl[IPA_IP_v6]);

#endif
				}
			}
		}
	}
	return;
}

void IPACM_LanToLan_Iface::handle_l2tp_disable()
{
	int i;
	ipa_hdr_l2_type peer_l2_hdr_type;
	list<peer_iface_info>::iterator it_peer_info;
	list<client_info>::iterator it_client;
	bool flag[IPA_HDR_L2_MAX];

	if(m_support_inter_iface_offload)
	{
		memset(flag, 0, sizeof(flag));
		for(it_peer_info = m_peer_iface_info.begin(); it_peer_info != m_peer_iface_info.end(); it_peer_info++)
		{
			peer_l2_hdr_type = it_peer_info->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
			flag[peer_l2_hdr_type] = true;
		}

		for(i = 0; i < IPA_HDR_L2_MAX; i++)
		{
			if(flag[i] == true)
			{
				IPACMDBG_H("Delete rt rule for peer l2 type %s\n", ipa_l2_hdr_type[i]);
				for(it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
				{
					m_p_iface->del_l2tp_rt_rule(IPA_IP_v6, it_client->l2tp_rt_rule_hdl[i].num_rt_hdl[IPA_IP_v6],
						it_client->l2tp_rt_rule_hdl[i].first_pass_rt_rule_hdl[IPA_IP_v6]);
				}
			}
		}
	}
	return;
}
#endif

int IPACM_LanToLan_Iface::add_wlan_svap_hpc_hdl(uint16_t vlan_id, ipa_hdr_l2_type peer_l2_type, uint32_t* hpc_hdl)
{

	if (num_of_wlan_svap_hpc_hdls >= MAX_SVAP_VLAN) {
		IPACMDBG_H("Max number of entries %d, cannot add more \n", num_of_wlan_svap_hpc_hdls);
		return IPACM_FAILURE;
	}

	for (int i = 0; i < num_of_wlan_svap_hpc_hdls; i++) {
		if (wlan_svap_hpc_hdls[i].vlan_id == vlan_id &&
			wlan_svap_hpc_hdls[i].peer_l2_type == peer_l2_type)
		{
			IPACMDBG_H("Entry with vlan_id %d and peer %d, already exists\n", vlan_id, peer_l2_type);
			wlan_svap_hpc_hdls[i].hpc_hdr_hdl = hpc_hdl[0];
			return IPACM_SUCCESS;
		}
	}

	// Entry not found create a new one
	IPACMDBG_H("Entry with vlan_id %d and peer %d, absent, create a new entry\n", vlan_id, peer_l2_type);
	wlan_svap_hpc_hdls[num_of_wlan_svap_hpc_hdls].vlan_id = vlan_id;
	wlan_svap_hpc_hdls[num_of_wlan_svap_hpc_hdls].peer_l2_type = peer_l2_type;
	wlan_svap_hpc_hdls[num_of_wlan_svap_hpc_hdls].hpc_hdr_hdl = hpc_hdl[0];

	num_of_wlan_svap_hpc_hdls++;

	return IPACM_SUCCESS;
}

int IPACM_LanToLan_Iface::del_wlan_svap_hpc_hdl(uint16_t vlan_id, ipa_hdr_l2_type peer_l2_type, uint32_t* hpc_hdl)
{

	if (num_of_wlan_svap_hpc_hdls <= 0) {
		IPACMDBG_H("No entries present, %d entries to delete \n", num_of_wlan_svap_hpc_hdls);
		return IPACM_FAILURE;
	}

	for (int i = 0; i < num_of_wlan_svap_hpc_hdls; i++) {
		if (wlan_svap_hpc_hdls[i].vlan_id == vlan_id &&
			wlan_svap_hpc_hdls[i].peer_l2_type == peer_l2_type)
		{
			IPACMDBG_H("Entry with vlan_id %d and peer %d, exists, delete entry\n", vlan_id, peer_l2_type);
			for(int k = i; k < num_of_wlan_svap_hpc_hdls - 1; k++)
			{
				wlan_svap_hpc_hdls[k].hpc_hdr_hdl = wlan_svap_hpc_hdls[k+1].hpc_hdr_hdl ;
				wlan_svap_hpc_hdls[k].vlan_id = wlan_svap_hpc_hdls[k+1].vlan_id;
				wlan_svap_hpc_hdls[k].peer_l2_type = wlan_svap_hpc_hdls[k+1].peer_l2_type;
			}
			num_of_wlan_svap_hpc_hdls--;
			wlan_svap_hpc_hdls[num_of_wlan_svap_hpc_hdls].hpc_hdr_hdl = 0;
			wlan_svap_hpc_hdls[num_of_wlan_svap_hpc_hdls].vlan_id = 0;
			wlan_svap_hpc_hdls[num_of_wlan_svap_hpc_hdls].peer_l2_type = IPA_HDR_L2_NONE;
			return IPACM_SUCCESS;
		}
	}

	// Entry not found
	IPACMDBG_H("Entry with vlan_id %d and peer %d, absent, nothing to delete\n", vlan_id, peer_l2_type);
	return IPACM_SUCCESS;
}

uint32_t IPACM_LanToLan_Iface::is_entry_present_wlan_svap_hpc_hdl(uint16_t vlan_id, ipa_hdr_l2_type peer_l2_type)
{
	uint32_t ret = false;

	for (int i = 0; i < num_of_wlan_svap_hpc_hdls; i++) {
		if (wlan_svap_hpc_hdls[i].vlan_id == vlan_id &&
			wlan_svap_hpc_hdls[i].peer_l2_type == peer_l2_type)
		{
			ret = wlan_svap_hpc_hdls[i].hpc_hdr_hdl;
			IPACMDBG_H("Entry with vlan_id %d and peer %d, present, hdl: %d\n", vlan_id, peer_l2_type, ret);
			return ret;
		}
	}
	IPACMDBG_H("Entry with vlan_id %d and peer %d, absent\n", vlan_id, peer_l2_type);

	return ret;
}

int IPACM_LanToLan_Iface::add_peer_bridge_flt_rule(uint32_t bridge_ipv4, uint32_t subnet_mask, ipa_ip_type ip_type, uint32_t *ipv6_prefix)
{
	list<flt_rule_info>::iterator it_flt;
	list<flt_rule_hdl_interbridge>::iterator itr_flt_rule_inter_bridge;
	client_info inter_client;
	bool continue_interration = false;
	int ret = IPACM_FAILURE;
	list<client_info>::iterator it_client;
	IPACMDBG_H("ip_type %d \n", ip_type);
	if(ip_type == IPA_IP_v4)
	{
		IPACMDBG_H("self %s has ", self.peer->m_p_iface->dev_name);
		iptodot(" peer bridge_ipv4 ip", bridge_ipv4);
		IPACMDBG_H("self %s has ", self.peer->m_p_iface->dev_name);
		iptodot(" peer subnet mask", subnet_mask);

		IPACMDBG_H("self client size %d\n", m_client_info.size());
		for (it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
		{
			IPACMDBG_H("currently checking client MAC 0x[%X][%X][%X][%X][%X][%X] vlan %d\n",
				it_client->mac_addr[0], it_client->mac_addr[1], it_client->mac_addr[2],
				it_client->mac_addr[3], it_client->mac_addr[4], it_client->mac_addr[5],
				it_client->vlan_id);
			for (it_flt = self.flt_rule.begin(); it_flt != self.flt_rule.end(); it_flt++)
			{
				if ((memcmp(it_client->mac_addr, it_flt->p_client->mac_addr, sizeof(it_client->mac_addr)) == 0) &&
						it_client->vlan_id == it_flt->p_client->vlan_id)
				{
					for (itr_flt_rule_inter_bridge = it_flt->flt_rule_inter_bridge.begin();
						itr_flt_rule_inter_bridge != it_flt->flt_rule_inter_bridge.end(); itr_flt_rule_inter_bridge++)
					{
						IPACMDBG_H("itr_flt_rule_inter_bridge->bridge_ipv4 : ");
						iptodot("ip", itr_flt_rule_inter_bridge->bridge_ipv4);
						if (itr_flt_rule_inter_bridge->bridge_ipv4 == bridge_ipv4)
						{
							IPACMDBG_H("Bridge Filter rule already Present!. Continue.\n");
							continue_interration = true;
							break;
						}
					}
					if (continue_interration == true)
					{
						continue_interration = false;
						continue;
					}
					if (it_flt->bridge_ipv4 == bridge_ipv4)
					{
						IPACMDBG_H("self Bridge ip ignore. Continue.\n");
						continue;
					}
					IPACMDBG_H(" Install Inter bridge offload flt rule on peer for client with dest subnet\n");
					memset(&inter_client, 0, sizeof(inter_client));
					IPACMDBG_H("Adding rule for client MAC 0x[%X][%X][%X][%X][%X][%X] vlan %d\n",
								it_client->mac_addr[0], it_client->mac_addr[1], it_client->mac_addr[2],
								it_client->mac_addr[3], it_client->mac_addr[4], it_client->mac_addr[5],
								it_client->vlan_id);
					IPACMDBG_H("iface_name %s\n", it_client->iface_name);
					memcpy(inter_client.mac_addr, it_client->mac_addr, sizeof(inter_client.mac_addr));
					inter_client.is_l2tp_client = it_client->is_l2tp_client;
					inter_client.mapping_info = it_client->mapping_info;
					inter_client.vlan_id = it_client->vlan_id;
					inter_client.bridge_ipv4 = bridge_ipv4;
					inter_client.subnet_mask = subnet_mask;
					ret = add_client_flt_rule(&self, &inter_client, IPA_IP_v4, true);
					if(ret == IPACM_FAILURE)
					{
						IPACMERR("Lan2Lan_v2 (%d) : Failed to install flt rule.\n", ip_type);
						return IPACM_FAILURE;
					}
				}
			}
		}
	}
	else if(ip_type == IPA_IP_v6)
	{
		IPACMDBG_H("self %s has v6 prefix 0x%x:%x:%x:%x\n", self.peer->m_p_iface->dev_name, ipv6_prefix[0], ipv6_prefix[1]);
		for (it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
		{
			IPACMDBG_H("currently checking client MAC 0x[%X][%X][%X][%X][%X][%X] vlan %d\n",
				it_client->mac_addr[0], it_client->mac_addr[1], it_client->mac_addr[2],
				it_client->mac_addr[3], it_client->mac_addr[4], it_client->mac_addr[5],
				it_client->vlan_id);
			for (it_flt = self.flt_rule.begin(); it_flt != self.flt_rule.end(); it_flt++)
			{
				IPACMDBG_H("ipv6_prefix 0x[%X][%X] \n", it_flt->ipv6_prefix[0], it_flt->ipv6_prefix[1]);
				if ((memcmp(it_client->mac_addr, it_flt->p_client->mac_addr, sizeof(it_client->mac_addr)) == 0) &&
						it_client->vlan_id == it_flt->p_client->vlan_id)
				{
					for (itr_flt_rule_inter_bridge = it_flt->flt_rule_inter_bridge.begin();
						itr_flt_rule_inter_bridge != it_flt->flt_rule_inter_bridge.end(); itr_flt_rule_inter_bridge++)
					{
						IPACMDBG_H("itr_flt_rule_inter_bridge->ipv6_prefix 0x[%X][%X] \n", itr_flt_rule_inter_bridge->ipv6_prefix[0], itr_flt_rule_inter_bridge->ipv6_prefix[1]);
						if((itr_flt_rule_inter_bridge->ipv6_prefix[0] == ipv6_prefix[0]) &&
							(itr_flt_rule_inter_bridge->ipv6_prefix[1] == ipv6_prefix[1]))
						{
							IPACMDBG_H("Prefix Filter rule already Present!. Continue.\n");
							continue_interration = true;
							break;
						}
					}
					if (continue_interration == true)
					{
						continue_interration = false;
						continue;
					}

					if((it_flt->ipv6_prefix[0] == ipv6_prefix[0]) && (it_flt->ipv6_prefix[1] == ipv6_prefix[1]))
					{
						IPACMDBG_H("self Bridge ip ignore. Continue.\n");
						continue;
					}
					IPACMDBG_H(" Install Inter bridge offload flt rule on peer for client with client prefix  0x[%X][%X]\n", ipv6_prefix[0], ipv6_prefix[1]);
					memset(&inter_client, 0, sizeof(inter_client));
					IPACMDBG_H("Adding rule for client MAC 0x[%X][%X][%X][%X][%X][%X] vlan %d\n",
								it_client->mac_addr[0], it_client->mac_addr[1], it_client->mac_addr[2],
								it_client->mac_addr[3], it_client->mac_addr[4], it_client->mac_addr[5],
								it_client->vlan_id);
					IPACMDBG_H("iface_name %s\n", it_client->iface_name);
					memcpy(inter_client.mac_addr, it_client->mac_addr, sizeof(inter_client.mac_addr));
					inter_client.is_l2tp_client = it_client->is_l2tp_client;
					inter_client.mapping_info = it_client->mapping_info;
					inter_client.vlan_id = it_client->vlan_id;
					memcpy(inter_client.ipv6_prefix, ipv6_prefix, sizeof(inter_client.ipv6_prefix));
					ret = add_client_flt_rule(&self, &inter_client, IPA_IP_v6, true);
					if(ret == IPACM_FAILURE)
					{
						IPACMERR("Lan2Lan_v2 (%d) : Failed to install flt rule.\n", ip_type);
						return IPACM_FAILURE;
					}
				}
			}
		}
	}
	else
	{
		IPACMERR("Wrong ip_type!!\n");
		return IPACM_FAILURE;
	}
	return IPACM_SUCCESS;
}

int IPACM_LanToLan_Iface::add_bridge_self_vlan_client(client_info * client, ipa_ip_type ip_type)
{
	bool continue_interration = false;
	client_info inter_client;
	int ret = IPACM_FAILURE;

	if(ip_type == IPA_IP_v4)
	{
		for(auto bridge_itr = bridges.begin();bridge_itr != bridges.end(); bridge_itr++)
		{
			IPACMDBG_H(" bridge ");
			iptodot("ip", bridge_itr->first);
		}
		for (auto it_flt = self.flt_rule.begin(); it_flt != self.flt_rule.end(); it_flt++)
		{
			if ((memcmp(client->mac_addr, it_flt->p_client->mac_addr, sizeof(client->mac_addr)) == 0) && client->vlan_id == it_flt->p_client->vlan_id)
			{
				for(auto bridge_itr = bridges.begin();bridge_itr != bridges.end(); bridge_itr++)
				{
					for (auto itr_flt_rule_inter_bridge = it_flt->flt_rule_inter_bridge.begin(); itr_flt_rule_inter_bridge != it_flt->flt_rule_inter_bridge.end(); itr_flt_rule_inter_bridge++)
					{
						if(bridge_itr->first == itr_flt_rule_inter_bridge->bridge_ipv4)
						{
							continue_interration =true;
							break;
						}
					}
					if (continue_interration == true)
					{
						continue_interration = false;
						continue;
					}
					if (it_flt->bridge_ipv4 == bridge_itr->first)
					{
						IPACMDBG_H("self Bridge ip ignore. Continue.\n");
						continue;
					}
					IPACMDBG_H(" bridge not found in filter list install rule 0x%X",bridge_itr->first);
									memset(&inter_client, 0, sizeof(inter_client));
					IPACMDBG_H("Adding rule for client MAC 0x[%X][%X][%X][%X][%X][%X] vlan %d\n",
								client->mac_addr[0], client->mac_addr[1], client->mac_addr[2],
								client->mac_addr[3], client->mac_addr[4], client->mac_addr[5],
								client->vlan_id);
					IPACMDBG_H("iface_name %s\n", client->iface_name);
					memcpy(inter_client.mac_addr, client->mac_addr, sizeof(inter_client.mac_addr));
					inter_client.is_l2tp_client = client->is_l2tp_client;
					inter_client.mapping_info = client->mapping_info;
					inter_client.vlan_id = client->vlan_id;
					inter_client.bridge_ipv4 = bridge_itr->first;
					inter_client.subnet_mask = bridge_itr->second;
					ret = add_client_flt_rule(&self, &inter_client, IPA_IP_v4, true);
					if(ret == IPACM_FAILURE)
					{
						IPACMERR("Lan2Lan_v2 (%d) : Failed to install flt rule.\n", ip_type);
						return IPACM_FAILURE;
					}
				}
			}
		}
	}
	else if(ip_type == IPA_IP_v6)
	{
		IPACMDBG_H("ipv6_prefix 0x[%X][%X] for vlan id %d\n", client->ipv6_prefix[0], client->ipv6_prefix[1], client->vlan_id);
		for (auto it_flt = self.flt_rule.begin(); it_flt != self.flt_rule.end(); it_flt++)
		{
			if ((memcmp(client->mac_addr, it_flt->p_client->mac_addr, sizeof(client->mac_addr)) == 0) && client->vlan_id == it_flt->p_client->vlan_id)
			{
				for(auto bridge_itr = lan_client_v6_prefix.begin();bridge_itr != lan_client_v6_prefix.end(); bridge_itr++)
				{
					for (auto itr_flt_rule_inter_bridge = it_flt->flt_rule_inter_bridge.begin(); itr_flt_rule_inter_bridge != it_flt->flt_rule_inter_bridge.end(); itr_flt_rule_inter_bridge++)
					{
						IPACMDBG_H("bridge_itr ipv6_prefix 0x[%X][%X] \n", bridge_itr->first, bridge_itr->second);
						IPACMDBG_H("itr_flt_rule_inter_bridge ipv6_prefix 0x[%X][%X] \n", itr_flt_rule_inter_bridge->ipv6_prefix[0], itr_flt_rule_inter_bridge->ipv6_prefix[1]);
						if((bridge_itr->first == itr_flt_rule_inter_bridge->ipv6_prefix[0]) &&
							(bridge_itr->second == itr_flt_rule_inter_bridge->ipv6_prefix[1]))
						{
							continue_interration =true;
							break;
						}
					}
					if (continue_interration == true)
					{
						continue_interration = false;
						continue;
					}
					if((bridge_itr->first == it_flt->ipv6_prefix[0]) &&
						(bridge_itr->second == it_flt->ipv6_prefix[1]))
					{
						IPACMDBG_H("Same v6 Prefix ignore. Continue.\n");
						continue;
					}
					IPACMDBG_H(" Prefix not found in filter list install rule 0x[%X][%X]\n",bridge_itr->first, bridge_itr->second);
									memset(&inter_client, 0, sizeof(inter_client));
					IPACMDBG_H("Adding rule for client MAC 0x[%X][%X][%X][%X][%X][%X] vlan %d\n",
								client->mac_addr[0], client->mac_addr[1], client->mac_addr[2],
								client->mac_addr[3], client->mac_addr[4], client->mac_addr[5],
								client->vlan_id);
					IPACMDBG_H("iface_name %s\n", client->iface_name);
					memcpy(inter_client.mac_addr, client->mac_addr, sizeof(inter_client.mac_addr));
					inter_client.is_l2tp_client = client->is_l2tp_client;
					inter_client.mapping_info = client->mapping_info;
					inter_client.vlan_id = client->vlan_id;
					inter_client.ipv6_prefix[0] = bridge_itr->first;
					inter_client.ipv6_prefix[1] = bridge_itr->second;
					ret = add_client_flt_rule(&self, &inter_client, IPA_IP_v6, true);
					if(ret == IPACM_FAILURE)
					{
						IPACMERR("Lan2Lan_v2 (%d) : Failed to install flt rule.\n", ip_type);
						return IPACM_FAILURE;
					}
				}
			}
		}
	}
	else
	{
		IPACMERR("Wrong ip_type!!\n");
		return IPACM_FAILURE;
	}
	return IPACM_SUCCESS;
}
