/*
Copyright (c) 2014-2021, The Linux Foundation. All rights reserved.

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

#define __stringify(x...) #x

const char *ipa_l2_hdr_type[] = {
	__stringify(NONE),
	__stringify(ETH_II),
	__stringify(802_3),
	__stringify(802_1Q),
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
	m_is_l2tp_iface = false;
#ifdef FEATURE_VLAN_MPDN
	m_is_vlan = false;
#endif
	for(i = 0; i < IPA_HDR_L2_MAX; i++)
	{
		ref_cnt_peer_l2_hdr_type[i] = 0;
		hdr_proc_ctx_for_inter_interface[i] = 0;
	}
	hdr_proc_ctx_for_intra_interface = 0;
	hdr_proc_ctx_for_l2tp = 0;

	if(p_iface->ipa_if_cate == WLAN_IF)
	{
		IPACMDBG_H("Interface %s is WLAN interface.\n", p_iface->dev_name);
		m_support_intra_iface_offload = true;
		if( ((IPACM_Wlan*)p_iface)->is_guest_ap() )
		{
			IPACMDBG_H("Interface %s is guest AP.\n", p_iface->dev_name);
			m_support_inter_iface_offload = false;
		}
	}
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
	ipa_ioc_vlan_iface_info *vlan_iface_data;

#ifdef FEATURE_L2TP
	ipa_ioc_l2tp_vlan_mapping_info *l2tp_vlan_mapping_data;
#endif
	ipacm_event_data_all *vlan_data;

	IPACMDBG_H("Get %s event.\n", IPACM_Iface::ipacmcfg->getEventName(event));

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
		IPACMDBG_H("Vlan iface\n");
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
					if(it->get_m_support_inter_iface_offload())
						it->add_all_inter_interface_client_flt_rule(data->iptype, Ids);
				}
				else
#endif //FEATURE_VLAN_MPDN
				{
					/* install inter-interface rules */
					if(it->get_m_support_inter_iface_offload())
						it->add_all_inter_interface_client_flt_rule(data->iptype);

					/* install intra-BSS rules */
					if(it->get_m_support_intra_iface_offload())
						it->add_all_intra_interface_client_flt_rule(data->iptype);
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
		IPACMDBG_H("Now the total number of interfaces is %d.\n", m_iface.size());

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
			for(it = ++m_iface.begin(); it != m_iface.end(); it++)
			{
				if(!it->get_is_vlan())
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
			}

			/* add client specific filtering rule on new interface for matching vlan ids*/
			front_iface.add_all_inter_interface_client_flt_rule(data->iptype, Ids);

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
#ifdef FEATURE_VLAN_MPDN
				/* non VLAN case - currently no support for non vlan <-> vlan offload */
				if(it->get_is_vlan())
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
			}

			/* add client specific filtering rule on new interface */
			front_iface.add_all_inter_interface_client_flt_rule(data->iptype);
		}

		/* populate the intra-interface information */
		if(front_iface.get_m_support_intra_iface_offload())
		{
			front_iface.handle_intra_interface_info();
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

	IPACMDBG_H("Populate peer info between: new_iface %s, existing iface %s\n", new_iface->get_iface_pointer()->dev_name,
		exist_iface->get_iface_pointer()->dev_name);

	/* populate the routing table information */
	snprintf(rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_%s_to_%s",
		ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type],
		ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
	IPACMDBG_H("IPv4 routing table for flt name: %s\n", rt_tbl_name_for_flt[IPA_IP_v4]);

	snprintf(rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_%s_to_%s",
		ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type],
		ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
	IPACMDBG_H("IPv6 routing table for flt name: %s\n", rt_tbl_name_for_flt[IPA_IP_v6]);

	snprintf(rt_tbl_name_for_rt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX, "eth_v4_%s_to_%s",
		ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type],
		ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
	IPACMDBG_H("IPv4 routing table for rt name: %s\n", rt_tbl_name_for_rt[IPA_IP_v4]);

	snprintf(rt_tbl_name_for_rt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX, "eth_v6_%s_to_%s",
		ipa_l2_hdr_type[new_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type],
		ipa_l2_hdr_type[exist_iface->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type]);
	IPACMDBG_H("IPv6 routing table for rt name: %s\n", rt_tbl_name_for_rt[IPA_IP_v6]);

	/* add new peer info in both new iface and existing iface */
	exist_iface->handle_new_iface_up(rt_tbl_name_for_flt, rt_tbl_name_for_rt, new_iface);

	new_iface->handle_new_iface_up(rt_tbl_name_for_rt, rt_tbl_name_for_flt, exist_iface);

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

void IPACM_LanToLan::handle_client_add(ipacm_event_eth_bridge *data)
{
	list<IPACM_LanToLan_Iface>::iterator it_iface;
	list<l2tp_vlan_mapping_info>::iterator it_mapping;
	l2tp_vlan_mapping_info *mapping_info = NULL;
	bool is_l2tp_client = false;

	IPACMDBG_H("Incoming client MAC: 0x%02x%02x%02x%02x%02x%02x, interface: %s\n", data->mac_addr[0], data->mac_addr[1],
		data->mac_addr[2], data->mac_addr[3], data->mac_addr[4], data->mac_addr[5], data->p_iface->dev_name);
#ifdef FEATURE_L2TP
	if(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP)
	{
		for(it_mapping = IPACM_Iface::ipacmcfg->m_l2tp_vlan_mapping.begin(); it_mapping != IPACM_Iface::ipacmcfg->m_l2tp_vlan_mapping.end(); it_mapping++)
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
	for(it_iface = m_iface.begin(); it_iface != m_iface.end(); it_iface++)
	{
		if(it_iface->get_iface_pointer() == data->p_iface)	//find the interface
		{
			IPACMDBG_H("Found the interface.\n");
#ifdef FEATURE_VLAN_MPDN
			if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == true)
			{
				if(it_iface->get_is_vlan())
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
			it_iface->handle_client_add(data->mac_addr, is_l2tp_client, mapping_info, data->VlanID);
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
	return;
}

void IPACM_LanToLan::handle_client_del(ipacm_event_eth_bridge *data)
{
	list<IPACM_LanToLan_Iface>::iterator it_iface;

	IPACMDBG_H("Incoming client MAC: 0x%02x%02x%02x%02x%02x%02x, interface: %s\n", data->mac_addr[0], data->mac_addr[1],
		data->mac_addr[2], data->mac_addr[3], data->mac_addr[4], data->mac_addr[5], data->p_iface->dev_name);
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
	IPACMDBG_H("There are %d interfaces in total.\n", m_iface.size());
	for(it = m_iface.begin(); it != m_iface.end(); it++)
	{
		it->print_data_structure_info();
	}

	IPACMDBG_H("There are %d cached client add events in total.\n", m_cached_client_add_event.size());

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
	ipa_hdr_l2_type peer_l2_type;
	peer_iface_info &peer = m_peer_iface_info.front();

	peer_l2_type = peer.peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
	if(ref_cnt_peer_l2_hdr_type[peer_l2_type] == 1)
	{
		for(it = m_client_info.begin(); it != m_client_info.end(); it++)
		{
#ifdef FEATURE_L2TP
			if(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP)
			{
				if(it->is_l2tp_client == false)
				{
					add_client_rt_rule(&peer, &(*it));
				}
				/* add l2tp rt rules */
				add_l2tp_client_rt_rule(&peer, &(*it));
			}
			else
				add_client_rt_rule(&peer, &(*it));
#else
			add_client_rt_rule(&peer, &(*it));
#endif
		}
	}

	return;
}

void IPACM_LanToLan_Iface::add_client_rt_rule(peer_iface_info *peer_info, client_info *client)
{
	int i, num_rt_rule = 0;
	uint32_t rt_rule_hdl[MAX_NUM_PROP];
	ipa_hdr_l2_type peer_l2_hdr_type;
#ifdef FEATURE_VLAN_MPDN
	std::array<uint8_t, 6> mac = {0};
	std::map<std::array<uint8_t, 6>, int >::iterator it;
#endif

	peer_l2_hdr_type = peer_info->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;

	/* if the peer info is not for intra interface communication */
	if(peer_info->peer != this)
	{
		IPACMDBG_H("This is for inter interface communication.\n");
#ifdef FEATURE_VLAN_MPDN
		if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable)
		{
			/* create mac as array and use it as key for a map that holdw a reference count per MAC */
			std::copy(std::begin(client->mac_addr), std::end(client->mac_addr), std::begin(mac));
			if(client->vlan_id)
				IPACMDBG_H("client vlan id %d\n", client->vlan_id);

			/* check if peer already has rt rule for this mac address */
			it = peer_info->mac_rt_rule_ref.find(mac);
			if(it != peer_info->mac_rt_rule_ref.end())
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
		}
#endif
		IPACMDBG_H("peer iface %s doesn't have rt rule for mac 0x[%X][%X][%X][%X][%X][%X], adding now\n",
			peer_info->peer->get_iface_pointer()->dev_name,
			client->mac_addr[0], client->mac_addr[1], client->mac_addr[2], client->mac_addr[3], client->mac_addr[4], client->mac_addr[5])

		m_p_iface->eth_bridge_add_rt_rule(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v4], hdr_proc_ctx_for_inter_interface[peer_l2_hdr_type],
			peer_l2_hdr_type, IPA_IP_v4, rt_rule_hdl, &num_rt_rule);

		client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v4] = num_rt_rule;
		IPACMDBG_H("Number of IPv4 routing rule is %d.\n", num_rt_rule);
		for(i=0; i<num_rt_rule; i++)
		{
			IPACMDBG_H("Routing rule %d handle %d\n", i, rt_rule_hdl[i]);
			client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v4][i] = rt_rule_hdl[i];
		}

		m_p_iface->eth_bridge_add_rt_rule(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v6], hdr_proc_ctx_for_inter_interface[peer_l2_hdr_type],
			peer_l2_hdr_type, IPA_IP_v6, rt_rule_hdl, &num_rt_rule);

		client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].num_hdl[IPA_IP_v6] = num_rt_rule;
		IPACMDBG_H("Number of IPv6 routing rule is %d.\n", num_rt_rule);
		for(i=0; i<num_rt_rule; i++)
		{
			IPACMDBG_H("Routing rule %d handle %d\n", i, rt_rule_hdl[i]);
			client->inter_iface_rt_rule_hdl[peer_l2_hdr_type].rule_hdl[IPA_IP_v6][i] = rt_rule_hdl[i];
		}
	}
	else
	{
		IPACMDBG_H("This is for intra interface communication.\n");
		m_p_iface->eth_bridge_add_rt_rule(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v4], hdr_proc_ctx_for_intra_interface,
			peer_l2_hdr_type, IPA_IP_v4, rt_rule_hdl, &num_rt_rule);

		client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v4] = num_rt_rule;
		IPACMDBG_H("Number of IPv4 routing rule is %d.\n", num_rt_rule);
		for(i=0; i<num_rt_rule; i++)
		{
			IPACMDBG_H("Routing rule %d handle %d\n", i, rt_rule_hdl[i]);
			client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v4][i] = rt_rule_hdl[i];
		}

		m_p_iface->eth_bridge_add_rt_rule(client->mac_addr, peer_info->rt_tbl_name_for_rt[IPA_IP_v6], hdr_proc_ctx_for_intra_interface,
			peer_l2_hdr_type, IPA_IP_v6, rt_rule_hdl, &num_rt_rule);

		client->intra_iface_rt_rule_hdl.num_hdl[IPA_IP_v6] = num_rt_rule;
		IPACMDBG_H("Number of IPv6 routing rule is %d.\n", num_rt_rule);
		for(i=0; i<num_rt_rule; i++)
		{
			IPACMDBG_H("Routing rule %d handle %d\n", i, rt_rule_hdl[i]);
			client->intra_iface_rt_rule_hdl.rule_hdl[IPA_IP_v6][i] = rt_rule_hdl[i];
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
			if (vlan_id == it_client->vlan_id)
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

void IPACM_LanToLan_Iface::add_one_client_flt_rule(IPACM_LanToLan_Iface *peer_iface, client_info *client)
{
	list<peer_iface_info>::iterator it;

	for(it = m_peer_iface_info.begin(); it != m_peer_iface_info.end(); it++)
	{
		if(it->peer == peer_iface)
		{
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

void IPACM_LanToLan_Iface::add_client_flt_rule(peer_iface_info *peer, client_info *client, ipa_ip_type iptype)
{
	list<flt_rule_info>::iterator it_flt;
	list<client_info>::iterator it;
	uint32_t flt_rule_hdl = 0, l2tp_flt_rule_hdl = 0, l2tp_second_pass_flt_rule_hdl = 0;
	list<uint32_t> flt_rule_hdls = std::list<uint32_t>();
	flt_rule_info new_flt_info;
	ipa_ioc_get_rt_tbl rt_tbl;

	if(m_is_l2tp_iface && iptype == IPA_IP_v4)
	{
		IPACMDBG_H("No need to install IPv4 flt rule on l2tp interface.\n");
		return;
	}

	for(it_flt = peer->flt_rule.begin(); it_flt != peer->flt_rule.end(); it_flt++)
	{
		if(it_flt->p_client == client)	//the client is already in the flt info list
		{
			IPACMDBG_H("The client is found in flt info list.\n");
			break;
		}
	}
#ifdef FEATURE_VLAN_MPDN
	if(m_is_vlan)
	{
		if(!client->vlan_id)
		{
			IPACMERR("VLAN IFACE and non VLAN client\n");
			return;
		}
		if(it_flt != peer->flt_rule.end())
		{
			if(it_flt->flt_rule_hdl[iptype]) {
				IPACMDBG_H("not adding rule for already found client 0x[%X][%X][%X][%X][%X][%X] vlan %d, iptype %d\n",
					it_flt->p_client->mac_addr[0], it_flt->p_client->mac_addr[1], it_flt->p_client->mac_addr[2],
					it_flt->p_client->mac_addr[3], it_flt->p_client->mac_addr[4], it_flt->p_client->mac_addr[5],
					it_flt->p_client->vlan_id, iptype);
				return;
			}

			IPACMDBG_H("flt rule is already present for other iptype (not %d), continue\n", iptype);
		}

		uint16_t Ids[IPA_MAX_NUM_OFFLOAD_VLANS];

		if(IPACM_Iface::ipacmcfg->get_iface_vlan_ids(get_iface_pointer()->dev_name, Ids))
		{
			IPACMERR("failed getting vlan ids for iface %s\n", get_iface_pointer()->dev_name);
			return;
		}

		int i;
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
			return;
		}
	}
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
			rt_tbl.ip = iptype;
			memcpy(rt_tbl.name, peer->rt_tbl_name_for_flt[iptype], sizeof(rt_tbl.name));
			IPACMDBG_H("This flt rule points to rt tbl %s.\n", rt_tbl.name);

			if(IPACM_Iface::m_routing.GetRoutingTable(&rt_tbl) == false)
			{
				IPACMERR("Failed to get routing table.\n");
				return;
			}

			m_p_iface->eth_bridge_add_flt_rule(client->mac_addr, rt_tbl.hdl,
				iptype, &flt_rule_hdl, client->vlan_id);
			IPACMDBG_H("Installed flt rule for IP type %d: handle %d\n", iptype, flt_rule_hdl);
		}
	}

	if(it_flt != peer->flt_rule.end())
	{
		it_flt->flt_rule_hdl[iptype] = flt_rule_hdl;
		it_flt->l2tp_first_pass_flt_rule_hdl[iptype].flt_rule_hdls = flt_rule_hdls;
		it_flt->l2tp_second_pass_flt_rule_hdl = l2tp_second_pass_flt_rule_hdl;
	}
	else
	{
		IPACMDBG_H("The client is not found in flt info list, insert a new one.\n");
		new_flt_info.p_client = client;
		new_flt_info.flt_rule_hdl[iptype] = flt_rule_hdl;
		/* Create empty list. */
		new_flt_info.l2tp_first_pass_flt_rule_hdl[IPA_IP_v4].flt_rule_hdls = std::list<uint32_t>();
		new_flt_info.l2tp_first_pass_flt_rule_hdl[IPA_IP_v6].flt_rule_hdls = std::list<uint32_t>();
		new_flt_info.l2tp_first_pass_flt_rule_hdl[iptype].flt_rule_hdls = flt_rule_hdls;
		new_flt_info.l2tp_second_pass_flt_rule_hdl = l2tp_second_pass_flt_rule_hdl;
		peer->flt_rule.push_front(new_flt_info);
		IPACMDBG_H("Inserted the new client %d.\n", sizeof(new_flt_info));
	}

	return;
}

void IPACM_LanToLan_Iface::del_one_client_flt_rule(IPACM_LanToLan_Iface *peer_iface, client_info *client)
{
	list<peer_iface_info>::iterator it;

	for(it = m_peer_iface_info.begin(); it != m_peer_iface_info.end(); it++)
	{
		if(it->peer == peer_iface)
		{
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
						m_p_iface->eth_bridge_del_flt_rule(it_flt->flt_rule_hdl[IPA_IP_v4], IPA_IP_v4);
						IPACMDBG_H("Deleted IPv4 flt rule %d.\n", it_flt->flt_rule_hdl[IPA_IP_v4]);
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
						m_p_iface->eth_bridge_del_flt_rule(it_flt->flt_rule_hdl[IPA_IP_v6], IPA_IP_v6);
						IPACMDBG_H("Deleted IPv6 flt rule %d.\n", it_flt->flt_rule_hdl[IPA_IP_v6]);
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

	peer_l2_hdr_type = peer->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
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

			IPACMDBG_H("ref count is now %d, peer %p, mac 0x[%X][%X][%X][%X][%X][%X]\n", it->second, peer,
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

	return;
}

void IPACM_LanToLan_Iface::handle_down_event()
{
	list<peer_iface_info>::iterator it_own_peer_info, it_other_iface_peer_info;
	IPACM_LanToLan_Iface *other_iface;

	/* clear inter-interface rules */
	if(m_support_inter_iface_offload)
	{
		for(it_own_peer_info = m_peer_iface_info.begin(); it_own_peer_info != m_peer_iface_info.end();
			it_own_peer_info++)
		{
			/* decrement reference count of peer l2 header type on both interfaces*/
			decrement_ref_cnt_peer_l2_hdr_type(it_own_peer_info->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type);
			it_own_peer_info->peer->decrement_ref_cnt_peer_l2_hdr_type(m_p_iface->tx_prop->tx[0].hdr_l2_type);

			/* first clear all flt rule on target interface */
			IPACMDBG_H("Clear all flt rule on target interface.\n");
			clear_all_flt_rule_for_one_peer_iface(&(*it_own_peer_info));

			other_iface = it_own_peer_info->peer;
			/* then clear all flt/rt rule and hdr proc ctx for target interface on peer interfaces */
			IPACMDBG_H("Clear all flt/rt rules and hdr proc ctx for target interface on peer interfaces %s.\n",
				it_own_peer_info->peer->get_iface_pointer()->dev_name);
			for(it_other_iface_peer_info = other_iface->m_peer_iface_info.begin();
				it_other_iface_peer_info != other_iface->m_peer_iface_info.end();
				it_other_iface_peer_info++)
			{
				if(it_other_iface_peer_info->peer == this)	//found myself in other iface's peer info list
				{
					IPACMDBG_H("Found the right peer info on other iface.\n");
					other_iface->clear_all_flt_rule_for_one_peer_iface(&(*it_other_iface_peer_info));
					other_iface->clear_all_rt_rule_for_one_peer_iface(&(*it_other_iface_peer_info));
					/* remove the peer info from the list */
					other_iface->m_peer_iface_info.erase(it_other_iface_peer_info);
					other_iface->del_hdr_proc_ctx(m_p_iface->tx_prop->tx[0].hdr_l2_type);
					break;
				}
			}

			/* then clear rt rule and hdr proc ctx and release rt table on target interface */
			IPACMDBG_H("Clear rt rules and hdr proc ctx and release rt table on target interface.\n");
			clear_all_rt_rule_for_one_peer_iface(&(*it_own_peer_info));
			del_hdr_proc_ctx(it_own_peer_info->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type);
		}
		m_peer_iface_info.clear();
	}

	/* clear intra interface rules */
	if(m_support_intra_iface_offload)
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
		add_all_inter_interface_client_flt_rule_one_vlan_id(IPA_IP_v4, vlan_id);

	if(get_m_is_ip_addr_assigned(IPA_IP_v6))
		add_all_inter_interface_client_flt_rule_one_vlan_id(IPA_IP_v6, vlan_id);
}

void IPACM_LanToLan_Iface::handle_vlan_id_del(uint16_t vlan_id)
{
	list<client_info>::iterator it_client;

	IPACMDBG_H("iface %s got vlan id %d del, looking for clients to remove\n",
		get_iface_pointer()->dev_name, vlan_id);

	/* go over all clients and remove those with the removed vlan id */
	IPACMDBG_H("There are %d m_client_info in total.\n", m_client_info.size());
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
	ipa_hdr_l2_type peer_l2_type;

	peer_l2_type = peer->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type;
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
	if(m_support_intra_iface_offload)
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
	uint32_t hdr_proc_ctx_hdl;

	if(m_p_iface->tx_prop == NULL)
	{
		IPACMERR("No tx prop.\n");
		return;
	}

	m_intra_interface_info.peer = this;

	snprintf(m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX,
		"eth_v4_intra_interface");
	IPACMDBG_H("IPv4 routing table for flt name: %s\n", m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v4]);
	snprintf(m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX,
		"eth_v6_intra_interface");
	IPACMDBG_H("IPv6 routing table for flt name: %s\n", m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v6]);

	memcpy(m_intra_interface_info.rt_tbl_name_for_rt[IPA_IP_v4], m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v4],
		IPA_RESOURCE_NAME_MAX);
	IPACMDBG_H("IPv4 routing table for rt name: %s\n", m_intra_interface_info.rt_tbl_name_for_rt[IPA_IP_v4]);
	memcpy(m_intra_interface_info.rt_tbl_name_for_rt[IPA_IP_v6], m_intra_interface_info.rt_tbl_name_for_flt[IPA_IP_v6],
		IPA_RESOURCE_NAME_MAX);
	IPACMDBG_H("IPv6 routing table for rt name: %s\n", m_intra_interface_info.rt_tbl_name_for_rt[IPA_IP_v6]);

	m_p_iface->eth_bridge_add_hdr_proc_ctx(m_p_iface->tx_prop->tx[0].hdr_l2_type,
		&hdr_proc_ctx_hdl);
	hdr_proc_ctx_for_intra_interface = hdr_proc_ctx_hdl;
	IPACMDBG_H("Hdr proc ctx for intra-interface communication: hdl %d\n", hdr_proc_ctx_hdl);

	return;
}

void IPACM_LanToLan_Iface::handle_new_iface_up(char rt_tbl_name_for_flt[][IPA_RESOURCE_NAME_MAX], char rt_tbl_name_for_rt[][IPA_RESOURCE_NAME_MAX],
		IPACM_LanToLan_Iface *peer_iface)
{
	peer_iface_info new_peer;
	ipa_hdr_l2_type peer_l2_hdr_type;

	new_peer.peer = peer_iface;
	memcpy(new_peer.rt_tbl_name_for_rt[IPA_IP_v4], rt_tbl_name_for_rt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX);
	memcpy(new_peer.rt_tbl_name_for_rt[IPA_IP_v6], rt_tbl_name_for_rt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX);
	memcpy(new_peer.rt_tbl_name_for_flt[IPA_IP_v4], rt_tbl_name_for_flt[IPA_IP_v4], IPA_RESOURCE_NAME_MAX);
	memcpy(new_peer.rt_tbl_name_for_flt[IPA_IP_v6], rt_tbl_name_for_flt[IPA_IP_v6], IPA_RESOURCE_NAME_MAX);

	peer_l2_hdr_type = peer_iface->m_p_iface->tx_prop->tx[0].hdr_l2_type;
	increment_ref_cnt_peer_l2_hdr_type(peer_l2_hdr_type);
	add_hdr_proc_ctx(peer_l2_hdr_type);

	/* push the new peer_iface_info into the list */
	m_peer_iface_info.push_front(new_peer);

	return;
}

void IPACM_LanToLan_Iface::handle_client_add(uint8_t *mac, bool is_l2tp_client, l2tp_vlan_mapping_info *mapping_info, uint16_t vlan_id)
{
	list<client_info>::iterator it_client;
	list<peer_iface_info>::iterator it_peer_info;
	client_info new_client;
	bool flag[IPA_HDR_L2_MAX];

	for(it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
	{
		if((memcmp(it_client->mac_addr, mac, sizeof(it_client->mac_addr)) == 0)
#ifdef FEATURE_VLAN_MPDN
			&& (((IPACM_Iface::ipacmcfg->ipacm_mpdn_enable && m_is_vlan && (it_client->vlan_id == vlan_id))) ||
			!IPACM_Iface::ipacmcfg->ipacm_mpdn_enable || !m_is_vlan)
#endif
			)
		{
			IPACMDBG_H("This client has been added before.\n");
			return;
		}
	}

	if(m_client_info.size() == MAX_NUM_CLIENT)
	{
		IPACMDBG_H("The number of clients has reached maximum %d.\n", MAX_NUM_CLIENT);
		return;
	}

	IPACMDBG_H("is_l2tp_client: %d, mapping_info: %p, vlan id %d, is l2tp enable: %d\n", is_l2tp_client, mapping_info, vlan_id, IPACM_Iface::ipacmcfg->ipacm_l2tp_enable);
	memset(&new_client, 0, sizeof(new_client));
	memcpy(new_client.mac_addr, mac, sizeof(new_client.mac_addr));
	new_client.is_l2tp_client = is_l2tp_client;
	new_client.mapping_info = mapping_info;
	new_client.vlan_id = vlan_id;
	m_client_info.push_front(new_client);

	client_info &front_client = m_client_info.front();

	/* install inter-interface rules */
	if(m_support_inter_iface_offload)
	{
		memset(flag, 0, sizeof(flag));
		for(it_peer_info = m_peer_iface_info.begin(); it_peer_info != m_peer_iface_info.end(); it_peer_info++)
		{
			/* make sure add routing rule only once for each peer l2 header type */
			if(flag[it_peer_info->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type] == false)
			{
				/* add client routing rule for each peer interface */
				if(front_client.is_l2tp_client == false)
				{
					add_client_rt_rule(&(*it_peer_info), &front_client);
				}
#ifdef FEATURE_L2TP
				if(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP)
				{
					/* add l2tp rt rules */
					add_l2tp_client_rt_rule(&(*it_peer_info), &front_client);
				}
#endif
				flag[it_peer_info->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type] = true;
			}

			/* add client filtering rule on peer interfaces */
			it_peer_info->peer->add_one_client_flt_rule(this, &front_client);

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
	if(m_support_intra_iface_offload)
	{
		/* add routing rule first */
		add_client_rt_rule(&m_intra_interface_info, &front_client);

		/* add filtering rule */
		if(m_is_ip_addr_assigned[IPA_IP_v4])
		{
			add_client_flt_rule(&m_intra_interface_info, &front_client, IPA_IP_v4);
		}
		if(m_is_ip_addr_assigned[IPA_IP_v6])
		{
			add_client_flt_rule(&m_intra_interface_info, &front_client, IPA_IP_v6);
		}
	}

	return;
}

list<client_info>::iterator IPACM_LanToLan_Iface::handle_client_del(uint8_t *mac, uint16_t vlan_id)
{
	list<client_info>::iterator it_client;
	list<peer_iface_info>::iterator it_peer_info;
	bool flag[IPA_HDR_L2_MAX];

#ifdef FEATURE_VLAN_MPDN
	if((vlan_id && !m_is_vlan) || (!vlan_id && m_is_vlan))
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
				IPACMDBG_H("Delete client filtering rule on peer interface.\n");
				it_peer_info->peer->del_one_client_flt_rule(this, &(*it_client));

				/* make sure to delete routing rule only once for each peer l2 header type */
				if(flag[it_peer_info->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type] == false)
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
					flag[it_peer_info->peer->get_iface_pointer()->tx_prop->tx[0].hdr_l2_type] = true;
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

void IPACM_LanToLan_Iface::add_hdr_proc_ctx(ipa_hdr_l2_type peer_l2_type)
{
	uint32_t hdr_proc_ctx_hdl;

	if(ref_cnt_peer_l2_hdr_type[peer_l2_type] == 1)
	{
		m_p_iface->eth_bridge_add_hdr_proc_ctx(peer_l2_type, &hdr_proc_ctx_hdl);
		hdr_proc_ctx_for_inter_interface[peer_l2_type] = hdr_proc_ctx_hdl;
		IPACMDBG_H("Installed inter-interface hdr proc ctx on iface %s: handle %d\n", m_p_iface->dev_name, hdr_proc_ctx_hdl);
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

void IPACM_LanToLan_Iface::print_data_structure_info()
{
	list<peer_iface_info>::iterator it_peer;
	list<client_info>::iterator it_client;
	int i, j, k;

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
			IPACMDBG_H("Ref_cnt of peer l2 type %s is %d.\n", ipa_l2_hdr_type[i], ref_cnt_peer_l2_hdr_type[i]);
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
	IPACMDBG_H("There are %d clients in total.\n", m_client_info.size());
	for(it_client = m_client_info.begin(); it_client != m_client_info.end(); it_client++)
	{
		IPACMDBG_H("Client %d MAC: 0x%02x%02x%02x%02x%02x%02x Pointer: 0x%08x\n", i, it_client->mac_addr[0], it_client->mac_addr[1],
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

	IPACMDBG_H("There are %d peer interfaces in total.\n", m_peer_iface_info.size());
	for(it_peer = m_peer_iface_info.begin(); it_peer != m_peer_iface_info.end(); it_peer++)
	{
		print_peer_info(&(*it_peer));
	}

	if(m_support_intra_iface_offload)
	{
		IPACMDBG_H("This interface supports intra-interface communication, printing info:\n");
		print_peer_info(&m_intra_interface_info);
	}

	return;
}

void IPACM_LanToLan_Iface::print_peer_info(peer_iface_info *peer_info)
{
	list<flt_rule_info>::iterator it_flt;
	list<rt_rule_info>::iterator it_rt;
	list<uint32_t>::iterator it_flt_hdl;

	IPACMDBG_H("Printing peer info for iface %s:\n", peer_info->peer->m_p_iface->dev_name);

	IPACMDBG_H("There are %d flt info in total.\n", peer_info->flt_rule.size());
	for(it_flt = peer_info->flt_rule.begin(); it_flt != peer_info->flt_rule.end(); it_flt++)
	{
		IPACMDBG_H("Flt rule handle for client 0x%08x:\n", it_flt->p_client);
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
