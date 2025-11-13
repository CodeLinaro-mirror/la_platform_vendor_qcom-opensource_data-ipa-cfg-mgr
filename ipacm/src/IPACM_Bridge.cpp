/*
@file    IPACM_Bridge.cpp
@brief   This file implements bridge related functionalities

DESCRIPTION
Implementation of handling various events on bridge interfaces

Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause-Clear
*/


#include <IPACM_Bridge.h>
#include "IPACM_IfaceManager.h"
#include "IPACM_Wan.h"
#include "IPACM_Config.h"
#include "IPACM_ConntrackClient.h"

IPACM_Bridge::IPACM_Bridge()
{
		IPACMDBG("Initailizing IPACM_Bridge class object\n");
		bridge_ipv4_addr = 0;
		memset(bridge_ipv6_addr, 0, IPV6_SIZE);
}


void IPACM_Bridge::event_callback(ipa_cm_event_id event, void *param)
{

		/*maintaining initial two members of ipacm_event_data_addr and ipacm_event_data_fid structure as same.
		to get the interface name details. */
		ipacm_event_data_addr *data = (ipacm_event_data_addr *)param;
		ipacm_event_iface_up* bridge_iface_up = NULL;
		int ipa_if_num = data->if_index;
		int skip_nat_set = 0;
		bool reserve_slot = false;
		bool is_bridge = true;
		if(strncmp(data->iface_name, IPACM_Iface::ipacmcfg->ipa_virtual_iface_name, strlen(IPACM_Iface::ipacmcfg->ipa_virtual_iface_name)) != 0)
		{
			IPACMDBG("Non-bridge interface %s event,ignoring\n", data->iface_name);
			return;
		}
		if( (data->iptype==IPA_IP_v4) && (data->ipv4_addr == 0) && (event != IPA_LINK_DOWN_EVENT))
		{
			IPACMDBG("Got NULL IPv4 address\n");
			return;
		}
		switch(event) {
				case IPA_ADDR_ADD_EVENT:
						if(data->iptype == IPA_IP_v4)
						{
							if(bridge_ipv4_addr == 0)
							{
								/*	This is to avoid installing IPA private subnet Filter rules in case of
									IPPT without NAT scenario to avoid packets taking SW path because we
									are installing private subnet rules with public IP assigned to bridge
									since bridge has no longer the private IP assigned. */

								for (int i = 0; i < MAX_NUM_IP_PASS_MPDN; i++)
								{
									if(IPACM_Iface::ipacmcfg->ip_pass_mpdn_table[i].valid_entry == true &&
										IPACM_Iface::ipacmcfg->ip_pass_mpdn_table[i].ip_pass_skip_nat == 1)
									{
										skip_nat_set = 1;
										break;
									}
								}
								if(!skip_nat_set)
								{
									if(IPACM_Iface::ipacmcfg->AddPrivateSubnet(data->ipv4_addr, data->ipv4_addr_mask, ipa_if_num) == true)
									{
										bridge_ipv4_addr = data->ipv4_addr;
										IPACMDBG_H("Resetting IPACM bridge private subnet_addr as: 0x%x \n", bridge_ipv4_addr);
									}
									else
									{
										IPACMERR("Can't Add IPACM private subnet_addr as: 0x%x \n", data->ipv4_addr);
									}
								}
							}
							IPACMDBG_H("Handling IPA_ADDR_ADD_EVENT for %s and bridge_ipv4_addr 0x%x\n",data->iface_name, bridge_ipv4_addr);

							skip_nat_set = 0;
						}

						if(data->iptype==IPA_IP_v6)
						{
							if(IPACM_Wan::is_global_ipv6_addr(data->ipv6_addr))
							{
								IPACMDBG_H("Handling v6 IPA_ADDR_ADD_EVENT  addr recvd: 0x%08x%08x%08x%08x.\n", data->ipv6_addr[0], data->ipv6_addr[1],
									data->ipv6_addr[2], data->ipv6_addr[3]);
								if( bridge_ipv6_addr[0] != 0)
								{
									IPACMDBG_H("Only one global addr is handled.\n");
									break;
								}

								memcpy(bridge_ipv6_addr, data->ipv6_addr, IPV6_SIZE);
								IPACMDBG_H("add brlan global ipv6 prefix: 0x%08x%08x.\n", bridge_ipv6_addr[0], bridge_ipv6_addr[1]);
								is_bridge = true;
								IPACM_Iface::ipacmcfg->add_vlan_ipv6_prefix(bridge_ipv6_addr, ipa_if_num, 0, is_bridge);

								IPACMDBG_H("unsubscribe for ct evts with bridge address: 0x%08x%08x\n", bridge_ipv6_addr[0], bridge_ipv6_addr[1]);
								bridge_iface_up = (ipacm_event_iface_up*)calloc(1, sizeof(*bridge_iface_up));
								memcpy(bridge_iface_up->ipv6_addr, bridge_ipv6_addr, IPV6_SIZE);
								IPACM_ConntrackClient::UpdateFilters_v6(bridge_iface_up);
								free(bridge_iface_up);
								bridge_iface_up = NULL;
							}
						}
						break;
				case IPA_ADDR_DEL_EVENT:
						if((data->iptype==IPA_IP_v4))
						{
							IPACMDBG_H("Handling IPA_ADDR_DEL_EVENT %s\n", data->iface_name);
							if(IPACM_Iface::ipacmcfg->DelPrivateSubnet(data->ipv4_addr, ipa_if_num) == true)
							{
								bridge_ipv4_addr = 0;
								IPACMDBG_H("Resetting IPACM bridge private subnet_addr as: 0x%x \n", bridge_ipv4_addr);
							}
							else
							{
								IPACMERR("Can't Delete IPACM private subnet_addr as: 0x%x \n", data->ipv4_addr);
							}
						}
						if((data->iptype==IPA_IP_v6))
						{
							if(IPACM_Wan::is_global_ipv6_addr(data->ipv6_addr))
							{
								IPACMDBG_H("Handling v6 IPA_ADDR_DEL_EVENT  prefix deleted: 0x%08x%08x.\n", data->ipv6_addr[0], data->ipv6_addr[1]);

								if(memcmp(bridge_ipv6_addr, data->ipv6_addr, IPV6_SIZE))
								{
									IPACMDBG_H("Del Addr evnt for non-cached global Addr. Ignore");
									break;
								}

								IPACMDBG_H("subscribe for ct evts with bridge address: 0x%08x%08x", bridge_ipv6_addr[0], bridge_ipv6_addr[1]);
								bridge_iface_up = (ipacm_event_iface_up*)calloc(1, sizeof(*bridge_iface_up));
								memcpy(bridge_iface_up->ipv6_addr, bridge_ipv6_addr, IPV6_SIZE);
								IPACM_ConntrackClient::UpdateFilters_v6(bridge_iface_up, ACCEPT_CT);
								free(bridge_iface_up);
								bridge_iface_up = NULL;

								IPACMDBG_H("remove brlan global ipv6 prefix: 0x%08x%08x.\n", data->ipv6_addr[0], data->ipv6_addr[1]);
								IPACM_Iface::ipacmcfg->del_vlan_ipv6_prefix(data->ipv6_addr, ipa_if_num, reserve_slot, is_bridge);
								memset(bridge_ipv6_addr, 0, IPV6_SIZE);
							}
						}
						break;
				case IPA_LINK_DOWN_EVENT:
						IPACMDBG_H("Handling IPA_LINK_DOWN_EVENT %s\n", data->iface_name);
						bridge_ipv4_addr = 0;
						IPACMDBG_H("Deleting the bridge instance and resetting IPACM bridge private subnet_addr as: 0x%x \n",
									bridge_ipv4_addr);
						if(IPACM_Iface::ipacmcfg->DelPrivateSubnetByIfIndex(ipa_if_num) == false)
						{
								IPACMERR("Failed to delete IPACM private subnet with interface index as: 0x%x \n", ipa_if_num);
								IPACMERR("Still proceeding to delete the object\n");
						}

						IPACMDBG_H("subscribe for ct evts with bridge address: 0x%08x%08x\n", bridge_ipv6_addr[0], bridge_ipv6_addr[1]);
						bridge_iface_up = (ipacm_event_iface_up*)calloc(1, sizeof(*bridge_iface_up));
						memcpy(bridge_iface_up->ipv6_addr, bridge_ipv6_addr, IPV6_SIZE);
						IPACM_ConntrackClient::UpdateFilters_v6(bridge_iface_up, ACCEPT_CT);
						free(bridge_iface_up);
						bridge_iface_up = NULL;

						IPACMDBG_H("remove brlan global ipv6 prefix: 0x%08x%08x.\n", bridge_ipv6_addr[0], bridge_ipv6_addr[1]);
						IPACM_Iface::ipacmcfg->del_vlan_ipv6_prefix(bridge_ipv6_addr, ipa_if_num, reserve_slot, is_bridge);
						memset(bridge_ipv6_addr, 0, IPV6_SIZE);

						IPACM_EvtDispatcher::deregistr(this);
						IPACM_IfaceManager::deregistr(this);
						delete this;
						break;
				default:
						IPACMDBG("Ignore cmd %d\n", event);
						break;
		}
		return;

}
