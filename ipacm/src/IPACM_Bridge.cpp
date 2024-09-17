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

IPACM_Bridge::IPACM_Bridge()
{
		IPACMDBG("Initailizing IPACM_Bridge class object\n");
		IPACM_EvtDispatcher::registr(IPA_ADDR_ADD_EVENT, this);
		IPACM_EvtDispatcher::registr(IPA_ADDR_DEL_EVENT, this);
		IPACM_EvtDispatcher::registr(IPA_LINK_DOWN_EVENT, this);
}


void IPACM_Bridge::event_callback(ipa_cm_event_id event, void *param)
{

		/*maintaining initial two members of ipacm_event_data_addr and ipacm_event_data_fid structure as same.
		to get the interface name details. */
		ipacm_event_data_addr *data = (ipacm_event_data_addr *)param;
		int ipa_if_num = data->if_index;
		int skip_nat_set = 0;
		if(strncmp(data->iface_name, IPACM_Iface::ipacmcfg->ipa_virtual_iface_name, strlen(data->iface_name)) != 0 &&
			!strstr(data->iface_name, "bridge"))
		{
			IPACMDBG("Non-bridge interface %s event,ignoring\n", data->iface_name);
			return;
		}
		if((data->ipv4_addr == 0) && (event != IPA_LINK_DOWN_EVENT))
		{
			IPACMDBG("Got NULL IPv4 address\n");
			return;
		}
		switch(event) {
				case IPA_ADDR_ADD_EVENT:
						IPACMDBG_H("Handling IPA_ADDR_ADD_EVENT for %s and bridge_ipv4_addr 0x%x\n",data->iface_name, data->ipv4_addr);
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
								if(IPACM_Iface::ipacmcfg->AddPrivateSubnet(data->ipv4_addr, data->ipv4_addr_mask, data->if_index) == true)
								{
									IPACMDBG_H("IPACM bridge private subnet_addr as: 0x%x \n", (data->ipv4_addr & data->ipv4_addr_mask));
								}
								else
								{
									IPACMERR("Can't Add IPACM private subnet_addr as: 0x%x \n", data->ipv4_addr);
								}
							}
						skip_nat_set = 0;
						break;
				case IPA_ADDR_DEL_EVENT:
						IPACMDBG_H("Handling IPA_ADDR_DEL_EVENT %s\n", data->iface_name);
							if(IPACM_Iface::ipacmcfg->DelPrivateSubnet(data->ipv4_addr, data->if_index) == true)
							{
								IPACMDBG_H("Resetting IPACM bridge private subnet_addr as: 0x%x \n", data->ipv4_addr);
							}
							else
							{
								IPACMERR("Can't Delete IPACM private subnet_addr as: 0x%x \n", data->ipv4_addr);
							}
						break;
				case IPA_LINK_DOWN_EVENT:
						IPACMDBG_H("Handling IPA_LINK_DOWN_EVENT %s\n", data->iface_name);
						IPACMDBG_H("Deleting the bridge instance and resetting IPACM bridge private subnet_addr for if index: %d\n",
									data->if_index);
						if(IPACM_Iface::ipacmcfg->DelPrivateSubnetByIfIndex(data->if_index) == false)
						{
								IPACMERR("Failed to delete IPACM private subnet with interface index as: 0x%x \n", ipa_if_num);
								IPACMERR("Still proceeding to delete the object\n");
						}
						break;
				default:
						IPACMDBG("Ignore cmd %d\n", event);
						break;
		}
		return;

}
