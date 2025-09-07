/*
@file    IPACM_Bridge.cpp
@brief   This file implements bridge related functionalities

DESCRIPTION
Implementation of handling various events on bridge interfaces

Changes from Qualcomm Technologies, Inc. are provided under the following license:

Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause-Clear
*/


#include <IPACM_Bridge.h>
#include "IPACM_IfaceManager.h"
#include "IPACM_ConntrackClient.h"



IPACM_Bridge::IPACM_Bridge()
{
		IPACMDBG("Initailizing IPACM_Bridge class object\n");
		bridge_ipv4_addr = 0;
}


void IPACM_Bridge::event_callback(ipa_cm_event_id event, void *param)
{

		/*maintaining initial two members of ipacm_event_data_addr and ipacm_event_data_fid structure as same.
		to get the interface name details. */
		ipacm_event_data_addr *data = (ipacm_event_data_addr *)param;
		int ipa_if_num = data->if_index;
		int skip_nat_set = 0;
		if(strncmp(data->iface_name, IPACM_Iface::ipacmcfg->ipa_virtual_iface_name, strlen(data->iface_name)) != 0)
		{
			IPACMDBG_H("Default Bridge name : %s \n", IPACM_Iface::ipacmcfg->ipa_virtual_iface_name);
			IPACMDBG_H("Current data->iface_name : %s \n", data->iface_name);
			if(strstr(data->iface_name, IPACM_Iface::ipacmcfg->ipa_virtual_iface_name))
			{
				IPACMDBG_H("Process For other Bridge Interface %s \n", data->iface_name);
				if(data->ipv4_addr == 0)
				{
					IPACM_Iface::iface_addr_query(data->if_index, false, &data->ipv4_addr ,&data->ipv4_addr_mask);
				}
				IPACMDBG("Got IPv4 address\n");
				iptodot("ip", data->ipv4_addr);
			}
			else
			{
				IPACMDBG("Non-bridge interface %s event,ignoring\n", data->iface_name);
				return;
			}
		}
		IPACMDBG_H("Handling Event for %s and data->ipv4_addr 0x%x, mask 0x%x\n",data->iface_name, data->ipv4_addr, data->ipv4_addr_mask);
		if((data->ipv4_addr == 0) && (event != IPA_LINK_DOWN_EVENT))
		{
			IPACMDBG("Got NULL IPv4 address\n");
			return;
		}
		switch(event) {
				case IPA_ADDR_ADD_EVENT:
						IPACMDBG_H("Handling IPA_ADDR_ADD_EVENT for %s and bridge_ipv4_addr 0x%x\n",data->iface_name, bridge_ipv4_addr);
						/*For Default bridge handleing*/
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
						else
						{
							/*For Ondemand bridge handleing*/
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
								if(IPACM_Iface::ipacmcfg->AddPrivateSubnet((data->ipv4_addr & data->ipv4_addr_mask), data->ipv4_addr_mask, ipa_if_num) == true)
								{
									IPACMDBG_H("IPACM bridge %s private subnet_addr as: 0x%x \n", data->iface_name, data->ipv4_addr);
								}
								else
								{
									IPACMERR("Can't Add IPACM bridge %s private subnet_addr as: 0x%x \n", data->iface_name, data->ipv4_addr);
								}
							}
						}
						skip_nat_set = 0;
						IPACMDBG_H("addr_add_evt(): Number of Private subnet %d\n", IPACM_Iface::ipacmcfg->ipa_num_private_subnet);
						break;
				case IPA_ADDR_DEL_EVENT:
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
							IPACMDBG_H("addr_del_evt(): Number of Private subnet %d\n", IPACM_Iface::ipacmcfg->ipa_num_private_subnet);
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
						IPACMDBG_H("link_down_evt(): Number of Private subnet %d\n", IPACM_Iface::ipacmcfg->ipa_num_private_subnet);
						if(IPACM_Iface::ipacmcfg->ipa_num_private_subnet == 0)
						{
							IPACM_EvtDispatcher::deregistr(this);
							IPACM_IfaceManager::deregistr(this);
							IPACMDBG_H("Delete this instance.\n");
							delete this;
						}
						break;
				default:
						IPACMDBG("Ignore cmd %d\n", event);
						break;
		}
		return;

}
