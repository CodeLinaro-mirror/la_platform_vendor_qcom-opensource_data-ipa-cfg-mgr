/*
@file    IPACM_Bridge.cpp
@brief   This file implements bridge related functionalities

DESCRIPTION
Implementation of handling various events on bridge interfaces

Changes from Qualcomm Technologies, Inc. are provided under the following license:
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include <string.h>
#include <IPACM_Bridge.h>
#include "IPACM_Wan.h"

std::unordered_map<int, bridge_info_t> IPACM_Bridge::bridges;
std::unordered_map<int, pending_addr_t> IPACM_Bridge::pending_addrs;

void IPACM_Bridge::register_bridge(const char *iface_name, int if_index)
{
	auto it = bridges.find(if_index);
	if (it != bridges.end())
	{
		it->second.name = iface_name;
	}
	else
	{
		bridges[if_index] = { iface_name, 0 };
		IPACM_LOG(IPACM_LOG_DEBUG, "Registered bridge %s if_index: %d\n", iface_name, if_index);
	}

	auto pit = pending_addrs.find(if_index);
	if (pit != pending_addrs.end())
	{
		pending_addr_t saved = pit->second;
		pending_addrs.erase(pit);
		IPACM_LOG(IPACM_LOG_DEBUG, "Replaying pending addr 0x%x for bridge %s\n",
		          saved.ipv4_addr, iface_name);
		handle_addr_add(iface_name, if_index, saved.ipv4_addr, saved.ipv4_addr_mask);
	}
}

void IPACM_Bridge::deregister_bridge(int if_index)
{
	pending_addrs.erase(if_index);
	if (bridges.erase(if_index) > 0)
		IPACM_LOG(IPACM_LOG_DEBUG, "Deregistered bridge if_index: %d\n", if_index);
}

bool IPACM_Bridge::is_bridge_iface(const char *iface_name, int if_index)
{
	(void)iface_name;
	return bridges.find(if_index) != bridges.end();
}

void IPACM_Bridge::handle_addr_add(const char *iface_name, int if_index,
                                   uint32_t ipv4_addr, uint32_t ipv4_addr_mask)
{
	int skip_nat_set = 0;

	auto it = bridges.find(if_index);
	if (it == bridges.end())
	{
		/* This is to handle netlink events for bridge in order:
		 RTM_NEWLINK (ifi_change -1), RTM_NEWLINK (if_change: 256/0)
		 RTM_NEWADDR*/
		if (strstr(iface_name, "bridge") != NULL)
		{
			pending_addrs[if_index] = { ipv4_addr, ipv4_addr_mask };
			IPACM_LOG(IPACM_LOG_DEBUG, "Stashing addr 0x%x for pending bridge %s if_index: %d\n",
			          ipv4_addr, iface_name, if_index);
		}
		return;
	}

	IPACM_LOG(IPACM_LOG_DEBUG, "Handling addr_add for %s ipv4: 0x%x\n", iface_name, ipv4_addr);

	uint32_t new_subnet = (ipv4_addr & ipv4_addr_mask);

	if (it->second.ipv4_addr != 0)
	{
		if (it->second.ipv4_addr == new_subnet)
		{
			IPACM_LOG(IPACM_LOG_DEBUG, "bridge %s already has addr 0x%x\n", iface_name, it->second.ipv4_addr);
			return;
		}

		IPACM_LOG(IPACM_LOG_DEBUG, "bridge %s addr renew: 0x%x -> 0x%x\n",
		          iface_name, it->second.ipv4_addr, new_subnet);

		if (IPACM_Iface::ipacmcfg->DelPrivateSubnet(it->second.ipv4_addr, if_index) != true)
		{
			IPACM_LOG(IPACM_LOG_ERR, "Can't Delete old private subnet for %s addr: 0x%x\n",
			          iface_name, it->second.ipv4_addr);
			return;
		}
		it->second.ipv4_addr = 0;
	}

	/*This is to avoid installing IPA private subnet Filter rules in case of
	IPPT without NAT scenario to avoid packets taking SW path because we
	are installing private subnet rules with public IP assigned to bridge
	since bridge has no longer the private IP assigned. */

	for (int i = 0; i < MAX_NUM_IP_PASS_MPDN; i++)
	{
		if (IPACM_Iface::ipacmcfg->ip_pass_mpdn_table[i].valid_entry == true &&
		    IPACM_Iface::ipacmcfg->ip_pass_mpdn_table[i].ip_pass_skip_nat == 1)
		{
			skip_nat_set = 1;
			break;
		}
	}

	if (!skip_nat_set)
	{
		if (IPACM_Iface::ipacmcfg->AddPrivateSubnet(new_subnet, ipv4_addr_mask,
		    if_index, IPACM_Wan::wan_v4_collision_exists(ipv4_addr, ipv4_addr_mask)) == true)
		{
			it->second.ipv4_addr = new_subnet;
			IPACM_LOG(IPACM_LOG_DEBUG, "bridge %s subnet: 0x%x\n", iface_name, it->second.ipv4_addr);
		}
		else
		{
			IPACM_LOG(IPACM_LOG_ERR, "Can't Add private subnet for %s addr: 0x%x\n", iface_name, ipv4_addr);
		}
	}
}

void IPACM_Bridge::handle_addr_del(const char *iface_name, int if_index,
                                   uint32_t ipv4_addr)
{
	pending_addrs.erase(if_index);

	if (!is_bridge_iface(iface_name, if_index))
		return;

	IPACM_LOG(IPACM_LOG_DEBUG, "Handling addr_del for %s\n", iface_name);

	auto it = bridges.find(if_index);
	if (it == bridges.end() || it->second.ipv4_addr == 0)
	{
		IPACM_LOG(IPACM_LOG_DEBUG,
		          "No private subnet was added for %s, skipping DelPrivateSubnet\n",
		          iface_name);
		return;
	}

	if (IPACM_Iface::ipacmcfg->DelPrivateSubnet(it->second.ipv4_addr, if_index) == true)
	{
		it->second.ipv4_addr = 0;
		IPACM_LOG(IPACM_LOG_DEBUG, "Cleared subnet for bridge %s\n", iface_name);
	}
	else
	{
		IPACM_LOG(IPACM_LOG_ERR, "Can't Delete private subnet for %s addr: 0x%x\n", iface_name, it->second.ipv4_addr);
	}
}

void IPACM_Bridge::handle_link_down(const char *iface_name, int if_index)
{
	if (!is_bridge_iface(iface_name, if_index))
		return;

	IPACM_LOG(IPACM_LOG_DEBUG, "Handling link_down for %s if_index: %d\n", iface_name, if_index);

	auto it = bridges.find(if_index);
	bool subnet_was_added = (it != bridges.end() && it->second.ipv4_addr != 0);

	deregister_bridge(if_index);

	if (!subnet_was_added)
	{
		IPACM_LOG(IPACM_LOG_DEBUG,
		          "No private subnet was added for %s, skipping DelPrivateSubnetByIfIndex\n",
		          iface_name);
		return;
	}

	if (IPACM_Iface::ipacmcfg->DelPrivateSubnetByIfIndex(if_index) == false)
	{
		IPACM_LOG(IPACM_LOG_ERR, "Failed to delete private subnet for %s\n", iface_name);
	}
}
