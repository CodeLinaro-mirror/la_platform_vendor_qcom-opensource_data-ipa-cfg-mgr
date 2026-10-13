/*!
@file    IPACM_Bridge.h
@brief   This file implements bridge interface related handlers

DESCRIPTION
Header file for bridge interface handling for IPA.

Changes from Qualcomm Technologies, Inc. are provided under the following license:
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause-Clear
*/


#ifndef IPACM_BRIDGE_H
#define IPACM_BRIDGE_H

#include <stdio.h>
#include <string>
#include <unordered_map>
#include <IPACM_Config.h>
#include <IPACM_Iface.h>

struct bridge_info_t
{
	std::string name;
	uint32_t    ipv4_addr;
};

struct pending_addr_t
{
	uint32_t ipv4_addr;
	uint32_t ipv4_addr_mask;
};

class IPACM_Bridge
{
	static std::unordered_map<int, bridge_info_t> bridges;
	static std::unordered_map<int, pending_addr_t> pending_addrs;

public:
	/* Registry management driven from Netlink IFLA_INFO_KIND == "bridge". */
	static void register_bridge(const char *iface_name, int if_index);
	static void deregister_bridge(int if_index);

	static bool is_bridge_iface(const char *iface_name, int if_index);
	static void handle_addr_add(const char *iface_name, int if_index,
	                            uint32_t ipv4_addr, uint32_t ipv4_addr_mask);
	static void handle_addr_del(const char *iface_name, int if_index,
	                            uint32_t ipv4_addr);
	static void handle_link_down(const char *iface_name, int if_index);
};

#endif /* IPACM_BRIDGE_H */
