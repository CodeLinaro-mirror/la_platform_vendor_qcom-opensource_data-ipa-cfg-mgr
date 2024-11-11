/*
Copyright (c) 2013-2019, The Linux Foundation. All rights reserved.

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

Changes from Qualcomm Technologies, Inc. are provided under the following license:
Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause-Clear
*/
/*!
	@file
	IPACM_Neighbor.cpp

	@brief
	This file implements the functionality of handling IPACM Neighbor events.

	@Author
	Skylar Chang

*/

#include <sys/ioctl.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <IPACM_Neighbor.h>
#include <IPACM_EvtDispatcher.h>
#include "IPACM_Defs.h"
#include "IPACM_Log.h"
#include "IPACM_Netlink.h"

#define MAX_FDB_ROW_LEN 200
#define MAX_FDB_PARAM_CNT 5
#define MAX_FDB_PARAM_LEN 50
#define IPA_SYS_CMD_LEN 200
#define DEV_LEN 3
#define MASTER_LEN 5
#define WLAN_LEN_LEN 4
#define BRIDGE_LEN 6

#define IPA_TMP_DIR "/tmp/data"
#define IPA_FDB_TABLE IPA_TMP_DIR"/ipa_fdb_table.txt"
#define IPA_NO_IFACE_NAME "IFACE_NONE"

IPACM_Neighbor::IPACM_Neighbor()
{
	IPACM_EvtDispatcher::registr(IPA_WLAN_CLIENT_ADD_EVENT_EX, this);
	IPACM_EvtDispatcher::registr(IPA_NEW_NEIGH_EVENT, this);
	IPACM_EvtDispatcher::registr(IPA_DEL_NEIGH_EVENT, this);
	IPACM_EvtDispatcher::registr(IPA_ADD_BRIDGE_VLAN_PHY_INTF, this);
	IPACM_EvtDispatcher::registr(IPA_ADD_BRIDGE_VLAN_BR_INTF, this);
	IPACM_EvtDispatcher::registr(IPA_CLEAN_NEIGHBOR_CACHE, this);
	IPACM_EvtDispatcher::registr(IPA_USB_LINK_UP_EVENT, this);
	IPACM_EvtDispatcher::registr(IPA_LINK_DOWN_EVENT, this);
	IPACM_EvtDispatcher::registr(IPA_WLAN_LINK_DOWN_EVENT, this);
	return;
}

/**
 * Validate VLAN bridge matching for a client interface.
 * This function checks if a client's interface VLAN ID matches the expected
 * bridge's associated VLAN ID. It handles both regular VLAN IDs and dummy
 * VLAN IDs (used for virtual VLAN configurations).
 */
bool IPACM_Neighbor::validate_bridge_vid(char* iface_name, const ipacm_bridge* expected_bridge, uint16_t& out_vlan_id)
{
	IPACM_Config* config = IPACM_Config::GetInstance();

	if((iface_name == NULL) || (expected_bridge == NULL))
	{
		IPACMERR("Invalid parameters received\n");
		return false;
	}

	// Check if this is a VLAN interface requiring validation
	bool is_vlan_mode = config->iface_in_vlan_mode(iface_name);
	bool is_added_vlan = config->is_added_vlan_iface(iface_name);

#ifdef IPA_L2TP_TUNNEL_UDP
	// L2TP interfaces don't require VLAN validation
	if (config->check_l2tp_iface(iface_name)) {
		return true;
	}
#endif

	// If not a VLAN interface, validation passes
	if (!is_vlan_mode && !is_added_vlan) {
		return true;
	}

	// Get VLAN ID from interface
	if (config->get_vlan_id(iface_name, &out_vlan_id)) {
		IPACMERR("Failed to get VLAN ID for interface %s\n", iface_name);
		return false;
	}

	// Handle dummy VLAN IDs (special case for virtual VLANs)
	if ((out_vlan_id > 0) && config->is_dummy_VID(out_vlan_id)) {
		ipa_bridge_vlan_mapping_info mapping_info = {};
		mapping_info.vlan_id = out_vlan_id;
		config->get_bridge_vlan_mapping(&mapping_info, true);
		ipacm_bridge* dummy_bridge = config->get_vlan_bridge(mapping_info.bridge_name);
		if (!dummy_bridge) {
			IPACMERR("Failed to get dummy bridge for VID %d, interface=%s\n",
					out_vlan_id, iface_name);
			return false;
		}
		if (dummy_bridge->associate_VID != expected_bridge->associate_VID) {
			IPACMERR("Client bridge dummy VID mismatch: expected=%d, actual=%d, interface=%s\n",
				expected_bridge->associate_VID,
				dummy_bridge->associate_VID,
				iface_name);
			return false;
		}
	}
	// Standard VLAN ID validation
	else if (expected_bridge->associate_VID != out_vlan_id) {
		IPACMDBG("Client bridge VID mismatch: expected=%d, actual=%d, interface=%s\n",
			expected_bridge->associate_VID, out_vlan_id, iface_name);
		return false;
	}

	IPACMDBG_H("Client-bridge VID match validated: %d for interface %s\n", out_vlan_id, iface_name);
	return true;
}
/* Extract interface name, IP adress, subnet with interface index value */
int IPACM_Neighbor::parse_bridge_info(int index, struct ipa_bridge_vlan_mapping_info *data)
{
	int fd;
        struct ifreq ifrr;
        struct sockaddr_in *ipaddr;

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
        {
                IPACMERR("unable to open socket");
                return -1;
        }
	IPACMDBG("Interface index %d\n", index);
        memset(&ifrr, 0, sizeof(struct ifreq));
        ifrr.ifr_ifindex = index;

	if (ioctl(fd, SIOCGIFNAME, &ifrr) == -1)
	{
		IPACMERR("unable to open socket");
		close(fd);
		return -1;
        }

        strlcpy(data->bridge_name, ifrr.ifr_name, IPA_RESOURCE_NAME_MAX);
	IPACMDBG("Bridge parse interface name%s\n", data->bridge_name);
	ifrr.ifr_ifindex = 0;

	if (ioctl(fd, SIOCGIFADDR, &ifrr) == -1)
	{
		IPACMERR("unable to open socket");
		close(fd);
		return -1;

	}
	ipaddr = (struct sockaddr_in *)&ifrr.ifr_addr;
        data->bridge_ipv4 = ntohl(ipaddr->sin_addr.s_addr);

	IPACMDBG("Bridge parse ipaddr 0x%x\n", data->bridge_ipv4);

        memset(&ifrr, 0, sizeof(struct ifreq));
        strlcpy(ifrr.ifr_name, data->bridge_name, IFNAMSIZ);
	ifrr.ifr_addr.sa_family = AF_INET;

	if (ioctl(fd, SIOCGIFNETMASK, &ifrr) == -1)
	{
		IPACMERR("unable to open socket");
		close(fd);
		return -1;

	}
	ipaddr = (struct sockaddr_in *)&ifrr.ifr_netmask;
	data->subnet_mask = ntohl((unsigned int)ipaddr->sin_addr.s_addr);

	IPACMDBG("Bridge parse subnet 0x%x\n", data->subnet_mask);
	close(fd);
	return 0;

}

int IPACM_Neighbor::parse_bridge_name(int index, struct ipa_bridge_vlan_mapping_info *data)
{
	int fd;
	struct ifreq ifrr;
	struct sockaddr_in *ipaddr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		IPACMERR("unable to open socket");
		return -1;
	}
	IPACMDBG("Interface index %d\n", index);
	memset(&ifrr, 0, sizeof(struct ifreq));
	ifrr.ifr_ifindex = index;

	if (ioctl(fd, SIOCGIFNAME, &ifrr) == -1)
	{
		IPACMERR("unable to open socket");
		close(fd);
		return -1;
	}

	strlcpy(data->bridge_name, ifrr.ifr_name, IPA_RESOURCE_NAME_MAX);
	IPACMDBG("Bridge parse interface name%s\n", data->bridge_name);
	close(fd);
	return 0;
}

void IPACM_Neighbor::event_callback(ipa_cm_event_id event, void *param)
{
	int ret = 0, ipa_interface_index = 0;
	char iface_name[IPA_IFACE_NAME_LEN] = {0};
	ipa_bridge_vlan_mapping_info mapping_info = {};
	std::list<ipa_neighbor_client>::iterator it;
	ipacm_bridge *bridge = NULL;
	uint16_t vlan_id = 0;
	ipacm_event_data_all *data_all = NULL;
	IPACM_Config* config = IPACM_Config::GetInstance();

	IPACMDBG("Recieved event %d\n", event);

	switch (event)
	{
		case IPA_WLAN_CLIENT_ADD_EVENT_EX:
		{
			ipacm_event_data_wlan_ex *data = (ipacm_event_data_wlan_ex *)param;
			ipa_interface_index = IPACM_Iface::iface_ipa_index_query(data->if_index);
			/* check for failure return */
			if (IPACM_FAILURE == ipa_interface_index) {
				IPACMERR("IPA_WLAN_CLIENT_ADD_EVENT_EX: not supported iface id: %d\n", data->if_index);
				break;
			}
			uint8_t client_mac_addr[6];
			memset(client_mac_addr,0,sizeof(client_mac_addr));

			IPACMDBG_H("Received IPA_WLAN_CLIENT_ADD_EVENT\n");
			for(int i = 0; i < data->num_of_attribs; i++)
			{
				if(data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_MAC_ADDR)
				{
					memcpy(client_mac_addr,
							data->attribs[i].u.mac_addr,
							sizeof(client_mac_addr));
					IPACMDBG_H("AP Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n",
							 client_mac_addr[0], client_mac_addr[1], client_mac_addr[2],
							 client_mac_addr[3], client_mac_addr[4], client_mac_addr[5]);
				}
				else
				{
					IPACMDBG_H("The attribute type is not expected!\n");
				}
			}

			ipa_get_if_name(iface_name, data->if_index);

			for (it = neighbor_client.begin(); it != neighbor_client.end(); ++it)
			{
				/* find the client */
				if (memcmp(it->mac_addr, client_mac_addr, IPA_MAC_ADDR_SIZE) == 0)
				{
					/* check if iface is not bridge interface*/
					if (strcmp(config->ipa_virtual_iface_name,
					    config->iface_table[ipa_interface_index].iface_name) != 0)
					{
						/* Posting the IPA_LAN_CLIENT_ADD_EVENT if client info already in neigh cache
						  To install the LanToLan rules in case of ipacm restart or race condition bw
						  WLAN_CLIENT_CONNECT_EX evt and neigh on self.
						*/
						if (it->v4_addr == 0)
						{
							if ((it->ipa_if_num == ipa_interface_index) &&
								(it->iface_index == data->if_index))
							{
								IPACMDBG_H("Neighbor if_index: %d, ipa_if_index = %d,"
									   " name = %s, ip4_addr = 0x%x\n", it->iface_index,
									   it->ipa_if_num, it->iface_name, it->v4_addr);
								/* check if getting real netdev name yet */
								if(strcmp(it->iface_name, IPA_NO_IFACE_NAME) == 0)
								{
									IPACMERR("client name %s not real\n", it->iface_name);
									continue;
								}
								handle_neigh_clients_ops(POST_LAN_CLIENT_ADD_EVT, &(*it));
							}
						}
						else if (it->v4_addr != 0) /* not 0.0.0.0 */
						{
							/* check if getting real netdev name yet */
							if(strcmp(it->iface_name, IPA_NO_IFACE_NAME) == 0)
							{
								IPACMERR("client name %s not real\n", it->iface_name);
								return;
							}

							if(strcmp(it->bridge->bridge_name, BRIDGE_0) != 0)
							{
								if(config->is_added_vlan_iface(iface_name))
								{
									/* check if getting real netdev name yet */
									if(strcmp(it->iface_name, IPA_NO_IFACE_NAME) == 0)
									{
										IPACMERR("client name %s not real\n", it->iface_name);
										return;
									}

									if (config->ipacm_mpdn_enable == TRUE)
									{
										/* Get the bridge interface info */
										bridge = config->get_vlan_bridge(it->iface_name);
										if (!bridge) {
											/* get_vlan bridge failed */
											IPACMERR("couldn't get bridge %s,"
												 " not sending internal event\n",
												 it->iface_name);
											return;
										}
									}
									handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_ADD_EVT, &(*it));
								}
							}
							else
							{
								/* use previous ipv4 first */
								if(data->if_index != it->iface_index)
								{
									IPACMERR("update new kernel iface index \n");
									it->iface_index = data->if_index;
								}

								/* check if client associated with previous network interface */
								if(ipa_interface_index != it->ipa_if_num)
								{
									/* replacing the updated iface */
									IPACMERR("client associated to different AP, update to %s \n",
										config->iface_table[ipa_interface_index].iface_name);
									it->ipa_if_num = ipa_interface_index;
									strlcpy(it->iface_name,
										config->iface_table[ipa_interface_index].iface_name,
										IPA_IFACE_NAME_LEN);
								}
								handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_ADD_EVT, &(*it));
							}
						}
					}
					break;
				}
			}
		}
		break;

		/* Update bridge<->vlan mapping with master interface index
		   and vlan id value and update status as partially updated entry
		*/
		case IPA_ADD_BRIDGE_VLAN_PHY_INTF:
		{
			struct vlan_iface_info vlan_data;
			struct ipa_bridge_vlan_mapping_info add_bridge_vlan_map;

			data_all = (ipacm_event_data_all *)param;
			ret = config->find_matching_vlan(data_all->if_index, &vlan_data);
			if(ret == IPACM_FAILURE)
			{
				IPACMERR("Vlan entry has not been created for interface index %d\n", data_all->if_index);
				return;
			}
			ret = parse_bridge_name(data_all->master_if_index, &add_bridge_vlan_map);
			if(ret == IPACM_FAILURE)
			{
				IPACMERR("Error parsing the bridge name\n");
				return;
			}
			IPACMDBG("Handling IPA_ADD_BRIDGE_VLAN_PHY_INTF event with vlan-id: %d "
				  "master-interface-index: %d\n", vlan_data.vlan_id, data_all->master_if_index);
			add_bridge_vlan_map.vlan_id = vlan_data.vlan_id;
			add_bridge_vlan_map.master_if_index = data_all->master_if_index;
			add_bridge_vlan_map.status = 0;
			config->add_bridge_vlan_mapping(&add_bridge_vlan_map);

		}
		break;
		/* Update partial bridge interface<->vlan entry with bridge interface
		   data.
		*/
		case IPA_ADD_BRIDGE_VLAN_BR_INTF:
		{
			IPACMDBG("Handling IPA_ADD_BRIDGE_VLAN_BR_INTF event\n");
			struct ipa_bridge_vlan_mapping_info vlan_bridge_data;
			int ret = 0;
			data_all = (ipacm_event_data_all *)param;

			ret = parse_bridge_info(data_all->if_index, &vlan_bridge_data);
			if(ret == -1)
			{
				IPACMERR(" error parsing the bridge info\n");
				return;
			}
			vlan_bridge_data.status = 1;
			vlan_bridge_data.master_if_index = data_all->if_index;
			vlan_bridge_data.vlan_id = 0;
			IPACMDBG("Update bridge details in bridge<->vlan mapping list "
				 "with bridge %s, IP 0x%x subnet 0x%x, status %d\n",
				 vlan_bridge_data.bridge_name, vlan_bridge_data.bridge_ipv4,
				 vlan_bridge_data.subnet_mask, vlan_bridge_data.status);
			config->add_bridge_vlan_mapping(&vlan_bridge_data);
		}
		break;
		/* Update partial bridge interface<->vlan entry with bridge interface
		   data.
		*/
		case IPA_CLEAN_NEIGHBOR_CACHE:
		{
				IPACMDBG("Handling %s\n", config->getEventName(IPA_CLEAN_NEIGHBOR_CACHE));
				ipacm_event_data_all *data = (ipacm_event_data_all *)param;
				IPACMDBG("data->iface_name: %s, data->if_index: %d\n", data->iface_name, data->if_index);
				handle_neigh_clients_ops(NEIGH_CLIENT_DEL, &(data->if_index));
		}
		break;

		case IPA_LINK_DOWN_EVENT:
		case IPA_WLAN_LINK_DOWN_EVENT:
		{
			ipacm_event_data_fid *data = (ipacm_event_data_fid *)param;
			IPACMDBG_H("Received IPA_LINK_DOWN_EVENT at Neighbour if_index :%d \n",data->if_index);
			for(it = neighbor_client.begin(); it != neighbor_client.end();)
			{
				if(it->iface_index == data->if_index)
				{
					handle_neigh_clients_ops(POST_LAN_CLIENT_DEL_EVT, &(*it), false, IPA_IP_v4);
					it = neighbor_client.erase(it);
				}
				else
				{
					++it;
				}
			}
		}
		break;

		case IPA_USB_LINK_UP_EVENT:
		{
			/* check by netdev interface to post CLIENT_IP_ADDR_ADD for all clients */
			ipacm_event_data_fid *data = (ipacm_event_data_fid *)param;
			ipa_interface_index = IPACM_Iface::iface_ipa_index_query(data->if_index);
			/* check for failure return */
			if (IPACM_FAILURE == ipa_interface_index) {
				IPACMERR("IPA_USB_LINK_UP_EVENT: not supported iface id: %d\n", data->if_index);
				break;
			}
			IPACMDBG_H("Received IPA_USB_LINK_UP_EVENT with if_index: %d, "
				   "ipa_interface_index = %d\n", data->if_index, ipa_interface_index);
			for (it = neighbor_client.begin(); it != neighbor_client.end(); ++it)
			{
				/* find the client */
				/* Post IPA_LAN_CLIENT_ADD_EVENT to Handle race Condition in RTM_NEWNEIGH on physical iface and ECM_CONNECT */

				if ((it->iface_index == data->if_index))
				{
					IPACMDBG_H("Neighbor if_index: %d, ipa_if_index = %d, name = %s\n",
							it->iface_index, it->ipa_if_num, it->iface_name);
					if(!config->is_added_vlan_iface(it->iface_name))
					{
						/* check if getting real netdev name yet */
						if(strcmp(it->iface_name, IPA_NO_IFACE_NAME) == 0)
						{
							IPACMERR("client name %s not real\n", it->iface_name);
							continue;
						}

						handle_neigh_clients_ops(POST_LAN_CLIENT_ADD_EVT, &(*it));
					}
					/* use previous ipv4 first */

					if (it->v4_addr != 0) /* not 0.0.0.0 */
					{
						IPACMDBG_H("Neighbor if_index: %d, ipa_if_index = %d, name = %s, ip4_addr = 0x%x\n",
								it->iface_index, it->ipa_if_num, it->iface_name, it->v4_addr);
						/* check if getting real netdev name yet */
						if(strcmp(it->iface_name, IPA_NO_IFACE_NAME) == 0)
						{
							IPACMERR("client name %s not real\n", it->iface_name);
							continue;
						}

						/* Post VLAN based event if VLAN iface added */
						if((it->bridge && (strcmp(it->bridge->bridge_name, BRIDGE_0) != 0)) ||
							((!it->bridge) &&config->is_added_vlan_iface(it->iface_name)))
						{
							if(config->is_added_vlan_iface(it->iface_name))
							{
								if (config->ipacm_mpdn_enable == TRUE)
								{
									if(it->bridge)
									{
										/* Get the bridge interface info */
										bridge = config->get_vlan_bridge(it->bridge->bridge_name);
										if (!bridge) {
											/* get_vlan bridge failed */
											IPACMERR("couldn't get bridge %s, not sending internal event\n",
													 it->iface_name);
											return;
										}
									}
									else
									{
										if(config->get_vlan_id(it->iface_name, &vlan_id))
										{
											IPACMDBG_H("failed to get iface vlan ID, skipping\n");
											continue;
										}
										if((vlan_id > 0) && config->is_dummy_VID(vlan_id))
										{
											mapping_info.vlan_id = vlan_id;
											config->get_bridge_vlan_mapping(&mapping_info, true);
											bridge = config->get_vlan_bridge(mapping_info.bridge_name);
											if(bridge && (bridge->associate_VID == 0))
											{
												IPACMDBG_H("client bridge dummy vid mismatch (%d)(%d), skip\n",
													 bridge->associate_VID,
													 bridge->associate_VID);
												continue;
											}
										}
									}
								}
								handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_ADD_EVT, &(*it));
							}
						}
						else
						{
							handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_ADD_EVT, &(*it));
						}
					}
				}
			}
		}
		break;


		case IPA_NEW_NEIGH_EVENT:
		{
			IPACMDBG_H("Received IPA_NEW_NEIGH_EVENT\n");
			handle_neighbor_add_del(event, param);
		}
		break;

		case IPA_DEL_NEIGH_EVENT:
		{
			IPACMDBG_H("Received IPA_DEL_NEIGH_EVENT\n");
			handle_neighbor_add_del(event, param);
		}
		break;

		default:
		{
			IPACMDBG_H("Invalid evnet\n");
		}
		break;
	}
	return;
}

void IPACM_Neighbor::handle_neighbor_add_del(ipa_cm_event_id event, void *param)
{
	int ipa_interface_index = 0;
	int old_if_index = 0;
	bool is_if_index_changed = false;
	std::list<ipa_neighbor_client>::iterator it;
	ipa_bridge_vlan_mapping_info mapping_info = {};
	ipa_neighbor_client element = {};
	ipacm_bridge* dummy_vlan_bridge = NULL;
	IPACM_Config* config = IPACM_Config::GetInstance();

	if(param == NULL)
	{
		IPACMERR("Invalid parameters received\n");
		return;
	}

	ipacm_event_data_all *data = (ipacm_event_data_all *)param;
	ipa_interface_index = IPACM_Iface::iface_ipa_index_query(data->if_index);

#if !defined(FEATURE_L2TP) && !defined(FEATURE_VLAN_MPDN)
	/* check for failure return */
	if (IPACM_FAILURE == ipa_interface_index) {
		IPACMERR("not supported iface id: %d\n", data->if_index);
		return;
	}
#endif
#ifdef FEATURE_VLAN_MPDN
	/* for vlan wan iface need to handle neighbors so condition should fail if vlan wan iface index matches */
	if((IPACM_FAILURE != ipa_interface_index &&
	    config->eth_wan_iface_table_idx != ipa_interface_index) &&
	   (config->ipacm_mpdn_enable == TRUE))
	{
		if(config->iface_in_vlan_mode(data->iface_name))
		{
			IPACMDBG_H("ignoring physical IFACE neighbor event in VLAN mode\n");
			return;
		}
	}
#endif
	IPACMDBG("Got Neighbor event with ip_type: %d: iface_name: %s\n", data->iptype, data->iface_name);

	if (data->iptype == IPA_IP_v4)
	{
		if(data->ipv4_addr != 0)
			handle_v4_neighbor(event, data, ipa_interface_index);
	}
	else if((data->ipv6_addr[0]) || (data->ipv6_addr[1]) || (data->ipv6_addr[2]) || (data->ipv6_addr[3]))
	{
		handle_v6_neighbor(event, data, ipa_interface_index);
	}
	else
	{
		IPACMDBG("Got Neighbor event with no ipv6/ipv4 address\n");
		for (it = neighbor_client.begin(); it != neighbor_client.end(); ++it)
		{
			/* find the client */
			if (memcmp(it->mac_addr, data->mac_addr, IPA_MAC_ADDR_SIZE) == 0)
			{
				IPACMDBG_H("Iface name:%s\n", data->iface_name);
				IPACMDBG_H("found client with MAC %02x:%02x:%02x:%02x:%02x:%02x,"
					   " total client: %d\n", it->mac_addr[0], it->mac_addr[1],
						it->mac_addr[2], it->mac_addr[3], it->mac_addr[4],
						it->mac_addr[5], neighbor_client.size());
				/* check if iface is not bridge interface*/
#ifdef FEATURE_VLAN_MPDN
				/* VLAN clients don't have to be on bridge0 */
				if (((config->ipacm_mpdn_enable == TRUE) && !strstr(data->iface_name, "bridge")) ||
					(((config->ipacm_l2tp_enable == IPACM_L2TP) ||
					(config->ipacm_l2tp_enable == IPACM_L2TP_E2E)) &&
					(strcmp(config->ipa_virtual_iface_name, data->iface_name) != 0)))
#else
				if (strcmp(config->ipa_virtual_iface_name, data->iface_name) != 0)
#endif
				{
#ifdef FEATURE_VLAN_MPDN
					/* VLAN interface && not the same iface name */
					if((config->ipacm_mpdn_enable == TRUE && (IPACM_FAILURE == ipa_interface_index)) ||
						config->is_added_vlan_iface(data->iface_name))
					{
						/* for this case we cached the neigh event from bridgeX where it won't have iface_name */
						if(strcmp(it->iface_name, IPA_NO_IFACE_NAME) == 0)
						{
							/* for VLAN interfaces make sure bridge is with correct VID */
							uint16_t vlan_id = 0;
							if(!validate_bridge_vid(data->iface_name, it->bridge, vlan_id))
							{
								continue;
							}
						}
						else if (strcmp(it->iface_name, data->iface_name) != 0)
						{
							IPACMDBG_H("VLAN interface name (%s) is different (%s): "
									"keep looking\n", it->iface_name,
									data->iface_name);
							continue;
						}
					}
#endif
					/* use previous ipv4 first */
					if(data->if_index != it->iface_index)
					{
						if(!strncmp(it->iface_name, data->iface_name, IPA_IFACE_NAME_LEN))
						{
							IPACMDBG("update new kernel iface index for %s\n",
									data->iface_name);
							old_if_index = it->iface_index;
						}
						IPACMDBG_H("interface index is changes from %d "
							    "to new kernel iface index %d\n",
								old_if_index, data->if_index);
						/* Post LAN CLIENT DEL to delete old index */
						handle_neigh_clients_ops(POST_LAN_CLIENT_DEL_EVT, &(*it), false, IPA_IP_v4);
						it->iface_index = data->if_index;
						strlcpy(it->iface_name, data->iface_name, IPA_IFACE_NAME_LEN);
					}

					/* check if client associated with previous network interface */
					if(ipa_interface_index != it->ipa_if_num)
					{
						/* replacing the updated iface */
						IPACMDBG_H("client associate to different AP %s\n", data->iface_name);
						it->ipa_if_num = ipa_interface_index;
						strlcpy(it->iface_name, data->iface_name, IPA_IFACE_NAME_LEN);
					}

					if (it->v4_addr != 0) /* not 0.0.0.0 */
					{
						/* check if getting real netdev name yet */
						if(strcmp(it->iface_name, IPA_NO_IFACE_NAME) == 0)
						{
							IPACMERR("client name %s not real\n", it->iface_name);
							return;
						}
						if(event == IPA_NEW_NEIGH_EVENT)
						{
							handle_neigh_clients_ops(POST_LAN_CLIENT_ADD_EVT, &(*it));
							handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_ADD_EVT, &(*it));
						}
						else
						{
#ifdef IPA_L2TP_TUNNEL_UDP
							if(config->check_l2tp_iface(it->iface_name))
								handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_DEL_EVT, &(*it), false, IPA_IP_MAX);
							else
#endif
								handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_DEL_EVT, &(*it));
						}
					}
				}
				/* delete cache neighbor entry */
				if (event == IPA_DEL_NEIGH_EVENT)
				{
					if(strcmp(data->iface_name, IPA_NO_IFACE_NAME) == 0)
					{
						IPACMERR("client name %s not real\n", data->iface_name);
						return;
					}
					handle_neigh_clients_ops(POST_LAN_CLIENT_DEL_EVT, data, true, IPA_IP_MAX);
					handle_neigh_clients_ops(NEIGH_CLIENT_DEL, &(data->if_index));
				}
				break;
			}
		}
		/* not find client */
		if (event == IPA_NEW_NEIGH_EVENT)
		{
			/* check if iface is not bridge interface*/
#ifdef FEATURE_VLAN_MPDN
			/* VLAN clients don't have to be on bridge0 */
			if (((config->ipacm_mpdn_enable == TRUE) && !strstr(data->iface_name, "bridge")) ||
				(((config->ipacm_l2tp_enable == IPACM_L2TP) ||
				(config->ipacm_l2tp_enable == IPACM_L2TP_E2E)) &&
				(strcmp(config->ipa_virtual_iface_name, data->iface_name) != 0)))
#else
			if (strcmp(config->ipa_virtual_iface_name, data->iface_name) != 0)
#endif
			{
#ifdef FEATURE_VLAN_MPDN
				/* if this is a vlan interface that was not added we ignore*/
				if((config->ipacm_mpdn_enable == TRUE) &&
					(IPACM_FAILURE == ipa_interface_index) &&
					(config->iface_in_vlan_mode(data->iface_name)) &&
					!(config->is_added_vlan_iface(data->iface_name)))
				{
					IPACMDBG_H("not added VLAN interface %s, add to cache \n", data->iface_name);
				}
#endif
				if(strcmp(data->iface_name, IPA_NO_IFACE_NAME) == 0)
				{
					IPACMERR("client name %s not real\n", data->iface_name);
					return;
				}

				memcpy(element.mac_addr, data->mac_addr, IPA_MAC_ADDR_SIZE);
				element.iface_index = data->if_index;
				element.ipa_if_num = ipa_interface_index;
				element.v4_addr = 0;
				strlcpy(element.iface_name, data->iface_name, IPA_IFACE_NAME_LEN);
#ifdef FEATURE_VLAN_MPDN
				if(config->ipacm_mpdn_enable == TRUE)
					element.bridge = NULL;
#endif
				handle_neigh_clients_ops(NEIGH_CLIENT_ADD, &element);
				handle_neigh_clients_ops(POST_LAN_CLIENT_ADD_EVT, &element);
				return;
			}
		}
	}
	return;
}

void IPACM_Neighbor::handle_v4_neighbor(ipa_cm_event_id event, ipacm_event_data_all *data, int ipa_interface_index)
{
	ipacm_bridge *bridge = NULL;
	std::list<ipa_neighbor_client>::iterator it;
	int skip_nat_set = 0;
	uint16_t vlan_id = 0;
	ipa_neighbor_client element = {};
	ipa_bridge_vlan_mapping_info mapping_info;
	ipacm_bridge* dummy_vlan_bridge = NULL;
	int bridge_index = 0;
	IPACM_Config* config = IPACM_Config::GetInstance();

	IPACMDBG_H("Got Neighbor event with ipv4 address: 0x%x \n", data->ipv4_addr);

	if(data == NULL)
	{
		IPACMERR("Invalid data received\n");
		return;
	}

	/* check if ipv4 address is link local(169.254.xxx.xxx) */
	if ((data->ipv4_addr & IPV4_ADDR_LINKLOCAL_MASK) == IPV4_ADDR_LINKLOCAL)
	{
		IPACMDBG_H("This is link local ipv4 address: 0x%x : ignore this NEIGH_EVENT\n", data->ipv4_addr);
		return;
	}
	/* check if iface is bridge interface*/
#ifdef FEATURE_VLAN_MPDN
	/* VLAN clients don't have to be on bridge0 */
	if (((config->ipacm_mpdn_enable == TRUE) && strstr(data->iface_name, "bridge")) ||
		(((config->ipacm_l2tp_enable == IPACM_L2TP) ||
		(config->ipacm_l2tp_enable == IPACM_L2TP_E2E)) &&
		(strcmp(config->ipa_virtual_iface_name, data->iface_name) == 0)))
#else
	if (strcmp(config->ipa_virtual_iface_name, data->iface_name) == 0)
#endif
	{
		bridge = config->get_vlan_bridge(data->iface_name);
		if(!bridge)
		{
			IPACMDBG("couldn't find the bridge %s, trying to add\n", data->iface_name);
			/* since we know that this is a bridge, let's try to add */
			config->add_vlan_bridge(data);
			bridge = config->get_vlan_bridge(data->iface_name);
			if(!bridge)
			{
				IPACMERR("couldn't find or add bridge %s, not sending internal event\n", data->iface_name);
				return;
			}
		}

		/*This is to avoid installing IPA private subnet Filter rules in case of
		IPPT without NAT scenario to avoid packets taking SW path because we
		are installing private subnet rules with public IP assigned to bridge
		since bridge has no longer the private IP assigned. */

		for (int i = 0; i < MAX_NUM_IP_PASS_MPDN; i++)
		{
			if(config->ip_pass_mpdn_table[i].valid_entry == true &&
				config->ip_pass_mpdn_table[i].ip_pass_skip_nat == 1)
			{
				skip_nat_set = 1;
				break;
			}
		}
		if(skip_nat_set)
		{
			if (IPACM_Iface::ipa_get_if_index(bridge->bridge_name, &bridge_index) == IPACM_SUCCESS)
			{
				if(config->DelPrivateSubnetByIfIndex(bridge_index) == true)
					IPACMDBG_H("Deleted IPACM bridge private subnet_addr for %s\n", bridge->bridge_name);
				else
					IPACMERR("Can't Delete IPACM private subnet_addr for %s\n", bridge->bridge_name);
			}
			else
			{
				IPACMERR("get interface index failed for %s\n", bridge->bridge_name);
			}

		}
		skip_nat_set = 0;

		/* search if seen this client or not*/
		for (it = neighbor_client.begin(); it != neighbor_client.end(); ++it)
		{
			if (memcmp(it->mac_addr, data->mac_addr, IPA_MAC_ADDR_SIZE) == 0)
			{
#ifdef FEATURE_VLAN_MPDN
				if(config->ipacm_mpdn_enable == TRUE)
				{
					if(it->bridge)
					{
						if(it->bridge != bridge)
						{
							IPACMERR("client (dev %s) already associated with a different bridge "
								 "%s->%s, keep looking for same MAC\n",
								it->iface_name,
								it->bridge->bridge_name,
								bridge->bridge_name);
							continue;
						}
					}
					else
					{
						/* for VLAN interfaces make sure bridge is with correct VID */
						if(!validate_bridge_vid(it->iface_name, bridge, vlan_id))
						{
							continue;
						}
					}
				}
#endif
				if(strcmp(data->iface_name, IPA_NO_IFACE_NAME) == 0)
				{
					IPACMERR("client name %s not real\n", data->iface_name);
					return;
				}

				IPACMDBG_H("Iface name:%s\n", data->iface_name);
				IPACMDBG_H("found client with MAC %02x:%02x:%02x:%02x:%02x:%02x,"
					   " total client: %d\n", it->mac_addr[0], it->mac_addr[1],
							it->mac_addr[2], it->mac_addr[3], it->mac_addr[4],
							it->mac_addr[5], neighbor_client.size());
				IPACMDBG_H("Neighbor: Iface name:%s, IfaceIndex:%d, ipv4:%x\n",
						it->iface_name, it->iface_index, data->ipv4_addr);
				it->v4_addr = data->ipv4_addr; //cache client's previous ipv4 address
#ifdef FEATURE_VLAN_MPDN
				if(config->ipacm_mpdn_enable == TRUE)
				{
					if(event == IPA_NEW_NEIGH_EVENT)
						handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_ADD_EVT, &(*it));
					else
						handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_DEL_EVT, &(*it));
				}
				else
#endif
				{
					if (config->ipacm_l2tp_enable == IPACM_L2TP ||
						config->ipacm_l2tp_enable == IPACM_L2TP_E2E)
					{
						if(event == IPA_NEW_NEIGH_EVENT)
							handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_ADD_EVT, data, true);
						else
							handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_DEL_EVT, data, true);
					}
				}
				break;
			}
		}
		/* Cache the neighbor event from bridgeX as well if physical netdev can't find */
		if((event == IPA_NEW_NEIGH_EVENT) && (it == neighbor_client.end()))
		{
			memcpy(element.mac_addr, data->mac_addr, IPA_MAC_ADDR_SIZE);
			element.iface_index = data->if_index;
			element.ipa_if_num = ipa_interface_index;
			element.v4_addr = data->ipv4_addr;
			strlcpy(element.iface_name, IPA_NO_IFACE_NAME, IPA_IFACE_NAME_LEN);
#ifdef FEATURE_VLAN_MPDN
			if(config->ipacm_mpdn_enable == TRUE)
				element.bridge = bridge;
#endif
			handle_neigh_clients_ops(NEIGH_CLIENT_ADD, &element);
			return;
		}
	}
	else
	{
		/* construct IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT command and insert to command-queue */
		if(event == IPA_NEW_NEIGH_EVENT)
		{
			/* Also save to cache for ipv4 */
			/*search if seen this client or not*/
			for (it = neighbor_client.begin(); it != neighbor_client.end(); ++it)
			{
				/* find the client */
				if (memcmp(it->mac_addr, data->mac_addr, IPA_MAC_ADDR_SIZE) == 0)
				{
					/* update the network interface client associated */
					/* for this case we cached the neigh event from bridgeX where it won't have iface_name */
					if(strcmp(it->iface_name, IPA_NO_IFACE_NAME) == 0)
					{
						/* for VLAN interfaces make sure bridge is with correct VID */
						if(config->iface_in_vlan_mode(data->iface_name)
#ifdef IPA_L2TP_TUNNEL_UDP
							&& !config->check_l2tp_iface(data->iface_name)
#endif
							)
						{
							uint16_t vlan_id;
							if(config->get_vlan_id(data->iface_name, &vlan_id))
							{
								IPACMERR("failed to get iface vlan ID, skipping\n");
								continue;
							}
							if(it->bridge && (it->bridge->associate_VID != vlan_id))
							{
								IPACMDBG("client bridge vid mismatch (%d)(%d), skip\n",
									vlan_id, it->bridge->associate_VID);
								continue;
							}
							IPACMDBG_H("client - bridge vid match (%d)\n", vlan_id);
						}
					}
					else if (strcmp(it->iface_name, data->iface_name) != 0)
					{
						IPACMDBG_H("VLAN interface name (%s) is different (%s): keep looking\n",
								it->iface_name, data->iface_name);
						continue;
					}
					it->iface_index = data->if_index;
					it->ipa_if_num = ipa_interface_index;
					it->v4_addr = data->ipv4_addr; // cache client's previous ipv4 address
					strlcpy(it->iface_name, data->iface_name, IPA_IFACE_NAME_LEN);
					IPACMDBG_H("update cache with %s iface, ipv4 address: 0x%x\n",
							data->iface_name, data->ipv4_addr);
					break;
				}
			}
			memcpy(element.mac_addr, data->mac_addr, IPA_MAC_ADDR_SIZE);
			element.iface_index = data->if_index;
			element.ipa_if_num = ipa_interface_index;
			element.v4_addr = data->ipv4_addr;
			strlcpy(element.iface_name, data->iface_name, IPA_IFACE_NAME_LEN);
#ifdef FEATURE_VLAN_MPDN
			if(config->ipacm_mpdn_enable == TRUE)
				element.bridge = NULL;
#endif
			handle_neigh_clients_ops(NEIGH_CLIENT_ADD, &element);
		}
		else
		{
			/*searh if seen this client or not*/
			for (it = neighbor_client.begin(); it != neighbor_client.end(); ++it)
			{
				/* find the client */
				if (memcmp(it->mac_addr, data->mac_addr, IPA_MAC_ADDR_SIZE) == 0)
				{
#ifdef FEATURE_VLAN_MPDN
					if(config->ipacm_mpdn_enable == TRUE)
					{
						/* for VLAN interfaces make sure this is the correct interface */
						if(config->iface_in_vlan_mode(it->iface_name) ||
						   config->is_added_vlan_iface(it->iface_name))
						{
							if(strcmp(it->iface_name, data->iface_name) != 0)
							{
								IPACMDBG_H("IP_ADDR_DEL_EVENT: MAC match but iface name is different %s <-> %s, skip\n",
									data->iface_name, it->iface_name);
								continue;
							}
						}
					}
#endif
					/* check if getting real netdev name yet */
					if(strcmp(data->iface_name, IPA_NO_IFACE_NAME) == 0)
					{
						IPACMERR("client name %s not real\n", data->iface_name);
						return;
					}

					handle_neigh_clients_ops(NEIGH_CLIENT_DEL, &(it->iface_index));
					handle_neigh_clients_ops(POST_LAN_CLIENT_DEL_EVT, data, true);
					return;
				}
			}
			/* not find client, no need clean-up */
		}
		if(strcmp(data->iface_name, IPA_NO_IFACE_NAME) == 0)
		{
			IPACMERR("client name %s not real\n", data->iface_name);
			return;
		}

		/* posting vlan event for wan case of eth vlan wan iface */
		if(event == IPA_NEW_NEIGH_EVENT)
			handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_ADD_EVT, data, true);
		else
			handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_DEL_EVT, data, true);

		return;
	}
}

void IPACM_Neighbor::handle_v6_neighbor(ipa_cm_event_id event, ipacm_event_data_all *data, int ipa_interface_index)
{
	std::list<ipa_neighbor_client>::iterator it;
	ipacm_bridge *bridge = NULL;
	uint16_t vlan_id = 0;
	ipa_bridge_vlan_mapping_info mapping_info;
	ipacm_bridge* dummy_vlan_bridge = NULL;
	IPACM_Config* config = IPACM_Config::GetInstance();

	IPACMDBG("Got New_Neighbor event with ipv6 addr [0x%x:%x:%x:%x] \n",
		data->ipv6_addr[0], data->ipv6_addr[1], data->ipv6_addr[2], data->ipv6_addr[3]);

	if(data == NULL)
	{
		IPACMERR("Invalid data received\n");
		return;
	}

	/* check if iface is bridge interface*/
#ifdef FEATURE_VLAN_MPDN
	/* VLAN clients don't have to be on bridge0 */
	if (strstr(data->iface_name, "bridge"))
#else
	if(strcmp(config->ipa_virtual_iface_name, data->iface_name) == 0)
#endif
	{
#ifdef FEATURE_VLAN_MPDN
		if(config->ipacm_mpdn_enable == TRUE)
		{
			bridge = config->get_vlan_bridge(data->iface_name);
			if(!bridge)
			{
				IPACMDBG("couldn't find the bridge %s, trying to add\n", data->iface_name);
				/* since we know that this is a bridge, let's try to add */
				config->add_vlan_bridge(data);
				bridge = config->get_vlan_bridge(data->iface_name);
				if(!bridge)
				{
					IPACMERR("couldn't find or add bridge %s, not sending internal event\n", data->iface_name);
					return;
				}
			}
		}
#endif
		/* search if seen this client or not*/
		for (it = neighbor_client.begin(); it != neighbor_client.end(); ++it)
		{
			if (memcmp(it->mac_addr, data->mac_addr, IPA_MAC_ADDR_SIZE) == 0)
			{
#ifdef FEATURE_VLAN_MPDN
				if(config->ipacm_mpdn_enable == TRUE)
				{
					if(it->bridge)
					{
						if(it->bridge != bridge)
						{
							IPACMERR("client (dev %s) already associated with a "
								"different bridge %s->%s, keep looking for same MAC\n",
								it->iface_name, it->bridge->bridge_name,
								bridge->bridge_name);
							continue;
						}
					}
					else
					{
						/* for VLAN interfaces make sure bridge is with correct VID */
						if(!validate_bridge_vid(it->iface_name, bridge, vlan_id))
						{
							continue;
						}
					}
				}
#endif
				data->if_index = it->iface_index;
				strlcpy(data->iface_name, it->iface_name, sizeof(data->iface_name));
				/* check if getting real netdev name yet */
				if(strcmp(data->iface_name, IPA_NO_IFACE_NAME) == 0)
				{
					IPACMERR("client name %s not real\n", data->iface_name);
					return;
				}
				if(event == IPA_NEW_NEIGH_EVENT)
					handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_ADD_EVT, data, true);
				else
					handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_DEL_EVT, &(*it));

				break;
			}
		}
	}
	else
	{
		/* In l2tp case can recieve vlan iface address without bridge */
		/* construct IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT command and insert to command-queue */
		if (event == IPA_NEW_NEIGH_EVENT)
			handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_ADD_EVT, data, true);
		else
			handle_neigh_clients_ops(POST_NEIGH_CLIENT_IP_DEL_EVT, data, true);
	}
}

/*
  Function: handle_neigh_clients_ops
  Params:
	ops: supports below operations:
		NEIGH_CLIENT_ADD: Add to neighbor_client list
			Input: ipa_neighbor_client List element
		NEIGH_CLIENT_DEL: Delete from neighbor_client list
			Input: iface_index to search in ipa_neighbor_client List
		POST_NEIGH_CLIENT_IP_ADD_EVT: Post IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT event
		POST_NEIGH_CLIENT_IP_DEL_EVT: Post IPA_NEIGH_CLIENT_IP_ADDR_DEL_EVENT event
		POST_LAN_CLIENT_ADD_EVT: Post IPA_LAN_CLIENT_ADD_EVENT event
		POST_LAN_CLIENT_DEL_EVT: Post IPA_LAN_CLIENT_DEL_EVENT event
			Input: if post_data is true, post data as it is.
				else interpret as list element and deep copy.
	data: data for all above events
	iptype: to be used for posting events
	post_data: see ops
*/
void IPACM_Neighbor::handle_neigh_clients_ops(ipacm_neigh_cache_ops_type ops, void* data,
					bool post_data,  ipa_ip_type iptype)
{
	ipacm_event_data_all *data_all = NULL;
	ipa_neighbor_client* element = NULL;
	ipacm_cmd_q_data evt_data = {};
	int* iface_idx = NULL;
	std::list<ipa_neighbor_client>::iterator it;
	IPACM_Config* config = IPACM_Config::GetInstance();

	if(data == NULL)
	{
		IPACMERR("Input data is NULL!\n");
		return;
	}

	switch(ops)
	{
		case NEIGH_CLIENT_ADD:
		{
			element = (ipa_neighbor_client *)data;
			IPACMDBG_H("Adding client with MAC %02x:%02x:%02x:%02x:%02x:%02x\n, total client: %zu\n",
				element->mac_addr[0], element->mac_addr[1],
				element->mac_addr[2], element->mac_addr[3],
				element->mac_addr[4], element->mac_addr[5],
				neighbor_client.size());
			if(neighbor_client.size() >= IPA_MAX_NUM_NEIGHBOR_CLIENTS)
			{
				it = neighbor_client.begin();
				IPACMDBG_H("Removing the client with MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
						it->mac_addr[0], it->mac_addr[1],
						it->mac_addr[2], it->mac_addr[3],
						it->mac_addr[4], it->mac_addr[5]);
				neighbor_client.pop_front();
			}
			neighbor_client.push_back(*element);
		}
		break;

		case NEIGH_CLIENT_DEL:
		{
			iface_idx = (int *)data;
			bool found = false;
			for(it = neighbor_client.begin(); it != neighbor_client.end();)
			{
				if(it->iface_index == *iface_idx)
				{
					if (!found)
						found = true;
					IPACMDBG_H("Erasing client with MAC:  %02x:%02x:%02x:%02x:%02x:%02x"
							" iface index: %d\n", it->mac_addr[0],
							it->mac_addr[1], it->mac_addr[2],
							it->mac_addr[3], it->mac_addr[4],
							it->mac_addr[5], *iface_idx);
					it = neighbor_client.erase(it);
				}
				else
				{
					++it;
				}
			}
			if(!found)
				IPACMDBG_H("Couldn't find the entry for client with iface_idx: %d", *iface_idx);
		}
		break;

		case POST_LAN_CLIENT_ADD_EVT:
		case POST_LAN_CLIENT_DEL_EVT:
                case POST_NEIGH_CLIENT_IP_ADD_EVT:
                case POST_NEIGH_CLIENT_IP_DEL_EVT:
		{
			data_all = (ipacm_event_data_all *)calloc(1, sizeof(ipacm_event_data_all));
			if (data_all == NULL)
			{
				IPACMERR("Unable to allocate memory\n");
				return;
			}
			if(post_data)
			{
				memcpy(data_all, data, sizeof(ipacm_event_data_all));
			}
			else
			{
				element = (ipa_neighbor_client *)data;
				data_all->iptype = iptype;
				data_all->if_index = element->iface_index;
				data_all->ipv4_addr = element->v4_addr;
				memcpy(data_all->mac_addr, element->mac_addr, IPA_MAC_ADDR_SIZE);
				strlcpy(data_all->iface_name, element->iface_name, IPA_IFACE_NAME_LEN);
				evt_data.evt_data = (void *)data_all;
			}

			if(ops == POST_LAN_CLIENT_ADD_EVT)
				evt_data.event = IPA_LAN_CLIENT_ADD_EVENT;
			else if(ops == POST_NEIGH_CLIENT_IP_ADD_EVT)
				evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT;
			else if(ops == POST_NEIGH_CLIENT_IP_DEL_EVT)
				evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_DEL_EVENT;
			else if(ops == POST_LAN_CLIENT_DEL_EVT)
				evt_data.event = IPA_LAN_CLIENT_DEL_EVENT;

			evt_data.evt_data = (void *)data_all;
			IPACM_EvtDispatcher::PostEvt(&evt_data);
			IPACMDBG_H("Posted event %s for interface %s\n",
					config->getEventName(evt_data.event),
					data_all->iface_name);
		}
		break;
	}
	return;
}

void IPACM_Neighbor::post_phys_iface_event(const char *iface_name, int ipa_if_num, int if_idx)
{
	char phys_iface_name[IPA_IFACE_NAME_LEN] = {0};
	int phys_if_idx;
	ipacm_event_data_fid *data_fid = NULL;
	ipacm_cmd_q_data evt_data;

	/* Vlan client */
	if (IPACM_FAILURE == ipa_if_num) {
		if (strstr(iface_name, ETH_INTF)) {
			strlcpy(phys_iface_name, ETH_INTF, IPA_IFACE_NAME_LEN);
		}
		else if (strstr(iface_name, ETH1_INTF)) {
			strlcpy(phys_iface_name, ETH1_INTF, IPA_IFACE_NAME_LEN);
		}
		else if (strstr(iface_name, RNDIS_INTF)) {
			strlcpy(phys_iface_name, RNDIS_INTF, IPA_IFACE_NAME_LEN);
		}
		else if (strstr(iface_name, ECM_INTF)) {
			strlcpy(phys_iface_name, ECM_INTF, IPA_IFACE_NAME_LEN);
		}
		else
			return;
		if(IPACM_Iface::ipa_get_if_index(phys_iface_name, &phys_if_idx))
		{
			IPACMERR("Error while getting interface index for %s device", phys_iface_name);
			return;
		}
	}
	else
		phys_if_idx = if_idx;

	data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
	if (data_fid == NULL) {
		IPACMERR("unable to allocate memory for event data_fid\n");
		return;
	}

	data_fid->if_index = phys_if_idx;
	evt_data.event = IPA_USB_LINK_UP_EVENT;
	evt_data.evt_data = data_fid;
	IPACMDBG_H("Posting usb IPA_LINK_UP_EVENT with if index: %d iface_name : %s\n",
						 data_fid->if_index, iface_name);
	IPACM_EvtDispatcher::PostEvt(&evt_data);
}
