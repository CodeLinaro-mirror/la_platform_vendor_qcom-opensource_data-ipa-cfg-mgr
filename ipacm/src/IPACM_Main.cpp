/*
 * Copyright (c) 2013-2021 The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name of The Linux Foundation nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
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
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted (subject to the limitations in the
 * disclaimer below) provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 *   * Neither the name of Qualcomm Innovation Center, Inc. nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
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
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Changes from Qualcomm Innovation Center, Inc. are provided under the following license:
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear.
 */
 /*!
	@file
	IPACM_Main.cpp.

	@brief
	This file implements the IPAM functionality.

	@Author
	Skylar Chang

*/
/******************************************************************************

                      IPCM_MAIN.C

******************************************************************************/

#include <sys/socket.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <sys/inotify.h>
#include <stdlib.h>
#include <execinfo.h>
#include "linux/ipa_qmi_service_v01.h"

#include <string.h>
#include <netlink/object.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/object-api.h>
#include <netlink/cache.h>

#include "IPACM_CmdQueue.h"
#include "IPACM_EvtDispatcher.h"
#include "IPACM_Defs.h"
#include "IPACM_Neighbor.h"
#include "IPACM_IfaceManager.h"
#include "IPACM_Log.h"

#include "IPACM_ConntrackListener.h"
#include "IPACM_ConntrackClient.h"
#include "IPACM_Netlink.h"

/* not defined(FEATURE_IPA_ANDROID)*/
#ifndef FEATURE_IPA_ANDROID
#include "IPACM_LanToLan.h"
#endif
#if defined(FEATURE_SOCKSv5) && defined(FEATURE_IPV6_NAT)
#error SOCKSv5 and IPV6_NAT cannot work without run time modifications
#endif
#define IPA_DRIVER  "/dev/ipa"

#define IPACM_SWALLOW_FILE_NAME     "ipa_filter_cfg.xml"
#define IPACM_CFG_FILE_NAME    "IPACM_cfg.xml"
#ifndef FEATURE_IPA_ANDROID
#define IPACM_PID_FILE "/var/run/data/ipa/ipacm.pid"
#ifdef DATA_CONFIG_DIR_PATH
#define IPACM_DIR_NAME SYSRW_CONFIG_DIR_PATH"/ipa"
#define IPACM_FIREWALL_DIR_NAME SYSRW_CONFIG_DIR_PATH
#else
#define IPACM_DIR_NAME     "/systemrw/data/ipa"
#define IPACM_FIREWALL_DIR_NAME     "/systemrw/data"
#endif
#else
#define IPACM_PID_FILE "/data/misc/ipa/ipacm.pid"
#define IPACM_DIR_NAME     "/data/misc/ipa/"
#endif
#define IPACM_NAME "ipacm"

#define INOTIFY_EVENT_SIZE  (sizeof(struct inotify_event))
#define INOTIFY_BUF_LEN     (INOTIFY_EVENT_SIZE +  NAME_MAX + 1)

#define IPA_DRIVER_WLAN_EVENT_MAX_OF_ATTRIBS  3
#define IPA_DRIVER_WLAN_EVENT_SIZE  (sizeof(struct ipa_wlan_msg_ex)+ IPA_DRIVER_WLAN_EVENT_MAX_OF_ATTRIBS*sizeof(ipa_wlan_hdr_attrib_val))
#define IPA_DRIVER_PIPE_STATS_EVENT_SIZE  (sizeof(struct ipa_get_data_stats_resp_msg_v01))
#define IPA_DRIVER_WLAN_META_MSG    (sizeof(struct ipa_msg_meta))
#define IPA_DRIVER_WLAN_BUF_LEN     (IPA_DRIVER_PIPE_STATS_EVENT_SIZE + IPA_DRIVER_WLAN_META_MSG)

#ifdef FEATURE_IPACM_RESTART
#define IPA_READY_QCMAP_NOTIFIER_FILE "/var/run/data/monitor/ipacmd.pid"
#endif
IPACM_Neighbor *neigh = NULL;

uint32_t ipacm_event_stats[IPACM_EVENT_MAX];

void ipa_is_ipacm_running(void);
int ipa_get_if_index(char *if_name, int *if_index);

#ifdef FEATURE_IPACM_RESTART
int ipa_reset();
int ipa_query_driver_event();
#endif

/* start netlink socket monitor*/
void* netlink_start(void *param)
{
	ipa_nl_sk_fd_set_info_t sk_fdset;
	int ret_val = 0;
	memset(&sk_fdset, 0, sizeof(ipa_nl_sk_fd_set_info_t));
	IPACMDBG_H("netlink starter memset sk_fdset succeeds\n");
	ret_val = ipa_nl_listener_init(NETLINK_ROUTE, (RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_LINK |
																										RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_NEIGH |
																										RTNLGRP_IPV6_PREFIX),
																 &sk_fdset, ipa_nl_recv_msg);

	if (ret_val != IPACM_SUCCESS)
	{
		IPACMERR("Failed to initialize IPA netlink event listener\n");
		return NULL;
	}

	return NULL;
}

/* start firewall-rule monitor*/
void* firewall_monitor(void *param)
{
	int length;
	int wd, wd1;
	char buffer[INOTIFY_BUF_LEN];
	int inotify_fd;
	ipacm_cmd_q_data evt_data;
	IPACM_Config* config;
	uint32_t mask = IN_MODIFY | IN_MOVE;

	inotify_fd = inotify_init();
	if (inotify_fd < 0)
	{
		PERROR("inotify_init");
	}

	IPACMDBG_H("Waiting for notifications in dirs %s with mask: 0x%x\n", IPACM_DIR_NAME,
		mask);

	wd = inotify_add_watch(inotify_fd,
												 IPACM_DIR_NAME,
												 mask);

	/* Read and store the data on boot up */
	config = IPACM_Config::GetInstance();

	if(config != NULL)
	{
		if(config->ReadSwAllow() != IPACM_SUCCESS)
		{
			IPACMERR("ReadSwAllow is failed\n");
		}
	}
	else
	{
		IPACMERR("config is not  initialized\n");
	}

	while (1)
	{
		length = read(inotify_fd, buffer, INOTIFY_BUF_LEN);
		if (length < 0)
		{
			IPACMERR("inotify read() error return length: %d and mask: 0x%x\n", length, mask);
			continue;
		}

		struct inotify_event* event;
		event = (struct inotify_event*)malloc(length);
		if(event == NULL)
		{
			IPACMERR("Failed to allocate memory.\n");
			return NULL;
		}
		memset(event, 0, length);
		memcpy(event, buffer, length);

		if (event->len > 0)
		{
			if ( (event->mask & IN_MODIFY) || (event->mask & IN_MOVE))
			{
				if (event->mask & IN_ISDIR)
				{
					IPACMDBG_H("The directory %s was 0x%x\n", event->name, event->mask);
				}
				else if (!strncmp(event->name, IPACM_SWALLOW_FILE_NAME, event->len)) // swallow rule change
				{
					IPACMDBG_H("File \"%s\" was 0x%x\n", event->name, event->mask);
					IPACMDBG_H("The interested file %s .\n", IPACM_SWALLOW_FILE_NAME);

					config = IPACM_Config::GetInstance();

					if(config != NULL && IPACM_Iface::ipacmcfg->ipacm_msgflt_enable)
					{
						config->ReadSwAllow();
					}
					else
					{
						IPACMERR("config is not  initialized\n");
					}
				}
				else if (!strncmp(event->name, IPACM_CFG_FILE_NAME, event->len) && IPACM_Iface::ipacmcfg->ipacm_msgflt_enable) // IPACM_configuration change
				{
					IPACMDBG_H("File \"%s\" was 0x%x\n", event->name, event->mask);
					IPACMDBG_H("The interested file %s .\n", IPACM_CFG_FILE_NAME);

					evt_data.event = IPA_CFG_CHANGE_EVENT;
					evt_data.evt_data = NULL;

					/* Insert IPA_FIREWALL_CHANGE_EVENT to command queue */
					IPACM_EvtDispatcher::PostEvt(&evt_data);
				}
			}
			IPACMDBG_H("Received monitoring event %s.\n", event->name);
		}
		free(event);
	}

	(void)inotify_rm_watch(inotify_fd, wd);
	(void)inotify_rm_watch(inotify_fd, wd1);
	(void)close(inotify_fd);
	return NULL;
}


/* start IPACM wan-driver notifier */
void* ipa_driver_msg_notifier(void *param)
{
	int length, fd, cnt;

#ifdef FEATURE_IPACM_RESTART
	FILE *fp = NULL;
#endif

	char buffer[IPA_DRIVER_WLAN_BUF_LEN];
	struct ipa_msg_meta event_hdr;
	struct ipa_ecm_msg event_ecm;
	struct ipa_wan_msg event_wan;
	struct ipa_wlan_msg_ex event_ex_o;
	struct ipa_wlan_msg *event_wlan=NULL;
	struct ipa_wlan_msg_ex *event_ex= NULL;
	struct ipa_get_data_stats_resp_msg_v01 event_data_stats;
	struct ipa_get_apn_data_stats_resp_msg_v01 event_network_stats;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
	struct ipa_lan_client_msg event_lan_client;
#endif

	ipacm_cmd_q_data evt_data;
	ipacm_event_data_mac *data = NULL;
	ipacm_event_data_fid *data_fid = NULL;
	ipacm_event_data_iptype *data_iptype = NULL;
	ipacm_event_data_wlan_ex *data_ex;
	ipa_get_data_stats_resp_msg_v01 *data_tethering_stats = NULL;
	ipa_get_apn_data_stats_resp_msg_v01 *data_network_stats = NULL;
	ipacm_event_data_addr *data_addr = NULL;
	ipacm_event_ip_pass_pdn_info *ip_pass_pdn_data;

#if defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
	ipa_vlan_iface_info vlan_info;
	ipa_ioc_l2tp_vlan_mapping_info mapping;
#endif
	ipacm_cmd_q_data new_neigh_evt;
	ipacm_event_data_all* new_neigh_data;
	ipa_ioc_gsb_info *event_gsb = NULL;
	ipa_ioc_pdn_config *pdn_info = NULL;

#ifdef FEATURE_SOCKSv5
	ipa_socksv5_msg add_socksv5_info;
	ipa_socksv5_msg *sock_up_event_data = NULL;
	uint32_t del_socksv5_info;
#endif
#ifdef IPA_IOCTL_ADD_VLAN_PRIORITY
	struct ipa_ioc_vlan_priority *vlan_prio_evt;
#endif
	struct ipa_macsec_map *macsecMap = NULL;
	int currentIfaceIndex;

	fd = open(IPA_DRIVER, O_RDWR);
	if (fd < 0)
	{
		IPACMERR("Failed opening %s.\n", IPA_DRIVER);
		return NULL;
	}

	while (1)
	{
		IPACMDBG_H("Waiting for notifications from IPA driver \n");
		memset(buffer, 0, sizeof(buffer));
		memset(&evt_data, 0, sizeof(evt_data));
		memset(&new_neigh_evt, 0, sizeof(ipacm_cmd_q_data));
		new_neigh_data = NULL;
		data = NULL;
		data_fid = NULL;
		data_tethering_stats = NULL;
		data_network_stats = NULL;

		length = read(fd, buffer, IPA_DRIVER_WLAN_BUF_LEN);
		if (length < 0)
		{
			PERROR("didn't read IPA_driver correctly");
			continue;
		}

		memcpy(&event_hdr, buffer,sizeof(struct ipa_msg_meta));
		IPACMDBG_H("Message type: %d\n", event_hdr.msg_type);
		IPACMDBG_H("Event header length received: %d\n",event_hdr.msg_len);

		/* Insert WLAN_DRIVER_EVENT to command queue */
		switch (event_hdr.msg_type)
		{

		case SW_ROUTING_ENABLE:
			IPACMDBG_H("Received SW_ROUTING_ENABLE\n");
			evt_data.event = IPA_SW_ROUTING_ENABLE;
			IPACMDBG_H("Not supported anymore\n");
			continue;

		case SW_ROUTING_DISABLE:
			IPACMDBG_H("Received SW_ROUTING_DISABLE\n");
			evt_data.event = IPA_SW_ROUTING_DISABLE;
			IPACMDBG_H("Not supported anymore\n");
			continue;

		case WLAN_AP_CONNECT:
			event_wlan = (struct ipa_wlan_msg *) (buffer + sizeof(struct ipa_msg_meta));
			IPACMDBG_H("Received WLAN_AP_CONNECT name: %s\n",event_wlan->name);
			IPACMDBG_H("AP Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n",
							 event_wlan->mac_addr[0], event_wlan->mac_addr[1], event_wlan->mac_addr[2],
							 event_wlan->mac_addr[3], event_wlan->mac_addr[4], event_wlan->mac_addr[5]);
                        data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
			if(data_fid == NULL)
			{
				IPACMERR("unable to allocate memory for event_wlan data_fid\n");
				return NULL;
			}
			ipa_get_if_index(event_wlan->name, &(data_fid->if_index));
			evt_data.event = IPA_WLAN_AP_LINK_UP_EVENT;
			evt_data.evt_data = data_fid;
			break;

		case WLAN_AP_DISCONNECT:
			event_wlan = (struct ipa_wlan_msg *)(buffer + sizeof(struct ipa_msg_meta));
			IPACMDBG_H("Received WLAN_AP_DISCONNECT name: %s\n",event_wlan->name);
			IPACMDBG_H("AP Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n",
							 event_wlan->mac_addr[0], event_wlan->mac_addr[1], event_wlan->mac_addr[2],
							 event_wlan->mac_addr[3], event_wlan->mac_addr[4], event_wlan->mac_addr[5]);
                        data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
			if(data_fid == NULL)
			{
				IPACMERR("unable to allocate memory for event_wlan data_fid\n");
				return NULL;
			}
			ipa_get_if_index(event_wlan->name, &(data_fid->if_index));
			evt_data.event = IPA_WLAN_LINK_DOWN_EVENT;
			evt_data.evt_data = data_fid;
			break;
		case WLAN_STA_CONNECT:
			event_wlan = (struct ipa_wlan_msg *)(buffer + sizeof(struct ipa_msg_meta));
			IPACMDBG_H("Received WLAN_STA_CONNECT name: %s\n",event_wlan->name);
			IPACMDBG_H("STA Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n",
							 event_wlan->mac_addr[0], event_wlan->mac_addr[1], event_wlan->mac_addr[2],
							 event_wlan->mac_addr[3], event_wlan->mac_addr[4], event_wlan->mac_addr[5]);
			data = (ipacm_event_data_mac *)malloc(sizeof(ipacm_event_data_mac));
			if(data == NULL)
			{
				IPACMERR("unable to allocate memory for event_wlan data_fid\n");
				return NULL;
			}
			memcpy(data->mac_addr,
				 event_wlan->mac_addr,
				 sizeof(event_wlan->mac_addr));
			ipa_get_if_index(event_wlan->name, &(data->if_index));
			evt_data.event = IPA_WLAN_STA_LINK_UP_EVENT;
			evt_data.evt_data = data;
			break;

		case WLAN_STA_DISCONNECT:
			event_wlan = (struct ipa_wlan_msg *)(buffer + sizeof(struct ipa_msg_meta));
			IPACMDBG_H("Received WLAN_STA_DISCONNECT name: %s\n",event_wlan->name);
			IPACMDBG_H("STA Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n",
							 event_wlan->mac_addr[0], event_wlan->mac_addr[1], event_wlan->mac_addr[2],
							 event_wlan->mac_addr[3], event_wlan->mac_addr[4], event_wlan->mac_addr[5]);
                        data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
			if(data_fid == NULL)
			{
				IPACMERR("unable to allocate memory for event_wlan data_fid\n");
				return NULL;
			}
			ipa_get_if_index(event_wlan->name, &(data_fid->if_index));
			evt_data.event = IPA_WLAN_LINK_DOWN_EVENT;
			evt_data.evt_data = data_fid;
			break;

		case WLAN_CLIENT_CONNECT:
			event_wlan = (struct ipa_wlan_msg *)(buffer + sizeof(struct ipa_msg_meta));
			IPACMDBG_H("Received WLAN_CLIENT_CONNECT\n");
			IPACMDBG_H("Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n",
							 event_wlan->mac_addr[0], event_wlan->mac_addr[1], event_wlan->mac_addr[2],
							 event_wlan->mac_addr[3], event_wlan->mac_addr[4], event_wlan->mac_addr[5]);
		        data = (ipacm_event_data_mac *)malloc(sizeof(ipacm_event_data_mac));
		        if (data == NULL)
		        {
		    	        IPACMERR("unable to allocate memory for event_wlan data\n");
		    	        return NULL;
		        }
			memcpy(data->mac_addr,
						 event_wlan->mac_addr,
						 sizeof(event_wlan->mac_addr));
			ipa_get_if_index(event_wlan->name, &(data->if_index));
		        evt_data.event = IPA_WLAN_CLIENT_ADD_EVENT;
			evt_data.evt_data = data;
			break;

		case WLAN_CLIENT_CONNECT_EX:
			IPACMDBG_H("Received WLAN_CLIENT_CONNECT_EX\n");

			memcpy(&event_ex_o, buffer + sizeof(struct ipa_msg_meta),sizeof(struct ipa_wlan_msg_ex));
			if(event_ex_o.num_of_attribs > IPA_DRIVER_WLAN_EVENT_MAX_OF_ATTRIBS)
			{
				IPACMERR("buffer size overflow\n");
				return NULL;
			}
			length = sizeof(ipa_wlan_msg_ex)+ event_ex_o.num_of_attribs * sizeof(ipa_wlan_hdr_attrib_val);
			IPACMDBG_H("num_of_attribs %d, length %d\n", event_ex_o.num_of_attribs, length);
			event_ex = (ipa_wlan_msg_ex *)malloc(length);
			if(event_ex == NULL )
			{
				IPACMERR("Unable to allocate memory\n");
				return NULL;
			}
			memcpy(event_ex, buffer + sizeof(struct ipa_msg_meta), length);
			data_ex = (ipacm_event_data_wlan_ex *)malloc(sizeof(ipacm_event_data_wlan_ex) + event_ex_o.num_of_attribs * sizeof(ipa_wlan_hdr_attrib_val));
		    if (data_ex == NULL)
		    {
				IPACMERR("unable to allocate memory for event data\n");
		    	return NULL;
		    }
			data_ex->num_of_attribs = event_ex->num_of_attribs;

			memcpy(data_ex->attribs,
						event_ex->attribs,
						event_ex->num_of_attribs * sizeof(ipa_wlan_hdr_attrib_val));

			ipa_get_if_index(event_ex->name, &(data_ex->if_index));
			evt_data.event = IPA_WLAN_CLIENT_ADD_EVENT_EX;
			evt_data.evt_data = data_ex;

			/* Construct new_neighbor msg with netdev device internally */
			new_neigh_data = (ipacm_event_data_all*)malloc(sizeof(ipacm_event_data_all));
			if(new_neigh_data == NULL)
			{
				IPACMERR("Failed to allocate memory.\n");
				return NULL;
			}
			memset(new_neigh_data, 0, sizeof(ipacm_event_data_all));
			strlcpy(new_neigh_data->iface_name, event_ex->name, sizeof(new_neigh_data->iface_name));
			new_neigh_data->iptype = IPA_IP_v6;
			for(cnt = 0; cnt < event_ex->num_of_attribs; cnt++)
			{
				if(event_ex->attribs[cnt].attrib_type == WLAN_HDR_ATTRIB_MAC_ADDR)
				{
					memcpy(new_neigh_data->mac_addr, event_ex->attribs[cnt].u.mac_addr, sizeof(new_neigh_data->mac_addr));
					IPACMDBG_H("Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n",
								 event_ex->attribs[cnt].u.mac_addr[0], event_ex->attribs[cnt].u.mac_addr[1], event_ex->attribs[cnt].u.mac_addr[2],
								 event_ex->attribs[cnt].u.mac_addr[3], event_ex->attribs[cnt].u.mac_addr[4], event_ex->attribs[cnt].u.mac_addr[5]);
				}
				else if(event_ex->attribs[cnt].attrib_type == WLAN_HDR_ATTRIB_STA_ID)
				{
					IPACMDBG_H("Wlan client id %d\n",event_ex->attribs[cnt].u.sta_id);
				}
				else
				{
					IPACMDBG_H("Wlan message has unexpected type!\n");
				}
			}
			new_neigh_data->if_index = data_ex->if_index;
			new_neigh_evt.evt_data = (void*)new_neigh_data;
			new_neigh_evt.event = IPA_NEW_NEIGH_EVENT;
			free(event_ex);
			break;

		case WLAN_CLIENT_DISCONNECT:
			IPACMDBG_H("Received WLAN_CLIENT_DISCONNECT\n");
			event_wlan = (struct ipa_wlan_msg *)(buffer + sizeof(struct ipa_msg_meta));
			IPACMDBG_H("Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n",
							 event_wlan->mac_addr[0], event_wlan->mac_addr[1], event_wlan->mac_addr[2],
							 event_wlan->mac_addr[3], event_wlan->mac_addr[4], event_wlan->mac_addr[5]);
			data = (ipacm_event_data_mac *)malloc(sizeof(ipacm_event_data_mac));
			if (data == NULL)
			{
				IPACMERR("unable to allocate memory for event_wlan data\n");
				goto done;
			}
			if(IPACM_FAILURE == ipa_get_if_index(event_wlan->name, &(data->if_index)))
			{
				data->if_index = event_wlan->if_index;
				IPACMDBG_H("Using WLAN_CLIENT_DISCONNECT if_index: %d\n",event_wlan->if_index);
			}

			memcpy(data->mac_addr, event_wlan->mac_addr, sizeof(event_wlan->mac_addr));
			evt_data.event = IPA_WLAN_CLIENT_DEL_EVENT;
			evt_data.evt_data = data;
			break;

		case WLAN_CLIENT_POWER_SAVE_MODE:
			IPACMDBG_H("Received WLAN_CLIENT_POWER_SAVE_MODE\n");
			event_wlan = (struct ipa_wlan_msg *)(buffer + sizeof(struct ipa_msg_meta));
			IPACMDBG_H("Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n",
							 event_wlan->mac_addr[0], event_wlan->mac_addr[1], event_wlan->mac_addr[2],
							 event_wlan->mac_addr[3], event_wlan->mac_addr[4], event_wlan->mac_addr[5]);
		        data = (ipacm_event_data_mac *)malloc(sizeof(ipacm_event_data_mac));
		        if (data == NULL)
		        {
		    	        IPACMERR("unable to allocate memory for event_wlan data\n");
		    	        return NULL;
		        }
			memcpy(data->mac_addr,
						 event_wlan->mac_addr,
						 sizeof(event_wlan->mac_addr));
			ipa_get_if_index(event_wlan->name, &(data->if_index));
			evt_data.event = IPA_WLAN_CLIENT_POWER_SAVE_EVENT;
			evt_data.evt_data = data;
			break;

		case WLAN_CLIENT_NORMAL_MODE:
			IPACMDBG_H("Received WLAN_CLIENT_NORMAL_MODE\n");
			event_wlan = (struct ipa_wlan_msg *)(buffer + sizeof(struct ipa_msg_meta));
			IPACMDBG_H("Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n",
							 event_wlan->mac_addr[0], event_wlan->mac_addr[1], event_wlan->mac_addr[2],
							 event_wlan->mac_addr[3], event_wlan->mac_addr[4], event_wlan->mac_addr[5]);
		        data = (ipacm_event_data_mac *)malloc(sizeof(ipacm_event_data_mac));
		        if (data == NULL)
		        {
		    	       IPACMERR("unable to allocate memory for event_wlan data\n");
		    	       return NULL;
		        }
			memcpy(data->mac_addr,
						 event_wlan->mac_addr,
						 sizeof(event_wlan->mac_addr));
			ipa_get_if_index(event_wlan->name, &(data->if_index));
			evt_data.evt_data = data;
			evt_data.event = IPA_WLAN_CLIENT_RECOVER_EVENT;
			break;

		case ECM_CONNECT:
			memcpy(&event_ecm, buffer + sizeof(struct ipa_msg_meta), sizeof(struct ipa_ecm_msg));
			IPACMDBG_H("Received ECM_CONNECT name: %s, ifindex: %d\n", event_ecm.name, event_ecm.ifindex);
			data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
			if(data_fid == NULL)
			{
				IPACMERR("unable to allocate memory for event_ecm data_fid\n");
				return NULL;
			}
			if (IPACM_Iface::ipa_get_if_index(event_ecm.name, &currentIfaceIndex) == IPACM_SUCCESS)
			{
				IPACMDBG_H("Notifing ifindex: %d\n", currentIfaceIndex);
				data_fid->if_index = currentIfaceIndex;
			}
			else
			{
				data_fid->if_index = event_ecm.ifindex;
			}
			evt_data.event = IPA_USB_LINK_UP_EVENT;
			evt_data.evt_data = data_fid;
			break;

		case ECM_DISCONNECT:
			memcpy(&event_ecm, buffer + sizeof(struct ipa_msg_meta), sizeof(struct ipa_ecm_msg));
			IPACMDBG_H("Received ECM_DISCONNECT name: %s\n",event_ecm.name);
			data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
			if(data_fid == NULL)
			{
				IPACMERR("unable to allocate memory for event_ecm data_fid\n");
				return NULL;
			}
			if (IPACM_Iface::ipa_get_if_index(event_ecm.name, &currentIfaceIndex) == IPACM_SUCCESS)
			{
				IPACMDBG_H("Notifing ifindex: %d\n", currentIfaceIndex);
				data_fid->if_index = currentIfaceIndex;
			}
			else
			{
				data_fid->if_index = event_ecm.ifindex;
			}
			evt_data.event = IPA_LINK_DOWN_EVENT;
			evt_data.evt_data = data_fid;
			break;

#ifdef FEATURE_IPACM_RESTART
		case IPA_DONE_RESTORE_EVENT:
			IPACMDBG_H("Received IPA_DONE_RESTORE_EVENT\n");
			fp = fopen(IPA_READY_QCMAP_NOTIFIER_FILE, "w");
			if (fp == NULL)
			{
				IPACMERR("can't open IPA ready monitor file\n");
				break;
			}
			fputs("IPA event restore done", fp);
			fclose(fp);
			continue;
#endif
		/* Add for 8994 Android case */
		case WAN_UPSTREAM_ROUTE_ADD:
			memcpy(&event_wan, buffer + sizeof(struct ipa_msg_meta), sizeof(struct ipa_wan_msg));
			IPACMDBG_H("Received WAN_UPSTREAM_ROUTE_ADD name: %s, tethered name: %s\n", event_wan.upstream_ifname, event_wan.tethered_ifname);
			data_iptype = (ipacm_event_data_iptype *)malloc(sizeof(ipacm_event_data_iptype));
			if(data_iptype == NULL)
			{
				IPACMERR("unable to allocate memory for event_ecm data_iptype\n");
				return NULL;
			}
			ipa_get_if_index(event_wan.upstream_ifname, &(data_iptype->if_index));
			ipa_get_if_index(event_wan.tethered_ifname, &(data_iptype->if_index_tether));
			data_iptype->iptype = event_wan.ip;
			IPACMDBG_H("Received WAN_UPSTREAM_ROUTE_ADD: fid(%d) tether_fid(%d) ip-type(%d)\n", data_iptype->if_index,
					data_iptype->if_index_tether, data_iptype->iptype);
			evt_data.event = IPA_WAN_UPSTREAM_ROUTE_ADD_EVENT;
			evt_data.evt_data = data_iptype;
			break;
		case WAN_UPSTREAM_ROUTE_DEL:
			memcpy(&event_wan, buffer + sizeof(struct ipa_msg_meta), sizeof(struct ipa_wan_msg));
			IPACMDBG_H("Received WAN_UPSTREAM_ROUTE_DEL name: %s, tethered name: %s\n", event_wan.upstream_ifname, event_wan.tethered_ifname);
			data_iptype = (ipacm_event_data_iptype *)malloc(sizeof(ipacm_event_data_iptype));
			if(data_iptype == NULL)
			{
				IPACMERR("unable to allocate memory for event_ecm data_iptype\n");
				return NULL;
			}
			ipa_get_if_index(event_wan.upstream_ifname, &(data_iptype->if_index));
			ipa_get_if_index(event_wan.tethered_ifname, &(data_iptype->if_index_tether));
			data_iptype->iptype = event_wan.ip;
			IPACMDBG_H("Received WAN_UPSTREAM_ROUTE_DEL: fid(%d) ip-type(%d)\n", data_iptype->if_index, data_iptype->iptype);
			evt_data.event = IPA_WAN_UPSTREAM_ROUTE_DEL_EVENT;
			evt_data.evt_data = data_iptype;
			break;
		/* End of adding for 8994 Android case */

		/* Add for embms case */
		case WAN_EMBMS_CONNECT:
			memcpy(&event_wan, buffer + sizeof(struct ipa_msg_meta), sizeof(struct ipa_wan_msg));
			IPACMDBG("Received WAN_EMBMS_CONNECT name: %s\n",event_wan.upstream_ifname);
			data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
			if(data_fid == NULL)
			{
				IPACMERR("unable to allocate memory for event data_fid\n");
				return NULL;
			}
			ipa_get_if_index(event_wan.upstream_ifname, &(data_fid->if_index));
			evt_data.event = IPA_WAN_EMBMS_LINK_UP_EVENT;
			evt_data.evt_data = data_fid;
			break;

		case WLAN_SWITCH_TO_SCC:
			IPACMDBG_H("Received WLAN_SWITCH_TO_SCC\n");
		case WLAN_WDI_ENABLE:
			IPACMDBG_H("Received WLAN_WDI_ENABLE\n");
			if (IPACM_Iface::ipacmcfg->isMCC_Mode == true)
			{
				IPACM_Iface::ipacmcfg->isMCC_Mode = false;
				evt_data.event = IPA_WLAN_SWITCH_TO_SCC;
				break;
			}
			continue;
		case WLAN_SWITCH_TO_MCC:
			IPACMDBG_H("Received WLAN_SWITCH_TO_MCC\n");
		case WLAN_WDI_DISABLE:
			IPACMDBG_H("Received WLAN_WDI_DISABLE\n");
			if (IPACM_Iface::ipacmcfg->isMCC_Mode == false)
			{
				IPACM_Iface::ipacmcfg->isMCC_Mode = true;
				evt_data.event = IPA_WLAN_SWITCH_TO_MCC;
				break;
			}
			continue;

		case WAN_XLAT_CONNECT:
			memcpy(&event_wan, buffer + sizeof(struct ipa_msg_meta),
				sizeof(struct ipa_wan_msg));
			IPACMDBG_H("Received WAN_XLAT_CONNECT name: %s\n",
					event_wan.upstream_ifname);

			/* post IPA_LINK_UP_EVENT event
			 * may be WAN interface is not up
			*/
			data_fid = (ipacm_event_data_fid *)calloc(1, sizeof(ipacm_event_data_fid));
			if(data_fid == NULL)
			{
				IPACMERR("unable to allocate memory for xlat event\n");
				return NULL;
			}
			ipa_get_if_index(event_wan.upstream_ifname, &(data_fid->if_index));
			evt_data.event = IPA_LINK_UP_EVENT;
			evt_data.evt_data = data_fid;
			IPACMDBG_H("Posting IPA_LINK_UP_EVENT event:%d\n", evt_data.event);
			IPACM_EvtDispatcher::PostEvt(&evt_data);

			/* post IPA_WAN_XLAT_CONNECT_EVENT event */
			memset(&evt_data, 0, sizeof(evt_data));
			data_fid = (ipacm_event_data_fid *)calloc(1, sizeof(ipacm_event_data_fid));
			if(data_fid == NULL)
			{
				IPACMERR("unable to allocate memory for xlat event\n");
				return NULL;
			}
			ipa_get_if_index(event_wan.upstream_ifname, &(data_fid->if_index));
			evt_data.event = IPA_WAN_XLAT_CONNECT_EVENT;
			evt_data.evt_data = data_fid;
			IPACMDBG_H("Posting IPA_WAN_XLAT_CONNECT_EVENT event:%d\n", evt_data.event);
			break;

		case IPA_TETHERING_STATS_UPDATE_STATS:
			memcpy(&event_data_stats, buffer + sizeof(struct ipa_msg_meta), sizeof(struct ipa_get_data_stats_resp_msg_v01));
			data_tethering_stats = (ipa_get_data_stats_resp_msg_v01 *)malloc(sizeof(struct ipa_get_data_stats_resp_msg_v01));
			if(data_tethering_stats == NULL)
			{
				IPACMERR("unable to allocate memory for event data_tethering_stats\n");
				return NULL;
			}
			memcpy(data_tethering_stats,
					 &event_data_stats,
						 sizeof(struct ipa_get_data_stats_resp_msg_v01));
			IPACMDBG("Received IPA_TETHERING_STATS_UPDATE_STATS ipa_stats_type: %d\n",data_tethering_stats->ipa_stats_type);
			IPACMDBG("Received %d UL, %d DL pipe stats\n",data_tethering_stats->ul_src_pipe_stats_list_len, data_tethering_stats->dl_dst_pipe_stats_list_len);
			evt_data.event = IPA_TETHERING_STATS_UPDATE_EVENT;
			evt_data.evt_data = data_tethering_stats;
			break;

		case IPA_TETHERING_STATS_UPDATE_NETWORK_STATS:
			memcpy(&event_network_stats, buffer + sizeof(struct ipa_msg_meta), sizeof(struct ipa_get_apn_data_stats_resp_msg_v01));
			data_network_stats = (ipa_get_apn_data_stats_resp_msg_v01 *)malloc(sizeof(ipa_get_apn_data_stats_resp_msg_v01));
			if(data_network_stats == NULL)
			{
				IPACMERR("unable to allocate memory for event data_network_stats\n");
				return NULL;
			}
			memcpy(data_network_stats,
					 &event_network_stats,
						 sizeof(struct ipa_get_apn_data_stats_resp_msg_v01));
			IPACMDBG("Received %d apn network stats \n", data_network_stats->apn_data_stats_list_len);
			evt_data.event = IPA_NETWORK_STATS_UPDATE_EVENT;
			evt_data.evt_data = data_network_stats;
			break;
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
		case IPA_PER_CLIENT_STATS_CONNECT_EVENT:
			IPACMDBG_H("Received IPA_PER_CLIENT_STATS_CONNECT_EVENT\n");
			memcpy(&event_lan_client, buffer + sizeof(struct ipa_msg_meta), sizeof(struct ipa_lan_client_msg));
			data = (ipacm_event_data_mac *)malloc(sizeof(ipacm_event_data_mac));
			if(data == NULL)
			{
				IPACMERR("unable to allocate memory for event data\n");
				return NULL;
			}
			memcpy(data->mac_addr,
						 event_lan_client.mac,
						 sizeof(event_lan_client.mac));
			ipa_get_if_index(event_lan_client.lanIface, &(data->if_index));
			IPACM_Iface::ipacmcfg->stats_client_info(data->mac_addr, true);
			evt_data.event = IPA_LAN_CLIENT_CONNECT_EVENT;
			evt_data.evt_data = data;
			break;

		case IPA_PER_CLIENT_STATS_DISCONNECT_EVENT:
			IPACMDBG_H("Received IPA_PER_CLIENT_STATS_DISCONNECT_EVENT\n");
			memcpy(&event_lan_client, buffer + sizeof(struct ipa_msg_meta), sizeof(struct ipa_lan_client_msg));
			data = (ipacm_event_data_mac *)malloc(sizeof(ipacm_event_data_mac));
			if(data == NULL)
			{
				IPACMERR("unable to allocate memory for event data\n");
				return NULL;
			}
			memcpy(data->mac_addr,
						 event_lan_client.mac,
						 sizeof(event_lan_client.mac));
			ipa_get_if_index(event_lan_client.lanIface, &(data->if_index));
			IPACM_Iface::ipacmcfg->stats_client_info(data->mac_addr, false);
			evt_data.event = IPA_LAN_CLIENT_DISCONNECT_EVENT;
			evt_data.evt_data = data;
			break;
#endif
#if defined(FEATURE_SOCKSv5) && defined(IPA_SOCKV5_EVENT_MAX)
		case IPA_SOCKV5_ADD:
			/* enable socksv5 */
			IPACM_Iface::ipacmcfg->ipacm_socksv5_enable = TRUE;
			IPACM_Iface::ipacmcfg->ipa_ipv6ct_max_entries = 500;

			IPACMDBG_H("Received IPA_SOCKV5_ADD (%d) \n", IPACM_Iface::ipacmcfg->ipacm_socksv5_enable);
			memcpy(&add_socksv5_info, buffer + sizeof(struct ipa_msg_meta), sizeof(add_socksv5_info));

			if (add_socksv5_info.ul_in.ip_type == IPA_IP_v4)
			{
				IPACMERR("not support inner ipv4 connections \n");
				continue;
			}
			/* adjust network order */
			if (add_socksv5_info.ul_in.ip_type == IPA_IP_v6)
			{
				add_socksv5_info.ul_in.ipv6_src[0] = ntohl(add_socksv5_info.ul_in.ipv6_src[0]);
				add_socksv5_info.ul_in.ipv6_src[1] = ntohl(add_socksv5_info.ul_in.ipv6_src[1]);
				add_socksv5_info.ul_in.ipv6_src[2] = ntohl(add_socksv5_info.ul_in.ipv6_src[2]);
				add_socksv5_info.ul_in.ipv6_src[3] = ntohl(add_socksv5_info.ul_in.ipv6_src[3]);
				add_socksv5_info.ul_in.ipv6_dst[0] = ntohl(add_socksv5_info.ul_in.ipv6_dst[0]);
				add_socksv5_info.ul_in.ipv6_dst[1] = ntohl(add_socksv5_info.ul_in.ipv6_dst[1]);
				add_socksv5_info.ul_in.ipv6_dst[2] = ntohl(add_socksv5_info.ul_in.ipv6_dst[2]);
				add_socksv5_info.ul_in.ipv6_dst[3] = ntohl(add_socksv5_info.ul_in.ipv6_dst[3]);
			}
			if (add_socksv5_info.dl_in.ip_type == IPA_IP_v6)
			{
				add_socksv5_info.dl_in.ipv6_src[0] = ntohl(add_socksv5_info.dl_in.ipv6_src[0]);
				add_socksv5_info.dl_in.ipv6_src[1] = ntohl(add_socksv5_info.dl_in.ipv6_src[1]);
				add_socksv5_info.dl_in.ipv6_src[2] = ntohl(add_socksv5_info.dl_in.ipv6_src[2]);
				add_socksv5_info.dl_in.ipv6_src[3] = ntohl(add_socksv5_info.dl_in.ipv6_src[3]);
				add_socksv5_info.dl_in.ipv6_dst[0] = ntohl(add_socksv5_info.dl_in.ipv6_dst[0]);
				add_socksv5_info.dl_in.ipv6_dst[1] = ntohl(add_socksv5_info.dl_in.ipv6_dst[1]);
				add_socksv5_info.dl_in.ipv6_dst[2] = ntohl(add_socksv5_info.dl_in.ipv6_dst[2]);
				add_socksv5_info.dl_in.ipv6_dst[3] = ntohl(add_socksv5_info.dl_in.ipv6_dst[3]);
			}
			else if(add_socksv5_info.dl_in.ip_type == IPA_IP_v4)
			{
				add_socksv5_info.dl_in.ipv4_src = ntohl(add_socksv5_info.dl_in.ipv4_src);
				add_socksv5_info.dl_in.ipv4_dst = ntohl(add_socksv5_info.dl_in.ipv4_dst);
				IPACMDBG("dst_ipv4 addr:0x%x src_ipv4 addr:0x%x\n",
					add_socksv5_info.dl_in.ipv4_dst,
					add_socksv5_info.dl_in.ipv4_src);
			}

			if (IPACM_Iface::ipacmcfg->socksv5_conn.size() == 0)
			{
				IPACMDBG_H("socksv5_conn size %d \n", IPACM_Iface::ipacmcfg->socksv5_conn.size());
				IPACMDBG_H("src_ipv6 addr:0x%x:%x:%x:%x\n",
					add_socksv5_info.ul_in.ipv6_src[0],
					add_socksv5_info.ul_in.ipv6_src[1],
					add_socksv5_info.ul_in.ipv6_src[2],
					add_socksv5_info.ul_in.ipv6_src[3]);
				IPACMDBG_H("dst_ipv6 addr:0x%x:%x:%x:%x\n",
					add_socksv5_info.ul_in.ipv6_dst[0],
					add_socksv5_info.ul_in.ipv6_dst[1],
					add_socksv5_info.ul_in.ipv6_dst[2],
					add_socksv5_info.ul_in.ipv6_dst[3]);
				/* update client ipv6 */
				IPACM_Iface::ipacmcfg->update_socksv5_client_v6_addr(add_socksv5_info.ul_in.ipv6_src);
				IPACMDBG_H("socksv5_conn size %d \n", IPACM_Iface::ipacmcfg->socksv5_conn.size());

				sock_up_event_data = (ipa_socksv5_msg *)malloc(sizeof(ipa_socksv5_msg));
				if(sock_up_event_data == NULL)
				{
					IPACMERR("unable to allocate memory for event_wlan data_event_conn\n");
					return NULL;
				}
				memcpy(sock_up_event_data, &add_socksv5_info, sizeof(ipa_socksv5_msg));
				evt_data.event = IPA_HANDLE_SOCKSv5_UP;
				evt_data.evt_data = sock_up_event_data;
				/* finish command queue */
				IPACMDBG_H("Posting IPA_HANDLE_SOCKSv5_UP event:%d\n", evt_data.event);
				IPACM_EvtDispatcher::PostEvt(&evt_data);
			}
				IPACMDBG_H("socksv5_conn size %d \n", IPACM_Iface::ipacmcfg->socksv5_conn.size());
				IPACM_Iface::ipacmcfg->add_socksv5_conn(&add_socksv5_info);
			continue;

		case IPA_SOCKV5_DEL:
			IPACMDBG_H("Received IPA_SOCKV5_DEL \n");
			memcpy(&del_socksv5_info, buffer + sizeof(struct ipa_msg_meta), sizeof(del_socksv5_info));
			IPACM_Iface::ipacmcfg->del_socksv5_conn(&del_socksv5_info);

			if (IPACM_Iface::ipacmcfg->socksv5_conn.size() == 0)
			{
				IPACM_Iface::ipacmcfg->ipacm_socksv5_enable = false;
				evt_data.event = IPA_HANDLE_SOCKSv5_DOWN;
				evt_data.evt_data = NULL;
				break;
			}
			else
			{
				IPACMDBG_H("socksv5_conn size %d \n", IPACM_Iface::ipacmcfg->socksv5_conn.size());
				continue;
			}
#endif //defined(FEATURE_SOCKSv5) && defined(IPA_SOCKV5_EVENT_MAX)
		case IPA_GSB_CONNECT:
			event_gsb = (ipa_ioc_gsb_info *) (buffer + sizeof(struct ipa_msg_meta));
			IPACMDBG_H("Received IPA_GSB_CONNECT name: %s\n",event_gsb->name);
            		data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
			if(data_fid == NULL)
			{
				IPACMERR("unable to allocate memory for event_gsb\n");
				return NULL;
			}
			ipa_get_if_index(event_gsb->name, &(data_fid->if_index));
			evt_data.event = IPA_USB_LINK_UP_EVENT;
			evt_data.evt_data = data_fid;
			break;

		case IPA_GSB_DISCONNECT:
			event_gsb = (ipa_ioc_gsb_info *)(buffer + sizeof(struct ipa_msg_meta));
			IPACMDBG_H("Received IPA_GSB_DISCONNECT name: %s\n",event_gsb->name);
			data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
			if(data_fid == NULL)
			{
				IPACMERR("unable to allocate memory for event_gsb\n");
				return NULL;
			}
			ipa_get_if_index(event_gsb->name, &(data_fid->if_index));
			evt_data.event = IPA_LINK_DOWN_EVENT;
			evt_data.evt_data = data_fid;
			break;

#ifdef IPA_IOCTL_ADD_VLAN_PRIORITY
		case IPA_VLAN_PRIORITY_UPDATE_EVENT:
			vlan_prio_evt = (struct ipa_ioc_vlan_priority *)(buffer + sizeof(struct ipa_msg_meta));
			if(IPACM_Iface::ipacmcfg->update_vlan_priority(vlan_prio_evt)) {
				IPACMERR("Update vlan prirority failed\n");
			}
			IPACMDBG_H("Updated vlan priority successfully!\n");
			continue;
#endif

		case IPA_PDN_IP_PASSTHROUGH_MODE_CONFIG:
			pdn_info = (ipa_ioc_pdn_config *)(buffer + sizeof(struct ipa_msg_meta));
			IPACMDBG_H("Received IPA_PDN_IP_PASSTHROUGH_MODE_CONFIG name: %s, default_pdn: %d, type: %d, enable: %d, VLAN ID: %d, Nat config: %d and PDN IP: 0x%x!\n",
				pdn_info->dev_name, pdn_info->default_pdn, pdn_info->pdn_cfg_type, pdn_info->enable, pdn_info->u.passthrough_cfg.vlan_id,
				pdn_info->u.passthrough_cfg.skip_nat, htonl(pdn_info->u.passthrough_cfg.pdn_ip_addr));
			IPACMDBG_H("Received mac_addr MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
							 pdn_info->u.passthrough_cfg.client_mac_addr[0],
							 pdn_info->u.passthrough_cfg.client_mac_addr[1],
							 pdn_info->u.passthrough_cfg.client_mac_addr[2],
							 pdn_info->u.passthrough_cfg.client_mac_addr[3],
							 pdn_info->u.passthrough_cfg.client_mac_addr[4],
							 pdn_info->u.passthrough_cfg.client_mac_addr[5]);

			/* Update IP Passthrough config. */
			IPACM_Iface::ipacmcfg->ip_pass_config_update(pdn_info);
			evt_data.event = IPA_IP_PASS_UPDATE_EVENT;
			ip_pass_pdn_data = (ipacm_event_ip_pass_pdn_info *)malloc(sizeof(ipacm_event_ip_pass_pdn_info));
			if(!ip_pass_pdn_data)
			{
				IPACMERR("unable to allocate memory for pdn_config\n");
				return NULL;
			}
			ip_pass_pdn_data->skip_nat = pdn_info->u.passthrough_cfg.skip_nat;
			ip_pass_pdn_data->pdn_ip_addr = htonl(pdn_info->u.passthrough_cfg.pdn_ip_addr);
			ip_pass_pdn_data->VlanID = pdn_info->u.passthrough_cfg.vlan_id;
			ip_pass_pdn_data->enable = pdn_info->enable;
			evt_data.evt_data = ip_pass_pdn_data;
			ipa_get_if_index(pdn_info->dev_name, &(ip_pass_pdn_data->if_index));
			break;

		default:
			IPACMDBG_H("Unhandled message type: %d\n", event_hdr.msg_type);
			continue;

		}
		/* finish command queue */
		IPACMDBG_H("Posting event:%d\n", evt_data.event);
		IPACM_EvtDispatcher::PostEvt(&evt_data);
		/* push new_neighbor with netdev device internally */
		if(new_neigh_data != NULL)
		{
			IPACMDBG_H("Internally post event IPA_NEW_NEIGH_EVENT\n");
			IPACM_EvtDispatcher::PostEvt(&new_neigh_evt);
		}
	}
done:
	(void)close(fd);
	return NULL;
}

void RegisterForSignals(bool default_handler);

#define MAX_IPACM_TRACE_STACK 40

static void IPACM_Signals_handler(int sig, siginfo_t *info, void *extra)
{
	ipacm_cmd_q_data evt_data;
	ucontext_t *p;
	int addr;
	void *array[MAX_IPACM_TRACE_STACK];
	int size, i;
	char **messages;

	IPACMERR("Received Signal: %d %s\n", sig, strsignal(sig));
	memset(&evt_data, 0, sizeof(evt_data));

	switch(sig)
	{
	case SIGUSR1:
		IPACMDBG_H("Received SW_ROUTING_ENABLE request \n");
		evt_data.event = IPA_SW_ROUTING_ENABLE;
		IPACM_Iface::ipacmcfg->ipa_sw_rt_enable = true;
		break;
	case SIGUSR2:
		IPACMDBG_H("Received SW_ROUTING_DISABLE request \n");
		evt_data.event = IPA_SW_ROUTING_DISABLE;
		IPACM_Iface::ipacmcfg->ipa_sw_rt_enable = false;
		break;
	case SIGFPE:
	case SIGSEGV:
	case SIGILL:
	case SIGBUS:
	case SIGABRT:
	case SIGTERM:
		p = (ucontext_t *)extra;
		IPACMERR("siginfo address=%x\n", info->si_addr);
		IPACMERR("arm_pc address = 0x%X\n", p->uc_mcontext.pc);
		IPACMERR("pstate = 0x%X\n", p->uc_mcontext.pstate);
		IPACMERR("fault address = 0x%X\n", p->uc_mcontext.fault_address);
		IPACMERR("arm_sp address = 0x%X\n", p->uc_mcontext.sp);
		IPACMERR("arm_lr address = 0x%X\n", p->uc_mcontext.regs[30]);
		IPACMERR("arm_r0  address = 0x%X\n", p->uc_mcontext.regs[0]);
		size = backtrace(array, MAX_IPACM_TRACE_STACK);

		messages = backtrace_symbols(array, size);

		/* skip first stack frame (points here) */
		IPACMERR("crash stack:\n");
		for(i = 1; i < size && messages != NULL; ++i)
		{
			IPACMERR("[bt]: (%d) %s\n", i, messages[i]);
		}
		IPACMERR("return to default signal handler\n");

		/* make sure buffer is printed to stodut before we crash */
		fflush(stdout);

		free(messages);

		/* got regular kill <PID>, kill -9 <PID> generates SIGKILL that cannot be handled by a signal handler */
		if(sig == SIGTERM)
		{
			IPACMERR("IPACM gracefully requested to quit by PID %d, complying\n", info->si_pid);
			exit(-1);
		}

		/* restore to default signal handler so core dump is generated from original fault point */
		RegisterForSignals(true);
		return;
		break;
	default:
		IPACMERR("unknown signal %d\n", sig);
		/* restore to default signal handler so core dump is generated from original fault point */
		RegisterForSignals(true);
		return;
	}

	/* finish command queue */
	IPACMDBG_H("Posting event:%d\n", evt_data.event);
	IPACM_EvtDispatcher::PostEvt(&evt_data);
	return;
}

void RegisterForSignals(bool default_handler)
{
	struct sigaction action = {};

	printf("register signal handlers\n");

	action.sa_flags = SA_SIGINFO;
	if(default_handler)
		action.sa_handler = SIG_DFL;
	else
		action.sa_sigaction = IPACM_Signals_handler;

	if(sigaction(SIGFPE, &action, NULL) == -1) {
		printf("couldn't register for SIGFPE\n");
	}
	if(sigaction(SIGSEGV, &action, NULL) == -1) {
		printf("couldn't register for SIGSEGV\n");
	}
	if(sigaction(SIGILL, &action, NULL) == -1) {
		printf("couldn't register for SIGILL\n");
	}
	if(sigaction(SIGBUS, &action, NULL) == -1) {
		printf("couldn't register for SIGBUS\n");
	}
	if(sigaction(SIGTERM, &action, NULL) == -1) {
		printf("couldn't register for SIGTERM\n");
	}
	if(sigaction(SIGABRT, &action, NULL) == -1) {
		printf("couldn't register for SIGABRT\n");
	}
	if(sigaction(SIGUSR1, &action, NULL) == -1) {
		printf("couldn't register for SIGUSR1\n");
	}
	if(sigaction(SIGUSR2, &action, NULL) == -1) {
		printf("couldn't register for SIGUSR2\n");
	}
}

void *l2tp_process(void *param)
{
	return l2tp_nl_process(param);
}

int main(int argc, char **argv)
{
	int ret;

#ifdef FEATURE_IPACM_RESTART
	FILE *fp = NULL;
#endif

	pthread_t netlink_thread = 0, monitor_thread = 0, ipa_driver_thread = 0;
	pthread_t cmd_queue_thread = 0;
	pthread_t l2tp_thread = 0;

	/* check if ipacm is already running or not */
	ipa_is_ipacm_running();
	IPACMDBG_H("In main()\n");

#ifdef FEATURE_IPACM_RESTART
	fp = fopen(IPA_READY_QCMAP_NOTIFIER_FILE, "w");
	if (fp == NULL)
	{
		IPACMERR("can't open ipa ready monitor file\n");
		return IPACM_FAILURE;
	}
	fputs("IPACM started", fp);
	fclose(fp);

	IPACMDBG_H("RESET IPA-HW rules\n");
	ipa_reset();
#endif

#ifdef IPA_HW_FNR_STATS
	IPACM_Iface::ipacmcfg->alloc_fnr_counter();
	IPACMDBG_H("Reallocation FNR Counter: Done\n");
#endif

	IPACM_IfaceManager *ifacemgr = new IPACM_IfaceManager();
	neigh = new IPACM_Neighbor();

#ifdef FEATURE_ETH_BRIDGE_LE
	IPACM_LanToLan* lan2lan = IPACM_LanToLan::get_instance();
#endif

#ifdef FEATURE_IPACM_RESTART
	ipa_query_driver_event();
#endif

	IPACM_ConntrackClient *cc = IPACM_ConntrackClient::GetInstance();
	CtList = new IPACM_ConntrackListener();

	/* Query bridge FDB to populate neighbor cache and create interfaces if missed any*/

	IPACMDBG_H("Staring IPA main\n");
	IPACMDBG_H("ipa_cmdq_successful\n");

#ifdef DATA_CONFIG_DIR_PATH
	IPACMDBG_H("using DATA_CONFIG_DIR_PATH %s\n", DATA_CONFIG_DIR_PATH);
#endif

	RegisterForSignals(false);

	if (IPACM_SUCCESS == cmd_queue_thread)
	{
		ret = pthread_create(&cmd_queue_thread, NULL, MessageQueue::Process, NULL);
		if (IPACM_SUCCESS != ret)
		{
			IPACMERR("unable to command queue thread\n");
			return ret;
		}
		IPACMDBG_H("created command queue thread\n");
		if(pthread_setname_np(cmd_queue_thread, "cmd queue process") != 0)
		{
			IPACMERR("unable to set thread name\n");
		}
	}

	if (IPACM_SUCCESS == netlink_thread)
	{
		ret = pthread_create(&netlink_thread, NULL, netlink_start, NULL);
		if (IPACM_SUCCESS != ret)
		{
			IPACMERR("unable to create netlink thread\n");
			return ret;
		}
		IPACMDBG_H("created netlink thread\n");
		if(pthread_setname_np(netlink_thread, "netlink socket") != 0)
		{
			IPACMERR("unable to set thread name\n");
		}
	}

	/* Enable Firewall support only on MDM targets */
#ifndef FEATURE_IPA_ANDROID
	if (IPACM_SUCCESS == monitor_thread)
	{
		ret = pthread_create(&monitor_thread, NULL, firewall_monitor, NULL);
		if (IPACM_SUCCESS != ret)
		{
			IPACMERR("unable to create monitor thread\n");
			return ret;
		}
		IPACMDBG_H("created firewall monitor thread\n");
		if(pthread_setname_np(monitor_thread, "firewall cfg process") != 0)
		{
			IPACMERR("unable to set thread name\n");
		}
	}
#endif

	if (IPACM_SUCCESS == ipa_driver_thread)
	{
		ret = pthread_create(&ipa_driver_thread, NULL, ipa_driver_msg_notifier, NULL);
		if (IPACM_SUCCESS != ret)
		{
			IPACMERR("unable to create ipa_driver_wlan thread\n");
			return ret;
		}
		IPACMDBG_H("created ipa_driver_wlan thread\n");
		if(pthread_setname_np(ipa_driver_thread, "ipa driver ntfy") != 0)
		{
			IPACMERR("unable to set thread name\n");
		}
	}

	neigh->update_neigh_cache();

	if (IPACM_SUCCESS == l2tp_thread)
	{
		ret = pthread_create(&l2tp_thread, NULL, l2tp_process, NULL);
		if (IPACM_SUCCESS != ret)
		{
			IPACMERR("unable to start l2tp_thread\n");
			return ret;
		}
		IPACMDBG_H("l2tp_thread created\n");
		if(pthread_setname_np(cmd_queue_thread, "l2tp_thread") != 0)
		{
			IPACMERR("unable to set thread name for l2tp_thrad\n");
		}
	}

	/* Create Conntrack listener threads here to support on-demand PDNs connections before WAN is up */
	CtList->CreateConnTrackThreads();

	pthread_join(cmd_queue_thread, NULL);
	pthread_join(netlink_thread, NULL);
	pthread_join(monitor_thread, NULL);
	pthread_join(ipa_driver_thread, NULL);
   	pthread_join(l2tp_thread, NULL);

	return IPACM_SUCCESS;
}

/*===========================================================================
		FUNCTION  ipa_is_ipacm_running
===========================================================================*/
/*!
@brief
  Determine whether there's already an IPACM process running, if so, terminate
  the current one

@return
	None

@note

- Dependencies
		- None

- Side Effects
		- None
*/
/*=========================================================================*/

void ipa_is_ipacm_running(void) {

	int fd;
	struct flock lock;
	int retval;

	fd = open(IPACM_PID_FILE, O_RDWR | O_CREAT, 0600);
	if ( fd <= 0 )
	{
		IPACMERR("Failed to open %s, error is %d - %s\n",
				 IPACM_PID_FILE, errno, strerror(errno));
		exit(0);
	}

	/*
	 * Getting an exclusive Write lock on the file, if it fails,
	 * it means that another instance of IPACM is running and it
	 * got the lock before us.
	 */
	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	retval = fcntl(fd, F_SETLK, &lock);

	if (retval != 0)
	{
		retval = fcntl(fd, F_GETLK, &lock);
		if (retval == 0)
		{
			IPACMERR("Unable to get lock on file %s (my PID %d), PID %d already has it\n",
					 IPACM_PID_FILE, getpid(), lock.l_pid);
			close(fd);
			exit(0);
		}
	}
	else
	{
		IPACMERR("PID %d is IPACM main process\n", getpid());
	}

	return;
}

/*===========================================================================
		FUNCTION  ipa_get_if_index
===========================================================================*/
/*!
@brief
  get ipa interface index by given the interface name

@return
	IPACM_SUCCESS or IPA_FALUIRE

@note

- Dependencies
		- None

- Side Effects
		- None
*/
/*=========================================================================*/
int ipa_get_if_index
(
	 char *if_name,
	 int *if_index
	 )
{
	int fd;
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		PERROR("get interface index socket create failed");
		return IPACM_FAILURE;
	}

	memset(&ifr, 0, sizeof(struct ifreq));

	(void)strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
	{
		IPACMERR("call_ioctl_on_dev: ioctl failed: can't find device %s",if_name);
		*if_index = -1;
		close(fd);
		return IPACM_FAILURE;
	}

	*if_index = ifr.ifr_ifindex;
	close(fd);
	return IPACM_SUCCESS;
}

#ifdef FEATURE_IPACM_RESTART
int ipa_reset()
{
	int fd = -1;

	if ((fd = open(IPA_DEVICE_NAME, O_RDWR)) < 0) {
		IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	if (ioctl(fd, IPA_IOC_CLEANUP) < 0) {
		IPACMERR("IOCTL IPA_IOC_CLEANUP call failed: %s \n", strerror(errno));
		close(fd);
		return IPACM_FAILURE;
	}

	IPACMDBG_H("send IPA_IOC_CLEANUP \n");
	close(fd);
	return IPACM_SUCCESS;
}

int ipa_query_driver_event()
{
	int fd = -1;

	if ((fd = open(IPA_DEVICE_NAME, O_RDWR)) < 0) {
		IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	if (ioctl(fd, IPA_IOC_QUERY_CACHED_DRIVER_MSG) < 0) {
		IPACMERR("IOCTL IPA_IOC_QUERY_CACHED_DRIVER_MSG call failed: %s \n",
			strerror(errno));
		close(fd);
		return IPACM_FAILURE;
	}

	IPACMDBG_H("send IPA_IOC_QUERY_CACHED_DRIVER_MSG \n");
	close(fd);
	return IPACM_SUCCESS;
}
#endif
