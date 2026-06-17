/*
 * Copyright (c) 2013-2020, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * Neither the name of The Linux Foundation nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
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
 * Changes from Qualcomm Technologies, Inc. are provided under the following license:
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear.
 */
/*!
	@file
	IPACM_Netlink.cpp

	@brief
	This file implements the IPAM Netlink Socket Parer functionality.

	@Author
	Skylar Chang

*/
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

#include <stdlib.h>
#include <errno.h>
#include <linux/rtnetlink.h>

#include "IPACM_CmdQueue.h"
#include "IPACM_Defs.h"
#include "IPACM_Netlink.h"
#include "IPACM_EvtDispatcher.h"
#include "IPACM_Config.h"
#include "IPACM_Iface.h"
#include "IPACM_Log.h"
#include "IPACM_Iface.h"
#include <linux/l2tp.h>
#include <sys/socket.h>

int find_mask(int ip_v4_last, int *mask_value);

#ifdef FEATURE_IPA_ANDROID

#define IPACM_NL_COPY_ADDR( event_info, element )                                        \
        memcpy( &event_info->attr_info.element.__data,                                   \
                RTA_DATA(rtah),                                                          \
                sizeof(event_info->attr_info.element.__data) );

#define IPACM_EVENT_COPY_ADDR_v6( event_data, element)                                   \
        memcpy( event_data, element.__data, sizeof(event_data));

#define IPACM_EVENT_COPY_ADDR_v4( event_data, element)                                   \
        memcpy( &event_data, element.__data, sizeof(event_data));

#define IPACM_NL_REPORT_ADDR( prefix, addr )                                             \
        if( AF_INET6 == (addr).ss_family ) {                                             \
          IPACM_LOG_IPV6_ADDR( prefix, addr.__data);                                    \
        } else {                                                                         \
          IPACM_LOG_IPV4_ADDR( prefix, (*(unsigned int*)&(addr).__data) );               \
        }

#else/* defined(FEATURE_IPA_ANDROID) */

#define IPACM_NL_COPY_ADDR( event_info, element ) \
	do { \
		memcpy( &event_info->attr_info.element.__ss_padding, RTA_DATA(rtah), sizeof(event_info->attr_info.element.__ss_padding) ); \
	} while (0)


#define IPACM_EVENT_COPY_ADDR_v6( event_data, element)                                   \
        memcpy( event_data, element.__ss_padding, sizeof(event_data));

#define IPACM_EVENT_COPY_ADDR_v4( event_data, element)                                   \
        memcpy( &event_data, element.__ss_padding, sizeof(event_data));

#define IPACM_NL_REPORT_ADDR( prefix, addr ) \
	do { \
		if( AF_INET6 == (addr).ss_family ) {       \
			IPACM_LOG_IPV6_ADDR( prefix, addr.__ss_padding); \
		} else {                                   \
		IPACM_LOG_IPV4_ADDR( prefix, (*(unsigned int*)&(addr).__ss_padding) ); \
		}                                          \
	} while (0)

#endif /* defined(FEATURE_IPA_ANDROID)*/

#define NDA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#define IPACM_LOG_IPV6_ADDR(prefix, ip_addr)                            \
        IPACMDBG_H(prefix);                                               \
		IPACMDBG_H(" IPV6 Address %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", \
                  (int)ip_addr[0],  (int)ip_addr[1],                                                        \
                  (int)ip_addr[2],  (int)ip_addr[3],                                                        \
                  (int)ip_addr[4],  (int)ip_addr[5],                                                        \
                  (int)ip_addr[6],  (int)ip_addr[7],                                                        \
                  (int)ip_addr[8],  (int)ip_addr[9],                                                        \
                  (int)ip_addr[10], (int)ip_addr[11],                                                       \
                  (int)ip_addr[12], (int)ip_addr[13],                                                       \
                  (int)ip_addr[14], (int)ip_addr[15]);

#define IPACM_LOG_IPV4_ADDR(prefix, ip_addr)                            \
        IPACMDBG_H(prefix);                                               \
        IPACMDBG_H(" IPV4 Address %d.%d.%d.%d\n",                         \
                    (unsigned char)(ip_addr),                               \
                    (unsigned char)(ip_addr >> 8),                          \
                    (unsigned char)(ip_addr >> 16) ,                        \
                    (unsigned char)(ip_addr >> 24));

/*sockfd global*/
int *p_sk_fd = NULL;

/* Opens a netlink socket*/
static int ipa_nl_open_socket
(
	 ipa_nl_sk_info_t *sk_info,
	 int protocol,
	 unsigned int grps
	 )
{
	int buf_size = 6669999, sendbuff=0, res = IPACM_SUCCESS;
	struct sockaddr_nl *p_sk_addr_loc = NULL;
	socklen_t optlen = 0;

	p_sk_fd = &(sk_info->sk_fd);
	p_sk_addr_loc = &(sk_info->sk_addr_loc);

	/* Open netlink socket for specified protocol */
	if((*p_sk_fd = socket(AF_NETLINK, SOCK_RAW, protocol)) < 0)
	{
		res = errno;
		IPACMDBG("Socket open failed %s  with\n", strerror(errno));
		return -res;
	}

	optlen = sizeof(sendbuff);
	res = getsockopt(*p_sk_fd, SOL_SOCKET, SO_SNDBUF, &sendbuff, &optlen);

	if(res < 0) {
		IPACMDBG("err: %s in getsockopt",strerror(errno));
	} else {
		IPACMDBG("orignal send buffer size = %d\n", sendbuff);
	}

	IPACMDBG("sets the send buffer to %d\n", buf_size);
	if (setsockopt(*p_sk_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(int)) < 0) {
		IPACMERR("err: %s in setting sockopt\n", strerror(errno));
	}

	/* Initialize socket addresses to null */
	memset(p_sk_addr_loc, 0, sizeof(struct sockaddr_nl));

	/* Populate local socket address using specified groups */
	p_sk_addr_loc->nl_family = AF_NETLINK;
	p_sk_addr_loc->nl_pid = 0;
	p_sk_addr_loc->nl_groups = grps;

	/* Bind socket to the local address, i.e. specified groups. This ensures
	 that multicast messages for these groups are delivered over this
	 socket. */

	if(bind(*p_sk_fd,
					(struct sockaddr *)p_sk_addr_loc,
					sizeof(struct sockaddr_nl)) < 0)
	{
		res = errno;
		IPACMDBG("Socket bind failed with err %s\n", strerror(errno));
		/* close the socket before returning the error */
		close(*p_sk_fd);
		*p_sk_fd = -1;
		p_sk_fd = NULL;
		return -res;
	}

	return IPACM_SUCCESS;
}

/* Add fd to fdmap array and store read handler function ptr (up to MAX_NUM_OF_FD).*/
static int ipa_nl_addfd_map
(
	 ipa_nl_sk_fd_set_info_t *info,
	 int fd,
	 ipa_sock_thrd_fd_read_f read_f
	 )
{
	if(info->num_fd < MAX_NUM_OF_FD)
	{
		FD_SET(fd, &info->fdset);

		/* Add fd to fdmap array and store read handler function ptr */
		info->sk_fds[info->num_fd].sk_fd = fd;
		info->sk_fds[info->num_fd].read_func = read_f;

		/* Increment number of fds stored in fdmap */
		info->num_fd++;
		if(info->max_fd < fd)
			info->max_fd = fd;
	}
	else
	{
		return IPACM_FAILURE;
	}

	return IPACM_SUCCESS;
}

/*  start socket listener */
static int ipa_nl_sock_listener_start
(
	 ipa_nl_sk_fd_set_info_t *sk_fd_set
	 )
{
	int i, ret;
	IPACMDBG("Starting the netlink thread\n");
	nl_lock = true;
	while(true)
	{
	    for(i = 0; i < sk_fd_set->num_fd; i++ )
		{
			FD_SET(sk_fd_set->sk_fds[i].sk_fd, &(sk_fd_set->fdset));
		}

		if((ret = select(sk_fd_set->max_fd + 1, &(sk_fd_set->fdset), NULL, NULL, NULL)) < 0)
		{
			IPACMERR("err: %s in select\n",strerror(errno));
		}
		else
		{
			for(i = 0; i < sk_fd_set->num_fd; i++)
			{

				if(FD_ISSET(sk_fd_set->sk_fds[i].sk_fd, &(sk_fd_set->fdset)))
				{

					if(sk_fd_set->sk_fds[i].read_func)
					{
						if(IPACM_SUCCESS != ((sk_fd_set->sk_fds[i].read_func)(sk_fd_set->sk_fds[i].sk_fd)))
						{
							IPACMERR("Error on read callback[%d] fd=%d\n",
											 i,
											 sk_fd_set->sk_fds[i].sk_fd);
						}
						FD_CLR(sk_fd_set->sk_fds[i].sk_fd, &(sk_fd_set->fdset));
					}
					else
					{
						IPACMERR("No read function\n");
					}
				}

			} /* end of for loop*/
		} /* end of else */
	} /* end of while */

	return IPACM_SUCCESS;
}

/* allocate memory for ipa_nl__msg */
static struct msghdr* ipa_nl_alloc_msg
(
	 uint32_t msglen
	 )
{
	unsigned char *buf = NULL;
	struct sockaddr_nl *nladdr = NULL;
	struct iovec *iov = NULL;
	struct msghdr *msgh = NULL;

	if(IPA_NL_MSG_MAX_LEN < msglen)
	{
		IPACMERR("Netlink message exceeds maximum length\n");
		return NULL;
	}

	msgh = (struct msghdr *)malloc(sizeof(struct msghdr));
	if(msgh == NULL)
	{
		IPACMERR("Failed malloc for msghdr\n");
		return NULL;
	}

	nladdr = (struct sockaddr_nl *)malloc(sizeof(struct sockaddr_nl));
	if(nladdr == NULL)
	{
		IPACMERR("Failed malloc for sockaddr\n");
		free(msgh);
		return NULL;
	}

	iov = (struct iovec *)malloc(sizeof(struct iovec));
	if(iov == NULL)
	{
		PERROR("Failed malloc for iovec");
		free(nladdr);
		free(msgh);
		return NULL;
	}

	buf = (unsigned char *)malloc(msglen);
	if(buf == NULL)
	{
		IPACMERR("Failed malloc for mglen\n");
		free(iov);
		free(nladdr);
		free(msgh);
		return NULL;
	}

	memset(nladdr, 0, sizeof(struct sockaddr_nl));
	nladdr->nl_family = AF_NETLINK;

	memset(msgh, 0x0, sizeof(struct msghdr));
	msgh->msg_name = nladdr;
	msgh->msg_namelen = sizeof(struct sockaddr_nl);
	msgh->msg_iov = iov;
	msgh->msg_iovlen = 1;

	memset(iov, 0x0, sizeof(struct iovec));
	memset(buf, 0, msglen);
	iov->iov_base = buf;
	iov->iov_len = msglen;

	return msgh;
}

/* release IPA message */
static void ipa_nl_release_msg
(
	 struct msghdr *msgh
	 )
{
	unsigned char *buf = NULL;
	struct sockaddr_nl *nladdr = NULL;
	struct iovec *iov = NULL;

	if(NULL == msgh)
	{
		return;
	}

	nladdr = (struct sockaddr_nl *)msgh->msg_name;
	iov = msgh->msg_iov;
	if(msgh->msg_iov)
	{
		buf = (unsigned char *)msgh->msg_iov->iov_base;
	}

	if(buf)
	{
	free(buf);
	}
	if(iov)
	{
	free(iov);
	}
	if(nladdr)
	{
	free(nladdr);
	}
	if(msgh)
	{
	free(msgh);
	}
	return;
}

/* receive and process nl message */
static int ipa_nl_recv
(
	 int              fd,
	 struct msghdr **msg_pptr,
	 unsigned int  *msglen_ptr
	 )
{
	struct msghdr *msgh = NULL;
	int rmsgl;

	msgh = ipa_nl_alloc_msg(IPA_NL_MSG_MAX_LEN);
	if(NULL == msgh)
	{
		IPACMERR("Failed to allocate NL message\n");
		goto error;
	}


	/* Receive message over the socket */
	rmsgl = recvmsg(fd, msgh, 0);

	/* Verify that something was read */
	if(rmsgl <= 0)
	{
		PERROR("NL recv error");
		goto error;
	}

	/* Verify that NL address length in the received message is expected value */
	if(sizeof(struct sockaddr_nl) != msgh->msg_namelen)
	{
		IPACMERR("rcvd msg with namelen != sizeof sockaddr_nl\n");
		goto error;
	}

	/* Verify that message was not truncated. This should not occur */
	if(msgh->msg_flags & MSG_TRUNC)
	{
		IPACMERR("Rcvd msg truncated!\n");
		goto error;
	}

	*msg_pptr    = msgh;
	*msglen_ptr = rmsgl;

	return IPACM_SUCCESS;

/* An error occurred while receiving the message. Free all memory before
				 returning. */
error:
	ipa_nl_release_msg(msgh);
	*msg_pptr    = NULL;
	*msglen_ptr  = 0;

	return IPACM_FAILURE;
}

/* decode the rtm netlink message */
static int ipa_nl_decode_rtm_link
(
	 const char              *buffer,
	 unsigned int             buflen,
	 ipa_nl_link_info_t      *link_info
)
{
	struct rtattr *attrib, *nested_attr, *vlan_attr;
	struct rtattr *device_link_info[IFLA_INFO_MAX + 1] = {0};
	struct rtattr *vlan_link_info_data_attrs[IFLA_VLAN_MAX+1] = {0};
	struct ifinfomsg *ifm;
	int nest_len, vlan_len;
	char *intf_type = NULL;
	/* NL message header */
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
	char *rta_data = NULL;

	ifm = (struct ifinfomsg *) NLMSG_DATA(nlh);
	buflen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
	/* Extract the header data */
	link_info->metainfo = *(struct ifinfomsg *)NLMSG_DATA(nlh);

	for (attrib = IFLA_RTA(ifm); RTA_OK(attrib, buflen); attrib = RTA_NEXT(attrib, buflen)) {
		rta_data = strdup((const char *)RTA_DATA(attrib));
		if (attrib->rta_type == IFLA_IFNAME && rta_data) {
			strlcpy(link_info->vlan_info.name, rta_data, IFACE_NAME);
			IPACMDBG("Extracted vlan interface name %s\n", link_info->vlan_info.name);
			/* This is the interface name. in case of macsec/vlan/vlan-macsec it can be macsec0, vlan0, macsec100.0 */
			strlcpy(link_info->name, rta_data, IFACE_NAME);
			IPACMDBG("Extracted interface name %s\n", link_info->name);
		}
		if (attrib->rta_type == IFLA_LINKINFO) {
			nested_attr = (struct rtattr *)RTA_DATA(attrib);
			nest_len = RTA_PAYLOAD(attrib);
			while (RTA_OK(nested_attr, nest_len)) {
				if ((nested_attr->rta_type <= IFLA_INFO_MAX) && (!device_link_info[nested_attr->rta_type]))
					device_link_info[nested_attr->rta_type] = nested_attr;
				nested_attr = RTA_NEXT(nested_attr, nest_len);
			}
			if (device_link_info [IFLA_INFO_KIND]) {
				intf_type = strdup((char *)RTA_DATA(device_link_info[IFLA_INFO_KIND]));
				if (intf_type) {
					if (!strcmp(intf_type, "vlan")) {
						link_info->link_type = IPA_LINK_TYPE_VLAN;
						link_info->vlan_info.vlan_interface_index = link_info->metainfo.ifi_index;
						IPACMDBG("Recived NEW_LINK for vlan type interface with interface index %d\n",
									link_info->metainfo.ifi_index);
					} else if (strcmp(intf_type, "macsec") == 0) {
						link_info->link_type = IPA_LINK_TYPE_MACSEC;
						IPACMDBG("Recived NEW_LINK for macsec type interface with interface index %d\n",
									link_info->metainfo.ifi_index);
					}
				}
			}
			if (intf_type && !strcmp(intf_type, "vlan") && device_link_info[IFLA_INFO_DATA]) {
				vlan_attr = (struct rtattr *)RTA_DATA(device_link_info[IFLA_INFO_DATA]);
				vlan_len = RTA_PAYLOAD(device_link_info[IFLA_INFO_DATA]);
				while (RTA_OK(vlan_attr, vlan_len)) {
					if ((vlan_attr->rta_type <= IFLA_INFO_MAX) &&(!vlan_link_info_data_attrs[vlan_attr->rta_type]))
						vlan_link_info_data_attrs[vlan_attr->rta_type] = vlan_attr;
					vlan_attr = RTA_NEXT(vlan_attr, vlan_len);
				}
				if (vlan_link_info_data_attrs[IFLA_VLAN_ID]) {
					link_info->vlan_id = *(uint16_t *)RTA_DATA(vlan_link_info_data_attrs[IFLA_VLAN_ID]);
					IPACMDBG("vlan id %d\n", link_info->vlan_id);

				}
			}
			if(intf_type != NULL){
				free(intf_type);
			}
		}
		if (attrib->rta_type == IFLA_MTU) {
			memcpy(&link_info->mtu,
						 RTA_DATA(attrib),
						 sizeof(link_info->mtu));
			IPACMDBG("Extracted MTU %d\n",link_info->mtu);
		}
		if(rta_data != NULL){
			free(rta_data);
		}

		if (attrib->rta_type == IFLA_MASTER) {
			memcpy(&link_info->master_interface_index,
						 RTA_DATA(attrib),
						 sizeof(link_info->master_interface_index));
			IPACMDBG("Extracted master interface index %d\n",
					link_info->master_interface_index);
		}
	}
	return IPACM_SUCCESS;
}

/* Decode kernel address message parameters from Netlink attribute TLVs. */
static int ipa_nl_decode_rtm_addr
(
	 const char              *buffer,
	 unsigned int             buflen,
	 ipa_nl_addr_info_t   *addr_info
	 )
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;  /* NL message header */
	struct rtattr *rtah = NULL;

	/* Extract the header data */
	addr_info->metainfo = *((struct ifaddrmsg *)NLMSG_DATA(nlh));
	buflen -= NLMSG_LENGTH(sizeof(struct ifaddrmsg));

	memset(&addr_info->attr_info, 0, sizeof(addr_info->attr_info));
	/* Extract the available attributes */
	addr_info->attr_info.param_mask = IPA_NLA_PARAM_NONE;

	rtah = IFA_RTA(NLMSG_DATA(nlh));

	while(RTA_OK(rtah, buflen))
	{
		switch(rtah->rta_type)
		{

		case IFA_ADDRESS:
			addr_info->attr_info.prefix_addr.ss_family = addr_info->metainfo.ifa_family;
			IPACM_NL_COPY_ADDR( addr_info, prefix_addr );
			addr_info->attr_info.param_mask |= IPA_NLA_PARAM_PREFIXADDR;
			break;
		default:
			break;

		}
		/* Advance to next attribute */
		rtah = RTA_NEXT(rtah, buflen);
	}

	return IPACM_SUCCESS;
}

static void logNeighborState(const uint16_t state, const int interfaceIndex) {
	std::string stateStr;
	char interfaceName[IF_NAME_LEN] = {0};


	ipa_get_if_name(interfaceName, interfaceIndex);
	stateStr += "interface index: " + std::to_string(interfaceIndex) + ", interface name: " + string(interfaceName) + ", neighbor state:";

	if (state & NUD_INCOMPLETE)
		stateStr += " INCOMPLETE";
	if (state & NUD_REACHABLE)
		stateStr += " NUD_REACHABLE";
	if (state & NUD_STALE)
		stateStr += " NUD_STALE";
	if (state & NUD_DELAY)
		stateStr += " NUD_DELAY";
	if (state & NUD_PROBE)
		stateStr += " NUD_PROBE";
	if (state & NUD_FAILED)
		stateStr += " NUD_FAILED";
	if (state & NUD_NOARP)
		stateStr += " NUD_NOARP";
	if (state & NUD_PERMANENT)
		stateStr += " NUD_PERMANENT";
	if (state == NUD_NONE)
		stateStr += " NUD_NONE";

	IPACMDBG("%s\n", stateStr.c_str());
}

/* Decode kernel neighbor message parameters from Netlink attribute TLVs. */
static int ipa_nl_decode_rtm_neigh
(
	 const char              *buffer,
	 unsigned int             buflen,
	 ipa_nl_neigh_info_t   *neigh_info
	 )
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;  /* NL message header */
	struct rtattr *rtah = NULL;
	bool address_set = false;

	/* Extract the header data */
	neigh_info->metainfo = *((struct ndmsg *)NLMSG_DATA(nlh));
	buflen -= NLMSG_LENGTH(sizeof(struct ndmsg));

	memset(&neigh_info->attr_info, 0, sizeof(neigh_info->attr_info));
	/* Extract the available attributes */
	neigh_info->attr_info.param_mask = IPA_NLA_PARAM_NONE;
	logNeighborState(neigh_info->metainfo.ndm_state, neigh_info->metainfo.ndm_ifindex);

	rtah = NDA_RTA(NLMSG_DATA(nlh));

	while(RTA_OK(rtah, buflen))
	{
		switch(rtah->rta_type)
		{

		case NDA_DST:
			if (!address_set)
			{
				neigh_info->attr_info.local_addr.ss_family = neigh_info->metainfo.ndm_family;
				IPACM_NL_COPY_ADDR( neigh_info, local_addr );
				IPACM_NL_REPORT_ADDR( " ", neigh_info->attr_info.local_addr);
				address_set = true;
			}
			break;

		case NDA_LLADDR:
			memcpy(neigh_info->attr_info.lladdr_hwaddr.sa_data,
						 RTA_DATA(rtah),
						 sizeof(neigh_info->attr_info.lladdr_hwaddr.sa_data));
			break;

		case NDA_MASTER:
				neigh_info->master_interface_index = *((int *) RTA_DATA(rtah));
				IPACMDBG("Master Interface Index for is %d\n", neigh_info->master_interface_index);
			break;

		default:
			break;

		}

		/* Advance to next attribute */
		rtah = RTA_NEXT(rtah, buflen);
	}

	return IPACM_SUCCESS;
}

/* Decode kernel route message parameters from Netlink attribute TLVs. */
static int ipa_nl_decode_rtm_route
(
	 const char              *buffer,
	 unsigned int             buflen,
	 ipa_nl_route_info_t   *route_info
	 )
{
	IPACMDBG("Handling new param route netlink\n");
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;  /* NL message header */
	struct rtattr *rtah = NULL;

	/* Extract the header data */
	route_info->metainfo = *((struct rtmsg *)NLMSG_DATA(nlh));
	buflen -= NLMSG_LENGTH(sizeof(struct rtmsg));

	memset(&route_info->attr_info, 0, sizeof(route_info->attr_info));
	route_info->attr_info.param_mask = IPA_RTA_PARAM_NONE;
	rtah = RTM_RTA(NLMSG_DATA(nlh));

	while(RTA_OK(rtah, buflen))
	{
		switch(rtah->rta_type)
		{

		case RTA_DST:
				route_info->attr_info.dst_addr.ss_family = route_info->metainfo.rtm_family;
				IPACM_NL_COPY_ADDR( route_info, dst_addr );
				route_info->attr_info.param_mask |= IPA_RTA_PARAM_DST;
			break;

		case RTA_SRC:
			route_info->attr_info.src_addr.ss_family = route_info->metainfo.rtm_family;
			IPACM_NL_COPY_ADDR( route_info, src_addr );
			route_info->attr_info.param_mask |= IPA_RTA_PARAM_SRC;
			break;

		case RTA_GATEWAY:
			route_info->attr_info.gateway_addr.ss_family = route_info->metainfo.rtm_family;
			IPACM_NL_COPY_ADDR( route_info, gateway_addr );
			route_info->attr_info.param_mask |= IPA_RTA_PARAM_GATEWAY;
			break;

		case RTA_IIF:
			memcpy(&route_info->attr_info.iif_index,
						 RTA_DATA(rtah),
						 sizeof(route_info->attr_info.iif_index));
			route_info->attr_info.param_mask |= IPA_RTA_PARAM_IIF;
			break;

		case RTA_OIF:
			memcpy(&route_info->attr_info.oif_index,
						 RTA_DATA(rtah),
						 sizeof(route_info->attr_info.oif_index));
			route_info->attr_info.param_mask |= IPA_RTA_PARAM_OIF;
			break;

		case RTA_PRIORITY:
			memcpy(&route_info->attr_info.priority,
						 RTA_DATA(rtah),
						 sizeof(route_info->attr_info.priority));
			route_info->attr_info.param_mask |= IPA_RTA_PARAM_PRIORITY;
			break;

		case RTA_TABLE:
			IPACMDBG("Handling RTA TABLE from netlink\n");
			memcpy(&route_info->attr_info.table_id,
                                                 RTA_DATA(rtah),
                                                 sizeof(route_info->attr_info.table_id));
			route_info->attr_info.param_mask |= IPA_RTA_PARAM_TABLE;
			IPACMDBG("Table id is %d\n",route_info->attr_info.table_id);
			break;

		default:
			break;

		}

		/* Advance to next attribute */
		rtah = RTA_NEXT(rtah, buflen);
	}

	return IPACM_SUCCESS;
}

/* Get vlan priority */
static bool ipa_nl_get_vlan_priority
(
	 ipa_vlan_iface_info   *vlan_info
	 )
{
	char cmd[200] = {0};
	FILE *fp = NULL;
	uint32_t priority = 0;

	snprintf(cmd, 200, "ip -d -o link show dev %s | grep \"egress-qos-map\" | sed -n \"s/^.*egress-qos-map { [0-9]:\\s*\\(\\S*\\).*$/\\1/p\" > /tmp/pcp.txt", vlan_info->name);
	system(cmd);
	fp = fopen("/tmp/pcp.txt", "r");
	if (!fp) {
		IPACMERR("can't open /tmp/pcp.txt\n");
		return IPACM_FAILURE;
	}

	if(fscanf(fp, "%d", &priority) > 0)
	{
		if(!(priority < 0 || priority > 7))
			vlan_info->priority = (uint8_t)priority;
	}
	IPACMDBG("Vlan ID %d, Priority %d\n", vlan_info->vlan_id, vlan_info->priority);
	fclose(fp);
	remove("/tmp/pcp.txt");
	return IPACM_SUCCESS;
}

static int get_macsec_lower_interface_name(struct ipa_macsec_map *macsecMap, char *lowerInterfaceName)
{
	char cmd[200] = {0};
	FILE *fp = NULL;

	snprintf(cmd, 200, "ls /sys/devices/virtual/net/%s | grep lower | cut -d'_' -f2 > /tmp/macsec_name.txt", macsecMap->macsec_name);
	system(cmd);
	fp = fopen("/tmp/macsec_name.txt", "r");
	if (!fp) {
		IPACMERR("can't open /tmp/macsec_name.txt\n");
		return IPACM_FAILURE;
	}
	if (!fgets(lowerInterfaceName, IF_NAME_LEN, fp)) {
		IPACMERR("fgets failed\n");
		remove("/tmp/macsec_name.txt");
		fclose(fp);
		return IPACM_FAILURE;
	}
	fclose(fp);
	remove("/tmp/macsec_name.txt");
	lowerInterfaceName[strcspn(lowerInterfaceName, "\r\n")] = 0;
	return IPACM_SUCCESS;
}

/* decode the ipa nl-message */
static int ipa_nl_decode_nlmsg
(
	const char   *buffer,
	unsigned int  buflen,
	ipa_nl_msg_t  *msg_ptr,
	char	      *iface_name,
	bool          query = false
)
{
	char dev_name[IF_NAME_LEN] = {0};
	char master_dev_name[IF_NAME_LEN] = {0};
	ipa_bridge_vlan_mapping_info vlan_bridge_data;
	int ret_val = IPACM_FAILURE, mask_index = 0, mask_value_v6 = 0;
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
	ipacm_event_route_vlan *vlan_rt_data;

	uint32_t if_ipv4_addr =0, if_ipipv4_addr_mask =0, temp =0, if_ipv4_addr_gw =0;
	uint8_t nullMac[IPA_MAC_ADDR_SIZE] = {0};
	uint16_t vlan_id = 0;
	uint32_t prefix_len = ~0;
	uint8_t num_msgs = 0;
	uint32_t ipv6_unique_local_prefix = 0xFD000000;
	uint32_t ipv6_unique_local_prefix_mask = 0xFF000000;

	ipacm_cmd_q_data evt_data = {};
	ipacm_cmd_q_data bridge_evt_data = {};
	ipacm_cmd_q_data vlan_event = {};
	ipacm_event_data_all *data_all = NULL;
	ipacm_event_data_fid *data_fid = NULL;
	ipacm_event_data_addr *data_addr = NULL;
	ipacm_event_data_all *vlan_data = NULL;
	struct ipa_vlan_iface_info vlan_info;
	struct ipa_macsec_map macsec_map, *macsec_map_data = NULL;
	IPACM_Config* config = IPACM_Config::GetInstance();
	int idx = 0;

	memset(nullMac, 0, sizeof(nullMac));
	memset(&vlan_info, 0, sizeof(vlan_info));
	memset(&macsec_map, 0, sizeof(macsec_map));

	IPACMDBG("Received buf[%p], Len[%u] to decode\n", buffer, buflen);

	while(NLMSG_OK(nlh, buflen))
	{
		memset(dev_name,0,IF_NAME_LEN);
		num_msgs++;
		IPACMDBG("num_msgs[%u], Received msg:%d from netlink, msg[%p], Curr_Len[%u], remaining_len[%u]\n",
				num_msgs, nlh->nlmsg_type, nlh, nlh->nlmsg_len, buflen);

		if ((nlh->nlmsg_flags & NLM_F_DUMP_INTR) || (nlh->nlmsg_type == NLMSG_OVERRUN))
		{
			IPACMERR("Dump was: %s\n", (nlh->nlmsg_flags & NLM_F_DUMP_INTR) ?
					"interrupted" : "overrun");
			ret_val = (nlh->nlmsg_flags & NLM_F_DUMP_INTR) ? -EINTR : -EIO;
			goto fail;
		}

		switch(nlh->nlmsg_type)
		{
			case RTM_NEWLINK:
				{
					IPACMDBG("\nGOT RTM_NEWLINK event\n");
					msg_ptr->type = nlh->nlmsg_type;
					msg_ptr->link_event = true;
					memset(&(msg_ptr->nl_link_info), 0, sizeof((msg_ptr->nl_link_info)));

					ret_val = ipa_nl_decode_rtm_link((const char *)nlh, nlh->nlmsg_len, &(msg_ptr->nl_link_info));
					if (IPACM_SUCCESS != ret_val) {
						IPACMERR("Failed to decode rtm link message\n");
						goto fail;
					} else {
						IPACMDBG("Got RTM_NEWLINK with below values\n");
						IPACMDBG("RTM_NEWLINK, ifi_change:%d\n", msg_ptr->nl_link_info.metainfo.ifi_change);
						IPACMDBG("RTM_NEWLINK, ifi_flags:%d\n", msg_ptr->nl_link_info.metainfo.ifi_flags);
						IPACMDBG("RTM_NEWLINK, ifi_index:%d\n", msg_ptr->nl_link_info.metainfo.ifi_index);
						IPACMDBG("RTM_NEWLINK, family:%d\n", msg_ptr->nl_link_info.metainfo.ifi_family);
						/**
						 * RTM_NEWLINK event with AF_BRIDGE family should be ignored in
						 * Android but this should be processed in case of MDM for
						 * Ehernet interface.
						 */
#ifdef FEATURE_IPA_ANDROID
						if (msg_ptr->nl_link_info.metainfo.ifi_family == AF_BRIDGE) {
							IPACMERR(" ignore this RTM_NEWLINK msg \n");
							goto next_msg;
						}
#endif

						ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_link_info.metainfo.ifi_index);
						if (ret_val != IPACM_SUCCESS) {
							IPACMERR("Error while getting interface name\n");
							goto fail;
						}

						/* Handle non-default AP. AP mode iface: wlan0
						   AP+STA mode iface: wlan1 */
						idx = IPACM_Iface::iface_ipa_index_query(msg_ptr->nl_link_info.metainfo.ifi_index);
						if((msg_ptr->nl_link_info.master_interface_index != 0) &&
						   (idx != INVALID_IFACE) && (config->iface_table[idx].if_cat != WAN_IF) &&
						   (strncmp(dev_name, WLAN_INTF, strlen(WLAN_INTF)) == 0))
						{
							IPACMDBG_H("Received NEWLINK on %s. ifi_idx: %d, master_idx: %d\n",
									dev_name,
									msg_ptr->nl_link_info.metainfo.ifi_index,
									msg_ptr->nl_link_info.master_interface_index);
							data_all = (ipacm_event_data_all *)calloc(1, sizeof(*data_all));
							if(!data_all) {
								IPACMERR("malloc failed\n");
								ret_val = -ENOMEM;
								goto fail;
							}
							data_all->if_index = msg_ptr->nl_link_info.metainfo.ifi_index;
							data_all->master_if_index = msg_ptr->nl_link_info.master_interface_index;
							bridge_evt_data.evt_data = data_all;
							bridge_evt_data.event = IPA_WLAN_BRIDGE_UPDATE_EVENT;
							IPACM_EvtDispatcher::PostEvt(&bridge_evt_data);
						}

						if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_VLAN) {
							strlcpy(vlan_info.name, msg_ptr->nl_link_info.name, sizeof(vlan_info.name));
							vlan_info.vlan_id = msg_ptr->nl_link_info.vlan_id;
							vlan_info.vlan_interface_index = msg_ptr->nl_link_info.metainfo.ifi_index;
							ipa_nl_get_vlan_priority(&vlan_info);
						}

						if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_MACSEC) {
							IPACMERR("macsec_name=%s, phy_name=%s\n", macsec_map.macsec_name, macsec_map.phy_name);
							strlcpy(macsec_map.macsec_name, msg_ptr->nl_link_info.name, sizeof(macsec_map.macsec_name));
							ret_val = get_macsec_lower_interface_name(&macsec_map, master_dev_name);
							if (IPACM_SUCCESS != ret_val)
								goto fail;
							strlcpy(macsec_map.phy_name, master_dev_name, sizeof(macsec_map.phy_name));
							IPACMERR("After assigning to macsec map: macsec_name=%s, phy_name=%s\n", macsec_map.macsec_name,
									macsec_map.phy_name);
							if (IPACM_Iface::ipacmcfg->insertOrAssignMacsecMap(&macsec_map)) {
								evt_data.event = IPA_HANDLE_MACSEC_ADD;
								macsec_map_data = static_cast<decltype(macsec_map_data)>(malloc(sizeof(*macsec_map_data)));
								if (!macsec_map_data) {
									IPACMERR("malloc failed\n");
									ret_val = -ENOMEM;
									goto fail;
								}
								memcpy(macsec_map_data, &macsec_map, sizeof(macsec_map));
								IPACMERR("macsec_map_data->macsec_name=%s, macsec_map_data->phy_name=%s\n", macsec_map_data->macsec_name, macsec_map_data->phy_name);
								evt_data.evt_data = macsec_map_data;
								IPACM_EvtDispatcher::PostEvt(&evt_data);
							}
						}

						if (IPACM_Iface::ipacmcfg->check_l2tp_iface( msg_ptr->nl_link_info.name) &&
								msg_ptr->nl_link_info.mtu) {
							IPACM_Iface::ipacmcfg->add_l2tp_mtu_info(msg_ptr->nl_link_info.mtu, msg_ptr->nl_link_info.name);
						}
						if ((IFF_UP & msg_ptr->nl_link_info.metainfo.ifi_change) ||
								(!memcmp(dev_name,"rmnet_data", 10) &&
								 (msg_ptr->nl_link_info.metainfo.ifi_type == ARPHRD_RAWIP))) {
							IPACMDBG("GOT useful newlink event\n");

							data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
							if (data_fid == NULL) {
								IPACMERR("unable to allocate memory for event data_fid\n");
								ret_val = -ENOMEM;
								goto fail;
							}
							data_fid->if_index = msg_ptr->nl_link_info.metainfo.ifi_index;
							strlcpy(data_fid->iface_name, dev_name, sizeof(data_fid->iface_name));
							if(msg_ptr->nl_link_info.vlan_id) {
								IPACMDBG("Add vlan<->interface details with vlan: %d interface: %s interface index %d priority %d\n",
										vlan_info.vlan_id, vlan_info.name, vlan_info.vlan_interface_index, vlan_info.priority);
								IPACM_Iface::ipacmcfg->add_vlan_iface(&vlan_info);
							}

							if (msg_ptr->nl_link_info.metainfo.ifi_flags & IFF_UP) {
								IPACMDBG_H("Interface %s bring up with IP-family: %d \n", dev_name,
										msg_ptr->nl_link_info.metainfo.ifi_family);
								/* post link up to command queue */
								evt_data.event = IPA_LINK_UP_EVENT;
								IPACMDBG_H("Posting IPA_LINK_UP_EVENT with if index: %d\n",
										msg_ptr->nl_link_info.metainfo.ifi_index);
							} else {
								if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_MACSEC ||
										IPACM_Iface::ipacmcfg->getMacsecMapping(msg_ptr->nl_link_info.metainfo.ifi_index,
											&macsec_map)) {
									if (IPACM_Iface::ipacmcfg->delMacsecMap(&macsec_map)) {
										evt_data.event = IPA_HANDLE_MACSEC_DEL;
										macsec_map_data = static_cast<decltype(macsec_map_data)>
											(malloc(sizeof(*macsec_map_data)));
										if (!macsec_map_data) {
											IPACMERR("malloc failed\n");
											ret_val = -ENOMEM;
											goto fail;
										}
										memcpy(macsec_map_data, &macsec_map, sizeof(macsec_map));
										evt_data.evt_data = macsec_map_data;
										IPACM_EvtDispatcher::PostEvt(&evt_data);
									}
								}
								IPACMDBG_H("Interface %s bring down with IP-family: %d \n", dev_name,
										msg_ptr->nl_link_info.metainfo.ifi_family);
								/* post link down to command queue */
								evt_data.event = IPA_LINK_DOWN_EVENT;
								IPACMDBG_H("Posting IPA_LINK_DOWN_EVENT with if index: %d\n",
										data_fid->if_index);
							}
							evt_data.evt_data = data_fid;
							IPACM_EvtDispatcher::PostEvt(&evt_data);
						}
						else
						{
							/* Add IPACM support for ECM plug-in/plug_out */
							/*--------------------------------------------------------------------------
							  Check if the interface is running.If its a RTM_NEWLINK and the interface
							  is running then it means that its a link up event
							  ---------------------------------------------------------------------------*/
							if ((msg_ptr->nl_link_info.metainfo.ifi_flags & IFF_RUNNING) &&
									(msg_ptr->nl_link_info.metainfo.ifi_flags & IFF_LOWER_UP)) {
								data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
								if (data_fid == NULL) {
									IPACMERR("unable to allocate memory for event data_fid\n");
									ret_val = -ENOMEM;
									goto fail;
								}
								data_fid->if_index = msg_ptr->nl_link_info.metainfo.ifi_index;

								IPACMDBG("Got a usb link_up event (Interface %s, %d) \n", dev_name,
										msg_ptr->nl_link_info.metainfo.ifi_index);
								strlcpy(data_fid->iface_name, dev_name, sizeof(data_fid->iface_name));
								if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_VLAN)
									IPACM_Iface::ipacmcfg->add_vlan_iface(&vlan_info);
								/*--------------------------------------------------------------------------
								  Post LAN iface (ECM) link up event
								  ---------------------------------------------------------------------------*/
								evt_data.event = IPA_USB_LINK_UP_EVENT;
								evt_data.evt_data = data_fid;
								IPACMDBG_H("Posting usb IPA_LINK_UP_EVENT with if index: %d\n", data_fid->if_index);
								IPACM_EvtDispatcher::PostEvt(&evt_data);
							} else if (!(msg_ptr->nl_link_info.metainfo.ifi_flags & IFF_LOWER_UP)) {
								data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
								if (data_fid == NULL) {
									IPACMERR("unable to allocate memory for event data_fid\n");
									ret_val = -ENOMEM;
									goto fail;
								}

								ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_link_info.metainfo.ifi_index);
								if(ret_val != IPACM_SUCCESS)
								{
									IPACMERR("Error while getting interface name\n");
									free(data_fid);
									goto fail;
								}
								IPACMDBG_H("Got a usb link_down event (Interface %s) \n", dev_name);


								if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_VLAN)
									IPACM_Iface::ipacmcfg->del_vlan_iface(&vlan_info);
								if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_MACSEC) {
									if (!IPACM_Iface::ipacmcfg->getMacsecMapping(msg_ptr->nl_link_info.metainfo.ifi_index,
												&macsec_map))
										IPACMERR("getMacsecMapping failed\n");
									if (IPACM_Iface::ipacmcfg->delMacsecMap(&macsec_map)) {
										evt_data.event = IPA_HANDLE_MACSEC_DEL;
										macsec_map_data = static_cast<decltype(macsec_map_data)>
											(malloc(sizeof(*macsec_map_data)));
										if (!macsec_map_data) {
											IPACMERR("malloc failed\n");
											ret_val = -ENOMEM;
											goto fail;
										}
										memcpy(macsec_map_data, &macsec_map, sizeof(macsec_map));
										evt_data.evt_data = macsec_map_data;
										IPACM_EvtDispatcher::PostEvt(&evt_data);
									}
								}
								if (msg_ptr->nl_link_info.metainfo.ifi_family == AF_BRIDGE ||
										msg_ptr->nl_link_info.metainfo.ifi_family == AF_UNSPEC) {
									IPACMDBG("Deleting the bridge<->vlan mapping entry with intterface index %d\n",
											msg_ptr->nl_link_info.metainfo.ifi_index);
									uint16_t vlan_master_interface_index = msg_ptr->nl_link_info.metainfo.ifi_index;
									IPACM_Iface::ipacmcfg->del_bridge_vlan_mapping(&vlan_master_interface_index);
									free(data_fid);
									goto next_msg;
								}

								data_fid->if_index = msg_ptr->nl_link_info.metainfo.ifi_index;
								strlcpy(data_fid->iface_name, dev_name, sizeof(data_fid->iface_name));
								/*--------------------------------------------------------------------------
								  Post LAN iface (ECM) link down event
								  ---------------------------------------------------------------------------*/
								evt_data.event = IPA_LINK_DOWN_EVENT;
								evt_data.evt_data = data_fid;
								IPACMDBG_H("Posting usb IPA_LINK_DOWN_EVENT with if index: %d\n", data_fid->if_index);
								IPACM_EvtDispatcher::PostEvt(&evt_data);
							}
						}
					}
				}
				break;

			case RTM_DELLINK:
				IPACMDBG("\nGOT RTM_DELLINK event\n");
				msg_ptr->type = nlh->nlmsg_type;
				msg_ptr->link_event = true;
				IPACMDBG("entering rtm decode\n");
				memset(&(msg_ptr->nl_link_info), 0, sizeof((msg_ptr->nl_link_info)));

				ret_val = ipa_nl_decode_rtm_link((const char *)nlh, nlh->nlmsg_len, &(msg_ptr->nl_link_info));
				if(IPACM_SUCCESS != ret_val)
				{
					IPACMERR("Failed to decode rtm link message\n");
					goto fail;
				} else {
					IPACMDBG("Got RTM_DELLINK with below values\n");
					IPACMDBG("RTM_DELLINK, ifi_change:%d\n", msg_ptr->nl_link_info.metainfo.ifi_change);
					IPACMDBG("RTM_DELLINK, ifi_flags:%d\n", msg_ptr->nl_link_info.metainfo.ifi_flags);
					IPACMDBG("RTM_DELLINK, ifi_index:%d\n", msg_ptr->nl_link_info.metainfo.ifi_index);
					IPACMDBG("RTM_DELLINK, family:%d\n", msg_ptr->nl_link_info.metainfo.ifi_family);

					ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_link_info.metainfo.ifi_index);
					if(ret_val != IPACM_SUCCESS)
					{
						IPACMERR("Error while getting interface name with index %d, continue as the interface might have already been down.\n",
								msg_ptr->nl_link_info.metainfo.ifi_index);
					}

					if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_VLAN) {
						strlcpy(vlan_info.name, msg_ptr->nl_link_info.name, sizeof(vlan_info.name));
						vlan_info.vlan_id = msg_ptr->nl_link_info.vlan_id;
						vlan_info.vlan_interface_index = msg_ptr->nl_link_info.metainfo.ifi_index;
						ipa_nl_get_vlan_priority(&vlan_info);
					}

					if(msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_VLAN) {
						data_all = (ipacm_event_data_all *)calloc(1, sizeof(*data_all));
						if (!data_all) {
							IPACMERR("malloc failed\n");
							ret_val = -ENOMEM;
							goto fail;
						}
						data_all->if_index = msg_ptr->nl_link_info.metainfo.ifi_index;
						evt_data.evt_data = data_all;
						evt_data.event = IPA_CLEAN_NEIGHBOR_CACHE;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
						IPACM_Iface::ipacmcfg->del_vlan_iface(&vlan_info);
					}
					if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_MACSEC) {
						if (!IPACM_Iface::ipacmcfg->getMacsecMapping(msg_ptr->nl_link_info.metainfo.ifi_index,
									&macsec_map))
							IPACMERR("getMacsecMapping failed\n");
						if (IPACM_Iface::ipacmcfg->delMacsecMap(&macsec_map)) {
							evt_data.event = IPA_HANDLE_MACSEC_DEL;
							macsec_map_data = static_cast<decltype(macsec_map_data)>
								(malloc(sizeof(*macsec_map_data)));
							if (!macsec_map_data) {
								IPACMERR("malloc failed\n");
								ret_val = -ENOMEM;
								goto fail;
							}
							memcpy(macsec_map_data, &macsec_map, sizeof(macsec_map));
							evt_data.evt_data = macsec_map_data;
							IPACM_EvtDispatcher::PostEvt(&evt_data);
						}
					}

					/* RTM_NEWLINK event with AF_BRIDGE family should be ignored in Android
					 *    but this should be processed in case of MDM for Ehernet interface.
					 */

					if (msg_ptr->nl_link_info.metainfo.ifi_family == AF_BRIDGE || msg_ptr->nl_link_info.metainfo.ifi_family == AF_UNSPEC)
					{
						IPACMDBG("Deleting the bridge<->vlan mapping entry with intterface index %d\n", msg_ptr->nl_link_info.metainfo.ifi_index);
						uint16_t vlan_master_interface_index = msg_ptr->nl_link_info.metainfo.ifi_index;
						IPACM_Iface::ipacmcfg->del_bridge_vlan_mapping(&vlan_master_interface_index);
					}

					/* post link down to command queue */
					evt_data.event = IPA_LINK_DOWN_EVENT;
					data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
					if(data_fid == NULL)
					{
						IPACMERR("unable to allocate memory for event data_fid\n");
						ret_val = -ENOMEM;
						goto fail;
					}

					data_fid->if_index = msg_ptr->nl_link_info.metainfo.ifi_index;
					strlcpy(data_fid->iface_name, dev_name, sizeof(data_fid->iface_name));

					IPACMDBG_H("posting IPA_LINK_DOWN_EVENT with if idnex:%d\n",
							data_fid->if_index);
					evt_data.evt_data = data_fid;
					IPACM_EvtDispatcher::PostEvt(&evt_data);
					/* finish command queue */
				}
				break;

			case RTM_NEWADDR:
				IPACMDBG("\nGOT RTM_NEWADDR event\n");
				memset(&(msg_ptr->nl_addr_info), 0, sizeof((msg_ptr->nl_addr_info)));

				ret_val = ipa_nl_decode_rtm_addr((const char *)nlh, nlh->nlmsg_len, &(msg_ptr->nl_addr_info));
				if(IPACM_SUCCESS != ret_val)
				{
					IPACMERR("Failed to decode rtm addr message\n");
					goto fail;
				} else {
					ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_addr_info.metainfo.ifa_index);
					if(ret_val != IPACM_SUCCESS)
					{
						IPACMERR("Error while getting interface name\n");
						goto fail;
					}
					IPACMDBG("Interface %s \n", dev_name);

					data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
					if(data_addr == NULL)
					{
						IPACMERR("unable to allocate memory for event data_addr\n");
						ret_val = -ENOMEM;
						goto fail;
					}
					memset(data_addr, 0, sizeof(ipacm_event_data_addr));
					if(AF_INET6 == msg_ptr->nl_addr_info.attr_info.prefix_addr.ss_family)
					{
						data_addr->iptype = IPA_IP_v6;
						IPACM_NL_REPORT_ADDR( "IFA_ADDRESS:", msg_ptr->nl_addr_info.attr_info.prefix_addr );
						IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr, msg_ptr->nl_addr_info.attr_info.prefix_addr);
						data_addr->ipv6_addr[0] = ntohl(data_addr->ipv6_addr[0]);
						data_addr->ipv6_addr[1] = ntohl(data_addr->ipv6_addr[1]);
						data_addr->ipv6_addr[2] = ntohl(data_addr->ipv6_addr[2]);
						data_addr->ipv6_addr[3] = ntohl(data_addr->ipv6_addr[3]);
					}
					else
					{
						data_addr->iptype = IPA_IP_v4;
						prefix_len = ~0;
						IPACM_NL_REPORT_ADDR( "IFA_ADDRESS:", msg_ptr->nl_addr_info.attr_info.prefix_addr );
						IPACM_EVENT_COPY_ADDR_v4( data_addr->ipv4_addr, msg_ptr->nl_addr_info.attr_info.prefix_addr);
						data_addr->ipv4_addr = ntohl(data_addr->ipv4_addr);
						prefix_len = ((prefix_len >> (IPV4_SIZE - msg_ptr->nl_addr_info.metainfo.ifa_prefixlen)) << (IPV4_SIZE - msg_ptr->nl_addr_info.metainfo.ifa_prefixlen));
						data_addr->ipv4_addr_mask = prefix_len;

					}

					evt_data.event = IPA_ADDR_ADD_EVENT;
					data_addr->if_index = msg_ptr->nl_addr_info.metainfo.ifa_index;
					strlcpy(data_addr->iface_name, dev_name, sizeof(data_addr->iface_name));
					if(AF_INET6 == msg_ptr->nl_addr_info.attr_info.prefix_addr.ss_family)
					{
						IPACMDBG("Posting IPA_ADDR_ADD_EVENT with if index:%d, ipv6 addr:0x%x:%x:%x:%x\n",
								data_addr->if_index,
								data_addr->ipv6_addr[0],
								data_addr->ipv6_addr[1],
								data_addr->ipv6_addr[2],
								data_addr->ipv6_addr[3]);
#if defined(FEATURE_L2TP) || defined(FEATURE_VLAN_MPDN)
						if(IPACM_Iface::ipacmcfg->is_added_vlan_iface(data_addr->iface_name))
						{
							if((data_addr->ipv6_addr[0] & ipv6_unique_local_prefix_mask) == (ipv6_unique_local_prefix & ipv6_unique_local_prefix_mask) &&
									((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) ||
									 (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E)))
							{
								IPACMDBG_H("Got IPv6 new addr event for a vlan iface %s.\n", data_addr->iface_name);
								IPACM_Iface::ipacmcfg->handle_vlan_iface_info(data_addr);
							}
						}
#endif
						evt_data.evt_data = data_addr;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
					}
					else if(AF_INET == msg_ptr->nl_addr_info.attr_info.prefix_addr.ss_family)
					{
						IPACMDBG("Posting IPA_ADDR_ADD_EVENT with if index:%d, ipv4 addr:0x%x\n",
								data_addr->if_index,
								data_addr->ipv4_addr);
						evt_data.evt_data = data_addr;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
					}
					else
					{
						free(data_addr);
					}

				}
				break;

			case RTM_DELADDR:
				IPACMDBG("\nGOT RTM_DELADDR event\n");
				memset(&(msg_ptr->nl_addr_info), 0, sizeof((msg_ptr->nl_addr_info)));

				ret_val = ipa_nl_decode_rtm_addr((const char *)nlh, nlh->nlmsg_len, &(msg_ptr->nl_addr_info));
				if(IPACM_SUCCESS != ret_val)
				{
					IPACMERR("Failed to decode rtm addr message\n");
					goto fail;
				} else {

					data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
					if(data_addr == NULL)
					{
						IPACMERR("unable to allocate memory for event data_addr\n");
						ret_val = -ENOMEM;
						goto fail;
					}
					memset(data_addr, 0, sizeof(ipacm_event_data_addr));
					if(AF_INET == msg_ptr->nl_addr_info.attr_info.prefix_addr.ss_family)
					{
						data_addr->iptype = IPA_IP_v4;
						prefix_len = ~0;
						IPACM_NL_REPORT_ADDR( "IFA_ADDRESS:", msg_ptr->nl_addr_info.attr_info.prefix_addr );
						IPACM_EVENT_COPY_ADDR_v4( data_addr->ipv4_addr, msg_ptr->nl_addr_info.attr_info.prefix_addr);
						data_addr->ipv4_addr = ntohl(data_addr->ipv4_addr);
						prefix_len = ((prefix_len >> (IPV4_SIZE - msg_ptr->nl_addr_info.metainfo.ifa_prefixlen)) << (IPV4_SIZE - msg_ptr->nl_addr_info.metainfo.ifa_prefixlen));
						data_addr->ipv4_addr_mask = prefix_len;
						data_addr->if_index = msg_ptr->nl_addr_info.metainfo.ifa_index;
						strlcpy(data_addr->iface_name, dev_name, sizeof(data_addr->iface_name));
						evt_data.event = IPA_ADDR_DEL_EVENT;
						IPACMDBG("Posting IPA_ADDR_DEL_EVENT with if index:%d, ipv4 addr:0x%x\n",
								data_addr->if_index,
								data_addr->ipv4_addr);
						evt_data.evt_data = data_addr;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
					}
					else
					{
						free(data_addr);
					}
				}
				break;
			case RTM_NEWROUTE:
				IPACMDBG("\nGOT RTM_NEWROUTE event\n");
				memset(&(msg_ptr->nl_route_info), 0, sizeof((msg_ptr->nl_route_info)));

				ret_val = ipa_nl_decode_rtm_route((const char *)nlh, nlh->nlmsg_len, &(msg_ptr->nl_route_info));
				if(IPACM_SUCCESS != ret_val)
				{
					IPACMERR("Failed to decode rtm route message\n");
					goto fail;
				}
				IPACMDBG("rtm_type: %d\n", msg_ptr->nl_route_info.metainfo.rtm_type);
				IPACMDBG("protocol: %d\n", msg_ptr->nl_route_info.metainfo.rtm_protocol);
				IPACMDBG("rtm_scope: %d\n", msg_ptr->nl_route_info.metainfo.rtm_scope);
				IPACMDBG("rtm_table: %d\n", msg_ptr->nl_route_info.metainfo.rtm_table);
				IPACMDBG("rtm_family: %d\n", msg_ptr->nl_route_info.metainfo.rtm_family);
				IPACMDBG("param_mask: 0x%x\n", msg_ptr->nl_route_info.attr_info.param_mask);

				/* take care of route add default route & uniroute */
				if((AF_INET == msg_ptr->nl_route_info.metainfo.rtm_family) &&
						(msg_ptr->nl_route_info.metainfo.rtm_type == RTN_UNICAST) &&
						((msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_BOOT) ||
						 (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_RA)) &&
						(msg_ptr->nl_route_info.metainfo.rtm_scope == RT_SCOPE_UNIVERSE) &&
						((msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN) ||
						 (msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_COMPAT)))
				{
					IPACMDBG("\n GOT RTM_NEWROUTE event\n");

					if(msg_ptr->nl_route_info.attr_info.param_mask & IPA_RTA_PARAM_DST)
					{
						ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_route_info.attr_info.oif_index);
						if(ret_val != IPACM_SUCCESS)
						{
							IPACMERR("Error while getting interface name\n");
							goto fail;
						}

						IPACM_NL_REPORT_ADDR( "route add -host\n", msg_ptr->nl_route_info.attr_info.dst_addr );
						IPACM_NL_REPORT_ADDR( "gw", msg_ptr->nl_route_info.attr_info.gateway_addr );
						IPACMDBG("dev %s\n",dev_name );
						/* insert to command queue */
						IPACM_EVENT_COPY_ADDR_v4( if_ipv4_addr, msg_ptr->nl_route_info.attr_info.dst_addr);

						evt_data.event = IPA_ROUTE_ADD_EVENT;
						data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
						if(data_addr == NULL)
						{
							IPACMERR("unable to allocate memory for event data_addr\n");
							ret_val = -ENOMEM;
							goto fail;
						}

						data_addr->if_index = msg_ptr->nl_route_info.attr_info.oif_index;
						data_addr->iptype = IPA_IP_v4;
						data_addr->ipv4_addr = ntohl(if_ipv4_addr);
						data_addr->ipv4_addr_mask = ntohl(if_ipipv4_addr_mask);

						IPACMDBG("Posting IPA_ROUTE_ADD_EVENT with if index:%d, ipv4 address 0x%x, mask:0x%x\n",
								data_addr->if_index,
								data_addr->ipv4_addr,
								data_addr->ipv4_addr_mask);
						evt_data.evt_data = data_addr;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
						/* finish command queue */

					}
					else
					{
						ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_route_info.attr_info.oif_index);
						if(ret_val != IPACM_SUCCESS)
						{
							IPACMERR("Error while getting interface name\n");
							goto fail;
						}
						else
						{
							IPACM_NL_REPORT_ADDR( "route add default gw \n", msg_ptr->nl_route_info.attr_info.gateway_addr );
							IPACMDBG_H("dev %s \n", dev_name);
							IPACM_NL_REPORT_ADDR( "dstIP:", msg_ptr->nl_route_info.attr_info.dst_addr );

							/* insert to command queue */
							data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
							if(data_addr == NULL)
							{
								IPACMERR("unable to allocate memory for event data_addr\n");
								ret_val = -ENOMEM;
								goto fail;
							}

							IPACM_EVENT_COPY_ADDR_v4( if_ipv4_addr, msg_ptr->nl_route_info.attr_info.dst_addr);
							IPACM_EVENT_COPY_ADDR_v4( if_ipipv4_addr_mask, msg_ptr->nl_route_info.attr_info.dst_addr);
							IPACM_EVENT_COPY_ADDR_v4( if_ipv4_addr_gw, msg_ptr->nl_route_info.attr_info.gateway_addr);

							data_addr->if_index = msg_ptr->nl_route_info.attr_info.oif_index;
							data_addr->iptype = IPA_IP_v4;
							data_addr->ipv4_addr = ntohl(if_ipv4_addr);
							data_addr->ipv4_addr_gw = ntohl(if_ipv4_addr_gw);
							data_addr->ipv4_addr_mask = ntohl(if_ipipv4_addr_mask);

							if(msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_COMPAT &&
									msg_ptr->nl_route_info.attr_info.param_mask & IPA_RTA_PARAM_GATEWAY &&
									strstr(dev_name, ETH_INTF) && IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
							{
								data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
								if(data_fid == NULL)
								{
									IPACMERR("unable to allocate memory for event_ecm data_fid\n");
									ret_val = -ENOMEM;
									goto fail;
								}
								strlcpy(IPACM_Iface::ipacmcfg->iface_table[IPACM_Iface::ipacmcfg->eth_wan_iface_table_idx].iface_name,
										dev_name, sizeof(IPACM_Iface::ipacmcfg->iface_table[IPACM_Iface::ipacmcfg->eth_wan_iface_table_idx].iface_name));
								IPACM_Iface::ipacmcfg->iface_table[IPACM_Iface::ipacmcfg->eth_wan_iface_table_idx].virtualIface = true;

								data_fid->if_index = msg_ptr->nl_route_info.attr_info.oif_index;
								evt_data.event = IPA_USB_LINK_UP_EVENT;
								evt_data.evt_data = data_fid;
								IPACM_EvtDispatcher::PostEvt(&evt_data);
							}

							if(msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN)
							{
								evt_data.event = IPA_ROUTE_ADD_EVENT;
								IPACMDBG_H("Posting IPA_ROUTE_ADD_EVENT with if index:%d, ipv4 addr:0x%x, mask: 0x%x and gw: 0x%x\n",
										data_addr->if_index,
										data_addr->ipv4_addr,
										data_addr->ipv4_addr_mask,
										data_addr->ipv4_addr_gw);
							}
							else if(msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_COMPAT)
							{
								evt_data.event = IPA_WAN_GW_ADDR_ADD_EVENT;
								IPACMDBG_H("Posting IPA_WAN_GW_ADDR_ADD_EVENT with if index:%d, ipv4 addr:0x%x, mask: 0x%x and gw: 0x%x\n",
										data_addr->if_index,
										data_addr->ipv4_addr,
										data_addr->ipv4_addr_mask,
										data_addr->ipv4_addr_gw);
							}
							evt_data.evt_data = data_addr;
							IPACM_EvtDispatcher::PostEvt(&evt_data);
							/* finish command queue */
						}
					}
				}

				/* ipv6 routing table */
				if((AF_INET6 == msg_ptr->nl_route_info.metainfo.rtm_family) &&
						(msg_ptr->nl_route_info.metainfo.rtm_type == RTN_UNICAST) &&
						((msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_KERNEL) ||
						 (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_BOOT) ||
						 (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_RA)) &&
						((msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN) ||
						 (msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_COMPAT)))
				{
					IPACMDBG("\n GOT valid v6-RTM_NEWROUTE event\n");
					ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_route_info.attr_info.oif_index);
					if(ret_val != IPACM_SUCCESS)
					{
						IPACMERR("Error while getting interface name\n");
						goto fail;
					}

					if(msg_ptr->nl_route_info.attr_info.param_mask & IPA_RTA_PARAM_DST)
					{
						IPACM_NL_REPORT_ADDR( "Route ADD DST:", msg_ptr->nl_route_info.attr_info.dst_addr );
						IPACMDBG("%d, metric %d, dev %s\n",
								msg_ptr->nl_route_info.metainfo.rtm_dst_len,
								msg_ptr->nl_route_info.attr_info.priority,
								dev_name);

						/* insert to command queue */
						data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
						if(data_addr == NULL)
						{
							IPACMERR("unable to allocate memory for event data_addr\n");
							ret_val = -ENOMEM;
							goto fail;
						}

						IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr, msg_ptr->nl_route_info.attr_info.dst_addr);

						data_addr->ipv6_addr[0] = ntohl(data_addr->ipv6_addr[0]);
						data_addr->ipv6_addr[1] = ntohl(data_addr->ipv6_addr[1]);
						data_addr->ipv6_addr[2] = ntohl(data_addr->ipv6_addr[2]);
						data_addr->ipv6_addr[3] = ntohl(data_addr->ipv6_addr[3]);

						mask_value_v6 = msg_ptr->nl_route_info.metainfo.rtm_dst_len;
						for(mask_index = 0; mask_index < 4; mask_index++)
						{
							if(mask_value_v6 >= 32)
							{
								mask_v6(32, &data_addr->ipv6_addr_mask[mask_index]);
								mask_value_v6 -= 32;
							}
							else
							{
								mask_v6(mask_value_v6, &data_addr->ipv6_addr_mask[mask_index]);
								mask_value_v6 = 0;
							}
						}

						IPACMDBG("ADD IPV6 MASK %d: %08x:%08x:%08x:%08x \n",
								msg_ptr->nl_route_info.metainfo.rtm_dst_len,
								data_addr->ipv6_addr_mask[0],
								data_addr->ipv6_addr_mask[1],
								data_addr->ipv6_addr_mask[2],
								data_addr->ipv6_addr_mask[3]);

						data_addr->ipv6_addr_mask[0] = ntohl(data_addr->ipv6_addr_mask[0]);
						data_addr->ipv6_addr_mask[1] = ntohl(data_addr->ipv6_addr_mask[1]);
						data_addr->ipv6_addr_mask[2] = ntohl(data_addr->ipv6_addr_mask[2]);
						data_addr->ipv6_addr_mask[3] = ntohl(data_addr->ipv6_addr_mask[3]);

						evt_data.event = IPA_ROUTE_ADD_EVENT;
						data_addr->if_index = msg_ptr->nl_route_info.attr_info.oif_index;
						data_addr->iptype = IPA_IP_v6;

						IPACMDBG("Posting IPA_ROUTE_ADD_EVENT with if index:%d, ipv6 addr\n",
								data_addr->if_index);
						evt_data.evt_data = data_addr;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
						/* finish command queue */
					}
					if(msg_ptr->nl_route_info.attr_info.param_mask & IPA_RTA_PARAM_GATEWAY)
					{
						IPACM_NL_REPORT_ADDR( "Route ADD ::/0  Next Hop:", msg_ptr->nl_route_info.attr_info.gateway_addr );
						IPACMDBG(" metric %d, dev %s\n",
								msg_ptr->nl_route_info.attr_info.priority,
								dev_name);

						/* insert to command queue */
						data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
						if(data_addr == NULL)
						{
							IPACMERR("unable to allocate memory for event data_addr\n");
							ret_val = -ENOMEM;
							goto fail;
						}

						if(msg_ptr->nl_route_info.attr_info.param_mask & IPA_RTA_PARAM_PRIORITY)
						{
							IPACMDBG_H("ip -6 route add default dev %s metric %d\n",
									dev_name,
									msg_ptr->nl_route_info.attr_info.priority);
						}
						else
						{
							IPACMDBG_H("ip -6 route add default dev %s\n", dev_name);
						}

						IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr, msg_ptr->nl_route_info.attr_info.dst_addr);

						data_addr->ipv6_addr[0]=ntohl(data_addr->ipv6_addr[0]);
						data_addr->ipv6_addr[1]=ntohl(data_addr->ipv6_addr[1]);
						data_addr->ipv6_addr[2]=ntohl(data_addr->ipv6_addr[2]);
						data_addr->ipv6_addr[3]=ntohl(data_addr->ipv6_addr[3]);

						IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr_mask, msg_ptr->nl_route_info.attr_info.dst_addr);

						data_addr->ipv6_addr_mask[0]=ntohl(data_addr->ipv6_addr_mask[0]);
						data_addr->ipv6_addr_mask[1]=ntohl(data_addr->ipv6_addr_mask[1]);
						data_addr->ipv6_addr_mask[2]=ntohl(data_addr->ipv6_addr_mask[2]);
						data_addr->ipv6_addr_mask[3]=ntohl(data_addr->ipv6_addr_mask[3]);

						IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr_gw, msg_ptr->nl_route_info.attr_info.gateway_addr);
						data_addr->ipv6_addr_gw[0] = ntohl(data_addr->ipv6_addr_gw[0]);
						data_addr->ipv6_addr_gw[1] = ntohl(data_addr->ipv6_addr_gw[1]);
						data_addr->ipv6_addr_gw[2] = ntohl(data_addr->ipv6_addr_gw[2]);
						data_addr->ipv6_addr_gw[3] = ntohl(data_addr->ipv6_addr_gw[3]);
						IPACM_NL_REPORT_ADDR( " ", msg_ptr->nl_route_info.attr_info.gateway_addr);

					if(((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) ||
						(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E)) &&
						((data_addr->ipv6_addr[0] & ipv6_unique_local_prefix_mask) == (ipv6_unique_local_prefix & ipv6_unique_local_prefix_mask)) &&
						IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
					{
						IPACMDBG(" updating the l2tp peer route_info\n");
						ipacm_event_data_all data_all;
						memset(&data_all,0,sizeof(ipacm_event_data_all));
						memcpy(&data_all.iface_name, dev_name, sizeof(dev_name));
						memcpy(&data_all.ipv6_addr, data_addr->ipv6_addr, sizeof(data_addr->ipv6_addr));
						IPACM_Iface::ipacmcfg->handle_l2tp_client_gw_info(&data_all, data_addr->ipv6_addr_gw);
					}

						if(msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_COMPAT &&
								strstr(dev_name, ETH_INTF) && IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
						{
							data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
							if(data_fid == NULL)
							{
								IPACMERR("unable to allocate memory for event_ecm data_fid\n");
								ret_val = -ENOMEM;
								goto fail;
							}
							strlcpy(IPACM_Iface::ipacmcfg->iface_table[IPACM_Iface::ipacmcfg->eth_wan_iface_table_idx].iface_name,
									dev_name, sizeof(IPACM_Iface::ipacmcfg->iface_table[IPACM_Iface::ipacmcfg->eth_wan_iface_table_idx].iface_name));
							IPACM_Iface::ipacmcfg->iface_table[IPACM_Iface::ipacmcfg->eth_wan_iface_table_idx].virtualIface = true;

							data_fid->if_index = msg_ptr->nl_route_info.attr_info.oif_index;
							evt_data.event = IPA_USB_LINK_UP_EVENT;
							evt_data.evt_data = data_fid;
							IPACM_EvtDispatcher::PostEvt(&evt_data);
						}

						if(msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN)
						{
							evt_data.event = IPA_ROUTE_ADD_EVENT;
							IPACMDBG("Posting IPA_ROUTE_ADD_EVENT with if index:%d, ipv6 address\n",
									data_addr->if_index);
						}
						else if(msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_COMPAT)
						{
							evt_data.event = IPA_WAN_GW_ADDR_ADD_EVENT;
							IPACMDBG("Posting IPA_WAN_GW_ADDR_ADD_EVENT with if index:%d, ipv6 address\n",
									data_addr->if_index);
						}

						data_addr->if_index = msg_ptr->nl_route_info.attr_info.oif_index;
						data_addr->iptype = IPA_IP_v6;

						evt_data.evt_data = data_addr;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
					}
				}
				break;

			case RTM_DELROUTE:
				IPACMDBG("\nGOT RTM_DELROUTE event\n");
				memset(&(msg_ptr->nl_route_info), 0, sizeof((msg_ptr->nl_route_info)));

				ret_val = ipa_nl_decode_rtm_route((const char *)nlh, nlh->nlmsg_len, &(msg_ptr->nl_route_info));
				if(IPACM_SUCCESS != ret_val)
				{
					IPACMERR("Failed to decode rtm route message\n");
					goto fail;
				}
				/* take care of route delete of default route & uniroute */
				if((msg_ptr->nl_route_info.metainfo.rtm_type == RTN_UNICAST) &&
						((msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_BOOT) ||
						 (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_RA)) &&
						(msg_ptr->nl_route_info.metainfo.rtm_scope == 0) &&
						(msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN))
				{

					if(AF_INET == msg_ptr->nl_route_info.metainfo.rtm_family &&
							msg_ptr->nl_route_info.attr_info.param_mask & IPA_RTA_PARAM_DST)
					{
						ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_route_info.attr_info.oif_index);
						if(ret_val != IPACM_SUCCESS)
						{
							IPACMERR("Error while getting interface name\n");
							goto fail;
						}
						IPACM_NL_REPORT_ADDR( "route del -host ", msg_ptr->nl_route_info.attr_info.dst_addr);
						IPACM_NL_REPORT_ADDR( " gw ", msg_ptr->nl_route_info.attr_info.gateway_addr);
						IPACMDBG("dev %s\n", dev_name);

						/* insert to command queue */
						data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
						if(data_addr == NULL)
						{
							IPACMERR("unable to allocate memory for event data_addr\n");
							ret_val = -ENOMEM;
							goto fail;
						}
						IPACM_EVENT_COPY_ADDR_v4( if_ipv4_addr, msg_ptr->nl_route_info.attr_info.dst_addr);
						temp = (-1);
						if_ipipv4_addr_mask = ntohl(temp);

						evt_data.event = IPA_ROUTE_DEL_EVENT;
						data_addr->if_index = msg_ptr->nl_route_info.attr_info.oif_index;
						data_addr->iptype = IPA_IP_v4;
						data_addr->ipv4_addr = ntohl(if_ipv4_addr);
						data_addr->ipv4_addr_mask = ntohl(if_ipipv4_addr_mask);

						IPACMDBG_H("Posting event IPA_ROUTE_DEL_EVENT with if index:%d, ipv4 address 0x%x, mask:0x%x\n",
								data_addr->if_index,
								data_addr->ipv4_addr,
								data_addr->ipv4_addr_mask);
						evt_data.evt_data = data_addr;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
						/* finish command queue */
					}
					else
					{
						ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_route_info.attr_info.oif_index);
						if(ret_val != IPACM_SUCCESS)
						{
							IPACMERR("Error while getting interface name\n");
							goto fail;
						}

						/* insert to command queue */
						data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
						if(data_addr == NULL)
						{
							IPACMERR("unable to allocate memory for event data_addr\n");
							ret_val = -ENOMEM;
							goto fail;
						}

						if(AF_INET6 == msg_ptr->nl_route_info.metainfo.rtm_family)
						{
							if(msg_ptr->nl_route_info.attr_info.param_mask & IPA_RTA_PARAM_PRIORITY)
							{
								IPACMDBG("ip -6 route del default dev %s metric %d\n",
										dev_name,
										msg_ptr->nl_route_info.attr_info.priority);
							}
							else
							{
								IPACMDBG("ip -6 route del default dev %s\n", dev_name);
							}
							IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr, msg_ptr->nl_route_info.attr_info.dst_addr);
							data_addr->ipv6_addr[0] = ntohl(data_addr->ipv6_addr[0]);
							data_addr->ipv6_addr[1] = ntohl(data_addr->ipv6_addr[1]);
							data_addr->ipv6_addr[2] = ntohl(data_addr->ipv6_addr[2]);
							data_addr->ipv6_addr[3] = ntohl(data_addr->ipv6_addr[3]);

							IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr_mask, msg_ptr->nl_route_info.attr_info.dst_addr);
							data_addr->ipv6_addr_mask[0] = ntohl(data_addr->ipv6_addr_mask[0]);
							data_addr->ipv6_addr_mask[1] = ntohl(data_addr->ipv6_addr_mask[1]);
							data_addr->ipv6_addr_mask[2] = ntohl(data_addr->ipv6_addr_mask[2]);
							data_addr->ipv6_addr_mask[3] = ntohl(data_addr->ipv6_addr_mask[3]);

							IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr_gw, msg_ptr->nl_route_info.attr_info.gateway_addr);
							data_addr->ipv6_addr_gw[0] = ntohl(data_addr->ipv6_addr_gw[0]);
							data_addr->ipv6_addr_gw[1] = ntohl(data_addr->ipv6_addr_gw[1]);
							data_addr->ipv6_addr_gw[2] = ntohl(data_addr->ipv6_addr_gw[2]);
							data_addr->ipv6_addr_gw[3] = ntohl(data_addr->ipv6_addr_gw[3]);
							IPACM_NL_REPORT_ADDR( " ", msg_ptr->nl_route_info.attr_info.gateway_addr);
							data_addr->iptype = IPA_IP_v6;

						if(((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) ||
			 			(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E)) &&
						((data_addr->ipv6_addr[0] & ipv6_unique_local_prefix_mask) == (ipv6_unique_local_prefix & ipv6_unique_local_prefix_mask)) &&
						IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
						{
							IPACMDBG(" updating the l2tp peer route_info\n");
							ipacm_event_data_all data_all;
							memset(&data_all,0,sizeof(ipacm_event_data_all));
							memcpy(&data_all.iface_name, dev_name, sizeof(dev_name));
							memcpy(&data_all.ipv6_addr, data_addr->ipv6_addr, sizeof(data_addr->ipv6_addr));
							IPACM_Iface::ipacmcfg->del_l2tp_client_gw_info(&data_all, data_addr->ipv6_addr_gw);
						}
						}
						else
						{
							IPACM_NL_REPORT_ADDR( "route del default gw\n", msg_ptr->nl_route_info.attr_info.gateway_addr);
							IPACMDBG("dev %s\n", dev_name);

							IPACM_EVENT_COPY_ADDR_v4( data_addr->ipv4_addr, msg_ptr->nl_route_info.attr_info.dst_addr);
							data_addr->ipv4_addr = ntohl(data_addr->ipv4_addr);

							IPACM_EVENT_COPY_ADDR_v4( data_addr->ipv4_addr_mask, msg_ptr->nl_route_info.attr_info.dst_addr);
							data_addr->ipv4_addr_mask = ntohl(data_addr->ipv4_addr_mask);

							data_addr->iptype = IPA_IP_v4;
						}

						evt_data.event = IPA_ROUTE_DEL_EVENT;
						data_addr->if_index = msg_ptr->nl_route_info.attr_info.oif_index;

						IPACMDBG_H("Posting IPA_ROUTE_DEL_EVENT with if index:%d\n",
								data_addr->if_index);
						evt_data.evt_data = data_addr;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
						/* finish command queue */
					}
				}

				/* ipv6 routing table */
				if((AF_INET6 == msg_ptr->nl_route_info.metainfo.rtm_family) &&
						(msg_ptr->nl_route_info.metainfo.rtm_type == RTN_UNICAST) &&
						(msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_KERNEL) &&
						(msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN))
				{
					IPACMDBG("\n GOT valid v6-RTM_DELROUTE event\n");
					ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_route_info.attr_info.oif_index);
					if(ret_val != IPACM_SUCCESS)
					{
						IPACMERR("Error while getting interface name");
						goto fail;
					}

					if(msg_ptr->nl_route_info.attr_info.param_mask & IPA_RTA_PARAM_DST)
					{
						IPACM_NL_REPORT_ADDR( "DEL", msg_ptr->nl_route_info.attr_info.dst_addr);
						IPACMDBG("/%d, metric %d, dev %s\n",
								msg_ptr->nl_route_info.metainfo.rtm_dst_len,
								msg_ptr->nl_route_info.attr_info.priority,
								dev_name);

						/* insert to command queue */
						data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
						if(data_addr == NULL)
						{
							IPACMERR("unable to allocate memory for event data_addr\n");
							ret_val = -ENOMEM;
							goto fail;
						}

						IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr, msg_ptr->nl_route_info.attr_info.dst_addr);

						data_addr->ipv6_addr[0] = ntohl(data_addr->ipv6_addr[0]);
						data_addr->ipv6_addr[1] = ntohl(data_addr->ipv6_addr[1]);
						data_addr->ipv6_addr[2] = ntohl(data_addr->ipv6_addr[2]);
						data_addr->ipv6_addr[3] = ntohl(data_addr->ipv6_addr[3]);

						mask_value_v6 = msg_ptr->nl_route_info.metainfo.rtm_dst_len;
						for(mask_index = 0; mask_index < 4; mask_index++)
						{
							IPACMDBG("%dst %d \n",
									mask_index,
									mask_value_v6);
							if(mask_value_v6 >= 32)
							{
								mask_v6(32, &data_addr->ipv6_addr_mask[mask_index]);
								mask_value_v6 -= 32;
								IPACMDBG("%dst: %08x \n",
										mask_index,
										data_addr->ipv6_addr_mask[mask_index]);
							}
							else
							{
								mask_v6(mask_value_v6, data_addr->ipv6_addr_mask);
								mask_value_v6 = 0;
								IPACMDBG("%dst: %08x \n",
										mask_index,
										data_addr->ipv6_addr_mask[mask_index]);
							}
						}

						IPACMDBG("DEL IPV6 MASK 0st: %08x ",
								data_addr->ipv6_addr_mask[0]);
						IPACMDBG("1st: %08x ",
								data_addr->ipv6_addr_mask[1]);
						IPACMDBG("2st: %08x ",
								data_addr->ipv6_addr_mask[2]);
						IPACMDBG("3st: %08x \n",
								data_addr->ipv6_addr_mask[3]);

						data_addr->ipv6_addr_mask[0] = ntohl(data_addr->ipv6_addr_mask[0]);
						data_addr->ipv6_addr_mask[1] = ntohl(data_addr->ipv6_addr_mask[1]);
						data_addr->ipv6_addr_mask[2] = ntohl(data_addr->ipv6_addr_mask[2]);
						data_addr->ipv6_addr_mask[3] = ntohl(data_addr->ipv6_addr_mask[3]);

						evt_data.event = IPA_ROUTE_DEL_EVENT;
						data_addr->if_index = msg_ptr->nl_route_info.attr_info.oif_index;
						data_addr->iptype = IPA_IP_v6;

						IPACMDBG_H("posting event IPA_ROUTE_DEL_EVENT with if index:%d, ipv4 address\n",
								data_addr->if_index);
						evt_data.evt_data = data_addr;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
						/* finish command queue */
					}
				}
				break;

			case RTM_NEWNEIGH:
				IPACMDBG("\nGOT RTM_NEWNEIGH event\n");
				memset(&(msg_ptr->nl_neigh_info), 0, sizeof((msg_ptr->nl_neigh_info)));

				ret_val = ipa_nl_decode_rtm_neigh((const char *)nlh, nlh->nlmsg_len, &(msg_ptr->nl_neigh_info));
				if(IPACM_SUCCESS != ret_val)
				{
					IPACMERR("Failed to decode rtm neighbor message\n");
					goto fail;
				}

				IPACMDBG("NDA_LLADDR:MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
						(unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[0],
						(unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[1],
						(unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[2],
						(unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[3],
						(unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[4],
						(unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[5]);

				ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_neigh_info.metainfo.ndm_ifindex);
				if(ret_val != IPACM_SUCCESS)
				{
					IPACMERR("Error while getting interface index\n");
					goto fail;
				}
				else
				{
					IPACMDBG("\n GOT RTM_NEWNEIGH event (%s) ip %d\n",dev_name,msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family);
				}
				IPACMDBG("Neighbour event with interface index %d master interface index %d family %d\n", msg_ptr->nl_neigh_info.metainfo.ndm_ifindex, msg_ptr->nl_neigh_info.master_interface_index, msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family);

				if(iface_name != NULL)
				{
					if(strncmp(iface_name, dev_name, strlen(iface_name)) != 0)
					{
						IPACMDBG("Skiping this neighbor as it does not belong"
							 " to interface %s\n", iface_name);
						goto fail;
					}
				}

				if(((msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family == AF_INET) ||
							(msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family == AF_INET6)) &&
						(msg_ptr->nl_neigh_info.metainfo.ndm_state != NUD_REACHABLE) && (msg_ptr->nl_neigh_info.metainfo.ndm_state != NUD_PERMANENT))
				{
					IPACMDBG_H("RTM_NEWNEIGH received with NOARP. Ignoring\n");
					goto next_msg;
				}
				IPACMDBG_H("RTM_NEWNEIGH received with state[%02X]\n", msg_ptr->nl_neigh_info.metainfo.ndm_state);

				if((msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data[0] == 0x33) &&
						(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data[1] == 0x33))
				{
					IPACMDBG_H("RTM_NEWNEIGH received with ipv6 brodcast mac address. So Ignoring\n");
					goto next_msg;
				}
				if((msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data[0] == 0x01) &&
						(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data[1] == 0x00) &&
						(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data[2] == 0x5e))
				{
					IPACMDBG_H("RTM_NEWNEIGH received with ipv4 brodcast mac address. So Ignoring\n");
					goto next_msg;
				}

				memset(&vlan_event, 0, sizeof(vlan_event));

				if((msg_ptr->nl_neigh_info.metainfo.ndm_ifindex != 0) && (msg_ptr->nl_neigh_info.master_interface_index == 0) &&
						(msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family != 0))
				{
					vlan_event.event = IPA_ADD_BRIDGE_VLAN_BR_INTF;
					IPACMDBG("Performing IPA_ADD_BRIDGE_VLAN_BR_INTF with interface index %d and master interface index %d\n", msg_ptr->nl_neigh_info.metainfo.ndm_ifindex, msg_ptr->nl_neigh_info.master_interface_index);

				}
				else if ((msg_ptr->nl_neigh_info.metainfo.ndm_ifindex != 0) && (msg_ptr->nl_neigh_info.master_interface_index != 0) &&
						(msg_ptr->nl_neigh_info.master_interface_index != msg_ptr->nl_neigh_info.metainfo.ndm_ifindex))
				{
					IPACMDBG("Performing IPA_ADD_BRIDGE_VLAN_PHY_INTF with interface index %d and master interface index %d\n", msg_ptr->nl_neigh_info.metainfo.ndm_ifindex, msg_ptr->nl_neigh_info.master_interface_index);
					vlan_event.event = IPA_ADD_BRIDGE_VLAN_PHY_INTF;

				}
				if((vlan_event.event == IPA_ADD_BRIDGE_VLAN_BR_INTF) || (vlan_event.event == IPA_ADD_BRIDGE_VLAN_PHY_INTF))
				{
					vlan_data = (ipacm_event_data_all *)calloc(1, sizeof(ipacm_event_data_all));
					if(vlan_data == NULL)
					{
						IPACMERR("unable to allocate memory for vlan_data\n");
						ret_val = -ENOMEM;
						goto fail;
					}
					vlan_data->if_index = msg_ptr->nl_neigh_info.metainfo.ndm_ifindex;
					vlan_data->master_if_index = msg_ptr->nl_neigh_info.master_interface_index;
					strlcpy(vlan_data->iface_name, dev_name, sizeof(vlan_data->iface_name));
					vlan_event.evt_data = (void *)vlan_data;
					IPACM_EvtDispatcher::PostEvt(&vlan_event);
				}

				// This check is to  prevent handling of netlink messages with NULL MAC addr
				if(!(memcmp(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data,
								nullMac,sizeof(nullMac))))
				{
					IPACMDBG_H("RTM_NEWNEIGH received with NULL MAC\n");
					goto next_msg;
				}

				/* insert to command queue */
				data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
				if(data_all == NULL)
				{
					IPACMERR("unable to allocate memory for event data_all\n");
					ret_val = -ENOMEM;
					goto fail;
				}

				memset(data_all, 0, sizeof(ipacm_event_data_all));
				if(msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family == AF_INET6)
				{
					IPACM_NL_REPORT_ADDR( " ", msg_ptr->nl_neigh_info.attr_info.local_addr);
					IPACM_EVENT_COPY_ADDR_v6( data_all->ipv6_addr, msg_ptr->nl_neigh_info.attr_info.local_addr);

					data_all->ipv6_addr[0]=ntohl(data_all->ipv6_addr[0]);
					data_all->ipv6_addr[1]=ntohl(data_all->ipv6_addr[1]);
					data_all->ipv6_addr[2]=ntohl(data_all->ipv6_addr[2]);
					data_all->ipv6_addr[3]=ntohl(data_all->ipv6_addr[3]);
					data_all->iptype = IPA_IP_v6;
					if(query)
					{
						IPACMDBG("Queried Neighbor V6 address: 0x%x:%x:%x:%x\n",
							data_all->ipv6_addr[0], data_all->ipv6_addr[1],
							data_all->ipv6_addr[2], data_all->ipv6_addr[3]);
						config->queried_v6_list.push_back({data_all->ipv6_addr[0],
										data_all->ipv6_addr[1],
										data_all->ipv6_addr[2],
										data_all->ipv6_addr[3]});
					}
				}
				else if (msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family == AF_INET)
				{
					IPACM_NL_REPORT_ADDR( " ", msg_ptr->nl_neigh_info.attr_info.local_addr);
					IPACM_EVENT_COPY_ADDR_v4( data_all->ipv4_addr, msg_ptr->nl_neigh_info.attr_info.local_addr);
					data_all->ipv4_addr = ntohl(data_all->ipv4_addr);
					data_all->iptype = IPA_IP_v4;
					if(query)
					{
						IPACMDBG("Queried Neighbor V4 address: 0x%x\n", data_all->ipv4_addr);
						config->queried_v4_list.push_back(data_all->ipv4_addr);
					}
				}
				else
				{
					IPACMDBG_H("ss_family = %d\n", msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family);
					data_all->iptype = IPA_IP_v6;
				}

				memcpy(data_all->mac_addr,
						msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data,
						sizeof(data_all->mac_addr));
				data_all->if_index = msg_ptr->nl_neigh_info.metainfo.ndm_ifindex;
				strlcpy(data_all->iface_name, dev_name, sizeof(data_all->iface_name));

				IPACMDBG_H("for IF %s, got ndm_family %d, ndm_state %d\n", dev_name, msg_ptr->nl_neigh_info.metainfo.ndm_family,
						msg_ptr->nl_neigh_info.metainfo.ndm_state);

				/* Add support to replace src-mac as bridge0 mac */
				if((msg_ptr->nl_neigh_info.metainfo.ndm_family == AF_BRIDGE) &&
						(msg_ptr->nl_neigh_info.metainfo.ndm_state == NUD_PERMANENT))
				{
					/* Posting IPA_BRIDGE_LINK_UP_EVENT event */
					evt_data.event = IPA_BRIDGE_LINK_UP_EVENT;
					IPACMDBG_H("posting IPA_BRIDGE_LINK_UP_EVENT (%s):index:%d \n",
							dev_name,
							data_all->if_index);
				}
				else
				{
					/* Posting new_neigh events for all LAN/WAN clients */
					evt_data.event = IPA_NEW_NEIGH_EVENT;
					IPACMDBG_H("posting IPA_NEW_NEIGH_EVENT (%s):index:%d ip-family: %d\n",
							dev_name, data_all->if_index,
							msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family);

					/* Add Dummy VLAN Mapping for Non-Vlan Ifaces */
					idx = IPACM_Iface::iface_ipa_index_query(msg_ptr->nl_neigh_info.metainfo.ndm_ifindex);
					if((config != NULL) && ((idx != INVALID_IFACE && config->iface_table[idx].if_cat != WAN_IF &&
									!config->iface_in_vlan_mode(dev_name)) || config->check_l2tp_iface(data_all->iface_name)))
					{
						if((msg_ptr->nl_neigh_info.metainfo.ndm_ifindex != msg_ptr->nl_neigh_info.master_interface_index))
						{
							memset(master_dev_name,0,IF_NAME_LEN);
							if(msg_ptr->nl_neigh_info.master_interface_index &&
									ipa_get_if_name(master_dev_name, msg_ptr->nl_neigh_info.master_interface_index) == IPACM_SUCCESS)
							{
								memset(&vlan_bridge_data, 0, sizeof(vlan_bridge_data));
								vlan_bridge_data.vlan_id = DUMMY_VLAN_ID_BASE+ msg_ptr->nl_neigh_info.metainfo.ndm_ifindex;
								strlcpy(vlan_bridge_data.bridge_name, master_dev_name, IF_NAME_LEN);
								IPACM_Iface::iface_addr_query(msg_ptr->nl_neigh_info.master_interface_index, false, &if_ipv4_addr, &if_ipipv4_addr_mask);
								vlan_bridge_data.bridge_ipv4 = if_ipv4_addr;
								vlan_bridge_data.subnet_mask = if_ipipv4_addr_mask;
								vlan_bridge_data.master_if_index = msg_ptr->nl_neigh_info.master_interface_index;
#ifdef IPA_L2TP_TUNNEL_UDP
								if(config->check_l2tp_iface(data_all->iface_name))
								{
									vlan_bridge_data.vlan_id = DUMMY_VLAN_ID_BASE+ msg_ptr->nl_neigh_info.master_interface_index;
									config->add_l2tp_dummy_vlan_mapping(master_dev_name, data_all->iface_name,
											msg_ptr->nl_neigh_info.master_interface_index);
									config->add_bridge_vlan_mapping(&vlan_bridge_data);
									vlan_bridge_data.status = 1;
									config->add_bridge_vlan_mapping(&vlan_bridge_data);
								}
								else
#endif
								{
									vlan_data = (ipacm_event_data_all *)calloc(1, sizeof(*vlan_data));
									if(!vlan_data) {
										IPACMERR("malloc failed\n");
										ret_val = -ENOMEM;
										goto fail;
									}
									vlan_data->if_index = msg_ptr->nl_neigh_info.metainfo.ndm_ifindex;
									vlan_data->master_if_index = msg_ptr->nl_neigh_info.master_interface_index;
									bridge_evt_data.evt_data = vlan_data;
									bridge_evt_data.event = IPA_WLAN_BRIDGE_UPDATE_EVENT;
									IPACM_EvtDispatcher::PostEvt(&bridge_evt_data);
								}
							}
						}
					}
				}
				evt_data.evt_data = data_all;
				IPACM_EvtDispatcher::PostEvt(&evt_data);
				/* finish command queue */
				break;

			case RTM_DELNEIGH:
				IPACMDBG("\nGOT RTM_DELNEIGH event\n");
				memset(&(msg_ptr->nl_neigh_info), 0, sizeof((msg_ptr->nl_neigh_info)));

				ret_val = ipa_nl_decode_rtm_neigh((const char *)nlh, nlh->nlmsg_len, &(msg_ptr->nl_neigh_info));
				if(IPACM_SUCCESS != ret_val)
				{
					IPACMERR("Failed to decode rtm neighbor message\n");
					goto fail;
				}

				IPACMDBG("NDA_LLADDR:MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
						(unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[0],
						(unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[1],
						(unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[2],
						(unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[3],
						(unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[4],
						(unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[5]);

				ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_neigh_info.metainfo.ndm_ifindex);
				if(ret_val != IPACM_SUCCESS)
				{
					IPACMERR("Error while getting interface index\n");
					goto fail;
				}
				else
				{
					IPACMDBG("\n GOT RTM_DELNEIGH event (%s) ip %d\n",dev_name,msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family);
				}

				//This check is to prevent handling of netlink messages with NULL MAC addr
				if(!(memcmp(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data,
								nullMac,sizeof(nullMac))))
				{
					IPACMDBG_H("RTM_DELNEIGH received with NULL MAC\n");
					goto next_msg;
				}
				if((msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data[0] == 0x33) &&
						(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data[1] == 0x33))
				{
					IPACMDBG_H("RTM_DELNEIGH received with ipv6 brodcast mac address. So Ignoring\n");
					goto next_msg;
				}
				if((msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data[0] == 0x01) &&
						(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data[1] == 0x00) &&
						(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data[2] == 0x5e))
				{
					IPACMDBG_H("RTM_DELNEIGH received with ipv4 brodcast mac address. So Ignoring\n");
					goto next_msg;
				}

				/* insert to command queue */
				data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
				if(data_all == NULL)
				{
					IPACMERR("unable to allocate memory for event data_all\n");
					ret_val = -ENOMEM;
					goto fail;
				}

				memset(data_all, 0, sizeof(ipacm_event_data_all));

				strlcpy(data_all->iface_name, dev_name, sizeof(data_all->iface_name));

				if(msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family == AF_INET6)
				{
					IPACM_NL_REPORT_ADDR(" ", msg_ptr->nl_neigh_info.attr_info.local_addr);
					IPACM_EVENT_COPY_ADDR_v6(data_all->ipv6_addr, msg_ptr->nl_neigh_info.attr_info.local_addr);

					data_all->ipv6_addr[0] = ntohl(data_all->ipv6_addr[0]);
					data_all->ipv6_addr[1] = ntohl(data_all->ipv6_addr[1]);
					data_all->ipv6_addr[2] = ntohl(data_all->ipv6_addr[2]);
					data_all->ipv6_addr[3] = ntohl(data_all->ipv6_addr[3]);
					data_all->iptype = IPA_IP_v6;
				}
				else if (msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family == AF_INET)
				{
					IPACM_NL_REPORT_ADDR(" ", msg_ptr->nl_neigh_info.attr_info.local_addr);
					IPACM_EVENT_COPY_ADDR_v4(data_all->ipv4_addr, msg_ptr->nl_neigh_info.attr_info.local_addr);
					data_all->ipv4_addr = ntohl(data_all->ipv4_addr);
					data_all->iptype = IPA_IP_v4;
				}
				else
				{
					data_all->iptype = IPA_IP_v6;
				}

				memcpy(data_all->mac_addr,
						msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data,
						sizeof(data_all->mac_addr));
				evt_data.event = IPA_DEL_NEIGH_EVENT;
				data_all->if_index = msg_ptr->nl_neigh_info.metainfo.ndm_ifindex;

				IPACMDBG_H("posting IPA_DEL_NEIGH_EVENT (%s):index:%d ip-family: %d\n",
						dev_name,
						data_all->if_index,
						msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family);
				evt_data.evt_data = data_all;
				IPACM_EvtDispatcher::PostEvt(&evt_data);
				break;

			default:
				IPACMDBG(" ignore NL event %d!!!\n ", nlh->nlmsg_type);
				break;

		}
		goto next_msg;
fail:
		IPACMDBG("Msg[%p] failed to process with ret[%d]\n", nlh, ret_val);
next_msg:
		nlh = NLMSG_NEXT(nlh, buflen);
	}

	return ret_val;
}


/*  Virtual function registered to receive incoming messages over the NETLINK routing socket*/
int ipa_nl_recv_msg(int fd)
{
	struct msghdr *msghdr = NULL;
	struct iovec *iov = NULL;
	unsigned int msglen = 0;
	ipa_nl_msg_t *nlmsg = NULL;
	int ret_val = IPACM_SUCCESS;

	nlmsg = (ipa_nl_msg_t *)malloc(sizeof(ipa_nl_msg_t));
	if(NULL == nlmsg)
	{
		IPACMERR("Failed alloc of nlmsg \n");
		ret_val = -ENOMEM;
		goto error;
	}
	else
	{
		ret_val = ipa_nl_recv(fd, &msghdr, &msglen);
		if((IPACM_SUCCESS != ret_val) || (msghdr == NULL))
		{
			IPACMERR("Failed to receive nl message ret_val[%d], msghdr[%p]\n", ret_val, msghdr);
			goto error;
		}

		iov = msghdr->msg_iov;

		memset(nlmsg, 0, sizeof(ipa_nl_msg_t));
		if(IPACM_SUCCESS != ipa_nl_decode_nlmsg((char *)iov->iov_base, msglen, nlmsg, NULL))
		{
			IPACMERR("Failed to decode nl message, ret_val[%d]\n", ret_val);
			goto error;
		}
		ret_val = IPACM_SUCCESS;
	}

error:
	/* Release NetLink message buffer */
	if(msghdr)
	{
		ipa_nl_release_msg(msghdr);
	}
	if(nlmsg)
	{
		free(nlmsg);
	}

	return ret_val;
}

/*  get ipa interface name */
int ipa_get_if_name
(
	 char *if_name,
	 int if_index
	 )
{
	int fd;
	struct ifreq ifr;

	if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		IPACMERR("err: %s in open socket for iface name\n",strerror(errno));
		return IPACM_FAILURE;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	ifr.ifr_ifindex = if_index;
	IPACMDBG("Interface index %d\n", if_index);

	if(ioctl(fd, SIOCGIFNAME, &ifr) < 0)
	{
		IPACMERR("call_ioctl_on_dev: ioctl failed: %d:\n", errno);
		close(fd);
		return IPACM_FAILURE;
	}

	(void)strlcpy(if_name, ifr.ifr_name, sizeof(ifr.ifr_name));
	IPACMDBG("interface name %s\n", ifr.ifr_name);
	close(fd);

	return IPACM_SUCCESS;
}

/* Initialization routine for listener on NetLink sockets interface */
int ipa_nl_listener_init
(
	 unsigned int nl_type,
	 unsigned int nl_groups,
	 ipa_nl_sk_fd_set_info_t *sk_fdset,
	 ipa_sock_thrd_fd_read_f read_f,
	 ipa_nl_sk_info_t *sk_info
	 )
{
	int ret_val;
	int max_retries = 100;
	int retry_delay = 2000;
	int retry_count = 0;

	memset(sk_info, 0, sizeof(ipa_nl_sk_info_t));
	IPACMDBG_H("Entering IPA NL listener init\n");

	if(ipa_nl_open_socket(sk_info, nl_type, nl_groups) >= 0)
	{
		IPACMDBG_H("IPA Open netlink socket succeeds\n");
	}
	else
	{
		IPACMERR("Netlink socket open failed\n");
		while (retry_count < max_retries) {
			memset(sk_info, 0, sizeof(ipa_nl_sk_info_t));
			if (ipa_nl_open_socket(sk_info, nl_type, nl_groups) >= 0) {
				IPACMDBG_H("IPA Open netlink socket succeeds\n");
				break;
			} else {
				IPACMERR("Netlink socket open failed\n");
				retry_count++;
				if (retry_count < max_retries) {
					IPACMDBG("Retrying in %d ms...\n", retry_delay);
					usleep(retry_delay * 1000);
				} else {
					IPACMERR("Exceeded maximum retry attempts\n");
					break;
				}
			}
		}

		if (retry_count == max_retries) {
			IPACMERR("Exceeded maximum retry attempts\n");
			close(sk_info->sk_fd);
			return IPACM_FAILURE;
		}
	}

	/* Add NETLINK socket to the list of sockets that the listener
					 thread should listen on. */

	if(ipa_nl_addfd_map(sk_fdset, sk_info->sk_fd, read_f) != IPACM_SUCCESS)
	{
		IPACMERR("cannot add nl routing sock for reading\n");
		close(sk_info->sk_fd);
		return IPACM_FAILURE;
	}
	ret_val = ipa_nl_sock_listener_start(sk_fdset);

	if(ret_val != IPACM_SUCCESS)
	{
		IPACMERR("Failed to start NL listener\n");
	}

	return IPACM_SUCCESS;
}

int recv_genl(struct nlmsghdr *nlh, ipa_nl_l2tp_info_t *l2tp_attr_info)
{
	char *message;
	uint32_t data32;
	uint16_t data16;
	uint8_t data8;
	int fd_attr;
	struct in6_addr *v6_addr;
	struct in6_addr saddr6;
	struct in6_addr daddr6;

	struct nlattr *attrs[L2TP_ATTR_MAX + 1];

	IPACMDBG_H("recv_genl\n");

	if(genlmsg_parse(nlh, 0, attrs, L2TP_ATTR_MAX, NULL))
	{
		IPACMDBG_H("genlmsg_parse failed");
		return NL_SKIP;
	}

	if(attrs[L2TP_ATTR_NONE])
	{
		IPACMDBG_H("received data is NULL");
		return NL_SKIP;
	}

	if(attrs[L2TP_ATTR_ENCAP_TYPE])
	{
		data16 = nla_get_u16(attrs[L2TP_ATTR_ENCAP_TYPE]);
		l2tp_attr_info->encap_type = data16;
		IPACMDBG_H("received data_encap=%hu\n",data16);
	}

	if(attrs[L2TP_ATTR_CONN_ID])
	{
		data32 = nla_get_u32(attrs[L2TP_ATTR_CONN_ID]);
		l2tp_attr_info->tunnel_id = data32;
		IPACMDBG_H("received data_conn_id=%u\n",data32);
	}

	if(attrs[L2TP_ATTR_SESSION_ID])
	{
		data32 = nla_get_u32(attrs[L2TP_ATTR_SESSION_ID]);
		l2tp_attr_info->session_id = data32;
		IPACMDBG_H("received session id=%u\n",data32);
	}

	if(attrs[L2TP_ATTR_IFNAME])
	{
		message = nla_get_string(attrs[L2TP_ATTR_IFNAME]);
		strlcpy(l2tp_attr_info->l2tp_iface_name, message, sizeof(l2tp_attr_info->l2tp_iface_name));
		IPACMDBG_H("received data_ifname=%s\n",message);
	}

	if(attrs[L2TP_ATTR_UDP_SPORT])
	{
		data16 = nla_get_u16(attrs[L2TP_ATTR_UDP_SPORT]);
		l2tp_attr_info->src_port = data16;
		IPACMDBG_H("received source port=%hu\n",data16);
	}

	if(attrs[L2TP_ATTR_UDP_DPORT])
	{
		data16 = nla_get_u16(attrs[L2TP_ATTR_UDP_DPORT]);
		l2tp_attr_info->dst_port = data16;
		IPACMDBG_H("received dst port=%hu\n",data16);
	}

	if(attrs[L2TP_ATTR_IP6_SADDR])
	{
		v6_addr = (struct in6_addr *)nla_data(attrs[L2TP_ATTR_IP6_SADDR]);
		memcpy(l2tp_attr_info->src_ipv6_addr, v6_addr, 4*sizeof(uint32_t));
		l2tp_attr_info->src_ipv6_addr[0] = ntohl(l2tp_attr_info->src_ipv6_addr[0]);
		l2tp_attr_info->src_ipv6_addr[1] = ntohl(l2tp_attr_info->src_ipv6_addr[1]);
		l2tp_attr_info->src_ipv6_addr[2] = ntohl(l2tp_attr_info->src_ipv6_addr[2]);
		l2tp_attr_info->src_ipv6_addr[3] = ntohl(l2tp_attr_info->src_ipv6_addr[3]);
		IPACMDBG_H("received src addr:0x%x:%x:%x:%x\n",l2tp_attr_info->src_ipv6_addr[0],l2tp_attr_info->src_ipv6_addr[1],
			l2tp_attr_info->src_ipv6_addr[2],l2tp_attr_info->src_ipv6_addr[3]);
	}

	if(attrs[L2TP_ATTR_IP6_DADDR])
	{
		v6_addr = (struct in6_addr *)nla_data(attrs[L2TP_ATTR_IP6_DADDR]);
		memcpy(l2tp_attr_info->dst_ipv6_addr, v6_addr, 4*sizeof(uint32_t));
		l2tp_attr_info->dst_ipv6_addr[0] = ntohl(l2tp_attr_info->dst_ipv6_addr[0]);
		l2tp_attr_info->dst_ipv6_addr[1] = ntohl(l2tp_attr_info->dst_ipv6_addr[1]);
		l2tp_attr_info->dst_ipv6_addr[2] = ntohl(l2tp_attr_info->dst_ipv6_addr[2]);
		l2tp_attr_info->dst_ipv6_addr[3] = ntohl(l2tp_attr_info->dst_ipv6_addr[3]);
		IPACMDBG_H("received dst addr:0x%x:%x:%x:%x\n",l2tp_attr_info->dst_ipv6_addr[0],l2tp_attr_info->dst_ipv6_addr[1],
			l2tp_attr_info->dst_ipv6_addr[2],l2tp_attr_info->dst_ipv6_addr[3]);
	}

	IPACMDBG_H("exit recv_genl\n");

	return NL_OK;
}

int recv_genl_msg(struct nl_msg *msg,void *arg)
{
	ipa_nl_l2tp_info_t l2tp_attr_info;
	struct l2tp_tunnel_info tunnel_info;
	struct l2tp_session_info session_info;
	int ret = 0;
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct genlmsghdr *gnlh = genlmsg_hdr(nlh);

	IPACMDBG_H("exit recv_genl_msg cmd_id : %d\n",gnlh->cmd);

	memset(&l2tp_attr_info, 0, sizeof(ipa_nl_l2tp_info_t));
	ret = recv_genl(nlh, &l2tp_attr_info);
	if(ret != NL_OK)
	{
		IPACMERR("Unable to parse msg\n");
		return ret;
	}

	switch(gnlh->cmd)
	{
		case L2TP_CMD_TUNNEL_CREATE:
			IPACMDBG_H("kernel_tunnel creation\n");
			tunnel_info.l2tp_tunnel_id = l2tp_attr_info.tunnel_id;
			tunnel_info.tunnel_type = l2tp_attr_info.encap_type ? IPA_L2TP_TUNNEL_IP :
										IPA_L2TP_TUNNEL_UDP;
			tunnel_info.src_port = l2tp_attr_info.src_port;
			tunnel_info.dst_port = l2tp_attr_info.dst_port;
			memcpy(tunnel_info.src_ipv6_addr, l2tp_attr_info.src_ipv6_addr, 4*sizeof(uint32_t));
			memcpy(tunnel_info.dst_ipv6_addr, l2tp_attr_info.dst_ipv6_addr, 4*sizeof(uint32_t));
			IPACM_Iface::ipacmcfg->add_l2tp_tunnel_info(&tunnel_info);
			break;

		case L2TP_CMD_TUNNEL_DELETE:
			IPACMDBG_H("kernel_tunnel deletion\n");
			tunnel_info.l2tp_tunnel_id = l2tp_attr_info.tunnel_id;
			tunnel_info.src_port = l2tp_attr_info.src_port;
			tunnel_info.dst_port = l2tp_attr_info.dst_port;
			memcpy(tunnel_info.src_ipv6_addr, l2tp_attr_info.src_ipv6_addr, 4*sizeof(uint32_t));
			memcpy(tunnel_info.dst_ipv6_addr, l2tp_attr_info.dst_ipv6_addr, 4*sizeof(uint32_t));
			IPACM_Iface::ipacmcfg->del_l2tp_tunnel_info(tunnel_info.l2tp_tunnel_id);
			break;

		case L2TP_CMD_SESSION_CREATE:
			IPACMDBG_H("kernel_session creation\n");
			strlcpy(session_info.l2tp_iface_name, l2tp_attr_info.l2tp_iface_name,
				sizeof(session_info.l2tp_iface_name));
			session_info.l2tp_session_id = l2tp_attr_info.session_id;
			session_info.l2tp_tunnel_id = l2tp_attr_info.tunnel_id;
			IPACM_Iface::ipacmcfg->add_l2tp_vlan_mapping(&session_info);
			break;

		case L2TP_CMD_SESSION_DELETE:
			IPACMDBG_H("kernel_session deletion\n");
			strlcpy(session_info.l2tp_iface_name, l2tp_attr_info.l2tp_iface_name,
				sizeof(session_info.l2tp_iface_name));
			session_info.l2tp_session_id = l2tp_attr_info.session_id;
			session_info.l2tp_tunnel_id = l2tp_attr_info.tunnel_id;
			IPACM_Iface::ipacmcfg->del_l2tp_vlan_mapping(&session_info);
			break;

		case L2TP_CMD_TUNNEL_GET:
			IPACMDBG_H("kernel_tunnel Get\n");
			tunnel_info.l2tp_tunnel_id = l2tp_attr_info.tunnel_id;
			tunnel_info.tunnel_type = l2tp_attr_info.encap_type ? IPA_L2TP_TUNNEL_IP :
				IPA_L2TP_TUNNEL_UDP;
			tunnel_info.src_port = l2tp_attr_info.src_port;
			tunnel_info.dst_port = l2tp_attr_info.dst_port;
			memcpy(tunnel_info.src_ipv6_addr, l2tp_attr_info.src_ipv6_addr, 4*sizeof(uint32_t));
			memcpy(tunnel_info.dst_ipv6_addr, l2tp_attr_info.dst_ipv6_addr, 4*sizeof(uint32_t));
			IPACM_Iface::ipacmcfg->add_l2tp_tunnel_info(&tunnel_info);
			break;
		case L2TP_CMD_SESSION_GET:
			IPACMDBG_H("kernel_session Get\n");
			strlcpy(session_info.l2tp_iface_name, l2tp_attr_info.l2tp_iface_name,
					sizeof(session_info.l2tp_iface_name));
			session_info.l2tp_session_id = l2tp_attr_info.session_id;
			session_info.l2tp_tunnel_id = l2tp_attr_info.tunnel_id;
			IPACM_Iface::ipacmcfg->add_l2tp_vlan_mapping(&session_info);
			break;
		default:
			ret = NL_SKIP;
	}

	IPACMDBG_H("exit recv_genl_msg\n");
	return ret;
}

void *l2tp_nl_process(void *param)
{
	struct nl_sock* sock;
	int family_id = -1;
	int ret = 0;
	int group_id = -1;

	IPACMDBG_H("function l2tp_process start\n");

	sock = nl_socket_alloc();
	if(!sock)
	{
		IPACMDBG_H("allocating nl_sock failed");
		goto handle;
	}

	ret = genl_connect(sock);
	if(ret < 0)
	{
		IPACMDBG_H("genl_connect failed");
		nl_socket_free(sock);
		goto handle;
	}

	family_id = genl_ctrl_resolve(sock,"l2tp");
	if(family_id < 0)
	{
		IPACMDBG_H("genl_ctrl_resolve failed %s",nl_geterror(family_id));
		nl_socket_free(sock);
		goto handle;
	}

	IPACMDBG_H("family_id : %d\n",family_id);

	group_id = genl_ctrl_resolve_grp(sock, "l2tp", "l2tp");
	if(group_id < 0)
	{
		IPACMDBG_H("genl_ctrl_resolve_grp failed\n");
		nl_socket_free(sock);
		goto handle;
	}

	IPACMDBG_H("group_id : %d\n",group_id);

	ret = nl_socket_add_membership(sock, group_id);
	if(ret < 0)
	{
		IPACMDBG_H("nl_socket_add_membership failed");
		nl_socket_free(sock);
		goto handle;
	}

	IPACMDBG_H("nl_socket_add_membership success\n");

	nl_socket_modify_cb(sock, NL_CB_MSG_IN, NL_CB_CUSTOM, &recv_genl_msg, sock);

	IPACMDBG_H("started receiving messages\n");

	while(1)
	{
		nl_recvmsgs_default(sock);
	}

	IPACMDBG_H("freeing netlink socket\n");

	nl_socket_free(sock);

	IPACMDBG_H("function l2tp_process complete\n");

handle:
	return NULL;
}


int ipa_nl_receive(int fd, struct msghdr *msg, int flags)
{
	int len = 0;

	do
	{
		len = recvmsg(fd, msg, flags);
	} while (len < 0 && (errno == EINTR || errno == EAGAIN));

	if (len < 0)
	{
		IPACMERR("Netlink receive failed\n");
		return -errno;
	}

	if (len == 0)
	{
		IPACMERR("EOF on Netlink\n");
		return -ENODATA;
	}

	return len;
}

int ipa_nl_recvmsg(int fd, struct msghdr *msg, char **result)
{
	struct iovec *iov = msg->msg_iov;
	char *buf = NULL;
	int len = 0;

	iov->iov_base = NULL;
	iov->iov_len = 0;

	len = ipa_nl_receive(fd, msg, MSG_PEEK | MSG_TRUNC);

	IPACMDBG_DMESG("Netlink route message length : %d\n", len);

	if (len < 0)
	{
		return len;
	}

	buf = (char *)malloc(len);

	if (!buf)
	{
		IPACMERR("Failed malloc for buffer\n");
		return -ENOMEM;
	}

	memset(buf, 0, len);
	iov->iov_base = buf;
	iov->iov_len = len;

	len = ipa_nl_receive(fd, msg, 0);

	if (len < 0)
	{
		free(buf);
		return len;
	}

	*result = buf;

	return len;
}

int ipa_nl_send_getroute(ipa_ip_type ip_type, char * iface_name)
{

	ipacm_event_data_addr *data_addr = NULL;
	ipacm_event_data_fid *data_fid = NULL;
	int ret_val = IPACM_FAILURE, dump_intr = 0, msglen = 0, nl_sock = 0;
	ipacm_cmd_q_data evt_data;
	uint32_t ipv4_addr = 0, ipv4_addr_mask = 0, temp = 0, ipv4_addr_gw = 0;
	uint32_t if_ipv4_addr =0, if_ipipv4_addr_mask =0, if_ipv4_addr_gw =0;
	ssize_t msgsent_len = 0;
	char *buf = NULL;
	nl_request_t nl_request;
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct nlmsghdr *h = NULL;
	ipa_nl_route_info_t nl_route_info_get_route;
	struct iovec iov;
	char dev_name[IF_NAME_LEN]={0};
	int mask_value, mask_index, mask_value_v6;

	nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (nl_sock < 0)
	{
		IPACMERR("Failed to open netlink socket");
		return IPACM_FAILURE;
	}

	memset(&nl_request, 0, sizeof(nl_request));
	memset(&nladdr, 0, sizeof(sockaddr_nl));
	memset(&evt_data, 0, sizeof(ipacm_cmd_q_data));
	memset(&msg, 0, sizeof(msghdr));
	memset(&nl_route_info_get_route, 0, sizeof(ipa_nl_route_info_t));
	memset(&iov, 0, sizeof(iovec));

	nl_request.nlh.nlmsg_type = RTM_GETROUTE;
	nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_request.nlh.nlmsg_len = sizeof(nl_request);
	nl_request.nlh.nlmsg_seq = time(NULL);
	nl_request.nlh.nlmsg_pid = 0;

	if(ip_type == IPA_IP_v6)
	{
		nl_request.rtm.rtm_family = AF_INET6;
	}
	else
	{
		nl_request.rtm.rtm_family = AF_INET;
	}

	msgsent_len = send(nl_sock, &nl_request, sizeof(nl_request), 0);

	msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	msglen = ipa_nl_recvmsg(nl_sock, &msg, &buf);

	if(msglen <= 0)
	{
		PERROR("NL route recv error\n");
		goto error;
	}

	h = (struct nlmsghdr *)buf;

	IPACMDBG("Route msg_len : %d\n", msglen);

	while (NLMSG_OK(h, msglen))
	{
		if (h->nlmsg_flags & NLM_F_DUMP_INTR)
		{
			IPACMERR("Dump was interrupted\n");
			goto error;
		}

		if (nladdr.nl_pid != 0)
		{
			continue;
		}

		if (h->nlmsg_type == NLMSG_ERROR)
		{
			IPACMERR("Netlink message error");
			goto error;
		}
		memset(&nl_route_info_get_route, 0, sizeof(ipa_nl_route_info_t));
		ipa_nl_decode_rtm_route((char*)h,msglen,&nl_route_info_get_route);
		IPACMDBG("In case RTM_GETROUTE\n");
		IPACMDBG("rtm_type: %d\n", nl_route_info_get_route.metainfo.rtm_type);
		IPACMDBG("protocol: %d\n", nl_route_info_get_route.metainfo.rtm_protocol);
		IPACMDBG("rtm_scope: %d\n", nl_route_info_get_route.metainfo.rtm_scope);
		IPACMDBG("rtm_table: %d\n", nl_route_info_get_route.metainfo.rtm_table);
		IPACMDBG("rtm_family: %d\n", nl_route_info_get_route.metainfo.rtm_family);
		IPACMDBG("param_mask: 0x%x\n", nl_route_info_get_route.attr_info.param_mask);

		/* take care of route add default route & uniroute */
		if((AF_INET == nl_route_info_get_route.metainfo.rtm_family) &&
			 (nl_route_info_get_route.metainfo.rtm_type == RTN_UNICAST) &&
			 ((nl_route_info_get_route.metainfo.rtm_protocol == RTPROT_BOOT) ||
			  (nl_route_info_get_route.metainfo.rtm_protocol == RTPROT_RA)) &&
			 (nl_route_info_get_route.metainfo.rtm_scope == RT_SCOPE_UNIVERSE) &&
			 ((nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_MAIN) ||
			 (nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_COMPAT)))
		{

			if(nl_route_info_get_route.attr_info.param_mask & IPA_RTA_PARAM_DST)
			{
				ret_val = ipa_get_if_name(dev_name, nl_route_info_get_route.attr_info.oif_index);
				if(ret_val != IPACM_SUCCESS)
				{
					IPACMERR("Error while getting interface name\n");
					goto error;
				}
				if((iface_name != NULL) && memcmp(dev_name, iface_name, sizeof(dev_name)))
				{
					IPACMERR("iface %s is not matching with  %s dev_name, so skipping the route query\n",iface_name , dev_name);
					h = NLMSG_NEXT(h, msglen);
					continue;
				}
				IPACM_NL_REPORT_ADDR( "route add -host", nl_route_info_get_route.attr_info.dst_addr );
				IPACM_NL_REPORT_ADDR( "gw", nl_route_info_get_route.attr_info.gateway_addr );
				IPACMDBG("dev %s\n",dev_name );
				/* insert to command queue */
				IPACM_EVENT_COPY_ADDR_v4( if_ipv4_addr, nl_route_info_get_route.attr_info.dst_addr);
				temp = (-1);

				evt_data.event = IPA_ROUTE_ADD_EVENT;
				data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
				if(data_addr == NULL)
				{
					IPACMERR("unable to allocate memory for event data_addr\n");
					goto error;
				}

				data_addr->if_index = nl_route_info_get_route.attr_info.oif_index;
				data_addr->iptype = IPA_IP_v4;
				data_addr->ipv4_addr = ntohl(if_ipv4_addr);
				data_addr->ipv4_addr_mask = ntohl(if_ipipv4_addr_mask);

				IPACMDBG("Posting IPA_ROUTE_ADD_EVENT with if index:%d, ipv4 address 0x%x, mask:0x%x\n",
								 data_addr->if_index,
								 data_addr->ipv4_addr,
								 data_addr->ipv4_addr_mask);
				evt_data.evt_data = data_addr;
				IPACM_EvtDispatcher::PostEvt(&evt_data);
				/* finish command queue */

			}
			else
			{
				ret_val = ipa_get_if_name(dev_name, nl_route_info_get_route.attr_info.oif_index);
				if(ret_val != IPACM_SUCCESS)
				{
					IPACMERR("Error while getting interface name\n");
					goto error;
				}
				else
				{
					IPACM_NL_REPORT_ADDR( "route add default gw \n", nl_route_info_get_route.attr_info.gateway_addr );
					IPACMDBG_H("dev %s \n", dev_name);
					if((iface_name != NULL) && memcmp(dev_name, iface_name, sizeof(dev_name)))
					{
						IPACMERR("iface %s is not matching with  %s dev_name, so skipping the route query\n",iface_name , dev_name);
						h = NLMSG_NEXT(h, msglen);
						continue;
					}
					IPACM_NL_REPORT_ADDR( "dstIP:", nl_route_info_get_route.attr_info.dst_addr );

					/* insert to command queue */
					data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
					if(data_addr == NULL)
					{
						IPACMERR("unable to allocate memory for event data_addr\n");
						goto error;
					}

					IPACM_EVENT_COPY_ADDR_v4( if_ipv4_addr, nl_route_info_get_route.attr_info.dst_addr);
					IPACM_EVENT_COPY_ADDR_v4( if_ipipv4_addr_mask, nl_route_info_get_route.attr_info.dst_addr);
					IPACM_EVENT_COPY_ADDR_v4( if_ipv4_addr_gw, nl_route_info_get_route.attr_info.gateway_addr);

					data_addr->if_index = nl_route_info_get_route.attr_info.oif_index;
					data_addr->iptype = IPA_IP_v4;
					data_addr->ipv4_addr = ntohl(if_ipv4_addr);
					data_addr->ipv4_addr_gw = ntohl(if_ipv4_addr_gw);
					data_addr->ipv4_addr_mask = ntohl(if_ipipv4_addr_mask);

					if(nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_COMPAT &&
						nl_route_info_get_route.attr_info.param_mask & IPA_RTA_PARAM_GATEWAY &&
						strstr(dev_name, ETH_INTF) && IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
					{
						data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
						if(data_fid == NULL)
						{
							IPACMERR("unable to allocate memory for event_ecm data_fid\n");
							return IPACM_FAILURE;
						}
						strlcpy(IPACM_Iface::ipacmcfg->iface_table[IPACM_Iface::ipacmcfg->eth_wan_iface_table_idx].iface_name,
							dev_name, sizeof(IPACM_Iface::ipacmcfg->iface_table[IPACM_Iface::ipacmcfg->eth_wan_iface_table_idx].iface_name));
						IPACM_Iface::ipacmcfg->iface_table[IPACM_Iface::ipacmcfg->eth_wan_iface_table_idx].virtualIface = true;

						data_fid->if_index = nl_route_info_get_route.attr_info.oif_index;
						evt_data.event = IPA_USB_LINK_UP_EVENT;
						evt_data.evt_data = data_fid;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
					}

					if(nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_MAIN)
					{
						evt_data.event = IPA_ROUTE_ADD_EVENT;
						IPACMDBG_H("Posting IPA_ROUTE_ADD_EVENT with if index:%d, ipv4 addr:0x%x, mask: 0x%x and gw: 0x%x\n",
									data_addr->if_index,
									data_addr->ipv4_addr,
									data_addr->ipv4_addr_mask,
									data_addr->ipv4_addr_gw);
					}
					else if(nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_COMPAT)
					{
						evt_data.event = IPA_WAN_GW_ADDR_ADD_EVENT;
						IPACMDBG_H("Posting IPA_WAN_GW_ADDR_ADD_EVENT with if index:%d, ipv4 addr:0x%x, mask: 0x%x and gw: 0x%x\n",
									data_addr->if_index,
									data_addr->ipv4_addr,
									data_addr->ipv4_addr_mask,
									data_addr->ipv4_addr_gw);
					}

					evt_data.evt_data = data_addr;
					IPACM_EvtDispatcher::PostEvt(&evt_data);
					/* finish command queue */
				}
			}

		}

		/* ipv6 routing table */
		if((AF_INET6 == nl_route_info_get_route.metainfo.rtm_family) &&
			(nl_route_info_get_route.metainfo.rtm_type == RTN_UNICAST) &&
			 ((nl_route_info_get_route.metainfo.rtm_protocol == RTPROT_BOOT) ||
			  (nl_route_info_get_route.metainfo.rtm_protocol == RTPROT_RA) ||
			  (nl_route_info_get_route.metainfo.rtm_protocol == RTPROT_KERNEL))&&
			 ((nl_route_info_get_route.metainfo.rtm_scope == RT_SCOPE_UNIVERSE)||
			 (nl_route_info_get_route.metainfo.rtm_scope == RT_SCOPE_LINK))&&
			 ((nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_MAIN) ||
			 	(nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_COMPAT)))
		{
			IPACMDBG("\n GOT valid v6-RTM_NEWROUTE event\n");
			ret_val = ipa_get_if_name(dev_name, nl_route_info_get_route.attr_info.oif_index);
			if(ret_val != IPACM_SUCCESS)
			{
				IPACMERR("Error while getting interface name\n");
				goto error;
			}
			if((iface_name != NULL) && memcmp(dev_name, iface_name, sizeof(dev_name)))
			{
				IPACMERR("iface %s is not matching with  %s dev_name, so skipping the route query\n",iface_name , dev_name);
				h = NLMSG_NEXT(h, msglen);
				continue;
			}

			if(nl_route_info_get_route.attr_info.param_mask & IPA_RTA_PARAM_DST)
			{
				IPACM_NL_REPORT_ADDR( "Route ADD DST:", nl_route_info_get_route.attr_info.dst_addr );
				IPACMDBG("%d, metric %d, dev %s\n",
								 nl_route_info_get_route.metainfo.rtm_dst_len,
								 nl_route_info_get_route.attr_info.priority,
								 dev_name);

				/* insert to command queue */
				data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
				if(data_addr == NULL)
				{
					IPACMERR("unable to allocate memory for event data_addr\n");
					goto error;
				}
				memset(data_addr,0,sizeof(ipacm_event_data_addr));
				IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr, nl_route_info_get_route.attr_info.dst_addr);
		
				data_addr->ipv6_addr[0] = ntohl(data_addr->ipv6_addr[0]);
				data_addr->ipv6_addr[1] = ntohl(data_addr->ipv6_addr[1]);
				data_addr->ipv6_addr[2] = ntohl(data_addr->ipv6_addr[2]);
				data_addr->ipv6_addr[3] = ntohl(data_addr->ipv6_addr[3]);

				mask_value_v6 = nl_route_info_get_route.metainfo.rtm_dst_len;
				for(mask_index = 0; mask_index < 4; mask_index++)
				{
					if(mask_value_v6 >= 32)
					{
						mask_v6(32, &data_addr->ipv6_addr_mask[mask_index]);
						mask_value_v6 -= 32;
					}
					else
					{
						mask_v6(mask_value_v6, &data_addr->ipv6_addr_mask[mask_index]);
						mask_value_v6 = 0;
					}
				}

				IPACMDBG("ADD IPV6 MASK %d: %08x:%08x:%08x:%08x \n",
								nl_route_info_get_route.metainfo.rtm_dst_len,
								 data_addr->ipv6_addr_mask[0],
								 data_addr->ipv6_addr_mask[1],
								 data_addr->ipv6_addr_mask[2],
								 data_addr->ipv6_addr_mask[3]);
		
				data_addr->ipv6_addr_mask[0] = ntohl(data_addr->ipv6_addr_mask[0]);
				data_addr->ipv6_addr_mask[1] = ntohl(data_addr->ipv6_addr_mask[1]);
				data_addr->ipv6_addr_mask[2] = ntohl(data_addr->ipv6_addr_mask[2]);
				data_addr->ipv6_addr_mask[3] = ntohl(data_addr->ipv6_addr_mask[3]);

				evt_data.event = IPA_ROUTE_ADD_EVENT;
				data_addr->if_index = nl_route_info_get_route.attr_info.oif_index;
				data_addr->iptype = IPA_IP_v6;

				IPACMDBG("Posting IPA_ROUTE_ADD_EVENT with if index:%d, ipv6 addr\n",
								 data_addr->if_index);
				evt_data.evt_data = data_addr;
				IPACM_EvtDispatcher::PostEvt(&evt_data);
				/* finish command queue */
			}
			if(nl_route_info_get_route.attr_info.param_mask & IPA_RTA_PARAM_GATEWAY)
			{
				IPACM_NL_REPORT_ADDR( "Route ADD ::/0  Next Hop:", nl_route_info_get_route.attr_info.gateway_addr );
				IPACMDBG(" metric %d, dev %s\n",
								 nl_route_info_get_route.attr_info.priority,
								 dev_name);

				/* insert to command queue */
				data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
				if(data_addr == NULL)
				{
					IPACMERR("unable to allocate memory for event data_addr\n");
					goto error;
				}

				if(nl_route_info_get_route.attr_info.param_mask & IPA_RTA_PARAM_PRIORITY)
				{
					IPACMDBG_H("ip -6 route add default dev %s metric %d\n",
									 dev_name,
									 nl_route_info_get_route.attr_info.priority);
				}
				else
				{
					IPACMDBG_H("ip -6 route add default dev %s\n", dev_name);
				}
				memset(data_addr,0,sizeof(ipacm_event_data_addr));
				IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr, nl_route_info_get_route.attr_info.dst_addr);

				data_addr->ipv6_addr[0]=ntohl(data_addr->ipv6_addr[0]);
				data_addr->ipv6_addr[1]=ntohl(data_addr->ipv6_addr[1]);
				data_addr->ipv6_addr[2]=ntohl(data_addr->ipv6_addr[2]);
				data_addr->ipv6_addr[3]=ntohl(data_addr->ipv6_addr[3]);

				IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr_mask, nl_route_info_get_route.attr_info.dst_addr);

				data_addr->ipv6_addr_mask[0]=ntohl(data_addr->ipv6_addr_mask[0]);
				data_addr->ipv6_addr_mask[1]=ntohl(data_addr->ipv6_addr_mask[1]);
				data_addr->ipv6_addr_mask[2]=ntohl(data_addr->ipv6_addr_mask[2]);
				data_addr->ipv6_addr_mask[3]=ntohl(data_addr->ipv6_addr_mask[3]);

				IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr_gw, nl_route_info_get_route.attr_info.gateway_addr);
				data_addr->ipv6_addr_gw[0] = ntohl(data_addr->ipv6_addr_gw[0]);
				data_addr->ipv6_addr_gw[1] = ntohl(data_addr->ipv6_addr_gw[1]);
				data_addr->ipv6_addr_gw[2] = ntohl(data_addr->ipv6_addr_gw[2]);
				data_addr->ipv6_addr_gw[3] = ntohl(data_addr->ipv6_addr_gw[3]);
				IPACM_NL_REPORT_ADDR( " ", nl_route_info_get_route.attr_info.gateway_addr);

				if(nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_COMPAT &&
						strstr(dev_name, ETH_INTF) && IPACM_Iface::ipacmcfg->is_added_vlan_iface(dev_name))
				{
					data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
					if(data_fid == NULL)
					{
						IPACMERR("unable to allocate memory for event_ecm data_fid\n");
						return IPACM_FAILURE;
					}
					strlcpy(IPACM_Iface::ipacmcfg->iface_table[IPACM_Iface::ipacmcfg->eth_wan_iface_table_idx].iface_name,
						dev_name, sizeof(IPACM_Iface::ipacmcfg->iface_table[IPACM_Iface::ipacmcfg->eth_wan_iface_table_idx].iface_name));
					IPACM_Iface::ipacmcfg->iface_table[IPACM_Iface::ipacmcfg->eth_wan_iface_table_idx].virtualIface = true;

					data_fid->if_index = nl_route_info_get_route.attr_info.oif_index;
					evt_data.event = IPA_USB_LINK_UP_EVENT;
					evt_data.evt_data = data_fid;
					IPACM_EvtDispatcher::PostEvt(&evt_data);
				}
				data_addr->if_index = nl_route_info_get_route.attr_info.oif_index;


				if(nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_MAIN)
				{
					evt_data.event = IPA_ROUTE_ADD_EVENT;
					IPACMDBG("Posting IPA_ROUTE_ADD_EVENT with if index:%d, ipv6 address\n",
								data_addr->if_index);
				}
				else if(nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_COMPAT)
				{
					evt_data.event = IPA_WAN_GW_ADDR_ADD_EVENT;
					IPACMDBG("Posting IPA_WAN_GW_ADDR_ADD_EVENT with if index:%d, ipv6 address\n",
								data_addr->if_index);
				}

				data_addr->iptype = IPA_IP_v6;
				evt_data.evt_data = data_addr;
				IPACM_EvtDispatcher::PostEvt(&evt_data);
				/* finish command queue */
			}
		}

		h = NLMSG_NEXT(h, msglen);
    }

	free(buf);
	close(nl_sock);
	return IPACM_SUCCESS;
error:
	free(buf);
	close(nl_sock);
	return IPACM_FAILURE;
}

/* find the newroute subnet mask */
int find_mask(int ip_v4_last, int *mask_value)
{

	switch(ip_v4_last)
	{

	case 3:
		*mask_value = 252;
		return IPACM_SUCCESS;
		break;

	case 7:
		*mask_value = 248;
		return IPACM_SUCCESS;
		break;

	case 15:
		*mask_value = 240;
		return IPACM_SUCCESS;
		break;

	case 31:
		*mask_value = 224;
		return IPACM_SUCCESS;
		break;

	case 63:
		*mask_value = 192;
		return IPACM_SUCCESS;
		break;

	case 127:
		*mask_value = 128;
		return IPACM_SUCCESS;
		break;

	case 255:
		*mask_value = 0;
		return IPACM_SUCCESS;
		break;

	default:
		return IPACM_FAILURE;
		break;

	}
}

/* map mask value for ipv6 */
int mask_v6(int index, uint32_t *mask)
{
	switch(index)
	{

	case 0:
		*mask = 0x00000000;
		return IPACM_SUCCESS;
		break;
	case 4:
		*mask = 0xf0000000;
		return IPACM_SUCCESS;
		break;
	case 8:
		*mask = 0xff000000;
		return IPACM_SUCCESS;
		break;
	case 12:
		*mask = 0xfff00000;
		return IPACM_SUCCESS;
		break;
	case 16:
		*mask = 0xffff0000;
		return IPACM_SUCCESS;
		break;
	case 20:
		*mask = 0xfffff000;
		return IPACM_SUCCESS;
		break;
	case 24:
		*mask = 0xffffff00;
		return IPACM_SUCCESS;
		break;
	case 28:
		*mask = 0xfffffff0;
		return IPACM_SUCCESS;
		break;
	case 32:
		*mask = 0xffffffff;
		return IPACM_SUCCESS;
		break;
	default:
		return IPACM_FAILURE;
		break;

	}
}

int ipa_open_nl_getlink_socket
(
 ipa_sk_info_t   *sk_info,
 int               protocol,
 unsigned int      grps
 )
{
	int                  *p_sk_fd;
	struct sockaddr_nl   *p_sk_addr_loc ;
	int ret = 0;

	//ds_assert(sk_info != NULL);

	p_sk_fd = &(sk_info->sk_fd);
	p_sk_addr_loc = &(sk_info->sk_addr_loc);

	/*--------------------------------------------------------------------------
	  Open netlink socket for specified protocol
	  ---------------------------------------------------------------------------*/
	if ((*p_sk_fd = socket(AF_NETLINK, SOCK_RAW, protocol)) < 0)
	{
		ret = errno;
		IPACMDBG("Socket open failed %s \n", strerror(errno));
		return ret;
	}

	/*--------------------------------------------------------------------------
	  Initialize socket parameters to 0
	  --------------------------------------------------------------------------*/
	memset(p_sk_addr_loc, 0, sizeof(struct sockaddr_nl));

	/*-------------------------------------------------------------------------
	  Populate socket parameters
	  --------------------------------------------------------------------------*/
	p_sk_addr_loc->nl_family = AF_NETLINK;
	p_sk_addr_loc->nl_pid = 0;
	p_sk_addr_loc->nl_groups = grps;

	/*-------------------------------------------------------------------------
	  128    Bind socket to receive the netlink events for the required groups
	  129  --------------------------------------------------------------------------*/

	if( bind( *p_sk_fd,
				(struct sockaddr *)p_sk_addr_loc,
				sizeof(struct sockaddr_nl) ) < 0)
	{
		ret = errno;
		IPACMDBG("Socket bind failed %s- Make sure no-one has opened a NL socket"
				" with\n", strerror(errno));
		close(*p_sk_fd);
		return ret;
	}
	return ret;
}

int  ipa_nl_query_getlink(int af_family)
{
	ipa_sk_info_t   sk_info;
	struct sockaddr_nl req_nl_addr, recv_nl_addr;
	struct msghdr req_nl_msg, recv_nl_msg;
	ipa_nl_req_type    nl_req;
	char dev_name[IF_NAME_LEN];

	struct iovec recv_iovec, req_iovec;
	char buff[8124] = {0};
	int ret_val = IPACM_SUCCESS;
	struct nlmsghdr *nl_hdr = NULL;
	struct ifinfomsg *iface_info = NULL;
	ssize_t  msglen = 0;
	ipa_nl_msg_t *msg_ptr = NULL;

	memset(&req_nl_msg, 0, sizeof(req_nl_msg));
	memset(&req_nl_addr, 0, sizeof(req_nl_addr));
	memset(&nl_req, 0, sizeof(nl_req));
	memset(&sk_info, 0, sizeof(sk_info));

	ret_val = ipa_open_nl_getlink_socket(&sk_info, NETLINK_ROUTE, RTMGRP_LINK);
	if (ret_val != 0)
	{
		IPACMDBG("Failed to open the netlink socket", 0, 0, 0);
		goto end;
	}

	req_nl_addr.nl_family = AF_NETLINK;
	nl_req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	nl_req.hdr.nlmsg_type = RTM_GETLINK;
	nl_req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_req.hdr.nlmsg_seq = 1;
	nl_req.hdr.nlmsg_pid = 0;
	nl_req.gen.rtgen_family =  AF_PACKET;

	req_iovec.iov_base = &nl_req;
	req_iovec.iov_len = nl_req.hdr.nlmsg_len;
	req_nl_msg.msg_iov = &req_iovec;
	req_nl_msg.msg_iovlen = 1;
	req_nl_msg.msg_name = &req_nl_addr;
	req_nl_msg.msg_namelen = sizeof(req_nl_addr);
	memset(&recv_nl_msg, 0, sizeof(recv_nl_msg));
	memset(&recv_iovec, 0, sizeof(recv_iovec));

	recv_iovec.iov_base = (void*)buff;
	recv_iovec.iov_len = sizeof(buff);

	recv_nl_msg.msg_name = (void*)&recv_nl_addr;
	recv_nl_msg.msg_namelen = sizeof(recv_nl_addr);
	recv_nl_msg.msg_iov = &recv_iovec;
	recv_nl_msg.msg_iovlen = 1;
	recv_nl_msg.msg_control = NULL;
	recv_nl_msg.msg_controllen = 0;
	recv_nl_msg.msg_flags = 0;
	ipa_nl_link_info_t nl_link_info;

	if (sendmsg(sk_info.sk_fd, (struct msghdr *) &req_nl_msg, 0) <= 0)
	{
		IPACMDBG("QCMAP:Netlink Query to Kernel failed errno:%d",errno,0,0);
		ret_val =  errno;
		goto end;
	}

	msg_ptr = (ipa_nl_msg_t *)calloc(1, sizeof(ipa_nl_msg_t));

	if(msg_ptr == NULL)
	{
		IPACMERR("Failed malloc for msg_ptr\n");
		ret_val = -ENOMEM;
		goto end;
	}

	while(1)
	{
		if ((msglen = recvmsg(sk_info.sk_fd, &recv_nl_msg, 0)) < 0)
		{
			ret_val = errno;
			IPACMDBG("Error in reading from netlink socket errno:%d", errno, 0, 0);
			break;
		}
		IPACMDBG("No of bytes recevied:%d", msglen);

		nl_hdr = (struct nlmsghdr*)buff;

		if (nl_hdr->nlmsg_type == NLMSG_DONE)
		{
			IPACMDBG("Received NLMSG_DONE\n");
			break;
		}

		while(NLMSG_OK(nl_hdr, msglen))
		{
			if ((nl_hdr->nlmsg_type == NLMSG_DONE) || (nl_hdr->nlmsg_type == NLMSG_ERROR))
			{
				IPACMDBG("Received: %s\n", (nl_hdr->nlmsg_type == NLMSG_DONE) ?
					"NLMSG_DONE" : "NLMSG_ERROR");
				goto end;
			}

			if ((iface_info = (struct ifinfomsg*)NLMSG_DATA (nl_hdr)) == NULL)
			{
				IPACMDBG("Interface info from netlink message is NULL\n");
				goto next_msg;
			}

			ret_val =  ipa_get_if_name(dev_name, iface_info->ifi_index);
			if(ret_val != 0)
			{
				IPACMDBG("Error while getting interface index\n");
				goto next_msg;
			}
			if(!strcmp(dev_name,"lo") || !strcmp(dev_name,"ip_vti0") || !strcmp(dev_name,"ip6_vti0")
					|| !strcmp(dev_name,"sit0") || !strcmp(dev_name,"can0"))
			{
				goto next_msg;
			}

			if (nl_hdr->nlmsg_type == RTM_NEWLINK)
			{
				if(iface_info->ifi_flags & IFF_UP)
				{
					if (ipa_nl_decode_nlmsg((const char*)nl_hdr, nl_hdr->nlmsg_len,
								 msg_ptr, NULL))
					{
						IPACMERR("Failed to decode rtm link message\n");
						goto next_msg;
					}
				}
			}
next_msg:
			nl_hdr = NLMSG_NEXT(nl_hdr, msglen);
		}
	}

end:
	if (sk_info.sk_fd > 0)
		close(sk_info.sk_fd);
	if(msg_ptr != NULL)
	{
		free(msg_ptr);
		msg_ptr = NULL;
	}
	return ret_val;
}

int ipa_nl_query_ip_addr_info(int af_family)
{
	ssize_t msglen = 0, nl_sock = 0;
	ssize_t msgsent_len = 0;
	char *buf = NULL;
	nl_request_t nl_request;
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct iovec iov;
	IPACM_Config* config = NULL;
	config = IPACM_Config::GetInstance();
	ipa_nl_msg_t  *msg_ptr = NULL;
	int ret_val = IPACM_SUCCESS;

	nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (nl_sock < 0)
	{
		IPACMERR("Failed to open netlink socket");
		return IPACM_FAILURE;
	}

	msg_ptr = (ipa_nl_msg_t*)calloc(1, sizeof(ipa_nl_msg_t));//msg_ptr2;
	if(msg_ptr == NULL)
	{
		IPACMERR("Failed malloc for msg_ptr\n");
		ret_val = -ENOMEM;
		goto end;
	}

	memset(&nl_request, 0, sizeof(nl_request));
	memset(&nladdr, 0, sizeof(sockaddr_nl));
	memset(&msg, 0, sizeof(msghdr));
	memset(&iov, 0, sizeof(iovec));

	nl_request.nlh.nlmsg_type = RTM_GETADDR;
	nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_request.nlh.nlmsg_len = sizeof(nl_request);
	nl_request.nlh.nlmsg_seq = time(NULL);
	nl_request.nlh.nlmsg_pid = 0;


	nl_request.rtm.rtm_family = af_family;

	msgsent_len = send(nl_sock, &nl_request, sizeof(nl_request), 0);

	msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	msglen = ipa_nl_recvmsg(nl_sock, &msg, &buf);

	if((msglen <= 0) || (nladdr.nl_pid != 0))
	{
		ret_val = errno;
		IPACMERR("Netlink receive error msglen[%d], nl_pid[%u]\n", msglen, nladdr.nl_pid);
		goto end;
	}

	IPACMDBG("Route msg_len : %d\n", msglen);

	ret_val = ipa_nl_decode_nlmsg((const char*)buf, msglen, msg_ptr, NULL);
	if (IPACM_SUCCESS != ret_val) {
		IPACMERR("Failed to decode rtm link message\n");
		goto end;
	}

end:
	close(nl_sock);

	if (buf)
		free(buf);
	if (msg_ptr)
		free(msg_ptr);

	return ret_val;
}

int ipa_nl_query_newneigh(int af_family, char* dev_name, bool query)
{
	IPACMDBG("entered ipa_nl_send_getneigh \n");
	int ret_val = IPACM_FAILURE, msglen = 0, nl_sock = 0;
	ssize_t msgsent_len = 0;
	char *buf = NULL;
	nl_request_t nl_request;
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct iovec iov;
	ipa_nl_msg_t  *msg_ptr = NULL;
	nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (nl_sock < 0)
	{
		IPACMERR("Failed to open netlink socket");
		return IPACM_FAILURE;
	}
	msg_ptr = (ipa_nl_msg_t*)calloc(1, sizeof(ipa_nl_msg_t));
	if(msg_ptr == NULL)
	{
		IPACMERR("Failed malloc for msg_ptr\n");
		ret_val = -ENOMEM;
		goto end;
	}
	memset(&nl_request, 0, sizeof(nl_request));
	memset(&nladdr, 0, sizeof(sockaddr_nl));
	memset(&msg, 0, sizeof(msghdr));
	memset(&iov, 0, sizeof(iovec));

	nl_request.nlh.nlmsg_type = RTM_GETNEIGH;
	nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_request.nd.ndm_state = NUD_REACHABLE;
	nl_request.nd.ndm_flags = NTF_MASTER|NTF_SELF;
	nl_request.nlh.nlmsg_len = sizeof(nl_request_t);
	nl_request.nlh.nlmsg_seq = 1;
	nl_request.nlh.nlmsg_pid = 0;
	nl_request.rtm.rtm_family = af_family;

	if (dev_name)
	{
		IPACMDBG("Query neigh events for iface %s\n", dev_name);
		nl_request.nd.ndm_ifindex = if_nametoindex(dev_name);
	}

	msgsent_len = send(nl_sock, &nl_request, sizeof(nl_request), 0);

	msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	msglen = ipa_nl_recvmsg(nl_sock, &msg, &buf);

	if((msglen <= 0) || (nladdr.nl_pid != 0))
	{
		IPACMERR("Netlink receive error msglen[%d], nl_pid[%u]\n", msglen, nladdr.nl_pid);
		goto end;
	}

	ret_val = ipa_nl_decode_nlmsg((const char*)buf, msglen, msg_ptr, dev_name, query);

	if (IPACM_SUCCESS != ret_val) {
		IPACMERR("Failed to decode rtm link message\n");
		goto end;
	}

	ret_val  = IPACM_SUCCESS;

end:
	IPACMDBG("End\n");
	close(nl_sock);

	if (buf)
		free(buf);
	if (msg_ptr)
		free(msg_ptr);

	return ret_val;
}

int l2tp_nl_tunnel_get(int l2tpcmd)
{
	struct nl_msg *msg = NULL;
	struct nl_cb *cb = NULL;
	int result = -EPROTONOSUPPORT;
	enum nl_cb_kind cb_kind = NL_CB_DEFAULT;
	int flags = NLM_F_DUMP;
	static struct nl_sock *nl_sock = NULL;
	static int nl_family;

	IPACMDBG("l2tp_nl_tunnel_get\n");

	nl_sock = nl_socket_alloc();
	if (!nl_sock) {
		IPACMERR("nl_handle_alloc is failed");
		return IPACM_FAILURE;
	}

	if (nl_connect(nl_sock, NETLINK_GENERIC) < 0) {
		IPACMERR("nl_connect is failed");
		result = IPACM_FAILURE;
		goto out;
	}

	nl_family = genl_ctrl_resolve(nl_sock, L2TP_GENL_NAME);

	msg = nlmsg_alloc();

	if(!msg)
	{
		IPACMERR("Failed to allocated netlink message");
		result = IPACM_FAILURE;
		goto out;
	}

	cb = nl_cb_alloc(cb_kind);
	if (!cb) {
		result = IPACM_FAILURE;
		goto out;
	}

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, recv_genl_msg, NULL);

	flags = NLM_F_REQUEST|NLM_F_DUMP;
	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nl_family, 0, flags,
							    l2tpcmd, L2TP_GENL_VERSION);
	nl_send_auto_complete(nl_sock, msg);

	result = nl_recvmsgs(nl_sock, cb);
	if (result > 0) {
		result = nl_wait_for_ack(nl_sock);
	}

	if (result > 0) {
		result = 0;
	}
	nl_cb_put(cb);
out:
	IPACMERR("End\n");
	if(msg)
	{
		nlmsg_free(msg);
	}
	nl_socket_free(nl_sock);
	return result;
}

int ipa_query_active_feature()
{
	int fd = -1;

	if ((fd = open(IPA_DEVICE_NAME, O_RDWR)) < 0) {
		IPACMERR("Failed opening %s.\n", IPA_DEVICE_NAME);
		return IPACM_FAILURE;
	}

	if (ioctl(fd, IPA_IOC_QUERY_CACHED_DRIVER_MSG, 1) < 0) {
		IPACMERR("IOCTL IPA_IOC_QUERY_CACHED_DRIVER_MSG call failed: %s \n",
			strerror(errno));
		close(fd);
		return IPACM_FAILURE;
	}

	IPACMDBG_H("send IPA_IOC_QUERY_CACHED_DRIVER_MSG \n");
	close(fd);
	return IPACM_SUCCESS;
}

void ipa_query_nl_getevents()
{
	while(!nl_lock);
	IPACMDBG_H("Querying the netlink events\n");
	IPACMDBG("Handling ipacm_restart\n");
	ipa_nl_query_getlink(AF_PACKET);
	IPACMDBG("Send GETLINK is completed\n");
	ipa_nl_query_ip_addr_info(AF_INET);
	ipa_nl_query_ip_addr_info(AF_INET6);
	IPACMDBG("Send GETADDR is completed\n");
	if((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) ||
		(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E))
	{
		IPACMDBG("Send L2tp tunnels info\n");
		l2tp_nl_tunnel_get(L2TP_CMD_TUNNEL_GET);
		l2tp_nl_tunnel_get(L2TP_CMD_SESSION_GET);
	}
	ipa_nl_query_newneigh(AF_BRIDGE);
	/* Query conntracks only if ipacm is restarted */
	ipa_nl_query_newneigh(AF_INET6, NULL, ipacm_restarted);
	ipa_nl_query_newneigh(AF_INET, NULL, ipacm_restarted);
	IPACMDBG("Send GETNEIGH is completed\n");
	ipa_nl_send_getroute(IPA_IP_v6);
	ipa_nl_send_getroute(IPA_IP_v4);
	IPACMDBG("Send GETROUTE is completed\n");
	ipa_query_active_feature();
	IPACMDBG_DMESG("IPACM process started, ipa path is re-established\n");
	/* Make it false as conntrack query is take care above */
	if(ipacm_restarted)
		ipacm_restarted = false;
}
