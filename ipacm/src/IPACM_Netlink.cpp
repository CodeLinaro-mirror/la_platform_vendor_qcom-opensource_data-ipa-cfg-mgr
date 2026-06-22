/*
Copyright (c) 2013-2020, The Linux Foundation. All rights reserved.

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
#include "IPACM_CmdQueue.h"
#include "IPACM_Defs.h"
#include "IPACM_Netlink.h"
#include "IPACM_EvtDispatcher.h"
#include "IPACM_Log.h"
#include "IPACM_Iface.h"
#include "IPACM_Config.h"
#include "IPACM_ConntrackListener.h"

#ifdef FEATURE_EoGRE
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#endif

#define DUMMY_RGIP_ADDRESS 169
int ipa_get_if_name(char *if_name, int if_index);
int find_mask(int ip_v4_last, int *mask_value);
IPACM_Config *pConfig;
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

#define IPACM_NL_COPY_ADDR( event_info, element )                                        \
        RTA_PAYLOAD(rtah) >  (_SS_SIZE - (2 * sizeof (__ss_aligntype))) ?                \
        memcpy( &event_info->attr_info.element.__ss_padding,                             \
                RTA_DATA(rtah),                                                          \
                (_SS_SIZE - (2 * sizeof (__ss_aligntype)))):                             \
                memcpy( &event_info->attr_info.element.__ss_padding,                     \
                RTA_DATA(rtah),                                                          \
                RTA_PAYLOAD(rtah));

#define IPACM_EVENT_COPY_ADDR_v6( event_data, element)                                   \
        memcpy( event_data, element.__ss_padding, sizeof(event_data));

#define IPACM_EVENT_COPY_ADDR_v4( event_data, element)                                   \
        memcpy( &event_data, element.__ss_padding, sizeof(event_data));

#define IPACM_NL_REPORT_ADDR( prefix, addr )                                             \
        if( AF_INET6 == (addr).ss_family ) {                                             \
          IPACM_LOG_IPV6_ADDR( prefix, addr.__ss_padding);                               \
        } else {                                                                         \
          IPACM_LOG_IPV4_ADDR( prefix, (*(unsigned int*)&(addr).__ss_padding) );         \
        }
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

#ifdef FEATURE_EoGRE
#define parse_gre(attrib, max, rta) \
	(getAttr((attrib), (max), (struct rtattr*)RTA_DATA(rta), RTA_PAYLOAD(rta), 0,true))

static void getAttr(struct rtattr *attrib[], int max, struct rtattr *rta, int len,unsigned short flags, bool flag)
{
	memset(attrib, 0, sizeof(struct rtattr *) * (max + 1));
	unsigned short type;
	while (RTA_OK(rta, len))
	{
		if(flag)
		{
			type=  rta->rta_type & ~flags;
			if ((type <= max) && (!attrib[type]))
			{
				attrib[type] = rta;
			}
                }
		else
                {
			if (rta->rta_type <= max)
			{
				attrib[rta->rta_type] = rta;
			}
		}
		rta = RTA_NEXT(rta,len);
	}
}
#endif

/* Opens a netlink socket*/
static int ipa_nl_open_socket
(
	 ipa_nl_sk_info_t *sk_info,
	 int protocol,
	 unsigned int grps
	 )
{
	int buf_size = 6669999, sendbuff=0, res;
	struct sockaddr_nl *p_sk_addr_loc;
	socklen_t optlen;

	p_sk_fd = &(sk_info->sk_fd);
	p_sk_addr_loc = &(sk_info->sk_addr_loc);

	/* Open netlink socket for specified protocol */
	if((*p_sk_fd = socket(AF_NETLINK, SOCK_RAW, protocol)) < 0)
	{
		IPACMERR("cannot open netlink socket\n");
		return IPACM_FAILURE;
	}

	optlen = sizeof(sendbuff);
	res = getsockopt(*p_sk_fd, SOL_SOCKET, SO_SNDBUF, &sendbuff, &optlen);

	if(res == -1) {
		IPACMDBG("Error getsockopt one");
	} else {
		IPACMDBG("orignal send buffer size = %d\n", sendbuff);
	}
	IPACMDBG("sets the send buffer to %d\n", buf_size);
	if (setsockopt(*p_sk_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(int)) == -1) {
    IPACMERR("Error setting socket opts\n");
	}

	/* Initialize socket addresses to null */
	memset(p_sk_addr_loc, 0, sizeof(struct sockaddr_nl));

	/* Populate local socket address using specified groups */
	p_sk_addr_loc->nl_family = AF_NETLINK;
	p_sk_addr_loc->nl_pid = getpid();
	p_sk_addr_loc->nl_groups = grps;

	/* Bind socket to the local address, i.e. specified groups. This ensures
	 that multicast messages for these groups are delivered over this
	 socket. */

	if(bind(*p_sk_fd,
					(struct sockaddr *)p_sk_addr_loc,
					sizeof(struct sockaddr_nl)) < 0)
	{
		IPACMERR("Socket bind failed\n");
		return IPACM_FAILURE;
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

	while(true)
	{
	    for(i = 0; i < sk_fd_set->num_fd; i++ )
		{
			FD_SET(sk_fd_set->sk_fds[i].sk_fd, &(sk_fd_set->fdset));
		}

		if((ret = select(sk_fd_set->max_fd + 1, &(sk_fd_set->fdset), NULL, NULL, NULL)) < 0)
		{
			IPACMERR("ipa_nl select failed\n");
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

#if defined(FEATURE_EoGRE) || defined(FEATURE_PMIPV6) || defined(FEATURE_IPoGRE)
static int get_eogre_tunnel_details(struct ifinfomsg* ifi, int len, int type)
{
	struct rtattr *attrib[IFLA_MAX + 1];
	struct rtattr *linkinfo[IFLA_INFO_MAX+1];
	struct rtattr *greinfo[IFLA_GRE_MAX + 1];
	unsigned saddr = 0;
	unsigned daddr = 0;
	unsigned link = 0;
	struct in6_addr saddr6;
	struct in6_addr daddr6;
	enum ipa_ip_type iptype;
	struct ipa_ipgre_info eogre_info;

	memset(&eogre_info, 0, sizeof(eogre_info));

	if ( IPACM_Iface::ipacmcfg->eogre_enabled == true )
	{
		IPACMERR("Can't enable eogre when it's already enabled\n");
		return IPACM_FAILURE;
	}

	IPACMDBG("IFI max: %d IFLA_MAX, %d len\n",IFLA_MAX,len);
	getAttr(attrib, IFLA_MAX, IFLA_RTA(ifi), len,0,false);

	if (attrib[IFLA_IFNAME])
	{
		IPACMDBG("ifname %s \n",(char*)RTA_DATA(attrib[IFLA_IFNAME]));
		strlcpy(IPACM_Iface::ipacmcfg->eogre_tunnel_name, (char*)RTA_DATA(attrib[IFLA_IFNAME]), IPA_IFACE_NAME_LEN);
	}
	else
	{
		IPACMDBG("No ifname info\n");
		return IPACM_FAILURE;
	}

	if(!strcmp(IPACM_Iface::ipacmcfg->eogre_tunnel_name, "gre4t-gretap2"))
	{
		iptype = IPA_IP_v4;
	}
	else if(!strcmp(IPACM_Iface::ipacmcfg->eogre_tunnel_name, "gre6t-gretap2"))
	{
		iptype = IPA_IP_v6;
	}
	else
	{
		IPACMERR("Unexpected eogre tunnel name %s\n", IPACM_Iface::ipacmcfg->eogre_tunnel_name);
		return IPACM_FAILURE;
	}

	if (!attrib[IFLA_LINKINFO])
	{
		IPACMDBG("No Link info\n");
		return IPACM_FAILURE;
	}
	else
	{
		parse_gre(linkinfo, IFLA_INFO_MAX, attrib[IFLA_LINKINFO]);
		IPACMDBG("Nested1\n");
		if (!linkinfo[IFLA_INFO_DATA])
		{
			IPACMDBG("No IFLA_INFO_DATA\n");
			return IPACM_FAILURE;
		}
		else if(strcmp(IPACM_Iface::ipacmcfg->eogre_tunnel_name, "gre4t-gretap2") && strcmp(IPACM_Iface::ipacmcfg->eogre_tunnel_name, "gre6t-gretap2"))
		{
			IPACMDBG("It is not the gretap evt breaking auto learning here\n");
			return IPACM_FAILURE;
		}
		else
		{
			parse_gre(greinfo, IFLA_GRE_MAX,
				linkinfo[IFLA_INFO_DATA]);
			IPACMDBG("Nested2\n");
			eogre_info.iptype = iptype;
			eogre_info.gre_protocol = EOGRE_PROTOCOL_TYPE;
			if(iptype == IPA_IP_v4)
			{
				if (greinfo[IFLA_GRE_LOCAL])
				{
					saddr = *(__u32 *)RTA_DATA(greinfo[IFLA_GRE_LOCAL]);
				}
				if (greinfo[IFLA_GRE_REMOTE])
				{
					daddr = *(__u32 *)RTA_DATA(greinfo[IFLA_GRE_REMOTE]);
				}

				eogre_info.ipv4_src = ntohl(saddr);
				eogre_info.ipv4_dst = ntohl(daddr);
				IPACMDBG("EoGRE info, src addr: %x, dst addr %x, link %d\n", eogre_info.ipv4_src, eogre_info.ipv4_dst, link);
			}
			else
			{
				if (greinfo[IFLA_GRE_LOCAL])
				{
					memcpy(&saddr6, (struct nlattr  *)RTA_DATA(greinfo[IFLA_GRE_LOCAL]), sizeof(saddr6));
				}

				if (greinfo[IFLA_GRE_REMOTE])
				{
					memcpy(&daddr6, (struct nlattr  *)RTA_DATA(greinfo[IFLA_GRE_REMOTE]), sizeof(daddr6));
				}

				memcpy(&eogre_info.ipv6_src, &saddr6, sizeof(saddr6));
				memcpy(&eogre_info.ipv6_dst, &daddr6, sizeof(daddr6));

				IPACM_Iface::addr2host(IPA_IP_v6, &eogre_info.ipv6_src);
				IPACM_Iface::addr2host(IPA_IP_v6, &eogre_info.ipv6_dst);
				IPACMDBG_H("EoGRE info v6: src addr:0x%x:%x:%x:%x, dst addr:0x%x:%x:%x:%x \n",
					saddr6.s6_addr32[0],saddr6.s6_addr32[1],saddr6.s6_addr32[2],saddr6.s6_addr32[3],
					daddr6.s6_addr32[0],daddr6.s6_addr32[1],daddr6.s6_addr32[2],daddr6.s6_addr32[3]);
			}
			IPACMDBG("Got bng address, next is to post IPA_HANDLE_EoGRE_UP evt\n")
			IPACM_Iface::ipacmcfg->eogre_enabled = true;
			if (eogre_info.iptype == IPA_IP_v4)
			{
				IPACM_LOG_IP_ADDR(
						"The eogre src address (host order) on conversion from input:",
						IPA_IP_v4,
						&eogre_info.ipv4_src);
				IPACM_LOG_IP_ADDR(
						"The eogre dst address (host order) on conversion from input:",
						IPA_IP_v4,
						&eogre_info.ipv4_dst);
			}
			else
			{
				IPACM_LOG_IP_ADDR(
						"The eogre src address (host order) on conversion from input:",
						IPA_IP_v6,
						&eogre_info.ipv6_src);
				IPACM_LOG_IP_ADDR(
						"The eogre dst address (host order) on conversion from input:",
						IPA_IP_v6,
						&eogre_info.ipv6_dst);
			}
			memcpy(&(IPACM_Iface::ipacmcfg->eogre_info), &eogre_info, sizeof(ipa_ipgre_info));
			ipacm_cmd_q_data evt_data;
			evt_data.event    = IPA_HANDLE_EoGRE_UP;
			evt_data.evt_data = 0;
			IPACMDBG_H("Posting IPA_HANDLE_EoGRE_UP \n");
			IPACM_EvtDispatcher::PostEvt(&evt_data);
		}
	}
return IPACM_SUCCESS;
}
static int del_eogre_tunnel(struct ifinfomsg* ifi, int len, int type)
{
	struct rtattr *attrib[IFLA_MAX + 1];
	struct rtattr *linkinfo[IFLA_INFO_MAX+1];
	struct rtattr *greinfo[IFLA_GRE_MAX + 1];
	IPACMDBG("IFI max: %d IFLA_MAX, %d len\n",IFLA_MAX,len);
	getAttr(attrib, IFLA_MAX, IFLA_RTA(ifi), len,0,false);
	if (attrib[IFLA_IFNAME])
	{
		IPACMDBG("Tunnel Delete: ifname %s \n",(char*)RTA_DATA(attrib[IFLA_IFNAME]));
		if(strncmp(IPACM_Iface::ipacmcfg->eogre_tunnel_name, (char*)RTA_DATA(attrib[IFLA_IFNAME]), strlen(IPACM_Iface::ipacmcfg->eogre_tunnel_name)) == 0)
		{
			IPACMDBG("Tunnel name matched, Cleaning up\n");
			IPACM_Iface::ipacmcfg->eogre_tunnel_name[0] ='\0';
			if ( IPACM_Iface::ipacmcfg->eogre_enabled == false )
			{
				IPACMERR("Can't disable eogre when it's already disabled\n");
                          	return IPACM_FAILURE;
			}
			IPACM_Iface::ipacmcfg->eogre_enabled = false;
			ipacm_cmd_q_data evt_data;
			evt_data.event    = IPA_HANDLE_EoGRE_DOWN;
			evt_data.evt_data = 0;
			IPACMDBG_H("Posting IPA_HANDLE_EoGRE_DOWN \n");
			IPACM_EvtDispatcher::PostEvt(&evt_data);
		}
	}
return IPACM_SUCCESS;
}

static int populate_gre_details(struct ifinfomsg* ifi, int len, int type){
	struct rtattr *attrib[IFLA_MAX + 1];
    struct rtattr *linkinfo[IFLA_INFO_MAX+1];
    struct rtattr *greinfo[IFLA_GRE_MAX + 1];
	unsigned saddr = 0;
	unsigned daddr = 0;
	unsigned link =0;
	struct in6_addr saddr6;
	struct in6_addr daddr6;
	enum ipa_ip_type iptype;
	pConfig = IPACM_Config::GetInstance();
	if(type==778){
		iptype=IPA_IP_v4;
	}
	else{
		iptype=IPA_IP_v6;
	}
	IPACMDBG("IFI max: %d IFLA_MAX, %d len\n",IFLA_MAX,len);
       if(pConfig->mape_enable) {
               IPACMDBG_H(" MAPE is enabled \n");
               return IPACM_SUCCESS;
	}
	getAttr(attrib, IFLA_MAX, IFLA_RTA(ifi), len,0,false);  // get attributes
    if (attrib[IFLA_IFNAME]) {  // validation
        IPACMDBG("ifname %s \n",(char*)RTA_DATA(attrib[IFLA_IFNAME]));
		strlcpy(pConfig->pmip_details.tunnel_name, (char*)RTA_DATA(attrib[IFLA_IFNAME]), IPA_IFACE_NAME_LEN);
    }
	if (!attrib[IFLA_LINKINFO]){
		IPACMDBG("No Link info\n");
		return IPACM_FAILURE;
	}
	else{
		parse_gre(linkinfo, IFLA_INFO_MAX, attrib[IFLA_LINKINFO]);
		IPACMDBG("Nested1\n");
		if (!linkinfo[IFLA_INFO_DATA]){
			IPACMDBG("No IFLA_INFO_DATA\n");
			return IPACM_FAILURE;
		}
		else{
			parse_gre(greinfo, IFLA_GRE_MAX,
				linkinfo[IFLA_INFO_DATA]);
			IPACMDBG("Nested2\n");

			ipa_ipgre_info ipgre_info  = pConfig->ipgre_info;
			ipgre_info.iptype=iptype;
			if(iptype == IPA_IP_v4){
				if (greinfo[IFLA_GRE_LOCAL])
				saddr = *(__u32 *)RTA_DATA(greinfo[IFLA_GRE_LOCAL]);

				if (greinfo[IFLA_GRE_REMOTE])
					daddr = *(__u32 *)RTA_DATA(greinfo[IFLA_GRE_REMOTE]);

				ipgre_info.ipv4_src=ntohl(saddr);
				ipgre_info.ipv4_dst=ntohl(daddr);
				IPACMDBG("GRE info, src addr: %x, dst addr %x, link %d\n", ipgre_info.ipv4_src,ipgre_info.ipv4_dst,link);
			}
			else{
				if (greinfo[IFLA_GRE_LOCAL])
					memcpy(&saddr6, (struct nlattr  *)RTA_DATA(greinfo[IFLA_GRE_LOCAL]), sizeof(saddr6));
				if (greinfo[IFLA_GRE_REMOTE])
					memcpy(&daddr6, (struct nlattr  *)RTA_DATA(greinfo[IFLA_GRE_REMOTE]), sizeof(daddr6));

				memcpy(&ipgre_info.ipv6_src,&saddr6,sizeof(saddr6));
				memcpy(&ipgre_info.ipv6_dst,&daddr6,sizeof(daddr6));

				IPACM_Iface::addr2host(IPA_IP_v6, &ipgre_info.ipv6_src);
				IPACM_Iface::addr2host(IPA_IP_v6, &ipgre_info.ipv6_dst);



				IPACMDBG_H("GRE info v6: src addr:0x%x:%x:%x:%x, dst addr:0x%x:%x:%x:%x \n",
							saddr6.s6_addr32[0],saddr6.s6_addr32[1],saddr6.s6_addr32[2],saddr6.s6_addr32[3],daddr6.s6_addr32[0],daddr6.s6_addr32[1],daddr6.s6_addr32[2],daddr6.s6_addr32[3]);
			}

			memcpy(&(pConfig->ipgre_info),&ipgre_info,sizeof(ipa_ipgre_info));
			IPACMDBG("GRE info, src addr: %x, dst addr %x, link %d\n", ipgre_info.ipv4_src,ipgre_info.ipv4_dst,link);
#if defined(FEATURE_PMIPV6) || defined(FEATURE_IPoGRE)
			if(pConfig->pmip_details.pmipv6_enabled)
			{
				/* Send GRE UP event */
				pConfig->pmip_details.pmipv6_tunnel_setup = true;
				ipacm_cmd_q_data evt_data;
				evt_data.event    = IPA_HANDLE_GRE_UP;
				evt_data.evt_data = 0;
				if(pConfig->pmip_details.pmipv6_gre_event_posted==false){
					pConfig->pmip_details.pmipv6_gre_event_posted=true;
					IPACMDBG_H("Posting usb IPA_HANDLE_GRE_UP \n");
					IPACM_EvtDispatcher::PostEvt(&evt_data);
				}
			}
			else {
				if(pConfig->ipogre_enabled == true)
				{
					IPACMDBG_H("IPoGRE Already enabled\n");
					return IPACM_SUCCESS;
				}
				pConfig->ipogre_enabled = true;
				ipacm_cmd_q_data evt_data;
				evt_data.event    = IPA_HANDLE_IPOGRE_UP;
				evt_data.evt_data = 0;
				IPACMDBG_H("Posting IPA_HANDLE_IPOGRE_UP \n");
				IPACM_EvtDispatcher::PostEvt(&evt_data);
			}
#endif
		}
	}
return IPACM_SUCCESS;
}

static int tunnel_delete(struct ifinfomsg* ifi, int len, int type)
{
	struct rtattr *attrib[IFLA_MAX + 1];
    struct rtattr *linkinfo[IFLA_INFO_MAX+1];
    struct rtattr *greinfo[IFLA_GRE_MAX + 1];
	unsigned saddr = 0;
	unsigned daddr = 0;
	unsigned link =0;
	struct in6_addr saddr6;
	struct in6_addr daddr6;
	enum ipa_ip_type iptype;
	pConfig = IPACM_Config::GetInstance();
	if(type==778)
	{
		iptype=IPA_IP_v4;
	}
	else
	{
		iptype=IPA_IP_v6;
	}
	if(pConfig->pmip_details.pmipv6_tunnel_setup || pConfig->ipogre_enabled)
	{
		IPACMDBG("IFI max: %d IFLA_MAX, %d len\n",IFLA_MAX,len);
		getAttr(attrib, IFLA_MAX, IFLA_RTA(ifi), len,0,false);
		if (attrib[IFLA_IFNAME])
		{
			IPACMDBG("Tunnel Delete: ifname %s \n",(char*)RTA_DATA(attrib[IFLA_IFNAME]));
#if defined(FEATURE_PMIPV6) || defined(FEATURE_IPoGRE)
			if(strncmp(pConfig->pmip_details.tunnel_name, (char*)RTA_DATA(attrib[IFLA_IFNAME]), strlen(pConfig->pmip_details.tunnel_name)) == 0)
			{
				IPACMDBG("Tunnel name matched, Cleaning up\n");
				pConfig->pmip_details.tunnel_name[0]='\0';
				pConfig->pmip_details.pmipv6_tunnel_setup=false;
				pConfig->pmip_details.pmipv6_gre_event_posted=false;
				if(pConfig->pmip_details.pmipv6_enabled)
				{
					/* Send GRE DOWN event */
					ipacm_cmd_q_data evt_data;
					evt_data.event    = IPA_HANDLE_GRE_DOWN;
					evt_data.evt_data = 0;
					IPACMDBG_H("Posting IPA_HANDLE_GRE_DOWN \n");
					IPACM_EvtDispatcher::PostEvt(&evt_data);
				}
				else
				{
					pConfig->ipogre_enabled = false;
					/* Send GRE DOWN event */
					ipacm_cmd_q_data evt_data;
					evt_data.event    = IPA_HANDLE_IPOGRE_DOWN;
					evt_data.evt_data = 0;
					IPACMDBG_H("Posting IPA_HANDLE_IPOGRE_DOWN \n");
					IPACM_EvtDispatcher::PostEvt(&evt_data);
				}
			}
#endif
		}
	}
	return IPACM_SUCCESS;
}
#endif
/* decode the rtm netlink message */
static int ipa_nl_decode_rtm_link
(
	 const char              *buffer,
	 unsigned int             buflen,
	 ipa_nl_link_info_t      *link_info
)
{
	struct rtattr *attrib, *nested_attr, *vlan_attr;
	struct rtattr *device_link_info[IFLA_INFO_MAX + 1] = {};
	struct rtattr *vlan_link_info_data_attrs[IFLA_VLAN_MAX+1] = {};
	struct ifinfomsg *ifm;
	int len, nest_len, vlan_len;
	char *intf_type = NULL;
	/* NL message header */
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
	char *rta_data = NULL;

	ifm = (struct ifinfomsg *) NLMSG_DATA(nlh);
	len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
	/* Extract the header data */
	link_info->metainfo = *(struct ifinfomsg *)NLMSG_DATA(nlh);
	buflen -= sizeof(struct nlmsghdr);

	for (attrib = IFLA_RTA(ifm); RTA_OK(attrib, len); attrib = RTA_NEXT(attrib, len)) {
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
					} else if (strcmp(intf_type, "ppp") == 0) {
						link_info->link_type = IPA_LINK_TYPE_PPP;
						IPACMDBG("Received NEW_LINK for ppp type interface with interface index %d\n",
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
			if(intf_type != NULL)
			{
				free(intf_type);
			}
		}
		if(rta_data != NULL)
		{
			free(rta_data);
		}
		if (attrib->rta_type == IFLA_MASTER) {
			memcpy(&link_info->master_interface_index,
						 RTA_DATA(attrib),
						 sizeof(link_info->master_interface_index));
			IPACMDBG("Extracted master interface index %d\n",
					link_info->metainfo.ifi_index);
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
	buflen -= sizeof(struct nlmsghdr);

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
		case IFA_LOCAL:
			addr_info->attr_info.local_addr.ss_family = addr_info->metainfo.ifa_family;
			IPACM_NL_COPY_ADDR( addr_info, local_addr );
			addr_info->attr_info.param_mask |= IPA_NLA_PARAM_LOCALADDR;
			break;
		default:
			break;

		}
		/* Advance to next attribute */
		rtah = RTA_NEXT(rtah, buflen);
	}

	return IPACM_SUCCESS;
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
	buflen -= sizeof(struct nlmsghdr);

	memset(&neigh_info->attr_info, 0, sizeof(neigh_info->attr_info));
	/* Extract the available attributes */
	neigh_info->attr_info.param_mask = IPA_NLA_PARAM_NONE;

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
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;  /* NL message header */
	struct rtattr *rtah = NULL;
	struct rtattr *inner_rtah = NULL;
	int inner_rtalen;

	/* Extract the header data */
	route_info->metainfo = *((struct rtmsg *)NLMSG_DATA(nlh));
	buflen -= sizeof(struct nlmsghdr);

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

		case RTA_METRICS:
			inner_rtalen = RTA_PAYLOAD(rtah);
			for(inner_rtah = (struct rtattr *)RTA_DATA(rtah); RTA_OK(inner_rtah, inner_rtalen);
				inner_rtah = RTA_NEXT(inner_rtah,inner_rtalen))
			{
				if(inner_rtah->rta_type == RTAX_MTU)
				{
					memcpy(&route_info->attr_info.mtu,
						RTA_DATA(inner_rtah),
					 	sizeof(route_info->attr_info.mtu));

					IPACMDBG_H("MTU: %d\n", route_info->attr_info.mtu);
				}
			}
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

static int get_macsec_lower_interface_name(struct ipa_macsec_map *macsecMap, char *lowerInterfaceName) {
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
		fclose(fp);
		return IPACM_FAILURE;
	}
	fclose(fp);
	lowerInterfaceName[strcspn(lowerInterfaceName, "\r\n")] = 0;
	return IPACM_SUCCESS;
}

/* Get vlan priority */
static int ipa_nl_get_vlan_priority
(
	 ipa_vlan_iface_info   *vlan_info
	 )
{
	char cmd[200] = {0};
	FILE *fp = NULL;
	uint32_t priority = 0;

	/* Explicitly default priority to 0; updated only if PCP is configured.
	 * This ensures the caller always gets a valid priority regardless of
	 * whether the function succeeds or fails. */
	vlan_info->priority = 0;

	/* Validate interface name to prevent shell command injection.
	 * Linux interface names must only contain alphanumeric characters,
	 * '-', '.', or '_'. Any other character is rejected with an error.
	 * priority is already set to 0 above, so the caller is safe on failure. */
	for (int i = 0; vlan_info->name[i] != '\0'; i++)
	{
		char c = vlan_info->name[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'))
		{
			IPACMERR("Unsafe char in iface name '%s', aborting PCP lookup\n",
				vlan_info->name);
			return IPACM_FAILURE;
		}
	}

	snprintf(cmd, 200, "ip -d -o link show dev %s | grep \"egress-qos-map\" | sed -n \"s/^.*egress-qos-map { [0-9]:\\s*\\(\\S*\\).*$/\\1/p\" > /tmp/pcp.txt", vlan_info->name);
	system(cmd);
	fp = fopen("/tmp/pcp.txt", "r");
	if (!fp) {
		IPACMERR("can't open /tmp/pcp.txt\n");
		return IPACM_FAILURE;
	}

	if(fscanf(fp, "%d", &priority) > 0)
	{
		if(!(priority > 7))
			vlan_info->priority = (uint8_t)priority;
	}
	else {
		IPACMERR("Failed to read priority from /tmp/pcp.txt\n");
		fclose(fp); 	// ← must close before returning
		remove("/tmp/pcp.txt");
		return IPACM_FAILURE;
	}
	IPACMDBG("Vlan ID %d, Priority %d\n", vlan_info->vlan_id, vlan_info->priority);
	fclose(fp);
	remove("/tmp/pcp.txt");
	return IPACM_SUCCESS;
}

/* decode the ipa nl-message */
static int ipa_nl_decode_nlmsg
(
	 const char   *buffer,
	 unsigned int  buflen,
	 ipa_nl_msg_t  *msg_ptr
	 )
{
	char dev_name[IF_NAME_LEN]={0};
	char master_dev_name[IF_NAME_LEN]={0};
	int ret_val, mask_value, mask_index, mask_value_v6, ipa_interface_index;
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;

	uint32_t if_ipv4_addr =0, if_ipipv4_addr_mask =0, temp =0, if_ipv4_addr_gw =0;
	uint8_t nullMac[IPA_MAC_ADDR_SIZE];
	uint32_t prefix_len = ~0;

	ipacm_cmd_q_data evt_data;
	ipacm_cmd_q_data vlan_event;
	ipacm_event_data_all *data_all;
	ipacm_event_data_fid *data_fid;
	ipacm_event_data_addr *data_addr;
	ipacm_event_data_all *vlan_data;
	struct ipa_vlan_iface_info vlan_info;
	struct ipa_macsec_map macsec_map, *macsec_map_data;
	ipacm_event_mtu_info *mtu_event = NULL;
	ipa_mtu_info *mtu_info;
	IPACM_Config* config = NULL;
	int idx = 0;
	int instance_found = 0;
	char phy_dev[ETH_PHY_IFACE_LEN] = { 0 };

	memset(nullMac, 0, sizeof(nullMac));
	memset(&vlan_info, 0, sizeof(vlan_info));
	memset(&macsec_map, 0, sizeof(macsec_map));
	while(NLMSG_OK(nlh, buflen))
	{
		memset(dev_name,0,IF_NAME_LEN);
		IPACMDBG("Received msg:%d from netlink\n", nlh->nlmsg_type)
		switch(nlh->nlmsg_type)
		{
		case RTM_NEWLINK:
			msg_ptr->type = nlh->nlmsg_type;
			msg_ptr->link_event = true;
			if (IPACM_SUCCESS != ipa_nl_decode_rtm_link(buffer, buflen, &(msg_ptr->nl_link_info))) {
				IPACMERR("Failed to decode rtm link message\n");
				return IPACM_FAILURE;
			} else {
				IPACMDBG("Got RTM_NEWLINK with below values\n");
				IPACMDBG("RTM_NEWLINK, ifi_change:%d\n", msg_ptr->nl_link_info.metainfo.ifi_change);
				IPACMDBG("RTM_NEWLINK, ifi_flags:%d\n", msg_ptr->nl_link_info.metainfo.ifi_flags);
				IPACMDBG("RTM_NEWLINK, ifi_index:%d\n", msg_ptr->nl_link_info.metainfo.ifi_index);
				IPACMDBG("RTM_NEWLINK, family:%d\n", msg_ptr->nl_link_info.metainfo.ifi_family);
				IPACMDBG("RTM_NEWLINK, ifi_type:%d\n", msg_ptr->nl_link_info.metainfo.ifi_type);
				/**
				 * RTM_NEWLINK event with AF_BRIDGE family should be ignored in
				 * Android but this should be processed in case of MDM for
				 * Ehernet interface.
				 */
#ifdef FEATURE_EoGRE || FEATURE_PMIPV6
				// struct nlmsghdr *h;
				struct ifinfomsg *ifi2;
				//ifi_type is 1 for gretap2
			if(msg_ptr->nl_link_info.metainfo.ifi_type == 778 || msg_ptr->nl_link_info.metainfo.ifi_type == 823 || msg_ptr->nl_link_info.metainfo.ifi_type == 769){//GRE tunnel
					if(IFF_UP & msg_ptr->nl_link_info.metainfo.ifi_flags){
						ifi2 = (struct ifinfomsg*) NLMSG_DATA(nlh);
							if(populate_gre_details(ifi2,nlh->nlmsg_len,msg_ptr->nl_link_info.metainfo.ifi_type))
								{
									IPACMDBG("Failed to get GRE info\n");
								}
							else{
								IPACMDBG("GRE info populated\n");
								//post GRE UP event
								}
					}
				}
				else if (msg_ptr->nl_link_info.metainfo.ifi_type == 1)
				{
					//EoGRE tunnel
					if (IFF_UP & msg_ptr->nl_link_info.metainfo.ifi_flags)
					{
						ifi2 = (struct ifinfomsg*) NLMSG_DATA(nlh);
						if (get_eogre_tunnel_details(ifi2, nlh->nlmsg_len, msg_ptr->nl_link_info.metainfo.ifi_type))
						{
							IPACMDBG("Failed to get EoGRE tunnel info\n");
						}
						else
						{
							IPACMDBG("EoGRE tunnel info populated\n");
						}
					}
				}
#endif
#ifdef FEATURE_IPA_ANDROID
				if (msg_ptr->nl_link_info.metainfo.ifi_family == AF_BRIDGE) {
					IPACMERR(" ignore this RTM_NEWLINK msg \n");
					return IPACM_SUCCESS;
				}
#endif

				ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_link_info.metainfo.ifi_index);
				if (ret_val != IPACM_SUCCESS) {
					IPACMERR("Error while getting interface name\n");
				}

				if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_VLAN) {
					strlcpy(vlan_info.name, msg_ptr->nl_link_info.name, sizeof(vlan_info.name));
					vlan_info.vlan_id = msg_ptr->nl_link_info.vlan_id;
					vlan_info.vlan_interface_index = msg_ptr->nl_link_info.metainfo.ifi_index;

					if(ipa_nl_get_vlan_priority(&vlan_info) != IPACM_SUCCESS)
						IPACMDBG_H("Failed to fetch VLAN PCP");

					IPACMDBG("Add vlan<->interface details with vlan: %d interface: %s interface index %d priority %d\n",
						vlan_info.vlan_id, vlan_info.name, vlan_info.vlan_interface_index, vlan_info.priority);
					IPACM_Iface::ipacmcfg->add_vlan_iface(&vlan_info);
				}

				if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_MACSEC) {
					strlcpy(macsec_map.macsec_name, msg_ptr->nl_link_info.name, sizeof(macsec_map.macsec_name));
					if (get_macsec_lower_interface_name(&macsec_map, master_dev_name) != IPACM_SUCCESS)
						return IPACM_FAILURE;
					strlcpy(macsec_map.phy_name, master_dev_name, sizeof(macsec_map.phy_name));
					if (IPACM_Iface::ipacmcfg->insertOrAssignMacsecMap(&macsec_map)) {
						evt_data.event = IPA_HANDLE_MACSEC_ADD;
						macsec_map_data = static_cast<decltype(macsec_map_data)>(malloc(sizeof(*macsec_map_data)));
						if (!macsec_map_data) {
							IPACMERR("malloc failed\n");
							return IPACM_FAILURE;
						}
						memcpy(macsec_map_data, &macsec_map, sizeof(macsec_map));
						evt_data.evt_data = macsec_map_data;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
					}
				}

				if (IFF_UP & msg_ptr->nl_link_info.metainfo.ifi_change) {
					IPACMDBG("GOT useful newlink event\n");

					IPACMDBG_H("New Interface %s  with IP-family: %d \n",
						dev_name, msg_ptr->nl_link_info.metainfo.ifi_family);

					data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
					if (data_fid == NULL) {
						IPACMERR("unable to allocate memory for event data_fid\n");
						return IPACM_FAILURE;
					}
					data_fid->if_index = msg_ptr->nl_link_info.metainfo.ifi_index;
					strlcpy(data_fid->iface_name, dev_name, sizeof(data_fid->iface_name));
					if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_PPP) {
						data_fid->is_ppp_iface = true;
					}
					else {
						data_fid->is_ppp_iface = false;
					}
					if (msg_ptr->nl_link_info.vlan_id) {
						memset(&vlan_info, 0, sizeof(ipa_vlan_iface_info));
						strlcpy(vlan_info.name, msg_ptr->nl_link_info.name, IPA_RESOURCE_NAME_MAX);
						vlan_info.vlan_id = msg_ptr->nl_link_info.vlan_id;
						vlan_info.vlan_interface_index = msg_ptr->nl_link_info.metainfo.ifi_index;
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
#ifdef FEATURE_IPoGRE
						if (strncmp(dev_name, IPACM_Iface::ipacmcfg->rgip_iface_name,
							sizeof(IPACM_Iface::ipacmcfg->rgip_iface_name)) == 0)
						{
							/* Query the IP address currently assigned to the interface */
							uint32_t queried_ip = 0;
							int query_fd = socket(AF_INET, SOCK_DGRAM, 0);
							if (query_fd >= 0)
							{
								struct ifreq ifr_query;
								memset(&ifr_query, 0, sizeof(ifr_query));
								strlcpy(ifr_query.ifr_name, dev_name, IFNAMSIZ);
								if (ioctl(query_fd, SIOCGIFADDR, &ifr_query) == 0)
								{
									queried_ip = ntohl(((struct sockaddr_in *)&ifr_query.ifr_addr)->sin_addr.s_addr);
								}
								close(query_fd);
							}
							if (queried_ip != 0)
							{
								IPACM_Iface::ipacmcfg->rgip_ip = queried_ip;
								/* Check whether rgip interface has dummy IP assigned, if yes post RGIP ADD with proper stored rgip */
								if ((IPACM_Iface::ipacmcfg->rgip_ip >> 24) == DUMMY_RGIP_ADDRESS)
								{
									IPACMDBG_H("RGIP iface %s link up but stored ip 0x%x is dummy "
											"(169.x.x.x), skip IPA_HANDLE_RGIP_UP\n",
											dev_name, IPACM_Iface::ipacmcfg->rgip_ip);

									IPACMDBG_H("RGIP iface %s link up, post IPA_HANDLE_RGIP_UP with stored ip 0x%x\n",
										dev_name, IPACM_Iface::ipacmcfg->rgip_ip_ippt);
									ipacm_cmd_q_data rgip_evt_data;
									uint32_t *rgip_v4 = (uint32_t*) malloc(sizeof(uint32_t));
									if(rgip_v4 == NULL)
									{
										IPACMERR("Memory not assigned to rgip\n");
									}
									else
									{
										*rgip_v4 = IPACM_Iface::ipacmcfg->rgip_ip_ippt;
										memset(&rgip_evt_data, 0, sizeof(rgip_evt_data));
										rgip_evt_data.event = IPA_HANDLE_RGIP_UP;
										rgip_evt_data.evt_data = rgip_v4;
										IPACM_EvtDispatcher::PostEvt(&rgip_evt_data);
									}
								}
								else
								{
									IPACMDBG_H("RGIP iface %s link up, post IPA_HANDLE_RGIP_UP with stored ip 0x%x\n",
										dev_name, IPACM_Iface::ipacmcfg->rgip_ip);
									ipacm_cmd_q_data rgip_evt_data;
									uint32_t *rgip_v4 = (uint32_t*) malloc(sizeof(uint32_t));
									if(rgip_v4 == NULL)
									{
										IPACMERR("Memory not assigned to rgip\n");
										}
									else
									{
										IPACM_Iface::ipacmcfg->rgip_ip = queried_ip;
										*rgip_v4 = IPACM_Iface::ipacmcfg->rgip_ip;
										memset(&rgip_evt_data, 0, sizeof(rgip_evt_data));
										rgip_evt_data.event = IPA_HANDLE_RGIP_UP;
										rgip_evt_data.evt_data = rgip_v4;
										IPACM_EvtDispatcher::PostEvt(&rgip_evt_data);
									}
								}
							}
							else
							{
								IPACMDBG_H("RGIP iface %s link up but no IP assigned yet, skip IPA_HANDLE_RGIP_UP\n",
									dev_name);
							}
						}
#endif
					} else {
					if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_MACSEC ||
						IPACM_Iface::ipacmcfg->populateMacsecMap(msg_ptr->nl_link_info.metainfo.ifi_index,
						&macsec_map)) {
						if (IPACM_Iface::ipacmcfg->delMacsecMap(&macsec_map)) {
							evt_data.event = IPA_HANDLE_MACSEC_DEL;
							macsec_map_data = static_cast<decltype(macsec_map_data)>
								(malloc(sizeof(*macsec_map_data)));
							if (!macsec_map_data) {
								IPACMERR("malloc failed\n");
								return IPACM_FAILURE;
							}
							memcpy(macsec_map_data, &macsec_map, sizeof(macsec_map));
							evt_data.evt_data = macsec_map_data;
							IPACM_EvtDispatcher::PostEvt(&evt_data);
						}
					}
#ifdef FEATURE_IPoGRE
					if (strncmp(dev_name, IPACM_Iface::ipacmcfg->rgip_iface_name,
						sizeof(IPACM_Iface::ipacmcfg->rgip_iface_name)) == 0)
					{
						IPACMDBG_H("RGIP iface %s link down, post IPA_HANDLE_RGIP_DEL\n", dev_name);
						ipacm_cmd_q_data rgip_evt_data;
						uint32_t *rgip_v4 = (uint32_t*) malloc(sizeof(uint32_t));
						if(rgip_v4 == NULL)
						{
							IPACMERR("Memory not assigned to rgip\n");
						}
						else
						{
							memset(&rgip_evt_data, 0, sizeof(rgip_evt_data));
							rgip_evt_data.event = IPA_HANDLE_RGIP_DEL;
							*rgip_v4 = 0;
							rgip_evt_data.evt_data = rgip_v4;
							IPACM_EvtDispatcher::PostEvt(&rgip_evt_data);
						}
					}
#endif
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

				ipa_interface_index = IPACM_Iface::iface_ipa_index_query(msg_ptr->nl_link_info.metainfo.ifi_index);
				if (ipa_interface_index != IPACM_FAILURE)
				{
					if (IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].ifi_flags != msg_ptr->nl_link_info.metainfo.ifi_flags)

					{
						IPACMDBG("Change in ifi_flags process event\n");
						IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].ifi_flags = msg_ptr->nl_link_info.metainfo.ifi_flags;
					}
					else
					{
						IPACMDBG("No change in ifi_flags return\n");
						return IPACM_SUCCESS;
					}
				}
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
						return IPACM_FAILURE;
					}
					data_fid->if_index = msg_ptr->nl_link_info.metainfo.ifi_index;
					if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_PPP) {
						data_fid->is_ppp_iface = true;
					}
					else {
						data_fid->is_ppp_iface = false;
					}

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
						return IPACM_FAILURE;
					}

					ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_link_info.metainfo.ifi_index);
					if (ret_val != IPACM_SUCCESS) {
						IPACMERR("Error while getting interface name\n");
					}
					IPACMDBG_H("Got a usb link_down event (Interface %s) \n", dev_name);


					if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_VLAN)
					{
						/* generate IPA_ROUTE_DEL_VLAN_PDN_EVENT for v4 PDN as v6 PDN already has associated vlan*/
						ipacm_cmd_q_data del_evt_data;
						ipacm_event_route_vlan *del_vlan_data;
						del_evt_data.event = IPA_ROUTE_DEL_VLAN_PDN_EVENT;
						del_vlan_data = (ipacm_event_route_vlan *)malloc(sizeof(ipacm_event_route_vlan));
						if(!del_vlan_data)
						{
							IPACMERR("couldn't allocate memory for new vlan pdn event\n");
							return IPACM_FAILURE;
						}
						memset(del_vlan_data, 0, sizeof(ipacm_event_route_vlan));
						del_vlan_data->iptype = IPA_IP_MAX;
						del_vlan_data->VlanID = vlan_info.vlan_id;
						del_evt_data.evt_data = del_vlan_data;
						IPACMDBG_H("sending IPA_ROUTE_DEL_VLAN_PDN_EVENT vlan id %d, iptype %d,\n", del_vlan_data->VlanID, del_vlan_data->iptype);
						IPACM_EvtDispatcher::PostEvt(&del_evt_data);

						IPACMDBG("Delete vlan iface For vlan_id %d \n", vlan_info.vlan_id);
						IPACM_Iface::ipacmcfg->del_vlan_iface(&vlan_info);
					}
					if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_MACSEC ||
						IPACM_Iface::ipacmcfg->populateMacsecMap(msg_ptr->nl_link_info.metainfo.ifi_index,
						&macsec_map)) {
						if (IPACM_Iface::ipacmcfg->delMacsecMap(&macsec_map)) {
							evt_data.event = IPA_HANDLE_MACSEC_DEL;
							macsec_map_data = static_cast<decltype(macsec_map_data)>
								(malloc(sizeof(*macsec_map_data)));
							if (!macsec_map_data) {
								IPACMERR("malloc failed\n");
								return IPACM_FAILURE;
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
						return IPACM_SUCCESS;
					}

					data_fid->if_index = msg_ptr->nl_link_info.metainfo.ifi_index;
					strlcpy(data_fid->iface_name, dev_name, sizeof(data_fid->iface_name));
					if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_PPP) {
						data_fid->is_ppp_iface = true;
					}
					else {
						data_fid->is_ppp_iface = false;
					}

					/*--------------------------------------------------------------------------
						Post LAN iface (ECM) link down event
					---------------------------------------------------------------------------*/
#ifdef FEATURE_IPoGRE
					if (strncmp(dev_name, IPACM_Iface::ipacmcfg->rgip_iface_name,
						sizeof(IPACM_Iface::ipacmcfg->rgip_iface_name)) == 0)
					{
						IPACMDBG_H("RGIP iface %s link down (lower), post IPA_HANDLE_RGIP_DEL\n", dev_name);
						ipacm_cmd_q_data rgip_evt_data;
						uint32_t *rgip_v4 = (uint32_t*) malloc(sizeof(uint32_t));
						if(rgip_v4 == NULL)
						{
							IPACMERR("Memory not assigned to rgip\n");
						}
						else
						{
							memset(&rgip_evt_data, 0, sizeof(rgip_evt_data));
							rgip_evt_data.event = IPA_HANDLE_RGIP_DEL;
							*rgip_v4 = 0;
							rgip_evt_data.evt_data = rgip_v4;
							IPACM_EvtDispatcher::PostEvt(&rgip_evt_data);
						}
					}
#endif
					evt_data.event = IPA_LINK_DOWN_EVENT;
					evt_data.evt_data = data_fid;
					IPACMDBG_H("Posting usb IPA_LINK_DOWN_EVENT with if index: %d\n", data_fid->if_index);
					IPACM_EvtDispatcher::PostEvt(&evt_data);
				}
			}
			break;

		case RTM_DELLINK:
			IPACMDBG("\n GOT dellink event\n");
			msg_ptr->type = nlh->nlmsg_type;
			msg_ptr->link_event = true;
			IPACMDBG("entering rtm decode\n");
			if(IPACM_SUCCESS != ipa_nl_decode_rtm_link(buffer, buflen, &(msg_ptr->nl_link_info)))
			{
				IPACMERR("Failed to decode rtm link message\n");
				return IPACM_FAILURE;
			}
			else
			{
				IPACMDBG("Got RTM_DELLINK with below values\n");
				IPACMDBG("RTM_DELLINK, ifi_change:%d\n", msg_ptr->nl_link_info.metainfo.ifi_change);
				IPACMDBG("RTM_DELLINK, ifi_flags:%d\n", msg_ptr->nl_link_info.metainfo.ifi_flags);
				IPACMDBG("RTM_DELLINK, ifi_index:%d\n", msg_ptr->nl_link_info.metainfo.ifi_index);
				IPACMDBG("RTM_DELLINK, family:%d\n", msg_ptr->nl_link_info.metainfo.ifi_family);
				IPACMDBG("RTM_DELLINK, type:%d\n", msg_ptr->nl_link_info.metainfo.ifi_type);
				/* RTM_NEWLINK event with AF_BRIDGE family should be ignored in Android
				 *    but this should be processed in case of MDM for Ehernet interface.
				 */
				struct ifinfomsg *ifi2;
#if defined(FEATURE_PMIPV6) || defined(FEATURE_IPoGRE)
				if(msg_ptr->nl_link_info.metainfo.ifi_type == 778 || msg_ptr->nl_link_info.metainfo.ifi_type == 823 || msg_ptr->nl_link_info.metainfo.ifi_type == 769)
				{//GRE tunnel
						ifi2 = (struct ifinfomsg*) NLMSG_DATA(nlh);
						tunnel_delete(ifi2, nlh->nlmsg_len,msg_ptr->nl_link_info.metainfo.ifi_type);
						IPACMDBG("Tunnel Delete Done\n");
				}
#endif
#ifdef FEATURE_EoGRE
				if(msg_ptr->nl_link_info.metainfo.ifi_type == 1)
				{
					ifi2 = (struct ifinfomsg*) NLMSG_DATA(nlh);
					del_eogre_tunnel(ifi2, nlh->nlmsg_len,msg_ptr->nl_link_info.metainfo.ifi_type);
					IPACMDBG("Tunnel Delete Done\n");
				}
#endif
#ifdef FEATURE_IPoGRE
				struct ifinfomsg *ifi2_rgip = (struct ifinfomsg*) NLMSG_DATA(nlh);
				struct rtattr *attrib1[IFLA_MAX + 1];
				getAttr(attrib1, IFLA_MAX, IFLA_RTA(ifi2_rgip), nlh->nlmsg_len, 0, false);
				if (attrib1[IFLA_IFNAME]) {
					if (strncmp((char*)RTA_DATA(attrib1[IFLA_IFNAME]), IPACM_Iface::ipacmcfg->rgip_iface_name,
						sizeof(IPACM_Iface::ipacmcfg->rgip_iface_name)) == 0)
					{
						IPACMDBG_H("RGIP iface %s link down/delete, post IPA_HANDLE_RGIP_DEL\n", dev_name);
						ipacm_cmd_q_data rgip_evt_data;
						uint32_t *rgip_v4 = (uint32_t*) malloc(sizeof(uint32_t));
						if(rgip_v4 == NULL)
						{
							IPACMERR("Memory not assigned to rgip\n");
						}
						else
						{
							memset(&rgip_evt_data, 0, sizeof(rgip_evt_data));
							rgip_evt_data.event = IPA_HANDLE_RGIP_DEL;
							*rgip_v4 = 0;
							rgip_evt_data.evt_data = rgip_v4;
							IPACM_EvtDispatcher::PostEvt(&rgip_evt_data);
						}
					}
				}
#endif
				if (msg_ptr->nl_link_info.metainfo.ifi_family == AF_BRIDGE || msg_ptr->nl_link_info.metainfo.ifi_family == AF_UNSPEC)
				{
					IPACMDBG("Deleting the bridge<->vlan mapping entry with intterface index %d\n", msg_ptr->nl_link_info.metainfo.ifi_index);
					uint16_t vlan_master_interface_index = msg_ptr->nl_link_info.metainfo.ifi_index;
					IPACM_Iface::ipacmcfg->del_bridge_vlan_mapping(&vlan_master_interface_index);
					return IPACM_SUCCESS;
				}
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

					if(ipa_nl_get_vlan_priority(&vlan_info) != IPACM_SUCCESS)
						IPACMDBG_H("Failed to fetch VLAN PCP");
				}

				if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_MACSEC) {
					strlcpy(macsec_map.macsec_name, msg_ptr->nl_link_info.name, sizeof(macsec_map.macsec_name));
					ret_val = ipa_get_if_name(master_dev_name, msg_ptr->nl_link_info.master_interface_index);
					if (ret_val != IPACM_SUCCESS) {
						IPACMERR("Error while getting master interface name\n");
						return IPACM_FAILURE;
					}
					strlcpy(macsec_map.phy_name, msg_ptr->nl_link_info.name, sizeof(macsec_map.phy_name));
				}

				if(msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_VLAN)
				{
					IPACMDBG("Process RTM_DELLINK For vlan_id %d \n", vlan_info.vlan_id);

					/* generate IPA_ROUTE_DEL_VLAN_PDN_EVENT for v4 PDN as v6 PDN already has associated vlan*/
					ipacm_cmd_q_data del_evt_data;
					ipacm_event_route_vlan *del_vlan_data;
					del_evt_data.event = IPA_ROUTE_DEL_VLAN_PDN_EVENT;
					del_vlan_data = (ipacm_event_route_vlan *)malloc(sizeof(ipacm_event_route_vlan));
					if(!del_vlan_data)
					{
						IPACMERR("couldn't allocate memory for new vlan pdn event\n");
						return IPACM_FAILURE;
					}
					memset(del_vlan_data, 0, sizeof(ipacm_event_route_vlan));
					del_vlan_data->iptype = IPA_IP_MAX;
					del_vlan_data->VlanID = vlan_info.vlan_id;
					del_evt_data.evt_data = del_vlan_data;
					IPACMDBG_H("sending IPA_ROUTE_DEL_VLAN_PDN_EVENT vlan id %d, iptype %d,\n", del_vlan_data->VlanID, del_vlan_data->iptype);
					IPACM_EvtDispatcher::PostEvt(&del_evt_data);

					IPACMDBG("Delete vlan iface For vlan_id %d \n", vlan_info.vlan_id);
					IPACM_Iface::ipacmcfg->del_vlan_iface(&vlan_info);
				}
				if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_MACSEC ||
					IPACM_Iface::ipacmcfg->populateMacsecMap(msg_ptr->nl_link_info.metainfo.ifi_index,
					&macsec_map)) {
					if (IPACM_Iface::ipacmcfg->delMacsecMap(&macsec_map)) {
						evt_data.event = IPA_HANDLE_MACSEC_DEL;
						macsec_map_data = static_cast<decltype(macsec_map_data)>
							(malloc(sizeof(*macsec_map_data)));
						if (!macsec_map_data) {
							IPACMERR("malloc failed\n");
							return IPACM_FAILURE;
						}
						memcpy(macsec_map_data, &macsec_map, sizeof(macsec_map));
						evt_data.evt_data = macsec_map_data;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
					}
				}

				/* post link down to command queue */
				evt_data.event = IPA_LINK_DOWN_EVENT;
				data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
				if(data_fid == NULL)
				{
					IPACMERR("unable to allocate memory for event data_fid\n");
					return IPACM_FAILURE;
				}

				data_fid->if_index = msg_ptr->nl_link_info.metainfo.ifi_index;
				if (msg_ptr->nl_link_info.link_type == IPA_LINK_TYPE_PPP)
				{
					data_fid->is_ppp_iface = true;
				}
				else
				{
					data_fid->is_ppp_iface = false;
				}
				strlcpy(data_fid->iface_name, dev_name, sizeof(data_fid->iface_name));

				IPACMDBG_H("posting IPA_LINK_DOWN_EVENT with if idnex:%d\n",
								 data_fid->if_index);
				evt_data.evt_data = data_fid;
				IPACM_EvtDispatcher::PostEvt(&evt_data);
				/* finish command queue */
			}
			break;

		case RTM_NEWADDR:
		case RTM_DELADDR:
			if(nlh->nlmsg_type == RTM_NEWADDR)
			{
				IPACMDBG("\n GOT RTM_NEWADDR event\n");
			}
			else
			{
				IPACMDBG("\n GOT RTM_DELADDR event\n");
			}

			if(IPACM_SUCCESS != ipa_nl_decode_rtm_addr(buffer, buflen, &(msg_ptr->nl_addr_info)))
			{
				IPACMERR("Failed to decode rtm addr message\n");
				return IPACM_FAILURE;
			}
			else
			{
				IPACMDBG("msg_type: %d\n", nlh->nlmsg_type);
				IPACMDBG("ifa_family: %d\n", msg_ptr->nl_addr_info.metainfo.ifa_family);
				IPACMDBG("ifa_prefixlen: %d\n", msg_ptr->nl_addr_info.metainfo.ifa_prefixlen);
				IPACMDBG("ifa_flags: %d\n", msg_ptr->nl_addr_info.metainfo.ifa_flags);
				IPACMDBG("ifa_scope: %d\n", msg_ptr->nl_addr_info.metainfo.ifa_scope);
				IPACMDBG("ifa_index: %d\n", msg_ptr->nl_addr_info.metainfo.ifa_index);
				IPACMDBG("param_mask: 0x%x\n", msg_ptr->nl_addr_info.attr_info.param_mask);

				ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_addr_info.metainfo.ifa_index);
				if(ret_val != IPACM_SUCCESS)
				{
					IPACMERR("Error while getting interface name\n");
					return IPACM_FAILURE;
				}
				IPACMDBG("Interface %s \n", dev_name);

				data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
				if(data_addr == NULL)
				{
					IPACMERR("unable to allocate memory for event data_addr\n");
					return IPACM_FAILURE;
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

				if(AF_INET6 == msg_ptr->nl_addr_info.attr_info.local_addr.ss_family &&
					IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable)
				{
					IPACM_NL_REPORT_ADDR( "IFA_ADDRESS:", msg_ptr->nl_addr_info.attr_info.local_addr );
					IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr, msg_ptr->nl_addr_info.attr_info.local_addr);
					data_addr->iptype = IPA_IP_v6;
					data_addr->ipv6_addr[0] = ntohl(data_addr->ipv6_addr[0]);
					data_addr->ipv6_addr[1] = ntohl(data_addr->ipv6_addr[1]);
					data_addr->ipv6_addr[2] = ntohl(data_addr->ipv6_addr[2]);
					data_addr->ipv6_addr[3] = ntohl(data_addr->ipv6_addr[3]);
					IPACMDBG("Posting IPA_ADDR_ADD_EVENT with if index:%d, ipv6 addr:0x%x:%x:%x:%x\n",
								data_addr->if_index,
								data_addr->ipv6_addr[0],
								data_addr->ipv6_addr[1],
								data_addr->ipv6_addr[2],
								data_addr->ipv6_addr[3]);
				}

				if(nlh->nlmsg_type == RTM_NEWADDR)
				{
					evt_data.event = IPA_ADDR_ADD_EVENT;
#ifdef FEATURE_IPoGRE
					if ((data_addr->iptype == IPA_IP_v4) && (strncmp(dev_name, IPACM_Iface::ipacmcfg->rgip_iface_name, sizeof(IPACM_Iface::ipacmcfg->rgip_iface_name)) == 0))
					{
						if (IPACM_Iface::ipacmcfg->rgip_ip != 0)
						{
							IPACMDBG_H("RGIP iface %s addr add but rgip_ip 0x%x already "
								"assigned and non-zero, skip IPA_HANDLE_RGIP_UP\n",
								dev_name, IPACM_Iface::ipacmcfg->rgip_ip);
						}
						else {
							IPACMDBG_H("RGIP iface %s addr add, post IPA_HANDLE_RGIP_UP\n", dev_name);
							if((data_addr->ipv4_addr >> 24) == DUMMY_RGIP_ADDRESS)
							{
								IPACMDBG_H("RGIP iface %s got dummy IP 0x%x (169.x.x.x), "
										"skip IPA_HANDLE_RGIP_UP and rgip_ip update\n",
										dev_name, data_addr->ipv4_addr);

								IPACMDBG_H("RGIP iface %s link up, post IPA_HANDLE_RGIP_UP with stored ip 0x%x\n",
									dev_name, IPACM_Iface::ipacmcfg->rgip_ip_ippt);
								IPACM_Iface::ipacmcfg->rgip_ip = IPACM_Iface::ipacmcfg->rgip_ip_ippt;
								ipacm_cmd_q_data rgip_evt_data;
								uint32_t *rgip_v4 = (uint32_t*) malloc(sizeof(uint32_t));
								if(rgip_v4 == NULL)
								{
									IPACMERR("Memory not assigned to rgip\n");
								}
								else
								{
									*rgip_v4 = IPACM_Iface::ipacmcfg->rgip_ip_ippt;
									memset(&rgip_evt_data, 0, sizeof(rgip_evt_data));
									rgip_evt_data.event = IPA_HANDLE_RGIP_UP;
									rgip_evt_data.evt_data = rgip_v4;
									IPACM_EvtDispatcher::PostEvt(&rgip_evt_data);
								}
							}
							else
							{
								IPACMDBG_H("RGIP iface %s addr add, post IPA_HANDLE_RGIP_UP\n", dev_name);
								ipacm_cmd_q_data rgip_evt_data;
								uint32_t *rgip_v4 = (uint32_t*) malloc(sizeof(uint32_t));
								if(rgip_v4 == NULL)
								{
									IPACMERR("Memory not assigned to rgip\n");
								}
								else
								{
									memcpy(rgip_v4,&data_addr->ipv4_addr,sizeof(uint32_t));
									memset(&rgip_evt_data, 0, sizeof(rgip_evt_data));
									rgip_evt_data.event = IPA_HANDLE_RGIP_UP;
									rgip_evt_data.evt_data = rgip_v4;
									IPACM_EvtDispatcher::PostEvt(&rgip_evt_data);
									IPACM_Iface::ipacmcfg->rgip_ip = data_addr->ipv4_addr;
								}
							}
						}
					}
					/* The RGIP interface was deleted and a new interface came up with a
					 * different name but the same IPv4 address as the stored rgip_ip.
					 * Identify it as the new RGIP interface and re-trigger RGIP UP. */
					else if ((data_addr->iptype == IPA_IP_v4) &&
					         (IPACM_Iface::ipacmcfg->rgip_ip != 0) &&
					         (data_addr->ipv4_addr == IPACM_Iface::ipacmcfg->rgip_ip))
					{
						IPACMDBG_H("New iface %s has IP 0x%x matching stored rgip_ip — "
						           "treating as new RGIP iface (old name: %s)\n",
						           dev_name, data_addr->ipv4_addr,
						           IPACM_Iface::ipacmcfg->rgip_iface_name);
						/* Update rgip_iface_name to the new interface name */
						strlcpy(IPACM_Iface::ipacmcfg->rgip_iface_name, dev_name,
						        sizeof(IPACM_Iface::ipacmcfg->rgip_iface_name));
						ipacm_cmd_q_data rgip_evt_data;
						uint32_t *rgip_v4 = (uint32_t*) malloc(sizeof(uint32_t));
						if(rgip_v4 == NULL)
						{
							IPACMERR("Memory not assigned to rgip\n");
						}
						else
						{
							memcpy(rgip_v4,&data_addr->ipv4_addr,sizeof(uint32_t));
							memset(&rgip_evt_data, 0, sizeof(rgip_evt_data));
							rgip_evt_data.event = IPA_HANDLE_RGIP_UP;
							rgip_evt_data.evt_data = rgip_v4;
							IPACM_EvtDispatcher::PostEvt(&rgip_evt_data);
							/* Refresh rgip_ip with the confirmed address */
							IPACM_Iface::ipacmcfg->rgip_ip = data_addr->ipv4_addr;
						}
					}
#endif
				}
				else
				{
#ifdef FEATURE_IPoGRE
					if ((data_addr->iptype == IPA_IP_v4) && (strncmp(dev_name, IPACM_Iface::ipacmcfg->rgip_iface_name, sizeof(IPACM_Iface::ipacmcfg->rgip_iface_name)) == 0))
					{
						IPACMDBG_H("RGIP iface %s addr deleted, post IPA_HANDLE_RGIP_DEL\n", dev_name);
						ipacm_cmd_q_data rgip_evt_del_data;
						uint32_t *rgip_v4_del = (uint32_t*) malloc(sizeof(uint32_t));
						if(rgip_v4_del == NULL)
						{
							IPACMERR("Memory not assigned to rgip\n");
						}
						else
						{
							memset(&rgip_evt_del_data, 0, sizeof(rgip_evt_del_data));
							rgip_evt_del_data.event = IPA_HANDLE_RGIP_DEL;
							*rgip_v4_del = 0;
							rgip_evt_del_data.evt_data = rgip_v4_del;
							IPACM_EvtDispatcher::PostEvt(&rgip_evt_del_data);
						}
					}
#endif
					evt_data.event = IPA_ADDR_DEL_EVENT;
				}
				data_addr->if_index = msg_ptr->nl_addr_info.metainfo.ifa_index;
				strlcpy(data_addr->iface_name, dev_name, sizeof(data_addr->iface_name));
				if(AF_INET6 == msg_ptr->nl_addr_info.attr_info.prefix_addr.ss_family)
				{
					if(nlh->nlmsg_type == RTM_NEWADDR)
					{
						IPACMDBG("Posting IPA_ADDR_ADD_EVENT with if index:%d, ipv6 addr:0x%x:%x:%x:%x\n",
								 data_addr->if_index,
								 data_addr->ipv6_addr[0],
								 data_addr->ipv6_addr[1],
								 data_addr->ipv6_addr[2],
								 data_addr->ipv6_addr[3]);
					}
					else
					{
						IPACMDBG("Posting IPA_ADDR_DEL_EVENT with if index:%d, ipv6 addr:0x%x:%x:%x:%x\n",
								 data_addr->if_index,
								 data_addr->ipv6_addr[0],
								 data_addr->ipv6_addr[1],
								 data_addr->ipv6_addr[2],
								 data_addr->ipv6_addr[3]);
					}
					evt_data.evt_data = data_addr;
					IPACM_EvtDispatcher::PostEvt(&evt_data);
				}
				else if(AF_INET == msg_ptr->nl_addr_info.attr_info.prefix_addr.ss_family)
				{
					if(nlh->nlmsg_type == RTM_NEWADDR)
					{
						IPACMDBG("Posting IPA_ADDR_ADD_EVENT with if index:%d, ipv4 addr:0x%x\n",
								 data_addr->if_index,
								 data_addr->ipv4_addr);
					}
					else
					{
						IPACMDBG("Posting IPA_ADDR_DEL_EVENT with if index:%d, ipv4 addr:0x%x\n",
								 data_addr->if_index,
								 data_addr->ipv4_addr);
					}
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

			if(IPACM_SUCCESS != ipa_nl_decode_rtm_route(buffer, buflen, &(msg_ptr->nl_route_info)))
			{
				IPACMERR("Failed to decode rtm route message\n");
				return IPACM_FAILURE;
			}

			IPACMDBG("In case RTM_NEWROUTE\n");
			IPACMDBG("rtm_type: %d\n", msg_ptr->nl_route_info.metainfo.rtm_type);
			IPACMDBG("protocol: %d\n", msg_ptr->nl_route_info.metainfo.rtm_protocol);
			IPACMDBG("rtm_scope: %d\n", msg_ptr->nl_route_info.metainfo.rtm_scope);
			IPACMDBG("rtm_table: %d\n", msg_ptr->nl_route_info.metainfo.rtm_table);
			IPACMDBG("rtm_family: %d\n", msg_ptr->nl_route_info.metainfo.rtm_family);
			IPACMDBG("param_mask: 0x%x\n", msg_ptr->nl_route_info.attr_info.param_mask);

			/* take care of MTU */
			if((msg_ptr->nl_route_info.metainfo.rtm_type == RTN_UNICAST) &&
				 ((msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_BOOT) ||
				  (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_RA) ||
				  (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_STATIC))&&
				  ((msg_ptr->nl_route_info.metainfo.rtm_scope == RT_SCOPE_UNIVERSE)||
				  (msg_ptr->nl_route_info.metainfo.rtm_scope == RT_SCOPE_LINK))&&
				  (msg_ptr->nl_route_info.attr_info.mtu))
			{
				mtu_event = (ipacm_event_mtu_info *)malloc(sizeof(*mtu_event));
				if(mtu_event == NULL)
				{
					IPACMERR("Failed to allocate memory.\n");
					return IPACM_FAILURE;
				}

				memset(mtu_event, 0, sizeof(ipa_mtu_info));
				mtu_info = &(mtu_event->mtu_info);
				mtu_event->if_index = msg_ptr->nl_route_info.attr_info.oif_index;

				ret_val = ipa_get_if_name(mtu_info->if_name, msg_ptr->nl_route_info.attr_info.oif_index);
				if(ret_val != IPACM_SUCCESS)
				{
					IPACMERR("Error while getting interface name\n");
					free(mtu_event);
					return IPACM_FAILURE;
				}

				if(AF_INET == msg_ptr->nl_route_info.metainfo.rtm_family)
				{
					mtu_info->ip_type = IPA_IP_v4;
					mtu_info->mtu_v4 = msg_ptr->nl_route_info.attr_info.mtu;
					IPACMDBG_H("Posting IPA_MTU_SET if_name %s ip_type %d mtu_v4 %d\n",
						mtu_info->if_name, mtu_info->ip_type, mtu_info->mtu_v4);
				}
				else if(AF_INET6 == msg_ptr->nl_route_info.metainfo.rtm_family)
				{
					mtu_info->ip_type = IPA_IP_v6;
					mtu_info->mtu_v6 = msg_ptr->nl_route_info.attr_info.mtu;
					IPACMDBG_H("Posting IPA_MTU_SET if_name %s ip_type %d mtu_v6 %d\n",
						mtu_info->if_name, mtu_info->ip_type, mtu_info->mtu_v6);
				}
				else
				{
					IPACMERR("Invalid ip_type (%d) abort\n", msg_ptr->nl_route_info.metainfo.rtm_family);
					free(mtu_event);
					return IPACM_FAILURE;
				}

				evt_data.event = IPA_MTU_SET;
				evt_data.evt_data = mtu_event;
				IPACM_EvtDispatcher::PostEvt(&evt_data);
			}

			/* take care of route add default route & uniroute */
			if((AF_INET == msg_ptr->nl_route_info.metainfo.rtm_family) &&
				 (msg_ptr->nl_route_info.metainfo.rtm_type == RTN_UNICAST) &&
				 ((msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_BOOT) ||
				  (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_RA) ||
				  (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_STATIC))&&
				 ((msg_ptr->nl_route_info.metainfo.rtm_scope == RT_SCOPE_UNIVERSE)||
				 (msg_ptr->nl_route_info.metainfo.rtm_scope == RT_SCOPE_LINK)) &&
				 (IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable ||
				 IPACM_Iface::ipacmcfg->eth_vlan_wan_enable ||
				 (msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN)))
			{
				IPACMDBG("\n GOT RTM_NEWROUTE event\n");
				/* br-wan mode Enable with DHCP backhaul */
				if(strstr(dev_name, "br-ethwan"))
				{
					IPACM_Iface::ipacmcfg->eth_wan_br_wan_enable = true;
					IPACMDBG("GOT RTM_NEWROUTE event, br-wan enabled %d \n", IPACM_Iface::ipacmcfg->eth_wan_br_wan_enable);
				}

				if(strcmp(dev_name,MAPE_IFACE_NAME) == 0){
					IPACMDBG_H(" Ignoring route on %s \n",dev_name);
					return IPACM_SUCCESS;
				}
				if(msg_ptr->nl_route_info.attr_info.param_mask & IPA_RTA_PARAM_DST)
				{
					ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_route_info.attr_info.oif_index);
					if(ret_val != IPACM_SUCCESS)
					{
						IPACMERR("Error while getting interface name\n");
						return IPACM_FAILURE;
					}

					IPACM_NL_REPORT_ADDR( "route add -host", msg_ptr->nl_route_info.attr_info.dst_addr );
					IPACM_NL_REPORT_ADDR( "gw", msg_ptr->nl_route_info.attr_info.gateway_addr );
					IPACMDBG("dev %s\n",dev_name );
					/* insert to command queue */
					IPACM_EVENT_COPY_ADDR_v4( if_ipv4_addr, msg_ptr->nl_route_info.attr_info.dst_addr);
					temp = (-1);

					evt_data.event = IPA_ROUTE_ADD_EVENT;
					data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
					if(data_addr == NULL)
					{
						IPACMERR("unable to allocate memory for event data_addr\n");
						return IPACM_FAILURE;
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
						return IPACM_FAILURE;
					}
					else
					{
						IPACM_NL_REPORT_ADDR( "route add default gw \n", msg_ptr->nl_route_info.attr_info.gateway_addr );
						IPACMDBG_H("dev %s \n", dev_name);
						IPACM_NL_REPORT_ADDR( "dstIP: \n", msg_ptr->nl_route_info.attr_info.dst_addr );

						/* insert to command queue */
						data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
						if(data_addr == NULL)
						{
							IPACMERR("unable to allocate memory for event data_addr\n");
							return IPACM_FAILURE;
						}

						IPACM_EVENT_COPY_ADDR_v4( if_ipv4_addr, msg_ptr->nl_route_info.attr_info.dst_addr);
						IPACM_EVENT_COPY_ADDR_v4( if_ipipv4_addr_mask, msg_ptr->nl_route_info.attr_info.dst_addr);
						IPACM_EVENT_COPY_ADDR_v4( if_ipv4_addr_gw, msg_ptr->nl_route_info.attr_info.gateway_addr);

						data_addr->if_index = msg_ptr->nl_route_info.attr_info.oif_index;
						data_addr->iptype = IPA_IP_v4;
						data_addr->ipv4_addr = ntohl(if_ipv4_addr);
						data_addr->ipv4_addr_gw = ntohl(if_ipv4_addr_gw);
						data_addr->ipv4_addr_mask = ntohl(if_ipipv4_addr_mask);

						if(msg_ptr->nl_route_info.attr_info.param_mask & IPA_RTA_PARAM_GATEWAY &&
							(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable ||
							IPACM_Iface::ipacmcfg->eth_vlan_wan_enable ||
							IPACM_Iface::ipacmcfg->eth_wan_br_wan_enable ||
							(msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN)))
						{
							data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
							if(data_fid == NULL)
							{
								IPACMERR("unable to allocate memory for event_ecm data_fid\n");
								free(data_addr);
								return IPACM_FAILURE;
							}

							for (instance_found = IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces - MAX_NUM_PPPOE_MPDN;
								instance_found < IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces; instance_found++)
							{
								if(strcmp(
									IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name, dev_name) == 0)
								{
									break;
								}
							}

							if(instance_found < IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces)
							{
								IPACMDBG_H("Found devname:%s at iface_idx: %d\n", dev_name, instance_found);
								goto process;
							}

							for (instance_found = IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces - MAX_NUM_PPPOE_MPDN;
								instance_found < IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces; instance_found++)
							{
								if(strlen(IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name) == 0)
								{
									IPACMDBG_H("Found empty slot at iface_idx: %d\n", instance_found);
									break;
								}
							}

							if(instance_found == IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces)
							{
								IPACMERR("Max number of supported Eth vlan interfaces are reached.\n");
								free(data_addr);
								free(data_fid);
								break;
							}

							strlcpy(IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name,
								dev_name, sizeof(IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name));
							IPACM_Iface::ipacmcfg->iface_table[instance_found].virtual_iface = true;
process:

							if(strstr(dev_name, "pppoe"))
							{
								data_fid->is_ppp_iface = true;
							}
							else
							{
								data_fid->is_ppp_iface = false;
							}
							IPACMDBG_H("is_ppp_iface %d \n", data_fid->is_ppp_iface);
							if(!strstr(dev_name, "pppoe") && !strstr(dev_name, "br-ethwan"))
							{
								IPACMDBG_H("No br-wan mode Enabled, wan dev name %s \n", dev_name);
								strlcpy(IPACM_Iface::ipacmcfg->iface_table[instance_found].phy_dev_name,
									dev_name, ETH_PHY_IFACE_LEN);
							}
							else
							{
								/*
								 *  get phy interface name from
								 *  root@OpenWrt:/# brctl show
								 *  bridge name     bridge id               STP enabled     interfaces
								 *  br-ethwan101    7fff.00557bb57df7       no              eth1
								 *  br-lan          7fff.00557bb57df8       no              eth0
								 */
								IPACMDBG_H("br-wan_iface %s \n", dev_name);
								if(strstr(dev_name, "br-ethwan") ||
									strstr(dev_name, "br-wanpppoe"))
								{
									IPACMDBG_H("br-wan mode Enabled, wan dev name %s get phy name !! \n", dev_name);
									IPACM_Iface::ipacmcfg->get_phy_name_from_bridge_iface(dev_name, phy_dev);
									if(phy_dev != NULL)
									{
										IPACMDBG_H("wan dev name %s associated phy_name %s \n", dev_name, phy_dev);
										strlcpy(IPACM_Iface::ipacmcfg->iface_table[instance_found].phy_dev_name, phy_dev, ETH_PHY_IFACE_LEN);
									}
									else
									{
										IPACMERR("Failed to get associated phy_name for wan dev name %s\n", dev_name);
										free(data_fid);
										return IPACM_FAILURE;
									}
								}
							}

							IPACMDBG_H("wan dev name %s associated phy_name %s \n", dev_name,
									IPACM_Iface::ipacmcfg->iface_table[instance_found].phy_dev_name);
							IPACMDBG("Posting IPA_USB_LINK_UP_EVENT with for dev_name %s \n", dev_name);
							data_fid->if_index = msg_ptr->nl_route_info.attr_info.oif_index;
							evt_data.event = IPA_USB_LINK_UP_EVENT;
							evt_data.evt_data = data_fid;
							IPACM_EvtDispatcher::PostEvt(&evt_data);
						}

						if(msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN)
						{
							evt_data.event = IPA_ROUTE_ADD_EVENT;
							evt_data.evt_data = data_addr;
							IPACMDBG_H("Posting IPA_ROUTE_ADD_EVENT with dev_name %s if index:%d, ipv4 addr:0x%x, mask: 0x%x and gw: 0x%x\n",
								 dev_name, data_addr->if_index,
								 data_addr->ipv4_addr,
								 data_addr->ipv4_addr_mask,
								 data_addr->ipv4_addr_gw);
						}
						else if(msg_ptr->nl_route_info.metainfo.rtm_table != RT_TABLE_MAIN &&
							(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable ||
							IPACM_Iface::ipacmcfg->eth_vlan_wan_enable))
						{
							evt_data.event = IPA_WAN_GW_ADDR_ADD_EVENT;
							evt_data.evt_data = data_addr;
							IPACMDBG_H("Posting IPA_WAN_GW_ADDR_ADD_EVENT with dev_name %s if index:%d, ipv4 addr:0x%x, mask: 0x%x and gw: 0x%x\n",
								dev_name, data_addr->if_index,
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
			/* Check for delegate_prefix route for Prefix Delegation */
			if((msg_ptr->nl_route_info.metainfo.rtm_family == AF_INET6) &&
			   (msg_ptr->nl_route_info.metainfo.rtm_type == RTN_BLACKHOLE || msg_ptr->nl_route_info.metainfo.rtm_type == RTN_UNREACHABLE) &&
			   (msg_ptr->nl_route_info.attr_info.param_mask & IPA_RTA_PARAM_DST))
			{
				IPACMDBG_H("Got RTM_NEWROUTE for delegate_prefix route with dst_len %d\n", msg_ptr->nl_route_info.metainfo.rtm_dst_len);

				IPACM_EVENT_COPY_ADDR_v6(IPACM_Iface::ipacmcfg->ipv6_delegate_prefix, msg_ptr->nl_route_info.attr_info.dst_addr);

				IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[0] = ntohl(IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[0]);
				IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[1] = ntohl(IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[1]);
				IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[2] = ntohl(IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[2]);
				IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[3] = ntohl(IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[3]);
				IPACM_Iface::ipacmcfg->delegate_prefix_valid = true;
				IPACM_Iface::ipacmcfg->ipv6_delegate_prefix_len = msg_ptr->nl_route_info.metainfo.rtm_dst_len;

				IPACMDBG_H("Stored delegate_prefix prefix 0x%08x%08x%08x%08x\n",
					IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[0], IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[1],
					IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[2], IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[3]);
            }
			/* ipv6 routing table */
			if((AF_INET6 == msg_ptr->nl_route_info.metainfo.rtm_family) &&
				(msg_ptr->nl_route_info.metainfo.rtm_type == RTN_UNICAST) &&
				 ((msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_BOOT) ||
				  (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_RA) ||
				  (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_STATIC) ||
				  (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_KERNEL))&&
				 ((msg_ptr->nl_route_info.metainfo.rtm_scope == RT_SCOPE_UNIVERSE)||
				 (msg_ptr->nl_route_info.metainfo.rtm_scope == RT_SCOPE_LINK)) &&
				 (IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable ||
				 IPACM_Iface::ipacmcfg->eth_vlan_wan_enable ||
				 (msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN)))
			{
				IPACMDBG("\n GOT valid v6-RTM_NEWROUTE event\n");
				ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_route_info.attr_info.oif_index);
				if(ret_val != IPACM_SUCCESS)
				{
					IPACMERR("Error while getting interface name\n");
					return IPACM_FAILURE;
				}
				/* br-wan mode Enable with DHCP backhaul */
				if(strstr(dev_name, "br-ethwan"))
				{
					IPACM_Iface::ipacmcfg->eth_wan_br_wan_enable = true;
					IPACMDBG("\n GOT v6-RTM_NEWROUTE event, br-wan enabled %d \n", IPACM_Iface::ipacmcfg->eth_wan_br_wan_enable);
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
						return IPACM_FAILURE;
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
						free(data_addr);
						return IPACM_FAILURE;
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

					if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable ||
						IPACM_Iface::ipacmcfg->eth_vlan_wan_enable ||
						IPACM_Iface::ipacmcfg->eth_wan_br_wan_enable ||
						(msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN))
					{
						data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
						if(data_fid == NULL)
						{
							IPACMERR("unable to allocate memory for event_ecm data_fid\n");
							free(data_addr);
							return IPACM_FAILURE;
						}

						for (instance_found = IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces - MAX_NUM_PPPOE_MPDN;
							instance_found < IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces; instance_found++)
						{
							if(strcmp(
								IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name, dev_name) == 0)
							{
								break;
							}
						}

						if(instance_found < IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces)
						{
							IPACMDBG_H("Found devname:%s at iface_idx: %d\n", dev_name, instance_found);
							goto process_v6;
						}

						for (instance_found = IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces - MAX_NUM_PPPOE_MPDN;
							instance_found < IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces; instance_found++)
						{
							if(strlen(IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name) == 0)
							{
								IPACMDBG_H("Found empty slot at iface_idx: %d\n", instance_found);
								break;
							}
						}

						if(instance_found == IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces)
						{
							IPACMERR("Max number of supported Eth vlan interfaces are reached.\n");
							free(data_addr);
							free(data_fid);
							break;
						}
						strlcpy(IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name,
							dev_name, sizeof(IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name));
						IPACM_Iface::ipacmcfg->iface_table[instance_found].virtual_iface = true;
process_v6:
						if(strstr(dev_name, "pppoe"))
						{
							data_fid->is_ppp_iface = true;
						}
						else
						{
							data_fid->is_ppp_iface = false;
						}
						IPACMDBG_H("is_ppp_iface %d \n", data_fid->is_ppp_iface);
						if(!strstr(dev_name, "pppoe") && !strstr(dev_name, "br-ethwan"))
						{
							IPACMDBG_H("No br-wan mode Enabled, wan dev name %s \n", dev_name);
							strlcpy(IPACM_Iface::ipacmcfg->iface_table[instance_found].phy_dev_name,
								dev_name, ETH_PHY_IFACE_LEN);
						}
						else
						{
							/*
							 *  get phy interface name from
							 *  root@OpenWrt:/# brctl show
							 *  bridge name     bridge id               STP enabled     interfaces
							 *  br-ethwan101    7fff.00557bb57df7       no              eth1
							 *  br-lan          7fff.00557bb57df8       no              eth0
							 */
							IPACMDBG_H("br-wan_iface %s \n", dev_name);
							if(strstr(dev_name, "br-ethwan") ||
								strstr(dev_name, "br-wanpppoe"))
							{
								IPACMDBG_H("br-wan mode Enabled, wan dev name %s get phy name !! \n", dev_name);
								IPACM_Iface::ipacmcfg->get_phy_name_from_bridge_iface(dev_name, phy_dev);
								if(phy_dev != NULL)
								{
									IPACMDBG_H("wan dev name %s associated phy_name %s \n", dev_name, phy_dev);
									strlcpy(IPACM_Iface::ipacmcfg->iface_table[instance_found].phy_dev_name, phy_dev, ETH_PHY_IFACE_LEN);
								}
								else
								{
									IPACMERR("Failed to get associated phy_name for wan dev name %s\n", dev_name);
									free(data_fid);
									return IPACM_FAILURE;
								}
							}
						}

						IPACMDBG_H("wan dev name %s associated phy_name %s \n", dev_name,
							IPACM_Iface::ipacmcfg->iface_table[instance_found].phy_dev_name);
						IPACMDBG("Posting IPA_USB_LINK_UP_EVENT with for dev_name %s \n", dev_name);
						data_fid->if_index = msg_ptr->nl_route_info.attr_info.oif_index;
						evt_data.event = IPA_USB_LINK_UP_EVENT;
						evt_data.evt_data = data_fid;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
					}

					if(msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN)
					{
						evt_data.event = IPA_ROUTE_ADD_EVENT;
						IPACMDBG("Posting IPA_ROUTE_ADD_EVENT with dev_name %s if index:%d, ipv6 address\n",
							dev_name, data_addr->if_index);
					}
					else if(msg_ptr->nl_route_info.metainfo.rtm_table != RT_TABLE_MAIN &&
						(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable ||
						IPACM_Iface::ipacmcfg->eth_vlan_wan_enable))
					{
						evt_data.event = IPA_WAN_GW_ADDR_ADD_EVENT;
						IPACMDBG("Posting IPA_WAN_GW_ADDR_ADD_EVENT with dev_name %s if index:%d, ipv6 address\n",
							dev_name, data_addr->if_index);
					}

					data_addr->if_index = msg_ptr->nl_route_info.attr_info.oif_index;
					data_addr->iptype = IPA_IP_v6;

					evt_data.evt_data = data_addr;
					IPACM_EvtDispatcher::PostEvt(&evt_data);
					/* finish command queue */
				}
			}
			break;

		case RTM_DELROUTE:
			if(IPACM_SUCCESS != ipa_nl_decode_rtm_route(buffer, buflen, &(msg_ptr->nl_route_info)))
			{
				IPACMERR("Failed to decode rtm route message\n");
				return IPACM_FAILURE;
			}

			IPACMDBG("In case RTM_DELROUTE\n");
			IPACMDBG("rtm_type: %d\n", msg_ptr->nl_route_info.metainfo.rtm_type);
			IPACMDBG("protocol: %d\n", msg_ptr->nl_route_info.metainfo.rtm_protocol);
			IPACMDBG("rtm_scope: %d\n", msg_ptr->nl_route_info.metainfo.rtm_scope);
			IPACMDBG("rtm_table: %d\n", msg_ptr->nl_route_info.metainfo.rtm_table);
			IPACMDBG("rtm_family: %d\n", msg_ptr->nl_route_info.metainfo.rtm_family);
			IPACMDBG("param_mask: 0x%x\n", msg_ptr->nl_route_info.attr_info.param_mask);

			/* Check for delegate_prefix route delete for Prefix Delegation */
			if((msg_ptr->nl_route_info.metainfo.rtm_family == AF_INET6) &&
			   (msg_ptr->nl_route_info.metainfo.rtm_type == RTN_BLACKHOLE || msg_ptr->nl_route_info.metainfo.rtm_type == RTN_UNREACHABLE) &&
			   (msg_ptr->nl_route_info.attr_info.param_mask & IPA_RTA_PARAM_DST))
			{
				uint32_t ipv6_addr[4];
				IPACMDBG_H("Got RTM_DELROUTE for delegate_prefix route with dst_len %d\n", msg_ptr->nl_route_info.metainfo.rtm_dst_len);
				IPACM_EVENT_COPY_ADDR_v6(ipv6_addr, msg_ptr->nl_route_info.attr_info.dst_addr);

				ipv6_addr[0] = ntohl(ipv6_addr[0]);
				ipv6_addr[1] = ntohl(ipv6_addr[1]);
				ipv6_addr[2] = ntohl(ipv6_addr[2]);
				ipv6_addr[3] = ntohl(ipv6_addr[3]);

				if(IPACM_Iface::ipacmcfg->delegate_prefix_valid == true &&
					IPACM_Iface::ipacmcfg->ipv6_delegate_prefix_len == msg_ptr->nl_route_info.metainfo.rtm_dst_len &&
					IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[0] == ipv6_addr[0] &&
					IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[1] == ipv6_addr[1] &&
					IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[2] == ipv6_addr[2] &&
					IPACM_Iface::ipacmcfg->ipv6_delegate_prefix[3] == ipv6_addr[3])
				{
					IPACMDBG_H("Delete delegate_prefix prefix\n");
					IPACM_Iface::ipacmcfg->delegate_prefix_valid = false;
					memset(IPACM_Iface::ipacmcfg->ipv6_delegate_prefix, 0, sizeof(IPACM_Iface::ipacmcfg->ipv6_delegate_prefix));
					IPACM_Iface::ipacmcfg->ipv6_delegate_prefix_len = 0;
				}
			}

			/* take care of route delete of default route & uniroute */
			if((msg_ptr->nl_route_info.metainfo.rtm_type == RTN_UNICAST) &&
				 ((msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_BOOT) ||
				  (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_RA) ||
				  (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_STATIC))&&
				 (msg_ptr->nl_route_info.metainfo.rtm_scope == 0) &&
				 (msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN))
			{

				if(AF_INET == msg_ptr->nl_route_info.metainfo.rtm_family && msg_ptr->nl_route_info.attr_info.param_mask & IPA_RTA_PARAM_DST)
				{
					ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_route_info.attr_info.oif_index);
					if(ret_val != IPACM_SUCCESS)
					{
						IPACMERR("Error while getting interface name\n");
						return IPACM_FAILURE;
					}
					if(strcmp(dev_name,MAPE_IFACE_NAME) == 0){
						IPACMDBG_H(" Ignoring route on %s \n",dev_name);
						return IPACM_SUCCESS;
					}

					IPACM_NL_REPORT_ADDR( "route del -host ", msg_ptr->nl_route_info.attr_info.dst_addr);
					IPACM_NL_REPORT_ADDR( " gw ", msg_ptr->nl_route_info.attr_info.gateway_addr);
					IPACMDBG("dev %s\n", dev_name);

					/* insert to command queue */
					data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
					if(data_addr == NULL)
					{
						IPACMERR("unable to allocate memory for event data_addr\n");
						return IPACM_FAILURE;
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
						return IPACM_FAILURE;
					}

					if(strcmp(dev_name,MAPE_IFACE_NAME) == 0){
						IPACMDBG_H(" Ignoring route on %s \n",dev_name);
						return IPACM_SUCCESS;
					}

					/* insert to command queue */
					data_addr = (ipacm_event_data_addr *)malloc(sizeof(ipacm_event_data_addr));
					if(data_addr == NULL)
					{
						IPACMERR("unable to allocate memory for event data_addr\n");
						return IPACM_FAILURE;
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
					}
					else
					{
						IPACM_NL_REPORT_ADDR( "route del default gw", msg_ptr->nl_route_info.attr_info.gateway_addr);
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
				 ((msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_KERNEL) ||
				  (msg_ptr->nl_route_info.metainfo.rtm_protocol == RTPROT_STATIC))&&
				 (msg_ptr->nl_route_info.metainfo.rtm_table == RT_TABLE_MAIN))
			{
				IPACMDBG("\n GOT valid v6-RTM_DELROUTE event\n");
				ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_route_info.attr_info.oif_index);
				if(ret_val != IPACM_SUCCESS)
				{
					IPACMERR("Error while getting interface name\n");
					return IPACM_FAILURE;
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
						return IPACM_FAILURE;
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
			if(IPACM_SUCCESS != ipa_nl_decode_rtm_neigh(buffer, buflen, &(msg_ptr->nl_neigh_info)))
			{
				IPACMERR("Failed to decode rtm neighbor message\n");
				return IPACM_FAILURE;
			}

			ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_neigh_info.metainfo.ndm_ifindex);
			if(ret_val != IPACM_SUCCESS)
			{
				IPACMERR("Error while getting interface index\n");
				return IPACM_FAILURE;
			}
			else
			{
				IPACMDBG("\n GOT RTM_NEWNEIGH event (%s) ip %d\n",dev_name,msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family);
			}
			IPACMDBG("Neighbour event with interface index %d master interface index %d family %d\n", msg_ptr->nl_neigh_info.metainfo.ndm_ifindex, msg_ptr->nl_neigh_info.master_interface_index, msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family);

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
					vlan_data = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
					if(vlan_data == NULL)
					{
							IPACMERR("unable to allocate memory for vlan_data\n");
							return IPACM_FAILURE;
					}
					vlan_data->if_index = msg_ptr->nl_neigh_info.metainfo.ndm_ifindex;
					vlan_data->master_if_index = msg_ptr->nl_neigh_info.master_interface_index;
					vlan_event.evt_data = (void *)vlan_data;
					IPACM_EvtDispatcher::PostEvt(&vlan_event);
			}

			// This check is to  prevent handling of netlink messages with NULL MAC addr
			if(!(memcmp(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data,
						nullMac,sizeof(nullMac))))
			{
			  IPACMDBG_H("RTM_NEWNEIGH received with NULL MAC\n");
			  return IPACM_SUCCESS;
			}

			/* insert to command queue */
		    data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
		    if(data_all == NULL)
			{
		    	IPACMERR("unable to allocate memory for event data_all\n");
						return IPACM_FAILURE;
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
		    }
		    else if (msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family == AF_INET)
		    {
				IPACM_NL_REPORT_ADDR( " ", msg_ptr->nl_neigh_info.attr_info.local_addr);
				IPACM_EVENT_COPY_ADDR_v4( data_all->ipv4_addr, msg_ptr->nl_neigh_info.attr_info.local_addr);
		    	data_all->ipv4_addr = ntohl(data_all->ipv4_addr);
		    	data_all->iptype = IPA_IP_v4;
		    }
		    else
		    {
			IPACMDBG_H("ss_family = %d\n", msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family);
		        data_all->iptype = IPA_IP_v6;
		    }

		    IPACMDBG("NDA_LLADDR:MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
		     (unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[0],
		     (unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[1],
		     (unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[2],
		     (unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[3],
		     (unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[4],
		     (unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[5]);


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

#ifdef FEATURE_IPoGRE
			/*
			 * RGIP passthrough: when a LAN client whose IPv4 address equals the
			 * stored rgip_ip appears in the neighbor table, it means the RGIP
			 * passthrough client is reachable on the LAN side.  Enable RGIP
			 * passthrough so ConntrackListener installs no-op NAT entries
			 * (private_ip == public_ip == rgip_addr) for its conntrack flows.
			 */
			if ((data_all->iptype == IPA_IP_v4) &&
			    (IPACM_Iface::ipacmcfg->rgip_ip != 0) &&
			    (data_all->ipv4_addr == IPACM_Iface::ipacmcfg->rgip_ip))
			{
				ipacm_cmd_q_data rgip_pass_evt;
				ipacm_event_rgip_pass_info *rgip_pass_data =
					(ipacm_event_rgip_pass_info *)malloc(sizeof(ipacm_event_rgip_pass_info));
				if (rgip_pass_data)
				{
					rgip_pass_data->enable    = 1;
					rgip_pass_data->rgip_addr = data_all->ipv4_addr;
					rgip_pass_evt.event    = IPA_RGIP_PASS_UPDATE_EVENT;
					rgip_pass_evt.evt_data = rgip_pass_data;
				IPACMDBG_H("Posting IPA_RGIP_PASS_UPDATE_EVENT: enable, "
				           "rgip=0x%x (neigh %s)\n",
				           rgip_pass_data->rgip_addr, dev_name);
					IPACM_EvtDispatcher::PostEvt(&rgip_pass_evt);
					/* Also post IPA_HANDLE_RGIP_UP using the persistent
					 * rgip_ip_ippt so ConntrackListener re-installs the
					 * RGIP PDN entry whenever the RGIP passthrough client
					 * reappears in the neighbor table. */
					if (IPACM_Iface::ipacmcfg->rgip_ip_ippt != 0)
					{
						ipacm_cmd_q_data rgip_up_evt;
						uint32_t *rgip_v4_up = (uint32_t *)malloc(sizeof(uint32_t));
						if (rgip_v4_up)
						{
							*rgip_v4_up = IPACM_Iface::ipacmcfg->rgip_ip_ippt;
							memset(&rgip_up_evt, 0, sizeof(rgip_up_evt));
							rgip_up_evt.event = IPA_HANDLE_RGIP_UP;
							rgip_up_evt.evt_data = rgip_v4_up;
							IPACMDBG_H("Posting IPA_HANDLE_RGIP_UP with "
							           "rgip_ip_ippt=0x%x\n", *rgip_v4_up);
							IPACM_EvtDispatcher::PostEvt(&rgip_up_evt);
						}
					}
				}
			}
#endif /* FEATURE_IPoGRE */
		}
	    evt_data.evt_data = data_all;
				IPACM_EvtDispatcher::PostEvt(&evt_data);
				/* finish command queue */
		break;

		case RTM_DELNEIGH:
			if(IPACM_SUCCESS != ipa_nl_decode_rtm_neigh(buffer, buflen, &(msg_ptr->nl_neigh_info)))
			{
				IPACMERR("Failed to decode rtm neighbor message\n");
				return IPACM_FAILURE;
			}

			ret_val = ipa_get_if_name(dev_name, msg_ptr->nl_neigh_info.metainfo.ndm_ifindex);
			if(ret_val != IPACM_SUCCESS)
			{
				IPACMERR("Error while getting interface index\n");
				return IPACM_FAILURE;
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
			  return IPACM_SUCCESS;
			}

			/* insert to command queue */
			data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
			if(data_all == NULL)
			{
				IPACMERR("unable to allocate memory for event data_all\n");
				return IPACM_FAILURE;
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

		    IPACMDBG("NDA_LLADDR:MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
		     (unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[0],
		     (unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[1],
		     (unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[2],
		     (unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[3],
		     (unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[4],
		     (unsigned char)(msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr).sa_data[5]);

				memcpy(data_all->mac_addr,
							 msg_ptr->nl_neigh_info.attr_info.lladdr_hwaddr.sa_data,
							 sizeof(data_all->mac_addr));
		    evt_data.event = IPA_DEL_NEIGH_EVENT;
			data_all->if_index = msg_ptr->nl_neigh_info.metainfo.ndm_ifindex;

#ifdef FEATURE_IPoGRE
			/*
			 * RGIP passthrough: when the LAN client whose IPv4 address equals
			 * rgip_ip disappears from the neighbor table, disable RGIP
			 * passthrough so ConntrackListener stops installing no-op NAT
			 * entries for its flows.
			 */
			if ((data_all->iptype == IPA_IP_v4) &&
			    (IPACM_Iface::ipacmcfg->rgip_ip != 0) &&
			    (data_all->ipv4_addr == IPACM_Iface::ipacmcfg->rgip_ip))
			{
				ipacm_cmd_q_data rgip_pass_evt;
				ipacm_event_rgip_pass_info *rgip_pass_data =
					(ipacm_event_rgip_pass_info *)malloc(sizeof(ipacm_event_rgip_pass_info));
				if (rgip_pass_data)
				{
					rgip_pass_data->enable    = 0;
					rgip_pass_data->rgip_addr = 0;
					rgip_pass_evt.event    = IPA_RGIP_PASS_UPDATE_EVENT;
					rgip_pass_evt.evt_data = rgip_pass_data;
					IPACMDBG_H("Posting IPA_RGIP_PASS_UPDATE_EVENT: disable "
					           "(neigh %s departed)\n", dev_name);
					IPACM_EvtDispatcher::PostEvt(&rgip_pass_evt);
				}
			}
#endif /* FEATURE_IPoGRE */

		    IPACMDBG_H("posting IPA_DEL_NEIGH_EVENT (%s):index:%d ip-family: %d\n",
                                 dev_name,
							data_all->if_index,
							msg_ptr->nl_neigh_info.attr_info.local_addr.ss_family);
				evt_data.evt_data = data_all;
				IPACM_EvtDispatcher::PostEvt(&evt_data);
				/* finish command queue */
			break;

		default:
			IPACMDBG(" ignore NL event %d!!!\n ", nlh->nlmsg_type);
			break;

		}
		nlh = NLMSG_NEXT(nlh, buflen);
	}

	return IPACM_SUCCESS;
}


/*  Virtual function registered to receive incoming messages over the NETLINK routing socket*/
int ipa_nl_recv_msg(int fd)
{
	struct msghdr *msghdr = NULL;
	struct iovec *iov = NULL;
	unsigned int msglen = 0;
	ipa_nl_msg_t *nlmsg = NULL;

	nlmsg = (ipa_nl_msg_t *)malloc(sizeof(ipa_nl_msg_t));
	if(NULL == nlmsg)
	{
		IPACMERR("Failed alloc of nlmsg \n");
		goto error;
	}
	else
	{
		if(IPACM_SUCCESS != ipa_nl_recv(fd, &msghdr, &msglen))
		{
			IPACMERR("Failed to receive nl message \n");
			goto error;
		}

		if(msghdr== NULL)
		{
			IPACMERR(" failed to get msghdr\n");
			goto error;
		}

		iov = msghdr->msg_iov;

		memset(nlmsg, 0, sizeof(ipa_nl_msg_t));
		if(IPACM_SUCCESS != ipa_nl_decode_nlmsg((char *)iov->iov_base, msglen, nlmsg))
		{
			IPACMERR("Failed to decode nl message \n");
			goto error;
		}
		/* Release NetLink message buffer */
		if(msghdr)
		{
			ipa_nl_release_msg(msghdr);
		}
		if(nlmsg)
		{
			free(nlmsg);
		}
	}

	return IPACM_SUCCESS;

error:
	if(msghdr)
	{
		ipa_nl_release_msg(msghdr);
	}
	if(nlmsg)
	{
		free(nlmsg);
	}

	return IPACM_FAILURE;
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
		IPACMERR("get interface name socket create failed: %d \n", errno);
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
	 ipa_sock_thrd_fd_read_f read_f
	 )
{
	ipa_nl_sk_info_t sk_info;
	int ret_val;

	memset(&sk_info, 0, sizeof(ipa_nl_sk_info_t));
	IPACMDBG_H("Entering IPA NL listener init\n");

	if(ipa_nl_open_socket(&sk_info, nl_type, nl_groups) == IPACM_SUCCESS)
	{
		IPACMDBG_H("IPA Open netlink socket succeeds\n");
	}
	else
	{
		IPACMERR("Netlink socket open failed\n");
		return IPACM_FAILURE;
	}

	/* Add NETLINK socket to the list of sockets that the listener
					 thread should listen on. */

	if(ipa_nl_addfd_map(sk_fdset, sk_info.sk_fd, read_f) != IPACM_SUCCESS)
	{
		IPACMERR("cannot add nl routing sock for reading\n");
		close(sk_info.sk_fd);
		return IPACM_FAILURE;
	}

	/* Start the socket listener thread */
	ret_val = ipa_nl_sock_listener_start(sk_fdset);

	if(ret_val != IPACM_SUCCESS)
	{
		IPACMERR("Failed to start NL listener\n");
	}

	return IPACM_SUCCESS;
}

/* To get dump of routes from kernel in case of RTM_GETROUTE */
int ipa_nl_route_receive(int fd, struct msghdr *msg, int flags)
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

int ipa_nl_route_recvmsg(int fd, struct msghdr *msg, char **result)
{
	struct iovec *iov = msg->msg_iov;
	char *buf = NULL;
	int len = 0;

	iov->iov_base = NULL;
	iov->iov_len = 0;

	len = ipa_nl_route_receive(fd, msg, MSG_PEEK | MSG_TRUNC);

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

	len = ipa_nl_route_receive(fd, msg, 0);

	if (len < 0)
	{
		free(buf);
		return len;
	}

	*result = buf;

	return len;
}

int ipa_nl_send_getroute(ipa_ip_type ip_type)
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
	int instance_found = 0;
	ipacm_event_data_all *data_all;

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

	msglen = ipa_nl_route_recvmsg(nl_sock, &msg, &buf);

	if(msglen <= 0)
	{
		PERROR("NL route recv error\n");
		goto error;
	}

	h = (struct nlmsghdr *)buf;

	IPACMDBG("Route msg_len : %d\n", msglen)

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
			  (nl_route_info_get_route.metainfo.rtm_protocol == RTPROT_RA) ||
			  (nl_route_info_get_route.metainfo.rtm_protocol == RTPROT_STATIC))&&
			 ((nl_route_info_get_route.metainfo.rtm_scope == RT_SCOPE_UNIVERSE)||
			 (nl_route_info_get_route.metainfo.rtm_scope == RT_SCOPE_LINK))&&
			 (IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable ||
			 IPACM_Iface::ipacmcfg->eth_vlan_wan_enable ||
			 (nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_MAIN)))
		{

			if(nl_route_info_get_route.attr_info.param_mask & IPA_RTA_PARAM_DST)
			{
				ret_val = ipa_get_if_name(dev_name, nl_route_info_get_route.attr_info.oif_index);
				if(ret_val != IPACM_SUCCESS)
				{
					IPACMERR("Error while getting interface name\n");
					goto error;
				}
		
				IPACM_NL_REPORT_ADDR( "route add -host", nl_route_info_get_route.attr_info.dst_addr );
				IPACM_NL_REPORT_ADDR( "gw", nl_route_info_get_route.attr_info.gateway_addr );
				IPACMDBG("dev %s\n",dev_name );

				if(strcmp(dev_name,MAPE_IFACE_NAME) == 0){
					IPACMDBG_H(" Ignoring route on %s  \n",dev_name);
					free(buf);
					close(nl_sock);
					return IPACM_SUCCESS;
				}

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
					IPACM_NL_REPORT_ADDR( "dstIP:\n", nl_route_info_get_route.attr_info.dst_addr );

					if(strcmp(dev_name,MAPE_IFACE_NAME) == 0){
						IPACMDBG_H(" Ignoring route on %s \n",dev_name);
						free(buf);
						close(nl_sock);
						return IPACM_SUCCESS;
					}

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

					if(nl_route_info_get_route.attr_info.param_mask & IPA_RTA_PARAM_GATEWAY &&
						(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable  ||
						IPACM_Iface::ipacmcfg->eth_vlan_wan_enable ||
						(nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_MAIN)))
					{
						data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
						if(data_fid == NULL)
						{
							IPACMERR("unable to allocate memory for event_ecm data_fid\n");
							free(data_addr);
							return IPACM_FAILURE;
						}

						for (instance_found = IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces - MAX_NUM_PPPOE_MPDN;
							instance_found < IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces; instance_found++)
						{
							if(strcmp(
								IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name, dev_name) == 0)
							{
								break;
							}
						}

						if(instance_found < IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces)
						{
							IPACMDBG_H("Found devname:%s at iface_idx: %d\n", dev_name, instance_found);
							goto proces_getroute;
						}

						for (instance_found = IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces - MAX_NUM_PPPOE_MPDN;
							instance_found < IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces; instance_found++)
						{
							if(strlen(IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name) == 0)
							{
								IPACMDBG_H("Found empty slot at iface_idx: %d\n", instance_found);
								break;
							}
						}

						if(instance_found == IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces)
						{
							IPACMERR("Max number of supported Eth vlan interfaces are reached.\n");
							free(data_addr);
							free(data_fid);
							break;
						}

						strlcpy(IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name,
							dev_name, sizeof(IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name));
						IPACM_Iface::ipacmcfg->iface_table[instance_found].virtual_iface = true;

proces_getroute:
						if(strstr(dev_name, "pppoe"))
						{
							data_fid->is_ppp_iface = true;
						}
						else
						{
							data_fid->is_ppp_iface = false;
						}
						if(!strstr(dev_name, "pppoe"))
						{
							strlcpy(IPACM_Iface::ipacmcfg->iface_table[instance_found].phy_dev_name,
								dev_name, ETH_PHY_IFACE_LEN);
						}

						data_fid->if_index = nl_route_info_get_route.attr_info.oif_index;
						evt_data.event = IPA_USB_LINK_UP_EVENT;
						evt_data.evt_data = data_fid;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
					}

					if(nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_MAIN)
					{
						memset(&evt_data, 0, sizeof(ipacm_cmd_q_data));
						evt_data.event = IPA_ROUTE_ADD_EVENT;
						evt_data.evt_data = data_addr;
						IPACMDBG_H("Posting IPA_ROUTE_ADD_EVENT with if index:%d, ipv4 addr:0x%x, mask: 0x%x and gw: 0x%x\n",
									 data_addr->if_index,
									 data_addr->ipv4_addr,
									 data_addr->ipv4_addr_mask,
									 data_addr->ipv4_addr_gw);
					}
					else if(nl_route_info_get_route.metainfo.rtm_table != RT_TABLE_MAIN &&
						(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable  ||
						IPACM_Iface::ipacmcfg->eth_vlan_wan_enable))
					{
						memset(&evt_data, 0, sizeof(ipacm_cmd_q_data));
						evt_data.event = IPA_WAN_GW_ADDR_ADD_EVENT;
						evt_data.evt_data = data_addr;
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
			  (nl_route_info_get_route.metainfo.rtm_protocol == RTPROT_STATIC) ||
			  (nl_route_info_get_route.metainfo.rtm_protocol == RTPROT_KERNEL))&&
			 ((nl_route_info_get_route.metainfo.rtm_scope == RT_SCOPE_UNIVERSE)||
			 (nl_route_info_get_route.metainfo.rtm_scope == RT_SCOPE_LINK))&&
			 (IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable ||
			 IPACM_Iface::ipacmcfg->eth_vlan_wan_enable  ||
			 (nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_MAIN)))
		{
			IPACMDBG("\n GOT valid v6-RTM_NEWROUTE event, table = %d \n", nl_route_info_get_route.metainfo.rtm_table);
			ret_val = ipa_get_if_name(dev_name, nl_route_info_get_route.attr_info.oif_index);
			if(ret_val != IPACM_SUCCESS)
			{
				IPACMERR("Error while getting interface name\n");
				goto error;
			}
			if(nl_route_info_get_route.attr_info.param_mask & IPA_RTA_PARAM_DST)
			{
				IPACM_NL_REPORT_ADDR( "Route ADD DST:\n", nl_route_info_get_route.attr_info.dst_addr );
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

				memset(&evt_data, 0, sizeof(ipacm_cmd_q_data));
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
				IPACM_NL_REPORT_ADDR( "Route ADD ::/0  Next Hop:\n", nl_route_info_get_route.attr_info.gateway_addr );
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

				IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr, nl_route_info_get_route.attr_info.dst_addr);

				data_addr->ipv6_addr[0]=ntohl(data_addr->ipv6_addr[0]);
				data_addr->ipv6_addr[1]=ntohl(data_addr->ipv6_addr[1]);
				data_addr->ipv6_addr[2]=ntohl(data_addr->ipv6_addr[2]);
				data_addr->ipv6_addr[3]=ntohl(data_addr->ipv6_addr[3]);

				IPACMDBG("ipv6_addr: %08x:%08x:%08x:%08x \n",
					data_addr->ipv6_addr[0],
					data_addr->ipv6_addr[1],
					data_addr->ipv6_addr[2],
					data_addr->ipv6_addr[3]);
				IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr_mask, nl_route_info_get_route.attr_info.dst_addr);

				data_addr->ipv6_addr_mask[0]=ntohl(data_addr->ipv6_addr_mask[0]);
				data_addr->ipv6_addr_mask[1]=ntohl(data_addr->ipv6_addr_mask[1]);
				data_addr->ipv6_addr_mask[2]=ntohl(data_addr->ipv6_addr_mask[2]);
				data_addr->ipv6_addr_mask[3]=ntohl(data_addr->ipv6_addr_mask[3]);
				IPACMDBG("ipv6_addr_mask: %08x:%08x:%08x:%08x \n",
					data_addr->ipv6_addr_mask[0],
					data_addr->ipv6_addr_mask[1],
					data_addr->ipv6_addr_mask[2],
					data_addr->ipv6_addr_mask[3]);
				IPACM_EVENT_COPY_ADDR_v6( data_addr->ipv6_addr_gw, nl_route_info_get_route.attr_info.gateway_addr);
				data_addr->ipv6_addr_gw[0] = ntohl(data_addr->ipv6_addr_gw[0]);
				data_addr->ipv6_addr_gw[1] = ntohl(data_addr->ipv6_addr_gw[1]);
				data_addr->ipv6_addr_gw[2] = ntohl(data_addr->ipv6_addr_gw[2]);
				data_addr->ipv6_addr_gw[3] = ntohl(data_addr->ipv6_addr_gw[3]);
				IPACMDBG("ipv6_addr_gw: %08x:%08x:%08x:%08x \n",
					data_addr->ipv6_addr_gw[0],
					data_addr->ipv6_addr_gw[1],
					data_addr->ipv6_addr_gw[2],
					data_addr->ipv6_addr_gw[3]);
				IPACM_NL_REPORT_ADDR( " ", nl_route_info_get_route.attr_info.gateway_addr);

				if(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable ||
					IPACM_Iface::ipacmcfg->eth_vlan_wan_enable ||
					(nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_MAIN))
				{
					data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
					if(data_fid == NULL)
					{
						IPACMERR("unable to allocate memory for event_ecm data_fid\n");
						free(data_addr);
						return IPACM_FAILURE;
					}

					for (instance_found = IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces - MAX_NUM_PPPOE_MPDN;
						instance_found < IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces; instance_found++)
					{
						if(strcmp(
							IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name, dev_name) == 0)
						{
							break;
						}
					}

					if(instance_found < IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces)
					{
						IPACMDBG_H("Found devname:%s at iface_idx: %d\n", dev_name, instance_found);
						goto process_getroute_v6;
					}

					for (instance_found = IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces - MAX_NUM_PPPOE_MPDN;
						instance_found < IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces; instance_found++)
					{
						if(strlen(IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name) == 0)
						{
							IPACMDBG_H("Found empty slot at iface_idx: %d\n", instance_found);
							break;
						}
					}

					if(instance_found == IPACM_Iface::ipacmcfg->ipa_num_ipa_interfaces)
					{
						IPACMERR("Max number of supported Eth vlan interfaces are reached.\n");
						free(data_addr);
						free(data_fid);
						break;
					}

process_getroute_v6:
					if(strstr(dev_name, "pppoe"))
					{
						data_fid->is_ppp_iface = true;
					}
					else
					{
						data_fid->is_ppp_iface = false;
					}
					if(!strstr(dev_name, "pppoe"))
					{
						strlcpy(IPACM_Iface::ipacmcfg->iface_table[instance_found].phy_dev_name,
							dev_name, ETH_PHY_IFACE_LEN);
					}
					IPACMDBG("Posting IPA_USB_LINK_UP_EVENT for %s\n", dev_name);
					strlcpy(IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name,
						dev_name, sizeof(IPACM_Iface::ipacmcfg->iface_table[instance_found].iface_name));
					IPACM_Iface::ipacmcfg->iface_table[instance_found].virtual_iface = true;
					data_fid->if_index = nl_route_info_get_route.attr_info.oif_index;
					memset(&evt_data, 0, sizeof(ipacm_cmd_q_data));
					evt_data.event = IPA_USB_LINK_UP_EVENT;
					evt_data.evt_data = data_fid;
					IPACM_EvtDispatcher::PostEvt(&evt_data);
				}

				if(nl_route_info_get_route.metainfo.rtm_table == RT_TABLE_MAIN)
				{
					evt_data.event = IPA_ROUTE_ADD_EVENT;
					data_addr->if_index = nl_route_info_get_route.attr_info.oif_index;
					IPACMDBG("Posting IPA_ROUTE_ADD_EVENT with if index:%d, ipv6 address\n",
								data_addr->if_index);
				}
				else if(nl_route_info_get_route.metainfo.rtm_table != RT_TABLE_MAIN &&
						(IPACM_Iface::ipacmcfg->eth_wan_pppoe_enable ||
						IPACM_Iface::ipacmcfg->eth_vlan_wan_enable))
				{
					evt_data.event = IPA_WAN_GW_ADDR_ADD_EVENT;
					data_addr->if_index = nl_route_info_get_route.attr_info.oif_index;
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

int ipa_nl_query_newneigh(int af_family)
{
	IPACMDBG("ipa_nl_send_getneigh\n");
	int ret_val = IPACM_FAILURE, msglen = 0, nl_sock = 0;
	ssize_t msgsent_len = 0;
	char *buf = NULL;
	nl_request_t nl_request;
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct nlmsghdr *h = NULL;
	struct iovec iov;
	nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl_sock < 0)
	{
		IPACMERR("Failed to open netlink socket");
		return IPACM_FAILURE;
	}

	ipa_nl_msg_t  *msg_ptr = (ipa_nl_msg_t*)calloc(1, sizeof(ipa_nl_msg_t));
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

	msgsent_len = send(nl_sock, &nl_request, sizeof(nl_request), 0);

	msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	msglen = ipa_nl_route_recvmsg(nl_sock, &msg, &buf);

	if(msglen <= 0)
	{
		IPACMERR("NL route recv error\n");
	}

	h = (struct nlmsghdr *)buf;
	while (NLMSG_OK(h, msglen))
	{
		if (h->nlmsg_flags & NLM_F_DUMP_INTR)
		{
			IPACMERR("Dump was interrupted\n");
			break;
		}
		if (h->nlmsg_flags & NLMSG_OVERRUN || !h->nlmsg_flags)
		{
			IPACMERR("Dump was overun\n");
			break;
		}
		if(h->nlmsg_type == NLMSG_DONE)
			break;
		if (nladdr.nl_pid != 0)
		{
			h = NLMSG_NEXT(h, msglen);
			continue;
		}

		if (h->nlmsg_type == NLMSG_ERROR)
		{
			IPACMERR("Netlink message error");
			break;
		}

		if (ipa_nl_decode_nlmsg((const char*)h, msglen, msg_ptr)) {
			IPACMERR("Failed to decode rtm link message\n");
			h = NLMSG_NEXT(h, msglen);
			continue;
		}
		h = NLMSG_NEXT(h, msglen);
	}
	IPACMDBG("End\n");
	close(nl_sock);
	free(buf);
	buf = NULL;
	free(msg_ptr);
	msg_ptr = NULL;
	return 1;
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
ipa_nl_sk_info_t   *sk_info,
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
	ipa_nl_sk_info_t   sk_info;
	struct sockaddr_nl req_nl_addr, recv_nl_addr;
	struct msghdr req_nl_msg, recv_nl_msg;
	ipa_nl_req_type    nl_req;
	char dev_name[IF_NAME_LEN];

	struct iovec recv_iovec, req_iovec;
	char buff[8124] = {0};
	unsigned int ret_val = 0;
	struct nlmsghdr *nl_hdr = NULL;
	struct ifinfomsg *iface_info = NULL;
	int ret;

	memset(&req_nl_msg, 0, sizeof(req_nl_msg));
	memset(&req_nl_addr, 0, sizeof(req_nl_addr));
	memset(&nl_req, 0, sizeof(nl_req));
	memset(&sk_info, 0, sizeof(sk_info));

	if (ipa_open_nl_getlink_socket(&sk_info, NETLINK_ROUTE, RTMGRP_LINK) != 0)
	{
		IPACMDBG("Failed to open the netlink socket", 0, 0, 0);
		return -1;
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
	ipa_nl_msg_t *msg_ptr = (ipa_nl_msg_t *)calloc(1, sizeof(ipa_nl_msg_t));

	if (sendmsg(sk_info.sk_fd, (struct msghdr *) &req_nl_msg, 0) <= 0)
	{
		IPACMDBG("QCMAP:Netlink Query to Kernel failed errno:%d",errno,0,0);
		return -1;
	}
	while(1)
	{
		if ((ret_val = recvmsg(sk_info.sk_fd, &recv_nl_msg, 0)) < 0)
		{
			IPACMDBG("Error in reading from netlink socket errno:%d", errno, 0, 0);
			break;
		}
		IPACMDBG("No of bytes recevied:%d", ret_val);
		if ((nl_hdr = (struct nlmsghdr*)buff) == NULL)
		{
			IPACMDBG("nl_hdr is NULL", 0, 0, 0);
			break;
		}
		if (nl_hdr->nlmsg_type == NLMSG_DONE)
		{
			IPACMDBG("Received NLMSG_DONE\n");
			break;
		}

		while(NLMSG_OK(nl_hdr, ret_val))
		{
			if (nl_hdr->nlmsg_type == NLMSG_DONE)
			{
				IPACMDBG("Received NLMSG_DONE\n");
				break;
			}
			if (nl_hdr->nlmsg_type == NLMSG_ERROR)
			{
				IPACMDBG("Error in received netlink msg :%u", nl_hdr->nlmsg_type, 0, 0);
				break;
			}
			if ((iface_info = (struct ifinfomsg*)NLMSG_DATA (nl_hdr))==NULL)
			{
				IPACMDBG("Interface info from netlink message is NULL\n");
				nl_hdr = NLMSG_NEXT(nl_hdr, ret_val);
				continue;
			}
			ret =  ipa_get_if_name(dev_name,
					iface_info->ifi_index);
			if(ret != 0)
			{
				IPACMDBG("Error while getting interface index\n");
				ret = 0;
				nl_hdr = NLMSG_NEXT(nl_hdr, ret_val);
				continue;
			}
			if(!strcmp(dev_name,"lo") || !strcmp(dev_name,"ip_vti0") || !strcmp(dev_name,"ip6_vti0")
					|| !strcmp(dev_name,"sit0") || !strcmp(dev_name,"can0"))
			{
				nl_hdr = NLMSG_NEXT(nl_hdr, ret_val);
				continue;
			}

			if (nl_hdr->nlmsg_type == RTM_NEWLINK)
			{
				if(iface_info->ifi_flags & IFF_UP)
				{
					if (ipa_nl_decode_nlmsg((const char*)nl_hdr, ret_val, msg_ptr)) {
						IPACMERR("Failed to decode rtm link message\n");
						nl_hdr = NLMSG_NEXT(nl_hdr, ret_val);
						continue;
					}
				}
			}
			nl_hdr = NLMSG_NEXT(nl_hdr, ret_val);
		}
	}
	if (sk_info.sk_fd > 0)
		close(sk_info.sk_fd);
	return 0;
}
