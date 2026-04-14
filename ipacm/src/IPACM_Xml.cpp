/*
 * Copyright (c) 2013, 2018-2020 The Linux Foundation. All rights reserved.
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
 * Copyright (c) 2023-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
/*!
  @file
   IPACM_Xml.cpp

  @brief
   This file implements the XML specific parsing functionality.

  @Author
   Skylar Chang/Shihuan Liu
*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "IPACM_Xml.h"
#include "IPACM_Log.h"
#include "IPACM_Netlink.h"

static char* IPACM_read_content_element
(
	 xmlNode* element
);

static int32_t IPACM_util_icmp_string
(
	 const char* xml_str,
	 const char* str
);

static int ipacm_cfg_xml_parse_tree
(
	 xmlNode* xml_node,
	 IPACM_conf_t *config
);

static int ipacm_cfg_validate_parsed_xml(IPACM_conf_t *config);

static int IPACM_firewall_xml_parse_tree(const char *xml_file, xmlNode* xml_node, IPACM_firewall_t &firewall_config);

static int IPACM_cfg_ext_xml_parse_tree(xmlNode* xml_node, IPACM_dscp_pcp_conf_t *config);

/*Reads content (stored as child) of the element */
static char* IPACM_read_content_element
(
	 xmlNode* element
)
{
	xmlNode* child_ptr;

	for (child_ptr  = element->children;
			 child_ptr != NULL;
			 child_ptr  = child_ptr->next)
	{
		if (child_ptr->type == XML_TEXT_NODE)
		{
			return (char*)child_ptr->content;
		}
	}
	return NULL;
}

/* insensitive comparison of a libxml's string (xml_str) and a regular string (str)*/
static int32_t IPACM_util_icmp_string
(
	 const char* xml_str,
	 const char* str
)
{
	int32_t ret = -1;

	if (NULL != xml_str && NULL != str)
	{
		uint32_t len1 = strlen(str);
		uint32_t len2 = strlen(xml_str);
		/* If the lengths match, do the string comparison */
		if (len1 == len2)
		{
			ret = strncasecmp(xml_str, str, len1);
		}
	}

	return ret;
}

/* This function read IPACM XML and populate the IPA CM Cfg */
int ipacm_read_cfg_xml(char *xml_file, IPACM_conf_t *config)
{
	xmlDocPtr doc = NULL;
	xmlNode* root = NULL;
	int ret_val = IPACM_SUCCESS;

	/* Invoke the XML parser and obtain the parse tree */
	doc = xmlReadFile(xml_file, "UTF-8", XML_PARSE_NOBLANKS);
	if (doc == NULL) {
		IPACMDBG_H("IPACM_xml_parse: libxml returned parse error!\n");
		return IPACM_FAILURE;
	}

	/*Get the root of the tree*/
	root = xmlDocGetRootElement(doc);

	memset(config, 0, sizeof(IPACM_conf_t));

	/* parse the xml tree returned by libxml */
	ret_val = ipacm_cfg_xml_parse_tree(root, config);

	if (ret_val != IPACM_SUCCESS)
	{
		IPACMDBG_H("IPACM_xml_parse: ipacm_cfg_xml_parse_tree returned parse error!\n");
	}

	/* Validate the config parsed from the xml tree */
	ret_val = ipacm_cfg_validate_parsed_xml(config);

	if (ret_val != IPACM_SUCCESS)
	{
		IPACMDBG_H("IPACM_xml_parse: ipacm_cfg_validate_parsed_xml returned parse error!\n");
	}

	/* Free up the libxml's parse tree */
	xmlFreeDoc(doc);

	return ret_val;
}

/* This function traverses the xml tree*/
static int ipacm_cfg_xml_parse_tree
(
	 xmlNode* xml_node,
	 IPACM_conf_t *config
)
{
	int32_t ret_val = IPACM_SUCCESS;
	int str_size;
	char* content;
	char content_buf[MAX_XML_STR_LEN];
	struct ether_addr *eth_addr = NULL;

	if (NULL == xml_node)
		return ret_val;
	while ( xml_node != NULL &&
				 ret_val == IPACM_SUCCESS)
	{
		switch (xml_node->type)
		{
		case XML_ELEMENT_NODE:
			{
				if (IPACM_util_icmp_string((char*)xml_node->name, system_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, ODU_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, IPACMCFG_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, IPACMIFACECFG_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, IFACE_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, IPACMALG_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, ALG_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, IPACMNat_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, IPACM_IPV6CT_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, IPACM_IPV6NAT_TAG) == 0 ||
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
						IPACM_util_icmp_string((char*)xml_node->name, LAN_Stats_TAG) == 0 ||
#endif
						IPACM_util_icmp_string((char*)xml_node->name, IPACM_L2TP_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, IPACM_MPDN_TAG) == 0 ||

						IPACM_util_icmp_string((char*)xml_node->name, IPACM_EASY_MESH) == 0 ||

						IPACM_util_icmp_string((char*)xml_node->name, IPACM_SOCKSv5_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, GRE_TAG) == 0 ||
#ifdef FEATURE_DUAL_BACKHAUL
						IPACM_util_icmp_string((char*)xml_node->name, Dual_backhaul_TAG) == 0 ||
#endif
#ifdef FEATURE_EoGRE
						IPACM_util_icmp_string((char*)xml_node->name, EoGRE_v6options_TAG) == 0 ||
#endif
						IPACM_util_icmp_string((char*)xml_node->name, PUBLIC_IP_SUPPORT_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, IPACM_WLAN_VLAN_MPDN) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, Static_Policy_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, IPACM_QOS_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, IPACMLOG_TAG) == 0 ||
						IPACM_util_icmp_string((char*)xml_node->name, DEVICEMODE) == 0)
				{
					if (0 == IPACM_util_icmp_string((char*)xml_node->name, IFACE_TAG))
					{
						/* increase iface entry number */
						config->iface_config.num_iface_entries++;
					}

					if (0 == IPACM_util_icmp_string((char*)xml_node->name, ALG_TAG))
					{
						/* increase iface entry number */
						config->alg_config.num_alg_entries++;
					}
					/* go to child */
					ret_val = ipacm_cfg_xml_parse_tree(xml_node->children, config);
				}
#ifdef FEATURE_DUAL_BACKHAUL
				else if(IPACM_util_icmp_string((char*)xml_node->name, Dual_backhaul_enable_TAG) == 0){
					IPACMDBG_H("Inside Dual backhaul TAG \n");
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (atoi(content_buf))
						{
							config->dual_backhaul_conf.dualbackhaul_enable = true;
							IPACMDBG_H("Dual Backhaul enable %d buf(%d)\n", config->dual_backhaul_conf.dualbackhaul_enable, atoi(content_buf));
						}
						else
						{
							config->dual_backhaul_conf.dualbackhaul_enable = false;
							IPACMDBG_H("Dual Backhaul enable %d buf(%d)\n", config->dual_backhaul_conf.dualbackhaul_enable, atoi(content_buf));
						}
					}
				}
#endif
#ifdef FEATURE_EoGRE
				else if(IPACM_util_icmp_string((char*)xml_node->name, EoGRE_v6options_enable_TAG) == 0){
					IPACMDBG_H("Inside EoGRE v6options TAG \n");
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (atoi(content_buf))
						{
							config->v6options_enable = true;
							IPACMDBG_H("v6options enable %d buf(%d)\n", config->v6options_enable, atoi(content_buf));
						}
						else
						{
							config->v6options_enable = false;
							IPACMDBG_H("v6options enable %d buf(%d)\n", config->v6options_enable, atoi(content_buf));
						}
					}
				}
#endif
				else if (IPACM_util_icmp_string((char*)xml_node->name, GREEnabled_TAG) == 0)
				{
					IPACMDBG_H("inside GRE TAG \n");

					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (atoi(content_buf))
						{
							config->gre_conf.gre_enable = true;
							IPACMDBG_H("GRE enable %d buf(%d)\n", config->gre_conf.gre_enable, atoi(content_buf));
						}
						else
						{
							config->gre_conf.gre_enable = false;
							IPACMDBG_H("GRE enable %d buf(%d)\n", config->gre_conf.gre_enable, atoi(content_buf));
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, GREAutolearn_TAG) == 0)
				{
					IPACMDBG_H("inside GREAutolearn TAG \n");

					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (atoi(content_buf))
						{
							config->gre_conf.gre_autolearn = true;
							IPACMDBG_H("GRE Autolearn %d buf(%d)\n", config->gre_conf.gre_autolearn, atoi(content_buf));
						}
						else
						{
							config->gre_conf.gre_autolearn = false;
							IPACMDBG_H("GRE Autolearn %d buf(%d)\n", config->gre_conf.gre_autolearn, atoi(content_buf));
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, GRE_Server_TAG) == 0)
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->gre_conf.gre_server_ipv4
							= ntohl(inet_addr(content_buf));
						IPACMDBG_H("subnet_addr: %s \n", content_buf);
					}
				}
#ifdef FEATURE_IPACM_PER_CLIENT_STATS
				else if (IPACM_util_icmp_string((char*)xml_node->name, LAN_Stats_Enable_TAG) == 0)
				{
					IPACMDBG_H("inside enable lan statistics\n");
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (atoi(content_buf))
						{
							config->lan_stats_enable = true;
							IPACMDBG_H("LAN Stats enable %d buf(%d)\n", config->lan_stats_enable, atoi(content_buf));
						}
						else
						{
							config->lan_stats_enable = false;
							IPACMDBG_H("LAN Stats enable %d buf(%d)\n", config->lan_stats_enable, atoi(content_buf));
						}
					}
				}
#endif
				else if (IPACM_util_icmp_string((char*)xml_node->name, ODUMODE_TAG) == 0)
				{
					IPACMDBG_H("inside ODU-XML\n");
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (0 == strncasecmp(content_buf, ODU_ROUTER_TAG, str_size))
						{
							config->router_mode_enable = true;
							IPACMDBG_H("router-mode enable %d\n", config->router_mode_enable);
						}
						else if (0 == strncasecmp(content_buf, ODU_BRIDGE_TAG, str_size))
						{
							config->router_mode_enable = false;
							IPACMDBG_H("router-mode enable %d\n", config->router_mode_enable);
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, ODUEMBMS_OFFLOAD_TAG) == 0)
				{
					IPACMDBG_H("inside ODU-XML\n");
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (atoi(content_buf))
						{
							config->odu_embms_enable = true;
							IPACMDBG_H("router-mode enable %d buf(%d)\n", config->odu_embms_enable, atoi(content_buf));
						}
						else
						{
							config->odu_embms_enable = false;
							IPACMDBG_H("router-mode enable %d buf(%d)\n", config->odu_embms_enable, atoi(content_buf));
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, NAME_TAG) == 0)
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						strlcpy(config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].iface_name, content_buf, str_size+1);
						IPACMDBG_H("Name %s\n", config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].iface_name);
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, PHY_TAG) == 0)
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						strlcpy(config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].phy_dev_name, content_buf, str_size+1);
						config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].virtual_iface = true;
						IPACMDBG_H("Phy %s\n", config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].phy_dev_name);
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, CATEGORY_TAG) == 0)
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (0 == strncasecmp(content_buf, WANIF_TAG, str_size))
						{
							config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat = WAN_IF;
							IPACMDBG_H("Category %d\n", config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat);
						}
						else if (0 == strncasecmp(content_buf, LANIF_TAG, str_size))
						{
							config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat = LAN_IF;
							IPACMDBG_H("Category %d\n", config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat);
						}
						else if (0 == strncasecmp(content_buf, WLANIF_TAG, str_size))
						{
							config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat = WLAN_IF;
							IPACMDBG_H("Category %d\n", config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat);
						}
						else  if (0 == strncasecmp(content_buf, VIRTUALIF_TAG, str_size))
						{
							config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat = VIRTUAL_IF;
							IPACMDBG_H("Category %d\n", config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat);
						}
						else  if (0 == strncasecmp(content_buf, UNKNOWNIF_TAG, str_size))
						{
							config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat = UNKNOWN_IF;
							IPACMDBG_H("Category %d\n", config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat);
						}
						else  if (0 == strncasecmp(content_buf, ETHIF_TAG, str_size))
						{
							config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat = ETH_IF;
							IPACMDBG_H("Category %d\n", config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat);
						}
						else  if (0 == strncasecmp(content_buf, ODUIF_TAG, str_size))
						{
							config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat = ODU_IF;
							IPACMDBG("Category %d\n", config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_cat);
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, MODE_TAG) == 0)
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (0 == strncasecmp(content_buf, IFACE_ROUTER_MODE_TAG, str_size))
						{
							config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_mode = ROUTER;
							IPACMDBG_H("Iface mode %d\n", config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_mode);
						}
						else  if (0 == strncasecmp(content_buf, IFACE_BRIDGE_MODE_TAG, str_size))
						{
							config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_mode = BRIDGE;
							IPACMDBG_H("Iface mode %d\n", config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].if_mode);
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, WLAN_MODE_TAG) == 0)
				{
					IPACMDBG_H("Inside WLAN-XML\n");
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (0 == strncasecmp(content_buf, WLAN_FULL_MODE_TAG, str_size))
						{
							config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].wlan_mode = FULL;
							IPACMDBG_H("Wlan-mode full(%d)\n",
									config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].wlan_mode);
						}
						else  if (0 == strncasecmp(content_buf, WLAN_INTERNET_MODE_TAG, str_size))
						{
							config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].wlan_mode = INTERNET;
							config->num_wlan_guest_ap++;
							IPACMDBG_H("Wlan-mode internet(%d)\n",
									config->iface_config.iface_entries[config->iface_config.num_iface_entries - 1].wlan_mode);
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, Protocol_TAG) == 0)
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (0 == strncasecmp(content_buf, TCP_PROTOCOL_TAG, str_size))
						{
							config->alg_config.alg_entries[config->alg_config.num_alg_entries - 1].protocol = IPPROTO_TCP;
							IPACMDBG_H("Protocol %s: %d\n",
									content_buf, config->alg_config.alg_entries[config->alg_config.num_alg_entries - 1].protocol);
						}
						else if (0 == strncasecmp(content_buf, UDP_PROTOCOL_TAG, str_size))
						{
							config->alg_config.alg_entries[config->alg_config.num_alg_entries - 1].protocol = IPPROTO_UDP;
							IPACMDBG_H("Protocol %s: %d\n",
									content_buf, config->alg_config.alg_entries[config->alg_config.num_alg_entries - 1].protocol);
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, Port_TAG) == 0)
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->alg_config.alg_entries[config->alg_config.num_alg_entries - 1].port
							 = atoi(content_buf);
						IPACMDBG_H("port %d\n", config->alg_config.alg_entries[config->alg_config.num_alg_entries - 1].port);
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, NAT_MaxEntries_TAG) == 0)
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->nat_max_entries = atoi(content_buf);
						IPACMDBG_H("Nat Table Max Entries %d\n", config->nat_max_entries);
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, NAT_TableType_TAG) == 0)
				{
					config->nat_table_memtype = DDR_TABLETYPE_TAG;
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (0 == strncasecmp(content_buf, DDR_TABLETYPE_TAG, str_size))
						{
							config->nat_table_memtype = DDR_TABLETYPE_TAG;
						}
						else if (0 == strncasecmp(content_buf, SRAM_TABLETYPE_TAG, str_size))
						{
							config->nat_table_memtype = SRAM_TABLETYPE_TAG;
						}
						else if (0 == strncasecmp(content_buf, HYBRID_TABLETYPE_TAG, str_size))
						{
							config->nat_table_memtype = HYBRID_TABLETYPE_TAG;
						}
					}
					IPACMDBG_H("NAT Table location %s\n", config->nat_table_memtype);
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, IPV6CT_ENABLED_TAG) == 0)
				{
					content = IPACM_read_content_element(xml_node);
					if (content == NULL)
					{
						IPACMERR("Failed to read the content of the tag %s\n", IPV6CT_ENABLED_TAG);
					}
					else
					{
						str_size = strlen(content);
						if (str_size >= sizeof(content_buf))
						{
							IPACMERR("The content of the tag %s is too long\n", IPV6CT_ENABLED_TAG);
						}
						else
						{
							memset(content_buf, 0, sizeof(content_buf));
							memcpy(content_buf, (void *)content, str_size);
							content_buf[MAX_XML_STR_LEN-1] = '\0';
							config->ipv6ct_enable = atoi(content_buf);
							IPACMDBG_H("IPv6CT enable %d\n", config->ipv6ct_enable);
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, IPV6CT_MAX_ENTRIES_TAG) == 0)
				{
					content = IPACM_read_content_element(xml_node);
					if (content == NULL)
					{
						IPACMERR("Failed to read the content of the tag %s\n", IPV6CT_MAX_ENTRIES_TAG);
					}
					else
					{
						str_size = strlen(content);
						if (str_size >= sizeof(content_buf))
						{
							IPACMERR("The content of the tag %s is too long\n", IPV6CT_MAX_ENTRIES_TAG);
						}
						else
						{
							memset(content_buf, 0, sizeof(content_buf));
							memcpy(content_buf, (void *)content, str_size);
							content_buf[MAX_XML_STR_LEN-1] = '\0';
							config->ipv6ct_max_entries = atoi(content_buf);
							IPACMDBG_H("IPv6CT Table Max Entries %d\n", config->ipv6ct_max_entries);
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, CT_TableType_TAG) == 0)
				{
					config->ct_table_memtype = DDR_TABLETYPE_TAG;
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (0 == strncasecmp(content_buf, DDR_TABLETYPE_TAG, str_size))
						{
							config->ct_table_memtype = DDR_TABLETYPE_TAG;
						}
						else if (0 == strncasecmp(content_buf, SRAM_TABLETYPE_TAG, str_size))
						{
							config->ct_table_memtype = SRAM_TABLETYPE_TAG;
						}
						else if (0 == strncasecmp(content_buf, HYBRID_TABLETYPE_TAG, str_size))
						{
							config->ct_table_memtype = HYBRID_TABLETYPE_TAG;
						}
					}
					IPACMDBG_H("CT Table location %s\n", config->ct_table_memtype);
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, IPACM_IPV6NAT_Enable_TAG) == 0)
				{
					IPACMDBG_H("inside enable IPV6 NAT\n");
					content = IPACM_read_content_element(xml_node);
					if (content == NULL)
					{
						IPACMERR("Failed to read the content of the tag %s\n", IPACM_IPV6NAT_Enable_TAG);
					}
					else
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (atoi(content_buf))
						{
							config->ipv6_nat_enable = true;
							IPACMDBG_H("IPV6 NAT enable %d buf(%d)\n",
								config->ipv6_nat_enable, atoi(content_buf));
						}
						else
						{
							config->ipv6_nat_enable = false;
							IPACMDBG_H("IPV6 NAT enable %d buf(%d)\n",
								config->ipv6_nat_enable, atoi(content_buf));
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, IPACM_L2TP_Enable_TAG) == 0)
				{
						IPACMDBG_H("inside enable L2tp\n");
						content = IPACM_read_content_element(xml_node);
						if (content == NULL)
						{
							IPACMERR("Failed to read the content of the tag %s\n", IPACM_L2TP_Enable_TAG);
						}
						else
						{
							str_size = strlen(content);
							memset(content_buf, 0, sizeof(content_buf));
							memcpy(content_buf, (void *)content, str_size);
							content_buf[MAX_XML_STR_LEN-1] = '\0';
							config->ipacm_l2tp_enable = atoi(content_buf);
						}
				}

				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPACMFILEVAR_TAG))
				{		IPACMDBG_H("inside ipacm_logging \n");
						content = IPACM_read_content_element(xml_node);
						if (content)
						{
							str_size = strlen(content);
							memset(content_buf, 0, sizeof(content_buf));
							memcpy(content_buf, (void *)content, str_size);
							if(atoi(content_buf)!=0)
							{
								config->max_file_size = atoi(content_buf);
								IPACMDBG_H("max_filesz %d \n",config->max_file_size);
							}
						}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, IPACM_MPDN_Enable_TAG) == 0)
				{
						IPACMDBG_H("inside enable MPDN\n");
						content = IPACM_read_content_element(xml_node);
						if (content == NULL)
						{
							IPACMERR("Failed to read the content of the tag %s\n", IPACM_MPDN_Enable_TAG);
						}
						else
						{
							str_size = strlen(content);
							memset(content_buf, 0, sizeof(content_buf));
							memcpy(content_buf, (void *)content, str_size);
							content_buf[MAX_XML_STR_LEN-1] = '\0';
							if (atoi(content_buf))
							{
								config->ipacm_mpdn_enable = true;
								IPACMDBG_H("IPACM VLAN_MPDN is enable %d buf(%d)\n",
								config->ipacm_mpdn_enable, atoi(content_buf));
							}
							else
							{
								config->ipacm_mpdn_enable = false;
								IPACMDBG_H("IPACM VLAN_MPDN enable %d buf(%d)\n",
								config->ipacm_mpdn_enable, atoi(content_buf));
							}
						}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, ENABLE_PUBLIC_IP_SUPPORT) == 0)
				{
					IPACMDBG_H("inside Public Ip Support-XML\n");
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (atoi(content_buf))
						{
							config->public_ip_support_enable = true;
						}
						else
						{
							config->public_ip_support_enable = false;
						}
						IPACMDBG_H("Public IP support config enable %d buf(%d)\n", config->public_ip_support_enable, atoi(content_buf));
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, IPACM_Easy_Mesh_Enabled) == 0)
				{
					IPACMDBG_H("inside enable Easy Mesh\n");
					content = IPACM_read_content_element(xml_node);
					if (content == NULL)
					{
						IPACMERR("Failed to read the content of the tag %s\n", IPACM_Easy_Mesh_Enabled);
					}
					else
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (atoi(content_buf))
						{
							config->ipacm_emesh_enable = true;
							IPACMDBG_H("IPACM Easy mesh enable %d buf(%d)\n",
							config->ipacm_emesh_enable, atoi(content_buf));
						}
						else
						{
							config->ipacm_emesh_enable = false;
							IPACMDBG_H("IPACM Easy mesh disable %d buf(%d)\n",
							config->ipacm_emesh_enable, atoi(content_buf));
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, IPACM_Easy_Mesh_Mode) == 0)
				{
					IPACMDBG_H("inside enable Easy Mesh Mode type\n");
					content = IPACM_read_content_element(xml_node);
					if (content == NULL)
					{
						IPACMERR("Failed to read the content of the tag %s\n", IPACM_Easy_Mesh_Mode);
					}
					else
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->ipacm_emesh_mode = atoi(content_buf);
						IPACMDBG_H("IPACM Easy mesh mode %d buf(%d)\n",
								   config->ipacm_emesh_mode, atoi(content_buf));
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, IPACM_Wlan_Vlan_Mpdn_Enabled) == 0)
				{
					IPACMDBG_H("inside enable Vlan Mpdn-XML\n");
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (atoi(content_buf))
						{
							config->wlan_vlan_mpdn_enable = true;
						}
						else
						{
							config->wlan_vlan_mpdn_enable = false;
						}
						IPACMDBG_H("VLAN Mpdn for WLAN enable %d buf(%d)\n", config->wlan_vlan_mpdn_enable, atoi(content_buf));
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, Static_Policy_Enabled) == 0)
				{
					IPACMDBG_H("inside enable Static Policy-XML\n");
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (atoi(content_buf))
						{
							config->static_policy_enable = true;
						}
						else
						{
							config->static_policy_enable = false;
						}
						IPACMDBG_H("static_policy_enable %d buf(%d)\n", config->static_policy_enable, atoi(content_buf));
					}
				}
#ifdef FEATURE_STATIC_POLICY
				else if (IPACM_util_icmp_string((char*)xml_node->name, Static_Policy_DSCP_Mark_Mode) == 0)
				{
					IPACMDBG_H("inside Static_Policy_DSCP_Mark_Mode\n");
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->static_policy_dscp_mark_mode = atoi(content_buf);
						IPACMDBG_H("Static_Policy_DSCP_Mark_Mode:%d\n",
							atoi(content_buf));
					}
				}
#endif
				else if (IPACM_util_icmp_string((char*)xml_node->name, IPACM_QOS_ENABLE_TAG) == 0)
				{
					IPACMDBG_H("inside QOS mode\n");
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (atoi(content_buf))
						{
							config->qos_mode = true;
							IPACMDBG_H("QOS mode enabled %d buf(%d)\n", config->qos_mode, atoi(content_buf));
						}
						else
						{
							config->qos_mode = false;
							IPACMDBG_H("QOS mode disabled %d buf(%d)\n", config->qos_mode, atoi(content_buf));
						}
					} else {
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, IPACMDEVICEMODE) == 0)
				{
					IPACMDBG_H("inside IPacmDeviceMode\n");
					content = IPACM_read_content_element(xml_node);
					IPACMDBG_H("content %s\n", content);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						strlcpy(content_buf, content, str_size+1);
						IPACMDBG_H("content %s\n", content_buf);
						if (0 == strncasecmp(content_buf, "apbridge", str_size))
						{
							config->device_mode = DEVMODE_APBRIDGE;
						}
						else  if (0 == strncasecmp(content_buf, "stabridge", str_size))
						{
							config->device_mode = DEVMODE_STABRIDGE;
						}
						else
						{
							config->device_mode = DEVMODE_DEFAULT;
						}

					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, IPACMVLANMODE) == 0)
				{
					IPACMDBG_H("inside IPacm vlan mode\n");
					content = IPACM_read_content_element(xml_node);
					IPACMDBG_H("content %s\n", content);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						strlcpy(content_buf, content, str_size+1);
						IPACMDBG_H("content %s\n", content_buf);
						if (0 == strncasecmp(content_buf, "Enable", str_size))
						{
							config->device_vlan_mode = true;
						}
						else  if (0 == strncasecmp(content_buf, "Disable", str_size))
						{
							config->device_vlan_mode = false;
						}

					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, IPACMMGMNTVLANID) == 0)
				{
					IPACMDBG_H("Inside management vlan id extraction\n");
					content = IPACM_read_content_element(xml_node);
					if (content == NULL)
					{
						IPACMERR("Failed to read the content of the tag %s\n", IPACMMGMNTVLANID);
					}
					else
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						strlcpy(content_buf, content, str_size+1);
						config->mgmnt_vlan_id = atoi(content_buf);
						IPACMDBG_H("IPACM management vlan id %d\n", atoi(content_buf));
					}
				}

			}
			break;
		default:
			break;
		}
		/* go to sibling */
		xml_node = xml_node->next;
	} /* end while */
	return ret_val;
}


static int ipacm_cfg_validate_parsed_xml(IPACM_conf_t *config)
{
	int i;

	for (i = 0; i < config->iface_config.num_iface_entries; i++)
	{
		if (config->iface_config.iface_entries[i].phy_dev_name[0] == 0 &&
		    strncmp(config->iface_config.iface_entries[i].iface_name, "macsec", sizeof("macsec")) == 0)
		{
			IPACMERR("Interface %s has no physical interface in the configuration!\n",
				 config->iface_config.iface_entries[i].iface_name);
			return IPACM_FAILURE;
		}
	}

	return IPACM_SUCCESS;
}

/* This function read QCMAP CM Firewall XML and populate the QCMAP CM Cfg */
int IPACM_read_firewall_xml(const char *xml_file, IPACM_firewall_t &firewall_config)
{
	xmlDocPtr doc = NULL;
	xmlNode* root = NULL;
	int ret_val = IPACM_SUCCESS;

	memset(&firewall_config, 0, sizeof(firewall_config));

	/* invoke the XML parser and obtain the parse tree */
	doc = xmlReadFile(xml_file, "UTF-8", XML_PARSE_NOBLANKS);
	if (doc == NULL) {
		IPACMDBG_H("IPACM_xml_parse: libxml returned parse error\n");
		return IPACM_FAILURE;
	}
	/*get the root of the tree*/
	root = xmlDocGetRootElement(doc);
	if (root == NULL || IPACM_util_icmp_string((char*)root->name, system_TAG) != 0)
	{
		IPACMERR("The XML %s is not valid. Please start from %s tag", xml_file, system_TAG);
		ret_val = IPACM_FAILURE;
		goto bail;
	}

	/* parse the xml tree returned by libxml*/
	ret_val = IPACM_firewall_xml_parse_tree(xml_file, root->children, firewall_config);
	if (ret_val != IPACM_SUCCESS)
	{
		IPACMERR("IPACM_xml_parse: ipacm_firewall_xml_parse_tree returned parse error!\n");
		memset(&firewall_config, 0, sizeof(firewall_config));
		ret_val = IPACM_FAILURE;
		goto bail;
	}

bail:
	/* free the tree */
	xmlFreeDoc(doc);

	return ret_val;
}

int IPACM_read_firewall_xml(const char *xml_file, IPACM_firewall_conf_t &default_pdn_firewall_config)
{
	memset(&default_pdn_firewall_config, 0, sizeof(default_pdn_firewall_config));

	IPACM_firewall_t firewall_config;

	int ret_val = IPACM_read_firewall_xml(xml_file, firewall_config);
	if (ret_val != IPACM_SUCCESS)
	{
		IPACMERR("Failed to read the XML %s\n", xml_file);
		return ret_val;
	}

	if (firewall_config.pdn_count == 0)
	{
		IPACMDBG_H("There are no firewal rules in %s\n", xml_file);
		return IPACM_SUCCESS;
	}

	uint8_t pdn_index;
	if (!firewall_config.default_profile)
	{
		if (firewall_config.pdn_count != 1)
		{
			IPACMERR("The XML %s is not valid. Please add %s tag\n", xml_file, DefaultProfile_TAG);
			return IPACM_FAILURE;
		}
		pdn_index = 0;
	}
	else
	{
		for (pdn_index = 0; pdn_index < firewall_config.pdn_count; ++pdn_index)
		{
			if (firewall_config.default_profile == firewall_config.pdns[pdn_index].profile)
			{
				break;
			}
		}
		if (pdn_index == firewall_config.pdn_count)
		{
			IPACMERR("The XML %s is not valid. The default profile %d isn't located\n",
				xml_file, firewall_config.default_profile);
			return IPACM_FAILURE;
		}
	}

	memcpy(&default_pdn_firewall_config, &firewall_config.pdns[pdn_index], sizeof(default_pdn_firewall_config));
	return IPACM_SUCCESS;
}

/* This function traverses the firewall xml tree */
static int IPACM_firewall_xml_parse_tree(const char *xml_file, xmlNode* xml_node, IPACM_firewall_t &firewall_config)
{
	int mask_value_v6, mask_index;
	int32_t ret_val = IPACM_SUCCESS;
	char *content;
	int str_size;
	char content_buf[MAX_XML_STR_LEN];
	struct in6_addr ip6_addr;

	if (NULL == xml_node)
		return IPACM_SUCCESS;

	while ( xml_node != NULL &&
				 ret_val == IPACM_SUCCESS)
	{
		switch (xml_node->type)
		{

		case XML_ELEMENT_NODE:
		{
			if (IPACM_util_icmp_string((char*)xml_node->name, DefaultProfile_TAG) == 0)
			{
				content = IPACM_read_content_element(xml_node);
				if (content != NULL)
				{
					memset(content_buf, 0, sizeof(content_buf));
					memcpy(content_buf, (void *)content, strlen(content));
					content_buf[MAX_XML_STR_LEN-1] = '\0';
					firewall_config.default_profile = atoi(content_buf);
					IPACMDBG_H("Default profile is %d\n", firewall_config.default_profile);
				}
			}
			else if (IPACM_util_icmp_string((char*)xml_node->name, MobileAPFirewallCfg_TAG) == 0)
			{
				IPACMDBG_H("MobileAPFirewallCfg_TAG\n");
				if (++firewall_config.pdn_count > IPA_MAX_NUM_SW_PDNS)
				{
					IPACMERR("The XML %s is not valid. The number of %s tags should be at most %d\n",
						xml_file, MobileAPFirewallCfg_TAG, IPA_MAX_NUM_SW_PDNS);
					return IPACM_FAILURE;
				}
				/* go to child */
				ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
			}
			else if(IPACM_util_icmp_string((char*)xml_node->name, DefaultNetDev) == 0)
			{
				content = IPACM_read_content_element(xml_node);
				if(content != NULL)
				{
					str_size = strlen(content);
					memset(content_buf, 0, sizeof(content_buf));
					memcpy(content_buf, (void *)content, str_size);
					content_buf[MAX_XML_STR_LEN - 1] = '\0';
					IPACMDBG_H("DefaultNetDev is %s\n", content_buf);
				}
			}
			else
			{
				if (!firewall_config.pdn_count)
				{
					IPACMERR("The XML %s is not valid. Please add %s tag as a child of %s tag",
						xml_file, MobileAPFirewallCfg_TAG, system_TAG);
					return IPACM_FAILURE;
				}

				IPACM_firewall_conf_t* config = &firewall_config.pdns[firewall_config.pdn_count - 1];

				if (0 == IPACM_util_icmp_string((char*)xml_node->name, Firewall_TAG) ||
					0 == IPACM_util_icmp_string((char*)xml_node->name, FirewallEnabled_TAG)  ||
					0 == IPACM_util_icmp_string((char*)xml_node->name, FirewallPktsAllowed_TAG))
				{
					if (0 == IPACM_util_icmp_string((char*)xml_node->name, Firewall_TAG))
					{
						/* increase firewall entry num */
						config->num_extd_firewall_entries++;
					}

					if (0 == IPACM_util_icmp_string((char*)xml_node->name, FirewallPktsAllowed_TAG))
					{
						/* setup action of matched rules */
					    content = IPACM_read_content_element(xml_node);
					    if (content)
					    {
						        str_size = strlen(content);
						        memset(content_buf, 0, sizeof(content_buf));
						        memcpy(content_buf, (void *)content, str_size);
							content_buf[MAX_XML_STR_LEN-1] = '\0';
							if (atoi(content_buf)==1)
							{
								config->rule_action_accept = true;
							}
							else
							{
								config->rule_action_accept = false;
							}
							IPACMDBG_H(" Allow traffic which matches rules ?:%d\n",config->rule_action_accept);
					    }
				    }

					if (0 == IPACM_util_icmp_string((char*)xml_node->name, FirewallEnabled_TAG))
					{
						/* setup if firewall enable or not */
					    content = IPACM_read_content_element(xml_node);
					    if (content)
					    {
						        str_size = strlen(content);
						        memset(content_buf, 0, sizeof(content_buf));
						        memcpy(content_buf, (void *)content, str_size);
							content_buf[MAX_XML_STR_LEN-1] = '\0';
							if (atoi(content_buf)==1)
							{
								config->firewall_enable = true;
							}
						        else
							{
								config->firewall_enable = false;
							}
							IPACMDBG_H(" Firewall Enable?:%d\n", config->firewall_enable);
				        }
					}
					/* go to child */
					ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
				}
#ifdef FEATURE_IPACM_UL_FIREWALL
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, FirewallDirection_TAG))
				{ /* Getting an info about direction (UL/DL) */
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (0 == IPACM_util_icmp_string((char*)content_buf, UL_TAG))
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].firewall_direction
							= IPACM_MSGR_UL_FIREWALL;  /* Its UL*/
						}
						else if (0 == IPACM_util_icmp_string((char*)content_buf, DL_TAG))
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].firewall_direction
							= IPACM_MSGR_DL_FIREWALL;  /* Its DL*/
						}
					}
				}
#endif //FEATURE_IPACM_UL_FIREWALL
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPFamily_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].ip_vsn
							 = (firewall_ip_version_enum)atoi(content_buf);
						IPACMDBG_H("\n IP family type is %d \n",
								config->extd_firewall_entries[config->num_extd_firewall_entries - 1].ip_vsn);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV4SourceAddress_TAG))
				{
					config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_SRC_ADDR;
					/* go to child */
					ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV4SourceIPAddress_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v4.src_addr
							 = ntohl(inet_addr(content_buf));
						IPACMDBG_H("IPv4 source address is: %s \n", content_buf);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV4SourceSubnetMask_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v4.src_addr_mask
							 = ntohl(inet_addr(content_buf));
						IPACMDBG_H("IPv4 source subnet mask is: %s \n", content_buf);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV4DestinationAddress_TAG))
				{
					config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_DST_ADDR;
					/* go to child */
					ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV4DestinationIPAddress_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v4.dst_addr
							 = ntohl(inet_addr(content_buf));
						IPACMDBG_H("IPv4 destination address is: %s \n", content_buf);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV4DestinationSubnetMask_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v4.dst_addr_mask
							= ntohl(inet_addr(content_buf));
						IPACMDBG_H("IPv4 destination subnet mask is: %s \n", content_buf);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV4TypeOfService_TAG))
				{
					config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_TOS;
					/* go to child */
					ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TOSValue_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v4.tos
							 = atoi(content_buf);
						// Here we do not know if it is TOS with mask or not, so we put at both places
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.tos_value
							= atoi(content_buf);
						IPACMDBG_H("\n IPV4 TOS val is %d \n",
										 config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v4.tos);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TOSMask_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						uint8_t mask;

						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						mask = atoi(content_buf);
						IPACMDBG_H("\n IPv4 TOS mask is %u \n", mask);
						if (mask != 0xFF) {
							// TOS attribute cannot be used
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v4.tos = 0;
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.tos_mask = mask;

							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |=
								IPA_FLT_TOS_MASKED;
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask &=
								~IPA_FLT_TOS;
						} else {
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.tos_value = 0;
						}
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV4NextHeaderProtocol_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_PROTOCOL;
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v4.protocol = atoi(content_buf);
						IPACMDBG_H("\n IPv4 next header prot is %d \n",
								 config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v4.protocol);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV6SourceAddress_TAG))
				{
					config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |=
						 IPA_FLT_SRC_ADDR;
					/* go to child */
					ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV6SourceIPAddress_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						inet_pton(AF_INET6, content_buf, &ip6_addr);
						memcpy(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.src_addr,
									 ip6_addr.s6_addr, IPACM_IPV6_ADDR_LEN * sizeof(uint8_t));
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.src_addr[0]=ntohl(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.src_addr[0]);
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.src_addr[1]=ntohl(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.src_addr[1]);
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.src_addr[2]=ntohl(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.src_addr[2]);
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.src_addr[3]=ntohl(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.src_addr[3]);

						IPACMDBG_H("\n ipv6 source addr is %d \n ",
								config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.src_addr[0]);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV6SourcePrefix_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						mask_value_v6 = atoi(content_buf);
						for (mask_index = 0; mask_index < 4; mask_index++)
						{
							if (mask_value_v6 >= 32)
							{
								mask_v6(32, &(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.src_addr_mask[mask_index]));
								mask_value_v6 -= 32;
							}
							else
							{
								mask_v6(mask_value_v6, &(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.src_addr_mask[mask_index]));
								mask_value_v6 = 0;
							}
						}
						IPACMDBG_H("\n ipv6 source prefix is %d \n", atoi(content_buf));
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV6DestinationAddress_TAG))
				{
					config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |=
						 IPA_FLT_DST_ADDR;
					/* go to child */
					ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV6DestinationIPAddress_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						inet_pton(AF_INET6, content_buf, &ip6_addr);
						memcpy(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.dst_addr,
									 ip6_addr.s6_addr, IPACM_IPV6_ADDR_LEN * sizeof(uint8_t));
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.dst_addr[0]=ntohl(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.dst_addr[0]);
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.dst_addr[1]=ntohl(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.dst_addr[1]);
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.dst_addr[2]=ntohl(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.dst_addr[2]);
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.dst_addr[3]=ntohl(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.dst_addr[3]);
						IPACMDBG_H("\n ipv6 dest addr is %d \n",
								 config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.dst_addr[0]);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV6DestinationPrefix_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						mask_value_v6 = atoi(content_buf);
						for (mask_index = 0; mask_index < 4; mask_index++)
						{
							if (mask_value_v6 >= 32)
							{
								mask_v6(32, &(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.dst_addr_mask[mask_index]));
								mask_value_v6 -= 32;
							}
							else
							{
								mask_v6(mask_value_v6, &(config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.dst_addr_mask[mask_index]));
								mask_value_v6 = 0;
							}
						}
						IPACMDBG_H("\n ipv6 dest prefix is %d \n", atoi(content_buf));
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV6TrafficClass_TAG))
				{
					config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_TC;
					/* go to child */
					ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TrfClsValue_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.tc
							 = atoi(content_buf);
						IPACMDBG_H("\n ipv6 trf class val is %d \n",
								 config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.tc);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TrfClsMask_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.tc
							 &= atoi(content_buf);
						IPACMDBG_H("\n ipv6 trf class mask is %d \n", atoi(content_buf));
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPV6NextHeaderProtocol_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_NEXT_HDR;
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.next_hdr
							 = atoi(content_buf);
						IPACMDBG_H("\n ipv6 next header protocol is %d \n",
								 config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.u.v6.next_hdr);
					}
				}
#ifdef FEATURE_IPV6_NAT
				else if(0 == IPACM_util_icmp_string((char*)xml_node->name, IPV6NatEnabledfw_TAG))
				{
					int val = 0;

					content = IPACM_read_content_element(xml_node);
					if(content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						val = atoi(content_buf);
					}

					config->extd_firewall_entries[config->num_extd_firewall_entries - 1].IPV6NatEnabledfw = val ? true : false;
					IPACMDBG_H("this is %s IPV6 nat rule\n", val ? "an" : "not an");
				}
#endif
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TCPSource_TAG))
				{
					/* go to child */
					ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TCPSourcePort_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port
							 = atoi(content_buf);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TCPSourceRange_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if (atoi(content_buf) != 0)
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_SRC_PORT_RANGE;
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port_lo
								= config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port;
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port_hi
								= config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port + atoi(content_buf);
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port = 0;
							IPACMDBG_H("\n tcp source port from %d to %d \n",
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port_lo,
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port_hi);
						}
						else
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_SRC_PORT;
							IPACMDBG_H("\n tcp source port= %d \n",
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port);
						}
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TCPDestination_TAG))
				{
					/* go to child */
					ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TCPDestinationPort_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port
							 = atoi(content_buf);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TCPDestinationRange_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if(atoi(content_buf)!=0)
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_DST_PORT_RANGE;
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port_lo
								= config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port;
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port_hi
								= config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port + atoi(content_buf);
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port = 0;
							IPACMDBG_H("\n tcp dest port from %d to %d \n",
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port_lo,
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port_hi);
						}
						else
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_DST_PORT;
							IPACMDBG_H("\n tcp dest port= %d \n",
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port);
						}
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, UDPSource_TAG))
				{
					/* go to child */
					ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, UDPSourcePort_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port
							 = atoi(content_buf);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, UDPSourceRange_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if(atoi(content_buf)!=0)
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_SRC_PORT_RANGE;
 							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port_lo
								= config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port;
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port_hi
								= config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port + atoi(content_buf);
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port = 0;
							IPACMDBG_H("\n udp source port from %d to %d \n",
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port_lo,
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port_hi);
						}
						else
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_SRC_PORT;
							IPACMDBG_H("\n udp source port= %d \n",
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port);
						}
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, UDPDestination_TAG))
				{
					/* go to child */
					ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, UDPDestinationPort_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port
							 = atoi(content_buf);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, UDPDestinationRange_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if(atoi(content_buf)!=0)
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_DST_PORT_RANGE;
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port_lo
								= config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port;
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port_hi
								= config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port + atoi(content_buf);
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port = 0;
							IPACMDBG_H("\n UDP dest port from %d to %d \n",
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port_lo,
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port_hi);
						}
						else
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_DST_PORT;
							IPACMDBG_H("\n UDP dest port= %d \n",
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port);
						}
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, ICMPType_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.type = atoi(content_buf);
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_TYPE;
						IPACMDBG_H("\n icmp type is %d \n",
								 config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.type);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, ICMPCode_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.code = atoi(content_buf);
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_CODE;
						IPACMDBG_H("\n icmp code is %d \n",
								 config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.code);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, ESPSPI_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.spi = atoi(content_buf);
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_SPI;
						IPACMDBG_H("\n esp spi is %d \n",
								config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.spi);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TCP_UDPSource_TAG))
				{
					/* go to child */
					ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TCP_UDPSourcePort_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content,str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port
							 = atoi(content_buf);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TCP_UDPSourceRange_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if(atoi(content_buf)!=0)
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_SRC_PORT_RANGE;
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port_lo
								= config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port;
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port_hi
								= config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port + atoi(content_buf);
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port = 0;
							IPACMDBG_H("\n tcp_udp source port from %d to %d \n",
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port_lo,
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port_hi);
						}
						else
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_SRC_PORT;
							IPACMDBG_H("\n tcp_udp source port= %d \n",
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.src_port);

						}
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TCP_UDPDestination_TAG))
				{
					ret_val = IPACM_firewall_xml_parse_tree(xml_file, xml_node->children, firewall_config);
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TCP_UDPDestinationPort_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port
							 = atoi(content_buf);
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, TCP_UDPDestinationRange_TAG))
				{
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if(atoi(content_buf)!=0)
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_DST_PORT_RANGE;
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port_lo
								= config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port;
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port_hi
								= config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port + atoi(content_buf);
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port = 0;
							IPACMDBG_H("\n tcp_udp dest port from %d to %d \n",
								config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port_lo,
								config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port_hi);
						}
						else
						{
							config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.attrib_mask |= IPA_FLT_DST_PORT;
							IPACMDBG_H("\n tcp_udp dest port= %d \n",
									config->extd_firewall_entries[config->num_extd_firewall_entries - 1].attrib.dst_port);
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, NetDev_TAG) == 0)
				{
					content = IPACM_read_content_element(xml_node);
					if (content != NULL)
					{
						str_size = strlen(content);
						if (str_size >= IPA_IFACE_NAME_LEN)
						{
							IPACMERR("The length of NetDev tag content is bigger than %d in %s",
								IPA_IFACE_NAME_LEN, xml_file);
						}
						else if (content[0] == '0')
						{
							strlcpy(config->net_dev, UNKNOWN_NetDev_TAG, sizeof(config->net_dev));
							IPACMDBG_H("NetDev is %s\n", config->net_dev);
						}
						else
						{
							strlcpy(config->net_dev, content, sizeof(config->net_dev));
							IPACMDBG_H("NetDev is %s\n", config->net_dev);
						}
					}
				}
				else if (IPACM_util_icmp_string((char*)xml_node->name, Profile_TAG) == 0)
				{
					content = IPACM_read_content_element(xml_node);
					if (content != NULL)
					{
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, strlen(content));
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						config->profile = atoi(content_buf);
						IPACMDBG_H("Profile is %d\n", config->profile);
					}
				}
			}
			break;
		}
		default:
			break;
		}
		/* go to sibling */
		xml_node = xml_node->next;
	} /* end while */
	return ret_val;
}

/* This function traverses the cfg ext xml tree */
static int IPACM_cfg_ext_xml_parse_tree
(
	 xmlNode* xml_node,
	 IPACM_dscp_pcp_conf_t *config,
	 int* map_index
)
{
	int32_t ret_val = IPACM_SUCCESS;
	char *content;
	int str_size;
	char content_buf[MAX_XML_STR_LEN];
	int pcp_value;

	IPACM_ASSERT(config != NULL);

	if (NULL == xml_node)
		return ret_val;

	while ( xml_node != NULL )
	{
		switch (xml_node->type)
		{

		case XML_ELEMENT_NODE:
			{
				if (0 == IPACM_util_icmp_string((char*)xml_node->name, system_TAG) ||
						0 == IPACM_util_icmp_string((char*)xml_node->name, IPACMDSCPPCPCfg_TAG) ||
						0 == IPACM_util_icmp_string((char*)xml_node->name, IPACMDSCPPCPEnabled_TAG) ||
						0 == IPACM_util_icmp_string((char*)xml_node->name, IPACMDSCPPCPMapping_TAG)  ||
						0 == IPACM_util_icmp_string((char*)xml_node->name, DSCPPCPMapping_TAG))
				{
					if (0 == IPACM_util_icmp_string((char*)xml_node->name, IPACMDSCPPCPEnabled_TAG))
					{
						content = IPACM_read_content_element(xml_node);
						if (content)
						{
							str_size = strlen(content);
							memset(content_buf, 0, sizeof(content_buf));
							memcpy(content_buf, (void *)content, str_size);
							content_buf[MAX_XML_STR_LEN-1] = '\0';
							if (atoi(content_buf)==1)
							{
								config->add = 1;
							}
							else
							{
								config->add = 0;
							}
							IPACMDBG_H("DSCP PCP mapping %s\n",(config->add == 1)?"added":"removed");
						}
					}

					if (0 == IPACM_util_icmp_string((char*)xml_node->name, DSCPPCPMapping_TAG))
					{
						*map_index = *map_index + 1;
					}

					/* go to child */
					ret_val = IPACM_cfg_ext_xml_parse_tree(xml_node->children, config, map_index);
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, DSCP_TAG))
				{
					/* Get DSCP value and compare with index to error out */
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						if ( atoi(content_buf) != (int)(*map_index - 1) )
						{
							IPACMERR("DSCP value wrongly added, index = %d\n",(*map_index - 1));
							return IPACM_FAILURE;
						}
					}
				}
				else if (0 == IPACM_util_icmp_string((char*)xml_node->name, PCP_TAG))
				{
					/* Get the 8 bit PCP value and varify if value is between 0 to 7 */
					content = IPACM_read_content_element(xml_node);
					if (content)
					{
						str_size = strlen(content);
						memset(content_buf, 0, sizeof(content_buf));
						memcpy(content_buf, (void *)content, str_size);
						content_buf[MAX_XML_STR_LEN-1] = '\0';
						pcp_value = atoi(content_buf);
						if ((pcp_value > -1) && (pcp_value < 8) && (*map_index >= 1))
						{
							config->dscp_pcp_map[*map_index - 1] = (uint8_t) pcp_value;
						}
						else
						{
							IPACMERR("PCP value wrongly added, index = %d\n",(*map_index - 1));
							return IPACM_FAILURE;
						}
					}
				}
			}
		}
		/* go to sibling */
		xml_node = xml_node->next;
	}
	return ret_val;
}


/* This function read Config ext XML and populate the DSCP PCP Cfg */
int IPACM_read_cfg_ext_xml(char *xml_file, IPACM_dscp_pcp_conf_t *config)
{
	xmlDocPtr doc = NULL;
	xmlNode* root = NULL;
	int ret_val;
	int map_index;

	IPACM_ASSERT(xml_file != NULL);
	IPACM_ASSERT(config != NULL);

	/* invoke the XML parser and obtain the parse tree */
	doc = xmlReadFile(xml_file, "UTF-8", XML_PARSE_NOBLANKS);
	if (doc == NULL) {
		IPACMDBG_H("IPACM_xml_parse: libxml returned parse error\n");
		return IPACM_FAILURE;
	}
	/*get the root of the tree*/
	root = xmlDocGetRootElement(doc);

	/* parse the xml tree returned by libxml*/
	map_index = 0;
	ret_val = IPACM_cfg_ext_xml_parse_tree(root, config, &map_index);

	if (ret_val != IPACM_SUCCESS)
	{
		IPACMDBG_H("IPACM_xml_parse: IPACM_cfg_ext_xml_parse_tree returned parse error!\n");
	}

	/* free the tree */
	xmlFreeDoc(doc);

	return ret_val;
}
