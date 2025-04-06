/*
 * Copyright (c) 2013 - 2019 The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *  * Neither the name of The Linux Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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
 */

#ifndef IPACM_CONNTRACK_LISTENER
#define IPACM_CONNTRACK_LISTENER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>

#include "IPACM_CmdQueue.h"
#include "IPACM_Conntrack_NATApp.h"
#include "IPACM_Listener.h"
#ifdef CT_OPT
#include "IPACM_LanToLan.h"
#endif

#define MAX_IFACE_ADDRESS 50
#define MAX_STA_CLNT_IFACES 10
#define STA_CLNT_SUBNET_MASK 0xFFFFFF00

using namespace std;

typedef struct _nat_entry_bundle
{
	struct nf_conntrack *ct;
	enum nf_conntrack_msg_type type;
	nat_table_entry *rule;
	bool isTempEntry;
#ifdef FEATURE_VLAN_MPDN
	bool isVlan;
	bool IsVlanUp;
#endif
}nat_entry_bundle;

typedef struct __nat_client_info
{
	uint32_t nat_iface_ipv4_addr;
#ifdef FEATURE_VLAN_MPDN
	bool is_vlan_client;
	uint16_t vlan_id;
#endif
}nat_client_info;

typedef struct __nat_client_v6_info
{
	uint32_t nat_iface_ipv6_addr[4];
#ifdef FEATURE_VLAN_MPDN
	bool is_vlan_client;
	uint16_t vlan_id;
#endif
}nat_client_v6_info;

#ifdef FEATURE_VLAN_MPDN
typedef struct _nat_pdn_entry
{
	uint32_t public_ip;
	uint16_t associated_VIDs[IPA_MAX_NUM_SW_PDNS];
	uint8_t VID_cnt;
	uint8_t ip_pass_enable;
	uint32_t ip_pass_dummy_ip;
	uint8_t ip_pass_skip_nat;
}nat_pdn_entry;

typedef struct _ct_pdn_entry
{
	uint32_t ipv6_prefix[2];
	uint16_t associated_VIDs[IPA_MAX_NUM_SW_PDNS];
	uint8_t VID_cnt;
}ct_pdn_entry;

#endif

class IPACM_ConntrackListener : public IPACM_Listener
{

private:
	bool isCTReg;
	bool isNatThreadStart;
	bool WanUp;
	uint8_t ip_pass_enable_default_pdn;
	uint32_t ip_pass_dummy_ip_default_pdn;
	uint8_t ip_pass_skip_nat_default_pdn;
	bool WanUp_v6;
	bool is_acct_enabled;
	NatApp *nat_inst;
	NatBase *ipv6ct_inst;

	int NatIfaceCnt;
	int StaClntCnt;
	int StaClntCnt_v6;
	uint32_t pkt_threshld;
	NatIfaces *pNatIfaces;
	nat_client_info nat_clients[MAX_IFACE_ADDRESS];
	nat_client_v6_info nat_clients_v6[MAX_IFACE_ADDRESS];
	IpAddressesCollectionBase& nat_iface_ipv6_addr;
#ifdef FEATURE_VLAN_MPDN
	nat_pdn_entry vlan_pdns[IPA_MAX_NUM_HW_PDNS];
	int num_vlan_pdns;
	ct_pdn_entry v6_vlan_pdns[IPA_MAX_NUM_HW_PDNS];
	int num_v6_vlan_pdns;
#endif
	uint32_t nonnat_iface_ipv4_addr[MAX_IFACE_ADDRESS];
	IpAddressesCollectionBase& nonnat_iface_ipv6_addr;
	uint32_t sta_clnt_ipv4_addr[MAX_STA_CLNT_IFACES];
	IpAddressesCollectionBase& sta_clnt_ipv6_addr;
	IPACM_Config *pConfig;
#ifdef CT_OPT
	IPACM_LanToLan *p_lan2lan;
#endif

	void ProcessCTMessage(void *);
	void ProcessCTMessage_v6(const ipacm_ct_evt_data* evt_data, NatEntryBase& entry);
#if defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
	void ProcessSocksv5Conn(ipa_socksv5_msg *socksv5_info, bool is_add);
	void PostRouteAddVlanPdn(uint32_t public_ip);
	void PostSocksv5Ready(ipa_socksv5_msg* data_evt_conn);
#endif //defined(FEATURE_SOCKSv5) && defined (IPA_SOCKV5_EVENT_MAX)
	void ProcessTCPorUDPMsg(struct nf_conntrack *,
		enum nf_conntrack_msg_type, u_int8_t);
	void ProcessTCPorUDPMsg_v6(const ipacm_ct_evt_data* evt_data, NatEntryBase& entry);
	void CreateIpv6ctEntryFromCtEventData(const ipacm_ct_evt_data* evt_data, Ipv6ctEntry& entry) const;
#ifdef FEATURE_IPV6_NAT
	void CreateIpv6NatEntryFromCtEventData(const ipacm_ct_evt_data* evt_data, Ipv6NatEntry& entry) const;
#endif
#ifdef FEATURE_VLAN_MPDN
	void HandleVlanUp(void *);
	void HandleVlanDown(void *);
	void HandleVlanUpV6(void *);
        void HandleVlanDownV6(void *);
#endif
	void TriggerWANUp(void *);
	void TriggerWANUp_v6(const ipacm_event_iface_up* evt_data);
	void TriggerWANDown(uint32_t);
	void TriggerWANDown_v6(const uint32_t* wan_addr);
	int  CreateNatThreads(void);
	bool AddIface(nat_table_entry *, bool *, bool IsVlanUp,
  		 uint8_t ip_pass_enable, uint32_t ip_pass_dummy_ip, uint8_t ip_pass_skip_nat);
	int AddORDeleteNatEntry(const nat_entry_bundle *, bool *sendVlanEvent);
	int AddORDeleteNatEntry_v6(const ipacm_ct_evt_data* evt_data, const NatEntryBase& entry, bool isTempEntry, bool *sendVlanEvent);
	void PopulateTCPorUDPEntry(struct nf_conntrack *, uint32_t, nat_table_entry *);
	void CheckSTAClient(const nat_table_entry *rule, bool *isTempEntry);
	void CheckSTAClient_v6(const NatEntryBase& entry, bool& isTempEntry);
	int CheckNatIface(int if_index, bool *NatIface);
	void HandleNonNatIPAddr(void *, bool);
	void HandleNonNatIPAddr_v4(void* inParam, bool AddOp);
	void HandleNonNatIPAddr_v6(const IpAddress& ip, int if_index, bool AddOp);
	uint32_t GetPacketThreshhold(void);
	bool IsIpv6PrivateSubnet(const IpAddress& ip);

#ifdef CT_OPT
	void ProcessCTV6Message(void *);
	void HandleLan2Lan(struct nf_conntrack *,
		enum nf_conntrack_msg_type, nat_table_entry* );
#endif
#ifdef IPA_L2TP_TUNNEL_UDP
	void Handlel2tpVlanDown(void *);
#endif
	bool IsIpv6CTEnabled() const
	{
		return ipv6ct_inst != NULL;
	}

public:
	char wan_ifname[IPA_IFACE_NAME_LEN];
	uint32_t wan_ipaddr;
	IpAddress& wan_ipaddr_v6;
	bool isStaMode;
	IPACM_ConntrackListener();
	~IPACM_ConntrackListener();
	void event_callback(ipa_cm_event_id, void *data);
	int  CreateConnTrackThreads(void);

	void HandleNeighIpAddrAddEvt(ipacm_event_data_all *);
	void HandleNeighIpAddrAddEvt_v6(ipacm_event_data_all *);
	void HandleNeighIpAddrDelEvt(uint32_t);
	void HandleNeighIpAddrDelEvt_v6(const Ipv6IpAddress& ip);
	void HandleSTAClientAddEvt(uint32_t);
	void HandleSTAClientAddEvt_v6(const IpAddress& ip);
	void HandleSTAClientDelEvt(uint32_t);
	void HandleSTAClientDelEvt_v6(const IpAddress& ip);
	void ReadNfConntrackAcct();
	void HandleIPPassPDNInfoUpdate(void *in_param);
#ifdef FEATURE_VLAN_MPDN
	bool IsVlanIPv4(uint32_t ipv4_address, uint16_t *VlanId);
#endif
	bool IsVlanIPv6(const Ipv6IpAddress& ip, uint16_t *VlanId);
	void query_conntracks(int af_family, uint32_t ipv4_addr, uint32_t *ipv6_addr);
};

extern IPACM_ConntrackListener *CtList;

#endif /* IPACM_CONNTRACK_LISTENER */
