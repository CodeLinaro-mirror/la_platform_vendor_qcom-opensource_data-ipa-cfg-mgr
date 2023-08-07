/*!
@file    IPACM_Bridge.h
@brief   This file implements bridge interface related handlers

DESCRIPTION
Header file for bridge interface handling for IPA.

Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause-Clear
*/


#ifndef IPACM_BRIDGE_H
#define IPACM_BRIDGE_H

#include <stdio.h>
#include <IPACM_Config.h>
#include <IPACM_Iface.h>
class IPACM_Bridge : public IPACM_Listener
{
		uint32_t  bridge_ipv4_addr;
public:
		IPACM_Bridge();
		void event_callback(ipa_cm_event_id event, void *data);
};
#endif /* IPACM_BRIDGE_H */
