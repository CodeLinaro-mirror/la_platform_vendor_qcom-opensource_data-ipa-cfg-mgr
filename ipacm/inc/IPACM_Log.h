/*
Copyright (c) 2013, 2019, 2021, The Linux Foundation. All rights reserved.

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
*/
/*!
	@file
	IPACM_log.h

	@brief
	This file implements the IPAM log functionality.

	@Author
	Skylar Chang

*/
#ifndef IPACM_LOG_H
#define IPACM_LOG_H
#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <syslog.h>
#include <sys/utsname.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>  // for PRIu64

#ifdef USE_DLT
#include <dlt/dlt.h>
	DLT_IMPORT_CONTEXT(ctx);
#endif

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define IPACM_LOG_MAX_BUF_LEN 288
#define IPACM_LOG_MAX_CORE_BUF_LEN 256
#define IPACM_LOG_TIMESTAMP_BUF_LEN 30
#define IPACM_DEF_LOG_LEVEL 8
#define IPACM_DEF_SYSLOG_LEVEL 7
#define IPACM_DEF_LOG_TIMESTAMP_ENABLE 1

#define IPACMLOG_BUF_SZ_AFTER_CRASH_STR 1000
#define IPACMLOG_RECENT_BUF_TO_SYNC 4096

#ifdef FEATURE_IPA_ANDROID
	#define IPACMLOG_FILE "/dev/socket/ipacm_log_file"
#else
	#define IPACMLOG_FILE "/dev/socket/data/ipa/ipacm_log_file"
	#define KERNEL_VER_FILE "/tmp/kernel_ver.txt"
#endif

#define IPACM_LOG_COLLECTION_FILE "/var/run/data/ipa/ipacm_log.txt"

#define KERNEL_VERSION_4_9 "4.9"
#define KERNEL_VERSION_LENGTH 16

typedef struct ipacm_log_file_metadata_s {
	long int write_addr;
} ipacm_log_file_metadata_t;

typedef struct ipacm_log_buffer_s {
	char user_data[IPACM_LOG_MAX_BUF_LEN];
} ipacm_log_buffer_t;

enum ipacm_log_level_t {
	IPACM_LOG_DISABLED = 0,
	IPACM_LOG_ERR      = 4,
	IPACM_LOG_WARN     = 6,
	IPACM_LOG_INFO     = 7,
	IPACM_LOG_DEBUG    = 8,
	IPACM_LOG_LVL_MAX  = 9
};

enum ipacm_syslog_level_t {
	IPACM_SYSLOG_DISABLED = 0,
	IPACM_SYSLOG_LVL_MAX  = 9
};
extern uint8_t ipacm_global_log_level;
extern uint8_t ipacm_global_syslog_level;
extern bool ipacm_global_log_timestamp_enable;

bool is_kernel_version_newer_than(char* version, const char* cmp_version);
void get_kernel_version(char* kernel_ver);

char* get_time_string(char* buffer, int TimeStamp_len);
void ipacm_send_log_to_qxdm(void* user_data);
void ipacm_send_log_to_file(char* ipacm_log_data);
void log_ipacm_crash_info(const char* crash_str);
int  log_init();
void log_deinit();

#ifdef USE_DLT
#define IPACM_DLT_LOG(level, msg) \
	DLT_LOG(ctx, (DltLogLevelType)(level), DLT_CSTRING(msg))
#else
#define IPACM_DLT_LOG(level, msg) \
	do { } while (0)
#endif

#define IPACM_LOG(incoming_log_level, fmt, ...) \
	do { \
		if ((incoming_log_level > ipacm_global_log_level) && (incoming_log_level > ipacm_global_syslog_level)) break; \
		char __ipacm_log_core_buf[IPACM_LOG_MAX_CORE_BUF_LEN]; \
		__ipacm_log_core_buf[0] = (char)('0' + (uint8_t)incoming_log_level); \
		snprintf(__ipacm_log_core_buf+1, IPACM_LOG_MAX_CORE_BUF_LEN-1 , "%s:%d %s() " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
		ipacm_send_log_to_qxdm(__ipacm_log_core_buf); \
		if (incoming_log_level <= ipacm_global_syslog_level) syslog(LOG_USER | incoming_log_level - 1, "%s", __ipacm_log_core_buf+1); \
		if (incoming_log_level <= ipacm_global_log_level) \
		{\
			char __ipacm_log_buffer_send[IPACM_LOG_MAX_BUF_LEN] = {0}; \
			if(ipacm_global_log_timestamp_enable){\
				char __ipacm_log_timestamp_buf[IPACM_LOG_TIMESTAMP_BUF_LEN] = {0}; \
				snprintf(__ipacm_log_buffer_send, IPACM_LOG_MAX_BUF_LEN, "%s %s", get_time_string(__ipacm_log_timestamp_buf, IPACM_LOG_TIMESTAMP_BUF_LEN), __ipacm_log_core_buf+1); \
			}\
			else {\
				snprintf(__ipacm_log_buffer_send, IPACM_LOG_MAX_BUF_LEN, " %s", __ipacm_log_core_buf+1); \
			}\
			printf("%s\n", __ipacm_log_buffer_send); \
			ipacm_send_log_to_file(__ipacm_log_buffer_send); \
			IPACM_DLT_LOG((incoming_log_level) + 2, __ipacm_log_buffer_send); \
		}\
	} while (0)

#define IPACM_LOG_PRINT_IN_PLACE(fmt, ...) \
	do { \
		char __ipacm_log_buffer_send[IPACM_LOG_MAX_BUF_LEN] = {0}; \
		printf(fmt, ##__VA_ARGS__); \
		if (ipacm_global_log_timestamp_enable) { \
			char __ipacm_log_timestamp_buf[IPACM_LOG_TIMESTAMP_BUF_LEN] = {0}; \
			snprintf(__ipacm_log_buffer_send, IPACM_LOG_MAX_BUF_LEN," %s %s:%d %s(): " fmt, get_time_string(__ipacm_log_timestamp_buf, IPACM_LOG_TIMESTAMP_BUF_LEN), __FILE__,  __LINE__, __FUNCTION__, ##__VA_ARGS__); \
		}\
		else {\
			snprintf(__ipacm_log_buffer_send, IPACM_LOG_MAX_BUF_LEN," %s:%d %s(): " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
		} \
		ipacm_send_log_to_file(__ipacm_log_buffer_send); \
		IPACM_DLT_LOG((IPACM_LOG_DEBUG) + 2, __ipacm_log_buffer_send); \
	} while (0);

#ifdef __cplusplus
}
#endif

#endif