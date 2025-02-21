/*
Copyright (c) 2013,2019, 2021, The Linux Foundation. All rights reserved.

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
*
* Changes from Qualcomm Technologies, Inc. are provided under the following license:
* Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
* SPDX-License-Identifier: BSD-3-Clause-Clear.
*/
/*!
	@file
	IPACM_log.cpp

	@brief
	This file implements the IPAM log functionality.

	@Author
	Skylar Chang

*/
#include "IPACM_Log.h"
#include "IPACM_Config.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/if.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <IPACM_Defs.h>
#include <time.h>
#include <sys/time.h>
#include <sys/mman.h>

char* dump_file = 0;
void* mmap_addr = NULL;
void* write_addr = 0;
uint32_t max_filesize = 0;
int log_init_done = 0;
pthread_mutex_t file_lock;

#define FILE_LOCK()   \
    do \
    { \
        if(0 != pthread_mutex_lock(&file_lock)) \
        { \
                perror("File lock acquired failed\n"); \
		exit(EXIT_FAILURE); \
        }\
    } \
    while(0)

#define FILE_UNLOCK()   \
    do \
    { \
        if(0 != pthread_mutex_unlock(&file_lock)) \
        { \
                perror("File lock release failed\n"); \
                exit(EXIT_FAILURE);\
        }\
    } \
    while(0)

int log_fd = -1;
void logmessage(int log_level)
{
	return;
}
bool is_kernel_version_newer_than(
			char *version,
			const char *cmp_verison)
{
	char *ver = NULL, *cmp_ver = NULL;
	char *ptr1 = NULL, *ptr2 = NULL;
	char buff[KERNEL_VERSION_LENGTH];

	printf ("\n version %s cmp_verison = %s\n", version,
		cmp_verison);

	strlcpy(buff, cmp_verison, KERNEL_VERSION_LENGTH);
	ver = strtok_r(version,".", &ptr1);
	cmp_ver = strtok_r(buff,".", &ptr2);

	while ((ver != NULL) && (cmp_ver != NULL)) {
		if (atoi(ver) > atoi(cmp_ver))
			return true;
		else if (atoi(ver) < atoi(cmp_ver))
			return false;

		ver = strtok_r(NULL,".",&ptr1);
		cmp_ver = strtok_r(NULL,".",&ptr2);
	}

	if (cmp_ver == NULL)
		return true;
	else
		return false;
}
/* start IPACMDIAG socket*/
int create_socket(unsigned int *sockfd)
{

  if ((*sockfd = socket(AF_UNIX, SOCK_DGRAM, 0)) == IPACM_FAILURE)
  {
    perror("Error creating ipacm_log socket\n");
    return IPACM_FAILURE;
  }

  if(fcntl(*sockfd, F_SETFD, FD_CLOEXEC) < 0)
  {
    perror("Couldn't set ipacm_log Close on Exec\n");
  }

  return IPACM_SUCCESS;
}
void ipacm_log_send( void * user_data)
{
	ipacm_log_buffer_t ipacm_log_buffer;
	int numBytes=0, len;
	struct sockaddr_un ipacmlog_socket;
	static unsigned int ipacm_log_sockfd = 0;

	if(ipacm_log_sockfd == 0)
	{
		/* start ipacm_log socket */
		if(create_socket(&ipacm_log_sockfd) < 0)
		{
			printf("unable to create ipacm_log socket\n");
			return;
		}
		printf("create ipacm_log socket successfully\n");
	}
	ipacmlog_socket.sun_family = AF_UNIX;
	strlcpy(ipacmlog_socket.sun_path, IPACMLOG_FILE,sizeof(ipacmlog_socket.sun_path));
	len = strlen(ipacmlog_socket.sun_path) + sizeof(ipacmlog_socket.sun_family);

	memcpy(ipacm_log_buffer.user_data, user_data, MAX_BUF_LEN);

        if ((numBytes = sendto(ipacm_log_sockfd, (void *)&ipacm_log_buffer, sizeof(ipacm_log_buffer.user_data), 0,
			(struct sockaddr *)&ipacmlog_socket, len)) == -1)
	{
		printf("Send Failed(%d) %s \n",errno,strerror(errno));
		return;
	}
	return;
}
char *get_time_string(char *buffer, int len)
{
   struct timeval tv;
   struct tm *tm;
   unsigned long long milliseconds = 0;
   char timestamp_buf[TimeStamp_buff_len];

   if (!buffer || len <= 0)
     return NULL;

   gettimeofday(&tv, NULL);
   tm = localtime(&tv.tv_sec);

   if (!tm)
     return NULL;

   milliseconds = (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);

   strftime(timestamp_buf, 30, "%H:%M:%S", tm);
   snprintf(buffer, len, "%s%lld", timestamp_buf, milliseconds);

   return buffer;
}
/* IPACM logging initilation*/
int log_init() {
	int flags = 0;
	int trunc_ret = -1;
	IPACM_Config* config;
	struct stat st = {0};
	bool is_exist = false;
	config = IPACM_Config::GetInstance();
	dump_file = IPACM_LOG_COLLECTION_FILE;
	ipacm_log_file_metadata_t metadata;

	memset(&metadata, '\0', sizeof(ipacm_log_file_metadata_t));
	if(log_init_done)
	{
		printf("Logging already initiated, return\n");
		return 0;
	}

	if(access(dump_file, F_OK) == 0)
	{
		flags = O_RDWR;
		is_exist = true;
		stat(dump_file, &st);
		max_filesize = st.st_size;
	}
	else
	{
		flags = O_RDWR|O_CREAT|O_TRUNC;
		max_filesize = config->max_file_size;
	}
	if(0 == max_filesize)
	{
		printf("Logging disabled\n");
		return 0; // means disable logging
	}

	log_fd = open(dump_file, flags, 0644);
	if (log_fd < 0) {
		perror("Logger file open failed :%s\n");
		return -errno;
	}
	if(is_exist == false)
	{
		trunc_ret = ftruncate(log_fd, max_filesize);
		if(0 > trunc_ret)
		{
			perror("Ftruncate failed\n");
			return -errno;
		}
	}

	if(pthread_mutex_init(&file_lock, NULL) != 0)
	{
		perror("\n mutex init has failed\n");
		return -errno;
	}

	mmap_addr = mmap(NULL, max_filesize, PROT_READ|PROT_WRITE, MAP_SHARED, log_fd, 0);

	if((void*)-1 == mmap_addr || NULL == mmap_addr)
	{
		perror("Mmap failed\n");
		return -errno;
	}

	if(is_exist == false)
	{
		write_addr = mmap_addr + (sizeof(ipacm_log_file_metadata_t) + 1);
		memset(mmap_addr,' ', max_filesize);

		/* Adding a separator between metadata and the actual logs */
		*((char *)mmap_addr + sizeof(ipacm_log_file_metadata_t)) = '|';
	}
	else
	{
		memcpy(&metadata, mmap_addr, sizeof(ipacm_log_file_metadata_t));
		write_addr = mmap_addr + metadata.write_addr;
		if(write_addr > (mmap_addr + max_filesize))
		{
			write_addr = mmap_addr + (sizeof(ipacm_log_file_metadata_t) + 1);
		}
	}

	/* Now log init is complete */
	log_init_done = 1;

	IPACMDBG_H("\nFound offset: %ld, mmap_addr[%p], write_addr[%p], sizeof(metadata)[%d]. \n",
			metadata.write_addr, mmap_addr, write_addr, sizeof(ipacm_log_file_metadata_t));

	return 0;
}
void ipacm_log_dump(char* ipacm_log_data)
{
	int input_len = 0;
	if(!log_init_done)
	{
		return;
	}
	FILE_LOCK();
	/* Adding +1 to incorporate null character */
	input_len = strlen(ipacm_log_data) + 1;

	if(((char*)write_addr+input_len) > (char*)mmap_addr + max_filesize - 1)
	{
		write_addr = mmap_addr + (sizeof(ipacm_log_file_metadata_t) + 1);
	}
	snprintf((char*)write_addr, input_len, "%s", ipacm_log_data);
	write_addr = (char*)write_addr + (input_len - 1); //start of line
	FILE_UNLOCK();
}

void log_ipacm_crash_info(const char *crash_str)
{
    int size = 0;
    long bytes_written = 0;
    void *addr_to_sync = NULL;
    ipacm_log_file_metadata_t metadata;

    if(log_init_done)
    {
        FILE_LOCK();
        /* Write the crash string to the log file */
        if(((char*)write_addr + (strlen(crash_str) + 2)) > (char*)mmap_addr + max_filesize)
        {
            write_addr = mmap_addr + (sizeof(ipacm_log_file_metadata_t) + 1);
        }
        snprintf((char*)write_addr, strlen(crash_str) + 2, "%s\n",crash_str);
        write_addr += strlen(crash_str) + 2;

        /* Save the offset by adding IPACMLOG_BUF_SZ_AFTER_CRASH_STR to the current
         * offset as the trace logs will follow post this crash str.
         * If not done, those will get overwritten
         */
        bytes_written = (long)((char *)write_addr - (char *)mmap_addr +
				IPACMLOG_BUF_SZ_AFTER_CRASH_STR);

        metadata.write_addr = bytes_written;

        /* First, calculate the size of data that will be written to the file.
         * Since it is required by snprintf()
         */
        size = snprintf(NULL, 0, "saving offset: %ld, write_addr[%p], mmap_addr[%p]..... \n",
                bytes_written, write_addr, mmap_addr);

        if(((char*)write_addr + (size + 1)) > (char*)mmap_addr + max_filesize)
        {
            write_addr = mmap_addr + (sizeof(ipacm_log_file_metadata_t) + 1);
        }
        size = snprintf((char*)write_addr, size + 1,
                "saving offset: %ld, write_addr[%p], mmap_addr[%p]..... \n",
                bytes_written, write_addr, mmap_addr);

        write_addr += size;

        memcpy((char *)mmap_addr, &metadata, sizeof(ipacm_log_file_metadata_t));
        /* Adding a separator between metadata and the actual logs */
        *((char*)(mmap_addr) + sizeof(ipacm_log_file_metadata_t)) = '|';

        addr_to_sync = (void *)((((long)(write_addr) - IPACMLOG_RECENT_BUF_TO_SYNC) <
                    (long)mmap_addr) ? (long)mmap_addr :
                    ((long)(write_addr) - IPACMLOG_RECENT_BUF_TO_SYNC));

        /* sync recent IPACMLOG_RECENT_BUF_TO_SYNC bytes to file, considering that the previous
		 * data is already synced.
		 */
        if (msync(addr_to_sync, ((long)write_addr - (long)addr_to_sync), MS_SYNC) == -1) {
            perror("msync");
        }


        /* sync sizeof(ipacm_log_file_metadata_t + 1) Bytes METADATA if not already*/
        if(addr_to_sync != mmap_addr)
        {
            if (msync(mmap_addr, (sizeof(ipacm_log_file_metadata_t) + 1), MS_SYNC) == -1) {
                perror("msync");
            }
        }
        FILE_UNLOCK();
    }
}
