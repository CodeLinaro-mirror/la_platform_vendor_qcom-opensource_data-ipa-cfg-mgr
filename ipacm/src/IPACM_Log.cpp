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

 * Changes from Qualcomm Innovation Center are provided under the following license:
 *
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
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
int max_filesize = 0;
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
        int ret = 0;
        int trunc_ret = -1;
        IPACM_Config* config;
        config = IPACM_Config::GetInstance();
        dump_file = IPACM_LOG_COLLECTION_FILE;

        if(max_filesize != config->max_file_size)
        {
            if(log_init_done)
            {
                FILE_LOCK();
                munmap(mmap_addr, max_filesize);
                close(log_fd);
                remove(dump_file);
                log_fd = -1;
                log_init_done = 0;
                FILE_UNLOCK();
            }

            max_filesize = config->max_file_size;
            if(0 == max_filesize)
            {
                printf("Logging disabled\n");
                return 0; // means disable logging
            }
        }
        else
        {
            return 0;
        }

        log_fd = open(dump_file, O_RDWR|O_CREAT|O_TRUNC, 0644);
        if (log_fd < 0) {
                perror("Logger file open failed :%s\n");
		return -errno;
	}

        trunc_ret = ftruncate(log_fd, max_filesize);
        if(0 > trunc_ret)
        {
		perror("Ftruncate failed\n");
		return -errno;
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

	write_addr = mmap_addr;
	memset(mmap_addr,' ', max_filesize);

	/* Now log init is complete */
	log_init_done = 1;
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
	input_len = strlen(ipacm_log_data) + 1;

        if(((char*)write_addr+input_len) > (char*)mmap_addr+ max_filesize)
	{
		write_addr = mmap_addr;
	}
	snprintf((char*)write_addr, input_len + 1, "%s\n", ipacm_log_data);
	write_addr = (char*)write_addr + (input_len - 1); //start of line
	FILE_UNLOCK();
}
