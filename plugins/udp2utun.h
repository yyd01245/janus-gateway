#pragma once

#include <arpa/inet.h>
#include <glib.h>
#include <stdio.h>   //printf
#include <stdlib.h>  //exit(0);
#include <string.h>  //memset
#include <sys/socket.h>

#include "../mutex.h"
#include "plugin.h"

typedef struct udp_handle {
  struct sockaddr_in remote_addr;
  int slen;

  // int remote_socket_id;
  int local_socket_id;
  janus_plugin_session *plugin_session;
  GThread *recv_thread;

} udp_handle;

udp_handle *init_udp_handle(const char *remote_ip,
                            const unsigned int remote_port,
                            const unsigned int local_port);
int udp_close(udp_handle *handle);
void udp_free(udp_handle *handle);
int udp_send_handle(udp_handle *handle, char *buf, int len);

void utun_incoming_rtcp(janus_plugin_session *handle, int video, char *buf,
                        int len);
void utun_incoming_rtp(janus_plugin_session *handle, int video, char *buf,
                       int len);
