/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2019.  ALL RIGHTS RESERVED.
 * Copyright (c) 2019, NVIDIA CORPORATION. All rights reserved.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "tcp.h"
#include <ifaddrs.h>

#include <ucs/async/async.h>
#include <ucs/sys/string.h>
#include <ucs/config/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/tcp.h>
#include <dirent.h>


extern ucs_class_t UCS_CLASS_DECL_NAME(uct_tcp_iface_t);

static ucs_config_field_t uct_tcp_iface_config_table[] = {
  {"", "MAX_NUM_EPS=256", NULL,
   ucs_offsetof(uct_tcp_iface_config_t, super),
   UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},

  {"TX_SEG_SIZE", "8kb",
   "Size of send copy-out buffer",
   ucs_offsetof(uct_tcp_iface_config_t, tx_seg_size), UCS_CONFIG_TYPE_MEMUNITS},
  
  {"RX_SEG_SIZE", "64kb",
   "Size of receive copy-out buffer",
   ucs_offsetof(uct_tcp_iface_config_t, rx_seg_size), UCS_CONFIG_TYPE_MEMUNITS},

  {"MAX_IOV", "6",
   "Maximum IOV count that can contain user-defined payload in a single\n"
   "call to non-blocking vector socket send",
   ucs_offsetof(uct_tcp_iface_config_t, max_iov), UCS_CONFIG_TYPE_ULONG},

  {"SENDV_THRESH", "2kb",
   "Threshold for switching from send() to sendmsg() for short active messages",
   ucs_offsetof(uct_tcp_iface_config_t, sendv_thresh), UCS_CONFIG_TYPE_MEMUNITS},

  {"PREFER_DEFAULT", "y",
   "Give higher priority to the default network interface on the host",
   ucs_offsetof(uct_tcp_iface_config_t, prefer_default), UCS_CONFIG_TYPE_BOOL},

  {"PUT_ENABLE", "y",
   "Enable PUT Zcopy support",
   ucs_offsetof(uct_tcp_iface_config_t, put_enable), UCS_CONFIG_TYPE_BOOL},

  {"CONN_NB", "n",
   "Enable non-blocking connection establishment. It may improve startup "
   "time, but can lead to connection resets due to high load on TCP/IP stack",
   ucs_offsetof(uct_tcp_iface_config_t, conn_nb), UCS_CONFIG_TYPE_BOOL},

  {"MAX_POLL", UCS_PP_MAKE_STRING(UCT_TCP_MAX_EVENTS),
   "Number of times to poll on a ready socket. 0 - no polling, -1 - until drained",
   ucs_offsetof(uct_tcp_iface_config_t, max_poll), UCS_CONFIG_TYPE_UINT},

  {UCT_TCP_CONFIG_MAX_CONN_RETRIES, "25",
   "How many connection establishment attempts should be done if dropped "
   "connection was detected due to lack of system resources",
   ucs_offsetof(uct_tcp_iface_config_t, max_conn_retries), UCS_CONFIG_TYPE_UINT},

  {"NODELAY", "y",
   "Set TCP_NODELAY socket option to disable Nagle algorithm. Setting this\n"
   "option usually provides better performance",
   ucs_offsetof(uct_tcp_iface_config_t, sockopt_nodelay), UCS_CONFIG_TYPE_BOOL},

  UCT_TCP_SEND_RECV_BUF_FIELDS(ucs_offsetof(uct_tcp_iface_config_t, sockopt)),

  UCT_TCP_SYN_CNT(ucs_offsetof(uct_tcp_iface_config_t, syn_cnt)),

  UCT_IFACE_MPOOL_CONFIG_FIELDS("TX_", -1, 8, "send",
                                ucs_offsetof(uct_tcp_iface_config_t, tx_mpool), ""),

  UCT_IFACE_MPOOL_CONFIG_FIELDS("RX_", -1, 8, "receive",
                                ucs_offsetof(uct_tcp_iface_config_t, rx_mpool), ""),

  {NULL}
};


static UCS_CLASS_DEFINE_DELETE_FUNC(uct_tcp_iface_t, uct_iface_t);

static ucs_status_t uct_tcp_iface_get_device_address(uct_iface_h tl_iface,
                                                     uct_device_addr_t *addr)
{
    uct_tcp_iface_t *iface = ucs_derived_of(tl_iface, uct_tcp_iface_t);
    ucs_info("uct_tcp_iface_get_device_address family %d", iface->config.ifaddr.ss_family);
    char dest_str[UCS_SOCKADDR_STRING_LEN];

    if (iface->config.ifaddr.ss_family == AF_INET) {
        *(struct in_addr*)addr = ((struct sockaddr_in *)(&iface->config.ifaddr))->sin_addr;

    } else if (iface->config.ifaddr.ss_family == AF_INET6) {
        *(struct in6_addr*)addr = ((struct sockaddr_in6 *)(&iface->config.ifaddr))->sin6_addr;
    } else {
        ucs_error("tcp_iface: unknown iface family=%d", iface->config.ifaddr.ss_family);
        return UCS_ERR_IO_ERROR;
    }
    
    ucs_info("uct_tcp_iface_get_device_address(dest_addr=%s)",
                      ucs_sockaddr_str((const struct sockaddr *)(&iface->config.ifaddr), dest_str,
                                       UCS_SOCKADDR_STRING_LEN));

    return UCS_OK;
}



static ucs_status_t uct_tcp_iface_get_address(uct_iface_h tl_iface, uct_iface_addr_t *addr)
{
    uct_tcp_iface_t *iface = ucs_derived_of(tl_iface, uct_tcp_iface_t);

    struct port_scope_id {
        sa_family_t ss_family;
        in_port_t   sin_port;
        uint32_t    sin_scope_id;
    };
    char dest_str[UCS_SOCKADDR_STRING_LEN];
        ucs_info("uct_tcp_iface_get_address(dest_addr=%s)",
                      ucs_sockaddr_str((const struct sockaddr *)(&iface->config.ifaddr), dest_str,
                                       UCS_SOCKADDR_STRING_LEN));
    
    ucs_info("uct_tcp_iface_get_address family %d", iface->config.ifaddr.ss_family);
    if (iface->config.ifaddr.ss_family == AF_INET) {
        ((struct port_scope_id*)addr)->ss_family    = AF_INET;
        ((struct port_scope_id*)addr)->sin_port     = ((struct sockaddr_in *)(&iface->config.ifaddr))->sin_port;
    } else if (iface->config.ifaddr.ss_family == AF_INET6) {
        ((struct port_scope_id*)addr)->ss_family    = AF_INET6;
        ((struct port_scope_id*)addr)->sin_port     = ((struct sockaddr_in6 *)(&iface->config.ifaddr))->sin6_port;
        ((struct port_scope_id*)addr)->sin_scope_id = ((struct sockaddr_in6 *)(&iface->config.ifaddr))->sin6_scope_id;
        //ucs_info("uct_tcp_iface_get_address sin6_scope_id: %d", ((struct port_scope_id*)addr)->sin_scope_id);
    } else {
        ucs_error("tcp_iface: unknown iface family=%d", iface->config.ifaddr.ss_family);
        return UCS_ERR_IO_ERROR;
    }
    return UCS_OK;
}

static int uct_tcp_iface_is_reachable(const uct_iface_h tl_iface,
                                      const uct_device_addr_t *dev_addr,
                                      const uct_iface_addr_t *iface_addr)
{
    /* We always report that a peer is reachable. connect() call will
     * fail if the peer is unreachable when creating UCT/TCP EP */
    return 1;
}

static ucs_status_t uct_tcp_iface_query(uct_iface_h tl_iface, uct_iface_attr_t *attr)
{
    uct_tcp_iface_t *iface = ucs_derived_of(tl_iface, uct_tcp_iface_t);
    size_t am_buf_size     = iface->config.tx_seg_size - sizeof(uct_tcp_am_hdr_t);
    ucs_status_t status;
    int is_default;

    uct_base_iface_query(&iface->super, attr);

    status = uct_tcp_netif_caps(iface->if_name, &attr->latency.c,
                                &attr->bandwidth.shared);
    if (status != UCS_OK) {
        return status;
    }
    struct port_scope_id {
        sa_family_t ss_family;
        in_port_t   sin_port;
        uint32_t    sin_scope_id;
    };

    
    if (iface->config.ifaddr.ss_family == AF_INET6) {
        ucs_info("tcp_iface: iface family=%d", iface->config.ifaddr.ss_family);
        attr->iface_addr_len   = sizeof(struct port_scope_id);
        attr->device_addr_len  = sizeof(struct in6_addr);
    } else if (iface->config.ifaddr.ss_family == AF_INET) {
        ucs_info("tcp_iface: iface family=%d", iface->config.ifaddr.ss_family);
        attr->iface_addr_len   = sizeof(struct port_scope_id);
        attr->device_addr_len  = sizeof(struct in_addr);
    } else {
        ucs_error("tcp_iface: unknown iface family=%d", iface->config.ifaddr.ss_family);
        return UCS_ERR_IO_ERROR;
    }

    
    attr->cap.flags        = UCT_IFACE_FLAG_CONNECT_TO_IFACE |
                             UCT_IFACE_FLAG_AM_SHORT         |
                             UCT_IFACE_FLAG_AM_BCOPY         |
                             UCT_IFACE_FLAG_PENDING          |
                             UCT_IFACE_FLAG_CB_SYNC;
    attr->cap.event_flags  = UCT_IFACE_FLAG_EVENT_SEND_COMP |
                             UCT_IFACE_FLAG_EVENT_RECV      |
                             UCT_IFACE_FLAG_EVENT_FD;

    attr->cap.am.max_short = am_buf_size;
    attr->cap.am.max_bcopy = am_buf_size;

    if (iface->config.zcopy.max_iov > UCT_TCP_EP_ZCOPY_SERVICE_IOV_COUNT) {
        /* AM */
        attr->cap.am.max_iov          = iface->config.zcopy.max_iov -
                                        UCT_TCP_EP_ZCOPY_SERVICE_IOV_COUNT;
        attr->cap.am.max_zcopy        = iface->config.rx_seg_size -
                                        sizeof(uct_tcp_am_hdr_t);
        attr->cap.am.max_hdr          = iface->config.zcopy.max_hdr;
        attr->cap.am.opt_zcopy_align  = 1;
        attr->cap.flags              |= UCT_IFACE_FLAG_AM_ZCOPY;

        if (iface->config.put_enable) {
            /* PUT */
            attr->cap.put.max_iov          = iface->config.zcopy.max_iov -
                                             UCT_TCP_EP_ZCOPY_SERVICE_IOV_COUNT;
            attr->cap.put.max_zcopy        = UCT_TCP_EP_PUT_ZCOPY_MAX -
                                             UCT_TCP_EP_PUT_SERVICE_LENGTH;
            attr->cap.put.opt_zcopy_align  = 1;
            attr->cap.flags               |= UCT_IFACE_FLAG_PUT_ZCOPY;
        }
    }

    attr->bandwidth.dedicated = 0;
    attr->latency.m           = 0;
    attr->overhead            = 50e-6;  /* 50 usec */

    if (iface->config.prefer_default) {
        status = uct_tcp_netif_is_default(iface->if_name, &is_default);
        if (status != UCS_OK) {
             return status;
        }

        attr->priority    = is_default ? 0 : 1;
    } else {
        attr->priority    = 0;
    }

    return UCS_OK;
}

static ucs_status_t uct_tcp_iface_event_fd_get(uct_iface_h tl_iface, int *fd_p)
{
    uct_tcp_iface_t *iface = ucs_derived_of(tl_iface, uct_tcp_iface_t);

    return ucs_event_set_fd_get(iface->event_set, fd_p);
}

static void uct_tcp_iface_handle_events(void *callback_data,
                                        int events, void *arg)
{
    unsigned *count  = (unsigned*)arg;
    uct_tcp_ep_t *ep = (uct_tcp_ep_t*)callback_data;

    ucs_assertv(ep->conn_state != UCT_TCP_EP_CONN_STATE_CLOSED, "ep=%p", ep);

    if (events & UCS_EVENT_SET_EVREAD) {
        *count += uct_tcp_ep_cm_state[ep->conn_state].rx_progress(ep);
    }
    if (events & UCS_EVENT_SET_EVWRITE) {
        *count += uct_tcp_ep_cm_state[ep->conn_state].tx_progress(ep);
    }
}

unsigned uct_tcp_iface_progress(uct_iface_h tl_iface)
{
    uct_tcp_iface_t *iface = ucs_derived_of(tl_iface, uct_tcp_iface_t);
    unsigned max_events    = iface->config.max_poll;
    unsigned count         = 0;
    unsigned read_events;
    ucs_status_t status;

    do {
        read_events = ucs_min(ucs_sys_event_set_max_wait_events, max_events);
        status = ucs_event_set_wait(iface->event_set, &read_events,
                                    0, uct_tcp_iface_handle_events,
                                    (void *)&count);
        max_events -= read_events;
        ucs_trace_poll("iface=%p ucs_event_set_wait() returned %d: "
                       "read events=%u, total=%u",
                       iface, status, read_events,
                       iface->config.max_poll - max_events);
    } while ((max_events > 0) && (read_events == UCT_TCP_MAX_EVENTS) &&
             ((status == UCS_OK) || (status == UCS_INPROGRESS)));

    return count;
}

static ucs_status_t uct_tcp_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                        uct_completion_t *comp)
{
    uct_tcp_iface_t *iface = ucs_derived_of(tl_iface, uct_tcp_iface_t);

    if (comp != NULL) {
        return UCS_ERR_UNSUPPORTED;
    }

    if (iface->outstanding) {
        UCT_TL_IFACE_STAT_FLUSH_WAIT(&iface->super);
        return UCS_INPROGRESS;
    }

    UCT_TL_IFACE_STAT_FLUSH(&iface->super);
    return UCS_OK;
}

static void uct_tcp_iface_listen_close(uct_tcp_iface_t *iface)
{
    if (iface->listen_fd != -1) {
        close(iface->listen_fd);
        iface->listen_fd = -1;
    }
}

static void uct_tcp_iface_connect_handler(int listen_fd, int events, void *arg)
{
    uct_tcp_iface_t *iface = arg;
    struct sockaddr_storage peer_addr;
    socklen_t addrlen;
    ucs_status_t status;
    int fd;

    ucs_assert(listen_fd == iface->listen_fd);

    for (;;) {
        addrlen = sizeof(peer_addr);
        status  = ucs_socket_accept(iface->listen_fd, (struct sockaddr*)&peer_addr,
                                    &addrlen, &fd);
        if (status != UCS_OK) {
            if (status != UCS_ERR_NO_PROGRESS) {
                uct_tcp_iface_listen_close(iface);
            }
            return;
        }
        ucs_assert(fd != -1);

        status = uct_tcp_cm_handle_incoming_conn(iface, &peer_addr, fd);
        if (status != UCS_OK) {
            close(fd);
            return;
        }
    }
}

ucs_status_t uct_tcp_iface_set_sockopt(uct_tcp_iface_t *iface, int fd)
{
    ucs_status_t status;

    status = ucs_socket_setopt(fd, IPPROTO_TCP, TCP_NODELAY,
                               (const void*)&iface->sockopt.nodelay,
                               sizeof(int));
    if (status != UCS_OK) {
        return status;
    }

    status = ucs_socket_set_buffer_size(fd, iface->sockopt.sndbuf,
                                        iface->sockopt.rcvbuf);
    if (status != UCS_OK) {
        return status;
    }

    return ucs_tcp_base_set_syn_cnt(fd, iface->config.syn_cnt);
}

static uct_iface_ops_t uct_tcp_iface_ops = {
    .ep_am_short              = uct_tcp_ep_am_short,
    .ep_am_bcopy              = uct_tcp_ep_am_bcopy,
    .ep_am_zcopy              = uct_tcp_ep_am_zcopy,
    .ep_put_zcopy             = uct_tcp_ep_put_zcopy,
    .ep_pending_add           = uct_tcp_ep_pending_add,
    .ep_pending_purge         = uct_tcp_ep_pending_purge,
    .ep_flush                 = uct_tcp_ep_flush,
    .ep_fence                 = uct_base_ep_fence,
    .ep_create                = uct_tcp_ep_create,
    .ep_destroy               = uct_tcp_ep_destroy,
    .iface_flush              = uct_tcp_iface_flush,
    .iface_fence              = uct_base_iface_fence,
    .iface_progress_enable    = uct_base_iface_progress_enable,
    .iface_progress_disable   = uct_base_iface_progress_disable,
    .iface_progress           = uct_tcp_iface_progress,
    .iface_event_fd_get       = uct_tcp_iface_event_fd_get,
    .iface_event_arm          = ucs_empty_function_return_success,
    .iface_close              = UCS_CLASS_DELETE_FUNC_NAME(uct_tcp_iface_t),
    .iface_query              = uct_tcp_iface_query,
    .iface_get_address        = uct_tcp_iface_get_address,
    .iface_get_device_address = uct_tcp_iface_get_device_address,
    .iface_is_reachable       = uct_tcp_iface_is_reachable
};

static ucs_status_t uct_tcp_iface_listener_init(uct_tcp_iface_t *iface)
{
    struct sockaddr_storage bind_addr = iface->config.ifaddr;
    socklen_t socklen;
    char ip_port_str[UCS_SOCKADDR_STRING_LEN];
    ucs_status_t status;
    int ret;

    if (bind_addr.ss_family == AF_INET) {
        socklen = sizeof(struct sockaddr_in);
        ((struct sockaddr_in*)(&bind_addr))->sin_port = 0;     /* use a random port */
    } else if (bind_addr.ss_family == AF_INET6) {
        socklen = sizeof(struct sockaddr_in6);
        ((struct sockaddr_in6*)(&bind_addr))->sin6_port = 0;     /* use a random port */
    } else {
        ucs_error("tcp_iface: unknown iface family=%d", iface->config.ifaddr.ss_family);
        return UCS_ERR_IO_ERROR;
    }

    status = ucs_socket_server_init((struct sockaddr *)&bind_addr,
                                    sizeof(bind_addr), ucs_socket_max_conn(),
                                    &iface->listen_fd);
    if (status != UCS_OK) {
        goto err;
    }

    /* Get the port which was selected for the socket */
    ret = getsockname(iface->listen_fd, (struct sockaddr *)&bind_addr, &socklen);
    if (ret < 0) {
        ucs_error("getsockname(fd=%d) failed: %m", iface->listen_fd);
        status = UCS_ERR_IO_ERROR;
        goto err_close_sock;
    }

    if (bind_addr.ss_family == AF_INET) {
        ((struct sockaddr_in*)(&iface->config.ifaddr))->sin_port   = ((struct sockaddr_in*)(&bind_addr))->sin_port;
    } else if (bind_addr.ss_family == AF_INET6) {
        ((struct sockaddr_in6*)(&iface->config.ifaddr))->sin6_port = ((struct sockaddr_in6*)(&bind_addr))->sin6_port;
        ((struct sockaddr_in6*)(&iface->config.ifaddr))->sin6_scope_id = ((struct sockaddr_in6*)(&bind_addr))->sin6_scope_id;
        //ucs_info("leibin bind_addr sin6_scope_id: %d", ((struct sockaddr_in6*)(&bind_addr))->sin6_scope_id);
    } else {
        ucs_error("tcp_iface: unknown iface family=%d", iface->config.ifaddr.ss_family);
        return UCS_ERR_IO_ERROR;
    }

    /* Register event handler for incoming connections */
    status = ucs_async_set_event_handler(iface->super.worker->async->mode,
                                         iface->listen_fd,
                                         UCS_EVENT_SET_EVREAD |
                                         UCS_EVENT_SET_EVERR,
                                         uct_tcp_iface_connect_handler, iface,
                                         iface->super.worker->async);
    if (status != UCS_OK) {
        goto err_close_sock;
    }

    ucs_debug("tcp_iface %p: listening for connections (fd=%d) on %s",
              iface, iface->listen_fd, ucs_sockaddr_str((struct sockaddr *)&bind_addr,
                                                       ip_port_str, sizeof(ip_port_str)));
    return UCS_OK;

err_close_sock:
    close(iface->listen_fd);
err:
    return status;
}

static ucs_mpool_ops_t uct_tcp_mpool_ops = {
    ucs_mpool_chunk_malloc,
    ucs_mpool_chunk_free,
    NULL,
    NULL
};

static UCS_CLASS_INIT_FUNC(uct_tcp_iface_t, uct_md_h md, uct_worker_h worker,
                           const uct_iface_params_t *params,
                           const uct_iface_config_t *tl_config)
{
    uct_tcp_iface_config_t *config = ucs_derived_of(tl_config,
                                                    uct_tcp_iface_config_t);
    ucs_status_t status;

    UCT_CHECK_PARAM(params->field_mask & UCT_IFACE_PARAM_FIELD_OPEN_MODE,
                    "UCT_IFACE_PARAM_FIELD_OPEN_MODE is not defined");
    if (!(params->open_mode & UCT_IFACE_OPEN_MODE_DEVICE)) {
        ucs_error("only UCT_IFACE_OPEN_MODE_DEVICE is supported");
        return UCS_ERR_UNSUPPORTED;
    }

    if (ucs_derived_of(worker, uct_priv_worker_t)->thread_mode == UCS_THREAD_MODE_MULTI) {
        ucs_error("TCP transport does not support multi-threaded worker");
        return UCS_ERR_INVALID_PARAM;
    }

    UCS_CLASS_CALL_SUPER_INIT(uct_base_iface_t, &uct_tcp_iface_ops, md, worker,
                              params, tl_config
                              UCS_STATS_ARG((params->field_mask &
                                             UCT_IFACE_PARAM_FIELD_STATS_ROOT) ?
                                            params->stats_root : NULL)
                              UCS_STATS_ARG(params->mode.device.dev_name));

    ucs_strncpy_zero(self->if_name, params->mode.device.dev_name,
                     sizeof(self->if_name));
    self->outstanding        = 0;
    self->config.tx_seg_size = config->tx_seg_size +
                               sizeof(uct_tcp_am_hdr_t);
    self->config.rx_seg_size = config->rx_seg_size +
                               sizeof(uct_tcp_am_hdr_t);

    if (ucs_iov_get_max() >= UCT_TCP_EP_AM_SHORTV_IOV_COUNT) {
        self->config.sendv_thresh = config->sendv_thresh;
    } else {
        /* AM Short with non-blocking vector send can't be used */
        self->config.sendv_thresh = UCS_MEMUNITS_INF;
    }

    /* Maximum IOV count allowed by user's configuration (considering TCP
     * protocol and user's AM headers that use 1st and 2nd IOVs
     * correspondingly) and system constraints */
    self->config.zcopy.max_iov    = ucs_min(config->max_iov +
                                            UCT_TCP_EP_ZCOPY_SERVICE_IOV_COUNT,
                                            ucs_iov_get_max());
    /* Use a remaining part of TX segment for AM Zcopy header */
    self->config.zcopy.hdr_offset = (sizeof(uct_tcp_ep_zcopy_tx_t) +
                                     sizeof(struct iovec) *
                                     self->config.zcopy.max_iov);
    if ((self->config.zcopy.hdr_offset > self->config.tx_seg_size) &&
        (self->config.zcopy.max_iov > UCT_TCP_EP_ZCOPY_SERVICE_IOV_COUNT)) {
        ucs_error("AM Zcopy context (%zu) must be <= TX segment size (%zu). "
                  "It can be adjusted by decreasing maximum IOV count (%zu)",
                  self->config.zcopy.hdr_offset, self->config.tx_seg_size,
                  self->config.zcopy.max_iov);
        return UCS_ERR_INVALID_PARAM;
    }

    self->config.zcopy.max_hdr     = self->config.tx_seg_size -
                                     self->config.zcopy.hdr_offset;
    self->config.prefer_default    = config->prefer_default;
    self->config.put_enable        = config->put_enable;
    self->config.conn_nb           = config->conn_nb;
    self->config.max_poll          = config->max_poll;
    self->config.max_conn_retries  = config->max_conn_retries;
    self->config.syn_cnt           = config->syn_cnt;
    self->sockopt.nodelay          = config->sockopt_nodelay;
    self->sockopt.sndbuf           = config->sockopt.sndbuf;
    self->sockopt.rcvbuf           = config->sockopt.rcvbuf;

    ucs_list_head_init(&self->ep_list);
    kh_init_inplace(uct_tcp_cm_eps, &self->ep_cm_map);

    if (self->config.tx_seg_size > self->config.rx_seg_size) {
        ucs_error("RX segment size (%zu) must be >= TX segment size (%zu)",
                  self->config.rx_seg_size, self->config.tx_seg_size);
        return UCS_ERR_INVALID_PARAM;
    }

    status = ucs_mpool_init(&self->tx_mpool, 0, self->config.tx_seg_size,
                            0, UCS_SYS_CACHE_LINE_SIZE,
                            (config->tx_mpool.bufs_grow == 0) ?
                            32 : config->tx_mpool.bufs_grow,
                            config->tx_mpool.max_bufs,
                            &uct_tcp_mpool_ops, "uct_tcp_iface_tx_buf_mp");
    if (status != UCS_OK) {
        goto err;
    }

    status = ucs_mpool_init(&self->rx_mpool, 0, self->config.rx_seg_size * 2,
                            0, UCS_SYS_CACHE_LINE_SIZE,
                            (config->rx_mpool.bufs_grow == 0) ?
                            32 : config->rx_mpool.bufs_grow,
                            config->rx_mpool.max_bufs,
                            &uct_tcp_mpool_ops, "uct_tcp_iface_rx_buf_mp");
    if (status != UCS_OK) {
        goto err_cleanup_tx_mpool;
    }

/*    status = uct_tcp_netif_inaddr(self->if_name, &self->config.ifaddr,
                                  &self->config.netmask);
    if (status != UCS_OK) {
        goto err_cleanup_rx_mpool;
    }*/
    self->config.ifaddr  = *params->mode.device.ifaddr;
    self->config.netmask = *params->mode.device.netmask;
    ucs_info("%s family: %d", params->mode.device.dev_name, params->mode.device.ifaddr->ss_family);  
    if (params->mode.device.ifaddr->ss_family != AF_INET && params->mode.device.ifaddr->ss_family != AF_INET6) {
        ucs_log_print_backtrace(UCS_LOG_LEVEL_INFO);
    }
    char str[INET6_ADDRSTRLEN];
    memset(str, 0, INET6_ADDRSTRLEN);
    if(inet_ntop(params->mode.device.ifaddr->ss_family, params->mode.device.ifaddr->__ss_padding, str, INET6_ADDRSTRLEN) == NULL){       
        ucs_info("tcp_iface ip error error");    
    } else {
        ucs_info("ip: %s", str);  
    }
    status = ucs_event_set_create(&self->event_set);
    if (status != UCS_OK) {
        status = UCS_ERR_IO_ERROR;
        goto err_cleanup_rx_mpool;
    }

    status = uct_tcp_iface_listener_init(self);
    if (status != UCS_OK) {
        goto err_cleanup_event_set;
    }

    return UCS_OK;

err_cleanup_event_set:
    ucs_event_set_cleanup(self->event_set);
err_cleanup_rx_mpool:
    ucs_mpool_cleanup(&self->rx_mpool, 1);
err_cleanup_tx_mpool:
    ucs_mpool_cleanup(&self->tx_mpool, 1);
err:
    return status;
}

static void uct_tcp_iface_ep_list_cleanup(uct_tcp_iface_t *iface,
                                          ucs_list_link_t *ep_list)
{
    uct_tcp_ep_t *ep, *tmp;

    ucs_list_for_each_safe(ep, tmp, ep_list, list) {
        uct_tcp_cm_purge_ep(ep);
        uct_tcp_ep_destroy_internal(&ep->super.super);
    }
}

static void uct_tcp_iface_eps_cleanup(uct_tcp_iface_t *iface)
{
    ucs_list_link_t *ep_list;

    uct_tcp_iface_ep_list_cleanup(iface, &iface->ep_list);

    kh_foreach_value(&iface->ep_cm_map, ep_list, {
        uct_tcp_iface_ep_list_cleanup(iface, ep_list);
        ucs_free(ep_list);
    });

    kh_destroy_inplace(uct_tcp_cm_eps, &iface->ep_cm_map);
}

void uct_tcp_iface_add_ep(uct_tcp_ep_t *ep)
{
    uct_tcp_iface_t *iface = ucs_derived_of(ep->super.super.iface,
                                            uct_tcp_iface_t);
    UCS_ASYNC_BLOCK(iface->super.worker->async);
    ucs_list_add_tail(&iface->ep_list, &ep->list);
    UCS_ASYNC_UNBLOCK(iface->super.worker->async);
}

void uct_tcp_iface_remove_ep(uct_tcp_ep_t *ep)
{
    uct_tcp_iface_t *iface = ucs_derived_of(ep->super.super.iface,
                                            uct_tcp_iface_t);
    UCS_ASYNC_BLOCK(iface->super.worker->async);
    ucs_list_del(&ep->list);
    UCS_ASYNC_UNBLOCK(iface->super.worker->async);
}

static UCS_CLASS_CLEANUP_FUNC(uct_tcp_iface_t)
{
    ucs_status_t status;

    ucs_debug("tcp_iface %p: destroying", self);

    uct_base_iface_progress_disable(&self->super.super,
                                    UCT_PROGRESS_SEND |
                                    UCT_PROGRESS_RECV);

    status = ucs_async_remove_handler(self->listen_fd, 1);
    if (status != UCS_OK) {
        ucs_warn("failed to remove handler for server socket fd=%d", self->listen_fd);
    }

    uct_tcp_iface_eps_cleanup(self);

    ucs_mpool_cleanup(&self->rx_mpool, 1);
    ucs_mpool_cleanup(&self->tx_mpool, 1);

    uct_tcp_iface_listen_close(self);
    ucs_event_set_cleanup(self->event_set);
}

UCS_CLASS_DEFINE(uct_tcp_iface_t, uct_base_iface_t);
static UCS_CLASS_DEFINE_NEW_FUNC(uct_tcp_iface_t, uct_iface_t, uct_md_h,
                                 uct_worker_h, const uct_iface_params_t*,
                                 const uct_iface_config_t*);

ucs_status_t uct_tcp_query_devices(uct_md_h md,
                                   uct_tl_device_resource_t **devices_p,
                                   unsigned *num_devices_p)
{
    uct_tl_device_resource_t *devices, *tmp;
    struct ifaddrs *ifaddr, *ifa;
    unsigned num_devices;
    ucs_status_t status;
    int family;
    
    if (getifaddrs(&ifaddr) != 0) {
        status = UCS_ERR_IO_ERROR;
        goto out;
    }

    devices     = NULL;
    num_devices = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6)
            continue;

        if (!ucs_netif_flags_is_active(ifa->ifa_flags)) {
            continue;
        }

        tmp = ucs_realloc(devices, sizeof(*devices) * (num_devices + 1),
                          "tcp devices");
        if (tmp == NULL) {
            ucs_free(devices);
            status = UCS_ERR_NO_MEMORY;
            goto free_out;
        }
        devices = tmp;

        ucs_snprintf_zero(devices[num_devices].name,
                          sizeof(devices[num_devices].name),
                          "%s", ifa->ifa_name);

        if (family == AF_INET) {
            memcpy(&devices[num_devices].ifaddr, ifa->ifa_addr, sizeof(struct sockaddr_in));
            memcpy(&devices[num_devices].netmask, ifa->ifa_netmask, sizeof(struct sockaddr_in));
        } else if (family == AF_INET6) {
            memcpy(&devices[num_devices].ifaddr, ifa->ifa_addr, sizeof(struct sockaddr_in6));
            memcpy(&devices[num_devices].netmask, ifa->ifa_netmask, sizeof(struct sockaddr_in6));
        } else {
            ucs_error("tcp_iface: unknown iface family=%d", family);
            status = UCS_ERR_IO_ERROR;
            goto free_out;
        }
        devices[num_devices].type = UCT_DEVICE_TYPE_NET;
        ucs_info("%s family2: %d", ifa->ifa_name, ifa->ifa_addr->sa_family);
        ucs_info("%s family4: %d", devices[num_devices].name, devices[num_devices].ifaddr.ss_family);
        ++num_devices;


        //ucs_error("ifa_name: %s", ifa->ifa_name);
    }

    //IPv4 if available, otherwise IPv6
    uint8_t* processed = ucs_malloc(num_devices, "processed flag");
    unsigned new_num_devices = 0;
    int i;
    int j;
    for (i = 0; i < num_devices; i++) {
        processed[i] = 0;
    }
    for (i = 0; i < num_devices - 1; i++) {
        if (!processed[i]) {
            for(j = i + 1; j < num_devices; j++) {
                if (!processed[j]) {
                    if (!strcmp(devices[i].name, devices[j].name)) {
                        processed[i] = 1;
                        processed[j] = 1;
                        if (devices[i].ifaddr.ss_family == AF_INET) {
                            memcpy(&devices[new_num_devices++], &devices[i], sizeof(uct_tl_device_resource_t));
                        } else {
                            memcpy(&devices[new_num_devices++], &devices[j], sizeof(uct_tl_device_resource_t));
                        }
                    }
                }
            }
            if (!processed[i]) {
                processed[i] = 1;
                memcpy(&devices[new_num_devices++], &devices[i], sizeof(uct_tl_device_resource_t));
            }
        }
    }
    if (!processed[num_devices - 1]) {
        processed[num_devices - 1] = 1;
        memcpy(&devices[new_num_devices++], &devices[num_devices - 1], sizeof(uct_tl_device_resource_t));
    }
    ucs_free(processed);
    *num_devices_p = new_num_devices;
    *devices_p     = devices;
    status         = UCS_OK;
free_out:
    freeifaddrs(ifaddr);
out:
    return status;
}

UCT_TL_DEFINE(&uct_tcp_component, tcp, uct_tcp_query_devices, uct_tcp_iface_t,
              UCT_TCP_CONFIG_PREFIX, uct_tcp_iface_config_table,
              uct_tcp_iface_config_t);
