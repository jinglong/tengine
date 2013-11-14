
/*
 * Copyright (C) 2010-2013 Alibaba Group Holding Limited
 */


#ifndef _NGX_HTTP_PROXY_KEEPALIVE_MODULE_H_INCLUDED_
#define _NGX_HTTP_PROXY_KEEPALIVE_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t ngx_http_addrs_create_keepalive_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur);


#endif
