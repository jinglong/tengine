
/*
 * Copyright (C) 2010-2013 Alibaba Group Holding Limited
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_uint_t                         max_cached;
    ngx_msec_t                         keepalive_timeout;

    ngx_queue_t                        cache;
    ngx_queue_t                        free;

} ngx_http_addrs_keepalive_loc_conf_t;


typedef struct {
    ngx_http_addrs_keepalive_loc_conf_t  *conf;

    ngx_http_upstream_t               *upstream;

    void                              *data;

    ngx_event_get_peer_pt              original_get_peer;
    ngx_event_free_peer_pt             original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt      original_set_session;
    ngx_event_save_peer_session_pt     original_save_session;
#endif

} ngx_http_addrs_keepalive_peer_data_t;


typedef struct {
    ngx_http_addrs_keepalive_loc_conf_t  *conf;

    ngx_queue_t                        queue;
    ngx_connection_t                  *connection;

    socklen_t                          socklen;
    u_char                             sockaddr[NGX_SOCKADDRLEN];

} ngx_http_addrs_keepalive_cache_t;


static ngx_int_t ngx_http_addrs_get_keepalive_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_addrs_free_keepalive_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

static void ngx_http_addrs_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_http_addrs_keepalive_close_handler(ngx_event_t *ev);
static void ngx_http_addrs_keepalive_close(ngx_connection_t *c);


#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_addrs_keepalive_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_addrs_keepalive_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static void *ngx_http_addrs_keepalive_create_conf(ngx_conf_t *cf);
static char *ngx_http_addrs_keepalive_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_addrs_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_addrs_keepalive_timeout(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_addrs_keepalive_commands[] = {

    { ngx_string("addrs_keepalive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_addrs_keepalive,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("addrs_keepalive_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_addrs_keepalive_timeout,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_addrs_keepalive_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_addrs_keepalive_create_conf,  /* create location configuration */
    ngx_http_addrs_keepalive_merge_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_addrs_keepalive_module = {
    NGX_MODULE_V1,
    &ngx_http_addrs_keepalive_module_ctx,  /* module context */
    ngx_http_addrs_keepalive_commands,     /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_http_addrs_create_keepalive_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur)
{
    ngx_http_addrs_keepalive_peer_data_t  *kp;
    ngx_http_addrs_keepalive_loc_conf_t   *kcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "addrs create keepalive peer");

    kcf = ngx_http_get_module_loc_conf(r, ngx_http_addrs_keepalive_module);

    if (ngx_http_upstream_create_round_robin_peer(r, ur) != NGX_OK) {
        return NGX_ERROR;
    }

    if (kcf->max_cached == 0) {
        return NGX_OK;
    }

    kp = ngx_palloc(r->pool, sizeof(ngx_http_addrs_keepalive_peer_data_t));
    if (kp == NULL) {
        return NGX_ERROR;
    }

    kp->conf = kcf;
    kp->upstream = r->upstream;
    kp->data = r->upstream->peer.data;
    kp->original_get_peer = r->upstream->peer.get;
    kp->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = kp;
    r->upstream->peer.get = ngx_http_addrs_get_keepalive_peer;
    r->upstream->peer.free = ngx_http_addrs_free_keepalive_peer;

#if (NGX_HTTP_SSL)
    kp->original_set_session = r->upstream->peer.set_session;
    kp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_http_addrs_keepalive_set_session;
    r->upstream->peer.save_session = ngx_http_addrs_keepalive_save_session;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_addrs_get_keepalive_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_addrs_keepalive_peer_data_t  *kp = data;
    ngx_http_addrs_keepalive_cache_t      *item;

    ngx_int_t          rc;
    ngx_queue_t       *q, *cache;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "addrs get keepalive peer");

    /* ask balancer */

    rc = kp->original_get_peer(pc, kp->data);

    if (rc != NGX_OK) {
        return rc;
    }

    /* search cache for suitable connection */

    cache = &kp->conf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_addrs_keepalive_cache_t, queue);
        c = item->connection;

        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {
            ngx_queue_remove(q);
            ngx_queue_insert_head(&kp->conf->free, q);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "addrs get keepalive peer: using connection %p", c);

            c->idle = 0;
            c->log = pc->log;
            c->read->log = pc->log;
            c->write->log = pc->log;
            c->pool->log = pc->log;

            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }

            pc->connection = c;
            pc->cached = 1;

            return NGX_DONE;
        }
    }

    return NGX_OK;
}


static void
ngx_http_addrs_free_keepalive_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_addrs_keepalive_peer_data_t  *kp = data;
    ngx_http_addrs_keepalive_cache_t      *item;

    ngx_queue_t          *q;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "addrs free keepalive peer");

    /* cache valid connections */

    u = kp->upstream;
    c = pc->connection;

    if (state & NGX_PEER_FAILED
        || c == NULL
        || c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        goto invalid;
    }

    if (!u->keepalive) {
        goto invalid;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto invalid;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "addrs free keepalive peer: saving connection %p", c);

    if (ngx_queue_empty(&kp->conf->free)) {

        q = ngx_queue_last(&kp->conf->cache);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_addrs_keepalive_cache_t, queue);

        ngx_http_addrs_keepalive_close(item->connection);

    } else {
        q = ngx_queue_head(&kp->conf->free);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_addrs_keepalive_cache_t, queue);
    }

    item->connection = c;
    ngx_queue_insert_head(&kp->conf->cache, q);

    pc->connection = NULL;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (kp->conf->keepalive_timeout != 0)
    {
        ngx_add_timer(c->read, kp->conf->keepalive_timeout);
    }

    c->write->handler = ngx_http_addrs_keepalive_dummy_handler;
    c->read->handler = ngx_http_addrs_keepalive_close_handler;

    c->data = item;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;

    item->socklen = pc->socklen;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    if (c->read->ready) {
        ngx_http_addrs_keepalive_close_handler(c->read);
    }

invalid:

    kp->original_free_peer(pc, kp->data, state);
}


static void
ngx_http_addrs_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "addrs keepalive dummy handler");
}


static void
ngx_http_addrs_keepalive_close_handler(ngx_event_t *ev)
{
    ngx_http_addrs_keepalive_cache_t     *item;
    ngx_http_addrs_keepalive_loc_conf_t  *conf;

    int                n;
    char               buf[1];
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "addrs keepalive close handler");

    c = ev->data;

    if (c->close) {
        goto close;
    }

    if (c->read->timedout) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                       "addrs keepalive max idle timeout");
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        /* stale event */

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->data;
    conf = item->conf;

    ngx_http_addrs_keepalive_close(c);

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&conf->free, &item->queue);
}


static void
ngx_http_addrs_keepalive_close(ngx_connection_t *c)
{

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_addrs_keepalive_close;
            return;
        }
    }

#endif

    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_addrs_keepalive_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_addrs_keepalive_peer_data_t  *kp = data;

    return kp->original_set_session(pc, kp->data);
}


static void
ngx_http_addrs_keepalive_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_addrs_keepalive_peer_data_t  *kp = data;

    kp->original_save_session(pc, kp->data);
    return;
}

#endif


static void *
ngx_http_addrs_keepalive_create_conf(ngx_conf_t *cf)
{
    ngx_http_addrs_keepalive_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_addrs_keepalive_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *    conf->cache = {NULL, NULL}
     *    conf->free = {NULL, NULL}
     */

    conf->max_cached = NGX_CONF_UNSET_UINT;
    conf->keepalive_timeout = NGX_CONF_UNSET_MSEC;

    return conf;
}


static char *
ngx_http_addrs_keepalive_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_addrs_keepalive_loc_conf_t  *prev = parent;
    ngx_http_addrs_keepalive_loc_conf_t  *conf = child;

    if (conf->max_cached == NGX_CONF_UNSET_UINT) {
        conf->cache = prev->cache;
        conf->free = prev->free;
    }

    ngx_conf_merge_uint_value(conf->max_cached, prev->max_cached, 0);
    ngx_conf_merge_msec_value(conf->keepalive_timeout, prev->keepalive_timeout,
                              0);

    return NGX_CONF_OK;
}


static char *
ngx_http_addrs_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_addrs_keepalive_loc_conf_t  *kcf = conf;

    ngx_uint_t                            i;
    ngx_http_addrs_keepalive_cache_t     *cached;

    ngx_int_t    n;
    ngx_str_t   *value;

    if (kcf->max_cached != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return NGX_CONF_ERROR;
    }

    kcf->max_cached = n;

    /* allocate cache items and add to free queue */

    cached = ngx_pcalloc(cf->pool,
                sizeof(ngx_http_addrs_keepalive_cache_t) * kcf->max_cached);
    if (cached == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_queue_init(&kcf->cache);
    ngx_queue_init(&kcf->free);

    for (i = 0; i < kcf->max_cached; i++) {
        ngx_queue_insert_head(&kcf->free, &cached[i].queue);
        cached[i].conf = kcf;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_addrs_keepalive_timeout(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_addrs_keepalive_loc_conf_t  *kcf = conf;

    ngx_str_t   *value;
    ngx_msec_t   timeout;

    if (kcf->keepalive_timeout != NGX_CONF_UNSET_MSEC) {
        return "is duplicate";
    }

    value = cf->args->elts;

    timeout = ngx_parse_time(&value[1], 0);
    if (timeout == (ngx_msec_t) NGX_ERROR) {
        return "invalid value";
    }

    kcf->keepalive_timeout = timeout;

    return NGX_CONF_OK;
}

