
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_ts_stream.h"


typedef struct {
    int               dummy;
} ngx_http_ts_loc_conf_t;


typedef struct {
    ngx_ts_stream_t  *ts;
} ngx_http_ts_ctx_t;


static ngx_int_t ngx_http_ts_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_ts_program_handler(ngx_ts_program_t *prog,
    void *data);
static ngx_int_t ngx_http_ts_frame_handler(ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_chain_t *bufs, void *data);
static void ngx_http_ts_init(ngx_http_request_t *r);
static void ngx_http_ts_read_event_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_ts_process_body(ngx_http_request_t *r,
    ngx_chain_t *in);

static char *ngx_http_ts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_ts_create_conf(ngx_conf_t *cf);
static char *ngx_http_ts_merge_conf(ngx_conf_t *cf, void *parent, void *child);


static ngx_command_t  ngx_http_ts_commands[] = {

    { ngx_string("ts"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_ts,
      0,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_ts_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_ts_create_conf,       /* create location configuration */
    ngx_http_ts_merge_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_ts_module = {
    NGX_MODULE_V1,
    &ngx_http_ts_module_ctx,       /* module context */
    ngx_http_ts_commands,          /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_ts_handler(ngx_http_request_t *r)
{
    ngx_int_t           rc;
    ngx_http_ts_ctx_t  *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ts_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->ts = ngx_pcalloc(r->pool, sizeof(ngx_ts_stream_t));
    if (ctx->ts == NULL) {
        return NGX_ERROR;
    }

    ctx->ts->pool = r->pool;
    ctx->ts->log = r->connection->log;

    ctx->ts->program_handler = ngx_http_ts_program_handler;
    ctx->ts->frame_handler = ngx_http_ts_frame_handler;
    ctx->ts->data = r;

    ngx_http_set_ctx(r, ctx, ngx_http_ts_module);

    r->request_body_no_buffering = 1;

    rc = ngx_http_read_client_request_body(r, ngx_http_ts_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_ts_program_handler(ngx_ts_program_t *prog, void *data)
{
    ngx_http_request_t *r = data;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ts program pid:0x%04uxd, n:%ui, nes:%ui",
                   (unsigned) prog->pid, (ngx_uint_t) prog->number, prog->nes);

    return NGX_OK;
}


static ngx_int_t
ngx_http_ts_frame_handler(ngx_ts_program_t *prog, ngx_ts_es_t *es,
    ngx_chain_t *bufs, void *data)
{
    ngx_http_request_t *r = data;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ts frame pid:0x%04uxd, type:0x%02uxd, pts:%uL, dts:%uL",
                   (unsigned) es->pid, (unsigned) es->type, es->pts, es->dts);

    return NGX_OK;
}


static void
ngx_http_ts_init(ngx_http_request_t *r)
{
    ngx_http_request_body_t  *rb;

    rb = r->request_body;

    if (rb == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_http_ts_process_body(r, rb->bufs) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (r->reading_body) {
        r->read_event_handler = ngx_http_ts_read_event_handler;
    }
}


static void
ngx_http_ts_read_event_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_http_request_body_t  *rb;

    rb = r->request_body;

    for ( ;; ) {
        rc = ngx_http_read_unbuffered_request_body(r);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ngx_http_finalize_request(r, rc);
            return;
        }

        if (rb->bufs == NULL) {
            return;
        }

        if (ngx_http_ts_process_body(r, rb->bufs) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (rc == NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_NO_CONTENT);
            return;
        }

        rb->bufs = NULL;
    }
}


static ngx_int_t
ngx_http_ts_process_body(ngx_http_request_t *r, ngx_chain_t *cl)
{
    ngx_buf_t          *b;
    ngx_http_ts_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ts_module);

    while (cl) {
        b = cl->buf;

        if (b->in_file) {
            return NGX_ERROR;
        }

        if (ngx_ts_read(ctx->ts, b->pos, b->last - b->pos) != NGX_OK) {
            return NGX_ERROR;
        }

        b->pos = b->last;

        cl = cl->next;
    }

    return NGX_OK;
}


static char *
ngx_http_ts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_ts_handler;

    return NGX_CONF_OK;
}


static void *
ngx_http_ts_create_conf(ngx_conf_t *cf)
{
    ngx_http_ts_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ts_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_ts_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ts_loc_conf_t *prev = parent;
    ngx_http_ts_loc_conf_t *conf = child;

    (void) prev;
    (void) conf;

    return NGX_CONF_OK;
}
