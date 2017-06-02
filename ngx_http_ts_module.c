
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_ts_stream.h"
#include "ngx_ts_hls.h"
#include "ngx_ts_dash.h"


typedef struct {
    ngx_ts_hls_conf_t   *hls;
    ngx_ts_dash_conf_t  *dash;
} ngx_http_ts_loc_conf_t;


typedef struct {
    ngx_ts_stream_t     *ts;
    ngx_ts_hls_t        *hls;
    ngx_ts_dash_t       *dash;
    ngx_str_t            name;
} ngx_http_ts_ctx_t;


static ngx_int_t ngx_http_ts_handler(ngx_http_request_t *r);
static void ngx_http_ts_init(ngx_http_request_t *r);
static void ngx_http_ts_read_event_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_ts_pat_handler(ngx_ts_stream_t *ts);
static ngx_int_t ngx_http_ts_pmt_handler(ngx_ts_stream_t *ts,
    ngx_ts_program_t *prog);
static ngx_int_t ngx_http_ts_pes_handler(ngx_ts_stream_t *ts,
    ngx_ts_program_t *prog, ngx_ts_es_t *es, ngx_chain_t *bufs);

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

    { ngx_string("ts_hls"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_ts_hls_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_loc_conf_t, hls),
      NULL },

    { ngx_string("ts_dash"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_ts_dash_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_loc_conf_t, dash),
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
    ngx_uint_t          n;
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

    ctx->ts->pat_handler = ngx_http_ts_pat_handler;
    ctx->ts->pmt_handler = ngx_http_ts_pmt_handler;
    ctx->ts->pes_handler = ngx_http_ts_pes_handler;
    ctx->ts->data = r;

    for (n = 0; n < r->uri.len; n++) {
        if (r->uri.data[r->uri.len - 1 - n] == '/') {
            break;
        }
    }

    ctx->name.data = &r->uri.data[r->uri.len - n];
    ctx->name.len = n;

    /* XXX detect streams with the same ctx->name, add shared zone */

    ngx_http_set_ctx(r, ctx, ngx_http_ts_module);

    r->request_body_no_buffering = 1;

    rc = ngx_http_read_client_request_body(r, ngx_http_ts_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void
ngx_http_ts_init(ngx_http_request_t *r)
{
    ngx_http_ts_ctx_t        *ctx;
    ngx_http_request_body_t  *rb;

    rb = r->request_body;

    if (rb == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ts_module);

    if (ngx_ts_read(ctx->ts, rb->bufs) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_ERROR);
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
    ngx_http_ts_ctx_t        *ctx;
    ngx_http_request_body_t  *rb;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ts_module);

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

        if (ngx_ts_read(ctx->ts, rb->bufs) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_ERROR);
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
ngx_http_ts_pat_handler(ngx_ts_stream_t *ts)
{
    ngx_http_request_t *r = ts->data;

    ngx_http_ts_ctx_t       *ctx;
    ngx_http_ts_loc_conf_t  *tlcf;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ts pat nprogs:%ui",  ts->nprogs);

    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_ts_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_ts_module);

    if (tlcf->hls) {
        ctx->hls = ngx_ts_hls_create(tlcf->hls, ctx->ts, &ctx->name);
        if (ctx->hls == NULL) {
            return  NGX_ERROR;
        }
    }

    if (tlcf->dash) {
        ctx->dash = ngx_ts_dash_create(tlcf->dash, ctx->ts, &ctx->name);
        if (ctx->dash == NULL) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ts_pmt_handler(ngx_ts_stream_t *ts, ngx_ts_program_t *prog)
{
    ngx_http_request_t *r = ts->data;

    ngx_http_ts_ctx_t  *ctx;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ts pmt pid:0x%04uxd, n:%ui, nes:%ui",
                   (unsigned) prog->pid, (ngx_uint_t) prog->number, prog->nes);

    ctx = ngx_http_get_module_ctx(r, ngx_http_ts_module);

    if (ctx->dash) {
        if (ngx_ts_dash_handle_pmt(ctx->dash, prog) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ts_pes_handler(ngx_ts_stream_t *ts, ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_chain_t *bufs)
{
    ngx_http_request_t *r = ts->data;

    ngx_http_ts_ctx_t  *ctx;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ts pes pid:0x%04uxd, type:0x%02uxd, sid:0x%02uxd, "
                   "pts:%uL, dts:%uL",
                   (unsigned) es->pid, (unsigned) es->type, (unsigned) es->sid,
                   es->pts, es->dts);

    ctx = ngx_http_get_module_ctx(r, ngx_http_ts_module);

    if (ctx->hls) {
        if (ngx_ts_hls_write_frame(ctx->hls, prog, es, bufs) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ctx->dash) {
        if (ngx_ts_dash_write_frame(ctx->dash, prog, es, bufs) != NGX_OK) {
            return NGX_ERROR;
        }
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

    conf->hls = NGX_CONF_UNSET_PTR;
    conf->dash = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_ts_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ts_loc_conf_t *prev = parent;
    ngx_http_ts_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->hls, prev->hls, NULL);
    ngx_conf_merge_ptr_value(conf->dash, prev->dash, NULL);

    return NGX_CONF_OK;
}
