
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_ts_stream.h"
#include "ngx_ts_hls.h"


typedef struct {
    ngx_ts_hls_conf_t  *hls;
} ngx_http_ts_loc_conf_t;


typedef struct {
    ngx_ts_stream_t    *ts;
    ngx_ts_hls_t       *hls;
    ngx_str_t           name;
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
static char *ngx_http_ts_hls(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
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
      ngx_http_ts_hls,
      NGX_HTTP_LOC_CONF_OFFSET,
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

    if (tlcf->hls) {
        ctx = ngx_http_get_module_ctx(r, ngx_http_ts_module);

        ctx->hls = ngx_ts_hls_create(tlcf->hls, ctx->ts, &ctx->name);
        if (ctx->hls == NULL) {
            return  NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ts_pmt_handler(ngx_ts_stream_t *ts, ngx_ts_program_t *prog)
{
    ngx_http_request_t *r = ts->data;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ts pmt pid:0x%04uxd, n:%ui, nes:%ui",
                   (unsigned) prog->pid, (ngx_uint_t) prog->number, prog->nes);

    (void) r;

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


static char *
ngx_http_ts_hls(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ts_loc_conf_t *tscf = conf;

    ngx_str_t          *value, s;
    ngx_int_t           v;
    ngx_uint_t          i, nsegs;
    ngx_msec_t          min_seg, max_seg;
    ngx_ts_hls_conf_t  *hls;

    if (tscf->hls) {
        return "is duplicate";
    }

    hls = ngx_pcalloc(cf->pool, sizeof(ngx_ts_hls_conf_t));
    if (hls == NULL) {
        return NGX_CONF_ERROR;
    }

    hls->path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (hls->path == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    hls->path->name = value[1];

    if (hls->path->name.data[hls->path->name.len - 1] == '/') {
        hls->path->name.len--;
    }

    if (ngx_conf_full_name(cf->cycle, &hls->path->name, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    min_seg = 5000;
    max_seg = 0;
    nsegs = 6;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "segment=", 7) == 0) {

            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            min_seg = ngx_parse_time(&s, 0);
            if (min_seg == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid segment duration value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_segment=", 7) == 0) {

            s.len = value[i].len - 12;
            s.data = value[i].data + 12;

            max_seg = ngx_parse_time(&s, 0);
            if (max_seg == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid max segment duration value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "segments=", 7) == 0) {

            v = ngx_atoi(value[i].data + 9, value[i].len - 9);
            if (v == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid segments number value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            nsegs = v;

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    hls->min_seg = min_seg;
    hls->max_seg = max_seg ? max_seg : min_seg * 3;
    hls->nsegs = nsegs;

    hls->path->manager = ngx_ts_hls_file_manager;
    hls->path->data = hls;
    hls->path->conf_file = cf->conf_file->file.name.data;
    hls->path->line = cf->conf_file->line;

    if (ngx_add_path(cf, &hls->path) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    tscf->hls = hls;

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

    /*
     * set by ngx_pcalloc():
     *
     *     conf->hls = NULL;
     */

    return conf;
}


static char *
ngx_http_ts_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ts_loc_conf_t *prev = parent;
    ngx_http_ts_loc_conf_t *conf = child;

    if (conf->hls == NULL) {
        conf->hls = prev->hls;
    }

    return NGX_CONF_OK;
}
