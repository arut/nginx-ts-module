
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_stream.h"


#ifndef _NGX_TS_DASH_H_INCLUDED_
#define _NGX_TS_DASH_H_INCLUDED_


typedef struct {
    ngx_path_t             *path;
} ngx_ts_dash_conf_t;


typedef struct {
    /* TODO 32? */
    uint64_t                start;
    uint64_t                duration;
} ngx_ts_dash_segment_t;


typedef struct {
    ngx_ts_dash_segment_t  *segs;
    ngx_uint_t              nsegs;
    ngx_uint_t              seg;
    uint64_t                seg_pts;

    ngx_ts_es_t            *es;
    ngx_str_t               path;

    ngx_chain_t            *meta;
    ngx_chain_t            *data;
} ngx_ts_dash_rep_t;


typedef struct {
    ngx_ts_dash_rep_t      *reps;
    ngx_uint_t              nreps;
} ngx_ts_dash_set_t;


typedef struct {
    ngx_ts_stream_t        *ts;
    ngx_ts_dash_conf_t     *conf;

    u_char                 *path;
    ngx_chain_t            *free;

    ngx_ts_dash_set_t      *sets;
    ngx_uint_t              nsets;
} ngx_ts_dash_t;


ngx_ts_dash_t *ngx_ts_dash_create(ngx_ts_dash_conf_t *conf, ngx_ts_stream_t *ts,
    ngx_str_t *name);
ngx_int_t ngx_ts_dash_write_frame(ngx_ts_dash_t *dash, ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_chain_t *bufs);
ngx_msec_t ngx_ts_dash_file_manager(void *data);


#endif /* _NGX_TS_DASH_H_INCLUDED_ */
