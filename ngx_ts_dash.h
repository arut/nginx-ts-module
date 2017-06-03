
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
    ngx_msec_t              min_seg;
    ngx_msec_t              max_seg;
    ngx_msec_t              analyze;
    ngx_uint_t              nsegs;
} ngx_ts_dash_conf_t;


typedef struct {
    uint64_t                start;
    uint64_t                duration;
} ngx_ts_dash_segment_t;


typedef struct {
    u_char                 *dts;  /* 64-bit */
    u_char                 *pts;  /* 64-bit */
    u_char                 *seq;
    u_char                 *duration;
    u_char                 *sample_duration;
    u_char                 *nsamples;
    u_char                 *traf;
    u_char                 *trun;
    u_char                 *moof;
    u_char                 *moof_mdat;
    u_char                 *moof_data;
    u_char                 *mdat;
} ngx_ts_dash_subs_t;


typedef struct {
    ngx_ts_dash_segment_t  *segs;
    ngx_uint_t              nsegs;
    ngx_uint_t              seg;
    uint64_t                seg_pts;
    uint64_t                seg_dts;
    uint64_t                pts;

    ngx_uint_t              bandwidth;
    ngx_uint_t              bandwidth_bytes;
    uint64_t                bandwidth_pts;

    ngx_chain_t            *sps;
    ngx_chain_t            *pps;
    u_char                 *adts;

    ngx_ts_es_t            *es;
    ngx_str_t               path;

    ngx_chain_t            *meta;
    ngx_chain_t            *last_meta;
    ngx_chain_t            *data;
    ngx_chain_t            *last_data;

    ngx_uint_t              nsamples;
    ngx_uint_t              nmeta;
    ngx_uint_t              ndata;

    ngx_ts_dash_subs_t      subs;
} ngx_ts_dash_rep_t;


typedef struct {
    ngx_ts_dash_rep_t      *reps;
    ngx_uint_t              nreps;
    ngx_uint_t              video;  /* unsigned  video:1; */
} ngx_ts_dash_set_t;


typedef struct {
    ngx_ts_stream_t        *ts;
    ngx_ts_dash_conf_t     *conf;

    u_char                 *mpd_path;
    u_char                 *mpd_tmp_path;
    ngx_str_t               path;
    size_t                  playlist_len;
    time_t                  availability_start;

    ngx_chain_t            *free;
    ngx_ts_dash_set_t      *sets;
    ngx_uint_t              nsets;
} ngx_ts_dash_t;


ngx_ts_dash_t *ngx_ts_dash_create(ngx_ts_dash_conf_t *conf, ngx_ts_stream_t *ts,
    ngx_str_t *name);
char *ngx_ts_dash_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


#endif /* _NGX_TS_DASH_H_INCLUDED_ */
