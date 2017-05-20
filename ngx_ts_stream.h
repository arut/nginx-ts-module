
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_TS_STREAM_H_INCLUDED_
#define _NGX_TS_STREAM_H_INCLUDED_


typedef struct {
    u_char                        type;
    u_char                        sid;
    u_char                        cont;
    uint16_t                      pid;
    uint64_t                      pts;
    uint64_t                      dts;
    unsigned                      ptsf:1;
    unsigned                      rand:1;
    unsigned                      video:1;
    ngx_chain_t                  *bufs; /* ES */
} ngx_ts_es_t;


typedef struct {
    uint16_t                      number;
    uint16_t                      pid;
    uint16_t                      pcr_pid;
    uint64_t                      pcr;
    ngx_uint_t                    video;  /* unisgned  video:1; */
    ngx_uint_t                    nes;
    ngx_ts_es_t                  *es;
    ngx_chain_t                  *bufs; /* PMT */
} ngx_ts_program_t;


typedef struct ngx_ts_stream_s  ngx_ts_stream_t;


typedef ngx_int_t (*ngx_ts_pat_handler_pt)(ngx_ts_stream_t *ts);
typedef ngx_int_t (*ngx_ts_pmt_handler_pt)(ngx_ts_stream_t *ts,
    ngx_ts_program_t *prog);
typedef ngx_int_t (*ngx_ts_pes_handler_pt)(ngx_ts_stream_t *ts,
    ngx_ts_program_t *prog, ngx_ts_es_t *es, ngx_chain_t *bufs);


struct ngx_ts_stream_s {
    ngx_uint_t                    nprogs;
    ngx_ts_program_t             *progs;
    ngx_log_t                    *log;
    ngx_pool_t                   *pool;
    ngx_buf_t                    *buf;
    ngx_chain_t                  *free;
    ngx_chain_t                  *bufs; /* PAT */

    ngx_ts_pat_handler_pt         pat_handler;
    ngx_ts_pmt_handler_pt         pmt_handler;
    ngx_ts_pes_handler_pt         pes_handler;

    void                         *data;
};


ngx_int_t ngx_ts_read(ngx_ts_stream_t *ts, ngx_chain_t *in);
ngx_chain_t *ngx_ts_write_pat(ngx_ts_stream_t *ts, ngx_ts_program_t *prog);
ngx_chain_t *ngx_ts_write_pmt(ngx_ts_stream_t *ts, ngx_ts_program_t *prog);
ngx_chain_t *ngx_ts_write_pes(ngx_ts_stream_t *ts, ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_chain_t *bufs);
void ngx_ts_free_chain(ngx_ts_stream_t *ts, ngx_chain_t **ll);


#endif /* _NGX_TS_STREAM_H_INCLUDED_ */
