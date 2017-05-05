
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_TS_STREAM_H_INCLUDED_
#define _NGX_TS_STREAM_H_INCLUDED_


typedef struct {
    u_char                        type;
    uint16_t                      pid;
    uint64_t                      pts;
    uint64_t                      dts;
    ngx_chain_t                  *bufs; /* ES */
} ngx_ts_es_t;


typedef struct {
    uint16_t                      number;
    uint16_t                      pid;
    ngx_uint_t                    nes;
    ngx_ts_es_t                  *es;
    ngx_chain_t                  *bufs; /* PMT */
} ngx_ts_program_t;


typedef ngx_int_t (*ngx_ts_program_handler_pt)(ngx_ts_program_t *prog,
    void *data);
typedef ngx_int_t (*ngx_ts_frame_handler_pt)(ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_chain_t *bufs, void *data);


typedef struct {
    ngx_ts_program_handler_pt     program_handler;
    ngx_ts_frame_handler_pt       frame_handler;
    void                         *data;

    ngx_uint_t                    nprogs;
    ngx_ts_program_t             *progs;
    ngx_log_t                    *log;
    ngx_pool_t                   *pool;
    ngx_buf_t                    *buf;
    ngx_chain_t                  *free;
    ngx_chain_t                  *bufs; /* PAT */
} ngx_ts_stream_t;


ngx_int_t ngx_ts_read(ngx_ts_stream_t *ts, u_char *data, size_t len);


#endif /* _NGX_TS_STREAM_H_INCLUDED_ */
