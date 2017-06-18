
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_dash.h"


/*
 * ISO base media file format
 * ISO/IEC 14496-12:2008(E)
 */


static u_char *ngx_ts_dash_box_styp(u_char *p);
static u_char *ngx_ts_dash_box_sidx(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_moof(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_mfhd(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_traf(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_tfhd(u_char *p);
static u_char *ngx_ts_dash_box_tfdt(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_trun(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_mdat(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_ftyp(u_char *p);
static u_char *ngx_ts_dash_box_moov(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_mvhd(u_char *p);
static u_char *ngx_ts_dash_box_mvex(u_char *p);
static u_char *ngx_ts_dash_box_trex(u_char *p);
static u_char *ngx_ts_dash_box_trak(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_tkhd(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_mdia(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_mdhd(u_char *p);
static u_char *ngx_ts_dash_box_hdlr(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_minf(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_vmhd(u_char *p);
static u_char *ngx_ts_dash_box_smhd(u_char *p);
static u_char *ngx_ts_dash_box_dinf(u_char *p);
static u_char *ngx_ts_dash_box_dref(u_char *p);
static u_char *ngx_ts_dash_box_url(u_char *p);
static u_char *ngx_ts_dash_box_stbl(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_stts(u_char *p);
static u_char *ngx_ts_dash_box_stsc(u_char *p);
static u_char *ngx_ts_dash_box_stsz(u_char *p);
static u_char *ngx_ts_dash_box_stco(u_char *p);
static u_char *ngx_ts_dash_box_stsd(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_video(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_audio(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_avcc(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box_esds(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_box(u_char *p, const char type[4]);
static u_char *ngx_ts_dash_box_full(u_char *p, const char type[4],
    u_char version, uint32_t flags);
static u_char *ngx_ts_dash_box_update(u_char *p, u_char *ps);

static u_char *ngx_ts_dash_desc_es(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_desc_dec_conf(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_desc_dec_spec(u_char *p, ngx_ts_dash_rep_t *rep);
static u_char *ngx_ts_dash_desc_sl_conf(u_char *p);
static u_char *ngx_ts_dash_desc(u_char *p, u_char tag);
static u_char *ngx_ts_dash_desc_update(u_char *p, u_char *ps);


u_char *
ngx_ts_dash_write_segment_meta(u_char *p, ngx_ts_dash_rep_t *rep)
{
    p = ngx_ts_dash_box_styp(p);
    p = ngx_ts_dash_box_sidx(p, rep);
    p = ngx_ts_dash_box_moof(p, rep);

    return p;
}


u_char *
ngx_ts_dash_write_segment_data(u_char *p, ngx_ts_dash_rep_t *rep)
{
    return ngx_ts_dash_box_mdat(p, rep);
}


u_char *
ngx_ts_dash_write_init_segment(u_char *p, ngx_ts_dash_rep_t *rep)
{
    /* XXX watch buffer size! */

    p = ngx_ts_dash_box_ftyp(p);
    p = ngx_ts_dash_box_moov(p, rep);

    return p;
}


static u_char *
ngx_ts_dash_box_styp(u_char *p)
{
    /* TODO
     * ETSI TS 126 244 V12.3.0 (2014-10)
     * 13.2 Segment types, p. 52
     */

    u_char  *ps = p;

    p = ngx_ts_dash_box(p, "styp");

    /* major_brand */
    p = ngx_cpymem(p, "iso6", 4); /* XXX 3gh9 */

    /* TODO version */
    /* minor_version */
    p = ngx_ts_dash_write32(p, 1);

    /* TODO brands */
    /* compatible_brands */
    p = ngx_cpymem(p, "isom", 4);
    p = ngx_cpymem(p, "iso6", 4);
    p = ngx_cpymem(p, "dash", 4);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_sidx(u_char *p, ngx_ts_dash_rep_t *rep)
{
    /* TODO
     * ETSI TS 126 244 V12.3.0 (2014-10)
     * 13.4 Segment Index Box, p. 53
     */

    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "sidx", 1, 0);

    /* reference_ID */
    p = ngx_ts_dash_write32(p, 1);

    /* timescale */
    p = ngx_ts_dash_write32(p, 90000);

    /* earliest_presentation_time */
    rep->subs.pts = p;
    p = ngx_ts_dash_write64(p, 0);

    /* first_offset */
    p = ngx_ts_dash_write64(p, 0);

    /* reference_count */
    p = ngx_ts_dash_write32(p, 1);

    /* referenced_size */
    rep->subs.moof_mdat = p;
    p = ngx_ts_dash_write32(p, 0);

    /* subsegment_duration */
    rep->subs.duration = p;
    p = ngx_ts_dash_write32(p, 0);

    /* starts_with_SAP, SAP_type, SAP_delta_time */
    p = ngx_ts_dash_write32(p, 0x80000000);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_moof(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    rep->subs.moof = p;

    p = ngx_ts_dash_box(p, "moof");

    p = ngx_ts_dash_box_mfhd(p, rep);
    p = ngx_ts_dash_box_traf(p, rep);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_mfhd(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "mfhd", 0, 0);

    /* sequence_number */
    rep->subs.seq = p;
    p = ngx_ts_dash_write32(p, 0);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_traf(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    rep->subs.traf = p;

    p = ngx_ts_dash_box(p, "traf");

    p = ngx_ts_dash_box_tfhd(p);
    p = ngx_ts_dash_box_tfdt(p, rep);
    p = ngx_ts_dash_box_trun(p, rep);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_tfhd(u_char *p)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "tfhd", 0, 0);

    /* track_ID */
    p = ngx_ts_dash_write32(p, 1);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_tfdt(u_char *p, ngx_ts_dash_rep_t *rep)
{
    /* 
     * ETSI TS 126 244 V12.3.0 (2014-10)
     * 13.5 Track Fragment Decode Time Box, p. 55
     */

    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "tfdt", 1, 0);

    /* baseMediaDecodeTime */
    rep->subs.dts = p;
    p = ngx_ts_dash_write64(p, 0);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_trun(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    uint32_t   flags;

    flags = 0x000001         /* data-offset-present */
            | 0x000100       /* sample-duration-present */
            | 0x000200;      /* sample-size-present */

    if (rep->es->video) {
       flags |= 0x000400     /* sample-flags-present */
                | 0x000800;  /* sample-composition-time-offset-present */
    }

    rep->subs.trun = p;

    ps = p;

    p = ngx_ts_dash_box_full(p, "trun", 0, flags);

    /* sample_count */
    rep->subs.nsamples = p;
    p = ngx_ts_dash_write32(p, 0);

    /* data_offset */
    rep->subs.moof_data = p;
    p = ngx_ts_dash_write32(p, 0);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_mdat(u_char *p, ngx_ts_dash_rep_t *rep)
{

    u_char  *ps = p;

    rep->subs.mdat = p;

    p = ngx_ts_dash_box(p, "mdat");

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_ftyp(u_char *p)
{
    /*
     * ISO/IEC 14496-12:2008(E)
     * 4.3 File Type Box, p. 4
     */

    u_char  *ps = p;

    p = ngx_ts_dash_box(p, "ftyp");

    /* major_brand */
    p = ngx_cpymem(p, "iso6", 4);

    /* minor_version */
    p = ngx_ts_dash_write32(p, 1);

    /* TODO brands */
    /* compatible_brands */
    p = ngx_cpymem(p, "isom", 4);
    p = ngx_cpymem(p, "iso6", 4);
    p = ngx_cpymem(p, "dash", 4);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_moov(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box(p, "moov");

    p = ngx_ts_dash_box_mvhd(p);
    p = ngx_ts_dash_box_mvex(p);
    p = ngx_ts_dash_box_trak(p, rep);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_mvhd(u_char *p)
{
    u_char  *ps = p;

    time_t   now;

    ps = p;

    p = ngx_ts_dash_box_full(p, "mvhd", 0, 0);

    now = ngx_time();

    /* creation_time */
    p = ngx_ts_dash_write32(p, now);

    /* modification_time */
    p = ngx_ts_dash_write32(p, now);

    /* timescale */
    p = ngx_ts_dash_write32(p, 90000);

    /* duration */
    p = ngx_ts_dash_write32(p, 0);

    /* rate */
    p = ngx_ts_dash_write32(p, 0x00010000);

    /* volume */
    p = ngx_ts_dash_write32(p, 0x01000000);

    /* reserved */
    p = ngx_ts_dash_write64(p, 0);

    /* matrix */
    p = ngx_ts_dash_write32(p, 0x00010000);
    p = ngx_ts_dash_write32(p, 0x00000000);
    p = ngx_ts_dash_write32(p, 0x00000000);
    p = ngx_ts_dash_write32(p, 0x00000000);
    p = ngx_ts_dash_write32(p, 0x00010000);
    p = ngx_ts_dash_write32(p, 0x00000000);
    p = ngx_ts_dash_write32(p, 0x00000000);
    p = ngx_ts_dash_write32(p, 0x00000000);
    p = ngx_ts_dash_write32(p, 0x40000000);

    /* pre_defined */
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);

    /* next_track_ID */
    p = ngx_ts_dash_write32(p, 1);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_mvex(u_char *p)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box(p, "mvex");

    p = ngx_ts_dash_box_trex(p);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_trex(u_char *p)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "trex", 0, 0);

    /* track_ID */
    p = ngx_ts_dash_write32(p, 1);

    /* default_sample_description_index */
    p = ngx_ts_dash_write32(p, 1);

    /* default_sample_duration */
    p = ngx_ts_dash_write32(p, 0);

    /* default_sample_size */
    p = ngx_ts_dash_write32(p, 0);

    /* default_sample_flags */
    p = ngx_ts_dash_write32(p, 0);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_trak(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box(p, "trak");

    p = ngx_ts_dash_box_tkhd(p, rep);
    p = ngx_ts_dash_box_mdia(p, rep);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_tkhd(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    time_t   now;

    /* flags: Track_enabled (0x01), Track_in_movie (0x02) */
    p = ngx_ts_dash_box_full(p, "tkhd", 0, 0x03);

    now = ngx_time();

    /* creation_time */
    p = ngx_ts_dash_write32(p, now);

    /* modification_time */
    p = ngx_ts_dash_write32(p, now);

    /* track_ID */
    p = ngx_ts_dash_write32(p, 1);

    /* reserved */
    p = ngx_ts_dash_write32(p, 0);

    /* duration */
    p = ngx_ts_dash_write32(p, 0xffffffff);

    /* reserved */
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);

    /* layer, alternate_group */
    p = ngx_ts_dash_write32(p, 0);

    /* volume */
    p = ngx_ts_dash_write32(p, rep->es->video ? 0x00000000 : 0x01000000);

    /* matrix */
    p = ngx_ts_dash_write32(p, 0x00010000);
    p = ngx_ts_dash_write32(p, 0x00000000);
    p = ngx_ts_dash_write32(p, 0x00000000);
    p = ngx_ts_dash_write32(p, 0x00000000);
    p = ngx_ts_dash_write32(p, 0x00010000);
    p = ngx_ts_dash_write32(p, 0x00000000);
    p = ngx_ts_dash_write32(p, 0x00000000);
    p = ngx_ts_dash_write32(p, 0x00000000);
    p = ngx_ts_dash_write32(p, 0x40000000);

    /* XXX width */
    p = ngx_ts_dash_write32(p, 100 << 16);

    /* XXX height */
    p = ngx_ts_dash_write32(p, 100 << 16);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_mdia(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box(p, "mdia");

    p = ngx_ts_dash_box_mdhd(p);
    p = ngx_ts_dash_box_hdlr(p, rep);
    p = ngx_ts_dash_box_minf(p, rep);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_mdhd(u_char *p)
{
    u_char  *ps = p;

    time_t   now;

    p = ngx_ts_dash_box_full(p, "mdhd", 0, 0);

    now = ngx_time();

    /* creation_time */
    p = ngx_ts_dash_write32(p, now);

    /* modification_time */
    p = ngx_ts_dash_write32(p, now);

    /* timescale */
    p = ngx_ts_dash_write32(p, 90000);

    /* duration */
    p = ngx_ts_dash_write32(p, 0);

    /* language: und */
    p = ngx_ts_dash_write32(p, 0x55c40000);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_hdlr(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "hdlr", 0, 0);

    /* pre_defined */
    p = ngx_ts_dash_write32(p, 0);

    /* handler_type */
    p = ngx_cpymem(p, rep->es->video ? "vide" : "soun", 4);

    /* reserved */
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);

    /* name */
    p = ngx_cpymem(p, rep->es->video ? "video" : "audio", 6);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_minf(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box(p, "minf");

    if (rep->es->video) {
        p = ngx_ts_dash_box_vmhd(p);

    } else {
        p = ngx_ts_dash_box_smhd(p);
    }

    p = ngx_ts_dash_box_dinf(p);
    p = ngx_ts_dash_box_stbl(p, rep);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_vmhd(u_char *p)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "vmhd", 0, 1);

    /* graphicsmode, opcolor */
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_smhd(u_char *p)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "smhd", 0, 0);

    /* balance, reserved */
    p = ngx_ts_dash_write32(p, 0);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_dinf(u_char *p)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box(p, "dinf");

    p = ngx_ts_dash_box_dref(p);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_dref(u_char *p)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "dref", 0, 0);

    /* entry_count */
    p = ngx_ts_dash_write32(p, 1);

    p = ngx_ts_dash_box_url(p);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_url(u_char *p)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "url ", 0, 0x01);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_stbl(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box(p, "stbl");

    p = ngx_ts_dash_box_stsd(p, rep);
    p = ngx_ts_dash_box_stts(p);
    p = ngx_ts_dash_box_stsc(p);
    p = ngx_ts_dash_box_stsz(p);
    p = ngx_ts_dash_box_stco(p);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_stts(u_char *p)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "stts", 0, 0);

    /* entry_count */
    p = ngx_ts_dash_write32(p, 0);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_stsc(u_char *p)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "stsc", 0, 0);

    /* entry_count */
    p = ngx_ts_dash_write32(p, 0);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_stsz(u_char *p)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "stsz", 0, 0);

    /* sample_size */
    p = ngx_ts_dash_write32(p, 0);

    /* sample_count */
    p = ngx_ts_dash_write32(p, 0);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_stco(u_char *p)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "stco", 0, 0);

    /* entry_count */
    p = ngx_ts_dash_write32(p, 0);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_stsd(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "stsd", 0, 0);

    /* entry_count */
    p = ngx_ts_dash_write32(p, 1);
    
    if (rep->es->video) {
        p = ngx_ts_dash_box_video(p, rep);

    } else {
        p = ngx_ts_dash_box_audio(p, rep);
    }

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_video(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    ngx_uint_t   avc1;

    avc1 = (rep->es->type == NGX_TS_VIDEO_AVC);

    p = ngx_ts_dash_box(p, avc1 ? "avc1" : "mp4v");

    /* reserved */
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write16(p, 0);

    /* data_reference_index */
    p = ngx_ts_dash_write16(p, 1);

    /* pre_defined, reserved */
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);

    /* XXX width */
    p = ngx_ts_dash_write16(p, 100);

    /* XXX height */
    p = ngx_ts_dash_write16(p, 100);

    /* horizresolution */
    p = ngx_ts_dash_write32(p, 0x00480000);

    /* vertresolution */
    p = ngx_ts_dash_write32(p, 0x00480000);

    /* reserved */
    p = ngx_ts_dash_write32(p, 0);

    /* frame_count */
    p = ngx_ts_dash_write16(p, 1);

    /* compressorname */
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);

    /* depth */
    p = ngx_ts_dash_write16(p, 0x0018);

    /* pre_defined */
    p = ngx_ts_dash_write16(p, 0xffff);

    if (avc1) {
        p = ngx_ts_dash_box_avcc(p, rep);

    } else {
        p = ngx_ts_dash_box_esds(p, rep);
    }

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_audio(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box(p, "mp4a");

    /* reserved */
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write16(p, 0);

    /* data_reference_index */
    p = ngx_ts_dash_write16(p, 1);

    /* reserved */
    p = ngx_ts_dash_write32(p, 0);
    p = ngx_ts_dash_write32(p, 0);

    /* channel_count */
    p = ngx_ts_dash_write16(p, 2);

    /* samplesize */
    p = ngx_ts_dash_write16(p, 16);

    /* pre_defined, reserved */
    p = ngx_ts_dash_write32(p, 0);

    /* XXX samplerate */
    p = ngx_ts_dash_write32(p, 90000);

    p = ngx_ts_dash_box_esds(p, rep);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_avcc(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    u_char  *sps, *pps;
    size_t   sps_len, pps_len;

    sps_len = rep->sps_len;
    pps_len = rep->pps_len;

    if (sps_len < 4 || pps_len == 0) {
        return p;
    }

    sps = rep->sps;
    pps = rep->pps;

    p = ngx_ts_dash_box(p, "avcC");

    /*
     * ISO/IEC 14496-15:2004(E)
     * 5.2.4.1 AVC decoder configuration record, p. 12
     */

    /* configurationVersion */
    *p++ = 1;

    /* AVCProfileIndication */
    *p++ = sps[1];

    /* profile_compatibility */
    *p++ = sps[2];

    /* AVCLevelIndication */
    *p++ = sps[3];

    /* lengthSizeMinusOne (lengthSize = 4) */
    *p++ = 0xff;

    /* numOfSequenceParameterSets = 1 */
    *p++ = 0xe1;

    /* sequenceParameterSetLength */
    p = ngx_ts_dash_write16(p, sps_len);

    /* sequenceParameterSetNALUnit */
    p = ngx_cpymem(p, sps, sps_len);

    /* numOfPictureParameterSets */
    *p++ = 1;

    /* pictureParameterSetLength */
    p = ngx_ts_dash_write16(p, pps_len);

    /* pictureParameterSetNALUnit */
    p = ngx_cpymem(p, pps, pps_len);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box_esds(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    p = ngx_ts_dash_box_full(p, "esds", 0, 0);

    p = ngx_ts_dash_desc_es(p, rep);

    return ngx_ts_dash_box_update(p, ps);
}


static u_char *
ngx_ts_dash_box(u_char *p, const char type[4])
{
    /*
     * class Box
     * ISO/IEC 14496-12:2008(E)
     * 4.2 Object Structure, p. 4
     */

    /* size */
    p += 4;

    /* type */
    p = ngx_cpymem(p, type, 4);

    return p;
}


static u_char *
ngx_ts_dash_box_full(u_char *p, const char type[4], u_char version,
    uint32_t flags)
{
    /*
     * class Box
     * ISO/IEC 14496-12:2008(E)
     * 4.2 Object Structure, p. 4
     */

    p = ngx_ts_dash_box(p, type);

    /* version */
    *p++ = version;

    /* flags */
    *p++ = (u_char) (flags >> 16);
    *p++ = (u_char) (flags >> 8);
    *p++ = (u_char) flags;

    return p;
}


static u_char *
ngx_ts_dash_box_update(u_char *p, u_char *ps)
{
    ngx_ts_dash_write32(ps, p - ps);

    return p;
}


static u_char *
ngx_ts_dash_desc_es(u_char *p, ngx_ts_dash_rep_t *rep)
{
    /*
     * ISO/IEC 14496-1:2001(E)
     * 8.6.5 ES_Descriptor, p. 28
     */

    u_char  *ps = p;

    p = ngx_ts_dash_desc(p, 0x03);

    /* ES_ID */
    p = ngx_ts_dash_write16(p, 1);

    /* flags */
    *p++ = 0;

    p = ngx_ts_dash_desc_dec_conf(p, rep);
    p = ngx_ts_dash_desc_sl_conf(p);

    return ngx_ts_dash_desc_update(p, ps);
}


static u_char *
ngx_ts_dash_desc_dec_conf(u_char *p, ngx_ts_dash_rep_t *rep)
{
    /*
     * ISO/IEC 14496-1:2001(E)
     * 8.6.6 DecoderConfigDescriptor, p. 30
     */

    u_char  *ps = p;

    p = ngx_ts_dash_desc(p, 0x04);

    /* objectTypeIndication */
    *p++ = ngx_ts_dash_get_oti(rep->es->type);

    /* streamType, upStream, reserved */
    *p++ = (rep->es->video ? 0x04 : 0x05) << 2;

    /* bufferSizeDB */
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;

    /* maxBitrate */
    p = ngx_ts_dash_write32(p, rep->bandwidth * 2);

    /* avgBitrate */
    p = ngx_ts_dash_write32(p, rep->bandwidth);

    p = ngx_ts_dash_desc_dec_spec(p, rep);

    return ngx_ts_dash_desc_update(p, ps);
}


static u_char *
ngx_ts_dash_desc_dec_spec(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char  *ps = p;

    u_char  *a, obj_type, freq_index, chan_conf;

    if (rep->adts == NULL) {
        return p;
    }

    /* TODO
     * AudioSpecificConfig
     * https://wiki.multimedia.cx/index.php/MPEG-4_Audio#Audio_Specific_Config
     */

    a = rep->adts;

    obj_type = (a[2] >> 6) + 1;
    freq_index = (a[2] >> 2) & 0x0f;
    chan_conf = ((a[2] & 0x01) << 2) + (a[3] >> 6);

    if (freq_index == 15) {
        return p;
    }

    p = ngx_ts_dash_desc(p, 0x05);

    *p++ = (obj_type << 3) + (freq_index >> 1);
    *p++ = (freq_index << 7) + (chan_conf << 3);

    return ngx_ts_dash_desc_update(p, ps);
}


static u_char *
ngx_ts_dash_desc_sl_conf(u_char *p)
{
    /*
     * ISO/IEC 14496-1:2001(E)
     * 10.2.3 SL Packet Header Configuration, p. 227
     */

    u_char  *ps = p;

    p = ngx_ts_dash_desc(p, 0x06);

    /* predefined */
    *p++ = 0x02;

    return ngx_ts_dash_desc_update(p, ps);
}


static u_char *
ngx_ts_dash_desc(u_char *p, u_char tag)
{
    *p++ = tag;

    /* size */
    p += 4;

    return p;
}


static u_char *
ngx_ts_dash_desc_update(u_char *p, u_char *ps)
{
    uint32_t  size;

    ps++;

    size = p - ps - 4;

    *ps++ = (size >> 21) | 0x80;
    *ps++ = (size >> 14) | 0x80;
    *ps++ = (size >> 7) | 0x80;
    *ps++ = size & 0x7f;

    return p;
}


u_char *
ngx_ts_dash_write64(u_char *p, uint64_t v)
{
    *p++ = (u_char) (v >> 56);
    *p++ = (u_char) (v >> 48);
    *p++ = (u_char) (v >> 40);
    *p++ = (u_char) (v >> 32);
    *p++ = (u_char) (v >> 24);
    *p++ = (u_char) (v >> 16);
    *p++ = (u_char) (v >> 8);
    *p++ = (u_char) v;

    return p;
}


u_char *
ngx_ts_dash_write32(u_char *p, uint32_t v)
{
    *p++ = (u_char) (v >> 24);
    *p++ = (u_char) (v >> 16);
    *p++ = (u_char) (v >> 8);
    *p++ = (u_char) v;

    return p;
}


u_char *
ngx_ts_dash_write16(u_char *p, uint16_t v)
{
    *p++ = (u_char) (v >> 8);
    *p++ = (u_char) v;

    return p;
}


uint32_t
ngx_ts_dash_read32(u_char *p)
{
    uint32_t  v;

    v = *p++;
    v = (v << 8) + *p++;
    v = (v << 8) + *p++;
    v = (v << 8) + *p;

    return v;
}
