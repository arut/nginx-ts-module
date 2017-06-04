*************************
Nginx MPEG-TS Live Module
*************************

The module is under development.


Features
========

- receives MPEG-TS over HTTP
- produces and manages Live HLS
- produces and manages Live MPEG-DASH


Compatibility
=============

- nginx version >= 1.11.5


Build
=====

Things to do after downloading nginx::

    # static module
    > ./configure --add-module=/path/to/nginx-ts-module

    # dynamic module
    > ./configure --add-dynamic-module=/path/to/nginx-ts-module


Example
=======

nginx.conf::

    # nginx.conf

    events {
    }

    http {
        server {
            listen 8000;

            location / {
                root html;
            }

            location /publish/ {
                ts;
                ts_hls /var/hls segment=5s;
                ts_dash /var/dash segment=5s;

                client_max_body_size 0;
            }

            location /hls/ {
                types {
                    application/x-mpegURL m3u8;
                    video/MP2T ts;
                }

                root /var;
            }

            location /dash/ {
                types {
                    application/dash+xml mpd;
                    video/mp4 mp4;
                }

                root /var;
            }
        }
    }

HLS in HTML::

    <body>
      <video width="640" height="480" controls autoplay>
        <source src="http://127.0.0.1:8000/hls/sintel/index.m3u8" type="application/x-mpegURL">
      </video>
    </body>

MPEG-DASH in HTML using dash.js player (https://github.com/Dash-Industry-Forum/dash.js)::

    <script src="http://cdn.dashjs.org/latest/dash.all.min.js"></script>

    <style>
    video {
      width: 640px;
      height: 360px;
    }
    </style>

    <body>
      <div>
        <video data-dashjs-player autoplay src="http://127.0.0.1:8000/dash/sintel/index.mpd" controls></video>
      </div>
    </body>

broadcast mp4 file::

    ffmpeg -re -i ~/Movies/sintel.mp4 -c copy -bsf:v h264_mp4toannexb -f mpegts http://127.0.0.1:8000/publish/sintel

broadcast multi-bitrate mp4 file::

    ffmpeg -re -i ~/Movies/sintel.mp4 -map 0:0 -map 0:1 -map 0:1 -c copy -bsf:v h264_mp4toannexb -program "st=0:st=1" -program "st=2" -f mpegts http://127.0.0.1:8000/publish/sintel
