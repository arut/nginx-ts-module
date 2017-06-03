*************************
Nginx MPEG-TS Live Module
*************************

The module is under development.


Features
========

- receives MPEG-TS over HTTP
- produces and manages Live HLS


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
        types {
            application/x-mpegURL m3u8;
            video/MP2T ts;
        }

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
                root /var;
            }
        }
    }

index.html::

    <video width="640" height="480" controls autoplay>
        <source src="hls/sintel/index.m3u8" type="application/x-mpegURL">
    </video>

broadcast mp4 file::

    ffmpeg -re -i ~/Movies/sintel.mp4 -c copy -bsf:v h264_mp4toannexb -f mpegts http://127.0.0.1:8000/publish/sintel

broadcast multi-bitrate mp4 file::

    ffmpeg -re -i ~/Movies/sintel.mp4 -map 0:0 -map 0:1 -map 0:1 -c copy -bsf:v h264_mp4toannexb -program "st=0:st=1" -program "st=2" -f mpegts http://127.0.0.1:8000/publish/sintel
