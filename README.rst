*************************
NGINX MPEG-TS Live Module
*************************


.. contents::


Features
========

- receives MPEG-TS over HTTP
- produces and manages live HLS
- produces and manages live MPEG-DASH


Compatibility
=============

- `nginx <http://nginx.org>`_ version >= 1.11.5


Build
=====

Building nginx with the module:

.. code-block:: bash

    # static module
    $ ./configure --add-module=/path/to/nginx-ts-module

    # dynamic module
    $ ./configure --add-dynamic-module=/path/to/nginx-ts-module


Directives
==========

ts
--

========== ========
*Syntax:*  ``ts``
*Context:* location
========== ========

Sets up a live MPEG-TS handler for the location.
This directive is **required** for HLS or MPEG-DASH generation.

The last URI component is used as a stream name.
For example, if the URI is ``/foo/bar/baz``, the stream name is ``baz``.

A simple way to stream MPEG-TS over HTTP is by running ``ffmpeg``:

.. code-block:: bash
  
    $ ffmpeg -re -i /path/to/foo.mp4 -c copy -bsf:v h264_mp4toannexb -f mpegts http://127.0.0.1:8000/foo


By default, HTTP request body size is limited in nginx.
To enable live streaming without size limitation, use the directive
``client_max_body_size 0``.


ts_hls
------

========== ========
*Syntax:*  ``ts_hls path=PATH [segment=MIN[:MAX]] [segments=NUMBER] [max_size=SIZE] [noclean]``
*Context:* location
========== ========

Enables generating live HLS in the location.
The ``PATH`` parameter specifies a directory where HLS playlist and segment
files will be created.
The directory is created if missing.
For every publshed stream a subdirectory with the stream name is created under
the ``PATH`` directory.
The HLS playlist file created in the stream subdirectory is named
``index.m3u8``.
A path handler is installed to watch files in the directory.
The old files in the directory are automatically deleted once they get old
enough and are not supposed to be accessed by clients anymore.
It is not allowed to reuse the path in other ``ts_hls`` or ``ts_dash``
directives.

The ``segment`` parameter specifies minimum and maximum segment durations.
Normally, if a stream has video, segments are started at video key frames.
If a key frame does not appear within ``MAX`` duration, the segment is
truncated.
The default value for minimum segment duration is 5 seconds.
If unspecified, maximum segment duration is set to be twice as much as the
minimum.

The ``segments`` parameter specifies the maximum number of segments in a
playlist.
As new segments are added to the playlist, the oldest segments are removed from
it.

The ``max_size`` parameter specifies the maximum size of a segment.
A segment is truncated once it reaches this size.

The ``noclean`` parameter indicates that the old files (segments and the
playlist) should not be automatically removed.

Example::

    location / {
        ts;
        ts_hls path=/var/hls segment=10s;
    }


ts_dash
-------

========== ========
*Syntax:*  ``ts_dash path=PATH [segment=MIN[:MAX]] [segments=NUMBER] [analyze=DURATION] [max_size=SIZE] [noclean]``
*Context:* location
========== ========

Enables generating live MPEG-DASH in the location.


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
                ts_hls path=/var/hls segment=5s;
                ts_dash path=/var/dash segment=5s;

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

HLS in HTML:

.. code-block:: html

    <body>
      <video width="640" height="480" controls autoplay>
        <source src="http://127.0.0.1:8000/hls/sintel/index.m3u8" type="application/x-mpegURL">
      </video>
    </body>

MPEG-DASH in HTML using the `dash.js player <https://github.com/Dash-Industry-Forum/dash.js>`_:

.. code-block:: html

    <script src="http://cdn.dashjs.org/latest/dash.all.min.js"></script>

    <style>
    video {
      width: 640px;
      height: 480px;
    }
    </style>

    <body>
      <div>
        <video data-dashjs-player autoplay src="http://127.0.0.1:8000/dash/sintel/index.mpd" controls></video>
      </div>
    </body>

Broadcasting a simple mp4 file:

.. code-block:: bash

    $ ffmpeg -re -i ~/Movies/sintel.mp4 -c copy -bsf:v h264_mp4toannexb -f mpegts http://127.0.0.1:8000/publish/sintel

Broadcasting a multi-bitrate mp4 file:

.. code-block:: bash

    $ ffmpeg -re -i ~/Movies/sintel.mp4 -map 0:0 -map 0:1 -map 0:1 -c copy -bsf:v h264_mp4toannexb -program "st=0:st=1" -program "st=2" -f mpegts http://127.0.0.1:8000/publish/sintel
