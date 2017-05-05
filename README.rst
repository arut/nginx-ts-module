*************************
Nginx MPEG-TS Live Module
*************************

The module is under development.

Build
=====

Things to do after downloading nginx::

    # static module
    > ./configure --add-module=/path/to/nginx-ts-module

    # dynamic module
    > ./configure --add-dynamic-module=/path/to/nginx-ts-module
 

Example
=======

Example #1::

    # nginx.conf

    events {
    }

    http {
        server {
            listen 8000;
            location / {
                ts;
            }
        }
    }
