#!/bin/bash

if [ ! -f /.dockerenv ]; then
    echo "This is supposed to be run in a docker env";
    exit
fi

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

cat > /etc/supervisor/conf.d/supervisord.conf <<EOF
[supervisord]
nodaemon=true

[program:app]
command=stdbuf -o0 gunicorn -w 8 server:app -b unix:/tmp/gunicorn.sock --user app --access-logfile -
directory=/server
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
autorestart=true
user=app

[program:nginx]
command=/usr/sbin/nginx -g 'daemon off;'
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
autorestart=true
EOF

cat > /etc/nginx/sites-enabled/default <<EOF
server {
    listen 80;

    underscores_in_headers on;

    location / {
        include proxy_params;
        proxy_pass http://unix:/tmp/gunicorn.sock;
        proxy_pass_request_headers on;

        location ^~ /admin/ {
            deny all;
        }
    }
}

EOF

