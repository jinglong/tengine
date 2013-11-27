#!/usr/bin/perl

# Tests for upstream module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(6);

$t->set_dso("ngx_http_fastcgi_module", "ngx_http_fastcgi_module.so");
$t->set_dso("ngx_http_uwsgi_module", "ngx_http_uwsgi_module.so");
$t->set_dso("ngx_http_scgi_module", "ngx_http_scgi_module.so");
$t->set_dso("ngx_http_upstream_ip_hash_module", "ngx_http_upstream_ip_hash_module.so");
$t->set_dso("ngx_http_upstream_least_conn_module", "ngx_http_upstream_least_conn_module.so");

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon         off;

%%TEST_GLOBALS_DSO%%

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream bar {
        server 127.0.0.1:1970 id="localhost:1970";
        server 127.0.0.1:1971 id="localhost:1971";
    }

    resolver 8.8.8.8;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        addrs_keepalive 32;
        addrs_keepalive_timeout 500ms;

        location / {
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $arg_host;
            proxy_pass http://$arg_host;
        }

        location /bar {
            addrs_keepalive 32;
            addrs_keepalive_timeout 500ms;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_pass http://$arg_host/index.html;
        }
    }

    server {
        listen       127.0.0.1:1970;
        server_name  localhost;

        location / {
            index index.html;
        }
    }

    server {
        listen       127.0.0.1:1971;
        server_name  localhost;

        location / {
            index index.html;
        }
    }
}

EOF

$t->write_file('index.html', 'hello, tengine!');

$t->run();

###############################################################################

like(http_get('/?host=www.taobao.com'), qr/200/, 'from taobao servers');
like(http_get('/?host=www.taobao.com'), qr/200/, 'from taobao servers');

like(http_get('/bar?host=bar'), qr/hello, tengine!/, 'get index.html from bar servers');
like(http_get('/bar?host=bar'), qr/hello, tengine!/, 'get index.html from bar servers');

sleep(1);

like(http_get('/?host=www.taobao.com'), qr/200/, 'from taobao servers');

like(http_get('/bar?host=bar'), qr/hello, tengine!/, 'get index.html from bar servers');

###############################################################################
