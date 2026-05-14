#!/bin/sh
set -e

RADDB=/tmp/raddb
mkdir -p ${RADDB}/sites-enabled /tmp/radlog /tmp/radrun

# Minimal radiusd.conf for proxy-only operation
cat > ${RADDB}/radiusd.conf << 'EOF'
prefix = /usr
exec_prefix = ${prefix}
sbindir = ${exec_prefix}/sbin
logdir = /tmp/radlog
raddbdir = /tmp/raddb
radacctdir = ${logdir}/radacct
name = radiusd
confdir = ${raddbdir}
modconfdir = /tmp
certdir = /certs
cadir = /certs
run_dir = /tmp/radrun
db_dir = /tmp
libdir = /usr/lib/freeradius
pidfile = ${run_dir}/${name}.pid
max_request_time = 30
cleanup_delay = 5
max_requests = 16384
hostname_lookups = no
log {
    destination = stdout
    stripped_names = no
    auth = yes
}
security {
    max_attributes = 200
    reject_delay = 0
    status_server = yes
}
proxy_requests = yes
$INCLUDE proxy.conf
$INCLUDE clients.conf
thread pool {
    num_workers = 4
}
modules {
}
instantiate {
}
$INCLUDE sites-enabled/
EOF

# home_server pointing to the cluster FreeRADIUS over RadSec
cat > ${RADDB}/proxy.conf << 'EOF'
proxy server {
    default_fallback = no
}

home_server radsec {
    ipaddr = pint-freeradius.pint.svc.cluster.local
    port = 2083
    type = auth
    proto = tcp
    secret = radsec
    max_requests_per_connection = 0
    tls {
        private_key_file = /certs/router.key
        certificate_file = /certs/router.crt
        ca_file           = /certs/radsec-ca.pem
        tls_min_version   = "1.2"
        cipher_list       = "ECDHE+AESGCM:DHE+AESGCM"
        fragment_size     = 8192
    }
}

home_server_pool radsec_pool {
    type = fail-over
    home_server = radsec
}

realm radsec {
    auth_pool = radsec_pool
}
EOF

# Accept eapol_test on loopback — secret must match the -s flag passed to eapol_test
cat > ${RADDB}/clients.conf << 'EOF'
client localhost {
    ipaddr = 127.0.0.1
    proto  = *
    secret = radsec
    require_message_authenticator = no
}
EOF

# Proxy all auth requests to the RadSec realm; no local processing
cat > ${RADDB}/sites-enabled/default << 'EOF'
server default {
    listen {
        type   = auth
        ipaddr = 127.0.0.1
        port   = 1812
        proto  = udp
    }

    authorize {
        update control {
            &Proxy-To-Realm := "radsec"
        }
    }

    post-proxy {
    }
}
EOF

cat > /tmp/eapol.conf << 'EOF'
network={
    eap=TLS
    identity="smoketest"
    ca_cert="/certs/radsec-ca.pem"
    client_cert="/certs/user.crt"
    private_key="/certs/user.key"
}
EOF

echo "==> Starting FreeRADIUS proxy..."
freeradius -X -d ${RADDB} &
RADIUSD_PID=$!

sleep 2

echo "==> Running eapol_test..."
eapol_test -c /tmp/eapol.conf -a 127.0.0.1 -p 1812 -s radsec
STATUS=$?

kill $RADIUSD_PID 2>/dev/null || true
exit $STATUS
