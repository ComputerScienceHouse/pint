FROM freeradius/freeradius-server:latest-3.2-alpine

# Install radclient for manual status-server queries and debugging.
RUN apk add --no-cache freeradius-utils

# Remove default virtual servers (require local passwd/unix user databases)
# and the bundled EAP module (uses self-signed throwaway certs).
RUN rm -f /etc/raddb/sites-enabled/default \
          /etc/raddb/sites-enabled/inner-tunnel \
          /etc/raddb/mods-enabled/eap \
          /etc/raddb/mods-enabled/unix \
          /etc/raddb/mods-enabled/passwd \
          /etc/raddb/mods-enabled/sradutmp

# RadSec virtual server (TLS listener on 2083 + EAP-TLS processing)
COPY radsec /etc/raddb/sites-available/radsec
COPY status /etc/raddb/sites-available/status

# EAP-TLS module: verifies WiFi user certs against the WiFi CA
COPY eap /etc/raddb/mods-available/eap

# clients.conf wrapper: includes the PINT-managed dynamic client list
COPY clients.conf /etc/raddb/clients.conf

# Ensure enabled dirs exist (rm above may leave them empty on Alpine),
# enable our configs, and create the dynamic clients mount point.
RUN mkdir -p /etc/raddb/sites-enabled \
             /etc/raddb/mods-enabled \
             /etc/freeradius/dynamic && \
    ln -sf /etc/raddb/sites-available/radsec \
           /etc/raddb/sites-enabled/radsec && \
    ln -sf /etc/raddb/sites-available/status \
           /etc/raddb/sites-enabled/status && \
    ln -sf /etc/raddb/mods-available/eap \
           /etc/raddb/mods-enabled/eap

EXPOSE 2083
EXPOSE 18121/udp

CMD ["freeradius", "-f", "-l", "stdout"]
