FROM freeradius/freeradius-server:latest-3.2-alpine

# Remove default virtual servers (require local passwd/unix user databases)
# and the bundled EAP module (uses self-signed throwaway certs).
RUN rm -f /etc/freeradius/3.0/sites-enabled/default \
          /etc/freeradius/3.0/sites-enabled/inner-tunnel \
          /etc/freeradius/3.0/mods-enabled/eap \
          /etc/freeradius/3.0/mods-enabled/unix \
          /etc/freeradius/3.0/mods-enabled/passwd \
          /etc/freeradius/3.0/mods-enabled/sradutmp

# RadSec virtual server (TLS listener on 2083 + EAP-TLS processing)
COPY radsec /etc/freeradius/3.0/sites-available/radsec

# EAP-TLS module — verifies WiFi user certs against the WiFi CA
COPY eap /etc/freeradius/3.0/mods-available/eap

# clients.conf wrapper — includes the PINT-managed dynamic client list
COPY clients.conf /etc/freeradius/3.0/clients.conf

RUN ln -sf /etc/freeradius/3.0/sites-available/radsec \
           /etc/freeradius/3.0/sites-enabled/radsec && \
    ln -sf /etc/freeradius/3.0/mods-available/eap \
           /etc/freeradius/3.0/mods-enabled/eap

# Mount point for the pint-radius-config K8s Secret (clients.conf key).
# Full-directory mount (not subPath) so K8s auto-updates the file when
# the Secret changes; FreeRADIUS picks it up on the next SIGHUP from PINT.
RUN mkdir -p /etc/freeradius/dynamic

EXPOSE 2083

CMD ["freeradius", "-f", "-l", "stdout"]
