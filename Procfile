pint: set -a && . .env.dev && set +a && until nc -z localhost 8088; do sleep 0.2; done && ./pint
ipa-stub: set -a && . .env.dev && set +a && ./freeipa-stub
caddy: set -a && . .env.dev && set +a && if [ "$PINT_SERVER_URL" = "https://localhost:8443" ]; then caddy reverse-proxy --from https://localhost:8443 --to http://localhost:8080; else sleep infinity; fi
