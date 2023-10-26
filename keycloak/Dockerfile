FROM quay.io/keycloak/keycloak:22.0.0 as builder

ENV KC_DB=postgres
ENV KC_FEATURES=declarative-user-profile
ENV KC_HTTP_RELATIVE_PATH=/auth

RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:22.0.0
COPY --from=builder /opt/keycloak/ /opt/keycloak/

ENV KC_HOSTNAME_STRICT=false
ENV KC_HTTP_ENABLED=true
ENV KC_PROXY=edge
ENV KC_HOSTNAME_STRICT_HTTPS=false

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--optimized"]
