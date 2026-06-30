FROM python:3.13-slim@sha256:b04b5d7233d2ad9c379e22ea8927cd1378cd15c60d4ef876c065b25ea8fb3bf3 AS umac-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libssl-dev \
    && python3 -m pip install --no-cache-dir setuptools wheel \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY overrides/ssh/umac_ext/ ./

RUN python3 setup.py build_ext --inplace


FROM cowrie/cowrie:3.0@sha256:f5ee0f7d0171cb5d924ae9a96eeb7a3fef876f0217b4052ea22dc3f779691ebe

USER root

COPY --chown=cowrie:cowrie honeyfs /cowrie/cowrie-git/honeyfs
COPY --chown=cowrie:cowrie cowrie.cfg /etc/cowrie/cowrie.cfg
COPY --chown=cowrie:cowrie overrides/commands/__init__.py /cowrie/cowrie-git/src/cowrie/commands/__init__.py
COPY --chown=cowrie:cowrie overrides/commands/rpi4_overrides.py /cowrie/cowrie-git/src/cowrie/commands/rpi4_overrides.py
COPY --chown=cowrie:cowrie overrides/ssh/factory.py /cowrie/cowrie-git/src/cowrie/ssh/factory.py
COPY --chown=cowrie:cowrie overrides/ssh/transport.py /cowrie/cowrie-git/src/cowrie/ssh/transport.py
COPY --from=umac-builder --chown=cowrie:cowrie /build/openssh_umac*.so /cowrie/cowrie-git/src/
COPY assets/moduli /etc/ssh/moduli

USER cowrie
