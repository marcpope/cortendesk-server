# Runtime image. The binaries are built ahead of this, per architecture, and
# dropped in `bin/<target arch>/` — cross-compiling on the host is minutes,
# building under emulation is the better part of an hour.
#
# Build one locally with:
#   mkdir -p bin/amd64 && cp target/release/{hbbs,hbbr,cortendesk-utils} bin/amd64/
#   docker build --build-arg TARGETARCH=amd64 -t cortendesk-server .
FROM alpine:3.20

ARG TARGETARCH

COPY bin/${TARGETARCH}/hbbs bin/${TARGETARCH}/hbbr bin/${TARGETARCH}/cortendesk-utils /usr/bin/
RUN chmod +x /usr/bin/hbbs /usr/bin/hbbr /usr/bin/cortendesk-utils

# hbbs keeps its key pair and peer database in the working directory. Upstream
# used /root and every published compose file mounts a volume there, so moving
# it would silently orphan people's keys on upgrade.
WORKDIR /root
VOLUME /root

# hbbs: 21115 NAT test, 21116 tcp+udp signalling, 21118 websocket.
# hbbr: 21117 relay, 21119 websocket.
EXPOSE 21115 21116 21116/udp 21117 21118 21119

CMD ["hbbs"]
