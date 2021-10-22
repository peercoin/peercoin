FROM ubuntu:focal as build

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/peercoin*.tar.gz .

RUN set -ex \
  && tar -xzf peercoin*.tar.gz -C /opt \
  && rm -rf /opt/peercoin-*/bin/peercoin-qt \
  && mv /opt/peercoin-* /opt/peercoin

FROM ubuntu:focal

RUN useradd -r peercoin \
  && apt-get update -y \
  && apt-get install -y curl gnupg gosu \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ARG TARGETPLATFORM
ENV PEERCOIN_DATA=/home/peercoin/.peercoin
ENV PATH=/opt/peercoin/bin:$PATH

COPY --from=build /opt /opt

COPY docker-entrypoint.sh /entrypoint.sh

VOLUME ["/home/peercoin/.peercoin"]

EXPOSE 9901 9902 9903 9904

ENTRYPOINT ["/entrypoint.sh"]

CMD ["peercoind"]
