# syntax=docker/dockerfile:1.13.0-labs

FROM alpine:3.21 AS guix

RUN apk --no-cache --update add \
      bash \
      bzip2 \
      ca-certificates \
      curl \
      git \
      make \
      shadow

ARG guix_download_path=ftp://ftp.gnu.org/gnu/guix
ARG guix_version=1.4.0
ARG guix_checksum_aarch64=72d807392889919940b7ec9632c45a259555e6b0942ea7bfd131101e08ebfcf4
ARG guix_checksum_x86_64=236ca7c9c5958b1f396c2924fcc5bc9d6fdebcb1b4cf3c7c6d46d4bf660ed9c9
ARG builder_count=32

ENV PATH=/root/.config/guix/current/bin:$PATH

# Application Setup
# https://guix.gnu.org/manual/en/html_node/Application-Setup.html
ENV GUIX_PROFILE=/root/.guix-profile
ENV GUIX_LOCPATH=$GUIX_PROFILE/lib/locale
ENV LC_ALL=en_US.UTF-8

RUN guix_file_name=guix-binary-${guix_version}.$(uname -m)-linux.tar.xz    && \
    eval "guix_checksum=\${guix_checksum_$(uname -m)}"                     && \
    cd /tmp                                                                && \
    wget -q -O "$guix_file_name" "${guix_download_path}/${guix_file_name}" && \
    echo "${guix_checksum}  ${guix_file_name}" | sha256sum -c              && \
    tar xJf "$guix_file_name"                                              && \
    mv var/guix /var/                                                      && \
    mv gnu /                                                               && \
    mkdir -p ~root/.config/guix                                            && \
    ln -sf /var/guix/profiles/per-user/root/current-guix ~root/.config/guix/current && \
    source ~root/.config/guix/current/etc/profile

# Build Environment Setup
# https://guix.gnu.org/manual/en/html_node/Build-Environment-Setup.html

RUN groupadd --system guixbuild
RUN for i in $(seq -w 1 ${builder_count}); do    \
      useradd -g guixbuild -G guixbuild          \
              -d /var/empty -s $(which nologin)  \
              -c "Guix build user ${i}" --system \
              "guixbuilder${i}" ;                \
    done

RUN mkdir base_cache SDKs

RUN guix archive --authorize < ~root/.config/guix/current/share/guix/ci.guix.gnu.org.pub
CMD ["/root/.config/guix/current/bin/guix-daemon","--build-users-group=guixbuild"]

FROM guix AS guix-base

COPY depends /depends/

RUN make -C /depends -j"$(nproc)" download && mv /depends/sources /sources

COPY contrib/guix/manifest.scm /manifest.scm
COPY contrib/guix/patches /patches/

ARG guix_dist_url="https://git.savannah.gnu.org/git/guix.git"
ARG substitute_urls="https://ci.guix.gnu.org"
ARG time_machine_commit=998eda3067c7d21e0d9bb3310d2f5a14b8f1c681

ENV GUIX_DIST_URL="${guix_dist_url}"
ENV TIME_MACHINE_COMMIT="${time_machine_commit}"
ENV SUBSTITUTE_URLS="${substitute_urls}"

RUN --security=insecure \
    guix-daemon --build-users-group=guixbuild & \
    HOST=nil \
    guix time-machine \
        --url="${GUIX_DIST_URL}" \
        --commit="${TIME_MACHINE_COMMIT}" \
        --cores="$(nproc)" \
        --max-jobs="$(nproc)" \
        --substitute-urls="${SUBSTITUTE_URLS}" \
        --fallback \
        -- package --manifest=/manifest.scm \
                   --profile="${GUIX_PROFILE}" && \
    rm -rf /tmp/guix-build-* /tmp/guix-register-* /var/log/guix/drvs

FROM guix-base AS guix-host

ARG HOST
ENV HOST="${HOST}"
ENV HOSTS="${HOST}"
RUN --security=insecure \
    guix-daemon --build-users-group=guixbuild & \
    guix time-machine \
        --url="${GUIX_DIST_URL}" \
        --commit="${TIME_MACHINE_COMMIT}" \
        --cores="$(nproc)" \
        --max-jobs="$(nproc)" \
        --substitute-urls="${SUBSTITUTE_URLS}" \
        --fallback \
        -- package --manifest=/manifest.scm \
                   --profile="${GUIX_PROFILE}" && \
    rm -rf /tmp/guix-build-* /tmp/guix-register-* /var/log/guix/drvs

ARG xcode_download_path="https://bitcoincore.org/depends-sources/sdks/Xcode-12.2-12B45b-extracted-SDK-with-libcxx-headers.tar.gz"
ARG xcode_checksum=df75d30ecafc429e905134333aeae56ac65fac67cb4182622398fd717df77619

RUN if [[ "${HOST}" == "x86_64-apple-darwin" || "${HOST}" == "arm64-apple-darwin" ]]; then \
      wget -q -O /tmp/xcode.tar.gz ${xcode_download_path} && \
      echo "${xcode_checksum}  /tmp/xcode.tar.gz" | sha256sum -c && \
      tar -C /SDKs -xaf /tmp/xcode.tar.gz && \
      rm /tmp/xcode.tar.gz; \
    fi
