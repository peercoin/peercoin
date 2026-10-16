# syntax=docker/dockerfile:1.13.0-labs

FROM alpine:3.24 AS guix

RUN apk --no-cache --update add \
      bash \
      bzip2 \
      ca-certificates \
      curl \
      git \
      make \
      shadow

ARG guix_download_path=https://ftp.gnu.org/gnu/guix
ARG guix_version=1.5.0
ARG guix_checksum_aarch64=a5d58b1d0294cad6adb1f2aff627d37feb5db763fdffbceb8551f2b12123cf39
ARG guix_checksum_x86_64=aa41025489c5061543e9c48873eaa829b900b2da75d40f9648913622f5f47817
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

ARG guix_dist_url="https://codeberg.org/guix/guix.git"
ARG substitute_urls="https://ci.guix.gnu.org"
ARG time_machine_commit=5cb84f2013c5b1e48a7d0e617032266f1e6059e2

ENV GUIX_DIST_URL="${guix_dist_url}"
ENV TIME_MACHINE_COMMIT="${time_machine_commit}"
ENV SUBSTITUTE_URLS="${substitute_urls}"

RUN --security=insecure \
    --mount=type=bind,src=contrib/guix/manifest.scm,dst=/manifest.scm \
    --mount=type=bind,src=contrib/guix/patches,dst=/patches \
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
                   --profile="${GUIX_PROFILE}"

FROM guix-base AS guix-host

ARG HOST
ENV HOST="${HOST}"
ENV HOSTS="${HOST}"
RUN --security=insecure \
    --mount=type=bind,src=contrib/guix/manifest.scm,dst=/manifest.scm \
    --mount=type=bind,src=contrib/guix/patches,dst=/patches \
    guix-daemon --build-users-group=guixbuild & \
    guix time-machine \
        --url="${GUIX_DIST_URL}" \
        --commit="${TIME_MACHINE_COMMIT}" \
        --cores="$(nproc)" \
        --max-jobs="$(nproc)" \
        --substitute-urls="${SUBSTITUTE_URLS}" \
        --fallback \
        -- package --manifest=/manifest.scm \
                   --profile="${GUIX_PROFILE}"

RUN --mount=type=bind,src=depends,dst=/depends,rw \
    --mount=type=bind,src=src/ipc/libmultiprocess,dst=/src/ipc/libmultiprocess \
    make -C /depends HOST="${HOST}" -j"$(nproc)" download-one && mv /depends/sources /sources

ARG xcode_download_path="https://bitcoincore.org/depends-sources/sdks/Xcode-26.1.1-17B100-extracted-SDK-with-libcxx-headers.tar"
ARG xcode_checksum=9600fa93644df674ee916b5e2c8a6ba8dacf631996a65dc922d003b98b5ea3b1

RUN if [[ "${HOST}" == "x86_64-apple-darwin" || "${HOST}" == "arm64-apple-darwin" ]]; then \
      wget -q -O /tmp/xcode.tar ${xcode_download_path} && \
      echo "${xcode_checksum}  /tmp/xcode.tar" | sha256sum -c && \
      tar -C /SDKs -xaf /tmp/xcode.tar && \
      rm /tmp/xcode.tar; \
    fi

FROM guix-host AS guix-host-depends-cache

COPY base_cache/ /base_cache/
