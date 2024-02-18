# syntax=docker/dockerfile:1.3-labs
FROM alpine:3.19 AS guix

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

ENV PATH /root/.config/guix/current/bin:$PATH

# Application Setup
# https://guix.gnu.org/manual/en/html_node/Application-Setup.html
ENV GUIX_LOCPATH /root/.guix-profile/lib/locale
ENV LC_ALL en_US.UTF-8

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

# Guix expects this file to exist
RUN touch /etc/nsswitch.conf

RUN guix archive --authorize < ~root/.config/guix/current/share/guix/ci.guix.gnu.org.pub

# Build Environment Setup
# https://guix.gnu.org/manual/en/html_node/Build-Environment-Setup.html

RUN groupadd --system guixbuild
RUN for i in $(seq -w 1 ${builder_count}); do    \
      useradd -g guixbuild -G guixbuild          \
              -d /var/empty -s $(which nologin)  \
              -c "Guix build user ${i}" --system \
              "guixbuilder${i}" ;                \
    done

CMD ["/root/.config/guix/current/bin/guix-daemon","--build-users-group=guixbuild"]
WORKDIR /build

COPY manifest.scm .
COPY patches patches

FROM guix AS guix-base

ARG time_machine_commit=998eda3067c7d21e0d9bb3310d2f5a14b8f1c681
ARG substitute_urls="https://ci.guix.gnu.org"

ARG JOBS
ENV JOBS="${JOBS}"
ENV HOST=nil
RUN --security=insecure guix-daemon --build-users-group=guixbuild & \
    guix time-machine --url=https://git.savannah.gnu.org/git/guix.git \
                      --commit=$time_machine_commit \
                      --cores="${JOBS}" \
                      --keep-failed \
                      --fallback \
                      --substitute-urls=$substitute_urls \
                      -- environment --manifest="${PWD}/manifest.scm" \
                                     --container \
                                     --pure \
                                     --no-cwd \
                                     --cores="${JOBS}" \
                                     --keep-failed \
                                     --fallback \
                                     --link-profile \
                                     --substitute-urls=$substitute_urls \
                                     -- env HOST="${HOST}" \
                                            JOBS="${JOBS}"

FROM guix-base AS guix-host

ARG HOST
ENV HOST="${HOST}"
RUN --security=insecure guix-daemon --build-users-group=guixbuild & \
    guix time-machine --url=https://git.savannah.gnu.org/git/guix.git \
                      --commit=$time_machine_commit \
                      --cores="${JOBS}" \
                      --keep-failed \
                      --fallback \
                      --substitute-urls=$substitute_urls \
                      -- environment --manifest="${PWD}/manifest.scm" \
                                     --container \
                                     --pure \
                                     --no-cwd \
                                     --cores="${JOBS}" \
                                     --keep-failed \
                                     --fallback \
                                     --link-profile \
                                     --substitute-urls=$substitute_urls \
                                     -- env HOST="${HOST}" \
                                            JOBS="${JOBS}"
