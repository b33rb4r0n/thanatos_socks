### Corrected Dockerfile for Thanatos payload
### Comments with 🧩 mark the fixes related to vendoring/offline build

# Note: Invoke this Dockerfile from the `Payload_Type/thanatos` directory using:
#   docker build -t docker.io/mehrn00/thanatos:v0.1.17 -f .docker/Dockerfile .

FROM docker.io/library/fedora:39

# Version of sccache to install
ENV SCCACHE_VERSION v0.7.6

# Install build dependencies
# Install build dependencies
RUN dnf install -y \
    python3.11 \
    python3-pip \
    python3.11-devel \
    mingw64-gcc \
    mingw32-gcc \
    mingw64-gcc-c++ \
    mingw32-gcc-c++ \
    mingw64-winpthreads-static.noarch \
    mingw32-winpthreads-static.noarch \
    libgcc.i686 \
    libatomic-static.i686 \
    libatomic.i686 \
    glibc-devel.i686 \
    openssl-devel \
    openssl-devel.i686 \
    perl-FindBin \
    perl-File-Compare \
    perl-IPC-Cmd \
    perl-File-Copy \
    perl-lib \
    perl-core \                # 🧩 new: provides missing Perl stdlib modules
    perl-Time-Piece \           # 🧩 new: fixes "Can't locate Time/Piece.pm"
    clang \
    curl \
    make \
    musl-gcc \
    musl-libc-static \
    && dnf clean all


RUN python3.11 -m ensurepip

WORKDIR /tmp

# Install Python dependencies for Mythic container integration
COPY requirements.txt .
RUN python3.11 -m pip install -r requirements.txt
RUN rm requirements.txt

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup.sh \
    && sh rustup.sh -y \
    --profile minimal \
    --default-toolchain stable \
    -t x86_64-unknown-linux-gnu \
    -t i686-unknown-linux-gnu \
    -t x86_64-unknown-linux-musl \
    -t x86_64-pc-windows-gnu \
    -t i686-pc-windows-gnu

RUN rm -f rustup.sh

ENV PATH=$PATH:/root/.cargo/bin

# Install sccache for caching Rust builds
RUN curl -L \
    "https://github.com/mozilla/sccache/releases/download/${SCCACHE_VERSION}/sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
    -o sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz
RUN tar xf sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz
RUN mv sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl/sccache /usr/bin/sccache
RUN chmod +x /usr/bin/sccache
RUN rm -rf sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl
RUN rm -f sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz

# Copy Mythic payload framework
WORKDIR /Mythic
COPY main.py main.py
COPY thanatos thanatos

# 🧩 FIX: Copy Cargo config *before* vendoring so we can modify it temporarily
COPY .docker/config.toml /root/.cargo/config.toml

# 🧩 FIX: Fetch and vendor all dependencies (including lazy_static)
# Temporarily remove offline and replace-with settings from Cargo config
# so Cargo can access crates.io during the image build.
# Then restore them afterwards to ensure Mythic builds stay offline.
WORKDIR /Mythic/thanatos/agent_code
RUN sed -i '/offline/d' /root/.cargo/config.toml \
 && sed -i '/replace-with/d' /root/.cargo/config.toml \
 && sed -i '/vendored-sources/d' /root/.cargo/config.toml \
 && cargo fetch && cargo vendor /vendor \
 && echo "" >> /root/.cargo/config.toml \
 && echo "[source.crates-io]" >> /root/.cargo/config.toml \
 && echo "replace-with = \"vendored-sources\"" >> /root/.cargo/config.toml \
 && echo "[source.vendored-sources]" >> /root/.cargo/config.toml \
 && echo "directory = \"/vendor\"" >> /root/.cargo/config.toml \
 && echo "[net]" >> /root/.cargo/config.toml \
 && echo "offline = true" >> /root/.cargo/config.toml

# 🧩 EXPLANATION:
# - We copy .docker/config.toml earlier (so it's present before vendoring)
# - We strip offline/vendor lines temporarily
# - We fetch and vendor crates (includes lazy_static)
# - We restore the offline configuration afterwards
# => Result: /vendor contains all crates and Mythic builds offline successfully

WORKDIR /Mythic

# Configure sccache
ENV SCCACHE_DIR /Mythic/.cache/sccache

CMD ["python3.11", "main.py"]
