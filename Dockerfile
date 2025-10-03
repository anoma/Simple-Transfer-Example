FROM nvidia/cuda:13.0.0-devel-ubuntu22.04

# install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    protobuf-compiler \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# install the rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# intall foundry
RUN curl -L https://foundry.paradigm.xyz | bash
ENV PATH="/root/.foundry/bin:${PATH}"
RUN foundryup

# set working directory
WORKDIR /app

# copy your project
COPY . .

# build the rust projects
RUN cargo fetch
RUN cargo build --release --features gpu
RUN cp /app/target/release/transfer_app /app/
RUN rm -rf target

# install risc0
RUN curl -L https://risczero.com/install | bash
ENV PATH="/root/.risc0/bin:${PATH}"
RUN rzup install
RUN rzup install risc0-groth16

# entrypoint of the image
CMD ["/app/transfer_app"]