# Simplified Transfer Example

This repository contains a simplified example of a transfer application built with Rust, exposed via a JSON api.

The project demonstrates basic transfer functionality with multiple components organized in a workspace structure.

## Components

 -  **Transfer App** (`simple_transfer/transfer_app/`)

    The main application that orchestrates transfers and provides the user interface.

 - **Transfer Library** (`simple_transfer/transfer_library/`)

   Contains the core transfer logic and algorithms.

 - **Transfer NIF** (`simple_transfer/transfer_nif/`)

   Provides native function bindings for performance-critical operations.

 - **Transfer Witness** (`simple_transfer/transfer_witness/`)

   Handles cryptographic proof generation and verification for transfers.

## Building

To build the entire workspace:

```shell
cargo build
```

If you want to use local proving, enable the `gpu` feature flag:

```shell
cargo build --features gpu
```

### Docker

There is a Docker image in the repo to build your own image.

```shell
docker build -t transfer .
```

Run the container as follows. Replace the values as necessary.

```shell
docker run -it --rm -p 8000:8000 --runtime=nvidia --gpus all                        \
  -e API_KEY_ALCHEMY="ovJyhl3KJ0vGe-StM8BQf"                                        \
  -e API_KEY="ovJyhl3KJ0vGe-StM8BQf"                                                \
  -e PRIVATE_KEY="c5de8df2dff5964d9ff981282fea2b5e3bbee6801039f25a426b73d239f8694a" \
  -e ETHERSCAN="SVM9PUWMGKCW1K4U5KFTHAZZCDTF9C5136"                                 \
  -e PROTOCOL_ADAPTER_ADDRESS_SEPOLIA="0xc1CcCff7A03D640F2B25e86e88c9DDFCbD3cF09a"  \
  -e RPC_URL=https://eth-sepolia.g.alchemy.com/v2                                   \
  transfer /bin/bash
```
## Generate example JSON

The application has a flag to generate an example JSON request to mint.

```shell
cargo run -- --mint-example
```

if you have the application running a webserver somewhere, you can pipe the output through to a `curl` request.

```shell
cargo run -- --mint-example | curl -X POST -H "Content-Type: application/json" -d @- http://localhost:8000/api/mint
```