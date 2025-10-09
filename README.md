# Simplified Transfer Example

This repository contains a simplified example of a transfer application built
with Rust, exposed via a JSON api.

The project demonstrates basic transfer functionality with multiple components
organized in a workspace structure.

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

Note: CUDA can be tricky, and heavily depends on how your system is configured. You will at least need to know the path
to the cuda library (e.g., `/usr/local/cuda/lib64`) and the path to your cuda binaries (e.g., `/usr/local/cuda-13.
0/bin`). The cuda library path contains files such as `libculibos.a`. The cuda binaries path contains files such as
`cuda-gdb-minimal`. Based on these paths, set the following env vars before compiling.

```
export LD_LIBRARY_PATH=/usr/local/cuda-13.0/lib64:${LD_LIBRARY_PATH}
export PATH=/usr/local/cuda/bin:$PATH
```

## Running

To run the application, some parameters need to be passed via the environment.

| Variable                           | Meaning                                                     | Example                              |
|------------------------------------|-------------------------------------------------------------|--------------------------------------|
| `PRIVATE_KEY`                      | The hex encoded private key for the account                 | 0x00                                 |
| `USER_ADDRESS`                     | The hex encoded address belonging to the private key        | 0x00                                 |
| `API_KEY`                          | API key for Sepolia                                         | supersecret                          |
| `ETHERSCAN`                        | API key for ether scan                                      | supersecret                          |
| `PROTOCOL_ADAPTER_ADDRESS_SEPOLIA` | The hex encoded address of the forwarder contract           | 0x00                                 |
| `BONSAI_API_URL`                   | URL for Bonsai proving                                      | https://api.bonsai.xyz/              |
| `BONSAI_API_KEY`                   | API key for Bonsai                                          | supersecret                          |
| `RPC_URL`                          | URL for blockchain communication                            | https://eth-sepolia.g.alchemy.com/v2 |
| `TOKEN_ADDRESS`                    | The hex encoded address for the token contract (e.g., USDC) | 0x00                                 |
| `PERMIT2_ADDRESS`                  | The hex encoded address for permit2 contract                | 0x00                                 |
| `DEFAULT_AMOUNT`                   | The default amount for example transactions                 | 10                                   |
| `DEADLINE`                         | TODO                                                        | 1893456000                           |
| `FORWARDER_ADDRESS`                | The hex encoded address of the forwarder contract           | 0x00                                 |


To run the application, simply execute `cargo run`. If you want to use local proving, ensure the bonsai environment variables are unset (e.g., `unset BONSAI_API_KEY; unset BONSAI_API_URL`), and run `cargo run --features gpu`.

### Docker

There is a Docker image in the repo to build your own image. Note that the
docker image uses local proving and requires you to install nvidia cuda
container tools.

```shell
docker build -t transfer .
```

Run the container as follows. Replace the values as necessary.

```shell
docker run -it --rm -p 8000:8000 --runtime=nvidia --gpus all transfer
```

## Generate example JSON

The application has a flag to generate an example JSON request to mint.

```shell
cargo run -- --minting-example
```

if you have the application running a webserver somewhere, you can pipe the
output through to a `curl` request.

```shell
cargo run -- --minting-example | curl -X POST -H "Content-Type: application/json" -d @- http://localhost:8000/api/mint
```