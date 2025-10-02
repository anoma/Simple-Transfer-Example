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

## Generate example JSON

The application has a flag to generate an example JSON request to mint.

```shell
cargo run -- --mint-example
```

if you have the application running a webserver somewhere, you can pipe the output through to a `curl` request.

```shell
cargo run -- --mint-example | curl -X POST -H "Content-Type: application/json" -d @- http://localhost:8000/api/mint
```