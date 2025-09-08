# Simplified Transfer Example

This repository contains a simplified example of a transfer application built with Rust. The project demonstrates basic transfer functionality with multiple components organized in a workspace structure.

## Project Structure

- `simple_transfer/transfer_app/` - Main transfer application
- `simple_transfer/transfer_library/` - Core transfer library with business logic
- `simple_transfer/transfer_nif/` - Native Implemented Functions (NIF) bindings
- `simple_transfer/transfer_witness/` - Witness generation and verification

## Building

To build the entire workspace:

```shell
cargo build
```

To run the transfer application:

```shell
cargo run --bin transfer_app
```

## Components

### Transfer App
The main application that orchestrates transfers and provides the user interface.

### Transfer Library
Contains the core transfer logic and algorithms.

### Transfer NIF
Provides native function bindings for performance-critical operations.

### Transfer Witness
Handles cryptographic proof generation and verification for transfers.