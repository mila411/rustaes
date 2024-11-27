# Rust AES Implementation - Low-Level Study Repository

This repository serves as a learning platform for implementing low-level algorithms in Rust. The primary focus is on developing a **AES-256 encryption** module **without relying heavily on external crates**, allowing for a deeper understanding of Rust's capabilities and cryptographic principles.

## Features

- **AES-256 Encryption**: A complete implementation of the AES-256 encryption algorithm.
- **Minimal External Dependencies**: Utilizes only essential crates to maintain a lightweight and focused codebase.
- **Educational Purpose**: Designed to help learners grasp low-level programming concepts and cryptographic implementations in Rust.
- **Custom Key Expansion**: Implements the AES key expansion process from scratch.
- **Unit Tests**: Comprehensive tests to ensure the correctness of each component.

## Getting Started

### Prerequisites

- **Rust**: Ensure that Rust is installed on your machine. You can install Rust using [rustup](https://rustup.rs/).

### Installation

1. **Clone the Repository**

```bash
git clone https://github.com/your-username/rustaes.git
cd rustaes
```

1. **Build and Run Project**

```sh
cp .env.example .env
cargo build
$ cargo run                                                   [~/repos/rustaes][main]
   Compiling rustaes v0.1.0 (/Users/kenny/repos/rustaes)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.26s
     Running `target/debug/rustaes`
Encrypted block: [227, 236, 110, 1, 190, 207, 0, 224, 242, 142, 131, 43, 56, 115, 209, 43]
```

1. **Run Tests**

cargo test

## Changes Made

1. **Introduction**:
   - Opened with a clear statement about the repository being a learning platform for low-level Rust implementations, specifically focusing on AES-256 encryption without heavy reliance on external crates.

2. **Features**:
   - Highlighted key aspects such as AES-256 implementation, minimal dependencies, educational purpose, custom key expansion, and unit tests.

3. **Getting Started**:
   - Provided detailed instructions on prerequisites, installation, and running tests to help users set up the project quickly.

4. **Usage**:
   - Explained how to set up the environment using a [.env](http://_vscodecontentref_/0) file, run the encryption process, and gave an example of expected output.

5. **Project Structure**:
   - Outlined the main components of the project to give users an overview of where to find different parts of the codebase.

6. **Contributing**:
   - Encouraged community involvement by welcoming contributions and providing a way to report issues or suggest improvements.

7. **License**:
   - Included a section about licensing to inform users about the legal aspects of using the code.

8. **Acknowledgements**:
   - Gave credit to the AES specification and Rust's features that aid in building the project.

## Acknowledgements

Inspired by the [AES specification (FIPS-197)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf).
Utilizes Rust's powerful type system and ownership model to ensure memory safety and performance.
