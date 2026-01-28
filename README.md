# Lockness / CGGMP24 HD Wallet Demo

This is a Threshold Signature Scheme (TSS) HD Wallet demo project implemented based on Rust and the `cggmp24` library.

This project demonstrates how to perform Distributed Key Generation (DKG), Hierarchical Deterministic (HD) wallet derivation, pre-signing, and Ethereum transaction signing in a Multi-Party Computation (MPC) environment using the CGGMP24 protocol.

## Features

*   **Distributed Key Generation (DKG)**: 3-party participation (3-of-3) to generate distributed private key shares, supporting HD Wallet (BIP32) extension.
*   **Auxiliary Information Generation (Aux Info)**: Generates and caches Paillier keys and primes used for signing (`pregenerated_primes.json`).
*   **HD Wallet Derivation**:
    *   Demonstrates deriving a child public key from the master public key (path `m/0/0`).
    *   Calculates the corresponding Ethereum address.
*   **Pre-signing**: Generates pre-signature data in an offline phase to accelerate the online signing process.
*   **Transaction Signing**:
    *   Constructs an Ethereum EIP-1559 transaction.
    *   Performs distributed signing on the transaction using derivation path `m/0/0`.
    *   **Note**: The signing process uses pure Local Derivation, requiring no additional network interaction rounds.
*   **Signature Verification & Broadcasting**: Verifies the generated signature and attempts to broadcast it via the Sepolia testnet.
*   **Key Management**:
    *   **Export**: Reconstructs the master private key from shares (Reconstruct).
    *   **Import**: Re-shards a private key using Trusted Dealer mode.

## Prerequisites

*   Rust (latest stable version)
*   Network connection (for accessing Ethereum Sepolia RPC; if inaccessible, errors may occur during Nonce retrieval or broadcasting, but the core MPC flow demonstration remains unaffected)

## Quick Start

1.  **Enter project directory**:
    ```bash
    cd cggmp24-bip32
    ```

2.  **Run demo**:
    ```bash
    cargo run
    ```

## Demo Flow Details

The program automatically executes the following steps upon startup:

1.  **Load/Generate Key Shares**:
    *   Checks for local `key_shares.json`.
    *   If not found, starts 3 simulated nodes to run the DKG protocol.

2.  **Generate Aux Info**:
    *   Checks for `pregenerated_primes.json`.
    *   If not found, generates large primes in parallel (first run may take a few minutes).

3.  **Address Display**:
    *   Displays the Root PubKey and its ETH address.
    *   Calculates and displays the child PubKey and ETH address for path `m/0/0`.

4.  **Pre-signing**:
    *   Each party generates message-independent random numbers (Nonces).

5.  **Construct & Sign Transaction**:
    *   Constructs a transaction destined for Sepolia testnet.
    *   Each party uses `set_derivation_path` to specify path `m/0/0`.
    *   Uses pre-signature data to quickly complete signing.

6.  **Verify & Broadcast**:
    *   Recovers the public key from the signature to verify it matches the `m/0/0` address.
    *   Attempts to broadcast the transaction to the blockchain.

7.  **Key Recovery & Import Demo**:
    *   Demonstrates reconstructing the original private key from scattered Key Shares (for demo purposes only; avoid recovering private keys on a single machine in production).
    *   Demonstrates Trusted Dealer mode: splitting an existing private key into new shares.

## File Description

*   `src/main.rs`: Core logic code.
*   `key_shares.json`: DKG generated key shares cache.
*   `pregenerated_primes.json`: Time-consuming prime generation cache.

## Notes

*   **Simulated Network**: This demo uses in-memory `mpsc` channels to simulate network communication. In a production environment, this needs to be replaced with a real TCP/TLS network layer.
*   **Security**: The code includes private key recovery and printing logic solely for demonstration purposes. In a real production environment, private key shares should be kept strictly confidential, and the full private key should generally not be reconstructed.
---
# Lockness / CGGMP24 HD Wallet Demo

这是一个基于 Rust 和 `cggmp24` 库实现的门限签名 (TSS) HD 钱包演示项目。

本项目展示了如何在多方计算 (MPC) 环境下，使用 CGGMP24 协议进行分布式密钥生成 (DKG)、分层确定性 (HD) 钱包派生、预签名以及以太坊交易签名。

## 功能特性

*   **分布式密钥生成 (DKG)**: 3 方参与 (3-of-3) 生成分布式私钥分片，支持 HD Wallet (BIP32) 扩展。
*   **辅助信息生成 (Aux Info)**: 生成并缓存用于签名的 Paillier 密钥和素数 (`pregenerated_primes.json`)。
*   **HD 钱包派生**:
    *   演示从主公钥派生子公钥 (路径 `m/0/0`)。
    *   计算对应的以太坊地址。
*   **预签名 (Pre-signing)**: 离线阶段生成预签名数据，加速在线签名过程。
*   **交易签名**:
    *   构建以太坊 EIP-1559 交易。
    *   使用派生路径 `m/0/0` 对交易进行分布式签名。
    *   **注意**: 签名过程是纯本地计算派生 (Local Derivation)，无需额外的网络交互轮次。
*   **签名验证与广播**: 验证生成的签名并尝试通过 Sepolia 测试网广播。
*   **密钥管理**:
    *   **导出**: 从分片恢复主私钥 (Reconstruct)。
    *   **导入**: 使用 Trusted Dealer 模式将私钥重新分片。

## 运行前提

*   Rust (最新稳定版)
*   网络连接 (用于访问 Ethereum Sepolia RPC，若无法访问可能会在获取 Nonce 或广播时报错，但不影响 MPC 核心流程演示)

## 快速开始

1.  **进入项目目录**:
    ```bash
    cd cggmp24-bip32
    ```

2.  **运行演示**:
    ```bash
    cargo run
    ```

## 演示流程详解

程序启动后会自动执行以下步骤：

1.  **加载/生成密钥分片**:
    *   检查本地是否存在 `key_shares.json`。
    *   若不存在，启动 3 个模拟节点运行 DKG 协议生成密钥。

2.  **生成辅助素数 (Aux Info)**:
    *   检查 `pregenerated_primes.json`。
    *   若不存在，并行生成大素数（首次运行可能需要几分钟）。

3.  **地址展示**:
    *   显示主公钥 (Root PubKey) 及其 ETH 地址。
    *   计算并显示路径 `m/0/0` 对应的子公钥及 ETH 地址。

4.  **预签名 (Pre-signing)**:
    *   各方生成与消息无关的随机数 (Nonces)。

5.  **构建与签名交易**:
    *   构建一笔发往 Sepolia 测试网的交易。
    *   各方使用 `set_derivation_path` 指定路径 `m/0/0`。
    *   利用预签名数据快速完成签名。

6.  **验证与广播**:
    *   从签名中恢复公钥，验证是否与 `m/0/0` 地址匹配。
    *   尝试广播交易到区块链。

7.  **密钥恢复与导入演示**:
    *   演示如何将分散的 Key Shares 重组成原始私钥 (仅用于演示，生产环境应避免在单一机器恢复私钥)。
    *   演示 Trusted Dealer 模式：将一个现有私钥拆分为新的分片。

## 文件说明

*   `src/main.rs`: 核心逻辑代码。
*   `key_shares.json`: DKG 生成的密钥分片缓存。
*   `pregenerated_primes.json`: 耗时的素数生成缓存。

## 注意事项

*   **模拟网络**: 本演示使用内存中的 `mpsc` 通道模拟网络通信。在生产环境中，需要替换为真实的 TCP/TLS 网络层。
*   **安全性**: 代码中包含私钥恢复和打印逻辑仅用于演示目的。在实际生产环境中，私钥分片应严格保密，且通常不应恢复出完整私钥。