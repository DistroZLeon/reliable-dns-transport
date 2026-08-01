# Secure, reliable and resilient DNS Tunneling Protocol

## Overview
This repository contains the source code and the academic paper for a custom, bidirectional Command-and-Control (C2) and data exfiltration protocol built entirely over stateless DNS. 

The primary objective of this project is to provide a reliable transport layer capable of withstanding modern automated network defenses, specifically Response Rate Limiting (RRL) imposed by Internet Service Providers (ISPs) and public resolvers. The tunneling mechanism operates asynchronously using a client-server architecture, encapsulating bidirectional traffic exclusively within DNS TXT records and QNAME queries on UDP port 53.

## Key Features
*   **Reliable Transport Layer:** The system integrates a custom Stop-and-Wait Automatic Repeat Request (ARQ) mechanism to handle packet loss. 
*   **Implicit Traffic Shaping:** The ARQ architecture naturally limits transmission rates to avoid triggering anti-DDoS protections.
*   **Perfect Forward Secrecy (PFS):** Session keys are established using Ephemeral Elliptic Curve Diffie-Hellman (ECDHE) over the SECP256R1 curve.
*   **Authenticated Encryption:** All payload data is encrypted and authenticated using AES-GCM (256-bit).
*   **MitM Prevention:** Mutual authentication during the handshake phase is enforced via HMAC-SHA256 utilizing a Pre-Shared Key (PSK).
*   **Resilient Session Management (AOF Store):** Implements a custom Append-Only File (AOF) storage system that securely logs session states (creation, sequence updates, deletions) using encrypted blobs. This guarantees that active file transfers or command executions can seamlessly resume after a server restart or crash.
*   **Automated Compaction & Garbage Collection:** The AOF system features a background compaction thread that takes state snapshots to prevent log bloat. This works in tandem with an automated Garbage Collector that safely prunes inactive sessions, closes dangling file handles, and prevents resource exhaustion.
*   **Command and Control Capabilities:** The architecture supports concurrent file uploads, file downloads, and remote shell command execution in a secure environment.
*   **Containerized Server:** The server runs in an isolated Docker environment with automatic recovery and session persistence via Volume Binding.

## Repository Structure
*   **`thesisPaper/main.pdf`**: The full bachelor's thesis detailing the theoretical foundation, mathematical constraints, cryptographic choices, and performance evaluation of the protocol.
*   **`server.py`**: Manages the central UDP socket, multiplexes incoming sessions, and routes decrypted packets to the worker pool.
*   **`client.py`**: Generates DNS queries using Scapy, maintains local session state, and orchestrates tasks like uploads, downloads, and commands.
*   **`crypto_utils.py`**: Encapsulates all cryptographic primitives, including ECDHE key generation, HKDF derivation, AES-GCM encryption, and HMAC validation.
*   **`transport.py`**: Provides the binary serialization and deserialization logic for protocol headers and manages data fragmentation.
*   **`worker_pool.py`**: Manages concurrent task execution using dynamic thread pool resizing to prevent server bottlenecks.
*   **AOF Manager (Session Store):** Contains the state-persistence logic, managing the append-only log, performing background compaction, and replaying the encrypted session files upon server initialization.

## Protocol Architecture
Because UDP is inherently stateless and DNS imposes strict payload limitations, this custom protocol serializes every message with a 9-byte header. 

*   **Upstream Traffic (Base32):** Client requests are embedded in QNAMEs. Due to domain length restrictions, the payload size is calculated and capped at 100 bytes.
*   **Downstream Traffic (Base64):** Server responses utilize TXT records encoded in Base64. Leveraging the EDNS extension, downstream chunks are sized at 800 bytes while remaining under the 1232-byte DNS Flag Day 2020 restriction.

## Thesis Reference
For a comprehensive breakdown of the cryptographic implementations, fragmentation mathematics, and performance benchmarks against standard TCP baselines, please refer to `main.pdf`. The paper also includes detailed Wireshark traffic analysis demonstrating the protocol's evasive characteristics.
