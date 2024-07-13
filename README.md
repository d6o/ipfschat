# IPFSChat

IPFSChat is a decentralized chat application built on the InterPlanetary File System (IPFS) using Go. It leverages IPFS
PubSub for message distribution and Diffie-Hellman key exchange for secure communication.

![demo-gif](./demo.gif)

## Features

- Decentralized messaging using IPFS PubSub
- Secure communication with Diffie-Hellman key exchange
- AES-GCM encryption for message confidentiality
- Terminal-based user interface with `tview` and `tcell`

## Requirements

- Go 1.16+
- IPFS node with pubsub

## Installation

1. Clone the repository:

```sh
git clone https://github.com/d6o/ipfschat.git
cd ipfschat
```

2. Install dependencies:

```sh
go mod tidy
```

3. Run the application:

```sh
go run main.go <topic>
```

Replace `<topic>` with the desired chat topic.

## Usage

1. Start your IPFS daemon:

```sh
ipfs daemon
```

2. Run the IPFSChat application with a topic of your choice:

```sh
go run main.go mytopic
```

3. Use the terminal interface to send and receive messages securely.

## Code Overview

The main components of IPFSChat include:

- **DHKey Exchange**: Uses the `dhkx` library for Diffie-Hellman key exchange to establish shared secrets with peers.
- **IPFS PubSub**: Utilizes the IPFS PubSub system to publish and subscribe to messages on a specified topic.
- **Encryption**: Messages are encrypted with AES-GCM using the shared secret derived from the Diffie-Hellman exchange.
- **Terminal UI**: The user interface is built using `tview` and `tcell`, providing a text-based UI for interaction.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License.
