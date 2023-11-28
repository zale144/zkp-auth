# ZKP Authentication App

## Overview

The ZKP Authentication App implements a Zero-Knowledge Proof authentication protocol using cryptographic principles. 
This application comprises two main components: a **server** and a **client**. The server manages user registrations and authentications, while the client handles the process of registering and authenticating users without revealing their secrets.

## Features

### Server

**User Registration**: Handles registration requests from clients, storing their public keys securely. <br>
**Authentication Challenge**: Generates and provides a challenge to the client as part of the authentication process. <br>
**Verification**: Validates the client's response to the challenge to authenticate the user. <br>

### Client
**Register**: Generates a unique secret and corresponding public keys, sending the public keys to the server for registration.
**Login**: Initiates an authentication challenge with the server and responds to the server's challenge to complete the authentication process.

## Getting Started

### Prerequisites
- Go (version 1.15 or higher)
- gRPC and Protocol Buffers 

### Installation

Clone the repository:

    git clone https://github.com/zale144/zkp-auth.git

Navigate to the project directory:

    cd zkp-auth

### Running the Server

Navigate to the server directory:
    
    cd server

Build and run the server:
    
    go build
    ./server

### Using the Client

Navigate to the client directory:

    cd client

Build the client:

    go build

Run the client with the desired command:

    ./client register --user user123 --secret secret123
    ./client login --user user123 --secret secret123
