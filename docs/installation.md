---
title: Installation & Build
layout: default
nav_order: 4
---

# Installation & Build

## Prerequisites

```bash
# Android NDK
export NDK=$HOME/Library/Android/sdk/ndk/26.3.11579264

# CMake
brew install cmake  # macOS
# or
sudo apt-get install cmake  # Linux

# ADB (Android SDK Platform Tools)
```

## Building

```bash
# Clone repository
git clone <repo_url>
cd renef

# Setup dependencies (Lua + Capstone)
make setup

# Build everything (client + server + payload)
make all

# Or build in release mode (optimized, stripped)
make release

# Deploy to Android device
make deploy

# Deploy and setup port forwarding
make install
```

## Build Targets

- `make all` - Build client, server, and payload
- `make client` - Build only the CLI client
- `make server` - Build only the Android server
- `make payload` - Build only the agent payload (libagent.so)
- `make setup` - Setup Lua and Capstone dependencies
- `make deploy` - Push server and payload to /data/local/tmp/
- `make install` - Deploy and setup adb port forwarding
- `make clean` - Clean build artifacts
- `make release` - Build in release mode (optimized)
- `make debug` - Build in debug mode (symbols + logging)

## Deployment

After building, deploy to your Android device:

```bash
# Deploy server and payload
make deploy

# Start server on device
adb shell /data/local/tmp/renef_server

# In another terminal, run client
./build/renef
```
