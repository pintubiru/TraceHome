# TraceHome

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.18+-00ADD8.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)

**TraceHome** is a lightweight, web-based local network monitoring tool written in **Go (Golang)**. 
It scans your network in real-time, tracks device presence, categorizes users (Family, Guest, IoT), and sends **Telegram notifications** when devices connect or disconnect.

Designed to run on Linux machines (Raspberry Pi, Ubuntu Server, etc.).

## Features

* **Real-time Monitoring**: Detects when devices join or leave the network.
* **Web Dashboard**: Clean, responsive UI to view device status (Online/Offline).
* **Telegram Alerts**: Get instant notifications on your phone via TraceHome Bot.
* **Device Management**:
    * Categorize devices (Family, Guest, IoT).
    * Rename devices for easy identification.
    * View connection history logs.
* **Smart Detection**:
    * Identifies unknown devices.
    * **"Possible Match" Heuristics**: Suggests owners for new devices based on hostname similarity or timing (e.g., if a known device disconnects and a new one appears immediately, it might be the same device with a randomized MAC).
* **Lightweight**: Built with the Gin Framework and uses JSON for local storage (no heavy database required).

## Prerequisites

* **Linux OS** (Debian, Ubuntu, Raspbian, etc.)
* **Go** (Golang) installed (version 1.18 or higher)
* **arp-scan** (System dependency for scanning)

## Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/pintubiru/TraceHome.git
    cd TraceHome
    ```

2.  **Install system dependencies**
    This application relies on `arp-scan` to discover devices.
    ```bash
    sudo apt-get update
    sudo apt-get install arp-scan
    ```

3.  **Install Go dependencies**
    ```bash
    go mod init TraceHome
    go mod tidy
    ```

4.  **Configuration**
    Copy the example environment file:
    ```bash
    cp .env.example .env
    ```
    Open `.env` and configure your settings:
    ```ini
    NETWORK_INTERFACE=eth0      # Your network interface (run 'ip addr' to check)
    APP_PORT=1234               # Port for the web dashboard
    ROUTER_DNS=192.168.1.1      # Your Router IP (for hostname lookup)

    # Telegram Notification (Optional)
    TELEGRAM_BOT_TOKEN=your_bot_token_here
    TELEGRAM_CHAT_ID=your_chat_id_here
    ```

## Usage

Since `arp-scan` requires root privileges to scan the network properly, you must run the application with `sudo`.

### Development Mode
```bash
sudo go run main.go
