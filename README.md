
# AX520Tool

## Description

AX520Tool is a versatile command-line tool designed for programming firmware onto AX520 series devices via a serial port. It facilitates various operations such as flashing firmware, reading and verifying memory, erasing flash, and managing device execution. Whether you're a developer or an embedded systems enthusiast, AX520Tool streamlines the process of interacting with AX520-based hardware.

## Features

- **Firmware Downloading:** Upload firmware to AX520 devices with precise memory address targeting.
- **Memory Operations:** Read, write, and erase device memory regions.
- **Firmware Verification:** Ensure the integrity of flashed firmware by comparing device memory with source files.
- **Command-Line Interface:** Intuitive and flexible CLI for executing various operations.
- **Progress Indicators:** Real-time feedback during lengthy operations using progress bars.
- **Error Handling:** Comprehensive exception handling to guide users through issues.

## Installation
```bash
pip install ax520tool
```

## Usage

AX520Tool is operated via the command line. Below are the instructions to perform various operations.

### Basic Syntax

```bash
python ax520tool.py -p <serial_port> [options] <command> [command_options]
```

- `-p`, `--port`: **(Required)** Specify the serial port connected to the AX520 device (e.g., `COM3` on Windows or `/dev/ttyUSB0` on Linux).
- `-b`, `--board`: **(Optional)** Specify the board name. Defaults to `M5_TimerCamera520`.
- `-r`, `--reboot`: **(Optional)** Reboot the device after flashing.
- `-c`, `--check`: **(Optional)** Verify firmware after flashing.

### Commands

#### 1. Write Flash

Download firmware to the device.

**Syntax:**

```bash
python ax520tool.py -p <serial_port> write_flash <address1> <firmware1> [<address2> <firmware2> ...]
```

- `<address>`: Starting memory address (hex `0x...` or decimal).
- `<firmware>`: Path to the firmware binary file.

**Example:**

```bash
python ax520tool.py -p COM3 write_flash 0x3000000 firmware.bin
```

#### 2. Read Flash

Read firmware from the device.

**Syntax:**

```bash
python ax520tool.py -p <serial_port> read_flash <address> <size> <output_file>
```

- `<address>`: Starting memory address.
- `<size>`: Number of bytes to read.
- `<output_file>`: Path to save the read firmware.

**Example:**

```bash
python ax520tool.py -p COM3 read_flash 0x3000000 1048576 read_firmware.bin
```

#### 3. Erase Flash

Erase a region of the device's flash memory.

**Syntax:**

```bash
python ax520tool.py -p <serial_port> erase_flash <address> <size>
```

- `<address>`: Starting memory address.
- `<size>`: Number of bytes to erase.

**Example:**

```bash
python ax520tool.py -p COM3 erase_flash 0x3000000 65536
```

## Examples

### Flashing Firmware

Download `firmware.bin` to address `0x3000000` and reboot the device after flashing:

```bash
python ax520tool.py -p COM3 -r write_flash 0x3000000 firmware.bin
```

### Reading Firmware

Read `1MB` of firmware starting from address `0x3000000` and save it to `read_firmware.bin`:

```bash
python ax520tool.py -p COM3 read_flash 0x3000000 1048576 read_firmware.bin
```

### Erasing Flash Memory

Erase `64KB` of flash memory starting at address `0x3000000`:

```bash
python ax520tool.py -p COM3 erase_flash 0x3000000 65536
```

### Verifying Firmware

After flashing, verify the integrity of the firmware:

```bash
python ax520tool.py -p COM3 -c write_flash 0x3000000 firmware.bin
```

**Note:** The `-c` flag enables verification after flashing each file. **It will never check overlapping**.
