import logging
import serial
import struct
import time
import argparse
import os
from tqdm import tqdm

# Configure logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AX520ToolException(Exception):
    def __init__(self, message):
        super().__init__(message)
    
    class InvalidFlashRange(Exception):
        def __init__(self, value, def_range):
            message = f'Address {value:#010x} is not within valid range of {def_range[0]:#010x}:{def_range[1]:#010x}'
            super().__init__(message)
    
    class InvalidNumberFormat(Exception):
        def __init__(self, value):
            message = f'Input \'{value}\' is not a valid number, it need to be hex, dec or partition name.'
            super().__init__(message)

class AX520BoardHelper:
    BOARD_DEFS = {
        'M5_TimerCamera520':{
            'flash_size': 0xF42400,
            'flash_start_addr': 0x3000000,
            'flash_range': (0x3000000, 0x3F42400),
            'partition': {
                'miniboot': 0x3000000,
                'uboot': 0x3010000,
                'kernel': 0x3080000,
                'rootfs': 0x3080000
            }
        }
    }

    def __init__(self, board_name='M5_TimerCamera520'):
        self.board_name = board_name
        if board_name not in self.BOARD_DEFS:
            logger.warning(f'Unable to locate the board {board_name}, falling back to default.')
            self.board_name = 'M5_TimerCamera520'
        self.defs = self.BOARD_DEFS[self.board_name]

    @staticmethod
    def in_range(value, range):
        return (value >= range[0] and value <= range[1])

    def check_flash_addr(self, addr, end_addr=None, size=None):
        if not self.in_range(addr, self.defs['flash_range']):
            raise AX520ToolException.InvalidFlashRange(addr, self.defs['flash_range'])
        
        if end_addr is not None:
            if not self.in_range(end_addr, self.defs['flash_range']):
                raise AX520ToolException.InvalidFlashRange(end_addr, self.defs['flash_range'])
        
        if size is not None:
            if not self.in_range(addr+size, self.defs['flash_range']):
                raise AX520ToolException.InvalidFlashRange(addr+size, self.defs['flash_range'])
        
        return True

    def number_helper(self, number_or_str):
        number_or_str = number_or_str.strip()

        # Check if partion name
        if number_or_str in self.defs['partition']:
            return self.defs['partition'][number_or_str]

        # Check if hex
        if number_or_str[:2] == '0x':
            return int(number_or_str, 16)
        
        try:
            return int(number_or_str)
        except:
            raise AX520ToolException.InvalidNumberFormat(number_or_str)


class AX520Programmer:
    """AX520 Programmer for firmware operations over a serial port."""

    START_BYTE = b'\x02'
    END_BYTE = b'\x03'

    # Command codes
    HDBOOT_NOTIFY = 36
    MINIBOOT_NOTIFY = 117
    DEBUG_CMD = 20
    DLOAD_CMD = 24
    WRITE_CMD = 25
    READ_CMD = 26
    RUN_CMD = 27
    ERASE_CMD = 69
    EXECPROG_CMD = 29
    ACK_OK = 5
    ACK_ERR = 10

    MAX_BUFFER_SIZE = 256  # As per the device protocol

    def __init__(self, port_name, timeout=0.1):
        """Initialize the programmer with the specified serial port and timeout."""
        self.port_name = port_name
        self.timeout = timeout
        self.serial_port = None
        self.handshook = False
        self.boot_mode = None  # To distinguish between HDBOOT and MINIBOOT modes

    def open_connection(self):
        """Open the serial port connection."""
        try:
            self.serial_port = serial.Serial(
                port=self.port_name,
                baudrate=115200,
                timeout=self.timeout,
                write_timeout=self.timeout,
            )
            logger.debug(f"Opened serial port {self.port_name}")
            return self.serial_port.isOpen()
        except Exception as e:
            logger.error(f"Error opening serial port: {e}")
            return False

    def close_connection(self):
        """Close the serial port connection."""
        if self.serial_port and self.serial_port.isOpen():
            self.serial_port.close()
            self.serial_port = None
            logger.debug("Serial port closed")

    def _send(self, cmd, payload=b''):
        """Send a command with an optional payload to the device."""
        checksum = 0
        if payload:
            for b in payload:
                checksum = (checksum + b) & 0xFF
        data = self.START_BYTE + bytes([cmd]) + bytes([checksum]) + self.END_BYTE + payload
        try:
            self.serial_port.write(data)
            logger.debug(f"Sent command {cmd} with payload length {len(payload)}")
            return True
        except Exception as e:
            logger.error(f"Error sending data: {e}")
            return False

    def _recv(self, expected_cmd=None, timeout=None, len=0):
        """Receive a command from the device."""
        start_time = time.time()
        stack = []
        recevied_len = 0
        while True:
            if timeout and (time.time() - start_time) > timeout:
                logger.debug("Receive timeout")
                return None
            c = self.serial_port.read(1)
            if not c:
                continue
            if c != self.START_BYTE:
                continue
            cmd = self.serial_port.read(1)
            if not cmd:
                continue
            cmd = cmd[0]
            checksum = self.serial_port.read(1)
            if not checksum:
                continue
            end_byte = self.serial_port.read(1)
            if end_byte != self.END_BYTE:
                continue
            if len > 0:
                # Drop an unknown byte
                while len - recevied_len > 0:
                    stack.append(self.serial_port.read(1)[0])
                    recevied_len += 1
                    # logger.debug(f"RCV LEN: {recevied_len}")
            logger.debug(f"Received command {cmd}")
            if expected_cmd and cmd != expected_cmd:
                logger.error(f"Expected command {expected_cmd}, but received {cmd}")
                return None
            if len > 0:
                return cmd, stack
            else:
                return cmd

    def handshake(self, timeout=10):
        """Perform handshake with the device."""
        start_time = time.time()
        while not self.handshook and (time.time() - start_time) < timeout:
            ack = self._recv(timeout=1)
            if ack == self.HDBOOT_NOTIFY:
                logger.debug("Received HDBOOT_NOTIFY")
                self.boot_mode = 'HDBOOT'
                self.serial_port.reset_input_buffer()
                self.serial_port.reset_output_buffer()
                self._send(self.DEBUG_CMD)
                ack = self._recv(expected_cmd=self.ACK_OK, timeout=1)
                if ack == self.ACK_OK:
                    logger.info("Handshake successful")
                    self.handshook = True
                    return True
                else:
                    logger.error(f"Unexpected ACK: {ack}")
            elif ack == self.MINIBOOT_NOTIFY:
                logger.debug("Received MINIBOOT_NOTIFY")
                self.boot_mode = 'MINIBOOT'
                self.serial_port.reset_input_buffer()
                self.serial_port.reset_output_buffer()
                self._send(self.DEBUG_CMD)
                # In MINIBOOT mode, the device may not respond to DEBUG_CMD with ACK_OK
                logger.info("Handshake successful in MINIBOOT mode")
                self.handshook = True
                return True
            else:
                logger.info("Waiting for device notify...")
        logger.error("Handshake failed")
        return False

    def erase(self, address, size):
        """Erase a memory region starting at the specified address."""
        # The size needs to be divided by 4 as per protocol (size in words)
        payload = struct.pack('>II', address, size // 4)
        if not self._send(self.ERASE_CMD, payload):
            logger.error("Failed to send ERASE command")
            return False
        # Erase can take longer, so increase timeout
        ack = self._recv(expected_cmd=self.ACK_OK, timeout=20)
        if ack == self.ACK_OK:
            logger.debug(f"Memory erased at address {address:#010x}, size {size:#010x} bytes")
            return True
        else:
            logger.error("Erase operation failed")
            return False

    def _calc_crc8(self, data):
        """Calculate CRC-8 checksum for the given data."""
        crc = 0
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if (crc & 0x8000):
                    crc ^= (0x1070 << 3)
                crc <<= 1
        return (crc >> 8) & 0xFF

    def _download_chunk(self, address, data):
        """Download a chunk of data to the specified address."""
        size = len(data)
        # As per protocol, size needs to be specified in words (32-bit words)
        word_count = size // 4
        payload = struct.pack('>II', address, word_count) + data
        if not self._send(self.DLOAD_CMD, payload):
            return False
        ack = self._recv(timeout=1)
        if ack == self.ACK_OK:
            logger.debug(f"Chunk downloaded to address {address:#010x}")
            return True
        else:
            logger.error("Failed to download chunk")
            return False

    def execprog(self, address, size_with_crc):
        """Execute the program at the specified address with size and CRC."""
        payload = struct.pack('>II', address, size_with_crc)
        if not self._send(self.EXECPROG_CMD, payload):
            logger.error("Failed to send EXECPROG command")
            return False
        ack = self._recv(timeout=1)
        if ack == self.ACK_OK:
            logger.debug("EXECPROG command acknowledged")
            return True
        else:
            logger.error("Failed to execute program")
            return False

    def download_firmware(self, address, firmware_data, autostart=False):
        """Download firmware data to the device starting at the specified address."""
        # Ensure firmware data is 4-byte aligned
        if len(firmware_data) % 4 != 0:
            padding = b'\xFF' * (4 - len(firmware_data) % 4)
            firmware_data += padding
            logger.debug(f"Firmware data padded with {len(padding)} bytes")

        total_size = len(firmware_data)
        pos = 0
        chunk_size = self.MAX_BUFFER_SIZE
        exec_size = 0
        chk_buf = b""
        page_addr = address
        page_size = 256

        # Erase the memory region before downloading
        logger.info(f"Erasing memory at address {address:#010x}, size {total_size:#010x} bytes")
        if not self.erase(address, total_size):
            logger.error("Failed to erase memory")
            return False

        logger.debug(f"Starting firmware download to address {address:#010x}")
        with tqdm(total=total_size, unit='B', unit_scale=True, desc='Downloading') as pbar:
            while pos < total_size:
                remaining = total_size - pos
                if remaining < chunk_size:
                    chunk_size = remaining

                chunk = firmware_data[pos:pos + chunk_size]

                if not self._download_chunk(address + pos, chunk):
                    logger.error("Firmware download failed at position {}".format(pos))
                    return False

                exec_size += chunk_size
                chk_buf += chunk

                # Handle execprog if needed
                if exec_size >= page_size:
                    crc = self._calc_crc8(chk_buf)
                    size_with_crc = ((crc << 24) & 0xFF000000) + page_size
                    if not self.execprog(page_addr, size_with_crc):
                        logger.error(f"EXECPROG failed at address {page_addr:#010x}")
                        return False
                    chk_buf = b""
                    exec_size -= page_size
                    page_addr += page_size

                pos += chunk_size
                pbar.update(chunk_size)

            # Final execprog if needed
            if exec_size > 0:
                crc = self._calc_crc8(chk_buf)
                size_with_crc = ((crc << 24) & 0xFF000000) + exec_size
                if not self.execprog(page_addr, size_with_crc):
                    logger.error(f"Final EXECPROG failed at address {page_addr:#010x}")
                    return False

        if autostart:
            return self.run(address)

        return True

    def run(self, address):
        """Run the program starting at the specified address."""
        payload = struct.pack('>I', address)
        if not self._send(self.RUN_CMD, payload):
            logger.error("Failed to send RUN command")
            return False
        ack = self._recv(timeout=1)
        if ack == self.ACK_OK:
            logger.info("Device started successfully")
            return True
        else:
            logger.error("Failed to start the device")
            return False

    def write_memory(self, address, data):
        """Write a double word to a 4-byte aligned address."""
        if not isinstance(data, int):
            logger.error("Data must be an integer")
            return False
        payload = struct.pack('>II', address, data)
        if not self._send(self.WRITE_CMD, payload):
            logger.error("Failed to send WRITE command")
            return False
        ack = self._recv(timeout=1)
        if ack == self.ACK_OK:
            logger.info(f"Memory written at address {address:#010x} with data {data:#010x}")
            return True
        else:
            logger.error("Failed to write memory")
            return False

    def read_memory(self, address, size):
        """Read memory content starting from a specific address."""
        data = b''
        pos = 0
        total_size = size
        chunk_size = self.MAX_BUFFER_SIZE
        logging.debug(f"Reading {total_size} bytes from address {address:#010x}")
        while pos < total_size:
            remaining = total_size - pos
            if remaining < chunk_size:
                chunk_size = remaining
            # Size must be a multiple of 4
            if chunk_size % 4 != 0:
                chunk_size += (4 - (chunk_size % 4))
            word_count = chunk_size // 4
            payload = struct.pack('>II', address + pos, word_count)
            if not self._send(self.READ_CMD, payload):
                logging.error("Failed to send READ command")
                return None
            
            try:
                ack, chunk_data = self._recv(timeout=5, len=chunk_size)
                self._recv(timeout=1)
            except:
                logging.error("Failed to receive data")
                return None
            
            data += bytes(chunk_data[:remaining])  # Only take the needed bytes
            pos += chunk_size
        return data

    def dump_firmware(self, address, length):
        """Verify the firmware by reading back from the device and comparing."""

        total_size = length + (4 - length % 4)
        pos = 0
        chunk_size = self.MAX_BUFFER_SIZE
        firmware = b''
        logging.info(f"Reading firmware at address {address:#010x} with length {total_size:#010x}")
        with tqdm(total=total_size, unit='B', unit_scale=True, desc='Verifying') as pbar:
            while pos < total_size:
                remaining = total_size - pos
                if remaining < chunk_size:
                    chunk_size = remaining
                # Read chunk from device
                read_data = self.read_memory(address + pos, chunk_size)
                if read_data is None:
                    logging.error("Failed to read memory for verification")
                    return False
                firmware += read_data
                pos += len(read_data)
                pbar.update(len(read_data))
        logging.info("Firmware read successful")
        return firmware[:length]
    
    def verify_firmware(self, address, firmware_data):
        """Verify the firmware by reading back from the device and comparing."""
        # Ensure firmware data is 4-byte aligned
        if len(firmware_data) % 4 != 0:
            padding = b'\xFF' * (4 - len(firmware_data) % 4)
            firmware_data += padding
            logging.debug(f"Firmware data padded with {len(padding)} bytes for verification")

        total_size = len(firmware_data)
        pos = 0
        chunk_size = self.MAX_BUFFER_SIZE
        logging.info(f"Verifying firmware at address {address:#010x} with length {total_size:#010x}")
        with tqdm(total=total_size, unit='B', unit_scale=True, desc='Verifying') as pbar:
            while pos < total_size:
                remaining = total_size - pos
                if remaining < chunk_size:
                    chunk_size = remaining
                # Read chunk from device
                read_data = self.read_memory(address + pos, chunk_size)
                if read_data is None:
                    logging.error("Failed to read memory for verification")
                    return False
                # Compare with firmware data
                expected_chunk = firmware_data[pos:pos + len(read_data)]
                if read_data != expected_chunk:
                    # Find the exact mismatch location
                    for i in range(len(read_data)):
                        if read_data[i] != expected_chunk[i]:
                            mismatch_addr = address + pos + i
                            logging.error(f"Data mismatch at address {mismatch_addr:#010x}: "
                                          f"expected {expected_chunk[i]:02X}, got {read_data[i]:02X}")
                            return False
                    logging.error("Data mismatch found during verification")
                    return False
                pos += len(read_data)
                pbar.update(len(read_data))
        logging.info("Firmware verification successful")
        return True
    
    def exit(self):
        """Exit from the bootloader mode."""
        if not self._send(self.EXIT_CMD):
            logger.error("Failed to send EXIT command")
            return False
        logger.info("Exited from bootloader mode")
        return True


def main():
    """Main function to parse arguments and execute commands."""
    parser = argparse.ArgumentParser(description="AX520 programmer tool")
    parser.add_argument("-b", "--board", default='M5_TimerCamera520', help="Board name")
    parser.add_argument("-p", "--port", required=True, help="Serial port name")
    parser.add_argument("-r", "--reboot", help="Reboot after flashing", action="store_true")
    parser.add_argument("-c", "--check", help="Verify firmware after flashing", action="store_true")

    subparsers = parser.add_subparsers(dest='command', help='Operations (burn)')

    write_flash_parser = subparsers.add_parser('write_flash', help='Download firmware to the device')
    write_flash_parser.add_argument('flash_args', nargs='+', help='Address and firmware file pairs')

    read_flash_parser = subparsers.add_parser('read_flash', help='Read firmware from the device')
    read_flash_parser.add_argument('address', help='Starting address of the device')
    read_flash_parser.add_argument('size', help='Size of reading')
    read_flash_parser.add_argument('output_file', help='Location of the output file')

    erase_flash_parser = subparsers.add_parser('erase_flash', help='Erase flash of the device')
    erase_flash_parser.add_argument('address', help='Starting address of the device')
    erase_flash_parser.add_argument('size', help='Size of reading')

    args = parser.parse_args()

    board_def = AX520BoardHelper(args.board)

    if args.command == 'write_flash':
        flash_args = args.flash_args
        if len(flash_args) % 2 != 0:
            parser.error("The argument list must be pairs of address and firmware file")
        pairs = list(zip(flash_args[::2], flash_args[1::2]))
        # Validate addresses and firmware files
        for address_str, firmware_file in pairs:
            address = board_def.number_helper(address_str)
            board_def.check_flash_addr(address)
            if not os.path.exists(firmware_file):
                parser.error(f"Firmware file not found: {firmware_file}")
    elif args.command == 'read_flash':
        address = board_def.number_helper(args.address)
        size = board_def.number_helper(args.size)
        board_def.check_flash_addr(address, size=size)
    elif args.command == 'erase_flash':
        address = board_def.number_helper(args.address)
        size = board_def.number_helper(args.size)
        board_def.check_flash_addr(address, size=size)
    else:
        parser.print_help()
        return

    programmer = AX520Programmer(
        port_name=args.port,
        timeout=0.1
    )

    if not programmer.open_connection():
        logger.error("Failed to open serial port")
        return
    
    logger.info("Starting handshake with the device...")
    if not programmer.handshake(timeout=10):
        logger.error("Handshake failed")
        programmer.close_connection()
        return

    if args.command == 'write_flash':
        for address_str, firmware_file in pairs:
            address = int(address_str, 16)
            with open(firmware_file, 'rb') as f:
                firmware_data = f.read()

            board_def.check_flash_addr(address, size=len(firmware_data))

            logging.info(f"Downloading {firmware_file} to address {address:#010x}")
            if not programmer.download_firmware(address, firmware_data, autostart=False):
                logging.error("Firmware download failed")
                programmer.close_connection()
                return
            if args.check:
                if not programmer.verify_firmware(address, firmware_data):
                    logging.error("Firmware verification failed")
                    programmer.close_connection()
                    return

    if args.command == "read_flash":
        firmware = programmer.dump_firmware(address, size)
        open(args.output_file, 'w+b').write(firmware)
    
    if args.command == "erase_flash":
        logger.info(f"Erasing memory at address {address:#010x}, size {size:#010x} bytes")
        programmer.erase(address, size)

    if args.reboot:
        logger.info("Rebooting device")
        if not programmer.run(address):
            logger.error("Failed to reboot the device")
        else:
            programmer.handshook = False

    programmer.close_connection()
    logger.info("Operation completed successfully")


if __name__ == "__main__":
    main()
