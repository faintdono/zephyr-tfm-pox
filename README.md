# Demo Guide for Zephyr-TFM-POX Project

This guide provides steps to demo the Zephyr-TFM-POX project using Zephyr with Trusted Firmware-M (TF-M) on QEMU.

## Prerequisites

Ensure you have the following dependencies installed:

- **Zephyr SDK**: Includes cross-compilers and necessary tools.
- **CMake**: Used for building Zephyr applications.
- **Python 3**: Required for Zephyr's build system.
- **West (Zephyr's meta-tool)**: Used for managing Zephyr repositories and builds.
- **QEMU**: Emulator for running the built binaries.
- **ARM GNU Toolchain**: Needed for building TF-M.

### Install Dependencies (Ubuntu/Debian)
```sh
sudo apt update && sudo apt install -y cmake ninja-build gperf ccache dfu-util device-tree-compiler python3-pip python3-setuptools python3-wheel python3-dev git wget
pip3 install --user west
```

### Install Zephyr SDK
```sh
wget https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.16.2/zephyr-sdk-0.16.2-linux-x86_64-setup.run
chmod +x zephyr-sdk-0.16.2-linux-x86_64-setup.run
./zephyr-sdk-0.16.2-linux-x86_64-setup.run -- -d ~/zephyr-sdk
```

### Set Up Zephyr
```sh
west init ~/zephyrproject
cd ~/zephyrproject
west update
west zephyr-export
pip3 install --user -r zephyr/scripts/requirements.txt
```

### Set Up Environment
```sh
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
export ZEPHYR_SDK_INSTALL_DIR=~/zephyr-sdk
source ~/zephyrproject/zephyr/zephyr-env.sh
```

## Building and Running the Demo

### Clone the Zephyr-TFM-POX Repository
```sh
cd ~/zephyrproject
git clone https://github.com/faintdono/zephyr-tfm-pox.git
cd zephyr-tfm-pox
```

### Build the Demo
```sh
west build -p auto -b mps2_an521_ns .
```

### Run the Demo on QEMU
```sh
west build -t run
```

To manually launch QEMU:
```sh
qemu-system-arm -machine mps2-an521 -cpu cortex-m33 -nographic -kernel build/zephyr/zephyr.elf
```

## Conclusion

You have successfully built and run the Zephyr-TFM-POX project using Zephyr with TF-M on QEMU. Modify and expand the setup as needed for your specific use case!

## Disclaimer

This README.md file is AI Generated. I haven't confirm it will work 100% yet. Please feel free to just build it and run it with the way you have been learn in Zephyr project.