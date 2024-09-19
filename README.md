# BaseMirror

This repository contains the source code corresponding to the paper titled "[BaseMirror: Automatic Reverse Engineering of Baseband Commands from Android’s Radio Interface Layer](https://arxiv.org/abs/2409.00475)", authored by [Wenqiang Li](https://thesilentdawn.github.io/), [Haohuang Wen](https://onehouwong.github.io) and [Zhiqiang Lin](https://zhiqlin.github.io/).

## Paper Abstract
In modern mobile devices, baseband is an integral component running on top of cellular processors to handle crucial radio communications. However, recent research reveals significant vulnerabilities in these basebands, posing serious security risks like remote code execution. Yet, effectively scrutinizing basebands remains a daunting task, as they run closed-source and proprietary software on vendor-specific chipsets. Existing analysis methods are limited by their dependence on manual processes and heuristic approaches, reducing their scalability.
This paper introduces a novel approach to unveil security issues in basebands from a unique perspective: to uncover vendor-specific baseband commands from the *Radio Interface Layer (RIL)*, a hardware abstraction layer interfacing with basebands. To demonstrate this concept, we have designed and developed BASEMIRROR, a static binary analysis tool to automatically reverse engineer baseband commands from vendor-specific RIL binaries. It utilizes a bidirectional taint analysis algorithm to adeptly identify baseband commands from an enhanced control flow graph enriched with reconstructed virtual function calls. Our methodology has been applied to 2 vendor RIL libraries, encompassing a wide range of Samsung Exynos smartphone models on the market. Remarkably, BASEMIRROR has uncovered 873 unique baseband commands undisclosed to the public. Based on these results, we develop an automated attack discovery framework to successfully derive and validate 8 zero-day vulnerabilities that trigger denial of cellular service and arbitrary file access on a Samsung Galaxy A53 device. These findings have been reported and confirmed by Samsung and a bug bounty was awarded to us.

## Description of the Artifact
This repository contains the source code and resources associated with our paper.
The artifact facilitates vendor RIL command extraction through automatic reverse engineering by leveraging backward and bidirectional taint analysis. It includes detailed instructions for setup, building, and running the tools, along with requirements for specific hardware and software environments.

### Repo Architecture
- **automatic-testing**: Scripts designed for automated testing of commands on real devices
- **RIL_Analyzer-bw**: A project for automatic reverse engineering of firmware to extract commands using only backward tracing, suitable for identifying write-related commands.
- **RIL_Analyzer-bwfw**: A project for reverse engineering firmware with both backward and forward tracing, used for extracting read-related commands.

**PS. In the following, we will use project *RIL_Analyzer-bw* as example, but it works for *RIL_Analyzer-bwfw* too.**

## Command Extraction by Automatic Reverse Engineering

### Pre-request
Our tool has been tested in the following environment. Other environments may work, but we do not provide technical support.

- Hardware: at least 32GB DRAM and 10G Disk available
- Operating System: Ubuntu 20.04 x86_64 LTS
- Java Environment: OpenJDK 11.0.2
- Reverse Engine: Ghidra 9.2.2

#### Java Environment
- Download [OpenJDK 11.0.2](https://download.java.net/java/GA/jdk11/9/GPL/openjdk-11.0.2_linux-x64_bin.tar.gz)
- Run `tar -zxvf openjdk-11.0.2_linux-x64_bin.tar.gz` to decompress it
- Set java environment path following the [tutorial](https://stackoverflow.com/questions/9612941/how-to-set-java-environment-path-in-ubuntu)

#### Reverse Engine
- Download [Ghidra 9.2.2](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_9.2.2_build/ghidra_9.2.2_PUBLIC_20201229.zip)
- Run `unzip ghidra_9.2.2_public_20201229.zip` to decompress it
- Run `ghidra_9.2.2_PUBLIC/support/buildGhidraJar` to generate **ghidra.jar**

### Build
- Copy ghidra.jar into `RIL_Analyzer-bw/lib`
- Run `cd RIL_Analyzer-bw` to enter
- Run `make` to build `main.jar`

### Running
- Execute `python3 run.py` in the directory `RIL_Analyzer-bw` to analyze each vendor RIL shared library automatically
    - The directory `RIL_Analyzer-bw/ril_binaries` contains the example firmware from Samsung A536E that has been thoroughly tested in our paper.
    - The subsequent `Attack Payload Discovery` section uses the result of demo firmware, so do not delete this one.
    - You could copy others f into `RIL_Analyzer-bw/ril_binaries` to see more results.


### Results
All the execution results are in the directory `output`

**Show Commands**
- Run the script `python3 show_commands.py` will show the **description**, **value** and **static flag** of all the commands
    - If no `Key` and `StaticFlag` are presented, this is a hybrid command without `Direct Input Parameter` described in our paper Section 7 and will be future work.

## *Attack Payload Discovery (Optional)

### Pre-request
Our tool has been tested in the following environment. Other environments may work, but we do not provide technical support.

- Hardware:
    - Host: at least 32GB DRAM and 10G Disk available
    - Phone: Samsung Galaxy A53 5G SM-A536E
- Host Operating System: Ubuntu 20.04 x86_64 LTS
- Phone OS: A536EXXS4AVJ3
- NDK: r26c
- ADB

### Root

> **Important Notice:**
>
> Rooting your Android device is required to run the proposed automated attack discovery framework described in this repository. However, please be aware of the following critical information:
>
> - Samsung Devices: Rooting a Samsung device will trip the KNOX functions, which are used for security and device management. This action is irreversible and may void your warranty, disable certain features, and prevent future software updates.
>
> - General Warning: Rooting any Android device can introduce security vulnerabilities and may cause instability. Proceed with caution and at your own risk.
>
> Please make sure to fully understand the implications of rooting your device before following the instructions.

- Download [firmware](https://samfw.com/firmware/SM-A536E/ARO) and make sure version is A536EXXS4AVJ3
- [Root the phone](https://xdaforums.com/t/rooting-a-samsung-device-using-magisk-and-odin-2023.4594475/)

### NDK
- Download [NDK](https://developer.android.com/ndk/downloads)
- Add `android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin` into $PATH of the system

### ADB
- Run `apt install android-tools-adb`
- Attach the phone to Host and allow to be accessed without asking again.
- Run `adb shell` to enter the phone terminal
- Run `su` and click in the phone to grant root privilege **forever**
- Run `pgrep rild` to get the PID of the rild process
- Run `ls -l /proc/<rild_PID>/fd` to get the name of the ipc interface, such as `/dev/umts_ipc0`, and configure the variable `filename` as it.
- Close current terminal

### Test
- Run `cd automatic-testing` to enter current working directory
- Open a new terminal and Run `install.sh`
- Manually check all the files in the directory `RIL_Analyzer-bw/output` and copy all the correct logs file into the directory `raw_logs`.
    - Example: `mkdir raw_logs && cp ../RIL_Analyzer-bw/output/A536EXXS4AVJ3_A536EOWO4AVI2_ARO_LOG/LOG.txt.__write_chk.* ./raw_logs`
    - It could be `__write_chk` or `write` log starting with "LOG.txt" for different vendor RIL library
    - To determine, check which contains more keyword `taintFinish`
- Run `python 0-split_cmds.py` to extract commands from logs
- Configure the option in the file `1-test_cmds.py`
    - Set `test_cmd_type` to `static-input` or `hybrid-input`
    - Set `test_cmd_start` as the start point directory of the tested
    - Set `test_cmd_len` as the group size of the tested
- Run `python 1-test_cmds.py` to check if any commands could crash the phone
