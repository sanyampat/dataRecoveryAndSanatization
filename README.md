# SIH SanitizerOS
### Forensic Data Recovery, Evidence Acquisition & Secure Storage Sanitization

> A modular Linux-based storage forensics and sanitization platform for device discovery, forensic acquisition, deleted-file recovery, secure sanitization, and post-operation verification.

[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Linux](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://www.linux.org/)
[![CMake](https://img.shields.io/badge/Build-CMake-064F8C.svg)](https://cmake.org/)
[![OpenSSL](https://img.shields.io/badge/Crypto-OpenSSL-721412.svg)](https://www.openssl.org/)
[![Status](https://img.shields.io/badge/Status-Active%20Development-yellow.svg)](#development-status)
[![License](https://img.shields.io/badge/License-See%20LICENSE-lightgrey.svg)](#license)

---

## Overview

**SIH SanitizerOS** is a modular storage-forensics and secure-sanitization platform designed for controlled handling of storage devices.

The system combines:

- Device discovery and identification
- Storage metadata inspection
- Forensic disk acquisition
- SHA-256 evidence hashing
- Deleted-file carving
- File validation and confidence scoring
- Recovered-file classification
- Capability-driven storage sanitization
- Post-operation verification
- Evidence manifests and audit information
- Linux-based graphical and command-line workflows

The project is designed around a **modular C++ core** with a lightweight user interface layer, allowing individual storage technologies and forensic operations to be developed and tested independently.

---

# Architecture

```text
                         ┌──────────────────────────────┐
                         │        SIH SanitizerOS       │
                         │                              │
                         │     Linux Forensic System    │
                         └──────────────┬───────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────┐
              │                         │                         │
              ▼                         ▼                         ▼
     ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
     │ Device Layer    │      │ Acquisition     │      │ Recovery        │
     │                 │      │ Layer           │      │ Layer           │
     │ Drive Discovery │      │ Write Protect   │      │ File Carving    │
     │ Metadata        │      │ Disk Imaging    │      │ Validation      │
     │ Bus Detection   │      │ SHA-256 Hash    │      │ Confidence      │
     └────────┬────────┘      │ Evidence        │      │ Classification  │
              │               └────────┬────────┘      └────────┬────────┘
              │                        │                         │
              └────────────────────────┼─────────────────────────┘
                                       │
                                       ▼
                            ┌─────────────────────┐
                            │  Sanitization Core  │
                            │                     │
                            │ Capability Probe    │
                            │ Method Selection    │
                            │ Hardware Sanitizers │
                            │ Generic Clear       │
                            └──────────┬──────────┘
                                       │
                                       ▼
                            ┌─────────────────────┐
                            │    Verification     │
                            │                     │
                            │ Operation Status    │
                            │ Read-back Checks    │
                            │ Result Generation   │
                            └──────────┬──────────┘
                                       │
                                       ▼
                            ┌─────────────────────┐
                            │ UI / CLI / Reports  │
                            └─────────────────────┘
````

---

# Core Capabilities

## 1. Storage Device Discovery

The device layer discovers block storage devices through Linux system interfaces and exposes a unified representation of each drive.

Collected information includes:

* Device path
* Model
* Vendor
* Serial number
* Capacity
* Logical sector size
* Physical sector size
* Rotational state
* Bus type
* Media type

Example:

```text
Device      : /dev/sdb
Model       : VMware Virtual Disk
Serial      : -
Capacity    : 3.00 GiB
Bus         : SATA
Media       : HDD
Status      : SAFE
```

The abstraction is provided by:

```text
device/
├── DriveInfo.h
├── DriveManager.cpp
└── DriveManager.h
```

---

# 2. Forensic Acquisition

The acquisition subsystem provides controlled disk imaging for forensic workflows.

### Acquisition pipeline

```text
        Source Drive
             │
             ▼
      Device Inspection
             │
             ▼
      Write Protection
             │
             ▼
        Disk Imaging
             │
             ▼
        SHA-256 Hash
             │
             ▼
      Evidence Manifest
             │
             ▼
       Forensic Image
```

### Components

```text
acquisition/
├── AcquisitionManager.cpp
├── AcquisitionManager.h
├── DiskImager.cpp
├── DiskImager.h
├── HashEngine.cpp
├── HashEngine.h
├── WriteProtection.cpp
└── WriteProtection.h
```

The acquisition system records information such as:

* Source device
* Device model
* Serial number
* Image destination
* Image size
* SHA-256 hash
* Acquisition status
* Timestamp
* Write-protection state

This allows the generated image to be independently verified after acquisition.

---

# 3. Deleted-File Recovery

The recovery subsystem analyzes raw disk images and attempts to identify recoverable file structures.

### Recovery pipeline

```text
          Disk Image
              │
              ▼
         File Carving
              │
              ▼
        File Validation
              │
              ▼
       Confidence Scoring
              │
              ▼
       File Classification
              │
              ▼
       Recovered Files
```

### Components

```text
recovery/
├── FileCarver.cpp
├── FileCarver.h
├── FileValidator.cpp
├── FileValidator.h
├── ConfidenceScorer.cpp
├── ConfidenceScorer.h
├── FileClassifier.cpp
├── FileClassifier.h
└── RecoveredFile.h
```

The recovery pipeline provides more than simple signature matching.

Each candidate can contain:

* File type
* Start offset
* End offset
* Recovered size
* Validation result
* Confidence level
* Category
* Output path
* SHA-256 hash

Example:

```text
Type    : JPEG
Size    : 2.0 KB
Status  : VALID
Confidence: MEDIUM
Category: Images
```

---

# 4. Capability-Driven Sanitization

Sanitization is designed around the principle that **different storage technologies require different sanitization mechanisms**.

Instead of blindly applying one wipe algorithm to every device, SIH SanitizerOS probes the target device and determines which operations are available.

```text
                 Target Drive
                      │
                      ▼
             Capability Probe
                      │
          ┌───────────┼───────────┐
          │           │           │
          ▼           ▼           ▼
        NVMe         ATA         SCSI
          │           │           │
          ▼           ▼           ▼
      NVMe        ATA Sanitize  SCSI
      Sanitize    / Secure      Sanitize
          │        Erase          │
          └───────────┼───────────┘
                      │
                      ▼
              Generic CLEAR
                 fallback
```

The sanitization subsystem contains:

```text
sanitization/
├── SanitizationEngine.cpp
├── SanitizationEngine.h
├── DeviceCapabilityProbe.cpp
├── DeviceCapabilityProbe.h
├── DeviceCapabilities.h
├── SanitizationResult.h
├── GenericBlockSanitizer.cpp
├── GenericBlockSanitizer.h
├── AtaSanitizer.cpp
├── AtaSanitizer.h
├── NvmeSanitizer.cpp
├── NvmeSanitizer.h
├── ScsiSanitizer.cpp
├── ScsiSanitizer.h
├── Verification.cpp
└── Verification.h
```

### Sanitization decision model

```text
Device
  │
  ▼
Safety Checks
  │
  ├── System disk? ──────► REFUSE
  │
  ├── Mounted? ───────────► REFUSE
  │
  ▼
Capability Detection
  │
  ├── NVMe sanitize available
  │          │
  │          ▼
  │      NVMe Sanitizer
  │
  ├── ATA sanitize / erase available
  │          │
  │          ▼
  │      ATA Sanitizer
  │
  ├── SCSI sanitize available
  │          │
  │          ▼
  │      SCSI Sanitizer
  │
  └── No hardware method
             │
             ▼
      Generic Block Clear
```

---

# 5. Sanitization Result & Audit Model

Every sanitization operation produces a structured result rather than simply returning `true` or `false`.

The result records:

```text
Device
Bus
Media
Vendor
Model
Serial
Capacity
Method Applied
Assurance Level
Bytes Processed
Wipe Status
Verification Status
Verification Method
Samples Checked
Duration
Start Timestamp
Completion Timestamp
Error Information
```

Example:

```text
Device          : /dev/sdb
Bus             : SATA
Media           : SATA HDD
Method          : Generic Block Clear
Assurance       : CLEAR
Capacity        : 3221225472 bytes
Wipe            : PASS
Verification    : PASS
Samples Checked : 1000
Status          : SUCCESS
```

This result model is intended to form the foundation for future sanitization certificates and audit reports.

---

# 6. Verification

Verification is treated as a separate subsystem.

For logical CLEAR operations, the current verification implementation performs randomized read-back sampling.

```text
        Sanitization
             │
             ▼
       Verification
             │
       ┌─────┴─────┐
       │           │
       ▼           ▼
     PASS         FAIL
       │           │
       ▼           ▼
   Completed     Report
```

The verification layer uses direct I/O when supported and falls back to buffered reads when required by the device or virtualized environment.

---

# 7. Safety System

Storage sanitization is destructive, therefore safety checks are performed before any destructive operation.

The engine checks for conditions such as:

* Active system disk
* Mounted storage
* Device accessibility
* Device capabilities
* Supported sanitization method

Example safety behavior:

```text
/dev/sda
SYSTEM (Protected)
        │
        ▼
  Sanitization Refused
```

while a disposable test disk may appear as:

```text
/dev/sdb
SAFE (Unmounted)
        │
        ▼
  Eligible for Operation
```

> **Never assume `/dev/sda`, `/dev/sdb`, etc. refers to a particular physical drive. Always verify the device path, model, serial number, capacity and mount state before performing destructive operations.**

---

# User Interface

The project includes a lightweight Linux GUI designed around the major forensic workflows.

### Device

```text
┌──────────────────────────────────────────────┐
│ Devices                                      │
├──────────────────────────────────────────────┤
│ Device │ Model │ Capacity │ Bus │ Status     │
│ /dev/sda │ ... │ 40 GB   │ SATA│ SYSTEM      │
│ /dev/sdb │ ... │ 3 GB    │ SATA│ SAFE        │
└──────────────────────────────────────────────┘
```

### Acquisition

Provides:

* Source device selection
* Destination image selection
* Acquisition execution
* Evidence manifest
* SHA-256 verification

### Recovery

Provides:

* Disk-image selection
* File carving
* Validation
* Confidence scoring
* File classification
* Recovered-file output

### Sanitization

Provides:

* Drive inspection
* Device safety status
* Sanitization method
* Confirmation dialog
* Sanitization execution
* Result reporting

---

# Project Structure

```text
dataRecoveryAndSanatization/
│
├── UI/
│   ├── ui.py
│   └── sanitizer_ui.cpp
│
├── acquisition/
│   ├── AcquisitionManager.cpp
│   ├── AcquisitionManager.h
│   ├── DiskImager.cpp
│   ├── DiskImager.h
│   ├── HashEngine.cpp
│   ├── HashEngine.h
│   ├── WriteProtection.cpp
│   └── WriteProtection.h
│
├── apps/
│   ├── acquisition-test/
│   ├── device-test/
│   ├── recovery-test/
│   └── sanitizer/
│
├── device/
│   ├── DriveInfo.h
│   ├── DriveManager.cpp
│   └── DriveManager.h
│
├── recovery/
│   ├── FileCarver.cpp
│   ├── FileCarver.h
│   ├── FileValidator.cpp
│   ├── FileValidator.h
│   ├── ConfidenceScorer.cpp
│   ├── ConfidenceScorer.h
│   ├── FileClassifier.cpp
│   ├── FileClassifier.h
│   └── RecoveredFile.h
│
├── sanitization/
│   ├── SanitizationEngine.cpp
│   ├── SanitizationEngine.h
│   ├── DeviceCapabilityProbe.cpp
│   ├── DeviceCapabilityProbe.h
│   ├── DeviceCapabilities.h
│   ├── SanitizationResult.h
│   ├── GenericBlockSanitizer.cpp
│   ├── GenericBlockSanitizer.h
│   ├── AtaSanitizer.cpp
│   ├── AtaSanitizer.h
│   ├── NvmeSanitizer.cpp
│   ├── NvmeSanitizer.h
│   ├── ScsiSanitizer.cpp
│   ├── ScsiSanitizer.h
│   ├── Verification.cpp
│   └── Verification.h
│
├── os/
│   └── launcher/
│
├── CMakeLists.txt
├── README.md
└── LICENSE
```

---

# Technology Stack

| Technology           | Purpose                                            |
| -------------------- | -------------------------------------------------- |
| **C++17**            | Core storage and forensic engine                   |
| **CMake**            | Build system                                       |
| **Python 3**         | GUI/application layer                              |
| **Tkinter**          | Lightweight Linux GUI                              |
| **pybind11**         | Python ↔ C++ bridge                                |
| **OpenSSL**          | Cryptographic hashing                              |
| **Linux/POSIX APIs** | Raw block-device operations                        |
| **NVMe ioctl**       | NVMe device operations                             |
| **SCSI SG_IO**       | SCSI/ATA passthrough                               |
| **libblkid**         | Block-device/filesystem information                |
| **The Sleuth Kit**   | Filesystem/forensic functionality where applicable |

---

# Requirements

The recommended development environment is Linux.

Tested development direction:

```text
Debian Linux
    │
    ├── Xorg
    ├── Openbox
    ├── Python 3
    ├── Tkinter
    └── C++17 toolchain
```

## Debian / Ubuntu dependencies

```bash
sudo apt update

sudo apt install \
    build-essential \
    cmake \
    git \
    python3 \
    python3-dev \
    python3-tk \
    pybind11-dev \
    libssl-dev \
    libblkid-dev \
    libudev-dev \
    pkg-config \
    libtsk-dev
```

For the graphical environment:

```bash
sudo apt install \
    xorg \
    openbox \
    xterm \
    xinit
```

---

# Build

Clone the repository:

```bash
git clone https://github.com/sanyampat/dataRecoveryAndSanatization.git
cd dataRecoveryAndSanatization
```

Create a build directory:

```bash
mkdir -p build
cd build
```

Configure:

```bash
cmake ..
```

Build:

```bash
cmake --build . -j$(nproc)
```

---

# Python / C++ Bridge

The graphical interface communicates with the C++ core through a `pybind11` module.

After building:

```bash
cd /path/to/dataRecoveryAndSanatization
PYTHONPATH="$PWD/UI" python3 -c \
'import cpp_sanitizer; print("CPP SANITIZER OK")'
```

Expected output:

```text
CPP SANITIZER OK
```

---

# Running the GUI

From the repository root:

```bash
cd /path/to/dataRecoveryAndSanatization
PYTHONPATH="$PWD/UI" python3 UI/ui.py
```

For the intended lightweight Linux environment, the GUI can be launched automatically through Xorg/Openbox.

Example:

```bash
#!/bin/sh

openbox &

cd /path/to/dataRecoveryAndSanatization

exec python3 UI/ui.py
```

---

# Testing

## Device discovery

Build and run the device test:

```bash
./build/device-test
```

or:

```bash
sudo ./build/device-test
```

---

## Acquisition

The acquisition workflow should be tested only against:

* Disposable drives
* Test virtual disks
* Forensic copies
* Authorized evidence media

Never experiment with the operating system disk.

---

## Recovery

A typical recovery workflow is:

```text
Test Disk
    │
    ▼
Create Raw Image
    │
    ▼
Delete Test Files
    │
    ▼
Run File Carver
    │
    ▼
Validate Candidates
    │
    ▼
Score Confidence
    │
    ▼
Classify
    │
    ▼
Recover
```

Recovered files should be independently checked using standard tools such as:

```bash
file recovered-file
```

and where appropriate:

```bash
sha256sum recovered-file
```

---

# Sanitization Testing

**Only test sanitization against a disposable device or virtual disk.**

Example safe development environment:

```text
VMware / QEMU
      │
      ▼
Disposable virtual disk
      │
      ▼
/dev/sdb
      │
      ▼
Sanitization testing
```

Never assume `/dev/sdb` is safe merely because it is named `/dev/sdb`.

Before destructive testing:

```bash
lsblk -o NAME,SIZE,MODEL,SERIAL,TYPE,MOUNTPOINTS
```

Verify:

* Correct device
* Correct capacity
* Correct model
* Correct serial number
* No important partitions
* No mounted filesystems

---

# Standards & Sanitization Philosophy

The project follows a **capability-driven** sanitization model.

The objective is not to claim that every device can be securely sanitized using the same technique.

Different storage technologies have different characteristics:

```text
HDD
 └── Block-level overwrite may provide CLEAR

SATA SSD
 └── Prefer device-supported sanitization mechanisms
     where available

NVMe SSD
 └── Prefer NVMe Sanitize / supported device-level methods

SCSI
 └── Use supported SCSI sanitization mechanisms

USB / Virtual / Unknown
 └── Use an appropriate fallback and clearly report
     the achievable assurance level
```

The project distinguishes between:

### CLEAR

A logical sanitization operation such as block-level overwriting.

### PURGE

A device-level sanitization mechanism intended to provide stronger protection against recovery than ordinary logical overwriting.

The software should **not claim PURGE merely because a command was issued**. The actual device capability, command result and verification evidence must support the reported outcome.

---

# Development Status

## Implemented

* [x] Storage device discovery
* [x] Drive metadata abstraction
* [x] Linux block-device interaction
* [x] C++17 modular architecture
* [x] CMake build system
* [x] Forensic acquisition architecture
* [x] Disk imaging
* [x] SHA-256 hashing
* [x] Write-protection abstraction
* [x] File carving
* [x] File validation
* [x] Confidence scoring
* [x] File classification
* [x] Python/Tkinter GUI
* [x] Python/C++ pybind11 bridge
* [x] Capability probing architecture
* [x] Sanitization result model
* [x] Generic block sanitization architecture
* [x] NVMe sanitization architecture
* [x] ATA sanitization architecture
* [x] SCSI sanitization architecture
* [x] Post-operation verification architecture
* [x] System/mounted-device safety guards

## In Progress

* [ ] Hardware-wide sanitization validation
* [ ] Improved ATA passthrough compatibility
* [ ] Improved SCSI capability detection
* [ ] Device-specific verification strategies
* [ ] Stronger system-disk/LVM detection
* [ ] Comprehensive hardware compatibility testing
* [ ] Automated regression tests
* [ ] Sanitization certificates
* [ ] Full forensic audit logging
* [ ] Bootable live environment
* [ ] Hardware compatibility database

---

# Roadmap

## Phase 1 — Core Platform

* [x] Device discovery
* [x] Drive metadata
* [x] Modular architecture
* [x] CMake build
* [x] Linux integration

## Phase 2 — Forensic Acquisition

* [x] Disk imaging
* [x] SHA-256 hashing
* [x] Write-protection abstraction
* [x] Evidence manifest
* [ ] Extended acquisition logging

## Phase 3 — Recovery

* [x] File carving
* [x] File validation
* [x] Confidence scoring
* [x] File classification
* [ ] More file signatures
* [ ] Fragmented-file recovery
* [ ] Advanced filesystem recovery
* [ ] Recovery reporting

## Phase 4 — Sanitization

* [x] Sanitization engine
* [x] Capability detection architecture
* [x] Device-specific sanitizer architecture
* [x] Generic block fallback
* [x] Result/audit structure
* [ ] ATA command hardening
* [ ] NVMe hardware validation
* [ ] SCSI command validation
* [ ] Media-aware verification
* [ ] Sanitization certificates
* [ ] Hardware compatibility testing

## Phase 5 — SIH SanitizerOS

* [x] Minimal Linux development environment
* [x] Xorg/Openbox GUI environment
* [x] Python/Tkinter interface
* [ ] Bootable ISO
* [ ] Automatic GUI startup
* [ ] Offline forensic toolkit
* [ ] Evidence/audit storage
* [ ] Automated device classification
* [ ] Hardware compatibility database
* [ ] Production-ready deployment image

---

# Security Considerations

This project performs operations directly against storage devices.

### Forensic acquisition

Whenever possible:

* Use write protection.
* Preserve the original evidence.
* Work from forensic images.
* Hash acquired images.
* Preserve acquisition metadata.

### Sanitization

Before any destructive operation:

1. Confirm the physical device.
2. Confirm model and serial number.
3. Confirm capacity.
4. Confirm the device is not the system disk.
5. Confirm partitions are not mounted.
6. Confirm the device is disposable or explicitly authorized.
7. Confirm the sanitization method.
8. Record the result.

### Never do this

```text
"sudo ./sanitizer /dev/sda"
```

without first verifying what `/dev/sda` actually represents.

Device names are assigned dynamically by Linux and can change between boots or hardware configurations.

---

# Example End-to-End Workflow

```text
                ┌─────────────────┐
                │ Storage Device  │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Device Discovery│
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Device Inspection│
                └────────┬────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
              ▼                     ▼
        Forensic Workflow     Sanitization
              │                     │
              ▼                     ▼
       Write Protection       Safety Checks
              │                     │
              ▼                     ▼
        Disk Imaging         Capability Probe
              │                     │
              ▼                     ▼
          SHA-256              Method Select
              │                     │
              ▼                     ▼
        Evidence Image        Device Sanitizer
              │                     │
              ▼                     ▼
        File Recovery          Verification
              │                     │
              └──────────┬──────────┘
                         │
                         ▼
                  Audit / Report
```

---

# Project Goals

The long-term goal of SIH SanitizerOS is to provide a **portable Linux-based forensic and storage-sanitization environment** that can operate independently of a host operating system.

The intended platform will eventually provide:

* Bootable forensic environment
* Device discovery
* Evidence acquisition
* Recovery tools
* Storage sanitization
* Device capability detection
* Hardware-specific sanitization
* Verification
* Evidence manifests
* Audit logs
* Sanitization certificates
* Portable offline operation

---

# Contributing

Contributions are welcome.

Create a feature branch:

```bash
git checkout -b feature/your-feature
```

Make your changes:

```bash
git add .
git commit -m "Add: your feature"
```

Push:

```bash
git push origin feature/your-feature
```

Then open a Pull Request.

When contributing:

* Keep modules separated by responsibility.
* Prefer modern C++ practices.
* Avoid destructive operations in automated tests.
* Test storage operations using disposable devices.
* Document hardware-specific behavior.
* Clearly identify experimental functionality.
* Do not claim sanitization assurance without appropriate evidence.
* Add regression tests for new functionality.

---

# Disclaimer

SIH SanitizerOS is intended for:

* Authorized digital forensics
* Data recovery
* Storage research
* Authorized storage sanitization
* Security research
* Educational purposes

Sanitization operations can permanently destroy data.

**Only operate on storage devices that you own or have explicit authorization to process.**

The authors are not responsible for:

* Data loss
* Hardware damage
* Incorrect device selection
* Misuse of the software
* Unauthorized data processing

---

# License

See [`LICENSE`](LICENSE) for the applicable license.

---

# Project

**SIH SanitizerOS — Data Recovery & Secure Sanitization**

GitHub:

[https://github.com/sanyampat/dataRecoveryAndSanatization](https://github.com/sanyampat/dataRecoveryAndSanatization)

Built as a Smart India Hackathon-oriented project focused on:

```text
Digital Forensics
        +
Data Recovery
        +
Forensic Acquisition
        +
Secure Data Sanitization
        +
Linux Systems
```

---

## ⭐ Support the Project

If you find SIH SanitizerOS useful, consider giving the repository a ⭐ and contributing improvements.

**Repository:**
[https://github.com/sanyampat/dataRecoveryAndSanatization](https://github.com/sanyampat/dataRecoveryAndSanatization)

```


[1]: https://github.com/sanyampat/dataRecoveryAndSanatization "GitHub - sanyampat/dataRecoveryAndSanatization · GitHub"
