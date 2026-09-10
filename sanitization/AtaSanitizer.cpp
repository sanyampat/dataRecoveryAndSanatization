#include "AtaSanitizer.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <ctime>
#include <iostream>
#include <thread>

namespace core::sanitization {

namespace {

std::string nowUtc() {
    std::time_t t = std::time(nullptr);
    std::tm utc{};
    gmtime_r(&t, &utc);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return buf;
}

SanitizationResult makeError(const DeviceCapabilities& caps,
                              const std::string& method,
                              const std::string& err) {
    SanitizationResult r;
    r.devicePath     = caps.devicePath;
    r.busType        = "SATA";
    r.mediaType      = caps.isRotational ? "SATA HDD" : "SATA SSD";
    r.model          = caps.model;
    r.vendor         = caps.vendor;
    r.serialNumber   = caps.serialNumber;
    r.capacityBytes  = caps.capacityBytes;
    r.methodApplied  = method;
    r.assuranceLevel = AssuranceLevel::NONE;
    r.error          = err;
    return r;
}

} // namespace

// ---------------------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------------------

SanitizationResult AtaSanitizer::purge(const DeviceCapabilities& caps) const {
    auto t0 = std::chrono::steady_clock::now();

    int fd = open(caps.devicePath.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return makeError(caps, "ATA Purge", "Cannot open device: " + std::string(std::strerror(errno)));
    }

    SanitizationResult res;
    bool opened = true;

    if (caps.supportsAtaSanitizeCrypto && !caps.ataSecurityFrozen) {
        res = ataSanitizeCrypto(fd, caps);
    } else if (caps.supportsAtaSanitizeBlock && !caps.ataSecurityFrozen) {
        res = ataSanitizeBlock(fd, caps);
    } else if (caps.supportsAtaEnhSecurityErase && !caps.ataSecurityFrozen) {
        res = ataSecurityErase(fd, caps, /*enhanced=*/true);
    } else if (caps.supportsAtaSecurityErase && !caps.ataSecurityFrozen) {
        res = ataSecurityErase(fd, caps, /*enhanced=*/false);
    } else {
        close(fd);
        return makeError(caps, "ATA Purge",
                         caps.ataSecurityFrozen
                             ? "ATA Security is FROZEN — cannot execute hardware erase."
                             : "No ATA Purge-capable command supported by this device.");
    }

    if (opened) close(fd);

    // ATA hardware erase is validated via command status, NOT zero-fill read-back
    if (res.wipePassed) {
        res.verificationAttempted = true;
        res.verificationPassed    = true;
        res.verificationMethod    = "ATA Command Status Validation";
        res.verificationScope     = "Command Status Only";
        res.bytesVerified         = 0;
    }

    auto t1 = std::chrono::steady_clock::now();
    res.durationSeconds = std::chrono::duration<double>(t1 - t0).count();
    res.completedAtUtc  = nowUtc();
    res.success         = res.wipePassed && res.verificationPassed;
    return res;
}

// ---------------------------------------------------------------------------
// ATA Sanitize — Crypto Scramble EXT
// ---------------------------------------------------------------------------

SanitizationResult AtaSanitizer::ataSanitizeCrypto(int fd, const DeviceCapabilities& caps) const {
    SanitizationResult res;
    res.devicePath    = caps.devicePath;
    res.busType       = "SATA";
    res.mediaType     = caps.isRotational ? "SATA HDD" : "SATA SSD";
    res.model         = caps.model;
    res.vendor        = caps.vendor;
    res.serialNumber  = caps.serialNumber;
    res.capacityBytes = caps.capacityBytes;
    res.methodApplied = "ATA Sanitize — Crypto Scramble EXT";
    res.assuranceLevel= AssuranceLevel::PURGE;
    res.startedAtUtc  = nowUtc();

    uint8_t sense[32] = {};
    constexpr uint64_t kCryptoScrambleMagic = 0x43727970ULL;

    bool ok = sendAtaCommand(
        fd,
        0xB4,
        0x0011,
        0,
        kCryptoScrambleMagic,
        nullptr,
        0,
        AtaDirection::NON_DATA,
        sense,
        sizeof(sense)
    );
    if (!ok) {
        res.error = "ATA SANITIZE CRYPTO SCRAMBLE command rejected (check root permissions).";
        return res;
    }

    res.wipePassed = waitSanitizeComplete(fd, 600);
    if (!res.wipePassed) {
        res.error = "ATA Sanitize Crypto Scramble: timed out or device reported error.";
    }
    res.bytesProcessed = res.wipePassed ? caps.capacityBytes : 0;
    return res;
}

// ---------------------------------------------------------------------------
// ATA Sanitize — Block Erase EXT
// ---------------------------------------------------------------------------

SanitizationResult AtaSanitizer::ataSanitizeBlock(int fd, const DeviceCapabilities& caps) const {
    SanitizationResult res;
    res.devicePath    = caps.devicePath;
    res.busType       = "SATA";
    res.mediaType     = caps.isRotational ? "SATA HDD" : "SATA SSD";
    res.model         = caps.model;
    res.vendor        = caps.vendor;
    res.serialNumber  = caps.serialNumber;
    res.capacityBytes = caps.capacityBytes;
    res.methodApplied = "ATA Sanitize — Block Erase EXT";
    res.assuranceLevel= AssuranceLevel::PURGE;
    res.startedAtUtc  = nowUtc();

    uint8_t sense[32] = {};
    constexpr uint64_t kBlockEraseMagic = 0x426B4572ULL;

    bool ok = sendAtaCommand(
        fd,
        0xB4,
        0x0012,
        0,
        kBlockEraseMagic,
        nullptr,
        0,
        AtaDirection::NON_DATA,
        sense,
        sizeof(sense)
    );
    if (!ok) {
        res.error = "ATA SANITIZE BLOCK ERASE command rejected.";
        return res;
    }

    res.wipePassed = waitSanitizeComplete(fd, 600);
    if (!res.wipePassed) {
        res.error = "ATA Sanitize Block Erase: timed out or device reported error.";
    }
    res.bytesProcessed = res.wipePassed ? caps.capacityBytes : 0;
    return res;
}

// ---------------------------------------------------------------------------
// ATA Security Erase
// ---------------------------------------------------------------------------

SanitizationResult AtaSanitizer::ataSecurityErase(int fd, const DeviceCapabilities& caps,
                                                    bool enhanced) const {
    SanitizationResult res;
    res.devicePath    = caps.devicePath;
    res.busType       = "SATA";
    res.mediaType     = caps.isRotational ? "SATA HDD" : "SATA SSD";
    res.model         = caps.model;
    res.vendor        = caps.vendor;
    res.serialNumber  = caps.serialNumber;
    res.capacityBytes = caps.capacityBytes;
    res.methodApplied = enhanced ? "ATA Security Erase — Enhanced" : "ATA Security Erase";
    res.assuranceLevel= AssuranceLevel::PURGE;
    res.startedAtUtc  = nowUtc();

    uint8_t pwBuf[512] = {};
    pwBuf[0] = 0x00;
    pwBuf[1] = 0x00;
    const char* pw = "SIH_SANITIZE";
    std::memcpy(pwBuf + 2, pw, std::min(static_cast<size_t>(32), std::strlen(pw)));

    uint8_t sense[32] = {};
    // SECURITY SET PASSWORD is PIO Data-Out
    if (!sendAtaCommand(fd, 0xF1, 0, 0, 0, pwBuf, 512, AtaDirection::DATA_OUT, sense, sizeof(sense))) {
        res.error = "ATA SECURITY SET PASSWORD command failed.";
        return res;
    }

    uint8_t eraseBuf[512] = {};
    eraseBuf[0] = 0x00;
    eraseBuf[1] = enhanced ? 0x02 : 0x00;
    std::memcpy(eraseBuf + 2, pw, std::min(static_cast<size_t>(32), std::strlen(pw)));

    // SECURITY ERASE UNIT is PIO Data-Out
    if (!sendAtaCommand(fd, 0xF4, 0, 0, 0, eraseBuf, 512, AtaDirection::DATA_OUT, sense, sizeof(sense))) {
        res.error = "ATA SECURITY ERASE UNIT command failed.";
        return res;
    }

    constexpr unsigned kTimeoutSec = 900;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(kTimeoutSec);
    while (std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        uint8_t id[512] = {};
        uint8_t idSense[32] = {};
        // IDENTIFY DEVICE is PIO Data-In
        if (sendAtaCommand(fd, 0xEC, 0, 0, 0, id, 512, AtaDirection::DATA_IN, idSense, sizeof(idSense))) {
            uint16_t w128 = static_cast<uint16_t>(id[128 * 2] | (id[128 * 2 + 1] << 8));
            bool secEnabled = (w128 & (1u << 1)) != 0;
            if (!secEnabled) {
                res.wipePassed = true;
                break;
            }
        }
    }

    if (!res.wipePassed) res.error = "ATA Security Erase timed out.";
    res.bytesProcessed = res.wipePassed ? caps.capacityBytes : 0;
    return res;
}

// ---------------------------------------------------------------------------
// Poll ATA SANITIZE STATUS EXT
// ---------------------------------------------------------------------------

bool AtaSanitizer::waitSanitizeComplete(int fd, unsigned timeoutSec) const {
    auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::seconds(timeoutSec);

    while (std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        uint8_t sense[32] = {};

        // SANITIZE STATUS EXT
        if (!sendAtaCommand(
                fd,
                0xB4,
                0x0000,
                0,
                0,
                nullptr,
                0,
                AtaDirection::NON_DATA,
                sense,
                sizeof(sense))) {
            continue;
        }

        // Descriptor-format sense: 0x72 or 0x73
        if (sense[0] != 0x72 && sense[0] != 0x73)
            continue;

        const uint8_t additionalLen = sense[7];
        const int end =
            std::min<int>(
                static_cast<int>(sizeof(sense)),
                8 + additionalLen);

        int offset = 8;

        while (offset + 1 < end) {
            const uint8_t descType = sense[offset];
            const uint8_t descLen  = sense[offset + 1];

            if (descType == 0x09) {
                // ATA Return Descriptor
                if (offset + 13 >= end)
                    break;

                // Sector Count Low byte
                const uint8_t sectorCountLow = sense[offset + 5];

                // ATA Status register
                const uint8_t status = sense[offset + 13];

                // SDIP = Sanitize Device In Progress
                const bool sdip =
                    (sectorCountLow & 0x80) != 0;

                if (!sdip) {
                    // ERR bit in ATA Status
                    return (status & 0x01) == 0;
                }

                break;
            }
            if (descLen < 1 || offset + 2 + descLen > end)
                break;
            offset += 2 + descLen;
        }
    }

    return false;
}

// ---------------------------------------------------------------------------
// Generic ATA passthrough via SG_IO
// ---------------------------------------------------------------------------

bool AtaSanitizer::sendAtaCommand(int fd, uint8_t cmd, uint16_t feature, uint16_t count,
                                   uint64_t lba, uint8_t* buf, size_t bufLen,
                                   AtaDirection dir, uint8_t* senseOut, size_t senseLen) const {
    uint8_t cdb[16] = {};
    cdb[0]  = 0x85; // ATA PASSTHROUGH (16)

    int protocol = 3; // Non-data
    if (dir == AtaDirection::DATA_IN) protocol = 4; // PIO Data-In
    else if (dir == AtaDirection::DATA_OUT) protocol = 5; // PIO Data-Out

// EXTEND=1: use the 48-bit ATA register layout
    cdb[1] = static_cast<uint8_t>((protocol << 1) | 0x01);

    if (dir == AtaDirection::DATA_IN) {
        cdb[2] = 0x2E; // CK_COND=1, T_DIR=1 (From Dev), BYT_BLOK=1, T_LENGTH=2
    } else if (dir == AtaDirection::DATA_OUT) {
        cdb[2] = 0x26; // CK_COND=1, T_DIR=0 (To Dev), BYT_BLOK=1, T_LENGTH=2
    } else {
        cdb[2] = 0x20; // CK_COND=1, T_DIR=0, T_LENGTH=0
    }

    cdb[3]  = static_cast<uint8_t>(feature & 0xFF);
    cdb[4]  = static_cast<uint8_t>(feature >> 8);
    cdb[5]  = static_cast<uint8_t>(count & 0xFF);
    cdb[6]  = static_cast<uint8_t>(count >> 8);
// ATA PASSTHROUGH (16): 48-bit LBA register mapping
    cdb[7]  = static_cast<uint8_t>((lba >> 24) & 0xFF); // LBA Low Ext
    cdb[8]  = static_cast<uint8_t>(lba & 0xFF);         // LBA Low
    cdb[9]  = static_cast<uint8_t>((lba >> 32) & 0xFF); // LBA Mid Ext
    cdb[10] = static_cast<uint8_t>((lba >> 8) & 0xFF);  // LBA Mid
    cdb[11] = static_cast<uint8_t>((lba >> 40) & 0xFF); // LBA High Ext
    cdb[12] = static_cast<uint8_t>((lba >> 16) & 0xFF); // LBA High

    cdb[13] = 0xA0; // DEVICE
    cdb[14] = cmd;

    sg_io_hdr_t io = {};
    io.interface_id    = 'S';
    io.cmd_len         = 16;
    io.cmdp            = cdb;

    if (dir == AtaDirection::DATA_IN) {
        io.dxfer_direction = SG_DXFER_FROM_DEV;
    } else if (dir == AtaDirection::DATA_OUT) {
        io.dxfer_direction = SG_DXFER_TO_DEV;
    } else {
        io.dxfer_direction = SG_DXFER_NONE;
    }

    io.dxfer_len       = static_cast<unsigned int>(bufLen);
    io.dxferp          = buf;
    io.sbp             = senseOut;
    io.mx_sb_len       = static_cast<uint8_t>(senseLen);
    io.timeout         = 30000;

    if (ioctl(fd, SG_IO, &io) != 0) return false;
    if (io.status && io.status != 0x02) {
        return false;
    }
    return true;
}

} // namespace core::sanitization