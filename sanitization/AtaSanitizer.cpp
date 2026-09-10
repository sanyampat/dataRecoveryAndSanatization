#include "AtaSanitizer.h"
#include "Verification.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>

#include <cerrno>
#include <chrono>
#include <cstring>
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

    // Select strongest available method
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

    if (res.wipePassed) {
        VerificationResult vr = Verification::verifyClear(caps);
        res.verificationAttempted = true;
        res.verificationPassed    = vr.passed;
        res.verificationMethod    = vr.method;
        res.samplesChecked        = vr.samplesChecked;
        if (!vr.passed && res.error.empty()) res.error = vr.error;
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
    // ATA SANITIZE DEVICE EXT (opcode 0xB4, feature 0x0011 = Crypto Scramble)
    bool ok = sendAtaCommand(fd, 0xB4, 0x11, 0x0000, 0, nullptr, 0, false, sense, sizeof(sense));
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
    // ATA SANITIZE DEVICE EXT feature 0x0012 = Block Erase
    bool ok = sendAtaCommand(fd, 0xB4, 0x12, 0x0000, 0, nullptr, 0, false, sense, sizeof(sense));
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

    // 1. Set password (opcode 0xF1, feature 0 = user password)
    uint8_t pwBuf[512] = {};  // password is in bytes 2–33; everything else = 0
    pwBuf[0] = 0x00;          // identifier = user password
    pwBuf[1] = 0x00;          // reserved
    const char* pw = "SIH_SANITIZE";
    std::memcpy(pwBuf + 2, pw, std::min(static_cast<size_t>(32), std::strlen(pw)));

    uint8_t sense[32] = {};
    if (!sendAtaCommand(fd, 0xF1, 0, 0, 0, pwBuf, 512, false, sense, sizeof(sense))) {
        res.error = "ATA SECURITY SET PASSWORD command failed.";
        return res;
    }

    // 2. Security Erase Unit (opcode 0xF4)
    //    Bit 1 of the word at offset 0 in buffer = ENHANCED
    uint8_t eraseBuf[512] = {};
    eraseBuf[0] = 0x00;
    eraseBuf[1] = enhanced ? 0x02 : 0x00;
    std::memcpy(eraseBuf + 2, pw, std::min(static_cast<size_t>(32), std::strlen(pw)));

    if (!sendAtaCommand(fd, 0xF4, 0, 0, 0, eraseBuf, 512, false, sense, sizeof(sense))) {
        res.error = "ATA SECURITY ERASE UNIT command failed.";
        return res;
    }

    // The drive goes busy for the duration; we poll IDENTIFY until security bit clears
    constexpr unsigned kTimeoutSec = 900;  // 15 min — large HDDs can take this long
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(kTimeoutSec);
    while (std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        // Re-open to check (device may have dropped the fd)
        uint8_t id[512] = {};
        uint8_t idSense[32] = {};
        if (sendAtaCommand(fd, 0xEC, 0, 0, 0, id, 512, true, idSense, sizeof(idSense))) {
            // Word 128 bits 2–0: Security status
            uint16_t w128 = static_cast<uint16_t>(id[128 * 2] | (id[128 * 2 + 1] << 8));
            bool secEnabled = (w128 & (1u << 1)) != 0;
            if (!secEnabled) {
                // Security disabled — erase is complete
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
// Poll ATA SANITIZE STATUS EXT (opcode 0xB4, feature 0x0000)
// ---------------------------------------------------------------------------

bool AtaSanitizer::waitSanitizeComplete(int fd, unsigned timeoutSec) const {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSec);
    while (std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        uint8_t sense[32] = {};
        // Feature 0x0000 = SANITIZE STATUS EXT
        if (!sendAtaCommand(fd, 0xB4, 0x00, 0, 0, nullptr, 0, false, sense, sizeof(sense))) {
            continue;
        }
        // Bit 15 of ATA Status register in the sense data: BUSY cleared → done
        // Simplified: if the command completes without ATA ERROR bit, we are done
        bool ataError = (sense[3] & 0x01) != 0;  // Error bit in ATA Return Descriptor
        if (!ataError) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Generic ATA passthrough via SG_IO
// ---------------------------------------------------------------------------

bool AtaSanitizer::sendAtaCommand(int fd, uint8_t cmd, uint8_t feature, uint16_t count,
                                   uint64_t lba, uint8_t* buf, size_t bufLen,
                                   bool dataIn, uint8_t* senseOut, size_t senseLen) const {
    uint8_t cdb[16] = {};
    cdb[0]  = 0x85;                             // ATA PASSTHROUGH (16)
    cdb[1]  = dataIn ? (4 << 1) : (3 << 1);    // PIO Data-In (4) or Non-data (3)
    cdb[2]  = dataIn ? 0x2E : 0x26;             // BYT_BLOK/T_LENGTH
    cdb[3]  = static_cast<uint8_t>(feature & 0xFF);
    cdb[4]  = static_cast<uint8_t>(feature >> 8);
    cdb[5]  = static_cast<uint8_t>(count & 0xFF);
    cdb[6]  = static_cast<uint8_t>(count >> 8);
    // LBA 24-bit (low / mid / high) — unused for most sanitize commands
    cdb[7]  = static_cast<uint8_t>(lba & 0xFF);
    cdb[8]  = static_cast<uint8_t>((lba >> 8) & 0xFF);
    cdb[9]  = static_cast<uint8_t>((lba >> 16) & 0xFF);
    cdb[10] = static_cast<uint8_t>((lba >> 24) & 0xFF);
    cdb[13] = 0xA0;                             // DEVICE = 0xA0
    cdb[14] = cmd;

    sg_io_hdr_t io = {};
    io.interface_id    = 'S';
    io.cmd_len         = 16;
    io.cmdp            = cdb;
    io.dxfer_direction = dataIn ? SG_DXFER_FROM_DEV
                                : (bufLen ? SG_DXFER_TO_DEV : SG_DXFER_NONE);
    io.dxfer_len       = static_cast<unsigned int>(bufLen);
    io.dxferp          = buf;
    io.sbp             = senseOut;
    io.mx_sb_len       = static_cast<uint8_t>(senseLen);
    io.timeout         = 30000;  // 30 s for the command itself

    if (ioctl(fd, SG_IO, &io) != 0) return false;
    if (io.status && io.status != 0x02 /*CHECK_CONDITION is normal for ATA passthrough*/) {
        return false;
    }
    return true;
}

} // namespace core::sanitization
