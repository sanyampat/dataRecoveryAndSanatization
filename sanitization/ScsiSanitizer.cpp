#include "ScsiSanitizer.h"
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

bool sendScsiCmd(int fd, uint8_t* cdb, size_t cdbLen,
                 uint8_t* buf, size_t bufLen, bool dataIn,
                 uint8_t* sense, size_t senseLen,
                 unsigned timeoutMs = 30000) {
    sg_io_hdr_t io = {};
    io.interface_id    = 'S';
    io.cmd_len         = static_cast<uint8_t>(cdbLen);
    io.cmdp            = cdb;
    io.dxfer_direction = dataIn ? SG_DXFER_FROM_DEV
                                : (bufLen ? SG_DXFER_TO_DEV : SG_DXFER_NONE);
    io.dxfer_len       = static_cast<unsigned int>(bufLen);
    io.dxferp          = buf;
    io.sbp             = sense;
    io.mx_sb_len       = static_cast<uint8_t>(senseLen);
    io.timeout         = timeoutMs;
    return ioctl(fd, SG_IO, &io) == 0;
}

} // namespace

// ---------------------------------------------------------------------------

SanitizationResult ScsiSanitizer::purge(const DeviceCapabilities& caps) const {
    auto t0 = std::chrono::steady_clock::now();

    int fd = open(caps.devicePath.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        SanitizationResult r;
        r.devicePath = caps.devicePath;
        r.error      = "Cannot open device: " + std::string(std::strerror(errno));
        return r;
    }

    SanitizationResult res = caps.supportsScsiSanitize
                               ? scsiSanitize  (fd, caps)
                               : scsiFormatUnit(fd, caps);

    close(fd);

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
    res.success = res.wipePassed && res.verificationPassed;
    return res;
}

// ---------------------------------------------------------------------------
// SCSI SANITIZE command (opcode 0x48)
// Service Action 0x01 = OVERWRITE — most broadly supported purge action
// ---------------------------------------------------------------------------

SanitizationResult ScsiSanitizer::scsiSanitize(int fd, const DeviceCapabilities& caps) const {
    SanitizationResult res;
    res.devicePath    = caps.devicePath;
    res.busType       = "SCSI";
    res.mediaType     = "SCSI Direct-Access Device";
    res.model         = caps.model;
    res.vendor        = caps.vendor;
    res.serialNumber  = caps.serialNumber;
    res.capacityBytes = caps.capacityBytes;
    res.methodApplied = "SCSI Sanitize — Overwrite";
    res.assuranceLevel= AssuranceLevel::PURGE;
    res.startedAtUtc  = nowUtc();

    // SANITIZE CDB (10 bytes)
    //  byte 0: 0x48 (SANITIZE)
    //  byte 1: Service Action = 0x01 (OVERWRITE)
    //  byte 1 bit 7: IMMED=1 (return immediately; we poll via REQUEST SENSE)
    uint8_t cdb[10] = {};
    cdb[0] = 0x48;
    cdb[1] = 0x01 | (1u << 7);  // SERVICE ACTION=OVERWRITE, IMMED=1

    uint8_t sense[32] = {};
    if (!sendScsiCmd(fd, cdb, sizeof(cdb), nullptr, 0, false, sense, sizeof(sense))) {
        res.error = "SCSI SANITIZE command rejected.";
        return res;
    }

    res.wipePassed = pollScsiSanitize(fd, 600);
    if (!res.wipePassed) res.error = "SCSI SANITIZE: timed out waiting for completion.";
    res.bytesProcessed = res.wipePassed ? caps.capacityBytes : 0;
    return res;
}

// ---------------------------------------------------------------------------
// SCSI FORMAT UNIT — fallback CLEAR when SANITIZE not supported
// ---------------------------------------------------------------------------

SanitizationResult ScsiSanitizer::scsiFormatUnit(int fd, const DeviceCapabilities& caps) const {
    SanitizationResult res;
    res.devicePath    = caps.devicePath;
    res.busType       = "SCSI";
    res.mediaType     = "SCSI Direct-Access Device";
    res.model         = caps.model;
    res.vendor        = caps.vendor;
    res.serialNumber  = caps.serialNumber;
    res.capacityBytes = caps.capacityBytes;
    res.methodApplied = "SCSI Format Unit (CLEAR fallback)";
    res.assuranceLevel= AssuranceLevel::CLEAR;
    res.startedAtUtc  = nowUtc();

    // FORMAT UNIT (opcode 0x04)
    uint8_t cdb[6] = { 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t sense[32] = {};

    if (!sendScsiCmd(fd, cdb, sizeof(cdb), nullptr, 0, false, sense, sizeof(sense), 900000)) {
        res.error = "SCSI FORMAT UNIT command failed.";
        return res;
    }

    res.wipePassed    = true;
    res.bytesProcessed= caps.capacityBytes;
    return res;
}

// ---------------------------------------------------------------------------
// Poll SCSI Sanitize completion via REQUEST SENSE (0x03)
// SCSI drives return 0x04/0x1B ("SANITIZE IN PROGRESS") while busy
// ---------------------------------------------------------------------------

bool ScsiSanitizer::pollScsiSanitize(int fd, unsigned timeoutSec) const {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSec);
    uint8_t cdb[6]    = { 0x03, 0x00, 0x00, 0x00, 0x12, 0x00 };  // REQUEST SENSE
    while (std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        uint8_t sdata[18] = {};
        uint8_t sense[32] = {};
        if (!sendScsiCmd(fd, cdb, sizeof(cdb), sdata, sizeof(sdata), true, sense, sizeof(sense))) {
            continue;
        }
        uint8_t sk  = sdata[2]  & 0x0F;
        uint8_t asc = sdata[12];
        uint8_t asq = sdata[13];

        if (sk == 0x00) return true;  // No sense — done
        if (sk == 0x02 && asc == 0x04 && asq == 0x1B) continue;  // Still in progress
        if (sk == 0x02 && asc == 0x04 && asq == 0x00) continue;  // Becoming ready
        return false;  // Any other error
    }
    return false;
}

} // namespace core::sanitization
