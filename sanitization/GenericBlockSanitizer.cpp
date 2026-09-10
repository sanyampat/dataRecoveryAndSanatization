#include "GenericBlockSanitizer.h"

#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace core::sanitization {

namespace {

// Human-readable timestamp in UTC ISO-8601
std::string nowUtc() {
    std::time_t t = std::time(nullptr);
    std::tm utc{};
    gmtime_r(&t, &utc);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return buf;
}

} // namespace

SanitizationResult GenericBlockSanitizer::clear(const DeviceCapabilities& caps) const {
    SanitizationResult res;
    res.devicePath    = caps.devicePath;
    res.busType       = [&]() -> std::string {
        switch (caps.bus) {
            case DeviceCapabilities::BusType::NVME:    return "NVMe";
            case DeviceCapabilities::BusType::SATA:    return "SATA";
            case DeviceCapabilities::BusType::SCSI:    return "SCSI";
            case DeviceCapabilities::BusType::USB:     return "USB";
            default:                                   return "Unknown";
        }
    }();
    res.model         = caps.model;
    res.vendor        = caps.vendor;
    res.serialNumber  = caps.serialNumber;
    res.capacityBytes = caps.capacityBytes;
    res.assuranceLevel= AssuranceLevel::CLEAR;
    res.methodApplied = "Generic Block Overwrite (O_SYNC Zero-Fill)";

    // Media type label
    if (caps.isVirtual) {
        res.mediaType = "Virtual Block Device";
    } else {
        switch (caps.media) {
            case DeviceCapabilities::MediaType::HDD: res.mediaType = "HDD"; break;
            case DeviceCapabilities::MediaType::SSD: res.mediaType = "SSD (No Purge Available)"; break;
            default:                                 res.mediaType = "Unknown"; break;
        }
        if (caps.bus == DeviceCapabilities::BusType::USB) res.mediaType = "USB Storage";
    }

    res.startedAtUtc = nowUtc();
    auto t0 = std::chrono::steady_clock::now();

    if (caps.capacityBytes == 0) {
        res.error = "Device capacity is 0 bytes — unable to write.";
        return res;
    }

    // Open for Read/Write so we can verify with the same descriptor
    constexpr size_t kBufSize = 4ULL * 1024 * 1024;  // 4 MiB
    int fd = open(caps.devicePath.c_str(), O_RDWR | O_SYNC | O_DIRECT | O_CLOEXEC);
    bool usedDirect = (fd >= 0);

    if (!usedDirect) {
        fd = open(caps.devicePath.c_str(), O_RDWR | O_SYNC | O_CLOEXEC);
        if (fd < 0) {
            res.error = "Cannot open device for writing: " + std::string(std::strerror(errno));
            return res;
        }
    }

    void* rawBuf = nullptr;
    uint32_t align = caps.physicalSectorSize > 0 ? caps.physicalSectorSize : 512;
    if (posix_memalign(&rawBuf, align, kBufSize) != 0) {
        close(fd);
        res.error = "posix_memalign failed.";
        return res;
    }
    std::memset(rawBuf, 0, kBufSize);
    char* buf = static_cast<char*>(rawBuf);

    // --- Phase 1: Overwrite ---
    uint64_t written = 0;
    bool writeOk = true;

    while (written < caps.capacityBytes) {
        uint64_t remaining = caps.capacityBytes - written;
        size_t toWrite     = static_cast<size_t>(std::min<uint64_t>(kBufSize, remaining));

        // If the remaining bytes are unaligned, O_DIRECT will reject the final write
        if (usedDirect && toWrite % align != 0) {
            int flags = fcntl(fd, F_GETFL);
            fcntl(fd, F_SETFL, flags & ~O_DIRECT);
            usedDirect = false;
        }

        ssize_t r = write(fd, buf, toWrite);
        if (r <= 0) {
            res.error = "Write failed at offset " + std::to_string(written) + ": " + std::strerror(errno);
            writeOk = false;
            break;
        }
        written += static_cast<uint64_t>(r);
    }

    res.bytesProcessed = written;

    if (fsync(fd) != 0) {
        res.error = "fsync() failed after write sequence: " + std::string(std::strerror(errno));
        writeOk = false;
    }
    
    res.wipePassed = writeOk && (written == caps.capacityBytes);

    // --- Phase 2: Full Deterministic Verification ---
    if (res.wipePassed) {
        res.verificationAttempted = true;
        res.verificationMethod    = "Full Sequential Read-Back (100% Coverage)";

        if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
            res.error = "Verification failed: cannot seek to offset 0.";
            res.verificationPassed = false;
        } else {
            uint64_t verified = 0;
            bool verifyOk = true;

            while (verified < caps.capacityBytes) {
                uint64_t remaining = caps.capacityBytes - verified;
                size_t toRead      = static_cast<size_t>(std::min<uint64_t>(kBufSize, remaining));

                if (usedDirect && toRead % align != 0) {
                    int flags = fcntl(fd, F_GETFL);
                    fcntl(fd, F_SETFL, flags & ~O_DIRECT);
                    usedDirect = false;
                }

                ssize_t r = read(fd, buf, toRead);
                if (r <= 0) {
                    res.error = "Verification read failed at offset " + std::to_string(verified) + ": " + std::strerror(errno);
                    verifyOk = false;
                    break;
                }

                for (ssize_t i = 0; i < r; ++i) {
                    if (buf[i] != 0x00) {
                        char hexStr[5];
                        snprintf(hexStr, sizeof(hexStr), "0x%02X", static_cast<unsigned char>(buf[i]));
                        res.error = "Verification mismatch: Expected 0x00, found " + std::string(hexStr) +
                                    " at absolute offset " + std::to_string(verified + static_cast<uint64_t>(i));
                        verifyOk = false;
                        break;
                    }
                }
                
                if (!verifyOk) break;
                verified += static_cast<uint64_t>(r);
            }

            res.verificationPassed = verifyOk && (verified == caps.capacityBytes);
            // Note: Once SanitizationResult.h is expanded, update `res.bytesVerified = verified;` here.
        }
    }

    close(fd);
    free(rawBuf);

    auto t1 = std::chrono::steady_clock::now();
    res.durationSeconds = std::chrono::duration<double>(t1 - t0).count();
    res.completedAtUtc  = nowUtc();
    res.success         = res.wipePassed && res.verificationPassed;
    return res;
}

} // namespace core::sanitization