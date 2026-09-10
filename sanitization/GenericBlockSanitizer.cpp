#include "GenericBlockSanitizer.h"
#include "Verification.h"

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
            default:                                    return "Unknown";
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
            default:                                  res.mediaType = "Unknown"; break;
        }
        if (caps.bus == DeviceCapabilities::BusType::USB) res.mediaType = "USB Storage";
    }

    res.startedAtUtc = nowUtc();
    auto t0 = std::chrono::steady_clock::now();

    if (caps.capacityBytes == 0) {
        res.error = "Device capacity is 0 bytes — unable to write. Check root privileges.";
        return res;
    }

    // -- Try O_DIRECT first (bypasses page cache for physical drives);
    //    fall back to O_SYNC if the driver or virtual device refuses it.
    constexpr size_t kBufSize = 4ULL * 1024 * 1024;  // 4 MiB

    auto openWithFlags = [&](int flags) -> int {
        return open(caps.devicePath.c_str(), flags);
    };

    int fd = openWithFlags(O_WRONLY | O_SYNC | O_DIRECT);
    bool usedDirect = (fd >= 0);

    if (!usedDirect) {
        // O_DIRECT rejected (common on virtual disks, tmpfs, loop devices)
        fd = openWithFlags(O_WRONLY | O_SYNC);
        if (fd < 0) {
            res.error = "Cannot open device for writing: " + std::string(std::strerror(errno));
            return res;
        }
        std::cerr << "[GenericBlockSanitizer] O_DIRECT unavailable on " << caps.devicePath
                  << " — using O_SYNC fallback.\n";
    }

    // Allocate memory — must be sector-aligned for O_DIRECT
    void* rawBuf = nullptr;
    if (posix_memalign(&rawBuf, static_cast<size_t>(caps.physicalSectorSize), kBufSize) != 0) {
        close(fd);
        res.error = "posix_memalign failed.";
        return res;
    }
    std::memset(rawBuf, 0, kBufSize);
    char* buf = static_cast<char*>(rawBuf);

    uint64_t written = 0;
    bool ok = true;

    while (written < caps.capacityBytes) {
        uint64_t remaining = caps.capacityBytes - written;
        size_t toWrite     = static_cast<size_t>(std::min<uint64_t>(kBufSize, remaining));

        // For O_DIRECT: chunk must be a multiple of physical sector size
        if (usedDirect && toWrite % caps.physicalSectorSize != 0) {
            toWrite = (toWrite / caps.physicalSectorSize) * caps.physicalSectorSize;
            if (toWrite == 0) break;  // less than one sector remaining — done
        }

        ssize_t r = write(fd, buf, toWrite);
        if (r <= 0) {
            if (errno == EINVAL && usedDirect) {
                // O_DIRECT rejected mid-write on some kernels — shouldn't happen
                // but handle gracefully
                std::cerr << "[GenericBlockSanitizer] O_DIRECT write error mid-stream.\n";
            }
            res.error = "Write failed at offset " + std::to_string(written) + ": " + std::strerror(errno);
            ok = false;
            break;
        }
        written += static_cast<uint64_t>(r);
    }

    fsync(fd);
    close(fd);
    free(rawBuf);

    res.bytesProcessed = written;
    res.wipePassed     = ok && (written >= caps.capacityBytes);

    // Verification
    if (res.wipePassed) {
        VerificationResult vr = Verification::verifyClear(caps);
        res.verificationAttempted = true;
        res.verificationPassed    = vr.passed;
        res.verificationMethod    = vr.method;
        res.samplesChecked        = vr.samplesChecked;
        if (!vr.passed) {
            res.error = vr.error;
        }
    }

    auto t1 = std::chrono::steady_clock::now();
    res.durationSeconds = std::chrono::duration<double>(t1 - t0).count();
    res.completedAtUtc  = nowUtc();
    res.success         = res.wipePassed && res.verificationPassed;
    return res;
}

} // namespace core::sanitization
