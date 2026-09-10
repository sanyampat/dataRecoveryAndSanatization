#include "Verification.h"

#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <string>

namespace core::sanitization {

VerificationResult Verification::verifyClear(const DeviceCapabilities& caps) {
    VerificationResult vr;
    vr.method = "Pseudorandom Read-Back (1000 × 1 MiB samples)";

    if (caps.capacityBytes == 0) {
        vr.error = "Cannot verify: capacity is 0 bytes.";
        return vr;
    }

    constexpr size_t kSampleSize = 1024 * 1024;  // 1 MiB per sample
    constexpr uint32_t kNumSamples = 1000;

    if (caps.capacityBytes < static_cast<uint64_t>(kSampleSize) * 2) {
        vr.error = "Drive too small for 1000-point sampling.";
        return vr;
    }

    // Try O_DIRECT first (bypasses page cache for physical drives);
    // fall back to O_RDONLY for virtual disks and loop devices.
    int fd = open(caps.devicePath.c_str(), O_RDONLY | O_DIRECT | O_CLOEXEC);
    bool usedDirect = (fd >= 0);
    if (!usedDirect) {
        fd = open(caps.devicePath.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            vr.error = "Cannot open device for verification: " + std::string(std::strerror(errno));
            return vr;
        }
        std::cerr << "[Verification] O_DIRECT unavailable on " << caps.devicePath
                  << " — using buffered read-back.\n";
    }

    // Aligned buffer (required by O_DIRECT)
    void* rawBuf = nullptr;
    const uint32_t align = caps.physicalSectorSize > 0 ? caps.physicalSectorSize : 512;
    if (posix_memalign(&rawBuf, align, kSampleSize) != 0) {
        close(fd);
        vr.error = "posix_memalign failed.";
        return vr;
    }
    char* buf = static_cast<char*>(rawBuf);

    std::random_device rd;
    std::mt19937_64 gen(rd());

    const uint64_t regionSize = caps.capacityBytes / kNumSamples;
    bool ok = true;
    uint32_t sampled = 0;

    for (uint32_t i = 0; i < kNumSamples && ok; ++i) {
        uint64_t regionStart = static_cast<uint64_t>(i) * regionSize;
        uint64_t maxOffset   = regionStart + regionSize;

        // Clamp to capacity, leave room for one sample block
        if (maxOffset + kSampleSize > caps.capacityBytes) {
            maxOffset = caps.capacityBytes - kSampleSize;
        }
        if (maxOffset < regionStart) maxOffset = regionStart;

        std::uniform_int_distribution<uint64_t> dist(regionStart, maxOffset);
        uint64_t offset = dist(gen);

        // Sector-align
        offset = (offset / align) * align;
        // Final boundary check
        if (offset + kSampleSize > caps.capacityBytes) {
            offset = ((caps.capacityBytes - kSampleSize) / align) * align;
        }

        if (lseek(fd, static_cast<off_t>(offset), SEEK_SET) == static_cast<off_t>(-1)) {
            vr.error = "Seek failed at offset " + std::to_string(offset);
            ok = false;
            break;
        }

        ssize_t r = read(fd, buf, kSampleSize);
        if (r <= 0) {
            vr.error = "Read failed at offset " + std::to_string(offset) + ": " + std::strerror(errno);
            ok = false;
            break;
        }

        // Check every byte for non-zero
        for (ssize_t j = 0; j < r; ++j) {
            if (buf[j] != 0x00) {
                vr.error = "Non-zero byte (0x" +
                           [&]() { char h[3]; snprintf(h, sizeof(h), "%02X", (unsigned char)buf[j]); return std::string(h); }() +
                           ") at absolute offset " + std::to_string(offset + static_cast<uint64_t>(j));
                ok = false;
                break;
            }
        }
        ++sampled;
    }

    free(rawBuf);
    close(fd);

    vr.samplesChecked = sampled;
    vr.passed         = ok;
    return vr;
}

} // namespace core::sanitization