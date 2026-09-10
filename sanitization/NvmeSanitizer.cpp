#include "NvmeSanitizer.h"
#include "Verification.h"

#include <linux/nvme_ioctl.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

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

} // namespace

// ---------------------------------------------------------------------------

SanitizationResult NvmeSanitizer::purge(const DeviceCapabilities& caps) const {
    SanitizationResult res;
    res.devicePath    = caps.devicePath;
    res.busType       = "NVMe";
    res.mediaType     = "NVMe SSD";
    res.model         = caps.model;
    res.vendor        = caps.vendor;
    res.serialNumber  = caps.serialNumber;
    res.capacityBytes = caps.capacityBytes;
    res.assuranceLevel= AssuranceLevel::PURGE;
    res.startedAtUtc  = nowUtc();

    auto t0 = std::chrono::steady_clock::now();

    // Open device
    int fd = open(caps.devicePath.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        res.error = "Cannot open NVMe device: " + std::string(std::strerror(errno));
        return res;
    }

    // Build the ioctl command from already-probed capabilities
    struct nvme_admin_cmd cmd = {};
    bool isSanitize = false;

    if (caps.supportsNvmeSanitizeCrypto) {
        cmd.opcode   = 0x84;   // NVMe Sanitize
        cmd.cdw10    = 0x04;   // SANACT = 4 (Crypto Erase)
        res.methodApplied = "NVMe Sanitize — Crypto Erase";
        isSanitize   = true;
    } else if (caps.supportsNvmeSanitizeBlock) {
        cmd.opcode   = 0x84;
        cmd.cdw10    = 0x02;   // SANACT = 2 (Block Erase)
        res.methodApplied = "NVMe Sanitize — Block Erase";
        isSanitize   = true;
    } else if (caps.supportsNvmeSanitizeOverwrite) {
        cmd.opcode   = 0x84;
        cmd.cdw10    = 0x03;   // SANACT = 3 (Overwrite)
        res.methodApplied = "NVMe Sanitize — Overwrite";
        isSanitize   = true;
    } else if (caps.supportsNvmeFormatCrypto) {
        // Format NVM — crypto erase: LBAF=0, MSET=0, PI=0, PIL=0, SES=2 (Crypto Erase)
        cmd.opcode   = 0x80;   // NVMe Format NVM
        cmd.nsid     = 0xFFFFFFFF;
        cmd.cdw10    = (0x02u << 9);  // SES = 2 (Cryptographic Erase)
        res.methodApplied = "NVMe Format NVM — Crypto Erase";
    } else if (caps.supportsNvmeFormatUser) {
        cmd.opcode   = 0x80;
        cmd.nsid     = 0xFFFFFFFF;
        cmd.cdw10    = (0x01u << 9);  // SES = 1 (User Data Erase)
        res.methodApplied = "NVMe Format NVM — User Data Erase";
    } else {
        close(fd);
        res.error = "No NVMe Sanitize or Format NVM command supported by this controller.";
        return res;
    }

    std::cout << "[NvmeSanitizer] Dispatching: " << res.methodApplied << "\n";

    if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) != 0) {
        close(fd);
        res.error = "NVMe ioctl submission failed: " + std::string(std::strerror(errno));
        return res;
    }

    if (isSanitize) {
        res.wipePassed = pollSanitizeLog(fd);
        if (!res.wipePassed) {
            res.error = "NVMe Sanitize: timed out or device reported failure in log page 0x81.";
        }
    } else {
        // Format NVM returns synchronously (or with a quick completion)
        res.wipePassed = true;
        std::cout << "[NvmeSanitizer] Format NVM issued successfully.\n";
    }

    close(fd);

    if (res.wipePassed) {
        res.bytesProcessed = caps.capacityBytes;
        VerificationResult vr = Verification::verifyClear(caps);
        res.verificationAttempted = true;
        res.verificationPassed    = vr.passed;
        res.verificationMethod    = vr.method;
        res.samplesChecked        = vr.samplesChecked;
        if (!vr.passed) res.error = vr.error;
    }

    auto t1 = std::chrono::steady_clock::now();
    res.durationSeconds = std::chrono::duration<double>(t1 - t0).count();
    res.completedAtUtc  = nowUtc();
    res.success         = res.wipePassed && res.verificationPassed;
    return res;
}

// ---------------------------------------------------------------------------
// Poll Sanitize Log Page 0x81 until completion or timeout
// ---------------------------------------------------------------------------

bool NvmeSanitizer::pollSanitizeLog(int fd) const {
    constexpr unsigned kMaxPolls = 300;  // 300 × 2 s = 10 min
    uint8_t log_buf[512] = {};

    for (unsigned poll = 0; poll < kMaxPolls; ++poll) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        struct nvme_admin_cmd logCmd = {};
        logCmd.opcode   = 0x02;    // Get Log Page
        logCmd.nsid     = 0xFFFFFFFF;
        logCmd.addr     = reinterpret_cast<__u64>(log_buf);
        logCmd.data_len = 512;
        logCmd.cdw10    = 0x81 | (0x7F << 16);  // LID=0x81, NUMD=127

        if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &logCmd) != 0) {
            std::cerr << "[NvmeSanitizer] Failed to read Sanitize Log Page.\n";
            continue;
        }

        uint16_t sprog = static_cast<uint16_t>(log_buf[0] | (log_buf[1] << 8));
        uint16_t sstat = static_cast<uint16_t>(log_buf[2] | (log_buf[3] << 8));
        uint8_t  status = sstat & 0x07;

        switch (status) {
            case 0x01:  // Completed successfully
                std::cout << "\n[NvmeSanitizer] Sanitize completed successfully.\n";
                return true;
            case 0x02:  // In progress
            {
                unsigned pct = static_cast<unsigned>((static_cast<uint64_t>(sprog) * 100ULL) / 65535ULL);
                std::cout << "[NvmeSanitizer] Sanitize in progress: " << pct << "%\r" << std::flush;
                break;
            }
            case 0x03:  // Failed
                std::cerr << "\n[NvmeSanitizer] Sanitize FAILED (SSTAT=0x03).\n";
                return false;
            case 0x04:  // Completed with deallocation
                std::cout << "\n[NvmeSanitizer] Sanitize completed (with deallocation).\n";
                return true;
            default:
                std::cerr << "\n[NvmeSanitizer] Unknown SSTAT=" << static_cast<int>(status) << "\n";
                return false;
        }
    }
    return false;
}

} // namespace core::sanitization