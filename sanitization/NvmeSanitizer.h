#pragma once

#include "DeviceCapabilities.h"
#include "SanitizationResult.h"

namespace core::sanitization {

/// NVMe sanitization commands (via NVME_IOCTL_ADMIN_CMD):
///   1. NVMe Sanitize — Crypto Erase   (SANICAP bit 0)  → PURGE
///   2. NVMe Sanitize — Block Erase    (SANICAP bit 1)  → PURGE
///   3. NVMe Sanitize — Overwrite      (SANICAP bit 2)  → PURGE
///   4. NVMe Format NVM — Crypto Erase (OACS bit 1 + FNA bit 1) → PURGE
///   5. NVMe Format NVM — User Erase   (OACS bit 1)     → PURGE
///
/// Completion is polled via Sanitize Log Page (0x81).
class NvmeSanitizer {
public:
    NvmeSanitizer()  = default;
    ~NvmeSanitizer() = default;

    /// Execute the strongest supported NVMe Purge command.
    SanitizationResult purge(const DeviceCapabilities& caps) const;

private:
    bool pollSanitizeLog(int fd) const;
};

} // namespace core::sanitization