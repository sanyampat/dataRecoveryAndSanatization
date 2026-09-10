#pragma once

#include "DeviceCapabilities.h"
#include "SanitizationResult.h"

namespace core::sanitization {

/// Result from a single verification check.
struct VerificationResult {
    bool        passed        = false;
    uint32_t    samplesChecked= 0;
    std::string method;
    std::string error;
};

/// Post-wipe verification service.
/// Performs pseudorandom surface sampling to confirm sanitization.
///
/// Uses O_DIRECT where the driver allows (to bypass page cache);
/// falls back to O_RDONLY otherwise (virtual disks, loop devices).
class Verification {
public:
    Verification()  = default;
    ~Verification() = default;

    /// Verify a CLEAR-level wipe: confirm all sampled sectors read back as 0x00.
    static VerificationResult verifyClear(const DeviceCapabilities& caps);
};

} // namespace core::sanitization