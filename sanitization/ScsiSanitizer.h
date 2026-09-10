#pragma once

#include "DeviceCapabilities.h"
#include "SanitizationResult.h"

namespace core::sanitization {

/// SCSI Sanitize command (SCSI Block Commands — SBC-4).
/// Also issues SCSI FORMAT UNIT as a fallback when the SANITIZE command is absent.
///
/// Achieves: NIST SP 800-88 PURGE (SANITIZE) or CLEAR (FORMAT UNIT)
class ScsiSanitizer {
public:
    ScsiSanitizer()  = default;
    ~ScsiSanitizer() = default;

    SanitizationResult purge(const DeviceCapabilities& caps) const;

private:
    SanitizationResult scsiSanitize  (int fd, const DeviceCapabilities& caps) const;
    SanitizationResult scsiFormatUnit(int fd, const DeviceCapabilities& caps) const;
    bool pollScsiSanitize(int fd, unsigned timeoutSec = 600) const;
};

} // namespace core::sanitization
