#pragma once

#include "DeviceCapabilities.h"
#include "SanitizationResult.h"

namespace core::sanitization {

/// Handles all drives where no hardware Purge command is available:
///   - Virtual disks (VMware, VirtualBox, QEMU, KVM)
///   - USB flash drives without passthrough ATA/SCSI support
///   - Drives where O_DIRECT fails (virtual block devices)
///   - Any unrecognised bus/media type
///
/// Achieves: NIST SP 800-88 CLEAR
/// Method:   O_WRONLY | O_SYNC sequential zero-fill with optional O_DIRECT upgrade.
class GenericBlockSanitizer {
public:
    GenericBlockSanitizer()  = default;
    ~GenericBlockSanitizer() = default;

    SanitizationResult clear(const DeviceCapabilities& caps) const;
};

} // namespace core::sanitization
