#pragma once

#include "DeviceCapabilities.h"
#include "SanitizationResult.h"
#include "../device/DriveInfo.h"

#include <memory>
#include <string>

namespace core::sanitization {

/// Capability-driven sanitization router.
///
/// Rather than selecting a sanitizer from the drive's bus-type alone,
/// the engine first probes the device with DeviceCapabilityProbe to discover
/// every supported hardware command, then delegates to the appropriate
/// concrete sanitizer in priority order:
///
///   1. NVMe Sanitize (Crypto / Block / Overwrite)  → NvmeSanitizer
///   2. ATA Sanitize / ATA Security Erase           → AtaSanitizer
///   3. SCSI Sanitize / Format Unit                 → ScsiSanitizer
///   4. Generic O_SYNC zero-fill (CLEAR fallback)   → GenericBlockSanitizer
///
/// Safety guards (system-disk / mount detection) are enforced before any
/// write reaches the device.
class SanitizationEngine {
public:
    SanitizationEngine()  = default;
    ~SanitizationEngine() = default;

    /// Probe the device, select the strongest supported method, execute it,
    /// verify the result, and return a full auditable SanitizationResult.
    SanitizationResult executeSanitization(const core::drive::DriveInfo& drive);

    /// Probe only — returns the capabilities snapshot without wiping anything.
    DeviceCapabilities probeCapabilities(const core::drive::DriveInfo& drive) const;
};

} // namespace core::sanitization