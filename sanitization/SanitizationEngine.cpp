#include "SanitizationEngine.h"
#include "DeviceCapabilityProbe.h"
#include "NvmeSanitizer.h"
#include "AtaSanitizer.h"
#include "ScsiSanitizer.h"
#include "GenericBlockSanitizer.h"

#include <iostream>

namespace core::sanitization {

DeviceCapabilities SanitizationEngine::probeCapabilities(const core::drive::DriveInfo& drive) const {
    DeviceCapabilityProbe probe;
    return probe.probe(drive);
}

SanitizationResult SanitizationEngine::executeSanitization(const core::drive::DriveInfo& drive) {
    // 1. Probe device capabilities
    DeviceCapabilityProbe probe;
    DeviceCapabilities caps = probe.probe(drive);

    // 2. Safety guards — abort before any write
    if (caps.isSystemDisk) {
        SanitizationResult r;
        r.devicePath   = drive.devicePath;
        r.blocked      = true;
        r.success      = false;
        r.error        = "CRITICAL SAFETY BLOCK: target is an active system disk (mount points: ";
        for (const auto& m : caps.mountPoints) r.error += m + " ";
        r.error += "). Sanitization refused.";
        return r;
    }
    if (caps.isMounted) {
        SanitizationResult r;
        r.devicePath = drive.devicePath;
        r.blocked    = true;
        r.success    = false;
        r.error      = "SAFETY BLOCK: device has mounted partitions (";
        for (const auto& m : caps.mountPoints) r.error += m + " ";
        r.error += "). Unmount all partitions and retry.";
        return r;
    }

    std::cout << "[SanitizationEngine] Probed " << caps.devicePath << "\n"
              << "  Bus: " << [&]() -> std::string {
                    switch (caps.bus) {
                        case DeviceCapabilities::BusType::NVME: return "NVMe";
                        case DeviceCapabilities::BusType::SATA: return "SATA";
                        case DeviceCapabilities::BusType::SCSI: return "SCSI";
                        case DeviceCapabilities::BusType::USB:  return "USB";
                        default:                                 return "Unknown";
                    }
              }() << "\n"
              << "  Best method available: " << caps.bestMethod() << "\n"
              << "  Assurance achievable: " << (caps.canAchievePurge() ? "PURGE" : "CLEAR") << "\n";

    // 3. Dispatch to the strongest supported sanitizer
    //    Priority order matches NIST 800-88 preference hierarchy.

    // NVMe
    if (caps.bus == DeviceCapabilities::BusType::NVME &&
        (caps.supportsNvmeSanitizeCrypto || caps.supportsNvmeSanitizeBlock ||
         caps.supportsNvmeSanitizeOverwrite || caps.supportsNvmeFormatCrypto ||
         caps.supportsNvmeFormatUser)) {
        NvmeSanitizer nvm;
        return nvm.purge(caps);
    }

    // ATA/SATA
    if (caps.bus == DeviceCapabilities::BusType::SATA &&
        (caps.supportsAtaSanitizeCrypto || caps.supportsAtaSanitizeBlock ||
         caps.supportsAtaSecurityErase || caps.supportsAtaEnhSecurityErase)) {
        AtaSanitizer ata;
        return ata.purge(caps);
    }

    // SCSI
    if ((caps.bus == DeviceCapabilities::BusType::SCSI) &&
        (caps.supportsScsiSanitize || caps.supportsScsiFormatUnit)) {
        ScsiSanitizer scsi;
        return scsi.purge(caps);
    }

    // Fallback: Generic O_SYNC zero-fill (CLEAR) — handles USB, virtual disks,
    // frozen-security SATA drives, and anything else.
    std::cerr << "[SanitizationEngine] No hardware Purge command available — "
              << "falling back to NIST Clear (generic zero-fill).\n";
    GenericBlockSanitizer generic;
    return generic.clear(caps);
}

} // namespace core::sanitization