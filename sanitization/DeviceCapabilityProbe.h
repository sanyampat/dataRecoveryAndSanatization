#pragma once

#include "DeviceCapabilities.h"
#include "../device/DriveInfo.h"

#include <string>

namespace core::sanitization {

/// Inspects a storage device and returns the full set of capabilities
/// needed to select the strongest available sanitization method.
///
/// Inspection order:
///  1. Sysfs (bus, media type, rotational, sector sizes, capacity, mounts)
///  2. NVMe Identify Controller via ioctl (SANICAP, OACS, FNA)
///  3. ATA IDENTIFY DEVICE via SG_IO (Sanitize feature set, Security feature set)
///  4. SCSI INQUIRY + Mode Sense (Sanitize support)
///  5. Vendor string heuristics for virtual machine guest detection
class DeviceCapabilityProbe {
public:
    DeviceCapabilityProbe()  = default;
    ~DeviceCapabilityProbe() = default;

    /// Probe a device described by DriveInfo.
    DeviceCapabilities probe(const core::drive::DriveInfo& drive) const;

    /// Probe directly by device path (e.g. "/dev/nvme0n1").
    DeviceCapabilities probeByPath(const std::string& devicePath) const;

private:
    // NVMe capability discovery
    void probeNvme(int fd, DeviceCapabilities& caps) const;

    // ATA capability discovery (via SCSI generic SG_IO passthrough)
    void probeAta(int fd, DeviceCapabilities& caps) const;

    // SCSI capability discovery
    void probeScsi(int fd, DeviceCapabilities& caps) const;

    // Sysfs metadata (rotational, sector sizes, capacity, bus, model, serial)
    void probeSysfs(const std::string& devName, DeviceCapabilities& caps) const;

    // /proc/mounts scanning for mounted/system-disk state
    void probeMounts(DeviceCapabilities& caps) const;

    // Virtual machine / hypervisor vendor string detection
    void probeVirtualDisk(int fd, DeviceCapabilities& caps) const;

    std::string readSysfsValue(const std::string& path) const;
};

} // namespace core::sanitization
