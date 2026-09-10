#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace core::drive {

enum class BusType {
    NVME,
    SATA,
    SCSI,
    USB,
    UNKNOWN
};

enum class MediaType {
    HDD,
    SSD,
    UNKNOWN
};

struct DriveInfo {
    std::string devicePath;
    std::string model;
    std::string serialNumber;

    uint64_t capacityBytes = 0;

    uint32_t logicalSectorSize = 512;
    uint32_t physicalSectorSize = 512;

    bool isRotational = false;

    BusType bus = BusType::UNKNOWN;
    MediaType mediaType = MediaType::UNKNOWN;

    // Safety and mount point tracking
    bool isMounted = false;
    bool isSystemDisk = false;
    std::vector<std::string> mountPoints;

    // --------------------------------------------------------
    // Bus type
    // --------------------------------------------------------

    std::string getBusTypeString() const {
        switch (bus) {
            case BusType::NVME:
                return "NVMe";

            case BusType::SATA:
                return "SATA";

            case BusType::SCSI:
                return "SCSI";

            case BusType::USB:
                return "USB";

            default:
                return "Unknown";
        }
    }

    // --------------------------------------------------------
    // Media type
    // --------------------------------------------------------

    std::string getMediaTypeString() const {
        switch (mediaType) {
            case MediaType::HDD:
                return "HDD";

            case MediaType::SSD:
                return "SSD";

            default:
                return "Unknown";
        }
    }
};

} // namespace core::drive