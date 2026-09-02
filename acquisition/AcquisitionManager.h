#pragma once

#include "../device/DriveInfo.h"

#include <cstdint>
#include <string>

namespace core::acquisition {

    // Metadata describing a completed forensic acquisition — ready to be
    // handed to the logging module (case record / hash-linked audit entry)
    // once that module is wired in.
    struct ImageMetadata {
        std::string sourceDevicePath;
        std::string sourceModel;
        std::string sourceSerial;
        std::string imagePath;
        uint64_t sizeBytes = 0;
        std::string sha256;
        std::string acquiredAtUtc; // ISO-8601 UTC timestamp
    };

    // Orchestrates a full acquisition run:
    //   WriteProtection::enforce() -> DiskImager::acquire() -> ImageMetadata
    //
    // If write protection can't be enforced (e.g. not running with
    // sufficient privilege), the acquisition is aborted rather than
    // silently imaging a device that wasn't actually write-blocked.
    class AcquisitionManager {
    public:
        struct Outcome {
            bool success = false;
            ImageMetadata metadata;   // valid only if success == true
            std::string errorMessage; // valid only if success == false
        };

        static Outcome acquire(const core::drive::DriveInfo& drive,
                                const std::string& outputImagePath);
    };

} // namespace core::acquisition
