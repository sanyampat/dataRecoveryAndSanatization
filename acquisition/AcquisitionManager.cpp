#include "AcquisitionManager.h"
#include "WriteProtection.h"
#include "DiskImager.h"

#include <iostream>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>

namespace core::acquisition {

    namespace {
        std::string currentUtcTimestamp() {
            auto now = std::chrono::system_clock::now();
            std::time_t t = std::chrono::system_clock::to_time_t(now);

            std::tm utcTm{};
            gmtime_r(&t, &utcTm);

            std::ostringstream oss;
            oss << std::put_time(&utcTm, "%Y-%m-%dT%H:%M:%SZ");
            return oss.str();
        }
    }

    AcquisitionManager::Outcome AcquisitionManager::acquire(const core::drive::DriveInfo& drive,
                                                              const std::string& outputImagePath) {
        Outcome outcome;

        std::cout << "\n== Acquisition: " << drive.devicePath << " ==\n";

        if (!WriteProtection::enforce(drive)) {
            outcome.errorMessage = "Could not enforce write protection on " + drive.devicePath +
                                    " - aborting rather than imaging an unprotected device.";
            std::cerr << "  -> " << outcome.errorMessage << "\n";
            return outcome;
        }

        ImagingResult imaging = DiskImager::acquire(drive, outputImagePath);
        if (!imaging.success) {
            outcome.errorMessage = imaging.errorMessage;
            return outcome;
        }

        outcome.metadata.sourceDevicePath = drive.devicePath;
        outcome.metadata.sourceModel = drive.model;
        outcome.metadata.sourceSerial = drive.serialNumber;
        outcome.metadata.imagePath = imaging.imagePath;
        outcome.metadata.sizeBytes = imaging.bytesRead;
        outcome.metadata.sha256 = imaging.sha256;
        outcome.metadata.acquiredAtUtc = currentUtcTimestamp();

        outcome.success = true;
        return outcome;
    }

} // namespace core::acquisition
