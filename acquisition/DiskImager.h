#pragma once

#include "../device/DriveInfo.h"

#include <cstdint>
#include <string>

namespace core::acquisition {

    // Result of a completed (or partially completed, on failure) imaging run.
    struct ImagingResult {
        bool success = false;
        std::string imagePath;
        uint64_t bytesRead = 0;
        std::string sha256;       // valid only if success == true
        std::string errorMessage; // valid only if success == false
    };

    // Streams a bit-for-bit forensic image of a source drive to an output
    // file, hashing the data as it goes via HashEngine instead of re-reading
    // the finished image afterwards just to hash it.
    //
    // Read path mirrors HddSanitizer::wipe / Verification::verifyZeroes:
    // O_DIRECT + posix_memalign-aligned buffers sized to the drive's
    // physical sector size.
    class DiskImager {
    public:
        // Images `drive` to a new file at `outputImagePath`. Creates the
        // parent directory tree if it doesn't already exist (mirrors the
        // CASE_DATA/<case>/evidence/ layout). The output file is opened
        // with ordinary buffered I/O — it's a regular file on the
        // case-data filesystem, not a raw block device, so O_DIRECT is
        // only needed on the read side.
        static ImagingResult acquire(const core::drive::DriveInfo& drive,
                                      const std::string& outputImagePath);
    };

} // namespace core::acquisition
