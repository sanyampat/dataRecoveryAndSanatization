#include "DiskImager.h"
#include "HashEngine.h"

#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <filesystem>

namespace core::acquisition {

    ImagingResult DiskImager::acquire(const core::drive::DriveInfo& drive,
                                       const std::string& outputImagePath) {
        ImagingResult result;
        result.imagePath = outputImagePath;

        std::cout << "  -> Starting forensic image acquisition from " << drive.devicePath << "...\n";

        // Make sure the destination directory exists (CASE_DATA/<case>/evidence/...)
        std::filesystem::path outPath(outputImagePath);
        if (outPath.has_parent_path()) {
            std::error_code dirErr;
            std::filesystem::create_directories(outPath.parent_path(), dirErr);
            if (dirErr) {
                result.errorMessage = "Could not create output directory: " + dirErr.message();
                return result;
            }
        }

        // Open the source with O_DIRECT — same pattern as HddSanitizer/Verification.
        int srcFd = open(drive.devicePath.c_str(), O_RDONLY | O_DIRECT);
        if (srcFd < 0) {
            result.errorMessage = "Could not open source device: " + drive.devicePath;
            return result;
        }

        // Output image is a regular file on the case-data filesystem — buffered
        // I/O is fine here, O_DIRECT is only a source-device concern.
        std::ofstream outFile(outputImagePath, std::ios::binary | std::ios::trunc);
        if (!outFile) {
            close(srcFd);
            result.errorMessage = "Could not open output image file: " + outputImagePath;
            return result;
        }

        const size_t bufferSize = 4 * 1024 * 1024; // 4 MiB chunks, matches HddSanitizer/HashEngine test
        void* alignedBuffer = nullptr;
        if (posix_memalign(&alignedBuffer, drive.physicalSectorSize, bufferSize) != 0) {
            close(srcFd);
            result.errorMessage = "posix_memalign failed";
            return result;
        }

        char* readBuf = static_cast<char*>(alignedBuffer);
        HashEngine hasher;

        uint64_t bytesRead = 0;
        bool failed = false;

        while (bytesRead < drive.capacityBytes) {
            size_t toRead = std::min(static_cast<uint64_t>(bufferSize), drive.capacityBytes - bytesRead);

            // O_DIRECT reads must be sector-aligned in length as well as offset.
            if (toRead % drive.physicalSectorSize != 0) {
                toRead = (toRead / drive.physicalSectorSize) * drive.physicalSectorSize;
                if (toRead == 0) break; // remainder smaller than one sector — stop
            }

            ssize_t n = read(srcFd, readBuf, toRead);
            if (n < 0) {
                result.errorMessage = "Read failed at offset " + std::to_string(bytesRead);
                failed = true;
                break;
            }
            if (n == 0) break; // end of device

            outFile.write(readBuf, n);
            if (!outFile) {
                result.errorMessage = "Write failed at offset " + std::to_string(bytesRead);
                failed = true;
                break;
            }

            hasher.update(readBuf, static_cast<size_t>(n));
            bytesRead += static_cast<uint64_t>(n);
        }

        free(alignedBuffer);
        close(srcFd);
        outFile.close();

        result.bytesRead = bytesRead;

        if (failed) {
            return result; // success stays false
        }

        result.sha256 = hasher.finalize();
        result.success = true;

        std::cout << "  -> Acquisition complete. " << bytesRead << " bytes imaged.\n";
        std::cout << "  -> SHA-256: " << result.sha256 << "\n";

        return result;
    }

} // namespace core::acquisition
