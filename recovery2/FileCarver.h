#pragma once

#include "RecoveredFile.h"
#include <tsk/libtsk.h>

#include <istream>
#include <string>
#include <vector>

namespace core::recovery {

// Finds carving candidates using Sleuthkit's optimized image I/O.
// Header match != done: a hit produces a *candidate* with a tentative end
// offset; FileValidator confirms structure afterward.
class FileCarver {
public:
    FileCarver();
    ~FileCarver();

    // Scans imagePath for JPEG/PDF/ZIP headers using TSK's image API
    // Returns one RecoveredFile candidate per hit, with sourceImagePath/offsetStart/
    // offsetEnd/fileType populated and everything else left at its default
    // (Unknown/UNVERIFIED) for later pipeline stages to fill in.
    std::vector<RecoveredFile> scan(const std::string& imagePath) const;

private:
    // TSK uses 4 MB buffer sizing internally; we align with that
    // for coherence with DiskImager's convention.
    static constexpr size_t kReadBufferSize = 4ULL * 1024 * 1024;

    // Reasonable upper bound on how far past a header we'll search for an
    // end marker before giving up. Mirrors PhotoRec's PHOTOREC_MAX_SIG_SIZE.
    static constexpr uint64_t kMaxCandidateSize = 200ULL * 1024 * 1024;

    std::vector<FileSignature> signatures_;

    // Per-format boundary finders using TSK's image handle.
    // Each seeks within the image and returns the tentative end offset (exclusive),
    // or 0 if no plausible end was found.
    uint64_t findJpegEnd(TSK_IMG_INFO* imgInfo, uint64_t headerOffset, 
                         uint64_t imageSize) const;
    uint64_t findPdfEnd(TSK_IMG_INFO* imgInfo, uint64_t headerOffset, 
                        uint64_t imageSize) const;
    uint64_t findZipEnd(TSK_IMG_INFO* imgInfo, uint64_t headerOffset, 
                        uint64_t imageSize) const;

    // Helper: read from TSK image with error handling
    ssize_t readFromImage(TSK_IMG_INFO* imgInfo, uint64_t offset, 
                          char* buf, size_t len) const;
};

} // namespace core::recovery