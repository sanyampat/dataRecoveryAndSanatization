#pragma once

#include "RecoveredFile.h"

#include <istream>
#include <string>
#include <vector>

namespace core::recovery {

// Finds carving candidates in an already-acquired forensic image (only
// ever reads the image file produced by AcquisitionManager — never a raw
// device). Header match != done: a hit produces a *candidate* with a
// tentative end offset; FileValidator confirms structure afterward. This
// header/footer split mirrors PhotoRec's filegen.c model at the
// architecture level, even though PhotoRec itself fuses "where does it
// end" and "is it valid" into one pass for speed.
class FileCarver {
public:
    FileCarver();

    // Scans imagePath for JPEG/PDF/ZIP headers and returns one
    // RecoveredFile candidate per hit, with sourceImagePath/offsetStart/
    // offsetEnd/fileType populated and everything else left at its
    // default (Unknown/UNVERIFIED) for later pipeline stages to fill in.
    std::vector<RecoveredFile> scan(const std::string& imagePath) const;

private:
    // 4 MB reads, matching DiskImager's buffer sizing convention. Large
    // enough to amortize I/O, small enough to bound memory for a
    // sliding-window scan over a multi-GB image.
    static constexpr size_t kReadBufferSize = 4ULL * 1024 * 1024;

    // Reasonable upper bound on how far past a header we'll search for an
    // end marker before giving up. Mirrors PhotoRec's PHOTOREC_MAX_SIG_SIZE
    // -scale bounding — keeps a corrupt/never-closing candidate from
    // scanning the entire rest of a multi-GB image.
    static constexpr uint64_t kMaxCandidateSize = 200ULL * 1024 * 1024;

    std::vector<FileSignature> signatures_;

    // Per-format boundary finders. Each seeks `in` itself and returns the
    // tentative end offset (exclusive), or 0 if no plausible end was
    // found before hitting kMaxCandidateSize / end of image.
    uint64_t findJpegEnd(std::istream& in, uint64_t headerOffset, uint64_t imageSize) const;
    uint64_t findPdfEnd(std::istream& in, uint64_t headerOffset, uint64_t imageSize) const;
    uint64_t findZipEnd(std::istream& in, uint64_t headerOffset, uint64_t imageSize) const;
};

} // namespace core::recovery
