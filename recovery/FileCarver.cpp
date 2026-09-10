#include "FileCarver.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace core::recovery {

FileCarver::FileCarver() {
    // Populate signature table for JPEG, PDF, ZIP
    signatures_.push_back({FileType::JPEG, 0, "\xFF\xD8\xFF"});
    signatures_.push_back({FileType::PDF,  0, "%PDF-"});
    signatures_.push_back({FileType::ZIP,  0, "PK\x03\x04"});
}

FileCarver::~FileCarver() = default;

// Helper: read from TSK image with proper error handling
ssize_t FileCarver::readFromImage(TSK_IMG_INFO* imgInfo, uint64_t offset,
                                   char* buf, size_t len) const {
    if (!imgInfo || !buf) return -1;
    
    // TSK's img_read returns ssize_t: bytes read or -1 on error
    ssize_t bytesRead = tsk_img_read(imgInfo, offset, buf, len);
    return bytesRead;
}

std::vector<RecoveredFile> FileCarver::scan(const std::string& imagePath) const {
    std::vector<RecoveredFile> candidates;

    // Open image using Sleuthkit's optimized I/O layer
    TSK_IMG_INFO* imgInfo = tsk_img_open_sing(imagePath.c_str(), TSK_IMG_TYPE_DETECT, 0);
    if (!imgInfo) {
        tsk_error_print(stderr);
        return candidates;
    }

    uint64_t imageSize = imgInfo->size;
    std::vector<char> buf(kReadBufferSize);
    uint64_t currentOffset = 0;

    // Sliding window scan using TSK's buffered reads (more efficient than direct file I/O)
    while (currentOffset < imageSize) {
        uint64_t toRead = std::min<uint64_t>(kReadBufferSize, imageSize - currentOffset);
        
        ssize_t bytesRead = readFromImage(imgInfo, currentOffset, buf.data(), toRead);
        if (bytesRead <= 0) break;

        // Check each signature against the buffer
        for (const auto& sig : signatures_) {
            for (size_t i = 0; i + sig.magicBytes.size() <= static_cast<size_t>(bytesRead); ++i) {
                if (std::memcmp(buf.data() + i, sig.magicBytes.data(), 
                               sig.magicBytes.size()) == 0) {
                    uint64_t headerOffset = currentOffset + i;

                    // Find the end of the candidate based on file type
                    uint64_t endOffset = 0;
                    switch (sig.fileType) {
                        case FileType::JPEG:
                            endOffset = findJpegEnd(imgInfo, headerOffset, imageSize);
                            break;
                        case FileType::PDF:
                            endOffset = findPdfEnd(imgInfo, headerOffset, imageSize);
                            break;
                        case FileType::ZIP:
                            endOffset = findZipEnd(imgInfo, headerOffset, imageSize);
                            break;
                        default:
                            endOffset = headerOffset + kMaxCandidateSize;
                    }

                    if (endOffset > headerOffset) {
                        RecoveredFile candidate;
                        candidate.sourceImagePath = imagePath;
                        candidate.offsetStart = headerOffset;
                        candidate.offsetEnd = endOffset;
                        candidate.fileType = sig.fileType;
                        candidates.push_back(candidate);
                    }
                }
            }
        }

        currentOffset += bytesRead;
    }

    tsk_img_close(imgInfo);
    return candidates;
}

uint64_t FileCarver::findJpegEnd(TSK_IMG_INFO* imgInfo, uint64_t headerOffset,
                                  uint64_t imageSize) const {
    // JPEG ends with FFD9 marker. Scan forward looking for it.
    uint64_t searchLimit = std::min(headerOffset + kMaxCandidateSize, imageSize);
    std::vector<char> buf(kReadBufferSize);

    for (uint64_t offset = headerOffset; offset < searchLimit; offset += kReadBufferSize) {
        uint64_t toRead = std::min<uint64_t>(kReadBufferSize, searchLimit - offset);
        
        ssize_t bytesRead = readFromImage(imgInfo, offset, buf.data(), toRead);
        if (bytesRead <= 0) return 0;

        // Search for FFD9 marker
        for (ssize_t i = 0; i + 1 < bytesRead; ++i) {
            if (static_cast<unsigned char>(buf[i]) == 0xFF &&
                static_cast<unsigned char>(buf[i + 1]) == 0xD9) {
                return offset + i + 2;  // +2 to include the marker itself
            }
        }
    }

    return 0;  // No end marker found
}

uint64_t FileCarver::findPdfEnd(TSK_IMG_INFO* imgInfo, uint64_t headerOffset,
                                 uint64_t imageSize) const {
    // PDF ends with %%EOF. Scan forward looking for it.
    uint64_t searchLimit = std::min(headerOffset + kMaxCandidateSize, imageSize);
    std::vector<char> buf(kReadBufferSize);
    std::string eofMarker = "%%EOF";

    for (uint64_t offset = headerOffset; offset < searchLimit; offset += kReadBufferSize) {
        uint64_t toRead = std::min<uint64_t>(kReadBufferSize, searchLimit - offset);
        
        ssize_t bytesRead = readFromImage(imgInfo, offset, buf.data(), toRead);
        if (bytesRead <= 0) return 0;

        // Search for %%EOF marker
        for (ssize_t i = 0; i + static_cast<ssize_t>(eofMarker.size()) <= bytesRead; ++i) {
            if (std::memcmp(buf.data() + i, eofMarker.c_str(), eofMarker.size()) == 0) {
                return offset + i + eofMarker.size();
            }
        }
    }

    return 0;  // No end marker found
}

uint64_t FileCarver::findZipEnd(TSK_IMG_INFO* imgInfo, uint64_t headerOffset,
                                 uint64_t imageSize) const {
    // ZIP ends with EOCD (PK\x05\x06). Scan forward with reasonable bound.
    uint64_t searchLimit = std::min(headerOffset + kMaxCandidateSize, imageSize);
    std::vector<char> buf(kReadBufferSize);
    std::string eocdSig("PK\x05\x06", 4);

    for (uint64_t offset = headerOffset; offset < searchLimit; offset += kReadBufferSize) {
        uint64_t toRead = std::min<uint64_t>(kReadBufferSize, searchLimit - offset);
        
        ssize_t bytesRead = readFromImage(imgInfo, offset, buf.data(), toRead);
        if (bytesRead <= 0) return 0;

        // Search for EOCD signature
        for (ssize_t i = 0; i + static_cast<ssize_t>(eocdSig.size()) <= bytesRead; ++i) {
            if (std::memcmp(buf.data() + i, eocdSig.c_str(), eocdSig.size()) == 0) {
                // Tentative end; FileValidator will refine this
                return offset + i + 22;  // EOCD minimum size
            }
        }
    }

    return 0;  // No end marker found
}

} // namespace core::recovery