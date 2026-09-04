#pragma once

#include <cstdint>
#include <string>

// core::recovery — carving-only recovery pipeline (JPEG/PDF/ZIP) that
// consumes an already-acquired image file (AcquisitionManager's
// ImageMetadata::imagePath), never a raw device. No filesystem parsing,
// no deleted-file/free-space/slack-space logic in this build — see
// ForensicOS_Recovery_Context.md Section 3 for the optional libtsk
// stretch slice and Section "out of scope" notes.

namespace core::recovery {

enum class FileType {
    UNKNOWN,
    JPEG,
    PDF,
    ZIP
};

enum class FileCategory {
    Unknown,
    Images,
    Documents,
    Archives
};

// Mirrors the VALID/PARTIAL/CORRUPT/UNVERIFIED convention already used
// elsewhere in the project (ForensicOS_README.md Sec.35) rather than
// inventing new terminology.
enum class ValidationState {
    VALID,
    PARTIAL,
    CORRUPT,
    UNVERIFIED
};

// Project-original four-tier scoring model (ForensicOS_README.md
// Sec.38/62). This is NOT a NIST SP 800-86 concept — neither PhotoRec nor
// TSK implement anything resembling it. Do not cite it as NIST in
// slides/report language.
enum class ConfidenceLevel {
    HIGH,
    MEDIUM,
    LOW,
    UNVERIFIED
};

inline std::string toString(FileType type) {
    switch (type) {
        case FileType::JPEG: return "JPEG";
        case FileType::PDF:  return "PDF";
        case FileType::ZIP:  return "ZIP";
        default:             return "UNKNOWN";
    }
}

inline std::string toString(FileCategory category) {
    switch (category) {
        case FileCategory::Images:    return "Images";
        case FileCategory::Documents: return "Documents";
        case FileCategory::Archives:  return "Archives";
        default:                      return "Unknown";
    }
}

inline std::string toString(ValidationState state) {
    switch (state) {
        case ValidationState::VALID:   return "VALID";
        case ValidationState::PARTIAL: return "PARTIAL";
        case ValidationState::CORRUPT: return "CORRUPT";
        default:                       return "UNVERIFIED";
    }
}

inline std::string toString(ConfidenceLevel level) {
    switch (level) {
        case ConfidenceLevel::HIGH:   return "HIGH";
        case ConfidenceLevel::MEDIUM: return "MEDIUM";
        case ConfidenceLevel::LOW:    return "LOW";
        default:                      return "UNVERIFIED";
    }
}

// A single signature-table entry FileCarver scans block-by-block for.
// Deliberately a flat, small table rather than PhotoRec's 256-bucket
// linked list (file_check_list_t) — that structure exists to scan dozens
// of formats fast; at 2-3 formats a flat vector scanned per candidate
// offset is simpler and fast enough.
struct FileSignature {
    FileType    fileType;
    uint64_t    magicOffset;   // offset of magicBytes within the candidate, from its start
    std::string magicBytes;    // raw byte sequence; may contain arbitrary/non-printable bytes
};

// One carved-and-processed recovery candidate. Populated incrementally
// across the pipeline:
//   FileCarver     -> sourceImagePath, offsetStart, offsetEnd, fileType
//   FileValidator  -> validationState (and, for ZIP, corrects offsetEnd
//                      to the EOCD-derived authoritative length)
//   ConfidenceScorer -> confidence
//   FileClassifier -> category, outputPath, sha256, timestampUtc
struct RecoveredFile {
    std::string      sourceImagePath;
    uint64_t         offsetStart     = 0;
    uint64_t         offsetEnd       = 0;   // exclusive
    FileType         fileType        = FileType::UNKNOWN;
    FileCategory     category        = FileCategory::Unknown;
    ValidationState  validationState = ValidationState::UNVERIFIED;
    ConfidenceLevel  confidence      = ConfidenceLevel::UNVERIFIED;
    std::string      outputPath;   // empty if not written to CASE_DATA
    std::string      sha256;       // empty until FileClassifier computes it
    std::string      timestampUtc; // set by FileClassifier when written

    uint64_t size() const {
        return offsetEnd > offsetStart ? offsetEnd - offsetStart : 0;
    }
};

} // namespace core::recovery
