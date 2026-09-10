#include "FileValidator.h"

#include <cstdint>
#include <string>

namespace core::recovery {

FileValidator::FileValidator() = default;
FileValidator::~FileValidator() = default;

void FileValidator::validate(RecoveredFile& candidate,
                             const std::string& imagePath) const {
    if (candidate.offsetEnd <= candidate.offsetStart) {
        candidate.validationState = ValidationState::CORRUPT;
        return;
    }

    // Open the disk image using TSK image-type detection.
    // TSK_IMG_TYPE_EXTERNAL is only appropriate for TSK's external-image
    // mechanism, not for a normal disk-image file path.
    TSK_IMG_INFO* imgInfo = tsk_img_open_sing(imagePath.c_str(),
                                               TSK_IMG_TYPE_DETECT, 0);
    if (!imgInfo) {
        candidate.validationState = ValidationState::UNVERIFIED;
        return;
    }

    switch (candidate.fileType) {
        case FileType::JPEG:
            candidate.validationState =
                validateJpeg(imgInfo, candidate.offsetStart, candidate.offsetEnd);
            break;

        case FileType::PDF:
            candidate.validationState =
                validatePdf(imgInfo, candidate.offsetStart, candidate.offsetEnd);
            break;

        case FileType::ZIP:
            candidate.validationState = validateZip(candidate, imgInfo);
            break;

        default:
            candidate.validationState = ValidationState::UNVERIFIED;
            break;
    }

    tsk_img_close(imgInfo);
}

std::string FileValidator::readRange(TSK_IMG_INFO* imgInfo, uint64_t start,
                                     uint64_t length) const {
    if (!imgInfo || length == 0) {
        return std::string();
    }

    std::string buf(static_cast<size_t>(length), '\0');

    ssize_t got = tsk_img_read(imgInfo, start, buf.data(),
                               static_cast<size_t>(length));

    if (got <= 0) {
        return std::string();
    }

    buf.resize(static_cast<size_t>(got));
    return buf;
}

ValidationState FileValidator::validateJpeg(TSK_IMG_INFO* imgInfo,
                                            uint64_t start,
                                            uint64_t end) const {
    if (end <= start) {
        return ValidationState::CORRUPT;
    }

    // Minimum structure for a JFIF JPEG:
    // SOI (2) + APP0 marker (2) + length (2) + "JFIF\0" (5).
    if (end - start < 11) {
        return ValidationState::CORRUPT;
    }

    // JPEG must begin with SOI: FF D8.
    const std::string soi = readRange(imgInfo, start, 2);

    if (soi.size() < 2 ||
        static_cast<unsigned char>(soi[0]) != 0xFF ||
        static_cast<unsigned char>(soi[1]) != 0xD8) {
        return ValidationState::CORRUPT;
    }

    // The test JPEGs produced by our pipeline contain a JFIF APP0
    // segment immediately after SOI.
    const std::string app0 = readRange(imgInfo, start + 2, 9);

    if (app0.size() < 9 ||
        static_cast<unsigned char>(app0[0]) != 0xFF ||
        static_cast<unsigned char>(app0[1]) != 0xE0 ||
        static_cast<unsigned char>(app0[2]) != 0x00 ||
        static_cast<unsigned char>(app0[3]) != 0x10 ||
        app0[4] != 'J' ||
        app0[5] != 'F' ||
        app0[6] != 'I' ||
        app0[7] != 'F' ||
        app0[8] != '\0') {
        return ValidationState::CORRUPT;
    }

    // FileCarver::findJpegEnd() places offsetEnd immediately after
    // the FFD9 EOI marker.
    if (end - start < 2) {
        return ValidationState::PARTIAL;
    }

    const std::string footer = readRange(imgInfo, end - 2, 2);

    if (footer.size() < 2 ||
        static_cast<unsigned char>(footer[0]) != 0xFF ||
        static_cast<unsigned char>(footer[1]) != 0xD9) {
        return ValidationState::PARTIAL;
    }

    return ValidationState::VALID;
}

ValidationState FileValidator::validatePdf(TSK_IMG_INFO* imgInfo,
                                           uint64_t start,
                                           uint64_t end) const {
    if (end <= start) {
        return ValidationState::CORRUPT;
    }

    // PDF header: %PDF-
    const std::string headerTag = "%PDF-";
    const std::string header = readRange(imgInfo, start, headerTag.size());

    if (header.size() < headerTag.size() ||
        header != headerTag) {
        return ValidationState::CORRUPT;
    }

    // FileCarver::findPdfEnd() places offsetEnd immediately after %%EOF.
    const std::string eofTag = "%%EOF";
    const uint64_t length = end - start;

    if (length < eofTag.size()) {
        return ValidationState::PARTIAL;
    }

    const std::string footer =
        readRange(imgInfo, end - eofTag.size(), eofTag.size());

    if (footer.size() < eofTag.size() ||
        footer != eofTag) {
        return ValidationState::PARTIAL;
    }

    return ValidationState::VALID;
}

ValidationState FileValidator::validateZip(RecoveredFile& candidate,
                                           TSK_IMG_INFO* imgInfo) const {
    constexpr uint64_t kEocdSize = 22;

    if (candidate.offsetEnd < candidate.offsetStart + kEocdSize) {
        return ValidationState::CORRUPT;
    }

    // ZIP local file header.
    const std::string localSig =
        readRange(imgInfo, candidate.offsetStart, 4);

    if (localSig.size() < 4 ||
        static_cast<unsigned char>(localSig[0]) != 'P' ||
        static_cast<unsigned char>(localSig[1]) != 'K' ||
        static_cast<unsigned char>(localSig[2]) != 0x03 ||
        static_cast<unsigned char>(localSig[3]) != 0x04) {
        return ValidationState::CORRUPT;
    }

    // FileCarver::findZipEnd() returns EOCD offset + 22.
    const uint64_t eocdOffset =
        candidate.offsetEnd - kEocdSize;

    const std::string eocd =
        readRange(imgInfo, eocdOffset, kEocdSize);

    if (eocd.size() < kEocdSize) {
        return ValidationState::PARTIAL;
    }

    if (static_cast<unsigned char>(eocd[0]) != 'P' ||
        static_cast<unsigned char>(eocd[1]) != 'K' ||
        static_cast<unsigned char>(eocd[2]) != 0x05 ||
        static_cast<unsigned char>(eocd[3]) != 0x06) {
        return ValidationState::PARTIAL;
    }

    auto readU16LE = [&eocd](size_t off) -> uint16_t {
        return static_cast<uint16_t>(
            static_cast<unsigned char>(eocd[off]) |
            (static_cast<unsigned char>(eocd[off + 1]) << 8));
    };

    auto readU32LE = [&eocd](size_t off) -> uint32_t {
        return static_cast<uint32_t>(
            static_cast<unsigned char>(eocd[off]) |
            (static_cast<unsigned char>(eocd[off + 1]) << 8) |
            (static_cast<unsigned char>(eocd[off + 2]) << 16) |
            (static_cast<unsigned char>(eocd[off + 3]) << 24));
    };

    const uint32_t centralDirSize =
        readU32LE(12);

    const uint32_t centralDirOffset =
        readU32LE(16);

    const uint16_t commentLength =
        readU16LE(20);

    // EOCD + variable-length comment gives the authoritative ZIP end.
    uint64_t authoritativeEnd =
        eocdOffset +
        kEocdSize +
        static_cast<uint64_t>(commentLength);

    if (imgInfo && authoritativeEnd > imgInfo->size) {
        authoritativeEnd = imgInfo->size;
    }

    candidate.offsetEnd = authoritativeEnd;

    // The central directory is relative to the beginning of this archive.
    const uint64_t expectedCdEnd =
        candidate.offsetStart +
        static_cast<uint64_t>(centralDirOffset) +
        static_cast<uint64_t>(centralDirSize);

    if (expectedCdEnd <= eocdOffset) {
        return ValidationState::VALID;
    }

    return ValidationState::PARTIAL;
}

} // namespace core::recovery