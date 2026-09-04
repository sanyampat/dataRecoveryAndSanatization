#include "FileValidator.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <vector>

namespace core::recovery {

namespace {

// Reads up to `length` bytes starting at `start`; returns fewer if the
// image is shorter than requested (never throws on a short read).
std::vector<char> readRange(const std::string& path, uint64_t start, uint64_t length) {
    std::vector<char> data;
    std::ifstream in(path, std::ios::binary);
    if (!in) return data;
    in.seekg(static_cast<std::streamoff>(start), std::ios::beg);
    data.resize(static_cast<size_t>(length));
    in.read(data.data(), static_cast<std::streamsize>(length));
    data.resize(static_cast<size_t>(in.gcount()));
    return data;
}

bool contains(const std::vector<char>& haystack, const std::string& needle) {
    if (needle.size() > haystack.size()) return false;
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

} // namespace

void FileValidator::validate(RecoveredFile& candidate, const std::string& imagePath) const {
    switch (candidate.fileType) {
        case FileType::PDF:
            candidate.validationState = validatePdf(imagePath, candidate.offsetStart, candidate.offsetEnd);
            break;
        case FileType::JPEG:
            candidate.validationState = validateJpeg(imagePath, candidate.offsetStart, candidate.offsetEnd);
            break;
        case FileType::ZIP:
            candidate.validationState = validateZip(candidate, imagePath);
            break;
        default:
            candidate.validationState = ValidationState::UNVERIFIED;
    }
}

ValidationState FileValidator::validatePdf(const std::string& imagePath, uint64_t start, uint64_t end) const {
    if (end <= start) return ValidationState::CORRUPT;

    // Header check beyond magic bytes: confirm "%PDF-1." is followed by an
    // actual version digit (i.e. bytes 6-7 are '.' then '0'-'9'), rather
    // than trusting the bare 6-byte "%PDF-1" magic match alone — this is
    // FileValidator's stricter check; PhotoRec's own header_check_pdf only
    // requires buffer[6] to be printable, which we tighten here per the
    // spec's "confirm %PDF-1. followed by a version digit."
    auto head = readRange(imagePath, start, 8);
    if (head.size() < 8 || head[6] != '.' || head[7] < '0' || head[7] > '9') {
        return ValidationState::CORRUPT;
    }

    // FileCarver only produced this candidate because it found "%%EOF" —
    // re-derive that here rather than trusting it blindly, and
    // additionally require an xref/trailer keyword, which a well-formed,
    // non-corrupt PDF has and a garbage carve typically won't.
    const uint64_t length = end - start;
    auto body = readRange(imagePath, start, length);
    if (!contains(body, "%%EOF")) {
        return ValidationState::PARTIAL; // terminator moved/vanished on re-check
    }

    const bool hasXref = contains(body, "xref") || contains(body, "trailer");
    return hasXref ? ValidationState::VALID : ValidationState::PARTIAL;
}

ValidationState FileValidator::validateJpeg(const std::string& imagePath, uint64_t start, uint64_t end) const {
    if (end <= start) return ValidationState::CORRUPT;

    // FileCarver's marker walk already terminated on a genuine FFD9 to
    // produce this candidate at all (a walk that runs off the end returns
    // 0 and never becomes a candidate) — so reaching here means the
    // *bracketing* is already sound. What's left to sanity-check is
    // decodability: confirm a start-of-frame marker (SOF0 baseline or
    // SOF2 progressive) appears somewhere in the stream. A JPEG with no
    // SOF is not decodable even if correctly bracketed.
    const uint64_t length = end - start;
    auto body = readRange(imagePath, start, length);

    for (size_t i = 0; i + 1 < body.size(); ++i) {
        const auto b0 = static_cast<unsigned char>(body[i]);
        const auto b1 = static_cast<unsigned char>(body[i + 1]);
        if (b0 == 0xFF && (b1 == 0xC0 || b1 == 0xC2)) {
            return ValidationState::VALID;
        }
    }
    return ValidationState::PARTIAL; // bracketed correctly but no SOF found
}

ValidationState FileValidator::validateZip(RecoveredFile& candidate, const std::string& imagePath) const {
    // ZIP is self-describing from its End Of Central Directory record —
    // but FileCarver's offsetEnd for ZIP is only a generous provisional
    // upper bound (potentially far past the real archive, out to
    // kMaxCandidateSize or image end), NOT a reliable anchor to search
    // backward from. A real forensic image typically has a large amount
    // of unrelated/random data after the actual archive before the image
    // ends, so assuming the EOCD sits within the last 64KB of that huge
    // provisional range is wrong in exactly the case that matters most —
    // confirmed by testing against a real acquired image where a small
    // ZIP was followed by ~250KB of unrelated data before image end.
    //
    // Correct approach: scan FORWARD from the header for occurrences of
    // the EOCD signature (PK\x05\x06), and structurally verify each one
    // (central-directory offset/size must be internally consistent with
    // where the EOCD was found) rather than trusting position alone. The
    // first structurally-consistent match, scanning forward, is the real
    // EOCD — any spurious 4-byte signature matches in following filler
    // data are exceedingly unlikely to also pass the consistency check.
    constexpr size_t kEocdMinSize = 22;
    constexpr uint64_t kMaxCommentLen = 64 * 1024;

    const uint64_t searchStart = candidate.offsetStart;
    const uint64_t provisionalEnd = candidate.offsetEnd;
    if (provisionalEnd <= searchStart) return ValidationState::CORRUPT;

    const std::string eocdSig("PK\x05\x06", 4);
    constexpr size_t kChunkSize = 1ULL * 1024 * 1024; // 1 MB scan chunks, small overlap between them
    const size_t overlap = 3; // signature is 4 bytes; keep 3 bytes carry across chunk boundaries

    std::ifstream in(imagePath, std::ios::binary);
    if (!in) return ValidationState::CORRUPT;
    in.seekg(static_cast<std::streamoff>(searchStart), std::ios::beg);

    std::vector<char> buf(kChunkSize);
    uint64_t chunkBase = searchStart;
    size_t carry = 0;

    while (chunkBase + carry < provisionalEnd) {
        const size_t maxNew = static_cast<size_t>(
            std::min<uint64_t>(buf.size() - carry, provisionalEnd - chunkBase - carry));
        in.read(buf.data() + carry, static_cast<std::streamsize>(maxNew));
        const size_t got = carry + static_cast<size_t>(in.gcount());
        if (got <= carry) break; // no new bytes

        for (size_t i = 0; i + kEocdMinSize <= got; ++i) {
            if (std::memcmp(buf.data() + i, eocdSig.data(), 4) != 0) continue;

            const auto* eocd = reinterpret_cast<const unsigned char*>(buf.data() + i);
            const uint32_t cdSize   = eocd[12] | (eocd[13] << 8) | (eocd[14] << 16) | (static_cast<uint32_t>(eocd[15]) << 24);
            const uint32_t cdOffset = eocd[16] | (eocd[17] << 8) | (eocd[18] << 16) | (static_cast<uint32_t>(eocd[19]) << 24);
            const uint16_t commentLen = static_cast<uint16_t>(eocd[20] | (eocd[21] << 8));

            const uint64_t eocdAbs = chunkBase + i;
            if (eocdAbs < searchStart) continue; // shouldn't happen, but guard anyway

            const uint64_t relativeEocd = eocdAbs - searchStart;
            if (static_cast<uint64_t>(cdOffset) > relativeEocd) continue; // inconsistent — not a real EOCD, keep scanning

            const uint64_t cdRegionLen = relativeEocd - cdOffset;
            if (cdRegionLen != cdSize) continue; // central directory size doesn't line up — keep scanning
            if (commentLen > kMaxCommentLen) continue; // implausible comment length — keep scanning

            // Structurally consistent — accept as the real EOCD.
            candidate.offsetEnd = std::min(eocdAbs + kEocdMinSize + commentLen, provisionalEnd);
            return ValidationState::VALID;
        }

        if (got < carry + maxNew) break; // hit EOF or provisionalEnd this read

        const size_t newCarry = std::min(overlap, got);
        std::memmove(buf.data(), buf.data() + got - newCarry, newCarry);
        chunkBase += got - newCarry;
        carry = newCarry;
    }

    return ValidationState::CORRUPT; // no structurally-consistent EOCD found anywhere in range
}

} // namespace core::recovery
