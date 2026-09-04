#include "FileCarver.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>

namespace core::recovery {

namespace {

bool matchesAt(const std::vector<char>& buf, size_t pos, const std::string& magic) {
    if (pos + magic.size() > buf.size()) return false;
    return std::memcmp(buf.data() + pos, magic.data(), magic.size()) == 0;
}

} // namespace

FileCarver::FileCarver() {
    // JPEG: FFD8FF at offset 0. PDF: literal "%PDF-1" (6 bytes) at offset
    // 0 — matches PhotoRec's file_pdf.c header_check_pdf. ZIP: local file
    // header PK\x03\x04 at offset 0 (the PK\x05\x06 winzip/empty-archive
    // case is a second signature PhotoRec registers separately; skipped
    // here since it's an edge case not needed for the Sept 7 scope).
    signatures_ = {
        {FileType::JPEG, 0, std::string("\xFF\xD8\xFF", 3)},
        {FileType::PDF,  0, std::string("%PDF-1", 6)},
        {FileType::ZIP,  0, std::string("PK\x03\x04", 4)},
    };
}

std::vector<RecoveredFile> FileCarver::scan(const std::string& imagePath) const {
    std::vector<RecoveredFile> candidates;

    std::ifstream in(imagePath, std::ios::binary);
    if (!in) {
        std::cerr << "[FileCarver] failed to open image: " << imagePath << "\n";
        return candidates;
    }

    in.seekg(0, std::ios::end);
    const uint64_t imageSize = static_cast<uint64_t>(in.tellg());
    in.seekg(0, std::ios::beg);

    // Longest magic we search for, so we know how much overlap to keep
    // between successive reads — a signature can straddle a buffer
    // boundary in a single streaming pass.
    size_t maxMagicLen = 0;
    for (const auto& sig : signatures_) {
        maxMagicLen = std::max(maxMagicLen, sig.magicBytes.size());
    }

    std::vector<char> buf(kReadBufferSize);
    uint64_t baseOffset = 0;   // absolute image offset of buf[0]
    size_t carryOver = 0;      // bytes of overlap already sitting at buf[0..carryOver)

    while (in) {
        in.read(buf.data() + carryOver, static_cast<std::streamsize>(buf.size() - carryOver));
        const size_t bytesRead = carryOver + static_cast<size_t>(in.gcount());
        if (bytesRead == carryOver) break; // no new bytes — EOF

        // Don't test matches inside the trailing (maxMagicLen - 1) bytes
        // unless this is the final block — that tail gets re-checked next
        // iteration once more bytes follow it.
        const bool isFinalBlock = bytesRead < buf.size();
        const size_t scanLimit = isFinalBlock ? bytesRead
                                               : (maxMagicLen > 0 ? bytesRead - (maxMagicLen - 1) : bytesRead);

        for (size_t pos = 0; pos < scanLimit; ++pos) {
            for (const auto& sig : signatures_) {
                if (!matchesAt(buf, pos, sig.magicBytes)) continue;

                const uint64_t headerOffset = baseOffset + pos;

                uint64_t end = 0;
                switch (sig.fileType) {
                    case FileType::JPEG: end = findJpegEnd(in, headerOffset, imageSize); break;
                    case FileType::PDF:  end = findPdfEnd(in, headerOffset, imageSize); break;
                    case FileType::ZIP:  end = findZipEnd(in, headerOffset, imageSize); break;
                    default: break;
                }

                if (end > headerOffset) {
                    RecoveredFile candidate;
                    candidate.sourceImagePath = imagePath;
                    candidate.offsetStart = headerOffset;
                    candidate.offsetEnd = end;
                    candidate.fileType = sig.fileType;
                    candidates.push_back(std::move(candidate));
                }

                // Boundary search seeks `in` around internally; restore the
                // stream to where the block scan should resume before
                // continuing (harmless if called again for another match
                // in this same block — always the same target position).
                in.clear();
                in.seekg(static_cast<std::streamoff>(baseOffset + bytesRead), std::ios::beg);
                break; // don't test remaining signatures at this offset
            }
        }

        if (isFinalBlock) break;

        // Keep the last (maxMagicLen - 1) bytes as overlap for next block.
        const size_t carry = maxMagicLen > 0 ? maxMagicLen - 1 : 0;
        if (carry > 0) {
            std::memmove(buf.data(), buf.data() + bytesRead - carry, carry);
        }
        baseOffset += bytesRead - carry;
        carryOver = carry;
    }

    return candidates;
}

uint64_t FileCarver::findJpegEnd(std::istream& in, uint64_t headerOffset, uint64_t imageSize) const {
    // JPEG's FFD9 (EOI) is NOT safe to footer-scan for naively — the
    // entropy-coded scan data can contain the byte sequence FFD9 by
    // coincidence, producing truncated/false files. Instead walk the
    // actual marker structure: after FFD8 (SOI), read markers one at a
    // time, respecting each marker's declared 2-byte big-endian length to
    // jump past its payload, and only accept FFD9 as real once reached in
    // proper marker sequence outside any scan segment.
    //
    // Footer-matching is format-dependent, not a universal technique —
    // don't "simplify" this down to a blind footer scan later; that
    // silently degrades accuracy (see PDF's findPdfEnd, where a footer
    // scan IS the right approach — the two formats are genuinely
    // different here, this isn't inconsistency).
    in.clear();
    in.seekg(static_cast<std::streamoff>(headerOffset + 2), std::ios::beg); // past FFD8

    uint64_t pos = headerOffset + 2;
    const uint64_t limit = std::min(imageSize, headerOffset + kMaxCandidateSize);

    while (pos + 1 < limit) {
        unsigned char marker[2];
        in.read(reinterpret_cast<char*>(marker), 2);
        if (in.gcount() != 2) break;
        pos += 2;

        if (marker[0] != 0xFF) break; // lost sync — not a well-formed marker stream

        const unsigned char code = marker[1];

        if (code == 0xD9) {
            return pos; // genuine EOI reached in proper marker sequence
        }
        if (code == 0xD8 || code == 0x01 || (code >= 0xD0 && code <= 0xD7)) {
            continue; // standalone markers (SOI/TEM/RSTn) carry no length field
        }
        if (code == 0xDA) {
            // Start of Scan: entropy-coded data follows with no declared
            // length. Byte-scan forward for the next real marker (an FF
            // byte not followed by 0x00 stuffing and not an RSTn), rather
            // than trusting any FFD9 encountered inside the scan data.
            unsigned char b = 0, prev = 0;
            bool foundNext = false;
            while (pos < limit) {
                in.read(reinterpret_cast<char*>(&b), 1);
                if (in.gcount() != 1) break;
                ++pos;
                if (prev == 0xFF && b != 0x00 && b != 0xFF && !(b >= 0xD0 && b <= 0xD7)) {
                    pos -= 2; // rewind so the outer loop re-reads this marker properly
                    in.clear();
                    in.seekg(static_cast<std::streamoff>(pos), std::ios::beg);
                    foundNext = true;
                    break;
                }
                prev = b;
            }
            if (!foundNext) break;
            continue;
        }

        // Ordinary marker with a declared length: read it and skip payload.
        unsigned char lenBytes[2];
        in.read(reinterpret_cast<char*>(lenBytes), 2);
        if (in.gcount() != 2) break;
        const uint16_t segLen = (static_cast<uint16_t>(lenBytes[0]) << 8) | lenBytes[1];
        if (segLen < 2) break; // malformed — length field must include itself
        pos += 2;
        const uint64_t payload = segLen - 2;
        in.seekg(static_cast<std::streamoff>(payload), std::ios::cur);
        pos += payload;
    }

    return 0; // ran off the end without a genuine EOI — not a complete candidate
}

uint64_t FileCarver::findPdfEnd(std::istream& in, uint64_t headerOffset, uint64_t imageSize) const {
    // Footer-scan fallback strategy (skipping PhotoRec's /L linearization
    // -hint optimization — that's a speed win across many formats, not
    // needed at 2-3 formats): scan forward for the literal "%%EOF", and
    // allow one trailing newline-variant PhotoRec itself tolerates
    // (bare LF, CRLF, or bare CR).
    const uint64_t limit = std::min(imageSize, headerOffset + kMaxCandidateSize);
    const std::string marker = "%%EOF";
    const size_t markerLen = marker.size();

    std::vector<char> window(kReadBufferSize);
    uint64_t windowStart = headerOffset; // absolute offset of window[0]
    size_t carry = 0;

    in.clear();
    in.seekg(static_cast<std::streamoff>(headerOffset), std::ios::beg);

    while (windowStart + carry < limit) {
        const size_t maxNew = std::min(window.size() - carry,
                                        static_cast<size_t>(limit - windowStart - carry));
        in.read(window.data() + carry, static_cast<std::streamsize>(maxNew));
        const size_t got = carry + static_cast<size_t>(in.gcount());
        if (got == carry) break; // no new bytes read

        for (size_t i = 0; i + markerLen <= got; ++i) {
            if (std::memcmp(window.data() + i, marker.data(), markerLen) != 0) continue;

            uint64_t end = windowStart + i + markerLen;

            char trail[2] = {0, 0};
            in.clear();
            in.seekg(static_cast<std::streamoff>(end), std::ios::beg);
            in.read(trail, 2);
            const std::streamsize gotTrail = in.gcount();
            if (gotTrail >= 2 && trail[0] == '\r' && trail[1] == '\n') {
                end += 2; // CRLF
            } else if (gotTrail >= 1 && (trail[0] == '\n' || trail[0] == '\r')) {
                end += 1; // bare LF or bare CR
            }
            return std::min(end, imageSize);
        }

        if (got < carry + maxNew) break; // reached EOF/limit this read

        const size_t newCarry = markerLen > 0 ? markerLen - 1 : 0;
        std::memmove(window.data(), window.data() + got - newCarry, newCarry);
        windowStart += got - newCarry;
        carry = newCarry;
    }

    return 0; // no %%EOF found within bounds — truncated / not a real candidate
}

uint64_t FileCarver::findZipEnd(std::istream& /*in*/, uint64_t headerOffset, uint64_t imageSize) const {
    // ZIP is self-describing from its End Of Central Directory record, not
    // a footer-scanned format. Per the spec, FileCarver's job for ZIP is
    // limited to "found a plausible header, hand off" — FileValidator
    // owns the EOCD walk and corrects offsetEnd to the authoritative
    // archive length. Here we just give the candidate a generous
    // provisional upper bound for the validator to examine.
    return std::min(imageSize, headerOffset + kMaxCandidateSize);
}

} // namespace core::recovery
