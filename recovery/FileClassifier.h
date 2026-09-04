#pragma once

#include "RecoveredFile.h"

#include <string>

namespace core::recovery {

// Thin, per the spec: takes a validated+scored candidate, assigns a
// category, streams its bytes out to CASE_DATA in chunks (never loaded
// whole into RAM), and hashes the written bytes via the project's
// existing acquisition::HashEngine (streaming SHA-256, no second hashing
// implementation). Neither PhotoRec nor TSK needed a separate
// classification step in this sense — this component is mostly original
// wiring around the decided-to-keep candidate.
class FileClassifier {
public:
    // outputRoot: directory recovered files are streamed into, mirroring
    // the project's CASE_DATA convention. Per the spec's recommendation:
    // everything scored LOW or above gets written; UNVERIFIED/discarded
    // candidates are logged but not written, to avoid cluttering
    // CASE_DATA with carved-over garbage while still keeping a record.
    explicit FileClassifier(std::string outputRoot = "CASE_DATA");

    // Populates category/outputPath/sha256/timestampUtc on candidate.
    // Returns false if the candidate wasn't written (below threshold, or
    // a genuine I/O failure) — candidate.outputPath is left empty in
    // either case.
    bool classify(RecoveredFile& candidate, const std::string& imagePath) const;

private:
    std::string outputRoot_;

    static FileCategory categoryFor(FileType type);
    static std::string extensionFor(FileType type);
    std::string computeSha256(const std::string& path) const;
    static std::string currentTimestampUtc();
};

} // namespace core::recovery
