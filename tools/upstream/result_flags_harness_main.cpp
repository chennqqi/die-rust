// Project-generated research harness for SCANSTRUCT result flags.
// It links the unmodified pinned engine and supplies only benign rules.

#include "die_script.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <cstdio>

namespace {

constexpr const char *UPSTREAM_COMMIT =
    "74eaf505c250ab47e709024e9dc41657cd8f2254";
constexpr const char *FORMATS_COMMIT =
    "1151e7254fdee3c0294ff7095edbdd7bfccf8201";
constexpr const char *XSCANENGINE_COMMIT =
    "dfe4a419e4f491bb23688ba03c5a5bf39e34da83";
constexpr const char *DIE_SCRIPT_COMMIT =
    "5d82316c110abf0eb863b50bc679d330e05067b6";
constexpr const char *INPUT_SHA256 =
    "28aa71cff9d35029534ce01a6c64d944e910f9b0232b9519679c79abf2288b87";

QJsonArray serializeRecords(
    const QList<XScanEngine::SCANSTRUCT> &records
)
{
    QJsonArray output;
    for (const XScanEngine::SCANSTRUCT &record : records) {
        QJsonObject item;
        item.insert("type", record.sType);
        item.insert("name", record.sName);
        item.insert("signature", record.varInfo);
        item.insert("heuristic", record.bIsHeuristic);
        item.insert(
            "advanced_heuristic",
            record.bIsAHeuristic
        );
        item.insert("unknown", record.bIsUnknown);
        output.append(item);
    }
    return output;
}

QJsonObject runCase(
    const QString &id,
    const QString &fixtureRoot,
    const QString &inputPath,
    const QString &database,
    const QString &signature,
    bool heuristicScan
)
{
    XScanEngine::SCAN_OPTIONS options = {};
    options.sMainDatabasePath = fixtureRoot + "/" + database;
    options.sSignatureName = signature;
    options.bIsHeuristicScan = heuristicScan;
    options.bShowType = true;
    options.bShowVersion = true;
    options.bShowInfo = true;

    XBinary::PDSTRUCT loadState = XBinary::createPdStruct();
    DiE_Script engine;
    const bool loaded = engine.loadDatabase(&options, &loadState);
    XBinary::PDSTRUCT scanState = XBinary::createPdStruct();
    const XScanEngine::SCAN_RESULT result = engine.scanFile(
        inputPath,
        &options,
        &scanState
    );

    QJsonObject output;
    output.insert("id", id);
    output.insert("database", database);
    output.insert("signature", signature);
    output.insert("heuristic_scan", heuristicScan);
    output.insert("database_loaded", loaded);
    output.insert(
        "load_not_canceled",
        XBinary::isPdStructNotCanceled(&loadState)
    );
    output.insert(
        "scan_not_canceled",
        XBinary::isPdStructNotCanceled(&scanState)
    );
    output.insert("error_count", result.listErrors.size());
    output.insert("records", serializeRecords(result.listRecords));
    return output;
}

}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    if (argc != 2) {
        std::fprintf(
            stderr,
            "usage: die-result-flags-harness <fixture-root>\n"
        );
        return 2;
    }

    const QString fixtureRoot = QString::fromLocal8Bit(argv[1]);
    const QString inputPath = fixtureRoot + "/input/probe.bin";
    QFile inputFile(inputPath);
    if (!inputFile.open(QIODevice::ReadOnly)) {
        std::fprintf(stderr, "cannot open fixture input\n");
        return 1;
    }
    const QByteArray input = inputFile.readAll();
    const QByteArray inputHash = QCryptographicHash::hash(
        input,
        QCryptographicHash::Sha256
    ).toHex();
    if (inputHash != QByteArray(INPUT_SHA256)) {
        std::fprintf(stderr, "fixture input hash mismatch\n");
        return 1;
    }

    QJsonArray cases;
    cases.append(runCase(
        "normal",
        fixtureRoot,
        inputPath,
        "main",
        "normal.1.sg",
        false
    ));
    cases.append(runCase(
        "heuristic",
        fixtureRoot,
        inputPath,
        "main",
        "HEUR.heuristic.2.sg",
        true
    ));
    cases.append(runCase(
        "advanced_heuristic",
        fixtureRoot,
        inputPath,
        "main",
        "HEUR.advanced.3.sg",
        true
    ));
    cases.append(runCase(
        "unknown",
        fixtureRoot,
        inputPath,
        "empty-main",
        "",
        false
    ));

    QJsonObject output;
    output.insert("schema_version", 1);
    output.insert("upstream_commit", UPSTREAM_COMMIT);
    output.insert("formats_commit", FORMATS_COMMIT);
    output.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    output.insert("die_script_commit", DIE_SCRIPT_COMMIT);
    output.insert("input_sha256", QString::fromLatin1(inputHash));
    output.insert("case_count", cases.size());
    output.insert("cases", cases);
    std::printf(
        "%s",
        QJsonDocument(output).toJson(QJsonDocument::Indented).constData()
    );
    return 0;
}
