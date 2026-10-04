// Project-generated research harness for SCAN_RESULT list contracts.
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
    "789b791f239520d2244dfa30bcec3dbf5b77db407d8cbca4aba64b29e99c8b54";
constexpr const char *COLLECTION_ROOT =
    "/tmp/die-result-list-collection";

QJsonArray serializeRecords(
    const QList<XScanEngine::SCANSTRUCT> &records
)
{
    QJsonArray output;
    for (const XScanEngine::SCANSTRUCT &record : records) {
        QJsonObject item;
        item.insert("type", record.sType);
        item.insert("name", record.sName);
        item.insert("version", record.sVersion);
        item.insert("info", record.sInfo);
        item.insert("signature", record.varInfo);
        item.insert("signature_file", record.varInfo2);
        item.insert("unknown", record.bIsUnknown);
        output.append(item);
    }
    return output;
}

QJsonArray serializeErrors(
    const QList<XScanEngine::ERROR_RECORD> &records
)
{
    QJsonArray output;
    for (const XScanEngine::ERROR_RECORD &record : records) {
        QJsonObject item;
        item.insert("script", record.sScript);
        item.insert("message", record.sErrorString);
        output.append(item);
    }
    return output;
}

QJsonArray serializeDebugRecords(
    const QList<XScanEngine::DEBUG_RECORD> &records
)
{
    QJsonArray output;
    for (const XScanEngine::DEBUG_RECORD &record : records) {
        QJsonObject item;
        item.insert("script", record.sScript);
        item.insert("type", record.sType);
        item.insert("name", record.sName);
        item.insert("value", record.sValue);
        item.insert("elapsed_ms", record.nElapsedTime);
        item.insert("line", record.nLine);
        output.append(item);
    }
    return output;
}

QJsonArray serializeHandlers(
    const QList<XHandler::RECORD> &records
)
{
    QJsonArray output;
    for (const XHandler::RECORD &record : records) {
        QJsonObject item;
        item.insert("kind", static_cast<int>(record.xhandler));
        item.insert(
            "source",
            record.mapOptions.value(
                XHandler::RECORD_OPTION_FILENAME_SOURCE
            ).toString()
        );
        item.insert(
            "destination",
            record.mapOptions.value(
                XHandler::RECORD_OPTION_FILENAME_DEST
            ).toString()
        );
        output.append(item);
    }
    return output;
}

QJsonObject runCase(
    const QString &id,
    const QString &fixtureRoot,
    const QString &inputPath,
    const QString &signatureName,
    bool showScanTime,
    bool collection
)
{
    XScanEngine::SCAN_OPTIONS options = {};
    options.sMainDatabasePath = fixtureRoot + "/main";
    options.bShowType = true;
    options.bShowVersion = true;
    options.bShowInfo = true;
    options.sSignatureName = signatureName;
    options.bShowScanTime = showScanTime;
    options.bCollection = collection;
    options.bCollectionAllFileTypes = true;
    options.bCollectionAllTypes = true;
    options.sCollectionResultDirectory = COLLECTION_ROOT;
    options.bCollectionCopyFiles = collection;
    options.sCollectionCopyFormat = "duplicate.bin";

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
    output.insert("signature_name", signatureName);
    output.insert("show_scan_time", showScanTime);
    output.insert("collection", collection);
    output.insert("database_loaded", loaded);
    output.insert(
        "load_not_canceled",
        XBinary::isPdStructNotCanceled(&loadState)
    );
    output.insert(
        "scan_not_canceled",
        XBinary::isPdStructNotCanceled(&scanState)
    );
    output.insert("records", serializeRecords(result.listRecords));
    output.insert("errors", serializeErrors(result.listErrors));
    output.insert(
        "debug_records",
        serializeDebugRecords(result.listDebugRecords)
    );
    output.insert("handlers", serializeHandlers(result.listHandlers));
    return output;
}

}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    if (argc != 2) {
        std::fprintf(
            stderr,
            "usage: die-result-lists-harness <fixture-root>\n"
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
        "default_success",
        fixtureRoot,
        inputPath,
        "a_first.1.sg",
        false,
        false
    ));
    cases.append(runCase(
        "all_lists",
        fixtureRoot,
        inputPath,
        "",
        true,
        true
    ));

    QJsonObject output;
    output.insert("schema_version", 1);
    output.insert("upstream_commit", UPSTREAM_COMMIT);
    output.insert("formats_commit", FORMATS_COMMIT);
    output.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    output.insert("die_script_commit", DIE_SCRIPT_COMMIT);
    output.insert("input_sha256", QString::fromLatin1(inputHash));
    output.insert("collection_root", COLLECTION_ROOT);
    output.insert("case_count", cases.size());
    output.insert("cases", cases);
    std::printf(
        "%s",
        QJsonDocument(output).toJson(QJsonDocument::Indented).constData()
    );
    return 0;
}
