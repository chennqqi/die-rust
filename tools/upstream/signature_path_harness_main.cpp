// Project-generated research harness for the private signature path filter.
// It links the unmodified pinned engine; the macro changes only C++ access
// checking in this translation unit so the otherwise unreachable comparator
// can be observed.

#include "die_scriptengine.h"
#define private public
#include "die_script.h"
#undef private

#include <QBuffer>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
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
    "ec19bc91132237e7293ac3a67caab394c86acad9e7f6dec4a403bfee42d95f8e";

QJsonObject serializeRecord(const XScanEngine::SCANSTRUCT &record)
{
    QJsonObject output;
    output.insert("filetype", XBinary::fileTypeIdToString(record.id.fileType));
    output.insert("type", record.sType);
    output.insert("name", record.sName);
    output.insert("signature", record.varInfo);
    output.insert("signature_path", record.varInfo2);
    output.insert("unknown", record.bIsUnknown);
    return output;
}

QJsonObject runCase(
    DiE_Script *engine,
    const XScanEngine::SCAN_OPTIONS &loadedOptions,
    const QByteArray &input,
    const QString &id,
    const QString &filter
)
{
    QByteArray caseInput = input;
    QBuffer buffer(&caseInput);
    buffer.setProperty("FileName", "probe.bin");
    if (!buffer.open(QIODevice::ReadOnly)) {
        return {{"id", id}, {"error", "cannot open input buffer"}};
    }

    XScanEngine::SCAN_OPTIONS options = loadedOptions;
    XBinary::PDSTRUCT state = XBinary::createPdStruct();
    XScanEngine::SCAN_RESULT result = {};
    const XScanEngine::SCANID parentId = {};
    engine->processDetect(
        nullptr,
        &result,
        &buffer,
        parentId,
        XBinary::FT_BINARY,
        &options,
        filter,
        false,
        &state
    );

    QJsonArray records;
    for (const XScanEngine::SCANSTRUCT &record : result.listRecords) {
        records.append(serializeRecord(record));
    }

    QJsonObject output;
    output.insert("id", id);
    output.insert("filter", filter);
    output.insert("record_count", records.size());
    output.insert("records", records);
    output.insert("error_count", result.listErrors.size());
    output.insert(
        "scan_not_canceled",
        XBinary::isPdStructNotCanceled(&state)
    );
    return output;
}

QJsonArray serializeLoadedSignatures(DiE_Script *engine)
{
    QJsonArray output;
    const QList<XScanEngine::SIGNATURE_RECORD> *records =
        engine->getSignatures();
    if (records == nullptr) {
        return output;
    }
    for (const XScanEngine::SIGNATURE_RECORD &record : *records) {
        QJsonObject item;
        item.insert("name", record.sName);
        item.insert("file_path", record.sFilePath);
        item.insert(
            "database_type",
            static_cast<qint32>(record.databaseType)
        );
        output.append(item);
    }
    return output;
}

}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    if (argc != 2) {
        std::fprintf(
            stderr,
            "usage: die-signature-path-harness <fixture-root>\n"
        );
        return 2;
    }

    const QString fixtureRoot = QString::fromLocal8Bit(argv[1]);
    QFile inputFile(fixtureRoot + "/input/probe.bin");
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

    XScanEngine::SCAN_OPTIONS options = {};
    options.sMainDatabasePath = fixtureRoot + "/main";
    options.sExtraDatabasePath = fixtureRoot + "/extra";
    options.bUseExtraDatabase = true;
    options.bUseCache = false;
    options.bShowType = true;
    options.bShowVersion = true;
    options.bShowInfo = true;

    XBinary::PDSTRUCT loadState = XBinary::createPdStruct();
    DiE_Script engine;
    const bool loaded = engine.loadDatabase(&options, &loadState);
    const QString mainPath =
        fixtureRoot + "/main/Binary/shared.1.sg";
    const QString extraPath =
        fixtureRoot + "/extra/Binary/shared.1.sg";

    QJsonArray cases;
    cases.append(runCase(
        &engine,
        options,
        input,
        "empty_filter",
        ""
    ));
    cases.append(runCase(
        &engine,
        options,
        input,
        "exact_main",
        mainPath
    ));
    cases.append(runCase(
        &engine,
        options,
        input,
        "exact_extra",
        extraPath
    ));
    cases.append(runCase(
        &engine,
        options,
        input,
        "missing",
        fixtureRoot + "/main/Binary/missing.1.sg"
    ));
    cases.append(runCase(
        &engine,
        options,
        input,
        "case_mismatch",
        fixtureRoot + "/main/Binary/SHARED.1.SG"
    ));
    cases.append(runCase(
        &engine,
        options,
        input,
        "dot_segment",
        fixtureRoot + "/main/Binary/../Binary/shared.1.sg"
    ));
    cases.append(runCase(
        &engine,
        options,
        input,
        "basename_only",
        "shared.1.sg"
    ));

    QJsonObject output;
    output.insert("schema_version", 1);
    output.insert("upstream_commit", UPSTREAM_COMMIT);
    output.insert("formats_commit", FORMATS_COMMIT);
    output.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    output.insert("die_script_commit", DIE_SCRIPT_COMMIT);
    output.insert("input_sha256", INPUT_SHA256);
    output.insert("fixture_root", fixtureRoot);
    output.insert("database_loaded", loaded);
    output.insert(
        "load_not_canceled",
        XBinary::isPdStructNotCanceled(&loadState)
    );
    output.insert(
        "loaded_signatures",
        serializeLoadedSignatures(&engine)
    );
    output.insert("case_count", cases.size());
    output.insert("cases", cases);
    std::printf(
        "%s",
        QJsonDocument(output).toJson(QJsonDocument::Indented).constData()
    );
    return 0;
}
