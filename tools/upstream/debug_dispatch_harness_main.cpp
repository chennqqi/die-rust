// Project-generated paired harness for debug-data dispatch reachability.
// It links the unmodified pinned engine, enumerates resource/debug parts from
// one PE, runs the public recursive scanner, then invokes the private rule
// executor on the enumerated debug bytes as a direct positive control.

#include "die_scriptengine.h"
#define private public
#include "die_script.h"
#undef private

#include "xformats.h"

#include <QBuffer>
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
constexpr const char *RULES_COMMIT =
    "c2c17dfa5ea4e078ba31eab55d87430c96622fb6";
constexpr const char *SAMPLE_NAME = "pe-resource-debug.exe";
constexpr const char *SAMPLE_SHA256 =
    "58e2b8e73ba187977564e719d39022079b8fb9172c5bcdf40c495ed825b38ea1";
constexpr qint64 SAMPLE_SIZE = 1536;
constexpr const char *RESOURCE_RULE_PATH =
    "/opt/die-source/Detect-It-Easy/db/Binary/win_resources.1.sg";
constexpr const char *RESOURCE_RULE_SHA256 =
    "2fdad41d666d32467cabe83dae7d16625ade5935e3061c58dfefeb1fb7b99db7";
constexpr const char *DEBUG_RULE_PATH =
    "/opt/die-source/Detect-It-Easy/db/Binary/"
    "debug_data_debugData.1.sg";
constexpr const char *DEBUG_RULE_NAME =
    "debug_data_debugData.1.sg";
constexpr const char *DEBUG_RULE_SHA256 =
    "381b6259b239f2633b92fbd84fd0d99b972751e20cab12b6e09139a260f1f47d";

QByteArray fileSha256(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }
    return QCryptographicHash::hash(
        file.readAll(),
        QCryptographicHash::Sha256
    ).toHex();
}

QJsonObject serializePart(
    const XBinary::FPART &part,
    const QByteArray &sample
)
{
    const QByteArray bytes = sample.mid(
        static_cast<int>(part.nFileOffset),
        static_cast<int>(part.nFileSize)
    );
    QJsonObject output;
    output.insert("filepart", static_cast<int>(part.filePart));
    output.insert(
        "filepart_string",
        XBinary::recordFilePartIdToString(part.filePart)
    );
    output.insert("offset", part.nFileOffset);
    output.insert("size", part.nFileSize);
    output.insert("name", part.sName);
    output.insert(
        "resource_id",
        part.mapProperties.value(
            XBinary::FPART_PROP_RESOURCEID
        ).toString()
    );
    output.insert(
        "sha256",
        QString::fromLatin1(
            QCryptographicHash::hash(
                bytes,
                QCryptographicHash::Sha256
            ).toHex()
        )
    );
    return output;
}

QJsonObject serializeId(const XScanEngine::SCANID &id)
{
    QJsonObject output;
    output.insert("filetype", static_cast<int>(id.fileType));
    output.insert(
        "filetype_string",
        XBinary::fileTypeIdToString(id.fileType)
    );
    output.insert("filepart", static_cast<int>(id.filePart));
    output.insert(
        "filepart_string",
        XBinary::recordFilePartIdToString(id.filePart)
    );
    output.insert("offset", id.nOffset);
    output.insert("size", id.nSize);
    return output;
}

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
        item.insert("signature_path", record.varInfo2);
        item.insert("unknown", record.bIsUnknown);
        item.insert("id", serializeId(record.id));
        item.insert("parent_id", serializeId(record.parentId));
        output.append(item);
    }
    return output;
}

XScanEngine::SCAN_OPTIONS makeOptions()
{
    XScanEngine::SCAN_OPTIONS options = {};
    options.sMainDatabasePath =
        "/opt/die-source/Detect-It-Easy/db";
    options.sExtraDatabasePath =
        "/opt/die-source/Detect-It-Easy/db_extra";
    options.sCustomDatabasePath =
        "/opt/die-source/Detect-It-Easy/db_custom";
    options.bUseExtraDatabase = true;
    options.bUseCustomDatabase = true;
    options.bUseCache = false;
    options.bIsRecursiveScan = true;
    options.bIsAggressiveScan = true;
    options.bShowType = true;
    options.bShowVersion = true;
    options.bShowInfo = true;
    return options;
}

}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    if (argc != 2) {
        std::fprintf(
            stderr,
            "usage: die-debug-dispatch-harness <fixture-root>\n"
        );
        return 2;
    }

    const QString fixtureRoot = QString::fromLocal8Bit(argv[1]);
    const QString samplePath = fixtureRoot + "/" + SAMPLE_NAME;
    QFile sampleFile(samplePath);
    if (!sampleFile.open(QIODevice::ReadOnly)) {
        std::fprintf(stderr, "cannot open fixture sample\n");
        return 1;
    }
    const QByteArray sample = sampleFile.readAll();
    const QByteArray sampleHash = QCryptographicHash::hash(
        sample,
        QCryptographicHash::Sha256
    ).toHex();
    if (
        sample.size() != SAMPLE_SIZE ||
        sampleHash != QByteArray(SAMPLE_SHA256)
    ) {
        std::fprintf(stderr, "fixture sample identity mismatch\n");
        return 1;
    }
    if (
        fileSha256(RESOURCE_RULE_PATH)
            != QByteArray(RESOURCE_RULE_SHA256) ||
        fileSha256(DEBUG_RULE_PATH)
            != QByteArray(DEBUG_RULE_SHA256)
    ) {
        std::fprintf(stderr, "fixed rule identity mismatch\n");
        return 1;
    }

    sampleFile.seek(0);
    XBinary::PDSTRUCT enumerationState = XBinary::createPdStruct();
    const XBinary::FT fileType = XFormats::getPrefFileType(
        &sampleFile,
        true,
        &enumerationState
    );
    sampleFile.seek(0);
    const QList<XBinary::FPART> parts = XFormats::getFileParts(
        fileType,
        &sampleFile,
        XBinary::FILEPART_RESOURCE | XBinary::FILEPART_DEBUGDATA,
        10000,
        false,
        -1,
        &enumerationState
    );

    QJsonArray serializedParts;
    XBinary::FPART debugPart = {};
    bool hasDebugPart = false;
    for (const XBinary::FPART &part : parts) {
        serializedParts.append(serializePart(part, sample));
        if (part.filePart == XBinary::FILEPART_DEBUGDATA) {
            debugPart = part;
            hasDebugPart = true;
        }
    }
    if (!hasDebugPart) {
        std::fprintf(stderr, "format layer did not enumerate debug data\n");
        return 1;
    }

    XScanEngine::SCAN_OPTIONS options = makeOptions();
    XBinary::PDSTRUCT loadState = XBinary::createPdStruct();
    DiE_Script engine;
    const bool loaded = engine.loadDatabase(&options, &loadState);

    XBinary::PDSTRUCT publicState = XBinary::createPdStruct();
    const XScanEngine::SCAN_RESULT publicResult = engine.scanFile(
        samplePath,
        &options,
        &publicState
    );

    QByteArray debugBytes = sample.mid(
        static_cast<int>(debugPart.nFileOffset),
        static_cast<int>(debugPart.nFileSize)
    );
    QBuffer debugBuffer(&debugBytes);
    debugBuffer.setProperty("FileName", "debug-data.bin");
    if (!debugBuffer.open(QIODevice::ReadOnly)) {
        std::fprintf(stderr, "cannot open direct debug buffer\n");
        return 1;
    }
    XScanEngine::SCAN_OPTIONS directOptions = options;
    directOptions.sSignatureName = DEBUG_RULE_NAME;
    XScanEngine::SCANID directParent = {};
    directParent.fileType = fileType;
    directParent.filePart = XBinary::FILEPART_DEBUGDATA;
    directParent.nOffset = debugPart.nFileOffset;
    directParent.nSize = debugPart.nFileSize;
    XBinary::PDSTRUCT directState = XBinary::createPdStruct();
    XScanEngine::SCAN_RESULT directResult = {};
    engine.processDetect(
        nullptr,
        &directResult,
        &debugBuffer,
        directParent,
        XBinary::FT_BINARY,
        &directOptions,
        "",
        false,
        &directState
    );

    QJsonObject output;
    output.insert("schema_version", 1);
    output.insert("upstream_commit", UPSTREAM_COMMIT);
    output.insert("formats_commit", FORMATS_COMMIT);
    output.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    output.insert("die_script_commit", DIE_SCRIPT_COMMIT);
    output.insert("rules_commit", RULES_COMMIT);
    output.insert("sample_name", SAMPLE_NAME);
    output.insert("sample_size", SAMPLE_SIZE);
    output.insert("sample_sha256", QString::fromLatin1(sampleHash));
    output.insert(
        "resource_rule_sha256",
        RESOURCE_RULE_SHA256
    );
    output.insert("debug_rule_sha256", DEBUG_RULE_SHA256);
    output.insert(
        "format_filetype",
        XBinary::fileTypeIdToString(fileType)
    );
    output.insert("enumerated_part_count", parts.size());
    output.insert("enumerated_parts", serializedParts);
    output.insert(
        "enumeration_not_canceled",
        XBinary::isPdStructNotCanceled(&enumerationState)
    );
    output.insert("database_loaded", loaded);
    output.insert(
        "load_not_canceled",
        XBinary::isPdStructNotCanceled(&loadState)
    );

    QJsonObject publicScan;
    publicScan.insert("recursive", options.bIsRecursiveScan);
    publicScan.insert("aggressive", options.bIsAggressiveScan);
    publicScan.insert(
        "initial_filetype",
        XBinary::fileTypeIdToString(publicResult.ftInit)
    );
    publicScan.insert(
        "records",
        serializeRecords(publicResult.listRecords)
    );
    publicScan.insert(
        "record_count",
        publicResult.listRecords.size()
    );
    publicScan.insert("error_count", publicResult.listErrors.size());
    publicScan.insert(
        "scan_not_canceled",
        XBinary::isPdStructNotCanceled(&publicState)
    );
    output.insert("public_recursive_scan", publicScan);

    QJsonObject directScan;
    directScan.insert("signature_filter", DEBUG_RULE_NAME);
    directScan.insert(
        "source_part",
        serializePart(debugPart, sample)
    );
    directScan.insert(
        "records",
        serializeRecords(directResult.listRecords)
    );
    directScan.insert(
        "record_count",
        directResult.listRecords.size()
    );
    directScan.insert("error_count", directResult.listErrors.size());
    directScan.insert(
        "scan_not_canceled",
        XBinary::isPdStructNotCanceled(&directState)
    );
    output.insert("direct_debug_scan", directScan);

    std::printf(
        "%s",
        QJsonDocument(output).toJson(QJsonDocument::Indented).constData()
    );
    return 0;
}
