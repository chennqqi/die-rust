// Project-generated research harness for SCANSTRUCT id/parentId contracts.
// It links the unmodified pinned engine and scans a generated PE resource.

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
constexpr const char *SAMPLE_NAME = "pe-manifest-resource.exe";
constexpr const char *SAMPLE_SHA256 =
    "0a973cbde2f520bdbd6e1b75304e4a412462113d4de9a8139cdf997af16641ee";
constexpr qint64 SAMPLE_SIZE = 1024;

QJsonObject serializeId(const XScanEngine::SCANID &id)
{
    QJsonObject output;
    output.insert("uuid", id.sUuid);
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
    output.insert("version", id.sVersion);
    output.insert("info", id.sInfo);
    output.insert("size", id.nSize);
    output.insert("offset", id.nOffset);
    output.insert("original_name", id.sOriginalName);
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
        item.insert("unknown", record.bIsUnknown);
        item.insert("id", serializeId(record.id));
        item.insert("parent_id", serializeId(record.parentId));
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
            "usage: die-result-ids-harness <nested-corpus-root>\n"
        );
        return 2;
    }

    const QString corpusRoot = QString::fromLocal8Bit(argv[1]);
    const QString inputPath = corpusRoot + "/" + SAMPLE_NAME;
    QFile inputFile(inputPath);
    if (!inputFile.open(QIODevice::ReadOnly)) {
        std::fprintf(stderr, "cannot open nested fixture input\n");
        return 1;
    }
    const QByteArray input = inputFile.readAll();
    const QByteArray inputHash = QCryptographicHash::hash(
        input,
        QCryptographicHash::Sha256
    ).toHex();
    if (
        input.size() != SAMPLE_SIZE ||
        inputHash != QByteArray(SAMPLE_SHA256)
    ) {
        std::fprintf(stderr, "nested fixture input identity mismatch\n");
        return 1;
    }

    XScanEngine::SCAN_OPTIONS options = {};
    options.bIsRecursiveScan = true;
    options.bIsResourcesScan = true;
    options.bIsAggressiveScan = true;
    options.bShowType = true;
    options.bShowVersion = true;
    options.bShowInfo = true;

    XBinary::PDSTRUCT state = XBinary::createPdStruct();
    DiE_Script engine;
    const XScanEngine::SCAN_RESULT result = engine.scanFile(
        inputPath,
        &options,
        &state
    );

    QJsonObject output;
    output.insert("schema_version", 1);
    output.insert("upstream_commit", UPSTREAM_COMMIT);
    output.insert("formats_commit", FORMATS_COMMIT);
    output.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    output.insert("die_script_commit", DIE_SCRIPT_COMMIT);
    output.insert("sample_name", SAMPLE_NAME);
    output.insert("sample_size", SAMPLE_SIZE);
    output.insert("sample_sha256", QString::fromLatin1(inputHash));
    output.insert("record_count", result.listRecords.size());
    output.insert("error_count", result.listErrors.size());
    output.insert(
        "scan_not_canceled",
        XBinary::isPdStructNotCanceled(&state)
    );
    output.insert("records", serializeRecords(result.listRecords));
    std::printf(
        "%s",
        QJsonDocument(output).toJson(QJsonDocument::Indented).constData()
    );
    return 0;
}
