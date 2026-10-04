// Project-generated research harness for generic Archive reachability.
// It links the unmodified pinned engine and changes only a QIODevice property
// plus the explicitly labeled verbose control.

#include "die_script.h"
#include "xformats.h"

#include <QBuffer>
#include <QCoreApplication>
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

QJsonArray serializeRecords(
    const QList<XScanEngine::SCANSTRUCT> &records
)
{
    QJsonArray output;
    for (const XScanEngine::SCANSTRUCT &record : records) {
        QJsonObject item;
        item.insert(
            "filetype",
            XBinary::fileTypeIdToString(record.id.fileType)
        );
        item.insert("type", record.sType);
        item.insert("name", record.sName);
        item.insert("version", record.sVersion);
        item.insert("info", record.sInfo);
        item.insert("signature", record.varInfo);
        item.insert("unknown", record.bIsUnknown);
        output.append(item);
    }
    return output;
}

QJsonObject runScan(
    QByteArray *data,
    const QString &fileName,
    bool forceArchive,
    bool verbose
)
{
    QBuffer buffer(data);
    buffer.setProperty("FileName", fileName);
    // scanProcess otherwise copies small devices into a fresh QBuffer and
    // intentionally does not propagate arbitrary source properties.
    buffer.setProperty(
        "Memory",
        reinterpret_cast<quint64>(data->constData())
    );
    if (forceArchive) {
        buffer.setProperty("filetypes", "ARCHIVE");
    }
    if (!buffer.open(QIODevice::ReadOnly)) {
        return {{"harness_error", "cannot open input buffer"}};
    }

    XBinary::PDSTRUCT detectorState = XBinary::createPdStruct();
    const QSet<XBinary::FT> detected = XFormats::getFileTypes(
        &buffer,
        true,
        &detectorState
    );
    buffer.seek(0);

    XScanEngine::SCAN_OPTIONS options = {};
    options.bUseCustomDatabase = true;
    options.bUseExtraDatabase = true;
    options.bShowType = true;
    options.bShowInfo = true;
    options.bShowVersion = true;
    options.bIsVerbose = verbose;
    options.bIsSort = true;
    options.sMainDatabasePath = "/opt/die-source/Detect-It-Easy/db";
    options.sExtraDatabasePath =
        "/opt/die-source/Detect-It-Easy/db_extra";
    options.sCustomDatabasePath =
        "/opt/die-source/Detect-It-Easy/db_custom";

    XBinary::PDSTRUCT loadState = XBinary::createPdStruct();
    DiE_Script engine;
    const bool loaded = engine.loadDatabase(&options, &loadState);
    XBinary::PDSTRUCT scanState = XBinary::createPdStruct();
    const XScanEngine::SCAN_RESULT result = engine.scanDevice(
        &buffer,
        &options,
        &scanState
    );

    QJsonObject output;
    output.insert("forced", forceArchive);
    output.insert("verbose", verbose);
    output.insert(
        "property",
        buffer.property("filetypes").toString()
    );
    output.insert(
        "detected_filetypes",
        XBinary::fileTypesToString(detected)
    );
    output.insert(
        "initial_filetype",
        XBinary::fileTypeIdToString(result.ftInit)
    );
    output.insert("database_loaded", loaded);
    output.insert("record_count", result.listRecords.size());
    output.insert("records", serializeRecords(result.listRecords));
    output.insert("error_count", result.listErrors.size());
    output.insert(
        "scan_success",
        XBinary::isPdStructSuccess(&scanState)
    );
    buffer.close();
    return output;
}

}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    if (argc != 2) {
        std::fprintf(
            stderr,
            "usage: die-generic-archive-dispatch-harness <archive>\n"
        );
        return 2;
    }

    const QString inputPath = QString::fromLocal8Bit(argv[1]);
    QFile input(inputPath);
    if (!input.open(QIODevice::ReadOnly)) {
        std::fprintf(stderr, "cannot open fixture input\n");
        return 3;
    }
    QByteArray data = input.readAll();
    input.close();

    QJsonObject output;
    output.insert("schema_version", 1);
    output.insert("upstream_commit", UPSTREAM_COMMIT);
    output.insert("formats_commit", FORMATS_COMMIT);
    output.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    output.insert("die_script_commit", DIE_SCRIPT_COMMIT);
    output.insert("input_name", QFileInfo(inputPath).fileName());
    output.insert("input_size", data.size());
    output.insert(
        "automatic_quiet",
        runScan(&data, inputPath, false, false)
    );
    output.insert(
        "automatic_verbose",
        runScan(&data, inputPath, false, true)
    );
    output.insert(
        "forced_archive_quiet",
        runScan(&data, inputPath, true, false)
    );
    output.insert(
        "forced_archive_verbose",
        runScan(&data, inputPath, true, true)
    );
    std::printf(
        "%s",
        QJsonDocument(output).toJson(QJsonDocument::Indented).constData()
    );
    return 0;
}
