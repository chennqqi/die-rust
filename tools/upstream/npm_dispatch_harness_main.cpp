// Project-generated research harness for NPM detector reachability.
// It links the unmodified pinned engine and changes only a QIODevice property
// in the explicitly labeled forced case.

#include "die_script.h"
#include "xformats.h"
#include "xnpm.h"

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
constexpr const char *XARCHIVE_COMMIT =
    "0fcd4e8d3e9933baac3b12246d82ac026557ffd0";
constexpr const char *XSCANENGINE_COMMIT =
    "dfe4a419e4f491bb23688ba03c5a5bf39e34da83";

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

bool directNpmValid(QByteArray *data)
{
    QBuffer buffer(data);
    if (!buffer.open(QIODevice::ReadOnly)) {
        return false;
    }
    XBinary::PDSTRUCT state = XBinary::createPdStruct();
    XNPM npm(&buffer);
    const bool result = npm.isValid(&state);
    buffer.close();
    return result;
}

QJsonObject runScan(
    QByteArray *data,
    const QString &fileName,
    bool forceNpm
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
    if (forceNpm) {
        buffer.setProperty("filetypes", "NPM");
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
    output.insert("forced", forceNpm);
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
            "usage: die-npm-dispatch-harness <input.tgz>\n"
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
    output.insert("xarchive_commit", XARCHIVE_COMMIT);
    output.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    output.insert("input_name", QFileInfo(inputPath).fileName());
    output.insert("input_size", data.size());
    output.insert("direct_npm_valid", directNpmValid(&data));
    output.insert("automatic", runScan(&data, inputPath, false));
    output.insert("forced_npm", runScan(&data, inputPath, true));
    std::printf(
        "%s",
        QJsonDocument(output).toJson(QJsonDocument::Indented).constData()
    );
    return 0;
}
