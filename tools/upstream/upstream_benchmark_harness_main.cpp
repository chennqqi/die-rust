// Project-generated benchmark harness for a pinned DIE-engine checkout.
// It replaces only the console main and emits deterministic correctness
// controls; timing and peak RSS are measured by the external process runner.

#include "die_script.h"

#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include <cstdio>

namespace {
XScanEngine::SCAN_OPTIONS scanOptions()
{
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
    return options;
}

void printJson(const QJsonObject &value)
{
    std::printf(
        "%s\n",
        QJsonDocument(value)
            .toJson(QJsonDocument::Compact)
            .constData()
    );
}
}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    QString mode;
    QString fileName;
    for (int i = 1; i < argc; i++) {
        QString argument = QString::fromLocal8Bit(argv[i]);
        if (
            (argument == "--noop")
            || (argument == "--database-only")
            || (argument == "--archive")
        ) {
            if (!mode.isEmpty()) {
                std::fprintf(stderr, "multiple modes\n");
                return 2;
            }
            mode = argument;
        } else if (fileName.isEmpty()) {
            fileName = argument;
        } else {
            std::fprintf(
                stderr,
                "unexpected argument: %s\n",
                argv[i]
            );
            return 2;
        }
    }

    if (mode == "--noop") {
        if (!fileName.isEmpty()) {
            std::fprintf(stderr, "noop does not accept a file\n");
            return 2;
        }
        QJsonObject result;
        result.insert("mode", "noop");
        printJson(result);
        return 0;
    }
    if (
        (mode != "--database-only")
        && (mode != "--archive")
    ) {
        std::fprintf(
            stderr,
            "usage: die-upstream-benchmark-harness "
            "--noop | --database-only | --archive <file>\n"
        );
        return 2;
    }
    if (
        (mode == "--database-only" && !fileName.isEmpty())
        || (mode == "--archive" && fileName.isEmpty())
    ) {
        std::fprintf(stderr, "invalid file argument for mode\n");
        return 2;
    }

    XScanEngine::SCAN_OPTIONS options = scanOptions();
    XBinary::PDSTRUCT pdStruct = XBinary::createPdStruct();
    DiE_Script engine;
    if (!engine.loadDatabase(&options, &pdStruct)) {
        std::fprintf(stderr, "cannot load pinned database\n");
        return 3;
    }

    if (mode == "--database-only") {
        QJsonObject result;
        result.insert("database_loaded", true);
        result.insert("mode", "database_only");
        printJson(result);
        return 0;
    }

    options.bIsArchivesScan = true;
    XScanEngine::SCAN_RESULT scanResult =
        engine.scanFile(fileName, &options, &pdStruct);
    qint32 streamRecordCount = 0;
    for (const XScanEngine::SCANSTRUCT &record :
         scanResult.listRecords) {
        if (record.id.filePart == XBinary::FILEPART_STREAM) {
            streamRecordCount++;
        }
    }
    QJsonObject result;
    result.insert("error_count", scanResult.listErrors.size());
    result.insert("mode", "archive");
    result.insert("pd_stopped", pdStruct.bIsStop);
    result.insert("record_count", scanResult.listRecords.size());
    result.insert("stream_record_count", streamRecordCount);
    printJson(result);
    return scanResult.listErrors.isEmpty() ? 0 : 4;
}
