// Project-generated research harness for a pinned DIE-engine checkout.
// It changes only SCAN_OPTIONS reachability; scanning and rendering remain
// upstream implementations.

#include "die_script.h"
#include "scanitemmodel.h"

#include <QCoreApplication>
#include <QString>

#include <cstdio>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    bool isArchive = false;
    bool isAggressive = false;
    bool isRecursive = false;
    QString fileName;

    for (int i = 1; i < argc; i++) {
        QString argument = QString::fromLocal8Bit(argv[i]);

        if (argument == "--archive") {
            isArchive = true;
        } else if (argument == "--aggressive") {
            isAggressive = true;
        } else if (argument == "--recursive") {
            isRecursive = true;
        } else if (fileName.isEmpty()) {
            fileName = argument;
        } else {
            std::fprintf(stderr, "unexpected argument: %s\n", argv[i]);
            return 2;
        }
    }

    if (fileName.isEmpty()) {
        std::fprintf(
            stderr,
            "usage: die-archive-harness [--archive] [--aggressive] "
            "[--recursive] <file>\n"
        );
        return 2;
    }

    XScanEngine::SCAN_OPTIONS options = {};
    options.bUseCustomDatabase = true;
    options.bUseExtraDatabase = true;
    options.bShowType = true;
    options.bShowInfo = true;
    options.bShowVersion = true;
    options.bIsArchivesScan = isArchive;
    options.bIsAggressiveScan = isAggressive;
    options.bIsRecursiveScan = isRecursive;
    options.bIsSort = true;
    options.bResultAsJSON = true;
    options.sMainDatabasePath = "/opt/die-source/Detect-It-Easy/db";
    options.sExtraDatabasePath = "/opt/die-source/Detect-It-Easy/db_extra";
    options.sCustomDatabasePath =
        "/opt/die-source/Detect-It-Easy/db_custom";

    XBinary::PDSTRUCT pdStruct = XBinary::createPdStruct();
    DiE_Script engine;

    if (!engine.loadDatabase(&options, &pdStruct)) {
        std::fprintf(stderr, "cannot load pinned database\n");
        return 3;
    }

    XScanEngine::SCAN_RESULT scanResult =
        engine.scanFile(fileName, &options, &pdStruct);
    ScanItemModel model(&options, &(scanResult.listRecords), 1, nullptr);

    std::printf(
        "%s\n",
        model.toString(XBinary::FORMATTYPE_JSON).toUtf8().constData()
    );
    if (!scanResult.listErrors.isEmpty()) {
        std::printf(
            "%s",
            DiE_Script::getErrorsString(&scanResult).toUtf8().constData()
        );
    }
    std::printf("\n");
    return 0;
}
