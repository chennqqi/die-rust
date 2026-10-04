// Project-generated research harness for a pinned DIE-engine checkout.
// It links the unmodified upstream engine objects and summarizes aggressive
// archive traversal without emitting the full 100000-record result tree.

#include "die_script.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QString>

#include <sys/resource.h>

#include <cstdio>

namespace {
qlonglong peakRssKiB()
{
    struct rusage usage = {};
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        return -1;
    }
    return usage.ru_maxrss;
}
}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    if (argc != 2) {
        std::fprintf(
            stderr,
            "usage: die-archive-iteration-boundary-harness <file>\n"
        );
        return 2;
    }

    XScanEngine::SCAN_OPTIONS options = {};
    options.bUseCustomDatabase = true;
    options.bUseExtraDatabase = true;
    options.bShowType = true;
    options.bShowInfo = true;
    options.bShowVersion = true;
    options.bIsAggressiveScan = true;
    options.bIsArchivesScan = true;
    options.bIsSort = true;
    options.sMainDatabasePath = "/opt/die-source/Detect-It-Easy/db";
    options.sExtraDatabasePath =
        "/opt/die-source/Detect-It-Easy/db_extra";
    options.sCustomDatabasePath =
        "/opt/die-source/Detect-It-Easy/db_custom";

    XBinary::PDSTRUCT pdStruct = XBinary::createPdStruct();
    DiE_Script engine;
    if (!engine.loadDatabase(&options, &pdStruct)) {
        std::fprintf(stderr, "cannot load pinned database\n");
        return 3;
    }

    qlonglong rssBeforeKiB = peakRssKiB();
    QElapsedTimer timer;
    timer.start();
    XScanEngine::SCAN_RESULT scanResult =
        engine.scanFile(
            QString::fromLocal8Bit(argv[1]),
            &options,
            &pdStruct
        );
    qint64 elapsedMs = timer.elapsed();
    qlonglong rssAfterKiB = peakRssKiB();

    QSet<QString> nodes;
    QSet<QString> pdfNodes;
    QSet<QString> streamNodes;
    for (const XScanEngine::SCANSTRUCT &record :
         scanResult.listRecords) {
        if (record.id.sUuid.isEmpty()) {
            continue;
        }
        nodes.insert(record.id.sUuid);
        if (record.id.fileType == XBinary::FT_PDF) {
            pdfNodes.insert(record.id.sUuid);
        }
        if (
            record.id.filePart
            == XBinary::FILEPART_STREAM
        ) {
            streamNodes.insert(record.id.sUuid);
        }
    }

    QJsonObject result;
    result.insert("aggressive_scan", options.bIsAggressiveScan);
    result.insert(
        "debug_record_count",
        scanResult.listDebugRecords.size()
    );
    result.insert(
        "elapsed_ms",
        static_cast<double>(elapsedMs)
    );
    result.insert("error_count", scanResult.listErrors.size());
    result.insert(
        "handler_count",
        scanResult.listHandlers.size()
    );
    result.insert("node_count", nodes.size());
    result.insert("pdf_node_count", pdfNodes.size());
    result.insert("pd_stopped", pdStruct.bIsStop);
    result.insert(
        "peak_rss_after_kib",
        static_cast<double>(rssAfterKiB)
    );
    result.insert(
        "peak_rss_before_kib",
        static_cast<double>(rssBeforeKiB)
    );
    result.insert(
        "record_count",
        scanResult.listRecords.size()
    );
    result.insert(
        "scan_result_time_ms",
        static_cast<double>(scanResult.nScanTime)
    );
    result.insert("stream_node_count", streamNodes.size());

    std::printf(
        "%s\n",
        QJsonDocument(result)
            .toJson(QJsonDocument::Compact)
            .constData()
    );
    return 0;
}
