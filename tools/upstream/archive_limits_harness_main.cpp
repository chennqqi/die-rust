// Project-generated research harness for a pinned DIE-engine checkout.
// It links the unmodified upstream engine objects and emits only a compact
// process/resource and result-tree summary.

#include "die_script.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QString>

#include <sys/resource.h>

#include <algorithm>
#include <cstdio>
#include <functional>

namespace {
struct CallbackState {
    qint32 calls;
    qint32 stopAfter;
};

void progressCallback(
    void *pUserData,
    XBinary::PDSTRUCT *pPdStruct
)
{
    CallbackState *pState =
        static_cast<CallbackState *>(pUserData);
    pState->calls++;
    if (
        (pState->stopAfter > 0)
        && (pState->calls >= pState->stopAfter)
    ) {
        XBinary::setPdStructStopped(pPdStruct);
    }
}

qlonglong peakRssKiB()
{
    struct rusage usage = {};
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        return -1;
    }
    return usage.ru_maxrss;
}

qint32 nodeDepth(
    const QString &id,
    const QHash<QString, QString> &parents,
    QHash<QString, qint32> *pCache,
    QSet<QString> *pActive
)
{
    if (pCache->contains(id)) {
        return pCache->value(id);
    }
    if (pActive->contains(id)) {
        return -1;
    }
    pActive->insert(id);
    QString parent = parents.value(id);
    qint32 result = 0;
    if (
        !parent.isEmpty()
        && (parent != id)
        && parents.contains(parent)
    ) {
        qint32 parentDepth =
            nodeDepth(parent, parents, pCache, pActive);
        result = parentDepth < 0 ? -1 : parentDepth + 1;
    }
    pActive->remove(id);
    pCache->insert(id, result);
    return result;
}
}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    qint32 cancelAfterCallbacks = 0;
    QString fileName;
    for (int i = 1; i < argc; i++) {
        QString argument = QString::fromLocal8Bit(argv[i]);
        if (argument == "--cancel-after-callbacks") {
            if ((i + 1) >= argc) {
                std::fprintf(
                    stderr,
                    "missing callback threshold\n"
                );
                return 2;
            }
            bool ok = false;
            cancelAfterCallbacks =
                QString::fromLocal8Bit(argv[++i]).toInt(&ok);
            if (!ok || (cancelAfterCallbacks < 1)) {
                std::fprintf(
                    stderr,
                    "invalid callback threshold\n"
                );
                return 2;
            }
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
    if (fileName.isEmpty()) {
        std::fprintf(
            stderr,
            "usage: die-archive-limits-harness "
            "[--cancel-after-callbacks N] <file>\n"
        );
        return 2;
    }

    XScanEngine::SCAN_OPTIONS options = {};
    options.bUseCustomDatabase = true;
    options.bUseExtraDatabase = true;
    options.bShowType = true;
    options.bShowInfo = true;
    options.bShowVersion = true;
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

    CallbackState callbackState = {};
    callbackState.stopAfter = cancelAfterCallbacks;
    pdStruct.pCallback = progressCallback;
    pdStruct.pCallbackUserData = &callbackState;
    pdStruct.nLastCallbackTime = 0;

    qlonglong rssBeforeKiB = peakRssKiB();
    QElapsedTimer timer;
    timer.start();
    XScanEngine::SCAN_RESULT scanResult =
        engine.scanFile(fileName, &options, &pdStruct);
    qint64 elapsedMs = timer.elapsed();
    qlonglong rssAfterKiB = peakRssKiB();

    QHash<QString, QString> parents;
    QHash<QString, XBinary::FILEPART> fileParts;
    QSet<QString> pdfNodes;
    for (const XScanEngine::SCANSTRUCT &record :
         scanResult.listRecords) {
        if (!record.id.sUuid.isEmpty()) {
            if (!parents.contains(record.id.sUuid)) {
                parents.insert(
                    record.id.sUuid,
                    record.parentId.sUuid
                );
                fileParts.insert(
                    record.id.sUuid,
                    record.id.filePart
                );
            }
            if (record.id.fileType == XBinary::FT_PDF) {
                pdfNodes.insert(record.id.sUuid);
            }
        }
    }

    QHash<QString, qint32> depths;
    qint32 maxDepth = 0;
    qint32 maxStreamDepth = 0;
    qint32 deepestPdfDepth = -1;
    qint32 streamNodes = 0;
    qint32 cyclicNodes = 0;
    for (
        auto iterator = parents.constBegin();
        iterator != parents.constEnd();
        ++iterator
    ) {
        QSet<QString> active;
        qint32 depth = nodeDepth(
            iterator.key(),
            parents,
            &depths,
            &active
        );
        if (depth < 0) {
            cyclicNodes++;
            continue;
        }
        maxDepth = std::max(maxDepth, depth);
        if (
            fileParts.value(iterator.key())
            == XBinary::FILEPART_STREAM
        ) {
            streamNodes++;
            maxStreamDepth = std::max(maxStreamDepth, depth);
        }
        if (pdfNodes.contains(iterator.key())) {
            deepestPdfDepth =
                std::max(deepestPdfDepth, depth);
        }
    }

    QJsonObject result;
    result.insert(
        "callback_calls",
        callbackState.calls
    );
    result.insert(
        "cancel_after_callbacks",
        cancelAfterCallbacks
    );
    result.insert("cyclic_node_count", cyclicNodes);
    result.insert("debug_record_count", scanResult.listDebugRecords.size());
    result.insert("deepest_pdf_depth", deepestPdfDepth);
    result.insert("elapsed_ms", static_cast<double>(elapsedMs));
    result.insert("error_count", scanResult.listErrors.size());
    result.insert("handler_count", scanResult.listHandlers.size());
    result.insert("max_depth", maxDepth);
    result.insert("max_stream_depth", maxStreamDepth);
    result.insert("node_count", parents.size());
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
    result.insert("record_count", scanResult.listRecords.size());
    result.insert(
        "scan_result_time_ms",
        static_cast<double>(scanResult.nScanTime)
    );
    result.insert("stream_node_count", streamNodes);

    std::printf(
        "%s\n",
        QJsonDocument(result)
            .toJson(QJsonDocument::Compact)
            .constData()
    );
    return 0;
}
