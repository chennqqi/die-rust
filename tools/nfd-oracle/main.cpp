// nfd-oracle — minimal console harness that runs the upstream
// SpecAbstract (NFD) engine and dumps the SCAN_RESULT record list as
// JSON, for differential comparison against diec-nfd.
//
// Usage: nfd-oracle <file> [file...]
//
// Upstream pin: DIE-engine 23fec32cac2a562342c1c2db8e22ce231b58f346 /
// SpecAbstract 5188e047755299a87d6feee840e6d8f31fb89b3d.

#include <QCoreApplication>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>

#include "specabstract.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);
    QTextStream err(stderr);

    QStringList files = app.arguments().mid(1);
    if (files.isEmpty()) {
        err << "usage: nfd-oracle <file> [file...]\n";
        return 2;
    }

    SpecAbstract engine;
    XScanEngine::SCAN_OPTIONS opts = {};
    opts.bIsDeepScan = true;
    opts.bIsHeuristicScan = true;
    opts.bIsVerbose = true;
    opts.bIsRecursiveScan = true;
    opts.bIsArchivesScan = true;
    opts.bIsOverlayScan = true;
    opts.bIsAggressiveScan = false;
    opts.bIsAllTypesScan = false;

    QJsonArray result;
    for (const QString &path : files) {
        if (!QFileInfo::exists(path)) {
            err << "missing: " << path << "\n";
            continue;
        }
        XScanEngine::SCAN_RESULT scan = engine.scanFile(path, &opts);
        QJsonArray records;
        for (const XScanEngine::SCANSTRUCT &r : scan.listRecords) {
            QJsonObject o;
            o["type"] = XScanEngine::recordTypeIdToString(r.type);
            o["name"] = XScanEngine::recordNameIdToString(r.name);
            if (!r.sName.isEmpty()) o["sname"] = r.sName;
            if (!r.sType.isEmpty()) o["stype"] = r.sType;
            o["version"] = r.sVersion;
            o["info"] = r.sInfo;
            o["heuristic"] = r.bIsHeuristic;
            o["unknown"] = r.bIsUnknown;
            o["idft"] = XBinary::fileTypeIdToString(r.id.fileType);
            o["idpart"] = XBinary::recordFilePartIdToFtString(r.id.filePart);
            o["pft"] = XBinary::fileTypeIdToString(r.parentId.fileType);
            o["ppart"] = XBinary::recordFilePartIdToFtString(r.parentId.filePart);
            o["oname"] = r.id.sOriginalName;
            records.append(o);
        }
        QJsonObject f;
        f["file"] = path;
        f["records"] = records;
        result.append(f);
    }
    out << QJsonDocument(result).toJson(QJsonDocument::Compact) << "\n";
    return 0;
}
