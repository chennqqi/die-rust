// list-oracle — console harness that runs the pinned upstream XArchive
// classes on an archive input and reports the member record list, for
// differential comparison against diec-engine::archive::list_secondary.
//
// Usage: list-oracle <input> [outdir]
//   Prints one JSON object per format class that claims the file:
//   {"format":"arj","records":[{"name":...,"size":...,"packed":...,
//    "dir":...,"method":...,"unpacked":...,"out_path":...}]}
//   When [outdir] is given, each record is also fed to unpackCurrent
//   and successful output written to <outdir>/<format>.<idx>.
//
// Upstream pin: DIE-engine 23fec32cac2a562342c1c2db8e22ce231b58f346.

#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>

#include "xarj.h"
#include "xlha.h"
#include "xcpio.h"
#include "xace.h"
#include "xudf.h"
#include "xwim.h"

// Enumerate records via the shared UNPACK_STATE stream API.
// When `outDir` is non-empty each record is additionally extracted via
// unpackCurrent so extracted bytes can be diffed against the Rust side.
static QJsonObject tryList(XBinary *pArchive, const QString &name,
                           const QString &outDir)
{
    QJsonObject report;
    if (!pArchive->isValid()) {
        return report;
    }
    report["format"] = name;

    XBinary::UNPACK_STATE state = {};
    if (!pArchive->initUnpack(&state, pArchive->getDefaultUnpackProperties())) {
        report["init_unpack"] = false;
        return report;
    }

    QJsonArray records;
    for (int idx = 0;; idx++) {
        if (idx > 0 && !pArchive->moveToNext(&state)) break;
        XBinary::ARCHIVERECORD rec = pArchive->infoCurrent(&state);
        QJsonObject m;
        m["name"] = rec.mapProperties.value(XBinary::FPART_PROP_ORIGINALNAME).toString();
        m["size"] = QString::number(rec.mapProperties.value(XBinary::FPART_PROP_UNCOMPRESSEDSIZE).toLongLong());
        m["packed"] = QString::number(rec.mapProperties.value(XBinary::FPART_PROP_COMPRESSEDSIZE).toLongLong());
        m["dir"] = rec.mapProperties.value(XBinary::FPART_PROP_ISFOLDER).toBool();
        m["method"] = QString::number(rec.mapProperties.value(XBinary::FPART_PROP_HANDLEMETHOD).toInt());
        m["method_name"] = rec.mapProperties.value(XBinary::FPART_PROP_COMPRESSPROPERTIES).toString();
        QDateTime dt = rec.mapProperties.value(XBinary::FPART_PROP_MTIME).toDateTime();
        if (dt.isValid()) m["mtime"] = dt.toString("yyyy-MM-dd HH:mm:ss");
        if (!outDir.isEmpty()) {
            QString memberPath = outDir + "/" + name + "." + QString::number(idx);
            QFile out(memberPath);
            if (out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                XBinary::PDSTRUCT pd = XBinary::createPdStruct();
                if (pArchive->unpackCurrent(&state, &out, &pd)) {
                    out.close();
                    m["unpacked"] = true;
                    m["out_path"] = memberPath;
                } else {
                    out.close();
                    out.remove();
                    m["unpacked"] = false;
                    if (!pd.sInfoString.isEmpty()) m["error"] = pd.sInfoString;
                }
            }
        }
        records.append(m);
        if (state.nNumberOfRecords > 0 && idx >= state.nNumberOfRecords - 1) break;
        if (idx > 100000) break;
    }
    report["records"] = records;
    pArchive->finishUnpack(&state);
    return report;
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);
    QTextStream err(stderr);

    QStringList args = app.arguments().mid(1);
    if (args.size() < 1 || args.size() > 2) {
        err << "usage: list-oracle <input> [outdir]\n";
        return 2;
    }
    QString outDir = args.size() == 2 ? args.at(1) : QString();

    struct CANDIDATE {
        QString name;
        XBinary *pObj;
    };
    QList<CANDIDATE> candidates;
    auto make = [&](const QString &name, auto factory) {
        QFile *pFile = new QFile(args.at(0), &app);
        if (!pFile->open(QIODevice::ReadOnly)) {
            delete pFile;
            return;
        }
        candidates.append({name, factory(pFile)});
    };

    make("arj", [](QIODevice *d) -> XBinary * { return new XARJ(d); });
    make("lha", [](QIODevice *d) -> XBinary * { return new XLHA(d); });
    make("ace", [](QIODevice *d) -> XBinary * { return new XACE(d); });
    make("cpio", [](QIODevice *d) -> XBinary * { return new XCPIO(d); });
    make("udf", [](QIODevice *d) -> XBinary * { return new XUDF(d); });
    make("wim", [](QIODevice *d) -> XBinary * { return new XWIM(d); });

    QJsonArray reports;
    for (const CANDIDATE &c : candidates) {
        QJsonObject r = tryList(c.pObj, c.name, outDir);
        if (!r.isEmpty()) {
            reports.append(r);
        }
    }
    out << QJsonDocument(reports).toJson(QJsonDocument::Compact) << "\n";
    return 0;
}
