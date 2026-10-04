// unpack-oracle — console harness that runs the pinned upstream
// XStaticUnpacker classes on a packed input and writes the unpacked
// output, for differential comparison against die-engine::unpack.
//
// Usage: unpack-oracle <input> <output-prefix>
//   Prints one JSON object per unpacker that claims the file, and
//   writes "<output-prefix>.<name>" for each successful unpack.
//
// Upstream pin: DIE-engine 23fec32cac2a562342c1c2db8e22ce231b58f346 /
// SpecAbstract 5188e047755299a87d6feee840e6d8f31fb89b3d.

#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>

#include "xaspack.h"
#include "xautoit.h"
#include "xboxedapp.h"
#include "xenigmavb.h"
#include "xfsg.h"
#include "xmew.h"
#include "xnspack.h"
#include "xpetite.h"
#include "xupx.h"
#include "xyoda.h"

// Try one unpacker class: detect, then initUnpack/unpackCurrent to
// an output file. Returns the JSON report for this class (empty
// object when the class does not claim the input).
static QJsonObject tryUnpack(XBinary *pUnpacker, const QString &name, const QString &outPath)
{
    QJsonObject report;
    if (!pUnpacker->isValid()) {
        return report;
    }

    report["packer"] = name;
    report["version"] = pUnpacker->getVersion();

    XBinary::UNPACK_STATE state = {};
    if (!pUnpacker->initUnpack(&state, pUnpacker->getDefaultUnpackProperties())) {
        report["init_unpack"] = false;
        return report;
    }

    // Archive unpackers expose N records: walk them all so the oracle
    // covers the full member list, not just the first entry.
    QString firstInfo;
    QJsonArray members;
    for (int idx = 0;; idx++) {
        if (idx > 0 && !pUnpacker->moveToNext(&state)) break;
        XBinary::ARCHIVERECORD rec = pUnpacker->infoCurrent(&state);
        if (idx == 0) {
            firstInfo = rec.mapProperties.value(XBinary::FPART_PROP_INFO).toString();
        }
        QString memberName = rec.mapProperties.value(XBinary::FPART_PROP_ORIGINALNAME).toString();
        if (memberName.isEmpty()) memberName = QString("record_%1").arg(idx);
        QString memberPath = (idx == 0 && members.isEmpty() && state.nNumberOfRecords <= 1)
                                 ? outPath
                                 : outPath + "." + memberName;

        QJsonObject member;
        member["name"] = memberName;
        QFile out(memberPath);
        if (out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            if (pUnpacker->unpackCurrent(&state, &out)) {
                out.close();
                member["unpacked"] = true;
                member["out_path"] = memberPath;
                member["out_size"] = QFileInfo(memberPath).size();
            } else {
                out.close();
                out.remove();
                member["unpacked"] = false;
            }
        }
        members.append(member);
        if (state.nNumberOfRecords > 0 && idx >= state.nNumberOfRecords - 1) break;
        if (idx > 100000) break;  // safety bound
    }
    report["members"] = members;
    report["unpacked"] = !members.isEmpty();
    if (members.size() == 1) {
        report["out_path"] = members.first().toObject().value("out_path");
        report["out_size"] = members.first().toObject().value("out_size");
    }
    report["info"] = firstInfo;
    pUnpacker->finishUnpack(&state);
    return report;
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);
    QTextStream err(stderr);

    QStringList args = app.arguments().mid(1);
    if (args.size() != 2) {
        err << "usage: unpack-oracle <input> <output-prefix>\n";
        return 2;
    }

    QFile input(args.at(0));
    if (!input.open(QIODevice::ReadOnly)) {
        err << "cannot open: " << args.at(0) << "\n";
        return 2;
    }

    // Keep one shared buffer: each unpacker gets its own QFile so the
    // device position is per-object, matching upstream usage.
    QByteArray data = input.readAll();
    input.close();

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
        XBinary *pObj = factory(pFile);
        candidates.append({name, pObj});
    };

    make("fsg", [](QIODevice *d) -> XBinary * { return new XFSG(d); });
    make("mew", [](QIODevice *d) -> XBinary * { return new XMEW(d); });
    make("petite", [](QIODevice *d) -> XBinary * { return new XPETITE(d); });
    make("aspack", [](QIODevice *d) -> XBinary * { return new XASPACK(d); });
    make("nspack", [](QIODevice *d) -> XBinary * { return new XNSPACK(d); });
    make("yoda", [](QIODevice *d) -> XBinary * { return new XYODA(d); });
    make("autoit", [](QIODevice *d) -> XBinary * { return new XAUTOIT(d); });
    make("enigmavb", [](QIODevice *d) -> XBinary * { return new XEnigmaVB(d); });
    make("boxedapp", [](QIODevice *d) -> XBinary * { return new XBoxedApp(d); });
    // XInstallSimple is gated behind USE_XEMULATOR (upstream runs the
    // stub decoder in a sandboxed x86 core) and is not part of this build.
    make("upx", [](QIODevice *d) -> XBinary * { return new XUPX(d); });

    QJsonArray reports;
    for (const CANDIDATE &c : candidates) {
        QJsonObject r = tryUnpack(c.pObj, c.name, args.at(1) + "." + c.name);
        if (!r.isEmpty()) {
            reports.append(r);
        }
    }

    QJsonDocument doc(reports);
    out << doc.toJson(QJsonDocument::Compact) << "\n";
    return 0;
}
