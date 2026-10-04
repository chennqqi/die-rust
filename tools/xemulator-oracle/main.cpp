// xemulator-oracle — console harness driving the pinned upstream
// XEmulator x86 core and the XStaticUnpacker emulator branches, for
// differential comparison against the diec-engine Rust port.
//
// Modes:
//   xemulator-oracle micro <hex-bytes> [max-steps]
//       32-bit flat setup: code at 0x10000 (rwx), stack at
//       0x30000-0x31000 (rw), data at 0x40000 (rwx, one page of the
//       same bytes). EIP=0x10000, ESP=stack top-0x10. Steps via
//       step() until a non-OK result or the step budget; prints a
//       JSON dump of registers, stop info, and per-region FNV-1a
//       hashes plus the first 64 bytes of each region.
//
//   xemulator-oracle unpack <input> <output-prefix>
//       Runs XInstallSimple / XASPACK / XPETITE detect+unpack like
//       unpack-oracle; prints one JSON object per claiming class.
//
// Upstream pins: DIE-engine 23fec32 / XStaticUnpacker 746fb24 /
// XEmulator 655e6da0410e88fe6dacf292fd157ef1585bf43c.

#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>

#include "xemumemorymanager.h"
#include "xemuregisters.h"
#include "xemux86.h"

#include "xaspack.h"
#include "xinstallsimple.h"
#include "xpetite.h"

static const XADDR MICRO_CODE = 0x10000;
static const XADDR MICRO_STACK = 0x30000;
static const quint64 MICRO_STACK_SIZE = 0x1000;
static const XADDR MICRO_DATA = 0x40000;

// FNV-1a 64 over a byte range — stable cross-process memory checksum.
static quint64 fnv1a(const QByteArray &ba)
{
    quint64 h = Q_UINT64_C(14695981039346656037);
    for (char c : ba) {
        h ^= (quint8)c;
        h *= Q_UINT64_C(1099511628211);
    }
    return h;
}

static quint64 fnv1aFile(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return 0;
    return fnv1a(f.readAll());
}

static QJsonObject microRun(const QByteArray &baCode, qint64 nMaxSteps)
{
    XEmuMemoryManager memory;
    memory.setBits(32);
    const XEmuMemoryManager::MEMORY_FLAGS rwx(true, true, true, false);
    const XEmuMemoryManager::MEMORY_FLAGS rw(true, true, false, false);
    QJsonObject result;

    bool bSetup = memory.mapFixed(MICRO_CODE, 0x1000, rwx, QStringLiteral("code")) &&
                  memory.mapFixed(MICRO_STACK, MICRO_STACK_SIZE, rw, QStringLiteral("stack")) &&
                  memory.mapFixed(MICRO_DATA, 0x1000, rwx, QStringLiteral("data")) &&
                  memory.write(MICRO_CODE, baCode) && memory.write(MICRO_DATA, baCode.left(0x1000));
    result["setup"] = bSetup;
    if (!bSetup) return result;

    XEmuX86 arch(&memory, 32);
    XEmuRegisters registers;
    registers.setGPR(XEmuRegisters::GPR_RSP, 4, MICRO_STACK + MICRO_STACK_SIZE - 0x10);
    registers.nRIP = MICRO_CODE;

    qint64 nSteps = 0;
    XEmuArch::STEP_INFO stop;
    stop.result = XEmuArch::STEP_OK;
    while (nSteps < nMaxSteps) {
        stop = arch.step(&registers);
        if (stop.result != XEmuArch::STEP_OK) break;
        nSteps++;
    }

    QJsonArray regs;
    for (int i = 0; i < 16; i++) {
        regs.append(QString::number(registers.getGPR(i, 4), 16));
    }
    result["gpr"] = regs;
    result["rip"] = QString::number(registers.nRIP, 16);
    result["rflags"] = QString::number(registers.nRFLAGS, 16);
    QJsonObject segs;
    segs["cs"] = registers.nCS;
    segs["ds"] = registers.nDS;
    segs["es"] = registers.nES;
    segs["fs"] = registers.nFS;
    segs["gs"] = registers.nGS;
    segs["ss"] = registers.nSS;
    result["segs"] = segs;
    result["steps"] = nSteps;
    result["stop_result"] = (int)stop.result;
    result["stop_address"] = QString::number(stop.nAddress, 16);
    result["stop_text"] = stop.sText;
    result["stop_comment"] = stop.sComment;

    QJsonArray regions;
    for (const XEmuMemoryManager::REGION &region : memory.getRegions()) {
        if (region.state != XEmuMemoryManager::STATE_COMMIT) continue;
        QJsonObject r;
        r["base"] = QString::number(region.nAddress, 16);
        bool bOk = false;
        QByteArray ba = memory.read(region.nAddress, region.nSize, &bOk);
        if (!bOk) {
            r["read_error"] = true;
        } else {
            r["fnv64"] = QString::number(fnv1a(ba), 16);
            r["head"] = QString::fromLatin1(ba.left(64).toHex());
        }
        regions.append(r);
    }
    result["regions"] = regions;
    return result;
}

// Mirrors nfd-oracle/unpack_main.cpp so report shapes stay comparable.
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
    report["init_unpack"] = true;
    report["records"] = (qint64)state.nNumberOfRecords;

    QJsonArray members;
    for (int idx = 0;; idx++) {
        if (idx > 0 && !pUnpacker->moveToNext(&state)) break;
        XBinary::ARCHIVERECORD rec = pUnpacker->infoCurrent(&state);
        QString memberName = rec.mapProperties.value(XBinary::FPART_PROP_ORIGINALNAME).toString();
        if (memberName.isEmpty()) memberName = QString("record_%1").arg(idx);
        QString memberPath = (idx == 0 && members.isEmpty() && state.nNumberOfRecords <= 1)
                                 ? outPath
                                 : outPath + "." + memberName;

        QJsonObject member;
        member["name"] = memberName;
        member["info"] = rec.mapProperties.value(XBinary::FPART_PROP_INFO).toString();
        QFile out(memberPath);
        if (out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            if (pUnpacker->unpackCurrent(&state, &out)) {
                out.close();
                member["unpacked"] = true;
                member["out_size"] = QFileInfo(memberPath).size();
                member["fnv64"] = QString::number(fnv1aFile(memberPath), 16);
            } else {
                out.close();
                out.remove();
                member["unpacked"] = false;
            }
        }
        members.append(member);
    }
    report["members"] = members;
    pUnpacker->finishUnpack(&state);
    return report;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);
    const QStringList args = app.arguments();

    if ((args.size() >= 3) && (args.at(1) == QStringLiteral("micro"))) {
        QByteArray code = QByteArray::fromHex(args.at(2).toLatin1());
        qint64 nMaxSteps = (args.size() >= 4) ? args.at(3).toLongLong() : 64;
        out << QJsonDocument(microRun(code, nMaxSteps)).toJson(QJsonDocument::Compact) << "\n";
        return 0;
    }

    if ((args.size() >= 4) && (args.at(1) == QStringLiteral("unpack"))) {
        QFile file(args.at(2));
        if (!file.open(QIODevice::ReadOnly)) {
            out << "{\"error\":\"cannot open input\"}\n";
            return 1;
        }
        const QString prefix = args.at(3);
        QJsonArray reports;

        {
            XInstallSimple x(&file);
            reports.append(tryUnpack(&x, QStringLiteral("installsimple"), prefix));
        }
        file.seek(0);
        {
            XASPACK x(&file);
            reports.append(tryUnpack(&x, QStringLiteral("aspack"), prefix));
        }
        file.seek(0);
        {
            XPETITE x(&file);
            reports.append(tryUnpack(&x, QStringLiteral("petite"), prefix));
        }
        out << QJsonDocument(reports).toJson(QJsonDocument::Compact) << "\n";
        return 0;
    }

    out << "usage: xemulator-oracle micro <hex> [steps] | unpack <file> <prefix>\n";
    return 2;
}
