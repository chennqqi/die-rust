// msdos-oracle — dump MSDOS host API method results from the pinned
// upstream DIE engine, for differential comparison against diec-rust.
//
// It instantiates XMSDOS + MSDOS_Script exactly like XScanEngine does,
// exposes the script object to QJSEngine as "MSDOS", evaluates the real
// upstream db/MSDOS/_init framework file (so JS-shadowed methods like
// getBaseOffset/getNEOffset/addressToOffset behave exactly as in rule
// execution), then evaluates a probe expression and prints JSON.
//
// Usage: msdos-oracle <db_dir> <file> [file...]
//
// Upstream pin: DIE-engine 23fec32cac2a562342c1c2db8e22ce231b58f346.

#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QJSEngine>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>

#include "msdos_script.h"
#include "xmsdos.h"

static QString probeScript()
{
    // One expression producing a JSON object with every MSDOS host API
    // method that Phase 42 implements. Signature probes use bytes that
    // the generated fixtures place at known offsets. Each call is
    // individually wrapped so a single failure (e.g. a missing JS-defined
    // method when _init aborted early) does not mask the rest.
    return QStringLiteral(R"JS(
(function() {
    function t(f) { try { return f(); } catch (e) { return "ERR:" + e; } }
    var r = {};
    r.isLE = t(function() { return MSDOS.isLE(); });
    r.isLX = t(function() { return MSDOS.isLX(); });
    r.isNE = t(function() { return MSDOS.isNE(); });
    r.isPE = t(function() { return MSDOS.isPE(); });
    r.dosStubOff = t(function() { return MSDOS.getDosStubOffset(); });
    r.dosStubSize = t(function() { return MSDOS.getDosStubSize(); });
    r.isDosStub = t(function() { return MSDOS.isDosStubPresent(); });
    r.ovOff = t(function() { return MSDOS.getOverlayOffset(); });
    r.ovSize = t(function() { return MSDOS.getOverlaySize(); });
    r.isOverlay = t(function() { return MSDOS.isOverlayPresent(); });
    r.cmpEP_a = t(function() { return MSDOS.compareEP("EB"); });
    r.cmpEP_b = t(function() { return MSDOS.compareEP("90"); });
    r.cmpOV_a = t(function() { return MSDOS.compareOverlay("AA"); });
    r.cmpOV_b = t(function() { return MSDOS.compareOverlay("42424242"); });
    r.cmpOV_off = t(function() { return MSDOS.compareOverlay("4242", 2); });
    r.osName = t(function() { return MSDOS.getOperationSystemName(); });
    r.osVer = t(function() { return MSDOS.getOperationSystemVersion(); });
    r.osOpt = t(function() { return MSDOS.getOperationSystemOptions(); });
    r.ffName = t(function() { return MSDOS.getFileFormatName(); });
    r.ffVer = t(function() { return MSDOS.getFileFormatVersion(); });
    r.ffOpt = t(function() { return MSDOS.getFileFormatOptions(); });
    r.richPresent = t(function() { return MSDOS.isRichSignaturePresent(); });
    r.nRich = t(function() { return MSDOS.getNumberOfRichIDs(); });
    r.richVerPresent = t(function() { return MSDOS.isRichVersionPresent(0x1234); });
    r.richVer0 = t(function() { return MSDOS.getRichVersion(0); });
    r.richID0 = t(function() { return MSDOS.getRichID(0); });
    r.richCnt0 = t(function() { return MSDOS.getRichCount(0); });
    r.epOff = t(function() { return MSDOS.getEntryPointOffset(); });
    r.epOff16 = t(function() { return MSDOS.getEntryPointOffset(16); });
    r.neOff = t(function() { return MSDOS.getNEOffset(); });
    r.neOffN8 = t(function() { return MSDOS.getNEOffset(-8); });
    r.baseOff = t(function() { return MSDOS.getBaseOffset(); });
    r.baseOff24 = t(function() { return MSDOS.getBaseOffset(0x18); });
    r.a2o = t(function() { return MSDOS.addressToOffset(0x1234, 0x5678); });
    r.a2o_one = t(function() { return MSDOS.addressToOffset(0x100); });
    r.va2o_seg = t(function() { return MSDOS.VAToOffset(0x10000000); });
    r.va2o_seg16 = t(function() { return MSDOS.VAToOffset(0x10000010); });
    r.va2o_low = t(function() { return MSDOS.VAToOffset(0x100); });
    r.va2o_neg = t(function() { return MSDOS.VAToOffset(-1); });
    r.rva2o = t(function() { return MSDOS.RVAToOffset(0x10000000); });
    r.o2va_hdr = t(function() { return MSDOS.OffsetToVA(0x40); });
    r.o2va_seg = t(function() { return MSDOS.OffsetToVA(0x100); });
    r.o2va_zero = t(function() { return MSDOS.OffsetToVA(0); });
    r.o2va_big = t(function() { return MSDOS.OffsetToVA(0xFFFFFF); });
    r.o2va_neg = t(function() { return MSDOS.OffsetToVA(-1); });
    r.o2rva = t(function() { return MSDOS.OffsetToRVA(0x100); });
    r.disasm_seg = t(function() { return MSDOS.getDisasmNextAddress(0x10000000); });
    r.disasm_seg2 = t(function() { return MSDOS.getDisasmNextAddress(0x10000002); });
    r.disasm_jmp = t(function() { return MSDOS.getDisasmNextAddress(0x10000008); });
    r.disasm_low = t(function() { return MSDOS.getDisasmNextAddress(0x100); });
    r.disasm_neg = t(function() { return MSDOS.getDisasmNextAddress(-1); });
    r.aoep = t(function() { return MSDOS.getAddressOfEntryPoint(); });
    return JSON.stringify(r);
})()
)JS");
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);
    QTextStream err(stderr);

    QStringList args = app.arguments().mid(1);
    if (args.size() < 2) {
        err << "usage: msdos-oracle <db_dir> <file> [file...]\n";
        return 2;
    }

    const QString dbDir = args.takeFirst();

    QFile initFile(dbDir + "/MSDOS/_init");
    if (!initFile.open(QIODevice::ReadOnly)) {
        err << "cannot open " << initFile.fileName() << "\n";
        return 2;
    }
    const QString initSource = QString::fromUtf8(initFile.readAll());
    initFile.close();

    QJsonArray result;
    for (const QString &path : args) {
        if (!QFileInfo::exists(path)) {
            err << "missing: " << path << "\n";
            continue;
        }

        QFile device(path);
        if (!device.open(QIODevice::ReadOnly)) {
            err << "cannot open: " << path << "\n";
            continue;
        }

        XMSDOS msdos(&device);
        XBinary::PDSTRUCT pdStruct = {};
        Binary_Script::OPTIONS scanOptions = {};
        MSDOS_Script script(&msdos, XBinary::FILEPART_HEADER, scanOptions, &pdStruct);

        QJSEngine engine;
        // Keep C++ ownership: the script object is stack-allocated, so the
        // engine must not delete it during garbage collection/shutdown.
        engine.setObjectOwnership(&script, QJSEngine::CppOwnership);
        engine.globalObject().setProperty("MSDOS", engine.newQObject(&script));

        QJsonObject entry;
        entry["file"] = path;

        QJSValue initResult = engine.evaluate(initSource, "MSDOS/_init");
        if (initResult.isError()) {
            entry["init_error"] = initResult.toString();
        }

        QJSValue probe = engine.evaluate(probeScript(), "probe");
        if (probe.isError()) {
            entry["error"] = probe.toString();
        } else {
            QJsonDocument doc = QJsonDocument::fromJson(probe.toString().toUtf8());
            entry["r"] = doc.object();
        }

        result.append(entry);
        device.close();
    }

    out << QString::fromUtf8(QJsonDocument(result).toJson(QJsonDocument::Compact)) << "\n";
    return 0;
}
