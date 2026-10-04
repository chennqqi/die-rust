// Project-generated research harness for SCANSTRUCT enum/string contracts.
// It links the unmodified pinned engine and supplies only benign rules.

#include "die_script.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <cstdio>

namespace {

constexpr const char *UPSTREAM_COMMIT =
    "74eaf505c250ab47e709024e9dc41657cd8f2254";
constexpr const char *FORMATS_COMMIT =
    "1151e7254fdee3c0294ff7095edbdd7bfccf8201";
constexpr const char *XSCANENGINE_COMMIT =
    "dfe4a419e4f491bb23688ba03c5a5bf39e34da83";
constexpr const char *DIE_SCRIPT_COMMIT =
    "5d82316c110abf0eb863b50bc679d330e05067b6";
constexpr const char *INPUT_SHA256 =
    "1effe084564a199b007fbfdeb2cbe1095bd5b5e87303147a515fefcd3e1cb7b5";

QJsonObject serializeRecord(const XScanEngine::SCANSTRUCT &record)
{
    QJsonObject output;
    output.insert("raw_type", record.sType);
    output.insert("raw_name", record.sName);
    output.insert("type_value", static_cast<int>(record.type));
    output.insert(
        "type_canonical",
        XScanEngine::recordTypeIdToString(record.type)
    );
    output.insert("name_value", static_cast<int>(record.name));
    output.insert(
        "name_canonical",
        XScanEngine::recordNameIdToString(record.name)
    );
    output.insert("signature", record.varInfo);
    output.insert("unknown", record.bIsUnknown);
    return output;
}

QJsonObject runCase(
    const QString &id,
    const QString &fixtureRoot,
    const QString &inputPath,
    const QString &database,
    const QString &signature,
    bool heuristicScan
)
{
    XScanEngine::SCAN_OPTIONS options = {};
    options.sMainDatabasePath = fixtureRoot + "/" + database;
    options.sSignatureName = signature;
    options.bIsHeuristicScan = heuristicScan;
    options.bShowType = true;
    options.bShowVersion = true;
    options.bShowInfo = true;

    XBinary::PDSTRUCT loadState = XBinary::createPdStruct();
    DiE_Script engine;
    const bool loaded = engine.loadDatabase(&options, &loadState);
    XBinary::PDSTRUCT scanState = XBinary::createPdStruct();
    const XScanEngine::SCAN_RESULT result = engine.scanFile(
        inputPath,
        &options,
        &scanState
    );

    QJsonArray records;
    for (const XScanEngine::SCANSTRUCT &record : result.listRecords) {
        records.append(serializeRecord(record));
    }
    QJsonObject output;
    output.insert("id", id);
    output.insert("database", database);
    output.insert("signature", signature);
    output.insert("heuristic_scan", heuristicScan);
    output.insert("database_loaded", loaded);
    output.insert(
        "load_not_canceled",
        XBinary::isPdStructNotCanceled(&loadState)
    );
    output.insert(
        "scan_not_canceled",
        XBinary::isPdStructNotCanceled(&scanState)
    );
    output.insert("error_count", result.listErrors.size());
    output.insert("records", records);
    return output;
}

QJsonObject typeMapping(const QString &input)
{
    const XScanEngine::RECORD_TYPE value =
        XScanEngine::recordTypeStringToId(input);
    return {
        {"input", input},
        {"value", static_cast<int>(value)},
        {"canonical", XScanEngine::recordTypeIdToString(value)},
    };
}

QJsonObject nameMapping(const QString &input)
{
    const XScanEngine::RECORD_NAME value =
        XScanEngine::recordNameStringToId(input);
    return {
        {"input", input},
        {"value", static_cast<int>(value)},
        {"canonical", XScanEngine::recordNameIdToString(value)},
    };
}

}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    if (argc != 2) {
        std::fprintf(
            stderr,
            "usage: die-result-enums-harness <fixture-root>\n"
        );
        return 2;
    }

    const QString fixtureRoot = QString::fromLocal8Bit(argv[1]);
    const QString inputPath = fixtureRoot + "/input/probe.bin";
    QFile inputFile(inputPath);
    if (!inputFile.open(QIODevice::ReadOnly)) {
        std::fprintf(stderr, "cannot open fixture input\n");
        return 1;
    }
    const QByteArray input = inputFile.readAll();
    const QByteArray inputHash = QCryptographicHash::hash(
        input,
        QCryptographicHash::Sha256
    ).toHex();
    if (inputHash != QByteArray(INPUT_SHA256)) {
        std::fprintf(stderr, "fixture input hash mismatch\n");
        return 1;
    }

    QJsonArray cases;
    cases.append(runCase(
        "known_alias",
        fixtureRoot,
        inputPath,
        "main",
        "known_alias.1.sg",
        false
    ));
    cases.append(runCase(
        "heuristic_prefix",
        fixtureRoot,
        inputPath,
        "main",
        "HEUR.heuristic.2.sg",
        true
    ));
    cases.append(runCase(
        "custom_raw",
        fixtureRoot,
        inputPath,
        "main",
        "custom.3.sg",
        false
    ));
    cases.append(runCase(
        "unknown_fallback",
        fixtureRoot,
        inputPath,
        "empty-main",
        "",
        false
    ));

    QJsonArray typeMappings;
    for (const QString &value : {
             QString("PE Tool"),
             QString("pe-tool"),
             QString("PETOOL"),
             QString("~PE Tool"),
             QString("!pe-tool"),
         }) {
        typeMappings.append(typeMapping(value));
    }
    QJsonArray nameMappings;
    for (const QString &value : {
             QString("7-Zip"),
             QString("7 ZIP"),
             QString("7zip"),
         }) {
        nameMappings.append(nameMapping(value));
    }
    QJsonArray reservedAliases;
    const int firstReserved =
        static_cast<int>(XScanEngine::RECORD_NAME_UNKNOWN0);
    const int lastReserved =
        static_cast<int>(XScanEngine::RECORD_NAME_UNKNOWN9);
    for (int value = firstReserved; value <= lastReserved; value++) {
        const XScanEngine::RECORD_NAME name =
            static_cast<XScanEngine::RECORD_NAME>(value);
        QJsonObject alias;
        alias.insert("value", value);
        alias.insert(
            "canonical",
            XScanEngine::recordNameIdToString(name)
        );
        reservedAliases.append(alias);
    }

    const XScanEngine::RECORD_TYPE outOfRangeType =
        static_cast<XScanEngine::RECORD_TYPE>(
            static_cast<int>(XScanEngine::__RECORD_TYPE_SIZE) + 17
        );
    const XScanEngine::RECORD_NAME outOfRangeName =
        static_cast<XScanEngine::RECORD_NAME>(lastReserved + 17);
    QJsonObject fallbacks;
    fallbacks.insert(
        "unknown_type_input",
        typeMapping("not-a-record-type")
    );
    fallbacks.insert(
        "unknown_name_input",
        nameMapping("not-a-record-name")
    );
    fallbacks.insert(
        "reserved_alias_input",
        nameMapping("_Unknown")
    );
    fallbacks.insert("reserved_alias_first_value", firstReserved);
    fallbacks.insert("reserved_alias_last_value", lastReserved);
    fallbacks.insert(
        "out_of_range_type_value",
        static_cast<int>(outOfRangeType)
    );
    fallbacks.insert(
        "out_of_range_type_string",
        XScanEngine::recordTypeIdToString(outOfRangeType)
    );
    fallbacks.insert(
        "out_of_range_name_value",
        static_cast<int>(outOfRangeName)
    );
    fallbacks.insert(
        "out_of_range_name_string",
        XScanEngine::recordNameIdToString(outOfRangeName)
    );

    QJsonObject output;
    output.insert("schema_version", 1);
    output.insert("upstream_commit", UPSTREAM_COMMIT);
    output.insert("formats_commit", FORMATS_COMMIT);
    output.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    output.insert("die_script_commit", DIE_SCRIPT_COMMIT);
    output.insert("input_sha256", QString::fromLatin1(inputHash));
    output.insert("case_count", cases.size());
    output.insert("cases", cases);
    output.insert("type_mappings", typeMappings);
    output.insert("name_mappings", nameMappings);
    output.insert("reserved_name_aliases", reservedAliases);
    output.insert("fallbacks", fallbacks);
    std::printf(
        "%s",
        QJsonDocument(output).toJson(QJsonDocument::Indented).constData()
    );
    return 0;
}
