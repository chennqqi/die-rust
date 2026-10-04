// Project-generated research harness for pinned DIE database-layer behavior.
// It links the unmodified upstream engine and supplies only benign rules.

#include "die_script.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include <cstdio>

namespace {

constexpr const char *UPSTREAM_COMMIT =
    "74eaf505c250ab47e709024e9dc41657cd8f2254";
constexpr const char *XSCANENGINE_COMMIT =
    "dfe4a419e4f491bb23688ba03c5a5bf39e34da83";

QString databaseTypeName(XScanEngine::DT databaseType)
{
    switch (databaseType) {
        case XScanEngine::DT_MAIN:
            return "main";
        case XScanEngine::DT_EXTRA:
            return "extra";
        case XScanEngine::DT_CUSTOM:
            return "custom";
    }
    return "unknown";
}

XScanEngine::SCAN_OPTIONS makeOptions(
    const QString &fixtureRoot,
    bool useExtra,
    bool useCustom
)
{
    XScanEngine::SCAN_OPTIONS options = {};
    options.sMainDatabasePath = fixtureRoot + "/main";
    options.sExtraDatabasePath = fixtureRoot + "/extra";
    options.sCustomDatabasePath = fixtureRoot + "/custom";
    options.bUseExtraDatabase = useExtra;
    options.bUseCustomDatabase = useCustom;
    options.bUseCache = false;
    options.bShowType = true;
    options.bShowVersion = true;
    options.bShowInfo = true;
    return options;
}

QJsonArray serializeSignatures(DiE_Script *engine)
{
    QJsonArray result;
    const QList<XScanEngine::SIGNATURE_RECORD> *records =
        engine->getSignatures();
    if (records == nullptr) {
        return result;
    }
    for (const XScanEngine::SIGNATURE_RECORD &record : *records) {
        QJsonObject item;
        item.insert(
            "database_type",
            databaseTypeName(record.databaseType)
        );
        item.insert(
            "database_type_value",
            static_cast<qint32>(record.databaseType)
        );
        item.insert("name", record.sName);
        item.insert("file_path", record.sFilePath);
        item.insert(
            "file_type_value",
            static_cast<qint32>(record.fileType)
        );
        result.append(item);
    }
    return result;
}

QJsonObject observeLoad(
    const QString &id,
    const QString &fixtureRoot,
    bool useExtra,
    bool useCustom
)
{
    XScanEngine::SCAN_OPTIONS options = makeOptions(
        fixtureRoot,
        useExtra,
        useCustom
    );
    XBinary::PDSTRUCT state = XBinary::createPdStruct();
    DiE_Script engine;
    QJsonObject result;
    result.insert("id", id);
    result.insert("use_extra", useExtra);
    result.insert("use_custom", useCustom);
    result.insert("loaded", engine.loadDatabase(&options, &state));
    const QJsonArray records = serializeSignatures(&engine);
    result.insert("signature_count", records.size());
    result.insert("signatures", records);
    result.insert(
        "load_pd_not_canceled",
        XBinary::isPdStructNotCanceled(&state)
    );
    return result;
}

QJsonObject observeScan(
    DiE_Script *engine,
    const XScanEngine::SCAN_OPTIONS &loadedOptions,
    const QString &id,
    bool useExtra,
    bool useCustom,
    bool sortResults
)
{
    XScanEngine::SCAN_OPTIONS options = loadedOptions;
    options.bUseExtraDatabase = useExtra;
    options.bUseCustomDatabase = useCustom;
    options.bIsSort = sortResults;

    QByteArray input("die-rust deterministic database layer corpus\n");
    XBinary::PDSTRUCT state = XBinary::createPdStruct();
    const XScanEngine::SCAN_RESULT scanResult = engine->scanMemory(
        input.data(),
        input.size(),
        &options,
        &state
    );

    QJsonArray names;
    for (
        const XScanEngine::SCANSTRUCT &record :
        scanResult.listRecords
    ) {
        names.append(record.sName);
    }
    QJsonArray errors;
    for (
        const XScanEngine::ERROR_RECORD &record :
        scanResult.listErrors
    ) {
        QJsonObject item;
        item.insert("script", record.sScript);
        item.insert("message", record.sErrorString);
        errors.append(item);
    }

    QJsonObject result;
    result.insert("id", id);
    result.insert("use_extra", useExtra);
    result.insert("use_custom", useCustom);
    result.insert("sort_results", sortResults);
    result.insert("names", names);
    result.insert("errors", errors);
    result.insert(
        "scan_pd_not_canceled",
        XBinary::isPdStructNotCanceled(&state)
    );
    return result;
}

}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    QCoreApplication::setOrganizationName("NTInfo");
    QCoreApplication::setApplicationName("die");

    if (argc != 2) {
        std::fprintf(
            stderr,
            "usage: die-database-layers-harness <fixture-root>\n"
        );
        return 2;
    }

    const QString fixtureRoot = QString::fromLocal8Bit(argv[1]);
    QJsonArray loadCases;
    loadCases.append(observeLoad(
        "main_only",
        fixtureRoot,
        false,
        false
    ));
    loadCases.append(observeLoad(
        "main_extra",
        fixtureRoot,
        true,
        false
    ));
    loadCases.append(observeLoad(
        "main_custom",
        fixtureRoot,
        false,
        true
    ));
    loadCases.append(observeLoad(
        "all_layers",
        fixtureRoot,
        true,
        true
    ));

    XScanEngine::SCAN_OPTIONS loadedOptions = makeOptions(
        fixtureRoot,
        true,
        true
    );
    XBinary::PDSTRUCT loadState = XBinary::createPdStruct();
    DiE_Script engine;
    const bool loadedAll = engine.loadDatabase(
        &loadedOptions,
        &loadState
    );

    QJsonArray scanCases;
    scanCases.append(observeScan(
        &engine,
        loadedOptions,
        "all_unsorted",
        true,
        true,
        false
    ));
    scanCases.append(observeScan(
        &engine,
        loadedOptions,
        "main_only_unsorted",
        false,
        false,
        false
    ));
    scanCases.append(observeScan(
        &engine,
        loadedOptions,
        "main_extra_unsorted",
        true,
        false,
        false
    ));
    scanCases.append(observeScan(
        &engine,
        loadedOptions,
        "main_custom_unsorted",
        false,
        true,
        false
    ));
    scanCases.append(observeScan(
        &engine,
        loadedOptions,
        "all_sorted",
        true,
        true,
        true
    ));

    QJsonObject output;
    output.insert("schema_version", 1);
    output.insert("upstream_commit", UPSTREAM_COMMIT);
    output.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    output.insert("fixture_root", fixtureRoot);
    output.insert("loaded_all", loadedAll);
    output.insert(
        "load_pd_not_canceled",
        XBinary::isPdStructNotCanceled(&loadState)
    );
    output.insert(
        "all_loaded_signatures",
        serializeSignatures(&engine)
    );
    output.insert("load_cases", loadCases);
    output.insert("scan_cases", scanCases);

    const QByteArray serialized =
        QJsonDocument(output).toJson(QJsonDocument::Indented);
    if (
        std::fwrite(
            serialized.constData(),
            1,
            static_cast<size_t>(serialized.size()),
            stdout
        ) != static_cast<size_t>(serialized.size())
    ) {
        return 1;
    }
    return 0;
}
