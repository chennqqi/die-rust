// Project-generated research harness for a fixed DEX rule and real XDEX
// context. It evaluates the byte-identical upstream rule with QScriptEngine.

#include "dex_script.h"
#include "xdex.h"

#include <QBuffer>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QScriptEngine>
#include <QScriptValue>
#include <QString>

#include <cstdio>

namespace {

constexpr const char *UPSTREAM_COMMIT =
    "74eaf505c250ab47e709024e9dc41657cd8f2254";
constexpr const char *XDEX_COMMIT =
    "035c61966d3a9018edf80cd0013083ee32626e71";
constexpr const char *XSCANENGINE_COMMIT =
    "dfe4a419e4f491bb23688ba03c5a5bf39e34da83";
constexpr const char *RULES_COMMIT =
    "c2c17dfa5ea4e078ba31eab55d87430c96622fb6";
constexpr const char *RULE_PATH =
    "/opt/die-source/Detect-It-Easy/db/DEX/protector_QDBH.2.sg";
constexpr const char *RULE_SHA256 =
    "5280ae0425f47c03ca037002b29964fe59eb898e871a00ad266475856f0e7ba7";

constexpr const char *RESULT_SHIM = R"JS(
var __detections = [];
var bDetected, sType, sName, sVersion, sOptions, sLang, sLangVersion;

function meta(type, name, version, options, lang, langVersion) {
    sType = type;
    sName = name ? name : String();
    sVersion = version ? version : String();
    sOptions = options ? options : String();
    sLang = lang ? lang : String();
    sLangVersion = langVersion ? langVersion : String();
    bDetected = false;
}

function _setResult(type, name, version, options) {
    __detections.push([
        String(type),
        String(name),
        String(version),
        String(options)
    ]);
}

function _setLang() {}
function _error(message) { throw new Error(String(message)); }

function result() {
    if (bDetected) {
        sVersion = sVersion ? sVersion : String();
        sOptions = sOptions ? sOptions : String();
        if (!sName) _error("No input detection name.");
        _setResult(sType, sName, sVersion, sOptions);
    }
    sName = sVersion = sOptions = sLang = sLangVersion = "";
    var value = bDetected;
    bDetected = false;
    return value;
}
)JS";

QJsonObject scriptError(
    const QString &stage,
    const QScriptValue &value,
    QScriptEngine *engine
)
{
    QJsonArray backtrace;
    for (const QString &line : engine->uncaughtExceptionBacktrace()) {
        backtrace.append(line);
    }
    QJsonObject output;
    output.insert("stage", stage);
    output.insert("name", value.property("name").toString());
    output.insert("message", value.property("message").toString());
    output.insert("line", value.property("lineNumber").toInt32());
    output.insert("backtrace", backtrace);
    return output;
}

QJsonObject runCase(
    const QJsonObject &input,
    const QByteArray &rule,
    QString *error
)
{
    const QString id = input.value("id").toString();
    const QByteArray dataHex =
        input.value("data_hex").toString().toLatin1();
    const QByteArray data = QByteArray::fromHex(dataHex);
    const QByteArray expectedDataHash =
        input.value("data_sha256").toString().toLatin1();
    const QByteArray actualDataHash =
        QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex();
    if (id.isEmpty() || dataHex.size() != data.size() * 2) {
        *error = "invalid DEX fixture case";
        return {};
    }
    if (actualDataHash != expectedDataHash) {
        *error = QString("fixture hash mismatch: %1").arg(id);
        return {};
    }

    QByteArray mutableData = data;
    QBuffer buffer(&mutableData);
    buffer.setProperty("FileName", id);
    if (!buffer.open(QIODevice::ReadOnly)) {
        *error = QString("cannot open DEX fixture: %1").arg(id);
        return {};
    }

    XDEX dex(&buffer);
    const bool parserValid = dex.isValid();
    XBinary::PDSTRUCT state = XBinary::createPdStruct();
    QList<XDEX_DEF::MAP_ITEM> mapItems = dex.getMapItems(&state);
    QList<QString> strings = dex.getStrings(&mapItems, &state);
    Binary_Script::OPTIONS options = {};
    DEX_Script script(&dex, XBinary::FILEPART_HEADER, options, &state);

    QScriptEngine engine;
    QScriptValue object = engine.newQObject(&script);
    engine.globalObject().setProperty("DEX", object);

    QJsonArray parsedStrings;
    for (const QString &string : strings) {
        parsedStrings.append(string);
    }
    QJsonObject output;
    output.insert("id", id);
    output.insert("data_hex", QString::fromLatin1(dataHex));
    output.insert("data_sha256", QString::fromLatin1(actualDataHash));
    output.insert("parser_valid", parserValid);
    output.insert("map_item_count", mapItems.size());
    output.insert("parsed_strings", parsedStrings);
    output.insert(
        "native_qdbh_present",
        script.isDexStringPresent(QStringLiteral("/qdbh"))
    );

    QScriptValue shimValue =
        engine.evaluate(QString::fromUtf8(RESULT_SHIM), "result-shim.js");
    if (shimValue.isError()) {
        output.insert("error", scriptError("shim", shimValue, &engine));
        *error = QString("result shim failed: %1").arg(id);
        return output;
    }
    QScriptValue ruleValue =
        engine.evaluate(QString::fromUtf8(rule), RULE_PATH);
    if (ruleValue.isError()) {
        output.insert("error", scriptError("rule", ruleValue, &engine));
        *error = QString("fixed rule evaluation failed: %1").arg(id);
        return output;
    }
    QScriptValue detectValue = engine.evaluate(
        "typeof detect === 'function' ? detect() : undefined",
        "invoke-detect.js"
    );
    if (detectValue.isError()) {
        output.insert("error", scriptError("detect", detectValue, &engine));
        *error = QString("fixed rule detect failed: %1").arg(id);
        return output;
    }
    QScriptValue detectionsValue =
        engine.evaluate("JSON.stringify(__detections)", "detections.js");
    QJsonParseError parseError = {};
    const QJsonDocument detections = QJsonDocument::fromJson(
        detectionsValue.toString().toUtf8(),
        &parseError
    );
    if (
        detectionsValue.isError() ||
        parseError.error != QJsonParseError::NoError ||
        !detections.isArray()
    ) {
        *error = QString("cannot serialize detections: %1").arg(id);
        return output;
    }
    output.insert("detect_is_boolean", detectValue.isBool());
    output.insert("detect_result", detectValue.toBool());
    output.insert("detections", detections.array());
    output.insert(
        "dex_script_error",
        XBinary::getPdStructErrorString(&state)
    );
    return output;
}

}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    if (argc != 2) {
        std::fprintf(stderr, "usage: die-dex-rule-harness <fixture.json>\n");
        return 2;
    }

    QFile fixtureFile(QString::fromLocal8Bit(argv[1]));
    QFile ruleFile(QString::fromLatin1(RULE_PATH));
    if (
        !fixtureFile.open(QIODevice::ReadOnly) ||
        !ruleFile.open(QIODevice::ReadOnly)
    ) {
        std::fprintf(stderr, "cannot open fixture or fixed rule\n");
        return 2;
    }
    QJsonParseError parseError = {};
    const QJsonDocument fixture =
        QJsonDocument::fromJson(fixtureFile.readAll(), &parseError);
    const QByteArray rule = ruleFile.readAll();
    const QByteArray ruleHash =
        QCryptographicHash::hash(rule, QCryptographicHash::Sha256).toHex();
    if (
        parseError.error != QJsonParseError::NoError ||
        !fixture.isObject() ||
        ruleHash != QByteArray(RULE_SHA256)
    ) {
        std::fprintf(stderr, "invalid fixture or fixed rule hash\n");
        return 2;
    }

    const QJsonArray inputCases = fixture.object().value("cases").toArray();
    if (inputCases.isEmpty()) {
        std::fprintf(stderr, "fixture case list is empty\n");
        return 2;
    }
    QJsonArray outputCases;
    for (const QJsonValue &value : inputCases) {
        if (!value.isObject()) {
            std::fprintf(stderr, "fixture case is not an object\n");
            return 2;
        }
        QString error;
        const QJsonObject output = runCase(value.toObject(), rule, &error);
        outputCases.append(output);
        if (!error.isEmpty()) {
            std::fprintf(stderr, "%s\n", error.toUtf8().constData());
            return 2;
        }
    }

    QJsonObject output;
    output.insert("schema_version", 1);
    output.insert("upstream_commit", UPSTREAM_COMMIT);
    output.insert("xdex_commit", XDEX_COMMIT);
    output.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    output.insert("rules_commit", RULES_COMMIT);
    output.insert("qt_version", qVersion());
    output.insert("engine", "QScriptEngine");
    output.insert("rule_path", RULE_PATH);
    output.insert("rule_sha256", RULE_SHA256);
    output.insert("case_count", outputCases.size());
    output.insert("cases", outputCases);
    const QByteArray json =
        QJsonDocument(output).toJson(QJsonDocument::Indented);
    std::fwrite(json.constData(), 1, static_cast<size_t>(json.size()), stdout);
    return 0;
}
