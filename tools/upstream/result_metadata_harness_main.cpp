// Project-generated research harness for SCAN_RESULT scalar metadata.
// It links the unmodified pinned engine and scans identical bytes through
// the four public entry points.

#include "die_script.h"

#include <QBuffer>
#include <QCoreApplication>
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
constexpr const char *FILE_PATH = "/tmp/die-result-metadata-input.exe";
constexpr const char *DEVICE_NAME = "named-device.exe";

QByteArray makeInput()
{
    QByteArray input(0x80, '\0');
    input[0] = 'M';
    input[1] = 'Z';
    input[2] = static_cast<char>(0x80);
    input[4] = 1;
    input[8] = 4;
    input[0x40] = static_cast<char>(0x90);
    input[0x41] = static_cast<char>(0xcd);
    input[0x42] = 0x20;
    return input;
}

XScanEngine::SCAN_OPTIONS makeOptions()
{
    XScanEngine::SCAN_OPTIONS options = {};
    options.bShowType = true;
    options.bShowInfo = true;
    options.bShowVersion = true;
    return options;
}

QJsonObject serialize(
    const QString &id,
    const XScanEngine::SCAN_RESULT &result,
    XBinary::PDSTRUCT &state
)
{
    QJsonObject output;
    output.insert("id", id);
    output.insert("nScanTime", result.nScanTime);
    output.insert("sFileName", result.sFileName);
    output.insert("nSize", result.nSize);
    output.insert("ftInit", static_cast<int>(result.ftInit));
    output.insert(
        "ftInit_string",
        XBinary::fileTypeIdToString(result.ftInit)
    );
    output.insert("record_count", result.listRecords.size());
    output.insert("error_count", result.listErrors.size());
    output.insert("scan_success", XBinary::isPdStructSuccess(&state));
    return output;
}

QJsonObject scanFile(DiE_Script *engine, const QByteArray &input)
{
    QFile file(FILE_PATH);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return {{"id", "file"}, {"harness_error", "cannot create file"}};
    }
    if (file.write(input) != input.size()) {
        return {{"id", "file"}, {"harness_error", "cannot write file"}};
    }
    file.close();

    XScanEngine::SCAN_OPTIONS options = makeOptions();
    XBinary::PDSTRUCT state = XBinary::createPdStruct();
    return serialize(
        "file",
        engine->scanFile(FILE_PATH, &options, &state),
        state
    );
}

QJsonObject scanMemory(DiE_Script *engine, QByteArray *input)
{
    XScanEngine::SCAN_OPTIONS options = makeOptions();
    XBinary::PDSTRUCT state = XBinary::createPdStruct();
    return serialize(
        "memory",
        engine->scanMemory(input->data(), input->size(), &options, &state),
        state
    );
}

QJsonObject scanDevice(DiE_Script *engine, QByteArray *input)
{
    QBuffer buffer(input);
    buffer.setProperty("FileName", DEVICE_NAME);
    if (!buffer.open(QIODevice::ReadOnly)) {
        return {
            {"id", "device"},
            {"harness_error", "cannot open device buffer"},
        };
    }
    XScanEngine::SCAN_OPTIONS options = makeOptions();
    XBinary::PDSTRUCT state = XBinary::createPdStruct();
    return serialize(
        "device",
        engine->scanDevice(&buffer, &options, &state),
        state
    );
}

QJsonObject scanSubdevice(DiE_Script *engine, const QByteArray &input)
{
    const QByteArray prefix = QByteArray::fromHex("aabbccdd");
    const QByteArray suffix = QByteArray::fromHex("eeff");
    QByteArray container = prefix + input + suffix;
    QBuffer buffer(&container);
    buffer.setProperty("FileName", "parent-container.bin");
    if (!buffer.open(QIODevice::ReadOnly)) {
        return {
            {"id", "subdevice"},
            {"harness_error", "cannot open parent buffer"},
        };
    }
    XScanEngine::SCAN_OPTIONS options = makeOptions();
    XBinary::PDSTRUCT state = XBinary::createPdStruct();
    return serialize(
        "subdevice",
        engine->scanSubdevice(
            &buffer,
            prefix.size(),
            input.size(),
            &options,
            &state
        ),
        state
    );
}

}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    Q_UNUSED(application)

    QByteArray input = makeInput();
    DiE_Script engine;
    QJsonArray cases;
    cases.append(scanFile(&engine, input));
    cases.append(scanMemory(&engine, &input));
    cases.append(scanDevice(&engine, &input));
    cases.append(scanSubdevice(&engine, input));

    QJsonObject output;
    output.insert("schema_version", 1);
    output.insert("upstream_commit", UPSTREAM_COMMIT);
    output.insert("formats_commit", FORMATS_COMMIT);
    output.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    output.insert("input_size", input.size());
    output.insert("input_hex", QString(input.toHex()));
    output.insert("file_path", FILE_PATH);
    output.insert("device_name", DEVICE_NAME);
    output.insert("case_count", cases.size());
    output.insert("cases", cases);
    std::printf(
        "%s",
        QJsonDocument(output).toJson(QJsonDocument::Indented).constData()
    );
    return 0;
}
