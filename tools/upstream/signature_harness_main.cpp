// Project-generated research harness for the pinned XBinary signature API.
// It does not modify upstream parsing or matching behavior.

#include "xbinary.h"
#include "xamigahunk.h"
#include "xcom.h"
#include "xelf.h"
#include "xmach.h"
#include "xmsdos.h"
#include "xpe.h"
#include "binary_script.h"

#include <QBuffer>
#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include <cstdio>
#include <cstring>
#include <memory>
#include <new>

namespace {

constexpr const char *UPSTREAM_COMMIT =
    "74eaf505c250ab47e709024e9dc41657cd8f2254";
constexpr const char *FORMATS_COMMIT =
    "1151e7254fdee3c0294ff7095edbdd7bfccf8201";
constexpr const char *XSCANENGINE_COMMIT =
    "dfe4a419e4f491bb23688ba03c5a5bf39e34da83";

qint64 jsonInteger(
    const QJsonObject &object,
    const QString &name,
    qint64 defaultValue
)
{
    QJsonValue value = object.value(name);
    if (value.isUndefined()) {
        return defaultValue;
    }
    return static_cast<qint64>(value.toDouble());
}

bool isHexData(const QByteArray &text)
{
    if ((text.size() % 2) != 0) {
        return false;
    }
    for (char character : text) {
        bool digit = (character >= '0') && (character <= '9');
        bool lower = (character >= 'a') && (character <= 'f');
        bool upper = (character >= 'A') && (character <= 'F');
        if (!(digit || lower || upper)) {
            return false;
        }
    }
    return true;
}

QString fileTypeName(XBinary::FT fileType)
{
    if (fileType == XBinary::FT_PE ||
        fileType == XBinary::FT_PE32 ||
        fileType == XBinary::FT_PE64) {
        return "pe";
    }
    if (fileType == XBinary::FT_ELF ||
        fileType == XBinary::FT_ELF32 ||
        fileType == XBinary::FT_ELF64) {
        return "elf";
    }
    if (fileType == XBinary::FT_MACHO ||
        fileType == XBinary::FT_MACHO32 ||
        fileType == XBinary::FT_MACHO64) {
        return "macho";
    }
    if (fileType == XBinary::FT_COM) {
        return "com";
    }
    if (fileType == XBinary::FT_MSDOS) {
        return "msdos";
    }
    if (fileType == XBinary::FT_AMIGAHUNK) {
        return "amigahunk";
    }
    return QString("unknown:%1").arg(static_cast<int>(fileType));
}

QString endianName(XBinary::ENDIAN endian)
{
    if (endian == XBinary::ENDIAN_LITTLE) {
        return "little";
    }
    if (endian == XBinary::ENDIAN_BIG) {
        return "big";
    }
    return "unknown";
}

QString unicodeTypeName(XBinary::UNICODE_TYPE unicodeType)
{
    if (unicodeType == XBinary::UNICODE_TYPE_LE) {
        return "little";
    }
    if (unicodeType == XBinary::UNICODE_TYPE_BE) {
        return "big";
    }
    return "none";
}

QJsonObject serializeMemoryMap(const XBinary::_MEMORY_MAP &memoryMap)
{
    QJsonArray records;
    for (const XBinary::_MEMORY_RECORD &record : memoryMap.listRecords) {
        QJsonObject output;
        output.insert("offset", QString::number(record.nOffset));
        output.insert(
            "address",
            QString::number(static_cast<qulonglong>(record.nAddress))
        );
        output.insert("size", QString::number(record.nSize));
        output.insert("virtual", record.bIsVirtual);
        records.append(output);
    }

    QJsonObject output;
    output.insert("file_type", fileTypeName(memoryMap.fileType));
    output.insert("endian", endianName(memoryMap.endian));
    output.insert(
        "module_address",
        QString::number(
            static_cast<qulonglong>(memoryMap.nModuleAddress)
        )
    );
    output.insert("binary_size", QString::number(memoryMap.nBinarySize));
    output.insert("image_size", QString::number(memoryMap.nImageSize));
    output.insert("code_base", QString::number(memoryMap.nCodeBase));
    output.insert(
        "start_load_offset",
        QString::number(memoryMap.nStartLoadOffset)
    );
    output.insert("records", records);
    return output;
}

bool deriveFormatMemoryMap(
    QBuffer *buffer,
    const QString &formatParser,
    XBinary::_MEMORY_MAP *memoryMap,
    bool *formatValid,
    QString *error
)
{
    if (formatParser == "pe") {
        XPE format(buffer);
        *formatValid = format.isValid();
        *memoryMap = format.getMemoryMap();
        return true;
    }
    if (formatParser == "elf") {
        XELF format(buffer);
        *formatValid = format.isValid();
        *memoryMap = format.getMemoryMap();
        return true;
    }
    if (formatParser == "macho") {
        XMACH format(buffer);
        *formatValid = format.isValid();
        *memoryMap = format.getMemoryMap();
        return true;
    }
    if (formatParser == "com") {
        XCOM format(buffer);
        *formatValid = format.isValid();
        *memoryMap = format.getMemoryMap();
        return true;
    }
    if (formatParser == "msdos") {
        XMSDOS format(buffer);
        *formatValid = format.isValid();
        *memoryMap = format.getMemoryMap();
        return true;
    }
    if (formatParser == "amigahunk") {
        XAmigaHunk format(buffer);
        *formatValid = format.isValid();
        *memoryMap = format.getMemoryMap();
        return true;
    }
    *error = QString("unsupported format_parser: %1").arg(formatParser);
    return false;
}

bool configureMemoryMap(
    const QJsonObject &input,
    qint64 dataSize,
    XBinary::_MEMORY_MAP *memoryMap,
    QString *error
)
{
    if (!input.contains("memory_map")) {
        return true;
    }

    QJsonObject object = input.value("memory_map").toObject();
    QString fileType = object.value("file_type").toString();
    if (fileType == "binary") {
        memoryMap->fileType = XBinary::FT_BINARY;
    } else if (fileType == "pe") {
        memoryMap->fileType = XBinary::FT_PE;
    } else if (fileType == "elf") {
        memoryMap->fileType = XBinary::FT_ELF;
    } else if (fileType == "macho") {
        memoryMap->fileType = XBinary::FT_MACHO;
    } else if (fileType == "com") {
        memoryMap->fileType = XBinary::FT_COM;
    } else if (fileType == "msdos") {
        memoryMap->fileType = XBinary::FT_MSDOS;
    } else if (fileType == "amigahunk") {
        memoryMap->fileType = XBinary::FT_AMIGAHUNK;
    } else {
        *error = QString("unsupported memory_map file_type: %1").arg(fileType);
        return false;
    }

    QString endian = object.value("endian").toString();
    if (endian == "little") {
        memoryMap->endian = XBinary::ENDIAN_LITTLE;
    } else if (endian == "big") {
        memoryMap->endian = XBinary::ENDIAN_BIG;
    } else {
        *error = QString("unsupported memory_map endian: %1").arg(endian);
        return false;
    }

    memoryMap->nModuleAddress = static_cast<XADDR>(
        jsonInteger(object, "module_address", 0)
    );
    memoryMap->nCodeBase = jsonInteger(object, "code_base", 0);
    memoryMap->nStartLoadOffset =
        jsonInteger(object, "start_load_offset", 0);
    memoryMap->nBinarySize = dataSize;
    memoryMap->nImageSize = dataSize;
    memoryMap->listRecords.clear();

    QJsonArray records = object.value("records").toArray();
    if (records.isEmpty()) {
        *error = "memory_map records are empty";
        return false;
    }
    for (const QJsonValue &value : records) {
        if (!value.isObject()) {
            *error = "memory_map record is not an object";
            return false;
        }
        QJsonObject source = value.toObject();
        XBinary::_MEMORY_RECORD record = {};
        record.nOffset = jsonInteger(source, "offset", -1);
        record.nAddress = static_cast<XADDR>(
            jsonInteger(source, "address", -1)
        );
        record.nSize = jsonInteger(source, "size", 0);
        if (record.nOffset < 0 || record.nSize <= 0) {
            *error = "memory_map record has invalid offset or size";
            return false;
        }
        memoryMap->listRecords.append(record);
    }
    return true;
}

QJsonObject runCase(const QJsonObject &input, QString *error)
{
    QJsonObject result;
    QString id = input.value("id").toString();
    QString pattern = input.value("pattern").toString();
    QByteArray dataHex = input.value("data_hex").toString().toLatin1();

    if (id.isEmpty()) {
        *error = "case id is empty";
        return result;
    }
    if (!isHexData(dataHex)) {
        *error = QString("invalid data_hex for %1").arg(id);
        return result;
    }

    QByteArray data = QByteArray::fromHex(dataHex);
    QBuffer buffer(&data);
    if (input.contains("file_name")) {
        buffer.setProperty(
            "FileName",
            input.value("file_name").toString()
        );
    }
    if (!buffer.open(QIODevice::ReadOnly)) {
        *error = QString("cannot open input buffer for %1").arg(id);
        return result;
    }

    XBinary binary(&buffer);
    XBinary::_MEMORY_MAP memoryMap = binary.getMemoryMap();
    QString formatParser = input.value("format_parser").toString();
    bool formatValid = false;
    if (!formatParser.isEmpty()) {
        if (!deriveFormatMemoryMap(
                &buffer,
                formatParser,
                &memoryMap,
                &formatValid,
                error
            )) {
            return result;
        }
    } else {
        if (!configureMemoryMap(input, data.size(), &memoryMap, error)) {
            return result;
        }
    }
    qint64 offset = jsonInteger(input, "offset", 0);
    qint64 findOffset = jsonInteger(input, "find_offset", 0);
    qint64 findSize =
        jsonInteger(input, "find_size", data.size() - findOffset);

    XBinary::PDSTRUCT validState = XBinary::createPdStruct();
    bool valid = XBinary::isSignatureValid(pattern, &validState);

    XBinary::PDSTRUCT compareState = XBinary::createPdStruct();
    bool compare =
        binary.compareSignature(&memoryMap, pattern, offset, &compareState);

    qint64 findResultSize = 0;
    XBinary::PDSTRUCT findState = XBinary::createPdStruct();
    qint64 findOffsetResult = binary.find_signature(
        &memoryMap,
        findOffset,
        findSize,
        pattern,
        &findResultSize,
        &findState
    );

    QString converted = XBinary::convertSignature(pattern);
    result.insert("id", id);
    result.insert("pattern", pattern);
    result.insert("data_hex", QString::fromLatin1(data.toHex()));
    result.insert("converted", converted);
    result.insert(
        "converted_utf8_hex",
        QString::fromLatin1(converted.toUtf8().toHex())
    );
    result.insert("valid", valid);
    result.insert(
        "valid_error",
        XBinary::getPdStructErrorString(&validState)
    );
    result.insert("offset", offset);
    result.insert("compare", compare);
    result.insert(
        "compare_error",
        XBinary::getPdStructErrorString(&compareState)
    );
    result.insert("find_offset", findOffsetResult);
    result.insert("find_result_size", findResultSize);
    result.insert("search_offset", findOffset);
    result.insert("search_size", findSize);
    result.insert(
        "find_error",
        XBinary::getPdStructErrorString(&findState)
    );
    if (input.contains("file_name")) {
        result.insert("file_name", input.value("file_name"));
    }
    if (input.contains("binary_script_scan_id")) {
        result.insert(
            "binary_script_scan_id",
            input.value("binary_script_scan_id")
        );
    }

    bool invokeScriptCompare =
        input.value("binary_script_compare").toBool();
    bool invokeScriptCompareEp =
        input.value("binary_script_compare_ep").toBool();
    bool invokeScriptCompareOverlay =
        input.value("binary_script_compare_overlay").toBool();
    bool invokeScriptFindSignature =
        input.value("binary_script_find_signature").toBool();
    bool invokeScriptFSig =
        input.value("binary_script_f_sig").toBool();
    bool invokeScriptIsSignaturePresent =
        input.value("binary_script_is_signature_present").toBool();
    bool invokeScriptOverlayInfo =
        input.value("binary_script_overlay_info").toBool();
    bool invokeScriptStringInfo =
        input.value("binary_script_string_info").toBool();
    bool invokeScriptContextInfo =
        input.value("binary_script_context_info").toBool();
    if (
        invokeScriptCompare ||
        invokeScriptCompareEp ||
        invokeScriptCompareOverlay ||
        invokeScriptFindSignature ||
        invokeScriptFSig ||
        invokeScriptIsSignaturePresent ||
        invokeScriptOverlayInfo ||
        invokeScriptStringInfo ||
        invokeScriptContextInfo
    ) {
        std::unique_ptr<XBinary> parsedBinary;
        XBinary *scriptBinary = &binary;
        QString scriptParser =
            input.value("binary_script_parser").toString();
        if (scriptParser == "pe") {
            parsedBinary = std::make_unique<XPE>(&buffer);
            scriptBinary = parsedBinary.get();
        } else if (!scriptParser.isEmpty()) {
            *error = QString(
                "unsupported binary_script_parser: %1"
            ).arg(scriptParser);
            return result;
        }

        Binary_Script::OPTIONS options = {};
        options.sScanID =
            input.value("binary_script_scan_id").toString();
        XBinary::PDSTRUCT scriptState = XBinary::createPdStruct();
        QString scriptFilePartName =
            input.value("binary_script_file_part").toString("header");
        XBinary::FILEPART scriptFilePart = XBinary::FILEPART_HEADER;
        if (scriptFilePartName == "overlay") {
            scriptFilePart = XBinary::FILEPART_OVERLAY;
        } else if (scriptFilePartName == "resource") {
            scriptFilePart = XBinary::FILEPART_RESOURCE;
        } else if (scriptFilePartName == "debugdata") {
            scriptFilePart = XBinary::FILEPART_DEBUGDATA;
        } else if (scriptFilePartName != "header") {
            *error = QString(
                "unsupported binary_script_file_part: %1"
            ).arg(scriptFilePartName);
            return result;
        }
        Binary_Script script(
            scriptBinary,
            scriptFilePart,
            options,
            &scriptState
        );
        XBinary::_MEMORY_MAP scriptMemoryMap =
            scriptBinary->getMemoryMap();

        if (!scriptParser.isEmpty()) {
            result.insert("binary_script_parser", scriptParser);
            result.insert(
                "binary_script_parser_valid",
                scriptBinary->isValid()
            );
        }
        if (invokeScriptCompare) {
            result.insert("binary_script_compare", true);
            result.insert(
                "binary_script_compare_result",
                script.compare(pattern, offset)
            );
        }
        if (invokeScriptCompareEp) {
            result.insert("binary_script_compare_ep", true);
            result.insert(
                "binary_script_entry_point_offset",
                scriptBinary->getEntryPointOffset(&scriptMemoryMap)
            );
            result.insert(
                "binary_compare_ep_result",
                scriptBinary->compareEntryPoint(
                    &scriptMemoryMap,
                    converted,
                    offset
                )
            );
            result.insert(
                "binary_script_compare_ep_result",
                script.compareEP(pattern, offset)
            );
        }
        if (invokeScriptCompareOverlay) {
            XBinary::PDSTRUCT overlayCompareState =
                XBinary::createPdStruct();
            result.insert("binary_script_compare_overlay", true);
            result.insert(
                "binary_script_overlay_offset",
                scriptBinary->getOverlayOffset(
                    &scriptMemoryMap,
                    &scriptState
                )
            );
            result.insert(
                "binary_script_overlay_size",
                scriptBinary->getOverlaySize(
                    &scriptMemoryMap,
                    &scriptState
                )
            );
            result.insert(
                "binary_compare_overlay_result",
                scriptBinary->compareOverlay(
                    &scriptMemoryMap,
                    converted,
                    offset,
                    &overlayCompareState
                )
            );
            result.insert(
                "binary_compare_overlay_error",
                XBinary::getPdStructErrorString(&overlayCompareState)
            );
            result.insert(
                "binary_script_compare_overlay_result",
                script.compareOverlay(pattern, offset)
            );
        }
        if (invokeScriptFindSignature) {
            result.insert("binary_script_find_signature", true);
            result.insert(
                "binary_script_find_signature_result",
                script.findSignature(findOffset, findSize, pattern)
            );
        }
        if (invokeScriptFSig) {
            result.insert("binary_script_f_sig", true);
            result.insert(
                "binary_script_f_sig_result",
                script.fSig(findOffset, findSize, pattern)
            );
        }
        if (invokeScriptIsSignaturePresent) {
            result.insert("binary_script_is_signature_present", true);
            result.insert(
                "binary_script_is_signature_present_result",
                script.isSignaturePresent(findOffset, findSize, pattern)
            );
        }
        if (invokeScriptOverlayInfo) {
            result.insert("binary_script_overlay_info", true);
            result.insert(
                "binary_script_file_part",
                scriptFilePartName
            );
            result.insert(
                "binary_script_get_overlay_offset_result",
                script.getOverlayOffset()
            );
            result.insert(
                "binary_script_get_overlay_size_result",
                script.getOverlaySize()
            );
            result.insert(
                "binary_script_is_overlay_present_result",
                script.isOverlayPresent()
            );
            result.insert(
                "binary_script_is_overlay_result",
                script.isOverlay()
            );
        }
        if (invokeScriptStringInfo) {
            QString headerString = script.getHeaderString();
            result.insert("binary_script_string_info", true);
            result.insert(
                "binary_script_get_file_suffix_result",
                script.getFileSuffix()
            );
            result.insert(
                "binary_script_get_header_string_result",
                headerString
            );
            result.insert(
                "binary_script_get_header_string_utf8_hex",
                QString::fromLatin1(headerString.toUtf8().toHex())
            );
            result.insert(
                "binary_script_is_plain_text_result",
                script.isPlainText()
            );
            result.insert(
                "binary_script_is_utf8_text_result",
                script.isUTF8Text()
            );
            result.insert(
                "x_binary_unicode_type_result",
                unicodeTypeName(scriptBinary->getUnicodeType())
            );
        }
        if (invokeScriptContextInfo) {
            result.insert("binary_script_context_info", true);
            result.insert(
                "binary_script_file_part",
                scriptFilePartName
            );
            result.insert(
                "binary_script_get_scan_id_result",
                script.getScanID()
            );
            result.insert(
                "binary_script_is_resource_result",
                script.isResource()
            );
            result.insert(
                "binary_script_is_debug_data_result",
                script.isDebugData()
            );
            result.insert(
                "binary_script_is_file_part_result",
                script.isFilePart()
            );

            QString prefill =
                input.value("binary_script_prefill").toString();
            if (!prefill.isEmpty()) {
                int fill = 0;
                if (prefill == "zero") {
                    fill = 0x00;
                } else if (prefill == "one") {
                    fill = 0x01;
                } else {
                    *error = QString(
                        "unsupported binary_script_prefill: %1"
                    ).arg(prefill);
                    return result;
                }
                alignas(Binary_Script)
                    unsigned char storage[sizeof(Binary_Script)];
                std::memset(storage, fill, sizeof(storage));
                Binary_Script *prefilledScript =
                    new (storage) Binary_Script(
                        scriptBinary,
                        scriptFilePart,
                        options,
                        &scriptState
                    );
                result.insert("binary_script_prefill", prefill);
                result.insert(
                    "binary_script_prefill_is_plain_text_result",
                    prefilledScript->isPlainText()
                );
                result.insert(
                    "binary_script_prefill_is_utf8_text_result",
                    prefilledScript->isUTF8Text()
                );
                result.insert(
                    "binary_script_prefill_is_unicode_text_result",
                    prefilledScript->isUnicodeText()
                );
                result.insert(
                    "binary_script_prefill_is_text_result",
                    prefilledScript->isText()
                );
                prefilledScript->~Binary_Script();
            }
        }
        result.insert(
            "binary_script_compare_error",
            XBinary::getPdStructErrorString(&scriptState)
        );
    }

    if (input.contains("base_signature")) {
        QString baseSignature = input.value("base_signature").toString();
        result.insert("base_signature", baseSignature);
        result.insert(
            "compare_strings",
            XBinary::compareSignatureStrings(baseSignature, pattern)
        );
    }
    if (input.contains("memory_map")) {
        result.insert("memory_map", input.value("memory_map"));
    }
    if (!formatParser.isEmpty()) {
        result.insert("format_parser", formatParser);
        result.insert("format_valid", formatValid);
        result.insert("derived_memory_map", serializeMemoryMap(memoryMap));
    }

    return result;
}

}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    if (argc != 2) {
        std::fprintf(
            stderr,
            "usage: die-signature-harness <vectors.json>\n"
        );
        return 2;
    }

    QFile inputFile(QString::fromLocal8Bit(argv[1]));
    if (!inputFile.open(QIODevice::ReadOnly)) {
        std::fprintf(stderr, "cannot open vector file\n");
        return 2;
    }

    QJsonParseError parseError = {};
    QJsonDocument document =
        QJsonDocument::fromJson(inputFile.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError ||
        !document.isObject()) {
        std::fprintf(stderr, "invalid vector JSON\n");
        return 2;
    }

    QJsonArray inputCases = document.object().value("cases").toArray();
    if (inputCases.isEmpty()) {
        std::fprintf(stderr, "vector list is empty\n");
        return 2;
    }

    QJsonArray outputCases;
    for (const QJsonValue &value : inputCases) {
        if (!value.isObject()) {
            std::fprintf(stderr, "vector entry is not an object\n");
            return 2;
        }
        QString error;
        QJsonObject output = runCase(value.toObject(), &error);
        if (!error.isEmpty()) {
            std::fprintf(stderr, "%s\n", error.toUtf8().constData());
            return 2;
        }
        outputCases.append(output);
    }

    QJsonObject output;
    output.insert("schema_version", 4);
    output.insert("upstream_commit", UPSTREAM_COMMIT);
    output.insert("formats_commit", FORMATS_COMMIT);
    output.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    output.insert("qt_version", qVersion());
    output.insert("case_count", outputCases.size());
    output.insert("cases", outputCases);
    std::printf(
        "%s",
        QJsonDocument(output).toJson(QJsonDocument::Indented).constData()
    );
    return 0;
}
