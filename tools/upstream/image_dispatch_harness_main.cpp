// Project-generated harness for non-JPEG/PNG image dispatch behavior.
// It links the unmodified pinned engine and varies only SCAN_OPTIONS.fileType.

#include "die_script.h"
#include "xformats.h"

#include <QBuffer>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStringList>

#include <cstdio>

namespace {

constexpr const char *UPSTREAM_COMMIT =
    "74eaf505c250ab47e709024e9dc41657cd8f2254";
constexpr const char *FORMATS_COMMIT =
    "1151e7254fdee3c0294ff7095edbdd7bfccf8201";
constexpr const char *XSCANENGINE_COMMIT =
    "dfe4a419e4f491bb23688ba03c5a5bf39e34da83";
constexpr const char *RULES_COMMIT =
    "c2c17dfa5ea4e078ba31eab55d87430c96622fb6";
constexpr const char *MANIFEST_SHA256 =
    "77e2e743897d9c85ed7c539b1213ce1270bf43aa2cf976a3bf470bdd185a9238";

struct Sample {
    const char *name;
    const char *specificFiletype;
    const char *sha256;
};

const Sample SAMPLES[] = {
    {
        "pixel.bmp",
        "BMP",
        "f7cbd816abfb19030d23b8de5435d0141443665a81ed5ba12114c70b5f53b610",
    },
    {
        "pixel.gif",
        "GIF",
        "5615ca327e5593a9494c3d0ca1fa1ca2bb076fbbaa58981430d3dd0b7e774f09",
    },
    {
        "pixel.tiff",
        "TIFF",
        "5b8de6f08055194ef790df081c2b76fa7920469750fd5ff47e6a209a7b3c716a",
    },
    {
        "pixel.ico",
        "ICO",
        "081eaf6938d3382fb806c0de9b1d79c93e5f17a706928b12d2c0be4581962d96",
    },
    {
        "pointer.cur",
        "CUR",
        "23c93025ed03880dd73cb37688383853aea376317aed0b999858de9e4fb36c21",
    },
    {
        "display.icc",
        "ICC",
        "f94da20185a7e71ff1ca637e6ddc0cffee333a0b82816b93bbfd5e6893febead",
    },
    {
        "pixel.webp",
        "WebP",
        "d1f5a9bc0e39c19ef6adc0c621864365f75288950d731600f6d6e5050d0549c4",
    },
};

QJsonArray serializeFiletypes(const QSet<XBinary::FT> &filetypes)
{
    QStringList names;
    for (XBinary::FT filetype : filetypes) {
        names.append(XBinary::fileTypeIdToString(filetype));
    }
    names.sort(Qt::CaseSensitive);
    QJsonArray output;
    for (const QString &name : names) {
        output.append(name);
    }
    return output;
}

QJsonArray serializeRecords(
    const QList<XScanEngine::SCANSTRUCT> &records
)
{
    QJsonArray output;
    for (const XScanEngine::SCANSTRUCT &record : records) {
        QJsonObject item;
        item.insert(
            "filetype",
            XBinary::fileTypeIdToString(record.id.fileType)
        );
        item.insert("type", record.sType);
        item.insert("name", record.sName);
        item.insert("version", record.sVersion);
        item.insert("info", record.sInfo);
        item.insert("unknown", record.bIsUnknown);
        item.insert("signature_file", record.varInfo2);
        output.append(item);
    }
    return output;
}

QJsonArray serializeErrors(
    const QList<XScanEngine::ERROR_RECORD> &errors
)
{
    QJsonArray output;
    for (const XScanEngine::ERROR_RECORD &error : errors) {
        QJsonObject item;
        item.insert("script", error.sScript);
        item.insert("message", error.sErrorString);
        output.append(item);
    }
    return output;
}

QJsonObject scan(
    DiE_Script *engine,
    const QByteArray &data,
    const QString &fileName,
    const XScanEngine::SCAN_OPTIONS &baseOptions,
    bool forceImage
)
{
    QBuffer buffer;
    buffer.setData(data);
    buffer.setProperty("FileName", fileName);
    if (!buffer.open(QIODevice::ReadOnly)) {
        return {{"harness_error", "cannot open scan buffer"}};
    }

    XScanEngine::SCAN_OPTIONS options = baseOptions;
    options.fileType = (
        forceImage ? XBinary::FT_IMAGE : XBinary::FT_UNKNOWN
    );
    XBinary::PDSTRUCT state = XBinary::createPdStruct();
    const XScanEngine::SCAN_RESULT result = engine->scanDevice(
        &buffer,
        &options,
        &state
    );

    QJsonObject output;
    output.insert("forced_image", forceImage);
    output.insert(
        "option_filetype",
        XBinary::fileTypeIdToString(options.fileType)
    );
    output.insert(
        "initial_filetype",
        XBinary::fileTypeIdToString(result.ftInit)
    );
    output.insert("records", serializeRecords(result.listRecords));
    output.insert("errors", serializeErrors(result.listErrors));
    output.insert(
        "scan_success",
        XBinary::isPdStructSuccess(&state)
    );
    return output;
}

bool readFile(const QString &path, QByteArray *data)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }
    *data = file.readAll();
    return true;
}

}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    if (argc != 2) {
        std::fprintf(
            stderr,
            "usage: die-image-dispatch-harness <fixture-root>\n"
        );
        return 2;
    }
    const QString fixtureRoot = QString::fromLocal8Bit(argv[1]);
    QByteArray manifest;
    if (!readFile(fixtureRoot + "/manifest.json", &manifest)) {
        std::fprintf(stderr, "cannot read fixture manifest\n");
        return 1;
    }
    const QByteArray manifestHash = QCryptographicHash::hash(
        manifest,
        QCryptographicHash::Sha256
    ).toHex();
    if (manifestHash != QByteArray(MANIFEST_SHA256)) {
        std::fprintf(stderr, "fixture manifest hash mismatch\n");
        return 1;
    }

    XScanEngine::SCAN_OPTIONS baseOptions = {};
    baseOptions.bIsVerbose = true;
    baseOptions.bShowType = true;
    baseOptions.bShowInfo = true;
    baseOptions.bShowVersion = true;
    baseOptions.bUseExtraDatabase = true;
    baseOptions.bUseCustomDatabase = true;
    baseOptions.sMainDatabasePath =
        "/opt/die-source/Detect-It-Easy/db";
    baseOptions.sExtraDatabasePath =
        "/opt/die-source/Detect-It-Easy/db_extra";
    baseOptions.sCustomDatabasePath =
        "/opt/die-source/Detect-It-Easy/db_custom";

    DiE_Script engine;
    XBinary::PDSTRUCT loadState = XBinary::createPdStruct();
    if (!engine.loadDatabase(&baseOptions, &loadState)) {
        std::fprintf(stderr, "cannot load pinned rule database\n");
        return 1;
    }

    QJsonArray samples;
    for (const Sample &sample : SAMPLES) {
        const QString path = fixtureRoot + "/" + sample.name;
        QByteArray data;
        if (!readFile(path, &data)) {
            std::fprintf(stderr, "cannot read fixture sample\n");
            return 1;
        }
        const QByteArray digest = QCryptographicHash::hash(
            data,
            QCryptographicHash::Sha256
        ).toHex();
        if (digest != QByteArray(sample.sha256)) {
            std::fprintf(stderr, "fixture sample hash mismatch\n");
            return 1;
        }

        QBuffer detectorBuffer(&data);
        if (!detectorBuffer.open(QIODevice::ReadOnly)) {
            std::fprintf(stderr, "cannot open detector buffer\n");
            return 1;
        }
        XBinary::PDSTRUCT detectorState = XBinary::createPdStruct();
        const QSet<XBinary::FT> detected = XFormats::getFileTypes(
            &detectorBuffer,
            true,
            &detectorState
        );
        QSet<XBinary::FT> imageFiltered = detected;
        XBinary::filterFileTypes(
            &imageFiltered,
            XBinary::FT_IMAGE
        );

        QJsonObject output;
        output.insert("name", sample.name);
        output.insert("specific_filetype", sample.specificFiletype);
        output.insert("size", static_cast<qint64>(data.size()));
        output.insert("sha256", QString::fromLatin1(digest));
        output.insert(
            "detected_filetypes",
            serializeFiletypes(detected)
        );
        output.insert(
            "image_filtered_filetypes",
            serializeFiletypes(imageFiltered)
        );
        output.insert(
            "automatic",
            scan(
                &engine,
                data,
                sample.name,
                baseOptions,
                false
            )
        );
        output.insert(
            "forced_image",
            scan(
                &engine,
                data,
                sample.name,
                baseOptions,
                true
            )
        );
        samples.append(output);
    }

    QJsonObject root;
    root.insert("schema_version", 1);
    root.insert("upstream_commit", UPSTREAM_COMMIT);
    root.insert("formats_commit", FORMATS_COMMIT);
    root.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    root.insert("rules_commit", RULES_COMMIT);
    root.insert("manifest_sha256", QString::fromLatin1(manifestHash));
    root.insert("qt_version", qVersion());
    root.insert("sample_count", samples.size());
    root.insert("samples", samples);
    const QByteArray json = QJsonDocument(root).toJson(
        QJsonDocument::Indented
    );
    std::fwrite(
        json.constData(),
        1,
        static_cast<size_t>(json.size()),
        stdout
    );
    return 0;
}
