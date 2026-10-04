// Project-generated research harness for a pinned XArchive checkout.
// It exercises the direct XSevenZip password contract without changing
// parsing, decryption, decompression, or checksum implementations.

#include "xsevenzip.h"

#include <QBuffer>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include <cstdio>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    QString password;
    QString fileName;

    for (int i = 1; i < argc; i++) {
        QString argument = QString::fromLocal8Bit(argv[i]);

        if (argument == "--password") {
            if ((i + 1) >= argc) {
                std::fprintf(stderr, "--password requires a value\n");
                return 2;
            }
            password = QString::fromLocal8Bit(argv[++i]);
        } else if (fileName.isEmpty()) {
            fileName = argument;
        } else {
            std::fprintf(stderr, "unexpected argument: %s\n", argv[i]);
            return 2;
        }
    }

    if (fileName.isEmpty()) {
        std::fprintf(
            stderr,
            "usage: die-sevenzip-password-harness "
            "[--password <value>] <file>\n"
        );
        return 2;
    }

    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly)) {
        std::fprintf(stderr, "cannot open input\n");
        return 3;
    }

    XBinary::PDSTRUCT pdStruct = XBinary::createPdStruct();
    XSevenZip archive(&file);
    XBinary::UNPACK_STATE state = {};
    QMap<XBinary::UNPACK_PROP, QVariant> properties;
    if (!password.isNull()) {
        properties.insert(XBinary::UNPACK_PROP_PASSWORD, password);
    }

    QJsonObject result;
    result.insert("archive_valid", archive.isValid(&pdStruct));
    result.insert("password_supplied", !password.isNull());

    bool initialized = archive.initUnpack(
        &state,
        properties,
        &pdStruct
    );
    result.insert("initialized", initialized);
    result.insert("record_count", state.nNumberOfRecords);

    if (initialized && state.nNumberOfRecords > 0) {
        XBinary::ARCHIVERECORD record = archive.infoCurrent(
            &state,
            &pdStruct
        );
        qint64 declaredSize = record.mapProperties.value(
            XBinary::FPART_PROP_UNCOMPRESSEDSIZE,
            0
        ).toLongLong();
        QByteArray outputBytes;
        QBuffer output(&outputBytes);
        bool outputOpened = output.open(QIODevice::ReadWrite);
        bool unpacked = false;
        if (outputOpened) {
            unpacked = archive.unpackCurrent(
                &state,
                &output,
                &pdStruct
            );
            output.close();
        }

        result.insert(
            "member_name",
            record.mapProperties.value(
                XBinary::FPART_PROP_ORIGINALNAME
            ).toString()
        );
        result.insert("declared_size", declaredSize);
        result.insert("output_opened", outputOpened);
        result.insert("unpacked", unpacked);
        result.insert("output_size", outputBytes.size());
        result.insert(
            "output_sha256",
            QString::fromLatin1(
                QCryptographicHash::hash(
                    outputBytes,
                    QCryptographicHash::Sha256
                ).toHex()
            )
        );
    }

    if (initialized) {
        archive.finishUnpack(&state, &pdStruct);
    }

    std::printf(
        "%s\n",
        QJsonDocument(result)
            .toJson(QJsonDocument::Compact)
            .constData()
    );
    return 0;
}
