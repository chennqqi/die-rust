// Project-generated research harness for pinned DIE engine cache behavior.
// It links the unmodified upstream engine and changes only cache reachability.

#include "die_script.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <QString>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>

namespace {

constexpr const char *UPSTREAM_COMMIT =
    "74eaf505c250ab47e709024e9dc41657cd8f2254";
constexpr const char *XSCANENGINE_COMMIT =
    "dfe4a419e4f491bb23688ba03c5a5bf39e34da83";
constexpr const char *WORK_ROOT = "/tmp/die-database-cache-harness";
constexpr qint64 FIXED_MTIME_SECONDS = 1700000000;
constexpr qint64 FIXED_MTIME_NANOSECONDS = 123000000;

struct CacheSnapshot {
    bool exists = false;
    qint64 size = 0;
    QString sha256;
};

bool setTimes(
    const QString &path,
    qint64 seconds,
    qint64 nanoseconds,
    QString *error
)
{
    const QByteArray nativePath = QFile::encodeName(path);
    struct timespec times[2] = {};
    times[0].tv_sec = seconds;
    times[0].tv_nsec = nanoseconds;
    times[1] = times[0];
    if (::utimensat(
            AT_FDCWD,
            nativePath.constData(),
            times,
            0
        ) != 0) {
        *error = QString("utimensat failed: %1").arg(path);
        return false;
    }
    return true;
}

bool copyFixture(
    const QString &fixtureRoot,
    QString *databasePath,
    QString *rulePath,
    QString *error
)
{
    const QString workRoot = QString::fromLatin1(WORK_ROOT);
    QDir work(workRoot);
    if (work.exists() && !work.removeRecursively()) {
        *error = "cannot clear harness work root";
        return false;
    }

    *databasePath = workRoot + "/database";
    *rulePath = *databasePath + "/Binary/fixture.1.sg";
    if (!QDir().mkpath(*databasePath + "/Binary")) {
        *error = "cannot create harness database";
        return false;
    }

    const QString source =
        fixtureRoot + "/valid-main/Binary/fixture.1.sg";
    if (!QFile::copy(source, *rulePath)) {
        *error = "cannot copy fixture rule";
        return false;
    }
    return setTimes(
        *rulePath,
        FIXED_MTIME_SECONDS,
        FIXED_MTIME_NANOSECONDS,
        error
    );
}

QString cachePathForDatabase(const QString &databasePath)
{
    const QString cacheDir =
        QStandardPaths::writableLocation(
            QStandardPaths::AppDataLocation
        ) + QDir::separator() + "db_cache";
    const QByteArray hash = QCryptographicHash::hash(
        databasePath.toUtf8(),
        QCryptographicHash::Md5
    ).toHex();
    return cacheDir + QDir::separator() +
        QString::fromLatin1(hash) + ".cache";
}

CacheSnapshot cacheSnapshot(const QString &path)
{
    CacheSnapshot result;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return result;
    }
    const QByteArray data = file.readAll();
    result.exists = true;
    result.size = data.size();
    result.sha256 = QString::fromLatin1(
        QCryptographicHash::hash(
            data,
            QCryptographicHash::Sha256
        ).toHex()
    );
    return result;
}

QByteArray readFile(const QString &path, QString *error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        *error = QString("cannot read file: %1").arg(path);
        return {};
    }
    return file.readAll();
}

bool writeFile(
    const QString &path,
    const QByteArray &data,
    QString *error
)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        *error = QString("cannot write file: %1").arg(path);
        return false;
    }
    if (file.write(data) != data.size()) {
        *error = QString("short write: %1").arg(path);
        return false;
    }
    return true;
}

bool setMode(const QString &path, mode_t mode, QString *error)
{
    const QByteArray nativePath = QFile::encodeName(path);
    if (::chmod(nativePath.constData(), mode) != 0) {
        *error = QString("chmod failed: %1").arg(path);
        return false;
    }
    return true;
}

QJsonObject serializeCache(const CacheSnapshot &snapshot)
{
    QJsonObject result;
    result.insert("exists", snapshot.exists);
    result.insert("size", snapshot.size);
    result.insert("sha256", snapshot.sha256);
    return result;
}

qint32 binarySignatureCount(DiE_Script *engine)
{
    const QList<XScanEngine::SIGNATURE_STATE> states =
        engine->getSignatureStates();
    for (const XScanEngine::SIGNATURE_STATE &state : states) {
        if (state.fileType == XBinary::FT_BINARY) {
            return state.nNumberOfSignatures;
        }
    }
    return 0;
}

QJsonArray scanNames(
    DiE_Script *engine,
    XScanEngine::SCAN_OPTIONS *options,
    QJsonArray *errors
)
{
    QByteArray input("die-rust deterministic corpus\n");
    XBinary::PDSTRUCT state = XBinary::createPdStruct();
    const XScanEngine::SCAN_RESULT result = engine->scanMemory(
        input.data(),
        input.size(),
        options,
        &state
    );
    QJsonArray names;
    for (const XScanEngine::SCANSTRUCT &record : result.listRecords) {
        names.append(record.sName);
    }
    for (const XScanEngine::ERROR_RECORD &record : result.listErrors) {
        QJsonObject item;
        item.insert("script", record.sScript);
        item.insert("message", record.sErrorString);
        errors->append(item);
    }
    return names;
}

QJsonObject observeLoad(
    const QString &id,
    const QString &databasePath,
    const QString &cachePath,
    bool stopBeforeLoad
)
{
    XScanEngine::SCAN_OPTIONS options = {};
    options.sMainDatabasePath = databasePath;
    options.bUseCache = true;
    options.bIsSort = true;
    options.bShowType = true;
    options.bShowVersion = true;
    options.bShowInfo = true;

    DiE_Script engine;
    XBinary::PDSTRUCT loadState = XBinary::createPdStruct();
    if (stopBeforeLoad) {
        XBinary::setPdStructStopped(&loadState);
    }
    const bool loaded = engine.loadDatabase(&options, &loadState);

    QJsonArray errors;
    QJsonObject result;
    result.insert("id", id);
    result.insert("loaded", loaded);
    result.insert("stop_before_load", stopBeforeLoad);
    result.insert(
        "load_pd_not_canceled",
        XBinary::isPdStructNotCanceled(&loadState)
    );
    result.insert(
        "binary_signature_count",
        binarySignatureCount(&engine)
    );
    result.insert("scan_names", scanNames(&engine, &options, &errors));
    result.insert("scan_errors", errors);
    result.insert("cache", serializeCache(cacheSnapshot(cachePath)));
    return result;
}

bool replaceRulePreservingStats(
    const QString &rulePath,
    QString *error
)
{
    QFile file(rulePath);
    if (!file.open(QIODevice::ReadWrite)) {
        *error = "cannot open rule for same-stat replacement";
        return false;
    }
    QByteArray data = file.readAll();
    const QByteArray before("Fixture");
    const QByteArray after("Changed");
    if (
        before.size() != after.size() ||
        !data.contains(before)
    ) {
        *error = "fixture replacement invariant failed";
        return false;
    }
    data.replace(before, after);
    if (!file.resize(0) || file.write(data) != data.size()) {
        *error = "cannot rewrite rule";
        return false;
    }
    file.close();
    return setTimes(
        rulePath,
        FIXED_MTIME_SECONDS,
        FIXED_MTIME_NANOSECONDS,
        error
    );
}

bool corruptMagic(const QString &cachePath, QString *error)
{
    QFile file(cachePath);
    if (!file.open(QIODevice::ReadWrite)) {
        *error = "cannot open cache for magic corruption";
        return false;
    }
    if (file.write(QByteArray(4, '\0')) != 4) {
        *error = "cannot corrupt cache magic";
        return false;
    }
    return true;
}

bool writeCachePrefix(
    const QString &cachePath,
    const QByteArray &validCache,
    qsizetype size,
    QString *error
)
{
    if (size < 0 || size > validCache.size()) {
        *error = "invalid cache prefix size";
        return false;
    }
    return writeFile(
        cachePath,
        validCache.left(static_cast<int>(size)),
        error
    );
}

bool writeBadVersionCache(
    const QString &cachePath,
    const QByteArray &validCache,
    QString *error
)
{
    if (validCache.size() < 8) {
        *error = "valid cache is shorter than magic and version";
        return false;
    }
    QByteArray data = validCache;
    data[4] = '\0';
    data[5] = '\0';
    data[6] = '\0';
    data[7] = '\x06';
    return writeFile(cachePath, data, error);
}

QJsonObject observeConcurrentWriters(
    const QString &databasePath,
    const QString &cachePath
)
{
    constexpr int WRITER_COUNT = 8;
    std::atomic<int> ready(0);
    std::atomic<bool> start(false);
    std::vector<int> loaded(WRITER_COUNT, 0);
    std::vector<qint32> counts(WRITER_COUNT, 0);
    std::vector<std::thread> threads;
    threads.reserve(WRITER_COUNT);

    for (int index = 0; index < WRITER_COUNT; ++index) {
        threads.emplace_back([&, index]() {
            XScanEngine::SCAN_OPTIONS options = {};
            options.sMainDatabasePath = databasePath;
            options.bUseCache = true;
            DiE_Script engine;
            XBinary::PDSTRUCT state = XBinary::createPdStruct();
            ready.fetch_add(1);
            while (!start.load()) {
                std::this_thread::yield();
            }
            loaded[index] = engine.loadDatabase(&options, &state) ? 1 : 0;
            counts[index] = binarySignatureCount(&engine);
        });
    }
    while (ready.load() != WRITER_COUNT) {
        std::this_thread::yield();
    }
    start.store(true);
    for (std::thread &thread : threads) {
        thread.join();
    }

    QJsonArray writerLoaded;
    QJsonArray writerCounts;
    bool allLoaded = true;
    for (int index = 0; index < WRITER_COUNT; ++index) {
        writerLoaded.append(loaded[index] != 0);
        writerCounts.append(counts[index]);
        allLoaded = allLoaded && loaded[index];
    }

    QJsonObject result = observeLoad(
        "concurrent_identical_writers",
        databasePath,
        cachePath,
        false
    );
    result.insert("writer_count", WRITER_COUNT);
    result.insert("writer_loaded", writerLoaded);
    result.insert("writer_signature_counts", writerCounts);
    result.insert("loaded", allLoaded && result.value("loaded").toBool());
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
            "usage: die-database-cache-harness <fixture-root>\n"
        );
        return 2;
    }

    QString databasePath;
    QString rulePath;
    QString error;
    if (!copyFixture(
            QString::fromLocal8Bit(argv[1]),
            &databasePath,
            &rulePath,
            &error
        )) {
        std::fprintf(stderr, "%s\n", error.toUtf8().constData());
        return 1;
    }

    const QString cachePath = cachePathForDatabase(databasePath);
    const QFileInfo cacheInfo(cachePath);
    QDir cacheDirectory = cacheInfo.dir();
    if (
        cacheDirectory.exists() &&
        !cacheDirectory.removeRecursively()
    ) {
        std::fprintf(stderr, "cannot clear cache directory\n");
        return 1;
    }

    QJsonArray cases;
    cases.append(observeLoad(
        "initial_miss",
        databasePath,
        cachePath,
        false
    ));
    cases.append(observeLoad(
        "unchanged_hit",
        databasePath,
        cachePath,
        false
    ));

    if (!replaceRulePreservingStats(rulePath, &error)) {
        std::fprintf(stderr, "%s\n", error.toUtf8().constData());
        return 1;
    }
    cases.append(observeLoad(
        "same_stats_stale_hit",
        databasePath,
        cachePath,
        false
    ));

    if (!setTimes(
            rulePath,
            FIXED_MTIME_SECONDS + 2,
            FIXED_MTIME_NANOSECONDS,
            &error
        )) {
        std::fprintf(stderr, "%s\n", error.toUtf8().constData());
        return 1;
    }
    cases.append(observeLoad(
        "stats_changed_rebuild",
        databasePath,
        cachePath,
        false
    ));

    const QByteArray rebuiltCache = readFile(cachePath, &error);
    if (rebuiltCache.isEmpty()) {
        std::fprintf(stderr, "%s\n", error.toUtf8().constData());
        return 1;
    }

    if (!corruptMagic(cachePath, &error)) {
        std::fprintf(stderr, "%s\n", error.toUtf8().constData());
        return 1;
    }
    cases.append(observeLoad(
        "bad_magic_fallback",
        databasePath,
        cachePath,
        false
    ));

    if (!writeBadVersionCache(cachePath, rebuiltCache, &error)) {
        std::fprintf(stderr, "%s\n", error.toUtf8().constData());
        return 1;
    }
    cases.append(observeLoad(
        "bad_version_fallback",
        databasePath,
        cachePath,
        false
    ));

    const qsizetype prefixSizes[] = {
        0,
        4,
        8,
        rebuiltCache.size() / 2,
        rebuiltCache.size() - 1,
    };
    const char *prefixIds[] = {
        "empty_cache_fallback",
        "magic_only_fallback",
        "magic_version_only_fallback",
        "truncated_record_fallback",
        "record_tail_truncated_fallback",
    };
    for (int index = 0; index < 5; ++index) {
        if (!writeCachePrefix(
                cachePath,
                rebuiltCache,
                prefixSizes[index],
                &error
            )) {
            std::fprintf(stderr, "%s\n", error.toUtf8().constData());
            return 1;
        }
        cases.append(observeLoad(
            prefixIds[index],
            databasePath,
            cachePath,
            false
        ));
    }

    if (!QFile::remove(cachePath)) {
        std::fprintf(stderr, "cannot remove cache before write denial\n");
        return 1;
    }
    if (!setMode(cacheDirectory.absolutePath(), 0555, &error)) {
        std::fprintf(stderr, "%s\n", error.toUtf8().constData());
        return 1;
    }
    cases.append(observeLoad(
        "cache_write_denied",
        databasePath,
        cachePath,
        false
    ));
    if (!setMode(cacheDirectory.absolutePath(), 0755, &error)) {
        std::fprintf(stderr, "%s\n", error.toUtf8().constData());
        return 1;
    }
    cases.append(observeLoad(
        "cache_write_recovery",
        databasePath,
        cachePath,
        false
    ));

    if (!QFile::remove(cachePath)) {
        std::fprintf(stderr, "cannot remove cache before concurrency\n");
        return 1;
    }
    cases.append(observeConcurrentWriters(databasePath, cachePath));

    const QString deniedDirectory =
        QString::fromLatin1(WORK_ROOT) + "/denied-directory";
    const QString deniedRule =
        deniedDirectory + "/Binary/fixture.1.sg";
    if (
        !QDir().mkpath(deniedDirectory + "/Binary") ||
        !QFile::copy(rulePath, deniedRule) ||
        !setMode(deniedDirectory, 0000, &error)
    ) {
        std::fprintf(stderr, "%s\n", error.toUtf8().constData());
        return 1;
    }
    cases.append(observeLoad(
        "database_directory_permission_denied",
        deniedDirectory,
        cachePathForDatabase(deniedDirectory),
        false
    ));
    if (!setMode(deniedDirectory, 0755, &error)) {
        std::fprintf(stderr, "%s\n", error.toUtf8().constData());
        return 1;
    }

    const QString deniedFile =
        QString::fromLatin1(WORK_ROOT) + "/denied-main.zip";
    if (
        !QFile::copy(
            QString::fromLocal8Bit(argv[1]) + "/valid-main.zip",
            deniedFile
        ) ||
        !setMode(deniedFile, 0000, &error)
    ) {
        std::fprintf(stderr, "%s\n", error.toUtf8().constData());
        return 1;
    }
    cases.append(observeLoad(
        "database_file_permission_denied",
        deniedFile,
        cachePathForDatabase(deniedFile),
        false
    ));
    if (!setMode(deniedFile, 0644, &error)) {
        std::fprintf(stderr, "%s\n", error.toUtf8().constData());
        return 1;
    }

    cases.append(observeLoad(
        "canceled_cache_hit",
        databasePath,
        cachePath,
        true
    ));

    if (!QFile::remove(cachePath)) {
        std::fprintf(stderr, "cannot remove cache before canceled miss\n");
        return 1;
    }
    cases.append(observeLoad(
        "canceled_cache_miss",
        databasePath,
        cachePath,
        true
    ));
    cases.append(observeLoad(
        "poisoned_empty_cache_hit",
        databasePath,
        cachePath,
        false
    ));

    QJsonObject output;
    output.insert("schema_version", 1);
    output.insert("upstream_commit", UPSTREAM_COMMIT);
    output.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    output.insert("effective_uid", static_cast<qint64>(::geteuid()));
    output.insert("effective_gid", static_cast<qint64>(::getegid()));
    output.insert("database_path", databasePath);
    output.insert("rule_path", rulePath);
    output.insert("cache_path", cachePath);
    output.insert("fixed_mtime_seconds", FIXED_MTIME_SECONDS);
    output.insert(
        "fixed_mtime_nanoseconds",
        FIXED_MTIME_NANOSECONDS
    );
    output.insert("cases", cases);

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
