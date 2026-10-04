// Project-generated research harness for pinned DIE engine-only contracts.
// It links the unmodified upstream engine and changes only option reachability.

#include "die_script.h"

#include <QBuffer>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include <cstdio>
#include <cstring>
#include <thread>

namespace {

constexpr const char *UPSTREAM_COMMIT =
    "74eaf505c250ab47e709024e9dc41657cd8f2254";
constexpr const char *XSCANENGINE_COMMIT =
    "dfe4a419e4f491bb23688ba03c5a5bf39e34da83";
constexpr const char *DIE_SCRIPT_COMMIT =
    "5d82316c110abf0eb863b50bc679d330e05067b6";
constexpr const char *INPUT_SHA256 =
    "b9e88c21a74e1be0f85e85465c3f6bb831a55ef1d626af3fa11164e5f353ac60";

enum class ScanMethod {
    File,
    Memory,
    Device,
    Subdevice,
};

enum class CallbackMode {
    None,
    Continue,
    StopFirst,
    StopSecond,
    StopLast,
    ExternalStopSecond,
};

struct CaseSpec {
    const char *id;
    const char *database;
    const char *signatureName;
    bool deep;
    bool sort;
    CallbackMode callbackMode;
    bool preStopped;
    ScanMethod method;
};

struct CallbackState {
    CallbackMode mode = CallbackMode::None;
    QJsonArray events;
    XBinary::PDSTRUCT *scanState = nullptr;
    qint32 externalStopWrites = 0;
    bool externalStopThreadDistinct = false;
};

enum class DeviceBehavior {
    Normal,
    Chunked,
    EarlyEof,
    ReadError,
    SeekError,
    Sequential,
};

class ProbeDevice final : public QIODevice {
public:
    ProbeDevice(
        const QByteArray &data,
        DeviceBehavior behavior,
        qint64 maxChunk,
        qint64 stopAfter
    )
        : m_data(data),
          m_behavior(behavior),
          m_maxChunk(maxChunk),
          m_stopAfter(stopAfter)
    {
    }

    qint64 size() const override
    {
        return m_data.size();
    }

    bool isSequential() const override
    {
        return m_behavior == DeviceBehavior::Sequential;
    }

    bool seek(qint64 position) override
    {
        m_seekCalls++;
        m_seekPositions.append(QString::number(position));
        if (
            m_behavior == DeviceBehavior::SeekError ||
            m_behavior == DeviceBehavior::Sequential
        ) {
            return false;
        }
        return QIODevice::seek(position);
    }

    qint64 bytesAvailable() const override
    {
        qint64 end = m_data.size();
        if (m_stopAfter >= 0) {
            end = qMin(end, m_stopAfter);
        }
        return qMax<qint64>(0, end - pos()) +
            QIODevice::bytesAvailable();
    }

    qint64 seekCalls() const
    {
        return m_seekCalls;
    }

    qint64 readCalls() const
    {
        return m_readCalls;
    }

    qint64 bytesReturned() const
    {
        return m_bytesReturned;
    }

    QJsonArray seekPositions() const
    {
        return m_seekPositions;
    }

    QJsonArray readRequests() const
    {
        return m_readRequests;
    }

    QJsonArray readReturns() const
    {
        return m_readReturns;
    }

protected:
    qint64 readData(char *data, qint64 maxSize) override
    {
        m_readCalls++;
        m_readRequests.append(QString::number(maxSize));
        if (m_behavior == DeviceBehavior::ReadError) {
            setErrorString("injected read error");
            m_readReturns.append("-1");
            return -1;
        }

        const qint64 position = pos();
        qint64 end = m_data.size();
        if (m_stopAfter >= 0) {
            end = qMin(end, m_stopAfter);
        }
        if (position < 0 || position >= end) {
            m_readReturns.append("0");
            return 0;
        }

        qint64 count = qMin(maxSize, end - position);
        if (
            m_behavior == DeviceBehavior::Chunked &&
            m_maxChunk > 0
        ) {
            count = qMin(count, m_maxChunk);
        }
        std::memcpy(
            data,
            m_data.constData() + position,
            static_cast<size_t>(count)
        );
        m_bytesReturned += count;
        m_readReturns.append(QString::number(count));
        return count;
    }

    qint64 writeData(const char *, qint64) override
    {
        return -1;
    }

private:
    QByteArray m_data;
    DeviceBehavior m_behavior;
    qint64 m_maxChunk = 0;
    qint64 m_stopAfter = -1;
    qint64 m_seekCalls = 0;
    qint64 m_readCalls = 0;
    qint64 m_bytesReturned = 0;
    QJsonArray m_seekPositions;
    QJsonArray m_readRequests;
    QJsonArray m_readReturns;
};

struct DeviceCaseSpec {
    const char *id;
    DeviceBehavior behavior;
    bool subdevice;
    qint64 offset;
    qint64 size;
    qint64 maxChunk;
    qint64 stopAfter;
    qint64 initialPosition;
};

bool scanCallback(
    const QString &currentSignature,
    qint32 numberOfSignatures,
    qint32 currentIndex,
    void *userData
)
{
    CallbackState *state = static_cast<CallbackState *>(userData);
    QJsonObject event;
    event.insert("signature", currentSignature);
    event.insert("number_of_signatures", numberOfSignatures);
    event.insert("current_index", currentIndex);
    state->events.append(event);
    const qint32 callbackNumber = state->events.size();

    if (
        state->mode == CallbackMode::ExternalStopSecond &&
        callbackNumber == 2
    ) {
        const std::thread::id callbackThread =
            std::this_thread::get_id();
        bool distinctThread = false;
        std::thread stopThread([&]() {
            distinctThread =
                std::this_thread::get_id() != callbackThread;
            XBinary::setPdStructStopped(state->scanState);
        });
        stopThread.join();
        state->externalStopWrites++;
        state->externalStopThreadDistinct = distinctThread;
    }

    return !(
        (state->mode == CallbackMode::StopFirst &&
         callbackNumber == 1) ||
        (state->mode == CallbackMode::StopSecond &&
         callbackNumber == 2) ||
        (state->mode == CallbackMode::StopLast &&
         callbackNumber == numberOfSignatures)
    );
}

QString layerPath(
    const QString &fixtureRoot,
    const QString &database,
    const QString &layer
)
{
    if (database == "orchestration") {
        return fixtureRoot + "/" + layer;
    }
    return fixtureRoot + "/" + database + "-" + layer;
}

QJsonObject serializeRecord(const XScanEngine::SCANSTRUCT &record)
{
    QJsonObject output;
    output.insert("type", record.sType);
    output.insert("name", record.sName);
    output.insert("version", record.sVersion);
    output.insert("info", record.sInfo);
    output.insert("priority", record.nPrio);
    output.insert("unknown", record.bIsUnknown);
    output.insert("heuristic", record.bIsHeuristic);
    output.insert("aggressive_heuristic", record.bIsAHeuristic);
    output.insert("signature", record.varInfo);
    output.insert("signature_file", record.varInfo2);
    return output;
}

QJsonArray serializeRecords(
    const QList<XScanEngine::SCANSTRUCT> &records
)
{
    QJsonArray output;
    for (const XScanEngine::SCANSTRUCT &record : records) {
        output.append(serializeRecord(record));
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

const char *methodName(ScanMethod method)
{
    switch (method) {
        case ScanMethod::File:
            return "scanFile";
        case ScanMethod::Memory:
            return "scanMemory";
        case ScanMethod::Device:
            return "scanDevice";
        case ScanMethod::Subdevice:
            return "scanSubdevice";
    }
    return "unknown";
}

const char *deviceBehaviorName(DeviceBehavior behavior)
{
    switch (behavior) {
        case DeviceBehavior::Normal:
            return "normal";
        case DeviceBehavior::Chunked:
            return "chunked";
        case DeviceBehavior::EarlyEof:
            return "early_eof";
        case DeviceBehavior::ReadError:
            return "read_error";
        case DeviceBehavior::SeekError:
            return "seek_error";
        case DeviceBehavior::Sequential:
            return "sequential";
    }
    return "unknown";
}

XScanEngine::SCAN_RESULT runScan(
    DiE_Script *engine,
    const CaseSpec &spec,
    const QString &inputPath,
    QByteArray *input,
    XScanEngine::SCAN_OPTIONS *options,
    XBinary::PDSTRUCT *state,
    QString *error
)
{
    if (spec.method == ScanMethod::File) {
        return engine->scanFile(inputPath, options, state);
    }
    if (spec.method == ScanMethod::Memory) {
        return engine->scanMemory(
            input->data(),
            input->size(),
            options,
            state
        );
    }
    if (spec.method == ScanMethod::Device) {
        QBuffer buffer(input);
        buffer.setProperty("FileName", "probe.bin");
        if (!buffer.open(QIODevice::ReadOnly)) {
            *error = "cannot open scanDevice buffer";
            return {};
        }
        return engine->scanDevice(&buffer, options, state);
    }

    QByteArray wrapped("pre", 3);
    wrapped.append(*input);
    wrapped.append("post", 4);
    QBuffer buffer(&wrapped);
    buffer.setProperty("FileName", "wrapped.bin");
    if (!buffer.open(QIODevice::ReadOnly)) {
        *error = "cannot open scanSubdevice buffer";
        return {};
    }
    return engine->scanSubdevice(
        &buffer,
        3,
        input->size(),
        options,
        state
    );
}

QJsonObject runCase(
    const CaseSpec &spec,
    const QString &fixtureRoot,
    const QString &inputPath,
    QByteArray *input,
    QString *error
)
{
    XScanEngine::SCAN_OPTIONS options = {};
    options.bUseCustomDatabase = true;
    options.bUseExtraDatabase = true;
    options.bShowType = true;
    options.bShowInfo = true;
    options.bShowVersion = true;
    options.bIsDeepScan = spec.deep;
    options.bIsSort = spec.sort;
    options.sSignatureName = QString::fromLatin1(spec.signatureName);
    const QString database = QString::fromLatin1(spec.database);
    options.sMainDatabasePath = layerPath(
        fixtureRoot,
        database,
        "main"
    );
    options.sExtraDatabasePath = layerPath(
        fixtureRoot,
        database,
        "extra"
    );
    options.sCustomDatabasePath = layerPath(
        fixtureRoot,
        database,
        "custom"
    );

    XBinary::PDSTRUCT scanState = XBinary::createPdStruct();
    CallbackState callbackState;
    callbackState.mode = spec.callbackMode;
    callbackState.scanState = &scanState;
    if (spec.callbackMode != CallbackMode::None) {
        options.scanEngineCallback = scanCallback;
        options.pUserData = &callbackState;
    }

    DiE_Script engine;
    XBinary::PDSTRUCT loadState = XBinary::createPdStruct();
    const bool loaded = engine.loadDatabase(&options, &loadState);
    if (!loaded) {
        *error = QString("cannot load fixture database: %1").arg(
            spec.id
        );
        return {};
    }

    if (spec.preStopped) {
        XBinary::setPdStructStopped(&scanState);
    }
    XScanEngine::SCAN_RESULT result = runScan(
        &engine,
        spec,
        inputPath,
        input,
        &options,
        &scanState,
        error
    );
    if (!error->isEmpty()) {
        return {};
    }

    QJsonObject output;
    output.insert("id", QString::fromLatin1(spec.id));
    output.insert("database", database);
    output.insert("method", QString::fromLatin1(methodName(spec.method)));
    output.insert(
        "signature_name",
        QString::fromLatin1(spec.signatureName)
    );
    output.insert("deep", spec.deep);
    output.insert("sort", spec.sort);
    output.insert("pre_stopped", spec.preStopped);
    output.insert("database_loaded", loaded);
    output.insert("records", serializeRecords(result.listRecords));
    output.insert("errors", serializeErrors(result.listErrors));
    output.insert("callback_events", callbackState.events);
    output.insert(
        "external_stop_writes",
        callbackState.externalStopWrites
    );
    output.insert(
        "external_stop_thread_distinct",
        callbackState.externalStopThreadDistinct
    );
    output.insert(
        "pd_stopped",
        XBinary::isPdStructStopped(&scanState)
    );
    output.insert(
        "pd_success",
        XBinary::isPdStructSuccess(&scanState)
    );
    output.insert(
        "pd_finished",
        XBinary::isPdStructFinished(&scanState)
    );
    output.insert(
        "pd_not_canceled",
        XBinary::isPdStructNotCanceled(&scanState)
    );
    output.insert(
        "pd_n_finished",
        static_cast<qint64>(scanState.nFinished)
    );
    output.insert("result_size", result.nSize);
    return output;
}

QJsonObject serializeRecoveryScan(
    const XScanEngine::SCAN_RESULT &result,
    XBinary::PDSTRUCT *state,
    const CallbackState &callbackState
)
{
    QJsonObject output;
    output.insert("records", serializeRecords(result.listRecords));
    output.insert("errors", serializeErrors(result.listErrors));
    output.insert("callback_events", callbackState.events);
    output.insert(
        "pd_stopped",
        XBinary::isPdStructStopped(state)
    );
    output.insert(
        "pd_success",
        XBinary::isPdStructSuccess(state)
    );
    output.insert(
        "pd_finished",
        XBinary::isPdStructFinished(state)
    );
    output.insert(
        "pd_not_canceled",
        XBinary::isPdStructNotCanceled(state)
    );
    output.insert(
        "pd_n_finished",
        static_cast<qint64>(state->nFinished)
    );
    return output;
}

QJsonObject runRecoveryCase(
    const QString &fixtureRoot,
    const QString &inputPath,
    QString *error
)
{
    XScanEngine::SCAN_OPTIONS options = {};
    options.bUseCustomDatabase = true;
    options.bUseExtraDatabase = true;
    options.bShowType = true;
    options.bShowInfo = true;
    options.bShowVersion = true;
    options.sMainDatabasePath = fixtureRoot + "/priority-main";
    options.sExtraDatabasePath = fixtureRoot + "/priority-extra";
    options.sCustomDatabasePath = fixtureRoot + "/priority-custom";
    options.scanEngineCallback = scanCallback;

    DiE_Script engine;
    XBinary::PDSTRUCT loadState = XBinary::createPdStruct();
    const bool loaded = engine.loadDatabase(&options, &loadState);
    if (!loaded) {
        *error = "cannot load recovery fixture database";
        return {};
    }

    XBinary::PDSTRUCT canceledState = XBinary::createPdStruct();
    CallbackState canceledCallback;
    canceledCallback.mode = CallbackMode::StopSecond;
    canceledCallback.scanState = &canceledState;
    options.pUserData = &canceledCallback;
    const XScanEngine::SCAN_RESULT canceledResult =
        engine.scanFile(inputPath, &options, &canceledState);

    XBinary::PDSTRUCT freshState = XBinary::createPdStruct();
    CallbackState freshCallback;
    freshCallback.mode = CallbackMode::Continue;
    freshCallback.scanState = &freshState;
    options.pUserData = &freshCallback;
    const XScanEngine::SCAN_RESULT freshResult =
        engine.scanFile(inputPath, &options, &freshState);

    QJsonObject output;
    output.insert("id", "post_cancel_fresh_state_recovery");
    output.insert("method", "scanFile_twice");
    output.insert("database_loaded", loaded);
    output.insert(
        "canceled",
        serializeRecoveryScan(
            canceledResult,
            &canceledState,
            canceledCallback
        )
    );
    output.insert(
        "fresh",
        serializeRecoveryScan(
            freshResult,
            &freshState,
            freshCallback
        )
    );
    return output;
}

QJsonObject runDeviceCase(
    const DeviceCaseSpec &spec,
    const QString &fixtureRoot,
    const QByteArray &input,
    QString *error
)
{
    QByteArray deviceData = input;
    if (spec.subdevice) {
        deviceData.prepend("pre", 3);
        deviceData.append("post", 4);
    }

    ProbeDevice device(
        deviceData,
        spec.behavior,
        spec.maxChunk,
        spec.stopAfter
    );
    device.setProperty("FileName", "fault-device.bin");
    if (!device.open(QIODevice::ReadOnly)) {
        *error = QString("cannot open probe device: %1").arg(spec.id);
        return {};
    }
    if (
        spec.initialPosition >= 0 &&
        !device.seek(spec.initialPosition)
    ) {
        *error = QString("cannot set initial position: %1").arg(spec.id);
        return {};
    }

    XScanEngine::SCAN_OPTIONS options = {};
    options.bUseCustomDatabase = true;
    options.bUseExtraDatabase = true;
    options.bShowType = true;
    options.bShowInfo = true;
    options.bShowVersion = true;
    options.fileType = XBinary::FT_BINARY;
    options.sSignatureName = "z_priority.1.sg";
    options.sMainDatabasePath = fixtureRoot + "/priority-main";
    options.sExtraDatabasePath = fixtureRoot + "/priority-extra";
    options.sCustomDatabasePath = fixtureRoot + "/priority-custom";

    DiE_Script engine;
    XBinary::PDSTRUCT loadState = XBinary::createPdStruct();
    const bool loaded = engine.loadDatabase(&options, &loadState);
    if (!loaded) {
        *error = QString("cannot load device fixture: %1").arg(spec.id);
        return {};
    }

    const bool rangeValid = spec.subdevice &&
        XBinary::isOffsetAndSizeValid(
            &device,
            spec.offset,
            spec.size
        );
    XBinary::PDSTRUCT scanState = XBinary::createPdStruct();
    XScanEngine::SCAN_RESULT result = {};
    if (spec.subdevice) {
        result = engine.scanSubdevice(
            &device,
            spec.offset,
            spec.size,
            &options,
            &scanState
        );
    } else {
        result = engine.scanDevice(
            &device,
            &options,
            &scanState
        );
    }

    QJsonObject output;
    output.insert("id", QString::fromLatin1(spec.id));
    output.insert(
        "method",
        spec.subdevice ? "scanSubdevice" : "scanDevice"
    );
    output.insert(
        "behavior",
        QString::fromLatin1(deviceBehaviorName(spec.behavior))
    );
    output.insert("database_loaded", loaded);
    output.insert("device_size", device.size());
    output.insert("initial_position", spec.initialPosition);
    output.insert("final_position", device.pos());
    output.insert("offset", spec.offset);
    output.insert("size", spec.size);
    output.insert("range_valid", rangeValid);
    output.insert("seek_calls", device.seekCalls());
    output.insert("seek_positions", device.seekPositions());
    output.insert("read_calls", device.readCalls());
    output.insert("read_requests", device.readRequests());
    output.insert("read_returns", device.readReturns());
    output.insert("bytes_returned", device.bytesReturned());
    output.insert("device_error", device.errorString());
    output.insert("records", serializeRecords(result.listRecords));
    output.insert("errors", serializeErrors(result.listErrors));
    output.insert("result_size", result.nSize);
    output.insert(
        "result_filetype",
        XBinary::fileTypeIdToString(result.ftInit)
    );
    output.insert(
        "pd_error",
        XBinary::getPdStructErrorString(&scanState)
    );
    output.insert(
        "pd_stopped",
        XBinary::isPdStructStopped(&scanState)
    );
    output.insert(
        "pd_success",
        XBinary::isPdStructSuccess(&scanState)
    );
    output.insert(
        "pd_finished",
        XBinary::isPdStructFinished(&scanState)
    );
    output.insert(
        "pd_n_finished",
        static_cast<qint64>(scanState.nFinished)
    );
    return output;
}

}  // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    if (argc != 2) {
        std::fprintf(
            stderr,
            "usage: die-engine-contract-harness <fixture-root>\n"
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
    QByteArray input = inputFile.readAll();
    const QByteArray inputHash = QCryptographicHash::hash(
        input,
        QCryptographicHash::Sha256
    ).toHex();
    if (inputHash != QByteArray(INPUT_SHA256)) {
        std::fprintf(stderr, "fixture input hash mismatch\n");
        return 1;
    }

    const CaseSpec cases[] = {
        {
            "filter_all",
            "priority",
            "",
            false,
            false,
            CallbackMode::None,
            false,
            ScanMethod::File,
        },
        {
            "filter_exact_extra",
            "orchestration",
            "a_extra.0.sg",
            false,
            false,
            CallbackMode::None,
            false,
            ScanMethod::File,
        },
        {
            "filter_missing",
            "priority",
            "missing.0.sg",
            false,
            false,
            CallbackMode::None,
            false,
            ScanMethod::File,
        },
        {
            "filter_case_mismatch",
            "priority",
            "Z_PRIORITY.1.SG",
            false,
            false,
            CallbackMode::None,
            false,
            ScanMethod::File,
        },
        {
            "filter_deep_disabled",
            "orchestration",
            "DS.deep.2.sg",
            false,
            false,
            CallbackMode::None,
            false,
            ScanMethod::File,
        },
        {
            "filter_deep_enabled",
            "orchestration",
            "DS.deep.2.sg",
            true,
            false,
            CallbackMode::None,
            false,
            ScanMethod::File,
        },
        {
            "sort_disabled",
            "sort",
            "",
            false,
            false,
            CallbackMode::None,
            false,
            ScanMethod::File,
        },
        {
            "sort_enabled",
            "sort",
            "",
            false,
            true,
            CallbackMode::None,
            false,
            ScanMethod::File,
        },
        {
            "callback_continue",
            "priority",
            "",
            false,
            false,
            CallbackMode::Continue,
            false,
            ScanMethod::File,
        },
        {
            "callback_stop_first",
            "priority",
            "",
            false,
            false,
            CallbackMode::StopFirst,
            false,
            ScanMethod::File,
        },
        {
            "callback_stop_second",
            "priority",
            "",
            false,
            false,
            CallbackMode::StopSecond,
            false,
            ScanMethod::File,
        },
        {
            "callback_stop_last",
            "priority",
            "",
            false,
            false,
            CallbackMode::StopLast,
            false,
            ScanMethod::File,
        },
        {
            "external_stop_second",
            "priority",
            "",
            false,
            false,
            CallbackMode::ExternalStopSecond,
            false,
            ScanMethod::File,
        },
        {
            "break_scan",
            "break",
            "",
            false,
            false,
            CallbackMode::None,
            false,
            ScanMethod::File,
        },
        {
            "pre_stopped",
            "priority",
            "",
            false,
            false,
            CallbackMode::None,
            true,
            ScanMethod::File,
        },
        {
            "entry_file",
            "priority",
            "z_priority.1.sg",
            false,
            false,
            CallbackMode::None,
            false,
            ScanMethod::File,
        },
        {
            "entry_memory",
            "priority",
            "z_priority.1.sg",
            false,
            false,
            CallbackMode::None,
            false,
            ScanMethod::Memory,
        },
        {
            "entry_device",
            "priority",
            "z_priority.1.sg",
            false,
            false,
            CallbackMode::None,
            false,
            ScanMethod::Device,
        },
        {
            "entry_subdevice",
            "priority",
            "z_priority.1.sg",
            false,
            false,
            CallbackMode::None,
            false,
            ScanMethod::Subdevice,
        },
    };

    QJsonArray outputs;
    QString error;
    for (const CaseSpec &spec : cases) {
        QJsonObject output = runCase(
            spec,
            fixtureRoot,
            inputPath,
            &input,
            &error
        );
        if (!error.isEmpty()) {
            std::fprintf(stderr, "%s\n", error.toUtf8().constData());
            return 1;
        }
        outputs.append(output);
    }

    QJsonObject recoveryOutput = runRecoveryCase(
        fixtureRoot,
        inputPath,
        &error
    );
    if (!error.isEmpty()) {
        std::fprintf(stderr, "%s\n", error.toUtf8().constData());
        return 1;
    }
    outputs.append(recoveryOutput);

    const DeviceCaseSpec deviceCases[] = {
        {
            "device_chunked_read",
            DeviceBehavior::Chunked,
            false,
            0,
            0,
            3,
            -1,
            -1,
        },
        {
            "device_early_eof",
            DeviceBehavior::EarlyEof,
            false,
            0,
            0,
            0,
            5,
            -1,
        },
        {
            "device_read_error",
            DeviceBehavior::ReadError,
            false,
            0,
            0,
            0,
            -1,
            -1,
        },
        {
            "device_seek_error",
            DeviceBehavior::SeekError,
            false,
            0,
            0,
            0,
            -1,
            -1,
        },
        {
            "device_sequential",
            DeviceBehavior::Sequential,
            false,
            0,
            0,
            0,
            -1,
            -1,
        },
        {
            "device_initial_position",
            DeviceBehavior::Normal,
            false,
            0,
            0,
            0,
            -1,
            7,
        },
        {
            "subdevice_chunked_read",
            DeviceBehavior::Chunked,
            true,
            3,
            input.size(),
            3,
            -1,
            -1,
        },
        {
            "subdevice_early_eof",
            DeviceBehavior::EarlyEof,
            true,
            3,
            input.size(),
            0,
            8,
            -1,
        },
        {
            "subdevice_read_error",
            DeviceBehavior::ReadError,
            true,
            3,
            input.size(),
            0,
            -1,
            -1,
        },
        {
            "subdevice_seek_error",
            DeviceBehavior::SeekError,
            true,
            3,
            input.size(),
            0,
            -1,
            -1,
        },
        {
            "subdevice_sequential",
            DeviceBehavior::Sequential,
            true,
            3,
            input.size(),
            0,
            -1,
            -1,
        },
        {
            "subdevice_negative_offset",
            DeviceBehavior::Normal,
            true,
            -1,
            1,
            0,
            -1,
            -1,
        },
        {
            "subdevice_zero_size",
            DeviceBehavior::Normal,
            true,
            0,
            0,
            0,
            -1,
            -1,
        },
        {
            "subdevice_negative_size",
            DeviceBehavior::Normal,
            true,
            0,
            -1,
            0,
            -1,
            -1,
        },
        {
            "subdevice_offset_at_end",
            DeviceBehavior::Normal,
            true,
            42,
            1,
            0,
            -1,
            -1,
        },
        {
            "subdevice_crosses_end",
            DeviceBehavior::Normal,
            true,
            41,
            2,
            0,
            -1,
            -1,
        },
        {
            "subdevice_exact_tail",
            DeviceBehavior::Normal,
            true,
            41,
            1,
            0,
            -1,
            -1,
        },
    };

    for (const DeviceCaseSpec &spec : deviceCases) {
        QJsonObject output = runDeviceCase(
            spec,
            fixtureRoot,
            input,
            &error
        );
        if (!error.isEmpty()) {
            std::fprintf(stderr, "%s\n", error.toUtf8().constData());
            return 1;
        }
        outputs.append(output);
    }

    QJsonObject root;
    root.insert("schema_version", 1);
    root.insert("upstream_commit", UPSTREAM_COMMIT);
    root.insert("xscanengine_commit", XSCANENGINE_COMMIT);
    root.insert("die_script_commit", DIE_SCRIPT_COMMIT);
    root.insert("qt_version", qVersion());
    root.insert("case_count", outputs.size());
    root.insert("input_sha256", QString::fromLatin1(inputHash));
    root.insert("cases", outputs);
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
