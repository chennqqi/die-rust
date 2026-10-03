#include "xmew.h"
#include <QCoreApplication>
#include <QFile>
#include <QTextStream>

static quint32 rd32(const quint8 *p) { return (quint32)(p[0] | ((quint32)p[1]<<8) | ((quint32)p[2]<<16) | ((quint32)p[3]<<24)); }
static quint32 algn(quint32 v, quint32 a) { return (v + a - 1) & ~(a - 1); }
static bool cont(quint64 sz, qint64 off, qint64 len) { return off >= 0 && len >= 0 && (quint64)(off+len) <= sz; }

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);
    QFile f(argv[1]);
    if (!f.open(QIODevice::ReadOnly)) return 1;
    QByteArray data = f.readAll();

    // DETECT values verified already: ver=11 offdiff=0x20 ssize=0x1000
    // dsize=0x1000 srcraw=0x200 srcrsz=0x200 vadd=0x1000 ibase=0x400000 lzma=0
    quint32 ssize = 0x1000, dsize = 0x1000, off = 0x20;
    quint32 vadd = 0x1000, base = 0x400000, vma = base + vadd;
    quint64 sizeSum = (quint64)ssize + dsize;
    QByteArray baBuf((int)sizeSum, (char)0);
    memcpy(baBuf.data() + dsize, data.constData() + 0x200, 0x200);
    quint8 *buf = (quint8 *)baBuf.data();

    qint64 sourceOff = (qint64)dsize + off;
    qint64 lesi = sourceOff + 12;
    quint32 entryPoint = rd32(buf + sourceOff + 4);
    quint32 newEdi = rd32(buf + sourceOff + 8);
    qint64 ledi = (qint64)newEdi - vma;
    qint64 locDs = (qint64)sizeSum - ((qint64)newEdi - vma);
    qint64 locSs = (qint64)ssize - 12 - off;
    out << "entryPoint=0x" << Qt::hex << entryPoint << " newEdi=0x" << newEdi
        << " lesi=0x" << lesi << " ledi=0x" << ledi << " locDs=0x" << locDs
        << " locSs=0x" << locSs << "\n";
    out << "hdr bytes:" << QByteArray((char*)buf + sourceOff, 20).toHex() << "\n";
    out << "stream:" << QByteArray((char*)buf + lesi, 12).toHex() << "\n";
    return 0;
}
