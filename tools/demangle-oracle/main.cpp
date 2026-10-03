// demangle-oracle — runs upstream XDemangle::demangle() on a corpus of
// (mode, symbol) pairs and prints tab-separated results. Usage:
//   demangle-oracle <pairs.txt>
// pairs.txt lines: "<mode>\t<symbol>" with mode = lowercase enum name
// (msvc, msvc32, msvc64, msvcarm32, msvcarm64, gnuv2, gnuv3, gccwin,
// gccmac, java, borland32, borland64, watcom, rust, gnat, dlang, swift,
// go, haskell, ocaml, tru64, sun, auto).
// Output per line: "<mode>\t<symbol>\t<demangled>".

#include <QCoreApplication>
#include <QFile>
#include <QTextStream>
#include "xdemangle.h"

static XDemangle::MODE parseMode(const QString &s)
{
    static const QMap<QString, XDemangle::MODE> m = {
        {"auto", XDemangle::MODE_AUTO},
        {"msvc", XDemangle::MODE_MSVC},
        {"msvc32", XDemangle::MODE_MSVC32},
        {"msvc64", XDemangle::MODE_MSVC64},
        {"msvcarm32", XDemangle::MODE_MSVCARM32},
        {"msvcarm64", XDemangle::MODE_MSVCARM64},
        {"gnuv2", XDemangle::MODE_GNU_V2},
        {"gnuv3", XDemangle::MODE_GNU_V3},
        {"gccwin", XDemangle::MODE_GCC_WIN},
        {"gccmac", XDemangle::MODE_GCC_MAC},
        {"java", XDemangle::MODE_JAVA},
        {"borland32", XDemangle::MODE_BORLAND32},
        {"borland64", XDemangle::MODE_BORLAND64},
        {"watcom", XDemangle::MODE_WATCOM},
        {"rust", XDemangle::MODE_RUST},
        {"gnat", XDemangle::MODE_GNAT},
        {"dlang", XDemangle::MODE_DLANG},
        {"swift", XDemangle::MODE_SWIFT},
        {"go", XDemangle::MODE_GO},
        {"haskell", XDemangle::MODE_HASKELL},
        {"ocaml", XDemangle::MODE_OCAML},
        {"tru64", XDemangle::MODE_TRU64},
        {"sun", XDemangle::MODE_SUN},
    };
    return m.value(s, XDemangle::MODE_UNKNOWN);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (argc != 2) {
        QTextStream(stderr) << "usage: demangle-oracle <pairs.txt>\n";
        return 2;
    }
    QFile f(QString::fromLocal8Bit(argv[1]));
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream(stderr) << "cannot open " << argv[1] << "\n";
        return 2;
    }
    XDemangle demangler;
    QTextStream in(&f);
    QTextStream out(stdout);
    while (!in.atEnd()) {
        QString line = in.readLine();
        if (line.isEmpty() || line.startsWith('#')) continue;
        int tab = line.indexOf('\t');
        if (tab < 0) {
            out << "?ERR\t" << line << "\n";
            continue;
        }
        QString modeName = line.left(tab);
        QString symbol = line.mid(tab + 1);
        XDemangle::MODE mode = parseMode(modeName);
        QString result = demangler.demangle(symbol, mode);
        out << modeName << '\t' << symbol << '\t' << result << '\n';
    }
    return 0;
}
