// egg_unpack - unified ProjectEGG extractor: detects the packing type of a game EXE (or BIND archive)
// and unpacks its contents into a folder named after the input file.
#include <algorithm>
#include <iostream>

#include "common.h"
#include "detect.h"
#include "extractors.h"
#include "platform.h"

namespace {

void PrintUsage() {
    std::cout <<
        "egg_unpack 0.2.2 - unified ProjectEGG extractor\n"
        "\n"
        "  egg_unpack <file>        detect the type\n"
        "  egg_unpack x <file>      extract into a folder next to <file>, named after it\n"
        "  egg_unpack d <file>      extract with verbose debug output (same as: x <file> --debug)\n"
        "\n"
        "Options:  -d, --debug        verbose output (also keeps intermediate files)\n"
        "          -h, --help         this help\n"
        "\n"
        "Exit codes: 0 extracted, 1 failed, 2 type detected but not implemented, 3 nothing to extract\n";
}

struct Options {
    fs::path input;
    bool extract = false;
};

bool ParseArgs(const std::vector<std::string>& args, Options& o) {
    std::vector<std::string> pos;
    for (size_t i = 1; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (a == "-d" || a == "--debug") util::g_debug = true;
        else if (a == "-h" || a == "--help") return false;
        else if (a.size() > 1 && a[0] == '-') { util::PrintErr("Unknown option: " + a); return false; }
        else pos.push_back(a);
    }

    auto lower = [](std::string s) { for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c))); return s; };
    if (pos.size() == 2 && (lower(pos[0]) == "x" || lower(pos[0]) == "d")) {
        o.extract = true;
        if (lower(pos[0]) == "d") util::g_debug = true;
        o.input = platform::PathFromUtf8(pos[1]);
    } else if (pos.size() == 1) {
        o.input = platform::PathFromUtf8(pos[0]);
    } else {
        return false;
    }
    return true;
}

std::string TagList(const Detection& d) {
    std::string s;
    for (size_t i = 0; i < d.types.size(); ++i) s += (i ? ", " : "") + std::string(TypeTag(d.types[i]));
    return s;
}

}  // namespace

int main(int argc, char** argv) {
    platform::InitConsole();
    Options opt;
    if (!ParseArgs(platform::GetArgsUtf8(argc, argv), opt)) {
        PrintUsage();
        return 1;
    }

    Context ctx;
    ctx.input = opt.input;
    const std::string fileName = util::PathToUtf8(ctx.input.filename());

    if (!fs::is_regular_file(ctx.input)) {
        util::Print("File not found: " + util::PathToUtf8(ctx.input));
        return 1;
    }
    Bytes data;
    if (!util::ReadFile(ctx.input, data) || data.empty()) {
        util::Print("Could not read the file (or it is empty): " + fileName);
        return 1;
    }
    ctx.data    = &data;
    ctx.exeName = util::PathToUtf8(ctx.input.stem());

    // --- detection -------------------------------------------------------------------
    Detection det = Detect(data);
    if (!opt.extract) {
        util::Print(FormatLine(fileName, det));
        return 0;
    }
    util::Print("Extracting " + fileName + "...");
    util::Info(FormatLine(fileName, det));

    auto fail = [&](const std::string& reason, int code = 1) {
        util::RemoveDirIfEmpty(ctx.outDir);
        util::Print("Failed to extract " + fileName + ", " + reason);
        return code;
    };
    auto succeed = [&] {
        util::Print("Extracted to " + util::PathToUtf8(ctx.outDir.filename()));
        return 0;
    };

    // --- choose the extractor --------------------------------------------------------------
    if (det.types.empty())
        return fail(det.isPe ? "unrecognized executable type (no known signature found)"
                             : "unrecognized file type");
    if (det.types.size() > 1)
        return fail("several types matched at once (" + TagList(det) + "), not guessing which one to use");

    GameType type = det.types[0];
    if (!HasExtractor(type))
        return fail(std::string(TypeTag(type)) + " was detected, but extraction of this type is not implemented yet", 2);
    util::Info(std::string("Detected: ") + TypeTag(type));

    if (!util::PrepareOutputDir(ctx.input, ctx.outDir)) return fail("could not create the output folder");
    util::Info("Output folder: " + util::PathToUtf8(ctx.outDir));

    util::ClearError();
    bool ok = false;
    switch (type) {
        case GameType::EggData:      ok = ExtractEggData(ctx); break;
        case GameType::Type98:
        case GameType::Type98Old:    ok = ExtractType98(ctx); break;
        case GameType::MsxPlayerOld: ok = ExtractMsxResources(ctx, 1); break;
        case GameType::MsxD4e:       ok = ExtractMsxResources(ctx, 2); break;
        case GameType::OldPc98Aes:
        case GameType::OldPc98NoAes: ok = ExtractOldPc98(ctx); break;
        case GameType::DataFileVer:  ok = ExtractDataFileVer(ctx); break;
        case GameType::OldXorLzss:   ok = ExtractOldXorLzss(ctx); break;
        case GameType::OldX1:        ok = ExtractOldX1(ctx); break;
        case GameType::Bind:         ok = ExtractBind(ctx); break;
        case GameType::Scn:          ok = ExtractScn(ctx); break;
        case GameType::Type60:       ok = ExtractType60(ctx); break;
        default: break;
    }

    if (!ok && util::NothingToExtract()) {                       // a recognized file without embedded data
        util::RemoveDirIfEmpty(ctx.outDir);
        util::Print("Nothing to extract from " + fileName + ", " + util::LastError());
        return 3;
    }
    if (!ok) return fail(util::LastError().empty() ? "nothing could be extracted" : util::LastError());
    return succeed();
}
