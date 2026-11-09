#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "ROPFuscatorPass.h"

#include "DLLHelper/DLLGrabberUtility.h"
#include "DLLHelper/OfficialDLLDownloader.h"
#include "DLLHelper/DLLExportGrabber.h"

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace llvm;

llvm::cl::opt<bool> ROPFuscatorEnable("obfropfuscator", llvm::cl::init(true),
    llvm::cl::desc("Enable ROPFuscator (ROP-gadget indirection on calls / loads / stores)"));

static constexpr const char* SystemDir = "C:\\Windows\\System32";
static constexpr unsigned XrefThreshold = 16;
static constexpr unsigned MaxSitesPerFn = 20;
static constexpr unsigned MaxMemSitesPerFn = 8;
static constexpr unsigned MemModuleBudget = 2048;
static constexpr bool SkipLoops = true;
static constexpr bool SkipThunks = true;
static constexpr bool PreferPtrSized = true;

static constexpr unsigned StashOffset = 0x200;
static constexpr int MaxFwdHops = 16;
static constexpr size_t MaxGadgetBytes = 16;

static const char* const SeedHostPool[] = {
    "ntdll.dll", "kernelbase.dll", "win32u.dll", "gdi32full.dll",
    "combase.dll", "sechost.dll", "shcore.dll", "bcrypt.dll", "ucrtbase.dll",
    "kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll",
    "shell32.dll", "shlwapi.dll", "ole32.dll", "oleaut32.dll",
    "ws2_32.dll", "winhttp.dll", "wininet.dll", "msvcrt.dll",
    "crypt32.dll", "psapi.dll", "version.dll", "setupapi.dll",
    "comctl32.dll", "comdlg32.dll", "wintrust.dll", "dbghelp.dll",
};

static constexpr uint64_t SeedSalt = 0x9E3779B9C0AFEE11ULL;

static uint64_t Mix64(uint64_t z)
{
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static uint64_t ModuleNameHash = 0;
static uint64_t SiteCounter = 0;

static uint64_t NextSiteId()
{
    const uint64_t ord = ++SiteCounter;
    return Mix64(ModuleNameHash ^ (ord * 0x9E3779B97F4A7C15ULL));
}

static uint64_t HashModuleUtf16Upper(const std::string& asciilower)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (char c : asciilower)
    {
        uint64_t ch = static_cast<uint64_t>(static_cast<uint8_t>(c));
        if (ch >= 'a' && ch <= 'z') ch -= 0x20;
        h ^= ch;
        h *= 0x100000001b3ULL;
    }
    return h;
}

static bool HasAnnotationTag(Function& f, const char* tag)
{
    Module* m = f.getParent();
    GlobalVariable* ga = m->getGlobalVariable("llvm.global.annotations");
    if (!ga) return false;

    ConstantArray* ca = dyn_cast<ConstantArray>(ga->getOperand(0));
    if (!ca) return false;

    for (unsigned i = 0; i < ca->getNumOperands(); ++i)
    {
        ConstantStruct* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
        if (!cs) continue;
        if (cs->getOperand(0)->stripPointerCasts() != &f) continue;

        auto* strgv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strgv || !strgv->hasInitializer()) continue;

        auto* cds = dyn_cast<ConstantDataSequential>(strgv->getInitializer());
        if (!cds || !cds->isString()) continue;

        if (cds->getAsCString() == tag) return true;
    }
    return false;
}

static bool HasNoROPAnnotation(Function& f)
{
    return HasAnnotationTag(f, "norop");
}

static std::string ToLowerASCII(std::string s)
{
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

static bool IsAPISet(const std::string& n)
{
    return n.rfind("api-ms-", 0) == 0 || n.rfind("ext-ms-", 0) == 0;
}

static std::string UnmangleCName(StringRef n)
{
    std::string s = n.str();
    if (!s.empty() && s[0] == '_') s.erase(0, 1);
    const size_t at = s.find('@');
    if (at != std::string::npos) s.resize(at);
    return s;
}

static bool IsEligibleDLLImport(const Function& f)
{
    if (!f.isDeclaration()) return false;
    if (f.isIntrinsic()) return false;
    if (!f.hasDLLImportStorageClass()) return false;
    if (f.getLinkage() != GlobalValue::ExternalLinkage) return false;
    return true;
}

struct HostState
{
    bool sourced = false;
    std::wstring canonicalpath;
    DLLExportGrabber::ExportTable exports;
};

static bool SourceHost(const std::string& host, HostState& out)
{
    out.sourced = false;
    if (IsAPISet(host)) return false;

    std::filesystem::path syspath(SystemDir);
    syspath /= host;

    DLLGrabberUtility::DllIdentity id;
    std::wstring err;
    if (!DLLGrabberUtility::Instance().GrabIdentity(syspath.wstring(), id, err)) return false;

    OfficialDllDownloader::DownloadResult dr;
    if (OfficialDllDownloader::Instance().TryGetCachedDll(id.DllName, id.TimeDateStamp, id.SizeOfImage, dr) && dr.Success)
    {
        out.canonicalpath = dr.OutputPath;
    }
    else if (OfficialDllDownloader::Instance().DownloadDll(id.DllName, id.TimeDateStamp, id.SizeOfImage, dr) && dr.Success)
    {
        out.canonicalpath = dr.OutputPath;
    }
    else
    {
        return false;
    }

    if (!DLLExportGrabber::Instance().GrabExports(out.canonicalpath, out.exports, err)) return false;
    out.sourced = true;
    return true;
}

static bool ResolveImport(const std::string& firsthost, const std::string& firstname, std::map<std::string, HostState>& hosts, std::string& outhost, uint32_t& outrva)
{
    std::string host = firsthost;
    std::string name = firstname;
    for (int hop = 0; hop <= MaxFwdHops; ++hop)
    {
        if (IsAPISet(host)) return false;
        auto it = hosts.find(host);
        if (it == hosts.end())
        {
            HostState hs;
            SourceHost(host, hs);
            auto ins = hosts.emplace(host, std::move(hs));
            it = ins.first;
        }
        if (!it->second.sourced) return false;
        const DLLExportGrabber::ExportTable& t = it->second.exports;
        auto ni = t.NameToIndex.find(name);
        if (ni == t.NameToIndex.end()) return false;
        const DLLExportGrabber::ExportEntry& e = t.Entries[ni->second];
        if (!e.Forwarded)
        {
            outhost = host;
            outrva = e.Rva;
            return true;
        }
        if (e.ForwardApiset) return false;
        if (e.ForwardByOrdinal) return false;
        if (e.ForwardDll.empty() || e.ForwardName.empty()) return false;
        host = e.ForwardDll;
        name = e.ForwardName;
    }
    return false;
}

static FunctionCallee GetModuleHandleADecl(Module& m)
{
    LLVMContext& c = m.getContext();
    PointerType* ptrty = PointerType::get(c, 0);
    FunctionType* ft = FunctionType::get(ptrty, {ptrty}, false);
    FunctionCallee cal = m.getOrInsertFunction("GetModuleHandleA", ft);
    if (Function* f = dyn_cast<Function>(cal.getCallee()))
    {
        f->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
        f->setLinkage(GlobalValue::ExternalLinkage);
    }
    return cal;
}

struct JmpGadget
{
    uint32_t rva;
    uint8_t reg;
    uint8_t modidx;
    uint8_t len;
};

struct MemGadget
{
    uint32_t rva;
    uint8_t dst;
    uint8_t base;
    int32_t disp;
    uint8_t opsize;
    uint8_t modidx;
    uint8_t len;
};

struct DllModule
{
    std::string namelower;
    std::wstring canonicalpath;
    uint32_t sizeofimage;
    uint8_t modidx;
    uint64_t namehash;
};

struct UsedGadget
{
    uint8_t modidx;
    uint32_t rva;
    uint8_t len;
    std::array<uint8_t, MaxGadgetBytes> bytes;
};

static std::vector<DllModule> DLLModules;
static std::vector<JmpGadget> JmpPool;
static std::vector<MemGadget> LoadPool;
static std::vector<MemGadget> StorePool;
static std::once_flag HarvestOnceFlag;
static std::vector<UsedGadget> UsedGadgets;
static DenseMap<Function*, DenseSet<uint8_t>> SlotFillDone;
static std::string NameSuffix;

// Loader patches every byte inside a .reloc fixup, so gadgets whose byte range overlaps any reloc target have a different byte image at runtime than what we scanned on disk. Dispatch would land in the right RVA but the opcode bytes would be wrong, so filter out any gadget overlapping the reloc table
static bool ScanDLLFile(const std::wstring& path, uint8_t modidx, uint32_t& outsizeofimage)
{
    outsizeofimage = 0;
    std::ifstream f(path.c_str(), std::ios::binary | std::ios::ate);
    if (!f) return false;
    const std::streamoff sz = f.tellg();
    if (sz < 0x400) return false;
    std::vector<uint8_t> img(static_cast<size_t>(sz));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(img.data()), sz);
    if (!f) return false;

    const uint32_t lfanew = *reinterpret_cast<const uint32_t*>(img.data() + 0x3C);
    if (lfanew + 0x18 > img.size()) return false;
    if (*reinterpret_cast<const uint32_t*>(img.data() + lfanew) != 0x00004550) return false;
    const uint8_t* fh = img.data() + lfanew + 4;
    const uint16_t nsec = *reinterpret_cast<const uint16_t*>(fh + 0x02);
    const uint16_t optsz = *reinterpret_cast<const uint16_t*>(fh + 0x10);
    const uint8_t* sec = fh + 0x14 + optsz;
    if (sec + static_cast<size_t>(nsec) * 40 > img.data() + img.size()) return false;
    if (optsz >= 0x3C)
    {
        const uint8_t* opt = fh + 0x14;
        if (*reinterpret_cast<const uint16_t*>(opt) == 0x20B)
            outsizeofimage = *reinterpret_cast<const uint32_t*>(opt + 0x38);
    }

    struct Range
    {
        uint32_t s;
        uint32_t e;
    };
    std::vector<Range> relocs;
    if (optsz >= 0x90)
    {
        const uint8_t* opt = fh + 0x14;
        const uint32_t rrva = *reinterpret_cast<const uint32_t*>(opt + 0x88);
        const uint32_t rsz = *reinterpret_cast<const uint32_t*>(opt + 0x8C);
        if (rrva && rsz)
        {
            const uint8_t* s2 = fh + 0x14 + optsz;
            uint32_t roff = 0;
            for (uint16_t s = 0; s < nsec; ++s, s2 += 40)
            {
                const uint32_t va = *reinterpret_cast<const uint32_t*>(s2 + 0x0C);
                const uint32_t rs = *reinterpret_cast<const uint32_t*>(s2 + 0x10);
                if (rrva >= va && rrva < va + rs)
                {
                    roff = *reinterpret_cast<const uint32_t*>(s2 + 0x14) + (rrva - va);
                    break;
                }
            }
            uint32_t off = roff;
            const uint32_t end = static_cast<uint32_t>(std::min<size_t>(static_cast<size_t>(off) + rsz, img.size()));
            while (off && off + 8 <= end)
            {
                const uint32_t blkva = *reinterpret_cast<const uint32_t*>(img.data() + off);
                const uint32_t blksz = *reinterpret_cast<const uint32_t*>(img.data() + off + 4);
                if (blksz < 8 || off + blksz > img.size()) break;
                const uint32_t n = (blksz - 8) / 2;
                for (uint32_t i = 0; i < n; ++i)
                {
                    const uint16_t e = *reinterpret_cast<const uint16_t*>(img.data() + off + 8 + i * 2);
                    if ((e >> 12) == 0) continue;
                    const uint32_t rva = blkva + (e & 0x0FFF);
                    relocs.push_back({rva, rva + 8});
                }
                off += blksz;
            }
        }
    }
    auto overlapsreloc = [&](uint32_t rva, uint32_t len)
    {
        for (const Range& r : relocs)
        {
            if (rva < r.e && rva + len > r.s) return true;
        }
        return false;
    };

    const uint8_t* seciter = fh + 0x14 + optsz;
    for (uint16_t s = 0; s < nsec; ++s, seciter += 40)
    {
        const uint32_t virtaddr = *reinterpret_cast<const uint32_t*>(seciter + 0x0C);
        const uint32_t rawsz = *reinterpret_cast<const uint32_t*>(seciter + 0x10);
        const uint32_t rawptr = *reinterpret_cast<const uint32_t*>(seciter + 0x14);
        const uint32_t chars = *reinterpret_cast<const uint32_t*>(seciter + 0x24);
        if (!(chars & 0x20000000)) continue;
        if (rawptr >= img.size()) continue;
        const size_t avail = std::min<size_t>(rawsz, img.size() - rawptr);
        const uint8_t* b = img.data() + rawptr;

        for (size_t p = 0; p + 2 < avail; ++p)
        {
            const uint8_t b0 = b[p];
            const uint8_t b1 = b[p + 1];

            // only reg codes {0, 10, 11} = {rax, r10, r11}. The x64 volatile non argument GPRs; rcx/rdx/r8/r9 hold incoming call arguments and must not become the gadget's working register or the dispatched callee sees scrambled args
            auto recordjmp = [&](uint8_t regcode, uint32_t glen)
            {
                if (regcode != 0 && regcode != 10 && regcode != 11) return;
                const uint32_t rva = virtaddr + static_cast<uint32_t>(p);
                if (overlapsreloc(rva, glen)) return;
                JmpPool.push_back({rva, regcode, modidx, static_cast<uint8_t>(glen)});
            };

            if (b0 == 0xFF && b1 >= 0xE0 && b1 <= 0xE7)
            {
                recordjmp(static_cast<uint8_t>(b1 & 7), 2);
            }
            else if (b0 == 0x41 && p + 2 < avail && b[p + 1] == 0xFF && b[p + 2] >= 0xE0 && b[p + 2] <= 0xE7)
            {
                recordjmp(static_cast<uint8_t>((b[p + 2] & 7) | 8), 3);
            }

            const uint32_t rpfx = (b0 >= 0x40 && b0 <= 0x4F) ? 1u : 0u;
            const uint8_t rex = rpfx ? b0 : 0;
            if (p + rpfx + 2 >= avail) continue;
            const uint8_t op = rpfx ? b1 : b0;
            const uint8_t mrm = b[p + rpfx + 1];
            if (op != 0x8B && op != 0x89) continue;
            const uint8_t mod = static_cast<uint8_t>(mrm >> 6);
            const uint8_t rm = static_cast<uint8_t>(mrm & 7);
            if (mod == 3) continue;
            if (rm == 4) continue;
            if (mod == 0 && rm == 5) continue;

            uint32_t dispbytes = (mod == 1) ? 1 : (mod == 2) ? 4 : 0;
            const uint32_t hdr = rpfx + 2;
            const uint32_t total = hdr + dispbytes + 1;
            if (p + total > avail) continue;
            if (b[p + hdr + dispbytes] != 0xC3) continue;

            const uint8_t regcode = static_cast<uint8_t>(((mrm >> 3) & 7) | ((rex & 0x04) ? 8 : 0));
            const uint8_t basecode = static_cast<uint8_t>((mrm & 7) | ((rex & 0x01) ? 8 : 0));
            if (regcode == 4 || basecode == 4) continue;
            // Exclude RBP (code 5). If the enclosing function uses RBP as its frame pointer, binding our asm's {dst} or {base} to rbp lets the gadget overwrite the frame pointer mid-function and every subsequent `[rbp-K]` stack-slot access then dereferences whatever we loaded, producing an access violation that looks like unrelated code
            if (regcode == 5 || basecode == 5) continue;

            int32_t disp = 0;
            if (dispbytes == 1)
            {
                disp = static_cast<int8_t>(b[p + hdr]);
            }
            else if (dispbytes == 4)
            {
                int32_t t;
                std::memcpy(&t, b + p + hdr, 4);
                disp = t;
            }
            const uint8_t opsize = (rex & 0x08) ? 8 : 4;
            const uint32_t rva = virtaddr + static_cast<uint32_t>(p);
            if (overlapsreloc(rva, total)) continue;

            MemGadget g{rva, regcode, basecode, disp, opsize, modidx, static_cast<uint8_t>(total)};
            if (op == 0x8B) LoadPool.push_back(g);
            else StorePool.push_back(g);
        }
    }
    return true;
}

static bool HarvestDLL(const std::string& nmlower)
{
#ifdef _WIN32
    for (const DllModule& m : DLLModules)
    {
        if (m.namelower == nmlower) return true;
    }

    std::filesystem::path syspath(SystemDir);
    syspath /= nmlower;

    DLLGrabberUtility::DllIdentity id;
    std::wstring err;
    if (!DLLGrabberUtility::Instance().GrabIdentity(syspath.wstring(), id, err)) return false;

    OfficialDllDownloader::DownloadResult dr;
    if (!OfficialDllDownloader::Instance().TryGetCachedDll(id.DllName, id.TimeDateStamp, id.SizeOfImage, dr) || !dr.Success)
    {
        if (!OfficialDllDownloader::Instance().DownloadDll(id.DllName, id.TimeDateStamp, id.SizeOfImage, dr) || !dr.Success) return false;
    }

    DllModule mod;
    mod.namelower = nmlower;
    mod.canonicalpath = dr.OutputPath;
    mod.sizeofimage = id.SizeOfImage;
    mod.modidx = static_cast<uint8_t>(DLLModules.size());
    mod.namehash = HashModuleUtf16Upper(nmlower);
    DLLModules.push_back(mod);

    uint32_t soi = 0;
    if (!ScanDLLFile(mod.canonicalpath, mod.modidx, soi)) return false;
    return true;
#else
    (void)nmlower;
    return false;
#endif
}

static std::vector<std::string> DiscoverImportedDLLs(Module& m)
{
    std::vector<std::string> out;
#ifdef _WIN32
    std::unordered_set<std::string> seen;
    std::map<std::string, HostState> hosts;

    for (Function& f : m)
    {
        if (!IsEligibleDLLImport(f)) continue;
        const std::string cname = UnmangleCName(f.getName());
        for (const char* seed : SeedHostPool)
        {
            const std::string hostlower = seed;
            auto it = hosts.find(hostlower);
            if (it == hosts.end())
            {
                HostState hs;
                SourceHost(hostlower, hs);
                it = hosts.emplace(hostlower, std::move(hs)).first;
            }
            if (!it->second.sourced) continue;
            if (!it->second.exports.NameToIndex.count(cname)) continue;
            std::string termhost;
            uint32_t termrva = 0;
            if (ResolveImport(hostlower, cname, hosts, termhost, termrva))
            {
                if (seen.insert(termhost).second) out.push_back(termhost);
                break;
            }
        }
    }
#else
    (void)m;
#endif
    return out;
}

static void HarvestOnce()
{
#ifdef _WIN32
    std::call_once(HarvestOnceFlag, []() {});
#else
    (void)HarvestOnceFlag;
#endif
}

static std::string ROPFuscatorSym(const char* stem)
{
    return std::string(stem) + "_" + NameSuffix;
}

// inline asm references need a globally visible COFF symbol for the linker. InternalLinkage GVs get a `.N` suffix that inline asm cannot see, so use ExternalLinkage + HiddenVisibility + appendToCompilerUsed to anchor the GV without exposing it as a dynamic export
static void AnchorROPFuscatorGV(Module& m, GlobalVariable* gv)
{
    gv->setLinkage(GlobalValue::ExternalLinkage);
    gv->setVisibility(GlobalValue::HiddenVisibility);
    gv->setDSOLocal(true);
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    appendToCompilerUsed(m, {gv});
}

static GlobalVariable* GetOrCreateSlotsGV(Module& m, size_t nmodules)
{
    const std::string name = ROPFuscatorSym("__ropf_slots");
    if (GlobalVariable* existing = m.getGlobalVariable(name)) return existing;
    LLVMContext& c = m.getContext();
    Type* i64 = Type::getInt64Ty(c);
    ArrayType* arrty = ArrayType::get(i64, nmodules);
    GlobalVariable* gv = new GlobalVariable(m, arrty, false, GlobalValue::ExternalLinkage, ConstantAggregateZero::get(arrty), name);
    gv->setAlignment(Align(8));
    AnchorROPFuscatorGV(m, gv);
    return gv;
}

static GlobalVariable* GetOrCreateDLLNameGV(Module& m, const std::string& nm)
{
    const std::string gvname = ROPFuscatorSym("__ropf_name") + "_" + std::to_string(std::hash<std::string>{}(nm));
    if (GlobalVariable* existing = m.getGlobalVariable(gvname)) return existing;
    LLVMContext& c = m.getContext();
    Constant* init = ConstantDataArray::getString(c, nm, true);
    GlobalVariable* gv = new GlobalVariable(m, init->getType(), true, GlobalValue::PrivateLinkage, init, gvname);
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

struct Dispatch
{
    uint32_t enc;
    uint32_t key;
    uint64_t siteid;
    uint8_t modidx;
    uint32_t gadgetrva;
};

static Dispatch MakeDispatch(uint8_t modidx, uint32_t gadgetrva)
{
    Dispatch d;
    d.siteid = NextSiteId();
    d.modidx = modidx;
    d.gadgetrva = gadgetrva;
    const uint64_t mix = Mix64(SeedSalt ^ d.siteid ^ (static_cast<uint64_t>(modidx) << 32) ^ static_cast<uint64_t>(gadgetrva));
    d.key = static_cast<uint32_t>(mix ^ (mix >> 32));
    d.enc = static_cast<uint32_t>(gadgetrva) ^ d.key;
    return d;
}

static void RecordUsed(uint8_t modidx, uint32_t rva, uint8_t len)
{
    UsedGadget ug{};
    ug.modidx = modidx;
    ug.rva = rva;
    ug.len = len;
    ug.bytes.fill(0);
    UsedGadgets.push_back(ug);
}

static void TagROPFuscator(Instruction* i)
{
    LLVMContext& c = i->getContext();
    i->setMetadata("lic.phase1", MDNode::get(c, {MDString::get(c, "p1")}));
    i->setMetadata("lic.rop", MDNode::get(c, {MDString::get(c, "p3")}));
}

static uint8_t PickScratch(std::initializer_list<uint8_t> forbidden)
{
    for (uint8_t cand : {static_cast<uint8_t>(0), static_cast<uint8_t>(10), static_cast<uint8_t>(11)})
    {
        bool bad = false;
        for (uint8_t f : forbidden)
        {
            if (f == cand)
            {
                bad = true;
                break;
            }
        }
        if (!bad) return cand;
    }
    return 0xFF;
}

static const char* RegName64(uint8_t code)
{
    static const char* k[] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    };
    return k[code & 15];
}

static const char* RegName32(uint8_t code)
{
    static const char* k[] = {
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    };
    return k[code & 15];
}

static std::string EmitStashSaveOpen(unsigned preshift, const char* stashreg)
{
    const unsigned off = StashOffset - preshift - 8;
    std::ostringstream o;
    o << "pushq %" << stashreg << "\n\t"
      << "movq -" << off << "(%rsp), %" << stashreg << "\n\t";
    return o.str();
}

static std::string EmitStashRestoreClose(unsigned preshift, const char* stashreg)
{
    const unsigned off = StashOffset - preshift - 8;
    std::ostringstream o;
    o << "movq %" << stashreg << ", -" << off << "(%rsp)\n\t"
      << "popq %" << stashreg << "\n\t";
    return o.str();
}

static const char* PickStashReg(uint8_t avoida, uint8_t avoidb)
{
    static const struct
    {
        uint8_t code;
        const char* name;
    } cands[] = {
        {3, "rbx"}, {14, "r14"}, {15, "r15"}, {12, "r12"},
        {13, "r13"}, {7, "rdi"}, {6, "rsi"}, {5, "rbp"},
    };
    for (const auto& c : cands)
    {
        if (c.code != avoida && c.code != avoidb) return c.name;
    }
    return nullptr;
}

static void EnsureSlotFilled(Function* f, GlobalVariable* slotsgv, uint8_t modidx)
{
    auto& done = SlotFillDone[f];
    if (!done.insert(modidx).second) return;

    LLVMContext& c = f->getContext();
    BasicBlock& entry = f->getEntryBlock();
    IRBuilder<> b(&entry, entry.getFirstInsertionPt());

    FunctionCallee gmh = GetModuleHandleADecl(*f->getParent());
    FunctionType* llaft = FunctionType::get(PointerType::get(c, 0), {PointerType::get(c, 0)}, false);
    FunctionCallee lla = f->getParent()->getOrInsertFunction("LoadLibraryA", llaft);
    if (Function* lf = dyn_cast<Function>(lla.getCallee()))
    {
        lf->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
        lf->setLinkage(GlobalValue::ExternalLinkage);
    }

    Type* i64 = Type::getInt64Ty(c);
    Type* ptrty = PointerType::get(c, 0);
    Constant* nullptr_ = ConstantPointerNull::get(cast<PointerType>(ptrty));

    const DllModule& m = DLLModules[modidx];
    GlobalVariable* namegv = GetOrCreateDLLNameGV(*f->getParent(), m.namelower);

    Value* h0 = b.CreateCall(gmh, {namegv}, "ROPFPFH0");
    Value* nz = b.CreateICmpNE(h0, nullptr_, "ROPFPFHOk");

    BasicBlock* curbb = b.GetInsertBlock();
    BasicBlock* bbtail = curbb->splitBasicBlock(b.GetInsertPoint(), "ROPFPFAfter");
    BasicBlock* bbll = BasicBlock::Create(c, "ROPFPFLL", f, bbtail);
    curbb->getTerminator()->eraseFromParent();
    IRBuilder<>(curbb).CreateCondBr(nz, bbtail, bbll);

    IRBuilder<> bl(bbll);
    Value* h1 = bl.CreateCall(lla, {namegv}, "ROPFPFH1");
    bl.CreateBr(bbtail);

    IRBuilder<> bt(bbtail, bbtail->getFirstInsertionPt());
    PHINode* h = bt.CreatePHI(ptrty, 2, "ROPFPFH");
    h->addIncoming(h0, curbb);
    h->addIncoming(h1, bbll);
    Value* hi = bt.CreatePtrToInt(h, i64, "ROPFPFHI");
    Value* idx[2] = {
        ConstantInt::get(Type::getInt32Ty(c), 0),
        ConstantInt::get(Type::getInt32Ty(c), static_cast<uint32_t>(modidx)),
    };
    Value* slot = bt.CreateGEP(slotsgv->getValueType(), slotsgv, idx, "ROPFPFSlot");
    bt.CreateStore(hi, slot);
}

static bool TryEmitSiteA(CallBase* cb)
{
    Value* callee = cb->getCalledOperand();
    if (!callee) return false;
    auto* i2p = dyn_cast<IntToPtrInst>(callee);
    if (!i2p) return false;
    if (!i2p->getMetadata("lic.phase1")) return false;

    if (isa<InvokeInst>(cb)) return false;
    if (JmpPool.empty()) return false;

    const uint64_t sid = NextSiteId();
    std::mt19937_64 rng(SeedSalt ^ sid ^ 0xCA11B0BAULL);
    const JmpGadget& g = JmpPool[rng() % JmpPool.size()];
    const uint8_t rt = g.reg;
    const uint8_t scr = PickScratch({rt});
    if (scr == 0xFF) return false;

    const Dispatch d = MakeDispatch(g.modidx, g.rva);

    Function* parent = cb->getFunction();
    LLVMContext& c = parent->getContext();
    IRBuilder<> b(cb);

    EnsureSlotFilled(parent, GetOrCreateSlotsGV(*parent->getParent(), DLLModules.size()), g.modidx);

    Type* rett = cb->getType();
    const bool hasret = !rett->isVoidTy();

    Value* fpi64 = nullptr;
    if (Value* src = i2p->getOperand(0))
    {
        if (src->getType()->isIntegerTy(64)) fpi64 = src;
    }
    if (!fpi64) fpi64 = b.CreatePtrToInt(callee, Type::getInt64Ty(c));

    const unsigned nargs = cb->arg_size();
    static const char* const IntRegs[4] = {"{rcx}", "{rdx}", "{r8}", "{r9}"};
    static const char* const FloatRegs[4] = {"{xmm0}", "{xmm1}", "{xmm2}", "{xmm3}"};
    if (nargs > 4) return false;
    if (cb->getFunctionType()->isVarArg()) return false;

    uint8_t fpreg = 0xFF;
    for (uint8_t cand : {static_cast<uint8_t>(0), static_cast<uint8_t>(10), static_cast<uint8_t>(11)})
    {
        if (cand != rt && cand != scr)
        {
            fpreg = cand;
            break;
        }
    }
    if (fpreg == 0xFF) return false;
    const char* fpregname = RegName64(fpreg);

    SmallVector<Value*, 8> ins;
    SmallVector<Type*, 8> intys;
    std::string cons;

    if (hasret)
    {
        if (rett->isFloatingPointTy()) cons = "={xmm0},";
        else if (rett->isIntegerTy() || rett->isPointerTy()) cons = "={rax},";
        else return false;
    }

    cons += "{";
    cons += fpregname;
    cons += "},";
    ins.push_back(fpi64);
    intys.push_back(Type::getInt64Ty(c));

    for (unsigned i = 0; i < nargs; ++i)
    {
        Value* a = cb->getArgOperand(i);
        Type* t = a->getType();
        if (t->isPointerTy())
        {
            a = b.CreatePtrToInt(a, Type::getInt64Ty(c));
            t = Type::getInt64Ty(c);
        }
        if (t->isIntegerTy())
        {
            if (t->getIntegerBitWidth() < 64)
            {
                a = b.CreateZExt(a, Type::getInt64Ty(c));
                t = Type::getInt64Ty(c);
            }
            cons += IntRegs[i];
            cons += ",";
        }
        else if (t->isFloatingPointTy())
        {
            cons += FloatRegs[i];
            cons += ",";
        }
        else
        {
            return false;
        }
        ins.push_back(a);
        intys.push_back(t);
    }

    std::ostringstream asmt;
    constexpr unsigned preshift = 8u;
    asmt << "pushfq\n\t";
    const char* stashrega = PickStashReg(0xFE, 0xFE);
    asmt << EmitStashSaveOpen(preshift, stashrega);
    asmt << "movq %" << fpregname << ", %" << RegName64(rt) << "\n\t";
    asmt << "movabsq $$" << static_cast<unsigned long long>(d.enc) << ", %" << RegName64(scr) << "\n\t";
    asmt << "xorl $$" << static_cast<unsigned>(d.key) << ", %" << RegName32(scr) << "\n\t";
    asmt << "addq " << ROPFuscatorSym("__ropf_slots") << "+" << (static_cast<unsigned>(d.modidx) * 8) << "(%rip), %" << RegName64(scr) << "\n\t";
    asmt << "callq *%" << RegName64(scr) << "\n\t";
    asmt << EmitStashRestoreClose(preshift, stashrega);
    asmt << "popfq";

    cons +=
        "~{rsi},~{rdi},"
        "~{xmm4},~{xmm5},~{xmm6},~{xmm7},"
        "~{xmm8},~{xmm9},~{xmm10},~{xmm11},"
        "~{xmm12},~{xmm13},~{xmm14},~{xmm15},"
        "~{memory},~{cc},~{dirflag},~{fpsr}";
    if (!hasret || !rett->isFloatingPointTy()) cons += ",~{xmm0},~{xmm1},~{xmm2},~{xmm3}";
    const bool raxasoutput = hasret && (rett->isIntegerTy() || rett->isPointerTy());
    if (!raxasoutput && fpreg != 0) cons += ",~{rax}";
    if (fpreg != 10) cons += ",~{r10}";
    if (fpreg != 11) cons += ",~{r11}";
    for (unsigned i = nargs; i < 4; ++i) cons += (std::string(",~") + IntRegs[i]);

    Type* asmrett = rett;
    if (hasret && (rett->isIntegerTy() || rett->isPointerTy())) asmrett = Type::getInt64Ty(c);
    FunctionType* iaft = FunctionType::get(hasret ? asmrett : Type::getVoidTy(c), intys, false);
    InlineAsm* ia = InlineAsm::get(iaft, asmt.str(), cons, true, false, InlineAsm::AD_ATT);
    CallInst* newcall = b.CreateCall(ia, ins);
    newcall->setDebugLoc(cb->getDebugLoc());
    TagROPFuscator(newcall);

    if (hasret)
    {
        Value* result = newcall;
        if (rett->isPointerTy()) result = b.CreateIntToPtr(result, rett);
        else if (rett->isIntegerTy() && rett->getIntegerBitWidth() < 64) result = b.CreateTrunc(result, rett);
        cb->replaceAllUsesWith(result);
    }
    cb->eraseFromParent();

    RecordUsed(g.modidx, g.rva, g.len);
    return true;
}

static bool TryEmitSiteB(LoadInst* li)
{
    if (li->isVolatile() || li->isAtomic()) return false;
    Type* valt = li->getType();
    unsigned bits = 0;
    if (valt->isIntegerTy()) bits = valt->getIntegerBitWidth();
    else if (valt->isPointerTy()) bits = 64;
    else return false;
    if (bits != 32 && bits != 64) return false;
    const uint8_t width = static_cast<uint8_t>(bits / 8);

    std::vector<const MemGadget*> ok;
    for (const MemGadget& g : LoadPool)
    {
        if (g.opsize == width && g.dst != g.base) ok.push_back(&g);
    }
    if (ok.empty()) return false;
    const uint64_t sid = NextSiteId();
    std::mt19937_64 rng(SeedSalt ^ sid ^ 0xBEEFULL);
    const MemGadget& g = *ok[rng() % ok.size()];

    const Dispatch d = MakeDispatch(g.modidx, g.rva);

    Function* parent = li->getFunction();
    LLVMContext& c = parent->getContext();
    IRBuilder<> b(li);

    EnsureSlotFilled(parent, GetOrCreateSlotsGV(*parent->getParent(), DLLModules.size()), g.modidx);

    Value* addri64 = b.CreatePtrToInt(li->getPointerOperand(), Type::getInt64Ty(c));

    const uint8_t basereg = g.base;
    const uint8_t dstreg = g.dst;
    const uint8_t scr = PickScratch({basereg, dstreg});
    if (scr == 0xFF) return false;

    const std::string dstcons = std::string("={") + RegName64(dstreg) + "}";
    const std::string basecons = std::string("{") + RegName64(basereg) + "}";

    const char* stashregb = PickStashReg(basereg, dstreg);
    const bool dostashb = stashregb != nullptr;

    std::ostringstream asmt;
    constexpr unsigned preshiftb = 8u;
    asmt << "pushfq\n\t";
    if (dostashb) asmt << EmitStashSaveOpen(preshiftb, stashregb);
    if (g.disp != 0)
    {
        asmt << "leaq " << (-static_cast<int64_t>(g.disp)) << "(%" << RegName64(basereg) << "), %" << RegName64(basereg) << "\n\t";
    }
    asmt << "movabsq $$" << static_cast<unsigned long long>(d.enc) << ", %" << RegName64(scr) << "\n\t";
    asmt << "xorl $$" << static_cast<unsigned>(d.key) << ", %" << RegName32(scr) << "\n\t";
    asmt << "addq " << ROPFuscatorSym("__ropf_slots") << "+" << (static_cast<unsigned>(d.modidx) * 8) << "(%rip), %" << RegName64(scr) << "\n\t";
    asmt << "callq *%" << RegName64(scr) << "\n\t";
    if (dostashb) asmt << EmitStashRestoreClose(preshiftb, stashregb);
    asmt << "popfq";

    std::string cons = dstcons + "," + basecons + ",";
    cons += "~{memory},~{cc},~{dirflag},~{fpsr}";
    if (scr != dstreg && scr != basereg) cons += (std::string(",~{") + RegName64(scr) + "}");

    FunctionType* iaft = FunctionType::get(Type::getInt64Ty(c), {Type::getInt64Ty(c)}, false);
    InlineAsm* ia = InlineAsm::get(iaft, asmt.str(), cons, true, false, InlineAsm::AD_ATT);
    CallInst* ac = b.CreateCall(ia, {addri64});
    ac->setDebugLoc(li->getDebugLoc());
    TagROPFuscator(ac);

    Value* result = ac;
    if (width == 4) result = b.CreateTrunc(result, Type::getInt32Ty(c));
    if (valt->isPointerTy()) result = b.CreateIntToPtr(result, valt);

    li->replaceAllUsesWith(result);
    li->eraseFromParent();

    RecordUsed(g.modidx, g.rva, g.len);
    return true;
}

static bool TryEmitSiteC(StoreInst* si)
{
    if (si->isVolatile() || si->isAtomic()) return false;
    Value* val = si->getValueOperand();
    Type* valt = val->getType();
    unsigned bits = 0;
    if (valt->isIntegerTy()) bits = valt->getIntegerBitWidth();
    else if (valt->isPointerTy()) bits = 64;
    else return false;
    if (bits != 32 && bits != 64) return false;
    const uint8_t width = static_cast<uint8_t>(bits / 8);

    std::vector<const MemGadget*> ok;
    for (const MemGadget& g : StorePool)
    {
        if (g.opsize == width && g.dst != g.base) ok.push_back(&g);
    }
    if (ok.empty()) return false;

    const uint64_t sid = NextSiteId();
    std::mt19937_64 rng(SeedSalt ^ sid ^ 0xDEADULL);
    std::vector<const MemGadget*> ok2;
    for (const MemGadget* gp : ok)
    {
        if (PickScratch({gp->dst, gp->base}) != 0xFF) ok2.push_back(gp);
    }
    if (ok2.empty()) return false;
    const MemGadget& g = *ok2[rng() % ok2.size()];

    const uint8_t srcreg = g.dst;
    const uint8_t basereg = g.base;
    const uint8_t scr = PickScratch({srcreg, basereg});

    const Dispatch d = MakeDispatch(g.modidx, g.rva);

    Function* parent = si->getFunction();
    LLVMContext& c = parent->getContext();
    IRBuilder<> b(si);

    EnsureSlotFilled(parent, GetOrCreateSlotsGV(*parent->getParent(), DLLModules.size()), g.modidx);

    Value* addri64 = b.CreatePtrToInt(si->getPointerOperand(), Type::getInt64Ty(c));
    Value* vali64;
    if (valt->isPointerTy()) vali64 = b.CreatePtrToInt(val, Type::getInt64Ty(c));
    else if (valt->isIntegerTy(64)) vali64 = val;
    else vali64 = b.CreateZExt(val, Type::getInt64Ty(c));

    const std::string basecons = std::string("{") + RegName64(basereg) + "}";
    const std::string srccons = std::string("{") + RegName64(srcreg) + "}";

    const char* stashregc = PickStashReg(basereg, srcreg);
    const bool dostashc = stashregc != nullptr;

    std::ostringstream asmt;
    constexpr unsigned preshiftc = 8u;
    asmt << "pushfq\n\t";
    if (dostashc) asmt << EmitStashSaveOpen(preshiftc, stashregc);
    if (g.disp != 0)
    {
        asmt << "leaq " << (-static_cast<int64_t>(g.disp)) << "(%" << RegName64(basereg) << "), %" << RegName64(basereg) << "\n\t";
    }
    asmt << "movabsq $$" << static_cast<unsigned long long>(d.enc) << ", %" << RegName64(scr) << "\n\t";
    asmt << "xorl $$" << static_cast<unsigned>(d.key) << ", %" << RegName32(scr) << "\n\t";
    asmt << "addq " << ROPFuscatorSym("__ropf_slots") << "+" << (static_cast<unsigned>(d.modidx) * 8) << "(%rip), %" << RegName64(scr) << "\n\t";
    asmt << "callq *%" << RegName64(scr) << "\n\t";
    if (dostashc) asmt << EmitStashRestoreClose(preshiftc, stashregc);
    asmt << "popfq";

    std::string cons = basecons + "," + srccons + ",";
    cons += "~{memory},~{cc},~{dirflag},~{fpsr}";
    cons += (std::string(",~{") + RegName64(scr) + "}");

    FunctionType* iaft = FunctionType::get(Type::getVoidTy(c), {Type::getInt64Ty(c), Type::getInt64Ty(c)}, false);
    InlineAsm* ia = InlineAsm::get(iaft, asmt.str(), cons, true, false, InlineAsm::AD_ATT);
    CallInst* ac = b.CreateCall(ia, {addri64, vali64});
    ac->setDebugLoc(si->getDebugLoc());
    TagROPFuscator(ac);

    si->eraseFromParent();
    RecordUsed(g.modidx, g.rva, g.len);
    return true;
}

static bool IsCRTLikeName(StringRef name)
{
    static const char* prefix[] = {
        "__scrt_", "__security_", "__report_", "__raise_",
        "_initterm", "_cexit", "__onexit", "__xmainret", "__xcptfilter",
        "__std_", "_std_",
        "__ms_v", "_vsnprintf", "_vsprintf", "_vprintf",
        "_snprintf", "_sprintf",
        "_RTC_", "__RTC_",
        "_C_specific_handler", "__C_specific_handler", "__CxxFrameHandler",
        "__GSHandlerCheck", "__gs_",
        "_setjmp", "_longjmp", "_except_handler",
        "__chkstk", "__alloca_probe", "__stdio_",
        "__dyn_tls_", "_tls_start", "_tls_end",
        "pre_c_init", "_pre_cpp_init",
        "??_C@", "??_7", "??_8", "??_9", "??_R",
        "__ropf_",
    };
    for (const char* p : prefix)
    {
        if (name.starts_with(p)) return true;
    }
    return false;
}

static bool IsCRTLikeSection(const Function& f)
{
    if (!f.hasSection()) return false;
    StringRef s = f.getSection();
    return s.starts_with(".CRT$") || s.starts_with(".tls$");
}

static bool IsThunkLike(const Function& f)
{
    if (f.isDeclaration()) return false;
    unsigned nondbg = 0;
    bool hascall = false;
    for (const BasicBlock& bb : f)
    {
        for (const Instruction& i : bb)
        {
            if (isa<DbgInfoIntrinsic>(&i)) continue;
            ++nondbg;
            if (nondbg > 3) return false;
            if (const auto* cb = dyn_cast<CallBase>(&i))
            {
                if (!cb->getIntrinsicID()) hascall = true;
            }
        }
    }
    return hascall;
}

struct XRefInfo
{
    DenseMap<const Function*, unsigned> callcount;
    DenseSet<const Function*> addresstaken;
};

static XRefInfo BuildXRefs(const Module& m)
{
    XRefInfo info;
    for (const Function& f : m)
    {
        for (const User* u : f.users())
        {
            if (const auto* cb = dyn_cast<CallBase>(u))
            {
                if (cb->getCalledFunction() == &f)
                {
                    ++info.callcount[&f];
                    continue;
                }
            }
            info.addresstaken.insert(&f);
        }
    }
    return info;
}

//  EH funclets cannot take our entry block split
static bool HasFuncletPads(const Function& f)
{
    for (const BasicBlock& bb : f)
    {
        if (bb.isEHPad()) return true;
        for (const Instruction& i : bb)
        {
            if (isa<FuncletPadInst>(&i) || isa<CatchSwitchInst>(&i)) return true;
        }
    }
    return false;
}

//  musttail requires an exact match call sequence. Any inserted code between the function entry and the musttail terminator breaks the backend's tail call lowering and reverts to a regular call that corrupts the frame
static bool HasMustTailCall(const Function& f)
{
    for (const BasicBlock& bb : f)
    {
        for (const Instruction& i : bb)
        {
            if (const auto* cb = dyn_cast<CallBase>(&i))
            {
                if (cb->isMustTailCall()) return true;
            }
        }
    }
    return false;
}

// tiny lambdas / operator()s almost always get inlined 
static bool IsTinyFn(const Function& f)
{
    unsigned n = 0;
    for (const BasicBlock& bb : f)
    {
        for (const Instruction& i : bb)
        {
            if (isa<DbgInfoIntrinsic>(&i)) continue;
            if (++n > 8) return false;
        }
    }
    return true;
}

static bool IsROPFuscatorEligible(Function& f, const XRefInfo& xr)
{
    if (f.isDeclaration()) return false;
    if (IsCRTLikeName(f.getName())) return false;
    if (IsCRTLikeSection(f)) return false;
    if (HasNoROPAnnotation(f)) return false;
    if (f.hasFnAttribute(Attribute::AlwaysInline)) return false;
    if (f.hasFnAttribute(Attribute::Naked)) return false;
    if (HasFuncletPads(f)) return false;
    if (HasMustTailCall(f)) return false;

    if (SkipThunks && IsThunkLike(f)) return false;
    if (IsTinyFn(f)) return false;
    auto it = xr.callcount.find(&f);
    unsigned c = (it == xr.callcount.end()) ? 0u : it->second;
    if (c >= XrefThreshold) return false;
    if (xr.addresstaken.count(&f)) return false;
    return true;
}

bool RunROPFuscator(Module& m)
{
    if (!ROPFuscatorEnable) return false;

    HarvestOnce();

    const auto discovered = DiscoverImportedDLLs(m);
    for (const std::string& nm : discovered) HarvestDLL(nm);

    if (DLLModules.empty() || JmpPool.empty()) return false;

    ModuleNameHash = HashModuleUtf16Upper(m.getName().str());
    SiteCounter = 0;
    SlotFillDone.clear();
    {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(ModuleNameHash));
        NameSuffix = buf;
    }

    const XRefInfo xr = BuildXRefs(m);
    bool mutated = false;

    // stable name hash sort so the module wide mem site budget spreads evenly across the module instead of being consumed by whichever functions happen to come first in the module's natural order
    std::vector<Function*> funcs;
    funcs.reserve(m.size());
    for (Function& f : m) funcs.push_back(&f);
    std::stable_sort(funcs.begin(), funcs.end(), [](Function* a, Function* b)
    {
        return std::hash<std::string>{}(a->getName().str()) < std::hash<std::string>{}(b->getName().str());
    });

    const bool havemodbudget = MemModuleBudget != 0;
    unsigned memmodremaining = havemodbudget ? MemModuleBudget : 0u;

    for (Function* fp : funcs)
    {
        Function& f = *fp;
        if (!IsROPFuscatorEligible(f, xr)) continue;

        DominatorTree dt;
        LoopInfo li;
        if (!f.isDeclaration())
        {
            dt.recalculate(f);
            li.analyze(dt);
        }

        struct MemPick
        {
            enum
            {
                B,
                C,
            } kind;
            Instruction* i;
            unsigned prio;
        };
        std::vector<Instruction*> picksa;
        std::vector<MemPick> picksmem;

        auto scoremem = [](Instruction* i, bool isload) -> unsigned
        {
            if (!PreferPtrSized) return 0;
            Type* t = isload ? cast<LoadInst>(i)->getType() : cast<StoreInst>(i)->getValueOperand()->getType();
            if (t->isPointerTy()) return 2;
            if (t->isIntegerTy(64)) return 2;
            return 1;
        };

        for (Instruction& i : instructions(f))
        {
            if (SkipLoops && !f.isDeclaration() && li.getLoopFor(i.getParent())) continue;
            if (i.getMetadata("lic.rop")) continue;

            if (auto* cb = dyn_cast<CallBase>(&i))
            {
                Value* callee = cb->getCalledOperand();
                if (auto* i2p = dyn_cast_or_null<IntToPtrInst>(callee))
                {
                    if (i2p->getMetadata("lic.phase1")) picksa.push_back(&i);
                }
                continue;
            }
            if (auto* lival = dyn_cast<LoadInst>(&i))
            {
                picksmem.push_back({MemPick::B, lival, scoremem(lival, true)});
            }
            else if (auto* sival = dyn_cast<StoreInst>(&i))
            {
                picksmem.push_back({MemPick::C, sival, scoremem(sival, false)});
            }
        }

        if (!picksmem.empty())
        {
            std::mt19937 rng(static_cast<unsigned>(SeedSalt ^ std::hash<std::string>{}(f.getName().str())));
            std::shuffle(picksmem.begin(), picksmem.end(), rng);
            std::stable_sort(picksmem.begin(), picksmem.end(), [](const MemPick& a, const MemPick& b)
            {
                return a.prio > b.prio;
            });

            if (picksmem.size() > MaxMemSitesPerFn) picksmem.resize(MaxMemSitesPerFn);
            if (havemodbudget && picksmem.size() > memmodremaining) picksmem.resize(memmodremaining);
        }

        unsigned fnremaining = MaxSitesPerFn;

        if (picksa.size() > fnremaining)
        {
            std::mt19937 rng(static_cast<unsigned>(SeedSalt ^ std::hash<std::string>{}(f.getName().str()) ^ 0xA1A1A1A1u));
            std::shuffle(picksa.begin(), picksa.end(), rng);
            picksa.resize(fnremaining);
        }
        for (Instruction* i : picksa)
        {
            if (TryEmitSiteA(cast<CallBase>(i)))
            {
                if (fnremaining > 0) --fnremaining;
                mutated = true;
            }
        }

        if (picksmem.size() > fnremaining) picksmem.resize(fnremaining);
        for (const MemPick& p : picksmem)
        {
            bool ok = (p.kind == MemPick::B) ? TryEmitSiteB(cast<LoadInst>(p.i)) : TryEmitSiteC(cast<StoreInst>(p.i));
            if (ok)
            {
                if (havemodbudget && memmodremaining > 0) --memmodremaining;
                mutated = true;
            }
        }
    }

    return mutated;
}

PreservedAnalyses ROPFuscatorPass::run(Module& m, ModuleAnalysisManager&)
{
    return RunROPFuscator(m) ? PreservedAnalyses::none() : PreservedAnalyses::all();
}