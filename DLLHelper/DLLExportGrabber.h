#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <Windows.h>

class DLLExportGrabber final
{
public:
    struct ExportEntry
    {
        std::string Name;
        uint32_t Rva = 0;
        bool Forwarded = false;
        std::string ForwardDll;
        std::string ForwardName;
        bool ForwardByOrdinal = false;
        bool ForwardApiset = false;
    };

    struct ExportTable
    {
        std::vector<ExportEntry> Entries;
        std::unordered_map<std::string, uint32_t> NameToIndex;
    };

    static DLLExportGrabber& Instance()
    {
        static DLLExportGrabber instance;
        return instance;
    }

    DLLExportGrabber(const DLLExportGrabber&) = delete;
    DLLExportGrabber& operator=(const DLLExportGrabber&) = delete;
    DLLExportGrabber(DLLExportGrabber&&) = delete;
    DLLExportGrabber& operator=(DLLExportGrabber&&) = delete;

    bool GrabExports(const std::wstring& dllpath, ExportTable& table, std::wstring& error)
    {
        table = ExportTable{};
        error.clear();

        if (dllpath.empty())
        {
            error = L"DLL path cannot be empty";
            return false;
        }

        const std::filesystem::path inputpath(dllpath);
        if (!inputpath.is_absolute())
        {
            error = L"DLL path must be absolute";
            return false;
        }

        std::error_code ec;
        const std::filesystem::path canonicalpath = std::filesystem::weakly_canonical(inputpath, ec);
        if (ec || canonicalpath.empty())
        {
            error = L"Failed to canonicalize the DLL path";
            return false;
        }
        if (!std::filesystem::exists(canonicalpath, ec) || ec || !std::filesystem::is_regular_file(canonicalpath, ec) || ec)
        {
            error = L"DLL path does not identify a regular file";
            return false;
        }
        if (ToLowerAscii(canonicalpath.extension().wstring()) != L".dll")
        {
            error = L"The selected file must have a .dll extension";
            return false;
        }

        const std::wstring cachekey = canonicalpath.wstring();
        {
            std::lock_guard<std::mutex> lock(cachemutex);
            const auto hit = cache.find(cachekey);
            if (hit != cache.end())
            {
                table = hit->second;
                return true;
            }
        }

        ExportTable parsed;
        if (!ParseFile(canonicalpath, parsed, error)) return false;

        std::lock_guard<std::mutex> lock(cachemutex);
        auto [it, inserted] = cache.emplace(cachekey, std::move(parsed));
        table = it->second;
        (void)inserted;
        return true;
    }

private:
    DLLExportGrabber() = default;

    struct MappedFile
    {
        HANDLE File = INVALID_HANDLE_VALUE;
        HANDLE Mapping = nullptr;
        const uint8_t* Base = nullptr;
        uint64_t Size = 0;
        ~MappedFile()
        {
            if (Base) UnmapViewOfFile(Base);
            if (Mapping) CloseHandle(Mapping);
            if (File != INVALID_HANDLE_VALUE) CloseHandle(File);
        }
    };

    static bool MapReadOnly(const std::filesystem::path& path, MappedFile& out)
    {
        out.File = CreateFileW(path.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (out.File == INVALID_HANDLE_VALUE) return false;

        LARGE_INTEGER fs{};
        if (!GetFileSizeEx(out.File, &fs) || fs.QuadPart < 0x1000) return false;
        out.Size = static_cast<uint64_t>(fs.QuadPart);

        out.Mapping = CreateFileMappingW(out.File, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!out.Mapping) return false;

        out.Base = static_cast<const uint8_t*>(MapViewOfFile(out.Mapping, FILE_MAP_READ, 0, 0, 0));
        return out.Base != nullptr;
    }

    static bool ParseFile(const std::filesystem::path& path, ExportTable& table, std::wstring& error)
    {
        MappedFile mf;
        if (!MapReadOnly(path, mf))
        {
            error = L"Failed to open/map the DLL read-only";
            return false;
        }

        if (mf.Size < sizeof(IMAGE_DOS_HEADER))
        {
            error = L"File too small for a PE";
            return false;
        }
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mf.Base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || static_cast<uint64_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > mf.Size)
        {
            error = L"Invalid DOS header";
            return false;
        }

        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(mf.Base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            error = L"Invalid NT signature";
            return false;
        }
       
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            error = L"Not a PE32+ (x64) DLL";
            return false;
        }

        const IMAGE_DATA_DIRECTORY& expdir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expdir.VirtualAddress == 0 || expdir.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
        {
            error = L"No export directory";
            return false;
        }

        const uint16_t seccount = nt->FileHeader.NumberOfSections;
        if (seccount == 0 || seccount > 96)
        {
            error = L"Implausible section count";
            return false;
        }
        const uint64_t sectableoff = static_cast<uint64_t>(dos->e_lfanew) + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
        if (sectableoff + static_cast<uint64_t>(seccount) * sizeof(IMAGE_SECTION_HEADER) > mf.Size)
        {
            error = L"Section table out of bounds";
            return false;
        }
        auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(mf.Base + sectableoff);

        auto rvatooff = [&](uint32_t rva, uint32_t need) -> uint64_t
        {
            if (rva == 0 || need == 0) return 0;
            for (uint16_t i = 0; i < seccount; ++i)
            {
                const uint32_t span = (std::max)(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
                if (rva >= sections[i].VirtualAddress && rva - sections[i].VirtualAddress < span)
                {
                    const uint64_t off = static_cast<uint64_t>(sections[i].PointerToRawData) + (rva - sections[i].VirtualAddress);
                    if (off + need <= mf.Size) return off;
                    return 0;
                }
            }
            return 0;
        };

        auto readcstr = [&](uint32_t rva, size_t maxlen, std::string& out) -> bool
        {
            const uint64_t off = rvatooff(rva, 1);
            if (!off) return false;
            out.clear();
            for (size_t i = 0; i < maxlen; ++i)
            {
                if (off + i >= mf.Size) return false;
                const char c = static_cast<char>(mf.Base[off + i]);
                if (!c) return !out.empty();
                out.push_back(c);
            }
            
            return false;
        };

        const uint64_t diroff = rvatooff(expdir.VirtualAddress, static_cast<uint32_t>(sizeof(IMAGE_EXPORT_DIRECTORY)));
        if (!diroff)
        {
            error = L"Export directory out of bounds";
            return false;
        }
        auto* dir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(mf.Base + diroff);

        if (dir->NumberOfFunctions == 0 || dir->NumberOfFunctions > 0x100000 || dir->NumberOfNames > 0x100000)
        {
            error = L"Implausible export counts";
            return false;
        }
        const uint64_t eatoff = rvatooff(dir->AddressOfFunctions, dir->NumberOfFunctions * 4u);
        const uint64_t namesoff = dir->NumberOfNames ? rvatooff(dir->AddressOfNames, dir->NumberOfNames * 4u) : 0;
        const uint64_t ordsoff = dir->NumberOfNames ? rvatooff(dir->AddressOfNameOrdinals, dir->NumberOfNames * 2u) : 0;
        if (!eatoff || (dir->NumberOfNames && (!namesoff || !ordsoff)))
        {
            error = L"Export arrays out of bounds";
            return false;
        }

        table.Entries.reserve(dir->NumberOfFunctions);

        auto readu32 = [&](uint64_t off) -> uint32_t
        {
            uint32_t v;
            std::memcpy(&v, mf.Base + off, 4);
            return v;
        };
        auto readu16 = [&](uint64_t off) -> uint16_t
        {
            uint16_t v;
            std::memcpy(&v, mf.Base + off, 2);
            return v;
        };

        auto isforwarder = [&](uint32_t rva) -> bool
        {
            return rva >= expdir.VirtualAddress && rva < expdir.VirtualAddress + expdir.Size;
        };

        auto parseforwarder = [&](const std::string& raw, ExportEntry& e)
        {
            const size_t dot = raw.find_last_of('.');
            if (dot == std::string::npos || dot == 0 || dot + 1 >= raw.size())
            {
                e.ForwardDll.clear();
                return;
            }
            std::string dll = raw.substr(0, dot);
            for (char& c : dll)
            {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            }
            if (dll.size() < 4 || dll.compare(dll.size() - 4, 4, ".dll") != 0) dll += ".dll";
            e.ForwardDll = dll;
            e.ForwardApiset = dll.rfind("api-ms-", 0) == 0 || dll.rfind("ext-ms-", 0) == 0;

            const std::string member = raw.substr(dot + 1);
            if (!member.empty() && member[0] == '#')
            {
                e.ForwardByOrdinal = true;
            }
            else
            {
                e.ForwardName = member;
            }
        };

        std::vector<uint8_t> named(dir->NumberOfFunctions, 0);
        for (uint32_t i = 0; i < dir->NumberOfNames; ++i)
        {
            const uint32_t namerva = readu32(namesoff + static_cast<uint64_t>(i) * 4);
            const uint16_t eatidx = readu16(ordsoff + static_cast<uint64_t>(i) * 2);
            if (eatidx >= dir->NumberOfFunctions)
            {
                error = L"Name ordinal index out of range";
                return false;
            }
            std::string name;
            if (!readcstr(namerva, 256, name))
            {
                error = L"Unterminated or unreadable export name";
                return false;
            }
            const uint32_t funcrva = readu32(eatoff + static_cast<uint64_t>(eatidx) * 4);

            ExportEntry e;
            e.Name = name;
            if (funcrva && isforwarder(funcrva))
            {
                e.Forwarded = true;
                std::string raw;
                if (!readcstr(funcrva, 256, raw))
                {
                    error = L"Unterminated forwarder string";
                    return false;
                }
                parseforwarder(raw, e);
            }
            else
            {
                e.Rva = funcrva;
            }

            named[eatidx] = 1;
            const uint32_t idx = static_cast<uint32_t>(table.Entries.size());
            table.NameToIndex.emplace(e.Name, idx);
            table.Entries.push_back(std::move(e));
        }

        for (uint32_t i = 0; i < dir->NumberOfFunctions; ++i)
        {
            if (named[i]) continue;
            const uint32_t funcrva = readu32(eatoff + static_cast<uint64_t>(i) * 4);
            if (!funcrva) continue;

            ExportEntry e;
            if (isforwarder(funcrva))
            {
                e.Forwarded = true;
                std::string raw;
                if (!readcstr(funcrva, 256, raw))
                {
                    error = L"Unterminated forwarder string";
                    return false;
                }
                parseforwarder(raw, e);
            }
            else
            {
                e.Rva = funcrva;
            }

            table.Entries.push_back(std::move(e));
        }

        if (table.Entries.empty())
        {
            error = L"DLL exports nothing";
            return false;
        }
        return true;
    }

    static std::wstring ToLowerAscii(std::wstring value)
    {
        for (wchar_t& ch : value)
        {
            if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
        }
        return value;
    }

    std::mutex cachemutex;
    std::unordered_map<std::wstring, ExportTable> cache;
};