#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

#include <Windows.h>

class DLLGrabberUtility final
{
public:
    struct DllIdentity
    {
        std::wstring DllName;
        uint32_t TimeDateStamp = 0;
        uint32_t SizeOfImage = 0;

        bool IsValid() const
        {
            return !DllName.empty() && TimeDateStamp != 0 && SizeOfImage >= 0x1000;
        }
    };

    static DLLGrabberUtility& Instance()
    {
        static DLLGrabberUtility instance;
        return instance;
    }

    DLLGrabberUtility(const DLLGrabberUtility&) = delete;
    DLLGrabberUtility& operator=(const DLLGrabberUtility&) = delete;
    DLLGrabberUtility(DLLGrabberUtility&&) = delete;
    DLLGrabberUtility& operator=(DLLGrabberUtility&&) = delete;

    bool GrabIdentity(const std::wstring& dllpath, DllIdentity& identity, std::wstring& error) const
    {
        identity = DllIdentity{};
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

        identity.DllName = ToLowerAscii(canonicalpath.filename().wstring());

        HANDLE file = CreateFileW(canonicalpath.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            error = L"Failed to open the DLL read-only";
            return false;
        }

        LARGE_INTEGER filesize{};
        if (!GetFileSizeEx(file, &filesize) || filesize.QuadPart < static_cast<LONGLONG>(sizeof(IMAGE_DOS_HEADER)))
        {
            CloseHandle(file);
            error = L"Failed to read the DLL file size";
            return false;
        }

        HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping)
        {
            CloseHandle(file);
            error = L"Failed to create a read-only DLL mapping";
            return false;
        }

        auto* base = static_cast<const uint8_t*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
        if (!base)
        {
            CloseHandle(mapping);
            CloseHandle(file);
            error = L"Failed to map the DLL read-only";
            return false;
        }

        bool success = false;
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

        if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 && static_cast<uint64_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) <= static_cast<uint64_t>(filesize.QuadPart))
        {
            auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
            auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);

            if (nt32->Signature == IMAGE_NT_SIGNATURE)
            {
                identity.TimeDateStamp = nt32->FileHeader.TimeDateStamp;
                if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                {
                    identity.SizeOfImage = nt32->OptionalHeader.SizeOfImage;
                    success = true;
                }
                else if (nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    identity.SizeOfImage = nt64->OptionalHeader.SizeOfImage;
                    success = true;
                }
            }
        }

        UnmapViewOfFile(base);
        CloseHandle(mapping);
        CloseHandle(file);

        if (!success)
        {
            error = L"Failed to extract a valid PE identity from the DLL";
            return false;
        }

        if (!identity.IsValid())
        {
            error = L"The DLL identity is not valid";
            return false;
        }

        return true;
    }

private:
    DLLGrabberUtility() = default;

    static std::wstring ToLowerAscii(std::wstring value)
    {
        for (wchar_t& ch : value)
        {
            if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
        }
        return value;
    }
};