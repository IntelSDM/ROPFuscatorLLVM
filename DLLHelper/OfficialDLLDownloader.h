#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <Windows.h>
#include <winhttp.h>
#include <bcrypt.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

class OfficialDllDownloader final
{
public:
    struct DownloadResult
    {
        bool Success = false;
        std::wstring OutputPath;
        std::wstring Error;
    };

    static OfficialDllDownloader& Instance()
    {
        static OfficialDllDownloader instance;
        return instance;
    }

    OfficialDllDownloader(const OfficialDllDownloader&) = delete;
    OfficialDllDownloader& operator=(const OfficialDllDownloader&) = delete;
    OfficialDllDownloader(OfficialDllDownloader&&) = delete;
    OfficialDllDownloader& operator=(OfficialDllDownloader&&) = delete;

    bool TryGetCachedDll(const std::wstring& dllname, uint32_t timedatestamp, uint32_t sizeofimage, DownloadResult& result)
    {
        result = DownloadResult{};

        std::wstring identityhash;
        std::wstring error;
        if (!BuildIdentityHash(dllname, timedatestamp, sizeofimage, identityhash, error))
        {
            result.Error = error;
            return false;
        }

        std::wstring sanitizedname;
        if (!SanitizeDllName(dllname, sanitizedname, error))
        {
            result.Error = error;
            return false;
        }

        const std::filesystem::path identitydir = downloadroot / identityhash;
        const std::filesystem::path outputpath = identitydir / sanitizedname;
        result.OutputPath = outputpath.wstring();

        if (!IsPathInsideRoot(outputpath))
        {
            result.Error = L"Generated cache path escaped the download root";
            return false;
        }

        std::error_code ec;
        if (!std::filesystem::exists(identitydir, ec) || ec) return false;

        FileMutex cachemutex;
        if (!cachemutex.Acquire(identitydir / LockFileName, error))
        {
            result.Error = error;
            return false;
        }

        if (!CachedFileMatches(outputpath, timedatestamp, sizeofimage)) return false;

        result.Success = true;
        return true;
    }

    bool DownloadDll(const std::wstring& dllname, uint32_t timedatestamp, uint32_t sizeofimage, DownloadResult& result)
    {
        result = DownloadResult{};

        std::wstring identityhash;
        std::wstring inputerror;
        if (!BuildIdentityHash(dllname, timedatestamp, sizeofimage, identityhash, inputerror))
        {
            result.Error = inputerror;
            return false;
        }

        std::wstring sanitizedname;
        if (!SanitizeDllName(dllname, sanitizedname, inputerror))
        {
            result.Error = inputerror;
            return false;
        }

        const std::filesystem::path identitydir = downloadroot / identityhash;
        const std::filesystem::path outputpath = identitydir / sanitizedname;

        if (!IsPathInsideRoot(outputpath))
        {
            result.Error = L"Generated cache path escaped the download root";
            return false;
        }

        result.OutputPath = outputpath.wstring();

        std::error_code ec;
        std::filesystem::create_directories(identitydir, ec);
        if (ec)
        {
            result.Error = L"Failed to create the identity cache directory";
            return false;
        }

        FileMutex cachemutex;
        if (!cachemutex.Acquire(identitydir / LockFileName, result.Error)) return false;

        if (CachedFileMatches(outputpath, timedatestamp, sizeofimage))
        {
            result.Success = true;
            return true;
        }

        if (std::filesystem::exists(outputpath, ec))
        {
            std::filesystem::remove(outputpath, ec);
            if (ec)
            {
                result.Error = L"Failed to remove invalid cached DLL";
                return false;
            }
        }

        const std::filesystem::path temporarypath = BuildTemporaryPath(outputpath);
        uint64_t downloadedbytes = 0;
        uint32_t httpstatus = 0;

        if (!DownloadFile(BuildPeBinaryUrl(sanitizedname, timedatestamp, sizeofimage), temporarypath, downloadedbytes, httpstatus, result.Error))
        {
            std::filesystem::remove(temporarypath, ec);
            if (result.Error.empty()) result.Error = L"Microsoft symbol store did not return the requested DLL";
            return false;
        }

        if (!PeFileMatchesIdentity(temporarypath, timedatestamp, sizeofimage))
        {
            std::filesystem::remove(temporarypath, ec);
            result.Error = L"Downloaded file's PE identity does not match the request";
            return false;
        }

        if (CachedFileMatches(outputpath, timedatestamp, sizeofimage))
        {
            std::filesystem::remove(temporarypath, ec);
            result.Success = true;
            return true;
        }

        if (!MoveFileExW(temporarypath.wstring().c_str(), outputpath.wstring().c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            std::filesystem::remove(temporarypath, ec);
            if (CachedFileMatches(outputpath, timedatestamp, sizeofimage))
            {
                result.Success = true;
                return true;
            }
            result.Error = L"Failed to move the validated DLL into the identity cache";
            return false;
        }

        result.Success = true;
        return true;
    }

private:
    class FileMutex final
    {
    public:
        FileMutex() = default;
        FileMutex(const FileMutex&) = delete;
        FileMutex& operator=(const FileMutex&) = delete;

        ~FileMutex()
        {
            Release();
        }

        bool Acquire(const std::filesystem::path& lockpath, std::wstring& error, uint32_t timeoutms = 30000)
        {
            Release();

            lockfile = CreateFileW(lockpath.wstring().c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (lockfile == INVALID_HANDLE_VALUE)
            {
                error = L"Failed to open the identity cache lock file";
                return false;
            }

            const uint64_t deadline = GetTickCount64() + timeoutms;

            for (;;)
            {
                OVERLAPPED overlapped{};
                if (LockFileEx(lockfile, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped))
                {
                    locked = true;
                    return true;
                }

                const DWORD lockerror = GetLastError();
                if (lockerror != ERROR_LOCK_VIOLATION && lockerror != ERROR_IO_PENDING)
                {
                    error = L"Failed to lock the identity cache lock file";
                    Release();
                    return false;
                }

                if (GetTickCount64() >= deadline)
                {
                    error = L"Timed out waiting for the identity cache file mutex";
                    Release();
                    return false;
                }

                Sleep(25);
            }
        }

        void Release()
        {
            if (lockfile != INVALID_HANDLE_VALUE)
            {
                if (locked)
                {
                    OVERLAPPED overlapped{};
                    UnlockFileEx(lockfile, 0, 1, 0, &overlapped);
                    locked = false;
                }
                CloseHandle(lockfile);
                lockfile = INVALID_HANDLE_VALUE;
            }
        }

    private:
        HANDLE lockfile = INVALID_HANDLE_VALUE;
        bool locked = false;
    };

    static constexpr size_t MaxDllNameLength = 128;
    static constexpr uint32_t MinSizeOfImage = 0x1000;
    static constexpr uint64_t MaxSizeOfImage = 256ull * 1024ull * 1024ull;
    static constexpr uint64_t MaxDownloadBytes = 256ull * 1024ull * 1024ull;
    static constexpr std::wstring_view CacheRoot = L"C:\\ProgramData\\DRM\\DllCache";
    static constexpr std::wstring_view LockFileName = L".cache.lock";

    inline static const std::wstring symbolserver = L"msdl.microsoft.com";

    const std::filesystem::path downloadroot;
    std::atomic<uint64_t> temporarysequence{0};

    OfficialDllDownloader() : downloadroot(NormalizeDownloadRoot(std::wstring(CacheRoot)))
    {
    }

    static std::filesystem::path NormalizeDownloadRoot(const std::wstring& root)
    {
        std::filesystem::path path(root);

        if (!path.is_absolute())
        {
            std::fprintf(stderr, "[OfficialDllDownloader] FATAL: download root must be absolute\n");
            std::abort();
        }

        if (path == path.root_path())
        {
            std::fprintf(stderr, "[OfficialDllDownloader] FATAL: download root cannot be a filesystem root\n");
            std::abort();
        }

        std::error_code ec;
        std::filesystem::create_directories(path, ec);
        if (ec)
        {
            std::fprintf(stderr, "[OfficialDllDownloader] FATAL: failed to create the DLL cache root\n");
            std::abort();
        }

        std::filesystem::path canonical = std::filesystem::weakly_canonical(path, ec);
        if (ec || canonical.empty())
        {
            std::fprintf(stderr, "[OfficialDllDownloader] FATAL: failed to canonicalize the DLL cache root\n");
            std::abort();
        }

        return canonical;
    }

    static bool SanitizeDllName(const std::wstring& input, std::wstring& sanitized, std::wstring& error)
    {
        sanitized.clear();

        if (input.empty() || input.size() > MaxDllNameLength)
        {
            error = L"DLL name is empty or exceeds 128 characters";
            return false;
        }

        if (input.front() == L'.' || input.back() == L'.' || input.front() == L' ' || input.back() == L' ')
        {
            error = L"DLL name has an unsafe leading or trailing character";
            return false;
        }

        bool previouswasdot = false;
        size_t dotcount = 0;
        size_t lastdot = std::wstring::npos;

        for (size_t index = 0; index < input.size(); ++index)
        {
            const wchar_t ch = input[index];

            const bool allowed = (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') || (ch >= L'0' && ch <= L'9') || ch == L'_' || ch == L'-' || ch == L'.';

            if (!allowed)
            {
                error = L"DLL name contains a character outside the ASCII allow-list";
                return false;
            }

            if (ch == L'.')
            {
                if (previouswasdot)
                {
                    error = L"DLL name contains consecutive dots";
                    return false;
                }
                previouswasdot = true;
                lastdot = index;
                dotcount++;
            }
            else
            {
                previouswasdot = false;
            }
        }

        if (dotcount == 0 || lastdot == 0 || lastdot + 1 >= input.size())
        {
            error = L"DLL name must contain a filename stem and extension";
            return false;
        }

        if (ToLowerAscii(input.substr(lastdot)) != L".dll")
        {
            error = L"Only .dll file names are accepted";
            return false;
        }

        const std::wstring stem = ToLowerAscii(input.substr(0, lastdot));
        static const std::array<std::wstring_view, 22> reservednames = {
            L"con", L"prn", L"aux", L"nul",
            L"com1", L"com2", L"com3", L"com4", L"com5",
            L"com6", L"com7", L"com8", L"com9",
            L"lpt1", L"lpt2", L"lpt3", L"lpt4", L"lpt5",
            L"lpt6", L"lpt7", L"lpt8", L"lpt9"
        };

        if (std::find(reservednames.begin(), reservednames.end(), stem) != reservednames.end())
        {
            error = L"DLL name uses a reserved Windows device name";
            return false;
        }

        sanitized = ToLowerAscii(input);
        return true;
    }

    static bool SanitizePeIdentity(uint32_t timedatestamp, uint32_t sizeofimage, std::wstring& error)
    {
        if (timedatestamp == 0)
        {
            error = L"PE TimeDateStamp cannot be zero";
            return false;
        }

        if (sizeofimage < MinSizeOfImage || static_cast<uint64_t>(sizeofimage) > MaxSizeOfImage)
        {
            error = L"PE SizeOfImage is outside the supported range";
            return false;
        }

        return true;
    }

    static bool BuildIdentityHash(const std::wstring& dllname, uint32_t timedatestamp, uint32_t sizeofimage, std::wstring& identityhash, std::wstring& error)
    {
        identityhash.clear();

        std::wstring sanitizedname;
        if (!SanitizeDllName(dllname, sanitizedname, error) || !SanitizePeIdentity(timedatestamp, sizeofimage, error)) return false;

        const std::wstring material = sanitizedname + L"|" + ToUpperHex(timedatestamp, 8) + L"|" + ToLowerHex(sizeofimage, 0);

        std::string hashmaterial;
        hashmaterial.reserve(material.size());
        for (const wchar_t ch : material)
        {
            hashmaterial.push_back(static_cast<char>(ch));
        }

        std::array<BYTE, 32> digest{};
        if (!Sha256(hashmaterial.data(), hashmaterial.size(), digest, error)) return false;

        identityhash = BytesToLowerHex(digest.data(), digest.size());
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

    static std::wstring ToUpperHex(uint32_t value, int width)
    {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0') << std::setw(width) << value;
        return ss.str();
    }

    static std::wstring ToLowerHex(uint32_t value, int width)
    {
        std::wstringstream ss;
        ss << std::nouppercase << std::hex;
        if (width > 0) ss << std::setfill(L'0') << std::setw(width);
        ss << value;
        return ss.str();
    }

    static bool Sha256(const void* data, size_t datasize, std::array<BYTE, 32>& digest, std::wstring& error)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        std::vector<BYTE> hashobject;
        bool success = false;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (status < 0)
        {
            error = L"Failed to open the Windows SHA-256 provider";
            return false;
        }

        DWORD objectlength = 0;
        DWORD resultlength = sizeof(objectlength);
        status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectlength), sizeof(objectlength), &resultlength, 0);

        DWORD hashlength = 0;
        resultlength = sizeof(hashlength);
        if (status >= 0)
        {
            status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashlength), sizeof(hashlength), &resultlength, 0);
        }

        if (status >= 0 && objectlength > 0 && hashlength == digest.size())
        {
            hashobject.resize(objectlength);
            status = BCryptCreateHash(algorithm, &hash, hashobject.data(), static_cast<ULONG>(hashobject.size()), nullptr, 0, 0);
        }

        if (status >= 0 && hash)
        {
            status = BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<void*>(data)), static_cast<ULONG>(datasize), 0);
        }

        if (status >= 0 && hash)
        {
            status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
        }

        success = status >= 0 && hash != nullptr;

        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);

        if (!success) error = L"Failed to calculate the identity SHA-256";

        return success;
    }

    static std::wstring BytesToLowerHex(const BYTE* bytes, size_t size)
    {
        static const wchar_t digits[] = L"0123456789abcdef";
        std::wstring output;
        output.reserve(size * 2);

        for (size_t index = 0; index < size; ++index)
        {
            output.push_back(digits[(bytes[index] >> 4) & 0xF]);
            output.push_back(digits[bytes[index] & 0xF]);
        }

        return output;
    }

    static std::wstring BuildPeBinaryUrl(const std::wstring& sanitizeddllname, uint32_t timedatestamp, uint32_t sizeofimage)
    {
        std::wstringstream ss;
        ss << L"/download/symbols/" << sanitizeddllname << L"/" << ToUpperHex(timedatestamp, 8) << ToLowerHex(sizeofimage, 0) << L"/" << sanitizeddllname;
        return ss.str();
    }

    bool IsPathInsideRoot(const std::filesystem::path& candidate) const
    {
        const std::filesystem::path root = downloadroot.lexically_normal();
        const std::filesystem::path normalized = candidate.lexically_normal();

        auto rootiterator = root.begin();
        auto candidateiterator = normalized.begin();

        for (; rootiterator != root.end(); ++rootiterator, ++candidateiterator)
        {
            if (candidateiterator == normalized.end() || *candidateiterator != *rootiterator) return false;
        }

        return candidateiterator != normalized.end();
    }

    std::filesystem::path BuildTemporaryPath(const std::filesystem::path& outputpath)
    {
        const uint64_t sequence = temporarysequence.fetch_add(1, std::memory_order_relaxed) + 1;

        std::wstringstream temporaryname;
        temporaryname << outputpath.filename().wstring() << L"." << GetCurrentProcessId() << L"." << GetCurrentThreadId() << L"." << sequence << L".tmp";

        return outputpath.parent_path() / temporaryname.str();
    }

    bool CachedFileMatches(const std::filesystem::path& path, uint32_t timedatestamp, uint32_t sizeofimage) const
    {
        std::error_code ec;
        if (!std::filesystem::exists(path, ec) || ec) return false;
        return PeFileMatchesIdentity(path, timedatestamp, sizeofimage);
    }

    static bool ReadPeIdentity(const std::filesystem::path& filepath, uint32_t& timedatestamp, uint32_t& sizeofimage)
    {
        timedatestamp = 0;
        sizeofimage = 0;

        HANDLE file = CreateFileW(filepath.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;

        LARGE_INTEGER filesize{};
        if (!GetFileSizeEx(file, &filesize) || filesize.QuadPart < static_cast<LONGLONG>(sizeof(IMAGE_DOS_HEADER)))
        {
            CloseHandle(file);
            return false;
        }

        HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping)
        {
            CloseHandle(file);
            return false;
        }

        auto* base = static_cast<const uint8_t*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
        if (!base)
        {
            CloseHandle(mapping);
            CloseHandle(file);
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
                uint32_t actualsize = 0;

                if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                {
                    actualsize = nt32->OptionalHeader.SizeOfImage;
                }
                else if (nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    actualsize = nt64->OptionalHeader.SizeOfImage;
                }

                if (actualsize != 0)
                {
                    timedatestamp = nt32->FileHeader.TimeDateStamp;
                    sizeofimage = actualsize;
                    success = true;
                }
            }
        }

        UnmapViewOfFile(base);
        CloseHandle(mapping);
        CloseHandle(file);

        return success;
    }

    static bool PeFileMatchesIdentity(const std::filesystem::path& filepath, uint32_t expectedtimedatestamp, uint32_t expectedsizeofimage)
    {
        uint32_t actualtimestamp = 0;
        uint32_t actualsize = 0;
        return ReadPeIdentity(filepath, actualtimestamp, actualsize) && actualtimestamp == expectedtimedatestamp && actualsize == expectedsizeofimage;
    }

    bool DownloadFile(const std::wstring& urlpath, const std::filesystem::path& outputpath, uint64_t& bytesdownloaded, uint32_t& httpstatus, std::wstring& error)
    {
        bytesdownloaded = 0;
        httpstatus = 0;

        HINTERNET session = WinHttpOpen(L"Microsoft-DLL-Downloader/3.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session)
        {
            error = L"Failed to create a WinHTTP session";
            return false;
        }

        WinHttpSetTimeouts(session, 5000, 15000, 15000, 30000);

        HINTERNET connection = WinHttpConnect(session, symbolserver.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!connection)
        {
            WinHttpCloseHandle(session);
            error = L"Failed to connect to the Microsoft symbol server";
            return false;
        }

        HINTERNET request = WinHttpOpenRequest(connection, L"GET", urlpath.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!request)
        {
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            error = L"Failed to create the Microsoft symbol-server request";
            return false;
        }

        bool success = false;

        if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(request, nullptr))
        {
            error = L"Microsoft symbol-server request failed";
        }
        else
        {
            DWORD statuscode = 0;
            DWORD statussize = sizeof(statuscode);

            if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &statuscode, &statussize, nullptr))
            {
                httpstatus = statuscode;
            }

            if (httpstatus == 404)
            {
                error = L"Microsoft symbol server returned 404 for the requested PE identity";
            }
            else if (httpstatus != 200)
            {
                std::wstringstream ss;
                ss << L"Microsoft symbol server returned HTTP " << httpstatus;
                error = ss.str();
            }
            else
            {
                uint64_t contentlength = 0;
                DWORD contentlength32 = 0;
                DWORD contentlengthsize = sizeof(contentlength32);

                if (WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &contentlength32, &contentlengthsize, nullptr))
                {
                    contentlength = contentlength32;
                }

                if (contentlength > MaxDownloadBytes)
                {
                    error = L"Microsoft symbol-server response exceeds the download cap";
                }
                else
                {
                    std::ofstream output(outputpath, std::ios::binary | std::ios::trunc);

                    if (!output.is_open())
                    {
                        error = L"Failed to open the temporary DLL download file";
                    }
                    else
                    {
                        std::array<BYTE, 64 * 1024> buffer{};
                        bool responsetoolarge = false;
                        bool readfailed = false;
                        bool writefailed = false;

                        for (;;)
                        {
                            DWORD bytesread = 0;

                            if (!WinHttpReadData(request, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesread))
                            {
                                readfailed = true;
                                break;
                            }

                            if (bytesread == 0) break;

                            bytesdownloaded += bytesread;

                            if (bytesdownloaded > MaxDownloadBytes)
                            {
                                responsetoolarge = true;
                                break;
                            }

                            output.write(reinterpret_cast<const char*>(buffer.data()), bytesread);

                            if (!output.good())
                            {
                                writefailed = true;
                                break;
                            }
                        }

                        output.flush();
                        if (!output.good()) writefailed = true;
                        output.close();

                        if (responsetoolarge) error = L"Microsoft symbol-server response exceeded the download cap";
                        else if (readfailed) error = L"Failed while reading the Microsoft symbol-server response";
                        else if (writefailed) error = L"Failed while writing the temporary DLL download";
                        else if (bytesdownloaded == 0) error = L"Microsoft symbol server returned an empty DLL body";
                        else success = true;
                    }
                }
            }
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);

        return success;
    }
};