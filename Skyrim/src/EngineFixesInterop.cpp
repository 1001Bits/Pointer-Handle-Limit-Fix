#include "EngineFixesInterop.h"

#include "EngineFixesConfig.h"
#include "Logging.h"
#include "PatchTable.g.h"
#include "PluginPaths.h"
#include "RuntimeTypes.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <limits>

namespace shcr::enginefixes
{
    namespace
    {
        constexpr wchar_t kModuleName[] = L"EngineFixes.dll";
        constexpr FileVersion kFileVersion{ 7, 0, 20, 0 };
        constexpr std::uint32_t kAeTeardownOwnerRva = 0x001B9AB0u;
        constexpr std::uint32_t kImageSize = 0x002A4000u;
        constexpr std::uint32_t kTimeDateStamp = 0x699FC3BAu;
        constexpr std::uint32_t kWrapperRva = 0x000711F0u;
        constexpr std::uint32_t kWrapperEndRva = 0x00071403u;
        constexpr std::size_t kWrapperBytes =
            kWrapperEndRva - kWrapperRva;
        constexpr std::uint32_t kHookTargetRva = 0x0023EAC0u;
        constexpr std::uint32_t kHookDestinationRva = 0x0023EAC8u;
        constexpr std::uint32_t kHookTrampolineRva = 0x0023EAE0u;
        constexpr std::uint32_t kHookTrampolineSizeRva = 0x0023EAE8u;
        constexpr std::uintptr_t kSafetyHookTrampolineBytes = 24u;
        constexpr std::size_t kDigestBytes = 32;
        volatile LONG g_authenticated = 0;

        constexpr std::uint8_t kStockOwnerBytes[16]{
            0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41,
            0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C
        };
        constexpr std::uint8_t kFileDigest[kDigestBytes]{
            0x5D, 0x13, 0x84, 0xAC, 0xFB, 0x52, 0x3A, 0xBD,
            0x13, 0x33, 0xF5, 0xAF, 0x71, 0xAF, 0x0B, 0x7D,
            0x13, 0x1B, 0x6E, 0xBB, 0x1A, 0x0E, 0xE6, 0xB3,
            0xED, 0xFF, 0x86, 0xFB, 0x4C, 0x93, 0xAD, 0xF3
        };
        constexpr std::uint8_t kWrapperDigest[kDigestBytes]{
            0x9D, 0x95, 0x27, 0x24, 0x5B, 0x18, 0x7E, 0x31,
            0xD0, 0x67, 0xF2, 0xCC, 0xF7, 0x7E, 0x8C, 0xB8,
            0x1D, 0xD4, 0x61, 0x5D, 0xEA, 0x26, 0x3D, 0x76,
            0x08, 0xF1, 0x0F, 0x9F, 0xC3, 0xEE, 0x2B, 0xE0
        };

        struct Sha256
        {
            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            void* object = nullptr;

            ~Sha256() noexcept
            {
                if (hash)
                    (void)BCryptDestroyHash(hash);
                if (algorithm)
                    (void)BCryptCloseAlgorithmProvider(algorithm, 0);
                std::free(object);
            }

            [[nodiscard]] bool Initialize() noexcept
            {
                DWORD objectBytes = 0;
                DWORD resultBytes = 0;
                DWORD digestBytes = 0;
                if (BCryptOpenAlgorithmProvider(&algorithm,
                        BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
                    BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&objectBytes),
                        sizeof(objectBytes), &resultBytes, 0) < 0 ||
                    resultBytes != sizeof(objectBytes) || objectBytes == 0 ||
                    BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                        reinterpret_cast<PUCHAR>(&digestBytes),
                        sizeof(digestBytes), &resultBytes, 0) < 0 ||
                    resultBytes != sizeof(digestBytes) ||
                    digestBytes != kDigestBytes) {
                    return false;
                }
                object = std::malloc(objectBytes);
                return object && BCryptCreateHash(algorithm, &hash,
                    static_cast<PUCHAR>(object), objectBytes,
                    nullptr, 0, 0) >= 0;
            }

            [[nodiscard]] bool Update(
                const void* a_data, std::size_t a_bytes) noexcept
            {
                if (!hash || (!a_data && a_bytes != 0) ||
                    a_bytes > (std::numeric_limits<ULONG>::max)())
                    return false;
                return BCryptHashData(hash,
                    const_cast<PUCHAR>(static_cast<const UCHAR*>(a_data)),
                    static_cast<ULONG>(a_bytes), 0) >= 0;
            }

            [[nodiscard]] bool Finish(
                std::uint8_t (&a_digest)[kDigestBytes]) noexcept
            {
                return hash && BCryptFinishHash(
                    hash, a_digest, sizeof(a_digest), 0) >= 0;
            }
        };

        [[nodiscard]] bool HashMemory(
            const void* a_data,
            std::size_t a_bytes,
            std::uint8_t (&a_digest)[kDigestBytes]) noexcept
        {
            Sha256 sha;
            return sha.Initialize() && sha.Update(a_data, a_bytes) &&
                sha.Finish(a_digest);
        }

        [[nodiscard]] bool HashFile(
            const wchar_t* a_path,
            std::uint8_t (&a_digest)[kDigestBytes]) noexcept
        {
            const HANDLE file = CreateFileW(a_path, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
                return false;

            Sha256 sha;
            bool good = sha.Initialize();
            std::uint8_t buffer[64 * 1024]{};
            while (good) {
                DWORD bytesRead = 0;
                if (!ReadFile(file, buffer, sizeof(buffer), &bytesRead,
                        nullptr)) {
                    good = false;
                    break;
                }
                if (bytesRead == 0)
                    break;
                good = sha.Update(buffer, bytesRead);
            }
            (void)CloseHandle(file);
            return good && sha.Finish(a_digest);
        }

        [[nodiscard]] bool ReadFixedFileVersion(
            const wchar_t* a_path, FileVersion& a_version) noexcept
        {
            a_version = {};
            DWORD ignored = 0;
            const DWORD bytes = GetFileVersionInfoSizeW(a_path, &ignored);
            if (bytes == 0)
                return false;
            void* data = std::malloc(bytes);
            if (!data)
                return false;
            bool good = GetFileVersionInfoW(a_path, 0, bytes, data) != FALSE;
            VS_FIXEDFILEINFO* fixed = nullptr;
            UINT fixedBytes = 0;
            good = good && VerQueryValueW(data, L"\\",
                reinterpret_cast<void**>(&fixed), &fixedBytes) != FALSE &&
                fixed && fixedBytes >= sizeof(VS_FIXEDFILEINFO) &&
                fixed->dwSignature == VS_FFI_SIGNATURE;
            if (good) {
                a_version = {
                    HIWORD(fixed->dwFileVersionMS),
                    LOWORD(fixed->dwFileVersionMS),
                    HIWORD(fixed->dwFileVersionLS),
                    LOWORD(fixed->dwFileVersionLS)
                };
            }
            std::free(data);
            return good;
        }

        [[nodiscard]] bool SameVersion(
            const FileVersion& a_left,
            const FileVersion& a_right) noexcept
        {
            return a_left.major == a_right.major &&
                a_left.minor == a_right.minor &&
                a_left.build == a_right.build &&
                a_left.revision == a_right.revision;
        }

        [[nodiscard]] bool IsExecutableProtection(DWORD a_protection) noexcept
        {
            if ((a_protection & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
                return false;
            switch (a_protection & 0xFFu) {
            case PAGE_EXECUTE:
            case PAGE_EXECUTE_READ:
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY:
                return true;
            default:
                return false;
            }
        }

        [[nodiscard]] bool IsReadableProtection(DWORD a_protection) noexcept
        {
            if ((a_protection & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
                return false;
            switch (a_protection & 0xFFu) {
            case PAGE_READONLY:
            case PAGE_READWRITE:
            case PAGE_WRITECOPY:
            case PAGE_EXECUTE_READ:
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY:
                return true;
            default:
                return false;
            }
        }

        [[nodiscard]] bool RegionContains(
            std::uintptr_t a_address,
            std::size_t a_bytes,
            DWORD a_type,
            DWORD a_exactProtection = 0) noexcept
        {
            MEMORY_BASIC_INFORMATION info{};
            if (a_bytes == 0 ||
                VirtualQuery(reinterpret_cast<const void*>(a_address),
                    &info, sizeof(info)) != sizeof(info) ||
                info.State != MEM_COMMIT || info.Type != a_type ||
                (a_exactProtection != 0 &&
                    info.Protect != a_exactProtection) ||
                !IsReadableProtection(info.Protect)) {
                return false;
            }
            const std::uintptr_t begin = reinterpret_cast<std::uintptr_t>(
                info.BaseAddress);
            return a_address >= begin && a_bytes <= info.RegionSize &&
                a_address - begin <= info.RegionSize - a_bytes;
        }

        [[nodiscard]] bool IsPrivateExecutableRegion(
            std::uintptr_t a_address, std::size_t a_bytes) noexcept
        {
            MEMORY_BASIC_INFORMATION info{};
            if (a_bytes == 0 ||
                VirtualQuery(reinterpret_cast<const void*>(a_address),
                    &info, sizeof(info)) != sizeof(info) ||
                info.State != MEM_COMMIT || info.Type != MEM_PRIVATE ||
                info.Protect != PAGE_EXECUTE_READWRITE ||
                !IsExecutableProtection(info.Protect)) {
                return false;
            }
            const std::uintptr_t begin = reinterpret_cast<std::uintptr_t>(
                info.BaseAddress);
            return a_address >= begin && a_bytes <= info.RegionSize &&
                a_address - begin <= info.RegionSize - a_bytes;
        }

        [[nodiscard]] bool IsImageExecutableRegion(
            std::uintptr_t a_address, std::size_t a_bytes) noexcept
        {
            MEMORY_BASIC_INFORMATION info{};
            if (!RegionContains(a_address, a_bytes, MEM_IMAGE) ||
                VirtualQuery(reinterpret_cast<const void*>(a_address),
                    &info, sizeof(info)) != sizeof(info)) {
                return false;
            }
            return IsExecutableProtection(info.Protect);
        }

        [[nodiscard]] std::uintptr_t RelativeTarget5(
            const std::uint8_t* a_instruction) noexcept
        {
            std::int32_t displacement = 0;
            std::memcpy(&displacement, a_instruction + 1,
                sizeof(displacement));
            return static_cast<std::uintptr_t>(
                reinterpret_cast<std::intptr_t>(a_instruction) + 5 +
                static_cast<std::intptr_t>(displacement));
        }

        [[nodiscard]] bool ExactExecutableWrapper(
            HMODULE a_module, std::uintptr_t a_destination) noexcept
        {
            const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(
                a_module);
            if (!RegionContains(base, sizeof(IMAGE_DOS_HEADER), MEM_IMAGE))
                return false;
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE ||
                dos->e_lfanew <= 0)
                return false;
            const std::uint32_t ntOffset =
                static_cast<std::uint32_t>(dos->e_lfanew);
            if (ntOffset > kImageSize - sizeof(IMAGE_NT_HEADERS64))
                return false;
            const std::uintptr_t ntAddress = base +
                ntOffset;
            if (ntAddress < base ||
                !RegionContains(ntAddress, sizeof(IMAGE_NT_HEADERS64),
                    MEM_IMAGE)) {
                return false;
            }
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                ntAddress);
            if (nt->Signature != IMAGE_NT_SIGNATURE ||
                nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
                nt->OptionalHeader.SizeOfImage != kImageSize ||
                nt->FileHeader.TimeDateStamp != kTimeDateStamp ||
                nt->FileHeader.NumberOfSections == 0 ||
                a_destination != base + kWrapperRva)
                return false;

            bool wrapperInExecutableSection = false;
            const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
            const std::size_t sectionBytes =
                static_cast<std::size_t>(nt->FileHeader.NumberOfSections) *
                    sizeof(IMAGE_SECTION_HEADER);
            const std::uintptr_t sectionAddress =
                reinterpret_cast<std::uintptr_t>(section);
            if (sectionAddress < base || sectionBytes > kImageSize ||
                sectionAddress - base > kImageSize - sectionBytes ||
                !RegionContains(sectionAddress,
                    sectionBytes, MEM_IMAGE)) {
                return false;
            }
            for (WORD index = 0; index < nt->FileHeader.NumberOfSections;
                 ++index) {
                const std::uint32_t begin = section[index].VirtualAddress;
                const std::uint32_t bytes =
                    section[index].Misc.VirtualSize;
                if ((section[index].Characteristics &
                        IMAGE_SCN_MEM_EXECUTE) != 0 &&
                    kWrapperRva >= begin && kWrapperBytes <= bytes &&
                    kWrapperRva - begin <= bytes - kWrapperBytes) {
                    wrapperInExecutableSection = true;
                    break;
                }
            }
            if (!wrapperInExecutableSection ||
                !IsImageExecutableRegion(a_destination, kWrapperBytes))
                return false;

            std::uint8_t digest[kDigestBytes]{};
            return HashMemory(reinterpret_cast<const void*>(a_destination),
                    kWrapperBytes, digest) &&
                std::memcmp(digest, kWrapperDigest, sizeof(digest)) == 0;
        }

        template <class T>
        [[nodiscard]] T ReadValue(std::uintptr_t a_address) noexcept
        {
            T value{};
            std::memcpy(&value, reinterpret_cast<const void*>(a_address),
                sizeof(value));
            return value;
        }
    }

    bool IsAuthenticatedFormCachingLifecycleOwner(
        const RuntimeContext& a_runtime,
        std::uint32_t a_ownerRva,
        const std::uint8_t* a_stockBytes,
        std::size_t a_stockByteCount) noexcept
    {
        if (a_runtime.runtimeVersion != kRuntimeAE ||
            a_ownerRva != kAeTeardownOwnerRva || !a_stockBytes ||
            a_stockByteCount != sizeof(kStockOwnerBytes) ||
            std::memcmp(a_stockBytes, kStockOwnerBytes,
                sizeof(kStockOwnerBytes)) != 0) {
            return false;
        }

        const HMODULE module = GetModuleHandleW(kModuleName);
        wchar_t path[32768]{};
        if (!module || !GetLoadedModulePath(module, path, std::size(path)))
            return false;
        const wchar_t* basename = wcsrchr(path, L'\\');
        basename = basename ? basename + 1 : path;
        FileVersion version;
        std::uint8_t fileDigest[kDigestBytes]{};
        if (_wcsicmp(basename, kModuleName) != 0 ||
            !ReadFixedFileVersion(path, version) ||
            !SameVersion(version, kFileVersion) ||
            !HashFile(path, fileDigest) ||
            std::memcmp(fileDigest, kFileDigest, sizeof(fileDigest)) != 0) {
            return false;
        }

        const std::uintptr_t owner = a_runtime.imageBase + a_ownerRva;
        if (!IsImageExecutableRegion(owner, a_stockByteCount))
            return false;
        const auto* ownerBytes = reinterpret_cast<const std::uint8_t*>(owner);
        if (ownerBytes[0] != 0xE9 ||
            std::memcmp(ownerBytes + 5, a_stockBytes + 5,
                a_stockByteCount - 5) != 0) {
            return false;
        }

        const std::uintptr_t destinationStub = RelativeTarget5(ownerBytes);
        if (destinationStub < 10 ||
            !IsPrivateExecutableRegion(destinationStub - 10,
                kSafetyHookTrampolineBytes)) {
            return false;
        }
        const auto* trampoline = reinterpret_cast<const std::uint8_t*>(
            destinationStub - 10);
        const auto* backJump = trampoline + 5;
        const auto* stub = trampoline + 10;
        if (std::memcmp(trampoline, a_stockBytes, 5) != 0 ||
            backJump[0] != 0xE9 || RelativeTarget5(backJump) != owner + 5 ||
            std::memcmp(stub, "\xFF\x25\x00\x00\x00\x00", 6) != 0) {
            return false;
        }
        const std::uintptr_t destination = ReadValue<std::uintptr_t>(
            reinterpret_cast<std::uintptr_t>(stub + 6));
        if (!ExactExecutableWrapper(module, destination))
            return false;

        const std::uintptr_t moduleBase = reinterpret_cast<std::uintptr_t>(
            module);
        if (!RegionContains(moduleBase + kHookTargetRva,
                kHookTrampolineSizeRva + sizeof(std::uintptr_t) -
                    kHookTargetRva,
                MEM_IMAGE)) {
            return false;
        }
        const bool authenticated =
            ReadValue<std::uintptr_t>(moduleBase + kHookTargetRva) ==
                owner &&
            ReadValue<std::uintptr_t>(moduleBase + kHookDestinationRva) ==
                destination &&
            ReadValue<std::uintptr_t>(moduleBase + kHookTrampolineRva) ==
                reinterpret_cast<std::uintptr_t>(trampoline) &&
            ReadValue<std::uintptr_t>(moduleBase +
                kHookTrampolineSizeRva) == kSafetyHookTrampolineBytes;
        if (authenticated)
            (void)InterlockedExchange(&g_authenticated, 1);
        return authenticated;
    }

    bool WasFormCachingLifecycleOwnerAuthenticated() noexcept
    {
        return InterlockedCompareExchange(&g_authenticated, 0, 0) != 0;
    }

    bool RevalidateFormCachingLifecycleOwner(
        const RuntimeContext& a_runtime) noexcept
    {
        return WasFormCachingLifecycleOwnerAuthenticated() &&
            IsAuthenticatedFormCachingLifecycleOwner(
                a_runtime, kAeTeardownOwnerRva, kStockOwnerBytes,
                sizeof(kStockOwnerBytes));
    }

    void LogAuthenticatedFormCachingLifecycleOwner() noexcept
    {
        static volatile LONG logged = 0;
        if (InterlockedCompareExchange(&logged, 1, 0) != 0)
            return;
        Log("compatibility: EngineFixesFormCaching PASS "
            "runtime=1.6.1170.0 version=7.0.20.0 "
            "sha256=5D1384ACFB523ABD1333F5AF71AF0B7D131B6EBB1A0EE6B3EDFF86FB4C93ADF3 "
            "destinationRva=000711F0 safetyHookChain=PASS originalCall=PASS");
    }
}
