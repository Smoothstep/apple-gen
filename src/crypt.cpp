#include <array>
#include <assert.h>
#include <concepts>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <memory_resource>
#include <optional>
#include <ranges>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#ifdef _BUILD_SHARED
#define DLL_EXPORT
#endif

extern "C"
{
#include "ids_validation.h"
}

#ifdef _DEBUG
#define DEBUG_ASSERT(X, Y) assert(X &&Y)
#else
#define DEBUG_ASSERT(X, Y)
#endif

template <class T>
concept RegType = (std::is_reference_v<T> || std::is_pointer_v<T>) || std::is_integral_v<T>;

#ifdef _WIN32
template <class T> constexpr auto type_arg_size() -> size_t
{
    static_assert(sizeof(T) <= 16, "Invalid argument size");

    if constexpr (sizeof(T) <= 8)
    {
        return 1;
    }
    else if constexpr (sizeof(T) == 16)
    {
        return 2;
    }
}

template <class T, class... Args> struct InternalCallTemplate
{
    constexpr InternalCallTemplate(T (*)(Args...)) noexcept {};
    using Type = T (*)(Args...);
    static constexpr size_t num_args = (type_arg_size<Args>() + ... + 0ULL);
};

template <class T, typename T::Type P> struct InternalCall
{
    constexpr InternalCall() noexcept = default;
    using Template = T;
    static constexpr auto target = P;
};

template <class Call> [[gnu::noinline]] void call_internal()
{
    asm("push rbp;"
        "mov rbp, rsp;"
        "sub rsp, 0x20;"
        "and rsp, 0xFFFFFFFFFFFFFFF0;");

    if constexpr (Call::Template::num_args > 4)
    {
        // asm("mov rax, r8;");
    }

    if constexpr (Call::Template::num_args > 3)
    {
        asm("mov r9, rcx;");
    }

    if constexpr (Call::Template::num_args > 2)
    {
        asm("mov r8, rdx;");
    }

    if constexpr (Call::Template::num_args > 1)
    {
        asm("mov rdx, rsi;");
    }

    if constexpr (Call::Template::num_args > 0)
    {
        asm("mov rcx, rdi;");
    }

    asm("call %0;"
        "mov rsp, rbp;"
        "pop rbp;"
        "ret;"
        :
        : "r"(Call::target));
}

template <class T> union B64Type
{
    constexpr B64Type(T value) : value{value} {}
    std::remove_reference_t<T> value;
    uint64_t value64;
};

template <class TResult, class TTarget, size_t NumArgs>
[[gnu::noinline]] void call_external_dispatch(TTarget *target, std::array<uint64_t, NumArgs> args,
                                              TResult &result)
{
#define ARG(x) *(reinterpret_cast<uint64_t *>(&args) + x)

    asm("push r12;"
        "push rsi;"
        "push rdi;"
        "push r8;"
        "mov r12, rcx;");

    if constexpr (NumArgs > 0)
    {
        asm("mov rdi, %0;" ::"r"(ARG(0)));
    }

    if constexpr (NumArgs > 1)
    {
        asm("mov rsi, %0;" ::"r"(ARG(1)));
    }

    if constexpr (NumArgs > 3)
    {
        asm("mov rcx, %0;" ::"r"(ARG(3)));
    }

    if constexpr (NumArgs > 4)
    {
        asm("mov r8, %0;" ::"r"(ARG(4)));
    }

    if constexpr (NumArgs > 2)
    {
        asm("mov rdx, %0;" ::"r"(ARG(2)));
    }

    asm("push rbp;"
        "mov rbp, rsp;"
        "sub rsp, 0x10;"
        "and rsp, 0xFFFFFFFFFFFFFFF0;"
        "call r12;"
        "mov rsp, rbp;"
        "pop rbp;"
        "pop r8;"
        "pop rdi;"
        "pop rsi;"
        "pop r12;"
        "mov [r8], rax");
}

template <class TResult, class TTarget, RegType... Args>
auto call_external(TTarget *target, Args &&...args) -> TResult
{
    TResult result;
    // fastcall ABI adaption
    call_external_dispatch<TResult>(
        target, std::array<uint64_t, sizeof...(Args) + 1>{(B64Type<Args>{args}.value64)..., 0},
        result);
    return result;
}

#define WRAP_FAKE_API_P(X, N)                                                                      \
    void fn__fake__##N()                                                                           \
    {                                                                                              \
        call_internal<InternalCall<decltype(InternalCallTemplate{&X}), &X>>();                     \
    }                                                                                              \
    auto __fake__##N = &fn__fake__##N;
#else
template <class TResult, class TTarget, RegType... Args>
auto call_external(TTarget *target, Args... args) -> TResult
{
    return reinterpret_cast<TResult (*)(Args...)>(target)(args...);
}

#define WRAP_FAKE_API_P(X, N) auto __fake__##N = &X;
#endif

#define WRAP_FAKE_API(X) WRAP_FAKE_API_P(X, X)

enum class TypeId : uint32_t
{
    kTypeUnknown = 0,
    kTypeStr = 1,
    kTypeByte = 2,
    kTypeDict = 3,
    kTypeInt = 4,
    kTypeRef = 5
};

class IOObject
{
    public:
    constexpr IOObject() = default;
    virtual ~IOObject() = default;
};

class HasTypeId
{
    protected:
    constexpr HasTypeId(TypeId id) : id{id} { assert(id != TypeId::kTypeUnknown); }

    public:
    const TypeId id;
};

class TyId : public HasTypeId
{
    public:
    using str_t = std::string;
    using bytes_t = std::vector<uint8_t>;
    // Some compilers complain about incomplete types, so use a pointer
    using dict_t = std::unordered_map<str_t, std::unique_ptr<TyId>>;
    using int_t = std::uint64_t;
    using ref_t = TyId *;
    using variant_t = std::variant<str_t, bytes_t, int_t, ref_t, dict_t>;

    template <class T> static constexpr auto get_type_id() -> TypeId
    {
        if constexpr (std::is_same_v<T, str_t>)
        {
            return TypeId::kTypeStr;
        }
        else if constexpr (std::is_same_v<T, bytes_t>)
        {
            return TypeId::kTypeByte;
        }
        else if constexpr (std::is_same_v<T, dict_t>)
        {
            return TypeId::kTypeDict;
        }
        else if constexpr (std::is_same_v<T, int_t>)
        {
            return TypeId::kTypeInt;
        }
        else if constexpr (std::is_same_v<T, ref_t>)
        {
            return TypeId::kTypeRef;
        }
        else
        {
            return TypeId::kTypeUnknown;
        }
    }

    protected:
    variant_t value;

    public:
    TyId(TyId &&) = default;
    constexpr TyId(const TyId &) = delete;
    constexpr TyId() = delete;

    template <class T>
        requires(!std::is_same_v<std::decay_t<T>, TyId> && get_type_id<T>() != TypeId::kTypeUnknown)
    constexpr TyId(const T &value = {}) : HasTypeId{get_type_id<T>()}, value{value}
    {
    }
    template <class T>
        requires(!std::is_same_v<std::decay_t<T>, TyId> && get_type_id<T>() != TypeId::kTypeUnknown)
    constexpr TyId(T &&value) : HasTypeId{get_type_id<T>()}, value{std::forward<T>(value)}
    {
    }
    template <class T, class... Args>
        requires(!std::is_same_v<std::decay_t<T>, TyId> && get_type_id<T>() != TypeId::kTypeUnknown)
    TyId(std::in_place_type_t<T> ipt, Args &&...args)
        : HasTypeId{get_type_id<T>()}, value{ipt, std::forward<Args>(args)...}
    {
    }

    template <class T> constexpr auto visit(T &&fn) { return std::visit(fn, value); }
    template <class T> constexpr auto visit(T &&fn) const { return std::visit(fn, value); }
};

template <class T> class KnownType : public TyId
{
    using Type = T;

    public:
    template <class... Args>
    constexpr KnownType(Args &&...args) : TyId{T{std::forward<Args>(args)...}}
    {
    }

    auto operator->() -> T * { return &std::get<T>(value); }
    constexpr auto operator->() const -> const T * { return &std::get<T>(value); }
    constexpr auto operator*() const -> const T * { return &std::get<T>(value); }
};

#define _MAX_32_PTR_INDEX (1 << 24)

struct SmallPtrKey
{
    uint32_t key;
};

template <class T> struct SmallPtr : public SmallPtrKey
{
    constexpr SmallPtr(uint32_t key) : SmallPtrKey{key} {}
    constexpr SmallPtr(std::nullptr_t) : SmallPtrKey{0} {}
    constexpr SmallPtr(const SmallPtr &Other) = default;

    auto get() -> T *;
    operator T *() { return get(); }
    auto operator->() -> T * { return get(); }
    auto operator*() -> T * { return get(); }
    constexpr operator uint32_t() const { return key; }
};

template <class T> union MaybeSmallPtr
{
    SmallPtr<T> small_ptr;
    T *ptr;
    uint64_t large;

    inline bool is_small() const { return large <= _MAX_32_PTR_INDEX; }
};

class IOObjectAllocator
{
    public:
    template <class T, class... Args> auto alloc(Args &&...args) -> SmallPtr<T>
    {
        if (counter >= _MAX_32_PTR_INDEX)
        {
            counter = 1;
        }

        uint32_t key = counter++;

        map.insert({key, std::make_unique<T>(std::forward<Args>(args)...)});

        return {key};
    }

    void free(uint32_t key)
    {
        if (auto it = map.find(key); it != map.end())
        {
            map.erase(it);
        }
    }

    template <class T> T *get(uint32_t key) { return static_cast<T *>(map[key].get()); }

    private:
    uint32_t counter{1};
    std::unordered_map<uint32_t, std::unique_ptr<IOObject>> map{};
};

#define VBYTES(X) X, X + sizeof(X)

template <class T> struct EncValue
{
    KnownType<T> raw;
    KnownType<std::vector<uint8_t>> encrypted;
};

struct SystemInfo
{
    SystemInfo(const MachineInfo *info)
        : board_id{.raw{info->board_id}, .encrypted{}},
          root_disk_uuid{.raw{info->root_disk_uuid},
                         .encrypted{VBYTES(info->root_disk_uuid_encrypted)}},
          product_name{.raw{info->product_name}, .encrypted{}},
          platform_serial{.raw{info->platform_serial},
                          .encrypted{VBYTES(info->platform_serial_encrypted)}},
          platform_uuid{.raw{info->platform_uuid},
                        .encrypted{VBYTES(info->platform_uuid_encrypted)}},
          mlb{.raw{info->mlb}, .encrypted{VBYTES(info->mlb_encrypted)}},
          mac_address{.raw{VBYTES(info->mac)}, .encrypted{}},
          rom{.raw{VBYTES(info->rom)}, .encrypted{VBYTES(info->rom_encrypted)}}
    {
    }

    EncValue<std::string> board_id;
    EncValue<std::string> root_disk_uuid;
    EncValue<std::string> product_name;
    EncValue<std::string> platform_serial;
    EncValue<std::string> platform_uuid;
    EncValue<std::string> mlb;
    EncValue<std::vector<uint8_t>> mac_address;
    EncValue<std::vector<uint8_t>> rom;
};

using SystemInfoProperties = std::unordered_map<std::string_view, const TyId *>;

template <class T> class ServiceIterator : public IOObject
{
    public:
    ServiceIterator(const T *services, size_t index = 0) : services{services}, index{index} {}
    virtual ~ServiceIterator() override = default;

    constexpr auto operator==(const ServiceIterator &other) const -> bool
    {
        return index == other.index;
    }

    constexpr auto operator!=(const ServiceIterator &other) const -> bool
    {
        return index != other.index;
    }

    constexpr auto operator++() -> ServiceIterator &
    {
        ++index;
        return *this;
    }

    constexpr auto value() const -> const T *
    {
        const auto &reg = services[index];
        return &reg;
    }

    private:
    const T *services;
    size_t index;
};

template <class T> class RegistryEntry : public IOObject
{
    const T &registry;

    public:
    RegistryEntry(const T &registry) : registry{registry} {}

    auto operator[](std::string_view key) const -> const TyId *
    {
        return registry.properties.at(key);
    }
};

class IORegistry : IOObject
{
    friend class RegistryEntry<IORegistry>;

    public:
    using iter_t = ServiceIterator<IORegistry>;

    public:
    IORegistry(const SystemInfoProperties &properties)
        : entries{*this}, last_iter{this, 1ULL}, properties{properties}
    {
    }

    auto begin() -> iter_t const { return {this}; }
    auto end() -> iter_t const { return last_iter; }

    private:
    std::vector<RegistryEntry<IORegistry>> entries;
    iter_t last_iter;

    protected:
    const SystemInfoProperties &properties;
};

using IORegistryEntry = RegistryEntry<IORegistry>;
using IORegistryIterator = IORegistry::iter_t;

class IOService : public IOObject
{
    IORegistry *registry;

    public:
    IOService(IORegistry *registry) : registry{registry} {}
};

#pragma pack(push, 16)
struct ValidationMutableVars
{
    uint32_t var_2aa150;
    uint32_t var_2aa154;
    uint64_t var_2aa158;
    uint32_t var_2aa160[0x9C0];

    ValidationMutableVars() : var_2aa150{0xE24B36FA}, var_2aa154{0xCD18C502}, var_2aa158{0}
    {
        std::fill(var_2aa160, var_2aa160 + sizeof(var_2aa160) / sizeof(uint32_t), 0xD3C2BD4D);
    }
};
#pragma pack(pop)

struct ValidationThreadContext : public IOObjectAllocator
{
    IORegistry registry;
    SystemInfo sys_info;
    SystemInfoProperties sys_dict;
    ValidationMutableVars mutable_vars;

    ValidationThreadContext(ValidationThreadContext &&) = default;

    explicit ValidationThreadContext(const MachineInfo *info) : registry{sys_dict}, sys_info{info}
    {
        sys_dict.insert({"board-id", &sys_info.board_id.raw});
        sys_dict.insert({"product-name", &sys_info.product_name.raw});

        sys_dict.insert({"IOPlatformUUID", &sys_info.platform_uuid.raw});
        sys_dict.insert({"Fyp98tpgj", &sys_info.platform_uuid.encrypted});

        sys_dict.insert({"IOPlatformSerialNumber", &sys_info.platform_serial.raw});
        sys_dict.insert({"Gq3489ugfi", &sys_info.platform_serial.encrypted});

        sys_dict.insert({"IOMACAddress", &sys_info.mac_address.raw});
        sys_dict.insert({"kbjfrfpoJU", &sys_info.root_disk_uuid.encrypted});

        sys_dict.insert({"4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:ROM", &sys_info.rom.raw});
        sys_dict.insert({"oycqAZloTNDm", &sys_info.rom.encrypted});

        sys_dict.insert({"4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:MLB", &sys_info.mlb.raw});
        sys_dict.insert({"abKPld1EcMni", &sys_info.mlb.encrypted});
    }
};

thread_local std::optional<ValidationThreadContext> t_reg_context{};

template <class T> auto SmallPtr<T>::get() -> T * { return t_reg_context->get<T>(key); }

extern "C"
{
    extern void sub_ffffff8000ec7320(void *, uint64_t, void *);
    extern void sub_b1db0(...);
    extern void sub_b1dd0(...);
    extern void sub_b1df0(...);
    extern void sub_b1e30(...);
    
    void *f_malloc(size_t size) { return std::malloc(size); }
    void f_free(void *p) { std::free(p); }
    void *f_memcpy(void *dst, void *src, size_t size) { return std::memcpy(dst, src, size); }
    void f_bzero(void *s, size_t n) { memset(s, 0, n); }

    using CFTypeID = TypeId;
    using CFTypeIDRef = CFTypeID *;

    struct CFUUIDBytes
    {
        uint8_t bytes[16];
    };

    struct CFUUID
    {
        CFUUIDBytes bytes;
    };

    using CFUUIDRef = CFUUID *;

    struct CFRange
    {
        int64_t from, to;
    };

    using CFRangeRef = CFRange *;

    struct CFData
    {
        int value;
    };

    using CFDataRef = CFData *;

    struct DADisk
    {
        int value;
    };

    using DADiskRef = DADisk *;

    struct DASession
    {
        int value;
    };

    using DASessionRef = DASession *;

    struct CFDictionary
    {
        int value;
    };

    using CFDictionaryRef = CFDictionary *;

    struct CFAllocator
    {
        int value;
    };

    struct CFMutableDictionary
    {
        int value;
    };

    using CFMutableDictionaryRef = CFMutableDictionary *;

    using CFAllocatorRef = CFAllocator *;

    struct IOOptionBits
    {
        int value;
    };

    struct CFRuntimeBase
    {
        uintptr_t _cfisa;
        uint8_t _cfinfo[4];
        uint32_t _rc;
    };

    using CFTypeRef = HasTypeId *;

    struct CFType
    {
        int32_t value;
    };

    enum
    {
        _kCFRuntimeNotATypeID = 0
    };

    struct CFString
    {
        CFRuntimeBase base;
        union
        {
            struct
            {
                int32_t length;
            } inline1;

            struct
            {
                void *buffer;
                uint32_t length;
                CFAllocatorRef contentsDeallocator;
            } notInlineImmutable1;
            struct
            {
                void *buffer;
                CFAllocatorRef contentsDeallocator;
            } notInlineImmutable2;
            struct
            {
                void *buffer;
                uint32_t length;
                uint32_t capacityFields;
                uint32_t gapEtc;
                CFAllocatorRef contentsAllocator;
            } notInlineMutable;
        } variants;
    };

    using CFStringRef = CFString *;

    using kern_return_t = uint64_t;
    using mach_port_t = uint32_t;
    using io_name_t = char[128];
    using io_string_t = char[512];
    using io_object_t = const void *;
    using io_iterator_t = void *;
    using io_registry_entry_t = io_object_t;
    using io_service_t = io_object_t;

    using CFStringEncoding = uint32_t;

    struct CFBoolean
    {
        bool value;
    };

    using Boolean = bool;
    using CFHashCode = uint32_t;
    using CFIndex = int32_t;

    typedef const void *(*CFDictionaryRetainCallBack)(CFAllocatorRef allocator, const void *value);
    typedef void (*CFDictionaryReleaseCallBack)(CFAllocatorRef allocator, const void *value);
    typedef CFStringRef (*CFDictionaryCopyDescriptionCallBack)(const void *value);
    typedef Boolean (*CFDictionaryEqualCallBack)(const void *value1, const void *value2);
    typedef CFHashCode (*CFDictionaryHashCallBack)(const void *value);

    struct CFDictionaryValueCallBacks
    {
        CFIndex version;
        CFDictionaryRetainCallBack retain;
        CFDictionaryReleaseCallBack release;
        CFDictionaryCopyDescriptionCallBack copyDescription;
        CFDictionaryEqualCallBack equal;
    };

    struct CFDictionaryKeyCallBacks
    {
        CFIndex version;
        CFDictionaryRetainCallBack retain;
        CFDictionaryReleaseCallBack release;
        CFDictionaryCopyDescriptionCallBack copyDescription;
        CFDictionaryEqualCallBack equal;
        CFDictionaryHashCallBack hash;
    };

    mach_port_t kIOMasterPortDefault{};
    CFAllocatorRef kCFAllocatorDefault{};
    KnownType<TyId::int_t> kCFBooleanTrueValue{true};
    KnownType<TyId::int_t> *kCFBooleanTrue = &kCFBooleanTrueValue;
    CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks{};
    CFDictionaryKeyCallBacks kCFTypeDictionaryKeyCallBacks{};
    const char *kDADiskDescriptionVolumeUUIDKeyString{"DADiskDescriptionVolumeUUIDKey"};
    const char *kDADiskDescriptionVolumeUUIDKey{"DADiskDescriptionVolumeUUIDKey"};

    SmallPtrKey IOIteratorNext(SmallPtr<IORegistryIterator> iter)
    {
        if (**iter == t_reg_context->registry.end())
        {
            return {};
        }

        auto v = iter->value();
        ++(**iter);

        return t_reg_context->alloc<IORegistryIterator>(v);
    }

    WRAP_FAKE_API(IOIteratorNext);

    kern_return_t IOObjectRelease(MaybeSmallPtr<IOObject> object)
    {
        if (object.ptr)
        {
            if (object.is_small())
            {
                t_reg_context->free(object.small_ptr);
            }
            else
            {
                delete object.ptr;
            }
        }
        return {};
    }

    WRAP_FAKE_API(IOObjectRelease);

    const TyId *IORegistryEntryCreateCFProperty(SmallPtr<IORegistryEntry> entry, const char *key,
                                                CFAllocatorRef allocator, IOOptionBits options)
    {
        return (**entry)[key];
    }

    WRAP_FAKE_API(IORegistryEntryCreateCFProperty);

    uint32_t IORegistryEntryFromPath(mach_port_t masterPort, const io_string_t path)
    {
        return t_reg_context->alloc<IORegistryEntry>(t_reg_context->registry);
    }

    WRAP_FAKE_API(IORegistryEntryFromPath);

    kern_return_t IORegistryEntryGetParentEntry(SmallPtr<IORegistryEntry> entry,
                                                const io_name_t plane,
                                                SmallPtr<IORegistryEntry> *parent)
    {
        *parent = t_reg_context->alloc<IORegistryEntry>(t_reg_context->registry);
        return {};
    }

    WRAP_FAKE_API(IORegistryEntryGetParentEntry);

    kern_return_t IOServiceGetMatchingServices(mach_port_t masterPort, CFDictionaryRef matching,
                                               SmallPtr<IORegistryIterator> *existing)
    {
        *existing = t_reg_context->alloc<IORegistryIterator>(t_reg_context->registry.begin());
        return {};
    }

    WRAP_FAKE_API(IOServiceGetMatchingServices);

    SmallPtrKey IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching)
    {
        return t_reg_context->alloc<IORegistryEntry>(t_reg_context->registry);
    }

    WRAP_FAKE_API(IOServiceGetMatchingService);

    KnownType<TyId::dict_t> *
    CFDictionaryCreateMutable(CFAllocatorRef allocator, CFIndex capacity,
                              const CFDictionaryKeyCallBacks *keyCallBacks,
                              const CFDictionaryValueCallBacks *valueCallBacks)
    {
        return new KnownType<TyId::dict_t>();
    }

    WRAP_FAKE_API(CFDictionaryCreateMutable);

    const TyId *CFDictionaryGetValue(KnownType<TyId::dict_t> *theDict, const char *key)
    {
        if (auto it = (*theDict)->find(key); it != (*theDict)->end())
        {
            return it->second.get();
        }
        return nullptr;
    }

    WRAP_FAKE_API(CFDictionaryGetValue);

    void CFDictionarySetValue(KnownType<TyId::dict_t> *theDict, const char *key, TyId *value)
    {
        (*theDict)->insert({key, std::make_unique<TyId>(std::move(*value))});
    }

    WRAP_FAKE_API(CFDictionarySetValue);

    KnownType<TyId::dict_t> *DADiskCopyDescription(DADiskRef disk)
    {
        auto *dict = new KnownType<TyId::dict_t>();

        (*dict)->emplace(kDADiskDescriptionVolumeUUIDKeyString,
                         std::make_unique<TyId>(**t_reg_context->sys_info.root_disk_uuid.raw));

        return dict;
    }

    WRAP_FAKE_API(DADiskCopyDescription);

    DADiskRef DADiskCreateFromBSDName(CFAllocatorRef allocator, DASessionRef session,
                                      const char *name)
    {
        static DADisk disk;
        return &disk;
    }

    WRAP_FAKE_API(DADiskCreateFromBSDName);

    DASessionRef DASessionCreate(CFAllocatorRef allocator)
    {
        static DASession session;
        return &session;
    }

    WRAP_FAKE_API(DASessionCreate);

    void *__memset_chk(void *dest, int val, size_t len, size_t dstlen)
    {
        return memset(dest, val, len);
    }

    WRAP_FAKE_API(__memset_chk);

    void __stack_chk_fail() {}

    WRAP_FAKE_API(__stack_chk_fail);

    uint32_t arc4random() { return 0; }

    WRAP_FAKE_API(arc4random);

    void *statfs_INODE64() { return {}; }

    WRAP_FAKE_API(statfs_INODE64);

    int sysctlbyname(const char *name, void *dst, size_t *sz, void *, size_t)
    {
#if USE_KERN_VERSION
        constexpr std::string_view os_version = "17.4.0";
        constexpr std::string_view os_revision = "199506";

        if (strcmp(name, "kern.osversion") == 0)
        {
            memcpy(dst, os_version.data(), *sz = os_version.size());
        }
        else if (strcmp(name, "kern.osrevision") == 0)
        {
            memcpy(dst, os_revision.data(), *sz = os_revision.size());
        }

        return 0;
#else
        return 1;
#endif
    }

    WRAP_FAKE_API(sysctlbyname);

    void CFDataGetBytes(const TyId *theData, uint64_t from, uint64_t to, uint8_t *buffer)
    {
        const auto [size, data] = (*theData).visit(
            [](const auto &v) -> std::tuple<size_t, const uint8_t *>
            {
                if constexpr (std::is_same_v<std::decay_t<decltype(v)>, TyId::str_t> ||
                              std::is_same_v<std::decay_t<decltype(v)>, TyId::bytes_t>)
                {
                    return {v.size(), reinterpret_cast<const uint8_t *>(v.data())};
                }
                else
                {
                    return {0ULL, nullptr};
                }
            });

        assert(data);
        assert(size >= to);

        if (size >= to)
        {
            memcpy(buffer, data + from, to - from);
        }
    }

    WRAP_FAKE_API(CFDataGetBytes);

    CFIndex CFDataGetLength(KnownType<TyId::bytes_t> *theData) { return (*theData)->size(); }

    WRAP_FAKE_API(CFDataGetLength);

    CFTypeID CFDataGetTypeID() { return TypeId::kTypeByte; }

    WRAP_FAKE_API(CFDataGetTypeID);

    CFTypeID CFGetTypeID(CFTypeRef cf)
    {
        if (!cf)
        {
            return CFTypeID::kTypeUnknown;
        }

        return cf->id;
    }

    WRAP_FAKE_API(CFGetTypeID);

    void CFRelease(CFTypeRef cf) {}

    WRAP_FAKE_API(CFRelease);

    bool CFStringGetCString(KnownType<TyId::str_t> *theString, char *buffer, CFIndex bufferSize,
                            CFStringEncoding encoding)
    {
        std::memcpy(buffer, (*theString)->data(), bufferSize);
#ifdef _WIN32
        strncpy_s(buffer, bufferSize, (*theString)->data(), (*theString)->size());
#else
        std::strncpy(buffer, (*theString)->data(), (*theString)->size());
#endif
        return true;
    }

    WRAP_FAKE_API(CFStringGetCString);

    CFIndex CFStringGetLength(KnownType<TyId::str_t> *theString) { return (*theString)->size(); }

    WRAP_FAKE_API(CFStringGetLength);

    CFIndex CFStringGetMaximumSizeForEncoding(CFIndex length, CFStringEncoding encoding)
    {
        return length;
    }

    WRAP_FAKE_API(CFStringGetMaximumSizeForEncoding);

    KnownType<TyId::str_t> *CFUUIDCreateString(CFAllocatorRef alloc, KnownType<TyId::str_t> *uuid)
    {
        // Assume already uuid
        return uuid;
    }

    WRAP_FAKE_API(CFUUIDCreateString);

    CFTypeID CFStringGetTypeID(void) { return CFTypeID::kTypeStr; }

    WRAP_FAKE_API(CFStringGetTypeID);

    KnownType<TyId::dict_t> *IOServiceMatching(const char *name)
    {
        auto *dict = new KnownType<TyId::dict_t>();

        (*dict)->emplace("IOProviderClass",
                         std::make_unique<TyId>(std::in_place_type_t<std::string>{}, name));

        return dict;
    }

    WRAP_FAKE_API(IOServiceMatching);

    WRAP_FAKE_API_P(f_memcpy, memcpy);
    WRAP_FAKE_API_P(f_malloc, malloc);
    WRAP_FAKE_API_P(f_free, free);
    WRAP_FAKE_API_P(f_bzero, __bzero);

    auto __writable_variables() -> void * { return &t_reg_context->mutable_vars; }
}

#ifdef _WIN32
#define a_sscanf sscanf_s
#else
#define a_sscanf std::sscanf
#endif

template <size_t N> constexpr auto byte_scan_template()
{
    constexpr std::string_view byte_template = "%2hhx";

    std::array<char, N * byte_template.size() + 1> template_string = {};

    for (size_t i = 0; i < template_string.size() - 1; ++i)
    {
        template_string[i] = byte_template[i % byte_template.size()];
    }

    return template_string;
}

template <std::ranges::random_access_range T>
auto UUIDFromString(std::string_view uuid, T &result) -> bool
{
    constexpr size_t Len = 16;

    return unpack_iterator_into<Len>(
               [uuid](auto &&...v)
               {
                   constexpr auto scan_template = "%2hhx%2hhx%2hhx%2hhx-%2hhx%2hhx-%2hhx%2hhx-%2hhx%"
                                                 "2hhx-%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx";

                   return a_sscanf(uuid.data(), scan_template, std::forward<decltype(v)>(v)...);
               },
               result) == Len;
}

template <size_t Len, std::ranges::random_access_range T>
auto BytesFromString(std::string_view rom, T &result) -> bool
{
    return unpack_iterator_into<Len>(
               [rom](auto &&...v)
               {
                   constexpr auto scan_template = byte_scan_template<Len>();

                   return a_sscanf(rom.data(), scan_template.data(),
                                   std::forward<decltype(v)>(v)...);
               },
               result) == Len;
}

template <std::ranges::random_access_range T>
auto MACFromString(std::string_view IOMACAddress, T &result) -> bool
{
    auto mac = IOMACAddress |
               std::ranges::views::filter([](const auto C) -> bool { return C != ':'; }) |
               std::ranges::views::transform([](const auto C) -> char { return std::toupper(C); });

    return BytesFromString<6>(std::string(mac.begin(), mac.end()), result);
}

template <size_t Index, std::ranges::random_access_range T>
constexpr auto access_index(const T &arr) -> typename T::element_type
{
    return arr[Index];
}

template <size_t Index, class... Args, class Fn>
constexpr auto indexed(Fn fn, Args &&...args) //-> std::invoke_result<Fn, Args...>
{
    return std::invoke(fn, std::forward<Args>(args)...);
}

template <size_t N, std::ranges::contiguous_range T, class Fn>
constexpr auto unpack_iterator_into(Fn func, T &rng)
{
    return
        [rng{std::ranges::subrange(rng)}, func]<size_t... Indices>(std::index_sequence<Indices...>)
    {
        auto iter = rng.begin();
        auto arr = std::array{indexed<Indices>([](auto &iter) { return &*iter++; }, iter)...};

        return std::invoke(func, std::get<Indices>(arr)...);
    }(std::make_index_sequence<N>());
}

extern "C"
{
#define CHECK_PARAM(X)                                                                             \
    if (!X)                                                                                        \
        return NAC_INVALID_PARAMETER;

    EXPORT_CRYPT NacError build_machine_info(const char *board_id, const char *root_disk_uuid,
                                             const char *product_name, const char *platform_serial,
                                             const char *platform_uuid, const char *mlb,
                                             const char *rom, const char *mac, MachineInfo *info)
    {
        CHECK_PARAM(board_id);
        CHECK_PARAM(root_disk_uuid);
        CHECK_PARAM(product_name);
        CHECK_PARAM(platform_serial);
        CHECK_PARAM(platform_uuid);
        CHECK_PARAM(mlb);
        CHECK_PARAM(rom);
        CHECK_PARAM(mac);
        CHECK_PARAM(info);

        MachineInfo info_result{};

        std::memcpy(info_result.board_id, board_id, std::strlen(board_id));
        std::memcpy(info_result.product_name, product_name, std::strlen(product_name));
        std::memcpy(info_result.platform_serial, platform_serial, std::strlen(platform_serial));
        std::memcpy(info_result.mlb, mlb, std::strlen(mlb));
        std::memcpy(info_result.root_disk_uuid, root_disk_uuid, std::strlen(root_disk_uuid));
        std::memcpy(info_result.platform_uuid, platform_uuid, std::strlen(platform_uuid));

        uint64_t result = encrypt_io_data(platform_serial, std::strlen(platform_serial),
                                          info_result.platform_serial_encrypted);

        if (result)
        {
            return NAC_ENCRYPT_ERROR;
        }

        {
            std::array<uint8_t, 16> uuid;

            if (!UUIDFromString(root_disk_uuid, uuid))
            {
                return NAC_INVALID_PARAMETER;
            }

            result =
                encrypt_io_data(uuid.data(), uuid.size(), info_result.root_disk_uuid_encrypted);

            if (result)
            {
                return NAC_ENCRYPT_ERROR;
            }
        }

        {
            std::array<uint8_t, 16> uuid;

            if (!UUIDFromString(platform_uuid, uuid))
            {
                return NAC_INVALID_PARAMETER;
            }

            result = encrypt_io_data(uuid.data(), uuid.size(), info_result.platform_uuid_encrypted);

            if (result)
            {
                return NAC_ENCRYPT_ERROR;
            }
        }

        if (!MACFromString(rom, info_result.rom))
        {
            return NAC_INVALID_PARAMETER;
        }

        if (!MACFromString(mac, info_result.mac))
        {
            return NAC_INVALID_PARAMETER;
        }

        result = encrypt_io_data(info_result.mlb, std::strlen(info_result.mlb) + 1,
                                 info_result.mlb_encrypted);

        if (result)
        {
            return NAC_ENCRYPT_ERROR;
        }

        result =
            encrypt_io_data(info_result.rom, sizeof(info_result.rom), info_result.rom_encrypted);

        if (result)
        {
            return NAC_ENCRYPT_ERROR;
        }

        *info = info_result;

        return NAC_NO_ERROR;
    }

    EXPORT_CRYPT NacError encrypt_io_data(const void *data, unsigned int size, void *output)
    {
        CHECK_PARAM(data);
        CHECK_PARAM(size);
        CHECK_PARAM(output);

        if (!data)
        {
            return NAC_INVALID_PARAMETER;
        }

        if (!size)
        {
            return NAC_INVALID_PARAMETER;
        }

        if (!output)
        {
            return NAC_INVALID_PARAMETER;
        }

        uint64_t result = call_external<uint64_t>(&sub_ffffff8000ec7320, data, size, output);

        if (result)
        {
            return NAC_ENCRYPT_ERROR;
        }

        return NAC_NO_ERROR;
    }

    EXPORT_CRYPT NacError init_nac_request(const ValidationCert *cert,
                                           const MachineInfo *machine_info,
                                           ValidationContext **out_context,
                                           ValidationRequest **out_request)
    {
        CHECK_PARAM(cert);
        CHECK_PARAM(machine_info);
        CHECK_PARAM(out_context);
        CHECK_PARAM(out_request);

        t_reg_context.emplace(machine_info);

        if (!cert)
        {
            return NAC_INVALID_PARAMETER;
        }

        if (!out_context)
        {
            return NAC_INVALID_PARAMETER;
        }

        if (!out_request)
        {
            return NAC_INVALID_PARAMETER;
        }

        uint64_t request_len{};
        uint64_t result = call_external<uint64_t>(&sub_b1db0, cert, sizeof(ValidationCert),
                                                  out_context, out_request, &request_len);

        if (result)
        {
            return NAC_SIGN_ERROR;
        }

        if (request_len != sizeof(ValidationRequest)) 
        {
            return NAC_SIGN_ERROR;
        }

        return NAC_NO_ERROR;
    }

    EXPORT_CRYPT NacError sign_nac_request(ValidationContext *context, const SessionData *session,
                                           ValidationSignature **out_validation,
                                           unsigned int *out_validation_length)
    {
        CHECK_PARAM(context);
        CHECK_PARAM(session);
        CHECK_PARAM(out_validation);
        CHECK_PARAM(out_validation_length);

        if (!t_reg_context)
        {
            return NAC_INVALID_CALL;
        }

        auto sz = sizeof(SessionData);
        uint64_t result = call_external<uint64_t>(&sub_b1dd0, context, session, sz);

        if (result)
        {
            return NAC_REQUEST_ERROR;
        }

        result = call_external<uint64_t>(&sub_b1df0, context, 0ull, 0ull, out_validation,
                                         out_validation_length);

        if (result)
        {
            return NAC_REQUEST_ERROR;
        }

        return NAC_NO_ERROR;
    }

    EXPORT_CRYPT NacError free_nac(ValidationContext *context)
    {
        if (context)
        {
            uint64_t result = call_external<uint64_t>(&sub_b1e30, context);

            if (result)
            {
                return NAC_FREE_ERROR;
            }
        }

        return NAC_NO_ERROR;
    }

    EXPORT_CRYPT void free_data(void *data)
    {
        if (data)
        {
            free(data);
        }
    }
}