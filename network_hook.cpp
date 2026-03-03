//
// Encrypt Hook implementation for logging encryption function calls
//

#include "network_hook.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include <dlfcn.h>
#include <cstring>
#include <cinttypes>
#include <cstdio>
#include <string>
#include <fstream>
#include <sstream>
#include <sys/mman.h>
#include <unistd.h>
#include <iomanip>

#if !ENABLE_NETWORK_HOOK
// Hook disabled, provide empty implementation
void hook_network_methods(void *il2cpp_handle, const char *game_data_dir) {
    LOGI("Encrypt hooks are disabled");
}
#else

// Encrypt function offset from base address
#define ENCRYPT_FUNCTION_OFFSET 0x45FC70C

// Original encrypt function pointer
static void (*Encrypt_Function_Original)(void *arg0) = nullptr;

// Helper function to convert bytes to hex string
static std::string bytes_to_hex(const uint8_t *data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; i++) {
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return ss.str();
}

// Hook wrapper for encrypt function
// Based on Frida script logic:
// - args[0] is the first parameter
// - Read pointer from args[0] -> struct_ptr
// - Read pointer from struct_ptr + 0xB8 -> key_array_ptr
// - Read U32 from key_array_ptr + 24 -> key_length
// - Read ByteArray from key_array_ptr + 32 -> key_data
static void Encrypt_Function_Hook_Wrapper(void *arg0) {
    LOGI("[*] Encrypt function called");
    LOGI("[*] arg0: %p", arg0);
    
    if (!arg0) {
        LOGW("[*] arg0 is null, skipping");
        if (Encrypt_Function_Original) {
            Encrypt_Function_Original(arg0);
        }
        return;
    }
    
    // Check if memory is readable
    if ((uintptr_t)arg0 < 0x1000 || (uintptr_t)arg0 > 0x7FFFFFFFFFFFFFFF) {
        LOGW("[*] arg0 has invalid address: %p", arg0);
        if (Encrypt_Function_Original) {
            Encrypt_Function_Original(arg0);
        }
        return;
    }
    
    try {
        // Read struct pointer from args[0]
        void *struct_ptr = nullptr;
        __builtin_memcpy(&struct_ptr, arg0, sizeof(void*));
        LOGI("[*] struct_ptr: %p", struct_ptr);
        
        if (!struct_ptr) {
            LOGW("[*] struct_ptr is null");
            if (Encrypt_Function_Original) {
                Encrypt_Function_Original(arg0);
            }
            return;
        }
        
        // Check struct_ptr validity
        if ((uintptr_t)struct_ptr < 0x1000 || (uintptr_t)struct_ptr > 0x7FFFFFFFFFFFFFFF) {
            LOGW("[*] struct_ptr has invalid address: %p", struct_ptr);
            if (Encrypt_Function_Original) {
                Encrypt_Function_Original(arg0);
            }
            return;
        }
        
        // Read key array pointer from struct_ptr + 0xB8
        void *key_array_ptr = nullptr;
        uint8_t *struct_base = (uint8_t*)struct_ptr;
        __builtin_memcpy(&key_array_ptr, struct_base + 0xB8, sizeof(void*));
        LOGI("[*] Key array address: %p", key_array_ptr);
        
        if (!key_array_ptr) {
            LOGW("[*] key_array_ptr is null");
            if (Encrypt_Function_Original) {
                Encrypt_Function_Original(arg0);
            }
            return;
        }
        
        // Check key_array_ptr validity
        if ((uintptr_t)key_array_ptr < 0x1000 || (uintptr_t)key_array_ptr > 0x7FFFFFFFFFFFFFFF) {
            LOGW("[*] key_array_ptr has invalid address: %p", key_array_ptr);
            if (Encrypt_Function_Original) {
                Encrypt_Function_Original(arg0);
            }
            return;
        }
        
        // Read key length from key_array_ptr + 24
        uint32_t key_length = 0;
        uint8_t *key_array_base = (uint8_t*)key_array_ptr;
        __builtin_memcpy(&key_length, key_array_base + 24, sizeof(uint32_t));
        LOGI("[*] Key length: %u", key_length);
        
        // Validate key length
        if (key_length == 0 || key_length > 1024) {
            LOGW("[*] Invalid key length: %u", key_length);
            if (Encrypt_Function_Original) {
                Encrypt_Function_Original(arg0);
            }
            return;
        }
        
        // Read key data from key_array_ptr + 32
        uint8_t *key_data_ptr = key_array_base + 32;
        
        // Check if we can safely read the key data
        if ((uintptr_t)key_data_ptr < 0x1000 || 
            (uintptr_t)key_data_ptr > 0x7FFFFFFFFFFFFFFF ||
            (uintptr_t)(key_data_ptr + key_length) > 0x7FFFFFFFFFFFFFFF) {
            LOGW("[*] Key data pointer out of bounds");
            if (Encrypt_Function_Original) {
                Encrypt_Function_Original(arg0);
            }
            return;
        }
        
        // Read key data
        uint8_t *key_data = new uint8_t[key_length];
        __builtin_memcpy(key_data, key_data_ptr, key_length);
        
        // Convert to hex string
        std::string key_hex = bytes_to_hex(key_data, key_length);
        LOGI("[*] Key (hex): %s", key_hex.c_str());
        LOGI("[*] Key: %s", key_hex.c_str());
        
        delete[] key_data;
    } catch (...) {
        LOGE("[*] Exception occurred while reading key data");
    }
    
    // Call original function
    if (Encrypt_Function_Original) {
        Encrypt_Function_Original(arg0);
    }
}

// Install function hook using inline hook with trampoline
template<typename FuncPtr>
static bool install_hook(void *target_addr, void *hook_func, FuncPtr *original_func) {
    if (!target_addr || !hook_func) {
        LOGE("Invalid hook parameters");
        return false;
    }
    
    // Save original function pointer
    *original_func = (FuncPtr)target_addr;
    
    // Calculate relative offset for branch instruction
    int64_t offset = (int64_t)hook_func - (int64_t)target_addr;
    
    // Check if offset is within range for ARM64 branch instruction
    // ARM64 branch range: ±128MB
    if (offset >= -0x8000000 && offset <= 0x7FFFFFF) {
        // Direct branch is possible
        // Make memory writable
        size_t page_size = getpagesize();
        uintptr_t page_start = (uintptr_t)target_addr & ~(page_size - 1);
        
        if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            LOGE("Failed to make memory writable");
            return false;
        }
        
        // ARM64 branch instruction: B <offset>
        // Encoding: 0x14 | (offset >> 2) & 0x3FFFFFF
        uint32_t branch_inst = 0x14000000 | ((offset >> 2) & 0x3FFFFFF);
        *(uint32_t*)target_addr = branch_inst;
        
        // Flush instruction cache
        __builtin___clear_cache((char*)target_addr, (char*)target_addr + 4);
        
        LOGI("Hook installed at %p -> %p (direct, offset: %" PRId64 ")", target_addr, hook_func, offset);
        return true;
    } else {
        // Offset out of range, use trampoline
        // Try to allocate memory near target function (within ±128MB)
        size_t page_size = getpagesize();
        uintptr_t target_page = (uintptr_t)target_addr & ~(page_size - 1);
        
        // Try to allocate memory in the same page or nearby
        void *trampoline = nullptr;
        for (int i = 0; i < 10; i++) {
            // Try allocating at different offsets
            uintptr_t try_addr = target_page + (i * page_size);
            trampoline = mmap((void*)try_addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (trampoline != MAP_FAILED) {
                break;
            }
        }
        
        if (trampoline == nullptr || trampoline == MAP_FAILED) {
            // Fallback: allocate anywhere
            trampoline = mmap(nullptr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        }
        
        if (trampoline == nullptr || trampoline == MAP_FAILED) {
            LOGE("Failed to allocate trampoline memory");
            return false;
        }
        
        // Calculate offsets
        int64_t offset_to_trampoline = (int64_t)trampoline - (int64_t)target_addr;
        int64_t offset_to_hook = (int64_t)hook_func - (int64_t)trampoline;
        
        // Check if we can reach trampoline
        if (offset_to_trampoline < -0x8000000 || offset_to_trampoline > 0x7FFFFFF) {
            LOGE("Trampoline offset out of range: %" PRId64, offset_to_trampoline);
            munmap(trampoline, page_size);
            return false;
        }
        
        // Build trampoline code to jump to hook function
        // If hook is also out of range from trampoline, use absolute address
        uint32_t *trampoline_code = (uint32_t*)trampoline;
        if (offset_to_hook >= -0x8000000 && offset_to_hook <= 0x7FFFFFF) {
            // Can use relative branch from trampoline
            trampoline_code[0] = 0x14000000 | ((offset_to_hook >> 2) & 0x3FFFFFF);
        } else {
            // Use absolute address: LDR x16, [PC+8]; BR x16; .quad hook_func
            trampoline_code[0] = 0x58000050; // LDR x16, [PC, #8]
            trampoline_code[1] = 0xD61F0200; // BR x16
            *(uint64_t*)(&trampoline_code[2]) = (uint64_t)hook_func;
            __builtin___clear_cache((char*)trampoline, (char*)trampoline + 16);
        }
        
        // Make target memory writable
        uintptr_t page_start = (uintptr_t)target_addr & ~(page_size - 1);
        if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            LOGE("Failed to make memory writable");
            munmap(trampoline, page_size);
            return false;
        }
        
        // Write branch to trampoline
        uint32_t branch_inst = 0x14000000 | ((offset_to_trampoline >> 2) & 0x3FFFFFF);
        *(uint32_t*)target_addr = branch_inst;
        
        // Flush instruction cache
        __builtin___clear_cache((char*)target_addr, (char*)target_addr + 4);
        
        LOGI("Hook installed at %p -> trampoline %p -> hook %p", target_addr, trampoline, hook_func);
        return true;
    }
}

// Hook encrypt function
void hook_network_methods(void *il2cpp_handle, const char *game_data_dir) {
    LOGI("Installing encrypt function hook...");
    
    if (!il2cpp_handle) {
        LOGE("Invalid il2cpp handle");
        return;
    }
    
    // Get libil2cpp.so base address from handle
    Dl_info dlInfo;
    uint64_t target_base = 0;
    
    // Try to get base address using dladdr on the handle
    if (dladdr(il2cpp_handle, &dlInfo)) {
        target_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
        LOGI("Found libil2cpp.so base: 0x%" PRIx64, target_base);
    } else {
        // Fallback: try to get base from any symbol in the handle
        void *sym = dlsym(il2cpp_handle, "il2cpp_init");
        if (sym && dladdr(sym, &dlInfo)) {
            target_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
            LOGI("Found libil2cpp.so base via symbol: 0x%" PRIx64, target_base);
        } else {
            LOGE("Failed to get libil2cpp.so base address");
            return;
        }
    }
    
    if (target_base == 0) {
        LOGE("Failed to find libil2cpp.so base address");
        return;
    }
    
    // Calculate encrypt function address: base + offset
    uint64_t encrypt_addr = target_base + ENCRYPT_FUNCTION_OFFSET;
    void *encrypt_func_ptr = (void*)encrypt_addr;
    
    LOGI("Target module base: 0x%" PRIx64, target_base);
    LOGI("Encrypt function offset: 0x%X", ENCRYPT_FUNCTION_OFFSET);
    LOGI("Encrypt function address: 0x%" PRIx64 " (%p)", encrypt_addr, encrypt_func_ptr);
    
    // Verify the address is readable
    Dl_info verifyInfo;
    if (dladdr(encrypt_func_ptr, &verifyInfo)) {
        LOGI("Address verified, belongs to: %s", verifyInfo.dli_fname ? verifyInfo.dli_fname : "unknown");
    } else {
        LOGW("Warning: Could not verify address with dladdr");
    }
    
    // Wait a bit for module to be fully loaded
    sleep(2);
    
    // Install hook
    LOGI("Installing hook at %p", encrypt_func_ptr);
    if (install_hook(encrypt_func_ptr, (void*)Encrypt_Function_Hook_Wrapper, &Encrypt_Function_Original)) {
        LOGI("✓ Encrypt function hooked successfully");
    } else {
        LOGE("✗ Failed to hook encrypt function");
    }
    
    LOGI("Encrypt hook installation completed");
}

#endif // ENABLE_NETWORK_HOOK

