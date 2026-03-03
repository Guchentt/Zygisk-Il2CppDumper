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
#include <climits>
#include <errno.h>

// External il2cpp base address (set in il2cpp_dump.cpp)
extern uint64_t il2cpp_base;

// Helper macro to check if pointer is valid (within reasonable range)
#define IS_VALID_PTR(ptr) ((ptr) != nullptr && (uintptr_t)(ptr) >= 0x1000 && (uintptr_t)(ptr) < UINTPTR_MAX)

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

// Static counter to limit logging frequency
static uint32_t hook_call_count = 0;
static bool key_logged = false;

// ============ 权限检查函数 ============

// 检查内存权限
static bool is_memory_executable(void *addr) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return false;
    
    char line[512];
    uintptr_t target = (uintptr_t)addr;
    bool executable = false;
    
    while (fgets(line, sizeof(line), maps)) {
        uintptr_t start, end;
        char perms[5];
        
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (target >= start && target < end) {
                executable = (perms[2] == 'x');  // 检查执行权限
                break;
            }
        }
    }
    
    fclose(maps);
    return executable;
}

// 调试函数：打印内存权限
static void debug_memory_permissions(void *addr, const char *name) {
    LOGI("Checking %s permissions at %p:", name, addr);
    
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return;
    
    char line[512];
    uintptr_t target = (uintptr_t)addr;
    bool found = false;
    
    while (fgets(line, sizeof(line), maps)) {
        uintptr_t start, end;
        char perms[5];
        char path[256] = "";
        
        // 解析 maps 行
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) >= 3) {
            // 尝试读取路径
            char *path_start = strchr(line, '/');
            if (path_start) {
                strncpy(path, path_start, sizeof(path) - 1);
                path[strcspn(path, "\n")] = '\0';
            }
            
            if (target >= start && target < end) {
                LOGI("  Range: 0x%lx-0x%lx Perms: %s Path: %s", 
                     start, end, perms, path[0] ? path : "[anonymous]");
                found = true;
                break;
            }
        }
    }
    
    if (!found) {
        LOGI("  Not found in memory maps!");
    }
    
    fclose(maps);
}

// Hook wrapper for encrypt function
// Based on Frida script logic:
// - args[0] is the first parameter
// - Read pointer from args[0] -> struct_ptr
// - Read pointer from struct_ptr + 0xB8 -> key_array_ptr
// - Read U32 from key_array_ptr + 24 -> key_length
// - Read ByteArray from key_array_ptr + 32 -> key_data
static void Encrypt_Function_Hook_Wrapper(void *arg0) {
    // 限制调用次数
    hook_call_count++;
    
    LOGI("[*] Encrypt function called #%u", hook_call_count);
    
    // 只在第一次调用时记录详细信息
    if (hook_call_count <= 3) {
        LOGI("[*] arg0: %p", arg0);
        
        // 尝试读取密钥
        if (IS_VALID_PTR(arg0)) {
            void *struct_ptr = nullptr;
            __builtin_memcpy(&struct_ptr, arg0, sizeof(void*));
            
            if (IS_VALID_PTR(struct_ptr)) {
                void *key_array_ptr = nullptr;
                uint8_t *struct_base = (uint8_t*)struct_ptr;
                __builtin_memcpy(&key_array_ptr, struct_base + 0xB8, sizeof(void*));
                
                if (IS_VALID_PTR(key_array_ptr)) {
                    uint32_t key_length = 0;
                    uint8_t *key_array_base = (uint8_t*)key_array_ptr;
                    __builtin_memcpy(&key_length, key_array_base + 24, sizeof(uint32_t));
                    
                    if (key_length > 0 && key_length <= 64) {
                        uint8_t *key_data_ptr = key_array_base + 32;
                        if (IS_VALID_PTR(key_data_ptr)) {
                            uint8_t key_buffer[64];
                            __builtin_memcpy(key_buffer, key_data_ptr, key_length);
                            
                            char hex_str[129];
                            for (uint32_t i = 0; i < key_length; i++) {
                                hex_str[i * 2] = "0123456789abcdef"[(key_buffer[i] >> 4) & 0xF];
                                hex_str[i * 2 + 1] = "0123456789abcdef"[key_buffer[i] & 0xF];
                            }
                            hex_str[key_length * 2] = '\0';
                            
                            LOGI("[*] Key length: %u, Key (hex): %s", key_length, hex_str);
                            key_logged = true;
                        }
                    }
                }
            }
        }
    }
    
    // ============ 关键：调用原始函数 ============
    if (Encrypt_Function_Original) {
        Encrypt_Function_Original(arg0);
    } else {
        LOGE("[*] Original function pointer is null!");
    }
}

// Install function hook using inline hook with trampoline
template<typename FuncPtr>
static bool install_hook(void *target_addr, void *hook_func, FuncPtr *original_func) {
    if (!target_addr || !hook_func) {
        LOGE("Invalid hook parameters");
        return false;
    }
    
    LOGI("Installing hook: target=%p, hook=%p", target_addr, hook_func);
    debug_memory_permissions(target_addr, "target function");
    
    // Verify target address is executable and aligned
    if ((uintptr_t)target_addr & 0x3) {
        LOGE("Target address not 4-byte aligned: %p", target_addr);
        return false;
    }
    
    // Get page size
    size_t page_size = getpagesize();
    uintptr_t target_page_start = (uintptr_t)target_addr & ~(page_size - 1);
    
    LOGI("Page size: %zu, Target page start: 0x%lx", page_size, target_page_start);
    
    // Make target memory writable
    if (mprotect((void*)target_page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("Failed to make memory writable: %s (errno=%d)", strerror(errno), errno);
        return false;
    }
    LOGI("Target memory made writable");
    
    // ============ 分配 trampoline 内存 ============
    
    // 分配 trampoline 内存（一个完整页面）
    void *trampoline = mmap(nullptr, page_size, 
                           PROT_READ | PROT_WRITE,  // 先申请读写权限
                           MAP_PRIVATE | MAP_ANONYMOUS, 
                           -1, 0);
    
    if (trampoline == MAP_FAILED) {
        LOGE("Failed to allocate trampoline memory: %s (errno=%d)", strerror(errno), errno);
        return false;
    }
    
    // 确保地址对齐
    if ((uintptr_t)trampoline & 0x3) {
        LOGE("Trampoline not 4-byte aligned: %p", trampoline);
        munmap(trampoline, page_size);
        return false;
    }
    
    LOGI("Trampoline allocated at %p (size: %zu)", trampoline, page_size);
    debug_memory_permissions(trampoline, "trampoline (before setup)");
    
    // ============ 构建 trampoline 代码 ============
    
    uint32_t *target_code = (uint32_t*)target_addr;
    uint32_t *trampoline_code = (uint32_t*)trampoline;
    
    // 保存原始指令
    uint32_t saved_instructions[4];
    LOGI("Reading original instructions at %p:", target_addr);
    for (int i = 0; i < 4; i++) {
        saved_instructions[i] = target_code[i];
        LOGI("  [%d] 0x%08X", i, saved_instructions[i]);
    }
    
    // 计算跳回地址（目标函数+16字节）
    void *return_addr = (void*)((uintptr_t)target_addr + 16);
    LOGI("Return address after trampoline: %p", return_addr);
    
    // 复制原始指令到 trampoline
    for (int i = 0; i < 4; i++) {
        trampoline_code[i] = saved_instructions[i];
    }
    
    // 在 trampoline 末尾添加跳回指令
    uintptr_t trampoline_jump_addr = (uintptr_t)trampoline + 16;  // 4条指令后
    int64_t offset_to_return = (int64_t)return_addr - (int64_t)trampoline_jump_addr;
    
    LOGI("Trampoline jump from 0x%lx to %p, offset: %" PRId64, 
         trampoline_jump_addr, return_addr, offset_to_return);
    
    if (offset_to_return >= -0x8000000 && offset_to_return <= 0x7FFFFFF) {
        // 相对跳转
        trampoline_code[4] = 0x14000000 | ((offset_to_return >> 2) & 0x3FFFFFF);
        LOGI("Using relative jump back: 0x%08X", trampoline_code[4]);
    } else {
        // 绝对跳转
        trampoline_code[4] = 0x58000050; // LDR x16, [PC, #8]
        trampoline_code[5] = 0xD61F0200; // BR x16
        *(uint64_t*)(&trampoline_code[6]) = (uint64_t)return_addr;
        LOGI("Using absolute jump back via x16");
    }
    
    // ============ 确保 trampoline 内存可执行 ============
    
    uintptr_t trampoline_page = (uintptr_t)trampoline & ~(page_size - 1);
    
    LOGI("Setting trampoline memory to executable (page: 0x%lx)", trampoline_page);
    
    // 首先确保是读写权限
    if (mprotect((void*)trampoline_page, page_size, PROT_READ | PROT_WRITE) != 0) {
        LOGE("Failed to set trampoline to RW: %s (errno=%d)", strerror(errno), errno);
        munmap(trampoline, page_size);
        return false;
    }
    
    // 写入完成后设置为可执行
    if (mprotect((void*)trampoline_page, page_size, PROT_READ | PROT_EXEC) != 0) {
        LOGE("Failed to set trampoline to RX: %s (errno=%d)", strerror(errno), errno);
        munmap(trampoline, page_size);
        return false;
    }
    
    LOGI("Trampoline set to executable at 0x%" PRIxPTR, trampoline_page);
    
    // 检查权限
    if (!is_memory_executable(trampoline)) {
        LOGE("CRITICAL: Trampoline is NOT executable after mprotect!");
        // 尝试再次设置
        if (mprotect((void*)trampoline_page, page_size, PROT_READ | PROT_EXEC) == 0) {
            LOGI("Fixed trampoline permissions on second attempt");
        } else {
            LOGE("Failed to fix trampoline permissions: %s", strerror(errno));
            munmap(trampoline, page_size);
            return false;
        }
    } else {
        LOGI("Trampoline is executable ✓");
    }
    
    // 清除指令缓存
    __builtin___clear_cache((char*)trampoline, (char*)trampoline + page_size);
    
    // ARM 内存屏障
    asm volatile("dsb sy\nisb sy\n" : : : "memory");
    
    debug_memory_permissions(trampoline, "trampoline (after setup)");
    
    // ============ 修改目标函数 ============
    
    // 计算跳转到 hook 函数的偏移
    int64_t offset_to_hook = (int64_t)hook_func - (int64_t)target_addr;
    
    LOGI("Offset from target to hook: %" PRId64, offset_to_hook);
    
    if (offset_to_hook >= -0x8000000 && offset_to_hook <= 0x7FFFFFF) {
        // 相对跳转
        target_code[0] = 0x14000000 | ((offset_to_hook >> 2) & 0x3FFFFFF);
        LOGI("Patching target with relative jump: 0x%08X", target_code[0]);
        for (int i = 1; i < 4; i++) {
            target_code[i] = 0xD503201F; // NOP
        }
    } else {
        // 绝对跳转
        target_code[0] = 0x58000050; // LDR x16, [PC, #8]
        target_code[1] = 0xD61F0200; // BR x16
        *(uint64_t*)(&target_code[2]) = (uint64_t)hook_func;
        target_code[3] = 0xD503201F; // NOP
        LOGI("Patching target with absolute jump via x16");
    }
    
    // 清除目标函数缓存
    __builtin___clear_cache((char*)target_addr, (char*)target_addr + 16);
    asm volatile("dsb sy\nisb sy\n" : : : "memory");
    
    LOGI("Target function patched");
    
    // ============ 保存原始函数指针 ============
    
    // original_func 应该指向 trampoline
    *original_func = (FuncPtr)trampoline;
    
    LOGI("✓ Hook installed successfully:");
    LOGI("  Target: %p -> Hook: %p -> Trampoline: %p", 
         target_addr, hook_func, trampoline);
    LOGI("  Original function pointer saved: %p", (void*)*original_func);
    
    return true;
}

// Hook encrypt function
void hook_network_methods(void *il2cpp_handle, const char *game_data_dir) {
    LOGI("Installing encrypt function hook...");
    
    if (!il2cpp_handle) {
        LOGE("Invalid il2cpp handle");
        return;
    }
    
    // Use the global il2cpp_base variable
    if (il2cpp_base == 0) {
        LOGE("il2cpp_base is 0, trying to get base address...");
        // Fallback: try to get base from any symbol
        Dl_info dlInfo;
        void *sym = dlsym(il2cpp_handle, "il2cpp_init");
        if (sym && dladdr(sym, &dlInfo)) {
            il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
            LOGI("Found libil2cpp.so base via symbol: 0x%" PRIx64, il2cpp_base);
        } else {
            LOGE("Failed to get libil2cpp.so base address");
            return;
        }
    }
    
    LOGI("Using il2cpp_base: 0x%" PRIx64, il2cpp_base);
    
    // Calculate encrypt function address: base + offset
    uint64_t encrypt_addr = il2cpp_base + ENCRYPT_FUNCTION_OFFSET;
    void *encrypt_func_ptr = (void*)encrypt_addr;
    
    LOGI("Target module base: 0x%" PRIx64, il2cpp_base);
    LOGI("Encrypt function offset: 0x%X", ENCRYPT_FUNCTION_OFFSET);
    LOGI("Encrypt function address: 0x%" PRIx64 " (%p)", encrypt_addr, encrypt_func_ptr);
    
    // Verify the address
    Dl_info verifyInfo;
    if (dladdr(encrypt_func_ptr, &verifyInfo)) {
        LOGI("Address verified, belongs to: %s", 
             verifyInfo.dli_fname ? verifyInfo.dli_fname : "unknown");
        
        // 检查地址是否在正确的模块中
        if (strstr(verifyInfo.dli_fname, "libil2cpp.so") == NULL) {
            LOGW("Warning: Function not in libil2cpp.so! Path: %s", verifyInfo.dli_fname);
        }
    } else {
        LOGW("Warning: Could not verify address with dladdr");
    }
    
    // 检查目标函数权限
    debug_memory_permissions(encrypt_func_ptr, "encrypt function");
    
    if (!is_memory_executable(encrypt_func_ptr)) {
        LOGE("Target function is not executable! Hook will fail.");
        return;
    }
    
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

