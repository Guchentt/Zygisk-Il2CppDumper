//
// Network Hook implementation for logging network communication
//

#include "network_hook.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include <dlfcn.h>
#include <cstring>
#include <cinttypes>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

// Il2Cpp base address
extern uint64_t il2cpp_base;

// Function hook structure
struct HookInfo {
    void *original_func;
    void *hook_func;
    uint8_t original_bytes[16];
    size_t patch_size;
};

// Hook XNetwork.Send(String handler, Byte[] content)
// VA: 0x770936decbf8
static void (*XNetwork_Send_String_ByteArray_Original)(void *handler_str, void *content_bytes) = nullptr;

// Hook XNetwork.Call(String handler, Byte[] content, ...)
// VA: 0x770936decd20
static void (*XNetwork_Call_String_ByteArray_Original)(void *handler_str, void *content_bytes, void *reply, void *exceptionReply, bool excludeMask) = nullptr;

// Hook XNetwork.ProcessMessage(Object msg, Int32 seqNo)
// VA: 0x770936dec648
static void (*XNetwork_ProcessMessage_Original)(void *msg, int32_t seqNo) = nullptr;

// Hook XHttp.PostAsync(String url, String content)
// VA: 0x7709379335d8
static void (*XHttp_PostAsync_Original)(void *url_str, void *content_str) = nullptr;

// Helper function to get string from Il2CppString
static std::string get_il2cpp_string(void *str_obj) {
    if (!str_obj) return "";
    
    // Il2CppString layout: length (offset 0x10), chars (offset 0x14)
    // Read directly from memory (no exception handling since exceptions are disabled)
    int32_t length = *(int32_t*)((uint8_t*)str_obj + 0x10);
    if (length > 0 && length < 10000) {
        char16_t *chars = (char16_t*)((uint8_t*)str_obj + 0x14);
        std::string result;
        result.reserve(length);
        for (int i = 0; i < length; i++) {
            if (chars[i] < 128) {
                result += (char)chars[i];
            }
        }
        return result;
    }
    return "[Unable to read string]";
}

// Helper function to get byte array info
static std::string get_byte_array_info(void *array_obj) {
    if (!array_obj) return "null";
    
    // Il2CppArray layout: length (offset 0x18), data (offset 0x20)
    // Read directly from memory (no exception handling since exceptions are disabled)
    int32_t length = *(int32_t*)((uint8_t*)array_obj + 0x18);
    if (length > 0 && length < 1000000) {
        char buffer[64];
        snprintf(buffer, sizeof(buffer), "ByteArray[%d bytes]", length);
        return buffer;
    }
    return "[Unable to read array]";
}

// Hook wrapper for XNetwork.Send
static void XNetwork_Send_String_ByteArray_Hook_Wrapper(void *handler_str, void *content_bytes) {
    std::string handler = get_il2cpp_string(handler_str);
    std::string content_info = get_byte_array_info(content_bytes);
    
    LOGI("=== NETWORK SEND ===");
    LOGI("Handler: %s", handler.c_str());
    LOGI("Content: %s", content_info.c_str());
    LOGI("===================");
    
    // Call original function
    if (XNetwork_Send_String_ByteArray_Original) {
        XNetwork_Send_String_ByteArray_Original(handler_str, content_bytes);
    }
}

// Hook wrapper for XNetwork.Call
static void XNetwork_Call_String_ByteArray_Hook_Wrapper(void *handler_str, void *content_bytes, void *reply, void *exceptionReply, bool excludeMask) {
    std::string handler = get_il2cpp_string(handler_str);
    std::string content_info = get_byte_array_info(content_bytes);
    
    LOGI("=== NETWORK CALL ===");
    LOGI("Handler: %s", handler.c_str());
    LOGI("Content: %s", content_info.c_str());
    LOGI("ExcludeMask: %s", excludeMask ? "true" : "false");
    LOGI("===================");
    
    // Call original function
    if (XNetwork_Call_String_ByteArray_Original) {
        XNetwork_Call_String_ByteArray_Original(handler_str, content_bytes, reply, exceptionReply, excludeMask);
    }
}

// Hook wrapper for XNetwork.ProcessMessage
static void XNetwork_ProcessMessage_Hook_Wrapper(void *msg, int32_t seqNo) {
    LOGI("=== NETWORK RECEIVE ===");
    LOGI("Message SeqNo: %d", seqNo);
    LOGI("Message Object: %p", msg);
    LOGI("======================");
    
    // Call original function
    if (XNetwork_ProcessMessage_Original) {
        XNetwork_ProcessMessage_Original(msg, seqNo);
    }
}

// Hook wrapper for XHttp.PostAsync
static void XHttp_PostAsync_Hook_Wrapper(void *url_str, void *content_str) {
    std::string url = get_il2cpp_string(url_str);
    std::string content = get_il2cpp_string(content_str);
    
    LOGI("=== HTTP POST ===");
    LOGI("URL: %s", url.c_str());
    LOGI("Content: %s", content.c_str());
    LOGI("================");
    
    // Call original function
    if (XHttp_PostAsync_Original) {
        XHttp_PostAsync_Original(url_str, content_str);
    }
}

// Install function hook using inline hook
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
    if (offset < -0x8000000 || offset > 0x7FFFFFF) {
        LOGE("Hook offset out of range: %" PRId64, offset);
        return false;
    }
    
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
    
    LOGI("Hook installed at %p -> %p (offset: %" PRId64 ")", target_addr, hook_func, offset);
    return true;
}

// Hook network methods
void hook_network_methods(void *il2cpp_handle) {
    LOGI("Installing network hooks...");
    
    if (!il2cpp_handle) {
        LOGE("Invalid il2cpp handle");
        return;
    }
    
    // Calculate absolute addresses from RVA offsets
    // XNetwork.Send(String, Byte[]) - RVA: 0x4acbbf8, VA: 0x770936decbf8
    uint64_t XNetwork_Send_VA = il2cpp_base + 0x4acbbf8;
    
    // XNetwork.Call(String, Byte[], ...) - RVA: 0x4acbd20, VA: 0x770936decd20
    uint64_t XNetwork_Call_VA = il2cpp_base + 0x4acbd20;
    
    // XNetwork.ProcessMessage(Object, Int32) - RVA: 0x4acb648, VA: 0x770936dec648
    uint64_t XNetwork_ProcessMessage_VA = il2cpp_base + 0x4acb648;
    
    // XHttp.PostAsync(String, String) - RVA: 0x56125d8, VA: 0x7709379335d8
    uint64_t XHttp_PostAsync_VA = il2cpp_base + 0x56125d8;
    
    // Wait a bit for il2cpp to fully initialize
    sleep(2);
    
    // Install hooks
    LOGI("Hooking XNetwork.Send at %p", (void*)XNetwork_Send_VA);
    if (install_hook((void*)XNetwork_Send_VA, (void*)XNetwork_Send_String_ByteArray_Hook_Wrapper, &XNetwork_Send_String_ByteArray_Original)) {
        LOGI("✓ XNetwork.Send hooked successfully");
    } else {
        LOGW("✗ Failed to hook XNetwork.Send");
    }
    
    LOGI("Hooking XNetwork.Call at %p", (void*)XNetwork_Call_VA);
    if (install_hook((void*)XNetwork_Call_VA, (void*)XNetwork_Call_String_ByteArray_Hook_Wrapper, &XNetwork_Call_String_ByteArray_Original)) {
        LOGI("✓ XNetwork.Call hooked successfully");
    } else {
        LOGW("✗ Failed to hook XNetwork.Call");
    }
    
    LOGI("Hooking XNetwork.ProcessMessage at %p", (void*)XNetwork_ProcessMessage_VA);
    if (install_hook((void*)XNetwork_ProcessMessage_VA, (void*)XNetwork_ProcessMessage_Hook_Wrapper, &XNetwork_ProcessMessage_Original)) {
        LOGI("✓ XNetwork.ProcessMessage hooked successfully");
    } else {
        LOGW("✗ Failed to hook XNetwork.ProcessMessage");
    }
    
    LOGI("Hooking XHttp.PostAsync at %p", (void*)XHttp_PostAsync_VA);
    if (install_hook((void*)XHttp_PostAsync_VA, (void*)XHttp_PostAsync_Hook_Wrapper, &XHttp_PostAsync_Original)) {
        LOGI("✓ XHttp.PostAsync hooked successfully");
    } else {
        LOGW("✗ Failed to hook XHttp.PostAsync");
    }
    
    LOGI("Network hooks installation completed");
}




