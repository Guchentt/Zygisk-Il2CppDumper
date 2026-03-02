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
#include <fstream>
#include <sstream>
#include <sys/mman.h>
#include <unistd.h>

#if !ENABLE_NETWORK_HOOK
// Hook disabled, provide empty implementation
void hook_network_methods(void *il2cpp_handle, const char *game_data_dir) {
    LOGI("Network hooks are disabled");
}
#else

// Simple JSON parser to extract method VA from script.json
// param_count: -1 means any, otherwise match specific parameter count
static uint64_t find_method_va_from_json(const std::string& json_content, 
                                         const std::string& class_name, 
                                         const std::string& method_name,
                                         int param_count = -1) {
    // Look for pattern: "name": "ClassName" followed by methods array
    // Then find "name": "MethodName" with matching paramCount and extract "va": "0x..."
    
    size_t class_pos = json_content.find("\"name\": \"" + class_name + "\"");
    if (class_pos == std::string::npos) {
        LOGW("Class %s not found in script.json", class_name.c_str());
        return 0;
    }
    
    // Find methods array after class name
    size_t methods_pos = json_content.find("\"methods\": [", class_pos);
    if (methods_pos == std::string::npos) {
        LOGW("Methods array not found for class %s", class_name.c_str());
        return 0;
    }
    
    // Find the end of methods array (to limit search scope)
    size_t methods_end = json_content.find("],", methods_pos);
    if (methods_end == std::string::npos) {
        methods_end = json_content.find("\n          ]", methods_pos);
    }
    if (methods_end == std::string::npos) {
        methods_end = json_content.length();
    }
    
    // Search for method name within methods array
    size_t search_pos = methods_pos;
    while (true) {
        size_t method_name_pos = json_content.find("\"name\": \"" + method_name + "\"", search_pos);
        if (method_name_pos == std::string::npos || method_name_pos > methods_end) {
            LOGW("Method %s::%s not found in script.json", class_name.c_str(), method_name.c_str());
            return 0;
        }
        
        // Check paramCount if specified
        if (param_count >= 0) {
            size_t param_count_pos = json_content.find("\"paramCount\":", method_name_pos);
            if (param_count_pos != std::string::npos && param_count_pos < methods_end) {
                size_t param_value_start = json_content.find_first_of("0123456789", param_count_pos + 13);
                if (param_value_start != std::string::npos) {
                    size_t param_value_end = json_content.find_first_not_of("0123456789", param_value_start);
                    std::string param_str = json_content.substr(param_value_start, param_value_end - param_value_start);
                    int found_param_count = std::stoi(param_str);
                    
                    if (found_param_count != param_count) {
                        // Not the right overload, continue searching
                        search_pos = method_name_pos + 1;
                        continue;
                    }
                }
            }
        }
        
        // Find "va" field after method name
        size_t va_pos = json_content.find("\"va\":", method_name_pos);
        if (va_pos == std::string::npos || va_pos > methods_end) {
            search_pos = method_name_pos + 1;
            continue;
        }
        
        // Extract hex value: "va": "0x1234567890abcdef"
        size_t quote_start = json_content.find('"', va_pos + 5);
        if (quote_start == std::string::npos || quote_start > methods_end) {
            search_pos = method_name_pos + 1;
            continue;
        }
        
        size_t quote_end = json_content.find('"', quote_start + 1);
        if (quote_end == std::string::npos || quote_end > methods_end) {
            search_pos = method_name_pos + 1;
            continue;
        }
        
        std::string va_str = json_content.substr(quote_start + 1, quote_end - quote_start - 1);
        
        // Parse hex string
        uint64_t va = 0;
        if (va_str.length() > 2 && va_str.substr(0, 2) == "0x") {
            std::istringstream iss(va_str);
            iss >> std::hex >> va;
        } else if (!va_str.empty() && va_str != "0") {
            std::istringstream iss(va_str);
            iss >> std::hex >> va;
        }
        
        // Validate VA (should be non-zero and reasonable)
        if (va != 0 && va > 0x1000000 && va < 0x7FFFFFFFFFFFFFFF) {
            LOGI("Found %s::%s (paramCount=%d) at VA: 0x%" PRIx64, 
                 class_name.c_str(), method_name.c_str(), param_count, va);
            return va;
        }
        
        // Invalid VA, continue searching
        search_pos = method_name_pos + 1;
    }
    
    return 0;
}

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

// Helper function to get string from Il2CppString (safe version)
static std::string get_il2cpp_string(void *str_obj) {
    if (!str_obj) return "[null]";
    
    // Il2CppString layout: length (offset 0x10), chars (offset 0x14)
    // Read directly from memory with bounds checking
    uint8_t *base = (uint8_t*)str_obj;
    
    // Check if memory is readable (basic check)
    if ((uintptr_t)base < 0x1000 || (uintptr_t)base > 0x7FFFFFFFFFFFFFFF) {
        return "[invalid_ptr]";
    }
    
    int32_t length = 0;
    // Try to read length safely
    __builtin_memcpy(&length, base + 0x10, sizeof(int32_t));
    
    if (length > 0 && length < 1000) {  // Reduced max length for safety
        char16_t *chars = (char16_t*)(base + 0x14);
        std::string result;
        result.reserve(length);
        for (int i = 0; i < length && i < 1000; i++) {
            uint16_t c = chars[i];
            if (c < 128 && c != 0) {
                result += (char)c;
            }
        }
        if (result.empty()) {
            return "[empty_string]";
        }
        return result;
    }
    return "[invalid_length]";
}

// Helper function to get byte array info (safe version)
static std::string get_byte_array_info(void *array_obj) {
    if (!array_obj) return "[null]";
    
    // Il2CppArray layout: length (offset 0x18), data (offset 0x20)
    // Read directly from memory with bounds checking
    uint8_t *base = (uint8_t*)array_obj;
    
    // Check if memory is readable
    if ((uintptr_t)base < 0x1000 || (uintptr_t)base > 0x7FFFFFFFFFFFFFFF) {
        return "[invalid_ptr]";
    }
    
    int32_t length = 0;
    __builtin_memcpy(&length, base + 0x18, sizeof(int32_t));
    
    if (length >= 0 && length < 1000000) {
        char buffer[64];
        snprintf(buffer, sizeof(buffer), "ByteArray[%d]", length);
        return buffer;
    }
    return "[invalid_length]";
}

// Hook wrapper for XNetwork.Send
static void XNetwork_Send_String_ByteArray_Hook_Wrapper(void *handler_str, void *content_bytes) {
    // Call original function FIRST to avoid blocking
    if (XNetwork_Send_String_ByteArray_Original) {
        XNetwork_Send_String_ByteArray_Original(handler_str, content_bytes);
    }
    
    // Then log (non-blocking)
    std::string handler = get_il2cpp_string(handler_str);
    std::string content_info = get_byte_array_info(content_bytes);
    
    LOGI("=== NETWORK SEND ===");
    LOGI("Handler: %s", handler.c_str());
    LOGI("Content: %s", content_info.c_str());
    LOGI("===================");
}

// Hook wrapper for XNetwork.Call
static void XNetwork_Call_String_ByteArray_Hook_Wrapper(void *handler_str, void *content_bytes, void *reply, void *exceptionReply, bool excludeMask) {
    // Call original function FIRST to avoid blocking
    if (XNetwork_Call_String_ByteArray_Original) {
        XNetwork_Call_String_ByteArray_Original(handler_str, content_bytes, reply, exceptionReply, excludeMask);
    }
    
    // Then log (non-blocking)
    std::string handler = get_il2cpp_string(handler_str);
    std::string content_info = get_byte_array_info(content_bytes);
    
    LOGI("=== NETWORK CALL ===");
    LOGI("Handler: %s", handler.c_str());
    LOGI("Content: %s", content_info.c_str());
    LOGI("ExcludeMask: %s", excludeMask ? "true" : "false");
    LOGI("===================");
}

// Hook wrapper for XNetwork.ProcessMessage
static void XNetwork_ProcessMessage_Hook_Wrapper(void *msg, int32_t seqNo) {
    // Call original function FIRST to avoid blocking
    if (XNetwork_ProcessMessage_Original) {
        XNetwork_ProcessMessage_Original(msg, seqNo);
    }
    
    // Then log (non-blocking)
    LOGI("=== NETWORK RECEIVE ===");
    LOGI("Message SeqNo: %d", seqNo);
    LOGI("Message Object: %p", msg);
    LOGI("======================");
}

// Hook wrapper for XHttp.PostAsync
static void XHttp_PostAsync_Hook_Wrapper(void *url_str, void *content_str) {
    // Call original function FIRST to avoid blocking
    if (XHttp_PostAsync_Original) {
        XHttp_PostAsync_Original(url_str, content_str);
    }
    
    // Then log (non-blocking)
    std::string url = get_il2cpp_string(url_str);
    std::string content = get_il2cpp_string(content_str);
    
    LOGI("=== HTTP POST ===");
    LOGI("URL: %s", url.c_str());
    LOGI("Content: %s", content.c_str());
    LOGI("================");
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

// Hook network methods
void hook_network_methods(void *il2cpp_handle, const char *game_data_dir) {
    LOGI("Installing network hooks from script.json...");
    
    if (!il2cpp_handle) {
        LOGE("Invalid il2cpp handle");
        return;
    }
    
    if (!game_data_dir) {
        LOGE("Invalid game_data_dir");
        return;
    }
    
    // Read script.json file
    std::string script_json_path = std::string(game_data_dir) + "/files/script.json";
    std::ifstream json_file(script_json_path);
    if (!json_file) {
        LOGE("Failed to open script.json: %s", script_json_path.c_str());
        return;
    }
    
    // Read entire file into string
    std::stringstream json_buffer;
    json_buffer << json_file.rdbuf();
    std::string json_content = json_buffer.str();
    json_file.close();
    
    LOGI("Loaded script.json (%zu bytes)", json_content.size());
    
    // Extract method addresses from JSON
    // XNetwork.Send(String, Byte[]) - paramCount=2
    uint64_t XNetwork_Send_VA = find_method_va_from_json(json_content, "XNetwork", "Send", 2);
    
    // XNetwork.Call(String, Byte[], Action, Action, bool) - paramCount=5
    uint64_t XNetwork_Call_VA = find_method_va_from_json(json_content, "XNetwork", "Call", 5);
    
    // XNetwork.ProcessMessage(Object, Int32) - paramCount=2
    uint64_t XNetwork_ProcessMessage_VA = find_method_va_from_json(json_content, "XNetwork", "ProcessMessage", 2);
    
    // XHttp.PostAsync(String, String) - paramCount=2
    uint64_t XHttp_PostAsync_VA = find_method_va_from_json(json_content, "XHttp", "PostAsync", 2);
    
    // Wait a bit for il2cpp to fully initialize
    sleep(2);
    
    // Install hooks
    if (XNetwork_Send_VA != 0) {
        LOGI("Hooking XNetwork.Send at %p", (void*)XNetwork_Send_VA);
        if (install_hook((void*)XNetwork_Send_VA, (void*)XNetwork_Send_String_ByteArray_Hook_Wrapper, &XNetwork_Send_String_ByteArray_Original)) {
            LOGI("✓ XNetwork.Send hooked successfully");
        } else {
            LOGW("✗ Failed to hook XNetwork.Send");
        }
    } else {
        LOGW("✗ XNetwork.Send address not found in script.json");
    }
    
    if (XNetwork_Call_VA != 0) {
        LOGI("Hooking XNetwork.Call at %p", (void*)XNetwork_Call_VA);
        if (install_hook((void*)XNetwork_Call_VA, (void*)XNetwork_Call_String_ByteArray_Hook_Wrapper, &XNetwork_Call_String_ByteArray_Original)) {
            LOGI("✓ XNetwork.Call hooked successfully");
        } else {
            LOGW("✗ Failed to hook XNetwork.Call");
        }
    } else {
        LOGW("✗ XNetwork.Call address not found in script.json");
    }
    
    if (XNetwork_ProcessMessage_VA != 0) {
        LOGI("Hooking XNetwork.ProcessMessage at %p", (void*)XNetwork_ProcessMessage_VA);
        if (install_hook((void*)XNetwork_ProcessMessage_VA, (void*)XNetwork_ProcessMessage_Hook_Wrapper, &XNetwork_ProcessMessage_Original)) {
            LOGI("✓ XNetwork.ProcessMessage hooked successfully");
        } else {
            LOGW("✗ Failed to hook XNetwork.ProcessMessage");
        }
    } else {
        LOGW("✗ XNetwork.ProcessMessage address not found in script.json");
    }
    
    if (XHttp_PostAsync_VA != 0) {
        LOGI("Hooking XHttp.PostAsync at %p", (void*)XHttp_PostAsync_VA);
        if (install_hook((void*)XHttp_PostAsync_VA, (void*)XHttp_PostAsync_Hook_Wrapper, &XHttp_PostAsync_Original)) {
            LOGI("✓ XHttp.PostAsync hooked successfully");
        } else {
            LOGW("✗ Failed to hook XHttp.PostAsync");
        }
    } else {
        LOGW("✗ XHttp.PostAsync address not found in script.json");
    }
    
    LOGI("Network hooks installation completed");
}

#endif // ENABLE_NETWORK_HOOK

