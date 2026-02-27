//
// Created by Perfare on 2020/7/4.
//

#include "metadata_dump.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <fstream>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>

// Il2Cpp global metadata file header structure
#pragma pack(push, 1)
typedef struct Il2CppGlobalMetadataHeader {
    int32_t sanity;
    int32_t version;
    int32_t stringLiteralOffset;
    int32_t stringLiteralCount;
    int32_t stringOffset;
    int32_t stringCount;
    int32_t eventsOffset;
    int32_t eventsCount;
    int32_t propertiesOffset;
    int32_t propertiesCount;
    int32_t methodsOffset;
    int32_t methodsCount;
    int32_t parameterDefaultValuesOffset;
    int32_t parameterDefaultValuesCount;
    int32_t fieldDefaultValuesOffset;
    int32_t fieldDefaultValuesCount;
    int32_t fieldAndParameterDefaultValueDataOffset;
    int32_t fieldAndParameterDefaultValueDataCount;
    int32_t fieldMarshaledSizesOffset;
    int32_t fieldMarshaledSizesCount;
    int32_t parametersOffset;
    int32_t parametersCount;
    int32_t fieldsOffset;
    int32_t fieldsCount;
    int32_t genericParametersOffset;
    int32_t genericParametersCount;
    int32_t genericParameterConstraintsOffset;
    int32_t genericParameterConstraintsCount;
    int32_t genericContainersOffset;
    int32_t genericContainersCount;
    int32_t nestedTypesOffset;
    int32_t nestedTypesCount;
    int32_t interfacesOffset;
    int32_t interfacesCount;
    int32_t vtableMethodsOffset;
    int32_t vtableMethodsCount;
    int32_t interfaceOffsetsOffset;
    int32_t interfaceOffsetsCount;
    int32_t typeDefinitionsOffset;
    int32_t typeDefinitionsCount;
    int32_t imagesOffset;
    int32_t imagesCount;
    int32_t assembliesOffset;
    int32_t assembliesCount;
    int32_t assemblyRefsOffset;
    int32_t assemblyRefsCount;
    int32_t referencedAssembliesOffset;
    int32_t referencedAssembliesCount;
    int32_t attributeInfoOffset;
    int32_t attributeInfoCount;
    int32_t attributeTypeRangesOffset;
    int32_t attributeTypeRangesCount;
    int32_t unusedAttributeInfoOffset;
    int32_t unusedAttributeInfoCount;
    int32_t exportedTypeDefinitionsOffset;
    int32_t exportedTypeDefinitionsCount;
} Il2CppGlobalMetadataHeader;
#pragma pack(pop)

// Find global metadata in memory by searching for signature
static void* find_metadata_in_memory(size_t *metadata_size) {
    void *handle = xdl_open("libil2cpp.so", 0);
    if (!handle) {
        LOGE("Failed to open libil2cpp.so");
        return nullptr;
    }

    // Get libil2cpp.so base address
    Dl_info dl_info;
    if (dladdr(handle, &dl_info) == 0) {
        LOGE("Failed to get libil2cpp.so info");
        xdl_close(handle);
        return nullptr;
    }

    uint8_t *base = (uint8_t*)dl_info.dli_fbase;
    
    // Try to find global metadata section in memory
    // Method 1: Search for metadata magic numbers
    // Common metadata versions and their sanity values
    const uint32_t metadata_signatures[] = {
        0xAF1BFAFA,  // Version 16
        0xFAB1AF1B,  // Version 19
        0xAF1BF1B1,  // Version 20+
    };

    // Search in a reasonable range around the library
    size_t search_size = 50 * 1024 * 1024; // 50MB max search
    uint8_t *search_end = base + search_size;

    for (uint8_t *ptr = base; ptr < search_end; ptr += 4) {
        // Check if memory is accessible
        if (ptr >= (uint8_t*)0x40000000) break; // Don't search beyond kernel space
        
        for (int sig_idx = 0; sig_idx < 3; sig_idx++) {
            if (*(uint32_t*)ptr == metadata_signatures[sig_idx]) {
                // Found potential metadata header
                Il2CppGlobalMetadataHeader *header = (Il2CppGlobalMetadataHeader*)ptr;
                
                // Validate header
                if (header->version >= 16 && header->version <= 30 &&
                    header->assembliesCount > 0 && header->imagesCount > 0) {
                    LOGI("Found metadata header at: %p (version: %d)", ptr, header->version);
                    
                    // Estimate metadata size based on offsets and counts
                    // Find the highest offset + count
                    int32_t max_offset = 0;
                    int32_t max_count = 0;
                    
                    if (header->stringLiteralOffset > max_offset) {
                        max_offset = header->stringLiteralOffset;
                        max_count = header->stringLiteralCount;
                    }
                    if (header->stringOffset > max_offset) {
                        max_offset = header->stringOffset;
                        max_count = header->stringCount;
                    }
                    if (header->methodsOffset > max_offset) {
                        max_offset = header->methodsOffset;
                        max_count = header->methodsCount;
                    }
                    if (header->fieldsOffset > max_offset) {
                        max_offset = header->fieldsOffset;
                        max_count = header->fieldsCount;
                    }
                    if (header->typeDefinitionsOffset > max_offset) {
                        max_offset = header->typeDefinitionsOffset;
                        max_count = header->typeDefinitionsCount;
                    }
                    
                    // Estimate size (this is approximate)
                    *metadata_size = max_offset + max_count * 4 + 4096; // Add some padding
                    LOGI("Estimated metadata size: %zu", *metadata_size);
                    
                    xdl_close(handle);
                    return ptr;
                }
            }
        }
    }

    // Method 2: Try to find via il2cpp symbols
    // Some Il2Cpp versions have global symbols for metadata
    void *metadata_ptr = xdl_sym(handle, "g_MetadataFile", nullptr);
    if (metadata_ptr) {
        LOGI("Found metadata via g_MetadataFile symbol: %p", metadata_ptr);
        xdl_close(handle);
        *metadata_size = 10 * 1024 * 1024; // 10MB default
        return metadata_ptr;
    }

    // Method 3: Search for metadata in /proc/self/maps
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[256];
        while (fgets(line, sizeof(line), maps)) {
            // Look for rw-p sections that might contain metadata
            if (strstr(line, "rw-p") && strstr(line, "/dev/ashmem/") == nullptr) {
                unsigned long start, end;
                if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                    uint8_t *ptr = (uint8_t*)start;
                    if (end - start > 0x1000 && end - start < 0x10000000) {
                        for (int sig_idx = 0; sig_idx < 3; sig_idx++) {
                            if (*(uint32_t*)ptr == metadata_signatures[sig_idx]) {
                                Il2CppGlobalMetadataHeader *header = (Il2CppGlobalMetadataHeader*)ptr;
                                if (header->version >= 16 && header->version <= 30) {
                                    LOGI("Found metadata in maps at: %p", ptr);
                                    *metadata_size = end - start;
                                    fclose(maps);
                                    xdl_close(handle);
                                    return ptr;
                                }
                            }
                        }
                    }
                }
            }
        }
        fclose(maps);
    }

    LOGW("Could not find metadata in memory");
    xdl_close(handle);
    return nullptr;
}

// Dump metadata from memory to file
void dump_global_metadata(const char *game_data_dir) {
    LOGI("Attempting to dump global-metadata.dat from memory...");
    
    size_t metadata_size = 0;
    void *metadata_ptr = find_metadata_in_memory(&metadata_size);
    
    if (!metadata_ptr) {
        LOGE("Failed to find metadata in memory");
        return;
    }
    
    // Verify metadata header
    Il2CppGlobalMetadataHeader *header = (Il2CppGlobalMetadataHeader*)metadata_ptr;
    LOGI("Metadata version: %d, sanity: 0x%x", header->version, header->sanity);
    LOGI("Assemblies: %d, Images: %d, TypeDefinitions: %d",
         header->assembliesCount, header->imagesCount, header->typeDefinitionsCount);
    
    // Create output file path
    std::string outPath = std::string(game_data_dir) + "/files/global-metadata.dat";
    
    // Write metadata to file
    std::ofstream outFile(outPath, std::ios::binary);
    if (!outFile) {
        LOGE("Failed to create output file: %s", outPath.c_str());
        return;
    }
    
    outFile.write((char*)metadata_ptr, metadata_size);
    outFile.close();
    
    LOGI("Successfully dumped global-metadata.dat to: %s", outPath.c_str());
    LOGI("Metadata size: %zu bytes", metadata_size);
}
