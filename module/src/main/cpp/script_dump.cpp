//
// Created by Perfare on 2020/7/4.
//

#include "script_dump.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"
#include <cinttypes>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

// Use the global il2cpp API function pointers defined in il2cpp_dump.cpp
#define DO_API(r, n, p) extern r (*n) p
#include "il2cpp-api-functions.h"
#undef DO_API

// Il2Cpp base address defined in il2cpp_dump.cpp
extern uint64_t il2cpp_base;

// Generate script.json for IDA Pro analysis
void dump_script_json(const char *game_data_dir) {
    LOGI("Generating script.json...");
    
    std::stringstream jsonOutput;
    
    // Get all assemblies
    size_t size;
    auto domain = il2cpp_domain_get();
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);
    
    if (!assemblies || size == 0) {
        LOGE("No assemblies found");
        return;
    }
    
    jsonOutput << "{\n";
    jsonOutput << "  \"assemblies\": [\n";
    
    for (size_t i = 0; i < size; ++i) {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        const char *image_name = il2cpp_image_get_name(image);
        auto classCount = il2cpp_image_get_class_count(image);
        
        jsonOutput << "    {\n";
        jsonOutput << "      \"name\": \"" << image_name << "\",\n";
        jsonOutput << "      \"classes\": [\n";
        
        for (int32_t j = 0; j < classCount; ++j) {
            auto klass = il2cpp_image_get_class(image, j);
            const char *class_name = il2cpp_class_get_name(const_cast<Il2CppClass *>(klass));
            const char *namespace_name = il2cpp_class_get_namespace(const_cast<Il2CppClass *>(klass));
            
            jsonOutput << "        {\n";
            jsonOutput << "          \"name\": \"" << class_name << "\",\n";
            jsonOutput << "          \"namespace\": \"" << namespace_name << "\",\n";
            
            // Dump methods
            jsonOutput << "          \"methods\": [\n";
            void *iter = nullptr;
            bool first_method = true;
            while (auto method = il2cpp_class_get_methods(const_cast<Il2CppClass *>(klass), &iter)) {
                if (!first_method) {
                    jsonOutput << ",\n";
                }
                first_method = false;
                
                const char *method_name = il2cpp_method_get_name(method);
                void *method_ptr = reinterpret_cast<void *>(const_cast<Il2CppMethodPointer>(method->methodPointer));
                uint32_t iflags = 0;
                auto flags = il2cpp_method_get_flags(method, &iflags);
                auto param_count = il2cpp_method_get_param_count(method);
                auto return_type = il2cpp_method_get_return_type(method);
                auto return_class = il2cpp_class_from_type(return_type);
                const char *return_type_name = il2cpp_class_get_name(return_class);
                
                jsonOutput << "            {\n";
                jsonOutput << "              \"name\": \"" << method_name << "\",\n";
                jsonOutput << "              \"offset\": \"0x" << std::hex << (uint64_t)method_ptr - il2cpp_base << "\",\n";
                jsonOutput << "              \"va\": \"0x" << std::hex << (uint64_t)method_ptr << "\",\n";
                jsonOutput << "              \"flags\": " << std::dec << flags << ",\n";
                jsonOutput << "              \"paramCount\": " << param_count << ",\n";
                jsonOutput << "              \"returnType\": \"" << return_type_name << "\"\n";
                jsonOutput << "            }";
            }
            jsonOutput << "\n          ],\n";
            
            // Dump fields
            jsonOutput << "          \"fields\": [\n";
            iter = nullptr;
            bool first_field = true;
            while (auto field = il2cpp_class_get_fields(const_cast<Il2CppClass *>(klass), &iter)) {
                if (!first_field) {
                    jsonOutput << ",\n";
                }
                first_field = false;
                
                const char *field_name = il2cpp_field_get_name(field);
                size_t offset = il2cpp_field_get_offset(field);
                auto field_type = il2cpp_field_get_type(field);
                auto field_class = il2cpp_class_from_type(field_type);
                const char *field_type_name = il2cpp_class_get_name(field_class);
                auto attrs = il2cpp_field_get_flags(field);
                
                jsonOutput << "            {\n";
                jsonOutput << "              \"name\": \"" << field_name << "\",\n";
                jsonOutput << "              \"offset\": \"0x" << std::hex << offset << "\",\n";
                jsonOutput << "              \"type\": \"" << field_type_name << "\",\n";
                jsonOutput << "              \"flags\": " << std::dec << attrs << "\n";
                jsonOutput << "            }";
            }
            jsonOutput << "\n          ]\n";
            
            jsonOutput << "        }";
            if (j < classCount - 1) {
                jsonOutput << ",";
            }
            jsonOutput << "\n";
        }
        
        jsonOutput << "      ]\n";
        jsonOutput << "    }";
        if (i < size - 1) {
            jsonOutput << ",";
        }
        jsonOutput << "\n";
    }
    
    jsonOutput << "  ],\n";
    
    // Add metadata info
    jsonOutput << "  \"metadata\": {\n";
    jsonOutput << "    \"il2cppBase\": \"0x" << std::hex << il2cpp_base << "\",\n";
    jsonOutput << "    \"assemblyCount\": " << std::dec << size << "\n";
    jsonOutput << "  }\n";
    
    jsonOutput << "}\n";
    
    // Write to file
    std::string outPath = std::string(game_data_dir) + "/files/script.json";
    std::ofstream outFile(outPath);
    if (!outFile) {
        LOGE("Failed to create script.json: %s", outPath.c_str());
        return;
    }
    
    outFile << jsonOutput.str();
    outFile.close();
    
    LOGI("Successfully generated script.json: %s", outPath.c_str());
}

