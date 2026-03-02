//
// Network Hook for logging network communication
//

#ifndef ZYGISK_IL2CPPDUMPER_NETWORK_HOOK_H
#define ZYGISK_IL2CPPDUMPER_NETWORK_HOOK_H

#include <cstdint>
#include <cstddef>

// Enable/disable network hooking
// Set to 0 to disable network hooks (game will run normally)
#define ENABLE_NETWORK_HOOK 0

// Hook network methods to log network communication
// Reads method addresses from script.json and installs hooks
void hook_network_methods(void *il2cpp_handle, const char *game_data_dir);

#endif //ZYGISK_IL2CPPDUMPER_NETWORK_HOOK_H

