//
// Network Hook for logging network communication
//

#ifndef ZYGISK_IL2CPPDUMPER_NETWORK_HOOK_H
#define ZYGISK_IL2CPPDUMPER_NETWORK_HOOK_H

#include <cstdint>
#include <cstddef>

// Enable/disable network hooking
// Set to 0 to disable network hooks (game will run normally)
#define ENABLE_NETWORK_HOOK 1

// Hook network methods to log network communication
void hook_network_methods(void *il2cpp_handle);

#endif //ZYGISK_IL2CPPDUMPER_NETWORK_HOOK_H


