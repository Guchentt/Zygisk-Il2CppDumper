//
// Network Hook for logging network communication
//

#ifndef ZYGISK_IL2CPPDUMPER_NETWORK_HOOK_H
#define ZYGISK_IL2CPPDUMPER_NETWORK_HOOK_H

#include <cstdint>
#include <cstddef>

// Hook network methods to log network communication
void hook_network_methods(void *il2cpp_handle);

#endif //ZYGISK_IL2CPPDUMPER_NETWORK_HOOK_H

