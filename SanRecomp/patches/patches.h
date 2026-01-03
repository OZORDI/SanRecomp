#pragma once

// GTA V-specific patches
#include "gta5_patches.h"
#include "player_limit_patches.h"

// Note: The following Sonic '06 specific patches are disabled for GTA V:
// - aspect_ratio_patches.h (has Sonicteam namespace references)
// - camera_patches.h (has Sonicteam namespace references)
// - Other game-specific patches

inline void InitPatches()
{
    // Initialize GTA V-specific patches
    GTA5Patches::Init();
    
    // Initialize player limit patches (extended multiplayer support)
    PlayerLimitPatches::Init();
}
