#include "exports.h"
#include <apu/embedded_player.h>
#include <kernel/function.h>
#include <kernel/heap.h>
#include <app.h>

// TODO: Implement GTA V-specific sound system
void Game_PlaySound(const char* pName)
{
     if (EmbeddedPlayer::s_isActive)
     {
         EmbeddedPlayer::Play(pName);
     }
     // else: GTA V sound system not yet implemented
}

void Game_PlaySound(const char* pBankName, const char* pName)
{
    // TODO: Implement GTA V sound playback
    // GTA V uses RAGE audio system, different from Sonic '06
    (void)pBankName;
    (void)pName;
}
