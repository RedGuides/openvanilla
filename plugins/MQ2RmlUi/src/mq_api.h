// The slice of the MacroQuest 3.1.4.7 (commit 681a436, eqlib emu-rof2) plugin ABI this plugin uses.
// Declarations are copied from src/main/GraphicsEngine.h, MQ2Main.h and MQ2Globals.h of that build.
#pragma once

#include <d3d9.h>
#include <functional>

namespace mq {

struct MQRenderCallbacks
{
	std::function<void()> CreateDeviceObjects = nullptr;
	std::function<void()> InvalidateDeviceObjects = nullptr;
	std::function<void()> GraphicsSceneRender = nullptr;
};

extern "C" __declspec(dllimport) int AddRenderCallbacks(const MQRenderCallbacks& callbacks);
extern "C" __declspec(dllimport) void RemoveRenderCallbacks(int id);
extern "C" __declspec(dllimport) void WriteChatf(const char* format, ...);
extern "C" __declspec(dllimport) int GetGameState();

extern "C" __declspec(dllimport) IDirect3DDevice9* gpD3D9Device;
extern "C" __declspec(dllimport) bool gbDeviceAcquired;
extern "C" __declspec(dllimport) char gPathMQRoot[MAX_PATH];

} // namespace mq

#define PLUGIN_API extern "C" __declspec(dllexport)

// Must match __ExpectedVersionDate " " __ExpectedVersionTime of the loaded MQ2Main (RoF2 client).
#define MQ_EXPECTED_EQ_VERSION "May 10 2013 23:30:08"
