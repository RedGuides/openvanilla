// Mirrors the layout-relevant parts of MacroQuest's contrib/imgui/imconfig.h (MQ 3.1.4.7, emu RoF2 / DX9)
// so this header binds against the shipped imgui.dll without pulling in eqlib.
#pragma once

#define DEPRECATE(msg) [[deprecated(msg)]]

#define IMGUI_API __declspec(dllimport)
#define IMGUI_IMPL_API

#define IM_VEC4_CLASS_EXTRA \
    static ImVec4 FromImU32(ImU32 u32); \
    ImU32 ToImU32() const;

#define IMGUI_DEFINE_MATH_OPERATORS

#define ImTextureID void*
