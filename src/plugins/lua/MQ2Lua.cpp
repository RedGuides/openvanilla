/*
 * MacroQuest: The extension platform for EverQuest
 * Copyright (C) 2002-present MacroQuest Authors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "pch.h"

#include "LuaInterface.h"
#include "LuaCommon.h"
#include "LuaThread.h"
#include "LuaEvent.h"
#include "LuaActor.h"
#include "LuaImGui.h"
#include "bindings/lua_Bindings.h"
#include "imgui/ImGuiUtils.h"
#include "imgui/ImGuiFileDialog.h"
#include "imgui/ImGuiTextEditor.h"

#include <mq/Plugin.h>
#include <mq/utils/Args.h>
#include <fmt/format.h>

#pragma warning(push)
#pragma warning(disable: 4244)
#include <fmt/chrono.h>
#pragma warning(pop)

#include <yaml-cpp/yaml.h>

#include <string>
#include <fstream>

PreSetup("MQ2Lua");
PLUGIN_VERSION(0.1);

using namespace std::chrono_literals;
namespace fs = std::filesystem;

using MQ2Args = Args<&WriteChatf>;
using MQ2HelpArgument = HelpArgument;

namespace mq::lua {

// provide option strings here
static const std::string KEY_TURBO_NUM = "turboNum";
static const std::string KEY_LUA_DIR = "luaDir";
static const std::string KEY_MODULE_DIR = "moduleDir";
static const std::string KEY_LUA_REQUIRE_PATHS = "luaRequirePaths";
static const std::string KEY_DLL_REQUIRE_PATHS = "dllRequirePaths";
static const std::string KEY_INFO_GC = "infoGC";
static const std::string KEY_SQUELCH_STATUS = "squelchStatus";
static const std::string KEY_SHOW_MENU = "showMenu";

// configurable options, defaults provided where needed
static uint32_t s_turboNum = 500;
static std::string s_luaDirName = "lua";
static std::string s_moduleDirName = "modules";
static LuaEnvironmentSettings s_environment;
static std::chrono::milliseconds s_infoGC = 3600s; // 1 hour
static bool s_squelchStatus = false;
static bool s_verboseErrors = true;

// this is static and will never change
static std::string s_configPath = (std::filesystem::path(gPathConfig) / "MQ2Lua.yaml").string();
static YAML::Node s_configNode;

// this is for the imgui menu display
static bool s_showMenu = false;
static ImGuiFileDialog* s_scriptLaunchDialog = nullptr;
static ImGuiFileDialog* s_luaDirDialog = nullptr;
static ImGuiFileDialog* s_moduleDirDialog = nullptr;
static imgui::TextEditor* s_luaCodeViewer = nullptr;

// use a vector for s_running because we need to iterate it every pulse, and find only if a command is issued
std::vector<std::shared_ptr<LuaThread>> s_running;
std::vector<std::shared_ptr<LuaThread>> s_pending;

std::unordered_map<uint32_t, LuaThreadInfo> s_infoMap;

#pragma region Shared Function Definitions

void DebugStackTrace(lua_State* L, const char* message)
{
	std::string_view svMessage{ message ? message : "nil" };
	LuaError("%.*s", svMessage.length(), svMessage.data());

	if (s_verboseErrors)
	{
		int top = lua_gettop(L);

		struct StackLine {
			std::string str;
			int a;
			int b;

			StackLine(std::string str_, int i_, int top_)
				: str(std::move(str_))
				, a(i_)
				, b(i_ - (top_ + 1))
			{}
		};
		std::vector<StackLine> lines;

		for (int i = top; i >= 1; i--)
		{
			int t = lua_type(L, i);
			switch (t)
			{
			case LUA_TSTRING: {
				const char* str = lua_tostring(L, i);
				if (string_equals(str, message) && i == top) {
					top -= 3; // skip exception, location, and error.
					i -= 2;
					break;
				}
				lines.emplace_back(fmt::format("`{}'", str), i, top);
				break;
			}

			case LUA_TBOOLEAN:
				lines.emplace_back(lua_toboolean(L, i) ? "true" : "false", i, top);
				break;

			case LUA_TNUMBER:
				lines.emplace_back(fmt::format("{}", lua_tonumber(L, i)), i, top);
				break;

			case LUA_TUSERDATA:
				lines.emplace_back(fmt::format("[{}]", luaL_tolstring(L, i, NULL)), i, top);
				break;

			default:
				lines.emplace_back(fmt::format("{}", lua_typename(L, t)), i, top);
				break;
			}
		}

		if (lines.size() > 0)
		{
			LuaError("---- Begin Stack (size: %i) ----", lines.size());
			for (const StackLine& line : lines)
			{
				LuaError("%i -- (%i) ---- %s", line.a, line.b, line.str.c_str());
			}
			LuaError("---- End Stack ----\n");
		}
	}
}

bool DoStatus()
{
	return !s_squelchStatus;
}

void EndScript(const std::shared_ptr<LuaThread>& thread, const LuaThread::RunResult& result,
	bool announce)
{
	if (!thread->IsString() && announce)
	{
		WriteChatStatus("Ending lua script '%s' with PID %d and status %d",
			thread->GetName().c_str(), thread->GetPID(), static_cast<int>(result.first));
	}

	auto fin_it = s_infoMap.find(thread->GetPID());
	if (fin_it != s_infoMap.end())
	{
		if (result.second)
			fin_it->second.SetResult(*result.second, thread->GetEvaluateResult());
		else
			fin_it->second.EndRun();
	}
}

std::shared_ptr<LuaThread> GetLuaThreadByPID(int pid)
{
	for (const auto& thread : s_running)
	{
		if (thread && thread->GetPID() == pid)
			return thread;
	}

	for (const auto& thread : s_pending)
	{
		if (thread && thread->GetPID() == pid)
			return thread;
	}

	return nullptr;
}

void OnLuaThreadDestroyed(LuaThread* destroyedThread)
{
	s_running.erase(std::remove_if(s_running.begin(), s_running.end(),
		[&](const std::shared_ptr<LuaThread>& thread) -> bool
		{
			if (thread && thread.get() != destroyedThread
				&& thread->IsDependency(destroyedThread))
			{
				// Exit the thread immediately
				thread->Exit(lua::LuaThreadExitReason::DependencyRemoved);

				EndScript(thread, { sol::thread_status::dead, std::nullopt }, false);

				WriteChatStatus("Running lua script '%s' with PID %d terminated due to stopping of '%s'",
					thread->GetName().c_str(), thread->GetPID(), destroyedThread->GetName().c_str());

				return true;
			}
			return false;
		}), end(s_running));
}

void OnLuaTLORemoved(MQTopLevelObject* tlo, int pidOwner)
{
	auto iter = std::find_if(begin(mq::lua::s_running), end(mq::lua::s_running),
		[pidOwner](const auto& thread) { return thread && thread->GetPID() == pidOwner; });

	s_running.erase(std::remove_if(s_running.begin(), s_running.end(),
		[&](const std::shared_ptr<LuaThread>& thread) -> bool
		{
			if (thread && thread->GetPID() != pidOwner
				&& thread->IsDependency(tlo))
			{
				// Exit the thread immediately
				thread->Exit(lua::LuaThreadExitReason::DependencyRemoved);

				EndScript(thread, { sol::thread_status::dead, std::nullopt }, false);

				if (iter != end(mq::lua::s_running))
				{
					WriteChatStatus("Running lua script '%s' with PID %d terminated due to removal of '%s' from '%s'",
						thread->GetName().c_str(), thread->GetPID(), tlo->Name.c_str(), (*iter)->GetName().c_str());
				}
				else
				{
					WriteChatStatus("Running lua script '%s' with PID %d terminated due to removal of '%s'",
						thread->GetName().c_str(), thread->GetPID(), tlo->Name.c_str());
				}
				return true;
			}
			return false;
		}), end(s_running));
}

#pragma endregion

#pragma region TLO

class MQ2LuaInfoType : public MQ2Type
{
public:
	enum class Members
	{
		PID,
		Name,
		Path,
		Arguments,
		StartTime,
		EndTime,
		ReturnCount,
		Return,
		Status
	};

	MQ2LuaInfoType() : MQ2Type("luainfo")
	{
		ScopedTypeMember(Members, PID);
		ScopedTypeMember(Members, Name);
		ScopedTypeMember(Members, Path);
		ScopedTypeMember(Members, Arguments);
		ScopedTypeMember(Members, StartTime);
		ScopedTypeMember(Members, EndTime);
		ScopedTypeMember(Members, ReturnCount);
		ScopedTypeMember(Members, Return);
		ScopedTypeMember(Members, Status);
	};

	virtual bool GetMember(MQVarPtr VarPtr, const char* Member, char* Index, MQTypeVar& Dest) override
	{
		using namespace mq::datatypes;

		auto pMember = MQ2LuaInfoType::FindMember(Member);
		if (pMember == nullptr)
			return false;

		auto info = VarPtr.Get<LuaThreadInfo>();
		if (!info)
			return false;

		switch (static_cast<Members>(pMember->ID))
		{
		case Members::PID:
			Dest.Type = pIntType;
			Dest.Set(info->pid);
			return true;

		case Members::Name:
			Dest.Type = pStringType;
			strcpy_s(DataTypeTemp, MAX_STRING, info->name.c_str());
			Dest.Ptr = &DataTypeTemp[0];
			return true;

		case Members::Path:
			Dest.Type = pStringType;
			strcpy_s(DataTypeTemp, MAX_STRING, info->path.c_str());
			Dest.Ptr = &DataTypeTemp[0];
			return true;

		case Members::Arguments:
			Dest.Type = pStringType;
			strcpy_s(DataTypeTemp, MAX_STRING, join(info->arguments, ",").c_str());
			Dest.Ptr = &DataTypeTemp[0];
			return true;

		case Members::StartTime: {
			Dest.Type = pStringType;
			time_t startTime = std::chrono::system_clock::to_time_t(info->startTime);
			ctime_s(DataTypeTemp, DataTypeTemp.size(), &startTime);
			Dest.Ptr = &DataTypeTemp[0];
			return true;
		}

		case Members::EndTime:
			if (info->endTime != std::chrono::system_clock::time_point{})
			{
				Dest.Type = pStringType;
				time_t endTime = std::chrono::system_clock::to_time_t(info->endTime);
				ctime_s(DataTypeTemp, DataTypeTemp.size(), &endTime);
				return true;
			}

			return false;

		case Members::ReturnCount:
			Dest.Type = pIntType;
			Dest.Set(info->returnValues.size());
			return true;

		case Members::Return:
			Dest.Type = pStringType;
			if (info->returnValues.empty())
				return false;

			if (!Index || !Index[0])
			{
				strcpy_s(DataTypeTemp, MAX_STRING, join(info->returnValues, ",").c_str());
			}
			else
			{
				int index = GetIntFromString(Index, 0) - 1;
				if (index < 0 || index >= static_cast<int>(info->returnValues.size()))
					return false;

				strcpy_s(DataTypeTemp, MAX_STRING, info->returnValues.at(index).c_str());
			}

			Dest.Ptr = &DataTypeTemp[0];
			return true;

		case Members::Status:
			Dest.Type = pStringType;
			strcpy_s(DataTypeTemp, MAX_STRING, std::string(info->status_string()).c_str());
			Dest.Ptr = &DataTypeTemp[0];
			return true;

		default:
			return false;
		}
	}

	bool ToString(MQVarPtr VarPtr, char* Destination) override
	{
		auto info = VarPtr.Get<LuaThreadInfo>();
		if (!info || info->returnValues.empty())
			return false;

		strcpy_s(Destination, MAX_STRING, join(info->returnValues, ",").c_str());
		return true;
	}
};
MQ2LuaInfoType* pLuaInfoType = nullptr;

//----------------------------------------------------------------------------

class MQ2LuaType : public MQ2Type
{
public:
	enum class Members
	{
		PIDs,
		Dir,
		Turbo,
		RequirePaths,
		CRequirePaths,
		Script
	};

	MQ2LuaType() : MQ2Type("lua")
	{
		ScopedTypeMember(Members, PIDs);
		ScopedTypeMember(Members, Dir);
		ScopedTypeMember(Members, Turbo);
		ScopedTypeMember(Members, RequirePaths);
		ScopedTypeMember(Members, CRequirePaths);
		ScopedTypeMember(Members, Script);
	}

	virtual bool GetMember(MQVarPtr VarPtr, const char* Member, char* Index, MQTypeVar& Dest) override
	{
		using namespace mq::datatypes;

		auto pMember = MQ2LuaType::FindMember(Member);
		if (pMember == nullptr)
			return false;

		switch (static_cast<Members>(pMember->ID))
		{
		case Members::PIDs:
		{
			Dest.Type = pStringType;
			std::vector<std::string> pids;
			std::transform(s_running.cbegin(), s_running.cend(), std::back_inserter(pids),
				[](const std::shared_ptr<LuaThread>& thread) { return std::to_string(thread->GetPID()); });
			strcpy_s(DataTypeTemp, join(pids, ",").c_str());
			Dest.Ptr = &DataTypeTemp[0];
			return true;
		}
		case Members::Dir:
			Dest.Type = pStringType;
			if (!Index[0] || ci_equals(Index, "lua"))
			{
				Dest.Ptr = &s_environment.luaDir[0];
			}
			else if (ci_equals(Index, "modules"))
			{
				Dest.Ptr = &s_environment.moduleDir[0];
			}
			else
			{
				return false;
			}
			return true;

		case Members::Turbo:
			Dest.Type = pIntType;
			Dest.Set(s_turboNum);
			return true;

		case Members::RequirePaths:
			Dest.Type = pStringType;
			strcpy_s(DataTypeTemp, fmt::format("{}\\?.lua;{}", s_environment.luaDir,
				s_environment.luaRequirePaths.empty() ? "" : join(s_environment.luaRequirePaths, ";")).c_str());
			Dest.Ptr = &DataTypeTemp[0];
			return true;

		case Members::CRequirePaths:
			Dest.Type = pStringType;
			strcpy_s(DataTypeTemp, fmt::format("{}\\?.dll;{}", s_environment.luaDir,
				s_environment.dllRequirePaths.empty() ? "" : join(s_environment.dllRequirePaths, ";")).c_str());
			Dest.Ptr = &DataTypeTemp[0];
			return true;

		case Members::Script:
		{
			Dest.Type = pLuaInfoType;
			if (!Index || !Index[0])
			{
				if (s_infoMap.empty())
					return false;

				// grab the latest start time that has an end time
				auto latest = s_infoMap.cbegin();
				for (auto it = s_infoMap.cbegin(); it != s_infoMap.cend(); ++it)
				{
					if (it->second.endTime != std::chrono::system_clock::time_point{}
						&& it->second.startTime > latest->second.startTime)
					{
						latest = it;
					}
				}

				if (latest->second.endTime != std::chrono::system_clock::time_point{})
				{
					Dest.Set(latest->second);
					return true;
				}

				return false;
			}

			auto pid = GetIntFromString(Index, 0UL);
			auto it = s_infoMap.end();
			if (pid > 0UL)
			{
				it = std::find_if(s_infoMap.begin(), s_infoMap.end(),
					[&pid](const auto& kv) { return kv.first == pid; });
			}
			else
			{
				std::string script(Index);
				it = std::find_if(s_infoMap.begin(), s_infoMap.end(),
					[&script](const auto& kv) { return ci_equals(kv.second.name, script); });
			}

			if (it != s_infoMap.end())
			{
				Dest.Set(it->second);
				return true;
			}

			return false;
		}

		default:
			return false;
		}
	}

	bool ToString(MQVarPtr VarPtr, char* Destination) override
	{
		strcpy_s(Destination, MAX_STRING, "Lua");
		return true;
	}

	static bool dataLua(const char* Index, MQTypeVar& Dest);
};
MQ2LuaType* pLuaType = nullptr;

bool MQ2LuaType::dataLua(const char* Index, MQTypeVar& Dest)
{
	Dest.DWord = 1;
	Dest.Type = pLuaType;
	return true;
}

#pragma endregion

#pragma region Commands

static uint32_t LuaRunCommand(const std::string& script, const std::vector<std::string>& args)
{
	// Need to do this first to get the script path and compare paths instead of just the names
	// since there are multiple valid ways to name the same script
	ScriptLocationInfo locationInfo = s_environment.GetScriptLocationInfo(script);
	if (!locationInfo.found)
	{
		LuaError("Cannot find lua script matching \"%s\".", script.c_str());
		return 0;
	}

	// methodology for duplicate scripts:
	//   if a script with the same name is _currently_ running, inform and exit
	//   if a script with the same name _has previously_ run, drop from infoMap and run
	//   otherwise, run script as normal
	auto info_it = std::find_if(s_infoMap.begin(), s_infoMap.end(),
		[&locationInfo](const std::pair<uint32_t, mq::lua::LuaThreadInfo>& kv)
		{
			return ci_equals(kv.second.name, locationInfo.canonicalName);
		});

	if (info_it != s_infoMap.end() && info_it->second.status != LuaThreadStatus::Exited)
	{
		// script is currently running, inform and exit
		WriteChatStatus("Lua script '%s' is already running, not starting another instance.",
			locationInfo.canonicalName.c_str());
		return 0;
	}

	if (info_it != s_infoMap.end())
	{
		// script has previously run, simply erase it because we are going to get a new entry
		s_infoMap.erase(info_it);
	}

	std::shared_ptr<LuaThread> entry = LuaThread::Create(&s_environment);
	entry->SetTurbo(s_turboNum);
	entry->EnableEvents();
	entry->EnableImGui();
	s_pending.push_back(entry);

	WriteChatStatus("Running lua script '%s' with PID %d", locationInfo.canonicalName.c_str(), entry->GetPID());

	if (std::optional<LuaThreadInfo> result = entry->StartFile(locationInfo, args))
	{
		result->status = LuaThreadStatus::Running;
		s_infoMap.emplace(result->pid, *result);
		return result->pid;
	}

	return 0;
}

static uint32_t LuaParseCommand(const std::string& script, std::string_view name = "lua parse")
{
	auto info_it = std::find_if(s_infoMap.begin(), s_infoMap.end(),
		[&](const std::pair<uint32_t, mq::lua::LuaThreadInfo>& kv)
		{ return kv.second.name == name && kv.second.isString; });

	if (info_it != s_infoMap.end()
		&& info_it->second.endTime == std::chrono::system_clock::time_point{}
		&& name == "lua parse")
	{
		// parsed script is currently running, inform and exit
		WriteChatStatus("Parsed Lua script is already running, not starting another instance.");
		return 0;
	}

	if (info_it != s_infoMap.end())
	{
		// always erase previous parse entries in the ps, it gets overcrowded otherwise
		s_infoMap.erase(info_it);
	}

	// Create LuaThread with mq namespace already injected.
	std::shared_ptr<LuaThread> entry = LuaThread::Create(&s_environment);
	entry->SetTurbo(s_turboNum);
	entry->InjectMQNamespace();
	if (name == "lua parse")
	{
		entry->SetEvaluateResult(true);
	}

	s_pending.push_back(entry);

	//WriteChatStatus("Running lua string with PID %d", entry->GetPID());

	std::optional<LuaThreadInfo> result = entry->StartString(script, name);
	if (result)
	{
		result->status = LuaThreadStatus::Running;
		s_infoMap.emplace(result->pid, *result);
		return result->pid;
	}

	return 0;
}

static void LuaStopCommand(std::optional<std::string> script = std::nullopt)
{
	if (script)
	{
		auto thread_it = s_running.end();
		uint32_t pid = GetIntFromString(*script, 0UL);
		if (pid > 0UL)
		{
			// Find by PID
			thread_it = std::find_if(s_running.begin(), s_running.end(),
				[&pid](const std::shared_ptr<LuaThread>& thread) { return thread->GetPID() == pid; });
		}
		else
		{
			// Find By Canonical Name
			thread_it = std::find_if(s_running.begin(), s_running.end(),
				[&script](const std::shared_ptr<LuaThread>& thread) { return ci_equals(thread->GetName(), *script); });

			if (thread_it == s_running.end())
			{
				// Try to find this script
				ScriptLocationInfo info = s_environment.GetScriptLocationInfo(*script);
				if (info.found)
				{
					thread_it = std::find_if(s_running.begin(), s_running.end(),
						[&info](const std::shared_ptr<LuaThread>& thread) { return ci_equals(thread->GetName(), info.canonicalName); });
				}
				else
				{
					std::string canonicalName = LuaEnvironmentSettings::GetCanonicalScriptName(*script, s_environment.luaDir);

					thread_it = std::find_if(s_running.begin(), s_running.end(),
						[&canonicalName](const std::shared_ptr<LuaThread>& thread) { return ci_equals(thread->GetName(), canonicalName); });
				}
			}
		}

		if (thread_it != s_running.end())
		{
			std::shared_ptr<LuaThread>& thread = *thread_it;

			WriteChatStatus("Ending running lua script '%s' with PID %d", thread->GetName().c_str(), thread->GetPID());

			// this will force the coroutine to yield, and removing this thread from the vector will cause it to gc
			thread->Exit();
		}
		else
		{
			WriteChatStatus("No lua script matching \"%s\" was found", script->c_str());
		}
	}
	else
	{
		// kill all scripts
		for (std::shared_ptr<LuaThread>& thread : s_running)
		{
			thread->Exit();
		}

		WriteChatStatus("Ending ALL lua scripts");
	}
}

static void LuaPauseCommand(std::optional<std::string> script, bool on, bool off)
{
	auto toggle = [](const std::shared_ptr<LuaThread>& thread)
	{
		LuaThreadStatus status = thread->Pause();

		auto info = s_infoMap.find(thread->GetPID());
		if (info != s_infoMap.end())
		{
			info->second.status = std::move(status);
		}
	};

	if (script)
	{
		auto thread_it = s_running.end();
		uint32_t pid = GetIntFromString(*script, 0UL);

		if (pid > 0UL)
		{
			thread_it = std::find_if(s_running.begin(), s_running.end(),
				[&pid](const std::shared_ptr<LuaThread>& thread) { return thread->GetPID() == pid; });
		}
		else
		{
			thread_it = std::find_if(s_running.begin(), s_running.end(),
				[&script](const std::shared_ptr<LuaThread>& thread) { return ci_equals(thread->GetName(), *script); });
		}

		if (thread_it != s_running.end())
		{
			std::shared_ptr<LuaThread>& thread = *thread_it;

			if ((on && !thread->IsPaused()) || (off && thread->IsPaused()) || (!on && !off))
			{
				toggle(thread);
			}
		}
		else
		{
			WriteChatStatus("No lua script '%s' to pause/resume", script->c_str());
		}
	}
	else if (on)
	{
		for (const auto& thread : s_running)
		{
			if (!thread->IsPaused())
			{
				toggle(thread);
			}
		}

		WriteChatStatus("Pausing ALL running lua scripts");
	}
	else if (off)
	{
		for (const auto& thread : s_running)
		{
			if (thread->IsPaused())
			{
				toggle(thread);
			}
		}

		WriteChatStatus("Resuming ALL paused lua scripts");
	}
	else
	{
		// try to Get the user's intention here. If all scripts are running/paused, batch toggle state.
		// If there are any running, assume we want to pause those only.
		auto findIter = std::find_if(s_running.cbegin(), s_running.cend(),
			[](const std::shared_ptr<LuaThread>& thread) { return !thread->IsPaused(); });
		if (findIter != s_running.cend())
		{
			// have at least one running script, so pause all running scripts
			for (const std::shared_ptr<LuaThread>& thread : s_running)
			{
				if (!thread->IsPaused())
				{
					toggle(thread);
				}
			}

			WriteChatStatus("Pausing ALL running lua scripts");
		}
		else if (!s_running.empty())
		{
			// we have no running scripts, so restart all paused scripts
			for (const std::shared_ptr<LuaThread>& thread : s_running)
			{
				toggle(thread);
			}

			WriteChatStatus("Resuming ALL paused lua scripts");
		}
		else
		{
			// there are no scripts running or paused, just inform the user of that
			WriteChatStatus("There are no running OR paused lua scripts to pause/resume");
		}
	}
}

void SetLuaDirName(const std::string& luaDir)
{
	s_luaDirName = luaDir;
	s_environment.luaDir = (std::filesystem::path(gPathMQRoot) / s_luaDirName).string();
	s_configNode[KEY_LUA_DIR] = s_luaDirName;

	for (auto& thread : s_running)
	{
		thread->UpdateLuaDir(s_environment.luaDir);
	}

	for (auto& thread : s_pending)
	{
		thread->UpdateLuaDir(s_environment.luaDir);
	}

	std::error_code ec;
	if (!std::filesystem::exists(s_environment.luaDir, ec)
		&& !std::filesystem::create_directories(s_environment.luaDir, ec))
	{
		WriteChatf("Failed to open or create directory at %s. Scripts will not run.", s_environment.luaDir.c_str());
		WriteChatf("Error was %s", ec.message().c_str());
	}
}

void SetModuleDirName(const std::string& moduleDir)
{
	s_moduleDirName = moduleDir;
	s_environment.moduleDir = (std::filesystem::path(gPathMQRoot) / s_moduleDirName).string();

	std::error_code ec;
	if (!std::filesystem::exists(s_environment.moduleDir, ec)
		&& !std::filesystem::create_directories(s_environment.moduleDir, ec))
	{
		WriteChatf("Failed to open or create directory at %s. Modules will not load.", s_environment.moduleDir.c_str());
		WriteChatf("Error was %s", ec.message().c_str());
	}

	s_configNode[KEY_MODULE_DIR] = s_moduleDirName;
}

static void WriteSettings()
{
	std::fstream file(s_configPath, std::ios::out);

	YAML::Emitter y_out;
	y_out << s_configNode;

	file << y_out.c_str();
}

static void ReadSettings()
{
	try
	{
		s_configNode = YAML::LoadFile(s_configPath);
	}
	catch (const YAML::ParserException& e)
	{
		// failed to parse, notify and return
		WriteChatf("Failed to parse settings file: %s", e.what());
	}
	catch (const YAML::BadFile&)
	{
	}

	if (mq::test_and_set(s_turboNum, s_configNode[KEY_TURBO_NUM].as<uint32_t>(s_turboNum)))
	{
		// update turbo
		for (const std::shared_ptr<LuaThread>& thread : s_running)
		{
			thread->SetTurbo(s_turboNum);
		}
	}

	s_verboseErrors = s_configNode["verboseErrors"].as<bool>(false);

	std::string tempDirName = s_luaDirName;
	if (mq::test_and_set(tempDirName, s_configNode[KEY_LUA_DIR].as<std::string>(tempDirName)) || s_environment.luaDir.empty())
	{
		SetLuaDirName(tempDirName);
	}

	std::string tempModuleDirName = s_moduleDirName;
	if (mq::test_and_set(tempModuleDirName, s_configNode[KEY_MODULE_DIR].as<std::string>(tempModuleDirName)) || s_environment.moduleDir.empty())
	{
		SetModuleDirName(tempModuleDirName);
	}

	s_environment.luaRequirePaths.clear();
	if (s_configNode[KEY_LUA_REQUIRE_PATHS].IsSequence()) // if this is not a sequence, add nothing
	{
		for (const auto& path : s_configNode[KEY_LUA_REQUIRE_PATHS])
		{
			auto fin_path = std::filesystem::path(gPathMQRoot) / std::filesystem::path(path.as<std::string>());
			s_environment.luaRequirePaths.emplace_back(fin_path.string());
		}
	}

	s_environment.dllRequirePaths.clear();
	if (s_configNode[KEY_DLL_REQUIRE_PATHS].IsSequence()) // if this is not a sequence, add nothing
	{
		for (const auto& path : s_configNode[KEY_DLL_REQUIRE_PATHS])
		{
			auto fin_path = std::filesystem::path(gPathMQRoot) / std::filesystem::path(path.as<std::string>());
			s_environment.dllRequirePaths.emplace_back(fin_path.string());
		}
	}

	auto GC_interval = s_configNode[KEY_INFO_GC].as<std::string>(std::to_string(s_infoGC.count()));
	trim(GC_interval);

	if (GC_interval.length() > 1 && GC_interval.find_first_not_of("0123456789") == std::string::npos)
	{
		auto result = 0ULL;
		std::from_chars(GC_interval.data(), GC_interval.data() + GC_interval.size(), result);
		s_infoGC = std::chrono::milliseconds(result);
	}
	else if (GC_interval.length() > 1 && GC_interval.compare(GC_interval.length() - 1, 1, "h") == 0)
	{
		auto result = 0ULL;
		std::from_chars(GC_interval.data(), GC_interval.data() + GC_interval.size() - 1, result);
		if (result >= 0) s_infoGC = std::chrono::hours{ result };
	}
	else if (GC_interval.length() > 1 && GC_interval.compare(GC_interval.length() - 1, 1, "m") == 0)
	{
		auto result = 0ULL;
		std::from_chars(GC_interval.data(), GC_interval.data() + GC_interval.size() - 1, result);
		if (result >= 0) s_infoGC = std::chrono::minutes{ result };
	}
	else if (GC_interval.length() > 2 && GC_interval.compare(GC_interval.length() - 2, 2, "ms") == 0)
	{
		auto result = 0ULL;
		std::from_chars(GC_interval.data(), GC_interval.data() + GC_interval.size() - 2, result);
		s_infoGC = std::chrono::milliseconds{ result };
	}
	else if (GC_interval.length() > 1 && GC_interval.compare(GC_interval.length() - 1, 1, "s") == 0)
	{
		auto result = 0ULL;
		std::from_chars(GC_interval.data(), GC_interval.data() + GC_interval.size() - 1, result);
		if (result >= 0) s_infoGC = std::chrono::seconds{ result };
	}

	s_squelchStatus = s_configNode[KEY_SQUELCH_STATUS].as<bool>(s_squelchStatus);
	s_showMenu = s_configNode[KEY_SHOW_MENU].as<bool>(s_showMenu);
}

static void LuaConfCommand(const std::string& setting, const std::string& value)
{
	if (!value.empty())
	{
		if (ci_equals(setting, KEY_LUA_REQUIRE_PATHS) || ci_equals(setting, KEY_DLL_REQUIRE_PATHS))
		{
			if (s_configNode[setting].IsNull())
				s_configNode[setting] = YAML::Load("[]");

			auto it = std::find_if(s_configNode[setting].begin(), s_configNode[setting].end(), [&value](const auto& node)
				{
					return node.IsScalar() && ci_equals(value, node.as<std::string>());
				});
			if (it != s_configNode[setting].end())
			{
				WriteChatStatus("Lua removing %s from %s and saving...", value.c_str(), setting.c_str());
				s_configNode[setting].remove(std::distance(s_configNode[setting].begin(), it));
				if (s_configNode[setting].size() == 0)
					s_configNode.remove(setting);
			}
			else
			{
				WriteChatStatus("Lua adding %s to %s and saving...", value.c_str(), setting.c_str());
				s_configNode[setting].push_back(value);
			}
		}
		else
		{
			WriteChatStatus("Lua setting %s to %s and saving...", setting.c_str(), value.c_str());
			s_configNode[setting] = value;
		}
		WriteSettings();
		ReadSettings();
	}
	else if (s_configNode[setting])
	{
		if (s_configNode[setting].IsSequence())
		{
			auto vec = s_configNode[setting].as<std::vector<std::string>>();
			WriteChatStatus("Lua setting %s is set to [%s].", setting.c_str(), join(vec, ", ").c_str());
		}
		else
			WriteChatStatus("Lua setting %s is set to %s.", setting.c_str(), s_configNode[setting].as<std::string>().c_str());
	}
	else
	{
		WriteChatStatus("Lua setting %s is not set (using default).", setting.c_str());
	}
}

static void LuaPSCommand(const std::vector<std::string>& filters = {})
{
	auto predicate = [&filters](const LuaThreadInfo& info)
	{
		if (filters.empty())
		{
			return info.status == LuaThreadStatus::Running || info.status == LuaThreadStatus::Paused;
		}

		auto status = info.status_string();

		return std::find(filters.begin(), filters.end(), status) != filters.end();
	};

	WriteChatStatus("|  PID  |    NAME    |    START    |     END     |   STATUS   |");

	for (const auto& [pid, info] : s_infoMap)
	{
		if (predicate(info))
		{
			fmt::memory_buffer line;
			fmt::format_to(fmt::appender(line), "|{:^7}|{:^12}|{:%m/%d %I:%M%p}|{:^13}|{:^12}|",
				pid,
				info.name.length() > 12 ? info.name.substr(0, 9) + "..." : info.name,
				info.startTime,
				info.status == LuaThreadStatus::Exited ? fmt::format("{:%m/%d %I:%M%p}", info.endTime) : "",
				info.status_string());
			WriteChatStatus("%.*s", line.size(), line.data());
		}
	}
}

static void LuaInfoCommand(const std::optional<std::string>& script = std::nullopt)
{
	if (script)
	{
		auto thread_it = s_infoMap.end();
		uint32_t pid = GetIntFromString(*script, 0UL);

		if (pid > 0UL)
		{
			thread_it = std::find_if(s_infoMap.begin(), s_infoMap.end(),
				[&pid](const auto& kv) { return kv.first == pid; });
		}
		else
		{
			thread_it = std::find_if(s_infoMap.begin(), s_infoMap.end(),
				[&script](const auto& kv) { return ci_equals(kv.second.name, *script); });
		}

		if (thread_it != s_infoMap.end())
		{
			const LuaThreadInfo& info = thread_it->second;

			fmt::memory_buffer line;
			fmt::format_to(
				fmt::appender(line),
				"pid: {}\nname: {}\npath: {}\narguments: {}\nstartTime: {}\nendTime: {}\nreturnValues: {}\nstatus: {}",
				info.pid,
				info.name,
				info.path,
				join(info.arguments, ", "),
				info.startTime,
				info.endTime,
				join(info.returnValues, ", "),
				static_cast<int>(info.status));

			WriteChatStatus("%.*s", line.size(), line.data());
		}
		else
		{
			WriteChatStatus("No lua script '%s'", script->c_str());
		}
	}
	else
	{
		WriteChatStatus("|  PID  |         NAME         |    START    |     END     |   STATUS   |");

		for (const auto& [pid, info] : s_infoMap)
		{
			fmt::memory_buffer line;
			fmt::format_to(fmt::appender(line), "|{:^7}|{:^22}|{:^13}|{:^13}|{:^12}|",
				pid,
				info.name.length() > 22 ? info.name.substr(0, 19) + "..." : info.name,
				(info.startTime != std::chrono::system_clock::time_point() ? fmt::format("{:%H:%M:%S}", info.startTime) : std::string()),
				(info.endTime != std::chrono::system_clock::time_point() ? fmt::format("{:%H:%M:%S}", info.endTime) : std::string()),
				static_cast<int>(info.status));
			WriteChatStatus("%.*s", line.size(), line.data());
		}
	}
}

static void LuaGuiCommand()
{
	s_showMenu = !s_showMenu;
	s_configNode[KEY_SHOW_MENU] = s_showMenu;
}

static args::HelpFlag HelpFlag(args::Group& group)
{
	return args::HelpFlag(group, "help", "displays this help text", { "h", "?", "help" });
}

void LuaCommand(SPAWNINFO* pChar, char* Buffer)
{
	MQ2Args arg_parser("Lua: A lua script binding plugin.");
	arg_parser.Prog("/lua");
	arg_parser.RequireCommand(false);
	arg_parser.LongPrefix("-");
	args::Group commands(arg_parser, "", args::Group::Validators::AtMostOne);

	args::Command run(commands, "run", "run lua script from file location",
		[](args::Subparser& parser)
		{
			args::Group arguments(parser, "", args::Group::Validators::AllChildGroups);
			args::Positional<std::string> script(arguments, "script", "the name of the lua script to run. will automatically append .lua extension if no extension specified.");
			args::PositionalList<std::string> script_args(arguments, "args", "optional arguments to pass to the lua script.");
			auto h = HelpFlag(parser);
			parser.Parse();

			if (script) LuaRunCommand(script.Get(), script_args.Get());
		});

	args::Command parse(commands, "parse", "parse a lua string with an available mq namespace",
		[](args::Subparser& parser)
		{
			args::Group arguments(parser, "", args::Group::Validators::DontCare);
			args::PositionalList<std::string> script(arguments, "script", "the text of the lua script to run");
			auto h = HelpFlag(parser);
			parser.Parse();

			if (script) LuaParseCommand(join(script.Get(), " "));
		});

	args::Command stop(commands, "stop", "stop one or all running lua scripts",
		[](args::Subparser& parser)
		{
			args::Group arguments(parser, "", args::Group::Validators::AtMostOne);
			args::Positional<std::string> script(arguments, "process", "optional parameter to specify a PID or name of script to stop, if not specified will stop all running scripts.");
			auto h = HelpFlag(parser);
			parser.Parse();

			if (script) LuaStopCommand(script.Get());
			else LuaStopCommand();
		});
	stop.RequireCommand(false);

	args::Command pause(commands, "pause", "pause one or all running lua scripts",
		[](args::Subparser& parser)
		{
			args::Group arguments(parser, "", args::Group::Validators::AtMostOne);
			args::Positional<std::string> script(arguments, "process", "optional parameter to specify a PID or name of script to pause, if not specified will pause all running scripts.");

			args::Group idempotent(parser, "", args::Group::Validators::AtMostOne);
			args::Flag on(idempotent, "on", "idempotently turn pause on", { "on" });
			args::Flag off(idempotent, "off", "idempotently turn pause on", { "off" });

			auto h = HelpFlag(parser);
			parser.Parse();

			if (script) LuaPauseCommand(script.Get(), on, off);
			else LuaPauseCommand({}, on, off);
		});
	pause.RequireCommand(false);

	args::Command conf(commands, "conf", "set or view configuration variable",
		[](args::Subparser& parser)
		{
			args::Group arguments(parser, "", args::Group::Validators::AtLeastOne);
			args::Positional<std::string> setting(arguments, "setting", "The setting to display/set");
			args::PositionalList<std::string> value(arguments, "value", "An optional parameter to specify the value to set");
			auto h = HelpFlag(parser);
			parser.Parse();

			if (setting) LuaConfCommand(setting.Get(), join(value.Get(), " "));
		});

	args::Command reloadconf(commands, "reloadconf", "reload configuration",
		[](args::Subparser& parser)
		{
			args::Group arguments(parser, "", args::Group::Validators::DontCare);
			auto h = HelpFlag(parser);
			parser.Parse();

			WriteChatStatus("Reloading lua config.");
			ReadSettings();
		});

	args::Command ps(commands, "ps", "ps-like process listing",
		[](args::Subparser& parser)
		{
			args::Group arguments(parser, "", args::Group::Validators::AtMostOne);
			args::PositionalList<std::string> filters(arguments, "filters", "optional parameters to specify status filters. Defaults to RUNNING or PAUSED.");
			auto h = HelpFlag(parser);
			parser.Parse();

			LuaPSCommand(filters.Get());
		});

	args::Command info(commands, "info", "info for a process",
		[](args::Subparser& parser)
		{
			args::Group arguments(parser, "", args::Group::Validators::AtMostOne);
			args::Positional<std::string> script(arguments, "process", "optional parameter to specify a PID or name of script to get info for, if not specified will return table of all scripts.");
			auto h = HelpFlag(parser);
			parser.Parse();

			if (script) LuaInfoCommand(script.Get());
			else LuaInfoCommand();
		});

	args::Command gui(commands, "gui", "toggle the lua GUI",
		[](args::Subparser& parser)
		{
			parser.Parse();
			LuaGuiCommand();
		});

	auto h = HelpFlag(commands);

	auto args = allocate_args(Buffer);
	try
	{
		arg_parser.ParseArgs(args);
	}
	catch (const args::Help&)
	{
		arg_parser.Help();
	}
	catch (const args::Error& e)
	{
		WriteChatColor(e.what());
	}

	if (args.empty())
	{
		arg_parser.Help();
	}
}

#pragma endregion

#pragma region LuaEnvironmentSettings

LuaEnvironmentSettings::LuaEnvironmentSettings()
{
}

LuaEnvironmentSettings::~LuaEnvironmentSettings()
{
}

void LuaEnvironmentSettings::ConfigureLuaState(sol::state_view sv)
{
	if (!m_initialized)
	{
		m_packagePath = sv["package"]["path"].get<std::string>();
		m_packageCPath = sv["package"]["cpath"].get<std::string>();

		// Lua _VERSION is output as "Lua 5.1" -- could use regex to match, but all versions seem to be in this format
		m_version = sv["_VERSION"].get<std::string>();
		const size_t pos = m_version.rfind(' ');
		if (pos != std::string::npos)
		{
			m_version = m_version.substr(pos + 1);
		}

		// LuaJIT jit.version is output as "LuaJIT 2.1.0-beta3"
		m_jitversion = sv["jit"]["version"].get<std::string>();
		const size_t jitpos = m_jitversion.rfind(' ');
		if (jitpos != std::string::npos)
		{
			m_jitversion = m_jitversion.substr(jitpos + 1);
		}

		m_initialized = true;
	}

	std::error_code ec;

	// always search the local dir first, then luarocks in modules, then anything specified by the user, then the default paths
	{
		std::vector<std::string> formattedRequirePaths = {
			"{luaDir}\\?\\init.lua",
			"{luaDir}\\?.lua",
			"{moduleDir}\\{jitVersion}\\luarocks\\share\\lua\\{luaVersion}\\?.lua",
			"{moduleDir}\\{jitVersion}\\luarocks\\share\\lua\\{luaVersion}\\?\\init.lua",
			"{moduleDir}\\luarocks\\share\\lua\\{luaVersion}\\?.lua",
			"{moduleDir}\\luarocks\\share\\lua\\{luaVersion}\\?\\init.lua",
		};
		for (const std::string& searchPath : luaRequirePaths)
		{
			if (searchPath.find("?") == std::string::npos)
			{
				formattedRequirePaths.push_back(fmt::format("{}\\?\\init.lua", searchPath));
				formattedRequirePaths.push_back(fmt::format("{}\\?.lua", searchPath));
			}
			else
			{
				formattedRequirePaths.push_back(searchPath);
			}
		}
		formattedRequirePaths.push_back("{originalPath}");

		sv["package"]["path"] = fmt::format(join(formattedRequirePaths, ";"),
			fmt::arg("luaDir", luaDir),
			fmt::arg("moduleDir", moduleDir),
			fmt::arg("jitVersion", m_jitversion),
			fmt::arg("luaVersion", m_version),
			fmt::arg("originalPath", m_packagePath));
	}

	sv["package"]["cpath"] = fmt::format("{moduleDir}\\{jitVersion}\\luarocks\\lib\\lua\\{luaVersion}\\?.dll;{dllPaths}{originalPath}",
		fmt::arg("moduleDir", moduleDir),
		fmt::arg("jitVersion", m_jitversion),
		fmt::arg("luaVersion", m_version),
		fmt::arg("dllPaths", dllRequirePaths.empty() ? "" : join(dllRequirePaths, ";") + ";"),
		fmt::arg("originalPath", m_packageCPath));
}

ScriptLocationInfo LuaEnvironmentSettings::GetScriptLocationInfo(std::string_view script) const
{
	ScriptLocationInfo info;

	if (GetScriptLocationInfo(script, luaDir, info))
		return info;

	for (const std::string& searchPath : luaRequirePaths)
	{
		if (GetScriptLocationInfo(script, searchPath, info))
			return info;
	}

	return info;
}

bool LuaEnvironmentSettings::GetScriptLocationInfo(std::string_view script, const std::string& searchDir,
	ScriptLocationInfo& info) const
{
	if (!GetScriptPath(script, searchDir, info))
		return false;

	info.canonicalName = GetCanonicalScriptName(info.fullPath, searchDir, info.isUsingInit);
	return true;
}

std::string LuaEnvironmentSettings::GetScriptPath(std::string_view script) const
{
	ScriptLocationInfo info;
	if (GetScriptPath(script, luaDir, info))
		return info.fullPath;

	for (const std::string& searchPath : luaRequirePaths)
	{
		if (GetScriptPath(script, searchPath, info))
			return info.fullPath;
	}

	return {};
}

bool LuaEnvironmentSettings::GetScriptPath(std::string_view script, const std::string& searchDir,
	ScriptLocationInfo& info) const
{
	std::error_code ec;

	const auto script_path = fs::absolute(fs::path(searchDir) / script, ec).lexically_normal();
	const auto lua_path = script_path.parent_path() / (script_path.filename().string() + ".lua");

	if (fs::exists(script_path, ec) && fs::is_directory(script_path, ec) && fs::exists(script_path / "init.lua", ec))
	{
		info.fullPath = (script_path / "init.lua").string();
		info.foundSearchPath = searchDir;
		info.found = true;
		info.isUsingInit = true;
		return true;
	}

	if (!fs::exists(script_path, ec) && fs::exists(lua_path, ec) && fs::is_directory(lua_path, ec) && fs::exists(lua_path / "init.lua", ec))
	{
		info.fullPath = (lua_path / "init.lua").string();
		info.foundSearchPath = searchDir;
		info.found = true;
		info.isUsingInit = true;
		return true;
	}

	if (fs::exists(script_path, ec) && !fs::is_directory(script_path, ec))
	{
		info.fullPath = script_path.string();
		info.foundSearchPath = searchDir;
		info.found = true;
		info.isUsingInit = false;
		return true;
	}

	if (fs::exists(lua_path, ec) && !fs::is_directory(lua_path, ec))
	{
		info.fullPath = lua_path.string();
		info.foundSearchPath = searchDir;
		info.found = true;
		info.isUsingInit = false;
		return true;
	}

	return false;
}

std::string LuaEnvironmentSettings::GetCanonicalScriptName(std::string_view script, std::string_view searchPath,
	bool isUsingInit /* = false */)
{
	auto script_path = fs::path(script);

	// attempt to make it relative to the search directory that we were found in.
	auto relative = script_path.lexically_relative(searchPath);
	if (!relative.empty() && relative.native()[0] != '.')
		script_path = relative;

	// Strip init.lua
	if (isUsingInit || ci_equals(script_path.filename().string(), "init.lua"))
		script_path = script_path.parent_path();

	// Strip lua extension
	else if (script_path.extension() == ".lua")
		script_path.replace_extension("");

	// Use forward slashes
	return mq::replace(script_path.string(), "\\", "/");
}

bool LuaEnvironmentSettings::IsSearchPath(std::string_view script) const
{
	fs::path script_path(script);
	std::error_code ec;

	if (fs::equivalent(script_path, luaDir, ec))
		return true;

	for (const std::string& searchPath : luaRequirePaths)
	{
		if (fs::equivalent(script_path, searchPath, ec))
			return true;
	}

	return false;
}

#pragma endregion

#pragma region Lua Plugin Interface

class LuaPluginInterfaceImpl : public LuaPluginInterface
{
public:
	LuaScriptPtr CreateLuaScript() override
	{
		LuaScriptPtr entry = LuaThread::Create(&s_environment);
		entry->SetTurbo(s_turboNum);
		s_pending.push_back(entry);

		return entry;
	}

	void DestroyLuaScript(const LuaScriptPtr& thread) override
	{
		thread->Exit();
		s_infoMap.erase(thread->GetPID());
	}

	void ExecuteFile(const LuaScriptPtr& thread, std::string_view filename, const std::vector<std::string>& arguments) override
	{
		std::optional<LuaThreadInfo> result = thread->StartFile(filename, arguments);
		if (result)
		{
			result->status = LuaThreadStatus::Running;
			s_infoMap.emplace(result->pid, *result);
		}

		// TODO: Return value?
	}

	void ExecuteString(const LuaScriptPtr& thread, std::string_view script, std::string_view name = "") override
	{
		std::optional<LuaThreadInfo> result = thread->StartString(script, name);
		if (result)
		{
			result->status = LuaThreadStatus::Running;
			s_infoMap.emplace(result->pid, *result);
		}

		// TODO: Return value?
	}

	void SetTurbo(const LuaScriptPtr& thread, uint32_t turbo) override
	{
		thread->SetTurbo(turbo);
	}

	void InjectMQNamespace(const LuaScriptPtr& thread) override
	{
		return thread->InjectMQNamespace();
	}

	bool IsPaused(const LuaScriptPtr& thread) override
	{
		return thread->IsPaused();
	}

	int GetPid(const LuaScriptPtr& thread) override
	{
		return thread->GetPID();
	}

	const std::string& GetName(const LuaScriptPtr& thread) override
	{
		return thread->GetName();
	}

	sol::state_view GetLuaState(const LuaScriptPtr& thread) override
	{
		return thread->GetState();
	}
};

LuaPluginInterfaceImpl* s_pluginInterface = nullptr;

#pragma endregion

} // namespace mq::lua


#pragma region GUI

static void DrawLuaSettings()
{
	using namespace mq::lua;

	ImGui::BeginChild("##luasettings", ImVec2(0, -ImGui::GetFrameHeightWithSpacing() - 4), false);

	bool squelch = s_configNode[KEY_SQUELCH_STATUS].as<bool>(s_squelchStatus);
	if (ImGui::Checkbox("Suppress Lua Messages", &squelch))
	{
		s_squelchStatus = squelch;
		s_configNode[KEY_SQUELCH_STATUS] = s_squelchStatus;
	}

	bool showgui = s_configNode[KEY_SHOW_MENU].as<bool>(s_showMenu);
	if (ImGui::Checkbox("Show Lua GUI", &showgui))
	{
		s_showMenu = showgui;
		s_configNode[KEY_SHOW_MENU] = s_showMenu;
	}

	if (ImGui::Checkbox("Print Lua Stack in Exception Messages", &s_verboseErrors))
	{
		s_configNode["verboseErrors"] = s_verboseErrors;
	}

	ImGui::NewLine();

	ImGui::Text("Turbo Num:");
	uint32_t turbo_selected = s_configNode[KEY_TURBO_NUM].as<uint32_t>(s_turboNum), turbo_min = 100U, turbo_max = 1000U;
	ImGui::SetNextItemWidth(-1.0f);
	if (ImGui::SliderScalar("##turboNumslider", ImGuiDataType_U32, &turbo_selected, &turbo_min, &turbo_max, "%u Instructions per Frame", ImGuiSliderFlags_None))
	{
		s_turboNum = turbo_selected;
		s_configNode[KEY_TURBO_NUM] = s_turboNum;
	}


	ImGui::Text("Lua Directory:");
	auto dirDisplay = s_configNode[KEY_LUA_DIR].as<std::string>(s_luaDirName);
	ImGui::SetNextItemWidth(-80.0f);
	ImGui::InputText("##luadirname", &dirDisplay[0], dirDisplay.size(), ImGuiInputTextFlags_ReadOnly);

	if (!s_luaDirDialog)
	{
		s_luaDirDialog = IGFD_Create();
	}

	ImGui::SameLine();
	ImGui::SetNextItemWidth(80.0f);
	if (ImGui::Button("Choose..."))
	{
		IGFD_OpenDialog2(s_luaDirDialog, "ChooseLuaDirKey", "Select Lua Directory", nullptr,
			(std::string(gPathMQRoot) + "/").c_str(), 1, nullptr, ImGuiFileDialogFlags_None);
	}

	if (IGFD_DisplayDialog(s_luaDirDialog, "ChooseLuaDirKey", ImGuiWindowFlags_None, ImVec2(350, 350), ImVec2(FLT_MAX, FLT_MAX)))
	{
		if (IGFD_IsOk(s_luaDirDialog))
		{
			std::shared_ptr<char> selected_path(IGFD_GetCurrentPath(s_luaDirDialog), IGFD_DestroyString);

			std::error_code ec;
			if (selected_path && std::filesystem::exists(selected_path.get(), ec))
			{
				auto mq_path = std::filesystem::canonical(std::filesystem::path(gPathMQRoot), ec).string();
				auto lua_path = std::filesystem::canonical(std::filesystem::path(selected_path.get()), ec).string();

				std::string lua_name = lua_path;

				// If lua_path begins with mq_path, then make it relative.
				int pos = mq::ci_find_substr(lua_path, mq_path);
				if (pos == 0)
				{
					std::string_view sv(lua_path);
					sv = sv.substr(mq_path.size());
					
					auto slashPos = sv.find_first_not_of("\\/");
					if (slashPos != std::string_view::npos && slashPos != 0)
					{
						sv.remove_prefix(slashPos);
					}

					lua_name = std::string(sv);
				}

				SetLuaDirName(lua_name);
			}
		}

		IGFD_CloseDialog(s_luaDirDialog);
	}

	ImGui::Text("Modules Directory:");
	auto dirDisplayModules = s_configNode[KEY_MODULE_DIR].as<std::string>(s_moduleDirName);
	ImGui::SetNextItemWidth(-80.0f);
	ImGui::InputText("##moduledirname", &dirDisplayModules[0], dirDisplayModules.size(), ImGuiInputTextFlags_ReadOnly);

	if (!s_moduleDirDialog)
	{
		s_moduleDirDialog = IGFD_Create();
	}

	ImGui::SameLine();
	ImGui::SetNextItemWidth(80.0f);
	if (ImGui::Button("Choose...##modulebutton"))
	{
		IGFD_OpenDialog2(s_moduleDirDialog, "ChooseModuleDirKey", "Select Module Directory", nullptr,
			(std::string(gPathMQRoot) + "/").c_str(), 1, nullptr, ImGuiFileDialogFlags_None);
	}

	if (IGFD_DisplayDialog(s_moduleDirDialog, "ChooseModuleDirKey", ImGuiWindowFlags_None, ImVec2(350, 350), ImVec2(FLT_MAX, FLT_MAX)))
	{
		if (IGFD_IsOk(s_moduleDirDialog))
		{
			std::shared_ptr<char> selected_path(IGFD_GetCurrentPath(s_moduleDirDialog), IGFD_DestroyString);

			std::error_code ec;
			if (selected_path && std::filesystem::exists(selected_path.get(), ec))
			{
				auto mq_path = std::filesystem::canonical(std::filesystem::path(gPathMQRoot), ec).string();
				auto module_path = std::filesystem::canonical(std::filesystem::path(selected_path.get()), ec).string();

				std::string module_name = module_path;

				// If lua_path begins with mq_path, then make it relative.
				int pos = mq::ci_find_substr(module_path, mq_path);
				if (pos == 0)
				{
					std::string_view sv(module_path);
					sv = sv.substr(mq_path.size());

					auto slashPos = sv.find_first_not_of("\\/");
					if (slashPos != std::string_view::npos && slashPos != 0)
					{
						sv.remove_prefix(slashPos);
					}

					module_name = std::string(sv);
				}

				SetModuleDirName(module_name);
			}
		}

		IGFD_CloseDialog(s_moduleDirDialog);
	}

	ImGui::Text("Process Info Garbage Collect Time");
	float gc_selected = s_configNode[KEY_INFO_GC].as<uint64_t>(s_infoGC.count()) / 60000.f;
	ImGui::SetNextItemWidth(-1.0f);
	if (ImGui::SliderFloat("##infoGCslider", &gc_selected, 0.f, 300.f, "%.3f minutes", ImGuiSliderFlags_None))
	{
		using float_minutes = std::chrono::duration<float, std::ratio<60>>;

		float_minutes fmins = float_minutes{ gc_selected };
		s_infoGC = std::chrono::duration_cast<std::chrono::milliseconds>(fmins);
		s_configNode[KEY_INFO_GC] = s_infoGC.count();
	}

	ImGui::NewLine();

	ImGui::Text("Lua Require Paths");
	{
		if (ImGui::BeginListBox("##luarequirepaths", ImVec2(-1.0f, 80.0f)))
		{
			if (s_configNode[KEY_LUA_REQUIRE_PATHS].IsSequence())
			{
				std::optional<int> to_remove = std::nullopt;
				int idx = 0;
				for (const auto& path : s_configNode[KEY_LUA_REQUIRE_PATHS])
				{
					ImGui::Text(path.as<std::string>().c_str());
					if (ImGui::IsItemHovered())
					{
						ImGui::BeginTooltip();
						ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
						ImGui::TextUnformatted(path.as<std::string>().c_str());
						ImGui::PopTextWrapPos();
						ImGui::EndTooltip();
					}

					ImGui::SameLine(ImGui::GetWindowContentRegionMax().x - ImGui::GetFrameHeight());

					char id[64];
					sprintf_s(id, "X##lua%d", idx);
					if (ImGui::Button(id, ImVec2(0, ImGui::GetFrameHeight())))
					{
						to_remove = idx;
					}

					++idx;
				}

				if (to_remove)
				{
					s_environment.luaRequirePaths.clear();
					s_configNode[KEY_LUA_REQUIRE_PATHS].remove(*to_remove);
					for (const auto& path : s_configNode[KEY_LUA_REQUIRE_PATHS])
					{
						auto fin_path = std::filesystem::path(gPathMQRoot) / std::filesystem::path(path.as<std::string>());
						s_environment.luaRequirePaths.emplace_back(fin_path.string());
					}
				}
			}

			ImGui::EndListBox();

			static char lua_req_buf[256] = { 0 };
			ImGui::SetNextItemWidth(-1.0f);
			if (ImGui::InputText("##luarequireadd", lua_req_buf, 256, ImGuiInputTextFlags_EnterReturnsTrue) && strlen(lua_req_buf) > 0)
			{
				s_configNode[KEY_LUA_REQUIRE_PATHS].push_back<std::string>(lua_req_buf);
				auto fin_path = std::filesystem::path(gPathMQRoot) / std::filesystem::path(lua_req_buf);
				s_environment.luaRequirePaths.emplace_back(fin_path.string());
				memset(lua_req_buf, 0, 256);
			}
		}
	}

	ImGui::Text("DLL Require Paths");
	{
		if (ImGui::BeginListBox("##dllrequirepaths", ImVec2(-1.0f, 80.0f)))
		{
			if (s_configNode[KEY_DLL_REQUIRE_PATHS].IsSequence())
			{
				std::optional<int> to_remove = std::nullopt;
				int idx = 0;
				for (const auto& path : s_configNode[KEY_DLL_REQUIRE_PATHS])
				{
					ImGui::Text(path.as<std::string>().c_str());
					if (ImGui::IsItemHovered())
					{
						ImGui::BeginTooltip();
						ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
						ImGui::TextUnformatted(path.as<std::string>().c_str());
						ImGui::PopTextWrapPos();
						ImGui::EndTooltip();
					}

					char id[64];
					sprintf_s(id, "X##dll%d", idx);

					ImGui::SameLine(ImGui::GetWindowContentRegionMax().x - ImGui::GetFrameHeight());
					if (ImGui::Button(id, ImVec2(0, ImGui::GetFrameHeight())))
					{
						to_remove = idx;
					}

					++idx;
				}

				if (to_remove)
				{
					s_environment.dllRequirePaths.clear();
					s_configNode[KEY_DLL_REQUIRE_PATHS].remove(*to_remove);
					for (const auto& path : s_configNode[KEY_DLL_REQUIRE_PATHS])
					{
						auto fin_path = std::filesystem::path(gPathMQRoot) / std::filesystem::path(path.as<std::string>());
						s_environment.dllRequirePaths.emplace_back(fin_path.string());
					}
				}
			}
			ImGui::EndListBox();

			static char dll_req_buf[256] = { 0 };
			ImGui::SetNextItemWidth(-1.0f);
			if (ImGui::InputText("##dllrequireadd", dll_req_buf, 256, ImGuiInputTextFlags_EnterReturnsTrue) && strlen(dll_req_buf) > 0)
			{
				s_configNode[KEY_DLL_REQUIRE_PATHS].push_back<std::string>(dll_req_buf);
				auto fin_path = std::filesystem::path(gPathMQRoot) / std::filesystem::path(dll_req_buf);
				s_environment.dllRequirePaths.emplace_back(fin_path.string());
				memset(dll_req_buf, 0, 256);
			}
		}
	}

	ImGui::EndChild();

	if (ImGui::Button("Write Config"))
	{
		WriteSettings();
	}
}

#pragma endregion


PLUGIN_API void InitializePlugin()
{
	using namespace mq::lua;
	DebugSpewAlways("Lua Initializing version %f", MQ2Version);

	ReadSettings();

	AddCommand("/lua", LuaCommand);

	pLuaInfoType = new MQ2LuaInfoType;
	pLuaType = new MQ2LuaType;
	AddMQ2Data("Lua", &MQ2LuaType::dataLua);

	AddCascadeMenuItem("Lua", LuaGuiCommand, -1);
	AddSettingsPanel("plugins/Lua", DrawLuaSettings);

	s_pluginInterface = new LuaPluginInterfaceImpl();

	bindings::InitializeBindings_MQMacroData();

	LuaActors::Start();
}

PLUGIN_API void ShutdownPlugin()
{
	using namespace mq::lua;

	LuaActors::Stop();

	bindings::ShutdownBindings_MQMacroData();

	RemoveCommand("/lua");

	RemoveMQ2Data("Lua");
	delete pLuaType;
	delete pLuaInfoType;

	RemoveCascadeMenuItem("Lua");
	if (s_scriptLaunchDialog != nullptr) IGFD_Destroy(s_scriptLaunchDialog);

	RemoveSettingsPanel("plugins/Lua");
	if (s_luaDirDialog != nullptr) IGFD_Destroy(s_luaDirDialog);
	if (s_moduleDirDialog != nullptr) IGFD_Destroy(s_moduleDirDialog);

	delete s_pluginInterface;
	s_pluginInterface = nullptr;
}

PLUGIN_API void OnPulse()
{
	using namespace mq::lua;

	if (!s_pending.empty())
	{
		std::move(s_pending.begin(), s_pending.end(), std::back_inserter(s_running));
		s_pending.clear();
	}

	s_running.erase(std::remove_if(s_running.begin(), s_running.end(),
		[](const std::shared_ptr<LuaThread>& thread) -> bool
		{
			LuaThread::RunResult result = thread->Run();

			if (result.first != sol::thread_status::yielded)
			{
				EndScript(thread, result, true);
				return true;
			}

			return false;
		}), s_running.end());

	// Process messages after any threads have ended or started (the order likely won't matter since cleanup is checked)
	LuaActors::Process();

	if (s_infoGC.count() > 0)
	{
		auto now_time = std::chrono::system_clock::now();
		static auto last_check_time = now_time;

		if (now_time >= last_check_time + s_infoGC)
		{
			// this doesn't need to be super tight, no one should be depending on this clearing objects at exactly the GC
			// interval, so just clear out anything that existed last time we checked.
			for (auto it = s_infoMap.begin(); it != s_infoMap.end();)
			{
				if (it->second.endTime != std::chrono::system_clock::time_point{}
					&& it->second.endTime <= last_check_time)
					it = s_infoMap.erase(it);
				else
					++it;
			}

			last_check_time = now_time;
		}
	}
}

PLUGIN_API void OnAddSpawn(PlayerClient* spawn)
{
	using namespace mq::lua;
	for (const auto& thread : s_running)
		thread->AddSpawn(spawn);

	for (const auto& thread : s_pending)
		thread->AddSpawn(spawn);
}

PLUGIN_API void OnRemoveSpawn(PlayerClient* spawn)
{
	using namespace mq::lua;
	for (const auto& thread : s_running)
		thread->RemoveSpawn(spawn);

	for (const auto& thread : s_pending)
		thread->RemoveSpawn(spawn);
}

PLUGIN_API void OnAddGroundItem(EQGroundItem* item)
{
	using namespace mq::lua;
	for (const auto& thread : s_running)
		thread->AddGroundItem(item);

	for (const auto& thread : s_pending)
		thread->AddGroundItem(item);
}

PLUGIN_API void OnRemoveGroundItem(EQGroundItem* item)
{
	using namespace mq::lua;
	for (const auto& thread : s_running)
		thread->RemoveGroundItem(item);

	for (const auto& thread : s_pending)
		thread->RemoveGroundItem(item);
}

PLUGIN_API void OnUpdateImGui()
{
	using namespace mq::lua;

	// update any script-defined windows first
	for (const std::shared_ptr<LuaThread>& thread : s_running)
	{
		if (LuaImGuiProcessor* imgui = thread->GetImGuiProcessor())
			imgui->Pulse();
	}

	if (!s_showMenu)
		return;

	// now update the lua menu window
	ImGui::SetNextWindowSize(ImVec2(500, 440), ImGuiCond_FirstUseEver);
	if (ImGui::Begin("Lua Task Manager", &s_showMenu, ImGuiWindowFlags_None))
	{
		static bool show_running = true;
		static bool show_paused = true;
		static bool show_exited = false;

		auto should_show = [](const LuaThreadInfo& info)
		{
			if (info.status == LuaThreadStatus::Exited)
				return show_exited;

			if (info.status == LuaThreadStatus::Paused)
				return show_paused;

			return show_running;
		};

		static uint32_t selected_pid = 0;

		ImGui::BeginGroup();
		{
			ImGui::BeginChild("process list", ImVec2(150, -ImGui::GetFrameHeightWithSpacing() - 4), true);

			auto doSection = [&](const char* text, auto&& condition, bool& show)
			{
				int count = 0;
				for (const auto& [_, info] : s_infoMap)
				{
					if (condition(info))
						++count;
				}

				if (ImGui::TreeNodeEx(text, ImGuiTreeNodeFlags_DefaultOpen, count > 0 ? "%s (%d)" : "%s", text, count))
				{
					show = true;
					ImGui::Unindent(ImGui::GetTreeNodeToLabelSpacing());

					for (const auto& [_, info] : s_infoMap)
					{
						if (condition(info))
						{
							ImGuiTreeNodeFlags node_flags = ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_OpenOnDoubleClick
								| ImGuiTreeNodeFlags_SpanFullWidth | ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
							if (selected_pid == info.pid)
								node_flags |= ImGuiTreeNodeFlags_Selected;

#pragma warning(suppress : 4312)
							ImGui::TreeNodeEx((void*)info.pid, node_flags, "%s: %d", info.name.c_str(), info.pid);

							if (ImGui::IsItemClicked())
								selected_pid = info.pid;
						}
					}
					ImGui::Indent(ImGui::GetTreeNodeToLabelSpacing());
					ImGui::TreePop();
				}
				else
				{
					show = false;
				}
			};

			doSection("Running", [](auto& info) { return info.status == LuaThreadStatus::Running || info.status == LuaThreadStatus::Starting;  }, show_running);
			doSection("Paused", [](auto& info) { return info.status == LuaThreadStatus::Paused;  }, show_paused);
			doSection("Exited", [](auto& info) { return info.status == LuaThreadStatus::Exited;  }, show_exited);

			ImGui::EndChild();
		}
		ImGui::EndGroup();

		ImGui::SameLine();

		ImGui::BeginGroup();

		auto infoIter = s_infoMap.find(selected_pid);
		if (infoIter != s_infoMap.end() && should_show(infoIter->second))
		{
			LuaThreadInfo& info = infoIter->second;

			if (!s_luaCodeViewer)
			{
				s_luaCodeViewer = new imgui::TextEditor();
				s_luaCodeViewer->SetLanguageDefinition(imgui::texteditor::LanguageDefinition::Lua());
				s_luaCodeViewer->SetPalette(imgui::TextEditor::GetDarkPalette());
				s_luaCodeViewer->SetReadOnly(true);
				s_luaCodeViewer->SetRenderLineNumbers(false);
				s_luaCodeViewer->SetRenderCursor(false);
				s_luaCodeViewer->SetShowWhitespace(false);
			}

			ImGui::BeginChild("process view", ImVec2(0, -2 * ImGui::GetFrameHeightWithSpacing() - 4)); // Leave room for 1 line below us

			ImGui::LabelText("PID", "%d", info.pid);
			ImGui::LabelText("Name", "%s", info.name.c_str());

			if (!info.isString)
			{
				ImGui::LabelText("Path", "%s", info.path.c_str());
			}

			if (!info.arguments.empty())
			{
				ImGui::LabelText("Arguments", "%s", join(info.arguments, ", ").c_str());
			}

			std::string_view status = info.status_string();
			ImGui::LabelText("Status", "%.*s", status.size(), status.data());

			if (!info.returnValues.empty())
			{
				ImGui::LabelText("Return Values", "%s", join(info.returnValues, ", ").c_str());
			}

			ImGui::LabelText("Start Time", "%s", fmt::format("{:%a, %b %d @ %I:%M:%S %p}", info.startTime).c_str());

			if (info.endTime != std::chrono::system_clock::time_point{})
			{
				ImGui::LabelText("End Time", "%s", fmt::format("{:%a, %b %d @ %I:%M:%S %p}", info.endTime).c_str());
			}

			if (info.isString)
			{
				ImGui::Text("Script");
				ImGui::Separator();
				ImGui::PushFont(imgui::ConsoleFont);

				static int s_lastPID = -1;
				if (s_lastPID != info.pid)
				{
					s_lastPID = info.pid;
					s_luaCodeViewer->SetText(info.path);
				}

				s_luaCodeViewer->Render("Script", ImGui::GetContentRegionAvail());
				ImGui::PopFont();
			}

			ImGui::EndChild();

			if (info.status != LuaThreadStatus::Exited)
			{
				if (ImGui::Button("Stop"))
				{
					LuaStopCommand(fmt::format("{}", info.pid));
				}

				ImGui::SameLine();

				if (ImGui::Button(info.status == LuaThreadStatus::Paused ? "Resume" : "Pause"))
				{
					LuaPauseCommand(fmt::format("{}", info.pid), false, false);
				}
			}
			else
			{
				if (ImGui::Button("Restart"))
				{
					if (info.isString)
					{
						std::string script(info.path);
						std::string name(info.name);
						selected_pid = LuaParseCommand(script, name);
					}
					else
					{
						// need to copy these because the run command will junk the info
						std::string script(info.name);
						std::vector<std::string> args(info.arguments);
						selected_pid = LuaRunCommand(script, args);
					}
				}
			}

		}
		else
		{
			selected_pid = 0;
		}
		ImGui::EndGroup();

		ImGui::Spacing();

		static char args[MAX_STRING] = { 0 };

		auto args_entry = [](const char* vFilter, void* vUserDatas, bool* vCantContinue)
		{
			ImGui::InputText("args", (char*)vUserDatas, MAX_STRING);
		};

		if (!s_scriptLaunchDialog)
		{
			s_scriptLaunchDialog = IGFD_Create();
		}

		if (ImGui::Button("Launch Script...", ImVec2(-1, 0)))
		{
			IGFD_OpenDialogWithPane2(
				s_scriptLaunchDialog,
				"ChooseScriptKey",
				"Select Lua Script to Run",
				".lua",
				(s_environment.luaDir + "/").c_str(),
				args_entry,
				350,
				1,
				static_cast<void*>(args),
				ImGuiFileDialogFlags_None
			);
		}

		if (IGFD_DisplayDialog(s_scriptLaunchDialog, "ChooseScriptKey", ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoDocking, ImVec2(700, 350), ImVec2(FLT_MAX, FLT_MAX)))
		{
			if (IGFD_IsOk(s_scriptLaunchDialog))
			{
				IGFD_Selection selection = IGFD_GetSelection(s_scriptLaunchDialog, IGFD_ResultMode_KeepInputFile);

				// avoid a silent crash to desktop by ensuring selection.table is valid
				char* selected_file = nullptr;

				if (selection.table != nullptr) {
					if (selection.table->filePathName != nullptr) {
						selected_file = selection.table->filePathName;
					} else if (selection.table->fileName != nullptr) {
						selected_file = selection.table->fileName;
					}
				}

				std::error_code ec;
				if (selected_file != nullptr && std::filesystem::exists(selected_file, ec))
				{
					// make these both canonical to ensure we get a correct comparison
					auto lua_path = std::filesystem::canonical(std::filesystem::path(s_environment.luaDir), ec).string();
					auto script_path = std::filesystem::canonical(
						std::filesystem::path(selected_file), ec
					).replace_extension("").string();

					auto [rootEnd, scriptEnd] = std::mismatch(lua_path.begin(), lua_path.end(), script_path.begin());

					auto clean_name = [](std::string_view s)
					{
						s.remove_prefix(std::min(s.find_first_not_of("\\"), s.size()));
						return std::string(s);
					};

					std::string script_name = rootEnd != lua_path.end()
						? script_path
						: clean_name(std::string(scriptEnd, script_path.end()));

					std::string args;
					auto user_datas = static_cast<const char*>(IGFD_GetUserDatas(s_scriptLaunchDialog));
					if (user_datas != nullptr)
						args = std::string(user_datas);

					LuaRunCommand(script_name, allocate_args(args));
				} else {
					WriteChatf("No file was selected or file does not exist.");
				}

				IGFD_Selection_DestroyContent(&selection);
			}

			IGFD_CloseDialog(s_scriptLaunchDialog);
		}

		s_configNode[KEY_SHOW_MENU] = s_showMenu;
	}
	ImGui::End();
}

PLUGIN_API void OnWriteChatColor(const char* Line, int Color, int Filter)
{
	for (const std::shared_ptr<mq::lua::LuaThread>& thread : mq::lua::s_running)
	{
		if (thread && !thread->IsPaused())
		{
			if (lua::LuaEventProcessor* events = thread->GetEventProcessor())
				events->Process(Line);
		}
	}
}

PLUGIN_API bool OnIncomingChat(const char* Line, DWORD Color)
{
	for (const std::shared_ptr<mq::lua::LuaThread>& thread : mq::lua::s_running)
	{
		if (thread && !thread->IsPaused())
		{
			if (lua::LuaEventProcessor* events = thread->GetEventProcessor())
				events->Process(Line);
		}
	}

	return false;
}

PLUGIN_API PluginInterface* GetPluginInterface()
{
	return mq::lua::s_pluginInterface;
}

PLUGIN_API void OnUnloadPlugin(const char* pluginName)
{
	using namespace mq::lua;

	// Visit all of our currently running scripts and terminate any that might be utilizing this plugin as a dependency.
	MQPlugin* plugin = GetPlugin(pluginName);

	s_running.erase(std::remove_if(s_running.begin(), s_running.end(),
		[&](const std::shared_ptr<LuaThread>& thread) -> bool
		{
			if (thread && thread->IsDependency(plugin))
			{
				// Exit the thread immediately
				thread->Exit(lua::LuaThreadExitReason::DependencyRemoved);

				EndScript(thread, { sol::thread_status::dead, std::nullopt }, false);

				WriteChatStatus("Running lua script '%s' with PID %d terminated due to unloading of %s",
					thread->GetName().c_str(), thread->GetPID(), pluginName);
				return true;
			}

			return false;
		}), end(s_running));
}
