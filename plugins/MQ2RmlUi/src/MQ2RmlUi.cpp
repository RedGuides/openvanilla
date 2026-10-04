// MQ2RmlUi - RmlUi (HTML/CSS-style UI with flexbox, transitions and animations) for MacroQuest emu.
//
// Each RmlUi document gets its own Rml::Context, rendered into a D3D9 render target during MQ's
// GraphicsSceneRender callback and presented inside a borderless ImGui window. ImGui therefore keeps
// handling focus, z-order and "is the mouse over UI" for EQ, and we forward its mouse/keyboard state.
//
// Lua talks to the plugin through the rml_* C exports below via LuaJIT FFI (see lua/rmlui/init.lua).

#include "mq_api.h"
#include "RenderInterface_DX9.h"

#include "imgui.h"

#include <RmlUi/Core.h>
#include <RmlUi/Debugger.h>

#include <windows.h>

#include <chrono>
#include <cstdarg>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------------------------
// Plugin identity (checked by MQ's plugin loader)

PLUGIN_API bool IsBuiltForNext = true;
PLUGIN_API const char EverQuestVersion[] = MQ_EXPECTED_EQ_VERSION;
__declspec(dllexport) float MQ2Version = 1.0f;

PLUGIN_API void InitPluginHandle(void* /*plugin*/, uint64_t /*handle*/) {}

static constexpr int kApiVersion = 1;

enum WindowFlags
{
	RMLWIN_AUTOCLOSE = 1,   // close if the owner stops polling (Lua script ended)
	RMLWIN_CLICKTHROUGH = 2, // never take mouse input
};

static constexpr double kAutoCloseSeconds = 5.0;

// ---------------------------------------------------------------------------------------------

namespace {

double NowSeconds()
{
	static const auto start = std::chrono::steady_clock::now();
	return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}

void Chat(const char* format, ...)
{
	char buffer[1024];
	va_list args;
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	mq::WriteChatf("\at[MQ2RmlUi]\ax %s", buffer);
}

std::string NormalizePath(const char* path)
{
	std::string p = path ? path : "";
	for (char& c : p)
		if (c == '\\') c = '/';

	const bool absolute = (p.size() > 1 && p[1] == ':') || (!p.empty() && p[0] == '/');
	if (!absolute)
	{
		std::string root = mq::gPathMQRoot;
		for (char& c : root)
			if (c == '\\') c = '/';
		p = root + "/lua/" + p;
	}
	return p;
}

std::string EscapeRml(const char* text)
{
	std::string out;
	for (const char* c = text ? text : ""; *c; ++c)
	{
		switch (*c)
		{
		case '&': out += "&amp;"; break;
		case '<': out += "&lt;"; break;
		case '>': out += "&gt;"; break;
		case '"': out += "&quot;"; break;
		default: out += *c; break;
		}
	}
	return out;
}

std::string Sanitize(const std::string& s)
{
	std::string out = s;
	for (char& c : out)
		if (c == '\t' || c == '\n' || c == '\r') c = ' ';
	return out;
}

void AppendUtf8(std::string& out, unsigned int cp)
{
	if (cp < 0x80) out += (char)cp;
	else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
	else if (cp < 0x10000) { out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
	else { out += (char)(0xF0 | (cp >> 18)); out += (char)(0x80 | ((cp >> 12) & 0x3F)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
}

bool IsTextInput(Rml::Element* e)
{
	if (!e) return false;
	const Rml::String& tag = e->GetTagName();
	return tag == "input" || tag == "textarea" || tag == "select";
}

// ---------------------------------------------------------------------------------------------

class SystemInterface_MQ : public Rml::SystemInterface
{
public:
	double GetElapsedTime() override { return NowSeconds(); }

	bool LogMessage(Rml::Log::Type type, const Rml::String& message) override
	{
		OutputDebugStringA(("[MQ2RmlUi] " + message + "\n").c_str());
		if (type == Rml::Log::LT_ERROR || type == Rml::Log::LT_ASSERT || type == Rml::Log::LT_WARNING)
		{
			const double now = NowSeconds();
			if (now - m_windowStart > 5.0) { m_windowStart = now; m_count = 0; }
			if (++m_count <= 12)
				Chat("%s%s", type == Rml::Log::LT_WARNING ? "\ay" : "\ar", message.c_str());
		}
		return true;
	}

	void SetClipboardText(const Rml::String& text) override { ImGui::SetClipboardText(text.c_str()); }

	void GetClipboardText(Rml::String& text) override
	{
		const char* c = ImGui::GetClipboardText();
		text = c ? c : "";
	}

private:
	double m_windowStart = 0;
	int m_count = 0;
};

struct RmlWindow;

class DocumentListener : public Rml::EventListener
{
public:
	explicit DocumentListener(RmlWindow* owner) : m_owner(owner) {}
	void ProcessEvent(Rml::Event& event) override;

private:
	RmlWindow* m_owner;
};

struct RmlWindow
{
	std::string name;
	std::string path;
	int flags = 0;

	Rml::Context* context = nullptr;
	Rml::ElementDocument* document = nullptr;
	std::unique_ptr<DocumentListener> listener;
	bool isDebuggerHost = false;

	bool visible = true;
	float defaultW = 320, defaultH = 240;
	float defaultX = -1, defaultY = -1;
	bool hasPendingRect = false;
	float pendingX = -1, pendingY = -1, pendingW = 0, pendingH = 0;

	// Size of the ImGui content region; the render target follows it.
	int wantW = 0, wantH = 0;
	double lastShown = -100;
	double lastPoll = 0;

	IDirect3DTexture9* rt = nullptr;
	IDirect3DSurface9* rtSurface = nullptr;
	IDirect3DSurface9* rtDepth = nullptr;
	int rtW = 0, rtH = 0;
	bool rendered = false;

	int lastMouseX = -1, lastMouseY = -1;
	bool mouseInside = false;
	int buttonsDown = 0;
	bool wasFocused = false;
	enum class Drag { None, Move, Resize } drag = Drag::None;

	// Window chrome state driven by action="window:*" elements (rmlui/theme/window.rml).
	bool pinned = false;
	bool collapsed = false;
	bool toggleCollapse = false;
	float expandedHeight = 0;
	ImVec2 windowSize = ImVec2(0, 0);

	std::deque<std::string> events;

	void ReleaseTarget()
	{
		if (rtDepth) { rtDepth->Release(); rtDepth = nullptr; }
		if (rtSurface) { rtSurface->Release(); rtSurface = nullptr; }
		if (rt) { rt->Release(); rt = nullptr; }
		rtW = rtH = 0;
		rendered = false;
	}

	void PushEvent(std::string e)
	{
		if (events.size() >= 256)
			events.pop_front();
		events.push_back(std::move(e));
	}
};

void DocumentListener::ProcessEvent(Rml::Event& event)
{
	Rml::Element* target = event.GetTargetElement();
	std::string id, action;
	for (Rml::Element* e = target; e; e = e->GetParentNode())
	{
		if (id.empty() && !e->GetId().empty())
			id = e->GetId();
		if (action.empty())
			action = e->GetAttribute<Rml::String>("action", "");
		if (!id.empty() && !action.empty())
			break;
	}

	const Rml::String& type = event.GetType();
	if ((type == "click" || type == "dblclick" || type == "mousedown") && id.empty() && action.empty())
		return;

	std::string value = event.GetParameter<Rml::String>("value", "");
	if (value.empty() && target && (type == "change" || type == "submit"))
		value = target->GetAttribute<Rml::String>("value", "");

	std::string button;
	if (type == "click" || type == "mousedown" || type == "dblclick")
		button = std::to_string(event.GetParameter<int>("button", 0));

	if (type == "click" && action.rfind("window:", 0) == 0)
	{
		RmlWindow* w = m_owner;
		if (action == "window:close")
		{
			w->visible = false;
		}
		else if (action == "window:collapse")
		{
			w->toggleCollapse = true;
		}
		else if (action == "window:pin")
		{
			w->pinned = !w->pinned;
			if (w->document)
				w->document->SetClass("pinned", w->pinned);
		}
	}
	else if (type == "dblclick" && target && action.empty())
	{
		for (Rml::Element* e = target; e; e = e->GetParentNode())
		{
			if (e->GetId() == "window-titlebar")
			{
				m_owner->toggleCollapse = true;
				break;
			}
		}
	}

	m_owner->PushEvent(type + "\t" + Sanitize(id) + "\t" + Sanitize(action) + "\t" + Sanitize(value) + "\t" + button);
}

// ---------------------------------------------------------------------------------------------
// Global state

SystemInterface_MQ g_system;
RenderInterface_DX9 g_render;
bool g_initialized = false;
bool g_deviceReady = false;
int g_renderCallbacksId = -1;
std::map<std::string, std::unique_ptr<RmlWindow>> g_windows;
std::string g_returnBuffer;
RmlWindow* g_debuggerHost = nullptr;
bool g_debuggerInitialized = false;
std::vector<Rml::byte> g_iconFontData; // must outlive the font engine

RmlWindow* FindRmlWindow(const char* name)
{
	if (!g_initialized || !name)
		return nullptr;
	auto it = g_windows.find(name);
	return it == g_windows.end() ? nullptr : it->second.get();
}

Rml::Element* FindElement(const char* window, const char* id)
{
	RmlWindow* w = FindRmlWindow(window);
	if (!w || !w->document)
		return nullptr;
	if (!id || !*id || strcmp(id, "body") == 0)
		return w->document;
	return w->document->GetElementById(id);
}

void UnloadDocument(RmlWindow* w)
{
	if (w->document)
	{
		if (w->listener)
		{
			for (const char* type : { "click", "dblclick", "change", "submit" })
				w->document->RemoveEventListener(type, w->listener.get(), true);
		}
		w->context->UnloadDocument(w->document);
		w->document = nullptr;
		w->context->Update();
	}
}

bool LoadDocument(RmlWindow* w)
{
	UnloadDocument(w);

	w->document = w->context->LoadDocument(w->path);
	if (!w->document)
	{
		Chat("\arfailed to load '%s'", w->path.c_str());
		return false;
	}

	if (!w->listener)
		w->listener = std::make_unique<DocumentListener>(w);
	for (const char* type : { "click", "dblclick", "change", "submit" })
		w->document->AddEventListener(type, w->listener.get(), true);

	if (Rml::Element* title = w->document->GetElementById("window-title"))
		title->SetInnerRML(EscapeRml(w->document->GetTitle().c_str()));
	w->document->SetClass("pinned", w->pinned);
	w->document->SetClass("collapsed", w->collapsed);

	w->document->Show();
	return true;
}

void DestroyRmlWindow(const std::string& name)
{
	auto it = g_windows.find(name);
	if (it == g_windows.end())
		return;

	RmlWindow* w = it->second.get();
	if (g_debuggerInitialized && g_debuggerHost && w != g_debuggerHost)
	{
		Rml::Debugger::SetVisible(false);
		Rml::Debugger::SetContext(g_debuggerHost->context);
	}
	if (w == g_debuggerHost)
		return; // the debugger host lives until shutdown

	UnloadDocument(w);
	w->ReleaseTarget();
	Rml::RemoveContext(w->context->GetName());
	g_windows.erase(it);
}

RmlWindow* CreateRmlWindow(const std::string& name)
{
	auto w = std::make_unique<RmlWindow>();
	w->name = name;
	w->lastPoll = NowSeconds();
	w->context = Rml::CreateContext("mq2rmlui_" + name, Rml::Vector2i(320, 240), &g_render);
	if (!w->context)
		return nullptr;
	RmlWindow* raw = w.get();
	g_windows[name] = std::move(w);
	return raw;
}

// ---------------------------------------------------------------------------------------------
// Rendering (MQ GraphicsSceneRender callback, inside EQ's scene)

bool EnsureTarget(IDirect3DDevice9* device, RmlWindow* w)
{
	const int width = Rml::Math::Clamp(w->wantW, 1, 4096);
	const int height = Rml::Math::Clamp(w->wantH, 1, 4096);
	if (w->rt && w->rtW == width && w->rtH == height)
		return true;

	w->ReleaseTarget();
	if (FAILED(device->CreateTexture(width, height, 1, D3DUSAGE_RENDERTARGET, D3DFMT_A8R8G8B8, D3DPOOL_DEFAULT, &w->rt, nullptr)))
		return false;
	if (FAILED(w->rt->GetSurfaceLevel(0, &w->rtSurface))
		|| FAILED(device->CreateDepthStencilSurface(width, height, D3DFMT_D24S8, D3DMULTISAMPLE_NONE, 0, TRUE, &w->rtDepth, nullptr)))
	{
		w->ReleaseTarget();
		return false;
	}
	w->rtW = width;
	w->rtH = height;
	return true;
}

void OnCreateDeviceObjects()
{
	g_render.SetDevice(mq::gpD3D9Device);
	g_deviceReady = mq::gpD3D9Device != nullptr;
}

void OnInvalidateDeviceObjects()
{
	g_deviceReady = false;
	for (auto& [_, w] : g_windows)
		w->ReleaseTarget();
}

void OnGraphicsSceneRender()
{
	if (!g_initialized || !g_deviceReady || !mq::gpD3D9Device)
		return;

	IDirect3DDevice9* device = mq::gpD3D9Device;
	g_render.SetDevice(device);

	const double now = NowSeconds();
	std::vector<RmlWindow*> pending;
	for (auto& [_, w] : g_windows)
	{
		if (w->visible && w->context && w->wantW > 0 && w->wantH > 0 && now - w->lastShown < 0.5)
			pending.push_back(w.get());
	}
	if (pending.empty())
		return;

	IDirect3DStateBlock9* stateBlock = nullptr;
	if (FAILED(device->CreateStateBlock(D3DSBT_ALL, &stateBlock)))
		return;

	IDirect3DSurface9* oldTarget = nullptr;
	IDirect3DSurface9* oldDepth = nullptr;
	D3DVIEWPORT9 oldViewport;
	D3DMATRIX oldWorld, oldView, oldProjection;
	device->GetRenderTarget(0, &oldTarget);
	device->GetDepthStencilSurface(&oldDepth);
	device->GetViewport(&oldViewport);
	device->GetTransform(D3DTS_WORLD, &oldWorld);
	device->GetTransform(D3DTS_VIEW, &oldView);
	device->GetTransform(D3DTS_PROJECTION, &oldProjection);

	for (RmlWindow* w : pending)
	{
		if (!EnsureTarget(device, w))
			continue;

		w->context->SetDimensions(Rml::Vector2i(w->rtW, w->rtH));
		w->context->Update();

		device->SetRenderTarget(0, w->rtSurface);
		device->SetDepthStencilSurface(w->rtDepth);
		g_render.BeginFrame(w->rtW, w->rtH);
		w->context->Render();
		g_render.EndFrame();
		w->rendered = true;
	}

	device->SetRenderTarget(0, oldTarget);
	device->SetDepthStencilSurface(oldDepth);
	device->SetViewport(&oldViewport);
	device->SetTransform(D3DTS_WORLD, &oldWorld);
	device->SetTransform(D3DTS_VIEW, &oldView);
	device->SetTransform(D3DTS_PROJECTION, &oldProjection);
	if (oldTarget) oldTarget->Release();
	if (oldDepth) oldDepth->Release();

	stateBlock->Apply();
	stateBlock->Release();
}

// The render target holds premultiplied alpha; ImGui's DX9 backend blends straight alpha.
void SetPremultipliedBlend(const ImDrawList*, const ImDrawCmd*)
{
	if (IDirect3DDevice9* device = mq::gpD3D9Device)
	{
		device->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_ONE);
		device->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
	}
}

// ---------------------------------------------------------------------------------------------
// ImGui hosting and input forwarding

struct KeyMap { ImGuiKey imgui; Rml::Input::KeyIdentifier rml; };
const KeyMap kKeys[] = {
	{ ImGuiKey_Backspace, Rml::Input::KI_BACK }, { ImGuiKey_Delete, Rml::Input::KI_DELETE },
	{ ImGuiKey_LeftArrow, Rml::Input::KI_LEFT }, { ImGuiKey_RightArrow, Rml::Input::KI_RIGHT },
	{ ImGuiKey_UpArrow, Rml::Input::KI_UP }, { ImGuiKey_DownArrow, Rml::Input::KI_DOWN },
	{ ImGuiKey_Home, Rml::Input::KI_HOME }, { ImGuiKey_End, Rml::Input::KI_END },
	{ ImGuiKey_PageUp, Rml::Input::KI_PRIOR }, { ImGuiKey_PageDown, Rml::Input::KI_NEXT },
	{ ImGuiKey_Enter, Rml::Input::KI_RETURN }, { ImGuiKey_KeypadEnter, Rml::Input::KI_NUMPADENTER },
	{ ImGuiKey_Tab, Rml::Input::KI_TAB }, { ImGuiKey_Escape, Rml::Input::KI_ESCAPE },
	{ ImGuiKey_A, Rml::Input::KI_A }, { ImGuiKey_C, Rml::Input::KI_C },
	{ ImGuiKey_V, Rml::Input::KI_V }, { ImGuiKey_X, Rml::Input::KI_X },
	{ ImGuiKey_Z, Rml::Input::KI_Z }, { ImGuiKey_F8, Rml::Input::KI_F8 },
};

int KeyModifiers(const ImGuiIO& io)
{
	int mods = 0;
	if (io.KeyCtrl) mods |= Rml::Input::KM_CTRL;
	if (io.KeyShift) mods |= Rml::Input::KM_SHIFT;
	if (io.KeyAlt) mods |= Rml::Input::KM_ALT;
	return mods;
}

RmlWindow::Drag DragModeAt(Rml::Element* element)
{
	for (Rml::Element* e = element; e; e = e->GetParentNode())
	{
		if (e->HasAttribute("resize"))
			return RmlWindow::Drag::Resize;
		if (e->HasAttribute("action") || IsTextInput(e) || e->GetTagName() == "button")
			return RmlWindow::Drag::None;
		if (e->HasAttribute("drag"))
			return RmlWindow::Drag::Move;
	}
	return RmlWindow::Drag::None;
}

void HandleInput(RmlWindow* w, const ImVec2& origin, bool hovered)
{
	ImGuiIO& io = ImGui::GetIO();
	Rml::Context* ctx = w->context;
	const int mods = KeyModifiers(io);

	if (w->flags & RMLWIN_CLICKTHROUGH)
		hovered = false;

	const ImVec2 mouse = ImGui::GetMousePos();
	const int mx = (int)(mouse.x - origin.x);
	const int my = (int)(mouse.y - origin.y);

	if (hovered || w->buttonsDown)
	{
		if (mx != w->lastMouseX || my != w->lastMouseY || !w->mouseInside)
		{
			ctx->ProcessMouseMove(mx, my, mods);
			w->lastMouseX = mx;
			w->lastMouseY = my;
		}
		w->mouseInside = true;

		for (int b = 0; b < 3; ++b)
		{
			const int bit = 1 << b;
			if (hovered && ImGui::IsMouseClicked(b))
			{
				if (b == 0)
					w->drag = w->pinned ? RmlWindow::Drag::None : DragModeAt(ctx->GetHoverElement());
				ctx->ProcessMouseButtonDown(b, mods);
				w->buttonsDown |= bit;
			}
			else if ((w->buttonsDown & bit) && (ImGui::IsMouseReleased(b) || !ImGui::IsMouseDown(b)))
			{
				ctx->ProcessMouseButtonUp(b, mods);
				w->buttonsDown &= ~bit;
				if (b == 0)
					w->drag = RmlWindow::Drag::None;
			}
		}

		if (hovered && io.MouseWheel != 0.0f)
			ctx->ProcessMouseWheel(-io.MouseWheel, mods);
	}
	else if (w->mouseInside)
	{
		ctx->ProcessMouseLeave();
		w->mouseInside = false;
		w->lastMouseX = w->lastMouseY = -1;
	}

	if (w->drag != RmlWindow::Drag::None && ImGui::IsMouseDown(0))
	{
		const ImVec2 delta = io.MouseDelta;
		if (delta.x != 0.0f || delta.y != 0.0f)
		{
			if (w->drag == RmlWindow::Drag::Move)
			{
				ImGui::SetWindowPos(ImGui::GetWindowPos() + delta);
			}
			else
			{
				ImVec2 size = ImGui::GetWindowSize() + delta;
				size.x = size.x < 120.0f ? 120.0f : size.x;
				size.y = size.y < 60.0f ? 60.0f : size.y;
				ImGui::SetWindowSize(size);
			}
		}
	}

	const bool focused = ImGui::IsWindowFocused();
	if (w->document)
		w->document->SetClass("focused", focused);
	Rml::Element* focus = ctx->GetFocusElement();
	const bool typing = IsTextInput(focus);

	if (focused)
	{
		for (const KeyMap& k : kKeys)
		{
			if (ImGui::IsKeyPressed(k.imgui, true))
				ctx->ProcessKeyDown(k.rml, mods);
			if (ImGui::IsKeyReleased(k.imgui))
				ctx->ProcessKeyUp(k.rml, mods);
		}

		if (typing)
		{
			std::string text;
			for (int i = 0; i < io.InputQueueCharacters.Size; ++i)
			{
				const unsigned int c = io.InputQueueCharacters[i];
				if (c >= 32 && c != 127)
					AppendUtf8(text, c);
			}
			if (!text.empty())
				ctx->ProcessTextInput(text);
			ImGui::SetNextFrameWantCaptureKeyboard(true);
		}
	}
	else if (w->wasFocused && focus && focus != w->document)
	{
		focus->Blur();
	}
	w->wasFocused = focused;
}

void DrawWindow(RmlWindow* w)
{
	const std::string title = (w->isDebuggerHost ? std::string("RmlUi Debugger") : w->name) + "##mq2rmlui";

	if (w->hasPendingRect)
	{
		if (w->pendingX >= 0 && w->pendingY >= 0)
			ImGui::SetNextWindowPos(ImVec2(w->pendingX, w->pendingY), ImGuiCond_Always);
		if (w->pendingW > 0 && w->pendingH > 0)
			ImGui::SetNextWindowSize(ImVec2(w->pendingW, w->pendingH), ImGuiCond_Always);
		w->hasPendingRect = false;
	}
	else
	{
		if (w->defaultX >= 0 && w->defaultY >= 0)
			ImGui::SetNextWindowPos(ImVec2(w->defaultX, w->defaultY), ImGuiCond_FirstUseEver);
		ImGui::SetNextWindowSize(ImVec2(w->defaultW, w->defaultH), ImGuiCond_FirstUseEver);
	}

	if (w->toggleCollapse && w->document && w->windowSize.x > 0)
	{
		w->toggleCollapse = false;
		if (!w->collapsed)
		{
			Rml::Element* bar = w->document->GetElementById("window-titlebar");
			Rml::Element* frame = w->document->GetElementById("window-frame");
			if (bar && frame)
			{
				const float frameBottomGap = (float)w->rtH - (frame->GetAbsoluteTop() + frame->GetOffsetHeight());
				const float height = bar->GetAbsoluteTop() + bar->GetOffsetHeight() + frame->GetClientTop() + frameBottomGap;
				w->expandedHeight = w->windowSize.y;
				w->collapsed = true;
				ImGui::SetNextWindowSize(ImVec2(w->windowSize.x, height), ImGuiCond_Always);
			}
		}
		else
		{
			w->collapsed = false;
			ImGui::SetNextWindowSize(ImVec2(w->windowSize.x, w->expandedHeight), ImGuiCond_Always);
		}
		w->document->SetClass("collapsed", w->collapsed);
	}
	w->toggleCollapse = false;

	ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse
		| ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoNav;
	if (w->flags & RMLWIN_CLICKTHROUGH)
		flags |= ImGuiWindowFlags_NoInputs;

	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowMinSize, ImVec2(16, 16));
	const bool open = ImGui::Begin(title.c_str(), nullptr, flags);
	ImGui::PopStyleVar(3);

	if (open)
	{
		ImVec2 avail = ImGui::GetContentRegionAvail();
		if (avail.x < 1) avail.x = 1;
		if (avail.y < 1) avail.y = 1;
		w->wantW = (int)avail.x;
		w->wantH = (int)avail.y;
		w->windowSize = ImGui::GetWindowSize();
		w->lastShown = NowSeconds();

		const ImVec2 origin = ImGui::GetCursorScreenPos();
		if (w->rt && w->rendered)
		{
			ImDrawList* drawList = ImGui::GetWindowDrawList();
			drawList->AddCallback(SetPremultipliedBlend, nullptr);
			drawList->AddImage(ImTextureRef((ImTextureID)w->rt), origin, origin + ImVec2((float)w->rtW, (float)w->rtH));
			drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);
		}

		ImGui::InvisibleButton("##rmlsurface", avail,
			ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight | ImGuiButtonFlags_MouseButtonMiddle);
		const bool hovered = ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem);

		HandleInput(w, origin, hovered);
	}
	ImGui::End();
}

void LoadDefaultFonts()
{
	char windir[MAX_PATH] = {};
	GetWindowsDirectoryA(windir, MAX_PATH);
	const std::string fonts = std::string(windir) + "/Fonts/";

	int loaded = 0;
	for (const char* file : { "segoeui.ttf", "segoeuib.ttf", "seguisb.ttf", "segoeuii.ttf", "segoeuil.ttf" })
	{
		const std::string path = fonts + file;
		if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES && Rml::LoadFontFace(path))
			++loaded;
	}
	for (const char* file : { "seguisym.ttf", "seguiemj.ttf" })
	{
		const std::string path = fonts + file;
		if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES)
			Rml::LoadFontFace(path, true);
	}
	if (loaded == 0)
		Rml::LoadFontFace(fonts + "arial.ttf", true);

	// Window chrome glyphs use font-family "Icons": Segoe Fluent Icons (Win11) or Segoe MDL2 Assets (Win10),
	// which share code points for the glyphs the theme uses.
	for (const char* file : { "SegoeIcons.ttf", "segmdl2.ttf" })
	{
		FILE* f = fopen((fonts + file).c_str(), "rb");
		if (!f)
			continue;
		fseek(f, 0, SEEK_END);
		g_iconFontData.resize((size_t)ftell(f));
		fseek(f, 0, SEEK_SET);
		fread(g_iconFontData.data(), 1, g_iconFontData.size(), f);
		fclose(f);
		if (Rml::LoadFontFace(Rml::Span<const Rml::byte>(g_iconFontData.data(), g_iconFontData.size()), "Icons",
			Rml::Style::FontStyle::Normal, Rml::Style::FontWeight::Normal))
			break;
	}
}

void ShutdownRml()
{
	if (!g_initialized)
		return;
	g_initialized = false;

	if (g_debuggerInitialized)
	{
		Rml::Debugger::Shutdown();
		g_debuggerInitialized = false;
	}
	g_debuggerHost = nullptr;

	for (auto& [_, w] : g_windows)
	{
		UnloadDocument(w.get());
		w->ReleaseTarget();
	}
	Rml::Shutdown();
	g_windows.clear();
	g_iconFontData.clear();
}

} // namespace

// ---------------------------------------------------------------------------------------------
// MQ plugin callbacks

PLUGIN_API void InitializePlugin()
{
	Rml::SetSystemInterface(&g_system);
	Rml::SetRenderInterface(&g_render);
	if (!Rml::Initialise())
	{
		Chat("\arRmlUi failed to initialise");
		return;
	}
	LoadDefaultFonts();
	g_initialized = true;

	mq::MQRenderCallbacks callbacks;
	callbacks.CreateDeviceObjects = OnCreateDeviceObjects;
	callbacks.InvalidateDeviceObjects = OnInvalidateDeviceObjects;
	callbacks.GraphicsSceneRender = OnGraphicsSceneRender;
	g_renderCallbacksId = mq::AddRenderCallbacks(callbacks);

	Chat("RmlUi %s loaded. Try \ay/lua run rmlhud\ax", Rml::GetVersion().c_str());
}

PLUGIN_API void ShutdownPlugin()
{
	if (g_renderCallbacksId >= 0)
	{
		mq::RemoveRenderCallbacks(g_renderCallbacksId);
		g_renderCallbacksId = -1;
	}
	ShutdownRml();
	g_deviceReady = false;
	g_render.SetDevice(nullptr);
}

PLUGIN_API void OnPulse()
{
	if (!g_initialized)
		return;

	const double now = NowSeconds();
	std::vector<std::string> expired;
	for (auto& [name, w] : g_windows)
	{
		if ((w->flags & RMLWIN_AUTOCLOSE) && now - w->lastPoll > kAutoCloseSeconds)
			expired.push_back(name);
	}
	for (const std::string& name : expired)
		DestroyRmlWindow(name);
}

PLUGIN_API void OnUpdateImGui()
{
	if (!g_initialized)
		return;

	for (auto& [_, w] : g_windows)
	{
		if (w->visible && w->context && (w->document || w->isDebuggerHost))
			DrawWindow(w.get());
	}
}

// ---------------------------------------------------------------------------------------------
// Lua FFI API. All functions are safe to call when the plugin is not initialized.

PLUGIN_API int rml_api_version() { return kApiVersion; }
PLUGIN_API int rml_ready() { return g_initialized ? 1 : 0; }

PLUGIN_API int rml_open(const char* name, const char* path, int width, int height, int flags)
{
	if (!g_initialized || !name || !*name || !path)
		return 0;

	RmlWindow* w = FindRmlWindow(name);
	const std::string fullPath = NormalizePath(path);
	if (!w)
	{
		w = CreateRmlWindow(name);
		if (!w)
			return 0;
	}
	w->flags = flags;
	w->lastPoll = NowSeconds();
	w->visible = true;
	if (width > 0) w->defaultW = (float)width;
	if (height > 0) w->defaultH = (float)height;

	if (w->document && w->path == fullPath)
		return 1;

	w->path = fullPath;
	if (!LoadDocument(w))
	{
		DestroyRmlWindow(name);
		return 0;
	}
	return 1;
}

PLUGIN_API int rml_close(const char* name)
{
	if (!FindRmlWindow(name))
		return 0;
	DestroyRmlWindow(name);
	return 1;
}

PLUGIN_API int rml_reload(const char* name)
{
	RmlWindow* w = FindRmlWindow(name);
	if (!w || w->path.empty())
		return 0;
	Rml::Factory::ClearStyleSheetCache();
	Rml::Factory::ClearTemplateCache();
	return LoadDocument(w) ? 1 : 0;
}

PLUGIN_API int rml_show(const char* name, int show)
{
	RmlWindow* w = FindRmlWindow(name);
	if (!w)
		return 0;
	w->visible = show != 0;
	return 1;
}

PLUGIN_API int rml_is_open(const char* name)
{
	RmlWindow* w = FindRmlWindow(name);
	return (w && w->document) ? 1 : 0;
}

PLUGIN_API int rml_set_window(const char* name, float x, float y, float width, float height)
{
	RmlWindow* w = FindRmlWindow(name);
	if (!w)
		return 0;
	w->pendingX = x;
	w->pendingY = y;
	w->pendingW = width;
	w->pendingH = height;
	w->hasPendingRect = true;
	return 1;
}

PLUGIN_API int rml_set_default_pos(const char* name, float x, float y)
{
	RmlWindow* w = FindRmlWindow(name);
	if (!w)
		return 0;
	w->defaultX = x;
	w->defaultY = y;
	return 1;
}

PLUGIN_API int rml_set_rml(const char* window, const char* id, const char* rml)
{
	Rml::Element* e = FindElement(window, id);
	if (!e)
		return 0;
	e->SetInnerRML(rml ? rml : "");
	return 1;
}

PLUGIN_API int rml_set_text(const char* window, const char* id, const char* text)
{
	Rml::Element* e = FindElement(window, id);
	if (!e)
		return 0;
	e->SetInnerRML(EscapeRml(text));
	return 1;
}

PLUGIN_API int rml_set_attr(const char* window, const char* id, const char* attr, const char* value)
{
	Rml::Element* e = FindElement(window, id);
	if (!e || !attr)
		return 0;
	if (value)
		e->SetAttribute(attr, Rml::String(value));
	else
		e->RemoveAttribute(attr);
	return 1;
}

PLUGIN_API int rml_set_class(const char* window, const char* id, const char* cls, int on)
{
	Rml::Element* e = FindElement(window, id);
	if (!e || !cls)
		return 0;
	e->SetClass(cls, on != 0);
	return 1;
}

PLUGIN_API int rml_set_style(const char* window, const char* id, const char* property, const char* value)
{
	Rml::Element* e = FindElement(window, id);
	if (!e || !property)
		return 0;
	if (!value || !*value)
	{
		e->RemoveProperty(property);
		return 1;
	}
	return e->SetProperty(property, value) ? 1 : 0;
}

PLUGIN_API int rml_set_value(const char* window, const char* id, const char* value)
{
	Rml::Element* e = FindElement(window, id);
	auto* control = dynamic_cast<Rml::ElementFormControl*>(e);
	if (!control)
		return 0;
	control->SetValue(value ? value : "");
	return 1;
}

PLUGIN_API const char* rml_get_value(const char* window, const char* id)
{
	Rml::Element* e = FindElement(window, id);
	if (!e)
		return nullptr;
	if (auto* control = dynamic_cast<Rml::ElementFormControl*>(e))
		g_returnBuffer = control->GetValue();
	else
		g_returnBuffer = e->GetInnerRML();
	return g_returnBuffer.c_str();
}

// Returns the next queued event as "type\tid\taction\tvalue\tbutton", or NULL. Also serves as the
// owner heartbeat for RMLWIN_AUTOCLOSE windows.
PLUGIN_API const char* rml_poll(const char* name)
{
	RmlWindow* w = FindRmlWindow(name);
	if (!w)
		return nullptr;
	w->lastPoll = NowSeconds();
	if (w->events.empty())
		return nullptr;
	g_returnBuffer = std::move(w->events.front());
	w->events.pop_front();
	return g_returnBuffer.c_str();
}

PLUGIN_API int rml_load_font(const char* path, int fallback)
{
	if (!g_initialized || !path)
		return 0;
	return Rml::LoadFontFace(NormalizePath(path), fallback != 0) ? 1 : 0;
}

PLUGIN_API int rml_debugger(const char* name, int show)
{
	if (!g_initialized)
		return 0;

	if (!g_debuggerHost)
	{
		g_debuggerHost = CreateRmlWindow("__rmlui_debugger");
		if (!g_debuggerHost)
			return 0;
		g_debuggerHost->isDebuggerHost = true;
		g_debuggerHost->defaultW = 1000;
		g_debuggerHost->defaultH = 700;
		g_debuggerInitialized = Rml::Debugger::Initialise(g_debuggerHost->context);
	}
	if (!g_debuggerInitialized)
		return 0;

	RmlWindow* target = FindRmlWindow(name);
	Rml::Debugger::SetContext(target ? target->context : g_debuggerHost->context);
	Rml::Debugger::SetVisible(show != 0);
	g_debuggerHost->visible = show != 0;
	return 1;
}
