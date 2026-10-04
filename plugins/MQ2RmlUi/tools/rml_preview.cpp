// Offline preview: renders an RML document through RenderInterface_DX9 on a private D3D9 device and
// writes PNG frames, composited over a backdrop like the game scene would be.
//
//   rml_preview <doc.rml> <out-prefix> [width height] [commands...]
//     text:id=value   style:id:prop=value   class:id:name   unclass:id:name
//     mouse:x,y       down / up (left button)   wait:seconds   shot:name

#include "RenderInterface_DX9.h"

#include <RmlUi/Core.h>

#include <windows.h>
#include <objidl.h>
#include <algorithm>
namespace Gdiplus { using std::min; using std::max; }
#include <gdiplus.h>

#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "gdiplus.lib")

static double g_clock = 0.0;

class PreviewSystem : public Rml::SystemInterface
{
public:
	double GetElapsedTime() override { return g_clock; }
	bool LogMessage(Rml::Log::Type type, const Rml::String& message) override
	{
		const char* tag = type == Rml::Log::LT_ERROR ? "ERROR" : type == Rml::Log::LT_WARNING ? "WARN" : type == Rml::Log::LT_ASSERT ? "ASSERT" : "info";
		if (type <= Rml::Log::LT_WARNING)
			std::printf("[%s] %s\n", tag, message.c_str());
		return true;
	}
};

static int PngEncoderClsid(CLSID* clsid)
{
	UINT num = 0, size = 0;
	Gdiplus::GetImageEncodersSize(&num, &size);
	std::vector<BYTE> buffer(size);
	auto* info = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buffer.data());
	Gdiplus::GetImageEncoders(num, size, info);
	for (UINT i = 0; i < num; ++i)
		if (wcscmp(info[i].MimeType, L"image/png") == 0) { *clsid = info[i].Clsid; return 0; }
	return -1;
}

static bool SavePng(IDirect3DDevice9* device, IDirect3DSurface9* rt, int w, int h, const std::string& path)
{
	IDirect3DSurface9* sys = nullptr;
	if (FAILED(device->CreateOffscreenPlainSurface(w, h, D3DFMT_A8R8G8B8, D3DPOOL_SYSTEMMEM, &sys, nullptr)))
		return false;
	device->GetRenderTargetData(rt, sys);

	D3DLOCKED_RECT lr;
	sys->LockRect(&lr, nullptr, D3DLOCK_READONLY);

	const int pad = 24;
	const int W = w + pad * 2, H = h + pad * 2;
	Gdiplus::Bitmap bmp(W, H, PixelFormat32bppARGB);
	for (int y = 0; y < H; ++y)
	{
		for (int x = 0; x < W; ++x)
		{
			// Backdrop: muted "zone" gradient with a checker so translucency is visible.
			int br = 46 + (y * 30) / H, bg = 62 + (x * 20) / W, bb = 52;
			if (((x / 16) + (y / 16)) % 2) { br += 8; bg += 8; bb += 8; }
			int r = br, g = bg, b = bb;
			const int sx = x - pad, sy = y - pad;
			if (sx >= 0 && sy >= 0 && sx < w && sy < h)
			{
				const uint8_t* p = static_cast<uint8_t*>(lr.pBits) + sy * lr.Pitch + sx * 4;
				const int a = p[3];
				b = p[0] + (bb * (255 - a)) / 255;
				g = p[1] + (bg * (255 - a)) / 255;
				r = p[2] + (br * (255 - a)) / 255;
				r = r > 255 ? 255 : r; g = g > 255 ? 255 : g; b = b > 255 ? 255 : b;
			}
			bmp.SetPixel(x, y, Gdiplus::Color(255, (BYTE)r, (BYTE)g, (BYTE)b));
		}
	}
	sys->UnlockRect();
	sys->Release();

	CLSID clsid;
	if (PngEncoderClsid(&clsid) != 0)
		return false;
	std::wstring wpath(path.begin(), path.end());
	return bmp.Save(wpath.c_str(), &clsid, nullptr) == Gdiplus::Ok;
}

int main(int argc, char** argv)
{
	if (argc < 3)
	{
		std::printf("usage: rml_preview <doc.rml> <out-prefix> [width height] [commands...]\n");
		return 1;
	}
	const std::string docPath = argv[1];
	const std::string outPrefix = argv[2];
	int width = 340, height = 360, argi = 3;
	if (argc > 4 && isdigit((unsigned char)argv[3][0]))
	{
		width = atoi(argv[3]);
		height = atoi(argv[4]);
		argi = 5;
	}

	Gdiplus::GdiplusStartupInput gsi;
	ULONG_PTR gdiToken;
	Gdiplus::GdiplusStartup(&gdiToken, &gsi, nullptr);

	HWND hwnd = CreateWindowA("STATIC", "rml_preview", WS_OVERLAPPEDWINDOW, 0, 0, 64, 64, nullptr, nullptr, nullptr, nullptr);
	IDirect3D9* d3d = Direct3DCreate9(D3D_SDK_VERSION);
	D3DPRESENT_PARAMETERS pp = {};
	pp.Windowed = TRUE;
	pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
	pp.BackBufferFormat = D3DFMT_UNKNOWN;
	pp.hDeviceWindow = hwnd;
	IDirect3DDevice9* device = nullptr;
	if (FAILED(d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &pp, &device)))
	{
		std::printf("CreateDevice failed\n");
		return 2;
	}

	IDirect3DTexture9* rt = nullptr;
	IDirect3DSurface9* rtSurface = nullptr;
	IDirect3DSurface9* depth = nullptr;
	device->CreateTexture(width, height, 1, D3DUSAGE_RENDERTARGET, D3DFMT_A8R8G8B8, D3DPOOL_DEFAULT, &rt, nullptr);
	rt->GetSurfaceLevel(0, &rtSurface);
	device->CreateDepthStencilSurface(width, height, D3DFMT_D24S8, D3DMULTISAMPLE_NONE, 0, TRUE, &depth, nullptr);

	PreviewSystem system;
	RenderInterface_DX9 render;
	render.SetDevice(device);
	Rml::SetSystemInterface(&system);
	Rml::SetRenderInterface(&render);
	Rml::Initialise();

	char windir[MAX_PATH];
	GetWindowsDirectoryA(windir, MAX_PATH);
	for (const char* f : { "segoeui.ttf", "segoeuib.ttf", "seguisb.ttf", "segoeuii.ttf", "segoeuil.ttf" })
		Rml::LoadFontFace(std::string(windir) + "/Fonts/" + f);
	Rml::LoadFontFace(std::string(windir) + "/Fonts/seguisym.ttf", true);
	std::vector<Rml::byte> icons;
	if (FILE* f = fopen((std::string(windir) + "/Fonts/SegoeIcons.ttf").c_str(), "rb"))
	{
		fseek(f, 0, SEEK_END);
		icons.resize((size_t)ftell(f));
		fseek(f, 0, SEEK_SET);
		fread(icons.data(), 1, icons.size(), f);
		fclose(f);
		Rml::LoadFontFace(Rml::Span<const Rml::byte>(icons.data(), icons.size()), "Icons", Rml::Style::FontStyle::Normal, Rml::Style::FontWeight::Normal);
	}

	Rml::Context* ctx = Rml::CreateContext("preview", { width, height });
	Rml::ElementDocument* doc = ctx->LoadDocument(docPath);
	if (!doc)
	{
		std::printf("failed to load %s\n", docPath.c_str());
		return 3;
	}
	if (auto* title = doc->GetElementById("window-title"))
		title->SetInnerRML(doc->GetTitle());
	doc->Show();

	auto byId = [&](const std::string& id) -> Rml::Element* { return id == "body" ? doc : doc->GetElementById(id); };

	auto frame = [&]() {
		ctx->Update();
		device->BeginScene();
		device->SetRenderTarget(0, rtSurface);
		device->SetDepthStencilSurface(depth);
		render.BeginFrame(width, height);
		ctx->Render();
		render.EndFrame();
		device->EndScene();
	};
	auto advance = [&](double seconds) {
		const double end = g_clock + seconds;
		while (g_clock < end) { g_clock += 1.0 / 60.0; frame(); }
	};

	int shots = 0;
	auto shot = [&](const std::string& name) {
		frame();
		const std::string path = outPrefix + "_" + name + ".png";
		std::printf("%s %s\n", SavePng(device, rtSurface, width, height, path) ? "wrote" : "FAILED", path.c_str());
		++shots;
	};

	advance(0.1);
	for (int i = argi; i < argc; ++i)
	{
		std::string cmd = argv[i];
		auto after = [&](const char* prefix) { return cmd.substr(strlen(prefix)); };
		if (cmd.rfind("text:", 0) == 0)
		{
			std::string rest = after("text:");
			size_t eq = rest.find('=');
			if (auto* e = byId(rest.substr(0, eq))) e->SetInnerRML(rest.substr(eq + 1));
			else std::printf("no element %s\n", rest.substr(0, eq).c_str());
		}
		else if (cmd.rfind("style:", 0) == 0)
		{
			std::string rest = after("style:");
			size_t c = rest.find(':'), eq = rest.find('=');
			if (auto* e = byId(rest.substr(0, c)))
			{
				if (!e->SetProperty(rest.substr(c + 1, eq - c - 1), rest.substr(eq + 1)))
					std::printf("bad property %s\n", rest.c_str());
			}
		}
		else if (cmd.rfind("class:", 0) == 0 || cmd.rfind("unclass:", 0) == 0)
		{
			const bool on = cmd[0] == 'c';
			std::string rest = cmd.substr(on ? 6 : 8);
			size_t c = rest.find(':');
			if (auto* e = byId(rest.substr(0, c))) e->SetClass(rest.substr(c + 1), on);
		}
		else if (cmd.rfind("mouse:", 0) == 0)
		{
			int x = 0, y = 0;
			sscanf_s(after("mouse:").c_str(), "%d,%d", &x, &y);
			ctx->ProcessMouseMove(x, y, 0);
		}
		else if (cmd == "down") ctx->ProcessMouseButtonDown(0, 0);
		else if (cmd == "up") ctx->ProcessMouseButtonUp(0, 0);
		else if (cmd.rfind("wait:", 0) == 0) advance(atof(after("wait:").c_str()));
		else if (cmd.rfind("shot:", 0) == 0) shot(after("shot:"));
	}
	if (shots == 0)
		shot("final");

	Rml::Shutdown();
	depth->Release();
	rtSurface->Release();
	rt->Release();
	device->Release();
	d3d->Release();
	Gdiplus::GdiplusShutdown(gdiToken);
	return 0;
}
