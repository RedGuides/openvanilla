#pragma once

#include <RmlUi/Core/RenderInterface.h>
#include <RmlUi/Core/Types.h>
#include <d3d9.h>
#include <cstdint>
#include <vector>

// Fixed-function Direct3D 9 backend for RmlUi 6.
// Supports geometry, textures, scissoring, stencil clip masks and CSS transforms.
// Layers, filters and shaders (box-shadow, linear-gradient(), filter:) are not implemented.
class RenderInterface_DX9 : public Rml::RenderInterface
{
public:
	void SetDevice(IDirect3DDevice9* device) { m_device = device; }
	IDirect3DDevice9* GetDevice() const { return m_device; }

	// Sets up device state for drawing into the currently bound render target of the given size.
	// The bound depth-stencil surface must have a stencil channel and be at least as large.
	void BeginFrame(int width, int height);
	void EndFrame();

	Rml::CompiledGeometryHandle CompileGeometry(Rml::Span<const Rml::Vertex> vertices, Rml::Span<const int> indices) override;
	void RenderGeometry(Rml::CompiledGeometryHandle geometry, Rml::Vector2f translation, Rml::TextureHandle texture) override;
	void ReleaseGeometry(Rml::CompiledGeometryHandle geometry) override;

	Rml::TextureHandle LoadTexture(Rml::Vector2i& texture_dimensions, const Rml::String& source) override;
	Rml::TextureHandle GenerateTexture(Rml::Span<const Rml::byte> source, Rml::Vector2i source_dimensions) override;
	void ReleaseTexture(Rml::TextureHandle texture) override;

	void EnableScissorRegion(bool enable) override;
	void SetScissorRegion(Rml::Rectanglei region) override;

	void EnableClipMask(bool enable) override;
	void RenderToClipMask(Rml::ClipMaskOperation operation, Rml::CompiledGeometryHandle geometry, Rml::Vector2f translation) override;

	void SetTransform(const Rml::Matrix4f* transform) override;

private:
	struct Vertex
	{
		float x, y, z;
		D3DCOLOR color;
		float u, v;
	};
	static constexpr DWORD kFVF = D3DFVF_XYZ | D3DFVF_DIFFUSE | D3DFVF_TEX1;

	struct Geometry
	{
		std::vector<Vertex> vertices;
		std::vector<uint16_t> indices16;
		std::vector<uint32_t> indices32;
	};

	IDirect3DTexture9* CreateTextureBGRA(const uint8_t* rgba, int width, int height, bool premultiply);
	void ApplyWorld(Rml::Vector2f translation);
	void DrawGeometry(const Geometry* geometry);

	IDirect3DDevice9* m_device = nullptr;
	D3DMATRIX m_projection = {};
	D3DMATRIX m_transform = {};
	bool m_hasTransform = false;
	bool m_inFrame = false;
	int m_width = 0;
	int m_height = 0;
	DWORD m_stencilTestValue = 0;
};
