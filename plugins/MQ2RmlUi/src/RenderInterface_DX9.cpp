#include "RenderInterface_DX9.h"

#include <RmlUi/Core/Core.h>
#include <RmlUi/Core/FileInterface.h>
#include <RmlUi/Core/Log.h>

#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_STDIO
#define STBI_ONLY_PNG
#define STBI_ONLY_JPEG
#define STBI_ONLY_TGA
#define STBI_ONLY_BMP
#include "stb_image.h"

#include <cstring>

namespace {

D3DMATRIX Identity()
{
	D3DMATRIX m = {};
	m._11 = m._22 = m._33 = m._44 = 1.0f;
	return m;
}

D3DMATRIX Multiply(const D3DMATRIX& a, const D3DMATRIX& b)
{
	D3DMATRIX r;
	for (int i = 0; i < 4; ++i)
		for (int j = 0; j < 4; ++j)
			r.m[i][j] = a.m[i][0] * b.m[0][j] + a.m[i][1] * b.m[1][j] + a.m[i][2] * b.m[2][j] + a.m[i][3] * b.m[3][j];
	return r;
}

} // namespace

void RenderInterface_DX9::BeginFrame(int width, int height)
{
	m_width = width;
	m_height = height;
	m_inFrame = m_device != nullptr;
	if (!m_inFrame)
		return;

	IDirect3DDevice9* d = m_device;

	D3DVIEWPORT9 vp = { 0, 0, (DWORD)width, (DWORD)height, 0.0f, 1.0f };
	d->SetViewport(&vp);

	d->SetPixelShader(nullptr);
	d->SetVertexShader(nullptr);
	d->SetFVF(kFVF);

	d->SetRenderState(D3DRS_FILLMODE, D3DFILL_SOLID);
	d->SetRenderState(D3DRS_SHADEMODE, D3DSHADE_GOURAUD);
	d->SetRenderState(D3DRS_ZENABLE, FALSE);
	d->SetRenderState(D3DRS_ZWRITEENABLE, FALSE);
	d->SetRenderState(D3DRS_ALPHATESTENABLE, FALSE);
	d->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
	d->SetRenderState(D3DRS_LIGHTING, FALSE);
	d->SetRenderState(D3DRS_FOGENABLE, FALSE);
	d->SetRenderState(D3DRS_RANGEFOGENABLE, FALSE);
	d->SetRenderState(D3DRS_SPECULARENABLE, FALSE);
	d->SetRenderState(D3DRS_CLIPPING, TRUE);
	d->SetRenderState(D3DRS_CLIPPLANEENABLE, 0);
	d->SetRenderState(D3DRS_COLORVERTEX, TRUE);
	d->SetRenderState(D3DRS_DIFFUSEMATERIALSOURCE, D3DMCS_COLOR1);
	d->SetRenderState(D3DRS_VERTEXBLEND, D3DVBF_DISABLE);
	d->SetRenderState(D3DRS_INDEXEDVERTEXBLENDENABLE, FALSE);
	d->SetRenderState(D3DRS_SRGBWRITEENABLE, FALSE);
	d->SetRenderState(D3DRS_MULTISAMPLEANTIALIAS, FALSE);
	d->SetRenderState(D3DRS_ANTIALIASEDLINEENABLE, FALSE);
	d->SetRenderState(D3DRS_DITHERENABLE, FALSE);
	d->SetRenderState(D3DRS_COLORWRITEENABLE, 0xF);

	// RmlUi 6 works in premultiplied alpha.
	d->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE);
	d->SetRenderState(D3DRS_SEPARATEALPHABLENDENABLE, FALSE);
	d->SetRenderState(D3DRS_BLENDOP, D3DBLENDOP_ADD);
	d->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_ONE);
	d->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);

	d->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
	d->SetRenderState(D3DRS_STENCILENABLE, FALSE);
	d->SetRenderState(D3DRS_TWOSIDEDSTENCILMODE, FALSE);
	d->SetRenderState(D3DRS_STENCILMASK, 0xFF);
	d->SetRenderState(D3DRS_STENCILWRITEMASK, 0xFF);

	d->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
	d->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
	d->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
	d->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
	d->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
	d->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
	d->SetTextureStageState(0, D3DTSS_TEXCOORDINDEX, 0);
	d->SetTextureStageState(0, D3DTSS_TEXTURETRANSFORMFLAGS, D3DTTFF_DISABLE);
	d->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_DISABLE);
	d->SetTextureStageState(1, D3DTSS_ALPHAOP, D3DTOP_DISABLE);

	d->SetSamplerState(0, D3DSAMP_MINFILTER, D3DTEXF_LINEAR);
	d->SetSamplerState(0, D3DSAMP_MAGFILTER, D3DTEXF_LINEAR);
	d->SetSamplerState(0, D3DSAMP_MIPFILTER, D3DTEXF_NONE);
	d->SetSamplerState(0, D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP);
	d->SetSamplerState(0, D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP);
	d->SetSamplerState(0, D3DSAMP_SRGBTEXTURE, FALSE);

	// Pixel-space orthographic projection, y down, with the D3D9 half-pixel offset.
	const float w = (float)width;
	const float h = (float)height;
	m_projection = {};
	m_projection._11 = 2.0f / w;
	m_projection._22 = -2.0f / h;
	m_projection._33 = 1.0f / 20000.0f;
	m_projection._41 = -1.0f - 1.0f / w;
	m_projection._42 = 1.0f + 1.0f / h;
	m_projection._43 = 0.5f;
	m_projection._44 = 1.0f;

	const D3DMATRIX identity = Identity();
	d->SetTransform(D3DTS_VIEW, &identity);
	d->SetTransform(D3DTS_PROJECTION, &m_projection);
	d->SetTransform(D3DTS_WORLD, &identity);

	m_hasTransform = false;
	m_stencilTestValue = 0;

	d->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_STENCIL, D3DCOLOR_ARGB(0, 0, 0, 0), 1.0f, 0);
}

void RenderInterface_DX9::EndFrame()
{
	m_inFrame = false;
}

Rml::CompiledGeometryHandle RenderInterface_DX9::CompileGeometry(Rml::Span<const Rml::Vertex> vertices, Rml::Span<const int> indices)
{
	auto* geometry = new Geometry();
	geometry->vertices.resize(vertices.size());
	for (size_t i = 0; i < vertices.size(); ++i)
	{
		const Rml::Vertex& src = vertices[i];
		Vertex& dst = geometry->vertices[i];
		dst.x = src.position.x;
		dst.y = src.position.y;
		dst.z = 0.0f;
		dst.color = D3DCOLOR_ARGB(src.colour.alpha, src.colour.red, src.colour.green, src.colour.blue);
		dst.u = src.tex_coord.x;
		dst.v = src.tex_coord.y;
	}

	if (vertices.size() <= 0xFFFF)
	{
		geometry->indices16.resize(indices.size());
		for (size_t i = 0; i < indices.size(); ++i)
			geometry->indices16[i] = (uint16_t)indices[i];
	}
	else
	{
		geometry->indices32.assign(indices.begin(), indices.end());
	}

	return reinterpret_cast<Rml::CompiledGeometryHandle>(geometry);
}

void RenderInterface_DX9::ReleaseGeometry(Rml::CompiledGeometryHandle geometry)
{
	delete reinterpret_cast<Geometry*>(geometry);
}

void RenderInterface_DX9::ApplyWorld(Rml::Vector2f translation)
{
	D3DMATRIX world = Identity();
	world._41 = translation.x;
	world._42 = translation.y;
	if (m_hasTransform)
		world = Multiply(world, m_transform);
	m_device->SetTransform(D3DTS_WORLD, &world);
}

void RenderInterface_DX9::DrawGeometry(const Geometry* geometry)
{
	const UINT numVertices = (UINT)geometry->vertices.size();
	if (!geometry->indices16.empty())
	{
		m_device->DrawIndexedPrimitiveUP(D3DPT_TRIANGLELIST, 0, numVertices, (UINT)geometry->indices16.size() / 3,
			geometry->indices16.data(), D3DFMT_INDEX16, geometry->vertices.data(), sizeof(Vertex));
	}
	else if (!geometry->indices32.empty())
	{
		m_device->DrawIndexedPrimitiveUP(D3DPT_TRIANGLELIST, 0, numVertices, (UINT)geometry->indices32.size() / 3,
			geometry->indices32.data(), D3DFMT_INDEX32, geometry->vertices.data(), sizeof(Vertex));
	}
}

void RenderInterface_DX9::RenderGeometry(Rml::CompiledGeometryHandle handle, Rml::Vector2f translation, Rml::TextureHandle texture)
{
	if (!m_inFrame || !handle)
		return;

	ApplyWorld(translation);

	auto* tex = reinterpret_cast<IDirect3DTexture9*>(texture);
	m_device->SetTexture(0, tex);
	if (tex)
	{
		m_device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
		m_device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
	}
	else
	{
		m_device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_SELECTARG2);
		m_device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG2);
	}

	DrawGeometry(reinterpret_cast<const Geometry*>(handle));
}

IDirect3DTexture9* RenderInterface_DX9::CreateTextureBGRA(const uint8_t* rgba, int width, int height, bool premultiply)
{
	if (!m_device || width <= 0 || height <= 0)
		return nullptr;

	IDirect3DTexture9* texture = nullptr;
	if (FAILED(m_device->CreateTexture(width, height, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED, &texture, nullptr)))
		return nullptr;

	D3DLOCKED_RECT locked;
	if (FAILED(texture->LockRect(0, &locked, nullptr, 0)))
	{
		texture->Release();
		return nullptr;
	}

	for (int y = 0; y < height; ++y)
	{
		const uint8_t* src = rgba + (size_t)y * width * 4;
		uint8_t* dst = static_cast<uint8_t*>(locked.pBits) + (size_t)y * locked.Pitch;
		for (int x = 0; x < width; ++x, src += 4, dst += 4)
		{
			const uint8_t a = src[3];
			if (premultiply)
			{
				dst[0] = (uint8_t)((src[2] * a + 127) / 255);
				dst[1] = (uint8_t)((src[1] * a + 127) / 255);
				dst[2] = (uint8_t)((src[0] * a + 127) / 255);
			}
			else
			{
				dst[0] = src[2];
				dst[1] = src[1];
				dst[2] = src[0];
			}
			dst[3] = a;
		}
	}

	texture->UnlockRect(0);
	return texture;
}

Rml::TextureHandle RenderInterface_DX9::LoadTexture(Rml::Vector2i& texture_dimensions, const Rml::String& source)
{
	Rml::FileInterface* files = Rml::GetFileInterface();
	Rml::FileHandle file = files->Open(source);
	if (!file)
	{
		Rml::Log::Message(Rml::Log::LT_WARNING, "Could not open image '%s'", source.c_str());
		return 0;
	}

	const size_t size = files->Length(file);
	std::vector<stbi_uc> bytes(size);
	files->Read(bytes.data(), size, file);
	files->Close(file);

	int width = 0, height = 0, channels = 0;
	stbi_uc* pixels = stbi_load_from_memory(bytes.data(), (int)bytes.size(), &width, &height, &channels, 4);
	if (!pixels)
	{
		Rml::Log::Message(Rml::Log::LT_WARNING, "Could not decode image '%s': %s", source.c_str(), stbi_failure_reason());
		return 0;
	}

	IDirect3DTexture9* texture = CreateTextureBGRA(pixels, width, height, true);
	stbi_image_free(pixels);
	if (!texture)
		return 0;

	texture_dimensions = { width, height };
	return reinterpret_cast<Rml::TextureHandle>(texture);
}

Rml::TextureHandle RenderInterface_DX9::GenerateTexture(Rml::Span<const Rml::byte> source, Rml::Vector2i dimensions)
{
	IDirect3DTexture9* texture = CreateTextureBGRA(source.data(), dimensions.x, dimensions.y, false);
	return reinterpret_cast<Rml::TextureHandle>(texture);
}

void RenderInterface_DX9::ReleaseTexture(Rml::TextureHandle handle)
{
	if (auto* texture = reinterpret_cast<IDirect3DTexture9*>(handle))
		texture->Release();
}

void RenderInterface_DX9::EnableScissorRegion(bool enable)
{
	if (m_inFrame)
		m_device->SetRenderState(D3DRS_SCISSORTESTENABLE, enable ? TRUE : FALSE);
}

void RenderInterface_DX9::SetScissorRegion(Rml::Rectanglei region)
{
	if (!m_inFrame)
		return;

	RECT rect;
	rect.left = Rml::Math::Clamp(region.Left(), 0, m_width);
	rect.top = Rml::Math::Clamp(region.Top(), 0, m_height);
	rect.right = Rml::Math::Clamp(region.Right(), 0, m_width);
	rect.bottom = Rml::Math::Clamp(region.Bottom(), 0, m_height);
	m_device->SetScissorRect(&rect);
}

void RenderInterface_DX9::EnableClipMask(bool enable)
{
	if (m_inFrame)
		m_device->SetRenderState(D3DRS_STENCILENABLE, enable ? TRUE : FALSE);
}

void RenderInterface_DX9::RenderToClipMask(Rml::ClipMaskOperation operation, Rml::CompiledGeometryHandle geometry, Rml::Vector2f translation)
{
	if (!m_inFrame || !geometry)
		return;

	IDirect3DDevice9* d = m_device;

	const bool clear = operation == Rml::ClipMaskOperation::Set || operation == Rml::ClipMaskOperation::SetInverse;
	if (clear)
		d->Clear(0, nullptr, D3DCLEAR_STENCIL, 0, 1.0f, operation == Rml::ClipMaskOperation::SetInverse ? 1 : 0);

	d->SetRenderState(D3DRS_STENCILENABLE, TRUE);
	d->SetRenderState(D3DRS_COLORWRITEENABLE, 0);
	d->SetRenderState(D3DRS_STENCILFUNC, D3DCMP_ALWAYS);
	d->SetRenderState(D3DRS_STENCILFAIL, D3DSTENCILOP_KEEP);
	d->SetRenderState(D3DRS_STENCILZFAIL, D3DSTENCILOP_KEEP);

	switch (operation)
	{
	case Rml::ClipMaskOperation::Set:
		d->SetRenderState(D3DRS_STENCILREF, 1);
		d->SetRenderState(D3DRS_STENCILPASS, D3DSTENCILOP_REPLACE);
		m_stencilTestValue = 1;
		break;
	case Rml::ClipMaskOperation::SetInverse:
		d->SetRenderState(D3DRS_STENCILREF, 0);
		d->SetRenderState(D3DRS_STENCILPASS, D3DSTENCILOP_REPLACE);
		m_stencilTestValue = 1;
		break;
	case Rml::ClipMaskOperation::Intersect:
		d->SetRenderState(D3DRS_STENCILPASS, D3DSTENCILOP_INCRSAT);
		m_stencilTestValue += 1;
		break;
	}

	ApplyWorld(translation);
	d->SetTexture(0, nullptr);
	d->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_SELECTARG2);
	d->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG2);
	DrawGeometry(reinterpret_cast<const Geometry*>(geometry));

	d->SetRenderState(D3DRS_COLORWRITEENABLE, 0xF);
	d->SetRenderState(D3DRS_STENCILFUNC, D3DCMP_EQUAL);
	d->SetRenderState(D3DRS_STENCILREF, m_stencilTestValue);
	d->SetRenderState(D3DRS_STENCILPASS, D3DSTENCILOP_KEEP);
}

void RenderInterface_DX9::SetTransform(const Rml::Matrix4f* transform)
{
	m_hasTransform = transform != nullptr;
	if (transform)
	{
		// RmlUi stores column-major matrices for column vectors; that memory layout is exactly the
		// row-major, row-vector D3DMATRIX of the same transform.
		static_assert(sizeof(D3DMATRIX) == sizeof(float) * 16, "matrix size");
		std::memcpy(&m_transform, transform->data(), sizeof(D3DMATRIX));
	}
}
