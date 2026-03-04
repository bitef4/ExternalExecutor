#pragma once
#include <Windows.h>

namespace Offsets {
	const uintptr_t EnableLoadModule = 0x7811c08;

	inline constexpr uintptr_t FakeDataModelPointer = 0x7E83168;
	inline constexpr uintptr_t FakeDataModelToDataModel = 0x1C0;

	inline constexpr uintptr_t Children = 0x70;
	inline constexpr uintptr_t ChildrenEnd = 0x8;
	inline constexpr uintptr_t Name = 0xB0;
	inline constexpr uintptr_t Value = 0xD0;

	inline constexpr uintptr_t ClassDescriptor = 0x18;
	inline constexpr uintptr_t ClassDescriptorToClassName = 0x8;

	inline constexpr uintptr_t LocalScriptByteCode = 0x1A8;
	inline constexpr uintptr_t LocalScriptHash = 0xE8;
	inline constexpr uintptr_t ModuleScriptByteCode = 0x150;
	inline constexpr uintptr_t ModuleScriptHash = 0xE8;
}