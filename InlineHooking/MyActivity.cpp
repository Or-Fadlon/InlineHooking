#include "pch.h"
#include "MyActivity.h"
#include <Windows.h>
#include <iostream>
#include <stdio.h>

using namespace std;

///// ***Change base on function to hook***

// Library of function to hook
const char lib[] = "kernel32.dll";
// Name of function to hook
const char functionName[] = "OutputDebugStringA";
// Signature of function to hook
// Original function: void OutputDebugStringA([in, optional] LPCSTR lpOutputString);
typedef void (WINAPI* OriginalFunctionSignature)(LPCSTR lpOutputString);
// Number of bytes to copy from the beginning of the function
const int numOfBytesToCopy = 6;

///// ***Change base on function to hook***

OriginalFunctionSignature FunctionTrampoline;
BYTE* trampoline;
const int trampolineSize = 30;

void WINAPI MyOutputDebugString(LPCSTR lpOutputString)
{
	printf("[Fadlon] MyOutputDebugString: '%s'\n", lpOutputString);
	lpOutputString = "HOOKED!";
	return FunctionTrampoline(lpOutputString);
}


bool Error(const char* msg)
{
	printf("[Fadlon] Error: %s (%u)\n", msg, GetLastError());
	return false;
}

void PrintHex(char* data, int dataSize, char* name)
{
	printf("[Fadlon] %s: '", name);
	for (int i = 0; i < dataSize; i++)
	{
		printf("%hhx ", data[i]);
	}
	printf("'\n");
}

bool BuildTrampoline(const OriginalFunctionSignature origFunctionAddress)
{
	trampoline = (BYTE*)VirtualAlloc(nullptr, trampolineSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (trampoline == nullptr) return Error("Failed to allocate memory for trampoline");
	memcpy(trampoline, origFunctionAddress, numOfBytesToCopy);

	printf("[Fadlon] trampoline - '%lx'\n", trampoline);
	PrintHex((char*)trampoline, trampolineSize, (char*)"trampoline");

	trampoline[numOfBytesToCopy] = 0xE9;
	uintptr_t trampolineToOriginalAddress = (BYTE*)origFunctionAddress - trampoline - numOfBytesToCopy;
	*(uintptr_t*)((uintptr_t)trampoline + numOfBytesToCopy + 1) = trampolineToOriginalAddress;

	printf("[Fadlon] trampoline - '%lx'\n", trampoline);
	PrintHex((char*)trampoline, trampolineSize, (char*)"trampoline");

	return true;
}

OriginalFunctionSignature GetOriginalFunctionAdress(const char* lib, const char* functionName)
{
	// Locate original function address
	const HMODULE hModule = GetModuleHandleA(lib);
	if (hModule == nullptr)
	{
		printf("[Fadlon] Error!: Can't find '%s' module (%u)\n", lib, GetLastError());
		return nullptr;
	}
	OriginalFunctionSignature origFunctionAddress = (OriginalFunctionSignature)GetProcAddress(hModule, functionName);
	if (origFunctionAddress == nullptr)
	{
		printf("[Fadlon] Error!: Can't find '%s' function (%u)\n", functionName, GetLastError());
		return nullptr;
	}
}

bool InlineHook()
{
	OriginalFunctionSignature origFunctionAddress = GetOriginalFunctionAdress(lib, functionName);

	printf("[Fadlon] origFunctionAddress - '%lx'\n", origFunctionAddress);
	PrintHex((char*)*origFunctionAddress, 15, (char*)"origFunctionAddress");

	// Build the trampoline
	if (!BuildTrampoline(origFunctionAddress))
	{
		printf("[Fadlon] Error!: BuildTrampoline (%u)\n", GetLastError());
		return false;
	}

	// Calculate the relative address to JMP to the Hook function
	intptr_t hookRelativeAddress = (BYTE*)MyOutputDebugString - (BYTE*)origFunctionAddress - 5;

	// **Patch the original function**
	// Change memory protection on original function to make sure it is writable
	const int vpSize = 6;
	DWORD oldProtectVal;
	VirtualProtect(origFunctionAddress, vpSize, PAGE_READWRITE, &oldProtectVal);
	// Replace the first BYTE with a JMP instruction
	*(BYTE*)origFunctionAddress = 0xE9;
	// Replace other BYTEs with relative address to my hook function
	*(intptr_t*)((intptr_t)origFunctionAddress + 1) = hookRelativeAddress;
	// Restore original memory protection on original function
	VirtualProtect(origFunctionAddress, vpSize, oldProtectVal, &oldProtectVal);

	// Cast the trampoline address to a function 
	FunctionTrampoline = (OriginalFunctionSignature)trampoline;

	printf("[Fadlon] Done\n");

	return true;
}

//	UnHook!
int UnHook()
{
	OriginalFunctionSignature origFunctionAddress = GetOriginalFunctionAdress(lib, functionName);
	// **Patch the original function**
	// Change memory protection on original function to make sure it is writable
	const int vpSize = 6;
	DWORD oldProtectVal;
	VirtualProtect(origFunctionAddress, vpSize, PAGE_READWRITE, &oldProtectVal);
	// Replace the original instructions from the trampoline to the original function
	memcpy(origFunctionAddress, trampoline, numOfBytesToCopy);
	// Restore original memory protection on original function
	VirtualProtect(origFunctionAddress, vpSize, oldProtectVal, &oldProtectVal);

	// Free allocated trampoline function memory
	bool freeRes = VirtualFree(trampoline, 0, MEM_RELEASE);
	if (freeRes == false) return Error("Failed to free trampoline memory");

	return true;
}


bool StartActivity()
{
	OutputDebugString("[Fadlon] **Hi Before**");
	printf("[Fadlon] Start Activity\n");
	const bool retVal = InlineHook();
	printf("[Fadlon] Hooked\n");
	OutputDebugString("[Fadlon] **Hi After**");
	return retVal;
}

bool StopActivity()
{
	OutputDebugString("[Fadlon] **Hi Before**");
	printf("[Fadlon] Stop Activity\n");
	const bool retVal = UnHook();
	printf("[Fadlon] Unload\n");
	OutputDebugString("[Fadlon] **Hi After**");
	return retVal;
}
