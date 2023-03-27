#include "MyActivity.h"
#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <stdio.h>

using namespace std;

// original function: void OutputDebugStringA([in, optional] LPCSTR lpOutputString);
// typedef void(WINAPI* HookOutputDebugStringA)(LPCSTR lpOutputString);
// original function: void OutputDebugStringW([in, optional] LPCWSTR lpOutputString);
// typedef void(WINAPI* HookOutputDebugStringW)(LPCWSTR lpOutputString);

// Set up a function to call that will pass execution to our trampoline code
// to ultimately pass execution back to the read OutputDebugString code
typedef void(WINAPI* HookOutputDebugStringA)(LPCSTR lpOutputString);
HookOutputDebugStringA outputDebugStringTrampoline;

// This is our function hook
// This is what we will execute before passing execution back to the real function
void WINAPI MyOutputDebugString(LPCSTR lpOutputString)
{
	printf("[Fadlon] MyOutputDebugString\n");
	// Overwrite the text in the OutputDebugString with our message
	lpOutputString = "Hooked";
	// Pass execution to our trampoline which will ultimately return back to the original function
	return outputDebugStringTrampoline(lpOutputString);
}

int Error(const char* msg) {
	printf("[Fadlon] Error!: %s (%u)", msg, GetLastError());
	return 1;
}

int InlineHook()
{
	// Call OutputDebugString before hooking to show original functionality
	OutputDebugString("Before");

	printf("[Fadlon] Inline enter\n");
	HookOutputDebugStringA* origFunctionAddress = (HookOutputDebugStringA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OutputDebugStringA");
	printf("[Fadlon] origFunctionAddress - '%x'\n", origFunctionAddress);

	// Allocate some memory to store the start of the original function
	BYTE* trampolineAddress = (BYTE*)VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (trampolineAddress == NULL) {
		Error("Failed to allocate memory for trampoline");
	}

	const int numOfBytesToCopy = 5;
	const int trampolineSize = numOfBytesToCopy * 3;
	char trampoline[trampolineSize] = {};

	// Copy the first few bytes of the original function to the trampoline function
	memcpy(trampolineAddress, origFunctionAddress, numOfBytesToCopy);

	// The the end of the copied bytes we want to JMP back to the original hooked function
	// 0xE9 is the JMP opcode here. It needs to be given a 4 bytes address
	*(DWORD*)(trampoline + numOfBytesToCopy) = 0xE9;

	// Calculate where we want to jump back to in the original hooked fuction
	uintptr_t jumpAddress = (BYTE*)origFunctionAddress - trampolineAddress - numOfBytesToCopy;
	printf("[Fadlon] jumpAddress - '%x'\n", jumpAddress);

	// Write the JMP address to our trampoline
	*(uintptr_t*)((uintptr_t)trampoline + numOfBytesToCopy + 1) = jumpAddress;

	// Write the trampoline to the allocated trampoline memory region
	if (!WriteProcessMemory(GetCurrentProcess(), trampolineAddress, trampoline, sizeof(trampoline), NULL)) {
		return Error("Error while writing process memory to trampoline");
	}

	printf("[Fadlon] trampoline: '");
	for (int i = 0; i < trampolineSize; i++) {
		printf("%x", trampoline[i]);
	}
	printf("'\n");

	printf("[Fadlon] VP1\n");
	// Change memory protection on OutputDebugString code to make sure it's writable
	DWORD oldProtectVal;
	VirtualProtect(origFunctionAddress, 6, PAGE_READWRITE, &oldProtectVal);

	// Patch the original OutputDebugString code
	// First we replace the first BYTE with a JMP instruction
	*(BYTE*)origFunctionAddress = 0xE9;

	// Then we calculate the relative address to JMP to our Hook function
	intptr_t hookAddress = (intptr_t)((CHAR*)MyOutputDebugString - (intptr_t)origFunctionAddress) - 5;

	// Write the relative address to the original OutputDebugString function
	*(intptr_t*)((intptr_t)origFunctionAddress + 1) = hookAddress;

	printf("[Fadlon] %x\n", hookAddress);
	// Restore original memory protection on OutputDebugString code
	VirtualProtect(origFunctionAddress, 6, oldProtectVal, &oldProtectVal);
	printf("[Fadlon] VP2\n");

	// Cast the trampoline address to a function 
	outputDebugStringTrampoline = (HookOutputDebugStringA)trampolineAddress;

	printf("[Fadlon] After\n");
	// The hook should now be complete
	// Call OutputDebugString again to test the hook
	//OutputDebugString("After");

	return 0;
}



bool StartActivity()
{
	//HookOutputDebugStringA hookFunction = MyOutputDebugString;
	printf("[Fadlon] Start\n");
	return InlineHook();
}

//	UnHook!
int UnHook()
{
	return 0;
}

bool StopActivity()
{
	return UnHook();
}
