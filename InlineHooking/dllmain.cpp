#include "pch.h"
#include "MyActivity.h"
#include <stdexcept>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		OutputDebugString("Dll Process Attach");
		try
		{
			StartActivity() ? OutputDebugString("StartActivity Successfully!") : OutputDebugString("StartActivity Failed!");
		}
		catch (const std::exception& e)
		{
			MessageBox(NULL, e.what(), "FAIL", MB_OK);
			return FALSE;
		}
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		OutputDebugString("Dll Process Detach");
		try
		{
			StopActivity() ? OutputDebugString("StopActivity Successfully!") : OutputDebugString("StopActivity Failed!");

		}
		catch (const std::exception& e)
		{
			MessageBox(NULL, e.what(), "FAIL", MB_OK);
			return FALSE;
		}
		break;
	}
	return TRUE;
}
