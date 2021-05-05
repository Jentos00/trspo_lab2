#define WIN32_LEAN_AND_MEAN 
#include <winsock2.h> 
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include "time.h"
#include <tlhelp32.h>
#include <comdef.h>
#include <vector>
#include <tchar.h>

using namespace std;

string pid_name, func_hide, sendMes;

int init()
{
	WSADATA wsa_data;
	return (0 == WSAStartup(MAKEWORD(2, 2), &wsa_data));

}
void deinit()
{
	WSACleanup();
}

int sock_err(const char* function, int s)
{
	int err;
	err = WSAGetLastError();

	fprintf(stderr, "%s: socket error: %d\n", function, err);
	return -1;
}

int find_args(vector <string> input, int num_arg, string pid_or_name) {
	for (int i = 0; i < num_arg; i++)
		if (input[i] == pid_or_name) return i;
	return -1;
}


DWORD Pid_from_Name(string processname)
{
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD res = NULL;
	hProcess = CreateToolhelp32Snapshot(0x00000002, 0);
	if (INVALID_HANDLE_VALUE == hProcess) return(FALSE);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcess, &pe32)) {
		CloseHandle(hProcess);
		cout << "!!! Failed to gather information on system processes!" << endl;
		return(NULL);
	}
	do {
		_bstr_t b(pe32.szExeFile);
		const char* c = b;
		if (0 == strcmp(processname.c_str(), c)) {
			res = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcess, &pe32));
	CloseHandle(hProcess);
	return res;
}

int LoadLib(DWORD ProcessId)
{
	char CurDir[MAX_PATH] = { 0 };

	HMODULE KernelModule;
	HANDLE TID;
	LPVOID LoadLibrary;
	LPVOID ArgLoadLibrary;
	int NumberWrittenSymbols;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	GetCurrentDirectoryA(sizeof(CurDir), CurDir);
	size_t len = sizeof(CurDir);
	while (CurDir[--len] != '\\')
		CurDir[len] = 0;
	strcat_s(CurDir, "app\\hook.dll");
	const char* DllName = CurDir;

	if (hProcess == NULL)
	{
		cout << "Error, OpenProcess: " << GetLastError() << endl;
		return 0;
	}

	KernelModule = GetModuleHandleW(L"kernel32.dll");

	if (KernelModule == NULL)
	{
		cout << "Error, GetModuleHandleW: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return 0;
	}

	LoadLibrary = GetProcAddress(KernelModule, "LoadLibraryA");

	if (LoadLibrary == NULL)
	{
		cout << "Error,GetProcAddress : " << GetLastError() << endl;

		CloseHandle(hProcess);
		return 0;
	}

	ArgLoadLibrary = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(DllName) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (ArgLoadLibrary == NULL)
	{
		cout << "Error,VirtualAllocEx : " << GetLastError() << endl;

		CloseHandle(hProcess);
		return 0;
	}

	NumberWrittenSymbols = WriteProcessMemory(hProcess, ArgLoadLibrary, DllName, strlen(DllName) + 1, NULL);

	if (NumberWrittenSymbols == NULL)
	{
		cout << "Error, WriteProcessMemory : " << GetLastError() << endl;

		CloseHandle(hProcess);
		return 0;
	}

	TID = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, ArgLoadLibrary, NULL, NULL);

	if (TID == NULL)
	{
		cout << "Error,CreateRemoteThread : " << GetLastError() << endl;

		CloseHandle(hProcess);
		return 0;
	}

	CloseHandle(hProcess);
	return 1;
}

int Start_work(string Message, DWORD hPid)
{

	SOCKET LSock, CSock;
	struct sockaddr_in addr;
	int error;
	char* rbuf = new char[512];
	if (init() == 0)
	{
		return -1;
	}
	LSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (LSock < 0)
	{

		return sock_err("socket", LSock);
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htons(9000);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(LSock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		closesocket(LSock);


		return sock_err("bind", LSock);
	}
	if (listen(LSock, 100) < 0)
	{
		closesocket(LSock);
		cout << "Here" << endl;
		return sock_err("listen", LSock);
	}

	if (!LoadLib(hPid))
		return 0;

	memset(rbuf, 0, 512);
	CSock = accept(LSock, NULL, NULL);

	error = recv(CSock, rbuf, 512, 0);
	if (error > 0) {

		cout << "Message from client: " << rbuf << endl;
		send(CSock, Message.c_str(), strlen(Message.c_str()) + 1, 0);
		cout << "Message for client:" << Message.c_str() << endl;
	}
	else {

		closesocket(CSock);
		closesocket(LSock);
		return sock_err("recv", CSock);

	}
	do {
		memset(rbuf, 0, 512);
		error = recv(CSock, rbuf, 512, 0);
		if (error > 0) {
			cout << "Message from client: " << rbuf << endl;
		}

		else {

			cout << "Broke connection" << endl;
			break;
		}

	} while (1);
	closesocket(CSock);
	closesocket(LSock);
	free(rbuf);
	return 0;
}

int main(int argc, char* argv[])
{
	if (argc < 5)
	{
		cout << "Error.Args." << endl;
		return 0;
	}
	if (!IsUserAnAdmin()) {
		cout << "Not admin priv." << endl;
		return 0;
	}
	int Pid = 0, Func = 0;
	int ret;
	DWORD hPid;
	vector <string> input;
	string sendStr;
	for (int i = 0; i < argc - 1; i++)
	{
		input.push_back(argv[i + 1]);
	}

	if ((ret = find_args(input, argc - 2, "-pid")) != -1) {
		pid_name = input[ret + 1];
		Pid = 1;
	}
	else if ((ret = find_args(input, argc - 2, "-name")) != -1)
		pid_name = input[ret + 1];
	else {
		cout << "-pid or -name not found" << endl;
		return 0;
	}

	if ((ret = find_args(input, argc - 2, "-func")) != -1) {
		func_hide = input[ret + 1];
		Func = 1;
	}
	else if ((ret = find_args(input, argc - 2, "-hide")) != -1)
		func_hide = input[ret + 1];
	else {
		cout << "func or -hide not found" << endl;
		return 0;
	}

	if (Pid)
	{
		hPid = atoi(pid_name.c_str());
	}
	else
	{
		hPid = Pid_from_Name(pid_name);
	}
	if (!hPid)
	{
		cout << "The process was not find" << endl;
		return 0;
	}
	for (u_int i = 0; i < input.size() - 1; i++) {
		sendMes += input[i];
		sendMes += " ";
	}
	sendMes += input[input.size() - 1];
	cout << "Start work" << endl;
	if (Start_work(sendMes, hPid) == 0)
	{
		cout << "Successful execution" << endl;
	}
	else
	{
		cout << "Execution failed" << endl;

	}

	deinit();
	return 0;
}