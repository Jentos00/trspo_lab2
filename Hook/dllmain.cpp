#include "pch.h"

#pragma comment(lib, "ws2_32.lib")

#define WIN32_LEAN_AND_MEAN 
#pragma warning(disable  : 4996);
SOCKET CSock = NULL;
extern "C" LPVOID Target = NULL;
LPVOID my_addr;



std::string name_of_process;
bool Connect;
void sendMsg()
{
	if (Connect)
	{
		CHAR Msg[512] = { 0 };
		SYSTEMTIME T;
		char time[512] = { 0 };
		GetLocalTime(&T);
		char buf[512] = { 0 };
		sprintf_s(buf, "Date: %d:%d:%d- Time: %d:%d:%d\n", T.wDay, T.wMonth, T.wYear, T.wHour, T.wMinute, T.wSecond);

		if (time == NULL || strcmp(buf, time))
		{
			sprintf_s(time, "Date: %d:%d:%d Time: %d:%d:%d\n", T.wDay, T.wMonth, T.wYear, T.wHour, T.wMinute, T.wSecond);
			sprintf_s(Msg, "Func:%s . %s ", name_of_process.c_str(), time);
			send(CSock, Msg, strlen(Msg) + 1, 0);
		}

		Connect = FALSE;
	}
}
extern "C" VOID Dyn() 
{
	Connect = TRUE;
	sendMsg();
}
int init()
{
	WSADATA wsa_data;
	return (0 == WSAStartup(MAKEWORD(2, 2), &wsa_data));

}
void deinit()
{
	WSACleanup();

}
int Con()
{


	init();
	sockaddr_in ServerAddr;
	int error;


	CSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	ServerAddr.sin_port = htons(9000);
	error = connect(CSock, (sockaddr*)&ServerAddr, sizeof(ServerAddr));
	if (error == SOCKET_ERROR) {
		closesocket(CSock);
		deinit();
		return 0;
	}
	return 1;
}
std::string recv_message(char* recvbuf)
{
	char* char_buf = new char[strlen(recvbuf) + 1];
	strcpy(char_buf, recvbuf);
	char* buf = strtok(char_buf, " ");
	buf = strtok(NULL, " ");
	buf = strtok(NULL, " ");
	std::string buffer = buf;
	free(char_buf);
	return buffer;
}
std::string recv_path(char* recvbuf)
{
	char* char_buf = new char[strlen(recvbuf) + 1];
	strcpy(char_buf, recvbuf);
	char* buf = strtok(char_buf, " ");
	buf = strtok(NULL, " ");
	buf = strtok(NULL, " ");
	buf = strtok(NULL, " ");
	std::string buffer = buf;
	free(char_buf);
	return buffer;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{


		if (Con() == 0)
		{
			break;

		}
		char* recvbuf = new char[512];
		strcpy(recvbuf, "Hello message");
		int err = send(CSock, recvbuf, strlen(recvbuf) + 1, 0);
		if (err > 0)
		{

		}
		else
		{
			int r = GetLastError();
			std::stringstream out;
			out << r;
			std::string error = out.str();
			std::string sl = "Win Text = '";

			sl += "'Text";
		}
		err = recv(CSock, recvbuf, 512, 0);
		if (err > 0)
		{

		}

		else
		{
			break;
		}
		std::string func_or_hide = recv_message(recvbuf);

		name_of_process = recv_path(recvbuf);


		if (func_or_hide == "-hide")
		{
			std::string hideName = name_of_process;
			HideFile(hideName);
			closesocket(CSock);
			deinit();
			return 1;
		}
		if (func_or_hide == "-func")
		{

			Target = DetourFindFunction("kernel32.dll", name_of_process.c_str());
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			Connect = TRUE;
			DetourAttach(&(PVOID&)Target, Hook_x64);
			int err = DetourTransactionCommit();
			if (err != NO_ERROR) {
				char Msg[512] = { 0 };
				sprintf_s(Msg, "DetourTransactionCommit() Error: %d\n", err);
				send(CSock, Msg, strlen(Msg) + 1, 0);
				return 1;
			}
		}
		break; }

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}