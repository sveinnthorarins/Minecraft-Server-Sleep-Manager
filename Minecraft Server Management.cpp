
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#include <string>
#include <iostream>
#include <fstream>
#include <regex>
#include <ctime>
#include <chrono>
#include <thread>
#include <WS2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdlib.h>

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

using namespace std;

struct rcon_packet {
	int size;
	int id;
	int type;
	char data[1446];
	char nullbytes[2];
};

wstring getCurrentTime();
int getConfiguration();
void listenForActivityOnPort(u_short port);
bool isActiveConnection(u_short port);
void errorExit(wstring msg);
void stopServer();

bool serverActive = false;
HANDLE writeToServer = INVALID_HANDLE_VALUE;

u_short serverPort;
u_short rconPort;
string rconPassword;
string serverAddress;

int main()
{
	HWND wh = GetConsoleWindow();
	MoveWindow(wh, 70, 120, 1220, 780, TRUE);
	SetConsoleTitleW(L"Minecraft Server Management");

	wcout << "[" << getCurrentTime() << "] Booting up..\n";

	wcout << "[" << getCurrentTime() << "] Reading values from server.properties file..\n";

	int i = getConfiguration();

	if (i == 0) {
		wcout << "You need to enable rcon in your server.properties file for this program to work.\n";
		wcout << "Press any key to exit.\n";
		int c = getchar();
		return 0;
	} else if (i == 2) {
		wcout << "ERROR: Problem reading server.properties file.\n";
		wcout << "Press any key to exit.\n";
		int c = getchar();
		return 0;
	} else {
		wcout << "[" << getCurrentTime() << "] Values read successfully..\n";
	}

	wcout << "[" << getCurrentTime() << "] Starting server management..\n";

	//variables
	chrono::minutes sleepTime(30);

	//cmd command to start server
	wstring command = L"cmd.exe /c start.bat";
	LPWSTR com = new wchar_t[command.size() + 1];
	copy(command.begin(), command.end(), com);
	com[command.size()] = 0;

	//cmd.exe path
	wstring exepath = L"c:\\windows\\system32\\cmd.exe";

	//security attributes for pipes
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = FALSE;
	saAttr.lpSecurityDescriptor = NULL;

	//initiate winsock dll
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		errorExit(L"Error in WSAStartup.");

	//continuously loop this while program is on
	while (true) {

		wcout << "[" << getCurrentTime() << "] Listening for activity on server port..\n";

		listenForActivityOnPort(serverPort);

		wcout << "[" << getCurrentTime() << "] Activity found, starting server..\n";

		STARTUPINFOW startupInfo;
		ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
		startupInfo.cb = sizeof(STARTUPINFOW);
		
		PROCESS_INFORMATION processInfo;
		ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
			
		if (!CreateProcessW(exepath.c_str(), com, 0, 0, FALSE, CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE, 0, 0, &startupInfo, &processInfo)) {
			wcout << "[" << getCurrentTime() << "] Problem starting server..\n";
			wcout << "[" << getCurrentTime() << "] Press any key to exit..\n";
			int c = getchar();
			return 0;
		}

		wcout << "[" << getCurrentTime() << "] Server started..\n";

		serverActive = true;

		while (serverActive) {
			this_thread::sleep_for(sleepTime);
			wcout << "[" << getCurrentTime() << "] Checking for activity on server..\n";
			
			DWORD exitCode;
			bool b = GetExitCodeProcess(processInfo.hProcess, &exitCode);
			if (b != 0 && exitCode == STILL_ACTIVE) {
				if (!isActiveConnection(serverPort)) {
					wcout << "[" << getCurrentTime() << "] No activity found on server port..\n";
					wcout << "[" << getCurrentTime() << "] Shutting down server..\n";
					serverActive = false;
					stopServer();
				}
				else {
					wcout << "[" << getCurrentTime() << "] Activity found, continuing sleep..\n";
				}
			}
			else if (b != 0) {
				serverActive = false;
				wcout << "[" << getCurrentTime() << "] Server manually stopped or crashed..\n";
			}
		}

		//wait for program to close
		DWORD exitCode = STILL_ACTIVE;
		while (exitCode == STILL_ACTIVE) {
			bool b = GetExitCodeProcess(processInfo.hProcess, &exitCode);
		}
		
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
	}
}

wstring getCurrentTime() {
	time_t currTime = time(0);
	wstring timeString = wstring(_wctime(&currTime));
	timeString = timeString.substr(0, timeString.size()-1);
	return timeString;
}

int getConfiguration() {
	u_short count = 0;
	ifstream input ("server.properties");
	string line;
	while (getline(input, line, '\n')) {
		if (line.substr(0,1).compare("#") != 0) {
			line = regex_replace(line, regex("\\s+"), "");
			size_t point = line.find("=");
			string key = line.substr(0, point);
			if (key == "server-port") {
				string val = line.substr(point + 1, (line.length() - key.length() - 1));
				serverPort = (u_short)strtoul(val.c_str(), NULL, 0);
				count++;
			}
			else if (key == "server-ip") {
				string val = line.substr(point + 1, (line.length() - key.length() - 1));
				serverAddress = val;
				count++;
			}
			else if (key == "rcon.port") {
				string val = line.substr(point + 1, (line.length() - key.length() - 1));
				rconPort = (u_short)strtoul(val.c_str(), NULL, 0);
				count++;
			}
			else if (key == "rcon.password") {
				string val = line.substr(point + 1, (line.length() - key.length() - 1));
				rconPassword = val;
				count++;
			}
			else if (key == "enable-rcon") {
				string val = line.substr(point + 1, (line.length() - key.length() - 1));
				if (val.compare("false") == 0) {
					return 0;
				}
				count++;
			}
		}
	}
	if (count == 5) return 1;
	else return 2;
}

void listenForActivityOnPort(u_short port) {
	SOCKET soc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (soc == INVALID_SOCKET)
		errorExit(L"Error creating internet socket.");

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	int addrlen = sizeof(addr);

	int bindres = bind(soc, (sockaddr*) &addr, addrlen);
	if (bindres != 0)
		errorExit(L"Error binding socket.");

	int listres = listen(soc, 3);
	if (listres != 0)
		errorExit(L"Error listening to socket.");
	
	SOCKET new_soc = INVALID_SOCKET;

	while (new_soc == INVALID_SOCKET) {
		new_soc = accept(soc, (sockaddr*)&addr, &addrlen);
	}

	closesocket(soc);
	closesocket(new_soc);
}

bool isActiveConnection(u_short port) {
	PMIB_TCPTABLE tcpTable;
	DWORD dwSize = 0;
	DWORD dwRetVal = 0;

	tcpTable = (MIB_TCPTABLE*)MALLOC(sizeof(MIB_TCPTABLE));
	if (tcpTable == NULL)
		errorExit(L"Error allocating memory.");

	dwSize = sizeof(MIB_TCPTABLE);

	if ((dwRetVal = GetTcpTable(tcpTable, &dwSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
		FREE(tcpTable);
		tcpTable = (MIB_TCPTABLE*)MALLOC(dwSize);
		if (tcpTable == NULL)
			errorExit(L"Error allocating memory.");
	}

	if ((dwRetVal = GetTcpTable(tcpTable, &dwSize, TRUE)) == NO_ERROR) {
		if (tcpTable) {
			for (int i = 0; i < (int)tcpTable->dwNumEntries; i++) {
				if (ntohs((u_short)tcpTable->table[i].dwLocalPort) == port && tcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
					FREE(tcpTable);
					return TRUE;
				}
			}
		}
	}

	if (tcpTable != NULL) {
		FREE(tcpTable);
		tcpTable = NULL;
	}

	return FALSE;
}

void errorExit(wstring msg) {
	wcout << msg << endl;
	wcout << "[" << getCurrentTime() << "] Press any key to exit..\n";
	int c = getchar();
	if (serverActive) {
		stopServer();
		this_thread::sleep_for(chrono::seconds(12));
	}
	exit(3);
}

void stopServer() {
	int rconId = 10; //just some id

	SOCKET soc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (soc == INVALID_SOCKET)
		errorExit(L"Failed to initialize RCON socket.");

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(rconPort);
	const char* serverAddressChars = serverAddress.c_str();
	inet_pton(AF_INET, serverAddressChars, &(addr.sin_addr));

	int r = connect(soc, (struct sockaddr*) &addr, sizeof(addr));
	if (r != 0)
		errorExit(L"Failed to connect RCON socket. Error code: " + WSAGetLastError());
	//Extreme to exit program with error, but it shouldn't happen as long as code is right.

	rcon_packet authpack = { 0, 0, 0, { 0x00 }, { '\0', '\0' } };
	authpack.size = sizeof(int) * 2 + rconPassword.length() + 2;
	authpack.id = rconId;
	authpack.type = 3;
	strncpy_s(authpack.data, rconPassword.c_str(), rconPassword.length());

	int len, bytesleft;
	int total = 0;
	int ret = -1;
	len = bytesleft = authpack.size + sizeof(int);

	while (total < len) {
		ret = send(soc, (char*)&authpack + total, bytesleft, 0);
		if (ret == -1) {
			//Extreme to exit program with error, but it shouldn't happen as long as code is right.
			errorExit(L"Error sending RCON packet.");
			//Keeping the break here, in case errorExit gets changed to less drastic measures later on.
			break;
		}
		total += ret;
		bytesleft -= ret;
	}

	int psize;
	rcon_packet authpackrecv = { 0, 0, 0, { 0x00 }, { '\0', '\0' } };

	int recvret = recv(soc, (char*)&psize, sizeof(int), 0);

	authpackrecv.size = psize;
	int recieved = 0;
	while (recieved < psize) {
		ret = recv(soc, (char*)&authpackrecv + sizeof(int) + recieved, psize - recieved, 0);
		recieved += ret;
	}

	if (authpackrecv.id == -1)
		errorExit(L"RCON authentication failed.");
	//Extreme to exit program with error, but it shouldn't happen as long as code is right.

	string command = "stop";

	rcon_packet compack = { 0, 0, 0, { 0x00 }, { '\0', '\0' } };
	compack.size = sizeof(int) * 2 + command.length() + 2;
	compack.id = rconId;
	compack.type = 2;
	strncpy_s(compack.data, command.c_str(), command.length());

	int len2, bytesleft2;
	int total2 = 0;
	int ret2 = -1;
	len2 = bytesleft2 = compack.size + sizeof(int);

	while (total2 < len2) {
		ret2 = send(soc, (char*)&compack + total2, bytesleft2, 0);
		if (ret2 == -1) {
			//Extreme to exit program with error, but it shouldn't happen as long as code is right.
			errorExit(L"Error sending RCON packet.");
			//Keeping the break here, in case errorExit gets changed to less drastic measures later on.
			break;
		}
		total2 += ret2;
		bytesleft2 -= ret2;
	}

	closesocket(soc);
}