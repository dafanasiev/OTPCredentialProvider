#include "Logger.h"

void PrintLn(const wchar_t *message, const wchar_t *message2, const wchar_t *message3, const wchar_t *message4)
{
	INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
	GetCurrentTimeAndDate(date_time);
	WriteLogFile(date_time);

	WriteLogFile(message);
	WriteLogFile(message2);
	WriteLogFile(message3);
	WriteLogFile(message4);
	WriteLogFile("\n");
}
void PrintLn(const wchar_t *message, const wchar_t *message2, const wchar_t *message3)
{
	PrintLn(message, message2, message3, L"");
}
void PrintLn(const wchar_t *message, const wchar_t *message2)
{
	PrintLn(message, message2, L"");
}
void PrintLn(const wchar_t *message) {
	PrintLn(message, L"");
}

void PrintLn(const char* message)
{
	INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
	GetCurrentTimeAndDate(date_time);
	WriteLogFile(date_time);

	WriteLogFile(message);
	WriteLogFile("\n");
}

void PrintLn(const char* message, int line)
{
	INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
	GetCurrentTimeAndDate(date_time);
	WriteLogFile(date_time);

	char code[1024];
	sprintf_s(code, sizeof(code), message, line);

	WriteLogFile(code);
	WriteLogFile("\n");
}

void PrintLn(const wchar_t *message, int line)
{
	INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
	GetCurrentTimeAndDate(date_time);
	WriteLogFile(date_time);

	wchar_t code[1024];
	swprintf_s(code, sizeof(code), message, line);

	//	OutputDebugStringW(message);
	WriteLogFile(code);
	WriteLogFile("\n");
}

void PrintLn(int line)
{
	INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
	GetCurrentTimeAndDate(date_time);
	WriteLogFile(date_time);

	char code[1024];
	sprintf_s(code, sizeof(code), "%d", line);

	WriteLogFile(code);
	WriteLogFile("\n");
}

void WriteLogFile(const char* szString)
{
	FILE* pFile;
	if (fopen_s(&pFile, LOGFILE_NAME, "a") == 0)
	{
		fprintf(pFile, "%s", szString);
		fclose(pFile);
	}
}

void WriteLogFile(const wchar_t* szString)
{
	FILE* pFile;
	if (fopen_s(&pFile, LOGFILE_NAME, "a") == 0)
	{
		fwprintf(pFile, L"%s", szString);
		fclose(pFile);
	}
}

void GetCurrentTimeAndDate(char(&time)[MAX_TIME_SIZE])
{
	SYSTEMTIME st;
	GetSystemTime(&st);

	sprintf_s(time, ARRAYSIZE(time), "%04d%02d%02d %02d%02d%02d%04d: ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}
