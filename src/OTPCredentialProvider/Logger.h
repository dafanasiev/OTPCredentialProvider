#pragma once

#include <windows.h>
#include <strsafe.h>



#define LOGFILE_NAME "C:\\multiotplog.txt"
#define MAX_TIME_SIZE 250

#define ZERO(NAME) \
	ZeroMemory(NAME, sizeof(NAME))

#define INIT_ZERO_WCHAR(NAME, SIZE) \
	wchar_t NAME[SIZE]; \
	ZERO(NAME)

#define INIT_ZERO_CHAR(NAME, SIZE) \
	char NAME[SIZE]; \
	ZERO(NAME) 


void PrintLn(const wchar_t *message, const wchar_t *message2, const wchar_t *message3, const wchar_t *message4);
void PrintLn(const wchar_t *message, const wchar_t *message2, const wchar_t *message3);
void PrintLn(const wchar_t *message, const wchar_t *message2);
void PrintLn(const wchar_t *message);
void PrintLn(const char* message);
void PrintLn(const char* message, int line);
void PrintLn(const wchar_t *message, int line);
void PrintLn(int line);
void GetCurrentTimeAndDate(char(&time)[MAX_TIME_SIZE]);
void WriteLogFile(const wchar_t* szString);
void WriteLogFile(const char* szString);