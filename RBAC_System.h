#pragma once

#include <string.h>

/////////////Role Based Access Control/////////////////////

#define MAX_FILE_AMOUNT 20
#define MAX_PROCESS_AMOUNT 20
#define MAX_FILE_NAME_LENGTH 2048
#define MAX_PROCESS_NAME_LENGTH 2048

//#define RIGHT_TO_READ 0x03//0b011
//#define RIGHT_TO_WRITE 0x04//0b100

#define ROLE_NOBODY 0b000
#define ROLE_USER 0b011
#define ROLE_ADMIN 0b111

const char User[] = "User";
const char Admin[] = "Admin";
const char Nobody[] = "Nobody";

typedef struct RBAC_PROCESS
{
    char role;
    char processName[MAX_PROCESS_NAME_LENGTH];

}RBAC_PROCESS;

unsigned int rbacProcessCounter = 0;
RBAC_PROCESS rbacProcessList[MAX_PROCESS_AMOUNT] = { 0 };

typedef struct RBAC_FILE
{
    char level;
    char fileName[MAX_PROCESS_NAME_LENGTH];

}RBAC_FILE;

unsigned int rbacFileCounter = 0;
RBAC_FILE rbacFileList[MAX_FILE_AMOUNT] = { 0 };

int compareStrings(char* first, char* second)
{
    while (*first && *second)
    {
        if (*first != *second) return 0;
        ++first;
        ++second;
    }
    return 0;
}

void rbacAddUsersToList(char* data)
{
    // DbgPrint("in parsing finction\n");
    char* line_tok = NULL;
    char* _line_tok = NULL;
    char* arg_tok = NULL;
    char* _arg_tok = NULL;

    while (1) {
        if (line_tok == NULL)
            line_tok = strtok_s(data, "\n", &_line_tok);
        else
            line_tok = strtok_s(NULL, "\n", &_line_tok);

        if (line_tok == NULL)
            break;

        arg_tok = strtok_s(line_tok, " ", &_arg_tok);
        strcpy(rbacProcessList[rbacProcessCounter].processName, arg_tok);
        // DbgPrint("first arg_tok: %s\n", arg_tok);

        arg_tok = strtok_s(NULL, " ", &_arg_tok);
        // DbgPrint("sec arg_tok: %s\n", arg_tok);

        if (compareStrings(arg_tok, "Admin"))
            rbacProcessList[rbacProcessCounter].role = ROLE_ADMIN;
        else if (compareStrings(arg_tok, "User"))
            rbacProcessList[rbacProcessCounter].role = ROLE_USER;
        else if (compareStrings(arg_tok, "Nobody"))
            rbacProcessList[rbacProcessCounter].role = ROLE_NOBODY;

        rbacProcessCounter++;
    }

}

void rbacAddFilesToList(char* data)
{
    char* line_tok = NULL;
    char* _line_tok = NULL;
    char* arg_tok = NULL;
    char* _arg_tok = NULL;

    while (1) {

        if (line_tok == NULL)
            line_tok = strtok_s(data, "\n", &_line_tok);
        else
            line_tok = strtok_s(NULL, "\n", &_line_tok);

        if (line_tok == NULL)
            break;

        arg_tok = strtok_s(line_tok, " ", &_arg_tok);
        strcpy(rbacFileList[rbacFileCounter].fileName, arg_tok);

        arg_tok = strtok_s(NULL, " ", &_arg_tok);

        if (compareStrings(arg_tok, "Admin"))
            rbacFileList[rbacFileCounter].level = ROLE_ADMIN;
        else if (compareStrings(arg_tok, "User"))
            rbacFileList[rbacFileCounter].level = ROLE_USER;
        else if (compareStrings(arg_tok, "Nobody"))
            rbacFileList[rbacFileCounter].level = ROLE_NOBODY;

        rbacFileCounter++;
    }
}

int rbacCheckProcessRole(unsigned int processRole, unsigned int fileLevel, unsigned int request)
{
    DbgPrint("rbacCheckProcessRole, procRole: %u, fileLev: %u, request: %u\n", processRole, fileLevel, request);
    if (fileLevel <= processRole)
    {
        DbgPrint("fileLevel <= processRole\nAccess\n");
        return 1;
    }
    else if ((fileLevel & processRole & request) > 0)
    {
        DbgPrint("fileLevel & processRole & request > 0\nAccess\n");
        return 1;
    }
    DbgPrint("Access denied\n");
    return 0;
}

char rbacGetProcessRole(char name[MAX_PROCESS_NAME_LENGTH])
{
    DbgPrint("rbacGetProcessRole, prName: %s", name);

    for (unsigned int counter = 0; counter < rbacProcessCounter; counter++)
    {
        if (compareStrings(name, rbacProcessList[counter].processName))
        {
            DbgPrint("Role: %u\n", rbacProcessList[counter].role);
            return rbacProcessList[counter].role;
        }
    }
    DbgPrint("Role: %u\n", ROLE_ADMIN);
    return ROLE_ADMIN;
}

char rbacGetFileLevel(char name[MAX_FILE_NAME_LENGTH])
{
    DbgPrint("rbacGetFileLevel, filename: %s", name);

    for (unsigned int counter = 0; counter < rbacFileCounter; counter++)
    {
        if (compareStrings(name, rbacFileList[counter].fileName))
        {
            DbgPrint("Role: %u\n", rbacProcessList[counter].role);
            return rbacFileList[counter].level;
        }
    }
    DbgPrint("Role: %u\n", ROLE_NOBODY);
    return ROLE_NOBODY;
}

int rbacProcessExistInList(char name[MAX_PROCESS_NAME_LENGTH])
{
    for (unsigned int counter = 0; counter < rbacProcessCounter; counter++)
    {
        if (compareStrings(name, rbacProcessList[counter].processName))
            return 1;
    }
    return 0;
}

int rbacFileExistInList(char name[MAX_FILE_NAME_LENGTH])
{
    for (unsigned int counter = 0; counter < rbacFileCounter; counter++)
    {
        if (compareStrings(name, rbacFileList[counter].fileName))
            return 1;
    }
    return 0;
}