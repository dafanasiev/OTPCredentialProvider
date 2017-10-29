//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// This file contains some global variables that describe what our
// sample tile looks like.  For example, it defines what fields a tile has
// and which fields show in which states of LogonUI. This sample illustrates
// the use of each UI field type.

#pragma once
#include "helpers.h"

// The indexes of each of the fields in our credential provider's tiles. Note that we're
// using each of the nine available field types here.
// enum FIELD_ID
// {
//     SFI_TILEIMAGE         = 0,
//     SFI_LABEL             = 1,
//     SFI_LARGE_TEXT        = 2,
//     SFI_PASSWORD          = 3,
//     SFI_SUBMIT_BUTTON     = 4,
//     SFI_LAUNCHWINDOW_LINK = 5,
//     SFI_HIDECONTROLS_LINK = 6,
//     SFI_FULLNAME_TEXT     = 7,
//     SFI_DISPLAYNAME_TEXT  = 8,
//     SFI_LOGONSTATUS_TEXT  = 9,
//     SFI_CHECKBOX          = 10,
//     SFI_EDIT_TEXT         = 11,
//     SFI_COMBOBOX          = 12,
//     SFI_NUM_FIELDS        = 13,  // Note: if new fields are added, keep NUM_FIELDS last.  This is used as a count of the number of fields
// };

enum FIELD_ID
{
	SFI_TILEIMAGE            = 0,
	SFI_LABEL                = 1,
	SFI_LOGIN_NAME           = 2,
	SFI_LARGE_TEXT           = 3,
	SFI_PASSWORD             = 4,
	SFI_SUBMIT_BUTTON        = 5,
	SFI_PREV_PIN             = 6,
	SFI_PIN                  = 7,
    SFI_SYNCHRONIZE_LINK     = 8,
	SFI_FAILURE_TEXT         = 9,
	SFI_NEXT_LOGIN_ATTEMPT   = 10,
	SFI_NUM_FIELDS           = 11,
};


// The first value indicates when the tile is displayed (selected, not selected)
// the second indicates things like whether the field is enabled, whether it has key focus, etc.
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// These two arrays are seperate because a credential provider might
// want to set up a credential with various combinations of field state pairs
// and field descriptors.

// The field state value indicates whether the field is displayed
// in the selected tile, the deselected tile, or both.
// The Field interactive state indicates when
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // SFI_TILEIMAGE
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_LABEL
	{ CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_LOGIN_NAME
	{ CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // SFI_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_FOCUSED },    // SFI_PASSWORD
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_SUBMIT_BUTTON
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_PREV_PIN
	{ CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_PIN
	{ CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_SYNCHRONIZE_LINK
	{ CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_FAILURE_TEXT
	{ CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_NEXT_LOGIN_ATTEMPT
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_DISPLAYNAME_TEXT
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_LOGONSTATUS_TEXT
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_CHECKBOX
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_EDIT_TEXT
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_COMBOBOX
};

// Field descriptors for unlock and logon.
// The first field is the index of the field.
// The second is the type of the field.
// The third is the name of the field, NOT the value which will appear in the field.
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { SFI_TILEIMAGE,         CPFT_TILE_IMAGE,    L"Image",                      CPFG_CREDENTIAL_PROVIDER_LOGO  },
    { SFI_LABEL,             CPFT_SMALL_TEXT,    L"Tooltip",                    CPFG_CREDENTIAL_PROVIDER_LABEL },
	{ SFI_LOGIN_NAME,        CPFT_EDIT_TEXT,     L"Login name"                                                 },
	{ SFI_LARGE_TEXT,        CPFT_LARGE_TEXT,    L"multiOTP Login"                                             },
    { SFI_PASSWORD,          CPFT_PASSWORD_TEXT, L"Password text"                                              },
    { SFI_SUBMIT_BUTTON,     CPFT_SUBMIT_BUTTON, L"Submit"                                                     },
    { SFI_PREV_PIN,          CPFT_PASSWORD_TEXT, L"PREVIOUS PIN"                                               },
	{ SFI_PIN,               CPFT_PASSWORD_TEXT, L"PIN"                                                        },               
	{ SFI_SYNCHRONIZE_LINK,  CPFT_COMMAND_LINK,  L"Synchronize multiOTP"                                       },
	{ SFI_FAILURE_TEXT,      CPFT_SMALL_TEXT,    L"Logon Failure"                                              },
	{ SFI_NEXT_LOGIN_ATTEMPT,CPFT_COMMAND_LINK,  L"Next Login attempt"                                         },
	//    { SFI_FULLNAME_TEXT,     CPFT_SMALL_TEXT,    L"Full name: "                                                },
//    { SFI_DISPLAYNAME_TEXT,  CPFT_SMALL_TEXT,    L"Display name: "                                             },
//    { SFI_LOGONSTATUS_TEXT,  CPFT_SMALL_TEXT,    L"Logon status: "                                             },
//    { SFI_CHECKBOX,          CPFT_CHECKBOX,      L"Checkbox"                                                   },
//    { SFI_EDIT_TEXT,         CPFT_EDIT_TEXT,     L"Edit text"                                                  },
//    { SFI_COMBOBOX,          CPFT_COMBOBOX,      L"Combobox"                                                   },
};

//static const PWSTR s_rgComboBoxStrings[] =
//{
//    L"First",
//    L"Second",
//    L"Third",
//};
struct MULTIOTP_RESPONSE
{
	HRESULT ErrorNum;
	PWSTR MessageText;
};

static const MULTIOTP_RESPONSE s_rgmultiOTPResponse[] =
{
	{ 0,  L"SUCCES: Token resynchronization complete" },
	{ 10, L"INFO: Access Challenge returned back to the client" },
	{ 11, L"INFO : User successfully created or updated" },
	{ 12, L"INFO : User successfully deleted" },
	{ 13, L"INFO : User PIN code successfully changed" },
	{ 14, L"INFO : Token has been resynchronized successfully" },
	{ 15, L"INFO : Tokens definition file successfully imported" },
    { 16, L"INFO : QRcode successfully created" },
    { 17, L"INFO : UrlLink successfully created" },
    { 18, L"INFO : SMS code request received" },
    { 19, L"INFO : Requested operation successfully done" },
	{ 21, L"ERROR : User doesn't exist"},
	{ 22, L"ERROR : User already exists" },
	{ 23, L"ERROR : Invalid algorithm" },
	{ 24, L"ERROR : User locked(too many tries)" },
	{ 25, L"ERROR : User delayed(too many tries, but still a hope in a few minutes)" },
	{ 26, L"ERROR : The token has already been used" },
	{ 27, L"ERROR : Resynchronization of the token has failed" },
	{ 28, L"ERROR : Unable to write the changes in the file" },
	{ 29, L"ERROR : Token doesn't exist" },
	{ 30, L"ERROR : At least one parameter is missing" },
	{ 31, L"ERROR : Tokens definition file doesn't exist" },
	{ 32, L"ERROR : Tokens definition file not successfully imported" },
	{ 33, L"ERROR : Encryption hash error, encryption key is not matching" },
	{ 34, L"ERROR : Linked user doesn't exist" },
	{ 35, L"ERROR : User not created" },
	{ 37, L"ERROR : Token already attributed" },
	{ 38, L"ERROR : User is desactivated" },
	{ 39, L"ERROR : Requested operation aborted" },
	{ 41, L"ERROR : SQL error"},
	{ 50, L"ERROR : QRcode not created" },
	{ 51, L"ERROR : UrlLink not created(no provisionable client for this protocol)" },
	{ 60, L"ERROR : No information on where to send SMS code" },
	{ 61, L"ERROR : SMS code request received, but an error occurred during transmission"},
	{ 62, L"ERROR : SMS provider not supported"},
	{ 70, L"ERROR : Server authentication error"},
	{ 71, L"ERROR : Server request is not correctly formatted" },
	{ 72, L"ERROR : Server answer is not correctly formatted" },
	{ 80, L"ERROR : Server cache error"},
	{ 81, L"ERROR : Cache too old for this user, account autolocked" },
	{ 98, L"ERROR : Authentication failed(wrong token length)" },
	{ 99, L"ERROR : Authentication failed(and other possible unknown errors)" },
};