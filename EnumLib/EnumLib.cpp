#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <ntsecapi.h>
#include <ntstatus.h>
#include "EnumLib.h"

#include <vector>
#include <string>

#pragma comment(lib, "Advapi32.lib")

extern "C" __declspec(dllexport) void SayHello() {
    std::cout << "Hello from MyCustomDLL2!" << std::endl;
}

extern "C" __declspec(dllexport) NTSTATUS GetLSAPolicyHandleAllAccess(LPCWSTR computerName, LSA_HANDLE * outPolicyHandle) {
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    LSA_UNICODE_STRING lsaComputerName;
    lsaComputerName.Buffer = const_cast<LPWSTR>(computerName);
    lsaComputerName.Length = static_cast<USHORT>(wcslen(computerName) * sizeof(WCHAR));
    lsaComputerName.MaximumLength = lsaComputerName.Length + sizeof(WCHAR);

    // Open a policy handle
    NTSTATUS status = LsaOpenPolicy(
        computerName ? &lsaComputerName : NULL, // If computerName is NULL, it opens the policy on the local machine
        &ObjectAttributes,
        POLICY_ALL_ACCESS, // Desired access
        outPolicyHandle
    );

    return status;
}

extern "C" __declspec(dllexport) NTSTATUS GetLSAPolicyHandle(LPCWSTR computerName, LSA_HANDLE * outPolicyHandle, ACCESS_MASK accessRights) {
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    LSA_UNICODE_STRING lsaComputerName;
    lsaComputerName.Buffer = const_cast<LPWSTR>(computerName);
    lsaComputerName.Length = static_cast<USHORT>(wcslen(computerName) * sizeof(WCHAR));
    lsaComputerName.MaximumLength = lsaComputerName.Length + sizeof(WCHAR);

    // Open a policy handle
    NTSTATUS status = LsaOpenPolicy(
        computerName ? &lsaComputerName : NULL, // If computerName is NULL, it opens the policy on the local machine
        &ObjectAttributes,
        accessRights, // Desired access
        outPolicyHandle
    );

    return status;
}

// NULL userRights should enumerate all users. also lets change the name of this later.
__declspec(dllexport) std::vector<SID*> EnumerateUserSIDs(LSA_HANDLE PolicyHandle, const std::wstring & userRightStr) {
    std::vector<SID*> userSIDs;
    LSA_UNICODE_STRING userRight;
    PLSA_ENUMERATION_INFORMATION enumBuffer = NULL;
    ULONG countReturned = 0;
    NTSTATUS status;

    // Convert std::wstring to LSA_UNICODE_STRING
    userRight.Buffer = const_cast<wchar_t*>(userRightStr.c_str());
    userRight.Length = static_cast<USHORT>(userRightStr.size() * sizeof(WCHAR));
    userRight.MaximumLength = static_cast<USHORT>((userRightStr.size() + 1) * sizeof(WCHAR));

    status = LsaEnumerateAccountsWithUserRight(PolicyHandle, &userRight, (void**)&enumBuffer, &countReturned);
    if (status == STATUS_SUCCESS && enumBuffer != NULL) {
        for (ULONG i = 0; i < countReturned; ++i) {
            userSIDs.push_back(reinterpret_cast<SID*>(enumBuffer[i].Sid));
        }
    }

    return userSIDs;
}

__declspec(dllexport) std::vector<std::wstring> TranslateSidsToNames(LSA_HANDLE PolicyHandle, const std::vector<SID*>& sids) {
    PLSA_TRANSLATED_NAME translatedNames = NULL;
    PLSA_REFERENCED_DOMAIN_LIST domains = NULL;
    NTSTATUS status;
    std::vector<std::wstring> names;

    status = LsaLookupSids(PolicyHandle, static_cast<ULONG>(sids.size()), (PSID*)sids.data(), &domains, &translatedNames);
    if (status == STATUS_SUCCESS) {
        for (size_t i = 0; i < sids.size(); ++i) {
            // Get the domain name
            std::wstring domainName(domains->Domains[translatedNames[i].DomainIndex].Name.Buffer,
                domains->Domains[translatedNames[i].DomainIndex].Name.Length / sizeof(WCHAR));

            // Get the account name
            std::wstring accountName(translatedNames[i].Name.Buffer,
                translatedNames[i].Name.Length / sizeof(WCHAR));

            // Combine domain and account names
            names.emplace_back(domainName + L"\\" + accountName);
        }
        LsaFreeMemory(translatedNames);
        LsaFreeMemory(domains);
    }
    else {
        std::wcerr << L"Failed to lookup SIDs. Error: " << LsaNtStatusToWinError(status) << std::endl;
    }

    return names;
}

__declspec(dllexport) std::vector<PSID> LookupUserNamesToSids(LSA_HANDLE PolicyHandle, const std::vector<std::wstring>& userNames) {
    std::vector<PSID> sids;
    PLSA_UNICODE_STRING lsaUserNames = new LSA_UNICODE_STRING[userNames.size()];
    PLSA_TRANSLATED_SID2 lsaTranslatedSids = nullptr;
    PLSA_REFERENCED_DOMAIN_LIST lsaRefDomains = nullptr;

    // Fill the LSA_UNICODE_STRING array
    for (size_t i = 0; i < userNames.size(); ++i) {
        lsaUserNames[i].Buffer = const_cast<PWSTR>(userNames[i].c_str());
        lsaUserNames[i].Length = static_cast<USHORT>(userNames[i].size() * sizeof(WCHAR));
        lsaUserNames[i].MaximumLength = lsaUserNames[i].Length + sizeof(WCHAR);
    }

    // Perform the lookup
    NTSTATUS status = LsaLookupNames2(PolicyHandle, 0, userNames.size(), lsaUserNames, &lsaRefDomains, &lsaTranslatedSids);

    if (status == STATUS_SUCCESS) {
        for (size_t i = 0; i < userNames.size(); ++i) {
            PSID sidCopy = nullptr;
            if (lsaTranslatedSids[i].Use != SidTypeUnknown && lsaTranslatedSids[i].Use != SidTypeInvalid) {
                DWORD sidLength = GetLengthSid(lsaTranslatedSids[i].Sid);
                sidCopy = (PSID)malloc(sidLength);
                if (sidCopy && CopySid(sidLength, sidCopy, lsaTranslatedSids[i].Sid)) {
                    sids.push_back(sidCopy);
                }
            }
        }
    }
    else {
        std::wcerr << L"Failed to lookup names. Error: " << LsaNtStatusToWinError(status) << std::endl;
    }

    // Clean up
    if (lsaRefDomains) LsaFreeMemory(lsaRefDomains);
    if (lsaTranslatedSids) LsaFreeMemory(lsaTranslatedSids);
    delete[] lsaUserNames;

    return sids;
}

// look a single user sid for a given username
__declspec(dllexport) PSID LookupUserNameToSid(LSA_HANDLE PolicyHandle, const std::wstring& userName) {
	std::vector<std::wstring> userNames = { userName };
	std::vector<PSID> sids = LookupUserNamesToSids(PolicyHandle, userNames);
    if (sids.empty()) {
		return nullptr;
	}
	return sids[0];
}

// lookup user rights for a specified username
__declspec(dllexport) std::vector<std::wstring> EnumerateUserRights(LSA_HANDLE PolicyHandle, const std::wstring& userName) {
	std::vector<std::wstring> rights;
	PSID pSid = LookupUserNameToSid(PolicyHandle, userName);
    if (pSid) {
		rights = EnumerateUserRightsFromSID(PolicyHandle, pSid);
	}
	return rights;
}

// lookup user rights for a user with a given sid
// this is a tricky one is it doesnt show effective rights after derving from groups. 
// if a user has not been given extra rights then it will show empty (the api returns an infamous error code 2 "file/object not found")
__declspec(dllexport) std::vector<std::wstring> EnumerateUserRightsFromSID(LSA_HANDLE PolicyHandle, PSID pSid) {
    std::vector<std::wstring> rights;
    PLSA_UNICODE_STRING lsaRights = nullptr;
    ULONG countReturned = 0;
    NTSTATUS status;
    
    if (!IsValidSid(pSid)) {
		return rights;
	}
    LPWSTR stringSid = NULL;
    ConvertSidToStringSidW(pSid, &stringSid);
    std::wcout << L"Enumerating rights for SID: " << stringSid << std::endl;

    std::wcout << L"Enumerating rights for SID: " << GetSidString(pSid) << std::endl;

    status = LsaEnumerateAccountRights(PolicyHandle, pSid, &lsaRights, &countReturned);
    if (status == STATUS_SUCCESS && lsaRights != NULL) {
        for (ULONG i = 0; i < countReturned; ++i) {
            rights.emplace_back(lsaRights[i].Buffer, lsaRights[i].Length / sizeof(WCHAR));
        }
        LsaFreeMemory(lsaRights);
    }
    else {
        unsigned long int error = LsaNtStatusToWinError(status);
        std::wcout << L"Failed to enumerate rights. Error: " << error << std::endl;
	}

    return rights;
}

// lookup all user rights for all users
__declspec(dllexport) std::vector<std::pair<std::wstring, std::vector<std::wstring>>> EnumerateAllUserRights(LSA_HANDLE PolicyHandle) {
	std::vector<std::pair<std::wstring, std::vector<std::wstring>>> userRights;

    // Enumerate users with the specified right NULL means all users
	std::vector<SID*> sids = EnumerateUserSIDs(PolicyHandle, NULL);

    // Get names for each SID
	std::vector<std::wstring> names = TranslateSidsToNames(PolicyHandle, sids);

    // Get rights for each SID
    for (size_t i = 0; i < sids.size(); ++i) {
		std::vector<std::wstring> rights = EnumerateUserRightsFromSID(PolicyHandle, sids[i]);
		userRights.emplace_back(names[i], rights);
	}

	return userRights;
}

// get string representation for sid
__declspec(dllexport) std::wstring GetSidString(PSID pSid) {
	LPWSTR stringSid = NULL;
	ConvertSidToStringSidW(pSid, &stringSid);
	std::wstring sidString(stringSid);
	LocalFree(stringSid);
	return sidString;
}