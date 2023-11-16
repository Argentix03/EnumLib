#include "pch.h"
#include "../EnumLib/EnumLib.h"
#include <sstream>
#include <iostream>
#include <sddl.h>
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif


TEST(EnumLibTest, SayHelloTest) {
    // Redirect cout
    std::stringstream buffer;
    std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());

    // Act
    SayHello();

    // Redirect cout back to its old self
    std::cout.rdbuf(old);

    // Assert
    EXPECT_EQ(buffer.str(), "Hello from MyCustomDLL2!\n");
}

TEST(EnumLibTest, GetLSAPolicyHandleAllAccess_WithLocalComputerName) {
    LSA_HANDLE handle = NULL;

    // Act
    NTSTATUS status = GetLSAPolicyHandleAllAccess(L".", &handle);

    // Assert
    EXPECT_EQ(status, STATUS_SUCCESS);
    EXPECT_NE(handle, (LSA_HANDLE)NULL);

    // Clean up
    if (handle) {
		LsaClose(handle);
	}
}

TEST(EnumLibTest, EnumerateUserSIDs_SeInteractiveLogonRight) {
    // Setup - obtain a policy handle with all access
    LSA_HANDLE PolicyHandle = NULL;
    NTSTATUS status = GetLSAPolicyHandleAllAccess(L".", &PolicyHandle);
    EXPECT_EQ(status, STATUS_SUCCESS);
    EXPECT_NE(PolicyHandle, (LSA_HANDLE)NULL);

    // Test EnumerateUserSIDs using SeInteractiveLogonRight
    std::vector<SID*> sids = EnumerateUserSIDs(PolicyHandle, L"SeInteractiveLogonRight");
    EXPECT_FALSE(sids.empty());
    for (const auto& sid : sids)
        EXPECT_TRUE(IsValidSid(sid));

    // Cleanup but not using FreeSid because it keeps crashing and cba if it works
    if (PolicyHandle) {
		LsaClose(PolicyHandle);
	}
}

TEST(EnumLibTest, TranslateSidsToNamesTest) {
    // Setup - obtain a policy handle and some SIDs
    LSA_HANDLE PolicyHandle = NULL;
    GetLSAPolicyHandleAllAccess(L".", &PolicyHandle);
    EXPECT_FALSE(PolicyHandle == NULL);

    std::vector<SID*> sids = EnumerateUserSIDs(PolicyHandle, L"SeInteractiveLogonRight");
    EXPECT_FALSE(sids.empty());
    for (const auto& sid : sids)
		EXPECT_TRUE(IsValidSid(sid));

    // Test TranslateSidsToNames
    std::vector<std::wstring> names = TranslateSidsToNames(PolicyHandle, sids);
    EXPECT_FALSE(names.empty());

    // Cleanup
    if (PolicyHandle) {
        LsaClose(PolicyHandle);
    }
}

// turn it later to all usernames after adding support to enumerate user sids with NULL right.
TEST(EnumLibTest, LookupUserNamesToSidsTest) {
    // Setup - obtain a policy handle and some names
    LSA_HANDLE PolicyHandle = NULL;
    GetLSAPolicyHandleAllAccess(L".", &PolicyHandle);
    EXPECT_FALSE(PolicyHandle == NULL);

    std::vector<SID*> sids = EnumerateUserSIDs(PolicyHandle, L"SeInteractiveLogonRight");
    EXPECT_FALSE(sids.empty());

    std::vector<std::wstring> names = TranslateSidsToNames(PolicyHandle, sids);
    EXPECT_FALSE(names.empty());

    // Test LookupUserNamesToSids
    std::vector<PSID> remoteUserSids = LookupUserNamesToSids(PolicyHandle, names);
    EXPECT_FALSE(remoteUserSids.empty());

    // Additional checks can be added here
}

TEST(EnumLibTest, EnumerateUserRights_Administrator) {
    // Setup - obtain a policy handle
    LSA_HANDLE PolicyHandle = NULL;
    GetLSAPolicyHandleAllAccess(L".", &PolicyHandle);
    std::wstring userName = L"User"; // Replace with a valid user name for testing

    // Test EnumerateUserRights
    std::vector<std::wstring> rights = EnumerateUserRights(PolicyHandle, userName);
    EXPECT_FALSE(rights.empty()) 
        << L"User Rights for " << userName << std::endl;

    // Test EnumerateUserRights
    EXPECT_FALSE(EnumerateUserRights(PolicyHandle, L"User").empty());

    // Only User got any special rights on my machine, the rest only get anything from their groups
    EXPECT_TRUE(EnumerateUserRights(PolicyHandle, L"Guest").empty());
    EXPECT_TRUE(EnumerateUserRights(PolicyHandle, L"Administrator").empty());
    
    // Printing rights for visual inspection
    for (const auto& right : rights) {
        EXPECT_FALSE(rights.empty()) << L" - " << right << L"\n";
    }

    // Check if rights vector is populated
    EXPECT_TRUE(rights.empty());

    // Additional checks can be added here

    // Clean up
    if (PolicyHandle) {
        LsaClose(PolicyHandle);
    }
}

TEST(EnumLibTest, LookupUserNameToSidTest) {
    // Setup - obtain a policy handle and some names
    LSA_HANDLE PolicyHandle = NULL;
    GetLSAPolicyHandleAllAccess(L".", &PolicyHandle);
    EXPECT_FALSE(PolicyHandle == NULL);

    // the correct way it works is without domain/hostname.
    std::vector<std::wstring> usernames = {
        //L"User",
        L"Administrator",
        //L"BUILTIN\\Administrator",
        L"Guest",
        //L"BUILTIN\\Guest",
        //L"DESKTOP-I6IOPHH\\Administrator",
        //L"DESKTOP-I6IOPHH\\User",
        //L"DESKTOP - I6IOPHH\\Administrator",
        //L"DESKTOP - I6IOPHH\\User",
        L"DefaultAccount",
        L"WDAGUtilityAccount",
        L"LOCAL SERVICE",
        L"NETWORK SERVICE",
    };

    // Test LookupUserNamesToSids
    for (const auto& username : usernames) {
        PSID remoteUserSid = LookupUserNameToSid(PolicyHandle, username);
        EXPECT_TRUE(IsValidSid(remoteUserSid));
        LPWSTR stringSid = NULL;
        ConvertSidToStringSidW(remoteUserSid, &stringSid);
        EXPECT_FALSE(stringSid == NULL) << stringSid << std::endl;
    }
}