#pragma once


#include <windows.h>
#include <ntsecapi.h>
#include <vector>
#include <string>
#include <map>
#include <sddl.h>

extern "C" __declspec(dllexport) void SayHello();
extern "C" __declspec(dllexport) NTSTATUS GetLSAPolicyHandleAllAccess(LPCWSTR computerName, LSA_HANDLE * outPolicyHandle);
extern "C" __declspec(dllexport) NTSTATUS GetLSAPolicyHandle(LPCWSTR computerName, LSA_HANDLE * outPolicyHandle, ACCESS_MASK accessRights);
__declspec(dllexport) std::vector<SID*> EnumerateUserSIDs(LSA_HANDLE PolicyHandle, const std::wstring & userRightStr);
__declspec(dllexport) std::vector<std::wstring> TranslateSidsToNames(LSA_HANDLE PolicyHandle, const std::vector<SID*>& sids);
__declspec(dllexport) std::vector<PSID> LookupUserNamesToSids(LSA_HANDLE PolicyHandle, const std::vector<std::wstring>& userNames);
__declspec(dllexport) PSID LookupUserNameToSid(LSA_HANDLE PolicyHandle, const std::wstring& userName);
__declspec(dllexport) std::vector<std::wstring> EnumerateUserRights(LSA_HANDLE PolicyHandle, const std::wstring& userName);
__declspec(dllexport) std::vector<std::wstring> EnumerateUserRightsFromSID(LSA_HANDLE PolicyHandle, PSID pSid);
__declspec(dllexport) std::wstring GetSidString(PSID pSid);

std::map<std::wstring, std::wstring> wellKnownSids = {
    // Adding entries for well-known SIDs
    {L"S-1-0-0", L"NULL"},                                  // No Security principal
    {L"S-1-1-0", L"EVERYONE"},                              // WORLD. Includes all users.
    {L"S-1-2-0", L"LOCAL"},                                 // Includes users logged on locally.
    {L"S-1-2-1", L"CONSOLE_LOGON"},                         // Users logged on to the physical console.
    {L"S-1-3", L"CREATOR_AUTHORITY"},                       // Creator authority group.
    {L"S-1-3-0", L"CREATOR_OWNER"},                         // Placeholder for the object's creator.
    {L"S-1-3-1", L"CREATOR_GROUP"},                         // Placeholder for the creator's primary group.
    {L"S-1-3-2", L"OWNER_SERVER"},                          // Placeholder for owner server.
    {L"S-1-3-3", L"GROUP_SERVER"},                          // Placeholder for group server.
    {L"S-1-3-4", L"OWNER_RIGHTS"},                          // Represents the current owner of the object.
    {L"S-1-5", L"NT_AUTHORITY"},                            // Only SECURITY_NT_AUTHORITY identifier authority.
    {L"S-1-5-1", L"DIALUP"},                                // Users who logged on through a dial-up connection.
    {L"S-1-5-2", L"NETWORK"},                               // Users who logged on through a network.
    {L"S-1-5-3", L"BATCH"},                                 // Users who logged on through a batch queue.
    {L"S-1-5-4", L"INTERACTIVE"},                           // Users who logged on interactively.
    //{L"S-1-5-5-x-y", L"LOGON_ID"},                          // Represents a logon session.
    {L"S-1-5-6", L"SERVICE"},                               // Security principals logged on as a service.
    {L"S-1-5-7", L"ANONYMOUS"},                             // Represents an anonymous logon.
    {L"S-1-5-8", L"PROXY"},                                 // Proxy.
    {L"S-1-5-9", L"ENTERPRISE_DOMAIN_CONTROLLERS"},         // All domain controllers in a forest.
    {L"S-1-5-10", L"PRINCIPAL_SELF"},                       // Placeholder in inheritable ACE.
    {L"S-1-5-11", L"AUTHENTICATED_USERS"},                  // Authenticated users.
    {L"S-1-5-12", L"RESTRICTED_CODE"},                      // Used to control access by untrusted code.
    {L"S-1-5-13", L"TERMINAL_SERVER_USER"},                 // Users logged on to a Terminal Services server.
    {L"S-1-5-14", L"REMOTE_INTERACTIVE_LOGON"},             // Users logged on through terminal services logon.
    {L"S-1-5-15", L"THIS_ORGANIZATION"},                    // Users from the same organization.
    {L"S-1-5-17", L"IUSR"},                                 // Default Internet Information Services user.
    {L"S-1-5-18", L"LOCAL_SYSTEM"},                         // Operating system account.
    {L"S-1-5-19", L"LOCAL_SERVICE"},                        // Local service account.
    {L"S-1-5-20", L"NETWORK_SERVICE"},                      // Network service account.
    {L"S-1-5-21-0-0-0-496", L"COMPOUNDED_AUTHENTICATION"},  // Device identity in Kerberos ticket.
    {L"S-1-5-21-0-0-0-497", L"CLAIMS_VALID"},               // Claims queried and transformed.
    {L"S-1-5-32-544", L"BUILTIN_ADMINISTRATORS"},           // yeah... no just google them.
    {L"S-1-5-32-545", L"BUILTIN_USERS"},
    {L"S-1-5-32-546", L"BUILTIN_GUESTS"},
    {L"S-1-5-32-547", L"POWER_USERS"},
    {L"S-1-5-32-548", L"ACCOUNT_OPERATORS"},
    {L"S-1-5-32-549", L"SERVER_OPERATORS"},
    {L"S-1-5-32-550", L"PRINTER_OPERATORS"},
    {L"S-1-5-32-551", L"BACKUP_OPERATORS"},
    {L"S-1-5-32-552", L"REPLICATOR"},
    {L"S-1-5-32-554", L"ALIAS_PREW2KCOMPACC"},
    {L"S-1-5-32-555", L"REMOTE_DESKTOP"},
    {L"S-1-5-32-556", L"NETWORK_CONFIGURATION_OPS"},
    {L"S-1-5-32-557", L"INCOMING_FOREST_TRUST_BUILDERS"},
    {L"S-1-5-32-558", L"PERFMON_USERS"},
    {L"S-1-5-32-559", L"PERFLOG_USERS"},
    {L"S-1-5-32-560", L"WINDOWS_AUTHORIZATION_ACCESS_GROUP"},
    {L"S-1-5-32-561", L"TERMINAL_SERVER_LICENSE_SERVERS"},
    {L"S-1-5-32-562", L"DISTRIBUTED_COM_USERS"},
    {L"S-1-5-32-568", L"IIS_IUSRS"},
    {L"S-1-5-32-569", L"CRYPTOGRAPHIC_OPERATORS"},
    {L"S-1-5-32-573", L"EVENT_LOG_READERS"},
    {L"S-1-5-32-574", L"CERTIFICATE_SERVICE_DCOM_ACCESS"},
    {L"S-1-5-32-575", L"RDS_REMOTE_ACCESS_SERVERS"},
    {L"S-1-5-32-576", L"RDS_ENDPOINT_SERVERS"},
    {L"S-1-5-32-577", L"RDS_MANAGEMENT_SERVERS"},
    {L"S-1-5-32-578", L"HYPER_V_ADMINS"},
    {L"S-1-5-32-579", L"ACCESS_CONTROL_ASSISTANCE_OPS"},
    {L"S-1-5-32-580", L"REMOTE_MANAGEMENT_USERS"},
    {L"S-1-5-32-582", L"STORAGE_REPLICA_ADMINS"},
    {L"S-1-5-33", L"WRITE_RESTRICTED_CODE"},
    {L"S-1-5-64-10", L"NTLM_AUTHENTICATION"},
    {L"S-1-5-64-14", L"SCHANNEL_AUTHENTICATION"},
    {L"S-1-5-64-21", L"DIGEST_AUTHENTICATION"},
    {L"S-1-5-65-1", L"THIS_ORGANIZATION_CERTIFICATE"},
    {L"S-1-5-80", L"NT_SERVICE"},
    {L"S-1-5-80-0", L"NT_SERVICE\\ALL_SERVICES"},
    {L"S-1-5-80-2970612574-78537857-698502321-558674196-1451644582", L"NT SERVICE\\DPS"},
    {L"S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420", L"NT SERVICE\\WdiServiceHost"},
    {L"S-1-5-83-0", L"NT VIRTUAL MACHINE\\Virtual Machines"},
    {L"S-1-5-84-0-0-0-0-0", L"USER_MODE_DRIVERS"},
    {L"S-1-5-90-0", L"Windows Manager\\Windows Manager Group"},
    {L"S-1-5-113", L"LOCAL_ACCOUNT"},
    {L"S-1-5-114", L"LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP"},
    {L"S-1-5-1000", L"OTHER_ORGANIZATION"},
    {L"S-1-15-2-1", L"ALL_APP_PACKAGES"},
    {L"S-1-16-0", L"ML_UNTRUSTED"},
    {L"S-1-16-4096", L"ML_LOW"},
    {L"S-1-16-8192", L"ML_MEDIUM"},
    {L"S-1-16-8448", L"ML_MEDIUM_PLUS"},
    {L"S-1-16-12288", L"ML_HIGH"},
    {L"S-1-16-16384", L"ML_SYSTEM"},
    {L"S-1-16-20480", L"ML_PROTECTED_PROCESS"},
    {L"S-1-16-28672", L"ML_SECURE_PROCESS"},
    {L"S-1-18-1", L"AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY"},
    {L"S-1-18-2", L"SERVICE_ASSERTED_IDENTITY"},
    {L"S-1-18-3", L"FRESH_PUBLIC_KEY_IDENTITY"},
    {L"S-1-18-4", L"KEY_TRUST_IDENTITY"},
    {L"S-1-18-5", L"KEY_PROPERTY_MFA"},
    {L"S-1-18-6", L"KEY_PROPERTY_ATTESTATION"},
};
