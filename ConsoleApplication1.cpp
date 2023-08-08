#include <Windows.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#include <wchar.h>
#include <sddl.h>

int main() {
    LPWSTR fileName = (LPWSTR)LocalAlloc(LPTR, (wcslen(L"C:\\Windows\\System32\\WinHttpSvc.exe") + 1) * sizeof(wchar_t));
    if (fileName == NULL) {
        wprintf(L"Erro ao alocar memória para o nome do arquivo.\n");
        return 1;
    }

    if (wcscpy_s(fileName, wcslen(L"C:\\Windows\\System32\\WinHttpSvc.exe") + 1, L"C:\\Windows\\System32\\WinHttpSvc.exe") != 0) {
        wprintf(L"Erro ao copiar o nome do arquivo.\n");
        LocalFree(fileName);
        return 1;
    }

    PSECURITY_DESCRIPTOR pSD = NULL;

    // Obter o descritor de segurança atual do arquivo
    if (GetNamedSecurityInfo(
        fileName,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        NULL,
        NULL,
        &pSD) != ERROR_SUCCESS) {
        wprintf(L"Erro ao obter o descritor de segurança.\n");
        return 1;
    }

    // Obter a lista de controle de acesso atual (DACL)
    PACL pDACL;
    BOOL bDACLPresent, bDACLDefaulted;
    if (!GetSecurityDescriptorDacl(pSD, &bDACLPresent, &pDACL, &bDACLDefaulted)) {
        wprintf(L"Erro ao obter a lista de controle de acesso.\n");
        LocalFree(pSD);
        return 1;
    }

    // Obtém o SID do grupo de Administradores
    PSID pAdminSID = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &pAdminSID)) {
        wprintf(L"Erro ao alocar e inicializar o SID do grupo Administradores.\n");
        LocalFree(pSD);
        return 1;
    }

    // Obtém o SID do grupo de Usuários Autenticados
    PSID pAuthenticatedUsersSID = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthNTAuth = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &SIDAuthNTAuth, 1, SECURITY_AUTHENTICATED_USER_RID,
        0, 0, 0, 0, 0, 0, 0, &pAuthenticatedUsersSID)) {
        wprintf(L"Erro ao alocar e inicializar o SID do grupo Usuários Autenticados.\n");
        FreeSid(pAdminSID);
        LocalFree(pSD);
        return 1;
    }

    // Obtém o SID do grupo de Sistema
    PSID pSystemSID = NULL;
    if (!AllocateAndInitializeSid(
        &SIDAuthNT, 1, SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0, &pSystemSID)) {
        wprintf(L"Erro ao alocar e inicializar o SID do grupo Sistema.\n");
        FreeSid(pAdminSID);
        FreeSid(pAuthenticatedUsersSID);
        LocalFree(pSD);
        return 1;
    }

    // Obtém o SID do grupo de Usuários
    PSID pUsersSID = NULL;
    if (!AllocateAndInitializeSid(
        &SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS,
        0, 0, 0, 0, 0, 0, &pUsersSID)) {
        wprintf(L"Erro ao alocar e inicializar o SID do grupo Usuários.\n");
        FreeSid(pAdminSID);
        FreeSid(pAuthenticatedUsersSID);
        FreeSid(pSystemSID);
        LocalFree(pSD);
        return 1;
    }

    // Adicionar entradas de negação para os grupos Administradores e Usuários Autenticados
    EXPLICIT_ACCESS denyAccessAdmin;
    ZeroMemory(&denyAccessAdmin, sizeof(EXPLICIT_ACCESS));
    denyAccessAdmin.grfAccessPermissions = GENERIC_ALL;
    denyAccessAdmin.grfAccessMode = DENY_ACCESS;
    denyAccessAdmin.grfInheritance = NO_INHERITANCE;
    denyAccessAdmin.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    denyAccessAdmin.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    denyAccessAdmin.Trustee.ptstrName = (LPTSTR)pAdminSID;

    EXPLICIT_ACCESS denyAccessAuthUsers;
    ZeroMemory(&denyAccessAuthUsers, sizeof(EXPLICIT_ACCESS));
    denyAccessAuthUsers.grfAccessPermissions = GENERIC_ALL;
    denyAccessAuthUsers.grfAccessMode = DENY_ACCESS;
    denyAccessAuthUsers.grfInheritance = NO_INHERITANCE;
    denyAccessAuthUsers.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    denyAccessAuthUsers.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    denyAccessAuthUsers.Trustee.ptstrName = (LPTSTR)pAuthenticatedUsersSID;

    EXPLICIT_ACCESS denyAccessEntriesGroup1[2];
    denyAccessEntriesGroup1[0] = denyAccessAdmin;
    denyAccessEntriesGroup1[1] = denyAccessAuthUsers;

    EXPLICIT_ACCESS denyAccessSystem;
    ZeroMemory(&denyAccessSystem, sizeof(EXPLICIT_ACCESS));
    denyAccessSystem.grfAccessPermissions = GENERIC_ALL;
    denyAccessSystem.grfAccessMode = DENY_ACCESS;
    denyAccessSystem.grfInheritance = NO_INHERITANCE;
    denyAccessSystem.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    denyAccessSystem.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    denyAccessSystem.Trustee.ptstrName = (LPTSTR)pSystemSID;

    EXPLICIT_ACCESS denyAccessUsers;
    ZeroMemory(&denyAccessUsers, sizeof(EXPLICIT_ACCESS));
    denyAccessUsers.grfAccessPermissions = GENERIC_ALL;
    denyAccessUsers.grfAccessMode = DENY_ACCESS;
    denyAccessUsers.grfInheritance = NO_INHERITANCE;
    denyAccessUsers.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    denyAccessUsers.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    denyAccessUsers.Trustee.ptstrName = (LPTSTR)pUsersSID;

    EXPLICIT_ACCESS denyAccessEntriesGroup2[4]; // Including denyAccessAdmin and denyAccessAuthUsers
    denyAccessEntriesGroup2[0] = denyAccessAdmin;
    denyAccessEntriesGroup2[1] = denyAccessAuthUsers;
    denyAccessEntriesGroup2[2] = denyAccessSystem;
    denyAccessEntriesGroup2[3] = denyAccessUsers;

    if (SetEntriesInAcl(4, denyAccessEntriesGroup2, pDACL, &pDACL) != ERROR_SUCCESS) {
        wprintf(L"Erro ao adicionar entradas de negação na lista de controle de acesso.\n");
        FreeSid(pAdminSID);
        FreeSid(pAuthenticatedUsersSID);
        LocalFree(pSD);
        return 1;
    }

    // Aplicar o novo DACL ao descritor de segurança
    if (SetSecurityDescriptorDacl(pSD, TRUE, pDACL, FALSE) != ERROR_SUCCESS) {
        wprintf(L"Erro ao definir o DACL no descritor de segurança.\n");
        FreeSid(pAdminSID);
        FreeSid(pAuthenticatedUsersSID);
        LocalFree(pSD);
        LocalFree(pDACL);
        return 1;
    }

    // Aplicar o novo descritor de segurança ao arquivo
    if (SetNamedSecurityInfo(
        fileName,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        pDACL,
        NULL) != ERROR_SUCCESS) {
        wprintf(L"Erro ao definir o novo descritor de segurança.\n");
        FreeSid(pAdminSID);
        FreeSid(pAuthenticatedUsersSID);
        LocalFree(pSD);
        LocalFree(pDACL);
        return 1;
    }

    wprintf(L"Controle total negado para todos os grupos no arquivo.\n");

    // Liberar recursos
    FreeSid(pAdminSID);
    FreeSid(pAuthenticatedUsersSID);
    LocalFree(pSD);
    LocalFree(pDACL);

    return 0;
}
