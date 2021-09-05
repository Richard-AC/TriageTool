#include <string>
#include <windows.h>
#include <filesystem>
#include "filesystem_functions.h"

namespace fs = std::filesystem;

UINT32 setup_input_dir(const wchar_t* initial_dir, const wchar_t* input_dir, const wchar_t* extension){
    int i = 0;
    wchar_t format[] = L"%s\\input_%05d%s";
    wchar_t current_filepath[200] = L"";
    int err = _wmkdir(input_dir);
    if (err == -1) {
        printf("mkdir failed. The directory might already exist.\n");
        return 0;
    }

    for (const auto& entry : fs::recursive_directory_iterator(initial_dir)) {
        swprintf_s(current_filepath, 200, format, input_dir, i, extension);
        //printf("%ls\n", entry.path().c_str());
        //wprintf(L"%s\n", current_filepath);
        if (entry.is_directory()) {
            continue;
        }
        CopyFile(entry.path().c_str(), current_filepath, FALSE);
        i++;
    }

    return i;
}

void dispatch_input_files(UINT16* hashes_array, UINT32 number_of_files, const wchar_t* input_dir, const wchar_t* output_dir, const wchar_t* extension) {
    wchar_t crash_dir[200] = L"";
    const wchar_t crash_dir_format[] = L"%s\\crashes";
    swprintf_s(crash_dir, 200, crash_dir_format, output_dir);
    int err = _wmkdir(crash_dir);
    if (err == -1) {
        printf("mkdir failed.\n");
        return;
    }
    wchar_t filepath_format[] = L"%s\\input_%05d%s";
    wchar_t dirpath_format[] = L"%s\\crash_%04X";
    wchar_t current_filepath[200] = L"";
    wchar_t destination_filepath[200] = L"";
    wchar_t current_dir[200] = L"";
    for (UINT32 i = 0; i < number_of_files; i++) {
        if (hashes_array[i] == 0) {
            continue;
        }
        swprintf_s(current_filepath, 200, filepath_format, input_dir, i, extension);
        swprintf_s(current_dir, 200, dirpath_format, crash_dir, hashes_array[i]);
        int err = _wmkdir(current_dir);
        swprintf_s(destination_filepath, 200, filepath_format, current_dir, i, extension);
        CopyFile(current_filepath, destination_filepath, FALSE);
    }
    return;
}
