# VERASER VeraCrypt Plug-in - Technical Specification

**Version:** 1.0  
**Date:** September 2025  
**Author:** Ömer Can VURAL  
**Project:** VERASER Integration for VeraCrypt 1.25.9

---

## 1. Overview

### 1.1 Purpose
This document specifies the technical implementation of VERASER secure file erasure functionality as a plug-in for VeraCrypt, an open-source disk encryption software. The integration provides users with cryptographically secure file deletion capabilities directly within the VeraCrypt interface.

The project addresses the issue of residual data recoverability when files are copied into encrypted volumes, although the source file is deleted, forensic tools may still recover it. Veraser ensures that such files are irreversibly destroyed using proven sanitization methods.

### 1.2 Scope
The plug-in adds two new features to VeraCrypt's Tools menu:
- **Secure Copy**: Copy a file to a destination (e.g. encrypted volume) and securely delete the original
- **Secure Delete**: Securely delete a target file using secure delete algorithms

### 1.3 Target Platform
- **Operating System**: Windows (primary target for VeraCrypt 1.25.9)
- **Architecture**: x86/x64
- **Compiler**: Followed VeraCrypt original building instructions
- **Dependencies**: Windows CNG (bcrypt.lib), standard Windows SDK, OpenSSL

---

## 2. Architecture

### 2.1 Integration Approach
The VERASER engine is integrated as an embedded library within VeraCrypt's codebase:

```
VeraCrypt/src/Mount/
├─── ...
└─── src
    ├─── ...
    ├─── Common
    │       Dlgcode.c
    │       Language.xml
    │       ...
    │
    ├─── ExpandVolume
    │       resource.h
    │       ...
    │
    ├─── Main
    │   └─── Forms
    │           Forms.cpp
    │           Forms.h
    │           MainFrame.cpp
    │           MainFrame.h
    │           TrueCrypt.fbp
    │           ...
    │
    └─── Mount
            Mount.c
            Mount.h
            Mount.rc
            Mount.vcproj
            Resource.h
            veraser.c
            veraser.h
            ...
```

### 2.2 Component Diagram

```
┌─────────────────────────────────────┐
│      VeraCrypt Main Window          │
│                                     │
│  ┌─────────────────────────────┐    │
│  │     Tools Menu              │    │
│  │  - Benchmark                │    │
│  │  - [Separator]              │    │
│  │  - Secure Copy    [NEW]     │    │
│  │  - Secure Delete  [NEW]     │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
           │
           ├──────────────────┬──────────────────┐
           │                  │                  │
           ▼                  ▼                  ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ Secure Copy Dlg  │ │Secure Delete Dlg │ │  VERASER Core    │
│                  │ │                  │ │                  │
│ - Source Path    │ │ - Target Path    │ │ - ve_erase_path()│
│ - Dest Path      │ │ - Algorithm      │ │ - AES-256-CTR    │
│ - Algorithm      │ │   Selection      │ │ - DoD/NIST/etc   │
│   Selection      │ │                  │ │ - TRIM Support   │
└──────────────────┘ └──────────────────┘ └──────────────────┘
```

---

## 3. User Interface Specifications

### 3.1 Menu Integration

**Location**: VeraCrypt Main Window → Tools Menu

**New Menu Items**:
```
Tools
  ├── ...
  ├── ──────────────  [Separator]
  ├── Secure Copy     [NEW]
  └── Secure Delete   [NEW]
  ...
```

### 3.2 Secure Copy Dialog (IDD_SECURE_COPY_DLG)

**Dialog ID**: `1200`  
**Title**: "Secure Copy"  
**Dimensions**: 400x320 dialog units

**Controls**:
- **Description Label**: Static text explaining functionality
- **Source Button** (`IDC_SOURCE_BUTTON`): Opens file browser for source file selection
- **Source Path** (`IDC_SOURCE_PATH`): Read-only text field displaying selected source path
- **Destination Button** (`IDC_DESTINATION_BUTTON`): Opens folder browser for destination selection
- **Destination Path** (`IDC_DESTINATION_PATH`): Read-only text field displaying selected destination
- **Algorithm Group**: Radio button group containing 7 algorithm options
  - Zero (IDC_ALG_ZERO) - 1-pass zeros
  - Random (IDC_ALG_RANDOM) - 1-pass random
  - DoD 3-pass (IDC_ALG_DOD3) - US DoD 5220.22-M
  - DoD 7-pass (IDC_ALG_DOD7) - Extended DoD
  - NIST (IDC_ALG_NIST) - NIST 800-88 [DEFAULT]
  - Gutmann (IDC_ALG_GUTMANN) - 35-pass
  - SSD (IDC_ALG_SSD) - Encrypt + TRIM
- **OK Button**: Executes secure copy operation
- **Cancel Button**: Closes dialog without action

### 3.3 Secure Delete Dialog (IDD_SECURE_DELETE_DLG)

**Dialog ID**: `1201`  
**Title**: "Secure Delete"  
**Dimensions**: 400x280 dialog units

**Controls**:
- **Description Label**: Static text explaining functionality
- **Target Button** (`IDC_TARGET_BUTTON`): Opens file browser for target file selection
- **Target Path** (`IDC_TARGET_PATH`): Read-only text field displaying selected target path
- **Algorithm Group**: Radio button group (identical to Secure Copy)
- **OK Button**: Executes secure deletion
- **Cancel Button**: Closes dialog without action

---

## 4. Functional Specifications

### 4.1 Secure Copy Workflow

```
1. User clicks "Secure Copy" from Tools menu
2. Dialog opens with NIST algorithm pre-selected
3. User selects source file via file browser
4. User selects destination folder via folder browser
5. User optionally changes algorithm selection
6. User clicks OK
7. System validates:
   - Source file exists
   - Destination folder exists
   - User has write permissions
8. System copies file using Windows CopyFileW()
9. On successful copy:
   - Convert source path from UTF-16 to UTF-8
   - Initialize ve_options_t with selected algorithm
   - Call ve_erase_path() on original file
   - Display success/error message
10. Dialog closes
```

### 4.2 Secure Delete Workflow

```
1. User clicks "Secure Delete" from Tools menu
2. Dialog opens with NIST algorithm pre-selected
3. User selects target file via file browser
4. User optionally changes algorithm selection
5. User clicks OK
6. System validates:
   - Target file exists
   - User has delete permissions
7. System executes:
   - Convert target path from UTF-16 to UTF-8
   - Initialize ve_options_t with selected algorithm
   - Call ve_erase_path() on target file
   - Display success/error message
8. Dialog closes
```

### 4.3 Algorithm Behavior

| Algorithm | Passes | Method | Typical Use Case |
|-----------|--------|--------|------------------|
| **Zero** | 1 | Single pass of 0x00 bytes | Quick sanitization, low security |
| **Random** | 1 | CSPRNG data from BCryptGenRandom | General purpose |
| **DoD 3-pass** | 3 | 0xFF, 0x00, random + verify | Regulatory compliance |
| **DoD 7-pass** | 7 | Extended DoD pattern sequence | High security HDD |
| **NIST** | 1 | CSPRNG data (NIST 800-88) | **Recommended default** |
| **Gutmann** | 35 | Historical maximum patterns | Legacy/paranoid scenarios |
| **SSD** | 1 | AES-256-CTR encryption + TRIM | **Recommended for SSD/NVMe** |

---

## 5. API Integration

### 5.1 VERASER Core API Usage

**Header**: `veraser.h`  
**Implementation**: `veraser.c`

**Primary Function**:
```c
ve_status_t ve_erase_path(const char* path, const ve_options_t* options);
```

**Options Structure**:
```c
typedef struct {
    ve_algorithm_t algorithm;     // Algorithm selection
    ve_device_type_t device_type; // AUTO/SSD/HDD hint
    int passes;                   // For random algorithm
    int verify;                   // Enable verification
    int trim_mode;                // 0=auto, 1=on, 2=off
    int follow_symlinks;          // Traverse symlinks
    int erase_ads;                // NTFS ADS handling
    int erase_xattr;              // Extended attributes
    uint64_t chunk_size;          // I/O buffer size
    int threads;                  // Reserved for future
    int dry_run;                  // No-op preview mode
    int quiet;                    // Reduce verbosity
} ve_options_t;
```

### 5.2 Integration Pattern

**Typical Call Sequence**:
```c
// 1. Initialize options
ve_options_t options;
memset(&options, 0, sizeof(options));
options.algorithm = VE_ALG_NIST;  // Or user selection
options.trim_mode = 0;             // Auto TRIM
options.quiet = 1;                 // Suppress verbose output

// 2. Convert path encoding (Windows UTF-16 to UTF-8)
char targetPathA[MAX_PATH];
WideCharToMultiByte(CP_UTF8, 0, targetPathW, -1, 
                    targetPathA, MAX_PATH, NULL, NULL);

// 3. Execute erasure
ve_status_t status = ve_erase_path(targetPathA, &options);

// 4. Handle result
if (status != VE_SUCCESS) {
    const char* errorMsg = ve_last_error_message();
    // Display error to user
}
```

---

## 6. Security Considerations

### 6.1 Cryptographic Components

**Random Number Generation**:
- **Source**: Windows CNG BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG
- **Quality**: FIPS 140-2 compliant system CSPRNG
- **Usage**: Random pass generation, AES key/IV generation

**Encryption (SSD Mode)**:
- **Algorithm**: AES-256-CTR
- **Implementation**: Windows CNG BCrypt API
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 128 bits (16 bytes)
- **Mode**: Counter (CTR) with automatic increment

### 6.2 Memory Security

**Sensitive Data Handling**:
```c
// AES keys and buffers are securely wiped after use
void ve_secure_bzero(void* p, size_t n) {
    SecureZeroMemory(p, n);  // Windows secure zeroing
}
```

**Buffer Lifecycle**:
1. Allocate buffer for I/O operations (default 8 MiB)
2. Use for encryption/overwriting
3. Securely zero buffer before deallocation
4. Free memory

### 6.3 Thread Safety

- **Error Storage**: Thread-local storage (`__declspec(thread)`) ensures per-thread error messages
- **Reentrant Design**: All public APIs are thread-safe for concurrent operations
- **No Global State**: Operations are stateless and independent

### 6.4 Attack Surface Analysis

**Mitigated Threats**:
- File recovery tools (Recuva, PhotoRec)
- Forensic carving from unallocated space
- Simple filesystem analysis
- Basic disk imaging

---

## 7. Error Handling

### 7.1 Return Codes

```c
typedef enum {
    VE_SUCCESS = 0,           // Operation successful
    VE_ERR_INVALID_ARG = -1,  // Invalid parameters
    VE_ERR_IO = -2,           // I/O error
    VE_ERR_PERM = -3,         // Permission denied
    VE_ERR_UNSUPPORTED = -4,  // Feature not supported
    VE_ERR_PARTIAL = -5,      // Partial completion
    VE_ERR_INTERNAL = -128    // Internal error
} ve_status_t;
```

### 7.2 User-Facing Error Messages

**Dialog Error Display**:
```c
if (status != VE_SUCCESS) {
    const char* errorMsg = ve_last_error_message();
    wchar_t errorMsgW[512];
    
    if (errorMsg) {
        MultiByteToWideChar(CP_UTF8, 0, errorMsg, -1, 
                            errorMsgW, 512);
    } else {
        wcscpy_s(errorMsgW, 512, 
                 L"Secure deletion failed with unknown error");
    }
    
    MessageBoxW(hwndDlg, errorMsgW, L"Error", 
                MB_OK | MB_ICONERROR);
}
```

---

## 8. Build Configuration

### 8.1 Modified Files

**Source Code Changes**:
- `src/Mount/Mount.c` - Dialog procedures, menu handlers
- `src/Mount/Mount.rc` - Dialog resource definitions
- `src/Mount/Resource.h` - Control ID definitions
- `src/Mount/Mount.vcxproj` - Build configuration (bcrypt.lib linking)
- `src/Common/Language.xml` - Localized strings
- `src/Main/Forms/Forms.cpp` - wxWidgets menu integration
- `src/Main/Forms/Forms.h` - Menu item declarations

**New Files**:
- `src/Mount/veraser.c` - Core erasure engine
- `src/Mount/veraser.h` - Public API header

### 8.2 Linker Configuration

**Additional Dependencies**:
```xml
<Link>
  <AdditionalDependencies>
    bcrypt.lib;       <!-- Windows CNG -->
    shell32.lib;      <!-- Folder browser -->
    ole32.lib;        <!-- COM initialization -->
    %(AdditionalDependencies)
  </AdditionalDependencies>
</Link>
```

### 8.3 Preprocessor Definitions

```c
// Optional: Build CLI standalone version
#define VE_BUILD_CLI

// Optional: Use OpenSSL on POSIX (not applicable for Windows build)
#define VE_USE_OPENSSL
```

---

## 9. Localization

### 9.1 Language.xml Entries

```xml
<entry lang="en" key="IDM_SECURE_COPY">Secure Copy...</entry>
<entry lang="en" key="IDM_SECURE_DELETE">Secure Delete...</entry>
```

**Future Localization**:
- Dialog control labels should be extracted to Language.xml
- Algorithm descriptions should support translation
- Error messages should use localized strings

---

## 10. Testing Requirements

### 10.1 Functional Tests

| Test Case | Expected Result |
|-----------|----------------|
| Menu item visibility | Both items appear in Tools menu |
| Dialog opening | Dialogs open without errors |
| File browser operation | Source/target file selection works |
| Folder browser operation | Destination folder selection works |
| Default algorithm selection | NIST is pre-selected |
| Algorithm switching | Radio buttons function correctly |
| Secure copy with valid inputs | File copied and original deleted |
| Secure delete with valid inputs | File permanently deleted |
| Invalid source file | Error message displayed |
| Invalid destination folder | Error message displayed |
| Permission denied | Appropriate error message |

### 10.2 Security Tests

| Test Case | Verification Method |
|-----------|-------------------|
| File recovery attempt | Use Recuva/PhotoRec after deletion |
| Disk imaging analysis | Hex editor scan of unallocated space |
| Memory dump analysis | Verify no key material in RAM |
| Multiple pass verification | Confirm pattern application |
| TRIM execution | Check SSD controller logs (if available) |

### 10.3 Performance Tests

| Scenario | Target Performance |
|----------|-------------------|
| 1 GB file, NIST | < 2 seconds on SSD |
| 1 GB file, SSD mode | < 1 second on NVMe |
| 1 GB file, DoD 7-pass | < 15 seconds on HDD |
| 100 MB file, Gutmann | < 60 seconds |

---

## 11. Known Limitations

### 11.1 Current Implementation

- **Single-threaded**: No parallel processing for large directories
- **No progress bar**: Operations appear frozen during execution
- **Limited device detection**: Auto-detection returns AUTO (manual selection recommended)
- **No verification mode**: Verification flag exists but not implemented
- **Windows-only dialogs**: Native Win32 dialogs, no cross-platform UI
- **ANSI paths**: Uses narrow character paths (UTF-8), may have Unicode limitations

### 11.2 Platform-Specific Constraints

**Windows**:
- TRIM is implicit on delete for modern systems (Windows 7+)
- Requires administrative privileges for some operations
- Read-only attribute is automatically cleared before erasure

**NTFS**:
- Alternate Data Streams not handled in current version
- Compressed files may not overwrite as expected
- Sparse files deallocate blocks automatically

---

## 12. References

### 12.1 Standards

- **NIST SP 800-88 Rev. 1**: Guidelines for Media Sanitization
- **DoD 5220.22-M**: National Industrial Security Program Operating Manual (NISPOM)
- **FIPS 140-2**: Security Requirements for Cryptographic Modules
- **ISO/IEC 27040**: Information security — Storage security

### 12.2 Cryptographic Specifications

- **FIPS 197**: Advanced Encryption Standard (AES)
- **NIST SP 800-38A**: Recommendation for Block Cipher Modes (CTR mode)
- **NIST SP 800-90A**: Recommendation for Random Number Generation

---

**Document Version**: 1.0  
**Last Updated**: September 2025  
**Status**: Release Candidate