# Krypto-Tool - File & USB/HDD Encryption

A simple desktop application (C++ / GTK3 / OpenSSL) for encrypting and
decrypting files, folders, USB sticks, and external hard drives using
AES-256-CBC with a password of your choice.

**Required files in the same folder:**
- krypto_tool.cpp
- CMakeLists.txt

---

## Installation on Linux (Ubuntu/Debian)

### 1. Install dependencies

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libgtk-3-dev libssl-dev
```

For other distributions, use the equivalent package names:
- **Fedora:** sudo dnf install gcc-c++ cmake pkgconf-pkg-config gtk3-devel openssl-devel
- **Arch Linux:** sudo pacman -S base-devel cmake pkgconf gtk3 openssl

### 2. Build

```bash
mkdir build && cd build
cmake ..
make
```

### 3. Run

```bash
./krypto_tool
```

---

## Installation on Windows

GTK3 is not preinstalled on Windows. The simplest approach is to use
**MSYS2** (a Linux-like build environment for Windows).

### 1. Install MSYS2

1. Download and install MSYS2 from **https://www.msys2.org/**.
2. After installation, open the terminal named **"MSYS2 MinGW 64-bit"**
   (not the plain "MSYS2" terminal).

### 2. Install dependencies

In the MSYS2 MinGW64 terminal:

```bash
pacman -Syu
```

(If prompted to restart the terminal afterwards: close it, reopen
"MSYS2 MinGW 64-bit", and run the command again if needed.)

```bash
pacman -S --needed mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake \
  mingw-w64-x86_64-gtk3 mingw-w64-x86_64-openssl mingw-w64-x86_64-pkgconf
```

When prompted to select packages, press Enter to accept the default
(all) selection.

### 3. Build the project

In the same MinGW64 terminal, navigate to the project folder (Windows
drives are available under /c/, /d/, etc.), for example:

```bash
cd /c/Users/YourName/Desktop/krypto_tool
mkdir build && cd build
cmake -G "MinGW Makefiles" ..
mingw32-make
```

### 4. Run

```bash
./krypto_tool.exe
```

**Important for distributing the .exe:** To run krypto_tool.exe on
another Windows machine without MSYS2 installed, the GTK3/OpenSSL DLLs
must be included. The easiest way is to copy all .dll files from
C:\msys64\mingw64\bin\ into the same folder as the .exe, or to
permanently add C:\msys64\mingw64\bin to the Windows PATH environment
variable.

### Alternative: CLion on Windows

If you prefer CLion over the command line:
1. In CLion, go to Settings -> Build, Execution, Deployment -> Toolchains
   and add the MSYS2 environment as a toolchain (CLion usually detects
   an existing MSYS2/MinGW64 installation automatically).
2. Open the project folder containing krypto_tool.cpp and CMakeLists.txt.
3. CLion will load CMakeLists.txt automatically, and you can build and
   run it using the green Run button.

---

## Usage

1. Click "Choose files..." or "Choose folder..." to select individual
   files or an entire folder (e.g. a USB stick).
2. Click "Detect USB/HDD" (Linux) to automatically search for mounted
   external drives under /media, /mnt, /run/media.
3. Enter a password.
4. Click "Encrypt" or "Decrypt".

Important: there is no password recovery. If you forget the password,
the encrypted data is permanently lost. Test with a sample file first
before enabling the "Delete original file after operation" option.
