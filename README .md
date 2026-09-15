# Krypto-Tool – Datei- & USB-/HDD-Verschlüsselung

Ein einfaches Desktop-Programm (C++ / GTK3 / OpenSSL) zum Ver- und
Entschlüsseln von Dateien, Ordnern, USB-Sticks und externen Festplatten
mit AES-256-CBC und einem selbst gewählten Passwort.

**Benötigte Dateien im selben Ordner:**
- `krypto_tool.cpp`
- `CMakeLists.txt`

---

## 🐧 Installation unter Linux (Ubuntu/Debian)

### 1. Abhängigkeiten installieren

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libgtk-3-dev libssl-dev
```

Bei anderen Distributionen die entsprechenden Paketnamen verwenden:
- **Fedora:** `sudo dnf install gcc-c++ cmake pkgconf-pkg-config gtk3-devel openssl-devel`
- **Arch Linux:** `sudo pacman -S base-devel cmake pkgconf gtk3 openssl`

### 2. Bauen

```bash
mkdir build && cd build
cmake ..
make
```

### 3. Starten

```bash
./krypto_tool
```

---

## 🪟 Installation unter Windows

GTK3 ist unter Windows nicht vorinstalliert. Der einfachste Weg führt über
**MSYS2** (eine Linux-ähnliche Build-Umgebung für Windows).

### 1. MSYS2 installieren

1. MSYS2 von **https://www.msys2.org/** herunterladen und installieren.
2. Nach der Installation das mitgelieferte Terminal **"MSYS2 MinGW 64-bit"**
   öffnen (nicht das normale "MSYS2"-Terminal).

### 2. Abhängigkeiten installieren

Im MSYS2-MinGW64-Terminal:

```bash
pacman -Syu
```

(Falls danach zum Neustart des Terminals aufgefordert wird: Terminal schließen,
erneut "MSYS2 MinGW 64-bit" öffnen und den Befehl ggf. wiederholen.)

```bash
pacman -S --needed mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake \
  mingw-w64-x86_64-gtk3 mingw-w64-x86_64-openssl mingw-w64-x86_64-pkgconf
```

Bei der Paketauswahl einfach mit **Enter** die Standardauswahl (alle) bestätigen.

### 3. Projekt bauen

Im selben MinGW64-Terminal in den Projektordner wechseln (Windows-Laufwerke
sind unter `/c/`, `/d/` usw. erreichbar), z. B.:

```bash
cd /c/Users/DeinName/Desktop/krypto_tool
mkdir build && cd build
cmake -G "MinGW Makefiles" ..
mingw32-make
```

### 4. Starten

```bash
./krypto_tool.exe
```

**Wichtig für die Weitergabe der .exe:** Wenn du die `krypto_tool.exe` auf
einem anderen Windows-Rechner ohne MSYS2 starten willst, müssen die
GTK3-/OpenSSL-DLLs mitgeliefert werden. Am einfachsten kopierst du dazu alle
`.dll`-Dateien aus `C:\msys64\mingw64\bin\` in den gleichen Ordner wie die
`.exe`, oder du fügst `C:\msys64\mingw64\bin` dauerhaft zur Windows-Umgebungs-
variable `PATH` hinzu.

### Alternative: CLion unter Windows

Falls du lieber CLion statt der Kommandozeile nutzt:
1. In CLion unter **Settings → Build, Execution, Deployment → Toolchains**
   die MSYS2-Umgebung als Toolchain hinzufügen (CLion erkennt eine
   vorhandene MSYS2/MinGW64-Installation meist automatisch).
2. Projektordner mit `krypto_tool.cpp` und `CMakeLists.txt` öffnen.
3. CLion lädt die `CMakeLists.txt` automatisch und du kannst über den
   grünen "Run"-Button bauen und starten.

---

## Bedienung

1. **📄 Dateien wählen…** oder **📁 Ordner wählen…** – einzelne Dateien
   oder einen ganzen Ordner (z. B. den USB-Stick) auswählen.
2. **🔌 USB/HDD erkennen** (Linux) – sucht automatisch nach eingebundenen
   externen Laufwerken unter `/media`, `/mnt`, `/run/media`.
3. Passwort eingeben.
4. **🔐 Verschlüsseln** oder **🔓 Entschlüsseln** klicken.

⚠️ **Wichtig:** Es gibt keine Passwort-Wiederherstellung. Wenn du das
Passwort vergisst, sind die verschlüsselten Daten unwiederbringlich
verloren. Am besten zuerst an einer Testdatei ausprobieren, bevor du die
Option "Originaldatei nach Vorgang löschen" aktivierst.
