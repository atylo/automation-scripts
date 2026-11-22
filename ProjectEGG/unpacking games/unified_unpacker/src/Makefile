# Native (Linux/macOS, for testing the portable parts) :  make
# Windows .exe via MinGW-w64                            :  make win
# MSVC                                                  :  cl /std:c++20 /EHsc /O2 /utf-8 *.cpp /Fe:egg_unpack.exe
SRC = main.cpp common.cpp platform.cpp pe.cpp crypto.cpp compress.cpp d88.cpp detect.cpp \
      extract_eggdata.cpp extract_type98.cpp extract_msx.cpp extract_pc98.cpp keyfinder.cpp \
      extract_datafilever.cpp extract_lzss_exe.cpp extract_x1.cpp extract_bind.cpp extract_scn.cpp extract_type60.cpp pds.cpp romdb.cpp output.cpp eggdisk.cpp extract_cnpf.cpp
CXXFLAGS = -std=c++20 -O2 -Wall -Wextra

egg_unpack: $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $@

win: $(SRC)
	x86_64-w64-mingw32-g++ $(CXXFLAGS) -static $(SRC) -o egg_unpack.exe

clean:
	rm -f egg_unpack egg_unpack.exe
