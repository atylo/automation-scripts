# automation-scripts
Scripts I made with help of AI to solve simple problems and automate stuff, feel free to use

# ProjectEGG
ProjectEGG (Engrossing Game Gallery) has used tons of different obfuscations of over the years, 
and I created extractors for almost each one of them.
Those that don't have extractors or have unfinished ones, are used in less than 3 games. 

The list of all the executables produced by ProjectEGG, Compile and D4E can be found
in unpacking games\All_exe_types.txt , along with the type of obfuscation used and MD5 exe hash.
# UDM
An extractor for UDM self Extract Updater, basically a patcher, but the one that can contain fully recoverable files (as in Drop-in replacements)
ProjectEGG often uses these for patches to their physical releases sold on ac-mall
Like here https://www.amusement-center.com/project/egg/special/package_daivachronicle-re/ (page with a patcher)

# BIN archives
ProjectEGG distributes (Or rather downloads to your machine) games in special .bin archives, which can be extracted
with CNPF_archive_unpacker.py or EGGbins.bms script for QuickBMS, made by einstein95

# Verification and patching
Some games would refuse to run, because in the past, they probably used to write some registration/validation data to registry during install. 
Therefore to bypass it, you can use either of patchers, Dr0Wy3K_patcher.py or CBy3fc3_patcher.py 
The checkers are just to verify that game has valid data and thus would run
If a game or launcher still refuses to start, try running it like this from cmd:
DAIVA6.exe mode=start,userid=f or DAIVA6.exe mode=start,userid=1
