#pragma once

#include <cstdlib>
#include <string>

enum class Platform {
    Windows,
    Linux,
    Darwin,
};
#ifdef _WIN32
constexpr Platform kPlatform = Platform::Windows;
const char* const kAudioModule = "wasapi";
const char* const kConsoleModule = "wincons";
const char* const kDefaultAudioDevice = "default";
// Python has no AF_UNIX on Windows, so the SIM server is on loopback TCP
const char* const kDefaultSimcardServer = "http://127.0.0.1:8888";
#elif defined(__APPLE__)
constexpr Platform kPlatform = Platform::Darwin;
const char* const kAudioModule = "coreaudio";
const char* const kConsoleModule = "stdio";
const char* const kDefaultAudioDevice = "default";
const char* const kDefaultSimcardServer = "unix:/run/nekoims/simcard.sock";
#else
constexpr Platform kPlatform = Platform::Linux;
const char* const kAudioModule = "alsa";
const char* const kConsoleModule = "stdio";
const char* const kDefaultAudioDevice = "plughw:0,0";
const char* const kDefaultSimcardServer = "unix:/run/nekoims/simcard.sock";
#endif

// Where the ePDG dialer and start scripts keep their files (P-CSCF, config):
// /run/nekoims, or %ProgramData%\NekoIMS on Windows.
inline std::string run_dir() {
#ifdef _WIN32
    const char* pd = std::getenv("ProgramData");
    return std::string(pd ? pd : "C:\\ProgramData") + "\\NekoIMS";
#else
    return "/run/nekoims";
#endif
}

inline std::string default_config_path() {
#ifdef _WIN32
    return run_dir() + "\\config.json";
#else
    return "/etc/nekoims/config.json";
#endif
}

// Written by the ePDG dialer while its tunnel is up, one P-CSCF per line.
inline std::string pcscf_file() {
#ifdef _WIN32
    return run_dir() + "\\pcscf";
#else
    return run_dir() + "/pcscf";
#endif
}
