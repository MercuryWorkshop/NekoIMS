// IMS IPsec for sec-agree: the Security-Client/-Server/-Verify handling is
// shared here, the SAs themselves are per platform (ipsec_linux.cpp,
// ipsec_windows.cpp, included at the end).

#include "ipsec.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <sstream>

#include <re.h>
#include <baresip.h>

namespace nekoims {

namespace {

std::string trim(const std::string& s) {
    const size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return std::string();
    return s.substr(a, s.find_last_not_of(" \t\r\n") - a + 1);
}

}  // namespace

std::vector<SecMech> parse_security(const std::string& value) {
    std::vector<SecMech> out;
    std::stringstream entries(value);
    std::string entry;

    while (std::getline(entries, entry, ',')) {
        std::stringstream params(entry);
        std::string p;
        if (!std::getline(params, p, ';') || trim(p) != "ipsec-3gpp") continue;

        SecMech m;
        while (std::getline(params, p, ';')) {
            const size_t eq = p.find('=');
            if (eq == std::string::npos) continue;
            const std::string k = trim(p.substr(0, eq));
            const std::string v = trim(p.substr(eq + 1));
            if (k == "alg") m.alg = v;
            else if (k == "ealg") m.ealg = v;
            else if (k == "spi-c") m.spi_c = uint32_t(std::strtoul(v.c_str(), 0, 10));
            else if (k == "spi-s") m.spi_s = uint32_t(std::strtoul(v.c_str(), 0, 10));
            else if (k == "port-c") m.port_c = uint16_t(std::atoi(v.c_str()));
            else if (k == "port-s") m.port_s = uint16_t(std::atoi(v.c_str()));
            else if (k == "q") m.q = std::atof(v.c_str());
        }
        if (m.ealg.empty()) m.ealg = "null";
        out.push_back(m);
    }
    return out;
}

bool pick_security(const std::vector<SecMech>& offers, SecMech& out) {
    bool found = false;
    for (size_t i = 0; i < offers.size(); ++i) {
        const SecMech& m = offers[i];
        if (m.alg != "hmac-md5-96" && m.alg != "hmac-sha-1-96") continue;
        if (m.ealg != "null" && m.ealg != "aes-cbc") continue;
        if (!m.spi_c || !m.spi_s || !m.port_c || !m.port_s) continue;
        if (!found || m.q > out.q) out = m, found = true;
    }
    return found;
}

std::string security_client(uint32_t spi_c, uint32_t spi_s, uint16_t port) {
    static const char* const kOffers[][2] = {
        {"hmac-sha-1-96", "aes-cbc"},
        {"hmac-sha-1-96", "null"},
        {"hmac-md5-96", "aes-cbc"},
        {"hmac-md5-96", "null"},
    };
    std::string s;
    for (size_t i = 0; i < sizeof(kOffers) / sizeof(kOffers[0]); ++i) {
        char buf[160];
        re_snprintf(buf, sizeof(buf),
                    "ipsec-3gpp;alg=%s;ealg=%s;spi-c=%u;spi-s=%u;port-c=%u;"
                    "port-s=%u",
                    kOffers[i][0], kOffers[i][1], spi_c, spi_s, port, port);
        if (!s.empty()) s += ", ";
        s += buf;
    }
    return s;
}

}  // namespace nekoims

#ifdef _WIN32
#include "ipsec_windows.cpp"
#else
#include "ipsec_linux.cpp"
#endif
