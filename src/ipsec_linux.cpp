// ip xfrm implementation of IpsecSet, included by ipsec.cpp on Linux (and
// macOS, where it builds but has nothing to talk to). Not built on its own.
//
// This is a temporary IPsec implementation for carriers which require
// sec-agree on IMS registration. It shells out to `ip xfrm` in the current
// netns; see ipsec.h for the XFRM interface (link netns) details.

#include <sys/wait.h>

namespace nekoims {

namespace {

// Our reqids live in [kReqidBase, kReqidBase + kReqidSpan), four per set,
// reused round-robin (at most two sets are up at once: old and new).
const uint32_t kReqidBase = 0x4e4b0000;  // "NK"
const uint32_t kReqidSpan = 64;
// All our policies carry this priority, so leftovers can be told apart.
const uint32_t kPriority = 0x4e4b;
uint32_t g_next_reqid = 0;

std::string hex(const std::vector<uint8_t>& v) {
    static const char d[] = "0123456789abcdef";
    std::string s = "0x";
    for (size_t i = 0; i < v.size(); ++i) {
        s += d[v[i] >> 4];
        s += d[v[i] & 0xf];
    }
    return s;
}

const char kLinkNetns[] = "nsenter --net=/proc/1/ns/net ";

// Runs `ip <args>` (in the link netns if link); returns its exit status,
// output in out.
int ip(const std::string& args, std::string& out, bool link = false) {
    out.clear();
    const std::string cmd =
        std::string(link ? kLinkNetns : "") + "ip " + args + " 2>&1";
    FILE* f = popen(cmd.c_str(), "r");
    if (!f) return -1;
    char buf[512];
    while (fgets(buf, sizeof(buf), f)) out += buf;
    const int st = pclose(f);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

bool ip_ok(const std::string& args, std::string& why, bool link = false) {
    std::string out;
    if (ip(args, out, link) == 0) return true;
    // Keys are on the command line; only show the verb and the error.
    why = "ip " + args.substr(0, args.find(" spi ")) + ": " + trim(out);
    return false;
}

// "if_id 0x..." of the XFRM interface that has addr, or "" if it isn't on
// one.
std::string xfrm_if_id(const std::string& addr) {
    std::string out;
    if (ip("-o addr show to " + addr, out) || out.empty()) return std::string();
    // "731: ims0    inet6 2600:.../64 scope global ..."
    std::stringstream ss(out);
    std::string idx, name;
    ss >> idx >> name;
    name = name.substr(0, name.find('@'));
    if (name.empty() || ip("-d -o link show dev " + name, out))
        return std::string();
    const size_t x = out.find(" xfrm if_id ");
    if (x == std::string::npos) return std::string();
    std::stringstream id(out.substr(x + 12));
    std::string v;
    id >> v;
    return v.empty() ? std::string() : "if_id " + v;
}

std::string host_prefix(const std::string& addr) {
    return addr + (addr.find(':') != std::string::npos ? "/128" : "/32");
}

}  // namespace

// TS 33.203 7.1: the UE's SAs, with u = us (one port), p = the P-CSCF:
//   out  u -> p:port_s  SPI p.spi_s      in  p:port_s -> u  SPI our spi_c
//   out  u -> p:port_c  SPI p.spi_c      in  p:port_c -> u  SPI our spi_s
// Keys (Annex I): hmac-md5-96 IK, hmac-sha-1-96 IK || 32 zero bits,
// aes-cbc CK.
bool IpsecSet::install(const std::string& local, const std::string& remote,
                       uint16_t port, uint32_t spi_c,
                       uint32_t spi_s, const SecMech& server,
                       const std::vector<uint8_t>& ck,
                       const std::vector<uint8_t>& ik, std::string& why) {
    remove();

    if (ik.size() != 16 || (server.ealg == "aes-cbc" && ck.size() != 16)) {
        why = "AKA gave no 128-bit CK/IK";
        return false;
    }

    std::vector<uint8_t> ikey(ik);
    std::string auth;
    if (server.alg == "hmac-sha-1-96") {
        ikey.resize(20, 0);
        auth = "auth-trunc 'hmac(sha1)' " + hex(ikey) + " 96";
    } else {
        auth = "auth-trunc 'hmac(md5)' " + hex(ikey) + " 96";
    }
    const std::string enc = server.ealg == "aes-cbc"
                                ? "enc 'cbc(aes)' " + hex(ck)
                                : std::string("enc 'ecb(cipher_null)' ''");

    struct Sa {
        bool out;
        uint16_t rport;
        uint32_t spi;
    };
    const Sa sas[4] = {
        {true, server.port_s, server.spi_s},
        {false, server.port_s, spi_c},
        {true, server.port_c, server.spi_c},
        {false, server.port_c, spi_s},
    };
    const std::string if_id = xfrm_if_id(local);

    // SIP runs over UDP and TCP on the same ports (RFC 3261 18.1.1: requests
    // over ~1300 bytes, e.g. an incoming INVITE, go over TCP), so the SAs
    // select on addresses only and both protocols get policies.
    static const char* const kProtos[] = {"udp", "tcp"};

    for (size_t i = 0; i < 4; ++i) {
        const Sa& sa = sas[i];
        const uint32_t reqid = kReqidBase + (g_next_reqid++ % kReqidSpan);
        const std::string& src = sa.out ? local : remote;
        const std::string& dst = sa.out ? remote : local;
        const unsigned sport = sa.out ? port : sa.rport;
        const unsigned dport = sa.out ? sa.rport : port;
        char spi[16], ports[48], inport[24];
        re_snprintf(spi, sizeof(spi), "0x%08x", sa.spi);
        re_snprintf(ports, sizeof(ports), "sport %u dport %u", sport, dport);
        re_snprintf(inport, sizeof(inport), "dport %u", dport);

        std::ostringstream state;
        state << "xfrm state add src " << src << " dst " << dst
              << " proto esp spi " << spi << " reqid " << reqid
              << " mode transport replay-window 32 " << auth << " " << enc
              << " sel src " << host_prefix(src) << " dst "
              << host_prefix(dst);
        // The link-netns check below matches templates only against SAs
        // with the interface's if_id; the SPI lookup on input ignores it.
        if (!sa.out && !if_id.empty()) state << " " << if_id;
        if (!ip_ok(state.str(), why)) {
            remove();
            return false;
        }
        reqids_.push_back(reqid);

        for (size_t p = 0; p < 2; ++p) {
            // Inbound, the P-CSCF picks the SA by our port alone, and both
            // of ours are the same: it sends everything (responses from
            // port-s too) on the SA for our spi-s. So inbound policies
            // accept either SA (no reqid).
            std::ostringstream sel;
            sel << "src " << host_prefix(src) << " dst " << host_prefix(dst)
                << " proto " << kProtos[p] << " " << ports << " dir "
                << (sa.out ? "out" : "in");
            std::ostringstream pol;
            pol << "xfrm policy update " << sel.str() << " priority "
                << kPriority << " tmpl src " << src << " dst " << dst
                << " proto esp mode transport";
            if (sa.out) pol << " reqid " << reqid;
            if (!ip_ok(pol.str(), why)) {
                remove();
                return false;
            }
            policies_.push_back(sel.str());

            // One per set and protocol, on our port but any P-CSCF port (it
            // answers from ports other than port-c/port-s). Not addresses
            // only: the interface's own check of the still-encrypted inner
            // ESP (P-CSCF -> us, proto esp) must keep matching charon's
            // tunnel policy.
            const std::string lsel = "src " + host_prefix(src) + " dst " +
                                     host_prefix(dst) + " proto " +
                                     kProtos[p] + " " + inport + " dir in " +
                                     if_id;
            if (!sa.out && !if_id.empty() &&
                std::find(link_policies_.begin(), link_policies_.end(),
                          lsel) == link_policies_.end()) {
                std::ostringstream lpol;
                lpol << "xfrm policy update " << lsel << " priority "
                     << kPriority << " tmpl src " << src << " dst " << dst
                     << " proto esp mode transport";
                if (!ip_ok(lpol.str(), why, true)) {
                    why += " (in the XFRM interface's link netns)";
                    remove();
                    return false;
                }
                link_policies_.push_back(lsel);
            }
        }
    }

    info("ipsec: SAs up, %s/%s, %s:%u <-> %s:%u/%u, SPIs out 0x%08x/0x%08x "
         "in 0x%08x/0x%08x%s%s\n",
         server.alg.c_str(), server.ealg.c_str(), local.c_str(), port,
         remote.c_str(), server.port_s, server.port_c, server.spi_s,
         server.spi_c, spi_c, spi_s, if_id.empty() ? "" : ", link netns ",
         if_id.c_str());
    return true;
}

void IpsecSet::remove() {
    std::string out;
    for (size_t i = 0; i < policies_.size(); ++i)
        ip("xfrm policy delete " + policies_[i], out);
    for (size_t i = 0; i < link_policies_.size(); ++i)
        ip("xfrm policy delete " + link_policies_[i], out, true);
    char r[16];
    for (size_t i = 0; i < reqids_.size(); ++i) {
        re_snprintf(r, sizeof(r), "%u", reqids_[i]);
        ip(std::string("xfrm state deleteall reqid ") + r, out);
    }
    policies_.clear();
    link_policies_.clear();
    reqids_.clear();
}

std::string IpsecSet::stats() const {
    std::string res;
    char r[16];
    for (size_t i = 0; i < reqids_.size(); ++i) {
        std::string out;
        re_snprintf(r, sizeof(r), "%u", reqids_[i]);
        if (ip(std::string("-s xfrm state list reqid ") + r, out)) continue;
        // Keep "src .. dst ..", the spi line, the selector, and the lines
        // after "lifetime current:" and "stats:".
        std::stringstream lines(out);
        std::string line, next;
        while (std::getline(lines, line)) {
            const std::string t = trim(line);
            if (t.compare(0, 4, "src ") == 0 || t.compare(0, 10, "proto esp ") == 0 ||
                t.compare(0, 4, "sel ") == 0) {
                res += "  " + t + "\n";
            } else if (t == "lifetime current:" || t == "stats:") {
                if (std::getline(lines, next)) res += "    " + trim(next) + "\n";
            }
        }
    }
    // Here and in the link netns: behind an XFRM interface, inbound policy
    // drops of our packets are counted there.
    for (int link = 0; link < 2; ++link) {
        FILE* f = popen((std::string(link ? kLinkNetns : "") +
                         "cat /proc/net/xfrm_stat 2>/dev/null")
                            .c_str(),
                        "r");
        if (!f) continue;
        char buf[128];
        std::string nz;
        while (std::fgets(buf, sizeof(buf), f)) {
            char name[64];
            unsigned long v = 0;
            if (std::sscanf(buf, "%63s %lu", name, &v) == 2 && v)
                nz += std::string(" ") + name + "=" + std::to_string(v);
        }
        pclose(f);
        res += std::string(link ? "  xfrm_stat (link netns):" : "  xfrm_stat:") +
               (nz.empty() ? std::string(" all zero") : nz) + "\n";
    }
    // Which inbound policies the link netns has for the interface: ours
    // must sort ahead of charon's (lower priority value).
    if (!link_policies_.empty()) {
        std::string out;
        if (!ip("-o xfrm policy list dir in", out, true)) {
            std::stringstream lines(out);
            std::string line;
            while (std::getline(lines, line)) {
                if (line.find("if_id") == std::string::npos) continue;
                const size_t t = line.find("tmpl");
                std::string l = line.substr(0, t == std::string::npos ? line.size() : t);
                for (size_t i = 0; i < l.size(); ++i)
                    if (l[i] == '\t' || l[i] == '\\') l[i] = ' ';
                res += "  link in-policy: " + trim(l) + "\n";
            }
        }
    }
    // Decrypted packets that never reach the socket show up here instead
    // (bad UDP checksum, no socket on the port, reassembly failures).
    FILE* f = std::fopen("/proc/net/snmp6", "r");
    if (f) {
        char buf[128];
        std::string nz;
        while (std::fgets(buf, sizeof(buf), f)) {
            char name[64];
            unsigned long v = 0;
            if (std::sscanf(buf, "%63s %lu", name, &v) != 2 || !v) continue;
            const std::string n = name;
            if (n.compare(0, 4, "Udp6") == 0 ||
                n.find("Reasm") != std::string::npos ||
                n.find("Discards") != std::string::npos ||
                n.find("Errors") != std::string::npos)
                nz += " " + n + "=" + std::to_string(v);
        }
        std::fclose(f);
        res += "  snmp6:" + (nz.empty() ? std::string(" all zero") : nz) + "\n";
    }
    return res;
}

void IpsecSet::forget_shared(const IpsecSet& other) {
    for (size_t i = 0; i < policies_.size();) {
        bool shared = false;
        for (size_t j = 0; j < other.policies_.size(); ++j)
            shared = shared || policies_[i] == other.policies_[j];
        if (shared)
            policies_.erase(policies_.begin() + long(i));
        else
            ++i;
    }
}

void IpsecSet::flush_stale() {
    char prio[24];
    re_snprintf(prio, sizeof(prio), " priority %u ", kPriority);
    for (int link = 0; link < 2; ++link) {
        std::string out;
        if (ip("-o xfrm policy list", out, link)) continue;
        std::stringstream lines(out);
        std::string line;
        while (std::getline(lines, line)) {
            if (line.find(prio) == std::string::npos) continue;
            // "src A dst B proto P sport X dport Y \tdir D priority N ptype
            // main \ttmpl ... [\tif_id 0x..]"
            const size_t d = line.find("dir ");
            if (d == std::string::npos) continue;
            std::string sel = line.substr(0, line.find_first_of("\t\\", 0));
            std::string del = trim(sel) + " " +
                              line.substr(d, line.find(' ', d + 4) - d);
            // ip prints it after the template: "...\tif_id 0x2a\"
            const size_t x = line.find("if_id ");
            if (x != std::string::npos) {
                std::string v = line.substr(x + 6);
                v = v.substr(0, v.find_first_of(" \t\\"));
                if (!v.empty()) del += " if_id " + v;
            }
            std::string ignored;
            ip("xfrm policy delete " + del, ignored, link);
        }
    }
    std::string out;
    char r[16];
    for (uint32_t i = 0; i < kReqidSpan; ++i) {
        re_snprintf(r, sizeof(r), "%u", kReqidBase + i);
        ip(std::string("xfrm state deleteall reqid ") + r, out);
    }
}

}  // namespace nekoims
