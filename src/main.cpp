// NekoIMS entrypoint
//
// Loads a JSON config, brings up libcurl, libre and baresip (with the AMR and
// G.711 codecs statically linked in), then registers to the IMS core through
// the P-CSCF handed to us by the ePDG dialer. REGISTER and its IMS-AKA
// challenge are handled by ImsRegistration; baresip handles calls, either
// on the local sound card or, in B2BUA mode, bridged to an external SIP UA.
#include "platform.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <re.h>
#include <baresip.h>

#include "b2bua.h"
#include "netns.h"
#include "ims_register.h"
#include "simcard_client.h"
#include "sms.h"

namespace {

const char* const kMmtelIcsi = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";
const int kAsyncWorkers = 4;

struct Settings {
    std::string domain;  // IMS home network domain
    std::string msisdn;  // E.164, e.g. +15551234567 (optional)
    std::string impi;    // default: <IMSI>@<domain>
    std::string impu;    // default: sip:<msisdn or IMSI>@<domain>
    std::string pcscf;   // P-CSCF address from the ePDG dialer
    unsigned pcscf_port = 5060;
    std::string transport = "udp";
    std::string ifname;        // tunnel interface (optional)
    bool sec_agree = false;  // IMS IPsec, see ImsRegConfig
    // IMS leg codecs. baresip's AMR encoder ignores mode-set and sends
    // AMR-WB mode 8 / AMR MR122, so a network that restricts AMR modes (AT&T
    // in incoming offers) needs them left out, e.g. "PCMU": answers follow
    // the offer's codec order, not this one.
    std::string audio_codecs = "AMR-WB/16000,AMR/8000,PCMU,PCMA";
    std::string aka_app = "isim";  // SIM application for IMS AKA
    std::string sip_listen;    // optional, overrides sip_port
    unsigned sip_port = 5060;  // local SIP port on every address
    std::string simcard_server = kDefaultSimcardServer;
    std::string imei;  // for +sip.instance (TS 24.229 5.1.1.2.1)
    std::string user_agent = "NekoIMS/" NEKOIMS_VERSION;
    std::string pani;  // P-Access-Network-Info (optional)
    std::string audio_device = kDefaultAudioDevice;  // ALSA/WASAPI device
    std::vector<std::string> contact_features;
    uint32_t expires = 600000;
    bool debug = false;
    bool sip_trace = false;
    bool ctrl_tcp = false;
    std::string ctrl_tcp_listen = "127.0.0.1:4444";
    bool httpd = false;
    std::string http_listen = "127.0.0.1:8000";
    nekoims::SmsConfig sms;  // SMS over IMS, see sms.h
    bool b2bua = false;  // headless, calls bridged to an external UA
    nekoims::B2buaConfig b2bua_cfg;
};

nekoims::ImsRegistration* g_reg = nullptr;
struct ua* g_ims_ua = nullptr;
std::string g_bye_hdrs;  // see bye_headers_handler()

void usage(const char* argv0) {
    std::fprintf(stderr,
                 "NekoIMS %s\n"
                 "Usage: %s [-c config.json] [-p pcscf] [-v] [-t] [-h]\n"
                 "  -c <path>  Config file (default: %s)\n"
                 "  -p <addr>  P-CSCF (overrides config; default: config, then\n"
                 "             the first line of %s)\n"
                 "  -v         Verbose/debug logging\n"
                 "  -t         SIP trace\n"
                 "  -h         Show this help\n",
                 NEKOIMS_VERSION, argv0, default_config_path().c_str(),
                 pcscf_file().c_str());
}

// First address in the dialer's P-CSCF file, skipping blank and # lines.
bool read_pcscf_file(const std::string& path, std::string& out) {
    std::ifstream in(path.c_str());
    std::string line;
    while (std::getline(in, line)) {
        const size_t b = line.find_first_not_of(" \t\r");
        if (b == std::string::npos || line[b] == '#') continue;
        const size_t e = line.find_last_not_of(" \t\r");
        out = line.substr(b, e - b + 1);
        return true;
    }
    return false;
}

bool sms_mode(const nlohmann::json& j, const char* key,
              nekoims::SmsConfig::Mode& out) {
    const std::string v = j.value(key, std::string("plain"));
    if (v == "plain")
        out = nekoims::SmsConfig::Plain;
    else if (v == "binary_b64")
        out = nekoims::SmsConfig::BinaryB64;
    else if (v == "off")
        out = nekoims::SmsConfig::Off;
    else
        return false;
    return true;
}

// "sms": {"rx": "plain", "tx": "plain", "format": "auto", "smsc": ""}
bool sms_settings(const nlohmann::json& j, nekoims::SmsConfig& out,
                  const std::string& path) {
    const std::string format = j.value("format", std::string("auto"));
    out.smsc = j.value("smsc", out.smsc);

    if (format == "3gpp")
        out.format = nekoims::sms::Format::Gpp;
    else if (format == "3gpp2")
        out.format = nekoims::sms::Format::Gpp2;
    else if (format != "auto") {
        std::fprintf(stderr, "nekoims: %s: sms.format must be auto, 3gpp or "
                     "3gpp2\n", path.c_str());
        return false;
    }

    if (!sms_mode(j, "rx", out.rx) || !sms_mode(j, "tx", out.tx)) {
        std::fprintf(stderr, "nekoims: %s: sms.rx and sms.tx must be plain, "
                     "binary_b64 or off\n", path.c_str());
        return false;
    }
    return true;
}

bool load_settings(const std::string& path, Settings& out) {
    std::ifstream in(path.c_str());
    if (!in) {
        std::fprintf(stderr, "nekoims: cannot open config '%s'\n",
                     path.c_str());
        return false;
    }

    try {
        nlohmann::json j = nlohmann::json::parse(in);

        out.domain = j.at("domain").get<std::string>();
        out.pcscf = j.value("pcscf", out.pcscf);
        out.msisdn = j.value("msisdn", out.msisdn);
        out.impi = j.value("impi", out.impi);
        out.impu = j.value("impu", out.impu);
        out.pcscf_port = j.value("pcscf_port", out.pcscf_port);
        out.transport = j.value("transport", out.transport);
        out.ifname = j.value("interface", out.ifname);
        out.sip_listen = j.value("sip_listen", out.sip_listen);
        out.sip_port = j.value("sip_port", out.sip_port);
        out.simcard_server = j.value("simcard_server", out.simcard_server);
        out.imei = j.value("imei", out.imei);
        out.user_agent = j.value("user_agent", out.user_agent);
        out.pani = j.value("p_access_network_info", out.pani);
        out.audio_device = j.value("audio_device", out.audio_device);
        out.expires = j.value("expires", out.expires);
        out.debug = j.value("debug", out.debug);
        out.sip_trace = j.value("sip_trace", out.sip_trace);
        out.ctrl_tcp = j.value("ctrl_tcp", out.ctrl_tcp);
        out.ctrl_tcp_listen = j.value("ctrl_tcp_listen", out.ctrl_tcp_listen);
        out.httpd = j.value("httpd", out.httpd);
        out.http_listen = j.value("http_listen", out.http_listen);
        out.sec_agree = j.value("sec_agree", out.sec_agree);
        out.aka_app = j.value("aka_app", out.aka_app);
        out.audio_codecs = j.value("audio_codecs", out.audio_codecs);
        if (out.aka_app != "isim" && out.aka_app != "usim") {
            std::fprintf(stderr,
                         "nekoims: %s: \"aka_app\" must be \"isim\" or "
                         "\"usim\"\n",
                         path.c_str());
            return false;
        }

        if (j.contains("sms") &&
            !sms_settings(j["sms"], out.sms, path))
            return false;
        if (j.contains("sms_mode"))
            std::fprintf(stderr,
                         "nekoims: %s: \"sms_mode\" is gone, use "
                         "\"sms\": {\"rx\": ..., \"tx\": ...}\n",
                         path.c_str());

        if (j.contains("contact_features"))
            out.contact_features =
                j["contact_features"].get<std::vector<std::string> >();
        else
            out.contact_features = {
                std::string("+g.3gpp.icsi-ref=\"") + kMmtelIcsi + "\"",
                "+sip.instance=\"<{imei_urn}>\"",
                "audio",
            };
        // Without it the network keeps SMS off IMS (TS 24.341 5.3.1.2)
        if (out.sms.rx != nekoims::SmsConfig::Off &&
            !j.contains("contact_features"))
            out.contact_features.push_back("+g.3gpp.smsip");

        if (j.contains("b2bua")) {
            const nlohmann::json& b = j["b2bua"];
            nekoims::B2buaConfig& c = out.b2bua_cfg;

            out.b2bua = b.value("enabled", out.b2bua);
            c.username = b.value("username", c.username);
            c.password = b.value("password", c.password);
            c.target = b.value("target", c.target);
            c.audio_codecs = b.value("audio_codecs", c.audio_codecs);
            c.listen = b.value("listen", c.listen);
            c.netns = b.value("netns", c.netns);
            if (!c.netns.empty() && kPlatform != Platform::Linux) {
                std::fprintf(stderr, "nekoims: %s: b2bua.netns is Linux "
                             "only, set b2bua.listen to the address the "
                             "external UA reaches\n", path.c_str());
                return false;
            }
            if (!c.netns.empty() && c.listen.empty()) {
                std::fprintf(stderr, "nekoims: %s: b2bua.netns needs "
                             "b2bua.listen\n", path.c_str());
                return false;
            }
        }
    } catch (const nlohmann::json::exception& e) {
        std::fprintf(stderr, "nekoims: bad config '%s': %s\n", path.c_str(),
                     e.what());
        return false;
    }

    // ipsec_windows.cpp has no SAs to install, so REGISTER could only fail
    if (out.sec_agree && kPlatform == Platform::Windows) {
        std::fprintf(stderr, "nekoims: %s: sec_agree (IMS IPsec, needed by "
                     "this carrier) is only implemented on Linux\n",
                     path.c_str());
        return false;
    }

    if (out.transport != "udp" && out.transport != "tcp") {
        std::fprintf(stderr, "nekoims: transport must be udp or tcp\n");
        return false;
    }

    return true;
}

// RFC 7254: urn:gsma:imei:TAC(8)-SNR(6)-spare(1)
std::string imei_urn(const std::string& imei) {
    if (imei.size() != 15 ||
        imei.find_first_not_of("0123456789") != std::string::npos)
        return std::string();

    return "urn:gsma:imei:" + imei.substr(0, 8) + "-" + imei.substr(8, 6) +
           "-" + imei.substr(14, 1);
}

std::string contact_params(const Settings& s) {
    const std::string urn = imei_urn(s.imei);
    std::string out;

    for (size_t i = 0; i < s.contact_features.size(); ++i) {
        std::string f = s.contact_features[i];
        const size_t pos = f.find("{imei_urn}");
        if (pos != std::string::npos) {
            if (urn.empty()) continue;
            f.replace(pos, std::strlen("{imei_urn}"), urn);
        }
        out += ";" + f;
    }

    return out;
}

std::string pcscf_uri(const Settings& s) {
    const bool v6 = s.pcscf.find(':') != std::string::npos;
    std::ostringstream u;

    u << "sip:" << (v6 ? "[" : "") << s.pcscf << (v6 ? "]" : "") << ":"
      << s.pcscf_port << ";transport=" << s.transport;

    return u.str();
}

std::string uri_user(const std::string& uri) {
    const size_t colon = uri.find(':');
    const size_t at = uri.find('@');
    if (colon == std::string::npos || at == std::string::npos || at < colon)
        return std::string();
    return uri.substr(colon + 1, at - colon - 1);
}

// baresip config, unlike normal baresip it's not in disk but rather in memory,
// so we can generate it from the JSON config.
std::string baresip_config(const Settings& s) {
    std::ostringstream c;

    c << "sip_transports\tudp,tcp\n";
    // An unspecified address applies the port to every local address, so
    // the Contact port is stable (MT requests are sent to it).
    // This might be undesirable when not in a Linux network namespace, TBD.
    if (!s.sip_listen.empty())
        c << "sip_listen\t" << s.sip_listen << "\n";
    else
        c << "sip_listen\t0.0.0.0:" << s.sip_port << "\n";
    // The interface filter would also hide the LAN addresses the external
    // UA is reached on; with b2bua.listen that one is added back in main().
    if (!s.ifname.empty() && (!s.b2bua || !s.b2bua_cfg.listen.empty()))
        c << "net_interface\t" << s.ifname << "\n";
    if (s.pcscf.find(':') != std::string::npos) c << "net_prefer_ipv6\tyes\n";

    if (s.b2bua) {
        // Both legs of a call are cross-connected through aubridge, which
        // needs one sample format on both sides; auresamp converts each
        // codec to it. B2bua accepts INVITEs itself (to authenticate them).
        c << "audio_player\taubridge,nil\n"
          << "audio_source\taubridge,nil\n"
          << "audio_alert\taubridge,nil\n"
          << "auplay_srate\t16000\n"
          << "ausrc_srate\t16000\n"
          << "auplay_channels\t1\n"
          << "ausrc_channels\t1\n"
          << "call_accept\tno\n";
    } else {
        c << "audio_player\t" << kAudioModule << "," << s.audio_device << "\n"
          << "audio_source\t" << kAudioModule << "," << s.audio_device << "\n"
          << "audio_alert\t" << kAudioModule << "," << s.audio_device << "\n";
    }

    // stdio/wincons + menu: interactive keys (d = dial, a = answer, b = hangup)
    // misleading names aside, these modules aren't *actually* loaded from disk,
    // they're statically linked in. The module.so declarations are still
    // necessary for baresip to use them, though. B2BUA mode is headless: the
    // menu would accept, answer and ring calls on its own.
    if (!s.b2bua)
        c << "module\t" << kConsoleModule << ".so\n"
          << "module\tmenu.so\n"
          << "module\t" << kAudioModule << ".so\n";
    else
        c << "module\taubridge.so\n";

    c << "module\tg711.so\n"
      << "module\tamr.so\n"
      << "module\tauconv.so\n"
      << "module\tauresamp.so\n"
      << "module\tausine.so\n"
      << "module\taufile.so\n";

    // Commands come from the menu module, which B2BUA mode doesn't load;
    // there these mostly just report events (ctrl_tcp).
    if (s.ctrl_tcp)
        c << "module\tctrl_tcp.so\n"
          << "ctrl_tcp_listen\t" << s.ctrl_tcp_listen << "\n";
    if (s.httpd)
        c << "module\thttpd.so\n"
          << "http_listen\t" << s.http_listen << "\n";


    return c.str();
}

// regint=0: baresip must not register; ImsRegistration owns REGISTER.
std::string ua_aor(const std::string& impu, const Settings& s) {
    std::ostringstream a;

    a << "<" << impu << ">"
      << ";regint=0"
      << ";outbound=\"" << pcscf_uri(s) << "\""
      << ";100rel=yes"
      << ";audio_codecs=" << s.audio_codecs;

    return a.str();
}

// LABEL: BareSIP bug workaround
//
// baresip stops the audio stream on any 18x without SDP, even when a
// previous reliable 183 already carried the SDP answer (early media). Verizon
// sends 183 (SDP) -> 180 (no SDP) -> 200 OK (no SDP), so the stream is
// stopped at 180 and never restarted, leaving outgoing calls silent. Per
// RFC 3960 the early media session continues, so restart it here once a
// remote SDP answer is known.
// ^^ Via Claude Opus 5.5, this information has not been personally verified
// fully by a human. Please don't make a bug report based on it upstream unless
// *you* verify it.
void early_media_fix_handler(enum bevent_ev ev, struct bevent* event,
                             void* arg) {
    (void)arg;

    if (ev != BEVENT_CALL_RINGING && ev != BEVENT_CALL_ESTABLISHED) return;

    struct call* call = bevent_get_call(event);
    struct audio* au = call_audio(call);
    if (!au || audio_started(au)) return;

    // No remote format means no SDP answer yet: a plain 180, leave it.
    if (!sdp_media_rformat(stream_sdpmedia(audio_strm(au)), NULL)) return;

    info("nekoims: restarting audio stopped by SDP-less %s\n",
         ev == BEVENT_CALL_RINGING ? "18x" : "200");

    int err = call_update_media(call);
    if (err) warning("nekoims: audio restart failed: %m\n", err);
}

// Makes our BYEs look like a Verizon handset's (TS 24.229).
//
// Verizon handsets send Reason: SIP;cause=200;text="User Triggered" on
// hangup. Without it, a Google Pixel we hang up on keeps a stale call slot in
// its modem and rejects every later call from us until its IMS stack
// restarts. They also send P-Access-Network-Info and P-Preferred-Identity,
// which the network uses when releasing the session. It's still a mistrery
// why this bug only affects Google Pixel phones, but we this also brings us
// closer to the iPhone VoWiFi behavior, which is a good thing.
//
// Needs call_set_close_headers() from patches/baresip. libre also sends these
// on our 200 OK when the peer hangs up. IMS calls only, not B2BUA LAN legs.
void bye_headers_handler(enum bevent_ev ev, struct bevent* event, void* arg) {
    (void)arg;

    if (ev != BEVENT_CALL_ANSWERED && ev != BEVENT_CALL_ESTABLISHED) return;
    if (call_get_ua(bevent_get_call(event)) != g_ims_ua) return;

    int err = call_set_close_headers(bevent_get_call(event), "%s",
                                     g_bye_hdrs.c_str());
    if (err) warning("nekoims: cannot set BYE headers: %m\n", err);
}

struct Laddr {
    std::string ifname;
    struct sa sa;
};

bool collect_laddr(const char* ifname, const struct sa* sa, void* arg) {
    Laddr l;
    l.ifname = ifname ? ifname : "?";
    l.sa = *sa;
    static_cast<std::vector<Laddr>*>(arg)->push_back(l);
    return false;
}

void reg_stopped(void* arg) {
    (void)arg;
    re_cancel();
}

// Menu "quit" (ua_stop_all) ends here once baresip's SIP stack has drained;
// the stack is still usable, so deregister from IMS before leaving.
void uag_exit_handler(void* arg) {
    (void)arg;

    if (g_reg)
        g_reg->stop(reg_stopped, NULL);
    else
        re_cancel();
}

void signal_handler(int sig) {
    static bool term = false;

    if (term) {
        module_app_unload();
        mod_close();
        std::exit(0);
    }

    term = true;
    info("nekoims: terminated by signal %d\n", sig);

    if (g_reg)
        g_reg->stop(reg_stopped, NULL);
    else
        re_cancel();
}

}  // namespace

int main(int argc, char* argv[]) {
    std::string config_path = default_config_path();
    const std::string pcscf_path = pcscf_file();
    bool verbose = false;
    bool trace = false;
    std::string pcscf;

    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "-c") && i + 1 < argc) {
            config_path = argv[++i];
        } else if (!std::strcmp(argv[i], "-p") && i + 1 < argc) {
            pcscf = argv[++i];
        } else if (!std::strcmp(argv[i], "-v")) {
            verbose = true;
        } else if (!std::strcmp(argv[i], "-t")) {
            trace = true;
        } else if (!std::strcmp(argv[i], "-h")) {
            usage(argv[0]);
            return EXIT_SUCCESS;
        } else {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    // Keep logs live when piped (e.g. to tee); stdbuf can't reach a
    // static binary. The MSVC CRT has no line buffering (_IOLBF means full
    // buffering and rejects size 0), so go unbuffered there.
    if (kPlatform == Platform::Linux) {
        std::setvbuf(stdout, NULL, _IOLBF, 0);
    } else if (kPlatform == Platform::Windows) {
        std::setvbuf(stdout, NULL, _IONBF, 0);
    }

    Settings settings;
    if (!load_settings(config_path, settings)) return EXIT_FAILURE;
    if (!pcscf.empty()) settings.pcscf = pcscf;
    if (settings.pcscf.empty() &&
        read_pcscf_file(pcscf_path, settings.pcscf))
        std::fprintf(stderr, "nekoims: using P-CSCF %s from %s\n",
                     settings.pcscf.c_str(), pcscf_path.c_str());
    if (settings.pcscf.empty()) {
        std::fprintf(stderr,
                     "nekoims: no P-CSCF, pass -p <addr>, set \"pcscf\" in "
                     "%s or bring up the ePDG dialer (%s)\n",
                     config_path.c_str(), pcscf_path.c_str());
        return EXIT_FAILURE;
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        std::fprintf(stderr, "nekoims: curl_global_init failed\n");
        return EXIT_FAILURE;
    }

    int err = libre_init();
    if (err) {
        std::fprintf(stderr, "nekoims: libre_init failed (%d)\n", err);
        curl_global_cleanup();
        return EXIT_FAILURE;
    }

    if (verbose || settings.debug) log_enable_debug(true);

    info("NekoIMS %s (baresip %s)\n", NEKOIMS_VERSION, baresip_version());

    nekoims::SimcardClient sim(settings.simcard_server);
    std::unique_ptr<nekoims::ImsRegistration> reg;
    std::unique_ptr<nekoims::Netns> netns;  // b2bua.netns
    std::unique_ptr<nekoims::B2bua> b2bua;
    std::unique_ptr<nekoims::Sms> sms;
    nekoims::ImsRegConfig rc;
    std::string ua_id;  // identity for calls and SMS, see below
    struct ua* ua = NULL;
    const std::string conf = baresip_config(settings);

    // Identities: TS 23.003 13.3 (IMPI) and 13.4B (temporary IMPU)
    rc.domain = settings.domain;
    rc.impi = settings.impi;
    rc.impu = settings.impu;
    if (rc.impi.empty() || (rc.impu.empty() && settings.msisdn.empty())) {
        std::string imsi, why;
        if (!sim.imsi(imsi, why)) {
            warning("nekoims: cannot read IMSI from %s: %s\n",
                    settings.simcard_server.c_str(), why.c_str());
            err = EIO;
            goto out;
        }
        if (rc.impi.empty()) rc.impi = imsi + "@" + settings.domain;
        if (rc.impu.empty() && settings.msisdn.empty())
            rc.impu = "sip:" + imsi + "@" + settings.domain;
    }
    if (rc.impu.empty())
        rc.impu = "sip:" + settings.msisdn + "@" + settings.domain;

    // Calls, SMS and the Contact use the number: an ISIM's IMPU is often a
    // barred, IMSI-based identity that can register but not call.
    ua_id = settings.msisdn.empty()
                ? rc.impu
                : "sip:" + settings.msisdn + "@" + settings.domain;
    rc.contact_user = uri_user(ua_id);
    rc.outbound = pcscf_uri(settings);
    rc.contact_params = contact_params(settings);
    rc.expires = settings.expires;
    rc.user_agent = settings.user_agent;
    rc.sec_agree = settings.sec_agree;
    rc.aka_app = settings.aka_app;
    rc.sec_port = uint16_t(settings.sip_port);
    rc.sec_proto = settings.transport;
    if (settings.sec_agree && !settings.sip_listen.empty())
        warning("nekoims: sec_agree uses sip_port %u for its SAs; make sure "
                "sip_listen listens there\n", settings.sip_port);
    if (!settings.pani.empty())
        rc.headers.push_back(std::make_pair(
            std::string("P-Access-Network-Info"), settings.pani));

    if (settings.b2bua && !settings.ifname.empty() &&
        settings.b2bua_cfg.listen.empty())
        warning(
            "nekoims: b2bua: ignoring \"interface\" (%s), set b2bua.listen "
            "to keep it and add the external UA's address\n",
            settings.ifname.c_str());

    if (imei_urn(settings.imei).empty())
        warning(
            "nekoims: no valid 15-digit IMEI configured, "
            "registering without +sip.instance\n");

    err = conf_configure_buf(reinterpret_cast<const uint8_t*>(conf.data()),
                             conf.size());
    if (err) {
        warning("nekoims: configure failed: %m\n", err);
        goto out;
    }

    re_thread_async_init(kAsyncWorkers);

    err = baresip_init(conf_config());
    if (err) {
        warning("nekoims: baresip init failed: %m\n", err);
        goto out;
    }

    // Fix for windows including Link Local IPv4 addresses on 
    // any adapter without an IPv4. You can't bind to these 
    // addresses (it seems) so BareSIP will crash when trying to. 
    {
        std::vector<Laddr> all;
        net_laddr_apply(baresip_network(), collect_laddr, &all);
        for (size_t i = 0; i < all.size(); ++i) {
            if (sa_af(&all[i].sa) == AF_INET &&
                (sa_in(&all[i].sa) >> 16) == 0xa9fe)
                net_rm_address(baresip_network(), &all[i].sa);
        }
    }

    // b2bua.listen: ua_init() below opens SIP sockets on each of baresip's
    // addresses, so reduce them to the listen address plus the IMS side (the
    // interface's addresses, or else just the one the P-CSCF is reached
    // from). The listen address can be anything bindable, e.g. 127.0.0.2,
    // which interface enumeration would never list.
    //
    // It goes first: libre sends from the socket whose address the kernel
    // would route from, else the first one of the right family. The IMS side
    // always matches its route, the external UA may not (127.0.0.2 talking
    // to 127.0.0.1 is routed from 127.0.0.1).
    //
    // With b2bua.netns the listen address is in another namespace, so its
    // sockets are opened there after ua_init(). libre still picks sockets by
    // routing in this namespace, which can't see that one; it only keeps
    // them apart by address family. So the IMS side drops the listen
    // address's family, and must not need it for the P-CSCF.
    if (settings.b2bua && !settings.b2bua_cfg.listen.empty()) {
        struct network* net = baresip_network();
        const bool other_ns = !settings.b2bua_cfg.netns.empty();
        std::vector<Laddr> ims;
        struct sa lan, pcscf;

        if (sa_set_str(&lan, settings.b2bua_cfg.listen.c_str(), 0)) {
            warning("nekoims: b2bua.listen must be an IP address: %s\n",
                    settings.b2bua_cfg.listen.c_str());
            err = EINVAL;
            goto out;
        }

        if (sa_set_str(&pcscf, settings.pcscf.c_str(), settings.pcscf_port)) {
            warning("nekoims: b2bua.listen: P-CSCF must be an IP address\n");
            err = EINVAL;
            goto out;
        }
        if (other_ns && sa_af(&pcscf) == sa_af(&lan)) {
            warning("nekoims: b2bua.netns: the P-CSCF (%j) and b2bua.listen "
                    "(%j) are both %s; in another namespace the listen "
                    "address must be the other IP version\n",
                    &pcscf, &lan, sa_af(&lan) == AF_INET ? "IPv4" : "IPv6");
            err = EINVAL;
            goto out;
        }

        if (!settings.ifname.empty()) {
            net_laddr_apply(net, collect_laddr, &ims);
        } else {
            Laddr l;
            l.ifname = "ims";
            if (net_dst_source_addr_get(&pcscf, &l.sa)) {
                warning("nekoims: b2bua.listen: no route to the P-CSCF %s, "
                        "set \"interface\"\n", settings.pcscf.c_str());
                err = EHOSTUNREACH;
                goto out;
            }
            ims.push_back(l);
        }

        net_flush_addresses(net);
        if (!other_ns) err = net_add_address_ifname(net, &lan, "b2bua");
        for (size_t i = 0; !err && i < ims.size(); ++i) {
            if (other_ns && sa_af(&ims[i].sa) == sa_af(&lan)) continue;
            err = net_add_address_ifname(net, &ims[i].sa, ims[i].ifname.c_str());
        }
        if (err) {
            warning("nekoims: b2bua.listen: cannot set addresses: %m\n", err);
            goto out;
        }
    }

    err = ua_init(settings.user_agent.c_str(), true, true, false);
    if (err) {
        warning("nekoims: ua init failed: %m\n", err);
        goto out;
    }

    uag_set_exit_handler(uag_exit_handler, NULL);

    // b2bua.netns: the external UA's SIP sockets, opened in its namespace.
    // The address is also given to baresip for picking media addresses,
    // after ua_init() so baresip opens no SIP socket on it here.
    if (settings.b2bua && !settings.b2bua_cfg.netns.empty()) {
        struct sa lan, sip;
        uint16_t port = settings.sip_port;
        if (!settings.sip_listen.empty() &&
            !sa_decode(&sip, settings.sip_listen.c_str(),
                       settings.sip_listen.size()))
            port = sa_port(&sip);
        (void)sa_set_str(&lan, settings.b2bua_cfg.listen.c_str(), port);

        netns.reset(new nekoims::Netns());
        err = netns->open(settings.b2bua_cfg.netns);
        if (err) goto out;

        {
            nekoims::NetnsScope in_lan(netns.get(), true);
            err = sip_transp_add(uag_sip(), SIP_TRANSP_UDP, &lan);
            if (!err) err = sip_transp_add(uag_sip(), SIP_TRANSP_TCP, &lan);
        }
        if (!err) err = net_add_address_ifname(baresip_network(), &lan, "b2bua");
        if (err) {
            warning("nekoims: b2bua: cannot listen on %J in %s: %m\n", &lan,
                    settings.b2bua_cfg.netns.c_str(), err);
            goto out;
        }
        info("nekoims: b2bua: listening on %J in %s\n", &lan,
             settings.b2bua_cfg.netns.c_str());
    }

    if (trace || settings.sip_trace) uag_enable_sip_trace(true);

    // Before conf_modules(), so it sees MESSAGE ahead of baresip
    if (settings.sms.rx != nekoims::SmsConfig::Off ||
        settings.sms.tx != nekoims::SmsConfig::Off) {
        nekoims::SmsConfig sc = settings.sms;
        sc.deliver = !settings.b2bua || settings.ctrl_tcp;  // menu/ctrl_tcp
        sc.impu = ua_id;
        sc.domain = settings.domain;
        sc.outbound = rc.outbound;
        sc.pani = settings.pani;
        sms.reset(new nekoims::Sms(uag_sip(), sc));
        err = sms->start();
        if (err) {
            warning("nekoims: sms setup failed: %m\n", err);
            goto out;
        }
    }

    err = conf_modules();
    if (err) {
        warning("nekoims: loading modules failed: %m\n", err);
        goto out;
    }

    err = bevent_register(early_media_fix_handler, NULL);
    if (!err) err = bevent_register(bye_headers_handler, NULL);
    if (err) {
        warning("nekoims: event handler setup failed: %m\n", err);
        goto out;
    }

    err = ua_alloc(&ua, ua_aor(ua_id, settings).c_str());
    if (err) {
        warning("nekoims: account setup failed: %m\n", err);
        goto out;
    }
    g_ims_ua = ua;

    // BareSIP by default will set the SDP to state the default route's address
    // This is not okay since the PCSCF route (through the ePDG ) is
    // not the default route. Since Windows doesn't support network 
    // namespaces, we have to patch BareSIP to state the known VPN
    // address instead of the default route.
    {
        struct sa pcscf, media;
        if (!sa_set_str(&pcscf, settings.pcscf.c_str(), settings.pcscf_port) &&
            !net_dst_source_addr_get(&pcscf, &media)) {
            ua_set_media_laddr(ua, &media);
            info("nekoims: IMS media on %j\n", &media);
        }
    }

    // IMS headers for requests baresip sends (INVITE etc.), TS 24.229 5.1.2A
    {
        std::vector<std::pair<std::string, std::string> > hdrs;
        hdrs.push_back(std::make_pair(std::string("P-Preferred-Identity"),
                                      "<" + ua_id + ">"));
        hdrs.push_back(std::make_pair(
            std::string("P-Preferred-Service"),
            std::string("urn:urn-7:3gpp-service.ims.icsi.mmtel")));
        hdrs.push_back(std::make_pair(
            std::string("Accept-Contact"),
            std::string("*;+g.3gpp.icsi-ref=\"") + kMmtelIcsi + "\""));
        if (!settings.pani.empty())
            hdrs.push_back(std::make_pair(std::string("P-Access-Network-Info"),
                                          settings.pani));

        for (size_t i = 0; i < hdrs.size(); ++i) {
            struct pl name, val;
            pl_set_str(&name, hdrs[i].first.c_str());
            pl_set_str(&val, hdrs[i].second.c_str());
            ua_add_custom_hdr(ua, &name, &val);
        }

        // and P-Access-Network-Info on responses to INVITE (TS 24.229
        // 5.1.4.2): AT&T cancels calls whose 180 has none ("Invalid
        // Location"). Needs ua_set_resp_headers() from patches/baresip.
        if (!settings.pani.empty())
            ua_set_resp_headers(
                ua, ("P-Access-Network-Info: " + settings.pani + "\r\n").c_str());

        // Handsets repeat these on BYE (TS 24.229 5.1.5)
        g_bye_hdrs = "Reason: SIP;cause=200;text=\"User Triggered\"\r\n";
        for (size_t i = 0; i < hdrs.size(); ++i) {
            if (hdrs[i].first == "P-Preferred-Identity" ||
                hdrs[i].first == "P-Access-Network-Info")
                g_bye_hdrs += hdrs[i].first + ": " + hdrs[i].second + "\r\n";
        }
    }

    if (settings.b2bua) {
        settings.b2bua_cfg.ims_domain = settings.domain;
        b2bua.reset(new nekoims::B2bua(settings.b2bua_cfg, ua));
        b2bua->set_netns(netns.get());
        err = b2bua->start();
        if (err) {
            warning("nekoims: b2bua setup failed: %m\n", err);
            goto out;
        }

        if (sms) {
            nekoims::B2bua* b = b2bua.get();
            nekoims::SmsLan lan;
            lan.ua = b->lan_ua();
            lan.authorized = [b](const struct sip_msg* m) {
                return b->authorized(m);
            };
            lan.target = [b]() { return b->lan_target(); };
            sms->set_lan(lan);
        }
    }

    // With sec-agree, calls follow REGISTER to the P-CSCF's protected port
    // and carry Security-Verify (TS 24.229 5.1.2A.1.1).
    if (rc.sec_agree) {
        rc.on_route_change = [ua]() {
            if (!g_reg) return;
            account_set_outbound(ua_account(ua), g_reg->outbound().c_str(), 0);
            const char* names[] = {"Security-Verify", "Require",
                                   "Proxy-Require"};
            for (size_t i = 0; i < 3; ++i) {
                struct pl name;
                pl_set_str(&name, names[i]);
                ua_rm_custom_hdr(ua, &name);
            }
            const std::string sv = g_reg->security_verify();
            if (sv.empty()) return;
            const std::string vals[] = {sv, "sec-agree", "sec-agree"};
            for (size_t i = 0; i < 3; ++i) {
                struct pl name, val;
                pl_set_str(&name, names[i]);
                pl_set_str(&val, vals[i].c_str());
                ua_add_custom_hdr(ua, &name, &val);
            }
        };
    }

    // Assert the identity the registration says we have, not the (often
    // barred) ISIM IMPU we registered (TS 24.229 5.1.2A.1.1).
    rc.on_identity_change = [ua]() {
        if (!g_reg) return;
        const std::string ppi = "<" + g_reg->preferred_identity() + ">";
        struct pl name, val;
        pl_set_str(&name, "P-Preferred-Identity");
        ua_rm_custom_hdr(ua, &name);
        pl_set_str(&val, ppi.c_str());
        ua_add_custom_hdr(ua, &name, &val);

        const std::string key = "P-Preferred-Identity: ";
        const size_t a = g_bye_hdrs.find(key);
        if (a != std::string::npos) {
            const size_t e = g_bye_hdrs.find("\r\n", a);
            g_bye_hdrs.replace(a + key.size(), e - a - key.size(), ppi);
        }
    };

    reg.reset(new nekoims::ImsRegistration(uag_sip(), rc, sim));
    g_reg = reg.get();
    if (sms) sms->set_ims(reg.get(), ua);

    err = reg->start();
    if (err) {
        warning("nekoims: register failed: %m\n", err);
        goto out;
    }

    err = re_main(signal_handler);

out:
    g_reg = nullptr;
    sms.reset();
    reg.reset();
    b2bua.reset();

    bevent_unregister(bye_headers_handler);
    bevent_unregister(early_media_fix_handler);
    ua_stop_all(true);
    ua_close();
    module_app_unload();
    conf_close();
    baresip_close();
    mod_close();
    re_thread_async_close();
    libre_close();

    curl_global_cleanup();

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
