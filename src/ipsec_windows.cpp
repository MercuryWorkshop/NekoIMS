// Windows implementation of IpsecSet, included by ipsec.cpp. Not built on
// its own.
//
// There is no ip xfrm here; sec-agree would need transport-mode SAs through
// WFP (IPsecSaContextCreate and friends). Until then registration fails with
// a clear reason when sec_agree is on.

namespace nekoims {

bool IpsecSet::install(const std::string&, const std::string&, uint16_t,
                       uint32_t, uint32_t, const SecMech&,
                       const std::vector<uint8_t>&,
                       const std::vector<uint8_t>&, std::string& why) {
    why = "sec_agree IPsec is only implemented on Linux";
    return false;
}

void IpsecSet::remove() {}

std::string IpsecSet::stats() const { return std::string(); }

void IpsecSet::forget_shared(const IpsecSet&) {}

void IpsecSet::flush_stale() {}

}  // namespace nekoims
