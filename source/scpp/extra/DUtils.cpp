// Copyright Mathias Lang
// Not originally part of SCP but required for the D side to work

#include "DUtils.h"
#include "xdrpp/marshal.h"
#include "xdr/Stellar-SCP.h"
#include <functional>

using namespace xdr;
using namespace stellar;

std::set<unsigned int>* makeTestSet()
{
    std::set<unsigned int>* set = new std::set<unsigned int>({1, 2, 3, 4, 5});
    return set;
}

template <typename T>
void* makeStdSet()
{
    std::set<T>* set = new std::set<T>();
    return set;
}

opaque_vec<> XDRToOpaque(const xdr::xvector<unsigned char>& param)
{
    return xdr::xdr_to_opaque(param);
}
opaque_vec<> XDRToOpaque(const stellar::SCPQuorumSet& param)
{
    return xdr::xdr_to_opaque(param);
}
opaque_vec<> XDRToOpaque(const stellar::SCPStatement& param)
{
    return xdr::xdr_to_opaque(param);
}

#define PUSHBACKINST1(T) template void push_back<T, xvector<T>>(xvector<T>&, T&);
#define PUSHBACKINST2(T, VT) template void push_back<T, VT>(VT&, T&);
#define PUSHBACKINST3(T, V) template void push_back<T, V<T>>(V<T>&, T&);

PUSHBACKINST1(unsigned char)
PUSHBACKINST1(xvector<unsigned char>)
PUSHBACKINST1(SCPEnvelope)
PUSHBACKINST1(PublicKey)
PUSHBACKINST1(SCPQuorumSet)

PUSHBACKINST2(const SCPEnvelope, xvector<SCPEnvelope>)
PUSHBACKINST2(const SCPBallot, xvector<SCPBallot>)
PUSHBACKINST2(const SCPEnvelope, std::vector<SCPEnvelope>)
PUSHBACKINST2(const SCPBallot, std::vector<SCPBallot>)
PUSHBACKINST2(const PublicKey, xvector<PublicKey>)
PUSHBACKINST3(xvector<unsigned char>, std::vector)
PUSHBACKINST3(unsigned char, std::vector)

PUSHBACKINST3(PublicKey, std::vector)
PUSHBACKINST3(SCPEnvelope, std::vector)
PUSHBACKINST3(SCPBallot, std::vector)
PUSHBACKINST3(SCPQuorumSet, std::vector)

template opaque_vec<> duplicate<opaque_vec<>>(opaque_vec<> const&);

#define CPPSETFOREACHINST(T) template int cpp_set_foreach<T>(void*, void*, void*);
CPPSETFOREACHINST(Value)
CPPSETFOREACHINST(SCPBallot)
CPPSETFOREACHINST(PublicKey)
CPPSETFOREACHINST(unsigned int)

#define CPPSETEMPTYINST(T) template bool cpp_set_empty<T>(const void*);
CPPSETEMPTYINST(Value)
CPPSETEMPTYINST(unsigned int)
CPPSETEMPTYINST(SCPBallot)
CPPSETEMPTYINST(PublicKey)

#define CPPSETSIZEINST(T) template size_t cpp_set_size<T>(const void*);
CPPSETSIZEINST(Value)
CPPSETSIZEINST(unsigned int)
CPPSETSIZEINST(SCPBallot)
CPPSETSIZEINST(PublicKey)

#define CPPSETMAKETESTINST(T) template void* makeStdSet<T>();
CPPSETMAKETESTINST(Value)
CPPSETMAKETESTINST(unsigned int)
CPPSETMAKETESTINST(SCPBallot)
CPPSETMAKETESTINST(PublicKey)

template<>
void cpp_set_insert<SCPBallot>(void* setptr, void* key)
{
    // todo
    // ((std::set<T>*)setptr)->insert(*(T*)key);
}

template<>
void cpp_set_insert<PublicKey>(void* setptr, void* key)
{
    // todo
    // ((std::set<T>*)setptr)->insert(*(T*)key);
}

#define CPPSETINSERTINST(T) template void cpp_set_insert<T>(void*, void*);
CPPSETINSERTINST(Value)
CPPSETINSERTINST(unsigned int)
CPPSETINSERTINST(SCPBallot)
CPPSETINSERTINST(PublicKey)

void callCPPDelegate (void* cb)
{
    auto callback = (std::function<void()>*)cb;
    (*callback)();
    delete callback;
}

std::shared_ptr<SCPQuorumSet> makeSharedSCPQuorumSet (
    const SCPQuorumSet& quorum)
{
    return std::make_shared<SCPQuorumSet>(quorum);
}
