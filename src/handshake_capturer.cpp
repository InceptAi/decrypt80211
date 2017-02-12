/*
 * Copyright (c) 2016, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "handshake_capturer.h"

#ifdef TINS_HAVE_DOT11

#include "dot11/dot11_data.h"

using std::max_element;
using std::max;
using std::min;
using std::pair;
using std::cout;
using std::endl;

namespace Tins {

bool RSNHandshakeCapturer::process_packet(const PDU& pdu) {
    const RSNEAPOL* eapol = pdu.find_pdu<RSNEAPOL>();
    const Dot11Data* dot11 = pdu.find_pdu<Dot11Data>();
    if (!eapol || !dot11) {
        // cout << "Early return from RSNHandshakeCapturer." << endl;
        return false;
    }

    if (eapol) {
        cout << "Found EAPOL packet." << endl;
    }
    
    // Use this to identify each flow, regardless of the direction
    pair<address_type, address_type> addresses;
    addresses.first  = min(dot11->src_addr(), dot11->dst_addr());
    addresses.second = max(dot11->src_addr(), dot11->dst_addr());
        
    // 1st packet
    if (eapol->key_t() && eapol->key_ack() && !eapol->key_mic() && !eapol->install()) {
        cout << "First packet." << endl;
        handshakes_[addresses].assign(eapol, eapol + 1);
    }
    // 2nd and 4th packets
    else if (eapol->key_t() && !eapol->key_ack() && eapol->key_mic() && !eapol->install()) {
        cout << "EAPOL key length:" << eapol->key_length() << endl;
        cout << "EAPOL wpa length:" << eapol->wpa_length() << endl;
        cout << "EAPOL length:" << eapol->length() << endl;
        // Comment from epan-dissectors-packet-ieee80211.c from wireshark:
        /* We check the key length to differentiate between message 2 and 4 and just hope that
           there are no strange implementations with key data and non-zero key length in message 4.
           According to the IEEE specification, sections 11.6.6.3 and 11.6.6.5 we should
           use the Secure Bit and/or the Nonce, but there are implementations ignoring the spec.
           The Secure Bit is incorrectly set on rekeys for Windows clients for Message 2 and the Nonce is non-zero
           in Message 4 in Bug 11994 (Apple?) */
        // 2nd packet won't have the secure bit set
        if (!eapol->secure() && eapol->wpa_length() > 0) {
            cout << "Second packet." << endl;
            do_insert(addresses, eapol, 1);
        }
        // Otherwise, this should be the 4th and last packet
        else if (do_insert(addresses, eapol, 3)) {
            cout << "Fourth and last packet." << endl;
            completed_handshakes_.push_back(
                handshake_type(
                    addresses.first,
                    addresses.second,
                    handshakes_[addresses]
                )
            );
            handshakes_.erase(addresses);
            return true;
        }
    }
    // 3nd packet
    else if (eapol->key_t() && eapol->key_ack() && eapol->key_mic() && eapol->install()) {
        cout << "Third packet." << endl;
        do_insert(addresses, eapol, 2);
    }
    return false;
}

bool RSNHandshakeCapturer::do_insert(const handshake_map::key_type& key,
                                     const RSNEAPOL* eapol,
                                     size_t expected) {
    handshake_map::iterator iter = handshakes_.find(key);
    if (iter != handshakes_.end()) {
        if (iter->second.size() != expected) {
            // skip repeated
            if (iter->second.size() != expected + 1) {
                iter->second.clear();
            }
        }
        else {
            iter->second.push_back(*eapol);
            return true;
        }
    }
    return false;
}

} // namespace Tins;

#endif // TINS_HAVE_DOT11
