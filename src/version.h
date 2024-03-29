// Copyright (c) 2012-2014 The Bitcoin Core developers
// Copyright (c) 2017-2018 The cruZado developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

/**
 * network protocol versioning
 */

static const int PROTOCOL_VERSION = 170007;

//! initial proto version, to be increased after version/verack negotiation
static const int INIT_PROTO_VERSION = 209;

//! Disconnect from peers older than this protocol version.
static const int MIN_PEER_PROTO_VERSION = 170004;

//! nTime field added to CAddress, starting with this version;
//! the older encoding that omits nTime is only used in "version" messages.
static const int CADDR_TIME_VERSION = 31402;

//! BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 60000;

//! "filter*" commands are disabled without NODE_BLOOM after and including this version
static const int NO_BLOOM_VERSION = 170004;

#endif // BITCOIN_VERSION_H
