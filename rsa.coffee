###
# RSA Encryption Library for OChat.
#
# Copyright (C) 2015, Ember Group. All rights reserved.
# Licensed under zlib Licence with one modification (see below).
#
# This software is provided 'as-is', without any express or implied
# warranty. In no event will the authors be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgement in the product documentation, including
#    the name of the original product and the names of the authors, is required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
###

# Utility functions.

# Encodes a single byte as zero-padded hex.
byte2hex = (byte) ->
  if byte < 0x10 then '0' + byte.toString(16) else byte.toString(16);

# Encodes a string as hex using UTF-8
hexify = (string) ->
  hexString = "";
  i = 0;
  while i < string.length
    cpt = string.codePointAt(i)
    if cpt < 0x80 then hexString += byte2hex(cpt);
    else if cpt < 0x800
      hexString += byte2hex((cpt >> 6) | 0xb0) + byte2hex((cpt % (1<<6)) | 0x80);
    else if cpt < 0x10000
      hexString += byte2hex (cpt >> 12) | 0xe0;
      hexString += byte2hex ((cpt >> 6) % (1<<6)) | 0x80;
      hexString += byte2hex (cpt % (1<<6)) | 0x80;
    else if cpt < 0x200000
      hexString += byte2hex (cpt >> 18) | 0xf0;
      hexString += byte2hex ((cpt >> 12) % (1<<6)) | 0x80;
      hexString += byte2hex ((cpt >> 6) % (1<<6)) | 0x80;
      hexString += byte2hex (cpt % (1<<6)) | 0x80;
    else hexString += 'ee8080';   # Reserved area, displays a 'cannot display' character
    i++;
  return hexString;

unhexify = (hexString) ->
  string = "";
  i = 0;
  while i < hexString.length
    byte = parseInt(hexString.substr(i, 2), 16);
    string += String.fromCodePoint(
      if byte < 0x80 then byte;
      else if byte < 0xe0
        byte2 = parseInt(hexString.substr(i+=2, 2), 16);
        ((byte ^ 0xb0) << 6) + (byte2 ^ 0x80);
      else if byte < 0xf0
        byte2 = parseInt(hexString.substr(i+=2, 2), 16);
        byte3 = parseInt(hexString.substr(i+=2, 2), 16);
        ((byte ^ 0xe0) << 12) + ((byte2 ^ 0x80) << 6) + (byte3 ^ 0x80);
      else if byte < 0xf8
        byte2 = parseInt(hexString.substr(i+=2, 2), 16);
        byte3 = parseInt(hexString.substr(i+=2, 2), 16);
        byte4 = parseInt(hexString.substr(i+=2, 2), 16);
        ((byte ^ 0xf0) << 18) + ((byte2 ^ 0x80) << 12) + ((byte3 ^ 0x80) << 6) + (byte4 ^ 0x80);
      else 0xe000;  # Same as the 0xEE8080 above
    );
    i += 2;
  return string;

  divideString = (str, chunkLength) ->
    i = 0;
    while i < str.length string.slice(i, i += chunkLength);


class RSAKey
  p: null
  q: null
  n: null
  e: 0
  d: null
  owner: ""

  constructor: (seed, length, exponent, owner) ->
    factor_size = length >> 1;
    @e = exponent;
    e_big = new BigInteger(exponent);

    loop
      loop
        @p = new BigInteger(factor_size, 1, seed);
        break if @p.subtract(BigInteger.ONE).gcd(e_big).compareTo(BigInteger.ONE) is 0 and @p.isProbablePrime(10);
      loop
        @q = new BigInteger(factor_size, 1, seed);
        break if @q.subtract(BigInteger.ONE).gcd(e_big).compareTo(BigInteger.ONE) is 0 and @p.isProbablePrime(10);
      phi = @p.subtract(BigInteger.ONE).multiply @q.subtract(BigInteger.ONE);
      if phi.gcd(e_big).compareTo(BigInteger.ONE) is 0
        @n = @p.multiply @q;
        @d = e_big.modInverse(phi)
        break;
    @owner = if owner? then owner else null;

  getPublic: -> new RSAPublicKey(@n, @e, @owner);
  getPrivate: -> new RSAPrivateKey(@n, @d, @owner);

class RSAPublicKey
  n: null
  e: 0
  owner: ""

  constructor: (n, e, owner) ->
    @n = if typeof(n) is 'string' then new BigInteger(n, 16) else n;
    @e = if typeof(e) is 'string' then parseInt(e, 16) else e;
    @owner = if owner? then owner else null;

  encrypt: (msg) ->
    chunkLength = 0.75*@n.bitLength/8;
    if msg.length <= chunkLength
      msg = new BigInteger(msg, 16);
      msg.modPow(@e, @n).toString(16);
    else @encrypt chunk for chunk in divideString(msg);

  # For signature-type cases where things are decrypted with a public key.
  decrypt: (msg) ->
    if typeof(msg) is 'string' then encrypt msg;
    else (@encrypt chunk for chunk in msg).join();

class RSAPrivateKey
  n: null
  d: null
  owner: ""

  constructor: (n, d, owner) ->
    @n = if typeof(n) is 'string' then new BigInteger(n, 16) else n;
    @d = if typeof(d) is 'string' then new BigInteger(d, 16) else d;
    @owner = if owner? then owner else null;

  decrypt: (msg) ->
    chunkLength = 0.75*@n.bitLength/8;
    if msg.length <= chunkLength
      msg = new BigInteger(msg, 16);
      msg.modPow(@d, @n).toString(16);
    else @decrypt chunk for chunk in divideString(msg);

  sign: (msg) ->
    if typeof(msg) is 'string' then encrypt msg;
    else (@decrypt chunk for chunk in msg).join();

if module?
  module.exports =
    RSAKey: RSAKey
    RSAPublicKey: RSAPublicKey
    RSAPrivateKey: RSAPrivateKey
    byte2hex: byte2hex
    hexify: hexify
    unhexify: unhexify

global.RSAKey = RSAKey
global.RSAPublicKey = RSAPublicKey
global.RSAPrivateKey = RSAPrivateKey
global.byte2hex = byte2hex
global.hexify = hexify
global.unhexify = unhexify
