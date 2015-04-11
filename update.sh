#!/usr/bin/env bash
set -e

libssl_src=./

(cd $libssl_src/crypto/objects/;
perl objects.pl objects.txt obj_mac.num obj_mac.h;
perl obj_dat.pl obj_mac.h obj_dat.h )

mv $libssl_src/crypto/objects/obj_mac.h ./include/openssl/obj_mac.h
