/*
 * Copyright (c) 2015 Ted Unangst <tedu@tedunangst.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package main

import (
	"github.com/dchest/bcrypt_pbkdf"
	"bytes"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type Seckey struct {
	sigalg [2]byte
	encalg [2]byte
	symalg [2]byte
	kdfalg [2]byte
	randomid [8]byte
	kdfrounds uint32
	salt [16]byte
	nonce [24]byte
	tag [16]byte
	sigkey [64]byte
	enckey [32]byte
	ident string
}

type Pubkey struct {
	sigalg [2]byte
	encalg [2]byte
	randomid [8]byte
	sigkey [32]byte
	enckey [32]byte
	ident string
}

type Encmsg struct {
	encalg [2]byte
	secrandomid [8]byte
	pubrandomid [8]byte
	ephpubkey [32]byte
	ephnonce [24]byte
	ephtag [16]byte
	nonce [24]byte
	tag [16]byte
}

type Symmsg struct {
	symalg [2]byte
	kdfalg [2]byte
	kdfrounds uint32
	salt [16]byte
	nonce [24]byte
	tag [16]byte
}

func wraplines(s string) string {
	for i := 76; i < len(s); i += 77 {
		s = s[0:i] + "\n" + s[i:]
	}
	return s
}

func encodeSeckey(seckey *Seckey) string {
	var buf bytes.Buffer
	buf.Write(seckey.sigalg[:])
	buf.Write(seckey.encalg[:])
	buf.Write(seckey.symalg[:])
	buf.Write(seckey.kdfalg[:])
	buf.Write(seckey.randomid[:])
	binary.Write(&buf, binary.BigEndian, seckey.kdfrounds)
	buf.Write(seckey.salt[:])
	buf.Write(seckey.nonce[:])
	buf.Write(seckey.tag[:])
	// XXX need encrypt
	buf.Write(seckey.sigkey[:])
	buf.Write(seckey.enckey[:])
	str := base64.StdEncoding.EncodeToString(buf.Bytes())
	str = wraplines(str)
	return "-----BEGIN REOP SECRET KEY-----\n" +
		"ident:" + seckey.ident + "\n" +
		str + "\n" +
		"-----END REOP SECRET KEY-----\n"
}

func decodeSeckey(seckeydata string) *Seckey {
	lines := strings.Split(seckeydata, "\n")
	var ident string
	fmt.Sscanf(lines[1], "ident:%s", &ident)
	b64 := strings.Join(lines[2:6], "\n")
	data, _ := base64.StdEncoding.DecodeString(b64)
	buf := bytes.NewBuffer(data)
	seckey := new(Seckey)
	buf.Read(seckey.sigalg[:])
	buf.Read(seckey.encalg[:])
	buf.Read(seckey.symalg[:])
	buf.Read(seckey.kdfalg[:])
	buf.Read(seckey.randomid[:])
	binary.Read(buf, binary.BigEndian, &seckey.kdfrounds)
	buf.Read(seckey.salt[:])
	buf.Read(seckey.nonce[:])
	buf.Read(seckey.tag[:])
	buf.Read(seckey.sigkey[:])
	buf.Read(seckey.enckey[:])
	// XXX use a real key
	var symkey [32]byte
	var enc [16 + 64 + 32]byte
	copy(enc[0:16], seckey.tag[:])
	copy(enc[16:80], seckey.sigkey[:])
	copy(enc[80:112], seckey.enckey[:])
	dec, ok := secretbox.Open(nil, enc[:], &seckey.nonce, &symkey)
	if !ok {
		log.Fatal("decryption failed")
	}
	copy(seckey.sigkey[:], dec[0:64])
	copy(seckey.enckey[:], dec[64:96])
	seckey.ident = ident
	return seckey
}

func decodePubkey(pubkeydata string) *Pubkey {
	lines := strings.Split(pubkeydata, "\n")
	var ident string
	fmt.Sscanf(lines[1], "ident:%s", &ident)
	b64 := strings.Join(lines[2:4], "\n")
	data, _ := base64.StdEncoding.DecodeString(b64)
	buf := bytes.NewBuffer(data)
	pubkey := new(Pubkey)
	buf.Read(pubkey.sigalg[:])
	buf.Read(pubkey.encalg[:])
	buf.Read(pubkey.randomid[:])
	buf.Read(pubkey.sigkey[:])
	buf.Read(pubkey.enckey[:])
	pubkey.ident = ident
	return pubkey
}

func readSeckey(seckeyfile string) *Seckey {
	seckeydata, err := ioutil.ReadFile(seckeyfile)
	if err != nil {
		log.Fatal(err)
	}
	seckey := decodeSeckey(string(seckeydata))
	return seckey
}

func readPubkey(pubkeyfile string) *Pubkey {
	pubkeydata, err := ioutil.ReadFile(pubkeyfile)
	if err != nil {
		log.Fatal(err)
	}
	pubkey := decodePubkey(string(pubkeydata))
	return pubkey
}

func encryptMsg(seckey *Seckey, pubkey *Pubkey, msg []byte) string {
	encmsg := new(Encmsg)
	encmsg.encalg[0] = 'e'
	encmsg.encalg[1] = 'C'
	copy(encmsg.secrandomid[:], seckey.randomid[:])
	copy(encmsg.pubrandomid[:], pubkey.randomid[:])

	ephpub, ephsec, _ := box.GenerateKey(rand.Reader)

	rand.Read(encmsg.nonce[:])
	enc := box.Seal(nil, msg, &encmsg.nonce, &pubkey.enckey, ephsec)
	copy(encmsg.tag[:], enc[0:16])
	enc = enc[16:]

	rand.Read(encmsg.ephnonce[:])
	encephpub := box.Seal(nil, ephpub[:], &encmsg.ephnonce, &pubkey.enckey, &seckey.enckey)
	copy(encmsg.ephtag[:], encephpub[0:16])
	copy(encmsg.ephpubkey[:], encephpub[16:])

	var buf bytes.Buffer
	buf.Write(encmsg.encalg[:])
	buf.Write(encmsg.secrandomid[:])
	buf.Write(encmsg.pubrandomid[:])
	buf.Write(encmsg.ephpubkey[:])
	buf.Write(encmsg.ephnonce[:])
	buf.Write(encmsg.ephtag[:])
	buf.Write(encmsg.nonce[:])
	buf.Write(encmsg.tag[:])
	hdr := base64.StdEncoding.EncodeToString(buf.Bytes())
	hdr = wraplines(hdr)

	str := base64.StdEncoding.EncodeToString(enc)
	str = wraplines(str)

	return "-----BEGIN REOP ENCRYPTED MESSAGE-----\n" +
		"ident:" + seckey.ident + "\n" +
		hdr + "\n" +
		"-----BEGIN REOP ENCRYPTED MESSAGE DATA-----\n" +
		str + "\n" +
		"-----END REOP ENCRYPTED MESSAGE-----\n"
}

func encryptSymmsg(password string, msg []byte) string {
	symmsg := new(Symmsg)
	rounds := 42

	copy(symmsg.symalg[:], "SP")
	copy(symmsg.kdfalg[:], "BK")
	symmsg.kdfrounds = uint32(rounds)
	rand.Read(symmsg.salt[:])
	rand.Read(symmsg.nonce[:])

	key, _ := bcrypt_pbkdf.Key([]byte(password), symmsg.salt[:], rounds, 32)
	var symkey [32]byte
	copy(symkey[:], key)

	enc := secretbox.Seal(nil, msg, &symmsg.nonce, &symkey)
	copy(symmsg.tag[:], enc[0:16])
	enc = enc[16:]

	var buf bytes.Buffer
	buf.Write(symmsg.symalg[:])
	buf.Write(symmsg.kdfalg[:])
	binary.Write(&buf, binary.BigEndian, symmsg.kdfrounds)
	buf.Write(symmsg.salt[:])
	buf.Write(symmsg.nonce[:])
	buf.Write(symmsg.tag[:])

	hdr := base64.StdEncoding.EncodeToString(buf.Bytes())
	hdr = wraplines(hdr)

	str := base64.StdEncoding.EncodeToString(enc)
	str = wraplines(str)

	return "-----BEGIN REOP ENCRYPTED MESSAGE-----\n" +
		"ident:<symmetric>\n" +
		hdr + "\n" +
		"-----BEGIN REOP ENCRYPTED MESSAGE DATA-----\n" +
		str + "\n" +
		"-----END REOP ENCRYPTED MESSAGE-----\n"
}

func main() {
	if len(os.Args) == 4 {
		seckey := readSeckey(os.Args[1])
		pubkey := readPubkey(os.Args[2])

		msg, err := ioutil.ReadFile(os.Args[3])
		if err != nil {
			log.Fatal(err)
		}

		s := encryptMsg(seckey, pubkey, msg)
		fmt.Println(s)
	} else if len(os.Args) == 3 {
		password := os.Args[1]
		msg, err := ioutil.ReadFile(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		s := encryptSymmsg(password, msg)
		fmt.Println(s)
	}
}



