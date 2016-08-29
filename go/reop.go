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
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/dchest/bcrypt_pbkdf"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// Seckey is a secret (private) key.
type Seckey struct {
	sigalg    [2]byte
	encalg    [2]byte
	symalg    [2]byte
	kdfalg    [2]byte
	randomid  [8]byte
	kdfrounds uint32
	salt      [16]byte
	nonce     [24]byte
	tag       [16]byte
	sigkey    [64]byte
	enckey    [32]byte
	ident     string
}

// Pubkey is a public key.
type Pubkey struct {
	sigalg   [2]byte
	encalg   [2]byte
	randomid [8]byte
	sigkey   [32]byte
	enckey   [32]byte
	ident    string
}

// Encmsg is a public-key encrypted message.
type Encmsg struct {
	encalg      [2]byte
	secrandomid [8]byte
	pubrandomid [8]byte
	ephpubkey   [32]byte
	ephnonce    [24]byte
	ephtag      [16]byte
	nonce       [24]byte
	tag         [16]byte
}

// Symmsg is a symmetrically encrypted message.
type Symmsg struct {
	symalg    [2]byte
	kdfalg    [2]byte
	kdfrounds uint32
	salt      [16]byte
	nonce     [24]byte
	tag       [16]byte
}

func wraplines(s string) string {
	for i := 76; i < len(s); i += 77 {
		s = s[0:i] + "\n" + s[i:]
	}
	return s
}

func readUint32(data []byte) (ret uint32) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.BigEndian, &ret)
	return
}

func b64pton(data []byte, length int) []byte {
	result := make([]byte, length)
	n, err := base64.StdEncoding.Decode(result, data)
	if err != nil && n != length {
		fmt.Fprintln(os.Stderr, "Base64 decoding failed.")
		fmt.Println("err:", err, "n:", n)
		log.Fatal(err)
	}
	return result
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

func readIdent(ciphertext []byte) (int, string) {
	newlineIndex := bytes.IndexByte(ciphertext, '\n')
	thisLine := string(ciphertext[:newlineIndex])
	var result string
	fmt.Sscanf(thisLine, "ident:%s", &result)
	return newlineIndex + 1, result
}

func decryptMsg(seckeyfile, pubkeyfile string, ciphertext []byte) string {
	var ident string
	var msglen int
	var msgraw []byte
	var hdr []byte
	if len(ciphertext) >= 6 && string(ciphertext[0:4]) == "RBF\u0000" {
		algorithm := string(ciphertext[4:6])
		switch algorithm {
		case "SP":
			if len(ciphertext) <= 68 {
				fmt.Fprintln(os.Stderr, "Badly formatted message!")
				os.Exit(1)
			}
			hdr = ciphertext[4:68]
			ciphertext = ciphertext[68:]
			break
		default:
			nyi("Binary decryption")
		}
		identlen :=  readUint32(ciphertext[0:4])
		ident = string(ciphertext[4:4 + identlen])
		msgraw = ciphertext[4 + identlen:]
	} else {
		// in the C, these are pointers to halfway through ciphertext
		// that's not fun
		var begin int
		var end int
		var beginmsg = []byte("-----BEGIN REOP ENCRYPTED MESSAGE-----\n")
		var begindata = []byte("-----BEGIN REOP ENCRYPTED MESSAGE DATA-----\n")
		var endmsg = []byte("-----END REOP ENCRYPTED MESSAGE-----\n")
		if bytes.Index(ciphertext, beginmsg) != 0 {
			fmt.Fprintln(os.Stderr, "Badly formatted message!")
			os.Exit(1)
		}
		begin, ident = readIdent(ciphertext[len(beginmsg):])
		begin = begin + len(beginmsg)
		end = begin + bytes.Index(ciphertext[begin:], begindata)
		if end == -1 {
			fmt.Fprintln(os.Stderr, "Badly formatted message!")
			os.Exit(1)
		}
		// this was nasty to figure out; it's a sizeof() a union with several structs
		hdr = b64pton(ciphertext[begin:end], 128)
		begin = end + len(begindata)
		end = begin + bytes.Index(ciphertext[begin:], endmsg)
		if end == -1 {
			fmt.Fprintln(os.Stderr, "Badly formatted message!")
			os.Exit(1)
		}
		msglen = (end - begin - 1) / 4 * 3
		msgraw = b64pton(ciphertext[begin:end], msglen)
		for msgraw[len(msgraw)-1] == 0 {
			msgraw = msgraw[:len(msgraw)-1]
		}
	}

	algorithm := string(hdr[:2])

	switch algorithm {
	case "SP":
		msg := new(Symmsg)
		copy(msg.symalg[:], hdr[0:2])
		copy(msg.kdfalg[:], hdr[2:4])
		msg.kdfrounds = readUint32(hdr[4:8])
		copy(msg.salt[:], hdr[8:24])
		copy(msg.nonce[:], hdr[24:48])
		copy(msg.tag[:], hdr[48:64])
		if string(msg.kdfalg[:]) != "BK" {
			fmt.Fprintln(os.Stderr, "unsupported KDF")
			os.Exit(1)
		}
		fmt.Print("passphrase: ")
		password, err := terminal.ReadPassword(0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Unable to read password: %v", err)
			os.Exit(1)
		}
		key, _ := bcrypt_pbkdf.Key(password, msg.salt[:], int(msg.kdfrounds), 32)
		var symkey [32]byte
		copy(symkey[:], key)
		raw := append(msg.tag[:], msgraw...)
		var dec []byte
		dec, worked := secretbox.Open(nil, raw, &msg.nonce, &symkey)
		if !worked {
			fmt.Fprintln(os.Stderr, "Decryption failed!")
			os.Exit(1)
		}
		return string(dec)
	case "eC":
		//seckey := readSeckey(seckeyfile)
		//pubkey := readPubkey(pubkeyfile)
		nyi("Public-key decryption with identity " + ident)
	case "CS":
		nyi("Old public-key algorithm")
	case "eS":
		nyi("Old symmetric algorithm")
	}
	return ""
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

func usage(message string) {
	fmt.Fprintf(os.Stderr, message)
	fmt.Fprintf(os.Stderr, "\n")
	flag.PrintDefaults()
	os.Exit(1)
}

func nyi(feature string) {
	fmt.Fprintf(os.Stderr, feature)
	fmt.Fprintf(os.Stderr, " is not yet implemented\n")
	os.Exit(1)
}

func main() {
	// uses the flag package to parse flags
	// XXX allow options to be passed as "reop -Seqm message.txt" which isn't possible with flag

	// verbs
	var decrypt = flag.Bool("D", false, "Decrypt a message.")
	var encrypt = flag.Bool("E", false, "Encrypt a message.")
	var generate = flag.Bool("G", false, "Generate a new key pair.")
	var sign = flag.Bool("S", false, "Sign a message.")
	var verify = flag.Bool("V", false, "Verify a signed message.")

	// formats
	var v1compat = flag.Bool("1", false, "Use the deprecated version 1 format.")
	var binary = flag.Bool("b", false, "Store cyphertext as binary instead of base64.")
	var embedded = flag.Bool("e", false, "Store signature alongside message.")

	// options
	var nopasswd = flag.Bool("n", false, "Generate a key with no password.")
	var quiet = flag.Bool("q", false, "Suppress informational output.")

	// parameters
	var ident = flag.String("i", "", "Identity tag to generate or search for")
	var msgfile = flag.String("m", "", "Message file")
	var pubkeyfile = flag.String("p", "", "Public key file")
	var seckeyfile = flag.String("s", "", "Secret key file")
	var xfile = flag.String("x", "", "Signature on -S/-V; ciphertext on -E/-D")

	flag.Parse()

	verb := "NONE"
	switch {
	case *decrypt:
		verb = "DECRYPT"
		*decrypt = false
	case *encrypt:
		verb = "ENCRYPT"
		*encrypt = false
	case *generate:
		verb = "GENERATE"
		*generate = false
	case *sign:
		verb = "SIGN"
		*sign = false
	case *verify:
		verb = "VERIFY"
		*verify = false
	}

	if verb == "NONE" {
		usage("Give a command!")
	}

	if *decrypt || *encrypt || *generate || *sign || *verify {
		usage("Don't give two commands!")
	}

	switch "-" {
	case *msgfile, *xfile:
		nyi("Passing - to -m/-x to use stdin/stdout")
	}

	switch verb {
	case "ENCRYPT", "DECRYPT":
		if *msgfile == "" {
			usage("Specify a message")
		}
		if *xfile == "" {
			if *msgfile == "-" {
				usage("Can't read from stdin and write to stdout")
			}
			*xfile = *msgfile + ".enc"
		}
	case "SIGN", "VERIFY":
		fmt.Println("In the future, this will check some stuff")
	}

	switch verb {
	case "DECRYPT":
		ciphertext, err := ioutil.ReadFile(*xfile)
		if err != nil {
			log.Fatal(err)
		}

		s := decryptMsg(*seckeyfile, *pubkeyfile, ciphertext)
		ioutil.WriteFile(*msgfile, []byte(s), os.FileMode(0611))
	case "ENCRYPT":
		if *seckeyfile != "" && (*pubkeyfile == "" && *ident == "") {
			usage("Specify a public key or identity name")
		}
		if *binary || *v1compat {
			nyi("Encryption formatting")
		}
		if *ident != "" {
			nyi("Finding keys in ~/.reop")
		}
		if *pubkeyfile != "" {
			seckey := readSeckey(*seckeyfile)
			pubkey := readPubkey(*pubkeyfile)

			msg, err := ioutil.ReadFile(*msgfile)
			if err != nil {
				log.Fatal(err)
			}

			s := encryptMsg(seckey, pubkey, msg)
			ioutil.WriteFile(*xfile, []byte(s), os.FileMode(0611))
		} else {
			fmt.Print("passphrase: ")
			password, err := terminal.ReadPassword(0)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Unable to read passphrase: %v", err)
				os.Exit(1)
			}
			fmt.Print("confirm passphrase: ")
			confirmed, err := terminal.ReadPassword(0)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Unable to read passphrase: %v", err)
				os.Exit(1)
			}
			if !bytes.Equal(password, confirmed) {
				fmt.Fprintf(os.Stderr, "Passphrases didn't match!\n")
				os.Exit(1)
			}
			msg, err := ioutil.ReadFile(*msgfile)
			if err != nil {
				log.Fatal(err)
			}
			s := encryptSymmsg(string(password), msg)
			ioutil.WriteFile(*xfile, []byte(s), os.FileMode(0611))
		}
	case "GENERATE":
		if !*quiet {
			fmt.Println("Skipping password: ", *nopasswd)
		}
		nyi("Key generation")
	case "SIGN":
		if !*quiet {
			fmt.Println("Embedding message w/ signature: ", *embedded)
		}
		nyi("Message signing")
	case "VERIFY":
		nyi("Message verification")
	}
}

// XXX securely erase everything at the end
