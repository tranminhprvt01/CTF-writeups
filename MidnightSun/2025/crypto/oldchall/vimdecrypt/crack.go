// Usage: ./crack dogecrypt < /usr/share/dict/words
package main

import "bufio"
import "errors"
import "flag"
import "fmt"
import "hash/crc32"
import "io"
import "io/ioutil"
import "os"
import "runtime"

func looksPlaintext(data []byte) bool {
	var n, d int

	// Looks like plaintext if at least 75% ASCII.
	for _, b := range data {
		if b < 128 {
			n += 1
		}
		d += 1
	}

	return float32(n) / float32(d) > 0.75
}

func crc32Byte(crc uint32, b byte) uint32 {
	return ^crc32.Update(^crc, crc32.IEEETable, []byte{b})
}

func initKeys(password []byte) []uint32 {
	keys := make([]uint32, 3)
	keys[0] = 305419896
	keys[1] = 591751049
	keys[2] = 878082192
	for _, b := range password {
		updateKeys(keys, b)
	}
	return keys
}

func updateKeys(keys []uint32, b byte) {
	keys[0] = crc32Byte(keys[0], b)
	keys[1] = keys[1] + (keys[0] & 0xff)
	keys[1] = keys[1] * 134775813 + 1
	keys[2] = crc32Byte(keys[2], byte(keys[1] >> 24))
}

func decryptByte(keys []uint32) byte {
	t := uint16(keys[2]) | 2
	return byte((t * (t ^ 1)) >> 8)
}

func decrypt(ciphertext, password []byte) []byte {
	keys := initKeys(password)
	plaintext := make([]byte, len(ciphertext))
	for i := range ciphertext {
		plaintext[i] = ciphertext[i] ^ decryptByte(keys)
		updateKeys(keys, plaintext[i])
	}

	return plaintext
}

func trial(ciphertext, password []byte) {
	plaintext := decrypt(ciphertext, password)
	if looksPlaintext(plaintext) {
		fmt.Printf("%q â†’ %q\n", password, plaintext)
	}
}

func trialRoutine(ch chan([]byte), ciphertext []byte) {
	for {
		password, ok := <-ch
		if !ok {
			break
		}
		trial(ciphertext, password)
	}
}

func readVimCrypt(r io.Reader) ([]byte, error) {
	header := make([]byte, 12)
	_, err := io.ReadFull(r, header)
	if err != nil {
		return nil, err
	}
	if string(header) != "VimCrypt~01!" {
		return nil, errors.New("Not a ZIP-encrypted Vim file (bad magic)")
	}
	return ioutil.ReadAll(r)
}

func readVimCryptFilename(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readVimCrypt(f)
}

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Need a file name.\n")
		os.Exit(1)
	}
	filename := flag.Arg(0)
	ciphertext, err := readVimCryptFilename(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %q: %s\n", filename, err)
		os.Exit(1)
	}
	ch := make(chan([]byte))
	runtime.GOMAXPROCS(runtime.NumCPU())
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		go trialRoutine(ch, ciphertext)
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		ch <- scanner.Bytes()
	}
}
