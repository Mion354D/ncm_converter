package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/bogem/id3v2"
)

func main() {
	var err error
	defer func() {
		if err != nil {
			var input string
			fmt.Println()
			fmt.Printf("\n Error found.\n")
			fmt.Scanln(&input)
		}
	}()
	list, err := readCurrentDirectory()
	if err != nil {
		return
	}

	failedList := []string{}
	for _, filePath := range list {
		err = convert(filePath)
		if err != nil {
			failedList = append(failedList, filePath)
		}
	}
	if len(failedList) != 0 {
		err = fmt.Errorf("errors found")
		fmt.Printf("\n failure list: \n")
		for _, v := range failedList {
			fmt.Println(v)
		}
	}
	return
}

func convert(filePath string) error {
	inputStream, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer inputStream.Close()

	err = magicHeader(inputStream)
	if err != nil {
		return err
	}
	decryptedCR4, err := cr4Key(inputStream)
	if err != nil {
		return err
	}

	meta, err := mataData(inputStream)
	if err != nil {
		return err
	}
	fmt.Printf("meta: %s\n", meta)

	metaMap, err := decodeJSON(meta)
	if err != nil {
		return err
	}

	abImg, err := albumImage(inputStream)
	if err != nil {
		return err
	}

	//writeBytesToJPEG(image, "C:\\Users\\mion\\Desktop\\ws\\ncm_converter\\に中한\\yes.jpg")

	outFilePath := renameNCMtoMP3(filePath, metaMap["format"].(string))
	fmt.Printf("outputFilePath: %s\n", outFilePath)

	audioData, err := decodeCR4(inputStream, decryptedCR4)
	if err != nil {
		return err
	}

	err = WriteMP3WithID3v2(audioData, outFilePath, metaMap, abImg)
	if err != nil {
		return err
	}

	return nil
}

func WriteMP3WithID3v2(audioData []byte, filename string, mdMap map[string]interface{}, abImg []byte) (err error) {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(filename)
		}
	}()
	defer file.Close()

	tag := id3v2.NewEmptyTag()
	tag.SetAlbum(mdMap["album"].(string))
	tag.SetArtist((mdMap["artist"].([]interface{}))[0].([]interface{})[0].(string))
	tag.SetTitle(mdMap["musicName"].(string))

	frame := id3v2.PictureFrame{
		// todo: judge image type here
		MimeType: "image/jpeg",
		Picture:  abImg,
	}
	tag.AddAttachedPicture(frame)

	if _, err := tag.WriteTo(file); err != nil {
		fmt.Println("Error writing md to new audio:", err)
		return err
	}

	_, err = file.Write(audioData)
	if err != nil {
		fmt.Println("Error writing audioData :", err)
		return err
	}

	return nil
}

func decodeJSON(jsonString []byte) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := json.Unmarshal(jsonString, &result)
	if err != nil {
		fmt.Println("Error converting md to map:", err)
		return nil, err
	}
	return result, nil
}

func decodeCR4(inputStream io.Reader, decryptedCR4 []byte) ([]byte, error) {
	cr4 := NewCR4(decryptedCR4)

	var decryptedData []byte
	buffer := make([]byte, 0x8000)
	count := 0
	for {
		len, err := inputStream.Read(buffer)
		if err != nil && err != io.EOF {
			fmt.Println("Error converting music:", err)
			return nil, err
		}

		if len == 0 {
			break
		}

		for i := 0; i < len; i++ {
			j := (i + 1) & 0xff
			buffer[i] ^= byte(cr4.box[(cr4.box[j]+cr4.box[(cr4.box[j]+j)&0xff])&0xff])
		}

		decryptedData = append(decryptedData, buffer[:len]...)

		count++
	}

	return decryptedData, nil
}

type CR4 struct {
	box []int
}

func NewCR4(key []byte) *CR4 {
	c := &CR4{}
	c.buildKeyBox(key)
	return c
}

func (nc *CR4) buildKeyBox(key []byte) {
	mKeyBox := make([]int, 256)
	for i := 0; i < 256; i++ {
		mKeyBox[i] = i
	}

	var swap, c, lastByte, keyOffset int

	for i := 0; i < 256; i++ {
		swap = mKeyBox[i]
		c = (swap + lastByte + int(key[keyOffset])) & 0xff

		keyOffset++
		if keyOffset >= len(key) {
			keyOffset = 0
		}
		mKeyBox[i] = mKeyBox[c]
		mKeyBox[c] = swap
		lastByte = c
	}
	nc.box = mKeyBox
}

func albumImage(inputStream io.Reader) ([]byte, error) {
	lenBytes := make([]byte, 4)
	_, err := inputStream.Read(lenBytes)
	if err != nil {
		fmt.Println("Error reading albumImage length:", err)
		return nil, err
	}

	imageLen := int(binary.LittleEndian.Uint32(lenBytes))

	imageData := make([]byte, imageLen)
	_, err = inputStream.Read(imageData)
	if err != nil {
		fmt.Println("Error reading albumImage:", err)
		return nil, err
	}

	return imageData, nil
}

func writeBytesToJPEG(data []byte, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	fmt.Println("Data written to", filename)
	return nil
}

func mataData(inputStream io.Reader) ([]byte, error) {
	lenBytes := make([]byte, 4)
	_, err := inputStream.Read(lenBytes)
	if err != nil {
		fmt.Println("Error reading md length:", err)
		return nil, err
	}

	headerLen := binary.LittleEndian.Uint32(lenBytes)

	headerBytes := make([]byte, headerLen)
	_, err = inputStream.Read(headerBytes)
	if err != nil {
		fmt.Println("Error reading md body:", err)
		return nil, err
	}

	// Skip CRC (4 bytes) and unused Gap (5 bytes)
	discardBytes := make([]byte, 9)
	if _, err := inputStream.Read(discardBytes); err != nil {
		fmt.Println("Error skipping CRC:", err)
		return nil, err
	}

	for i := 0; i < len(headerBytes); i++ {
		headerBytes[i] ^= 0x63
	}

	// Remove the prefix "163 key(Don't modify):" (22 bytes)
	headerBytes = headerBytes[22:]

	// Decode Base64
	decodedBytes, err := base64.StdEncoding.DecodeString(string(headerBytes))
	if err != nil {
		fmt.Println("Error decoding md:", err)
		return nil, err
	}

	// Perform AES decryption here if AES package is available in your code
	decodedBytes, _ = decryptAES(decodedBytes, META_KEY)
	// Remove the prefix "music:" (6 bytes) to get JSON
	jsonData := decodedBytes[6:]
	return jsonData, nil
}

func cr4Key(inputStream io.Reader) ([]byte, error) {
	lenBytes := make([]byte, 4)
	_, err := inputStream.Read(lenBytes)
	if err != nil {
		fmt.Println("Error reading length of cr4 key:", err)
		return nil, err
	}
	keyLen := binary.LittleEndian.Uint32(lenBytes)
	key := make([]byte, keyLen)
	_, err = inputStream.Read(key)
	if err != nil {
		fmt.Println("Error reading cr4 key:", err)
		return nil, err
	}

	for i := 0; i < len(key); i++ {
		key[i] ^= 0x64
	}
	key, _ = decryptAES(key, CR4_KEY)
	return key, nil
}

var (
	CR4_KEY  = []byte{0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57}
	META_KEY = []byte{0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28}
)

func decryptAES(data, key []byte) ([]byte, error) {
	cipher, _ := aes.NewCipher(key)
	decrypted := make([]byte, len(data))
	size := aes.BlockSize
	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return unpad(decrypted), nil
}

func unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:length-unpadding]
}

func magicHeader(inputStream io.Reader) error {
	bytes := make([]byte, 10)
	_, err := inputStream.Read(bytes)
	if err != nil {
		fmt.Println("Error sub header:", err)
		return err
	}
	return nil
}

func renameNCMtoMP3(filePath string, realFormat string) string {
	dir, file := filepath.Split(filePath)
	fileBase := strings.TrimSuffix(file, filepath.Ext(file))
	newFilePath := filepath.Join(dir, fileBase+"."+realFormat)

	return newFilePath
}

func readCurrentDirectory() ([]string, error) {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("Error getting executable path:", err)
		return nil, err
	}
	dir := filepath.Dir(exePath)

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		fmt.Println("Error reading directory:", err)
		return nil, err
	}

	var ncmFiles []string
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".ncm" {
			ncmFiles = append(ncmFiles, filepath.Join(dir, file.Name()))
		}
	}
	return ncmFiles, nil
}
