package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/gdamore/tcell/v2"
	shell "github.com/ipfs/go-ipfs-api"
	"github.com/monnand/dhkx"
	"github.com/rivo/tview"
	"hash/fnv"
	"io"
	"log"
	"os"
	"strings"
)

const (
	Separator         = ":"
	KeyExchangePrefix = "KEYEXCHANGE"
	MessagePrefix     = "MESSAGE"
)

var (
	keys       = make(map[string]*dhkx.DHKey)
	messageBox *tview.TextView
	logBox     *tview.TextView
	inputField *tview.InputField
	app        *tview.Application
	ipfsShell  *shell.Shell
	privKey    *dhkx.DHKey
	topic      string
	group      *dhkx.DHGroup
	pubKey     []byte
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: program <topic>")
		return
	}

	topic = os.Args[1]

	app = tview.NewApplication()

	messageBox = tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWrap(true)
	logBox = tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWrap(true)
	inputField = tview.NewInputField().SetLabel("Enter message: ").SetFieldBackgroundColor(tcell.ColorBlack)

	messageBox.SetBorder(true).SetTitle("Messages")
	logBox.SetBorder(true).SetTitle("Logs")
	inputField.SetBorder(true).SetTitle("Input")

	inputField.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			message := inputField.GetText()
			inputField.SetText("")
			go sendMessage(message)
		}
	})

	flex := tview.NewFlex().
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(messageBox, 0, 3, false).
			AddItem(inputField, 5, 1, true), 0, 2, true).
		AddItem(logBox, 0, 1, false)

	go func() {
		if err := app.SetRoot(flex, true).Run(); err != nil {
			panic(err)
		}
	}()

	ctx := context.Background()

	group, privKey, pubKey = initializeDHKeys()

	ipfsShell = connectToIPFS()

	subscription := subscribeToTopic(ipfsShell, topic)
	defer subscription.Cancel()

	err := publishKey(ipfsShell, topic, pubKey)
	if err != nil {
		panic(err)
	}

	handleMessages(ctx, subscription, privKey, group, ipfsShell, topic)
}

func handleMessages(ctx context.Context, sub *shell.PubSubSubscription, privKey *dhkx.DHKey, group *dhkx.DHGroup, sh *shell.Shell, topic string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			msg, err := sub.Next()
			if err != nil {
				logMessage(fmt.Sprintf("Error receiving message: %v", err))
				return
			}
			logMessage(fmt.Sprintf("Message received: %s", msg.Data))
			processReceivedMessage(string(msg.Data), privKey, group, sh, topic)
		}
	}
}

func processReceivedMessage(message string, privKey *dhkx.DHKey, group *dhkx.DHGroup, sh *shell.Shell, topic string) {
	parts := strings.Split(message, Separator)
	if len(parts) < 2 {
		logMessage("Invalid message format")
		return
	}

	switch parts[0] {
	case KeyExchangePrefix:
		handleKeyExchange(parts, privKey, group, sh, topic)
	case MessagePrefix:
		handleEncryptedMessage(parts)
	}
}

func handleKeyExchange(parts []string, privKey *dhkx.DHKey, group *dhkx.DHGroup, sh *shell.Shell, topic string) {
	if parts[1] == hex.EncodeToString(privKey.Bytes()) {
		logMessage("Found self key exchange message")
		return
	}
	pub, err := hex.DecodeString(parts[1])
	if err != nil {
		logMessage(fmt.Sprintf("Error decoding public key: %v", err))
		return
	}
	if _, ok := keys[parts[1]]; ok {
		return
	}
	pubKey := dhkx.NewPublicKey(pub)
	secret, err := group.ComputeKey(pubKey, privKey)
	if err != nil {
		logMessage(fmt.Sprintf("Error computing shared secret: %v", err))
		return
	}
	keys[parts[1]] = secret
	logMessage(fmt.Sprintf("Computed shared secret with peer: %s", parts[1]))
	if err := publishKey(sh, topic, privKey.Bytes()); err != nil {
		logMessage(fmt.Sprintf("Error publishing key: %v", err))
	}
}

func handleEncryptedMessage(parts []string) {
	if parts[1] == hex.EncodeToString(privKey.Bytes()) {
		logMessage("Found self message")
		return
	}

	shared, ok := keys[parts[1]]
	if !ok {
		logMessage(fmt.Sprintf("Unknown sender: %s", parts[1]))
		return
	}

	hashedKey := sha256.Sum256(shared.Bytes())
	decryptedMessage, err := decryptMessage(hashedKey[:], parts[2])
	if err != nil {
		logMessage(fmt.Sprintf("Found a message for another user."))
		return
	}

	displayMessage(fmt.Sprintf("%s: %s", parts[1][0:10], decryptedMessage), parts[1])
	logMessage(fmt.Sprintf("Decrypted message: %s", decryptedMessage))
}

func publishKey(sh *shell.Shell, topic string, pubKey []byte) error {
	err := sh.PubSubPublish(topic, KeyExchangePrefix+Separator+hex.EncodeToString(pubKey))
	if err != nil {
		logMessage(fmt.Sprintf("Error publishing key: %v", err))
	} else {
		logMessage("Published key successfully")
	}
	return err
}

func initializeDHKeys() (*dhkx.DHGroup, *dhkx.DHKey, []byte) {
	group, err := dhkx.GetGroup(0)
	if err != nil {
		log.Fatalf("Error getting DH group: %v", err)
	}

	privKey, err := group.GeneratePrivateKey(nil)
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}

	pubKey := privKey.Bytes()
	logMessage("My public key: " + hex.EncodeToString(pubKey))
	return group, privKey, pubKey
}

func connectToIPFS() *shell.Shell {
	ipfsShell := shell.NewShell("localhost:5001")
	if ipfsShell == nil {
		log.Fatalf("Failed to create IPFS shell")
	}
	logMessage("Connected to IPFS")
	return ipfsShell
}

func subscribeToTopic(sh *shell.Shell, topic string) *shell.PubSubSubscription {
	sub, err := sh.PubSubSubscribe(topic)
	if err != nil {
		log.Fatalf("Error subscribing to topic: %v", err)
	}
	logMessage("Subscribed to topic: " + topic)
	return sub
}

func logMessage(log string) {
	app.QueueUpdateDraw(func() {
		fmt.Fprintln(logBox, log)
		logBox.ScrollToEnd()
	})
}

func displayMessage(message, sender string) {
	color := getColor(sender)
	app.QueueUpdateDraw(func() {
		fmt.Fprintf(messageBox, "[%s]%s[white]\n", color, message)
		messageBox.ScrollToEnd()
	})
}

func decryptMessage(secret []byte, encryptedMessage string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func sendMessage(message string) {
	logMessage(fmt.Sprintf("Sending message: %s", message))
	for key, secret := range keys {
		logMessage(fmt.Sprintf("Encrypting message for key: %s", key))
		hashedKey := sha256.Sum256(secret.Bytes())
		encryptedMessage, err := encryptMessage(hashedKey[:], []byte(message))
		if err != nil {
			logMessage(fmt.Sprintf("Error encrypting message for key %s: %v", key, err))
			continue
		}
		logMessage(fmt.Sprintf("Message encrypted for key %s: %s", key, encryptedMessage))
		err = ipfsShell.PubSubPublish(topic, MessagePrefix+Separator+hex.EncodeToString(privKey.Bytes())+Separator+encryptedMessage)
		if err != nil {
			logMessage(fmt.Sprintf("Error publishing encrypted message for key %s: %v", key, err))
			continue
		}
		logMessage(fmt.Sprintf("Encrypted message sent to %s", key))
	}
	logMessage("Message sending process completed")
	displayMessage(fmt.Sprintf("Me: %s", message), hex.EncodeToString(privKey.Bytes()))
}

func encryptMessage(secret, message []byte) (string, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, message, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func getColor(sender string) string {
	h := fnv.New32a()
	h.Write([]byte(sender))
	colorIndex := h.Sum32() % uint32(len(ColorNames))
	return ColorNames[colorIndex]
}

var (
	ColorNames []string
)

func init() {
	for name := range tcell.ColorNames {
		ColorNames = append(ColorNames, name)
	}
}
