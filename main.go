package main

import (
	"encoding/hex"
	"log"
	"os"

	"github.com/miekg/pkcs11"
)

func main() {
	pkcs11LibraryPath := "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
	if p := os.Getenv("SOFTHSM2_LIBRARY_PATH"); p != "" {
		pkcs11LibraryPath = p
	}

	userPin := "1234"
	if p := os.Getenv("SOFTHSM2_USER_PIN"); p != "" {
		userPin = p
	}

	p := pkcs11.New(pkcs11LibraryPath)
	err := p.Initialize()
	if err != nil {
		log.Fatalf("failed to initialize %s: %v", pkcs11LibraryPath, err)
	}
	defer p.Destroy()
	defer p.Finalize()

	// list the initialized tokens.
	slots, err := p.GetSlotList(true)
	if err != nil {
		log.Fatalf("failed to get slot list: %v", err)
	}
	for _, slotID := range slots {
		slotInfo, err := p.GetSlotInfo(slotID)
		if err != nil {
			log.Fatalf("failed to get slot %d info: %v", slotID, err)
		}
		tokenInfo, err := p.GetTokenInfo(slotID)
		if err != nil {
			log.Fatalf("failed to get slot %d token info: %v", slotID, err)
		}
		if tokenInfo.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
			continue
		}
		log.Printf("slot:\n")
		log.Printf("  id: %d\n", slotID)
		log.Printf("  description: %s\n", slotInfo.SlotDescription)
		log.Printf("  token: %s\n", tokenInfo.Label)
		logPrivateKeys(p, slotID, userPin)
	}

	// TODO wrap a secret. Maybe using p.EncryptInit(session, pkcs11.NewMechanism(), ...)?
	//      see https://github.com/miekg/pkcs11/issues/131
}

func logPrivateKeys(p *pkcs11.Ctx, slotID uint, userPin string) {
	// login.
	session, err := p.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Fatalf("failed to OpenSession of slot %d: %v", slotID, err)
	}
	defer p.CloseSession(session)
	err = p.Login(session, pkcs11.CKU_USER, userPin)
	if err != nil {
		log.Fatalf("failed to Login slot %d: %v", slotID, err)
	}
	defer p.Logout(session)

	// list the private keys.
	objectsTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		//pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}
	if err := p.FindObjectsInit(session, objectsTemplate); err != nil {
		log.Fatalf("failed to FindObjectsInit: %v", err)
	}
	log.Printf("  private_keys:\n")
	for {
		keys, _, err := p.FindObjects(session, 10)
		if err != nil {
			log.Fatalf("failed to FindObjects: %v", err)
		}
		if len(keys) == 0 {
			break
		}
		attributeTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			// NB these are only valid in RSA public keys:
			// 		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
			// 		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, nil),
			// 		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		}
		for _, key := range keys {
			attributes, err := p.GetAttributeValue(session, key, attributeTemplate)
			if err != nil {
				log.Fatalf("failed to GetAttributeValue: %v", err)
			}
			log.Printf("    -\n")
			for _, attribute := range attributes {
				switch attribute.Type {
				case pkcs11.CKA_KEY_TYPE:
					// NB can be a pkcs11.CKK_XXXX, e.g. a pkcs11.CKK_RSA.
					log.Printf("      type: %s", hex.EncodeToString(attribute.Value))
				case pkcs11.CKA_ID:
					log.Printf("      id: %s", hex.EncodeToString(attribute.Value))
				case pkcs11.CKA_LABEL:
					log.Printf("      label: %s", attribute.Value)
				default:
					log.Printf("      #%d: %s", attribute.Type, hex.EncodeToString(attribute.Value))
				}
			}
		}
	}
	if err := p.FindObjectsFinal(session); err != nil {
		log.Fatalf("failed to FindObjectsFinal: %v", err)
	}
}
