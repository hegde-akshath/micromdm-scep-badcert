package depot

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/rsa"
	"time"
	"fmt"
	"runtime/debug"
	"os"
	"strconv"
        
	"unsafe"
	"github.com/hegde-akshath/badcert"
	"github.com/hegde-akshath/badcert/pkix"
	"github.com/hegde-akshath/micromdm-scep-badcert/cryptoutil"
	"github.com/smallstep/scep"
)

type CertRequestType int

const (
	GOOD CertRequestType = iota
	VERSION_1 
	VERSION_2
	BASIC_CONST_CA_TRUE
	KEY_USAGE_KEYCERTSIGN
	PATHLEN_PRESENT
        EMPTY_ISSUER
	NO_SAN_EMPTY_SUBJECT
        NO_SUBJECT_SAN_NOT_CRITICAL
        SAN_PRESENT_BUT_EMPTY
	SIGALG_MISMATCH
        AKID_NOT_PRESENT
	AKID_NO_KEYID
	AKID_CRITICAL
	SKID_CRITICAL
)

// Signer signs x509 certificates and stores them in a Depot
type Signer struct {
	depot            Depot
	caPass           string
	allowRenewalDays int
	validityDays     int
	serverAttrs      bool
	signatureAlgo    x509.SignatureAlgorithm
}

// Option customizes Signer
type Option func(*Signer)

// NewSigner creates a new Signer
func NewSigner(depot Depot, opts ...Option) *Signer {
	s := &Signer{
		depot:            depot,
		allowRenewalDays: 14,
		validityDays:     365,
		signatureAlgo:    0,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithSignatureAlgorithm sets the signature algorithm to be used to sign certificates.
// When set to a non-zero value, this would take preference over the default behaviour of
// matching the signing algorithm from the x509 CSR.
func WithSignatureAlgorithm(a x509.SignatureAlgorithm) Option {
	return func(s *Signer) {
		s.signatureAlgo = a
	}
}

// WithCAPass specifies the password to use with an encrypted CA key
func WithCAPass(pass string) Option {
	return func(s *Signer) {
		s.caPass = pass
	}
}

// WithAllowRenewalDays sets the allowable renewal time for existing certs
func WithAllowRenewalDays(r int) Option {
	return func(s *Signer) {
		s.allowRenewalDays = r
	}
}

// WithValidityDays sets the validity period new certs will use
func WithValidityDays(v int) Option {
	return func(s *Signer) {
		s.validityDays = v
	}
}

func WithSeverAttrs() Option {
	return func(s *Signer) {
		s.serverAttrs = true
	}
}

func RecoveryFunc() {
	if r := recover(); r != nil {
		fmt.Println("--- Caught Panic! ---")
                fmt.Printf("Error Details (Panic Value): %v\n", r)
                fmt.Println("--- Stack Trace ---")
                fmt.Println(string(debug.Stack()))
        }
}


func BuildLeafCertificateRecipe(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) (*badcert.BadCertificate) {
	var leafCert *badcert.BadCertificate
        var leafExtensions badcert.ExtensionSlice
        
	convertedKeyUsage           := (badcert.KeyUsage)(tmpl.KeyUsage)
	convertedExtKeyUsage        := *((*[]badcert.ExtKeyUsage)(unsafe.Pointer(&tmpl.ExtKeyUsage)))
        convertedIssuer             := (*pkix.Name)(unsafe.Pointer(&signerCert.Issuer))
	convertedSubject            := (*pkix.Name)(unsafe.Pointer(&tmpl.Subject))
	convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))

	leafExtensions = badcert.CreateExtensions().SetBasicConstraintsExtension(true, false, 0, false).SetKeyUsageExtension(false, convertedKeyUsage).SetExtKeyUsageExtension(false, convertedExtKeyUsage).SetAKIDExtensionFromKey(false, signerCert.PublicKey).SetSKIDExtension(false, tmpl.SubjectKeyId).SetSANExtension(false, tmpl.DNSNames, tmpl.EmailAddresses, tmpl.IPAddresses, tmpl.URIs)


	leafCert = badcert.CreateBadCertificate().SetVersion3().SetSerialNumber(tmpl.SerialNumber).SetIssuer(convertedIssuer).SetSubject(convertedSubject).SetValidity(&tmpl.NotBefore, &tmpl.NotAfter).SetCertificatePublicKey(leafKey).SetSignatureAlgorithmFromPrivateKey(signerPrivateKey, convertedSignatureAlgorithm)
	leafCert = leafCert.SetExtensions(leafExtensions)
	return leafCert
}

func BadCertVersion1(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
	convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
	leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
	leafCert = leafCert.SetVersion1()
	leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
	x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
	convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
	return convertedCert.Raw, nil
}

func BadCertVersion2(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
	convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
	leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
	leafCert = leafCert.SetVersion2()
	leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
	x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
	convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
	return convertedCert.Raw, nil
}

func BadCertBasicConstraintsCATrue(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
       convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
       leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
       modifiedLeafExtensions := leafCert.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, true, -1, false)
       leafCert.SetExtensions(modifiedLeafExtensions)
       leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
       x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
       convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
       return convertedCert.Raw, nil 
}

func BadCertKeyusageKeycertsign(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
       convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
       leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
       //NOTE: The KeyUsage field in tmpl is not a pointer. So its not possible to check if this was set explicitly as its zero value is also a valid keyusage
       //Relying on the assumption that the caller has always set it, like in the SignCSR Caller of this function
       modifiedKeyUsage := badcert.KeyUsageCertSign | *((*badcert.KeyUsage)(&tmpl.KeyUsage))
       modifiedLeafExtensions := leafCert.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(false, modifiedKeyUsage)
       leafCert.SetExtensions(modifiedLeafExtensions)
       leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
       x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
       convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
       return convertedCert.Raw, nil 
}
func BadCertPathlenPresent(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
       convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
       leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
       modifiedLeafExtensions := leafCert.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 1, false)
       leafCert.SetExtensions(modifiedLeafExtensions)
       leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
       x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
       convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
       return convertedCert.Raw, nil 
}

func BadCertEmptyIssuer(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
       convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
       leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
       leafCert.SetIssuer(&pkix.Name{}) 
       leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
       x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
       convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
       return convertedCert.Raw, nil 
}

func BadCertNoSanEmptySubject(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
       convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
       leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
       leafCert.SetSubject(&pkix.Name{})
       modifiedLeafExtensions := leafCert.GetExtensions().UnsetSANExtension()
       leafCert.SetExtensions(modifiedLeafExtensions)
       leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
       x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
       convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
       return convertedCert.Raw, nil 
}

func BadCertNoSubjectSanNotCritical(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
       convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
       leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
       leafCert.SetSubject(&pkix.Name{})
       //Extenions don't need to be modified as the above function already creates SAN extension as non critical
       leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
       x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
       convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
       return convertedCert.Raw, nil 
}

func BadCertSanPresentButEmpty(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
       convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
       leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
       modifiedLeafExtensions := leafCert.GetExtensions().UnsetSANExtension()
       modifiedLeafExtensions = modifiedLeafExtensions.SetSANExtension(false, nil, nil, nil, nil)
       leafCert.SetExtensions(modifiedLeafExtensions)
       leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
       x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
       convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
       return convertedCert.Raw, nil 
}

func BadCertSigalgMismatch(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
       convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
       leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
       leafCert.SetSignatureAlgorithmFromPrivateKey(signerPrivateKey, badcert.SHA384WithRSA) 
       leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
       x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
       convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
       return convertedCert.Raw, nil 
}

func BadCertAKIDNotPresent(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
       convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
       leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)
       modifiedLeafExtensions := leafCert.GetExtensions().UnsetAKIDExtension()
       leafCert.SetExtensions(modifiedLeafExtensions)
       leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
       x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
       convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
       return convertedCert.Raw, nil 
}

func BadCertAKIDNoKeyid(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
       convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
       leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
       modifiedLeafExtensions := leafCert.GetExtensions().UnsetAKIDExtension().SetAKIDExtension(false, nil)
       leafCert.SetExtensions(modifiedLeafExtensions)
       leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
       x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
       convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
       return convertedCert.Raw, nil 
}

func BadCertAKIDCritical(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
       convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
       leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
       modifiedLeafExtensions := leafCert.GetExtensions().UnsetAKIDExtension().SetAKIDExtension(true, signerCert.SubjectKeyId)
       leafCert.SetExtensions(modifiedLeafExtensions)
       leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
       x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
       convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
       return convertedCert.Raw, nil 
}

func BadCertSKIDCritical(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
       convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
       leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
       modifiedLeafExtensions := leafCert.GetExtensions().UnsetSKIDExtension().SetSKIDExtensionFromKey(true, leafKey)
       leafCert.SetExtensions(modifiedLeafExtensions)
       leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
       x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
       convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
       return convertedCert.Raw, nil 
}

// SignCSR signs a certificate using Signer's Depot CA
func (s *Signer) SignCSR(m *scep.CSRReqMessage) (*x509.Certificate, error) {
	var crtBytes []byte
	var newerr error
	var certRequestTypeNum CertRequestType

	id, err := cryptoutil.GenerateSubjectKeyID(m.CSR.PublicKey)
	if err != nil {
		return nil, err
	}

	serial, err := s.depot.Serial()
	if err != nil {
		return nil, err
	}

	var signatureAlgo x509.SignatureAlgorithm
	if s.signatureAlgo != 0 {
		signatureAlgo = s.signatureAlgo
	}

	// create cert template
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      m.CSR.Subject,
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour).UTC(),
		SubjectKeyId: id,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		SignatureAlgorithm: signatureAlgo,
		DNSNames:           m.CSR.DNSNames,
		EmailAddresses:     m.CSR.EmailAddresses,
		IPAddresses:        m.CSR.IPAddresses,
		URIs:               m.CSR.URIs,
	}

	if s.serverAttrs {
		tmpl.KeyUsage |= x509.KeyUsageDataEncipherment | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
        
	caCerts, caKey, err := s.depot.CA([]byte(s.caPass))
	if err != nil {
		return nil, err
	}
        
	certRequestType := os.Getenv("CERT_REQUEST_TYPE")
	if certRequestType == "" {
		certRequestTypeNum = GOOD
	}

	certRequestTypeNumInt, err := strconv.Atoi(certRequestType)
	if err != nil {
		return nil, err
	}
	certRequestTypeNum = CertRequestType(certRequestTypeNumInt)

	if certRequestTypeNum == 0 {
		os.Stdout.Write([]byte("\nPerforming default signing\n"))
		crtBytes, newerr = x509.CreateCertificate(rand.Reader, tmpl, caCerts[0], m.CSR.PublicKey, caKey)
	        if newerr != nil {
			return nil, newerr
	        }
        } else if certRequestTypeNum == VERSION_1 {
		os.Stdout.Write([]byte("\nSigning with Version V1\n"))
		crtBytes, newerr = BadCertVersion1(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestTypeNum == VERSION_2 {
		os.Stdout.Write([]byte("\nSigning with Version V2\n"))
		crtBytes, newerr = BadCertVersion2(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestTypeNum == BASIC_CONST_CA_TRUE {
		os.Stdout.Write([]byte("\nSigning with Basic Constraints CA set to True\n"))
		crtBytes, newerr = BadCertBasicConstraintsCATrue(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestTypeNum == KEY_USAGE_KEYCERTSIGN {
		os.Stdout.Write([]byte("\nSigning with key usage containing KeyCertSign\n"))
		crtBytes, newerr = BadCertKeyusageKeycertsign(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestTypeNum == PATHLEN_PRESENT {
		os.Stdout.Write([]byte("\nSigning with Basic Constraints containing positive pathlen\n"))
		crtBytes, newerr = BadCertPathlenPresent(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestTypeNum == EMPTY_ISSUER {
		os.Stdout.Write([]byte("\nSigning with empty issuer\n"))
		crtBytes, newerr = BadCertEmptyIssuer(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestTypeNum == NO_SAN_EMPTY_SUBJECT {
		os.Stdout.Write([]byte("\nSigning with no SAN but empty Subject\n"))
		crtBytes, newerr = BadCertNoSanEmptySubject(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestTypeNum == NO_SUBJECT_SAN_NOT_CRITICAL {
		os.Stdout.Write([]byte("\nSigning with no Subject but SAN not critical\n"))
		crtBytes, newerr = BadCertNoSubjectSanNotCritical(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestTypeNum == SAN_PRESENT_BUT_EMPTY {
		os.Stdout.Write([]byte("\nSigning with SAN present but empty\n"))
		crtBytes, newerr = BadCertSanPresentButEmpty(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestTypeNum == SIGALG_MISMATCH {
		os.Stdout.Write([]byte("\nSigning with sigalg mismatch\n"))
		crtBytes, newerr = BadCertSigalgMismatch(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestTypeNum == AKID_NOT_PRESENT {
		os.Stdout.Write([]byte("\nSigning with AKID not present\n"))
		crtBytes, newerr = BadCertAKIDNotPresent(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestTypeNum == AKID_NO_KEYID {
		os.Stdout.Write([]byte("\nSigning with AKID containing no KeyId\n"))
		crtBytes, newerr = BadCertAKIDNoKeyid(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestTypeNum == AKID_CRITICAL {
		os.Stdout.Write([]byte("\nSigning with AKID critical\n"))
		crtBytes, newerr = BadCertAKIDCritical(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestTypeNum == SKID_CRITICAL {
		os.Stdout.Write([]byte("\nSigning with SKID critical\n"))
		crtBytes, newerr = BadCertSKIDCritical(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	}

	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, err
	}
	
	name := certName(crt)

	// Test if this certificate is already in the CADB, revoke if needed
	// revocation is done if the validity of the existing certificate is
	// less than allowRenewalDays
	_, err = s.depot.HasCN(name, s.allowRenewalDays, crt, false)
	if err != nil {
		return nil, err
	}

	if err := s.depot.Put(name, crt); err != nil {
		return nil, err
	}

	return crt, nil
}

func certName(crt *x509.Certificate) string {
	if crt.Subject.CommonName != "" {
		return crt.Subject.CommonName
	}
	return string(crt.Signature)
}
