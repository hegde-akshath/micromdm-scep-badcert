package depot

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/rsa"
	"time"
	"fmt"
	"runtime/debug"
	"os"
        
	"unsafe"
	"github.com/hegde-akshath/badcert"
	"github.com/hegde-akshath/badcert/pkix"
	"github.com/hegde-akshath/micromdm-scep-badcert/cryptoutil"
	"github.com/smallstep/scep"
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

func SetVersion1(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
	convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
	leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
	leafCert = leafCert.SetVersion1()
	leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
	x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
	convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
	return convertedCert.Raw, nil
}

func SetVersion2(tmpl *x509.Certificate, leafKey any, signerCert *x509.Certificate, signerPrivateKey *rsa.PrivateKey) ([]byte, error) {
	convertedSignatureAlgorithm := *((*badcert.SignatureAlgorithm)(unsafe.Pointer(&tmpl.SignatureAlgorithm)))
	leafCert := BuildLeafCertificateRecipe(tmpl, leafKey, signerCert, signerPrivateKey)	
	leafCert = leafCert.SetVersion2()
	leafCert.SignTBS(signerPrivateKey, convertedSignatureAlgorithm)
	x509Cert := badcert.GetCertificateFromBadCertificate(leafCert)
	convertedCert := (*x509.Certificate)(unsafe.Pointer(x509Cert))
	return convertedCert.Raw, nil
}

// SignCSR signs a certificate using Signer's Depot CA
func (s *Signer) SignCSR(m *scep.CSRReqMessage) (*x509.Certificate, error) {
	var crtBytes []byte
	var newerr error

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
        
	crtBytes, newerr = x509.CreateCertificate(rand.Reader, tmpl, caCerts[0], m.CSR.PublicKey, caKey)
	if newerr != nil {
		return nil, newerr
	}
        
	certRequestType := os.Getenv("CERT_REQUEST_TYPE")
	if certRequestType == "" || certRequestType == "good" {
		os.Stdout.Write([]byte("\nPerforming default signing\n"))
		crtBytes, newerr = x509.CreateCertificate(rand.Reader, tmpl, caCerts[0], m.CSR.PublicKey, caKey)
	        if newerr != nil {
			return nil, newerr
	        }
        } else if certRequestType == "v1" {
		os.Stdout.Write([]byte("\nSigning with Version V1\n"))
		crtBytes, newerr = SetVersion1(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
                if newerr != nil {
			return nil, newerr
	        }
	} else if certRequestType == "v2" {
		os.Stdout.Write([]byte("\nSigning with Version V2\n"))
		crtBytes, newerr = SetVersion2(tmpl, m.CSR.PublicKey, caCerts[0], caKey)
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
