package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"goiyov/cache"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/pkg/errors"
)

var (
	rootCa  *x509.Certificate // CA证书
	rootKey *rsa.PrivateKey   // 证书私钥
)

var (
	_rootCa = []byte(`-----BEGIN CERTIFICATE-----
MIIDEDCCAfgCFCPC5VTUh33lj0dbmziBqdrPGdS1MA0GCSqGSIb3DQEBCwUAMBQx
EjAQBgNVBAMMCXN0YXJ0LmNvbTAeFw0yMTA0MTMwMjU2MjBaFw0yMjA0MTMwMjU2
MjBaMHUxCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJHRDELMAkGA1UEBwwCU1oxDDAK
BgNVBAoMA0NPTTEMMAoGA1UECwwDTlNQMQ8wDQYDVQQDDAZTRVJWRVIxHzAdBgkq
hkiG9w0BCQEWEHlvdXJlbWFpbEBxcS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCcayRe9kHtLGc3ytV5e6NxbgayLP1TMG3YE8okDlwNRKD0HFN6
WWBZbUCAN+8wTSimeVZTGWAy8E4yk8mJL1e7eUIF9HP95f0EAQFWWe5IpcLBpQSR
GsG67vISF7D4i6B7GUTDixLNgKwmVQvv1FxxOux0MMf+rDVEPEVr2cE0s+ubW5jd
aR/AXdGO3KPX5OEVqUCw1D1QBszmn21Iwrh74+wh0cmetkw1NHbQUMzJ5JCEQnBR
kD/YXZGRL0iqtqOd1LHyXlGYoASgwikm1ckFv9Kr5RZrGuB3g5D0B1W42arYRZYu
cLEL4bchnU6Cq0nbhbwUR2FbFau5tC/mvea9AgMBAAEwDQYJKoZIhvcNAQELBQAD
ggEBAC7mLDWFOwTrz3R6I0F0npgKS7bBXpztSwrIBsz9RKAhGGaeS93S35Enxaex
hnoY2Q3lhmkOKmZPfpio0B1OxFDod0PaMD5AhxiXLfXDP29Kxvs8hLzQ+WUyA0m3
1+ZXOzXLvgGFbO9Y6gCIWtdWCVeIOsHGic1sMRk5a0Wd2evMJmJxOkLceh+n1pZg
ri8PrMj3GBaxx6QZWx2AeRiBfwkS/NzskfYBNDLQU40Bpygtd7H7czQ6Clf5WvJ5
anJLq6PcsaPlzs4UjNeMoSleXXP0Oi5yHnlzo1n1VfA/DWPgvYQqQ/e8Xr6zK+lR
dVUe+psUe6D059yFDm5cvKgAoAw=
-----END CERTIFICATE-----
`)
	_rootKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAnGskXvZB7SxnN8rVeXujcW4Gsiz9UzBt2BPKJA5cDUSg9BxT
ellgWW1AgDfvME0opnlWUxlgMvBOMpPJiS9Xu3lCBfRz/eX9BAEBVlnuSKXCwaUE
kRrBuu7yEhew+IugexlEw4sSzYCsJlUL79RccTrsdDDH/qw1RDxFa9nBNLPrm1uY
3WkfwF3Rjtyj1+ThFalAsNQ9UAbM5p9tSMK4e+PsIdHJnrZMNTR20FDMyeSQhEJw
UZA/2F2RkS9IqrajndSx8l5RmKAEoMIpJtXJBb/Sq+UWaxrgd4OQ9AdVuNmq2EWW
LnCxC+G3IZ1OgqtJ24W8FEdhWxWrubQv5r3mvQIDAQABAoIBAHPsS8Y9B1r4v35v
yooAAX99JWVDRnMyvxWWhQb3xWzn4clIfO1985QTDex4h8HqTSgjYMCxW8QkqC9/
q6sJ9SExmqbDJnuSyVMAU7dlat1YS+ArphjMFauujqSt/jAVetgAQCATn9nBdNPr
z67sWZ5pJvhtdqrdgZSSfniRp0igrkrYZoCgsy6wwHMfBIdU8EzYNUtNXVgrk0hH
jKaPXBXLe9h/IHtM1ynC/kyjwMnSWdarAvKm+7aP/6Nxs2Pz9GDk50HaRs4USCo1
I9PyoZh/0Qzqla/qxurEuNH42thIIWkgVnrjzcXvbQf97+YPxE5W+AhENtf1RabD
tTBEaYECgYEAzllZ3OrXk++wNOe+H7gBAqOpp/tYOgKnSj/c4dk/BcV/9cHEIsTb
vFAC2DLCa1sXfA0KkGR6q5qgZYcsmKakHORLm1ViYrg8dBvBs1+8i76e1nSu51t+
CcsKabuxvwQFipKY6iZsllmK2gokeBBzIy8k1IsLNGs1OmA967oM4C0CgYEAwg4u
YXxRf0C+vF9wnXQ0J6LQOOvHt+wqSg4P51tWhkC/8FMSVmrNgmC/8JvsBg0IiSTf
zXhA3Ei5hguVrHRn6Rqdp2rqHVIH7RTtqhbieo9iH5l96lwGgzgbkWv/92hwmwK3
X6mNYe/4FH2CLZJR5uhHcd2Qzqnhcj7LnvfxqtECgYEApySO+rgq6MSkySXRxeWI
w/eHq+6Wt16A3U6/fx02xFkG3i0Wz0b/6hgxRahP/R+q9SunG/CXwLqeI78La5bH
pjNx3p+Z8vbi2PXGv6HTmqpMBNA9AGAGxq31gFGtl1kNmAJI5Jk9KcfcBeNjSPGi
IaTFQ3hhGhOg6OkeHvv0A/0CgYA5hHyI1pFNV4JxURSPBt9ilCaFiJU01aIfOxXJ
rE/0EQMTF3xK8vMg3s5lYcHOdVR/WdegDjGjWUbsDUj6ybH27LWn5s+niyXgRqC/
FnNggllCJnuk2Evx3tKFAu7mhSVDPMXfa+EFE1yDrkPEgCcYeuaaQGLobn/tHeG6
p6EQ0QKBgQCqK4ilPfTDW7MkYPgEmtJ973tfoFr5fMPcygKu0zg+JlRSpjbjhwwF
k1t8I0V1cYnj0+MRp8isgqwOz/eKhos3Rt2AU4MN25WlOoXiXYvBOanzpxuIwxXB
OHlntLMmCMGcnfy92lzFyRhyRJEPEdru7LwYC7qKpAiRFPXChjXHiw==
-----END RSA PRIVATE KEY-----
`)
)

var certCache *cache.Cache

func init() {
	certCache = cache.NewCache()

	if err := loadRootCa(); err != nil {
		panic(err)
	}
	if err := loadRootKey(); err != nil {
		panic(err)
	}
}

func GetCertificate(host string) (tls.Certificate, error) {
	certificate, err := certCache.GetOrStore(host, func() (interface{}, error) {
		host, _, err := net.SplitHostPort(host)
		if err != nil {
			return nil, err
		}
		certByte, priByte, err := generatePem(host)
		if err != nil {
			return nil, err
		}
		certificate, err := tls.X509KeyPair(certByte, priByte)
		if err != nil {
			return nil, err
		}
		return certificate, nil
	})
	return certificate.(tls.Certificate), err
}
func generatePem(host string) ([]byte, []byte, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)   //把 1 左移 128 位，返回给 big.Int
	serialNumber, _ := rand.Int(rand.Reader, max) //返回在 [0, max) 区间均匀随机分布的一个随机值
	template := x509.Certificate{
		SerialNumber: serialNumber, // SerialNumber 是 CA 颁布的唯一序列号，在此使用一个大随机数来代表它
		Subject: pkix.Name{ //Name代表一个X.509识别名。只包含识别名的公共属性，额外的属性被忽略。
			CommonName: host,
		},
		NotBefore:      time.Now().AddDate(-1, 0, 0),
		NotAfter:       time.Now().AddDate(1, 0, 0),
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, //KeyUsage 与 ExtKeyUsage 用来表明该证书是用来做服务器认证的
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},               // 密钥扩展用途的序列
		EmailAddresses: []string{"forward.nice.cp@gmail.com"},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	priKey, err := generateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	cer, err := x509.CreateCertificate(rand.Reader, &template, rootCa, &priKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{ // 证书
			Type:  "CERTIFICATE",
			Bytes: cer,
		}), pem.EncodeToMemory(&pem.Block{ // 私钥
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priKey),
		}), err
}

// 秘钥对 生成一对具有指定字位数的RSA密钥
func generateKeyPair() (*rsa.PrivateKey, error) {
	priKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrap(err, "密钥对生成失败")
	}

	return priKey, nil
}

// 加载根证书
func loadRootCa() error {
	p, _ := pem.Decode(_rootCa)
	var err error
	rootCa, err = x509.ParseCertificate(p.Bytes)
	if err != nil {
		return errors.Wrap(err, "CA证书解析失败")
	}

	return nil
}

// 加载根Private Key
func loadRootKey() error {
	p, _ := pem.Decode(_rootKey)
	var err error
	rootKey, err = x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		return errors.Wrap(err, "Key证书解析失败")
	}

	return err
}

// 获取证书原内容
func GetCaCert() []byte {
	return _rootCa
}

// 添加信任跟证书至钥匙串
func AddTrustedCert() error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}

	fileName := dir + "/caRootCert.crt"
	file, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer os.Remove(fileName)
	defer file.Close()

	file.Write(_rootCa)

	var command string
	switch runtime.GOOS {
	case "darwin":
		command = fmt.Sprintf("sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s", fileName)
	case "windows":
		command = fmt.Sprintf("certutil -addstore -f \"ROOT\" %s", fileName)
	default:
		return errors.New("仅支持MaxOS/Windows系统")
	}

	return shell(command)
}

// 执行shell命令
func shell(command string) error {
	cmd := exec.Command("sh", "-c", command)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		return errors.Wrap(err, "")
	}
	return errors.Wrap(cmd.Wait(), out.String())
}
