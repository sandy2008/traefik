package internal

// TlsOptions holds TLS configuration options
type TlsOptions struct {
	Tls          string
	Cert         string
	Key          string
	Cacert       string
	AllowedUsers string
}
