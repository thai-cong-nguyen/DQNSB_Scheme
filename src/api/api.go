package api

// APIConfig represents the API service configuration
type APIConfig struct {
	HTTPPort       int
	WSPort         int
	RateLimits     map[string]int
	AllowedOrigins []string
	TLSEnabled     bool
	AuthEnabled    bool
}
