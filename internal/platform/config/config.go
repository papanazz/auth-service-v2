package config

import (
	"errors"
	"os"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	App           AppConfig
	Server        ServerConfig
	Database      DatabaseConfig
	Redis         RedisConfig
	Security      SecurityConfig
	Observability ObservabilityConfig
}

type AppConfig struct {
	Name     string `env:"APP_NAME" envDefault:"auth-service"`
	Env      string `env:"APP_ENV" envDefault:"development"`
	LogLevel string `env:"LOG_LEVEL" envDefault:"debug"`
}

type ServerConfig struct {
	HTTP HTTPConfig
	GRPC GRPCConfig
}

type HTTPConfig struct {
	Port            int           `env:"HTTP_PORT" envDefault:"8080"`
	ShutdownTimeout time.Duration `env:"HTTP_SHUTDOWN_TIMEOUT" envDefault:"10s"`
}

type GRPCConfig struct {
	Port int `env:"GRPC_PORT" envDefault:"9090"`
}

type DatabaseConfig struct {
	URL string `env:"DATABASE_URL"`

	MaxConnections        int32         `env:"DATABASE_MAX_CONNECTIONS" envDefault:"20"`
	MinConnections        int32         `env:"DATABASE_MIN_CONNECTIONS" envDefault:"5"`
	MaxConnectionLifetime time.Duration `env:"DATABASE_MAX_CONNECTION_LIFETIME" envDefault:"30m"`
	MaxConnectionIdleTime time.Duration `env:"DATABASE_MAX_CONNECTION_IDLE_TIME" envDefault:"5m"`
	HealthCheckPeriod     time.Duration `env:"DATABASE_HEALTH_CHECK_PERIOD" envDefault:"1m"`
}

type RedisConfig struct {
	Address  string `env:"REDIS_ADDRESS" envDefault:"localhost:6379"`
	Password string `env:"REDIS_PASSWORD"`
	DB       int    `env:"REDIS_DB" envDefault:"0"`

	PoolSize           int           `env:"REDIS_POOL_SIZE" envDefault:"20"`
	MinIdleConnections int           `env:"REDIS_MIN_IDLE_CONNECTIONS" envDefault:"5"`
	DialTimeout        time.Duration `env:"REDIS_DIAL_TIMEOUT" envDefault:"5s"`
	ReadTimeout        time.Duration `env:"REDIS_READ_TIMEOUT" envDefault:"3s"`
	WriteTimeout       time.Duration `env:"REDIS_WRITE_TIMEOUT" envDefault:"3s"`
	PoolTimeout        time.Duration `env:"REDIS_POOL_TIMEOUT" envDefault:"4s"`
	IdleTimeout        time.Duration `env:"REDIS_IDLE_TIMEOUT" envDefault:"5m"`
}

type SecurityConfig struct {
	JWT          JWTConfig
	RefreshToken RefreshTokenConfig
	Login        LoginSecurityConfig
}

type JWTConfig struct {
	SecretKey string        `env:"JWT_SECRET_KEY"`
	TTL       time.Duration `env:"JWT_TTL" envDefault:"15m"`
}

type RefreshTokenConfig struct {
	TTL time.Duration `env:"REFRESH_TOKEN_TTL" envDefault:"720h"`
}

type LoginSecurityConfig struct {
	IP    LoginIPConfig
	Email LoginEmailConfig
}

type LoginIPConfig struct {
	Limit  int           `env:"LOGIN_IP_LIMIT" envDefault:"20"`
	Window time.Duration `env:"LOGIN_IP_WINDOW" envDefault:"1m"`
}

type LoginEmailConfig struct {
	Limit  int           `env:"LOGIN_EMAIL_LIMIT" envDefault:"5"`
	Window time.Duration `env:"LOGIN_EMAIL_WINDOW" envDefault:"15m"`
}

type ObservabilityConfig struct {
	OTLPExporterEndpoint string `env:"OTEL_EXPORTER_OTLP_ENDPOINT" envDefault:"localhost:4317"`
}

func Load() (*Config, error) {
	_ = godotenv.Load(".env")

	if appEnv := os.Getenv("APP_ENV"); appEnv != "" {
		_ = godotenv.Overload(".env." + appEnv)
	}

	cfg := &Config{}

	if err := env.Parse(cfg); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Database.URL == "" {
		return errors.New("DATABASE_URL is required")
	}

	if c.Security.JWT.SecretKey == "" {
		return errors.New("JWT_SECRET_KEY is required")
	}

	return nil
}
