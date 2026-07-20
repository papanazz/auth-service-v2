package config

import (
	"errors"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	AppName  string `env:"APP_NAME" envDefault:"auth-service-v2"`
	AppEnv   string `env:"APP_ENV" envDefault:"development"`
	LogLevel string `env:"LOG_LEVEL" envDefault:"debug"`

	HTTP          HTTPConfig
	Database      DatabaseConfig
	Redis         RedisConfig
	Observability ObservabilityConfig
}

type HTTPConfig struct {
	Port            int           `env:"HTTP_PORT" envDefault:"8080"`
	ShutdownTimeout time.Duration `env:"HTTP_SHUTDOWN_TIMEOUT" envDefault:"10s"`
}

type DatabaseConfig struct {
	URL                   string        `env:"DATABASE_URL"`
	MaxConnections        int32         `env:"DATABASE_MAX_CONNECTIONS" envDefault:"20"`
	MinConnections        int32         `env:"DATABASE_MIN_CONNECTIONS" envDefault:"5"`
	MaxConnectionLifetime time.Duration `env:"DATABASE_MAX_CONNECTION_LIFETIME" envDefault:"30m"`
	MaxConnectionIdleTime time.Duration `env:"DATABASE_MAX_CONNECTION_IDLE_TIME" envDefault:"5m"`
	HealthCheckPeriod     time.Duration `env:"DATABASE_HEALTH_CHECK_PERIOD" envDefault:"1m"`
}

type ObservabilityConfig struct {
	OTLPExporterEndpoint string `env:"OTEL_EXPORTER_OTLP_ENDPOINT" envDefault:"localhost:4317"`
}

type RedisConfig struct {
	Address            string        `env:"REDIS_ADDRESS" envDefault:"localhost:6379"`
	Password           string        `env:"REDIS_PASSWORD"`
	DB                 int           `env:"REDIS_DB" envDefault:"0"`
	PoolSize           int           `env:"REDIS_POOL_SIZE" envDefault:"20"`
	MinIdleConnections int           `env:"REDIS_MIN_IDLE_CONNECTIONS" envDefault:"5"`
	DialTimeout        time.Duration `env:"REDIS_DIAL_TIMEOUT" envDefault:"5s"`
	ReadTimeout        time.Duration `env:"REDIS_READ_TIMEOUT" envDefault:"3s"`
	WriteTimeout       time.Duration `env:"REDIS_WRITE_TIMEOUT" envDefault:"3s"`
	PoolTimeout        time.Duration `env:"REDIS_POOL_TIMEOUT" envDefault:"4s"`
	IdleTimeout        time.Duration `env:"REDIS_IDLE_TIMEOUT" envDefault:"5m"`
}

func Load() (*Config, error) {

	// Load .env if exists
	// Ignore error because production uses real environment variables
	_ = godotenv.Load()

	cfg := &Config{}

	if err := env.Parse(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {

	if c.Database.URL == "" {
		return errors.New(
			"DATABASE_URL is required",
		)
	}

	return nil
}
