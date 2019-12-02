package main

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/minio/highwayhash"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v2"
)

// Application constants
const (
	ErrorPrefix = "metahash: "

	HashKey = "9A9198AC29E70120624E3495C1354F81702A89F8C60748553282FD238AE26566"
)

// Config is a application config.
type Config struct {
	Path     string   `yaml:"path"`
	Excludes []string `yaml:"excludes"`

	// DB string `yaml:"db"`

	re  []*regexp.Regexp
	db  map[string][]byte
	key []byte
	h   hash.Hash
}

// nolint: gochecknoglobals
var (
	// Logging levels.
	Debug *log.Logger
	Info  *log.Logger
	Error *log.Logger
)

// Recurse recursively scans specified path and hashes files metadata.
func (cfg *Config) Recurse() error {
	return filepath.Walk(cfg.Path, func(path string, info os.FileInfo, e error) error {
		if info == nil {
			return nil
		}

		for i := range cfg.re {
			if cfg.re[i].MatchString(filepath.Join(cfg.Path, path, info.Name())) {
				Debug.Printf("Skip: %v", filepath.Join(cfg.Path, path, info.Name()))

				if info.IsDir() {
					return filepath.SkipDir
				}

				return nil
			}
		}

		if e != nil {
			return fmt.Errorf("%sscan error: %w", ErrorPrefix, e)
		}

		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}

		f := func(name string, h hash.Hash, values ...interface{}) error {
			b, err := GetHash(h, values...)
			if err != nil {
				return err
			}

			cfg.db[filepath.Join(cfg.Path, name)] = b

			Debug.Printf("Add: %v", filepath.Join(cfg.Path, path, info.Name()))

			return nil
		}

		switch v := info.Sys().(type) {
		case (*unix.Stat_t):
			if err := f(info.Name(), cfg.h, v.Mode, v.Uid, v.Gid, v.Size, v.Mtim.Sec, v.Mtim.Nsec, v.Ctim.Sec, v.Ctim.Nsec); err != nil {
				return fmt.Errorf("%sscan error: %w", ErrorPrefix, err)
			}
		case (*syscall.Stat_t):
			if err := f(info.Name(), cfg.h, v.Mode, v.Uid, v.Gid, v.Size, v.Mtim.Sec, v.Mtim.Nsec, v.Ctim.Sec, v.Ctim.Nsec); err != nil {
				return fmt.Errorf("%sscan error: %w", ErrorPrefix, err)
			}
		}

		return nil
	})
}

// IsDirectory returns 'True' when path is a directory.
func IsDirectory(path string) (bool, error) {
	fileInfo, err := os.Lstat(path)
	if err != nil {
		return false, err
	}

	return fileInfo.IsDir(), nil
}

// ReadConfig parses application config.
func ReadConfig(file string) (*Config, error) {
	cfg := new(Config)

	f, err := ioutil.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, fmt.Errorf("%sfailed to read application config: %w", ErrorPrefix, err)
	}

	err = yaml.Unmarshal(f, cfg)
	if err != nil {
		return nil, fmt.Errorf("%sfailed to parse application config: %w", ErrorPrefix, err)
	}

	var ok bool

	if ok, err = IsDirectory(cfg.Path); !ok {
		if err != nil {
			return nil, fmt.Errorf("%ssearch path is not a directory: %w", ErrorPrefix, err)
		}

		return nil, fmt.Errorf("%ssearch path is not a directory", ErrorPrefix)
	}

	for i := range cfg.Excludes {
		var re *regexp.Regexp

		re, err = regexp.Compile(cfg.Excludes[i])
		if err != nil {
			return nil, fmt.Errorf("%sexclude[%d] is not valid regexp: %w", ErrorPrefix, i, err)
		}

		cfg.re = append(cfg.re, re)
	}

	cfg.db = make(map[string][]byte)

	cfg.key, err = hex.DecodeString(HashKey)
	if err != nil {
		return nil, fmt.Errorf("%sfailed to decode hex key: %w", ErrorPrefix, err)
	}

	cfg.h, err = highwayhash.New64(cfg.key)
	if err != nil {
		return nil, fmt.Errorf("%sfailed to create hash instance: %w", ErrorPrefix, err)
	}

	return cfg, nil
}

// GetHash computes hash for input data.
func GetHash(h hash.Hash, values ...interface{}) ([]byte, error) {
	data := new(bytes.Buffer)
	enc := gob.NewEncoder(data)

	for i := range values {
		if err := enc.Encode(values[i]); err != nil {
			return nil, fmt.Errorf("%shash error: %w", ErrorPrefix, err)
		}
	}

	defer data.Reset()

	return h.Sum(data.Bytes()), nil
}

func main() {
	// initialize loggers
	Debug = log.New(
		os.Stdout,
		"DEBUG: ",
		log.Lshortfile,
	)
	Info = log.New(
		os.Stdout,
		"INFO: ",
		log.Lshortfile,
	)
	Error = log.New(
		os.Stderr,
		"ERROR: ",
		log.Lshortfile,
	)

	t := time.Now()

	cfg, err := ReadConfig("config.yaml")
	if err != nil {
		Error.Fatalf("%v\n", err)
	}

	if err = cfg.Recurse(); err != nil {
		Error.Fatalf("%v\n", err)
	}

	Info.Printf(
		"Elapsed: %s\nScaned files: %d\n",
		time.Since(t).Truncate(time.Millisecond).String(),
		len(cfg.db),
	)
}
