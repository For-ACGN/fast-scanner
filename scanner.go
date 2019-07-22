package scanner

import (
	"context"
	"sync"

	"github.com/pkg/errors"
)

type Scanner struct {
	targets   string
	ports     string
	opts      *Options
	ctx       context.Context
	cancel    func()
	startOnce sync.Once
	stopOnce  sync.Once
}

func New(targets, ports string, opts *Options) (*Scanner, error) {
	if targets == "" {
		return nil, errors.New("no targets")
	}
	if ports == "" {
		return nil, errors.New("no ports")
	}
	opts.apply()
	ctx, cancel := context.WithCancel(context.Background())
	s := Scanner{
		targets: targets,
		ports:   ports,
		opts:    opts,
		ctx:     ctx,
		cancel:  cancel,
	}
	return &s, nil
}

func (s *Scanner) Start() error {

	generator, err := GenTargets(s.ctx, s.targets)
	if err != nil {
		return err
	}
	<-generator

	return nil
}

func (s *Scanner) Stop() {
	s.stopOnce.Do(func() {
		s.cancel()
	})
}
