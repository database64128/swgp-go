//go:build !linux

package service

import "context"

type statusNotifier struct{}

func newStatusNotifier(context.Context) statusNotifier { return statusNotifier{} }

func (statusNotifier) Close() error { return nil }
func (statusNotifier) Ready()       {}
func (statusNotifier) Stopping()    {}
