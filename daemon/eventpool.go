// Copyright (c) 2018-2019 Aalborg University
// Use of this source code is governed by a GPLv3
// license that can be found in the LICENSE file.

package daemon

import (
	"github.com/aau-network-security/haaukins/svcs/ctfd"
	"net/http"
	"strings"
	"sync"

	"github.com/aau-network-security/haaukins/store"
)

type EventPool struct {
	m               sync.RWMutex
	host            string
	notFoundHandler http.Handler
	events          map[store.Tag]ctfd.Event
	handlers        map[store.Tag]http.Handler
}

func NewEventPool(host string) *EventPool {
	return &EventPool{
		host:            host,
		notFoundHandler: notFoundHandler(),
		events:          map[store.Tag]ctfd.Event{},
		handlers:        map[store.Tag]http.Handler{},
	}
}

func (ep *EventPool) AddEvent(ev ctfd.Event) {
	tag := ev.GetConfig().Tag

	ep.m.Lock()
	defer ep.m.Unlock()

	ep.events[tag] = ev
	ep.handlers[tag] = ev.Handler()
}

func (ep *EventPool) RemoveEvent(t store.Tag) error {
	ep.m.Lock()
	defer ep.m.Unlock()

	if _, ok := ep.events[t]; !ok {
		return UnknownEventErr
	}

	delete(ep.events, t)
	delete(ep.handlers, t)

	return nil
}

func (ep *EventPool) GetEvent(t store.Tag) (ctfd.Event, error) {
	ep.m.RLock()
	ev, ok := ep.events[t]
	ep.m.RUnlock()
	if !ok {
		return nil, UnknownEventErr
	}

	return ev, nil
}

func (ep *EventPool) GetAllEvents() []ctfd.Event {
	events := make([]ctfd.Event, len(ep.events))

	var i int
	ep.m.RLock()
	for _, ev := range ep.events {
		events[i] = ev
		i++
	}
	ep.m.RUnlock()

	return events
}

func (ep *EventPool) Close() error {
	var firstErr error

	for _, ev := range ep.events {
		if err := ev.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

func (ep *EventPool) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	domainParts := strings.SplitN(r.Host, ".", 2)

	if len(domainParts) != 2 {
		ep.notFoundHandler.ServeHTTP(w, r)
		return
	}

	sub, dom := domainParts[0], domainParts[1]
	if !strings.HasPrefix(dom, ep.host) {
		ep.notFoundHandler.ServeHTTP(w, r)
		return
	}

	ep.m.RLock()
	mux, ok := ep.handlers[store.Tag(sub)]
	ep.m.RUnlock()
	if !ok {
		ep.notFoundHandler.ServeHTTP(w, r)
		return
	}

	mux.ServeHTTP(w, r)
}

func getHost(r *http.Request) string {
	if r.URL.IsAbs() {
		host := r.Host
		// Slice off any port information.
		if i := strings.Index(host, ":"); i != -1 {
			host = host[:i]
		}
		return host
	}
	return r.URL.Host
}
