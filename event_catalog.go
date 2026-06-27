package zlog

import "fmt"

type EventDefinition struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Required   []string `json:"required"`
	Optional   []string `json:"optional"`
	Compliance []string `json:"compliance"`
}

type EventCatalog struct{ defs map[string]EventDefinition }

func NewEventCatalog(defs ...EventDefinition) *EventCatalog {
	c := &EventCatalog{defs: map[string]EventDefinition{}}
	for _, d := range defs {
		c.Register(d)
	}
	return c
}
func (c *EventCatalog) Register(d EventDefinition) {
	if c.defs == nil {
		c.defs = map[string]EventDefinition{}
	}
	c.defs[d.Name] = d
}
func (c *EventCatalog) Get(name string) (EventDefinition, bool) { d, ok := c.defs[name]; return d, ok }
func (c *EventCatalog) Validate(name string, attrs []Attr) error {
	d, ok := c.Get(name)
	if !ok {
		return fmt.Errorf("zlog event %q is not registered", name)
	}
	have := map[string]bool{}
	for _, a := range attrs {
		have[a.Key] = true
	}
	for _, k := range d.Required {
		if !have[k] {
			return fmt.Errorf("zlog event %q missing required attr %q", name, k)
		}
	}
	return nil
}
func (l *Logger) Event(c *EventCatalog, level Level, name string, attrs ...Attr) error {
	if c != nil {
		if err := c.Validate(name, attrs); err != nil {
			return err
		}
	}
	l.Log(level, name, append([]Attr{EventName(name)}, attrs...)...)
	return nil
}
