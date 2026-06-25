package zlog

import "time"

func applyEncoderOptions(s Sink, opts Options) {
	if s == nil {
		return
	}
	switch x := s.(type) {
	case *WriterSink:
		applyEncoderConfig(x.enc, opts)
	case *MultiSink:
		for _, child := range x.sinks {
			applyEncoderOptions(child, opts)
		}
	case *AsyncSink:
		applyEncoderOptions(x.sink, opts)
	}
}

func applyEncoderConfig(enc Encoder, opts Options) {
	layout := opts.TimeLayout
	if layout == "" {
		layout = opts.TimeFormat
	}
	switch e := enc.(type) {
	case *ConsoleEncoder:
		if layout != "" {
			e.TimeFormat = layout
		} else if e.TimeFormat == "" {
			e.TimeFormat = time.RFC3339Nano
		}
		if opts.ConsoleColor != nil {
			e.Color = *opts.ConsoleColor
		}
		if opts.Prettify != nil {
			e.Prettify = *opts.Prettify
		}
		if opts.KVSeparator != "" {
			e.KVSeparator = opts.KVSeparator
		}
		if opts.PairSeparator != "" {
			e.PairSeparator = opts.PairSeparator
		}
	case *JSONEncoder:
		if layout != "" {
			e.TimeFormat = layout
		}
	case *LogfmtEncoder:
		if layout != "" {
			e.TimeFormat = layout
		}
	}
}

func applySinkRedactor(s Sink, redactor Redactor) {
	if s == nil {
		return
	}
	switch x := s.(type) {
	case *WriterSink:
		x.Redactor(redactor)
	case *MultiSink:
		for _, child := range x.sinks {
			applySinkRedactor(child, redactor)
		}
	case *AsyncSink:
		applySinkRedactor(x.sink, redactor)
	}
}
