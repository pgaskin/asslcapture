// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// Package pflagx extends github.com/spf13/pflag with extra functionality.
package pflagx

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

const annotationGroup = "group"

// RegisterFlags registers flags from a pointer to a struct with the default
// values and tags: group, long, short, metavar, doc.
func RegisterFlags(fs *pflag.FlagSet, cfg any) {
	rv := reflect.ValueOf(cfg).Elem()
	rt := rv.Type()
	for i := range rt.NumField() {
		field := rt.Field(i)
		fv := rv.Field(i)

		long := field.Tag.Get("long")
		if long == "" {
			continue
		}
		short := field.Tag.Get("short")
		doc := field.Tag.Get("doc")

		switch p := fv.Addr().Interface().(type) {
		case *bool:
			if short != "" {
				fs.BoolVarP(p, long, short, *p, doc)
			} else {
				fs.BoolVar(p, long, *p, doc)
			}
		case *string:
			if short != "" {
				fs.StringVarP(p, long, short, *p, doc)
			} else {
				fs.StringVar(p, long, *p, doc)
			}
		case *[]string:
			if short != "" {
				fs.StringArrayVarP(p, long, short, *p, doc)
			} else {
				fs.StringArrayVar(p, long, *p, doc)
			}
		case *time.Duration:
			if short != "" {
				fs.DurationVarP(p, long, short, *p, doc)
			} else {
				fs.DurationVar(p, long, *p, doc)
			}
		case *int:
			if short != "" {
				fs.IntVarP(p, long, short, *p, doc)
			} else {
				fs.IntVar(p, long, *p, doc)
			}
		case *[]int:
			if short != "" {
				fs.IntSliceVarP(p, long, short, *p, doc)
			} else {
				fs.IntSliceVar(p, long, *p, doc)
			}
		}

		if group := field.Tag.Get("group"); group != "" {
			fs.SetAnnotation(long, annotationGroup, []string{group})
		}
		if metavar := field.Tag.Get("metavar"); metavar != "" {
			fs.SetAnnotation(long, "metavar", []string{metavar})
		}
	}
}

func PrintHelp(fs *pflag.FlagSet) {
	var groups []string
	seen := make(map[string]bool)
	grouped := make(map[string][]*pflag.Flag)
	fs.VisitAll(func(f *pflag.Flag) {
		group := ""
		if g := f.Annotations[annotationGroup]; len(g) > 0 {
			group = g[0]
		}
		if !seen[group] {
			seen[group] = true
			groups = append(groups, group)
		}
		grouped[group] = append(grouped[group], f)
	})

	fmt.Fprintf(fs.Output(), "usage: %s [options]\n", fs.Name())
	for _, group := range groups {
		flags := grouped[group]
		if len(flags) == 0 {
			continue
		}

		labels := make([]string, len(flags))
		maxLen := 0
		for i, f := range flags {
			labels[i] = flagLabel(f)
			if len(labels[i]) > maxLen {
				maxLen = len(labels[i])
			}
		}

		indent := 2 + maxLen + 2
		fmt.Fprintf(fs.Output(), "\n%s OPTIONS\n", strings.ToUpper(group))
		for i, f := range flags {
			doc := wrapText(f.Usage+defaultSuffix(f), indent, 120)
			fmt.Fprintf(fs.Output(), "  %-*s  %s\n", maxLen, labels[i], doc)
		}
	}
	fmt.Fprintln(fs.Output())
}

func wrapText(text string, indent, totalWidth int) string {
	width := totalWidth - indent
	if width <= 0 || len(text) <= width {
		return text
	}
	cont := "\n" + strings.Repeat(" ", indent)
	var b strings.Builder
	b.Grow(len(text))
	lineLen := 0
	for len(text) > 0 {
		nsp := strings.IndexFunc(text, func(r rune) bool {
			return r != ' '
		})
		if nsp < 0 {
			break
		}
		nw := strings.IndexByte(text[nsp:], ' ')
		if nw < 0 {
			nw = len(text)
		} else {
			nw += nsp
		}
		spaces, word := text[:nsp], text[nsp:nw]
		text = text[nw:]
		if lineLen == 0 {
			b.WriteString(word)
			lineLen = len(word)
		} else if lineLen+len(spaces)+len(word) <= width {
			b.WriteString(spaces)
			b.WriteString(word)
			lineLen += len(spaces) + len(word)
		} else {
			b.WriteString(cont)
			b.WriteString(word)
			lineLen = len(word)
		}
	}
	return b.String()
}

func defaultSuffix(f *pflag.Flag) string {
	switch f.Value.Type() {
	case "bool":
		return ""
	case "string":
		if f.DefValue == "" {
			return ""
		}
		return ` (default: "` + f.DefValue + `")`
	case "int", "int64", "uint", "uint64":
		if f.DefValue == "0" {
			return ""
		}
		return " (default: " + f.DefValue + ")"
	case "duration":
		if f.DefValue == "0s" {
			return ""
		}
		return " (default: " + f.DefValue + ")"
	case "stringArray", "stringSlice", "intSlice":
		if f.DefValue == "[]" || f.DefValue == "" {
			return ""
		}
		return " (default: " + f.DefValue + ")"
	default:
		if f.DefValue == "" {
			return ""
		}
		return " (default: " + f.DefValue + ")"
	}
}

func flagLabel(f *pflag.Flag) string {
	var name string
	if f.Shorthand != "" {
		name = fmt.Sprintf("-%s, --%s", f.Shorthand, f.Name)
	} else {
		name = fmt.Sprintf("    --%s", f.Name)
	}
	if mv := f.Annotations["metavar"]; len(mv) > 0 {
		name += " " + mv[0]
	} else if f.Value.Type() != "bool" {
		name += " " + f.Value.Type()
	}
	return name
}
