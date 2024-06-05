package authrule

import (
	"fmt"
	"github.com/samber/lo"
	"github.com/traPtitech/traefik-forward-auth/internal/token"
	"github.com/vulcand/predicate"
	"regexp"
)

type Predicate func(object any) bool

func andFunc(left, right Predicate) Predicate {
	return func(object any) bool {
		return left(object) && right(object)
	}
}

func orFunc(left, right Predicate) Predicate {
	return func(object any) bool {
		return left(object) || right(object)
	}
}

func notFunc(fn Predicate) Predicate {
	return func(object any) bool {
		return !fn(object)
	}
}

func truePredicate() Predicate {
	return func(object any) bool {
		return true
	}
}

func inPredicate(allowedPaths []string) func(path string, targets ...string) (Predicate, error) {
	return func(path string, targets ...string) (Predicate, error) {
		if !lo.Contains(allowedPaths, path) {
			return nil, fmt.Errorf("\"%v\" is not allowed as path reference - include it in \"info-fields\" config", path)
		}
		return func(object any) bool {
			strRep, ok := token.GetPathStr(object, path)
			if !ok {
				return false
			}
			for _, target := range targets {
				if strRep == target {
					return true
				}
			}
			return false
		}, nil
	}
}

func regexpPredicate(allowedPaths []string) func(path string, pattern string) (Predicate, error) {
	return func(path string, pattern string) (Predicate, error) {
		if !lo.Contains(allowedPaths, path) {
			return nil, fmt.Errorf("\"%v\" is not allowed as path reference, include it in \"info-fields\" config", path)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		return func(object any) bool {
			strRep, ok := token.GetPathStr(object, path)
			if !ok {
				return false
			}
			return re.MatchString(strRep)
		}, nil
	}
}

var operators = predicate.Operators{
	AND: andFunc,
	OR:  orFunc,
	NOT: notFunc,
}

func NewAuthRule(rule string, allowedPaths []string) (Predicate, error) {
	parser, err := predicate.NewParser(predicate.Def{
		Operators: operators,
		Functions: map[string]any{
			"True":   truePredicate,
			"In":     inPredicate(allowedPaths),
			"Regexp": regexpPredicate(allowedPaths),
		},
	})
	if err != nil {
		return nil, err
	}

	pr, err := parser.Parse(rule)
	if err != nil {
		return nil, err
	}
	return pr.(Predicate), nil
}
