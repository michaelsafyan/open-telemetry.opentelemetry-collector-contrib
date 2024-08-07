// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "interpolation" assists with interpolating variables
// from relevant OTel signals in URIs used for storage.
//
// The "resolver.go" file provides the default implementation
// of the "VariableResolver" interface that is used in this package.
package interpolation

import (
	"unicode/utf8"
)

// Implementation of "VariableResolver"
type resolverImpl struct {
	ctx InterpolationContext
}

// Identifies a token in the variable resolution expression
type tokenType int
const (
	TOKEN_TYPE_INVALID tokenType = iota,
	IDENTIFIER,
	DOT,
	STRING_LITERAL,
	INTEGER_LITERAL,
	LEFT_BRACE,
	RIGHT_BRACE,
	LEFT_PAREN,
	RIGHT_PAREN,
	COMMA,
	EOF
)

// Identifies a single token in the variable resolution expression
type token struct {
	t tokenType
	v string
}
func (t *token) is(tt tokenType) bool {
	return t.t == tt
}
func (t *token) value() string {
	return t.v
}

// Interface for reading tokens from the input
type tokenReader interface {
	more() bool
	peek() (*token, error)
	next() (*token, error)
}

// Lexer for the variable resolution expression
type variableResolutionExprLexer struct {
	exprString string
	remainingString string
	currentByteIndex int
	currentRuneIndex int
	nextToken *token
	nextError error
}

func (vrel *variableResolutionExprLexer) more() bool {
	return vrel.nextToken != nil || len(vrel.remainingString) > 0
}

func (vrel *variableResolutionExprLexer) peekRune() rune {
	if (len(vrel.remainingString) == 0) {
		return ' '
	}

	remaining = vrel.remainingString[:]
	nextRune, _ := utf8.DecodeRuneInString(remaining)
	return nextRune
}

func (vrel *variableResolutionExprLexer) nextRune() rune {
	if (len(vrel.remainingString) == 0) {
		return ' '
	}

	remaining = vrel.remainingString[:]
	nextRune, width := utf8.DecodeRuneInString(remaining)
	vrel.currentByteIndex += width
	vrel.currentRuneIndex += 1
	vrel.remainingString = remaining[width:]
	return nextRune
}

func (vrel *variableResolutionExprLexer) skipWhiteSpace() {
	for len(vrel.remainingString) > 0 &&
	    unicode.IsSpace(vrel.peekRune()) {
	  vrel.nextRune()
	}
}

func (vrel *variableResolutionExprLexer) isQuoteMark(r rune) bool {
	return r == '\'' || r == '"' || r == '`'
}

func (vrel *variableResolutionExprLexer) consumeQuotedStringLiteral() (*token, error) {
	quoteMark := vrel.nextRune()
	if !vrel.isQuoteMark(quoteMark) {
		return nil, errors.New("expected quote mark")
	}
}

func (vrel *variableResolutionExprLexer) singleRuneOperatorToTokenType(r rune) tokenType {
	switch (r) {
		case '.': return DOT
		case '[': return LEFT_BRACE
		case ']': return RIGHT_BRACE
		case '(': return LEFT_PAREN
		case ')': return RIGHT_PAREN
		case ',': return COMMA
		default: return TOKEN_TYPE_INVALID 
	}
}

func (vrel *variableResolutionExprLexer) isSingleRuneOperator(r rune) bool {
	tt := vrel.singleRuneOperatorToTokenType(r)
	return tt != TOKEN_TYPE_INVALID
}

func (vrel *variableResolutionExprLexer) consumeSingleRuneOperator() (*token, error) {
	opRune := vrel.nextRune()
	tt := vrel.singleRuneOperatorToTokenType(opRune)
	if tt == TOKEN_TYPE_INVALID {
		return nil, errors.New("expected valid operator rune")
	}
	buffer := utf8.AppendRune(make([]byte), opRune)
	bufferStr := string(buffer[:])
	return &token{
		t: tt,
		v: bufferStr,
	}, nil
}

func (vrel *variableResolutionExprLexer) isIdentifierStart(r rune) bool {
}

func (vrel *variableResolutionExprLexer) isIdentifierContent(r rune) bool {
}

func (vrel *variableResolutionExprLexer) consumeIdentifier() (*token, error) {

}

func (vrel *variableResolutionExprLexer) isIntegerStart(r rune) bool {
}

func (vrel *variableResolutionExprLexer) isIntegerContent(r rune) bool {
}

func (vrel *variableResolutionExprLexer) consumeInteger() (*token, error) {

}

func (vrel *variableResolutionExprLexer) peek() (token, error) {
	if vrel.nextToken != nil || vrel.nextError != nil {
		return vrel.nextToken, vrel.nextError
	}

	vrel.skipWhiteSpace()
	if (len(vrel.remainingString) == 0) {
		vrel.nextToken = &token{
			t: EOF,
			v: "",
		}
		return vrel.nextToken, nil
	}

	r := vrel.peekRune()
	var t *token = nil
	var e error = nil
	if vrel.isQuoteMark(r) {
		t, e = vrel.consumeQuotedStringLiteral()
	} else if vrel.isSingleRuneOperator(r) {
		t, e = vrel.consumeSingleRuneOperator()
	} else if vrel.isIdentifierStart(r) {
		t, e = vrel.consumeIdentifier()
	} else if vrel.isDigit(r) {
		t, e = vrel.consumeInteger()
	} else {
		e = fmt.Errorf("Unexpected %v in %v (byte index: %v, code point index: %v)", r, vrel.exprString, vrel.currentByteIndex, vrel.currentRuneIndex)
	}

	vrel.nextToken = t
	vrel.nextError = e
	return vrel.nextToken, vrel.nextError
}

func (vrel *variableResolutionExprLexer) next() (token, error) {
	result, err := vrel.peek()
	if err != nil {
		return nil, err
	}

	if !result.is(EOF) {
		vrel.nextToken = nil
		vrel.nextError = nil
	}
	return result
}

func newLexer(s string) *variableResolutionExprLexer {
	return &variableResolutionExprLexer{
		exprString: s,
		remainingString: s,
		currentByteIndex: 0,
		currentRuneIndex: 0,
		nextToken: nil,
		nextError: nil,
	}
}

type subLexer struct {
	reader *tokenReader
	isEnd func(t *token)bool
}

func (sl *subLexer) more() bool {
	return sl.reader.more() && !sl.isEnd(sl.reader.peek())
}

func (sl *subLexer) peek() (*token, error) {
	if sl.more() {
		return sl.reader.peek()
	}
	return &token{
		t: EOF,
		v: "",
	}, nil
}

func (sl *subLexer) next() (*token, error) {
	if sl.more() {
		return sl.reader.next()
	}
	return &token{
		t: EOF,
		v: "",
	}, nil
}

func untilType(r *tokenReader, tt tokenType) *tokenReader {
	return &subLexer{
		reader: r,
		func(t *token) bool { return t.is(tt) },
	}
}

// Instantiates a new resolver.
func NewResolver(ctx InterpolationContext) VariableResolver {
	return &resolverImpl {
		ctx: ctx,
	}
}

func (r *resolverImpl) resolveInternal(l *tokenReader) (InterpolationContext, error) {
	var builder strings.Builder
	var currentContext = r.ctx
	var t *token = nil
	var e error = nil
	for t, e = l.next() ; e == nil && !t.is(EOF) {
		pt, _ = l.peek()
		if t.is(IDENTIFIER) {
			if pt != nil && pt.is(LEFT_PAREN) {
			  // This use of an identifier is likely a function invocation
			  
			  // TODO: handle this case
			  return "", errors.New("function calls not yet implemented")
			} else if currentContext.ContainsField(t.value()) {
			  // This probably is following a "." and is a property lookup.
			  currentContext, e = currentContext.GetField(t.value())
			  builder.WriteString(t.value())
			  continue
			} else if currentContext.ContainsValue(t.value()) {
			  // This probably is followinga "." but is a map lookup using property syntax.
			  currentContext, e = currentContext.GetValue(t.value())
			  builder.WriteString(t.value())
			  continue
			}
		} else if t.is(DOT) && (pt.is(IDENTIFIER) || pt.is(STRING_LITERAL)) {
			continue
		} else if t.is(LEFT_BRACE) (pt.is(IDENTIFIER) || pt.is(STRING_LITERAL)) {
			// Map property lookup case

		} else if t.is(LEFT_BRACE) (pt.is(INTEGER_LITERAL)) {
			// Array/list lookup case
		} 
	}
}

// Attempts to the resolve the variable in a fairly general way
func (r *resolverImpl) Resolve(expr string) (string, error) {
	// Handle trivial reference to the top level object.
	if expr == "" || expr == "." || expr == "$." {
		return r.ctx.ConvertToString()
	}

	// Attempt more advanced parsing where this is not the case.
	l := newLexer(expr)
	ultimateContext, err := resolveInternal(l)
	if err != nil {
		return "", err
	}
	return ultimateContext.ConvertToString()
}
