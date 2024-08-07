// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "interpolation" assists with interpolating variables
// from relevant OTel signals in URIs used for storage.
//
// The "resolver.go" file provides the default implementation
// of the "VariableResolver" interface that is used in this package.
package interpolation

import (
	"unicode"
	"unicode/utf8"
)

// Implementation of "VariableResolver"
type resolverImpl struct {
	ctx InterpolationContext
}

// Identifies a token in the variable resolution expression
type tokenType int

const (
	// Enum values for different kinds of tokens used
	// in the process of interpolating strings dynamically.
	TokenTypeInvalid tokenType = iota,
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
	exprString       string
	remainingString  string
	currentByteIndex int
	currentRuneIndex int
	nextToken        *token
	nextError        error
}

func (vrel *variableResolutionExprLexer) more() bool {
	return vrel.nextToken != nil || len(vrel.remainingString) > 0
}

func (vrel *variableResolutionExprLexer) peekRune() rune {
	if len(vrel.remainingString) == 0 {
		return ' '
	}

	remaining = vrel.remainingString[:]
	nextRune, _ := utf8.DecodeRuneInString(remaining)
	return nextRune
}

func (vrel *variableResolutionExprLexer) nextRune() rune {
	if len(vrel.remainingString) == 0 {
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
	switch r {
	case '.':
		return DOT
	case '[':
		return LEFT_BRACE
	case ']':
		return RIGHT_BRACE
	case '(':
		return LEFT_PAREN
	case ')':
		return RIGHT_PAREN
	case ',':
		return COMMA
	default:
		return TokenTypeInvalid
	}
}

func (vrel *variableResolutionExprLexer) isSingleRuneOperator(r rune) bool {
	tt := vrel.singleRuneOperatorToTokenType(r)
	return tt != TokenTypeInvalid
}

func (vrel *variableResolutionExprLexer) consumeSingleRuneOperator() (*token, error) {
	opRune := vrel.nextRune()
	tt := vrel.singleRuneOperatorToTokenType(opRune)
	if tt == TokenTypeInvalid {
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
	return unicode.IsLetter(r) || (r == '_')
}

func (vrel *variableResolutionExprLexer) isIdentifierContent(r rune) bool {
	return vrel.isIdentifierStart(r) || unicode.IsDigit(r)
}

func (vrel *variableResolutionExprLexer) consumeIdentifier() (*token, error) {
	var builder strings.Builder
	firstRune, firstRuneErr := vrel.peekRune()
	if firstRuneErr != nil {
		return nil, firstRuneErr
	}
	if !vrel.isIdentifierStart(firstRune) {
		return nil, fmt.Errorf("Not an identifier start: %v", firstRune)
	}
	builder.WriteRune(firstRune)
	for vrel.more() {
		peekRune, err := vrel.peekRune()
		if err != nil {
			return nil, err
		}
		if !vrel.isIdentifierContent(peekRune) {
			break
		}

		nextRune, nextRuneErr := vrel.nextRune()
		if nextRuneErr != nil {
			return nil, nextRuneErr
		}
		builder.WriteRune(nextRune)
	}

	content := builder.String()
	return &token{
		t: IDENTIFIER,
		v: content,
	}, nil
}

func (vrel *variableResolutionExprLexer) isIntegerStart(r rune) bool {
	// TODO: maybe allow "+" and "-" at the start
	// TODO: maybe allow "0x", "0b", etc.
	return unicode.IsDigit(r)
}

func (vrel *variableResolutionExprLexer) isIntegerContent(r rune) bool {
	return unicode.IsDigit(r)
}

func (vrel *variableResolutionExprLexer) consumeInteger() (*token, error) {
	var builder strings.Builder
	firstRune, firstRuneErr := vrel.peekRune()
	if firstRuneErr != nil {
		return nil, firstRuneErr
	}
	if !vrel.isIntegerStart(firstRune) {
		return nil, fmt.Errorf("Not an integer start: %v", firstRune)
	}
	builder.WriteRune(firstRune)
	for vrel.more() {
		peekRune, err := vrel.peekRune()
		if err != nil {
			return nil, err
		}
		if !vrel.isIntegerContent(peekRune) {
			break
		}

		nextRune, nextRuneErr := vrel.nextRune()
		if nextRuneErr != nil {
			return nil, nextRuneErr
		}
		builder.WriteRune(nextRune)
	}

	content := builder.String()
	return &token{
		t: INTEGER_LITERAL,
		v: content,
	}, nil
}

func (vrel *variableResolutionExprLexer) peek() (token, error) {
	if vrel.nextToken != nil || vrel.nextError != nil {
		return vrel.nextToken, vrel.nextError
	}

	vrel.skipWhiteSpace()
	if len(vrel.remainingString) == 0 {
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
		exprString:       s,
		remainingString:  s,
		currentByteIndex: 0,
		currentRuneIndex: 0,
		nextToken:        nil,
		nextError:        nil,
	}
}

type subLexer struct {
	reader     *tokenReader
	braceCount int
	parenCount int
}

func (sl *subLexer) more() bool {
	return sl.reader.more() && ((sl.braceCount > 0) || (sl.parenCount > 0))
}

func (sl *subLexer) peek() (*token, error) {
	if sl.more() {
		return sl.reader.peek()
	}
	if sl.braceCount != 0 {
		return nil, errors.New("Mismatched braces")
	}
	if sl.parenCount != 0 {
		return nil, errors.New("Mismatched parens")
	}
	return &token{
		t: EOF,
		v: "",
	}, nil
}

func (sl *subLexer) next() (*token, error) {
	result, err := sl.peek()

	if sl.more() {
		nextToken, err := sl.reader.next()
		if err != nil {
			return nil, err
		}
		if nextToken.is(LEFT_BRACE) {
			sl.braceCount += 1
		} else if nextToken.is(RIGHT_BRACE) {
			sl.braceCount -= 1
		} else if nextToken.is(LEFT_PAREN) {
			sl.parenCount += 1
		} else if nextToken.is(RIGHT_PAREN) {
			sl.parenCount -= 1
		}
	}

	return result, err
}

// Instantiates a new resolver.
func NewResolver(ctx InterpolationContext) VariableResolver {
	return &resolverImpl{
		ctx: ctx,
	}
}

func (r *resolverImpl) resolveInternal(l *tokenReader) (InterpolationContext, error) {
	var currentContext = r.ctx
	var t *token = nil
	var e error = nil

	for l.more() {
		t, e = l.peek()
		if e != nil {
			return nil, e
		}

		if t.is(DOT) {
			l.next()
			t, e = l.peek()
			if !t.is(IDENTIFIER) && !t.is(STRING_LITERAL) {
				return nil, fmt.Errorf("Expected identifier or string literal after '.'")
			}
		}

		if t.is(LEFT_BRACE) {
			currentContext, e = r.resolveArrayOrMapElement(currentContext, l)
		} else if t.is(IDENTIFIER) || t.is(STRING_LITERAL) {
			currentContext, e = r.resolveElement(currentContext, l)
		} else {
			return nil, fmt.Errorf("Unexpected token: %v", t.v)
		}
	}

	return currentContext, nil
}

func (r *resolverImpl) resolveArrayOrMapElement(
	currentContext InterpolationContext, l *tokenReader) (InterpolationContext, error) {
	lbrace, err := l.next()
	if err != nil {
		return nil, err
	}
	if !lbrace.is(LEFT_BRACE) {
		return nil, errors.New("Expected [")
	}

	sl := &subLexer{reader: l, braceCount: 1}
	elementRef, elementRefErr := r.resolveInternal(sl)
	if elementRefErr != nil {
		return nil, elementRefErr
	}

	if !elementRef.IsScalar() {
		return nil, errors.New("Cannot use a non-scalar value as a map or array element")
	}

	elementAsInt, intConversionErr := elementRef.ConvertToInt()
	if intConversionErr == nil && currentContext.ContainsIndex(elementAsInt) {
		return currentContext.GetIndex(elementAsInt)
	}

	elementAsStr, strConversionErr := elementRef.ConvertToString()
	if strConversionErr != nil {
		return nil, strConversionErr
	}

	if currentContext.ContainsKey(elementAsStr) {
		return currentContext.GetValue(elementAsStr)
	}

	if currentContext.ContainsField(elementAsStr) {
		return currentContext.GetField(elementAsStr)
	}

	return nil, fmt.Errorf("No such element: %v", elementAsStr)
}

func (r *resolverImpl) resolveElement(
	currentContext InterpolationContext, l *tokenReader) (InterpolationContext, error) {
	fieldOrMapElement, err := l.next()
	if !fieldOrMapElement.is(IDENTIFIER) && !fieldOrMapElement.is(STRING_LITERAL) {
		return nil, errors.New("Expected identifier or string literal.")
	}

	elementAsStr, strConversionErr := fieldOrMapElement.ConvertToString()
	if strConversionErr != nil {
		return nil, strConversionErr
	}

	if currentContext.ContainsField(elementAsStr) {
		return currentContext.GetField(elementAsStr)
	}

	if currentContext.IsMap() {
		if currentContext.ContainsKey(elementAsStr) {
			return currentContext.GetValue(elementAsStr)
		}

		pluralVariant := string(utf8.AppendRune([]byte(elementAsStr), 's'))
		if currentContext.ContainsKey(pluralVariant) {
			return currentContext.GetValue(pluralVariant)
		}
	}

	return nil, fmt.Errorf("No such element: %v", elementAsStr)
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
