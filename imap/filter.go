package imap

import (
	"fmt"
	"net/textproto"
	"strings"
	"time"
)

// SeqSet represents a sequence set of message numbers
type SeqSet struct {
	start uint32
	end   uint32 // 0 means unbounded
}

// NewSeqSet creates a new sequence set
func NewSeqSet(start uint32, end uint32) *SeqSet {
	return &SeqSet{start: start, end: end}
}

func (s *SeqSet) String() string {
	if s.end == 0 {
		return fmt.Sprintf("%d:*", s.start)
	}
	if s.start == s.end {
		return fmt.Sprintf("%d", s.start)
	}
	return fmt.Sprintf("%d:%d", s.start, s.end)
}

// SearchFilter represents an IMAP search filter
type SearchFilter struct {
	SeqNum       *SeqSet              // Sequence number is in sequence set
	Uid          *SeqSet              // UID is in sequence set
	Since        time.Time            // Internal date is since this date
	Before       time.Time            // Internal date is before this date
	SentSince    time.Time            // Date header field is since this date
	SentBefore   time.Time            // Date header field is before this date
	Header       textproto.MIMEHeader // Each header field value is present
	Body         []string             // Each string is in the body
	Text         []string             // Each string is in the text (header + body)
	WithFlags    []string             // Each flag is present
	WithoutFlags []string             // Each flag is not present
	Larger       uint32               // Size is larger than this number
	Smaller      uint32               // Size is smaller than this number
	Not          []*SearchFilter      // Each criteria doesn't match
	Or           [][2]*SearchFilter   // Each criteria pair has at least one match of two

	conditions []string // Internal slice to store search conditions
}

// NewSearchFilter creates a new search filter
func NewSearchFilter() *SearchFilter {
	return &SearchFilter{
		Header:     make(textproto.MIMEHeader),
		conditions: make([]string, 0),
	}
}

// AddCondition adds a raw search condition
func (sf *SearchFilter) AddCondition(condition string) *SearchFilter {
	sf.conditions = append(sf.conditions, condition)
	return sf
}

// WithSeqSet adds a sequence set condition
func (sf *SearchFilter) WithSeqSet(seqSet *SeqSet) *SearchFilter {
	sf.SeqNum = seqSet
	return sf
}

// WithUID adds a UID condition
func (sf *SearchFilter) WithUID(seqSet *SeqSet) *SearchFilter {
	sf.Uid = seqSet
	return sf
}

// WithSince adds a SINCE condition
func (sf *SearchFilter) WithSince(date time.Time) *SearchFilter {
	sf.Since = date
	return sf
}

// WithBefore adds a BEFORE condition
func (sf *SearchFilter) WithBefore(date time.Time) *SearchFilter {
	sf.Before = date
	return sf
}

// WithSentSince adds a SENTSINCE condition
func (sf *SearchFilter) WithSentSince(date time.Time) *SearchFilter {
	sf.SentSince = date
	return sf
}

// WithSentBefore adds a SENTBEFORE condition
func (sf *SearchFilter) WithSentBefore(date time.Time) *SearchFilter {
	sf.SentBefore = date
	return sf
}

// WithHeader adds a header condition
func (sf *SearchFilter) WithHeader(field, value string) *SearchFilter {
	sf.Header.Add(field, value)
	return sf
}

// WithBody adds a body search condition
func (sf *SearchFilter) WithBody(text string) *SearchFilter {
	sf.Body = append(sf.Body, text)
	return sf
}

// WithText adds a text search condition
func (sf *SearchFilter) WithText(text string) *SearchFilter {
	sf.Text = append(sf.Text, text)
	return sf
}

// WithFlag adds a flag condition
func (sf *SearchFilter) WithFlag(flag string) *SearchFilter {
	sf.WithFlags = append(sf.WithFlags, flag)
	return sf
}

// WithoutFlag adds a flag exclusion condition
func (sf *SearchFilter) WithoutFlag(flag string) *SearchFilter {
	sf.WithoutFlags = append(sf.WithoutFlags, flag)
	return sf
}

// WithLarger adds a size larger than condition
func (sf *SearchFilter) WithLarger(size uint32) *SearchFilter {
	sf.Larger = size
	return sf
}

// WithSmaller adds a size smaller than condition
func (sf *SearchFilter) WithSmaller(size uint32) *SearchFilter {
	sf.Smaller = size
	return sf
}

// WithNot adds a NOT condition
func (sf *SearchFilter) WithNot(filter *SearchFilter) *SearchFilter {
	sf.Not = append(sf.Not, filter)
	return sf
}

// WithOr adds an OR condition
func (sf *SearchFilter) WithOr(filter1, filter2 *SearchFilter) *SearchFilter {
	sf.Or = append(sf.Or, [2]*SearchFilter{filter1, filter2})
	return sf
}

// String converts the search filter to IMAP search command string
func (sf *SearchFilter) String() string {
	sf.buildConditions()

	if len(sf.conditions) == 0 {
		return "ALL"
	}

	return strings.Join(sf.conditions, " ")
}

// buildConditions builds the conditions slice based on the filter settings
func (sf *SearchFilter) buildConditions() {
	// Clear existing conditions
	sf.conditions = make([]string, 0)

	// Handle sequence sets
	if sf.SeqNum != nil {
		sf.AddCondition(sf.SeqNum.String())
	}
	if sf.Uid != nil {
		sf.AddCondition("UID " + sf.Uid.String())
	}

	// Handle dates
	if !sf.Since.IsZero() {
		sf.AddCondition("SINCE " + sf.Since.Format("2-Jan-2006"))
	}
	if !sf.Before.IsZero() {
		sf.AddCondition("BEFORE " + sf.Before.Format("2-Jan-2006"))
	}
	if !sf.SentSince.IsZero() {
		sf.AddCondition("SENTSINCE " + sf.SentSince.Format("2-Jan-2006"))
	}
	if !sf.SentBefore.IsZero() {
		sf.AddCondition("SENTBEFORE " + sf.SentBefore.Format("2-Jan-2006"))
	}

	// Handle headers
	for field, values := range sf.Header {
		for _, value := range values {
			sf.AddCondition(fmt.Sprintf("HEADER %s %s",
				quoteString(field), quoteString(value)))
		}
	}

	// Handle body searches
	for _, text := range sf.Body {
		sf.AddCondition("BODY " + quoteString(text))
	}

	// Handle text searches
	for _, text := range sf.Text {
		sf.AddCondition("TEXT " + quoteString(text))
	}

	// Handle flags
	for _, flag := range sf.WithFlags {
		flag = strings.TrimPrefix(flag, "\\")
		sf.AddCondition(flag)
	}
	for _, flag := range sf.WithoutFlags {
		flag = strings.TrimPrefix(flag, "\\")
		sf.AddCondition("UN" + flag)
	}

	// Handle size constraints
	if sf.Larger > 0 {
		sf.AddCondition(fmt.Sprintf("LARGER %d", sf.Larger))
	}
	if sf.Smaller > 0 {
		sf.AddCondition(fmt.Sprintf("SMALLER %d", sf.Smaller))
	}

	// Handle NOT criteria
	for _, not := range sf.Not {
		sf.AddCondition("NOT (" + not.String() + ")")
	}

	// Handle OR criteria
	for _, or := range sf.Or {
		if len(or) == 2 {
			sf.AddCondition(fmt.Sprintf("OR (%s) (%s)",
				or[0].String(), or[1].String()))
		}
	}
}

// quoteString adds quotes around a string if it contains spaces or special characters
func quoteString(s string) string {
	if strings.ContainsAny(s, ` "(){}[]<>`) {
		return `"` + AddSlashes.Replace(s) + `"`
	}
	return s
}

// Common flag constants
const (
	FlagSeen     = "\\Seen"
	FlagAnswered = "\\Answered"
	FlagFlagged  = "\\Flagged"
	FlagDeleted  = "\\Deleted"
	FlagDraft    = "\\Draft"
	FlagRecent   = "\\Recent"
)
