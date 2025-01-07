package imap

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jhillyerd/enmime"
	"github.com/rs/xid"
	"github.com/sqs/go-xoauth2"
	"golang.org/x/net/html/charset"
)

// AddSlashes adds slashes to double quotes
var AddSlashes = strings.NewReplacer(`"`, `\"`)

// RemoveSlashes removes slashes before double quotes
var RemoveSlashes = strings.NewReplacer(`\"`, `"`)

// Client is basically an IMAP connection
type Client struct {
	conn    *tls.Conn
	strtokI int
	strtok  string
}

// EmailAddresses are a map of email address to names
type EmailAddresses map[string]string

// Message is an email message
type Message struct {
	Flags       []string
	Received    time.Time
	Sent        time.Time
	Size        uint64
	Subject     string
	UID         int
	MessageID   string
	From        EmailAddresses
	To          EmailAddresses
	ReplyTo     EmailAddresses
	CC          EmailAddresses
	BCC         EmailAddresses
	Body        string
	Text        string
	HTML        string
	Attachments []Attachment
}

// Attachment is an Message attachment
type Attachment struct {
	Name     string
	MimeType string
	Content  []byte
}

func (e EmailAddresses) String() string {
	emails := strings.Builder{}
	i := 0
	for e, n := range e {
		if i != 0 {
			emails.WriteString(", ")
		}
		if len(n) != 0 {
			if strings.ContainsRune(n, ',') {
				emails.WriteString(fmt.Sprintf(`"%s" <%s>`, AddSlashes.Replace(n), e))
			} else {
				emails.WriteString(fmt.Sprintf(`%s <%s>`, n, e))
			}
		} else {
			emails.WriteString(e)
		}
		i++
	}
	return emails.String()
}

func (e Message) String() string {
	email := strings.Builder{}

	email.WriteString(fmt.Sprintf("Subject: %s\n", e.Subject))

	if len(e.To) != 0 {
		email.WriteString(fmt.Sprintf("To: %s\n", e.To))
	}
	if len(e.From) != 0 {
		email.WriteString(fmt.Sprintf("From: %s\n", e.From))
	}
	if len(e.CC) != 0 {
		email.WriteString(fmt.Sprintf("CC: %s\n", e.CC))
	}
	if len(e.BCC) != 0 {
		email.WriteString(fmt.Sprintf("BCC: %s\n", e.BCC))
	}
	if len(e.ReplyTo) != 0 {
		email.WriteString(fmt.Sprintf("ReplyTo: %s\n", e.ReplyTo))
	}
	if len(e.Text) != 0 {
		if len(e.Text) > 70 {
			email.WriteString(fmt.Sprintf("Text: %s...", e.Text[:70]))
		} else {
			email.WriteString(fmt.Sprintf("Text: %s", e.Text))
		}
		email.WriteString(fmt.Sprintf("(%d)\n", len(e.Text)))
	}
	if len(e.HTML) != 0 {
		if len(e.HTML) > 70 {
			email.WriteString(fmt.Sprintf("HTML: %s...", e.HTML[:70]))
		} else {
			email.WriteString(fmt.Sprintf("HTML: %s", e.HTML))
		}
		email.WriteString(fmt.Sprintf(" (%d)\n", len(e.HTML)))
	}

	if len(e.Attachments) != 0 {
		email.WriteString(fmt.Sprintf("%d Attachment(s): %s\n", len(e.Attachments), e.Attachments))
	}

	if len(e.Body) != 0 {
		if len(e.Body) > 70 {
			email.WriteString(fmt.Sprintf("Raw Body: %s...", e.Body[:70]))
		} else {
			email.WriteString(fmt.Sprintf("Raw Body: %s", e.Body))
		}
		email.WriteString(fmt.Sprintf(" (%d)\n", len(e.Body)))
	}
	return email.String()
}

func (a Attachment) String() string {
	return fmt.Sprintf("%s (%s %d)", a.Name, a.MimeType, len(a.Content))
}

func numbersJoin(numbers []int, sep string) (out string) {
	if len(numbers) == 0 {
		return
	}

	var builder strings.Builder
	for i, num := range numbers {
		if i > 0 {
			builder.WriteString(sep)
		}
		builder.WriteString(strconv.Itoa(num))
	}

	return builder.String()
}

// New makes a new imap
func NewClient() (d *Client, err error) {
	d = &Client{}
	return
}

func (c *Client) Connect(host string, port int) (err error) {
	c.conn, err = tls.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), nil)
	return
}

// Close closes the imap connection
func (d *Client) Close() error {
	return d.conn.Close()
}

func (d *Client) Authenticate(user string, accessToken string) (err error) {
	b64 := xoauth2.XOAuth2String(user, accessToken)
	_, err = d.Exec(fmt.Sprintf("AUTHENTICATE XOAUTH2 %s", b64))
	return
}

// Login attempts to login
func (d *Client) Login(username string, password string) (err error) {
	_, err = d.Exec(fmt.Sprintf(`LOGIN "%s" "%s"`, AddSlashes.Replace(username), AddSlashes.Replace(password)))
	return
}

func (d *Client) Logout() (err error) {
	_, err = d.Exec("LOGOUT")
	return
}

const nl = "\r\n"

func dropNl(b []byte) []byte {
	if len(b) >= 1 && b[len(b)-1] == '\n' {
		if len(b) >= 2 && b[len(b)-2] == '\r' {
			return b[:len(b)-2]
		} else {
			return b[:len(b)-1]
		}
	}
	return b
}

var atom = regexp.MustCompile(`{\d+}$`)

// Exec executes the command on the imap connection
func (d *Client) Exec(command string) (response string, err error) {
	var resp strings.Builder
	tag := []byte(fmt.Sprintf("%X", xid.New()))
	c := fmt.Sprintf("%s %s\r\n", tag, command)
	_, err = d.conn.Write([]byte(c))
	if err != nil {
		return
	}
	log.Println("[IMAP] ->", command)
	r := bufio.NewReader(d.conn)
	resp = strings.Builder{}
	var line []byte
	for err == nil {
		line, err = r.ReadBytes('\n')
		for {
			if a := atom.Find(dropNl(line)); a != nil {
				var n int
				n, err = strconv.Atoi(string(a[1 : len(a)-1]))
				if err != nil {
					return
				}

				buf := make([]byte, n)
				_, err = io.ReadFull(r, buf)
				if err != nil {
					return
				}
				line = append(line, buf...)

				buf, err = r.ReadBytes('\n')
				if err != nil {
					return
				}
				line = append(line, buf...)

				continue
			}
			break
		}

		// XID project is returning 40-byte tags. The code was originally hardcoded 16 digits.
		taglen := len(tag)
		oklen := 3
		if len(line) >= taglen+oklen && bytes.Equal(line[:taglen], tag) {
			if !bytes.Equal(line[taglen+1:taglen+oklen], []byte("OK")) {
				err = fmt.Errorf("imap command failed: %s", line[taglen+oklen+1:])
				return
			}
			break
		}

		resp.Write(line)
	}
	response = resp.String()
	// log.Println("[IMAP] <-", response)
	return
}

// GetFolders returns all folders
// GetFolders returns all available folders/mailboxes
func (d *Client) GetFolders() ([]string, error) {
	resp, err := d.Exec(`LIST "" "*"`)
	if err != nil {
		return nil, fmt.Errorf("LIST command failed: %w", err)
	}

	var folders []string
	lines := strings.Split(resp, "\r\n")

	// 正则表达式用于匹配 LIST 响应的各个部分
	// 格式: * LIST (\Flags) "Separator" "Folder Name"
	listRegex := regexp.MustCompile(`^\* LIST \((.*?)\) "(.?)" "(.+)"$`)

	for _, line := range lines {
		// 跳过空行和标签行
		if line == "" || !strings.HasPrefix(line, "* LIST") {
			continue
		}

		// 处理未加引号的简单格式
		if !strings.Contains(line, `"`) {
			parts := strings.Split(line, " ")
			if len(parts) >= 4 {
				folder := parts[len(parts)-1]
				folders = append(folders, RemoveSlashes.Replace(folder))
			}
			continue
		}

		// 处理标准的带引号格式
		matches := listRegex.FindStringSubmatch(line)
		if len(matches) == 4 {
			folderName := matches[3]
			// 处理 IMAP 文件夹名称中的特殊字符
			folderName = RemoveSlashes.Replace(folderName)
			folders = append(folders, folderName)
			continue
		}

		// 处理包含特殊字符的复杂格式
		// 例如: * LIST (\HasNoChildren) "/" "INBOX/Reports & Updates"
		start := strings.LastIndex(line, `"`)
		if start > 0 {
			folderName := line[start+1 : len(line)-1]
			folderName = RemoveSlashes.Replace(folderName)
			folders = append(folders, folderName)
		}
	}

	return folders, nil
}

// SelectFolder selects a folder
func (d *Client) SelectFolder(folder string) (err error) {
	_, err = d.Exec(`EXAMINE "` + AddSlashes.Replace(folder) + `"`)
	if err != nil {
		return
	}
	// d.Folder = folder
	return nil
}

// Move a read email to a specified folder
func (d *Client) MoveEmail(uid int, folder string) (err error) {
	_, err = d.Exec(`UID MOVE ` + strconv.Itoa(uid) + ` "` + AddSlashes.Replace(folder) + `"`)
	if err != nil {
		return
	}
	// d.Folder = folder
	return nil
}

// Search returns the UIDs in the current folder that match the search criteria
func (d *Client) Search(filter string) ([]int, error) {
	// Execute the UID SEARCH command
	r, err := d.Exec("UID SEARCH " + filter)
	if err != nil {
		return nil, fmt.Errorf("failed to execute UID SEARCH: %w", err)
	}

	// Parse the response to extract UIDs
	var uids []int
	lines := strings.Split(r, "\r\n")

	for _, line := range lines {
		// Skip empty lines
		if len(line) == 0 {
			continue
		}

		// Look for lines starting with "* SEARCH"
		if !strings.HasPrefix(line, "* SEARCH") {
			continue
		}

		// Split the line into fields and parse UIDs
		fields := strings.Fields(line)[2:] // Skip "* SEARCH"
		for _, field := range fields {
			uid, err := strconv.Atoi(field)
			if err != nil {
				continue // Skip invalid numbers
			}
			uids = append(uids, uid)
		}
	}
	return uids, nil
}

const (
	EDate uint8 = iota
	ESubject
	EFrom
	ESender
	EReplyTo
	ETo
	ECC
	EBCC
	EInReplyTo
	EMessageID
)

const (
	EEName uint8 = iota
	// EESR is unused and should be ignored
	EESR
	EEMailbox
	EEHost
)

// Token is a fetch response token (e.g. a number, or a quoted section, or a container, etc.)
type Token struct {
	Type   TType
	Str    string
	Num    int
	Tokens []*Token
}

// TType is the enum type for token values
type TType uint8

const (
	// TUnset is an unset token; used by the parser
	TUnset TType = iota
	// TAtom is a string that's prefixed with `{n}`
	// where n is the number of bytes in the string
	TAtom
	// TNumber is a numeric literal
	TNumber
	// TLiteral is a literal (think string, ish, used mainly for field names, I hope)
	TLiteral
	// TQuoted is a quoted piece of text
	TQuoted
	// TNil is a nil value, nothing
	TNil
	// TContainer is a container of tokens
	TContainer
)

// TimeFormat is the Go time version of the IMAP times
const TimeFormat = "_2-Jan-2006 15:04:05 -0700"

type tokenContainer *[]*Token

func (c *Client) Fetch(cmd string) (records [][]*Token, err error) {
	resp, err := c.Exec(cmd)
	if err != nil {
		return
	}
	records, err = c.parseFetchResponse(resp)
	return
}

// ParseFetchResponse parses a response from a FETCH command into tokens
func (d *Client) parseFetchResponse(r string) (records [][]*Token, err error) {
	records = make([][]*Token, 0)
	for {
		t := []byte{' ', '\r', '\n'}
		ok := false
		if string(d.StrtokInit(r, t)) == "*" {
			if _, err := strconv.Atoi(string(d.Strtok(t))); err == nil && string(d.Strtok(t)) == "FETCH" {
				ok = true
			}
		}

		if !ok {
			return nil, fmt.Errorf("unable to parse Fetch line %#v", string(r[:d.GetStrtokI()]))
		}

		tokens := make([]*Token, 0)
		r = r[d.GetStrtokI()+1:]

		currentToken := TUnset
		tokenStart := 0
		tokenEnd := 0
		// escaped := false
		depth := 0
		container := make([]tokenContainer, 4)
		container[0] = &tokens

		pushToken := func() *Token {
			var t *Token
			switch currentToken {
			case TQuoted:
				t = &Token{
					Type: currentToken,
					Str:  RemoveSlashes.Replace(string(r[tokenStart : tokenEnd+1])),
				}
			case TLiteral:
				s := string(r[tokenStart : tokenEnd+1])
				num, err := strconv.Atoi(s)
				if err == nil {
					t = &Token{
						Type: TNumber,
						Num:  num,
					}
				} else {
					if s == "NIL" {
						t = &Token{
							Type: TNil,
						}
					} else {
						t = &Token{
							Type: TLiteral,
							Str:  s,
						}
					}
				}
			case TAtom:
				t = &Token{
					Type: currentToken,
					Str:  string(r[tokenStart : tokenEnd+1]),
				}
			case TContainer:
				t = &Token{
					Type:   currentToken,
					Tokens: make([]*Token, 0, 1),
				}
			}

			if t != nil {
				*container[depth] = append(*container[depth], t)
			}
			currentToken = TUnset

			return t
		}

		l := len(r)
		i := 0
		for i < l {
			b := r[i]

			switch currentToken {
			case TQuoted:
				switch b {
				case '"':
					tokenEnd = i - 1
					pushToken()
					goto Cont
				case '\\':
					i++
					goto Cont
				}
			case TLiteral:
				switch {
				case IsLiteral(rune(b)):
				default:
					tokenEnd = i - 1
					pushToken()
				}
			case TAtom:
				switch {
				case unicode.IsDigit(rune(b)):
				default:
					tokenEnd = i
					size, err := strconv.Atoi(string(r[tokenStart:tokenEnd]))
					if err != nil {
						return nil, err
					}
					i += len("}") + len(nl)
					tokenStart = i
					tokenEnd = tokenStart + size - 1
					i = tokenEnd
					pushToken()
				}
			}

			switch currentToken {
			case TUnset:
				switch {
				case b == '"':
					currentToken = TQuoted
					tokenStart = i + 1
				case IsLiteral(rune(b)):
					currentToken = TLiteral
					tokenStart = i
				case b == '{':
					currentToken = TAtom
					tokenStart = i + 1
				case b == '(':
					currentToken = TContainer
					t := pushToken()
					depth++
					container[depth] = &t.Tokens
				case b == ')':
					depth--
				}
			}

		Cont:
			if depth < 0 {
				break
			}
			i++
			if i >= l {
				tokenEnd = l
				pushToken()
			}
		}
		records = append(records, tokens)
		r = r[i+1+len(nl):]

		if len(r) == 0 {
			break
		}
	}

	return
}

// IsLiteral returns if the given byte is an acceptable literal character
func IsLiteral(b rune) bool {
	switch {
	case unicode.IsDigit(b),
		unicode.IsLetter(b),
		b == '\\',
		b == '.',
		b == '[',
		b == ']':
		return true
	}
	return false
}

// GetTokenName returns the name of the given token type token
func (t TType) GetTokenName() string {
	switch t {
	case TUnset:
		return "TUnset"
	case TAtom:
		return "TAtom"
	case TNumber:
		return "TNumber"
	case TLiteral:
		return "TLiteral"
	case TQuoted:
		return "TQuoted"
	case TNil:
		return "TNil"
	case TContainer:
		return "TContainer"
	}
	return ""
}

func (t Token) String() string {
	tokenType := t.Type.GetTokenName()
	switch t.Type {
	case TUnset, TNil:
		return tokenType
	case TAtom, TQuoted:
		return fmt.Sprintf("(%s, len %d, chars %d %#v)", tokenType, len(t.Str), len([]rune(t.Str)), t.Str)
	case TNumber:
		return fmt.Sprintf("(%s %d)", tokenType, t.Num)
	case TLiteral:
		return fmt.Sprintf("(%s %s)", tokenType, t.Str)
	case TContainer:
		return fmt.Sprintf("(%s children: %s)", tokenType, t.Tokens)
	}
	return ""
}

// checkType validates a type against a list of acceptable types,
// if the type of the token isn't in the list, an error is returned
func (d *Client) checkType(token *Token, acceptableTypes []TType, tks []*Token, loc string, v ...interface{}) (err error) {
	ok := false
	for _, a := range acceptableTypes {
		if token.Type == a {
			ok = true
			break
		}
	}
	if !ok {
		types := ""
		for i, a := range acceptableTypes {
			if i != 0 {
				types += "|"
			}
			types += a.GetTokenName()
		}
		err = fmt.Errorf("IMAP: expected %s token %s, got %+v in %v", types, token, tks, loc)
	}
	return err
}

// This strtok implementation is supposed to resemble the PHP function,
// except that this will return "" if it couldn't find something instead of `false`
// since Go can't return mixed types, and we want to keep the ability of using this function
// in successes in conditions

// StrtokInit starts the strtok sequence
func (d *Client) StrtokInit(b string, delims []byte) string {
	d.strtokI = 0
	d.strtok = b
	return d.Strtok(delims)
}

// Strtok returns the next "token" in the sequence with the given delimeters
func (d *Client) Strtok(delims []byte) string {
	start := d.strtokI
	for d.strtokI < len(d.strtok) {
		if bytes.ContainsRune(delims, rune(d.strtok[d.strtokI])) {
			if start == d.strtokI {
				start++
			} else {
				d.strtokI++
				return string(d.strtok[start : d.strtokI-1])
			}
		}
		d.strtokI++
	}

	return string(d.strtok[start:])
}

// GetStrtokI returns the current position of the tokenizer
func (d *Client) GetStrtokI() int {
	return d.strtokI
}

func (d *Client) decodeRecords(records [][]*Token) (emails map[int]*Message, err error) {
	emails = make(map[int]*Message)
	reader := func(label string, input io.Reader) (io.Reader, error) {
		label = strings.Replace(label, "windows-", "cp", -1)
		encoding, _ := charset.Lookup(label)
		return encoding.NewDecoder().Reader(input), nil
	}
	dec := mime.WordDecoder{CharsetReader: reader}
	for _, tks := range records {
		m := &Message{}
		skip := 0
		for i, t := range tks {
			if skip > 0 {
				skip--
				continue
			}
			if err = d.checkType(t, []TType{TLiteral}, tks, "in root"); err != nil {
				return nil, err
			}
			switch t.Str {
			case "FLAGS":
				if err = d.checkType(tks[i+1], []TType{TContainer}, tks, "after FLAGS"); err != nil {
					return nil, err
				}
				m.Flags = make([]string, len(tks[i+1].Tokens))
				for i, t := range tks[i+1].Tokens {
					if err = d.checkType(t, []TType{TLiteral}, tks, "for FLAGS[%d]", i); err != nil {
						return nil, err
					}
					m.Flags[i] = t.Str
				}
				skip++
			case "INTERNALDATE":
				if err = d.checkType(tks[i+1], []TType{TQuoted}, tks, "after INTERNALDATE"); err != nil {
					return nil, err
				}
				m.Received, err = time.Parse(TimeFormat, tks[i+1].Str)
				if err != nil {
					return nil, err
				}
				m.Received = m.Received.UTC()
				skip++
			case "RFC822.SIZE":
				if err = d.checkType(tks[i+1], []TType{TNumber}, tks, "after RFC822.SIZE"); err != nil {
					return nil, err
				}
				m.Size = uint64(tks[i+1].Num)
				skip++
			case "ENVELOPE":
				if err = d.checkType(tks[i+1], []TType{TContainer}, tks, "after ENVELOPE"); err != nil {
					return nil, err
				}
				if err = d.checkType(tks[i+1].Tokens[EDate], []TType{TQuoted, TNil}, tks, "for ENVELOPE[%d]", EDate); err != nil {
					return nil, err
				}
				if err = d.checkType(tks[i+1].Tokens[ESubject], []TType{TQuoted, TAtom, TNil}, tks, "for ENVELOPE[%d]", ESubject); err != nil {
					return nil, err
				}

				m.Sent, _ = time.Parse("Mon, _2 Jan 2006 15:04:05 -0700", tks[i+1].Tokens[EDate].Str)
				m.Sent = m.Sent.UTC()

				m.Subject, err = dec.DecodeHeader(tks[i+1].Tokens[ESubject].Str)
				if err != nil {
					return nil, err
				}

				for _, a := range []struct {
					dest  *EmailAddresses
					pos   uint8
					debug string
				}{
					{&m.From, EFrom, "FROM"},
					{&m.ReplyTo, EReplyTo, "REPLYTO"},
					{&m.To, ETo, "TO"},
					{&m.CC, ECC, "CC"},
					{&m.BCC, EBCC, "BCC"},
				} {
					if tks[i+1].Tokens[EFrom].Type != TNil {
						if err = d.checkType(tks[i+1].Tokens[a.pos], []TType{TNil, TContainer}, tks, "for ENVELOPE[%d]", a.pos); err != nil {
							return nil, err
						}
						*a.dest = make(map[string]string, len(tks[i+1].Tokens[EFrom].Tokens))
						for i, t := range tks[i+1].Tokens[a.pos].Tokens {
							if err = d.checkType(t.Tokens[EEName], []TType{TQuoted, TNil}, tks, "for %s[%d][%d]", a.debug, i, EEName); err != nil {
								return nil, err
							}
							if err = d.checkType(t.Tokens[EEMailbox], []TType{TQuoted, TNil}, tks, "for %s[%d][%d]", a.debug, i, EEMailbox); err != nil {
								return nil, err
							}
							if err = d.checkType(t.Tokens[EEHost], []TType{TQuoted, TNil}, tks, "for %s[%d][%d]", a.debug, i, EEHost); err != nil {
								return nil, err
							}

							name, err := dec.DecodeHeader(t.Tokens[EEName].Str)
							if err != nil {
								return nil, err
							}
							mailbox, err := dec.DecodeHeader(t.Tokens[EEMailbox].Str)
							if err != nil {
								return nil, err
							}

							host, err := dec.DecodeHeader(t.Tokens[EEHost].Str)
							if err != nil {
								return nil, err
							}

							(*a.dest)[strings.ToLower(mailbox+"@"+host)] = name
						}
					}
				}

				m.MessageID = tks[i+1].Tokens[EMessageID].Str

				skip++
			case "BODY[]":
				if err = d.checkType(tks[i+1], []TType{TAtom}, tks, "after BODY[]"); err != nil {
					return
				}
				m.Body = tks[i+1].Str
				skip++
			case "UID":
				if err = d.checkType(tks[i+1], []TType{TNumber}, tks, "after UID"); err != nil {
					return nil, err
				}
				m.UID = tks[i+1].Num
				skip++
			}
		}
		emails[m.UID] = m
	}
	return
}

// GetOverviews returns emails without bodies for the given UIDs in the current folder.
// If no UIDs are given, then everything in the current folder is selected
func (d *Client) GetOverviews(uids ...int) (emails map[int]*Message, err error) {
	uidsStr := numbersJoin(uids, ",")
	records, err := d.Fetch("UID FETCH " + uidsStr + " ALL")
	if err != nil {
		return
	}
	return d.decodeRecords(records)
}

// GetEmails returns email with their bodies for the given UIDs in the current folder.
// If no UIDs are given, then everything in the current folder is selected
func (d *Client) GetEmails(uids ...int) (emails map[int]*Message, err error) {
	uidsStr := numbersJoin(uids, ",")
	records, err := d.Fetch("UID FETCH " + uidsStr + " BODY.PEEK[]")
	if err != nil {
		return
	}
	emails, err = d.decodeRecords(records)
	if err != nil {
		return
	}
	for _, m := range emails {
		r := strings.NewReader(m.Body)
		envelope, e := enmime.ReadEnvelope(r)
		if e != nil {
			continue
		}
		for _, a := range []struct {
			header    string
			addresses *EmailAddresses
		}{
			{"From", &m.From},
			{"Reply-To", &m.ReplyTo},
			{"To", &m.To},
			{"cc", &m.CC},
			{"bcc", &m.BCC},
		} {
			alist, _ := envelope.AddressList(a.header)
			(*a.addresses) = make(map[string]string, len(alist))
			for _, addr := range alist {
				(*a.addresses)[strings.ToLower(addr.Address)] = addr.Name
			}
		}
		m.Subject = envelope.GetHeader("Subject")
		m.Text = envelope.Text
		m.HTML = envelope.HTML
		if len(envelope.Attachments) != 0 {
			for _, a := range envelope.Attachments {
				m.Attachments = append(m.Attachments, Attachment{
					Name:     a.FileName,
					MimeType: a.ContentType,
					Content:  a.Content,
				})
			}
		}
		if len(envelope.Inlines) != 0 {
			for _, a := range envelope.Inlines {
				m.Attachments = append(m.Attachments, Attachment{
					Name:     a.FileName,
					MimeType: a.ContentType,
					Content:  a.Content,
				})
			}
		}
	}
	return
}
