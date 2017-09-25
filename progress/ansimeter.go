package progress

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh/terminal"
)

// ANSIMeter is a progress.Meter that uses ANSI escape codes to make
// better use of the available horizontal space.
type ANSIMeter struct {
	label   []rune
	total   float64
	written float64
	spin    int
	t0      time.Time
}

// these are the bits of the ANSI escapes (beyond \r) that we use
// (names of the terminfo capabilities, see terminfo(5))
var (
	// clear to end of line
	clrEOL = "\033[K"
	// make cursor invisible
	cursorInvisible = "\033[?25l"
	// make cursor visible
	cursorVisible = "\033[?12;25h"
	// turn on reverse video
	enterReverseMode = "\033[7m"
	// go back to normal video
	exitAttributeMode = "\033[0m"
)

func getCol() int {
	col, _, _ := terminal.GetSize(0)
	if col < 10 {
		// give up
		col = 80
	}
	return col
}

func (p *ANSIMeter) Start(label string, total float64) {
	p.label = []rune(label)
	p.total = total
	p.t0 = time.Now().UTC()
	fmt.Print(cursorInvisible)
}

func norm(col int, msg []rune) []rune {
	out := make([]rune, col)
	copy(out, msg)
	d := col - len(msg)
	if d < 0 {
		out[col-1] = '…'
	} else {
		for i := len(msg); i < col; i++ {
			out[i] = ' '
		}
	}
	return out
}

func (p *ANSIMeter) SetTotal(total float64) {
	p.total = total
}

func (p *ANSIMeter) percent() string {
	if p.total == 0. {
		return "---%"
	}
	q := p.written * 100 / p.total
	if q > 999.4 || q < 0. {
		return "???%"
	}
	return fmt.Sprintf("%3.0f%%", q)
}

func (p *ANSIMeter) Set(current float64) {
	p.written = current
	col := getCol()
	// time left: 5
	//    gutter: 1
	//     speed: 8
	//    gutter: 1
	//   percent: 4
	//    gutter: 1
	//          =====
	//           20
	var percent, speed, timeleft string
	if col > 15 {
		since := time.Now().UTC().Sub(p.t0).Seconds()
		per := since / p.written
		left := (p.total - p.written) * per
		timeleft = " " + formatDuration(left)
		if col > 21 {
			percent = " " + p.percent()
			if col > 30 {
				speed = " " + formatBPS(p.written, since, -1)
			}
		}
	}

	msg := make([]rune, 0, col)
	msg = append(msg, norm(col-len(percent)-len(speed)-len(timeleft), p.label)...)
	msg = append(msg, []rune(percent)...)
	msg = append(msg, []rune(speed)...)
	msg = append(msg, []rune(timeleft)...)
	i := int(current * float64(col) / p.total)
	// the following can't happen... except when they do
	switch {
	case i > col:
		i = col
	case i < 0:
		i = 0
	}
	fmt.Print("\r", enterReverseMode, string(msg[:i]), exitAttributeMode, string(msg[i:]))
}

func (p *ANSIMeter) Spin(msgstr string) {
	col := getCol()
	msg := norm(col, []rune(msgstr))
	p.spin++
	if p.spin > 90 {
		p.spin = -p.spin + 1

	}
	spin := p.spin
	if spin < 0 {
		spin = -spin
	}
	i := spin * col / 100
	j := (spin + 10) * col / 100
	fmt.Print("\r", string(msg[:i]), enterReverseMode, string(msg[i:j]), exitAttributeMode, string(msg[j:]))
}

func (*ANSIMeter) Finished() {
	fmt.Print("\r", exitAttributeMode, cursorVisible, clrEOL)
}

func (*ANSIMeter) Notify(msgstr string) {
	col := getCol()
	fmt.Print("\r", exitAttributeMode, clrEOL)
	n := 0
	for _, w := range strings.Fields(msgstr) {
		wl := utf8.RuneCountInString(w)
		if n > 0 {
			if n+wl+1 > col {
				fmt.Print("\n")
				n = 0
			} else {
				fmt.Print(" ")
				n++
			}
		}
		n += wl
		fmt.Print(w)
	}
	if n > 0 {
		fmt.Print("\n")
	}
}

// Write does nothing
func (p *ANSIMeter) Write(bs []byte) (n int, err error) {
	n = len(bs)
	// TODO: lock, n'eh
	p.Set(p.written + float64(n))

	return
}
