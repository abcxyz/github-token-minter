// Code generated by "stringer -type=Level -trimprefix=Level"; DO NOT EDIT.

package server

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[LevelInvalid-1]
	_ = x[LevelRead-2]
	_ = x[LevelWrite-4]
	_ = x[LevelAdmin-8]
}

const (
	_Level_name_0 = "InvalidRead"
	_Level_name_1 = "Write"
	_Level_name_2 = "Admin"
)

var (
	_Level_index_0 = [...]uint8{0, 7, 11}
)

func (i Level) String() string {
	switch {
	case 1 <= i && i <= 2:
		i -= 1
		return _Level_name_0[_Level_index_0[i]:_Level_index_0[i+1]]
	case i == 4:
		return _Level_name_1
	case i == 8:
		return _Level_name_2
	default:
		return "Level(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}