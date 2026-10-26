//! Выделение по экранным ячейкам, с сохранением целых Unicode-графем.
use std::ops::Range;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Point {
    pub row: usize,
    pub column: usize,
}
#[derive(Clone, Debug)]
pub(crate) struct Selection {
    pub rows: Vec<String>,
    pub start: Point,
    pub end: Point,
    pub dragging: bool,
}
impl Selection {
    pub fn new(rows: Vec<String>, start: Point) -> Self {
        Self {
            rows,
            start,
            end: start,
            dragging: true,
        }
    }
    pub fn range(&self, row: usize) -> Option<Range<usize>> {
        let (start, end) = if self.start <= self.end {
            (self.start, self.end)
        } else {
            (self.end, self.start)
        };
        if row < start.row || row > end.row || start == end {
            return None;
        }
        let size = UnicodeWidthStr::width(self.rows.get(row)?.as_str());
        let from = if row == start.row {
            start.column.min(size)
        } else {
            0
        };
        let to = if row == end.row {
            end.column.min(size)
        } else {
            size
        };
        (from < to).then_some(from..to)
    }
    pub fn text(&self) -> String {
        let (start, end) = if self.start <= self.end {
            (self.start, self.end)
        } else {
            (self.end, self.start)
        };
        if start == end {
            return String::new();
        }
        let mut lines = Vec::new();
        for row in start.row..=end.row.min(self.rows.len().saturating_sub(1)) {
            let mut value = String::new();
            if let Some(range) = self.range(row) {
                let mut column = 0;
                for g in self.rows[row].graphemes(true) {
                    let size = UnicodeWidthStr::width(g);
                    if column < range.end && column + size > range.start {
                        value.push_str(g);
                    }
                    column += size;
                }
            }
            lines.push(value.trim_end().to_owned());
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_reverse_selection_and_blank_lines_match_screen_cells() {
        let mut selection = Selection::new(
            vec!["ab世界 e\u{301} 👩‍💻".into(), "".into(), "  tail".into()],
            Point { row: 0, column: 3 },
        );
        selection.end = Point { row: 2, column: 4 };
        assert_eq!(selection.text(), "世界 e\u{301} 👩‍💻\n\n  ta");
        std::mem::swap(&mut selection.start, &mut selection.end);
        assert_eq!(selection.text(), "世界 e\u{301} 👩‍💻\n\n  ta");
    }
    #[test]
    fn click_does_not_select_or_copy() {
        let selection = Selection::new(vec!["value".into()], Point { row: 0, column: 2 });
        assert!(selection.text().is_empty());
        assert!(selection.range(0).is_none());
    }
}
