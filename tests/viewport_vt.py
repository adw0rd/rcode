"""Минимальная модель VT для проверок координат настоящего PTY.

Только стандартная библиотека: UTF-8 декодируется потоково, управляющие
последовательности меняют сетку, а не удаляются из накопленного текста.
"""

import codecs
import unicodedata


class Viewport:
    def __init__(self, width, height):
        self.width, self.height = width, height
        self.cells = self.blank()
        self.row = self.col = 0
        self.saved_cursor = (0, 0)
        self.alternate = False
        self.used_alternate = False
        self.left_alternate = False
        self.cursor_visible = True
        self.bracketed_paste = False
        self.mouse_modes = set()
        self.queried_cursor = False
        self.synchronized_update = False
        self.completed_frames = 0
        self.normal = None
        self.last_alternate = None
        self.pending = ""
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")

    def blank(self):
        return [[" "] * self.width for _ in range(self.height)]

    def rows(self):
        return ["".join(row).rstrip() for row in self.cells]

    @property
    def frame_complete(self):
        return (not self.synchronized_update and not self.pending
                and not self.decoder.getstate()[0])

    def resize(self, width, height):
        old = self.cells
        self.width, self.height = width, height
        self.cells = self.blank()
        for index, row in enumerate(old[:height]):
            self.cells[index][:min(width, len(row))] = row[:width]
        self.row = min(self.row, height - 1)
        self.col = min(self.col, width - 1)

    def feed(self, data):
        value = self.pending + self.decoder.decode(data)
        self.pending = ""
        index = 0
        while index < len(value):
            char = value[index]
            if char == "\x1b":
                start = index
                index += 1
                if index == len(value):
                    self.pending = value[start:]
                    break
                if value[index] == "[":
                    index += 1
                    parameters = index
                    while index < len(value) and not "@" <= value[index] <= "~":
                        index += 1
                    if index == len(value):
                        self.pending = value[start:]
                        break
                    self.csi(value[parameters:index], value[index])
                    index += 1
                    continue
                if value[index] == "]":
                    end = index + 1
                    while end < len(value) and value[end] != "\x07" and value[end:end + 2] != "\x1b\\":
                        end += 1
                    if end == len(value):
                        self.pending = value[start:]
                        break
                    index = end + (1 if value[end] == "\x07" else 2)
                    continue
                if value[index] == "7":
                    self.saved_cursor = self.row, self.col
                elif value[index] == "8":
                    self.row, self.col = self.saved_cursor
                elif value[index] in "()" and index + 1 < len(value):
                    index += 1
                index += 1
                continue
            if char == "\r":
                self.col = 0
            elif char == "\n":
                self.row += 1
                if self.row >= self.height:
                    self.cells.pop(0)
                    self.cells.append([" "] * self.width)
                    self.row = self.height - 1
            elif char == "\b":
                self.col = max(0, self.col - 1)
            elif char == "\t":
                self.col = min(self.width - 1, (self.col // 8 + 1) * 8)
            elif ord(char) >= 32 and char != "\x7f":
                self.put(char)
            index += 1

    def put(self, char):
        if unicodedata.combining(char) or unicodedata.category(char) in ("Mn", "Me", "Cf"):
            if self.col:
                at = min(self.width - 1, self.col - 1)
                while at and self.cells[self.row][at] == "":
                    at -= 1
                self.cells[self.row][at] += char
            return
        size = 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        if self.col >= self.width:
            self.col = 0
            self.row += 1
            if self.row >= self.height:
                self.cells.pop(0)
                self.cells.append([" "] * self.width)
                self.row = self.height - 1
        self.cells[self.row][self.col] = char
        if size == 2 and self.col + 1 < self.width:
            self.cells[self.row][self.col + 1] = ""
        self.col += size

    def csi(self, parameters, command):
        private = parameters.startswith("?")
        raw = parameters.lstrip("?")
        args = [int(part or "0") for part in raw.split(";") if part.isdigit() or not part]
        first = args[0] if args else 0
        amount = first or 1
        if command in "hl" and private:
            enabled = command == "h"
            for mode in args:
                if mode == 1049:
                    if enabled and not self.alternate:
                        self.normal = self.cells, self.row, self.col
                        self.cells = self.blank()
                        self.row = self.col = 0
                        self.alternate = self.used_alternate = True
                    elif not enabled and self.alternate:
                        self.last_alternate = self.rows()
                        self.alternate = False
                        self.left_alternate = True
                        if self.normal:
                            self.cells, self.row, self.col = self.normal
                            self.normal = None
                elif mode == 25:
                    self.cursor_visible = enabled
                elif mode == 2004:
                    self.bracketed_paste = enabled
                elif mode == 2026:
                    if not enabled and self.synchronized_update:
                        self.completed_frames += 1
                    self.synchronized_update = enabled
                elif mode in (1000, 1002, 1003, 1005, 1006, 1015):
                    if enabled:
                        self.mouse_modes.add(mode)
                    else:
                        self.mouse_modes.discard(mode)
        elif command in "Hf":
            self.row = min(self.height - 1, max(0, first - 1))
            self.col = min(self.width - 1, max(0, (args[1] if len(args) > 1 else 1) - 1))
        elif command == "G":
            self.col = min(self.width - 1, max(0, first - 1))
        elif command == "A":
            self.row = max(0, self.row - amount)
        elif command == "B":
            self.row = min(self.height - 1, self.row + amount)
        elif command == "C":
            self.col = min(self.width - 1, self.col + amount)
        elif command == "D":
            self.col = max(0, self.col - amount)
        elif command == "J":
            if first in (2, 3):
                self.cells = self.blank()
            else:
                for row in range(self.height):
                    for col in range(self.width):
                        if (first == 0 and (row, col) >= (self.row, self.col)) or (first == 1 and (row, col) <= (self.row, self.col)):
                            self.cells[row][col] = " "
        elif command == "K":
            for col in range(self.width):
                if first == 2 or (first == 0 and col >= self.col) or (first == 1 and col <= self.col):
                    self.cells[self.row][col] = " "
        elif command == "s":
            self.saved_cursor = self.row, self.col
        elif command == "u":
            self.row, self.col = self.saved_cursor
        elif command == "n" and first == 6:
            self.queried_cursor = True


def verify_viewport():
    view = Viewport(12, 6)
    encoded = "Привет界".encode()
    view.feed(encoded[:3])
    view.feed(encoded[3:])
    assert view.rows()[0] == "Привет界"
    assert view.col == 8
    view.feed(b"\x1b[?1049h\x1b[6;1Hfooter\x1b[2;3Hinput")
    assert view.rows()[5] == "footer" and view.rows()[1] == "  input"
    view.feed(b"\x1b[1D\x1b[K")
    assert view.rows()[1] == "  inpu"
    view.feed(b"\x1b[?1049l")
    assert view.rows()[0] == "Привет界" and view.left_alternate
    view.feed(b"\x1b[?2026h\x1b[2;3H\x1b[?25h")
    assert not getattr(view, "frame_complete", True), "CursorShow before synchronized-update end is not a completed frame"
    view.feed(b"\x1b[?2026l")
    assert view.frame_complete and view.completed_frames == 1


if __name__ == "__main__":
    verify_viewport()
