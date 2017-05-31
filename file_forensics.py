#!/usr/bin/env python
"""Searches specified directory for miss named files."""


import os


class bcolors:
    """Color text in terminal."""

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class FileForensics:
    """Identify miss named files."""

    def __init__(self):
        """Initialize object without processing any files."""
        self.filelist = list()

    def scan_dir(self, dir):
        """Scan dir looking for files and performs basic checks."""
        import pathlib
        import magic

        for filename in find_all_files(dir):
            self.filelist.append({
                    "filename": filename,
                    "mime": magic.from_file(filename, mime=True),
                    "size_bytes": os.path.getsize(filename),
                    "ext": pathlib.Path(filename).suffix
                    })

    def get_lenght(self):
        """Return number of processed files."""
        return len(self.filelist)

    def get_big_files(self, size_threshold=10):
        """Return list of file bigger than X MB (size in MB)."""
        for f in self.filelist:
            if f["size_bytes"] > size_threshold*(1024*1024):
                yield f["size_bytes"]/(1024*1024), f["mime"], f["filename"]

    def get_keyword_files(
            self,
            filename_keywords="keywords",
            read_size=1024*1024,
            offset=50):
        """Return list of files matching keywords with matched information."""
        import ahocorasick

        A = ahocorasick.Automaton()
        with open(filename_keywords, "r") as f:
            while True:
                word = f.readline()
                if not word:
                    break
                A.add_word(word.strip(), word.strip())

        A.make_automaton()

        for file in self.filelist:
            with open(file["filename"], "r") as f:
                matches = list()
                buff = f.read(read_size)
                for match in A.iter(buff):
                    pos_cur = match[0]
                    pos_start = max(match[0]-offset, 0)
                    pos_end = min(match[0]+offset, read_size)
                    offset_start = buff[
                            pos_start:pos_cur-len(match[1])+1
                        ].find("\n")
                    offset_end = buff[pos_cur+1:pos_end].rfind("\n")

                    if offset_start >= offset:
                        offset_start = 0
                    if offset_end <= 0:
                        offset_end = offset
                    offset_end = offset - offset_end

                    matched_text = buff[
                            pos_start+offset_start:pos_cur-len(match[1])+1
                        ] + \
                        bcolors.FAIL + \
                        buff[pos_cur-len(match[1])+1:pos_cur+1] + \
                        bcolors.ENDC + \
                        buff[pos_cur+1:pos_end-offset_end]

                    matches.append((matched_text.replace("\n", " "), match[1]))
                if len(matches) > 0:
                    yield (file, matches)

    def get_highentropy_files(self, ent_threshold=0.7):
        """Return list of files with higher entropy (encrypted, compressed)."""
        import entropy

        ignored_mimetypes = [
            "application/x-shockwave-flash",
            "application/x-font-",
            "application/pdf",
            "image/"
        ]

        for file in self.filelist:
            with open(file["filename"], "r") as f:
                buff = f.read(1024*1024)

                skip = False
                for mime in ignored_mimetypes:
                    if file["mime"].startswith(mime):
                        skip = True
                        break
                if not skip:
                    ent = entropy.shannon_entropy(buff)
                    if ent >= ent_threshold:
                        yield (file, ent)


def find_all_files(path):
    """Find all files in specified directory and yields them."""
    for root, dirs, files in os.walk(os.path.join(path)):
        for filename in files:
            yield os.path.join(root, filename)


def main():
    """Analyze directory from command line looking for suspicious files."""
    ff = FileForensics()
    # ff.scan_dir("/Users/ns/notes")  # FIXME
    ff.scan_dir("/Users/ns/work/termination_data")

    print "\n--- BIG FILES ---"
    for (size, mime, filename) in ff.get_big_files():
        print (bcolors.FAIL+"{:>10} MB"+bcolors.ENDC+"   {:<20} {:<10}").\
            format(size, mime, filename)

    print "\n--- FOUND KEYWORDS ---"
    for (file, matches) in ff.get_keyword_files():
        print "{:<5} {:<20} ({:<10})".format(
            len(matches), file["mime"], file["filename"])
        for position, match in matches:
            print "\t- {:<10} {:<10}".format(position, match)
        print

    print "\n--- HIGH ENTROPY FILES ---"
    for (file, ent) in ff.get_highentropy_files():
        print (bcolors.FAIL+"\t {:.2f}"+bcolors.ENDC+" ({:<10}) {:<10}").\
            format(ent, file["mime"], file["filename"])


if __name__ == "__main__":
    main()
