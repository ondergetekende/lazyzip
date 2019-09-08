import binascii
import os
import struct
import typing

# References:
# - https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
# - https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html


class _LazyZipFileEntry:
    def __init__(self, path: str):
        self.path = path

    @property
    def filename(self):
        return os.path.basename(self.path)

    @property
    def comment(self):
        return ""

    @property
    def size(self) -> int:
        return os.path.getsize(self.path)

    @property
    def last_modified(self) -> int:
        return os.path.getsize(self.path)

    def data_length(self) -> int:
        return os.path.getsize(self.path)

    @property
    def data(self) -> bytes:
        return open(self.path, 'rb').read()

    def estimate_length(self):
        return len(self.filename) + self.data_length + 42

    def get_zip_file_bytes(self) -> bytes:
        filename_encoded = self.filename.encode()
        extra_field = b''
        data = self.data
        crc = binascii.crc32(data)  #   crc-32

        return b''.join([
            struct.pack(
                '<LHHHHHLLLHH',
                0x04034b50,  # local file header signature
                0x0A,  # version needed to extract
                0,  # general purpose bit flag
                0,  # compression method
                0,  # last mod file time
                0,  # last mod file date
                crc,  #   crc-32
                len(data),  #   compressed size
                len(data),  #   uncompressed size
                len(filename_encoded),  #   file name length
                len(extra_field),  #   extra field length
            ),
            filename_encoded,
            extra_field,
            data,
        ])

    def get_zip_directory_bytes(self, relative_offset) -> bytes:
        data = self.data
        filename_encoded = self.filename.encode()
        comment_encoded = self.comment.encode()
        extra_field = b''
        data = self.data

        return b''.join([
            struct.pack(
                '<4s4B4HL2L5H2L',
                b'PK\x01\x02',  # central file header signature
                0x03, 0x1e,  # version made by
                0x00, 0x10,  # version needed to extract
                0x0800,  # general purpose bit flag (UTF-8 filename)
                0x0,  # compression method
                0x2864,  # last mod file time
                0x864f,  # last mod file date
                binascii.crc32(data),  # crc-32
                len(data),  # compressed size
                len(data),  # uncompressed size
                len(filename_encoded),  # file name length
                len(extra_field),  # extra field length
                len(comment_encoded),  # file comment length
                0,  # disk number start
                0,  # internal file attributes
                0,  # external file attributes
                relative_offset,  # relative offset of local header 
            ),
            filename_encoded,
            extra_field,
            comment_encoded
        ])


class LazyZipFile:
    def __init__(self, base_path=None):
        self.base_path = base_path
        self.files: typing.List[_LazyZipFileEntry] = []

    def add_file(self, path, local_path=None):
        if not local_path:
            local_path = os.path.join(self.base_path, path)
            self.files.append(_LazyZipFileEntry(local_path))

    def as_iterable(self) -> typing.Iterable[bytes]:
        offset = 0
        file_map = []

        for entry in self.files:
            chunk = entry.get_zip_file_bytes()
            file_map.append((offset, entry))
            yield chunk
            offset += len(chunk)

        central_directory_size = 0
        central_directory_offset = offset

        for offset, entry in file_map:
            chunk = entry.get_zip_directory_bytes(offset)
            central_directory_size += len(chunk)
            yield chunk

        final_chunk = struct.pack(
            '<IHHHHIIH',
            0x06054b50, # end of central dir signature
            0, # number of this disk
            0, # number of the disk with the start of the central directory
            len(file_map), # total number of entries in the central directory on this disk
            len(file_map), # total number of entries in the central directory
            central_directory_size, # size of the central directory
            central_directory_offset, # offset of start of central directory with respect to the starting disk number
            0, # .ZIP file comment length
        )
        yield final_chunk