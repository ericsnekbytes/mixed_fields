import os
import traceback

from types import SimpleNamespace


class MixedFieldsError(Exception):
    pass


class MixedFields:
    # Mixed Fields file format.
    #
    # File contents is a series of fields, where
    # each field is (TAG + PAYLOAD + END_BYTE),
    # and some fields have 0 length payload.
    #
    # Tags are (START_BYTE + 4_LETTER_TAGNAME).
    #
    # Some predefined tags (field types) are part
    # of the spec. Fields *can* be variable length,
    # and specify their length via a variable-length
    # -size-field at the beginning of the payload
    # (the size field specifies the count of user
    # bytes to follow)

    # ASCII/UTF8 separator bytes
    SEP_FILE = b'\x1C'
    SEP_GROUP = b'\x1D'
    SEP_RECORD = b'\x1E'
    SEP_UNIT = b'\x1F'

    # Standard sizes
    TAG_SIZE = 5
    SIZE_BITS_PER_SIZE_BYTE = 7

    # Header (TAG + PAYLOAD + END_BYTE)
    TAG_HEADER = (
        SEP_FILE
        + b'Mixd'
    )
    PAYLOAD_HEADER = b'Flds'
    ENDBYTE_HEADER = SEP_FILE
    HEADER = (
        TAG_HEADER
        + PAYLOAD_HEADER
        + ENDBYTE_HEADER
    )

    # Metadata field (variable length)
    TAG_METADATA = (
        SEP_RECORD
        + b'sMDT'
    )
    METADATA_SIZE_FIELD_8 = b'\x08'
    PAYLOAD_METADATA_EMPTY = (
        b'\x00\x00\x00\x00\x00\x00\x00\x00'
    )
    PACKED_PAYLOAD_METADATA = (
        METADATA_SIZE_FIELD_8
        + PAYLOAD_METADATA_EMPTY
    )
    ENDBYTE_META_STOP = SEP_RECORD  # TODO rename
    METADATA_FIELD_8_EMPTY = (
        TAG_METADATA
        + PACKED_PAYLOAD_METADATA
        + ENDBYTE_META_STOP
    )

    # General data field (TAG + PAYLOAD + END_BYTE)
    TAG_DATA = (
        SEP_GROUP
        + b'sDAT'
    )
    ENDBYTE_DATA = SEP_GROUP

    # End file field
    TAG_ENDFILE = (
        SEP_FILE
        + b'xEOF'
    )
    PAYLOAD_ENDFILE = b''  # Empty
    ENDBYTE_ENDFILE = SEP_FILE
    ENDFILE = (
        TAG_ENDFILE
        + PAYLOAD_ENDFILE
        + ENDBYTE_ENDFILE
    )

    def __init__(self, path=None):
        self._path = path
        self._bytes_written = 0
        self._finalized_file_write = False
        self._head = 0  # Seek position for reading files

        self._header = b''
        self._metadata = b''
        self._eof = b''

    def _path_set(self):
        return self._path is not None

    def _dirty_state(self):
        return self._bytes_written > 0 and not self._finalized_file_write

    def set_path(self, path, ignore_errors=False):
        if self._dirty_state() and not ignore_errors:
            raise MixedFieldsError('DIRTY_STATE', 'Error, cannot set path without close()\'ing current file')

        self._path = path
        self._bytes_written = 0
        self._finalized_file_write = False
        self._head = 0
        self._header = b''
        self._metadata = b''
        self._eof = b''

    def _is_variable_length(self, tag):
        if tag in {self.TAG_DATA, self.TAG_METADATA}:
            return True
        return False

    # Read a single data field, return the payload bytes (not header, metadata, or end of file tags)
    def read_item(self):
        if not self._path_set():
            raise MixedFieldsError('PATH_NONE', 'Error, path is not set')
        if self._dirty_state():
            raise MixedFieldsError('DIRTY_STATE', 'Error, cannot read from an unfinalized file')
        if not os.path.exists(self._path):
            raise MixedFieldsError('FILE_DOES_NOT_EXIST', 'Error, file does not exist')
        if os.stat(self._path).st_size == 0:
            raise MixedFieldsError('FILE_EMPTY', 'Error, file is empty')
        file_stats = os.stat(self._path)

        # Return empty bytes if past end of file
        if not (self._head < file_stats.st_size):
            return b''

        # Start reading fields
        chunk = b''  # Payload bytes
        data_field_read = False
        with open(self._path, 'rb') as fhandle:
            # Set position to last unread byte
            fhandle.seek(self._head)

            while not data_field_read:
                chunk = b''  # Reset

                tag = fhandle.read(self.TAG_SIZE)
                if len(tag) < self.TAG_SIZE:
                    raise MixedFieldsError('BAD_TAG', 'Error, invalid tag')

                # Check for/get size field value
                size_subfield = b''
                size_value = 0
                if self._is_variable_length(tag):
                    # TODO refactor this conditional
                    # Don't read from file/change seek position unless field length is variable
                    current_byte = fhandle.read(1)
                    size_subfield += current_byte
                    # TODO intercept invalid length field carrier structure
                if self._is_variable_length(tag):

                    # An MSB/leading bit of 1 means continue reading the size
                    # field, 0 means this is the last byte of the size field
                    while current_byte[0] & 0b1000_0000:
                        size_subfield += current_byte
                        current_byte = fhandle.read(1)

                        # Check for the last byte, add and break if needed
                        if not current_byte[0] & 0b1000_0000:
                            size_subfield += current_byte
                            break

                    size_value = self.read_size_field(size_subfield)

                # Read in payload for variable-size fields here
                if size_subfield:
                    chunk += fhandle.read(size_value)

                # Handle special tags
                if not self._header:
                    if tag != self.TAG_HEADER:
                        raise MixedFieldsError('BAD_HEADER', f'Error, invalid file header: {str(tag)}')

                    chunk += fhandle.read(len(self.PAYLOAD_HEADER))
                    if chunk != self.PAYLOAD_HEADER:
                        raise MixedFieldsError('BAD_HEADER_PAYLOAD', f'Error, bad header payload: {str(chunk)}')
                    end_byte = fhandle.read(len(self.ENDBYTE_HEADER))
                    if end_byte != self.ENDBYTE_HEADER:
                        raise MixedFieldsError('BAD_HEADER_ENDBYTE', f'Error, bad header endbyte: {str(end_byte)}')

                    self._header = tag + chunk + end_byte

                    continue

                if self._header and not self._metadata:
                    if tag != self.TAG_METADATA:
                        raise MixedFieldsError('BAD_METADATA_FIELD', 'Error, invalid file metadata tag!')

                    # This is a variable size field, we read those in above
                    if chunk != self.PAYLOAD_METADATA_EMPTY:
                        raise MixedFieldsError('BAD_METADATA_PAYLOAD', f'Error, bad metadata payload: {str(chunk)}')
                    end_byte = fhandle.read(len(self.ENDBYTE_META_STOP))
                    if end_byte != self.ENDBYTE_META_STOP:
                        raise MixedFieldsError('BAD_METADATA_ENDBYTE', f'Error, bad metadata endbyte: {str(end_byte)}')

                    self._metadata = tag + chunk + end_byte

                    continue

                if tag == self.TAG_ENDFILE:
                    end_byte = fhandle.read(len(self.ENDBYTE_ENDFILE))

                    if end_byte != self.ENDBYTE_ENDFILE:
                        raise MixedFieldsError('BAD_ENDFILE_ENDBYTE', f'Error, bad endfile endbyte: {str(end_byte)}')

                    self._eof = tag + end_byte

                if self._eof:  # TODO make this behave differently...N files per physical file?
                    break

                if tag == self.TAG_DATA:
                    data_field_read = True

                # Read the end byte last (there are plans for fixed length payloads which have to be read first)
                end_byte = fhandle.read(len(self.ENDBYTE_HEADER))
                if end_byte != self.ENDBYTE_DATA:  # TODO eventual support for other fields
                    raise MixedFieldsError('BAD_DATA_ENDBYTE', f'Error, bad data endbyte: {str(end_byte)}')

                # Store seek position for subsequent reads
                self._head = fhandle.tell()

        if not chunk and not self._eof:  # Error out when EOF is missing and file end is reached
            raise MixedFieldsError('MISSING_EOF', 'Error, missing EOF field!')

        return chunk

    def _write_field(self, tag, item_bytes, end_byte):
        return self._write(tag + item_bytes + end_byte)

    def _write(self, item_bytes):
        status = SimpleNamespace(STATUS='OK', BYTE_COUNT=0, ERRORS=[])
        try:
            with open(self._path, 'ab') as fhandle:
                status.BYTE_COUNT += fhandle.write(
                    item_bytes
                )
                fhandle.flush()
                self._bytes_written += status.BYTE_COUNT
        except Exception as err:
            status.STATUS = 'ERROR'
            status.ERRORS.append(MixedFieldsError('FILE_WRITE_ERROR', 'Error writing file', traceback.format_exc()))

        return status

    def _write_header_field(self):
        if not self._path_set():
            raise MixedFieldsError('PATH_NONE', 'Error, path is not set')
        return self._write(self.HEADER)

    def _write_metadata(self):
        # TODO flesh this out
        if not self._path_set():
            raise MixedFieldsError('PATH_NONE', 'Error, path is not set')
        return self._write(self.METADATA_FIELD_8_EMPTY)

    def get_size_subfield(self, size):
        if size == 0:
            # Size fields are a minimum of 1 byte
            return b'\x00'

        # A size field is a series of bytes, each starting with
        # 1 (to specify that there is another size byte following)
        # or 0 (to specify that the size field has ended, which will
        # be present on the MSB of the last byte of the size field).
        #
        # Example: 1023 = size_bin = 0b11_1111_1111 --> Field = (1)000_0111  (0)111_1111
        size_field_bits = b''
        bit_string = bin(size)[2:]  # Length as a binary string with the 0b stripped off (digits only)

        # We need groups of 7 bits (starting from the LSB), strip off any
        # leading remainder bits (a 10 bit size would have a (% 7) 3 bit remainder
        remainder = len(bit_string) % self.SIZE_BITS_PER_SIZE_BYTE

        # Get the "packed" size field bytes (with carrier
        # bits added), starting with the leading byte
        most_sig_byte = b''
        if remainder:
            leading_bits_as_num = int(bit_string[:remainder], 2)
            if len(bit_string) / self.SIZE_BITS_PER_SIZE_BYTE > 1:
                leading_bits_as_num = leading_bits_as_num | 0b10_00_00_00

            most_sig_byte = leading_bits_as_num.to_bytes(1, 'big')
        size_field_bits += most_sig_byte
        # ....
        position = remainder
        while position < len(bit_string):
            chunk_as_num = int(bit_string[position: position + self.SIZE_BITS_PER_SIZE_BYTE], 2)

            position += self.SIZE_BITS_PER_SIZE_BYTE
            if position < len(bit_string):
                # If there are additional bytes coming, set the leading bit to 1
                chunk_as_num = chunk_as_num | 0b10_00_00_00
            size_field_bits += chunk_as_num.to_bytes(1, 'big')

        return size_field_bits

    def read_size_field(self, size_field_bytes):
        size_value_bit_string = ''
        for bb in size_field_bytes:
            size_bits_no_carrier = bb & 0b0111_1111  # Strip the leading carrier digit off
            format_specifier = f'0>{self.SIZE_BITS_PER_SIZE_BYTE}'
            size_bit_chunk = f'{bin(size_bits_no_carrier)[2:]:{format_specifier}}'  # Remove '0b' and Pad to 7 bits
            size_value_bit_string += size_bit_chunk
        size_value = int(size_value_bit_string, 2)
        return size_value

    def write_item(self, item_bytes):
        if not self._path_set():
            raise MixedFieldsError('PATH_NONE', 'Error, path is not set')
        self._finalized_file_write = False

        # Write header/metadata if needed
        with open(self._path, 'ab') as fhandle:
            if self._bytes_written == 0:
                self._write_header_field()
                self._write_metadata()

        # Write length field and user bytes
        item_size_field = self.get_size_subfield(len(item_bytes))
        self._write_field(self.TAG_DATA, item_size_field + item_bytes, self.ENDBYTE_DATA)

    def close(self):
        if self._bytes_written > 0 and not self._finalized_file_write:
            self._write(self.ENDFILE)
        self._finalized_file_write = True