import os
import traceback

from types import SimpleNamespace


FIELDINFO = SimpleNamespace(
    PAYLOAD='PAYLOAD',
    ENDBYTE='ENDBYTE',
    TAG='TAG',
)


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

    # Extra (user) metadata field
    TAG_EXTRA_METADATA = (
        SEP_RECORD
        + b'eMDT'
    )
    TAG_EMETA = TAG_EXTRA_METADATA  # Convenience
    ENDBYTE_EXTRA_METADATA = SEP_RECORD

    # General data field (TAG + PAYLOAD + END_BYTE)
    TAG_DATA = (
        SEP_RECORD
        + b'sDAT'
    )
    ENDBYTE_DATA = SEP_RECORD

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

    # Store here for users/convenience
    INFO = FIELDINFO
    VALID_TAGS = {
        TAG_HEADER,
        TAG_METADATA,
        TAG_ENDFILE,
        TAG_DATA,
        TAG_EXTRA_METADATA
    }

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
        # TODO raise exception on invalid tag
        if tag in {self.TAG_DATA, self.TAG_METADATA, self.TAG_EXTRA_METADATA}:
            return True
        return False

    @staticmethod
    def split_sized_chunk(chunk):
        """Read/remove the size field from the front of a chunk, then return the size and remaining chunk"""
        if len(chunk) == 0:
            raise MixedFieldsError('EMPTY_CHUNK', 'Error, cannot read size from empty chunk')

        # Get the size subfield
        size_subfield = b''
        for byte_val in chunk:
            size_subfield += bytes([byte_val])
            if not (byte_val & 0b1000_0000):
                break
        size_value = MixedFields.read_size_subfield(size_subfield)

        # Get the chunk remainder
        partial_chunk = b''
        if len(size_subfield) < len(chunk):  # A zero length payload is valid
            partial_chunk = chunk[len(size_subfield):]

        return (size_value, partial_chunk)

    def _read_field(self):
        with open(self._path, 'rb') as fhandle:
            fhandle.seek(self._head)  # Start at last unread position

            tag = fhandle.read(5)  # TODO const for this
            if len(tag) < 5:
                raise MixedFieldsError('BAD_TAG', f'Error, invalid tag length ({tag})')
            chunk = b''

            # Validate tag
            if tag not in MixedFields.VALID_TAGS:
                raise MixedFieldsError('INVALID_TAG', 'Error, invalid tag!')

            # Read variable length payloads here
            if self._is_variable_length(tag):
                # Check for/get size field value
                size_subfield = b''
                size_value = 0
                if self._is_variable_length(tag):
                    current_byte = fhandle.read(1)
                    size_subfield += current_byte

                    while current_byte[0] & 0b1000_0000:
                        # Read and add the next byte to the subfield
                        current_byte = fhandle.read(1)
                        size_subfield += current_byte

                    size_value = self.read_size_subfield(size_subfield)

                # Read in payload for variable-size fields here
                if size_subfield:
                    chunk += fhandle.read(size_value)
                else:
                    pass  # TODO enforce minimums for builtin metadata fields (min 8 byte) etc

            # Read fixed length field payloads here
            if tag == MixedFields.TAG_HEADER:
                chunk += fhandle.read(4)  # TODO const for header payload len
            if tag == MixedFields.TAG_ENDFILE:
                pass  # EOF is a zero length field

            # Get/check field endbyte
            end_byte = fhandle.read(1)
            if tag == MixedFields.TAG_HEADER and end_byte != MixedFields.ENDBYTE_HEADER:
                raise MixedFieldsError('BAD_HEADER_ENDBYTE', f'Error, bad header endbyte: {str(end_byte)}')
            if tag == MixedFields.TAG_ENDFILE and end_byte != self.ENDBYTE_ENDFILE:
                raise MixedFieldsError('BAD_ENDFILE_ENDBYTE', f'Error, bad endfile endbyte: {str(end_byte)}')
            if tag == MixedFields.TAG_METADATA and end_byte != self.ENDBYTE_META_STOP:
                raise MixedFieldsError('BAD_METADATA_ENDBYTE', f'Error, bad metadata endbyte: {str(end_byte)}')
            if tag == MixedFields.TAG_DATA and end_byte != self.ENDBYTE_DATA:
                raise MixedFieldsError('BAD_DATA_ENDBYTE', f'Error, bad data endbyte: {str(end_byte)}')
            if tag == MixedFields.TAG_EXTRA_METADATA and end_byte != self.ENDBYTE_EXTRA_METADATA:
                raise MixedFieldsError('BAD_EXTRA_METADATA_ENDBYTE', f'Error, bad extra metadata endbyte: {str(end_byte)}')

            # Store seek position for subsequent reads
            self._head = fhandle.tell()

            # Return an annotated field dict
            field = {
                MixedFields.INFO.TAG: tag,
                MixedFields.INFO.PAYLOAD: chunk,
                MixedFields.INFO.ENDBYTE: end_byte,
            }
            return field

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
            return {}

        # Start reading fields
        tag = b''
        chunk = b''  # Payload bytes
        end_byte = b''
        user_field_read = False
        valid_tags = {
            self.TAG_HEADER,
            self.TAG_METADATA,
            self.TAG_EXTRA_METADATA,
            self.TAG_DATA,
            self.TAG_ENDFILE
        }
        with open(self._path, 'rb') as fhandle:
            # Set position to last unread byte
            fhandle.seek(self._head)

            while not user_field_read:
                chunk = b''  # Reset

                tag = fhandle.read(self.TAG_SIZE)
                if len(tag) < self.TAG_SIZE or tag not in valid_tags:
                    raise MixedFieldsError('BAD_TAG', 'Error, invalid tag')

                # Check for/get size field value
                size_subfield = b''
                size_value = 0
                if self._is_variable_length(tag):
                    current_byte = fhandle.read(1)
                    size_subfield += current_byte

                    while current_byte[0] & 0b1000_0000:
                        # Read and add the next byte to the subfield
                        current_byte = fhandle.read(1)
                        size_subfield += current_byte

                    size_value = self.read_size_subfield(size_subfield)

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
                    self._head = fhandle.tell()
                    break

                # Read the end byte last (there are plans for fixed length payloads which have to be read first)
                end_byte = fhandle.read(len(self.ENDBYTE_HEADER))
                if tag == self.TAG_DATA:
                    if end_byte != self.ENDBYTE_DATA:
                        raise MixedFieldsError('BAD_DATA_ENDBYTE', f'Error, bad data endbyte: {str(end_byte)}')
                if tag == self.TAG_EXTRA_METADATA:
                    if end_byte != self.ENDBYTE_EXTRA_METADATA:
                        raise MixedFieldsError('BAD_EXTRA_METADATA_ENDBYTE', f'Error, bad extra metadata endbyte: {str(end_byte)}')

                # Stop reading once a field has been consumed
                if tag in {self.TAG_DATA, self.TAG_EXTRA_METADATA}:
                    user_field_read = True

                # Store seek position for subsequent reads
                self._head = fhandle.tell()

        if not chunk and not self._eof:  # Error out when EOF is missing and file end is reached
            raise MixedFieldsError('MISSING_EOF', 'Error, missing EOF field!')

        field_info = self.INFO
        return {field_info.TAG: tag, field_info.PAYLOAD: chunk, field_info.ENDBYTE: end_byte}

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

    @staticmethod
    def get_size_subfield(size):
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
        remainder = len(bit_string) % MixedFields.SIZE_BITS_PER_SIZE_BYTE

        # Get the "packed" size field bytes (with carrier
        # bits added), starting with the leading byte
        most_sig_byte = b''
        if remainder:
            leading_bits_as_num = int(bit_string[:remainder], 2)
            if len(bit_string) / MixedFields.SIZE_BITS_PER_SIZE_BYTE > 1:
                leading_bits_as_num = leading_bits_as_num | 0b10_00_00_00

            most_sig_byte = leading_bits_as_num.to_bytes(1, 'big')
        size_field_bits += most_sig_byte
        # ....
        position = remainder
        while position < len(bit_string):
            chunk_as_num = int(bit_string[position: position + MixedFields.SIZE_BITS_PER_SIZE_BYTE], 2)

            position += MixedFields.SIZE_BITS_PER_SIZE_BYTE
            if position < len(bit_string):
                # If there are additional bytes coming, set the leading bit to 1
                chunk_as_num = chunk_as_num | 0b10_00_00_00
            size_field_bits += chunk_as_num.to_bytes(1, 'big')

        return size_field_bits

    @staticmethod
    def read_size_subfield(size_field_bytes):
        size_value_bit_string = ''
        for bb in size_field_bytes:
            size_bits_no_carrier = bb & 0b0111_1111  # Strip the leading carrier digit off
            format_specifier = f'0>{MixedFields.SIZE_BITS_PER_SIZE_BYTE}'
            size_bit_chunk = f'{bin(size_bits_no_carrier)[2:]:{format_specifier}}'  # Remove '0b' and Pad to 7 bits
            size_value_bit_string += size_bit_chunk
        size_value = int(size_value_bit_string, 2)
        return size_value

    def write_item(self, item_bytes, tag=TAG_DATA):
        if not self._path_set():
            raise MixedFieldsError('PATH_NONE', 'Error, path is not set')
        if not (tag in {self.TAG_DATA, self.TAG_EXTRA_METADATA}):
            raise MixedFieldsError('INVALID_WRITE_TAG', 'Error, can only write TAG_DATA and TAG_EXTRA_METADATA fields')
        self._finalized_file_write = False

        # Write header/metadata if needed
        with open(self._path, 'ab') as fhandle:
            if self._bytes_written == 0:
                self._write_header_field()
                self._write_metadata()

        # TODO support additional field types, better handling
        desired_tag = tag
        desired_endbyte = self.ENDBYTE_DATA if tag == self.TAG_DATA else self.ENDBYTE_EXTRA_METADATA

        # Write length field and user bytes
        item_size_field = self.get_size_subfield(len(item_bytes))
        self._write_field(desired_tag, item_size_field + item_bytes, desired_endbyte)

    def close(self):
        if self._bytes_written > 0 and not self._finalized_file_write:
            self._write(self.ENDFILE)
        self._finalized_file_write = True
